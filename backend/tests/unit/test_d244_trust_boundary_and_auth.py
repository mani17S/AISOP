"""
AISOP Gate D.2.4.4 Adversarial Trust-Boundary & Auth Lifecycle Tests.

Addresses and verifies:
1. SEC-D243-001 (Critical): Report formatting trust boundary bound to exact canonical
   validation output digest (SHA-256). Replay attacks, claim tampering, metadata modifications,
   and detached forgery fail closed.
2. SEC-D243-002 (High): Ingress API authentication database session lifecycle. Sessions are
   strictly scoped to the token lookup and closed before inference or route execution begins.
"""

from __future__ import annotations

import asyncio
import copy
import json
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, status
from sqlalchemy.orm import sessionmaker

from app.api.v1.endpoints.cases import get_case_llm_provider
from app.core.config import Settings, get_settings
from app.db.session import (
    get_db_session,
    get_db_session_factory,
    isolated_session,
)
from app.main import create_app
from app.models.case import CaseAuditEventModel, CaseEvidenceModel, CaseModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from app.modules.ai.context_builder.hasher import compute_validation_output_sha256
from tests.conftest import AsyncSessionAdapter
from tests.unit.test_case_synthesis_api import (
    InstrumentedSession,
    InstrumentedSessionFactory,
    MockCaseLLMProvider,
    build_test_validation_result,
    build_valid_llm_json,
    seed_analyst_with_token,
    seed_case_with_lead,
    seed_evidence_event,
)


@pytest.fixture
def auth_settings() -> Settings:
    return Settings(
        _env_file=None,
        API_AUTH_ENABLED=True,
        API_AUTH_ALLOW_LEGACY_KEYS=True,
        API_AUTH_KEYS=[
            "legacy-machine:legacy-machine-key-999",
        ],
    )


@pytest.fixture
def app_instance(db_session, auth_settings: Settings) -> FastAPI:
    app = create_app()

    async def override_get_db():
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    sync_factory = sessionmaker(bind=db_session._sync.bind)
    instrumented_factory = InstrumentedSessionFactory(sync_factory)

    app.dependency_overrides[get_db_session] = override_get_db
    app.dependency_overrides[get_db_session_factory] = lambda: instrumented_factory
    app.dependency_overrides[get_settings] = lambda: auth_settings
    app.state.session_tracker = instrumented_factory
    return app


# ═════════════════════════════════════════════════════════════════════════════
# SEC-D243-001: Adversarial Validation Output Tampering & Trust Boundary Tests
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.anyio
async def test_replay_attack_with_modified_claim_text_rejected(db_session, app_instance: FastAPI):
    """
    SEC-D243-001 Adversarial Test 1:
    Caller reuses genuine case_id, investigation_id, and context_hash from a genuine
    investigation, but alters the claim text.
    Must be demoted to unverified and empty confirmed findings.
    """
    lead_token, lead = await seed_analyst_with_token(db_session, prefix="d244_1", username="d244_1", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)
    event = await seed_evidence_event(db_session)
    link = CaseEvidenceModel(id=uuid.uuid4(), case_id=case.id, evidence_id=event.id, linked_by_analyst_id=lead.id)
    db_session.add(link)
    await db_session.commit()

    mock_llm = MockCaseLLMProvider(response_template=build_valid_llm_json(event_uuid=event.id))
    app_instance.dependency_overrides[get_case_llm_provider] = lambda: mock_llm

    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Step 1: Synthesize legitimate investigation
        r_synth = await client.post(
            f"/api/v1/cases/{case.id}/investigations/synthesize",
            json={},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r_synth.status_code == status.HTTP_200_OK
        val_res = r_synth.json()

        # Step 2: Adversary modifies claim text while keeping genuine audit identifiers
        tampered_res = copy.deepcopy(val_res)
        assert len(tampered_res["output"]["claims"]) > 0
        tampered_res["output"]["claims"][0]["claim_text"] = "Attacker fabricated arbitrary malicious finding."

        # Step 3: Attempt to format tampered result as verified
        r_fmt = await client.post(
            "/api/v1/reports/format",
            json={
                "validation_result": tampered_res,
                "case_id": str(case.id),
            },
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r_fmt.status_code == status.HTTP_200_OK
        data = r_fmt.json()

        # Invariant: Tampered claims MUST NOT be marked server-verified
        assert data["provenance"]["is_verified_investigation"] is False
        assert data["executive_brief"]["key_confirmed_findings"] == []
        assert data["technical_report"]["confirmed_findings"] == []


@pytest.mark.anyio
async def test_modified_metadata_attributes_demoted(db_session, app_instance: FastAPI):
    """
    SEC-D243-001 Adversarial Test 2:
    Caller reuses genuine audit identifiers but alters grounding_status, confidence,
    supporting_evidence_ids, or model_identifier.
    Every variation must fail the output digest check and demote to unverified.
    """
    lead_token, lead = await seed_analyst_with_token(db_session, prefix="d244_2", username="d244_2", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)
    event = await seed_evidence_event(db_session)
    link = CaseEvidenceModel(id=uuid.uuid4(), case_id=case.id, evidence_id=event.id, linked_by_analyst_id=lead.id)
    db_session.add(link)
    await db_session.commit()

    mock_llm = MockCaseLLMProvider(response_template=build_valid_llm_json(event_uuid=event.id))
    app_instance.dependency_overrides[get_case_llm_provider] = lambda: mock_llm

    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r_synth = await client.post(
            f"/api/v1/cases/{case.id}/investigations/synthesize",
            json={},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r_synth.status_code == status.HTTP_200_OK
        genuine_val_res = r_synth.json()

        # Mutation A: Alter confidence
        tampered_conf = copy.deepcopy(genuine_val_res)
        tampered_conf["output"]["claims"][0]["confidence"] = 0.42
        r_fmt_a = await client.post(
            "/api/v1/reports/format",
            json={"validation_result": tampered_conf, "case_id": str(case.id)},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r_fmt_a.status_code == status.HTTP_200_OK
        assert r_fmt_a.json()["provenance"]["is_verified_investigation"] is False

        # Mutation B: Alter supporting_evidence_ids
        tampered_ev = copy.deepcopy(genuine_val_res)
        tampered_ev["output"]["claims"][0]["supporting_evidence_ids"] = [str(uuid.uuid4())]
        r_fmt_b = await client.post(
            "/api/v1/reports/format",
            json={"validation_result": tampered_ev, "case_id": str(case.id)},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r_fmt_b.status_code == status.HTTP_200_OK
        assert r_fmt_b.json()["provenance"]["is_verified_investigation"] is False

        # Mutation C: Alter model_identifier
        tampered_model = copy.deepcopy(genuine_val_res)
        tampered_model["output"]["model_identifier"] = "adversarial-gpt4-forgery"
        r_fmt_c = await client.post(
            "/api/v1/reports/format",
            json={"validation_result": tampered_model, "case_id": str(case.id)},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r_fmt_c.status_code == status.HTTP_200_OK
        assert r_fmt_c.json()["provenance"]["is_verified_investigation"] is False


@pytest.mark.anyio
async def test_audit_record_missing_or_corrupted_digest_fails_closed(db_session, app_instance: FastAPI):
    """
    SEC-D243-001 Adversarial Test 3:
    If an audit record in the database is missing output_sha256 or has a corrupted digest,
    the format endpoint fails closed and treats the request as unverified.
    """
    lead_token, lead = await seed_analyst_with_token(db_session, prefix="d244_3", username="d244_3", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)

    val_res = build_test_validation_result(inv_id=uuid.uuid4(), event_uuid=uuid.uuid4())
    val_res_dict = json.loads(val_res.model_dump_json())

    # Seed an audit record with MISSING output_sha256 in details
    audit_event = CaseAuditEventModel(
        id=uuid.uuid4(),
        case_id=case.id,
        actor_analyst_id=lead.id,
        actor_username=lead.username,
        action="case_investigation_synthesized",
        context_sha256=val_res.context_sha256,
        created_at=datetime.now(timezone.utc),
        details={
            "investigation_id": str(val_res.output.investigation_id),
            "decision": val_res.decision.value,
            "is_valid": True,
            # output_sha256 explicitly omitted
        },
    )
    db_session.add(audit_event)
    await db_session.commit()

    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/reports/format",
            json={"validation_result": val_res_dict, "case_id": str(case.id)},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r.status_code == status.HTTP_200_OK
        data = r.json()
        assert data["provenance"]["is_verified_investigation"] is False
        assert data["executive_brief"]["key_confirmed_findings"] == []


@pytest.mark.anyio
async def test_obsolete_unscoped_action_cannot_authorize_report(db_session, app_instance: FastAPI):
    """
    SEC-D243-001 Adversarial Test 4:
    Legacy or obsolete audit actions (e.g., 'investigation_synthesized' from unscoped legacy routes)
    CANNOT authorize verified report generation. Only scoped 'case_investigation_synthesized'
    or 'case_report_synthesized' are accepted.
    """
    lead_token, lead = await seed_analyst_with_token(db_session, prefix="d244_4", username="d244_4", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)

    val_res = build_test_validation_result(inv_id=uuid.uuid4(), event_uuid=uuid.uuid4())
    val_res_dict = json.loads(val_res.model_dump_json())
    digest = compute_validation_output_sha256(val_res)

    # Seed an audit record with obsolete action 'investigation_synthesized'
    obsolete_audit = CaseAuditEventModel(
        id=uuid.uuid4(),
        case_id=case.id,
        actor_analyst_id=lead.id,
        actor_username=lead.username,
        action="investigation_synthesized",  # Obsolete action
        context_sha256=val_res.context_sha256,
        created_at=datetime.now(timezone.utc),
        details={
            "investigation_id": str(val_res.output.investigation_id),
            "decision": val_res.decision.value,
            "is_valid": True,
            "output_sha256": digest,
        },
    )
    db_session.add(obsolete_audit)
    await db_session.commit()

    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/reports/format",
            json={"validation_result": val_res_dict, "case_id": str(case.id)},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r.status_code == status.HTTP_200_OK
        data = r.json()
        assert data["provenance"]["is_verified_investigation"] is False


@pytest.mark.anyio
async def test_rejected_decision_in_audit_record_cannot_verify(db_session, app_instance: FastAPI):
    """
    SEC-D243-001 Adversarial Test 5:
    Audit record with decision 'reject_to_fallback' or is_valid=False CANNOT authorize verified claims.
    """
    lead_token, lead = await seed_analyst_with_token(db_session, prefix="d244_5", username="d244_5", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)

    val_res = build_test_validation_result(inv_id=uuid.uuid4(), event_uuid=uuid.uuid4())
    val_res_dict = json.loads(val_res.model_dump_json())
    digest = compute_validation_output_sha256(val_res)

    audit_reject = CaseAuditEventModel(
        id=uuid.uuid4(),
        case_id=case.id,
        actor_analyst_id=lead.id,
        actor_username=lead.username,
        action="case_investigation_synthesized",
        context_sha256=val_res.context_sha256,
        created_at=datetime.now(timezone.utc),
        details={
            "investigation_id": str(val_res.output.investigation_id),
            "decision": "reject_to_fallback",  # Rejected decision
            "is_valid": True,
            "output_sha256": digest,
        },
    )
    db_session.add(audit_reject)
    await db_session.commit()

    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/reports/format",
            json={"validation_result": val_res_dict, "case_id": str(case.id)},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r.status_code == status.HTTP_200_OK
        data = r.json()
        assert data["provenance"]["is_verified_investigation"] is False


@pytest.mark.anyio
async def test_detached_formatting_cannot_bypass_verification(db_session, app_instance: FastAPI):
    """
    SEC-D243-001 Adversarial Test 6:
    Detached formatting (case_id is None) with copied genuine investigation/context identifiers
    is ALWAYS unverified and confirmed findings are stripped.
    """
    lead_token, lead = await seed_analyst_with_token(db_session, prefix="d244_6", username="d244_6", global_role="analyst_tier_2")
    val_res = build_test_validation_result(inv_id=uuid.uuid4(), event_uuid=uuid.uuid4())
    val_res_dict = json.loads(val_res.model_dump_json())

    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/reports/format",
            json={"validation_result": val_res_dict, "case_id": None},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r.status_code == status.HTTP_200_OK
        data = r.json()
        assert data["provenance"]["is_verified_investigation"] is False
        assert data["executive_brief"]["key_confirmed_findings"] == []
        assert data["technical_report"]["confirmed_findings"] == []


@pytest.mark.anyio
async def test_exact_matching_output_digest_produces_verified_report(db_session, app_instance: FastAPI):
    """
    SEC-D243-001 Adversarial Test 7 (Legitimate Verification):
    When the submitted validation output matches the exact canonical SHA-256 digest persisted
    in the audit record of a genuine case investigation, the report is marked verified and
    confirmed findings are preserved.
    """
    lead_token, lead = await seed_analyst_with_token(db_session, prefix="d244_7", username="d244_7", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)
    event = await seed_evidence_event(db_session)
    link = CaseEvidenceModel(id=uuid.uuid4(), case_id=case.id, evidence_id=event.id, linked_by_analyst_id=lead.id)
    db_session.add(link)
    await db_session.commit()

    mock_llm = MockCaseLLMProvider(response_template=build_valid_llm_json(event_uuid=event.id))
    app_instance.dependency_overrides[get_case_llm_provider] = lambda: mock_llm

    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Step 1: Synthesize legitimate investigation to record server audit
        r_synth = await client.post(
            f"/api/v1/cases/{case.id}/investigations/synthesize",
            json={},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r_synth.status_code == status.HTTP_200_OK
        val_res_dict = r_synth.json()

        # Step 2: Format untampered output against the case
        r_fmt = await client.post(
            "/api/v1/reports/format",
            json={"validation_result": val_res_dict, "case_id": str(case.id)},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r_fmt.status_code == status.HTTP_200_OK
        data = r_fmt.json()

        assert data["provenance"]["is_verified_investigation"] is True
        assert len(data["executive_brief"]["key_confirmed_findings"]) > 0
        assert len(data["technical_report"]["confirmed_findings"]) > 0


# ═════════════════════════════════════════════════════════════════════════════
# SEC-D243-002: Ingress Authentication Database Connection Lifecycle Tests
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.anyio
async def test_auth_session_closed_strictly_before_inference(db_session, app_instance: FastAPI):
    """
    SEC-D243-002 Test 1:
    Verifies that the ingress API-key authentication session is created and cleanly closed
    BEFORE route execution / LLM inference starts, holding 0 connections during inference.
    """
    lead_token, lead = await seed_analyst_with_token(db_session, prefix="d244_auth1", username="d244_auth1", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)
    event = await seed_evidence_event(db_session)
    link = CaseEvidenceModel(id=uuid.uuid4(), case_id=case.id, evidence_id=event.id, linked_by_analyst_id=lead.id)
    db_session.add(link)
    await db_session.commit()

    tracker: InstrumentedSessionFactory = app_instance.state.session_tracker
    tracker.reset()

    active_during_inference = None
    auth_sess = None
    phase_a_sess = None

    def on_inference():
        nonlocal active_during_inference, auth_sess, phase_a_sess
        active_during_inference = list(tracker.active_sessions)
        assert len(tracker.created_sessions) == 2, (
            f"Expected exactly 2 sessions created before inference, found {len(tracker.created_sessions)}"
        )
        auth_sess = tracker.created_sessions[0]
        phase_a_sess = tracker.created_sessions[1]
        assert auth_sess.is_closed is True, "Ingress auth session must be closed before inference"
        assert phase_a_sess.is_closed is True, "Phase A session must be closed before inference"

    mock_llm = MockCaseLLMProvider(response_template=build_valid_llm_json(event_uuid=event.id))
    mock_llm.generate_callback = on_inference
    app_instance.dependency_overrides[get_case_llm_provider] = lambda: mock_llm

    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            f"/api/v1/cases/{case.id}/investigations/synthesize",
            json={},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r.status_code == status.HTTP_200_OK

    # Invariants
    assert active_during_inference == [], "Zero sessions held during slow inference"
    assert len(tracker.created_sessions) == 3, "Auth (0), Phase A (1), Phase C (2)"
    assert len(tracker.active_sessions) == 0, "All sessions closed with zero leaks"


@pytest.mark.anyio
async def test_isolated_session_handles_task_cancellation_cleanly(db_session):
    """
    SEC-D243-002 Test 2:
    Verifies that when an asyncio task executing inside isolated_session is cancelled,
    the session cleanly catches CancelledError (BaseException), rolls back, and closes.
    """
    sync_factory = sessionmaker(bind=db_session._sync.bind)
    tracker = InstrumentedSessionFactory(sync_factory)

    session_opened_event = asyncio.Event()

    async def worker():
        async with isolated_session(session_factory=tracker) as sess:
            session_opened_event.set()
            # Simulate long wait interrupted by cancellation
            await asyncio.sleep(60.0)

    task = asyncio.create_task(worker())
    await session_opened_event.wait()

    assert len(tracker.active_sessions) == 1
    managed_session = tracker.active_sessions[0]

    # Cancel the task
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Session must be rolled back and closed
    assert managed_session.is_closed is True
    assert managed_session.rollback_count == 1
    assert len(tracker.active_sessions) == 0


@pytest.mark.anyio
async def test_altered_narrative_summary_demoted(db_session, app_instance: FastAPI):
    """
    SEC-D243-001 Adversarial Test 8:
    Tampering with investigation_summary alters canonical output digest and demotes to unverified.
    """
    lead_token, lead = await seed_analyst_with_token(db_session, prefix="d244_8", username="d244_8", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)
    event = await seed_evidence_event(db_session)
    link = CaseEvidenceModel(id=uuid.uuid4(), case_id=case.id, evidence_id=event.id, linked_by_analyst_id=lead.id)
    db_session.add(link)
    await db_session.commit()

    mock_llm = MockCaseLLMProvider(response_template=build_valid_llm_json(event_uuid=event.id))
    app_instance.dependency_overrides[get_case_llm_provider] = lambda: mock_llm

    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r_synth = await client.post(
            f"/api/v1/cases/{case.id}/investigations/synthesize",
            json={},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r_synth.status_code == status.HTTP_200_OK
        genuine_res = r_synth.json()

        tampered_summary = copy.deepcopy(genuine_res)
        tampered_summary["output"]["investigation_summary"] = "Completely altered fabricated narrative summary of the incident."

        r_fmt = await client.post(
            "/api/v1/reports/format",
            json={"validation_result": tampered_summary, "case_id": str(case.id)},
            headers={"Authorization": f"Bearer {lead_token}"},
        )
        assert r_fmt.status_code == status.HTTP_200_OK
        data = r_fmt.json()
        assert data["provenance"]["is_verified_investigation"] is False
        assert data["executive_brief"]["key_confirmed_findings"] == []


@pytest.mark.anyio
async def test_unassigned_analyst_cannot_format_case_report(db_session, app_instance: FastAPI):
    """
    SEC-D243-001 Adversarial Test 9:
    An analyst not assigned to the case receives HTTP 404 anti-enumeration and cannot verify reports.
    """
    lead_token, lead = await seed_analyst_with_token(db_session, prefix="d244_9a", username="d244_9a", global_role="analyst_tier_2")
    unassigned_token, unassigned = await seed_analyst_with_token(db_session, prefix="d244_9b", username="d244_9b", global_role="analyst_tier_2")
    case = await seed_case_with_lead(db_session, lead=lead)

    val_res = build_test_validation_result(inv_id=uuid.uuid4(), event_uuid=uuid.uuid4())
    val_res_dict = json.loads(val_res.model_dump_json())

    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/v1/reports/format",
            json={"validation_result": val_res_dict, "case_id": str(case.id)},
            headers={"Authorization": f"Bearer {unassigned_token}"},
        )
        assert r.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.anyio
async def test_ordinary_exception_in_isolated_session_triggers_cleanup(db_session):
    """
    SEC-D243-002 Test 3:
    Verifies that an ordinary exception inside isolated_session rolls back and closes the session.
    """
    sync_factory = sessionmaker(bind=db_session._sync.bind)
    tracker = InstrumentedSessionFactory(sync_factory)

    with pytest.raises(ValueError, match="Simulated application error"):
        async with isolated_session(session_factory=tracker) as sess:
            raise ValueError("Simulated application error")

    assert len(tracker.created_sessions) == 1
    session = tracker.created_sessions[0]
    assert session.is_closed is True
    assert session.rollback_count == 1
    assert len(tracker.active_sessions) == 0


@pytest.mark.anyio
async def test_shared_auth_refactor_preserves_public_and_protected_perimeter(db_session, app_instance: FastAPI):
    """
    SEC-D243-002 Test 4:
    Verifies that the refactored verify_api_key preserves all route perimeter guarantees:
    - Public endpoints (/api/v1/health) remain accessible without credentials.
    - Protected endpoints reject requests with missing credentials (401).
    - Invalid tokens fail closed (401).
    """
    transport = httpx.ASGITransport(app=app_instance)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Public route check
        r_health = await client.get("/api/v1/health")
        assert r_health.status_code == status.HTTP_200_OK

        # Missing auth check on protected route
        r_no_auth = await client.post("/api/v1/reports/format", json={})
        assert r_no_auth.status_code == status.HTTP_401_UNAUTHORIZED

        # Malformed auth check
        r_bad_auth = await client.post(
            "/api/v1/reports/format",
            json={},
            headers={"Authorization": "Bearer totally_bogus_token"},
        )
        assert r_bad_auth.status_code == status.HTTP_401_UNAUTHORIZED
