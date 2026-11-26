"""
The stored evidence-sufficiency verdict must be on every CaseResponse the service returns for an existing case,
not only on list/detail: after an analyst edits, transfers or closes a case the frontend replaces its copy with the
write response, so a missing verdict would show a false "Not assessed". The read is the same stored-verdict lookup the
detail path uses; it never calls the evidence gate and never writes an audit row.
"""

from __future__ import annotations

import itertools
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import func, select

from app.api.dependencies import get_current_analyst  # noqa: F401  (import check only; keeps module load order identical to test_case_api)
from app.core.config import Settings, get_settings
from app.core.rbac import AuthenticatedAnalyst, GlobalRole, hash_canonical_token
from app.db.session import get_db_session
from app.main import create_app
from app.models.analyst import Analyst, AnalystApiClient
from app.models.case import CaseAssignmentModel, CaseAuditEventModel, CaseModel
from app.schemas.case import (
    CaseCreateRequest,
    CaseLifecycleUpdateRequest,
    CaseMetadataUpdateRequest,
    CaseStatus,
    LeadTransferRequest,
)
from app.services.case_service import CaseService

_FIELDS = ("sufficiency_verdict", "sufficiency_rule_version", "sufficiency_assessed_at", "sufficiency_incidents_truncated")
_SEQ = itertools.count(7000)
_RUN_AT = datetime(2026, 11, 25, 10, 1, tzinfo=timezone.utc)

_LIMITED = {"incidents": [{"sufficiency": {"verdict": "limited", "rule_version": "suff-v5", "reason_codes": []}}],
            "truncation": {"incidents_total": 1}}
_INSUFFICIENT = {"incidents": [{"sufficiency": {"verdict": "sufficient", "rule_version": "a", "reason_codes": []}},
                               {"sufficiency": {"verdict": "insufficient", "rule_version": "b", "reason_codes": []}}],
                 "truncation": {"incidents_total": 2}}
_UNKNOWN = object()


def _fields(resp):
    return tuple(getattr(resp, f) for f in _FIELDS)


async def _analyst(db_session, role: str) -> Analyst:
    a = Analyst(id=uuid.uuid4(), username=f"u{uuid.uuid4().hex[:8]}", email=f"{uuid.uuid4().hex[:8]}@aisop.local",
                global_role=role, is_active=True)
    db_session.add(a)
    await db_session.flush()
    return a


def _actor(a: Analyst, role: GlobalRole) -> AuthenticatedAnalyst:
    return AuthenticatedAnalyst(analyst_id=a.id, username=a.username, global_role=role, is_active=True)


async def _seed(db_session, details):
    """A tier-2 lead, a security-admin transfer target and an open case; ``details`` None means no stored run."""
    lead = await _analyst(db_session, "analyst_tier_2")
    target = await _analyst(db_session, "security_admin")
    case = CaseModel(id=uuid.uuid4(), case_number=f"CASE-20261125-{next(_SEQ):04d}", title="Write path verdict", severity="high", status="open")
    db_session.add(case)
    await db_session.flush()
    db_session.add(CaseAssignmentModel(id=uuid.uuid4(), case_id=case.id, analyst_id=lead.id, case_role="lead"))
    if details is not None:
        db_session.add(CaseAuditEventModel(id=uuid.uuid4(), case_id=case.id, actor_analyst_id=lead.id, actor_username=lead.username,
                                           action="case_multisource_investigation", details=details, created_at=_RUN_AT))
    await db_session.commit()
    return lead, target, case


async def _call(db_session, op, lead, target, case_id):
    svc = CaseService()
    actor = _actor(lead, GlobalRole.ANALYST_TIER_2)
    if op == "update":
        return await svc.update_case_metadata(db_session, case_id, CaseMetadataUpdateRequest(title="Renamed case title"), actor)
    if op == "transfer":
        return await svc.transfer_lead(db_session, case_id, LeadTransferRequest(target_analyst_id=target.id, reason="Hand over to the administrator"), actor)
    return await svc.close_case(db_session, case_id, CaseLifecycleUpdateRequest(status=CaseStatus.CLOSED, closure_reason="Root cause removed"), actor)


async def _audit_count(db_session, case_id, *, run_only=False):
    q = select(func.count()).select_from(CaseAuditEventModel).where(CaseAuditEventModel.case_id == case_id)
    if run_only:
        q = q.where(CaseAuditEventModel.action == "case_multisource_investigation")
    return (await db_session.execute(q)).scalar_one()


@pytest.fixture(autouse=True)
def _fresh_memo():
    import app.services.multisource_investigation_service as svc

    svc._LEGACY_MEMO.clear()
    yield
    svc._LEGACY_MEMO.clear()


@pytest.fixture
def no_gate(monkeypatch):
    import app.modules.ai.guardrails.sufficiency_gate as gate
    import app.modules.correlation.workflow as wf
    import app.services.case_service as cs

    calls: list[int] = []

    def boom(*a, **k):
        calls.append(1)
        raise AssertionError("evaluate_sufficiency must not run on a case write path")

    for mod in (gate, wf, cs):
        monkeypatch.setattr(mod, "evaluate_sufficiency", boom, raising=False)
    return calls


class TestWritePathsCarryTheStoredVerdict:
    @pytest.mark.anyio
    @pytest.mark.parametrize("op", ["update", "transfer", "close"])
    @pytest.mark.parametrize("name,details,expected", [("limited", _LIMITED, "limited"), ("insufficient", _INSUFFICIENT, "insufficient")])
    async def test_response_has_the_same_four_fields_as_detail(self, db_session, no_gate, op, name, details, expected):
        lead, target, case = await _seed(db_session, details)
        before_detail = _fields(await CaseService().get_case_detail(db_session, case.id))
        assert before_detail[0].value == expected

        resp = await _call(db_session, op, lead, target, case.id)

        assert _fields(resp) == before_detail
        db_session._sync.expire_all()                      # the test reuses one session; a real request re-loads the assignments
        assert _fields(resp) == _fields(await CaseService().get_case_detail(db_session, case.id))
        assert resp.sufficiency_verdict.value == expected
        assert resp.model_dump(mode="json")["sufficiency_verdict"] == expected
        assert no_gate == []

    @pytest.mark.anyio
    @pytest.mark.parametrize("op", ["update", "transfer", "close"])
    async def test_no_stored_run_gives_none_on_the_response(self, db_session, no_gate, op):
        lead, target, case = await _seed(db_session, None)
        resp = await _call(db_session, op, lead, target, case.id)
        assert _fields(resp) == (None, None, None, None)
        assert no_gate == []

    @pytest.mark.anyio
    @pytest.mark.parametrize("op", ["update", "transfer", "close"])
    async def test_the_read_writes_no_audit_row_and_changes_no_run(self, db_session, no_gate, op):
        lead, target, case = await _seed(db_session, _LIMITED)
        total, runs = await _audit_count(db_session, case.id), await _audit_count(db_session, case.id, run_only=True)
        await _call(db_session, op, lead, target, case.id)
        assert await _audit_count(db_session, case.id) == total + 1            # only the operation's own audit row
        assert await _audit_count(db_session, case.id, run_only=True) == runs

    @pytest.mark.anyio
    async def test_create_case_has_no_verdict_and_never_calls_the_gate(self, db_session, no_gate):
        lead = await _analyst(db_session, "analyst_tier_2")
        await db_session.commit()
        resp = await CaseService().create_case(db_session, CaseCreateRequest(title="Brand new case", severity="high"),
                                               _actor(lead, GlobalRole.ANALYST_TIER_2))
        assert _fields(resp) == (None, None, None, None)
        assert no_gate == []


# ---- API level: the JSON the frontend receives from the write endpoints ----

@pytest.fixture
def auth_settings() -> Settings:
    return Settings(_env_file=None, API_AUTH_ENABLED=True, API_AUTH_ALLOW_LEGACY_KEYS=True, API_AUTH_KEYS=["legacy-machine:legacy-machine-key-999"])


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

    app.dependency_overrides[get_db_session] = override_get_db
    app.dependency_overrides[get_settings] = lambda: auth_settings
    return app


async def _token_for(db_session, analyst: Analyst, prefix: str) -> str:
    import hashlib

    hex_prefix = hashlib.md5(prefix.encode()).hexdigest()[:16]
    token = f"aisop_live_{hex_prefix}_{'b' * 64}"
    db_session.add(AnalystApiClient(id=uuid.uuid4(), analyst_id=analyst.id, client_name=f"{prefix}-client", token_prefix=hex_prefix,
                                    hashed_secret=hash_canonical_token(token), is_active=True))
    await db_session.commit()
    return token


class TestWriteEndpointsReturnTheVerdict:
    @pytest.mark.anyio
    @pytest.mark.parametrize("path,method,body", [
        ("", "PATCH", {"title": "Renamed via the API"}),
        ("/lead", "POST", None),
        ("/close", "POST", {"status": "closed", "closure_reason": "Root cause eliminated"}),
    ])
    async def test_endpoint_json_has_the_verdict(self, app_instance, db_session, path, method, body):
        lead, target, case = await _seed(db_session, _INSUFFICIENT)
        token = await _token_for(db_session, lead, f"verdictapi{path.strip('/') or 'patch'}")
        if body is None:
            body = {"target_analyst_id": str(target.id), "reason": "Hand over to the administrator"}
        transport = httpx.ASGITransport(app=app_instance)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            res = await client.request(method, f"/api/v1/cases/{case.id}{path}", headers={"Authorization": f"Bearer {token}"}, json=body)
            assert res.status_code == 200, res.text
            out = res.json()
            detail = await client.get(f"/api/v1/cases/{case.id}", headers={"Authorization": f"Bearer {token}"})
        # After a lead transfer the old lead is only an investigator; detail is still readable by an assigned analyst.
        assert detail.status_code == 200, detail.text
        for f in ("sufficiency_verdict", "sufficiency_rule_version", "sufficiency_incidents_truncated"):
            assert out[f] == detail.json()[f]
        assert out["sufficiency_verdict"] == "insufficient" and out["sufficiency_rule_version"] == "b"
        assert out["sufficiency_incidents_truncated"] is False and out["sufficiency_assessed_at"] is not None
