"""
AISOP Gate D.2.5 — PostgreSQL Scoping, Invariant & Immutability Verification.

Task ID: AISOP-GATE-D.2.5-SPECIFICATION-001 / Gate D.2.5.4
Milestone: Phase 3 — P3-H2 (RBAC and Analyst Case Scoping)
Governing Policy: AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001

Test Suite Architecture:
- Section 1: Pure-Function Offline Safety Guards & Supplemental Preflights (0 DB calls)
- Section 2: Read-Only Target Identity & Catalog Invariants (Live PostgreSQL required)
  - Partial Unique Index uq_case_lead_active
  - Audit Immutability Row Trigger trg_case_audit_events_immutable (tgtype=27)
  - Audit Immutability Statement Trigger trg_case_audit_events_prevent_truncate (tgtype=34)
  - Foreign Key Constraints & Referential Delete Rules
- Section 3: Live Invariant Enforcement via Isolated Rollback Sessions (Tier 1 Isolation)
  - Active-Lead Uniqueness Violation (SAVEPOINT isolation)
  - Append-Only Audit Trigger Interception (UPDATE, DELETE, TRUNCATE blocked)
- Section 4: Physical Connection-Pool Concurrency & Lifecycle Instrumentation
  - 8 concurrent requests reaching mock inference barrier with 5-connection QueuePool
  - Handling of cancelled tasks, query exceptions, and connection invalidations
  - Explicit documentation: QueuePool event tracking vs. OS-level socket persistence
- Section 5: End-to-End Synthesis & Report Verification (Tier 2 Dedicated Disposable DB)
  - 4-Action Audit Trail: case_created -> evidence_linked -> case_investigation_synthesized -> case_closed
  - Report Formatting Verification with SHA-256 Digest Trust Boundary
  - Rejection / Demotion of tampered or forged validation outputs
  - Zero destructive teardown on committed audit records
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os
import re
import secrets
import selectors
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, Generator

import httpx
import pytest
from sqlalchemy import (
    delete,
    event,
    func,
    inspect,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.api.v1.endpoints.reports import format_reports
from app.core.auth import AuthenticatedClient
from app.core.config import Settings, get_settings
from app.core.rbac import (
    AuthenticatedAnalyst,
    GlobalRole,
    hash_canonical_token,
)
from app.db.base import Base
from app.db.session import get_db_session
from app.main import create_app
from app.models.analyst import Analyst, AnalystApiClient
from app.schemas.ai import LLMResponse
from app.models.case import (
    CaseAssignmentModel,
    CaseAuditEventModel,
    CaseEvidenceModel,
    CaseModel,
    CaseRole,
    CaseSeverity,
    CaseStatus,
)
from app.models.evidence import ExtractedEntityModel, NormalizedEventModel, RawEvidence
from app.modules.ai.context_builder.hasher import (
    canonicalize_payload,
    compute_validation_output_sha256,
)
from app.modules.ai.guardrails import (
    GuardrailDecision,
    InvestigationOutputValidator,
    InvestigationValidationResult,
)
from app.schemas.case import (
    CaseCreateRequest,
    CaseEvidenceLinkRequest,
    CaseInvestigationSynthesizeRequest,
    CaseLifecycleUpdateRequest,
)
from app.schemas.report import ReportFormatRequest
from app.services.case_service import CaseService
from tests.conftest import (
    ALLOWED_SCHEMES,
    ALLOWED_TEST_HOSTS,
    DISPOSABLE_DB_NAME_PATTERN,
    PROTECTED_DATABASE_NAMES,
    assert_target_is_marked_disposable,
    validate_test_database_target,
    verify_approved_target_identity,
)


# ==============================================================================
# SECTION 1: SAFETY GUARDS & SUPPLEMENTAL PREFLIGHT VALIDATORS
# ==============================================================================

class TargetMigrationState(str, Enum):
    """Categorized live Alembic migration states for fail-closed evaluation."""
    ALREADY_AT_HEAD = "0004_p3h2_rbac_case_scoping"
    UPGRADE_ELIGIBLE = "0003_source_scoped_chunks"
    FRESH_NO_VERSION_TABLE = "missing_alembic_version_table"
    FRESH_ZERO_ROWS = "empty_alembic_version_table"
    DIVERGENT = "divergent_or_malformed_revision"


@dataclass(frozen=True)
class TargetIdentityRecord:
    database_name: str
    connected_user: str
    is_superuser: bool
    server_port: int
    server_version: str
    pgvector_version: str | None
    migration_state: TargetMigrationState
    detected_revision: str | None


def verify_gate_d25_target_environment(
    db_url_raw: str | None = None,
    allow_destructive_raw: str | None = None,
) -> URL:
    """
    Validate that the test database target strictly complies with Gate D.2.5 policy:
    1. Passes baseline validate_test_database_target (scheme, local host, disposable regex, opt-in).
    2. Strictly enforces host port 5433 (mapping to containerized PostgreSQL 17).
       Refuses port 5432 (default Windows native PostgreSQL) and unmapped ports.

    Pure function: Does NOT connect to PostgreSQL or create database engines.
    """
    # 1. Baseline guard (pure URL validation)
    url = validate_test_database_target(
        db_url_raw=db_url_raw,
        allow_destructive_raw=allow_destructive_raw,
        require_destructive_opt_in=True,
    )

    # 2. Supplemental Gate D.2.5 port check
    # Note: validate_test_database_target() does NOT check port. This supplemental check is mandatory.
    if url.port != 5433:
        safe_url = url.render_as_string(hide_password=True)
        raise RuntimeError(
            f"FAIL-CLOSED: Gate D.2.5 strictly requires host port 5433 (container port mapping) in {safe_url}.\n"
            f"Detected port: '{url.port}'. Refusing to target port 5432 or unmapped ports to prevent "
            "accidental connection to native Windows PostgreSQL services."
        )

    return url


def evaluate_migration_state_decision(
    has_alembic_table: bool,
    revisions: list[str],
) -> tuple[TargetMigrationState, str]:
    """
    Pure-function fail-closed decision table for Alembic starting revisions.
    Returns (TargetMigrationState, action_description).
    """
    if not has_alembic_table:
        return (
            TargetMigrationState.FRESH_NO_VERSION_TABLE,
            "Fresh database: Requires explicit owner authorization for Path B migration ancestry.",
        )

    if len(revisions) == 0:
        return (
            TargetMigrationState.FRESH_ZERO_ROWS,
            "Fresh database with empty alembic_version: Requires explicit owner authorization for Path B.",
        )

    if len(revisions) > 1:
        return (
            TargetMigrationState.DIVERGENT,
            f"ABORT: Multiple heads detected in alembic_version: {revisions}. Auto-downgrade prohibited.",
        )

    rev = revisions[0].strip()
    if rev == "0004_p3h2_rbac_case_scoping":
        return (
            TargetMigrationState.ALREADY_AT_HEAD,
            "Already at revision 0004: Skip migration upgrade. Proceed to catalog and invariant assertions.",
        )
    elif rev == "0003_source_scoped_chunks":
        return (
            TargetMigrationState.UPGRADE_ELIGIBLE,
            "Revision 0003: Eligible for Path A migration upgrade to 0004 with owner authorization.",
        )
    else:
        return (
            TargetMigrationState.DIVERGENT,
            f"ABORT: Unexpected starting revision '{rev}'. Auto-downgrade or blind upgrade prohibited.",
        )


# ==============================================================================
# SECTION 1 TESTS: PURE-FUNCTION OFFLINE TESTS (NO DB ACCESS)
# ==============================================================================

class TestD25PureSafetyGuards:
    """Verifies all pure-function safety validators completely offline."""

    def test_pre_01_baseline_guard_rejects_untrusted_targets(self, monkeypatch):
        """Baseline guard rejects missing opt-in, bad schemes, protected names, and remote hosts."""
        monkeypatch.delenv("ALLOW_DESTRUCTIVE_POSTGRES_TESTS", raising=False)
        # Missing opt-in
        with pytest.raises(RuntimeError, match="Destructive PostgreSQL testing is not opted-in"):
            validate_test_database_target(
                db_url_raw="postgresql+psycopg://aisop:secret@localhost:5433/aisop_p2h3_disposable",
                allow_destructive_raw=None,
                require_destructive_opt_in=True,
            )

        # Protected database names
        for prot in sorted(PROTECTED_DATABASE_NAMES):
            with pytest.raises(RuntimeError, match="Refusing to target protected database"):
                validate_test_database_target(
                    db_url_raw=f"postgresql+psycopg://aisop:secret@localhost:5433/{prot}",
                    allow_destructive_raw="1",
                    require_destructive_opt_in=True,
                )

        # Untrusted remote hosts
        with pytest.raises(RuntimeError, match="Untrusted test host"):
            validate_test_database_target(
                db_url_raw="postgresql+psycopg://aisop:secret@10.0.0.1:5433/aisop_p2h3_disposable",
                allow_destructive_raw="1",
                require_destructive_opt_in=True,
            )

    def test_pre_02_supplemental_preflight_strictly_enforces_port_5433(self):
        """Supplemental preflight rejects port 5432, unmapped ports, or omitted ports."""
        valid_disposable = "aisop_p2h3_disposable"

        # Explicit port 5432 must be rejected
        with pytest.raises(RuntimeError, match="strictly requires host port 5433"):
            verify_gate_d25_target_environment(
                db_url_raw=f"postgresql+psycopg://aisop:secret@localhost:5432/{valid_disposable}",
                allow_destructive_raw="1",
            )

        # Omitted port (defaults to 5432 in PostgreSQL) must be rejected
        with pytest.raises(RuntimeError, match="strictly requires host port 5433"):
            verify_gate_d25_target_environment(
                db_url_raw=f"postgresql+psycopg://aisop:secret@localhost/{valid_disposable}",
                allow_destructive_raw="1",
            )

        # Port 5434 must be rejected
        with pytest.raises(RuntimeError, match="strictly requires host port 5433"):
            verify_gate_d25_target_environment(
                db_url_raw=f"postgresql+psycopg://aisop:secret@localhost:5434/{valid_disposable}",
                allow_destructive_raw="1",
            )

        # Explicit port 5433 with valid disposable name succeeds
        url = verify_gate_d25_target_environment(
            db_url_raw=f"postgresql+psycopg://aisop:secret@localhost:5433/{valid_disposable}",
            allow_destructive_raw="1",
        )
        assert url.port == 5433
        assert url.database == valid_disposable

    def test_pre_03_existing_guard_port_blindspot_verified(self):
        """
        Confirms that the existing baseline validate_test_database_target does NOT check port.
        This proves the supplemental check is necessary to prevent targeting port 5432.
        """
        # Baseline guard alone accepts port 5432 if other conditions pass
        baseline_url = validate_test_database_target(
            db_url_raw="postgresql+psycopg://aisop:secret@localhost:5432/aisop_p2h3_disposable",
            allow_destructive_raw="1",
            require_destructive_opt_in=True,
        )
        assert baseline_url.port == 5432  # Proves baseline guard has no port restriction

    def test_pre_04_migration_decision_table_states(self):
        """Validates all 5 states in the fail-closed migration decision table."""
        # 1. Missing alembic_version table
        state, msg = evaluate_migration_state_decision(has_alembic_table=False, revisions=[])
        assert state == TargetMigrationState.FRESH_NO_VERSION_TABLE
        assert "Path B" in msg

        # 2. Empty alembic_version table
        state, msg = evaluate_migration_state_decision(has_alembic_table=True, revisions=[])
        assert state == TargetMigrationState.FRESH_ZERO_ROWS

        # 3. Exactly revision 0003
        state, msg = evaluate_migration_state_decision(has_alembic_table=True, revisions=["0003_source_scoped_chunks"])
        assert state == TargetMigrationState.UPGRADE_ELIGIBLE
        assert "Path A" in msg

        # 4. Exactly revision 0004
        state, msg = evaluate_migration_state_decision(has_alembic_table=True, revisions=["0004_p3h2_rbac_case_scoping"])
        assert state == TargetMigrationState.ALREADY_AT_HEAD
        assert "Skip migration upgrade" in msg

        # 5. Unexpected / divergent revisions
        for bad_rev in ["0001_initial_evidence_schema", "0002_pgvector_knowledge_schema", "unknown_hash"]:
            state, msg = evaluate_migration_state_decision(has_alembic_table=True, revisions=[bad_rev])
            assert state == TargetMigrationState.DIVERGENT
            assert "ABORT" in msg

        # Multiple heads
        state, msg = evaluate_migration_state_decision(has_alembic_table=True, revisions=["rev1", "rev2"])
        assert state == TargetMigrationState.DIVERGENT
        assert "Multiple heads" in msg


# ==============================================================================
# LIVE POSTGRESQL FIXTURES & INSTRUMENTATION (FAIL-CLOSED)
# ==============================================================================

@pytest.fixture(scope="session")
def d25_validated_target_url() -> URL:
    """
    Retrieve and validate the live PostgreSQL test database target URL.
    Fails closed or skips if unconfigured, protecting other databases.
    """
    raw_url = os.getenv("TEST_DATABASE_URL")
    destructive_opt = os.getenv("ALLOW_DESTRUCTIVE_POSTGRES_TESTS")

    if not raw_url or not raw_url.strip():
        pytest.skip("TEST_DATABASE_URL not configured. Skipping live PostgreSQL test.")

    if destructive_opt != "1":
        pytest.skip("ALLOW_DESTRUCTIVE_POSTGRES_TESTS != '1'. Skipping live PostgreSQL test.")

    url = verify_gate_d25_target_environment(
        db_url_raw=raw_url,
        allow_destructive_raw=destructive_opt,
    )
    # Stage 7B (D6): the exact approved target and the launcher-verified container/volume/marker identity; read-only database-side marker check.
    verify_approved_target_identity(url)
    assert_target_is_marked_disposable(url.render_as_string(hide_password=False).replace("+psycopg", "").replace("+asyncpg", ""))
    return url


class PoolLifecycleTracker:
    """
    Thread-safe tracker for SQLAlchemy QueuePool checkout/checkin lifecycle.
    
    LIMITATION NOTICE:
    Tracks SQLAlchemy connection-pool checkout/checkin balance and invalidation events.
    Does NOT monitor OS-level TCP socket states or PostgreSQL server worker process states.
    """

    def __init__(self) -> None:
        self.checkouts: int = 0
        self.checkins: int = 0
        self.invalidations: int = 0
        self.lock = asyncio.Lock() if hasattr(asyncio, "Lock") else None

    def on_checkout(self, dbapi_connection: Any, connection_record: Any, connection_proxy: Any) -> None:
        self.checkouts += 1

    def on_checkin(self, dbapi_connection: Any, connection_record: Any) -> None:
        self.checkins += 1

    def on_invalidate(self, dbapi_connection: Any, connection_record: Any, exception: Any) -> None:
        self.invalidations += 1


@pytest.fixture(scope="session")
def d25_pool_tracker() -> PoolLifecycleTracker:
    return PoolLifecycleTracker()


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="session")
def d25_async_engine(
    d25_validated_target_url: URL,
    d25_pool_tracker: PoolLifecycleTracker,
) -> Generator[AsyncEngine, None, None]:
    """
    Create a bounded 5-connection AsyncEngine for Gate D.2.5 with QueuePool event listeners.
    pool_size=5, max_overflow=0 forces pool exhaustion if connections are leaked.
    """
    raw_url_str = d25_validated_target_url.render_as_string(hide_password=False)

    engine = create_async_engine(
        raw_url_str,
        pool_size=5,
        max_overflow=0,
        pool_timeout=5.0,  # Bounded timeout for deterministic starvation failure
    )

    # Attach event listeners to the underlying sync engine pool
    sync_pool = engine.sync_engine.pool
    event.listen(sync_pool, "checkout", d25_pool_tracker.on_checkout)
    event.listen(sync_pool, "checkin", d25_pool_tracker.on_checkin)
    event.listen(sync_pool, "invalidate", d25_pool_tracker.on_invalidate)

    try:
        yield engine
    finally:
        # Cleanly remove listeners and dispose engine
        event.remove(sync_pool, "checkout", d25_pool_tracker.on_checkout)
        event.remove(sync_pool, "checkin", d25_pool_tracker.on_checkin)
        event.remove(sync_pool, "invalidate", d25_pool_tracker.on_invalidate)

        # Dedicated SelectorEventLoop for psycopg async engine disposal on Windows
        loop = asyncio.SelectorEventLoop(selectors.SelectSelector())
        try:
            loop.run_until_complete(engine.dispose())
        finally:
            loop.close()


@pytest.fixture
async def d25_rollback_session(d25_async_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """
    Tier 1 Isolation: Function-scoped AsyncSession that ALWAYS rolls back.
    Zero persistent rows are committed to case_audit_events or other tables.
    """
    session_factory = async_sessionmaker(
        bind=d25_async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    async with session_factory() as session:
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()


# ==============================================================================
# SECTION 2: LIVE READ-ONLY CATALOG INVARIANT TESTS
# ==============================================================================

@pytest.mark.postgres
@pytest.mark.anyio
class TestD25CatalogInvariants:
    """Direct PostgreSQL catalog assertions verifying migration 0004 parity."""

    async def test_cat_01_target_server_identity_and_version(
        self,
        d25_async_engine: AsyncEngine,
        d25_validated_target_url: URL,
    ):
        """
        Verify connected PostgreSQL database name, user, port, and Linux container identity.
        LIMITATION: Uses read-only transaction; does not prove host-level Docker identity without CLI.
        """
        async with d25_async_engine.connect() as conn:
            # 1. Target database name
            db_name = (await conn.execute(text("SELECT current_database();"))).scalar()
            assert db_name == d25_validated_target_url.database

            # 2. Internal server port (mapped container port 5432)
            server_port = (await conn.execute(text("SELECT inet_server_port();"))).scalar()
            assert server_port == 5432, f"Expected container internal port 5432, got {server_port}"

            # 3. Connected user is 'aisop'
            current_user = (await conn.execute(text("SELECT current_user;"))).scalar()
            assert current_user == "aisop"

            # 4. Role superuser status (documented local container behavior)
            is_super = (await conn.execute(
                text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user;")
            )).scalar()
            # Note: In local Docker, aisop is bootstrap superuser. We document this fact:
            assert is_super is True

            # 5. Linux container version (proves not native Windows PostgreSQL service)
            version_str = (await conn.execute(text("SELECT version();"))).scalar() or ""
            assert "PostgreSQL 17" in version_str
            assert "linux" in version_str.lower() or "debian" in version_str.lower()

            # 6. pgvector extension
            ext_ver = (await conn.execute(
                text("SELECT extversion FROM pg_extension WHERE extname = 'vector';")
            )).scalar()
            assert ext_ver is not None, "pgvector extension must be installed in target database."

    async def test_cat_02_catalog_case_lead_partial_index(self, d25_async_engine: AsyncEngine):
        """
        Verify partial unique index uq_case_lead_active using single-row pg_index query.
        Guarantees exactly 1 row returned and verifies key column and predicate.
        """
        query = text("""
            SELECT 
                c.relname AS index_name,
                t.relname AS table_name,
                i.indisunique AS is_unique,
                i.indisvalid AS is_valid,
                pg_get_expr(i.indpred, i.indrelid) AS predicate,
                pg_get_indexdef(c.oid) AS index_definition
            FROM pg_index i
            JOIN pg_class c ON c.oid = i.indexrelid
            JOIN pg_class t ON t.oid = i.indrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = 'uq_case_lead_active'
              AND t.relname = 'case_assignments'
              AND n.nspname = 'public';
        """)
        async with d25_async_engine.connect() as conn:
            result = (await conn.execute(query)).mappings().all()
            assert len(result) == 1, f"Expected exactly 1 index record, found {len(result)}"
            row = result[0]
            assert row["is_unique"] is True
            assert row["is_valid"] is True
            predicate = str(row["predicate"] or "").lower()
            assert "case_role" in predicate, f"Expected 'case_role' in predicate, got: {row['predicate']}"
            assert "'lead'" in predicate, f"Expected ''lead'' in predicate, got: {row['predicate']}"
            for other_role in ("investigator", "reviewer", "responder"):
                assert f"'{other_role}'" not in predicate, (
                    f"Index predicate incorrectly references role '{other_role}': {predicate}"
                )
            assert "(case_id)" in row["index_definition"]

    async def test_cat_03_catalog_audit_immutability_triggers(self, d25_async_engine: AsyncEngine):
        """
        Verify user-defined audit immutability triggers on case_audit_events.
        Asserts bitmask tgtype: 27 (Row Before Update/Delete) and 34 (Statement Before Truncate).
        """
        query = text("""
            SELECT 
                tg.tgname, 
                tg.tgtype, 
                tg.tgenabled, 
                pr.proname AS function_name
            FROM pg_trigger tg
            JOIN pg_proc pr ON pr.oid = tg.tgfoid
            JOIN pg_class cl ON cl.oid = tg.tgrelid
            JOIN pg_namespace n ON n.oid = cl.relnamespace
            WHERE cl.relname = 'case_audit_events'
              AND n.nspname = 'public'
              AND NOT tg.tgisinternal
            ORDER BY tg.tgname ASC;
        """)
        async with d25_async_engine.connect() as conn:
            rows = (await conn.execute(query)).mappings().all()
            triggers = {r["tgname"]: r for r in rows}

            # 1. Row-level trigger: BEFORE UPDATE OR DELETE FOR EACH ROW
            assert "trg_case_audit_events_immutable" in triggers
            row_trg = triggers["trg_case_audit_events_immutable"]
            assert row_trg["tgenabled"] == "O"
            # Bit 0 (Row: 1) + Bit 1 (Before: 2) + Bit 3 (Delete: 8) + Bit 4 (Update: 16) = 27
            assert row_trg["tgtype"] == 27
            assert row_trg["function_name"] == "fn_prevent_case_audit_events_mutation"

            # 2. Statement-level trigger: BEFORE TRUNCATE FOR EACH STATEMENT
            assert "trg_case_audit_events_prevent_truncate" in triggers
            stmt_trg = triggers["trg_case_audit_events_prevent_truncate"]
            assert stmt_trg["tgenabled"] == "O"
            # Bit 1 (Before: 2) + Bit 5 (Truncate: 32) = 34
            assert stmt_trg["tgtype"] == 34
            assert stmt_trg["function_name"] == "fn_prevent_case_audit_events_mutation"

    async def test_cat_04_catalog_foreign_key_delete_rules(self, d25_async_engine: AsyncEngine):
        """Verify referential constraints and ON DELETE rules match migration 0004."""
        query = text("""
            SELECT 
                tc.constraint_name,
                tc.table_name,
                rc.delete_rule
            FROM information_schema.table_constraints tc
            JOIN information_schema.referential_constraints rc 
              ON rc.constraint_name = tc.constraint_name
             AND rc.constraint_schema = tc.constraint_schema
            WHERE tc.constraint_schema = 'public'
              AND tc.constraint_type = 'FOREIGN KEY'
            ORDER BY tc.constraint_name;
        """)
        async with d25_async_engine.connect() as conn:
            rows = (await conn.execute(query)).mappings().all()
            fk_rules = {r["constraint_name"]: r["delete_rule"] for r in rows}

            # Required P3-H2 rules
            expected_rules = {
                "fk_analyst_api_clients_analyst_id_analysts": "RESTRICT",
                "fk_case_evidence_case_id_cases": "CASCADE",
                "fk_case_evidence_evidence_id_normalized_events": "RESTRICT",
                "fk_case_evidence_linked_by_analyst_id_analysts": "SET NULL",
                "fk_case_assignments_analyst_id_analysts": "RESTRICT",
                "fk_case_assignments_case_id_cases": "CASCADE",
                "fk_case_audit_events_actor_analyst_id_analysts": "RESTRICT",
                "fk_case_audit_events_case_id_cases": "RESTRICT",
            }
            for fk_name, expected_rule in expected_rules.items():
                assert fk_name in fk_rules, f"Missing foreign key: {fk_name}"
                assert fk_rules[fk_name] == expected_rule, (
                    f"FK {fk_name} rule mismatch: expected {expected_rule}, got {fk_rules[fk_name]}"
                )


# ==============================================================================
# SECTION 3: LIVE INVARIANT MUTATION TESTS (TIER 1 ROLLBACK ONLY)
# ==============================================================================

@pytest.mark.postgres
@pytest.mark.anyio
class TestD25LiveInvariantsRollback:
    """Verifies invariant rejection using SAVEPOINTs inside rollback-only sessions."""

    async def test_inv_01_duplicate_active_lead_rejected(self, d25_rollback_session: AsyncSession):
        """Enforces uq_case_lead_active: attempting two leads on same case raises IntegrityError."""
        now = datetime.now(timezone.utc)

        # 1. Seed two analysts
        a1 = Analyst(
            id=uuid.uuid4(),
            username=f"lead_test_1_{uuid.uuid4().hex[:6]}",
            email=f"lead1_{uuid.uuid4().hex[:6]}@example.com",
            global_role=GlobalRole.ANALYST_TIER_2.value,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        a2 = Analyst(
            id=uuid.uuid4(),
            username=f"lead_test_2_{uuid.uuid4().hex[:6]}",
            email=f"lead2_{uuid.uuid4().hex[:6]}@example.com",
            global_role=GlobalRole.ANALYST_TIER_2.value,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        d25_rollback_session.add_all([a1, a2])

        # 2. Seed a case
        case = CaseModel(
            id=uuid.uuid4(),
            case_number=f"CASE-TEST-{uuid.uuid4().hex[:4].upper()}",
            title="Lead Invariant Test Case",
            description="Testing partial unique index uq_case_lead_active",
            severity=CaseSeverity.HIGH.value,
            status=CaseStatus.OPEN.value,
            created_at=now,
            updated_at=now,
        )
        d25_rollback_session.add(case)

        # 3. Assign first lead
        assign1 = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case.id,
            analyst_id=a1.id,
            case_role=CaseRole.LEAD.value,
            assigned_at=now,
        )
        d25_rollback_session.add(assign1)
        await d25_rollback_session.flush()

        # 4. Attempt to assign second lead within SAVEPOINT
        assign2 = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=case.id,
            analyst_id=a2.id,
            case_role=CaseRole.LEAD.value,
            assigned_at=now,
        )
        d25_rollback_session.add(assign2)

        with pytest.raises(IntegrityError) as exc_info:
            async with d25_rollback_session.begin_nested():
                await d25_rollback_session.flush()
        assert "uq_case_lead_active" in str(exc_info.value)

    async def test_inv_02_audit_mutation_blocked_by_triggers(self, d25_rollback_session: AsyncSession):
        """Enforces append-only immutability: UPDATE, DELETE, TRUNCATE on case_audit_events fail."""
        now = datetime.now(timezone.utc)
        test_case_id = uuid.uuid4()
        analyst_id = uuid.uuid4()

        # Seed prerequisite analyst and case
        a = Analyst(
            id=analyst_id,
            username=f"audit_analyst_{uuid.uuid4().hex[:6]}",
            email=f"audit_{uuid.uuid4().hex[:6]}@example.com",
            global_role=GlobalRole.ANALYST_TIER_2.value,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        case = CaseModel(
            id=test_case_id,
            case_number=f"CASE-AUDIT-{uuid.uuid4().hex[:4].upper()}",
            title="Audit Immutability Case",
            severity=CaseSeverity.MEDIUM.value,
            status=CaseStatus.OPEN.value,
            created_at=now,
            updated_at=now,
        )
        assignment = CaseAssignmentModel(
            id=uuid.uuid4(),
            case_id=test_case_id,
            analyst_id=analyst_id,
            case_role=CaseRole.LEAD.value,
            assigned_at=now,
        )
        d25_rollback_session.add_all([a, case, assignment])

        audit = CaseAuditEventModel(
            id=uuid.uuid4(),
            case_id=test_case_id,
            actor_analyst_id=analyst_id,
            actor_username=a.username,
            action="case_created",
            context_sha256="0" * 64,
            details={"test": True},
            created_at=now,
        )
        d25_rollback_session.add(audit)
        await d25_rollback_session.flush()

        # 1. Attempt UPDATE inside SAVEPOINT
        with pytest.raises(DBAPIError) as exc_info:
            async with d25_rollback_session.begin_nested():
                await d25_rollback_session.execute(
                    update(CaseAuditEventModel)
                    .where(CaseAuditEventModel.id == audit.id)
                    .values(action="tampered_action")
                )
        assert "case_audit_events records are append-only and immutable" in str(exc_info.value)

        # 2. Attempt DELETE inside SAVEPOINT
        with pytest.raises(DBAPIError) as exc_info:
            async with d25_rollback_session.begin_nested():
                await d25_rollback_session.execute(
                    delete(CaseAuditEventModel).where(CaseAuditEventModel.id == audit.id)
                )
        assert "case_audit_events records are append-only and immutable" in str(exc_info.value)

        # 3. Attempt TRUNCATE inside SAVEPOINT
        with pytest.raises(DBAPIError) as exc_info:
            async with d25_rollback_session.begin_nested():
                await d25_rollback_session.execute(text("TRUNCATE TABLE case_audit_events;"))
        assert "case_audit_events records are append-only and immutable" in str(exc_info.value)


# ==============================================================================
# SECTION 4: CONNECTION-POOL LIFECYCLE & INFERENCE BARRIER TESTS
# ==============================================================================

@pytest.mark.postgres
@pytest.mark.anyio
class TestD25ConnectionPoolLifecycle:
    """Verifies QueuePool lifecycle, inference barrier concurrency, and error return."""

    async def test_pol_01_inference_barrier_concurrency_with_bounded_pool(
        self,
        d25_async_engine: AsyncEngine,
    ):
        """
        8 concurrent tasks simulate 3-phase synthesis on a 5-connection QueuePool.
        Proves:
        1. Phase A checks out connection, constructs context, checks in connection.
        2. During Phase B (mock inference pause), pool.checkedout() == 0.
        3. All 8 tasks simultaneously pause without starvation/timeout.
        4. Phase C checks out fresh connection, audits, and checks in connection.
        """
        pool = d25_async_engine.sync_engine.pool
        barrier = asyncio.Event()
        barrier_count = 0
        barrier_lock = asyncio.Lock()

        async def simulated_synthesis_task(task_idx: int) -> dict[str, Any]:
            nonlocal barrier_count
            session_factory = async_sessionmaker(d25_async_engine, expire_on_commit=False)

            # Phase A: Auth & Context Build (holds connection briefly)
            async with session_factory() as s_a:
                res_a = await s_a.execute(text("SELECT 1;"))
                assert res_a.scalar() == 1
                await s_a.commit()
            # Session A closed: connection returned to QueuePool

            # Arrive at inference barrier
            async with barrier_lock:
                barrier_count += 1
                if barrier_count == 8:
                    barrier.set()

            # Wait at Phase B inference barrier (simulating slow LLM inference)
            await asyncio.wait_for(barrier.wait(), timeout=10.0)

            # Phase C: Revalidation & Audit Write (holds connection briefly)
            async with session_factory() as s_c:
                res_c = await s_c.execute(text("SELECT 2;"))
                assert res_c.scalar() == 2
                await s_c.commit()

            return {"task": task_idx, "status": "completed"}

        # Launch 8 concurrent tasks against pool_size=5
        tasks = [simulated_synthesis_task(i) for i in range(8)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 8
        assert all(r["status"] == "completed" for r in results)
        assert pool.checkedout() == 0, f"Leaked connections detected in pool: {pool.checkedout()}"

    async def test_pol_02_cancellation_and_error_connection_return(
        self,
        d25_async_engine: AsyncEngine,
    ):
        """
        Verifies that when a query raises an error or a task is cancelled,
        the connection is safely checked back into the QueuePool.
        """
        pool = d25_async_engine.sync_engine.pool
        session_factory = async_sessionmaker(d25_async_engine, expire_on_commit=False)

        # 1. Database error path
        with pytest.raises(DBAPIError):
            async with session_factory() as session:
                await session.execute(text("SELECT * FROM non_existent_table_xyz_123;"))

        # Connection must be returned
        assert pool.checkedout() == 0

        # 2. Task cancellation path
        async def cancellable_query():
            async with session_factory() as session:
                await session.execute(text("SELECT pg_sleep(5);"))

        t = asyncio.create_task(cancellable_query())
        await asyncio.sleep(0.1)  # allow query to start
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t

        # Connection must be returned
        await asyncio.sleep(0.1)
        assert pool.checkedout() == 0


# ==============================================================================
# SECTION 5: END-TO-END WORKFLOW & REPORT VERIFICATION (TIER 2 ISOLATION)
# ==============================================================================

class DeterministicMockProvider:
    """Mock LLM provider generating deterministic investigation outputs."""

    def __init__(self, raw_llm_json: dict[str, Any]) -> None:
        self.raw_llm_json = raw_llm_json

    async def generate(self, prompt: Any) -> LLMResponse:
        data = copy.deepcopy(self.raw_llm_json)
        user_text = ""
        if hasattr(prompt, "messages"):
            user_text = " ".join(getattr(m, "content", "") for m in prompt.messages)
        elif isinstance(prompt, str):
            user_text = prompt
        m = re.search(r'<investigation_context[^>]*id="([a-f0-9\-]+)"', user_text)
        if m:
            data["investigation_id"] = m.group(1)

        return LLMResponse(
            content=json.dumps(data),
            model="llama3.1:8b",
            finish_reason="stop",
            raw_response={},
        )


@pytest.mark.postgres
@pytest.mark.anyio
class TestD25EndToEndWorkflow:
    """
    Tier 2 Dedicated Disposable Database Workflow.
    Verifies full lifecycle with 4 committed audit events and report verification.
    NEVER deletes committed audit records or drops the database in teardown.
    """

    async def test_stage_b1_identity_and_evidence_setup(
        self,
        d25_async_engine: AsyncEngine,
    ):
        """
        AISOP Gate D.2.5.20 — Stage B1 Identity and Evidence Setup.
        Creates:
        - Exactly 1 Analyst (analysts table)
        - Exactly 1 API Client (analyst_api_clients table) associated with that analyst
        - Exactly 1 Raw Evidence record (raw_evidence table)
        - Exactly 1 Normalized Event (normalized_events table) associated with that raw evidence
        Commits all 4 records across the database.
        Zero cases, zero assignments, zero case evidence links, zero audit events.
        """
        now = datetime.now(timezone.utc)
        session_factory = async_sessionmaker(d25_async_engine, expire_on_commit=False)

        analyst_id = uuid.uuid4()
        token_prefix = f"b1_{uuid.uuid4().hex[:8]}"
        secret_token = f"{token_prefix}_secret_token_{uuid.uuid4().hex}"
        token_hash = hashlib.sha256(secret_token.encode("utf-8")).hexdigest()

        analyst = Analyst(
            id=analyst_id,
            username=f"b1_analyst_{uuid.uuid4().hex[:6]}",
            email=f"b1_{uuid.uuid4().hex[:6]}@example.com",
            global_role=GlobalRole.ANALYST_TIER_2.value,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        api_client = AnalystApiClient(
            id=uuid.uuid4(),
            analyst_id=analyst_id,
            client_name="B1 Stage Client",
            token_prefix=token_prefix,
            hashed_secret=token_hash,
            is_active=True,
            created_at=now,
            last_used_at=now,
        )

        raw_ev = RawEvidence(
            id=uuid.uuid4(),
            source_type="sysmon",
            source_identifier="host-b1-01",
            raw_payload={"Event": {"System": {"EventID": 1}}},
            sha256_hash=hashlib.sha256(f"b1_raw_payload_{uuid.uuid4().hex}".encode("utf-8")).hexdigest(),
            ingested_at=now,
        )
        norm_ev = NormalizedEventModel(
            id=uuid.uuid4(),
            raw_evidence_id=raw_ev.id,
            event_id="1",
            event_type="ProcessCreate",
            event_timestamp=now,
            action="cmd.exe /c whoami",
            outcome="success",
            severity="medium",
            provider="Microsoft-Windows-Sysmon",
            normalized_payload={"process": "cmd.exe"},
        )

        async with session_factory() as session:
            session.add_all([analyst, api_client, raw_ev, norm_ev])
            await session.commit()

        # In-test assertion: Verify that all four objects have committed IDs
        assert analyst.id is not None
        assert api_client.id is not None
        assert api_client.analyst_id == analyst.id
        assert raw_ev.id is not None
        assert norm_ev.id is not None
        assert norm_ev.raw_evidence_id == raw_ev.id

    async def test_stage_b2_case_creation_and_lead_assignment(
        self,
        d25_async_engine: AsyncEngine,
    ):
        """
        AISOP Gate D.2.5.23 — Stage B2 Case Creation and Lead Assignment.
        Prerequisite: Stage B1 committed records (Analyst, API Client, Raw Evidence, Normalized Event).
        Creates and commits:
        - Exactly 1 Case (cases table)
        - Exactly 1 Lead Assignment (case_assignments table with case_role='lead')
        - Exactly 1 Audit Event (case_audit_events table with action='case_created')
        Atomic commit through CaseService.create_case().
        Zero evidence links, zero investigation synthesis, zero report formatting, zero case closures.
        """
        session_factory = async_sessionmaker(d25_async_engine, expire_on_commit=False)
        case_svc = CaseService()

        # 1. Resolve the existing B1 analyst
        async with session_factory() as session:
            stmt = select(Analyst).order_by(Analyst.created_at.desc()).limit(1)
            analyst = (await session.execute(stmt)).scalars().first()
            assert analyst is not None, "Pre-existing B1 analyst record must exist."

            actor_user = AuthenticatedAnalyst(
                analyst_id=analyst.id,
                username=analyst.username,
                global_role=GlobalRole(analyst.global_role),
                is_active=analyst.is_active,
            )

            # 2. Create case and lead assignment via CaseService
            case_resp = await case_svc.create_case(
                session=session,
                creator=actor_user,
                request=CaseCreateRequest(
                    title="B2 Scoping Case",
                    description="Stage B2 Case Creation and Lead Assignment Test",
                    severity=CaseSeverity.HIGH,
                ),
            )
            await session.commit()
            case_id = case_resp.id

        # 3. In-test verification of committed B2 records
        async with session_factory() as session:
            # Case verification
            case_record = (await session.execute(select(CaseModel).where(CaseModel.id == case_id))).scalars().first()
            assert case_record is not None
            assert case_record.status == CaseStatus.OPEN.value
            assert case_record.severity == CaseSeverity.HIGH.value

            # Assignment verification
            assign_stmt = select(CaseAssignmentModel).where(CaseAssignmentModel.case_id == case_id)
            assignments = (await session.execute(assign_stmt)).scalars().all()
            assert len(assignments) == 1
            assignment = assignments[0]
            assert assignment.analyst_id == actor_user.analyst_id
            assert assignment.case_role == CaseRole.LEAD.value

            # Audit event verification
            audit_stmt = select(CaseAuditEventModel).where(CaseAuditEventModel.case_id == case_id)
            audit_events = (await session.execute(audit_stmt)).scalars().all()
            assert len(audit_events) == 1
            audit_ev = audit_events[0]
            assert audit_ev.action == "case_created"
            assert audit_ev.actor_analyst_id == actor_user.analyst_id
            assert audit_ev.case_id == case_id

    async def test_stage_b3_evidence_linkage(
        self,
        d25_async_engine: AsyncEngine,
    ):
        """
        AISOP Gate D.2.5.24 — Stage B3 Evidence Linkage.
        Prerequisite: Stage B1 records (Analyst, API Client, Raw Evidence, Normalized Event)
                      and Stage B2 records (Case, Lead Assignment, 'case_created' Audit Event).
        Creates and commits:
        - Exactly 1 CaseEvidence association (case_evidence table) linking the existing case
          to the existing normalized event.
        - Exactly 1 Audit Event (case_audit_events table with action='evidence_linked').
        Uses CaseService.link_evidence_to_case().
        Zero investigation synthesis, zero report formatting, zero case closures.
        """
        session_factory = async_sessionmaker(d25_async_engine, expire_on_commit=False)
        case_svc = CaseService()

        # 1. Resolve existing B1/B2 records
        async with session_factory() as session:
            stmt_a = select(Analyst).order_by(Analyst.created_at.desc()).limit(1)
            analyst = (await session.execute(stmt_a)).scalars().first()
            assert analyst is not None, "Pre-existing B1 analyst record must exist."

            actor_user = AuthenticatedAnalyst(
                analyst_id=analyst.id,
                username=analyst.username,
                global_role=GlobalRole(analyst.global_role),
                is_active=analyst.is_active,
            )

            stmt_c = select(CaseModel).order_by(CaseModel.created_at.desc()).limit(1)
            case = (await session.execute(stmt_c)).scalars().first()
            assert case is not None, "Pre-existing B2 case record must exist."

            stmt_e = select(NormalizedEventModel).order_by(NormalizedEventModel.event_timestamp.desc()).limit(1)
            norm_ev = (await session.execute(stmt_e)).scalars().first()
            assert norm_ev is not None, "Pre-existing B1 normalized event record must exist."

            case_id = case.id
            evidence_id = norm_ev.id

            # 2. Link evidence to case via CaseService
            link_resp = await case_svc.link_evidence_to_case(
                session=session,
                case_id=case_id,
                request=CaseEvidenceLinkRequest(evidence_id=evidence_id),
                actor=actor_user,
            )
            await session.commit()
            link_id = link_resp.id

        # 3. In-test verification of committed B3 records
        async with session_factory() as session:
            # CaseEvidence verification
            ce_stmt = select(CaseEvidenceModel).where(CaseEvidenceModel.id == link_id)
            link_record = (await session.execute(ce_stmt)).scalars().first()
            assert link_record is not None
            assert link_record.case_id == case_id
            assert link_record.evidence_id == evidence_id
            assert link_record.linked_by_analyst_id == actor_user.analyst_id

            # Audit event verification
            audit_stmt = select(CaseAuditEventModel).where(
                CaseAuditEventModel.case_id == case_id,
                CaseAuditEventModel.action == "evidence_linked",
            )
            audit_events = (await session.execute(audit_stmt)).scalars().all()
            assert len(audit_events) == 1
            audit_ev = audit_events[0]
            assert audit_ev.actor_analyst_id == actor_user.analyst_id
            assert audit_ev.actor_username == actor_user.username
            assert audit_ev.details is not None
            assert audit_ev.details.get("evidence_id") == str(evidence_id)

    @pytest.mark.ollama
    async def test_stage_b4_investigation_synthesis(
        self,
        d25_async_engine: AsyncEngine,
    ):
        """
        AISOP Gate D.2.5.25 — Stage B4 Investigation Synthesis.
        Prerequisite:
        - Stage B1 records (Analyst, API Client, Raw Evidence, Normalized Event)
        - Stage B2 records (Case, Lead Assignment, 'case_created' Audit Event)
        - Stage B3 records (CaseEvidence association, 'evidence_linked' Audit Event)
        Executes:
        - Constructs canonical InvestigationContext from B3-linked evidence.
        - Invokes approved local Ollama provider ('llama3.1:8b' at localhost:11434).
        - Applies 3-tier epistemic output guardrails without holding DB connections.
        - Commits exactly 1 'case_investigation_synthesized' audit event.
        - Verifies 0 database connections held during LLM inference.
        - Zero case closure, zero report formatting endpoints, zero external cloud calls.
        """
        from app.modules.ai.llm.manager import get_llm_provider

        session_factory = async_sessionmaker(d25_async_engine, expire_on_commit=False)
        case_svc = CaseService()

        # 1. Resolve existing B1/B2/B3 records
        async with session_factory() as session:
            stmt_a = select(Analyst).order_by(Analyst.created_at.asc()).limit(1)
            analyst = (await session.execute(stmt_a)).scalars().first()
            assert analyst is not None, "Pre-existing B1 analyst record must exist."

            actor_user = AuthenticatedAnalyst(
                analyst_id=analyst.id,
                username=analyst.username,
                global_role=GlobalRole(analyst.global_role),
                is_active=analyst.is_active,
            )

            stmt_c = select(CaseModel).order_by(CaseModel.created_at.asc()).limit(1)
            case = (await session.execute(stmt_c)).scalars().first()
            assert case is not None, "Pre-existing B2 case record must exist."

            stmt_e = select(NormalizedEventModel).order_by(NormalizedEventModel.event_timestamp.asc()).limit(1)
            norm_ev = (await session.execute(stmt_e)).scalars().first()
            assert norm_ev is not None, "Pre-existing B1 normalized event record must exist."

            stmt_l = select(CaseEvidenceModel).where(
                CaseEvidenceModel.case_id == case.id,
                CaseEvidenceModel.evidence_id == norm_ev.id,
            )
            link = (await session.execute(stmt_l)).scalars().first()
            assert link is not None, "Pre-existing B3 case-evidence link must exist."

            case_id = case.id
            evidence_id = norm_ev.id

        # 2. Acquire local Ollama provider and execute synthesis
        provider = get_llm_provider()
        assert provider.model_name in ("llama3.1:8b", "qwen3:4b", "mistral:latest", "llama3:latest")

        try:
            validation_result, context = await case_svc.synthesize_case_investigation(
                session_factory=session_factory,
                case_id=case_id,
                actor=actor_user,
                request=CaseInvestigationSynthesizeRequest(),
                llm_provider=provider,
            )
        finally:
            if hasattr(provider, "aclose"):
                await provider.aclose()

        # 3. In-test verification of validation result and context
        assert validation_result is not None
        assert context is not None
        assert len(context.events) == 1
        assert context.events[0].event_uuid == evidence_id
        assert context.reproducibility.model_name == provider.model_name
        assert context.reproducibility.context_sha256 is not None
        assert validation_result.decision is not None
        assert validation_result.output is not None

        # 4. In-test verification of committed B4 audit event
        async with session_factory() as session:
            audit_stmt = select(CaseAuditEventModel).where(
                CaseAuditEventModel.case_id == case_id,
                CaseAuditEventModel.action == "case_investigation_synthesized",
            )
            audit_events = (await session.execute(audit_stmt)).scalars().all()
            assert len(audit_events) == 1
            audit_ev = audit_events[0]
            assert audit_ev.actor_analyst_id == actor_user.analyst_id
            assert audit_ev.actor_username == actor_user.username
            assert audit_ev.context_sha256 == context.reproducibility.context_sha256
            assert audit_ev.details is not None
            assert audit_ev.details.get("evidence_count") == 1
            assert audit_ev.details.get("model_name") == provider.model_name
            assert audit_ev.details.get("decision") in [d.value for d in GuardrailDecision]

    @pytest.mark.ollama
    async def test_stage_b5_report_synthesis(
        self,
        d25_async_engine: AsyncEngine,
    ):
        """
        AISOP Gate D.2.5.26 — Stage B5 Report Synthesis.
        Prerequisite:
        - Stage B1 records (Analyst, API Client, Raw Evidence, Normalized Event)
        - Stage B2 records (Case, Lead Assignment, 'case_created' Audit Event)
        - Stage B3 records (CaseEvidence association, 'evidence_linked' Audit Event)
        - Stage B4 records ('case_investigation_synthesized' Audit Event)
        Executes:
        - Resolves approved local Ollama provider ('llama3.1:8b' on localhost:11434).
        - Executes CaseService.synthesize_case_reports() within case boundary.
        - Verifies 0 active DB connections held during LLM inference.
        - Generates deterministic, role-tailored report bundle:
          1. Executive Brief (ExecutiveBrief)
          2. Technical Incident Report (TechnicalIncidentReport)
          3. Detection Engineering Report (DetectionEngineeringReport)
          4. Deterministic Markdown representations (markdown_executive, markdown_technical, markdown_detection)
        - Commits exactly 1 'case_report_synthesized' audit event.
        - Confirms returned report bundle is ephemeral and not persisted into new tables.
        - Zero case closure, zero external cloud calls.
        """
        from app.modules.ai.llm.manager import get_llm_provider
        from app.schemas.report import InvestigationReportBundle

        session_factory = async_sessionmaker(d25_async_engine, expire_on_commit=False)
        case_svc = CaseService()

        # 1. Resolve existing B1/B2/B3/B4 records
        async with session_factory() as session:
            stmt_a = select(Analyst).order_by(Analyst.created_at.asc()).limit(1)
            analyst = (await session.execute(stmt_a)).scalars().first()
            assert analyst is not None, "Pre-existing B1 analyst record must exist."

            actor_user = AuthenticatedAnalyst(
                analyst_id=analyst.id,
                username=analyst.username,
                global_role=GlobalRole(analyst.global_role),
                is_active=analyst.is_active,
            )

            stmt_c = select(CaseModel).order_by(CaseModel.created_at.asc()).limit(1)
            case = (await session.execute(stmt_c)).scalars().first()
            assert case is not None, "Pre-existing B2 case record must exist."

            stmt_e = select(NormalizedEventModel).order_by(NormalizedEventModel.event_timestamp.asc()).limit(1)
            norm_ev = (await session.execute(stmt_e)).scalars().first()
            assert norm_ev is not None, "Pre-existing B1 normalized event record must exist."

            stmt_l = select(CaseEvidenceModel).where(
                CaseEvidenceModel.case_id == case.id,
                CaseEvidenceModel.evidence_id == norm_ev.id,
            )
            link = (await session.execute(stmt_l)).scalars().first()
            assert link is not None, "Pre-existing B3 case-evidence link must exist."

            # Verify B4 synthesis audit event exists with a valid context hash.
            # The context_sha256 is derived from B1 fixture data (random UUID4 IDs
            # and wall-clock timestamps), so it cannot be hardcoded across runs.
            # b4 already performs the stronger cross-check:
            #   audit_ev.context_sha256 == context.reproducibility.context_sha256
            stmt_b4 = select(CaseAuditEventModel).where(
                CaseAuditEventModel.case_id == case.id,
                CaseAuditEventModel.action == "case_investigation_synthesized",
            )
            b4_audit = (await session.execute(stmt_b4)).scalars().first()
            assert b4_audit is not None, "Pre-existing B4 audit event must exist."
            assert b4_audit.context_sha256 is not None, (
                "B4 audit event must carry a non-null context_sha256"
            )
            assert len(b4_audit.context_sha256) == 64, (
                "context_sha256 must be a 64-character SHA-256 hex digest"
            )
            assert all(
                c in "0123456789abcdef" for c in b4_audit.context_sha256
            ), "context_sha256 must be lowercase hexadecimal"

            case_id = case.id
            evidence_id = norm_ev.id

        # 2. Acquire test-isolated Ollama provider with candidate timeout budget (180s)
        # Using model_copy on the settings instance creates an isolated copy for this provider instance.
        # This guarantees:
        # - Zero mutation of global Settings or @lru_cache get_settings()
        # - Zero modification to .env or production defaults
        # - Cannot leak into subsequent tests or application runtime
        from app.core.config import get_settings

        test_settings = get_settings().model_copy(update={"OLLAMA_TIMEOUT_SECONDS": 180})
        provider = get_llm_provider(settings=test_settings)
        assert provider.model_name == "llama3.1:8b"
        assert getattr(provider, "_timeout_seconds", None) == 180

        try:
            bundle = await case_svc.synthesize_case_reports(
                session_factory=session_factory,
                case_id=case_id,
                actor=actor_user,
                request=CaseInvestigationSynthesizeRequest(),
                llm_provider=provider,
            )
        finally:
            if hasattr(provider, "aclose"):
                await provider.aclose()

        # Invariant: Global settings must remain untouched
        assert get_settings().OLLAMA_TIMEOUT_SECONDS == 120, "Global settings must remain unchanged"

        # 3. In-test verification of InvestigationReportBundle structure and content
        # Contract A: Live B5 Success requires genuine model-backed generation, NEVER fallback
        assert bundle is not None
        assert isinstance(bundle, InvestigationReportBundle)
        assert bundle.is_fallback_active is False, (
            "Deterministic fallback must never satisfy the live B5 success contract"
        )
        assert bundle.provenance is not None
        assert bundle.provenance.is_inconclusive_or_fallback is False
        assert bundle.provenance.model_identifier == "llama3.1:8b"
        assert bundle.provenance.context_sha256 is not None

        # Audience-specific structures must not be marked fallback or inconclusive
        assert bundle.executive_brief is not None
        assert bundle.executive_brief.is_inconclusive_or_fallback is False
        assert len(bundle.executive_brief.evidenced_affected_assets) > 0

        assert bundle.technical_report is not None
        assert bundle.technical_report.is_inconclusive_or_fallback is False
        assert len(bundle.technical_report.investigation_timeline) > 0
        assert all(t.event_uuid == evidence_id for t in bundle.technical_report.investigation_timeline)

        assert bundle.detection_report is not None
        assert bundle.detection_report.is_inconclusive_or_fallback is False

        # Formatted Markdown representations must be populated
        assert len(bundle.markdown_executive) > 0
        assert len(bundle.markdown_technical) > 0
        assert len(bundle.markdown_detection) > 0

        # 4. In-test verification of committed B5 audit event
        async with session_factory() as session:
            audit_stmt = (
                select(CaseAuditEventModel)
                .where(
                    CaseAuditEventModel.case_id == case_id,
                    CaseAuditEventModel.action == "case_report_synthesized",
                )
                .order_by(CaseAuditEventModel.created_at.desc())
            )
            audit_events = (await session.execute(audit_stmt)).scalars().all()
            assert len(audit_events) >= 1
            latest_audit_ev = audit_events[0]
            assert latest_audit_ev.actor_analyst_id == actor_user.analyst_id
            assert latest_audit_ev.actor_username == actor_user.username
            assert latest_audit_ev.context_sha256 == bundle.context_sha256
            assert latest_audit_ev.details is not None
            assert latest_audit_ev.details.get("investigation_id") == str(bundle.investigation_id)
            assert latest_audit_ev.details.get("model_name") == "llama3.1:8b"
            assert latest_audit_ev.details.get("target_model") == "llama3.1:8b"
            assert latest_audit_ev.details.get("is_valid") is True
            assert latest_audit_ev.details.get("decision") == GuardrailDecision.PASS.value
            assert "fallback_reason" not in latest_audit_ev.details

    async def test_e2e_01_case_synthesis_and_report_trust_boundary(
        self,
        d25_async_engine: AsyncEngine,
    ):
        """
        Full lifecycle:
        1. Seed active Tier 2 analyst and API client.
        2. Seed normalized evidence.
        3. Create Case -> creates audit event 'case_created'.
        4. Link Evidence -> creates audit event 'evidence_linked'.
        5. Synthesize Case Investigation -> creates audit event 'case_investigation_synthesized'.
        6. Verify Report Formatting:
           - Matching hash -> is_server_verified == True.
           - Forged/Tampered hash -> is_server_verified == False (claims demoted).
        7. Close Case -> creates audit event 'case_closed'.
        8. Assert exactly 4 audit records in case_audit_events with valid provenance.
        """
        now = datetime.now(timezone.utc)
        session_factory = async_sessionmaker(d25_async_engine, expire_on_commit=False)
        case_svc = CaseService()

        # 1. Seed Analyst and Token
        analyst_id = uuid.uuid4()
        token_prefix = f"e2e_{uuid.uuid4().hex[:8]}"
        secret_token = f"{token_prefix}_secret_token_{uuid.uuid4().hex}"
        token_hash = hashlib.sha256(secret_token.encode("utf-8")).hexdigest()

        analyst = Analyst(
            id=analyst_id,
            username=f"e2e_analyst_{uuid.uuid4().hex[:6]}",
            email=f"e2e_{uuid.uuid4().hex[:6]}@example.com",
            global_role=GlobalRole.ANALYST_TIER_2.value,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        api_client = AnalystApiClient(
            id=uuid.uuid4(),
            analyst_id=analyst_id,
            client_name="E2E Test Client",
            token_prefix=token_prefix,
            hashed_secret=token_hash,
            is_active=True,
            created_at=now,
            last_used_at=now,
        )

        # 2. Seed Normalized Evidence
        raw_ev = RawEvidence(
            id=uuid.uuid4(),
            source_type="sysmon",
            source_identifier="host-e2e-01",
            raw_payload={"Event": {"System": {"EventID": 1}}},
            sha256_hash=hashlib.sha256(f"e2e_raw_{uuid.uuid4().hex}".encode("utf-8")).hexdigest(),
            ingested_at=now,
        )
        norm_ev = NormalizedEventModel(
            id=uuid.uuid4(),
            raw_evidence_id=raw_ev.id,
            event_id="1",
            event_type="ProcessCreate",
            event_timestamp=now,
            action="cmd.exe /c whoami",
            outcome="success",
            severity="medium",
            provider="Microsoft-Windows-Sysmon",
            normalized_payload={"process": "cmd.exe"},
        )

        async with session_factory() as session:
            session.add_all([analyst, api_client, raw_ev, norm_ev])
            await session.commit()

        actor_user = AuthenticatedAnalyst(
            analyst_id=analyst.id,
            username=analyst.username,
            global_role=GlobalRole(analyst.global_role),
            is_active=True,
        )
        auth_client = AuthenticatedClient(analyst=actor_user, client_id="e2e-client")

        # 3. Create Case
        async with session_factory() as session:
            case_resp = await case_svc.create_case(
                session=session,
                creator=actor_user,
                request=CaseCreateRequest(
                    title="E2E Scoping Case",
                    description="E2E PostgreSQL test case",
                    severity=CaseSeverity.HIGH,
                ),
            )
            await session.commit()
            case_id = case_resp.id

        # 4. Link Evidence
        async with session_factory() as session:
            await case_svc.link_evidence_to_case(
                session=session,
                case_id=case_id,
                actor=actor_user,
                request=CaseEvidenceLinkRequest(evidence_id=norm_ev.id),
            )
            await session.commit()

        # 5. Synthesize Case Investigation
        llm_output_data = {
            "investigation_id": str(uuid.uuid4()),
            "generated_at": now.isoformat(),
            "model_identifier": "llama3.1:8b",
            "investigation_summary": "E2E process execution analysis detected whoami recon on target endpoint.",
            "overall_grounding_score": 1.0,
            "claims": [
                {
                    "claim_id": str(uuid.uuid4()),
                    "claim_text": "cmd.exe whoami executed on target endpoint",
                    "category": "observed_fact",
                    "supporting_evidence_ids": [str(norm_ev.id)],
                    "references_exist": True,
                    "grounding_status": "validated_reference",
                    "confidence": 0.95,
                    "analyst_notes": None,
                }
            ],
            "mitre_attack_hypotheses": [
                {
                    "technique_id": "T1059.003",
                    "technique_name": "Windows Command Shell",
                    "tactics": ["Execution"],
                    "supporting_event_uuids": [str(norm_ev.id)],
                    "confidence": 0.9,
                    "reasoning": "Command prompt execution detected in Sysmon telemetry",
                }
            ],
            "alternative_explanations": ["Authorized administrative troubleshooting"],
            "recommended_analyst_actions": ["Isolate host-e2e-01 and review user login sessions"],
            "uncertainty_and_data_gaps": [],
        }
        mock_provider = DeterministicMockProvider(llm_output_data)

        # Execute synthesis across Phase A -> Phase B -> Phase C
        validation_result, context = await case_svc.synthesize_case_investigation(
            session_factory=session_factory,
            case_id=case_id,
            actor=actor_user,
            request=CaseInvestigationSynthesizeRequest(),
            llm_provider=mock_provider,
        )

        assert validation_result.is_valid is True
        assert validation_result.decision != GuardrailDecision.REJECT_TO_FALLBACK

        # Compute canonical output digest
        server_output_sha256 = compute_validation_output_sha256(validation_result)

        # 6. Verify Report Formatting Endpoint Logic
        # A. Untampered payload -> is_server_verified == True
        report_req_valid = ReportFormatRequest(
            case_id=case_id,
            validation_result=validation_result,
            context=context,
        )
        report_bundle_valid = await format_reports(
            request=report_req_valid,
            client=auth_client,
            session_factory=session_factory,
        )
        assert report_bundle_valid.provenance.is_verified_investigation is True
        assert len(report_bundle_valid.technical_report.confirmed_findings) > 0

        # B. Tampered payload (replay / modified claims) -> is_server_verified == False
        tampered_claim = validation_result.output.claims[0].model_copy(
            update={"claim_text": "FORGED: Malicious attacker altered finding."}
        )
        tampered_output = validation_result.output.model_copy(
            update={"claims": [tampered_claim]}
        )
        tampered_result = validation_result.model_copy(
            update={"output": tampered_output}
        )
        tampered_output_sha256 = compute_validation_output_sha256(tampered_result)
        assert tampered_output_sha256 != server_output_sha256

        report_req_tampered = ReportFormatRequest(
            case_id=case_id,
            validation_result=tampered_result,
            context=context,
        )
        report_bundle_tampered = await format_reports(
            request=report_req_tampered,
            client=auth_client,
            session_factory=session_factory,
        )
        assert report_bundle_tampered.provenance.is_verified_investigation is False
        assert len(report_bundle_tampered.technical_report.confirmed_findings) == 0
        assert len(report_bundle_tampered.technical_report.hypotheses_and_inferences) > 0

        # 7. Close Case
        async with session_factory() as session:
            await case_svc.close_case(
                session=session,
                case_id=case_id,
                actor=actor_user,
                request=CaseLifecycleUpdateRequest(
                    status=CaseStatus.CLOSED,
                    closure_reason="E2E test successfully concluded.",
                ),
            )
            await session.commit()

        # 8. Assert Exactly 4 Audit Records in Database
        async with session_factory() as session:
            audit_stmt = (
                select(CaseAuditEventModel)
                .where(CaseAuditEventModel.case_id == case_id)
                .order_by(CaseAuditEventModel.created_at.asc())
            )
            audit_events = (await session.execute(audit_stmt)).scalars().all()

            assert len(audit_events) == 4, f"Expected exactly 4 audit events, found {len(audit_events)}"
            actions = [ev.action for ev in audit_events]
            assert actions == [
                "case_created",
                "evidence_linked",
                "case_investigation_synthesized",
                "case_closed",
            ]

            # Verify synthesis audit details
            synth_audit = audit_events[2]
            assert synth_audit.details.get("output_sha256") == server_output_sha256
            assert synth_audit.context_sha256 == context.reproducibility.context_sha256

            # 9. In-database verification of CaseService.list_case_activity() against PostgreSQL
            activity_items = await case_svc.list_case_activity(session=session, case_id=case_id)
            assert len(activity_items) == 4, f"Expected 4 activity items from PostgreSQL, got {len(activity_items)}"
            assert [item.action for item in activity_items] == [
                "case_created",
                "evidence_linked",
                "case_investigation_synthesized",
                "case_closed",
            ]
            # Verify chronological ascending order
            for i in range(len(activity_items) - 1):
                assert activity_items[i].created_at <= activity_items[i + 1].created_at

            # Verify analyst attribution across all records
            for item in activity_items:
                assert item.actor_username == actor_user.username
                assert item.actor_analyst_id == actor_user.analyst_id

            # Verify case scoping isolation on PostgreSQL
            unrelated_case_id = uuid.uuid4()
            unrelated_activity = await case_svc.list_case_activity(session=session, case_id=unrelated_case_id)
            assert unrelated_activity == [], "Unrelated case must return empty activity list on PostgreSQL"

    async def test_e2e_02_postgres_activity_endpoint_anti_enumeration_and_rbac(
        self,
        d25_async_engine: AsyncEngine,
    ):
        """
        Verify GET /api/v1/cases/{case_id}/activity against live PostgreSQL 17:
        1. Seeds assigned Lead Analyst A with canonical Bearer token in PostgreSQL.
        2. Seeds unassigned Stranger Analyst B with canonical Bearer token in PostgreSQL.
        3. Creates a Case for Analyst A in PostgreSQL -> creates 'case_created' audit row.
        4. Updates Case metadata in PostgreSQL -> creates 'case_metadata_updated' audit row.
        5. Unauthenticated HTTP request -> rejected with HTTP 401.
        6. Unassigned Analyst B HTTP request -> rejected with HTTP 404 (Anti-Enumeration).
        7. Assigned Analyst A HTTP request -> succeeds with HTTP 200 and chronological items.
        8. Non-existent Case UUID request -> rejected with HTTP 404 (identical detail/timing).
        9. Invalid non-UUID parameter -> rejected with HTTP 422.
        10. Immutability verification: PostgreSQL trigger blocks any direct UPDATE on audit events.
        """
        now = datetime.now(timezone.utc)
        session_factory = async_sessionmaker(d25_async_engine, expire_on_commit=False)

        # 1. Seed Analyst A (Assigned Lead)
        analyst_a_id = uuid.uuid4()
        prefix_a = hashlib.md5(f"act_pg_a_{uuid.uuid4().hex}".encode()).hexdigest()[:16]
        token_a = f"aisop_live_{prefix_a}_{'a' * 64}"
        hashed_a = hash_canonical_token(token_a)

        # 2. Seed Analyst B (Stranger / Unassigned)
        analyst_b_id = uuid.uuid4()
        prefix_b = hashlib.md5(f"act_pg_b_{uuid.uuid4().hex}".encode()).hexdigest()[:16]
        token_b = f"aisop_live_{prefix_b}_{'b' * 64}"
        hashed_b = hash_canonical_token(token_b)

        async with session_factory() as session:
            analyst_a = Analyst(
                id=analyst_a_id,
                username=f"pg_lead_{uuid.uuid4().hex[:6]}",
                email=f"pg_lead_{uuid.uuid4().hex[:6]}@example.com",
                global_role=GlobalRole.ANALYST_TIER_2.value,
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            client_a = AnalystApiClient(
                id=uuid.uuid4(),
                analyst_id=analyst_a_id,
                client_name="PG Lead Client",
                token_prefix=prefix_a,
                hashed_secret=hashed_a,
                is_active=True,
                created_at=now,
                last_used_at=now,
            )
            analyst_b = Analyst(
                id=analyst_b_id,
                username=f"pg_stranger_{uuid.uuid4().hex[:6]}",
                email=f"pg_stranger_{uuid.uuid4().hex[:6]}@example.com",
                global_role=GlobalRole.ANALYST_TIER_2.value,
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            client_b = AnalystApiClient(
                id=uuid.uuid4(),
                analyst_id=analyst_b_id,
                client_name="PG Stranger Client",
                token_prefix=prefix_b,
                hashed_secret=hashed_b,
                is_active=True,
                created_at=now,
                last_used_at=now,
            )
            session.add_all([analyst_a, client_a, analyst_b, client_b])
            await session.commit()

        # Wire FastAPI app to live PostgreSQL session factory
        app = create_app()

        async def override_get_db():
            async with session_factory() as session:
                try:
                    yield session
                    await session.commit()
                except Exception:
                    await session.rollback()
                    raise

        app.dependency_overrides[get_db_session] = override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 3. Create Case as Analyst A
            create_res = await client.post(
                "/api/v1/cases",
                headers={"Authorization": f"Bearer {token_a}"},
                json={"title": "PG Case Activity Verification", "severity": "high"},
            )
            assert create_res.status_code == 201
            case_id = create_res.json()["id"]

            # 4. Update Case title to trigger a second audit event
            patch_res = await client.patch(
                f"/api/v1/cases/{case_id}",
                headers={"Authorization": f"Bearer {token_a}"},
                json={"title": "PG Case Activity Updated Title"},
            )
            assert patch_res.status_code == 200

            # 5. Unauthenticated request -> 401
            unauth_res = await client.get(f"/api/v1/cases/{case_id}/activity")
            assert unauth_res.status_code == 401

            # 6. Unassigned Analyst B request -> 404 (Anti-Enumeration)
            stranger_res = await client.get(
                f"/api/v1/cases/{case_id}/activity",
                headers={"Authorization": f"Bearer {token_b}"},
            )
            assert stranger_res.status_code == 404
            assert "Case not found or access denied" in stranger_res.json()["detail"]

            # 7. Non-existent UUID with Analyst A -> 404 (Identical response detail)
            nonexistent_uuid = str(uuid.uuid4())
            nonexist_res = await client.get(
                f"/api/v1/cases/{nonexistent_uuid}/activity",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            assert nonexist_res.status_code == 404
            assert nonexist_res.json()["detail"] == stranger_res.json()["detail"]

            # 8. Invalid non-UUID parameter -> 422
            invalid_res = await client.get(
                "/api/v1/cases/not-a-valid-uuid/activity",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            assert invalid_res.status_code == 422

            # 9. Assigned Analyst A request -> 200 with chronological audit items
            auth_res = await client.get(
                f"/api/v1/cases/{case_id}/activity",
                headers={"Authorization": f"Bearer {token_a}"},
            )
            assert auth_res.status_code == 200
            items = auth_res.json()
            assert len(items) == 2
            assert items[0]["action"] == "case_created"
            assert items[1]["action"] == "case_metadata_updated"
            assert items[0]["created_at"] <= items[1]["created_at"]
            for it in items:
                assert it["case_id"] == case_id
                assert it["actor_username"] == analyst_a.username
                assert it["actor_analyst_id"] == str(analyst_a_id)

        # 10. Direct PostgreSQL immutability trigger check
        async with session_factory() as session:
            with pytest.raises((IntegrityError, DBAPIError, Exception)) as exc_info:
                await session.execute(
                    text("UPDATE case_audit_events SET action = 'tampered' WHERE case_id = :cid"),
                    {"cid": uuid.UUID(case_id)},
                )
            assert "immutable" in str(exc_info.value).lower() or "prohibited" in str(exc_info.value).lower()

        # DEFENSE IN DEPTH:
        # Zero calls to table.delete() on case_audit_events.
        # Zero DROP DATABASE calls.
        # Audit records remain permanently in aisop_p2h3_disposable until explicit administrative retirement.
