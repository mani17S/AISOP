"""
Stage 7B (owner decision D6): offline proof of the PostgreSQL test-safety redesign. NO PostgreSQL connection is made here.

* the identity guard is pure and fail-closed (host, port, database, container, image, volume, disposable marker);
* the fixtures contain no database creation, no table-wide delete, no trigger disabling and no unguarded downgrade;
* the owned-row cleanup deletes exactly the rows a session inserted (proved on private in-memory SQLite).
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.rbac import GlobalRole
from app.db.base import Base
from app.models.analyst import Analyst
from app.models.case import CaseAuditEventModel, CaseModel
from tests import conftest as C

TESTS = Path(__file__).resolve().parents[1]
GOOD_URL = f"postgresql+psycopg://u:pw@{C.APPROVED_PG_HOST}:{C.APPROVED_PG_PORT}/{C.APPROVED_PG_DATABASE}"
GOOD_ENV = dict(C._IDENTITY_ENV)


def check(url=GOOD_URL, env=None):
    return C.verify_approved_target_identity(make_url(url), GOOD_ENV if env is None else env)


def test_the_exact_approved_target_with_the_full_identity_is_accepted():
    assert check().database == "aisop_stage7b_verify_disposable"
    assert re.match(C.DISPOSABLE_DB_NAME_PATTERN.pattern, C.APPROVED_PG_DATABASE) and C.APPROVED_PG_DATABASE not in C.PROTECTED_DATABASE_NAMES


@pytest.mark.parametrize("url", [
    f"postgresql+psycopg://u:pw@localhost:5433/{C.APPROVED_PG_DATABASE}",                 # not the exact host
    f"postgresql+psycopg://u:pw@127.0.0.1:5432/{C.APPROVED_PG_DATABASE}",                 # native Windows PostgreSQL port
    f"postgresql+psycopg://u:pw@127.0.0.1/{C.APPROVED_PG_DATABASE}",                      # port omitted -> 5432
    "postgresql+psycopg://u:pw@127.0.0.1:5433/aisop_p4b_disposable",                      # a different, even disposable-looking database
    "postgresql+psycopg://u:pw@127.0.0.1:5433/aisop_dev",
])
def test_wrong_host_port_or_database_fails_closed(url):
    with pytest.raises(RuntimeError, match="FAIL-CLOSED"):
        check(url)


@pytest.mark.parametrize("name", sorted(C._IDENTITY_ENV))
def test_each_identity_variable_is_required_and_must_match(name):
    missing = {k: v for k, v in GOOD_ENV.items() if k != name}
    with pytest.raises(RuntimeError, match=name):
        check(env=missing)
    wrong = dict(GOOD_ENV, **{name: "something-else"})
    with pytest.raises(RuntimeError, match=name) as ei:
        check(env=wrong)
    assert "something-else" not in str(ei.value)                                          # values are never echoed
    with pytest.raises(RuntimeError):
        check(env={})


def test_identity_error_messages_never_contain_the_password():
    with pytest.raises(RuntimeError) as ei:
        check(f"postgresql+psycopg://u:SECRETPW@127.0.0.1:5432/{C.APPROVED_PG_DATABASE}")
    assert "SECRETPW" not in str(ei.value)


def test_the_launcher_identity_matches_the_compose_metadata_on_disk():
    compose = (TESTS.parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
    assert f"container_name: {C.APPROVED_PG_CONTAINER}" in compose
    assert f"image: {C.APPROVED_PG_IMAGE}" in compose
    assert f'"{C.APPROVED_PG_PORT}:5432"' in compose
    assert f"name: {C.APPROVED_PG_VOLUME}" in compose


# ---------------------------------------------------------------- the fixtures contain no unsafe operation
def _code_without_comments_and_docstrings(path: Path) -> str:
    import ast
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):                                                         # drop docstrings
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)) and node.body and isinstance(node.body[0], ast.Expr) \
                and isinstance(getattr(node.body[0], "value", None), ast.Constant) and isinstance(node.body[0].value.value, str):
            node.body[0].value.value = ""
    return ast.unparse(tree)


def test_no_postgres_test_code_creates_drops_or_disables_anything():
    forbidden = ["CREATE DATABASE", "DROP DATABASE", "DISABLE TRIGGER", "ENABLE TRIGGER", "DROP SCHEMA", "DROP TABLE", "CREATE EXTENSION", "DROP EXTENSION"]
    offenders = []
    for path in [TESTS / "conftest.py", *sorted((TESTS / "integration").glob("test_postgres_*.py"))]:
        code = _code_without_comments_and_docstrings(path).upper()
        offenders += [f"{path.name}: {f}" for f in forbidden if f in code]
    assert offenders == []


def test_only_the_documented_truncate_attempt_exists_and_it_runs_inside_a_rolled_back_savepoint():
    hits = {}
    for path in sorted((TESTS / "integration").glob("test_postgres_*.py")) + [TESTS / "conftest.py"]:
        n = _code_without_comments_and_docstrings(path).upper().count("TRUNCATE TABLE")
        if n:
            hits[path.name] = n
    assert hits == {"test_postgres_case_scoping.py": 1}                                  # expects the append-only trigger to BLOCK it


def test_the_postgres_session_fixture_has_no_table_wide_delete():
    src = _code_without_comments_and_docstrings(TESTS / "conftest.py")
    body = src[src.index("async def postgres_session("):src.index("def postgres_alembic_config")]
    assert "sorted_tables" not in body and ".delete()" not in body and "DISABLE" not in body.upper()
    assert "OwnedRowTracker" in body and "verify_approved_target_identity" in body


def test_ensure_test_database_exists_never_creates():
    code = _code_without_comments_and_docstrings(TESTS / "conftest.py")
    start = code.index("def ensure_test_database_exists")
    body = code[start:code.index("class AsyncSessionAdapter")]
    assert "assert_target_is_marked_disposable" in body and "CREATE" not in body.upper()


def test_the_alembic_downgrade_lifecycle_test_is_skipped_unconditionally():
    from tests.integration import test_postgres_lifecycle as L
    marks = [m for m in getattr(L.test_postgres_alembic_downgrade_lifecycle, "pytestmark", []) if m.name == "skip"]
    assert marks and "ephemeral" in marks[0].kwargs["reason"]


def test_every_postgres_fixture_path_applies_the_identity_guard():
    src = (TESTS / "conftest.py").read_text(encoding="utf-8")
    assert "verify_approved_target_identity(url)" in src[src.index("def get_test_postgres_url"):]
    case = (TESTS / "integration" / "test_postgres_case_scoping.py").read_text(encoding="utf-8")
    assert "verify_approved_target_identity(url)" in case and "assert_target_is_marked_disposable" in case


# ---------------------------------------------------------------- owned-row cleanup (SQLite, private engine)
def _engine():
    e = create_engine("sqlite:///:memory:", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(e)
    return e


def _analyst(tag):
    now = datetime.now(timezone.utc)
    return Analyst(id=uuid.uuid4(), username=f"u_{tag}", email=f"{tag}@x.test", global_role=GlobalRole.ANALYST_TIER_2.value, is_active=True, created_at=now, updated_at=now)


def test_owned_row_cleanup_deletes_only_rows_the_session_inserted():
    engine = _engine()
    with Session(engine) as pre:                                   # someone else's data, committed earlier
        keep = _analyst("keep")
        pre.add(keep)
        pre.commit()
        keep_id = keep.id
    tracker = C.OwnedRowTracker()
    with Session(engine) as s:
        tracker.attach(s)
        mine, case_id = _analyst("mine"), uuid.uuid4()
        s.add(mine)
        now = datetime.now(timezone.utc)
        s.add(CaseModel(id=case_id, case_number="CASE-S7B", title="t", description="d", severity="high", status="open", created_at=now, updated_at=now))
        s.flush()
        audit_id = uuid.uuid4()
        s.add(CaseAuditEventModel(id=audit_id, case_id=case_id, actor_analyst_id=mine.id, actor_username=mine.username, action="x", context_sha256=None,
                                  details={}, created_at=now))
        s.commit()
        mine_id = mine.id
    deleted, left = tracker.cleanup(engine)
    with Session(engine) as check_s:
        assert check_s.get(Analyst, keep_id) is not None                                       # NOT owned: untouched
        assert check_s.get(Analyst, mine_id) is None and check_s.get(CaseModel, case_id) is None   # owned: removed
        assert check_s.scalar(select(func.count()).select_from(CaseAuditEventModel).where(CaseAuditEventModel.id == audit_id)) == 1   # append-only: never deleted
        assert check_s.scalar(select(func.count()).select_from(Analyst)) == 1                  # only the pre-existing analyst remains
    assert deleted == 2 and left == 0


def test_owned_row_cleanup_with_nothing_owned_deletes_nothing():
    engine = _engine()
    with Session(engine) as pre:
        pre.add(_analyst("a"))
        pre.add(_analyst("b"))
        pre.commit()
    assert C.OwnedRowTracker().cleanup(engine) == (0, 0)
    with Session(engine) as s:
        assert s.scalar(select(func.count()).select_from(Analyst)) == 2
