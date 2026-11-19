"""
Stage 7C (Workstream B): offline review tests for the PostgreSQL target guard and the OwnedRowTracker. NO PostgreSQL connection is made:
the database-side check runs against a fake ``psycopg`` module that records every SQL statement it is given.
"""

from __future__ import annotations

import re
import sys
import types
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.rbac import GlobalRole
from app.db.base import Base
from app.models.analyst import Analyst
from app.models.case import CaseModel
from app.models.evidence import NormalizedEventModel, RawEvidence
from tests import conftest as C

TESTS = Path(__file__).resolve().parents[1]
HEAD = "0004_p3h2_rbac_case_scoping"


# ---------------------------------------------------------------- fake psycopg: records SQL, returns scripted answers
class FakePsycopg(types.ModuleType):
    def __init__(self, *, name=None, comment=None, has_alembic=True, revisions=(HEAD,), fail=None):
        super().__init__("psycopg")
        self.sql: list[str] = []
        self.connected_to: list[str] = []
        self._name = C.APPROVED_PG_DATABASE if name is None else name
        self._comment = C.DISPOSABLE_MARKER if comment is None else comment
        self._has = has_alembic
        self._revs = list(revisions)
        self._fail = fail

    def connect(self, conn_str, autocommit=False):
        self.connected_to.append(conn_str)
        if self._fail:
            raise self._fail
        outer = self

        class Cur:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def execute(s, sql, params=None):
                outer.sql.append(sql)
                s.last = sql
            def fetchone(s):
                if "current_database()" in s.last and "shobj_description" in s.last:
                    return (outer._name, outer._comment)
                if "to_regclass" in s.last:
                    return ("alembic_version" if outer._has else None,)
                return None
            def fetchall(s):
                return [(r,) for r in outer._revs]

        class Conn:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def cursor(s): return Cur()
        return Conn()


URL = f"postgresql://u:SECRETPW@{C.APPROVED_PG_HOST}:{C.APPROVED_PG_PORT}/{C.APPROVED_PG_DATABASE}"


def run_check(monkeypatch, **kw):
    fake = FakePsycopg(**kw)
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    C.assert_target_is_marked_disposable(URL)
    return fake


def test_database_side_check_accepts_only_the_exact_marked_database_at_the_single_head(monkeypatch):
    fake = run_check(monkeypatch)
    assert all(s.lstrip().upper().startswith("SELECT") for s in fake.sql) and len(fake.sql) == 3     # read-only, nothing else


def test_wrong_database_name_fails_closed(monkeypatch):
    with pytest.raises(RuntimeError, match="FAIL-CLOSED"):
        run_check(monkeypatch, name="aisop_dev")


@pytest.mark.parametrize("comment", ["", "aisop-disposable-test-target:aisop_dev", "aisop-disposable-test-target:aisop_stage7b_verify_disposable ", "disposable"])
def test_a_missing_or_wrong_database_comment_marker_fails_closed(monkeypatch, comment):
    with pytest.raises(RuntimeError, match="marker"):
        run_check(monkeypatch, comment=comment)


def test_a_database_without_any_comment_fails_closed(monkeypatch):
    fake = FakePsycopg()
    fake._comment = None
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    with pytest.raises(RuntimeError, match="marker"):
        C.assert_target_is_marked_disposable(URL)


@pytest.mark.parametrize("kw", [{"has_alembic": False}, {"revisions": ()}, {"revisions": ("0003_source_scoped_chunks",)},
                                {"revisions": (HEAD, "other")}, {"revisions": ("unknown",)}])
def test_missing_wrong_or_multiple_alembic_revisions_fail_closed(monkeypatch, kw):
    with pytest.raises(RuntimeError, match="FAIL-CLOSED"):
        run_check(monkeypatch, **kw)


def test_a_missing_database_is_an_error_and_nothing_is_created_and_the_url_is_not_leaked(monkeypatch):
    fake = FakePsycopg(fail=ConnectionError('database "aisop_stage7b_verify_disposable" does not exist'))
    monkeypatch.setitem(sys.modules, "psycopg", fake)
    with pytest.raises(RuntimeError) as ei:
        C.assert_target_is_marked_disposable(URL)
    msg = str(ei.value)
    assert "nothing was created" in msg and "SECRETPW" not in msg and "does not exist" not in msg
    assert fake.sql == [] and len(fake.connected_to) == 1                                              # it connected once and ran no statement


def test_the_check_connects_to_the_target_database_only_never_to_the_postgres_maintenance_database():
    import ast
    tree = ast.parse((TESTS / "conftest.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "assert_target_is_marked_disposable")
    consts = [n.value for n in ast.walk(fn) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    verbs = [c for c in consts if re.match(r"^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|COMMENT|TRUNCATE|GRANT|REVOKE)(?:\s|$)", c, re.I)]
    assert verbs and all(v.lstrip().upper().startswith("SELECT") for v in verbs)          # every SQL literal is a SELECT
    assert not any("/postgres" in c for c in consts)                                       # it connects with the caller's target URL only


# ---------------------------------------------------------------- no fallback target anywhere in the PostgreSQL test path
def _pg_test_files():
    return [TESTS / "conftest.py", *sorted((TESTS / "integration").glob("test_postgres_*.py"))]


def test_no_postgres_test_path_reads_another_url_or_embeds_a_literal_server_url():
    offenders = []
    for p in _pg_test_files():
        src = p.read_text(encoding="utf-8")
        for m in re.finditer(r"(getenv|environ(?:\.get)?|environ\[)\(?\s*[\"'](\w+)[\"']", src):
            if m.group(2) not in {"TEST_DATABASE_URL", "ALLOW_DESTRUCTIVE_POSTGRES_TESTS"} and not m.group(2).startswith("AISOP_PG_"):
                offenders.append(f"{p.name}: env {m.group(2)}")
        if re.search(r"create(_async)?_engine\(\s*[\"']postgres", src):
            offenders.append(f"{p.name}: literal engine URL")
        if re.search(r"settings\.(database|db)_url|DATABASE_URL\b(?!\s*[\"']?\s*(not|is))", src) and "TEST_DATABASE_URL" not in src:
            offenders.append(f"{p.name}: application database setting")
    assert offenders == []


def test_every_engine_in_the_postgres_test_path_is_built_from_a_guarded_url():
    src = (TESTS / "conftest.py").read_text(encoding="utf-8")
    for fn in ("def postgres_sync_engine", "def postgres_engine", "def postgres_alembic_config"):
        body = src[src.index(fn):]
        body = body[:body.index("\n@pytest.fixture") if "\n@pytest.fixture" in body else len(body)]
        assert "get_test_postgres_url()" in body, fn
    case = (TESTS / "integration" / "test_postgres_case_scoping.py").read_text(encoding="utf-8")
    assert "create_async_engine(\n        raw_url_str" in case and "d25_validated_target_url.render_as_string" in case


def test_the_guard_never_prints_the_url_or_password():
    src = (TESTS / "conftest.py").read_text(encoding="utf-8")
    guard = src[src.index("def verify_approved_target_identity"):src.index("def get_test_postgres_url")]
    assert "print(" not in guard and "password" not in guard.lower()
    assert "render_as_string(hide_password=False)" not in guard


def test_every_new_postgres_test_is_marked_and_the_default_expression_excludes_it():
    from tests.integration import test_postgres_stage7b_verification as V
    assert V.pytestmark.mark.name == "postgres"
    cfg = (TESTS.parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert "postgres: marks tests requiring live PostgreSQL" in cfg


# ---------------------------------------------------------------- OwnedRowTracker
def _engine():
    e = create_engine("sqlite:///:memory:", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(e)
    return e


def _analyst(tag):
    now = datetime.now(timezone.utc)
    return Analyst(id=uuid.uuid4(), username=f"u_{tag}", email=f"{tag}@x.test", global_role=GlobalRole.ANALYST_TIER_2.value, is_active=True, created_at=now, updated_at=now)


def _capture(engine):
    stmts: list[str] = []
    event.listen(engine, "before_cursor_execute", lambda conn, cur, st, params, ctx, many: stmts.append(st))
    return stmts


def test_every_cleanup_statement_is_a_primary_key_scoped_delete_and_nothing_else():
    engine = _engine()
    tracker = C.OwnedRowTracker()
    with Session(engine) as s:
        tracker.attach(s)
        s.add_all([_analyst("a"), _analyst("b")])
        s.commit()
    stmts = _capture(engine)
    deleted, left = tracker.cleanup(engine)
    assert (deleted, left) == (2, 0) and len(stmts) == 2
    assert all(re.match(r"DELETE FROM analysts WHERE analysts\.id = \?", st.strip()) for st in stmts)
    assert not any(k in " ".join(stmts).upper() for k in ("TRUNCATE", "DROP", "ALTER", "SELECT"))


def test_rows_inserted_by_another_session_or_before_attach_are_never_touched():
    engine = _engine()
    other = C.OwnedRowTracker()
    with Session(engine) as s_other:
        other.attach(s_other)
        s_other.add(_analyst("other"))
        s_other.commit()
    mine = C.OwnedRowTracker()
    with Session(engine) as s:
        s.add(_analyst("before-attach"))                       # added before attach, in the same session
        s.flush()
        mine.attach(s)
        s.add(_analyst("mine"))
        s.commit()
    assert mine.cleanup(engine) == (1, 0)
    with Session(engine) as c:
        names = sorted(c.scalars(select(Analyst.username)).all())
    assert names == ["u_before-attach", "u_other"]


def test_a_rolled_back_row_is_not_provably_owned_and_nothing_is_deleted_for_it():
    engine = _engine()
    tracker = C.OwnedRowTracker()
    with Session(engine) as s:
        tracker.attach(s)
        s.add(_analyst("rolled"))
        s.flush()
        s.rollback()
    stmts = _capture(engine)
    deleted, left = tracker.cleanup(engine)
    assert deleted == 0 and stmts == [] and left == 1 and tracker.left_ids == ["analysts:ownership-not-provable"]


def test_a_failing_delete_is_reported_and_never_widened():
    engine = _engine()
    tracker = C.OwnedRowTracker()
    with Session(engine) as s:
        tracker.attach(s)
        s.add_all([_analyst("x"), _analyst("y")])
        s.commit()

    class Boom:
        def __init__(self, real): self.real, self.calls = real, 0
        def begin(self):
            self.calls += 1
            raise RuntimeError("delete refused")

    boom = Boom(engine)
    deleted, left = tracker.cleanup(boom)
    assert deleted == 0 and left == 2 and boom.calls == 2                       # each owned row attempted once; no other statement path exists
    with Session(engine) as c:
        assert c.scalar(select(func.count()).select_from(Analyst)) == 2


def test_children_are_deleted_before_parents_by_foreign_key_order():
    engine = _engine()
    tracker = C.OwnedRowTracker()
    with Session(engine) as s:
        tracker.attach(s)
        raw = RawEvidence(id=uuid.uuid4(), source_type="t", source_identifier="s", sha256_hash=uuid.uuid4().hex * 2, raw_payload={"a": 1})
        s.add(raw)
        s.flush()
        s.add(NormalizedEventModel(id=uuid.uuid4(), raw_evidence_id=raw.id, event_id="e", event_type="t", event_timestamp=datetime.now(timezone.utc),
                                   provider="p", action="a", outcome="unknown", severity="informational", normalized_payload={}))
        s.commit()
    stmts = _capture(engine)
    assert tracker.cleanup(engine) == (2, 0)
    order = [re.search(r"DELETE FROM (\w+)", st).group(1) for st in stmts]
    assert order.index("normalized_events") < order.index("raw_evidence")


def test_append_only_audit_rows_are_never_deleted_and_are_not_reported_as_a_problem():
    from app.models.case import CaseAuditEventModel
    engine = _engine()
    tracker = C.OwnedRowTracker()
    now = datetime.now(timezone.utc)
    with Session(engine) as s:
        tracker.attach(s)
        a, cid = _analyst("aud"), uuid.uuid4()
        s.add(a)
        s.add(CaseModel(id=cid, case_number="C-1", title="t", description="d", severity="high", status="open", created_at=now, updated_at=now))
        s.flush()
        s.add(CaseAuditEventModel(id=uuid.uuid4(), case_id=cid, actor_analyst_id=a.id, actor_username=a.username, action="x", context_sha256=None,
                                  details={}, created_at=now))
        s.commit()
    stmts = _capture(engine)
    tracker.cleanup(engine)
    assert not any("case_audit_events" in st for st in stmts) and tracker.retained_append_only == 1
