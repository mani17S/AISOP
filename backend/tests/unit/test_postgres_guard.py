"""
Unit tests for AISOP PostgreSQL Test Safety Guard (Gate B.2).

Provably offline unit tests verifying:
- Explicit TEST_DATABASE_URL enforcement (zero silent fallbacks to protected databases)
- Mandatory ALLOW_DESTRUCTIVE_POSTGRES_TESTS=1 opt-in for destructive fixtures
- Strict rejection of protected database names (aisop_test, aisop_dev, aisop_prod, aisop, postgres)
- Anchored regex allowlist matching (^aisop_[a-z0-9_]+_disposable$)
- Missing database component rejection
- Unsupported database scheme rejection
- Untrusted non-local host rejection
- Malformed configuration rejection
- Valid disposable target acceptance
- Password redaction across all exception messages
- Proof that invalid configuration fails closed before any database engine or connection is created
"""

from __future__ import annotations

import pytest
from sqlalchemy.engine import URL

from backend.tests.conftest import (
    ALLOWED_SCHEMES,
    ALLOWED_TEST_HOSTS,
    DISPOSABLE_DB_NAME_PATTERN,
    PROTECTED_DATABASE_NAMES,
    get_test_postgres_url,
    validate_test_database_target,
)


class TestPostgresGuardMissingConfig:
    def test_missing_test_database_url_fails_closed(self, monkeypatch):
        monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
        with pytest.raises(RuntimeError) as exc_info:
            validate_test_database_target(db_url_raw=None)
        assert "TEST_DATABASE_URL is not set" in str(exc_info.value)
        assert "Silent fallback to default or protected databases is prohibited" in str(
            exc_info.value
        )

    def test_empty_test_database_url_fails_closed(self):
        with pytest.raises(RuntimeError) as exc_info:
            validate_test_database_target(db_url_raw="   ")
        assert "TEST_DATABASE_URL is not set" in str(exc_info.value)

    def test_missing_destructive_opt_in_fails_closed(self, monkeypatch):
        monkeypatch.delenv("ALLOW_DESTRUCTIVE_POSTGRES_TESTS", raising=False)
        valid_url = "postgresql+psycopg://aisop:secret@localhost:5433/aisop_p2h3_disposable"
        with pytest.raises(RuntimeError) as exc_info:
            validate_test_database_target(
                db_url_raw=valid_url,
                allow_destructive_raw=None,
                require_destructive_opt_in=True,
            )
        assert "Destructive PostgreSQL testing is not opted-in" in str(exc_info.value)
        assert "ALLOW_DESTRUCTIVE_POSTGRES_TESTS = '1'" in str(exc_info.value)

    def test_falsy_destructive_opt_in_fails_closed(self):
        valid_url = "postgresql+psycopg://aisop:secret@localhost:5433/aisop_p2h3_disposable"
        for invalid_val in ["0", "false", "no", ""]:
            with pytest.raises(RuntimeError) as exc_info:
                validate_test_database_target(
                    db_url_raw=valid_url,
                    allow_destructive_raw=invalid_val,
                    require_destructive_opt_in=True,
                )
            assert "Destructive PostgreSQL testing is not opted-in" in str(exc_info.value)


class TestPostgresGuardProtectedDatabases:
    @pytest.mark.parametrize("protected_name", sorted(PROTECTED_DATABASE_NAMES))
    def test_protected_database_names_rejected(self, protected_name):
        url = f"postgresql+psycopg://aisop:secret_pw@localhost:5433/{protected_name}"
        with pytest.raises(RuntimeError) as exc_info:
            validate_test_database_target(
                db_url_raw=url,
                allow_destructive_raw="1",
                require_destructive_opt_in=True,
            )
        err_msg = str(exc_info.value)
        assert "Refusing to target protected database" in err_msg
        assert protected_name in err_msg
        # Proof of password redaction
        assert "secret_pw" not in err_msg


class TestPostgresGuardNamingPattern:
    def test_non_matching_database_names_rejected(self):
        invalid_names = [
            "aisop_sandbox",
            "aisop_dev_test",
            "other_database",
            "disposable",
            "aisop_disposable",  # Missing middle component
            "aisop_p2h3_disposable_extra",  # Not anchored at end
            "pre_aisop_p2h3_disposable",  # Not anchored at start
            "aisop-hyphen-disposable",  # Hyphens prohibited
            "aisop_disposable_test",  # Suffix mismatch
        ]
        for name in invalid_names:
            url = f"postgresql+psycopg://aisop:secret@localhost:5433/{name}"
            with pytest.raises(RuntimeError) as exc_info:
                validate_test_database_target(
                    db_url_raw=url,
                    allow_destructive_raw="1",
                    require_destructive_opt_in=True,
                )
            assert "Non-disposable database name" in str(exc_info.value)

    def test_database_name_normalization(self):
        # Normalizes only the database name for comparison
        url = "postgresql+psycopg://aisop:secret@localhost:5433/AISOP_P2H3_DISPOSABLE"
        validated_url = validate_test_database_target(
            db_url_raw=url,
            allow_destructive_raw="1",
            require_destructive_opt_in=True,
        )
        assert validated_url.database.lower() == "aisop_p2h3_disposable"

    def test_valid_disposable_database_names_accepted(self):
        valid_names = [
            "aisop_p2h3_disposable",
            "aisop_p3h2_disposable",
            "aisop_unit_123_disposable",
            "aisop_ci_worker_disposable",
        ]
        for name in valid_names:
            url_str = f"postgresql+psycopg://aisop:secret@localhost:5433/{name}"
            validated_url = validate_test_database_target(
                db_url_raw=url_str,
                allow_destructive_raw="1",
                require_destructive_opt_in=True,
            )
            assert validated_url.database == name


class TestPostgresGuardURLValidation:
    def test_missing_database_component_rejected(self):
        urls = [
            "postgresql+psycopg://aisop:secret@localhost:5433/",
            "postgresql+psycopg://aisop:secret@localhost:5433",
        ]
        for u in urls:
            with pytest.raises(RuntimeError) as exc_info:
                validate_test_database_target(
                    db_url_raw=u,
                    allow_destructive_raw="1",
                    require_destructive_opt_in=True,
                )
            assert "Missing database name" in str(exc_info.value)

    def test_unsupported_url_schemes_rejected(self):
        unsupported = [
            "mysql://aisop:secret@localhost:5433/aisop_test_disposable",
            "sqlite:///aisop_test_disposable.db",
            "http://localhost:5433/aisop_test_disposable",
            "mongodb://localhost:5433/aisop_test_disposable",
        ]
        for u in unsupported:
            with pytest.raises(RuntimeError) as exc_info:
                validate_test_database_target(
                    db_url_raw=u,
                    allow_destructive_raw="1",
                    require_destructive_opt_in=True,
                )
            assert "Unsupported database scheme" in str(exc_info.value)

    def test_untrusted_hosts_rejected(self):
        remote_hosts = [
            "prod-database.internal",
            "10.0.0.1",
            "192.168.1.100",
            "db.aws.cloud.corp",
            "remotehost",
        ]
        for h in remote_hosts:
            u = f"postgresql+psycopg://aisop:secret@{h}:5433/aisop_p2h3_disposable"
            with pytest.raises(RuntimeError) as exc_info:
                validate_test_database_target(
                    db_url_raw=u,
                    allow_destructive_raw="1",
                    require_destructive_opt_in=True,
                )
            assert "Untrusted test host" in str(exc_info.value)

    def test_local_hosts_accepted(self):
        for h, url_host in [("localhost", "localhost"), ("127.0.0.1", "127.0.0.1"), ("::1", "[::1]")]:
            u = f"postgresql+psycopg://aisop:secret@{url_host}:5433/aisop_p2h3_disposable"
            res = validate_test_database_target(
                db_url_raw=u,
                allow_destructive_raw="1",
                require_destructive_opt_in=True,
            )
            assert res.host == h

    def test_malformed_url_rejected(self):
        with pytest.raises(RuntimeError) as exc_info:
            validate_test_database_target(
                db_url_raw="not-a-valid-url:::://???",
                allow_destructive_raw="1",
                require_destructive_opt_in=True,
            )
        assert "Malformed TEST_DATABASE_URL" in str(exc_info.value)


class TestPostgresGuardCredentialRedaction:
    def test_password_redacted_in_all_failure_modes(self):
        secret_password = "SUPER_SENSITIVE_LEAK_TEST_PASSWORD_98765"

        test_cases = [
            f"postgresql+psycopg://aisop:{secret_password}@localhost:5433/aisop_test",  # protected
            f"postgresql+psycopg://aisop:{secret_password}@localhost:5433/invalid_name",  # non-disposable
            f"postgresql+psycopg://aisop:{secret_password}@remote-host.com:5433/aisop_p2h3_disposable",  # untrusted host
            f"mysql://aisop:{secret_password}@localhost:5433/aisop_p2h3_disposable",  # bad scheme
            f"postgresql+psycopg://aisop:{secret_password}@localhost:5433/",  # missing db
        ]

        for case_url in test_cases:
            with pytest.raises(RuntimeError) as exc_info:
                validate_test_database_target(
                    db_url_raw=case_url,
                    allow_destructive_raw="1",
                    require_destructive_opt_in=True,
                )
            err = str(exc_info.value)
            assert secret_password not in err, f"Secret password leaked in error message: {err}"


class TestGetTestPostgresUrlHelper:
    def test_fails_closed_before_any_engine_creation(self, monkeypatch):
        # When environment variables are absent, get_test_postgres_url fails fast
        monkeypatch.delenv("TEST_DATABASE_URL", raising=False)
        monkeypatch.delenv("ALLOW_DESTRUCTIVE_POSTGRES_TESTS", raising=False)

        with pytest.raises(RuntimeError) as exc_info:
            get_test_postgres_url(require_destructive_opt_in=True)
        assert "TEST_DATABASE_URL is not set" in str(exc_info.value)

    def test_returns_unredacted_url_to_sqlalchemy_only_when_validated(self, monkeypatch):
        # Stage 7B (D6): only the single approved target, with the launcher-verified identity, is returned; any other database is refused.
        from tests import conftest as C

        target_url = f"postgresql+psycopg://aisop:real_pw@127.0.0.1:5433/{C.APPROVED_PG_DATABASE}"
        monkeypatch.setenv("TEST_DATABASE_URL", target_url)
        monkeypatch.setenv("ALLOW_DESTRUCTIVE_POSTGRES_TESTS", "1")
        for name, value in C._IDENTITY_ENV.items():
            monkeypatch.setenv(name, value)

        result = get_test_postgres_url(require_destructive_opt_in=True)
        assert C.APPROVED_PG_DATABASE in result
        assert "real_pw" in result

        monkeypatch.setenv("TEST_DATABASE_URL", "postgresql+psycopg://aisop:real_pw@localhost:5433/aisop_p2h3_disposable")
        with pytest.raises(RuntimeError, match="FAIL-CLOSED"):
            get_test_postgres_url(require_destructive_opt_in=True)
        monkeypatch.setenv("TEST_DATABASE_URL", target_url)
        monkeypatch.delenv("AISOP_PG_VERIFIED_CONTAINER")
        with pytest.raises(RuntimeError, match="AISOP_PG_VERIFIED_CONTAINER"):
            get_test_postgres_url(require_destructive_opt_in=True)
