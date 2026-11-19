"""
Unit tests for AISOP Pure Role-Based Access Control (RBAC) & Scoping Policies.

Provably offline tests verifying:
- Canonical global and case role enums and rejection of non-canonical aliases
- Strict parsing and validation of role strings
- Canonical token structure parsing (aisop_<env>_<16hex>_<64hex>, 92 chars)
- Pure policy predicates covering:
  - Decision 1A (Sanitized global triage vs unscoped event detail)
  - Decision 2A (Strict Administrator Parity - no bypass for unassigned admin)
  - Decision 3A (Tier-1 Triage & Escalation privileges and assignment/closure limits)
  - Ingestion isolation
"""

from __future__ import annotations

import uuid
import pytest
from app.core.rbac import (
    AuthenticatedAnalyst,
    CaseRole,
    GlobalRole,
    can_access_case_evidence,
    can_access_global_entity_search,
    can_access_global_event_triage,
    can_access_unscoped_event_detail,
    can_close_or_archive_case,
    can_create_case,
    can_execute_case_synthesis,
    can_ingest_telemetry,
    can_manage_case_assignments,
    can_transfer_case_lead,
    can_update_case_metadata,
    has_case_role,
    has_global_role,
    is_canonical_token,
    is_valid_case_role,
    is_valid_global_role,
    parse_canonical_token,
    parse_case_role,
    parse_global_role,
)


# ═════════════════════════════════════════════════════════════════════════════
# 1. Canonical Roles & Validation Tests
# ═════════════════════════════════════════════════════════════════════════════


class TestCanonicalRoles:
    def test_approved_global_roles_exact_match(self):
        expected = {"ingest", "analyst_tier_1", "analyst_tier_2", "security_admin"}
        actual = {r.value for r in GlobalRole}
        assert actual == expected

    def test_approved_case_roles_exact_match(self):
        expected = {"viewer", "investigator", "lead"}
        actual = {r.value for r in CaseRole}
        assert actual == expected

    def test_rejects_global_role_aliases(self):
        invalid_aliases = [
            "tier_2",
            "admin",
            "analyst_t1",
            "investigator_t2",
            "superadmin",
            "INGEST",
            "analyst_tier_3",
            "",
            "   ",
        ]
        for alias in invalid_aliases:
            assert is_valid_global_role(alias) is False
            with pytest.raises(ValueError, match="Invalid global role"):
                parse_global_role(alias)

    def test_rejects_case_role_aliases(self):
        invalid_aliases = [
            "owner",
            "member",
            "read_only",
            "analyst",
            "LEAD",
            "lead_analyst",
            "",
            "   ",
        ]
        for alias in invalid_aliases:
            assert is_valid_case_role(alias) is False
            with pytest.raises(ValueError, match="Invalid case role"):
                parse_case_role(alias)

    def test_parse_valid_roles(self):
        assert parse_global_role("ingest") == GlobalRole.INGEST
        assert parse_global_role("analyst_tier_1") == GlobalRole.ANALYST_TIER_1
        assert parse_global_role("analyst_tier_2") == GlobalRole.ANALYST_TIER_2
        assert parse_global_role("security_admin") == GlobalRole.SECURITY_ADMIN

        assert parse_case_role("viewer") == CaseRole.VIEWER
        assert parse_case_role("investigator") == CaseRole.INVESTIGATOR
        assert parse_case_role("lead") == CaseRole.LEAD


# ═════════════════════════════════════════════════════════════════════════════
# 2. Canonical Token Parsing Tests
# ═════════════════════════════════════════════════════════════════════════════


class TestCanonicalTokens:
    def test_valid_canonical_live_token(self):
        token = "aisop_live_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        # 16-hex prefix: 0123456789abcdef (16)
        # 64-hex secret: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef (64)
        prefix = "0123456789abcdef"
        secret = "a" * 64
        valid_token = f"aisop_live_{prefix}_{secret}"
        assert len(valid_token) == 92
        assert is_canonical_token(valid_token) is True

        env, pfx, sec = parse_canonical_token(valid_token)
        assert env == "live"
        assert pfx == prefix
        assert sec == secret

    def test_valid_canonical_test_token(self):
        valid_token = f"aisop_test_{'f' * 16}_{'b' * 64}"
        assert len(valid_token) == 92
        assert is_canonical_token(valid_token) is True
        env, pfx, sec = parse_canonical_token(valid_token)
        assert env == "test"
        assert pfx == "f" * 16
        assert sec == "b" * 64

    def test_rejects_invalid_tokens(self):
        invalid_tokens = [
            "legacy-unprefixed-key",
            "aisop_live_shortprefix_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            f"aisop_staging_{'a' * 16}_{'b' * 64}",  # only live or test allowed
            f"aisop_live_{'G' * 16}_{'a' * 64}",    # non-hex chars
            f"aisop_live_{'a' * 16}_{'b' * 63}",    # 63 chars instead of 64
            f"aisop_live_{'a' * 15}_{'b' * 64}",    # 15 chars instead of 16
            "",
            None,
        ]
        for token in invalid_tokens:
            assert is_canonical_token(token) is False
            with pytest.raises(ValueError):
                parse_canonical_token(token)


# ═════════════════════════════════════════════════════════════════════════════
# 3. Decision 1A Policy Tests: Global Triage vs Unscoped Event Detail
# ═════════════════════════════════════════════════════════════════════════════


class TestDecision1APolicy:
    def test_global_event_triage_access(self):
        # Tier-1, Tier-2, and Security Admin can triage
        assert can_access_global_event_triage(GlobalRole.ANALYST_TIER_1) is True
        assert can_access_global_event_triage(GlobalRole.ANALYST_TIER_2) is True
        assert can_access_global_event_triage(GlobalRole.SECURITY_ADMIN) is True
        # Ingest and invalid roles are denied
        assert can_access_global_event_triage(GlobalRole.INGEST) is False
        assert can_access_global_event_triage("unknown_role") is False

    def test_unscoped_event_detail_restricted(self):
        # Only Tier-2 and Security Admin have unscoped global event detail
        assert can_access_unscoped_event_detail(GlobalRole.ANALYST_TIER_2) is True
        assert can_access_unscoped_event_detail(GlobalRole.SECURITY_ADMIN) is True
        # Tier-1 is STRICTLY DENIED unscoped detail (Decision 1A)
        assert can_access_unscoped_event_detail(GlobalRole.ANALYST_TIER_1) is False
        assert can_access_unscoped_event_detail(GlobalRole.INGEST) is False
        assert can_access_unscoped_event_detail("invalid") is False

    def test_global_entity_search_access(self):
        assert can_access_global_entity_search(GlobalRole.ANALYST_TIER_1) is True
        assert can_access_global_entity_search(GlobalRole.ANALYST_TIER_2) is True
        assert can_access_global_entity_search(GlobalRole.SECURITY_ADMIN) is True
        assert can_access_global_entity_search(GlobalRole.INGEST) is False


# ═════════════════════════════════════════════════════════════════════════════
# 4. Decision 2A Policy Tests: Strict Administrator Parity
# ═════════════════════════════════════════════════════════════════════════════


class TestDecision2APolicy:
    def test_admin_requires_case_assignment_for_evidence(self):
        # Admin assigned to case as viewer, investigator, or lead can access
        assert can_access_case_evidence(GlobalRole.SECURITY_ADMIN, CaseRole.VIEWER) is True
        assert can_access_case_evidence(GlobalRole.SECURITY_ADMIN, CaseRole.INVESTIGATOR) is True
        assert can_access_case_evidence(GlobalRole.SECURITY_ADMIN, CaseRole.LEAD) is True

        # CRITICAL: Admin with NO case assignment is DENIED (Decision 2A)
        assert can_access_case_evidence(GlobalRole.SECURITY_ADMIN, None) is False

    def test_admin_requires_case_assignment_for_synthesis(self):
        assert can_execute_case_synthesis(GlobalRole.SECURITY_ADMIN, CaseRole.INVESTIGATOR) is True
        assert can_execute_case_synthesis(GlobalRole.SECURITY_ADMIN, CaseRole.LEAD) is True

        # CRITICAL: Admin with NO assignment or Viewer role cannot run synthesis
        assert can_execute_case_synthesis(GlobalRole.SECURITY_ADMIN, None) is False
        assert can_execute_case_synthesis(GlobalRole.SECURITY_ADMIN, CaseRole.VIEWER) is False

    def test_analyst_case_evidence_access(self):
        # Tier-1 and Tier-2 assigned to case can inspect case evidence
        assert can_access_case_evidence(GlobalRole.ANALYST_TIER_1, CaseRole.VIEWER) is True
        assert can_access_case_evidence(GlobalRole.ANALYST_TIER_2, CaseRole.INVESTIGATOR) is True
        assert can_access_case_evidence(GlobalRole.ANALYST_TIER_1, None) is False


# ═════════════════════════════════════════════════════════════════════════════
# 5. Decision 3A Policy Tests: Tier-1 Triage & Escalation Capabilities & Limits
# ═════════════════════════════════════════════════════════════════════════════


class TestDecision3APolicy:
    def test_tier1_can_create_cases(self):
        assert can_create_case(GlobalRole.ANALYST_TIER_1) is True
        assert can_create_case(GlobalRole.ANALYST_TIER_2) is True
        assert can_create_case(GlobalRole.SECURITY_ADMIN) is True
        assert can_create_case(GlobalRole.INGEST) is False

    def test_tier1_lead_can_update_metadata_and_synthesize(self):
        # Tier-1 as case lead can update metadata
        assert can_update_case_metadata(GlobalRole.ANALYST_TIER_1, CaseRole.LEAD) is True
        # Tier-1 as investigator or lead can execute synthesis
        assert can_execute_case_synthesis(GlobalRole.ANALYST_TIER_1, CaseRole.LEAD) is True
        assert can_execute_case_synthesis(GlobalRole.ANALYST_TIER_1, CaseRole.INVESTIGATOR) is True
        # Tier-1 as viewer cannot
        assert can_execute_case_synthesis(GlobalRole.ANALYST_TIER_1, CaseRole.VIEWER) is False

    def test_tier1_lead_can_transfer_lead_to_tier2_or_admin(self):
        # Tier-1 lead can transfer to Tier-2
        assert can_transfer_case_lead(
            current_global_role=GlobalRole.ANALYST_TIER_1,
            current_case_role=CaseRole.LEAD,
            target_global_role=GlobalRole.ANALYST_TIER_2,
        ) is True

        # Tier-1 lead can transfer to Security Admin
        assert can_transfer_case_lead(
            current_global_role=GlobalRole.ANALYST_TIER_1,
            current_case_role=CaseRole.LEAD,
            target_global_role=GlobalRole.SECURITY_ADMIN,
        ) is True

        # CRITICAL: Transfer to another Tier-1 is PROHIBITED (Decision 3A)
        assert can_transfer_case_lead(
            current_global_role=GlobalRole.ANALYST_TIER_1,
            current_case_role=CaseRole.LEAD,
            target_global_role=GlobalRole.ANALYST_TIER_1,
        ) is False

        # Non-lead cannot transfer lead
        assert can_transfer_case_lead(
            current_global_role=GlobalRole.ANALYST_TIER_1,
            current_case_role=CaseRole.INVESTIGATOR,
            target_global_role=GlobalRole.ANALYST_TIER_2,
        ) is False

    def test_tier1_lead_cannot_manage_assignments(self):
        # CRITICAL (Decision 3A): Tier-1 lead cannot manage investigator assignments
        assert can_manage_case_assignments(GlobalRole.ANALYST_TIER_1, CaseRole.LEAD) is False

        # Tier-2 lead and Admin lead can manage assignments
        assert can_manage_case_assignments(GlobalRole.ANALYST_TIER_2, CaseRole.LEAD) is True
        assert can_manage_case_assignments(GlobalRole.SECURITY_ADMIN, CaseRole.LEAD) is True

        # Non-lead cannot manage assignments
        assert can_manage_case_assignments(GlobalRole.ANALYST_TIER_2, CaseRole.INVESTIGATOR) is False

    def test_tier1_lead_cannot_close_or_archive_cases(self):
        # CRITICAL (Decision 3A): Tier-1 lead cannot formally close or archive cases
        assert can_close_or_archive_case(GlobalRole.ANALYST_TIER_1, CaseRole.LEAD) is False

        # Tier-2 lead and Admin lead can close/archive cases
        assert can_close_or_archive_case(GlobalRole.ANALYST_TIER_2, CaseRole.LEAD) is True
        assert can_close_or_archive_case(GlobalRole.SECURITY_ADMIN, CaseRole.LEAD) is True


# ═════════════════════════════════════════════════════════════════════════════
# 6. Ingestion Isolation Policy Tests
# ═════════════════════════════════════════════════════════════════════════════


class TestIngestionPolicy:
    def test_ingest_role_exclusive(self):
        assert can_ingest_telemetry(GlobalRole.INGEST) is True
        assert can_ingest_telemetry(GlobalRole.ANALYST_TIER_1) is False
        assert can_ingest_telemetry(GlobalRole.ANALYST_TIER_2) is False
        assert can_ingest_telemetry(GlobalRole.SECURITY_ADMIN) is False
