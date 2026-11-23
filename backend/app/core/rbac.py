"""
AISOP Role-Based Access Control (RBAC) & Analyst Scoping Policy.

Enforces defensive zero-trust access boundaries across global telemetry
and case-scoped evidence in accordance with AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001.

Canonical Roles:
- Global: ingest, analyst_tier_1, analyst_tier_2, security_admin
- Case: viewer, investigator, lead

Security Invariants:
- Deny-by-default for all unrecognized roles, inactive accounts, or missing assignments.
- Strict Administrator Parity (Decision 2A): security_admin receives no implicit bypass
  for case evidence inspection or AI synthesis without active assignment.
- Tier-1 Triage & Escalation (Decision 3A): Tier-1 may create and lead cases, run AI
  synthesis, and transfer leadership to Tier-2/Admin, but cannot manage investigator
  assignments or close/archive cases.
- Unscoped Event Details (Decision 1A): Full event payloads and raw evidence are restricted
  to Tier-2 and Security Admin in global search; Tier-1 access requires case scoping.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Sequence

from pydantic import BaseModel, ConfigDict, Field


class GlobalRole(str, Enum):
    """
    Approved canonical global analyst and system roles.
    Aliases (e.g. 'tier_2', 'admin', 'analyst_t1') are strictly prohibited.
    """

    INGEST = "ingest"
    ANALYST_TIER_1 = "analyst_tier_1"
    ANALYST_TIER_2 = "analyst_tier_2"
    SECURITY_ADMIN = "security_admin"


class CaseRole(str, Enum):
    """
    Approved canonical case-scoped investigator roles.
    Aliases (e.g. 'owner', 'member', 'read_only') are strictly prohibited.
    """

    VIEWER = "viewer"
    INVESTIGATOR = "investigator"
    LEAD = "lead"


VALID_GLOBAL_ROLES: frozenset[str] = frozenset(r.value for r in GlobalRole)
VALID_CASE_ROLES: frozenset[str] = frozenset(r.value for r in CaseRole)

# Canonical Token Format: aisop_<env>_<16-hex-prefix>_<64-hex-secret> (Total length: 92)
CANONICAL_TOKEN_PATTERN = r"^aisop_(live|test)_([0-9a-f]{16})_([0-9a-f]{64})$"
CANONICAL_TOKEN_REGEX = re.compile(CANONICAL_TOKEN_PATTERN)


def is_valid_global_role(role: str) -> bool:
    """Return True if role matches a canonical GlobalRole value."""
    return role in VALID_GLOBAL_ROLES


def is_valid_case_role(role: str) -> bool:
    """Return True if role matches a canonical CaseRole value."""
    return role in VALID_CASE_ROLES


def parse_global_role(role: str | GlobalRole) -> GlobalRole:
    """
    Parse and validate a global role value into canonical GlobalRole enum.

    Raises:
        ValueError: If role is not a recognized canonical global role.
    """
    if isinstance(role, GlobalRole):
        return role
    if not isinstance(role, str) or role not in VALID_GLOBAL_ROLES:
        raise ValueError(
            f"Invalid global role '{role}'. Permitted canonical roles: "
            f"{sorted(VALID_GLOBAL_ROLES)}"
        )
    return GlobalRole(role)


def parse_case_role(role: str | CaseRole) -> CaseRole:
    """
    Parse and validate a case role value into canonical CaseRole enum.

    Raises:
        ValueError: If role is not a recognized canonical case role.
    """
    if isinstance(role, CaseRole):
        return role
    if not isinstance(role, str) or role not in VALID_CASE_ROLES:
        raise ValueError(
            f"Invalid case role '{role}'. Permitted canonical roles: "
            f"{sorted(VALID_CASE_ROLES)}"
        )
    return CaseRole(role)


def is_canonical_token(token: str) -> bool:
    """Check if token adheres to canonical aisop_<env>_<16hex>_<64hex> format."""
    if not isinstance(token, str) or len(token) != 92:
        return False
    return CANONICAL_TOKEN_REGEX.fullmatch(token) is not None


def parse_canonical_token(token: str) -> tuple[str, str, str]:
    """
    Parse a canonical token into (env, prefix, secret).

    Returns:
        tuple[str, str, str]: (env, prefix, secret)

    Raises:
        ValueError: If token does not match canonical structure.
    """
    if not isinstance(token, str):
        raise ValueError("Token must be a string.")
    match = CANONICAL_TOKEN_REGEX.fullmatch(token)
    if not match:
        raise ValueError(
            "Token does not conform to canonical format: "
            "aisop_<live|test>_<16-hex-prefix>_<64-hex-secret>"
        )
    env, prefix, secret = match.groups()
    return env, prefix, secret


def hash_canonical_token(token: str) -> str:
    """
    Compute cryptographic SHA-256 digest of complete canonical API token.

    Follows Gate D.1 approved specification: SHA-256 of the complete canonical token string.
    """
    import hashlib

    if not isinstance(token, str):
        raise ValueError("Token must be a string.")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthenticatedAnalyst(BaseModel):
    """
    Identity contract for an authenticated human security analyst.

    Represents verified analyst identity, active status, and canonical global role.
    Distinguished from AuthenticatedClient which represents machine client credentials.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    analyst_id: uuid.UUID = Field(
        description="Unique identifier for the analyst record in PostgreSQL",
    )
    username: str = Field(
        min_length=1,
        max_length=64,
        description="Canonical human analyst username (e.g. jdoe)",
    )
    global_role: GlobalRole = Field(
        description="Assigned canonical global role",
    )
    client_id: str = Field(
        default="analyst-client",
        description="Associated API client identifier",
    )
    is_active: bool = Field(
        default=True,
        description="Whether the analyst account is currently active",
    )


class AuthenticatedCaseContext(BaseModel):
    """
    Verified analyst authorization context within a specific security case.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: uuid.UUID = Field(description="Case UUID")
    analyst_id: uuid.UUID = Field(description="Analyst UUID")
    case_role: CaseRole = Field(description="Assigned role within this case")
    assigned_at: datetime = Field(description="Assignment timestamp (UTC)")


# ── Pure Authorization Predicates (Deny-by-Default) ──────────────────────────


def has_global_role(
    analyst_role: GlobalRole | str,
    required_roles: Sequence[GlobalRole | str] | set[GlobalRole | str] | GlobalRole | str,
) -> bool:
    """
    Pure predicate verifying if analyst_role meets any required role.
    Fails closed (returns False) for unrecognized or None values.
    """
    try:
        parsed_analyst = parse_global_role(analyst_role)
    except ValueError:
        return False

    if isinstance(required_roles, (GlobalRole, str)):
        target_roles = [required_roles]
    else:
        target_roles = list(required_roles)

    parsed_targets: set[GlobalRole] = set()
    for req in target_roles:
        try:
            parsed_targets.add(parse_global_role(req))
        except ValueError:
            continue

    return parsed_analyst in parsed_targets


def has_case_role(
    case_role: CaseRole | str | None,
    required_roles: Sequence[CaseRole | str] | set[CaseRole | str] | CaseRole | str,
) -> bool:
    """
    Pure predicate verifying if case_role meets any required role.
    Fails closed (returns False) if case_role is None or unrecognized.
    """
    if case_role is None:
        return False

    try:
        parsed_role = parse_case_role(case_role)
    except ValueError:
        return False

    if isinstance(required_roles, (CaseRole, str)):
        target_roles = [required_roles]
    else:
        target_roles = list(required_roles)

    parsed_targets: set[CaseRole] = set()
    for req in target_roles:
        try:
            parsed_targets.add(parse_case_role(req))
        except ValueError:
            continue

    return parsed_role in parsed_targets


def can_access_global_event_triage(global_role: GlobalRole | str) -> bool:
    """
    Decision 1A: Sanitized global event triage projection access.
    Permitted: analyst_tier_1, analyst_tier_2, security_admin.
    Prohibited: ingest.
    """
    return has_global_role(
        global_role,
        {
            GlobalRole.ANALYST_TIER_1,
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    )


def can_view_security_monitoring(global_role: GlobalRole | str) -> bool:
    """
    The Security page (what the server observed being done to it: failed logins, probes, lockouts, by source address).
    Permitted: security_admin only. It lists source addresses and attack patterns, which analysts do not need to investigate cases.
    """
    return has_global_role(global_role, {GlobalRole.SECURITY_ADMIN})


def can_access_unscoped_event_detail(global_role: GlobalRole | str) -> bool:
    """
    Decision 1A: Full event payloads and raw evidence in global unscoped query.
    Permitted: analyst_tier_2, security_admin.
    Prohibited: analyst_tier_1, ingest.
    """
    return has_global_role(
        global_role,
        {
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    )


def can_access_global_entity_search(global_role: GlobalRole | str) -> bool:
    """
    Sanitized global entity / IOC lookup access.
    Permitted: analyst_tier_1, analyst_tier_2, security_admin.
    Prohibited: ingest.
    """
    return has_global_role(
        global_role,
        {
            GlobalRole.ANALYST_TIER_1,
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    )


def can_ingest_telemetry(global_role: GlobalRole | str) -> bool:
    """
    Telemetry ingestion endpoint access.
    Permitted: ingest.
    Prohibited: analyst_tier_1, analyst_tier_2, security_admin.
    """
    return has_global_role(global_role, {GlobalRole.INGEST})


def can_create_case(global_role: GlobalRole | str) -> bool:
    """
    Decision 3A: Case creation.
    Permitted: analyst_tier_1, analyst_tier_2, security_admin.
    Prohibited: ingest.
    """
    return has_global_role(
        global_role,
        {
            GlobalRole.ANALYST_TIER_1,
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    )


def can_access_case_evidence(
    global_role: GlobalRole | str,
    case_role: CaseRole | str | None,
) -> bool:
    """
    Decision 2A: Case-scoped evidence access with strict administrator parity.
    Requires caller to hold a valid analyst global role AND an active case assignment
    (viewer, investigator, or lead).
    An unassigned security_admin returns False.
    """
    if not has_global_role(
        global_role,
        {
            GlobalRole.ANALYST_TIER_1,
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    ):
        return False

    return has_case_role(
        case_role,
        {
            CaseRole.VIEWER,
            CaseRole.INVESTIGATOR,
            CaseRole.LEAD,
        },
    )


def can_update_case_metadata(
    global_role: GlobalRole | str,
    case_role: CaseRole | str | None,
) -> bool:
    """
    Case metadata updates (title, description, severity).
    Permitted: Lead on the case holding global role Tier-1, Tier-2, or Admin.
    """
    if not has_global_role(
        global_role,
        {
            GlobalRole.ANALYST_TIER_1,
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    ):
        return False

    return has_case_role(case_role, {CaseRole.LEAD})


def can_transfer_case_lead(
    current_global_role: GlobalRole | str,
    current_case_role: CaseRole | str | None,
    target_global_role: GlobalRole | str,
) -> bool:
    """
    Decision 3A: Lead transfer.
    Current caller must be the active case Lead.
    Target analyst MUST hold global role analyst_tier_2 or security_admin.
    Transferring leadership to an analyst_tier_1 is prohibited.
    """
    if not has_global_role(
        current_global_role,
        {
            GlobalRole.ANALYST_TIER_1,
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    ):
        return False

    if not has_case_role(current_case_role, {CaseRole.LEAD}):
        return False

    return has_global_role(
        target_global_role,
        {
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    )


def can_manage_case_assignments(
    global_role: GlobalRole | str,
    case_role: CaseRole | str | None,
) -> bool:
    """
    Decision 3A: Managing investigator assignments.
    Strictly requires global role analyst_tier_2 or security_admin AND case role Lead.
    Tier-1 case lead CANNOT manage investigator assignments.
    """
    if not has_global_role(
        global_role,
        {
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    ):
        return False

    return has_case_role(case_role, {CaseRole.LEAD})


def can_close_or_archive_case(
    global_role: GlobalRole | str,
    case_role: CaseRole | str | None,
) -> bool:
    """
    Decision 3A: Formal case closure or archival.
    Strictly requires global role analyst_tier_2 or security_admin AND case role Lead.
    Tier-1 case lead CANNOT close or archive cases.
    """
    if not has_global_role(
        global_role,
        {
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    ):
        return False

    return has_case_role(case_role, {CaseRole.LEAD})


def can_execute_case_synthesis(
    global_role: GlobalRole | str,
    case_role: CaseRole | str | None,
) -> bool:
    """
    Decision 2A & 3A: AI Synthesis execution on case context.
    Permitted: Active investigator or lead holding global role Tier-1, Tier-2, or Admin.
    Viewers are prohibited.
    Unassigned security_admin is prohibited (Decision 2A Parity).
    """
    if not has_global_role(
        global_role,
        {
            GlobalRole.ANALYST_TIER_1,
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    ):
        return False

    return has_case_role(
        case_role,
        {
            CaseRole.INVESTIGATOR,
            CaseRole.LEAD,
        },
    )


def can_link_case_evidence(
    global_role: GlobalRole | str,
    case_role: CaseRole | str | None,
) -> bool:
    """
    Case evidence linking.
    Permitted: Active investigator or lead holding global role Tier-1, Tier-2, or Admin.
    Viewers are prohibited.
    Unassigned security_admin is prohibited (Decision 2A Parity).
    """
    if not has_global_role(
        global_role,
        {
            GlobalRole.ANALYST_TIER_1,
            GlobalRole.ANALYST_TIER_2,
            GlobalRole.SECURITY_ADMIN,
        },
    ):
        return False

    return has_case_role(
        case_role,
        {
            CaseRole.INVESTIGATOR,
            CaseRole.LEAD,
        },
    )

