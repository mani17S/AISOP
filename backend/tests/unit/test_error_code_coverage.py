"""
Error-code coverage tests (Phase 2.3).

Static checks over every raise site in ``backend/app`` plus parameterized behaviour checks of the shared domain codes.
No database, no network. The central status-derived mapping still covers every site that has no specific code.
"""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from app.core.errors import (
    CODE_PATTERN,
    DOMAIN_CODES,
    ApiError,
    CodedHTTPException,
    code_for_status,
    install_error_handlers,
)
from app.middleware.correlation import RequestCorrelationMiddleware

pytestmark = pytest.mark.anyio

APP_ROOT = Path(__file__).resolve().parents[2] / "app"
RAISERS = {"HTTPException", "ApiError", "CodedHTTPException", "StructuredHttpError"}
EXC_NAMES = {"exc", "e", "err", "error", "ex", "exception"}


def _call_name(node: ast.Call) -> str:
    return getattr(node.func, "id", getattr(node.func, "attr", ""))


def _sites():
    for path in APP_ROOT.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _call_name(node) in RAISERS:
                yield path.relative_to(APP_ROOT).as_posix(), node


def _message_expr(node: ast.Call):
    for kw in node.keywords:
        if kw.arg == "detail":
            return kw.value
    name = _call_name(node)
    if name == "ApiError" and len(node.args) > 2:
        return node.args[2]
    if name == "HTTPException" and len(node.args) > 1:
        return node.args[1]
    if name == "CodedHTTPException" and len(node.args) > 1:
        return node.args[1]
    return None


def test_inventory_is_stable_and_counted():
    names = [_call_name(n) for _, n in _sites()]
    # Reported numbers in the Phase 2.3 matrix; a change here means the matrix must be updated on purpose.
    assert names.count("HTTPException") + names.count("CodedHTTPException") + names.count("ApiError") + names.count("StructuredHttpError") == 109 + 0  # 107 + 2: the Security overview role refusal (2026-11-22) and the hourly case-creation limit (2026-11-23)
    assert names.count("StructuredHttpError") == 1


def test_every_specific_code_literal_is_registered_and_well_formed():
    used: set[str] = set()
    for rel, node in _sites():
        name = _call_name(node)
        code = None
        for kw in node.keywords:
            if kw.arg == "code" and isinstance(kw.value, ast.Constant):
                code = kw.value.value
        if name == "ApiError" and len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
            code = node.args[1].value
        if name == "ApiError" and code is None and len(node.args) > 1 and isinstance(node.args[1], ast.Name):
            code = node.args[1].id  # constant imported from errors.py; resolved below
        if name == "CodedHTTPException":
            assert isinstance(code, str), f"{rel}:{node.lineno} CodedHTTPException needs a literal code"
        if isinstance(code, str):
            if name == "ApiError" and code.isupper() and code in dir(__import__("app.core.errors", fromlist=["x"])):
                code = getattr(__import__("app.core.errors", fromlist=["x"]), code)
            assert CODE_PATTERN.match(code), f"{rel}:{node.lineno} malformed code {code!r}"
            assert code in DOMAIN_CODES or code in {
                "QUERY_PARAMETER_INVALID", "CONTEXT_INTEGRITY_FAILED", "CONTEXT_BUDGET_EXCEEDED", "REPORT_PARAMETER_INVALID",
                "EVIDENCE_PERSISTENCE_FAILED", "SERVICE_UNAVAILABLE",
            }, f"{rel}:{node.lineno} code {code!r} not registered in DOMAIN_CODES"
            used.add(code)
    # No dead registrations: every registered code is used by at least one site.
    assert DOMAIN_CODES - used == set(), f"registered but unused: {sorted(DOMAIN_CODES - used)}"


def test_no_raise_site_puts_exception_text_in_its_message():
    # str(x) of typed business values (UUID lists, status enums) is allowed; any reference to an exception variable is not.
    # Two sites interpolate a sorted list of validated UUIDs and are covered by this allowance on purpose.
    offenders = []
    for rel, node in _sites():
        expr = _message_expr(node)
        if expr is None:
            continue
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name) and sub.id in EXC_NAMES:
                # allowed only as the first argument of safe_exception_text(...)
                parent_safe = any(
                    isinstance(p, ast.Call) and _call_name(p) == "safe_exception_text" and sub in ast.walk(p.args[0])
                    for p in ast.walk(expr)
                    if isinstance(p, ast.Call) and p.args
                )
                if not parent_safe:
                    offenders.append(f"{rel}:{node.lineno} uses exception variable {sub.id!r} in the message")
    assert offenders == []


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 409, 413, 415, 422, 429, 503, 500, 502])
def test_every_status_has_a_central_code_even_without_a_specific_one(status):
    assert CODE_PATTERN.match(code_for_status(status))


def _app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestCorrelationMiddleware)
    install_error_handlers(app)

    @app.get("/coded/{status}/{code}")
    async def coded(status: int, code: str):
        raise CodedHTTPException(status, "Authored safe message.", code=code)

    @app.get("/plain/{status}")
    async def plain(status: int):
        from fastapi import HTTPException

        raise HTTPException(status, "Authored safe message.")

    return app


SPECIFIC = [
    ("ACCOUNT_DEACTIVATED", 403), ("AUTHORIZATION_REVOKED", 403), ("MACHINE_CREDENTIAL_NOT_PERMITTED", 403),
    ("UNSCOPED_ENDPOINT_DISABLED", 403), ("CASE_TERMINAL_STATE", 409), ("EVIDENCE_ALREADY_LINKED", 409),
    ("ASSIGNMENT_ALREADY_EXISTS", 409), ("SYNTHESIS_INPUT_CHANGED", 409), ("EVIDENCE_NOT_FOUND", 404),
    ("DUPLICATE_EVIDENCE_IDS", 400), ("ASSIGNMENT_TARGET_INVALID", 400), ("LEADERSHIP_RULE_VIOLATION", 400),
    ("NOT_CASE_LEAD", 403), ("AUTHORIZATION_SERVICE_UNAVAILABLE", 500), ("AUTHENTICATION_SERVICE_UNAVAILABLE", 500),
    ("AUDIT_LOGGING_FAILED", 500), ("REPORT_FORMATTING_FAILED", 500), ("INVALID_CASE_IDENTIFIER", 422),
]


@pytest.mark.parametrize("code,status", SPECIFIC)
async def test_specific_codes_surface_with_status_and_authored_message(code, status):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=_app(), raise_app_exceptions=False), base_url="http://t") as c:
        res = await c.get(f"/coded/{status}/{code}")
    assert res.status_code == status
    body = res.json()
    assert body["error"]["code"] == code
    assert body["detail"] == body["error"]["message"] == "Authored safe message."
    assert body["error"]["request_id"] == res.headers["X-Request-ID"]


@pytest.mark.parametrize("status,code", [(401, "AUTHENTICATION_REQUIRED"), (403, "PERMISSION_DENIED"), (404, "RESOURCE_NOT_FOUND"), (409, "CONFLICT"), (422, "VALIDATION_FAILED")])
async def test_sites_without_a_specific_code_keep_the_status_derived_code(status, code):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=_app(), raise_app_exceptions=False), base_url="http://t") as c:
        res = await c.get(f"/plain/{status}")
    assert res.status_code == status and res.json()["error"]["code"] == code


async def test_a_malformed_code_is_ignored_not_echoed():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=_app(), raise_app_exceptions=False), base_url="http://t") as c:
        res = await c.get("/coded/409/not_a_valid_code")
    assert res.status_code == 409 and res.json()["error"]["code"] == "CONFLICT"
    assert "not_a_valid_code" not in res.text


def test_api_error_still_exposes_code():
    assert ApiError(422, "CONTEXT_BUDGET_EXCEEDED", "m").code == "CONTEXT_BUDGET_EXCEEDED"
