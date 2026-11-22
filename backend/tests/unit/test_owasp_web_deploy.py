"""
OWASP Top 10 (2021) web and deployment checks (static, offline, no live services).

Each test is a regression guard for one finding in docs/07_Security/OWASP_Top10_2021_Checklist.md. They read configuration
and source text only: no network, no Docker, no database. Run from the repository root.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[3]
NGINX = ROOT / "deploy" / "nginx" / "nginx.conf"
NGINX_LOCAL = ROOT / "deploy" / "nginx" / "nginx.local.conf"
HEADERS = ROOT / "frontend" / "public" / "_headers"
INDEX_HTML = ROOT / "frontend" / "index.html"
COMPOSE = ROOT / "docker-compose.yml"
RENDER = ROOT / "render.yaml"
BACKEND_APP = ROOT / "backend" / "app"
FRONTEND_SRC = ROOT / "frontend" / "src"


# ── minimal nginx parser (blocks and add_header only) ─────────────────────────────────────────────────────────────────

def _strip_comments(text: str) -> str:
    return re.sub(r"(?m)#.*$", "", text)


def _blocks(text: str, header: str) -> list[str]:
    """Return the bodies of every ``header { ... }`` block (brace matched), outermost matches only."""
    out: list[str] = []
    for m in re.finditer(header + r"\s*\{", text):
        depth, i = 1, m.end()
        while depth and i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
        out.append(text[m.end(): i - 1])
    return out


def _direct(body: str) -> str:
    """Body text with nested ``{...}`` blocks removed, so only directives at this level remain."""
    out, depth = [], 0
    for ch in body:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _add_headers(body: str) -> dict[str, str]:
    return {m.group(1).lower(): m.group(2) for m in re.finditer(r'add_header\s+(\S+)\s+("(?:[^"]*)"|\'[^\']*\')', _direct(body))}


def _https_server(text: str) -> str:
    for server in _blocks(text, r"(?m)^\s*server"):
        if "listen 443" in server or "listen 8443" in server:
            return server
    raise AssertionError("no TLS server block found")


def _walk_locations(server_body: str):
    """Yield (name, effective_add_headers) for every location, applying nginx add_header inheritance (none declared => inherit)."""
    server_headers = _add_headers(server_body)

    def rec(body: str, inherited: dict[str, str]):
        for name, inner in _location_pairs(body):
            own = _add_headers(inner)
            effective = own if own else inherited
            yield name, effective
            yield from rec(inner, effective)

    yield from rec(server_body, server_headers)


def _location_pairs(body: str):
    pairs = []
    for m in re.finditer(r"location\s+([^{]+?)\s*\{", body):
        # only direct children: skip locations that sit inside another location's braces
        before = body[: m.start()]
        if before.count("{") - before.count("}") != 0:
            continue
        depth, i = 1, m.end()
        while depth and i < len(body):
            depth += {"{": 1, "}": -1}.get(body[i], 0)
            i += 1
        pairs.append((m.group(1).strip(), body[m.end(): i - 1]))
    return pairs


# ── A05: nginx security headers survive add_header inheritance ────────────────────────────────────────────────────────

REQUIRED_HEADERS = ("strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy", "content-security-policy")


def test_nginx_every_location_keeps_security_headers():
    """nginx drops ALL inherited add_header directives in a location that declares any add_header of its own."""
    server = _https_server(_strip_comments(NGINX.read_text(encoding="utf-8")))
    seen = list(_walk_locations(server))
    assert seen, "expected location blocks"
    for name, headers in seen:
        missing = [h for h in REQUIRED_HEADERS if h not in headers]
        assert not missing, f"location {name!r} loses security headers {missing} (add_header inheritance)"


def test_nginx_csp_is_tight_and_set_once_per_response():
    server = _https_server(_strip_comments(NGINX.read_text(encoding="utf-8")))
    csp = _add_headers(server)["content-security-policy"]
    assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp and "base-uri 'self'" in csp
    connect = re.search(r"connect-src ([^;]*)", csp).group(1).split()
    assert connect == ["'self'"], f"connect-src must be same-origin only behind the proxy, got {connect}"
    assert "'unsafe-eval'" not in csp
    script = re.search(r"script-src ([^;]*)", csp).group(1).split()
    assert script == ["'self'"], "script-src must be 'self' only (style-src keeps 'unsafe-inline' for React inline styles)"


def test_nginx_does_not_proxy_api_docs_or_openapi():
    text = _strip_comments(NGINX.read_text(encoding="utf-8"))
    server = _https_server(text)
    names = {name: inner for name, inner in _location_pairs(server)}
    docs = [n for n in names if "docs" in n or "redoc" in n or "openapi" in n]
    assert docs, "docs/redoc/openapi must be handled explicitly"
    for n in docs:
        assert "proxy_pass" not in names[n], f"{n} must not be proxied (OpenAPI is a map of every endpoint)"
        assert "return 404" in names[n]
    assert any("openapi" in n for n in names), "the OpenAPI JSON path must be blocked too"


@pytest.mark.parametrize("path", [NGINX, NGINX_LOCAL])
def test_nginx_tls_only_modern_protocols(path):
    text = _strip_comments(path.read_text(encoding="utf-8"))
    protocols = re.search(r"ssl_protocols\s+([^;]+);", text).group(1).split()
    assert set(protocols) <= {"TLSv1.2", "TLSv1.3"}
    assert "ssl_session_tickets off" in text
    assert "server_tokens off" in text


def test_nginx_production_template_has_hsts_and_rate_limit_and_no_embedded_secrets():
    raw = NGINX.read_text(encoding="utf-8")
    text = _strip_comments(raw)
    assert "Strict-Transport-Security" in text and "max-age=31536000" in text
    assert "limit_req_zone" in text and "limit_req zone=" in text, "ingress request-rate limit (A04) is missing"
    assert "BEGIN PRIVATE KEY" not in raw
    assert re.search(r"proxy_set_header\s+X-Forwarded-For\s+\$remote_addr;", text), "X-Forwarded-For must be overwritten, not appended"


# ── A05: static host headers (Cloudflare Pages) ───────────────────────────────────────────────────────────────────────

def test_pages_headers_file_carries_framing_and_transport_headers():
    text = HEADERS.read_text(encoding="utf-8")
    assert "X-Content-Type-Options: nosniff" in text
    assert "X-Frame-Options: DENY" in text
    assert "Strict-Transport-Security:" in text
    csp = re.search(r"Content-Security-Policy:\s*(.+)", text)
    assert csp, "frame-ancestors is ignored in a <meta> CSP, so a real header is required"
    assert "frame-ancestors 'none'" in csp.group(1)
    # connect-src is set by the meta CSP (it is rewritten at build time for a hosted API); a header with default-src would intersect and block it.
    assert "default-src" not in csp.group(1) and "connect-src" not in csp.group(1)


def test_index_html_csp_has_no_script_escape_hatches():
    html = INDEX_HTML.read_text(encoding="utf-8")
    csp = re.search(r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"', html).group(1)
    directives = {d.split()[0]: d.split()[1:] for d in csp.split(";") if d.strip()}
    assert directives["script-src"] == ["'self'"]
    assert directives["default-src"] == ["'self'"]
    assert directives["object-src"] == ["'none'"]
    assert directives["base-uri"] == ["'self'"]
    assert all(src in {"'self'", "http://127.0.0.1:8000", "http://localhost:8000"} for src in directives["connect-src"])
    assert "*" not in csp and "'unsafe-eval'" not in csp
    # No third-party origin is loaded by the page (fonts are bundled from npm packages, supply-chain row).
    assert not re.search(r'(src|href)="https?://', html)


# ── A05 / A02: compose and Render blueprint ───────────────────────────────────────────────────────────────────────────

def test_compose_database_is_loopback_only_and_healthcheck_follows_overrides():
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    pg = compose["services"]["postgres"]
    for port in pg["ports"]:
        assert str(port).startswith("127.0.0.1:"), f"database port {port} must be bound to loopback"
    env = pg["environment"]
    # Local default is allowed only because the port is loopback; it must be overridable, and the healthcheck must follow the override.
    assert "${POSTGRES_PASSWORD:-" in env["POSTGRES_PASSWORD"]
    test = " ".join(pg["healthcheck"]["test"])
    assert "-U aisop" not in test and "-d aisop_dev" not in test, "healthcheck hardcodes the default user/db and breaks when they are overridden"
    assert "POSTGRES_USER" in test and "POSTGRES_DB" in test
    assert "privileged" not in pg and "network_mode" not in pg


def test_render_blueprint_is_production_hardened_and_holds_no_secrets():
    blueprint = yaml.safe_load(RENDER.read_text(encoding="utf-8"))
    for svc in blueprint["services"]:
        env = {e["key"]: e for e in svc["envVars"]}
        assert env["ENVIRONMENT"]["value"] == "production"
        assert env["API_AUTH_ENABLED"]["value"] == "true"
        assert env["API_AUTH_ALLOW_LEGACY_KEYS"]["value"] == "false"
        assert env["LLM_ENABLED"]["value"] == "false"
        for secret in ("DATABASE_URL", "CORS_ORIGINS"):
            assert env[secret].get("sync") is False and "value" not in env[secret], f"{secret} must be set in the dashboard, not the repo"
        assert "DEBUG" not in env or env["DEBUG"]["value"] == "false"
        assert "API_AUTH_KEYS" not in env, "a static key must never be committed"
    assert "aisop:aisop" not in RENDER.read_text(encoding="utf-8")


def test_production_environment_disables_api_docs():
    """A05: Swagger/OpenAPI are development-only. Builds the app in production mode (no lifespan, no database)."""
    import os

    from fastapi.testclient import TestClient

    from app.core.config import get_settings

    saved = {k: os.environ.get(k) for k in ("ENVIRONMENT", "API_AUTH_ENABLED")}
    os.environ["ENVIRONMENT"] = "production"
    os.environ["API_AUTH_ENABLED"] = "true"
    get_settings.cache_clear()
    try:
        from app.main import create_app

        client = TestClient(create_app())
        for path in ("/docs", "/redoc", "/api/v1/openapi.json", "/openapi.json"):
            assert client.get(path).status_code == 404, path
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        get_settings.cache_clear()


# ── A03: injection sinks in backend source ────────────────────────────────────────────────────────────────────────────

def _backend_py_files():
    return [p for p in BACKEND_APP.rglob("*.py") if "__pycache__" not in p.parts and "migrations" not in p.parts]


def test_backend_has_no_dynamic_code_execution_or_unsafe_deserialization():
    banned_calls = {"eval", "exec", "compile", "__import__"}
    banned_attrs = {("os", "system"), ("os", "popen"), ("pickle", "load"), ("pickle", "loads"), ("marshal", "load"), ("marshal", "loads"),
                    ("subprocess", "run"), ("subprocess", "Popen"), ("subprocess", "call"), ("subprocess", "check_output"), ("yaml", "load"), ("yaml", "unsafe_load")}
    offenders = []
    for path in _backend_py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Name) and f.id in banned_calls:
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} {f.id}()")
                if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and (f.value.id, f.attr) in banned_attrs:
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} {f.value.id}.{f.attr}()")
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} shell=True")
    assert not offenders, offenders


def test_raw_sql_text_calls_are_static_string_literals():
    """sqlalchemy text()/exec_driver_sql must never receive an f-string, concatenation, %-format or .format() (SQL injection)."""
    offenders = []
    for path in _backend_py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
            if name not in {"text", "exec_driver_sql"} or not node.args:
                continue
            if name == "text" and isinstance(f, ast.Attribute) and not (isinstance(f.value, ast.Name) and f.value.id in {"sa", "sqlalchemy"}):
                continue  # some other object's .text() method

            def static(n: ast.AST) -> bool:
                if isinstance(n, ast.Constant):
                    return isinstance(n.value, str)
                if isinstance(n, ast.JoinedStr):
                    return False
                if isinstance(n, ast.BinOp):
                    # implicit adjacent literals are folded by the parser; an explicit + of literals is still static
                    return isinstance(n.op, ast.Add) and static(n.left) and static(n.right)
                return False

            if not static(node.args[0]):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert not offenders, f"non-literal SQL passed to text(): {offenders}"


# ── A03: XSS sinks in the frontend (code only, comments stripped) ─────────────────────────────────────────────────────

def _frontend_code(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)(^|\s)//.*$", "", text)


def test_frontend_source_has_no_html_injection_or_eval_sinks():
    sinks = re.compile(r"dangerouslySetInnerHTML|\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function\(|javascript:")
    offenders = []
    for path in list(FRONTEND_SRC.rglob("*.ts")) + list(FRONTEND_SRC.rglob("*.tsx")):
        for m in sinks.finditer(_frontend_code(path)):
            offenders.append(f"{path.relative_to(ROOT)}: {m.group(0)}")
    assert not offenders, offenders


def test_frontend_never_uses_localstorage_or_logs_secrets():
    offenders = []
    for path in list(FRONTEND_SRC.rglob("*.ts")) + list(FRONTEND_SRC.rglob("*.tsx")):
        code = _frontend_code(path)
        if re.search(r"\blocalStorage\b", code):
            offenders.append(f"{path.relative_to(ROOT)}: localStorage")
        for m in re.finditer(r"console\.(log|debug|info|warn|error)\(([^;]*)\)", code):
            if re.search(r"api[_-]?key|apiKey|X-API-Key|Authorization", m.group(2), re.I):
                offenders.append(f"{path.relative_to(ROOT)}: console logs a key")
    assert not offenders, offenders


def test_frontend_href_values_from_data_are_not_unvalidated():
    """The only data-driven href is the operator contact URL, a compile-time constant that must be https."""
    operator = (FRONTEND_SRC / "legal" / "operator.ts").read_text(encoding="utf-8")
    assert re.search(r"contactUrl:\s*'https://", operator)
    dynamic = []
    for path in FRONTEND_SRC.rglob("*.tsx"):
        for m in re.finditer(r"(?:href|src)=\{([^}]+)\}", _frontend_code(path)):
            dynamic.append((path.name, m.group(1).strip()))
    assert all(name == "Legal.tsx" and expr == "operator.contactUrl" for name, expr in dynamic), dynamic


# ── A10: SSRF guards ───────────────────────────────────────────────────────────────────────────────────────────────────

def test_llm_endpoint_guard_rejects_non_local_hosts_credentials_and_metadata_addresses():
    from app.modules.ai.llm.exceptions import LLMConfigurationError
    from app.modules.ai.llm.locality import assert_endpoint_allowed

    assert_endpoint_allowed("http://127.0.0.1:11434", False)
    assert_endpoint_allowed("http://localhost:11434", False)
    for bad in ("http://169.254.169.254/latest", "http://10.0.0.5:11434", "http://[::ffff:169.254.169.254]/", "http://evil.example",
                "http://127.0.0.1.evil.example:11434", "file:///etc/passwd", "http://user:pw@127.0.0.1:11434", "ftp://127.0.0.1", ""):
        with pytest.raises(LLMConfigurationError):
            assert_endpoint_allowed(bad, False)
