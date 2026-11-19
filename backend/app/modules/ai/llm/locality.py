"""
Local-first endpoint guard for the Ollama adapter (and the embedder that shares its endpoint).

The check is purely syntactic: it never resolves DNS and never opens a connection. Only ``localhost``, ``127.0.0.0/8`` and ``::1`` count as local.
Anything else needs the explicit operator opt-in ``LLM_ALLOW_NON_LOCAL_ENDPOINT=true``. URLs carrying credentials are always rejected so that
secrets can never reach logs, health output or error messages. Error messages never echo the configured URL.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from app.modules.ai.llm.exceptions import LLMConfigurationError


def is_local_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_endpoint_allowed(base_url: str, allow_non_local: bool) -> None:
    """Raise ``LLMConfigurationError`` (fixed, secret-free message) unless the endpoint is acceptable under the local-first policy."""
    try:
        parts = urlsplit((base_url or "").strip())
        host, scheme, has_credentials = parts.hostname, parts.scheme.lower(), bool(parts.username or parts.password)
        parts.port  # noqa: B018 - validates the port component
    except ValueError:
        raise LLMConfigurationError("LLM endpoint configuration is invalid.") from None
    if scheme not in ("http", "https") or not host:
        raise LLMConfigurationError("LLM endpoint configuration is invalid (an http(s) URL with a host is required).")
    if has_credentials:
        raise LLMConfigurationError("LLM endpoint configuration is invalid (credentials in the URL are not allowed).")
    if not allow_non_local and not is_local_host(host):
        raise LLMConfigurationError(
            "LLM endpoint is not local. Set LLM_ALLOW_NON_LOCAL_ENDPOINT=true to explicitly allow sending prompts to another host."
        )
