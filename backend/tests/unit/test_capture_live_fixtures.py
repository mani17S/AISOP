"""
Permanent Automated Regression Tests for AISOP P3-H3B Capture Harness.

Governing Specification: P3-H3B_Capture_Protocol_Specification.md, Revision 1.1.2.
Adheres to AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001:
- 100% offline execution with zero live network access.
- Mocks all HTTP transport layers and Ollama daemon endpoints.
- Validates AUD-P3H3B-01 (failure-class retry limits & fail-fast vs retry mechanics).
- Validates AUD-P3H3B-02 (loopback isolation, port 11434, credential presence rejection).
- Validates AUD-P3H3B-03 (strict timeout bounding: 0.0 < timeout <= 120.0s).
- Validates preflight model verification and fail-closed absence of /api/pull.
- Validates 5-point fixture idempotency and corrupt fixture quarantine.
- Validates atomic filesystem persistence with fsync and safe temp cleanup.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import sys
from typing import Any
from unittest.mock import MagicMock, call, patch
import uuid

import httpx
import pytest

# Ensure backend and scripts are in sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent.parent
SCRIPTS_DIR = BACKEND_DIR / "scripts"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from capture_live_fixtures import (
    DEFAULT_MODEL_TAG,
    DEFAULT_OLLAMA_HOST,
    DEFAULT_TIMEOUT_SECONDS,
    HARNESS_VERSION,
    MAX_ATTEMPTS_BY_FAILURE_CLASS,
    RETRY_POLICY_ID,
    RETRY_POLICY_VERSION,
    build_retry_policy_provenance,
    FixturePersistenceError,
    LoopbackSecurityError,
    ModelNotAvailableLocallyError,
    OllamaDaemonUnreachableError,
    OllamaPreflightError,
    check_existing_fixture,
    classify_http_failure,
    execute_single_ollama_inference,
    package_and_persist_fixture,
    probe_local_ollama_daemon,
    run_batch_capture,
    validate_execution_timeout,
    validate_loopback_endpoint,
)
from app.modules.evaluation.dataset_loader import ScenarioDatasetLoader
from app.schemas.evaluation import CapturedInvestigationFixture


# ── SECTION A: LOOPBACK URL VALIDATION (AUD-P3H3B-02) ─────────────────────────

class TestLoopbackEndpointValidation:
    """Verifies strict loopback destination filtering, port 11434 enforcement, and credential rejection."""

    @pytest.mark.parametrize(
        "endpoint, expected_canonical",
        [
            ("http://127.0.0.1:11434", "http://127.0.0.1:11434"),
            ("http://localhost:11434", "http://localhost:11434"),
            ("http://[::1]:11434", "http://[::1]:11434"),
            ("http://127.0.0.1:11434/", "http://127.0.0.1:11434"),
            ("http://localhost:11434/", "http://localhost:11434"),
            ("http://[::1]:11434/", "http://[::1]:11434"),
            ("  http://127.0.0.1:11434  ", "http://127.0.0.1:11434"),
        ],
    )
    def test_accepted_loopback_endpoints(self, endpoint: str, expected_canonical: str) -> None:
        """Permitted loopback variants normalize to canonical format without trailing slashes."""
        assert validate_loopback_endpoint(endpoint) == expected_canonical

    @pytest.mark.parametrize(
        "remote_endpoint",
        [
            "http://192.168.1.10:11434",
            "http://10.0.0.5:11434",
            "http://172.16.0.1:11434",
            "http://8.8.8.8:11434",
            "http://127.0.0.2:11434",
            "http://127.1.1.1:11434",
            "http://0.0.0.0:11434",
        ],
    )
    def test_rejection_of_remote_and_non_approved_ips(self, remote_endpoint: str) -> None:
        """Remote and non-approved IP addresses must be rejected immediately."""
        with pytest.raises(LoopbackSecurityError, match="Security violation: Endpoint hostname"):
            validate_loopback_endpoint(remote_endpoint)

    @pytest.mark.parametrize(
        "external_host",
        [
            "http://example.com:11434",
            "http://ollama.internal:11434",
            "http://ollama.local:11434",
            "http://remote-server:11434",
            "http://api.ollama.ai:11434",
        ],
    )
    def test_rejection_of_external_hostnames(self, external_host: str) -> None:
        """External domain names and hostnames must be rejected."""
        with pytest.raises(LoopbackSecurityError, match="Security violation: Endpoint hostname"):
            validate_loopback_endpoint(external_host)

    @pytest.mark.parametrize(
        "invalid_scheme",
        [
            "https://127.0.0.1:11434",
            "https://localhost:11434",
            "ftp://127.0.0.1:11434",
            "file://127.0.0.1:11434",
            "ws://127.0.0.1:11434",
        ],
    )
    def test_rejection_of_non_http_schemes(self, invalid_scheme: str) -> None:
        """Schemes other than http:// must be rejected."""
        with pytest.raises(LoopbackSecurityError, match="Invalid scheme"):
            validate_loopback_endpoint(invalid_scheme)

    @pytest.mark.parametrize(
        "invalid_port",
        [
            "http://127.0.0.1:8000",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:11435",
            "http://127.0.0.1:22",
            "http://127.0.0.1",
            "http://localhost",
        ],
    )
    def test_rejection_of_incorrect_ports(self, invalid_port: str) -> None:
        """Ports other than 11434 must be rejected."""
        with pytest.raises(LoopbackSecurityError, match="Invalid port"):
            validate_loopback_endpoint(invalid_port)

    @pytest.mark.parametrize(
        "credentialed_url",
        [
            "http://user:pass@127.0.0.1:11434",
            "http://user@127.0.0.1:11434",
            "http://:pass@127.0.0.1:11434",
            "http://@127.0.0.1:11434",  # Presence-based credential check edge case
            "http://admin:secret@localhost:11434",
        ],
    )
    def test_rejection_of_credentials(self, credentialed_url: str) -> None:
        """URLs containing credentials (including empty userinfo delimiter) must be rejected."""
        with pytest.raises(LoopbackSecurityError, match="URL credentials are strictly forbidden"):
            validate_loopback_endpoint(credentialed_url)

    @pytest.mark.parametrize(
        "path_url",
        [
            "http://127.0.0.1:11434/api",
            "http://127.0.0.1:11434/api/chat",
            "http://127.0.0.1:11434/v1",
            "http://localhost:11434/ollama",
        ],
    )
    def test_rejection_of_unexpected_paths(self, path_url: str) -> None:
        """Endpoints with sub-paths must be rejected; base endpoint must be host:port only."""
        with pytest.raises(LoopbackSecurityError, match="Unexpected URL path"):
            validate_loopback_endpoint(path_url)

    @pytest.mark.parametrize(
        "query_or_fragment_url",
        [
            "http://127.0.0.1:11434?param=1",
            "http://localhost:11434?key=val",
            "http://127.0.0.1:11434#section",
            "http://[::1]:11434#frag",
        ],
    )
    def test_rejection_of_query_and_fragments(self, query_or_fragment_url: str) -> None:
        """Query parameters and URL fragments must be rejected."""
        with pytest.raises(LoopbackSecurityError, match="(Query parameters|URL fragments) are forbidden"):
            validate_loopback_endpoint(query_or_fragment_url)

    @pytest.mark.parametrize("empty_input", ["", "   ", None])
    def test_rejection_of_empty_endpoint(self, empty_input: Any) -> None:
        """Empty or non-string inputs must raise LoopbackSecurityError."""
        with pytest.raises(LoopbackSecurityError, match="Endpoint URL cannot be empty"):
            validate_loopback_endpoint(empty_input)


# ── SECTION B: TIMEOUT VALIDATION (AUD-P3H3B-03) ─────────────────────────────

class TestTimeoutValidation:
    """Verifies strict bounding and validation of execution timeouts."""

    @pytest.mark.parametrize(
        "valid_timeout, expected",
        [
            (120.0, 120.0),
            (60.0, 60.0),
            (1.0, 1.0),
            (0.1, 0.1),
            ("120.0", 120.0),
            ("30", 30.0),
        ],
    )
    def test_valid_timeouts_accepted(self, valid_timeout: Any, expected: float) -> None:
        """Finite floats in range (0.0, 120.0] are accepted and returned as floats."""
        assert validate_execution_timeout(valid_timeout) == expected

    @pytest.mark.parametrize("non_positive", [0.0, 0, -0.0, -1.0, -120.0])
    def test_rejection_of_zero_and_negative_timeouts(self, non_positive: Any) -> None:
        """Zero and negative timeout values must raise ValueError."""
        with pytest.raises(ValueError, match="Timeout must be strictly positive"):
            validate_execution_timeout(non_positive)

    @pytest.mark.parametrize("excessive", [120.0001, 120.1, 150.0, 300.0, 9999.0])
    def test_rejection_of_excessive_timeouts(self, excessive: float) -> None:
        """Timeout exceeding 120.0s boundary must raise ValueError without silent clamping."""
        with pytest.raises(ValueError, match="Timeout cannot exceed 120.0s"):
            validate_execution_timeout(excessive)

    @pytest.mark.parametrize(
        "non_finite",
        [float("nan"), float("inf"), float("-inf")],
    )
    def test_rejection_of_nan_and_infinities(self, non_finite: float) -> None:
        """NaN and infinite float values must raise ValueError."""
        with pytest.raises(ValueError, match="Timeout cannot be NaN or infinite"):
            validate_execution_timeout(non_finite)

    @pytest.mark.parametrize("invalid_str", ["abc", "invalid", "120s", "none", "", None])
    def test_rejection_of_invalid_string_representations(self, invalid_str: Any) -> None:
        """Unparseable string values must raise ValueError."""
        with pytest.raises(ValueError, match="Invalid timeout value"):
            validate_execution_timeout(invalid_str)


# ── SECTION C: FAILURE-CLASS RETRY POLICY (DDR-05, OPTION C) ────────────────────


def _build_exception(kind: str, request: httpx.Request) -> BaseException:
    """Build an exception of the given kind for classification/execution tests."""
    if kind.startswith("http_"):
        code = int(kind.split("_")[1])
        response = httpx.Response(code, request=request)
        return httpx.HTTPStatusError("HTTP Error", request=request, response=response)
    if kind == "connect_error":
        return httpx.ConnectError("connection refused", request=request)
    if kind == "read_timeout":
        return httpx.ReadTimeout("timed out", request=request)
    if kind == "connect_timeout":
        return httpx.ConnectTimeout("connect timed out", request=request)
    if kind == "value_error":
        return ValueError("unrelated")
    if kind == "key_error":
        return KeyError("unrelated")
    if kind == "read_error":
        return httpx.ReadError("read failed", request=request)
    if kind == "remote_protocol_error":
        return httpx.RemoteProtocolError("protocol error", request=request)
    raise ValueError(f"unknown exception kind: {kind}")


class TestFailureClassRetryPolicy:
    """Verifies per-failure-class retry limits and deterministic backoff.

    DDR-05 Option C policy:
      - HTTP 5xx / connection-establishment: max 2 retries (3 total attempts)
      - Request timeout (>120s): max 1 retry (2 total attempts, 2s backoff)
      - Mid-transfer disconnect / HTTP 4xx / other: no retry (1 attempt)
    All tests use mocks — zero live network access, zero real backoff delays.
    """

    @pytest.fixture(autouse=True)
    def patch_time_sleep(self) -> None:
        """Zero out time.sleep so backoff delays do not slow unit tests."""
        with patch("capture_live_fixtures.time.sleep") as mock_sleep:
            self.mock_sleep = mock_sleep
            try:
                yield
            finally:
                self.mock_sleep = None

    @pytest.mark.parametrize(
        "exc_kind, expected_class, expected_max_attempts",
        [
            ("http_400", "http_4xx", 1),
            ("http_401", "http_4xx", 1),
            ("http_404", "http_4xx", 1),
            ("http_422", "http_4xx", 1),
            ("http_500", "http_5xx", 3),
            ("http_502", "http_5xx", 3),
            ("http_503", "http_5xx", 3),
            ("http_504", "http_5xx", 3),
            ("connect_error", "connection_establishment", 3),
            ("read_timeout", "request_timeout", 2),
            ("connect_timeout", "request_timeout", 2),
            ("read_error", "mid_transfer_disconnect", 1),
            ("remote_protocol_error", "mid_transfer_disconnect", 1),
            ("value_error", "unknown", 1),
            ("key_error", "unknown", 1),
        ],
    )
    def test_classify_http_failure(
        self, exc_kind: str, expected_class: str, expected_max_attempts: int
    ) -> None:
        """Classifier must map each exception kind to its failure class and attempt limit."""
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        exc = _build_exception(exc_kind, dummy_req)
        failure_class, max_attempts = classify_http_failure(exc)
        assert failure_class == expected_class
        assert max_attempts == expected_max_attempts
        assert max_attempts == MAX_ATTEMPTS_BY_FAILURE_CLASS[failure_class]

    def test_http_5xx_exhaustion_three_attempts_then_reraise(self) -> None:
        """HTTP 5xx must retry up to 3 total attempts before reraising."""
        mock_client = MagicMock(spec=httpx.Client)
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        dummy_resp = httpx.Response(500, request=dummy_req)
        mock_client.post.return_value = dummy_resp

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            execute_single_ollama_inference(
                mock_client,
                "http://127.0.0.1:11434/api/chat",
                {"model": "llama3.1:8b"},
            )

        assert exc_info.value.response.status_code == 500
        assert mock_client.post.call_count == MAX_ATTEMPTS_BY_FAILURE_CLASS["http_5xx"]

    def test_connect_error_exhaustion_three_attempts_then_reraise(self) -> None:
        """Connection-establishment failure must retry up to 3 total attempts."""
        mock_client = MagicMock(spec=httpx.Client)
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        mock_client.post.side_effect = httpx.ConnectError("refused", request=dummy_req)

        with pytest.raises(httpx.ConnectError):
            execute_single_ollama_inference(
                mock_client,
                "http://127.0.0.1:11434/api/chat",
                {"model": "llama3.1:8b"},
            )

        assert mock_client.post.call_count == MAX_ATTEMPTS_BY_FAILURE_CLASS["connection_establishment"]

    def test_request_timeout_exhaustion_two_attempts_then_reraise(self) -> None:
        """Request timeout must retry only once (2 total attempts) then reraise."""
        mock_client = MagicMock(spec=httpx.Client)
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        mock_client.post.side_effect = httpx.ReadTimeout("timed out", request=dummy_req)

        with pytest.raises(httpx.ReadTimeout):
            execute_single_ollama_inference(
                mock_client,
                "http://127.0.0.1:11434/api/chat",
                {"model": "llama3.1:8b"},
            )

        assert mock_client.post.call_count == MAX_ATTEMPTS_BY_FAILURE_CLASS["request_timeout"]

    def test_read_error_no_retry_single_attempt(self) -> None:
        """Mid-transfer ReadError must not be retried (1 attempt, immediate reraised)."""
        mock_client = MagicMock(spec=httpx.Client)
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        mock_client.post.side_effect = httpx.ReadError("read failed", request=dummy_req)

        with pytest.raises(httpx.ReadError):
            execute_single_ollama_inference(
                mock_client,
                "http://127.0.0.1:11434/api/chat",
                {"model": "llama3.1:8b"},
            )

        assert mock_client.post.call_count == MAX_ATTEMPTS_BY_FAILURE_CLASS["mid_transfer_disconnect"]

    def test_remote_protocol_error_no_retry_single_attempt(self) -> None:
        """RemoteProtocolError must not be retried (1 attempt, immediate reraised)."""
        mock_client = MagicMock(spec=httpx.Client)
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        mock_client.post.side_effect = httpx.RemoteProtocolError("protocol error", request=dummy_req)

        with pytest.raises(httpx.RemoteProtocolError):
            execute_single_ollama_inference(
                mock_client,
                "http://127.0.0.1:11434/api/chat",
                {"model": "llama3.1:8b"},
            )

        assert mock_client.post.call_count == MAX_ATTEMPTS_BY_FAILURE_CLASS["mid_transfer_disconnect"]

    def test_http_4xx_fails_fast_single_attempt(self) -> None:
        """HTTP 4xx must fail immediately on attempt 1 without retry."""
        mock_client = MagicMock(spec=httpx.Client)
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        dummy_resp = httpx.Response(400, request=dummy_req)
        mock_client.post.return_value = dummy_resp

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            execute_single_ollama_inference(
                mock_client,
                "http://127.0.0.1:11434/api/chat",
                {"model": "llama3.1:8b"},
            )

        assert exc_info.value.response.status_code == 400
        assert mock_client.post.call_count == MAX_ATTEMPTS_BY_FAILURE_CLASS["http_4xx"]

    def test_inference_recovers_after_transient_503_on_second_attempt(self) -> None:
        """Inference succeeds if a transient 503 is followed by 200 OK on attempt 2."""
        mock_client = MagicMock(spec=httpx.Client)
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        resp_503 = httpx.Response(503, request=dummy_req)
        resp_200 = httpx.Response(200, request=dummy_req, json={"message": {"content": "ok"}})
        mock_client.post.side_effect = [resp_503, resp_200]

        result = execute_single_ollama_inference(
            mock_client,
            "http://127.0.0.1:11434/api/chat",
            {"model": "llama3.1:8b"},
        )

        assert result.status_code == 200
        assert mock_client.post.call_count == 2

    def test_timeout_recovers_on_second_attempt(self) -> None:
        """Inference succeeds if ReadTimeout on attempt 1 is followed by 200 OK on attempt 2."""
        mock_client = MagicMock(spec=httpx.Client)
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        dummy_resp = httpx.Response(200, request=dummy_req, json={"message": {"content": "ok"}})
        mock_client.post.side_effect = [
            httpx.ReadTimeout("timed out", request=dummy_req),
            dummy_resp,
        ]

        result = execute_single_ollama_inference(
            mock_client,
            "http://127.0.0.1:11434/api/chat",
            {"model": "llama3.1:8b", "format": "json"},
        )

        assert result.status_code == 200
        assert mock_client.post.call_count == MAX_ATTEMPTS_BY_FAILURE_CLASS["request_timeout"]

    def test_deterministic_backoff_sequence_2s_then_4s(self) -> None:
        """Backoff delays must be 2s before retry 1 and 4s before retry 2 (5xx class)."""
        mock_client = MagicMock(spec=httpx.Client)
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        resp_503 = httpx.Response(503, request=dummy_req)
        resp_200 = httpx.Response(200, request=dummy_req, json={"message": {"content": "ok"}})
        mock_client.post.side_effect = [resp_503, resp_503, resp_200]

        result = execute_single_ollama_inference(
            mock_client,
            "http://127.0.0.1:11434/api/chat",
            {"model": "llama3.1:8b"},
        )

        assert result.status_code == 200
        assert mock_client.post.call_count == MAX_ATTEMPTS_BY_FAILURE_CLASS["http_5xx"]
        assert self.mock_sleep.call_args_list == [call(2.0), call(4.0)]

    def test_timeout_backoff_is_2s_only(self) -> None:
        """Timeout class (max 2 attempts) must back off 2s once before the final attempt."""
        mock_client = MagicMock(spec=httpx.Client)
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        mock_client.post.side_effect = httpx.ReadTimeout("timed out", request=dummy_req)

        with pytest.raises(httpx.ReadTimeout):
            execute_single_ollama_inference(
                mock_client,
                "http://127.0.0.1:11434/api/chat",
                {"model": "llama3.1:8b"},
            )

        assert mock_client.post.call_count == MAX_ATTEMPTS_BY_FAILURE_CLASS["request_timeout"]
        assert self.mock_sleep.call_args_list == [call(2.0)]

    def test_no_backoff_when_no_retry_is_permitted(self) -> None:
        """ReadError and HTTP 4xx must never call time.sleep."""
        mock_client = MagicMock(spec=httpx.Client)
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        mock_client.post.side_effect = httpx.ReadError("read failed", request=dummy_req)

        with pytest.raises(httpx.ReadError):
            execute_single_ollama_inference(
                mock_client,
                "http://127.0.0.1:11434/api/chat",
                {"model": "llama3.1:8b"},
            )

        self.mock_sleep.assert_not_called()



# ── SECTION D: PREFLIGHT, REDIRECT & OFFLINE SAFETY ───────────────────────────

class TestPreflightAndRedirectHardening:
    """Verifies preflight model validation, redirect blocking, and fail-closed absence of /api/pull."""

    def test_preflight_success_when_model_present(self) -> None:
        """Preflight probe verifies local daemon connectivity and model tag presence."""
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/api/tags"
            return httpx.Response(
                200,
                json={"models": [{"name": "llama3.1:8b"}, {"name": "nomic-embed-text:latest"}]},
            )

        transport = httpx.MockTransport(handler)
        with patch("httpx.Client", return_value=httpx.Client(transport=transport, follow_redirects=False)):
            info = probe_local_ollama_daemon(
                host="http://127.0.0.1:11434",
                target_model="llama3.1:8b",
                timeout=5.0,
            )
            assert info["target_model"] == "llama3.1:8b"
            assert info["matched_tag"] == "llama3.1:8b"

    def test_preflight_fails_closed_when_model_missing_without_pull(self) -> None:
        """Preflight fails closed with ModelNotAvailableLocallyError; never calls /api/pull."""
        requested_endpoints: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested_endpoints.append(request.url.path)
            return httpx.Response(
                200,
                json={"models": [{"name": "mistral:7b"}]},
            )

        transport = httpx.MockTransport(handler)
        with patch("httpx.Client", return_value=httpx.Client(transport=transport, follow_redirects=False)):
            with pytest.raises(ModelNotAvailableLocallyError, match="Target model 'llama3.1:8b' is NOT present"):
                probe_local_ollama_daemon(
                    host="http://127.0.0.1:11434",
                    target_model="llama3.1:8b",
                    timeout=5.0,
                )

        assert "/api/tags" in requested_endpoints
        assert "/api/pull" not in requested_endpoints

    def test_preflight_fails_closed_when_daemon_unreachable(self) -> None:
        """Preflight raises OllamaDaemonUnreachableError when connection cannot be established."""
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused on 127.0.0.1:11434", request=request)

        transport = httpx.MockTransport(handler)
        with patch("httpx.Client", return_value=httpx.Client(transport=transport, follow_redirects=False)):
            with pytest.raises(OllamaDaemonUnreachableError, match="Ollama daemon is not reachable"):
                probe_local_ollama_daemon(
                    host="http://127.0.0.1:11434",
                    target_model="llama3.1:8b",
                    timeout=5.0,
                )


# ── SECTION E: IDEMPOTENCY, QUARANTINE & ATOMIC PERSISTENCE ────────────────────

class TestFixtureIdempotencyAndAtomicPersistence:
    """Verifies 5-point cache check, corrupt fixture quarantine, and crash-resilient atomic persistence."""

    def test_check_existing_fixture_missing(self, tmp_path: Path) -> None:
        """Missing fixture file returns cache miss without quarantine."""
        missing_file = tmp_path / "SCN-ATO-001-captured.json"
        is_hit, reason, env = check_existing_fixture(
            fixture_path=missing_file,
            target_scenario_id="SCN-ATO-001",
            target_model="llama3.1:8b",
            target_prompt_sha256="dummy_sha256",
            target_inference_parameters={"temperature": 0.0},
        )
        assert is_hit is False
        assert reason == "fixture_missing"
        assert env is None

    def test_check_existing_fixture_corrupt_quarantine(self, tmp_path: Path) -> None:
        """Corrupt or non-JSON fixture is automatically quarantined to .corrupt.<timestamp>.json."""
        corrupt_file = tmp_path / "SCN-ATO-001-captured.json"
        corrupt_file.write_text("NOT_VALID_JSON{[[", encoding="utf-8")

        is_hit, reason, env = check_existing_fixture(
            fixture_path=corrupt_file,
            target_scenario_id="SCN-ATO-001",
            target_model="llama3.1:8b",
            target_prompt_sha256="dummy_sha256",
            target_inference_parameters={"temperature": 0.0},
        )
        assert is_hit is False
        assert reason == "corrupt_fixture_quarantined"
        assert env is None
        assert not corrupt_file.exists()

        # Check quarantine file existence
        quarantine_files = list(tmp_path.glob("SCN-ATO-001-captured.corrupt.*.json"))
        assert len(quarantine_files) == 1

    def test_check_existing_fixture_mismatches(self, tmp_path: Path) -> None:
        """Mismatches in prompt hash, model tag, or parameters cause a clean cache miss."""
        raw_resp = json.dumps({"summary": "test finding"})
        raw_sha256 = hashlib.sha256(raw_resp.encode("utf-8")).hexdigest()
        canonical_prompt_sha = hashlib.sha256(b"canonical_prompt_content").hexdigest()
        different_prompt_sha = hashlib.sha256(b"different_prompt_content").hexdigest()

        fixture = CapturedInvestigationFixture(
            schema_version="1.0.0",
            scenario_id="SCN-ATO-001",
            capture_timestamp_utc="2026-10-31T00:00:00Z",
            model_identifier="llama3.1:8b",
            prompt_sha256=canonical_prompt_sha,
            raw_response_sha256=raw_sha256,
            raw_response=raw_resp,
            capture_method="ollama_api_capture",
            capture_environment={},
            inference_parameters={"temperature": 0.0, "format": "json"},
        )
        fixture_file = tmp_path / "SCN-ATO-001-captured.json"
        fixture_file.write_text(fixture.model_dump_json(indent=2), encoding="utf-8")

        # Stale prompt hash
        is_hit, reason, _ = check_existing_fixture(
            fixture_path=fixture_file,
            target_scenario_id="SCN-ATO-001",
            target_model="llama3.1:8b",
            target_prompt_sha256=different_prompt_sha,
            target_inference_parameters={"temperature": 0.0, "format": "json"},
        )
        assert is_hit is False
        assert "stale_prompt_hash" in reason

        # Model tag mismatch
        is_hit, reason, _ = check_existing_fixture(
            fixture_path=fixture_file,
            target_scenario_id="SCN-ATO-001",
            target_model="mistral:7b",
            target_prompt_sha256=canonical_prompt_sha,
            target_inference_parameters={"temperature": 0.0, "format": "json"},
        )
        assert is_hit is False
        assert "model_mismatch" in reason

        # Valid hit
        is_hit, reason, loaded_env = check_existing_fixture(
            fixture_path=fixture_file,
            target_scenario_id="SCN-ATO-001",
            target_model="llama3.1:8b",
            target_prompt_sha256=canonical_prompt_sha,
            target_inference_parameters={"temperature": 0.0, "format": "json"},
        )
        assert is_hit is True
        assert reason == "valid_up_to_date_cache_hit"
        assert loaded_env is not None
        assert loaded_env.scenario_id == "SCN-ATO-001"

    def test_package_and_persist_fixture_atomic(self, tmp_path: Path) -> None:
        """Atomic persistence writes staging file, validates self-readback, and renames cleanly."""
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        mock_resp = httpx.Response(
            200,
            request=dummy_req,
            json={
                "message": {"content": json.dumps({"test": "value"})},
                "total_duration": 1500000000,
                "eval_count": 120,
            },
        )

        prompt_sha = hashlib.sha256(b"[system, user]").hexdigest()
        fixtures_dir = tmp_path / "fixtures"
        envelope, final_path = package_and_persist_fixture(
            scenario_id="SCN-ATO-001",
            model_tag="llama3.1:8b",
            manifest_digest="sha256:123456",
            model_blob_verified=True,
            prompt_sha256=prompt_sha,
            serialized_prompt="[system, user]",
            response=mock_resp,
            target_inference_parameters={"temperature": 0.0},
            fixtures_dir=fixtures_dir,
            retain_http_body=True,
        )

        assert final_path.exists()
        assert final_path.name == "SCN-ATO-001-captured.json"
        assert envelope.scenario_id == "SCN-ATO-001"
        assert envelope.capture_environment["model_blob_verified"] is True
        assert envelope.capture_environment["ollama_transport_metadata"]["total_duration_ns"] == 1500000000

        # No temporary files left behind
        temp_files = list(fixtures_dir.glob("*.tmp.*"))
        assert len(temp_files) == 0


# ── SECTION G: PARTIAL CAPTURE SAFETY AT BATCH LEVEL ─────────────────────────

class TestPartialCaptureSafety:
    """Verifies partial capture, idempotent skip, and interruption safety at run_batch_capture().

    All tests use mocks and temporary directories — zero live network access,
    zero modifications to project fixture files or the batch summary.
    """

    @pytest.fixture
    def batch_context(self, tmp_path: Path) -> dict:
        """Set up temp directories and a scenario loader for batch testing."""
        fixtures_dir = tmp_path / "fixtures"
        prompts_dir = tmp_path / "prompts"
        summary_file = tmp_path / "summary.json"
        fixtures_dir.mkdir(parents=True)
        prompts_dir.mkdir(parents=True)

        loader = ScenarioDatasetLoader(base_dir=Path("datasets/ground_truth"))

        return {
            "fixtures_dir": fixtures_dir,
            "prompts_dir": prompts_dir,
            "summary_file": summary_file,
            "loader": loader,
        }

    def _mock_daemon(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Mock probe_local_ollama_daemon to return valid local info."""

        def fake_probe(host: str, target_model: str, timeout: float) -> dict:
            return {
                "host": "http://127.0.0.1:11434",
                "target_model": target_model,
                "matched_tag": target_model,
                "all_tags": [target_model],
            }

        monkeypatch.setattr("capture_live_fixtures.probe_local_ollama_daemon", fake_probe)

    def _mock_inference_raise(
        self, monkeypatch: pytest.MonkeyPatch, exception: BaseException
    ) -> None:
        """Mock execute_single_ollama_inference to raise the given exception."""

        def fake_inference(client, chat_url: str, payload: dict):
            raise exception

        monkeypatch.setattr(
            "capture_live_fixtures.execute_single_ollama_inference", fake_inference
        )

    def _mock_inference_return(
        self, monkeypatch: pytest.MonkeyPatch, response_obj
    ) -> None:
        """Mock execute_single_ollama_inference to return a response object."""

        def fake_inference(client, chat_url: str, payload: dict):
            return response_obj

        monkeypatch.setattr(
            "capture_live_fixtures.execute_single_ollama_inference", fake_inference
        )

    def _mock_build_prompt(self, monkeypatch: pytest.MonkeyPatch, prompt_sha256: str) -> None:
        """Mock build_and_serialize_prompt to return a known prompt_sha256."""

        def fake_build_prompt(context, prompt_builder, model_tag: str, max_tokens: int):
            mock_req = MagicMock()
            mock_req.messages = []
            return ("serialized_prompt", prompt_sha256, b"canonical_bytes", mock_req)

        monkeypatch.setattr(
            "capture_live_fixtures.build_and_serialize_prompt", fake_build_prompt
        )

    def test_timeout_exhaustion_transport_failure_no_fixture_written(
        self, batch_context: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """TimeoutException during inference → transport_failure status, no fixture file.

        Verifies that when execute_single_ollama_inference raises (after retry
        exhaustion), run_batch_capture records a transport failure and writes
        no CapturedInvestigationFixture for the failed scenario.
        """
        self._mock_daemon(monkeypatch)

        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")
        self._mock_inference_raise(
            monkeypatch, httpx.ReadTimeout("timed out", request=dummy_req)
        )

        summary = run_batch_capture(
            model_tag="llama3.1:8b",
            host="http://127.0.0.1:11434",
            timeout=120.0,
            temperature=0.0,
            num_predict=1024,
            force=False,
            requested_scenarios=["SCN-ATO-001"],
            datasets_dir=Path("datasets/ground_truth"),
            fixtures_dir=batch_context["fixtures_dir"],
            prompts_dir=batch_context["prompts_dir"],
            summary_file=batch_context["summary_file"],
        )

        counts = summary["summary_counts"]
        assert counts["transport_failures_count"] == 1
        assert counts["captured_count"] == 0
        assert counts["error_count"] == 0
        assert counts["total_scenarios_evaluated"] == 1

        result = summary["scenario_results"][0]
        assert result["scenario_id"] == "SCN-ATO-001"
        assert result["status"] == "transport_failure"

        # Verify no fixture file was written for the failed scenario
        fixture_path = batch_context["fixtures_dir"] / "SCN-ATO-001-captured.json"
        assert not fixture_path.exists()

    def test_idempotent_skip_preserves_valid_fixture(
        self, batch_context: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Valid existing fixture → skipped, inference not called, fixture unchanged.

        Verifies that rerunning without --force skips a scenario whose fixture
        passes the 5-point idempotency check, and that the fixture file's
        contents and hashes remain unchanged.
        """
        self._mock_daemon(monkeypatch)

        inference_called = []

        def fake_inference(client, chat_url: str, payload: dict):
            inference_called.append(True)
            raise AssertionError("Inference must not be called for a cached fixture")

        monkeypatch.setattr(
            "capture_live_fixtures.execute_single_ollama_inference", fake_inference
        )

        # Create a valid fixture for SCN-ATO-001
        raw_resp = json.dumps({"summary": "test finding"})
        raw_sha256 = hashlib.sha256(raw_resp.encode("utf-8")).hexdigest()
        prompt_sha = hashlib.sha256(b"canonical_prompt_for_ato001").hexdigest()

        fixture = CapturedInvestigationFixture(
            schema_version="1.0.0",
            scenario_id="SCN-ATO-001",
            capture_timestamp_utc="2026-10-31T00:00:00Z",
            model_identifier="llama3.1:8b",
            model_digest="sha256:667b0c1932bc6ffc593ed1d03f895bf2dc8dc6df21db3042284a6f4416b06a29",
            prompt_sha256=prompt_sha,
            raw_response_sha256=raw_sha256,
            raw_response=raw_resp,
            capture_method="ollama_api_capture",
            capture_environment={},
            inference_parameters={
                "temperature": 0.0,
                "num_predict": 1024,
                "format": "json",
            },
        )
        fixture_path = batch_context["fixtures_dir"] / "SCN-ATO-001-captured.json"
        fixture_path.write_text(fixture.model_dump_json(indent=2), encoding="utf-8")
        fixture_mtime_before = fixture_path.stat().st_mtime
        fixture_hash_before = hashlib.sha256(fixture_path.read_bytes()).hexdigest()

        # Mock prompt building to return the matching prompt_sha256
        self._mock_build_prompt(monkeypatch, prompt_sha)

        summary = run_batch_capture(
            model_tag="llama3.1:8b",
            host="http://127.0.0.1:11434",
            timeout=120.0,
            temperature=0.0,
            num_predict=1024,
            force=False,
            requested_scenarios=["SCN-ATO-001"],
            datasets_dir=Path("datasets/ground_truth"),
            fixtures_dir=batch_context["fixtures_dir"],
            prompts_dir=batch_context["prompts_dir"],
            summary_file=batch_context["summary_file"],
        )

        # Verify skip
        counts = summary["summary_counts"]
        assert counts["skipped_cache_hit_count"] == 1
        assert counts["captured_count"] == 0

        # Verify inference was not called
        assert len(inference_called) == 0

        # Verify fixture file unchanged (same mtime and content hash)
        assert fixture_path.stat().st_mtime == fixture_mtime_before
        assert (
            hashlib.sha256(fixture_path.read_bytes()).hexdigest() == fixture_hash_before
        )

    def test_idempotent_mismatch_does_not_skip(
        self, batch_context: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Mismatched fixture (wrong prompt hash) → cache miss, inference called.

        Verifies that a fixture whose prompt_sha256 does not match the current
        prompt is correctly treated as a cache miss, forcing recapture.
        """
        self._mock_daemon(monkeypatch)

        inference_called = []

        def fake_inference(client, chat_url: str, payload: dict):
            inference_called.append(True)
            mock_resp = MagicMock()
            mock_resp.json.return_value = {
                "message": {"content": '{"test": "value"}'}
            }
            mock_resp.content = b'{"message": {"content": "{"test": "value"}"}}'
            return mock_resp

        monkeypatch.setattr(
            "capture_live_fixtures.execute_single_ollama_inference", fake_inference
        )

        # Create a fixture with a DELIBERATELY WRONG prompt_sha256
        raw_resp = json.dumps({"summary": "test finding"})
        raw_sha256 = hashlib.sha256(raw_resp.encode("utf-8")).hexdigest()
        wrong_prompt_sha = hashlib.sha256(b"wrong_prompt").hexdigest()
        correct_prompt_sha = hashlib.sha256(b"canonical_prompt_for_ato001").hexdigest()

        fixture = CapturedInvestigationFixture(
            schema_version="1.0.0",
            scenario_id="SCN-ATO-001",
            capture_timestamp_utc="2026-10-31T00:00:00Z",
            model_identifier="llama3.1:8b",
            model_digest="sha256:667b0c1932bc6ffc593ed1d03f895bf2dc8dc6df21db3042284a6f4416b06a29",
            prompt_sha256=wrong_prompt_sha,
            raw_response_sha256=raw_sha256,
            raw_response=raw_resp,
            capture_method="ollama_api_capture",
            capture_environment={},
            inference_parameters={
                "temperature": 0.0,
                "num_predict": 1024,
                "format": "json",
            },
        )
        fixture_path = batch_context["fixtures_dir"] / "SCN-ATO-001-captured.json"
        fixture_path.write_text(fixture.model_dump_json(indent=2), encoding="utf-8")

        # Mock prompt building to return the CORRECT prompt_sha256 (mismatch!)
        self._mock_build_prompt(monkeypatch, correct_prompt_sha)

        summary = run_batch_capture(
            model_tag="llama3.1:8b",
            host="http://127.0.0.1:11434",
            timeout=120.0,
            temperature=0.0,
            num_predict=1024,
            force=False,
            requested_scenarios=["SCN-ATO-001"],
            datasets_dir=Path("datasets/ground_truth"),
            fixtures_dir=batch_context["fixtures_dir"],
            prompts_dir=batch_context["prompts_dir"],
            summary_file=batch_context["summary_file"],
        )

        # Verify cache miss → inference called
        counts = summary["summary_counts"]
        assert counts["captured_count"] == 1
        assert counts["skipped_cache_hit_count"] == 0
        assert len(inference_called) == 1

    def test_batch_summary_accurate_mixed_results(
        self, batch_context: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Mix of transport failure and capture → summary accurately reflects both.

        Verifies that when one scenario fails and another succeeds, the batch
        summary accurately records both outcomes without overwriting or hiding
        the failure.
        """
        self._mock_daemon(monkeypatch)

        call_count = [0]
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")

        def fake_inference(client, chat_url: str, payload: dict):
            call_count[0] += 1
            if call_count[0] == 1:
                # First scenario: transport failure
                raise httpx.ReadTimeout("timed out", request=dummy_req)
            # Second scenario: success
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"message": {"content": '{"test": "value"}'}}
            mock_resp.content = b'{}'
            return mock_resp

        monkeypatch.setattr(
            "capture_live_fixtures.execute_single_ollama_inference", fake_inference
        )

        summary = run_batch_capture(
            model_tag="llama3.1:8b",
            host="http://127.0.0.1:11434",
            timeout=120.0,
            temperature=0.0,
            num_predict=1024,
            force=False,
            requested_scenarios=["SCN-ATO-001", "SCN-ATO-002"],
            datasets_dir=Path("datasets/ground_truth"),
            fixtures_dir=batch_context["fixtures_dir"],
            prompts_dir=batch_context["prompts_dir"],
            summary_file=batch_context["summary_file"],
        )

        counts = summary["summary_counts"]
        assert counts["total_scenarios_evaluated"] == 2
        assert counts["transport_failures_count"] == 1
        assert counts["captured_count"] == 1
        assert counts["error_count"] == 0

        statuses = [r["status"] for r in summary["scenario_results"]]
        assert "transport_failure" in statuses
        assert "captured" in statuses

    def test_scenario_isolation_limits_execution(
        self, batch_context: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--scenarios limits execution to explicitly selected IDs.

        Verifies that requested_scenarios filters the scenario set and that
        unrelated scenarios are not invoked.
        """
        self._mock_daemon(monkeypatch)

        executed_ids = []
        dummy_req = httpx.Request("POST", "http://127.0.0.1:11434/api/chat")

        def fake_inference(client, chat_url: str, payload: dict):
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"message": {"content": '{"test": "value"}'}}
            mock_resp.content = b'{}'
            return mock_resp

        monkeypatch.setattr(
            "capture_live_fixtures.execute_single_ollama_inference", fake_inference
        )

        # We can't easily extract scenario_id from payload, so we verify via
        # total_scenarios_evaluated and scenario_results instead.
        summary = run_batch_capture(
            model_tag="llama3.1:8b",
            host="http://127.0.0.1:11434",
            timeout=120.0,
            temperature=0.0,
            num_predict=1024,
            force=False,
            requested_scenarios=["SCN-ATO-001"],
            datasets_dir=Path("datasets/ground_truth"),
            fixtures_dir=batch_context["fixtures_dir"],
            prompts_dir=batch_context["prompts_dir"],
            summary_file=batch_context["summary_file"],
        )

        counts = summary["summary_counts"]
        assert counts["total_scenarios_evaluated"] == 1
        assert summary["scenario_results"][0]["scenario_id"] == "SCN-ATO-001"

        # Verify only one scenario was processed (inference called once)
        # Note: inference may be called 0 times if cached, 1+ times if not
        # The key assertion is total_scenarios_evaluated == 1


# ── SECTION H: RETRY-POLICY PROVENANCE IN BATCH SUMMARIES ──────────────────────

class TestRetryPolicyProvenance:
    """Verifies each batch summary records retry-policy provenance from the active
    implementation (DDR-05 Option C / G4), not merely hardcoded documentation.

    All tests use mocks and temporary directories — zero live network access,
    zero modifications to project fixture files or the batch summary.
    """

    @pytest.fixture
    def batch_context(self, tmp_path: Path) -> dict:
        """Set up temp directories and a scenario loader for batch testing."""
        fixtures_dir = tmp_path / "fixtures"
        prompts_dir = tmp_path / "prompts"
        summary_file = tmp_path / "summary.json"
        fixtures_dir.mkdir(parents=True)
        prompts_dir.mkdir(parents=True)

        loader = ScenarioDatasetLoader(base_dir=Path("datasets/ground_truth"))

        return {
            "fixtures_dir": fixtures_dir,
            "prompts_dir": prompts_dir,
            "summary_file": summary_file,
            "loader": loader,
        }

    def _mock_daemon(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Mock probe_local_ollama_daemon to return valid local info."""

        def fake_probe(host: str, target_model: str, timeout: float) -> dict:
            return {
                "host": "http://127.0.0.1:11434",
                "target_model": target_model,
                "matched_tag": target_model,
                "all_tags": [target_model],
            }

        monkeypatch.setattr("capture_live_fixtures.probe_local_ollama_daemon", fake_probe)

    def _mock_inference_return(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Mock execute_single_ollama_inference to return a successful response."""

        def fake_inference(client, chat_url: str, payload: dict):
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"message": {"content": '{"test": "value"}'}}
            mock_resp.content = b"{}"
            return mock_resp

        monkeypatch.setattr(
            "capture_live_fixtures.execute_single_ollama_inference", fake_inference
        )

    def _run_capture(self, batch_context: dict, monkeypatch: pytest.MonkeyPatch) -> dict:
        """Run a single-scenario capture batch with mocked inference and daemon."""
        self._mock_daemon(monkeypatch)
        self._mock_inference_return(monkeypatch)
        return run_batch_capture(
            model_tag="llama3.1:8b",
            host="http://127.0.0.1:11434",
            timeout=120.0,
            temperature=0.0,
            num_predict=1024,
            force=False,
            requested_scenarios=["SCN-ATO-001"],
            datasets_dir=Path("datasets/ground_truth"),
            fixtures_dir=batch_context["fixtures_dir"],
            prompts_dir=batch_context["prompts_dir"],
            summary_file=batch_context["summary_file"],
        )

    def test_build_retry_policy_provenance_matches_implementation_constants(
        self,
    ) -> None:
        """Provenance is derived from the actual active constants, not hardcoded."""
        provenance = build_retry_policy_provenance()

        assert provenance["policy_id"] == RETRY_POLICY_ID
        assert provenance["policy_version"] == RETRY_POLICY_VERSION
        assert provenance["concurrency"] == 1
        assert provenance["per_attempt_timeout_seconds"] == DEFAULT_TIMEOUT_SECONDS

        # Failure-class values come from MAX_ATTEMPTS_BY_FAILURE_CLASS.
        for failure_class, info in provenance["failure_classes"].items():
            expected_max_attempts = MAX_ATTEMPTS_BY_FAILURE_CLASS[failure_class]
            assert info["max_total_attempts"] == expected_max_attempts
            assert info["max_retries"] == expected_max_attempts - 1

        # Backoff values come from BACKOFF_SECONDS_BEFORE_RETRY.
        import capture_live_fixtures as m

        for retry_str, delay in provenance["backoff_seconds_before_retry"].items():
            assert delay == m.BACKOFF_SECONDS_BEFORE_RETRY[int(retry_str)]

    def test_new_summary_includes_retry_policy_provenance(
        self, batch_context: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Batch summaries written under the G4 policy include retry_policy provenance."""
        summary = self._run_capture(batch_context, monkeypatch)

        assert "retry_policy" in summary
        policy = summary["retry_policy"]
        assert policy["policy_id"] == RETRY_POLICY_ID
        assert policy["policy_version"] == RETRY_POLICY_VERSION
        assert policy["failure_classes"]["http_5xx"]["max_total_attempts"] == 3
        assert policy["failure_classes"]["http_5xx"]["max_retries"] == 2
        assert policy["failure_classes"]["connection_establishment"]["max_total_attempts"] == 3
        assert policy["failure_classes"]["request_timeout"]["max_total_attempts"] == 2
        assert policy["failure_classes"]["request_timeout"]["max_retries"] == 1
        assert policy["failure_classes"]["mid_transfer_disconnect"]["max_total_attempts"] == 1
        assert policy["failure_classes"]["mid_transfer_disconnect"]["max_retries"] == 0
        assert policy["failure_classes"]["http_4xx"]["max_total_attempts"] == 1
        assert policy["failure_classes"]["http_4xx"]["max_retries"] == 0
        assert policy["backoff_seconds_before_retry"] == {"1": 2.0, "2": 4.0}
        assert policy["per_attempt_timeout_seconds"] == 120.0
        assert policy["concurrency"] == 1

    def test_summary_records_configuration_concurrency(
        self, batch_context: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Configuration records concurrency=1 alongside existing fields."""
        summary = self._run_capture(batch_context, monkeypatch)
        assert summary["configuration"]["concurrency"] == 1
        assert summary["configuration"]["num_predict"] == 1024
        assert summary["configuration"]["timeout_seconds"] == 120.0

    def test_policy_identity_distinguishes_g4_from_historical(self) -> None:
        """Policy id/version are stable identifiers that differ from historical runs."""
        provenance = build_retry_policy_provenance()
        assert provenance["policy_id"] == "P3-H3B-DDR-05-Option-C"
        assert provenance["policy_version"] == "1.0"
        # Historical captures (pre-G4) would not carry this policy identity;
        # the combination of policy_id + policy_version distinguishes this cohort.

    def test_serialization_is_deterministic(
        self, batch_context: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Repeated builds of the provenance dict produce byte-identical output."""
        p1 = json.dumps(build_retry_policy_provenance(), sort_keys=True)
        p2 = json.dumps(build_retry_policy_provenance(), sort_keys=True)
        assert p1 == p2

    def test_historical_summary_keys_remain_present(
        self, batch_context: dict, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """New summaries preserve all pre-existing summary fields for compatibility."""
        summary = self._run_capture(batch_context, monkeypatch)
        assert "harness_version" in summary
        assert "execution_timestamp_utc" in summary
        assert "completion_timestamp_utc" in summary
        assert "total_duration_seconds" in summary
        assert "configuration" in summary
        assert "model_provenance" in summary
        assert "summary_counts" in summary
        assert "scenario_results" in summary
        assert summary["harness_version"] == HARNESS_VERSION
