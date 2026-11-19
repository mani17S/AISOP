"""
AISOP P3-H3B Live Ollama Model Benchmark Execution & Fixture Capture Protocol Harness.

Governing Charters:
- AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001 (Zero External WAN Invocations, $0 Spend)
- ADR-001 (Local-First Architecture & Daemon Isolation)
- ADR-004 (Canonical Sysmon Event Telemetry Normalization)
- P3-H3B Capture Protocol Specification Revision 1.1.1 (DDR-01 through DDR-10)

Key Architectural Invariants:
1. Scenario Loading (DDR-08): Ingests 19 approved scenarios; excludes drafts (SCN-BEN-005).
2. Telemetry Normalization (CF-01, BLK-1.1-01, DDR-02): Raw Sysmon events are parsed via
   SysmonParser into CanonicalEvent instances, projected deterministically into
   ContextEventItem models, and assembled into InvestigationContext using approved
   InvestigationScopeType (SINGLE_EVENT | INCIDENT_TIMELINE).
3. Structured Prompt Serialization (MF-02, DDR-03): Prompts are serialized as canonical
   JSON message arrays, eliminating delimiter injection and smuggling attacks.
4. Cryptographic Envelope & Decoupling (F-04, F-05, Refinement B, DDR-01, DDR-04):
   Separates application JSON payload (raw_response) from transport metadata
   (capture_environment["ollama_transport_metadata"]). Records manifest layer digest,
   model blob verification status, and HTTP body digest.
5. Hardened 5-Point Idempotency (F-03, Refinement A, DDR-06): Re-runs skip valid captures
   matching scenario ID, model tag, current prompt SHA-256, payload SHA-256, and
   inference hyper-parameters.
6. Crash-Resilient Atomic Persistence (DDR-07): Uses temporary files (.tmp.<uuid>) with
   os.fsync() and atomic os.replace() to prevent file corruption.
7. Local Daemon Preflight Verification (F-07, DDR-09): Probes GET /api/tags to guarantee
   target model is present locally before issuing any inference requests; fails closed
   without ever calling /api/pull.
8. Execution Concurrency (DDR-05): Strictly sequential execution (concurrency=1) with
   120s per-attempt timeout and failure-class retry policy per DDR-05 Option C:
   HTTP 5xx / connection-establishment: max 2 retries (3 total attempts);
   request timeout (>120s): max 1 retry (2 total attempts);
   mid-transfer disconnect / HTTP 4xx: no automatic retry (1 attempt).
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import uuid

import httpx


# ── PROJECT PATH CONFIGURATION ────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# 120s per-attempt timeout; failure-class retry policy per DDR-05 Option C:
# HTTP 5xx / connection-establishment: max 2 retries (3 total attempts);
# request timeout (>120s): max 1 retry (2 total attempts);
# mid-transfer disconnect / HTTP 4xx: no automatic retry (1 attempt).

from app.modules.ai.context_builder.context_builder import InvestigationContextBuilder
from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency
from app.modules.ai.prompt_builder.builder import InvestigationPromptBuilder
from app.modules.evaluation.dataset_loader import ScenarioDatasetLoader
from app.modules.evaluation.metrics import canonicalize_prompt_artifact
from app.modules.evidence.sysmon_parser import SysmonParser
from app.schemas.ai import LLMMessage, LLMRequest, MessageRole
from app.schemas.evaluation import CapturedInvestigationFixture
from app.schemas.investigation import (
    ContextEventItem,
    InvestigationContext,
    InvestigationScopeType,
)

# ── HARNESS CONSTANTS ─────────────────────────────────────────────────────────
NAMESPACE_AISOP_BENCHMARK = uuid.UUID("3c8e7b9e-6a5d-4f1e-9d2a-8c7e6b5a4f3d")
DEFAULT_MODEL_TAG = "llama3.1:8b"
DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_TEMPERATURE = 0.0
DEFAULT_NUM_PREDICT = 1024
DEFAULT_MAX_RETRIES = 2
HARNESS_VERSION = "1.1.2"

# Standard candidate manifest search locations for local Ollama storage
CANDIDATE_MODELS_ROOTS = [
    Path(r"D:\OllamaModels\models"),
    Path.home() / ".ollama" / "models",
    Path(os.environ.get("OLLAMA_MODELS", r"D:\OllamaModels\models")),
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("aisop.capture_harness")


# ── CUSTOM EXCEPTIONS ─────────────────────────────────────────────────────────
class OllamaPreflightError(Exception):
    """Base exception for local Ollama preflight verification failures."""


class ModelNotAvailableLocallyError(OllamaPreflightError):
    """Raised when the requested model tag is not found in local daemon tags."""


class OllamaDaemonUnreachableError(OllamaPreflightError):
    """Raised when the local Ollama daemon cannot be reached on loopback."""


class FixturePersistenceError(Exception):
    """Raised when atomic fixture serialization or disk replacement fails."""


class LoopbackSecurityError(OllamaPreflightError):
    """Raised when an invalid, non-loopback, or unapproved endpoint is configured."""


def validate_loopback_endpoint(endpoint_url: str) -> str:
    """
    Validate that an endpoint URL strictly targets local Ollama loopback on port 11434.

    Enforces AUD-P3H3B-02 and AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001:
    - Scheme must be strictly 'http'
    - No URL credentials (username / password)
    - Port must be exactly 11434
    - Hostname must be strictly '127.0.0.1', 'localhost', or '::1'
    - No query parameters or URL fragments
    - Path must be empty or '/'
    - Returns canonical normalized base URL: 'http://<host>:11434'
    """
    if not isinstance(endpoint_url, str) or not endpoint_url.strip():
        raise LoopbackSecurityError("Endpoint URL cannot be empty.")

    clean_url = endpoint_url.strip()
    try:
        parsed = urllib.parse.urlsplit(clean_url)
    except Exception as exc:
        raise LoopbackSecurityError(f"Malformed URL '{clean_url}': {exc}") from exc

    if parsed.scheme.lower() != "http":
        raise LoopbackSecurityError(
            f"Invalid scheme '{parsed.scheme}'. Local Ollama daemon endpoint must use 'http://'."
        )

    if parsed.username is not None or parsed.password is not None:
        raise LoopbackSecurityError(
            "URL credentials are strictly forbidden on loopback endpoint."
        )

    if parsed.query:
        raise LoopbackSecurityError("Query parameters are forbidden on local Ollama endpoint.")

    if parsed.fragment:
        raise LoopbackSecurityError("URL fragments are forbidden on local Ollama endpoint.")

    clean_path = parsed.path.strip()
    if clean_path and clean_path != "/":
        raise LoopbackSecurityError(
            f"Unexpected URL path '{parsed.path}'. Endpoint must specify host and port only without path prefixes."
        )

    if parsed.port != 11434:
        raise LoopbackSecurityError(
            f"Invalid port '{parsed.port}'. Ollama daemon must run on port 11434."
        )

    hostname = (parsed.hostname or "").strip().lower()
    if hostname not in ("127.0.0.1", "localhost", "::1"):
        raise LoopbackSecurityError(
            f"Security violation: Endpoint hostname '{hostname}' rejected. "
            "In accordance with AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001, "
            "only '127.0.0.1', 'localhost', and '::1' on port 11434 are permitted."
        )

    normalized_host = f"[{hostname}]" if hostname == "::1" else hostname
    return f"http://{normalized_host}:11434"


def validate_execution_timeout(timeout: float) -> float:
    """
    Validate that timeout is a finite, positive float not exceeding 120.0s.

    Enforces 0.0 < timeout <= 120.0. Rejects zero, negative, NaN, infinity, and
    values exceeding the DDR-05 120-second boundary.
    """
    try:
        val = float(timeout)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid timeout value '{timeout}': must be a valid float.") from exc

    if math.isnan(val) or math.isinf(val):
        raise ValueError(f"Timeout cannot be NaN or infinite: {timeout}")

    if val <= 0.0:
        raise ValueError(f"Timeout must be strictly positive (> 0.0s), got {val}s.")

    if val > 120.0:
        raise ValueError(
            f"Timeout cannot exceed 120.0s in accordance with DDR-05 and zero-billing limits, got {val}s."
        )

    return val


# ── PREFLIGHT VERIFICATION (F-07, F-04, Refinement B, DDR-04, DDR-09) ─────────
def probe_local_ollama_daemon(
    host: str = DEFAULT_OLLAMA_HOST,
    target_model: str = DEFAULT_MODEL_TAG,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """
    Probe the local Ollama daemon to ensure it is reachable and has the target model.

    Enforces fail-closed local verification (F-07). Never calls /api/pull.
    If the daemon is unreachable or the model is not installed locally, raises
    an exception immediately to abort execution and prevent WAN registry pulls.
    """
    validated_host = validate_loopback_endpoint(host)
    validated_timeout = validate_execution_timeout(timeout)
    tags_url = f"{validated_host}/api/tags"

    logger.info("Executing preflight probe against local daemon: %s", tags_url)
    try:
        with httpx.Client(timeout=validated_timeout, follow_redirects=False) as client:
            resp = client.get(tags_url)
            resp.raise_for_status()
            data = resp.json()
    except httpx.ConnectError as exc:
        raise OllamaDaemonUnreachableError(
            f"Ollama daemon is not reachable at {validated_host}. "
            f"Ensure Ollama is running locally on 127.0.0.1:11434 before starting capture. Details: {exc}"
        ) from exc
    except httpx.TimeoutException as exc:
        raise OllamaDaemonUnreachableError(
            f"Timed out after {validated_timeout}s while probing Ollama daemon at {tags_url}."
        ) from exc
    except Exception as exc:
        raise OllamaPreflightError(f"Unexpected error probing Ollama daemon tags: {exc}") from exc

    raw_models = data.get("models", [])
    available_tags: list[str] = []
    for item in raw_models:
        name = item.get("name") or item.get("model")
        if name:
            available_tags.append(str(name).strip().lower())

    # Check for target model or instruct alias
    target_normalized = target_model.strip().lower()
    matches = [
        tag
        for tag in available_tags
        if tag == target_normalized
        or tag == f"{target_normalized}-instruct"
        or (":" not in target_normalized and tag.startswith(f"{target_normalized}:"))
    ]

    if not matches:
        raise ModelNotAvailableLocallyError(
            f"Target model '{target_model}' is NOT present in local Ollama repository! "
            f"Available local models: {available_tags}. "
            "In accordance with AISOP-POL-LOCAL-FIRST-ZERO-BILLING-001 and F-07, "
            "automatic /api/pull is strictly forbidden. Capture aborted to prevent external WAN traffic."
        )

    logger.info(
        "Preflight verified: local daemon reachable; target model '%s' confirmed (matched '%s').",
        target_model,
        matches[0],
    )
    return {"host": validated_host, "target_model": target_model, "matched_tag": matches[0], "all_tags": available_tags}


def resolve_manifest_layer_digest(
    target_model: str = DEFAULT_MODEL_TAG,
    candidate_roots: Optional[List[Path]] = None,
) -> Tuple[Optional[str], Optional[int], Optional[Path]]:
    """
    Locate the local manifest file for target_model and extract its model layer digest.

    Adheres to F-04 / DDR-04: Extracts the declared layer blob digest without executing
    arbitrary external registry lookups.
    """
    roots = candidate_roots or CANDIDATE_MODELS_ROOTS

    # Parse model parts: e.g. "llama3.1:8b" -> repo "library/llama3.1", tag "8b"
    model_tag = target_model.strip()
    if ":" in model_tag:
        model_name, tag = model_tag.split(":", 1)
    else:
        model_name, tag = model_tag, "latest"

    # Search paths in order: registry.ollama.ai/library/<name>/<tag>
    for root in roots:
        manifests_dir = root / "manifests" / "registry.ollama.ai" / "library" / model_name
        manifest_file = manifests_dir / tag
        if manifest_file.is_file():
            try:
                with open(manifest_file, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
                layers = manifest_data.get("layers", [])
                for layer in layers:
                    if layer.get("mediaType") == "application/vnd.ollama.image.model":
                        digest = layer.get("digest")
                        size = layer.get("size")
                        logger.info(
                            "Found manifest layer digest for '%s' in %s: %s (%s bytes)",
                            target_model,
                            manifest_file,
                            digest,
                            f"{size:,}" if size else "unknown",
                        )
                        return digest, size, manifest_file
            except Exception as exc:
                logger.warning("Failed to parse manifest file %s: %s", manifest_file, exc)

    logger.warning("No local manifest file found for '%s' across candidates: %s", target_model, roots)
    return None, None, None


def verify_model_blob_integrity(
    layer_digest: str,
    candidate_roots: Optional[List[Path]] = None,
    compute_hash: bool = False,
) -> Tuple[bool, Optional[Path]]:
    """
    Check for the existence of the model layer blob, and optionally compute its SHA-256.

    Adheres to F-04, Refinement B, and DDR-04:
    - If compute_hash=False: verifies file existence only; returns (False, blob_path)
      signifying model_blob_verified=False (preflight byte-hash skipped for performance).
    - If compute_hash=True: streams the multi-gigabyte blob through SHA-256; returns
      (True, blob_path) upon exact match, or raises ValueError on mismatch.
    """
    roots = candidate_roots or CANDIDATE_MODELS_ROOTS

    # Layer digest format is "sha256:<64-hex>". Blob filename is "sha256-<64-hex>".
    clean_digest = layer_digest.strip().lower()
    if clean_digest.startswith("sha256:"):
        blob_filename = f"sha256-{clean_digest[7:]}"
        expected_hex = clean_digest[7:]
    else:
        blob_filename = f"sha256-{clean_digest}"
        expected_hex = clean_digest

    blob_path: Optional[Path] = None
    for root in roots:
        candidate = root / "blobs" / blob_filename
        if candidate.is_file():
            blob_path = candidate
            break

    if blob_path is None:
        logger.warning("Model blob file '%s' not found across candidate roots: %s", blob_filename, roots)
        return False, None

    if not compute_hash:
        logger.info(
            "Model blob file verified to exist at %s (size: %s bytes). Independent SHA-256 computation skipped.",
            blob_path,
            f"{blob_path.stat().st_size:,}",
        )
        return False, blob_path

    logger.info("Computing SHA-256 over model layer blob (%s bytes) at %s...", f"{blob_path.stat().st_size:,}", blob_path)
    hasher = hashlib.sha256()
    start_t = time.monotonic()
    with open(blob_path, "rb") as f:
        while chunk := f.read(8 * 1024 * 1024):  # 8 MB buffer
            hasher.update(chunk)
    computed_hex = hasher.hexdigest().lower()
    duration = time.monotonic() - start_t

    if computed_hex != expected_hex:
        raise ValueError(
            f"Model layer blob hash mismatch for {blob_path}! "
            f"Expected {expected_hex}, but calculated {computed_hex}."
        )

    logger.info("Model layer blob SHA-256 verified successfully in %.2fs: %s", duration, computed_hex)
    return True, blob_path


# ── TELEMETRY NORMALIZATION & PROJECTION (CF-01, BLK-1.1-01, DDR-02) ──────────
def normalize_scenario_events(
    scenario: Any,
    sysmon_parser: SysmonParser,
) -> list[ContextEventItem]:
    """
    Normalize raw Sysmon telemetry events into canonical ContextEventItem models.

    Addresses CF-01: Raw PascalCase Sysmon dictionaries fail ContextEventItem validation
    (25 errors, extra='forbid'). They must pass through SysmonParser into CanonicalEvent,
    then project deterministically into ContextEventItem using RFC 4122 UUIDv5 identifiers.
    """
    context_items: list[ContextEventItem] = []

    for idx, raw_ev in enumerate(scenario.raw_telemetry_events):
        raw_bytes = json.dumps(raw_ev, sort_keys=True).encode("utf-8")
        raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        canonical_events = sysmon_parser.parse(raw_ev, raw_ref=raw_sha256)

        for c_idx, ce in enumerate(canonical_events):
            event_uuid = uuid.uuid5(
                NAMESPACE_AISOP_BENCHMARK,
                f"{scenario.scenario_id}.event.{idx}.{c_idx}",
            )

            source_id = (
                ce.host.hostname
                if ce.host and ce.host.hostname
                else ce.provider or "Microsoft-Windows-Sysmon"
            )

            item = ContextEventItem(
                event_uuid=event_uuid,
                raw_evidence_sha256=ce.raw_ref or raw_sha256,
                event_id=ce.event_id,
                event_type=ce.event_type,
                timestamp_utc=ce.timestamp,
                action=ce.action,
                outcome=ce.outcome,
                severity=ce.severity,
                source_identifier=source_id,
                summary=ce.raw_payload_summary or f"{ce.event_type} {ce.action}",
                attributes=ce.custom_fields,
            )
            context_items.append(item)

    return context_items


def build_scenario_context(
    scenario: Any,
    context_items: list[ContextEventItem],
    context_builder: InvestigationContextBuilder,
    model_tag: str = DEFAULT_MODEL_TAG,
    temperature: float = DEFAULT_TEMPERATURE,
) -> InvestigationContext:
    """
    Construct a deterministic InvestigationContext from normalized events.

    Addresses BLK-1.1-01: Uses valid InvestigationScopeType members
    (SINGLE_EVENT | INCIDENT_TIMELINE), avoiding AttributeError.
    Generates deterministic investigation_id using UUIDv5.
    """
    investigation_id = uuid.uuid5(NAMESPACE_AISOP_BENCHMARK, scenario.scenario_id)

    scope_type = (
        InvestigationScopeType.SINGLE_EVENT
        if len(context_items) == 1
        else InvestigationScopeType.INCIDENT_TIMELINE
    )

    context = context_builder.build_structured_context(
        events=context_items,
        investigation_id=investigation_id,
        scope_type=scope_type,
        time_window_start=min(e.timestamp_utc for e in context_items),
        time_window_end=max(e.timestamp_utc for e in context_items),
        target_hosts=sorted(list({e.source_identifier for e in context_items})),
        llm_provider="ollama",
        model_name=model_tag,
        temperature=temperature,
    )
    return context


# ── STRUCTURED PROMPT SERIALIZATION & ARTIFACT (MF-02, DDR-03) ────────────────
def build_and_serialize_prompt(
    context: InvestigationContext,
    prompt_builder: InvestigationPromptBuilder,
    model_tag: str = DEFAULT_MODEL_TAG,
    max_tokens: int = DEFAULT_NUM_PREDICT,
) -> Tuple[str, str, bytes, LLMRequest]:
    """
    Generate an LLMRequest and serialize it to a canonical structured JSON array.

    Addresses MF-02: Rejects plain-text role delimiters (e.g. [SYSTEM MESSAGE]) which
    are vulnerable to delimiter injection / prompt smuggling. Serializes ordered sequence
    of LLMMessage models into a structured JSON string, and computes its canonical SHA-256.
    """
    req = prompt_builder.build_request(
        context=context,
        model_override=model_tag,
        max_tokens=max_tokens,
    )

    # Ordered JSON array representation of LLMMessage sequence
    messages_payload = [
        {"role": msg.role.value, "content": msg.content}
        for msg in req.messages
    ]

    serialized_prompt = json.dumps(messages_payload, indent=2, ensure_ascii=False)
    canonical_bytes = canonicalize_prompt_artifact(serialized_prompt)
    prompt_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

    return serialized_prompt, prompt_sha256, canonical_bytes, req


def persist_prompt_artifact(
    scenario_id: str,
    canonical_bytes: bytes,
    prompts_dir: Path,
) -> Path:
    """
    Persist the canonical prompt artifact to disk atomically.
    Ensures prompt text on disk matches prompt_sha256 byte-for-byte.
    """
    prompts_dir.mkdir(parents=True, exist_ok=True)
    target_path = prompts_dir / f"{scenario_id}.txt"
    tmp_path = prompts_dir / f"{scenario_id}.txt.tmp.{uuid.uuid4()}"

    try:
        with open(tmp_path, "wb") as f:
            f.write(canonical_bytes)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target_path)
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    return target_path


# ── HARDENED 5-POINT IDEMPOTENCY CHECK (F-03, Refinement A, DDR-06) ───────────
def check_existing_fixture(
    fixture_path: Path,
    target_scenario_id: str,
    target_model: str,
    target_prompt_sha256: str,
    target_inference_parameters: dict[str, Any],
) -> Tuple[bool, str, Optional[CapturedInvestigationFixture]]:
    """
    Perform a hardened 5-point verification check against an existing fixture file.

    Returns (should_skip, reason, validated_fixture).
    Verification checks:
    1. Scenario ID equality
    2. Model tag equality (case-insensitive, whitespace-trimmed)
    3. Current prompt SHA-256 equality (detects prompt template or telemetry drift)
    4. Payload cryptographic integrity (raw_response_sha256 == sha256(raw_response))
    5. Hyper-parameter equality (temperature, num_predict, format)
    """
    if not fixture_path.exists():
        return False, "fixture_missing", None

    try:
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw_text = f.read()
        envelope = CapturedInvestigationFixture.model_validate_json(raw_text)
    except Exception as exc:
        # Quarantine corrupt fixture to prevent silent reuse
        quarantine_path = fixture_path.with_name(
            f"{fixture_path.stem}.corrupt.{int(time.time())}.json"
        )
        logger.warning(
            "Existing fixture %s is invalid or corrupt: %s. Quarantining to %s.",
            fixture_path.name,
            exc,
            quarantine_path.name,
        )
        try:
            os.replace(fixture_path, quarantine_path)
        except OSError as q_exc:
            logger.error("Failed to rename corrupt fixture %s: %s", fixture_path, q_exc)
        return False, "corrupt_fixture_quarantined", None

    # Check 1: Scenario ID
    if envelope.scenario_id != target_scenario_id:
        return False, f"scenario_id_mismatch ({envelope.scenario_id} != {target_scenario_id})", None

    # Check 2: Canonical Model Tag
    if envelope.model_identifier.strip().lower() != target_model.strip().lower():
        return False, f"model_mismatch ({envelope.model_identifier} != {target_model})", None

    # Check 3: Current Prompt Hash Match
    if envelope.prompt_sha256.lower() != target_prompt_sha256.lower():
        return False, "stale_prompt_hash (prompt or telemetry changed)", None

    # Check 4: Payload Cryptographic Integrity
    raw_response_content = (
        envelope.raw_response
        if isinstance(envelope.raw_response, str)
        else json.dumps(envelope.raw_response, sort_keys=True)
    )
    computed_raw_sha256 = hashlib.sha256(raw_response_content.encode("utf-8")).hexdigest().lower()
    if envelope.raw_response_sha256.lower() != computed_raw_sha256:
        return False, "payload_hash_mismatch (envelope corrupt)", None

    # Check 5: Hyper-Parameters Equality (Refinement A)
    if envelope.inference_parameters != target_inference_parameters:
        return False, "inference_parameters_mismatch (hyper-parameters changed)", None

    return True, "valid_up_to_date_cache_hit", envelope


# ── FAILURE-CLASS RETRY POLICY (DDR-05, Option C — Project Owner approved) ─────
# Per failure class: maximum TOTAL attempts including the initial attempt.
MAX_ATTEMPTS_BY_FAILURE_CLASS: dict[str, int] = {
    "http_5xx": 3,
    "connection_establishment": 3,
    "request_timeout": 2,
    "mid_transfer_disconnect": 1,
    "http_4xx": 1,
    "unknown": 1,
}

# Deterministic backoff delay (seconds) before retry number N (1-indexed).
# Timeout class permits only retry #1 (2s); 5xx/connect permit #1 (2s) then #2 (4s).
BACKOFF_SECONDS_BEFORE_RETRY: dict[int, float] = {
    1: 2.0,
    2: 4.0,
}

# Retry-policy provenance identity. These values distinguish the G4 Option C
# failure-class retry policy from historical capture conditions, which applied
# the DDR-05 literal wording uniformly (2 retries on HTTP 5xx/disconnect only,
# no timeout backoff distinction). The provenance dict is derived from the
# active constants above so the serialized summary always reflects the actual
# effective configuration, not merely hardcoded documentation.
RETRY_POLICY_ID = "P3-H3B-DDR-05-Option-C"
RETRY_POLICY_VERSION = "1.0"


def build_retry_policy_provenance() -> dict[str, Any]:
    """
    Build the retry-policy provenance block recorded in each capture batch summary.

    All values are derived from the active `MAX_ATTEMPTS_BY_FAILURE_CLASS` and
    `BACKOFF_SECONDS_BEFORE_RETRY` constants, so the provenance always reflects
    the actual effective configuration rather than static documentation.
    """
    failure_classes: dict[str, dict[str, int]] = {}
    for failure_class in (
        "http_5xx",
        "connection_establishment",
        "request_timeout",
        "mid_transfer_disconnect",
        "http_4xx",
    ):
        max_attempts = MAX_ATTEMPTS_BY_FAILURE_CLASS[failure_class]
        failure_classes[failure_class] = {
            "max_retries": max_attempts - 1,
            "max_total_attempts": max_attempts,
        }

    return {
        "policy_id": RETRY_POLICY_ID,
        "policy_version": RETRY_POLICY_VERSION,
        "failure_classes": failure_classes,
        "backoff_seconds_before_retry": {
            str(retry_number): delay
            for retry_number, delay in sorted(BACKOFF_SECONDS_BEFORE_RETRY.items())
        },
        "per_attempt_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        "concurrency": 1,
    }


def classify_http_failure(exc: BaseException) -> tuple[str, int]:
    """
    Classify an inference-request failure and return (failure_class, max_total_attempts).

    Classification precedence is most-specific first because httpx 0.28.1 places
    TimeoutException, ConnectError, ReadError and RemoteProtocolError under the
    shared TransportError base:
      1. HTTPStatusError       -> http_5xx (3 attempts) / http_4xx (1 attempt)
      2. ConnectError          -> connection_establishment (3 attempts)
      3. TimeoutException      -> request_timeout (2 attempts)
         [covers ReadTimeout, ConnectTimeout]
      4. ReadError / RemoteProtocolError
                              -> mid_transfer_disconnect (1 attempt)
      5. anything else         -> unknown (1 attempt, no retry)
    """
    if isinstance(exc, httpx.HTTPStatusError):
        if exc.response.status_code >= 500:
            return "http_5xx", MAX_ATTEMPTS_BY_FAILURE_CLASS["http_5xx"]
        return "http_4xx", MAX_ATTEMPTS_BY_FAILURE_CLASS["http_4xx"]
    if isinstance(exc, httpx.ConnectError):
        return (
            "connection_establishment",
            MAX_ATTEMPTS_BY_FAILURE_CLASS["connection_establishment"],
        )
    if isinstance(exc, httpx.TimeoutException):
        return "request_timeout", MAX_ATTEMPTS_BY_FAILURE_CLASS["request_timeout"]
    if isinstance(exc, (httpx.ReadError, httpx.RemoteProtocolError)):
        return (
            "mid_transfer_disconnect",
            MAX_ATTEMPTS_BY_FAILURE_CLASS["mid_transfer_disconnect"],
        )
    return "unknown", MAX_ATTEMPTS_BY_FAILURE_CLASS["unknown"]


def execute_single_ollama_inference(
    client: httpx.Client,
    chat_url: str,
    payload: dict[str, Any],
) -> httpx.Response:
    """
    Execute a single sequential POST /api/chat invocation with failure-class retry.

    Enforces concurrency=1, strict JSON format, and the DDR-05 Option C retry policy:
      - HTTP 5xx and connection-establishment failure: max 2 retries (3 total attempts)
      - Request timeout (>120s): max 1 retry (2 total attempts)
      - Mid-transfer disconnect and HTTP 4xx: no automatic retry (1 attempt)

    Deterministic backoff: 2s before the 1st retry, 4s before the 2nd retry where
    applicable. Timeout failures receive only one retry, with a 2s delay.
    Maximum attempt counts include the initial attempt. The last exception is
    reraised once the class-specific attempt limit is exhausted.
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = client.post(chat_url, json=payload)
            resp.raise_for_status()
            return resp
        except Exception as exc:  # classify every transport failure before deciding
            failure_class, max_attempts = classify_http_failure(exc)
            logger.warning(
                "Ollama inference attempt %d/%d failed (%s): %s",
                attempt,
                max_attempts,
                failure_class,
                exc,
            )
            if attempt >= max_attempts:
                logger.error(
                    "Ollama inference exhausted %s budget (%d attempts); reraising",
                    failure_class,
                    attempt,
                )
                raise
            backoff = BACKOFF_SECONDS_BEFORE_RETRY.get(attempt, 0.0)
            if backoff > 0:
                logger.info(
                    "Retrying after %.1fs backoff (attempt %d of %d)",
                    backoff,
                    attempt + 1,
                    max_attempts,
                )
                time.sleep(backoff)


# ── PACKAGING & ATOMIC PERSISTENCE (F-04, F-05, Refinement B, DDR-07) ─────────
def package_and_persist_fixture(
    scenario_id: str,
    model_tag: str,
    manifest_digest: Optional[str],
    model_blob_verified: bool,
    prompt_sha256: str,
    serialized_prompt: str,
    response: httpx.Response,
    target_inference_parameters: dict[str, Any],
    fixtures_dir: Path,
    retain_http_body: bool = False,
) -> Tuple[CapturedInvestigationFixture, Path]:
    """
    Package raw Ollama HTTP response into a CapturedInvestigationFixture and persist atomically.

    Adheres to F-05 / DDR-01: Decouples raw application content (raw_response) from
    outer transport telemetry (capture_environment["ollama_transport_metadata"]).
    Adheres to DDR-07: Uses atomic temporary file write with os.fsync() and os.replace().
    """
    resp_bytes = response.content
    resp_json = response.json()

    # Extract provider-reported model identity from the response envelope
    provider_reported_model_identifier: str | None = None
    resp_model = resp_json.get("model")
    if resp_model and str(resp_model).strip():
        provider_reported_model_identifier = str(resp_model).strip()

    # Extract application generated content
    message_obj = resp_json.get("message", {})
    raw_response_str = message_obj.get("content", "")
    if not isinstance(raw_response_str, str):
        raw_response_str = json.dumps(raw_response_str, ensure_ascii=False)

    raw_response_sha256 = hashlib.sha256(raw_response_str.encode("utf-8")).hexdigest()
    http_body_sha256 = hashlib.sha256(resp_bytes).hexdigest()

    # Extract Ollama execution telemetry
    transport_metadata = {
        "created_at": resp_json.get("created_at"),
        "total_duration_ns": resp_json.get("total_duration"),
        "load_duration_ns": resp_json.get("load_duration"),
        "prompt_eval_count": resp_json.get("prompt_eval_count"),
        "prompt_eval_duration_ns": resp_json.get("prompt_eval_duration"),
        "eval_count": resp_json.get("eval_count"),
        "eval_duration_ns": resp_json.get("eval_duration"),
        "done_reason": resp_json.get("done_reason"),
    }

    capture_env: dict[str, Any] = {
        "os": sys.platform,
        "python_version": sys.version,
        "harness_version": HARNESS_VERSION,
        "model_blob_verified": model_blob_verified,
        "ollama_transport_metadata": transport_metadata,
        "http_response_body_sha256": http_body_sha256,
    }
    if retain_http_body:
        capture_env["http_response_body"] = response.text

    envelope = CapturedInvestigationFixture(
        schema_version="1.0.0",
        scenario_id=scenario_id,
        capture_timestamp_utc=datetime.now(timezone.utc),
        model_identifier=model_tag,
        provider_reported_model_identifier=provider_reported_model_identifier,
        model_digest=manifest_digest,
        prompt_sha256=prompt_sha256,
        prompt_artifact=serialized_prompt,
        raw_response_sha256=raw_response_sha256,
        raw_response=raw_response_str,
        capture_method="ollama_api_capture",
        capture_environment=capture_env,
        capture_manifest_version="1.0.0",
        inference_parameters=target_inference_parameters,
    )

    fixtures_dir.mkdir(parents=True, exist_ok=True)
    target_fixture_path = fixtures_dir / f"{scenario_id}-captured.json"
    tmp_path = fixtures_dir / f"{scenario_id}-captured.json.tmp.{uuid.uuid4()}"

    serialized_fixture = envelope.model_dump_json(indent=2).encode("utf-8")
    try:
        with open(tmp_path, "wb") as f:
            f.write(serialized_fixture)
            f.flush()
            os.fsync(f.fileno())

        # Self-verification readback before atomic rename
        with open(tmp_path, "rb") as f:
            CapturedInvestigationFixture.model_validate_json(f.read())

        os.replace(tmp_path, target_fixture_path)
    except Exception as exc:
        raise FixturePersistenceError(
            f"Failed to atomically persist fixture for scenario {scenario_id}: {exc}"
        ) from exc
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    return envelope, target_fixture_path


# ── BATCH CAPTURE ORCHESTRATOR ────────────────────────────────────────────────
def run_batch_capture(
    model_tag: str = DEFAULT_MODEL_TAG,
    host: str = DEFAULT_OLLAMA_HOST,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    temperature: float = DEFAULT_TEMPERATURE,
    num_predict: int = DEFAULT_NUM_PREDICT,
    force: bool = False,
    verify_blobs: bool = False,
    retain_http_body: bool = False,
    dry_run: bool = False,
    requested_scenarios: Optional[List[str]] = None,
    allow_draft: bool = False,
    datasets_dir: Optional[Path] = None,
    fixtures_dir: Optional[Path] = None,
    prompts_dir: Optional[Path] = None,
    summary_file: Optional[Path] = None,
    gate_off_ablation: bool = False,
) -> dict[str, Any]:
    """
    Execute the formal P3-H3B capture workflow across ground-truth evaluation scenarios.

    Strictly adheres to:
    - Zero external network requests (loopback only)
    - Sequential execution (concurrency=1)
    - Full error classification and transparent batch summary recording

    Stage 3C (ADR-008): this harness calls Ollama directly (outside the production
    GatedGenerator), so it applies the SAME deterministic evidence-sufficiency gate itself
    by default: scenarios whose context is assessed INSUFFICIENT are not sent to the model
    and are recorded as ``skipped_gate_insufficient``. Bypassing the gate requires the explicit
    ``gate_off_ablation=True`` (CLI ``--gate-off-ablation``), which is recorded in the batch
    summary configuration so gate-off captures can never be mistaken for gate-on captures.
    """
    base_datasets_dir = datasets_dir or (PROJECT_ROOT / "datasets" / "ground_truth")
    target_fixtures_dir = fixtures_dir or (base_datasets_dir / "fixtures")
    target_prompts_dir = prompts_dir or (base_datasets_dir / "prompts")
    summary_path = summary_file or (PROJECT_ROOT / "docs" / "04_Testing" / "batch_capture_summary.json")

    validated_host = validate_loopback_endpoint(host)
    validated_timeout = validate_execution_timeout(timeout)

    start_time_utc = datetime.now(timezone.utc)
    start_time_monotonic = time.monotonic()
    logger.info("=" * 70)
    logger.info("Starting AISOP P3-H3B Live Ollama Capture Harness (v%s)", HARNESS_VERSION)
    logger.info("Target Model: %s | Host: %s | Timeout: %.1fs | Concurrency: 1", model_tag, validated_host, validated_timeout)
    logger.info("Dry-Run Mode: %s | Force Recapture: %s | Verify Blobs: %s", dry_run, force, verify_blobs)
    logger.info("=" * 70)

    # 1. Preflight Verification (Strict Offline / Local Loopback)
    daemon_info = probe_local_ollama_daemon(
        host=validated_host,
        target_model=model_tag,
        timeout=min(validated_timeout, 5.0),
    )
    manifest_digest, manifest_size, manifest_path = resolve_manifest_layer_digest(target_model=model_tag)

    model_blob_verified = False
    if manifest_digest:
        model_blob_verified, blob_path = verify_model_blob_integrity(
            layer_digest=manifest_digest,
            compute_hash=verify_blobs,
        )

    # 2. Dataset Ingestion (DDR-08)
    loader = ScenarioDatasetLoader(base_dir=base_datasets_dir)
    scenarios = loader.load_all_scenarios(include_unapproved=allow_draft)

    if requested_scenarios:
        req_set = {s.strip() for s in requested_scenarios}
        scenarios = [s for s in scenarios if s.scenario_id in req_set]
        logger.info("Filtered scenarios to %d requested IDs: %s", len(scenarios), [s.scenario_id for s in scenarios])
    else:
        logger.info("Loaded %d ground-truth scenarios (allow_draft=%s).", len(scenarios), allow_draft)

    # 3. Preparation of Components
    sysmon_parser = SysmonParser()
    context_builder = InvestigationContextBuilder()
    prompt_builder = InvestigationPromptBuilder()

    target_inference_params = {
        "temperature": temperature,
        "num_predict": num_predict,
        "format": "json",
    }

    chat_url = f"{validated_host}/api/chat"
    results: list[dict[str, Any]] = []
    skipped_count = 0
    captured_count = 0
    dry_run_count = 0
    transport_failures_count = 0
    error_count = 0
    gate_skipped_count = 0

    # 4. Sequential Execution Loop (concurrency=1)
    with httpx.Client(timeout=validated_timeout, follow_redirects=False) as client:
        for idx, scenario in enumerate(scenarios, start=1):
            sc_id = scenario.scenario_id
            logger.info("--- [%d/%d] Processing Scenario: %s ---", idx, len(scenarios), sc_id)
            sc_start = time.monotonic()

            try:
                # Step A: Telemetry Normalization (CF-01)
                context_items = normalize_scenario_events(scenario, sysmon_parser)

                # Step B: Deterministic Context Assembly (BLK-1.1-01)
                context = build_scenario_context(
                    scenario=scenario,
                    context_items=context_items,
                    context_builder=context_builder,
                    model_tag=model_tag,
                    temperature=temperature,
                )

                # Step B2: Deterministic evidence-sufficiency gate (Stage 3C, ADR-008).
                # Fail-closed: evaluate_sufficiency never raises; INSUFFICIENT means no model call.
                if not gate_off_ablation:
                    assessment = evaluate_sufficiency(context)
                    if assessment.abstain:
                        logger.info(
                            "[GATE-SKIP] %s: evidence INSUFFICIENT (%s); live inference not issued",
                            sc_id,
                            ", ".join(assessment.reason_codes),
                        )
                        gate_skipped_count += 1
                        results.append(
                            {
                                "scenario_id": sc_id,
                                "status": "skipped_gate_insufficient",
                                "sufficiency_reason_codes": list(assessment.reason_codes),
                                "sufficiency_assessment_sha256": assessment.assessment_sha256,
                                "duration_seconds": round(time.monotonic() - sc_start, 3),
                            }
                        )
                        continue

                # Step C: Structured Prompt Serialization (MF-02)
                serialized_prompt, prompt_sha256, canonical_bytes, llm_request = build_and_serialize_prompt(
                    context=context,
                    prompt_builder=prompt_builder,
                    model_tag=model_tag,
                    max_tokens=num_predict,
                )

                # Step D: Persist Prompt Artifact
                prompt_file_path = persist_prompt_artifact(
                    scenario_id=sc_id,
                    canonical_bytes=canonical_bytes,
                    prompts_dir=target_prompts_dir,
                )

                # Step E: Hardened 5-Point Idempotency Check (F-03, Refinement A)
                fixture_path = target_fixtures_dir / f"{sc_id}-captured.json"
                if not force:
                    is_cached, skip_reason, cached_envelope = check_existing_fixture(
                        fixture_path=fixture_path,
                        target_scenario_id=sc_id,
                        target_model=model_tag,
                        target_prompt_sha256=prompt_sha256,
                        target_inference_parameters=target_inference_params,
                    )
                    if is_cached and cached_envelope:
                        logger.info("[SKIP] %s: Reusing valid existing capture (%s)", sc_id, skip_reason)
                        skipped_count += 1
                        results.append(
                            {
                                "scenario_id": sc_id,
                                "status": "skipped_cache_hit",
                                "reason": skip_reason,
                                "prompt_sha256": prompt_sha256,
                                "raw_response_sha256": cached_envelope.raw_response_sha256,
                                "duration_seconds": round(time.monotonic() - sc_start, 3),
                                "fixture_path": str(fixture_path),
                            }
                        )
                        continue

                # Step F: Dry-Run Intercept
                if dry_run:
                    logger.info(
                        "[DRY-RUN] %s: Preflight, normalization & prompt generation verified (sha256: %s...)",
                        sc_id,
                        prompt_sha256[:16],
                    )
                    dry_run_count += 1
                    results.append(
                        {
                            "scenario_id": sc_id,
                            "status": "dry_run_verified",
                            "prompt_sha256": prompt_sha256,
                            "prompt_path": str(prompt_file_path),
                            "duration_seconds": round(time.monotonic() - sc_start, 3),
                        }
                    )
                    continue

                # Step G: Sequential HTTP Inference Execution (concurrency=1)
                payload = {
                    "model": model_tag,
                    "messages": [
                        {"role": msg.role.value, "content": msg.content}
                        for msg in llm_request.messages
                    ],
                    "format": "json",
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": num_predict,
                    },
                }

                logger.info("Issuing POST /api/chat for %s (timeout: %.1fs)...", sc_id, timeout)
                try:
                    response = execute_single_ollama_inference(client, chat_url, payload)
                except Exception as net_exc:
                    # In accordance with Section 11.2 & 11.3:
                    # Transport failures (States 2 and 3) do NOT produce a CapturedInvestigationFixture.
                    # They are recorded in batch summary, leaving the scenario UNMEASURED in the replay runner.
                    logger.error("Transport failure for scenario %s: %s", sc_id, net_exc)
                    transport_failures_count += 1
                    results.append(
                        {
                            "scenario_id": sc_id,
                            "status": "transport_failure",
                            "error": str(net_exc),
                            "prompt_sha256": prompt_sha256,
                            "duration_seconds": round(time.monotonic() - sc_start, 3),
                        }
                    )
                    continue

                # Step H: Packaging & Atomic Persistence (F-05, DDR-07)
                envelope, written_path = package_and_persist_fixture(
                    scenario_id=sc_id,
                    model_tag=model_tag,
                    manifest_digest=manifest_digest,
                    model_blob_verified=model_blob_verified,
                    prompt_sha256=prompt_sha256,
                    serialized_prompt=serialized_prompt,
                    response=response,
                    target_inference_parameters=target_inference_params,
                    fixtures_dir=target_fixtures_dir,
                    retain_http_body=retain_http_body,
                )

                logger.info(
                    "[CAPTURED] %s: Persisted authentic envelope to %s (resp_sha256: %s...)",
                    sc_id,
                    written_path.name,
                    envelope.raw_response_sha256[:16],
                )
                captured_count += 1
                results.append(
                    {
                        "scenario_id": sc_id,
                        "status": "captured",
                        "prompt_sha256": prompt_sha256,
                        "raw_response_sha256": envelope.raw_response_sha256,
                        "duration_seconds": round(time.monotonic() - sc_start, 3),
                        "fixture_path": str(written_path),
                    }
                )

            except Exception as exc:
                logger.error("Unhandled error processing scenario %s: %s", sc_id, exc, exc_info=True)
                error_count += 1
                results.append(
                    {
                        "scenario_id": sc_id,
                        "status": "error",
                        "error": str(exc),
                        "duration_seconds": round(time.monotonic() - sc_start, 3),
                    }
                )

    total_duration = time.monotonic() - start_time_monotonic

    # 5. Generate and Persist Batch Summary
    summary = {
        "harness_version": HARNESS_VERSION,
        "execution_timestamp_utc": start_time_utc.isoformat(),
        "completion_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total_duration_seconds": round(total_duration, 2),
        "configuration": {
            "model_tag": model_tag,
            "host": validated_host,
            "timeout_seconds": validated_timeout,
            "temperature": temperature,
            "num_predict": num_predict,
            "concurrency": 1,
            "force": force,
            "verify_blobs": verify_blobs,
            "dry_run": dry_run,
            "allow_draft": allow_draft,
            "sufficiency_gate": "gate_off_ablation" if gate_off_ablation else "gate_on",
        },
        "retry_policy": build_retry_policy_provenance(),
        "model_provenance": {
            "model_tag": model_tag,
            "manifest_digest": manifest_digest,
            "manifest_path": str(manifest_path) if manifest_path else None,
            "model_blob_verified": model_blob_verified,
        },
        "summary_counts": {
            "total_scenarios_evaluated": len(scenarios),
            "captured_count": captured_count,
            "skipped_cache_hit_count": skipped_count,
            "dry_run_verified_count": dry_run_count,
            "transport_failures_count": transport_failures_count,
            "error_count": error_count,
            "skipped_gate_insufficient_count": gate_skipped_count,
        },
        "scenario_results": results,
    }

    try:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_summary = summary_path.with_name(f"{summary_path.name}.tmp.{uuid.uuid4()}")
        with open(tmp_summary, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_summary, summary_path)
        logger.info("Batch capture summary successfully saved to: %s", summary_path)
    except Exception as exc:
        logger.error("Failed to persist batch capture summary to %s: %s", summary_path, exc)

    logger.info("=" * 70)
    logger.info("AISOP P3-H3B Live Ollama Capture Completed")
    logger.info("Total: %d | Captured: %d | Skipped: %d | Dry-Run: %d | Transport Failures: %d | Errors: %d",
                len(scenarios), captured_count, skipped_count, dry_run_count, transport_failures_count, error_count)
    logger.info("=" * 70)

    return summary


# ── CLI ENTRY POINT ───────────────────────────────────────────────────────────
def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AISOP P3-H3B Live Ollama Model Benchmark Execution & Fixture Capture Protocol Harness"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=DEFAULT_MODEL_TAG,
        help=f"Target Ollama model tag (default: '{DEFAULT_MODEL_TAG}')",
    )
    parser.add_argument(
        "--host",
        type=str,
        default=DEFAULT_OLLAMA_HOST,
        help=f"Local Ollama loopback host URL (default: '{DEFAULT_OLLAMA_HOST}')",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS}s)",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=DEFAULT_TEMPERATURE,
        help=f"Sampling temperature (default: {DEFAULT_TEMPERATURE} for deterministic evaluation)",
    )
    parser.add_argument(
        "--num-predict",
        type=int,
        default=DEFAULT_NUM_PREDICT,
        help=f"Maximum tokens to predict (default: {DEFAULT_NUM_PREDICT})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Bypass 5-point idempotency skip check and force recapture of existing fixtures",
    )
    parser.add_argument(
        "--verify-blobs",
        action="store_true",
        default=False,
        help="Compute SHA-256 over local 4.9 GB model layer blob during preflight (Refinement B)",
    )
    parser.add_argument(
        "--retain-http-body",
        action="store_true",
        default=False,
        help="Store complete stringified HTTP response body in capture_environment metadata",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Execute preflight, normalization, prompt assembly and idempotency checks without issuing HTTP chat requests",
    )
    parser.add_argument(
        "--scenarios",
        type=str,
        default=None,
        help="Optional comma-separated list of scenario IDs to process (e.g. 'SCN-ATO-001,SCN-CHN-001')",
    )
    parser.add_argument(
        "--allow-draft",
        action="store_true",
        default=False,
        help="Include unapproved/draft scenarios (such as SCN-BEN-005) in capture run",
    )
    parser.add_argument(
        "--datasets-dir",
        type=str,
        default=str(PROJECT_ROOT / "datasets" / "ground_truth"),
        help="Base directory containing ground_truth scenario categories",
    )
    parser.add_argument(
        "--fixtures-dir",
        type=str,
        default=str(PROJECT_ROOT / "datasets" / "ground_truth" / "fixtures"),
        help="Directory to persist captured fixture envelopes",
    )
    parser.add_argument(
        "--prompts-dir",
        type=str,
        default=str(PROJECT_ROOT / "datasets" / "ground_truth" / "prompts"),
        help="Directory to persist canonical prompt text artifacts",
    )
    parser.add_argument(
        "--summary-file",
        type=str,
        default=str(PROJECT_ROOT / "docs" / "04_Testing" / "batch_capture_summary.json"),
        help="Destination path for batch capture JSON summary file (default: docs/04_Testing/batch_capture_summary.json)",
    )
    parser.add_argument(
        "--gate-off-ablation",
        action="store_true",
        default=False,
        help=(
            "EVALUATION ABLATION ONLY: bypass the deterministic evidence-sufficiency gate. "
            "Default is gate-on (INSUFFICIENT scenarios are not sent to the model). "
            "The choice is recorded in the batch summary configuration."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    requested_scenarios = (
        [s.strip() for s in args.scenarios.split(",") if s.strip()]
        if args.scenarios
        else None
    )

    try:
        summary = run_batch_capture(
            model_tag=args.model,
            host=args.host,
            timeout=args.timeout,
            temperature=args.temperature,
            num_predict=args.num_predict,
            force=args.force,
            verify_blobs=args.verify_blobs,
            retain_http_body=args.retain_http_body,
            dry_run=args.dry_run,
            requested_scenarios=requested_scenarios,
            allow_draft=args.allow_draft,
            datasets_dir=Path(args.datasets_dir),
            fixtures_dir=Path(args.fixtures_dir),
            prompts_dir=Path(args.prompts_dir),
            summary_file=Path(args.summary_file),
            gate_off_ablation=args.gate_off_ablation,
        )

        counts = summary.get("summary_counts", {})
        if counts.get("error_count", 0) > 0:
            return 1
        if counts.get("transport_failures_count", 0) > 0:
            # Partial batch completed with transport failures
            return 2
        return 0

    except LoopbackSecurityError as exc:
        logger.error("[SECURITY ERROR - NON-LOOPBACK ENDPOINT REJECTED] %s", exc)
        return 12
    except OllamaPreflightError as exc:
        logger.error("[PREFLIGHT FAILED] %s", exc)
        return 10
    except ValueError as exc:
        logger.error("[CONFIGURATION ERROR] %s", exc)
        return 11
    except Exception as exc:
        logger.error("[FATAL ERROR] %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
