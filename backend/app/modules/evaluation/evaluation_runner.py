"""
AISOP Evaluation Replay Runner & Benchmark Engine.

P3-H3A.2: Evaluation Integrity Remediation.
Coordinates offline evaluation of investigation outputs against ground-truth scenarios:
- Strictly decoupled from ground-truth answer synthesis; never auto-manufactures passing fixtures.
- Explicitly separates 'harness_self_test' from 'captured_evaluation' modes.
- Distinguishes authentic measured scenarios from unmeasured/missing scenarios.
- Implements structured entity-based IOC false-positive extraction (removes hardcoded fp=0).
- Computes dataset-level micro MITRE metrics and benign scenario false-positive tracking.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import re
from typing import Any, Mapping, Sequence
import uuid

from app.modules.ai.context_builder.hasher import compute_validation_output_sha256
from app.modules.evaluation.grounding_evaluator import GroundingEvaluator
from app.modules.evaluation.metrics import (
    canonicalize_prompt_artifact,
    categorize_fallback,
    compute_precision_recall_f1,
    is_schema_valid_output,
    is_syntactic_json,
    normalize_ioc,
    safe_division,
)
from app.modules.evaluation.mitre_evaluator import MitreEvaluator
from app.schemas.evaluation import (
    BenchmarkRunSummary,
    CapturedInvestigationFixture,
    EvaluationScenario,
    FallbackReasonCategory,
    HumanClaimAdjudication,
    IocTypeEvaluationResult,
    MitreEvaluationResult,
    ReviewerStatus,
    ScenarioCategory,
    ScenarioEvaluationResult,
)
from app.schemas.investigation import StructuredInvestigationOutput


class EvaluationReplayRunner:
    """
    Offline evaluation runner for replaying and grading model investigation outputs.
    """

    def __init__(
        self,
        grounding_evaluator: GroundingEvaluator | None = None,
        mitre_evaluator: MitreEvaluator | None = None,
    ) -> None:
        self.grounding_evaluator = grounding_evaluator or GroundingEvaluator()
        self.mitre_evaluator = mitre_evaluator or MitreEvaluator()

    def evaluate_scenario_output(
        self,
        scenario: EvaluationScenario,
        raw_output_text: str | None = None,
        structured_output_dict: dict[str, Any] | None = None,
        fixture_envelope: CapturedInvestigationFixture | None = None,
        prompt_artifact: str | bytes | None = None,
        adjudication_registry: Mapping[str | uuid.UUID, HumanClaimAdjudication] | None = None,
        output_source_type: str = "offline_replay_fixture",
        execution_latencies_ms: dict[str, float] | None = None,
        is_measured: bool = True,
    ) -> ScenarioEvaluationResult:
        """
        Evaluate a single scenario against an output payload.

        Can accept either:
        - fixture_envelope: Cryptographically bound CapturedInvestigationFixture envelope.
        - raw_output_text: Unparsed string (tests JSON parsing & schema parsing).
        - structured_output_dict: Pre-parsed dictionary.
        - None: Missing fixture (marks scenario UNMEASURED).
        """
        notes: list[str] = []
        is_json_valid = False
        parsed_dict: dict[str, Any] | None = None

        if output_source_type == "legacy_unverified_fixture":
            is_measured = False
            notes.append(
                "LEGACY_UNVERIFIED: Fixture lacks CapturedInvestigationFixture cryptographic envelope. "
                "Excluded from official measured performance."
            )
            if structured_output_dict is not None:
                is_json_valid = True
                parsed_dict = structured_output_dict
                raw_text = str(structured_output_dict)
            elif raw_output_text is not None:
                raw_text = raw_output_text
                is_json_valid, parsed_dict, json_err = is_syntactic_json(raw_output_text)
                if not is_json_valid:
                    notes.append(f"JSON Syntax Error: {json_err}")
            else:
                raw_text = ""
                notes.append("UNMEASURED: No output payload provided for legacy fixture.")
        elif fixture_envelope is not None:
            # 1. Enforce scenario ID binding
            if fixture_envelope.scenario_id != scenario.scenario_id:
                notes.append(
                    f"FIXTURE MISBINDING: Envelope scenario_id '{fixture_envelope.scenario_id}' "
                    f"does not match target scenario '{scenario.scenario_id}'."
                )
                is_measured = False
                raw_text = ""
                parsed_dict = None
                is_json_valid = False
                output_source_type = "fixture_misbound"
            else:
                # 2. Cryptographic payload integrity verification
                raw_resp_str = (
                    fixture_envelope.raw_response
                    if isinstance(fixture_envelope.raw_response, str)
                    else json.dumps(fixture_envelope.raw_response)
                )
                computed_sha256 = hashlib.sha256(raw_resp_str.encode("utf-8")).hexdigest()
                if computed_sha256.lower() != fixture_envelope.raw_response_sha256.lower():
                    notes.append(
                        f"FIXTURE INTEGRITY COMPROMISED: Payload SHA-256 '{computed_sha256}' "
                        f"does not match envelope declared SHA-256 '{fixture_envelope.raw_response_sha256}'."
                    )
                    is_measured = False
                    raw_text = ""
                    parsed_dict = None
                    is_json_valid = False
                    output_source_type = "fixture_hash_mismatch"
                else:
                    # 3. Prompt Artifact Verification
                    candidate_prompt = (
                        prompt_artifact
                        if prompt_artifact is not None
                        else fixture_envelope.prompt_artifact
                    )
                    if candidate_prompt is None:
                        notes.append(
                            "PROMPT ARTIFACT MISSING: Exact prompt artifact unavailable for verification. "
                            "Authenticity cannot be cryptographically established."
                        )
                        is_measured = False
                        raw_text = ""
                        parsed_dict = None
                        is_json_valid = False
                        output_source_type = "missing_prompt_artifact"
                    else:
                        computed_prompt_hash = hashlib.sha256(
                            canonicalize_prompt_artifact(candidate_prompt)
                        ).hexdigest()
                        if computed_prompt_hash.lower() != fixture_envelope.prompt_sha256.lower():
                            notes.append(
                                f"PROMPT INTEGRITY MISMATCH: Computed prompt SHA-256 '{computed_prompt_hash}' "
                                f"does not match envelope declared prompt_sha256 '{fixture_envelope.prompt_sha256}'."
                            )
                            is_measured = False
                            raw_text = ""
                            parsed_dict = None
                            is_json_valid = False
                            output_source_type = "prompt_hash_mismatch"
                        else:
                            raw_text = raw_resp_str
                            is_json_valid, parsed_dict, json_err = is_syntactic_json(raw_text)
                            if not is_json_valid:
                                notes.append(f"JSON Syntax Error: {json_err}")
                            output_source_type = fixture_envelope.capture_method
        elif structured_output_dict is not None:
            is_json_valid = True
            parsed_dict = structured_output_dict
            raw_text = str(structured_output_dict)
        elif raw_output_text is not None:
            raw_text = raw_output_text
            is_json_valid, parsed_dict, json_err = is_syntactic_json(raw_output_text)
            if not is_json_valid:
                notes.append(f"JSON Syntax Error: {json_err}")
        else:
            raw_text = ""
            notes.append("UNMEASURED: No authentic captured model response provided for this scenario.")
            is_measured = False

        # Schema Validation
        is_schema_valid = False
        validated_model: StructuredInvestigationOutput | None = None
        if is_json_valid and parsed_dict is not None:
            is_schema_valid, validated_model, schema_err = is_schema_valid_output(parsed_dict)
            if not is_schema_valid:
                notes.append(f"Schema Error: {schema_err}")

        # Model Identifier Consistency Verification
        # Infrastructure binding: compare requested model tag vs provider-reported identity.
        # Content-declared identity (validated_model.model_identifier) is untrusted generated
        # content and must not cause infrastructure identity mismatch.
        if fixture_envelope is not None and is_measured:
            requested_tag = (fixture_envelope.model_identifier or "").strip().lower()
            provider_identity = (
                fixture_envelope.provider_reported_model_identifier or ""
            ).strip().lower()
            if provider_identity:
                # Provider-reported identity is directly observed from response envelope
                if requested_tag and requested_tag != provider_identity:
                    notes.append(
                        f"MODEL IDENTIFIER MISMATCH: Requested model tag "
                        f"'{fixture_envelope.model_identifier}' does not match "
                        f"provider-reported identity "
                        f"'{fixture_envelope.provider_reported_model_identifier}'."
                    )
                    is_measured = False
                    output_source_type = "model_identifier_mismatch"
            # Legacy compatibility: if provider_reported_model_identifier is absent,
            # default to the requested model_tag (legacy fixtures pre-dating this field).
            # No mismatch is possible since the derived value equals the requested tag.

        # Fallback Categorization
        fallback_cat = categorize_fallback(
            raw_text=raw_text,
            parsed_json=parsed_dict,
            validated_model=validated_model,
            output_source_type=output_source_type,
        )

        # Output Hash Computation
        output_hash: str | None = None
        if validated_model is not None:
            try:
                output_hash = compute_validation_output_sha256(validated_model)
            except Exception as exc:
                output_hash = None
                notes.append(f"Output hash computation failed: {exc}")

        # Eligibility for official benchmark score
        is_official = (scenario.provenance.review_status == ReviewerStatus.APPROVED)

        # Evaluate Grounding & Claims if schema valid
        claim_evals = []
        fact_coverage = []
        grounding_prec: float | None = None
        unsupported_rate: float | None = None
        ref_validity_rate: float | None = None
        lexical_rate: float | None = None
        requires_human_review = 0

        if validated_model is not None:
            context_uuids = {
                str(e.get("event_uuid") or e.get("EventUUID") or "")
                for e in scenario.raw_telemetry_events
                if (e.get("event_uuid") or e.get("EventUUID"))
            } or None

            claim_evals, grounding_prec, unsupported_rate, detailed_grounding = (
                self.grounding_evaluator.evaluate_claims(
                    scenario=scenario,
                    investigation_output=validated_model,
                    context_event_uuids=context_uuids,
                    adjudication_registry=adjudication_registry,
                )
            )
            fact_coverage = self.grounding_evaluator.evaluate_fact_coverage(
                scenario=scenario,
                investigation_output=validated_model,
            )
            ref_validity_rate = detailed_grounding.get("reference_validity_rate")
            lexical_rate = detailed_grounding.get("lexical_diagnostic_overlap_rate")
            requires_human_review = detailed_grounding.get("claims_requiring_human_adjudication", 0)

        # Evaluate MITRE ATT&CK if schema valid
        if validated_model is not None:
            mitre_eval = self.mitre_evaluator.evaluate_mitre_hypotheses(
                scenario=scenario,
                investigation_output=validated_model,
            )
        else:
            # When model output is invalid or missing, all mandatory expected techniques are missed
            expected_mandatory = [
                e.technique_id for e in scenario.expected_mitre_techniques if e.is_mandatory and not e.is_uncertain
            ]
            mitre_eval = MitreEvaluationResult(
                precision=None,
                recall=0.0 if expected_mandatory else None,
                f1=0.0 if expected_mandatory else None,
                true_positives=[],
                false_positives=[],
                false_negatives=expected_mandatory,
                uncertain_mappings=[],
            )

        # Evaluate IOC Extraction
        ioc_evals = self._evaluate_iocs(scenario=scenario, validated_model=validated_model)

        return ScenarioEvaluationResult(
            scenario_id=scenario.scenario_id,
            category=scenario.category,
            review_status=scenario.provenance.review_status,
            is_official_score_eligible=is_official,
            is_json_valid=is_json_valid,
            is_schema_valid=is_schema_valid,
            is_measured=is_measured,
            output_source_type=output_source_type,
            fallback_category=fallback_cat,
            grounding_precision=grounding_prec,
            unsupported_claim_rate=unsupported_rate,
            reference_validity_rate=ref_validity_rate,
            lexical_diagnostic_overlap_rate=lexical_rate,
            claims_requiring_human_review_count=requires_human_review,
            mitre_eval=mitre_eval,
            ioc_evaluations=ioc_evals,
            claim_evaluations=claim_evals,
            fact_coverage=fact_coverage,
            execution_latencies_ms=execution_latencies_ms,
            reproducibility_hash=output_hash,
            evaluation_notes=notes,
        )

    def _extract_observables_from_model(
        self,
        validated_model: StructuredInvestigationOutput,
    ) -> dict[str, set[str]]:
        """
        Extract normalized candidate observables from structured response fields,
        filtering out negated mentions while respecting clause boundaries.
        """
        extracted_by_type: dict[str, set[str]] = {
            "ipv4": set(),
            "ipv6": set(),
            "domain": set(),
            "sha256": set(),
            "md5": set(),
            "sha1": set(),
            "executable": set(),
            "user": set(),
        }

        # Gather distinct text segments with their surrounding contexts
        text_segments: list[str] = [validated_model.investigation_summary]
        for c in validated_model.claims:
            claim_text = getattr(c, "claim_text", getattr(c, "statement", ""))
            text_segments.append(claim_text)
            if c.analyst_notes:
                text_segments.append(c.analyst_notes)
        for h in validated_model.mitre_attack_hypotheses:
            text_segments.append(h.reasoning)
        text_segments.extend(validated_model.alternative_explanations)
        text_segments.extend(validated_model.recommended_analyst_actions)
        text_segments.extend(validated_model.uncertainty_and_data_gaps)

        full_corpus = "\n".join(text_segments)

        # Clause boundary constraint: negation cannot cross clause terminators (, ; : . \n)
        # or contrasting conjunctions (but, however, although, whereas, yet)
        clause_lookahead = r"(?:(?!\b(?:but|however|although|whereas|yet)\b)[^,;:\.\n]){0,40}"

        # 1. IPv4 extraction
        raw_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", full_corpus)
        for ip_cand in raw_ips:
            try:
                parsed_ip = ipaddress.ip_address(ip_cand)
                # Discard trivial version numbers or 0.0.0.0/255.255.255.255
                if parsed_ip.is_unspecified or parsed_ip.is_loopback:
                    continue
                # Negation guard: check if preceded or followed by negation within clause window
                neg_pat_before = rf"(?:not|no|neither|without|unrelated to|not observed|no evidence of|was not|did not)\s+{clause_lookahead}{re.escape(ip_cand)}"
                neg_pat_after = rf"{re.escape(ip_cand)}\s+{clause_lookahead}(?:was not|is not|were not|did not|not observed|not detected|not seen|not active)"
                if re.search(neg_pat_before, full_corpus, flags=re.IGNORECASE) or re.search(neg_pat_after, full_corpus, flags=re.IGNORECASE):
                    continue
                extracted_by_type["ipv4"].add(str(parsed_ip))
            except ValueError:
                pass

        # 2. IPv6 extraction (RFC 5952 canonical formatting)
        raw_ipv6_cands = re.findall(r"(?<![a-zA-Z0-9:])([0-9a-fA-F:]{3,39})(?![a-zA-Z0-9:])", full_corpus)
        for ip6_cand in raw_ipv6_cands:
            if ip6_cand.count(":") >= 2:
                try:
                    parsed_ip6 = ipaddress.ip_address(ip6_cand)
                    if isinstance(parsed_ip6, ipaddress.IPv6Address) and not parsed_ip6.is_unspecified and not parsed_ip6.is_loopback:
                        neg_pat_before = rf"(?:not|no|neither|without|unrelated to|not observed|no evidence of|was not|did not)\s+{clause_lookahead}{re.escape(ip6_cand)}"
                        neg_pat_after = rf"{re.escape(ip6_cand)}\s+{clause_lookahead}(?:was not|is not|were not|did not|not observed|not detected|not seen|not active)"
                        if re.search(neg_pat_before, full_corpus, flags=re.IGNORECASE) or re.search(neg_pat_after, full_corpus, flags=re.IGNORECASE):
                            continue
                        extracted_by_type["ipv6"].add(str(parsed_ip6))
                except ValueError:
                    pass

        # 3. SHA256 / MD5 / SHA1 extraction
        hashes_256 = re.findall(r"\b[A-Fa-f0-9]{64}\b", full_corpus)
        for h in hashes_256:
            extracted_by_type["sha256"].add(h.lower())

        hashes_md5 = re.findall(r"\b[A-Fa-f0-9]{32}\b", full_corpus)
        for h in hashes_md5:
            extracted_by_type["md5"].add(h.lower())

        hashes_sha1 = re.findall(r"\b[A-Fa-f0-9]{40}\b", full_corpus)
        for h in hashes_sha1:
            extracted_by_type["sha1"].add(h.lower())

        # 4. Executable / process extraction
        exe_matches = re.findall(
            r"\b[a-zA-Z0-9_\.-]+\.(?:exe|dll|sys|ps1|bat|cmd|vbs|hta|scr)\b",
            full_corpus,
            flags=re.IGNORECASE,
        )
        for e in exe_matches:
            clean_exe = e.strip().lower()
            neg_pat_before = rf"(?:not|no|neither|without|was not executed|did not execute|not observed)\s+{clause_lookahead}{re.escape(clean_exe)}"
            neg_pat_after = rf"{re.escape(clean_exe)}\s+{clause_lookahead}(?:was not executed|did not execute|not executed|was not observed|not detected|not run)"
            if re.search(neg_pat_before, full_corpus, flags=re.IGNORECASE) or re.search(neg_pat_after, full_corpus, flags=re.IGNORECASE):
                continue
            extracted_by_type["executable"].add(clean_exe)

        # 5. Domain extraction
        domain_matches = re.findall(
            r"\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,}|internal|local|corp|net|org|com|edu|gov|xyz)\b",
            full_corpus,
            flags=re.IGNORECASE,
        )
        non_domain_extensions = {".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd", ".json", ".md", ".py", ".sh", ".txt"}
        for d in domain_matches:
            d_lower = d.strip().lower()
            if any(d_lower.endswith(ext) for ext in non_domain_extensions):
                continue
            if re.match(r"^\d+\.\d+$", d_lower):
                continue
            extracted_by_type["domain"].add(normalize_ioc(d_lower, "domain"))

        # 6. User extraction
        user_matches = re.findall(r"\b[A-Za-z0-9_-]+\\[A-Za-z0-9_.-]+\b", full_corpus)
        for u in user_matches:
            extracted_by_type["user"].add(u.strip())

        return extracted_by_type

    def _evaluate_iocs(
        self,
        scenario: EvaluationScenario,
        validated_model: StructuredInvestigationOutput | None,
    ) -> dict[str, IocTypeEvaluationResult]:
        """
        Evaluate extracted indicators of compromise against expected observables.
        Counts both missed expected observables (FN) and extra hallucinated observables (FP).
        """
        results: dict[str, IocTypeEvaluationResult] = {}
        if not scenario.expected_observables:
            return results

        # Group expected observables by type
        expected_by_type: dict[str, set[str]] = {}
        for exp in scenario.expected_observables:
            t = exp.observable_type.lower().strip()
            norm_val = normalize_ioc(exp.observable_value, t)
            expected_by_type.setdefault(t, set()).add(norm_val)

        predicted_observables = (
            self._extract_observables_from_model(validated_model)
            if validated_model is not None
            else {}
        )

        for obs_type, expected_vals in expected_by_type.items():
            norm_type = "executable" if obs_type in ("executable", "process", "image") else obs_type
            norm_type = "ipv4" if obs_type in ("ipv4", "ip") else norm_type
            norm_type = "ipv6" if obs_type == "ipv6" else norm_type
            norm_type = "sha256" if obs_type in ("sha256", "hash") else norm_type
            norm_type = "md5" if obs_type == "md5" else norm_type
            norm_type = "sha1" if obs_type == "sha1" else norm_type
            norm_type = "domain" if obs_type == "domain" else norm_type
            norm_type = "user" if obs_type == "user" else norm_type

            predicted_vals = predicted_observables.get(norm_type, set())
            expected_set = {normalize_ioc(v, norm_type) for v in expected_vals}

            # Exact Entity Set Comparison
            true_positives = sorted(expected_set & predicted_vals)
            false_positives = sorted(predicted_vals - expected_set)
            false_negatives = sorted(expected_set - predicted_vals)

            tp = len(true_positives)
            fp = len(false_positives)
            fn = len(false_negatives)

            precision, recall, f1 = compute_precision_recall_f1(
                tp=tp, fp=fp, fn=fn, zero_target_penalty=True
            )

            results[obs_type] = IocTypeEvaluationResult(
                observable_type=obs_type,
                precision=precision,
                recall=recall,
                f1=f1,
                true_positives=true_positives,
                false_positives=false_positives,
                false_negatives=false_negatives,
            )

        return results

    @staticmethod
    def _generate_self_test_mock(scenario: EvaluationScenario) -> dict[str, Any]:
        """Generate diagnostic mock payload for harness self-testing only."""
        dummy_event_id = "a1b2c3d4-e5f6-7890-1234-56789abcdef0"
        if scenario.raw_telemetry_events:
            first_event = scenario.raw_telemetry_events[0]
            dummy_event_id = str(first_event.get("event_uuid") or first_event.get("EventUUID") or dummy_event_id)

        claims = []
        if scenario.expected_claims:
            claims.append(
                {
                    "claim_id": str(uuid.uuid4()),
                    "claim_text": f"Harness diagnostic claim for {scenario.scenario_id}",
                    "category": "observed_fact",
                    "confidence": 0.90,
                    "supporting_evidence_ids": [dummy_event_id],
                    "references_exist": True,
                    "grounding_status": "validated_reference",
                    "analyst_notes": "Diagnostic self-test payload",
                }
            )

        hypotheses = []
        if scenario.expected_mitre_techniques:
            first_tech = scenario.expected_mitre_techniques[0]
            hypotheses.append(
                {
                    "technique_id": first_tech.technique_id,
                    "technique_name": first_tech.technique_name,
                    "tactics": [first_tech.tactic or "Execution"],
                    "confidence": 0.90,
                    "reasoning": f"Diagnostic self-test reasoning for {first_tech.technique_id}",
                    "supporting_event_uuids": [dummy_event_id],
                }
            )

        return {
            "investigation_id": str(uuid.uuid4()),
            "generated_at": "2026-10-30T12:00:00Z",
            "model_identifier": "HARNESS_SELF_TEST",
            "investigation_summary": f"Harness self-test execution summary for {scenario.scenario_id} telemetry verification.",
            "claims": claims,
            "mitre_attack_hypotheses": hypotheses,
            "alternative_explanations": [],
            "recommended_analyst_actions": ["Review raw event telemetry"],
            "uncertainty_and_data_gaps": scenario.known_uncertainty,
            "overall_grounding_score": 1.0 if claims else 0.0,
        }

    def run_benchmark(
        self,
        scenarios: Sequence[EvaluationScenario],
        fixtures_by_scenario_id: Mapping[str, Any] | None = None,
        fixture_envelopes_by_scenario_id: Mapping[str, CapturedInvestigationFixture] | None = None,
        prompt_artifacts_by_scenario_id: Mapping[str, str | bytes] | None = None,
        adjudication_registry: Mapping[str | uuid.UUID, HumanClaimAdjudication] | None = None,
        dataset_version: str = "1.0.0",
        run_id: str | None = None,
        benchmark_mode: str = "captured_evaluation",  # or "harness_self_test"
    ) -> BenchmarkRunSummary:
        """
        Execute full benchmark run across a collection of scenarios and fixtures.
        """
        now = datetime.now(timezone.utc)
        scenario_results: list[ScenarioEvaluationResult] = []
        model_identifiers: set[str] = set()
        envelopes_map = fixture_envelopes_by_scenario_id if fixture_envelopes_by_scenario_id is not None else {}
        fixtures_map = fixtures_by_scenario_id if fixtures_by_scenario_id is not None else {}
        prompts_map = prompt_artifacts_by_scenario_id if prompt_artifacts_by_scenario_id is not None else {}

        for scenario in scenarios:
            envelope = envelopes_map.get(scenario.scenario_id)
            fixture = fixtures_map.get(scenario.scenario_id)
            prompt_artifact = prompts_map.get(scenario.scenario_id)

            if benchmark_mode == "harness_self_test":
                if fixture is None and envelope is None:
                    fixture = self._generate_self_test_mock(scenario)
                result = self.evaluate_scenario_output(
                    scenario=scenario,
                    structured_output_dict=fixture if isinstance(fixture, dict) else None,
                    raw_output_text=fixture if isinstance(fixture, str) else None,
                    adjudication_registry=adjudication_registry,
                    output_source_type="harness_self_test_mock",
                    is_measured=True,
                )
                model_identifiers.add("HARNESS_SELF_TEST")
            elif envelope is not None:
                result = self.evaluate_scenario_output(
                    scenario=scenario,
                    fixture_envelope=envelope,
                    prompt_artifact=prompt_artifact,
                    adjudication_registry=adjudication_registry,
                    is_measured=True,
                )
                if result.is_measured:
                    model_identifiers.add(envelope.model_identifier)
            elif isinstance(fixture, CapturedInvestigationFixture):
                result = self.evaluate_scenario_output(
                    scenario=scenario,
                    fixture_envelope=fixture,
                    prompt_artifact=prompt_artifact,
                    adjudication_registry=adjudication_registry,
                    is_measured=True,
                )
                if result.is_measured:
                    model_identifiers.add(fixture.model_identifier)
            elif isinstance(fixture, dict) and "raw_response_sha256" in fixture and "scenario_id" in fixture:
                try:
                    parsed_env = CapturedInvestigationFixture.model_validate(fixture)
                    result = self.evaluate_scenario_output(
                        scenario=scenario,
                        fixture_envelope=parsed_env,
                        prompt_artifact=prompt_artifact,
                        adjudication_registry=adjudication_registry,
                        is_measured=True,
                    )
                    if result.is_measured:
                        model_identifiers.add(parsed_env.model_identifier)
                except Exception as exc:
                    result = self.evaluate_scenario_output(
                        scenario=scenario,
                        raw_output_text=None,
                        adjudication_registry=adjudication_registry,
                        output_source_type="corrupt_fixture_envelope",
                        is_measured=False,
                    )
                    result.evaluation_notes.append(f"Fixture envelope validation error: {exc}")
            elif fixture is None:
                # Missing fixture: mark unmeasured; NEVER auto-manufacture passing answer!
                result = self.evaluate_scenario_output(
                    scenario=scenario,
                    raw_output_text=None,
                    adjudication_registry=adjudication_registry,
                    output_source_type="missing_fixture",
                    is_measured=False,
                )
            elif isinstance(fixture, str):
                # Bare un-enveloped string fixture: legacy unverified fixture
                result = self.evaluate_scenario_output(
                    scenario=scenario,
                    raw_output_text=fixture,
                    adjudication_registry=adjudication_registry,
                    output_source_type="legacy_unverified_fixture",
                    is_measured=False,
                )
            elif isinstance(fixture, dict):
                # Bare un-enveloped dict fixture: legacy unverified fixture
                result = self.evaluate_scenario_output(
                    scenario=scenario,
                    structured_output_dict=fixture,
                    adjudication_registry=adjudication_registry,
                    output_source_type="legacy_unverified_fixture",
                    is_measured=False,
                )
            else:
                result = self.evaluate_scenario_output(
                    scenario=scenario,
                    raw_output_text=None,
                    adjudication_registry=adjudication_registry,
                    output_source_type="missing_fixture",
                    is_measured=False,
                )

            scenario_results.append(result)

        total_scenarios = len(scenario_results)
        official_results = [r for r in scenario_results if r.is_official_score_eligible]
        draft_count = total_scenarios - len(official_results)

        # Distinguish measured scenarios from unmeasured
        measured_official = [r for r in official_results if r.is_measured]
        unmeasured_count = len(official_results) - len(measured_official)

        # In harness self-test mode, evaluate all official results for harness validation
        scoring_set = official_results if benchmark_mode == "harness_self_test" else measured_official

        # Validity Rates
        valid_json_count = sum(1 for r in scoring_set if r.is_json_valid)
        valid_schema_count = sum(1 for r in scoring_set if r.is_schema_valid)
        json_validity_rate = (valid_json_count / len(scoring_set) * 100.0) if scoring_set else 0.0
        schema_validity_rate = (valid_schema_count / len(scoring_set) * 100.0) if scoring_set else 0.0

        # Fallback Rate
        fallback_count = sum(
            1 for r in scoring_set
            if r.fallback_category != FallbackReasonCategory.GENUINE_MODEL_OUTPUT
        )
        fallback_rate = (fallback_count / len(scoring_set) * 100.0) if scoring_set else 0.0

        # Grounding metrics
        grounding_precisions = [r.grounding_precision for r in scoring_set if r.grounding_precision is not None]
        avg_grounding = (sum(grounding_precisions) / len(grounding_precisions)) if grounding_precisions else None

        unsupported_rates = [r.unsupported_claim_rate for r in scoring_set if r.unsupported_claim_rate is not None]
        avg_unsupported = (sum(unsupported_rates) / len(unsupported_rates)) if unsupported_rates else None

        # MITRE Macro Metrics (computed over scenarios where metric is defined)
        mitre_precisions = [r.mitre_eval.precision for r in scoring_set if r.mitre_eval.precision is not None]
        avg_mitre_prec = (sum(mitre_precisions) / len(mitre_precisions)) if mitre_precisions else None

        mitre_recalls = [r.mitre_eval.recall for r in scoring_set if r.mitre_eval.recall is not None]
        avg_mitre_rec = (sum(mitre_recalls) / len(mitre_recalls)) if mitre_recalls else None

        mitre_f1s = [r.mitre_eval.f1 for r in scoring_set if r.mitre_eval.f1 is not None]
        avg_mitre_f1 = (sum(mitre_f1s) / len(mitre_f1s)) if mitre_f1s else None

        # MITRE Micro Metrics (Total TP / (Total TP + Total FP))
        total_tp = sum(len(r.mitre_eval.true_positives) for r in scoring_set)
        total_fp = sum(len(r.mitre_eval.false_positives) for r in scoring_set)
        total_fn = sum(len(r.mitre_eval.false_negatives) for r in scoring_set)
        micro_mitre_prec, micro_mitre_rec, micro_mitre_f1 = compute_precision_recall_f1(
            tp=total_tp, fp=total_fp, fn=total_fn, zero_target_penalty=True
        )

        # Benign False Positive Accounting
        benign_scenarios = [r for r in scoring_set if r.category == ScenarioCategory.BENIGN_BASELINE]
        benign_evaluated = len(benign_scenarios)
        benign_fp_count = sum(len(r.mitre_eval.false_positives) for r in benign_scenarios)
        benign_with_fp = sum(1 for r in benign_scenarios if len(r.mitre_eval.false_positives) > 0)
        benign_fp_rate = safe_division(float(benign_with_fp), float(benign_evaluated))

        # Claims pending human adjudication
        total_pending_human_review = sum(r.claims_requiring_human_review_count for r in scoring_set)

        # Aggregate IOC F1
        ioc_f1s = [
            ioc_res.f1
            for r in scoring_set
            for ioc_res in r.ioc_evaluations.values()
            if ioc_res.f1 is not None
        ]
        avg_ioc_f1 = (sum(ioc_f1s) / len(ioc_f1s)) if ioc_f1s else None

        if benchmark_mode == "harness_self_test":
            model_ident_str = "HARNESS_SELF_TEST"
        else:
            model_ident_str = ", ".join(sorted(model_identifiers)) if model_identifiers else "unknown"

        limitations = [
            "Offline replay engine evaluates recorded fixtures without live Ollama token generation timing.",
            "Execution latencies are unavailable for static replay runs.",
            "Unapproved draft scenarios are excluded from official benchmark scores in accordance with P3-H3A.",
            "Automated semantic entailment is not claimed; claims with valid references require human adjudication.",
            "Missing authentic fixtures are strictly reported as UNMEASURED and excluded from performance claims.",
        ]

        # Compute identity dimensions for benchmark reporting
        requested_tags: set[str] = set()
        provider_reported_ids: set[str] = set()
        content_declared_ids: set[str] = set()
        certified_digests: set[str] = set()
        identity_binding_statuses: set[str] = set()
        evidence_sources: set[str] = set()

        for scenario in official_results:
            envelope = envelopes_map.get(scenario.scenario_id)
            if envelope is None:
                continue
            requested_tag = (envelope.model_identifier or "").strip().lower()
            provider_identity = (
                envelope.provider_reported_model_identifier or ""
            ).strip().lower()
            if requested_tag:
                requested_tags.add(requested_tag)
            if provider_identity:
                provider_reported_ids.add(provider_identity)
            if envelope.model_digest:
                certified_digests.add(envelope.model_digest)
            # Evidence source
            if envelope.provider_reported_model_identifier is not None:
                evidence_sources.add("directly_observed")
            else:
                evidence_sources.add("legacy_derived")
            # Binding status
            if provider_identity:
                if requested_tag and requested_tag == provider_identity:
                    identity_binding_statuses.add("consistent")
                elif requested_tag:
                    identity_binding_statuses.add("diverged")
                else:
                    identity_binding_statuses.add("unknown")
            else:
                identity_binding_statuses.add("legacy_consistent")

        # Aggregate content-declared identities from validated models
        for scenario in official_results:
            # Find validated model from scenario results
            for result in scenario_results:
                if result.scenario_id == scenario.scenario_id:
                    # validated_model is not stored in result; skip content-declared
                    # collection here since it's already filtered by is_measured
                    break

        def _join_or_none(values: set[str]) -> str | None:
            if not values:
                return None
            if len(values) == 1:
                return next(iter(values))
            return "mixed(" + ", ".join(sorted(values)) + ")"

        # Determine overall binding status
        if identity_binding_statuses:
            binding_status = _join_or_none(identity_binding_statuses)
        else:
            binding_status = "no_measured_scenarios"

        return BenchmarkRunSummary(
            run_id=run_id or str(uuid.uuid4()),
            dataset_version=dataset_version,
            timestamp_utc=now,
            benchmark_mode=benchmark_mode,
            evaluated_model_identifier=model_ident_str,
            requested_model_tag=_join_or_none(requested_tags),
            provider_reported_model_identifier=_join_or_none(provider_reported_ids),
            certified_model_digest=_join_or_none(certified_digests),
            identity_binding_status=binding_status,
            identity_evidence_source=_join_or_none(evidence_sources),
            total_scenarios_evaluated=total_scenarios,
            official_approved_scenarios=len(official_results),
            draft_excluded_scenarios=draft_count,
            measured_scenarios_count=len(measured_official),
            unmeasured_scenarios_count=unmeasured_count,
            benign_scenarios_evaluated=benign_evaluated,
            benign_false_positive_count=benign_fp_count,
            benign_false_positive_rate=round(benign_fp_rate, 4) if benign_fp_rate is not None else None,
            claims_requiring_human_adjudication_count=total_pending_human_review,
            overall_json_validity_rate=round(json_validity_rate, 2),
            overall_schema_validity_rate=round(schema_validity_rate, 2),
            overall_evidence_grounding_precision=round(avg_grounding, 4) if avg_grounding is not None else None,
            overall_unsupported_claim_rate=round(avg_unsupported, 4) if avg_unsupported is not None else None,
            overall_mitre_precision=round(avg_mitre_prec, 4) if avg_mitre_prec is not None else None,
            overall_mitre_recall=round(avg_mitre_rec, 4) if avg_mitre_rec is not None else None,
            overall_mitre_f1=round(avg_mitre_f1, 4) if avg_mitre_f1 is not None else None,
            dataset_micro_mitre_precision=round(micro_mitre_prec, 4) if micro_mitre_prec is not None else None,
            dataset_micro_mitre_recall=round(micro_mitre_rec, 4) if micro_mitre_rec is not None else None,
            dataset_micro_mitre_f1=round(micro_mitre_f1, 4) if micro_mitre_f1 is not None else None,
            overall_ioc_f1=round(avg_ioc_f1, 4) if avg_ioc_f1 is not None else None,
            fallback_rate=round(fallback_rate, 2),
            latency_summary={"status": "UNAVAILABLE_FOR_OFFLINE_REPLAY", "metrics": None},
            reproducibility_summary={"mode": "deterministic_fixture_evaluation"},
            known_limitations=limitations,
            scenario_results=scenario_results,
        )
