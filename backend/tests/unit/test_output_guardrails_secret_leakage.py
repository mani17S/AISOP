"""
Unit Tests for Output Guardrails Credential & Secret Leakage Defense (OWASP GenAI LLM02).

Validates:
- Redaction of sensitive credentials, passwords, JWT tokens, API keys, and private keys
  from generated LLM investigation outputs prior to presentation or storage.
- Audit violation logging with rule_id SEC-GR-CREDENTIAL-LEAKAGE.
- Tri-state decision transition to REMEDIATED upon secret detection.
- Clean pass-through for outputs containing zero sensitive patterns.
"""

from __future__ import annotations

import uuid
import pytest

from app.modules.ai.guardrails import (
    GuardrailDecision,
    InvestigationOutputValidator,
    ViolationSeverity,
)
from app.schemas.investigation import (
    ClaimCategory,
    FactualClaimItem,
    GroundingStatus,
    StructuredInvestigationOutput,
)
from tests.unit.test_output_guardrails_p2 import make_test_context


class TestOutputGuardrailsSecretLeakage:
    """Tests for SEC-GR-CREDENTIAL-LEAKAGE output sanitization."""

    @pytest.fixture
    def test_context(self):
        return make_test_context()

    def test_secret_in_investigation_summary_is_redacted(self, test_context) -> None:
        raw_output = StructuredInvestigationOutput(
            investigation_id=test_context.investigation_id,
            generated_at=test_context.reproducibility.created_at_utc,
            model_identifier="llama3.1:8b",
            investigation_summary="Host compromise detected. Admin password: 'SuperSecret123!' was recovered from memory dump.",
            claims=[],
            mitre_attack_hypotheses=[],
            alternative_explanations=[],
            recommended_analyst_actions=["Isolate host"],
            uncertainty_and_data_gaps=[],
            overall_grounding_score=0.0,
        )

        validator = InvestigationOutputValidator(strict_mode=False)
        result = validator.validate(raw_output, test_context)

        assert result.decision == GuardrailDecision.REMEDIATED
        assert "SuperSecret123!" not in result.output.investigation_summary
        assert "[REDACTED_SECRET]" in result.output.investigation_summary

        secret_violations = [v for v in result.violations if v.rule_id == "SEC-GR-CREDENTIAL-LEAKAGE"]
        assert len(secret_violations) >= 1
        assert secret_violations[0].target_field == "investigation_summary"
        assert secret_violations[0].severity == ViolationSeverity.HIGH

    def test_api_key_in_claim_text_is_redacted(self, test_context) -> None:
        ev_uuid = test_context.events[0].event_uuid
        claim = FactualClaimItem(
            claim_id=str(uuid.uuid4()),
            claim_text="Exfiltrated credentials using AWS key AKIAIOSFODNN7EXAMPLE to cloud storage.",
            category=ClaimCategory.OBSERVED_FACT,
            supporting_evidence_ids=[ev_uuid],
            references_exist=True,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
            confidence=0.95,
        )

        raw_output = StructuredInvestigationOutput(
            investigation_id=test_context.investigation_id,
            generated_at=test_context.reproducibility.created_at_utc,
            model_identifier="llama3.1:8b",
            investigation_summary="Suspicious PowerShell data exfiltration.",
            claims=[claim],
            mitre_attack_hypotheses=[],
            alternative_explanations=[],
            recommended_analyst_actions=["Revoke API access"],
            uncertainty_and_data_gaps=[],
            overall_grounding_score=1.0,
        )

        validator = InvestigationOutputValidator(strict_mode=False)
        result = validator.validate(raw_output, test_context)

        assert result.decision == GuardrailDecision.REMEDIATED
        assert "AKIAIOSFODNN7EXAMPLE" not in result.output.claims[0].claim_text
        assert "[REDACTED_API_KEY]" in result.output.claims[0].claim_text

        secret_violations = [v for v in result.violations if v.rule_id == "SEC-GR-CREDENTIAL-LEAKAGE"]
        assert any(v.target_field == "claims[0].claim_text" for v in secret_violations)

    def test_jwt_token_in_alternative_explanations_is_redacted(self, test_context) -> None:
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        raw_output = StructuredInvestigationOutput(
            investigation_id=test_context.investigation_id,
            generated_at=test_context.reproducibility.created_at_utc,
            model_identifier="llama3.1:8b",
            investigation_summary="Routine scheduled batch task executed.",
            claims=[],
            mitre_attack_hypotheses=[],
            alternative_explanations=[f"Automated service authentication using bearer token: {jwt_token}"],
            recommended_analyst_actions=["Review audit logs"],
            uncertainty_and_data_gaps=[],
            overall_grounding_score=0.0,
        )

        validator = InvestigationOutputValidator(strict_mode=False)
        result = validator.validate(raw_output, test_context)

        assert result.decision == GuardrailDecision.REMEDIATED
        assert jwt_token not in result.output.alternative_explanations[0]
        assert "[REDACTED_JWT_TOKEN]" in result.output.alternative_explanations[0]

    def test_private_key_in_recommended_actions_is_redacted(self, test_context) -> None:
        raw_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y1+FakeKeyContentForTesting1234567890==\n-----END RSA PRIVATE KEY-----"
        raw_output = StructuredInvestigationOutput(
            investigation_id=test_context.investigation_id,
            generated_at=test_context.reproducibility.created_at_utc,
            model_identifier="llama3.1:8b",
            investigation_summary="Unauthorized SSH key generated.",
            claims=[],
            mitre_attack_hypotheses=[],
            alternative_explanations=[],
            recommended_analyst_actions=[f"Verify if host was configured with: {raw_key}"],
            uncertainty_and_data_gaps=[],
            overall_grounding_score=0.0,
        )

        validator = InvestigationOutputValidator(strict_mode=False)
        result = validator.validate(raw_output, test_context)

        assert result.decision == GuardrailDecision.REMEDIATED
        assert raw_key not in result.output.recommended_analyst_actions[0]
        assert "[REDACTED_PRIVATE_KEY]" in result.output.recommended_analyst_actions[0]

    def test_clean_output_triggers_zero_secret_violations(self, test_context) -> None:
        ev_uuid = test_context.events[0].event_uuid
        claim = FactualClaimItem(
            claim_id=str(uuid.uuid4()),
            claim_text="powershell.exe executed with EncodedCommand parameter.",
            category=ClaimCategory.OBSERVED_FACT,
            supporting_evidence_ids=[ev_uuid],
            references_exist=True,
            grounding_status=GroundingStatus.VALIDATED_REFERENCE,
            confidence=0.90,
        )

        raw_output = StructuredInvestigationOutput(
            investigation_id=test_context.investigation_id,
            generated_at=test_context.reproducibility.created_at_utc,
            model_identifier="llama3.1:8b",
            investigation_summary="Potential code execution observed on domain controller.",
            claims=[claim],
            mitre_attack_hypotheses=[],
            alternative_explanations=["Scheduled system maintenance task"],
            recommended_analyst_actions=["Inspect host event logs directly"],
            uncertainty_and_data_gaps=[],
            overall_grounding_score=1.0,
        )

        validator = InvestigationOutputValidator(strict_mode=False)
        result = validator.validate(raw_output, test_context)

        secret_violations = [v for v in result.violations if v.rule_id == "SEC-GR-CREDENTIAL-LEAKAGE"]
        assert len(secret_violations) == 0

