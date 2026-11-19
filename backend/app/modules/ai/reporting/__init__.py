"""
AISOP Role-Tailored Reporting Subsystem.

Provides deterministic report synthesis and Markdown rendering for:
- Executive Brief
- Technical Incident Response Report
- Detection Engineering Report
"""

from app.modules.ai.reporting.synthesizer import (
    ContextIntegrityError,
    DeterministicReportSynthesizer,
    verify_context_binding,
)

__all__ = [
    "ContextIntegrityError",
    "DeterministicReportSynthesizer",
    "verify_context_binding",
]
