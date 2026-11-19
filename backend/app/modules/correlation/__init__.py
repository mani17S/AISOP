"""
AISOP multi-source correlation and deterministic investigation workflow (Stage 3C-R, ADR-009).

normalize -> correlate -> timeline / ATT&CK mapping -> sufficiency gate -> optional gated LLM ->
claim verification -> analyst-facing report, with a hash-chained ledger.
"""

from app.modules.correlation.correlator import correlate
from app.modules.correlation.ledger import Ledger, verify_chain
from app.modules.correlation.mitre import map_techniques
from app.modules.correlation.normalize import normalize_records
from app.modules.correlation.workflow import analyze, run_workflow

__all__ = [
    "Ledger",
    "analyze",
    "correlate",
    "map_techniques",
    "normalize_records",
    "run_workflow",
    "verify_chain",
]
