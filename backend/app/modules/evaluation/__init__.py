"""
AISOP Evaluation Subsystem.

P3-H3A: Ground-Truth AI Evaluation Framework.
Provides offline-first evaluation, metric calculation, and report generation.
"""

from app.modules.evaluation.dataset_loader import ScenarioDatasetLoader
from app.modules.evaluation.evaluation_runner import EvaluationReplayRunner
from app.modules.evaluation.report_generator import BenchmarkReportGenerator

__all__ = [
    "ScenarioDatasetLoader",
    "EvaluationReplayRunner",
    "BenchmarkReportGenerator",
]

