"""
AISOP Scenario Dataset Loader & Path-Protected Ingestion Engine.

Provides secure, schema-validated loading of ground-truth scenarios with:
- Strict path traversal protection.
- Pydantic V2 schema validation.
- Duplicate scenario ID detection.
- Provenance and approval status filtering.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.schemas.evaluation import EvaluationScenario, ReviewerStatus


class DatasetLoadingError(Exception):
    """Raised when scenario files cannot be loaded, resolved, or validated."""
    pass


class DuplicateScenarioIdError(DatasetLoadingError):
    """Raised when multiple scenarios share the same scenario_id."""
    pass


class ScenarioDatasetLoader:
    """
    Secure loader for ground-truth evaluation datasets.
    """

    def __init__(self, base_dir: Path | str | None = None) -> None:
        if base_dir is None:
            # Default to <workspace_root>/datasets/ground_truth
            # Relative to this file: ../../../../datasets/ground_truth
            self.base_dir = (Path(__file__).resolve().parents[4] / "datasets" / "ground_truth").resolve()
        else:
            self.base_dir = Path(base_dir).resolve()

    def _verify_path_safety(self, target_path: Path) -> Path:
        """
        Verify that target_path resides strictly within self.base_dir.
        Prevents directory traversal attacks via '..' or symlinks.
        """
        resolved_target = target_path.resolve()
        try:
            resolved_target.relative_to(self.base_dir)
        except ValueError as exc:
            raise DatasetLoadingError(
                f"Security violation: path '{target_path}' attempts to traverse outside dataset base directory '{self.base_dir}'"
            ) from exc
        return resolved_target

    def load_scenario_from_file(self, file_path: Path | str) -> EvaluationScenario:
        """
        Load and validate an individual scenario JSON file.
        """
        path_obj = Path(file_path)
        safe_path = self._verify_path_safety(path_obj)

        if not safe_path.exists():
            raise DatasetLoadingError(f"Scenario file does not exist: {safe_path}")
        if not safe_path.is_file():
            raise DatasetLoadingError(f"Scenario path is not a file: {safe_path}")

        try:
            with open(safe_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            raise DatasetLoadingError(f"Malformed JSON in scenario file '{safe_path.name}': {exc}") from exc
        except Exception as exc:
            raise DatasetLoadingError(f"Failed to read scenario file '{safe_path.name}': {exc}") from exc

        try:
            return EvaluationScenario.model_validate(data)
        except ValidationError as exc:
            raise DatasetLoadingError(
                f"Scenario schema validation failed for '{safe_path.name}': {exc}"
            ) from exc

    def load_all_scenarios(
        self,
        include_unapproved: bool = False,
    ) -> list[EvaluationScenario]:
        """
        Recursively discover and load all scenario JSON files in self.base_dir.

        Args:
            include_unapproved: If False, scenarios with review_status != 'approved'
                are excluded from the returned list.

        Returns:
            List of valid EvaluationScenario instances sorted by scenario_id.
        """
        if not self.base_dir.exists() or not self.base_dir.is_dir():
            return []

        loaded_scenarios: list[EvaluationScenario] = []
        seen_ids: dict[str, Path] = {}

        for file_path in sorted(self.base_dir.rglob("*.json")):
            # Skip hidden files, fixtures, or non-scenario replay files
            if file_path.name.startswith(".") or "fixtures" in file_path.parts or file_path.name.endswith("-replay.json"):
                continue

            scenario = self.load_scenario_from_file(file_path)

            # Enforce scenario_id uniqueness
            if scenario.scenario_id in seen_ids:
                prior_file = seen_ids[scenario.scenario_id]
                raise DuplicateScenarioIdError(
                    f"Duplicate scenario_id '{scenario.scenario_id}' found in '{file_path.name}'; "
                    f"already loaded from '{prior_file.name}'"
                )

            seen_ids[scenario.scenario_id] = file_path

            if not include_unapproved and scenario.provenance.review_status != ReviewerStatus.APPROVED:
                continue

            loaded_scenarios.append(scenario)

        return loaded_scenarios

    def get_scenario_by_id(
        self,
        scenario_id: str,
        include_unapproved: bool = True,
    ) -> EvaluationScenario | None:
        """Retrieve a specific scenario by its unique scenario_id."""
        clean_id = scenario_id.strip().upper()
        all_scenarios = self.load_all_scenarios(include_unapproved=include_unapproved)
        for s in all_scenarios:
            if s.scenario_id == clean_id:
                return s
        return None
