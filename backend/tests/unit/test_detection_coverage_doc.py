"""The telemetry-requirements document is generated from the rule table and must not drift from it."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location("detection_coverage", _ROOT / "backend" / "scripts" / "detection_coverage.py")
dc = importlib.util.module_from_spec(_SPEC)
sys.modules["detection_coverage"] = dc
_SPEC.loader.exec_module(dc)  # type: ignore[union-attr]

from app.modules.correlation.mitre_endpoint import ENDPOINT_RULES  # noqa: E402

DOC = _ROOT / "docs" / "10_Research" / "Detection_Coverage_and_Telemetry.md"


def test_the_checked_in_document_matches_the_rule_table():
    assert DOC.read_text(encoding="utf-8").replace("\r\n", "\n") == dc.build_markdown(), "regenerate with backend/scripts/detection_coverage.py"


def test_every_rule_appears_once_and_overrides_name_real_rules():
    text = dc.build_markdown()
    for r in ENDPOINT_RULES:
        assert text.count(f"| `{r.rule_id}` |") == 1
    assert set(dc.TELEMETRY) <= {r.rule_id for r in ENDPOINT_RULES}


def test_typed_field_rules_are_listed_with_the_events_they_read():
    """A rule that reads Sysmon or Security typed fields needs that event, so it is listed explicitly and not left to the command-line default."""
    typed = ("EP-T1003.001-LSASS-MEMORY-READ", "EP-T1055-REMOTE-THREAD", "EP-T1562.002-AUDIT-POLICY-CHANGED", "EP-T1070.001-LOG-CLEARED",
             "EP-T1547.001-RUN-KEY-OR-STARTUP", "EP-T1047-WMI-PROVIDER-SPAWN", "EP-T1021.006-WINRM-HOST-PROCESS")
    for rule_id in typed:
        assert rule_id in dc.TELEMETRY
    assert dc.telemetry_for("EP-T1003.001-LSASS-MEMORY-READ") == (dc.SYSMON_10,)
    assert dc.telemetry_for("EP-T1053.005-SCHTASKS-CREATE") == (dc.PROC_CMD,)
