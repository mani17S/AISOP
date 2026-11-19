"""
Stage 3C (ADR-008): choke-point, architecture, dataset-protection and evaluation-harness tests.

Offline: no database, no network, no model (a call-counting scripted provider only).
"""

from __future__ import annotations

import ast
import inspect
import shutil
from pathlib import Path

import pytest

from app.modules.ai.guardrails.gated_generation import GatedGenerator, SufficiencyGateViolation
from app.modules.ai.guardrails.sufficiency_gate import evaluate_sufficiency
from app.modules.evaluation import sufficiency_evaluator as se
from app.modules.evaluation.sufficiency_evaluator import (
    CountingProvider,
    SufficiencyDatasetIntegrityError,
    _scripted_request,
    build_context_from_case,
    compute_metrics,
    evaluate_split,
    load_cases,
    verify_manifest,
)
from app.schemas.sufficiency import SufficiencyVerdict
from tests.unit.test_evidence_sufficiency_gate import ent, ev, make

BACKEND = Path(__file__).resolve().parents[2]
APP_DIR = BACKEND / "app"
SCRIPTS_DIR = BACKEND / "scripts"
ALLOWED_GENERATE_CALLERS = {
    (APP_DIR / "modules" / "ai" / "guardrails" / "gated_generation.py").resolve(),
    (APP_DIR / "modules" / "evaluation" / "sufficiency_evaluator.py").resolve(),  # gate-off ablation arm only
}


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ── GatedGenerator ────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_gated_generator_refuses_without_assessment_or_when_insufficient_or_mismatched():
    provider = CountingProvider()
    ctx = make([ev("e0"), ev("e1", etype="network_connection", eid="3", off=5.0)], [ent("process", "p.exe", "e0"), ent("domain", "c2.badcdn.example", "e0", "e1")])
    other = make([ev("z0")], [ent("process", "q.exe", "z0")], cid="OTHER")

    with pytest.raises(SufficiencyGateViolation):
        await GatedGenerator.generate(provider, _scripted_request(), None, ctx)

    insufficient = evaluate_sufficiency(make([], root=None))
    assert insufficient.verdict == SufficiencyVerdict.INSUFFICIENT
    with pytest.raises(SufficiencyGateViolation):
        await GatedGenerator.generate(provider, _scripted_request(), insufficient, ctx)

    with pytest.raises(SufficiencyGateViolation):  # assessment of a different context
        await GatedGenerator.generate(provider, _scripted_request(), evaluate_sufficiency(other), ctx)

    with pytest.raises(SufficiencyGateViolation):
        await GatedGenerator.generate(provider, _scripted_request(), evaluate_sufficiency(ctx), None)
    assert provider.calls == 0


@pytest.mark.anyio
async def test_gated_generator_permits_sufficient_and_limited():
    provider = CountingProvider()
    sufficient_ctx = make([ev("e0"), ev("e1", etype="network_connection", eid="3", off=5.0)], [ent("process", "p.exe", "e0"), ent("domain", "c2.badcdn.example", "e0", "e1")])
    limited_ctx = make([ev("e0")], [ent("process", "p.exe", "e0")])
    for ctx, verdict in ((sufficient_ctx, SufficiencyVerdict.SUFFICIENT), (limited_ctx, SufficiencyVerdict.LIMITED)):
        a = evaluate_sufficiency(ctx)
        assert a.verdict == verdict
        await GatedGenerator.generate(provider, _scripted_request(), a, ctx)
    assert provider.calls == 2


# ── Architecture: no unguarded generate() call, no way to disable the gate ────
def _generate_calls(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "generate"
        and not (isinstance(n.func.value, ast.Name) and n.func.value.id == "GatedGenerator")
    ]


def test_no_unguarded_model_generate_call_in_production_tree():
    offenders = {}
    for root in (APP_DIR, SCRIPTS_DIR):
        for path in root.rglob("*.py"):
            lines = _generate_calls(path)
            if lines and path.resolve() not in ALLOWED_GENERATE_CALLERS:
                offenders[str(path.relative_to(BACKEND))] = lines
    assert offenders == {}, f"unguarded .generate( calls: {offenders}"
    assert len(_generate_calls(next(iter(sorted(ALLOWED_GENERATE_CALLERS))))) >= 1


def test_services_call_the_provider_only_through_the_gated_generator():
    for rel in ("services/investigation_service.py", "services/case_service.py"):
        src = (APP_DIR / rel).read_text(encoding="utf-8")
        assert "GatedGenerator.generate(" in src, rel
        assert "evaluate_sufficiency(" in src, rel
        tree = ast.parse(src)
        gate_line = min(n.lineno for n in ast.walk(tree) if isinstance(n, ast.Call)
                        and getattr(n.func, "id", "") == "evaluate_sufficiency")
        gen_line = min(n.lineno for n in ast.walk(tree) if isinstance(n, ast.Call)
                       and isinstance(n.func, ast.Attribute) and n.func.attr == "generate")
        assert gate_line < gen_line, f"gate must run before generation in {rel}"


def test_the_ablation_module_is_not_reachable_from_production_code():
    for root in (APP_DIR, SCRIPTS_DIR):
        for path in root.rglob("*.py"):
            if path.name == "sufficiency_evaluator.py":
                continue
            assert "sufficiency_evaluator" not in path.read_text(encoding="utf-8"), path


def test_there_is_no_setting_or_environment_switch_that_disables_the_gate():
    for path in APP_DIR.rglob("*.py"):
        text = path.read_text(encoding="utf-8").lower()
        for forbidden in ("disable_sufficiency", "sufficiency_gate_enabled", "skip_sufficiency", "sufficiency_gate_mode"):
            assert forbidden not in text, (forbidden, path)
    import app.core.config as cfg
    assert not any("sufficien" in name.lower() for name in cfg.Settings.model_fields)


def test_capture_harness_is_gate_on_by_default_and_gates_before_inference():
    path = SCRIPTS_DIR / "capture_live_fixtures.py"
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_batch_capture")
    default = {a.arg: d for a, d in zip(func.args.args[-len(func.args.defaults):], func.args.defaults)}["gate_off_ablation"]
    assert isinstance(default, ast.Constant) and default.value is False
    assert "--gate-off-ablation" in src
    assert src.index("evaluate_sufficiency(context)") < src.index("execute_single_ollama_inference(client, chat_url, payload)")
    assert '"sufficiency_gate": "gate_off_ablation" if gate_off_ablation else "gate_on"' in src


# ── Dataset protection ────────────────────────────────────────────────────────
def test_shipped_dataset_manifest_verifies_and_labels_are_not_generated():
    verify_manifest()
    for split in ("dev", "heldout"):
        assert (se.DEFAULT_BASE_DIR / split / "labels.template.json").is_file()
    # labels.json is owner-authored: the generator/evaluator never create it (it may exist later).
    assert "labels.json" not in (se.DEFAULT_BASE_DIR / "MANIFEST.sha256").read_text(encoding="utf-8").replace("labels.template.json", "")
    assert len(load_cases("dev")) + len(load_cases("heldout")) >= 80


def _copy_dataset(tmp_path: Path) -> Path:
    dst = tmp_path / "sufficiency"
    shutil.copytree(se.DEFAULT_BASE_DIR, dst)
    for f in dst.rglob("*"):
        if f.is_file():
            f.chmod(0o666)  # the shipped files are read-only; the copies are tampered with on purpose
    return dst


def test_tampered_missing_or_unlisted_case_files_are_rejected(tmp_path):
    dst = _copy_dataset(tmp_path)
    target = next((dst / "dev" / "cases").glob("*.json"))
    target.chmod(0o666)
    target.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(SufficiencyDatasetIntegrityError, match="hash mismatch"):
        verify_manifest(dst)

    dst2 = _copy_dataset(tmp_path / "b")
    (dst2 / "dev" / "cases" / "extra.json").write_text("{}", encoding="utf-8")
    with pytest.raises(SufficiencyDatasetIntegrityError, match="unlisted"):
        verify_manifest(dst2)

    dst3 = _copy_dataset(tmp_path / "c")
    next((dst3 / "heldout" / "cases").glob("*.json")).unlink()
    with pytest.raises(SufficiencyDatasetIntegrityError, match="missing"):
        verify_manifest(dst3)


def test_case_files_are_read_only_on_disk():
    for path in list((se.DEFAULT_BASE_DIR / "dev" / "cases").glob("*.json"))[:5]:
        assert not path.stat().st_mode & 0o200


@pytest.mark.anyio
async def test_heldout_split_requires_owner_labels_and_an_explicit_final_flag():
    with pytest.raises(SufficiencyDatasetIntegrityError, match="final_heldout"):
        await evaluate_split("heldout")
    if not (se.DEFAULT_BASE_DIR / "heldout" / "labels.json").exists():
        with pytest.raises(SufficiencyDatasetIntegrityError, match="labels"):
            await evaluate_split("heldout", final_heldout=True)


# ── Evaluation harness ────────────────────────────────────────────────────────
def test_every_derived_case_builds_a_valid_context():
    for split in ("dev", "heldout"):
        for case in load_cases(split):
            ctx = build_context_from_case(case)
            assert len(ctx.reproducibility.context_sha256) == 64


@pytest.mark.anyio
async def test_dev_split_runs_without_labels_and_reports_prevention_and_ablation():
    report = await evaluate_split("dev")
    if not report["labels_available"]:
        assert str(report["metrics"]).startswith("UNAVAILABLE")
    assert report["deterministic_on_rerun"] is True
    assert report["evidence_reference_validity"] == 1.0
    assert report["model_invocation_prevention_rate_predicted_insufficient"] == 1.0
    assert report["predicted_distribution"]["INSUFFICIENT"] >= 2  # the empty-scope and out-of-window cases
    abl = report["ablation"]
    assert abl["gate_on_model_calls"] == report["cases"] - report["predicted_distribution"]["INSUFFICIENT"]
    assert abl["gate_off_model_calls"] == report["cases"]
    assert abl["gate_on_model_calls"] < abl["gate_off_model_calls"]


def test_metric_definitions_on_a_hand_computed_example():
    pairs = [
        ("SUFFICIENT", "SUFFICIENT"), ("SUFFICIENT", "LIMITED"),
        ("LIMITED", "SUFFICIENT"), ("LIMITED", "LIMITED"),
        ("INSUFFICIENT", "INSUFFICIENT"), ("INSUFFICIENT", "SUFFICIENT"),
        ("LIMITED", "INSUFFICIENT"),
    ]
    m = compute_metrics(pairs)
    assert m["n"] == 7 and m["accuracy"] == round(3 / 7, 4)
    assert m["false_sufficient_rate"] == round(2 / 5, 4)             # LIMITED/INSUFFICIENT labels predicted SUFFICIENT
    assert m["false_sufficient_on_insufficient_rate"] == 0.5          # 1 of 2 INSUFFICIENT labels
    assert m["false_insufficient_rate"] == round(1 / 5, 4)           # SUFFICIENT/LIMITED labels predicted INSUFFICIENT
    assert m["predicted_abstention_rate"] == round(2 / 7, 4)
    assert compute_metrics([])["accuracy"] is None


def test_evaluator_only_reads_dataset_files():
    src = inspect.getsource(se)
    assert "write_text" not in src and "write_bytes" not in src and 'open(' not in src
