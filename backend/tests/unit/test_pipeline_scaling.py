"""
Pipeline scaling and output stability (backend/evaluation_tools/pipeline_fingerprint.py).

On 2026-11-24 the correlator and the per-incident graph and report were found to rescan every link for every incident, so 1,500 records took 515 seconds. They
were rewritten to give IDENTICAL output (fingerprints below were captured BEFORE the change and matched after it) and 1,500 records now take about 15 seconds.

Pinned here: (1) the exact output of the demo scenarios, the envelope scenarios and a 600-record log, so a future speed-up cannot change a verdict, a link or an
incident id without this test saying so; (2) a generous time bound that a return to the cubic behaviour would break (800 records took about 100 seconds before).
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_ROOT / "backend" / "scripts"))
_SPEC = importlib.util.spec_from_file_location("pipeline_fingerprint", _ROOT / "backend" / "evaluation_tools" / "pipeline_fingerprint.py")
pf = importlib.util.module_from_spec(_SPEC)
sys.modules["pipeline_fingerprint"] = pf
_SPEC.loader.exec_module(pf)  # type: ignore[union-attr]

from app.modules.correlation import demo_data as dd  # noqa: E402
from app.modules.correlation.workflow import analyze  # noqa: E402
from app.modules.evidence_domains import scenarios as S  # noqa: E402

PINNED = {
    "demo:01_intrusion_chain": "5cbea792047300507e315e8cee56057b1a36086e617892f926957fad85c9f1fa",
    "demo:02_duplicates_near_duplicates": "ced9f80d199d47b213999e9e11142f96a0fe665201498474649fbe32733b6079",
    "demo:03_contradictory_evidence": "b5095372c1ce881794e707e31dbf1f5b9e088b952852fa6e868054307f3c7933",
    # Re-pinned 2026-11-25: the demo DNS record states severity "informational"; the IDS adapter used to turn that unmapped value into an invented "medium"
    # and now keeps "informational". Verified as the only difference: forcing that one alert back to "medium" reproduces the previous fingerprint 50dacc9c...
    "demo:04_unrelated_and_weak_context": "5963feed468399d4d037d631d800f223680c4be7364f271fab6ecd81a8e693f3",
    "demo:05_insufficient_unparseable": "a78ea9799b6ef5a9ef687cf162b66878a336ed3bfbcdacf11fa637e6f64bf5a6",
    "demo:06_uncorroborated_single_alert": "d0e8f9c435be524ea52e557379564cd6b8f5ef54afc08c9317ece591f7340f98",
    "envelope:scenario_a_identity_cloud": "ad7beb7213c31cdf66c8d62c5d0b967c0f615c3f9cedcf3f662464c3860a6728",
    "envelope:scenario_b_network_endpoint": "93eeceda4d68837747101fad860bc1a14f8c8e95688c1277725a1b07a432f65f",
    "envelope:scenario_c_email_forensic": "6e1d24a2d3759e160719399744f5d3bd76ae69b046119121e004128959339c86",
    "synthetic_ssh_600": "0b438b21ca24b06ce6bd81cc63c809f7bffcb5b631cd4e8ed721bea85140c78d",
}


def _records(name: str):
    if name.startswith("demo:"):
        s = dd.SCENARIOS[name.split(":", 1)[1]]
        return s["build"](), s.get("assets")
    if name.startswith("envelope:"):
        return getattr(S, name.split(":", 1)[1])(), None
    return pf.synthetic_ssh(600, 7), None


@pytest.mark.parametrize("name", sorted(PINNED))
def test_the_pipeline_output_is_exactly_what_it_was_before_the_speed_up(name):
    records, assets = _records(name)
    assert pf.fingerprint(analyze(records, assets=assets)) == PINNED[name]


def test_eight_hundred_records_do_not_take_minutes():
    started = time.perf_counter()
    result = analyze(pf.synthetic_ssh(800, 3))
    elapsed = time.perf_counter() - started
    assert len(result.normalization.events) == 800
    assert elapsed < 60, f"800 records took {elapsed:.0f}s; the cubic scan has probably returned (about 100 s before the fix, about 4 s after)"
