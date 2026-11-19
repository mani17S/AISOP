"""
Offline unit tests for the pinned local ATT&CK reference loader (synthetic in-memory STIX-like fixtures only).

No network, DNS, socket, database, application startup or real dataset is used. Temporary files go to pytest's
tmp_path (run with --basetemp on D:). The loader is reference data only; it never substitutes or migrates mappings.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
import socket
from pathlib import Path
from typing import Any, Optional

import pydantic
import pytest

from app.modules.attack_reference import (
    AttackReferenceError,
    ErrorCode,
    PinnedRelease,
    ReferenceStatus,
    catalogue_from_document,
    load_catalogue,
    try_load_catalogue,
)

SENTINEL = "SECRET-DESCRIPTION-SENTINEL-DO-NOT-RETAIN"
ENT = "enterprise-attack"
BACKEND = Path(__file__).resolve().parents[2]
REPO = BACKEND.parent


# ── synthetic fixture builders ──────────────────────────────────────────────────────────────────────────────────
def sid(kind: str, n: int) -> str:
    return f"{kind}--{n:08x}-0000-4000-8000-{n:012x}"


def tactic(n: int, tid: str, name: str, short: str, domains: tuple[str, ...] = (ENT,), **extra: Any) -> dict[str, Any]:
    obj = {
        "type": "x-mitre-tactic", "id": sid("x-mitre-tactic", n), "spec_version": "2.1", "name": name,
        "x_mitre_shortname": short, "x_mitre_domains": list(domains),
        "external_references": [{"source_name": "mitre-attack", "external_id": tid, "url": "https://example.invalid"}],
        "description": SENTINEL,
    }
    obj.update(extra)
    return obj


def technique(n: int, aid: str, name: str, phases: tuple[str, ...] = ("execution",), domains: tuple[str, ...] = (ENT,),
              **extra: Any) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "type": "attack-pattern", "id": sid("attack-pattern", n), "spec_version": "2.1", "name": name,
        "external_references": [
            {"source_name": "capec", "external_id": "CAPEC-1"},
            {"source_name": "mitre-attack", "external_id": aid, "url": "https://example.invalid"},
        ],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases],
        "x_mitre_domains": list(domains), "x_mitre_is_subtechnique": "." in aid,
        "description": SENTINEL, "x_mitre_version": "1.0",
        "created": "2020-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
    }
    obj.update(extra)
    return obj


def rel(n: int, kind: str, src: int, tgt: int) -> dict[str, Any]:
    return {
        "type": "relationship", "id": sid("relationship", n), "spec_version": "2.1", "relationship_type": kind,
        "source_ref": sid("attack-pattern", src), "target_ref": sid("attack-pattern", tgt), "description": SENTINEL,
    }


def base_document() -> dict[str, Any]:
    objs: list[dict[str, Any]] = [
        {"type": "x-mitre-collection", "id": sid("x-mitre-collection", 1), "spec_version": "2.1", "name": "Enterprise ATT&CK",
         "x_mitre_version": "20.1", "x_mitre_attack_spec_version": "3.3.0"},
        {"type": "identity", "id": sid("identity", 2), "spec_version": "2.1", "name": "The MITRE Corporation"},
        tactic(10, "TA0002", "Execution", "execution"),
        tactic(11, "TA0005", "Stealth", "stealth"),
        tactic(12, "TA0112", "Defense Impairment", "defense-impairment"),
        technique(100, "T1059", "Command and Scripting Interpreter", ("execution",)),
        technique(101, "T1059.001", "PowerShell", ("execution",)),
        technique(102, "T1070.001", "Clear Windows Event Logs", ("stealth",), revoked=True),
        technique(103, "T1685", "Disable or Modify Tools", ("defense-impairment",)),
        technique(104, "T1685.005", "Clear Windows Event Logs", ("defense-impairment",)),
        technique(105, "T1043", "Commonly Used Port", ("execution",), x_mitre_deprecated=True),
        technique(106, "T1562", "Impair Defenses", ("stealth",), revoked=True),
        technique(107, "T1562.001", "Disable or Modify Tools", ("stealth",), revoked=True),
        technique(108, "T1562.003", "Impair Command History Logging", ("stealth",), revoked=True),
        technique(109, "T1690", "Prevent Command History Logging", ("defense-impairment",)),
        technique(110, "T1404", "Mobile Only Technique", ("execution",), domains=("mobile-attack",)),
        technique(111, "T1111", "Orphan Revoked", ("stealth",), revoked=True),
        {"type": "attack-pattern", "id": sid("attack-pattern", 112), "spec_version": "2.1", "name": "Non ATT&CK pattern",
         "external_references": [{"source_name": "capec", "external_id": "CAPEC-9"}]},
        rel(200, "subtechnique-of", 101, 100),
        rel(201, "subtechnique-of", 104, 103),
        rel(202, "revoked-by", 102, 104),
        rel(203, "revoked-by", 106, 103),
        rel(204, "revoked-by", 107, 103),
        rel(205, "revoked-by", 108, 109),
        rel(206, "revoked-by", 108, 104),
        {"type": "relationship", "id": sid("relationship", 207), "spec_version": "2.1", "relationship_type": "uses",
         "source_ref": sid("attack-pattern", 100), "target_ref": sid("attack-pattern", 101)},
    ]
    return {"type": "bundle", "id": "bundle--" + "0" * 8 + "-0000-4000-8000-" + "0" * 12, "objects": objs}


def pin_for(doc_bytes: bytes, version: str = "20.1", size: Optional[int] = None) -> PinnedRelease:
    return PinnedRelease(release_version=version, sha256=hashlib.sha256(doc_bytes).hexdigest().upper(), domain=ENT,
                         collection_name="Enterprise ATT&CK", size_bytes=size)


def write_doc(tmp_path: Path, doc: dict[str, Any], name: str = "enterprise-test.json") -> tuple[Path, PinnedRelease]:
    data = json.dumps(doc).encode("utf-8")
    p = tmp_path / name
    p.write_bytes(data)
    return p, pin_for(data)


def mem(doc: dict[str, Any], **kw: Any):
    return catalogue_from_document(doc, pin_for(b"x"), sha256="0" * 64, size_bytes=1, **kw)


def code_of(call) -> ErrorCode:
    with pytest.raises(AttackReferenceError) as ei:
        call()
    return ei.value.code


def objects_of(doc: dict[str, Any], aid: str) -> dict[str, Any]:
    for o in doc["objects"]:
        for r in o.get("external_references", []):
            if r.get("external_id") == aid and r.get("source_name") == "mitre-attack":
                return o
    raise KeyError(aid)


# ── 8.1 integrity and version ───────────────────────────────────────────────────────────────────────────────────
def test_pinned_file_is_accepted_and_counted(tmp_path):
    p, pin = write_doc(tmp_path, base_document())
    cat = load_catalogue(p, pin)
    m = cat.meta
    assert (m.release_version, m.domain, m.technique_count, m.tactic_count) == ("20.1", ENT, 11, 3)
    assert m.revoked_count == 5 and m.deprecated_count == 1
    assert m.excluded_other_domain_technique_count == 1 and m.skipped_attack_patterns_without_attack_id == 1
    assert m.sha256 == pin.sha256 and m.object_count == len(base_document()["objects"])


def test_wrong_release_version_refused(tmp_path):
    doc = base_document()
    doc["objects"][0]["x_mitre_version"] = "19.0"
    p, pin = write_doc(tmp_path, doc)
    assert code_of(lambda: load_catalogue(p, pin)) == ErrorCode.VERSION_MISMATCH


def test_hash_mismatch_refused_before_parsing(tmp_path):
    p = tmp_path / "x.json"
    p.write_bytes(b"this is not json at all")
    pin = pin_for(b"some other content")
    assert code_of(lambda: load_catalogue(p, pin)) == ErrorCode.HASH_MISMATCH     # not MALFORMED_JSON: hash came first


def test_size_mismatch_refused(tmp_path):
    p, pin = write_doc(tmp_path, base_document())
    wrong = PinnedRelease(pin.release_version, pin.sha256, pin.domain, pin.collection_name, size_bytes=1)
    assert code_of(lambda: load_catalogue(p, wrong)) == ErrorCode.SIZE_MISMATCH


def test_missing_path_and_directory(tmp_path):
    pin = pin_for(b"x")
    assert code_of(lambda: load_catalogue(tmp_path / "absent.json", pin)) == ErrorCode.PATH_MISSING
    assert code_of(lambda: load_catalogue(tmp_path, pin)) == ErrorCode.NOT_A_FILE


def test_empty_and_truncated_files_rejected(tmp_path):
    empty = tmp_path / "e.json"
    empty.write_bytes(b"")
    assert code_of(lambda: load_catalogue(empty, pin_for(b"x"))) == ErrorCode.EMPTY_FILE
    full = json.dumps(base_document()).encode()
    trunc = tmp_path / "t.json"
    trunc.write_bytes(full[: len(full) // 2])
    assert code_of(lambda: load_catalogue(trunc, pin_for(full))) == ErrorCode.HASH_MISMATCH          # pinned hash is of the full file
    assert code_of(lambda: load_catalogue(trunc, pin_for(full[: len(full) // 2]))) == ErrorCode.MALFORMED_JSON  # even if re-pinned


def test_malformed_json_and_nonfinite_constants_rejected(tmp_path):
    for payload in (b"{not json", b'{"type": "bundle", "objects": [NaN]}'):
        p = tmp_path / "m.json"
        p.write_bytes(payload)
        assert code_of(lambda: load_catalogue(p, pin_for(payload))) == ErrorCode.MALFORMED_JSON


def test_size_bounds_enforced(tmp_path):
    p, pin = write_doc(tmp_path, base_document())
    assert code_of(lambda: load_catalogue(p, pin, max_bytes=10)) == ErrorCode.TOO_LARGE
    assert code_of(lambda: mem(base_document(), max_objects=5)) == ErrorCode.TOO_MANY_OBJECTS


@pytest.mark.parametrize("mutate,expected", [
    (lambda d: d.update(type="grouping"), ErrorCode.BAD_COLLECTION_TYPE),
    (lambda d: d.pop("objects"), ErrorCode.MISSING_OBJECTS),
    (lambda d: d.update(objects={"a": 1}), ErrorCode.MISSING_OBJECTS),
    (lambda d: d["objects"].append("not-an-object"), ErrorCode.NON_OBJECT_ENTRY),
    (lambda d: d["objects"].append({"type": "malware"}), ErrorCode.INVALID_FIELD),
    (lambda d: d["objects"].pop(0), ErrorCode.COLLECTION_MISSING),
    (lambda d: d["objects"].append(copy.deepcopy(d["objects"][0]) | {"id": sid("x-mitre-collection", 99)}), ErrorCode.MULTIPLE_COLLECTIONS),
    (lambda d: d["objects"][0].update(name="Mobile ATT&CK"), ErrorCode.DOMAIN_MISMATCH),
])
def test_collection_structure_rejected(mutate, expected):
    doc = base_document()
    mutate(doc)
    assert code_of(lambda: mem(doc)) == expected


def test_top_level_non_object_rejected():
    assert code_of(lambda: mem([])) == ErrorCode.BAD_COLLECTION_TYPE


# ── 8.2 object projection ───────────────────────────────────────────────────────────────────────────────────────
def test_valid_technique_and_tactic_projected():
    cat = mem(base_document())
    t = cat.get_technique("T1059.001")
    assert t is not None and (t.name, t.is_subtechnique, t.parent_id, t.tactic_ids) == ("PowerShell", True, "T1059", ("TA0002",))
    ta = cat.lookup_tactic("TA0005")
    assert ta is not None and (ta.name, ta.shortname) == ("Stealth", "stealth")
    assert cat.tactic_by_shortname("defense-impairment").tactic_id == "TA0112"
    assert cat.tactic_by_shortname("defense-evasion") is None          # the legacy slug is not a current tactic


def test_multiple_and_non_attack_external_references_handled():
    doc = base_document()
    assert mem(doc).get_technique("T1059") is not None                  # capec reference alongside the ATT&CK one
    assert mem(doc).meta.skipped_attack_patterns_without_attack_id == 1  # pattern with only a non-ATT&CK reference


def test_duplicate_stix_id_rejected():
    doc = base_document()
    doc["objects"].append(copy.deepcopy(objects_of(doc, "T1059")))
    assert code_of(lambda: mem(doc)) == ErrorCode.DUPLICATE_STIX_ID


def test_duplicate_attack_id_rejected_never_silently_chosen():
    doc = base_document()
    doc["objects"].append(technique(300, "T1059", "A Second Object With The Same Id"))
    assert code_of(lambda: mem(doc)) == ErrorCode.DUPLICATE_ATTACK_ID


def test_duplicate_tactic_identity_rejected():
    doc = base_document()
    doc["objects"].append(tactic(301, "TA0002", "Execution Again", "execution-again"))
    assert code_of(lambda: mem(doc)) == ErrorCode.DUPLICATE_ATTACK_ID


def test_wrong_domain_object_excluded_but_reported_as_wrong_domain():
    cat = mem(base_document())
    assert cat.get_technique("T1404") is None
    assert cat.lookup_technique("T1404").status == ReferenceStatus.WRONG_DOMAIN


@pytest.mark.parametrize("mutate", [
    lambda o: o.pop("name"),
    lambda o: o.update(name=""),
    lambda o: o.update(name="x" * 300),
    lambda o: o.update(spec_version="2.0"),
    lambda o: o.update(revoked="true"),                      # strict: a string is not a boolean
    lambda o: o.update(x_mitre_domains="enterprise-attack"),
    lambda o: o.pop("x_mitre_domains"),
    lambda o: o.update(modified="yesterday"),
    lambda o: o.update(external_references="nope"),
])
def test_missing_or_invalid_required_fields_rejected(mutate):
    doc = base_document()
    mutate(objects_of(doc, "T1059"))
    assert code_of(lambda: mem(doc)) == ErrorCode.INVALID_FIELD


@pytest.mark.parametrize("bad_id", ["T12", "t1059", "T1059.1", "T1059.0011", " T1059", "TA0002", "T1059,T1070"])
def test_malformed_attack_ids_rejected_not_coerced(bad_id):
    doc = base_document()
    objects_of(doc, "T1059")["external_references"][1]["external_id"] = bad_id
    assert code_of(lambda: mem(doc)) == ErrorCode.INVALID_FIELD


def test_ambiguous_attack_ids_on_one_object_rejected():
    doc = base_document()
    objects_of(doc, "T1059")["external_references"].append({"source_name": "mitre-attack", "external_id": "T1060"})
    assert code_of(lambda: mem(doc)) == ErrorCode.INVALID_FIELD


def test_optional_fields_absent_or_null_handled():
    doc = base_document()
    o = objects_of(doc, "T1059")
    for k in ("revoked", "x_mitre_deprecated", "x_mitre_version", "created", "modified", "kill_chain_phases"):
        o.pop(k, None)
    o["x_mitre_is_subtechnique"] = None
    o2 = objects_of(doc, "T1685")
    o2.update(revoked=None, x_mitre_deprecated=None, created=None)
    cat = mem(doc)
    t = cat.get_technique("T1059")
    assert (t.revoked, t.deprecated, t.tactic_ids, t.version, t.created) == (False, False, (), None, None)
    assert cat.get_technique("T1685").revoked is False


def test_subtechnique_flag_must_match_id_shape():
    doc = base_document()
    objects_of(doc, "T1059.001")["x_mitre_is_subtechnique"] = False
    assert code_of(lambda: mem(doc)) == ErrorCode.INVALID_FIELD


# ── 8.3 lifecycle and relationships ─────────────────────────────────────────────────────────────────────────────
def test_lifecycle_states_are_distinguishable():
    cat = mem(base_document())
    assert cat.lookup_technique("T1059").status == ReferenceStatus.CURRENT
    assert cat.lookup_technique("T1070.001").status == ReferenceStatus.REVOKED
    assert cat.lookup_technique("T1043").status == ReferenceStatus.DEPRECATED
    assert cat.lookup_technique("T9999").status == ReferenceStatus.UNKNOWN
    doc = base_document()
    objects_of(doc, "T1111")["x_mitre_deprecated"] = True
    assert mem(doc).lookup_technique("T1111").status == ReferenceStatus.REVOKED_AND_DEPRECATED


@pytest.mark.parametrize("query", ["T12", "t1059", " T1059", "T1059 ", "T1059\n", "", None, 1059, "TA0002"])
def test_invalid_syntax_lookups_are_never_coerced(query):
    res = mem(base_document()).lookup_technique(query)
    assert res.status == ReferenceStatus.INVALID_SYNTAX and res.record is None


def test_revoked_by_direction_and_one_to_one_successor():
    cat = mem(base_document())
    old = cat.get_technique("T1070.001")
    assert old.replaced_by == ("T1685.005",) and old.revoked
    new = cat.get_technique("T1685.005")
    assert new.replaced_by == () and not new.revoked                       # the pointer is not reversed
    assert [s.attack_id for s in cat.successors_of("T1070.001")] == ["T1685.005"]


def test_many_to_one_successor_preserved_for_every_old_id():
    cat = mem(base_document())
    assert cat.get_technique("T1562").replaced_by == ("T1685",)
    assert cat.get_technique("T1562.001").replaced_by == ("T1685",)


def test_multiple_replacement_targets_all_preserved():
    cat = mem(base_document())
    assert cat.get_technique("T1562.003").replaced_by == ("T1685.005", "T1690")


def test_no_explicit_successor_means_none_is_inferred():
    cat = mem(base_document())
    t = cat.get_technique("T1111")
    assert t.revoked and t.replaced_by == () and cat.successors_of("T1111") == ()


def test_missing_relationship_target_is_unresolved_not_dropped_silently():
    doc = base_document()
    doc["objects"].append(rel(310, "revoked-by", 111, 99999))             # target object does not exist
    cat = mem(doc)
    t = cat.get_technique("T1111")
    assert t.replaced_by == () and t.unresolved_successor_refs == (sid("attack-pattern", 99999),)
    assert cat.meta.unresolved_replacement_count == 1


def test_relationship_with_unknown_source_is_a_warning_not_a_crash():
    doc = base_document()
    doc["objects"].append(rel(311, "revoked-by", 88888, 104))
    assert any("source outside the Enterprise technique set" in w for w in mem(doc).warnings)


def test_revoked_by_on_a_live_object_is_a_warning():
    doc = base_document()
    doc["objects"].append(rel(312, "revoked-by", 100, 103))
    assert any("not marked revoked" in w for w in mem(doc).warnings)


def test_parent_and_sub_technique_links():
    cat = mem(base_document())
    assert cat.parent_of("T1059.001").attack_id == "T1059"
    assert cat.children_of("T1685") == ("T1685.005",)
    assert cat.get_technique("T1059").parent_id is None


def test_revoked_subtechnique_without_parent_is_allowed_but_live_one_is_rejected():
    cat = mem(base_document())
    assert cat.get_technique("T1562.001").parent_id is None               # revoked sub-technique: no parent link
    doc = base_document()
    doc["objects"] = [o for o in doc["objects"] if o["id"] != sid("relationship", 200)]
    assert code_of(lambda: mem(doc)) == ErrorCode.SUBTECHNIQUE_WITHOUT_PARENT


def test_inconsistent_parent_relationships_rejected():
    doc = base_document()
    doc["objects"].append(rel(320, "subtechnique-of", 101, 103))           # second parent
    assert code_of(lambda: mem(doc)) == ErrorCode.INCONSISTENT_RELATIONSHIP
    doc = base_document()
    doc["objects"] = [o for o in doc["objects"] if o["id"] != sid("relationship", 200)]
    doc["objects"].append(rel(321, "subtechnique-of", 101, 103))           # parent id prefix does not match
    assert code_of(lambda: mem(doc)) == ErrorCode.INCONSISTENT_RELATIONSHIP


def test_unresolved_tactic_reference_rejected_and_other_kill_chains_ignored():
    doc = base_document()
    objects_of(doc, "T1059")["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": "no-such-tactic"}]
    assert code_of(lambda: mem(doc)) == ErrorCode.UNRESOLVED_TACTIC
    doc = base_document()
    objects_of(doc, "T1059")["kill_chain_phases"] = [{"kill_chain_name": "other-chain", "phase_name": "whatever"}]
    assert mem(doc).get_technique("T1059").tactic_ids == ()


def test_tactic_ids_are_sorted_and_deduplicated():
    doc = base_document()
    objects_of(doc, "T1059")["kill_chain_phases"] = [
        {"kill_chain_name": "mitre-attack", "phase_name": p} for p in ("stealth", "execution", "stealth")]
    assert mem(doc).get_technique("T1059").tactic_ids == ("TA0002", "TA0005")


# ── 8.4 data minimisation and boundaries ────────────────────────────────────────────────────────────────────────
def test_descriptions_are_not_retained_anywhere():
    cat = mem(base_document())
    assert "description" not in {f for f in type(cat.get_technique("T1059")).model_fields}
    blobs = [cat.get_technique("T1059").model_dump_json(), cat.lookup_tactic("TA0002").model_dump_json(),
             cat.meta.model_dump_json(), repr(cat.techniques()), repr(cat.tactics()), repr(cat.warnings)]
    assert not any(SENTINEL in b for b in blobs)
    assert not hasattr(cat, "__dict__")                                    # slots only: no stray raw-object attributes


def test_load_is_deterministic():
    a, b = mem(base_document()), mem(base_document())
    assert a.techniques() == b.techniques() and a.tactics() == b.tactics() and a.meta == b.meta
    assert a.technique_ids() == tuple(sorted(a.technique_ids()))


def test_no_network_dns_or_socket_activity_during_load(tmp_path, monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("network activity attempted")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, refuse)
    p, pin = write_doc(tmp_path, base_document())
    assert load_catalogue(p, pin).meta.technique_count == 11


def test_source_file_is_never_rewritten(tmp_path):
    p, pin = write_doc(tmp_path, base_document())
    before = (p.read_bytes(), p.stat().st_mtime_ns)
    load_catalogue(p, pin)
    try_load_catalogue(p, pin)
    assert (p.read_bytes(), p.stat().st_mtime_ns) == before
    assert sorted(x.name for x in tmp_path.iterdir()) == [p.name]          # no cache or export was written


def test_unavailable_catalogue_is_an_explicit_state_not_an_exception(tmp_path):
    res = try_load_catalogue(tmp_path / "absent.json", pin_for(b"x"))
    assert res.available is False and res.catalogue is None and res.error_code == ErrorCode.PATH_MISSING
    ok = try_load_catalogue(*write_doc(tmp_path, base_document()))
    assert ok.available and ok.error_code is None


def test_optional_catalogue_failure_does_not_affect_the_deterministic_path(tmp_path):
    from app.modules.correlation.mitre import map_techniques

    assert try_load_catalogue(tmp_path / "absent.json", pin_for(b"x")).available is False
    assert map_techniques([]) == []                                        # deterministic ATT&CK rules run unchanged


def test_error_messages_do_not_echo_untrusted_values():
    doc = base_document()
    objects_of(doc, "T1059")["name"] = ""
    objects_of(doc, "T1059")["external_references"][0]["external_id"] = "INJECTED-<script>-VALUE"
    with pytest.raises(AttackReferenceError) as ei:
        mem(doc)
    assert "INJECTED" not in str(ei.value) and "<script>" not in str(ei.value)


# ── 8.5 project compatibility ───────────────────────────────────────────────────────────────────────────────────
_ALLOWED_IMPORTS = {"__future__", "hashlib", "json", "re", "dataclasses", "enum", "pathlib", "typing", "pydantic", "app", "threading"}


def _package_files() -> list[Path]:
    return sorted((BACKEND / "app" / "modules" / "attack_reference").glob("*.py"))


def test_module_imports_only_stdlib_pydantic_and_itself():
    seen: set[str] = set()
    for f in _package_files():
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                seen |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                seen.add(node.module.split(".")[0])
    assert seen <= _ALLOWED_IMPORTS, sorted(seen - _ALLOWED_IMPORTS)       # no network, DB, subprocess or STIX library


#: Files that may mention the package: the deterministic output validator and its policy module (types and an injected,
#: optional catalogue), the single composition module that owns the lazy provider, and the two live call sites that pass
#: an ``attack_reference`` argument down to the validator. Nothing may LOAD the file except the package's own provider.
_ALLOWED_REFERENCERS = {
    "app/modules/ai/guardrails/validator.py",
    "app/modules/ai/guardrails/attack_policy.py",
    "app/services/attack_reference_service.py",
    "app/services/case_service.py",
    "app/services/multisource_investigation_service.py",
    "app/modules/correlation/workflow.py",
}


def test_loader_is_not_wired_into_the_application():
    own = BACKEND / "app" / "modules" / "attack_reference"
    offenders, loaders = [], []
    for p in (BACKEND / "app").rglob("*.py"):
        if own in p.parents:
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        rel_path = p.relative_to(BACKEND).as_posix()
        if "attack_reference" in text and rel_path not in _ALLOWED_REFERENCERS:
            offenders.append(rel_path)
        if re.search(r"\b(try_)?load_catalogue\s*\(", text):
            loaders.append(rel_path)
    assert offenders == []                                                  # incl. main.py, services, API, adapters
    assert loaders == []                                                    # no application code ever loads the dataset


def test_existing_pinned_pydantic_is_used():
    pin = re.search(r"^pydantic==(\S+)\s*$", (REPO / "requirements.txt").read_text(encoding="utf-8"), re.M)
    assert pin is not None and pin.group(1) == pydantic.VERSION


def test_existing_rule_tables_are_untouched_by_the_loader():
    from app.modules.correlation.mitre import RULES as CORR
    from app.modules.evidence_domains.domain_attack import RULES as DOMAIN

    assert len(CORR) == 6 and len(DOMAIN) == 7                              # shape of the two existing tables (report-only task)


def test_revoked_ids_stay_readable_and_are_never_replaced_automatically():
    cat = mem(base_document())
    rec = cat.get_technique("T1070.001")
    assert rec is not None and rec.attack_id == "T1070.001" and rec.name == "Clear Windows Event Logs"
    assert cat.lookup_technique("T1070.001").status == ReferenceStatus.REVOKED
    assert cat.lookup_technique("T1070.001").record.attack_id == "T1070.001"  # lookup returns the old id, not the successor
