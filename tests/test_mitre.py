"""MITRE ATT&CK mapping tests: table validity, rule mapping, coverage."""

from __future__ import annotations

import io
import json
import re
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
from conftest import event_dict

from huntforge.cli.main import main as cli_main
from huntforge.core import plugins as plugins_mod
from huntforge.detections import DetectionEngine, list_rules
from huntforge.mitre import KNOWN_IDS, TABLE, coverage_from_findings, rule_techniques
from huntforge.mitre.mapping import validate_mapping
from huntforge.mitre.table import load_table


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_main(argv)
    return code, out.getvalue(), err.getvalue()


def run_json(argv: list[str]) -> tuple[int, dict]:
    code, out, _ = run([*argv, "--json"])
    return code, json.loads(out)


# ---------------------------------------------------------------------------
# Technique table
# ---------------------------------------------------------------------------

_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_table_loads_with_metadata() -> None:
    assert len(TABLE.techniques) >= 20
    assert TABLE.attack_snapshot
    assert TABLE.data_version == "0.6.0"
    assert "subset" in TABLE.note.lower()


def test_technique_ids_valid_and_unique() -> None:
    ids = [t.id for t in TABLE.techniques]
    assert len(ids) == len(set(ids))
    for tid in ids:
        assert _ID_RE.match(tid), tid


def test_techniques_have_required_fields() -> None:
    for technique in TABLE.techniques:
        assert technique.name.strip()
        assert technique.tactics
        assert all(t.strip() for t in technique.tactics)
        assert technique.description.strip()
        assert isinstance(technique.huntforge_sources, list)


def test_table_lookup_case_insensitive() -> None:
    assert TABLE.get("t1059.001").name == "PowerShell"
    assert TABLE.get("T1059.001").name == "PowerShell"
    with pytest.raises(KeyError):
        TABLE.get("T9999")


def test_table_reload_matches_singleton() -> None:
    assert [t.id for t in load_table().techniques] == TABLE.ids()


def test_unobservable_techniques_documented_as_gaps() -> None:
    unobservable = [t for t in TABLE.techniques if not t.huntforge_sources]
    assert unobservable  # e.g. T1003.001 (LSASS), T1070.001
    assert any(t.id == "T1003.001" for t in unobservable)


def test_plugin_registered() -> None:
    info = plugins_mod.get_registry().get("mitre")
    assert info.version == "0.9.0"
    assert "mitre" in info.commands


# ---------------------------------------------------------------------------
# Rule -> technique mapping
# ---------------------------------------------------------------------------


def test_every_rule_mapped_to_known_technique() -> None:
    assert validate_mapping() == []
    mapping = rule_techniques()
    assert len(mapping) == len(list_rules()) == 10
    for rule_id, techniques in mapping.items():
        assert techniques, rule_id
        for tid in techniques:
            assert tid in KNOWN_IDS, (rule_id, tid)


def test_known_rule_mappings() -> None:
    mapping = rule_techniques()
    assert mapping["HF-DET-ENCPSH"] == ["T1059.001"]
    assert mapping["HF-DET-DLPSH"] == ["T1105"]
    assert mapping["HF-DET-RUNKEY"] == ["T1547.001"]
    assert mapping["HF-DET-BRUTE"] == ["T1110"]
    assert mapping["HF-DET-ADMINHOST"] == ["T1078"]


def test_engine_copies_mapping_onto_findings() -> None:
    stored = dict(event_dict())  # sysmon 1, powershell -enc
    stored["id"] = 1
    findings = DetectionEngine([stored]).run()
    enc = [f for f in findings if f.rule_id == "HF-DET-ENCPSH"]
    assert enc and enc[0].mitre == ["T1059.001"]
    assert enc[0].provenance == "huntforge.detections"
    as_dict = enc[0].to_dict()
    assert as_dict["mitre"] == ["T1059.001"]
    assert as_dict["provenance"] == "huntforge.detections"


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


def _stored_finding(uid: str, rule_id: str, mitre: list[str]) -> dict:
    return {
        "finding_uid": uid,
        "rule_id": rule_id,
        "rule_version": "0.5.0",
        "severity": "high",
        "title": "t",
        "confidence": 80,
        "mitre": mitre,
        "provenance": "huntforge.detections",
    }


def test_coverage_from_findings() -> None:
    findings = [
        _stored_finding("HF-0001", "HF-DET-ENCPSH", ["T1059.001"]),
        _stored_finding("HF-0002", "HF-DET-ENCPSH", ["T1059.001"]),
        _stored_finding("HF-0003", "HF-DET-RUNKEY", ["T1547.001"]),
    ]
    coverage = coverage_from_findings(findings)
    assert coverage["covered_count"] == 2
    by_id = {e["technique_id"]: e for e in coverage["covered"]}
    assert by_id["T1059.001"]["finding_count"] == 2
    assert by_id["T1059.001"]["rules"] == {"HF-DET-ENCPSH": 2}
    assert coverage["unknown_technique_ids"] == []


def test_coverage_unknown_technique_reported() -> None:
    findings = [_stored_finding("HF-0001", "X", ["T9999"])]
    coverage = coverage_from_findings(findings)
    assert coverage["covered_count"] == 0
    assert coverage["unknown_technique_ids"] == ["T9999"]
    assert coverage["unknown_references"] == {"T9999": ["HF-0001"]}


def test_coverage_empty() -> None:
    coverage = coverage_from_findings([])
    assert coverage["covered"] == []
    assert coverage["covered_count"] == 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_mitre_techniques(isolated_state: Path) -> None:
    code, out, _ = run(["mitre", "techniques"])
    assert code == 0
    assert "T1059.001" in out
    assert "PowerShell" in out


def test_cli_mitre_techniques_json(isolated_state: Path) -> None:
    code, data = run_json(["mitre", "techniques"])
    assert code == 0
    assert data["data"]["technique_count"] >= 20
    assert data["data"]["techniques"][0]["id"].startswith("T")


def test_cli_mitre_needs_case_or_techniques(isolated_state: Path) -> None:
    code, _, err = run(["mitre"])
    assert code == 2
    assert "techniques" in err


def test_cli_mitre_coverage(isolated_state: Path) -> None:
    assert run(["case", "create", "MITRE-1"])[0] == 0
    code, _, _ = run(
        ["ingest", "tests/fixtures/sysmon_intrusion.json", "--case", "MITRE-1"]
    )
    assert code == 0
    assert run(["detect", "--case", "MITRE-1"])[0] == 1
    code, data = run_json(["mitre", "--case", "MITRE-1"])
    assert code == 0
    payload = data["data"]
    assert payload["stored_findings"] > 0
    covered = {e["technique_id"] for e in payload["covered"]}
    assert "T1059.001" in covered  # encoded powershell fired
    assert payload["gaps"]
    assert "T1003.001" in payload["unobservable"]
    # Human output shows technique names and gaps.
    code, out, _ = run(["mitre", "--case", "MITRE-1"])
    assert code == 0
    assert "T1059.001 PowerShell" in out
    assert "gaps" in out


def test_cli_mitre_no_findings_hint(isolated_state: Path) -> None:
    assert run(["case", "create", "MITRE-2"])[0] == 0
    code, out, _ = run(["mitre", "--case", "MITRE-2"])
    assert code == 0
    assert "0 of" in out
    assert "huntforge detect" in out


def test_cli_mitre_unknown_case(isolated_state: Path) -> None:
    code, _, err = run(["mitre", "--case", "NOPE"])
    assert code == 2
