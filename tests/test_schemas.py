"""Schema conformance: every command's --json output validates.

The v1.0 stability promise is only as strong as its enforcement: this
suite runs each command against a fixture case and checks the result
with ``huntforge.schemas.validate()``. Any drift between the shipped
JSON and ``docs/SCHEMAS.md`` fails the build here, not in a consumer's
pipeline.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
from conftest import build_hive

from huntforge import __version__, schemas
from huntforge.cli.main import main

FIXTURES = Path(__file__).parent / "fixtures"


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def run_json(argv: list[str]) -> tuple[int, dict[str, Any]]:
    code, out, _ = run([*argv, "--json"])
    return code, json.loads(out)


def assert_envelope(payload: dict[str, Any], command: str) -> None:
    errors = schemas.validate(payload, "envelope")
    assert not errors, f"envelope errors for {command}: {errors[:5]}"
    assert payload["tool"] == "huntforge"
    assert payload["version"] == __version__
    assert payload["command"] == command


def assert_records(records: list[dict[str, Any]], schema: str, label: str) -> None:
    for i, record in enumerate(records):
        errors = schemas.validate(record, schema)
        assert not errors, f"{label}[{i}] errors: {errors[:5]}"


@pytest.fixture()
def rich_case(isolated_state: Path) -> Iterator[str]:
    """Case with events from four sources, findings, and a note."""
    case_id = "SCHEMA-DEMO"
    assert run(["case", "create", case_id])[0] == 0
    for fixture in (
        "sysmon_intrusion.xml",
        "security_events.json",
        "powershell_events.xml",
        "intrusion_task.xml",
    ):
        code, _out, err = run(["ingest", str(FIXTURES / fixture), "--case", case_id])
        assert code == 0, err
    run(["notes", "--case", case_id, "--add", "schema conformance note"])
    run(["detect", "--case", case_id])  # exit 1: findings are the product
    yield case_id


# --- envelope + command contracts ----------------------------------------


def test_case_commands(rich_case: str) -> None:
    code, payload = run_json(["case", "show", rich_case])
    assert code == 0
    assert_envelope(payload, "case show")
    assert not schemas.validate(payload["data"], "case")
    assert payload["data"]["evidence_files"]

    code, payload = run_json(["case", "list"])
    assert code == 0
    assert_envelope(payload, "case list")
    assert payload["data"]["count"] >= 1
    assert_records(payload["data"]["cases"], "case", "case list")


def test_ingest_contract(rich_case: str, tmp_path: Path) -> None:
    code, payload = run_json(
        ["ingest", str(FIXTURES / "sysmon_intrusion.json"), "--case", rich_case]
    )
    assert code == 0
    assert_envelope(payload, "ingest")
    data = payload["data"]
    for key in (
        "files_found",
        "registered",
        "parsed_events",
        "parsed_by_source",
        "evidence",
    ):
        assert key in data, f"ingest data missing {key}"


def test_events_contract(rich_case: str) -> None:
    code, payload = run_json(["events", "--case", rich_case])
    assert code == 0
    assert_envelope(payload, "events")
    assert payload["data"]["count"] == len(payload["events"]) > 0
    assert_records(payload["events"], "event", "events")

    # Filters keep the contract.
    code, payload = run_json(
        ["events", "--case", rich_case, "--process", "powershell.exe"]
    )
    assert code == 0
    assert_envelope(payload, "events")
    assert_records(payload["events"], "event", "events filtered")


def test_audit_contract(rich_case: str) -> None:
    code, payload = run_json(["audit", "--case", rich_case])
    assert code == 0
    assert_envelope(payload, "audit")
    assert payload["data"]["count"] == len(payload["data"]["entries"]) > 0
    assert_records(payload["data"]["entries"], "audit_entry", "audit")


def test_registry_contract(isolated_state: Path, tmp_path: Path) -> None:
    hive = tmp_path / "t.dat"
    hive.write_bytes(build_hive())
    code, payload = run_json(["registry", str(hive), "ControlSet001"])
    assert code == 0
    assert_envelope(payload, "registry")
    assert not schemas.validate(payload["data"], "registry_view")


def test_timeline_contract(rich_case: str) -> None:
    code, payload = run_json(["timeline", "--case", rich_case])
    assert code == 0
    assert_envelope(payload, "timeline")
    data = payload["data"]
    assert data["coverage"]["timed_count"] == len(data["timed"]) > 0
    # Timed items carry the event core fields.
    for item in data["timed"]:
        for key in ("id", "timestamp", "source", "event_id", "summary"):
            assert key in item, f"timeline item missing {key}"


def test_lineage_contract(rich_case: str) -> None:
    code, payload = run_json(["lineage", "--case", rich_case])
    assert code == 0
    assert_envelope(payload, "lineage")
    data = payload["data"]
    assert data["instance_count"] > 0
    assert isinstance(data["trees"], list)


def test_entities_contract(rich_case: str) -> None:
    code, payload = run_json(["entities", "--case", rich_case])
    assert code == 0
    assert_envelope(payload, "entities")
    assert payload["data"]["count"] == len(payload["data"]["entities"]) > 0
    assert_records(payload["data"]["entities"], "entity", "entities")


def test_detect_contract(rich_case: str) -> None:
    code, payload = run_json(["detect", "--case", rich_case])
    assert code == 1  # findings are the product
    assert_envelope(payload, "detect")
    assert payload["status"] == "warning"
    assert len(payload["findings"]) > 0
    assert_records(payload["findings"], "finding", "detect")
    data = payload["data"]
    for key in ("count", "by_severity", "rules_run", "rules_without_data"):
        assert key in data, f"detect data missing {key}"


def test_rules_contract(isolated_state: Path) -> None:
    code, payload = run_json(["rules", "list"])
    assert code == 0
    assert_envelope(payload, "rules list")
    assert payload["data"]["count"] == len(payload["data"]["rules"]) > 0
    assert_records(payload["data"]["rules"], "rule", "rules")


def test_mitre_contracts(rich_case: str, isolated_state: Path) -> None:
    code, payload = run_json(["mitre", "techniques"])
    assert code == 0
    assert_envelope(payload, "mitre techniques")
    assert payload["data"]["technique_count"] > 0
    assert_records(payload["data"]["techniques"], "technique", "mitre techniques")

    code, payload = run_json(["mitre", "--case", rich_case])
    assert code == 0
    assert_envelope(payload, "mitre")
    data = payload["data"]
    for key in ("covered", "gaps", "unobservable", "covered_count"):
        assert key in data, f"mitre data missing {key}"
    assert data["stored_findings"] > 0


def test_sigma_contracts(rich_case: str, isolated_state: Path) -> None:
    code, payload = run_json(["sigma", "list"])
    assert code == 0
    assert_envelope(payload, "sigma list")
    assert_records(payload["data"]["rules"], "sigma_rule", "sigma list")

    rule = FIXTURES / ".." / ".." / "src" / "huntforge" / "sigma" / "samples"
    sample = rule / "encoded_powershell.json"
    code, payload = run_json(
        ["sigma", "run", "--rule", str(sample), "--case", rich_case]
    )
    assert code in (0, 1)
    assert_envelope(payload, "sigma run")
    assert_records(payload["findings"], "finding", "sigma run")


def test_correlate_contract(rich_case: str) -> None:
    code, payload = run_json(["correlate", "--case", rich_case])
    assert code == 0
    assert_envelope(payload, "correlate")
    data = payload["data"]
    assert data["cluster_count"] == len(data["clusters"]) > 0
    for cluster in data["clusters"]:
        errors = schemas.validate(cluster, "activity_cluster")
        assert not errors, f"cluster errors: {errors[:5]}"
        for linkage in cluster["linkages"]:
            errors = schemas.validate(linkage, "linkage")
            assert not errors, f"linkage errors: {errors[:5]}"
            assert linkage["label"] == "INFERRED"


def test_narrative_contract(rich_case: str) -> None:
    code, payload = run_json(["narrative", "--case", rich_case, "--cluster", "0"])
    assert code == 0
    assert_envelope(payload, "narrative")
    errors = schemas.validate(payload["data"], "narrative")
    assert not errors, f"narrative errors: {errors[:5]}"


def test_notes_contract(rich_case: str) -> None:
    code, payload = run_json(["notes", "--case", rich_case])
    assert code == 0
    assert_envelope(payload, "notes")
    assert payload["data"]["count"] == len(payload["data"]["notes"]) > 0
    assert_records(payload["data"]["notes"], "note", "notes")


def test_batch_contract(isolated_state: Path, tmp_path: Path) -> None:
    input_dir = tmp_path / "in"
    input_dir.mkdir()
    for fixture in ("sysmon_intrusion.xml", "security_events.json"):
        (input_dir / fixture).write_bytes((FIXTURES / fixture).read_bytes())
    out_dir = tmp_path / "out"
    code, payload = run_json(["batch", str(input_dir), "--output", str(out_dir)])
    assert code in (0, 1)
    assert_envelope(payload, "batch")
    errors = schemas.validate(payload["data"], "batch_summary")
    assert not errors, f"batch summary errors: {errors[:5]}"

    manifest = json.loads((out_dir / "batch-manifest.json").read_text())
    errors = schemas.validate(manifest, "batch_manifest")
    assert not errors, f"manifest errors: {errors[:5]}"
    summary_file = json.loads((out_dir / "batch-summary.json").read_text())
    errors = schemas.validate(summary_file, "batch_summary")
    assert not errors, f"summary file errors: {errors[:5]}"


def test_export_contract(rich_case: str, tmp_path: Path) -> None:
    for what, schema in (("events", "event"), ("findings", "finding")):
        target = tmp_path / f"{what}.jsonl"
        code, payload = run_json(
            ["export", "--case", rich_case, "--what", what, "--output", str(target)]
        )
        assert code in (0, 1), payload["summary"]
        assert_envelope(payload, "export")
        lines = [line for line in target.read_text().splitlines() if line.strip()]
        assert lines, f"no {what} exported"
        for line in lines:
            env = json.loads(line)
            errors = schemas.validate(env, "jsonl_envelope")
            assert not errors, f"jsonl envelope errors: {errors[:5]}"
            assert env["schema"] == f"huntforge/{what[:-1]}@1.0"
            errors = schemas.validate(env["record"], schema)
            assert not errors, f"jsonl {what} record errors: {errors[:5]}"


def test_report_contract(rich_case: str, tmp_path: Path) -> None:
    out_dir = tmp_path / "report"
    code, payload = run_json(
        ["report", "case", rich_case, "--output", str(out_dir), "--format", "json"]
    )
    assert code == 0
    assert_envelope(payload, "report case")
    assert set(payload["data"]["formats"]) == {"json"}
    report = json.loads((out_dir / f"{rich_case}.json").read_text())
    errors = schemas.validate(report, "report")
    assert not errors, f"report errors: {errors[:5]}"
    assert report["meta"]["report_schema_version"] == "huntforge/report@1.0"
    assert report["executive_summary"]["analyst_review_required"] is True


def test_schema_command(isolated_state: Path) -> None:
    code, payload = run_json(["schema"])
    assert code == 0
    assert_envelope(payload, "schema")
    assert payload["data"]["count"] == len(schemas.names()) > 0
    ids = {entry["$id"] for entry in payload["data"]["schemas"]}
    assert "huntforge/event@1.0" in ids

    code, payload = run_json(["schema", "finding"])
    assert code == 0
    assert_envelope(payload, "schema")
    assert payload["data"]["schema"]["$id"] == "huntforge/finding@1.0"

    code, _out, _err = run(["schema", "bogus"])
    assert code == 2  # usage error, but the envelope is still valid JSON
    _, payload = run_json(["schema", "bogus"])
    assert payload["status"] == "error"
    assert_envelope(payload, "schema")


def test_error_envelope_still_valid(isolated_state: Path) -> None:
    code, payload = run_json(["events", "--case", "NO-SUCH-CASE"])
    assert code == 2
    assert payload["status"] == "error"
    assert_envelope(payload, "events")


# --- validator unit tests -------------------------------------------------


def test_validate_accepts_valid_event() -> None:
    record = {
        "id": 1,
        "source": "sysmon",
        "event_id": "1",
        "timestamp": "2026-10-02T08:58:00Z",
        "timestamp_original": None,
        "host": "WS-1",
        "user": None,
        "process_name": "a.exe",
        "process_id": 4,
        "parent_name": None,
        "parent_id": None,
        "command_line": None,
        "file_path": None,
        "registry_key": None,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "hashes": None,
        "flags": [],
        "provenance": {},
        "raw": None,
        "evidence_id": 1,
    }
    assert schemas.validate(record, "event") == []


def test_validate_rejects_missing_required() -> None:
    errors = schemas.validate({"id": 1}, "event")
    assert any("missing required key 'source'" in e for e in errors)


def test_validate_rejects_wrong_type() -> None:
    record = {"id": "not-an-int", "source": "sysmon"}
    errors = schemas.validate(record, "event")
    assert any("$.id" in e and "integer" in e for e in errors)


def test_validate_rejects_bad_enum() -> None:
    errors = schemas.validate(
        {
            "tool": "huntforge",
            "version": "1.0.0",
            "command": "x",
            "timestamp": "t",
            "status": "bogus",
            "summary": "",
            "data": {},
            "findings": [],
            "events": [],
        },
        "envelope",
    )
    assert any("not in enum" in e for e in errors)


def test_validate_bool_is_not_integer() -> None:
    errors = schemas.validate(
        {
            "id": True,
            "source": "sysmon",
            "event_id": "1",
            "timestamp": None,
            "timestamp_original": None,
            "host": None,
            "user": None,
            "process_name": None,
            "process_id": None,
            "parent_name": None,
            "parent_id": None,
            "command_line": None,
            "file_path": None,
            "registry_key": None,
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "hashes": None,
            "flags": [],
            "provenance": {},
            "raw": None,
            "evidence_id": None,
        },
        "event",
    )
    assert any("$.id" in e for e in errors)


def test_schema_ids_are_versioned() -> None:
    for name in schemas.names():
        doc = schemas.get(name)
        assert doc["$id"].endswith("@1.0"), name
        assert doc["$id"].startswith("huntforge/")
