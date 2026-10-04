"""Reporting tests: notes CRUD, report assembly, renderers, CLI."""

from __future__ import annotations

import io
import json
import sqlite3
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
from conftest import make_event

from huntforge import reporting as reporting_mod
from huntforge.cli.main import main as cli_main
from huntforge.reporting.model import REQUIRED_SECTIONS, build_report
from huntforge.reporting.render import (
    render_findings_csv,
    render_html,
    render_json,
    render_markdown,
)
from huntforge.store.db import CaseDB, CaseError


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_main(argv)
    return code, out.getvalue(), err.getvalue()


def run_json(argv: list[str]) -> tuple[int, dict]:
    code, out, _ = run([*argv, "--json"])
    return code, json.loads(out)


def seed_events(db: CaseDB) -> None:
    """Two timed Sysmon events with distinct sources + one untimed task."""
    db.add_event(make_event())
    db.add_event(
        make_event(
            timestamp="2026-10-02T19:50:00Z",
            source="sysmon",
            event_id=3,
            process_id=4242,
            command_line=None,
            parent_name=None,
            parent_id=None,
        )
    )
    db.add_event(
        make_event(
            timestamp_original=None,
            source="tasks",
            event_id="task",
            process_name=None,
            process_id=None,
            command_line=None,
        )
    )


def seed_finding(db: CaseDB) -> str:
    return db.add_finding(
        {
            "rule_id": "HF-DET-ENCPSH",
            "rule_version": "0.5.0",
            "severity": "high",
            "title": "Encoded PowerShell execution",
            "confidence": 80,
            "why": ["command line contains -enc flag"],
            "what": "powershell ran with an encoded command",
            "confidence_reason": "exact flag match",
            "observed": ["powershell.exe -enc aGVsbG8= at 2026-10-02T19:48:39Z"],
            "inferred": ["operator may be hiding intent"],
            "evidence": [
                {
                    "event_id": 1,
                    "source": "sysmon",
                    "source_event_id": "1",
                    "observation": "encoded command line",
                }
            ],
            "mitre": ["T1059.001"],
            "provenance": "huntforge.detections",
        }
    )


# ---------------------------------------------------------------------------
# notes: store


def test_notes_add_and_list(case_db: CaseDB) -> None:
    first = case_db.add_note("initial triage: looks like the invoice lure")
    second = case_db.add_note("escalate to IR", author="soc-lead")
    assert first == 1
    assert second == 2
    notes = case_db.list_notes()
    assert [n["id"] for n in notes] == [1, 2]
    assert notes[0]["text"] == "initial triage: looks like the invoice lure"
    assert notes[0]["author"] == "analyst"
    assert notes[1]["author"] == "soc-lead"
    assert notes[0]["ts"]  # timestamp recorded


def test_notes_reject_empty(case_db: CaseDB) -> None:
    with pytest.raises(CaseError):
        case_db.add_note("   ")


def test_notes_table_migrated_on_old_db(isolated_state: Path) -> None:
    db = CaseDB.create(isolated_state, "CASE-OLD")
    db.close()
    # Simulate a pre-v0.8 database: drop the notes table, then reopen.
    conn = sqlite3.connect(str(isolated_state / "cases" / "CASE-OLD" / "store.db"))
    conn.execute("DROP TABLE notes")
    conn.commit()
    conn.close()
    reopened = CaseDB(isolated_state, "CASE-OLD")
    try:
        assert reopened.add_note("migration works") == 1
    finally:
        reopened.close()


# ---------------------------------------------------------------------------
# notes: service + CLI


def test_notes_service_roundtrip(case_db: CaseDB) -> None:
    note = reporting_mod.notes_mod.add_note(case_db, "hello")
    assert note["text"] == "hello"
    assert reporting_mod.notes_mod.list_notes(case_db) == [note]


def test_notes_cli_add_and_list(isolated_state: Path) -> None:
    code, _, _ = run(["case", "create", "CASE-001"])
    assert code == 0
    code, out, _ = run(["notes", "--case", "CASE-001", "--add", "check the Run key"])
    assert code == 0
    assert "note #1 added" in out
    code, out, _ = run(["notes", "--case", "CASE-001", "--list"])
    assert code == 0
    assert "check the Run key" in out
    assert "(analyst)" in out


def test_notes_cli_defaults_to_list(isolated_state: Path) -> None:
    run(["case", "create", "CASE-001"])
    code, out, _ = run(["notes", "--case", "CASE-001"])
    assert code == 0
    assert "no notes" in out


def test_notes_cli_empty_text_rejected(isolated_state: Path) -> None:
    run(["case", "create", "CASE-001"])
    code, _, err = run(["notes", "--case", "CASE-001", "--add", "  "])
    assert code == 2
    assert "empty" in err


def test_notes_cli_unknown_case(isolated_state: Path) -> None:
    code, _, err = run(["notes", "--case", "NOPE", "--list"])
    assert code == 2
    assert "unknown case" in err


# ---------------------------------------------------------------------------
# report assembly


def _seeded(case_db: CaseDB) -> None:
    seed_events(case_db)
    seed_finding(case_db)
    case_db.add_note("analyst eyes on this one")


def test_report_has_all_sections(case_db: CaseDB) -> None:
    _seeded(case_db)
    report = build_report(case_db)
    for section in REQUIRED_SECTIONS:
        assert section in report, f"missing section {section}"


def test_report_executive_summary_marked_generated(case_db: CaseDB) -> None:
    _seeded(case_db)
    summary = build_report(case_db)["executive_summary"]
    assert summary["generated"] is True
    assert summary["analyst_review_required"] is True
    assert "CASE-001" in summary["text"]
    assert "2 detection" not in summary["text"]  # exactly one finding
    assert "1 detection finding(s)" in summary["text"]


def test_report_finding_labels_observed_inferred(case_db: CaseDB) -> None:
    _seeded(case_db)
    findings = build_report(case_db)["detections"]["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_uid"] == "HF-0001"
    assert finding["observed"]["label"] == "OBSERVED"
    assert finding["observed"]["facts"] == [
        "powershell.exe -enc aGVsbG8= at 2026-10-02T19:48:39Z"
    ]
    assert finding["inferred"]["label"] == "INFERRED"
    assert finding["inferred"]["hypotheses"] == ["operator may be hiding intent"]
    assert finding["mitre"] == ["T1059.001"]


def test_report_untimed_events_never_placed(case_db: CaseDB) -> None:
    _seeded(case_db)
    highlights = build_report(case_db)["timeline_highlights"]
    assert highlights["untimed_count"] == 1
    assert highlights["timed_count"] == 2
    assert all(e["id"] != 3 for e in highlights["first_events"])


def test_report_methodology_lists_parsers(case_db: CaseDB) -> None:
    _seeded(case_db)
    report = build_report(case_db)
    parsers = {p["name"] for p in report["methodology"]["parsers"]}
    assert "fixture-loader" in parsers


def test_report_empty_case(isolated_state: Path) -> None:
    db = CaseDB.create(isolated_state, "CASE-EMPTY")
    try:
        report = build_report(db)
        for section in REQUIRED_SECTIONS:
            assert section in report
        assert report["case_overview"]["events"] == 0
        assert report["detections"]["count"] == 0
        assert report["correlations"]["cluster_count"] == 0
        assert report["analyst_notes"]["count"] == 0
        assert "0 detection finding(s)" in report["executive_summary"]["text"]
    finally:
        db.close()


def test_report_does_not_claim_present(case_db: CaseDB) -> None:
    _seeded(case_db)
    claims = build_report(case_db)["what_this_report_does_not_claim"]
    assert any("attribut" in c for c in claims)
    assert any("clean" in c for c in claims)


def test_report_chain_of_custody(case_db: CaseDB) -> None:
    _seeded(case_db)
    coc = build_report(case_db)["chain_of_custody"]
    assert isinstance(coc["evidence"], list)
    assert isinstance(coc["audit"], list)


# ---------------------------------------------------------------------------
# renderers


def test_render_json_roundtrip(case_db: CaseDB) -> None:
    _seeded(case_db)
    report = build_report(case_db)
    parsed = json.loads(render_json(report))
    assert parsed["meta"]["case_id"] == "CASE-001"
    assert parsed["meta"]["report_schema_version"] == "huntforge/report@1.0"
    assert parsed["meta"]["generated_at"]
    for section in REQUIRED_SECTIONS:
        assert section in parsed


def test_render_markdown_marks_generated(case_db: CaseDB) -> None:
    _seeded(case_db)
    md = render_markdown(build_report(case_db))
    assert "CASE-001" in md
    assert "analyst review required" in md
    assert "OBSERVED" in md
    assert "INFERRED" in md
    assert "Analyst notes" in md
    assert "analyst eyes on this one" in md


def test_render_html_self_contained(case_db: CaseDB) -> None:
    _seeded(case_db)
    page = render_html(build_report(case_db))
    assert "<!DOCTYPE html>" in page
    assert "http://" not in page
    assert "https://" not in page
    assert "<link" not in page
    assert "<script" not in page
    assert "src=" not in page
    assert "href=" not in page
    # Content is escaped: no raw injection from note text.
    assert "OBSERVED" in page and "INFERRED" in page


def test_render_html_escapes_content(case_db: CaseDB) -> None:
    case_db.add_note("<script>alert('x')</script>")
    page = render_html(build_report(case_db))
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page


def test_render_findings_csv_columns_and_escaping() -> None:
    findings = [
        {
            "finding_uid": "HF-0001",
            "severity": "high",
            "rule_id": "R",
            "rule_version": "1",
            "title": "=cmd|'/c calc'!A0",
            "confidence": 90,
            "why": ["+suspicious"],
            "observed": {"label": "OBSERVED", "facts": ["-weird"]},
            "inferred": {"label": "INFERRED", "hypotheses": ["@guess"]},
            "evidence": [{"event_id": 7}],
            "mitre": ["T1059.001"],
            "provenance": "huntforge.detections",
        }
    ]
    rows = list(render_findings_csv(findings).splitlines())
    assert rows[0].split(",")[0] == "finding_uid"
    # Formula-looking cells are neutralized with a leading quote.
    assert "'=cmd" in rows[1]
    assert "'+suspicious" in rows[1]
    assert "'-weird" in rows[1]
    assert "'@guess" in rows[1]


def test_render_findings_csv_empty() -> None:
    assert render_findings_csv([]).splitlines() == [
        "finding_uid,severity,rule_id,rule_version,title,confidence,"
        "why,observed_facts,inferred_hypotheses,evidence_event_ids,"
        "mitre,provenance"
    ]


# ---------------------------------------------------------------------------
# report files: service + CLI


def test_generate_writes_all_formats(isolated_state: Path, tmp_path: Path) -> None:
    db = CaseDB.create(isolated_state, "CASE-001")
    try:
        _seeded(db)
        out = tmp_path / "report"
        manifest = reporting_mod.report_mod.generate(db, out)
        assert manifest["formats"] == ["html", "json", "md", "csv"]
        assert len(manifest["files"]) == 4
        for path in manifest["files"]:
            assert Path(path).exists()
        names = {Path(p).name for p in manifest["files"]}
        assert names == {
            "CASE-001.html",
            "CASE-001.json",
            "CASE-001.md",
            "CASE-001-findings.csv",
        }
    finally:
        db.close()


def test_generate_single_format(isolated_state: Path, tmp_path: Path) -> None:
    db = CaseDB.create(isolated_state, "CASE-001")
    try:
        manifest = reporting_mod.report_mod.generate(db, tmp_path, ("json",))
        assert manifest["files"] == [str((tmp_path / "CASE-001.json").resolve())]
    finally:
        db.close()


def test_generate_rejects_unknown_format(isolated_state: Path, tmp_path: Path) -> None:
    db = CaseDB.create(isolated_state, "CASE-001")
    try:
        with pytest.raises(ValueError, match="unknown report format"):
            reporting_mod.report_mod.generate(db, tmp_path, ("pdf",))  # type: ignore[arg-type]
    finally:
        db.close()


def test_report_cli_all_formats(isolated_state: Path, tmp_path: Path) -> None:
    run(["case", "create", "CASE-001"])
    outdir = tmp_path / "r"
    code, out, _ = run(
        ["report", "case", "CASE-001", "--output", str(outdir), "--format", "all"]
    )
    assert code == 0
    assert "4 file(s)" in out
    assert (outdir / "CASE-001.html").exists()
    assert (outdir / "CASE-001-findings.csv").exists()


def test_report_cli_single_format_json(isolated_state: Path, tmp_path: Path) -> None:
    run(["case", "create", "CASE-001"])
    outdir = tmp_path / "r"
    code, out, _ = run(
        ["report", "case", "CASE-001", "--output", str(outdir), "--format", "json"]
    )
    assert code == 0
    assert (outdir / "CASE-001.json").exists()
    assert not (outdir / "CASE-001.html").exists()


def test_report_cli_json_envelope(isolated_state: Path, tmp_path: Path) -> None:
    run(["case", "create", "CASE-001"])
    code, payload = run_json(
        ["report", "case", "CASE-001", "--output", str(tmp_path), "--format", "md"]
    )
    assert code == 0
    assert payload["status"] == "ok"
    assert payload["command"] == "report case"
    assert len(payload["data"]["files"]) == 1


def test_report_cli_unknown_case(isolated_state: Path, tmp_path: Path) -> None:
    code, _, err = run(["report", "case", "NOPE", "--output", str(tmp_path)])
    assert code == 2
    assert "unknown case" in err


def test_report_cli_is_audited(isolated_state: Path, tmp_path: Path) -> None:
    run(["case", "create", "CASE-001"])
    run(["report", "case", "CASE-001", "--output", str(tmp_path)])
    db = CaseDB(isolated_state, "CASE-001")
    try:
        commands = [entry["command"] for entry in db.audit_log()]
        assert "report" in commands
    finally:
        db.close()


# ---------------------------------------------------------------------------
# plugin registry


def test_reporting_registered() -> None:
    from huntforge.core.plugins import get_registry

    info = get_registry().get("reporting")
    assert info.version == "1.0.0"
    assert set(info.commands) == {"report", "notes"}
