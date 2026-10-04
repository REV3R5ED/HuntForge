"""HuntForge v0.9 tests: batch triage, JSONL export, config file, hardening.

Conventions: bare pytest binary, ``from conftest import``, no
no tests-package imports; all fixtures synthetic (text only — no binary
fixtures committed).
"""

from __future__ import annotations

import io
import json
import time
from pathlib import Path

import pytest

from huntforge.batch import (
    BatchRunner,
    export_events,
    export_findings,
    export_what,
    sanitize_case_name,
)
from huntforge.cli.main import main
from huntforge.core import appconfig as appconfig_mod
from huntforge.core.appconfig import ConfigError, load_config
from huntforge.core.config import resolve_state_dir
from huntforge.store.db import CaseDB

FIXTURES = Path(__file__).parent / "fixtures"


def _copy_fixtures(target: Path, *names: str) -> Path:
    target.mkdir(parents=True, exist_ok=True)
    for name in names:
        (target / name).write_bytes((FIXTURES / name).read_bytes())
    return target


# -- case naming ------------------------------------------------------------


def test_sanitize_case_name_deterministic_and_safe() -> None:
    assert sanitize_case_name("sysmon_intrusion", 3) == "batch-0003-sysmon_intrusion"
    assert sanitize_case_name("weird name (1)", 1) == "batch-0001-weird_name_1"
    assert sanitize_case_name("../../etc", 9) == "batch-0009-etc"
    assert sanitize_case_name("", 2) == "batch-0002-evidence"


def test_sanitize_case_name_caps_at_64_chars() -> None:
    name = sanitize_case_name("x" * 200, 1)
    assert len(name) <= 64
    assert name.startswith("batch-0001-")


# -- config file ------------------------------------------------------------


def test_load_config_full_toml(tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        'state_dir = "/tmp/hfstate"\n'
        'default_severity = "high"\n'
        'analyst_name = "Pouya"\n',
        encoding="utf-8",
    )
    parsed = load_config(str(cfg))
    assert parsed.source == str(cfg)
    assert parsed.state_dir == "/tmp/hfstate"
    assert parsed.default_severity == "high"
    assert parsed.analyst_name == "Pouya"
    assert parsed.warnings == []


def test_load_config_missing_file_returns_empty() -> None:
    parsed = load_config()
    assert parsed.source is None
    assert parsed.state_dir is None


def test_load_config_explicit_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "nope.toml"))


def test_load_config_unknown_key_warns(tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text('bogus = "x"\n', encoding="utf-8")
    parsed = load_config(str(cfg))
    assert len(parsed.warnings) == 1
    assert "bogus" in parsed.warnings[0]


def test_load_config_bad_severity_raises(tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text('default_severity = "extreme"\n', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(str(cfg))


def test_toml_subset_reader_direct(tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text(
        '# comment\nanalyst_name = "Pouya"\ndefault_severity="low"  # trailing\n',
        encoding="utf-8",
    )
    values = appconfig_mod._read_toml_subset(cfg)
    assert values["analyst_name"] == ("Pouya", 2)
    assert values["default_severity"] == ("low", 3)


def test_toml_subset_reader_rejects_fancy_syntax(tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text("[section]\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        appconfig_mod._read_toml_subset(cfg)


def test_config_state_dir_precedence(tmp_path: Path) -> None:
    # Config beats the built-in default; explicit flag beats config.
    via_config = resolve_state_dir(None, config_value=str(tmp_path / "cfg"))
    assert via_config == tmp_path / "cfg"
    via_flag = resolve_state_dir(
        str(tmp_path / "flag"), config_value=str(tmp_path / "cfg")
    )
    assert via_flag == tmp_path / "flag"


def test_detect_uses_config_default_severity(
    isolated_state: Path, tmp_path: Path
) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text('default_severity = "high"\n', encoding="utf-8")
    src = _copy_fixtures(tmp_path / "in", "sysmon_intrusion.xml")
    assert main(["case", "create", "CFG"]) == 0
    assert main(["ingest", str(src / "sysmon_intrusion.xml"), "--case", "CFG"]) == 0
    # The intrusion fixture yields high + medium findings; config keeps high.
    assert main(["--config", str(cfg), "detect", "--case", "CFG", "--json"]) == 1
    # Explicit --severity still wins over config.
    assert (
        main(
            [
                "--config",
                str(cfg),
                "detect",
                "--case",
                "CFG",
                "--severity",
                "medium",
                "--json",
            ]
        )
        == 1
    )


def test_notes_author_from_config(isolated_state: Path, tmp_path: Path) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text('analyst_name = "Pouya"\n', encoding="utf-8")
    assert main(["case", "create", "NOTE"]) == 0
    assert main(["--config", str(cfg), "notes", "--case", "NOTE", "--add", "hi"]) == 0
    db = CaseDB(isolated_state, "NOTE")
    try:
        notes = db.list_notes()
    finally:
        db.close()
    assert notes[0]["author"] == "Pouya"


# -- batch ------------------------------------------------------------------


def test_batch_creates_one_case_per_file(isolated_state: Path, tmp_path: Path) -> None:
    src = _copy_fixtures(
        tmp_path / "in", "sysmon_intrusion.xml", "security_events.json"
    )
    out = tmp_path / "out"
    runner = BatchRunner(isolated_state)
    summary = runner.run(src, out)
    assert summary["files_found"] == 2
    assert summary["cases_created"] == 2
    assert summary["files_failed"] == []
    assert summary["total_events"] > 0
    assert (out / "batch-manifest.json").is_file()
    assert (out / "batch-summary.json").is_file()
    case_ids = [c["case_id"] for c in summary["cases"]]
    assert len(set(case_ids)) == 2
    for record in summary["cases"]:
        assert record["status"] == "ok"
        assert record["sha256"]
        assert record["parser"] in ("sysmon", "security")


def test_batch_cases_are_isolated(isolated_state: Path, tmp_path: Path) -> None:
    src = _copy_fixtures(
        tmp_path / "in", "sysmon_intrusion.xml", "security_events.json"
    )
    runner = BatchRunner(isolated_state)
    summary = runner.run(src, tmp_path / "out")
    counts = [c["events"] for c in summary["cases"]]
    assert all(n > 0 for n in counts)
    # Sum of per-case events equals the total (no cross-contamination).
    assert sum(counts) == summary["total_events"]


def test_batch_idempotent_rerun(isolated_state: Path, tmp_path: Path) -> None:
    src = _copy_fixtures(tmp_path / "in", "sysmon_intrusion.xml")
    out = tmp_path / "out"
    runner = BatchRunner(isolated_state)
    first = runner.run(src, out)
    assert first["cases_created"] == 1
    second = runner.run(src, out)
    assert second["cases_created"] == 0
    assert second["cases_skipped"] == 1
    assert second["total_events"] == first["total_events"]


def test_batch_corrupt_input_does_not_abort(
    isolated_state: Path, tmp_path: Path
) -> None:
    src = _copy_fixtures(tmp_path / "in", "sysmon_intrusion.xml", "malformed.xml")
    summary = BatchRunner(isolated_state).run(src, tmp_path / "out")
    assert summary["cases_created"] == 2
    assert summary["files_failed"] == []
    malformed = next(c for c in summary["cases"] if c["filename"] == "malformed.xml")
    assert malformed["status"] == "ok"
    assert malformed["warnings"]


def test_batch_top_techniques_present(isolated_state: Path, tmp_path: Path) -> None:
    src = _copy_fixtures(tmp_path / "in", "sysmon_intrusion.xml")
    summary = BatchRunner(isolated_state).run(src, tmp_path / "out")
    assert summary["total_findings"] > 0
    top = summary["top_techniques"]
    assert top, "intrusion fixture should cover techniques"
    assert all({"technique_id", "name", "finding_count"} <= set(e) for e in top)


def test_batch_cli_happy_path(isolated_state: Path, tmp_path: Path) -> None:
    src = _copy_fixtures(tmp_path / "in", "sysmon_intrusion.xml")
    out = tmp_path / "out"
    assert main(["batch", str(src), "--output", str(out)]) == 1  # findings -> 1
    assert (out / "batch-summary.json").is_file()


def test_batch_cli_empty_dir_fails(isolated_state: Path, tmp_path: Path) -> None:
    src = tmp_path / "empty"
    src.mkdir()
    assert main(["batch", str(src), "--output", str(tmp_path / "out")]) == 2


def test_batch_cli_missing_dir_fails(isolated_state: Path, tmp_path: Path) -> None:
    assert main(["batch", str(tmp_path / "nope"), "--output", str(tmp_path)]) == 2


def test_batch_performance_sanity(isolated_state: Path, tmp_path: Path) -> None:
    # Every text fixture in the repo must triage in well under 30s.
    src = _copy_fixtures(
        tmp_path / "in",
        *[p.name for p in FIXTURES.iterdir() if p.suffix in (".xml", ".json")],
    )
    start = time.monotonic()
    summary = BatchRunner(isolated_state).run(src, tmp_path / "out")
    elapsed = time.monotonic() - start
    assert summary["files_found"] > 0
    assert elapsed < 30, f"batch too slow: {elapsed:.1f}s"


# -- JSONL export -----------------------------------------------------------


def _ingest_case(isolated_state: Path, tmp_path: Path) -> None:
    src = _copy_fixtures(tmp_path / "in", "sysmon_intrusion.xml")
    assert main(["case", "create", "EXP"]) == 0
    assert main(["ingest", str(src / "sysmon_intrusion.xml"), "--case", "EXP"]) == 0
    assert main(["detect", "--case", "EXP"]) == 1


def test_export_events_jsonl_valid(isolated_state: Path, tmp_path: Path) -> None:
    _ingest_case(isolated_state, tmp_path)
    db = CaseDB(isolated_state, "EXP")
    try:
        buf = io.StringIO()
        count = export_events(db, buf)
        lines = buf.getvalue().splitlines()
    finally:
        db.close()
    assert count == len(lines) > 0
    for line in lines:
        obj = json.loads(line)  # every line parses
        assert obj["record_type"] == "event"
        assert obj["schema"] == "huntforge/event@0.9"
        assert obj["tool"] == "huntforge"
        assert isinstance(obj["record"]["id"], int)


def test_export_findings_jsonl_valid(isolated_state: Path, tmp_path: Path) -> None:
    _ingest_case(isolated_state, tmp_path)
    db = CaseDB(isolated_state, "EXP")
    try:
        buf = io.StringIO()
        count = export_findings(db, buf)
        lines = buf.getvalue().splitlines()
    finally:
        db.close()
    assert count == len(lines) > 0
    for line in lines:
        obj = json.loads(line)
        assert obj["record_type"] == "finding"
        assert obj["schema"] == "huntforge/finding@0.9"


def test_export_what_rejects_unknown() -> None:
    with pytest.raises(ValueError):
        export_what(None, "nope", io.StringIO())  # type: ignore[arg-type]


def test_export_cli_to_file(isolated_state: Path, tmp_path: Path) -> None:
    _ingest_case(isolated_state, tmp_path)
    out = tmp_path / "events.jsonl"
    assert (
        main(["export", "--case", "EXP", "--what", "events", "--output", str(out)]) == 0
    )
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines and all(json.loads(line) for line in lines)


def test_export_cli_stdout(isolated_state: Path, tmp_path: Path, capsys) -> None:
    _ingest_case(isolated_state, tmp_path)
    capsys.readouterr()  # discard setup output
    assert main(["export", "--case", "EXP", "--what", "events"]) == 0
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert lines and all(json.loads(line) for line in lines)
    assert "exported" in captured.err  # envelope went to stderr


def test_export_cli_json_needs_output(isolated_state: Path, tmp_path: Path) -> None:
    _ingest_case(isolated_state, tmp_path)
    assert main(["export", "--case", "EXP", "--json"]) == 2


# -- hardening --------------------------------------------------------------


def test_batch_plugin_registered() -> None:
    from huntforge.core import plugins as plugins_mod

    info = plugins_mod.get_registry().get("batch")
    assert info.version == "0.9.0"
    assert set(info.commands) == {"batch", "export"}


def test_version_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_oversize_file_skipped_with_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import huntforge.parsers.common as common_mod
    from huntforge.parsers import parse_file

    monkeypatch.setattr(common_mod, "MAX_PARSE_BYTES", 0)
    fixture = FIXTURES / "sysmon_intrusion.xml"
    result = parse_file(fixture, "sysmon", source_sha256="ab" * 32, ingest_time=None)
    assert result.events == []
    assert result.warnings and "parse limit" in result.warnings[0]


def test_oversize_hive_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import huntforge.parsers.common as common_mod

    monkeypatch.setattr(common_mod, "MAX_PARSE_BYTES", 0)
    # Self-contained: any non-empty file is "oversize" when the limit is 0.
    hive = tmp_path / "synthetic_hive.dat"
    hive.write_bytes(b"regf")
    assert main(["registry", str(hive), "\\"]) == 2


def test_batch_file_limit_enforced(tmp_path: Path) -> None:
    runner = BatchRunner(tmp_path)
    src = tmp_path / "many"
    src.mkdir()
    (src / "one.xml").write_text("<x/>", encoding="utf-8")
    # Simulate the limit without creating 10k files.
    import huntforge.batch.batch as batch_mod

    original = batch_mod.MAX_BATCH_FILES
    batch_mod.MAX_BATCH_FILES = 0
    try:
        with pytest.raises(ValueError, match="exceeds the batch limit"):
            runner.run(src, tmp_path / "out")
    finally:
        batch_mod.MAX_BATCH_FILES = original
