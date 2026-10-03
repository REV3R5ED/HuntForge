"""CLI tests: commands, JSON contract, exit codes, audit trail."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
from conftest import event_dict, write_jsonl

from huntforge import __version__
from huntforge.cli.main import main


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def run_json(argv: list[str]) -> tuple[int, dict[str, object]]:
    code, out, _ = run([*argv, "--json"])
    return code, json.loads(out)


def test_version() -> None:
    with pytest.raises(SystemExit) as exc:
        run(["--version"])
    # argparse --version raises SystemExit(0); check the flag path instead
    assert exc.value.code == 0


def test_case_create_show_list(isolated_state: Path) -> None:
    code, _out, _err = run(["case", "create", "CASE-001", "--name", "Workstation"])
    assert code == 0

    code, data = run_json(["case", "show", "CASE-001"])
    assert code == 0
    assert data["status"] == "ok"
    assert data["data"]["name"] == "Workstation"  # type: ignore[index]
    assert data["tool"] == "huntforge"
    assert data["version"] == __version__

    code, data = run_json(["case", "list"])
    assert code == 0
    assert data["data"]["count"] == 1  # type: ignore[index]


def test_case_create_duplicate_exit_2(isolated_state: Path) -> None:
    assert run(["case", "create", "CASE-001"])[0] == 0
    code, _out, err = run(["case", "create", "CASE-001"])
    assert code == 2
    assert "already exists" in err


def test_case_show_unknown_exit_2(isolated_state: Path) -> None:
    code, _out, err = run(["case", "show", "NOPE"])
    assert code == 2
    assert "unknown case" in err


def test_case_id_traversal_rejected(isolated_state: Path) -> None:
    code, _out, err = run(["case", "create", "../evil"])
    assert code == 2


def _seed(isolated_state: Path, tmp_path: Path) -> None:
    run(["case", "create", "CASE-001"])
    fixture = write_jsonl(
        tmp_path / "events.jsonl",
        [
            event_dict(
                host="WS-001", user="alice", event_id=1, process_name="powershell.exe"
            ),
            event_dict(
                host="WS-001",
                user="bob",
                event_id=4688,
                process_name="cmd.exe",
                command_line="cmd.exe /c whoami",
            ),
            event_dict(
                host="WS-002",
                user="alice",
                event_id=3,
                process_name="powershell.exe",
                file_path="C:\\Temp\\drop.exe",
                timestamp="2026-10-02T20:00:00Z",
            ),
        ],
    )
    evidence = tmp_path / "security.evtx"
    evidence.write_bytes(b"fake")
    code, _out, _err = run(
        ["ingest", str(evidence), "--case", "CASE-001", "--fixture", str(fixture)]
    )
    assert code == 0


def test_ingest_registers_evidence_and_events(
    isolated_state: Path, tmp_path: Path
) -> None:
    _seed(isolated_state, tmp_path)
    code, data = run_json(["case", "show", "CASE-001"])
    assert code == 0
    assert data["data"]["events"] == 3  # type: ignore[index]
    assert data["data"]["evidence"] == 2  # type: ignore[index]


def test_events_query_filters(isolated_state: Path, tmp_path: Path) -> None:
    _seed(isolated_state, tmp_path)

    code, data = run_json(["events", "--case", "CASE-001", "--host", "WS-001"])
    assert code == 0
    assert data["data"]["count"] == 2  # type: ignore[index]

    code, data = run_json(["events", "--case", "CASE-001", "--process", "cmd.exe"])
    assert data["data"]["count"] == 1  # type: ignore[index]

    code, data = run_json(
        ["events", "--case", "CASE-001", "--user", "alice", "--keyword", "drop.exe"]
    )
    assert data["data"]["count"] == 1  # type: ignore[index]

    # deterministic ordering by timestamp
    code, data = run_json(["events", "--case", "CASE-001"])
    events = data["events"]  # type: ignore[index]
    timestamps = [e["timestamp"] for e in events]
    assert timestamps == sorted(timestamps)


def test_events_empty_store_message(isolated_state: Path) -> None:
    run(["case", "create", "EMPTY"])
    code, out, _err = run(["events", "--case", "EMPTY"])
    assert code == 0
    assert "no events match" in out

    code, data = run_json(["events", "--case", "EMPTY", "--host", "WS-999"])
    assert code == 0
    assert data["data"]["count"] == 0  # type: ignore[index]
    assert data["status"] == "ok"


def test_events_unknown_case_exit_2(isolated_state: Path) -> None:
    code, _out, err = run(["events", "--case", "NOPE"])
    assert code == 2
    assert "unknown case" in err


def test_events_invalid_limit_exit_2(isolated_state: Path, tmp_path: Path) -> None:
    _seed(isolated_state, tmp_path)
    code, _out, err = run(["events", "--case", "CASE-001", "--limit", "0"])
    assert code == 2


def test_json_envelope_schema(isolated_state: Path, tmp_path: Path) -> None:
    _seed(isolated_state, tmp_path)
    _code, data = run_json(["events", "--case", "CASE-001", "--event-id", "4688"])
    for key in (
        "tool",
        "version",
        "command",
        "timestamp",
        "status",
        "summary",
        "data",
        "findings",
        "events",
    ):
        assert key in data, f"envelope missing {key}"
    assert data["timestamp"].endswith("Z")
    event = data["events"][0]  # type: ignore[index]
    assert event["provenance"]["source_sha256"]
    assert event["timestamp"].endswith("Z")


def test_human_output_lists_events(isolated_state: Path, tmp_path: Path) -> None:
    _seed(isolated_state, tmp_path)
    code, out, _err = run(["events", "--case", "CASE-001", "--process", "cmd.exe"])
    assert code == 0
    assert "cmd.exe" in out
    assert "whoami" in out


def test_audit_trail(isolated_state: Path, tmp_path: Path) -> None:
    _seed(isolated_state, tmp_path)
    run(["events", "--case", "CASE-001", "--host", "WS-001"])
    code, data = run_json(["audit", "--case", "CASE-001"])
    assert code == 0
    entries = data["data"]["entries"]  # type: ignore[index]
    commands = {e["command"] for e in entries}
    # every invocation touching the case was logged
    assert {"case", "ingest", "events"} <= commands
    for entry in entries:
        assert entry["ts"].endswith("Z")
        assert entry["status"] in ("ok", "error")


def test_ingest_fixture_all_bad_exit_2(isolated_state: Path, tmp_path: Path) -> None:
    run(["case", "create", "CASE-001"])
    bad = tmp_path / "bad.jsonl"
    bad.write_text("nope\n", encoding="utf-8")
    code, _out, err = run(
        ["ingest", str(tmp_path), "--case", "CASE-001", "--fixture", str(bad)]
    )
    assert code == 2
    assert "loaded 0 events" in err


def test_plugin_registry_lists_core() -> None:
    from huntforge.core.plugins import get_registry

    info = get_registry().get("core")
    assert info.version == __version__
    assert "events" in info.commands
