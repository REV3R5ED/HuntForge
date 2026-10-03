"""Tests for v0.4: unified timeline, process lineage, entity resolution."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
from conftest import make_event

from huntforge.store.db import CaseDB
from huntforge.timeline import TIMELINE_VERSION, ensure_registered
from huntforge.timeline import entities as entities_mod
from huntforge.timeline import lineage as lineage_mod
from huntforge.timeline import timeline as timeline_mod
from huntforge.timeline.entities import (
    normalize_file,
    normalize_hash,
    normalize_host,
    normalize_ip,
    normalize_process,
    normalize_registry,
    normalize_user,
)


def _add(db: CaseDB, **overrides: object) -> int:
    return db.add_event(make_event(**overrides))


def _run(argv: list[str]) -> tuple[int, str, str]:
    from huntforge.cli.main import main

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def _run_json(argv: list[str]) -> tuple[int, dict[str, object]]:
    code, out, _ = _run([*argv, "--json"])
    return code, json.loads(out)


# ---------------------------------------------------------------------------
# timeline
# ---------------------------------------------------------------------------


def _seed_timeline(db: CaseDB) -> None:
    _add(
        db,
        timestamp="2026-10-02T09:13:02Z",
        source="sysmon",
        event_id="3",
        process_name="powershell.exe",
        process_id=7422,
        dst_ip="203.0.113.44",
        dst_port=443,
    )
    _add(
        db,
        timestamp="2026-10-02T09:11:03Z",
        source="sysmon",
        event_id="1",
        process_name="WINWORD.EXE",
        process_id=3131,
        parent_name="explorer.exe",
        parent_id=2048,
    )
    _add(
        db,
        timestamp="2026-10-02T09:12:41Z",
        source="security",
        event_id="4688",
        process_name="powershell.exe",
        process_id=7422,
        parent_name="WINWORD.EXE",
        parent_id=3131,
    )
    # Untimed: parser could not recover an original timestamp.
    _add(
        db,
        timestamp="2026-10-03T04:00:00Z",
        timestamp_original=None,
        source="tasks",
        event_id="task",
    )


def test_timeline_merges_sources_chronologically(case_db: CaseDB) -> None:
    _seed_timeline(case_db)
    result = timeline_mod.build_timeline(case_db, timeline_mod.TimelineOptions())
    assert [e["id"] for e in result.timed] == [2, 3, 1]
    assert [e["timestamp"] for e in result.timed] == [
        "2026-10-02T09:11:03Z",
        "2026-10-02T09:12:41Z",
        "2026-10-02T09:13:02Z",
    ]


def test_timeline_untimed_section_never_dropped(case_db: CaseDB) -> None:
    _seed_timeline(case_db)
    result = timeline_mod.build_timeline(case_db, timeline_mod.TimelineOptions())
    assert len(result.untimed) == 1
    assert result.untimed[0]["source"] == "tasks"
    assert result.coverage["untimed_count"] == 1
    assert result.coverage["timed_count"] == 3


def test_timeline_time_range_filter(case_db: CaseDB) -> None:
    _seed_timeline(case_db)
    result = timeline_mod.build_timeline(
        case_db,
        timeline_mod.TimelineOptions(
            from_ts="2026-10-02T09:12:00Z", to_ts="2026-10-02T09:13:00Z"
        ),
    )
    assert [e["id"] for e in result.timed] == [3]
    # Untimed events are not affected by the window.
    assert len(result.untimed) == 1


def test_timeline_source_filter(case_db: CaseDB) -> None:
    _seed_timeline(case_db)
    result = timeline_mod.build_timeline(
        case_db, timeline_mod.TimelineOptions(source="sysmon")
    )
    assert {e["source"] for e in result.timed} == {"sysmon"}
    assert len(result.timed) == 2


def test_timeline_invalid_bounds_rejected(case_db: CaseDB) -> None:
    with pytest.raises(ValueError, match="invalid --from"):
        timeline_mod.build_timeline(
            case_db, timeline_mod.TimelineOptions(from_ts="not-a-time")
        )
    with pytest.raises(ValueError, match="--from must not be later"):
        timeline_mod.build_timeline(
            case_db,
            timeline_mod.TimelineOptions(
                from_ts="2026-10-03T00:00:00Z", to_ts="2026-10-02T00:00:00Z"
            ),
        )
    with pytest.raises(ValueError, match="limit must be a positive int"):
        timeline_mod.TimelineOptions(limit=0)


def test_timeline_coverage_and_truncation(case_db: CaseDB) -> None:
    _seed_timeline(case_db)
    result = timeline_mod.build_timeline(case_db, timeline_mod.TimelineOptions(limit=2))
    assert result.truncated is True
    assert len(result.timed) == 2
    sources = result.coverage["sources"]
    assert sources["sysmon"]["events"] == 2
    assert sources["sysmon"]["first"] == "2026-10-02T09:11:03Z"
    assert sources["sysmon"]["last"] == "2026-10-02T09:13:02Z"
    assert result.coverage["range"] == {
        "from": "2026-10-02T09:11:03Z",
        "to": "2026-10-02T09:12:41Z",
    }


def test_timeline_empty_case(case_db: CaseDB) -> None:
    result = timeline_mod.build_timeline(case_db, timeline_mod.TimelineOptions())
    assert result.timed == [] and result.untimed == []
    assert result.coverage["range"] is None


def test_timeline_summaries(case_db: CaseDB) -> None:
    _add(
        case_db,
        timestamp="2026-10-02T09:13:02Z",
        source="sysmon",
        event_id="3",
        process_name="powershell.exe",
        process_id=7422,
        src_ip="192.168.1.50",
        dst_ip="203.0.113.44",
        dst_port=443,
    )
    result = timeline_mod.build_timeline(case_db, timeline_mod.TimelineOptions())
    assert "203.0.113.44:443" in result.timed[0]["summary"]
    as_dict = result.to_dict()
    assert as_dict["coverage"]["timed_count"] == 1


# ---------------------------------------------------------------------------
# lineage
# ---------------------------------------------------------------------------


def _seed_lineage(db: CaseDB) -> None:
    _add(
        db,
        timestamp="2026-10-02T09:11:03Z",
        source="sysmon",
        event_id="1",
        host="WS-001",
        process_name="explorer.exe",
        process_id=2048,
        parent_name="winlogon.exe",
        parent_id=1000,
    )
    _add(
        db,
        timestamp="2026-10-02T09:11:04Z",
        source="sysmon",
        event_id="1",
        host="WS-001",
        process_name="winword.exe",
        process_id=3131,
        parent_name="explorer.exe",
        parent_id=2048,
    )
    _add(
        db,
        timestamp="2026-10-02T09:12:41Z",
        source="security",
        event_id="4688",
        host="WS-001",
        process_name="powershell.exe",
        process_id=7422,
        parent_name="winword.exe",
        parent_id=3131,
    )
    # Non-creation reference to the powershell instance.
    _add(
        db,
        timestamp="2026-10-02T09:13:02Z",
        source="sysmon",
        event_id="3",
        host="WS-001",
        process_name="powershell.exe",
        process_id=7422,
        dst_ip="203.0.113.44",
    )


def test_lineage_multi_level_tree(case_db: CaseDB) -> None:
    _seed_lineage(case_db)
    forest = lineage_mod.build_lineage(case_db)
    assert forest["instance_count"] == 3
    roots = forest["roots"]
    assert len(roots) == 1
    lines = lineage_mod.render_forest(forest, roots)
    text = "\n".join(lines)
    assert "explorer.exe (2048)" in text
    assert "winword.exe (3131)" in text
    assert "powershell.exe (7422)" in text
    # winlogon (1000) was never observed: explorer is an orphan root.
    assert "parent pid 1000 not observed" in text
    # The network event corroborates the powershell instance.
    assert "1 related event(s)" in text


def test_lineage_same_image_reuses_one_instance(case_db: CaseDB) -> None:
    # Sysmon 1 + Security 4688 for the same (host, pid, image): one instance.
    _add(
        case_db,
        timestamp="2026-10-02T09:12:41Z",
        source="sysmon",
        event_id="1",
        host="H",
        process_name="powershell.exe",
        process_id=7422,
        parent_id=3131,
        parent_name="winword.exe",
    )
    _add(
        case_db,
        timestamp="2026-10-02T09:12:42Z",
        source="security",
        event_id="4688",
        host="H",
        process_name="powershell.exe",
        process_id=7422,
        parent_id=3131,
        parent_name="winword.exe",
    )
    forest = lineage_mod.build_lineage(case_db)
    assert forest["instance_count"] == 1


def test_lineage_pid_reuse_ambiguity(case_db: CaseDB) -> None:
    _add(
        case_db,
        timestamp="2026-10-02T09:12:41Z",
        source="sysmon",
        event_id="1",
        host="H",
        process_name="powershell.exe",
        process_id=7422,
        parent_id=3131,
        parent_name="winword.exe",
    )
    _add(
        case_db,
        timestamp="2026-10-02T12:00:05Z",
        source="sysmon",
        event_id="1",
        host="H",
        process_name="notepad.exe",
        process_id=7422,
        parent_id=2048,
        parent_name="explorer.exe",
    )
    _add(
        case_db,
        timestamp="2026-10-02T12:01:17Z",
        source="sysmon",
        event_id="1",
        host="H",
        process_name="calc.exe",
        process_id=9001,
        parent_id=7422,
        parent_name="notepad.exe",
    )
    forest = lineage_mod.build_lineage(case_db)
    assert forest["instance_count"] == 3
    assert forest["reused_pids"] == ["h:7422"]
    instances = forest["instances"]
    calc = next(v for v in instances.values() if v.image == "calc.exe")
    # Linked to the latest plausible parent, with the ambiguity named.
    parent = instances[calc.parent_key or ""]
    assert parent.image == "notepad.exe"
    assert calc.ambiguous_parent == ["powershell.exe (7422)", "notepad.exe (7422)"]


def test_lineage_ancestors_descendants(case_db: CaseDB) -> None:
    _seed_lineage(case_db)
    forest = lineage_mod.build_lineage(case_db)
    instances = forest["instances"]
    ps = next(v for v in instances.values() if v.image == "powershell.exe")
    chain = lineage_mod.ancestors(forest, ps.key)
    assert [instances[k].image for k in chain] == [
        "explorer.exe",
        "winword.exe",
        "powershell.exe",
    ]
    explorer = next(v for v in instances.values() if v.image == "explorer.exe")
    below = lineage_mod.descendants(forest, explorer.key)
    assert len(below) == 3


def test_lineage_events_without_pid_ignored(case_db: CaseDB) -> None:
    _add(case_db, timestamp="2026-10-02T09:00:00Z", source="tasks", event_id="task")
    forest = lineage_mod.build_lineage(case_db)
    assert forest["instance_count"] == 0
    assert lineage_mod.render_forest(forest, forest["roots"]) == []


# ---------------------------------------------------------------------------
# entities
# ---------------------------------------------------------------------------


def test_normalize_user() -> None:
    assert normalize_user("FIN-014\\m.alvarez") == "m.alvarez@fin-014"
    assert normalize_user("m.alvarez@FIN-014") == "m.alvarez@fin-014"
    assert normalize_user("  LocalSystem ") == "localsystem"
    assert normalize_user("S-1-5-18") == "s-1-5-18"


def test_normalize_others() -> None:
    assert normalize_host("WS-FIN-014") == "ws-fin-014"
    assert normalize_ip(" 2001:DB8::1 ") == "2001:db8::1"
    assert normalize_process("PowerShell.EXE") == "powershell.exe"
    assert normalize_file("C:\\Temp\\X.EXE") == "c:\\temp\\x.exe"
    assert normalize_hash("SHA256", "ABCD") == "sha256:abcd"
    assert normalize_registry("HKCU\\Software\\Run") == "hkcu\\software\\run"


def test_entities_link_across_sources(case_db: CaseDB) -> None:
    _add(
        case_db,
        source="sysmon",
        event_id="1",
        host="WS-FIN-014",
        user="FIN-014\\m.alvarez",
        process_name="powershell.exe",
        file_path="C:\\Temp\\drop.exe",
        hashes={"SHA256": "ABCD"},
    )
    _add(
        case_db,
        source="security",
        event_id="4688",
        host="ws-fin-014",
        user="m.alvarez@fin-014",
        process_name="PowerShell.EXE",
        file_path="c:\\temp\\DROP.exe",
        hashes={"sha256": "abcd"},
    )
    resolved = entities_mod.resolve_entities(case_db)
    by_key = {(e.type, e.value): e for e in resolved}
    user = by_key[("user", "m.alvarez@fin-014")]
    assert user.count == 2
    assert user.sources == {"sysmon", "security"}
    assert sorted(user.observed_as) == ["FIN-014\\m.alvarez", "m.alvarez@fin-014"]
    host = by_key[("host", "ws-fin-014")]
    assert host.count == 2
    proc = by_key[("process", "powershell.exe")]
    assert proc.count == 2
    assert proc.first_seen == proc.last_seen == "2026-10-02T19:48:39Z"
    hashed = by_key[("hash", "sha256:abcd")]
    assert hashed.count == 2


def test_entities_untimed_have_no_first_seen(case_db: CaseDB) -> None:
    _add(
        case_db,
        timestamp="2026-10-03T04:00:00Z",
        timestamp_original=None,
        source="tasks",
        event_id="task",
        user="FIN-014\\m.alvarez",
    )
    resolved = entities_mod.resolve_entities(case_db)
    user = next(e for e in resolved if e.type == "user")
    assert user.count == 1
    assert user.first_seen is None and user.last_seen is None


# ---------------------------------------------------------------------------
# model: explicit None vs omitted timestamp_original
# ---------------------------------------------------------------------------


def test_timestamp_original_explicit_none_preserved() -> None:
    event = make_event(timestamp_original=None)
    assert event.timestamp_original is None


def test_timestamp_original_omitted_fills_in() -> None:
    event = make_event(timestamp="2026-10-02T21:48:39+02:00")
    assert event.timestamp_original == "2026-10-02T21:48:39+02:00"


def test_timeline_module_registered() -> None:
    ensure_registered()  # idempotent
    from huntforge.core import plugins as plugins_mod

    info = plugins_mod.get_registry().get("timeline")
    assert info.version == TIMELINE_VERSION
    assert info.commands == ["timeline", "lineage", "entities"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_timeline_json(isolated_state: Path, case_db: CaseDB) -> None:
    _seed_timeline(case_db)
    code, data = _run_json(["timeline", "--case", "CASE-001"])
    assert code == 0
    assert data["status"] == "ok"  # type: ignore[index]
    timed = data["data"]["timed"]  # type: ignore[index]
    assert len(timed) == 3
    assert data["data"]["coverage"]["untimed_count"] == 1  # type: ignore[index]


def test_cli_timeline_filters(isolated_state: Path, case_db: CaseDB) -> None:
    _seed_timeline(case_db)
    code, data = _run_json(
        [
            "timeline",
            "--case",
            "CASE-001",
            "--from",
            "2026-10-02T09:12:00Z",
            "--to",
            "2026-10-02T09:13:00Z",
            "--source",
            "sec",
        ]
    )
    assert code == 0
    timed = data["data"]["timed"]  # type: ignore[index]
    assert len(timed) == 1
    assert timed[0]["event_id"] == "4688"


def test_cli_timeline_bad_option_exit_2(isolated_state: Path, case_db: CaseDB) -> None:
    code, _out, err = _run(["timeline", "--case", "CASE-001", "--from", "bogus"])
    assert code == 2
    assert "invalid --from" in err


def test_cli_lineage(isolated_state: Path, case_db: CaseDB) -> None:
    _seed_lineage(case_db)
    code, out, _ = _run(["lineage", "--case", "CASE-001"])
    assert code == 0
    assert "powershell.exe (7422)" in out
    code, data = _run_json(["lineage", "--case", "CASE-001", "--pid", "7422"])
    assert code == 0
    assert data["data"]["focus"][0]["image"] == "powershell.exe"  # type: ignore[index]


def test_cli_lineage_image_and_errors(isolated_state: Path, case_db: CaseDB) -> None:
    _seed_lineage(case_db)
    code, data = _run_json(["lineage", "--case", "CASE-001", "--image", "POWERSHELL"])
    assert code == 0
    assert len(data["data"]["focus"]) == 1  # type: ignore[index]
    code, _out, err = _run(["lineage", "--case", "CASE-001", "--pid", "999"])
    assert code == 2
    assert "no process instance" in err
    code, _out, err = _run(
        ["lineage", "--case", "CASE-001", "--pid", "1", "--image", "x"]
    )
    assert code == 2
    assert "only one of" in err


def test_cli_entities(isolated_state: Path, case_db: CaseDB) -> None:
    _add(case_db, user="FIN-014\\m.alvarez")
    _add(case_db, user="m.alvarez@fin-014", source="security", event_id="4688")
    code, data = _run_json(["entities", "--case", "CASE-001"])
    assert code == 0
    entities = data["data"]["entities"]  # type: ignore[index]
    users = [e for e in entities if e["type"] == "user"]
    assert len(users) == 1
    assert users[0]["value"] == "m.alvarez@fin-014"
    assert users[0]["count"] == 2
    code, data = _run_json(["entities", "--case", "CASE-001", "--type", "user"])
    assert code == 0
    assert data["data"]["count"] == 1  # type: ignore[index]


def test_cli_unknown_case_exit_2(isolated_state: Path) -> None:
    for cmd in (["timeline"], ["lineage"], ["entities"]):
        code, _out, err = _run([*cmd, "--case", "NOPE"])
        assert code == 2
        assert "unknown case" in err


def test_cli_commands_audited(isolated_state: Path, case_db: CaseDB) -> None:
    _seed_timeline(case_db)
    for cmd in ("timeline", "lineage", "entities"):
        assert _run([cmd, "--case", "CASE-001"])[0] == 0
    db = CaseDB(isolated_state, "CASE-001")
    try:
        commands = [row["command"] for row in db.audit_log(limit=10)]
    finally:
        db.close()
    assert "timeline" in commands
    assert "lineage" in commands
    assert "entities" in commands
