"""Tests for the per-case SQLite store: cases, evidence, events, audit."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from conftest import make_event

from huntforge.cases.service import CaseService
from huntforge.store.db import CaseDB, CaseError, list_cases, validate_case_id


def test_create_and_meta(isolated_state: Path) -> None:
    db = CaseDB.create(isolated_state, "CASE-001", name="Irvine workstation")
    try:
        meta = db.meta()
        assert meta["case_id"] == "CASE-001"
        assert meta["name"] == "Irvine workstation"
        assert meta["created"].endswith("Z")
        assert db.event_count() == 0
        assert db.evidence_count() == 0
    finally:
        db.close()


def test_create_duplicate_rejected(isolated_state: Path, case_db: CaseDB) -> None:
    with pytest.raises(CaseError):
        CaseDB.create(isolated_state, "CASE-001")


def test_open_unknown_case_rejected(isolated_state: Path) -> None:
    with pytest.raises(CaseError):
        CaseDB(isolated_state, "NOPE-999")


@pytest.mark.parametrize(
    "bad", ["", "../evil", "a/b", "has space", "x" * 65, "-lead", ".", ".."]
)
def test_bad_case_ids_rejected(bad: str) -> None:
    with pytest.raises(CaseError):
        validate_case_id(bad)


@pytest.mark.parametrize("good", ["CASE-001", "a", "x.y_z-9", "0" * 64])
def test_good_case_ids_accepted(good: str) -> None:
    assert validate_case_id(good) == good


def test_evidence_dedupe_by_sha256(case_db: CaseDB) -> None:
    first = case_db.add_evidence("/tmp/a.evtx", "a.evtx", 10, "aa" * 32, "bb" * 16)
    second = case_db.add_evidence("/tmp/b.evtx", "b.evtx", 10, "aa" * 32, "bb" * 16)
    assert first.id == second.id
    assert case_db.evidence_count() == 1


def test_event_round_trip(case_db: CaseDB) -> None:
    row_id = case_db.add_event(make_event())
    assert row_id == 1
    events = case_db.query_events()
    assert len(events) == 1
    event = events[0]
    assert event["timestamp"] == "2026-10-02T19:48:39Z"
    assert event["host"] == "WS-001"
    assert event["process_name"] == "powershell.exe"
    assert event["process_id"] == 4242
    assert event["provenance"]["parser_name"] == "fixture-loader"
    assert case_db.event_count() == 1


def test_query_filters(case_db: CaseDB) -> None:
    case_db.add_event(
        make_event(
            host="WS-001", user="alice", event_id=1, process_name="powershell.exe"
        )
    )
    case_db.add_event(
        make_event(
            host="WS-002",
            user="bob",
            event_id=4688,
            process_name="cmd.exe",
            command_line="cmd.exe /c whoami",
        )
    )
    case_db.add_event(
        make_event(
            host="WS-001",
            user="bob",
            event_id=3,
            process_name="powershell.exe",
            file_path="C:\\evil\\drop.exe",
        )
    )

    assert len(case_db.query_events(host="ws-001")) == 2  # case-insensitive
    assert len(case_db.query_events(user="BOB")) == 2
    assert len(case_db.query_events(event_id="4688")) == 1
    assert len(case_db.query_events(process="POWERSHELL.EXE")) == 2
    assert len(case_db.query_events(keyword="whoami")) == 1
    assert len(case_db.query_events(keyword="drop.exe")) == 1
    # AND combination
    assert len(case_db.query_events(host="WS-001", user="bob")) == 1
    assert len(case_db.query_events(host="WS-002", process="powershell.exe")) == 0


def test_query_ordering_and_pagination(case_db: CaseDB) -> None:
    case_db.add_event(make_event(timestamp="2026-10-02T19:00:00Z", host="B"))
    case_db.add_event(make_event(timestamp="2026-10-02T18:00:00Z", host="A"))
    case_db.add_event(make_event(timestamp="2026-10-02T20:00:00Z", host="C"))
    events = case_db.query_events()
    assert [e["host"] for e in events] == ["A", "B", "C"]
    page = case_db.query_events(limit=1, offset=1)
    assert [e["host"] for e in page] == ["B"]


def test_indexes_exist(case_db: CaseDB) -> None:
    assert case_db.path.exists()
    conn = sqlite3.connect(str(case_db.path))
    try:
        names = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
    finally:
        conn.close()
    for expected in (
        "events_time",
        "events_host",
        "events_user",
        "events_event_id",
        "events_process",
        "evidence_sha",
    ):
        assert expected in names


def test_audit_log(case_db: CaseDB) -> None:
    case_db.audit("events", {"case": "CASE-001"}, result_count=3, status="ok")
    case_db.audit("ingest", {"case": "CASE-001"}, result_count=1, status="error")
    rows = case_db.audit_log()
    assert len(rows) == 2
    assert rows[0]["command"] == "ingest"  # newest first
    assert rows[0]["status"] == "error"
    assert rows[1]["result_count"] == 3
    assert rows[0]["args"]["case"] == "CASE-001"
    assert rows[0]["ts"].endswith("Z")


def test_list_cases(isolated_state: Path, case_service: CaseService) -> None:
    case_service.create("CASE-002", name="Second")
    case_service.create("CASE-001", name="First")
    cases = list_cases(isolated_state)
    assert [c["case_id"] for c in cases] == ["CASE-001", "CASE-002"]
    assert cases[0]["name"] == "First"
    assert list_cases(isolated_state / "missing") == []
