"""Tests for evidence ingest: hashing, registry, fixture loader."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from conftest import event_dict, write_jsonl

from huntforge.ingest.service import hash_file, ingest_path, load_fixture
from huntforge.store.db import CaseDB


def test_hash_file(tmp_path: Path) -> None:
    target = tmp_path / "data.bin"
    target.write_bytes(b"hello huntforge")
    sha256, md5 = hash_file(target)
    assert sha256 == hashlib.sha256(b"hello huntforge").hexdigest()
    assert md5 == hashlib.md5(b"hello huntforge").hexdigest()


def test_ingest_single_file(case_db: CaseDB, tmp_path: Path) -> None:
    target = tmp_path / "security.evtx"
    target.write_bytes(b"fake-evtx-bytes")
    summary = ingest_path(case_db, target)
    assert summary["files_found"] == 1
    assert summary["registered"] == 1
    assert summary["total_bytes"] == len(b"fake-evtx-bytes")
    assert case_db.evidence_count() == 1
    record = case_db.list_evidence()[0]
    assert record.filename == "security.evtx"
    assert record.sha256 == hashlib.sha256(b"fake-evtx-bytes").hexdigest()


def test_ingest_directory_recursive(case_db: CaseDB, tmp_path: Path) -> None:
    evdir = tmp_path / "evidence"
    evdir.mkdir()
    (evdir / "a.evtx").write_bytes(b"a")
    sub = evdir / "sub"
    sub.mkdir()
    (sub / "b.evtx").write_bytes(b"b")
    summary = ingest_path(case_db, evdir)
    assert summary["files_found"] == 2
    flat = ingest_path(case_db, evdir, recursive=False)
    assert flat["files_found"] == 1


def test_ingest_source_files_untouched(case_db: CaseDB, tmp_path: Path) -> None:
    target = tmp_path / "x.evtx"
    target.write_bytes(b"bytes")
    before = target.stat().st_mtime_ns
    ingest_path(case_db, target)
    assert target.stat().st_mtime_ns == before
    assert target.read_bytes() == b"bytes"


def test_ingest_missing_path(case_db: CaseDB, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        ingest_path(case_db, tmp_path / "nope.evtx")


def test_load_fixture(case_db: CaseDB, tmp_path: Path) -> None:
    fixture = write_jsonl(
        tmp_path / "events.jsonl",
        [event_dict(host="WS-001"), event_dict(host="WS-002", event_id=4688)],
    )
    summary = load_fixture(case_db, fixture)
    assert summary == {"loaded": 2, "skipped": 0, "errors": []}
    assert case_db.event_count() == 2
    events = case_db.query_events()
    assert events[0]["provenance"]["parser_name"] == "fixture-loader"
    assert (
        events[0]["provenance"]["source_sha256"]
        == hashlib.sha256(fixture.read_bytes()).hexdigest()
    )
    # fixture registered as evidence too
    assert case_db.evidence_count() == 1


def test_load_fixture_malformed_lines_skipped(case_db: CaseDB, tmp_path: Path) -> None:
    fixture = tmp_path / "events.jsonl"
    fixture.write_text(
        json.dumps(event_dict(host="WS-001"))
        + "\n"
        + "this is not json\n"
        + "[1, 2, 3]\n"
        + json.dumps({**event_dict(host="WS-002"), "timestamp": "bogus"})
        + "\n"
        + "\n",
        encoding="utf-8",
    )
    summary = load_fixture(case_db, fixture)
    assert summary["loaded"] == 1
    assert summary["skipped"] == 3
    assert len(summary["errors"]) == 3
    assert case_db.event_count() == 1


def test_load_fixture_missing_file(case_db: CaseDB, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_fixture(case_db, tmp_path / "missing.jsonl")


def test_load_fixture_preserves_explicit_provenance(
    case_db: CaseDB, tmp_path: Path
) -> None:
    payload = event_dict()
    payload["provenance"] = {
        "source_file": "custom.evtx",
        "record_index": 7,
        "parser_name": "custom-parser",
        "parser_version": "9.9",
        "ingest_time": "2026-01-01T00:00:00Z",
        "source_sha256": "cc" * 32,
    }
    fixture = write_jsonl(tmp_path / "events.jsonl", [payload])
    summary = load_fixture(case_db, fixture)
    assert summary["loaded"] == 1
    event = case_db.query_events()[0]
    assert event["provenance"]["parser_name"] == "custom-parser"
    assert event["provenance"]["record_index"] == 7
