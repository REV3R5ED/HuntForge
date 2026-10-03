"""Shared fixtures for HuntForge tests.

``isolated_state`` points ``HUNTFORGE_STATE_DIR`` at a fresh tmp dir so
tests never touch the real ``~/.huntforge``. ``case_db`` creates a case
named ``CASE-001`` in it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from huntforge.cases.service import CaseService
from huntforge.core import config as config_mod
from huntforge.models.events import NormalizedEvent, Provenance
from huntforge.store.db import CaseDB


@pytest.fixture()
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    state_dir = tmp_path / "state"
    monkeypatch.setenv("HUNTFORGE_STATE_DIR", str(state_dir))
    return config_mod.resolve_state_dir()


@pytest.fixture()
def case_db(isolated_state: Path) -> CaseDB:
    db = CaseDB.create(isolated_state, "CASE-001", name="Test case")
    yield db
    db.close()


@pytest.fixture()
def case_service(isolated_state: Path) -> CaseService:
    return CaseService(isolated_state)


def make_provenance(**overrides: object) -> Provenance:
    base: dict[str, object] = {
        "source_file": "evidence/test.evtx",
        "record_index": 0,
        "parser_name": "fixture-loader",
        "parser_version": "0.1.0",
        "ingest_time": "2026-10-03T00:00:00Z",
        "source_sha256": "ab" * 32,
    }
    base.update(overrides)
    return Provenance(**base)  # type: ignore[arg-type]


def make_event(**overrides: object) -> NormalizedEvent:
    base: dict[str, object] = {
        "timestamp": "2026-10-02T19:48:39Z",
        "source": "sysmon",
        "event_id": 1,
        "provenance": make_provenance(),
        "host": "WS-001",
        "user": "CORP\\jdoe",
        "process_name": "powershell.exe",
        "process_id": 4242,
        "parent_name": "winword.exe",
        "parent_id": 3131,
        "command_line": "powershell.exe -enc aGVsbG8=",
    }
    base.update(overrides)
    return NormalizedEvent(**base)  # type: ignore[arg-type]


def write_jsonl(path: Path, records: list[dict[str, object]]) -> Path:
    with path.open("w", encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record) + "\n")
    return path


def event_dict(**overrides: object) -> dict[str, object]:
    event = make_event(**overrides)
    data = event.to_dict()
    data.pop("provenance", None)  # loader fills provenance when missing
    return data
