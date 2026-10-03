"""Tests for the normalized event model and provenance (v1.0-stable core)."""

from __future__ import annotations

import pytest
from conftest import make_event, make_provenance

from huntforge.models.events import EventValidationError, NormalizedEvent, Provenance


def test_timestamp_zulu_normalized() -> None:
    event = make_event(timestamp="2026-10-02T19:48:39Z")
    assert event.timestamp == "2026-10-02T19:48:39Z"
    assert event.timestamp_original == "2026-10-02T19:48:39Z"


def test_timestamp_offset_converted_to_utc() -> None:
    event = make_event(timestamp="2026-10-02T21:48:39+02:00")
    assert event.timestamp == "2026-10-02T19:48:39Z"
    assert event.timestamp_original == "2026-10-02T21:48:39+02:00"


def test_timestamp_naive_assumed_utc() -> None:
    event = make_event(timestamp="2026-10-02T19:48:39")
    assert event.timestamp == "2026-10-02T19:48:39Z"


@pytest.mark.parametrize(
    "bad", ["", "not-a-date", "2026-13-45T99:99:99Z", "Oct 2 2026", "12345"]
)
def test_bad_timestamps_rejected(bad: str) -> None:
    with pytest.raises(EventValidationError):
        make_event(timestamp=bad)


def test_provenance_required() -> None:
    with pytest.raises(EventValidationError):
        NormalizedEvent(
            timestamp="2026-10-02T19:48:39Z",
            source="sysmon",
            event_id="1",
            provenance=None,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("field", ["source_file", "parser_name", "source_sha256"])
def test_provenance_fields_required(field: str) -> None:
    kwargs = {
        "source_file": "a.evtx",
        "record_index": 0,
        "parser_name": "p",
        "parser_version": "1",
        "ingest_time": "2026-10-02T00:00:00Z",
        "source_sha256": "ff" * 32,
    }
    kwargs[field] = ""
    with pytest.raises(EventValidationError):
        Provenance(**kwargs)  # type: ignore[arg-type]


def test_provenance_record_index_must_be_non_negative_int() -> None:
    with pytest.raises(EventValidationError):
        make_provenance(record_index=-1)


def test_event_id_coerced_to_str() -> None:
    assert make_event(event_id=4688).event_id == "4688"
    assert make_event(event_id=" 1 ").event_id == "1"


def test_source_and_event_id_required() -> None:
    with pytest.raises(EventValidationError):
        make_event(source="  ")
    with pytest.raises(EventValidationError):
        make_event(event_id="")


def test_int_fields_coerced() -> None:
    event = make_event(process_id="4242", dst_port="443")
    assert event.process_id == 4242
    assert event.dst_port == 443


def test_int_fields_reject_garbage() -> None:
    with pytest.raises(EventValidationError):
        make_event(process_id="not-a-pid")


def test_hashes_keys_lowercased() -> None:
    event = make_event(hashes={"SHA256": "AA" * 32, "md5": "bb" * 16})
    assert event.hashes == {"sha256": "AA" * 32, "md5": "bb" * 16}


def test_round_trip_dict() -> None:
    event = make_event()
    restored = NormalizedEvent.from_dict(event.to_dict())
    assert restored.to_dict() == event.to_dict()


def test_from_dict_missing_provenance_rejected() -> None:
    data = make_event().to_dict()
    del data["provenance"]
    with pytest.raises(EventValidationError):
        NormalizedEvent.from_dict(data)


def test_from_dict_missing_provenance_field_rejected() -> None:
    data = make_event().to_dict()
    assert isinstance(data["provenance"], dict)
    del data["provenance"]["source_sha256"]
    with pytest.raises(EventValidationError):
        NormalizedEvent.from_dict(data)


def test_from_dict_rejects_bad_timestamp() -> None:
    data = make_event().to_dict()
    data["timestamp"] = "yesterday-ish"
    with pytest.raises(EventValidationError):
        NormalizedEvent.from_dict(data)
