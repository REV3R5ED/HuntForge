"""The normalized event model — the v1.0-stable core of HuntForge.

Every parser (v0.2+ EVTX/Sysmon/PowerShell, v0.3 prefetch/registry/…)
normalizes its native records into :class:`NormalizedEvent`. Fields
that have no meaning for a given source stay ``None``; provenance is
mandatory and can never be ``None`` — an event without provenance is
rejected at construction time.

Design notes for future phases:
- ``timestamp`` is always UTC ISO-8601 ending in ``Z``;
  ``timestamp_original`` preserves the value exactly as ingested.
- ``event_id`` is coerced to ``str`` (Sysmon uses ints, EVTX uses
  ints, some sources use strings).
- ``hashes`` maps algorithm name (lowercase, e.g. ``"sha256"``) to
  hex digest.
- ``raw`` is a short reference/excerpt, never the full native record;
  full records live in the evidence files registered at ingest time.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from huntforge.core.logging import TimestampError, normalize_timestamp


class EventValidationError(ValueError):
    """Raised when a normalized event fails validation."""


@dataclass
class Provenance:
    """Where an event came from and how it was produced.

    All fields are required. ``source_sha256`` is the SHA-256 of the
    evidence file the event was parsed from, so any event can be traced
    back to the exact bytes it was derived from.
    """

    source_file: str
    record_index: int
    parser_name: str
    parser_version: str
    ingest_time: str
    source_sha256: str

    def __post_init__(self) -> None:
        for attr in (
            "source_file",
            "parser_name",
            "parser_version",
            "ingest_time",
            "source_sha256",
        ):
            if not getattr(self, attr):
                raise EventValidationError(
                    f"provenance.{attr} is required and must be non-empty"
                )
        if not isinstance(self.record_index, int) or self.record_index < 0:
            raise EventValidationError(
                "provenance.record_index must be a non-negative int"
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Provenance:
        try:
            return cls(
                source_file=str(data["source_file"]),
                record_index=int(data["record_index"]),
                parser_name=str(data["parser_name"]),
                parser_version=str(data["parser_version"]),
                ingest_time=str(data["ingest_time"]),
                source_sha256=str(data["source_sha256"]),
            )
        except KeyError as exc:
            raise EventValidationError(
                f"provenance missing required field: {exc}"
            ) from exc


@dataclass
class NormalizedEvent:
    """One endpoint telemetry record in HuntForge's common schema."""

    timestamp: str  # UTC ISO-8601, normalized at construction
    source: str  # e.g. "evtx:Security", "sysmon", "powershell"
    event_id: str  # coerced to str
    provenance: Provenance
    timestamp_original: str | None = None
    host: str | None = None
    user: str | None = None
    process_name: str | None = None
    process_id: int | None = None
    parent_name: str | None = None
    parent_id: int | None = None
    command_line: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    file_path: str | None = None
    registry_key: str | None = None
    hashes: dict[str, str] = field(default_factory=dict)
    raw: str | None = None

    def __post_init__(self) -> None:
        if not self.source or not str(self.source).strip():
            raise EventValidationError("event source is required and must be non-empty")
        self.source = str(self.source).strip()
        if self.event_id is None or str(self.event_id).strip() == "":
            raise EventValidationError("event_id is required and must be non-empty")
        self.event_id = str(self.event_id).strip()
        if not isinstance(self.provenance, Provenance):
            raise EventValidationError(
                "provenance is required and must be a Provenance"
            )
        try:
            utc, original = normalize_timestamp(str(self.timestamp))
        except TimestampError as exc:
            raise EventValidationError(f"invalid timestamp: {exc}") from exc
        self.timestamp = utc
        if self.timestamp_original is None:
            self.timestamp_original = original
        for int_field in ("process_id", "parent_id", "src_port", "dst_port"):
            value = getattr(self, int_field)
            if value is not None and not isinstance(value, int):
                try:
                    setattr(self, int_field, int(value))
                except (TypeError, ValueError):
                    raise EventValidationError(
                        f"{int_field} must be an int, got {value!r}"
                    ) from None
        if not isinstance(self.hashes, dict):
            raise EventValidationError(
                "hashes must be a dict of algorithm -> hex digest"
            )
        self.hashes = {str(k).lower(): str(v) for k, v in self.hashes.items()}

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["provenance"] = self.provenance.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NormalizedEvent:
        data = dict(data)
        if "provenance" not in data or not isinstance(data["provenance"], dict):
            raise EventValidationError("event provenance is required")
        data["provenance"] = Provenance.from_dict(data["provenance"])
        try:
            return cls(**{k: v for k, v in data.items() if k in _EVENT_FIELDS})
        except TypeError as exc:
            raise EventValidationError(f"invalid event fields: {exc}") from exc


_EVENT_FIELDS = {f for f in NormalizedEvent.__dataclass_fields__}
