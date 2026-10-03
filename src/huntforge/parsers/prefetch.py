"""Windows Prefetch (.pf) parser (v0.3).

Parses uncompressed Prefetch files (format versions 23/26/30 — Vista/7,
8/8.1, 10) with pure-Python :mod:`struct` parsing, following the
published layout (libyal "Windows Prefetch File (PF) format"):
84-byte header (version at 0, ``SCCA`` signature at 4, UTF-16LE
executable name at 16, prefetch hash at 76), then a version-specific
file-information block carrying the run count, last-run FILETIMEs and
offsets to the file-metrics array, filename strings and volume
information.

Each ``.pf`` file yields ONE normalized event (execution evidence:
executable name, run count, most recent run) — a prefetch file is a
summary artifact, so one event per file keeps ``parsed_events`` counts
truthful.

Honest limitations (also in README):
- Compressed ``MAM`` prefetch (some Windows 10/11 systems) is detected
  and rejected with a clean error — decompress before ingesting.
- Format version 31 (Windows 11 24H2+) is rejected as unsupported.
- Version 30 has two file-information variants; the variant is picked
  from the file-metrics array offset (``0x130`` -> run count at +124,
  ``0x128`` -> run count at +116).
- Trace-chain arrays are not parsed (not needed for execution
  evidence); volume parsing extracts device path, serial and creation
  time only.
- Validated against synthetic fixtures built to the published layout;
  real-world validation against live ``C:\\Windows\\Prefetch`` copies
  is still pending.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from huntforge.models.events import NormalizedEvent
from huntforge.parsers.common import (
    MAX_PARSE_BYTES,
    excerpt,
    fresh_ingest_time,
    make_provenance,
)

PARSER_NAME = "prefetch"
PARSER_VERSION = "0.3.0"

#: ``SCCA`` signature lives at offset 4 (version is at offset 0).
PREFETCH_MAGIC = b"SCCA"
PREFETCH_MAGIC_OFFSET = 4

#: Compressed prefetch (Windows 10/11): detected, rejected with guidance.
MAM_MAGIC = b"MAM\x04"

SUPPORTED_VERSIONS = (23, 26, 30)

#: Hard caps so a corrupt file cannot blow up memory.
_MAX_METRICS_ENTRIES = 100_000
_MAX_FILENAME_BYTES = 10 * 1024 * 1024
_MAX_VOLUMES = 256

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


class PrefetchError(ValueError):
    """Raised when a Prefetch file cannot be parsed (clean, no crash)."""


def filetime_to_iso(value: int) -> str | None:
    """Convert a Windows FILETIME to UTC ISO-8601; ``None`` for 0/invalid."""
    if value == 0:
        return None
    try:
        moment = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except (OverflowError, ValueError, OSError):
        return None
    if moment.year > 3000:  # corrupt/garbage FILETIME
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise PrefetchError(f"truncated file: cannot read u32 at {offset:#x}")
    return int(struct.unpack_from("<I", data, offset)[0])


def _u64(data: bytes, offset: int) -> int:
    if offset + 8 > len(data):
        raise PrefetchError(f"truncated file: cannot read u64 at {offset:#x}")
    return int(struct.unpack_from("<Q", data, offset)[0])


def _utf16(data: bytes, offset: int, size: int) -> str:
    if offset + size > len(data):
        raise PrefetchError(f"truncated file: cannot read string at {offset:#x}")
    raw = data[offset : offset + size]
    # Filenames are not strict UTF-16 (unpaired surrogates occur).
    return raw.decode("utf-16-le", errors="replace").split("\x00")[0]


@dataclass
class PrefetchInfo:
    """Parsed contents of one Prefetch file."""

    version: int
    executable: str
    prefetch_hash: int
    file_size: int
    run_count: int
    last_runs: list[str] = field(default_factory=list)  # UTC ISO, newest first
    filenames: list[str] = field(default_factory=list)  # referenced files
    volumes: list[dict[str, Any]] = field(default_factory=list)


def parse_prefetch(data: bytes, *, filename: str = "") -> PrefetchInfo:
    """Parse raw Prefetch bytes; raises :class:`PrefetchError` on failure."""
    label = filename or "<data>"
    if len(data) < 84:
        raise PrefetchError(f"{label}: truncated file ({len(data)} bytes)")
    if data[:4] == MAM_MAGIC:
        raise PrefetchError(
            f"{label}: compressed (MAM) prefetch is not supported — "
            "decompress the file before ingesting"
        )
    if data[PREFETCH_MAGIC_OFFSET : PREFETCH_MAGIC_OFFSET + 4] != PREFETCH_MAGIC:
        raise PrefetchError(f"{label}: not a Prefetch file (bad SCCA signature)")
    version = struct.unpack_from("<I", data, 0)[0]
    if version not in SUPPORTED_VERSIONS:
        raise PrefetchError(
            f"{label}: unsupported prefetch format version {version} "
            f"(supported: {', '.join(map(str, SUPPORTED_VERSIONS))})"
        )
    declared_size = struct.unpack_from("<I", data, 12)[0]
    executable = _utf16(data, 16, 60)
    if not executable:
        raise PrefetchError(f"{label}: empty executable name")
    prefetch_hash = struct.unpack_from("<I", data, 76)[0]

    info = PrefetchInfo(
        version=version,
        executable=executable,
        prefetch_hash=prefetch_hash,
        file_size=declared_size or len(data),
        run_count=0,
    )
    _parse_file_information(data, info, label=label)
    return info


def _parse_file_information(data: bytes, info: PrefetchInfo, *, label: str) -> None:
    """Fill run count, last runs, filenames and volumes for *info*."""
    base = 84  # file information starts right after the 84-byte header
    metrics_offset = _u32(data, base + 0)
    metrics_count = _u32(data, base + 4)
    filename_offset = _u32(data, base + 16)
    filename_size = _u32(data, base + 20)
    volumes_offset = _u32(data, base + 24)
    volume_count = _u32(data, base + 28)

    if info.version == 23:
        info.run_count = _u32(data, base + 68)
        last = filetime_to_iso(_u64(data, base + 44))
        info.last_runs = [last] if last else []
        _parse_volumes(data, info, volumes_offset, volume_count, 104, label)
    elif info.version in (26, 30):
        # v30 has two variants: metrics offset 0x130 -> run count at
        # +124 (variant 1), 0x128 -> run count at +116 (variant 2).
        # Volume entries: 104 bytes on v23/v26, 96 on v30.
        if info.version == 30 and metrics_offset == 0x128:
            run_count_off, vol_entry = base + 116, 96
        elif info.version == 30:
            run_count_off, vol_entry = base + 124, 96
        else:
            run_count_off, vol_entry = base + 124, 104
        info.run_count = _u32(data, run_count_off)
        runs: list[str] = []
        for index in range(8):
            stamp = filetime_to_iso(_u64(data, base + 44 + index * 8))
            if stamp:
                runs.append(stamp)
        info.last_runs = runs
        _parse_volumes(data, info, volumes_offset, volume_count, vol_entry, label)
    if metrics_count:
        _parse_filenames(
            data,
            info,
            metrics_offset,
            metrics_count,
            filename_offset,
            filename_size,
            label=label,
        )


def _parse_filenames(
    data: bytes,
    info: PrefetchInfo,
    metrics_offset: int,
    metrics_count: int,
    filename_offset: int,
    filename_size: int,
    *,
    label: str,
) -> None:
    """Extract referenced filenames via the file-metrics array."""
    if metrics_count > _MAX_METRICS_ENTRIES:
        raise PrefetchError(f"{label}: absurd metrics count {metrics_count}")
    if filename_size > _MAX_FILENAME_BYTES:
        raise PrefetchError(f"{label}: absurd filename section size {filename_size}")
    if filename_offset + filename_size > len(data):
        raise PrefetchError(f"{label}: filename strings run past end of file")
    strings = data[filename_offset : filename_offset + filename_size]
    entry_size = 32  # v23/v26/v30 metrics entries are all 32 bytes
    names: list[str] = []
    for index in range(metrics_count):
        entry_off = metrics_offset + index * entry_size
        if entry_off + entry_size > len(data):
            raise PrefetchError(f"{label}: metrics entry {index} past end of file")
        name_off = _u32(data, entry_off + 12)
        name_chars = _u32(data, entry_off + 16)
        name_bytes = name_chars * 2
        if name_off + name_bytes > len(strings):
            continue  # corrupt entry: skip, don't abort the file
        name = strings[name_off : name_off + name_bytes].decode(
            "utf-16-le", errors="replace"
        )
        if name:
            names.append(name)
    info.filenames = names


def _parse_volumes(
    data: bytes,
    info: PrefetchInfo,
    volumes_offset: int,
    volume_count: int,
    entry_size: int,
    label: str,
) -> None:
    """Extract volume device path / serial / creation time (v26/v30)."""
    if volume_count > _MAX_VOLUMES:
        raise PrefetchError(f"{label}: absurd volume count {volume_count}")
    for index in range(volume_count):
        entry_off = volumes_offset + index * entry_size
        if entry_off + 40 > len(data):
            raise PrefetchError(f"{label}: volume entry {index} past end of file")
        path_off = _u32(data, entry_off + 0)
        path_chars = _u32(data, entry_off + 4)
        created = filetime_to_iso(_u64(data, entry_off + 8))
        serial = _u32(data, entry_off + 16)
        abs_off = volumes_offset + path_off
        device_path = _utf16(data, abs_off, path_chars * 2)
        info.volumes.append(
            {
                "device_path": device_path,
                "serial": f"{serial:08X}",
                "created": created,
            }
        )


def prefetch_to_event(
    info: PrefetchInfo,
    *,
    source_file: str,
    record_index: int,
    source_sha256: str,
    ingest_time: str,
) -> NormalizedEvent:
    """One normalized execution-evidence event per Prefetch file."""
    timestamp = info.last_runs[0] if info.last_runs else ingest_time
    original = (
        f"FILETIME last run ({len(info.last_runs)} recorded)"
        if info.last_runs
        else None
    )
    raw_bits = [
        f"prefetch v{info.version} {info.executable}",
        f"run_count={info.run_count}",
        f"hash=0x{info.prefetch_hash:08X}",
        f"referenced_files={len(info.filenames)}",
    ]
    if info.volumes:
        raw_bits.append(f"volumes={len(info.volumes)}")
    return NormalizedEvent(
        timestamp=timestamp,
        timestamp_original=original,
        source="prefetch",
        event_id="prefetch",
        process_name=info.executable,
        file_path=info.executable,
        raw=excerpt(raw_bits),
        provenance=make_provenance(
            source_file=source_file,
            record_index=record_index,
            parser_name=PARSER_NAME,
            parser_version=PARSER_VERSION,
            ingest_time=ingest_time,
            source_sha256=source_sha256,
        ),
    )


def parse_prefetch_file(
    path: Path,
    *,
    source_sha256: str,
    ingest_time: str | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Parse one ``.pf`` file into normalized events (never raises)."""
    ingest_time = ingest_time or fresh_ingest_time()
    data = path.read_bytes()
    if len(data) > MAX_PARSE_BYTES:
        return [], [f"{path.name}: file exceeds size limit, skipped"]
    try:
        info = parse_prefetch(data, filename=path.name)
    except PrefetchError as exc:
        return [], [str(exc)]
    event = prefetch_to_event(
        info,
        source_file=str(path),
        record_index=0,
        source_sha256=source_sha256,
        ingest_time=ingest_time,
    )
    return [event], []
