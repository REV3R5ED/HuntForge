"""Shared fixtures for HuntForge tests.

``isolated_state`` points ``HUNTFORGE_STATE_DIR`` at a fresh tmp dir so
tests never touch the real ``~/.huntforge``. ``case_db`` creates a case
named ``CASE-001`` in it.
"""

from __future__ import annotations

import json
import struct
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


# ---------------------------------------------------------------------------
# v0.3 synthetic forensic fixtures (built programmatically, never real data)
# ---------------------------------------------------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402


def datetime_to_filetime(moment: datetime) -> int:
    """UTC datetime -> Windows FILETIME (100-ns ticks since 1601-01-01)."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    delta = moment.astimezone(timezone.utc) - epoch
    return int(delta.total_seconds() * 10_000_000)


def build_prefetch(
    *,
    version: int = 30,
    executable: str = "MALWARE.EXE",
    run_count: int = 14,
    last_runs: list[datetime] | None = None,
    filenames: list[str] | None = None,
    volume_path: str = "\\Device\\HarddiskVolume2",
    serial: int = 0xA1B2C3D4,
) -> bytes:
    """Build a synthetic Prefetch (.pf) file to the published layout.

    v23: 156-byte file info (run count at +68, one FILETIME at +44);
    v26/v30: 220-byte file info (run count at +124, eight FILETIMEs).
    """
    if version not in (23, 26, 30):
        raise ValueError(f"unsupported fixture version {version}")
    now = datetime.now(timezone.utc)
    if last_runs is None:
        last_runs = [now - timedelta(hours=2), now - timedelta(days=1)]
    if filenames is None:
        filenames = [
            "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\TEMP\\MALWARE.EXE",
            "\\DEVICE\\HARDDISKVOLUME2\\WINDOWS\\SYSTEM32\\KERNEL32.DLL",
        ]
    info_size = 156 if version == 23 else 220
    metrics_offset = 84 + info_size
    name_blob = executable.encode("utf-16-le")[:60].ljust(60, b"\x00")

    header = struct.pack(
        "<I4sII60sII",
        version,
        b"SCCA",
        0x11,
        0,  # file size patched at the end
        name_blob,
        0xDEADBEEF,
        0,
    )
    assert len(header) == 84

    info = bytearray(info_size)
    struct.pack_into("<I", info, 0, metrics_offset)
    struct.pack_into("<I", info, 4, len(filenames))
    # trace chains: offset 0 / count 0 (not parsed by HuntForge)
    if version == 23:
        struct.pack_into("<Q", info, 44, datetime_to_filetime(last_runs[0]))
        struct.pack_into("<I", info, 68, run_count)
    else:
        for index, moment in enumerate(last_runs[:8]):
            struct.pack_into("<Q", info, 44 + index * 8, datetime_to_filetime(moment))
        struct.pack_into("<I", info, 124, run_count)

    filename_offset = metrics_offset + len(filenames) * 32
    strings = b"".join(name.encode("utf-16-le") + b"\x00\x00" for name in filenames)
    struct.pack_into("<I", info, 16, filename_offset)
    struct.pack_into("<I", info, 20, len(strings))

    metrics = bytearray()
    string_off = 0
    for name in filenames:
        encoded = name.encode("utf-16-le")
        metrics += struct.pack("<IIIIIIQ", 0, 0, 0, string_off, len(encoded) // 2, 0, 0)
        string_off += len(encoded) + 2

    volumes_offset = filename_offset + len(strings)
    vol_entry_size = 104 if version != 30 else 96
    struct.pack_into("<I", info, 24, volumes_offset)
    struct.pack_into("<I", info, 28, 1)
    struct.pack_into("<I", info, 32, vol_entry_size + len(volume_path) * 2 + 2)
    vol_entry = bytearray(vol_entry_size)
    struct.pack_into("<I", vol_entry, 0, vol_entry_size)  # path rel. to vol info
    struct.pack_into("<I", vol_entry, 4, len(volume_path))
    struct.pack_into("<Q", vol_entry, 8, datetime_to_filetime(now - timedelta(days=30)))
    struct.pack_into("<I", vol_entry, 16, serial)
    vol_blob = bytes(vol_entry) + volume_path.encode("utf-16-le") + b"\x00\x00"

    blob = header + bytes(info) + bytes(metrics) + strings + vol_blob
    blob = bytearray(blob)
    struct.pack_into("<I", blob, 12, len(blob))  # declared file size
    return bytes(blob)


class _HiveBuilder:
    """Minimal registry-hive writer (cells are 8-byte aligned)."""

    def __init__(self) -> None:
        self._cells: list[tuple[int, bytes]] = []
        self._next = 0x20

    def alloc(self, payload: bytes) -> int:
        size = 4 + len(payload)
        size = (size + 7) & ~7
        offset = self._next
        self._next += size
        cell = struct.pack("<i", -size) + payload + b"\x00" * (size - 4 - len(payload))
        self._cells.append((offset, cell))
        return offset

    def data_cell(self, data: bytes) -> int:
        # Real hives store value data directly after the cell-size
        # header (the VK record carries the length); no length prefix.
        return self.alloc(data)

    def vk(self, name: str, vtype: int, data: bytes) -> int:
        name_b = name.encode("utf-16-le")
        if len(data) <= 4:
            size_field = 0x80000000 | len(data)
            data_field = data.ljust(4, b"\x00")
        else:
            size_field = len(data)
            data_field = struct.pack("<I", self.data_cell(data))
        payload = (
            b"vk"
            + struct.pack("<H", len(name_b))
            + struct.pack("<I", size_field)
            + data_field
            + struct.pack("<I", vtype)
            + struct.pack("<HH", 0, 0)
            + name_b
        )
        return self.alloc(payload)

    def lf(self, children: list[int]) -> int:
        payload = (
            b"lf"
            + struct.pack("<H", len(children))
            + b"".join(struct.pack("<II", off, 0) for off in children)
        )
        return self.alloc(payload)

    def nk(
        self,
        name: str,
        *,
        timestamp: datetime,
        parent: int = -1,
        subkeys: list[int] | None = None,
        values: list[int] | None = None,
    ) -> int:
        subkeys = subkeys or []
        values = values or []
        list_off = self.lf(subkeys) if subkeys else -1
        value_list = (
            self.alloc(b"".join(struct.pack("<I", v) for v in values)) if values else -1
        )
        name_b = name.encode("ascii")  # flag 0x20: ASCII/compressed name
        payload = (
            b"nk"
            + struct.pack("<H", 0x20)
            + struct.pack("<Q", datetime_to_filetime(timestamp))
            + struct.pack("<i", parent)
            + struct.pack("<I", len(subkeys))
            + struct.pack("<I", 0)  # volatile subkeys
            + struct.pack("<i", list_off)
            + struct.pack("<i", -1)
            + struct.pack("<I", len(values))
            + struct.pack("<i", value_list)
            + struct.pack("<i", -1)  # security
            + struct.pack("<i", -1)  # class
            + struct.pack("<IIII", 0, 0, 0, 0)
            + struct.pack("<I", 0)
            + struct.pack("<H", len(name_b))
            + struct.pack("<H", 0)
            + name_b
        )
        return self.alloc(payload)


def _sz(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def build_hive(
    *,
    timestamp: datetime | None = None,
    run_values: list[tuple[str, str]] | None = None,
) -> bytes:
    """Build a synthetic hive with Run/RunOnce keys and a Services tree.

    Layout (all under a ``ROOT`` key)::

        Software\\Microsoft\\Windows\\CurrentVersion\\Run      (REG_SZ values)
        Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce  (1 REG_SZ)
        ControlSet001\\Services\\BadSvc   (ImagePath/Start/Type/ObjectName/DisplayName)
        ControlSet001\\Services\\GoodSvc  (ImagePath/Start/ObjectName)

    ``run_values`` overrides the default Run key entries as
    ``(name, command)`` pairs.
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc) - timedelta(days=1)
    b = _HiveBuilder()

    def key(name: str, children: dict[str, int], values: list[int]) -> int:
        # children: name -> offset (built bottom-up by the caller)
        return b.nk(
            name, timestamp=timestamp, subkeys=list(children.values()), values=values
        )

    if run_values is None:
        run_values = [
            ("Updater", "C:\\Users\\test\\AppData\\Roaming\\updater.exe --silent"),
            ("BadThing", "C:\\Temp\\evil.exe"),
        ]
    run_value_cells = [b.vk(name, 1, _sz(command)) for name, command in run_values]
    runonce_values = [b.vk("Once", 1, _sz("C:\\Windows\\Temp\\once.exe /q"))]
    run = key("Run", {}, run_value_cells)
    runonce = key("RunOnce", {}, runonce_values)
    current_version = key("CurrentVersion", {"Run": run, "RunOnce": runonce}, [])
    windows = key("Windows", {"CurrentVersion": current_version}, [])
    microsoft = key("Microsoft", {"Windows": windows}, [])
    software = key("Software", {"Microsoft": microsoft}, [])

    badsvc_values = [
        b.vk("DisplayName", 1, _sz("Bad Service")),
        b.vk("ImagePath", 2, _sz("C:\\Temp\\badsvc.exe -k netsvcs")),
        b.vk("Start", 4, struct.pack("<I", 2)),
        b.vk("Type", 4, struct.pack("<I", 0x10)),
        b.vk("ObjectName", 1, _sz("LocalSystem")),
    ]
    goodsvc_values = [
        b.vk("ImagePath", 2, _sz("C:\\Windows\\System32\\svchost.exe -k netsvcs")),
        b.vk("Start", 4, struct.pack("<I", 3)),
        b.vk("ObjectName", 1, _sz("NT AUTHORITY\\NetworkService")),
    ]
    badsvc = key("BadSvc", {}, badsvc_values)
    goodsvc = key("GoodSvc", {}, goodsvc_values)
    services = key("Services", {"BadSvc": badsvc, "GoodSvc": goodsvc}, [])
    ccs = key("ControlSet001", {"Services": services}, [])

    root = key("ROOT", {"Software": software, "ControlSet001": ccs}, [])
    root_offset = root  # cells are allocated bottom-up; root is last

    hbin = bytearray(0x1000)
    hbin[0:4] = b"hbin"
    struct.pack_into("<I", hbin, 4, 0)  # offset of this bin
    struct.pack_into("<I", hbin, 8, 0x1000)  # bin size
    for offset, cell in b._cells:
        hbin[offset : offset + len(cell)] = cell
    # trailing free cell
    free_start = b._next
    free_size = 0x1000 - free_start
    struct.pack_into("<i", hbin, free_start, free_size)

    header = bytearray(0x1000)
    header[0:4] = b"regf"
    struct.pack_into("<II", header, 4, 1, 1)
    struct.pack_into("<Q", header, 0x0C, datetime_to_filetime(timestamp))
    struct.pack_into("<II", header, 0x14, 1, 5)
    struct.pack_into("<I", header, 0x24, root_offset)  # root cell offset
    struct.pack_into("<I", header, 0x28, 0x1000)  # hive bins size
    header[0x30 : 0x30 + 18] = "SYNTHETIC".encode("utf-16-le")
    checksum = 0
    for index in range(0, 0x1FC, 4):
        checksum ^= struct.unpack_from("<I", header, index)[0]
    struct.pack_into("<I", header, 0x1FC, checksum & 0xFFFFFFFF)
    return bytes(header) + bytes(hbin)
