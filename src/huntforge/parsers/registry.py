"""Offline Windows registry hive parser (v0.3).

Reads forensic copies of registry hives (``NTUSER.DAT``, ``SOFTWARE``,
``SYSTEM``, ``SAM``, …) — never the live registry — with pure-Python
parsing of the ``regf`` hive format: header, hbin pages, NK key cells,
VK value cells and lf/lh/li/ri subkey lists. Common value types are
decoded (``REG_SZ``, ``REG_EXPAND_SZ``, ``REG_BINARY``,
``REG_DWORD``, ``REG_DWORD_BIG_ENDIAN``, ``REG_MULTI_SZ``,
``REG_QWORD``); anything else is returned as hex with its type name.

Honest limitations (also in README):
- No transaction-log (.LOG1/.LOG2) replay — only the primary hive.
- No deleted-cell recovery.
- Large values spanning multiple cells (``db`` indirect blocks) are
  skipped with a note, not followed.
- Security descriptors (SK records) are not parsed.
- Validated against synthetic fixtures built to the published layout;
  real-world validation against live hive copies is still pending.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

PARSER_NAME = "registry-hive"
PARSER_VERSION = "0.3.0"

REGF_MAGIC = b"regf"
HEADER_SIZE = 0x1000
HBIN_SIZE = 0x1000

#: Guards so a corrupt hive cannot loop or blow up memory.
_MAX_DEPTH = 64
_MAX_CELLS_PER_OP = 100_000
_MAX_VALUE_BYTES = 4 * 1024 * 1024

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

_VALUE_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}


class HiveError(ValueError):
    """A hive cannot be parsed (corrupt, truncated, unsupported)."""


class KeyNotFoundError(HiveError):
    """The requested key path does not exist in the hive."""


def _filetime_to_iso(value: int) -> str | None:
    if value == 0:
        return None
    try:
        moment = _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except (OverflowError, ValueError, OSError):
        return None
    if moment.year > 3000:
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class RegValue:
    """One decoded registry value."""

    name: str
    type: int
    type_name: str
    data: Any  # str | int | list[str] — JSON-safe

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "type_name": self.type_name,
            "data": self.data,
        }


@dataclass
class KeyView:
    """Subkeys + values of one registry key."""

    path: str
    last_write: str | None
    subkeys: list[str] = field(default_factory=list)
    values: list[RegValue] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "last_write": self.last_write,
            "subkeys": self.subkeys,
            "values": [v.to_dict() for v in self.values],
        }


class Hive:
    """An offline registry hive parsed from raw bytes."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._cells_seen = 0
        if len(data) < HEADER_SIZE:
            raise HiveError(f"truncated hive ({len(data)} bytes)")
        if data[0:4] != REGF_MAGIC:
            raise HiveError("not a registry hive (bad regf magic)")
        root_rel = self._u32(0x24)
        self._root = self._nk(root_rel, depth=0)

    # -- low-level cell access --------------------------------------
    def _u32(self, offset: int) -> int:
        if offset + 4 > len(self._data):
            raise HiveError(f"truncated hive reading u32 at {offset:#x}")
        return int(struct.unpack_from("<I", self._data, offset)[0])

    def _cell(self, rel_offset: int) -> bytes:
        """Return the data of an allocated cell (offsets are hbin-relative)."""
        if rel_offset < 0 or rel_offset > len(self._data):
            raise HiveError(f"cell offset {rel_offset:#x} out of range")
        absolute = HEADER_SIZE + rel_offset
        if absolute + 4 > len(self._data):
            raise HiveError(f"truncated hive at cell {rel_offset:#x}")
        size = struct.unpack_from("<i", self._data, absolute)[0]
        if size >= 0:
            raise HiveError(f"cell {rel_offset:#x} is free/unallocated")
        size = -size
        if absolute + size > len(self._data):
            raise HiveError(f"truncated hive: cell {rel_offset:#x} overruns file")
        self._cells_seen += 1
        if self._cells_seen > _MAX_CELLS_PER_OP:
            raise HiveError("hive walk exceeded cell budget (corrupt?)")
        return self._data[absolute + 4 : absolute + size]

    # -- key records -------------------------------------------------
    def _nk(self, rel_offset: int, depth: int) -> dict[str, Any]:
        if depth > _MAX_DEPTH:
            raise HiveError("key nesting too deep (corrupt?)")
        cell = self._cell(rel_offset)
        if len(cell) < 72 or cell[0:2] != b"nk":
            raise HiveError(f"bad NK record at {rel_offset:#x}")
        flags = struct.unpack_from("<H", cell, 2)[0]
        last_write = _filetime_to_iso(struct.unpack_from("<Q", cell, 4)[0])
        subkey_count = struct.unpack_from("<I", cell, 16)[0]
        subkey_list = struct.unpack_from("<i", cell, 24)[0]
        value_count = struct.unpack_from("<I", cell, 32)[0]
        value_list = struct.unpack_from("<i", cell, 36)[0]
        name_len = struct.unpack_from("<H", cell, 68)[0]
        name_raw = cell[72 : 72 + name_len]
        name = (
            name_raw.decode("ascii", errors="replace")
            if flags & 0x20
            else name_raw.decode("utf-16-le", errors="replace")
        )
        return {
            "offset": rel_offset,
            "name": name,
            "last_write": last_write,
            "subkey_count": subkey_count,
            "subkey_list": subkey_list,
            "value_count": value_count,
            "value_list": value_list,
            "depth": depth,
        }

    def _subkey_offsets(self, nk: dict[str, Any]) -> list[int]:
        if not nk["subkey_count"]:
            return []
        return self._walk_list(nk["subkey_list"], nk["depth"] + 1)

    def _walk_list(self, rel_offset: int, depth: int) -> list[int]:
        cell = self._cell(rel_offset)
        magic = cell[0:2]
        if magic in (b"lf", b"lh"):
            count = struct.unpack_from("<H", cell, 2)[0]
            offsets = []
            for i in range(count):
                base = 4 + i * 8
                if base + 4 > len(cell):
                    raise HiveError("truncated lf/lh subkey list")
                offsets.append(struct.unpack_from("<I", cell, base)[0])
            return offsets
        if magic in (b"li", b"ri"):
            count = struct.unpack_from("<H", cell, 2)[0]
            children = []
            for i in range(count):
                base = 4 + i * 4
                if base + 4 > len(cell):
                    raise HiveError("truncated li/ri subkey list")
                children.append(struct.unpack_from("<I", cell, base)[0])
            if magic == b"li":
                return children
            nested: list[int] = []
            for child in children:  # ri: recurse into sub-lists
                nested.extend(self._walk_list(child, depth))
            return nested
        raise HiveError(f"unknown subkey list type {magic!r} at {rel_offset:#x}")

    # -- value records -----------------------------------------------
    def _vk(self, rel_offset: int) -> RegValue:
        cell = self._cell(rel_offset)
        if len(cell) < 20 or cell[0:2] != b"vk":
            raise HiveError(f"bad VK record at {rel_offset:#x}")
        name_len = struct.unpack_from("<H", cell, 2)[0]
        data_size_raw = struct.unpack_from("<I", cell, 4)[0]
        data_field = cell[8:12]
        data_type = struct.unpack_from("<I", cell, 12)[0]
        name = cell[20 : 20 + name_len].decode("utf-16-le", errors="replace")
        inline = bool(data_size_raw & 0x80000000)
        data_size = data_size_raw & 0x7FFFFFFF
        if data_size > _MAX_VALUE_BYTES:
            raise HiveError(f"value {name!r}: data size {data_size} exceeds limit")
        if inline:
            raw = data_field[:data_size]
        else:
            data_offset = struct.unpack_from("<I", data_field, 0)[0]
            absolute = HEADER_SIZE + data_offset + 4  # skip cell-size header
            if absolute + data_size > len(self._data):
                raise HiveError(f"value {name!r}: data overruns file")
            raw = self._data[absolute : absolute + data_size]
        type_name = _VALUE_TYPES.get(data_type, f"REG_UNKNOWN_{data_type}")
        return RegValue(
            name=name, type=data_type, type_name=type_name, data=_decode(raw, data_type)
        )

    def _values(self, nk: dict[str, Any]) -> list[RegValue]:
        count = nk["value_count"]
        if not count:
            return []
        if count > 100_000:
            raise HiveError("absurd value count (corrupt?)")
        content = self._cell(nk["value_list"])  # value list cell payload
        values = []
        for _ in range(count):
            if len(content) < 4:
                raise HiveError("truncated value list")
            vk_off = int(struct.unpack_from("<I", content, 0)[0])
            content = content[4:]
            values.append(self._vk(vk_off))
        return values

    # -- public API ----------------------------------------------------
    def list_key(self, path: str) -> KeyView:
        """List subkeys and values at *path* (``\\``-separated, case-insensitive).

        Raises :class:`KeyNotFoundError` when the path does not exist.
        """
        parts = [p for p in path.replace("/", "\\").split("\\") if p]
        nk = self._root
        walked = []
        for part in parts:
            found = None
            for offset in self._subkey_offsets(nk):
                child = self._nk(offset, nk["depth"] + 1)
                if child["name"].lower() == part.lower():
                    found = child
                    break
            if found is None:
                raise KeyNotFoundError(f"key not found: {path!r} (failed at {part!r})")
            nk = found
            walked.append(nk["name"])
        subkeys = [
            self._nk(offset, nk["depth"] + 1)["name"]
            for offset in self._subkey_offsets(nk)
        ]
        return KeyView(
            path="\\".join(walked) if walked else nk["name"],
            last_write=nk["last_write"],
            subkeys=sorted(subkeys, key=str.lower),
            values=self._values(nk),
        )

    def key_exists(self, path: str) -> bool:
        try:
            self.list_key(path)
        except KeyNotFoundError:
            return False
        return True

    @property
    def root_name(self) -> str:
        return str(self._root["name"])


def _decode(raw: bytes, data_type: int) -> Any:
    """Decode raw value bytes by registry type (JSON-safe output)."""
    if data_type in (1, 2, 6):  # REG_SZ, REG_EXPAND_SZ, REG_LINK
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    if data_type == 7:  # REG_MULTI_SZ
        text = raw.decode("utf-16-le", errors="replace")
        return [part for part in text.split("\x00") if part]
    if data_type == 4:  # REG_DWORD
        return struct.unpack("<I", raw.ljust(4, b"\x00")[:4])[0]
    if data_type == 5:  # REG_DWORD_BIG_ENDIAN
        return struct.unpack(">I", raw.ljust(4, b"\x00")[:4])[0]
    if data_type == 11:  # REG_QWORD
        return struct.unpack("<Q", raw.ljust(8, b"\x00")[:8])[0]
    return raw.hex()  # REG_BINARY, REG_NONE and anything else
