"""Analyst config file support (v0.9): ``~/.huntforge/config.toml`` or ``--config``.

Stdlib-only. Python 3.11+ uses ``tomllib``; 3.10 falls back to a tiny
TOML-subset reader (top-level ``key = "value"`` pairs and ``#``
comments only) — config stays best-effort on 3.10, never fatal.

Known keys (all optional, all strings):

- ``state_dir`` — default state directory (below ``--state-dir`` and
  ``HUNTFORGE_STATE_DIR`` in precedence).
- ``default_severity`` — default ``detect --severity`` filter, one of
  informational/low/medium/high/critical.
- ``analyst_name`` — default author for ``notes --add``.

Unknown keys are kept as warnings, never errors. Invalid values raise
``ConfigError`` naming the file and line.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):  # pragma: no cover - exercised on 3.12
    import tomllib
else:  # Python 3.10: TOML-subset reader below
    tomllib = None  # type: ignore[assignment]

CONFIG_FILENAME = "config.toml"
CONFIG_DIR_NAME = ".huntforge"

KNOWN_KEYS = ("state_dir", "default_severity", "analyst_name")

SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})

# TOML-subset reader (3.10 fallback): key = "value" with # comments.
_PAIR_RE = re.compile(
    r"""^\s*([A-Za-z0-9_.\-]+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*(?:\#.*)?$"""
)
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}


class ConfigError(Exception):
    """Raised for unreadable or invalid config files."""


@dataclass
class AppConfig:
    """Parsed analyst config. ``source`` is the file loaded, None if none."""

    source: str | None = None
    state_dir: str | None = None
    default_severity: str | None = None
    analyst_name: str | None = None
    warnings: list[str] = field(default_factory=list)


def find_config_file(explicit: str | None = None) -> Path | None:
    """Locate the config file: ``--config`` wins, else ``~/.huntforge/config.toml``."""
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"config file not found: {explicit}")
        return path
    candidate = Path.home() / CONFIG_DIR_NAME / CONFIG_FILENAME
    return candidate if candidate.is_file() else None


def _unescape(raw: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            out.append(_ESCAPES.get(nxt, nxt))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _read_toml_subset(path: Path) -> dict[str, tuple[str, int]]:
    """Parse top-level string pairs; returns {key: (value, line_no)}.

    Used only on Python < 3.11. Anything fancier (tables, arrays) is a
    ``ConfigError`` with a hint to use 3.11+ — config must never silently
    misread.
    """
    values: dict[str, tuple[str, int]] = {}
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _PAIR_RE.match(line)
        if not match:
            raise ConfigError(
                f"{path}:{line_no}: unsupported config syntax "
                f'(3.10 reads only top-level key = "value" pairs; '
                f"use Python 3.11+ for full TOML)"
            )
        key, raw_value = match.group(1), match.group(2)
        values[key] = (_unescape(raw_value), line_no)
    return values


def _load_values(path: Path) -> dict[str, tuple[str, int]]:
    """Load (value, line_no) pairs via tomllib (3.11+) or the subset reader."""
    if tomllib is None:  # Python 3.10
        return _read_toml_subset(path)
    try:
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
    except Exception as exc:
        raise ConfigError(f"{path}: cannot parse TOML: {exc}") from exc
    values: dict[str, tuple[str, int]] = {}
    for key, value in raw.items():
        if isinstance(value, str):
            values[str(key)] = (value, 0)
        else:
            raise ConfigError(
                f"{path}: key {key!r} must be a string (got {type(value).__name__})"
            )
    return values


def load_config(explicit: str | None = None) -> AppConfig:
    """Load analyst config; empty config when no file exists."""
    path = find_config_file(explicit)
    config = AppConfig()
    if path is None:
        return config
    config.source = str(path)
    values = _load_values(path)
    for key, (value, line_no) in values.items():
        if key not in KNOWN_KEYS:
            config.warnings.append(
                f"unknown config key {key!r} ignored ({config.source})"
            )
            continue
        if key == "default_severity" and value.lower() not in SEVERITIES:
            where = f"{path}:{line_no}" if line_no else str(path)
            raise ConfigError(
                f"{where}: default_severity must be one of "
                f"{sorted(SEVERITIES)} (got {value!r})"
            )
        if key == "default_severity":
            config.default_severity = value.lower()
        elif key == "state_dir":
            config.state_dir = value
        elif key == "analyst_name":
            config.analyst_name = value
    return config


def to_dict(config: AppConfig) -> dict[str, Any]:
    """Config as JSON-safe data (for the result envelope)."""
    return {
        "source": config.source,
        "state_dir": config.state_dir,
        "default_severity": config.default_severity,
        "analyst_name": config.analyst_name,
        "warnings": list(config.warnings),
    }
