"""Module/plugin registration for HuntForge phases.

The core module (v0.1: CLI, event model, store, ingest stub) is
registered here. Later phases (parsers, timeline, detection, sigma,
correlation, reporting, UI) register themselves the same way — either
by calling :func:`register` at import time or via
``importlib.metadata`` entry points under the ``huntforge.modules``
group.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import metadata
from typing import Any

ENTRY_POINT_GROUP = "huntforge.modules"


@dataclass
class ModuleInfo:
    name: str
    description: str
    version: str = "0.1.0"
    commands: list[str] = field(default_factory=list)
    factory: Callable[[], Any] | None = None


class ModuleRegistry:
    """Registry of HuntForge capability modules."""

    def __init__(self) -> None:
        self._modules: dict[str, ModuleInfo] = {}

    def register(self, info: ModuleInfo) -> None:
        if info.name in self._modules:
            raise ValueError(f"module {info.name!r} is already registered")
        self._modules[info.name] = info

    def get(self, name: str) -> ModuleInfo:
        try:
            return self._modules[name]
        except KeyError:
            raise KeyError(f"unknown module {name!r}") from None

    def names(self) -> list[str]:
        return sorted(self._modules)

    def discover(self) -> None:
        """Load modules advertised via entry points (best effort)."""
        # importlib.metadata.entry_points() changed shape across 3.10-3.13
        # (dict -> SelectableGroups -> EntryPoints); handle them all.
        raw: Any = metadata.entry_points()
        if hasattr(raw, "select"):  # Python 3.10/3.11
            entry_points = raw.select(group=ENTRY_POINT_GROUP)
        elif hasattr(raw, "items"):  # very old dict form
            entry_points = raw.get(ENTRY_POINT_GROUP, ())
        else:  # Python 3.12+ EntryPoints tuple
            entry_points = [ep for ep in raw if ep.group == ENTRY_POINT_GROUP]
        for ep in entry_points:
            try:
                factory = ep.load()
                info = factory() if callable(factory) else factory
                self.register(info)
            except Exception:
                continue  # pragma: no cover - plugin load is best effort

    def to_dict(self) -> list[dict[str, Any]]:
        return [
            {
                "name": m.name,
                "description": m.description,
                "version": m.version,
                "commands": m.commands,
            }
            for m in (self._modules[n] for n in self.names())
        ]


_registry = ModuleRegistry()


def get_registry() -> ModuleRegistry:
    return _registry


def register(info: ModuleInfo) -> None:
    _registry.register(info)
