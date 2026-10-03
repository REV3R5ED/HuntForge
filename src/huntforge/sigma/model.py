"""Sigma-inspired rule model (v0.6).

HuntForge supports a documented *subset* of Sigma — enough for the
common ``detection: selection: field: value`` shapes — in two input
forms:

1. **JSON** (preferred): a Sigma-inspired schema documented in
   ``docs/ATTACK.md`` (``title``, ``id``, ``logsource``,
   ``detection`` selections, ``condition``, ``level``, ``tags``).
2. **YAML** (best effort): real Sigma YAML goes through the minimal
   subset parser in :mod:`huntforge.sigma.yaml_subset`. Only flat
   ``key: value`` shapes work; anything fancier fails with a clear
   error naming the unsupported construct.

Supported detection features:
  - named selections mapping field names to a value or a list of
    values (list = OR within the field)
  - all fields in one selection must match (AND)
  - conditions: ``selection``, ``a and b``, ``a and not b``,
    ``a or b``, ``not a``, ``1 of sel*``, ``all of sel*``
    (``*`` globs over selection names)
  - ``*`` wildcards inside values (matched with fnmatch,
    case-insensitive)
  - Sigma field names are mapped to HuntForge event fields
    (see ``FIELD_ALIASES``); unknown fields are a validation error

NOT supported: ``|contains``/``|startswith``/``|endswith``/``|re``
modifiers (use ``*`` wildcards instead), aggregations
(``count() by ...``), ``near`` temporal correlation, nested
selections, keyword selections, multi-document files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class SigmaError(ValueError):
    """A Sigma rule file is invalid or uses unsupported features."""


#: Sigma field name (lowercased, without modifiers) -> HuntForge event field.
FIELD_ALIASES: dict[str, str] = {
    "image": "process_name",
    "processname": "process_name",
    "commandline": "command_line",
    "parentimage": "parent_name",
    "user": "user",
    "username": "user",
    "computer": "host",
    "computername": "host",
    "hostname": "host",
    "destinationip": "dst_ip",
    "destinationport": "dst_port",
    "sourceip": "src_ip",
    "sourceport": "src_port",
    "eventid": "event_id",
    "targetobject": "registry_key",
    "targetfilename": "file_path",
    "filename": "file_path",
    "details": "raw",
}

#: Sigma logsource category -> (event source, event ids) filter.
#: Unknown categories match all events (documented, not silent: the
#: rule's ``logsource`` is echoed in findings and listings).
LOGSOURCE_CATEGORIES: dict[str, tuple[str, tuple[str, ...]]] = {
    "process_creation": ("sysmon", ("1",)),
    "network_connection": ("sysmon", ("3",)),
    "image_load": ("sysmon", ("7",)),
    "file_event": ("sysmon", ("11",)),
    "registry_event": ("sysmon", ("12", "13", "14")),
    "ps_script": ("powershell", ("4103", "4104")),
    "powershell": ("powershell", ("4103", "4104")),
}

#: Sigma level -> HuntForge severity name.
LEVELS: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}

#: Confidence assigned from the rule author's level. A Sigma level is
#: the author's judgment, not HuntForge's analysis — the confidence
#: reason says so on every finding.
LEVEL_CONFIDENCE: dict[str, int] = {
    "critical": 85,
    "high": 70,
    "medium": 60,
    "low": 45,
    "informational": 30,
}


@dataclass(frozen=True)
class SigmaLogSource:
    product: str = ""
    category: str = ""
    service: str = ""
    definition: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "product": self.product,
            "category": self.category,
            "service": self.service,
            "definition": self.definition,
        }


@dataclass(frozen=True)
class SigmaRule:
    """A validated Sigma-subset rule."""

    id: str
    title: str
    detection: dict[str, dict[str, list[str]]]
    condition: str
    logsource: SigmaLogSource = field(default_factory=SigmaLogSource)
    description: str = ""
    author: str = ""
    date: str = ""
    level: str = "medium"
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    status: str = "experimental"
    source_format: str = "json"
    source_path: str = ""

    def selection_names(self) -> list[str]:
        return sorted(self.detection)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "author": self.author,
            "date": self.date,
            "status": self.status,
            "logsource": self.logsource.to_dict(),
            "detection": {
                name: dict(fields) for name, fields in self.detection.items()
            },
            "condition": self.condition,
            "level": self.level,
            "tags": list(self.tags),
            "falsepositives": list(self.falsepositives),
            "source_format": self.source_format,
            "source_path": self.source_path,
        }
