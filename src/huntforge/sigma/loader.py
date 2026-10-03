"""Load Sigma-subset rules from JSON or YAML files (v0.6).

JSON is the preferred, fully-documented form. YAML goes through the
minimal subset parser (:mod:`huntforge.sigma.yaml_subset`) and then
through the same validation, so both forms produce identical
:class:`SigmaRule` objects.
"""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from typing import Any

from huntforge.sigma.model import (
    FIELD_ALIASES,
    LEVELS,
    LOGSOURCE_CATEGORIES,
    SigmaError,
    SigmaLogSource,
    SigmaRule,
)
from huntforge.sigma.yaml_subset import YamlSubsetError
from huntforge.sigma.yaml_subset import parse as parse_yaml

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TECHNIQUE_TAG_RE = re.compile(r"^attack\.t(\d{4})(\.(\d{3}))?$", re.IGNORECASE)


def _require_str(mapping: dict[str, Any], key: str, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SigmaError(f"{where}: {key!r} must be a non-empty string")
    return value.strip()


def _normalize_values(value: Any, where: str) -> list[str]:
    """One scalar or a list of scalars -> list of strings."""
    items = value if isinstance(value, list) else [value]
    if not items:
        raise SigmaError(f"{where}: value list must not be empty")
    normalized: list[str] = []
    for item in items:
        if isinstance(item, bool) or not isinstance(item, (str, int)):
            raise SigmaError(
                f"{where}: values must be strings or integers, "
                f"got {item!r} (modifiers like '|contains' are not supported)"
            )
        normalized.append(str(item))
    return normalized


def _validate_detection(
    detection: Any,
) -> tuple[dict[str, dict[str, list[str]]], str]:
    """Validate the detection block; returns (selections, condition)."""
    if not isinstance(detection, dict) or not detection:
        raise SigmaError("detection: must be a non-empty mapping")
    raw_condition = detection.get("condition", "")
    if not isinstance(raw_condition, str) or not raw_condition.strip():
        raise SigmaError(
            "detection: needs a 'condition' string "
            "(e.g. 'selection', 'a and not b', '1 of sel*')"
        )
    selections: dict[str, dict[str, list[str]]] = {}
    for name, body in detection.items():
        if name == "condition":
            continue
        if not isinstance(name, str) or not name:
            raise SigmaError("detection: selection names must be strings")
        if not isinstance(body, dict) or not body:
            raise SigmaError(
                f"detection: selection {name!r} must be a non-empty "
                f"field -> value mapping"
            )
        fields: dict[str, list[str]] = {}
        for raw_field, value in body.items():
            if not isinstance(raw_field, str):
                raise SigmaError(
                    f"detection: selection {name!r}: field names must be strings"
                )
            if "|" in raw_field:
                base, _, modifier = raw_field.partition("|")
                raise SigmaError(
                    f"detection: selection {name!r}: field modifier "
                    f"'{raw_field}' is not supported "
                    f"(use '*' wildcards instead of '|{modifier}')"
                )
            alias = FIELD_ALIASES.get(raw_field.strip().lower())
            if alias is None:
                valid = ", ".join(sorted(FIELD_ALIASES))
                raise SigmaError(
                    f"detection: selection {name!r}: unknown field "
                    f"{raw_field!r} (supported Sigma fields: {valid})"
                )
            where = f"detection: selection {name!r} field {raw_field!r}"
            fields.setdefault(alias, []).extend(_normalize_values(value, where))
        selections[name] = fields
    # The condition must reference real selections; full grammar checking
    # happens in the engine, but unknown names are caught here. Glob
    # prefixes ("1 of sel*") are allowed when they match at least one
    # selection.
    names = set(selections)
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", raw_condition):
        lowered = token.lower()
        if lowered in ("and", "or", "not", "of", "all"):
            continue
        if token.isdigit():
            continue
        if "*" in token:
            continue  # glob over selection names, resolved by the engine
        if token not in names and not any(
            fnmatch.fnmatchcase(name, token + "*") for name in names
        ):
            raise SigmaError(
                f"detection: condition references unknown selection "
                f"{token!r} (defined: {', '.join(sorted(names))})"
            )
    return selections, raw_condition.strip()


def _validate_tags(tags: Any) -> list[str]:
    if tags is None:
        return []
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise SigmaError("tags: must be a list of strings")
    return [t.strip() for t in tags if t.strip()]


def rule_from_mapping(
    data: dict[str, Any], source_format: str, source_path: str
) -> SigmaRule:
    """Validate a parsed mapping into a :class:`SigmaRule`."""
    if not isinstance(data, dict):
        raise SigmaError("rule file must contain a mapping at the top level")
    where = f"rule {source_path or '<memory>'}"
    title = _require_str(data, "title", where)
    rule_id = _require_str(data, "id", where)
    if not _ID_RE.match(rule_id):
        raise SigmaError(f"{where}: id {rule_id!r} has invalid characters")
    description = data.get("description", "")
    if description is not None and not isinstance(description, str):
        raise SigmaError(f"{where}: description must be a string")
    level = str(data.get("level", "medium")).strip().lower()
    if level not in LEVELS:
        raise SigmaError(
            f"{where}: level {level!r} is unknown "
            f"(expected one of: {', '.join(sorted(LEVELS))})"
        )
    raw_logsource = data.get("logsource", {})
    if isinstance(raw_logsource, SigmaLogSource):
        logsource = raw_logsource
    else:
        if not isinstance(raw_logsource, dict):
            raise SigmaError(f"{where}: logsource must be a mapping")
        logsource = SigmaLogSource(
            product=str(raw_logsource.get("product", "") or ""),
            category=str(raw_logsource.get("category", "") or ""),
            service=str(raw_logsource.get("service", "") or ""),
            definition=str(raw_logsource.get("definition", "") or ""),
        )
    selections, condition = _validate_detection(data.get("detection"))
    falsepositives = data.get("falsepositives", [])
    if falsepositives is None:
        falsepositives = []
    if not isinstance(falsepositives, list) or not all(
        isinstance(item, str) for item in falsepositives
    ):
        raise SigmaError(f"{where}: falsepositives must be a list of strings")
    return SigmaRule(
        id=rule_id,
        title=title,
        detection=selections,
        condition=condition,
        logsource=logsource,
        description=str(description or ""),
        author=str(data.get("author", "") or ""),
        date=str(data.get("date", "") or ""),
        level=level,
        tags=_validate_tags(data.get("tags")),
        falsepositives=[item for item in falsepositives],
        status=str(data.get("status", "experimental") or "experimental"),
        source_format=source_format,
        source_path=source_path,
    )


def technique_ids_from_tags(tags: list[str]) -> list[str]:
    """``attack.t1059.001`` tags -> ``['T1059.001']`` (order preserved)."""
    found: list[str] = []
    for tag in tags:
        match = _TECHNIQUE_TAG_RE.match(tag.strip())
        if match:
            tid = f"T{match.group(1)}"
            if match.group(3):
                tid += f".{match.group(3)}"
            if tid not in found:
                found.append(tid)
    return found


def logsource_filter(logsource: SigmaLogSource) -> tuple[str, tuple[str, ...]] | None:
    """(event source, event ids) the rule applies to, or None for all."""
    category = logsource.category.strip().lower()
    if category in LOGSOURCE_CATEGORIES:
        return LOGSOURCE_CATEGORIES[category]
    service = logsource.service.strip().lower()
    if service == "security":
        return ("evtx:Security", ())
    if service == "sysmon":
        return ("sysmon", ())
    if service == "powershell":
        return ("powershell", ("4103", "4104"))
    return None


def _resolve_sample(name: str, original: str | Path) -> Path:
    """Find a bundled sample by file stem or by rule id."""
    samples_dir = Path(__file__).parent / "samples"
    stem = Path(name).stem
    for sample in sorted(samples_dir.glob("*")):
        if sample.suffix.lower() not in (".json", ".yaml", ".yml"):
            continue
        if sample.stem == stem:
            return sample
    for sample in sorted(samples_dir.glob("*")):
        if sample.suffix.lower() not in (".json", ".yaml", ".yml"):
            continue
        try:
            if load_rule_file(sample).id == name:
                return sample
        except SigmaError:
            continue
    raise SigmaError(f"rule file not found: {original}")


def load_rule_file(path: str | Path) -> SigmaRule:
    """Load one Sigma rule from a JSON or YAML file (.json/.yaml/.yml)."""
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        # Also resolve bare names against the bundled samples: first by
        # file stem ("rare_outbound_port"), then by rule id
        # ("hf-sigma-0004").
        file_path = _resolve_sample(file_path.name, path)
    suffix = file_path.suffix.lower()
    try:
        text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SigmaError(f"cannot read rule file {file_path}: {exc}") from exc
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SigmaError(f"invalid JSON in {file_path}: {exc}") from exc
        return rule_from_mapping(data, "json", str(file_path))
    if suffix in (".yaml", ".yml"):
        try:
            data = parse_yaml(text)
        except YamlSubsetError as exc:
            raise SigmaError(f"YAML subset error in {file_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise SigmaError(f"rule file {file_path} must contain a mapping")
        return rule_from_mapping(data, "yaml", str(file_path))
    raise SigmaError(
        f"unsupported rule file type {suffix!r} (use .json, .yaml, or .yml)"
    )
