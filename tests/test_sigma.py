"""Sigma-subset tests: YAML parser, loader validation, engine, CLI."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
from conftest import event_dict

from huntforge.cli.main import main as cli_main
from huntforge.core import plugins as plugins_mod
from huntforge.sigma import (
    SigmaError,
    evaluate_rule,
    list_samples,
    load_rule_file,
    technique_ids_from_tags,
)
from huntforge.sigma.loader import (
    logsource_filter,
    rule_from_mapping,
)
from huntforge.sigma.model import SigmaLogSource, SigmaRule
from huntforge.sigma.yaml_subset import YamlSubsetError
from huntforge.sigma.yaml_subset import parse as parse_yaml


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_main(argv)
    return code, out.getvalue(), err.getvalue()


def run_json(argv: list[str]) -> tuple[int, dict]:
    code, out, _ = run([*argv, "--json"])
    return code, json.loads(out)


def make_rule(**overrides) -> SigmaRule:
    detection = {"selection": {"Image": "*powershell.exe"}, "condition": "selection"}
    detection.update(overrides.pop("detection", {}))
    if "condition" in overrides:
        detection["condition"] = overrides.pop("condition")
    base: dict = {
        "id": "test-001",
        "title": "Test rule",
        "detection": detection,
        "level": "high",
        "tags": ["attack.t1059.001"],
    }
    base.update(overrides)
    return rule_from_mapping(base, "json", "<test>")


def numbered(events: list[dict]) -> list[dict]:
    for index, event in enumerate(events, start=1):
        event["id"] = index
    return events


# ---------------------------------------------------------------------------
# YAML subset parser
# ---------------------------------------------------------------------------


def test_yaml_nested_maps_and_lists() -> None:
    doc = parse_yaml(
        """
title: Sample
id: s-1
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image: "*\\\\powershell.exe"
    CommandLine:
      - "*-enc*"
      - "*-EncodedCommand*"
  filter:
    Image: "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"
  condition: selection and not filter
tags:
  - attack.t1059.001
level: high
count: 3
enabled: true
empty: null
"""
    )
    assert doc["title"] == "Sample"
    assert doc["logsource"] == {
        "product": "windows",
        "category": "process_creation",
    }
    assert doc["detection"]["selection"]["CommandLine"] == [
        "*-enc*",
        "*-EncodedCommand*",
    ]
    assert doc["tags"] == ["attack.t1059.001"]
    assert doc["count"] == 3
    assert doc["enabled"] is True
    assert doc["empty"] is None


def test_yaml_inline_map_in_list() -> None:
    doc = parse_yaml(
        """
items:
  - name: first
    value: 1
  - name: second
    value: 2
"""
    )
    assert doc == {
        "items": [{"name": "first", "value": 1}, {"name": "second", "value": 2}]
    }


def test_yaml_comments_and_quotes() -> None:
    doc = parse_yaml(
        """
# a comment
title: "hash # not a comment"
desc: 'single # still not'
"""
    )
    assert doc == {
        "title": "hash # not a comment",
        "desc": "single # still not",
    }


def test_yaml_colon_inside_quotes() -> None:
    doc = parse_yaml('title: "a: b"\n')
    assert doc == {"title": "a: b"}


def test_yaml_rejects_tabs() -> None:
    with pytest.raises(YamlSubsetError, match="tabs"):
        parse_yaml("title: x\n\tkey: y\n")


def test_yaml_rejects_flow_collections() -> None:
    with pytest.raises(YamlSubsetError, match="flow"):
        parse_yaml("key: {a: b}\n")


def test_yaml_rejects_block_scalars() -> None:
    with pytest.raises(YamlSubsetError, match="[Bb]lock scalar"):
        parse_yaml("key: |\n  multiline\n")


def test_yaml_rejects_anchors() -> None:
    with pytest.raises(YamlSubsetError, match="[Aa]nchor"):
        parse_yaml("key: &anchor value\n")


def test_yaml_rejects_bad_indent() -> None:
    with pytest.raises(YamlSubsetError, match="[Ii]ndentation"):
        parse_yaml("a:\n  b: 1\n     c: 2\n")


def test_yaml_rejects_duplicate_keys() -> None:
    with pytest.raises(YamlSubsetError, match="duplicate"):
        parse_yaml("a: 1\na: 2\n")


def test_yaml_rejects_empty() -> None:
    with pytest.raises(YamlSubsetError, match="empty"):
        parse_yaml("  \n# nothing\n")


def test_yaml_limits_documented() -> None:
    # Multi-line quoted scalars are out of scope: loud error, not silent.
    with pytest.raises(YamlSubsetError):
        parse_yaml('title: "unterminated\n')


# ---------------------------------------------------------------------------
# Loader validation
# ---------------------------------------------------------------------------


def test_loader_minimal_json_rule(tmp_path: Path) -> None:
    path = tmp_path / "rule.json"
    path.write_text(
        json.dumps(
            {
                "title": "T",
                "id": "r-1",
                "detection": {
                    "selection": {"Image": "x"},
                    "condition": "selection",
                },
            }
        )
    )
    rule = load_rule_file(path)
    assert rule.level == "medium"
    assert rule.source_format == "json"


def test_loader_requires_title_and_id() -> None:
    with pytest.raises(SigmaError, match="title"):
        rule_from_mapping(
            {"id": "x", "detection": {"s": {"Image": "x"}, "condition": "s"}},
            "json",
            "",
        )
    with pytest.raises(SigmaError, match="id"):
        rule_from_mapping(
            {"title": "x", "detection": {"s": {"Image": "x"}, "condition": "s"}},
            "json",
            "",
        )


def test_loader_rejects_modifiers() -> None:
    with pytest.raises(SigmaError, match="not supported"):
        make_rule(
            detection={"selection": {"CommandLine|contains": "enc"}},
            condition="selection",
        )


def test_loader_rejects_unknown_field() -> None:
    with pytest.raises(SigmaError, match="unknown field"):
        make_rule(detection={"selection": {"NoSuchField": "x"}})


def test_loader_rejects_bad_level() -> None:
    with pytest.raises(SigmaError, match="level"):
        make_rule(level="extreme")


def test_loader_rejects_dangling_condition() -> None:
    with pytest.raises(SigmaError, match="unknown selection"):
        make_rule(condition="nosuchselection")


def test_loader_rejects_missing_file() -> None:
    with pytest.raises(SigmaError, match="not found"):
        load_rule_file("/nonexistent/rule.json")


def test_loader_rejects_bad_suffix(tmp_path: Path) -> None:
    path = tmp_path / "rule.txt"
    path.write_text("hello")
    with pytest.raises(SigmaError, match="unsupported rule file type"):
        load_rule_file(path)


def test_loader_rejects_bad_json(tmp_path: Path) -> None:
    path = tmp_path / "rule.json"
    path.write_text("{nope")
    with pytest.raises(SigmaError, match="invalid JSON"):
        load_rule_file(path)


def test_technique_ids_from_tags() -> None:
    assert technique_ids_from_tags(["attack.t1059.001", "attack.execution"]) == [
        "T1059.001"
    ]
    assert technique_ids_from_tags(["attack.t1110"]) == ["T1110"]
    assert technique_ids_from_tags([]) == []


def test_logsource_filter() -> None:
    assert logsource_filter(SigmaLogSource(category="process_creation")) == (
        "sysmon",
        ("1",),
    )
    assert logsource_filter(SigmaLogSource(service="security")) == (
        "evtx:Security",
        (),
    )
    assert logsource_filter(SigmaLogSource()) is None
    assert logsource_filter(SigmaLogSource(category="nonsense")) is None


def test_plugin_registered() -> None:
    info = plugins_mod.get_registry().get("sigma")
    assert info.version == "0.9.0"
    assert "sigma" in info.commands


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def _ps_event(**overrides) -> dict:
    base = event_dict(
        process_name="powershell.exe",
        command_line="powershell.exe -EncodedCommand aGVsbG8=",
    )
    base.update(overrides)
    return base


def test_engine_matches_selection() -> None:
    rule = make_rule()
    findings = evaluate_rule(rule, numbered([_ps_event()]))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "test-001"
    assert finding.rule_version == "0.6.0"
    assert finding.provenance == "huntforge.sigma"
    assert finding.mitre == ["T1059.001"]
    assert finding.evidence[0].event_id == 1
    assert "selection" in finding.why[0]
    as_dict = finding.to_dict()
    assert as_dict["mitre"] == ["T1059.001"]
    assert as_dict["provenance"] == "huntforge.sigma"


def test_engine_no_match() -> None:
    rule = make_rule()
    event = _ps_event(process_name="notepad.exe", command_line="notepad.exe")
    assert evaluate_rule(rule, numbered([event])) == []


def test_engine_wildcard_and_list_or() -> None:
    rule = make_rule(
        detection={
            "selection": {
                "Image": ["*powershell.exe", "*pwsh.exe"],
                "CommandLine": "*-enc*",
            },
            "condition": "selection",
        }
    )
    assert len(evaluate_rule(rule, numbered([_ps_event()]))) == 1
    assert evaluate_rule(rule, numbered([_ps_event(process_name="C:\\pwsh.exe")])) != []


def test_engine_case_insensitive() -> None:
    rule = make_rule(detection={"selection": {"Image": "*POWERSHELL.EXE"}})
    assert len(evaluate_rule(rule, numbered([_ps_event()]))) == 1


def test_engine_and_not_condition() -> None:
    rule = make_rule(
        detection={
            "selection": {"Image": "*powershell.exe"},
            "filter": {"Image": "*\\System32\\*"},
        },
        condition="selection and not filter",
    )
    assert len(evaluate_rule(rule, numbered([_ps_event()]))) == 1
    sys32 = _ps_event(
        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )
    assert evaluate_rule(rule, numbered([sys32])) == []


def test_engine_one_of_condition() -> None:
    rule = make_rule(
        detection={
            "sel_a": {"Image": "*notepad.exe"},
            "sel_b": {"CommandLine": "*-enc*"},
        },
        condition="1 of sel*",
    )
    assert len(evaluate_rule(rule, numbered([_ps_event()]))) == 1


def test_engine_all_of_condition() -> None:
    rule = make_rule(
        detection={
            "sel_a": {"Image": "*powershell.exe"},
            "sel_b": {"CommandLine": "*-enc*"},
        },
        condition="all of sel*",
    )
    assert len(evaluate_rule(rule, numbered([_ps_event()]))) == 1
    rule2 = make_rule(
        detection={
            "sel_a": {"Image": "*powershell.exe"},
            "sel_b": {"CommandLine": "*-no-such-flag*"},
        },
        condition="all of sel*",
    )
    assert evaluate_rule(rule2, numbered([_ps_event()])) == []


def test_engine_logsource_filters_events() -> None:
    rule = make_rule(
        logsource=SigmaLogSource(product="windows", category="network_connection")
    )
    assert evaluate_rule(rule, numbered([_ps_event()])) == []
    net = event_dict(
        source="sysmon",
        event_id=3,
        process_name="powershell.exe",
        dst_ip="203.0.113.7",
        dst_port=4444,
    )
    assert len(evaluate_rule(rule, numbered([net]))) == 1


def test_engine_parentheses_rejected() -> None:
    rule = make_rule(condition="(selection)")
    with pytest.raises(SigmaError, match="parentheses"):
        evaluate_rule(rule, numbered([_ps_event()]))


def test_engine_confidence_from_level() -> None:
    low = make_rule(level="low")
    findings = evaluate_rule(low, numbered([_ps_event()]))
    assert findings[0].confidence == 45
    assert "rule author's level" in findings[0].confidence_reason


# ---------------------------------------------------------------------------
# Bundled samples
# ---------------------------------------------------------------------------


def test_samples_load_and_have_techniques() -> None:
    samples = list_samples()
    assert len(samples) == 4
    ids = {s["id"] for s in samples}
    assert ids == {"hf-sigma-0001", "hf-sigma-0002", "hf-sigma-0003", "hf-sigma-0004"}
    for sample in samples:
        assert sample["techniques"], sample["id"]


def test_sample_encoded_powershell_fires() -> None:
    rule = load_rule_file("hf-sigma-0001")
    findings = evaluate_rule(rule, numbered([_ps_event()]))
    assert len(findings) == 1
    assert findings[0].mitre == ["T1059.001"]


def test_sample_office_spawn_fires() -> None:
    rule = load_rule_file("hf-sigma-0002")
    event = event_dict(
        process_name="powershell.exe",
        parent_name="C:\\Program Files\\Microsoft Office\\winword.exe",
    )
    findings = evaluate_rule(rule, numbered([event]))
    assert len(findings) == 1
    assert findings[0].mitre == ["T1204.002"]
    benign = event_dict(process_name="notepad.exe", parent_name="explorer.exe")
    assert evaluate_rule(rule, numbered([benign])) == []


def test_sample_yaml_rare_port_fires() -> None:
    rule = load_rule_file("hf-sigma-0004")
    assert rule.source_format == "yaml"
    net = event_dict(source="sysmon", event_id=3, dst_ip="203.0.113.7", dst_port=4444)
    findings = evaluate_rule(rule, numbered([net]))
    assert len(findings) == 1
    assert findings[0].mitre == ["T1571"]
    web = event_dict(source="sysmon", event_id=3, dst_ip="203.0.113.7", dst_port=443)
    assert evaluate_rule(rule, numbered([web])) == []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_sigma_list(isolated_state: Path) -> None:
    code, out, _ = run(["sigma", "list"])
    assert code == 0
    assert "hf-sigma-0001" in out
    assert "T1059.001" in out


def test_cli_sigma_list_json(isolated_state: Path) -> None:
    code, data = run_json(["sigma", "list"])
    assert code == 0
    assert data["data"]["count"] == 4


def test_cli_sigma_run(isolated_state: Path) -> None:
    assert run(["case", "create", "SIGMA-1"])[0] == 0
    code, _, _ = run(
        ["ingest", "tests/fixtures/sysmon_intrusion.json", "--case", "SIGMA-1"]
    )
    assert code == 0
    code, out, _ = run(["sigma", "run", "--case", "SIGMA-1", "--rule", "hf-sigma-0001"])
    assert code == 1
    assert "hf-sigma-0001" in out
    # Findings persist with sigma provenance.
    code, data = run_json(
        ["sigma", "run", "--case", "SIGMA-1", "--rule", "hf-sigma-0001"]
    )
    assert code == 1
    finding = data["findings"][0]
    assert finding["provenance"] == "huntforge.sigma"
    assert finding["rule_version"] == "0.6.0"
    assert finding["mitre"] == ["T1059.001"]


def test_cli_sigma_run_no_match(isolated_state: Path) -> None:
    assert run(["case", "create", "SIGMA-2"])[0] == 0
    code, out, _ = run(["sigma", "run", "--case", "SIGMA-2", "--rule", "hf-sigma-0001"])
    assert code == 0
    assert "no matches" in out


def test_cli_sigma_run_bad_file(isolated_state: Path) -> None:
    assert run(["case", "create", "SIGMA-3"])[0] == 0
    code, _, err = run(
        ["sigma", "run", "--case", "SIGMA-3", "--rule", "/nonexistent.yml"]
    )
    assert code == 2
    assert "not found" in err


def test_cli_sigma_run_invalid_rule(isolated_state: Path, tmp_path: Path) -> None:
    assert run(["case", "create", "SIGMA-4"])[0] == 0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"title": "No detection block", "id": "bad-1"}))
    code, _, err = run(["sigma", "run", "--case", "SIGMA-4", "--rule", str(bad)])
    assert code == 2
    assert "detection" in err
