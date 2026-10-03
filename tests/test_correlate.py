"""Correlation tests: linkages, clusters, narratives, CLI."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
from conftest import event_dict, make_event

from huntforge import correlate as correlate_mod
from huntforge.cli.main import main as cli_main
from huntforge.correlate import engine as engine_mod
from huntforge.correlate import linkages as linkages_mod
from huntforge.correlate.model import Linkage


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli_main(argv)
    return code, out.getvalue(), err.getvalue()


def run_json(argv: list[str]) -> tuple[int, dict]:
    code, out, _ = run([*argv, "--json"])
    return code, json.loads(out)


_next_id = 0


def ev(**overrides: Any) -> dict[str, Any]:
    """One db-row-shaped event dict with a unique id.

    Process context (name/pid/parent/command line) defaults to None —
    tests opt in explicitly — so unrelated fixtures cannot spuriously
    share conftest's powershell.exe/4242 defaults.
    """
    global _next_id
    _next_id += 1
    for key in (
        "process_name",
        "process_id",
        "parent_name",
        "parent_id",
        "command_line",
    ):
        overrides.setdefault(key, None)
    data = event_dict(**overrides)
    data["id"] = _next_id
    data["evidence_id"] = None
    data["provenance"] = {}
    return data


def base_chain() -> list[dict[str, Any]]:
    """Malicious chain: creation -> network -> file -> run key -> exec.

    All five events link into one cluster: same-process
    (creation+network), download-execution (network -> file -> proc),
    persistence-execution (run key -> evil.exe).
    """
    return [
        ev(
            timestamp="2026-10-03T10:00:00Z",
            source="sysmon",
            event_id="1",
            process_name="powershell.exe",
            process_id=4321,
            parent_name="winword.exe",
            parent_id=3131,
            command_line="powershell.exe -enc aGVsbG8=",
            host="WS-001",
        ),
        ev(
            timestamp="2026-10-03T10:00:30Z",
            source="sysmon",
            event_id="3",
            process_name="powershell.exe",
            process_id=4321,
            dst_ip="203.0.113.9",
            dst_port=443,
            host="WS-001",
        ),
        ev(
            timestamp="2026-10-03T10:01:00Z",
            source="sysmon",
            event_id="11",
            process_name="powershell.exe",
            process_id=4321,
            file_path="C:\\Users\\jdoe\\AppData\\Roaming\\evil.exe",
            host="WS-001",
        ),
        ev(
            timestamp="2026-10-03T10:05:00Z",
            source="registry",
            event_id="run-key",
            registry_key="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            file_path="C:\\Users\\jdoe\\AppData\\Roaming\\evil.exe",
            command_line='"C:\\Users\\jdoe\\AppData\\Roaming\\evil.exe"',
            host="WS-001",
        ),
        ev(
            timestamp="2026-10-03T10:05:10Z",
            source="sysmon",
            event_id="1",
            process_name="evil.exe",
            process_id=5555,
            parent_id=4321,
            host="WS-001",
        ),
    ]


# ---------------------------------------------------------------------------
# linkage detectors
# ---------------------------------------------------------------------------


def test_same_process_links_creation_and_network() -> None:
    events = base_chain()
    links = linkages_mod.detect_same_process(events)
    pair = {events[0]["id"], events[1]["id"]}
    matches = [link for link in links if {link.event_a, link.event_b} == pair]
    assert len(matches) == 1
    assert matches[0].kind == "same-process"
    assert matches[0].confidence == 90


def test_same_process_ignores_pid_reuse_outside_window() -> None:
    first = ev(
        timestamp="2026-10-03T10:00:00Z",
        process_name="powershell.exe",
        process_id=4321,
        host="WS-001",
    )
    second = ev(
        timestamp="2026-10-03T12:00:00Z",  # 2h later: outside the window
        process_name="powershell.exe",
        process_id=4321,
        host="WS-001",
    )
    assert linkages_mod.detect_same_process([first, second]) == []


def test_same_process_requires_same_host() -> None:
    first = ev(process_name="a.exe", process_id=1, host="WS-001")
    second = ev(process_name="a.exe", process_id=1, host="WS-002")
    assert linkages_mod.detect_same_process([first, second]) == []


def test_same_file_exact_path() -> None:
    created = ev(
        timestamp="2026-10-03T10:01:00Z",
        source="sysmon",
        event_id="11",
        file_path="C:\\Temp\\dropper.exe",
        host="WS-001",
    )
    proc = ev(
        timestamp="2026-10-03T10:02:00Z",
        source="sysmon",
        event_id="1",
        process_name="dropper.exe",
        process_id=777,
        host="WS-001",
    )
    # sysmon creation has no file_path; give it one to test exact match.
    proc["file_path"] = "c:/temp\\dropper.exe"  # case + separator variance
    links = linkages_mod.detect_same_file([created, proc])
    assert len(links) == 1
    assert links[0].confidence == 80
    assert "c:\\temp\\dropper.exe" in links[0].basis


def test_same_file_prefetch_basename() -> None:
    created = ev(
        timestamp="2026-10-03T10:00:00Z",
        source="sysmon",
        event_id="1",
        process_name="powershell.exe",
        process_id=4321,
        host="WS-001",
    )
    pf = ev(
        timestamp="2026-10-03T10:20:00Z",
        source="prefetch",
        event_id="run",
        process_name="POWERSHELL.EXE",
        host="WS-001",
    )
    links = linkages_mod.detect_same_file([created, pf])
    assert len(links) == 1
    assert links[0].confidence == 65
    assert "basename" in links[0].basis


def test_persistence_execution_full_and_basename() -> None:
    runkey = ev(
        timestamp="2026-10-03T10:05:00Z",
        source="registry",
        event_id="run-key",
        registry_key="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        file_path="C:\\evil\\payload.exe",
        host="WS-001",
    )
    proc = ev(
        timestamp="2026-10-03T10:06:00Z",
        source="sysmon",
        event_id="1",
        process_name="payload.exe",
        process_id=999,
        host="WS-001",
    )
    links = linkages_mod.detect_persistence_execution([runkey, proc])
    assert len(links) == 1
    assert links[0].kind == "persistence-execution"
    # basename-only (sysmon creation carries no full path): 60.
    assert links[0].confidence == 60


def test_persistence_execution_no_target_no_link() -> None:
    runkey = ev(
        source="registry",
        event_id="run-key",
        registry_key="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        host="WS-001",
    )
    proc = ev(
        source="sysmon",
        event_id="1",
        process_name="payload.exe",
        process_id=999,
        host="WS-001",
    )
    assert linkages_mod.detect_persistence_execution([runkey, proc]) == []


def test_download_execution_chain_with_lineage() -> None:
    net = ev(
        timestamp="2026-10-03T10:00:00Z",
        source="sysmon",
        event_id="3",
        process_name="powershell.exe",
        process_id=4321,
        dst_ip="203.0.113.9",
        dst_port=443,
        host="WS-001",
    )
    created = ev(
        timestamp="2026-10-03T10:01:00Z",
        source="sysmon",
        event_id="11",
        process_name="powershell.exe",
        process_id=4321,
        file_path="C:\\Temp\\dropper.exe",
        host="WS-001",
    )
    proc = ev(
        timestamp="2026-10-03T10:02:00Z",
        source="sysmon",
        event_id="1",
        process_name="dropper.exe",
        process_id=777,
        parent_id=4321,
        host="WS-001",
    )
    links = linkages_mod.detect_download_execution([net, created, proc])
    assert len(links) == 1
    link = links[0]
    assert link.kind == "download-execution"
    assert {link.event_a, link.event_b} == {net["id"], proc["id"]}
    assert link.confidence == 85  # lineage support


def test_download_execution_no_lineage_lower_confidence() -> None:
    net = ev(
        timestamp="2026-10-03T10:00:00Z",
        source="sysmon",
        event_id="3",
        process_name="chrome.exe",
        process_id=111,
        dst_ip="203.0.113.9",
        host="WS-001",
    )
    created = ev(
        timestamp="2026-10-03T10:01:00Z",
        source="sysmon",
        event_id="11",
        process_name="chrome.exe",
        process_id=111,
        file_path="C:\\Temp\\dropper.exe",
        host="WS-001",
    )
    proc = ev(
        timestamp="2026-10-03T10:02:00Z",
        source="sysmon",
        event_id="1",
        process_name="dropper.exe",
        process_id=777,
        parent_id=222,  # not the downloader
        host="WS-001",
    )
    links = linkages_mod.detect_download_execution([net, created, proc])
    assert len(links) == 1
    assert links[0].confidence == 70


def test_download_execution_file_not_by_downloader_no_link() -> None:
    net = ev(
        timestamp="2026-10-03T10:00:00Z",
        source="sysmon",
        event_id="3",
        process_name="notepad.exe",
        process_id=1234,
        dst_ip="203.0.113.9",
        host="WS-001",
    )
    created = ev(
        timestamp="2026-10-03T10:01:00Z",
        source="sysmon",
        event_id="11",
        process_name="powershell.exe",  # different process wrote the file
        process_id=4321,
        file_path="C:\\Temp\\dropper.exe",
        host="WS-001",
    )
    proc = ev(
        timestamp="2026-10-03T10:02:00Z",
        source="sysmon",
        event_id="1",
        process_name="dropper.exe",
        process_id=777,
        host="WS-001",
    )
    assert linkages_mod.detect_download_execution([net, created, proc]) == []


def test_download_execution_wrong_order_no_link() -> None:
    proc = ev(
        timestamp="2026-10-03T10:00:00Z",
        source="sysmon",
        event_id="1",
        process_name="dropper.exe",
        process_id=777,
        host="WS-001",
    )
    net = ev(
        timestamp="2026-10-03T10:05:00Z",  # network AFTER execution
        source="sysmon",
        event_id="3",
        process_name="dropper.exe",
        process_id=777,
        dst_ip="203.0.113.9",
        host="WS-001",
    )
    assert linkages_mod.detect_download_execution([net, proc]) == []


def test_untimed_events_never_linked() -> None:
    first = ev(
        timestamp="2026-10-03T10:00:00Z",
        process_name="a.exe",
        process_id=1,
        host="WS-001",
    )
    second = ev(
        timestamp="2026-10-03T10:01:00Z",
        process_name="a.exe",
        process_id=1,
        host="WS-001",
    )
    second["timestamp_original"] = None  # placeholder timestamp
    assert linkages_mod.detect_all([first, second]) == []


def test_linkage_model_validation() -> None:
    with pytest.raises(ValueError):
        Linkage(
            kind="same-process",
            event_a=1,
            event_b=1,
            basis="x",
            confidence=90,
            confidence_reason="x",
            heuristic="x",
            failure_modes="x",
        )
    with pytest.raises(ValueError):
        Linkage(
            kind="same-process",
            event_a=1,
            event_b=2,
            basis="x",
            confidence=101,
            confidence_reason="x",
            heuristic="x",
            failure_modes="x",
        )
    link = Linkage(
        kind="same-process",
        event_a=1,
        event_b=2,
        basis="same pid",
        confidence=90,
        confidence_reason="r",
        heuristic="h",
        failure_modes="f",
    )
    assert link.to_dict()["label"] == "INFERRED"


# ---------------------------------------------------------------------------
# clustering
# ---------------------------------------------------------------------------


def test_chain_correlates_into_one_cluster() -> None:
    events = base_chain()
    clusters, stats = engine_mod.correlate_case(events, [])
    assert len(clusters) == 1
    assert set(clusters[0].event_ids) == {e["id"] for e in events}
    assert stats["cluster_count"] == 1
    assert stats["uncorrelated_event_count"] == 0


def test_unrelated_activity_stays_separate() -> None:
    events = base_chain()
    events.append(
        ev(
            timestamp="2026-10-03T10:00:00Z",
            source="sysmon",
            event_id="1",
            process_name="notepad.exe",
            process_id=1234,
            host="WS-001",
        )
    )
    events.append(
        ev(
            timestamp="2026-10-03T10:00:05Z",
            source="sysmon",
            event_id="3",
            process_name="notepad.exe",
            process_id=1234,
            dst_ip="198.51.100.7",
            host="WS-001",
        )
    )
    clusters, stats = engine_mod.correlate_case(events, [])
    assert len(clusters) == 2
    sizes = sorted(len(c.event_ids) for c in clusters)
    assert sizes == [2, 5]
    assert stats["uncorrelated_event_count"] == 0


def test_singletons_are_uncorrelated() -> None:
    events = base_chain()
    lone = ev(
        timestamp="2026-10-03T11:00:00Z",
        source="sysmon",
        event_id="1",
        process_name="calc.exe",
        process_id=42,
        host="WS-001",
    )
    events.append(lone)
    clusters, stats = engine_mod.correlate_case(events, [])
    assert len(clusters) == 1
    assert stats["uncorrelated_event_count"] == 1


def test_empty_case() -> None:
    clusters, stats = engine_mod.correlate_case([], [])
    assert clusters == []
    assert stats["cluster_count"] == 0
    assert stats["linkage_count"] == 0


def test_cluster_confidence_is_weakest_link() -> None:
    events = base_chain()
    clusters, _ = engine_mod.correlate_case(events, [])
    cluster = clusters[0]
    weakest = min(link.confidence for link in cluster.linkages)
    assert cluster.confidence == weakest
    assert str(weakest) in cluster.confidence_reason


def test_finding_attached_to_cluster() -> None:
    events = base_chain()
    finding = {
        "finding_uid": "HF-0001",
        "rule_id": "HF-DET-ENCPSH",
        "title": "Encoded PowerShell",
        "severity": "high",
        "confidence": 85,
        "mitre": ["T1059.001"],
        "evidence": [
            {"event_id": events[0]["id"], "observation": "encoded command"},
            {"event_id": events[1]["id"], "observation": "network"},
        ],
    }
    clusters, _ = engine_mod.correlate_case(events, [finding])
    assert len(clusters) == 1
    assert len(clusters[0].findings) == 1
    assert clusters[0].techniques[0]["id"] == "T1059.001"
    assert clusters[0].techniques[0]["name"]  # resolved from the table


def test_finding_without_cluster_evidence_unattached() -> None:
    events = base_chain()
    lone = ev(source="sysmon", event_id="1", process_name="x.exe", process_id=9)
    finding = {
        "finding_uid": "HF-0009",
        "rule_id": "R",
        "title": "t",
        "severity": "low",
        "confidence": 10,
        "mitre": [],
        "evidence": [{"event_id": lone["id"], "observation": "x"}],
    }
    clusters, stats = engine_mod.correlate_case(events, [finding])
    assert len(clusters) == 1
    assert clusters[0].findings == []
    assert stats["unattached_finding_count"] == 1


def test_ranking_by_severity_then_findings() -> None:
    low_events = [
        ev(
            timestamp="2026-10-03T09:00:00Z",
            process_name="a.exe",
            process_id=10,
            host="WS-001",
        ),
        ev(
            timestamp="2026-10-03T09:00:05Z",
            source="sysmon",
            event_id="3",
            process_name="a.exe",
            process_id=10,
            dst_ip="198.51.100.7",
            host="WS-001",
        ),
    ]
    high_events = base_chain()
    events = low_events + high_events
    low_finding = {
        "finding_uid": "HF-0001",
        "rule_id": "R1",
        "title": "low",
        "severity": "low",
        "confidence": 40,
        "mitre": [],
        "evidence": [{"event_id": low_events[0]["id"], "observation": "x"}],
    }
    high_finding = {
        "finding_uid": "HF-0002",
        "rule_id": "R2",
        "title": "high",
        "severity": "high",
        "confidence": 80,
        "mitre": [],
        "evidence": [{"event_id": high_events[0]["id"], "observation": "x"}],
    }
    clusters, _ = engine_mod.correlate_case(events, [low_finding, high_finding])
    assert len(clusters) == 2
    assert clusters[0].findings[0]["severity"] == "high"
    assert clusters[1].findings[0]["severity"] == "low"


# ---------------------------------------------------------------------------
# what's missing + narrative
# ---------------------------------------------------------------------------


def test_whats_missing_prefetch_gap() -> None:
    created = ev(
        timestamp="2026-10-03T10:00:00Z",
        source="sysmon",
        event_id="1",
        process_name="evil.exe",
        process_id=4321,
        host="WS-001",
    )
    other_pf = ev(
        timestamp="2026-10-03T10:00:00Z",
        source="prefetch",
        event_id="run",
        process_name="NOTEPAD.EXE",
        host="WS-001",
    )
    missing = engine_mod._whats_missing([created], [created, other_pf])
    assert any("no prefetch entry" in m for m in missing)


def test_whats_missing_persistence_never_executed() -> None:
    runkey = ev(
        timestamp="2026-10-03T10:05:00Z",
        source="registry",
        event_id="run-key",
        registry_key="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        file_path="C:\\evil\\never-ran.exe",
        host="WS-001",
    )
    missing = engine_mod._whats_missing([runkey], [runkey])
    assert any("never observed executing" in m for m in missing)


def test_whats_missing_external_network_no_followup() -> None:
    net = ev(
        timestamp="2026-10-03T10:00:00Z",
        source="sysmon",
        event_id="3",
        process_name="svchost.exe",
        process_id=100,
        dst_ip="45.33.32.156",
        dst_port=443,
        host="WS-001",
    )
    missing = engine_mod._whats_missing([net], [net])
    assert any("no observed download" in m for m in missing)


def test_whats_missing_private_ip_ignored() -> None:
    net = ev(
        timestamp="2026-10-03T10:00:00Z",
        source="sysmon",
        event_id="3",
        process_name="svchost.exe",
        process_id=100,
        dst_ip="10.0.0.5",
        dst_port=445,
        host="WS-001",
    )
    missing = engine_mod._whats_missing([net], [net])
    assert not any("no observed download" in m for m in missing)


def test_narrative_labels_observed_vs_inferred() -> None:
    events = base_chain()
    clusters, _ = engine_mod.correlate_case(events, [])
    narrative = engine_mod.build_narrative(clusters[0], events)
    data = narrative.to_dict()
    assert all(e["label"] == "OBSERVED" for e in data["observed"])
    assert all(e["label"] == "INFERRED" for e in data["inferred"])
    assert len(data["observed"]) == len(events)
    # timeline order
    stamps = [e["timestamp"] for e in data["observed"]]
    assert stamps == sorted(stamps)
    assert data["confidence"] == clusters[0].confidence


def test_narrative_entities_present() -> None:
    events = base_chain()
    clusters, _ = engine_mod.correlate_case(events, [])
    narrative = engine_mod.build_narrative(clusters[0], events)
    kinds = {e["type"] for e in narrative.to_dict()["entities"]}
    assert {"host", "process"} <= kinds


def test_plugin_registered() -> None:
    correlate_mod.ensure_registered()
    from huntforge.core import plugins as plugins_mod

    info = plugins_mod.get_registry().get("correlate")
    assert info.version == "0.7.0"
    assert set(info.commands) == {"correlate", "narrative"}


# ---------------------------------------------------------------------------
# CLI end to end
# ---------------------------------------------------------------------------


def test_cli_correlate_intrusion_chain_one_cluster(isolated_state: Path) -> None:
    case = "CORR-1"
    assert run(["case", "create", case])[0] == 0
    assert (
        run(["ingest", "tests/fixtures/sysmon_intrusion.xml", "--case", case])[0] == 0
    )
    assert (
        run(["ingest", "tests/fixtures/intrusion_powershell.pf", "--case", case])[0]
        == 0
    )
    assert (
        run(["ingest", "tests/fixtures/intrusion_runkey.dat", "--case", case])[0] == 0
    )
    code, out, _ = run(["correlate", "--case", case])
    assert code == 0
    assert "activity cluster(s)" in out
    assert "INFERRED" in out
    code, data = run_json(["correlate", "--case", case])
    assert code == 0
    payload = data["data"]
    assert payload["cluster_count"] >= 1
    biggest = max(payload["clusters"], key=lambda c: c["event_count"])
    assert biggest["event_count"] >= 4
    assert any(link["kind"] == "same-process" for link in biggest["linkages"]) or any(
        link["kind"] == "same-file" for link in biggest["linkages"]
    )


def test_cli_correlate_empty_case(isolated_state: Path) -> None:
    assert run(["case", "create", "CORR-2"])[0] == 0
    code, out, _ = run(["correlate", "--case", "CORR-2"])
    assert code == 0
    assert "0 activity cluster(s)" in out


def test_cli_narrative(isolated_state: Path) -> None:
    case = "CORR-3"
    assert run(["case", "create", case])[0] == 0
    assert (
        run(["ingest", "tests/fixtures/sysmon_intrusion.xml", "--case", case])[0] == 0
    )
    code, out, _ = run(["narrative", "--case", case, "--cluster", "0"])
    assert code == 0
    assert "OBSERVED" in out
    assert "INFERRED" in out
    assert "what's missing" in out
    code, data = run_json(["narrative", "--case", case, "--cluster", "0"])
    assert code == 0
    payload = data["data"]
    assert payload["cluster_id"] == 0
    assert payload["observed"] and payload["inferred"]


def test_cli_narrative_bad_cluster(isolated_state: Path) -> None:
    assert run(["case", "create", "CORR-4"])[0] == 0
    code, _out, err = run(["narrative", "--case", "CORR-4", "--cluster", "9"])
    assert code == 2
    assert "no cluster 9" in err


def test_cli_correlate_with_detections(isolated_state: Path) -> None:
    case = "CORR-5"
    assert run(["case", "create", case])[0] == 0
    assert (
        run(["ingest", "tests/fixtures/sysmon_intrusion.xml", "--case", case])[0] == 0
    )
    assert run(["detect", "--case", case])[0] == 1  # findings stored
    code, data = run_json(["correlate", "--case", case])
    assert code == 0
    payload = data["data"]
    assert payload["cluster_count"] >= 1
    assert any(c["finding_count"] > 0 for c in payload["clusters"])
    assert any(c["techniques"] for c in payload["clusters"])


def test_make_event_import_sanity() -> None:
    event = make_event()
    assert event.process_name == "powershell.exe"
