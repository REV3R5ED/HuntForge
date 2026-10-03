"""Correlation engine: clusters, finding attachment, narratives.

The engine is deterministic: the same case always produces the same
clusters. It never invents evidence — linkages are INFERRED hypotheses
(``huntforge.correlate.linkages``) while the events, findings, and
entities they join remain OBSERVED facts. The narrative for a cluster
keeps those two categories in separate sections.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

from huntforge.correlate import linkages as linkages_mod
from huntforge.correlate.model import ActivityCluster, Linkage, Narrative
from huntforge.timeline import entities as entities_mod

_WHATS_MISSING_PREFETCH = (
    "no prefetch entry for {image} — execution may predate the prefetch "
    "collection window, prefetch may be disabled, or the entry may have "
    "been evicted"
)
_WHATS_MISSING_PERSIST = (
    "persistence points to {target}, but {target} was never observed "
    "executing in this case — the payload may not have run yet, or "
    "execution evidence was not collected"
)
_WHATS_MISSING_NETWORK = (
    "outbound connection to {dst} with no observed download or execution "
    "within 15 minutes — possible beaconing, data exfiltration, or "
    "benign traffic; corroborate before concluding"
)
_WHATS_MISSING_FILE = (
    "file {path} was created but never observed executing — it may be "
    "dormant, deleted before execution, or executed outside collection"
)

_DOWNLOAD_WINDOW_S = 15 * 60


def _ts(event: dict[str, Any]) -> datetime | None:
    raw = event.get("timestamp")
    if not raw:
        return None
    try:
        text = str(raw).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        moment = datetime.fromisoformat(text)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)
    except ValueError:
        return None


def _is_external_ip(value: Any) -> bool:
    """True for routable public IPs; False for private/loopback/unparseable."""
    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
    )


def _basename(path: Any) -> str:
    if not path:
        return ""
    return str(path).replace("/", "\\").rsplit("\\", 1)[-1].strip().lower()


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[int, int] = {}

    def find(self, node: int) -> int:
        root = self.parent.setdefault(node, node)
        while self.parent[root] != root:
            self.parent[root] = self.parent[self.parent[root]]
            root = self.parent[root]
        return root

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _cluster_events(
    events: list[dict[str, Any]], linkages: list[Linkage]
) -> list[tuple[list[int], list[Linkage]]]:
    """Connected components of >= 2 events joined by linkages."""
    uf = _UnionFind()
    for link in linkages:
        uf.union(link.event_a, link.event_b)
    groups: dict[int, list[int]] = {}
    for event in events:
        eid = int(event["id"])
        groups.setdefault(uf.find(eid), []).append(eid)
    links_by_pair: dict[frozenset[int], list[Linkage]] = {}
    for link in linkages:
        links_by_pair.setdefault(frozenset({link.event_a, link.event_b}), []).append(
            link
        )
    by_id = {int(e["id"]): e for e in events}
    components: list[tuple[list[int], list[Linkage]]] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        members.sort(key=lambda i: (str(by_id[i].get("timestamp") or ""), i))
        comp_links: list[Linkage] = []
        member_set = set(members)
        for pair, links in links_by_pair.items():
            if pair <= member_set:
                comp_links.extend(links)
        comp_links.sort(key=lambda link: (link.event_a, link.event_b, link.kind))
        components.append((members, comp_links))
    return components


def _attach_findings(
    clusters: list[ActivityCluster], findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Attach each finding to the cluster holding most of its evidence.

    Returns findings that could not be attached to any cluster.
    """
    cluster_sets = [set(c.event_ids) for c in clusters]
    unattached: list[dict[str, Any]] = []
    for finding in findings:
        evidence_ids: set[int] = set()
        for ref in finding.get("evidence") or []:
            if not isinstance(ref, dict):
                continue
            eid = ref.get("event_id")
            if eid is not None:
                evidence_ids.add(int(eid))
        best: ActivityCluster | None = None
        best_count = 0
        for cluster, members in zip(clusters, cluster_sets, strict=True):
            count = len(evidence_ids & members)
            if count > best_count:
                best, best_count = cluster, count
        if best is not None:
            best.findings.append(finding)
        else:
            unattached.append(finding)
    for cluster in clusters:
        cluster.findings.sort(key=lambda f: str(f.get("finding_uid") or ""))
    return unattached


def _cluster_entities(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Entity roll-up for one cluster, reusing v0.4 normalization."""
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        source = str(event.get("source") or "")
        pairs: list[tuple[str, str | None]] = [
            ("host", event.get("host")),
            ("user", event.get("user")),
            ("process", event.get("process_name")),
            ("file", event.get("file_path")),
            ("registry", event.get("registry_key")),
        ]
        if event.get("dst_ip"):
            pairs.append(("ip", event.get("dst_ip")))
        if event.get("src_ip"):
            pairs.append(("ip", event.get("src_ip")))
        for algo, digest in (event.get("hashes") or {}).items():
            pairs.append(("hash", f"{algo}:{digest}"))
        for kind, raw in pairs:
            if not raw:
                continue
            value = str(raw).strip()
            if not value:
                continue
            if kind == "host":
                norm = entities_mod.normalize_host(value)
            elif kind == "user":
                norm = entities_mod.normalize_user(value)
            elif kind == "process":
                norm = entities_mod.normalize_process(value)
            elif kind == "file":
                norm = entities_mod.normalize_file(value)
            elif kind == "registry":
                norm = entities_mod.normalize_registry(value)
            elif kind == "ip":
                norm = entities_mod.normalize_ip(value)
            elif kind == "hash":
                algo, _, digest = value.partition(":")
                norm = entities_mod.normalize_hash(algo, digest)
            else:
                norm = value.lower()
            key = (kind, norm)
            entry = seen.get(key)
            if entry is None:
                seen[key] = {
                    "type": kind,
                    "value": norm,
                    "observed_as": [value],
                    "count": 1,
                    "sources": [source],
                }
            else:
                entry["count"] += 1
                if value not in entry["observed_as"]:
                    entry["observed_as"].append(value)
                if source not in entry["sources"]:
                    entry["sources"].append(source)
    ordered = sorted(seen.values(), key=lambda e: (e["type"], -e["count"], e["value"]))
    for entry in ordered:
        entry["sources"] = sorted(entry["sources"])
        entry["observed_as"] = sorted(set(entry["observed_as"]))
    return ordered


def _cluster_techniques(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    """ATT&CK techniques evidenced by a cluster's findings, with names."""
    ids: list[str] = []
    for finding in findings:
        for tid in finding.get("mitre") or []:
            if tid not in ids:
                ids.append(tid)
    try:
        from huntforge.mitre.table import load_table

        table = load_table()
    except Exception:  # pragma: no cover - table is static and valid
        table = None
    techniques: list[dict[str, str]] = []
    for tid in sorted(ids):
        name = ""
        if table is not None:
            try:
                name = table.get(tid).name
            except (KeyError, ValueError):
                name = ""
        techniques.append({"id": tid, "name": name})
    return techniques


def _whats_missing(
    cluster_events: list[dict[str, Any]], all_events: list[dict[str, Any]]
) -> list[str]:
    """Name evidence that would be expected but was not observed."""
    missing: list[str] = []
    sources = {str(e.get("source") or "") for e in all_events}
    timed = [
        e for e in all_events if e.get("timestamp_original") is not None and _ts(e)
    ]

    executed_bases = {
        _basename(e.get("process_name"))
        for e in all_events
        if linkages_mod._is_proc_create(e) and _basename(e.get("process_name"))
    }
    executed_bases |= {
        _basename(e.get("process_name"))
        for e in all_events
        if str(e.get("source") or "") == "prefetch" and _basename(e.get("process_name"))
    }
    executed_bases.discard("")

    prefetch_bases = {
        _basename(e.get("process_name"))
        for e in all_events
        if str(e.get("source") or "") == "prefetch" and _basename(e.get("process_name"))
    }
    prefetch_bases.discard("")

    # 1. process creation without a prefetch entry (case has prefetch data).
    if "prefetch" in sources:
        for event in cluster_events:
            if not linkages_mod._is_proc_create(event):
                continue
            image = _basename(event.get("process_name"))
            if image and image not in prefetch_bases:
                missing.append(_WHATS_MISSING_PREFETCH.format(image=image))

    # 2. persistence whose target never executed.
    for event in cluster_events:
        if not linkages_mod._is_persistence(event):
            continue
        target = linkages_mod._persistence_target(event)
        base = _basename(target)
        if base and base not in executed_bases:
            missing.append(_WHATS_MISSING_PERSIST.format(target=target))

    # 3. external network connection with no download/execution after it.
    for event in cluster_events:
        dst = event.get("dst_ip")
        if not dst or not _is_external_ip(dst):
            continue
        t_net = _ts(event)
        host = str(event.get("host") or "").strip().lower()
        followed = False
        if t_net is not None:
            for other in timed:
                if str(other.get("host") or "").strip().lower() != host:
                    continue
                gap = (_ts(other) - t_net).total_seconds()  # type: ignore[operator]
                if 0 <= gap <= _DOWNLOAD_WINDOW_S and (
                    other.get("file_path") or linkages_mod._is_proc_create(other)
                ):
                    followed = True
                    break
        if not followed:
            missing.append(
                _WHATS_MISSING_NETWORK.format(
                    dst=f"{dst}:{event.get('dst_port') or '?'}"
                )
            )

    # 4. created file never executed.
    for event in cluster_events:
        if (
            str(event.get("source") or ""),
            str(event.get("event_id") or ""),
        ) not in linkages_mod._FILE_CREATE:
            continue
        base = _basename(event.get("file_path"))
        if base and base not in executed_bases:
            missing.append(_WHATS_MISSING_FILE.format(path=event.get("file_path")))

    return sorted(set(missing))


def _summarize_event(event: dict[str, Any]) -> str:
    source = event.get("source")
    eid = event.get("event_id")
    bits: list[str] = []
    if event.get("process_name"):
        proc = str(event["process_name"])
        if event.get("process_id") is not None:
            proc += f" (pid {event['process_id']})"
        if event.get("command_line"):
            cmd = str(event["command_line"])
            proc += f": {cmd[:80]}"
        bits.append(proc)
    if event.get("file_path"):
        bits.append(f"file {event['file_path']}")
    if event.get("registry_key"):
        bits.append(f"registry {event['registry_key']}")
    if event.get("dst_ip"):
        bits.append(f"-> {event['dst_ip']}:{event.get('dst_port') or '?'}")
    detail = "; ".join(bits) if bits else (str(event.get("raw") or "")[:80])
    return f"{source}:{eid} {detail}".strip()


def _cluster_summary(cluster: ActivityCluster, events: list[dict[str, Any]]) -> str:
    procs = [
        e for e in events if linkages_mod._is_proc_create(e) and e.get("process_name")
    ]
    host = str(events[0].get("host") or "?") if events else "?"
    if procs:
        names = sorted({_basename(p.get("process_name")) for p in procs})
        head = f"{', '.join(names)} on {host}"
    else:
        kinds = sorted({str(e.get("source") or "?") for e in events})
        head = f"{', '.join(kinds)} activity on {host}"
    sev = ""
    if cluster.findings:
        top = max(cluster.findings, key=lambda f: str(f.get("severity") or ""))
        sev = f"; top finding: {top.get('title')} ({top.get('severity')})"
    return f"{head}: {len(events)} event(s), {len(cluster.findings)} finding(s){sev}"


def correlate_case(
    events: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> tuple[list[ActivityCluster], dict[str, Any]]:
    """Correlate a case's events+findings into ranked activity clusters.

    Returns ``(clusters, stats)``. Clusters are ranked by (max finding
    severity, finding count, event count). ``stats`` reports linkage
    counts and uncorrelated events.
    """
    linkages = linkages_mod.detect_all(events)
    components = _cluster_events(events, linkages)
    by_id = {int(e["id"]): e for e in events}
    clusters: list[ActivityCluster] = []
    for cluster_id, (members, comp_links) in enumerate(components):
        cluster_events = [by_id[i] for i in members]
        weakest = min(comp_links, key=lambda link: link.confidence)
        cluster = ActivityCluster(
            cluster_id=cluster_id,
            event_ids=list(members),
            linkages=comp_links,
            confidence=weakest.confidence,
            confidence_reason=(
                f"weakest linkage: {weakest.kind} "
                f"(events #{weakest.event_a}/#{weakest.event_b}, "
                f"confidence {weakest.confidence})"
            ),
        )
        cluster.entities = _cluster_entities(cluster_events)
        clusters.append(cluster)
    unattached = _attach_findings(clusters, findings)
    for cluster in clusters:
        cluster.techniques = _cluster_techniques(cluster.findings)
    # Rank: severity of findings first, then finding count, then size.
    clusters.sort(
        key=lambda c: (
            -c.max_severity_rank(),
            -len(c.findings),
            -len(c.event_ids),
            c.cluster_id,
        )
    )
    for new_id, cluster in enumerate(clusters):
        cluster.cluster_id = new_id
    kinds: dict[str, int] = {}
    for link in linkages:
        kinds[link.kind] = kinds.get(link.kind, 0) + 1
    correlated_ids = {eid for c in clusters for eid in c.event_ids}
    stats = {
        "cluster_count": len(clusters),
        "linkage_count": len(linkages),
        "linkages_by_kind": kinds,
        "uncorrelated_event_count": len(events) - len(correlated_ids),
        "unattached_finding_count": len(unattached),
    }
    return clusters, stats


def build_narrative(
    cluster: ActivityCluster,
    events: list[dict[str, Any]],
    unattached_note: bool = False,
) -> Narrative:
    """Build the analyst narrative for one cluster."""
    by_id = {int(e["id"]): e for e in events}
    ordered = sorted(
        (by_id[i] for i in cluster.event_ids),
        key=lambda e: (str(e.get("timestamp") or ""), int(e.get("id") or 0)),
    )
    observed: list[dict[str, Any]] = []
    for event in ordered:
        untimed = event.get("timestamp_original") is None
        observed.append(
            {
                "id": int(event["id"]),
                "timestamp": event.get("timestamp"),
                "timestamp_original": event.get("timestamp_original"),
                "untimed": untimed,
                "source": event.get("source"),
                "event_id": event.get("event_id"),
                "summary": _summarize_event(event),
                "label": "OBSERVED",
            }
        )
    inferred: list[dict[str, Any]] = [
        {
            "kind": link.kind,
            "event_a": link.event_a,
            "event_b": link.event_b,
            "claim": (
                f"events #{link.event_a} and #{link.event_b} are hypothesized "
                f"to describe the same activity ({link.kind}): {link.basis}"
            ),
            "confidence": link.confidence,
            "confidence_reason": link.confidence_reason,
            "failure_modes": link.failure_modes,
            "label": "INFERRED",
        }
        for link in cluster.linkages
    ]
    detections = [
        {
            "finding_uid": f.get("finding_uid"),
            "rule_id": f.get("rule_id"),
            "title": f.get("title"),
            "severity": f.get("severity"),
            "confidence": f.get("confidence"),
        }
        for f in cluster.findings
    ]
    cluster_events = [by_id[i] for i in cluster.event_ids]
    missing = _whats_missing(cluster_events, events)
    summary = _cluster_summary(cluster, cluster_events)
    if unattached_note:
        missing = missing  # placeholder for future extension
    return Narrative(
        cluster_id=cluster.cluster_id,
        confidence=cluster.confidence,
        confidence_reason=cluster.confidence_reason,
        summary=summary,
        observed=observed,
        inferred=inferred,
        detections=detections,
        techniques=[dict(t) for t in cluster.techniques],
        entities=[dict(e) for e in cluster.entities],
        whats_missing=missing,
    )
