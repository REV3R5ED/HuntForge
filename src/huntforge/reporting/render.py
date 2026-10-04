"""Report renderers for HuntForge v0.8 (stdlib-only).

Four outputs, all derived from the same report dict built by
:mod:`huntforge.reporting.model`:

- JSON: the report dict itself, pretty-printed.
- Markdown: analyst-readable document.
- HTML: self-contained offline page (inline CSS, no external assets —
  no ``<link>``, no ``<script src>``, no ``<img src>``, no URLs at all).
- CSV: the findings list as a flat table. Cells that look like
  spreadsheet formulas (``=``, ``+``, ``-``, ``@`` prefixes) are
  neutralized with a leading single quote (CSV injection defense).

Every renderer escapes content for its medium (``html.escape`` for
HTML; Markdown has no executable syntax to worry about beyond code
spans for identifiers).
"""

from __future__ import annotations

import csv
import html
import io
import json
from typing import Any

REPORT_SCHEMA_VERSION = "0.8.0"


def render_json(report: dict[str, Any]) -> str:
    """Pretty-printed JSON of the report dict."""
    return json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"


# ---------------------------------------------------------------------------
# CSV findings export


def _csv_safe(value: Any) -> str:
    """Neutralize spreadsheet-formula injection in a CSV cell."""
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


CSV_FINDING_COLUMNS = (
    "finding_uid",
    "severity",
    "rule_id",
    "rule_version",
    "title",
    "confidence",
    "why",
    "observed_facts",
    "inferred_hypotheses",
    "evidence_event_ids",
    "mitre",
    "provenance",
)


def render_findings_csv(findings: list[dict[str, Any]]) -> str:
    """Flat CSV of the report's findings (formula-injection safe)."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_FINDING_COLUMNS)
    for finding in findings:
        evidence_ids = ";".join(
            str(ref.get("event_id"))
            for ref in finding.get("evidence") or []
            if ref.get("event_id") is not None
        )
        writer.writerow(
            [
                _csv_safe(finding.get("finding_uid")),
                _csv_safe(finding.get("severity")),
                _csv_safe(finding.get("rule_id")),
                _csv_safe(finding.get("rule_version")),
                _csv_safe(finding.get("title")),
                _csv_safe(finding.get("confidence")),
                _csv_safe(" | ".join(finding.get("why") or [])),
                _csv_safe(
                    " | ".join((finding.get("observed") or {}).get("facts") or [])
                ),
                _csv_safe(
                    " | ".join((finding.get("inferred") or {}).get("hypotheses") or [])
                ),
                _csv_safe(evidence_ids),
                _csv_safe(", ".join(finding.get("mitre") or [])),
                _csv_safe(finding.get("provenance")),
            ]
        )
    return out.getvalue()


# ---------------------------------------------------------------------------
# Markdown


def _md_escape(text: Any) -> str:
    return str(text if text is not None else "").replace("|", "\\|")


def render_markdown(report: dict[str, Any]) -> str:
    """Analyst-readable Markdown report."""
    meta = report["meta"]
    lines: list[str] = []
    add = lines.append

    add(f"# HuntForge case report — `{meta['case_id']}`")
    add("")
    add(
        f"Generated {meta['generated_at']} by huntforge {meta['tool_version']} "
        f"(reporting {meta['reporting_module']})."
    )
    add("")

    summary = report["executive_summary"]
    add("## Executive summary *(generated — analyst review required)*")
    add("")
    add(summary["text"])
    add("")

    add("## What this report does not claim")
    add("")
    for claim in report["what_this_report_does_not_claim"]:
        add(f"- {claim}")
    add("")

    add("## Methodology")
    add("")
    for parser in report["methodology"]["parsers"]:
        add(f"- parser `{parser['name']}` v{parser['version']}")
    steps = report["methodology"]["analysis_steps"]
    add(f"- analysis steps (from audit log): {', '.join(steps) or 'none'}")
    add("")

    overview = report["case_overview"]
    add("## Case overview")
    add("")
    add(f"- events: {overview['events']}")
    add(f"- evidence files: {overview['evidence_files']}")
    add(f"- untimed events: {overview['untimed_events']}")
    for source in overview["sources"]:
        add(
            f"- `{source['source']}`: {source['events']} events "
            f"({source['first']} .. {source['last']})"
        )
    add("")

    add("## Detections (OBSERVED findings)")
    add("")
    detections = report["detections"]
    if not detections["findings"]:
        add("No findings.")
    for finding in detections["findings"]:
        add(
            f"### [{finding['finding_uid']}] "
            f"{str(finding['severity']).upper()} — {finding['title']}"
        )
        add("")
        add(f"- rule: `{finding['rule_id']}` v{finding['rule_version']}")
        add(f"- confidence: {finding['confidence']}")
        if finding["mitre"]:
            add(f"- ATT&CK: {', '.join(finding['mitre'])}")
        for reason in finding["why"]:
            add(f"- why: {reason}")
        observed = finding["observed"]["facts"]
        if observed:
            add("- **OBSERVED**:")
            for fact in observed:
                add(f"  - {fact}")
        inferred = finding["inferred"]["hypotheses"]
        if inferred:
            add("- **INFERRED** (analyst decides):")
            for guess in inferred:
                add(f"  - {guess}")
        add("")

    add("## ATT&CK coverage")
    add("")
    coverage = report["attack_coverage"]
    add(f"Snapshot: {coverage['attack_snapshot']}")
    add("")
    if coverage["covered"]:
        add("Covered techniques:")
        for entry in coverage["covered"]:
            add(
                f"- {entry['technique_id']} {entry['name']} "
                f"(findings: {', '.join(entry['findings']) or 'none'})"
            )
    if coverage["gaps"]:
        add(f"Gaps (no findings): {', '.join(coverage['gaps'])}")
    add("")

    add("## Correlations")
    add("")
    correlations = report["correlations"]
    add(f"{correlations['cluster_count']} activity cluster(s).")
    for cluster in correlations["clusters"]:
        add("")
        add(f"### Cluster {cluster['cluster_id']} (confidence {cluster['confidence']})")
        add("")
        add(f"**OBSERVED** ({len(cluster['observed'])} events):")
        for event in cluster["observed"]:
            add(
                f"- {event.get('timestamp')} [#{event.get('id')}] "
                f"{event.get('source')}:{event.get('event_id')}"
            )
        if cluster["inferred"]:
            add("**INFERRED** linkages:")
            for link in cluster["inferred"]:
                add(
                    f"- [{link.get('kind')}] events "
                    f"#{link.get('event_a')}/#{link.get('event_b')}: "
                    f"{link.get('basis')}"
                )
        if cluster["whats_missing"]:
            add("What's missing:")
            for item in cluster["whats_missing"]:
                add(f"- {item}")
    add("")

    notes = report["analyst_notes"]
    add("## Analyst notes *(analyst-authored)*")
    add("")
    if not notes["notes"]:
        add("No analyst notes recorded.")
    for note in notes["notes"]:
        add(f"- [#{note['id']}] {note['ts']} ({note['author']}): {note['text']}")
    add("")

    add("## Limitations")
    add("")
    for limitation in report["limitations"]:
        add(f"- {limitation}")
    add("")

    add("## Chain of custody")
    add("")
    for item in report["chain_of_custody"]["evidence"]:
        add(
            f"- #{item['id']} {item['filename']} "
            f"sha256={item['sha256']} md5={item['md5']} "
            f"({item['size']} bytes, ingested {item['ingested_at']}, "
            f"parser {item['parser']})"
        )
    add("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML (self-contained: inline CSS, no external assets, no URLs)


_CSS = """
body{font-family:monospace,monospace;background:#1e1e1e;color:#d4d4d4;
margin:0;padding:0}
main{max-width:960px;margin:0 auto;padding:24px}
h1{color:#e8e8e8;border-bottom:2px solid #4ec9b0;padding-bottom:8px}
h2{color:#4ec9b0;margin-top:32px}
h3{color:#c586c0}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;
font-size:12px;font-weight:bold}
.obs{background:#1a4d2e;color:#9fe8b8}
.inf{background:#5a3d00;color:#ffd97a}
.gen{background:#3d3d5c;color:#c9c9ff}
table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{border:1px solid #444;padding:6px 10px;text-align:left;
vertical-align:top}
th{background:#2d2d2d;color:#e8e8e8}
.sev-critical{color:#ff6b6b;font-weight:bold}
.sev-high{color:#ff9e64;font-weight:bold}
.sev-medium{color:#e5c07b}
.sev-low{color:#98c379}
pre{background:#141414;padding:12px;overflow-x:auto;white-space:pre-wrap}
.note{border-left:3px solid #4ec9b0;padding:8px 12px;background:#242424;
margin:12px 0}
.warn{border-left:3px solid #e5c07b;padding:8px 12px;background:#2a2416;
margin:12px 0}
footer{margin-top:40px;color:#888;font-size:12px}
"""


def render_html(report: dict[str, Any]) -> str:
    """Self-contained offline HTML report (inline CSS, no external assets)."""
    meta = report["meta"]
    esc = html.escape
    parts: list[str] = []
    add = parts.append

    add("<!DOCTYPE html>")
    add('<html lang="en"><head><meta charset="utf-8">')
    add(f"<title>Case report {esc(str(meta['case_id']))} — HuntForge</title>")
    add(f"<style>{_CSS}</style></head><body><main>")

    add(f"<h1>Case report: {esc(str(meta['case_id']))}</h1>")
    add(
        f"<p>Generated {esc(str(meta['generated_at']))} by huntforge "
        f"{esc(str(meta['tool_version']))} "
        f"({esc(str(meta['reporting_module']))}).</p>"
    )

    summary = report["executive_summary"]
    add(
        "<h2>Executive summary "
        '<span class="badge gen">GENERATED — ANALYST REVIEW REQUIRED</span></h2>'
    )
    add(f"<div class='note'>{esc(summary['text'])}</div>")

    add("<h2>What this report does not claim</h2><ul>")
    for claim in report["what_this_report_does_not_claim"]:
        add(f"<li>{esc(claim)}</li>")
    add("</ul>")

    add("<h2>Methodology</h2><ul>")
    for parser in report["methodology"]["parsers"]:
        add(
            f"<li>parser <code>{esc(parser['name'])}</code> "
            f"v{esc(parser['version'])}</li>"
        )
    add("</ul>")

    overview = report["case_overview"]
    add("<h2>Case overview</h2>")
    add("<table><tr><th>Metric</th><th>Value</th></tr>")
    for key, label in (
        ("events", "Events"),
        ("evidence_files", "Evidence files"),
        ("untimed_events", "Untimed events"),
    ):
        add(f"<tr><td>{label}</td><td>{esc(str(overview[key]))}</td></tr>")
    add("</table><table><tr><th>Source</th><th>Events</th><th>Range</th></tr>")
    for source in overview["sources"]:
        add(
            f"<tr><td>{esc(str(source['source']))}</td>"
            f"<td>{esc(str(source['events']))}</td>"
            f"<td>{esc(str(source['first']))} .. {esc(str(source['last']))}</td></tr>"
        )
    add("</table>")

    add('<h2>Detections <span class="badge obs">OBSERVED</span></h2>')
    detections = report["detections"]
    if detections["findings"]:
        add(
            "<table><tr><th>UID</th><th>Severity</th><th>Rule</th>"
            "<th>Title</th><th>Conf</th><th>ATT&amp;CK</th></tr>"
        )
        for finding in detections["findings"]:
            sev = str(finding["severity"])
            add(
                f"<tr><td>{esc(str(finding['finding_uid']))}</td>"
                f'<td class="sev-{esc(sev)}">{esc(sev.upper())}</td>'
                f"<td>{esc(str(finding['rule_id']))}</td>"
                f"<td>{esc(str(finding['title']))}</td>"
                f"<td>{esc(str(finding['confidence']))}</td>"
                f"<td>{esc(', '.join(finding['mitre']))}</td></tr>"
            )
        add("</table>")
        for finding in detections["findings"]:
            add(
                f"<h3>[{esc(str(finding['finding_uid']))}] "
                f"{esc(str(finding['title']))}</h3>"
            )
            add("<ul>")
            for reason in finding["why"]:
                add(f"<li>why: {esc(reason)}</li>")
            add("</ul>")
            observed = finding["observed"]["facts"]
            if observed:
                add('<p><span class="badge obs">OBSERVED</span></p><ul>')
                for fact in observed:
                    add(f"<li>{esc(fact)}</li>")
                add("</ul>")
            inferred = finding["inferred"]["hypotheses"]
            if inferred:
                add(
                    '<p><span class="badge inf">INFERRED</span> '
                    "(analyst decides)</p><ul>"
                )
                for guess in inferred:
                    add(f"<li>{esc(guess)}</li>")
                add("</ul>")
    else:
        add("<p>No findings.</p>")

    add("<h2>Correlations</h2>")
    correlations = report["correlations"]
    add(f"<p>{correlations['cluster_count']} activity cluster(s).</p>")
    for cluster in correlations["clusters"]:
        add(
            f"<h3>Cluster {esc(str(cluster['cluster_id']))} "
            f"(confidence {esc(str(cluster['confidence']))})</h3>"
        )
        add(
            '<p><span class="badge obs">OBSERVED</span> '
            f"{len(cluster['observed'])} event(s)</p><ul>"
        )
        for event in cluster["observed"]:
            add(
                f"<li>{esc(str(event.get('timestamp')))} "
                f"[#{esc(str(event.get('id')))}] "
                f"{esc(str(event.get('source')))}:"
                f"{esc(str(event.get('event_id')))}</li>"
            )
        add("</ul>")
        if cluster["inferred"]:
            add('<p><span class="badge inf">INFERRED</span> linkages</p><ul>')
            for link in cluster["inferred"]:
                add(
                    f"<li>[{esc(str(link.get('kind')))}] events "
                    f"#{esc(str(link.get('event_a')))}/"
                    f"#{esc(str(link.get('event_b')))}: "
                    f"{esc(str(link.get('basis')))}</li>"
                )
            add("</ul>")
        if cluster["whats_missing"]:
            add("<div class='warn'><b>What's missing:</b><ul>")
            for item in cluster["whats_missing"]:
                add(f"<li>{esc(item)}</li>")
            add("</ul></div>")

    add("<h2>Analyst notes</h2>")
    notes = report["analyst_notes"]
    if notes["notes"]:
        for note in notes["notes"]:
            add(
                f"<div class='note'><b>#{esc(str(note['id']))}</b> "
                f"{esc(str(note['ts']))} ({esc(str(note['author']))}): "
                f"{esc(str(note['text']))}</div>"
            )
    else:
        add("<p>No analyst notes recorded.</p>")

    add("<h2>Limitations</h2><ul>")
    for limitation in report["limitations"]:
        add(f"<li>{esc(limitation)}</li>")
    add("</ul>")

    add("<h2>Chain of custody</h2>")
    add("<table><tr><th>#</th><th>File</th><th>SHA-256</th><th>Ingested</th></tr>")
    for item in report["chain_of_custody"]["evidence"]:
        add(
            f"<tr><td>{esc(str(item['id']))}</td>"
            f"<td>{esc(str(item['filename']))}</td>"
            f"<td>{esc(str(item['sha256']))}</td>"
            f"<td>{esc(str(item['ingested_at']))}</td></tr>"
        )
    add("</table>")

    add(
        f"<footer>HuntForge case report — generated "
        f"{esc(str(meta['generated_at']))}. The executive summary is "
        "machine-generated and requires analyst review.</footer>"
    )
    add("</main></body></html>")
    return "\n".join(parts) + "\n"
