# HuntForge integrations (v1.0)

Everything an automation consumer needs to drive HuntForge from a
pipeline: the JSONL export schemas, the result envelope, exit codes,
the batch manifest/summary formats, input caps, and the config file.
HuntForge is stdlib-only and fully offline — nothing here makes
network calls.

The full field-level contracts live in `docs/SCHEMAS.md` and are
machine-readable via `huntforge schema <name>` (no network needed).

## JSONL export (`huntforge export`)

```
huntforge export --case CASE-001 --what events -o events.jsonl
huntforge export --case CASE-001 --what findings --format jsonl -o findings.jsonl
huntforge export --case CASE-001 --what events > events.jsonl   # stdout mode
```

- One JSON object per line, UTF-8, `\n`-terminated. Every line parses
  independently — stream it, `jq` it, ship it to a SIEM.
- Deterministic order: events by row id, findings by UID. Re-exports
  are byte-identical unless the case changed.
- Without `--output`, the JSONL goes to **stdout** and the result
  envelope moves to **stderr** (pipe-safe). `--json` requires
  `--output` (stdout is reserved for the data).

### Event line

```json
{
  "record_type": "event",
  "schema": "huntforge/event@1.0",
  "tool": "huntforge",
  "version": "1.0.0",
  "record": {
    "id": 3,
    "timestamp": "2026-10-02T09:14:02Z",
    "timestamp_original": "2026-10-02 09:14:02.123",
    "host": "WS-FIN-014",
    "user": "m.alvarez",
    "source": "sysmon",
    "event_id": "1",
    "process_name": "powershell.exe",
    "process_id": 8114,
    "parent_name": "winword.exe",
    "parent_id": 6020,
    "command_line": "powershell.exe -NoProfile -EncodedCommand ...",
    "src_ip": null, "src_port": null,
    "dst_ip": "203.0.113.44", "dst_port": 443,
    "file_path": null,
    "registry_key": null,
    "hashes": {"sha256": "...", "md5": "..."},
    "flags": ["encoded-command"],
    "evidence_id": 1,
    "provenance": {
      "source_file": "evidence/sysmon_intrusion.xml",
      "record_index": 12,
      "parser_name": "sysmon",
      "parser_version": "0.2.0",
      "ingest_time": "2026-10-03T07:00:51Z",
      "source_sha256": "..."
    },
    "raw": "sysmon event 1"
  }
}
```

### Finding line

```json
{
  "record_type": "finding",
  "schema": "huntforge/finding@1.0",
  "tool": "huntforge",
  "version": "1.0.0",
  "record": {
    "finding_uid": "HF-0001",
    "rule_id": "HF-DET-ENCPSH",
    "rule_version": "0.5.0",
    "severity": "high",
    "title": "Encoded PowerShell execution",
    "confidence": 75,
    "confidence_reason": "...",
    "why": ["powershell.exe ran with -EncodedCommand ..."],
    "what": "powershell.exe(8114) executed an encoded command",
    "evidence": [{"event_id": 3, "observation": "..."}],
    "observed": ["..."],
    "inferred": ["..."],
    "mitre": ["T1059.001"],
    "provenance": "huntforge.detections",
    "created_at": "2026-10-03T07:00:52Z"
  }
}
```

Schema stability: `huntforge/event@1.0` / `huntforge/finding@1.0`
are the frozen v1.x contracts. New fields may be added; existing
fields will not be renamed, removed, or retyped during v1.x. A
breaking change would mint new `$id` versions (e.g.
`huntforge/event@2.0`).

## Result envelope (`--json`)

Every command emits the same envelope on stdout (unless `--output`
is omitted on `export`, where stdout is the data):

```json
{
  "tool": "huntforge",
  "version": "1.0.0",
  "command": "detect",
  "timestamp": "2026-10-03T07:00:00Z",
  "status": "ok",
  "summary": "3 finding(s): 2 high, 1 medium",
  "data": {},
  "findings": [],
  "events": []
}
```

`status` is `ok` | `warning` | `error`. Diagnostics always go to
stderr; stdout carries only the envelope (or the data, for stdout
export). The envelope contract is `huntforge/envelope@1.0`
(`huntforge schema envelope`).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | success (including "no events match", "no findings") |
| `1` | success with findings/warnings (detections found something, batch had failures) |
| `2` | usage or operational error |

## Batch (`huntforge batch`)

```
huntforge batch ./evidence-drop --output ./batch-out
huntforge batch ./evidence-drop --output ./batch-out --severity high
```

- Input: a directory, walked recursively (sorted). Hidden paths
  (any component starting with `.`) are skipped.
- One case per file: `batch-0001-sysmon_intrusion`, `batch-0002-...`
  — deterministic from the sorted filename order. Each file is
  ingested with source auto-detection and run through the detection
  catalog; findings are stored in the case.
- `batch-summary.json` (in `--output`, contract
  `huntforge/batch-summary@1.0`): files found/created/skipped,
  per-case event and finding counts, severity totals, `files_failed`,
  and `top_techniques` (ATT&CK coverage computed from stored
  findings only).
- `batch-manifest.json` (in `--output`, contract
  `huntforge/batch-manifest@1.0`): per-SHA-256 processing records.
  Re-running the same command **skips** files already processed
  (`status: "skipped"`). A corrupt manifest is discarded and
  rebuilt — never fatal.
- Each processed case gets its own `batch` audit record in the case DB.

## Input caps

| Cap | Value | Behavior when exceeded |
|-----|-------|------------------------|
| Files per batch | 10,000 | run refused (split the input) |
| Input bytes per batch | 10 GiB | run refused |
| Parsed file size | 100 MiB (`MAX_PARSE_BYTES`) | registered as evidence, not parsed; warning |
| JSONL fixture line | 1 MiB (`MAX_FIXTURE_LINE_BYTES`) | line skipped; warning |
| Warnings per file | 25 (`MAX_WARNINGS_PER_FILE`) | truncated in output (full set in `--json`) |

Parsers are best-effort: malformed input produces warnings, never a
crash. The batch runner wraps per-file work so one corrupt file can
never abort the run.

## Config file

`~/.huntforge/config.toml`, or `--config PATH`:

```toml
state_dir = "/srv/huntforge/state"   # default state directory
default_severity = "high"            # default detect --severity filter
analyst_name = "Pouya"               # default author for notes --add
```

- All keys optional; unknown keys produce a stderr warning.
- `default_severity` must be
  `informational|low|medium|high|critical` (a bare level filters to
  exactly that level; append `+`, e.g. `high+`, for "at least").
