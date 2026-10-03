# HuntForge

**Hunt the endpoint. Reconstruct the attack.**

HuntForge is an endpoint threat-hunting and Windows forensics platform.
It ingests endpoint telemetry and forensic artifacts, normalizes them
into a common evidence model, reconstructs timelines and process
relationships, runs explainable detections, maps to MITRE ATT&CK, and
produces reproducible investigation cases.

Built for SOC analysts, threat hunters, DFIR practitioners, incident
responders, and students. Defensive-first: evidence is read-only by
default, every detection is explainable with preserved evidence, humans
make the final judgment, and observed facts are always distinguished
from inference.

## v0.6 — what works today

- **Core CLI** (`huntforge`): `case create/show/list`, `ingest`,
  `events`, `registry`, `timeline`, `lineage`, `entities`, `detect`,
  `rules list`, `mitre`, `mitre techniques`, `sigma list`,
  `sigma run`, `audit`, `--version`. JSON output on every command
  (`--json`), structured exit codes (0 ok / 1 findings / 2 error).
- **Normalized event model** (the v1.0-stable core): UTC-normalized
  timestamps with originals preserved, host/user, source + event id,
  process and parent (name/pid), command line, network tuple,
  file path, registry key, hashes, parser-observation **flags**, raw
  reference — and **mandatory provenance** (source file, record index,
  parser name/version, ingest time, source SHA-256) on every event.
  v0.4 fix: an explicit `timestamp_original=None` (parser could not
  recover an original timestamp) is now preserved instead of being
  filled in — those events surface as *untimed*, never placed on a
  timeline.
- **Telemetry parsers** (stdlib-only, fully offline): Sysmon
  (EventIDs 1/3/7/11/12/13/14), Security log (4624/4625/4634/4647
  logon/logoff, 4688 process creation with hex-PID decoding),
  PowerShell operational log (4103/4104 script-block capture,
  4105/4106), and generic exported Windows Event XML/JSON.
  `-EncodedCommand`/`-enc` is recorded as `flags: ["encoded-command"]`
  — an observation, never a verdict.
- **Persistence parsers** (stdlib-only, fully offline — forensic
  copies only, never the live system):
  - Prefetch (`.pf`, versions 23/26/30): executable, run count,
    last-run times, referenced files, volume info → one
    `prefetch:prefetch` execution-evidence event per file.
  - Offline registry hives (`regf`): `huntforge registry <hive>
    <key-path>` lists subkeys and decodes `REG_SZ`/`REG_EXPAND_SZ`/
    `REG_BINARY`/`REG_DWORD`/`REG_MULTI_SZ`/`REG_QWORD`; ingest
    auto-scans `Run`/`RunOnce` keys into `registry:run-key` events.
  - Scheduled tasks (`schtasks /query /xml`): triggers, actions,
    principals → `tasks:task` events with `runs-as-system` /
    `action-in-temp-dir` observations.
  - Services: JSON exports or a `SYSTEM` hive's `Services` key →
    `services:service` events with `auto-start` /
    `image-in-temp-dir` / `unquoted-service-path` observations.
- **Unified timeline** (`huntforge timeline --case ID [--from TS]
  [--to TS] [--source TYPE]`): every event with an original timestamp
  merged into one UTC-chronological view with per-source coverage
  (counts, first/last seen); events without one go in an `untimed`
  section — never dropped, never invented.
- **Process lineage** (`huntforge lineage --case ID [--pid N |
  --image NAME]`): parent→child trees from Sysmon 1 / Security 4688
  creation records. Same (host, PID, image) merges into one instance;
  PID reuse becomes separate instances with the reused PID flagged,
  and an ambiguous child links to the latest plausible parent with an
  explicit note naming every candidate.
- **Entity resolution** (`huntforge entities --case ID [--type T]`):
  hosts case-insensitive, `DOMAIN\user` → `user@domain`, file paths
  and registry keys case-insensitive, hashes lowercased — with every
  observed spelling, per-source observation counts, and first/last
  seen. Observation only: no verdicts (v0.5).
- **Evidence ingest**: registers files with SHA-256 + MD5 hashing
  (sources never modified; duplicates deduped by hash), auto-detects
  the source kind by content (`--source` overrides, `--no-parse`
  registers only), and reports `parsed_events`, `parsed_by_source`
  and `parse_warnings` — malformed records warn, never crash.
- **Per-case SQLite event store** (`~/.huntforge/cases/<CASE-ID>/store.db`,
  override with `HUNTFORGE_STATE_DIR`): cases, evidence registry,
  events with indexes on timestamp/host/user/event-id/process, and an
  audit table. v0.1 databases gain the `flags` column automatically.
- **Audit trail**: every CLI invocation touching a case is logged
  (command, args, timestamp, result count).
- **ATT&CK mapping** (`huntforge mitre --case ID`, `huntforge mitre
  techniques`): a curated local technique table (23 techniques,
  versioned, ATT&CK v16.1 snapshot — a subset, documented as such,
  fully offline). Every v0.5 detection rule is mapped to its
  technique(s); findings carry `mitre` IDs and the case store
  persists them. Coverage view shows techniques with findings, gaps
  (no findings), and techniques not observable with current parsers
  (e.g. LSASS access needs Sysmon 10). A mapped finding is evidence
  of technique *use* — never attribution of intent. See
  [docs/ATTACK.md](docs/ATTACK.md).
- **Sigma-subset rules** (`huntforge sigma list`, `huntforge sigma run
  --case ID --rule FILE`): documented JSON rule schema plus a
  best-effort YAML importer (hand-written subset parser, stdlib-only).
  Supported: named selections, `and`/`or`/`not` conditions,
  `1 of sel*` / `all of sel*`, `*` wildcards, Sigma field-name
  mapping, logsource filtering. Not supported (loud load-time
  errors, never silent): `|contains`-style modifiers, aggregations,
  `near`, nested selections. Four bundled samples; findings keep
  provenance `huntforge.sigma` v0.6.0 and `attack.t*` tags become
  `mitre` IDs.

## Quick start

```bash
pip install -e '.[dev]'      # or: pip install huntforge

huntforge case create CASE-001 --name "Workstation WS-001"
huntforge ingest ./evidence --case CASE-001
huntforge ingest ./evidence --case CASE-001 --fixture events.jsonl
huntforge events --case CASE-001 --process powershell.exe
huntforge events --case CASE-001 --host WS-001 --keyword mimikatz --json
huntforge timeline --case CASE-001
huntforge lineage --case CASE-001 --image powershell
huntforge entities --case CASE-001 --type ip
huntforge audit --case CASE-001
```

See [docs/USAGE.md](docs/USAGE.md) for a full scenario walkthrough.

## Roadmap

- [x] **v0.1** — Core CLI, normalized event model, JSON output, provenance
- [x] **v0.2** — Windows Event/Sysmon/PowerShell ingestion
- [x] **v0.3** — Prefetch, registry hives, scheduled tasks, services
- [x] **v0.4** — Unified timeline, process lineage, entity views, gap reporting
- [x] **v0.5** — Explainable detection rules (never label malicious from a heuristic alone)
- [x] **v0.6** — MITRE ATT&CK mapping, Sigma-compatible rule ingestion
- [ ] **v0.7** — Correlation engine, investigation graph export
- [ ] **v0.8** — Case management (notes, findings, manifests, chain of custody), reports
- [ ] **v0.9** — Analyst UI + ecosystem integrations (SentinelKit, LogLens, AegisForge)
- [ ] **v1.0** — Stable schemas, release docs, benchmark/demo corpus, hardened plugin API

## Limitations (v0.6)

- **Binary `.evtx` is not parsed**: the adapter detects it by magic
  bytes and prints the exact `wevtutil qe … /f:xml` command to export
  it first. Exported Event XML and JSON are fully parsed.
- **Prefetch**: versions 23/26/30 only. Compressed (MAM) prefetch and
  version 31 (Windows 11 24H2+) are rejected with guidance;
  trace-chain arrays are not parsed.
- **Registry**: offline forensic copies only (never the live
  registry). No transaction-log replay, no deleted-cell recovery, no
  multi-cell (`db`) large values, no security descriptors.
- **Timeline**: ordering is only as good as source clocks; clock skew
  between hosts is not corrected.
- **Lineage**: a child links to the latest parent instance whose
  start precedes the child's; short-lived processes can mislead the
  heuristic — the ambiguity note is the safety net, not a guarantee.
- Parsers are validated against synthetic fixtures built to the
  published binary layouts; validation against live forensic copies
  is pending.
- No correlation or reports (v0.7+).
  Amcache/Shimcache parsing is not yet implemented.
- Detections are heuristics, not verdicts: no v0.5 rule emits
  `critical`, every finding separates observed facts from inferences,
  and confidence scores always carry their reasoning. Parser flags and
  the v0.4 views remain observations only.
- ATT&CK table is a curated 23-technique subset (not the full
  matrix); mappings are evidence of technique use, never attribution.
  Sigma support is a documented subset — modifiers, aggregations,
  and `near` are rejected at load time, never silently mis-evaluated.
- Single-user local tool: the SQLite store has no access control;
  keep case directories on trusted storage.
- Python 3.10–3.13, stdlib only (no third-party runtime dependencies).

## Development

```bash
python -m pip install -e '.[dev]'
pytest -q            # 272 tests, 88%+ coverage, 80% gate
ruff check . && ruff format --check . && mypy src
```

## License

MIT — see [LICENSE](LICENSE). Copyright 2026 Pouya Shini Karim.
