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

## v0.2 — what works today

- **Core CLI** (`huntforge`): `case create/show/list`, `ingest`,
  `events`, `audit`, `--version`. JSON output on every command
  (`--json`), structured exit codes (0 ok / 2 error).
- **Normalized event model** (the v1.0-stable core): UTC-normalized
  timestamps with originals preserved, host/user, source + event id,
  process and parent (name/pid), command line, network tuple,
  file path, registry key, hashes, parser-observation **flags**, raw
  reference — and **mandatory provenance** (source file, record index,
  parser name/version, ingest time, source SHA-256) on every event.
- **Telemetry parsers** (stdlib-only, fully offline): Sysmon
  (EventIDs 1/3/7/11/12/13/14), Security log (4624/4625/4634/4647
  logon/logoff, 4688 process creation with hex-PID decoding),
  PowerShell operational log (4103/4104 script-block capture,
  4105/4106), and generic exported Windows Event XML/JSON.
  `-EncodedCommand`/`-enc` is recorded as `flags: ["encoded-command"]`
  — an observation, never a verdict.
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

## Quick start

```bash
pip install -e '.[dev]'      # or: pip install huntforge

huntforge case create CASE-001 --name "Workstation WS-001"
huntforge ingest ./evidence --case CASE-001
huntforge ingest ./evidence --case CASE-001 --fixture events.jsonl
huntforge events --case CASE-001 --process powershell.exe
huntforge events --case CASE-001 --host WS-001 --keyword mimikatz --json
huntforge audit --case CASE-001
```

See [docs/USAGE.md](docs/USAGE.md) for a full scenario walkthrough.

## Roadmap

- [x] **v0.1** — Core CLI, normalized event model, JSON output, provenance
- [x] **v0.2** — Windows Event/Sysmon/PowerShell ingestion
- [ ] **v0.3** — Prefetch, Amcache/Shimcache, registry persistence, services, tasks
- [ ] **v0.4** — Unified timeline, process lineage, entity views, gap reporting
- [ ] **v0.5** — Explainable detection rules (never label malicious from a heuristic alone)
- [ ] **v0.6** — MITRE ATT&CK mapping, Sigma-compatible rule ingestion
- [ ] **v0.7** — Correlation engine, investigation graph export
- [ ] **v0.8** — Case management (notes, findings, manifests, chain of custody), reports
- [ ] **v0.9** — Analyst UI + ecosystem integrations (SentinelKit, LogLens, AegisForge)
- [ ] **v1.0** — Stable schemas, release docs, benchmark/demo corpus, hardened plugin API

## Limitations (v0.2)

- **Binary `.evtx` is not parsed**: the adapter detects it by magic
  bytes and prints the exact `wevtutil qe … /f:xml` command to export
  it first. Exported Event XML and JSON are fully parsed.
- No prefetch/registry/task parsers yet (v0.3); no timeline,
  detections, ATT&CK mapping, correlation, or reports (v0.4+).
- Parser flags (e.g. `encoded-command`) are observations only — v0.5
  detections will act on them; nothing is ever labeled malicious by
  a parser.
- Single-user local tool: the SQLite store has no access control;
  keep case directories on trusted storage.
- Python 3.10–3.13, stdlib only (no third-party runtime dependencies).

## Development

```bash
python -m pip install -e '.[dev]'
pytest -q            # 68 tests, 90%+ coverage, 80% gate
ruff check . && ruff format --check . && mypy src
```

## License

MIT — see [LICENSE](LICENSE). Copyright 2026 Pouya Shini Karim.
