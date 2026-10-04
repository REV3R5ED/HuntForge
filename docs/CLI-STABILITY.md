# HuntForge CLI stability policy (v1.x)

v1.0 freezes the command surface. Automation built against
`huntforge 1.x` keeps working for the whole 1.x series.

## Stable commands

Every command below keeps its name, its flags, its exit-code
behavior, and its `--json` envelope shape through v1.x:

| Command | Purpose |
|---------|---------|
| `case create/show/list` | case management |
| `ingest` | ingest evidence into a case |
| `events` | query normalized events |
| `audit` | case audit log |
| `registry` | offline hive key listing |
| `timeline` | unified chronological view |
| `lineage` | process parent/child trees |
| `entities` | cross-source entity resolution |
| `detect` | explainable detection rules |
| `rules list` | detection rule catalog |
| `mitre` / `mitre techniques` | ATT&CK coverage |
| `sigma list` / `sigma run` | Sigma-subset rules |
| `correlate` | cross-source correlation |
| `narrative` | cluster narrative |
| `report case` | case reports (json/html/md/csv) |
| `notes` | analyst notes |
| `batch` | batch triage |
| `export` | JSONL export for SIEM |
| `schema` | print stable schema documents |

Global flags `--json`, `--state-dir`, `--config`, `--version` are
stable. Exit codes are stable: `0` success, `1` findings/warnings,
`2` error.

## What "stable" means

- Command and flag names: unchanged.
- `--json` envelope (`huntforge/envelope@1.0`): unchanged.
- Record schemas (`docs/SCHEMAS.md`): fields only added, never
  removed, renamed, or retyped.
- Human-readable text output is **not** covered — it is for eyes,
  not parsers. Parse `--json`.
- Rule logic may improve (better precision, new rules); rule **IDs**
  (`HF-DET-XXX`) are stable, rule versions bump when logic changes.

## Deprecation policy

If a command or flag must change in a future major version:

1. The old spelling keeps working for one full minor-version
   series, emitting a stderr deprecation warning naming the
   replacement.
2. The deprecation is recorded in `CHANGELOG.md` under the version
   that introduces it.
3. Removal happens only in a new major version (2.0), and the
   migration is documented in the release notes.

No deprecations are active in 1.0.0 — nothing from the 0.x series
was removed to reach 1.0.
