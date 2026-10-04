# HuntForge stable JSON schemas (v1.0)

HuntForge's automation surface is its JSON: every `--json` envelope,
every JSONL export line, every batch artifact, every generated report.
v1.0 freezes these contracts. The machine-readable documents live in
`src/huntforge/schemas/` and print offline via:

```
huntforge schema                  # list all schema names and $ids
huntforge schema event            # print the event schema document
huntforge schema finding --json   # same, as JSON
```

## The 1.x stability promise

- Fields are **only ever added**, never removed, renamed, or retyped
  during v1.x.
- New optional fields may appear; consumers should ignore unknown
  fields.
- A breaking change would mint a **new `$id`** (e.g.
  `huntforge/event@2.0`) — the `@1.0` documents keep meaning exactly
  what they mean today.
- Parser versions (`provenance.parser_version`) evolve independently;
  they describe the parser build, not the schema.

## Schema index

| Name | `$id` | Where it appears |
|------|-------|------------------|
| `envelope` | `huntforge/envelope@1.0` | every command's `--json` output |
| `event` | `huntforge/event@1.0` | `events` payload, `export --what events`, timeline items |
| `finding` | `huntforge/finding@1.0` | `detect`/`sigma run` findings, `export --what findings` |
| `linkage` | `huntforge/linkage@1.0` | `correlate` clusters, narratives (always `label: "INFERRED"`) |
| `activity_cluster` | `huntforge/activity-cluster@1.0` | `correlate` data.clusters |
| `narrative` | `huntforge/narrative@1.0` | `narrative` command data |
| `report` | `huntforge/report@1.0` | `report case --format json` (`meta.report_schema_version`) |
| `batch_summary` | `huntforge/batch-summary@1.0` | `batch` data payload and `batch-summary.json` |
| `batch_manifest` | `huntforge/batch-manifest@1.0` | `batch-manifest.json` (sha256 → case record) |
| `jsonl_envelope` | `huntforge/jsonl-envelope@1.0` | every line of `export` output |
| `case` | `huntforge/case@1.0` | `case show` / `case list` records |
| `audit_entry` | `huntforge/audit-entry@1.0` | `audit` entries, report chain-of-custody |
| `note` | `huntforge/note@1.0` | `notes` records |
| `entity` | `huntforge/entity@1.0` | `entities` records |
| `registry_view` | `huntforge/registry-view@1.0` | `registry` data payload |
| `rule` | `huntforge/rule@1.0` | `rules list` catalog entries |
| `sigma_rule` | `huntforge/sigma-rule@1.0` | `sigma list` entries |
| `technique` | `huntforge/technique@1.0` | `mitre techniques` entries |

## Contract notes

**Envelope.** `{"tool","version","command","timestamp","status",
"summary","data","findings","events"}`. `status` drives the exit
code: `ok` → 0, `warning` → 1 (findings are the product, not an
error), `error` → 2. `data` is command-specific (documented per
command in `docs/USAGE.md`); `findings` holds finding records;
`events` holds event records.

**Event.** Field presence is stable across all parsers — 23 keys,
inapplicable ones `null`, never absent. `timestamp` is UTC (`Z`);
`timestamp_original` preserves the source's verbatim text and is
`null` only when the source carried no recoverable time (the
"untimed" section of `timeline`).

**Finding.** `why` (matched conditions), `observed` (facts),
`inferred` (labeled hypotheses), `evidence` (event row-id citations),
`confidence` 0–100 with `confidence_reason`. `finding_uid`
(`HF-0001`…) and `created_at` exist on stored findings; fresh
engine output may omit them.

**Report vs finding.** The generated report wraps each finding's
`observed`/`inferred` arrays as objects —
`{"facts": [...], "note": ...}` / `{"hypotheses": [...], "note": ...}` —
so the report is explicit about what the analyst still owes. The
underlying finding contract is unchanged.

**Linkage.** Always carries `"label": "INFERRED"`. `kind` is one of
`same-process`, `same-file`, `persistence-execution`,
`download-execution`. `confidence` is the weakest link in its
cluster's chain. Narratives render linkages in a condensed form
(`claim` replaces `basis`/`heuristic` for analyst reading) — the
full form is always available from `correlate`.

**Batch.** `batch-summary.json` and the `batch` command's data
payload are the same document. `batch-manifest.json` maps input
SHA-256 → the case record; entries with `"status": "ok"` are
skipped on re-run (`"status": "skipped"` in the summary).

**Validation.** `tests/test_schemas.py` runs every command against
a fixture case and validates each `--json` output with
`huntforge.schemas.validate()` — the suite fails on drift, so the
documents above cannot silently go stale.
