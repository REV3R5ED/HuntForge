# MITRE ATT&CK in HuntForge (v0.6)

## What this is

HuntForge ships a **curated, local ATT&CK technique table**
(`src/huntforge/mitre/techniques.json`) — a versioned subset chosen for
endpoint forensics, stamped with the ATT&CK snapshot it was curated
from (currently ATT&CK v16.1, October 2026). It is **not the full
matrix**, and it never phones home: there is no TAXII feed, no
network call, no auto-update. When the table needs refreshing, it is
refreshed by hand, reviewed, and versioned with the release.

Technique IDs are stable references. Names, tactic assignments, and
descriptions are HuntForge's own summaries, written for analysts.

## Coverage philosophy

A finding mapped to a technique is **evidence that the technique was
used** in the case. It is never attribution of actor intent, and a
technique with no findings is a **gap in evidence, not proof of
absence**. Every mapping below documents its reasoning; weak mappings
say so.

`huntforge mitre --case ID` shows the coverage view: which techniques
have findings (with the rules and finding UIDs behind each), which
techniques have no findings (**gaps**), and which techniques HuntForge
cannot currently observe at all (**not observable with current
parsers** — e.g. LSASS access needs Sysmon EventID 10, which no parser
reads yet). `huntforge mitre techniques` lists the whole table.

## The curated table (23 techniques)

| ID | Name | Tactics | Observable via |
|----|------|---------|----------------|
| T1059.001 | PowerShell | Execution | sysmon:1, evtx:Security:4688, powershell:4103/4104 |
| T1059.003 | Windows Command Shell | Execution | sysmon:1, evtx:Security:4688 |
| T1053.005 | Scheduled Task/Job | Execution, Persistence, Privilege Escalation | tasks:task |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | registry:run-key, sysmon:12/13/14 |
| T1543.003 | Windows Service | Persistence, Privilege Escalation | services:service |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | — (needs Security 1102; not parsed) |
| T1070.004 | File Deletion | Defense Evasion | — (needs Sysmon 23; not parsed) |
| T1003.001 | LSASS Memory | Credential Access | — (needs Sysmon 10; not parsed) |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | evtx:Security:4624, sysmon:3 |
| T1083 | File and Directory Discovery | Discovery | sysmon:1, evtx:Security:4688 (weak) |
| T1033 | System Owner/User Discovery | Discovery | sysmon:1, evtx:Security:4688 (weak) |
| T1057 | Process Discovery | Discovery | sysmon:1, evtx:Security:4688 (weak) |
| T1016 | System Network Configuration Discovery | Discovery | sysmon:1, evtx:Security:4688 (weak) |
| T1049 | System Network Connections Discovery | Discovery | sysmon:1, evtx:Security:4688 (weak) |
| T1135 | Network Share Discovery | Discovery | sysmon:1, evtx:Security:4688 (weak) |
| T1204.002 | Malicious File | Execution | sysmon:1, evtx:Security:4688 |
| T1566.001 | Spearphishing Attachment | Initial Access | sysmon:1 (execution side only; delivery is PhishScope's job) |
| T1105 | Ingress Tool Transfer | Command and Control | powershell:4103/4104, sysmon:1 |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | sysmon:3 |
| T1071 | Application Layer Protocol | Command and Control | sysmon:3 |
| T1571 | Non-Standard Port | Command and Control | sysmon:3 |
| T1110 | Brute Force | Credential Access | evtx:Security:4625 |
| T1078 | Valid Accounts | Defense Evasion, Persistence, Privilege Escalation, Initial Access | evtx:Security:4624 |

## Built-in rule → technique mapping

| Rule | Techniques | Reasoning |
|------|-----------|-----------|
| HF-DET-ENCPSH (Encoded PowerShell) | T1059.001 | Encoded execution *in PowerShell* — the technique is the interpreter abuse, not encoding in general. |
| HF-DET-DLPSH (PowerShell downloads) | T1105 | Remote content retrieval into the victim environment. |
| HF-DET-OFFICE (Office → shell) | T1204.002 | User execution of a malicious file. **Not** T1566.001: we see the execution, never the delivery email. |
| HF-DET-RUNKEY (Run-key persistence) | T1547.001 | Direct sub-technique match. |
| HF-DET-SVC (writable service image) | T1543.003 | Direct sub-technique match. |
| HF-DET-TASK (writable task action) | T1053.005 | Direct sub-technique match. |
| HF-DET-RAREPORT (rare external port) | T1571 | Non-standard port use. Weak on its own — documented as a pivot lead. |
| HF-DET-BRUTE (failed-logon burst) | T1110 | Direct technique match. |
| HF-DET-ADMINHOST (privileged logon, new host) | T1078 | Valid-account use from an unexpected source. |
| HF-DET-TEMPEXEC (writable-dir execution) | T1204.002 | Execution of a user-controlled file. Weaker than OFFICE's mapping — the file's provenance is unknown, so this is recorded as a lower-confidence association. |

Every v0.5 rule maps to at least one table technique (`validate_mapping()`
in `huntforge.mitre.mapping` enforces this in tests). The detection
engine copies the mapping onto each finding (`finding.mitre`), and the
case store persists it, so `huntforge mitre --case` covers Sigma
findings too.

## Sigma-subset rule support

HuntForge evaluates a documented **subset** of Sigma — enough for the
common shapes, honest about the rest.

### Rule format (JSON, preferred)

```json
{
  "title": "Encoded PowerShell Command Line",
  "id": "hf-sigma-0001",
  "description": "…",
  "author": "HuntForge",
  "date": "2026/10/03",
  "status": "experimental",
  "logsource": {"product": "windows", "category": "process_creation"},
  "detection": {
    "selection": {
      "Image": ["*\\powershell.exe", "*powershell.exe"],
      "CommandLine": ["*-EncodedCommand*", "*-enc *"]
    },
    "condition": "selection"
  },
  "falsepositives": ["…"],
  "level": "high",
  "tags": ["attack.execution", "attack.t1059.001"]
}
```

- `detection` holds named selections; each maps Sigma field names to a
  value or list of values (list = OR). All fields in a selection must
  match (AND).
- `condition` is required. Supported: `selection`,
  `a and b`, `a or b`, `not a`, `a and not b`,
  `1 of sel*`, `all of sel*` (`*` globs over selection names).
- Values support `*` wildcards (case-insensitive fnmatch).
- Sigma field names map to HuntForge event fields (`Image` →
  `process_name`, `CommandLine` → `command_line`, `ParentImage` →
  `parent_name`, `DestinationIp`/`DestinationPort`, `TargetObject` →
  `registry_key`, …). Unknown fields are a load-time error listing
  what is supported.
- `logsource.category` filters events (`process_creation` → Sysmon 1,
  `network_connection` → Sysmon 3, `ps_script` → PowerShell 4103/4104,
  `registry_event` → Sysmon 12/13/14). Unknown categories match all
  events (the logsource is echoed, never silently applied).
- `level` maps to severity; the finding's confidence derives from the
  **rule author's** level, and the confidence reason says so.
- `attack.t1059.001` tags become the finding's `mitre` list.

### YAML (best effort)

Real Sigma YAML goes through a minimal hand-written subset parser
(`huntforge.sigma.yaml_subset`) — stdlib-only means no PyYAML.
Supported: block mappings, block sequences, `- key: value` inline map
heads, quoted/bare strings, integers, `true`/`false`,
`null`. **Not supported** (each fails loudly, naming the construct):
tabs, flow collections (`{}`/`[]`), block scalars (`|`/`>`),
anchors/aliases, tags, directives, duplicate keys, multi-line strings.

### Not supported (by design, v0.6)

`|contains` / `|startswith` / `|endswith` / `|re` modifiers (use `*`
wildcards), aggregations (`count() by …`), `near` temporal
correlation, nested selections, keyword-only selections,
multi-document files. A rule using any of these is rejected at load
time with a message saying exactly what is unsupported — never
silently mis-evaluated.

### CLI

```console
$ huntforge sigma list
$ huntforge sigma run --case CASE-001 --rule hf-sigma-0001
$ huntforge sigma run --case CASE-001 --rule ./my_rule.yaml --json
```

`sigma run` persists findings like `detect` does (exit 1 when findings
exist), with provenance `huntforge.sigma` and rule version `0.6.0`.
Bare names resolve against the four bundled samples in
`huntforge/sigma/samples/` (3 JSON + 1 YAML).
