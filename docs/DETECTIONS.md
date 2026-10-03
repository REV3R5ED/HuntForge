# HuntForge detection rules (v0.5)

> Every rule is a named, versioned Python function — no ML, no black
> box. A finding reports that a **technique-shaped pattern was
> observed**, with the evidence cited, the reasoning shown, and a
> confidence score *with its justification*. **No rule declares
> anything malicious.** The analyst makes the final call.

## Severity model

| Severity | Meaning |
|---|---|
| `critical` | Confirmed-compromise indicator. **No v0.5 starter rule emits this** — a heuristic alone is never enough to declare a compromise. Reserved for future high-confidence correlation (v0.7). |
| `high` | Strong technique indicator; prioritize investigation. |
| `medium` | Notable indicator; investigate in context. |
| `low` | Weak or noisy indicator; needs corroboration. |
| `informational` | Context worth knowing; no action implied. (No starter rules yet.) |

Severity ordering for `--severity high+`: `informational < low < medium < high < critical`.

## How to read a finding

- **why** — the matched conditions, in plain language.
- **what** — one-paragraph summary of the activity.
- **evidence** — every cited event as `event #N (source:event_id)` plus the observation drawn from it. Re-derive with `huntforge events --case ID`.
- **confidence** — 0–100, always paired with **confidence_reason**.
- **observed** vs **inferred** — facts are facts; guesses are labeled guesses.

Run the catalog: `huntforge detect --case CASE-001 [--rule ID] [--severity high+] [--explain]`
List rules: `huntforge rules list`

> v0.6: every rule below is mapped to MITRE ATT&CK technique(s) —
> findings carry `mitre` IDs. See [ATTACK.md](ATTACK.md) for the
> technique table, the per-rule mapping with reasoning, and the
> coverage philosophy.

---

## HF-DET-ENCPSH — Encoded PowerShell execution · HIGH

**Logic.** Process-creation events (Sysmon 1, Security 4688) where the
image is `powershell.exe`/`pwsh.exe` **and** the parser recorded the
`encoded-command` observation **or** the command line matches an
`-EncodedCommand`/`-enc`/`-e` switch.

**False positives.** Administrators and deployment tooling (SCCM,
scripts avoiding quoting pain) use `-EncodedCommand` legitimately.
Corroborate with the parent process (`HF-DET-OFFICE`), downloads
(`HF-DET-DLPSH`), and the surrounding timeline.

**Evidence required.** Sysmon 1 or Security 4688 **with command lines**
(requires Sysmon command-line capture / 4688 command-line auditing —
without it this rule cannot fire).

## HF-DET-DLPSH — PowerShell downloading remote content · HIGH

**Logic.** PowerShell script-block excerpts (4104/4103) and
`powershell.exe`/`pwsh.exe` command lines are scanned for
download-related patterns: `Invoke-WebRequest`/`IWR`,
`Invoke-RestMethod`/`IRM`, `Net.WebClient`, `DownloadString`/`DownloadFile`,
`bitsadmin … transfer`, `Start-BitsTransfer`, `certutil … urlcache`,
`curl`/`wget` with output flags. The matched pattern is named in the
finding.

**False positives.** Updaters, package managers, and admin tooling
download files routinely. The pattern name lets the analyst judge
intent.

**Evidence required.** PowerShell Script Block Logging (4104) or
process command lines. Script blocks are excerpted (500 chars) in the
normalized event; full text stays in the evidence file.

## HF-DET-OFFICE — Office application spawning shell/script interpreter · HIGH

**Logic.** Process-creation events where the parent image is an Office
host (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, …)
and the child is a shell/script host (`powershell.exe`, `cmd.exe`,
`wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`,
`regsvr32.exe`, `wmic.exe`).

**False positives.** Legitimate Office automation and add-ins
occasionally spawn shells. The child command line (shown in the
finding) usually separates benign automation from maldocs.

**Evidence required.** Process-creation telemetry with parent image
names (Sysmon 1 or Security 4688).

## HF-DET-RUNKEY — Run-key persistence · MEDIUM → HIGH

**Logic.** For each Run/RunOnce persistence event — offline-hive
Run-key values **or** Sysmon 12/13/14 writes under a `\Run`/`\RunOnce`
key — extract the target executable and check whether the same image
was observed executing (process creation or prefetch). Fires **MEDIUM**
for persistence alone, **HIGH** when execution is corroborated.

**False positives.** Installers and updaters legitimately use Run
keys. A lone Run key for a known-vendor binary is usually benign;
temp-dir targets deserve scrutiny.

**Evidence required.** Registry Run-key events (offline hive) or
Sysmon 12/13/14 under `\Run(Once)`. Sysmon targets are parsed from the
value-data excerpt (best effort). Execution correlation needs
process-creation or prefetch telemetry in the same case.

## HF-DET-SVC — Service with user-writable image path · HIGH

**Logic.** Service-definition events whose image path falls under a
writable/temp directory (`\Temp\`, `\Users\…\AppData\Local\Temp`,
`\ProgramData\`, `C:\Windows\Temp`).

**False positives.** Some third-party software installs services from
`ProgramData`. Check the vendor, the service account, and the binary's
reputation.

**Evidence required.** Service definitions (offline Services export).

## HF-DET-TASK — Scheduled task with user-writable action · MEDIUM

**Logic.** Scheduled-task events whose action path falls under a
writable/temp directory.

**False positives.** Updaters (browsers, chat apps) commonly schedule
tasks from AppData. Review the task author, triggers, and binary.

**Evidence required.** Scheduled-task XML exports.

## HF-DET-RAREPORT — Outbound connection to rare external port · LOW

**Logic.** Sysmon network-connection events (EventID 3) whose
destination is a **public** IP and whose destination port is outside
the built-in common-service list. Internal traffic never fires.

**False positives.** High — custom business apps, remote-access tools,
gaming, and P2P all use uncommon ports. Treat as a pivot lead: check
the process, the destination, and the timeline.

**Evidence required.** Sysmon 3 with destination IP/port. No
reputation lookup is performed (offline by design).

## HF-DET-BRUTE — Failed-logon burst · MEDIUM

**Logic.** Security 4625 events grouped by (user, source IP); a
sliding 10-minute window with **≥ 5** failures fires one finding per
pair, citing the densest window.

**False positives.** Mistyped passwords, stale cached credentials,
expired service-account passwords. A burst followed by a successful
4624 from the same source is far more interesting — check the
timeline.

**Evidence required.** Security 4625 with timestamps, target user, and
source IP.

## HF-DET-ADMINHOST — Privileged logon from first-seen host · LOW

**Logic.** Security 4624 events ordered per admin-like account
(`admin…`/`administrator`). When an account with an established source
history logs on from a **new** source IP, fire. Accounts with no prior
history never fire (no baseline, no finding).

**False positives.** Admins get new workstations; VPN/DHCP churn moves
source IPs. Low-confidence tripwire — best combined with other
findings.

**Evidence required.** Security 4624 with target user and source IP,
plus enough history to establish normal sources.

## HF-DET-TEMPEXEC — Execution from user-writable directory · MEDIUM

**Logic.** The executable path is extracted from each
process-creation command line (quoted program or first token) and
matched against writable/temp directory patterns.

**False positives.** Installers, self-updaters, and portable apps run
from temp directories. Path extraction is heuristic — unquoted or
heavily obfuscated command lines may be missed or misread.

**Evidence required.** Process-creation events with command lines
(Sysmon 1 or Security 4688 with command-line auditing).

---

## Deliberate omissions (v0.5)

- **LSASS access (Sysmon 10):** not parsed yet — no rule.
- **Signature status:** no signature data in the model — no rule.
- **Impossible travel:** overreach for host telemetry — skipped in
  favor of `HF-DET-ADMINHOST`.
- **Critical severity:** no starter rule emits it (see severity model).
- **Allow/block lists:** planned; not in v0.5.
