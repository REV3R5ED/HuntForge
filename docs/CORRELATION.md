# CORRELATION.md — linkage heuristics and their failure modes

HuntForge v0.7 correlates a case's events into **activity clusters**
and renders each cluster as an **attack narrative**. The design rule
from the master plan applies throughout: **observed facts and
inferences are kept separate**. Events are OBSERVED; the links between
them are INFERRED hypotheses — deterministic, explainable, and always
labeled as such.

A linkage joins exactly two events. Clusters are the connected
components of the linkage graph (events joined by any chain of
linkages). A single unlinked event is not a cluster — it is reported
as uncorrelated.

## The four heuristics

### 1. same-process — confidence 90

**What matches:** same host (case-insensitive) + same numeric PID +
same process-image basename, with the pair no more than 15 minutes
apart.

**What it claims:** "these two events describe the same running
process instance" — e.g. a Sysmon process-creation record and the
network connection that process made 30 seconds later.

**Why 90:** host + numeric PID + image basename agreeing within a
short window is strong; distinct process instances rarely share all
three.

**Failure modes:** PID reuse — a PID may be recycled for a different
process within the window. The same-image requirement reduces but
does not eliminate this. Two rapid executions of the same binary get
the same PID only if the first exited, which this linkage cannot
distinguish from continued execution.

### 2. same-file — confidence 80 (full path) / 65 (prefetch basename)

**What matches:** exact normalized-path agreement (case-insensitive,
separators normalized) across two events — e.g. a Sysmon file-creation
record and a persistence entry pointing at the same path. Prefetch
entries only record the executable *name*, so prefetch↔creation links
use basename matching within 60 minutes at the lower confidence.

**What it claims:** "these two events reference the same file."

**Why 80/65:** exact path agreement across events is strong;
basename-only agreement is weaker (same filename, different
directory).

**Failure modes:** common system paths (e.g.
`C:\Windows\System32\foo.dll`) can coincide across unrelated
activity. Prefetch staleness: a prefetch last-run time may reflect an
older execution than the one observed.

### 3. persistence-execution — confidence 80 (full path) / 60 (basename)

**What matches:** a registry Run/RunOnce value, scheduled task, or
service whose target executable (from `file_path`, or parsed from the
command line) matches an observed process creation (or prefetch
entry) on the same host.

**What it claims:** "the binary this persistence mechanism points at
was observed executing."

**Why 80/60:** full normalized-path agreement is strong; most
process-creation records carry only the image basename, so basename
agreement is the common case and scores lower.

**Failure modes:** basename collisions (`C:\evil\svchost.exe` vs
`C:\Windows\System32\svchost.exe`). A persistence entry may reference
a binary that runs routinely for benign reasons — the linkage says
the target executed, not that the execution was malicious.

### 4. download-execution — confidence 85 (with lineage) / 70 (without)

**What matches:** on one host, strictly ordered within 15 minutes: a
network connection by process P, then P creates a file, then a
process creation whose image basename matches the created file. The
file creation *must* be attributed to the same process instance that
made the connection (Sysmon records the creating process) —
otherwise any host activity in the window would link spuriously. The
linkage joins the network event to the process creation and cites the
file event in its basis.

**What it claims:** "this process downloaded something and then ran
it."

**Why 85/70:** same-process attribution of the download plus strict
ordering is strong; process-lineage support (the connecting process
is the parent of the executed process) makes it stronger.

**Failure modes:** temporal coincidence with same-process
attribution can still mislead (an updater connecting, then writing
an unrelated file). Browser and updater traffic routinely triggers
this pattern benignly.

## What is never linked

- **Untimed events** (`timestamp_original` is `None`): they cannot be
  ordered, so any temporal claim about them would be invented.
- Events on different hosts (except where a heuristic explicitly
  allows it — none currently do).
- An event to itself.

## Cluster confidence

A cluster's confidence is its **weakest linkage** — the chain is only
as strong as its weakest link — and the narrative names that linkage
explicitly. Confidence is never averaged: averaging would hide the
doubt.

## What's missing

Every narrative names evidence that would be expected but was not
observed:

- a process creation with no prefetch entry (case has prefetch data)
  — execution may predate the collection window;
- a persistence target never observed executing;
- an external connection with no download/execution within 15
  minutes — possible beaconing, or benign traffic;
- a created file never observed executing.

These are prompts for the analyst, not conclusions.

## Determinism

The same case always produces the same clusters: detectors are pure
functions of the event set, pairs are deduplicated, and ranking is
by (finding severity, finding count, event count, cluster id). There
is no randomness and no learning component.
