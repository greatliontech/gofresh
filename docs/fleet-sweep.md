# Weekly fleet health sweep

The standing producer of field reports over this machine's tool estate
(gofresh, gomutant, stipulator, pew and the repos that consume them):
tool health is observed on a schedule so sessions stop discovering
breakage by tripping on it.

## What runs

A systemd user timer (`fleet-sweep.timer`, Mondays 06:17, persistent)
runs `scripts/fleet-sweep-run.sh`, which

1. executes `scripts/fleet-sweep.sh` — the mechanical gatherer — and
   persists the time-stamped report under `~/.local/state/fleet-sweep/`
   (90-day retention; defects outlive reports as issue docs), then
2. invokes a headless judge (`claude -p`) whose tool surface is
   WRITE-ONLY (Read/Glob/Grep/Write/Edit — no shell): it writes issue
   docs and index rows, and the wrapper owns every git operation.
   The report waits on disk for a hand judgment whenever the judge
   fails, and a sweep that aborted, deferred, or lost its completion
   trailer never reaches the judge at all. (Stated property: the
   judge's state-dir grant includes the report and prior logs it
   reads — process evidence, not durable artifacts, so a misbehaving
   write there loses nothing the estate keeps.)

Sweep health is three-valued: a fact, a red fact, or NOT MEASURED. A
missing tool aborts the sweep (its preflight), a wanted-quiet machine
defers it whole, a lock refusal or budget overrun mid-sweep marks that
section NOT MEASURED — and the judge never files a NOT MEASURED,
DEFERRED, or NOTE line as a red fact. The machine lock sits OUTSIDE
each command's budget, so waiting for the lock can never convert a
healthy verdict into a timeout.

## What the gatherer checks

- **Binary provenance** — each installed tool binary's vcs.revision
  against its repo HEAD, and dirty-build stamps. The skew guards
  refuse loudly at use; the sweep catches drift before use. The check
  is deliberately coarse — ANY commit moves HEAD, docs included — and
  the standing response to SKEW is equally cheap: `go install` in the
  named repo, then close the filing.
- **Shape-corpus version lag** — each consumer's pinned gofresh
  version against the latest remote release tag (the remote is the
  authority: CI mints tags the local clone may lag). Corpus content
  drift is unrepresentable; version lag is the one drift channel left.
- **gomutant findings stores** — size and record summary per estate.
  Inspection that exceeds its budget is reported as a fact (train
  chunk 110 tracks inspection cost), never hidden.
- **stipulator check verdicts** — every estate with authored bindings
  runs `stipulator check` (warm serving keeps routine runs cheap; a
  cold estate re-executing is exactly the idle-window work the sweep
  exists to absorb). Manifest-only estates report adoption incomplete.
  This is the check verdict's scheduled seat, deliberately
  machine-side rather than CI-side: the verdict is suite-scale work
  the CI budgets exclude (CI runs build/vet/tests; the sweep runs the
  verdict weekly where the warm witness store lives).
- **pew store freshness** — whole-store `pew status` per store under
  the store's standing vouch set (tugboat's audited set lives in its
  CLAUDE.md and is mirrored in the gatherer — the two point at each
  other until a repo-level vouch source lands, pew
  docs/issues/repo-level-vouch-source.md; protodb's store has no
  assessed set yet and its unverifiable rows are expected).
  `unverifiable` is a defect class exactly like stale/unrecorded.
  Long row lists are capped in the report and the report SAYS so
  ("showing N of M") — a cap is a visible fact, never a silent one.

The repo lists at the top of `fleet-sweep.sh` ARE the estate
definition, and the estate is deliberately bounded to the
greatliontech org's repos on this machine: known out-of-boundary
estates exist (candosa/cerebro and thegrumpylion/vmm carry .stipulator
estates; several thegrumpylion repos carry .gomutant stores) and join
only by joining the lists. The report prints the lists and reports an
absent listed repo as ABSENT — a silent cap would read as "covered
everything" when it didn't.

## Filing doctrine (the judge's contract)

Red facts become durable filings, never chat. The judge WRITES an
issue doc under the owning repo's `docs/issues/` with a `Lands:` line
slotted per that repo's own conventions: for the tool repos the
register is the cross-tool train (`docs/plans/cross-tool-train.md`);
elsewhere the strict order is a chunk of that repo's active plan, a
checkable condition (a repo's next change-set gate that forces the
diagnosis is a legitimate condition), and only then `user decision`.
Facts already tracked by a live chunk or issue doc are noted in the
judge's reply, not re-filed — and dedup is a method, not a vibe: every
red fact's disposition names the candidate docs scanned, a new doc may
not overlap an existing doc's rows (widen it, or state disjointness),
and one unit of work carries ONE Lands: trigger — a filing adopts or
retargets an existing doc's trigger rather than minting a second, and
a Lands: change rewrites the index row in the same edit (the row is
what triage reads first). A doc the judge would WIDEN that carries
in-flight changes parks exactly like an index row — the addition goes
to the state dir, never inside a foreign uncommitted change set — and
the parked directory drains GENERICALLY: every parked file opens with
a 'Target: <repo>/docs/issues/<file>' line — the file is the sole
carrier of its work across weeks and says what it is for, so the
drain reads the line, never the filename — and applies once its
target is clean, then is marked drained; the report's pending section
skips drained files, so parked work stays visible exactly until
done. Set
claims are made from the full row lists persisted beside each report
(report-<stamp>.rows/), never from a capped section; a hand-run
gatherer sets SWEEP_ROWS_DIR to get the same evidence, since the
doctrine binds hand judges equally.

The WRAPPER commits — the judge cannot: per repo, pathspec-scoped to
the new issue docs plus the index (`docs(sweep): weekly fleet health
filings <stamp>`), and the index row joins the commit only when the
index was clean before the judge ran. A dirty index's row is parked
under `~/.local/state/fleet-sweep/parked/` instead. Nothing the sweep
writes is left SILENTLY uncommitted — the two deliberate exceptions
are loud in the judge log: pre-dirty files skipped to stay with their
own change sets, and whole repos whose outside-docs/issues state
changed during the judge window (the wrapper refuses the commit
either direction, edit or revert). A filing never mixes into someone
else's change set. Sweep filings routinely cite ACROSS repos, so
closing or folding any sweep-filed doc runs its cite walk over the
WHOLE estate, not the owning repo alone — a cross-repo cite left
dangling points readers at a path that never existed. No pushes, no
code, no spec edits — those belong to sessions running the full
adversarial loop.

## Installation

```
mkdir -p ~/.config/systemd/user
cp scripts/systemd/fleet-sweep.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now fleet-sweep.timer
```

The report's completion trailer attests the sweep REACHED ITS END —
per-section health stays three-valued, and the runner appends a
not-measured tally so a mostly unmeasured sweep cannot read as a
quiet green. Parked filings surface in their own report section until
drained.

`systemctl --user list-timers fleet-sweep.timer` shows the next run;
`journalctl --user -u fleet-sweep.service` the last run's log.
