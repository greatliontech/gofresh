# Attribute the remaining cold-analysis working set

Measured 2026-10-05 at gomutant chunk 308's open (the machine alone,
the parent's VmHWM sampled every five seconds through one target of
gomutant's own derived campaign — 796 subjects over 5 oracle packages,
9 candidates):

- warm memos: 0.54 GB high-water mark over the whole run, committed in
  3m30s — the views, the proofs and the attach each served from the
  persistent memo;
- cold memos (a fresh cache home): the SAME run reached 3.47 GB — 0.78
  GB at the oracle observation, 1.9 GB thirty seconds into "proving
  oracle closure freshness", 3.2 GB at nine minutes, 33 minutes to the
  commit; the resident set fell to 0.41 GB when the pass ended.

Those measurements distinguish cold work from warm memo serving, but do not
establish that completed package programs remain retained. The observability
pass in `closure/observability.go` deletes each completed group's entry from
`h.progs`; the empty-root group also releases its entry. Rebuilding that
release would not address a remaining fault. The discharge's rooted-group
release is separate and also already exists.

The reported multi-target measurements (3.6 GB through the proof pass and
8.4 GB at the first attach's cold observation/fold) remain workload evidence,
not ownership attribution. A runtime collection target also does not bound
the live set required by an individual package's analysis.

The deciding measurement compares the same current workload cold and warm,
records phase-local peaks and retained RSS after release, and attributes the
remaining live objects before changing ownership. Preserve the same subjects,
verdicts and deciding work; a refusal or skipped analysis is not a memory win.

Lands: docs/plans/tooling-redesign.md 7.7 (retained charter 314).
