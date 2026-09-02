# Cross-tool pipeline audit (2026-09-02)

Evidence base for the train's Band T and Band P (docs/plans/cross-tool-train.md).
One read-only audit per repo against one brief — the no-wasted-work ruling: fail-early
preparation, then an incremental check-freshness / measure / persist loop per unit, the
operator told what is going on throughout. Each report has the same eight sections:
operations inventory, late refusals, progress and reporting, incrementality and
freshness, knob inventory, self-test story, known-failure register, cross-cutting shape.

- gofresh.md — the engine: one uncached observation pass is the atom everything else pays for.
- gomutant.md — `run` is the model reporter; the other verbs and the CLI `ephemeral` inherit none of it.
- stipulator.md — the reporter exists and the CLI never constructs it; four preparation-decidable refusals fire after execution.
- pew.md — no reporter, no signal handling, persistence per package, freshness opt-in and computed twice.

Delete-on-close: this directory is deleted when Band P closes; its charters carry the
findings forward and git holds the reports.
