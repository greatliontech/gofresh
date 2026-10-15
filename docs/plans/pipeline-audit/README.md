# Cross-tool pipeline audit (2026-09-02)

Historical evidence base for the retained train's Band T and Band P.
The active roadmap is `docs/plans/tooling-redesign.md`; these reports and
their summaries describe the audited snapshots, not current behavior.
One read-only audit per repo against one brief — the no-wasted-work ruling: fail-early
preparation, then an incremental check-freshness / measure / persist loop per unit, the
operator told what is going on throughout. Each report has the same eight sections:
operations inventory, late refusals, progress and reporting, incrementality and
freshness, knob inventory, self-test story, known-failure register, cross-cutting shape.

- gofresh.md — the engine: one uncached observation pass is the atom everything else pays for.
- gomutant.md — `run` is the model reporter; the other verbs and the CLI `ephemeral` inherit none of it.
- stipulator.md — the reporter exists and the CLI never constructs it; four preparation-decidable refusals fire after execution.
- pew.md — no reporter, no signal handling, persistence per package, freshness opt-in and computed twice.

Lands: tooling-redesign 9.4, after every report's remaining obligation has a
current disposition and destination and its load-bearing rationale/citations
have been promoted or retargeted. Then delete this directory; git retains the
reports. Band P's completed checkbox alone does not establish that reconciliation.
