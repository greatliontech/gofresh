# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[dependency-heavy-refinement-precision](dependency-heavy-refinement-precision.md)** — the
  declaration-RTA refinement recovers 0/1 irrelevant edits on the Observer sample: graph-wide
  callable-carrying package variables (2,486 across 233 of 460 module-scoped packages) make every
  subject open-world, so refined evidence stays unverifiable without whole-program immutability
  proofs. *Lands:
  before a consumer relies on refined mode to recover reuse for a dependency-heavy benchmark
  package.*
- **[refined-batch-load-failure-coupling](refined-batch-load-failure-coupling.md)** — a
  package-local load or analysis failure still fails the whole refined batch, marking healthy
  packages' drifted subjects unverifiable, where the observability tier isolates per subject.
  *Lands: when refined batch analysis degrades a package-local load or analysis failure to
  subject-local unavailable evidence the way the observability tier's isolation retry does.*
- **[guard-root-overlap-first-match](guard-root-overlap-first-match.md)** — the first
  admitting guard root's resolution failure is final; a later overlapping root that would
  cover is never consulted. Conservative (stays observed); reuse lost in overlap
  topologies. *Lands: when overlapping roots occur in a real configuration, or when the
  coverage walk is next touched.*
- **[machine-fact-source-list-unenforced](machine-fact-source-list-unenforced.md)** — the
  allowlist derives from guard.MachineFactSources (cannot diverge), but nothing proves the
  gatherer opens only listed files; a new unlisted fact source would silently stall every
  machine-fact-gathering witness again. *Lands: when gatherFacts next gains or changes a
  fact source, or when the observation harness gains a self-tracing test surface.*
- **[interprocedural-fresh-path-proofs](interprocedural-fresh-path-proofs.md)** — the
  fresh-path observability grammar is intraprocedural: scratch paths built in or passed
  through helpers refuse the proof (28 corpus witnesses); propagation needs an
  attributed interprocedural extension of the SSA walk. *Lands: when the observability
  audit next extends beyond admission classes, or when a consuming corpus's serving is
  demonstrably gated on helper-mediated scratch patterns.*
