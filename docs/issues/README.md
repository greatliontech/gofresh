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
- **[observability-toolchain-accessors-unaudited](observability-toolchain-accessors-unaudited.md)** — runtime.GOROOT and toolchain-derived paths fail observability audit, so non-pure toolchain-reading witnesses cannot carry proofs though their reads are guard-covered. *Lands: when the observability audit next extends, or when a consumer needs those proofs.*
- **[observation-guard-classes-ranked](observation-guard-classes-ranked.md)** — per-test attribution ranks three fixable observation classes blocking ~97% of gofresh witness serving: GOCACHE (~300, deferred guard class), /tmp ephemeral (128), machine-guard proc reads (18). *Lands: when observation next gains a guard-covered or ephemeral class, or a consumer prioritizes warming.*
- **[guard-root-overlap-first-match](guard-root-overlap-first-match.md)** — the first
  admitting guard root's resolution failure is final; a later overlapping root that would
  cover is never consulted. Conservative (stays observed); reuse lost in overlap
  topologies. *Lands: when overlapping roots occur in a real configuration, or when the
  coverage walk is next touched.*
