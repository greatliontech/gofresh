# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[dependency-heavy-refinement-precision](dependency-heavy-refinement-precision.md)** — the
  declaration-RTA refinement exceeds a 25-minute all-benchmark budget and recovers no reuse on
  the bounded Observer sibling-edit sample. *Lands: before a consumer relies on refined mode to
  recover reuse for a dependency-heavy benchmark package.*
- **[refined-tier-missing-root-degradation](refined-tier-missing-root-degradation.md)** — a
  subject missing from its program's roots degrades subject-locally in observability analysis
  but still fails the whole refinement batch, coupling unrelated subjects to one unrootable
  symbol. *Lands: when declaration-RTA refinement degrades a missing subject root to
  subject-local unavailable evidence the way observability analysis does.*
- **[positionless-method-declaration-key-variant-ambiguity](positionless-method-declaration-key-variant-ambiguity.md)** —
  a position-less method (universe `error.Error` promoted through embedding) gets a `pkg.ID`-based
  declaration key that differs between a package and its test variant, tripping the
  ambiguous-subject guard and failing the whole package under `Tests: true`. *Lands: before a
  consumer package holding a universe-method-bearing top-level type is analyzed with test
  variants — pew recording protodb's `internal/db` is blocked on it.*
- **[observation-manifest-union](observation-manifest-union.md)** — sealed observations cannot
  adopt or widen a persisted manifest union, so a consumer re-executing a subset of contributing
  processes must mark a legitimately widened union non-reusable. *Lands: when a consumer needs to
  merge fresh completed observations into a persisted manifest union without re-running every
  contributing process.*
