# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[dependency-heavy-refinement-precision](dependency-heavy-refinement-precision.md)** — the
  declaration-RTA refinement exceeds a 25-minute all-benchmark budget and recovers no reuse on
  the bounded Observer sibling-edit sample. *Lands: before a consumer relies on refined mode to
  recover reuse for a dependency-heavy benchmark package.*
- **[refined-batch-load-failure-coupling](refined-batch-load-failure-coupling.md)** — a
  package-local load or analysis failure still fails the whole refined batch, marking healthy
  packages' drifted subjects unverifiable, where the observability tier isolates per subject.
  *Lands: when refined batch analysis degrades a package-local load or analysis failure to
  subject-local unavailable evidence the way the observability tier's isolation retry does.*
- **[observation-manifest-union](observation-manifest-union.md)** — sealed observations cannot
  adopt or widen a persisted manifest union, so a consumer re-executing a subset of contributing
  processes must mark a legitimately widened union non-reusable. *Lands: when a consumer needs to
  merge fresh completed observations into a persisted manifest union without re-running every
  contributing process.*
