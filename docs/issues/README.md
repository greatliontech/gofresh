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
- **[fortest-dependency-variant-subject-misattribution](fortest-dependency-variant-subject-misattribution.md)** —
  the subject scan keys every `ForTest`-carrying variant to the package under test, but `go list`
  sets `ForTest` on intermediate recompiled dependencies too, so even a single-package scan
  misattributes a recompiled dependency's declarations to the tested package — wrong `known`
  subjects and, on a shared top-level symbol name, a spurious ambiguous-subject failure. *Lands:
  when a requested package's test binary recompiles any dependency and the recompiled variant's
  subjects must stay attributed to their own package.*
- **[observation-manifest-union](observation-manifest-union.md)** — sealed observations cannot
  adopt or widen a persisted manifest union, so a consumer re-executing a subset of contributing
  processes must mark a legitimately widened union non-reusable. *Lands: when a consumer needs to
  merge fresh completed observations into a persisted manifest union without re-running every
  contributing process.*
