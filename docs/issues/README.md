# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[dependency-heavy-refinement-precision](dependency-heavy-refinement-precision.md)** — the
  declaration-RTA refinement recovers 0/1 irrelevant edits on the Observer sample: graph-wide
  callable-carrying package variables (2,486 across 233 of 460 module-scoped packages) make every
  subject open-world, so refined evidence stays unverifiable without whole-program immutability
  proofs. *Lands: before a consumer relies on refined mode for a
  dependency-heavy benchmark package, and only after re-measuring the open-world
  population under the shared-dynamic-state mutation analysis shows the residual is
  worth the alias-level extension.*
