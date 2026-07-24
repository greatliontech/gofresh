# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[closure-digests-reused-for-naming](closure-digests-reused-for-naming.md)** — validation's
  moved-file naming re-reads and re-hashes files the closure tier already digested; plumbing
  the closure's own per-file digests into the view removes the cost and the attribution
  window together. *Lands: when closure per-file digests flow into fileDigests.*
- **[generic-subject-precision](generic-subject-precision.md)** — parameterized subjects
  read open-world from their constraint, so refinement widens to maximal; constraint-aware
  narrowing plus instantiation-rooted traversal would recover precision. *Lands: when a
  corpus demonstrably loses serving precision to open-world generic subjects.*
- **[observation-pass-subprocess-floor](observation-pass-subprocess-floor.md)** — with
  analysis memoized, the serving floor is per-pass toolchain subprocesses (listing, roots
  load, guard and env probes) times the six-pass drift-refusal structure. *Lands: fewer
  passes (observed capture sharing the construction bracket), batched probes, or the
  floor is accepted.*
- **[dependency-heavy-refinement-precision](dependency-heavy-refinement-precision.md)** — the
  declaration-RTA refinement recovers 0/1 irrelevant edits on the Observer sample: graph-wide
  callable-carrying package variables (2,486 across 233 of 460 module-scoped packages) make every
  subject open-world, so refined evidence stays unverifiable without whole-program immutability
  proofs. *Lands: before a consumer relies on refined mode for a
  dependency-heavy benchmark package, and only after re-measuring the open-world
  population under the shared-dynamic-state mutation analysis shows the residual is
  worth the alias-level extension - re-measured 2026-07-22: 39/39 still open-world under
  the narrowing, the extension is the only mover.*
