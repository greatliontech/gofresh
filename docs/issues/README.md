# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[testing-log-output-defeats-observability](testing-log-output-defeats-observability.md)** — the
  observability proof classifies `t.Fatal`'s formatted output as unobservable, so file-reading
  oracles that can fail through it are permanently uncacheable under the observed policy.
  *Lands: when a consumer needs observed-policy caching for `t.Fatal`-failing oracles that read
  runtime inputs, or the next observability-analysis precision pass.*
- **[closure-digests-reused-for-naming](closure-digests-reused-for-naming.md)** — validation's
  moved-file naming re-reads and re-hashes files the closure tier already digested; plumbing
  the closure's own per-file digests into the view removes the cost and the attribution
  window together. *Lands: when closure per-file digests flow into fileDigests.*
- **[dependency-heavy-refinement-precision](dependency-heavy-refinement-precision.md)** — the
  declaration-RTA refinement recovers 0/1 irrelevant edits on the Observer sample: graph-wide
  callable-carrying package variables (2,486 across 233 of 460 module-scoped packages) make every
  subject open-world, so refined evidence stays unverifiable without whole-program immutability
  proofs. *Lands: before a consumer relies on refined mode for a
  dependency-heavy benchmark package, and only after re-measuring the open-world
  population under the shared-dynamic-state mutation analysis shows the residual is
  worth the alias-level extension - re-measured 2026-07-22: 39/39 still open-world under
  the narrowing, the extension is the only mover.*
