# Plan: gofresh issue burn-down and self-hosting polish

Spec: `docs/specs/` (canonical per touched domain: runtime-inputs.md for
classification and observation, guards.md for guard coverage and machine
facts, purity.md for fresh-path proofs, closure.md for refinement).
Eliminates the standing issue inventory and the self-hosting serving gap;
every chunk runs the adversarial loop and the corpus check stays green.

- [x] 1. Self-serving corpus: volatile-OS-root paths classify without
  real filesystem probes — the library's own stat of a fabricated
  /proc path taints the whole test binary's observation (109 subjects
  re-execute every run)
- [x] 2. Guard-root overlap: a failing admitting root consults later
  overlapping roots instead of finaling (guard-root-overlap-first-match)
- [x] 3. Machine-fact gatherer enforcement: every gatherer read routes
  through one membership-checked open seam
  (machine-fact-source-list-unenforced)
- [ ] 4. Interprocedural fresh-path proofs: attributed parameter
  freshness across function boundaries, same consumer discipline
  (interprocedural-fresh-path-proofs; 28-witness refusal class)
- [ ] 5. Refinement open-world re-measurement under the
  shared-dynamic-state narrowing; disposition per the issue's own
  acceptance bar (dependency-heavy-refinement-precision)
- [ ] 6. Final sweep: disposition per remaining deferral, then close-out
  gate — full suite, release, corpus double-check green
