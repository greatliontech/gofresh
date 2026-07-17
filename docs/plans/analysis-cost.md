# Analysis cost

- [x] 1. Fix `checkRefinedBatch` running its base re-observation brackets under `context.Background()` instead of the caller's context.
- [x] 2. Slim drift brackets to one observation per side: `reobserveBase` and the `ensureRefined`/`ensureObservable` before/after brackets compare a single fresh observation against the view instead of constructing a full double-observed view; the observed-check drift path shares one bracket pair and one closure Hasher across refinement and observability analysis.
- [x] 3. Add batched observed checking: one bracket pair, one shared runtime-input observation window, and one shared drift analysis for a caller-supplied recording set, with a property test pinning batch↔single verdict equivalence; share one bracket pair in observed-refined capture the same way.
- [x] 4. Batch observability analysis like refinement: group subjects by package, share the loaded program and attributed-RTA masks, and cache per-file maximal effect scans within a Hasher, pinned against REQ-closure-observability-batch-equivalence by a property test covering the shared-hasher prime→refine→observe sequence.
- [x] 5. Detect systemic batch-analysis failures (load or context errors) in the observability fallback and fail once instead of retrying the failing load per subject.
- [x] 6. Make the API context-first: remove the `context.Background()` convenience wrappers from view construction, checking, and validation; every operation takes the caller's context.
- [x] 7. Add a caller-supplied analysis budget for observed proving that yields an unavailable proof on exhaustion, never validity, with the budget rule stated in the overview spec.
- [ ] 8. Add an engine progress hook emitting phase and per-subject analysis events for long operations.
- [ ] 9. Share one package load per observation between the purity scan and the testing-type effect scan if their load modes can be unified without changing either scan's facts; otherwise record why not.
- [ ] 10. Close out: re-measure suite and representative workload timings against the pre-plan baseline, restore the full suite under its timeout, release, and delete this plan.
