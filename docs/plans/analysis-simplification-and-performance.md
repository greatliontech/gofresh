# Analysis simplification and performance

Derived from: docs/specs/overview.md, docs/specs/closure.md (every chunk is
same-verdict under REQ-fresh-coherent-view unless it amends the spec first;
chunks 1–2 are spec amendments).

- [x] 1. Amputate declaration-RTA refinement: spec requirements, budget API,
      `Refinement` evidence, `DeclarationRTA` identity, tier2 compute
      plumbing; close out `dependency-heavy-refinement-precision`.
- [x] 2. Assembly is not an analysis surface: spec states the
      classification; mutable-local asm packages hash whole-dir, cache
      ones keep their version pin, both widen and refuse observability
      without fine analysis; the Plan9 scanner deletes whole (its
      toolchain arm was reachability-dead: filePkgs only ever holds
      mutable/cache packages).
- [x] 3. Per-file effect scan reads and parses once (equivalence-pinned
      against the two-pass reference; benchmark added).
- [x] 4. Reason channel consolidates onto typed effects; the one contractual
      projection ("test variants") stays; duplicate `*Reason`/`*Effects`
      walker pairs collapse.
- [x] 5. Observed-proof path: the capture bracket reuses the view's
      construction env snapshot (env is immutable configuration), and the
      observability batch releases each group's whole-program SSA with the
      group — bounded peak, resolving the retention issue; the view load
      stays out of the bracket (its facts are construction-generation and
      the memo writes before the closing compare).
- [x] 6. In-pass cross-package contribution memo: shared dependency files
      hash once per pass, not once per subject package.
- [x] 7. tier2 allocation diet: visited-set reuse, type-identity keys
      replacing `types.TypeString`, per-subject reachability
      materialization trimmed.
- [x] 8. maximal/testvariant allocation diet: single content buffer, shared
      FileSets where sound, fixed-point walks de-duplicated.
- [x] 9. Persistent memo for pinned-package effect scans (spec: extends the
      dynamic-state-memo pattern; mutable-local files never keyed).
- [x] 10. Persistent memo absorption for the typed testing-type scan (spec:
      observability-memo key pattern); observability memo writes become
      slice-granular so a deadline mid-group keeps the completed slices'
      proofs.
- [ ] 11. closure consolidates and decomposes (scope decided: leaf
      packages + same-package file split — the heavy tests are
      Hasher-bound and stay with the facade under any split, so a full
      effect/tier2 package split buys no suite time for its churn):
      internal/cachefile, internal/listing, internal/testvariant (pure
      ledger tests move with it), internal/program, internal/rta extract
      behind zero-churn facade aliases; tier2.go splits into
      observability/attribution/freshpath/analyzer files; dead surface
      deleted (the production-dead declaration-contribution collection
      with driver pins re-homed, the withFresh axis, refinement-named
      identifiers, the write-only residue); the memo store/load shapes,
      module-pin/pinned-classification sites, per-batch key and
      compartment-identity derivations, and the duplicated unsafe-widen
      sites each collapse onto one home; the per-view
      beforePreciseAnalysis seam either joins the viewTestHooks surface
      or stays deliberately per-view (user's call at close-out); the
      facade suite's user-cache isolation stays XDG-scoped with the
      rationale recorded at close-out (HOME participates in go tooling
      env, so a portable override needs its own design).
- [ ] 12. Re-measure: instrumented campaign + stipulator corpus check;
      results recorded against the 2026-08-01 baseline; feeds the gomutant
      pipelining decision. Close-out also dispositions the overlap between
      FuzzMaximalClosureFloor's equality leg and the witness surface of
      REQ-closure-batch-equivalence.
