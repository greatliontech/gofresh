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
- [ ] 10. Persistent memo absorption for the typed testing-type scan (spec:
      observability-memo key pattern); observability memo writes become
      slice-granular so a deadline mid-group keeps the completed slices'
      proofs.
- [ ] 11. closure decomposes into a facade over internal sub-packages
      (program loading, RTA/attribution, effects, maximal scan,
      test-variant compartment, memos) — tests move with their subsystem
      so the suite splits into parallel, independently-cacheable
      binaries; dead surface deleted (incl. the production-dead
      declaration-contribution collection with its driver pins re-homed
      onto reachable-set assertions, the single-valued withFresh
      parameter, and stale refinement-named identifiers); the three
      parallel persistent-memo store/load shapes (memo.go, dynamicstate,
      effectmemo) collapse onto one cache-file helper, and the
      module-pin derivation + pinned-classification predicate (4-5 sites
      each, inconsistent ToSlash) collapse onto Hasher helpers; the
      suite's user-cache isolation (XDG_CACHE_HOME, Linux-only for
      os.UserCacheDir) becomes platform-complete as the tests move.
- [ ] 12. Re-measure: instrumented campaign + stipulator corpus check;
      results recorded against the 2026-08-01 baseline; feeds the gomutant
      pipelining decision. Close-out also dispositions the overlap between
      FuzzMaximalClosureFloor's equality leg and the witness surface of
      REQ-closure-batch-equivalence.
