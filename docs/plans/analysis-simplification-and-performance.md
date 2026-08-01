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
- [ ] 4. Reason channel consolidates onto typed effects; the one contractual
      projection ("test variants") stays; duplicate `*Reason`/`*Effects`
      walker pairs collapse.
- [ ] 5. Observed-proof path stops re-loading: capture batches share the
      pass snapshot and Hasher state, `computeGroup` caches its program,
      duplicate `go list`/`go env` execs collapse.
- [ ] 6. In-pass cross-package contribution memo: shared dependency files
      hash once per pass, not once per subject package.
- [ ] 7. tier2 allocation diet: visited-set reuse, type-identity keys
      replacing `types.TypeString`, per-subject reachability
      materialization trimmed.
- [ ] 8. maximal/testvariant allocation diet: single content buffer, shared
      FileSets where sound, fixed-point walks de-duplicated.
- [ ] 9. Persistent memo for pinned-package effect scans (spec: extends the
      dynamic-state-memo pattern; mutable-local files never keyed).
- [ ] 10. Persistent memo absorption for the typed testing-type scan (spec:
      observability-memo key pattern).
- [ ] 11. closure decomposes into a facade over internal sub-packages
      (program loading, RTA/attribution, effects, maximal scan,
      test-variant compartment, memos) — tests move with their subsystem
      so the suite splits into parallel, independently-cacheable
      binaries; dead surface deleted (incl. the production-dead
      declaration-contribution collection with its driver pins re-homed
      onto reachable-set assertions, the single-valued withFresh
      parameter, and stale refinement-named identifiers).
- [ ] 12. Re-measure: instrumented campaign + stipulator corpus check;
      results recorded against the 2026-08-01 baseline; feeds the gomutant
      pipelining decision.
