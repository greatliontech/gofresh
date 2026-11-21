# Chunk 4 Working Notes: Untangle `dynstate` Subpackages (`freshalloc` -> `capsule` -> `structmut`, `seams`) & Eliminate Callback Inversion

## Architecture & Dependency DAG

1. **Shared `flowir` Nested-Body Walkers (`internal/flowir`):**
   - Promote `(*Body).ForEachNestedOp` and `(*PkgCache).ForEachOp` onto `internal/flowir` so closures, IIFEs, and range-loop bodies are walked through one canonical helper across `freshalloc`, `capsule`, `structmut`, and `dynstate`.

2. **Layer 1: `internal/dynstate/internal/freshalloc` (`<= ~920` LOC max):**
   - Owns stack-private fresh local allocations (`FreshLocalsCache`, `CollectFreshLocalStructVars`, `IsRootedAtFreshLocal`, `IsFreshInlineValue`, `IdentReachesMutatedOrAddrPrefix`, `FindMutexConfinedConstructorCaches`), constructor freshness (`PkgFreshConstructors`, `ComputePackageFreshConstructors`), intra-package non-escaping parameter confinement (`params.go`, `escape_uses.go`), `flowir`-based fresh-owned-container GFP (`OwnedContainerSummary`, `ComputeFreshOwnedContainers`), and non-`ValueOf` `reflect.Value` origin / unexported field-step screening (`CollectNonValueOfReflectConstructors`, `IsNonValueOfReflectExpr`, `IsCallOnNonValueOfLocal`, `PkgCanStepUnexportedReflectField`).
   - Decompose `constructors.go` (`1,815` LOC) into `constructors.go`, `constructors_fields.go`, and `constructors_func.go` (`freshConstructorFuncAnalyzer`), using `flowir.Body.HasGoAnywhere()` in place of raw AST `GoStmt` inspection.
   - Zero imports of `capsule`, `structmut`, `seams`, or `dynstate`.

3. **Layer 2: `internal/dynstate/internal/capsule` (`<= ~831` LOC max):**
   - Move non-capsule cross-package method and var-write summary passes (`methods_and_sinks.go`: `DeriveNonMutatingMethods`, `DeriveNoPostInitCarrierWrites`, `CollectDirectCrossPkgVarWrites`, `CollectNonMethodCrossPkgVarUses`) and their unit tests into `internal/dynstate` (`methods_and_sinks.go`, `methods_and_sinks_test.go`).
   - `capsule` imports `freshalloc` (never `structmut`), computing immutable `capsule.PackageFacts` (`Clusters`, `Builders`, `Capsules`, `CondMutations`, `ClaimedVars`, `ExemptNodes`, `ExemptFamilyByFunc`, `ExemptReadFields`, `ForeignReflectFields`, `ClusterCapsuleElemTypes`) via `capsule.DerivePackageFacts` / `capsule.DerivePackageFactsCtx`.

4. **Layer 3: `internal/dynstate/internal/structmut` (`<= ~991` LOC max):**
   - Extract the 22 `mutated_*.go` struct-mutation, reflect, eface-union, and wrapper-offset files out of `freshstruct` into `internal/dynstate/internal/structmut` layered cleanly above `freshalloc` and `capsule`.
   - Accept `*capsule.PackageFacts` directly in `CollectMutatedStructTypesWithCapsuleCtx` and `DeriveCapsuleAndStructFactsCtx` (revoking `CapsuleReflectSafe` on `PkgCastsUnsafePtrToMutatedStructCtx` and merging `CondMutations`), retiring `internal/dynstate/internal/freshstruct`.
   - Split `mutated_capsule_methods.go` (`1,001` LOC) into `mutated_capsule_methods.go` + `mutated_capsule_callables.go`, and split `mutated_types_resolve.go` (`928` LOC) into `mutated_types_selections.go` + `mutated_types_finalize.go` as explicit methods on `*wrapperPtrDiscipline` and `*mutatedStructCollector`.

5. **Sibling Package: `internal/dynstate/internal/seams` (`<= ~920` LOC max):**
   - Replace `ExportedSeamMarkHook` callback inversion with structured `ExportedSeamSite` slices on `seams.Result` (`ExportedSeamSites []ExportedSeamSite`), consumed directly in `internal/dynstate/facts_derive.go`.
   - Refactor `bracketed.go` (`1,508` LOC) onto an explicit `bracketedSeamAnalyzer` struct across `bracketed.go`, `bracketed_atomic.go`, and `bracketed_cleanup.go`.
   - Split `parallel_graph.go` (`1,359` LOC) into `parallel_graph_types.go` and `parallel_graph_nodes.go`, and split `parallel_wire.go` (`1,450` LOC) into `parallel_wire_targets.go` and `parallel_solve.go`.

## Execution & Verification Checklist
- [ ] Add `(*Body).ForEachNestedOp` and `(*PkgCache).ForEachOp` to `internal/flowir`.
- [ ] Create `internal/dynstate/internal/freshalloc` (decomposing `constructors.go`, moving `owned_containers.go` + `reflect_origin.go`, and moving fresh-local/constructor tests).
- [ ] Move `methods_and_sinks.go` (+ tests) from `capsule` to `internal/dynstate`, and refactor `capsule.DerivePackageFactsCtx` onto `freshalloc` + immutable `capsule.PackageFacts`.
- [ ] Create `internal/dynstate/internal/structmut` from the 22 `mutated_*.go` files (splitting `mutated_capsule_methods.go` and `mutated_types_resolve.go`, consuming `*capsule.PackageFacts`, moving struct-mutation tests, and retiring `freshstruct`).
- [ ] Refactor `internal/dynstate/internal/seams` (removing `ExportedSeamMarkHook` and decomposing `bracketed.go`, `parallel_graph.go`, and `parallel_wire.go`) and update `internal/dynstate`.
- [ ] Retarget/pin static `stipulator` bindings (`955/955` `current` and `resolved`), run dual-toolchain (`godst` + vanilla Go `1.27.4`) `-race -failfast` suites + targeted `gomutant ephemeral` probes (`0` survivors), converge independent adversarial review to `ZERO FINDINGS`, delete `docs/notes/untangle-dynstate-subpackages.md`, and commit Chunk 4.
