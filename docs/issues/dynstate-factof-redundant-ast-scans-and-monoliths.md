# Eliminate Redundant AST Scans in `FactOfWithHooks`, Optimize `Compose` & Split `dynstate` into Subpackages

**Lands:** Chunk 6 in [`docs/plans/plan.md`](../plans/plan.md) (`Decompose, Unify, Optimize, Fix Defects & Harden gofresh/internal/dynstate and Subpackages`).

## Context & Concrete Findings

### 1. Redundant Whole-Package AST Scans and Index Rebuilds in `FactOfWithHooks` (`internal/dynstate/facts.go:836-1121`)

A single `FactOfWithHooks(p, hooks)` invocation performs **25+ separate `ast.Inspect` passes over `p.Syntax`** and recomputes identical package-wide indexes multiple times:

1. **`directCallSites(p)` Built 5 Times Per Package**:
   - Built inside `initOnlyReachableHelpers(p)` at `facts.go:841`, a 2nd time inside `initOnlyReachableHelpers(p)` at `func_summary.go:5306` (`analyzeBracketedSeams`), a 3rd time at `func_summary.go:6646` (`dataMemoVars`), a 4th time at `func_summary.go:6690` (`recordDynamicGlobalUses`), and a 5th time at `func_summary.go:11422` (`closedInterfaceFields`).
2. **`initOnlyReachableHelpers(p)` Computed Twice Per Package**:
   - Computed at `facts.go:841` and recomputed from scratch at `func_summary.go:5306`.
3. **`buildPkgSyntaxIndex(p)` Computed Late (`facts.go:1069`) and Bypassed**:
   - Constructed only after `func_summary.go` has already run 15+ full-package `ast.Inspect` passes; even after `idx` is built at `facts.go:1069`, `facts.go:1073-1103` re-walks `p.Syntax` `file.Decls` for `//gofresh:single-subject` `ValueSpec`s (already in `idx.varSpecs`), and `isDeterministicImmutableBuilderGlobal` (`discharges_proto.go:3184-3224`) manually walks `p.Syntax` `file.Decls` instead of looking up `idx.varSpecs[v]`.
   - In `recordDynamicGlobalUses` (`func_summary.go:7783-8048`), each wave of the `pendingReturns` frontier loop rescans all `p.Syntax` `file.Decls` and `ast.Inspect`s every `FuncDecl.Body` and `ValueSpec` instead of using `idx.usesOf[fnObj]`.
4. **Package-Invariant Scans Repeated 6+ Times Inside `VerifyReadOnlyRefConfinement` (`refconfine.go:359-450, 1798-1975`)**:
   - Every call to `VerifyReadOnlyRefConfinement` re-runs `walkInv` across all files in `p.Syntax` (`funcValueTaken`, `calleeIdents`, `calledMethodSels`, `declBodies`, `returnEnclFunc`, `resultVarFunc`, `litResultVars`) and re-runs `computeLocalFreshContainers` (2 full-package `ast.Inspect` passes whose `sigVars`, `candidates`, and `disqualified` sets are 100% independent of `taintedRef`).

### 2. Algorithmic Bottlenecks in `fixpoint.go`, `protoaudit`, `freshstruct`, and `seams`

1. **21 Full Passes Over `allFacts`, Redundant Per-Root DAG Walks, and Iterative Undirected Component Loop in `fixpoint.go`**:
   - `Compose` (`fixpoint.go:701-1826`) loops over `allFacts` 14 times (`L707, 730, 752, 783, 813, 844, 886, 905, 1084, 1128, 1170, 1205, 1265, 1358, 1444, 1495`), `NewDeferralResolution` + `ResolveEnvAudit` loop 3 times (`L132, 268, 375`), `BlockedExportedSeams` loops 3 times (`L542, 615, 686`), and `CarrierLinkGraph` loops once (`L504`).
   - At `fixpoint.go:1695-1710` (`walk(node.ImportPath, map[string]bool{})`) and `L1777-1788` (`collect(node.ImportPath, map[string]bool{})`), a fresh `seen` map is allocated per root node matching `viewPackage`, re-traversing the transitive import DAG multiple times instead of sharing a single `seen` map across roots (as `L1730` already does).
   - `CarrierLinkGraph` (`fixpoint.go:980-1001`) propagates `mutated`, `escaped`, and `envCarrying` across `linkAdj` using a `for changed` fixed-point loop over all edges instead of a single $O(V + E)$ BFS from marked vertices.
   - `fixpoint.go:1641-1663` iterates `allFacts[pkgPath]` -> `fact.Declares` 3 separate times for `CulpritMutated`, `CulpritEscapes`, and `CulpritEnvCarrying`, recomputing `vouchedOut`, `auditedSourceOut`, `directiveDischargedOut`, and `protoGrpcDischargedOut` each time.
2. **AST Walks Inside the Fixed-Point Loop in `deriveNonMutatingMethods` (`discharges_proto.go:237-450`)**:
   - On every iteration of the fixed point (`L353-431`), `deriveNonMutatingMethods` runs two `ast.Inspect(fd.Body, ...)` walks (`localScalarVars` and `CallExpr` checks) per candidate method instead of checking immediate AST disqualifiers and recording `calleeDeps[fn]` once before solving the fixed point in memory.
3. **Quadratic/Repeated AST Walks in `freshstruct` (`discharges_proto.go:6825, 7808, 9247, 10559-10842, 12739-13444`)**:
   - `findMutexConfinedConstructorCaches(p, idx)` is called twice (`L211` and `L10571`) and at `L13328` computes `computeExclusiveHelperCone` across all `idx.funcDecls` before checking whether `mv` is even referenced in `idx.usesOf[mv]`.
   - `collectFreshLocalStructVars(p, idx, fd)` is recomputed from scratch in `verifyLockedStructFamilyDiscipline` (`L7808`) and again in `collectMutatedStructTypes` (`L9247`).
   - `computePackageFreshConstructors` (`L10656-10831`) re-runs `analyzeSingleFreshConstructorFunc` across all functions in the package on every outer greatest-fixed-point iteration instead of re-evaluating only callers of changed callees.
   - `stepNonEscapingIntraParams` (`L12820-12877`) runs a nested fixed-point `ast.Inspect(fd.Body, ...)` per parameter slot per iteration to discover `TypeSwitchStmt` and `AssignStmt` local aliases instead of pre-indexing local alias edges once per `fd`.
   - `verifyOnceInitConeImmutability` (`L6825, 7128`) calls `findLocalSyncOnceMemoizers(p, idx, fnFD)` twice per function in `fullInitCone`.
4. **`analyzeSeamCallGraph` Bottlenecks (`func_summary.go:476-4622`)**:
   - `wireInstantiatedNamedTypes` (`L2550-2575`) iterates all of `p.TypesInfo.Types`, `Defs`, `Uses`, `Instances`, and `Implicits` even when `len(genericRecvMethods) == 0`.
   - `astSubtreeID` (`L1895-2032`) allocates graph nodes in `adj` for every AST node in bound expression subtrees instead of only taint-capable AST nodes.
   - Merge the 12 separate `ast.Inspect` passes into 3 structured phases.

### 3. Target Subpackage & File Decomposition Blueprint (~250–750 Lines Per File) + Unit Tests

1. **`internal/dynstate/internal/syntaxutil`** (~550 LOC across `ast.go`, `types.go`, `fixpoint.go` + `syntaxutil_test.go`).
2. **`internal/dynstate/internal/refconfine`** (~1,650 LOC across `index.go`, `confine.go`, `capsules.go`, `helpers.go` + `refconfine_test.go`).
3. **`internal/dynstate/internal/freshstruct`** (~2,400 LOC across `fresh_local.go`, `constructors.go`, `escape_uses.go`, `params.go`, `mutated_types.go` + `freshstruct_test.go`).
4. **`internal/dynstate/internal/protoaudit`** (~5,800 LOC across `summaries.go`, `clusters.go`, `builder.go`, `desc_builder.go`, `snapshot_cone.go`, `once_memo.go`, `roles_locked.go`, `grpc.go` + `protoaudit_test.go`).
5. **`internal/dynstate/internal/seams`** (~3,800 LOC across `callgraph.go`, `flow_summary.go`, `parallel_reach.go`, `seq_edges.go`, `testing_handles.go`, `bracketed.go` + `seams_test.go`).
6. **`internal/dynstate` Core Package** (~5,600 LOC across `directives.go`, `typecarrier.go`, `facts_codec.go`, `facts_derive.go`, `fixpoint_env.go`, `fixpoint_seams.go`, `fixpoint_compose.go`, `discharges_audited.go`, `summary_uses.go`, `summary_env.go`, `summary_leakfree.go` + `dynstate_test.go`).
7. Add `./internal/dynstate/internal/...` to `race:leaf` in `gofresh/.stipulator/policy.textproto`.
