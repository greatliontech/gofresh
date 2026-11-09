# Eliminate Redundant AST Scans in `FactOfWithHooks` and Split `dynstate` Monoliths

**Lands:** Chunk 4 in [`docs/plans/plan.md`](../plans/plan.md) (`Decompose gofresh/internal/dynstate Subpackages`).

## Context & Concrete Findings

### 1. Redundant Whole-Package AST Scans and Index Rebuilds in `FactOfWithHooks` (`internal/dynstate/facts.go:836-1121`)

A single `FactOfWithHooks(p, hooks)` invocation performs **25+ separate `ast.Inspect` passes over `p.Syntax`** and recomputes identical package-wide indexes multiple times:

1. **`directCallSites(p)` Built 5 Times Per Package**:
   - Built inside `initOnlyReachableHelpers(p)` at `facts.go:841`.
   - Built a second time inside `initOnlyReachableHelpers(p)` at `func_summary.go:5307` (`analyzeBracketedSeams`).
   - Built a third time at `func_summary.go:6646` (`recordDynamicGlobalUses`).
   - Built a fourth time at `func_summary.go:6690` (`computeSyncMapDynamicSyncedVars`).
   - Built a fifth time at `facts.go:944` (`returnEnvFreeFunctions`).
2. **`initOnlyReachableHelpers(p)` Computed Twice Per Package**:
   - Computed at `facts.go:841` and recomputed from scratch at `func_summary.go:5307` because `analyzeBracketedSeams` does not receive the `initOnly` set already computed by `FactOfWithHooks`.
3. **`buildPkgSyntaxIndex(p)` Computed Late and Re-walked Earlier**:
   - `buildPkgSyntaxIndex(p)` is not constructed until `facts.go:1069` (`DischargeAuditedSyncOnceInits`), while earlier phases (`analyzeSeamCallGraph` at `func_summary.go:501-565`, `analyzeBracketedSeams` at `func_summary.go:5146-5230`, `recordDynamicGlobalUses` at `func_summary.go:6668-6685`) each manually walk `p.Syntax` to index `*types.Func -> *ast.FuncDecl`, `*types.Var -> ast.Expr`, and `init()` bodies.
4. **`findMutexConfinedConstructorCaches(p, idx)` Called Twice**:
   - Called at `discharges_proto.go:200` (`DischargeProtoAndMemoizerInits`) and immediately called again at `discharges_proto.go:202` inside `dischargeFreshStructCacheGlobals(p, idx)`.
5. **Package-Invariant Scans Inside `VerifyReadOnlyRefConfinement` (`refconfine.go:1797-1914`)**:
   - `VerifyReadOnlyRefConfinement` is called once per candidate variable across 5 loops (`discharges_proto.go:813, 9761, 9833, 9889, 10275`). On every call it re-walks all `p.Syntax` files to compute package-invariant `funcValueTaken := map[*types.Func]bool` (`refconfine.go:1797-1823`) and `computeLocalFreshContainers(p, info)` (`refconfine.go:1829-1914`).

### 2. Oversized Monolithic Functions in `internal/dynstate`

Seven functions in `internal/dynstate` exceed 900–4,100 lines with 10+ mutually recursive closures sharing mutable outer-scope maps:

1. `analyzeSeamCallGraph` (`func_summary.go:476-4622` — **4,147 lines**).
2. `VerifyReadOnlyRefConfinement` (`refconfine.go:231-1789` — **1,559 lines**).
3. `analyzeBracketedSeams` (`func_summary.go:5141-6608` — **1,468 lines**).
4. `recordDynamicGlobalUses` (`func_summary.go:6627-8074` — **1,448 lines**).
5. `Compose` (`fixpoint.go:701-1826` — **1,126 lines**).
6. `returnEnvFreeFunctions` (`func_summary.go:8791-9904` — **1,114 lines**).
7. `verifyProtoDescBuilderType` (`discharges_proto.go:3232-4172` — **941 lines**).

## Resolution

During Chunk 4 (`Decompose gofresh/internal/dynstate Subpackages`):
1. Build a unified `PkgAnalysisIndex` (`PkgSyntaxIndex`, `CallSiteIndex`, `InitOnlyHelpers`, `FuncValueTaken`, `LocalFreshContainers`, `MutexConfinedConstructorCaches`) once at the start of `FactOfWithHooks` (`facts.go:840`) and thread it through all subpackage verifiers (`seams`, `refconfine`, `protoaudit`, `freshstruct`, and `recordDynamicGlobalUses`).
2. Decompose the 7 monolithic functions into explicit stage methods on dedicated analyzer state structs within their respective subpackages (`seams`, `refconfine`, `protoaudit`, and `dynstate`).
