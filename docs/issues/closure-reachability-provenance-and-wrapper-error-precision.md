# Decompose & Optimize `internal/closure` Core (`freshpath`, `attribution`, `analyzer`, `observability`, `maximal`) and Fix Reachability/Wrapper-Error/Fresh-Path Precision

**Lands:** Chunk 5 in [`docs/plans/plan.md`](../plans/plan.md) (`Decompose, Optimize & Fix Precision in gofresh/internal/closure Core`).

## Context & Concrete Findings

### 1. Precision & Soundness Defects in `attribution.go` and `freshpath.go`

1. **`provenanceReachable` & `provenanceReachableWithCandidates` Hardcode `audited = false` and Allocate Uncached `freshParamAnalysis` Per Dynamic Call Site (`attribution.go:3709, 3714, 4018`)**:
   - `provenanceReachable` (`3709`) and `provenanceReachableWithCandidates` (`3714`) pass `false` as `audited` to `provenanceBFSWithCandidates`.
   - Inside `provenanceBFSWithCandidates` (`4018`), every dynamic call or interface invoke allocates a throwaway `&freshParamAnalysis{audited: audited}` with `audited: false`, `summary: nil`, and `dynamicMemos: nil`, refusing to close interface invokes on standard-library concrete types (`*strconv.NumError`, `*errors.errorString`, `*strings.Reader`, `*bytes.Buffer`) and recomputing `walkDynamicValue` and `progAllFunctions(prog)` from scratch on every site.
2. **Missing `fp *freshParamAnalysis` Propagation in `fileValueFromAdmittedOpen` (`freshpath.go:740-764`) and `fileValueFromFreshOpenFile` (`freshpath.go:997-1039`)**:
   - `fileValueFromAdmittedOpen` (`744, 758`) and `fileValueFromFreshOpenFile` (`1004, 1014, 1020`) call `freshPathValue(..., nil, nil)` with `fp = nil` even though `observableFileValue` (`957`) and `scanCall` (`analyzer.go:1123`) have `fp` (`a.fresh`) in scope. When a helper receives a `t.TempDir()` path via a function parameter (`*ssa.Parameter`), `f.Name()`, `f.Read()`, and `f.Close()` on an `os.OpenFile(dirParam+"/x", ...)` handle fail to recognize the parameter-backed fresh path.
3. **Startup Reachability Contamination Across `std` `init` Roots and Carrier-Free `std` Calls (`attribution.go:650-738, 3717-4049`, `observability.go:1991-2055`)**:
   - `std` `init` roots traverse `result.Targets` into non-standard functions (`attribution.go:650-663, 3717-3779, 4041`).
   - Static calls to carrier-free audited pure `std` functions with carrier-free arguments descend into internal `std` dynamic dispatches (`(*sync.Once).doSlow`, `(*pp).handleMethods`), colliding with mask-wide targets (`attribution.go:3990-4015`).
   - `startupTargets` filters `site.Parent()` by `initRes.Reachable` instead of dead-branch-pruned `startupFns` (`attribution.go:573-586, 670-683`).
   - `computeRTAAsyncStartupFunctions` seeds `asyncFns` from internal `std` dynamic dispatches (`observability.go:1991-2055`).
4. **`resolveConcreteMethodTargetsSeen` Rejects Wrapper Error Methods (`(*strconv.NumError).Error()`) (`freshpath.go:4492`)**:
   - Because `*strconv.NumError` has an `error` field (`Err`) and `(*strconv.NumError).Error` invokes `e.Err.Error()`, `resolveConcreteMethodTargetsSeen` refuses `err.Error()` unless it verifies via whole-program field stores on `fp.summary` that every store to `(named.Origin(), fieldIdx)` writes a closed dynamic value and recursively resolves the inner interface invoke.
5. **Inverted Package Check in `userTouchedStdGlobals` (`attribution.go:728`)**:
   - `if !isStdPkgPath(userPaths, gPkg) || (isOwnInit && fp == gPkg)` checks `!isStdPkgPath(userPaths, gPkg)` instead of checking whether the touching function `f` belongs to a user package (`!isStdPkgPath(userPaths, fp)`), failing to record stdlib globals directly mutated by user `init` functions while recording stdlib globals initialized by their own stdlib `init`.

### 2. Major Algorithmic Bottlenecks & Redundant Scans Across `maximal.go`, `freshpath.go`, `attribution.go`, `analyzer.go`, `observability.go`

1. **Per-Subject `parser.ParseFile` from Raw Bytes & 5x `ast.Inspect` in `maximal.go` (`observability.go:678-695`, `maximal.go:539-821, 1114-1191, 1281-1334`)**:
   - In `observabilityGroup`, for every closed-world subject in a package with a filterable maximal blocker, `subjectMaximalExternalEffectsWithZeroGlobals` calls `maximalFileEffectsContentWithZeroGlobals`, which invokes `parser.ParseFile(token.NewFileSet(), filename, content, parser.SkipObjectResolution)` from raw bytes and runs up to 5 separate AST walks + `maximalTestingTypeEffectsFiltered` **on every subject in the package** ($N$ full file parses + $5N$ AST walks instead of parsing and indexing once per package).
   - `maximalFileEffectsContentWithZeroGlobals` (`maximal.go:566-601`) also duplicates `fileImportNames` (`823-851`), and `filterUnreachedMaximalEffects` (`1352-1355`) runs 3 back-to-back `ast.Inspect` walks (`filePackageVarInitDeps`, `fileUnconditionalInitVarCalls`, `fileHasTestingRunCall`) on the same `*ast.File`.
2. **10–14 Redundant SSA Function/Instruction Scans Per Batch & Subject (`attribution.go`, `analyzer.go`, `observability.go`, `freshpath.go`, `freshparam.go`)**:
   - **Three Whole-Program Global-Mutation Scans**: `verifiedUserSentinelGlobals` (`freshpath.go:2532-2612`), `computeMutatedGlobals` (`freshpath.go:2632-2667`), and `wholeZeroGlobalsForBase` (`observability.go:2196`) all walk every function, block, instruction, and operand in `ssa.Program` instead of computing global write/mutation/address-taken summaries once inside `enumerateCallerReferencesWithOrdered` (`attribution.go:1535`).
   - **Full Instruction Scan in `collectTestingHarnessCallbacks` (`attribution.go:3308-3352`)**: Scans all blocks and instructions of every function in `prov` for `testing.Cleanup` / `Fuzz` calls instead of looking up `summary.harnessCallbackSites` in `programSummary.sites`.
   - **Per-Subject Re-Scanning of Shared Startup & `TestMain` Functions (`analyzer.go:2642-2668`, `observability.go:1878-1936`)**: `subjectReachedAndStartupOnlyDeclKeys` re-scans `reach.startupFunctions` and `reach.testMainFunctions` and re-runs `asyncOrDynamicStartupFunctions` BFS for every subject even when `reach.baseStartup` is `true` (shared across the entire batch).
   - **Up to 4x `newFreshParamAnalysis` Call-Graph Rebuilds Per Subject (`freshparam.go:467-479`)**: Scans all blocks/instructions of `reach.functions` to build `fp.callers` instead of projecting `reach.summary.sites` or reusing `fp`.
   - **Uncached Per-Call Lookups in `freshpath.go`**: `closureCreations(fn)` (`3417-3430`) rescans `fn.Parent().Blocks` instead of consulting `summary.closureRefs[fn]`; `blockInCycle` (`546-565`) runs an uncached CFG BFS per `MkdirTemp`/`CreateTemp` call; `programCancelCtxType` (`5004-5017`) linearly scans `prog.ImportedPackages()` instead of calling `prog.ImportedPackage("context")`.
3. **Full From-Scratch `rta.Analyze` Re-Runs & $O(\text{BatchSize} \times |\text{Targets}|)$ Map Scans in `attribution.go`**:
   - In `attributedReachableSetsOnce` (`attribution.go:340-406`) and `binaryReachableUnion` (`957-1008`), discovering a testing callback (`t.Cleanup` / `f.Fuzz`) discards the entire `attributedRTA` state and re-runs `rta.Analyze(ctx, roots, seeds)` from scratch over all 64 subjects and `init` roots instead of calling incremental `Analyzer.Extend`.
   - `attributedReachableSetsOnce` (`attribution.go:528-556`) and `activateHarnessDispatchedMethods` (`attribution.go:3862-3876`) iterate over the entire `res.Reachable`, `res.Resolved`, `res.Targets`, and `res.HarnessStdTargets` maps once per subject (up to $64\times$ and $192\times$ per batch) instead of partitioning by bitmask once.
   - `attribution.go:355-359, 472-476` rescans `allFunctions` inside the per-subject loop instead of reusing the pre-collected generic instances per origin.

### 3. God-File Structure & Duplicated Scaffolding in `freshpath.go`, `attribution.go`, `analyzer.go`, `observability.go`, `memo.go`

- `freshpath.go` (`5,117` lines), `attribution.go` (`4,105` lines), `analyzer.go` (`2,746` lines), and `observability.go` (`2,710` lines) mix multiple distinct subsystems and duplicate:
  - `evalFP` / `collectFP` Tarjan SCC scaffolding between `closedDynamicTargets` and `closedInvokeTargets` (`freshpath.go:4159-4232` vs `4272-4372`).
  - 5-way `subjectQuery` memo reset (`freshparam.go:320, 385, 404, 450`, `freshpath.go:5075`).
  - Callee/invoke depth & seen-map cloning (`freshpath.go:2828, 2967`, `freshparam.go:331`).
  - `cellOf` vs `structElemCellOf` address-chain peelers (`freshpath.go:3379` vs `3440`).
  - 6-way tuple `*ssa.Extract` referrer loops (`freshpath.go:624, 766, 786, 3155, 4090, 4118`).
  - `asyncOrDynamicStartupFunctions` (`observability.go:1878`) vs `computeRTAAsyncStartupFunctions` (`1958`).
  - `recordTestMainCallEffect` (`observability.go:834`) vs `recordDirectCallEffect` (`1008`).
  - 3 identical instruction type/flag prelude loops (`analyzer.go:897`, `observability.go:792, 930`).
  - 4 slice-to-map cachefile wrappers across `memo.go` and `effectmemo.go`, plus duplicate raw-digest cache loaders in `listingmemo.go` and `toolchain_loader.go`.

## Resolution

During Chunk 5:
1. **Decompose `freshpath.go`, `attribution.go`, `analyzer.go`, `observability.go`, and `memo.go`**:
   - Split `freshpath.go` (`5,117` lines) into 6 focused files (`freshpath_fs.go`, `dynamic_walk.go`, `sentinel_globals.go`, `callee_return.go`, `container_cells.go`, `dispatch_targets.go`) and decompose `walkDynamicValue` and `walkDynamicValueUncached`.
   - Split `attribution.go` (`4,105` lines) into `attribution_batch.go`, `attribution_provenance.go`, and `attribution_harness.go`; `analyzer.go` (`2,746` lines) into `analyzer.go` and `analyzer_declkeys.go`; `observability.go` (`2,710` lines) into `observability.go` and `observability_startup.go`; and merge `effectmemo.go` into `memo.go`.
2. **Land All Precision & Soundness Fixes**:
   - Thread `audited` and shared `freshParamAnalysis` through `provenanceReachable` / `provenanceBFSWithCandidates`; thread `fp` into `fileValueFromAdmittedOpen` and `fileValueFromFreshOpenFile`; fix the inverted `userTouchedStdGlobals` package check (`attribution.go:728`); eliminate `std` `init` and carrier-free `std` static-call RTA contamination; and close wrapper-error method dispatch (`(*strconv.NumError).Error()`) from whole-program field stores.
3. **Land All Scan-Elimination & Deduplication Optimizations**:
   - Pre-parse and index maximal AST files once per package in `observabilityGroup` (eliminating per-subject `parser.ParseFile` and 5x `ast.Inspect` in `maximal.go`).
   - Use incremental `Analyzer.Extend` for callback RTA extension and partition `rta.Result` bitmasks in one pass in `attribution.go`.
   - Fold whole-program global mutation/zero-global/sentinel scans and `harnessCallbackSites` indexing into `enumerateCallerReferencesWithOrdered`; cache `baseStartup` declaration keys and `asyncOrDynamicStartupFunctions` across the batch; reuse `summary.sites` in `newFreshParamAnalysis`; and deduplicate `evalAndCollectDynamicValue`, `resetMemos`, `enterCallee`/`enterInvoke`, `peelAddressCell`, `forEachTupleExtract`, `propagateAsyncOrDynamicStartup`, and `recordCallEffect`.
