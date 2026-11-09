# Fix Provenance BFS `audited` Propagation, `freshParamAnalysis` Reuse, Startup RTA Contamination, and Wrapper-Error Method Resolution

**Lands:** Chunk 3 in [`docs/plans/plan.md`](../plans/plan.md) (`Extract gofresh/internal/closure/internal/toolchain` & `internal/closure` reachability/freshpath fixes).

## Context & Concrete Reachable Findings

### 1. `provenanceReachable` & `provenanceReachableWithCandidates` Hardcode `audited = false` and Allocate Uncached `freshParamAnalysis` Per Dynamic Call Site (`attribution.go:3709, 3714, 4018`)

- **Reachable Path**:
  - `attributedReachableSetsOnce` (`attribution.go:200`) and `binaryReachableUnion` (`attribution.go:600`) receive `audited bool`.
  - However, `provenanceReachable` (`attribution.go:3709`) and `provenanceReachableWithCandidates` (`attribution.go:3714`) pass `false` as the first argument (`audited`) to `provenanceBFSWithCandidates`.
  - Inside the inner instruction loop of `provenanceBFSWithCandidates` (`attribution.go:4018`), every dynamic call or interface invoke allocates a brand-new `&freshParamAnalysis{audited: audited}` with `audited: false`, `summary: nil`, and `dynamicMemos: nil`:
    1. Because `audited` is `false`, `closedInvokeTargets(site, fresh)` (`freshpath.go:4489`) refuses to close interface invokes on standard library concrete types (`*strconv.NumError`, `*errors.errorString`, `*strings.Reader`, `*bytes.Buffer`) and falls back to RTA's mask-wide `result.Targets[site]`.
    2. Because `summary` and `dynamicMemos` are `nil`, every dynamic call site in the BFS recomputes `walkDynamicValue` and `progAllFunctions(prog)` (`ssautil.AllFunctions(prog)` + `slices.SortFunc` in `freshpath.go:391-409`) from scratch.

### 2. Startup Reachability Contamination Across `std` `init` Roots and Carrier-Free `std` Calls (`attribution.go:650-738, 3717-4049`, `observability.go:1991-2055`)

1. **`std` `init` Roots Traverse `result.Targets` into Non-Standard Functions (`attribution.go:650-663, 3717-3779, 4041`)**:
   - `cachedBaseStartupReachability` seeds `rta.Analyze` with all `initRoots` (`std` and non-`std`) sharing `startupMask = 1`.
   - When any non-standard `init()` creates a `func()` closure (such as `sync.OnceValue(func() T { ... })`, whose inner closure `sync.OnceValue$1` has `Parent() == sync.OnceValue[T]`, already scanned) or boxes a non-standard type into `any`/`error`/`fmt.Stringer`, RTA merges those targets into `result.Targets[site]` under `startupMask`.
   - When `provenanceBFSWithCandidates` walks from a `std` `init` root (which by Go's spec can never call non-standard code), `enqueueSiteTargets(result.Targets[site])` jumps into unrelated non-standard closures and methods.
2. **Static Calls to Carrier-Free Audited Pure `std` Functions Descend Into Internal `std` Dynamic Dispatches (`attribution.go:3990-4015`)**:
   - When a function calls a carrier-free audited pure `std` function with carrier-free arguments (e.g., `regexp.MustCompile("...")`, `crypto/sha256.Sum256(b)`, or `fmt.Sprintf("go1.%d", n)` where `n` is `int`), `provenanceBFSWithCandidates` unconditionally enqueues the `std` callee and descends into internal `(*sync.Once).doSlow` or `(*pp).handleMethods` dynamic call sites, colliding with mask-wide `func()` / `Error()` / `String()` targets in `result.Targets[site]`.
3. **`startupTargets` Projects From `initRes.Reachable` Instead of Provenance-Pruned `startupFns` (`attribution.go:573-586, 670-683`)**:
   - Even after `provenanceReachableStartup` prunes dead branches via `liveBlocks(fn, fnZeroGlobals)`, `startupTargets` filters `site.Parent()` by `initRes.Reachable` instead of `startupFns`.
4. **`userTouchedStdGlobals` Marks `std`-Touched Globals as User-Touched (`attribution.go:714-738`)**:
   - At `attribution.go:727`, `std` helper functions (`isStdPkgPath(userPaths, fp) == true`, `isOwnInit == false`) touching `std` globals are recorded in `userTouchedStdGlobals`.
5. **`computeRTAAsyncStartupFunctions` Seeds From Internal `std` Dynamic Calls (`observability.go:1991-2055`)**:
   - Seeding `asyncFns` from internal `std` dynamic dispatches marks colliding non-standard closures as async startup functions, disabling `syncZeroGlobals` dead-branch pruning at `attribution.go:3936`.

### 3. `resolveConcreteMethodTargetsSeen` Rejects Wrapper Error Methods (`(*strconv.NumError).Error()`) (`freshpath.go:4492`)

- **Reachable Path**:
  - `strconv.ParseBool(s)` returns `error` backed by `*strconv.NumError` (`struct { Func string; Num string; Err error }`).
  - When a caller invokes `err.Error()`, `closedInvokeTargets` resolves `concreteTypes = {*strconv.NumError}` and calls `resolveConcreteMethodTargetsSeen` (`freshpath.go:4435`).
  - At `freshpath.go:4492`, because `*strconv.NumError` has an `error` interface field (`Err`) and `(*strconv.NumError).Error` invokes `e.Err.Error()`, `typeMayCarryDynamicTop(audited, ct)` and `paramMaySupplyDynamicSeen(..., declFn.Params[0])` both return `true`, causing `resolveConcreteMethodTargetsSeen` to return `false` and refuse `err.Error()`.
- **First-Principles Fix**:
  - When `declFn` is an audited pure `std` method whose receiver parameter `declFn.Params[0]` only accesses dynamic fields `(named.Origin(), fieldIdx)` to invoke interface methods on the loaded field value (with carrier-free arguments), check via a memoized whole-program field-store summary on `fp.summary` whether every store to `(named.Origin(), fieldIdx)` across `prog` writes a closed dynamic value (`walkDynamicValue`), and recursively resolve the inner interface invoke against those stored concrete types via `resolveConcreteMethodTargetsSeen`.

## Resolution

Land all three fixes with unit and integration regression tests in Chunk 3 (`internal/closure`).
