# Decompose, Optimize, Fix Precision & Harden Tests in `internal/closure/internal/rta`

**Lands:** Chunk 3 in [`docs/plans/plan.md`](../plans/plan.md) (`Decompose, Optimize, Fix Precision & Harden gofresh/internal/closure/internal/rta`).

## Context & Concrete Findings

### 1. Algorithmic & Performance Inefficiencies in `internal/closure/internal/rta/rta.go` (`1,918` Lines)

1. **Quadratic `ContainsTypeParam` Re-Invocations, Missing Package-Scope Fast Path, and Map Churn (`rta.go:437-488, 1234, 1509-1589, 1611-1616, 1718-1723, 1830-1835`)**:
   - In `ContainsTypeParam` (`rta.go:1554-1573`), every non-parameterized `*types.Named` (`t.TypeParams() == nil && t.TypeArgs() == nil`) unconditionally recurses into `ContainsTypeParam(t.Underlying(), seen)`. A non-parameterized named type declared at package scope (`obj.Parent() == obj.Pkg().Scope()`), unless it is a constraint interface containing a `*types.Union`, can never capture a function-local type parameter. Without that $O(1)$ scope guard, `ContainsTypeParam` walks the entire transitive struct field graph of package-level types (`*testing.T`, `*os.File`, `reflect.Value`, etc.) on every call.
   - `addRuntimeType` (`1611-1616`), `addHarnessStdRuntimeType` (`1718-1723`), and `addWritableRuntimeType` (`1830-1835`) clear `r.typeParamSeen` and re-run `ContainsTypeParam` at the root type `T` AND at every recursive child type (`t.Elem()`, `t.Underlying()`, `t.Field(i).Type()`, `t.Key()`), causing $O(D \cdot N)$ redundant traversals per composite type.
   - `ContainsTypeParam` computes `unaliased := types.Unalias(t)` at line 1513 but checks/inserts `seen[t]` instead of `seen[unaliased]` at lines 1520–1521.
   - Callers in `rta.go:1234`, `observability.go:48`, and `attribution.go:222, 878, 3763, 3771` allocate a fresh `map[types.Type]bool{}` on every call (including inside `typeCanCarryAnyInitBoxed`'s inner loop over `initBoxed`).
2. **Triple `r.prog.MethodSets.MethodSet(T)` Lookups Per Runtime Type (`rta.go:1470, 1620, 1652, 1727, 1736, 1758`)**:
   - When `addRuntimeType` or `addHarnessStdRuntimeType` visits a concrete type `T`, it calls `r.prog.MethodSets.MethodSet(T)` 3 separate times: once for exported method reachability (`1620`/`1727`), once inside `r.interfaces(T)` to compute `attributedFingerprint` (`1470`), and once to walk method signatures (`1652`/`1758`).
3. **`checkTypedCallbackTrampolineAssert` Synthesizes `$bound` Wrappers for Entire Packages & Scans Package Instructions Twice (`rta.go:914-1059`)**:
   - Lines 965–972 iterate over every `*ssa.Type` in `f.Pkg.Members` and call `f.Prog.MethodSets.MethodSet(types.NewPointer(m.Type()))` and `f.Prog.MethodValue(mset.At(i))`, which lazily synthesizes `$bound` wrapper SSA functions for every method of every type in `f.Pkg` (e.g., all of `package time` when visiting `time.goFunc`). Iterating declared methods via `named.NumMethods()` + `f.Prog.FuncValue(named.Method(i))` avoids `MethodSets.MethodSet` and avoids synthesizing unused `$bound` wrappers.
   - Lines 977–1037 and 1041–1057 scan every instruction of every function in `f.Pkg` twice instead of once, and `r.trampolineAsserts` is discarded after each `rta.Analyze` call.
4. **Duplicate `unwrapWrapperCallee` & Unmemoized `ssaFuncPkgPath` Block Scans (`rta.go:653-769, 1745`)**:
   - `noteReflectCallSite` calls `unwrapWrapperCallee(g)` at line 758 and then calls `noteReflectCalleeUse(g, masks)` at line 768, which calls `unwrapWrapperCallee(g)` a second time on >99.9% of static calls.
   - For `$bound` and `$thunk` synthetic wrappers, `ssaFuncPkgPath` (`653-706`) falls through to scanning `fn.Blocks` and `b.Instrs` on every call (`visitFunc`, `visitDynCall`, `visitInvoke`, `addHarnessStdReachable`, `addHarnessStdRuntimeType`).
5. **Unnecessary Heap Allocations in `addRuntimeMethodFunc`, `attributedFingerprint`, and `isPureHarnessInternalStdType`**:
   - `addRuntimeMethodFunc` (`rta.go:502`) allocates `types.NewSignatureType(nil, ...)` even though `mv := r.prog.MethodValue(sel)` already has a receiverless, non-generic `mv.Signature`.
   - `attributedFingerprint` (`rta.go:1910`) calls `method.Id()` (allocating `pkg.Path() + "." + method.Name()` on the heap for every unexported method) and `fmt.Appendf` (boxing 3 `any` values per method).
   - `isPureHarnessInternalStdType` (`rta.go:125-214`) allocates a fresh `seen := make(map[types.Type]bool)` on every `MakeInterface` (`1114`) and on every recursive child step in `addHarnessStdRuntimeType` (`1704`) without per-type memoization.

### 2. Precision & Correctness Defects

1. **`Seeds.AddrTaken` Forced Reachable Whenever `reflect` Is Imported (`rta.go:347-349, 1184-1194, 1342-1343`)**:
   - `Analyze` sets `r.reflectValueCall = prog.LookupMethod(valType, reflectPkg.Pkg, "Call")` whenever `prog.ImportedPackage("reflect") != nil`. When `Seeds.AddrTaken` seeds candidate functions via `visitAddrTakenFunc`, line 347 (`if r.reflectValueCall != nil || r.reflectValueCallSlice != nil { r.addReachable(f, delta) }`) immediately marks every candidate function reachable and walks its body even when the candidate is never dispatched by the subject, contradicting `Seeds`'s contract (`rta.go:1187-1194`) and polluting `result.Targets` for `provenanceBFSWithCandidates`.
2. **Top-Level-Only Exclusion in `isPureHarnessInternalStdType` (`rta.go:137-143` vs `158-167`)**:
   - `isPureHarnessInternalStdType` checks exclusions (`context`, `errors`, `os.File`, `io.discard`) only on `topNamed` before entering the recursive `walk`, allowing a struct in a harness-internal stdlib package that embeds or contains a field of type `context.Context`, `*os.File`, or `io.discard` to pass `walk`.

## Resolution

During Chunk 3:
1. **Decompose `internal/closure/internal/rta/rta.go` (`1,918` lines) into 4 focused files**:
   - `rta.go` (~420 lines): Core worklist engine, `Result`, `Seeds`, `Analyze`, and incremental `Analyzer.Extend` API.
   - `dispatch.go` (~380 lines): Dynamic function calls, interface invoke resolution, method-set bloom fingerprinting (`attributedFingerprint` without heap allocations), and memoized `ssaFuncPkgPath` / `unwrapWrapperCallee`.
   - `runtime_types.go` (~450 lines): Unified Plane-0 / Plane-1 runtime type traversal (single `MethodSet(T)` lookup per type), memoized `isPureHarnessInternalStdType` (with recursive exclusion checks), and fast `ContainsTypeParam(t types.Type) bool` (with package-scope `*types.Named` fast path and `unaliased` cycle tracking).
   - `reflect.go` (~520 lines): Reflective method-value / writable-container state machine (reusing `mv.Signature` directly in `addRuntimeMethodFunc`), `closedMethodValueSigs`, and single-pass `checkTypedCallbackTrampolineAssert` without `MethodValue` `$bound` wrapper synthesis.
2. **Fix `Seeds.AddrTaken` candidate seeding vs `reflectValueCall` reachability**, add incremental `Analyzer.Extend`, and emit `rta.analyze.done` trace events.
3. **Harden `internal/closure/internal/rta/rta_test.go`**:
   - Add direct unit tests for `checkTypedCallbackTrampolineAssert` (positive & 5 negative cases), `computeClosedMethodValueSigs` (Phi, intra-package helper, unused, and 6 escape/fallback cases), `onlyDirectCallCallee`, `ContainsTypeParam` across all `go/types` constructors, `isPureHarnessInternalStdType` nested exclusions, fingerprint collisions, and a `TestBatchVsSoloEquivalenceProperty` property test.
