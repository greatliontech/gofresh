# Extract `internal/dynstate/internal/syntaxutil`, Unify Confinement/Summary Engines & Fix `dynstate` Soundness/Precision Defects

**Lands:** Chunk 6 in [`docs/plans/plan.md`](../plans/plan.md) (`Decompose, Unify, Optimize, Fix Defects & Harden gofresh/internal/dynstate and Subpackages`).

## Context & Concrete Findings

### 1. Soundness & Precision Defects in `internal/dynstate` (`func_summary.go`)

1. **Defect 1 (Soundness): `boundValueRetentionFreeJudged` Misses `range` and `copy` Carrier Smuggling in `init` Flow (`func_summary.go:174-235, 10190-10199`)**:
   - In `boundValueJudged` (`func_summary.go:10190-10199`), when `tolerateRootedStores == true` (used by `boundValueRetentionFreeJudged` for `ParamRetentionFree` and `ReceiverRetentionFree`), `propagateLocalTaint` is called to populate `carrierReaching` (locals whose values derive from a package-level dynamic carrier), passing **`nil` as `rangeTainted` at line 10197**.
   - Furthermore, `propagateLocalTaint` (`func_summary.go:174-235`) hand-rolls its own switch over `*ast.AssignStmt`, `*ast.RangeStmt`, and `*ast.ValueSpec` instead of using `eachLocalBinding` (`func_summary.go:83-125`), and **omits builtin `copy(dst, src)`**.
   - **Violating path**: If an `init`-called method or helper iterates a package-level carrier slice/map (`for _, fn := range globalHooks { r.slot = fn }`) or copies one (`local := make([]func(), len(globalHooks)); copy(local, globalHooks); r.slots = local`) and stores the local into a receiver/parameter field `r.slot`, `carrierReach(rhs)` at `func_summary.go:10301` evaluates `carrierReaching[local] == false` and `smuggles == false`, falsely proving the method/function `ReceiverRetentionFree` / `ParamRetentionFree` and dropping the init-flow escape mark on `r` (violating `REQ-closure-shared-dynamic-state-init-aliasing`).
   - **Fix**: Pass `carrierReach` (not `nil`) as `rangeTainted` at `func_summary.go:10197` and handle builtin `copy(dst, src)` in `propagateLocalTaint` / `eachLocalBinding`.
2. **Defect 2 (Precision / Inconsistency): `boundValueJudged` Checks `isRoot(n.X)` Instead of `rooted(n.X)` on `*ast.SelectorExpr` (`func_summary.go:10495, 10444`)**:
   - At `func_summary.go:10487`, `case *ast.IndexExpr:` checks `if rooted(n.X) && !allowed[rootIdent(n.X)]`, and `receiverReadOnlyMethods` (`func_summary.go:11770`) checks `if recvRooted(n.X) && !allowed[rootIdent(n.X)]`, whereas `boundValueJudged` at `func_summary.go:10495` checks `if isRoot(n.X) && !allowed[rootIdent(n.X)]` (and `L10444` checks `isRoot(sel.X)`), where `isRoot` (`L10201-10211`) only accepts a bare `*ast.Ident`.
   - **Violating path**: When a function or range body reads a scalar field through a chained selector or index on a bound root (`return p.subPtr.count` or `return p.items[0].count`), `isRoot(n.X)` is `false` at `.count`, so `consume(n.X)` is never called and `ast.Inspect` visits `p.subPtr` / `p.items[0]` with `!allowed[p]`, falsely setting `leaky = true` on a pure scalar read.
   - **Fix**: Replace `isRoot(n.X)` / `isRoot(sel.X)` at `func_summary.go:10495, 10444` with `rooted(n.X)` / `rooted(sel.X)`.
3. **Defect 3 (Precision / Copy-Paste Drift): `receiverReadOnlyMethods` Omits `case *ast.ValueSpec:` (`func_summary.go:11560-11796`)**:
   - `receiverReadOnlyMethods` taints local `var` declarations via `propagateLocalTaint` (`L11477-11486`), but its main `ast.Inspect` switch (`L11560-11796`) omits `case *ast.ValueSpec:` (unlike `boundValueJudged` at `L10311-10332`). In a read-only method containing `var s []int = r.items; return len(s)`, `r.items` is not consumed by a `ValueSpec` arm, falsely disqualifying the method from `ReceiverReadOnly`.
   - **Fix**: Unify `receiverReadOnlyMethods` with `boundValueJudged`.
4. **Defect 4 (Soundness): `initAliasedLocals` `bind` Misses Cross-Package `pkg.Carrier = ...` and `SliceExpr` LHS in `CarrierLinks` (`func_summary.go:6833-6881`)**:
   - `bind` unwraps `*ast.SelectorExpr` via `target = t.X` without checking whether `t.X` is a package qualifier (`*types.PkgName`), and then at `L6864` returns `false` on `*types.PkgName`; it also omits `*ast.SliceExpr` in the unwrap loop. When package `A`'s `init()` assigns `pkgB.ExportedCarrier = ownCarrier` or `ownCarrier[:1][0] = otherCarrier`, no `CarrierLink` is recorded (violating `REQ-closure-shared-dynamic-state-init-aliasing`).
   - **Fix**: Unwrap `*ast.SelectorExpr` whose `t.X` is a `*types.PkgName` to `t.Sel` and break; include `case *ast.SliceExpr: target = t.X; composite = true`; and delete the 100%-duplicate `storeLink` closure (`L6754-6795`).

### 2. Major Engine Unifications Across `dynstate`

1. **Delete `verifyProtectedMemoStructConfinement` (`discharges_audited.go:1469-1899, 2485-2792`, ~730 LOC) by Routing Through `VerifyReadOnlyRefConfinement` (`refconfine.go`)**:
   - `verifyProtectedMemoStructConfinement` hand-rolls 700 lines of AST/type confinement checks (`exprMutatesProtectedStruct`, `exprTakesAddrInsideProtected`, `callMutatesProtectedContainer`, `callBoxesProtectedIntoInterface`, `assignErasesProtected`, `typeMentionsProtectedStruct`) and then at line 1853 calls `VerifyReadOnlyRefConfinement` anyway.
   - `VerifyReadOnlyRefConfinement` already enforces `SeedStructOrigin`, `seedStructTypeViolated`, `callErasesSeedStruct`, `assignErasesTaint`, `exprMutatesTaintedTarget`, `&`, `==`/`!=`, `CompositeLit`, `SendStmt`, `ReturnStmt`, `IncDecStmt`, `RangeStmt`, and mutating builtins. Adding `AllowInFunc` and `ForbidNonNilPtrIdentityCompare` options to `refconfine.Config` deletes ~700 lines of duplicate confinement code in `discharges_audited.go`.
2. **Unify `receiverReadOnlyMethods` (`func_summary.go:11368-11806`) with `boundValueJudged` (`func_summary.go:10091-10522`)**:
   - Expressing receiver-specific options (`onceFill` exemption, `governedCalls`, `unexportedDispatchTargets`, `closedFieldDispatchTargets`) on `boundValueJudged` eliminates ~300 lines of duplicated use-shape logic and fixes Defects 2 and 3.
3. **Unify Local `sync.Once` Memoizer Verifiers (`discharges_proto.go:5347-5456` vs `6355-6569`)**:
   - Combine `isMemoizedOnceGetterClosure` (110 lines) and `findLocalSyncOnceMemoizers` (215 lines) into a single `localSyncOnceMemoizer` detector supporting both inline `once.Do(initLit); return cached` and helper-wrapped `lazy := func() { once.Do(initLit) }; getter := func() T { lazy(); return cached }`.
4. **Unify `verifyProtoMessageType` (`discharges_proto.go:5823-5955`) and `verifyProtoExtensionType` (`discharges_proto.go:5957-6074`)**:
   - Both execute the exact same 7-step verification pipeline; parameterizing role (`ProtoRoleMessage` vs `ProtoRoleExtension`) and optional `initHelper` cuts ~130 lines of duplication.
5. **Unify Mutex-Guarded Map Memoizer Verifiers (`discharges_audited.go:216-672`, `942-1460`, `discharges_proto.go:13309-13515`)**:
   - Extract shared lock-region and map-confinement helpers across `verifyUnixMapperVar`, `verifyReflectTypeMemoMap`, and `findMutexConfinedConstructorCaches`.
6. **Unify Local Fresh-Allocation & Escape-Position Analyzers (`refconfine.go:1798-1975`, `discharges_proto.go:9921-10226`, `11071-11699`)**:
   - Share `isFreshFieldInit`, `funcBodyHasGoto`, `clampToLoops`, `defer`/`go`/`FuncLit` capture disqualification, and local alias/substruct pointer propagation across `computeLocalFreshContainers`, `collectFreshLocalStructVars`, and `analyzeSingleFreshConstructorFunc`.
7. **Deduplicate `recordDynamicGlobalUses` (`func_summary.go:6754-6795, 7565-7738`)**:
   - Delete duplicate `storeLink` (`L6754-6795`), unify attributed method (`L7565-7618`) and function (`L7620-7695`) body walks, and merge the identical `initOnly` (`L7697-7716`) and `init` (`L7718-7737`) arms.
8. **Extract `internal/dynstate/internal/syntaxutil` Shared Leaf Package**:
   - Unify 70+ `unparenExpr` calls (`ast.Unparen`), 7 identifier object resolvers (`IdentDefOrUse` / `IdentUseOrDef` / `LookupIdentVar`), 8 named-type predicates (`IsNamedInPkg`, `IsReflectType`, `IsSyncMutexOrRWMutex`, `IsSyncOnceType`, `IsSyncMap`, `IsUnsafePointerType`, `IsErrorType`), 3 builtin call resolvers (`LookupBuiltin`), 6 callee unwrappers (`UnwrapCallee`, `PlainCalleeFunc`), 7 place-spine extractors (`RootIdent`, `ChainRoot`, `ExtractPlaceSpine`), struct-deref and selection-hop walkers (`UnwrapNamedStruct`, `SelectionHopTypes`, `WalkValueContainedStructs`), `RecvTypeName` / `RecvBaseNamedType`, `EachLocalBinding` (including `copy(dst, src)`), 4 mutex lock/unlock matchers, and fixed-point solvers (`SolveLeastFixedPoint`, `SolveReachFixedPoint`, `PropagateBFS`).

## Resolution

During Chunk 6:
1. Extract `internal/dynstate/internal/syntaxutil` (`ast.go`, `types.go`, `fixpoint.go` + `syntaxutil_test.go`).
2. Fix Soundness/Precision Defects 1–4 with dedicated regression tests in `internal/dynstate/dynstate_test.go`.
3. Execute Consolidations 1–8 across `refconfine`, `freshstruct`, `protoaudit`, `seams`, and `dynstate`.
