# Extract `internal/dynstate/internal/syntaxutil` and Deduplicate AST/Type Helpers

**Lands:** Chunk 4 in [`docs/plans/plan.md`](../plans/plan.md) (`Decompose gofresh/internal/dynstate Subpackages`).

## Context & Concrete Duplicated Surfaces

`internal/dynstate` (`35,595` non-test lines across 9 files) contains extensive copy-pasted AST, `go/types`, callee-resolution, place-spine, struct-traversal, and mutex-matching helpers across `func_summary.go`, `discharges_proto.go`, `discharges_audited.go`, `refconfine.go`, and `typecarrier.go`:

1. **Duplicate Parenthesis Unwrapper (70+ Call Sites)**:
   - `unparenExpr(expr ast.Expr) ast.Expr` (`func_summary.go:70-78`) is a manual loop over `*ast.ParenExpr` duplicating standard-library `ast.Unparen(expr)` across `func_summary.go`, `discharges_proto.go`, `discharges_audited.go`, and `refconfine.go`.
2. **7 Duplicate Identifier `types.Object` Resolvers (`TypesInfo.Uses` / `Defs`)**:
   - `identDefOrUse(info, id)` (`func_summary.go:150-158`: `Defs` then `Uses`).
   - `identUseOrDef(info, id)` (`func_summary.go:8283-8291`: `Uses` then `Defs`).
   - 3 verbatim local `resolve := func(id *ast.Ident) types.Object` closures (`func_summary.go:5242-5249`, `func_summary.go:6657-6664`, `func_summary.go:8438-8445`).
   - `lookupIdentVar(info, id)` (`discharges_audited.go:2950-2962`) and `isIdentUsingObj(info, expr, target)` (`discharges_audited.go:2942-2948`).
3. **8 Duplicate Named-Type Package/Name Predicates**:
   - `isNamedInPkg(t, pkgPath, name)` (`discharges_audited.go:2974-2980`) and `isPkgNamedType(t, pkgPath, typeName)` (`func_summary.go:5457-5461`) are byte-for-byte identical.
   - `isSyncMap(t)` (`func_summary.go:11106-11120`), inline `sync.Once` / `sync.Pool` checks (`discharges_proto.go:1303-1315`, `func_summary.go:11068-11100`), `isReflectTypeType(t)` (`discharges_proto.go:3105-3119`), and `isErrorType(t)` (`discharges_proto.go:10844-10850`) vs inline `types.Universe.Lookup("error")` checks (`discharges_proto.go:3223`, `func_summary.go:8876`).
4. **3 Builtin Call Resolvers + 15+ Inline `*types.Builtin` Type Switches**:
   - `lookupBuiltin(info, fun)` (`refconfine.go:24-39`), `mapperCallBuiltinObj(info, fun)` (`discharges_audited.go:721-733`), and `isMakeCall(info, call)` (`discharges_proto.go:13469-13478`), plus 15+ inline `info.Uses[id].(*types.Builtin)` checks across `discharges_proto.go` and `func_summary.go`.
5. **6 Duplicate Callee Expression Unwrappers and `*types.Func` Resolvers**:
   - `unwrapCallee(expr)` and `plainCalleeFunc(info, expr)` (`func_summary.go:22-68`), `callTargetIdent(fun)` (`refconfine.go:2098-2111`), `resolveCalledFuncObj(info, call)` (`discharges_proto.go:13762-13780`), and `resolveConcretePkgCallee(p, info, call, index)` (`refconfine.go:460-482`).
6. **7 Overlapping Root-Variable / Place-Spine Extractors**:
   - `rootIdent(expr)` (`func_summary.go:129-148`), `extractTargetVar(info, expr)` (`func_summary.go:361-428`), `rootLocalIdent(expr)` (`discharges_proto.go:10040-10063`), `rootPkgScopeVar(p, expr)` (`discharges_proto.go:6216-6251`), `lookupPkgScopeVar(p, expr)` (`discharges_proto.go:13521-13537`), and `rootImportedVar(p, expr)` (`discharges_proto.go:986-1020`).
7. **Duplicated Struct-Deref, Selection-Hop, and Value-Contained Struct Walkers**:
   - `derefStructType` (`discharges_audited.go:2990-3006`) vs `derefNamedStruct` (`discharges_proto.go:1322-1340`).
   - `selectionHopTypes` (`discharges_audited.go:233-282`) vs `selection crosses pointer` loops (`discharges_proto.go:1342-1365`, `refconfine.go:1960-1990`).
   - `collectValueContainedStructs` (`discharges_audited.go:201-231`) vs `walkValueContainedStructs` (`discharges_proto.go:1367-1382`).
8. **14+ Hand-Rolled Recursive `seen := map[types.Type]bool{}` Type Switches**:
   - Despite `walkTypeStructure(t, visitNamed)` in `typecarrier.go:283-310`, 14+ functions across `refconfine.go`, `discharges_audited.go`, `discharges_proto.go`, and `func_summary.go` hand-roll identical recursive type switches over `*types.Pointer`, `*types.Slice`, `*types.Array`, `*types.Map`, `*types.Chan`, `*types.Struct`, and `*types.Tuple`.
9. **4 Duplicate Mutex Lock / Defer-Unlock Statement Matchers**:
   - `isMutexLockOrUnlockCall` (`discharges_audited.go:2873-2905`), `matchLockMethodCall` (`func_summary.go:5633-5685`), `matchSelectMutexLockCall` / `matchDeferSelectMutexUnlock` (`discharges_proto.go:13922-13992`), and `matchMutexGuardPair` (`discharges_proto.go:13446-13467`).

## Resolution

During Chunk 4 (`Decompose gofresh/internal/dynstate Subpackages`), extract a shared leaf foundation package `internal/dynstate/internal/syntaxutil` containing:
- Shared value and summary types (`TypeRef`, `FuncKey`, `CrossCallRequirement`, `FreshStructConstructorSummary`, `FreshnessReq`, `Hook`, `PkgSyntaxIndex`, `CallSiteIndex`) so `refconfine`, `seams`, `protoaudit`, and `freshstruct` share types without circular imports.
- Single canonical implementations of `ast.Unparen`, `IdentObject`, `LookupIdentVar`, `IsNamedInPkg`, `LookupBuiltin`, `UnwrapCallee`, `PlainCalleeFunc`, `ExtractPlaceSpine`, `DerefStructType`, `SelectionHopTypes`, `WalkValueContainedStructs`, `WalkTypeStructure`, `UnderlyingType`, and `MatchMutexLockUnlock`.
