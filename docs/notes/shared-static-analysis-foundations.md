# Chunk 2 Working Notes: Shared Static-Analysis Foundations (`internal/syntaxutil`, `internal/flowir`, `internal/refconfine`)

## Scope & Goals

1. **Promote Shared Static-Analysis Packages Out of `internal/dynstate`:**
   - Move `internal/dynstate/syntaxutil` → `internal/syntaxutil` (Layer 0).
   - Move `internal/dynstate/flowir` → `internal/flowir` (Layer 1, importing `internal/syntaxutil`).
   - Move `internal/dynstate/refconfine` → `internal/refconfine` (Layer 1, importing `internal/auditset`, `internal/flowir`, `internal/syntaxutil`).
   - Update all imports across root `package gofresh`, `internal/closure`, `internal/propharness`, `internal/dynstate`, and `internal/dynstate/internal/{capsule,freshstruct,seams}`, removing sideways imports into `internal/dynstate/*`.
   - Update `.stipulator/policy.textproto` (`./internal/syntaxutil`, `./internal/flowir`, `./internal/refconfine` in `race:leaf`) and retarget/pin the 7 static `stipulator` bindings in `.stipulator/bindings/closure.textproto`.

2. **`internal/syntaxutil` Consolidation (`<= ~1,050` LOC):**
   - Add generic `SolveBipartiteLFP` and `PruneUnsatisfiedDeps` to `fixpoint.go`, wire existing bipartite fixed-point and dependency-pruning loops (`cone_resolve_lfp.go` Stages 2a & 2c, `summary_leakfree.go`), and cover with `rapid` property tests against independent brute-force reference oracles in `syntaxutil_test.go`.
   - Promote shared `IsRefHeaderType` to `types.go` and canonical `NodeHasGotoOrLabel` (for uncached sub-statement AST nodes such as `IfStmt` branches) to `ast.go`.
   - Split `keys.go` (`930` LOC) into `keys.go` (core callable/parameter/field/env-audit keys, graph edges, and `ExplainHookSet`) and `discharge_keys.go` (init-region, once-memo, read-only var alias, static composite global, and exported seam fact keys).

3. **`internal/flowir` Consolidation (`<= ~1,050` LOC):**
   - Split `lower.go` (`1,405` LOC) into `lower_stmt.go` and `lower_expr.go`.
   - Record control-flow hazard flags (`HasGoto`, `HasNestedGoto`, `HasLabel`, `HasFallthrough`, `HasLabeledBranch`, `HasDefer`, `HasGo`) directly on `flowir.Body` during statement/sub-block/closure lowering, and pre-index any `FuncLit` inside `type` declarations or function signatures in `NewPkgCache` (without altering `DeclLowerCount` or `MissCount`), retiring duplicate AST `hasGoto` / `blockHasGoto*` walks across `propharness`, `dynstate`, `refconfine`, `capsule`, and `freshstruct`.
   - Promote `VarWriteInfo` (`VarWriteInfos`, `SingleWritePkgGlobalInit`, `SingleWriteLocalInit`, `VarHasExplicitWriteOrAddr`, `ForEachPlaceRootVar`, `ForEachValueRootVar`) onto `flowir.PkgCache` (`var_writes.go`), retiring the duplicate scanner in `dynstate/flow_cache.go`.
   - Promote `PlaceEntersInterior`, `ValueMentionsVar`, `ValueMentionsVars`, `BodyMentionsVars`, `VisitAllOps`, `VisitSyncAndIIFEOps`, `ForEachIIFEReturnValue`, and `CollectBackingVars` into `internal/flowir` (`ops_walk.go` / `aliases.go`), deduplicating `isFreshStringSliceCopy` and `isRefHeaderForMem` onto `syntaxutil`.

4. **`internal/refconfine` Refactoring & Splitting (`<= ~1,050` LOC):**
   - Refactor `confine.go` (`2,410` LOC) from closure soup inside `VerifyReadOnlyRefConfinement` into an explicit `flowir`-native `refConfinementSolver` split across `confine.go`, `confine_taint.go`, and `confine_check.go` (`<= ~850` LOC each).
   - Split `unsafe_layout.go` (`1,975` LOC) into `unsafe_layout_types.go`, `unsafe_capsule_decl.go`, and `unsafe_hazard.go` (`<= ~850` LOC each), extracting local-origin isomorphic-cast verification out of deeply nested inline closures.

## Soundness & Invariant Checks

- **Zero `PkgCache` Miss Invariant:** `internal/dynstate/flowir_unification_test.go` asserts `fc.declLowerCount == wantDeclLowers` (counting `FuncDecl` with non-nil `Body` + `VAR`/`CONST` `GenDecl`) and `fc.missCount == 0` across all `factOfWithCache` passes (including fuzzing). Pre-indexing `FuncLit`s in `type` `GenDecl`s and `FuncDecl.Type`/`Recv` inside `NewPkgCache` without incrementing `DeclLowerCount`, while using `syntaxutil.NodeHasGotoOrLabel` on un-indexed sub-statement nodes (`IfStmt` branches), preserves `declLowerCount` and `missCount == 0` universally.
- **Closure Boundary Semantics on `HasGoto`:** Go `goto` and labels cannot cross `*ast.FuncLit` boundaries, whereas `RangeStmt` bodies (`op.RangeBody`) belong to the enclosing function's own scope. `Body.HasGoto`, `HasLabel`, `HasFallthrough`, `HasLabeledBranch`, `HasDefer`, and `HasGo` track the body's own synchronous scope (including `RangeBody` sub-blocks, excluding child `FuncLit`s), while `Body.HasNestedGoto` (`Body.HasGotoAnywhere()`) tracks `goto` inside nested `FuncLit`s for callers (`CollectFreshLocalStructVars`, `PkgFreshConstructors`, `builder_sample`, `once_memo`) that rely on monotonic lexical `token.Pos` ordering across nested closures.
