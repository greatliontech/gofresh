# Chunk 12 Working Notes: `internal/closure` Bottom-Up Consolidation, `sinkOnly` Deletion, Stream/Closure/AST Parameterization & Cohesive File Decomposition

## 1. Scope & Governing Contracts (`docs/plans/plan.md:57-61`)

1. **Part 1 — Unified Workspace/Module/Listing Collector & Shared View-Load Classifiers**:
   - Update `REQ-closure-listing-memo` in `docs/specs/closure.md` (re-pinning `.stipulator/bindings/closure.textproto`).
   - Unify `(*Hasher).moduleGraphInputs` (`dynamicstate.go`) and `(*Hasher).listingInputs` (`listingmemo.go`) in `internal/closure/module_inputs.go`:
     - Record existing intermediate `go.mod` files between `dir` and the outermost containing `mainDir` in `rec.Files` (with `go.sum`, `vendor/modules.txt`, and recursive local `replace`s) rather than blindly adding them to `rec.Absent`.
     - Verify `os.Lstat` reports `os.IsNotExist` before recording a path in `rec.Absent` (failing closed on dangling symlinks where `os.ReadFile` returns `IsNotExist` while `os.Lstat` succeeds).
     - Recurse transitively across local `replace` targets in both `go.mod` and `go.work`, consult `GOMOD`, preserve `IsGeneratedTestMainFor(pkgPath)` and `listing-unmodelled` diagnostics, and bump `listingRecordVersion` (`3 -> 4`).
   - Share `LoadedPackageDirs`, `ClassifyLoadedPackage`, `LoadedListingID`, and `IsGeneratedTestMainPackage` in `internal/closure/viewload.go` across `closure`, `scan.go`, and `explain.go`, routing `ExplainDynamicState` through `closure.LoadViewGraph` (`deps = true` so `packages.Visit` retains `Syntax`/`TypesInfo` on imported packages).
   - Retire `docs/issues/listing-memo-nested-workspace-absent-gomod.md`.

2. **Part 2 — Directive, Global, Startup-BFS & SSA-Confinement Unification**:
   - `directives_and_types.go`:
     - Unify `parseGoLinknameDirectiveComment` / `forEachGoLinknameDirective` across `analyzer_index.go`, `analyzer_declkeys.go`, `program_globals.go`, and `maximal.go` (fixing `/*go:linkname*/` / `/*go:linknamestd*/` block-comment bypass and leading-space prose misparsing while preserving raw-text fail-closed floor behavior on string literals in `auditedLinknamesWithLocals`).
     - Unify parameterized `typeUsesUnsafePointerWith` across `analyzer_declkeys.go`, `analyzer.go`, and `attribution_harness.go`.
     - Centralize `functionSymbolName` and `baseFunctionSymbolName` (eliminating 9 inline `$bound`/`$thunk` trimmers).
   - `program_globals.go` (retiring `sentinel_globals.go`):
     - Fold `nonReadOnlySSAGlobals` into `enumerateCallerReferencesWithOrdered` (`wholeProgram bool` + non-nil `nonReadOnlyGlobals`, `mutatedGlobals`, `errorNewSentinelGlobals`, `zeroCandidateGlobals`) and share one `classifyGlobalOperand` / `scanProgramGlobals` across `nonReadOnlySSAGlobals`, `mutatedGlobalsForProgram` (rejecting self-referencing `g = &g`), `verifiedUserSentinelGlobals` (fixing empty-map re-scan bug), `wholeZeroGlobalsForBase`, and `unmutatedZeroGlobalsForFunctions`.
   - `observability_startup.go`:
     - Delete `liveCalleeBlocks` (`callee_return.go`) in favor of `liveBlocks(callee, nil)` (extending `hasPrunableCond` fast-check to orphan unreachable blocks and negated short-circuit conditions).
     - Unify `asyncOrDynamicStartupFunctions` and `computeRTAAsyncStartupFunctions` onto `collectAsyncOrDynamicStartup`.
   - `ssa_confinement.go`:
     - Unify `cellOf` and `structElemCellOf` onto `resolveLocalCell` (+ `localAllocRoot`).
     - Move `forEachLocalSliceAllocStore` (always skipping `*ssa.DebugRef`) + `fixedVariadicArgs` + `variadicSliceElementsAll` + `peelVariadicCallArg` across all 7 variadic/slice callers.
     - Unify `valueOnlyReturnedOutsideTupleIndex`/`allocOnlyReturnedOutsideTupleIndex`, `paramFlowsOutsideContextValuePayload`/`allocFlowsOutsideContextValuePayload`, and `paramMaySupplyTupleDynamicSeen` onto `valueFlowsOutsideAllowedSinks` / `allocFlowsOutsideAllowedSinks` (fixing the `Return`/`MakeInterface` tuple-alloc drift and missing `alloc.Parent() == callee` guard).

3. **Part 3 — `sinkOnly` Deletion, `inMemoryStreamOperand`, Local `MakeClosure` Propagation, `go/parser` + `go/ast`, `-buildvcs` `ReadBuildInfo` Gate, Ladders & Cohesive Splits**:
   - Update `REQ-closure-observability-writer-sink`, `REQ-closure-observability-audited-set`, `REQ-closure-observability-dispatch`, `REQ-closure-coverage`, and `REQ-closure-view-maximal` in `docs/specs/closure.md` (re-pinning `.stipulator/bindings/closure.textproto`).
   - Delete `collect.sinkOnly` (`dynamic_walk.go` + `dynamic_closures.go`).
   - Propagate closed inline function arguments and fresh/stream parameters across non-escaping local `MakeClosure` call sites (`!fp.programValueRef[fn]`) in `freshparam.go`, `dispatch_targets.go`, and `attribution_summary.go` (preserving `summary.closures[fn]` whenever `!rawFuncEscaped[fn]`).
   - Implement parameterized `inMemoryStreamOperand` (`stream_sinks.go`):
     - `fmt.Fprint*` over `*bytes.Buffer`, `*strings.Builder`, unmutated `io.Discard`, carrier-free pure `hash.Hash` implementations (`!typeMayCarryDynamicTop`, plus `crypto/hmac` over closed pure hash factories), and alias-confined `*bufio.Writer` / `*text/tabwriter.Writer` whose construction and every `Reset`/`Init` rebind recursively target admitted in-memory writers (rejecting unverified interface escapes that could type-assert and `Reset`).
     - `fmt.Fscan*` over `*strings.Reader`, `*bytes.Reader`, `*bytes.Buffer`, and alias-confined `*bufio.Reader` over admitted in-memory readers (plus `fmt.Sscan*` in `fmtSymbols`, and `fmtFscanFamily` in `maximalObservabilityBlocker`).
     - `go/parser` (`ParseExpr` unconditionally; `ParseFile` and `ParseExprFrom` at Tier 2 when `src` is `MakeInterface`-rooted non-nil over `string`/`[]byte`/in-memory `io.Reader` and `mode & parser.Trace == 0`; `ParseDir` and `ast.Print` refused; `ast.Fprint` and `scanner.PrintError` writer-gated) + sealed `go/ast` node interfaces (`ast.Node`, `ast.Expr`, `ast.Stmt`, `ast.Decl`, `ast.Spec` admitted when concrete provenance closes or when binary-wide `MakeInterface`/RTA inspection proves zero non-`go/ast` implementations, defeating interface-embedding overrides of `Pos`/`End`), backed by structural toolchain verifiers for `text/tabwriter`, `go/token`, `go/scanner`, `go/ast`, `go/parser`, and `go/build/constraint`.
   - Wire `buildflags.EffectiveBuildVCS` + `go.mod` metadata gating `runtime/debug.ReadBuildInfo`:
     - Wire `toolchain.VerifyRuntimeDebugPackage` + `toolchain.VerifyRuntimeModinfoAST` into `toolchain_contracts_packages.go` / `toolchain_contracts_surface.go`.
     - Fold mutable-local `go.mod` / `go.sum` (and active `go.work` / `go.work.sum`) into `MaximalClosure` and `SourceFiles` when `"runtime/debug"` is in the package's transitive `pkgs` graph (`identityFoldStrategy` -> `gofresh/closure@2`, bumping `ClosureStrategy`).
     - Admit `ParseBuildInfo` and `(*BuildInfo).String` unconditionally under audited toolchain; gate `ReadBuildInfo` on verified `runtime/debug` + `runtime.modinfo`, folded `go.mod` metadata, and non-VCS `EffectiveBuildVCS` (`"false"` on `package main` at Tier 1; `"false"` or `"auto"` on `pkg.test` at Tier 2; refused under `"true"` or unparseable flags).
   - Unify the 4 standard/delegate callee admission ladders (`effects.go`), `walkDirectFlowEffects` (`observability.go`), and `walkPackageGraphEffects` (`maximal.go`).
   - Execute cohesive same-package file splits across `package closure` + `scan.go` keeping **every** non-test `.go` file `<= ~950` LOC (`<= 1,050` ceiling) and all 9 stipulator-bound symbols intact.
   - Bump `ObservationRTA`, `effectScanStrategy`, `ClosureStrategy`, `listingRecordVersion`, and `toolchainVerifierVersion`; retire `docs/issues/auditset-math-fmt-writer-and-asmverify-bt.md` and `docs/issues/closure-and-toolchain-file-decomposition.md`.

## 2. Key Soundness Invariants & Edge-Case Guards

1. **`ExplainDynamicState` Dependency Syntax Requirement**:
   - Must call `closure.LoadViewGraph` (`deps = true`), never `LoadViewPackages` (`deps = false`), so cross-package `packages.Visit` retains `Syntax` and `TypesInfo` on imported packages.
2. **Dangling Symlink vs Absent File in `module_inputs.go`**:
   - `os.ReadFile` follows symlinks and returns `os.IsNotExist` on dangling symlinks, whereas `MatchesDisk` and `loadListing` check `os.Lstat`. Only record a path in `absent` when `os.Lstat` also returns `os.IsNotExist`; fail closed otherwise.
3. **Wrapper `MakeInterface` Rebind Escape (`*bufio.Writer`, `*bufio.Reader`, `*tabwriter.Writer`)**:
   - Because arbitrary Go code receiving `io.Writer` can type-assert `w.(*bufio.Writer).Reset(os.Stdout)`, a boxed `MakeInterface` of a wrapper is confined only when every consumer of that interface value is the `fmt.Fprint*`/`fmt.Fscan*`/`parser.Parse*` sink itself, a recursively confined outer wrapper constructor/`Reset`/`Init`, a pure non-rebinding stdlib reader/writer (`io.ReadAll`, `io.Copy`), or a closed user parameter whose referrers are recursively confined.
4. **Pure `hash.Hash` vs `crypto/hmac` Dynamic Inner Hash**:
   - Admit concrete `hash.Hash` implementations from verified pure hash packages iff `!typeMayCarryDynamicTop(ct)` (automatically admitting `*sha256.Digest`, `*sha512.Digest`, `*md5.digest`, `*sha1.digest`, `*fnv.sum*`, `*adler32.digest`, `*crc32.digest`, `*crc64.digest` while excluding `*maphash.Hash`), plus `*hmac.HMAC` only when traced to `crypto/hmac.New` whose factory argument resolves exclusively to closed functions returning admitted pure `hash.Hash` types.
5. **`go/parser` Non-Nil `src` (`any`) & `parser.Trace == 0`**:
   - Converting a `nil` `io.Reader` to `any` via `ChangeInterface` produces `src == nil`, causing `readSource` to call `os.ReadFile(filename)`. Require every path reaching `src` to originate at `*ssa.MakeInterface` over `string`, `[]byte`, a non-`io.Reader` concrete type, or an `io.Reader` satisfying `inMemoryStreamOperand`, and require `mode` to provably exclude `parser.Trace` (`1 << 3`).
6. **`go/ast` Interface-Embedding Override Trap**:
   - Because an external struct `type EvilExpr struct { ast.Expr }` promotes `exprNode()` while overriding `Pos() token.Pos`, `go/ast` interface invokes (`ast.Node`, `ast.Expr`, `ast.Stmt`, `ast.Decl`, `ast.Spec`) and `ast.Inspect`/`ast.Walk` visitor parameters close via the `go/ast` node rule only when `!a.openWorld` and binary-wide `MakeInterface` / runtime-type inspection confirms zero non-`go/ast` concrete types implement that interface (otherwise ordinary `closedInvokeTargets` / open-world widening applies).

## 3. Integrated Implementation & Proactive Soundness Reconciliations

1. **`go/ast.Fprint` Refused Due to Reflection Dispatch & `FieldFilter` Callback (`internal/auditset/traits.go`, `docs/specs/closure.md`)**:
   - Inspecting `$GOROOT/src/go/ast/print.go:65, 223, 238` revealed that `ast.Fprint(w, fset, x, f)` walks `reflect.ValueOf(x)` across struct fields (`x.Field(i).Interface()`) and formats them via `fmt.Fprintf(p, "%v", v)` without SSA `*ssa.MakeInterface` edges (defeating RTA reachability of inner `String()` methods under `REQ-closure-observability-reflect-exclusion`), invokes `f(name, value)` dynamically, and iterates `reflect.MapKeys()` on `Scope.Objects`. Removed `"go/ast": {"Fprint"}` from `writerFirstExtraStdFuncs` so both `go/ast.Print` and `go/ast.Fprint` remain refused, while keeping reflection-free `go/scanner.PrintError(w, err)` writer-gated.
2. **`go/ast` `Ident.String` & `ObjKind.String` Receiver-Qualified Admission (`internal/auditset/traits.go`, `internal/closure/effects.go`)**:
   - Excluded bare `"String"` from `goASTSymbols` (because `CommentMap.String` and `Scope.String` format `%p` heap addresses and `Scope.String` iterates an unsorted `map[string]*Object`) and wired `auditset.ReceiverMethod(f, "go/ast", auditset.GoASTMethod)` in `auditedStandardMethod` (`effects.go`) to admit pure `Ident.String` and `ObjKind.String`.
3. **All Non-Test Production Files Verified `<= 960` LOC**:
   - Every production `.go` file across `internal/closure`, `internal/closure/internal/...`, `internal/buildflags`, `internal/auditset`, `scan.go`, `explain.go`, and `session.go` stays well under the `1,050` LOC ceiling.

## 4. Round 1 Adversarial Review Dispositions (`R1-F1..R1-F8`)

1. **`R1-F1` (`[HIGH]`, confirmed & fixed) — Non-deterministic `(*go/ast.Scope).String` and `(go/ast.CommentMap).String` via `fmt` / harness interface dispatch**:
   - *Diagnosis*: `Scope.String` and `CommentMap.String` format `%p` heap pointers and iterate `Scope.Objects` in randomized Go map order; when boxed into `any` (directly, inside a composite, or by widening an `ast.Node` carrying `*ast.File` via `*ssa.ChangeInterface`) and formatted inside `fmt` (`callerStd == true`), `!callerStd` bypassed `admittedPureStandardOrDelegateCallee`, and `walkDirectFlowEffects` skipped `std` frames in `init()` / `TestMain`. Conversely, RTA's stdlib scan visits dead `if debugResolve` inside `go/parser/resolver.go`, so checking non-stdlib `*ssa.MakeInterface` / `*ssa.ChangeInterface` (exempting `go/ast` traversal interfaces `Node`, `Expr`, `Stmt`, `Decl`, `Spec`, `Visitor`), `enumeratedTypes`/`initBoxedTypes`, and non-stdlib function-value references (`scanValue` + `walkDirectFlowEffects`) avoids false positives on `ast.Inspect`.
   - *Fix*: Added `(*tier2Analyzer).checkMakeInterfaceStdHooks` (`parser_and_ast.go`, emitting `closure.std_hook.reject`, invoked on non-stdlib `*ssa.MakeInterface` and `*ssa.ChangeInterface` in `scanInstruction` and `walkDirectFlowEffects` plus `enumeratedTypes`/`initBoxedTypes` in `tier2ReachableWithObjects`), added non-stdlib `go/ast.String` function-value checks in `scanValue` and `walkDirectFlowEffects`, and kept `forceCheckStdTarget` on `net/url`.
   - *Regression tests*: `TestFmtSprintASTScopeRejected`, `TestFmtSprintCompositeASTScopeRejected`, `TestTLogASTCommentMapRejected`, `TestFmtSprintWidenedASTNodeToAnyRejected`, and `TestAfterInitScopeFormat` (`stream_and_consolidation_test.go`).

2. **`R1-F2` (`[HIGH]`, confirmed & fixed) — `verifyWrapperRootConfined` alias escapes via `bufio` pass-throughs, outer wrapper delegation, tuple returns, and re-entrant returns**:
   - *Diagnosis*: `bufio.NewWriter*`/`NewReader*` return an existing `*bufio.Writer`/`*bufio.Reader` alias unchanged when buffer capacity suffices; `checkStdWrapperIfaceCall` did not enqueue `site.Value()` on constructor calls or `c.Args[0]` on `Reset`/`Init` or verify `c.Args[0]` on `ReadFrom`, `walkCallOrigin` did not forbid sibling tuple slots (`return bw, bw`), and `propagateUserCall` re-entry looked up `callStack[callee]` from the outer frame.
   - *Fix*: Extracted `stream_sinks_wrappers.go` (`verifyWrapperRootConfined`), tracked `wrapperCallFrame{resultVal, tupleIdx}` + `downwardSites`, rejected re-entrant `callStack[callee].resultVal != nil` downward calls, enforced exclusive `frame.tupleIdx` return slot membership, gated `addClosureCaptures` on `strictLocalFunc[fn]` + `downwardSites`, and enqueued/checked outer wrappers in `checkStdWrapperIfaceCall` and `checkStdWrapperPtrCall`.
   - *Regression tests*: `TestBufioReaderPassThroughNestedResetRejected`, `TestBufioReaderViaUnconfinedReadFromRejected`, `TestTupleReturningHelperSiblingResetRejected`, and `TestReentrantHelperReturnResetRejected` (`stream_and_consolidation_test.go`).

3. **`R1-F3` (`[HIGH]`, confirmed & fixed) — Cross-flow closure state smuggling via struct-stored `MakeClosure` in `localClosureSitesClosed`**:
   - *Diagnosis*: `resolveIndirectFuncSites` resolved struct-field (`*ssa.FieldAddr`) closure stores into `summary.sites[fn]` while leaving `summary.valueRef[fn] == false`, allowing `localClosureSitesClosed` to filter struct-field closures (`makeHolder()`) down to `fp.functions` and drop `TestMain` / sibling-test callers mutating shared `FreeVar` state.
   - *Fix*: Added `strictLocalFunc map[*ssa.Function]bool` on `callerReferenceSummary` (`attribution_summary.go`, forbidding `*ssa.FieldAddr` stores, `initFlowFrame` parents, and escaping outer `MakeClosure`s) and gated `localClosureSitesClosed` (`freshparam.go`) on `fp.summary.strictLocalFunc[fn]` (preserving frame-local closures inside helpers called both in `init()` and in subjects).
   - *Regression tests*: `TestVictimStructStoredClosure`, `TestVictimNonInitStructStoredClosure`, and `TestSharedHelperCalledInInitAndSubject` (`stream_and_consolidation_test.go`).

4. **`R1-F4` (`[HIGH]`, confirmed & fixed) — Sealed `go/ast` node interface bypass via composite types + `reflect`**:
   - *Diagnosis*: `goASTIfaceSealed` checked only top-level `RuntimeTypes()` and `MakeInterface` operands, missing `[1]EvilNode` boxed into `reflect.TypeOf([1]EvilNode{}).Elem()` followed by `reflect.New` storing an `ast.Node` override into an open global.
   - *Fix*: Walked `walkTypeGraph(..., true, ...)` checking both `cur` and `types.NewPointer(cur)` (skipping `types.Invalid` SSA pseudo-types and emitting `closure.ast_sealed.reject` with the unsealing type provenance) across `RuntimeTypes()`, all package-scope `*types.TypeName` declarations in `AllPackages()`, all SSA instruction/operand types in `progOrderedFunctions`, and `enumeratedTypes`/`initBoxedTypes` (`parser_and_ast.go`), and tightened `REQ-closure-observability-dispatch` (`docs/specs/closure.md`).
   - *Regression test*: `TestVictimOpenGlobalNodePos` (`stream_and_consolidation_test.go`).

5. **`R1-F5` (`[HIGH]`, confirmed & fixed) — Tier-1 `auditedLinknamesWithLocals` block-comment `/*go:linkname ...*/` same-line bypass**:
   - *Diagnosis*: `auditedLinknamesWithLocals` sliced `/*go:linkname` to `'\n'` instead of the first `"*/"`, allowing `/*go:linkname evil*//* runtime.getAuxv*/` to parse as a 2-arg directive targeting `runtime.getAuxv`.
   - *Fix*: Rejected interior `"*/"` and non-identifier `fields[0]` (`!token.IsIdentifier(fields[0])`) in `parseGoLinknameDirectiveComment` (`directives_and_types.go`), and sliced block-comment directives to their closing `"*/"` (rejecting embedded `\r\n` and advancing past `"*/"` to scan any subsequent same-line directive) in `auditedLinknamesWithLocals` (`maximal.go`).
   - *Regression tests*: `block_same_line_split_bypass`, `non_identifier_local`, `TestSplitBlockLinkname`, updated `TestRapidGoLinknameDirectiveParserOracle`, and `FuzzParseGoLinknameDirectiveComment` (`stream_and_consolidation_test.go`).

6. **`R1-F6` (`[MEDIUM]`, confirmed & fixed) — `collectRuntimeDebugModMetadata` omitted `vendor/modules.txt`**:
   - *Diagnosis*: Under `-mod=vendor`, `cmd/go` populates `debug.ReadBuildInfo().Deps` replacement/module metadata from `<modDir>/vendor/modules.txt` and `<workDir>/vendor/modules.txt`.
   - *Fix*: Folded optional `vendor/modules.txt` per mutable-local module (`modvendor:`) and under active `GOWORK` (`goworkvendor:`) in `collectRuntimeDebugModMetadata` (`closure.go`) and updated `docs/specs/closure.md`.
   - *Regression test*: Step 7 in `TestRuntimeDebugReadBuildInfoBuildVCSAndGoModFold` (`stream_and_consolidation_test.go`).

7. **`R1-F7` (`[MEDIUM]`, confirmed & fixed) — GOROOT-mutation verification gaps in `VerifyGoTokenPackageAST` and `VerifyGoParserPackageAST`**:
   - *Diagnosis*: `typeUsesUnsafePointer` did not walk `tt.TypeArgs()` on `go/token.FileSet`; `VerifyGoTokenPackageAST` did not enforce a non-generic unexported-fields `FileSet` struct; `VerifyGoParserPackageAST` did not verify unaliased `readSource(_, src)` / `p.init(_, _, mode)` parameter forwarding in `ParseFile`/`ParseExprFrom`, sticky `firstIotaShift` on intermediate explicit consts, or `FuncLit` guard reset in `verifyTraceCallsGated`.
   - *Fix*: Walked `tt.TypeArgs()` on `FileSet` in `analyzer_index.go`, enforced non-generic unexported-fields `FileSet` and `*ast.TypeSpec` qualifiers in `audit_go_ast_parser.go`, and enforced unaliased `readSource`/`.init` forwarding, `firstIotaShift = false` reset, and `*ast.FuncLit` `guarded = false` reset in `audit_go_parser.go`.
   - *Regression tests*: `go_token_generic_fileset_rejected`, `go_token_exported_fileset_field_rejected`, `funclit_inside_if_trace_unguarded`, `parsefile_nil_readsource`, `parsefile_forced_trace_init`, `parsefile_readsource_alias`, and `trace_iota_broken_by_intermediate_const` (`kernel_and_verifiers_test.go`).

8. **`R1-F8` (`[LOW]`, confirmed & fixed) — `moduleGraphInputs` under symlinked `h.dir`**:
   - *Diagnosis*: When `h.dir` traversed a symlink while `GOMOD` resolved to the real path, `isDirWithin(dir, candidate)` failed and `requireMainModule: false` returned `ok = true` without recording intermediate `go.mod` sentinels.
   - *Fix*: Set `requireMainModule: true` in `moduleGraphInputs` (`dynamicstate.go`) and resolved `EvalSymlinks(dir)` in `collectModuleInputs` (`module_inputs.go`) so both logical and physical `go.work` and intermediate `go.mod` chains are recorded.
   - *Regression test*: Symlinked `h.dir` `SnapshotScanInputs` + mid-load `sub/go.mod` creation check in `TestCollectModuleInputsNestedWorkspaceTransitiveReplacesAndDanglingSymlink` (`memo_scope_test.go`).

## 5. Round 2 Adversarial Review Dispositions (`R2-F1..R2-F3`)

1. **`R2-F1` (`[HIGH]`, confirmed & fixed) — `checkMakeInterfaceStdHooks` bypasses via `ast.Visitor -> any` widening and `*ssa.TypeAssert` interface assertions**:
   - *Diagnosis*: `isGoASTTraversalInterfaceType` exempted boxing into `go/ast.Visitor` while `walkValueTypes` omitted `"Visitor"` from its `go/ast` named-type switch, and `scanInstruction` / `walkDirectFlowEffects` checked `*ssa.MakeInterface` and `*ssa.ChangeInterface` without checking `*ssa.TypeAssert` to an interface type (`n.(any)`).
   - *Fix*: Added `"Visitor"` to the `go/ast` named-type switch in `checkMakeInterfaceStdHooks` and extracted shared `(*tier2Analyzer).checkInstructionStdHooks` (`parser_and_ast.go`) covering `*ssa.MakeInterface`, `*ssa.ChangeInterface`, and interface-target `*ssa.TypeAssert` across `scanInstruction` (`analyzer.go`) and `walkDirectFlowEffects` (`observability.go`).
   - *Regression tests*: `TestFmtSprintWidenedASTVisitorRejected`, `TestFmtSprintTypeAssertedASTNodeRejected`, and concrete `*ast.GenDecl` type-assertion positive control (`stream_and_consolidation_test.go`).

2. **`R2-F2` (`[HIGH]`, confirmed & fixed) — Cross-scope `stdAlloc` / `MakeInterface` seed under-approximation on mutable/rebindable stdlib carrier structs & `rootedFunctionsStrategy` bump**:
   - *Diagnosis*: `walkDynamicValueUncached` (`case *ssa.Alloc:` and `case *ssa.MakeInterface:` `carriesInner`) treated stdlib heap allocations (`tabwriter.NewWriter`, `bufio.NewWriter*`/`NewReader*`/`NewScanner`, `io.LimitReader`) as closed leaves from constructor arguments alone even in cross-scope walks (`fp.enumOnly || fp.inFieldStore || fp.inProgramSites`), missing post-construction in-place `.Init`/`.Reset`/`.Split` or exported-field carrier mutations (`tw.Init(envWriter{}, ...)`, `lr.R = envReader{}`) in callers outside the subject's cone.
   - *Fix*: Added `isMutableStdCarrierAllocType` (`dynamic_walk.go`, detecting exported dynamic-carrying struct fields and exported `Init`/`Reset`/`Split` methods accepting dynamic-carrying parameters mechanically from `go/types`) to both `case *ssa.Alloc:` (`stdAlloc`) and `case *ssa.MakeInterface:` (`carriesInner`) when `fp.enumOnly || fp.inFieldStore || fp.inProgramSites`, and bumped `rootedFunctionsStrategy` (`16 -> 17` in `scope.go`).
   - *Regression test*: `TestSubjectEnumerationRebindableStdWrapperRefused` (`EmitTabwriter`, `Report.EmitMethod`, `EmitBufioWriter`, `EmitLimitedReader`, plus immutable `EmitSectionReader` positive control across `ComputeObservabilityBatch` and `ComputeRootedFunctions`).

3. **`R2-F3` (`[MEDIUM]`, confirmed & fixed) — Unbounded recursion on cyclic stream wrappers + cross-call `Phi` helper origin memoization**:
   - *Diagnosis*: `walkCallOrigin` and `verifyHMACNewCall` passed literal `1` rather than `curDepth+1` into recursive `inMemoryStreamValue` / `verifyWrapperRootConfined` calls, allowing loop-carried `Phi` wrappers (`w = bufio.NewWriter(w)`) and self-wrapping `hmac.New` factories to recurse unboundedly; additionally, `visited[cur]` in `verifyStatefulStreamOrigin` was shared across distinct `callBindings` frames (`Phi(idWriter(bwGood), idWriter(bwBad))`).
   - *Fix*: Threaded `curDepth+1` (`curDepth > 16` bound) across `walkOrigin`, `walkCallOrigin`, `verifyHMACNewCall`, `inMemoryStreamValue`, and `verifyWrapperRootConfined`, replaced unconditional `visited` cycle acceptance with DFS `inStack` cycle rejection (`"cyclic_stream_origin"`), and restricted `topMemo` to top-level frames (`len(curFP.callBindings) == 0 && len(curStack) == 0`).
   - *Regression tests*: `TestLoopWrappedBufioWriterRejected`, `TestRecursiveHMACFactoryRejected`, and `TestPhiSameHelperTwoBufioArgsRejected` (`stream_and_consolidation_test.go`).

## 6. Round 3 Adversarial Review Dispositions (`R3-F1`)

1. **`R3-F1` (`[HIGH]`, confirmed & fixed) — Generalize `isMutableStdCarrierAllocType` from `Init`/`Reset`/`Split` to exported API surface (`container/list`, `io.Pipe`, preserving `context.cancelCtx`)**:
   - *Diagnosis*: `isMutableStdCarrierAllocType` checked only `case "Init", "Reset", "Split":` and top-level fields, missing `(*container/list.List).PushBack(v any)` / `Front() *Element` and `(*io.PipeReader).CloseWithError(err error)`. Walking unexported fields unconditionally would falsely classify `context.cancelCtx` (`done atomic.Value`) as externally mutable; restricting recursion to the exported surface (exported fields on exported structs + same-package struct results of exported methods + exported methods accepting `typeMayCarryDynamicTop` parameters, excluding `WriteTo`, `ReadFrom`, `strings.WriteString`, and `context.Value`) matches Go package encapsulation.
   - *Fix*: Updated `isMutableStdCarrierAllocType` (`dynamic_walk.go`, `971` LOC) to walk exported fields and exported method signatures/results.
   - *Regression tests*: `TestSubjectEnumerationRebindableStdWrapperRefused` (`FormatListFront`, `FormatPipeErr`, `EmitNopCloser`) and `TestIsMutableStdCarrierAllocTypeStructuralMatrix` (`stream_and_consolidation_test.go`).




