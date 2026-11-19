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
