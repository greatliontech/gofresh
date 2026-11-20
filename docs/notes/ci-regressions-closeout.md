# CI Regressions Close-Out Working Notes

## Governing Contracts & Scope

- **Specs:**
  - `docs/specs/closure.md`:
    - `REQ-closure-observability-audited-set` (`go/token`, `go/scanner`, `go/ast`, `go/parser` checked derivations)
    - `REQ-closure-observability-toolchain-key` (`semantic-authority`, `implementation-dependencies`, `observation-premises` inactive runtime gates)
    - `REQ-closure-observability-property-harness` (first-principles `propharness` boundary gate & `StateMachine` method dispatch)
    - `REQ-closure-blindspot` (verified vs. unverified intra-package `TEXT` `CALL`s in non-toolchain `.s` assembly)
- **CI Failures Identified on `origin/main` (`44758646320` & `44758646479`):**
  1. `TestMultiToolchainSelectionAuditAndRuntimeDebug/usr_go` (`go1.26.11`): `go/parser` and `go/scanner` failed structural AST verification.
  2. `TestDstSelectionIsJudgedByContentNeverByTag` (`internal/closure/integration_test.go:1113`, non-short): `simoverlay with called runtime mutator: audited=true attribution=""`.
  3. `TestNonStandardAssemblyBlocksObservationProof/unverified-call` (`integration_view_test.go:8646`, non-short): `TEXT ·F(SB)` calling verified intra-package `TEXT ·Helper(SB)` (`RET`) evaluated `Observable=true` per `REQ-closure-blindspot`, while the outdated non-short subtest still asserted refusal.
  4. `TestRealGOMODCACHEPackagesMechanicalVerification/rapid@v1.3.0` (`internal/closure/observability_scan_test.go:3130`, non-short): `TestRealRapidStateMachineAndMake` refused with `property-harness argument is not locally closed in (*example.com/realrapid.cleanSM).Check`.

## Root-Cause Diagnoses

1. **Go 1.26 `go/internal/scannerhooks`, `go/scanner`, and `go/parser` (`audit_go_ast_parser.go`, `audit_go_parser.go`, `toolchain_contracts_packages.go`, `toolchain_contracts_surface.go`, `offsurface.go`)**:
   - In Go 1.26, `go/scanner` and `go/parser` share token string-end positions via `go/internal/scannerhooks` (`var StringEnd func(scanner any) token.Pos`), initialized once in `go/scanner`'s `func init() { scannerhooks.StringEnd = func(scanner any) token.Pos { return scanner.(*Scanner).stringEnd } }` and called read-only in `go/parser` (`scannerhooks.StringEnd(&p.scanner)`). (Go 1.27 replaced this with `(*scanner.Scanner).End()`.)
   - Soundness invariant: admitting `scannerhooks` in `go/scanner` and `go/parser` requires:
     - `go/internal/scannerhooks` added to `listedSurfaceMustHaveGoFiles` and `isGoOnlyVerifiedSurfacePkg` and verified via `VerifyGoScannerHooksPackageAST` (closed imports `{"go/token": true}`, zero functions/methods/init/types, sole zero-initialized `var StringEnd func(any) token.Pos`).
     - `VerifyGoScannerPackageAST` permits `"go/internal/scannerhooks"` import and at most one `func init()` whose sole statement assigns `scannerhooks.StringEnd = func(<p> any) token.Pos { return <p>.(*Scanner).<field> }`, forbidding all other `scannerhooks` references.
     - `VerifyGoParserPackageAST` permits `"go/internal/scannerhooks"` import and call-only `scannerhooks.StringEnd(...)` expressions (never assigned or address-taken).
     - Off-surface `std` packages (`go/*`) must not import `go/internal/scannerhooks` (otherwise an off-surface `std/go/*` `init()`, skipped by `startupInitFunctions`, could overwrite `scannerhooks.StringEnd`).

2. **Soundness & CI Fix in `DiscoverRuntimeInactiveGates` (`internal/closure/internal/toolchain/audit_runtime.go:653-683`)**:
   - `resolveMutatorTargets` recursively allowed unguarded intra-`runtime` callers `cs.caller -> mName`. Because `cmd/compile` synthesizes calls to unexported `runtime` functions (`concatstring2`, `selectgo`, `chanrecv1`, `makemap`, etc.) without `//go:linkname` or `.s` references, allowing unguarded intra-`runtime` callers is unsound (an unguarded call from a compiler-intrinsic runtime helper would add `"runtime.<helper>"` to `InactiveRuntimeGates`, which `pulledRuntimeTargets` never sees) and broke `TestDstSelectionIsJudgedByContentNeverByTag` (`func gofreshBootActivate() { gofreshSimEnable() }`).
   - Neither vanilla Go (`synctest`) nor `godst` (`dstActive`, `dstInSimBubble`, `dstFenceActive`) has any unguarded intra-`runtime` call to a gate mutator (`dstActivate` has zero intra-`runtime` callers; `dstSimBubble = bubble` is guarded by `if dstActive() && ...`).
   - Fix: require every intra-`runtime` direct call site `cs` of a mutator `mName` to be guarded by `nodeGuardedByProvenFalseIf(cs.caller, cs.call)`; reject unguarded intra-`runtime` calls. Update `TestDiscoverRuntimeInactiveGates` to assert that unguarded `outerEnableTrace() { enableTrace() }` disqualifies `runtime.traceActive` while `guardedEnable() { if flagActive() { enableTrace() } }` unions `flagActive`'s mutators.

3. **Non-Standard Assembly Intra-Package Call Test (`integration_view_test.go:8626-8648`)**:
   - Under `REQ-closure-blindspot` (lines 367–385), `TEXT ·F(SB)` calling linkname-free, Go-body-free intra-package `TEXT ·Helper(SB)` (`RET`) on `amd64`/`arm64` is mechanically verified pure (`Observable == true`, `RequiresSingleSubject == false`), whereas calling a Go-bodied intra-package function (`func Helper() {}`) from `TEXT ·F(SB)` via `CALL ·Helper(SB)` (or calling an external/unresolved `(SB)` symbol) is refused naming `"non-toolchain assembly"`.
   - Fix: split into `verified-intra-package-call` (positive control on `amd64`/`arm64`) and `unverified-call` (`func Helper() {}` Go-bodied callee called via `CALL ·Helper(SB)` in `view.s`, refused naming `"non-toolchain assembly"`).

4. **Real `rapid@v1.3.0` `StateMachine.Check` Handle Provenance (`internal/closure/propertyharness_gate.go`)**:
   - `GOFRESH_TRACE=closure:TestRealRapidStateMachineAndMake` emitted `closure.propharness.gate_reject` with `detail=harness_struct_param_dyncall:bad_thunkcall_caller:crypto/internal/fips140/sha3.newCShake:...` and `(*runtime.gcWork).putObjBatch`.
   - `gomutant ephemeral` probe `C6` proved that under `hasRecv == true` (`fn.Signature.Recv() != nil`) in `nonHarnessDynamicCallMayPassBadHandle`, the `csig.Params().Len() == fn.Signature.Params().Len()+1` method-expression thunk arm is unreachable dead code across all three Go SSA thunk forms (`createThunk` always sets `Signature.Recv() == nil`: concrete `T.M` thunks reject earlier at `user_static_site_plus_dyn_ref`, non-harness `Iface.M` thunks reject via their internal `c.IsInvoke()` + `!hasRecv` arm, and harness `HarnessIface.M` thunks reject as dynamic harness targets), while its untyped arity check falsely matched every 2-arg function pointer in RTA reachability.
   - Fix: delete the dead `csig.Params().Len() == fn.Signature.Params().Len()+1` arm under `hasRecv == true` (retaining `sigNoRecvIdentical` for bound-method closures and renaming the duplicate `target` trace attribute in `emitHarnessGateReject` to `callee`), bump `ObservationRTA` (`@83` -> `@84`) and `toolchainVerifierVersion` (`@20` -> `@21`), and add positive (`TestStateRunnerAlongsideUnrelated2ArgDynCall`) and negative (`TestStateRunnerMethodThunkWithNilHandle` via `slices.BinarySearchFunc` + `localStateComparator.Compare`) tests.

## Verification & Mutation Probes

- Dual-toolchain (`godst` + vanilla Go `1.27.4`) tests + cross-OS `go vet` (`linux`, `darwin`, `openbsd`, `windows`) + `stipulator compile` + `stipulator verify --no-test --view bindings`: `955/955` rows `current` and `resolved`.
- `7/7` targeted `gomutant ephemeral` probes (`C1`–`C7`) killed.

## Round 1 Independent Adversarial Review Dispositions (`04e50fd7-5aec-46a7-9bf7-0f03d04f7d94`)

1. **Finding 1 (`HIGH`, `introduced` / `adjacent` — confirmed, fixing):**
   - `indexPackageAST` (`index.go:134-136`) skipped `id.Name == "_"` without recording `var _ = <expr>` initializers, allowing side-effecting blank-var initializers (including `scannerhooks.StringEnd` mutation in `go/scanner` or `go/internal/scannerhooks` and `os.*` calls in `go/parser` / `go/ast`).
   - Fix: record `blankVarInits []ast.Expr` and `hasMultiReturnBlankVar bool` in `PackageASTIndex`; add `(idx *PackageASTIndex) VerifyBlankVarInitsPure(pkgName string) error` (admitting only basic literals, unshadowed `nil`/`true`/`false`, `(LocalType)(nil)` / `(*LocalType)(nil)` over unique local types, and zero-element `LocalType{}` / `&LocalType{}`) and enforce across `go/token`, `go/scanner`, `go/ast`, `go/parser`, `text/tabwriter`, `runtime/debug`, `math`, and `internal/testlog`; require zero blank-var initializers, `len(idx.pkgValueCounts) == 1`, and `"go/token"` file import in `VerifyGoScannerHooksPackageAST`; enforce `allNonSelPropIdentsIn(files, "scannerhooks", allowedScannerHooksIdents)` and unshadowed `Scanner` + `"go/token"` import in `VerifyGoScannerPackageAST`.
2. **Finding 2 (`HIGH`, `introduced` — confirmed, fixing):**
   - `verifyToolchainSurfaceAndDelegatesWithIO` skipped in-surface unverified `go/*` packages and `pureDelegates`, missed cross-stdlib `//go:linkname`/`.s`/`.syso`/`cgo` references to `go/internal/scannerhooks`, and failed open on unparseable off-surface `go/*` files when `needsInactiveGateCheck` was false.
   - Fix: reject `"go/internal/scannerhooks"` imports in `verifyPureCandidateWithIOAndSalt` and in `verifyListedPackageWithIOAndSalt` outside `{"go/internal/scannerhooks", "go/scanner", "go/parser"}`; rename `OffSurfaceVerdict.ImportsScannerHooks` to `TouchesScannerHooks` (`json:"touchesScannerHooks,omitempty"`) and set it fail-closed on `hasUnparseable`, header/macro-budget failure, `"go/internal/scannerhooks"` imports, Go directives (`/*go:`, malformed `//go:linkname`, `//go:cgo_` or linkname targets mentioning `scannerhooks`), `extAsm`/`seedCrossMap`, and `.syso`/`cgo` raw bytes (`go/internal/scannerhooks` or `go%2finternal%2fscannerhooks`); check `ExternalLinknamePulls` across all `surfaceVerdicts`/`delegateVerdicts` plus all off-surface `d.inventory` packages in deterministic sorted order, emitting `DomainToolchain` `scannerhooks_confinement_error` naming the culprit; bump `toolchainVerifierVersion` to `@22`.
3. **Finding 3 (`MEDIUM`, `introduced` — confirmed, fixing):**
   - `TestNonStandardAssemblyBlocksObservationProof` hardcoded `CALL ·Helper(SB)` in `verified-intra-package-call` and `unverified-call`, whereas `asmverify` requires `BL` on `arm64`, and had a stale doc comment.
   - Fix: emit `BL ·Helper(SB)` when `runtime.GOARCH == "arm64"` and `CALL ·Helper(SB)` otherwise in both subtests, and update the test doc comment.
4. **Finding 4 (`MEDIUM`, `introduced` — partially superseded by `047d43f` deletion of dead `sigThunkMatchesMethod`, trace-pinning half confirmed & fixing):**
   - Probe `C6` (run while Round 1 review was reading the pre-`047d43f` diff) proved `sigThunkMatchesMethod` under `hasRecv == true` was unreachable dead code in Go SSA (`047d43f` deleted it; harness-interface method-expression thunks reject at `analyzer.go:105-110` as dynamic harness targets and at `propertyHarnessClosedArgsForTarget` on direct static calls).
   - Fix: add `rec.ByName("closure.propharness.gate_reject")` assertion for `TestStateRunnerMethodThunkWithNilHandle` pinning the renamed `callee` field (`"(*example.com/propcheck.Context).Fatalf"`) and `detail` (`"bad_invoke_caller:"` + `"bad_dyncall_caller:"`), plus add `TestHarnessIfaceMethodThunkWithNilHandle` pinning dynamic harness-interface thunk refusal.
5. **Finding 5 (`LOW`, `introduced` — confirmed, fixing):**
   - Pass `idx` into `verifyGoParserScannerHooksCallOnly(idx, files)` so `scannerhooks.StringEnd(...)` is admitted only when `idx.hasFileImport(f, "go/internal/scannerhooks")` holds; add `VerifyGoScannerHooksPackageAST` + Go 1.26 seeds to `FuzzToolchainMathDebugAndKernelVerifiers` and conditionally check `go/internal/scannerhooks` in `TestGOROOTTabwriterAndSyntaxPackageVerifiers`.
