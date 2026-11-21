# Chunk 3 Working Notes: Flatten `closure/internal/*` & Split Tier-1 `internal/closure` from Tier-2 `internal/observability`

## Scope & Target Architecture

1. **Eliminate All `internal/closure/internal/*` Subpackages:**
   - `internal/closure/internal/cprep` → `internal/cprep`
     - Reunite direct C/cgo comment & preamble unit tests (`TestCgoNativeFileHasRawString` from `cgo_scan_test.go` and `cprep` preamble cases from `cpreprocessor_test.go`) into `internal/cprep/cprep_test.go`.
     - Unexport internal-only lexer/macro helpers that have zero external callers outside `internal/cprep`.
   - `internal/closure/internal/asmverify` → `internal/asmverify`
     - Move `asmverify_external_test.go`'s pure `asmverify` property tests or keep SSA integration tests in `internal/observability`.
   - `internal/closure/internal/rta` → `internal/rta`
     - Deduplicate `isStdImportPathShape` onto `syntaxutil.IsStandardLibraryPkgPath`.
   - `internal/closure/internal/toolchain` → `internal/toolchain`
     - Reunite the 8 stranded toolchain files from `internal/closure` (`toolchainsource_ctimespec.go`, `toolchainsource_ctim.go`, `toolchainsource_other.go`, `toolchainsource_unix.go`, `toolchain_contracts_packages.go`, `toolchain_contracts_surface.go`, `toolchain_source_stamps.go`, `toolchain_source_digests.go`), `admissionPolicy` / `capturePolicyInputs` / `AnalyzingFrontend`, and `toolchainsource_hermetic_test.go` + `toolchain_multitoolchain_math_test.go`.
     - Unexport the ~75 internal AST/CFG/package-audit helpers that were previously exported only across the `closure` ↔ `closure/internal/toolchain` boundary.
     - Route `provenance.go` directly to `internal/toolchain` (`toolchain.AnalyzingFrontend`, `toolchain.ResolveSelection`).
   - `internal/closure/internal/program` → absorbed directly into `internal/observability` (`program.go` + `prepared_test.go`).

2. **Cross-Package Helper Deduplication:**
   - **Directives (`internal/cprep`):** Promote canonical Go compiler directive helpers (`ParseGoLinknameDirectiveComment`, `ForEachGoLinknameDirective`, `HasRawGoLinkname`, `CutGoLinknameLine`, `IsWasmImportComment`), retiring duplicated `BoundedToken(..., "//go:linkname", ...)` / `//go:linknamestd` / `go:wasmimport` scanners across `toolchain`, `closure`, and `observability`.
   - **Receiver & Stdlib Predicates (`internal/syntaxutil`):** Promote `RecvBaseTypeName(expr ast.Expr) string` (making `RecvTypeName(fd)` delegate to it) and `IsInternalStdPkgPath(pkgPath string) bool`, and tighten `IsStandardLibraryPkgPath` to reject `"C"`, retiring duplicates across `toolchain`, `rta`, and `observability`.
   - **`gotool.ListedPackage` & `packages.Package` Helpers (`internal/gotool`):** Add `SortedSourceFiles`, `HasNonHeaderNativeSource`, `HasCgoCallbackBlindspot`, and `HasNativeOrEmbed` on `gotool.ListedPackage`, and move `LoadedListingID`, `IsGeneratedTestMainPackage`, and `IsGeneratedTestMainPackageFor` from `closure/viewload.go` into `internal/gotool`.

3. **Principled Tier-1 (`internal/closure`) vs. Tier-2 (`internal/observability`) Split:**
   - **Tier-1 `internal/closure` (Zero `go/ssa`, `rta`, `asmverify`, `dynstate`, or `observability` imports):**
     - Owns `Hasher`, `Closure`, `MaximalFacts`, `Subject`, `AnalysisScope`, `ViewLoad`, `ComputeMaximalBatch`, `ComputeMaximalFactsBatch`, `TestVariantLedger`, `GraphMetadata`, `PackageScanKey`, `MutableFactKeys`, `WalkPackageGraphEffects` (accepting pure `PackageGraphFilter` data/predicates), persistent file/scan/fact-key memos, `SetMemoRoot`, and `PruneMemos`.
   - **Tier-2 `internal/observability` (Imports `closure`, `toolchain`, `rta`, `asmverify`, `propharness`, `refconfine`, `go/ssa`):**
     - Owns `Program`, `Prepared`, `Prepare`, `Load`, `FromPackages`, `Prover` (wrapping `*closure.Hasher` with SSA `progs`, `progErrs`, and `packageMates`), `Observability`, `ImmutableEnvironmentOutcomes`, `RootedFunctions`, `ComputeObservabilityBatch`, `ComputeRootedFunctions`, and `ComputeBinaryRootedFunctions`.
     - Replaces `Program.Summaries map[string]any` with strongly typed `programSummaries` fields and replaces `Program.ReadSource` closure callbacks with strongly typed `Source *closure.Hasher` + `SourceSnapshot map[string][]byte` fields on `Program`.
   - **Update `.stipulator/policy.textproto` & Static Bindings:**
     - Add `./internal/cprep`, `./internal/asmverify`, `./internal/rta`, `./internal/toolchain` to `race:leaf` and `./internal/observability` to `race:core`, removing `./internal/closure/internal/...`.
     - Retarget all moved production and witness test bindings via `stipulator retarget`, `stipulator compile`, `stipulator pin`, and `stipulator verify --no-test --view bindings` (`955/955` `current` and `resolved`).
