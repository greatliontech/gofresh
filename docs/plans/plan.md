# Fleet Architecture Decomposition, Batching & Evaluation Plan

## Chunk 1: Unified Cross-Tool Diagnostic Tracing (`internal/trace`)
- [x] Wire zero-disabled-cost `internal/trace` (`GOFRESH_TRACE` / `GOFRESH_TRACE_FILE`) into `pew` (`v0.11.0`)
- [x] Wire zero-disabled-cost `internal/trace` (`GOFRESH_TRACE` / `GOFRESH_TRACE_FILE`) into `stipulator` (`v0.77.0`)
- [x] Wire zero-disabled-cost `internal/trace` (`GOFRESH_TRACE` / `GOFRESH_TRACE_FILE`) into `gomutant` (`v0.68.0`)

## Chunk 2: Decompose `gofresh/internal/closure` Leaf Verifiers ([`closure-leaf-verifiers-cprep-asmverify-propharness`](../issues/closure-leaf-verifiers-cprep-asmverify-propharness.md))
- [ ] Extract `internal/closure/internal/cprep` (deterministic C and Go-assembler `#include`/`#define`/`#if` preprocessor, unified `VerifyAssemblyPreprocessorPass`, `SkipQuotedLiteral`, `ExtractFileCgoPreambles`, and string/byte symbol scanners from `toolchain_cpreprocessor.go` and `cgo_includes.go`)
- [ ] Extract `internal/closure/internal/asmverify` (mechanical Plan 9 `.s` assembly parser, `RODATA`/`(SB)` discipline checker, and ISA instruction verifier from `asmverify.go`, sharing `cprep.VerifyAssemblyPreprocessorPass`)
- [ ] Extract `internal/closure/internal/propharness` (mechanical AST and `go/types` source verifier for `pgregory.net/rapid` from `propertyharness.go`, indexing `pkg.Syntax` once via `harnessPkgIndex`)
- [ ] Consolidate `extractLocalVariadicSliceElems` across `freshpath.go`, `observability.go`, and `propharness`, and replace `unwrapParens` / `unwrapASTParen` with `ast.Unparen`

## Chunk 3: Extract `gofresh/internal/closure/internal/toolchain` & Fix Reachability/Wrapper-Error Precision ([`closure-toolchain-extraction-and-monolith-splits`](../issues/closure-toolchain-extraction-and-monolith-splits.md), [`closure-reachability-provenance-and-wrapper-error-precision`](../issues/closure-reachability-provenance-and-wrapper-error-precision.md))
- [ ] Move `auditedLinknameTargets`, `auditedReadOnlyVarLinknameTargets`, and `ClassBPackages` into `internal/auditset`
- [ ] Extract `internal/closure/internal/toolchain` (`toolchain_loader.go`, `toolchain_scope.go`, `toolchain_index.go`, `toolchain_contracts.go`, `toolchain_audit_core.go`, `toolchain_audit_io.go`, `toolchainsource_*.go`), unifying directive scanners and `receiverBaseTypeName` and splitting `verifyOSPackageAST`, `verifyTestingPackageAST`, `verifyTimePackageAST`, `verifyReflectPackageAST`, and `verifySyncPackageAST`
- [ ] Thread `audited` and shared `freshParamAnalysis` (`callerReferenceSummary` + `dynamicMemos`) through `provenanceReachable` / `provenanceBFSWithCandidates` (`attribution.go`)
- [ ] Eliminate `std` `init` and carrier-free `std` static-call RTA mask contamination in `attribution.go` and `observability.go`
- [ ] Close wrapper-error method dispatch (`(*strconv.NumError).Error()`) from whole-program field stores in `freshpath.go`

## Chunk 4: Decompose `gofresh/internal/dynstate` Subpackages & Deduplicate AST/Index Passes ([`dynstate-syntaxutil-and-ast-helper-deduplication`](../issues/dynstate-syntaxutil-and-ast-helper-deduplication.md), [`dynstate-factof-redundant-ast-scans-and-monoliths`](../issues/dynstate-factof-redundant-ast-scans-and-monoliths.md))
- [ ] Extract `internal/dynstate/internal/syntaxutil` (shared data types, `PkgAnalysisIndex`, `CallSiteIndex`, and deduplicated AST/type/callee/place-spine/struct-walk/mutex helpers)
- [ ] Extract `internal/dynstate/internal/refconfine` (`refconfine.go` and `typecarrier.go`, decomposing `VerifyReadOnlyRefConfinement` into stage methods)
- [ ] Extract `internal/dynstate/internal/seams` (`func_summary.go` bracketed test-seam analyzer, decomposing `analyzeSeamCallGraph` and `analyzeBracketedSeams` into stage methods)
- [ ] Extract `internal/dynstate/internal/protoaudit` (`discharges_proto.go` protobuf, gRPC, and locked/once/atomic descriptor and memoizer verifiers, decomposing `verifyProtoDescBuilderType`)
- [ ] Extract `internal/dynstate/internal/freshstruct` (`discharges_proto.go` fresh local struct constructors, non-escaping parameter summaries, and mutex-confined constructor caches)
- [ ] Build `PkgAnalysisIndex` once per `FactOfWithHooks` (`facts.go`), decompose `recordDynamicGlobalUses` (`func_summary.go`) and `Compose` (`fixpoint.go`), and add `./internal/dynstate/internal/...` to `race:leaf` in `gofresh/.stipulator/policy.textproto`

## Chunk 5: Decompose `gomutant` God-Files & Batch Freshness/Oracle Checks ([`gomutant:decompose-god-files-and-batch-freshness-checks`](../../gomutant/docs/issues/decompose-god-files-and-batch-freshness-checks.md))
- [ ] Split `findings.go` (`findings_parse.go`, `findings_merge.go`), `run.go` (`run_prepare.go`, `run_window.go`, `run_aggregate.go`, decomposing `runCounted`), and `internal/mcpserver/server.go` (per-tool files matching `internal/cmd/`) while preserving all `.stipulator/bindings/` symbols
- [ ] Deduplicate `explain` domain logic (`ExplainSymbol` / `ExplainTriage`) between `internal/cmd/explain.go` and `internal/mcpserver`
- [ ] Share `runtimeMemo` and batch `CheckObservedBatch` / `CheckBatch` checks (with narrowed `Sibling` views per target package) in `freshness.go` and `run.go`
- [ ] Check cheap view-free pin predicates before `t.newSubjectViews` in `freshForContext` (`findings.go`) and batch `LinkedTestPackagesContext` in `OracleClosureSignpostContext` + include `NeedImports | NeedDeps` in `internal/engine/engine.go`

## Chunk 6: Redesign `Snapshot` / `Sibling` Observability Sharing, Downstream Efficiency & `go-x-tools` Fixes ([`view-sibling-observability-batching-and-validation-economy`](../issues/view-sibling-observability-batching-and-validation-economy.md), [`go-x-tools-startup-purity-and-determinism`](../issues/go-x-tools-startup-purity-and-determinism.md), [`stipulator:eliminate-redundant-gofresh-sessions-and-split-golang-backend`](../../stipulator/docs/issues/eliminate-redundant-gofresh-sessions-and-split-golang-backend.md), [`pew:ab-memoization-and-cli-helper-deduplication`](../../pew/docs/issues/ab-memoization-and-cli-helper-deduplication.md))
- [ ] Eliminate startup `os.Getenv("GOPACKAGESDEBUG")`, `reflect.TypeFor` on concrete types, startup `tRune` global, and startup `maphash.MakeSeed()` in `go-x-tools`
- [ ] Batch package-mates into `ComputeObservabilityBatch` and share verified `Observability` proofs across `Snapshot` and its `Sibling` `Unit`s in `gofresh/view.go`; eliminate duplicate `hasher.GraphMetadata`, reuse session `buildFlags` in `NewBracketAt`, share validation brackets in `Snapshot.Validate`, and deduplicate `OutcomeBinding` / `CompletedState` / `completeBuildEnvironment` work
- [ ] Eliminate the second full-repo `soloSession.Snapshot` reload in `stipulator/internal/backends/golang/native.go`, reuse opening captures/certificates in `served.go` (and check `len(subjects) == 0` before `selectionEngine`), deduplicate opening `declarationPackages` `go list` calls, scope `retryDrifted` to drifted packages, and split oversized `internal/backends/golang` files
- [ ] Switch `sideGuards` in `pew/cmd/pew/ab.go` to `preparationReader`, eliminate duplicate `sideGuards` and `abPackageMetadata` calls per package in `pew ab`, and deduplicate `run.HarnessCompleted` and `resolveExistingPrefix`

## Chunk 7: Execute 4-Repo Speed, Efficiency, Accuracy & Incremental Findings Protocol
- [ ] Run Stage 1 (`stipulator check` & `stipulator verify --no-test` Pass 1 cold/refresh and Pass 2 warm zero-edit re-run) across `pew`, `stipulator`, `gomutant`, and `gofresh`
- [ ] Run Stage 2 (`gomutant run` Pass 1 campaign, Pass 2 warm zero-edit `100%` serve, Pass 3 surgical inert + semantic edit delta) across `pew`, `stipulator`, `gomutant`, and `gofresh`
- [ ] Run Stage 3 (`pew status`, `pew run` under `mlock quiet`, and warm `pew verify`) across `pew`, `stipulator`, `gomutant`, and `gofresh`
- [ ] Run Stage 4 (fix any remaining performance bottlenecks or surviving mutants exposed by the protocol)
