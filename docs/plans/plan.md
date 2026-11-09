# Fleet Architecture Decomposition, Batching & Evaluation Plan

## Chunk 1: Unified Cross-Tool Diagnostic Tracing (`internal/trace`)
- [x] Wire zero-disabled-cost `internal/trace` (`GOFRESH_TRACE` / `GOFRESH_TRACE_FILE`) into `pew` (`v0.11.0`)
- [x] Wire zero-disabled-cost `internal/trace` (`GOFRESH_TRACE` / `GOFRESH_TRACE_FILE`) into `stipulator` (`v0.77.0`)
- [x] Wire zero-disabled-cost `internal/trace` (`GOFRESH_TRACE` / `GOFRESH_TRACE_FILE`) into `gomutant` (`v0.68.0`)

## Chunk 2: Decompose `gofresh/internal/closure` Leaf Verifiers
- [ ] Extract `internal/closure/internal/cprep` (deterministic C and Go-assembler `#include`/`#define`/`#if` preprocessor and header-graph scanner from `toolchain_cpreprocessor.go` and `cgo_includes.go`)
- [ ] Extract `internal/closure/internal/asmverify` (mechanical Plan 9 `.s` assembly parser, `RODATA`/`(SB)` discipline checker, and ISA instruction verifier from `asmverify.go`)
- [ ] Extract `internal/closure/internal/propharness` (mechanical AST and `go/types` source verifier for `pgregory.net/rapid` from `propertyharness.go`)

## Chunk 3: Extract `gofresh/internal/closure/internal/toolchain`
- [ ] Move toolchain `std`/`runtime` inventory loader, stamp-gated memo, AST scope/directive indexer, and structural stdlib/runtime purity verifiers (`toolchain_loader.go`, `toolchain_scope.go`, `toolchain_index.go`, `toolchain_contracts.go`, `toolchain_audit_core.go`, `toolchain_audit_io.go`, `toolchainsource_*.go`) into `internal/closure/internal/toolchain`
- [ ] Keep thin `Hasher` delegation and `ResolveToolchainSelection` entry points in `internal/closure`

## Chunk 4: Decompose `gofresh/internal/dynstate` Subpackages
- [ ] Extract `internal/dynstate/internal/refconfine` (mutable-reference and dynamic-carrier type predicates and read-only reference confinement verifier from `refconfine.go` and `typecarrier.go`)
- [ ] Extract `internal/dynstate/internal/seams` (bracketed test-seam `t.Cleanup`/`defer` call-graph and live-testing-handle analyzer from `func_summary.go`)
- [ ] Extract `internal/dynstate/internal/protoaudit` (protobuf, gRPC, and locked/once/atomic descriptor and memoizer verifiers from `discharges_proto.go`)
- [ ] Extract `internal/dynstate/internal/freshstruct` (fresh local struct constructors, non-escaping intra-procedural parameter summaries, and mutex-confined constructor caches from `discharges_proto.go`)
- [ ] Update `gofresh/.stipulator/policy.textproto` `race:leaf` package patterns to include `./internal/dynstate/internal/...`

## Chunk 5: Decompose `gomutant` Root Package Along Natural Store & Reconcile Boundaries
- [ ] Split oversized `findings.go` (`3,306` lines) and `run.go` (`3,572` lines) along clean internal subpackage / file boundaries (`internal/findings` codec/interning helpers and focused campaign phase files) while preserving exported `package gomutant` types and `.stipulator/bindings/` symbols

## Chunk 6: Redesign `Snapshot` / `Sibling` Observability Sharing & `stipulator` Solo Scoping
- [ ] Share computed `Observability` dispositions across `Snapshot` and its `Sibling` views in `gofresh/view.go` so per-solo `Unit.Register` calls reuse package-batch observability without repeating `observeView`
- [ ] Scope `soloSession.Snapshot` (`SingleSubjectExecution`) in `stipulator/internal/backends/golang/native.go` to runnable/cached candidates needed by the active selection

## Chunk 7: Execute 4-Repo Speed, Efficiency, Accuracy & Incremental Findings Protocol
- [ ] Run Stage 1 (`stipulator check` & `stipulator verify --no-test` Pass 1 cold/refresh and Pass 2 warm zero-edit re-run) across `pew`, `stipulator`, `gomutant`, and `gofresh`
- [ ] Run Stage 2 (`gomutant run` Pass 1 campaign, Pass 2 warm zero-edit `100%` serve, Pass 3 surgical inert + semantic edit delta) across `pew`, `stipulator`, `gomutant`, and `gofresh`
- [ ] Run Stage 3 (`pew status`, `pew run` under `mlock quiet`, and warm `pew verify`) across `pew`, `stipulator`, `gomutant`, and `gofresh`
- [ ] Run Stage 4 (fix any remaining performance bottlenecks or surviving mutants exposed by the protocol)
