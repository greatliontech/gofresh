# Cohesive Same-Package Consolidation & File Decompositions in `internal/closure` and `internal/closure/internal/toolchain`

- **Status:** Open
- **Governing contract:** [`docs/specs/closure.md`](../specs/closure.md) (`REQ-closure-analysis`, `REQ-closure-observability-toolchain-key`)
- **Lands:** Chunks 7, 12 in [`docs/plans/plan.md`](../plans/plan.md)

## Problem

Multi-concern `1,429–2,480` line files across `internal/closure` and `internal/closure/internal/toolchain` combine overlapping walkers and distinct analysis responsibilities into single files:

1. [`internal/closure/internal/toolchain/`](../../internal/closure/internal/toolchain) (`audit_testing_writer.go` `1,863` LOC, `audit_os_core.go` `1,732` LOC, `audit_os_getwd.go` `1,629` LOC, `audit_os_inactive_discover.go` `1,612` LOC, `audit_testing_core.go` `1,538` LOC, `audit_testing_wiring.go` `1,485` LOC) and [`internal/closure/toolchain_contracts_orchestrator.go`](../../internal/closure/toolchain_contracts_orchestrator.go) (`1,515` LOC) + [`toolchain_source_loader.go`](../../internal/closure/toolchain_source_loader.go) (`1,429` LOC): duplicate 5 lexical-scope/shadowing walkers, `os`-only inactive-branch discovery, custom writer verification, and 3 `pkg/include` + package-file reader loops.
2. [`internal/closure/analyzer.go`](../../internal/closure/analyzer.go) (`2,480` LOC), [`attribution_provenance.go`](../../internal/closure/attribution_provenance.go) (`2,118` LOC), [`maximal.go`](../../internal/closure/maximal.go) (`1,964` LOC), [`attribution_harness.go`](../../internal/closure/attribution_harness.go) (`1,872` LOC), [`observability.go`](../../internal/closure/observability.go) (`1,842` LOC), and [`dynamic_walk.go`](../../internal/closure/dynamic_walk.go) (`1,660` LOC): bundle package indexing, delegate/cgo bypass, whole-program global scans, `flag` provenance, `sinkOnly` branches, closure capture resolution, variadic/tuple local-alloc confinement, and AST/SSA effect ladders.

## Resolution Scope

1. **Chunk 7 (`package toolchain` & `closure/toolchain_*.go`)**: Collapse duplicate scope, inactive-gate, CFG, and byte-sink walkers onto `kernel_scope.go`, `kernel_inactive.go`, `kernel_cfg.go`, and `sink_verify.go` (deleting `audit_testing_writer.go`), deduplicate `readListedPackageFiles` in `closure/toolchain_*.go`, and split remaining `os`, `testing`, and `toolchain_*` files cleanly below `~900` LOC within their existing packages.
2. **Chunk 12 (`package closure`)**: Deduplicate overlapping SSA, global, directive, variadic/tuple-alloc, stream-sink, and callee-effect walkers first (`module_inputs.go`, `directives_and_types.go`, `program_globals.go`, `ssa_confinement.go`, `dynamic_closures.go`, `stream_sinks.go`), and execute cohesive same-package splits (`attribution_carriers.go`, `attribution_stdlib_summaries.go`, `analyzer_index.go`, `analyzer_delegates_cgo.go`, `observability_flags.go`, `maximal_ast_scan.go`) keeping every file `<= ~1,050` LOC and all 9 stipulator-bound `package closure` symbols in place, retiring this issue at Chunk 12 close-out.
