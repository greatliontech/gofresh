# Cohesive Same-Package Consolidation & File Decompositions in `internal/closure`

- **Status:** Open
- **Governing contract:** [`docs/specs/closure.md`](../specs/closure.md) (`REQ-closure-analysis`, `REQ-closure-observability-toolchain-key`)
- **Lands:** Chunk 12 in [`docs/plans/plan.md`](../plans/plan.md)

## Problem

Multi-concern `1,660–2,480` line files in `internal/closure` combine overlapping walkers and distinct analysis responsibilities into single files:

1. [`internal/closure/analyzer.go`](../../internal/closure/analyzer.go), [`attribution_provenance.go`](../../internal/closure/attribution_provenance.go), [`maximal.go`](../../internal/closure/maximal.go), [`attribution_harness.go`](../../internal/closure/attribution_harness.go), [`observability.go`](../../internal/closure/observability.go), and [`dynamic_walk.go`](../../internal/closure/dynamic_walk.go): bundle package indexing, delegate/cgo bypass, whole-program global scans, `flag` provenance, `sinkOnly` branches, closure capture resolution, variadic/tuple local-alloc confinement, and AST/SSA effect ladders.

## Resolution Scope

1. **Chunk 12 (`package closure`)**: Deduplicate overlapping SSA, global, directive, variadic/tuple-alloc, stream-sink, and callee-effect walkers first (`module_inputs.go`, `directives_and_types.go`, `program_globals.go`, `ssa_confinement.go`, `dynamic_closures.go`, `stream_sinks.go`), and execute cohesive same-package splits (`attribution_carriers.go`, `attribution_stdlib_summaries.go`, `analyzer_index.go`, `analyzer_delegates_cgo.go`, `observability_flags.go`, `maximal_ast_scan.go`) keeping every file `<= ~1,050` LOC and all 9 stipulator-bound `package closure` symbols in place, retiring this issue at Chunk 12 close-out.
