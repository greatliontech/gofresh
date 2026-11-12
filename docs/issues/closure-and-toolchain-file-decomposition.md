# Cohesive Same-Package File Decompositions in `internal/closure` and `internal/closure/internal/toolchain`

- **Status:** Open
- **Governing contract:** [`docs/specs/closure.md`](../specs/closure.md) (`REQ-closure-analysis`, `REQ-closure-observability-toolchain-key`)
- **Lands:** Chunk 8 in [`docs/plans/plan.md`](../plans/plan.md)

## Problem

Seven files across `internal/closure` and `internal/closure/internal/toolchain` remain `1,538–2,480` lines long and bundle distinct, low-coupling analysis responsibilities into single files:

1. [`internal/closure/analyzer.go`](../../internal/closure/analyzer.go) (`2,480` lines): mixes `tier2Base` / `pkgIndex` / linkname & AST declaration indexing (`lines 1–809, 1603–1795, 2049–2295`), SSA function/instruction/call effect classification + `dispatchAdmitted` + `openFileFlags` (`lines 811–1435, 2297–2480`), and type-graph / unsafe-pointer / interface method-set walkers (`lines 1437–1601, 1796–2047`).
2. [`internal/closure/attribution_provenance.go`](../../internal/closure/attribution_provenance.go) (`2,136` lines): combines whole-program `callerReferenceSummary` enumeration (`lines 1–1552`) with per-subject RTA-masked `provenanceBFSWithCandidates` and carrier-free call/init-boxed helpers (`lines 1554–2136`).
3. [`internal/closure/observability.go`](../../internal/closure/observability.go) (`1,842` lines): embeds ~610 lines of `flag` / `FlagSet` registration & provenance analysis (`lines 1192–1801`) alongside core observability batch orchestration (`ComputeObservabilityBatch`, `lines 1–1191, 1803–1842`).
4. [`internal/closure/dynamic_walk.go`](../../internal/closure/dynamic_walk.go) (`1,645` lines): combines memo/seed/allocation/container confinement (`lines 1–1011`) with SSA value/call/builtin provenance rules (`valueProvenanceClosed`, `callReturnProvenanceClosed`, `ssaBuiltinClosed`, `lines 1012–1645`).
5. [`internal/closure/attribution_harness.go`](../../internal/closure/attribution_harness.go) (`1,601` lines): combines open-signature `subjectEnumerationClosure` & struct-field target analysis (`lines 17–869`), `testing` `Cleanup`/`Fuzz` callback extraction (`lines 871–1134, 1556–1601`), and rooted-provenance completeness / `reflect` / deserializer classifiers (`lines 1136–1554`).
6. [`internal/closure/internal/toolchain/audit_os_core.go`](../../internal/closure/internal/toolchain/audit_os_core.go) (`1,732` lines) and [`audit_testing_core.go`](../../internal/closure/internal/toolchain/audit_testing_core.go) (`1,538` lines): bundle top-level `os` boundary verifiers with `(*os.File)`/`(*os.file)` fd/write/close sink verifiers (`audit_os_core.go` line 704), and `testing` helper classifiers with `test.testlogfile` lifecycle pairing (`audit_testing_core.go` line 910).

## Resolution Scope

Decompose each file strictly within its existing package (`package closure` and `package toolchain`, keeping stipulator-bound `Hasher.ComputeObservabilityBatch` and `observableCallEffect` in `package closure`) along the responsibility boundaries above (`analyzer_effects.go`, `analyzer_types.go`, `attribution_summary.go`, `observability_flag.go`, `dynamic_provenance.go`, `attribution_open_closure.go`, `attribution_completeness.go`, `audit_os_file_sink.go`, `audit_testing_logfile.go`) after Chunks 1–6 semantic changes have landed and stabilized.
