# Comprehensive `gofresh` Phase, Subprocess, Cache & Verifier Tracing (`internal/trace`)

**Lands:** Chunks 6–7 in [`docs/plans/plan.md`](../plans/plan.md) (building on the `DomainDynstate`/`DomainRuntimeInput`/`DomainCache` additions, `cprep`/`asmverify`/`propharness` leaf-verifier trace events, `rta.analyze.done` trace events, and `closure` core/memo trace events landed in Chunks 2–5).

## Context & Current Blind Spots

`internal/trace` (`internal/trace/trace.go`) provides a zero-disabled-cost structured tracer (`activeCount.Load() <= 0` single-atomic-load fast path, carrier-free `envConfig`, `GOFRESH_TRACE` domain/target filtering, and `GOFRESH_TRACE_FILE` text/JSONL output), and Chunk 1 wired it into `pew`, `stipulator`, and `gomutant`.

Inside `gofresh` itself, however, only 19 `trace.Emit` calls exist across 4 files (`toolchain_loader.go`, `closure.go`, `view.go`, `session.go`), leaving major performance, cache-invalidation, and verdict-attribution blind spots across 6 internal layers:

1. **`internal/gotool`, `internal/closure/viewload.go`, and `internal/closure/internal/program` (0 trace events today)**:
   - Every external `go env` / `go list` / `go version` subprocess spawn (`gotool.Run`, `gotool.Env`, `gotool.CompleteEnv`, `gotool.ModuleRoot`) vs primed `WithPrimedGoEnv` / `WithPrimedModuleRoot` hits is invisible.
   - `viewload.LoadPackages` (`packages.Load` duration, pattern count, loaded package count, cold vs primed) and `program.Build` (SSA construction duration, package count, function count) emit no trace spans.
2. **`internal/cachefile`, `internal/closure/*memo.go`, and `view.go` `scanfacts` (partial)**:
   - `cachefile.Load` / `Store` / `Merge` / `pruneDirLocked` do not emit disk cache hit/miss, corrupted-entry drop, or byte-budget eviction events.
   - `internal/closure/memo.go` (`loadTier2Memo` / `saveTier2Memo`), `binarymemo.go`, `effectmemo.go`, and `view.go` (`loadScanFactsMemo` / `saveScanFactsMemo`) do not emit memo hit/miss or exact mismatch reasons (stamp mismatch, Go version/toolchain digest mismatch, compartment digest mismatch, or missing key).
3. **`internal/closure` Pipeline Phases & Leaf Verifiers (`rta`, `attribution`, `analyzer`, `maximal`, `propharness`, `asmverify`, `cprep`)**:
   - `closure.go` emits a single `observability.batch.done` summary event at the end of a batch, with zero visibility into where the batch spent its time or why a subject degraded:
     - `rta.Analyze` / `Analyzer.Extend` (`closure` domain, `rta.analyze.done`: roots, seeds, reachable functions, runtime types, reflection fallback, `elapsed_ms`).
     - `attribution.go` (`closure` domain, `attribution.batch.done` / `attribution.provenance.done`: startup functions, callback RTA extensions, provenance BFS visits, `elapsed_ms`).
     - `analyzer.go` & `freshpath.go` (`closure` domain, `tier2.subject.done`: verdict, impure target/reason, `elapsed_ms`).
     - `maximal.go` (`closure` domain, `maximal.subject.done`: external effect families, `elapsed_ms`).
     - Leaf verifiers (`propharness.verify.done`, `asmverify.package.done`, `cprep.verify.done`: package/file target, pass/fail verdict, rejection reason, `elapsed_ms`).
4. **`internal/dynstate` & Subpackages (`FactOf`, `Compose`, `refconfine`, `seams`, `protoaudit`, `freshstruct` — 0 trace events today)**:
   - Add `DomainDynstate Domain = "dynstate"` to `internal/trace`.
   - Emit `fact.package.done` (`target=<pkgPath>`, memo hit vs fresh AST scan, culprit count, discharge counts by family: `refconfine`, `seams`, `protoaudit`, `freshstruct`, `audited`, `elapsed_ms`).
   - Emit `compose.done` (fixpoint iterations, total packages, surviving dynamic-state culprits after reachability discharge, `elapsed_ms`).
5. **`internal/runtimeinput` & `internal/guard` (0 trace events today)**:
   - Add `DomainRuntimeInput Domain = "runtimeinput"` to `internal/trace`.
   - Emit `guard.capture.done` (`internal/guard`: platform/arch/CPU-feature/kernel digest summary, `elapsed_ms`).
   - Emit `bracket.capture.done` and `bracket.revalidate.done` (`internal/runtimeinput`: root count, drifted path count and first drifted path on concurrent mutation, `elapsed_ms`).
   - Emit `testlog.extract.done` (`FromTestLog`: total raw testlog operations, deduplicated file/dir/env entries, excluded/scratch-filtered entries, incomplete/refusal reason, `elapsed_ms`).
6. **Root `package gofresh` Lifecycle Phase Spans (`view.go`, `session.go`, `unit.go`)**:
   - `observeView` emits `view.observe.done` only at the end of a full pass without distinguishing Pass 1 (`scanViewSubjectsWithMemo` + `deriveViewDynamicState`) from Pass 2 (`ensureObservable` closure verification) or recording whether `Sibling` shared/published `Observability` back to its parent `Snapshot`.
   - `Unit.Register`, `Unit.Close`, and `Snapshot.Validate` should emit structured start/done spans with subject counts, bracket reuse, and validation outcome.

## Resolution

1. **Extend `internal/trace` (`internal/trace/trace.go` & `internal/trace/trace_test.go`)**:
   - Add `DomainDynstate ("dynstate")`, `DomainRuntimeInput ("runtimeinput")`, and `DomainCache ("cache")` to `internal/trace` and `parseFilter` (preserving all existing domains `toolchain`, `closure`, `view`, `session` and `all`/`*` matching).
   - Keep the disabled fast path at a single atomic load (`activeCount.Load() <= 0`) with zero allocations on disabled calls.
2. **Instrument Each Subsystem as Its Chunk Lands**:
   - **Chunk 2 (`cprep`, `asmverify`, `propharness`)**: Emit `cprep.verify.done`, `asmverify.package.done`, and `propharness.verify.done` under `DomainClosure` when `trace.Enabled`.
   - **Chunk 3 (`rta`)**: Emit `rta.analyze.done` under `DomainClosure`.
   - **Chunk 5 (`closure` core)**: Emit `attribution.batch.done`, `tier2.subject.done`, `maximal.subject.done`, `viewload.packages.done`, `program.build.done`, and `closure` memo hit/miss/reason events.
   - **Chunk 6 (`dynstate` & subpackages)**: Emit `fact.package.done` and `compose.done` under `DomainDynstate`.
   - **Chunk 7 (`view`, `session`, `runtimeinput`, `gotool`, `cachefile`, `guard`)**: Emit `gotool.exec.done` (with `primed` vs `spawned`), `cache.load` / `cache.store` / `cache.prune`, `guard.capture.done`, `bracket.capture.done` / `bracket.revalidate.done`, `testlog.extract.done`, and fine-grained `view.observe.pass1.done` / `view.ensure_observable.done` / `unit.close.done` / `view.validate.done` spans.
   - Add unit tests in `internal/trace/trace_test.go` and package tests verifying that `trace.WithSink` / `trace.WithFilteredSink` captures the new domains and events and that disabled tracing remains 0-alloc.
