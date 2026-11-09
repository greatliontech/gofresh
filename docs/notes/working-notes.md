# Working Notes: Fleet Evaluation, Incrementality & Architecture

## 1. Current Fleet Baseline (2026-11-09)

All 5 owned repositories are clean on `main`, green on GitHub Actions (`Next` + `CI` + `Release`), and installed locally against `gofresh v0.122.2`:

| Repository | Tag / Revision | Local Binary |
| :--- | :--- | :--- |
| `go-x-tools` | `5215c18e3` (`main`) | — |
| `gofresh` | `v0.122.2` (`2e2ee4ef659f4ff4b620ec9e792c278d398e7503`) | — |
| `pew` | `v0.10.3` (`3f543e8f85990e7f52c00707347c5d17f3dfd706`) | `/home/nikolas/.local/bin/pew` |
| `stipulator` | `v0.76.1` (`e4d5c3688dc3c1d5a0af44556744868ab6eab9be`) | `/home/nikolas/.local/bin/stipulator` |
| `gomutant` | `v0.67.2` (`1d2b1375d8ea80fb47b4b3bd15596d86ef17e636`) | `/home/nikolas/.local/bin/gomutant` & `/home/nikolas/go/bin/gomutant` |

### Recent Root-Cause Fixes Landed
1. **`go-x-tools` (`5215c18e3`)**: Eagerly unpack `*types.Named` (`t.Underlying()`) and `*types.Alias` (`types.Unalias(a)`) in `go/packages` immediately after `gcimporter.IImportShallow` finishes for a package, before closing `lp.done` and releasing dependent package typecheckers. Eliminates concurrent lazy `resolve()` races across shared imported types.
2. **`gofresh v0.122.2` (`2e2ee4e`)**:
   - Added nil-safe `underlyingType(t types.Type)` across `internal/dynstate` (`refconfine.go`, `discharges_audited.go`, `discharges_proto.go`, `func_summary.go`) and `internal/closure` (`propertyharness.go`) so `info.TypeOf(...)` returning `nil` (such as on constant-folded `unsafe.{Sizeof,Alignof,Offsetof}` calls where `go/types` omits `call.Fun` from `info.Types`) never panics.
   - Added `lookupBuiltin(info, fun)` in `internal/dynstate/refconfine.go` so package-qualified `unsafe.{Sizeof,Alignof,Offsetof}` calls are recognized alongside `len` and `cap` in `VerifyReadOnlyRefConfinement` and `callCallErasesSeedStruct`, while pointer-aliasing `unsafe` builtins (`unsafe.SliceData`, `unsafe.StringData`, `unsafe.Slice`, `unsafe.String`, `unsafe.Add`) remain rejected on protected references.
3. **`gomutant v0.67.2` (`1d2b137`)**:
   - Fixed cross-OS `GOOS=windows go vet -tags integration ./...` in `internal/engine/run.go`.
   - Fixed map-iteration order sensitivity in `TestMergeWholeFindingsPrunesAbsentSymbols` (`edits_test.go`).
   - Updated `TestOracleObservationBindsTheDeliveredMemoryEnvironment` (`internal/engine/outcome_test.go`) to verify the delivered `TMPDIR` on `deliveredEnv` while testing `GOMEMLIMIT` observation binding without conflicting with ambient `TMPDIR` ingest preservation.

---

## 2. Protocol: End-to-End Speed, Efficiency, Accuracy & Incremental Findings Evaluation

Target repositories (ordered smallest-to-largest): **`pew` → `stipulator` → `gomutant` → `gofresh`**.

### Stage 1: `stipulator` Speed, Cache Efficiency & Zero-Edit Incrementality
1. **Pass 1 (Cold / Stale Cache Refresh)**:
   - Run `stipulator check` and `stipulator verify --no-test` (under `unset ANTIGRAVITY_SOURCE_METADATA && ~/.local/bin/mlock run`).
   - Record per-phase wall-clock time (`compile`, `discovery`, `execution`, `verification`, `coverage`), resident/peak RSS, resolution-cache hit rate (`served from records` vs `resolved typed`), and witness-cache behavior (`served fresh`, `executed`, `uncacheable`, and any `WITNESS_CACHE_REFUSAL_*`).
2. **Pass 2 (Warm Zero-Edit Re-Run — Must-Have Incremental Contract)**:
   - Immediately re-run `stipulator check` with zero source edits.
   - **Contract**:
     - `0` typed resolutions recomputed (`100%` served from resolution cache).
     - `0` deterministic witnesses re-executed (only random-seeded property witnesses execute; `0` witness-cache refusals).
     - Sub-second / low-second discovery + verification latency.

### Stage 2: `gomutant` Full Campaign, Incremental Findings & Surgical Delta Verification
1. **Pass 1 (Populate Incremental Findings & Measure Campaign Throughput)**:
   - Run `gomutant run` (starting with scoped inventories in `.gomutant/*-targets.json` and expanding to package/repository campaigns).
   - Measure:
     - **Speed & Efficiency**: wall-clock time, mutants/sec, per-package mutant schema compilation vs overlay fallback rate, RTA oracle ordering short-circuits, baseline bank reuse, and peak RSS.
     - **Accuracy**: audit every `survived`, `killed`, `equivalent`, and `unverifiable` finding. Verify that pure/hermetic packages (such as `pew/internal/git`) finalize with verifiable runtime-input evidence and zero false refusals.
2. **Pass 2 (Warm Zero-Edit Re-Run — Must-Have Incremental Serve)**:
   - Run `gomutant status` and `gomutant run` immediately with zero edits.
   - **Contract**:
     - `100%` of findings served directly from `.gomutant/findings.json` (schema v17) with `0` oracle test spawns, `0` schema compilations, and `0` dropped/demoted/stale records.
3. **Pass 3 (Surgical Edit & Revert — Must-Have Incremental Delta)**:
   - Apply controlled single-function edits (reverted after verification):
     - **Inert edit** (comment/formatting): verify `gofresh` canonical/compartment digests keep the symbol's findings **100% fresh** (`0` re-executions).
     - **Semantic edit** to one function: verify `gomutant` invalidates and re-measures **only** the touched symbol/closure while serving all other symbols in `.gomutant/findings.json` untouched, and accurately flips the affected mutant verdict.

### Stage 3: `pew` Benchmark Freshness & Incrementality
1. Run `pew status` across `gofresh`, `pew`, `stipulator`, and `gomutant` to inspect which committed `benchmarks/` baselines moved after the `gofresh v0.122.2` upgrade.
2. Re-measure stale benchmarks under `mlock quiet`, then immediately run `pew status` and `pew verify` to confirm `100%` fresh serving (`0` stale) on warm re-check.

### Stage 4: Bottleneck & Survivor Fix Loop
1. **Speed / Efficiency**: Profile and fix any phase exhibiting redundant `go` tool spawns, unexpected cache invalidation, schema-compile blowup, or excessive RSS.
2. **Accuracy / Coverage**: For any genuine surviving mutant, strengthen tests to kill it or record a verified semantic equivalence; for any false `unverifiable` refusal on a pure/hermetic target, diagnose and fix the underlying analyzer from first principles.

---

## 3. Code Architecture Roadmap & Sequencing

### 3.1 Sequencing Decision (Before / While / After Protocol)
1. **Before running the full protocol — Unify & Extend Tracing (`trace`)**:
   - Expose `gofresh`'s zero-disabled-cost structured tracing (`github.com/greatliontech/gofresh/trace`, backed by `internal/trace`) so `pew`, `stipulator`, and `gomutant` emit structured phase and event spans into the same timeline/recorder as `gofresh`.
   - Running the evaluation protocol with unified tracing gives immediate causal visibility into every phase, cache hit/miss, `go` command spawn, schema compile, and closure/dynstate pass.
2. **During the protocol — Establish Golden Incremental Baselines**:
   - Populate `.gomutant/findings.json` (v17), `.stipulator/` caches, and `benchmarks/` baselines across `pew`, `stipulator`, `gomutant`, and `gofresh`, fixing any speed, efficiency, or accuracy defects uncovered by the trace-instrumented runs.
3. **After / Interleaved with Golden Baselines — Package Decomposition & Deduplication**:
   - Decompose oversized packages one bounded chunk at a time while using the newly populated incremental findings and `stipulator`/`pew` baselines as continuous regression guards.

### 3.2 Quantitative Size Audit (Non-Test `.go` Lines)
- **`gofresh` (`~84,000` non-test lines concentrated in 2 flat packages)**:
  - `internal/closure`: `~48,600` lines across 23 files (`toolchain_audit_io.go` 8,319; `toolchain_audit_core.go` 6,091; `propertyharness.go` 5,355; `freshpath.go` 5,090; `attribution.go` 4,104; `asmverify.go` 3,483; `toolchain_loader.go` 2,814; `analyzer.go` 2,745; `observability.go` 2,742; `toolchain_cpreprocessor.go` 2,107; `toolchain_contracts.go` 1,995; `maximal.go` 1,887; `closure.go` 1,083).
  - `internal/dynstate`: `~35,500` lines across 9 files (`discharges_proto.go` 14,063; `func_summary.go` 12,325; `discharges_audited.go` 3,051; `refconfine.go` 2,166; `fixpoint.go` 1,826; `facts.go` 1,330).
  - Root `package gofresh`: `view.go` (3,253), `session.go` (1,158).
- **`gomutant` (`~19,900` non-test lines)**:
  - Root `package gomutant`: `~13,400` lines (`run.go` 3,548; `findings.go` 3,306; `freshness.go` 1,911; `store.go` 1,456; `reconcile.go` 1,300; `gomutant.go` 1,006; `ephemeral.go` 962; `prepare.go` 931).
  - `internal/engine`: `run.go` (1,776), `buildset.go` (1,320), `schema.go` (990).
- **`stipulator`**:
  - Already modular across 33 `internal/*` packages; largest non-generated package is `internal/backends/golang` (`~8,585` lines across `execute.go` 1,894; `derive.go` 1,867; `golang.go` 1,769; `witnessrun.go` 1,683; `served.go` 1,372).
- **`pew`**:
  - Compact (`cmd/pew/run.go` 1,472; `internal/store/store.go` 1,047; `internal/compare/compare.go` 927).

### 3.3 Proposed Target Package Boundaries & User Alignment (2026-11-09)
- **User Alignment**:
  1. **Unified Tracing**: Approved. Wire structured tracing into `pew`, `stipulator`, and `gomutant` before running the evaluation protocol.
  2. **Natural Package Boundaries Only**: Approved. Follow natural, low-coupling boundaries (`asmverify`, `propharness`, `refconfine`, etc.); if a boundary is unclear or would force artificial coupling, do not force it.

1. **Cross-Tool Observability (`internal/trace` across `gofresh`, `pew`, `stipulator`, `gomutant`)**:
   - Because `gofresh` enforces a single-package public surface (`TestExportedSurfaceInventory` / `REQ-fresh-surface`) and `internal/gotool` in all 4 repos already strips `GOFRESH_TRACE` and `GOFRESH_TRACE_FILE` via `gotool.IsTraceEnvKey` (`REQ-fresh-trace-non-interference`), adding `internal/trace` to `pew`, `stipulator`, and `gomutant` (reading the same `GOFRESH_TRACE` and `GOFRESH_TRACE_FILE` env vars and emitting the identical JSONL/text schema) yields a **single interleaved trace stream** across both the downstream tool and `gofresh v0.122.2` without touching `gofresh`'s public surface.
   - Domains per tool:
     - **`pew`**: `select` (inventory & freshness), `execute` (`go test -bench` runs & profiles), `compare` (statistical analysis), `store` (artifact read/write).
     - **`stipulator`**: `compile` (spec/binding/pin load), `discover` (subject/witness discovery), `resolve` (resolution cache hit/miss & typed derivation), `witness` (witness cache hit/refusal & leg execution), `verify` (claim/pin/gap verification).
     - **`gomutant`**: `prepare` (target discovery & RTA oracle ordering), `schema` (per-package mutant schema compile & fallback), `oracle` (baseline bank hit/miss, `go test`/schema binary execution, runtime-input ingest), `reconcile` (freshness serve vs stale reason & findings merge).
2. **Decomposing `gofresh/internal/closure` (`~48.6k` lines → natural subpackages)**:
   - `internal/closure/internal/asmverify`: Mechanical `.s` assembly verifier (`asmverify.go`, `~3.5k` lines). Input: `go/types` package + `.s` file bytes.
   - `internal/closure/internal/propharness`: Mechanical property-testing harness verifier (`propertyharness.go`, `~5.4k` lines).
   - `internal/closure/internal/toolchain`: Toolchain stdlib/runtime loader, C preprocessor, scope/index, and stdlib/runtime purity audit (`toolchain_*.go`, `~23.1k` lines).
   - `internal/closure/internal/freshpath`: SSA freshness-path and impurity attribution (`freshpath.go`, `attribution.go`, `~9.2k` lines) — extract only if its coupling with `analyzer.go` / `observability.go` is clean; otherwise keep tightly coupled pass state together.
   - `internal/closure`: Coordinator (`closure.go`, `analyzer.go`, `observability.go`, `maximal.go`, `canonical.go`, `viewload.go`).
3. **Decomposing `gofresh/internal/dynstate` (`~35.5k` lines → natural subpackages)**:
   - `internal/dynstate/internal/refconfine`: Read-only reference and seed-struct confinement engine (`refconfine.go`, `~2.2k` lines).
   - `internal/dynstate/internal/protoaudit`: Protobuf generated-code and runtime descriptor/extension/enum verifiers (`discharges_proto.go`, `~14.1k` lines, split by descriptor/enum/extension/message domain).
   - `internal/dynstate/internal/funcsummary`: Per-function AST/SSA mutation, return-env, and parameter-leak summaries (`func_summary.go`, `~12.3k` lines) — extract if coupling with `facts.go` is narrow; otherwise split by file within `dynstate`.
   - `internal/dynstate`: Fact schema, audited stdlib discharges, and least-fixed-point graph solver (`facts.go`, `fixpoint.go`, `discharges_audited.go`, `typecarrier.go`).
4. **Decomposing `gomutant` Root Package (`~13.4k` lines)**:
   - Extract `internal/findings` (document v4–v17 schema, table interning, store lock/IO from `findings.go` + `store.go`) and `internal/reconcile` (freshness revalidation and incremental merge from `freshness.go` + `reconcile.go`) where boundaries with `Tree` are clean.
5. **Shared CLI / MCP / Process Utilities**:
   - Deduplicate `internal/{gotool,guidance,resident,toolversion,shortgates,shapecorpus,trace}` across `pew`, `stipulator`, `gomutant`.

---

## 4. Initial Bottleneck & Observability Diagnosis (2026-11-09)

1. **Premature Uninstrumented `stipulator check -C ../pew` Aborted**:
   - An uninstrumented `stipulator check -C ../pew` run spent `8m30.3s` in `discovery` (peak RSS `4.6 GiB`) and then stalled in `race: 11/12 packages` (`cmd/pew`) from `12m40s` to `44m24s` (`32+ minutes` on one package), while only `1/11` packages (`internal/guidance`) emitted a `persisted:` note.
2. **Code-Level Root Cause Identified in `stipulator` + `gofresh`**:
   - In `stipulator/internal/backends/golang/native.go` (`captureNativeGeneration`, lines 107–170), `stipulator` creates a group `Snapshot` over all 475 subjects and then a second `soloSession.Snapshot` (`SingleSubjectExecution`) over all subjects that had `SharedDynamicStateCause` under `PackageExecution`, calling `CaptureBatch` on both — but never pre-populating `observable` on the parent snapshots.
   - In `stipulator/internal/backends/golang/selection.go` (lines 158–263), every `solo` subject (`view.isSolo(s)`) and every `Fuzz*` subject mixed with `Test*` subjects in a package (e.g., `~150+` tests in `cmd/pew`) is placed into `plannedSolos[pkg]` and executed via `runNativePackage` in `inSlot`.
   - For **every single solo test** (`j = 0 .. N-1`):
     1. `prepareNativeAttempt` calls `binding.BeginPackage([]Subject{solo})` → `b.snapshot.Sibling([]Subject{solo})`. Because the parent snapshot's `observable` map is empty, each child `Sibling` starts with an empty `observable` map.
     2. `unit.Register` calls `u.view.prepareOutcomeSupport` → `u.view.ensureObservable(preparing, [solo])` (`gofresh/view.go:1823`), which runs `hasher.ComputeObservabilityBatch([solo])` **and** a full `after, err := v.observe(ctx)` pass (`go env -json` + `scanViewSubjects` + `ComputeMaximalFactsBatch`), storing the result only in the ephemeral child `v.observable`!
     3. After the test binary finishes, `afterSlot` calls `finishNativeRun(ctx, &units[i].solos[j])` → `a.unit.Close(ctx)` (`gofresh/unit.go:505`), which calls `u.view.Validate(ctx)` — running **another** full `v.observe(ctx)` pass per solo test!
   - Thus, a package with `150` solo tests triggers **300+ sequential `observeView` passes** (`~35 minutes`) instead of sharing batch observability and package-level validation!
3. **Immediate Action (Chunk 1)**:
   - Wire `internal/trace` across `pew`, `stipulator`, and `gomutant` (and add fine-grained timing spans in `stipulator/internal/backends/golang/{native.go,selection.go,nativeexecution.go,witnessrun.go}` so every group snapshot, solo execution, `unit.Register`, `unit.Close`, and `publishPackage` emits its exact `duration_ms` and refusal reason) before running any further protocol commands.


