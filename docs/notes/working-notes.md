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

### 3.3 Agreed Package Boundaries & Coupling Audit (2026-11-09)
- **User Alignment (2026-11-09)**:
  1. **Unified Tracing**: Approved & completed (Chunk 1).
  2. **Architecture & Decomposition Before Ad-Hoc Patching**: Approved. Stop reactive symptom patching; execute a structured package decomposition and `Snapshot`/`Sibling` batching redesign (`docs/plans/plan.md`) before running the 4-repo evaluation protocol.
  3. **Follow Natural, Low-Coupling Boundaries Only**: Approved. Note that `gofresh/.stipulator/policy.textproto` already routes `./internal/closure/internal/...` to the fast `race:leaf` invocation (`5m` budget), where `compartment`, `digest`, `listing`, `program`, and `rta` already live.

1. **`gofresh/internal/closure` (`48,600` lines → `~17,000` lines + 4 `internal/closure/internal/*` leaf packages — Chunks 2 & 3)**:
   - **`internal/closure/internal/cprep`** (`~2,570` lines from `toolchain_cpreprocessor.go` + `cgo_includes.go`):
     - Deterministic C and Go-assembler `#include`/`#define`/`#if` preprocessor and header-graph scanner.
     - Zero dependencies on `closure`, `ssa`, or `packages` (stdlib only). Shared by `asmverify`, `toolchain`, and `closure`.
   - **`internal/closure/internal/asmverify`** (`~3,300` lines from `asmverify.go`):
     - Mechanical Plan 9 `.s` assembly parser, `RODATA`/`(SB)` discipline checker, and ISA instruction verifier across `amd64`, `arm64`, `ppc64le`, `riscv64`, `s390x`, `loong64`.
     - Depends only on `go/types`, stdlib, and `internal/closure/internal/cprep`. Leaves `<200` lines of `tier2Base` / `tier2Analyzer` memo and linkname glue in `closure/asmverify.go`.
   - **`internal/closure/internal/propharness`** (`~4,700` lines from `propertyharness.go` lines 839–5355):
     - Mechanical AST and `go/types` source verifier for `pgregory.net/rapid` (`VerifyPackageWithReason(audited bool, pkg *packages.Package) (bool, string)`).
     - Depends only on `go/ast`, `go/constant`, `go/token`, `go/types`, `go-x-tools/go/packages`, `internal/auditset`, `internal/dynstate`. Leaves `~600` lines of SSA call-site boundary-gate checks in `closure/propertyharness.go`.
   - **`internal/closure/internal/toolchain`** (`~21,100` lines from `toolchain_loader.go`, `toolchain_scope.go`, `toolchain_index.go`, `toolchain_contracts.go`, `toolchain_audit_core.go`, `toolchain_audit_io.go`, `toolchainsource_*.go`):
     - Go toolchain `std`/`runtime` inventory loader, stamp-gated memo, AST scope/directive indexer, and structural stdlib/runtime purity verifiers.
     - Narrow interface back to `closure`: `ResolveSelection`, `ResolveToolchainSelection`, `SelectionDegradation`, `SourceDigests`, `AttributeSelection`.
2. **`gofresh/internal/dynstate` (`35,595` lines → `~13,500` lines + 4 `internal/dynstate/internal/*` leaf packages — Chunk 4)**:
   - **`internal/dynstate/internal/refconfine`** (`~2,800` lines from `refconfine.go` + `typecarrier.go`):
     - Mutable-reference and dynamic-carrier type predicates (`IsDirectMutableRef`, `TypeCarriesMutableRef`, `TypeContainsRefOrPointer`, `TypeMayCarryDynamic`, `IsDynamicCarrierType`) and `VerifyReadOnlyRefConfinement`.
     - Depends only on `go/ast`, `go/token`, `go/types`, `go-x-tools/go/packages`, `internal/auditset`. Re-exported thinly from `dynstate`.
   - **`internal/dynstate/internal/seams`** (`~6,350` lines from `func_summary.go` lines 279–6626):
     - Self-contained bracketed test-seam (`t.Cleanup` / `defer` global save-and-restore) call-graph and live-testing-handle analyzer (`AnalyzeBracketedSeams`). Cuts `func_summary.go` in half (`12,325` → `~5,975` lines).
   - **`internal/dynstate/internal/protoaudit`** (`~7,800` lines from `discharges_proto.go` lines 1388–9128):
     - Protobuf, gRPC, and locked/once/atomic descriptor and memoizer verifiers, split internally into `cluster.go`, `runtime.go`, `memoizer.go`, and `grpc.go`.
   - **`internal/dynstate/internal/freshstruct`** (`~4,900` lines from `discharges_proto.go` lines 9129–14063):
     - Fresh local struct constructors, non-escaping intra-procedural parameter summaries, and mutex-confined constructor caches.
   - Add `./internal/dynstate/internal/...` to `race:leaf` in `gofresh/.stipulator/policy.textproto`.
3. **`gomutant` Root Package (`~13.4k` lines — Chunk 5)**:
   - Extract internal findings codec/interning helpers and split `findings.go` (`3,306` lines) and `run.go` (`3,572` lines) along natural phase/responsibility boundaries while preserving all exported `package gomutant` types and `.stipulator/bindings/` symbols.

---

## 4. Architectural Bottleneck & Observability Diagnosis (2026-11-09)

1. **Completed Chunk 1 (`internal/trace` Across Fleet)**:
   - Wired `internal/trace` across `pew v0.11.0` (`6f17379`), `stipulator v0.77.0` (`490afde`), and `gomutant v0.68.0` (`6a6cab4`) with `0` allocations on the disabled fast path, carrier-free package-level state, and identical `GOFRESH_TRACE` / `GOFRESH_TRACE_FILE` wire format.
   - Verified cold-to-warm `stipulator verify --no-test` resolution-cache performance across all 3 downstream repos:
     - **`pew`**: Cold `48.1s` (`1` served, `309` resolved typed, peak `2.0 GiB`) → Warm `1.8s` (`310/310` served from records, `0` resolved typed, peak `112 MiB`).
     - **`stipulator`**: Cold `5m20.9s` (`0` served, `1153` resolved typed, peak `5.5 GiB`) → Warm `11.8s` (`1153/1153` served from records, `0` resolved typed, peak `325 MiB`).
     - **`gomutant`**: Cold `44.0s` (`0` served, `732` resolved typed, peak `1.1 GiB`) → Warm `2.3s` (`732/732` served from records, `0` resolved typed, peak `199 MiB`).
2. **Exact Mathematical Root Cause of the 32-Minute Solo-Test Stall (`Snapshot` / `Sibling` / `Unit` Lifecycle — Chunk 6)**:
   - `gofresh/view.go:1022` (`Sibling`) ALREADY inherits `observable[subject]` from its parent `Snapshot`, and `ensureObservable` (`view.go:1836-1843`) is a `0ms` no-op when `v.observable[subject]` is already populated.
   - However:
     1. In `stipulator/internal/backends/golang/native.go` (`captureNativeGeneration`), `stipulator` calls `CaptureBatch` (not `CaptureObservedBatch`), so the parent `Snapshot` and `solo` `Snapshot` have an empty `v.observable` map.
     2. When `prepareNativeAttempt` creates a 1-subject `Sibling` `Unit` for each of the $N \approx 150$ solo tests in `cmd/pew`, `u.view.ensureObservable` computes `observableComputed` and stores it **only** in the ephemeral child `Sibling`'s `v.observable` map — never sharing it back to the parent `Snapshot` — and runs a full `v.observe(ctx)` pass (`~4.5s` over `cmd/pew`'s 114-package dependency graph) per solo test.
     3. In `unit.Close(ctx)` → `u.view.Validate(ctx)` → `validateObserved(ctx)` (`view.go:1155-1164`), each solo `Unit` runs `v.newSeededValidationView(ctx)` (`v.observe(ctx)` #2) AND `current.ensureObservable(ctx, [solo])` (`v.observe(ctx)` #3).
     4. Total for 150 solo tests in one package: $150 \times 3 = 450$ full `observeView` passes $\times 4.5\text{s} \approx 33.75\text{ minutes}$.
   -Additionally, in `captureNativeGeneration` (`native.go:156-220`), `soloSession.Snapshot` (`SingleSubjectExecution`) captures all `438` `SharedDynamicStateCause` candidates across the repository even when `stipulator check --ids ...` is scoped to 1 requirement (`6` subjects).
3. **Correction on `auditset` vs. Policy Configuration**:
   - Per `docs/specs/closure.md:1597,1725` and `internal/auditset/auditset_test.go:73,76`, `math` runtime floating-point functions (`NaN`, `Inf`, `Pow`) and `reflect.TypeFor` are intentionally excluded from `auditset.go` (whereas `allowedPureMathSelectors` / `allowedPureReflectSelectors` in `toolchain_contracts.go` govern internal `std` pure-delegate verification only).
   - `gofresh` and `stipulator` set `assume_pure: true` in `.stipulator/policy.textproto` for witness execution, whereas `pew` and `gomutant` do not. We must never weaken `auditset` invariants (`REQ-closure-observability-audited-set` / `REQ-closure-observability-reflect-exclusion`).

---

## 5. Comprehensive 5-Repository Audit & Single-Pass Issue Schedule (2026-11-09)

To ensure every package refactoring chunk folds in its structural decomposition, deduplication, efficiency, and precision fixes in a **single pass** (rather than moving code blindly and doing a 2nd/3rd/Nth pass), three independent audits were completed across `gofresh` (`internal/closure`, `internal/dynstate`, root `package gofresh`), `go-x-tools`, `pew`, `stipulator`, and `gomutant`, and all findings were filed as tracked `docs/issues/*.md` items with concrete `Lands: Chunk N` slots in [`docs/plans/plan.md`](../plans/plan.md):

1. **Chunk 2 (`gofresh/internal/closure` Leaf Verifiers)**:
   - [`closure-leaf-verifiers-cprep-asmverify-propharness.md`](../issues/closure-leaf-verifiers-cprep-asmverify-propharness.md):
     - Extract `internal/closure/internal/cprep`, `internal/closure/internal/asmverify`, and `internal/closure/internal/propharness`.
     - Deduplicate the two 200-line assembly preprocessor passes (`verifyAssemblyFileSinglePass` vs `verifyNonStdAsmPreprocessorPass`), 3 Cgo preamble extractors, 14+ open-coded quoted-literal skippers, `[]byte` vs `string` symbol scanners, 4 variadic slice-over-local-alloc SSA extractors (`extractLocalVariadicSliceElems`), `unwrapParens`/`unwrapASTParen` (`ast.Unparen`), and 8 repeated `ast.Inspect` passes in `propertyharness.go` (`harnessPkgIndex`).
2. **Chunk 3 (`gofresh/internal/closure/internal/toolchain` & Reachability/Wrapper-Error Precision)**:
   - [`closure-toolchain-extraction-and-monolith-splits.md`](../issues/closure-toolchain-extraction-and-monolith-splits.md):
     - Move `auditedLinknameTargets`, `auditedReadOnlyVarLinknameTargets`, and `ClassBPackages` into `internal/auditset`.
     - Extract `internal/closure/internal/toolchain` (`~23.2k` lines), unify directive scanners and `receiverBaseTypeName`, and decompose `verifyOSPackageAST` (`1,622` lines), `verifyTestingPackageAST` (`1,348` lines), `verifyTimePackageAST` (`1,056` lines), `verifyReflectPackageAST` (`950` lines), and `verifySyncPackageAST` (`838` lines).
   - [`closure-reachability-provenance-and-wrapper-error-precision.md`](../issues/closure-reachability-provenance-and-wrapper-error-precision.md):
     - Fix `provenanceReachable` / `provenanceReachableWithCandidates` (`attribution.go:3709, 3714`) hardcoding `audited = false` and `provenanceBFSWithCandidates` (`attribution.go:4018`) allocating a throwaway `freshParamAnalysis` with `summary: nil` and `dynamicMemos: nil` on every dynamic call site in the BFS.
     - Eliminate `std` `init` root traversal into non-standard functions (`attribution.go:3717-3779, 4041`), cut static calls to carrier-free audited pure `std` functions with carrier-free arguments (`attribution.go:3990-4015`), filter `startupTargets` by provenance-pruned `startupFns` (`attribution.go:573, 670`), skip `std` functions in `userTouchedStdGlobals` (`attribution.go:718`), and stop seeding `computeRTAAsyncStartupFunctions` from internal `std` dynamic dispatches (`observability.go:1991`).
     - Close wrapper-error method dispatch (`(*strconv.NumError).Error()` in `freshpath.go:4492`) from whole-program field stores on `fp.summary`.
3. **Chunk 4 (`gofresh/internal/dynstate` Subpackages & AST/Index Deduplication)**:
   - [`dynstate-syntaxutil-and-ast-helper-deduplication.md`](../issues/dynstate-syntaxutil-and-ast-helper-deduplication.md):
     - Extract `internal/dynstate/internal/syntaxutil` shared leaf package and eliminate 70+ `unparenExpr` calls (`ast.Unparen`), 7 duplicate identifier object resolvers, 8 named-type predicates, 3 builtin call resolvers, 6 callee unwrappers, 7 place-spine extractors, duplicated struct-deref/selection-hop walkers, 14+ recursive type switches, and 4 mutex lock/unlock matchers.
   - [`dynstate-factof-redundant-ast-scans-and-monoliths.md`](../issues/dynstate-factof-redundant-ast-scans-and-monoliths.md):
     - Build a single `PkgAnalysisIndex` once at the start of `FactOfWithHooks` (eliminating 5x `directCallSites`, 2x `initOnlyReachableHelpers`, 2x `findMutexConfinedConstructorCaches`, and per-var `funcValueTaken` / `computeLocalFreshContainers` AST scans) and decompose the 7 `dynstate` monolithic functions (`analyzeSeamCallGraph`, `VerifyReadOnlyRefConfinement`, `analyzeBracketedSeams`, `recordDynamicGlobalUses`, `Compose`, `returnEnvFreeFunctions`, `verifyProtoDescBuilderType`) across `refconfine`, `seams`, `protoaudit`, `freshstruct`, and `dynstate`.
4. **Chunk 5 (`gomutant` God-File Decomposition & Freshness/Oracle Batching)**:
   - [`gomutant:decompose-god-files-and-batch-freshness-checks.md`](../../gomutant/docs/issues/decompose-god-files-and-batch-freshness-checks.md):
     - Split `findings.go` (`3,306` lines), `run.go` (`3,572` lines, decomposing the 2,700-line `runCounted`), and `internal/mcpserver/server.go` (`2,413` lines) along phase/tool boundaries while preserving all `.stipulator/bindings/` symbols.
     - Deduplicate CLI/MCP `explain` domain logic (`ExplainSymbol` / `ExplainTriage`).
     - Share `runtimeMemo` and batch `CheckObservedBatch` / `CheckBatch` checks (with narrowed `Sibling` views per target package) in `freshness.go` and `run.go` (eliminating $1100+$ full-module `observeView` reloads in `InspectFindings` / `opts.Posture`).
     - Check cheap view-free pin predicates before `t.newSubjectViews` in `freshForContext` and batch `LinkedTestPackagesContext` in `OracleClosureSignpostContext` + include `NeedImports | NeedDeps` in `internal/engine/engine.go`.
5. **Chunk 6 (`Snapshot`/`Sibling` Batching, `stipulator` & `pew` Efficiency, and `go-x-tools` Startup Purity)**:
   - [`go-x-tools-startup-purity-and-determinism.md`](../issues/go-x-tools-startup-purity-and-determinism.md):
     - Remove package-init `os.Getenv("GOPACKAGESDEBUG")` in `go/packages/golist.go:29`, replace `reflect.TypeFor` on concrete types with `reflect.TypeOf` in `go/ast/edge/edge.go:185` and `go/ssa/ssa.go:1629, 1633`, convert `tRune` in `go/ssa/builder.go:95` to a function, and replace startup `maphash.MakeSeed()` in `go/types/typeutil/map.go:375` with deterministic `hashString`.
   - [`view-sibling-observability-batching-and-validation-economy.md`](../issues/view-sibling-observability-batching-and-validation-economy.md):
     - Batch package-mates into `ComputeObservabilityBatch` (up to 64 subjects per SSA build) and publish verified `Observability` proofs back to the parent `Snapshot` after `ensureObservable`'s closing `v.observe(ctx)` succeeds; pass `meta` from `scanViewSubjectsWithMemo` to `deriveViewDynamicState`; reuse session `buildFlags` in `NewBracketAt`; share validation brackets in `Snapshot.Validate`; and deduplicate `OutcomeBinding` / `CompletedState` / `completeBuildEnvironment` work.
   - [`stipulator:eliminate-redundant-gofresh-sessions-and-split-golang-backend.md`](../../stipulator/docs/issues/eliminate-redundant-gofresh-sessions-and-split-golang-backend.md):
     - Eliminate the second full-repo `soloSession.Snapshot` reload in `captureNativeGeneration`, reuse opening captures/certificates between `NewServed` and `openingCapture` (and check `len(subjects) == 0` before `selectionEngine`), deduplicate opening `declarationPackages` `go list` calls, scope `retryDrifted` to drifted packages, and split oversized `internal/backends/golang` files.
   - [`pew:ab-memoization-and-cli-helper-deduplication.md`](../../pew/docs/issues/ab-memoization-and-cli-helper-deduplication.md):
     - Switch `sideGuards` in `cmd/pew/ab.go` to `preparationReader`, eliminate duplicate `sideGuards` and `abPackageMetadata` calls per package in `pew ab`, and deduplicate `run.HarnessCompleted` and `resolveExistingPrefix`.






