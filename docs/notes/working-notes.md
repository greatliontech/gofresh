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

1. **`gofresh/internal/closure` (`48,600` lines → `~17,000` lines + `rta` refactor + 4 new `internal/closure/internal/*` leaf packages — Chunks 2–5)**:
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
2. **`gofresh/internal/dynstate` (`35,595` lines → `~5,600` lines + 5 `internal/dynstate/internal/*` leaf packages — Chunk 6)**:
   - **`internal/dynstate/internal/syntaxutil`** (`~550` lines across `ast.go`, `types.go`, `fixpoint.go`):
     - Shared AST, `go/types`, place-spine, and fixed-point primitives.
   - **`internal/dynstate/internal/refconfine`** (`~1,650` lines from `refconfine.go` + `typecarrier.go` + unified protected-memo confinement):
     - Mutable-reference and dynamic-carrier type predicates (`IsDirectMutableRef`, `TypeCarriesMutableRef`, `TypeContainsRefOrPointer`, `TypeMayCarryDynamic`, `IsDynamicCarrierType`) and `VerifyReadOnlyRefConfinement`.
     - Depends only on `go/ast`, `go/token`, `go/types`, `go-x-tools/go/packages`, `internal/auditset`, and `syntaxutil`. Re-exported thinly from `dynstate`.
   - **`internal/dynstate/internal/seams`** (`~3,800` lines from `func_summary.go` lines 279–6626):
     - Self-contained bracketed test-seam (`t.Cleanup` / `defer` global save-and-restore) call-graph and live-testing-handle analyzer (`AnalyzeBracketedSeams`).
   - **`internal/dynstate/internal/protoaudit`** (`~5,800` lines from `discharges_proto.go` lines 1388–9128):
     - Protobuf, gRPC, and locked/once/atomic descriptor and memoizer verifiers, split across 8 focused files.
   - **`internal/dynstate/internal/freshstruct`** (`~2,400` lines from `discharges_proto.go` lines 9129–14063):
     - Fresh local struct constructors, non-escaping intra-procedural parameter summaries, and mutex-confined constructor caches.
   - Add `./internal/dynstate/internal/...` to `race:leaf` in `gofresh/.stipulator/policy.textproto`.
3. **`gomutant` Root Package (`~13.4k` lines — Chunk 8)**:
   - Extract internal findings codec/interning helpers and split `findings.go` (`3,306` lines) and `run.go` (`3,572` lines) along natural phase/responsibility boundaries while preserving all exported `package gomutant` types and `.stipulator/bindings/` symbols.

---

## 4. Architectural Bottleneck & Observability Diagnosis (2026-11-09)

1. **Completed Chunk 1 (`internal/trace` Across Fleet)**:
   - Wired `internal/trace` across `pew v0.11.0` (`6f17379`), `stipulator v0.77.0` (`490afde`), and `gomutant v0.68.0` (`6a6cab4`) with `0` allocations on the disabled fast path, carrier-free package-level state, and identical `GOFRESH_TRACE` / `GOFRESH_TRACE_FILE` wire format.
   - Verified cold-to-warm `stipulator verify --no-test` resolution-cache performance across all 3 downstream repos:
     - **`pew`**: Cold `48.1s` (`1` served, `309` resolved typed, peak `2.0 GiB`) → Warm `1.8s` (`310/310` served from records, `0` resolved typed, peak `112 MiB`).
     - **`stipulator`**: Cold `5m20.9s` (`0` served, `1153` resolved typed, peak `5.5 GiB`) → Warm `11.8s` (`1153/1153` served from records, `0` resolved typed, peak `325 MiB`).
     - **`gomutant`**: Cold `44.0s` (`0` served, `732` resolved typed, peak `1.1 GiB`) → Warm `2.3s` (`732/732` served from records, `0` resolved typed, peak `199 MiB`).
2. **Exact Mathematical Root Cause of the 32-Minute Solo-Test Stall (`Snapshot` / `Sibling` / `Unit` Lifecycle — Chunks 7 & 8)**:
   - `gofresh/view.go:1022` (`Sibling`) ALREADY inherits `observable[subject]` from its parent `Snapshot`, and `ensureObservable` (`view.go:1836-1843`) is a `0ms` no-op when `v.observable[subject]` is already populated.
   - However:
     1. In `stipulator/internal/backends/golang/native.go` (`captureNativeGeneration`), `stipulator` calls `CaptureBatch` (not `CaptureObservedBatch`), so the parent `Snapshot` and `solo` `Snapshot` have an empty `v.observable` map.
     2. When `prepareNativeAttempt` creates a 1-subject `Sibling` `Unit` for each of the $N \approx 150$ solo tests in `cmd/pew`, `u.view.ensureObservable` computes `observableComputed` and stores it **only** in the ephemeral child `Sibling`'s `v.observable` map — never sharing it back to the parent `Snapshot` — and runs a full `v.observe(ctx)` pass (`~4.5s` over `cmd/pew`'s 114-package dependency graph) per solo test.
     3. In `unit.Close(ctx)` → `u.view.Validate(ctx)` → `validateObserved(ctx)` (`view.go:1155-1164`), each solo `Unit` runs `v.newSeededValidationView(ctx)` (`v.observe(ctx)` #2) AND `current.ensureObservable(ctx, [solo])` (`v.observe(ctx)` #3).
     4. Total for 150 solo tests in one package: $150 \times 3 = 450$ full `observeView` passes $\times 4.5\text{s} \approx 33.75\text{ minutes}$.
   - Additionally, in `captureNativeGeneration` (`native.go:156-220`), `soloSession.Snapshot` (`SingleSubjectExecution`) captures all `438` `SharedDynamicStateCause` candidates across the repository even when `stipulator check --ids ...` is scoped to 1 requirement (`6` subjects).
3. **Correction on `auditset` vs. Policy Configuration**:
   - Per `docs/specs/closure.md:1597,1725` and `internal/auditset/auditset_test.go:73,76`, `math` runtime floating-point functions (`NaN`, `Inf`, `Pow`) and `reflect.TypeFor` are intentionally excluded from `auditset.go` (whereas `allowedPureMathSelectors` / `allowedPureReflectSelectors` in `toolchain_contracts.go` govern internal `std` pure-delegate verification only).
   - `gofresh` and `stipulator` set `assume_pure: true` in `.stipulator/policy.textproto` for witness execution, whereas `pew` and `gomutant` do not. We must never weaken `auditset` invariants (`REQ-closure-observability-audited-set` / `REQ-closure-observability-reflect-exclusion`).

---

## 5. Comprehensive Global `gofresh` + 5-Repository Audit & Resequenced 9-Chunk Schedule (2026-11-10)

Following user alignment that package/file decomposition must never be purely mechanical — every split exists to reason about component functionality, consolidate/simplify/refactor duplicated mechanisms, optimize algorithmic bottlenecks, fix soundness/precision defects, expand internal tracing, and harden unit/property testing (`*_test.go` per subpackage) — five global deep audits were completed across every package in `gofresh` (`cprep`/`asmverify`/`propharness`, `rta`, `toolchain` & `closure` core, `dynstate` & subpackages, root `package gofresh` & `runtimeinput`/`gotool`/`testvariant`/`cachefile`/`guard`/`testenv`, and 6-layer `internal/trace` coverage) plus `go-x-tools`, `pew`, `stipulator`, and `gomutant`.

All findings are tracked in `docs/issues/*.md` and sequenced into 9 isolated, commit-sized chunks in [`docs/plans/plan.md`](../plans/plan.md):

1. **Chunk 1 (COMPLETED)**: Unified Cross-Tool Diagnostic Tracing (`internal/trace` in `pew v0.11.0`, `stipulator v0.77.0`, `gomutant v0.68.0`).
2. **Chunk 2 (COMPLETED — `gofresh/internal/closure` Leaf Verifiers & Core `internal/trace` Domains)**:
   - Extended `internal/trace` (`internal/trace/trace.go` & `internal/trace/trace_test.go`) with `DomainDynstate ("dynstate")`, `DomainRuntimeInput ("runtimeinput")`, and `DomainCache ("cache")`.
   - Extracted, simplified, optimized, and hardened `internal/closure/internal/cprep` (`tokens.go`, `macros.go`, `symbols.go`, `asm.go`, `cgo.go` + `cprep_test.go`), `internal/closure/internal/asmverify` (`asmverify.go`, `parse.go`, `isa.go`, `r14.go`, `cpuid.go` + `asmverify_test.go`), and `internal/closure/internal/propharness` (`index.go`, `vars.go`, `protocol.go`, `surface.go` + `propharness_test.go`) with zero aliases/pass-through wrappers in `internal/closure`:
     - Unifies 4 `#define`/directive parsers (`CutDirectiveKeyword`, `ParseDefineDirective`) and 9 leading-ident loops, byte-level `NextAsmWordRune`/`ScanAsmWordToken`, single-pass `StripAssemblyComments` + `BlankQuotedLiterals`, `cgo.go` duplicate `EvalSymlinks` fixes, single-pass `scanAsmTokens`, zero-alloc `isFrameSlotIdentBeforePlusFP`, unified mnemonic/register tables, Pass-1 `dataDirectives` collection, single-pass `harnessPkgIndex` ($O(1)$ `findFuncParamIndex`), pre-order `approvedIdents` fold, unified `mutatingBuiltinFirstArg`/`rootPlaceVar`/`lookupLocalVar`/`usedIdentAndObject`, `forEachLocalSliceAllocStore` across `freshpath.go`/`observability.go`/`propertyharness.go`, and `cprep.verify.done`/`asmverify.package.done`/`propharness.verify.done` trace events.
   - [`gofresh-comprehensive-phase-and-cache-tracing.md`](../issues/gofresh-comprehensive-phase-and-cache-tracing.md):
     - Continues across Chunks 3–7 for `rta`, `closure` core/memos, `dynstate`, `runtimeinput`, `gotool`, `cachefile`, `view`, and `session`.
3. **Chunk 3 (COMPLETED — `gofresh/internal/closure/internal/rta` Decomposition, Optimization, Precision & Tests)**:
   - Split `rta.go` (`1,918` lines) into `rta.go`, `dispatch.go`, `runtime_types.go`, and `reflect.go`, unifying Plane-0 (`addRuntimeType`) and Plane-1 (`addHarnessStdRuntimeType`) into `visitRuntimeType`.
   - Fixed quadratic `ContainsTypeParam` re-invocations on structural children, added the $O(1)$ package-scope non-interface `*types.Named` fast path, retained verified type-param-free entries in `r.typeParamSeen` across calls (`r.hasTypeParam`), fixed `seen[unaliased]` cycle tracking, and made `seen` lazy so callers pass `nil`.
   - Eliminated triple `MethodSet(T)` lookups per runtime type, fixed `checkTypedCallbackTrampolineAssert` `$bound` wrapper synthesis (`named.NumMethods()` + `f.Prog.FuncValue`) and folded its two package instruction scans into one, eliminated duplicate `unwrapWrapper` calls, memoized `funcPkgPath` and `unwrapWrapper` on synthetic functions, reused `mv.Signature` in `addRuntimeMethodFunc`, made `attributedFingerprint` allocation-free (`strconv.AppendInt` stack buffer without `method.Id()`), and memoized `isPureHarnessInternalStdType` with recursive exclusions (`context`, `errors`, `os.File`, `io.discard`).
   - Fixed `Seeds.AddrTaken` (`seedAddrTakenFunc`) so candidate functions only become reachable when dispatched at a matching dynamic call site rather than unconditionally when `reflect` is imported, added incremental `Analyzer.Extend` (wired into `attributedReachableSetsOnce` and `binaryReachableUnion`), emitted `rta.analyze.done` trace events, and expanded `rta_test.go` (`TestBatchVsSoloAndExtendEquivalenceProperty`).
4. **Chunk 4 (COMPLETED — `gofresh/internal/closure/internal/toolchain` Extraction, AST Primitive Unification & Direct Unit Tests)**:
   - Moved `auditedLinknameTargets`, `auditedReadOnlyVarLinknameTargets`, and `ClassBPackages` into `internal/auditset` (including `auditset.Identity()`) and removed duplicate policy-input hashing in `internal/closure/dependencies.go`.
   - Extracted `internal/closure/internal/toolchain` into 17 focused files (`index.go`, `scope.go`, `contracts_pure.go`, `offsurface.go`, `audit_runtime.go`, `audit_testlog.go`, `audit_testdeps.go`, `audit_testing_writer.go`, `audit_testing_core.go`, `audit_testing_wiring.go`, `audit_os_core.go`, `audit_os_open_read.go`, `audit_os_getwd.go`, `audit_os_stat.go`, `audit_os_inactive_discover.go`, `audit_os_inactive_check.go`, `audit_bufio.go`) and split `toolchain_loader.go` into `toolchain_contracts_orchestrator.go` and `toolchain_source_loader.go` with zero aliases or pass-through wrappers.
   - Wired `PackageASTIndex` (`indexPackageAST`), `VerifyStructFields`, `VerifyFuncPreamble`, `VerifyIgnoringEINTRHelper`, `scanGoDirectiveComments`, `filterNonSelPropIdentsInSet`, and `RecvBaseTypeName` across the toolchain verifiers (`VerifyPurePackageAST`, `VerifyInternalTestlogPackageAST`, `VerifyTestdepsPackageAST`, `VerifyTestingPackageAST`, `VerifyOSPackageAST`, `discoverOSInactiveState`, `VerifyBufioWriterAST`, `DiscoverRuntimeInactiveGates`) and `internal/closure`, and added direct AST unit tests (`index_scope_test.go`, `audit_os_test.go`, `audit_sinks_test.go`, `audit_runtime_testing_test.go`).
5. **Chunk 5 (COMPLETED — `gofresh/internal/closure` Core Decomposition, Scan Consolidation & Reachability/Wrapper-Error Precision)**:
   - Fixed missing `fp *freshParamAnalysis` propagation in `fileValueFromAdmittedOpen` and `fileValueFromFreshOpenFile`, fixed per-subject `parser.ParseFile` + 5x `ast.Inspect` in `maximal.go` (`parsedMaximalFile` + `maximalTestingUnfiltered` + single-pass `edges`/`parents` AST walk + `len(receivers) == 0` short-circuit), fixed inverted `userTouchedStdGlobals` package check (`!isToolchainStdPackagePath`), threaded `audited` (`sum.pureDelegates`) and shared `freshParamAnalysis` (`resetDynamicMemos`) through `provenanceReachable`/`provenanceBFSWithCandidates`, eliminated `std` `init` and carrier-free `std` static-call RTA contamination, partitioned `rta.Result` bitmasks in one pass (`partitionAttributedBits`), and closed wrapper-error method dispatch (`(*strconv.NumError).Error()` + `internal/strconv.Error`).
   - Consolidated 10–14 SSA instruction scans into `enumerateCallerReferencesWithOrdered`, cached `baseStartup` declaration keys and `asyncOrDynamicStartupFunctions` across the batch, built `fp.callers` in $O(\text{edges})$ from `fp.summary.allStaticSites`, and split `freshpath.go` (6 files: `freshpath_fs.go`, `dynamic_walk.go`, `sentinel_globals.go`, `callee_return.go`, `container_cells.go`, `dispatch_targets.go`), `attribution.go` (3 files: `attribution_batch.go`, `attribution_provenance.go`, `attribution_harness.go`), `analyzer.go` (2 files: `analyzer.go`, `analyzer_declkeys.go`), `observability.go` (2 files: `observability.go`, `observability_startup.go`), merged `effectmemo.go` into `memo.go`, and emitted `attribution.batch.done`, `tier2.subject.done`, `maximal.subject.done`, `viewload.packages.done`, `program.build.done`, and `closure` memo trace events.
6. **Chunk 6 (`gofresh/internal/dynstate` Subpackages, Engine Unification, Soundness/Precision Fixes & `Compose` Optimization)**:
   - [`dynstate-syntaxutil-and-ast-helper-deduplication.md`](../issues/dynstate-syntaxutil-and-ast-helper-deduplication.md) & [`dynstate-factof-redundant-ast-scans-and-monoliths.md`](../issues/dynstate-factof-redundant-ast-scans-and-monoliths.md):
     - Extract `internal/dynstate/internal/syntaxutil` (`ast.go`, `types.go`, `fixpoint.go` + `syntaxutil_test.go`), `refconfine` (4 files + `refconfine_test.go`, deleting ~730 lines of duplicate `verifyProtectedMemoStructConfinement`), `freshstruct` (5 files + `freshstruct_test.go`), `protoaudit` (8 files + `protoaudit_test.go`), and `seams` (6 files + `seams_test.go`).
     - Fix Soundness/Precision Defects 1–4 in `internal/dynstate` (`boundValueRetentionFreeJudged` `range`/`copy` carrier smuggling, `boundValueJudged` `rooted(n.X)` on `SelectorExpr`, unified `receiverReadOnlyMethods` + `boundValueJudged`, and cross-package/`SliceExpr` `CarrierLinks` in `initAliasedLocals`), build unified `PkgAnalysisIndex` once per `FactOfWithHooks`, optimize `Compose`/`CarrierLinkGraph` in `fixpoint.go`, split core `dynstate` into 11 focused files, and add `./internal/dynstate/internal/...` to `race:leaf` in `.stipulator/policy.textproto`.
7. **Chunk 7 (Root `package gofresh` Batching/Splits & `internal/runtimeinput`, `gotool`, `testvariant`, `cachefile`, `guard`, `testenv` Simplification/Fixes)**:
   - [`view-sibling-observability-batching-and-validation-economy.md`](../issues/view-sibling-observability-batching-and-validation-economy.md) & [`runtimeinput-gotool-testvariant-cachefile-simplification.md`](../issues/runtimeinput-gotool-testvariant-cachefile-simplification.md):
     - Split `view.go` (4 files) and `session.go` (3 files), delete vestigial `dynstate` wrappers, fix `prepareOutcomeSupport` (`session.go:1125`) polluting `v.capturedObserved` on mixed `Unit`s, batch package-mates into `ComputeObservabilityBatch`, publish verified `Observability` proofs back to parent `Snapshot`s, share validation brackets in `Snapshot.Validate`, and eliminate redundant digest/env/binding work.
     - Unify `exclusionPatterns` UTF-8/control-byte validation, resolve `moduleDir` once, reuse `chainResolveObserved` target in `hashPath`, memoize `bracketCoverage.covers`, run `finalizeManifestState` once, and eliminate manifest encode/decode round-trips in `internal/runtimeinput`; fix `drainCollected` `WaitDelay == 0` timer race in `internal/gotool`; pre-index `testvariant.InertForSubject`; fix `cachefile.go` `knownBytes` overwrite drift and `writeSeq` pruning; and clean up `guard.go` and `testenv`.
8. **Chunk 8 (Downstream Fleet Refactoring, Batching & Startup Purity Across `go-x-tools`, `gomutant`, `stipulator`, and `pew`)**:
   - [`go-x-tools-startup-purity-and-determinism.md`](../issues/go-x-tools-startup-purity-and-determinism.md), [`gomutant:decompose-god-files-and-batch-freshness-checks.md`](../../../gomutant/docs/issues/decompose-god-files-and-batch-freshness-checks.md), [`stipulator:eliminate-redundant-gofresh-sessions-and-split-golang-backend.md`](../../../stipulator/docs/issues/eliminate-redundant-gofresh-sessions-and-split-golang-backend.md), [`pew:ab-memoization-and-cli-helper-deduplication.md`](../../../pew/docs/issues/ab-memoization-and-cli-helper-deduplication.md).
9. **Chunk 9 (Execute 4-Repo Speed, Efficiency, Accuracy & Incremental Findings Protocol)**.

