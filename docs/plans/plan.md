# Gofresh & Ecosystem Master Plan

## Phase 1: `gofresh` Core Speed, Precision & Zero-Config Foundation

- [x] **Chunk 1.1: Build-Environment Filtering, `gotool` Cache Helpers, Cgroup-Aware Resident Limits & Memo Preview**
  - [x] Filter `completeBuildEnvironment` (`builddescription.go`) and `gotool.MemoKey` (`gotool/memo.go`) to build-determining `go env` and OS environment keys so ambient shell variables (`ANTIGRAVITY_SOURCE_METADATA`, `PWD`, `SHLVL`, `TERM`) and checkout/cache paths (`GOMOD`, `GOCACHE`, `GOTMPDIR`) never invalidate `Guards.BuildConfig` or bust persistent disk memos (`docs/specs/guards.md`, `docs/specs/controls.md`).
  - [x] Export `gotool.PreserveBuildCache` (promoting `internal/testenv/cache.go`) for hermetic test suites (`docs/specs/overview.md`).
  - [x] Make `resident` host memory limits cgroup-v2-aware (`/sys/fs/cgroup/memory.max`) and optimize Linux process-tree resident sampling to walk `/proc/<pid>/task/<tid>/children` from `os.Getpid()` (`docs/specs/overview.md`).
  - [x] Add `PreviewPruneMemos(maxBytes int64)` to `closure/internal/cachefile`, `closure`, and `gofresh` so dry-run cache pruning shares the exact directory-walking implementation of `PruneMemos` (`docs/specs/closure.md`).
  - [x] Expose structured culprit package/symbol fields on `Verdict` / `ObservationProof` so consumers never string-parse diagnostic prose (`docs/specs/overview.md`, `docs/specs/evidence.md`).

- [ ] **Chunk 1.2: Stdlib Source Digest Memoization, `observeView` De-Amplification & `ComputeRootedFunctions` Disk Memo**
  - [ ] Persist per-package and aggregate `ToolchainContent` digests inside the `toolchainsource` disk memo (validated by file metadata stamps), memoize verified `toolchainDigests` in-process per toolchain/platform/buildFlags scope, and remove `GOMOD`/`GOWORK` from `toolchainSourceScope` (`closure/toolchainsource.go`, `docs/specs/closure.md`).
  - [ ] Reduce `NewView` / `Unit` observation passes to one opening observation and one closing validation observation; skip redundant `current.ensureObservable` in `validateObserved` when `v.observabilityEnsured && v.observation.equal(current.observation)`; reuse `v.observation.envSnapshot` in `ensureObservable` (`view.go`, `docs/specs/evidence.md`).
  - [ ] Persist `ComputeRootedFunctions` and `ComputeBinaryRootedFunctions` in the `observability` disk memo and compute them in the same loaded `*program` / `attributedReachableSets` pass before releasing `h.progs` (`closure/observability.go`, `closure/rooted.go`, `view.go`).
  - [ ] Keep `h.lists[pkgPath]` alive for the lifetime of a `Hasher` instance instead of deleting it in `ComputeMaximalFactsBatch` (`closure/maximal.go`).

- [ ] **Chunk 1.3: Reachable `TestVariantDeclaration.References` Attribution, Automatic Ledger Revalidation & RTA-Scoped Closure/Effects**
  - [ ] Attribute `TestVariantDelta` (`closure/testvariant/testvariant.go`, `applicability.go`) via transitive reachability over `TestVariantDeclaration.References` from the subject symbol (plus `init` and reachable `method` declarations) so editing, adding, or deleting unrelated tests/benchmarks in `*_test.go` is inert (`docs/specs/closure.md`, `docs/specs/evidence.md`).
  - [ ] Fold `TestVariantLedger` inert-delta checking directly into `Check` / `RuntimeBinding.Check` whenever `recorded.TestVariantLedger != ""` (`checking.go`, `view.go`).
  - [ ] Scope `MaximalClosure` and `scanPackageEffects` to RTA-reachable symbols, functions, and non-test-only dependency packages (`closure/maximal.go`, `closure/effects.go`, `docs/specs/closure.md`).

- [ ] **Chunk 1.4: Zero-Config Autodetection & Elimination of Manual Source Directives, `vouches` & Version Allowlists**
  - [ ] Auto-discharge subject-rooted package state under `SingleSubjectExecution` via `ComputeRootedFunctions` without requiring `//gofresh:single-subject`, and extend `SingleSubjectExecution` across transitive helper packages in single-subject processes (`dynamicstate.go`, `view.go`, `docs/specs/closure.md`, `docs/specs/purity.md`).
  - [ ] Replace hardcoded third-party module version strings (`protobuf`, `grpc`, `rapid`, `x/sys`, `yaml.v3`) and generated-header name checks with content-keyed structural/SSA verification memoized by dependency content digest (`dynamicstate.go`, `closure/propertyharness.go`, `docs/specs/closure.md`).
  - [ ] Recognize lexical save-and-`defer`-restore test-seam assignments in sequential tests automatically (`dynamicstate.go`, `docs/specs/closure.md`).
  - [ ] Automatically classify self-cleaned in-tree scratch paths (`pre == ENOENT && post == ENOENT`) and content-hash read-only external binaries resolved along `PATH` in `runtimeinput` (`runtimeinput/runtimeinput.go`, `docs/specs/runtime-inputs.md`).
  - [ ] Remove retired manual source directives (`//gofresh:pure`, `//gofresh:external`, `//gofresh:single-subject`) and manual `vouches` file / `WithDynamicStateVouches` / `WithAssumePure` surfaces (`purity.go`, `vouchfile.go`, `gofresh.go`, `docs/specs/purity.md`).

- [ ] **Chunk 1.5: SSA-Based Dynamic-State Analysis, Witness Executor Helper, Legacy `Engine` Retirement & Test Suite Acceleration**
  - [ ] Replace the raw-AST local alias/escape/capture pattern matcher in `purity.go` and NUL/SOH string encodings in `dynamicstate.go` with a compositional `go/ssa` def-use dataflow pass using typed Go structs inside `closure` (`closure/`, `dynamicstate.go`, `purity.go`).
  - [ ] Add first-class test binary compilation and witness process execution helpers on `Snapshot` / `RuntimeBinding` (`session.go`, `unit.go`).
  - [ ] Batch synthetic module subtests in `view_test.go` (`TestCarrierEscapeDischarges`) and `closure/closure_test.go` (`TestReadOnlyObservabilityProof`) and preserve `toolchainsource` memos across `XDG_CACHE_HOME`-isolated tests.

---

## Phase 2: `pew` Zero-Config, Speed & Architectural Collapse

- [ ] **Chunk 2.1: Single-Pass Benchmark Compilation, Module-Scoped `gofresh.Session` Caching & Affinity Guard**
  - [ ] Update `pew` to the new `gofresh` foundation.
  - [ ] Compile each benchmark package once in `preparePackageRun` (`cmd/pew/run.go`) and reuse the compiled binary across warmup, measurement, and profiling.
  - [ ] Cache `*gofresh.Session` per module across `pew status`, `pew run`, and `pew stat`, and parallelize Side A / Side B build preparation in `pew ab` (`cmd/pew/status.go`, `cmd/pew/run.go`, `cmd/pew/stat_subject.go`, `cmd/pew/ab.go`).
  - [ ] Include effective `GOMAXPROCS` / CPU affinity in runtime/workload guards (`internal/run/`, `cmd/pew/workload.go`, `docs/specs/`).

- [ ] **Chunk 2.2: Zero-Config Directive Removal, `stat`/`ab` Consolidation & Parallel Test Suite**
  - [ ] Remove `//pew:scratch` (`cmd/pew/runtime_destinations.go`), `//gofresh:inputs` (`cmd/pew/source_inputs.go`), `vouches` (`cmd/pew/vouchfile.go`), `revalidateWithLedger`, `analysisSession`/`analysisView`, and `sampleModuleToolchain` (`cmd/pew/provenance.go`).
  - [ ] Unify profile collection and comparison report rendering between `pew stat` and `pew ab` (`cmd/pew/stat_*.go`, `cmd/pew/ab_*.go`, `cmd/pew/profiles.go`).
  - [ ] Replace `context.WithValue` (`invocationKey`, `admissionKey`, `reporterKey`) and `os.Chdir` (`withWorkingDir`) with an explicit `*Invocation` struct holding `workDir`, share read-only fixture modules in `TestMain`, fix `vouch_test.go` `GOCACHE` preservation, and enable `t.Parallel()` across `pew` tests.

---

## Phase 3: `stipulator` Zero-Config, Cache-First Resolution, Speed & Package Split

- [ ] **Chunk 3.1: Zero-Config Policy Synthesis, Automatic `PackageExecution` / `SingleSubjectExecution` Partitioning & Scope-Invariant `GOMAXPROCS`**
  - [ ] Update `stipulator` to the new `gofresh` foundation and delete duplicate environment/resident/ledger helpers (`internal/backends/golang/normalize.go`, `execute.go`, `internal/witnesscache/witnesscache.go`).
  - [ ] Fix `executionScope.packageCount` (`internal/backends/golang/allocation.go`) so `SpawnBound` and `GOMAXPROCS` are scope-invariant and applied only to `RuntimeDescription.Environment`.
  - [ ] Automatically partition witnesses per package between batch `PackageExecution` and solo `SingleSubjectExecution`, auto-bracket workspace metadata (`go.mod`, `go.sum`, `go.work`, `.stipulator`), auto-extract `linker_strings` from `-ldflags`, synthesize default policy when `.stipulator/policy.textproto` is absent, and remove `assume_pure` and manual `bracket_paths` from `.stipulator/policy.textproto` (`docs/specs/evidence.md`, `internal/backends/golang/`).

- [ ] **Chunk 3.2: Unified Cache-First Resolver (All Symbol Kinds), Legacy `gofresh.Engine` Removal & `internal/backends/golang` Package Split**
  - [ ] Cache `type`, `var`, `const`, and `field` resolutions alongside callables in `resolutioncache` / `Served`, serve warm hits without calling `packages.Load` or spawning `internal-resolve`, and replace per-package `go list -compiled -export` with one batched `go list -deps -test -json` per selection (`internal/backends/golang/served.go`, `sourcecertificate.go`, `internal/resolutioncache/`).
  - [ ] Unify `WholeTree`, `Declarations`, and `Served`, remove the `internal-resolve` child IPC protocol (`resolver.go`, `resolverclient.go`) and legacy `derive.go` `groupEngine`/`newEngine` scaffolding, cache state in `mcpserver.Server`, and split `internal/backends/golang` into focused subpackages (`gopolicy`, `goresolve`, `gowitness`).

- [ ] **Chunk 3.3: Hermetic `TestMain` Cache Sharing, Hook Injection & Parallel Test Suite**
  - [ ] Initialize baseline hermetic env vars and a shared `XDG_CACHE_HOME` once in `TestMain` (`internal/backends/golang/main_test.go`) so `NeutralAmbient` keeps `gofresh` memos warm across tests, replace package-global test hooks with struct fields, share read-only `testdata/*` `Context` fixtures via `sync.OnceValues`, and enable `t.Parallel()`.

---

## Phase 4: `gomutant` Zero-Config, Mutant Schemata, Precision & Dead-Code Purge

- [ ] **Chunk 4.1: Dead-Code Purge, Catalog Precision Fixes, `PreviewPruneMemos` & Zero-Config Target/Exemption Autodetection**
  - [ ] Update `gomutant` to the new `gofresh` foundation and migrate `freshness.go` from legacy `gofresh.Engine` to `gofresh.Session` (then remove legacy `Engine` from `gofresh`).
  - [ ] Delete the dead oracle-drift subsystem (`freshness.go:1758-2127`, `run.go:5134-5387`, `killerdrift_test.go`), unused persisted `CompartmentLedger` (`findings.go`, `interned.go`), dead `bankedCoverage` (`bank.go`), and unreachable `auditNarrowedSurvivors` (`run.go:6088-6189`).
  - [ ] Replace `previewMemos` (`cacheprune.go:355-406`) with `gofresh.PreviewPruneMemos`, replace string-parsing in `exemptions.go` with structured `gofresh.Verdict` fields, and replace `internal/engine/memlimit*.go` and `procgroup_*.go` with `gofresh/resident` and `gofresh/gotool`.
  - [ ] Fix `--budget` pre-filtering (`internal/engine/mutants.go:108`), eliminate guaranteed no-op/duplicate return & statement mutations (`catalog_returns.go`, `catalog_statements.go`), prune equivalent `make(map, cap)` and `len(x) <= 0` / `len(x) > 0` mutations (`catalog_literals.go`, `catalog_comparison.go`), auto-discover `var _ Iface = ...` structural targets (`enumerate.go`), and enable automatic `SingleSubjectExecution`.

- [ ] **Chunk 4.2: In-Memory RTA Oracle Reachability, Fast Candidate Materialization & Per-Package Mutant Schemata**
  - [ ] Derive test-package import closures in-memory from `t.pkgs` instead of spawning $N \times$ `go list -deps -test` in `DerivedOracleContext` (`internal/engine/buildset.go`), filter/order oracle tests by RTA reachability and ascending duration, fold `-coverprofile` into the initial baseline probe, and drop redundant `scopedBaselinePasses` during kill confirmation.
  - [ ] Cache `sourceBytes` and `funcsBySymbol` on `engine.Tree`, seed `renderedSeen[string(baseline)] = true`, and gate `processImports` on deleted `types.PkgName` identifiers (`internal/engine/candidate_edit.go`, `symbol.go`, `surface.go`).
  - [ ] Implement per-package mutant schemata (`go test -c -overlay` compiled once per package and switched via `GOMUTANT_MUTANT_ID`) for type-valid AST mutations (`internal/engine/run.go`).

- [ ] **Chunk 4.3: Root Package Decomposition, CLI/MCP Deduplication & Parallel Test Suite**
  - [ ] Split `run.go` (`6,314` LoC) into `prepare.go`, `schedule.go`, `execute.go`, and `reconcile.go`, and consolidate duplicated CLI (`internal/cmd`) and MCP (`internal/mcpserver`) orchestration.
  - [ ] Memoize read-only `fixtureTree(t)` and `lifecycleModule(t)`, batch `TestVacuous` operator-accounting targets in `run_test.go`, tighten multi-second timeout sleeps, move mutable `seams` to struct fields, and enable `t.Parallel()` across `gomutant` tests.
