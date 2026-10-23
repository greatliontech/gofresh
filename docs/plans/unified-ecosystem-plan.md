# Unified 4-Repo Ecosystem Plan (`gofresh`, `stipulator`, `gomutant`, `pew`)

## 1. Vision & Core Architectural Principles

`gofresh` is the shared freshness and execution-evidence engine powering three hot-loop developer tools:
1. **`stipulator`** (`../stipulator`): Specification-to-code traceability and witness test verification.
2. **`gomutant`** (`../gomutant`): Incremental mutation testing with banked baselines and cross-commit finding carry.
3. **`pew`** (`../pew`): Statistical benchmark execution, A/B comparison, and profile regression analysis.

To succeed in the hot development loop across all projects, the 4-repository stack simultaneously delivers:
- **Accuracy (No False-Valid Floor)**: A cached verdict, mutation kill/survivor record, or benchmark sample is reused only when its transitive code closure, selected standard-library content, build configuration, and observed runtime inputs (`GODEBUG=testlog` + environment/hardware guards) still hold.
- **Speed (Sub-Second Warm Path, Bounded Cold Path)**:
  - Tier 1 (`closure/maximal.go` + `closure/testvariant.go`) hashes the maximal non-standard package closure and test-variant compartments at the AST/token level without building SSA.
  - Tier 2/3 (`purity.go`, `dynamicstate.go`, `closure/observability.go`) runs whole-program SSA and attributed RTA only on cold misses for subjects that need observation or dynamic-state discharge, persisting results in the content-addressed memo store (`closure/memo.go`).
- **Efficiency & Zero-Maintenance Toolchain Upgrades**:
  - Developers switch seamlessly between vanilla Go toolchains (e.g., `/usr/bin/go`) and custom deterministic simulation toolchains (`godst`, `-tags=dst`, `-race`, `CGO_ENABLED=0`, cross-platform `GOOS`/`GOARCH`) without manually maintaining per-release SHA-256 hash tables in `gofresh` and without running an x86-64 binary symbolic execution prover in the hot loop.

---

## 2. Action Plan & Progress Checklist

### Phase 1: Prune the `5.1w` Symbolic/Native Proof Spikes & Wire Local `replace` Across All 4 Repos
- [x] Archive the `5.1w` spike state at branch `archive/5.1w-nativeproof-spikes` (`24ebf5c`).
- [x] Remove unwired spike packages (`internal/nativeproof/`, `internal/bitrelation/`, `internal/assemblycapture/`, `internal/buildflags/quoted.go` — 115,483 LOC total).
- [x] Remove unwired `closure/` symbolic-execution and native-correspondence spike files (`activation_*`, `assembly_*`, `computation*`, `float_*`, `global_*`, `narrow_*`, `region*`, `registration*`, `rooted_global_*`, `round_*`, `runtime_*_selected_test.go`, `scalar_constant.go`, `selected_source*`, `source_*`, `storage_*`, `fixtureownership_test.go`).
- [x] Remove `golang.org/x/arch` from `go.mod` / `go.sum`.
- [x] Clean up spike-only spec/binding/gap artifacts (`docs/specs/implementation-verification.md`, `.stipulator/bindings/implementation.textproto`, `.stipulator/bindings/activation*.textproto`, `.stipulator/bindings/assembly-streaming.textproto`, `.stipulator/gaps/impl-*.textproto`).
- [x] Retain post-`v0.118.0` core improvements (`6816a87`, `f5f02e6`, `5e96626`, `c6644c9`, `24ebf5c`).
- [x] Configure local `replace github.com/greatliontech/gofresh => ../gofresh` in `../stipulator/go.mod`, `../gomutant/go.mod`, and `../pew/go.mod`.

### Phase 2: Replace Hardcoded Toolchain SHA-256 Tables (`closure/toolchainaudit.go`) with Structural Stdlib & `godst` Boundary Verification
- [x] Separate `ToolchainContent` (full `std` selected-file digest for cross-toolchain cache invalidation) from `SelectionAudited` (structural stdlib boundary verifier, `gofresh/toolchain-verifier@5`).
- [x] Replace hardcoded per-release SHA-256 tables (`auditedToolchainSources`) with `verifyToolchainSurfaceWithIO` and `verifyListedPackageWithIO`, memoized in `cachefile` by `(toolchainVerifierVersion, AdmissionPolicy, importPath, digest)`.
- [x] Enforce closed import allowlist (`allowedPurePackageImport`) with zero prefix wildcards across all 44 `auditset.PurePackages()` and 39 `pureDelegatePackages` (`internal/*`, `crypto/*`, `encoding/json/*`).
- [x] Enforce unaliased imports and selector restrictions across `"time"` (including `Unix`, `UnixMicro`, `UnixMilli`, permitting `time.Unix(...).UTC()` in `encoding/json/v2`), `"fmt"`, `"runtime"`, `"math/rand"`, `"os"`, `"syscall"`, and `"internal/syscall/windows"`.
- [x] Enforce column-0 directive scanning in `verifyFileLinknameDirectives`, rejecting `//go:wasmimport` and `//go:cgo_` and enforcing 1-arg (`allowedPureSingleArgLinknames`) and 2-arg (`allowedPureLinknameTargets`) `//go:linkname` allowlists across pure and delegate packages.
- [x] Enforce `os`, `testing`, `testing/internal/testdeps`, and `net` boundary contracts (`verifyOSPackageAST` requiring all 7 boundary functions and `testlog.Open` + `testlog.Logger().Chdir` in `os.Chdir`; `verifyTestingPackageAST` requiring checked `StopTestLog()` and `dstWrapTestlogWriter`/`writeFromBubble`/`dstHostStreamWrite` when `dst_hostio.go` is selected).
- [x] Bind all verifier policy tables in `capturePolicyInputs` (`closure/dependencies.go`), bind `SelectionAudited()` in `effectScanScope` (`closure/effectmemo.go`) and `SetAnalysisScope` (`closure/memo.go`), and re-verify `lp.digest` after reading files in `verifyListedPackageWithIO` to prevent TOCTOU cache poisoning.
- [x] Verify all `closure` tests pass on both `godst` (`go1.27.2-dst.15`) and stock Go (`/usr/bin/go`, `go1.26.2`).

### Phase 3: Consumer Alignment, Spec Hygiene, & Adversarial Review Convergence
- [x] Fix all 16 dangling `REQ-impl-*` references in `gofresh/docs/specs/` and re-pin `gofresh/.stipulator/bindings/` (`864 bindings (0 stale), 0 unpinned, 0 moved`).
- [x] Add `(*Snapshot).ExplainDynamicState` in `gofresh/session.go`.
- [x] Migrate `stipulator`'s `groupEngine` (`internal/backends/golang/derive.go`) and `ExplainDynamicState` (`internal/backends/golang/explain.go`) to `gofresh.NewSession` and `(*gofresh.Snapshot).ExplainDynamicState`.
- [x] Update `gomutant` (`freshness.go`, `findings_test.go`, and v4 manifest test fixtures) against local `gofresh`.
- [x] Run `task install` in `../stipulator`, `../pew`, and `../gomutant` so `~/.local/bin/{stipulator,pew,gomutant}` run the latest code.
- [x] Converge independent adversarial review subagents (`adversarial-reviewer`) across all changes (3 rounds on `gofresh/closure` -> **0 defects**; 2 rounds on `gofresh/session.go`, `stipulator`, and `gomutant` -> **0 defects**).
- [x] Pass inner-loop gates (`task check` / `task vet test:short`) and `stipulator verify --no-test` across all 4 repositories (`3,672` total bindings, `0 stale`, `0 unpinned`, `0 moved`).

### Phase 4: Full Gate Verification, Warm-Loop Benchmarking, & Atomic Git Commits
- [ ] Complete cold `stipulator gate` run (`task-1074`) across `gofresh`, `stipulator`, `pew`, and `gomutant` and record cold witness execution metrics.
- [ ] Measure warm `stipulator gate` / `stipulator verify` latency and memory across the 4 repositories to confirm sub-second / low-second warm hot-loop targets.
- [ ] Commit atomic, well-structured commits in each repository (`gofresh`, `../stipulator`, `../gomutant`, keeping local `replace` directives until ready to tag a new `gofresh` release).

---

## 3. Performance & Resource Telemetry

| Repository & Operation | Wall Time | Resident / Peak Memory | Verdict / Cache Status |
| :--- | :--- | :--- | :--- |
| **`gofresh`** (`stipulator verify --no-test`) | **28.9s** (compile 16.4s, discovery 6.3s, verify 6.1s) | End: **75 MiB**, Peak: **389 MiB** (descendants **311 MiB**) | `864 bindings (0 stale), 0 unpinned, 0 moved` (`309 served, 346 typed`) |
| **`stipulator`** (`stipulator verify --no-test`, cold) | **2m22.1s** (compile 0s, discovery 40.8s, verify 1m41s) | End: **171 MiB**, Peak: **2.1 GiB** (descendants **1.2 GiB**) | `1550 bindings (0 stale), 0 unpinned, 0 moved` (`1149 records published`) |
| **`pew`** (`stipulator verify --no-test`) | **< 15s** | Peak **< 650 MiB** | `432 bindings (0 stale), 0 unpinned, 0 moved` |
| **`gomutant`** (`stipulator verify --no-test`) | **13.6s** (compile 5.7s, discovery 3.3s, verify 4.6s) | End: **71 MiB**, Peak: **623 MiB** (descendants **197 MiB**) | `826 bindings (0 stale), 0 unpinned, 0 moved` |
| **`gofresh`** (`task check`: `vet` + `test:short`) | **~19.8s** (`gofresh` 2.4s, `closure` 5.1s, `gotool` 11.8s, `runtimeinput` 2.7s) | Within budget | All packages pass |
| **`stipulator`** (`task vet test:short`) | **~1m57s** (`backends/golang` 89.1s, `check` 12.5s, `mcpserver` 7.4s, `cmd` 5.8s) | Within budget | All packages pass |
| **`pew`** (`task check`: `vet` + `test:short`) | **~12.5s** (`gotool` 5.1s, `cmd/pew` 4.3s, `run` 2.6s) | Within budget | All packages pass |
| **`gomutant`** (`task vet test:selfhost-plan` + `test:short`) | **~2m25s** (`selfhost-plan` 2m05s, `test:short` 20.8s) | Peak **4.0 GiB** (cold SSA proof of `gomutant` & `internal/cmd`) | `6 measure (238 candidates)`, all tests pass |
| **`gofresh`** (`stipulator gate` cold `-race` pass, in flight) | 90/92 packages persisted in **4m45.8s**; `gofresh` + `gofresh/closure` `-race` running | Parent **455 MiB RSS**, `closure.test` **1.18 GiB RSS**, `gofresh.test` **1.26 GiB RSS** | In progress (`task-1074`) |
