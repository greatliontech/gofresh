# Working Notes: 5-Repo Freshness, Verification & Mutation Convergence

## 1. User Alignment & Session Rules (2026-11-06)

- **Selected Recovery Path (Option 1):** Audit and split the uncommitted `+14,235 / -6,052` working tree (`73` modified files + `3` untracked) back into disciplined, commit-sized chunks rather than converging the entangled C.4 + D.1 blob in place.
- **Full 5-Repo Ownership:** Full authority and ownership over both specs and code across the **5 repositories**: `go-x-tools`, `gofresh`, `gomutant`, `stipulator`, and `pew` (`godst` is explicitly outside repository scope).
- **Toolchain Invariance Requirement:** All 5 repositories must work identically under both `godst` (custom Go builds, e.g. `go1.27.2-dst.15`) and vanilla / system-installed Go toolchains — never hardcoding assumptions to one flavor or version string.
- **Compaction Defense:** Persist and commit findings, hypotheses, audit results, review dispositions, and user decisions frequently in `docs/notes/working-notes.md` so zero reasoning is lost across context compactions.
- **Lossless Working-Tree Checkpoint:** Full patch (`working-tree.patch`) and byte-for-byte file tree saved at `/home/nikolas/.gemini/antigravity-cli/brain/50b146c5-9ee0-44e7-8117-b53693375665/scratch/wt-checkpoint-20261106/`.

---

## 2. Diagnosis of Prior `gofresh` Session (`97dac15b`)

- **Committed Baseline (`HEAD` = `fa814e9`, 7 commits ahead of `origin/main`):**
  - `6a29303` docs: add tracing, surface purification, and correctness/coverage plan and blueprints
  - `af7ee21` feat(trace): implement `internal/trace` and wire structured diagnostic events (**Chunk A.1**)
  - `5024e0e` refactor!: evict `guidance`, `resident`, `toolversion`, `shortgates`, and `shapecorpus` subpackages (**Chunk B.1**)
  - `332c00b` refactor!: internalize `gotool` and `runtimeinput` into single-package `gofresh` (**Chunk B.2**)
  - `7e6f3eb` test(trace): add trace gate harness, causal witnesses, and non-interference fuzzing (**Chunk C.1**)
  - `6e2cf1a` fix(closure): harden `dynstate`, `testvariant`, and cgo scanner invariants and edge coverage (**Chunk C.2**)
  - `fa814e9` fix(runtimeinput,closure): enforce existence-bound and scratch boundaries, tuple type walking, and composition/TOCTOU suites (**Chunk C.3**)
- **Why `97dac15b` Stalled (`47,831` steps / `113.2 MB` transcript, terminated 2026-11-03 15:54):**
  1. Between `L34708` and `L36835` (pre-issue), it started Chunk D.1 work removing mutable package-level test hooks in `gofresh` and `internal/closure`.
  2. At `L36734`–`L39639` (after `docs/issues/gomutant-reuse-startup-rta-and-stale-findings.md` was filed), it implemented **Chunk C.4** on the same dirty tree. `go test ./...` passed (`0` failures).
  3. Instead of isolating, reviewing, and committing Chunk C.4, it ran `stipulator check`, hit Stipulator's `5m0s` (`300s`) timeout on `./internal/closure` and root `.` under `GOMAXPROCS=2 -race`, and spent ~20 hours (`L39640`–`L47831`, ~8,200 steps, `0` commits, `0` reviews) adding a `+1,727`-line persistent stdlib export-header cache in `internal/closure/internal/program/program.go`, `rawmemo.go`, `TestMain` pre-seeding, and rewriting thousands of lines across `integration_view_test.go`, `integration_execution_test.go`, `internal/closure/integration_test.go`, and `toolchainsource_hermetic_test.go`.
  4. At termination (`L47824`), cold `stipulator check` still timed out (`./internal/closure` = `288.6s` on 2 cores, root `.` = `~847s` CPU across 2 cores).

---

## 3. Root-Cause Diagnosis: `stipulator check` 300s Timeout at `GOMAXPROCS=2`

Inspection of `.stipulator/policy.textproto`, `.github/workflows/ci.yaml`, and `../stipulator/proto/stipulator/v1/policy.proto` established the exact structural cause:

1. **Core Dilution Across `./...` (`policy.proto:199-204`):**
   - Stipulator derives witness unit concurrency as `units = min(nproc/2, permitted_package_count)` and freezes per-unit `GOMAXPROCS = nproc / units` before capture grouping.
   - With `packages: "./..."` (`18` packages in `gofresh`), `units` scales up to `min(nproc/2, 18)` (e.g. `16`), clamping *every* package binary to `GOMAXPROCS=1..2`. The 16 small internal packages finish in `<2s`, leaving the two heavy SSA + child-`go`-command `-race` binaries (`.` and `./internal/closure`) running for minutes throttled to **2 cores** on an otherwise idle host.
2. **Consolidation + `soloSubjects` → `PackageExecution` Shift:**
   - Chunk B.2 folded `gotool` and `runtimeinput` (`115 KB` of witness bindings) into root `gofresh`, and Chunks C.1–C.3 added heavy multi-feature composition, TOCTOU, trace-witness, and fuzz suites.
   - Previously, mutable package-level test hooks caused `SharedDynamicStateCause` refusals under `PackageExecution`, making Stipulator run per-test `soloSubjects` where each test had its own `300s` invocation budget. Once test-hook culprits were removed (the right structural fix!), *all* bound witnesses in root `gofresh` ran together inside a single `GOMAXPROCS=2 go test -race` binary.
3. **Stale Policy Budget vs. CI Reality:**
   - `.github/workflows/ci.yaml` already budgets `race-timeout: 100m` split across **4 race shards** at `race-p: 2` because 2-core `-race` execution of full `go/ssa` + `go/packages` + child `go` toolchain integration witnesses genuinely takes >5m of 2-core CPU time even with a fast engine.
   - `policy.proto:37-40` explicitly states: *"Explicit per-invocation timeout, required and positive: a deliberately long-running invocation is admitted by review rather than aborted by an inherited ceiling."*
   - **Resolution for Chunk D.1:** Keep genuine, high-leverage, low-complexity engine optimizations and test-hook culprit elimination (zero `soloSubjects` fallbacks!), reject speculative test-gutting / 1,700-line cache complexity that only existed to chase an unreviewed 300s 2-core cap, and align `.stipulator/policy.textproto` (e.g., splitting fast `./internal/...` packages from heavy `.` / `./internal/closure` invocations so heavy packages aren't starved to `GOMAXPROCS=2` by 16 tiny siblings, and setting an honest measured `-race` timeout).

---

## 4. Ordered Cross-Repo Execution Roadmap

1. **`gofresh` — Chunk C.4 (Correctness & Specs):**
   - Audit diff classification from `Chunk C.4 Diff Auditor` and `Chunk D.1 & Test-Hook Diff Auditor`.
   - Isolate Chunk C.4 (`gomutant-reuse-startup-rta-and-stale-findings.md` Findings 1 & 2: startup unmutated-zero-global dead-branch pruning, source-audited assembly verification if sound, carrier-free & audited-`context.Context` parameter closure, and `docs/specs/closure.md` + `.stipulator/bindings/closure.textproto` updates).
   - Verify (`go vet` cross-OS, `go test -race`, `gomutant ephemeral` probes on changed invariants, `stipulator compile`/`verify`), run independent read-only adversarial review to convergence, and commit.
2. **`gofresh` — Chunk D.1 (Test-Hook Culprit Elimination, High-Signal Optimizations & Policy Alignment):**
   - Apply clean package-level test-hook culprit removals (`aaa_module_surface_test.go` proving zero `SharedDynamicStateCause` across all module packages under `PackageExecution`).
   - Apply verified, clean engine optimizations (measured with `internal/trace` and `mlock quiet` benchmarks) without test-suite mutilation or fragile cache bloat.
   - Align `.stipulator/policy.textproto` invocation topology and budgets, run full `stipulator check` + test gates, run adversarial review to convergence, and commit.
3. **Downstream Alignment & Tool Fixes (`pew`, `stipulator`, `gomutant` — Chunk B.3 + `gomutant` Issues):**
   - Internalize evicted CLI/MCP/process helpers (`guidance`, `resident`, `toolversion`, `gotool` supervisor, and `gomutant` exemption-clause splitters) into `internal/` of `pew`, `stipulator`, and `gomutant` (Option 1A) + file tracked consolidation issues for Option 1B evaluation.
   - Fix `gomutant` Finding 3 (`REQ-result-hygiene` / `MergeWholeFindings` pruning deleted symbols on whole-package `--package` runs) AND `gomutant` `docs/issues/schema-single-function-compile-and-overlay-reuse.md` ($O(L)$ top-level mutant helper functions instead of 540k-line inline switch, shared `(dir, schemaKey)` overlay directory across `testPkg` oracles, runtime-input merge / `PWD` working-tree protection).
   - Verify with local `replace` directives first; push `gofresh` so CI/Release mints the release tag automatically, bump `go.mod` across `pew`, `stipulator`, and `gomutant`, retire completed plan/blueprints/issues, and verify all repositories clean and green.
