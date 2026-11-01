# Gofresh Tracing, Surface Purification, Correctness & Coverage Plan

## Phase A: First-Class Tracing (`internal/trace`)

- [ ] **Chunk A.1: Implement `internal/trace` & Wire Structured Events Across `toolchain`, `closure`, `view`, and `session`**
  - [ ] Implement `internal/trace` (`GOFRESH_TRACE`, `GOFRESH_TRACE_FILE`, `WithSink`, `WithFilteredSink`, `Recorder`, `Enabled` single-atomic-load fast path, `RefreshFromEnv`, line-oriented text and JSONL formatters, and `domain:substring` target filtering) per [`docs/notes/blueprint-tracing.md`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/notes/blueprint-tracing.md).
  - [ ] Enforce the trace non-interference invariant by stripping `GOFRESH_TRACE` and `GOFRESH_TRACE_FILE` in `NormalizeEnv` and ignoring them in `runtimeinput` testlog `getenv` ingestion.
  - [ ] Wire `toolchain`, `closure`, `view` (including exact `two_pass_diff` field reporting in `compareObservations`), and `session` trace events, add `REQ-fresh-trace` and `REQ-fresh-trace-non-interference` to `docs/specs/overview.md` and `.stipulator/bindings/fresh.textproto`, document `GOFRESH_TRACE` and `GOFRESH_TRACE_FILE` on package `gofresh`, and add comprehensive unit and concurrency tests in `internal/trace/trace_test.go`.

## Phase B: Public Surface & Tool-Leakage Eviction

- [ ] **Chunk B.1: Evict Non-Freshness Subpackages (`guidance`, `resident`, `toolversion`, `shortgates`, `shapecorpus`) & Cross-Tool Specs**
  - [ ] Delete `guidance/`, `resident/`, and `toolversion/` (including `toolversion/go.mod`), and move `shortgates/` and `shapecorpus/` into `internal/testenv` per [`docs/notes/blueprint-surface-eviction.md`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/notes/blueprint-surface-eviction.md).
  - [ ] Delete `docs/specs/guidance.md`, `docs/specs/controls.md`, `.stipulator/bindings/guidance.textproto`, and `.stipulator/bindings/control.textproto`, remove the shared-substrate preamble, `REQ-fresh-resident-readings`, `REQ-fresh-tool-version`, and `guidance.md`/`controls.md` references from `docs/specs/overview.md` and `.stipulator/bindings/fresh.textproto`, and record the retired requirements in `.stipulator/tombstones.textproto`.
  - [ ] Delete `CLAUDE.md` and `.claude/` from the repository root.

- [ ] **Chunk B.2: Internalize `gotool` & `runtimeinput` and Collapse Legacy `engine`/`option` Layer in Root `gofresh`**
  - [ ] Move narrowed `gotool` to `internal/gotool` (evicting `Runner.Program`, `Containment`, `RunMemo`, `Sampler`, `SnapshotSampler`, `Salvaged`) and replace `SessionPolicy.Runner`, `CaptureGuards`, and `ResolveToolchainSelection` `gotool` parameters with `SessionPolicy.PrepareCommand func(*exec.Cmd)` and `BuildDescription`.
  - [ ] Move `runtimeinput` to `internal/runtimeinput`, evict `gomutant`-only exemption-clause helpers (`RefusalClause`, `RefusalAttribution`, `MovedBracketClause`, `CanonicalMovedBracketClause`), unexport internal outcome-support/roots plumbing, and expose the clean runtime-observation domain surface (including `CompletedObservationState`) on root `gofresh` so `github.com/greatliontech/gofresh` is the sole public package.
  - [ ] Evict `RepositoryVouchFile`, `ReadVouchFile`, `BuildDescription.TestCompileArgs`, `DiagnosticsTo`, `Progress.Diagnostic`, `UnitPhases`, `Progress.IsUnit`, `ToolchainProvenance`, `ToolchainSampler`, `SampleFunc`, and `ErrNoSampler`; enforce `ToolchainSkew` automatically in `NewSession`; collapse the unexported `engine` and 12 `option` closures in `session.go` into `Session`; and amend `REQ-fresh-go-command-policy`, `REQ-fresh-toolchain-skew`, `REQ-fresh-progress` (`docs/specs/overview.md`), `REQ-vouch-input` (`docs/specs/purity.md`), `REQ-inputs-identity-facade`, `REQ-inputs-completed-observation`, `REQ-inputs-file-eligibility`, `REQ-inputs-producer-facade`, and `REQ-inputs-refusal-attribution` (`docs/specs/runtime-inputs.md`) along with `.stipulator/bindings/{fresh,vouch,inputs,guard,purity}.textproto`.

- [ ] **Chunk B.3: Align Downstream Tools (`pew`, `stipulator`, `gomutant`) & File Shared-Utility Consolidation Issue**
  - [ ] Internalize evicted CLI/MCP/process utilities (`guidance`, `resident`, `toolversion`, `gotool` process supervisor, and `gomutant`'s exemption-clause helpers) into `internal/` of `../pew`, `../stipulator`, and `../gomutant` (Option 1A) and migrate all 3 tools to the single-package `gofresh` release.
  - [ ] File a tracked issue in `../pew`, `../stipulator`, and `../gomutant` recording the shared CLI/MCP/process utility duplication so Option 1B (shared tool-support library extraction) is evaluated when auditing those tools.

## Phase C: Per-Subsystem Deep Correctness Audit & Exhaustive Case/Edge Coverage

- [ ] **Chunk C.1: Trace-Backed Test Harness, Causal-Witness Assertions & Universal Non-Interference Property Suite**
  - [ ] Integrate `trace.WithSink` (`*trace.Recorder`) into `internal/testenv` and `Session` test helpers to enforce the zero-unintended-degradation gate (`package_verdict_error`, `package_io_error`, `degradation`, `two_pass_diff`) per [`docs/notes/blueprint-correctness-and-coverage.md`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/notes/blueprint-correctness-and-coverage.md).
  - [ ] Pin exact structured causal witnesses across toolchain, closure, view, and session refusal/impurity tests, and add the universal trace non-interference property/fuzz suite.

- [ ] **Chunk C.2: Deep Correctness Audit & Direct Exhaustive Unit/Property/Fuzz Suites for `internal/dynstate`, `internal/testvariant`, and C Preprocessor / Cgo Scanner**
  - [ ] Perform a line-by-line correctness audit of `internal/dynstate`, fix any discovered defects, and add `internal/dynstate/dynstate_test.go` covering fixed-point solvers (`DeferralResolution`, `EnvAuditResolution`), mutual recursion/diamond field-poisoning graphs, `directives.go`, and `typecarrier.go`.
  - [ ] Perform a line-by-line correctness audit of `internal/testvariant`, fix any discovered defects, and expand `internal/testvariant/testvariant_test.go` with an exhaustive AST edge matrix and the `InertForSubject(before, after, subj) == true` $\implies$ `Closure(before, subj) == Closure(after, subj)` soundness property/fuzz bridge.
  - [ ] Perform a line-by-line correctness audit of `internal/closure/toolchain_cpreprocessor.go` and `cgo_includes.go`, fix any discovered defects, and add `internal/closure/cpreprocessor_test.go` (`FuzzCPreprocessor` and deterministic preprocessor/macro/include/cgo boundary matrix).

- [ ] **Chunk C.3: Deep Correctness Audit & Multi-Feature Composition, Two-Pass/Bracket TOCTOU Fault-Injection, and Workspace/Symlink/Cache Resilience Suites**
  - [ ] Perform a line-by-line correctness audit of `internal/closure` (AST/SSA/RTA/observability/toolchain verifier), `internal/runtimeinput`, and root `Session`/`Snapshot`/`Unit`/`CheckingUnit`/`Explain`, fixing any discovered defects.
  - [ ] Add the multi-feature composition matrix (generics + RTA interface/method-value dispatch + stdlib delegates + `//gofresh:vouch` + `//go:linkname` + 3-way `p` / `p` test / `p_test` compartments) with trace-witness assertions.
  - [ ] Add the deterministic two-pass (`newViewFor`) field-perturbation & metadata-vs-content TOCTOU suite, bracket/`ScratchNamespace` escape suite, and `go.work` / symlinked `$PWD` / repo-under-`$TMPDIR` / corrupted-cache resilience suite.

## Phase D: Performance & Optimization Audit & Close-Out

- [ ] **Chunk D.1: Subsystem Performance & Optimization Audit, Implementation, Benchmark Verification & Plan Close-Out**
  - [ ] Audit hot paths across `internal/closure`, `internal/dynstate`, `internal/runtimeinput`, and root `gofresh` using `internal/trace` counters and benchmarks under `mlock quiet`.
  - [ ] Implement verified optimizations without weakening any Phase C invariant, run full test and Stipulator verification gates across all 4 repositories, and retire `docs/notes/blueprint-*.md` and `docs/plans/plan.md`.
