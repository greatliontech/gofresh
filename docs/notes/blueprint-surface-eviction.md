# Phase B Blueprint: Public Surface & Tool-Leakage Eviction

## 1. Governing Principle: Single-Package Freshness Library

`gofresh` is a Go library for freshness analysis and verification. It must have **one public Go package (`github.com/greatliontech/gofresh`)** and **zero public subpackages**. Anything that exists only as a CLI/MCP presentation layer, process-group supervisor, memory/RSS monitor, build-info version stamper, or tool-specific exemption parser is tool leakage and must be evicted from `gofresh` (even when shared by `pew`, `stipulator`, and `gomutant`).

Shared utilities evicted from `gofresh` are internalized into `internal/` of `pew`, `stipulator`, and `gomutant` (**Option 1A**), accompanied by a tracked issue in the 3 tool repositories recording the shared utility duplication so we can evaluate extracting a dedicated shared CLI/MCP support module (**Option 1B**) when working on those tools.

## 2. Subpackage Dispositions (All 7 Public Subpackages Removed)

1. **`github.com/greatliontech/gofresh/guidance` — EVICT**:
   - Delete `guidance/guidance.go` and `guidance/guidance_test.go`.
   - Delete `docs/specs/guidance.md` and `.stipulator/bindings/guidance.textproto`, remove `guidance.md` references from `docs/specs/overview.md`, and tombstone `REQ-guidance-*` in `.stipulator/tombstones.textproto`.
   - Internalize into `pew`, `stipulator`, and `gomutant`.
2. **`github.com/greatliontech/gofresh/resident` — EVICT**:
   - Delete `resident/` (`host*.go`, `resident*.go`, `words.go`, tests).
   - Remove `REQ-fresh-resident-readings` from `docs/specs/overview.md` and `.stipulator/bindings/fresh.textproto`, and tombstone it in `.stipulator/tombstones.textproto`.
   - Internalize into `pew`, `stipulator`, and `gomutant`.
3. **`github.com/greatliontech/gofresh/toolversion` — EVICT**:
   - Delete `toolversion/` (including nested `toolversion/go.mod` submodule).
   - Remove `REQ-fresh-tool-version` from `docs/specs/overview.md` and `.stipulator/bindings/fresh.textproto`, and tombstone it in `.stipulator/tombstones.textproto`.
   - Internalize into `pew`, `stipulator`, and `gomutant`.
4. **`github.com/greatliontech/gofresh/shortgates` — INTERNALIZE TO `internal/testenv`**:
   - Move `shortgates/` into `internal/testenv` in `gofresh` for `gofresh`'s own test-tier verification; internalize into `pew`, `stipulator`, and `gomutant` if used by their test suites.
5. **`github.com/greatliontech/gofresh/shapecorpus` — INTERNALIZE TO `internal/testenv`**:
   - Move `shapecorpus/` into `internal/testenv` in `gofresh` (used only by `internal/closure/algebra_test.go` and `stipulator`'s test suite).
6. **`github.com/greatliontech/gofresh/gotool` — INTERNALIZE & EVICT PROCESS SUPERVISOR**:
   - Move narrowed `gotool` into `gofresh/internal/gotool`, keeping only what `gofresh` uses internally (`go env -json` snapshot reading, `go list` / `LoadPackages`, `CanonicalDir`, `Coordinate`, `RunMemo`, environment normalization, and Go version parsing).
   - Evict general child-process management (`Runner.Program`, `Containment` with `SIGQUIT` `Quit`/`Grace`, `Sampler`, `SnapshotSampler`, `Salvaged`) from `gofresh` into `internal/gotool` of `pew`, `stipulator`, and `gomutant`.
   - Delete cross-tool CLI/MCP control spec `docs/specs/controls.md` and `.stipulator/bindings/control.textproto`, and tombstone `REQ-control-*` in `.stipulator/tombstones.textproto` (done in Chunk B.1 along with the other retired cross-tool specs).
7. **`github.com/greatliontech/gofresh/runtimeinput` — INTERNALIZE TO `internal/runtimeinput` & PROMOTE DOMAIN TYPES**:
   - Move `runtimeinput/` into `gofresh/internal/runtimeinput`.
   - Evict `gomutant`-only exemption-clause string helpers (`RefusalClause`, `RefusalAttribution`, `MovedBracketClause`, `CanonicalMovedBracketClause`) to `gomutant`.
   - Unexport internal cross-package plumbing (`OutcomeBinding`, `OutcomeSupport`, `CompletionReceipt`, `HasOutcomeSupport`, `FileInputContext`, `FileEligibility`, `FileInputKind`, `ProducerFrame.Observe`, `ProducerFrame.Completion`, `ProducerFrame.OutcomeBinding`).
   - Expose the clean runtime-observation domain surface directly on root `gofresh` (`ScratchNamespace`, `ValidateScratchNamespace`, `Observation`, `RuntimeState`, `CompletedObservationState`, `RuntimeDescription` / `DescribeRuntimeInputs`, `CurrentRuntimeInputs`, `MovedRuntimeInputs`, `RuntimeInputPaths`, `MergeObservations`, `AdoptObservation`, `IncompleteRuntimeObservation`, `AbsoluteObservation`, `RelativeObservation`, `FromTestLog`, `CaptureBracket`, `CaptureProducerFrame`, `InputRoots`, and `(*Session).CheckFileInputEligibility`), so external consumers import **only** `github.com/greatliontech/gofresh`.

## 3. Root `gofresh` Surface Cleanup & `session.go` Legacy Layer Collapse

1. **Vouch File Naming Policy Eviction**:
   - Evict `RepositoryVouchFile` (`"vouches"`) and `ReadVouchFile(dir)` from `gofresh` (move to `pew`/`gomutant`).
   - Keep `ParseVouchEntry` and `ParseVouchEntries` for `SessionPolicy.Vouches`.
2. **`BuildDescription.TestCompileArgs` Eviction**:
   - Remove `(BuildDescription).TestCompileArgs(outputPath)` from `gofresh` (move to callers in `pew`/`stipulator`/`gomutant`).
3. **CLI Spinner / Progress Formatting Helpers Eviction**:
   - Remove `DiagnosticsTo(io.Writer) func(Progress)`, `(Progress).Diagnostic() string`, `UnitPhases() []string`, and `(Progress).IsUnit() bool` from `gofresh` (move to CLI callers), keeping `Progress` as pure data on `SessionPolicy.Progress`.
4. **Automatic `ToolchainSkew` Enforcement in `NewSession`**:
   - Have `NewSession` automatically check `ToolchainSkew` against its captured `GOVERSION` snapshot (returning `*ToolchainProvenanceError` on skew).
   - Keep `ToolchainSkew` and `ToolchainProvenanceError` on `gofresh`; evict `ToolchainProvenance`, `ToolchainSampler`, `SampleFunc`, and `ErrNoSampler`.
5. **Decouple Root Signatures from `gotool`**:
   - Replace `SessionPolicy.Runner gotool.Runner` with `SessionPolicy.PrepareCommand func(*exec.Cmd)`.
   - Update `CaptureGuards` and `ResolveToolchainSelection` to accept `BuildDescription` (plus optional `PrepareCommand` or via `Session`) instead of `*gotool.EnvReader`.
6. **Collapse Legacy Unexported `engine` & `option` Layer in `session.go`**:
   - Collapse `type engine struct` into `Session` in production `session.go`, eliminating the duplicate `Session` wrapper and moving the white-box test builder (`newEngine` / `option`) out of production `session.go` into `frontend_harness_test.go` (test-hook restructuring is scheduled in Chunk D.1).
7. **Repository Root Hygiene**:
   - Delete the 449 KB `CLAUDE.md` historical session log and `.claude/` directory from the repository root.

## 4. Specification Amendments (`docs/specs/` & `.stipulator/`)

Landed atomically with their corresponding implementation chunks (Option 1):
1. **Chunk B.1**:
   - Delete [`docs/specs/guidance.md`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/guidance.md) (`REQ-guidance-*`) and `.stipulator/bindings/guidance.textproto`.
   - Delete [`docs/specs/controls.md`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/controls.md) (`REQ-control-*`) and `.stipulator/bindings/control.textproto`.
   - In [`docs/specs/overview.md`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/overview.md):
     - Remove the "fleet's shared substrate" preamble and retired document/package index entries ([`overview.md:11-65`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/overview.md#L11-L65)).
     - Delete **`REQ-fresh-tool-version`** ([`overview.md:67-84`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/overview.md#L67-L84)) and **`REQ-fresh-resident-readings`** ([`overview.md:466-538`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/overview.md#L466-L538)) and their bindings in `.stipulator/bindings/fresh.textproto`.
   - Record retired requirements (`REQ-guidance-*`, `REQ-control-*`, `REQ-fresh-tool-version`, `REQ-fresh-resident-readings`) in `.stipulator/tombstones.textproto`.
2. **Chunk B.2**:
   - In [`docs/specs/overview.md`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/overview.md):
     - Narrow **`REQ-fresh-go-command-policy`** ([`overview.md:370-416`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/overview.md#L370-L416)) to `gofresh`'s own `go` subprocess execution (normalized environment, `PWD` derivation, `GOPACKAGESDRIVER=off`, pass-scoped `go env -json` snapshot, canonical directory resolution, and caller-supplied `PrepareCommand` hook), removing the consumer child-process supervisor (`Containment`, `Quit` grace, `Program`, `Salvaged`).
     - Amend **`REQ-fresh-toolchain-skew`** ([`overview.md:418-464`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/overview.md#L418-L464)) so `NewSession` enforces language-series skew directly over its captured `GOVERSION` snapshot rather than taking a consumer-held `Sampler`.
     - Amend **`REQ-fresh-progress`** ([`overview.md:812-819`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/overview.md#L812-L819)) to keep `Progress` as pure event data without CLI line-rendering/spinner helpers (`Diagnostic`, `DiagnosticsTo`, `UnitPhases`, `IsUnit`).
   - In [`docs/specs/purity.md`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/purity.md):
     - Amend **`REQ-vouch-input`** ([`purity.md:107-123`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/purity.md#L107-L123)) to remove `RepositoryVouchFile` / `ReadVouchFile`, retaining `SessionPolicy.Vouches` and `ParseVouchEntry` / `ParseVouchEntries`.
   - In [`docs/specs/runtime-inputs.md`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/runtime-inputs.md):
     - Amend **`REQ-inputs-identity-facade`** ([`runtime-inputs.md:368-379`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/runtime-inputs.md#L368-L379)), **`REQ-inputs-completed-observation`** ([`runtime-inputs.md:446-457`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/runtime-inputs.md#L446-L457)), **`REQ-inputs-file-eligibility`** ([`runtime-inputs.md:815-846`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/runtime-inputs.md#L815-L846)), **`REQ-inputs-producer-facade`** ([`runtime-inputs.md:848-886`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/runtime-inputs.md#L848-L886)), and **`REQ-inputs-refusal-attribution`** ([`runtime-inputs.md:994-1066`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/docs/specs/runtime-inputs.md#L994-L1066)) to reflect single-package `gofresh` ownership (`Session` preflight, promoted root `gofresh` runtime-observation types including `CompletedObservationState`, unexported internal roots/outcome plumbing, and eviction of `gomutant`-specific exemption-table string splitters `RefusalClause`, `RefusalAttribution`, `MovedBracketClause`, `CanonicalMovedBracketClause`).
   - Update `.stipulator/bindings/{fresh,vouch,inputs,guard,purity}.textproto` (retargeting any `gotool` / `runtimeinput` package paths and symbol names to `internal/gotool`, `internal/runtimeinput`, and root `gofresh`).
