# Audit 07c: Root Package Tests — Part 2 (`initsubject_test.go` through `vouchfile_test.go`)

## 1. Scope & Verification Proof

- **Scope:** 45 root-package test files (`initsubject_test.go` through `vouchfile_test.go` alphabetically).
- **Total Lines Read:** 8,842 lines across 45 files (100% of lines read in full).
- **Package Membership:** 44 files in `package gofresh` (white-box tests accessing internal types, `engine`, `viewTestHooks`, `subjectScan`, `producingUnit`, `observationFacts`, `processFactCache`) and 1 file in `package gofresh_test` (`toolversion_test.go`).

| # | File | Lines | Test / Fuzz Funcs | Local Helpers / Types | `testing.Short()` Skips | Spawns `go` / Compiles Test Binary |
| :--- | :--- | ---: | ---: | ---: | :--- | :--- |
| 1 | `initsubject_test.go` | 283 | 4 | 1 | 4 / 4 | Yes (`newEngine` + `newView`) |
| 2 | `judgment_fuzz_test.go` | 45 | 1 (`Fuzz`) | 0 | 0 / 1 | No (pure in-memory algebra) |
| 3 | `judgment_test.go` | 348 | 6 | 2 | 0 / 6 | No (uses `runtimeinput.Current` on `t.TempDir()`) |
| 4 | `membership_surface_test.go` | 71 | 1 | 0 | 1 / 1 | Yes (`NewSession` + `Snapshot` for membership error check!) |
| 5 | `membership_test.go` | 121 | 2 | 0 | 0 / 2 | No (pure in-memory `&Snapshot{}`) |
| 6 | `movedreasons_test.go` | 112 | 2 | 0 | 1 / 2 | Yes (`newEngine` + `capture` + `check` in 1 of 2) |
| 7 | `oncefill_test.go` | 145 | 1 | 0 | 1 / 1 | Yes (29 parallel `writeViewModule` + `captureCheck` subtests!) |
| 8 | `outcome_test.go` | 489 | 4 | 2 | 4 / 4 | Yes (compiles `go test -c` binary + multiple `newView`s) |
| 9 | `package_unit_test.go` | 277 | 2 | 0 | 1 / 2 | Yes (`go test -c` + 11 subtest executions in 1; pure in 1) |
| 10 | `preparation_test.go` | 212 | 5 | 1 (`const`) | 5 / 5 | Yes (`newEngine` + `newView` + `unauditedTagEnv`) |
| 11 | `processaccount_test.go` | 541 | 4 | 0 | 2 / 4 | Yes (`go test -c` + 12 subtests in 1; `NewSession` in 1; pure in 2) |
| 12 | `producing_selection_test.go` | 253 | 1 | 1 | 1 / 1 | Yes (3× `go test -c` + ~24 subtest executions!) |
| 13 | `progressdiagnostic_test.go` | 77 | 1 | 0 | 0 / 1 | No (pure in-memory `Progress.Diagnostic` + `DiagnosticsTo`) |
| 14 | `progressunits_test.go` | 221 | 3 | 0 | 2 / 3 | Yes (`newEngine` + `newView` + `CaptureObserved` in 2; pure in 1) |
| 15 | `provenance_composite_test.go` | 261 | 5 | 2 | 0 / 5 | No (AST walk over repo + pure in-memory unit checks) |
| 16 | `provenance_test.go` | 101 | 2 | 0 | 0 / 2 | No (pure string/version algebra) |
| 17 | `purity_environment_test.go` | 34 | 1 | 0 | 1 / 1 | Yes (`scanSubjectsInWithBuildFlagsEnv` over temp module) |
| 18 | `purity_test.go` | 202 | 4 | 0 | 3 / 4 | Yes (`packages.Load` / `scanSubjects...` in 3; pure `go/types` in 1) |
| 19 | `raceshards_test.go` | 350 | 4 | 6 | 0 / 4 | No (AST walk over repo `_test.go` + `.github/workflows/ci.yaml`) |
| 20 | `recvname_test.go` | 121 | 2 | 0 | 0 / 2 | No (pure `go/parser` + `go/types` synthetic `packages.Package`) |
| 21 | `refusalchannels_test.go` | 142 | 2 | 0 | 2 / 2 | Yes (6× `writeViewModule` + `unauditedTagEnv` engine runs) |
| 22 | `runner_test.go` | 326 | 3 | 3 | 0 / 3 | Yes (`e.capture` in 1 — **missing `testing.Short()`!**; AST walks in 2) |
| 23 | `runtime_binding_test.go` | 371 | 4 | 0 | 3 / 4 | Yes (`go test -c` in 1; `NewSession`+`Snapshot` in 2; `quick.Check` in 1) |
| 24 | `runtime_config_collision_test.go` | 46 | 1 | 0 | 1 / 1 | Yes (`NewSession` + `Snapshot` + 2× `BindRuntime` + `Check`!) |
| 25 | `runtime_motion_test.go` | 220 | 1 | 2 | 1 / 1 | Yes (`go test -c` + 4 subtest executions + v1..v3 legacy checks) |
| 26 | `runtime_partial_motion_linux_test.go` | 181 | 2 | 0 | 2 / 2 | Yes (2× `newRuntimeMotionFixture` compiling `go test -c` + 7 runs) |
| 27 | `scanmemo_test.go` | 540 | 6 | 6 | 5 / 6 | Yes (repeated cold/warm `newView` passes in 5; pure JSON roundtrip in 1) |
| 28 | `session_directory_unix_test.go` | 42 | 1 | 0 | 0 / 1 | Yes (`NewSession` — spawns `go env` without `testing.Short()`!) |
| 29 | `session_ownership_test.go` | 65 | 1 | 0 | 0 / 1 | Yes (`NewSession` — spawns `go env` without `testing.Short()`!) |
| 30 | `session_pwd_test.go` | 234 | 1 | 0 | 1 / 1 | Yes (`go test -c` + 2× self-reexec `TestSessionCheckerProcess`) |
| 31 | `session_test.go` | 809 | 4 | 2 | 1 / 4 | Yes (`go test -c` + self-reexec in 1; `NewSession`+`Snapshot` in 2 **missing `testing.Short()`!**) |
| 32 | `session_vouches_test.go` | 31 | 1 | 0 | 0 / 1 | Yes (`NewSession` — spawns `go env` without `testing.Short()`!) |
| 33 | `shortgates_test.go` | 17 | 1 | 0 | 0 / 1 | No (AST walk via `shortgates.Pin`) |
| 34 | `snapshotreuse_test.go` | 109 | 2 | 0 | 2 / 2 | Yes (`newEngine` + `newView` + `CaptureObserved`) |
| 35 | `structural_test.go` | 89 | 4 | 0 | 0 / 4 | No (pure `reflect` / `stipulator/stipulate/structural`) |
| 36 | `subject_facts_test.go` | 190 | 3 | 1 | 1 / 3 | Yes (`newEngine` + `newView` in 1; pure in-memory in 2) |
| 37 | `testvariant_test.go` | 367 | 6 | 3 | 6 / 6 | Yes (6× `writePartitionModule` + `newEngine` + `capture`/`check`) |
| 38 | `toolchain_dependencies_test.go` | 275 | 3 | 0 | 2 / 3 | Yes (2× `cp -a --reflink=auto GOROOT` + `go run ./cmd` in 1; `newView` in 1; pure in 1) |
| 39 | `toolchainkey_test.go` | 45 | 1 | 0 | 0 / 1 | No (pure `go/types` synthetic check) |
| 40 | `toolversion_test.go` | 22 | 1 | 0 | 0 / 1 | Yes (`go test -count=1 ./...` in `toolversion/` without `testing.Short()`!) |
| 41 | `unit_cancellation_test.go` | 113 | 1 | 0 | 1 / 1 | Yes (`NewSession` + `Snapshot` + 8 barrier subtests) |
| 42 | `unit_preparation_test.go` | 59 | 1 | 0 | 1 / 1 | Yes (`NewSession` + `Snapshot` just to test `ValidateScratchNamespaces`!) |
| 43 | `unit_protocol_test.go` | 84 | 1 (`Fuzz`) | 0 | 0 / 1 | No (pure in-memory state-machine fuzzing) |
| 44 | `unscoped_facts_test.go` | 57 | 1 | 0 | 1 / 1 | Yes (`writePinnedDepModule` + 4× `runScan`) |
| 45 | `vouchfile_test.go` | 189 | 2 | 0 | 1 / 2 | Yes (`writePinnedDepModule` + 13× `newEngine` in 1; pure in 1) |

---

## 2. Exhaustive File-by-File and Test-by-Test Inventory

### 2.1 [`initsubject_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/initsubject_test.go#L1-L283) (283 lines)

- **Helpers:**
  - [`writeInitFixture(t *testing.T, dir string, files map[string]string)`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/initsubject_test.go#L11-L22): Yet another duplicate `map[string]string` module tree writer (identical to `writeModuleTree` and `writePartitionModule`).
- **Tests:**
  1. [`TestInitSubjectsCapturePositionally`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/initsubject_test.go#L30-L144) (lines 30–144):
     - **Witnesses:** Positional `init#<file>#<ordinal>` subject addressing (0-based within each file), independent closure hashes per `init` declaration, invariance under edits to unimported sibling packages (`other/other.go`), and sensitivity to edits in functions called by `init()` (`wireA()`).
     - **Setup Weight:** Heavy — writes module fixture, constructs 3 full `engine` + `view` instances (`engine`, `engine2`, `engine3`) running `go env`, `go list`, and `packages.Load` three times sequentially.
     - **Tier:** Tier 2 (Package-Scan & Closure Integration).
  2. [`TestInitSubjectUnknownOrdinalRefuses`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/initsubject_test.go#L149-L172) (lines 149–172):
     - **Witnesses:** Out-of-range ordinal (`init#a.go#1` when `a.go` has only 1 `init()`) refuses at `engine.newView` naming `init#a.go#1`.
     - **Setup Weight:** Heavy (`newEngine` + `newView`) for a subject-scan lookup refusal that could be tested directly on `scanSubjectsFromLoaded` or combined into a single `newView` call in `TestInitSubjectsCapturePositionally`.
     - **Tier:** Tier 1/2 (Subject Scan Unit / Table).
  3. [`TestInitSubjectIdentityStableAcrossOtherFiles`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/initsubject_test.go#L179-L230) (lines 179–230):
     - **Witnesses:** Per-file `init` ordinal scoping: adding `aa.go` with `func init()` gets `init#aa.go#0` without shifting `init#a.go#0`.
     - **Setup Weight:** Heavy (2× `newEngine` + `newView` + `Capture`).
     - **Tier:** Tier 1/2 (Subject Scan Unit / Table).
  4. [`TestInitOrdinalIgnoresUnnameableReceiverMethod`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/initsubject_test.go#L237-L282) (lines 237–282):
     - **Witnesses:** `func ((T)) init() {}` is a method (even with parenthesized receiver), not a package `init()` declaration, so it does not increment the `init#a.go#<ordinal>` counter.
     - **Setup Weight:** Heavy (`newEngine` + 2× `newView` + `Capture`) to test AST `fn.Recv == nil` vs `recvTypeName(fn)` in `subjectScan`! Note that `recvTypeName` already unwraps `((T))` to `"T"`, and this is purely an AST/types scan property just like `recvname_test.go`.
     - **Tier:** Tier 1 (AST/Types Scan Unit Test — belongs in the same table as `recvname_test.go`).

---

### 2.2 [`judgment_fuzz_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/judgment_fuzz_test.go#L1-L45) (45 lines)

- **Tests:**
  1. [`FuzzJudgmentDiagnosticIndependence`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/judgment_fuzz_test.go#L15-L44) (lines 15–44):
     - **Witnesses:** Pure property test over `decideAfterClosureObserved`: for all 4 `closure.RefusalKind` origins and all 16 combinations (`mask := 0..15`) of `{state.Unverifiable, observation, purity, state.BracketMoved}`, replacing `cl.Reason` and `state.Reason` with arbitrary fuzzed `text` never changes the semantic decision (`Status`, `Ground.Cause`, `Ground.Accepted`), and `state.BracketMoved` always forces `Stale` with `RuntimeInputsCause`/`Changed` and empty `AcceptedAuthority{}`.
     - **Setup Weight:** Fast, zero-subprocess in-memory fuzzing.
     - **Overlap:** Directly complements `TestJudgmentDoesNotReadDiagnosticAuthority` in `judgment_test.go` (lines 156–195). Having a separate 45-line file for a single fuzz function that calls `testPurityAuthority` defined in `judgment_test.go` is unnecessary file fragmentation; it belongs directly inside `judgment_test.go`.
     - **Tier:** Tier 1 (Pure Judgment Algebra).

---

### 2.3 [`judgment_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/judgment_test.go#L1-L348) (348 lines)

- **Helpers:**
  - [`testPurityAuthority(enabled bool) PurityAuthority`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/judgment_test.go#L15-L20): Returns `{Recorded: CallerPurity, Current: CallerPurity}` when `enabled`.
  - [`judgmentFixture(t *testing.T) (*Snapshot, Subject, Fingerprint, runtimeinput.State)`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/judgment_test.go#L24-L59): Builds an in-memory `*Snapshot` with `deferredCheckClose: true`, synthetic `observationFacts`, and a v4 base64 manifest evaluated via `runtimeinput.Current` over `t.TempDir()`.
- **Tests:**
  1. [`TestJudgmentAuthorityAndScope`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/judgment_test.go#L61-L154) (lines 61–154):
     - **Witnesses:** 10-case table testing `v.CheckObserved` authority admission, precedence, and immutability of input `Fingerprint` bytes (`observation conjunction`, `purity is independent of invalid proof`, `invalid proof`, `wrong proof subject`, `missing completeness assertion`, `policy movement`, `external dominates assertions`, `guard drift dominates external`, `source mismatch skips all authority`, `ordinary proof needs no observation`), plus verifying that `Ground.Accepted` uses current view discharges rather than copying historical `fp.*Discharges`.
     - **Setup Weight:** Fast, in-memory.
     - **Tier:** Tier 1 (Pure Judgment Algebra).
  2. [`TestJudgmentDoesNotReadDiagnosticAuthority`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/judgment_test.go#L156-L195) (lines 156–195):
     - **Witnesses:** `decideAfterClosureObserved` and `v.judgmentFor` ignore diagnostic string text (even forged `sharedDynamicStatePrefix`), preserve `SharedDynamicStateCause` culprit (`Refused`) vs budget-cut (`Unavailable`), and keep `byProof` vs `byPurity` `Ground.Accepted` distinct even when diagnostic strings match.
     - **Setup Weight:** Fast, in-memory.
     - **Tier:** Tier 1 (Pure Judgment Algebra).
  3. [`TestJudgmentRuntimeRefusalAndWindowPrecedence`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/judgment_test.go#L197-L236) (lines 197–236):
     - **Witnesses:** Observation proof cannot lift a runtime input refusal (`refused.Unverifiable = true`), whereas purity authority can; late runtime window movement (`Changed` or `Unavailable` in `v.finishRuntimeObservation`) overrides `Unverifiable`/`Valid` to `Stale` (`RuntimeInputsCause`) with zero `AcceptedAuthority{}`, but does not override an earlier guard staleness (`BuildConfigCause`).
     - **Setup Weight:** Fast, in-memory.
     - **Tier:** Tier 1 (Pure Judgment Algebra).
  4. [`TestJudgmentGuardConditions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/judgment_test.go#L238-L268) (lines 238–268):
     - **Witnesses:** 10-case table over `decide(...)` testing `Missing`, `Changed`, `Unavailable`, and `Unsupported` `CauseCondition`s across `ToolchainCause`, `RuntimeInputsCause`, `ClosureCause`, `TestVariantsCause`, and `DynamicStateStrategyCause`.
     - **Setup Weight:** Fast, in-memory.
     - **Tier:** Tier 1 (Pure Judgment Algebra).
  5. [`TestJudgmentBatchEqualsSingleAndSibling`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/judgment_test.go#L270-L297) (lines 270–297):
     - **Witnesses:** `CheckObservedBatch` agrees with per-subject `CheckObserved` and `Sibling([]Subject{s, s}).CheckObserved`, and outcome support is bound to the exact subject (`subject` is `Valid`, `other` sharing the same `fp` is `Unverifiable`).
     - **Setup Weight:** Fast, in-memory.
     - **Tier:** Tier 1 (Pure Judgment Algebra).
  6. [`TestJudgmentApplicabilityNeedsCurrentProofAndOriginalSupport`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/judgment_test.go#L299-L347) (lines 299–347):
     - **Witnesses:** 5-case table verifying that `InertTestVariantExtension` applicability requires both current observability with `outcome.Method` and original outcome-supported runtime inputs (not `identity-only` or `absent`).
     - **Setup Weight:** Fast, in-memory.
     - **Tier:** Tier 1 (Pure Judgment Algebra).

---

### 2.4 [`membership_surface_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/membership_surface_test.go#L1-L71) (71 lines)

- **Tests:**
  1. [`TestViewMembershipRefusalsRetainSelectionScope`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/membership_surface_test.go#L13-L70) (lines 13–70):
     - **Witnesses:** When a subject `g` is declared in the package (`all` includes `f, g`) but excluded in a `Sibling([]Subject{f})` projection (`selected`), calling `Capture`, `CaptureObserved`, `SourceFilesFor`, `TestVariantLedger`, `AttachObservation`, or `RuntimeBinding.CurrentFacts` on `g` returns `*UnknownSubjectsError{Scope: SelectedView, Subjects: []Subject{g}}` without starting precise analysis (`beforePreciseAnalysis` hook) and without sealing the valid sibling `f`.
     - **Setup Weight:** **Unnecessarily Heavy!** Writes a `go.mod` + `p.go` module, calls `NewSession` and `session.Snapshot` (spawning `go env`, `go list`, `packages.Load`) solely to construct a `*Snapshot` with two subjects `f, g` and project `selected, _ := all.Sibling([]Subject{f})`.
     - **Duplication / Consolidation:** Every single check in lines 38–69 (`Capture`, `CaptureObserved`, `SourceFilesFor`, `TestVariantLedger`, `AttachObservation`, `bound.CurrentFacts`) checks membership against `v.facts.maximal` / `v.memberSet` BEFORE touching any compiler or filesystem state! It can run in < 1ms on an in-memory `&Snapshot{}` fixture inside `membership_test.go`.
     - **Tier:** Tier 1 (belongs in `membership_test.go`, zero subprocesses needed).

---

### 2.5 [`membership_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/membership_test.go#L1-L121) (121 lines)

- **Tests:**
  1. [`TestMembershipRefusalsCollectOrderedSubjectsAndScope`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/membership_test.go#L14-L42) (lines 14–42):
     - **Witnesses:** `v.Sibling(...)` and `requireSubjects(...)` return `*UnknownSubjectsError` with `ParentView` or `SelectedSource` scope, deduplicating unknown subjects in first-seen request order; duplicate known subjects deduplicate cleanly; `v.Sibling(nil)` refuses.
     - **Setup Weight:** Fast, in-memory `&Snapshot{}`.
     - **Tier:** Tier 1 (View Membership & Batch Preparation Algebra).
  2. [`TestRecordedBatchPreparationHasDeterministicCompleteTiers`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/membership_test.go#L44-L120) (lines 44–120):
     - **Witnesses:** `CheckBatch` and `CheckObservedBatch` validate recorded batches in 3 strict deterministic tiers (`tier 0: RecordShapeRefusal` -> `tier 1: RecordKindRefusal` -> `tier 2: UnknownSubjectsError{Scope: SelectedView}`), sorting subjects by `(Package, Symbol)` axes independently (so `"a"."z.F" < "a.z"."F"`), performing zero runtime/analysis work on refusal, and returning an empty map on `nil` input.
     - **Setup Weight:** Fast, in-memory `&Snapshot{}`.
     - **Overlap:** Overlaps with `TestMalformedRecordRefusesTheBatchBeforeAnyWindow` in `preparation_test.go` (lines 88–131), which pays a full `newEngine` + `newView` + `Capture` over a temp module just to test `bad.ResultKind = Kind(99)` on `CheckBatch` and `CheckObservedBatch`!
     - **Tier:** Tier 1 (View Membership & Batch Preparation Algebra).

---

### 2.6 [`movedreasons_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/movedreasons_test.go#L1-L112) (112 lines)

- **Tests:**
  1. [`TestStaleRuntimeInputsNamesTheMover`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/movedreasons_test.go#L19-L93) (lines 19–93):
     - **Witnesses:** `REQ-inputs-path-identities`: when a bracketed runtime file (`data/fixture.txt`) changes after capture, `e.check` returns `Stale` with `Reason` containing `"moved: path data/fixture.txt"` and `Ground.Cause == {RuntimeInputsCause, Changed}`. Also tests `view.withMovedInputs` directly to verify that decoration is keyed on semantic `Ground.Cause`, not `v.Reason` string matching.
     - **Setup Weight:** Heavy (`newEngine` + `e.capture` + `2× e.check` spawning `go` commands), even though lines 83–92 (`view.withMovedInputs` on `&Snapshot{engine: e, moduleDir: tmp}`) demonstrate that `withMovedInputs` only needs an engine/dir and a `Fingerprint` with `RuntimeInputs`!
     - **Tier:** Tier 1/2 (`withMovedInputs` is a fast unit test; end-to-end check is covered by `runtime_motion_test.go`).
  2. [`TestDriftRefusalComponents`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/movedreasons_test.go#L98-L111) (lines 98–111):
     - **Witnesses:** Pure helper checks on `differingGuard` (`"buildconfig"` vs fallback `"guards"`) and `compareObservationProof` (`"captured observable, now not observable: reaches os.Open"`).
     - **Setup Weight:** Fast (< 0.1ms), pure in-memory. Yet it lives in a file that skips on `testing.Short()` in its first test.
     - **Tier:** Tier 1 (Pure Judgment / Diagnostic Formatting).

---

### 2.7 [`oncefill_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/oncefill_test.go#L1-L145) (145 lines)

- **Tests:**
  1. [`TestOnceFilledMemoKeepsTheProof`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/oncefill_test.go#L17-L144) (lines 17–144):
     - **Witnesses:** `REQ-closure-shared-dynamic-state-receiver-proof`: tests 23 table cases + 2 promoted-implementer subtests + 6 shared/reachable/copied `sync.Once` subtests + 1 test-file fake `init()` subtest + 1 unexported-method-with-no-declaration subtest (**33 subtests total**). Checks when a receiver-rooted `sync.Once.Do` memo fill or closed-interface dispatch preserves the receiver read-only proof on package-level variable `G` vs when it downgrades `F` to `Unverifiable` naming `example.com/view.G`.
     - **Setup Weight:** **Extremely Heavy!** Spawns **33 separate `writeViewModule` + `captureCheck` executions** (each running `go env`, `go list`, `packages.Load`, closure hashing, and `Check` — two full engine views per `captureCheck`, i.e., **66 view constructions**!) in parallel.
     - **Consolidation Opportunity:**
       1. 32 of the 33 subtests use the exact same package structure (`package view`) and only vary the method declarations on `type gen struct` (or small struct variations) and which method `F_i()` calls! Putting all 23+6+3 independent types/functions (`G1..G32`, `F1..F32`) into **one** module fixture (or testing `scanSubjectsFromLoaded` directly over a single in-memory `packages.Load`) reduces 66 full engine view passes to **1**.
     - **Tier:** Tier 2 (Shared-Dynamic-State Receiver Proof Harness).

---

### 2.8 [`outcome_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/outcome_test.go#L1-L489) (489 lines)

- **Helpers:**
  - [`writeSupportedViewModule(t *testing.T) string`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/outcome_test.go#L17-L25): Calls `writeObservedViewModule(t)` and overwrites `observed_test.go` with `TestRead` calling `os.Getenv("OUTCOME_VALUE")`. (Used across `outcome_test.go`, `processaccount_test.go`, `toolchain_dependencies_test.go`, `unit_cancellation_test.go`.)
  - [`supportedObservation(t *testing.T, view *Snapshot, root, dir, process, log string) runtimeinput.Observation`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/outcome_test.go#L29-L53): Captures a `ProducerFrame`, calls `view.PrepareOutcomeSupport`, mints a completion receipt, writes a synthetic testlog, and calls `frame.Observe`.
- **Tests:**
  1. [`TestOutcomeSupportCannotCrossTestVariantChange`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/outcome_test.go#L55-L95) (lines 55–95):
     - **Witnesses:** Editing a test body (`os.Getenv` -> `os.ReadFile`) changes `TestVariantClosure`, so attaching an observation supported under the old `Snapshot` to the new `Fingerprint` yields `Unverifiable` on `CheckObserved`.
     - **Setup Weight:** Medium/Heavy (2× `engine.newView` + `CaptureObserved`), though the underlying check is `runtimeinput.HasOutcomeSupport(fp.RuntimeInputs, outcomeSubject(fp, subject))` where `outcomeSubject` hashes `fp.TestVariantClosure` — already tested in-memory in line 276 of the same file!
     - **Tier:** Tier 1/2.
  2. [`TestOutcomePreparationRejectsInvalidAndEndedTransactions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/outcome_test.go#L97-L149) (lines 97–149):
     - **Witnesses:** `PrepareOutcomeSupport` rejects empty subjects, NUL byte in `frame.PkgDir`, empty process identity, and mid-issuance sealing (`ErrViewSealed`) or context cancellation (`context.Canceled`) via `view.beforeOutcomeIssue`.
     - **Setup Weight:** Heavy (3× `engine.newView` over disk module), even though `PrepareOutcomeSupport` input validation and `beforeOutcomeIssue` sealing/cancellation only need a pre-populated in-memory `Snapshot`!
     - **Tier:** Tier 1 (Unit Protocol / Outcome Preparation).
  3. [`TestOutcomeSupportBindsActualExecutionAndRecordedSubject`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/outcome_test.go#L151-L371) (lines 151–371):
     - **Witnesses:** End-to-end `go test -c` compilation and execution of `TestEnv` (supported, exit 0 -> `Valid`), `TestFail` (supported, exit 1 -> `Valid`), `TestFile` (unsupported `os.ReadFile` -> `Unverifiable`), `outcomeSubject` sensitivity to `MaximalClosure`/`TestVariantClosure`/`Toolchain`/`BuildConfig`/`Strategy`, cross-subject support rejection (`TestOther`), identity-only observation rejection, env movement staleness (`OUTCOME_VALUE=changed`), mixed-subject (`TestEnv` + `TestFile`) process support refusal naming `TestFile`, and `Validate` obligation after `PrepareOutcomeSupport`.
     - **Setup Weight:** Heavy (`go test -c` + 3 test binary runs + ~8 `engine.newView` calls).
     - **Tier:** Tier 3 (Subprocess / Retained-Binary Integration).
  4. [`TestStaticReachabilityAdmitsEffectFreeSubjectWithIdentityOnlyObservation`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/outcome_test.go#L373-L488) (lines 373–488):
     - **Witnesses:** Effect-free subjects (`PureAdd`, `TestPure`) receive `gofresh/static-reachability@1` outcome authority under an identity-only observation (`Valid`), downgrading their `ObservationProof.Evidence` seal via `observationProofEvidenceMode(fp, false)` refuses (`Unverifiable`), and effectful subjects in the same package (`TestEnv`, `TestFile`) remain `Unverifiable` under identity-only observation.
     - **Setup Weight:** Medium/Heavy (2× `engine.newView` + `CaptureObserved` over 4 subjects).
     - **Tier:** Tier 2 (Observability & Static-Reachability Integration).

---

### 2.9 [`package_unit_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/package_unit_test.go#L1-L277) (277 lines)

- **Tests:**
  1. [`TestPackageUnitOwnsTheWholeExecution`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/package_unit_test.go#L21-L247) (lines 21–247):
     - **Witnesses:** `PackageUnit` lifecycle (`BeginPackage`, `Register`, `Submit`, `Close`, `Abort`) over a compiled `package.test` binary:
       - Subject slice ownership/cloning (`requested` and `process.Subjects()` mutation resistance) and single-process-per-unit enforcement.
       - 3 incomplete closing subtests (`contributor`, `terminal`, `never started`).
       - 5 execution disposition subtests (`two observing subjects` -> `SupportedObservation`, `[Valid, Valid]`; `unsupported contributor` -> `IdentityObservation`, `[Unverifiable, Unverifiable]`; `purity does not promote sibling` -> `IdentityObservation`, `[Unverifiable, Valid]`; `ordinary failing test` -> `SupportedObservation`, `[Valid, Valid]`; `abnormal original attempt` -> `IncompleteObservation`, `[Unverifiable, Unverifiable]`).
       - `independent retry`, `cancellation keeps closed sibling`, and `closing drift exposes no prefix` (`ErrViewChanged`).
     - **Setup Weight:** Heavy (`go test -c` + 8 test binary executions).
     - **Overlap:** Shares significant structural overlap with `producing_selection_test.go` and `processaccount_test.go`.
     - **Tier:** Tier 3 (Subprocess / Retained-Binary Integration).
  2. [`TestPackageUnitRefusesIncompatibleScope`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/package_unit_test.go#L249-L276) (lines 249–276):
     - **Witnesses:** Pure in-memory `RuntimeBinding.BeginPackage` scope checks: rejects `nil`, multi-subject under `SingleSubject: true`, cross-package `[a, c]`, and unknown subjects; deduplicates `[a, a]` and preserves order `[b, a]` under `SingleSubject: false`.
     - **Setup Weight:** Fast (< 0.1ms), zero subprocesses.
     - **Tier:** Tier 1 (Unit Protocol State Machine).

---

### 2.10 [`preparation_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/preparation_test.go#L1-L212) (212 lines)

- **Helpers:**
  - `const preparationSource = "package view\n\nfunc F() int { return 1 }\n\nfunc G() int { return 2 }\n"` (line 13).
- **Tests:**
  1. [`TestUnknownSubjectRefusesBeforeTheMaximalFold`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/preparation_test.go#L18-L61) (lines 18–61):
     - **Witnesses:** Unknown subject refuses at `engine.newView` before `viewTestHooks.maximalBatch` runs; batch with multiple unknown subjects returns `*UnknownSubjectsError` in deduplicated request order.
     - **Setup Weight:** Heavy (`newEngine` + 2× `newView`).
     - **Tier:** Tier 2 (Engine View Construction Pipeline).
  2. [`TestModuleCacheViewPackageRefusesBeforeTheTypedLoad`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/preparation_test.go#L65-L84) (lines 65–84):
     - **Witnesses:** Requesting a subject in a module-cache dependency (`golang.org/x/sync/errgroup.Group.Go`) refuses after `go list` before `viewTestHooks.typedLoad` runs.
     - **Setup Weight:** Heavy (`writePinnedDepModule` + `newEngine` + `newView`).
     - **Tier:** Tier 2 (Engine View Construction Pipeline).
  3. [`TestMalformedRecordRefusesTheBatchBeforeAnyWindow`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/preparation_test.go#L88-L131) (lines 88–131):
     - **Witnesses:** `CheckBatch` and `CheckObservedBatch` refuse a batch containing `Kind(99)` before opening any runtime-input window (`viewTestHooks.runtimeWindow`).
     - **Setup Weight:** **Unnecessarily Heavy!** Writes a module and runs `newEngine` + `newView` + `Capture` to test the exact same `prepareRecordedBatch` tier-0 check that `TestRecordedBatchPreparationHasDeterministicCompleteTiers` in `membership_test.go` (lines 44–120) already tests in-memory with `viewTestHooks.runtimeWindow`!
     - **Duplication:** 100% redundant with `membership_test.go:44-120`.
     - **Tier:** Tier 1 (Delete / fold into `membership_test.go`).
  4. [`TestMissingAttachmentRefusesBeforeTheValidationObservation`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/preparation_test.go#L135-L163) (lines 135–163):
     - **Witnesses:** Calling `view.Validate` after `view.CaptureObserved` without `AttachObservation` refuses with `"no attached completed observation"` before `viewTestHooks.observe` runs.
     - **Setup Weight:** Heavy (`writeObservedViewModule` + `newEngine` + `newView` + `CaptureObserved`), even though `Validate()` checks `len(v.capturedObserved) > len(v.attachedObserved)` under `v.mu` before calling `reobserve`!
     - **Tier:** Tier 1 (can be tested on an in-memory `Snapshot`, or alongside `outcome_test.go:363`).
  5. [`TestToolchainSelectionNoticeAnnouncedAtViewConstruction`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/preparation_test.go#L171-L211) (lines 171–211):
     - **Witnesses:** Under `unauditedTagEnv(t)` with `-tags=badstd`, `engine.newView` emits exactly one `Progress{Phase: "toolchain-unaudited"}` event before any `list`/`typecheck`/`hash`/`load`/`prove` work event.
     - **Setup Weight:** Heavy (`unauditedTagEnv` + `newEngine` + `newView`).
     - **Tier:** Tier 2 (Progress & Toolchain Audit Integration).

---

### 2.11 [`processaccount_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/processaccount_test.go#L1-L541) (541 lines)

- **Tests:**
  1. [`TestProcessAccountIsOwnedDataWithoutProducingCapability`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/processaccount_test.go#L20-L53) (lines 20–53):
     - **Witnesses:** Reflection walk over `ProcessAccount` confirming it contains only plain value fields (`struct`, `string`, `bool`, `uint8`) with zero methods and no embedded `Fingerprint`, `Verdict`, `Observation`, `OutcomeSupport`, `ProducerFrame`, or `Contribution`; also checks `nil` and zero-value `Unit.Account()` / `PackageUnit.Account()` return `(ProcessAccount{}, false)`.
     - **Setup Weight:** Fast (< 0.1ms), pure reflection/in-memory.
     - **Tier:** Tier 1 (Structural / Value-Graph & Unit Protocol).
  2. [`TestProcessAccountPreservesFinalizedFacts`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/processaccount_test.go#L55-L409) (lines 55–409):
     - **Witnesses:** Exhaustive end-to-end verification of `u.Account()` across 12 subtests:
       - `successful account owns canonical data` (matches `runtimeinput.CompletedState`, immune to caller mutation, capture file removal, or subsequent `u.Abort()`).
       - 4 unfinalized endings (`missing terminal`, `never started`, `cancelled`, `aborted` -> `Observation == UnknownObservation`, `Inputs == runtimeinput.State{}`).
       - `abnormal completion` and `missing capture` -> `IncompleteObservation` with `Inputs.Unverifiable == true`.
       - `identity-only singleton` (`BeginIdentity` -> `IdentityObservation`).
       - `abort after observation` and `caller cancellation outranks abort after observation` (pausing at `viewTestHooks.observe` barrier).
       - `package source drift` and `singleton source drift` (`Close` returns `ErrViewChanged` and zero result, but `u.Account()` retains the observed `ProcessAccount`!).
     - **Setup Weight:** Heavy (`go test -c` + 9 test binary executions).
     - **Overlap:** Heavily overlaps with `package_unit_test.go` and `session_test.go` (which also compile a test binary and exercise `NeverStarted`, `AbnormalCompletion`, `BeginIdentity`, source drift, and abort during close).
     - **Tier:** Tier 3 (Subprocess / Retained-Binary Integration).
  3. [`TestProcessAccountDuringRegistration`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/processaccount_test.go#L411-L507) (lines 411–507):
     - **Witnesses:** Pausing `u.Register` at `beforeOutcomeIssue` barrier: `u.Account()` reports `ProcessAccount{Process: "reserved-process", Artifact: "declared-artifact", Prepared: false}` while pending, transitions to `Prepared: true` on completion (or stays `Prepared: false` on context cancellation), and 100 concurrent `u.Account()` readers during `u.Submit` never observe a torn `Terminal` struct.
     - **Setup Weight:** Medium/Heavy (`NewSession` + `Snapshot` over `writeSupportedViewModule`), even though `unit_cancellation_test.go` builds the exact same session/snapshot to pause at `beforeOutcomeIssue`!
     - **Tier:** Tier 2 (or Tier 1 with an in-memory `Snapshot`).
  4. [`TestProcessAccountRetainsObservationComputedBeforeAbort`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/processaccount_test.go#L509-L540) (lines 509–540):
     - **Witnesses:** Pure white-box interleaving test on `&PackageUnit{producing: &producingUnit{phase: unitClosing, ...}}`: if `u.Abort()` runs before `u.producing.recordObservation(observation, reason)`, `u.Account()` still records the computed observation facts while `u.Close()` refuses with `ErrUnitClosed`.
     - **Setup Weight:** Fast (< 0.5ms), in-memory.
     - **Tier:** Tier 1 (Unit Protocol State Machine).

---

### 2.12 [`producing_selection_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/producing_selection_test.go#L1-L253) (253 lines)

- **Helpers:**
  - [`testUnitsSelectProducingEvidence(t *testing.T, sourceOnly, mutating bool)`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/producing_selection_test.go#L29-L252): Builds a module and compiles `package.test` for 3 modes (`source`, `mixed`, `mutating`), then runs 9 table cases + `independent closing and corruption refusal`.
- **Tests:**
  1. [`TestUnitsSelectProducingEvidence`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/producing_selection_test.go#L17-L27) (lines 17–27):
     - **Witnesses:** How `producingUnit` selects among source-only closure proof, `//gofresh:pure` directive authority, and runtime observation proof across singleton (`Begin`) and package (`BeginPackage`) units, with and without `ProcessDescription.Capture`:
       - `singleton without capture`, `package without capture`, `optional identity capture` (on `TestScalar`).
       - `purity without capture`, `purity identity capture`, `mixed supported roster` (`[TestPure, TestEnv]`), `purity is not preservation` (`[TestEnv, TestMutator]` where `TestMutator` calls `os.Setenv`), `external defeats caller purity` (`TestExternal`), `observing missing capture` (`TestEnv` without capture -> `IncompleteObservation`, `Unverifiable`).
       - `independent closing and corruption refusal` (mutating `first.execution.fingerprints[plain].PurityAssertion` causes `first.close` to fail closed without tainting `retry`).
     - **Setup Weight:** Very Heavy — compiles **3 separate `go test -c` binaries** (`source`, `mixed`, `mutating`) and spawns **~18 test binary executions** plus `session.Snapshot` and `BindArtifact` calls.
     - **Tier:** Tier 3 (Subprocess / Retained-Binary Integration).

---

### 2.13 [`progressdiagnostic_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/progressdiagnostic_test.go#L1-L77) (77 lines)

- **Tests:**
  1. [`TestProgressDiagnosticRendersDetailBearingEventsOnly`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/progressdiagnostic_test.go#L16-L76) (lines 16–76):
     - **Witnesses:** `Progress.Diagnostic()` formatting on 6 cases (4 detail-bearing phases `toolchain-unaudited`, `analysis-unavailable`, `listing-unmodelled` with newline folding to `; `, `cancelled` with `\r\n` folding; 2 non-detail phases `load`, `served` returning `"", false`) and `DiagnosticsTo(&out)` prefixing `"gofresh: "` + concurrency serialization test (8 bursts × 256 goroutines writing 200-byte lines concurrently without tearing).
     - **Setup Weight:** Fast, pure in-memory.
     - **Tier:** Tier 1 (Progress & Diagnostic Algebra — combine with `TestKeptOnCancelDetailRendersItsCounts` from `progressunits_test.go` and `TestUnitPhasesAreTheDocsList` from `provenance_composite_test.go`).

---

### 2.14 [`progressunits_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/progressunits_test.go#L1-L221) (221 lines)

- **Tests:**
  1. [`TestProgressReportsUnitsServedAndKept`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/progressunits_test.go#L15-L157) (lines 15–157):
     - **Witnesses:**
       - Cold view construction over 2 packages (`a`, `b`) emits `list` and `hash` (`Index` in `1..2`, `Total: 2`) for each package and a shared `typecheck` (`Total >= 2`).
       - Cold `CaptureObserved` runs `prove`; warm `CaptureObserved` on a new engine over the same `XDG_CACHE_HOME` emits `Progress{Phase: "served", Served: "observability proof", Index: 1, Detail: ""}` and zero `prove` or detail-bearing events.
       - Cancelling `CaptureObserved` at `viewTestHooks.beforeAnalysis` emits one `Phase: "cancelled"` event (`"0 observability proof slices and 0 scans persisted this operation; a rerun serves them"`).
       - Non-context failure (unknown subject) emits no `cancelled` event.
     - **Setup Weight:** Heavy (writes 2-package module, builds 3 engines/views, runs cold + warm `CaptureObserved`). Note: Uses `t.Setenv("XDG_CACHE_HOME", t.TempDir())` without preserving `GOCACHE` explicitly, though `GOENV` is not `off` here.
     - **Tier:** Tier 2 (Engine Progress & Memo Integration).
  2. [`TestOperationBoundaryReportsOncePerOperation`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/progressunits_test.go#L163-L202) (lines 163–202):
     - **Witnesses:** Nested `engine.beginOperation` calls report `served` and `cancelled` only once when the outermost `outerDone(&cancelled)` completes.
     - **Setup Weight:** **Unnecessarily Heavy!** Calls `writeViewModule` + `newEngine(withDir(dir))` + `closureNewAt(dir)` (spawning `go env`) and skips on `testing.Short()`, even though `beginOperation` and `accountPass` only inspect `ctx` and `hasher.Served(...)` in memory!
     - **Tier:** Tier 1 (Pure Progress Accounting — does not need disk module or `testing.Short()`).
  3. [`TestKeptOnCancelDetailRendersItsCounts`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/progressunits_test.go#L207-L220) (lines 207–220):
     - **Witnesses:** Pure string formatting of `keptOnCancelDetail(proofs, scans)` for `(1, 1)`, `(1, 3)`, `(0, 0)`.
     - **Setup Weight:** Fast (< 0.1ms), pure in-memory.
     - **Tier:** Tier 1 (Progress & Diagnostic Algebra).

---

### 2.15 [`provenance_composite_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_composite_test.go#L1-L261) (261 lines)

> **Architectural Smell:** Despite being named `provenance_composite_test.go`, this file is a grab-bag of **three completely unrelated domains**: (1) `Progress` phase classification and AST walking (`TestEveryEmittedPhaseIsClassified`, `TestEmittedPhaseWalkReadsEveryEmitterShape`, `TestUnitPhasesAreTheDocsList`), (2) `ToolchainProvenance` (`TestToolchainProvenanceIsOneRefusal`), and (3) `ParseVouchEntries` (`TestParseVouchEntriesIsASet`)!

- **Helpers:**
  - [`emittedPhases(root string) (map[string]bool, error)`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_composite_test.go#L98-L158): Walks non-test `.go` files under `root` parsing calls to `emitProgress`, `emitUnit`, `emitDiagnostic`, `Unit`, and `Progress{Phase: "..."}` composite literals.
  - [`mustProvenance(t *testing.T, sampler ToolchainSampler) *ToolchainProvenance`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_composite_test.go#L203-L210).
- **Tests:**
  1. [`TestEveryEmittedPhaseIsClassified`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_composite_test.go#L30-L49) (lines 30–49):
     - **Witnesses:** Every `Progress.Phase` literal emitted anywhere in production code is in `UnitPhases() ∪ {"served", "cancelled", "budget-exhausted"} ∪ {"toolchain-unaudited", "analysis-unavailable", "listing-unmodelled"}`, and every unit/diagnostic phase is emitted at least once.
     - **Setup Weight:** Fast AST walk over repository `.go` files.
     - **Tier:** Tier 4 (Repo Hygiene / Static Source Invariant).
  2. [`TestEmittedPhaseWalkReadsEveryEmitterShape`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_composite_test.go#L55-L94) (lines 55–94):
     - **Witnesses:** Self-test of the test helper `emittedPhases` over synthetic `.go` files in `t.TempDir()`.
     - **Tier:** Tier 4 (Meta-test for `emittedPhases`).
  3. [`TestToolchainProvenanceIsOneRefusal`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_composite_test.go#L165-L199) (lines 165–199):
     - **Witnesses:** `NewToolchainProvenance` and `ToolchainProvenance.Check`: wraps sampler errors and version skew in `*ToolchainProvenanceError`; returns sampled version on agreement; refuses `nil` interface, typed-nil `*gotool.Sampler`, `SampleFunc(nil)`, and zero-value `ToolchainProvenance{}` with untyped `ErrNoSampler`.
     - **Setup Weight:** Fast (< 0.1ms), pure in-memory.
     - **Tier:** Tier 1 (belongs in `provenance_test.go`).
  4. [`TestParseVouchEntriesIsASet`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_composite_test.go#L216-L227) (lines 216–227):
     - **Witnesses:** `ParseVouchEntries` deduplicates and sorts `IMPORT-PATH:VARIABLE` entries into `IMPORT-PATH.VARIABLE`, refuses the whole slice on a malformed entry, and returns empty on `nil`.
     - **Setup Weight:** Fast (< 0.1ms), pure in-memory.
     - **Tier:** Tier 1 (belongs in `vouchfile_test.go`, which already tests `ParseVouchEntry` and `ReadVouchFile`!).
  5. [`TestUnitPhasesAreTheDocsList`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_composite_test.go#L233-L260) (lines 233–260):
     - **Witnesses:** `UnitPhases()` returns a defensive copy of `{"hash", "list", "load", "observe", "prove", "runtime", "typecheck"}` and `Progress.IsUnit()` agrees with it.
     - **Setup Weight:** Fast (< 0.1ms), pure in-memory.
     - **Tier:** Tier 1 (belongs in `progressdiagnostic_test.go` / `progress_test.go`).

---

### 2.16 [`provenance_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_test.go#L1-L101) (101 lines)

- **Tests:**
  1. [`TestToolchainSkewComparesLanguageSeries`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_test.go#L14-L77) (lines 14–77):
     - **Witnesses:** `ToolchainSkew` and `toolchainSkew(binary, ambient)` + `gotool.LanguageSeries`: same language series (ignoring patch/vendor/OS suffixes and trailing CRLF/LF or devel hash) agrees; newer frontend over older ambient within same major (`go1.27` over `go1.26`) agrees; older frontend over newer ambient (`go1.26` over `go1.27`) refuses; cross-major (`go3` vs `go1` in either direction) refuses; unidentifiable version on either or both sides refuses naming `"unidentifiable"`.
     - **Setup Weight:** Fast (< 0.1ms), pure string algebra.
     - **Tier:** Tier 1 (Toolchain Provenance Algebra).
  2. [`TestToolchainSkewLabelsTheBinarySide`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_test.go#L82-L100) (lines 82–100):
     - **Witnesses:** `ToolchainSkew("go99.1.0")` formats `runtime.Version()` as the `"binary built with ..."` side and `"go99.1.0"` as the `"ambient toolchain ..."` side, each with its own language series.
     - **Setup Weight:** Fast (< 0.1ms), pure string algebra.
     - **Tier:** Tier 1 (Toolchain Provenance Algebra — merge with `TestToolchainProvenanceIsOneRefusal` from `provenance_composite_test.go`).

---

### 2.17 [`purity_environment_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity_environment_test.go#L1-L34) (34 lines)

- **Tests:**
  1. [`TestPurityScanUsesSuppliedEnvironment`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity_environment_test.go#L10-L33) (lines 10–33):
     - **Witnesses:** `scanSubjectsInWithBuildFlagsEnv` honors `GOFLAGS=-tags=special` in its supplied `env` slice so `special.go` (`//gofresh:pure func F()`) is selected over `default.go`.
     - **Setup Weight:** Heavy (`packages.Load` over temp module) in a standalone 34-line file.
     - **Consolidation:** Single point-fix regression test that belongs directly inside `purity_test.go`.
     - **Tier:** Tier 2 (Subject & Directive Scan).

---

### 2.18 [`purity_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity_test.go#L1-L202) (202 lines)

- **Tests:**
  1. [`TestScanPureDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity_test.go#L19-L51) (lines 19–51):
     - **Witnesses:** `REQ-purity-directive`: `scanPureDirectives` over `github.com/greatliontech/gofresh/closure/fixtures/puredirective` marks `Asserted`, `T.Asserted`, and external-test `BenchmarkXAsserted` as pure, and leaves `NotAsserted`, `SpacedDirective`, `T.NotAsserted`, `BenchmarkXNotAsserted` unmarked.
     - **Setup Weight:** Medium (`packages.Load` over existing fixture package).
     - **Tier:** Tier 2 (Subject & Directive Scan).
  2. [`TestScanAcceptsUniverseMethodAcrossTestVariants`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity_test.go#L63-L90) (lines 63–90):
     - **Witnesses:** `REQ-purity-directive`: a type embedding `error` (`type E = interface{ error }`, `type T struct{ error }`) scanned across both production and in-package test variants does not trigger a false-positive ambiguous-subject refusal on `error.Error`.
     - **Setup Weight:** Medium (`scanPureDirectivesIn` calling `packages.Load` over temp module), even though `TestDeclarationKeysIgnoreBuildVariantIdentity` (lines 179–201) tests the exact underlying `objectDeclarationKey` / `nodeDeclarationKey` cause in-memory, or `scanSubjectsFromLoaded` can be called on synthetic `packages.Package`s without spawning `go list`!
     - **Tier:** Tier 2 (Subject & Directive Scan).
  3. [`TestScanKeepsRecompiledDependencySubjectsUnderOwnPackage`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity_test.go#L102-L171) (lines 102–171):
     - **Witnesses:** When `a_test` imports `r` and `r` imports `a`, `go list -test` produces a recompiled dependency variant `r [a.test]` with `ForTest == "example.com/m/a"`. Verifies that `scanSubjectsInWithBuildFlagsEnv` attributes `r`'s symbols (`G`, `Use`) only to `example.com/m/r` and never leaks `a`'s `//gofresh:pure` on `a.G` to `r.G`.
     - **Setup Weight:** **Calls `packages.Load` TWICE** over the same temp module: once in lines 131–136 just to assert `r [a.test]` exists, and a second time inside `scanSubjectsInWithBuildFlagsEnv` in line 149! Calling `scanSubjectsFromLoaded` on the already-loaded `loaded` packages would cut the `packages.Load` cost in half.
     - **Tier:** Tier 2 (Subject & Directive Scan).
  4. [`TestDeclarationKeysIgnoreBuildVariantIdentity`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity_test.go#L179-L201) (lines 179–201):
     - **Witnesses:** `objectDeclarationKey` and `nodeDeclarationKey` produce identical keys for `production` (`ID: "example.com/p"`) and `variant` (`ID: "example.com/p [example.com/p.test]"`) on position-less universe objects (`error.Error`, `ast.NewIdent("f")`), while distinguishing `error.Error` from `len`.
     - **Setup Weight:** Fast (< 0.1ms), pure in-memory `go/types` + `go/ast`.
     - **Tier:** Tier 1 (Subject & Directive Scan Unit).

---

### 2.19 [`raceshards_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L1-L350) (350 lines)

- **Types & Helpers:**
  - [`type raceShard struct`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L21-L24)
  - [`raceShardsOf(t *testing.T, workflow string) []raceShard`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L30-L41)
  - [`parseRaceShards(workflow string) ([]raceShard, error)`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L44-L68)
  - [`isTestName(name, prefix string) bool`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L73-L82)
  - [`testFunctions(root string) ([]string, error)`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L92-L136)
  - [`takesPointerTo(fn *ast.FuncDecl, name string) bool`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L144-L159)
  - [`shardPartitionFaults(shards []raceShard, names []string) ([]string, error)`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L171-L215)
- **Tests:**
  1. [`TestRaceShardsPartitionEveryTest`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L222-L241) (lines 222–241):
     - **Witnesses:** Parses `race-shards` from `.github/workflows/ci.yaml` and walks all `_test.go` files in the repository, asserting every `Test*`, `Example*`, and `Fuzz*` function matches Performing an exact partition (matched by ровно 1 shard regex).
     - **Setup Weight:** Fast AST walk over repo `_test.go` files.
     - **Tier:** Tier 4 (Repo / CI Hygiene).
  2. [`TestShardPartitionJudgesEveryName`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L248-L286) (lines 248–286):
     - **Witnesses:** Self-test of test helper `shardPartitionFaults`.
     - **Tier:** Tier 4 (Meta-test for test helper).
  3. [`TestRaceShardsReadingRefusesEveryOtherShape`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L291-L310) (lines 291–310):
     - **Witnesses:** Self-test of test helper `parseRaceShards`.
     - **Tier:** Tier 4 (Meta-test for test helper).
  4. [`TestTestFunctionsWalkMirrorsGoTest`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/raceshards_test.go#L318-L349) (lines 318–349):
     - **Witnesses:** Self-test of test helper `testFunctions` over a temp directory tree.
     - **Tier:** Tier 4 (Meta-test for test helper).

---

### 2.20 [`recvname_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/recvname_test.go#L1-L121) (121 lines)

- **Tests:**
  1. [`TestRecvTypeNameReducesEveryReceiverForm`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/recvname_test.go#L21-L60) (lines 21–60):
     - **Witnesses:** `recvTypeName(fd)` reduces `T`, `*T`, `(T)`, `(*T)`, `((*T))`, `(((T)))`, `(P[X])`, `((*P[X, Y]))` to the base type name (`"T"` or `"P"`), and returns `""` on invalid receivers (`pkg.T`, `[]T`, or empty `&ast.FieldList{}`).
     - **Setup Weight:** Fast (< 0.5ms), pure `go/parser`.
     - **Tier:** Tier 1 (AST/Types Scan Unit).
  2. [`TestUnnameableReceiverNeverMintsPlainFunctionSubject`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/recvname_test.go#L67-L120) (lines 67–120):
     - **Witnesses:** `scanSubjectsFromLoaded` over a synthetic `packages.Package` containing `//gofresh:pure func (r pkg.T) Foo() {}` mints zero subjects (never a phantom plain function `Foo`) and does not collide with or leak `//gofresh:pure` onto a real `func Foo() {}`.
     - **Setup Weight:** Fast (< 1ms), uses `scanSubjectsFromLoaded` directly over `parser.ParseFile` + `types.NewPackage` without spawning `go list`!
     - **Note:** This proves how `initsubject_test.go` (`TestInitOrdinalIgnoresUnnameableReceiverMethod`) and parts of `purity_test.go` *should* have been written instead of spawning full `newEngine` / `packages.Load` subprocesses!
     - **Tier:** Tier 1 (AST/Types Scan Unit).

---

### 2.21 [`refusalchannels_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/refusalchannels_test.go#L1-L142) (142 lines)

- **Tests:**
  1. [`TestOpenWorldRefusalNamesTheConferringTerm`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/refusalchannels_test.go#L19-L46) (lines 19–46):
     - **Witnesses:** `REQ-closure-refusal-channels`: open-world signature-dynamism refusal names the first conferring term (`parameter f func()`, `parameter #2 func()`, `parameter #1 func()`, `receiver view.R`, `type parameter T constrained by any`) and the discharge channels; a closed signature `func F(n int) int` is `Valid`.
     - **Setup Weight:** **Heavy!** Runs **6 separate `writeViewModule` + `captureCheck` passes** (12 full engine view constructions!), even though all 6 functions (`F1(f func())`, `F2(int, func())`, `F3(_ func())`, `(r R) F4()`, `F5[T any](t T)`, `F6(n int) int`) can live in a **single** `package view` source file (or be scanned in-memory via `scanSubjectsFromLoaded`)!
     - **Tier:** Tier 1/2 (consolidate 6 module builds into 1 or into an in-memory scan table).
  2. [`TestUnauditedSelectionAttributesTierRefusals`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/refusalchannels_test.go#L55-L141) (lines 55–141):
     - **Witnesses:** `REQ-closure-refusal-channels`: under `unauditedTagEnv(t)` + `-tags=badstd`, tier refusals (`Open`, `Dial`, `Shared`) append `" (judged under an unaudited toolchain selection: the audited surface of <ver> moved in 1 keys: strings)"` exactly once, whereas declaration-borne refusals (`Declared` with `//gofresh:external` and `Twice` with ambiguous identity) carry no unaudited-toolchain attribution, and an audited selection (without `-tags=badstd`) appends nothing.
     - **Setup Weight:** Heavy (`unauditedTagEnv` + `newView` + 3× `captureCheck` + `audited.newView`). Notice lines 121–126 call `captureCheck` 3 more times over the exact same `dir` that `view` (line 90) already loaded! Calling `view.Capture` + `view.Check` on the existing `view` avoids 6 redundant `newView` constructions.
     - **Tier:** Tier 2 (Engine Closure & Refusal Attribution).

---

### 2.22 [`runner_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runner_test.go#L1-L326) (326 lines)

- **Helpers:**
  - [`freeSpawnFunctions(t *testing.T) []string`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runner_test.go#L156-L185): Parses `gotool/*.go` for exported package-level functions taking `(context.Context, string, []string)`.
  - [`bareSpawnSites(root string, free []string) ([]string, error)`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runner_test.go#L192-L261): Walks non-test `.go` files outside `gotool` looking for calls to `gotool` free spawn functions or `gotool.Runner{}.Run`.
  - [`barePackageLoadSites(root string) ([]string, error)`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runner_test.go#L266-L325): Walks non-test `.go` files outside `gotool` looking for direct calls to `packages.Load`.
- **Tests:**
  1. [`TestEngineSpawnsThroughTheInstalledRunner`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runner_test.go#L26-L85) (lines 26–85):
     - **Witnesses:** `REQ-guard-toolchain` & `REQ-guard-buildconfig`: installing `gotool.Runner{Prepare: ...}` via `withGoRunner` intercepts every `go` command spawned during `e.capture` (`env -json` and `list`), never spawns `go version`, and spawns `go env -json` ровно 2 times (construction pass and closing pass).
     - **Defect / Missing Short Gate:** **Missing `if testing.Short() { t.Skip(...) }`!** This test writes a module to `t.TempDir()` and runs `newEngine` + `e.capture` (spawning `go env`, `go list`, `packages.Load`) unconditionally even during `go test -short`!
     - **Tier:** Tier 2 (Engine Runner & Snapshot Count Integration).
  2. [`TestEngineSpawnSitesReadARunner`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runner_test.go#L97-L116) (lines 97–116):
     - **Witnesses:** Static AST invariant over the codebase: `gotool` exports zero free spawn functions, no non-test file outside `gotool` calls `gotool.Runner{}.Run`, and no non-test file outside `gotool` calls `packages.Load` directly.
     - **Setup Weight:** Fast AST walk.
     - **Tier:** Tier 4 (Repo Hygiene / Static Source Invariant).
  3. [`TestBareSpawnWalkReadsTheThreeFreeFunctions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runner_test.go#L124-L150) (lines 124–150):
     - **Witnesses:** Self-test of test helper `bareSpawnSites` over synthetic `.go` files in `t.TempDir()`.
     - **Tier:** Tier 4 (Meta-test for `bareSpawnSites`).

---

### 2.23 [`runtime_binding_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_binding_test.go#L1-L371) (371 lines)

- **Tests:**
  1. [`TestRuntimeBindingsShareGenerationAcrossPackages`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_binding_test.go#L19-L190) (lines 19–190):
     - **Witnesses:**
       - `snapshot.BindRuntime` shares the source/build `Snapshot` generation without re-observing source (`passes == 0`, `a.Snapshot() == snapshot`).
       - Incomplete (`ErrUnitIncomplete`) or cancelled (`context.Canceled`) `PackageUnit` siblings do not expose evidence or corrupt the binding.
       - Executing two retained package test binaries (`a`, `b`) under distinct relative `RuntimeDescription{Directory: "a"}` and `"b"` injects `PWD=<resolved dir>`, records `PWD` and `BOUND_VALUE` in `RuntimeInputs` (with empty `Guards.Machine` and `Guards.RuntimeConfig` for `CodeResult`), validates under the same binding, and stales (`"PWD"`) under the other binding.
       - Rebinding `snapshot` to a new `RuntimeDescription` does not load source or mutate prior bindings; foreign `BuildBinding` from a later `session.Snapshot` generation is rejected by `u.Register`.
     - **Setup Weight:** Heavy (compiles 2 `go test -c` binaries + 3 test binary runs + 2 `session.Snapshot` passes).
     - **Overlap:** Overlaps heavily with `session_pwd_test.go` (which also builds a retained binary and tests `PWD` as a recorded runtime dependency across two directories `runtime-a` and `runtime-b-longer`).
     - **Tier:** Tier 3 (Subprocess / Retained-Binary Integration).
  2. [`TestRuntimeBindingGuardAgreementAndClosing`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_binding_test.go#L192-L281) (lines 192–281):
     - **Witnesses:**
       - `Measurement` snapshot captures zero runtime guards at `session.Snapshot` time (`samples == 0`), and samples twice (`samples == 2`, agreement pair) at `snapshot.BindRuntime` time via `viewTestHooks.runtimeGuards`.
       - Changing `GOGC=100` -> `GOGC=200` changes `Guards.RuntimeConfig` without changing `Guards.BuildConfig`, staling as `"runtimeconfig"`.
       - `v.Sibling`, `v.newSeededValidationView`, and `v.CaptureObserved` preserve the `RuntimeBinding`'s runtime guards; changing `machine` via `viewTestHooks.runtimeGuards` causes a new binding to stale as `"machine"` and causes the old binding's closing pass (`a.Check`, `seed.newSeededValidationView`, `sibling.reobserveBase`, `sibling.CaptureObserved`) to fail closed with `ErrViewChanged`.
       - Torn machine sample (`a` vs `b` during `BindRuntime`) returns `ErrViewChanged` and `nil` binding; cancelled `BindRuntime` returns `context.Canceled` without damaging existing bindings.
     - **Setup Weight:** Medium (`NewSession` + `Snapshot` over `writeViewModule`).
     - **Tier:** Tier 2 (Session / Runtime Guard Lifecycle).
  3. [`TestRuntimeBindingEnvironmentOwnership`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_binding_test.go#L283-L332) (lines 283–332):
     - **Witnesses:** Pure in-memory `Snapshot.BindRuntime` environment canonicalization and ownership: `nil` inherits build env with `PWD` overwritten to runtime `dir`; `[]string{}` starts empty and adds `PWD=dir`; `PWD=wrong` is replaced; duplicate keys (`DUP=1`, `DUP=2`), missing `=`, or empty key `=value` refuse; `nil` or cancelled `ctx` refuses; `testing/quick.Check` property verifies sorting, `PWD` injection, and caller slice mutation isolation.
     - **Setup Weight:** Fast (< 2ms), pure in-memory `&Snapshot{}`.
     - **Tier:** Tier 1 (Session & Runtime Configuration Algebra).
  4. [`TestSnapshotAndCodeBindingNeedNoMachineSupport`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_binding_test.go#L334-L370) (lines 334–370):
     - **Witnesses:** With `guard.MachineFactSources = nil` (simulating unavailable machine hardware counters/support), `session.Snapshot` succeeds for both `CodeResult` and `Measurement`; `snapshot.BindRuntime` refuses for `Measurement` but succeeds for `CodeResult` (along with `CurrentFacts` and `Check`).
     - **Setup Weight:** Medium (`NewSession` + 2× `Snapshot`).
     - **Tier:** Tier 2 (Session / Runtime Guard Lifecycle).

---

### 2.24 [`runtime_config_collision_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_config_collision_test.go#L1-L46) (46 lines)

- **Tests:**
  1. [`TestRuntimeBindingRefusesDelimiterCollision`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_config_collision_test.go#L9-L45) (lines 9–45):
     - **Witnesses:** Two runtime environments `[]string{"GOGC=200\nGODEBUG=x", "GODEBUG=y"}` vs `[]string{"GOGC=200", "GODEBUG=x\nGODEBUG=y"}` produce distinct `Guards.RuntimeConfig` hashes (`Check` returns `Stale` with `Reason == "runtimeconfig"`) while keeping `Guards.BuildConfig` and `Guards.Machine` equal.
     - **Setup Weight:** **Unnecessarily Heavy!** Writes a module to disk and runs `NewSession` + `session.Snapshot` (spawning `go env`, `go list`, `packages.Load`) in a standalone 46-line file just to test that `guard.CurrentRuntimeGuards` / `RuntimeConfig` hashing is collision-resistant across `\n` in env values!
     - **Consolidation:** Can be tested directly at the `guard` level or on an in-memory `&Snapshot{kind: Measurement}` in `runtime_binding_test.go` (like `TestRuntimeBindingEnvironmentOwnership`) in < 1ms without spawning any `go` subprocess!
     - **Tier:** Tier 1 (fold into `runtime_binding_test.go`).

---

### 2.25 [`runtime_motion_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_motion_test.go#L1-L220) (220 lines)

- **Types & Helpers:**
  - [`type runtimeMotionFixture struct`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_motion_test.go#L20-L26)
  - [`newRuntimeMotionFixture(t *testing.T) runtimeMotionFixture`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_motion_test.go#L28-L94): Creates a temp module `example.com/runtimemotion` with 4 tests (`TestReader`, `TestDirentReader`, `TestUnknown` reading symlink to external file, `TestSupported`), creates a `Session` with `PureSubjects: [reader, unknown, direntReader]`, takes a `Snapshot`, and compiles `package.test` via `go test -c`. (Shared with `runtime_partial_motion_linux_test.go`.)
- **Tests:**
  1. [`TestRuntimeMovementRefusesPureProductionAndHistory`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_motion_test.go#L96-L219) (lines 96–219):
     - **Witnesses:**
       - `stable_reader`: `PureSubjects` member reading `"input"` without mid-run file modification closes as `Valid` with `BracketMoved == false`.
       - `known_motion`: modifying `"input"` from `"before"` to `"after"` after execution before `u.Close` returns `*RuntimeInputSpanError` (`Cause{RuntimeInputsCause, Changed}`), empty `final.Subjects`, and `account.Inputs.BracketMoved == true` on `u.Account()`.
       - A v4 `Fingerprint` bearing the moved manifest (`failed`) evaluates to `Stale` (`RuntimeInputsCause`/`Changed`, empty `AcceptedAuthority{}`) under `binding.Check` even for a `PureSubjects` member, both before and after restoring `"input"` to `"before"`.
       - Rewriting the manifest version to v1, v2, or v3 (removing `"bracketMoved":true`) evaluates to `Stale` (`RuntimeInputsCause`/`Unavailable`) without mutating the historical JSON bytes.
       - `independent_unknown_pure` (reading symlink outside root -> `Valid` because of `PureSubjects`, with `account.Inputs.Unverifiable == true`) and `independent_supported` (`Valid` with `SupportedObservation`).
     - **Setup Weight:** Heavy (`go test -c` + 4 test binary runs).
     - **Tier:** Tier 3 (Subprocess / Retained-Binary Integration).

---

### 2.26 [`runtime_partial_motion_linux_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_partial_motion_linux_test.go#L1-L181) (181 lines)

- **Tests:**
  1. [`TestPureUnitPartialRootMovement`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_partial_motion_linux_test.go#L12-L103) (lines 12–103):
     - **Witnesses:** With an unhashable FIFO (`syscall.Mkfifo(fifo, 0600)`) present in the module directory (making the directory bracket partially unknown/unverifiable):
       - `stable unknown` and `independent stable unknown` (where `"input"` is unchanged) close as `Valid` under `PureSubjects` (`BracketMoved == false`, `Unverifiable == true`).
       - `known file with FIFO` (where `"input"` changes content from `"before"` to `"after!"` with `os.Chtimes` restoring mtime), `external link with FIFO` (replacing `"input"` with a symlink), and `read denied after stat` (`os.Chmod(p, 0000)`) all detect movement on `"input"` and refuse `u.Close` with `*RuntimeInputSpanError` and `BracketMoved == true`.
     - **Setup Weight:** Heavy — calls `newRuntimeMotionFixture(t)` (compiling `package.test` via `go test -c`) and runs 5 test binary executions.
     - **Tier:** Tier 3 (Subprocess / Retained-Binary Integration).
  2. [`TestPureUnitRetainsDirentTypeAcrossSearchDenial`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_partial_motion_linux_test.go#L105-L180) (lines 105–180):
     - **Witnesses:** When `data/` has mode `0400` (search denied) during `u.Register` and `u.Close` (but `0700` during test execution), `os.ReadDir` still observes dirent types (`d.Type()`): leaving `data/input` as a regular file (`retype == false`) closes as `Valid`, whereas replacing `data/input` with a directory (`retype == true`) before restoring `0400` on `data/` is caught via dirent type change and refuses `u.Close` with `*RuntimeInputSpanError` (`BracketMoved == true`).
     - **Setup Weight:** Heavy — calls `newRuntimeMotionFixture(t)` a **second time** (re-running `NewSession`, `Snapshot`, and `go test -c` on the exact same source code!) and runs 2 test binary executions.
     - **Consolidation:** Sharing a single `newRuntimeMotionFixture(t)` across `runtime_motion_test.go` and both tests in `runtime_partial_motion_linux_test.go` saves 2 redundant `NewSession` + `Snapshot` + `go test -c` compilations! Even better, partial bracket comparison with FIFOs and `0400` directories is fundamentally a `runtimeinput.Bracket` property that can be tested directly on `runtimeinput.CaptureBracket` in `runtimeinput/` without compiling Go test binaries at all.
     - **Tier:** Tier 3 (merge fixture with `runtime_motion_test.go`; push pure bracket filesystem cases to `runtimeinput`).

---

### 2.27 [`scanmemo_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L1-L540) (540 lines)

- **Helpers & Globals:**
  - [`scanMemoModule(t *testing.T) string`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L17-L37): Writes a 3-package module (`dep`, `view`, `other`) exercising `//gofresh:pure`, shared dynamic state mutation, and `//gofresh:external`.
  - [`var scanMemoSubjects`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L39-L44).
  - [`scanOutputs(t *testing.T, view *Snapshot, subjects []Subject) map[Subject]string`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L48-L60).
  - [`boolWord(b bool) string`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L62-L67).
  - [`leakModule(t *testing.T) string`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L317-L338), [`leakA`, `leakB`, `leakSubjects`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L340-L344), [`newLeakView`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L346-L357).
- **Tests:**
  1. [`TestScanMemoServesTheWholeScanWithoutATypedLoad`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L72-L139) (lines 72–139):
     - **Witnesses:** `REQ-closure-scan-memo`: a warm `engine.newView` over an unchanged module performs zero `typedLoad`s (`loads == 0`, `warm.facts.source == nil`), emits `served` summaries for `"scan"` and `"testing scan"`, and produces `subjectFacts` and `scanOutputs` identical to the cold view.
     - **Setup Weight:** Heavy (cold + warm `newView`).
     - **Tier:** Tier 2 (Scan Memo Integration).
  2. [`TestScanMemoMissesOnVouchChangeAndCorruption`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L143-L223) (lines 143–223):
     - **Witnesses:** Changing the vouch set (`withDynamicStateVouches` or `.gofresh/vouches` file) misses the scan memo (`loads > 0`), whereas a `.gofresh/vouches` file matching the option hits the memo (`loads == 0`); corrupting `scanfacts/*.json` recomputes cleanly without error.
     - **Setup Weight:** Heavy (5× `newEngine` + `newView`).
     - **Tier:** Tier 2 (Scan Memo Integration).
  3. [`TestScanMemoKeyTracksTheTestBinaryGraph`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L231-L312) (lines 231–312):
     - **Witnesses:** `REQ-closure-scan-memo` & `REQ-closure-canonical-member`: source declaration edits to `dep/dep.go`, `view/view.go`, or `view/view_test.go` (inside the test-binary graph) invalidate the scan memo (`loads > 0`), whereas edits to `other/other.go` (outside the graph) hit the memo (`loads == 0`); comment-only edits to `dep/dep.go` or `view/view.go` invalidate the position-bearing scan memo (`loads > 0`) while keeping public `closure(subject).Hash` unchanged.
     - **Setup Weight:** Very Heavy — runs **13 `engine.newView` passes** in a loop (2 declaration edits × 4 files + 2 comment edits × 2 files + initial cold view)! Why does line 253 loop `for _, name := range []string{"a", "second"}` performing two identical declaration-append edits per file, restoring `original` after each one?! Because the test restores `original` on line 265, the `"second"` iteration just tests that another edit also misses (likely guarding against a single-slot cache or hash collision, though 1 edit per file already proves graph membership).
     - **Tier:** Tier 2 (Scan Memo Integration).
  4. [`TestScanMemoComposesEachPackageOverItsOwnGraph`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L364-L410) (lines 364–410):
     - **Witnesses:** `REQ-closure-shared-dynamic-state` & `REQ-closure-scan-memo`: in a 4-package module (`a -> d`, `b -> c -> d` where `c` mutates `d.Callback`), batching `[a, b]` in one view produces the exact same per-package judgments as solitary views (`a` is verifiable, `b` is downgraded on `d.Callback`), and a half-warm cache (warmed on `a` alone) performs only 1 `typedLoad` (for `b`) when constructing the `[a, b]` batch view.
     - **Setup Weight:** Heavy (5× `newLeakView`).
     - **Tier:** Tier 2 (Scan Memo Integration).
  5. [`TestScanMemoRefusesAnEntryOfAnotherShape`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L414-L468) (lines 414–468):
     - **Witnesses:** Rewriting `"version": 0` inside persisted `scanfacts/*.json` entries causes the next `newView` to miss and recompute (`loads > 0`).
     - **Setup Weight:** Heavy (2× `newView` over `scanMemoModule`), even though this could be tested as a 1-step subtest inside `TestScanMemoMissesOnVouchChangeAndCorruption` (which already globs and rewrites `scanfacts/*.json` on line 207!) without creating another temp module and running another cold `newView`!
     - **Tier:** Tier 2 (fold into `TestScanMemoMissesOnVouchChangeAndCorruption`).
  6. [`TestScanEntryRoundTripsEveryOutput`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L473-L500) (lines 473–500):
     - **Witnesses:** Pure in-memory JSON roundtrip of `entryOf(scan, pkg)` -> `json.Marshal` -> `json.Unmarshal` -> `scanFromEntries` across all `subjectScan` maps (`known`, `pure`, `openWorld`, `external`, `downgradeReason`, `downgradeCulprit`, `vouchDischarges`, `discharges`, `ambiguous`).
     - **Setup Weight:** Fast (< 0.2ms), pure in-memory.
     - **Tier:** Tier 1 (Scan Entry Serialization Algebra).
  7. [`TestScanMemoServesTheDischargedScan`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/scanmemo_test.go#L505-L539) (lines 505–539):
     - **Witnesses:** Under `withSingleSubjectExecution()`, attestation-scoped discharges (`singleSubject: "example.com/view/gen.memo"`) are persisted in the scan memo entry and served identically on a warm `newView` (`loads == 0`).
     - **Setup Weight:** Heavy (cold + warm `newLeakView`). Could easily be asserted on `scanMemoModule` in `TestScanMemoServesTheWholeScanWithoutATypedLoad` by passing `withSingleSubjectExecution()`.
     - **Tier:** Tier 2 (Scan Memo Integration).

---

### 2.28 [`session_directory_unix_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_directory_unix_test.go#L1-L42) (42 lines)

- **Tests:**
  1. [`TestSessionRuntimeDirectoryPreservesSymlinkParents`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_directory_unix_test.go#L16-L41) (lines 16–41):
     - **Witnesses:** When `build/via` is a symlink to `destination/child`, `RuntimeDescription{Directory: "via/.."}` resolves via the filesystem (`filepath.EvalSymlinks`) to `destination` (the symlink target's parent), not `build` (lexical `filepath.Clean` before symlink resolution), and sets `PWD` in `binding.runtime.env` to `destination`.
     - **Setup Weight & Defect:** Calls `NewSession` (spawning `go env`) **without a `testing.Short()` skip**, even though `snapshot.BindRuntime` only reads `snapshot.session.build.Directory` and `snapshot.session.build.Environment` (just like `TestRuntimeBindingEnvironmentOwnership` in `runtime_binding_test.go:285`, which constructs `&Snapshot{session: &Session{build: ...}}` in memory with zero subprocesses)!
     - **Consolidation:** Fold into `runtime_binding_test.go` (or `session_test.go`) using `&Snapshot{session: &Session{build: ...}}` in < 0.5ms with zero `go` subprocesses.
     - **Tier:** Tier 1 (Session & Runtime Configuration Algebra).

---

### 2.29 [`session_ownership_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_ownership_test.go#L1-L65) (65 lines)

- **Tests:**
  1. [`TestSessionOwnsItsDescriptions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_ownership_test.go#L14-L64) (lines 14–64):
     - **Witnesses:** Defensive cloning of `BuildDescription` (`Environment`, `Flags`, `Inputs`), `SessionPolicy` (`PureSubjects`, `Vouches`, `Runner.Containment`), `RuntimeDescription.Environment`, and the `BuildDescription` returned by `Snapshot.BuildDescription(pkg)` against caller slice/pointer mutation.
     - **Setup Weight & Defect:** Calls `NewSession` (spawning `go env` to validate `-tags=owned`) **without a `testing.Short()` skip** in a standalone 65-line file.
     - **Consolidation:** Belongs in `session_test.go` (or `session_config_test.go`).
     - **Tier:** Tier 1/2 (Session Configuration Ownership).

---

### 2.30 [`session_pwd_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_pwd_test.go#L1-L234) (234 lines)

- **Tests:**
  1. [`TestSessionPWDIsARecordedRuntimeDependency`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_pwd_test.go#L20-L233) (lines 20–233):
     - **Witnesses:**
       - Executing a retained benchmark binary (`BenchmarkPWD` reading `os.Getenv("PWD")`) under `RuntimeDescription{Directory: a}` records `PWD` in `RuntimeInputs`.
       - Checking under `Directory: a` (or with `UNREAD_RUNTIME_VALUE=changed`) is `Valid`; checking under `Directory: b` is `Stale`, while `Guards.BuildConfig` is unchanged.
       - Spawns the current test binary as a fresh subprocess (`-test.run=^TestSessionCheckerProcess$`) twice (for `same` and `other directory`) to verify cross-process JSON `Fingerprint` persistence.
       - Reconstructs a legacy v2 manifest (which omitted `PWD`) and verifies that `view.Check`, `view.CheckObserved`, and `execution.Check` all refuse to validate it (`verdict.Status != Valid`) without mutating the historical JSON bytes.
     - **Setup Weight:** Very Heavy (`go test -c` + 3 benchmark/test runs + 2 self-reexec subprocesses each running `NewSession` + `Snapshot` + `BindRuntime` + `Check`).
     - **Duplication:**
       1. `TestRuntimeBindingsShareGenerationAcrossPackages` in `runtime_binding_test.go` (lines 19–190) already tests `PWD` delivery, `PWD` recording in `RuntimeInputs`, same-directory `Valid`, and cross-directory `Stale` (`"PWD"`) on a retained binary!
       2. `TestSessionSeparatesCompilationFromExecution` in `session_test.go` (lines 253–274) already spawns `TestSessionCheckerProcess` as a fresh subprocess!
       3. Legacy manifest version rejection (v1..v3) is already tested in `runtime_motion_test.go` (lines 188–216)!
     - **Tier:** Tier 3 (consolidate with `runtime_binding_test.go` and `session_test.go`).

---

### 2.31 [`session_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_test.go#L1-L809) (809 lines)

- **Types & Helpers:**
  - [`type sessionCheckRecord struct`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_test.go#L615-L621).
  - [`bindTestRuntime(t *testing.T, snapshot *Snapshot, description RuntimeDescription) *RuntimeBinding`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_test.go#L658-L665).
- **Tests:**
  1. [`TestSessionSeparatesCompilationFromExecution`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_test.go#L24-L613) (lines 24–613):
     - **Witnesses:** A 590-line monolithic "everything-in-one-function" integration test covering:
       - Build-vs-runtime `GOAMD64` (`v1` at build time vs `v2` at runtime) selection (`base.go` vs `feature.go`) on `Measurement` (`BenchmarkValue`, `BenchmarkFile`).
       - Symlinked relative capture path resolution (`capture-relative/via/../testlog`) when the host process `t.Chdir(shadow)` is in a different directory.
       - `TestVariantLedger`, `SourceFiles()` slice cloning, `CurrentFacts`.
       - Empty unit close (`ErrUnitIncomplete`) and late `Register` (`ErrUnitClosed`).
       - Duplicate `Register` rejection, cross-unit `Submit` rejection, empty `Terminal{}` rejection, duplicate `Submit` rejection.
       - Concurrent `Close` rejection (`ErrUnitClosed`) while the first `Close` is paused at `closingGate` (`env -json`).
       - Cross-process JSON check via `TestSessionCheckerProcess`.
       - Sibling unit execution after first unit closed.
       - `aborted.Abort()` while `aborted.Close(ctx)` is paused at `abortGate`, verifying no subsequent `env -json` query is spawned.
       - `BeginIdentity` (`IdentityObservation`), plus runtime input motion during `BeginIdentity` source validation (`ErrViewChanged`).
       - `NeverStarted` terminal (`Close` returns error) and `AbnormalCompletion` terminal (`IncompleteObservation`, `Unverifiable`).
       - Checking under a fresh `Session`: unchanged (`Valid`), `CGO_CFLAGS_ALLOW` compiler env change (`Stale` `"buildconfig"`), ambient `ANTIGRAVITY_SOURCE_METADATA`/`TERM` change (`Valid`), `FRESH_SESSION_VALUE` runtime env change (`Stale`), `GOAMD64=v2` + `feature.go` edit (`Stale`), foreign `BuildBinding` rejection.
       - `pending.Close` while `pending.Register` is paused at `beforeOutcomeIssue` (`ErrUnitIncomplete`, then `Register` returns `ErrUnitClosed` — **duplicated in `unit_cancellation_test.go`!**).
       - Source drift during execution (`ErrViewChanged`).
       - Non-empty `BuildDescription.Package` rejected by `NewSession`.
       - `CheckInertExtension` when `unused_test.go` is added (`Valid`), plus source drift on the closing pass of `CheckInertExtension` (`ErrViewChanged`).
     - **Setup Weight:** Extremely Heavy (compiles 2 `go test -c` binaries, runs 9 test binary executions, 1 self-reexec subprocess, and 6 `NewSession` + `Snapshot` passes).
     - **Architectural Critique:** Half of this 590-line test exercises pure in-memory `producingUnit` state-machine transitions (duplicate `Register`, foreign `Submit`, empty `Terminal`, duplicate `Submit`, concurrent `Close`, `Abort` during `Close`, `Close` during `Register`, `NeverStarted`) that do not require compiling or running a real benchmark binary! Meanwhile, those exact state-machine transitions are *also* re-tested in `package_unit_test.go`, `processaccount_test.go`, `unit_cancellation_test.go`, and `unit_protocol_test.go`.
     - **Tier:** Split into Tier 1 (Unit State-Machine Protocol) and Tier 3 (Compilation vs Execution Separation).
  2. [`TestSessionCheckerProcess`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_test.go#L625-L656) (lines 625–656):
     - **Witnesses:** Subprocess entrypoint invoked when `FRESH_SESSION_CHECK` env var is set by `TestSessionSeparatesCompilationFromExecution` and `TestSessionPWDIsARecordedRuntimeDependency`.
     - **Tier:** Tier 3 helper entrypoint.
  3. [`TestSnapshotCaptureAndCaptureBatch`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_test.go#L667-L749) (lines 667–749):
     - **Witnesses:**
       - Lines 669–714: Calling all 18 exported methods on `(*Snapshot)(nil)` and `&Snapshot{}` returns `"gofresh: uninitialized snapshot"` (or `nil` for `SourceFiles()`).
       - Lines 715–748: `snapshot.Capture(ctx, subA)` and `snapshot.CaptureBatch(ctx)` over a 2-function module `example.com/cap`.
     - **Defect / Missing Short Gate:** **Missing `if testing.Short() { t.Skip(...) }` before line 715!** Lines 669–714 are pure in-memory nil/zero-receiver checks (< 0.1ms), but lines 715–748 write a module to disk and call `NewSession` + `session.Snapshot` (spawning `go env`, `go list`, `packages.Load`) unconditionally even under `-short`!
     - **Tier:** Lines 669–714 are Tier 1; lines 715–748 are Tier 2.
  4. [`TestSessionPolicyAssumePureAndSnapshotFor`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_test.go#L751-L806) (lines 751–806):
     - **Witnesses:** `(*Session)(nil).SnapshotFor` refuses; `session.SnapshotFor` with mismatched `moduleDir` refuses; `SessionPolicy{AssumePure: ...}` marks `impure` (`os.Getenv("X")`) as valid under `sibling.Capture` + `sibling.Check` + `sibling.Validate`.
     - **Defect / Missing Short Gate:** **Missing `if testing.Short() { t.Skip(...) }`!** Spawns `NewSession` + `SnapshotFor` + `Validate` (`go env`, `go list`, `packages.Load`) unconditionally even under `-short`!
     - **Tier:** Tier 2.

---

### 2.32 [`session_vouches_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_vouches_test.go#L1-L31) (31 lines)

- **Tests:**
  1. [`TestSessionAcceptsTheResolvedVouchSet`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_vouches_test.go#L9-L30) (lines 9–30):
     - **Witnesses:** `ParseVouchEntries` output is accepted by `SessionPolicy{Vouches: entries}` in `NewSession`; `canonicalSessionVouches` rejects non-canonical strings (`""`, `"example.com/dep:State"` with colon, missing dot, invalid identifier, no dot) and sorts/deduplicates canonical `"pkg.Var"` strings.
     - **Setup Weight & Defect:** Calls `NewSession` (spawning `go env`) **without `testing.Short()`** in a 31-line file, even though `NewSession` just calls `canonicalSessionVouches(policy.Vouches)` (which lines 21–29 already call directly in-memory!).
     - **Consolidation:** Fold into `vouchfile_test.go` (or `session_test.go`).
     - **Tier:** Tier 1 (Vouch Grammar & Set Algebra).

---

### 2.33 [`shortgates_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/shortgates_test.go#L1-L17) (17 lines)

- **Tests:**
  1. [`TestShortGatesLiveInTestBodiesAndSkip`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/shortgates_test.go#L14-L16) (lines 14–16):
     - **Witnesses:** Calls `shortgates.Pin(t, ".")` to verify that every `testing.Short()` reference in the repo is an immediate `if testing.Short() { t.Skip(...) }` inside a `Test*` or `Fuzz*` body. (Note: `shortgates.Pin` only checks that *existing* `testing.Short()` calls are well-formed; it does not catch tests that *forgot* `testing.Short()` like `runner_test.go:26`, `session_test.go:667`, `session_test.go:751`, `session_directory_unix_test.go:16`, `session_ownership_test.go:14`, `session_vouches_test.go:9`, and `toolversion_test.go:14`!)
     - **Tier:** Tier 4 (Repo Hygiene).

---

### 2.34 [`snapshotreuse_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/snapshotreuse_test.go#L1-L109) (109 lines)

- **Tests:**
  1. [`TestObservedCaptureReusesConstructionSnapshot`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/snapshotreuse_test.go#L19-L45) (lines 19–45):
     - **Witnesses:** `view.CaptureObserved` passes the exact `*gotool.EnvSnapshot` pointer captured during `engine.newView` (`view.facts.snapshot`) to the precise-analysis bracket (`viewTestHooks.snapshot`), avoiding redundant `go env -json` executions.
     - **Setup Weight:** Heavy (`writeObservedViewModule` + `newEngine` + `newView` + `CaptureObserved`).
     - **Tier:** Tier 2 (Engine Snapshot & Overlay Lifecycle).
  2. [`TestObservedCaptureRefusesMidWindowOverlayBeforeAnyLoad`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/snapshotreuse_test.go#L53-L108) (lines 53–108):
     - **Witnesses:** Writing `GOFLAGS=-overlay=/absent.json` into the `GOENV` file after `engine.newView` causes `view.CaptureObserved` to refuse on live build-flag revalidation before any `load` or `prove` progress phase runs.
     - **Setup Weight:** Heavy (`writeObservedViewModule` + `newEngine` + `newView` + `CaptureObserved`).
     - **Tier:** Tier 2 (Engine Snapshot & Overlay Lifecycle — combine with `preparation_test.go` and `runner_test.go`).

---

### 2.35 [`structural_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/structural_test.go#L1-L89) (89 lines)

- **Tests:**
  1. [`TestVariantLedgerTypesAreExportedData`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/structural_test.go#L13-L64) (lines 13–64):
     - **Witnesses:** Field shapes of `TestVariantLedger`, `TestVariantDelta`, `TestVariantDeclaration`, `TestVariantFileHeader`, `TestVariantFileBindings`, `TestVariantImport`, `TestVariantDeclarationChange`, and `TestVariantHeaderChange` via `reflect` and `structural.ExportedData`.
  2. [`TestPurityInputIsSubjectPredicate`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/structural_test.go#L66-L77) (lines 66–77):
     - **Witnesses:** Field shape of `SessionPolicy` via `structural.ExportedData`.
  3. [`TestViewCheckUsesConstructionKind`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/structural_test.go#L79-L81) (lines 79–81):
     - **Witnesses:** Signature of `(*Snapshot).Check` via `structural.FunctionSignature`.
  4. [`TestVouchInputShapes`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/structural_test.go#L83-L87) (lines 83–87):
     - **Witnesses:** Signatures of `ParseVouchEntry`, `ParseVouchEntries`, and `ReadVouchFile` via `structural.FunctionSignature`.
- **Architectural Note:** All 4 tests are stipulator structural pins. `TestProcessAccountIsOwnedDataWithoutProducingCapability` in `processaccount_test.go:20-53` is also a reflection structural check on `ProcessAccount`.
- **Tier:** Tier 1 (Public Surface / Structural Pins).

---

### 2.36 [`subject_facts_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/subject_facts_test.go#L1-L190) (190 lines)

- **Helpers:**
  - [`testSubjectFacts(c closure.Closure) subjectFacts`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/subject_facts_test.go#L14-L40): Constructs a synthetic `subjectFacts` value from a `closure.Closure`. (Used across `subject_facts_test.go`, `judgment_test.go`, `toolchain_dependencies_test.go`.)
- **Tests:**
  1. [`TestSubjectFactsHiddenObligations`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/subject_facts_test.go#L42-L99) (lines 42–99):
     - **Witnesses:** Even when `base.external = true` dominates the projected `closure().Reason`, changing any underlying masked obligation (`source.Effects`, `openWorld`, `sharedState`, `ambiguous`) causes `view.compareObservationContext` to detect drift (`ErrViewChanged`, or `ErrAnalysisUnavailable` when `shared state` is cut by analysis budget). Also verifies that non-nil `&subjectRefusal{}` with empty `reason` still projects `Unverifiable: true` and the refusal's `RefusalKind`.
     - **Setup Weight:** Fast (< 0.2ms), pure in-memory.
     - **Tier:** Tier 1 (Subject Facts & Projection Algebra).
  2. [`TestSubjectFactsProjectionAndSiblingIsolation`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/subject_facts_test.go#L101-L141) (lines 101–141):
     - **Witnesses:** `parent.Sibling` preserves `facts.source` and `subjectFacts`; mutating the returned `closure.Closure` value from `child.facts.closure(s)` does not mutate `child` or `parent`; `child.facts.takeCut(other, s)` only updates `sharedState` and `cut[s]` without copying `other`'s `openWorld` or mutating `parent.facts.maximal`; `compareObservationContext` honors context cancellation.
     - **Setup Weight:** Fast (< 0.2ms), pure in-memory.
     - **Tier:** Tier 1 (Subject Facts & Projection Algebra).
  3. [`TestViewBaseFactsKeepMaskedEffects`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/subject_facts_test.go#L143-L189) (lines 143–189):
     - **Witnesses:** Integration check over a single function `F(callback func())` carrying `//gofresh:external`, an open-world parameter `callback`, a mutated package var `Hook()`, `os.Getenv`, and `net.Dial`: `v.facts.maximal[s]` retains all 4 underlying obligations simultaneously (`external`, `openWorld != nil`, `sharedState != nil`, `os.Getenv` and `net.Dial` in `source.Effects`) while projecting `ExternalDirectiveCause` on `v.Check` and closing cleanly on `v.Validate`.
     - **Setup Weight:** Heavy (`writeModuleTree` + `newEngine` + `newView` + `Capture` + `Check` + `Validate`).
     - **Tier:** Tier 2 (Engine Closure & Scan Integration).

---

### 2.37 [`testvariant_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/testvariant_test.go#L1-L367) (367 lines)

- **Helpers & Constants:**
  - [`writePartitionModule(t *testing.T, files map[string]string) string`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/testvariant_test.go#L14-L26): Another duplicate temp-dir file writer.
  - `partitionProduction`, `partitionTest` (lines 28–29).
- **Tests:**
  1. [`TestSiblingTestAdditionStalesAsTestVariants`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/testvariant_test.go#L35-L73) (lines 35–73):
     - **Witnesses:** `REQ-closure-test-variant-identity`: adding `TestSibling` to `partition_test.go` stales production subject `F` with `Reason == "test variants"` on both `engine.check` and `engine.checkObserved`.
  2. [`TestTestFileSubjectBodyLivesInCompartment`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/testvariant_test.go#L78-L106) (lines 78–106):
     - **Witnesses:** `REQ-closure-test-variant-identity`: editing the body of `TestF` in `partition_test.go` stales subject `TestF` with `Reason == "test variants"`.
  3. [`TestPrePartitionRecordingFailsClosedAsTestVariants`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/testvariant_test.go#L112-L161) (lines 112–161):
     - **Witnesses:** A package with no test files captures `TestVariantClosure == testvariant.EmptyTestVariantClosure`; clearing `TestVariantClosure = ""` (simulating a pre-partition record) fails closed to `Stale` (`"test variants"`) on both `check` and `CheckObserved`.
  4. [`TestCompartmentDriftStalesWithoutPreciseAnalysis`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/testvariant_test.go#L168-L230) (lines 168–230):
     - **Witnesses:** `REQ-closure-test-variant-identity` & `REQ-fresh-hierarchical-check`: both unchanged (`Valid`) and compartment-drifted (`Stale` `"test variants"`) checks return without invoking `beforePreciseAnalysis`.
  5. [`TestMixedCoreAndCompartmentDriftStalesOnClosure`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/testvariant_test.go#L236-L285) (lines 236–285):
     - **Witnesses:** Editing both `sibling.go` (core) and `partition_test.go` (compartment) stales on `"closure"` (core precedence over compartment) on both `Check` and `CheckObserved`.
  6. [`TestViewServesTestVariantLedgerFromItsSnapshot`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/testvariant_test.go#L292-L366) (lines 292–366):
     - **Witnesses:** `REQ-closure-test-variant-ledger`, `REQ-fresh-coherent-view`, `REQ-fresh-view-source-identities`: `view.TestVariantLedger(subject)` returns the construction-time snapshot's declarations (`TestF`), clones `References` slices so caller mutation does not alias the view, includes `partition_test.go` in `view.SourceFilesFor(subject)`, refuses unknown subjects, and stays immutable across post-construction edits to `partition_test.go` on disk while a `fresh` view sees the added `TestSibling`.
- **Consolidation Analysis for `testvariant_test.go`:**
  - Tests 1, 2, 4, 5, and 6 all write the **exact same `example.com/partition` module** (`partitionProduction` + `partitionTest`), run `newEngine` + `Capture`, and then append `func TestSibling(t *testing.T) {}` to `partition_test.go`!
  - Even worse: Tests 1 and 4 test the **exact same scenario** (adding `TestSibling` to `partition_test.go` and calling `Check` and `CheckObserved` on `F`), with Test 4 merely adding `analyses := 0; drifted.beforePreciseAnalysis = func() { analyses++ }`!
  - And Tests 3, 4, and 5's verdict-ladder assertions (`TestVariantClosure == ""`, `TestVariantClosure` changed while `MaximalClosure` equal, and both `MaximalClosure` and `TestVariantClosure` changed) are pure `decide(...)` ladder properties that can be tested in < 0.1ms in `judgment_test.go`, while a **single** end-to-end test in `testvariant_test.go` can witness `F`, `TestF`, `TestVariantLedger`, and `SourceFilesFor` across one edit cycle (reducing 14 `newView` passes across 6 tests to **2 `newView` passes in 1 test**)!

---

### 2.38 [`toolchain_dependencies_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/toolchain_dependencies_test.go#L1-L275) (275 lines)

- **Tests:**
  1. [`TestToolchainContentBindsRecordedApplicability`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/toolchain_dependencies_test.go#L20-L194) (lines 20–194):
     - **Witnesses:** Clones `runtime.GOROOT()` via `cp -a --reflink=auto` and modifies stdlib source files in-place (`strings/compare.go` for `observed` reuse; `image/color/ycbcr.go` for `asserted-pure` reuse) without changing the reported `go version`:
       - Verifies `go run ./cmd` output actually changes (`"0"` -> `"3"` and `"0"` -> `"76"`).
       - Verifies `pending.Validate(ctx)` detects the mid-transaction stdlib source edit and returns `ErrViewChanged`.
       - Verifies `current.ToolchainContent` moves (while `Guards.Toolchain`, `MaximalClosure`, and `AdmissionPolicy` stay unchanged), staling the old record with `Reason == "toolchain content"` under both warm and discarded `XDG_CACHE_HOME` caches, and refusing a legacy record with `ToolchainContent == ""` as `Unverifiable`.
     - **Setup Weight:** Very Heavy — clones the entire Go toolchain (`GOROOT`) **twice** (once per subtest `observed` and `asserted-pure`) and runs `go run ./cmd` + 5 `newView` passes per subtest!
     - **Optimization Opportunity:** Both subtests (`observed` using `strings/compare.go` and `asserted-pure` using `image/color/ycbcr.go`) can share **one** cloned `GOROOT` (and one module with two functions `ObservedValue()` and `PureValue()`), cutting the `GOROOT` clone, `go run`, and `newView` passes in half!
     - **Tier:** Tier 3 (Heavy Toolchain Integration).
  2. [`TestObservationProofBindsToolchainDependencies`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/toolchain_dependencies_test.go#L198-L224) (lines 198–224):
     - **Witnesses:** Pure in-memory check that `compatibleObservationProof(record, subject)` and `outcomeSubject(record, subject)` bind `ToolchainContent`, `AdmissionPolicy`, and `ObservationProof.Strategy`.
     - **Setup Weight:** Fast (< 0.1ms), pure in-memory.
     - **Tier:** Tier 1 (Judgment & Proof Seal Algebra — belongs in `judgment_test.go`).
  3. [`TestPolicyMismatchCannotLiftClosureRefusal`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/toolchain_dependencies_test.go#L229-L274) (lines 229–274):
     - **Witnesses:** When a recorded `Fingerprint` has internally consistent `ObservationProof` and `RuntimeInputs` outcome support minted under `"historical-" + cl.AdmissionPolicy`, checking it against the current `AdmissionPolicy` returns `Unverifiable`.
     - **Setup Weight:** Heavy (`writeSupportedViewModule` + `newEngine` + 2× `newView` + `CaptureObserved` + `supportedObservation`), even though `TestJudgmentAuthorityAndScope` case `"policy movement"` in `judgment_test.go:85-89` **already tests this exact case in-memory**!
     - **Duplication:** 100% redundant with `judgment_test.go:85-89`.
     - **Tier:** Tier 1 (already covered in `judgment_test.go`).

---

### 2.39 [`toolchainkey_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/toolchainkey_test.go#L1-L45) (45 lines)

- **Tests:**
  1. [`TestUnauditedToolchainDropsPurityAdmissions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/toolchainkey_test.go#L14-L44) (lines 14–44):
     - **Witnesses:** `REQ-closure-observability-toolchain-key`: `auditedSynchronization(audited, lock)` (`*sync.Mutex.Lock`), `auditedPooling(audited, get)` (`*sync.Pool.Get`), and `auditedImmutableType(audited, reflType)` (`reflect.Type`) return `true` when `audited == true` and `false` when `audited == false`.
     - **Setup Weight:** Fast (< 0.1ms), pure in-memory `go/types` in a standalone 45-line file.
     - **Consolidation:** Fold into the fast purity/dynamic-state unit test file.
     - **Tier:** Tier 1 (Dynamic-State & Purity Admission Unit).

---

### 2.40 [`toolversion_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/toolversion_test.go#L1-L22) (22 lines)

- **Tests:**
  1. [`TestToolVersionModule`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/toolversion_test.go#L14-L21) (lines 14–21):
     - **Witnesses:** Runs `go test -count=1 ./...` inside the nested submodule `toolversion/` with `GOWORK=off` so root `go test ./...` covers the `toolversion` submodule.
     - **Note:** Only file in Scope 07c in `package gofresh_test`. Does not skip on `testing.Short()`, spawning a child `go test` process unconditionally.
     - **Tier:** Tier 4 (Repo / Submodule Test Runner Bridge).

---

### 2.41 [`unit_cancellation_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/unit_cancellation_test.go#L1-L113) (113 lines)

- **Tests:**
  1. [`TestUnitRegistrationCancellationRetainsCallerCause`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/unit_cancellation_test.go#L12-L112) (lines 12–112):
     - **Witnesses:** 2 × 2 × 2 = 8 subtests (`singleton` vs `package` × `close` vs `abort` × `live caller` vs `cancelled caller`) pausing `u.Register` at `transaction.view.beforeOutcomeIssue`:
       - Calling `u.Close` while `Register` is paused returns `ErrUnitIncomplete` and zero `Finalized`/`FinalizedProcess`.
       - If the caller of `u.Register` did not cancel `ctx` (`live caller`), `u.Register` returns `ErrUnitClosed` after `Close` or `Abort` ends the unit; if the caller cancelled `ctx` (`cancelled caller`), `u.Register` returns `context.Canceled`.
     - **Setup Weight & Duplication:**
       - Calls `writeSupportedViewModule` + `NewSession` + `session.Snapshot` (`go env`, `go list`, `packages.Load`) just to obtain a `Snapshot` on which `u.Register` will pause at `beforeOutcomeIssue`.
       - Directly overlaps with `TestProcessAccountDuringRegistration` in `processaccount_test.go:411-507` and lines 505–537 of `TestSessionSeparatesCompilationFromExecution` in `session_test.go`!
     - **Tier:** Tier 1 (Unit Protocol State Machine — can run on an in-memory `Snapshot` fixture without spawning `go` subprocesses).

---

### 2.42 [`unit_preparation_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/unit_preparation_test.go#L1-L59) (59 lines)

- **Tests:**
  1. [`TestUnitRefusesScratchDeclarationsBeforePreparation`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/unit_preparation_test.go#L12-L58) (lines 12–58):
     - **Witnesses:** Passing an invalid `runtimeinput.ScratchNamespace` (`{Dir: ".", Pattern: "bad/name"}`, `{Dir: "..", Pattern: "scratch-*"}`, `{Dir: "", Pattern: "scratch-*"}`, `{Dir: ".", Pattern: ""}`) in `ProcessDescription.ScratchNamespaces` to `u.Register` returns an error containing `"scratch namespace"` while leaving `u.producing.execution == nil` and `u.producing.phase == unitOpen`, so a subsequent valid `u.Register` on the same `u` succeeds!
     - **Setup Weight:** **Unnecessarily Heavy!** Writes a temp module and calls `NewSession` + `session.Snapshot` in a standalone 59-line file just to test pre-preparation validation in `u.Register`!
     - **Consolidation:** Belongs in the fast in-memory Unit Protocol test suite (`unit_protocol_test.go`).
     - **Tier:** Tier 1 (Unit Protocol State Machine).

---

### 2.43 [`unit_protocol_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/unit_protocol_test.go#L1-L84) (84 lines)

- **Tests:**
  1. [`FuzzUnitTerminalProtocol`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/unit_protocol_test.go#L13-L83) (lines 13–83):
     - **Witnesses:** Pure in-memory state-machine fuzz test over `Unit` and `PackageUnit` with a pre-populated `&unitExecution{ready: true}`:
       - Tests arbitrary sequences of `Submit(own, candidate)`, `Submit(other, candidate)`, `Abort()`, and cancelled `Close(ctx)` across 3 valid `Terminal` shapes (`NormalCompletion`, `AbnormalCompletion` with reason, `NeverStarted` with reason) and 4 invalid `Terminal` shapes (`Terminal{}`, `NormalCompletion` with reason, `AbnormalCompletion` without reason, unknown `Kind: 255`).
       - Verifies that at most one valid `Submit` on `own` before `Abort`/`Close` is accepted, `other` handle is always rejected, and cancelled `Close` returns `context.Canceled` before the unit ends and `ErrUnitClosed` after it ends.
     - **Setup Weight:** Fast, zero-subprocess in-memory fuzzing.
     - **Architectural Highlight:** This 84-line file is a model for how all unit state-machine protocol invariants (`unit_cancellation_test.go`, `unit_preparation_test.go`, `package_unit_test.go:249-276`, `processaccount_test.go:509-540`, and half of `session_test.go`) should be structured!
     - **Tier:** Tier 1 (Unit Protocol State Machine).

---

### 2.44 [`unscoped_facts_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/unscoped_facts_test.go#L1-L57) (57 lines)

- **Tests:**
  1. [`TestUnscopedFactsNeverUseTheProcessCache`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/unscoped_facts_test.go#L10-L56) (lines 10–56):
     - **Witnesses:** When `runScan` runs with a non-empty `memoScope` (`"complete"`), `processFactCache` caches dependency `dynamicStateFact`s (`loads` stays 1 on the warm run); when `runScan` runs with an empty `memoScope` (`""`), it neither reads poisoned entries from `processFactCache` nor writes to `processFactCache` (`loads` increments on every run).
     - **Setup Weight:** Heavy (`writePinnedDepModule` + 4× `runScan` invoking `packages.Load`) in a standalone 57-line file. Note: Calls `runScan` defined in another `_test.go` file (in Scope 07a/07b, `dynamicstate_memo_test.go`), showing split-brain test organization across files!
     - **Tier:** Tier 2 (fold into `dynamicstate_memo_test.go` / `scanmemo_test.go`).

---

### 2.45 [`vouchfile_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/vouchfile_test.go#L1-L189) (189 lines)

- **Tests:**
  1. [`TestRepositoryVouchFileJoinsTheVouchSet`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/vouchfile_test.go#L18-L159) (lines 18–159):
     - **Witnesses:** `REQ-vouch-input` & `REQ-vouch-recorded`:
       - Poisons `processFactCache` for `golang.org/x/sync/errgroup` with two fake mutated globals (`Ghost`, `Shade`), then runs `judge()` (`newEngine` + `newView` + `Capture` + `Check`) across 6 combinations of `.gofresh/vouches` file and `withDynamicStateVouches` / `withoutRepositoryVouches` options.
       - Then runs `newEngine` 7 more times to test `.gofresh/vouches` error handling: malformed line (`vouches:3`), `withoutRepositoryVouches()` ignoring malformed file, malformed file alongside `withDynamicStateVouches`, directory at `.gofresh/vouches`, oversized line (> 64KB scanner token limit), and `0000` chmod unreadable file.
     - **Setup Weight:** **Extremely Heavy!** Calls `newEngine` **14 times** (and `newView` + `Capture` + `Check` **7 times**, each running `go env`, `go list`, `packages.Load`) over `writePinnedDepModule(t)`!
       - Notice that the last 7 `newEngine` calls (lines 111–158) only test `ReadVouchFile` / `newEngine` reading `.gofresh/vouches` before any view is even constructed, and the 6 `judge()` calls only test set union (`file ∪ option`) and `withoutRepositoryVouches()`!
     - **Tier:** Tier 1/2 (File-reading error cases belong in `TestParseVouchEntryGrammar` on `ReadVouchFile`; at most 1–2 `newView` passes are needed to witness end-to-end engine wiring).
  2. [`TestParseVouchEntryGrammar`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/vouchfile_test.go#L164-L188) (lines 164–188):
     - **Witnesses:** `REQ-vouch-input`: `ParseVouchEntry` accepts valid `IMPORT-PATH:VARIABLE` strings (`golang.org/x/sync/errgroup:Ghost`, `a.example/dep/v2:_x9`), rejects 11 malformed strings, and `ReadVouchFile` sorts/deduplicates lines, ignores `#` comments and blank lines, and returns `nil, nil` on a non-existent file.
     - **Setup Weight:** Fast (< 0.5ms), pure in-memory + temp file read.
     - **Tier:** Tier 1 (combine with `TestParseVouchEntriesIsASet` from `provenance_composite_test.go:216-227` and `TestSessionAcceptsTheResolvedVouchSet` from `session_vouches_test.go:9-30`).

---

## 3. Root-Cause Diagnosis: Why 45 Fragmented Test Files Exist in Part 2

### 3.1 Symptom-Driven / Issue-Per-File Accretion
19 of the 45 files in Scope 07c are under 105 lines, and 12 are tiny 17–65 line single-test files created for individual point fixes or stipulator witness bindings:
- `shortgates_test.go` (17 lines)
- `toolversion_test.go` (22 lines)
- `session_vouches_test.go` (31 lines)
- `purity_environment_test.go` (34 lines)
- `session_directory_unix_test.go` (42 lines)
- `judgment_fuzz_test.go` (45 lines)
- `toolchainkey_test.go` (45 lines)
- `runtime_config_collision_test.go` (46 lines)
- `unscoped_facts_test.go` (57 lines)
- `unit_preparation_test.go` (59 lines)
- `session_ownership_test.go` (65 lines)
- `membership_surface_test.go` (71 lines)
- `progressdiagnostic_test.go` (77 lines)
- `unit_protocol_test.go` (84 lines)
- `structural_test.go` (89 lines)
- `provenance_test.go` (101 lines)
- `snapshotreuse_test.go` (109 lines)
- `movedreasons_test.go` (112 lines)
- `unit_cancellation_test.go` (113 lines)

Each time a narrow edge case or requirement pin was added (e.g., `GOFLAGS` in purity scan, `\n` delimiter in runtime config env, symlink `..` in runtime directory, `ScratchNamespace` validation before unit preparation, `unscoped` memo key bypass), a brand-new `*_test.go` file with its own `NewSession` / `Snapshot` / temp-module boilerplate was created instead of extending an existing table or state-machine harness.

### 3.2 Cross-Domain Grab-Bag Files & Split-Brain Helpers
- [`provenance_composite_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/provenance_composite_test.go#L1-L261) mixes **three unrelated domains** in one file: `Progress` AST emitter walking (`TestEveryEmittedPhaseIsClassified`, `TestEmittedPhaseWalkReadsEveryEmitterShape`, `TestUnitPhasesAreTheDocsList`), `ToolchainProvenance` (`TestToolchainProvenanceIsOneRefusal`), and `ParseVouchEntries` (`TestParseVouchEntriesIsASet`).
- Vouch parsing tests are scattered across **four files**: `vouchfile_test.go`, `session_vouches_test.go`, `provenance_composite_test.go`, and `structural_test.go`.
- Progress reporting tests are scattered across **four files**: `progressdiagnostic_test.go`, `progressunits_test.go`, `provenance_composite_test.go`, and `preparation_test.go`.
- Unit lifecycle / `ProcessAccount` tests are scattered across **seven files**: `unit_protocol_test.go`, `unit_preparation_test.go`, `unit_cancellation_test.go`, `package_unit_test.go`, `producing_selection_test.go`, `processaccount_test.go`, and `session_test.go`.
- Duplicate module-tree writers are re-implemented locally in file after file: `writeInitFixture` (`initsubject_test.go:11`), `writePartitionModule` (`testvariant_test.go:14`), inline `write` closures (`movedreasons_test.go:27`, `progressunits_test.go:28`, `purity_environment_test.go:15`, `purity_test.go:71`, `purity_test.go:109`, `refusalchannels_test.go:63`, `scanmemo_test.go:20`, `scanmemo_test.go:320`, `session_test.go:32`), alongside shared helpers `writeViewModule` and `writeModuleTree`.

### 3.3 Heavy Subprocess / Compiler Setup Used for Pure In-Memory Properties
1. [`membership_surface_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/membership_surface_test.go#L13-L70): Runs `NewSession` + `session.Snapshot` (`go env`, `go list`, `packages.Load`) just to test that `Sibling` membership refusals return `*UnknownSubjectsError{Scope: SelectedView}` — an in-memory map lookup already set up in `membership_test.go`!
2. [`preparation_test.go:88-131`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/preparation_test.go#L88-L131) (`TestMalformedRecordRefusesTheBatchBeforeAnyWindow`): Runs `newEngine` + `newView` + `Capture` over a temp module to test `Kind(99)` batch refusal, which is 100% duplicated in-memory by `TestRecordedBatchPreparationHasDeterministicCompleteTiers` in `membership_test.go:44-120`.
3. [`toolchain_dependencies_test.go:229-274`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/toolchain_dependencies_test.go#L229-L274) (`TestPolicyMismatchCannotLiftClosureRefusal`): Runs `newEngine` + 2× `newView` + `CaptureObserved` to test `AdmissionPolicy` mismatch, which is already a 4-line in-memory table case (`"policy movement"`) in `judgment_test.go:85-89`.
4. [`unit_preparation_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/unit_preparation_test.go#L12-L58): Runs `NewSession` + `session.Snapshot` to test `ScratchNamespace` validation at the top of `u.Register`, which happens before any engine/view work and only needs an in-memory `Unit`.
5. [`unit_cancellation_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/unit_cancellation_test.go#L12-L112): Runs `NewSession` + `session.Snapshot` to test `u.Register` paused at `beforeOutcomeIssue`, which only needs an in-memory `Snapshot` with `beforeOutcomeIssue` set.
6. [`runtime_config_collision_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtime_config_collision_test.go#L9-L45): Runs `NewSession` + `session.Snapshot` to test `GOGC`/`GODEBUG` newline delimiter collision in `RuntimeConfig` guard hashing.
7. [`progressunits_test.go:163-202`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/progressunits_test.go#L163-L202) (`TestOperationBoundaryReportsOncePerOperation`): Runs `writeViewModule` + `newEngine` + `closureNewAt` (`go env`) just to test in-memory `context.Context` nesting in `beginOperation`.
8. [`oncefill_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/oncefill_test.go#L17-L144): Spawns **33 separate `writeViewModule` + `captureCheck` executions** (66 `engine.newView` passes!) for receiver `sync.Once` cases that can all live in a single fixture module (or run directly via `scanSubjectsFromLoaded`).
9. [`testvariant_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/testvariant_test.go#L1-L367): Runs 6 separate module builds (14 `newView` passes) over the identical `example.com/partition` module to test `TestVariantClosure` verdict-ladder cases.

### 3.4 Seven Tests Spawning `go` Subprocesses Without `testing.Short()` Guards
While `shortgates_test.go` checks that *existing* `testing.Short()` statements are top-level in test functions, **7 test functions in Scope 07c spawn `go` subprocesses without any `testing.Short()` guard**:
1. [`TestEngineSpawnsThroughTheInstalledRunner`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runner_test.go#L26-L85) (`runner_test.go:26`) — runs `newEngine` + `e.capture` (`go env`, `go list`, `packages.Load`).
2. [`TestSnapshotCaptureAndCaptureBatch`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_test.go#L667-L749) (`session_test.go:667`) — runs `NewSession` + `session.Snapshot` + `CaptureBatch`.
3. [`TestSessionPolicyAssumePureAndSnapshotFor`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_test.go#L751-L806) (`session_test.go:751`) — runs `NewSession` + `SnapshotFor` + `Validate`.
4. [`TestSessionRuntimeDirectoryPreservesSymlinkParents`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_directory_unix_test.go#L16-L41) (`session_directory_unix_test.go:16`) — runs `NewSession` (`go env`).
5. [`TestSessionOwnsItsDescriptions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_ownership_test.go#L14-L64) (`session_ownership_test.go:14`) — runs `NewSession` (`go env` for `-tags=owned`).
6. [`TestSessionAcceptsTheResolvedVouchSet`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/session_vouches_test.go#L9-L30) (`session_vouches_test.go:9`) — runs `NewSession` (`go env`).
7. [`TestToolVersionModule`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/toolversion_test.go#L14-L21) (`toolversion_test.go:14`) — runs `go test -count=1 ./...` in `toolversion/`.

---

## 4. Concrete Consolidation Blueprint: 45 Files → 8 Cohesive Domain Test Files

All 45 files in Scope 07c naturally collapse into **8 domain-aligned test files** organized across **4 execution tiers**:

| Target Consolidated File | Tier | Absorbs Current Files (45) | Key Consolidation & Speedup Wins |
| :--- | :--- | :--- | :--- |
| **`judgment_test.go`** | **Tier 1** (Pure In-Memory Algebra, < 5ms) | `judgment_test.go`, `judgment_fuzz_test.go`, `subject_facts_test.go` (tests 1–2), `membership_test.go`, `membership_surface_test.go`, `movedreasons_test.go` (`TestDriftRefusalComponents` + `withMovedInputs`), `preparation_test.go` (`TestMalformedRecordRefusesTheBatchBeforeAnyWindow`), `toolchain_dependencies_test.go` (`TestObservationProofBindsToolchainDependencies`, `TestPolicyMismatchCannotLiftClosureRefusal`) | Eliminates 4 redundant subprocess-heavy tests by folding them into the fast in-memory `judgmentFixture` and `membership_test.go` tables; merges `FuzzJudgmentDiagnosticIndependence` into `judgment_test.go`. |
| **`unit_protocol_test.go`** | **Tier 1** (Pure In-Memory State Machine, < 10ms) | `unit_protocol_test.go`, `unit_preparation_test.go`, `unit_cancellation_test.go`, `package_unit_test.go` (`TestPackageUnitRefusesIncompatibleScope`), `processaccount_test.go` (`TestProcessAccountIsOwnedDataWithoutProducingCapability`, `TestProcessAccountRetainsObservationComputedBeforeAbort`, `TestProcessAccountDuringRegistration`), `outcome_test.go` (`TestOutcomePreparationRejectsInvalidAndEndedTransactions`), `preparation_test.go` (`TestMissingAttachmentRefusesBeforeTheValidationObservation`) | Replaces 4 `NewSession`/`Snapshot` disk setups with a single in-memory `Snapshot`/`RuntimeBinding` state-machine fixture testing all `Begin`/`BeginPackage`/`BeginIdentity`/`Register`/`Submit`/`Close`/`Abort`/`Account` transitions and barrier cancellations. |
| **`session_config_test.go`** | **Tier 1** (In-Memory Config, Provenance & Vouch Grammar, < 10ms) | `provenance_test.go`, `provenance_composite_test.go` (`TestToolchainProvenanceIsOneRefusal`, `TestParseVouchEntriesIsASet`, `TestUnitPhasesAreTheDocsList`), `vouchfile_test.go` (`TestParseVouchEntryGrammar` + file error cases), `session_vouches_test.go`, `session_directory_unix_test.go`, `session_ownership_test.go`, `runtime_binding_test.go` (`TestRuntimeBindingEnvironmentOwnership`), `runtime_config_collision_test.go`, `progressdiagnostic_test.go`, `progressunits_test.go` (`TestOperationBoundaryReportsOncePerOperation`, `TestKeptOnCancelDetailRendersItsCounts`), `structural_test.go`, `session_test.go` (nil/zero `Snapshot` table) | Eliminates 6 unguarded/unnecessary `NewSession` subprocess spawns; consolidates all vouch grammar, toolchain provenance skew, progress formatting, and session/runtime env ownership tests into one fast Tier 1 suite. |
| **`scan_subjects_test.go`** | **Tier 1 & 2** (AST/Types Scan & Receiver Proof Harness) | `recvname_test.go`, `toolchainkey_test.go`, `purity_test.go`, `purity_environment_test.go`, `initsubject_test.go`, `oncefill_test.go`, `refusalchannels_test.go`, `subject_facts_test.go` (`TestViewBaseFactsKeepMaskedEffects`) | Batching the 33 `oncefill_test.go` cases and 6 `refusalchannels_test.go` open-world cases into shared package fixtures (or direct `scanSubjectsFromLoaded` passes) cuts **~75 full engine view constructions down to ~4**! |
| **`scan_memo_test.go`** | **Tier 2** (Engine View, Memo, Progress & Compartment Integration) | `scanmemo_test.go`, `unscoped_facts_test.go`, `vouchfile_test.go` (`TestRepositoryVouchFileJoinsTheVouchSet` end-to-end check), `testvariant_test.go`, `preparation_test.go` (tests 1, 2, 5), `snapshotreuse_test.go`, `progressunits_test.go` (`TestProgressReportsUnitsServedAndKept`), `runner_test.go` (`TestEngineSpawnsThroughTheInstalledRunner`) | Collapses 6 duplicate `writePartitionModule` builds in `testvariant_test.go` into 1; merges `unscoped_facts_test.go` and `vouchfile_test.go` cache/memo tests into `scanmemo_test.go`; adds missing `testing.Short()` guard to `TestEngineSpawnsThroughTheInstalledRunner`. |
| **`execution_integration_test.go`** | **Tier 3** (Retained-Binary Execution & Outcome Support) | `outcome_test.go` (tests 1, 3, 4), `package_unit_test.go` (`TestPackageUnitOwnsTheWholeExecution`), `producing_selection_test.go`, `processaccount_test.go` (`TestProcessAccountPreservesFinalizedFacts`), `runtime_motion_test.go`, `runtime_partial_motion_linux_test.go`, `movedreasons_test.go` (`TestStaleRuntimeInputsNamesTheMover`) | Shares **one** compiled retained test binary fixture across outcome support, package unit execution, process account verification, and runtime input motion (instead of compiling 8 separate `go test -c` binaries across 6 files!). |
| **`session_integration_test.go`** | **Tier 3** (Compilation vs Execution, Runtime Bindings & Toolchain Content) | `session_test.go`, `session_pwd_test.go`, `runtime_binding_test.go` (tests 1, 2, 4), `toolchain_dependencies_test.go` (`TestToolchainContentBindsRecordedApplicability`) | Deduplicates `session_pwd_test.go` into `runtime_binding_test.go` / `session_test.go`; shares **one** cloned `GOROOT` across both `observed` and `asserted-pure` cases in `TestToolchainContentBindsRecordedApplicability` (halving `cp -a GOROOT` cost); adds missing `testing.Short()` guards. |
| **`repo_hygiene_test.go`** | **Tier 4** (Static Source, CI Shard & Submodule Hygiene) | `raceshards_test.go`, `runner_test.go` (`TestEngineSpawnSitesReadARunner`, `TestBareSpawnWalkReadsTheThreeFreeFunctions`), `provenance_composite_test.go` (`TestEveryEmittedPhaseIsClassified`, `TestEmittedPhaseWalkReadsEveryEmitterShape`), `shortgates_test.go`, `toolversion_test.go` | Groups all repository-wide AST walks (`emittedPhases`, `bareSpawnSites`, `barePackageLoadSites`, `shortgates.Pin`, `testFunctions` vs `.github/workflows/ci.yaml`) and submodule runner bridges into one dedicated meta-test file. |
