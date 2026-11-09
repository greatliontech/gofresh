# Decompose `view.go` & `session.go`, Batch `Snapshot`/`Sibling` Observability & Fix Validation/Unit Economy

**Lands:** Chunk 7 in [`docs/plans/plan.md`](../plans/plan.md) (`Redesign Root package gofresh & Simplify/Optimize/Fix internal/runtimeinput, gotool, testvariant, cachefile, guard, and testenv`).

## Context & Concrete Findings

### 1. $N$ Solo `Unit`s in One Package Trigger $3N$ `observeView` Passes and $N$ Full Package SSA Builds (`unit.go:142-250`, `view.go:982-1199, 1823-1959`, `internal/closure/observability.go:378-500`)

- `RuntimeBinding.Begin` (`unit.go:142-173`) derives a 1-subject `Sibling` (`u.view`) from `b.snapshot` (`view.go:982-1082`). `Sibling()` copies only entries already present in `b.snapshot.observable` at derivation time (`view.go:1022-1026`).
- In `Unit.Register` (`unit.go:229-250`), when `decide(...) != Valid`, `u.view.prepareOutcomeSupport` calls `u.view.CaptureObservedBatch(ctx)` -> `u.view.ensureObservable(ctx, [s_i])` (`view.go:1823-1959`).
- Because `observableRequests` has length 1 (`[s_i]`), `hasher.ComputeObservabilityBatch` (`observability.go:378-500`) loads and builds the **entire package's test-binary SSA program**, runs attributed bitmask reachability for **1 of 64 available bitmask slots**, writes only `[s_i]` to the disk memo (`observability.go:492`), releases the SSA program (`observability.go:430`), runs a closing `v.observe(ctx)` pass (`view.go:1939`, `observeView` #1), and stores `observable[s_i]` only in the ephemeral child `u.view.observable`.
- The next solo unit $s_{i+1}$ in the same package misses both `b.snapshot.observable` and the disk memo, rebuilding the entire package SSA from scratch ($N$ full SSA builds instead of $\lceil N/64 \rceil$) and running another `observeView` pass.
- In `Unit.Close` (`unit.go:505`) -> `u.view.Validate(ctx)` -> `validateObserved(ctx)` (`view.go:1123-1199`), `newSeededValidationView(ctx)` (`view.go:1084-1121`) runs `v.observe(ctx)` (`observeView` #2) and proves zero source/guard/closure drift, but initializes `current.observable` to an empty map (`view.go:1114`), forcing `current.ensureObservable(ctx, [s_i])` (`view.go:1162`) to run a second closing `v.observe(ctx)` (`observeView` #3).

### 2. `prepareOutcomeSupport` Pollutes `v.capturedObserved` for Non-Observed Subjects in Mixed-Package `Unit`s (`session.go:1110-1150`, `unit.go:229-250`)

- In `Unit.Register` (`unit.go:229-250`), `u.view.CaptureBatch(preparing)` captures non-observed fingerprints for all subjects, and then for subjects that need observation (`len(observed) != 0`), line 246 calls `u.view.prepareOutcomeSupport(ctx, frame, process.Identity, observedSubjects)`.
- Inside `prepareOutcomeSupport` (`session.go:1125`), it calls `v.CaptureObservedBatch(ctx)` (`view.go:656-683`), which loops over **every** subject in `v.subjects` (not just `observedSubjects`) and sets `v.capturedObserved[subject] = true` (`view.go:676`) for all of `v.subjects`.
- When `Unit.Close` (`unit.go:495, 505`) runs, pure/source-supported subjects in the same package still have `v.capturedObserved[pureSubject] == true`, causing `validateObserved` (`view.go:1141-1143`) to treat `pureSubject` as an observed subject during closing validation and require an attached observation for it.

### 3. Redundant Subprocess Spawns, Metadata Calls, Digest Recomputations & Allocations (`view.go`, `session.go`, `checking.go`, `unit.go`, `explain.go`)

1. **Duplicate `hasher.GraphMetadata` Call During View Construction (`view.go:2446` and `view.go:3022`)**:
   - `scanViewSubjectsWithMemo` calls `meta, err := hasher.GraphMetadata(pkgPaths...)` at `view.go:2446` for `misses`, and `deriveViewDynamicState` immediately calls `hasher.GraphMetadata(viewPackages...)` again at `view.go:3022` on the exact same `misses` slice instead of passing `meta`.
2. **Redundant `go env -json` Subprocess Spawns in `closure.NewBracketAt` (`view.go:1857`) and `ExplainDynamicState` (`explain.go:108`)**:
   - `ensureObservable` invokes `closure.NewBracketAt(...)` (`view.go:1857`), which calls `buildflags.Validate` and spawns `go env -json` even though `v.session` already holds a validated `envSnapshot` and `buildFlags`.
   - `ExplainDynamicState` (`explain.go:108-122`) calls `v.session.ToolchainSelection(ctx)`, creating a fresh `s.newPassReader()` and spawning `go env -json` even though `v.facts.snapshot` (`view.go:1810`) already holds the observed `gotool.EnvSnapshot`.
3. **`Snapshot.Validate` Runs 4 `observeView` Passes When Both `hasObserved` and `hasApplicability` Are Active (`view.go:885-900`, `checking.go:747-760`)**:
   - When a `Snapshot` has both observed captures (`hasObserved`) and applicability checks (`hasApplicability`), `Snapshot.Validate` calls `validateObserved` (2 `observeView` passes) followed by `validateApplicabilityChecks` (2 `observeView` passes) instead of sharing one re-observation bracket.
4. **Triple `OutcomeBinding` in `Unit.Register` (`unit.go:210, 246, 273`) and Double `CompletedState` in `Unit.Close` (`unit.go:484, 487`)**:
   - `Unit.Register` normalizes and SHA-256 hashes `env` via `OutcomeBinding` 3 times (`unit.go:210`, `session.go:1121`, `unit.go:273`).
   - `Unit.Close` verifies and recomputes the SHA-256 seal via `runtimeinput.CompletedState(observation)` twice (`unit.go:630` and `unit.go:487`), and calls `runtimeinput.HasOutcomeSupport` per observed subject in `Unit.account()` (`unit.go:608-615`, decoding and re-encoding the manifest $N$ times instead of once).
5. **5x `gotool.NormalizeEnv` in `NewSession` (`session.go:325-335`), Repeated Vouch Sorting (`view.go:2025-2036`), Full `Sibling` Allocation in `CurrentFacts` (`session.go:643-663`), and Double `prepareCandidates` in `CheckBatchWithLedgers` (`checking.go:569, 588`)**:
   - `completeBuildEnvironment` (`session.go:996-1080`) also re-unmarshals `snapshot.JSON` and re-stats/reads `GOENV` on every `observeView` pass even when `snapshot` is unchanged and `observation.Env` has no `GOENV` override.

### 4. God-File Structure & Vestigial Scaffolding in `view.go` (`3,254` Lines) and `session.go` (`1,159` Lines)

- `view.go` mixes 4 distinct domains (`Snapshot`/`Sibling` lifecycle, producer capture & closing validation, observability proof brackets & decision lattice, and subject AST/dynamic-state scanning) and retains:
  - ~110 lines of vestigial 1-line `dynstate` pass-through wrappers and `dynCulprit` <-> `dynstate.Culprit` copy loops (`view.go:2758-2796, 2993-3019, 3206-3253`).
  - ~85 lines of test-only package loaders (`scanPureDirectivesAt`, `scanSubjectsInWithBuildFlagsEnv` at `view.go:2275-2286, 2312-2386`) that have zero production callers and zero stipulator bindings.

## Resolution

During Chunk 7:
1. **Decompose `view.go` (`3,254` lines) into `view.go`, `validate.go`, `observability.go`, and `scan.go`, and `session.go` (`1,159` lines) into `session.go`, `binding.go`, and `progress.go`**:
   - Delete the ~110 lines of vestigial `dynstate` pass-through wrappers and `dynCulprit` conversion boilerplate in `scan.go`, and move test-only `scanPureDirectivesAt` / `scanSubjectsInWithBuildFlagsEnv` to `frontend_harness_test.go`.
2. **Batch `Snapshot`/`Sibling` Observability & Share Validation Brackets**:
   - Batch package-mates into `ComputeObservabilityBatch` (up to 64 subjects per SSA build) and publish verified `Observability` proofs back to the parent `Snapshot` after `ensureObservable`'s closing `v.observe(ctx)` succeeds.
   - Share the re-observation bracket when both `hasObserved` and `hasApplicability` are active in `Snapshot.Validate`.
3. **Fix `prepareOutcomeSupport` (`session.go:1125`) & Eliminate Redundant Subprocess/Digest Work**:
   - Scope `prepareOutcomeSupport` so only `observedSubjects` are marked in `v.capturedObserved` (and add a regression test for mixed pure + observed multi-subject `Unit`s).
   - Pass `meta` from `scanViewSubjectsWithMemo` into `deriveViewDynamicState`, reuse session `buildFlags` in `NewBracketAt`, prime `ExplainDynamicState` from `v.facts.snapshot`, deduplicate `OutcomeBinding` in `Unit.Register` and `CompletedState` in `Unit.Close`, retain sorted vouches on `Session`, avoid allocating a `Sibling` in `CurrentFacts`, and avoid double `prepareCandidates` in `CheckBatchWithLedgers`.
