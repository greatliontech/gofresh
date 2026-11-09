# Batch `Snapshot`/`Sibling` Observability and Eliminate Redundant `observeView` & Validation Passes

**Lands:** Chunk 6 in [`docs/plans/plan.md`](../plans/plan.md) (`Redesign Snapshot / Sibling Observability Sharing & stipulator Solo Scoping`).

## Context & Concrete Findings

### 1. $N$ Solo `Unit`s in One Package Trigger $3N$ `observeView` Passes and $N$ Full Package SSA Builds (`unit.go:142-250`, `view.go:982-1199, 1823-1959`, `internal/closure/observability.go:378-500`)

- `RuntimeBinding.Begin` (`unit.go:142-173`) derives a 1-subject `Sibling` (`u.view`) from `b.snapshot` (`view.go:982-1082`). `Sibling()` copies only entries already present in `b.snapshot.observable` at derivation time (`view.go:1022-1026`).
- In `Unit.Register` (`unit.go:229-250`), when `decide(...) != Valid`, `u.view.prepareOutcomeSupport` calls `u.view.CaptureObservedBatch(ctx, [s_i])` -> `u.view.ensureObservable(ctx, [s_i])` (`view.go:1823-1959`).
- Because `observableRequests` has length 1 (`[s_i]`), `hasher.ComputeObservabilityBatch` (`observability.go:378-500`) loads and builds the **entire package's test-binary SSA program**, runs attributed bitmask reachability for **1 of 64 available bitmask slots**, writes only `[s_i]` to the disk memo (`observability.go:492`), releases the SSA program (`observability.go:430`), runs a closing `v.observe(ctx)` pass (`view.go:1939`, `observeView` #1), and stores `observable[s_i]` only in the ephemeral child `u.view.observable`.
- The next solo unit $s_{i+1}$ in the same package misses both `b.snapshot.observable` and the disk memo, rebuilding the entire package SSA from scratch ($N$ full SSA builds instead of $\lceil N/64 \rceil$) and running another `observeView` pass.
- In `Unit.Close` (`unit.go:505`) -> `u.view.Validate(ctx)` -> `validateObserved(ctx)` (`view.go:1123-1199`), `newSeededValidationView(ctx)` (`view.go:1084-1121`) runs `v.observe(ctx)` (`observeView` #2) and proves zero source/guard/closure drift, but initializes `current.observable` to an empty map (`view.go:1114`), forcing `current.ensureObservable(ctx, [s_i])` (`view.go:1162`) to run a second closing `v.observe(ctx)` (`observeView` #3).

### 2. Duplicate `hasher.GraphMetadata` Call During View Construction (`view.go:2446` and `view.go:3022`)

- `scanViewSubjectsWithMemo` calls `meta, err := hasher.GraphMetadata(pkgPaths...)` at `view.go:2446` for `misses`, and `deriveViewDynamicState` immediately calls `hasher.GraphMetadata(viewPackages...)` again at `view.go:3022` on the exact same `misses` slice instead of passing `meta`.

### 3. Redundant `go env -json` Subprocess Spawns in `closure.NewBracketAt` (`view.go:1857`, `internal/closure/closure.go:317-318`)

- `ensureObservable` invokes `closure.NewBracketAt(ctx, v.session.repoRoot, v.session.cacheRoot, v.session.vouched, v.session.flagArgs...)` (`view.go:1857`), which calls `buildflags.Validate` and spawns a `go env -json` subprocess even though `v.session` already holds a validated `envSnapshot` and `buildFlags`.

### 4. `Snapshot.Validate` Runs 4 `observeView` Passes When Both `hasObserved` and `hasApplicability` Are Active (`view.go:885-900`, `checking.go:747-760`)

- When a `Snapshot` has both observed captures (`hasObserved`) and applicability checks (`hasApplicability`), `Snapshot.Validate` calls `validateObserved` (2 `observeView` passes) followed by `validateApplicabilityChecks` (2 `observeView` passes) instead of sharing one re-observation bracket.

### 5. Redundant Digest & Environment Recomputations in `Unit.Register`, `Unit.Close`, and `completeBuildEnvironment`

- `Unit.Register` computes `frame.OutcomeBinding(process.Identity, env)` 3 times for the same inputs (`unit.go:210`, `unit.go:273`, and `session.go:1121` via `validateObservedRegistration`).
- `Unit.Close` computes `runtimeinput.CompletedState(observation)` twice (`unit.go:630` and `unit.go:487`).
- `completeBuildEnvironment` (`session.go:996-1080`) re-unmarshals `snapshot.JSON` and re-stats/reads the `GOENV` file on every `observeView` pass even when `snapshot` is the immutable cached `v.session.envSnapshot` and `observation.Env` has no `GOENV` override.

## Resolution

During Chunk 6 (`Redesign Snapshot / Sibling Observability Sharing & stipulator Solo Scoping`):
1. When `ensureObservable` computes observability for an uncached subject in package $P$, batch all subjects of package $P$ present in the view/parent into `ComputeObservabilityBatch` (up to 64 subjects per SSA bitmask pass) and, after `ensureObservable`'s closing `v.observe(ctx)` succeeds, publish the verified `Observability` proofs back to the parent `Snapshot` so subsequent `Sibling`s inherit them at `Sibling()` time (`0` SSA builds and `0` `observeView` passes in `Register` for $s_2 \dots s_N$), while preserving all guard/bracket invariants pinned by `TestRuntimeBindingGuardAgreementAndClosing` and `TestObservedProducerLifecyclePassEconomy`.
2. Pass `meta` from `scanViewSubjectsWithMemo` into `deriveViewDynamicState`, reuse validated session `buildFlags` in `NewBracketAt`, share the re-observation bracket when both `hasObserved` and `hasApplicability` are active, and eliminate duplicate `OutcomeBinding`, `CompletedState`, and `completeBuildEnvironment` work.
