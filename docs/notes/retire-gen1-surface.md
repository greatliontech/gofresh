# Chunk 7 Working Notes: Retire Generation-1 Surface & `internal/outcome`, Split `view.go`, Final Verification & Release

## Scope & Goals

1. Make `Session -> Snapshot -> RuntimeBinding/BuildBinding -> Unit / CheckingUnit` the sole public producer and checking protocol across `docs/specs/` (`overview.md`, `evidence.md`, `guards.md`, `purity.md`, `explain.md`, `runtime-inputs.md`, `closure.md`) and `package gofresh`.
2. Retire `internal/outcome` into `internal/runtimeinput/outcome.go` (zero cycles) and prune dead Generation-1 `Observation` union/conversion/adoption/seal scaffolding (`Adopt`, `Merge`, `Absolute`, `Relative`, `Observation.seal`) and `Snapshot` `deferredCheckClose`/`applicabilityChecks` scaffolding.
3. Consolidate `observationFacts` per-subject maps into `subjectEntry`, `executionModelProjection` per-subject maps into `projectedSubject`, and `Snapshot` per-subject transaction maps into `subjectTxState`, and split `view.go` into cohesive `view.go`, `errors.go`, and `facts.go` so **100% of production files in `gofresh` are `<= ~1,050` LOC**.
4. Migrate Generation-1 tests onto `Unit` and `CheckingUnit`, align static `stipulator` records (`compile`, `dispose`, `retarget`, `unbind`, `pin`, `verify --no-test --view bindings`), converge adversarial review to `ZERO FINDINGS`, delete `docs/plans/plan.md` and `docs/notes/retire-gen1-surface.md`, commit, `git push origin main`, and verify the automated CI `Release` tag mints cleanly.

## Progress & Key Structural Decisions

- **Step 7.1 — Specs & Requirement Disposals (DONE)**:
  - Updated `docs/specs/{overview,evidence,guards,explain,runtime-inputs}.md` (`old -> new`).
  - Disposed `REQ-fresh-runtime-producer`, `REQ-inputs-merge`, `REQ-inputs-absolute-identities`, and `REQ-inputs-adoption` (`stipulator dispose retire`), and updated `REQ-inputs-relative-identities` to native `rel` path ingestion.
- **Step 7.2 — Retire `internal/outcome` & Prune `internal/runtimeinput` (DONE & VERIFIED)**:
  - Folded `internal/outcome` into `internal/runtimeinput/outcome.go` + `outcome_test.go`, unexporting `outcomeSpan`, `bindOutcome`, `prepareTrackedChdir`, and `matchesTrackedChdir` so cross-package capability forging is unrepresentable.
  - Pruned `Absolute`, `Relative`, `Adopt`, `Merge`, `convertIdentityKinds`, `convertAttributionDir`, and multi-process `Observation.seal` in `internal/runtimeinput/observation.go` (`Observation` retains `process string` + `sealed State` for $O(1)$ tamper detection in `CompletedState`).
- **Step 7.3 — Retire Generation-1 Root Exports, Consolidate `subjectEntry`/`subjectTxState` & Split `view.go` (DONE & VERIFIED)**:
  - Removed Generation-1 exports (`CaptureGuards`, `BuildDescription.GoEnv`, `Session.SnapshotFor`, `Snapshot.CaptureObservedBatch` -> `captureObservedBatch`, `Snapshot.AttachObservation`, `Snapshot.Sibling` -> `sibling`, `Snapshot.Check*`, `Snapshot.Validate` -> `validate`, `Snapshot.PrepareTrackedChdirSupport`, `RuntimeBinding.ProducerSnapshot`, `CulpritFromReason`, `ResolveToolchainSelection`, and raw `Bracket*`/`Observation`/`CompletedObservationState`/`IncompleteRuntimeObservation`/`AbsoluteObservation`/`RelativeObservation`/`AdoptObservation`/`MergeObservations`/`FromTestLog*`/`TestLogOption`/`With*`/`TrackedChdirSupport`/`InputRoots`/`FrameOptions`/`ProducerFrame`/`CaptureProducerFrame`/`ProducerIngest`/top-level `CheckFileInputEligibility`) and `deferredCheckClose`/`applicabilityChecks`.
  - Consolidated `observationFacts` maps into `subjects map[Subject]subjectEntry`, `executionModelProjection` maps into `subjects map[Subject]projectedSubject`, and `Snapshot` transaction maps into `txState map[Subject]subjectTxState`.
  - Split `view.go` into `errors.go`, `facts.go`, and `view.go`; verified **100% of non-test `.go` files across `gofresh` are `<= 1,007` LOC**.
- **Step 7.4 — Root Test Migration & Static `stipulator` Alignment (DONE & VERIFIED)**:
  - Migrated all 14 root test files onto `Unit`, `CheckingUnit`, `RuntimeBinding`, and internal `Snapshot` helpers; deleted redundant `producer_snapshot_test.go`.
  - Retargeted/unbound 33 moved/retired `stipulator` binding rows across `.stipulator/bindings/*.textproto`, updated `.stipulator/policy.textproto`, compiled, pinned, and verified **939/939 rows `current` and `resolved`**.

## Root-Cause Diagnoses & Fixes Surfaced During Verification

1. **`CheckingUnit.Close` Pass Economy & Non-Upgrade Monotonicity (`checking.go`)**:
   - *Diagnosis*: `CheckingUnit.close` unconditionally built a `newSeededValidationView` (1 `observe` pass) *and* ran `closeValidationReobservation` (a 2nd `observe` pass) even when zero slots selected an applicability proof (`slot.result.selected == false`), doubling `go list` + source-hashing + `go env` work on every `RuntimeBinding.Check` / `CheckBatchWithLedgers`. Furthermore, if an opening round judged an applicability-bearing candidate `Unverifiable` (e.g., due to a current applicability cut or unsupported inventory), leaving `records[i].observed = true` on `Close` allowed a seeded closing view to upgrade that slot from `Unverifiable` to `Valid`.
   - *Fix*: Added `needsSeededCloseView()` (`slot.result.selected`) so `Close` uses `cloneShell` + the single closing `closeValidationReobservation` when no applicability proof needs re-establishment, and cleared `records[i].observed = false` in `closeSlots` whenever `slot.result.verdict.Status != Valid` (verified via 2-round `CheckingUnit` regression test and `gomutant ephemeral` probe).
2. **`outflowAnalyzer` Mutual-Recursion Termination (`internal/dynstate/summary_env_returns.go`, `summary_env_returns_eval.go`)**:
   - *Diagnosis*: Surfaced when scanning `gofresh`'s own packages under `TestModulePackagesHaveNoSharedDynamicStateUnderPackageExecution`: `checkPlainCallReachArg` invoked `allowSigLeaf -> evalFree(ctx, leaf)` on signature-carrying non-mutable-reach call expressions (such as functions returning structs with `func` fields), and `evalFree` invoked `checkPlainCallReachArg` with a freshly reset `seen` map, causing infinite recursion on cyclic mutable-reach call writebacks (`m["self"] = deriveHook(m)`).
   - *Fix*: Moved `reachVisiting map[reachVisitKey]bool` (`{obj, allowInsParam}`) onto `outflowEvalCtx` (propagated across `litCtx`), guaranteeing termination on all cycles while preserving `judgeObj`'s coinductive `provingDepth` for parameter insertion. Pinned by `TestOutflowEvalTerminatesOnCyclicSignatureLeafCallWriteback`.
3. **Root-Indexed Bitset Hub Solver (`internal/dynstate/internal/seams/parallel_solve.go`) & Parallel `Compose` (`scan_dynstate.go`)**:
   - *Diagnosis*: `seams.(*parGraph).buildAndSolve` previously ran two full-graph DFSs + slice sorts per internal node with `liveIn >= 2 && liveOut >= 2` ($O(V \cdot E)$ on large packages), and `scanDynamicState` ran `dynstate.Compose` serially across all view packages.
   - *Fix*: Replaced per-node hub DFSs with 1 forward + 1 backward root-indexed `[]uint64` bitset propagation pass per distinct root and zero-allocation `compareRootBitsets` (verified by `TestRapidCompareRootBitsetsMatchesSliceCompare`), added `dynstate.factof.start` tracing + `FactOfWithHooksCtx(ctx, ...)`, and parallelized pure `dynstate.Compose` across `viewPackages` with a bounded `GOMAXPROCS` worker pool.
4. **Nil `v.facts` Guarding on Synthetic Test Snapshots (`judgment.go`, `facts.go`, `view.go`)**:
   - Guarded `v.facts != nil` in `judgmentFor`, `observationFacts.closure`, and `purityMatches` so synthetic uninitialized `&Snapshot{moduleDir: dir}` test fixtures never dereference `nil` `v.facts`.

## Verification Summary (Step 7.5)

- **Full `godst` (`go1.27.4-dst.17`) `-race -failfast ./...` suite**: 100% GREEN across all 25 packages (root `1573.88s`, including `TestModulePackagesHaveNoSharedDynamicStateUnderPackageExecution` in `612.16s`).
- **Full Vanilla Go (`1.27.4`) `-race -failfast ./...` suite**: 100% GREEN across all 25 packages (root `1621.13s`, `internal/observability` `919.90s`, `internal/toolchain` `174.04s`, `internal/closure` `160.12s`, `internal/dynstate` `51.96s`).
- **Targeted `gomutant ephemeral` Probes**: 6/6 killed (`internal/runtimeinput/observation.go` `CompletedState`, `internal/dynstate/internal/seams/parallel_solve.go` `compareRootBitsets`, `internal/dynstate/summary_env_returns_eval.go` `checkPlainCallReachArg`, `checking.go` `closeSlots`, `judgment.go` `judgmentFor`, `scan_dynstate.go` `ComposeCtx`).
- **Static `stipulator` Alignment**: 939/939 binding rows `current` and `resolved`.

## Independent Adversarial Review Dispositions

### Round 1 (`4af7fa93-0548-4b66-acdf-e2d500838518`)
1. **Finding 1 (`MEDIUM`, `introduced` — CONFIRMED, FIXED)**: `scan_dynstate.go` parallel `Compose` worker pool dropped `ctx` trace sinks (`ConeQuery{Ctx: nil}`), local mutable package `deriveLocalFact` / `interEntries` called contextless `dynstate.FactOf`, and `rootLocals`/`interEntries`/`missing`/`extraVariantFacts`/`composeOne` omitted `ctx.Err()` checks. Added `dynstate.ComposeCtx(ctx, ...)`, routed all `scan_dynstate.go` fact derivations through `FactOfWithHooksCtx(ctx, ...)`, checked `ctx.Err()` across every loop and worker boundary, and pinned `dynstate.factof.done`, `dynstate.compose.done`, and cancelled-context `Snapshot` refusal in `TestTraceCausalWitnessesAcrossDomains` + `gomutant ephemeral` Probe 6.
2. **Finding 2 (`MEDIUM`, `introduced` — CONFIRMED, FIXED)**: `REQ-fresh-producer-view` (`docs/specs/overview.md`) claimed child observed preparation published uncut proofs in-memory onto the shared `Snapshot` generation; removed that unimplemented claim to match `ensureObservable` (`v.txState` + persistent memo store) and `REQ-fresh-historical-implementation`.
3. **Finding 3 (`LOW`, `introduced` / `adjacent` — CONFIRMED, FIXED)**: Updated leftover Generation-1 / stale wording across `docs/specs/runtime-inputs.md` (`REQ-inputs-guard-covered`, `REQ-inputs-ephemeral-root`), `fingerprint.go` (`SingleSubjectExecution` and 3-kind `Fingerprint.Validate` doc comments), `scan.go` (`Snapshot.sibling`), and the 7-domain trace lists in `docs/specs/overview.md` (`REQ-fresh-trace`), `session.go`, and `internal/trace/trace.go`.
4. **Finding 4 (`LOW`, `introduced` & `adjacent` — CONFIRMED, FIXED)**: Deleted 4 zero-caller dead functions (`currentAndManifestWithModuleRoot`, `compatibleObservationProofMode`, `scanFromEntries`, `chainResolveObserved`) and inlined 3 redundant single-caller pass-through wrappers (`runtimeMotionAt`, `withEndpointMovedInputs`, `admittedObservationForModel`).
