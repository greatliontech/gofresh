# Chunk 7 Working Notes: Retire Generation-1 Surface & `internal/outcome`, Split `view.go`, Final Verification & Release

## Scope & Goals

1. Make `Session -> Snapshot -> RuntimeBinding/BuildBinding -> Unit / CheckingUnit` the sole public producer and checking protocol across `docs/specs/` (`overview.md`, `evidence.md`, `guards.md`, `purity.md`, `explain.md`, `runtime-inputs.md`, `closure.md`) and `package gofresh`.
2. Retire `internal/outcome` into `internal/runtimeinput/outcome.go` (zero cycles) and prune dead Generation-1 `Observation` union/conversion/adoption/seal scaffolding (`Adopt`, `Merge`, `Absolute`, `Relative`, `Observation.seal`) and `Snapshot` `deferredCheckClose`/`applicabilityChecks` scaffolding.
3. Consolidate `observationFacts` per-subject maps into `subjectEntry` and `Snapshot` per-subject transaction maps into `subjectTxState`, and split `view.go` into cohesive `view.go`, `errors.go`, and `facts.go` so **100% of production files in `gofresh` are `<= ~1,050` LOC**.
4. Migrate Generation-1 tests onto `Unit` and `CheckingUnit`, align static `stipulator` records (`compile`, `dispose`, `retarget`, `unbind`, `pin`, `verify --no-test --view bindings`), converge adversarial review to `ZERO FINDINGS`, delete `docs/plans/plan.md` and `docs/notes/retire-gen1-surface.md`, commit, `git push origin main`, and verify the automated CI `Release` tag mints cleanly.

## Ordered Execution Sub-Steps

- **Step 7.1 — Specs & Requirement Disposals**:
  - Dispose `REQ-fresh-runtime-producer`, `REQ-inputs-merge`, `REQ-inputs-absolute-identities`, and `REQ-inputs-adoption` (`0` incoming edges).
  - Update `REQ-inputs-relative-identities` (`old -> new`) to specify native checkout-free `rel` identity ingestion inside the declared evidence root.
  - Update `overview.md`, `evidence.md`, `guards.md`, `explain.md`, and `runtime-inputs.md` (`old -> new`) onto `Session -> Snapshot -> RuntimeBinding/BuildBinding -> Unit / CheckingUnit`.
- **Step 7.2 — Retire `internal/outcome` & Prune `internal/runtimeinput`**:
  - Fold `internal/outcome/outcome.go` + `outcome_test.go` into `internal/runtimeinput/outcome.go` + `outcome_test.go`, delete `internal/outcome/`, and remove `./internal/outcome` from `.stipulator/policy.textproto`.
  - Delete `Absolute`, `Relative`, `Adopt`, `Merge`, `convertIdentityKinds`, `convertAttributionDir`, and `Observation.seal` multi-process origin scaffolding in `internal/runtimeinput/observation.go`, and update `internal/runtimeinput/*_test.go`.
- **Step 7.3 — Retire Generation-1 Root Exports, Consolidate `subjectEntry`, & Split `view.go`**:
  - Remove/unexport Generation-1 exports (`CaptureGuards`, `BuildDescription.GoEnv`, `Session.SnapshotFor`, `Snapshot.CaptureObservedBatch` -> `captureObservedBatch`, `Snapshot.AttachObservation`, `Snapshot.Sibling` -> `sibling`, `Snapshot.Check*`, `Snapshot.Validate` -> `validate`, `Snapshot.PrepareTrackedChdirSupport`, `RuntimeBinding.ProducerSnapshot`, `CulpritFromReason`, `ResolveToolchainSelection`, and raw `Bracket*`/`Observation`/`CompletedObservationState`/`IncompleteRuntimeObservation`/`AbsoluteObservation`/`RelativeObservation`/`AdoptObservation`/`MergeObservations`/`FromTestLog*`/`TestLogOption`/`With*`/`TrackedChdirSupport`/`InputRoots`/`FrameOptions`/`ProducerFrame`/`CaptureProducerFrame`/`ProducerIngest`/top-level `CheckFileInputEligibility`), plus `deferredCheckClose` and `applicabilityChecks` scaffolding.
  - Consolidate `observationFacts` per-subject maps into `subjects map[Subject]subjectEntry` and `Snapshot` transaction maps into `txState map[Subject]subjectTxState`.
  - Split `view.go` into `view.go`, `errors.go`, and `facts.go`.
- **Step 7.4 — Migrate Root Tests onto `Unit` and `CheckingUnit` & Update Static `stipulator` Bindings**:
  - Migrate root `*_test.go` files onto `Unit` and `CheckingUnit`, delete `producer_snapshot_test.go`, update `surface_test.go`, and verify `stipulator compile` + `verify --no-test --view bindings`.
- **Step 7.5 — Dual-Toolchain Suites, Mutation Probes, Adversarial Review & CI Release**:
  - Run full `godst` and vanilla Go `1.27.4` suites, `gomutant ephemeral` probes, adversarial review to `ZERO FINDINGS`, delete `docs/plans/plan.md` and `docs/notes/retire-gen1-surface.md`, commit, `git push origin main`, and monitor GitHub Actions `CI` + `Release` via `schedule`.
