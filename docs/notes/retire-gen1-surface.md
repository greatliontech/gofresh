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
  - Verified `go test -short -race -failfast ./internal/runtimeinput ./internal/observability` green.
- **Step 7.3 — Retire Generation-1 Root Exports, Consolidate `subjectEntry`/`subjectTxState` & Split `view.go` (DONE & COMPILED)**:
  - Removed Generation-1 exports (`CaptureGuards`, `BuildDescription.GoEnv`, `Session.SnapshotFor`, `Snapshot.CaptureObservedBatch` -> `captureObservedBatch`, `Snapshot.AttachObservation`, `Snapshot.Sibling` -> `sibling`, `Snapshot.Check*`, `Snapshot.Validate` -> `validate`, `Snapshot.PrepareTrackedChdirSupport`, `RuntimeBinding.ProducerSnapshot`, `CulpritFromReason`, `ResolveToolchainSelection`, and raw `Bracket*`/`Observation`/`CompletedObservationState`/`IncompleteRuntimeObservation`/`AbsoluteObservation`/`RelativeObservation`/`AdoptObservation`/`MergeObservations`/`FromTestLog*`/`TestLogOption`/`With*`/`TrackedChdirSupport`/`InputRoots`/`FrameOptions`/`ProducerFrame`/`CaptureProducerFrame`/`ProducerIngest`/top-level `CheckFileInputEligibility`) and `deferredCheckClose`/`applicabilityChecks`.
  - Consolidated `observationFacts` maps into `subjects map[Subject]subjectEntry`, `executionModelProjection` maps into `subjects map[Subject]projectedSubject`, and `Snapshot` transaction maps into `txState map[Subject]subjectTxState`.
  - Split `view.go` into `errors.go`, `facts.go`, and `view.go`; verified `go build .` green and 100% of production files in `gofresh` `<= 991` LOC.
- **Step 7.4 — Migrate Root Tests onto `Unit` and `CheckingUnit` & Update Static `stipulator` Bindings (IN PROGRESS)**.
- **Step 7.5 — Dual-Toolchain Suites, Mutation Probes, Adversarial Review & CI Release (NEXT)**.
