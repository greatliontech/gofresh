# Chunk 1 Working Notes — Foundation & Leaf Package Consolidation

## Fleet Sequencing Alignment (User Alignment 2026-11-21)

- Freeze legacy consumer refactoring (`stipulator` Chunks 3–4, `pew` Chunk 1, `gomutant` Chunk 1 + `PrepareTrackedChdirSupport`) and execute the fleet strictly bottom-up with zero double work:
  1. **Stage 1 (`gofresh`):** Principled repackaging, IR/lattice consolidation, target consumer-boundary capabilities, and Generation-1 public surface retirement (`docs/plans/plan.md` Chunks 1–7) -> release `gofresh`.
  2. **Stage 2 (`stipulator`):** Ground-up re-derivation directly on consolidated `gofresh` -> release & install `stipulator`, then run full witness-executing `stipulator check` on `gofresh` and `stipulator`.
  3. **Stage 3 (`gomutant`):** Ground-up re-derivation on consolidated `gofresh` + ground-up `stipulator` (`Unit` / `CheckingUnit` replacing Generation-1 `ProducerFrame` / `Bracket` / `MergeObservations`) -> release & install `gomutant`.
  4. **Stage 4 (`pew`):** Ground-up re-derivation on consolidated `gofresh` + ground-up `stipulator` + ground-up `gomutant` -> release & install `pew`.
  5. **Stage 5 (Fleet Sweep):** Single end-to-end `stipulator check`, `GOFRESH_TRACE=all` `gomutant` campaign, and `pew` baseline verification across all 4 repos.

## Chunk 1 Governing Contracts & Scope

- **Specs:**
  - `docs/specs/overview.md`: `REQ-fresh-go-command-policy`, `REQ-fresh-coherent-view`, `REQ-fresh-trace`, `REQ-fresh-trace-non-interference`
  - `docs/specs/guards.md`: `REQ-guard-buildconfig`, `REQ-guard-explicit-build`, `REQ-guard-buildconfig-failclosed`, `REQ-guard-selective-capture`
  - `docs/specs/closure.md`: `REQ-closure-test-variant-hash`, `REQ-closure-test-variant-identity`, `REQ-closure-test-variant-ledger`, `REQ-closure-test-variant-inertness`, `REQ-closure-identity-strategy`
- **Structural Consolidations in Chunk 1:**
  1. **Retire `internal/closure/internal/digest` (18 LOC) and `internal/render` (22 LOC):**
     - Standardize 128-bit truncated SHA-256 hex encoding (`hex.EncodeToString(sum[:16])`, avoiding 64-byte string allocation + slice) in a small leaf helper or inline where appropriate; inline/move `CappedList` into its 2 callers (`validate.go` and `internal/runtimeinput/attribution.go`).
  2. **Unify `cmd/go` & package-listing metadata in `internal/gotool` + clean `internal/testenv`:**
     - Merge `internal/buildflags` (`flags.go`, `quoted.go`, 195 LOC; `REQ-guard-buildconfig-failclosed` bound to `Validate`) and `internal/closure/internal/listing` (`listing.go`, 122 LOC) + `GraphPackage` / `PackageClass` (currently in `internal/dynstate/facts_codec.go:21-45`, which forced `internal/closure` to import `internal/dynstate` solely for those two types!) into `internal/gotool`.
     - Move test-only `GoBuildCache` and `PreserveBuildCache` out of production `internal/gotool/env.go` into `internal/testenv`, deduplicate `envLastValue` in `internal/testenv/frontend.go` onto `gotool.LookupEnv`, and split `internal/testenv/frontend.go` (`1,137` LOC -> `frontend.go` + `stdlib_cache.go`, both `<= ~650` LOC).
  3. **Unify build-guard hashing in `internal/guard`:**
     - Move `completeBuildGoEnvKeys`, `completeBuildOSEnvKeys`, `completeBuildEnvironment`, and `normalizedGCCFlags` (`session.go:539-708`, 170 LOC) into `internal/guard/buildenv.go` (`guard.CompleteBuildEnvironment`), putting 100% of compilation-environment guard hashing in `internal/guard` and removing root `gofresh`'s direct import of `buildflags`.
  4. **Reunite `TestVariantLedger` in `internal/testvariant`:**
     - Merge `internal/closure/internal/compartment` (`compartment.go`, 462 LOC; 3 bound prod symbols `AddBaseBindings`, `ComputeIdentity`, `parseTestVariantFile` + 11 witness tests) into `internal/testvariant` (`compartment.go` + `testvariant.go`).
     - Delete the cycle-breaking `compartment.Source` and `compartment.ParseMemo` callback interfaces (`compartment.go:60-81`) and `closure/filememo.go`'s `variantParseMemo` adapter; expose pure `testvariant.ParseFile(baseName string, src []byte)` so `closure`'s `dirMemo` caches it directly alongside `canonicalDigest`.
  5. **Consolidate stdlib purity switches onto `internal/auditset` & split `auditset.go`:**
     - Audit ad-hoc stdlib purity switches in `dynstate` (`capsule/methods_and_sinks.go:238`, `cone_flowir.go:560-692`, `discharges_once_memo_recv.go:523`) against `internal/auditset/traits.go`, consolidating shared pure-stdlib traits into `internal/auditset`, and split `internal/auditset/auditset.go` (`911` LOC) into cohesive files (`packages_symbols.go` + `receivers_linknames.go`).
  6. **Policy & Static Stipulator Hygiene:**
     - Update `.stipulator/policy.textproto` (`race:leaf` package list removing retired `./internal/buildflags` and `./internal/render`), run `stipulator retarget` + `stipulator pin` + `stipulator verify --no-test --view bindings` ensuring `0` non-`current` / non-`resolved` rows.
