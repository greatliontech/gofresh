# Audit 08b: `closure` Tests Part 2, `closure/testvariant`, `closure/internal` Tests, and `closure/fixtures/*`

## 1. Executive Summary & Scope Verification

### 1.1 Assigned Scope & 100% Read Verification

Every single line of all 47 test files in Scope 08b (13,913 lines across the 46 prompt-listed files, noting that the prompt's `closure/internal/compartment/ledger_test.go` and `closure/internal/program/program_test.go` correspond on disk to `closure/internal/compartment/bindings_test.go` and `closure/internal/program/prepared_test.go`) and all 127 top-level fixture directories (135 Go package directories, 222 files, 4,102 lines) under `closure/fixtures/` were read and audited in full.

| Sub-Scope | File / Directory Count | Total Lines Read | Status |
| :--- | ---: | ---: | :--- |
| `closure/*_test.go` (Part 2: `flagset_test.go` .. `viewload_test.go`) | 41 files | 12,152 lines | 100% read |
| `closure/testvariant/testvariant_test.go` | 1 file | 214 lines | 100% read |
| `closure/internal/*/*_test.go` (`cachefile`, `compartment`, `program`, `rta`) | 5 files | 1,769 lines | 100% read |
| `closure/fixtures/*` | 127 top-level dirs (222 files) | 4,102 lines | 100% inspected & mapped |
| **Total** | **47 test files + 222 fixture files** | **18,237 lines** | **100% complete** |

### 1.2 Top-Level Architectural & Testing Findings

1. **`closure/fixtures/*` Pollutes Module Package Space with 135 Accidental Importable Packages**:
   - Because `closure/fixtures/` is not named `testdata/` and has no `go.mod` boundary, `go list ./...` at the repository root discovers and compiles **135 fixture packages** under `github.com/greatliontech/gofresh/closure/fixtures/...`.
   - Worse, several fixture packages (`embedfixture`, `externaldirective`, `puredirective`) are not even referenced by `closure/*_test.go` (they are only referenced by higher-level `runner` or legacy tests, or are completely orphaned in `closure/`), and **over 105 of the 127 fixture directories** are single-package 10–35 line Go snippets testing pure AST/type/SSA/RTA classification rules that do not need on-disk fixture packages at all.
2. **Severe Over-Use of Subprocess `go list` + Whole-Program SSA/RTA (`newAt(dir)`) for Local Unit/AST/Type Rules**:
   - `closure/internal/rta/rta_test.go` proves that `ssautil.BuildPackage` builds SSA from an in-memory Go source string in `< 1 ms` without spawning `go list` or loading standard library bodies from disk.
   - Despite this, `generic_test.go` (8 tests), `genericbounded_test.go` (8 tests + 6 subtests), `genericmethod_test.go` (2 tests), `flagset_test.go` (11 subpackages), `flagsetprov_test.go` (25 subpackages), `narrowdispatch_test.go` (9 subpackages), `paramcrossing_test.go` (9 subpackages), `outcomes_test.go` (17 subpackages + 4 full loads), `syncmemo_test.go` (5 subpackages), `ssahandles_test.go` (4 subpackages), and `propertyharness_test.go` (10 subjects) all write temporary module trees to disk and invoke `newAt(dir)` + `ComputeObservabilityBatch`.
   - `TestComputeMaximalBatchConservativelyMarksStandardWrappers` (`maximal_test.go:L135-261`) runs **14 separate `t.TempDir()` + `newAt(dir)` + `ComputeMaximalBatch` invocations in a loop** solely to test single-file AST/type wrapper classification (`maximalFileEffectsContent`), which other tests in the exact same file (`L451-694`) test directly in memory!
   - `TestDstSelectionIsJudgedByContentNeverByTag` (`toolchainsource_dst_test.go:L23-525`) spawns **~25 separate `testenv.OverlayGOROOTEnv` + `newAtEnv` (`go list` over `GOROOT`)** runs in a single test function to test AST/assembly verification of `image/color`, `runtime`, and `os`, duplicating the fast synthetic-file verifier tests in `toolchainsource_test.go` (`TestVerifyToolchainSurfaceEnforcesStructuralContracts` and `TestAssemblyVerifierPreprocessorAndContinuationRejections`).
   - `TestToolchainListingTracksFIPSAliasSelection` (`toolchain_dependencies_linux_test.go:L15-98`) executes `cp -a --reflink=auto` of the **entire `runtime.GOROOT()` tree** multiple times instead of using `testenv.OverlayGOROOTEnv` or a minimal synthetic `GOROOT` tree.
3. **Cross-Package & Cross-File Test Duplication around Test-Variant Ledgers and Inertness**:
   - `closure/testvariant/testvariant_test.go` (`TestInertForSubjectCoversReachabilityAndGuardRails`, `L37-213`) and `closure/internal/compartment/compartment_test.go` (`TestInertForSubjectAttributesReachableReferences`, `L546-759`) test the exact same `testvariant.InertForSubject` reachability, conservative refusal, and blank-const governor rules.
   - `closure/testvariant_binding_test.go` (`TestTestVariantInertnessRejectsRebinding`, `L14-74`) spawns 10 `go test` subprocesses + 10 `newAt` / `ComputeTestVariantLedger` runs to test universe shadowing and import rebinding that `closure/internal/compartment/bindings_test.go` (`TestInertnessPreservesExistingBindings`, `L12-50`) already tests in `< 1 ms` via `parseLedger`!
   - `closure/testvariant_test.go` (`L246-349`, `L581-607`) re-tests ledger declaration sorting and `DiffTestVariantLedgers` classification via slow `newAt(dir)` subprocess loads, duplicating `compartment_test.go` (`L31-305`).
4. **Fragmented File Granularity Across 65 `closure/*_test.go` Files**:
   - Many files in `closure/` are 26–120 line single-test files created per commit/issue (`nilreader_test.go` 26L, `observabilitybench_test.go` 31L, `inventory_variants_test.go` 40L, `toolchainexperiment_test.go` 45L, `listingsalvage_test.go` 53L, `helpers_test.go` 55L, `syncmemo_test.go` 61L, `observabilityrelease_test.go` 62L, `missingroot_test.go` 68L, `tier2driver_test.go` 70L, `paramcrossing_test.go` 73L, `initroot_test.go` 76L, `scope_test.go` 76L, `flagset_test.go` 86L, `narrowdispatch_test.go` 87L, `ssahandles_test.go` 92L). Consolidating these into cohesive domain test files aligned with a 4-tier testing architecture drastically reduces cognitive and maintenance overhead.

---

## 2. Exhaustive File-by-File and Test-by-Test Inventory (Part 2 + Subpackages)

### 2.1 `closure/flagset_test.go` (86 lines)
- **Lines L16–85**: `TestFlagSetFormsRideTheRegistrationJudgment`
  - **Witnesses**: `REQ-closure-observability-flag-registration` (FlagSet registration forms: custom `flag.NewFlagSet` registered in `init`, custom set read without `Parse`, `flag.CommandLine.BoolVar` read vs unread, `flag.CommandLine` pointer alias, local `FlagSet` parsed from `os.Args[1:]`, local `FlagSet` calling `fs.Args()`, `flag.CommandLine` swapped in `init` and registered via package func or method, and `flag.CommandLine` swapped in `init` without read).
  - **Harness / Cost**: Writes 11 subpackages into a temp module and runs `newAt(dir)` + `ComputeObservabilityBatch` (heavy `go list` + whole-program SSA/RTA).
  - **Overlap / Consolidation**: Duplicate harness pattern with `flagsetprov_test.go` and `closure/fixtures/flagreg*` (15 separate fixture directories in `closure/fixtures/`!). All FlagSet registration and provenance cases should live in a single table-driven test sharing one prepared module or in-memory SSA harness.
  - **Target Tier**: Tier 2 (In-Memory / Single-Batch Attributed RTA & Observability Engine).

### 2.2 `closure/flagsetprov_test.go` (119 lines)
- **Lines L15–118**: `TestClosedFlagSetsAreOrdinaryState`
  - **Witnesses**: `REQ-closure-observability-flag-registration` (FlagSet provenance rule across 25 subpackages: `startupclosed`, `startupfunc`, `startupsubjectparse`, `startupopenarg`, `startupopenret`, `startupstore`, `startupescape`, `startupmethod`, `startupreassign`, `startupnil`, `startupfield`, `startupglobal`, `startupparseonly`, `defaultset`, `localclosed`, `localfunc`, `localempty`, `localvar`, `localopen`, `localreparse`, `localreturn`, `localstore`, `localpkgvar`, `localescape`, `localreader`).
  - **Harness / Cost**: Writes 25 subpackages into a temp module and runs `newAt(dir)` + `ComputeObservabilityBatch`.
  - **Overlap / Consolidation**: Merge directly with `flagset_test.go` and the 15 `closure/fixtures/flag*` fixtures into one unified `flag_registration_test.go` batch.
  - **Target Tier**: Tier 2 (Attributed RTA & Observability Engine).

### 2.3 `closure/floorproperty_test.go` (117 lines)
- **Lines L14–51**: `floorModule(t testing.TB, seed uint64) (string, []Subject)` — helper generating a seeded 2–4 package module with transitive imports, optional `os.Args` init effects, and optional `_test.go` files.
- **Lines L58–116**: `FuzzMaximalClosureFloor`
  - **Witnesses**: `REQ-closure-floor` (batch vs solo equivalence of `ComputeMaximalBatch` hashes and source lists, plus never-narrow sensitivity when the root dependency package `p0` is edited).
  - **Harness / Cost**: Spawns `newAt(dir)` once for the batch, once per subject for solo comparison, and once after editing `p0/p0.go` (~5 `newAt` calls per seed).
  - **Target Tier**: Tier 3 (End-to-End Module & Property Integration).

### 2.4 `closure/frontend_test.go` (115 lines)
- **Lines L27–114**: `TestMemoScopesKeyOnTheOneFrontendSpelling`
  - **Witnesses**: `REQ-closure-identity-strategy` (`AnalyzingFrontend()` format `go/types@<runtime.Version()>`, presence in `testingScanScope` and `effectScanScope`, `IdentityStrategy` golden equality, and AST walk over `closure` + `closure/internal` ensuring `runtime.Version()` appears only in `AnalyzingFrontend()`).
  - **Harness / Cost**: Pure in-memory unit + AST check (`< 5 ms`).
  - **Target Tier**: Tier 1 (Pure Unit / AST / Identity Invariants).

### 2.5 `closure/generic_test.go` (475 lines)
- **Lines L14–36**: `writeGenericFixture` — helper writing a 1-package module `example.com/genericfixture`.
- **Lines L38–50**: `genericFixtureBody` — returns Go source with generic `Apply[T any]`, `Touch[T any]`, `PureCall`, `ImpureCall`, `TouchEnv`.
- **Lines L57–120**: `TestAttributedAnalysisCoversGenericSubjects`
  - **Witnesses**: `REQ-closure-analysis` (generic subject `Apply` vs `PureCall` vs `ImpureCall`, batch equivalence, and body-mutation sensitivity on `Apply[T]`).
- **Lines L125–169**: `TestAttributedAnalysisSeesEffectsThroughInstantiations`
  - **Witnesses**: `REQ-closure-analysis` (instantiation effect attribution when `Apply[int]` calls an effectful callback vs pure callback).
- **Lines L173–228**: `TestAttributedAnalysisCoversUninstantiatedGenericSubjects`
  - **Witnesses**: `REQ-closure-analysis` (origin fold over uninstantiated generic functions `DeadPure[T]` and `DeadEnv[T]`, plus body-mutation sensitivity).
- **Lines L235–255**: `TestAttributedAnalysisConvertsUnsupportedShapesToErrors`
  - **Witnesses**: `REQ-closure-analysis` (`arta.Analyze` returns an explicit error rather than panicking when handed a parameterized `*ssa.Function` body directly).
- **Lines L262–300**: `TestZeroParameterGenericSubjectIsForcedOpenWorld`
  - **Witnesses**: `REQ-closure-analysis` (`func Pure[T any]() int` with zero value parameters is refused open-world via `TypeParams()` check).
- **Lines L305–345**: `TestGenericMethodSubjectIsForcedOpenWorld`
  - **Witnesses**: `REQ-closure-analysis` (methods on generic receiver `Box[T]` are refused open-world via `RecvTypeParams()`, while non-generic caller `UsePureBox` closes over concrete `Box[int]`).
- **Lines L354–402**: `TestAttributedAnalysisSkipsParameterizedInstances`
  - **Witnesses**: `REQ-closure-analysis` (forwarding generic `Outer[T] -> Inner[T]` skips parameterized `Inner[T]` instance and analyzes concrete `Inner[int]`).
- **Lines L410–474**: `TestAttributedAnalysisSkipsLocalTypeInstances`
  - **Witnesses**: `REQ-closure-analysis` (generic function declaring a method-bearing local struct `box{v: x}` carrying `T` skips the parameterized local method instance).
- **Harness / Cost**: Every single test writes a temp module and runs multiple `newAt(dir)` + `program.Load` / `ComputeObservabilityBatch` passes (~14 full SSA loads across the file).
- **Consolidation**: Merge with `genericbounded_test.go` and `genericmethod_test.go` into a unified `generic_test.go` that combines read-only subjects into a single module load and tests `arta.Analyze` / constraint-bounding predicates via `ssautil.BuildPackage` in memory.

### 2.6 `closure/genericbounded_test.go` (435 lines)
- **Lines L15–37**: `writeBoundedFixture`, **L39–55**: `boundedBody`, **L259–280**: `flowBody`.
- **Lines L65–125**: `TestConstraintBoundedGenericSubjectAnalyzesClosed`
  - **Witnesses**: `REQ-closure-analysis` (type-set bounded generic `Double[T ~int | ~int64]` closes without instantiation, while `ReadEnv[T ~string]` is refused for `os.Getenv`, and editing `Double[T]` moves its Tier 2 hash).
- **Lines L131–159**: `TestUnboundedConstraintsStayOpenWorld`
  - **Witnesses**: `REQ-closure-analysis` (4 subtests: `comparable`, `method-bearing`, `dirty-union`, `interface-term` remain open-world).
  - **Defect / Cost**: Spawns 4 separate `newAt(dir)` + `ComputeObservabilityBatch` full loads just to test the `go/types` constraint-bounding predicate!
- **Lines L166–197**: `TestBoundedGenericWithoutInstantiationKeepsOriginFold`
  - **Witnesses**: `REQ-closure-analysis` (uninstantiated bounded generic `Uninstantiated[T ~int | ~uint]` and zero-value-arg `ZeroArg[T ~int]` fold origin effects and move hash on body edit).
- **Lines L202–248**: `TestBoundedGenericBatchEquivalence`
  - **Witnesses**: `REQ-closure-analysis` (`ComputeBatch` and `ComputeObservabilityBatch` match solo computations across bounded/unbounded generic subjects).
- **Lines L282–312**: `TestBoundedGenericRootsInstantiationFlow`
  - **Witnesses**: `REQ-closure-analysis` (concrete instantiation `Feed[int](touchEnv)` is rooted alongside the origin so callback effects are attributed).
- **Lines L321–360**: `TestBoundedGenericObservabilitySeesInstantiationEffects`
  - **Witnesses**: `REQ-closure-analysis` (observability refuses `Feed[T]` when instantiated with `touchEnv` and admits when instantiated only with `pure`).
- **Lines L366–389**: `TestRecursiveConstraintsTerminateOpen`
  - **Witnesses**: `REQ-closure-analysis` (2 subtests: `self` and `mutual` recursive constraints `type C[T any] interface{ ~int | C[T] }` terminate without infinite recursion and refuse open-world).
  - **Defect / Cost**: Runs 2 full `newAt(dir)` + `ComputeObservabilityBatch` passes for a pure `go/types` cycle guard!
- **Lines L398–434**: `TestBoundedGenericOriginEscapeEffectsStayVisible`
  - **Witnesses**: `REQ-closure-analysis` (`Stash[T ~int](x T)` storing `any(x)` into package global `sink` is refused for mutating package-level state).

### 2.7 `closure/genericmethod_test.go` (116 lines)
- **Lines L12–65**: `TestAttributedAnalysisCoversGenericMethods`
  - **Witnesses**: `REQ-closure-analysis` (Go 1.27 generic methods `func (r *Ring) N[Int ~int | ~int64](n Int) Int` analyzed via `UsePure`, `UseImpure`, and open-world `Ring.N`).
- **Lines L70–115**: `TestAttributedAnalysisSurvivesStdlibGenericMethods`
  - **Witnesses**: `REQ-closure-analysis` (importing `math/rand/v2` and calling `r.N(int64(10))` builds SSA and proves `RollDeterministic` observable).

### 2.8 `closure/helpers_test.go` (55 lines)
- **Lines L14–54**: Shared test helpers `newAt`, `newAtEnv`, `loadViewPackagesEnv`, `cgoEnabled`, `isolateProofCache`, `unauditedTagGOROOT`.

### 2.9 `closure/initroot_test.go` (76 lines)
- **Lines L15–75**: `TestInitSubjectRootsResolvePositionally`
  - **Witnesses**: `REQ-closure-analysis` (positional `init#<file>.go#<ordinal>` subject resolution across multiple `init()` declarations in `a.go` and `b.go`, plus rejection of bare `"init"` and out-of-range `"init#a.go#2"`).
  - **Target Tier**: Tier 2 (Attributed RTA & Observability Engine).

### 2.10 `closure/inventory_variants_test.go` (40 lines)
- **Lines L5–39**: `TestStandardInventoryCoversPGOCopiesWithoutLosingSourceChecks`
  - **Witnesses**: `REQ-fresh-toolchain-dependencies` (`h.standardInventoryCovers` strips PGO suffixes on standard packages while still rejecting synthetic `.testmain`, empty `ListedFiles`, missing `toolchainInventory`, and mismatched `ListedDir`).
  - **Harness / Cost**: Fast in-memory unit test (`< 1 ms`).
  - **Target Tier**: Tier 1 (Pure Unit).

### 2.11 `closure/listing_dependencies_test.go` (272 lines)
- **Lines L16–72**: `TestListingMemoRejectsRetypedSource` — witnesses `REQ-closure-listing-memo` when a subdirectory `extra.go/` is replaced by a regular Go file `extra.go`.
- **Lines L74–147**: `TestToolchainListingTracksPreviouslyEmptyEmbedDirectories` — witnesses `REQ-fresh-toolchain-dependencies` via a shell-shim `gotool.Runner` when an empty embedded directory `sub/` in a stdlib package gains `leaf.txt`.
- **Lines L149–186**: `TestListingEntriesTrackSymlinkTargetKinds` — fast unit test of `listingEntries` over dangling, directory, and file symlinks.
- **Lines L188–271**: `TestToolchainMemoRejectsIncompleteInventory` — corrupts the persisted `surfaceListing` JSON envelope in 7 ways (`nilPackages`, `emptyPackages`, `missingInventoryEntry`, `extraInventoryEntry`, `blankDigest`, `missingSeed`, `missingDelegate`) and verifies `toolchainSourceDigests` re-lists rather than trusting the corrupt record.
- **Consolidation**: Merge with `listingmemo_test.go` and `listingsalvage_test.go`.

### 2.12 `closure/listingmemo_test.go` (432 lines)
- **Lines L16–109**: Helpers `writeTree`, `listingMemoModule`, `listingEnv`, `listFrom`, `listOnce`, `snapshotFor`.
- **Lines L113–146**: `TestListingMemoServesTheListingWithoutASpawn` — witnesses `REQ-closure-listing-memo` warm hit (0 `go list` spawns on second `newAt`) and equivalence of `ComputeMaximalBatch`, `ComputeBatch`, `ComputeObservabilityBatch`.
- **Lines L157–241**: `TestListingMemoKeyTracksEveryConsultedInput` — tests 12 invalidation axes (adding/deleting/editing `.go` files, ignored files, subdirectories, `go.mod`, `go.sum`, `GOWORK`, `GOOS`, `CGO_ENABLED`, `-tags`, and corrupt cache entry fallback).
- **Lines L247–322**: `TestListingMemoRecordsTheModuleGraphsFiles` — tests `go.work`, unused workspace member `go.mod`, and transitive `replace` target `go.mod` invalidation.
- **Lines L328–353**: `TestListingMemoRecordsADotTestModulesOwnDirectory` — tests module whose path ends in `.test` (`module example.test`).
- **Lines L359–388**: `TestListingMemoServesVendoredTreesFromAnyWorkingDirectory` — tests `-mod=vendor` listing memo hit across different subdirectories.
- **Lines L393–407**: `TestListingMemoStoresNothingWithoutAMainModule` — verifies no listing memo entry is written when `go.mod` is absent.
- **Lines L412–431**: `TestListingScopeCarriesTheRecordShape` — fast reflection check that `typeShape(reflect.TypeFor[listingMemoEntry]())` appears in `listingMemoScope`.

### 2.13 `closure/listingsalvage_test.go` (53 lines)
- **Lines L25–52**: `TestListingRefusesTheSalvagedAnswer` — witnesses `REQ-fresh-go-command-policy` (`errors.Is(err, gotool.ErrListingRefused)` when a child process holds stdout open past `WaitDelay`).

### 2.14 `closure/maximal_facts_test.go` (224 lines)
- **Lines L13–78**: `TestMaximalFactsRetainHiddenBlockers` — fast in-memory test of `newMaximalFacts`, `MaximalFacts.Equal`, `Blocker` projection, and rank ordering across `EffectFact` slices.
- **Lines L80–109**: `TestMaximalFactsOwnTheirInputsAndProjections` — fast in-memory test of defensive copying and `Clone()`.
- **Lines L111–132**: `TestMaximalFactsAvailabilityAndDiagnosticOnlyCandidate` — fast in-memory test of `Complete()` and diagnostic-only facts.
- **Lines L134–213**: `TestComputeMaximalFactsBatchPreservesCompleteScanAndProjection` — module test verifying `ComputeMaximalFactsBatch` vs `ComputeMaximalBatch` over multi-blocker, clean, and non-Go assembly packages.
- **Lines L215–223**: `TestComputeMaximalFactsBatchCancellationReturnsNoFacts` — fast cancelled-context check.

### 2.15 `closure/maximal_test.go` (932 lines)
- **Lines L12–52**: `TestComputeMaximalBatchSharesPackageClosureWithoutSharingIdentity` — verifies distinct symbols in the same package share `pkgHash` but produce distinct subject hashes and reject unknown symbols.
- **Lines L54–82**: `TestComputeMaximalBatchWithSourcesIncludesWidenedPackageFiles` — uses `closure/fixtures/opaqueasm` to check `Sources` inclusion of `.s` and `.inc` files.
- **Lines L84–108**: `TestComputeMaximalBatchConservativelyMarksExternalPackageCode` — external non-stdlib package marked `external-package`.
- **Lines L110–133**: `TestComputeMaximalBatchConservativelyMarksDotImportedExternalCode` — dot-imported external package marked `external-package`.
- **Lines L135–261**: `TestComputeMaximalBatchConservativelyMarksStandardWrappers`
  - **Defect / Cost**: Loops over 14 subcases (`io/ioutil`, `os/signal`, `log`, `net/http/httptest`, `testing/iotest`, `testing/quick`, `testing.B.Loop`, `testing.T.TempDir`, `testing.T.Chdir`, `testing.T.Setenv`, `testing.T.Parallel`, `testing.T.Deadline`, `testing.TB`, `reflect.TypeFor`), creating a new `t.TempDir()`, calling `newAt(dir)`, and running `ComputeMaximalBatch` **14 separate times**! All 14 subcases only exercise `maximalFileEffectsContent` (the Tier 1 AST/type scanner), which is already tested in-memory at L451–694.
- **Lines L263–280**: `TestMaximalTestingMethodClassificationUsesHarnessReceiver` — fast in-memory test of `maximalFileEffectsContent`.
- **Lines L282–308**: `TestComputeMaximalBatchClassifiesCrossFileTestingAlias` — cross-file `type helperTB = testing.TB` alias classification.
- **Lines L310–339**: `TestComputeMaximalBatchClassifiesImportedTestingAlias` — cross-package `alias.TB` classification.
- **Lines L341–367**: `TestComputeMaximalBatchDoesNotClassifyUnrelatedPackageMethod` — unrelated `other.Setenv` is not misclassified as `testing.T.Setenv`.
- **Lines L369–418**: `TestComputeMaximalBatchConservativelyMarksNonGoEdges` — 2 subtests (`linkname`, `assembly`).
- **Lines L420–425**: `TestMaximalPackageMarksImplicitCgoExternal` — fast in-memory test of `maximalPackageEffectsContent` on `_cgo_gotypes.go`.
- **Lines L433–449**: `TestPreferredReasonOrdersRankThenLexicographic` — fast in-memory test of `preferEffectReason` (`REQ-closure-observability-cause-order`).
- **Lines L451–491**: `TestMaximalFileEffectsRetainAllFactsAndLegacyDiagnostic` — fast in-memory test of `maximalFileEffectsContent` (note: contains an unnecessary `if testing.Short() { t.Skip(...) }` even though it does not spawn any subprocess!).
- **Lines L498–560**: `TestMaximalUnauditedOperationNamesThePreferredDiagnostic` — fast in-memory test of `maximalFileEffectsContent` (also contains an unnecessary `testing.Short()` skip).
- **Lines L567–581**: `TestMaximalPackageSelectionRanksTheEffectUnion` — fast in-memory test of `maximalPackageEffectsContent`.
- **Lines L583–597**: `TestMaximalPackageEffectsRetainEveryNativeFact` — fast in-memory test of `maximalPackageEffectsContent`.
- **Lines L599–694**: `TestMaximalFileEffectsDeclaredImportNames` — fast in-memory test of `listedDeclaredNames`, `declaredOverridesKey`, and `maximalFileEffectsContentWithNames`.
- **Lines L696–712**: `TestComputeMaximalBatchHonorsCancellationDuringTraversal` — cancelled context test using `closure/fixtures/direct`.
- **Lines L718–748**: `TestMaximalHashCoversEmbeddedData` — witnesses `REQ-closure-coverage` (`//go:embed` payload edits move maximal hash).
- **Lines L759–823**: `FuzzPreferredReasonTotalAndRankMaximal` — fast in-memory property test of `preferEffectReason` and `effectCauseRank` (`REQ-closure-observability-cause-order`).
- **Lines L831–849**: `TestEffectCauseRankSymbolFreeStrata` — fast in-memory check of `effectCauseRank` strata 0..9.
- **Lines L851–931**: `TestListedNonStandardPathsPreservesDottedExternalClassifications` — fast in-memory test of `listedNonStandardPaths` and `maximalFileEffectsContentWithContextFiltered`.

### 2.16 `closure/memo_test.go` (533 lines)
- **Lines L18–34**: `memoModule` helper.
- **Lines L40–88**: `TestObservabilityMemoServesEquivalentProofsWithoutLoading` — witnesses `REQ-closure-observability-memo` (warm pass serves observability proofs with `programLoads == 0`).
- **Lines L92–179**: `TestObservabilityMemoMissesOnScopeAndSourceChange` — tests cache invalidation across dependency edits, test-file edits, build flags, `GOOS`, and unaudited tag `GOROOT`.
- **Lines L185–243**: `TestBatchEntriesDiscardStaleTestBinaryKeys` — verifies stale `TestBinaryKey` entries in batch requests do not poison or serve stale proofs.
- **Lines L248–337**: `cancelWhenDirNonEmpty` + `TestObservabilityMemoKeepsCompletedSlicesOnDeadline` — verifies completed package slices are persisted before a context deadline interrupts a multi-package batch.
- **Lines L342–374**: `TestObservabilityBatchCountsPersistedProofs` — verifies `ObservabilityPersistedProofs` counter.
- **Lines L379–407**: `TestObservabilityMemoEntryWithoutTheRequestedSubjectServesNothing` — verifies partial cache records lacking the requested subject trigger a load.
- **Lines L409–457**: `TestRootedFunctionsAndBinaryRootedFunctionsMemoServeAcrossPasses` — witnesses rooted-functions memo (`ComputeBatch` / `ComputeBinaryBatch`) warm hit (`programLoads == 0`).
- **Lines L459–532**: `TestRootedFunctionsBatchEntriesDiscardStaleTestBinaryKeysAndHonorContext` — verifies stale `TestBinaryKey` rejection and partial slice persistence on context cancellation for rooted-functions batches.

### 2.17 `closure/missingroot_test.go` (68 lines)
- **Lines L14–67**: `TestMissingRootDegradesSubjectLocally` — witnesses `REQ-closure-analysis` (a missing symbol in a batch degrades only that subject to the package floor in `ComputeBatch` and an explicit refusal in `ComputeObservabilityBatch`, while sibling valid subjects in the batch still get precise RTA proofs).

### 2.18 `closure/narrowdispatch_test.go` (87 lines)
- **Lines L18–86**: `TestClosedCellNarrowsComputedCallTargets` — witnesses `REQ-closure-observability-dispatch` across 9 subpackages (`recursive`, `mutuallyrecursive`, `branchcell`, `branchimpure`, `helperassigned`, `packagevar`, `escapedcell`, `paramcell`, `nilbranch`).
- **Consolidation**: Combine with `paramcrossing_test.go` into the Tier 2 RTA dispatch suite.

### 2.19 `closure/nilreader_test.go` (26 lines)
- **Lines L11–25**: `TestNilReaderRefusesAtEveryEntry` — fast check that `NewAt`, `NewBracketAt`, `LoadViewPackages`, and `LoadViewGraph` reject a `nil` `*gotool.SnapshotReader` before touching the filesystem.

### 2.20 `closure/observabilitybench_test.go` (31 lines)
- **Lines L11–30**: `BenchmarkComputeObservabilityBatch` — benchmarks `ComputeObservabilityBatch` over `observable`, `observablebad`, `observablefresh`, and `observablemutation`.

### 2.21 `closure/observabilityrelease_test.go` (62 lines)
- **Lines L10–37**: `TestObservabilityBatchReleasesPrograms` — verifies `RetainedPrograms == 0` after `ComputeObservabilityBatch`.
- **Lines L42–61**: `TestObservabilityBatchReleasesProgramOnUnrootedGroup` — verifies `RetainedPrograms == 0` when all subjects in a package group are missing/unrooted.

### 2.22 `closure/outcomes_test.go` (211 lines)
- **Lines L11–162**: `TestOutcomeInventorySeparatesAdmissionFromDerivation` — tests `ImmutableEnvironmentOutcomes` across 17 subpackages (`pure`, `env`, `clock`, `rng`, `fs`, `envclock`, `allfour`, `net`, `process`, `mutation`, `goroutine`, `external`, `initenv`, `tsetenv`, `belapsed`, `rapidcheck`, `osargs`) under cold, warm (0 programLoads), `GOOS=plan9`, and unaudited-tag `GOROOT`.
- **Lines L164–210**: `FuzzOutcomeInventoryRejectsUnsupportedEffects` — fast in-memory property test of `immutableEnvironmentMethod`.

### 2.23 `closure/paramcrossing_test.go` (73 lines)
- **Lines L20–72**: `TestCalleeParameterClosesThroughAttributedSites` — witnesses `REQ-closure-observability-dispatch` (callee function-parameter narrowing across 9 subpackages: `directpure`, `directimpure`, `twosites`, `mixedsites`, `transitive`, `interfacecarrier`, `returned`, `stored`, `exportedopen`).

### 2.24 `closure/pgo_binding_test.go` (108 lines)
- **Lines L17–78**: `TestPGOBuildCopiesRetainImportBindings` — generates a real CPU profile via `go test -cpuprofile` and runs `ComputeMaximalBatch` with `-pgo=default.pgo` to verify PGO build copies retain import bindings.
- **Lines L80–107**: `TestSyntheticTestPackageCannotReplaceAnImportBinding` — fast in-memory test over synthetic `listPkg` slices verifying that a `ForTest` or `.test` synthetic package never replaces the canonical import binding.

### 2.25 `closure/policymemo_test.go` (178 lines)
- **Lines L18–26**: `originalPolicyIdentity` helper.
- **Lines L28–47**: `TestPolicyMemoPreservesIdentityAndOwnsItsInputs` — fast in-memory check of `admissionPolicyFor` vs `originalPolicyIdentity` and input map mutation isolation.
- **Lines L49–119**: `TestPolicyMemoKeysEveryInput` — fast in-memory check that `admissionPolicyMemo` discriminates every input axis (`deg`, `version`, `goos`, `Packages`, `inventory`, `verified`).
- **Lines L121–164**: `TestPolicyMemoGeneratedHistories` — fast randomized 64-step history test comparing `admissionPolicyFor` against `originalPolicyIdentity`.
- **Lines L167–177**: `BenchmarkAdmissionPolicy` — fast benchmark of `admissionPolicyFor`.

### 2.26 `closure/propertyharness_test.go` (413 lines)
- **Lines L14–26**: `TestAuditedPropertyHarnessVersion` — fast check that `auditedPropertyHarnessVersion` equals `"v1.2.0"` and matches the repository's `go.mod` `pgregory.net/rapid` version.
- **Lines L36–412**: `TestPropertyHarnessAudit`
  - **Witnesses**: `REQ-closure-observability-property-harness` across a synthetic `pgregory.net/rapid` module + 10 subjects (`TestPropertyPure`, `TestPropertyCustomDraw`, `TestPropertyCleanup`, `TestPropertyMakeNow`, `TestPropertyMakeSeed`, `TestPropertyLog`, `TestPropertyTB`, `TestPropertyReadEnv`, `TestPropertyOpenCallback`, `TestPropertyCustomSeed`), plus cold/warm observability memo checks, `TestBinaryKey` checks, `ImmutableEnvironmentOutcomes` checks (`rapid-draw`), non-audited version degradation (`v1.2.1` via `go.work`), and surface verification failures (`surface_test.go` touching `os.Getenv("HOME")` and `rapid.go` dropping `export TB`).
  - **Harness / Cost**: Spawns 4 full `newAt` + `ComputeObservabilityBatch` / `ImmutableEnvironmentOutcomes` passes over a multi-module workspace.

### 2.27 `closure/refusalchannels_test.go` (128 lines)
- **Lines L17–49**: `TestAmbientEffectReasonsNameTheirDischargeChannel` — fast unit test verifying `effectBlockReason` maps `os-env`, `ambient-clock`, `process-random`, `filesystem`, `testing.T.Setenv`, `testing.B.Elapsed`, `rapid-draw`, and `os-args` to their human-readable refusal reasons (`REQ-closure-refusal-channels`).
- **Lines L56–127**: `TestObservabilityRefusalAttributesTheUnauditedSelection` — cold + warm memo test verifying that an unaudited tag (`-tags=closure_unaudited_fixture`) is attributed in the refusal reason for standard-library callers while package-level state mutations keep their native refusal reason.

### 2.28 `closure/scope_test.go` (76 lines)
- **Lines L9–48**: `TestAnalysisScopeRendersEachMemosAxes` — fast unit test of `testingScanScope`, `effectScanScope`, and `observabilityScope` string formatting and sensitivity to `toolchainDigest`, `SelectionAudited`, `SelectionDegradation`, `AdmissionPolicyIdentity`, `BuildContextHash`, `ExplicitBuildFlags`, and `AnalyzingFrontend()`.
- **Lines L50–75**: `TestAnalysisScopeRendersRootedMemoAxes` — fast unit test of `rootedScope` and `binaryRootedScope`.

### 2.29 `closure/ssahandles_test.go` (92 lines)
- **Lines L15–64**: `TestSSAHandlesDoNotInventSourceUnsafePointers` — witnesses `REQ-closure-observability-unsafe` over 4 subpackages (`iter`, `defer`, `realunsafe`, `typeassert`), verifying that Go's synthetic SSA `ssa$opaque` handles for range-over-func and defers do not trigger false-positive `unsafe.Pointer` refusals.
- **Lines L66–91**: `TestSSAHandleRecognitionKeepsSourceAndUnknownTypes` — fast `go/types` unit test of `ssaOpaqueHandle`.

### 2.30 `closure/syncmemo_test.go` (61 lines)
- **Lines L14–60**: `TestSyncMapMemoOperationsAreAuditedAndRangeIsNot` — witnesses `REQ-closure-shared-dynamic-state-memo` across 5 subpackages (`loadorstore`, `load`, `store`, `swap`, `rangecall`), verifying `sync.Map.{LoadOrStore,Load,Store,Swap}` on a private global are admitted while `Range` is refused.

### 2.31 `closure/testingmemo_test.go` (274 lines)
- **Lines L10–38**: Helpers `testingScanModule` and `countTestingScanLoads`.
- **Lines L45–181**: `TestTestingScanMemoServesWithoutTypeLoad` — witnesses `REQ-closure-testing-scan-memo` across `clean`, `alias`, `cross`, `notest`, and `unreferenced` packages (cold type-load count vs warm 0-type-load hit, plus corrupt cache record recovery).
- **Lines L188–273**: `TestTestingScanMemoMissesOnScopeAndSourceChange` — tests invalidation on test-file edit, imported alias package edit, build-tag change, and `GOOS=plan9`.

### 2.32 `closure/testvariant_binding_test.go` (106 lines)
- **Lines L14–74**: `TestTestVariantInertnessRejectsRebinding`
  - **Witnesses**: `REQ-closure-test-variant-inertness` across 5 subtests (`constant shadow`, `function shadow`, `type shadow`, `import swap`, `dot import swap`).
  - **Defect / Cost**: For each of the 5 subtests, it runs `go test` via `Runner.Run` before the edit, `computeAt` + `ledgerAt`, edits the file, runs `go test` via `Runner.Run` again, and runs `computeAt` + `ledgerAt` again (**10 `go test` subprocesses + 10 `newAt` loads**!). Meanwhile, `closure/internal/compartment/bindings_test.go` (`TestInertnessPreservesExistingBindings`) already tests the exact same 5 cases (plus 6 more) in `< 1 ms` via `parseLedger`!
- **Lines L76–105**: `TestTestVariantBindingGuardAllowsUnrelatedGrowth` — verifies adding a sibling test, helper, constant, type, and new package import in `p_test.go` stays `Inert() == true`.

### 2.33 `closure/testvariant_test.go` (608 lines)
- **Lines L13–76**: Helpers `writeTestVariantModule`, `computeAt`, `computeUnder`, `hasherUnder`, `ledgerAt`, `ledgerUnder`.
- **Lines L83–110**: `TestSiblingTestAdditionMovesCompartmentNotCore` — witnesses `REQ-closure-test-variant` (adding a sibling test moves `TestVariantHash` while preserving `Hash`).
- **Lines L114–136**: `TestProductionEditMovesCoreNotCompartment` — witnesses `REQ-closure-test-variant` (editing `p.go` moves `Hash` while preserving `TestVariantHash`).
- **Lines L143–179**: `TestNewTestOnlyDependencyMovesCore` — witnesses `REQ-closure-test-variant` (importing a new dependency in `p_test.go` widens the test binary's package graph and therefore moves `Hash`).
- **Lines L183–207**: `TestNoTestPackageCompartmentIsStableEmptyIdentity` — witnesses `REQ-closure-test-variant` (`EmptyTestVariantHash` for packages without `_test.go` files).
- **Lines L212–240**: `TestExternalTestPackageFilesEnterCompartmentAndLedger` — verifies `package p_test` files enter `TestVariantHash` and `ComputeTestVariantLedger`.
- **Lines L246–302**: `TestLedgerNamesTheEditedAndAppendedDeclarations` — tests `DiffTestVariantLedgers` over disk edits (duplicates `compartment_test.go`).
- **Lines L308–349**: `TestTestVariantLedgerIsDeterministicallySorted` — tests deterministic sorting of `Declarations` and `FileHeaders` (duplicates `compartment_test.go` and `testvariant/testvariant_test.go`).
- **Lines L354–405**: `TestComputeMaximalBatchMatchesIndependentComputeForBothHashes` — verifies batch vs solo equality of `Hash`, `TestVariantHash`, and `ComputeTestVariantLedgerBatch`.
- **Lines L414–444**: `TestDependencyPackageNamedLikeExternalTestKeepsItsCoreContribution` — verifies an ordinary dependency whose package declaration is `package helper_test` remains in the core `Hash` rather than being misclassified as an external test compartment.
- **Lines L450–487**: `TestWidenedCoreKeepsTestFilesUndiscriminated` — copies `closure/fixtures/opaqueasm` to verify widened assembly packages still separate `Hash` and `TestVariantHash`.
- **Lines L494–537**: `TestEmbeddedGoFixtureIsDataNotSource` — verifies an embedded `testdata/sample_test.go` via `//go:embed` moves `TestVariantHash` and marks `FileHeaders[].Embedded = true`.
- **Lines L544–576**: `TestCompiledAndEmbeddedTestFileFailsClosed` — verifies `//go:embed self_test.go` sets `Embedded = true` on the compiled file header and fails closed (`Inert() == false`).
- **Lines L581–607**: `TestLedgerDeltaOverRealLedgers` — tests `DiffTestVariantLedgers` across 5 disk mutations (duplicates `compartment_test.go:L83-285`).

### 2.34 `closure/tier2driver_test.go` (70 lines)
- **Lines L24–69**: Test helpers `computeTier2ResultAndReach` and `computeTier2Result` used by `closure_test.go`, `batch_test.go`, and `audited_test.go`.

### 2.35 `closure/toolchain_dependencies_linux_test.go` (235 lines)
- **Lines L15–27**: `isolatedToolchainSource(t)` — runs `cp -a --reflink=auto` of the entire `runtime.GOROOT()` tree into `t.TempDir()`.
  - **Defect / Cost**: Copying the entire Go toolchain (`~12,000+ files`) multiple times per test run is extremely heavy I/O when `testenv.OverlayGOROOTEnv` (used in `toolchainsource_dst_test.go`) or a minimal synthetic `GOROOT` with a `gotool.Runner` listing shim (used in `toolchainsource_test.go:L1481`) can isolate mutations to the single package under test!
- **Lines L29–98**: `TestToolchainListingTracksFIPSAliasSelection` + `testFIPSAliasSelection` — witnesses `REQ-fresh-toolchain-dependencies` under `GOFIPS140=off` and `GOFIPS140=v1.0.0` when `crypto/sha256` adds a file.
- **Lines L100–132**: `TestSubjectListingRefusesUninventoriedStandardPackage` — verifies that planting a brand-new standard library package `newstd` after the toolchain surface memo was populated causes `NewAt` to refuse with an uninventoried standard package error.
- **Lines L134–157**: `TestToolchainAdmissionNeedsEveryAuditedRoot` — verifies `toolchainSourceDegradation` refuses when an audited root is missing from `sourceDigests`.
- **Lines L159–234**: `TestToolchainListingDoesNotCacheSymlinkSelectionInputs` — verifies that when a standard package directory or file is a symlink, retargeting the symlink invalidates the listing memo.

### 2.36 `closure/toolchainexperiment_test.go` (45 lines)
- **Lines L13–44**: `TestAuditedExperimentRejectsUnverifiedSourceChanges` — verifies that under an audited `GOEXPERIMENT=simd`, modifying `internal/cpu` in an overlay `GOROOT` causes `toolchainSelectionNotice` to refuse with `"verified standard-library surface moved"`.

### 2.37 `closure/toolchainselection_test.go` (374 lines)
- **Lines L20–108**: `TestSelectionsAdmitByContent` — verifies content-addressed toolchain admission across native selection, `-tags=netgo`, `GOOS=plan9`, `GOEXPERIMENT=jsonv2`, `GOEXPERIMENT=runtimesecret`, and refusal under `unauditedTagGOROOT` and `GOEXPERIMENT=fieldtrack`.
- **Lines L114–176**: `TestToolchainSourceDegradationNamesEveryAxis` — fast in-memory test of `toolchainSourceDegradation` over synthetic `sourceDigests` (empty packages, unverified surface movement, missing `testing`/`os`/`time` roots).
- **Lines L181–210**: `TestEffectScanScopeDiscriminatesContentAndPolicy` — fast unit test of `effectScanScope` over `Hasher` structs.
- **Lines L215–228**: `TestUnauditedSelectionDisablesAdmissions` — fast unit test of `h.admittedStandardGlobal` and `h.admittedByPolicy`.
- **Lines L236–277**: `TestUnlistedSurfaceRefusesObservability` — verifies that a `Hasher` with an empty `toolchainDigest` refuses observability and skips memo persistence.
- **Lines L285–320**: `TestToolchainSelectionNoticeResolvedContextReadsTheEnvironment` — tests `ToolchainSelectionNoticeResolvedContext` under audited, `GOFLAGS=-tags=closure_unaudited_fixture`, and `GOOS=plan9` environments.
- **Lines L325–341**: `TestZeroHasherRefusesSelectionAudit` — fast unit test on `&Hasher{}`.
- **Lines L346–373**: Helpers `requireBareAxis` and `environmentWith`.

### 2.38 `closure/toolchainsource_cancel_test.go` (145 lines)
- **Lines L23–58**: `TestDigestTraversalEndsAtTheNextFileBoundary` — verifies `digestFilesWith` stops immediately at the next file boundary when its context is cancelled mid-file.
- **Lines L68–105**: `TestPackageFileWalkEndsAtTheNextEntry` — verifies `walkPackageTreeWith` stops at the next directory entry on context cancellation.
- **Lines L107–144**: `TestFinalDigestReadCannotCompleteACancelledConstruction` — verifies `toolchainSourceDigestsWith` returns the cancellation error and does not populate the memo when cancelled during the final file read.

### 2.39 `closure/toolchainsource_dst_test.go` (604 lines)
- **Lines L23–525**: `TestDstSelectionIsJudgedByContentNeverByTag`
  - **Witnesses**: `REQ-fresh-toolchain-dependencies` (content-based AST/preprocessor verification of `image/color`, `runtime`, `os`, and `testing` under `OverlayGOROOTEnv`, plus end-to-end observability proof preservation across tag changes).
  - **Major Performance / Duplication Defect**: This single test calls `testenv.OverlayGOROOTEnv(t, ...)` + `newAtEnv(dir, env)` **25 separate times**! Each call overlays `GOROOT` and spawns `go list` over the standard library plus full AST/type verification of the toolchain surface. Yet 22 of those 25 calls only test single-package mutations to `image/color`, `runtime`, or `os` that `verifyListedPackage` / `verifyOffSurfacePackageWithIO` can verify directly on a 5-line synthetic `listedPackage` in `< 1 ms` (exactly as `TestVerifyToolchainSurfaceEnforcesStructuralContracts` in `toolchainsource_test.go` already does!).
- **Lines L527–539**: `TestHarnessPremisePackagesAreSurfaceSeedsAndVerified` — fast check that `testing/internal/testdeps` and `internal/testlog` are in `surfaceSeeds()` and `verifiedSurfacePackages`.
- **Lines L547–563**: `TestListingScopeFollowsTheSurfaceRule` — fast check that `toolchainSourceScope` changes when `seeds` change.
- **Lines L570–603**: `TestListingMemoRecordLandsUnderTheLiveSeedsScope` — verifies the persisted `toolchain-surface` cache file key matches `toolchainSourceScope(..., surfaceSeeds())`.

### 2.40 `closure/toolchainsource_test.go` (3,691 lines)
- **Lines L30–69**: `TestDigestFilesFollowsNamesAndBytes` — fast test of `digestFiles` sensitivity to filenames, byte contents, and missing files.
- **Lines L71–86**: `TestDigestFilesFramesBinaryContentsUnambiguously` — fast check that length-framing prevents boundary ambiguity across files containing `\x00` and `\n`.
- **Lines L90–100**: `TestSelectedFilesCoversEveryBuildClass` — fast unit test of `listPkg.selectedFiles()` deduplication and sorting across all 10 file slices.
- **Lines L109–152**: `TestAuditedSurfaceDerivesTheDelegates` — fast invariant check over `auditedStandardGlobals`, `auditedStandardFunctions`, `auditedPurePackages`, `auditedDelegatePackages`, and `verifiedSurfacePackages`.
- **Lines L159–232**: `TestToolchainSourceDigestsReadTheRunningToolchain` — verifies `toolchainSourceDigests` on the running toolchain covers all `surfaceSeeds()`, rejects missing `GOROOT`, and shifts digests under `GOOS=plan9`.
- **Lines L240–331**: `TestSurfaceListingServesOnlyOverItsStamps` — fast unit test of `surfaceListing.fresh()` across directory stamp edits, file stamp edits, unselected `.go` file edits, non-selected `.txt` edits, `IgnoredOtherFiles`, `EmbedFiles`, and empty directories.
- **Lines L337–386**: `TestListingErrorsRefuseByNameAndTheEmptySelectionDigests` — verifies `listToolchainSurface` refuses when a package has a `ListError` and succeeds when a seed selects zero files under build constraints.
- **Lines L391–1413**: `TestVerifyToolchainSurfaceEnforcesStructuralContracts` — comprehensive in-memory/tempdir unit test of `verifyListedPackage`, `verifyListedPurePackage`, and `toolchainSourceDegradation` across hundreds of synthetic mutations to `os`, `time`, `math/rand`, `math/rand/v2`, `testing`, `testing/internal/testdeps`, `internal/testlog`, pure packages, and assembly files (`< 100 ms` total because it calls `verifyListedPackage` directly!).
- **Lines L1415–1422**: `contains` helper.
- **Lines L1430–1472**: `TestToolchainSourceScopeDiscriminatesEveryAxis` — tests `toolchainSourceScope` across `GOFLAGS`, `GOEXPERIMENT`, `GOOS`, `GOARCH`, `CGO_ENABLED`, `GOFIPS140`, and explicit build flags.
- **Lines L1481–1567**: `TestToolchainSourceMemoRelistsAMovedTree` — shell-shim test of `toolchainSourceDigests` memo hit and relisting when an unselected or selected file moves.
- **Lines L1569–1620**: `TestToolchainSourceScopeIgnoresModulePathsAndServesDigestMemo` — verifies two distinct modules (`example.com/moda` and `example.com/modb`) share the same `toolchainSourceScope` and warm `toolchain-surface` memo.
- **Lines L1622–1811**: `FuzzClosureCoverageAndMutableLocalIdentity` — property test for `REQ-closure-coverage` and `REQ-closure-mutable-local-identity` across seeded `listPkg` graphs with `EmbedFiles`, widened assembly/cgo files, and external test files.
- **Lines L1813–2117**: `FuzzToolchainKeyObligations` — property test for `REQ-fresh-toolchain-dependencies` across 8 mutation families (`version`, `goos`, `seedDigest`, `delegateDigest`, `dropSeed`, `auditGate`, `rootPath`, `embedPayload`).
- **Lines L2119–2322**: `TestNonInternalDelegatesAdmittedOnlyThroughAuditedStdCallers` — tests that `nonInternalDelegatePackages` (`errors`, `io`, `io/fs`, `math`, `math/bits`, `sync`, `sync/atomic`, `unicode`, `unicode/utf8`) are admitted only when called from audited stdlib callers (`strings`, `os`, `testing`), while direct user calls to unaudited symbols in those packages are refused.
- **Lines L2324–2583**: `TestNonInternalDelegateCrossPackageAndSiblingIsolation` — tests `verifyOffSurfacePackageWithIO` over synthetic multi-package trees (`os`, `syscall`, `io/fs`, `errors`, `internal/poll`, `internal/oserror`, `time`, `runtime`, `sync`, `testing`, `testing/internal/testdeps`, `internal/testlog`, `math/rand`, `math/rand/v2`), plus TOCTOU digest drift refusal.
- **Lines L2585–3139**: `mustMutateFixture` + synthetic stdlib source builders (`validTestingPackageFiles`, `validTestdepsPackageFiles`, `validTestlogPackageFiles`, `validPurePackageFiles`, `validDelegatePackageFiles`).
- **Lines L3141–3275**: `TestTestingAndTestdepsVerifierPayloadCountAndBindingContracts` — tests `verifyListedPackage` on `testing` and `testing/internal/testdeps` across parameter shadowing, payload count mismatches, method expressions, and mutated `TestMain` / `StartTestLog` bodies.
- **Lines L3277–3367**: `TestPkgIncludeHeaderMutationInvalidatesWarmCacheAndRefusesAudit` — tests that `GOROOT/pkg/include/textflag.h` is stamped and verified so injecting `#define RET SYSCALL` into `textflag.h` invalidates the warm cache and refuses the assembly audit.
- **Lines L3369–3638**: `TestAssemblyVerifierPreprocessorAndContinuationRejections` — tests the assembly preprocessor/verifier across macro pasting (`##`), nested `#ifdef`/`#ifndef`/`#else`, backslash line continuations, block comments, string/char literals, `CALL` targets, and `.inc` headers.
- **Lines L3640–3679**: `TestToolchainSurfaceAdmitsCrossTargetSelections` — verifies `verifyToolchainSurface` succeeds on the real `GOROOT` across `linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64`, `plan9/amd64`, `js/wasm`, `wasip1/wasm`, and `freebsd/riscv64`.
- **Lines L3681–3686**: `fmtSprintErr` helper.

### 2.41 `closure/viewload_test.go` (131 lines)
- **Lines L15–68**: `TestViewLoadSubstitutesForTestingTypeScanLoad` — verifies `LoadViewPackages` pre-populates the testing type-scan memo (`testingScanTypeLoadCount == 0` on subsequent `ComputeMaximalBatch`) and preserves equivalence with a private `newAt` pass.
- **Lines L73–130**: `TestViewLoadMissFallsBackToPrivateTestingTypeLoad` — verifies that if a package with `_test.go` files was omitted from `LoadViewPackages`, `ComputeMaximalBatch` falls back to a private type-scan load for that package (`testingScanTypeLoadCount == 1`).

---

### 2.42 `closure/testvariant/testvariant_test.go` (214 lines)
- **Lines L12–35**: `TestLessDeclarationOrdersByFileKindReceiverName` — fast unit test of `LessDeclaration` ordering across `(File, Kind, Receiver, Name)`.
- **Lines L37–213**: `TestInertForSubjectCoversReachabilityAndGuardRails` — fast unit test of `InertForSubject` across reachable helper edits, unreachable sibling edits, missing `ReferencesComplete`, empty `subjectName`, duplicate same-kind keys, different-kind namespace separation (`type Helper` vs `func (Helper) Helper`), `init`/`var`/header changes, blank `_` constant group governors, cyclic mutual recursion, and `Clone()` isolation.
  - **Overlap**: 90% overlap with `TestInertForSubjectAttributesReachableReferences` in `closure/internal/compartment/compartment_test.go:L546-759`!

### 2.43 `closure/internal/cachefile/cachefile_test.go` (222 lines)
- **Lines L15–34**: `TestUnwritableStoreIsSilent` — verifies `Store` and `Load` silently no-op when the parent cache directory is read-only (`0o500`).
- **Lines L38–53**: `TestRedirectedStoreRoundTrips` — verifies `Store` + `Load` round-trip and defensive copy of returned bytes.
- **Lines L55–86**: `TestRetentionBoundUnderChurn` — verifies `Store` bounds the class directory to `<= maxEntries` (`maxEntries +pruneStride - 1`) under 200 writes.
- **Lines L88–119**: `TestPrunePreservesTempWritesAndReclaimsObsoleteClasses` — verifies `Prune` removes obsolete class directories and excess files while preserving in-flight `.tmp-*` files.
- **Lines L121–151**: `TestPreviewPruneMatchesPruneWithoutMutatingStore` — verifies `PreviewPrune` reports identical `Removed` and `FreedBytes` counts without mutating disk.
- **Lines L153–185**: `TestPruneCountsSkippedEntriesAndContinues` — verifies `Prune` and `PreviewPrune` count unreadable (`0o000`) directories in `Skipped` and continue pruning readable classes.
- **Lines L187–221**: `TestConcurrentStoreLoadAndPrune` — 4-goroutine concurrent stress test of `Store`, `Load`, and `Prune`.
- **Assessment**: Exemplary Tier 1 unit test file—fast, self-contained, zero subprocesses, 100% focused on `cachefile` invariants.

### 2.44 `closure/internal/compartment/compartment_test.go` (761 lines)
- **Lines L14–25**: `parseLedger` helper.
- **Lines L31–53**: `TestConstInsertionInsideGroupReadsAsChanged` — verifies `iota` ordinal tracking inside `const (...)` blocks.
- **Lines L59–73**: `TestInitAndVarReordersReadAsChanged` — verifies positional ordinal tracking for `init#<file>#<ordinal>` and `var#<file>#<ordinal>`.
- **Lines L83–172**: `TestLedgerDeltaClassifiesInertness` — tests `DiffTestVariantLedgers` across 8 edits (sibling test append, existing body edit, helper edit, `var` append, `init()` append, import change, file directive comment, declaration deletion).
- **Lines L179–240**: `TestLedgerDeltaIsDeterministicAndClassifiesMembership` — tests `DiffTestVariantLedgers` sorting and `Inert()` across multi-file addition, removal, and header edits.
- **Lines L247–285**: `TestDirectiveCommentsDefeatInertness` — tests `//go:noinline`, `//line`, `/*line*/`, `//export` vs ordinary comments.
- **Lines L290–299**: `TestDocCommentRidesTheDeclarationHash` — verifies ordinary doc comments do not change declaration hashes while `//go:noinline` doc comments do.
- **Lines L306–360**: `TestDeclarationReferencesCollectIdentifiersAndSelectors` — tests `Declaration.References` and `ReferencesComplete` extraction across free identifiers, selectors, methods, and struct field keys.
- **Lines L367–407**: `TestImplicitConstRepetitionFoldsGoverningReferences` — verifies implicit `iota` constant specs inherit references from the governing explicit expression and preceding `iota` specs.
- **Lines L416–429**: `TestPackageClauseRenameSurfacesAsMembershipChange` — verifies renaming `package p` to `package p_test` changes `FileHeaders` and defeats `Inert()`.
- **Lines L434–444**: `TestClassificationIgnoresReferences` — verifies `EqualTestVariantDeclarations` and `DiffTestVariantLedgers` ignore manually mutated `References` slices when `Hash` is unchanged.
- **Lines L453–480**: `TestDeclarationReferencesAreAPureFunctionOfTheBytes` — verifies declaration order in source does not alter `References` or `Hash`.
- **Lines L484–495**: `TestCloneIsolatesReferences` — verifies `TestVariantLedger.Clone()` deep-copies `References`.
- **Lines L497–544**: Helpers `slicesContains` and `parseMultiFileLedger`.
- **Lines L546–759**: `TestInertForSubjectAttributesReachableReferences` — tests `testvariant.InertForSubject` over parsed single-file and multi-file ledgers (overlaps heavily with `closure/testvariant/testvariant_test.go:L37-213`).

### 2.45 `closure/internal/compartment/bindings_test.go` (153 lines)
*(Listed in prompt as `closure/internal/compartment/ledger_test.go`)*
- **Lines L12–50**: `TestInertnessPreservesExistingBindings` — fast table test of 11 universe-shadowing and import-rebinding cases (`constant shadow`, `function shadow`, `type shadow`, `iota shadow`, `unused universe shadow`, `ordinary growth`, `import swap`, `new code import`, `comment`, `dot import swap`, `unused blank import`).
- **Lines L52–80**: `TestBindingEvidenceFailsClosedAndClones` — verifies missing/unknown `BindingStrategy`, nil `Bindings`, blank import `Name`, `Embedded = true`, and zero `TestVariantDelta{}` all fail closed (`Inert() == false`), and `Clone()` deep-copies `FileHeaders` and `BaseFiles` bindings.
- **Lines L82–118**: `TestBindingLedgerRoundTrip` — verifies JSON round-trip of `TestVariantLedger` preserves `BaseFiles` binding evidence and rejects legacy JSON records lacking binding fields.
- **Lines L122–152**: `FuzzBindingGrowth` — fast in-memory property test varying shadowed universe names (`true`, `len`, `int`), package role (`p` vs `p_test`), reference presence, and `BaseFiles` vs `FileHeaders` placement.

### 2.46 `closure/internal/program/prepared_test.go` (461 lines)
*(Listed in prompt as `closure/internal/program/program_test.go`)*
- **Lines L25–55**: `preparationModule` helper writing a 9-package module (`a`, `r`, `plain`, `onlyext`, `onlytest`, `cmd`, `generic`, `bad`, `ownbad`).
- **Lines L57–120**: `programInventory` + `inventory(t, p *Program)` — extracts complete structural inventory of packages, typed imports, SSA packages, roots, `Ambiguous`, and `TestMain`.
- **Lines L122–219**: `TestPreparedProgramsMatchIndependentLoads` — verifies `Prepare(dir, env, nil, paths...).Build(path)` produces an identical `programInventory` to `Load(dir, env, nil, path)` across all 7 valid packages (including test-variant triangle recompilation `r [a.test]`, external-only tests, test-only packages, `package main` + `TestMain`, and Go 1.27 generic method instantiation), and rejects `bad`, `ownbad`, and unregistered paths.
- **Lines L221–259**: `typedInputSnapshot` + `typedSyntax` helper.
- **Lines L261–301**: `TestPreparedBuildsOwnSSAAndPreserveTypedInputs` — verifies repeated `p.Build` calls share `*types.Func` objects without sharing `*ssa.Program` or `PkgScopeProbe` state, do not mutate AST/TypesInfo inputs, and honor context cancellation.
- **Lines L303–377**: `mutateContext` + `TestPreparedCapturesContainersAndNewGenerations` — verifies `Prepare` defensively copies `paths`, `flags`, and `env` before caller mutation during context checks, sees source edits on subsequent `Prepare` calls, and rejects empty or `"."` paths.
- **Lines L379–460**: `TestPreparedGeneratedMainRequiresTargetVariants` — verifies an ordinary command package `q.test` (`package main` in directory `q.test/`) is never conflated with the synthesized test main of package `q` across `valid-command`, `invalid-command`, and `colliding-test-main` modes in both request orders.

### 2.47 `closure/internal/rta/rta_test.go` (172 lines)
- **Lines L16–112**: `TestContainsTypeParamAndStaggeredMasks` — builds SSA in memory via `ssautil.BuildPackage` (`< 1 ms`) and verifies `containsTypeParam` over cyclic generic types, staggered parameter pointer/slice masks (`func(a *int, b int, c []byte)`), variadic slice parameter attribution (`func(a int, rest ...*int)`), and method receiver mask alignment (`(box).write` vs `(*box).mutate`).
- **Lines L114–171**: `TestSkippedUnderlyingDoesNotSynthesizePhantomUnnamedWrapper` — builds SSA in memory via `ssautil.BuildPackage` and verifies that converting an unnamed struct carrying a type parameter (`struct{ v T; box }`) to an interface skips `AddTypes` without synthesizing a phantom wrapper on concrete `box`.
- **Architectural Note**: This file is the gold standard for how SSA/RTA unit tests in `closure/` should be written: zero `go list` subprocesses, zero temp modules on disk, direct in-memory `parser.ParseFile` + `ssautil.BuildPackage` + `Analyze`.

---

## 3. Complete Audit & Mapping of `closure/fixtures/*`

### 3.1 Why `closure/fixtures/*` Pollutes Module Package Space

1. **No `testdata/` or `go.mod` Boundary**:
   - In Go, the `go` command ignores directories named `testdata` (or starting with `_` or `.`) during recursive package pattern matching (`./...`), and stops at nested `go.mod` files.
   - Because the directory is named `closure/fixtures/` and contains no `go.mod` of its own, every subdirectory containing `.go` files is a first-class importable package in the root module `github.com/greatliontech/gofresh`.
   - Consequently, `go list ./...`, `go test ./...`, `go vet ./...`, IDE language servers (`gopls`), and `gomutant` discover, typecheck, and compile **135 accidental packages** under `github.com/greatliontech/gofresh/closure/fixtures/...` (across 127 top-level directories, 222 files, and 4,102 lines).
2. **Orphaned & Cross-Package Fixture Leakage**:
   - `closure/fixtures/embedfixture` is **100% dead code**—referenced nowhere in the entire repository.
   - `closure/fixtures/externaldirective` (`gofresh_test.go:L811`) and `closure/fixtures/puredirective` (`purity_test.go:L26`) are not referenced anywhere in `closure/*_test.go`; they are only referenced by root-package tests.
   - `closure/fixtures/observable` and `closure/fixtures/external` are referenced not only by `closure/*_test.go` but also by `fingerprint_record_test.go`, `view.go`, `gofresh_test.go`, `applicability_test.go`, `runtime_motion_test.go`, and `runtimeinput/*_test.go`.
3. **Why Almost All Fixtures Can Be Inline/Synthetic Sources or `testdata/`**:
   - **108 of the 127 fixtures** are tiny single-package snippets (`9–58` lines of pure Go without assembly, cgo, or multi-package `//go:linkname`) that test Tier 1 effect classification, Tier 2 RTA reachability, or observability refusal/admission rules. In a layered test architecture:
     - Pure AST/type/SSA/RTA and observability flow rules should be table cases fed to an in-memory `ssautil.BuildPackage` harness or a single shared multi-package batch fixture generated in `t.TempDir()`, eliminating 100+ disk directories.
     - The remaining ~19 fixtures that genuinely exercise `go list` / `packages.Load` filesystem mechanics (e.g., `.s`/`.inc` assembly files, `//go:embed`, multi-package `//go:linkname`, external `_test` package root collisions, or runtime filesystem execution in `runtimeinput`) belong under `closure/testdata/` (or `testdata/` in the root package for `gofresh_test.go` / `runtimeinput` fixtures), immediately removing **all 135 accidental packages** from `go list ./...`.

### 3.2 Complete Inventory & Disposition of All 127 `closure/fixtures/*` Directories

Legend for **Disposition**:
- **`DELETE (orphan)`**: Unreferenced anywhere in the repository.
- **`MOVE -> root testdata/`**: Only referenced by root-package tests (`gofresh_test.go`, `purity_test.go`), not by `closure`.
- **`INLINE (Tier 2 table)`**: Pure single-package Go source testing RTA/observability/maximal rules; convert to an inline table case in the consolidated Tier 2 batch/in-memory harness.
- **`KEEP -> closure/testdata/`**: Exercises multi-package graph loading, `.s`/`.inc` assembly, `//go:linkname`, external `_test` package ambiguity, or is a shared canonical integration fixture across multiple packages.

| # | Fixture Directory | Files (Lines) | Symbols & What It Tests | Referencing Tests | Disposition |
| ---: | :--- | :--- | :--- | :--- | :--- |
| 1 | `ambiguousroot` | `ambiguousroot.go` (8L), `ambiguousroot_test.go` (9L), `external_test.go` (13L) | `Size`, `TestSize` in both `p` and `p_test`; tests ambiguous test root refusal | `closure_test.go:L3511` | `KEEP -> closure/testdata/` |
| 2 | `asmcall` | `asm_amd64.s` (5L), `asmcall.go` (10L), `asmcall_test.go` (9L) | `asmEntry`, `helper`, `BenchmarkASMCall`; tests bodyless assembly declaration widening | `closure_test.go:L2637` | `KEEP -> closure/testdata/` |
| 3 | `asminvoke` | `asm_amd64.s` (5L), `asminvoke.go` (21L), `asminvoke_test.go` (9L) | `M`, `asmEntry`, `BenchmarkASMInvoke`; tests interface invoke + assembly widening | `closure_test.go:L3085` | `KEEP -> closure/testdata/` |
| 4 | `batchisolation` | `batchisolation.go` (57L), `batchisolation_test.go` (32L) | 18 functions/tests testing batch vs solo RTA & observability isolation | `batch_test.go:L19` | `INLINE (Tier 2 table)` |
| 5 | `benchpacing` | `baseline.txt` (1L), `benchpacing_test.go` (35L) | `BenchmarkLoopOnly`, `BenchmarkLoopReadsFile`, `BenchmarkResultField`, `BenchmarkReporting` (`testing.B.Loop` / `b.N`) | `audited_test.go:L1726` | `INLINE (Tier 2 table)` |
| 6 | `constgroup` | `constgroup_test.go` (14L) | `BenchmarkConstGroup`; implicit `iota` constant group dependency tracking | `closure_test.go:L2613` | `INLINE (Tier 2 table)` |
| 7 | `copyfs` | `copyfs_test.go` (13L) | `BenchmarkCopyFS`; `os.CopyFS` filesystem mutation refusal | `closure_test.go:L1848` | `INLINE (Tier 2 table)` |
| 8 | `createtemp` | `createtemp_test.go` (15L) | `BenchmarkCreateTemp`; `os.CreateTemp` mutation refusal | `closure_test.go:L1849` | `INLINE (Tier 2 table)` |
| 9 | `depdispatch` | `depdispatch_test.go` (76L) | `RunLocalDispatch`, `RunEffectDispatch`, `RunSharedDispatch`, `RunNilDispatch`; local vs open interface dispatch | `closure_test.go:L2117-2139` | `INLINE (Tier 2 table)` |
| 10 | `direct` | `direct_test.go` (30L) | `used`, `unused`, `BenchmarkDirect`; basic Tier 2 function reachability pruning | `closure_test.go:L1649`, `maximal_test.go:L706` | `KEEP -> closure/testdata/` |
| 11 | `dyncaller` | `dyncaller_test.go` (273L) | 35 funcs/tests covering computed calls, function values, method values, generics, and goroutines | `closure_test.go:L2104-2140`, `fixturepreparation_test.go:L136` | `INLINE (Tier 2 table)` |
| 12 | `dyninit` | `dyninit_test.go` (24L) | `RunInit`, `TestRunInit`; package `init` function value assignment | `closure_test.go:L2147` | `INLINE (Tier 2 table)` |
| 13 | `dyninitbound` | `dyninitbound_test.go` (58L) | `Run`, `EncLen`, `init`, `TestRun`; `init`-bound function table dispatch | `closure_test.go:L2132` | `INLINE (Tier 2 table)` |
| 14 | `dyninitcollide` | `dyninitcollide_test.go` (36L) | `Run`, `TestRun`; colliding `init` stores to package function variable | `closure_test.go:L2125` | `INLINE (Tier 2 table)` |
| 15 | `dyninitstdframe` | `dyninitstdframe_test.go` (36L) | `RunSort`, `driveSort`, `TestNothing`; `sort.Slice` stdlib frame callback attribution | `closure_test.go:L2138` | `INLINE (Tier 2 table)` |
| 16 | `embedfixture` | `data.txt` (1L), `embed_test.go` (15L) | `BenchmarkEmbed`; **completely unreferenced anywhere in repo** | *None* | `DELETE (orphan)` |
| 17 | `external` | `external_test.go` (16L) | `BenchmarkReadFile`, `TestReadFile`; canonical `os.ReadFile` fixture | `closure_test.go`, `gofresh_test.go`, `runtimeinput/*_test.go` | `KEEP -> closure/testdata/` |
| 18 | `externalbench` | `externalbench.go` (1L), `externalbench_test.go` (8L) | `BenchmarkExternal` in `package externalbench_test` | `closure_test.go:L1690` | `KEEP -> closure/testdata/` |
| 19 | `externaldirective` | `externaldirective.go` (19L) | `//gofresh:external` directive cases; only used by root `gofresh_test.go` | `gofresh_test.go:L811` | `MOVE -> root testdata/` |
| 20 | `filemutations` | `filemutations_test.go` (30L) | `BenchmarkCreate`, `BenchmarkOpenFileCreate`, `BenchmarkWriteFile` | `closure_test.go:L1850-1852` | `INLINE (Tier 2 table)` |
| 21 | `flaglookupsubject` | `flaglookupsubject.go` (3L), `flaglookupsubject_test.go` (15L) | `Prod`, `TestProd`; subject-time `flag.Lookup` refusal | `closure_test.go:L2208` | `INLINE (Tier 2 table)` |
| 22 | `flagparsemain` | `flagparsemain.go` (3L), `flagparsemain_test.go` (22L) | `TestMain` calling `flag.Parse()` | `closure_test.go:L2207` | `INLINE (Tier 2 table)` |
| 23 | `flagregalias` | `flagregalias.go` (19L), `flagregalias_test.go` (9L) | Pointer alias to flag-registered global variable | `closure_test.go:L2245` | `INLINE (Tier 2 table)` |
| 24 | `flagregcallback` | `flagregcallback.go` (12L), `flagregcallback_test.go` (9L) | `flag.Func` callback registration in `init()` | `closure_test.go:L2225` | `INLINE (Tier 2 table)` |
| 25 | `flagregdep` | `flagregdep.go` (10L), `flagregdep_test.go` (9L) | Imports `flagregescape` to test cross-package untraceable flag sink propagation | `closure_test.go:L2248` | `INLINE (Tier 2 table)` |
| 26 | `flagregescape` | `flagregescape.go` (16L), `flagregescape_test.go` (9L) | Helper-escaped `flag.StringVar` pointer target | `closure_test.go:L2221/L2248/L2338` | `INLINE (Tier 2 table)` |
| 27 | `flagreginit` | `flagreginit.go` (11L), `flagreginit_test.go` (9L) | `flag.BoolVar` in `init()` unread by `Prod` | `closure_test.go:L2199` | `INLINE (Tier 2 table)` |
| 28 | `flagreginvoke` | `flagreginvoke.go` (3L), `flagreginvoke_test.go` (32L) | `flag.Var` custom `flag.Value` registration in `TestMain` | `closure_test.go:L2233` | `INLINE (Tier 2 table)` |
| 29 | `flagreginvokeinit` | `flagreginvokeinit.go` (20L), `flagreginvokeinit_test.go` (9L) | `flag.Var` custom `flag.Value` registration in `init()` | `closure_test.go:L2234` | `INLINE (Tier 2 table)` |
| 30 | `flagreglocalmain` | `flagreglocalmain.go` (3L), `flagreglocalmain_test.go` (26L) | `flag.BoolVar` on local variable in `TestMain` | `closure_test.go:L2222` | `INLINE (Tier 2 table)` |
| 31 | `flagregmain` | `flagregmain.go` (3L), `flagregmain_test.go` (29L) | `flag.BoolVar` on package variable in `TestMain` | `closure_test.go:L2200` | `INLINE (Tier 2 table)` |
| 32 | `flagregmainread` | `flagregmainread.go` (11L), `flagregmainread_test.go` (20L) | `TestMain` reading flag-registered variable | `closure_test.go:L2228` | `INLINE (Tier 2 table)` |
| 33 | `flagregmethod` | `flagregmethod.go` (21L), `flagregmethod_test.go` (9L) | `flag.TextVar` custom `encoding.TextUnmarshaler` in `init()` | `closure_test.go:L2241/L2320` | `INLINE (Tier 2 table)` |
| 34 | `flagregstruct` | `flagregstruct.go` (36L), `flagregstruct_test.go` (21L) | `flag.IntVar(&cfg.port, ...)` struct field registration | `closure_test.go:L2212-2217/L2329` | `INLINE (Tier 2 table)` |
| 35 | `flagregsubject` | `flagregsubject.go` (15L), `flagregsubject_test.go` (9L) | Subject calling `flag.BoolVar` directly | `closure_test.go:L2203` | `INLINE (Tier 2 table)` |
| 36 | `fmtsink` | `fmtsink_test.go` (107L) | 14 functions/tests for `fmt.Fprintf` into local `bytes.Buffer` / `strings.Builder` vs escaping writers | `closure_test.go:L2074-2086` | `INLINE (Tier 2 table)` |
| 37 | `fmtsinkstdout` | `fmtsinkstdout_test.go` (11L) | `TestFprintfStdout`; `fmt.Fprintf(os.Stdout, ...)` refusal | `closure_test.go:L2091` | `INLINE (Tier 2 table)` |
| 38 | `fmtsinkvalue` | `fmtsinkvalue_test.go` (20L) | `TestValueFormatBuffer`; custom `fmt.Stringer` formatting into local buffer | `closure_test.go:L2087` | `INLINE (Tier 2 table)` |
| 39 | `fuzzsibling` | `fuzzsibling_test.go` (16L) | `FuzzDecode`, `TestSiblingRead`; `testing.F` sibling isolation | `closure_test.go:L2170/L2171` | `INLINE (Tier 2 table)` |
| 40 | `genericescape` | `genericescape.go` (17L), `genericescape_test.go` (9L) | `Secret`, `leak`, `BenchmarkGenericEscape`; generic function body reachability | `closure_test.go:L2588` | `INLINE (Tier 2 table)` |
| 41 | `genericmethod` | `genericmethod.go` (15L) | `Box[T].Get`, `Box[T].Set`; generic receiver method subjects | `closure_test.go:L1535` | `INLINE (Tier 2 table)` |
| 42 | `genericpostrta` | `asm_amd64.s` (5L), `genericpostrta.go` (23L), `genericpostrta_test.go` (10L) | Generic function + assembly post-RTA fallback | `closure_test.go:L3103` | `KEEP -> closure/testdata/` |
| 43 | `globalcallback` | `globalcallback.go` (13L) | `local`, `alternate`, `Set`, `F`; global function variable mutation | `batch_test.go:L142` | `INLINE (Tier 2 table)` |
| 44 | `harnessarg` | `baseline.txt` (1L), `harnessarg_test.go` (21L) | `TestLogEffectfulArgument`; `t.Log(effectfulStringer{})` | `closure_test.go:L1949` | `INLINE (Tier 2 table)` |
| 45 | `harnessclock` | `harnessclock_test.go` (14L) | `TestLogAmbientClock`; `t.Log(time.Now())` | `audited_test.go:L1082/L1083` | `INLINE (Tier 2 table)` |
| 46 | `harnesserrshared` | `baseline.txt` (1L), `harnesserrshared_test.go` (30L) | `TestPlant`, `TestUseErrBound`; shared `error` interface dispatch | `closure_test.go:L2066` | `INLINE (Tier 2 table)` |
| 47 | `harnessexitoutside` | `harnessexitoutside.go` (3L), `harnessexitoutside_test.go` (23L) | `hardStop` calling `os.Exit` outside `TestMain` | `closure_test.go:L2190` | `INLINE (Tier 2 table)` |
| 48 | `harnesslog` | `baseline.txt` (1L), `harnesslog_test.go` (86L) | 6 tests exercising `t.Fatal`, `t.Log`, `t.Error`, `t.Skip`, `testing.TB` | `audited_test.go:L1044`, `closure_test.go:L1943-1948` | `INLINE (Tier 2 table)` |
| 49 | `harnessmain` | `baseline.txt` (1L), `harnessmain_test.go` (33L) | `TestMain` calling `m.Run()` with custom `TB` implementation | `closure_test.go:L2054/L2450` | `INLINE (Tier 2 table)` |
| 50 | `harnessmainbound` | `baseline.txt` (1L), `harnessmainbound_test.go` (34L) | `TestMain` bound method `m.Run` call | `closure_test.go:L2057` | `INLINE (Tier 2 table)` |
| 51 | `harnessmainfmt` | `harnessmainfmt.go` (3L), `harnessmainfmt_test.go` (24L) | `TestMain` calling `fmt.Println` | `closure_test.go:L2194` | `INLINE (Tier 2 table)` |
| 52 | `harnessmainfunc` | `harnessmainfunc_test.go` (33L), `baseline.txt` (1L) | `TestMain` function value `m.Run` | `closure_test.go:L2056` | `INLINE (Tier 2 table)` |
| 53 | `harnessmainlaunder` | `baseline.txt` (1L), `harnessmainlaunder_test.go` (34L) | `TestMain` laundering `*testing.M` through helper | `closure_test.go:L2065` | `INLINE (Tier 2 table)` |
| 54 | `harnessmainlocal` | `baseline.txt` (1L), `harnessmainlocal_test.go` (28L) | `TestMain` local helper call | `closure_test.go:L2055` | `INLINE (Tier 2 table)` |
| 55 | `harnessmainphi` | `baseline.txt` (1L), `harnessmainphi_test.go` (36L) | `TestMain` phi node over `*testing.M` | `closure_test.go:L2067` | `INLINE (Tier 2 table)` |
| 56 | `harnessmainthunk` | `baseline.txt` (1L), `harnessmainthunk_test.go` (33L) | `TestMain` closure thunk calling `m.Run()` | `closure_test.go:L2058` | `INLINE (Tier 2 table)` |
| 57 | `harnessmainwrite` | `harnessmainwrite.go` (3L), `harnessmainwrite_test.go` (21L) | `TestMain` mutating package global before `m.Run()` | `closure_test.go:L2187`, `fixturepreparation_test.go:L135` | `INLINE (Tier 2 table)` |
| 58 | `harnessobserved` | `harnessobserved.go` (3L), `harnessobserved_test.go` (29L) | `TestMain` observed `os.Exit(m.Run())` | `closure_test.go:L2184` | `INLINE (Tier 2 table)` |
| 59 | `harnessroot` | `harnessroot.go` (5L), `harnessroot_test.go` (27L) | `TestMain` + `setup` + `BenchmarkProd` | `closure_test.go:L1570/L2253`, `gofresh_test.go:L525` | `KEEP -> closure/testdata/` |
| 60 | `harnesssetenv` | `baseline.txt` (1L), `harnesssetenv_test.go` (26L) | `TestSetenvStaysBlocked`, `TestCleanRead` | `closure_test.go:L1950/L1966` | `INLINE (Tier 2 table)` |
| 61 | `harnessshared` | `baseline.txt` (1L), `harnessshared_test.go` (34L) | Shared `testing.TB` helper across tests | `closure_test.go:L1965` | `INLINE (Tier 2 table)` |
| 62 | `harnessshareddispatch` | `baseline.txt` (1L), `harnessshareddispatch_test.go` (101L) | 7 tests for `testing.TB` bound/thunk/phi/laundered dispatch | `closure_test.go:L2059-2064` | `INLINE (Tier 2 table)` |
| 63 | `harnesstb` | `baseline.txt` (1L), `harnesstb_test.go` (56L) | `TestHelperTBFatal`, `TestHelperTBTwice`, `TestHelperTBRecursive` | `closure_test.go:L1951-1955` | `INLINE (Tier 2 table)` |
| 64 | `harnesstbenv` | `baseline.txt` (1L), `harnesstbenv_test.go` (21L) | `TestHelperTBSetenv` via `testing.TB` helper | `closure_test.go:L1956` | `INLINE (Tier 2 table)` |
| 65 | `harnesswrap` | `baseline.txt` (1L), `harnesswrap_test.go` (32L) | Custom struct embedding `testing.TB` | `closure_test.go:L1964` | `INLINE (Tier 2 table)` |
| 66 | `importbinding` | `importbinding_test.go` (12L) | `BenchmarkImportBinding`; local variable shadowing package name | `closure_test.go:L3067` | `INLINE (Tier 2 table)` |
| 67 | `initcwd` | `initcwd_test.go` (17L), `data/fixture.txt` (1L) | `init()` calling `os.Chdir` | `closure_test.go:L1827` | `INLINE (Tier 2 table)` |
| 68 | `initdynamic` | `initdynamic_test.go` (29L), `pre.txt` (1L) | `init()` dynamic function call reading file | `closure_test.go:L1838` | `INLINE (Tier 2 table)` |
| 69 | `initfile` | `fixture.txt` (1L), `initfile_test.go` (22L) | `init()` reading `fixture.txt` | `closure_test.go:L1826/L2179/L2448`, `fixturepreparation_test.go:L134` | `KEEP -> closure/testdata/` |
| 70 | `initfmthelper` | `initfmthelper_test.go` (30L) | `init()` formatting through helper | `closure_test.go:L2155` | `INLINE (Tier 2 table)` |
| 71 | `initfmtsink` | `initfmtsink_test.go` (21L) | `init()` formatting into `bytes.Buffer` | `closure_test.go:L2153` | `INLINE (Tier 2 table)` |
| 72 | `initfmtvalue` | `initfmtvalue_test.go` (26L) | `init()` formatting custom `Stringer` value | `closure_test.go:L2154` | `INLINE (Tier 2 table)` |
| 73 | `initglobaldispatch` | `baseline.txt` (1L), `initglobaldispatch_test.go` (27L) | `init()` interface dispatch on global | `closure_test.go:L2068` | `INLINE (Tier 2 table)` |
| 74 | `initregistry` | `bench/bench_test.go` (17L), `codec/codec.go` (15L), `registry/registry.go` (15L) | 3-package blank-import `_ ".../codec"` init registration pattern | `closure_test.go:L1605/L1606` | `KEEP -> closure/testdata/` |
| 75 | `initstdcallback` | `initstdcallback_test.go` (23L), `pre.txt` (1L) | `init()` passing callback to `strings.Map` | `closure_test.go:L1839` | `INLINE (Tier 2 table)` |
| 76 | `initstdhelper` | `initstdhelper_test.go` (18L), `fixtures/a.txt` (1L) | `init()` calling `filepath.Glob` | `closure_test.go:L1829` | `INLINE (Tier 2 table)` |
| 77 | `linknamelocal` | `bench/bench_test.go` (17L), `target/target.go` (7L) | 2-package `//go:linkname` across sibling packages | `closure_test.go:L3259` | `KEEP -> closure/testdata/` |
| 78 | `methodsubject` | `methodsubject.go` (15L) | `Counter.Value`, `(*Counter).Ptr` method subjects | `closure_test.go:L1496`, `gofresh_test.go:L345` | `KEEP -> closure/testdata/` |
| 79 | `mixedexternal` | `fixture.txt` (1L), `mixedexternal_test.go` (17L) | `BenchmarkMixedExternal` | `closure_test.go:L1854/L1900/L2254` | `INLINE (Tier 2 table)` |
| 80 | `mkdir` | `mkdir_test.go` (12L) | `BenchmarkMkdir`; `os.Mkdir` refusal | `closure_test.go:L1845` | `INLINE (Tier 2 table)` |
| 81 | `mkdirtemp` | `mkdirtemp_test.go` (12L) | `BenchmarkMkdirTemp`; `os.MkdirTemp` refusal | `closure_test.go:L1844` | `INLINE (Tier 2 table)` |
| 82 | `observable` | `observable_test.go` (36L) | `TestReadFile`, `TestGetenv`, `TestLookupEnv`, `TestOpen`, `TestReadDir` | `closure_test.go`, `audited_test.go`, `fingerprint_record_test.go` | `KEEP -> closure/testdata/` |
| 83 | `observablebad` | `observablebad_test.go` (26L) | `TestOpenStat`, `ReadUnattributed`, `TestReadDirInfo` | `closure_test.go:L2156/L2435`, `observabilitybench_test.go:L16` | `KEEP -> closure/testdata/` |
| 84 | `observablecallbackbad` | `observablecallbackbad_test.go` (28L) | `TestSubtestRead`, `TestNestedSubtestRead`, `TestConstructedMRun` | `closure_test.go:L2158/L2398/L2437` | `INLINE (Tier 2 table)` |
| 85 | `observableconcurrent` | `observableconcurrent_test.go` (15L) | `TestConcurrentFileRead` spawning goroutine | `closure_test.go:L1999/L2438/L3477` | `INLINE (Tier 2 table)` |
| 86 | `observablefresh` | `observablefresh_test.go` (324L) | 38 funcs/tests covering `t.TempDir()` fresh-path provenance rules | `closure_test.go:L1967/L2000`, `observabilitybench_test.go:L17` | `KEEP -> closure/testdata/` |
| 87 | `observablefreshinit` | `observablefreshinit_test.go` (28L) | `TestFreshHelperShadowedByStartupCaller` | `closure_test.go:L2038` | `INLINE (Tier 2 table)` |
| 88 | `observablemutation` | `observablemutation_test.go` (10L) | `TestRemove` (`os.Remove`) | `closure_test.go:L1997/L2441`, `observabilitybench_test.go:L18` | `KEEP -> closure/testdata/` |
| 89 | `observableopenfile` | `observableopenfile_test.go` (10L) | `TestOpenFile` (`os.OpenFile` read-only) | `closure_test.go:L1942/L2442` | `INLINE (Tier 2 table)` |
| 90 | `observableprocess` | `observableprocess_test.go` (10L) | `TestCommand` (`exec.Command`) | `closure_test.go:L1998/L2443` | `INLINE (Tier 2 table)` |
| 91 | `observablestat` | `observablestat_test.go` (10L) | `TestStat` (`os.Stat`) | `closure_test.go:L1996/L2444`, `observabilityrelease_test.go:L17` | `INLINE (Tier 2 table)` |
| 92 | `opaqueasm` | `asm_amd64.s` (8L), `defs.inc` (1L), `opaqueasm.go` (3L), `opaqueasm_test.go` (9L) | Assembly `.s` + `.inc` widening | `maximal_test.go:L58`, `testvariant_test.go:L462` | `KEEP -> closure/testdata/` |
| 93 | `openfileread` | `fixture.txt` (1L), `openfileread_test.go` (15L) | `BenchmarkOpenFileRead` | `closure_test.go:L1836` | `INLINE (Tier 2 table)` |
| 94 | `openrootread` | `fixture.txt` (1L), `openrootread_test.go` (19L) | `BenchmarkRootOpenFileRead` (`os.OpenRoot`) | `closure_test.go:L1837` | `INLINE (Tier 2 table)` |
| 95 | `pathbinding` | `link` (1L), `pathbinding_test.go` (27L), `post.txt` (1L), `pre.txt` (1L) | `BenchmarkPathBinding`; symlink/path binding | `closure_test.go:L1842` | `INLINE (Tier 2 table)` |
| 96 | `puredirective` | `puredirective.go` (22L), `puredirective_x_test.go` (18L) | `//gofresh:pure` directive cases; only used by root `purity_test.go` | `purity_test.go:L26` | `MOVE -> root testdata/` |
| 97 | `reflectexternal` | `reflectexternal_test.go` (18L) | `BenchmarkReflectExternal`; `reflect.ValueOf` method invocation | `closure_test.go:L3121` | `INLINE (Tier 2 table)` |
| 98 | `reflectfixture` | `reflect_test.go` (15L) | `BenchmarkReflect`; `reflect.Value.Call` widening | `closure_test.go:L2570` | `INLINE (Tier 2 table)` |
| 99 | `rootcollision` | `bench/bench_test.go` (16L), `dep/dep.go` (13L) | 2-package same-named `BenchmarkSame` root collision check | `closure_test.go:L1372/L3341`, `fixtureprogram_bench_test.go:L17` | `KEEP -> closure/testdata/` |
| 100 | `scalarglobalslice` | `scalarglobalslice.go` (22L), `scalarglobalslice_test.go` (9L) | `BumpSlice`, `TestSliceWrite`; backing-array write via global slice | `closure_test.go:L1995` | `INLINE (Tier 2 table)` |
| 101 | `scalarglobalwrite` | `scalarglobalwrite.go` (34L), `scalarglobalwrite_test.go` (16L) | `BumpDirect`, `BumpUnsafe`, `TestDirectWrite`, `TestUnsafeWrite` | `closure_test.go:L1993/L1994` | `INLINE (Tier 2 table)` |
| 102 | `sharedchdir` | `sharedchdir_test.go` (26L), `post/fixture.txt` (1L), `pre/fixture.txt` (1L) | `BenchmarkSharedChdir` | `closure_test.go:L1833` | `INLINE (Tier 2 table)` |
| 103 | `sharedfchdir` | `sharedfchdir_test.go` (39L), `post/fixture.txt` (1L), `pre/fixture.txt` (1L) | `BenchmarkSharedFchdir` | `closure_test.go:L1834` | `INLINE (Tier 2 table)` |
| 104 | `sharedfile` | `fixture.txt` (1L), `sharedfile_test.go` (23L) | `BenchmarkSharedFile` | `closure_test.go:L1830` | `INLINE (Tier 2 table)` |
| 105 | `sharedglobal` | `post.txt` (1L), `pre.txt` (1L), `sharedglobal_test.go` (27L) | `BenchmarkSharedGlobal` | `closure_test.go:L1832` | `INLINE (Tier 2 table)` |
| 106 | `sharedparam` | `post.txt` (1L), `pre.txt` (1L), `sharedparam_test.go` (23L) | `BenchmarkSharedParam` | `closure_test.go:L1831` | `INLINE (Tier 2 table)` |
| 107 | `stdcallback` | `stdcallback_test.go` (21L) | `BenchmarkSortCallback`; `sort.Sort` interface callback | `closure_test.go:L1791` | `INLINE (Tier 2 table)` |
| 108 | `stdwrapper` | `stdwrapper_test.go` (12L) | `BenchmarkTemplateParseFiles`; `text/template.ParseFiles` | `closure_test.go:L1773` | `INLINE (Tier 2 table)` |
| 109 | `subtestbench` | `subtestbench_test.go` (18L) | `BenchmarkSubRead`, `BenchmarkSubPure` (`b.Run`) | `closure_test.go:L2168/L2169` | `INLINE (Tier 2 table)` |
| 110 | `subtestparallel` | `subtestparallel_test.go` (13L) | `TestParallelChild` (`t.Run` + `t.Parallel`) | `closure_test.go:L2164` | `INLINE (Tier 2 table)` |
| 111 | `syscallbinding` | `link` (1L), `post.txt` (1L), `pre.txt` (1L), `syscallbinding_test.go` (31L) | `BenchmarkSyscallBinding` | `closure_test.go:L1843` | `INLINE (Tier 2 table)` |
| 112 | `tempdir` | `tempdir_test.go` (9L) | `BenchmarkTempDir` (`b.TempDir()`) | `closure_test.go:L1847` | `INLINE (Tier 2 table)` |
| 113 | `testmainfile` | `fixture.txt` (1L), `testmainfile_test.go` (19L) | `TestMain` + `BenchmarkTestMainFile` | `closure_test.go:L1840` | `INLINE (Tier 2 table)` |
| 114 | `testmainhelper` | `testmainhelper_test.go` (18L) | `TestMain` delegating `m.Run()` to `run(m)` helper | `closure_test.go:L2053` | `INLINE (Tier 2 table)` |
| 115 | `testmainroot` | `testmainroot_test.go` (22L) | `TestMain`, `setup`, `BenchmarkTestMainRoot` | `closure_test.go:L1631` | `INLINE (Tier 2 table)` |
| 116 | `testmainruntimefile` | `fixture.txt` (1L), `testmainruntimefile_test.go` (16L) | `TestMain` reading file before `m.Run()` | `closure_test.go:L1841` | `INLINE (Tier 2 table)` |
| 117 | `toolchainindirect` | `toolchainindirect_test.go` (11L), `helper/helper.go` (9L) | 2-package `runtime.NumCPU()` call through `helper.Cores()` | `closure_test.go:L2051` | `INLINE (Tier 2 table)` |
| 118 | `toolchaininit` | `toolchaininit_test.go` (16L) | `init()` calling `runtime.Version()` | `closure_test.go:L2052` | `INLINE (Tier 2 table)` |
| 119 | `toolchainread` | `toolchainread_test.go` (45L) | 6 tests reading/mutating files under `runtime.GOROOT()` | `closure_test.go:L2044-2049` | `INLINE (Tier 2 table)` |
| 120 | `toolchainruntime` | `toolchainruntime_test.go` (10L) | `TestOtherRuntimeSurface` (`runtime.NumCPU()`) | `closure_test.go:L2050/L2447` | `INLINE (Tier 2 table)` |
| 121 | `unixatbinding` | `link` (1L), `post.txt` (1L), `pre.txt` (1L), `unixatbinding_test.go` (31L) | `BenchmarkUnixAtBinding` (`syscall.Openat`) | `closure_test.go:L1846` | `INLINE (Tier 2 table)` |
| 122 | `unixcwd` | `unixcwd_test.go` (20L), `data/fixture.txt` (1L) | `BenchmarkUnixCWD` (`syscall.Chdir`) | `closure_test.go:L1828` | `INLINE (Tier 2 table)` |
| 123 | `unixfchdir` | `unixfchdir_test.go` (38L), `post/fixture.txt` (1L), `pre/fixture.txt` (1L) | `BenchmarkUnixFchdir` (`syscall.Fchdir`) | `closure_test.go:L1835` | `INLINE (Tier 2 table)` |
| 124 | `unixopencreate` | `unixopencreate_test.go` (18L) | `BenchmarkUnixOpenCreate` (`syscall.Open` with `O_CREAT`) | `closure_test.go:L1853` | `INLINE (Tier 2 table)` |
| 125 | `unsafesibling` | `grammar.go` (9L), `unsafesibling_test.go` (20L) | `Carry`, `TestCleanRead`, `TestReachesUnsafe` | `closure_test.go:L1974/L1975` | `INLINE (Tier 2 table)` |
| 126 | `unsafeslice` | `doc.go` (3L), `unsafeslice_test.go` (17L) | `TestSliceHeader` (`unsafe.Slice` / `unsafe.StringData`) | `closure_test.go:L1980` | `INLINE (Tier 2 table)` |
| 127 | `unsafewrapped` | `unsafewrapped_test.go` (17L), `handle/handle.go` (18L) | 2-package wrapped `unsafe.Pointer` handle | `closure_test.go:L2043` | `INLINE (Tier 2 table)` |

#### Summary of Fixture Dispositions
- **Delete immediately (orphan)**: 1 (`embedfixture`)
- **Move to root `testdata/`**: 2 (`externaldirective`, `puredirective`)
- **Inline into Tier 2 table / batch tests**: 108 fixtures
- **Move to `closure/testdata/`**: 16 fixtures (`ambiguousroot`, `asmcall`, `asminvoke`, `direct`, `external`, `externalbench`, `genericpostrta`, `harnessroot`, `initfile`, `initregistry`, `linknamelocal`, `methodsubject`, `observable`, `observablebad`, `observablefresh`, `observablemutation`, `opaqueasm`, `rootcollision` — or 18 max)
- **Net result on `go list ./...`**: **-135 accidental packages (100% eliminated from module package graph)**.

---

## 4. Consolidation Plan for All 65 `closure/*_test.go` + 6 Subpackage Test Files

### 4.1 The 4-Tier Testing Architecture for `closure`

Currently, `closure/` has **65 test files** (`24,587` lines) plus **6 subpackage test files** (`1,769` lines in `closure/testvariant` and `closure/internal/*`), totaling **71 test files** (`26,356` lines). Tests are scattered across dozens of tiny per-commit files and massive monoliths (`closure_test.go` 4,574L, `toolchainsource_test.go` 3,690L, `audited_test.go` 3,634L), and local AST/type/SSA properties are repeatedly tested through full `newAt(dir)` (`go list` + stdlib surface check + `packages.Load` + whole-program SSA/RTA).

Consolidating into a **4-Tier Testing Architecture** reduces the 65 `closure/*_test.go` files to **14 cohesive, domain-aligned test files** (plus the 4 internal/subpackage test files):

| Tier | Purpose & Allowed Setup | Target Speed | Target Consolidated Files in `closure/` |
| :--- | :--- | :--- | :--- |
| **Tier 0: Internal Subpackage Unit Tests** | Pure in-memory unit/property tests of internal engines (`cachefile`, `compartment`, `rta`) and `program` preparation. | `< 50 ms` (except `prepared_test.go`) | `closure/internal/cachefile/cachefile_test.go`<br>`closure/internal/compartment/compartment_test.go` (merge `bindings_test.go`)<br>`closure/internal/rta/rta_test.go`<br>`closure/internal/program/prepared_test.go`<br>`closure/testvariant/testvariant_test.go` (deduplicate against `compartment_test.go`) |
| **Tier 1: In-Memory Frontend, AST/Type Scanner, Verifier & Scope Unit Tests** | `go/parser`, `go/types`, synthetic `listPkg` / `listedPackage` structs. **Zero `go list` or `packages.Load` subprocesses.** | `< 200 ms` total | 1. `scope_and_policy_test.go`<br>2. `effectscan_unit_test.go`<br>3. `toolchain_verifier_unit_test.go` |
| **Tier 2: In-Memory SSA (`ssautil.BuildPackage`) & Shared-Prepared-Program RTA / Observability Tests** | Either in-memory `ssautil.BuildPackage` (for local RTA/generic/constraint/dispatch rules) or **one shared `program.Prepared` / single batch `Hasher` per file** (for stdlib-coupled observability rules). | `< 2 s` per file | 4. `rta_reachability_test.go`<br>5. `generic_analysis_test.go`<br>6. `observability_effects_test.go`<br>7. `observability_harness_and_flags_test.go`<br>8. `audited_stdlib_test.go` |
| **Tier 3: Toolchain Surface, Memo Persistence & Module Integration Tests** | Exercises `gotool.Runner`, `go list` shims, `cachefile` persistence, `testvariant` module compartments, and property fuzzers. | `< 5 s` total | 9. `maximal_and_floor_test.go`<br>10. `testvariant_integration_test.go`<br>11. `toolchain_surface_integration_test.go`<br>12. `memo_persistence_test.go`<br>13. `helpers_test.go`<br>14. `bench_test.go` |

### 4.2 Complete Mapping of All 65 `closure/*_test.go` Files into the 14 Target Files

1. **`scope_and_policy_test.go` (Tier 1 — Pure Unit)**
   - Absorbs: `frontend_test.go` (114L), `scope_test.go` (75L), `policymemo_test.go` (177L), `nilreader_test.go` (25L), `inventory_variants_test.go` (39L), `refusalchannels_test.go` (`L17-49`), `auditset_test.go` (72L), `canonical_test.go` (282L), `environment_test.go` (17L).
   - Eliminates all subprocess calls; tests every scope string, `IdentityStrategy`, `AdmissionPolicy` memo, `effectCauseRank`, and `preferEffectReason` in `< 20 ms`.

2. **`effectscan_unit_test.go` (Tier 1 — AST/Type Effect Scanner Unit & Reference Equivalence)**
   - Absorbs: `effectscan_equivalence_test.go` (253L), `effectscan_reference_test.go` (588L), `bindingcollection_test.go` (104L), and the in-memory `maximalFileEffects*` / `maximalPackageEffects*` tests from `maximal_test.go` (`L263-280`, `L420-694`, `L759-931`), **plus converts `TestComputeMaximalBatchConservativelyMarksStandardWrappers` (`maximal_test.go:L135-261`) from 14 subprocess module loads into a `< 5 ms` in-memory table test**.

3. **`toolchain_verifier_unit_test.go` (Tier 1 — Synthetic Stdlib & Assembly Verifier Unit Tests)**
   - Absorbs: `toolchainsource_test.go` (`L30-152`, `L240-1472`, `L1813-3275`, `L3369-3638`), plus **converts the 22 single-package AST/assembly mutation subcases of `TestDstSelectionIsJudgedByContentNeverByTag` (`toolchainsource_dst_test.go:L23-450`) from slow `OverlayGOROOTEnv` + `newAtEnv` subprocess runs into fast `verifyListedPackage` / `verifyOffSurfacePackageWithIO` synthetic unit cases**.

4. **`rta_reachability_test.go` (Tier 2 — Function Reachability, Dispatch, and Escape)**
   - Absorbs: `narrowdispatch_test.go` (86L), `paramcrossing_test.go` (72L), `initroot_test.go` (75L), `missingroot_test.go` (67L), `ambiguity_test.go` (62L), `attachment_test.go` (84L), `dynamicstate_test.go` (30L), `ssahandles_test.go` (91L), and the Tier 2 reachability/dispatch sections of `closure_test.go` (along with inlined fixtures `direct`, `depdispatch`, `dyncaller`, `dyninit*`, `stdcallback`, `stdwrapper`, `reflect*`).

5. **`generic_analysis_test.go` (Tier 2 — Generic Subjects, Bounded Constraints, Generic Methods)**
   - Absorbs: `generic_test.go` (474L), `genericbounded_test.go` (434L), `genericmethod_test.go` (115L), plus inlined fixtures `genericescape` and `genericmethod`.
   - Converts `TestUnboundedConstraintsStayOpenWorld` and `TestRecursiveConstraintsTerminateOpen` to direct `go/types` / `ssautil.BuildPackage` checks instead of spawning 6 full `newAt(dir)` subprocess loads.

6. **`observability_effects_test.go` (Tier 2 — Ambient Channels, Fresh TempDir Provenance, Outcomes, Sync.Map)**
   - Absorbs: `outcomes_test.go` (210L), `syncmemo_test.go` (60L), `entropy_test.go` (191L), `canary_test.go` (65L), `refusalchannels_test.go` (`L56-127`), and the ambient-effect / fresh-file / global-mutation sections of `closure_test.go` (along with inlined fixtures `copyfs`, `createtemp`, `filemutations`, `fmtsink*`, `mkdir*`, `observable*`, `openfile*`, `openrootread`, `pathbinding`, `scalarglobal*`, `shared*`, `syscallbinding`, `tempdir`, `toolchain*`, `unix*`, `unsafe*`).

7. **`observability_harness_and_flags_test.go` (Tier 2 — `testing` Harness, `TestMain`, `flag.FlagSet`, and `rapid`)**
   - Absorbs: `flagset_test.go` (85L), `flagsetprov_test.go` (118L), `propertyharness_test.go` (412L), and the `TestMain` / `testing.TB` / `flag` sections of `closure_test.go` (along with all 15 inlined `flag*` fixtures and 21 `harness*` / `testmain*` / `subtest*` / `fuzzsibling` fixtures).

8. **`audited_stdlib_test.go` (Tier 2 — Audited Standard Library Admission Suite)**
   - Absorbs: `audited_test.go` (3,634L), sharing prepared fixture programs across batches.

9. **`maximal_and_floor_test.go` (Tier 3 — Maximal Package Closure, Floor Property, PGO & Non-Go Widening)**
   - Absorbs: `maximal_facts_test.go` (223L), `maximal_test.go` (module-level tests `L12-133`, `L282-418`, `L696-748`, `L1622-1811` from `toolchainsource_test.go`), `floorproperty_test.go` (116L), `pgo_binding_test.go` (107L), `dependencies_test.go` (166L).

10. **`testvariant_integration_test.go` (Tier 3 — Test-Variant Compartment & Ledger Integration)**
    - Absorbs: `testvariant_test.go` (607L, stripped of pure ledger-diff tests that duplicate `compartment_test.go`), `testvariant_binding_test.go` (105L, removing the 10 redundant `go test` subprocesses already covered by `compartment/bindings_test.go`), `compartmentledger_test.go` (251L).

11. **`toolchain_surface_integration_test.go` (Tier 3 — Toolchain Listing, Selection, Overlay & Cancellation)**
    - Absorbs: `toolchainselection_test.go` (373L), `toolchainexperiment_test.go` (44L), `toolchainsource_cancel_test.go` (144L), `toolchain_dependencies_linux_test.go` (234L — replacing `cp -a` of `GOROOT` with `OverlayGOROOTEnv` or synthetic `GOROOT` shim), the 3 end-to-end tests in `toolchainsource_dst_test.go`, and the real-`GOROOT` / shim tests in `toolchainsource_test.go` (`L159-232`, `L1481-1620`, `L3277-3367`, `L3640-3679`).

12. **`memo_persistence_test.go` (Tier 3 — Disk Memo Suites: Listing, File, Contrib, Testing, Effect, Observability, ViewLoad)**
    - Absorbs: `listingmemo_test.go` (431L), `listing_dependencies_test.go` (271L), `listingsalvage_test.go` (52L), `filememo_test.go` (356L), `contribmemo_test.go` (140L), `testingmemo_test.go` (273L), `effectmemo_test.go` (357L), `memo_test.go` (532L), `viewload_test.go` (130L), `cacheisolation_test.go` (30L), `bracketlive_test.go` (43L), `batch_test.go` (620L), `observabilityrelease_test.go` (61L), `fixturepreparation_test.go` (213L), `fixtureprogram_test.go` (263L).

13. **`helpers_test.go` (Shared Test Helpers)**
    - Absorbs: `helpers_test.go` (54L) + `tier2driver_test.go` (69L).

14. **`bench_test.go` (Benchmarks)**
    - Absorbs: `observabilitybench_test.go` (30L) + `fixtureprogram_bench_test.go` (46L) + `BenchmarkAdmissionPolicy` (`policymemo_test.go:L167-177`).
