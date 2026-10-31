# Audit 08c — Subpackage Tests (`runtimeinput`, `gotool`, `guard`, `guidance`, `resident`, `internal/*`, `shortgates`, `toolversion`)

## Scope Summary

| Package | Test Files | Total Lines (`wc -l`) | Primary Test Mechanisms |
| :--- | ---: | ---: | :--- |
| `runtimeinput` | 34 | 10,557 | Tempdir FS fixtures, testlog strings, `testing/quick`, `testing.F`, `go env` subprocesses, self-re-exec |
| `gotool` | 16 | 1,948 | Subprocess shims (`sh`, `go`), Linux cgroup/procfs fixtures, in-memory env/flag tables |
| `guard` | 8 | 886 | In-memory projection/comparison tables, `testing.F`, Linux `/proc` & sysfs parsers |
| `guidance` | 2 | 1,297 | Pure projection/rendering assertions, `testing.F` |
| `resident` | 4 | 816 | Pure ceiling-family/command-word classification, `testing.F`, host-specific path fixtures |
| `internal/auditset` | 2 | 225 | In-memory set/identity normalization tables |
| `internal/buildflags` | 1 | 35 | Build-flag normalization table |
| `internal/jsonrecord` | 1 | 19 | JSON strict decoding assertions |
| `internal/outcome` | 1 | 34 | Outcome support token preparation/verification |
| `internal/render` | 1 | 26 | Bounded list formatting assertions |
| `internal/testenv` | 2 | 153 | `GOCACHE` / `GOROOT` environment preservation helpers |
| `shortgates` | 1 | 191 | AST/file gate checks over temporary package trees |
| `toolversion` | 1 | 57 | BuildInfo / version string derivation assertions |
| **Total** | **74** | **16,244** | — |

*(Note: The prompt summary counted `internal/**/*_test.go` as 7 files / 492 lines; `internal/` actually contains 8 `*_test.go` files totaling 492 lines because `internal/auditset` and `internal/testenv` have 2 test files each. All 74 files and all 16,244 lines have been read in full.)*

---

## Part 1: `runtimeinput` Test Suite Audit (34 files, 10,557 lines)

### 1.1 File-by-File and Test-by-Test Inventory (`runtimeinput`)

#### 1. [`runtimeinput/adopt_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/adopt_test.go) (182 lines)
- **Helpers**:
  - `adoptTestState` (`L14-L29`): encodes a `manifest`, normalizes `env`, and calls `currentWithNormalizedEnv` to produce a canonical `State`.
- **Tests**:
  - `TestAdoptedUnionMergesLikeFreshObservations` (`L34-L67`): Witnesses `REQ-inputs-adoption` + `REQ-inputs-merge` (adopting a persisted union manifest and merging with a third observation yields identical `State` to merging all three fresh observations). Setup: tempdir + 1 file. Tier: **Tier 1 (Algebraic / In-Memory + Minimal FS State)**.
  - `TestAdoptRefusesMovedManifestNamingTheMover` (`L71-L86`): Witnesses `REQ-inputs-adoption` (refuses a manifest whose file content mutated after recording, naming the moved input). Setup: tempdir + 1 file. Tier: **Tier 1**.
  - `TestAdoptRefusesNonCanonicalEncoding` (`L90-L112`): Witnesses `REQ-inputs-adoption` canonical-encoding gate (rejects trailing base64 chars, empty string, and valid-JSON/base64 with trailing whitespace). Setup: tempdir + env-only manifest. Tier: **Tier 1 (Pure Wire/Encoding)**.
  - `TestAdoptBoundaryValidationAndProvenance` (`L119-L137`): Witnesses `REQ-inputs-adoption` boundary validation (rejects empty process identity, duplicate env keys, and provenance conflict when merging adopted and completed observations for the same process ID). Setup: tempdir + env-only manifest. Tier: **Tier 1**.
  - `TestAdoptCarriesUnverifiableReasons` (`L141-L160`): Witnesses `REQ-inputs-adoption` (unverifiable reasons survive `Adopt` + `Merge`). Setup: tempdir + env-only manifest. Tier: **Tier 1**.
  - `TestAdoptObservationFreeManifest` (`L164-L182`): Witnesses `REQ-inputs-adoption` + `REQ-inputs-merge` zero-observation identity. Setup: tempdir. Tier: **Tier 1**.

#### 2. [`runtimeinput/attribution_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/attribution_test.go) (658 lines)
- **Tests**:
  - `TestClassificationRefusalNamesItsObservation` (`L26-L113`): Witnesses `REQ-inputs-refusal-attribution` and `REQ-inputs-external-dir-existence` (`open /`, parent traversal to `/`, `stat /`, `/proc/stat`, `chdir /`, non-UTF-8 `chdir` target; checks `state.Reason` is the clause, `state.Attribution` quotes op/path/dir, and `m.Unverifiable` contains no `attributionSeparator`). Setup: tempdir + `testBracket`. Tier: **Tier 2 (FS Classification & Bracket)**.
  - `TestAttributionIsOutsideTheInputsIdentity` (`L126-L239`): Witnesses `REQ-inputs-refusal-attribution` (two checkouts produce identical `Manifest`, `Digest`, and `Reason` while `Attribution` names each checkout's dir; `Current`, `Merge`, `Absolute`, and `Relative` preserve/convert `Attribution` properly; sorted manifest clause order determines which attribution wins). Setup: 2 tempdirs + `testBracket`. Tier: **Tier 2**.
  - `TestRefusalClauseSurvivesSeparatorsInNames` (`L247-L341`): Witnesses `REQ-inputs-refusal-attribution` (`RefusalClause`, `RefusalAttribution`, `memberListName`, `representableReasonName`, `operationAttribution`, `resolvedTargetAttribution` round-trip across adversarial separator/bracket/quote strings). Setup: pure in-memory table. Tier: **Tier 1 (Pure String/Grammar Property)**.
  - `TestRefusalAttributionIsTheClauseSplitsComplement` (`L349-L370`): Witnesses `REQ-inputs-refusal-attribution` (`RefusalClause` + `RefusalAttribution` partition identity). Setup: pure in-memory table. Overlaps directly with `TestRefusalClauseSurvivesSeparatorsInNames`. Tier: **Tier 1**.
  - `TestConvertAttributionDirRewritesOnlyTheOperationForm` (`L377-L392`): Witnesses `REQ-inputs-refusal-attribution` (`convertAttributionDir` grammar selectivity). Setup: pure in-memory table. Tier: **Tier 1**.
  - `TestInModuleRefusedPathSpellsModuleRelative` (`L402-L469`): Witnesses `REQ-inputs-refusal-attribution` (escaping symlinks `escape` and `escapefile` inside the module spell module-relative in `Reason` and `Manifest` across two checkouts while `Attribution` names the resolved target). Setup: 3 tempdirs + symlinks + `testBracket`. Tier: **Tier 2**.
  - `TestEscapingLinkSpellsRelativeUnderASymlinkedPrefix` (`L475-L513`): Witnesses `REQ-inputs-refusal-attribution` (module reached via symlinked parent prefix still spells escaping link relative in `(symlink outside every bracket root: escape)`). Setup: tempdirs + symlinks + `testBracket`. Tier: **Tier 2**.
  - `TestMovedBracketMemberListIsTheAttribution` (`L520-L552`): Witnesses `REQ-inputs-refusal-attribution` (`observation bracket moved: data` carries `added: b.txt, "x; y.txt"` in `state.Attribution` and keeps ` [added:...]` out of `m.Unverifiable`). Setup: tempdir + `testBracket`. Tier: **Tier 2**.
  - `TestMovedBracketRootSpelledLikeAMemberList` (`L561-L658`): Witnesses `REQ-inputs-refusal-attribution` (quoting of bracket roots whose names contain member-list framing chars `[`, `]`, `;`, `"`; `splitBracketAttribution`, `MovedBracketClause`, `CanonicalMovedBracketClause` idempotence). Mixes FS bracket runs (`L562-L600`, `L647-L657`) with pure string table checks (`L606-L645`). Tier: **Tier 1 / Tier 2 Split**.

#### 3. [`runtimeinput/attribution_unix_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/attribution_unix_test.go) (116 lines)
- **Tests**:
  - `TestUnhashableInModuleMembersSpellModuleRelative` (`L21-L116`): Witnesses `REQ-inputs-refusal-attribution` on Unix (`syscall.Mkfifo` and `os.Chmod(0000)` inside module spell `data/pipe` and `data/secret` module-relative in both bracket walk and `Current` revalidation across two checkouts). Setup: tempdirs + FIFO + chmod. Tier: **Tier 2 (Unix FS)**.

#### 4. [`runtimeinput/bracket_module_root_stat_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/bracket_module_root_stat_test.go) (83 lines)
- **Tests**:
  - `TestModuleRootBracketCoversInteriorStats` (`L16-L83`): Witnesses `REQ-inputs-bracket-coverage` (a `stat` of a file under a `.` module-root bracket is covered and binds metadata digest rather than sealing `stat metadata input`, whereas a `stat` under `WithBracketExcludedPaths("toolstate")` seals `stat metadata input: toolstate/cache`). Setup: tempdir + `CaptureBracket`. Overlaps heavily with `TestBracketNeverWeakensDisposition` in `valuebinding_test.go`. Tier: **Tier 2**.

#### 5. [`runtimeinput/bracket_motion_linux_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/bracket_motion_linux_test.go) (37 lines)
- **Tests**:
  - `TestBracketRetypingRemainsKnownBesideUnhashableContent` (`L10-L37`): Witnesses `REQ-inputs-value-binding` (replacing a regular file with a FIFO or vice versa between bracket capture and `FromTestLog` sets `observation.BracketMoved = true`). Setup: tempdir + `syscall.Mkfifo`. Overlaps with `TestBracketMovementIncludesObjectTransitions` (`bracket_motion_test.go`) and `TestPartialRootKnownMovement` (`partial_motion_linux_test.go`). Tier: **Tier 2**.

#### 6. [`runtimeinput/bracket_motion_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/bracket_motion_test.go) (186 lines)
- **Tests**:
  - `TestBracketMovementSurvivesComposition` (`L15-L84`): Witnesses `REQ-inputs-value-binding` (`BracketMoved` survives `CompletedState`, `Current`, `Absolute`, `Relative`, `Adopt`, `Merge` with empty/incomplete/moved, rejects unsealed `BracketMoved` tampering, and is not erased if the file is later restored on disk). Setup: tempdir + `testBracket`. Overlaps with `TestRunToIngestWindowMutationSealsObservationUnverifiable` (`valuebinding_test.go`) and `FuzzOutcomeEvidenceMergePreservesSupport` (`outcome_test.go`). Tier: **Tier 2**.
  - `TestBracketUnknownDoesNotMaskComparableMovement` (`L86-L129`): Witnesses `REQ-inputs-value-binding` (an unhashable external symlink root alongside a mutated regular root or late-replaced root still reports `BracketMoved`). Setup: tempdir + symlinks. Tier: **Tier 2**.
  - `TestBracketMovementIncludesObjectTransitions` (`L131-L162`): Witnesses `REQ-inputs-value-binding` (`appearance`, `disappearance`, `retype` file->dir set `BracketMoved`). Setup: tempdir. Overlaps with `TestBracketMovesOnPersistedMutation` (`bracket_test.go`). Tier: **Tier 2**.
  - `TestMovementManifestCanonicalWireAndDigest` (`L164-L186`): Witnesses wire encoding of `"bracketMoved":true` in v4 manifest, digest preimage `bracket-moved\n`, rejection of `"bracketMoved":false`/`null`/duplicate/misordered, and that `Incomplete(..., MovedBracketClause("data"), ...)` does not set `BracketMoved`. Setup: pure wire/manifest + `t.TempDir()`. Tier: **Tier 1 (Pure Wire/Encoding)**.

#### 7. [`runtimeinput/bracket_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/bracket_test.go) (796 lines)
- **Helpers**:
  - `bracketTree` (`L22-L42`): builds a module tree with `data/a.txt`, `data/sub/b.txt`, symlink `data/link -> a.txt`, and `top.txt`.
- **Tests**:
  - `TestBracketCaptureAndRevalidateAgreeOnUnchangedTree` (`L48-L85`): Witnesses `REQ-inputs-value-binding` (self-agreement on unchanged tree, equivalent root declaration normalization `./data` vs `data`, empty bracket). Setup: `bracketTree`. Tier: **Tier 2**.
  - `TestBracketMovesOnPersistedMutation` (`L92-L238`): Witnesses `REQ-inputs-value-binding` and `REQ-inputs-bracket-coverage` across 17 subtests (content edit with restored mtime/size, mtime-only, mode-only, file created, file deleted, file->dir, dir->file, symlink retargeted, file root deleted/mtime/mode, absent root appears as file/dir, external file root edited, hardlink alias edit, empty dir created, dir mode change). Setup: `bracketTree` per subtest. Tier: **Tier 2**.
  - `TestBracketExclusionsRemoveSubtreeFromFingerprintAndCoverage` (`L244-L295`): Witnesses `REQ-inputs-bracket-coverage` exclusion clause (`WithBracketExcludedPaths`). Setup: `bracketTree`. Tier: **Tier 2**.
  - `TestBracketRootRefusedByHashingSemanticsIsUnverifiable` (`L303-L327`): Witnesses `REQ-inputs-bracket-coverage` refusal clause (module-relative symlink root resolving to external dir). Setup: `bracketTree` + symlink. Tier: **Tier 2**.
  - `TestAbsoluteDirectoryRootBindsItsTree` (`L336-L385`): Witnesses `REQ-inputs-bracket-coverage` for external directory roots. Setup: `bracketTree` + external dir. Tier: **Tier 2**.
  - `TestAbsoluteDirectoryRootWalksItsResolvedTree` (`L394-L444`): Witnesses `REQ-inputs-value-binding` full-chain rule for symlinked external directory root + exclusions under it. Setup: `bracketTree` + symlinked external dir. Tier: **Tier 2**.
  - `TestAbsoluteRootContainingVolatileOSRootIsRefused` (`L449-L474`): Witnesses `REQ-inputs-volatile-os-roots` (refuses `/` or parent of `/proc`, and seals unverifiable when a symlink root resolves into `/proc`). Setup: `bracketTree` + symlink to `guard.VolatileOSRoots[0]`. Tier: **Tier 2**.
  - `TestFilesystemRootIsRefusedAsBracketRoot` (`L478-L483`): Witnesses refusal of `/` as a bracket root. Tier: **Tier 2**.
  - `TestBracketRevalidateRefusesForeignModuleViewAndUnsealedBracket` (`L489-L512`): Witnesses `REQ-inputs-value-binding` refusal of foreign `moduleDir`, zero `Bracket`, tampered `facts`, or `nil` context. Tier: **Tier 2**.
  - `TestCaptureBracketRejectsMalformedRootsAndPatterns` (`L517-L534`): Witnesses root/exclusion pattern validation (`""`, `"../outside"`, `".."`, `\n`, `\x00`, `\r`). Tier: **Tier 1**.
  - `TestCaptureBracketHonorsCancellation` (`L539-L556`): Witnesses `REQ-inputs-context` cancellation during `CaptureBracket` using `cancelAfterChecks`. Tier: **Tier 2**.
  - `FuzzBracketSinglePersistedMutationMovesFingerprint` (`L564-L678`): Property/fuzz test witnessing `REQ-inputs-value-binding` and `REQ-inputs-bracket-coverage` over PRNG-generated directory trees, mutations, exclusions, and unreadable sibling files. Tier: **Tier 2 (Property/Fuzz)**.
  - `TestBracketMoveAttributionNamesTheMove` (`L686-L796`): Witnesses `REQ-inputs-value-binding` move attribution (`recently touched:`, `added:`, `removed:`, `render.ListCap` capping with `, and N more`, quoting of filenames with `\n`). Tier: **Tier 2**.

#### 8. [`runtimeinput/directory_fact_identity_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/directory_fact_identity_test.go) (47 lines)
- **Tests**:
  - `TestAliasRootListingAvailabilityDoesNotMixStatIdentities` (`L10-L47`): Witnesses that when a bracket root is a symlink to `.` (`alias -> .`) and `walkRuntimeDirectory` fails with `EACCES` on `readdir`, the root's `lstat` vs followed-dir `stat` facts are not conflated into false movement across capture/revalidate availability combinations (`before`, `after` in `{false, true}`). Setup: tempdir + `walkRuntimeDirectory` hook. Belongs with `namespace_presence_test.go` / `overlap_membership_test.go`. Tier: **Tier 2 (Hooked FS Fact Comparison)**.

#### 9. [`runtimeinput/exclusions_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/exclusions_test.go) (332 lines)
- **Tests**:
  - `TestExcludedPathsAreNeverRecorded` (`L13-L67`): Witnesses `REQ-inputs-exclusions` (`WithExcludedPaths(".git")` drops `.git/HEAD` open and `.git` stat, and digest is invariant to `.git/HEAD` mutation). Tier: **Tier 2**.
  - `TestExclusionBoundaryIsPathSeparator` (`L71-L91`): Witnesses `REQ-inputs-exclusions` (`.git` does not exclude `.gitignore`). Tier: **Tier 2**.
  - `TestExclusionOfRootListingKeepsChildren` (`L95-L119`): Witnesses `REQ-inputs-exclusions` (`WithExcludedPaths(".")` drops `open ..` module-root listing while keeping `spec.md`). Tier: **Tier 2**.
  - `TestExclusionAbsoluteKind` (`L123-L149`): Witnesses `REQ-inputs-exclusions` for absolute path patterns. Tier: **Tier 2**.
  - `TestExcludedChdirStillTracksWorkingDirectory` (`L154-L190`): Witnesses `REQ-inputs-exclusions` (excluding `deep/scratch` drops the `chdir` target path identity while still updating `cwd` for subsequent `open ../kept.txt`). Tier: **Tier 2**.
  - `TestEmptyExclusionPatternRefused` (`L194-L199`): Witnesses `WithExcludedPaths("")` error refusal. Duplicates `TestCaptureBracketRejectsMalformedRootsAndPatterns`. Tier: **Tier 1**.
  - `TestExcludedPathsOutrankClassificationRefusals` (`L206-L256`): Witnesses `REQ-inputs-exclusions` precedence over `open /` and `open /proc/sys/net/core/somaxconn`. Tier: **Tier 2**.
  - `TestExclusionOutranksExistenceBindingAndChdir` (`L265-L332`): Witnesses `REQ-inputs-exclusions` precedence over external dir `stat`, absent external `stat`, and `chdir /` target classification refusal (while retaining `working-directory change` observation seal). Tier: **Tier 2**.

#### 10. [`runtimeinput/file_eligibility_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/file_eligibility_test.go) (541 lines)
- **Helpers**:
  - `eligibilityFile` (`L17-L30`), `eligibilityModule` (`L34-L46`), `eligibilityEnv` (`L48-L54`), `eligibilityObserve` (`L56-L72`).
- **Tests**:
  - `TestFileInputEligibilityMatchesProducer` (`L76-L124`): Witnesses `FileInputEligibility` agreement with `ProducerFrame.ObserveInputs` across 10 subtests (`ordinary`, `build-cache`, `build-fuzz`, `module-cache`, `module-download`, `overlapping-cache`, `overlapping-fuzz`, `inside-tree`, `cache-equals-tree`, `cache-contains-tree`). Spawns `go env -json` once per subtest (10 subprocesses!). Tier: **Tier 3 (Subprocess / Producer Integration)** — could be Tier 2 if `Roots` memo or synthetic `gotool.Runner` were shared across subtests with fixed roots.
  - `TestFileInputEligibilityEffectiveRootsAndExceptions` (`L126-L209`): Witnesses `FileInputEligibility` with `GOENV` file, symlinked `GOCACHE`, env override, `GOROOT/VERSION`, symlinked `GOROOT`, and `TMPDIR`/`GOTMPDIR` persistent regular files. Spawns multiple `go env` subprocesses. Tier: **Tier 3**.
  - `TestFileInputEligibilityResolutionInputs` (`L213-L239`): Witnesses `FileInputEligibility` when the queried file is itself the `GOENV` config file. Spawns `go env` subprocesses. Tier: **Tier 3**.
  - `TestFileInputEligibilityRefusesProjectedAndUnsupported` (`L241-L300`): Witnesses `FileInputEligibility` refusals for relative/dir/missing/unclean/non-UTF-8 paths, malformed env, missing/foreign `PWD`, invalid module/pkg dirs, symlinks, `os.DevNull`, `/proc/cpuinfo` (`ProjectedFileInput`), and `/proc/self/status` (`UnverifiableFileInput` without probing). Spawns `go env` subprocesses for valid-env cases because no shared `Roots` memo is passed! Tier: **Tier 2 ( needlessly paying Tier 3 subprocess cost)**.
  - `TestFileInputEligibilityExclusionPrecedence` (`L302-L332`): Witnesses `FileInputEligibility` exclusion precedence + default `.git` exclusion. Again passes no `Roots` memo, spawning `go env` subprocesses on every loop iteration. Tier: **Tier 2 (needlessly paying Tier 3 subprocess cost)**.
  - `TestFileInputEligibilityUnavailableRoots` (`L334-L355`): Witnesses `FileInputEligibility` error when `go env -json` omits any of `GOROOT`, `GOMODCACHE`, `GOCACHE`, `GOTMPDIR`. Spawns 4 real `go env -json` subprocesses via `Runner.Prepare`. Tier: **Tier 3**.
  - `TestFileInputEligibilityCancellation` (`L357-L426`): Witnesses `FileInputEligibility` context cancellation at entry, after `go env` roots command, before probe, and during `classifyProbe`. Tier: **Tier 3 / Tier 2**.
  - `TestFileInputEligibilityOwnsCallerSlices` (`L428-L464`): Witnesses defensive cloning of `in.Env` and `in.ExcludedPaths` when `Runner.Prepare` mutates caller slices mid-call. Spawns 2 `go env` subprocesses. Tier: **Tier 3**.
  - `TestFileInputEligibilityExecution` (`L466-L541`): Self-re-executes the test binary (`-test.run=^TestFileInputEligibilityExecution$ -test.testlogfile=...`) in `"query"` and `"read"` modes to verify that calling `FileInputEligibility` inside a child process does not log an `open` of the queried file, whereas `os.ReadFile` does. Tier: **Tier 3 (Self-Re-Exec Integration)**.

#### 11. [`runtimeinput/guardcovered_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/guardcovered_test.go) (1,229 lines)
- **Helpers**:
  - `completedFromLog` (`L16-L31`): captures a bracket on `"data"` and runs `ambientFromTestLog` with `WithCompletedProcess("package-test-binary:guard")`.
- **Tests**:
  - `TestGuardCoveredRootsSkipPinnedReads` (`L37-L74`): Witnesses `REQ-inputs-guard-covered` (`withToolchainRoot` elides `open` and `stat` inside root). Tier: **Tier 2**.
  - `TestGuardCoveredOverlappingRootsConsultBeyondFirstMatch` (`L82-L152`): Witnesses `REQ-inputs-guard-covered` (inner root symlink escaping into outer root is covered by outer root; out-and-back chain via outer root is covered). Tier: **Tier 2**.
  - `TestGuardCoveredResolutionIsFailClosed` (`L158-L244`): Witnesses `REQ-inputs-guard-covered` fail-closed cases (module symlink into root, symlink escaping out of root, ambiguous `..` traversal across symlink under root, congruent `..` traversal under root, missing path under root). Tier: **Tier 2**.
  - `TestGuardCoveredSymlinkedRoot` (`L249-L278`): Witnesses `REQ-inputs-guard-covered` when declared root itself is a symlink. Tier: **Tier 2**.
  - `TestGuardCoveredRootValidation` (`L282-L289`): Witnesses `withToolchainRoot` validation of empty/relative/unclean roots. Tier: **Tier 1**.
  - `TestModuleCacheRootExcludesDownloadCache` (`L295-L327`): Witnesses `REQ-inputs-guard-covered` (`withModuleCacheRoot` elides extracted module files but observes `cache/download/...`). Tier: **Tier 2**.
  - `TestGuardCoveredRefusesOutAndBackChain` (`L333-L365`): Witnesses `REQ-inputs-guard-covered` (symlink chain leaving root and re-entering is observed). Overlaps with `TestGuardCoveredOverlappingRootsConsultBeyondFirstMatch`. Tier: **Tier 2**.
  - `TestGuardCoveredRelativeAfterChdirStaysObserved` (`L370-L395`): Witnesses `REQ-inputs-guard-covered` (relative read after `chdir` into root stays observed). Tier: **Tier 2**.
  - `TestGuardCoveredUnresolvableRootDeclaresNothing` (`L400-L410`): Witnesses `REQ-inputs-guard-covered` (non-existent root covers nothing). Tier: **Tier 2**.
  - `TestBuildCacheRootCoversToolchainMediatedReads` (`L418-L513`): Witnesses `REQ-inputs-guard-covered` (`withBuildCacheRoot` elides `-d`, `-a`, `trim.txt` but observes `fuzz/corpus/seed1` and escaping symlinks). Tier: **Tier 2**.
  - `TestEphemeralTempRootAdmitsOnlyItsOwnIdentity` (`L520-L641`): Witnesses `REQ-inputs-ephemeral-root` (`withEphemeralTempRoot` admits `stat`/`open` of the root itself, observes existing deeper files, supports symlinked root, ignores missing root, and rejects module-interior root). Tier: **Tier 2**.
  - `TestMachineFactIdentitiesDigestAsStableProjection` (`L648-L673`): Witnesses `REQ-inputs-machine-identity` on Linux (`/proc/cpuinfo`, `/proc/meminfo`, `/proc/sys/kernel/osrelease` digest stably). Tier: **Tier 2**.
  - `TestMachineFactArmsAndContrast` (`L679-L732`): Witnesses `REQ-inputs-machine-identity` (injected `currentMachineFacts` error -> `unhashable runtime input`, changed `MachineFacts` -> digest moves, `/proc/stat` -> `volatile OS input`). Tier: **Tier 2**.
  - `TestVolatileOSPathsClassifyLexically` (`L739-L817`): Witnesses `REQ-inputs-volatile-os-roots` (`/proc/stat`, missing `/proc/...`, `/sys/...` refuse lexically without calling `classifyProbe`; ephemeral/bracket/guard roots under `/proc` refused/ignored). Tier: **Tier 2**.
  - `TestNullSinkRecordsNothing` (`L823-L869`): Witnesses `REQ-inputs-null-sink` (`/dev/null` and `/dev//null` elided; `/dev/zero` and symlink to `/dev/null` stay observed). Tier: **Tier 2**.
  - `TestEphemeralScratchAbsentAtIngestRecordsNothing` (`L877-L969`): Witnesses `REQ-inputs-ephemeral-root` (absent deeper paths under ephemeral root elided; persistent deeper file, escaping symlink ancestor, and dangling symlink ancestor stay observed). Tier: **Tier 2**.
  - `TestPWDAdmitsOnlyWhenPinnedToSpawnDir` (`L973-L1017`): Witnesses `REQ-inputs-pwd` (`getenv PWD` binds `PWD` when `PWD == packageDir`, seals `process-local environment input: PWD` when divergent or absent). Overlaps with `TestFromTestLogMarksPWDUnverifiable` (`runtimeinput_test.go`) and `FuzzPWDObservationBindsOnlyTheObservedValue` (`pwd_test.go`). Tier: **Tier 1 / Tier 2**.
  - `TestExternalDirectoryStatBindsExistence` (`L1023-L1118`): Witnesses `REQ-inputs-external-dir-existence` (external dir `stat` binds existence, moves on deletion or retyping to file, while `open` seals `external directory input` and external file `stat` seals `stat metadata input`). Tier: **Tier 2**.
  - `TestAbsentExternalStatBindsAbsence` (`L1124-L1163`): Witnesses `REQ-inputs-absent-stat` (stat of absent external path binds absence and moves when created). Tier: **Tier 2**.
  - `TestEphemeralRootNeverSwallowsModuleInteriorReads` (`L1170-L1195`): Witnesses `REQ-inputs-ephemeral-root` (when module tree lies inside declared ephemeral root, module-interior absent open is still recorded). Tier: **Tier 2**.
  - `TestEphemeralRootRefusesAliasRouteIntoModule` (`L1202-L1229`): Witnesses `REQ-inputs-ephemeral-root` (symlink inside ephemeral root pointing into module tree is not treated as ephemeral scratch). Tier: **Tier 2**.

#### 12. [`runtimeinput/helpers_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/helpers_test.go) (44 lines)
- **Helpers**:
  - `ambientFromTestLog`, `ambientIncomplete`, `ambientAbsolute`, `ambientRelative`, `ambientMerge`, `ambientCurrent`, `ambientCurrentEnv`, `ambientMovedInputs`, `ambientCaptureBracket` (`L10-L44`): thin wrappers passing `os.Environ()` and `context.Background()`.

#### 13. [`runtimeinput/machine_motion_linux_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/machine_motion_linux_test.go) (163 lines)
- **Helpers**:
  - `machineMotionFacts` (`L15-L20`), `machineMotionRoots` (`L22-L30`), `machineMotionSamples` (`L32-L54`).
- **Tests**:
  - `TestMachineProjectionMovementSurvivesSourceAvailabilityShift` (`L56-L85`): Witnesses `REQ-inputs-machine-identity` + `REQ-inputs-value-binding` across 7 availability/projection combinations on two machine-fact bracket roots. Tier: **Tier 2 (Hooked In-Memory/FS)**.
  - `TestMachineBracketMovementSurvivesPostChangeManifest` (`L87-L123`): Witnesses that when machine projection shifts between bracket capture and `FromTestLog`, `observation.BracketMoved` is set even though post-change manifest hashing sees the new projection consistently. Tier: **Tier 2**.
  - `TestMachineProjectionKeepsRootScopeAndSeal` (`L125-L163`): Witnesses `b.checkSealed()` against relocating/mutating machine-fact root facts and verifies bracket exclusion of one machine-fact root. Tier: **Tier 2**.

#### 14. [`runtimeinput/movedinputs_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/movedinputs_test.go) (161 lines)
- **Tests**:
  - `TestMovedInputsNamesTheMover` (`L15-L74`): Witnesses `REQ-inputs-guard` (`MovedInputs` returns `["env MOVED_INPUT_PROBE"]` or `["path data/fixture.txt"]` when mutated, and `[]` when unmoved). Tier: **Tier 2**.
  - `TestStateManifestRoundTripsUnmoved` (`L79-L108`): Witnesses `Current` returning identical `State` when unmoved. Duplicates assertions already made in `runtimeinput_test.go` (`TestCurrentUsesSuppliedEnvironment`, `FuzzRuntimeObservationAndPathInvariants`). Tier: **Tier 2**.
  - `TestManifestRejectsMalformedEntryDigests` (`L113-L127`): Witnesses canonical wire validation of 32-char lowercase hex digests. Tier: **Tier 1 (Pure Wire/Encoding)**.
  - `TestManifestRejectsDuplicateIdentities` (`L132-L147`): Witnesses wire rejection of duplicate env or path identities. Tier: **Tier 1 (Pure Wire/Encoding)**.
  - `TestManifestRejectsOlderToolEncodings` (`L152-L161`): Witnesses wire rejection of v1 schema shapes. Overlaps with `TestMergeRejectsMalformedAndUnsupportedManifest` (`runtimeinput_test.go`), `TestOutcomeManifestRefusesInconsistentSupport` (`outcome_test.go`), and `FuzzHistoricalPWDManifestDoesNotUpgrade` (`pwd_history_test.go`). Tier: **Tier 1 (Pure Wire/Encoding)**.

#### 15. [`runtimeinput/namespace_presence_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/namespace_presence_test.go) (221 lines)
- **Helpers**:
  - `namespaceAvailabilityCase` (`L11-L13`), `checkNamespaceAvailability` (`L17-L98`): hooks `walkRuntimeDirectory`, `statRuntimePath`, `lstatRuntimePath` to simulate independent failure of parent directory listing vs direct path stat.
- **Tests**:
  - `TestNamespacePresenceMeetsCompleteListingAbsence` (`L100-L115`): 8 subtests (`reverse={false,true}` x `{"changed","same present","same absent","excluded"}`) comparing direct stat presence/absence against complete parent listing. Tier: **Tier 2 (Hooked FS Fact Comparison)**.
  - `TestResolvedFinalAbsenceSurvivesAvailabilityShift` (`L117-L132`): 8 subtests with `alias: true` (`alias -> data`). Tier: **Tier 2**.
  - `TestResolvedAbsenceRequiresTheFinalComponent` (`L134-L165`): Witnesses that `alias/parent/p` does not record resolved namespace absence when `parent` itself is missing, and seals final absence when `parent` exists. Tier: **Tier 2**.
  - `TestNamespaceExistenceComparisonIsSymmetric` (`L167-L186`): Pure unit test over `movedBracketRoot` checking symmetry of `namespaceFact` vs `followedStatFact` against a complete directory listing. Tier: **Tier 1 (Pure Fact Algebra)**.
  - `TestMissingAncestorAppearanceDoesNotInventResolutionDrift` (`L188-L221`): Witnesses that when `alias/parent/p` is absent because `parent` is missing, creating `parent` (as dir or symlink) while `p` remains absent does not move the bracket. Overlaps directly with `TestResolvedAbsenceRequiresTheFinalComponent` (`L134-L153`) and `TestRootNamespaceFactsKeepAbsenceAndDanglingLinksDistinct` (`partial_motion_linux_test.go:L136-L146`). Tier: **Tier 2**.

#### 16. [`runtimeinput/observationclass_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/observationclass_test.go) (369 lines)
- **Helpers**:
  - `touchFuture` (`L13-L19`).
- **Tests**:
  - `TestOpenObservedEvidenceTravelsAcrossCheckouts` (`L25-L70`): Witnesses `REQ-inputs-observation-class` (`open` records `Metadata: false`, ignores mtime changes, and revalidates in a second checkout). Tier: **Tier 2**.
  - `TestStatObservedEvidenceStaysMetadataBound` (`L75-L100`): Witnesses `REQ-inputs-observation-class` (`stat` records `Metadata: true` and moves on mtime change). Tier: **Tier 2**.
  - `TestStatUpgradesAnOpenObservedEntry` (`L104-L120`): Witnesses `REQ-inputs-observation-class` (`open` + `stat` in same log records `Metadata: true`). Tier: **Tier 2**.
  - `TestMergeUnionsObservationClasses` (`L125-L149`): Witnesses `REQ-inputs-observation-class` (`Merge` of `open` and `stat` observations yields `Metadata: true`). Tier: **Tier 2**.
  - `TestRelativeIdentitiesTravelAcrossCheckoutRoots` (`L155-L203`): Witnesses `REQ-inputs-relative-identities` (`Absolute` -> `Relative` converts in-module paths to `rel` and revalidates in second checkout). Tier: **Tier 2**.
  - `TestConversionsPreserveMetadataClass` (`L209-L247`): Witnesses `REQ-inputs-observation-class` + `REQ-inputs-relative-identities` (`Absolute` <-> `Relative` preserves `Metadata: true`). Tier: **Tier 2**.
  - `TestConversionCollapsesKindsUnderClassUnion` (`L252-L295`): Witnesses `Relative` collapsing a `rel` (`Metadata: false`) and `abs` (`Metadata: true`) entry for the same file into one `rel` (`Metadata: true`) entry. Tier: **Tier 2**.
  - `TestRelativeExternalIdentitiesStayAbsolute` (`L299-L320`): Witnesses `Relative` keeping external paths as `abs`. Tier: **Tier 2**.
  - `TestRelativeRefusesMovedState` (`L324-L340`): Witnesses `Relative` refusing a state whose file mutated since observation. Tier: **Tier 2**.
  - `TestRelativeRoundTripsWithAbsolute` (`L345-L369`): Witnesses `Absolute` -> `Relative` -> `Absolute` round-trip equality. Redundant with `TestConversionsPreserveMetadataClass` (`L209-L247`) and `TestRelativeIdentitiesTravelAcrossCheckoutRoots` (`L155-L173`). Tier: **Tier 2**.

#### 17. [`runtimeinput/optionorder_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/optionorder_test.go) (15 lines)
- **Tests**:
  - `TestIngestRefusesTheFirstMalformedDeclaration` (`L10-L15`): Single 5-line test checking that passing two invalid `TestLogOption`s returns the first option's error. Should be a 3-line assertion inside `runtimeinput_test.go` or `guardcovered_test.go`. Tier: **Tier 1**.

#### 18. [`runtimeinput/outcome_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/outcome_test.go) (611 lines)
- **Helpers**:
  - `supportedIngest` (`L27-L38`), `outcomeReadFunc` (`L325-L327`).
- **Tests**:
  - `TestProducerRequiresIndependentExecutionPremises` (`L40-L107`): Witnesses `REQ-inputs-producer-premises` across 12 subtests (`supported`, `receipt missing`, `support missing`, `unsupported inventory`, `wrong process`, `wrong environment`, `wrong support process`, `wrong support environment`, `abnormal completion`, `file contradicts inventory`, `exclusion cannot hide contradiction`, `unknown operation`), plus copied vs independent `ProducerFrame` and missing capture paths. Note: calls `frame.Observe` without a shared `Roots` memo in `supportedIngest`, paying `go env -json` subprocesses on subtests that reach root resolution! Tier: **Tier 2 / Tier 3**.
  - `TestOutcomeBindingPreservesEnvironmentBytes` (`L109-L141`): Witnesses raw non-UTF-8 byte distinction (`\xff` vs `\xfe`) in `OutcomeBinding` and `Completion`. Tier: **Tier 2**.
  - `TestOutcomePremiseInputsAndExportedSubjects` (`L143-L175`): Witnesses validation of process names and env slices in `OutcomeBinding` / `Completion`, `completionPremise` invalid binding reason, and defensive cloning of `Outcome.Subjects()`. Tier: **Tier 1 / Tier 2**.
  - `TestIdentityFacadePreservesGuardsWithoutGrantingOutcomes` (`L177-L243`): Witnesses `frame.ObserveInputs` (records path identities without granting `HasOutcomeSupport`, works without `OutcomeSupport`, refuses invalid `Completion`, honors cancellation). Tier: **Tier 2 / Tier 3**.
  - `TestIdentityFacadeDistinguishesCaptureFailureFromUnguardedIdentity` (`L245-L273`): Witnesses `ObserveInputs` completion-disposition `reason` channel vs `obs.Reason` for missing/headerless testlog vs out-of-bracket file read. Tier: **Tier 2 / Tier 3**.
  - `TestScratchRootDeclarationPreservesEnvironmentValues` (`L275-L298`): Witnesses `in.ScratchRoot` eliding `stat <scratch>` while preserving `getenv TMPDIR` value binding. Tier: **Tier 2 / Tier 3**.
  - `TestProducerKeepsOneEnvironmentSnapshot` (`L300-L323`): Witnesses defensive cloning of `in.Env` in `frame.Observe` when `in.Runner.Prepare` mutates the caller's slice. Tier: **Tier 2 / Tier 3**.
  - `TestCaptureCancellationCannotBecomeIncompleteEvidence` (`L329-L364`): Witnesses `captureReader`, `frame.Observe` cancellation via `cancelAfterChecks`, `environmentLog` cancellation, and NUL-path unreadable capture attribution. Overlaps with `producer_boundaries_test.go`. Tier: **Tier 1 / Tier 2**.
  - `FuzzOutcomeBindingRetainsEnvironmentBytes` (`L366-L400`): Fuzz/property test of `frame.OutcomeBinding` injective framing over arbitrary environment strings. Tier: **Tier 1 (Pure Property/Fuzz)**.
  - `TestOutcomeSupportSurvivesWithoutPromotion` (`L402-L470`): Witnesses `HasOutcomeSupport` across `Current`, `Absolute`, `Relative`, `Adopt`, `Merge` (preserved when all contributors are supported or empty, dropped when merged with identity-only or incomplete observation, never promoted by `Adopt`, rejected on v1 manifest). Tier: **Tier 2**.
  - `TestProducerCancellationReachesClosingBracket` (`L472-L496`): Witnesses cancellation during `frame.Observe`'s closing bracket walk using a warmed `Roots` memo and `cancelAfterChecks`. Tier: **Tier 2**.
  - `TestOutcomeManifestRefusesInconsistentSupport` (`L498-L518`): Witnesses `encode`/`decode` refusal of inconsistent `Outcome`/`Subjects`/`Paths` combinations in `manifest`. Tier: **Tier 1 (Pure Wire/Encoding)**.
  - `TestManifestDigestPinsTheWireFold` (`L520-L529`): Pins exact 32-hex `manifestDigest` values for identity-only and outcome-supported manifests. Tier: **Tier 1 (Pure Wire/Encoding)**.
  - `FuzzOutcomeEvidenceMergePreservesSupport` (`L531-L611`): Fuzz/property test of `Merge` commutativity, idempotence, associativity, `BracketMoved` union, and `HasOutcomeSupport` conjunction across 5 observation modes. Overlaps with `FuzzMergeAlgebra` (`runtimeinput_test.go`). Tier: **Tier 1 (Pure Property/Fuzz)**.

#### 19. [`runtimeinput/overlap_membership_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/overlap_membership_test.go) (262 lines)
- **Helpers**:
  - `partialRuntimeWalk` (`L14-L40`), `clonePathFacts` (`L193-L207`).
- **Tests**:
  - `TestOverlappingRootsShareComparableFacts` (`L42-L112`): Witnesses fact comparison across overlapping roots (`["data", "data/p"]`) under 4 scenarios (`appearance`, `knowledge shifts`, `excluded parent`, `captured contradiction`). Tier: **Tier 2 (Hooked FS Fact Comparison)**.
  - `TestPartialListingRetainsPositiveMembership` (`L114-L159`): Witnesses that a partial `readdir` listing still records positive membership for entries it visited, detecting addition/removal across capture and revalidate. Tier: **Tier 2**.
  - `TestCrossRootMembershipKeepsExclusionScope` (`L161-L191`): Witnesses that an unexcluded absolute root's partial listing of `"excluded"` does not collide with a relative root that excluded `"data/excluded"`. Tier: **Tier 2**.
  - `TestFactAccountRetainsContradictionsCanonically` (`L209-L235`): Pure unit test of `pathFacts` canonical hashing (order/duplicate invariance) and contradiction retention in `movedBracketRoot`. Tier: **Tier 1 (Pure Fact Algebra)**.
  - `TestBracketSealBindsMembershipKnowledgeAndScope` (`L237-L262`): Witnesses `b.checkSealed()` against tampering with `listings[dir]` (`complete`, `names`, `offset`). Overlaps with `TestBracketSealBindsFactAvailabilityAndValues` (`partial_motion_linux_test.go:L113-L134`) and `TestBracketSealCoversCaptureListing` (`scratchnamespace_test.go:L316-L336`). Tier: **Tier 2**.

#### 20. [`runtimeinput/partial_motion_linux_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/partial_motion_linux_test.go) (223 lines)
- **Tests**:
  - `TestPartialRootKnownMovement` (`L10-L74`): Witnesses `BracketMoved = true` when a known file mutates alongside a `same-root FIFO`, `external symlink` replacement, `unreadable file` (`chmod 0000`), or `unreadable member`. Tier: **Tier 2**.
  - `TestRootKnowledgeChangeAloneIsNotMovement` (`L76-L111`): Witnesses that losing or regaining search permission (`chmod 0000` / `0700`) on an unbracketed parent directory makes the observation `Unverifiable` without setting `BracketMoved`. Tier: **Tier 2**.
  - `TestBracketSealBindsFactAvailabilityAndValues` (`L113-L134`): Witnesses `b.checkSealed()` when deleting or mutating entries in `b.roots[0].facts.values`. Tier: **Tier 2**.
  - `TestRootNamespaceFactsKeepAbsenceAndDanglingLinksDistinct` (`L136-L165`): Witnesses (1) an absent intermediate directory appearing does not move an absent child root (duplicates `namespace_presence_test.go:L148-L153` and `L188-L221`), and (2) removing a dangling symlink moves the bracket. Tier: **Tier 2**.
  - `TestDirectoryEntryTypeSurvivesUnavailableInfo` (`L167-L223`): Witnesses that in a readable but non-searchable directory (`chmod 0400`, where `ReadDir` succeeds and exposes `DirEntry.Type()` via `d_type` while `DirEntry.Info()` fails with `EACCES`), retyping a file to a directory is still detected as `BracketMoved`. Tier: **Tier 2 (Linux FS)**.

#### 21. [`runtimeinput/premises_property_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/premises_property_test.go) (164 lines)
- **Tests**:
  - `TestProducerPremisesAcrossGeneratedBindings` (`L21-L164`): Property test (`testing/quick`, 20 iterations x 17 modes = 340 observations + `Absolute`/`Relative`/`Adopt` round-trips) witnessing `REQ-inputs-producer-premises` across generated environment values, shuffled env slices, and repeated testlog lines, sharing a single `Roots` memo. Overlapping modes with `TestProducerRequiresIndependentExecutionPremises` in `outcome_test.go`. Tier: **Tier 2 (Property Test with Shared `Roots` Memo)**.

#### 22. [`runtimeinput/producer_boundaries_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/producer_boundaries_test.go) (105 lines)
- **Tests**:
  - `TestIncompleteCaptureHonorsCancellationAtBothBoundaries` (`L14-L25`): Witnesses `frame.incomplete` cancellation via `cancelAfterChecks`. Tier: **Tier 1 / Tier 2**.
  - `TestIncompleteCaptureSkipsAmbientRootLookupWhenCancelled` (`L27-L53`): Self-re-executes test binary with `-test.testlogfile` to verify that a cancelled `(ProducerFrame{}).incomplete` call does not call `os.Getwd()` (which logs `getenv PWD`). Note: a subprocess self-re-exec just to check that `ctx.Err()` is checked before `os.Getwd()` in `incomplete`! Tier: **Tier 3 (Disproportionate Subprocess for Local Guard)**.
  - `TestCaptureReaderDoesNotReadAfterCancellation` (`L55-L64`): Witnesses `captureReader.Read` checking `ctx.Err()` before calling underlying `Reader`. Duplicates `TestCaptureCancellationCannotBecomeIncompleteEvidence` (`outcome_test.go:L329-L341`). Tier: **Tier 1**.
  - `TestReadProducerLogRetainsCaptureFailureAndCancellation` (`L66-L95`): Witnesses `readProducerLog` cancellation and failure reasons (`""`, missing, NUL byte, directory). Duplicates `TestProducerFacadeFailsClosed` (`producer_test.go:L134-L159`) and `TestIdentityFacadeDistinguishesCaptureFailureFromUnguardedIdentity` (`outcome_test.go:L245-L261`). Tier: **Tier 1 / Tier 2**.
  - `TestEnvironmentLogChecksCancellationBeforeScreening` (`L97-L105`): Witnesses `environmentLog` checking `ctx.Err()` at entry. Duplicates `TestCaptureCancellationCannotBecomeIncompleteEvidence` (`outcome_test.go:L354-L357`). Tier: **Tier 1**.

#### 23. [`runtimeinput/producer_close_linux_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/producer_close_linux_test.go) (56 lines)
- **Tests**:
  - `TestReadProducerLogClosesItsFile` (`L11-L56`): Witnesses that `readProducerLog` closes its opened file descriptor across 5 cases (`successful`, `symlinked spelling`, `header rejected`, `read failure`, `cancelled after open`) by scanning `/proc/self/fd`. Belongs with `producer_test.go`. Tier: **Tier 2 (Linux FD check)**.

#### 24. [`runtimeinput/producer_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/producer_test.go) (483 lines)
- **Helpers**:
  - `producerModule` (`L13-L31`), `writeTestlog` (`L33-L40`), `captureGuards` (`L45-L57`), `producerEnv` (`L278-L296`), `manifestOf` (`L300-L311`).
- **Tests**:
  - `TestProducerFacadeMatchesHandAssembly` (`L63-L115`): Witnesses `REQ-inputs-producer-facade` (facade reproduces hand-assembled `FromTestLog` with `.` and `.git` excluded). Tier: **Tier 3 (calls `go env` via `captureGuards`)**.
  - `TestProducerFacadeFailsClosed` (`L120-L206`): Witnesses `REQ-inputs-producer-facade` across 9 fail-closed subtests (`caller health verdict wins`, `missing capture`, `headerless capture`, `capture truncated inside the header line`, `out-of-tree package refuses at capture`, `unreadable capture folds to incomplete`, `ingestion failure folds to incomplete`, `missing PWD`, `parent-inherited PWD`). Tier: **Tier 2 / Tier 3**.
  - `TestProducerFacadeAssemblesDeclarations` (`L213-L238`): Witnesses `ProducerIngest.ScratchRoot` reaching ingest options. Tier: **Tier 3**.
  - `TestProducerFrameResolvesSymlinkedRoot` (`L243-L273`): Witnesses `CaptureProducerFrame` resolving symlinked module root and accepting unresolved symlink `PWD`. Tier: **Tier 3**.
  - `TestProducerFacadeResolvesGuardRootsFromTheEnvironment` (`L316-L376`): Witnesses `REQ-inputs-guard-covered` through `ProducerFrame` (`GOROOT`, `GOMODCACHE`, `GOCACHE`, and in-tree cache rejection). Spawns ~10 `go env` subprocesses because `manifestOf` passes `Roots: nil`. Tier: **Tier 3**.
  - `TestProducerFacadeReportsCancellationAsTheCallersError` (`L383-L401`): Witnesses cancellation at entry and via `producerTestHooks.beforeRoots`. Tier: **Tier 2 / Tier 3**.
  - `TestProducerFacadeResolvesTheTempRootFromTheEnvironment` (`L407-L437`): Witnesses `TMPDIR` resolution and broken `GOTOOLCHAIN` fail-closed handling. Tier: **Tier 3**.
  - `TestProducerFacadeDeclaresTheGoCommandsTempRoot` (`L446-L483`): Witnesses `GOTMPDIR` resolution from env and `GOENV` file, and in-tree `GOTMPDIR` rejection. Tier: **Tier 3**.

#### 25. [`runtimeinput/pwd_history_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/pwd_history_test.go) (73 lines)
- **Tests**:
  - `FuzzHistoricalPWDManifestDoesNotUpgrade` (`L16-L73`): Fuzz test checking that manifests with `Version` 1, 2, or 3 are rejected by `Current`, `Adopt`, `Absolute`, `Relative`, and `Merge` with `"unsupported manifest version"`, and never grant `HasOutcomeSupport`. Belongs with wire/version tests in `runtimeinput_test.go` / `outcome_test.go`. Tier: **Tier 1 (Pure Wire/Property)**.

#### 26. [`runtimeinput/pwd_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/pwd_test.go) (43 lines)
- **Tests**:
  - `FuzzPWDObservationBindsOnlyTheObservedValue` (`L12-L43`): Fuzz test checking that `getenv PWD` binds `PWD` (invariant to `UNREAD` env var changes, moves when `PWD` changes or is unset). Overlaps with `TestPWDAdmitsOnlyWhenPinnedToSpawnDir` (`guardcovered_test.go:L973-L1017`) and `FuzzRuntimeObservationAndPathInvariants` (`runtimeinput_test.go:L1487-L1501`). Tier: **Tier 2 (Property/Fuzz)**.

#### 27. [`runtimeinput/rootsmemo_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/rootsmemo_test.go) (135 lines)
- **Tests**:
  - `TestRootsMemoizeForTheJudgedRun` (`L22-L90`): Installs a counting `#!/bin/sh` wrapper around `go` on `PATH` and verifies that `resolveRoots` with a `&Roots{}` memo spawns `go env -json` once across equivalent `pkgDir` spellings (`dir`, `dir/x/..`, symlink `link`), reversed `env`, and changed `PWD`, spawns again on a new env var or different `pkgDir`, and spawns every time when `memo == nil`. Tier: **Tier 3 (Subprocess Shim)**.
  - `TestProducerIngestReadsItsRootsMemo` (`L95-L135`): Uses the same counting wrapper to verify `frame.Observe` reuses `in.Roots`. Tier: **Tier 3 (Subprocess Shim)**.

#### 28. [`runtimeinput/roots_salvage_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/roots_salvage_test.go) (61 lines)
- **Tests**:
  - `TestRootsProbeServesTheSalvagedAnswer` (`L20-L61`): Witnesses `REQ-fresh-go-command-policy` for `resolveRoots` when a `#!/bin/sh` wrapper around `go` spawns a background `sleep 5 &` holding stdout open past `WaitDelay: 200ms` (salvages complete JSON, refuses torn JSON or banner-prefixed JSON with `exec.ErrWaitDelay`, refuses JSON missing `GOCACHE`). Tier: **Tier 3 (Subprocess Shim + WaitDelay)**.

#### 29. [`runtimeinput/roots_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/roots_test.go) (87 lines)
- **Tests**:
  - `TestUsableGuardRoot` (`L13-L29`): Pure table test of `usableGuardRoot`. Tier: **Tier 1**.
  - `TestUsableGuardRootOutsideTheTree` (`L34-L62`): Table + symlink test of `usableGuardRootOutside`. Tier: **Tier 1 / Tier 2**.
  - `TestUsableTempRoot` (`L66-L87`): Table + symlink test of `usableTempRoot`. Tier: **Tier 1 / Tier 2**.

#### 30. [`runtimeinput/runtimeinput_describe_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/runtimeinput_describe_test.go) (73 lines)
- **Tests**:
  - `TestDescribeDisclosesIdentitySet` (`L13-L73`): Witnesses `REQ-inputs-path-identities` (`Describe` returns `Unverifiable`, `EnvNames`, and materialized `Paths`, and rejects malformed manifest). Tier: **Tier 2**.

#### 31. [`runtimeinput/runtimeinput_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/runtimeinput_test.go) (1,564 lines)
- **Helpers**:
  - `testEntryDigest` (`L21`), `cancelAfterChecks` (`L23-L34`), `testBracket` (`L75-L85`), `testDirs` (`L87-L95`), `rawManifest` (`L210-L217`).
- **Tests**:
  - `TestCurrentHonorsCancellation` (`L36-L47`): Witnesses `Current` pre-cancelled context check. Tier: **Tier 1**.
  - `TestCurrentStopsBetweenInputsAndFileChunks` (`L49-L71`): Witnesses `Current`, `fileHash`, and `dirHashFiltered` cancellation via `cancelAfterChecks`. Tier: **Tier 2**.
  - `TestIncompleteObservationIsDistinctAndMergeable` (`L97-L128`): Witnesses `Incomplete` state properties, merge with empty, and rejection of blank/unsafe reasons. Tier: **Tier 1**.
  - `TestAbsoluteIdentitiesMergeAcrossModuleRoots` (`L130-L168`): Witnesses `Absolute` + `Merge` + `Paths` across two modules. Tier: **Tier 2**.
  - `TestAbsoluteIdentitiesNeverSuppressUnverifiability` (`L170-L208`): Witnesses `Absolute` preserving unverifiability and rejecting moved state. Tier: **Tier 2**.
  - `TestEnvDigestChangesWithoutStoringValue` (`L219-L254`): Witnesses `getenv` digest sensitivity without storing secret value in manifest JSON. Tier: **Tier 2**.
  - `TestCurrentUsesSuppliedEnvironment` (`L256-L285`): Witnesses `Current` using explicit `env` rather than ambient `os.Environ()`. Tier: **Tier 2**.
  - `TestFromTestLogMarksPWDUnverifiable` (`L287-L296`): Witnesses divergent `PWD` marking observation unverifiable. Duplicates `TestPWDAdmitsOnlyWhenPinnedToSpawnDir` (`guardcovered_test.go:L973-L1017`). Tier: **Tier 2**.
  - `TestEnvironmentStateAbsoluteAndMergeUseSuppliedEnvironment` (`L298-L338`): Witnesses `Absolute` and `Merge` checking against supplied `env`. Tier: **Tier 2**.
  - `TestAmbientConstructionWrappersMatchAmbientEnvironment` (`L340-L388`): Tests test-only helpers (`ambientFromTestLog`, `ambientIncomplete`, `ambientAbsolute`, `ambientMerge`) against explicit `os.Environ()` calls! Testing unexported test helpers (`ambient*` in `helpers_test.go`) is pure self-referential test scaffolding. Tier: **Delete / Vestigial Test Helper Test**.
  - `TestFileDigestChanges` (`L390-L414`): Witnesses `open` digest moving on file content edit. Tier: **Tier 2**.
  - `TestOpenFileMetadataMovesDigest` (`L416-L436`): Witnesses `open` digest moving on `os.Chmod`. Tier: **Tier 2**.
  - `TestOpenDirectoryEntryMetadataMovesDigest` (`L438-L462`): Witnesses directory `open` digest moving on child `os.Chmod`. Tier: **Tier 2**.
  - `TestMissingFileAppearanceMovesDigest` (`L464-L481`): Witnesses absent `open` digest moving when file appears. Tier: **Tier 2**.
  - `TestExternalDirectoryIsUnverifiable` (`L483-L503`): Witnesses external directory `open` sealing `external directory`. Tier: **Tier 2**.
  - `TestStatObservationIsUnverifiable` (`L505-L554`): Witnesses uncovered external file `stat` sealing `stat metadata`. Overlaps with `TestExternalDirectoryStatBindsExistence` (`guardcovered_test.go:L1092-L1118`) and `TestBracketNeverWeakensDisposition` (`valuebinding_test.go:L610-L620`). Tier: **Tier 2**.
  - `TestSymlinkDirectoryHashesInternalTarget` (`L556-L587`): Witnesses in-module directory symlink hashing target contents. Tier: **Tier 2**.
  - `TestSymlinkDirectoryToExternalTargetIsUnverifiable` (`L589-L613`): Witnesses in-module symlink to external dir sealing uncovered at construction and `external directory` in `Current`. Overlaps with `TestInModuleRefusedPathSpellsModuleRelative` (`attribution_test.go:L402-L469`). Tier: **Tier 2**.
  - `TestSymlinkFileToExternalTargetIsUnverifiable` (`L615-L646`): Witnesses in-module symlink to external file sealing uncovered at construction and `external runtime input target` in `Current`. Overlaps with `TestInModuleRefusedPathSpellsModuleRelative` (`attribution_test.go:L402-L469`). Tier: **Tier 2**.
  - `TestUnixBackslashPathRemainsV1Compatible` (`L648-L664`): Witnesses Unix filename containing `\` (`a\b`). Tier: **Tier 2**.
  - `TestSymlinkedModuleRootKeepsInternalDirectoryVerifiable` (`L666-L689`): Witnesses `FromTestLog` when `moduleDir` is a symlink. Tier: **Tier 2**.
  - `TestChdirResolvesRelativePaths` (`L691-L723`): Witnesses `chdir sub` + `open fixture.txt` tracking target file and recording both `working-directory change` and `relative runtime input after working-directory change`. Tier: **Tier 2**.
  - `TestCongruentParentTraversalResolvesLexically` (`L731-L753`): Witnesses `REQ-inputs-path-congruence` (`open ../fixture.txt` across real dir is verifiable). Covered also by `FuzzRuntimeObservationAndPathInvariants` (`L1445-L1453`). Tier: **Tier 2**.
  - `TestTraversalVerificationFailuresStaySealed` (`L758-L775`): Witnesses `REQ-inputs-path-congruence` (`open fixture.txt/../fixture.txt` and `open gone/../fixture.txt` seal `ambiguous parent traversal`). Tier: **Tier 2**.
  - `TestVolatileTraversalRefusesWithoutProbing` (`L780-L797`): Witnesses `open /proc/self/../environ` refusing without calling `congruenceProbe`. Tier: **Tier 2**.
  - `TestSymlinkedWorkingDirectoryTraversalIsUnverifiable` (`L803-L819`): Witnesses `open ../fixture.txt` from a symlinked `packageDir` sealing `ambiguous parent traversal`. Tier: **Tier 2**.
  - `TestSymlinkParentTraversalIsUnverifiable` (`L821-L834`): Witnesses `open link/../fixture.txt` sealing `ambiguous parent traversal`. Covered also by `FuzzRuntimeObservationAndPathInvariants` (`L1457-L1464`). Tier: **Tier 2**.
  - `TestAbsolutePathAfterChdirDoesNotAcquireRelativeDisposition` (`L836-L855`): Witnesses `chdir .` followed by absolute `open` not recording `relative runtime input after working-directory change`. Tier: **Tier 2**.
  - `TestCurrentRejectsRelativePathTraversal` (`L857-L863`): Witnesses `Current` rejecting `../secret.txt` in manifest. Tier: **Tier 1**.
  - `TestCurrentRejectsMalformedManifestIdentities` (`L865-L877`): Witnesses `Current` rejecting `\n` in env/path and relative path with `Kind: pathAbs`. Tier: **Tier 1**.
  - `TestModuleRelPaths` (`L879-L907`): Witnesses `ModuleRelPaths` returning only `pathRel` entries. Tier: **Tier 1**.
  - `TestPathsMaterializesRelativeAndExternalIdentities` (`L909-L932`): Witnesses `Paths` materializing `pathAbs` and `pathRel` entries. Tier: **Tier 1**.
  - `TestMergeUnionsIndependentProcessManifests` (`L934-L985`): Witnesses `Merge` unioning env, paths, and unverifiable reasons from two processes. Tier: **Tier 2**.
  - `TestCompletedObservationRequiresProcessAssertion` (`L987-L997`): Witnesses `FromTestLog` requiring valid `WithCompletedProcess`. Tier: **Tier 1**.
  - `TestCompletedObservationRetainsMalformedRecords` (`L999-L1020`): Witnesses `FromTestLog` marking unknown header, blank line, partial line, `\r\n`, and >64KB line as `Unverifiable`. Tier: **Tier 1 / Tier 2**.
  - `TestMergeRejectsConflictingEvidenceForOneProcess` (`L1022-L1035`): Witnesses `Merge` rejecting conflicting observations for the same process ID. Tier: **Tier 2**.
  - `TestProducerOperationsRejectRecomputedState` (`L1037-L1061`): Witnesses `Merge` and `Absolute` rejecting unsealed or transplanted `State`. Tier: **Tier 2**.
  - `TestMergeRejectsRelativeAndAbsoluteEvidenceForOneProcess` (`L1063-L1083`): Witnesses `Merge` rejecting pre- and post-`Absolute` observations of the same process, and `Absolute` idempotence. Tier: **Tier 2**.
  - `TestAbsolutePreservesCompletedVersusIncompleteOrigin` (`L1085-L1109`): Witnesses `Absolute` preserving completed vs incomplete provenance. Tier: **Tier 2**.
  - `TestAbsoluteProcessViewIgnoresUnrelatedMergedProcesses` (`L1111-L1141`): Witnesses `Merge(Absolute(Merge(a, b)), Absolute(a))` succeeding. Tier: **Tier 2**.
  - `TestMergeAlgebra` (`L1143-L1176`): Example test of `Merge` commutativity, idempotence, associativity. Completely subsumed by `FuzzMergeAlgebra` (`L1294-L1383`) and `FuzzOutcomeEvidenceMergePreservesSupport` (`outcome_test.go:L531-L611`). Tier: **Tier 1 (Redundant Example)**.
  - `TestMergeZeroIsExplicitEmptyManifest` (`L1178-L1198`): Witnesses 0-arg `Merge` returning valid empty manifest and rejecting `Observation{}`. Tier: **Tier 1**.
  - `TestMergeRejectsChildThatMovedBeforeUnion` (`L1200-L1215`): Witnesses `Merge` rejecting observations recorded under different values of an env var. Tier: **Tier 2**.
  - `TestMergeRejectsMalformedAndUnsupportedManifest` (`L1217-L1232`): Witnesses `Merge` rejecting unknown fields or v1 manifest. Tier: **Tier 1**.
  - `TestManifestEncodingIsCanonical` (`L1234-L1253`): Witnesses `encode` sorting and deduplicating `Env`, `Paths`, and `Unverifiable`. Tier: **Tier 1**.
  - `TestManifestDecoderRejectsUnknownAndTrailingData` (`L1255-L1268`): Witnesses `decode` rejecting unknown JSON fields, trailing JSON, duplicate keys, wrong case. Tier: **Tier 1**.
  - `TestNonUTF8ObservedPathIsUnverifiable` (`L1270-L1292`): Witnesses `open \xff` marking state unverifiable with quoted attribution. Tier: **Tier 2**.
  - `FuzzMergeAlgebra` (`L1294-L1383`): Fuzz/property test of `Merge` commutativity, idempotence, associativity, unverifiable-reason preservation, and unsealed-observation rejection. Tier: **Tier 1 (Property/Fuzz)**.
  - `FuzzRuntimeObservationAndPathInvariants` (`L1385-L1563`): Comprehensive fuzz/property test covering `FromTestLog`, congruent vs symlink `..` traversal, `Current`, `AdoptContext`, `MergeContext`, env sensitivity, unverifiable ops (`chdir`, escaping `..`, unknown op), `IncompleteContext`, `CompletedState`, `HasOutcomeSupport`, and `ProducerFrame.Completion`. Tier: **Tier 2 (Property/Fuzz)**.

#### 32. [`runtimeinput/scratchnamespace_matcher_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/scratchnamespace_matcher_test.go) (238 lines)
- **Helpers**:
  - `scratchMatcherHostRoot` (`L15-L22`).
- **Tests**:
  - `TestScratchNamespaceMatchesPath` (`L24-L61`): Table test of `(ScratchNamespace).MatchesPath` across 23 cases. Duplicates `TestScratchNamespaceMatching` in `scratchnamespace_test.go` (`L458-L488`). Tier: **Tier 1**.
  - `TestScratchNamespaceMatchesPathAgreement` (`L65-L113`): `testing/quick` property test (1,000 iterations) verifying `(ScratchNamespace).MatchesPath` agrees with internal `cfg.scratchNamespaces[0].matches(id)`. Tier: **Tier 1 (Property)**.
  - `TestScratchNamespaceMatchesPathMkdirTemp` (`L115-L135`): Verifies `(ScratchNamespace).MatchesPath` matches real `os.MkdirTemp` directories across 5 patterns. Tier: **Tier 2**.
  - `TestScratchNamespaceMatchesPathRejectsMalformed` (`L137-L166`): Verifies agreement of `MatchesPath`, `WithScratchNamespace`, and `ValidateScratchNamespace` on 16 malformed declarations + 16 malformed identities. Subsumes `TestScratchNamespaceRejectsMalformedDeclarations` (`scratchnamespace_test.go:L492-L508`) and `TestValidateScratchNamespaceMatchesOptionValidation` (`scratchnamespace_test.go:L514-L545`). Tier: **Tier 1**.
  - `TestScratchNamespaceMatchesPathDoesNotResolve` (`L171-L201`): Verifies `MatchesPath` is purely syntactic and never triggers `producerTestHooks.beforeRoots` or depends on whether the path exists/is a symlink. Tier: **Tier 1 / Tier 2**.
  - `FuzzScratchNamespaceMatchesPath` (`L205-L238`): Fuzz test verifying `MatchesPath` agrees with `WithScratchNamespace` + `validateManifest` + internal `matches`. Tier: **Tier 1 (Property/Fuzz)**.

#### 33. [`runtimeinput/scratchnamespace_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/scratchnamespace_test.go) (545 lines)
- **Tests**:
  - `TestScratchNamespaceAdmitsEndpointAbsentReads` (`L15-L38`): Witnesses `REQ-inputs-scratch-namespace` (absent at capture + absent at ingest -> elided). Tier: **Tier 2**.
  - `TestScratchNamespacePreservesAbsenceProbesOutsideIt` (`L44-L70`): Witnesses `REQ-inputs-scratch-namespace` (absent read outside namespace stays recorded and moves when file appears). Tier: **Tier 2**.
  - `TestScratchNamespacePreExistingMatchStaysObserved` (`L75-L98`): Witnesses `REQ-inputs-scratch-namespace` (pre-existing file matching pattern is vetoed by capture membership and stays observed). Tier: **Tier 2**.
  - `TestScratchNamespaceSurvivingScratchStaysObserved` (`L104-L130`): Witnesses `REQ-inputs-scratch-namespace` (scratch surviving at ingest stays observed and moves the bracket). Tier: **Tier 2**.
  - `TestScratchNamespaceConsumedAndRemovedSealsBracket` (`L136-L165`): Witnesses `REQ-inputs-scratch-namespace` (pre-existing matching dir removed during run stays observed and moves the bracket). Tier: **Tier 2**.
  - `TestScratchNamespaceInertWithoutBracketCoverage` (`L170-L190`): Witnesses `REQ-inputs-scratch-namespace` (namespace outside declared bracket roots is inert). Tier: **Tier 2**.
  - `TestScratchNamespaceExcludedSubtreeAliasStaysSealed` (`L197-L232`): Witnesses `REQ-inputs-scratch-namespace` (pre-existing matching symlink into bracket-excluded subtree is vetoed by capture membership). Tier: **Tier 2**.
  - `TestScratchNamespacePreExistingMatchVetoesDepth` (`L238-L257`): Witnesses `REQ-inputs-scratch-namespace` (absent read beneath pre-existing matching directory is vetoed and stays observed). Tier: **Tier 2**.
  - `TestScratchNamespaceUnderBracketExclusionAdmitsNothing` (`L262-L285`): Witnesses `REQ-inputs-scratch-namespace` (namespace under a bracket-excluded dir is inert). Tier: **Tier 2**.
  - `TestScratchNamespaceDanglingLinkAncestorStaysObserved` (`L291-L310`): Witnesses `REQ-inputs-scratch-namespace` (dangling symlink ancestor refuses scratch admission). Tier: **Tier 2**.
  - `TestBracketSealCoversCaptureListing` (`L316-L336`): Witnesses `b.checkSealed()` and `sealBracket` framing on `roots[0].members`. Belongs with bracket seal tests in `bracket_test.go`. Tier: **Tier 1 / Tier 2**.
  - `TestRecordedDirectoryDigestSharesCarveOut` (`L342-L383`): Witnesses that a recorded directory `open` digest ignores membership-restored churn inside the directory but moves on `os.Chmod`. Belongs in `bracket_test.go` / `runtimeinput_test.go`. Tier: **Tier 2**.
  - `TestScratchNamespaceEscapingLinkStaysObserved` (`L390-L410`): Witnesses `REQ-inputs-scratch-namespace` (absent leaf under symlink escaping bracket root stays observed). Tier: **Tier 2**.
  - `TestBracketToleratesRestoredChurnButNotModeChange` (`L417-L452`): Witnesses `bracket.revalidate` ignoring membership-restored churn while moving on `os.Chmod`. Belongs in `bracket_test.go`. Tier: **Tier 2**.
  - `TestScratchNamespaceMatching` (`L458-L488`): Pure table test of `cfg.scratchNamespaces[0].matches`. Duplicated and superseded by `scratchnamespace_matcher_test.go` (`TestScratchNamespaceMatchesPath` and `TestScratchNamespaceMatchesPathAgreement`). Tier: **Tier 1 (Redundant)**.
  - `TestScratchNamespaceRejectsMalformedDeclarations` (`L492-L508`): Table test of `WithScratchNamespace` errors. Duplicated and superseded by `TestScratchNamespaceMatchesPathRejectsMalformed` (`scratchnamespace_matcher_test.go:L137-L166`). Tier: **Tier 1 (Redundant)**.
  - `TestValidateScratchNamespaceMatchesOptionValidation` (`L514-L545`): Table test comparing `ValidateScratchNamespace` and `WithScratchNamespace`. Duplicated and superseded by `TestScratchNamespaceMatchesPathRejectsMalformed` (`scratchnamespace_matcher_test.go:L137-L166`). Tier: **Tier 1 (Redundant)**.

#### 34. [`runtimeinput/valuebinding_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/runtimeinput/valuebinding_test.go) (654 lines)
- **Helpers**:
  - `bindingModule` (`L14-L24`), `manifestReasons` (`L28-L35`), `bindingReasonObservations` (`L490-L521`).
- **Tests**:
  - `TestCompletedObservationRequiresBracket` (`L42-L62`): Witnesses `REQ-inputs-completed-observation` (missing, zero, foreign, or duplicate bracket rejected; `Incomplete` needs no bracket). Tier: **Tier 2**.
  - `TestRunToIngestWindowMutationSealsObservationUnverifiable` (`L69-L110`): Witnesses `REQ-inputs-value-binding` (mutation between bracket capture and `FromTestLog` seals `observation bracket moved: data`, preserved by `Current`, `Merge`, `Absolute`). Overlaps with `TestBracketMovementSurvivesComposition` (`bracket_motion_test.go:L15-L84`). Tier: **Tier 2**.
  - `TestSymlinkTargetMutationOutsideRootSealsIdentityUncovered` (`L118-L159`): Witnesses `REQ-inputs-value-binding` (in-root symlink resolving outside declared root seals `runtime input not covered by observation bracket`). Tier: **Tier 2**.
  - `TestOutOfRootSymlinkChainSealsIdentityUncovered` (`L168-L219`): Witnesses `REQ-inputs-value-binding` (symlink outside declared root pointing into declared root seals `symlink outside every bracket root`). Tier: **Tier 2**.
  - `TestInRootSymlinkChainStaysCoveredAndRetargetMovesBracket` (`L225-L255`): Witnesses `REQ-inputs-value-binding` (within-root symlink to within-root target is covered and retargeting moves bracket). Tier: **Tier 2**.
  - `TestCoveredObservationBindsAsBefore` (`L261-L275`): Witnesses happy-path covered `open` (existing and absent). Tier: **Tier 2**.
  - `TestOutOfRootReadSealsPerIdentityUncovered` (`L281-L305`): Witnesses per-identity uncovered reason alongside covered sibling. Tier: **Tier 2**.
  - `TestExcludedIdentityObservedIsUncovered` (`L311-L349`): Witnesses `WithBracketExcludedPaths` making direct and symlinked reads into excluded subtree uncovered. Tier: **Tier 2**.
  - `TestBracketCaptureRefusalSealsObservationUnverifiable` (`L355-L372`): Witnesses capture-unverifiable bracket propagating `observation bracket unverifiable: ...` to observation. Tier: **Tier 2**.
  - `TestAbsoluteIdentityCoverageRequiresAbsoluteRoot` (`L377-L412`): Witnesses absolute path requiring declared absolute bracket root (and lexical-then-resolved containment). Tier: **Tier 2**.
  - `TestAbsoluteRootThroughSymlinkedPrefixStaysCovered` (`L420-L442`): Witnesses absolute root behind symlinked prefix (`base/alias/ext.txt`) staying covered. Tier: **Tier 2**.
  - `TestAbsoluteIdentitySubRootChainStaysEnforced` (`L449-L482`): Witnesses symlink hop under an absolute root traversing an unbracketed intermediate symlink sealing `symlink outside every bracket root`. Tier: **Tier 2**.
  - `TestBindingReasonsSurviveMergeUnion` (`L530-L570`): Witnesses `Merge` preserving moved-bracket and uncovered-identity reasons. Subsumed by `FuzzMergeAlgebra` (`runtimeinput_test.go:L1294-L1383`) and `TestBracketMovementSurvivesComposition` (`bracket_motion_test.go`). Tier: **Tier 2**.
  - `TestBindingReasonsSurviveAbsoluteConversion` (`L577-L601`): Witnesses `Absolute` preserving moved-bracket and uncovered-identity reasons. Tier: **Tier 2**.
  - `TestBracketNeverWeakensDisposition` (`L610-L654`): Witnesses out-of-root `stat` keeping `stat metadata input`, in-root `stat` (file and root dir) being admitted without seal, and bracket-excluded `stat` keeping `stat metadata input`. Duplicates `TestModuleRootBracketCoversInteriorStats` (`bracket_module_root_stat_test.go:L16-L83`). Tier: **Tier 2**.

---

### 1.2 Architectural Critique of `runtimeinput/*_test.go`

#### Finding 1: Append-Only Per-Ticket Test File Proliferation (34 files for 1 package)
Instead of organizing tests by the package's domain layers, historical bug fixes and spec clauses each spawned a bespoke `*_test.go` file:
- **11 tiny single-topic files (< 150 lines each)**:
  - `optionorder_test.go` (15 lines, 1 test)
  - `bracket_motion_linux_test.go` (37 lines, 1 test)
  - `pwd_test.go` (43 lines, 1 fuzz test)
  - `helpers_test.go` (44 lines, thin `ambient*` wrappers)
  - `directory_fact_identity_test.go` (47 lines, 1 test)
  - `producer_close_linux_test.go` (56 lines, 1 test)
  - `roots_salvage_test.go` (61 lines, 1 test)
  - `pwd_history_test.go` (73 lines, 1 fuzz test)
  - `runtimeinput_describe_test.go` (73 lines, 1 test)
  - `bracket_module_root_stat_test.go` (83 lines, 1 test)
  - `roots_test.go` (87 lines, 3 unit tests)
  - `producer_boundaries_test.go` (105 lines, 5 tests)
  - `attribution_unix_test.go` (116 lines, 1 test)
  - `rootsmemo_test.go` (135 lines, 2 tests)

#### Finding 2: Concrete Cross-File Overlaps and Duplications
1. **Bracket Capture, Movement, Facts, and Sealing split across 9 files**:
   - `bracket_test.go`, `bracket_motion_test.go`, `bracket_motion_linux_test.go`, `bracket_module_root_stat_test.go`, `valuebinding_test.go`, `directory_fact_identity_test.go`, `namespace_presence_test.go`, `overlap_membership_test.go`, and `partial_motion_linux_test.go` all test the exact same `Bracket` / `pathFacts` / `movedBracketRoot` / `checkSealed` / `FromTestLog(..., WithBracket(b))` subsystem.
   - `TestModuleRootBracketCoversInteriorStats` (`bracket_module_root_stat_test.go:L16-L83`) tests the exact same invariant (covered interior `stat` binds metadata digest; `WithBracketExcludedPaths` `stat` seals `stat metadata input`) as `TestBracketNeverWeakensDisposition` (`valuebinding_test.go:L610-L654`).
   - `TestBracketMovementSurvivesComposition` (`bracket_motion_test.go:L15-L84`), `TestRunToIngestWindowMutationSealsObservationUnverifiable` (`valuebinding_test.go:L69-L110`), `TestBindingReasonsSurviveMergeUnion` (`valuebinding_test.go:L530-L570`), and `TestBindingReasonsSurviveAbsoluteConversion` (`valuebinding_test.go:L577-L601`) all test the same composition preservation of moved-bracket observations across `Current`, `Merge`, `Absolute`, `Relative`, and `Adopt`.
   - `TestBracketSealBindsMembershipKnowledgeAndScope` (`overlap_membership_test.go:L237-L262`), `TestBracketSealBindsFactAvailabilityAndValues` (`partial_motion_linux_test.go:L113-L134`), `TestBracketSealCoversCaptureListing` (`scratchnamespace_test.go:L316-L336`), and `TestMachineProjectionKeepsRootScopeAndSeal` (`machine_motion_linux_test.go:L125-L163`) all test `Bracket.checkSealed()` tampering one field at a time across 4 separate files.
   - `TestMissingAncestorAppearanceDoesNotInventResolutionDrift` (`namespace_presence_test.go:L188-L221`), `TestResolvedAbsenceRequiresTheFinalComponent` (`namespace_presence_test.go:L134-L153`), and `TestRootNamespaceFactsKeepAbsenceAndDanglingLinksDistinct` (`partial_motion_linux_test.go:L136-L146`) all test the exact same scenario: an absent intermediate directory appearing does not move a still-absent child bracket root.
2. **Scratch Namespace Matching Duplicated Across `scratchnamespace_test.go` and `scratchnamespace_matcher_test.go`**:
   - `TestScratchNamespaceMatching` (`scratchnamespace_test.go:L458-L488`), `TestScratchNamespaceRejectsMalformedDeclarations` (`L492-L508`), and `TestValidateScratchNamespaceMatchesOptionValidation` (`L514-L545`) are 100% subsumed by `TestScratchNamespaceMatchesPath`, `TestScratchNamespaceMatchesPathAgreement`, `TestScratchNamespaceMatchesPathRejectsMalformed`, and `FuzzScratchNamespaceMatchesPath` in `scratchnamespace_matcher_test.go`.
   - Furthermore, `TestBracketSealCoversCaptureListing` (`scratchnamespace_test.go:L316-L336`), `TestRecordedDirectoryDigestSharesCarveOut` (`L342-L383`), and `TestBracketToleratesRestoredChurnButNotModeChange` (`L417-L452`) are not even scratch-namespace tests — they are directory-digest and bracket-seal tests parked in `scratchnamespace_test.go` because they were added in the same commit.
3. **Producer Facade, Outcome Premises, and Boundaries Split Across 5 Files**:
   - `producer_test.go`, `outcome_test.go`, `premises_property_test.go`, `producer_boundaries_test.go`, and `producer_close_linux_test.go` all test `ProducerFrame` (`CaptureProducerFrame`, `Observe`, `ObserveInputs`, `Completion`, `OutcomeBinding`, `readProducerLog`, `captureReader`, `environmentLog`).
   - `TestCaptureReaderDoesNotReadAfterCancellation` (`producer_boundaries_test.go:L55-L64`) and `TestEnvironmentLogChecksCancellationBeforeScreening` (`producer_boundaries_test.go:L97-L105`) duplicate `TestCaptureCancellationCannotBecomeIncompleteEvidence` (`outcome_test.go:L329-L364`).
   - `TestReadProducerLogRetainsCaptureFailureAndCancellation` (`producer_boundaries_test.go:L66-L95`), `TestIdentityFacadeDistinguishesCaptureFailureFromUnguardedIdentity` (`outcome_test.go:L245-L273`), and `TestProducerFacadeFailsClosed` (`producer_test.go:L120-L206`) test the same missing/empty/headerless/directory testlog capture failure paths three times.
4. **Manifest Wire Encoding, Version Rejection, and Merge Algebra Split Across 5 Files**:
   - `runtimeinput_test.go`, `movedinputs_test.go`, `adopt_test.go`, `outcome_test.go`, `bracket_motion_test.go`, and `pwd_history_test.go` all test manifest JSON wire validation, v1/v2/v3 version refusal, and `Merge` algebra.
   - `TestMergeAlgebra` (`runtimeinput_test.go:L1143-L1176`) is a fixed 3-element example test of `Merge` commutativity/idempotence/associativity that sits right above `FuzzMergeAlgebra` (`L1294-L1383`) and alongside `FuzzOutcomeEvidenceMergePreservesSupport` (`outcome_test.go:L531-L611`).
5. **Unnecessary `go env -json` Subprocess Invocations in `file_eligibility_test.go`, `producer_test.go`, and `outcome_test.go`**:
   - `TestProducerFacadeResolvesGuardRootsFromTheEnvironment` (`producer_test.go:L316-L376`), `TestFileInputEligibilityRefusesProjectedAndUnsupported` (`file_eligibility_test.go:L241-L300`), and `TestFileInputEligibilityExclusionPrecedence` (`file_eligibility_test.go:L302-L332`) omit `Roots: memo` when calling `FileInputEligibility` or `captureGuards` in loops over identical environments, spawning dozens of redundant `go env -json` child processes for purely local path-classification checks.
6. **Self-Referential Test Helper Test**:
   - `TestAmbientConstructionWrappersMatchAmbientEnvironment` (`runtimeinput_test.go:L340-L388`) exists solely to test the test-only `ambient*` functions in `helpers_test.go`.

#### Finding 3: Target Consolidation Architecture for `runtimeinput` (34 files -> 6 files)
Consolidate all 34 test files into 6 cohesive, tier-structured files aligned with the package's domain boundaries:
1. **`runtimeinput/manifest_algebra_test.go`** (Tier 1 — Pure Wire Encoding, Manifest Version/Digest Validation, `Merge` / `Adopt` / `Absolute` / `Relative` / `Describe` / `MovedInputs` Algebra):
   - Consolidates `adopt_test.go`, `movedinputs_test.go`, `runtimeinput_describe_test.go`, `pwd_history_test.go`, `observationclass_test.go`, and the manifest/merge/conversion sections of `runtimeinput_test.go` and `bracket_motion_test.go`.
2. **`runtimeinput/classification_test.go`** (Tier 1 & Tier 2 — Testlog Ingestion, Path Congruence, Exclusions, Guard-Covered Roots, Ephemeral/Scratch Namespaces, `PWD`, and Refusal Attribution):
   - Consolidates `guardcovered_test.go`, `exclusions_test.go`, `scratchnamespace_test.go`, `scratchnamespace_matcher_test.go`, `attribution_test.go`, `attribution_unix_test.go`, `pwd_test.go`, `optionorder_test.go`, `roots_test.go`, and the path-classification/traversal sections of `runtimeinput_test.go`.
3. **`runtimeinput/bracket_test.go`** (Tier 1 & Tier 2 — Bracket Capture, Revalidation, Value Binding, Symlink Coverage, and Hooked FS Fact Comparison):
   - Consolidates `bracket_test.go`, `valuebinding_test.go`, `bracket_motion_test.go`, `bracket_module_root_stat_test.go`, `directory_fact_identity_test.go`, `namespace_presence_test.go`, `overlap_membership_test.go`.
4. **`runtimeinput/bracket_linux_test.go`** (Tier 2 — Linux-Specific FIFO/Permission/Machine-Projection Bracket Tests):
   - Consolidates `bracket_motion_linux_test.go`, `partial_motion_linux_test.go`, `machine_motion_linux_test.go`.
5. **`runtimeinput/producer_test.go`** (Tier 2 & Tier 3 — `ProducerFrame`, Execution Premises, `OutcomeSupport`, `Roots` Memo & Salvage, and `FileInputEligibility`):
   - Consolidates `producer_test.go`, `outcome_test.go`, `premises_property_test.go`, `producer_boundaries_test.go`, `producer_close_linux_test.go`, `rootsmemo_test.go`, `roots_salvage_test.go`, and `file_eligibility_test.go` (passing a shared `&Roots{}` memo wherever `go env` resolution itself is not the subject under test).
6. **`runtimeinput/helpers_test.go`** (Shared Test Fixtures & Builders):
   - Retains shared builders (`testDirs`, `testBracket`, `bindingModule`, `producerModule`, `cancelAfterChecks`), removing `TestAmbientConstructionWrappersMatchAmbientEnvironment`.

---
## Part 2: `gotool` Test Suite Audit (16 files, 1,948 lines)

### 2.1 File-by-File and Test-by-Test Inventory

#### 1. [`gotool/contain_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/contain_test.go) (413 lines)
- **Helpers**:
  - `processIsLive` (`L16-L35`): Checks `/proc/<pid>/stat` (Linux) or `syscall.Kill(pid, 0)` for non-zombie liveness.
  - `countGoEnvSpawns` (`L287-L287`): Inline counter inside `TestEnvReaderTakesOneSnapshot`.
- **Tests**:
  - `TestContainmentSweepsProcessGroupOnCancel` (`L41-L91`): Spawns `/bin/sh -c "sleep 30 & echo $!; wait"` via `Runner{Containment: &Containment{GracePeriod: 50ms}}`, cancels context, verifies grandchild is killed. Witnesses `REQ-gotool-containment`. Setup weight: **Heavy (`/bin/sh` + `sleep` subprocess + 100ms polling loop)**. Tier: **Tier 3 (Subprocess / OS Containment)**.
  - `TestContainmentQuitOnSignalSendsSIGQUITToGroup` (`L95-L124`): Spawns `/bin/sh` with `trap 'echo GOT_QUIT; exit 0' QUIT`, cancels context with `QuitOn`, verifies `GOT_QUIT` in stderr. Witnesses `REQ-gotool-containment`. Setup weight: **Heavy (`/bin/sh` subprocess)**. Tier: **Tier 3**.
  - `TestContainmentSweepsGrandchildAfterLeaderExits` (`L128-L162`): Spawns `/bin/sh -c "sleep 30 >/dev/null 2>&1 </dev/null & echo $!; exit 0"` and verifies `Run` sweeps the surviving background grandchild on normal leader exit. Witnesses `REQ-gotool-containment`. Setup weight: **Heavy (`/bin/sh` + `sleep` subprocess)**. Tier: **Tier 3**.
  - `TestContainmentSweepsStoppedDescendantOnNormalExit` (`L166-L204`): Spawns a background `sleep 30`, sends `SIGSTOP` to it before leader exits, verifies `SIGCONT`+`SIGKILL` sweep kills stopped descendant. Witnesses `REQ-gotool-containment`. Setup weight: **Heavy (`/bin/sh` + `sleep` subprocess)**. Tier: **Tier 3**.
  - `TestWaitDelayBoundsPipeHolderAfterLeaderExits` (`L210-L230`): Spawns `/bin/sh -c "sleep 30 & exit 0"` with `WaitDelay: 150ms` (no `Containment`), verifies `Run` returns within 5s with `WaitDelay` error. Setup weight: **Heavy (`/bin/sh` + `sleep` subprocess)**. Tier: **Tier 3**.
  - `TestSamplerMemoizesByCoordinateAndNeverACancellation` (`L235-L285`): Tests `NewSampler` memoization by `(canonicalDir, normalizedEnv)`, error non-memoization, and distinct `GOWORK` coordinates. Witnesses `REQ-gotool-env-memo`. **Misplaced in `contain_test.go`** — belongs with `samplermemo_test.go` / `memo_test.go`. Setup weight: **Medium (`Runner.Prepare` counter + `go env -json` subprocess)**. Tier: **Tier 2 / Tier 3**.
  - `TestEnvReaderTakesOneSnapshot` (`L289-L306`): Tests `EnvReader.Value` + `Values` taking only 1 `go env -json` snapshot. **Misplaced in `contain_test.go`** — belongs with `reader_test.go` / `primed_test.go`. Setup weight: **Medium (1 `go env -json` subprocess)**. Tier: **Tier 2 / Tier 3**.
  - `TestWaitDelaySalvagesCompleteJSONWhenBackgroundChildHoldsStdout` (`L312-L343`): Spawns fake `go` script (`sleep 30 & printf '{"GOROOT":"/fake/goroot"}\n'`) and verifies `TakeEnvSnapshot` salvages complete JSON after `exec.ErrWaitDelay`. Setup weight: **Heavy (fake `go` shell script + `sleep` subprocess + `WaitDelay`)**. Tier: **Tier 3**.
  - `TestWaitDelayRejectsTruncatedJSONWhenBackgroundChildHoldsStdout` (`L347-L377`): Same fake `go` script printing truncated `{"GOROOT":`, verifying `TakeEnvSnapshot` returns an error. Setup weight: **Heavy (fake `go` shell script + `sleep` subprocess)**. Tier: **Tier 3**.
  - `TestWaitDelaySalvagesGoVersionWhenBackgroundChildHoldsStdout` (`L381-L413`): Same fake `go` script for `go version`, verifying `GoVersion` salvages valid output and rejects non-zero exit (`exit 2`). Setup weight: **Heavy (2 fake `go` shell scripts + `sleep` subprocesses)**. Tier: **Tier 3**.

#### 2. [`gotool/env_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/env_test.go) (121 lines)
- **Tests**:
  - `TestNormalizeEnvCanonicalizesOrderAndPreservesValues` (`L10-L33`): Pure test of `NormalizeEnv` sorting, `GOENV=off` injection, and explicit `GOENV` preservation. Tier: **Tier 1 (Pure)**.
  - `TestNormalizeEnvRejectsInvalidFrames` (`L35-L53`): Pure table test of `NormalizeEnv` rejecting missing `=`, empty key, NUL in key/value, and duplicate keys. Tier: **Tier 1 (Pure)**.
  - `FuzzNormalizeEnvDeterminism` (`L55-L121`): Fuzz test verifying `NormalizeEnv` rejects invalid entries, is invariant under permutation, idempotent, and collision-free under `WriteNormalizedEnvFrame`. Tier: **Tier 1 (Property/Fuzz)**.

#### 3. [`gotool/finish_linux_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/finish_linux_test.go) (302 lines)
- **Tests**:
  - `TestCommandHoldsLeaderUntilEveryCollectedDescendantExits` (`L28-L108`): Spawns `/bin/sh` with a double-forked grandchild that outlives the leader by 250ms under `Containment{GracePeriod: 2s}`, asserting `cmd.Wait()` blocks until the grandchild is reaped and `collectedDescendantTerminated` holds. Witnesses `REQ-gotool-containment`. Setup weight: **Heavy (`/bin/sh` + `sleep` subprocesses)**. Tier: **Tier 3 (Linux OS Containment)**.
  - `TestCommandSweepsWhenGraceExpiresOnHeldDescendant` (`L115-L154`): Verifies `GracePeriod: 150ms` kills a `sleep 30` grandchild that ignores `SIGTERM`. Setup weight: **Heavy (`/bin/sh` + `sleep` subprocess)**. Tier: **Tier 3**.
  - `TestCommandReapsLeaderWhileStoppedDescendantIsSwept` (`L162-L207`): Spawns a stopped grandchild (`kill -STOP`), cancels context after leader exits, verifies `SIGCONT`+sweep terminates the stopped grandchild and `Wait` returns. Setup weight: **Heavy (`/bin/sh` + `sleep` subprocess)**. Tier: **Tier 3**.
  - `TestWaitidHoldAppliesOnlyUnderContainment` (`L215-L246`): Verifies `waitidHoldApplicable` returns false when `Containment == nil`, `SysProcAttr == nil`, or `Setpgid == false`, and true for a Runner-prepared contained command. Setup weight: **Pure / In-Memory (`exec.Command` struct inspection, no `.Run()`)**. Tier: **Tier 1 (Pure)**.
  - `TestCommandHoldsGroupIdentityAcrossLeaderWaitUntilKillCompletes` (`L255-L302`): Verifies `holdLeaderZombie` (`waitid(P_PID, pid, WEXITED|WNOWAIT)`) keeps the leader as a `Z` zombie in `/proc/<pid>/stat` during `afterHoldBeforeSweep` hook so PGID cannot be recycled before `kill(-pgid, SIGKILL)`, then reaps it. Witnesses `REQ-gotool-containment`. Setup weight: **Heavy (`/bin/sh` subprocess + `/proc` inspection)**. Tier: **Tier 3 (Linux OS Containment)**.

#### 4. [`gotool/finish_observer_linux_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/finish_observer_linux_test.go) (63 lines)
- **Helpers**:
  - `collectedDescendantTerminated` (`L14-L16`): Calls `collectedDescendantTerminatedAt("/proc", pid)`.
  - `collectedDescendantTerminatedAt` (`L18-L28`): Reads `<procRoot>/<pid>/stat` and returns true if absent (`ENOENT`) or state is `'Z'` or `'X'`.
- **Tests**:
  - `TestCollectedDescendantReadState` (`L30-L63`): Unit-tests the test-only helper `collectedDescendantTerminatedAt` over synthetic temp dir files! **Self-referential test of a test helper.** Tier: **Tier 1 (Redundant / Self-Referential)**.

#### 5. [`gotool/gotool_more_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/gotool_more_test.go) (150 lines)
- **Tests**:
  - `TestEnvReaderConcurrentAndErrors` (`L16-L70`): Tests `EnvReader` nil receiver, concurrent `Snapshot`/`Value`/`Values` (10 goroutines, 1 spawn), cancelled context before primings, non-existent `dir`, and malformed JSON from a fake `go` binary. Setup weight: **Medium (1 real `go env -json` + 1 fake `go` script)**. Tier: **Tier 2 / Tier 3**.
  - `TestRunnerAndProgramEdgeCases` (`L72-L108`): Tests `Runner.Command` with nil context, invalid env (`"INVALID"`), `Prepare` hook, `Run` stderr capture on unknown subcommand, and `Program` refusing empty `PATH`. Setup weight: **Medium (1 failing `go unknown-subcommand-xyz` spawn)**. Tier: **Tier 2 / Tier 3**.
  - `TestGoVersionAndSamplerErrors` (`L110-L129`): Tests `GoVersion` and `Sampler.Snapshot` error returns on non-existent directory and invalid env. Setup weight: **Light (failed `chdir` in child spawn)**. Tier: **Tier 2**.
  - `TestCanonicalDirWalksThroughALinkBeforeDotDot` (`L135-L150`): Verifies `canonicalDir` resolves symlinks before `..` (`work/link/..` -> `real`, not `work`). Setup weight: **Light (temp dir + symlink)**. Tier: **Tier 2**.

#### 6. [`gotool/gotool_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/gotool_test.go) (50 lines)
- **Tests**:
  - `TestEnvReaderCachesSnapshot` (`L12-L49`): Tests `EnvReader.Value("GOVERSION")`, `Values("GOOS", "GOARCH")`, and `Snapshot()` JSON unmarshaling. Almost identical to `TestEnvReaderTakesOneSnapshot` (`contain_test.go:L289-L306`) and `TestEnvReaderConcurrentAndErrors` (`gotool_more_test.go:L16-L38`). Setup weight: **Medium (1 `go env -json` subprocess)**. Tier: **Tier 2 / Tier 3 (Redundant)**.

#### 7. [`gotool/identity_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/identity_test.go) (53 lines)
- **Tests**:
  - `TestEnvSnapshotToolchainIdentity` (`L9-L53`): Pure table test of `EnvSnapshot.ToolchainIdentity()` across valid snapshot, missing `GOVERSION`, missing `GOHOSTOS`, missing `GOHOSTARCH`, whitespace-only value, and nil receiver. Tier: **Tier 1 (Pure)**.

#### 8. [`gotool/list_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/list_test.go) (44 lines)
- **Tests**:
  - `TestDecodeJSONStream` (`L10-L44`): Pure test of `DecodeJSONStream[item]` across concatenated JSON objects, empty input, and mid-stream malformed JSON. Tier: **Tier 1 (Pure)**.

#### 9. [`gotool/memo_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/memo_test.go) (102 lines)
- **Tests**:
  - `TestRunMemoSharesAcrossCallersAndIsolatesCoordinates` (`L16-L77`): Tests `RunMemo.Run` deduplicating concurrent identical invocations (8 goroutines -> 1 spawn), isolating different args/dirs/envs, returning defensive byte copies, and not memoizing failures (`version -not-a-flag`) or cancelled runs. Setup weight: **Medium (`go version` subprocesses)**. Tier: **Tier 3**.
  - `TestRunMemoIncludesChdirAffectingEnv` (`L79-L102`): Pure test of `memoKey` verifying `PWD` vs `PWD` change and relative `GOWORK` + `PWD` sensitivity. Tier: **Tier 1 (Pure)**.

#### 10. [`gotool/primed_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/primed_test.go) (29 lines)
- **Tests**:
  - `TestNewPrimedEnvReaderServesSnapshotWithoutSpawning` (`L12-L29`): Verifies `NewPrimedEnvReader(snap)` serves `Snapshot`, `Value`, and `Values` with 0 subprocess spawns, and `NewPrimedEnvReader(nil)` returns an error. Tier: **Tier 1 (Pure)**.

#### 11. [`gotool/program_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/program_test.go) (197 lines)
- **Tests**:
  - `TestProgramResolvesAgainstTheSuppliedEnvironment` (`L21-L71`): Places a fake `go` script in a temp dir, passes it in `env`'s `PATH` (while parent's `PATH` differs), and verifies `Runner.Command`, `Runner.Run`, and `Runner.Program` resolve `go` from `env`'s `PATH` and fall back to parent `PATH` only when `env` omits `PATH`. Setup weight: **Medium (fake `go` script)**. Tier: **Tier 2**.
  - `TestProgramValidatesAndNormalizesTheConsumersEnvironment` (`L76-L109`): Verifies `Runner.Program` rejects nil context, malformed env, duplicate keys, and relative `GOTMPDIR`, and normalizes the child's `cmd.Env` with `GOENV=off`. Setup weight: **Pure / In-Memory (`exec.Cmd` inspection without running)**. Tier: **Tier 1 (Pure)**.
  - `TestProgramPreparesAConsumerCommandUnderThePolicy` (`L116-L157`): Spawns `/bin/sh -c "sleep 30 & echo $!; wait"` via `Runner.Program` and verifies process-group sweep on cancel, `WaitDelay`, and `Prepare` hook. Duplicates `TestContainmentSweepsProcessGroupOnCancel` (`contain_test.go:L41-L91`). Setup weight: **Heavy (`/bin/sh` + `sleep` subprocess)**. Tier: **Tier 3 (Duplicate)**.
  - `TestProgramQuitsTheConsumersGroupOnTheNamedCause` (`L164-L197`): Spawns `/bin/sh` with `QUIT` trap via `Runner.Program` and verifies `SIGQUIT` delivery on `QuitOn` cause. Duplicates `TestContainmentQuitOnSignalSendsSIGQUITToGroup` (`contain_test.go:L95-L124`). Setup weight: **Heavy (`/bin/sh` subprocess)**. Tier: **Tier 3 (Duplicate)**.

#### 12. [`gotool/reader_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/reader_test.go) (37 lines)
- **Tests**:
  - `TestEnvSnapshotCarriesRawJSONAndParsesOnce` (`L12-L37`): Takes one `EnvSnapshot` and checks `snapshot.JSON`, `snapshot.Value("GOFLAGS")`, `snapshot.Values("GOVERSION", "GOHOSTOS")`, and nil receiver safety. Overlaps heavily with `gotool_test.go` (`L12-L49`) and `identity_test.go`. Setup weight: **Medium (1 `go env -json` subprocess, though `EnvSnapshot` parsing itself is pure)**. Tier: **Tier 2**.

#### 13. [`gotool/samplermemo_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/samplermemo_test.go) (176 lines)
- **Helpers**:
  - `writeFakeGoEnv` (`L17-L29`): Writes a fake `go` script that increments a counter file and prints `{"GOVERSION":"go1.test"}`.
- **Tests**:
  - `TestSamplerMemoizesAcrossIrrelevantEnvVars` (`L35-L108`): Uses `writeFakeGoEnv` in `PATH` to verify `Sampler.Snapshot` spawns once across variations of `HOME`, `USER`, `SSH_AUTH_SOCK`, `XDG_CACHE_HOME` (when `GOCACHE` and `GOENV` are explicit), re-spawns when `GOOS`, `CGO_CFLAGS`, `Custom_CC` (`CC`), or `PATH` changes, and re-spawns when `XDG_CACHE_HOME` changes with implicit `GOCACHE`. Witnesses `REQ-gotool-env-memo`. Setup weight: **Light/Medium (fake `go` shell script)**. Tier: **Tier 2**.
  - `TestGoEnvMemoProjectionUnit` (`L112-L176`): Pure table/assertions test of `goEnvMemoProjection` across irrelevant vars, `GO*`/`CGO_*`, `CC`/`CXX`/`FC`/`GCCGO`/`AR`/`PKG_CONFIG`, tool-named vars (`CC=my-clang`), and fallback vars (`HOME`/`XDG_CONFIG_HOME` when `GOENV=""`, `XDG_CACHE_HOME` when `GOCACHE=""`). Tier: **Tier 1 (Pure)**.

#### 14. [`gotool/setenv_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/setenv_test.go) (69 lines)
- **Tests**:
  - `TestSetEnvKeepsNormalizeEnvsOrder` (`L15-L42`): Pure test of `SetEnv` maintaining sorted order on normalized slices (replace in place, insert in order, and unnormalized append fallback). Belongs in `env_test.go`. Tier: **Tier 1 (Pure)**.
  - `TestCoordinateDegrades` (`L47-L69`): Tests `coordinate` fallback when `dir` is a removed directory (`os.Remove(gone)`). Belongs with `TestCanonicalDirWalksThroughALinkBeforeDotDot` (`gotool_more_test.go:L135-L150`) and `memo_test.go`. Tier: **Tier 2**.

#### 15. [`gotool/snapshotsampler_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/snapshotsampler_test.go) (61 lines)
- **Tests**:
  - `TestSnapshotSamplerSharesAcrossReaderAndSamplerCallers` (`L16-L61`): Verifies a `Sampler` passed as `SnapshotSampler` to `NewEnvReaderWithSampler` shares its memoized snapshot across direct `Sampler.Snapshot` and `EnvReader.Snapshot`/`Value` calls (1 spawn total), and that `NewEnvReaderWithSampler(..., nil)` still works per-reader. Setup weight: **Medium (2 `go env -json` spawns)**. Tier: **Tier 2 / Tier 3**.

#### 16. [`gotool/version_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/gotool/version_test.go) (81 lines)
- **Tests**:
  - `TestParseGoVersionOutput` (`L10-L38`): Pure table test of ` parseGoVersionOutput` across standard `go version`, custom toolchains, missing prefix, empty/whitespace, multi-line output, and control characters. Tier: **Tier 1 (Pure)**.
  - `FuzzParseGoVersionOutputSingleLine` (`L40-L50`): Fuzz test verifying any accepted `parseGoVersionOutput` result is non-empty and free of `\r\n\x00`. Tier: **Tier 1 (Property/Fuzz)**.
  - `TestValidateEnvRejectsRelativeGOTMPDIR` (`L52-L81`): Pure table test of `NormalizeEnv` rejecting relative `GOTMPDIR` (`relative/tmp`, `.`, `./tmp`, `../tmp`) and admitting empty or absolute `GOTMPDIR`. Belongs in `env_test.go`. Tier: **Tier 1 (Pure)**.

---

### 2.2 Architectural Critique of `gotool/*_test.go`

#### Finding 1: Severe Micro-File Fragmentation (16 files for 1,948 lines; 10 files <= 102 lines)
Ten of the 16 files in `gotool` are tiny fragments created for individual commits:
- `primed_test.go` (29 lines)
- `reader_test.go` (37 lines)
- `list_test.go` (44 lines)
- `gotool_test.go` (50 lines)
- `identity_test.go` (53 lines)
- `snapshotsampler_test.go` (61 lines)
- `finish_observer_linux_test.go` (63 lines)
- `setenv_test.go` (69 lines)
- `version_test.go` (81 lines)
- `memo_test.go` (102 lines)

#### Finding 2: Concrete Cross-File Overlaps, Misplaced Tests, and Self-Referential Helper Tests
1. **`EnvReader` and `EnvSnapshot` Tested Across 6 Separate Files**:
   - `gotool_test.go` (`TestEnvReaderCachesSnapshot`), `reader_test.go` (`TestEnvSnapshotCarriesRawJSONAndParsesOnce`), `primed_test.go` (`TestNewPrimedEnvReaderServesSnapshotWithoutSpawning`), `identity_test.go` (`TestEnvSnapshotToolchainIdentity`), `gotool_more_test.go` (`TestEnvReaderConcurrentAndErrors`), and `contain_test.go` (`TestEnvReaderTakesOneSnapshot`) all test `EnvReader` and `EnvSnapshot`.
   - `TestEnvReaderCachesSnapshot` (`gotool_test.go:L12-L49`) and `TestEnvReaderTakesOneSnapshot` (`contain_test.go:L289-L306`) are redundant with `TestEnvReaderConcurrentAndErrors` (`gotool_more_test.go:L16-L70`) and `TestEnvSnapshotCarriesRawJSONAndParsesOnce` (`reader_test.go:L12-L37`).
   - Furthermore, `TestEnvSnapshotCarriesRawJSONAndParsesOnce` (`reader_test.go`) spawns a real `go env -json` subprocess just to test `EnvSnapshot.Value` and `Values` lazy parsing, which can be tested purely in-memory on `&EnvSnapshot{JSON: []byte(...)}`!
2. **`Sampler` and Coordinate Memoization Split Across 4 Files**:
   - `contain_test.go` (`TestSamplerMemoizesByCoordinateAndNeverACancellation`), `samplermemo_test.go`, `snapshotsampler_test.go`, and `memo_test.go` all test coordinate-keyed memoization.
   - `TestSamplerMemoizesByCoordinateAndNeverACancellation` sits inside `contain_test.go` (`L235-L285`) despite having nothing to do with process containment.
3. **Duplicate Subprocess Containment Scripts in `program_test.go` and `contain_test.go`**:
   - `TestProgramPreparesAConsumerCommandUnderThePolicy` (`program_test.go:L116-L157`) and `TestProgramQuitsTheConsumersGroupOnTheNamedCause` (`program_test.go:L164-L197`) copy-paste the exact `/bin/sh -c "sleep 30 & echo $!; wait"` and `trap 'echo GOT_QUIT; exit 0' QUIT` subprocess tests from `contain_test.go` (`L41-L124`). Since `Runner.Command` delegates directly to `Runner.Program`, testing full subprocess group sweeps on both `Runner.Run` and `Runner.Program` doubles the slow `/bin/sh` + `sleep` wait time without exercising distinct production code.
4. **Self-Referential Test Helper Unit Test in `finish_observer_linux_test.go`**:
   - `finish_observer_linux_test.go` defines a test-only helper `collectedDescendantTerminated` (called once in `finish_linux_test.go:L92`) and then spends 34 lines (`TestCollectedDescendantReadState`, `L30-L63`) unit-testing that test helper!

#### Finding 3: Target Consolidation Architecture for `gotool` (16 files -> 4 files)
1. **`gotool/env_version_test.go`** (Tier 1 — Pure Environment Normalization, `SetEnv`, `goEnvMemoProjection`, Coordinate/Memo Key, `DecodeJSONStream`, and `parseGoVersionOutput`):
   - Consolidates `env_test.go`, `setenv_test.go`, `version_test.go`, `list_test.go`, `identity_test.go`, `TestGoEnvMemoProjectionUnit` (`samplermemo_test.go`), `TestRunMemoIncludesChdirAffectingEnv` (`memo_test.go`), and `TestCanonicalDirWalksThroughALinkBeforeDotDot` (`gotool_more_test.go`).
2. **`gotool/reader_sampler_test.go`** (Tier 1 & Tier 2 — `EnvSnapshot`, `EnvReader`, `NewPrimedEnvReader`, `Sampler`, `SnapshotSampler`, and `RunMemo`):
   - Consolidates `reader_test.go`, `primed_test.go`, `gotool_test.go`, `snapshotsampler_test.go`, `samplermemo_test.go`, `memo_test.go`, `TestEnvReaderConcurrentAndErrors` + `TestGoVersionAndSamplerErrors` (`gotool_more_test.go`), and `TestSamplerMemoizesByCoordinateAndNeverACancellation` + `TestEnvReaderTakesOneSnapshot` (`contain_test.go`).
3. **`gotool/contain_test.go`** (Tier 2 & Tier 3 — `Runner.Program`, `Runner.Command`, `Runner.Run`, Process-Group Containment, and `WaitDelay` Salvage):
   - Consolidates `contain_test.go` (containment and `WaitDelay` tests), `program_test.go` (deduplicating the copy-pasted `/bin/sh` group-sweep and `SIGQUIT` tests), and `TestRunnerAndProgramEdgeCases` (`gotool_more_test.go`).
4. **`gotool/contain_linux_test.go`** (Tier 3 — Linux `waitid` Zombie Hold and Descendant Drain):
   - Consolidates `finish_linux_test.go` and the 15-line `collectedDescendantTerminated` helper from `finish_observer_linux_test.go` (deleting the self-referential `TestCollectedDescendantReadState`).

---

## Part 3: `guard` Test Suite Audit (8 files, 886 lines)

### 3.1 File-by-File and Test-by-Test Inventory

#### 1. [`guard/comparison_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/guard/comparison_test.go) (43 lines)
- **Tests**:
  - `TestCompareFactsRetainsAxisAndMissingEvidence` (`L5-L43`): Pure table test of `CompareFacts` and `Compare` across all 6 guard axes (`Toolchain`, `BuildConfig`, `RuntimeConfig`, `CPUModel`, `Kernel`, `Governor`) and both `Present`/`Missing` directions for `CodeResult` vs `Measurement`. Witnesses `REQ-guard-compare`. Tier: **Tier 1 (Pure)**.

#### 2. [`guard/guard_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/guard/guard_test.go) (393 lines)
- **Helpers**:
  - `buildConfigOfT` (`L16-L24`): Spawns `go env -json` via `gotool.NewEnvReader` and calls `buildConfigOf(ctx, r, env)`.
- **Tests**:
  - `TestMachineFactsLinux` (`L26-L71`): Calls `CaptureMachineFacts()` on Linux, checks `CPUModel != ""`, `Kernel != ""`, and checks `/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor` consistency. Setup weight: **Light (reads `/proc` and `/sys`)**. Tier: **Tier 2 (Host/OS Integration)**.
  - `TestCompareCodeVsMeasurement` (`L73-L102`): Pure test of `Compare` for `CodeResult` vs `Measurement`. **100% redundant** with `TestCompareFactsRetainsAxisAndMissingEvidence` (`comparison_test.go:L5-L43`). Tier: **Tier 1 (Redundant)**.
  - `TestCompareCompleteness` (`L106-L119`): Pure test checking `Compare` rejects empty guard fields on `CodeResult` and `Measurement`. **100% redundant** with `TestCompareFactsRetainsAxisAndMissingEvidence` (`comparison_test.go`) and `FuzzCompareCompleteness` (`guard_test.go:L156-L173`). Tier: **Tier 1 (Redundant)**.
  - `TestCompareSingleAxisFlip` (`L121-L154`): Property check (`testing/quick`) that flipping any subset of the 6 fields causes `Compare` to fail appropriately for `CodeResult` (2 fields) and `Measurement` (6 fields). Witnesses `REQ-guard-compare`. Tier: **Tier 1 (Property)**.
  - `FuzzCompareCompleteness` (`L156-L173`): Fuzz test verifying `Compare` requires non-empty `Toolchain` and `BuildConfig` for `CodeResult` and all 6 fields for `Measurement`, and is reflexive when complete. Witnesses `REQ-guard-compare`. Tier: **Tier 1 (Property/Fuzz)**.
  - `TestBuildConfigDigestsBuildInputs` (`L179-L202`): Calls `buildConfigOfT` 3 times (spawning 3 `go env -json` subprocesses!) to test that `GODEBUG=gocachehash=1` changes `buildConfigOf` while `GODEBUG=gctrace=1` does not. **Unnecessary subprocesses**: `buildConfigDigest([]byte("{}"), env)` is pure and tests the exact same `GODEBUG` filtering without spawning `go env -json` 3 times! Tier: **Tier 1 (currently paying Tier 3 subprocess cost)**.
  - `TestBuildConfigInputsAreUnambiguous` (`L204-L217`): Pure test of `buildConfigDigest([]byte("{}"), ...)` verifying delimiter-injection resistance across `GOEXPERIMENT` and `GODEBUG`. Tier: **Tier 1 (Pure)**.
  - `TestRuntimeGodebugSetting` (`L219-L261`): Pure table test of `runtimeGodebugSetting` across `gocachehash`, `gocacheverify`, `gocachetest`, `gotypesalias`, empty tokens, and overrides. Tier: **Tier 1 (Pure)**.
  - `TestFilterGODEBUG` (`L263-L287`): Pure table test of `filterGODEBUG` (last setting wins, sorted output, build- vs runtime-affecting split). Tier: **Tier 1 (Pure)**.
  - `TestCaptureUsesSuppliedEnvironmentForGuards` (`L289-L318`): Spawns 3 `go env -json` subprocesses via `Capture` to verify `Capture` uses the supplied `env` parameter (`GOEXPERIMENT=arenas`) rather than `os.Environ()`. Could use `gotool.NewPrimedEnvReader(&gotool.EnvSnapshot{JSON: ...})` for 0 subprocesses! Tier: **Tier 2 / Tier 3**.
  - `TestCapturePropagatesBuildConfigEnvironmentErrors` (`L320-L346`): Uses a fake `go` script in `PATH` returning exit 1 on `go env -json` to verify `Capture` propagates the error. Setup weight: **Medium (fake `go` script)**. Tier: **Tier 2**.
  - `TestCaptureDigestsRuntimeConfigFromTheRuntimeEnvironment` (`L348-L382`): Spawns 2 `go env -json` subprocesses via `Capture` to verify `Capture` hashes `GOMAXPROCS` from the `env` argument rather than the reader's environment. Could use `gotool.NewPrimedEnvReader` for 0 subprocesses! Tier: **Tier 1 / Tier 2 (currently paying Tier 3 subprocess cost)**.
  - `TestRuntimeConfigOrderIndependent` (`L384-L393`): Pure test verifying `runtimeConfig` is invariant under env slice order. Tier: **Tier 1 (Pure)**.

#### 3. [`guard/helpers_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/guard/helpers_test.go) (25 lines)
- **Helpers**:
  - `captureAmbient` (`L12-L14`), `captureInDir` (`L18-L20`), `buildConfigAmbient` (`L22-L24`).
- **Critique**: `captureAmbient`, `captureInDir`, and `buildConfigAmbient` are **completely dead code** — they have 0 callers anywhere in `guard/*_test.go`!

#### 4. [`guard/machine_linux_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/guard/machine_linux_test.go) (173 lines)
- **Tests**:
  - `TestParseCPUInfoModelLines` (`L14-L53`): Pure table test of `parseCPUInfoModel` across x86 `model name`, ARM64 `Processor`+implementer/part, S390, RISC-V `uarch`, PowerPC `cpu`+`machine`, MIPS `cpu model`, LoongArch `Model Name`, `Hardware` fallback, and empty input. Tier: **Tier 1 (Pure)**.
  - `TestCaptureCPUModelFallbackOrder` (`L55-L108`): Pure table test of `captureCPUModelFrom` across `/proc/cpuinfo`, `/sys/devices/soc0/machine`, `/sys/firmware/devicetree/base/model` (NUL-terminated), `uname.Machine` (byte-slice conversion), and failure when all sources are empty. Tier: **Tier 1 (Pure)**.
  - `TestCaptureCPUFrequencyPolicyFallbackOrder` (`L110-L157`): Pure table test of `captureCPUFrequencyPolicyFrom` across `scaling_governor`, non-ENOENT error propagation, `cpufreq/` directory missing -> `constant-frequency`, `cpufreq/` directory present without `scaling_governor` -> refusal, and `cpu0` absent -> refusal. Tier: **Tier 1 (Pure)**.
  - `TestUnameStringStopsAtNUL` (`L159-L173`): Pure test of `unameString` NUL-termination and whitespace trimming. Tier: **Tier 1 (Pure)**.

#### 5. [`guard/reader_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/guard/reader_test.go) (53 lines)
- **Tests**:
  - `TestCaptureRefusesANilReaderAndAMalformedEnvironment` (`L15-L30`): Pure/in-memory test that `Capture` refuses nil reader, out-of-range `Kind(7)` (without spawning), and duplicate env keys. Tier: **Tier 1 (Pure)**.
  - `TestCapturePrimesTheCallersReader` (`L35-L52`): Verifies `Capture` + `r.Value(ctx, "GOFLAGS")` shares 1 `go env -json` snapshot on an unprimed reader. Setup weight: **Medium (1 `go env -json` subprocess)**. Tier: **Tier 2 / Tier 3**.

#### 6. [`guard/runtime_config_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/guard/runtime_config_test.go) (50 lines)
- **Tests**:
  - `TestRuntimeConfigSeparatesEmbeddedEnvironmentEntries` (`L10-L33`): Pure test of `runtimeConfig` delimiter-shifting resistance (`GOGC=200\nGODEBUG=x` vs `GOGC=200`, `GODEBUG=x\nGODEBUG=y`) and domain separation from legacy delimiter-only encoding. Tier: **Tier 1 (Pure)**.
  - `TestRuntimeConfigValueBoundaries` (`L35-L49`): Property test (`testing/quick`) over arbitrary non-NUL strings `a, b, c` verifying `runtimeConfig` never collides under newline boundary shifting. Tier: **Tier 1 (Property)**.

#### 7. [`guard/runtime_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/guard/runtime_test.go) (56 lines)
- **Tests**:
  - `TestCaptureRuntimeAdmission` (`L9-L38`): Pure table test of `CaptureRuntime` rejecting nil/cancelled context, invalid/unknown `Kind`, duplicate/malformed env, and returning `RuntimeGuards{}` on `CodeResult`. Tier: **Tier 1 (Pure)**.
  - `TestRuntimeCaptureCancellationOutranksMachineAnswer` (`L40-L55`): Pure test of `captureRuntimeFor` verifying context cancellation during `CaptureMachineFacts` returns `context.Canceled` without calling `runtimeConfig`. Tier: **Tier 1 (Pure)**.

#### 8. [`guard/toolchainform_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/guard/toolchainform_test.go) (97 lines)
- **Tests**:
  - `TestToolchainGuardIsGoVersionsOwnForm` (`L21-L96`): Verifies `toolchainOf(snapshot)` matches live `go version` output both natively and under cross-compile `GOOS=windows GOARCH=arm64`, verifies `Capture` spawns only 1 `go` command (`go env -json`), and verifies missing `GOVERSION`, `GOHOSTOS`, or `GOHOSTARCH` refuses naming the missing key. Note: lines `L79-L95` write a fake `go` script in `PATH` 3 times just to test `toolchainOf(snapshot)` on missing keys — which can be tested directly with `gotool.NewPrimedEnvReader(&gotool.EnvSnapshot{JSON: body})` in 0 subprocesses! Tier: **Tier 2 / Tier 3**.

---

### 3.2 Architectural Critique of `guard/*_test.go`

1. **Dead Test Helper File (`guard/helpers_test.go`)**:
   - All 3 functions in [`guard/helpers_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/guard/helpers_test.go#L12-L24) (`captureAmbient`, `captureInDir`, `buildConfigAmbient`) have zero callers anywhere in the repository. The entire file is dead code.
2. **Redundant Comparison Tests Across `guard_test.go` and `comparison_test.go`**:
   - `TestCompareCodeVsMeasurement` (`guard_test.go:L73-L102`) and `TestCompareCompleteness` (`guard_test.go:L106-L119`) are 100% subsumed by `TestCompareFactsRetainsAxisAndMissingEvidence` (`comparison_test.go:L5-L43`) and `FuzzCompareCompleteness` (`guard_test.go:L156-L173`).
3. **Avoidable `go env -json` Subprocess Spawns for Pure Digest / Primed Reader Logic**:
   - `TestBuildConfigDigestsBuildInputs` (`guard_test.go:L179-L202`) spawns 3 `go env -json` subprocesses via `buildConfigOfT` (which then becomes unused if switched to `buildConfigDigest([]byte("{}"), env)`), while `TestCaptureUsesSuppliedEnvironmentForGuards` (`L289-L318`), `TestCaptureDigestsRuntimeConfigFromTheRuntimeEnvironment` (`L348-L382`), and the missing-key loop in `TestToolchainGuardIsGoVersionsOwnForm` (`toolchainform_test.go:L79-L95`) spawn 8 more `go` subprocesses where `gotool.NewPrimedEnvReader` tests the exact same `Capture` code path in-memory.
4. **Target Consolidation Architecture for `guard` (8 files -> 2 files)**:
   - Delete `guard/helpers_test.go` (100% dead code).
   - **`guard/guard_test.go`** (Consolidates `guard_test.go`, `comparison_test.go`, `runtime_config_test.go`, `runtime_test.go`, `reader_test.go`, and `toolchainform_test.go` into cohesive sections: Compare/CompareFacts + Fuzz/Quick properties, BuildConfig & RuntimeConfig digest algebra, and Capture/CaptureRuntime admission + live toolchain agreement).
   - **`guard/machine_linux_test.go`** (Consolidates `machine_linux_test.go` and `TestMachineFactsLinux` from `guard_test.go:L26-L71`).

---

## Part 4: `guidance` Test Suite Audit (2 files, 1,297 lines)

### 4.1 File-by-File and Test-by-Test Inventory

#### 1. [`guidance/guidance_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/guidance/guidance_test.go) (750 lines)
- **Fixtures & Helpers**:
  - `sample` (`L12-L67`): 5-verb markdown document covering per-surface verb aliases, per-surface knob spellings, CLI-only verbs, fenced examples, and nested 4-backtick fenced examples.
  - `knobs` (`L744-L750`): Helper building a `Registered` map with `false` (zero default).
- **Tests**:
  - `TestParseAndRenderProjections` (`L73-L166`): Witnesses `REQ-guidance-format` and `REQ-guidance-render` (`Parse`, `Description`, `Long`, `Help`, `Orientation`, surface filtering, nested 4-backtick fences). Tier: **Tier 1 (Pure)**.
  - `TestKnobIsAddressedPerSurfaceWithItsTextVerbatim` (`L172-L264`): Witnesses `REQ-guidance-render` (`Document.Knob` per-surface addressing, cross-surface refusal, sibling-verb knob refusal, unknown verb/knob/surface refusal). Tier: **Tier 1 (Pure)**.
  - `TestParseRefusalsNameTheOffense` (`L268-L322`): 32-case table test + first-offense precedence check witnessing `REQ-guidance-format` refusal diagnostics. Tier: **Tier 1 (Pure)**.
  - `TestFenceIndentationFollowsMarkdown` (`L328-L343`): Witnesses `REQ-guidance-format` (4-space indented ```` ``` ```` is code content, not a fence opener). Tier: **Tier 1 (Pure)**.
  - `TestIndentedStructureFollowsMarkdown` (`L349-L376`): Witnesses `REQ-guidance-format` (up to 3 leading spaces on headings/labels is structural; 4+ spaces is content). Tier: **Tier 1 (Pure)**.
  - `TestParseNormalizesCarriageReturns` (`L380-L390`): Witnesses `REQ-guidance-format` (`\r\n` normalization). Tier: **Tier 1 (Pure)**.
  - `TestCoverageIsExactPerSurface` (`L396-L490`): Witnesses `REQ-guidance-coverage` (`Document.Coverage` exact match on `mcp` and `cli`, deterministic defect ordering across 20 map iterations, cross-surface spelling defects, unknown surface refusal). Tier: **Tier 1 (Pure)**.
  - `TestParseReconstructsGeneratedDocuments` (`L499-L687`): 250-iteration seeded property test generating valid documents with random verbs, surfaces, knob spellings, and `(default X)` forms, asserting `Parse` round-trip, `Description`, `Knob`, and `Coverage` defect prediction. Witnesses `REQ-guidance-format`, `REQ-guidance-render`, `REQ-guidance-coverage`. Tier: **Tier 1 (Property)**.
  - `TestKnobClauseIsTheFirstClauseOutsideParentheses` (`L694-L711`): 10-case table test of `Knob.Clause()` parenthesis-aware semicolon splitting. Belongs in `projections_test.go`. Tier: **Tier 1 (Pure)**.
  - `TestEmbeddedParsesOnceAndFailsLoudly` (`L716-L741`): Tests `Embed`, `Document()` pointer identity across calls, and `Must()` panic message formatting. Overlaps with `TestMustRefusalsNameTheTool` (`projections_test.go:L329-L367`). Tier: **Tier 1 (Pure)**.

#### 2. [`guidance/projections_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/guidance/projections_test.go) (547 lines)
- **Fixtures & Helpers**:
  - `projectionSource` (`L9-L43`), `fakeNode` (`L157-L188`, in-memory `SchemaNode` test double).
- **Tests**:
  - `TestKnobUsageIsThePflagGrammar` (`L50-L152`): Tests `Knob.Usage()` stripping code-span backticks and depth-matched `(default ...)` parentheticals, and `Document.Coverage` CLI default-form linting across zero-default, non-zero-default, and unregistered flags. Witnesses `REQ-guidance-coverage`. Tier: **Tier 1 (Pure)**.
  - `TestDescribeSchemaWalksEveryDepthAndRefusesAnUnknobbedProperty` (`L196-L254`): Tests `Document.DescribeSchema` across nested object properties and array items, nil root/property handling, and deterministic walk-order refusal of unknobbed properties. Witnesses `REQ-guidance-single-source`. Tier: **Tier 1 (Pure)**.
  - `TestRegistrationIsTheFaceNeutralProjection` (`L261-L324`): Tests `Embedded.Registration` and `Document.Registration` for `cli` and `mcp`, including `ProsePointer` quoting of spaced/tabbed CLI verb aliases and `LongHelp`. Witnesses `REQ-guidance-single-source`. Tier: **Tier 1 (Pure)**.
  - `TestMustRefusalsNameTheTool` (`L329-L367`): Tests `MustKnob`, `MustRegistration`, and `MustDescribeSchema` panic messages over both valid and malformed embedded documents. Tier: **Tier 1 (Pure)**.
  - `TestPrintsDefaultIsPflagsRuleAtEveryCliff` (`L378-L412`): Exhaustive table test of `PrintsDefault(flagType, defValue)` across all pflag zero/non-zero type cliffs. Witnesses `REQ-guidance-coverage`. Tier: **Tier 1 (Pure)**.
  - `TestServedJudgmentComparesBytesWithTheProjection` (`L419-L461`): Tests `Document.Served` byte comparison against `Usage()` (CLI) and `Clause()` (MCP), deterministic defect ordering, and unknown verb/surface errors. Witnesses `REQ-guidance-coverage`, `REQ-guidance-single-source`. Tier: **Tier 1 (Pure)**.
  - `FuzzGuidanceSingleSourceProjections` (`L468-L546`): Fuzz test witnessing `REQ-guidance-single-source` across generated clauses, `Registration`, `Knob`, `Served`, and `DescribeSchema`. Tier: **Tier 1 (Property/Fuzz)**.

---

### 4.2 Architectural Critique of `guidance/*_test.go`

- **Exemplary Tier-1 Pure Architecture**: `guidance` is 100% pure in-memory testing (0 subprocesses, 0 filesystem I/O, fast execution, strong property/fuzz coverage in `TestParseReconstructsGeneratedDocuments` and `FuzzGuidanceSingleSourceProjections`).
- **Minor Boundary Cleanup Between the 2 Files**:
  - `TestKnobClauseIsTheFirstClauseOutsideParentheses` (`guidance_test.go:L694-L711`) and `TestEmbeddedParsesOnceAndFailsLoudly` (`guidance_test.go:L716-L741`) test `Knob.Clause()` and `Embedded.Must()`, which are the primary subjects of `projections_test.go` (`TestKnobUsageIsThePflagGrammar` and `TestMustRefusalsNameTheTool`). Moving those 2 tests into `projections_test.go` makes `guidance_test.go` strictly about `Parse` + `Coverage` and `projections_test.go` strictly about `Knob`/`Registration`/`SchemaNode`/`Embedded` projections.

---

## Part 5: `resident` Test Suite Audit (4 files, 816 lines)

### 5.1 File-by-File and Test-by-Test Inventory

#### 1. [`resident/ceilingfamily_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/resident/ceilingfamily_test.go) (164 lines)
- **Tests**:
  - `TestCeilingIsHalfTheFamilysRoom` (`L26-L82`): Pure + 200-iteration seeded property test of `Reading.Ceiling()`, `Reading.ChildrenBudget()`, `ceiling(host, held)`, and `childrenBudget(host, held)`, proving invariance of ceiling and budget under page movement between `AvailableBytes` and family `held`. Witnesses `REQ-fresh-resident-readings`. Tier: **Tier 1 (Pure / Property)**.
  - `TestInstallCeilingCountsTheFamilysSet` (`L91-L164`): Uses synthetic `procTreeHeld` (`procRoot` swap) to verify `InstallCeiling` counts `RssAnon + RssShmem` (excluding file-backed RSS and peaks), preserves the prior limit when a live descendant's `status` is unreadable, and preserves the prior limit on pre-4.5 kernels lacking `RssAnon`/`RssShmem`. Witnesses `REQ-fresh-resident-readings`. Setup weight: **Light (temp dir synthetic `/proc` + `debug.SetMemoryLimit`)**. Tier: **Tier 2**.

#### 2. [`resident/host_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/resident/host_test.go) (255 lines)
- **Tests**:
  - `TestMeminfoParsesTheTwoHostLines` (`L17-L39`): Pure 8-case table test of `parseMeminfo`. Witnesses `REQ-fresh-resident-readings`. Tier: **Tier 1 (Pure)**.
  - `TestCeilingIsHalfTheHostsAvailableMemory` (`L49-L190`): Tests `ceiling` floor (`CeilingFloor`), `InstallCeiling` over synthetic `procRoot`, re-derivation following host availability up/down, preserving narrower operator `debug.SetMemoryLimit`, and honoring `GOMEMLIMIT` (`16GiB`, `512MiB`, `off`, `""`), plus live `Readings()` and `Sample()` checks at `L171-L189`. Witnesses `REQ-fresh-resident-readings`. Setup weight: **Light (temp dir synthetic `/proc` + live `/proc` read at end)**. Tier: **Tier 2**.
  - `TestHostMemoryAppliesCgroupV2Limits` (`L192-L255`): Tests `HostMemory()` clamping `TotalBytes` and `AvailableBytes` against synthetic cgroup v2 `memory.max`, `memory.high`, `memory.current`, and ancestor cgroup limits. Setup weight: **Light (temp dir synthetic `/proc` and `/sys/fs/cgroup`)**. Tier: **Tier 2**.

#### 3. [`resident/resident_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/resident/resident_test.go) (355 lines)
- **Helpers**:
  - `procTree` (`L83-L92`), `procTreeHeld` (`L96-L117`).
- **Tests**:
  - `TestStatusParsesTheTwoResidentLines` (`L25-L50`): Pure table test of `parseStatus` (`VmRSS`, `VmHWM`, `RssAnon`, `RssShmem`, pre-4.5 fallback, and 10 malformed cases). Witnesses `REQ-fresh-resident-readings`. Tier: **Tier 1 (Pure)**.
  - `TestStatParsesPastTheCommandName` (`L56-L78`): Pure table test of `parseStat` (parenthesized command names containing spaces/parens) and `live(state)`. Tier: **Tier 1 (Pure)**.
  - `TestSampleWalksTheLiveDescendants` (`L127-L228`): Tests `sampleAt(root, 100)` over a synthetic 10-process tree (`init`, `self`, sibling, children, grandchild, zombie `'Z'`, dead `'X'`, vanished status, leaving process with no memory lines, malformed `VmRSS`, unreadable `0o000` status, and `0o111` unlistable `/proc` directory). Witnesses `REQ-fresh-resident-readings`. Setup weight: **Light (temp dir synthetic `/proc`)**. Tier: **Tier 2**.
  - `TestSampleCountsALiveDescendantChain` (`L234-L274`): Spawns `sh -c "sleep 30; true"` and polls `Sample()` (every 20ms) until both the shell and its `sleep` child are counted in `Sample()`, then kills/waits and verifies reaping. Setup weight: **Heavy (`sh` + `sleep` subprocess)**. Tier: **Tier 3 (Live OS Process Tree)**.
  - `TestReadingsComposeTheWalkTheHostAndTheCeiling` (`L281-L320`): Tests `Readings()` over synthetic `procRoot` + `meminfo` + `debug.SetMemoryLimit(5 << 30)`. Witnesses `REQ-fresh-resident-readings`. Tier: **Tier 2**.
  - `TestSampleAtUsesTaskChildrenWhenPresent` (`L322-L355`): Tests `sampleAt` fast path when `/proc/<pid>/task/<pid>/children` files exist. Tier: **Tier 2**.

#### 4. [`resident/words_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/resident/words_test.go) (42 lines)
- **Tests**:
  - `TestWordsAreTheOneSpellingOfAReading` (`L10-L42`): Pure test of `Words`, `Suffix`, and `ByteWord` binary unit rounding cliffs (`0 B` through `3.5 GiB`). Witnesses `REQ-fresh-resident-readings`. Tier: **Tier 1 (Pure)**.

---

### 5.2 Architectural Critique of `resident/*_test.go`

1. **Duplicated `operatorWord` Reset Boilerplate and Split Ceiling Tests Across `host_test.go` and `ceilingfamily_test.go`**:
   - Both `TestInstallCeilingCountsTheFamilysSet` (`ceilingfamily_test.go:L95-L108`) and `TestCeilingIsHalfTheHostsAvailableMemory` (`host_test.go:L59-L74`) duplicate the exact 15-line `debug.SetMemoryLimit` + `operatorWord.mu.Lock()` reset + `GOMEMLIMIT` unset boilerplate.
   - `host_test.go` and `ceilingfamily_test.go` both test `ceiling(...)` and `InstallCeiling()`: `host_test.go` was written when `ceiling` only took `Memory`, and `ceilingfamily_test.go` was added later when `ceiling(Memory, held)` was updated to include the family's held set.
2. **Target Consolidation Architecture for `resident` (4 files -> 2 files)**:
   - **`resident/resident_pure_test.go`** (Tier 1 — Pure Parsers, Formatting, and Ceiling/Budget Math):
     - Consolidates `words_test.go` (`TestWordsAreTheOneSpellingOfAReading`), `TestStatusParsesTheTwoResidentLines` + `TestStatParsesPastTheCommandName` (`resident_test.go`), `TestMeminfoParsesTheTwoHostLines` (`host_test.go`), and `TestCeilingIsHalfTheFamilysRoom` (`ceilingfamily_test.go`).
   - **`resident/resident_linux_test.go`** (Tier 2 & Tier 3 — Synthetic `/proc` & Cgroup v2 Fixtures, `InstallCeiling`, and Live Descendant Walk):
     - Consolidates `procTree`/`procTreeHeld`, `TestSampleWalksTheLiveDescendants`, `TestSampleAtUsesTaskChildrenWhenPresent`, `TestReadingsComposeTheWalkTheHostAndTheCeiling`, `TestHostMemoryAppliesCgroupV2Limits`, `TestCeilingIsHalfTheHostsAvailableMemory`, `TestInstallCeilingCountsTheFamilysSet` (sharing one `resetCeilingState(t)` helper), and `TestSampleCountsALiveDescendantChain`.

---

## Part 6: `internal/*` Test Suites Audit (8 files across 6 packages, 492 lines)

### 6.1 File-by-File and Test-by-Test Inventory

#### 1. [`internal/auditset/auditset_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset_test.go) (193 lines)
- **Tests**:
  - `TestVersionListingAdmitsOnlyListedVersions` (`L11-L19`): Pure test of `VersionListing.Listed`. Tier: **Tier 1 (Pure)**.
  - `TestAuditedSetsAreExactlyTheAuditedContents` (`L23-L109`): Pins exact slices/maps and predicates for `syncNames`, `poolNames`, `timeMethods`, `memoNames`, `reflectSymbols`, `reflectImmutableTypes`, `reflectMethods`, `randSymbols`, `randMethods`, `fmtSymbols`, `fips140Symbols`, `Symbol`, `SyncMethod`, `AtomicMethod`, `StandardSentinelGlobal`, `PoolMethod`, `SyncName`, `PoolName`, `ReflectImmutable`. Witnesses `REQ-closure-shared-dynamic-state-audited-discharges`. Tier: **Tier 1 (Pure)**.
  - `TestBoundedTokenNeverShadowsALongerName` (`L111-L134`): Pure 8-case table test of `BoundedToken` directive/generated-comment prefix matching. Tier: **Tier 1 (Pure)**.
  - `TestAuditedShapesAreDisjoint` (`L139-L151`): Verifies `symbolTables` and `purePackages` are disjoint and non-empty. Witnesses `REQ-closure-observability-audited-set`. Tier: **Tier 1 (Pure)**.
  - `TestReceiverLadderKeysOnPackageReceiverAndName` (`L157-L193`): Pure test of `ReceiverMethod` over synthetic `go/types.Func` receivers (value, pointer, type alias, foreign package, free function, nil). Tier: **Tier 1 (Pure)**.

#### 2. [`internal/auditset/identity_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/identity_test.go) (32 lines)
- **Tests**:
  - `TestIdentityCoversAdmissionInventories` (`L8-L32`): Mutates `purePackages`, `reflectImmutableTypes`, `symbolTables["reflect"]`, and method tables in place (with `defer delete`) to verify `Identity()` changes on membership mutation and is invariant under method slice order. Tier: **Tier 1 (Pure)**.

#### 3. [`internal/buildflags/buildflags_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/buildflags/buildflags_test.go) (35 lines)
- **Tests**:
  - `TestValidateRejectsOverlay` (`L12-L21`): Verifies `Validate` rejects `-overlay=overlay.json`, `-overlay overlay.json`, `--overlay=overlay.json`, `--overlay overlay.json` before touching the `EnvReader`. Tier: **Tier 1 (Pure)**.
  - `TestValidateRejectsPersistentOverlay` (`L23-L35`): Writes `GOFLAGS=-overlay=overlay.json` to a temp `goenv` file and spawns `go env -json` via `gotool.NewEnvReader` to verify `Validate` rejects persistent `-overlay`. Note: Using `gotool.NewPrimedEnvReader(&gotool.EnvSnapshot{JSON: []byte(`{"GOFLAGS":"-overlay=overlay.json"}`)})` would test `Validate`'s `GOFLAGS` inspection in 0 subprocesses! Tier: **Tier 2 / Tier 3 (convertible to Tier 1)**.

#### 4. [`internal/jsonrecord/jsonrecord_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/jsonrecord/jsonrecord_test.go) (19 lines)
- **Tests**:
  - `TestCanonicalEqualWhitespaceModes` (`L7-L19`): Pure test of `CanonicalEqual` in compacted (`true`) vs raw (`false`) modes. Tier: **Tier 1 (Pure)**.

#### 5. [`internal/outcome/outcome_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/outcome/outcome_test.go) (34 lines)
- **Tests**:
  - `TestSupportOwnsItsSubjectsAndRequiresPremises` (`L5-L34`): Pure test of `Prepare`, `Support.Reason`, and `Support.Subjects` (missing premises refusal, defensive deduplication/sorting of subjects, explicit refusal reason preservation). Tier: **Tier 1 (Pure)**.

#### 6. [`internal/render/render_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/render/render_test.go) (26 lines)
- **Tests**:
  - `TestCappedListFoldsOnlyPastTheCap` (`L8-L26`): Pure 6-case table test of `CappedList` around `ListCap` (`0`, `1`, `ListCap-1`, `ListCap`, `ListCap+1`, `ListCap+2`). Tier: **Tier 1 (Pure)**.

#### 7. [`internal/testenv/cache_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/testenv/cache_test.go) (98 lines)
- **Tests**:
  - `TestConfiguredCacheIsPreserved` (`L15-L24`): Pure test of `GoBuildCache` when `GOCACHE` is explicitly set in `env` (no subprocess spawned). Tier: **Tier 1 (Pure)**.
  - `TestBuildCacheUsesSuppliedEnvironment` (`L26-L71`): Tests `GoBuildCache` rejecting duplicate/malformed env and cancelled context, and resolving `GOCACHE` from a `GOENV` file when `GOCACHE=""` (spawns 1 `go env GOCACHE` subprocess for the `explicit == ""` case). Tier: **Tier 2 / Tier 3**.
  - `TestBuildCacheSurvivesMemoCacheIsolation` (`L73-L98`): Spawns 3 `go env GOCACHE` subprocesses to verify that resolving `GoBuildCache` before setting `XDG_CACHE_HOME` preserves the host `GOCACHE`. Tier: **Tier 3**.

#### 8. [`internal/testenv/goroot_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/testenv/goroot_test.go) (55 lines)
- **Tests**:
  - `TestOverlayGOROOTUnlinksHardlinkedSourceBeforeWrite` (`L12-L55`): Calls `OverlayGOROOT` 3 times (and `TakeEnvSnapshot` once) to verify `pkg/include/textflag.h` is copied (not hardlinked) and overlaid `src/strings/strings.go` unlinks before writing so the host `GOROOT` is never mutated in place. Setup weight: **Heavy (walks and hardlinks/copies `GOROOT` 3 times + 1 `go env -json` subprocess)**. Tier: **Tier 2 / Tier 3**.

---

### 6.2 Architectural Critique of `internal/**/*_test.go`

1. **Merge `internal/auditset/identity_test.go` (32 lines) into `internal/auditset/auditset_test.go` (193 lines)**:
   - Both test the exact same `auditset` tables in package `auditset`.
2. **Convert `TestValidateRejectsPersistentOverlay` (`internal/buildflags/buildflags_test.go:L23-L35`) to `gotool.NewPrimedEnvReader`**:
   - Avoids spawning `go env -json` and mutating process-wide `GOENV`/`GOFLAGS` via `t.Setenv` just to test `Validate` reading `r.Value(ctx, "GOFLAGS")`.
3. **Merge `internal/testenv/cache_test.go` and `internal/testenv/goroot_test.go` into `internal/testenv/testenv_test.go`**:
   - Note also that `internal/testenv` is a test-support package; in `TestOverlayGOROOTUnlinksHardlinkedSourceBeforeWrite`, calling `OverlayGOROOT(t, env, nil)` twice (`firstOverlay` at `L21` and again at `L48`) walks and hardlinks the entire Go standard library tree three times when `firstOverlay` (created before `overlaid`) already serves as the hardlinked control! Checking `firstOverlay`'s `src/strings/strings.go` after `overlaid` is created tests the exact same hardlink-unlink invariant while cutting 1 full `GOROOT` tree walk/hardlink pass.

---

## Part 7: `shortgates` Test Suite Audit (1 file, 191 lines)

### 7.1 File-by-File and Test-by-Test Inventory

#### 1. [`shortgates/shortgates_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/shortgates/shortgates_test.go) (191 lines)
- **Helpers**:
  - `recorder` (`L116-L129`): In-memory `Failer` implementation.
  - `pin` (`L132-L145`): Runs `Pin(r, root)` catching `fatalStop` panic.
- **Tests**:
  - `TestCheckDetectsEachViolation` (`L18-L57`): Pure 10-case table test of `Check(fset, files)` over in-memory parsed `ast.File`s (gate at head, gate after cheap controls, gate in `t.Run`, gate in `f.Fuzz`, gate in uninvoked closure, gate in helper, gate text in raw/interpreted string literal, gate that does not skip, gate that logs before skipping). Tier: **Tier 1 (Pure)**.
  - `TestWalkScopesTheTreeAndReportsEachClass` (`L61-L112`): Tests `Walk(dir)` over temp directories (`clean` skipping `testdata/`, `helperTree`, `rootless`, `flat`, `unparsable`). Setup weight: **Light (temp dir files)**. Tier: **Tier 2**.
  - `TestPinFailsEachArm` (`L150-L191`): Tests `Pin(r, dir)` over temp directories for clean tree and all 6 failure arms (`walk error`, `gate that does not skip`, `no test file at the root`, `no descent`, `gate in a helper`, `no gates`). Setup weight: **Light (temp dir files)**. Tier: **Tier 2**.

### 7.2 Architectural Critique of `shortgates/shortgates_test.go`
- **Well-Scoped Single File**: Clean separation of pure AST checking (`TestCheckDetectsEachViolation`) and filesystem walk/pinning (`TestWalkScopesTheTreeAndReportsEachClass`, `TestPinFailsEachArm`).
- **Minor Deduplication**: Both `TestWalkScopesTheTreeAndReportsEachClass` (`L63-L76`) and `TestPinFailsEachArm` (`L152-L165`) define identical 14-line local `write := func(t *testing.T, files map[string]string) string` closures and build the same 5 synthetic directory trees (`clean`, `helperTree`, `rootless`, `flat`, `unparsable`). Extracting `writeTree(t, files)` at package level removes the duplicate helper.

---

## Part 8: `toolversion` Test Suite Audit (1 file, 57 lines)

### 8.1 File-by-File and Test-by-Test Inventory

#### 1. [`toolversion/version_test.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/toolversion/version_test.go) (57 lines)
- **Tests**:
  - `TestEmbeddedIdentity` (`L9-L33`): Pure 11-case table test of `identity(*debug.BuildInfo)` covering nil info, empty info, release, dirty release, `(devel)`, invalid `vcs.modified`, module replacement, local replacement with spaces/newlines, non-`gofresh` dependency, local `(devel)` replacement, and workspace `(devel)` dependency. Tier: **Tier 1 (Pure)**.
  - `FuzzIdentityKeepsMetadataOnOneLine` (`L35-L47`): Fuzz test of `identity(info)` verifying single-line framing (no `\r\n\t`) and `modified=true` preservation. Tier: **Tier 1 (Property/Fuzz)**.
  - `TestRunningIdentity` (`L49-L57`): Calls exported `Identity()` and verifies it embeds the running test binary's `go=` version from `debug.ReadBuildInfo()`. Tier: **Tier 1 (Pure)**.

### 8.2 Architectural Critique of `toolversion/version_test.go`
- **Exemplary Tier-1 Test File**: 57 lines, 100% pure in-memory, complete branch coverage + fuzzing of line-framing invariant. No changes needed.

---

## Part 9: Cross-Package Synthesis & Consolidation Roadmap (Scope 08c)

### 9.1 Quantitative File & Line Consolidation Summary

| Subpackage | Current Test Files | Target Test Files | Files Removed | Key Structural Wins |
| :--- | ---: | ---: | ---: | :--- |
| `runtimeinput` | 34 | 6 | -28 | Eliminates 14 micro-files (<150L), deduplicates 4x bracket seal tests, 3x scratch matcher tests, 3x producer boundary tests, and adds shared `&Roots{}` memo to stop redundant `go env -json` spawns. |
| `gotool` | 16 | 4 | -12 | Eliminates 10 micro-files (<=102L), deletes self-referential `finish_observer_linux_test.go`, deduplicates copy-pasted `/bin/sh` containment tests in `program_test.go`, and groups `EnvReader`/`Sampler`/`RunMemo` tests. |
| `guard` | 8 | 2 | -6 | Deletes dead `guard/helpers_test.go` (0 callers), removes 2 redundant `Compare` tests in `guard_test.go`, and replaces 11 unnecessary `go env -json` subprocess spawns with `buildConfigDigest` / `NewPrimedEnvReader`. |
| `guidance` | 2 | 2 | 0 | Moves `TestKnobClauseIsTheFirstClauseOutsideParentheses` and `TestEmbeddedParsesOnceAndFailsLoudly` to `projections_test.go` for a clean parser-vs-projection split. |
| `resident` | 4 | 2 | -2 | Splits pure parsers/formatters/math (`resident_pure_test.go`) from Linux `/proc` & cgroup v2 integration (`resident_linux_test.go`), deduplicating `operatorWord` reset boilerplate. |
| `internal/*` | 8 | 6 | -2 | Merges `auditset/identity_test.go` into `auditset_test.go`, merges `testenv/cache_test.go` + `goroot_test.go` (removing 1 redundant `GOROOT` tree hardlink pass), and converts `buildflags_test.go` to `NewPrimedEnvReader`. |
| `shortgates` | 1 | 1 | 0 | Extracts shared `writeTree` helper used by `TestWalkScopesTheTreeAndReportsEachClass` and `TestPinFailsEachArm`. |
| `toolversion` | 1 | 1 | 0 | Already optimal (57 lines, 100% Tier-1 pure + fuzz). |
| **Total (Scope 08c)** | **74** | **24** | **-50 (-68%)** | **Reduces 74 test files to 24 cohesive, tier-aligned files while preserving 100% of requirement/invariant coverage and eliminating dozens of redundant `go` / `/bin/sh` subprocess spawns.** |
