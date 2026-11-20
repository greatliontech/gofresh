# Chunk 13 Working Notes: Unified Streaming `testlog` Pipeline, Shared Path Spine, Premise-Gated `testing.T.Chdir` & Test Overlay Lifecycle

## 1. Scope & Governing Contracts (`docs/plans/plan.md:62-65`)

1. **Part 1 — Unified Streaming `testlog` Pipeline & Shared `open`/`stat`/`chdir` Path Spine (`internal/runtimeinput`)**:
   - Collapsed `readProducerLog`, `environmentLog`, `FromTestLogFile`, and stipulator-bound `fromTestLog` onto one streaming `captureReader`-backed line scanner (`nextTestLogLineBytes`, `openProducerCapture`, `drainAndScreenCapture`, `fromTestLogStream`).
   - Preserved `FromTestLog` and `fromTestLog` (`bytes.NewReader(log)`) in `internal/runtimeinput/testlog.go` so `.stipulator/bindings/inputs.textproto` bindings remain intact.
   - Preserved exact `REQ-inputs-producer-facade` Steps 1–10 refusal precedence in `ProducerFrame.observe`:
     1–2. `completionPremise` with single `normalizeEnvironment(in.Env)` shared across binding, `PWD` check, `resolveRoots`, and `populateManifestDigests`.
     3. `if requireOutcomes { reason = in.Outcome.Reason(binding) }`.
     4. Open capture (`""` -> `"testlog capture unavailable: ..."`, `os.IsNotExist` -> `"test process produced no runtime-input log"`, open or mid-stream read I/O failure -> `"testlog capture unreadable: %q"`, context cancellation -> `ctx.Err()`).
     5. Verify `"# test log\n"` header (`"capture file carries no test-log header; the test binary never opened it"`).
     6. `if requireOutcomes`: verify every non-empty, non-`"# test log"` line begins with `"getenv "` (`"operation-outcome support does not cover the captured operations"`), outranking Steps 7–9 even when `f.bracket == nil`, `PWD != PkgDir`, or `resolveRoots` fails (`drainAndScreenCapture` streams on early error paths with zero whole-file allocation).
     7–10. `f.bracket == nil`, `producerPWDProblem`, `resolveRoots`, and `fromTestLogStream` ingestion.
   - Added zero-allocation `(cwd, relUnsafe, name, isStat)` `seenReads` deduplication on idempotent `open` and `stat` operations before path cleaning and filesystem probes (`chdir` is a `(cwd, chdirStack)` state transition and is never skipped by deduplication).
   - Added `classifyMemo` on `pathClassifier` (`eligibility.go`) and unified `open`/`stat` onto `processReadPathOp` / `recordClassifiedPath` (`testlog.go`).

2. **Part 2 — Premise-Gated `testing.T.Chdir` Excursion Contract (`docs/specs/runtime-inputs.md`, `docs/specs/evidence.md`, `docs/specs/closure.md`, `internal/closure/internal/asmverify`, `internal/closure`, `internal/outcome`, `internal/runtimeinput`, `binding.go`, `unit.go`, `runtimeinputs.go`, `session.go`)**:
   - Updated `REQ-inputs-observation-disposition`, `REQ-inputs-path-congruence`, `REQ-inputs-exclusions`, and `REQ-inputs-unbounded` in `docs/specs/runtime-inputs.md`, `REQ-fresh-authority-account` in `docs/specs/evidence.md`, and `REQ-closure-observability-toolchain-key` in `docs/specs/closure.md` (re-pinning `.stipulator/bindings/{closure,fresh,inputs}.textproto`).
   - Added ISA-verified `TextSummary.ForwardsTrapArg0Syscall` (`verifyTrapArg0SyscallTrampoline` in `internal/closure/internal/asmverify/asmverify.go` for `amd64`/`arm64` tail-jumps to `syscall·{Syscall,Syscall6,RawSyscall,RawSyscall6}(SB)` and linear `0(FP)` -> `AX`/`R8` + `SYSCALL`/`SVC` trampolines; bumped `NonStdAsmVerifierVersion` and `verifiedNonStdAsmMemoSummaryKey` to `@6`) so first-argument trap-number syscall wrappers (such as `golang.org/x/sys/unix.Syscall*`) are verified mechanically from `.s` assembly with zero package/symbol allowlists.
   - Computed `Observability.TrackedChdirSafe` on `tier2Base` (`binaryTrackedChdirSafe` in `internal/closure/tracked_chdir.go`, emitting `closure.tracked_chdir.reject` trace events):
     - Requires `SelectionAudited()` (which verifies `os.Chdir`, `(*os.File).Chdir`, `internal/testlog`, `internal/testdeps`, and `testing`'s `(*T/*B/*F/*common).Chdir`, `Setenv`, `Cleanup`, and `runCleanup`).
     - Computes whole-binary RTA + testing-callback reachability over Go test roots (`isGoTestExecutableRoot`) + `TestMain` + `initRoots`, rejecting startup/`TestMain` `testing.Chdir`, non-standard cgo/wasm/linkname/bodyless unverified assembly stubs, direct or address-taken CWD mutators (`os.Chdir`, `(*os.File).Chdir`, `syscall.{Chdir,Fchdir,Chroot,ForkExec,StartProcess,Exec}`, `os.StartProcess`, `os/exec`), non-constant or `{SYS_CHDIR, SYS_FCHDIR, SYS_CHROOT}` trap constants (resolved from target `syscall` `Types.Scope()`) on `syscall.Syscall*` and verified `trapArg0Stubs`, non-`"PWD"` string-constant violations on `os`/`syscall`/`testing` `Setenv`/`Unsetenv`/`Clearenv`, reflective call symbols, `text/template` `*os.File` boxing into `any`, non-`testing.TB` `"Chdir"`/`"Fchdir"` interface invokes, and unconfined `unsafe.Pointer` operations (`fnHasUnconfinedUnsafeForTrackedChdir` over `liveBlocks`).
   - At Tier 2 (`reachedDecls != nil`), exempted `testing.Chdir` from `packageWideMaximalHazard` when `base.binaryTrackedChdirSafe()` holds so unreached sibling `t.Chdir` tests do not poison sibling Tier-2 proofs, while keeping Tier 1 (`reachedDecls == nil`) `Unverifiable` so `Unit.Register` selects `testlog` observation, and keeping any subject reaching `testing.Chdir` `Observable: false`.
   - Issued unforgeable `TrackedChdirSupport` (`outcome.TrackedChdirSupport`, bound to `frame.span`, `f.Root`, and `f.PkgDir`) via `(*Snapshot).PrepareTrackedChdirSupport` and `Unit.Register` -> `Unit.Close` -> `ProducerIngest.TrackedChdir` (bumped `ObservationRTA` to `@76`).
   - Enforced balanced LIFO `chdir` excursion tracking in `testlog.go` (`runtimeinput.chdir.{untracked,ambiguous,unbalanced}` trace events):
     - Without valid `TrackedChdirSupport` (or when `!pwdCurrentTruthful` at start): seals `"working-directory change"`, sets `cwdChanged = true` and `pwdCurrentTruthful = false`, and seals `"process-local environment input: PWD"` on post-`chdir` `getenv PWD`.
     - With valid `TrackedChdirSupport` and `pwdCurrentTruthful`: requires clean unambiguous absolute `chdir` targets, tracks LIFO `chdirStack`, elides unambiguous scratch/temp-root `chdir` targets (`classifier.elidesUnambiguous(p)`), resolves in-excursion relative `open`/`stat` against `cwd`, keeps `PWD` truthful across balanced excursions, and seals `"working-directory change"` (plus `"process-local environment input: PWD"` if `sawInExcursionPWD`) if `cwdAmbiguous || len(chdirStack) != 0 || cwd != packageDir` at EOF.

3. **Part 3 — `internal/testenv` & Closure Fixture Overlay Lifecycle Consolidation (`internal/testenv/frontend.go`, `internal/testenv/goroot_test.go`, `internal/closure/frontend_harness_test.go`)**:
   - Returned explicit `cleanup func()` from `ParseAndTypecheckDAGWithStdlibErr` (`internal/testenv/frontend.go`) without appending to `sharedOverlayDirs` (cleaning up immediately on parse/typecheck error).
   - Wired deterministic per-owner `cleanup` across `buildInMemorySSA`, `loadRegisteredInMemoryFixture`, `supplyRegisteredFixtures`, `computeTier2ResultAndReach`, `(*inMemoryHasherState).cleanup` (`unprimeHasher` / `primeHasherFromDir`), and `(*fixturePrograms).release`, plus per-binary `TMPDIR` isolation in `internal/closure/frontend_harness_test.go`'s `TestMain` (zero package-level dynamic state under `PackageExecution`, zero leaked `/tmp/gofresh-inmem-pkg-*` directories).
   - Added `TestMain` calling `CleanupShared()` and `TestParseAndTypecheckDAGWithStdlibErrExplicitCleanupAndErrorCleanup` in `internal/testenv/goroot_test.go`.
   - Retired `docs/issues/testlog-streaming-chdir-elision-and-overlay-cleanup.md` and updated `docs/issues/README.md`.

## 2. Verification & Mutation Probes

- **Cross-OS `go vet`**: `GOOS=linux`, `GOOS=darwin`, `GOOS=windows` `go vet ./...` — PASS.
- **Self-Hosting `dynstate` Check**: `TestModulePackagesHaveNoSharedDynamicStateUnderPackageExecution` — PASS.
- **Overlay Leak Check**: `/tmp/gofresh-inmem-pkg-*` delta across `go test -short -race ./internal/runtimeinput ./internal/closure` = `0`.
- **Toolchain Invariance (`godst` + Vanilla Go 1.27.4)**:
  - `godst` `go test -short -race` across `./internal/outcome/...`, `./internal/testenv/...`, `./internal/runtimeinput/...`, `./internal/closure/...`, and `.` — PASS.
  - `/home/nikolas/sdk/go1.27.4/bin/go test -timeout=20m -short -race ./...` — PASS across all packages.
- **Targeted `gomutant ephemeral` Probes**: 11/11 probes (`M1`–`M11` across `testlog.go`, `producer.go`, `tracked_chdir.go`, `asmverify.go`, `unit.go`, and `frontend.go`) KILLED (`0` survivors; redundant `loadedTrapReg ||` disjunct in `asmverify.go` simplified after probe `M7` proved equivalence).
- **Stipulator Static Verification**: `stipulator compile` + `stipulator verify --no-test --view bindings` — `955/955` binding rows `current` and `resolved`.
