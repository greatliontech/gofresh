# Working Notes: 5-Repo Freshness, Verification & Mutation Convergence

## 1. User Alignment & Session Rules (2026-11-06)

- **Selected Recovery Path (Option 1):** Audit and split the uncommitted `+14,235 / -6,052` working tree (`73` modified files + `3` untracked) back into disciplined, commit-sized chunks rather than converging the entangled C.4 + D.1 blob in place.
- **Full 5-Repo Ownership:** Full authority and ownership over both specs and code across the **5 repositories**: `go-x-tools`, `gofresh`, `gomutant`, `stipulator`, and `pew` (`godst` is explicitly outside repository scope).
- **Toolchain Invariance Requirement:** All 5 repositories must work identically under both `godst` (custom Go builds, e.g. `go1.27.2-dst.15`) and vanilla / system-installed Go toolchains — never hardcoding assumptions to one flavor or version string.
- **Compaction Defense:** Persist and commit findings, hypotheses, audit results, review dispositions, and user decisions frequently in `docs/notes/working-notes.md` so zero reasoning is lost across context compactions.
- **Lossless Working-Tree Checkpoint:** Full patch (`working-tree.patch`) and byte-for-byte file tree saved at `/home/nikolas/.gemini/antigravity-cli/brain/50b146c5-9ee0-44e7-8117-b53693375665/scratch/wt-checkpoint-20261106/`.

---

## 2. Diagnosis of Prior `gofresh` Session (`97dac15b`)

- **Committed Baseline (`HEAD` = `fa814e9`, 7 commits ahead of `origin/main`):**
  - `6a29303` docs: add tracing, surface purification, and correctness/coverage plan and blueprints
  - `af7ee21` feat(trace): implement `internal/trace` and wire structured diagnostic events (**Chunk A.1**)
  - `5024e0e` refactor!: evict `guidance`, `resident`, `toolversion`, `shortgates`, and `shapecorpus` subpackages (**Chunk B.1**)
  - `332c00b` refactor!: internalize `gotool` and `runtimeinput` into single-package `gofresh` (**Chunk B.2**)
  - `7e6f3eb` test(trace): add trace gate harness, causal witnesses, and non-interference fuzzing (**Chunk C.1**)
  - `6e2cf1a` fix(closure): harden `dynstate`, `testvariant`, and cgo scanner invariants and edge coverage (**Chunk C.2**)
  - `fa814e9` fix(runtimeinput,closure): enforce existence-bound and scratch boundaries, tuple type walking, and composition/TOCTOU suites (**Chunk C.3**)
- **Why `97dac15b` Stalled (`47,831` steps / `113.2 MB` transcript, terminated 2026-11-03 15:54):**
  1. Between `L34708` and `L36835` (pre-issue), it started Chunk D.1 work removing mutable package-level test hooks in `gofresh` and `internal/closure`.
  2. At `L36734`–`L39639` (after `docs/issues/gomutant-reuse-startup-rta-and-stale-findings.md` was filed), it implemented **Chunk C.4** on the same dirty tree. `go test ./...` passed (`0` failures).
  3. Instead of isolating, reviewing, and committing Chunk C.4, it ran `stipulator check`, hit Stipulator's `5m0s` (`300s`) timeout on `./internal/closure` and root `.` under `GOMAXPROCS=2 -race`, and spent ~20 hours (`L39640`–`L47831`, ~8,200 steps, `0` commits, `0` reviews) adding a `+1,727`-line persistent stdlib export-header cache in `internal/closure/internal/program/program.go`, `rawmemo.go`, `TestMain` pre-seeding, and rewriting thousands of lines across `integration_view_test.go`, `integration_execution_test.go`, `internal/closure/integration_test.go`, and `toolchainsource_hermetic_test.go`.
  4. At termination (`L47824`), cold `stipulator check` still timed out (`./internal/closure` = `288.6s` on 2 cores, root `.` = `~847s` CPU across 2 cores).

---

## 3. Root-Cause Diagnosis: `stipulator check` 300s Timeout at `GOMAXPROCS=2`

Inspection of `.stipulator/policy.textproto`, `.github/workflows/ci.yaml`, and `../stipulator/proto/stipulator/v1/policy.proto` established the exact structural cause:

1. **Core Dilution Across `./...` (`policy.proto:199-204`):**
   - Stipulator derives witness unit concurrency as `units = min(nproc/2, permitted_package_count)` and freezes per-unit `GOMAXPROCS = nproc / units` before capture grouping.
   - With `packages: "./..."` (`18` packages in `gofresh`), `units` scales up to `min(nproc/2, 18)` (e.g. `16`), clamping *every* package binary to `GOMAXPROCS=1..2`. The 16 small internal packages finish in `<2s`, leaving the two heavy SSA + child-`go`-command `-race` binaries (`.` and `./internal/closure`) running for minutes throttled to **2 cores** on an otherwise idle host.
2. **Consolidation + `soloSubjects` → `PackageExecution` Shift:**
   - Chunk B.2 folded `gotool` and `runtimeinput` (`115 KB` of witness bindings) into root `gofresh`, and Chunks C.1–C.3 added heavy multi-feature composition, TOCTOU, trace-witness, and fuzz suites.
   - Previously, mutable package-level test hooks caused `SharedDynamicStateCause` refusals under `PackageExecution`, making Stipulator run per-test `soloSubjects` where each test had its own `300s` invocation budget. Once test-hook culprits were removed (the right structural fix!), *all* bound witnesses in root `gofresh` ran together inside a single `GOMAXPROCS=2 go test -race` binary.
3. **Stale Policy Budget vs. CI Reality:**
   - `.github/workflows/ci.yaml` already budgets `race-timeout: 100m` split across **4 race shards** at `race-p: 2` because 2-core `-race` execution of full `go/ssa` + `go/packages` + child `go` toolchain integration witnesses genuinely takes >5m of 2-core CPU time even with a fast engine.
   - `policy.proto:37-40` explicitly states: *"Explicit per-invocation timeout, required and positive: a deliberately long-running invocation is admitted by review rather than aborted by an inherited ceiling."*
   - **Resolution for Chunk D.1:** Keep genuine, high-leverage, low-complexity engine optimizations and test-hook culprit elimination (zero `soloSubjects` fallbacks!), reject speculative test-gutting / 1,700-line cache complexity that only existed to chase an unreviewed 300s 2-core cap, and align `.stipulator/policy.textproto` (e.g., splitting fast `./internal/...` packages from heavy `.` / `./internal/closure` invocations so heavy packages aren't starved to `GOMAXPROCS=2` by 16 tiny siblings, and setting an honest measured `-race` timeout).

---

## 4. Ordered Cross-Repo Execution Roadmap

1. **`gofresh` — Chunk C.4 (Correctness & Specs):**
   - Audit diff classification from `Chunk C.4 Diff Auditor` and `Chunk D.1 & Test-Hook Diff Auditor`.
   - Isolate Chunk C.4 (`gomutant-reuse-startup-rta-and-stale-findings.md` Findings 1 & 2: startup unmutated-zero-global dead-branch pruning, source-audited assembly verification if sound, carrier-free & audited-`context.Context` parameter closure, and `docs/specs/closure.md` + `.stipulator/bindings/closure.textproto` updates).
   - Verify (`go vet` cross-OS, `go test -race`, `gomutant ephemeral` probes on changed invariants, `stipulator compile`/`verify`), run independent read-only adversarial review to convergence, and commit.
2. **`gofresh` — Chunk D.1 (Test-Hook Culprit Elimination, High-Signal Optimizations & Policy Alignment):**
   - Apply clean package-level test-hook culprit removals (`aaa_module_surface_test.go` proving zero `SharedDynamicStateCause` across all module packages under `PackageExecution`).
   - Apply verified, clean engine optimizations (measured with `internal/trace` and `mlock quiet` benchmarks) without test-suite mutilation or fragile cache bloat.
   - Align `.stipulator/policy.textproto` invocation topology and budgets, run full `stipulator check` + test gates, run adversarial review to convergence, and commit.
3. **Downstream Alignment & Tool Fixes (`pew`, `stipulator`, `gomutant` — Chunk B.3 + `gomutant` Issues):**
   - Internalize evicted CLI/MCP/process helpers (`guidance`, `resident`, `toolversion`, `gotool` supervisor, and `gomutant` exemption-clause splitters) into `internal/` of `pew`, `stipulator`, and `gomutant` (Option 1A) + file tracked consolidation issues for Option 1B evaluation.
   - Fix `gomutant` Finding 3 (`REQ-result-hygiene` / `MergeWholeFindings` pruning deleted symbols on whole-package `--package` runs) AND `gomutant` `docs/issues/schema-single-function-compile-and-overlay-reuse.md` ($O(L)$ top-level mutant helper functions instead of 540k-line inline switch, shared `(dir, schemaKey)` overlay directory across `testPkg` oracles, runtime-input merge / `PWD` working-tree protection).
   - Verify with local `replace` directives first; push `gofresh` so CI/Release mints the release tag automatically, bump `go.mod` across `pew`, `stipulator`, and `gomutant`, retire completed plan/blueprints/issues, and verify all repositories clean and green.

---

## 5. Working-Tree Diff Audit Results (`73` Modified + `3` Untracked Files)

### 5.1 Non-Core-C.4 Files Classification (`ffafc6d3`)

1. **(A) Keep in Chunk C.4:**
   - `session.go` (`const ObservationRTA = "gofresh/observation-rta@58"`, bumped from `@57`) & `verdict_algebra_test.go` golden check.
   - `internal/closure/propertyharness.go` (`fp.prog = a.prog` in `localHarnessView()` so `freshParamAnalysis` sees `MutatedGlobals` / `errors.New` globals).
   - `internal/closure/internal/program/program.go` (`AllFunctions`, `OrderedFunctions`, `MutatedGlobals`, `Summaries` fields on `program.Program`, replacing package-level `sync.Map`s).
   - `composition_toctou_test.go` (`TestObservedReuseAcrossStartupZeroGlobalAndInterfaceCarriers`, L819–982).
   - `docs/specs/closure.md` (all C.4 hunks; L446–454 `atomic.Pointer` belongs to **(B)**) + `.stipulator/bindings/{closure,fixture-preparation}.textproto` (excluding **(B)**/`(D)` test bindings).

2. **(B) Keep for Chunk D.1 — Clean Package-Level Test-Hook / `SharedDynamicStateCause` Culprit Elimination:**
   - `docs/specs/closure.md` L446–454 + `internal/dynstate/func_summary.go` (`audited &&` gate fix on `atomicPtrCandidates` + `len(storesInFunc[v]) == 0` pure-`Load` support on production compartments) + `internal/dynstate/dynstate_test.go`.
   - `aaa_module_surface_test.go` L461–611 (`TestModulePackagesHaveNoSharedDynamicStateUnderPackageExecution` enforcing zero `SharedDynamicStateCause` culprits across all 18 packages' prod, in-package test, and external test compartments under `PackageExecution`).
   - Root `gofresh` (`session.go`, `view.go`, `checking.go`, `frontend_harness_test.go`, `surface_test.go`, `unit_protocol_test.go`, `verdict_algebra_test.go`, `dynamicstate_scan_test.go`): `withViewTestHooks` / `withSessionTestHooks`, carrier-free `factMemo` replacing `sync.Map`, `t.Cleanup(RefreshFromEnv)` removing `os.Unsetenv` blocker.
   - `internal/closure` (`closure.go`, `canonical.go`, `filememo.go`, `toolchain_loader.go`, `frontend_harness_test.go`): `withClosureTestHooks`, `Hasher` miss fields, carrier-free `syncMemo[V]` / `rawEnvelopeMemo[V]` replacing `sync.Map`, removing `sync.OnceValue` function-carrier globals in test harness.
   - `internal/guard/machine_linux{,_test}.go`: `gatherFactsFrom(readSource)` replacing mutable `var readFactSource`.
   - `internal/runtimeinput` (`hash.go`, `producer.go`, `testlog.go`, `bracket*_test.go`, `classification_test.go`, `manifest_algebra_test.go`, `producer_test.go`): `withRuntimeTestHooks` + removing `t.Chdir` package-wide blockers.
   - `internal/testenv/frontend.go` & `goroot_test.go`: carrier-free `stdlibMetaCache` (`gcexportdata` bytes) + per-call `newLocalExportImporter()` replacing mutable `*packages.Package` / `types.Importer` globals (without the +450-line **(D)** `StdlibMaterializer` sprawl).
   - `internal/trace/trace_test.go`: `t.Cleanup(RefreshFromEnv)` before `t.Setenv` removing `os.Unsetenv`.

3. **(C) Keep for Chunk D.1 — Clean, High-Leverage, Low-Complexity Bugfixes & Optimizations:**
   - `internal/gotool/gotool.go` (+17 lines): `parser.SkipObjectResolution` and conditional `parser.ParseComments` (only when file bytes contain `"go:"`, `"gofresh:"`, or `"protoc-gen-go"`).
   - `internal/closure/internal/program/program.go` (+45 lines): bounded concurrent `ssaPackage.Build()` after `ssautil.AllPackages`, largest-package-first.
   - `internal/closure/toolchain_contracts.go` (+26/-14 lines): inverted selector waitlists in `collectOffSurfaceStartupRuntimePulls`.
   - `internal/closure/toolchain_audit_io.go` (+62/-53 lines): pre-indexed Rule 3 call-site table outside the fixed-point loop in `discoverOSInactiveState`.
   - `internal/closure/toolchain_cpreprocessor.go` (+146/-30 lines): `bytes.Index` fix (eliminating quadratic slice-to-string heap copy per loop iteration) and zero-alloc fast paths.
   - `internal/closure/toolchain_loader.go` (`stampEntries` via open-dir `f.Readdir(-1)` + `dirEntriesMatch`, +70 lines) + `TestDirEntriesMatch`.
   - `internal/runtimeinput/producer{,_test}.go` (+14 lines: `EvalSymlinks` on testlog path & symlinked self binary under outer testlog) + `classification_test.go` / `inputs.textproto` fuzz binding.

4. **(D) Discard / Evict — Speculative Cache & Test-Mutilation Sprawl from 20-Hour Loop:**
   - **Evict `+1,665`-line `StdCache` / `HeadersOnly` custom `go/packages` replacement** (`program.go` L56–1913, `prepared_test.go`, `viewload.go`, `explain.go` header shortcut) and the **7 test-only `inMemory*` fields added onto production `closure.Hasher`**.
   - **Evict cross-`XDG_CACHE_HOME` cache write-backs** in `toolchain_loader.go` (`toolchainListingByScopeMemo` / `toolchainDigestsByIntegrityMemo` that polluted empty `XDG_CACHE_HOME` dirs and broke hermeticity, requiring `isolateEmptyProofCache` workarounds).
   - **Evict `TestMain` pre-seeding, `aaa_module_surface_test.go` test-relocation hack (L1–459), fuzz-seed deletions (`trace_witness_test.go`, `toolchainsource_hermetic_test.go`), and test-fixture weakenings** (stripping `"testing"` imports / merging distinct integration tests across `integration_view_test.go`, `integration_execution_test.go`, `internal/closure/integration_test.go`, `composition_toctou_test.go`).
   - *Note on `rawmemo.go` + `view.go`'s `scanFactsDecodeMemo`:* duplicated in two packages in the dirty tree; evaluate under `mlock quiet` benchmarks in Chunk D.1 whether a single clean helper in `internal/cachefile` earns its keep or is unnecessary once policy core-starvation is fixed.

### 5.2 Core C.4 Files Soundness & Strategy-Version Audit (`94965ec6`)

All 6 hunks in `docs/specs/closure.md` belong to **(A)** (5 pure C.4 hunks + 1 `atomic.Pointer` pure-`Load` hunk paired with `internal/dynstate/func_summary.go`). However, auditing the unreviewed `97dac15b` implementation uncovered **2 strategy-version defects** and **6 reachable soundness defects** that must be fixed in **Chunk C.4** before review and commit:

1. **Strategy Defect S1 [HIGH]: `DynamicStateStrategy` (`session.go`) not bumped (`@49` $\rightarrow$ `@50`):**
   - `internal/dynstate/func_summary.go` (`bracketedSeamNodes`) tightened `audited == false` (fixing an unaudited bypass on mutex-bracketed `atomic.Pointer[T]`) and widened `audited == true` (admitting pure-`Load` uninitialized unexported `atomic.Pointer[T]`), violating `REQ-fresh-observation-compatibility` and `REQ-closure-dynamic-state-memo` unless bumped to `"gofresh/dynamic-state@50"`.
2. **Strategy Defect S2 [MEDIUM]: `rootedFunctionsStrategy` (`internal/closure/scope.go`) not bumped (`@5` $\rightarrow$ `@6`):**
   - `ComputeRootedFunctions` calls `provenanceBFS`, which now prunes dead conditional branches via `liveBlocks` (including constant-bool pruning when `audited == false`) and incorporates C.4 caller-enumeration/struct/dynamic-value changes. Bump to `"gofresh/rooted-functions@6"`.
3. **Soundness Defect A1 [HIGH — Unsound False Proof]: `deadZeroGlobalIfBodies` (`maximal.go`) skips `if zeroGlobal` inside UNREACHED sibling functions:**
   - `deadZeroGlobalIfBodies` only skipped `nonStartupDecls[key]` without requiring `key` to be a reached startup-only declaration. An unreached sibling test helper `func EnableAndPollute() { flag = true; if flag { os.Setenv("K", "V") } }` (executed by another test in the same `PackageExecution` binary) had its `if` body skipped, suppressing package-wide `REQ-closure-observability-unsafe` hazards (`os.Setenv`, `unsafe.Slice`, `os.Exit`, `Chdir`).
   - **Fix:** Replace negative `nonStartupDecls` with a positive **`startupOnlyDecls`** allowlist: a `funcDeclKey` qualifies iff at least one `aux.startupOnly[fn]` maps to `key` AND zero non-`startupOnly` functions across the entire package/program (including unreached AST/SSA functions) map to `key`.
4. **Soundness Defect A2 [HIGH — Unsound False Proof]: `syncStartupOnlyFunctions` (`observability.go`) omits `reach.rootedExtraFunctions` (`f.Fuzz` callbacks):**
   - Helpers called from both `init()` and an `f.Fuzz(func(...) { zeroFlag = true; helper() })` callback (`rootedExtraFunctions`) were classified `startupOnly = true` while `zeroGlobals` checked only `init()`, pruning live `if zeroFlag` effects.
   - **Fix:** Exclude `reach.rootedExtraFunctions[fn]` in `syncStartupOnlyFunctions` and `startupOnlyDecls`.
5. **Soundness Defect A3 [HIGH — Unsound False Proof]: First-party `isUnmutatedSentinelGlobal` (`freshpath.go`) misses `func init()` (`init#N`) overwrites and `//go:linkname` / native hazards:**
   - `var ErrFoo = errors.New("x")` compiles into `g.Pkg.Func("init")`, while `func init() { ErrFoo = evilErr{} }` compiles into `init#1` (which `computeMutatedGlobals` excuses via `initFlowFrame`), letting `ErrFoo.Error()` narrow to `*errors.errorString` and miss `(evilErr).Error()` (`os.Getenv`).
   - **Fix:** Require across **all** functions in the SSA program that every `*ssa.Store` with `Addr == g` resides strictly in `g.Pkg.Func("init")` storing a static `errors.New` call, every other referrer of `g` is `*ssa.DebugRef` or `*ssa.UnOp{Op: token.MUL, X: g}`, and `g` has no `//go:linkname` (forward/reverse), cgo, or unverified assembly hazard in `g.Pkg`.
6. **Soundness Defect A4 [MEDIUM-HIGH — Unsound False Proof]: `io` wrapper sentinel synthesis & `!collect.collecting()` `context.Err()` short-circuit (`freshpath.go`):**
   - `staticCallResultDynamicValue` skipped `isAuditedStandardIOWrapperType` (`LimitedReader.Read`, `multiReader.Read`, `eofReader.Read`, `multiWriter.Write`) without verifying `isUnmutatedStandardSentinelGlobal` on synthesized `io.EOF` / `io.ErrShortWrite` or collecting its concrete types; `calleeResultDynamicValue` returned `true` for `context.Err()` when `collect == nil` before verifying `context.Canceled` is unmutated.
   - **Fix:** Check `isUnmutatedStandardSentinelGlobal` on `context.Canceled` before returning when `!collect.collecting()`, and verify + collect `io.EOF` / `io.ErrShortWrite` on audited `io` wrapper error returns.
7. **Soundness Defect A5 [MEDIUM — `-mod=vendor` & Unaudited Bypass]: `verifiedPackageAssembly` (`maximal.go`) & `nonSSAGlobalHazards` (`observability.go`):**
   - `verifiedPackageAssembly` omitted `h.pinnedPackage(*pkg)` (`underCache`), allowing mutable `vendor/` `.s` files (where `verifyAssemblyFile` permits `BYTE`/`WORD` opcodes) to masquerade as `go.sum`-pinned modules; `nonSSAGlobalHazards` called `auditset.AuditedAssemblyModule` directly without `audited`, `pinnedPackage`, or `verifyAssemblyFile`.
   - **Fix:** Require `h.pinnedPackage(*pkg)` in `verifiedPackageAssembly`, and route `nonSSAGlobalHazards`'s assembly check through `audited && h.verifiedPackageAssembly(...)`.
8. **Soundness Defect A6 [MEDIUM — Shadowed Universe Identifiers]: `ifCondRequiresNonZeroGlobalTyped` & `deadZeroGlobalIfBodies` (`maximal.go`):**
   - Passed `shadowed = nil` despite holding `info *types.Info`, allowing parameter/const shadowing (`func f(false bool) { if zeroBool != false { ... } }` or `const false = true`) to falsely prune a live branch.
   - **Fix:** Verify `info.Uses[x] == types.Universe.Lookup(x.Name)` in `ifCondRequiresNonZeroGlobalTyped`, and pass `idx.pkg.TypesInfo` from `deadZeroGlobalIfBodies` when available (checking `pkg.Types.Scope().Lookup(x.Name) == nil` alongside AST local shadowing otherwise).


---

## 6. Architectural Alignment: Zero Third-Party `VersionListing` Allowlists (2026-11-06)

- **User Diagnosis & Alignment:** `gofresh` analyzes arbitrary user subject repositories and their transitive dependencies, not just our own tools. Hardcoding third-party module paths and semver lists (`VersionListing`) inside `gofresh` (such as `golang.org/x/sys` accumulating 9 versions in `typecarrier.go`, `rapid@v1.3.0` in `propertyharness.go`, and the draft `auditedAssemblyListing` for `cpuid/v2@v2.3.0` and `sha1cd@v0.6.0` in `auditset.go`) is unscalable whack-a-mole and non-viable.
- **Agreed Resolution:**
  1. **Chunk C.4 — Module/Version-Independent Mechanical Per-`TEXT` `.s` Verification:**
     - Evict `auditedAssemblyListing` (`AuditedAssemblyModule`) from `internal/auditset` and evict hardcoded `"github.com/klauspost/cpuid/v2"` string checks from `internal/closure/analyzer.go`.
     - Verify non-toolchain Plan 9 `.s` and `.h` assembly mechanically on disk **per `TEXT ·fn(SB)` function** across *any* package (first-party, `vendor/`, or `GOMODCACHE`, any module, any version — all `.s`/`.h` files are already hashed into the source closure):
       - Require every `GLOBL` in the package's `.s` files to carry `RODATA`, zero stores to `(SB)` globals, zero cross-package `pkg·sym(SB)` references, zero unverified `CALL`/`JMP` targets outside local labels/verified intra-package `TEXT` symbols, and carrier-free Go stub signatures (`interface`, `func`, `unsafe.Pointer`, `chan` refused).
       - Decode per-`TEXT` instructions and raw `BYTE`/`WORD`/`LONG`/`QUAD` sequences directly:
         - Pure ALU/SIMD/memory-local functions (e.g. `sha1cd`, `xxhash`, `blake3`, `x/crypto`, user `.s` kernels) pass with zero effects.
         - Static CPU-feature queries (`CPUID` when leaf-1 `EBX[31:24]` and leaf-`0xb`/`0x1f` `EDX` per-core APIC ID bits are not extracted by Go callers, x86 `XGETBV` `BYTE $0x0f;$0x01;$0xd0`, ARM64 `MRS` `WORD` encodings of static ID registers `MIDR_EL1` / `ID_AA64PFR*` / `ID_AA64ISAR*` and SVE `ADDVL`/`ADDPL`, Darwin `#ifdef GOOS_darwin` read-only commpage capability bits) pass under the existing guard split (matching Go stdlib `internal/cpu`).
         - Hardware counters, RNGs, syscalls, traps, per-core APIC ID reads (`CPUID(1)` `EBX >> 24`), and unrecognized raw `BYTE`/`WORD`/`LONG`/`QUAD` opcodes (such as `BYTE $0x0f;$0x01;$0xf9` = `RDTSCP`) mechanically classify the `TEXT` symbol as `externalEffectNative` (`RTCounter`, `Ia32TscAux`, and `LogicalCPU` are refused automatically with zero package-name checks).
       - Verify pull-form `//go:linkname` variables targeting audited read-only runtime startup constants (`internal/cpu.HWCap`) are write-free and address-free across their declaring package.
     - Note: Defect **S1** (`DynamicStateStrategy` `@49` $\rightarrow$ `@50` + `func_summary.go` pure-`Load` `atomic.Pointer[T]`) moves cleanly to **Chunk D.1** alongside the test-hook culprit eliminations that consume it, keeping Chunk C.4 strictly scoped to closure/observability/assembly/parameter-closure.
  2. **Chunk D.2 — Delete `VersionListing` Completely:**
     - Added explicit **Chunk D.2** in `docs/plans/plan.md` (immediately after Chunk D.1, before the Chunk B.3 release) to replace the remaining two legacy `VersionListing`s (`AuditedSourceListing` in `internal/dynstate/typecarrier.go` and `auditedPropertyHarnessListing` in `internal/closure/propertyharness.go`) with structural source checks and delete `auditset.VersionListing` altogether.
  3. **Standing Rule Persisted:** Created root `AGENTS.md` (always-active workspace rule without frontmatter) codifying compaction defense, frequent `docs/notes/` updates & commits, 5-repo ownership, `godst`/vanilla toolchain invariance, and the ban on third-party module/version allowlists.

---

## 7. Chunk C.4 Implementation & Integration Catches (2026-11-06)

1. **`observability.go:loadCachedFrom` Lazy `prog.FromPackages` Materialization:**
   - Restored the `p.Prog == nil && len(p.Pkgs) > 0` `program.FromPackages(ctx, pkgPath, p.Pkgs)` branch in `loadCachedFrom` (`observability.go:102-112`) so white-box test frontends (`primeHasherFromDir`) materialize SSA on demand when `Program` was not pre-built.
2. **Go 1.22+ `for i := range uint32(N)` Induction Loops in `phiBoundedLoopUpperBound` (`asmverify.go`):**
   - Auditing all 47 `cpuid`/`cpuidex` call sites in `cpuid/v2@v2.4.0` confirmed 46 use constant leaves (with per-core leaves `0x01`, `0x0b`, `0x8000001e` masking out APIC ID bits everywhere except `LogicalCPU()`, which extracts `ebx >> 24` and is mechanically rejected) and 1 (`brandName()` at `cpuid.go:994`) uses `for i := range uint32(3)` (`0x80000002 + i`).
   - `go/ssa/builder.go:rangeInt` lowers `for i := range uint32(N)` with the induction `*ssa.Phi` in `rangeint.body` rather than `rangeint.loop`, where `predStep` computes `incr = phi + 1` and ends in `if incr < N` branching back to `rangeint.body`. Extended `phiBoundedLoopUpperBound` (`asmverify.go`) to recognize both classic header-phi loops and `rangeInt` body-phi loops (requiring `hi <= 0x7fffffff` to forbid signed/unsigned wraparound).
3. **Blank `import _ "unsafe"` vs. `effectScanStrategy` (`maximal.go` & `effectmemo.go`):**
   - Files using `//go:linkname` without naming `unsafe.Pointer` (such as `os_unsafe_linux_arm64.go` in `cpuid/v2`) write `import _ "unsafe"`. Because `"unsafe"` is a compiler pseudo-package with no runtime `init()` function and `//go:linkname` directives are classified independently, exempted `imp.alias == "_" && imp.pkgPath == "unsafe"` in `maximal.go` (retaining the block on `import . "unsafe"`) and bumped `effectScanStrategy` to `"gofresh/effect-scan@28"` (covering both this scan change and the `runtime.GOOS`/`GOARCH` & `strconv.ErrRange`/`ErrSyntax` additions in `internal/auditset`).
4. **Mutable First-Party Verified `.s` + `.h` Packages vs. `hasCgoCallbackBlindspot` (`analyzer.go`):**
   - `closure.go` hashes every file in a mutable assembly-bearing package directory (`p.Dir`) byte-for-byte into `MaximalClosure` (covering both `.s` and `.h`), while `analyzer.go:1599` previously checked `hasCgoCallbackBlindspot(idx.meta)` (which treats `len(HFiles) > 0` as potential native source) without excluding `a.verifiedPackageAssembly(idx.meta)`. Guarded `analyzer.go:1599` with `&& !a.verifiedPackageAssembly(idx.meta)` and populated `HFiles` in `frontend_harness_test.go` (`buildInMemorySSAFromFiles` and `primeHasherFromDir`).


---

## 8. Chunk C.4 Adversarial Review Round 1 & Mutation Probe Dispositions (2026-11-07)

### 8.1 `gomutant ephemeral` Probe Catches
- **Probes 1–3 (`CPUID` APIC ID shift mask, `HWCap` `BasicKind` check, raw `BYTE` `RDTSCP` opcode):** All **KILLED** on first run.
- **Probe 4 (`startupOnlyDecls` positive allowlist in `maximal.go`) & Probe 5 (`!poisoned[g]` user sentinel init#N guard in `freshpath.go`):** Initially **SURVIVED** because `startupunreached` used `os.Setenv` (already a `packageWideMaximalHazard`) and `sentinelmut` exercised whole-program RTA (`ReadSentinel()`) rather than caller-enumerated `FormatMutSentinel(err error)`. Tightened `startupwidenedshared` (`WidenedMutate` closed subject asserting `"package scan:"` refusal prefix) and added `FormatMutSentinel` in `audited_scan_test.go` — both Probes 4 and 5 **KILLED**.
- **Probes 6–7 (`asmFlagsIncludeRODATA` disjoint `+` carry check and `addIdentityChoicesForOptionalMacros` branching):** Both **KILLED**.

### 8.2 Adversarial Review Round 1 (`0ce01db8-18fe-441d-b38a-5ce88c2017de`) — 12 Findings (All `confirmed` / `introduced` / `fixed`)
1. **Finding 1 [HIGH — Conditional `#define` / `#undef` & `st == line` drop in `asmverify.go`]:**
   - Fixed by collecting conditional (`condDepth > 0`) and `#undef`'d macros (`collectOptionalNonStdAsmMacros`), appending identity choices (`cppMacroDef{body: m}`) in `addIdentityChoicesForOptionalMacros` so `stepCPPPass` branches both expanded and unexpanded forms, switching `parseSingleNonStdAsmFile` to `expandCPPStatesWithBudget` `terminals` (avoiding intermediate unexpanded macro states while retaining identity terminal branches), enforcing `choiceCur == nextBlock` across conditional macro choices, rejecting `#define`/`#undef` of reserved assembly directives/mnemonics/registers (`isReservedNonStdAsmMacroName`), enforcing `isValidAsmMnemonic(uop)` (rejecting unexpanded function-like macro invocations), and enforcing balanced `#if*`/`#endif` (`condDepth == 0` at EOF).
2. **Finding 2-A & 2-B [HIGH — Bodyless `.s` targets in `testMainObservedEffects` / `directExternalEffects` / stdlib callbacks & `TEXT ·init(SB)`]:**
   - Extracted `(*tier2Analyzer).scanBodylessNonStdFunction` (`analyzer.go`), invoked it in `testMainObservedEffects` and `directExternalEffects` (including dynamic targets called from skipped `idx.std` frames such as `sync.Once.Do`), and rejected `init` / `init·*` / `init.*` in `parseAsmGloblRODATA` and `parseAsmTextHeader`.
3. **Finding 3 [HIGH — Token-splitting `asmFlagsIncludeRODATA` accepting `-`, carry `+`, `<<`]:**
   - Replaced with strict fail-closed expression evaluation admitting only `|` and disjoint-bit `+` (`(acc&rhs) == 0`) over `RODATA` (`8`), `NOPTR` (`16`), `DUPOK` (`1`), and integer literals within `1|8|16`, requiring `(mask&8) != 0 && (mask&^(1|8|16)) == 0`.
4. **Finding 4 [HIGH — `ComputeRootedFunctions` / `rootedProvenanceIncomplete` marking verified pure `.s` stubs incomplete]:**
   - Added `isVerifiedPureRootedAsmStub(audited, prog, fn)` (`attribution.go`), populated `verifiedAsm` on `nonSSAGlobalHazardsSummary` (`observability.go`), and populated `OtherFiles` in `internal/testenv/frontend.go` (`parseAndTypecheckDAG`) so white-box and production packages match `go/packages`.
5. **Finding 5 [MEDIUM — Non-deterministic single-entry `b.idxByTypes` map iteration for `typeScope`]:**
   - Changed `verifiedPackageAssembly` (`asmverify.go`) and `nonSSAGlobalHazardsSummary` (`observability.go`) to collect all `typeScopes []*types.Package` matching `pkg.SourcePath()` / `pkg.ImportPath` / `pkg.Dir` and check all scopes in `parseAsmGloblRODATA` (failing closed if `len(pkg.GoFiles) > 0 && len(typeScopes) == 0`).
6. **Finding 6 [MEDIUM — `deadZeroGlobalIfBodies` requiring `len(startupOnlyDecls) > 0` for `func init()`]:**
   - Changed `isInitDecl` arm in `deadZeroGlobalIfBodies` (`maximal.go:792`) to `isStartupOnlyDecl = hasStartup`, and added `token.LOR` (`&&` conjunction) to `ifCondRequiresNonZeroGlobalWith` (`maximal.go:1017`).
7. **Finding 7 [MEDIUM — ARM64 exclusive/LSE store & atomic RMW mnemonics in `isAsmReadModifyWriteMnemonic`]:**
   - Added `STXR*`, `STLXR*`, `STXP*`, `STLXP*`, `CAS*`, `LDSMAX*`, `LDSMIN*`, `LDUMAX*`, `LDUMIN*`, `STADD*`, `STCLR*`, `STEOR*`, `STSET*`, `STSMAX*`, `STSMIN*`, `STUMAX*`, `STUMIN*` to `isAsmReadModifyWriteMnemonic`.
8. **Finding 8-A & 8-B [LOW — Duplicate conflicting `//go:linkname`, `//go:linknamestd`, `/*go:linkname*/`, and freestanding linknames]:**
   - Handled `go:linknamestd`, `/*go:linkname ...*/`, `"<conflict>"` sentinel on duplicate conflicting directives, and freestanding file-level `idx.linknameByName` lookup in `analyzer.go`, `asmverify.go`, and `observability.go`.
9. **Finding 9 [LOW — Defined boolean types (`type customBool bool`) in `liveBlocks`]:**
   - Added `isBooleanSSAType` (checking underlying `types.IsBoolean`) AND boolean `*ssa.ChangeType` / `*ssa.Convert` propagation (`unwrapBoolSSAConv`, `valOf`, and `switch x := instr.(type)`) in `liveBlocks` (`observability.go`).
10. **Finding 10 [LOW — Spec wording in `REQ-closure-shared-dynamic-state-init-flow`]:**
    - Clarified `docs/specs/closure.md` (`REQ-closure-shared-dynamic-state-init-flow`) to distinguish cgo and unverified assembly packages (downgraded whole) from mechanically verified assembly, and re-pinned `.stipulator/bindings/closure.textproto`.
11. **Finding 11 [LOW — Shared `Summaries` / `MutatedGlobals` map race in `loadRegisteredInMemoryFixture`]:**
    - Zeroed `cloned.Summaries = nil` and `cloned.MutatedGlobals = nil` in `loadRegisteredInMemoryFixture` (`frontend_harness_test.go`).
12. **Finding 12 [NIT — Regression tests for Round-1 edge cases]:**
    - Added subcases covering all Round-1 findings in `TestVerifyNonStdAssemblyMechanicalInvariants` and `TestObservabilityStartupPruningAssemblyAndOpenWorldClosures` (`audited_scan_test.go`).

### 8.3 Adversarial Review Round 2 (`0ce01db8-18fe-441d-b38a-5ce88c2017de`) — 6 Findings (All `confirmed` / `introduced` / `fixed`)
1. **`[R2-1]` [HIGH — Whole-unit macro pre-collection, un-`#include`d `.h`, and missing reserved mnemonics/registers in `asmverify.go`]:**
   - Replaced pre-collected whole-unit macro expansion in `parseSingleNonStdAsmFile` with a top-to-bottom translation-unit walker (`walkUnit`) that splices local `#include`s at their directive sites (with cycle/depth protection), updates `activeDefs` sequentially (`condDepth == 0` replaces/deletes; `condDepth > 0` branches with `ensureMacroIdentityChoice`), and never collects macros from un-`#include`d `.h` files or trailing `#define`s after `TEXT`.
   - Expanded `isReservedNonStdAsmMacroName` to cover `RDPID`, `INB`/`INW`/`INL`/`OUTB`/`OUTW`/`OUTL`/`INS*`/`OUTS*`, `UD2`/`BRK`/`HVC`/`SMC`/`HLT`, `CNTVCT_EL0`/`CNTPCT_EL0`/`CNTVCTSS_EL0`/`CNTPCTSS_EL0`, `RNDR`/`RNDRRS`, `MPIDR_EL1`, `R28`, and case-sensitive `g` (preserving uppercase `G(...)` crypto macros).
   - Fixed `DUPOK` (`2`) and `NOPROF` (`1`) bit values in `asmFlagsIncludeRODATA` matching `$GOROOT/src/runtime/textflag.h`.
2. **`[R2-2]` [HIGH — Spaced `( TLS )` / `( SB )`, bare `TLS`, and ARM64 `g` / `R28` register bypasses in `asmverify.go`]:**
   - Added `hasForbiddenAsmToken` enforced across `parseAsmGloblRODATA`, `validateAsmDataDirective`, `parseAsmTextHeader`, and `verifyAsmTextInstruction`, rejecting any `TLS` or `R28` token, any `SB` token not spelled canonically as `sym(SB)` with non-whitespace preceding `(`, and any standalone `g` token except stack-slot labels `g+<digits>(FP)`.
3. **`[R2-3]` [HIGH — Non-canonical `CPUID` `TEXT` blocks bypassing `cpuidCallReadsPerCoreState`]:**
   - Added `verifyCanonicalCPUIDTextBlock` and `isCanonicalCPUIDSignature` (`asmverify.go`), admitting call-site `CPUID` refinement (`cpuidArgs` = 1 or 2) only when the `TEXT` block is straight-line (zero labels/branches), loads `op+0(FP)` into `AX` and zeroes `CX` (1-arg) or loads `sub+4(FP)` into `CX` (2-arg), executes a single `CPUID`, stores unmodified `(AX, BX, CX, DX)` into contiguous `(retBase, retBase+4, retBase+8, retBase+12)(FP)` slots, returns via `RET`, and matches `func(uint32[, uint32]) (uint32, uint32, uint32, uint32)`. All other `CPUID`-bearing `TEXT` blocks classify unconditionally as `"per-core CPUID register"`.
4. **`[R2-4]` [MEDIUM — `nonSSAGlobalHazardsSummary` TOCTOU `os.ReadFile` vs. `Hasher.readFile` & `.S` uppercase GAS extension]:**
   - Added `ReadSource` onto `program.Program` (`program.go`), bound it via `Hasher.bindProgramReader` in `loadCachedFrom` (`observability.go`) and `newTier2Base` (`analyzer.go`) so non-cached `.s`/`.h` reads flow through `h.readFile` (`h.contents`), cleared `p.Summaries` on retained `h.progs` in `resetCallScope` (`closure.go`), zeroed `cloned.ReadSource` in `loadRegisteredInMemoryFixture` (`frontend_harness_test.go`), and restricted `.s` classification in `classifyOtherNativeExt` (`observability.go`) and `verifyNonStdAssemblyFiles` (`asmverify.go`) to exact lowercase `.s` (routing `.S` / `.sx` to `isOtherNative = true`).
5. **`[R2-5]` [MEDIUM — Duplicated native hazard check, nil `idx.meta` panic/fail-open, and detached `idx.linknameByName` in `filterBaseVerifiedZeroGlobals`]:**
   - Consolidated the non-std native/assembly write-hazard gate into `(*tier2Base).pkgFreeOfUnverifiedNativeWriteHazard` (`observability.go`, failing closed when `idx == nil || idx.std || idx.meta == nil`), shared by both `filterBaseVerifiedZeroGlobals` and `isVerifiedReadOnlyLinknameVar` (skipping `peerIdx.std` peers on `objsByLinkTarget`), and added `idx.linknameByName[g.Name()] != ""` to `filterBaseVerifiedZeroGlobals`.
6. **`[R2-6]` [LOW — `REQ-closure-blindspot` spec drift in `docs/specs/closure.md`]:**
   - Updated `REQ-closure-blindspot` (`docs/specs/closure.md`) to specify canonical `CPUID` wrapper call-site refinement, `TLS`/goroutine-register exclusion, and Tier-2 pull-form `internal/cpu.HWCap` scalar variable verification, and re-pinned `.stipulator/bindings/closure.textproto`.

### 8.4 Adversarial Review Round 3 (`0ce01db8-18fe-441d-b38a-5ce88c2017de`) — 6 Findings (All `confirmed` / `introduced` / `fixed`)
1. **`[R3-1]` [HIGH — C-identifier macro scanner rewriting `·EvilVar(SB)` into `·SafeLut(SB)`, non-ASCII `#define` names, and `"init"` macro shadowing]:**
   - Added `scanIdentToken(s, pos, asmIdentMode)` and `nextAsmIdentRune` in `toolchain_cpreprocessor.go` matching `cmd/asm/internal/lex/tokenizer.go:isIdentRune` (`'·'` `\u00B7`, `'∕'` `\u2215`, Unicode letters/digits) when `asmIdentMode == true` while keeping C/cgo macro expansion on `asmIdentMode == false`.
   - Switched assembly macro expansion and `hasForbiddenAsmToken` / `stmtMentionsAMD64R14` to `asmIdentMode == true` (`expandAsmCPPStatesWithBudget`, `trailingAsmFuncMacroIdent`) so `#define EvilVar SafeLut` never rewrites `·EvilVar(SB)`, and valid `RODATA` `GLOBL ·g(SB), RODATA, $8` scans as `"·g"` rather than bare register `"g"`.
   - Added `"init"` and control/debug/segment/system registers/mnemonics to `isReservedNonStdAsmMacroName` and enforced pure-ASCII macro names in `verifyNonStdAsmPreprocessorPass` and `parseSingleNonStdAsmFile`.
2. **`[R3-2]` [HIGH — 2-operand `GLOBL ·x(SB), $size` omitting flags and bypassing `asmFlagsIncludeRODATA`]:**
   - Tightened `parseAsmGloblRODATA` to require `len(operands) == 3` (`GLOBL sym(SB), flags, $size`), zero symbol offset on the declared symbol, `asmFlagsIncludeRODATA(operands[1])`, and a positive overflow-checked constant `$size` (`evalConstAsmUintExpr`), plus strict `/1|/2|/4|/8` width validation in `validateAsmDataDirective` and constant non-negative arithmetic `(SB)` offsets bounded by `maxConstAsmUintOffset` (`0x3fffffff`, preventing 32/64-bit signed relocation addend wraparound while preserving `+0+4(SB)` in `parquet-go/bitpack`).
3. **`[R3-3]` [HIGH — Cross-ISA opcode confusion, `amd64` entry-`R14` `g` register, parameterized/segment/platform registers, `<ABIInternal>`, and missing system mnemonics]:**
   - Threaded `GOARCH` (`Program.GOARCH`, `Hasher.effectiveGOARCH()`) through `verifyNonStdAssemblyMemo` / `verifyNonStdAssemblyFiles`, failing closed on any `GOARCH` outside `"amd64"` and `"arm64"`.
   - Partitioned raw opcodes and ISA-specific mnemonics by `goarch`: `BYTE` (`0x0f 0x01 0xd0` `XGETBV`) and `CPUID` only on `amd64`; `WORD` (`isAuditedARM64WordOpcode`, now also rejecting `Rd`/`Rn` in `{18, 28, 31}`) and `MRS` only on `arm64`; `DWORD`/`LONG`/`QUAD` impure everywhere.
   - Restricted `(SB)` ABI suffixes strictly to `<ABI0>` (rejecting `<ABIInternal>`), rejected register-named branch targets (`isArchRegisterIdent` preventing `AX: JMP AX` indirect-jump spoofing while preserving lowercase `r1:` labels on `amd64`), rejected parameterized registers (`R(...)`, `F(...)`, `V(...)`, `Z(...)`, `P(...)`, `M(...)`, `SPR(...)`, `SREG(...)`, `PN(...)`) and `R18`/`R18_PLATFORM`/`FS`/`GS`/`CS`/`SS`/`DS`/`ES`/`CR0`–`CR15`/`DR0`–`DR15`/`TR0`–`TR7`/`GDTR`/`IDTR`/`LDTR`/`MSW`/`TASK`, expanded `isImpureOrSystemAsmMnemonic` (including `RDRAND*`, `RDSEED*`, `RDFSBASE*`, `RDGSBASE*`, `WRFSBASE*`, `WRGSBASE*`, `RDPMC`, `XBEGIN`/`XEND`/`XABORT`/`XTEST`, `STD`, `FXRSTOR*`, `XRSTOR*`, `amd64`-scoped `SMSW*`/`SLDT*`/`STR*`/`VERR`/`VERW`/`LAR*`/`LSL*`, and `arm64`-scoped `SYS`/`SYSL`/`DC`/`IC`/`AT`/`TLBI`/`DCPS*`/`DRPS`/`ERET`/`WFI`/`WFE`) and `isAsmReadModifyWriteMnemonic` (`LDOR*`, `STOR*`, `VSCATTER*`, `VPSCATTER*`).
   - Added `verifyAMD64EntryR14NotRead(blk)` forward CFG reachability over `#if`/`#elif`/`#else`/`#endif`, macro choices, conditional/unconditional branches, `(PC)` conservative edges, and `RET`, rejecting any path that reads or partially clobbers `R14` before an unconditional 64-bit write.
4. **`[R3-4]` [MEDIUM — Preprocessor `#ifdef` splits inside `TEXT`, `BYTE` sequences, and canonical `CPUID` wrappers]:**
   - Recorded `asmCondKind`, `condDepth`, and `condEpoch` on `asmLogicalLine`, closed `curBlock = -1` when `#endif`/`#elif`/`#else` exits `openCondDepth`, rejected `TEXT`/`GLOBL`/`DATA` at `condDepth > openCondDepth`, required unconditional single-choice `condEpoch`-contiguous `BYTE` sequences on `amd64`, required `condOp == asmCondNone && condDepth == openCondDepth && retBase == 8` in `verifyCanonicalCPUIDTextBlock`, and cleared `sum.cpuidArgs = 0` whenever `sum.impureKind != ""`.
5. **`[R3-5]` [MEDIUM — Assembly-backed Go methods (`TEXT ·T·M(SB)`) bypassing receiver and `TEXT` lookup]:**
   - Rejected non-nil receivers (`Recv() != nil`) in both `verifiedPackageAssemblyFunc` and `asmSignatureCarrierFree`, and rejected `'·'` / `'('` / `')'` / `'*'` inside `goName` in `parseAsmTextHeader` and `parseAsmGloblRODATA`.
6. **`[R3-6]` [NIT — Duplicate `.s`/`.h` parsing across `nonSSAGlobalHazardsSummary` and `tier2Base.verifiedPackageAssembly`]:**
   - Consolidated into `verifyNonStdAssemblyMemo` on `Program.Summaries` (keyed by `goarch + "\x00" + pkgPath + "\x00" + dir + "\x00" + sFiles + "\x00|\x00" + hFiles`), storing `rodataGoNames` and validating against caller `typeScopes` on every lookup, and updated `REQ-closure-blindspot` in `docs/specs/closure.md`.

### 8.5 Adversarial Review Round 4 (`0ce01db8-18fe-441d-b38a-5ce88c2017de`) — 3 `cmd/asm` Findings in `asmverify.go` (All `confirmed` / `introduced` / `fixed`)
1. **`[R4-1]` [HIGH — `arm64` `MOVD` `MRS`/`MSR` system-register & PSTATE aliases in `sysRegEnc.go`]:**
   - Audited all 431 `arm64.SystemReg` entries in `$GOROOT/src/cmd/internal/obj/arm64/sysRegEnc.go` and `SpecialOperand` PSTATE fields (`DAIFSet`, `DAIFClr`) in `a.out.go`: 414 contain `_EL0`/`_EL1`/`_EL2`/`_EL3` and 17 do not (`CurrentEL`, `DAIF`, `DIT`, `FPCR`, `FPSR`, `NZCV`, `PAN`, `RNDR`, `RNDRRS`, `SPSel`, `SPSR_abt`, `SPSR_fiq`, `SPSR_irq`, `SPSR_und`, `SSBS`, `TCO`, `UAO`, plus ARMv9 `ALLINT`/`SVCR*`).
   - Added `isARM64TLSSysReg` (`TPIDR*`, `SCXTNUM*`) to `hasForbiddenAsmToken` and `isReservedNonStdAsmMacroName`, added `isARM64SystemOrPStateReg` + `stmtContainsARM64SysReg` + `isCleanARM64SysRegDestGPR`, reserved all system/PSTATE register names against `#define`/`#undef` and branch-label spoofing, and admitted `MOVD <SysReg>, Rd` as pure on `arm64` solely when unsuffixed `MOVD` reads an `isAuditedARM64IDRegName` register into a clean general-purpose register (`R0`–`R17`, `R19`–`R27`, `R29`, `R30`, `LR`), classifying all other `arm64` system-register/PSTATE reads and writes as `"hardware counter, entropy, or system assembly instruction"`.
2. **`[R4-2]` [HIGH — Plan 9 `X:Y` colon operand-pair syntax in `cmd/asm/internal/asm/parse.go`]:**
   - Added `hasUnquotedColon` and rejected unquoted `:` in operands fail-closed across `parseAsmGloblRODATA`, `validateAsmDataDirective`, `parseAsmTextHeader`, top-level `FUNCDATA`/`PCDATA`/`PCALIGN`/`PCALIGNMAX`, `verifyAsmTextInstruction`, and `stmtUnconditionallyKillsAMD64R14` (blocking reversed-operand `MOVD R0:CNTVCT_EL0` / `GLOBL ·x(SB), $8:RODATA` forms; verified zero occurrences across the 4,848-file `GOMODCACHE` `.s` corpus).
3. **`[R4-3]` [HIGH — `RET <arg>`, `DUFFCOPY`/`DUFFZERO`, `GETCALLERPC`, `UNDEF`, `arm64` `ADR`/`ADRP` + non-branch `PC`/`IP`, `amd64` `POPF*`/`PUSHF*` + `LFS*`–`LES*`, `.suffix` stripping, and `nonStdAsmVerifierVersion` `@2`]:**
   - Required operandless unsuffixed `RET` (`uop == "RET" && rest == ""`) in both `verifyAsmTextInstruction` and `verifyAMD64EntryR14NotRead` (rejecting `RET reg`, `RET sym(SB)`, `RETF*`, `RETAA`, `RETAB`, and `RET.*`).
   - Accounted for every portable `obj.Anames` opcode (`cmd/internal/obj/util.go`): rejected `DUFFCOPY`, `DUFFZERO`, `END`, and `XXX` fail-closed; admitted `PCALIGNMAX` alongside `PCALIGN`; classified `GETCALLERPC` and `UNDEF` as impure.
   - Rejected `ADR`, `ADRP`, `BLRAA*`, and `BRAA*` fail-closed, rejected `IP` and `MAXREG` tokens in `hasForbiddenAsmToken` (preserving lowercase `ip+0(FP)`), and added `hasAsmPCToken` rejecting any `PC` pseudo-register reference outside the final branch-target operand of `isAsmBranchMnemonic` (preserving `JEQ 2(PC)` and lowercase `pc+0(FP)` while blocking `LEAQ 0(PC), AX`, `MOVQ 0x1000(PC), AX`, `ADR 0(PC), R0`, and `CBZ PC, loop`).
   - Stripped dot-suffixes (`baseOp, hasDot, _ := strings.Cut(uop, ".")`) prior to `isImpureOrSystemAsmMnemonic`, `isAsmReadModifyWriteMnemonic`, `isAsmReadOnlyCompareMnemonic`, and call/branch gates; added `POPF*`, `PUSHF*`, `LFS*`, `LGS*`, `LSS*`, `LDS*`, `LES*`, and `arm64` `HINT`/`SEV`/`SEVL` to `isImpureOrSystemAsmMnemonic` and `isReservedNonStdAsmMacroName`; added `SPB`/`BPB`/`SIB`/`DIB`/`MAXREG` and `PN0`–`PN15` to `isArchRegisterIdent`; tightened `stmtUnconditionallyKillsAMD64R14` to exact 2-operand vs. 3-operand arities without dot-suffixes (blocking 3-operand masked `VMOVQ X0, K1, R14`); bumped `nonStdAsmVerifierVersion` to `"gofresh/nonstd-asm-verifier@2"`; and updated `REQ-closure-blindspot` in `docs/specs/closure.md`.
