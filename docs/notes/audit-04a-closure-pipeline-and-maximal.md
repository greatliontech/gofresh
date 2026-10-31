# Audit 04a: `closure` Pipeline, Maximal Closure, Observability, Memos, `testvariant`, and `closure/internal/*`

## Scope and Verification of Complete Read

All 26 assigned files (10,800 lines; 10,826 `view_file` line slots including trailing newline slots) were read in full from line 1 to EOF:

| # | File | Lines | Bytes | Status |
| :--- | :--- | ---: | ---: | :--- |
| 1 | `closure/closure.go` | 1,377 | 51,625 | 100% read (L1–1378) |
| 2 | `closure/maximal.go` | 1,538 | 55,643 | 100% read (L1–1539) |
| 3 | `closure/maximal_facts.go` | 142 | 6,057 | 100% read (L1–143) |
| 4 | `closure/observability.go` | 1,656 | 64,623 | 100% read (L1–1657) |
| 5 | `closure/canonical.go` | 267 | 9,621 | 100% read (L1–268) |
| 6 | `closure/dependencies.go` | 120 | 3,677 | 100% read (L1–121) |
| 7 | `closure/dynamicstate.go` | 125 | 4,380 | 100% read (L1–126) |
| 8 | `closure/effectmemo.go` | 182 | 8,889 | 100% read (L1–183) |
| 9 | `closure/effects.go` | 557 | 21,441 | 100% read (L1–558) |
| 10 | `closure/filememo.go` | 270 | 9,501 | 100% read (L1–271) |
| 11 | `closure/frontend.go` | 21 | 1,232 | 100% read (L1–22) |
| 12 | `closure/listingmemo.go` | 480 | 14,890 | 100% read (L1–481) |
| 13 | `closure/memo.go` | 265 | 9,843 | 100% read (L1–266) |
| 14 | `closure/policymemo.go` | 79 | 1,757 | 100% read (L1–80) |
| 15 | `closure/programfacade.go` | 9 | 225 | 100% read (L1–10) |
| 16 | `closure/propertyharness.go` | 293 | 11,459 | 100% read (L1–294) |
| 17 | `closure/rooted.go` | 414 | 14,387 | 100% read (L1–415) |
| 18 | `closure/scope.go` | 125 | 5,054 | 100% read (L1–126) |
| 19 | `closure/viewload.go` | 89 | 3,508 | 100% read (L1–90) |
| 20 | `closure/testvariant/testvariant.go` | 752 | 27,021 | 100% read (L1–753) |
| 21 | `closure/internal/cachefile/cachefile.go` | 375 | 9,822 | 100% read (L1–376) |
| 22 | `closure/internal/compartment/compartment.go` | 462 | 18,236 | 100% read (L1–463) |
| 23 | `closure/internal/digest/digest.go` | 18 | 441 | 100% read (L1–19) |
| 24 | `closure/internal/listing/listing.go` | 121 | 3,290 | 100% read (L1–122) |
| 25 | `closure/internal/program/program.go` | 410 | 15,394 | 100% read (L1–411) |
| 26 | `closure/internal/rta/rta.go` | 653 | 20,955 | 100% read (L1–654) |

---

## 1. Complete File-by-File, Type-by-Type, and Function-by-Function Inventory

### 1.1 `closure/closure.go` (L1–1377)

Core `Hasher` struct, constructors, maximal contribution fold, test-variant compartment hookup, Cgo/native `#include` escape scanner, file hashing, and `go list` execution/validation.

- **Types & Constants**:
  - `Closure` (`struct`, L42–70): Result of analyzing one subject (`Hash`, `ToolchainContent`, `AdmissionPolicy`, `TestVariants`, `Unverifiable`, `Reason`, `Refusal`, `Culprit`, `External`).
  - `RefusalKind` (`uint8`, L74–81): Consumer-tier refusal discriminator (`DependenceRefusal`, `OpenWorldRefusal`, `SharedDynamicStateRefusal`, `AmbiguousSubjectRefusal`).
  - `Hasher` (`struct`, L90–164): Stateful single-goroutine analysis engine with 23 fields spanning configuration (`dir`, `modCache`, `ctx`, `env`, `packageEnv`, `runner`, `buildFlags`, `snapshot`), toolchain selection (`selectionResolved`, `selection`, `source`), pass-lifetime caches (`progs`, `progErrs`, `lists`, `maximalTesting`, `maximalEffects`, `maximalFiles`, `testVariants`, `fileDigests`, `fileMemo`), batch-call-lifetime caches (`contribs`, `testBinaryKeys`, `variantScope`, `contents`), telemetry callbacks/counters (`progress`, `diagnostic`, `unit`, `persisted`, `served`), and view-shared state (`scope`, `viewLoad`).
  - `listPkg = listing.Package`, `listMod = listing.Module` (type aliases, L409–412).
  - `analysisTestHooks` (`var struct`, L559–573): Package-global test hooks (`testingTypeOwnLoad`, `fileParse`, `canonicalParse`, `variantParse`).
  - `depContribution` (`struct`, L645–648): Call-scoped memo entry for a dependency node (`contribution`, `files`).
  - `IdentityStrategy` (`const`, L737): `"gofresh/closure@1 gofresh/canonical-member@2 gofresh/variant-parse@2"`.
  - `identityFoldStrategy` (`const`, L747): `"gofresh/closure@1"`.
  - `walkEntryForTest` (`var func(path string)`, L777): Package-global test hook for cancellation during `allPackageFiles` walk.
- **Functions & Methods**:
  - `(*Hasher).UseViewLoad(load *ViewLoad)` (L172–174): Attaches a shared `ViewLoad` to avoid private `go/packages` loads in `maximalTestingTypeEffects`.
  - `(*Hasher).OnDiagnostic(f func(phase, pkgPath, detail string))` (L181–183) & `(*Hasher).emitDiagnostic` (L185–189).
  - `(*Hasher).OnProgress(f func(phase, pkgPath string))` (L195–197) & `(*Hasher).emitProgress` (L199–203).
  - `(*Hasher).OnUnit(f func(phase, pkgPath string, index, total int))` (L210–212), `(*Hasher).Unit` (L216–218), & `(*Hasher).emitUnit` (L220–224).
  - `(*Hasher).Served(class, pkgPath string)` (L231–239) & `(*Hasher).ServedSummary() map[string]map[string]bool` (L243–252): Tracks persistent memo hits by class and package.
  - `(*Hasher).Persisted() (proofs, scans int)` (L258–260): Returns counts of persisted proof slices and package scans.
  - `NewBracketAt(ctx context.Context, reader *gotool.EnvReader, buildFlags ...string) (*Hasher, error)` (L269–308): Builds a `Hasher` for an observation bracket by validating `GOFLAGS` against a live `EnvReader` while preserving `GOMODCACHE` from the base `reader`.
  - `NewAt(ctx context.Context, reader *gotool.EnvReader, buildFlags ...string) (*Hasher, error)` (L320–370): Primary `Hasher` constructor; normalizes env, validates build flags, takes env snapshot, resolves `GOMODCACHE`, and runs `resolveSelection`.
  - `(*Hasher).PassReader() *gotool.EnvReader` (L376–378): Returns a `gotool.PrimedEnvReader` seeded with `h.snapshot`.
  - `(*Hasher).FileDigest(path string) (string, bool)` (L385–388): Looks up a truncated SHA-256 content digest observed during the pass.
  - `(*Hasher).BoundAnalysis(bound context.Context) error` (L396–405): Replaces `h.ctx` before any analysis memo is populated.
  - `(*Hasher).maximalHash(pkgPath string) (string, error)` (L418–424): Computes Tier-1 package closure hash.
  - `(*Hasher).maximalContributions(pkgPath string) ([]string, error)` (L426–429): Wrapper around `maximalContributionsAndFiles` dropping the file slice.
  - `(*Hasher).maximalContributionsAndFiles(pkgPath string) ([]string, []string, error)` (L431–555): Partitioning engine over `h.list(pkgPath)`: separates `compartment.OwnVariantOf` files into `compartment.ComputeIdentity` + `compartment.AddBaseBindings`, folds remaining non-stdlib packages via `contributionAndFilesFor`, flushes file memos, and returns sorted contributions and mutable file paths.
  - `(*Hasher).resetCallScope()` (L579–587): Re-initializes `contribs`, `testBinaryKeys`, `variantScope`, and `contents` per top-level batch call.
  - `(*Hasher).modulePin(mod *listMod) string` (L592–594): Formats cache-relative `mod.Dir`.
  - `(*Hasher).pinnedPackage(p *listPkg) bool` (L599–601): Checks `p.Module != nil && !p.Module.Main && h.underCache(p.Dir)`.
  - `(*Hasher).contextErr() error` (L603–610): Checks `h.ctx.Err()`.
  - `hashContributions(pkgPath string, contribs []string) (string, error)` (L613–626): Sorts and hashes newline-joined contributions to 32 hex chars.
  - `(*Hasher).contribution(p listPkg) (string, error)` (L630–632) & `(*Hasher).contributionFor(pkgPath string, p listPkg) (string, error)` (L634–637).
  - `(*Hasher).contributionAndFilesFor(pkgPath string, p listPkg) (string, []string, error)` (L650–719): Computes `"cache:<pin>"` or `"src:<importPath>=<hash>"` for one `listPkg`, widening to `allPackageFiles` + Cgo `#include` verification when Cgo callback blindspots or `.s` assembly files are present.
  - `memberKinds(p listPkg) (compiled, embedded, canonical map[string]bool)` (L757–773): Classifies `GoFiles`/`CgoFiles` vs `EmbedFiles` vs unembedded compiled `canonical` files.
  - `allPackageFiles(check func() error, dir string) ([]string, error)` (L779–820): Walks `dir` collecting all regular files (and symlinks to regular files).
  - `resolveReal(path string) string` (L825–830): `filepath.EvalSymlinks` with fallback to `filepath.Clean`.
  - `cgoIncludeRootOutsideDir(p *listPkg, modCache string) string` (L844–868): Checks Cgo `-I`/`-iquote`/`-isystem`/`-idirafter` flags for roots escaping `p.Dir` and `modCache`.
  - `cgoIncludeFlagDirs(p *listPkg) []string` (L870–901), `cgoIncludeSearchDirs(p *listPkg) []string` (L903–915), `expandCgoIncludeDir(p *listPkg, dir string) string` (L917–919), `cleanCgoIncludeDir(p *listPkg, dir string) string` (L921–926).
  - `cgoEscapingInclude(p *listPkg, files []string) (string, error)` (L928–930) & `cgoEscapingIncludeWith(...)` (L932–1024): Scans C/C++/Go-cgo-preamble files for `#include`/`#import` directives escaping `p.Dir`.
  - `spliceCPreprocessorLines(text string) string` (L1026–1029), `goCgoPreamble(content []byte) (string, error)` (L1031–1056), `appendCgoCommentGroup(b *strings.Builder, cg *ast.CommentGroup)` (L1058–1075), `isNativeIncludeSource(rel string) bool` (L1077–1084), `cgoNativeFileHasRawString(text string) bool` (L1094–1097), `hasRawStringPrefix(before string) bool` (L1099–1107), `isCCharLiteralStart(before string) bool` (L1109–1118), `isCIdentByte(c byte) bool` (L1120–1122), `cgoIncludeDirective(line string) (string, bool, bool)` (L1124–1150), `stripCComments(text string) ([]string, bool)` (L1152–1222), `symlinkDirInPath(path, base string) string` (L1224–1254), `pathWithin(path, root string) bool` (L1256–1263).
  - `(*Hasher).underCache(dir string) bool` (L1267–1273): Checks if `dir` is within `h.modCache`.
  - `(*Hasher).hashFiles(dir string, files []string, canonical map[string]bool) (string, error)` (L1279–1281) & `hashFilesWith(...)` (L1290–1312): Folds `<relpath>\x00<digest>\n` over sorted files using canonical digest for compiled unembedded Go files and byte digest otherwise.
  - `(*Hasher).list(pkgPath string) ([]listPkg, error)` (L1321–1330) & `(*Hasher).listUnvalidated(pkgPath string) ([]listPkg, error)` (L1334–1358): Runs or loads memoized `go list -json -deps -test` and checks `standardInventoryCovers`.
  - `(*Hasher).standardInventoryCovers(pkgs []listPkg) error` (L1363–1377): Verifies every standard package in `pkgs` matches `h.source.inventory`.

---

### 1.2 `closure/maximal.go` (L1–1538)

Tier-1 batch closure computation (`ComputeMaximalBatch`, `ComputeMaximalFactsBatch`) and syntactic/typed external-effect scanning.

- **Types & Variables**:
  - `maximalEffectsResult` (`struct`, L123–126): In-memory memo entry (`effects`, `selected`).
  - `importAlias` (`struct`, L439–442): Parsed import `alias` and `pkgPath`.
  - `auditedLinknameTargets` (`var map[string]bool`, L1251–1255): `"runtime.getAuxv"`, `"runtime.vgetrandom"`, `"syscall.prlimit"`.
- **Functions & Methods**:
  - `(*Hasher).ComputeMaximalBatch(subjects []Subject) (map[Subject]Closure, map[Subject][]string, error)` (L33–46): Projects `ComputeMaximalFactsBatch` into `Closure` values.
  - `(*Hasher).ComputeMaximalFactsBatch(subjects []Subject) (map[Subject]MaximalFacts, map[Subject][]string, error)` (L54–113): Groups subjects by package, computes `maximalContributionsAndFiles`, `hashContributions`, `maximalExternalEffects`, and salts per-subject hashes via `maximalSubjectHash`.
  - `maximalSubjectHash(packageHash string, subject Subject) string` (L115–118): Length-prefixed SHA-256 salt of `(packageHash, subject.Package, subject.Symbol)`.
  - `(*Hasher).maximalExternalEffects(pkgPath string) ([]externalEffect, string, error)` (L132–218): Aggregates `maximalTestingTypeEffects`, property-harness facts, `pinnedEffectScanWithContext`, `maximalPackageExternalEffects`, and `maximalFileEffectsCachedWithContext` across non-stdlib packages in `h.list(pkgPath)`.
  - `(*Hasher).maximalFileEffectsCached(pkgPath, path string)` (L226–228), `(*Hasher).maximalFileEffectsCachedWithNames` (L230–232), `(*Hasher).maximalFileEffectsCachedWithContext` (L234–278): Per-file effect scan with in-memory (`h.maximalFiles`) and persistent (`h.fileScan`/`h.recordFileScan`) memoization.
  - `preferEffectReason(candidate, current externalEffect) bool` (L288–294) & `preferredEffectReason(effects []externalEffect) string` (L301–313): Cause-rank and lexicographic tie-breaking for diagnostics.
  - `(*Hasher).maximalTestingTypeEffects(pkgPath string) (maximalEffectScan, error)` (L315–393): Scans `pkg.TypesInfo` for `testing` package `SelectorExpr` uses matching `classBEffect("testing", ...)`; uses `testingScanDirName` memo or `viewLoadVariants` or fallback `gotool.LoadPackages`.
  - `(*Hasher).viewLoadVariants(pkgPath string) []*packages.Package` (L398–412): Filters `h.viewLoad.Packages()` for `pkgPath` and its `ForTest` variants.
  - `maximalPackageExternalEffects(pkg *listPkg) maximalEffectScan` (L414–434): Checks `hasExternalCgoMeta`, `SysoFiles`, `hasCgoCallbackBlindspot`, and `SFiles`.
  - `maximalFileEffects(audited bool, filename string)` (L448–454), `maximalFileEffectsContent` (L457–459), `maximalFileEffectsContentWithNames` (L464–466), `maximalFileEffectsContentWithNamesFiltered` (L468–470), `maximalFileEffectsContentWithContextFiltered` (L472–666): Syntactic AST file scanner for `//go:wasmimport`, `//go:linkname`, import alias collisions, dot/blank imports, `SelectorExpr` references to `classBEffect` / unaudited standard symbols, `time.Unix(...).UTC()`/`.In(time.FixedZone(...))` carve-outs, `TestMain` `os.Exit` epilogue carve-out, and `testingMethodEffectsFiltered`.
  - `impPkgPathOr(pkgPath string) string` (L668): Identity function (vestigial no-op).
  - `unwrapASTParen(expr ast.Expr) ast.Expr` (L670–678), `isASTTimeFixedZoneCall(expr ast.Expr, aliases map[string]string) bool` (L680–691), `chainedTimeUnixSelector(outerCall *ast.CallExpr, aliases map[string]string, hasSSAFlow bool) *ast.SelectorExpr` (L693–738).
  - `(*Hasher).subjectMaximalExternalEffects(base *tier2Base, pkgPath string, reachedDecls map[funcDeclKey]bool) ([]externalEffect, error)` (L744–816) & `(*Hasher).maximalTestingTypeEffectsFiltered(...)` (L818–884): Re-runs file and testing-type scans filtered by `unreachedASTDecls` when `hasFilterableMaximalBlocker` is true.
  - `testingMethodEffects(file *ast.File, aliases map[string]string)` (L894–896) & `testingMethodEffectsFiltered(file *ast.File, aliases map[string]string, unreachedDecls []ast.Node) ([]externalEffect, string)` (L898–1073): Syntactic taint/escape tracker for `*testing.T`/`B`/`F`/`M` handle parameters and local aliases across function bodies.
  - `testingIdentifierUseSupported(identifier *ast.Ident, parents map[ast.Node]ast.Node) bool` (L1075–1114), `unwrapParen(expression ast.Expr) ast.Expr` (L1116–1124), `identifierName(expression ast.Expr) (string, bool)` (L1126–1133), `testingHandleTypeNames(file *ast.File, aliases map[string]string) map[string]bool` (L1135–1142), `extendTestingHandleTypeNames(...)` (L1144–1160), `isTestingHandleType(...)` (L1162–1185).
  - `isAlwaysExternalPackage(pkgPath string) bool` (L1187–1190), `networkPackage(pkgPath string) bool` (L1196–1198), `isSourceOnlyStandardPackage(audited bool, pkgPath string) bool` (L1207–1236).
  - `auditedLinknamesOnly(audited bool, text string) bool` (L1270–1307): Validates `//go:linkname` and `//go:linknamestd` lines against `auditedLinknameTargets`.
  - `packageHasClassifiedExternalAPI(pkgPath string) bool` (L1309–1311), `implicitImportName(pkgPath string) string` (L1317–1325), `listedDeclaredNames(pkgs []listPkg) map[string]string` (L1327–1344), `listedNonStandardPaths(pkgs []listPkg) map[string]bool` (L1346–1363), `declaredOverridesKey(declaredNames map[string]string) string` (L1365–1367), `scanOverridesKey(declaredNames map[string]string, nonStdPaths map[string]bool) string` (L1369–1393), `trueReason(pkgPath string) string` (L1395–1397), `trueExternalEffect(pkgPath string) externalEffect` (L1402–1411).
  - `(*Hasher).pinnedEffectScan(pkg listPkg)` (L1432–1434), `(*Hasher).pinnedEffectScanWithNames` (L1436–1438), `(*Hasher).pinnedEffectScanWithContext` (L1440–1500): Persistent package-level effect-scan fold for version-pinned cache packages.
  - `userTestMainDecl(file *ast.File, aliases map[string]string) *ast.FuncDecl` (L1507–1538): Syntactic AST matcher for `func TestMain(*testing.M)`.

---

### 1.3 `closure/maximal_facts.go` (L1–142)

Public data projection of maximal closure identity and conservative blocker inventory.

- **Types & Constants**:
  - `MaximalIdentity` (`struct`, L11–16): `Hash`, `TestVariants`, `ToolchainContent`, `AdmissionPolicy`.
  - `BlockerKind` (`uint8`, L20–37): Exported mirror of `externalEffectKind` (`BlockerOpaque` through `BlockerUnauditedStandard`).
  - `Blocker` (`struct`, L45–59): Exported mirror of `externalEffect` (`Kind`, `Package`, `Symbol`, `Detail`, `Reason`, `Observable`, `Unrefinable`).
  - `MaximalFacts` (`struct`, L67–76): `Identity`, `Effects []Blocker`, `Diagnostic string`.
- **Functions & Methods**:
  - `newMaximalFacts(identity MaximalIdentity, effects []externalEffect, preferred string) MaximalFacts` (L78–110): Converts `[]externalEffect` to canonically sorted `[]Blocker`.
  - `(MaximalFacts).Clone() MaximalFacts` (L113–116), `(MaximalFacts).Closure() Closure` (L121–134), `(MaximalFacts).Equal(other MaximalFacts) bool` (L139–142).

---

### 1.4 `closure/observability.go` (L1–1656)

Whole-program SSA loading, batch preparation, attributed RTA orchestration, startup/test-main/subject reachability classification, and `flag` registration sink/provenance analysis.

- **Types & Constants**:
  - `batchPreparer` (`struct`, L65–70): Lazy wrapper around `(*Hasher).prepareBatch` for multi-package SSA loads.
  - `Subject` (`struct`, L173–176): `Package`, `Symbol`.
  - `Observability` (`struct`, L180–192): `Observable`, `Reason`, `OutcomeMethod`, `EffectFree`.
  - `ImmutableEnvironmentOutcomes` (`const`, L197): `outcome.Method`.
  - `maxAttributedSubjects` (`const`, L218): `subjectMaskBits` (64).
  - `packageBatch` (`struct`, L221–229): Per-package subject batching state for `ComputeObservabilityBatch` and `ComputeRootedFunctions`.
  - `flagSetKind` (`uint8`, L1167–1173): `flagSetUnproven`, `flagSetStartup`, `flagSetLocal`.
  - `unsupportedShapeReason` (`const`, L1624): `"attributed reachability unavailable: unsupported analysis shape"`.
- **Functions & Methods**:
  - `parameterizedBody(fn *ssa.Function) bool` (L32–50): Checks if `fn` has uninstantiated type parameters.
  - `(*Hasher).loadCached(pkgPath string) (*program, error)` (L57–59), `(*batchPreparer).prepare(ctx context.Context)` (L72–85), `(*batchPreparer).release(pkgPath string)` (L87–91), `(*Hasher).loadCachedContext` (L93–95), `(*Hasher).loadCachedFrom` (L97–124), `(*Hasher).releaseProgram(pkgPath string)` (L126–132), `(*Hasher).prepareBatch(ctx context.Context, uncached []string)` (L139–157).
  - `subjectRunsThroughHarness(prog *program, fn *ssa.Function) bool` (L165–170): Checks if `fn` is declared in a `_test.go` file.
  - `(*Hasher).ComputeObservabilityBatch(subjects []Subject) (map[Subject]Observability, error)` (L236–341) & `(*Hasher).observabilityGroup(group *packageBatch, bp *batchPreparer, results map[Subject]Observability) error` (L343–460): Orchestrates memo lookup, SSA loading, 64-subject slice RTA attribution (`attributedReachableSets`), per-slice persistence (`storeMemo`, `storeRootedMemo`), and selection attribution.
  - `(*Hasher).observabilityFromReachability(base *tier2Base, pkgPath string, reach attributedReachability) (Observability, error)` (L466–607): Evaluates `tier2ReachableWithObjects`, `directExternalEffects` (startup), `testMainObservedEffects`, open-world widenings, `maximalExternalEffects` / `subjectMaximalExternalEffects` backstop, `flagRegistrationFacts`, blocking subject effects, `immutableEnvironmentMethod`, and `hasNoExternalInputEffects`.
  - `hasNoExternalInputEffects(sets ...[]externalEffect) bool` (L611–620) & `immutableEnvironmentMethod(sets ...[]externalEffect) string` (L626–638).
  - `testMainObservedEffects(base *tier2Base, reachable attributedReachability) tier2Result` (L651–700) & `recordTestMainCallEffect(analyzer *tier2Analyzer, callee *ssa.Function, site ssa.CallInstruction)` (L708–748).
  - `directExternalEffects(base *tier2Base, reachable attributedReachability) tier2Result` (L750–817), `dispatchProvenanceClosed(site ssa.CallInstruction, fp *freshParamAnalysis) bool` (L829–837), `recordDirectCallEffect(analyzer *tier2Analyzer, callee *ssa.Function, site ssa.CallInstruction)` (L839–872).
  - `nonStandardFunctions(base *tier2Base, functions map[*ssa.Function]bool) map[*ssa.Function]bool` (L880–898).
  - `maximalObservabilityBlocker(audited bool, effect externalEffect) bool` (L900–971), `isOpenFlagSymbol(symbol string) bool` (L973–980).
  - `flagRegistrationSymbol(pkgPath, name string) bool` (L986–988), `flagValueRegistration` (L993–995), `flagPointerRegistration` (L998–1000), `(*tier2Base).flagRegistrationFacts()` (L1020–1158), `(*tier2Base).flagSetProvenance(...)` (L1201–1327), `flagProvenSetMethod(name string) bool` (L1333–1335), `flagProvenSetUse(...)` (L1341–1346), `closedParseArgument(v ssa.Value) bool` (L1351–1393), `ownInitializerFrame(fn *ssa.Function) bool` (L1399–1401), `provenStorage(kind flagSetKind, addr ssa.Value, fn *ssa.Function) (*ssa.Global, bool)` (L1411–1419), `confinedLocalStorage(v ssa.Value, seen map[ssa.Value]bool) bool` (L1428–1470), `flagSetReceiverParam(sig *types.Signature) bool` (L1476–1487), `addressRoot(v ssa.Value) ssa.Value` (L1492–1503), `flagRegistrationWriteShape(instr ssa.Instruction) bool` (L1510–1527), `registrationAddressComputation(v ssa.Value, seen map[ssa.Value]bool) bool` (L1537–1573), `recordFlagBackedReferences(...)` (L1582–1604), `flagBackedReadEffect(g *ssa.Global) externalEffect` (L1610–1616).
  - `packageWideMaximalHazard(effect externalEffect) bool` (L1630–1647), `hasFilterableMaximalBlocker(audited bool, effects []externalEffect) bool` (L1649–1656).

---

### 1.5 `closure/canonical.go` (L1–267)

Token-stream canonical digest for compiled, unembedded Go source files.

- **Types & Constants**:
  - `canonicalStrategy` (`const`, L30): `"gofresh/canonical-member@2"`.
  - `canonicalDirName` (`const`, L33): `"canonical"`.
  - `tokenItem` (`struct`, L167–171): `tok`, `lit`, `line`, `end`.
- **Functions & Methods**:
  - `retainedComment(text string) bool` (L44–77): Identifies `//export`, `+build`, generated-file markers (`generatedmark.IsMarker`), and `//<tool>:` or `/*<tool>:` directives.
  - `scanCanonical(content []byte) ([]tokenItem, bool)` (L93–120): Tokenizes `content` via `go/scanner` with `ScanComments`.
  - `canonicalDigest(content []byte) (string, bool)` (L122–163): Hashes tokens and retained/cgo-preamble comments (with lead-attachment bit).
  - `leadGroups(items []tokenItem) map[int]bool` (L178–201), `nextIndex(items []tokenItem, i int) int` (L205–212), `next(items []tokenItem, i int) tokenItem` (L216–221), `cgoPreamble(items []tokenItem, i int, inImportGroup bool) bool` (L228–237).
  - `(*Hasher).canonicalFileDigest(dir, byteDigest string, content []byte) string` (L244–261): Looks up/records canonical digest in `h.fileMemo.canonical`.
  - `canonicalScope() string` (L265–267): `canonicalStrategy + " " + AnalyzingFrontend()`.

---

### 1.6 `closure/dependencies.go` (L1–120)

Toolchain content and admission policy identity accessors and input capture.

- **Types & Variables**:
  - `policyInputs` (`struct`, L23–29): `verifier`, `audit`, `packages`, `linknames`, `seeds`.
  - `sourcePolicyMemo` (`var policyMemo`, L106).
- **Functions & Methods**:
  - `(*Hasher).ToolchainContent() string` (L17), `(*Hasher).AdmissionPolicy() string` (L21).
  - `capturePolicyInputs() policyInputs` (L34–104): Clones 18 package/selector/linkname maps into `policyInputs`.
  - `admissionPolicy() string` (L108–110): Calls `sourcePolicyMemo.value(capturePolicyInputs())`.
  - `(policyInputs).derive() string` (L112–120): JSON-marshals and SHA-256-hashes `"gofresh/toolchain-policy@2"` + inputs.

---

### 1.7 `closure/dynamicstate.go` (L1–125)

Graph metadata projection and persistent memo helpers for shared-dynamic-state facts.

- **Types & Constants**:
  - `PackageClass` (`int`, L16–22): `MutableLocalPackage`, `StandardPackage`, `PinnedPackage`.
  - `GraphPackage` (`struct`, L27–46): `ImportPath`, `PkgPath`, `ForTest`, `TestMain`, `Imports`, `Class`, `Pin`.
  - `dynamicStateDirName` (`const`, L100): `"dynamicstate"`.
- **Functions & Methods**:
  - `(*Hasher).GraphMetadata(pkgPaths ...string) ([]GraphPackage, error)` (L51–89): Deduplicates and classifies `h.list(pkgPath)` nodes into `[]GraphPackage`.
  - `LoadDynamicStateFacts(scope, bucket string) map[string]json.RawMessage` (L105–114) & `StoreDynamicStateFacts(scope, bucket string, facts map[string]json.RawMessage)` (L120–125): Thin wrappers over `cachefile.Load` / `cachefile.Merge`.

---

### 1.8 `closure/effectmemo.go` (L1–182)

Persistent memo serialization and scopes for package-level syntactic effect scans and typed testing-effect scans.

- **Types & Constants**:
  - `effectScanStrategy` (`const`, L65): `"gofresh/effect-scan@27"`.
  - `testingScanStrategy` (`const`, L89): `"gofresh/testing-scan@6"`.
  - `effectScanPayload` (`struct`, L103–109) & `effectScanEffect` (`struct`, L113–121).
  - `effectScanDirName = "effectscan"`, `testingScanDirName = "testingscan"` (`const`, L156–159).
- **Functions & Methods**:
  - `(*Hasher).effectScanScope() string` (L71–80), `(*Hasher).testingScanScope() string` (L97–99).
  - `encodeEffects(effects []externalEffect) []effectScanEffect` (L123–129), `decodeEffects(encoded []effectScanEffect) []externalEffect` (L131–140).
  - `effectScanKey(pin, importPath string, goFiles, cgoFiles []string) string` (L147–150).
  - `loadEffectScan(dirName, scope, key string) (maximalEffectScan, bool)` (L163–172) & `storeEffectScan(dirName, scope, key string, scan maximalEffectScan)` (L177–182).

---

### 1.9 `closure/effects.go` (L1–557)

External effect taxonomy, Class-B symbol tables, testing-harness admission tables, and standard-library pure symbol ladders.

- **Types, Constants & Variables**:
  - `externalEffectKind` (`uint8`, L10–35): `externalEffectOpaque` through `externalEffectUnauditedStandard`.
  - `externalEffect` (`struct`, L39–47): `kind`, `packagePath`, `symbol`, `detail`, `reason`, `unrefinable`, `observable`.
  - `maximalEffectScan` (`struct`, L49–58): `effects`, `importCandidates`, `preferred`.
  - `PurityResponsibility` (`const`, L155): Diagnostic string for `//gofresh:pure` or caller purity assertion.
  - `classBEntry` (`struct`, L169–172), `classBTable` & `classBPackages` (`var`, L178–301).
  - `harnessFamily` (`uint8`, L311–320), `harnessAdmission` (`struct`, L322–328), `harnessAdmissions` (`var map[string]harnessAdmission`, L334–369).
- **Functions & Methods**:
  - `(*maximalEffectScan).add(effect externalEffect)` (L60–62), `opaqueExternalEffect` (L64–66), `symbolExternalEffect` (L68–70).
  - `auditedStandardMethod(audited bool, fn *ssa.Function) bool` (L83–92), `auditedStandardCallee(audited bool, pkgPath, name string, fn *ssa.Function) bool` (L99–120), `unauditedStandardEffect(pkgPath, name string) externalEffect` (L126–128), `ambientDischargeChannel(kind externalEffectKind) string` (L141–149), `appendExternalEffect(effects []externalEffect, effect externalEffect) []externalEffect` (L157–167), `classBEffect(pkgPath, name string) (externalEffect, bool)` (L303–309).
  - `harnessReceiverMatches(fn *ssa.Function, receivers []string) bool` (L371–393), `harnessClassifiedEffect(name, suffix string) externalEffect` (L395–399), `harnessCalleeEffect(audited bool, fn *ssa.Function, dynamic bool) (externalEffect, bool)` (L403–413), `harnessBodyCut(audited bool, fn *ssa.Function) bool` (L417–426), `harnessOutcomeAdmitted(effect externalEffect) bool` (L431–440), `harnessInvokeAdmitted(audited bool, fn *ssa.Function) bool` (L444–450), `auditedHarnessLogging` (L454–456), `harnessLoggingEffect` (L459–461), `auditedHarnessPacing` (L465–467), `harnessPacingEffect` (L471–473), `harnessSubtestDriverEffect` (L478–480).
  - `classBPureStandard(audited bool, pkgPath, name string) bool` (L518–521), `auditedStandardSymbol(audited bool, pkgPath, name string) bool` (L529–531), `fmtFprintFamily(audited bool, pkgPath, name string) bool` (L540–549), `classBReason(pkgPath, name string) string` (L551–557).

---

### 1.10 `closure/filememo.go` (L1–270)

Per-directory persistent memos (`dirMemo[T]`) for per-file effect scans, test-variant compartment parses, and canonical member digests, plus once-per-call file reading (`readFile`) and `TestVariantLedger`.

- **Types & Constants**:
  - `fileScanDirName = "filescan"`, `variantParseDirName = "variantparse"` (`const`, L27–30).
  - `variantParseStrategy` (`const`, L38): `"gofresh/variant-parse@2"`.
  - `fileBytes` (`struct`, L47–50): `content []byte`, `sum [32]byte`.
  - `variantParsePayload` (`struct`, L83–86).
  - `dirMemo[T any]` (`struct`, L91–95): Generic per-directory batched persistent memo (`dirName`, `loaded`, `pending`).
  - `fileMemos` (`struct`, L155–159): Holds `scans`, `parses`, and `canonical` `dirMemo` instances.
  - `variantParseMemo` (`struct`, L201–204): Adapter implementing `compartment.ParseMemo`.
- **Functions & Methods**:
  - `variantParseScope() string` (L42–44), `(fileBytes).digest() string` (L53), `readBytes(path string) (fileBytes, error)` (L57–63), `(*Hasher).readFile(path string) (fileBytes, error)` (L68–80).
  - `newDirMemo[T any](dirName string) dirMemo[T]` (L97–103), `(*dirMemo[T]).lookup` (L105–124), `(*dirMemo[T]).record` (L126–134), `(*dirMemo[T]).flush` (L136–151), `newFileMemos() *fileMemos` (L161–167).
  - `(*Hasher).fileScan(dir, digest string)` (L172–181), `(*Hasher).recordFileScan(dir, digest string, scan maximalEffectScan)` (L185–190), `(variantParseMemo).Parsed` (L206–219), `(variantParseMemo).Record` (L221–229), `(*Hasher).flushFileMemos()` (L233–244), `(*Hasher).ReadFile(path string) ([]byte, [32]byte, error)` (L248–251), `(*Hasher).TestVariantLedger(pkgPath string) (testvariant.TestVariantLedger, error)` (L256–270).

---

### 1.11 `closure/frontend.go` (L1–21)

- `AnalyzingFrontend() string` (L21): Returns `runtime.Version()`.

---

### 1.12 `closure/listingmemo.go` (L1–480)

Persistent memo for `go list -json -deps -test`, recording and re-verifying directory entries, source-ext file digests, `go.mod`/`go.sum`/`go.work`/`vendor/modules.txt`, and `//go:embed` trees.

- **Types, Constants & Variables**:
  - `listingDirName` (`const`, L36): `"listing"`.
  - `listingRecordVersion` (`const`, L41): `3`.
  - `listingRecord` (`struct`, L46–52): `Version`, `Files`, `Dirs`, `Absent`, `Packages`.
  - `listingEntry` (`struct`, L56–61): `Name`, `Type`, `TargetType`, `Dangling`.
  - `listingShape` (`var string`, L72): Structural reflection hash of `listingRecord`.
  - `listingSourceExts` (`var map[string]bool`, L114–119).
- **Functions & Methods**:
  - `(listingEntry).regular() bool` (L63–65), `typeShape(t reflect.Type) string` (L74–110), `(*Hasher).listingScope() string` (L125–137), `(*Hasher).loadListing(pkgPath string) ([]listPkg, bool)` (L143–179), `(*Hasher).storeListing(pkgPath string, pkgs []listPkg)` (L184–195), `(*Hasher).listingInputs(pkgPath string, pkgs []listPkg) (*listingRecord, bool)` (L211–428), `embedRoots(dir string, patternSets ...[]string) []string` (L434–455), `listingEntries(dir string) ([]listingEntry, error)` (L459–480).

---

### 1.13 `closure/memo.go` (L1–265)

Store management facades (`SetMemoRoot`, `PruneMemos`, etc.), test-binary closure key derivation, and persistent memo helpers for observability proofs, view scan facts, and rooted-function inventories.

- **Types & Constants**:
  - `DefaultMemoMaxBytes = cachefile.DefaultMaxBytes` (`const`, L50).
  - `MemoPruneReport = cachefile.PruneReport` (type alias, L53).
  - `observabilityDirName = "observability"` (`const`, L77), `scanFactsDirName = "scanfacts"` (`const`, L172), `rootedDirName = "rooted"`, `binaryRootedDirName = "binaryrooted"` (`const`, L206–209).
- **Functions & Methods**:
  - `(*Hasher).SetAnalysisScope(scope AnalysisScope) AnalysisScope` (L28–35).
  - `SetMemoRoot(dir string)` (L44–46), `SetMemoMaxBytes(maxBytes int64)` (L59–61), `PruneMemos(maxBytes int64) (MemoPruneReport, error)` (L65–67), `PreviewPruneMemos(maxBytes int64) (MemoPruneReport, error)` (L71–73).
  - `loadMemo(scope, closureKey string) map[string]Observability` (L81–87), `storeMemo(scope, closureKey string, proofs map[string]Observability)` (L92–94), `(*Hasher).groupMemo(pkgPath string)` (L195–204).
  - `(*Hasher).testBinaryClosureKey(pkgPath string) (string, error)` (L106–124), `(*Hasher).sourceSpellingKey(pkgPath string) (string, error)` (L130–158), `(*Hasher).PackageScanKey(pkgPath string) (string, error)` (L165–167).
  - `LoadScanFacts(scope, key string, payload any) bool` (L176–181), `StoreScanFacts(scope, key string, payload any)` (L185–190).
  - `loadRootedMemo` (L211–223), `storeRootedMemo` (L225–227), `(*Hasher).rootedGroupMemo` (L229–238), `loadBinaryRootedMemo` (L240–249), `storeBinaryRootedMemo` (L251–253), `(*Hasher).binaryRootedMemo` (L255–265).

---

### 1.14 `closure/policymemo.go` (L1–79)

In-memory single-entry memo for `admissionPolicy()`.

- **Types**:
  - `policyMemo` (`struct`, L14–18): `mu sync.Mutex`, `key [sha256.Size]byte`, `result string`.
- **Functions & Methods**:
  - `(*policyMemo).value(in policyInputs) string` (L20–34): Mutex-guarded lookup/store by `in.key()`.
  - `(policyInputs).key() [sha256.Size]byte` (L39–79): Binary uvarint-framed SHA-256 over `policyInputs`.

---

### 1.15 `closure/programfacade.go` (L1–9)

- `type program = prog.Program` (type alias, L9).

---

### 1.16 `closure/propertyharness.go` (L1–293)

Audited property-testing harness (`pgregory.net/rapid`) admission rules and boundary argument/result closedness gates.

- **Constants & Variables**:
  - `auditedPropertyHarnessListing` (`var auditset.VersionListing`, L60): `{"pgregory.net/rapid": {"v1.3.0"}}`.
  - `propertyHarnessModulePath` (`const`, L63): `"pgregory.net/rapid"`.
- **Functions & Methods**:
  - `propertyHarnessPath(pkgPath string) bool` (L44–46), `auditedPropertyHarnessVersion(version string) bool` (L53–55), `auditedPropertyHarnessModule(version string, main, replaced bool) bool` (L70–72), `propertyHarnessFact() externalEffect` (L81–85).
  - `(*tier2Analyzer).propertyHarnessAudited(pkgPath string) bool` (L94–107), `propertyHarnessAuditedProg(p *program) bool` (L276–293).
  - `propertyHarnessHandleType(t types.Type) bool` (L119–135), `harnessHandleValue(v ssa.Value) bool` (L139–158), `propertyHarnessClosedValue(v ssa.Value, fp *freshParamAnalysis) bool` (L163–171), `harnessVariadicClosed(v ssa.Value, fp *freshParamAnalysis) bool` (L177–215), `propertyHarnessClosedArgs(c *ssa.CallCommon, fp *freshParamAnalysis) bool` (L222–235), `(*tier2Analyzer).localHarnessView() *freshParamAnalysis` (L242–247), `propertyHarnessClosedResult(call *ssa.Call, fp *freshParamAnalysis) bool` (L255–269).

---

### 1.17 `closure/rooted.go` (L1–414)

Post-initialization rooted-function inventories per subject (`ComputeRootedFunctions`) and per package test binary (`ComputeBinaryRootedFunctions`) for shared-dynamic-state reachability discharge.

- **Types**:
  - `RootedFunctions` (`struct`, L61–64): `Fns map[string]bool`, `Complete bool`.
- **Functions & Methods**:
  - `rootedFunctionKey(fn *ssa.Function) string` (L21–40): Formats `"<pkgPath>\x00<Name>"` or `"<pkgPath>\x00<Recv>.<Name>"`.
  - `(*Hasher).ComputeRootedFunctions(ctx context.Context, subjects []Subject) (map[Subject]RootedFunctions, error)` (L78–170) & `(*Hasher).rootedGroup(ctx context.Context, group *packageBatch, bp *batchPreparer, results map[Subject]RootedFunctions) error` (L192–245).
  - `rootedFunctionsFromReachability(reach attributedReachability) RootedFunctions` (L172–185).
  - `harnessRootName(name string) bool` (L253–268): Matches `Test*`, `Benchmark*`, `Fuzz*`, `Example*`.
  - `(*Hasher).ComputeBinaryRootedFunctions(ctx context.Context, pkgPaths []string) (map[string]RootedFunctions, error)` (L287–366) & `(*Hasher).binaryRootedPackage(ctx context.Context, path, closureHash string, bp *batchPreparer) (RootedFunctions, error)` (L371–414).

---

### 1.18 `closure/scope.go` (L1–125)

`AnalysisScope` identity rendering for all guard-dependent persistent memos.

- **Types & Constants**:
  - `AnalysisScope` (`struct`, L28–46): `ProofStrategy`, `FactStrategy`, `Toolchain`, `BuildConfig`, `SingleSubject`, `PackageProcess`, `Vouches`, plus unexported `toolchainContent`, `admissionPolicy`.
  - `rootedFunctionsStrategy` (`const`, L84): `"gofresh/rooted-functions@5"`.
- **Functions & Methods**:
  - `(AnalysisScope).guards() string` (L57–59), `(AnalysisScope).completeGuards() bool` (L61–63).
  - `(AnalysisScope).Proofs() string` (L67–72), `(AnalysisScope).TestingScan() string` (L77–82), `(AnalysisScope).Rooted() string` (L89–94), `(AnalysisScope).Facts() string` (L100–111), `(AnalysisScope).Scan() string` (L117–125).

---

### 1.19 `closure/viewload.go` (L1–89)

Shared `go/packages` typed loader (`ViewLoad`) for a coherent single-generation observation pass.

- **Types**:
  - `ViewLoad` (`struct`, L19–21): `pkgs []*packages.Package`.
- **Functions & Methods**:
  - `(*ViewLoad).Packages() []*packages.Package` (L25–30).
  - `LoadViewPackages(ctx context.Context, reader *gotool.EnvReader, buildFlags []string, pkgPaths ...string) (*ViewLoad, error)` (L37–44): Loads root syntax/types without `NeedDeps`.
  - `LoadViewGraph(ctx context.Context, reader *gotool.EnvReader, buildFlags []string, pkgPaths ...string) (*ViewLoad, error)` (L52–54): Loads whole dependency graph syntax/types (`NeedDeps`).
  - `loadView(ctx context.Context, reader *gotool.EnvReader, buildFlags []string, deps bool, pkgPaths ...string) (*ViewLoad, error)` (L56–89).

---

### 1.20 `closure/testvariant/testvariant.go` (L1–752)

Public test-variant compartment ledger types, diffing (`DiffTestVariantLedgers`), package-wide inertness (`TestVariantDelta.Inert`), and per-subject cone inertness (`InertForSubject`).

- **Types & Constants**:
  - `BindingStrategy` (`const`, L20): `"gofresh/test-variant-bindings@1"`.
  - `EmptyTestVariantClosure` (`const`, L29): `"e3b0c44298fc1c149afbf4c8996fb924"`.
  - `TestVariantLedger` (`struct`, L39–53): `BindingStrategy`, `BaseFiles`, `Declarations`, `FileHeaders`.
  - `TestVariantDeclaration` (`struct`, L70–105): `File`, `Kind`, `Name`, `Receiver`, `Hash`, `Package`, `References`.
  - `TestVariantFileHeader` (`struct`, L114–121): `File`, `Hash`, `Embedded`, `Bindings`.
  - `TestVariantFileBindings` (`struct`, L128–132): `Package`, `References`, `Imports`.
  - `TestVariantImport` (`struct`, L136–139): `Name`, `Path`.
  - `TestVariantDelta` (`struct`, L147–158): `BindingsPreserved`, `Added`, `Changed`, `Removed`, `HeaderChanges`.
  - `TestVariantDeclarationChange` (`struct`, L162–165), `TestVariantHeaderChange` (`struct`, L170–175).
  - `declarationIdentity` (`struct`, L239–241).
- **Functions & Methods**:
  - `inertAddedDeclaration(added TestVariantDeclaration) bool` (L208–217).
  - `(TestVariantDelta).Inert() bool` (L219–237).
  - `idOfDeclaration(d TestVariantDeclaration) declarationIdentity` (L243–245), `receiverTypeName(recv string) string` (L247–271).
  - `InertForSubject(before, after TestVariantLedger, subjectSymbol string) bool` (L288–526).
  - `DiffTestVariantLedgers(before, after TestVariantLedger) TestVariantDelta` (L535–629).
  - `LessDeclaration(a, b TestVariantDeclaration) bool` (L633–646).
  - `(TestVariantLedger).Clone() TestVariantLedger` (L649–660), `cloneHeaders` (L662–673), `ledgerFileBindings` (L675–702), `fileImportsMap` (L704–712), `bindingsPreserved` (L714–752).

---

### 1.21 `closure/internal/cachefile/cachefile.go` (L1–375)

On-disk JSON envelope cache store with atomic temp-file rename and LRU/mtime/seq retention pruning.

- **Types, Constants & Variables**:
  - `DefaultMaxBytes` (`const`, L30): `2 << 30` (2 GiB).
  - `PruneReport` (`struct`, L33–40): `Root`, `UsedBytes`, `ReclaimedBytes`, `RemainingBytes`, `RemovedEntries`, `SkippedEntries`.
  - `configMu`, `rootDir`, `maxBytes`, `pruneMu`, `knownRoot`, `knownBytes`, `knownValid`, `nextSeq`, `writeSeq` (`var`, L47–58).
  - `Envelope` (`struct`, L107–111): `Scope`, `Key`, `Payload`.
  - `diskEntry` (`struct`, L245–250): `path`, `size`, `modTime`, `seq`.
- **Functions**:
  - `SetRoot(dir string)` (L62–71), `SetMaxBytes(limit int64)` (L76–87), `MaxBytes() int64` (L91–95), `storeRoot() (string, error)` (L97–104).
  - `Path(dirName, scope, key string) (string, error)` (L114–121), `Load(dirName, scope, key string, payload any) bool` (L125–139), `Merge[T any](dirName, scope, key string, additions map[string]T)` (L144–156), `Store(dirName, scope, key string, payload any)` (L161–196).
  - `recordWriteAndEnforce(gofreshRoot, path string, size int64)` (L198–212), `Prune(maxBytes int64) (PruneReport, error)` (L219–229), `PreviewPrune(maxBytes int64) (PruneReport, error)` (L233–243), `pruneDirLocked(...)` (L252–375).

---

### 1.22 `closure/internal/compartment/compartment.go` (L1–462)

Test-variant compartment computation (`ComputeIdentity`, `AddBaseBindings`, `parseTestVariantFile`).

- **Types**:
  - `Identity` (`struct`, L29–34): `Hash`, `Ledger`, `dir`, `Files`.
  - `Source` (`interface`, L60–62) & `osSource` (`struct`, L64).
  - `ParseMemo` (`interface`, L78–81).
- **Functions & Methods**:
  - `OwnVariantOf(p listing.Package, pkgPath, baseDir string) bool` (L47–56).
  - `(osSource).ReadFile(path string) ([]byte, [32]byte, error)` (L66–72).
  - `ComputeIdentity(dir string, files []string, compiledGo, embeddedData map[string]bool, digests map[string]string, source Source, memo ParseMemo) (Identity, error)` (L94–162).
  - `AddBaseBindings(identity *Identity, baseGo []string, importNames map[string]string, source Source, memo ParseMemo) error` (L167–213).
  - `positionalDigest(content []byte, ordinal int) string` (L220–225), `referencedNames(node ast.Node) []string` (L232–247), `mergedNames(a, b []string) []string` (L250–266), `parseTestVariantFile(name string, content []byte) ([]testvariant.TestVariantDeclaration, testvariant.TestVariantFileHeader, error)` (L275–462).

---

### 1.23 `closure/internal/digest/digest.go` (L1–18)

- `Content(content []byte) string` (L10–12) & `FromSum(sum [32]byte) string` (L16–18): 32-hex-char SHA-256 truncation.

---

### 1.24 `closure/internal/listing/listing.go` (L1–121)

`go list -json -deps -test` JSON stream parser and model.

- **Types**:
  - `Package` (`struct`, L13–46), `Module` (`struct`, L63–69), `Error` (`struct`, L72–74).
- **Functions & Methods**:
  - `(Package).SourcePath() string` (L51–54), `(Package).IsGeneratedTestMainFor(pkgPath string) bool` (L58–60), `(Package).SourceFiles() []string` (L79–88).
  - `Parse(r io.Reader) ([]Package, error)` (L93–107), `UniqueStrings(values []string) []string` (L110–121).

---

### 1.25 `closure/internal/program/program.go` (L1–410)

Whole-program SSA loader (`Load`, `Prepare`/`Build`) and subject root indexer.

- **Types**:
  - `Program` (`struct`, L25–41): `PkgPath`, `Prog`, `Pkgs`, `Roots`, `Ambiguous`, `TestMain`, `PkgScopeProbe`.
  - `Prepared` (`struct`, L59–62): `roots`, `errs`.
- **Functions & Methods**:
  - `Load(ctx context.Context, dir string, env, buildFlags []string, pkgPath string) (*Program, error)` (L44–50).
  - `Prepare(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*Prepared, error)` (L69–155), `(*Prepared).Build(ctx context.Context, pkgPath string) (*Program, error)` (L161–174), `(*Prepared).HasRoots(pkgPath string) bool` (L180–186), `(*Prepared).Release(pkgPath string)` (L190–194).
  - `load(ctx context.Context, dir string, env, flags, paths []string) ([]*packages.Package, error)` (L197–206), `build(ctx context.Context, pkgPath string, roots []*packages.Package) (*Program, error)` (L213–391), `isTestMainHarness(pkg *packages.Package, function *types.Func) bool` (L393–410).

---

### 1.26 `closure/internal/rta/rta.go` (L1–653)

Bitmask-attributed Rapid Type Analysis (up to 64 subjects per pass).

- **Types**:
  - `Result` (`struct`, L21–25): `Reachable`, `Resolved`, `Targets`.
  - `attributedRTA` (`struct`, L29–54), `attributedConcreteTypeInfo` (`struct`, L69–74), `attributedInterfaceTypeInfo` (`struct`, L76–80).
  - `Seeds` (`struct`, L267–270) & `TypeSeed` (`struct`, L274–277).
- **Functions & Methods**:
  - `Analyze(ctx context.Context, roots map[*ssa.Function]uint64, seeds *Seeds) (*Result, error)` (L288–409).
  - `ContainsTypeParam(t types.Type, seen map[types.Type]bool) bool` (L455–535).
  - `(*attributedRTA).addResolvedTarget` (L56–67), `(*attributedRTA).addReachable` (L82–100), `(*attributedRTA).visitAddrTakenFunc` (L103–133), `(*attributedRTA).visitDynCall` (L135–156), `(*attributedRTA).addInvokeEdge` (L158–168), `(*attributedRTA).visitInvoke` (L170–189), `(*attributedRTA).visitFunc` (L191–223), `onlyDirectCallCallee(mk *ssa.MakeClosure) bool` (L228–254), `(*attributedRTA).interfaces` (L411–427), `(*attributedRTA).implementations` (L429–445), `(*attributedRTA).addRuntimeType` (L542–634), `attributedFingerprint(mset *types.MethodSet) uint64` (L636–649), `attributedImplements` (L651–653).

---

## 2. Public Surface Analysis (`closure` and `closure/testvariant`)

Because `closure` and `closure/testvariant` are non-`internal` packages at the module root (`github.com/greatliontech/gofresh/closure` and `github.com/greatliontech/gofresh/closure/testvariant`), every exported identifier in these files is part of the public Go library API unless moved or unexported.

### 2.1 `closure` Exported Symbols in Scope 04a

| Symbol | File | Actual Consumer | Surface Classification |
| :--- | :--- | :--- | :--- |
| `Closure` (`struct`) | `closure.go` | Root `gofresh` + external callers | **Domain-essential** (though `Refusal` and `Culprit` are consumer-tier view fields bolted onto the lower-tier `Closure` struct). |
| `RefusalKind` + 4 consts | `closure.go` | Root `gofresh` (`view.go`) | **Cross-tier coupling**: `Closure` computation in `closure` never sets `OpenWorldRefusal`, `SharedDynamicStateRefusal`, or `AmbiguousSubjectRefusal`; root `gofresh` mutates `Closure.Refusal` and `Closure.Culprit` after the fact. |
| `Hasher` (`struct`) | `closure.go` | Root `gofresh` + external callers | **Domain-essential**, but carries 10+ exported plumbing methods only used by root `gofresh` to coordinate pass state. |
| `NewAt` | `closure.go` | Root `gofresh` + external callers | **Domain-essential** constructor. |
| `NewBracketAt` | `closure.go` | Root `gofresh` (`bracket.go`) | **Internal plumbing** for observation brackets (`GOFLAGS` live validation vs base `GOMODCACHE`). |
| `(*Hasher).ComputeMaximalBatch` | `maximal.go` | Root `gofresh` + external callers | **Domain-essential** Tier-1 entry point. |
| `(*Hasher).ComputeMaximalFactsBatch` | `maximal.go` | Root `gofresh` + external callers | **Domain-essential** Tier-1 structured facts entry point. |
| `MaximalIdentity`, `BlockerKind` (+13 consts), `Blocker`, `MaximalFacts` (+`Clone`, `Closure`, `Equal`) | `maximal_facts.go` | Root `gofresh` + external callers | **Domain-essential** structured maximal closure representation. |
| `Subject`, `Observability`, `ImmutableEnvironmentOutcomes`, `(*Hasher).ComputeObservabilityBatch` | `observability.go` | Root `gofresh` + external callers | **Domain-essential** Tier-2 observability entry point. |
| `IdentityStrategy` | `closure.go` | Root `gofresh` | **Leaked version constant** used by root `gofresh` to stamp records. |
| `AnalyzingFrontend()` | `frontend.go` | Root `gofresh` | **Leaked internal helper** (`runtime.Version()`). |
| `PurityResponsibility` | `effects.go` | Root `gofresh` | **Leaked diagnostic string constant** shared between `closure` and root `gofresh`. |
| `(*Hasher).ToolchainContent()`, `(*Hasher).AdmissionPolicy()` | `dependencies.go` | Root `gofresh` | **Domain-essential** guard accessors. |
| `(*Hasher).UseViewLoad`, `ViewLoad`, `(*ViewLoad).Packages`, `LoadViewPackages`, `LoadViewGraph` | `closure.go`, `viewload.go` | Root `gofresh` | **Leaked internal plumbing**: exposes `go/packages.Package` AST/type trees across the `closure` ↔ `gofresh` package boundary because `gofresh`'s view/dynamic-state scanner lives in the root package instead of inside `closure` (or an internal package). |
| `(*Hasher).PassReader()`, `(*Hasher).FileDigest(path)`, `(*Hasher).BoundAnalysis(ctx)` | `closure.go` | Root `gofresh` | **Leaked pass-coordination plumbing** between `gofresh` and `closure`. |
| `(*Hasher).OnDiagnostic`, `(*Hasher).OnProgress`, `(*Hasher).OnUnit`, `(*Hasher).Unit`, `(*Hasher).Served`, `(*Hasher).ServedSummary`, `(*Hasher).Persisted` | `closure.go` | Root `gofresh` | **Leaked telemetry/progress plumbing**. Notably `(*Hasher).Unit(...)` and `(*Hasher).Served(...)` are exported solely so root `gofresh` can push its own events into `Hasher`'s counters/callbacks! |
| `PackageClass` (+3 consts), `GraphPackage`, `(*Hasher).GraphMetadata` | `dynamicstate.go` | Root `gofresh` | **Leaked internal plumbing** so root `gofresh`'s dynamic-state scanner can inspect `closure`'s `go list` graph without accessing `listing.Package`. |
| `LoadDynamicStateFacts`, `StoreDynamicStateFacts` | `dynamicstate.go` | Root `gofresh` | **Leaked cachefile plumbing**: `closure` does not even compute dynamic-state facts; it exports raw `cachefile` wrappers (`map[string]json.RawMessage`) for root `gofresh` because `cachefile` is under `closure/internal/cachefile`! |
| `(*Hasher).PackageScanKey`, `LoadScanFacts`, `StoreScanFacts` | `memo.go` | Root `gofresh` | **Leaked cachefile plumbing**: again, `closure` does not compute view scan facts (`payload any`), yet exports `LoadScanFacts`/`StoreScanFacts` solely because `cachefile` is imprisoned inside `closure/internal/cachefile`. |
| `AnalysisScope` (+`Proofs`, `TestingScan`, `Rooted`, `Facts`, `Scan`), `(*Hasher).SetAnalysisScope` | `scope.go`, `memo.go` | Root `gofresh` | **Leaked memo-key plumbing** coordinating memo scopes across `closure` and `gofresh`. |
| `SetMemoRoot`, `DefaultMemoMaxBytes`, `MemoPruneReport`, `SetMemoMaxBytes`, `PruneMemos`, `PreviewPruneMemos` | `memo.go` | Root `gofresh` + CLI + tests | Re-exports of `closure/internal/cachefile` functions. |
| `RootedFunctions`, `(*Hasher).ComputeRootedFunctions`, `(*Hasher).ComputeBinaryRootedFunctions` | `rooted.go` | Root `gofresh` | **Split-brain plumbing**: `closure` computes RTA function-key sets (`"path\x00Recv.Name"`) and exports them so root `gofresh` can intersect them with dynamic-state mutation sites. |
| `(*Hasher).ReadFile(path)` | `filememo.go` | `closure/internal/compartment` | **Accidental public export**: exported only to satisfy `compartment.Source` (`ReadFile(path string) ([]byte, [32]byte, error)`), leaking `Hasher.ReadFile` onto the public `Hasher` API! |
| `(*Hasher).TestVariantLedger(pkgPath)` | `filememo.go` | Root `gofresh` + external callers | **Domain-essential** for consumers of `testvariant`. |

### 2.2 `closure/testvariant` Exported Surface

`closure/testvariant` exports 2 constants (`BindingStrategy`, `EmptyTestVariantClosure`), 7 structs (`TestVariantLedger`, `TestVariantDeclaration`, `TestVariantFileHeader`, `TestVariantFileBindings`, `TestVariantImport`, `TestVariantDelta`, `TestVariantDeclarationChange`, `TestVariantHeaderChange`), and 5 functions/methods (`(TestVariantDelta).Inert`, `InertForSubject`, `DiffTestVariantLedgers`, `LessDeclaration`, `(TestVariantLedger).Clone`).
- **Stuttering names**: Every type in package `testvariant` is prefixed with `TestVariant*` (`testvariant.TestVariantLedger`, `testvariant.TestVariantDeclaration`, `testvariant.TestVariantDelta`, etc.).
- **Split-brain package boundary**: `closure/testvariant` holds the types and diff/inertness logic, while `closure/internal/compartment` holds the parser (`parseTestVariantFile`) and builder (`ComputeIdentity`, `AddBaseBindings`) that construct those exact types.

---

## 3. Architectural Audit & Consolidation Opportunities

### 3.1 The Fragmented Memo Subsystem (8 Files Across `closure` + `cachefile`)

Persistent and in-memory memoization in `closure` is currently scattered across **8 files in `closure`** plus `closure/internal/cachefile`:
1. `closure/internal/cachefile/cachefile.go`: Low-level on-disk store (`Load`, `Store`, `Merge`, `Prune`, `PreviewPrune`, `SetRoot`, `SetMaxBytes`).
2. `closure/memo.go`: Re-exports `cachefile` controls (`SetMemoRoot`, `PruneMemos`, etc.), defines `testBinaryClosureKey`/`sourceSpellingKey`/`PackageScanKey`, and implements 4 memo classes (`observability`, `scanfacts`, `rooted`, `binaryrooted`).
3. `closure/effectmemo.go`: Implements 2 memo classes (`effectscan` and `testingscan`) sharing `effectScanPayload`/`effectScanEffect`.
4. `closure/filememo.go`: Defines `dirMemo[T]` (a generic per-directory batched `cachefile.Load`/`cachefile.Merge` wrapper) and instantiates 3 per-directory memo classes (`filescan`, `variantparse`, `canonical`). Also holds `fileBytes`/`readBytes`/`(*Hasher).readFile` and `(*Hasher).TestVariantLedger`.
5. `closure/canonical.go`: Defines `canonicalDirName`, `canonicalScope()`, and `(*Hasher).canonicalFileDigest` reaching into `h.fileMemo.canonical`.
6. `closure/dynamicstate.go`: Defines `dynamicStateDirName` (`"dynamicstate"`) and exports `LoadDynamicStateFacts` / `StoreDynamicStateFacts` for root `gofresh`.
7. `closure/listingmemo.go`: Defines `listingDirName` (`"listing"`), `typeShape` reflection hashing, `listingInputs` filesystem/modfile modeling, and `loadListing`/`storeListing`.
8. `closure/scope.go`: Defines `AnalysisScope` and 5 scope-string renderers (`Proofs`, `TestingScan`, `Rooted`, `Facts`, `Scan`), while `effectScanScope()`, `canonicalScope()`, `variantParseScope()`, and `listingScope()` live outside `scope.go` in `effectmemo.go`, `canonical.go`, `filememo.go`, and `listingmemo.go`!
9. `closure/policymemo.go` + `closure/dependencies.go`: Defines a custom `sync.Mutex`-protected single-slot binary-keyed cache (`policyMemo`) for `admissionPolicy()`, even though `policyInputs.derive()` just JSON-marshals and SHA-256-hashes static maps (and `policyInputs.key()` in `policymemo.go` already serializes every map entry into a `[]byte` and SHA-256-hashes it on every single call, doing 95% of the work of `derive()` just to compute the cache lookup key!).

#### Concrete Defects & Consolidation Opportunities in Memos:
- **Redundant work in `policymemo.go` (`policyInputs.key()` vs `policyInputs.derive()`)**:
  On every `NewAt` call, `admissionPolicy()` calls `capturePolicyInputs()`, which clones 22 maps (`dependencies.go:34-104`), then calls `sourcePolicyMemo.value(in)`. Inside `value(in)`, `in.key()` (`policymemo.go:39-79`) sorts all map keys, serializes every string and bool into a `[]byte`, and computes `sha256.Sum256(data)`. Only if `key != m.key` does it call `in.derive()`, which sorts `in.seeds`, calls `json.Marshal`, and computes `sha256.Sum256`! Because `capturePolicyInputs()` + `in.key()` already clones, sorts, serializes, and hashes all inputs on every call, `policyMemo` saves virtually nothing (only the `json.Marshal` allocation) while adding `policymemo.go` (80 lines) and a mutex. Either compute the policy digest directly in `derive()` without `policymemo.go`, or compute it once unless a test mutates a table.
- **Misplaced `cachefile` ownership (`closure/internal/cachefile` vs `internal/cachefile`)**:
  Because `cachefile` is placed at `closure/internal/cachefile`, root `gofresh` cannot import it. Consequently, `closure` is forced to export `LoadDynamicStateFacts`, `StoreDynamicStateFacts`, `LoadScanFacts`, `StoreScanFacts`, `SetMemoRoot`, `SetMemoMaxBytes`, `PruneMemos`, and `PreviewPruneMemos` in its public API. Moving `cachefile` to top-level `internal/cachefile` (or moving `gofresh`'s dynamic-state/view scan into `closure`) immediately eliminates `LoadDynamicStateFacts`, `StoreDynamicStateFacts`, `LoadScanFacts`, and `StoreScanFacts` from `closure`'s exported surface.
- **Split-brain scope rendering (`scope.go` vs scattered `*Scope()` functions)**:
  `AnalysisScope` in `scope.go` renders scopes for 5 memos (`Proofs`, `TestingScan`, `Rooted`, `Facts`, `Scan`), while 4 other memos render their scopes ad-hoc on `Hasher` or as free functions (`h.effectScanScope()` in `effectmemo.go:71`, `canonicalScope()` in `canonical.go:265`, `variantParseScope()` in `filememo.go:42`, `h.listingScope()` in `listingmemo.go:125`). Notice the subtle discrepancy:
  - `AnalysisScope.guards()` includes `s.Toolchain + "|" + s.BuildConfig + "|" + AnalyzingFrontend() + "|" + s.toolchainContent + "|" + s.admissionPolicy` (where `s.admissionPolicy` has `"|unaudited"` appended in `SetAnalysisScope` when `!h.SelectionAudited()`).
  - `h.effectScanScope()` (`effectmemo.go:71-80`) manually concatenates `effectScanStrategy + " " + AnalyzingFrontend() + "|" + h.ToolchainContent() + "|" + h.AdmissionPolicy()` and appends `"|unaudited"` when `!h.SelectionAudited()`.
  Unifying all memo scope definitions in `scope.go` (or a single `memo.go`) eliminates duplicated `"|unaudited"` and frontend-version concatenation rules.
- **Duplicate `Complete && Fns == nil` post-load fixup in `memo.go`**:
  In `memo.go`, both `loadRootedMemo` (L216–220) and `loadBinaryRootedMemo` (L245–247) manually patch `if inv.Complete && inv.Fns == nil { inv.Fns = map[string]bool{} }` after JSON unmarshaling because `json.Unmarshal` decodes an empty JSON `{}` map or omitted field into `nil` if not initialized, or rather `map[string]bool{}` marshals as `{}` which unmarshals to non-nil empty map, except if `Fns` was `nil` when marshaled (`null`). Putting a helper or custom unmarshaler/normalizer on `RootedFunctions` avoids duplicating this across loaders.

---

### 3.2 `Hasher` State Management & Lifetime Hygiene

`Hasher` (`closure.go:90-164`) has grown into a 23-field god-object mixing 4 distinct lifetimes:
1. **Immutable construction state**: `dir`, `modCache`, `env`, `packageEnv`, `runner`, `buildFlags`, `snapshot`, `selectionResolved`, `selection`, `source`.
2. **Pass-mutable configuration & callbacks**: `ctx` (mutated by `BoundAnalysis` and temporarily swapped in `ComputeRootedFunctions` / `ComputeBinaryRootedFunctions`!), `scope`, `viewLoad`, `progress`, `diagnostic`, `unit`.
3. **Hasher-lifetime caches & counters**: `progs`, `progErrs`, `lists`, `maximalTesting`, `maximalEffects`, `maximalFiles`, `testVariants`, `fileDigests`, `fileMemo`, `persisted`, `served`.
4. **Per-batch-call ephemeral state** (armed in `resetCallScope()`, partially cleared in `defer func() { h.contents = nil }()`): `contribs`, `testBinaryKeys`, `variantScope`, `contents`.

#### Concrete Defects & Consolidation Opportunities in `Hasher`:
- **Asymmetric `resetCallScope()` cleanup**:
  `resetCallScope()` (`closure.go:579-587`) initializes four maps (`h.contribs`, `h.testBinaryKeys`, `h.variantScope`, `h.contents`), and the comment on `contribs` (`closure.go:127-131`) states: *"each public batch entry resets it, so content is re-observed per call (the Hasher's pinned contract)"*. However:
  1. When a batch call finishes, only `h.contents = nil` is deferred (`maximal.go:60`, `observability.go:239`, `rooted.go:80`, `rooted.go:289`); `h.contribs`, `h.testBinaryKeys`, and `h.variantScope` remain populated on `h` after the batch call returns! (See the defensive comment in `TestVariantLedger` at `filememo.go:260-265` noting that `h.contribs` can hold stale entries from a prior batch call).
  2. Furthermore, `h.lists`, `h.maximalEffects`, `h.maximalFiles`, `h.maximalTesting`, `h.testVariants`, and `h.fileDigests` are **never** reset in `resetCallScope()`! Thus, despite the comment claiming *"each public batch entry resets it, so content is re-observed per call (the Hasher's pinned contract)"*, `h.lists[pkgPath]`, `h.maximalEffects[pkgPath]`, and `h.maximalFiles[cacheKey]` remain cached across calls on the same `Hasher`. Grouping per-call state into a stack-allocated `callScope` struct (created at the start of a batch call and passed or attached for the duration of the call) would make lifetime invariants structural rather than relying on manual `resetCallScope()` + partial `defer` cleanup.
- **Temporarily mutating `h.ctx` in `ComputeRootedFunctions` and `ComputeBinaryRootedFunctions`**:
  In `rooted.go:81-83` and `rooted.go:290-292`:
  ```go
  prevCtx := h.ctx
  h.ctx = ctx
  defer func() { h.ctx = prevCtx }()
  ```
  `h.ctx` is mutated in-place so callees like `h.list()` / `h.testBinaryClosureKey()` observe `ctx` instead of `h.ctx`. Passing `ctx` explicitly (or binding it to the `callScope`) avoids mutating `Hasher` state mid-flight.
- **Duplicated environment normalization and build-flag validation across `NewAt`, `NewBracketAt`, and `loadView`**:
  `NewAt` (`closure.go:320-343`), `NewBracketAt` (`closure.go:269-289`), and `loadView` (`viewload.go:56-77`) all repeat the exact same nil checks, `gotool.NormalizeEnv`, `gotool.EnvForPackages`, and `buildflags.Validate` sequence.

---

### 3.3 Duplication and Structural Overlap Across `maximal.go`, `observability.go`, `rooted.go`, and `closure.go`

1. **Triplicated Batch-Preparation & Package-Grouping Loop (`observability.go` vs `rooted.go`)**:
   `ComputeObservabilityBatch` (`observability.go:236-328`), `ComputeRootedFunctions` (`rooted.go:78-169`), and `ComputeBinaryRootedFunctions` (`rooted.go:287-365`) all implement the exact same 90-line pattern:
   - Deduplicate inputs and group by package into `groups []*packageBatch` (or `paths []string`).
   - Define a closure `resolveGroupMemo` that lazily computes `testBinaryClosureKey(pkgPath)` and loads the persistent memo.
   - Construct a `&batchPreparer{h: h, candidates: func() []string { ... }}` that scans `groups[currentIdx:]`, skipping `h.progs`, `h.progErrs`, and fully memoized groups.
   - Iterate `for i, group := range groups`, advancing `currentIdx = i`, serving memo hits, recording `h.Served(...)`, and invoking the per-group SSA builder (`observabilityGroup`, `rootedGroup`, `binaryRootedPackage`) which calls `h.loadCachedFrom(ctx, path, bp)` and `defer h.releaseProgram(path)`.
   This 3x-duplicated batch scheduler can be consolidated into a single generic package-batch runner on `Hasher`.

2. **Chain of 4 Wrapper Functions in `maximal.go` (Vestigial Scaffolding)**:
   - `maximalFileEffectsCached` → `maximalFileEffectsCachedWithNames` → `maximalFileEffectsCachedWithContext` (`maximal.go:226-234`).
   - `maximalFileEffects` → `maximalFileEffectsContent` → `maximalFileEffectsContentWithNames` → `maximalFileEffectsContentWithNamesFiltered` → `maximalFileEffectsContentWithContextFiltered` (`maximal.go:448-472`).
   - `pinnedEffectScan` → `pinnedEffectScanWithNames` → `pinnedEffectScanWithContext` (`maximal.go:1432-1440`).
   - `declaredOverridesKey(declaredNames)` → `scanOverridesKey(declaredNames, nil)` (`maximal.go:1365-1367`).
   - `trueReason(pkgPath)` → `trueExternalEffect(pkgPath).reason` (`maximal.go:1395-1397`).
   - `impPkgPathOr(pkgPath string) string { return pkgPath }` (`maximal.go:668`) — a pure no-op identity function!
   Most of these intermediate wrapper functions have zero production callers (existing only for legacy unit tests that predated `declaredNames`, `nonStdPaths`, or `reachedDecls`).

3. **Duplicate `unwrapASTParen` vs `unwrapParen` in the Same File (`maximal.go`)**:
   In `maximal.go`, `unwrapASTParen(expr ast.Expr) ast.Expr` (L670–678) and `unwrapParen(expression ast.Expr) ast.Expr` (L1116–1124) are character-for-character identical functions in the exact same file!

4. **Redundant Second AST Walk in `testingMethodEffectsFiltered` (`maximal.go:980-1070`)**:
   In `testingMethodEffectsFiltered` (`maximal.go:898-1073`), for each `*ast.FuncDecl`, after computing `receivers` and `parents`:
   - Walk 1 (L980–1020) inspects `function.Body` to collect all `effects` (`escape` and `classBEffect("testing", selector.Sel.Name)`).
   - Walk 2 (L1021–1070) immediately inspects `function.Body` a second time with the exact same `switch` and `SelectorExpr` logic solely to compute `reason` (the legacy testing reason return value of `testingMethodEffectsFiltered`)!
   Worse yet: look at the single production caller of `testingMethodEffectsFiltered` at `maximal.go:657`:
   ```go
   testingEffects, _ := testingMethodEffectsFiltered(file, stdAliases, unreachedDecls)
   ```
   Production code **discards** the second return value (`reason`) because `maximalFileEffectsContentWithContextFiltered` derives `scan.preferred` from `preferredEffectReason(scan.effects...)`! The entire 50-line second AST walk (`maximal.go:1021-1070`) is dead work in production, kept alive only for `testingMethodEffects` in tests.

5. **Duplicate `maximalTestingTypeEffects` vs `maximalTestingTypeEffectsFiltered` (`maximal.go:315-393` vs `L818-884`)**:
   `maximalTestingTypeEffects` and `maximalTestingTypeEffectsFiltered` duplicate the `SelectorExpr` + `TypesInfo.Selections` / `TypesInfo.Uses` AST walk over `pkg.Syntax`. `maximalTestingTypeEffects` is simply `maximalTestingTypeEffectsFiltered` with `reachedDecls == nil` (plus the persistent memo read/write).

6. **Duplicate Fold Closure in `pinnedEffectScanWithContext` (`maximal.go:1450-1494`)**:
   Inside `pinnedEffectScanWithContext`, the closure `fold(scan maximalEffectScan)` (L1450–1460) and the inline loop body folding `scan` into `fileFold` (L1482–1491) are identical 10-line effect/importCandidate/preferred folding blocks, which also duplicate `record` in `maximalExternalEffects` (`maximal.go:147-158`). A single method `(*maximalEffectScan).merge(other maximalEffectScan)` would replace all three copies.

7. **Duplicate Import-Name Map Construction (`closure.go:445-456` vs `maximal.go:1327-1344`)**:
   In `maximalContributionsAndFiles` (`closure.go:445-456`), `importNames` is built from `pkgs` by mapping `p.SourcePath()` to `p.Name` and setting `""` on disagreement. In `maximal.go:1327-1344`, `listedDeclaredNames(pkgs)` does the exact same thing (skipping `main` and `_test` packages).

8. **Duplicate `parameterizedBody` (`observability.go:32-50` vs `closure/internal/rta/rta.go:326-340`)**:
   `parameterizedBody(fn *ssa.Function)` in `observability.go:32-50` and the parameterized-root check in `rta.Analyze` (`rta.go:326-340`) implement the exact same 15-line check (`fn.TypeParams().Len() > 0 || (fn.Signature != nil && fn.Signature.RecvTypeParams() != nil)`, `fn.TypeArgs()`, `rta.ContainsTypeParam`). Exporting `rta.Parameterized(fn *ssa.Function) bool` from `closure/internal/rta` eliminates the duplication.

9. **Duplicate Startup vs Test-Main SSA Walk Scaffolding (`observability.go:651-700` vs `L750-817`)**:
   `testMainObservedEffects` and `directExternalEffects` in `observability.go` share 85% of their instruction-loop body: filtering `idxForFunction`, recording `addValueType` on instructions and operands, calling `recordFlagBackedReferences`, and iterating `StaticCallee()` and `narrowedTargets`.

10. **420 Lines of C/C++/Cgo `#include` Lexer/Parser Embedded in `closure/closure.go` (`L822–1263`)**:
    Nearly a third of `closure/closure.go` (440 lines: `resolveReal`, `cgoIncludeRootOutsideDir`, `cgoIncludeFlagDirs`, `cgoIncludeSearchDirs`, `cgoEscapingIncludeWith`, `spliceCPreprocessorLines`, `goCgoPreamble`, `stripCComments`, `cgoIncludeDirective`, `symlinkDirInPath`, etc.) is a standalone C preprocessor `#include` and `-I` flag escape analyzer. Extracting this into its own file (`closure/cgo_includes.go`) would make `closure.go` focused on `Hasher` lifecycle and contribution folding.

---

### 3.4 `closure/internal/compartment` vs `closure/testvariant` vs `closure/canonical.go`

1. **Artificial Split Between `closure/internal/compartment` and `closure/testvariant`**:
   - `closure/testvariant` defines the data structures (`TestVariantLedger`, `TestVariantDeclaration`, `TestVariantFileHeader`, `TestVariantFileBindings`, `TestVariantImport`, `TestVariantDelta`) and the consumer-side operations (`DiffTestVariantLedgers`, `Inert`, `InertForSubject`, `LessDeclaration`, `Clone`).
   - `closure/internal/compartment` constructs those exact `testvariant.*` types (`ComputeIdentity`, `AddBaseBindings`, `parseTestVariantFile`).
   - Because `compartment` is a separate package from `closure`, `closure` had to define two adapter interfaces (`compartment.Source` and `compartment.ParseMemo`) and export `(*Hasher).ReadFile` (`filememo.go:248`) to wire `Hasher` and `fileMemos` into `compartment.ComputeIdentity`!
   - **Consolidation**: Either fold `closure/internal/compartment` directly into `closure` (as `closure/compartment.go`, eliminating the `compartment.Source` / `compartment.ParseMemo` interfaces and unexporting `Hasher.ReadFile`), or move the pure AST parser `parseTestVariantFile` into `closure/testvariant`.

2. **Divergent Directive Recognition Across `canonical.go`, `compartment.go`, and `maximal.go`**:
   Three files in this scope parse Go comments for compiler/tool directives with subtly different rules:
   - `canonical.go` (`retainedComment`, L44–77): Retains `//export `, `+build`, `generatedmark.IsMarker`, and any `//<name>:` or `/*<name>:` where `<name>` is `[a-z0-9_-]+`.
   - `compartment.go` (`parseTestVariantFile`, L405–423): Ledgers comments starting with `//go:` (excluding `//go:build`) as `"directive"` entries; ignores `/*go:...*/` block comments and `//gofresh:` directives!
   - `maximal.go` (`maximalFileEffectsContentWithContextFiltered`, L474–475 & `auditedLinknamesOnly`, L1270–1307): Uses `strings.Contains(text, "//go:wasmimport")` and `strings.Contains(text, "//go:linkname")`. Note the comment in `canonical.go:56-58`: *"gofresh's analyzer reads `go:linkname` out of block comments too, so a block comment carrying a directive is retained"*, whereas `maximal.go` and `compartment.go` only match `//go:`.

3. **Duplicate Hex-Truncated SHA-256 Computation Bypassing `closure/internal/digest`**:
   `closure/internal/digest/digest.go` (18 lines) was created with the doc comment: *"Package digest is the closure analyses' shared content-digest discipline: one function, one format, every consumer."*
   Yet across the very same packages, `hex.EncodeToString(sum[:])[:32]` / `hex.EncodeToString(hasher.Sum(nil))[:32]` is still hand-written in:
   - `closure/closure.go:625` (`hashContributions`)
   - `closure/closure.go:1311` (`hashFilesWith`)
   - `closure/maximal.go:117` (`maximalSubjectHash`)
   - `closure/internal/compartment/compartment.go:157` (`ComputeIdentity`)
   - `closure/internal/compartment/compartment.go:224` (`positionalDigest`)
   - `closure/internal/compartment/compartment.go:438` (`parseTestVariantFile`)

---

### 3.5 `closure/internal/program`, `closure/internal/rta`, and Micro-Files

1. **Trivial Micro-Files (`programfacade.go`, `frontend.go`, `closure/internal/digest/digest.go`)**:
   - `closure/programfacade.go` is 9 lines long and contains a single line of code: `type program = prog.Program` (analogous to `type listPkg = listing.Package` which lives directly in `closure.go:409`).
   - `closure/frontend.go` is 21 lines long and contains a single 1-line function: `func AnalyzingFrontend() string { return runtime.Version() }`.
   - `closure/internal/digest/digest.go` is 18 lines long with two 1-line functions (`Content`, `FromSum`).
   Folding `programfacade.go` and `frontend.go` into `closure.go` (or `scope.go`) reduces file clutter immediately.

2. **Dual `TestMain` Detection (`program.go:393-410` vs `maximal.go:1507-1538`)**:
   - `closure/internal/program/program.go` defines `isTestMainHarness(pkg *packages.Package, function *types.Func) bool` using `go/types` (`*types.Signature`, checking `_test.go` filename and `*testing.M` parameter).
   - `closure/maximal.go` defines `userTestMainDecl(file *ast.File, aliases map[string]string) *ast.FuncDecl` using `go/ast` (checking `func TestMain(*testing.M)` under `aliases`).
   While one operates on `types.Func` during SSA root indexing and the other operates on untyped `ast.File` during syntactic effect scanning, notice a subtle difference: `isTestMainHarness` checks `signature.Results().Len() != 0`, whereas `userTestMainDecl` (`maximal.go:1510`) checks `fd.Type.Params` but **does not check `fd.Type.Results == nil`**! If a file declares `func TestMain(m *testing.M) int { os.Exit(1); return 0 }` (which is not a valid Go test harness `TestMain` because it has a return value, and could be called as an ordinary function by a test), `userTestMainDecl` will treat it as the user `TestMain` and exempt its `os.Exit` call at the syntactic file-scan tier (`maximal.go:597-600, 640`). Adding `fd.Type.Results != nil` to `userTestMainDecl` aligns the AST check with `isTestMainHarness`.

3. **`closure/internal/program` Multi-Package `Prepare` vs `OwnVariantOf`**:
   In `closure/internal/program/program.go`:
   - `Prepare` (L109–112) constructs a synthetic `listing.Package` to call `compartment.OwnVariantOf(meta, path, base.Dir)`.
   - `build` (L268–270), however, checks `if p.ForTest == pkgPath && (p.PkgPath == pkgPath || p.PkgPath == pkgPath+"_test")` **without** checking `p.Dir == base.Dir` (unlike `compartment.OwnVariantOf`). Using a single helper for own-variant identification across `Prepare` and `build` ensures consistency.

4. **`closure/internal/rta` Design & Recovery Boundary**:
   - `rta.Analyze` (`rta.go:288-409`) is cleanly self-contained and bitmask-attributed (`uint64` masks for up to 64 subjects).
   - One notable耦合: `rta.Analyze` formats errors with `"closure: attributed reachability: ..."` (`rta.go:299, 303, 306, 339, 394, 400`), embedding the parent package's error prefix and exact substring (`"unsupported analysis shape"`) that `closure/attribution.go` matches on to trigger per-subject bisection. Defining a typed error or sentinel in `rta` (e.g., `rta.UnsupportedShapeError`) would replace fragile substring matching across package boundaries with structured error handling.

---

## 4. Summary of Top Consolidation & Cleanup Recommendations

1. **Unify the Memo Subsystem**:
   - Move `closure/internal/cachefile` to `internal/cachefile` so root `gofresh` can use it directly without leaking `LoadDynamicStateFacts`, `StoreDynamicStateFacts`, `LoadScanFacts`, and `StoreScanFacts` onto `closure`'s public API.
   - Consolidate `memo.go`, `effectmemo.go`, `filememo.go`, `policymemo.go`, and the memo parts of `dynamicstate.go` and `canonical.go` into a cohesive memo layer (`memo.go` + `listingmemo.go`), and centralize all memo scope renderings in `scope.go`.
   - Eliminate `policymemo.go` by computing `admissionPolicy()` directly without hashing the inputs twice (`policyInputs.key()` + `policyInputs.derive()`).
2. **Collapse `closure/internal/compartment` into `closure` (or `closure/testvariant`)**:
   - Eliminates `compartment.Source` and `compartment.ParseMemo` adapter interfaces and removes the accidental public export `(*Hasher).ReadFile`.
3. **Deduplicate Batch Orchestration in `observability.go` and `rooted.go`**:
   - Extract the triplicated group-memo + `batchPreparer` + `loadCachedFrom`/`releaseProgram` loop from `ComputeObservabilityBatch`, `ComputeRootedFunctions`, and `ComputeBinaryRootedFunctions`.
4. **Clean Up `maximal.go` Wrapper Chains & Dead Walks**:
   - Remove the 6 vestigial wrapper functions (`maximalFileEffects*`, `maximalFileEffectsCached*`, `pinnedEffectScan*`, `declaredOverridesKey`, `trueReason`, `impPkgPathOr`), delete duplicate `unwrapParen`, merge `maximalTestingTypeEffects` into `maximalTestingTypeEffectsFiltered`, and remove the dead second AST walk in `testingMethodEffectsFiltered`.
   - Add `fd.Type.Results != nil` guard to `userTestMainDecl` (`maximal.go:1510`) to match `isTestMainHarness` (`program.go:398`).
5. **Extract Cgo `#include` Scanner from `closure.go`**:
   - Move the 440-line C preprocessor and `-I` include escape scanner (`closure.go:822-1263`) to `closure/cgo_includes.go`, and fold trivial micro-files (`programfacade.go`, `frontend.go`) into `closure.go`.
