# Audit 05a: `internal/auditset`, `closure/toolchainsource*.go`, and `closure/toolchainaudit.go` (Part 1: Lines 1–10500)

## 1. Scope and Read-Completeness Verification

Every single line of the assigned scope (12,137 lines across 7 files, plus lines 10501–11250 of `closure/toolchainaudit.go` to capture the full body of `verifyOSNologStatHelpers` which begins at line 10309) was read sequentially in ≤800-line increments:

| # | File | Assigned Lines | Actual File Lines | Read Status |
| :--- | :--- | :--- | :--- | :--- |
| 1 | [`internal/auditset/auditset.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L1-L700) | 1–699 | 700 (699 + EOF newline) | 100% read |
| 2 | [`closure/toolchainsource.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L1-L882) | 1–881 | 882 (881 + EOF newline) | 100% read |
| 3 | [`closure/toolchainsource_ctim.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource_ctim.go#L1-L12) | 1–11 | 12 (11 + EOF newline) | 100% read |
| 4 | [`closure/toolchainsource_ctimespec.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource_ctimespec.go#L1-L10) | 1–9 | 10 (9 + EOF newline) | 100% read |
| 5 | [`closure/toolchainsource_other.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource_other.go#L1-L14) | 1–13 | 14 (13 + EOF newline) | 100% read |
| 6 | [`closure/toolchainsource_unix.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource_unix.go#L1-L25) | 1–24 | 25 (24 + EOF newline) | 100% read |
| 7 | [`closure/toolchainaudit.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1-L10500) | 1–10500 | 21,307 total (read 1–11250) | 100% of assigned range read |

---

## 2. Inventory & Analysis: `internal/auditset/auditset.go`

### 2.1 Complete Symbol Inventory (`internal/auditset/auditset.go`, Lines 1–699)

#### Types & Constants
- [`VersionListing`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L41-L47) (`type VersionListing map[string][]string`): Key-to-versions map for fail-closed version listings.
  - [`(VersionListing).Listed`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L49-L52) (`func (l VersionListing) Listed(key, version string) bool`): Reports whether `version` is in `l[key]`.
- [`FlagRole`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L354-L364) (`type FlagRole uint8`): Classification enum for standard `flag` package symbols:
  - `FlagRoleRefused` (0), `FlagRoleAudited` (1), `FlagRoleValueRegistration` (2), `FlagRolePointerRegistration` (3).
  - [`(FlagRole).IsRegistration`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L366-L370) (`func (r FlagRole) IsRegistration() bool`): True for `FlagRoleValueRegistration` or `FlagRolePointerRegistration`.

#### Package-Private Admission Tables
- [`syncMethods`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L54-L65) (`map[string][]string`): Audited synchronization methods on `sync` receivers (`Cond`, `Mutex`, `RWMutex`, `Once`).
- [`syncSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L67-L70) (`map[string]bool`): Bare `sync` symbols (`Locker`, `NewCond`).
- [`memoMethods`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L72-L80) (`map[string][]string`): Audited memo methods on `sync.Map` (`Load`, `Store`, `LoadOrStore`).
- [`poolMethods`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L82-L86) (`map[string][]string`): Audited pooling methods on `sync.Pool` (`Get`, `Put`).
- [`reflectSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L88-L145) (`map[string]bool`): Audited bare-name surface of `reflect` (`Type`, `TypeOf`, `DeepEqual`, `Elem`, descriptor queries, `StructField`, `StructTag`, `Get`, `Lookup`, `Kind` constants except `Pointer`/`UnsafePointer`/`Ptr`, `ChanDir` constants).
- [`reflectMethods`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L147-L155) (`map[string][]string`): Receiver-qualified `reflect` methods (`"rtype": {"Key"}`).
- [`reflectImmutableTypes`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L157-L163) (`map[string]bool`): `"Type": true`.
- [`constantImmutableTypes`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L165-L168) (`map[string]bool`): `"Value": true` (for `go/constant`).
- [`fmtSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L170-L179) (`map[string]bool`): Pure formatting symbols of `fmt` (`Sprint*`, `Errorf`, `Append*`, `FormatString`, `Stringer`).
- [`syncNames`, `poolNames`, `memoNames`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L181-L187) (`[]string`): Precomputed sorted name unions for `sync` sets.
- [`purePackages`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L189-L208) (`map[string]bool`): 45 standard-library packages admitted whole as bit-deterministic pure computation (`bufio`, `bytes`, `cmp`, `container/*`, `crypto/{hmac,md5,sha1,sha256,sha512,subtle}`, `encoding/*`, `errors`, `hash/*`, `io`, `io/fs`, `iter`, `maps`, `math/{big,bits}`, `path`, `regexp`, `regexp/syntax`, `slices`, `sort`, `strconv`, `strings`, `text/scanner`, `unicode/*`).
- [`timeSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L233-L267) (`map[string]bool`): Bare-name pure surface of `time` (`Date`, `FixedZone`, `ParseDuration`, types, months, weekdays, durations, layouts, pure `Time` and `Duration` methods that don't collide with ambient functions).
- [`timeMethods`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L269-L291) (`map[string][]string`): Receiver-qualified `time.Time` methods whose bare names collide with ambient functions (`"Time": {"After", "Unix", "UnixMilli", "UnixMicro", "UTC", "AddDate"}`).
- [`randSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L293-L306) (`map[string]bool`): Bare-name surface of `math/rand` (`New`, `NewSource`, `Rand`, `Source`, `Source64`).
- [`randMethods`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L308-L325) (`map[string][]string`): Receiver-qualified `math/rand` methods on `Rand` and `rngSource`.
- [`urlSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L327-L352) (`map[string]bool`): GODEBUG-free surface of `net/url`.
- [`flagSurface`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L372-L405) (`map[string]FlagRole`): Classification table for `flag` symbols.
- [`flagSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L425-L433) (`map[string]bool`): Derived subset of `flagSurface` where `role == FlagRoleAudited`.
- [`symbolTables`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L435-L453) (`map[string]map[string]bool`): Master map of 11 symbol-admitted packages (`context`, `crypto/fips140`, `fmt`, `math`, `reflect`, `sync/atomic`, `time`, `path/filepath`, `net/url`, `flag`, `math/rand`).
- [`atomicSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L455-L471) (`map[string]bool`): Scalar types and top-level scalar functions of `sync/atomic`.
- [`atomicMethods`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L473-L482) (`map[string][]string`): Receiver-qualified methods on scalar `sync/atomic` types (`Bool`, `Int32`, `Int64`, `Uint32`, `Uint64`, `Uintptr`).
- [`mathSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L484-L500) (`map[string]bool`): Compile-time constants of `math`.
- [`fips140Symbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L502-L511) (`map[string]bool`): `WithoutEnforcement`, `Enforced`.
- [`contextSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L513-L526) (`map[string]bool`): Timerless surface of `context`.
- [`standardSentinelGlobals`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L528-L535) (`map[string][]string`): Unmutated sentinel globals in `context`, `encoding/binary`, `io`, `io/fs`.
- [`filepathSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L559-L577) (`map[string]bool`): Lexical surface of `path/filepath`.

#### Exported Functions & Predicates
- [`Identity`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L23-L40) (`func Identity() string`): SHA-256 hex digest of JSON-marshaled admission tables.
- [`PurePackage`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L210-L212) (`func PurePackage(pkgPath string) bool`)
- [`PurePackages`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L214-L222) (`func PurePackages() []string`)
- [`ReceiverPackages`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L225-L231) (`func ReceiverPackages() []string`)
- [`FlagSurface`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L407-L410) (`func FlagSurface(name string) FlagRole`)
- [`FlagNonAuditedNames`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L412-L423) (`func FlagNonAuditedNames() []string`)
- [`StandardSentinelGlobal`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L537-L541) (`func StandardSentinelGlobal(pkgPath, name string) bool`)
- [`Symbol`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L543-L545) (`func Symbol(pkgPath, name string) bool`)
- [`SymbolPackages`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L547-L557) (`func SymbolPackages() []string`)
- [`SyncMethod`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L579-L581), [`PoolMethod`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L583-L585), [`TimeMethod`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L587-L589), [`ReflectMethod`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L591-L595), [`RandMethod`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L597-L601), [`AtomicMethod`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L603-L607), [`MemoMethod`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L642-L644) (`func(receiver, method string) bool`)
- [`ReceiverMethod`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L609-L632) (`func ReceiverMethod(fn *types.Func, pkgPath string, listed func(receiver, method string) bool) bool`)
- [`SyncName`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L634-L636), [`PoolName`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L638-L640), [`MemoName`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L646-L648), [`SyncSurfaceName`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L650-L654) (`func(name string) bool`)
- [`ReflectImmutable`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L656-L658), [`ConstantImmutable`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L660-L662) (`func(name string) bool`)
- [`BoundedToken`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L684-L699) (`func BoundedToken(text, marker, bounds string) (rest string, ok bool)`)

#### Unexported Helpers
- [`names`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L664-L667), [`namesWithSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L669-L682).

### 2.2 Architectural Findings in `internal/auditset/auditset.go`

1. **Redundant / Unconsolidated Receiver-Method Tables**:
   - Whereas `symbolTables` (line 441) consolidates per-package bare-symbol maps into `map[string]map[string]bool` so `SymbolPackages()` and `Symbol(pkg, name)` are derived from one map, the receiver-method tables (`syncMethods`, `poolMethods`, `memoMethods`, `timeMethods`, `reflectMethods`, `randMethods`, `atomicMethods`) are 7 separate variables with 7 separate exported predicate functions (`SyncMethod`, `PoolMethod`, `MemoMethod`, `TimeMethod`, `ReflectMethod`, `RandMethod`, `AtomicMethod`), and [`ReceiverPackages()`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L229-L231) is a **hardcoded slice literal** `[]string{"math/rand", "reflect", "sync", "sync/atomic", "time"}` that can drift if a new receiver table is added!
   - Similarly, [`Identity()`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L25-L40) manually enumerates 13 variables in a slice literal (`purePackages`, `symbolTables`, `methods(syncMethods)`, ..., `constantImmutableTypes`), and notably **omits `flagSurface`** (only `flagSymbols`, the `FlagRoleAudited` projection inside `symbolTables`, is hashed—so changing a symbol between `FlagRoleValueRegistration`, `FlagRolePointerRegistration`, and `FlagRoleRefused` in `flagSurface` does NOT move `auditset.Identity()`!).
2. **Misplaced Lexical Helper (`BoundedToken`)**:
   - [`BoundedToken`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L684-L699) is a generic string-prefix tokenizer used for `//go:` directives and generated-file headers. Putting it in `internal/auditset` couples lexical comment parsing to the standard-library admission inventory package.
3. **Unused / Vestigial `VersionListing`**:
   - [`VersionListing`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/internal/auditset/auditset.go#L41-L52) is an 11-line map wrapper from before the content-keyed audit migration whose comment still mentions "a toolchain release, a module variable, a harness package".

---

## 3. Inventory & Analysis: `closure/toolchainsource*.go`

### 3.1 Complete Symbol Inventory (`closure/toolchainsource*.go`)

#### `closure/toolchainsource.go` (Lines 1–881)
- **Types**:
  - [`sourceDigests`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L132-L140): Holds `Packages map[string]string` (audited subset), `Content string` (overall stdlib content digest), `Policy string`, `inventory map[string]listedPackage`, and `pureDelegates map[string]bool`.
  - [`surfaceListing`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L142-L158): Persistent cache payload (`Version`, `Packages`, `Discovery`, `Integrity`).
  - [`listedPackage`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L160-L167): Per-package metadata (`ImportPath`, `Dir`, `Files`, `EmbedRoots`, `Audited`, `digest`).
  - [`dirStamp`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L169-L174) & [`entryStamp`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L176-L189): Filesystem directory and entry metadata (`Name`, `Type`, `Size`, `ModTime`, `ChangeTime`).
  - [`persistedSourceDigests`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L666-L668): JSON wrapper for `All map[string]string`.
- **Constants & Globals**:
  - [`implicitLinkPackages`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L74-L81): `[]string{"runtime/race", "runtime/msan", "runtime/asan"}`.
  - [`sourceDigestsVersion`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L191-L199): `const sourceDigestsVersion = 5`.
  - [`sourceDigestsDirName`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L209): `"toolchain-source"`.
  - [`digestReadForTest`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L434-L436): Test hook `var digestReadForTest func(name string)`.
  - [`toolchainDigestsMemo`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L670): `var toolchainDigestsMemo sync.Map`.
  - [`movedKeysBound`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L859-L860): `const movedKeysBound = 8`.
  - [`harnessPremisePackages`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L876-L881): `[]string{"internal/testlog", "testing", "testing/internal/testdeps"}`.
- **Functions**:
  - [`auditedSurfaceTables`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L37-L72): Union of `sync/atomic`, `harnessPremisePackages`, `auditset.PurePackages()`, `auditset.SymbolPackages()`, `auditset.ReceiverPackages()`, `classBPackages`, and package prefixes of `auditedLinknameTargets`.
  - [`auditedSurface`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L83-L121): BFS closure over `std` starting from `surfaceSeeds()` following `Deps` and `Imports`.
  - [`sortedKeys`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L123-L130): Sorted keys of `map[string]bool`.
  - [`surfaceSeeds`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L201-L207): `append(auditedSurfaceTables(), implicitLinkPackages...)`.
  - [`selectedFiles`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L211-L223): Concatenates and sorts all 12 non-test file slices (`GoFiles`, `CgoFiles`, `CFiles`, `CXXFiles`, `MFiles`, `HFiles`, `FFiles`, `SFiles`, `SwigFiles`, `SwigCXXFiles`, `SysoFiles`, `EmbedFiles`).
  - [`stampEntries`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L225-L240), [`stampDirs`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L242-L259): ReadDir + Lstat stamping.
  - [`stdPackageGOROOT`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L261-L275): Extracts `GOROOT` prefix when `dir` ends with `/src/<importPath>`.
  - [`pkgIncludeRelativeFiles`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L277-L307): Recursive directory walk of `GOROOT/pkg/include`.
  - [`stampsCurrent`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L309-L340): Verifies `stampsTrusted`, `cacheableDiscovery(l)`, every `dirStamp` in `l.Discovery`, and that `GOROOT/pkg/include` (if present) was recorded.
  - [`cacheableDiscovery`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L342-L358): Rejects symlinked directories or entries.
  - [`listingIntegrity`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L360-L371): SHA-256 of `(scope, l)` with `Integrity` cleared.
  - [`stampDiscovery`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L373-L377), [`stampDiscoveryTree`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L379-L419), [`excludedStandardDirectory`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L421-L432): Recursive directory stamping of `GOROOT/src` and extra roots.
  - [`digestFiles`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L438-L450), [`digestFilesBuffered`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L452-L454), [`digestFilesBufferedOpt`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L456-L458), [`digestListedPackageUntraced`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L460-L462), [`digestListedPackageBuffered`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L464-L466), [`digestListedPackageBufferedOpt`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L468-L489), [`digestFilesWithExtraBufferedOpt`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L491-L546): Length-prefixed SHA-256 file hashing (folding `../../pkg/include/*` into `runtime`'s digest).
  - [`listSurface`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L548-L585), [`orderedStamps`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L587-L598), [`listingDiscoveryRoots`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L600-L637): Builds `surfaceListing` from `[]listing.Package`.
  - [`digestListing`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L639-L664): Computes digests for all packages in `surfaceListing`.
  - [`sourceDigestsFromMemo`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L672-L698), [`loadToolchainDigests`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L700-L727), [`storeToolchainDigests`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L729-L742): Two-tier (`sync.Map` + `cachefile`) digest memoization.
  - [`toolchainSnapshotIdentity`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L744-L754), [`toolchainSourceScope`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L756-L771): Scope key computation.
  - [`toolchainSourceDigests`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L773-L849): Top-level entry point for listing and digesting the toolchain stdlib.
  - [`boolKeys`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L851-L857), [`namedMoved`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource.go#L862-L874): Set conversion and refusal formatting helpers.

#### Platform Stamp Files (`closure/toolchainsource_*.go`)
- [`closure/toolchainsource_ctim.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource_ctim.go#L1-L12) (`//go:build unix && !(darwin || freebsd || netbsd)`): `statChangeTime(st *syscall.Stat_t) int64` reading `st.Ctim.Nano()`.
- [`closure/toolchainsource_ctimespec.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource_ctimespec.go#L1-L10) (`//go:build darwin || freebsd || netbsd`): `statChangeTime(st *syscall.Stat_t) int64` reading `st.Ctimespec.Nano()`.
- [`closure/toolchainsource_other.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource_other.go#L1-L14) (`//go:build !unix`): `changeTime(fs.FileInfo) int64` returning `0`, `const stampsTrusted = false`.
- [`closure/toolchainsource_unix.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainsource_unix.go#L1-L25) (`//go:build unix`): `changeTime(info fs.FileInfo) int64` delegating to `statChangeTime`, `const stampsTrusted = true`.

### 3.2 Architectural Findings in `closure/toolchainsource*.go`

1. **Five-Layer Wrapper Chain Around `digestFilesWithExtraBufferedOpt`**:
   - Lines 448–490 define 6 tiny wrapper functions (`digestFiles`, `digestFilesBuffered`, `digestFilesBufferedOpt`, `digestListedPackageUntraced`, `digestListedPackageBuffered`, `digestListedPackageBufferedOpt`) around `digestFilesWithExtraBufferedOpt`. This can be collapsed to 2 functions (`digestFiles` and `digestListedPackage(ctx, p, buf, trace)`).
2. **Redundant Double-Reading of Every Package During Verification**:
   - In `toolchainSourceDigests` (line 841), on a cold digest cache, `digestListing` reads every file of every stdlib package to compute `lp.digest`. Immediately afterward, `verifyToolchainSurfaceAndDelegatesWithIO` (in `toolchainaudit.go` lines 970–1375 and 3175–3273) reads all the files of every surface/delegate/off-surface package **again** to parse ASTs/directives, and then calls `digestListedPackageUntraced(ctx, lp)` (lines 1053, 1176, 1321, 3266) to read all the files of the package **a third time** to check `curDigest != lp.digest` for TOCTOU!
   - If the verifier hashes the exact `src []byte` buffers it reads into memory while parsing the package (and compares that hash to `lp.digest`), it achieves a stronger, zero-extra-I/O TOCTOU guarantee (proving the exact bytes parsed into the AST matched `lp.digest`) while eliminating an entire full-package file-read pass!
3. **`GOROOT/pkg/include` Special-Casing Split Across Files**:
   - `stdPackageGOROOT` in `toolchainsource.go` (line 261) only handles `/src/<importPath>`, while `packageGOROOTForInclude` in `toolchainaudit.go` (line 1679) wraps `stdPackageGOROOT` to also handle `/lib/fips140/` snapshot directories. Furthermore, `runtime` hashes `pkg/include` into its own package digest (line 469), and `toolchainaudit.go` then passes `rtLP.digest` around as `pkgIncludeSalt` to every other package's memo key (lines 850–852, 84–95). Computing a dedicated `pkgIncludeDigest` once on `sourceDigests` would eliminate the `runtime`-digest coupling and unify `stdPackageGOROOT` / `packageGOROOTForInclude`.
---

## 4. Complete Inventory of `closure/toolchainaudit.go` (Part 1: Lines 1–10500)

### 4.1 Constants, Types, Caches, and Pure-Package Allowlist Tables (Lines 1–590)

#### Constants, Verdict Types, and Memoization Caches (Lines 24–141)
- [`toolchainVerifierVersion`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L24-L27) (`const toolchainVerifierVersion = "gofresh/toolchain-verifier@17"`): Domain-separation version tag mixed into `toolchainSourceDigests` policy digest.
- [`verifiedPackageVerdict`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L29-L36) (`struct`): Cached verification outcome for a surface or pure-delegate package:
  - `OK bool`
  - `Delegates []string`: Unaudited internal helper packages delegated to by an audited package.
  - `InactiveRuntimeGates map[string][]string`: For `runtime`, maps each inactive boolean gate function name to the sorted slice of unexported top-level mutator function names in `runtime`.
  - `RuntimeLinknamePulls []string`: Target symbol names in `runtime` pulled via `//go:linkname` or assembly/cgo symbol references.
  - `ExternalLinknamePulls []offSurfaceCrossEdge`: Cross-package `(Pkg, Sym)` references outside the package and `runtime`.
  - `RequiredInactiveRuntimeGates []string`: Inactive `runtime` gate names required by this package's AST contract (e.g., `runtime.goroot` or `os`/`testlog` hooks).
- [`offSurfaceCrossEdge`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L38-L41) (`struct{ Pkg, Sym string }`): Cross-package symbol edge for off-surface reachability analysis.
- [`offSurfaceUnaliasedSel`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L43-L47) (`struct{ Ident, Sel string; Candidates []string }`): Unaliased selector `Ident.Sel` in a file with unaliased imports whose `package` clause was not resolved locally.
- [`offSurfaceVerdict`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L49-L66) (`struct`): Summary of an off-surface stdlib package's startup/init and per-declaration reachability to `runtime` symbols (`PackageName`, `DirectRuntimePulls`, `RuntimePullByDecl`, `LocalEdges`, `LocalSels`, `MethodsByType`, `CrossEdges`, `UnaliasedSels`, `DotImports`, `DotImportIdents`, `SeedDecls`, `SeedSels`, `SeedCrossEdges`, `SeedUnaliasedSels`, `SeedDotIdents`, `DeclaredNames`).
- In-memory memo caches (`sync.Map`):
  - [`verifiedPackageMemo`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L68-L70): Keyed by `policy + "\x00" + importPath + "\x00" + digest [+ "\x00" + pkgIncludeSalt]`.
  - [`verifiedPureDelegateMemo`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L72-L74): Same key format for pure delegate packages.
  - [`verifiedOffSurfaceMemo`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L76-L78): Same key format for `offSurfaceVerdict`.
  - [`pkgIncludeHeaderCache`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L80-L82): Keyed by `goroot + "\x00" + pkgIncludeSalt`.
- Memo key and lookup helpers:
  - [`listedPackageNeedsPkgIncludeSalt`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L84-L95) (`func(lp listedPackage) bool`): Returns true if `lp.ImportPath != "runtime"` and `lp.Files` contains any `.s`, `.S`, or `.h` file.
  - [`verifiedPackageMemoKey`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L97-L99) (`func(importPath, digest string) string`)
  - [`verifiedPackageMemoKeyWithPolicy`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L101-L110) (`func(policy, importPath, digest, pkgIncludeSalt string) string`)
  - [`verifiedPureDelegateMemoKeyWithPolicy`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L112-L121) (`func(policy, importPath, digest, pkgIncludeSalt string) string`)
  - [`verifiedOffSurfaceMemoKeyWithPolicy`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L123-L132) (`func(policy, importPath, digest, pkgIncludeSalt string) string`)
  - [`loadVerifiedPackageMemo`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L134-L141) (`func(m *sync.Map, memoKey string) (verifiedPackageVerdict, bool)`)

#### Pure-Package & Pure-Delegate Allowlist Tables (Lines 143–590)
- [`allowedPureSupportImports`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L143-L159) (`map[string]bool`): Non-pure stdlib packages that pure packages and pure delegates may import if all selector references stay within allowlists (`crypto/internal/fips140`, `fmt`, `math`, `reflect`, `runtime`, `sync`, `sync/atomic`, `time`).
- [`allowedPureCryptoInternalFIPS140Selectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L161-L170) (`map[string]bool`): `Enabled`, `Version`, `Name`, `RecordApproved`, `RecordNonApproved`, `Hash`.
- [`allowedPureBoringCipherSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L172-L178) (`map[string]bool`): `NewGCMTLS`, `NewGCMTLS13`.
- [`allowedPureFIPS140OnlyFIPSSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L180-L184) (`map[string]bool`): `Enabled`.
- [`allowedPureFIPS140OnlyDRBGSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L186-L192) (`map[string]bool`): `Read`.
- [`allowedPureSHAGodebugSettings`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L194-L200) (`map[string]bool`): `"sha3"`, `"fips140"`.
- [`allowedPureFmtSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L202-L226) (`map[string]bool`): 21 pure `fmt` selectors (`Append*`, `Errorf`, `Format*`, `GoStringer`, `Scanner`, `ScanState`, `Sprint*`, `State`, `Stringer`).
- [`allowedPureMathSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L228-L275) (`map[string]bool`): 44 pure `math` functions and constants.
- [`allowedPureReflectSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L277-L331) (`map[string]bool`): 51 pure `reflect` types, kinds, and functions (including `Value`, `ValueOf`, `SliceHeader`, `StringHeader`, `Pointer`, `Ptr`, `UnsafePointer`—broader than `auditset.reflectSymbols`).
- [`allowedPureFilepathliteSyscallSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L333-L337) (`map[string]bool`): `InvalidFilename`, `ENOENT`.
- [`allowedPureFilepathliteWindowsSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L339-L343) (`map[string]bool`): `IsNonoverridableDevice`.
- [`allowedPureMathRandSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L345-L351) (`map[string]bool`): `New`, `NewSource` (only when `pkgPath == "math/big"`).
- [`allowedPureRuntimeSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L353-L362) (`map[string]bool`): `GOARCH`, `GOOS`, `KeepAlive`, `SetFinalizer`, `AddCleanup`, `Cleanup`.
- [`allowedPureSyncSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L364-L380) (`map[string]bool`): `Cond`, `Locker`, `Map`, `Mutex`, `NewCond`, `Once`, `OnceFunc`, `OnceValue`, `OnceValues`, `Pool`, `RWMutex`, `WaitGroup`.
- [`allowedPureSyncAtomicSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L382-L409) (`map[string]bool`): 24 `sync/atomic` types and top-level functions (including `Pointer` and `Value` for internal caching inside pure packages).
- [`allowedPureTimeSelectors`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L411-L452) (`map[string]bool`): 38 pure `time` types, constants, and constructors (`Now`, `Since`, `Until`, `Sleep`, `After*`, `Tick*`, `LoadLocation*`, `Local` excluded).
- [`allowedPureAsmStandardHeaders`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L454-L464) (`map[string]bool`): `textflag.h`, `funcdata.h`, `go_asm.h`, `go_tls.h`.
- [`allowedPureAsmCrossPkgSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L466-L474) (`map[string]bool`): `internal/cpu·*` feature-flag reads (`X86`, `ARM64`, `ARM`, `PPC64`, `S390X`, `RISCV64`, `Loong64`) and `runtime·return0`.
- [`allowedPureLinknameTargets`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L476-L488) (`map[string]bool`): 8 allowed two-argument `//go:linkname` targets in pure/delegate packages (`internal/byteorder`, `crypto/sha512`, `runtime.Typedslicecopy`, `runtime.memmove`, `runtime.memclrNoHeapPointers`, `runtime.KeepAlive`, `runtime.RegisterCleanup`, `runtime.AddCleanup`).
- [`allowedPureSingleArgLinknames`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L490-L540) (`map[string]bool`): 46 allowed single-argument `//go:linkname` export directives (`pkgPath + "." + localSym`).
- [`isPureSupportImport`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L542-L561) (`func(pkgPath, importPath string) bool`): Checks `allowedPureSupportImports[importPath]` plus package-specific exceptions (`math/big` -> `math/rand`; `crypto/sha*` -> `crypto/internal/boring` and `internal/godebug`; `internal/filepathlite` -> `syscall` and `internal/syscall/windows`).
- [`forbiddenPureImport`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L563-L590) (`func(pkgPath, importPath string) bool`): Denylist check for ambient/OS/network/telemetry/runtime packages (`os`, `syscall`, `net`, `internal/poll`, `runtime/*`, `testing*`, `internal/godebug`, `crypto/rand`, `math/rand/v2`, etc.).

---

### 4.2 Top-Level Surface, Delegate, and Off-Surface Orchestration (Lines 592–1631)

- [`verifyToolchainSurface`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L592-L602) (`func(d sourceDigests) []string`): Wrapper around `verifyToolchainSurfaceContext(context.Background(), d)`.
- [`verifyToolchainSurfaceContext`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L604-L613) (`func(ctx context.Context, d sourceDigests) ([]string, error)`): Wrapper around `verifyToolchainSurfaceWithIO`.
- [`verifyToolchainSurfaceWithIO`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L615-L618) (`func(ctx context.Context, d sourceDigests) (failed []string, ioErr error, ctxErr error)`): Wrapper around `verifyToolchainSurfaceAndDelegatesWithIO`.
- [`verifyToolchainSurfaceAndDelegatesWithIO`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L620-L844) (`func(ctx context.Context, d sourceDigests) (failed []string, pureDelegates map[string]bool, ioErr error, ctxErr error)`):
  - Iterates over sorted `d.Packages` (`audited == true`), verifies each via `verifyListedPackageMemoized`.
  - Runs nested closure `walkDelegate(pkg string, stack map[string]bool) bool` (lines 692–755) to transitively verify `verdict.Delegates` via `verifyPureDelegateMemoized` (rejecting cycles and self-delegation).
  - Accumulates `RuntimeLinknamePulls` and `ExternalLinknamePulls` from all surface and delegate packages.
  - If any package has `RequiredInactiveRuntimeGates`, invokes `collectOffSurfaceStartupRuntimePulls` (line 781) to trace init/linkname reachability across off-surface stdlib packages (`d.inventory`), and verifies that every required inactive gate in `rtVerdict.InactiveRuntimeGates` has zero pulled mutators (lines 791–829).
- [`verifyListedPackageMemoized`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L846-L891) (`func(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (verifiedPackageVerdict, error)`): Looks up `verifiedPackageMemo`, falls back to `verifyListedPackageWithIOAndSalt`, stores result if `ioErr == nil && ctx.Err() == nil && lp.digest != ""`.
- [`verifyPureDelegateMemoized`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L893-L938) (`func(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (verifiedPackageVerdict, error)`): Identical memo wrapper around `verifyPureCandidateWithIOAndSalt` using `verifiedPureDelegateMemo`.
- [`verifyListedPackage`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L940-L954) (`func(lp listedPackage) error`): Direct unmemoized test entry point for `verifyListedPackageWithIO`.
- [`verifyListedPurePackage`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L956-L964) (`func(lp listedPackage) error`): Direct unmemoized test entry point for `verifyPureCandidateWithIO`.
- [`verifyPureCandidateWithIO`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L966-L968) & [`verifyPureCandidateWithIOAndSalt`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L970-L1091):
  - Rejects empty `lp.Dir`/`lp.Files`, rejects any file other than `.go`, `.s`, `.S`, `.h`.
  - Reads `.s`/`.S`/`.h` files and runs `verifyAssemblyFile`.
  - Runs `scanPreprocessedNonGoSymbolRefs` on `pkgIncludeHeaders` + assembly/header texts.
  - Parses `.go` files (`parser.ParseComments`), rejects `import "C"`, runs `verifyFileLinknameDirectives` and `collectGoLinknameTargets`.
  - Re-digests `lp` (`digestListedPackageUntraced`) to detect mid-flight file mutation.
  - Runs `verifyPurePackageAST(lp.ImportPath, parsedFiles)` (plus `verifyBufioWriterAST` when `lp.ImportPath == "bufio"`).
  - Collects internal delegates (unaliased/imported packages outside `PurePackage(imp)` and `isPureSupportImport`).
- [`verifyListedPackageWithIO`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1093-L1095) & [`verifyListedPackageWithIOAndSalt`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1097-L1375):
  - Dispatches `auditset.PurePackage(lp.ImportPath)` directly to `verifyPureCandidateWithIOAndSalt`.
  - For non-pure surface packages:
    - Enforces strict file-extension rules (`.go`, `.s`, `.S`, `.h`, `.c` only; `.s`/`.S`/`.c` forbidden in `os`, `internal/testlog`, `testing`, `testing/internal/testdeps`).
    - For `runtime`, also reads `GOROOT/pkg/include` regular files and verifies assembly headers (`textflag.h`, `funcdata.h`, `go_asm.h`, `go_tls.h`) against syscalls (`verifyAssemblyNoSyscall`).
    - Parses `.go` files, extracts cgo preambles (`extractFileCgoPreambles`), runs `scanPreprocessedNonGoSymbolRefs`, and collects linkname pulls (`collectGoLinknameTargets`).
    - For `os`, `internal/testlog`, `testing`, `testing/internal/testdeps`, runs `verifyHarnessFileDirectives`.
    - Re-digests `lp` (`digestListedPackageUntraced`) for TOCTOU protection.
    - Dispatches to package-specific AST verifiers:
      1. `runtime`: `discoverRuntimeInactiveGates` + `verifyRuntimePackageAST` (lines 1255–1268).
      2. `os`: `verifyOSPackageAST` (lines 1270–1277).
      3. `internal/testlog`: `verifyInternalTestlogPackageAST` (lines 1278–1282).
      4. `testing/internal/testdeps`: `verifyTestdepsPackageAST` (lines 1283–1287).
      5. `testing`: `verifyTestingPackageAST` (lines 1288–1292).
      6. `path/filepath`: collects `internal/filepathlite` delegate (lines 1293–1307).
      7. Class B & symbol/receiver packages (`time`, `math`, `math/rand`, `reflect`, `sync`, `sync/atomic`, `context`, `crypto/fips140`, `fmt`, `net/url`, `flag`, `go/token`, `go/ast`, `go/parser`, `go/constant`, `go/types`, `go/build`, `go/version`, `runtime/race`, `runtime/msan`, `runtime/asan`): dispatched in lines 1308–1370 (continued in Part 2 helper functions).
- [`scanGoDirectiveComments`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1377-L1410) (`func(src string, visit func(lit string) error) error`): Uses `go/scanner.Scanner` to visit every comment in `src`.
- [`forbiddenOSLinknameLocals`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1412-L1426) (`map[string]bool`): 42 `os` symbols (`Getenv`, `LookupEnv`, `Open`, `OpenFile`, `Create`, `ReadFile`, `ReadDir`, `Stat`, `Lstat`, `Chdir`, `Getwd`, `SameFile`, `NewFile`, `newFile`, `openFileNolog`, `openDir`, `openDirNolog`, `statNolog`, `lstatNolog`, `File`, `file`, `fileStat`, `dirInfo`, `ErrInvalid`, `ErrClosed`, `Stdout`, `Stderr`, `Stdin`, etc.) forbidden from appearing as `localSym` in any `//go:linkname` directive.
- [`verifyHarnessFileDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1428-L1510) (`func(pkgPath, text string, runtimePullLinknames, selfPushLinknames map[string]bool, osRuntimePullMap map[string]string, osAnyLinknameLocals map[string]bool) error`): Validates `//go:linkname` directives in `os`, `internal/testlog`, `testing`, and `testing/internal/testdeps`.
- [`isASCIIIdentByte`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1512-L1514), [`collectAllASCIIIdents`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1516-L1529), [`collectRawBytesRuntimeSymbolRefs`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1531-L1551), [`collectTextRuntimeSymbolRefs`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1553-L1555): Raw byte/text scanners for `runtime.` and `runtime·` symbol references.
- [`collectGoRuntimeLinknameTargets`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1557-L1559), [`splitLinknameTarget`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1561-L1574), [`collectGoLinknameTargets`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1576-L1631): Extracts `runtime` and external `(pkg, sym)` targets from `//go:linkname` directives.

---

### 4.3 Cgo Preamble, `pkg/include`, and C Preprocessor / Non-Go Symbol Scanner (Lines 1633–3118)

- [`extractCgoPreamble`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1633-L1648) (`func(doc *ast.CommentGroup) string`) & [`extractFileCgoPreambles`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1650-L1677) (`func(file *ast.File) []string`): Extracts comment blocks attached to `import "C"` specs/decls.
- [`packageGOROOTForInclude`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1679-L1692) (`func(dir, importPath string) (string, bool)`): Resolves `GOROOT` from `/src/<importPath>` or `/lib/fips140/...`.
- [`loadPkgIncludeHeadersForPackage`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1694-L1744) (`func(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (headers []string, verdictErr error, ioErr error)`): Loads and caches `.h`/`.s`/`.S` files under `GOROOT/pkg/include` (rejecting symlinks and non-regular files).
- **Custom C Preprocessor / Macro Expander** (Lines 1746–2687):
  - [`cppMacroDef`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1746-L1752) (`struct{ isFunc, variadic bool; params []string; body string }`)
  - [`collectCPPMacrosFromText`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1754-L1815) (`func(cleaned string, defs map[string][]cppMacroDef)`): Parses `#define` directives across logical lines.
  - [`collapseTokenPasteOps`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1817-L1833) (`func(s string) string`): Removes `##` and surrounding spaces.
  - [`parseCPPMacroCallArgs`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1835-L1871) (`func(s string, openParenIdx int) (args []string, nextIdx int, ok bool)`)
  - [`cppStringizeArg`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1873-L1895) (`func(arg string) string`): Implements `#param` stringization.
  - [`isHexDigitByte`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1897-L1908), [`matchCStringPrefixAt`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1910-L1927), [`writeNormalizedCStringByte`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1929-L1938), [`normalizeCStringLiterals`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1940-L2089): Unescapes octal/hex/universal escapes (`\x`, `\u`, `\U`) and folds adjacent C string literals (`"a" "b"` -> `"ab"`).
  - [`maxNonGoLogicalLineBytes`, `maxCPPExpandedStatesPerLine`, `maxCPPExpansionDepth`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2091-L2095) (`const`: 65536, 512, 16).
  - [`cppExpandBudget`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2097-L2100), [`cppStateKey`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2102-L2106), [`cppWorkItem`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2108-L2113).
  - [`lookupChosenMacro`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2115-L2134), [`addChosenMacro`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2136-L2145), [`isBlockedMacro`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2147-L2149), [`addBlockedMacro`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2151-L2159), [`mergeBlockedMacros`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2161-L2175).
  - [`isPasteAdjacentInBody`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2177-L2190), [`macroNormalParams`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2192-L2238), [`bodyMacroRefs`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2240-L2285), [`defReachesMacro`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2287-L2312).
  - [`substituteCPPMacroBody`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2314-L2409): Substitutes `#param`, `##`-adjacent raw args, `__VA_OPT__`, and expanded args.
  - [`stepCPPPass`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2411-L2625), [`expandCPPStatesWithBudget`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2627-L2674), [`expandCPPLineAllChoices`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2676-L2687): Non-deterministic multi-definition macro expander exploring all `#define` branches (`#ifdef`/`#else`) up to budget.
- **Assembly & C Symbol Extraction** (Lines 2689–3118):
  - [`collapseAsmMiddleDotAndSlashSpaces`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2689-L2724), [`leadingASCIIIdent`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2726-L2735), [`unescapeObjabiToken`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2737-L2757), [`collectRuntimeIdentsAndMachO`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2759-L2771).
  - [`collectCStringSymbolRefs`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2773-L2894), [`extractExpandedLineSymbols`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2896-L2952): Extracts `pkg.Sym`, `pkg·Sym`, `pkg__Sym` (gccgo `__asm__`), and Mach-O `_runtime.*` symbol references from expanded lines and C string literals (`__asm__`, `dlsym`, `#pragma cgo_import_static`).
  - [`unquotedParenBalance`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2954-L2976), [`trailingFuncMacroIdent`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L2978-L2999), [`buildLogicalNonGoScanLines`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3001-L3069).
  - [`scanPreprocessedNonGoSymbolRefs`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3071-L3118): Top-level entry point for scanning non-Go/cgo files for cross-package symbol references under both comment-stripping modes (`joinCont=false` and `joinCont=true`).

---

### 4.4 Off-Surface Reachability & `runtime` Inactive Gate Discovery (Lines 3120–4584)

- [`resolveStdInventoryImport`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3120-L3131) (`func(inventory map[string]listedPackage, importPath string) (string, bool)`): Resolves `importPath` or `"vendor/" + importPath` in `inventory`.
- [`verifyOffSurfacePackageMemoized`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3133-L3173) (`func(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (offSurfaceVerdict, error)`): Memoized wrapper around `verifyOffSurfacePackageWithIO`.
- [`verifyOffSurfacePackageWithIO`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3175-L3677) (`func(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (offSurfaceVerdict, error)`):
  - Rejects binary/SWIG files (`.syso`, `.swig`, `.swigcxx`).
  - Scans `.s`/`.S`/`.h`/`.c`/`.cc`/`.cpp`/`.cxx`/`.m`/`.f`/`.F`/`.for`/`.f90` and cgo preambles via `scanPreprocessedNonGoSymbolRefs`.
  - Scans `.go` files via `scanOffSurfaceGoDirectives` and `walkOffSurfaceAST` to build per-declaration local call/reference graphs, method sets (`MethodsByType`), cross-package edges (`CrossEdges`), unaliased selectors (`UnaliasedSels`), dot-imports (`DotImports`), and package-init/linkname-export seeds (`SeedDecls`, `SeedSels`, `SeedCrossEdges`, `SeedUnaliasedSels`, `SeedDotIdents`).
- [`scanOffSurfaceGoDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3679-L3719) (`func(src string, directRuntime map[string]bool, onTwoArgLink func(localSym, target string))`): Scans `//go:linkname` and `//go:cgo_import_*` directives in off-surface packages.
- [`walkOffSurfaceAST`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3721-L3957) (`func(node ast.Node, scope map[string]bool, recIdent, recSel func(string), recQual func(base, sel string))`): Custom lexical-scope AST walker tracking function literals, block scopes, `if`/`switch`/`for`/`range` init scopes, type switches, and select `:=` clauses to distinguish free package-level identifiers from shadowed local variables.
- [`collectOffSurfaceStartupRuntimePulls`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3959-L4157) (`func(ctx context.Context, d sourceDigests, policy, pkgIncludeSalt string, pureDelegates map[string]bool, externalSeeds []offSurfaceCrossEdge, pulledRuntimeTargets map[string]bool) (ioErr error, ctxErr error)`): Worklist reachability solver over all off-surface stdlib packages (`activatePkg`, `activateSym`, `activateSel`) propagating init seeds, exported methods, dot-imports, and linkname targets into `pulledRuntimeTargets`.
- [`allNonSelPropIdentsIn`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4159-L4194) (`func(files []*ast.File, name string, allowed map[*ast.Ident]bool) bool`): Verifies that every non-selector-property, non-struct-field-key `*ast.Ident` with `Name == name` across `files` is in `allowed`.
- [`discoverRuntimeInactiveGates`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4196-L4584) (`func(files []*ast.File, goSrcs []string, nonGoIdents map[string]bool) map[string][]string`):
  - Discovers unexported `runtime` zero-arg `bool` functions (`func() bool`) that either:
    1. Immediately return `false` (`return false`), OR
    2. Return `!flag.Load()` or `flag.Load() != 0` (or `> 0` for unsigned) on an unexported package-level `atomic.{Bool,Uint32,Uint64,Int32,Int64}` variable whose only other uses across `runtime` are `.Store(...)` calls inside unexported top-level `runtime` functions (and whose name does not appear in `//go:linkname` or `nonGoIdents`).
  - Returns `map[gateFuncName][]mutatorFuncName`.

---

### 4.5 Assembly & Pure-Package Verifiers (Lines 4586–5393)

- [`matchLineContinuation`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4586-L4598) (`func(src string, idx int) (int, bool)`): Matches `\` followed by `\n` or `\r\n`.
- [`stripAssemblyComments`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4600-L4714) (`func(src string, keepLiterals, joinContinuationWithSpace bool) string`): Strips `//` and `/* ... */` comments (handling `\` line continuations inside comments and string/char literals).
- [`foldAssemblyCommentContinuations`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4716-L4743) (`func(s string, joinWithSpace bool) string`).
- [`isAsmWordRune`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4745-L4748) (`func(r rune) bool`).
- [`verifyAssemblyNoSyscall`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4750-L4752) (`func(pkgPath, name, src string) error`): Calls `verifyAssemblyFile(pkgPath, name, src, nil)`.
- [`allowedAsmDirectiveKeywords`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4754-L4767) (`map[string]bool`): `include`, `ifdef`, `ifndef`, `if`, `elif`, `else`, `endif`, `undef`, `define`.
- [`verifyAssemblyFile`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4769-L4774) & [`verifyAssemblyFileSinglePass`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4776-L4993):
  - Runs twice (`joinContinuationWithSpace = false` and `true`).
  - Rejects unknown `#` directives, `#include <...>`, `#include` with path traversal, or `#include` of unselected local headers.
  - Rejects `#define` bodies containing `·`, `\`, `"`, `'`, or forbidden instructions.
  - Rejects token-pasting `##`, split `·` cross-package references, macro-shadowed cross-package qualifiers, cross-package references outside `allowedPureAsmCrossPkgSymbols`, and hardware/syscall instructions (`SYSCALL`, `SYSENTER`, `SVC`, `SWI`, `SC`, `SCV`, `ECALL`, `BREAK`, `SYSCALL_NE`, `TRAP`, `CHMK`, `INT`, `INT3`, `INTO`, `RDTSC`, `RDTSCP`, `RDRAND`, `RDSEED`, `MRS`, `CNTVCT_EL0`, `CNTPCT_EL0`, `RNDR`, `RNDRRS`, `RDTIME*`, `RDCYCLE*`, `RDINSTRET*`, `CSRR*`, `MFTB*`, `DARN`, `STCK*`, `STCKE`, `STCKF`, `TA`).
- [`verifyFileLinknameDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4995-L5030) (`func(pkgPath string, text string) error`): Verifies `//go:linkname` directives in pure/delegate packages against `allowedPureSingleArgLinknames` and `allowedPureLinknameTargets`.
- [`isOSStderrSelector`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L5032-L5039) & [`exprReferencesPkgPrefix`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L5041-L5056).
- [`verifyPurePackageAST`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L5058-L5319) (`func(pkgPath string, files []*ast.File) error`):
  - Rejects blank/dot imports of non-pure packages and imports of `forbiddenPureImport`.
  - Rejects exported package-level variables whose type or initializer references `sync` or `sync/atomic` (preventing callers from mutating shared sync primitives directly).
  - Walks every `ast.SelectorExpr` across `files` and checks package-qualified selectors against 16 hardcoded allowlist branches (`fmt`, `math`, `math/rand`, `reflect`, `runtime`, `sync`, `sync/atomic`, `time`, `crypto/internal/fips140`, `crypto/internal/boring`, `crypto/internal/fips140only`, `crypto/internal/fips140/drbg`, `internal/godebug`, `syscall`, `internal/syscall/windows`, `os.Stderr` in `runtime/internal/math`).
- [`declOrBodyShadowsIdent`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L5321-L5393) (`func(f *ast.File, fn *ast.FuncDecl, ident string) bool`): Checks if `ident` is shadowed by another import, package-level declaration, receiver/type/value parameter, or local assignment/declaration inside `fn.Body`.

---

### 4.6 `os` Package Structural Verifiers (Lines 5395–11113)

- [`verifyOSPackageAST`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L5395-L6868) (`func(files []*ast.File, osRuntimePullMap map[string]string, osAnyLinknameLocals map[string]bool) ([]string, error)` — **1,474 lines**):
  - Collects file imports (`internal/testlog`, `syscall`, `internal/poll`, `errors`, `io/fs`), top-level functions, methods on `File`/`file`/`fileStat`/`dirInfo`, and verifies uniqueness of reserved `os` declarations (`osReserved`, `osNoFileReserved`).
  - Verifies sentinel errors `ErrInvalid` (`fs.ErrInvalid`) and `ErrClosed` (`fs.ErrClosed`).
  - Invokes `verifyOSFileStructTypes`, `verifyOSExitIntegrity`, and `discoverOSInactiveState` (defined in Part 2, line 11177).
  - **Step 1 (lines 5827–5837)**: `Getenv` and `LookupEnv` — verifies first statement is `testlog.Getenv(key)`.
  - **Step 2 (lines 5839–5863)**: `Open` and `Create` — verifies 1-statement body `return OpenFile(name, ...)`.
  - **Step 3 (lines 5865–5949)**: `OpenFile`, `openFileNolog`, and `openDir` — verifies `OpenFile` calls `testlog.Open(name)` before returning `openFileNolog(name, flag, perm)` (with optional `chdir` bit mask); calls `verifyOSOpenFileNolog`; verifies `openDir` calls `testlog.Open(name)`.
  - **Step 4 (lines 5951–5985)**: `ReadFile` and `ReadDir` — invokes `verifyOSReadFile`; verifies `ReadDir` opens directory via `openDir`, `Open`, or `OpenFile`.
  - **Step 5 (lines 5987–6001)**: `Stat` and `Lstat` — verifies `testlog.Stat(name)` executes first (after optional inactive hook).
  - **Step 6 (lines 6003–6163)**: `Chdir` and `Getwd` — verifies `Chdir` calls `syscall.Chdir(dir)`, calls `testlog.Open(dir)` on error, and calls `testlog.Logger().Chdir(wd)` when updating `getwdCache`; invokes `verifyOSGetwd`.
  - **Step 7 (lines 6165–6865)**: `File` write/fd/close integrity:
    - `(*File).checkValid` (lines 6167–6186): `if f == nil { return ErrInvalid }`.
    - `(*File).wrapErr` (lines 6188–6250): Wraps non-nil errors in `&PathError{Op: op, Path: f.name, Err: err}`.
    - `(*File).Write` (lines 6252–6390): Verifies nil/checkValid guard, `f.write(b)` call, `n < 0` clamp, `n != len(b)` `io.ErrShortWrite`, `epipecheck` (`verifyOSEpipecheck`), and `f.wrapErr("write", e)`.
    - `(*File).WriteString` (lines 6392–6464): Verifies delegation to `f.Write(...)` (`unsafe.Slice(unsafe.StringData(s), len(s))` or `[]byte(s)`).
    - `(*File).write` (lines 6466–6567): Verifies Posix `f.pfd.Write(b)` and Plan 9 `syscall.Write(f.fd, b)` shapes.
    - `(*File).Fd` and `(*file).fd` (lines 6569–6571): Invokes `verifyOSFileFdMethods`.
    - `(*File).Close` (lines 6573–6613): Verifies `if f == nil { return ErrInvalid }; return f.file.close()`.
    - `(*file).close` (lines 6615–6865): Verifies Posix `file.pfd.Close()` and Plan 9 `fdmu.IncrefAndClose` + `syscall.Close` + `decref`/`destroy` shapes.
- [`exprContainsAnyCall`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L6870-L6886) (`func(expr ast.Expr) bool`).
- [`verifyOSFileStructTypes`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L6888-L6936) (`func(fileTypeSpec, rawFileTypeSpec *ast.TypeSpec, pkgDeclCounts map[string]int) error`): Verifies `type File struct { *file }` (single embedded `*file` field) and that `type file struct` has no exported fields.
- [`verifyOSExitIntegrity`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L6938-L7073) (`func(files []*ast.File, exitFn *ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsTestlog, fileImportsSyscall map[*ast.File]bool, osReserved map[string]bool) error`): Verifies `os.Exit(code)` calls `syscall.Exit(code)` directly (preceded only by an optional inactive hook) and that no other reachable `os` code calls `Exit` or `syscall.Exit` unless guarded by an inactive hook.
- [`verifyOSEpipecheck`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L7075-L7124) (`func(fn *ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsSyscall map[*ast.File]bool, osNoFileReserved, osAnyLinknameLocals map[string]bool) error`): Verifies `epipecheck(file *File, e error)` only calls `sigpipe()` when `e == syscall.EPIPE` (or is a no-op).
- [`verifyOSFileFdMethods`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L7126-L7225) (`func(fdExported, fdLower *ast.FuncDecl, osNoFileReserved map[string]bool, skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool) error`): Verifies `(*File).Fd()` and optional `(*file).fd()` return `uintptr(f.pfd.Sysfd)` or `uintptr(f.fd)` after nil-check (`^(uintptr(0))`).
- [`isDirinfoSwapCloseIf`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L7227-L7287) (`func(st ast.Stmt, rcRecv string, dirInfoCloseFn *ast.FuncDecl, osNoFileReserved, osAnyLinknameLocals map[string]bool) bool`): Matches `if d := file.dirinfo.Swap(nil); d != nil { d.close() }` in `(*file).close`.
- [`verifyOSOpenFileNolog`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L7289-L7971) (`func(...) error` — **683 lines**):
  - Nested helper closures:
    - `isVerifiedFileLit` (lines 7320–7378): Matches `&File{&file{pfd: poll.FD{Sysfd: ..., IsStream: true, ZeroReadIsEOF: true}, name: name, stdoutOrErr: ...}}`.
    - `verifyNewFileHelper` (lines 7380–7523): Verifies `newFile` helper across Unix (`fdKind`), Windows (`newFile(h, name, kind)`), and Plan 9 (`newFile(fd, name)`).
    - `matchNewFileCall` (lines 7525–7585): Matches calls to `newFile(...)`.
    - `isPathErrorReturn` (lines 7641–7662): Matches `return nil, &PathError{Op: "open", Path: name, Err: err}`.
    - `verifyIgnoringEINTR` (lines 7687–7689): Wrapper for `verifyOSIgnoringEINTR`.
    - `verifyJoinPathHelper` (lines 7691–7704) & `isMinusOneLit` (lines 7706–7713).
    - `verifyOpenHelper` (lines 7715–7848): Verifies `os.open` (`openat` / `syscall.Open`) helper.
  - Verifies 3 open acquisition forms (`ignoringEINTR(func() error { ... open/syscall.Open ... })`, direct `syscall.Open`, and Plan 9 `O_CREATE` `syscall.Create`/`syscall.Open` branch) followed by `newFile` construction and optional `runtime.SetFinalizer`.
- [`verifyOSReadFile`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L7973-L8253) (`func(...) error` — **281 lines**):
  - Verifies `ReadFile(name string) ([]byte, error)` has 4 statements (`Open(name)`, `if err != nil { return nil, err }`, `defer f.Close()`, `return readFileContents(...)` or inline read loop).
  - Runs BFS over `readFileContents`, `statOrZero`, and `(*File).Read` helper functions/methods to ensure none access `testlog` or call `Open`, `OpenFile`, `Stat`, `Lstat`, `Getenv`, `Chdir`, `Getwd`, or `syscall.{Open,Openat,Stat,Lstat,Getenv,Chdir,Getwd}`.
- [`funcHasUnnamedResults`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L8255-L8265) (`func(ft *ast.FuncType, count int) bool`).
- [`verifyOSIgnoringEINTR`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L8267-L8323) (`func(...) bool`): Verifies `ignoringEINTR(fn func() error) error` retry loop (`for { err := fn(); if err != syscall.EINTR { return err } }`).
- [`verifyOSGetwd`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L8325-L9999) (`func(...) error` — **1,675 lines for a single function!**):
  - Nested helper closures:
    - `isGetwdCacheSelect` (lines 8342–8358), `isSameFileIdentCall` (lines 8360–8380), `callReachesSameFile` (lines 8382–8399), `ifCondChecksSameFile` (lines 8401–8439).
    - `stmtReturnsIdent` (lines 8441–8459), `stmtWritesGetwdCacheIdent` (lines 8461–8492), `ifBodyCachesAndReturnsIdent` (lines 8494–8507).
    - `ifBodyBreaksOuter` (lines 8509–8545), `ifChecksSlashOrRootStatAndBreaks` (lines 8547–8603).
    - `stmtAssignsIdentFromSyscallGetwd` (lines 8605–8662), `stmtAssignsStatCall` (lines 8664–8687), `blockAssignsStatCall` (lines 8689–8704).
    - `blockReadsPWDInto` (lines 8706–8730), `blockReadsGetwdCacheInto` (lines 8732–8775).
    - `exprMentionsIdent` (lines 8777–8787), `exprIsPureDotChain` (lines 8789–8826), `stmtMutatesIdent` (lines 8828–8920).
    - `blockVerifiesHintViaSameFileAndReturns` (lines 8922–9132): Verifies that any cached/env `dir` hint (`$PWD` or `getwdCache.dir`) is validated via `statNolog(dir)` and `SameFile(dot, d)` before returning.
    - `verifyParentClimbLoop` (lines 9134–9520): Verifies the fallback `".."` parent-climbing `for` loop (`openDirNolog`/`Open`, `Readdirnames`, `lstatNolog(parent + "/" + name)`, `SameFile` match, `SameFile(pd, root)` termination).
  - Verifies `os.Getwd()` body across 5 statement shapes (direct `syscall.Getwd`, `PWD`/`getwdCache` hint check, root `"/"` check, error return, and parent-climb loop).
  - Audits every reference to `getwdCache` across the entire `os` package (lines 9564–9797) to prove that only `Getwd` (after `SameFile` verification) and `Chdir` (after `syscall.Chdir` succeeds and before `testlog.Logger().Chdir`) ever write `getwdCache.dir`.
  - Verifies `ignoringEINTR2`, `NewSyscallError`, `openDirNolog`, `verifyOSSameFile`, and `verifyOSNologStatHelpers` (lines 9799–9998).
- [`verifyOSSameFile`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L10001-L10307) (`func(...) (string, error)` — **307 lines**):
  - Verifies `SameFile(fi1, fi2 FileInfo) bool` type-asserts both arguments to `*fileStat`, delegates to `sameFile(fs1, fs2 *fileStat) bool` (with an optional disjoint alternate FileInfo implementation helper), and verifies `sameFile` returns a pure `&&` conjunction of `fs1.<field> == fs2.<field>` comparisons (after an optional `loadFileId()` prelude on Windows).
- [`verifyOSNologStatHelpers`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L10309-L11113) (`func(...) error` — **805 lines**, spanning the 10,500-line Part 1 boundary):
  - Runs a worklist over `statNolog`, `lstatNolog`, `fstatNolog`, `(*File).Stat`, and `(*fileStat).loadFileId`.
  - Implements a full two-pass lexical scope binder (`bindStatExpr` at lines 10478–10565, `bindStatStmt` at lines 10567–10797) that binds every `*ast.Ident` to its declaring `*ast.Ident` (`identBinding`) to prove that:
    1. Every returned `*fileStat` is freshly allocated (`&fileStat{...}` or `new(fileStat)`) and populated by a kernel stat syscall (`syscall.{Stat,Lstat,Fstat,Fstatat}`, `pfd.Fstat`, `GetFileAttributesEx`, etc.).
    2. No helper accesses `testlog` or mutates package-level state.

---

## 5. Structural Analysis: Why `toolchainaudit.go` Grew to 21,306 Lines and How to Collapse It

### 5.1 Quantitative Breakdown of `closure/toolchainaudit.go` (Part 1: Lines 1–10500)

| Subsystem in Part 1 | Line Range | Line Count | % of Part 1 | Primary Cause of Volume |
| :--- | :--- | ---: | ---: | :--- |
| Verdict types, memo keys, pure allowlists | 1–590 | 590 | 5.6% | 19 separate `map[string]bool` literals duplicating `internal/auditset` |
| Surface/delegate orchestration & directives | 592–1631 | 1,040 | 9.9% | 3 duplicated memo wrappers, 2 parallel package I/O pipelines, 4 linkname scanners |
| Cgo preamble + custom C preprocessor/scanner | 1633–3118 | 1,486 | 14.2% | Full non-deterministic C preprocessor (`#define`, `##`, `#`, `__VA_OPT__`) for `.s`/`.h`/cgo |
| Off-surface reachability & `runtime` gates | 3120–4584 | 1,465 | 14.0% | Custom scope-tracking AST walker (`walkOffSurfaceAST`) + manual `atomic` gate matcher |
| Assembly & pure-package AST verifiers | 4586–5393 | 808 | 7.7% | Custom assembly lexer + 16-branch selector cascade in `verifyPurePackageAST` |
| `os` package structural AST verifiers | 5395–10500 (+613) | 5,106 (+613) | 48.6% | Bespoke statement-index AST pattern matching (`verifyOSGetwd` alone = 1,675 lines!) |

---

### 5.2 The Seven Root Causes of the 21,306-Line Bloat

#### Root Cause 1: Manual Statement-by-Statement ASTUnwrapping Instead of Compositional AST Matchers (Accounts for ~65% of file volume)
Because `toolchainaudit.go` inspects Go standard library source using raw `go/ast` type assertions without a pattern-matching DSL or combinator library, matching even a 3-line Go idiom requires 40–90 lines of deeply nested `switch`/`ok` boilerplate.
- **Concrete Evidence**:
  - Checking `if f == nil { return ErrInvalid }` in `(*File).checkValid` ([lines 6167–6186](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L6167-L6186)), `(*File).Write` ([lines 6267–6286](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L6267-L6286)), `(*File).Fd` ([lines 7144–7166](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L7144-L7166)), and `(*File).Close` ([lines 6579–6598](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L6579-L6598)) is written out four separate times by manually unwrapping `*ast.IfStmt` -> `*ast.BinaryExpr` (`token.EQL`) -> `astEqualIdent(f, "nil")` -> `*ast.ReturnStmt`.
  - Checking `return nil, &PathError{Op: ..., Path: ..., Err: ...}` is manually unwrapped in `(*File).wrapErr` ([lines 6214–6246](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L6214-L6246)), `isPathErrorReturn` in `verifyOSOpenFileNolog` ([lines 7641–7662](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L7641-L7662)), and `verifyOSGetwd` ([lines 9926–9980](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L9926-L9980)).
  - Checking `for { err := fn(); if err != syscall.EINTR { return err } }` is written twice: `verifyOSIgnoringEINTR` ([lines 8267–8323](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L8267-L8323), 57 lines) and `ignoringEINTR2` inside `verifyOSGetwd` ([lines 9799–9862](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L9799-L9862), 64 lines), differing only in 1 vs 2 return values.

#### Root Cause 2: Four Separate Custom Lexical Scope & Mutation Walkers Built on Raw `go/ast`
Because `toolchainaudit.go` parses individual `.go` files with `go/parser` without running `go/types` resolution (or a single shared AST symbol-binding pass), it re-implements Go's lexical scoping and variable-mutation rules **four separate times** inside Part 1 alone:
1. [`walkOffSurfaceAST`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3721-L3957) (237 lines): Tracks block scopes, `:=` short var decls, `if`/`switch`/`for`/`range`/`select` scopes, and `TypeSwitchStmt` to resolve free identifiers in off-surface packages.
2. [`declOrBodyShadowsIdent`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L5321-L5393) (73 lines): Checks whether an import alias, package-level declaration, parameter, or local `:=`/`var` shadows a package-level identifier inside a function.
3. [`stmtMutatesIdent` + `exprIsPureDotChain` + `getwdCache` mutation auditor](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L8789-L9797) (345 lines inside `verifyOSGetwd`): Tracks local shadowing, `:=` redeclaration, `&ident` address-taking, and field assignment on `dir` and `getwdCache`.
4. [`bindStatExpr` + `bindStatStmt` + Pass 2a mutation/escape analysis](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L10467-L10878) (412 lines inside `verifyOSNologStatHelpers`): Builds a complete `identBinding map[*ast.Ident]*ast.Ident` lexical binder for Go statements/expressions and then runs a mutation/address-escape pass over those bindings!
- **Consolidation Opportunity**: A single shared `bindPackageAST(files []*ast.File) *PackageBindings` pass (~250 lines total, generalized from `bindStatExpr`/`bindStatStmt` + top-level/import resolution) gives every verifier in `toolchainaudit.go` exact `*ast.Ident -> Decl` resolution, local-vs-package-scope disambiguation, and mutation/address-taking sets—deleting >1,000 lines of repeated scope walkers across Part 1 and Part 2.

#### Root Cause 3: Syntactic Per-Platform Statement Enumeration in `os` Instead of Semantic Dataflow Contracts (`verifyOSGetwd` = 1,675 lines)
- [`verifyOSGetwd`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L8325-L9999) is **1,675 lines long** to verify a single 90-line stdlib function (`os.Getwd`).
- Why? Because instead of checking the **essential security contract** of `os.Getwd` (namely: *(1)* `Getwd` never calls `testlog.Getenv("PWD")` or `testlog.Stat`/`testlog.Open`; *(2)* any string read from `$PWD` or `getwdCache.dir` is only returned if guarded by a dominating `SameFile(statNolog("."), statNolog(hint))` branch; *(3)* `getwdCache.dir` is only written with a validated directory or inside `Chdir` before `testlog.Logger().Chdir`), `verifyOSGetwd` hardcodes the exact syntactic statement layout of `os/getwd.go` (`len(stmts)` bounds, exact `for` loop statement order, exact `if` condition operand orders, 15 nested single-use helper closures).
- Similarly, [`verifyOSOpenFileNolog`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L7289-L7971) (683 lines) and [`verifyOSPackageAST`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L5395-L6868) (1,474 lines) enumerate Unix, Windows, and Plan 9 statement layouts (`pfd.Write` vs `syscall.Write`, `pfd.Close` vs `fdmu.IncrefAndClose`, `ignoringEINTR(open)` vs `syscall.Create`) line-by-line.
- Expressing `os` verification as **contract predicates over the bound call/CFG graph** of each entrypoint (mandatory dominating hook call `testlog.{Getenv,Open,Stat}`, forbidden callees on `*Nolog` helpers, and dominating guard predicates for `getwdCache`/`SameFile`) collapses the 5,719-line `os` verifier suite (`verifyOS*`) to ~900 lines.

#### Root Cause 4: Split-Brain Pure Allowlist Tables Between `internal/auditset` and `closure/toolchainaudit.go` + 16-Way Cascade in `verifyPurePackageAST`
- `internal/auditset/auditset.go` defines the audited symbol tables for `fmt`, `math`, `reflect`, `sync`, `sync/atomic`, `time`, `math/rand`, `crypto/fips140`.
- `closure/toolchainaudit.go` (lines 143–452) defines a **second, parallel set of 15 selector maps** (`allowedPureFmtSelectors`, `allowedPureMathSelectors`, `allowedPureReflectSelectors`, `allowedPureSyncSelectors`, `allowedPureSyncAtomicSelectors`, `allowedPureTimeSelectors`, `allowedPureMathRandSelectors`, etc.).
- Then [`verifyPurePackageAST`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L5214-L5304) dispatches across those maps using a 90-line `if importPath == "fmt" { ... } else if importPath == "math" { ... }` 16-way `else if` chain!
- **Consolidation Opportunity**: Replace the 15 selector maps and the 16-way `else if` cascade in `verifyPurePackageAST` with a single declarative table:
  ```go
  type pureImportRule struct {
      onlyInPkg map[string]bool // nil = any pure/delegate package
      selectors map[string]bool
      extraCheck func(sel *ast.SelectorExpr) error
  }
  var pureSupportImportRules = map[string]pureImportRule{ ... }
  ```
  And derive the common subsets directly from `auditset` + explicit internal-only extensions. This collapses lines 143–452 and 5214–5304 by ~300 lines and eliminates drift between `auditset` and `toolchainaudit.go`.

#### Root Cause 5: Four Overlapping `//go:linkname` Directive Scanners
In lines 1377–5030, `//go:linkname` comments are parsed in **four separate functions** with subtly different whitespace/argument handling:
1. [`verifyHarnessFileDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1428-L1510): Uses `scanGoDirectiveComments` + `strings.Fields( trimmed )`.
2. [`collectGoLinknameTargets`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1576-L1631): Uses `scanGoDirectiveComments` + `auditset.BoundedToken` + `strings.Fields`.
3. [`scanOffSurfaceGoDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3679-L3719): Uses `scanGoDirectiveComments` + `auditset.BoundedToken` + `strings.Fields` (also scanning `//go:cgo_import_dynamic` and `//go:cgo_import_static`).
4. [`verifyFileLinknameDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L4995-L5030): Uses `scanGoDirectiveComments` + `strings.Fields` for pure packages.
- **Consolidation Opportunity**: Parse all `//go:` directives once per file into a typed `[]goDirective` slice (`Kind`, `Args []string`, `Raw string`) during file loading. All four consumers become 10-line table checks over `[]goDirective`.

#### Root Cause 6: Three Nearly Identical Memoization Wrappers and Two Parallel Package I/O Pipelines
- [`verifyListedPackageMemoized`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L846-L891), [`verifyPureDelegateMemoized`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L893-L938), and [`verifyOffSurfacePackageMemoized`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3133-L3173) are three copy-pasted 45-line functions (differing only in the `*sync.Map` and compute callback), accompanied by three copy-pasted key builders (`verifiedPackageMemoKeyWithPolicy`, `verifiedPureDelegateMemoKeyWithPolicy`, `verifiedOffSurfaceMemoKeyWithPolicy`, lines 101–132). A single generic helper `memoizePackageVerdict[V any](ctx, memo, prefix, lp, policy, salt, compute)` replaces all six functions in 35 lines.
- Similarly, [`verifyPureCandidateWithIOAndSalt`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L970-L1091), [`verifyListedPackageWithIOAndSalt`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L1097-L1375), and [`verifyOffSurfacePackageWithIO`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L3175-L3275) all duplicate the exact same 110-line file-reading, extension-classification, `loadPkgIncludeHeadersForPackage`, `scanPreprocessedNonGoSymbolRefs`, `parser.ParseFile`, and `digestListedPackageUntraced` TOCTOU check loop! Extracting a single `loadAndParseListedPackage(ctx, lp, pkgIncludeSalt, allowedExts)` loader eliminates ~250 lines of duplicated I/O and hashing boilerplate (and lets us hash the in-memory buffers directly instead of reading every file from disk a second time for TOCTOU).

#### Root Cause 7: Inline 1,800-Line C Preprocessor and Assembly Scanner Inside `toolchainaudit.go`
- Lines 1633–3118 (1,486 lines) and 4586–4993 (408 lines) implement a standalone C preprocessor (`#define`, `#undef`, `#include`, token pasting `##`, stringizing `#`, `__VA_OPT__`, octal/hex/universal C string unescaping, Mach-O/gccgo symbol extraction) and Go assembly verifier.
- Having 1,894 lines of C/assembly lexical preprocessing embedded directly inside `toolchainaudit.go` obscures the Go package verification logic and makes unit-testing the C/assembly scanner in isolation harder. Moving this self-contained scanner into `closure/toolchainasm.go` (or an internal package) cleanly separates non-Go preprocessing from Go AST contract verification.

---

### 5.3 Concrete Architecture for a Compact, Declarative AST/Contract Verification Engine

By applying the consolidations above across `closure/toolchainaudit.go`:

1. **`closure/astmatch.go` (~350 lines)**:
   - Shared `PackageBindings` pass (resolving every `*ast.Ident` to its package/file/local declaration, computing mutated variables, address-taken variables, and call edges once per package).
   - Compositional AST/CFG matchers: `MatchIdent`, `MatchSel`, `MatchCall`, `MatchNilGuardReturn`, `MatchPathErrorWrap`, `MatchEINTRLoop`, `DominatesCall`, `ReachableCallees`.
2. **`closure/toolchainasm.go` (~1,200 lines)**:
   - Self-contained C preprocessor, assembly directive/opcode verifier, and unified `//go:` directive parser (`parseGoDirectives`).
3. **Declarative Package Contract Table in `closure/toolchainaudit.go`**:
   - Unified `loadAndParseListedPackage` (hashing in-memory bytes once against `lp.digest` with zero TOCTOU re-reads) + generic `memoizePackageVerdict[V]`.
   - Table-driven `pureSupportImportRules` replacing the 15 selector maps and 16-way `else if` cascade.
   - Declarative entrypoint contracts for `os` (`Getenv`, `LookupEnv`, `Open`, `Create`, `OpenFile`, `ReadFile`, `ReadDir`, `Stat`, `Lstat`, `Chdir`, `Getwd`, `SameFile`, `File` methods) expressed over `PackageBindings` and `DominatesCall`/`ReachableCallees`, shrinking Part 1 of `toolchainaudit.go` from **10,500 lines to ~2,400 lines** (~77% reduction) with zero loss of fail-closed verification rigor.
