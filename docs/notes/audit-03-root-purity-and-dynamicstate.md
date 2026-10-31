# Audit 03 — Root Static and Dynamic-State Analysis Monoliths (`purity.go` & `dynamicstate.go`)

## 1. Executive Summary & Ground-Truth Scope Characterization

| File | Total Lines | Total Bytes | Package | Primary Role in Current Codebase |
| :--- | ---: | ---: | :--- | :--- |
| [`purity.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go) | 9,892 (9,893 w/ EOF) | 340,675 | `gofresh` | Subject directive scan (`//gofresh:pure`, `//gofresh:external`) **plus** a 9,300-line AST + `go/types` static dataflow, alias, escape, seam-bracketing, constructor-provenance, parameter/receiver summary, and pool/memo/interface-closure analysis engine for `REQ-closure-shared-dynamic-state`. |
| [`dynamicstate.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go) | 2,896 (2,897 w/ EOF) | 110,174 | `gofresh` | Per-package `dynamicStateFact` extraction (31 string-encoded relational fields), version-pinned bucket memoization (`processFactCache` + disk), test-binary cone slicing, cross-package fixed-point solver (`composeDynamicState`, `newDeferralResolution`, `resolveEnvAudit`), and SSA/RTA reachability discharge bridge (`dischargeUnreachableCulprits`, `dischargeBinaryUnreachableCulprits`). |
| **Combined** | **12,788** | **450,849** | `gofresh` | **58% of the root `gofresh` package's non-test code** is a standalone AST-based whole-program static analysis engine living outside `closure/`. |

### Crucial Ground-Truth Clarification on Subsystem Homes
A line-by-line reading of all 12,788 lines establishes two critical architectural facts:
1. **No SSA or Native Disassembly in `purity.go` / `dynamicstate.go`**: Neither file imports `go/ssa`, and neither contains assembly parsers or ELF/Mach-O/PE/DWARF/x86_64/arm64 machine-code disassembly (those live in `closure/toolchainaudit.go`, `closure/analyzer.go`, `closure/attribution.go`, and `closure/freshpath.go`). Instead, `purity.go` and `dynamicstate.go` operate **exclusively over `go/ast`, `go/types`, and `go/packages`** — only crossing into `closure`'s SSA/RTA engine at the very end of `scanViewSubjects` (`purity.go:179-198`) when `dischargeUnreachableCulprits` / `dischargeBinaryUnreachableCulprits` (`dynamicstate.go:716-884`) call `hasher.ComputeRootedFunctions` / `hasher.ComputeBinaryRootedFunctions` to filter AST-attributed culprit sites against SSA RTA reachability.
2. **Severe Misnomer and Split-Brain Monolith**:
   - [`purity.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go) is named after `ScanPureDirectives` (`//gofresh:pure`), which occupies only **lines 22–655 (~6.4% of the file)**.
   - The remaining **9,237 lines of `purity.go` (lines 657–9892)** are 100% dedicated to **shared-dynamic-state analysis** (`REQ-closure-shared-dynamic-state`): lexical save/restore and mutex/atomic hook seam recognition (`bracketedSeamNodes`), carrier mutation/escape classification (`recordDynamicGlobalUses`), closure environment capture auditing (`environmentFreeFuncLitJudged`), function-field and dispatch-table population tracking (`classifyFieldRegistrants`, `recordEnvCarryingRegistrations`), inter-procedural constructor return proofs and parameter-storage insertion proofs (`returnEnvFreeFunctions`), bound-value leak-free and retention-free dataflow (`boundValueJudged`, `paramLeakFreeFunctions`), receiver read-only and retention-free method proofs (`receiverReadOnlyMethods`, `receiverRetentionFreeMethods`), `sync.Once` memo fill proofs, `sync.Map` data-memo proofs (`dataMemoVars`), closed unexported interface field devirtualization (`closedInterfaceFields`), `sync.Pool` content-type proofs (`provenSharedPools`), function reference-region classification (`recordFunctionReferenceRegions`), and object-closed interface sentinel auditing (`recordOpaqueDynamicVars`).
   - [`dynamicstate.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go) is not a separate subsystem; it is the **serialization, caching, and cross-package relational composition half** of the exact functions defined in `purity.go:657-9892`.

---

## 2. Public Surface & Persistence Boundary Analysis

### 2.1 Exported Go Symbols in `purity.go` and `dynamicstate.go`

| Symbol | File & Lines | Signature | Domain Essential vs. Plumbing Assessment |
| :--- | :--- | :--- | :--- |
| [`ScanPureDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L36-L42) | `purity.go:36-42` | `func ScanPureDirectives(dir string, env, buildFlags []string, pkgPaths ...string) (func(Subject) bool, error)` | **Public API with severe hidden work defect**: Documented as returning a predicate marking symbols carrying `//gofresh:pure`. Internally calls `scanSubjectsInWithBuildFlagsEnv` → `scanViewSubjects` (`purity.go:49-58`), which loads the **entire mutable-local package graph**, runs **`deriveViewDynamicState` across all dependencies** (including loading missing pinned modules and computing 31-field dynamic state facts and fixed points!), and then **throws away** `state`, `load`, `openWorld`, `downgradeReason`, etc., returning only `scan.directivePure`. |

*(Note: `dynamicstate.go` exports zero top-level Go identifiers, but defines persisted JSON schemas and mutates `subjectScan` fields that project directly into `Verdict`, `Snapshot`, and `ExplainDynamicState`.)*

### 2.2 Persisted Cache Schemas & Wire Formats Defined in Scope

| Schema Type / Constant | File & Lines | Cache Layer / Consumer | Architectural Assessment |
| :--- | :--- | :--- | :--- |
| [`scanEntryVersion = 5`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L221) | `purity.go:221` | `closure.LoadScanFacts` / `closure.StoreScanFacts` | Versions persisted `packageScanEntry` JSON blobs. Tightly coupled to exact diagnostic string wording (`DowngradeReason` includes human-readable channel prose). |
| [`subjectScanEntry`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L224-L239) | `purity.go:224-239` | `packageScanEntry.Subjects` | Persists per-subject scan results (`Pure`, `OpenWorld`, `External`, `DowngradeReason`, `DowngradeCulprit`, `VouchDischarges`, `AttestationDischarges`, `PackageProcessDischarges`, `Ambiguous`). |
| [`packageScanEntry`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L243-L246) | `purity.go:243-246` | `closure.LoadScanFacts` / `closure.StoreScanFacts` | Keyed by `hasher.PackageScanKey(pkgPath)`. Notice the inverted layering: `closure` owns the cache store (`LoadScanFacts`/`StoreScanFacts`), while root `gofresh` defines the schema stored in it. |
| [`dynamicStateFact`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L27-L280) | `dynamicstate.go:27-280` | `processFactCache` (`sync.Map`) & `closure.LoadDynamicStateFacts` / `StoreDynamicStateFacts` | **31-field JSON struct** where almost every field is a `[]string` of ad-hoc `\x00` (NUL) and `\x01` (SOH) delimited tuples (`MethodUses`, `ParamLeakFree`, `ParamLeakFreeDeps`, `ParamRetentionFree`, `ParamRetentionFreeDeps`, `ParamUses`, `InitParamUses`, `InitMethodUses`, `CarrierLinks`, `FieldParamUses`, `ElemParamUses`, `FieldParamDefer`, `FieldParamPoison`, `ReturnFieldParamDefer`, `ReturnFieldParamPoison`, `AttributedUses`, `FuncRefs`, `OpacityBreaks`, `OpaqueDeps`, `EnvCarrying`, `EnvCallable`, `EnvCallUses`, `ReturnEnvFree`, `ReturnEnvDeps`, `ParamInsertionFree`, `ReturnEnvInsertionDeps`, `ParamInsertionDeps`). Again, `closure` owns disk persistence (`LoadDynamicStateFacts`), while root `gofresh` owns the schema. |

---

## 3. Exhaustive Line-by-Line Inventory of `purity.go` (Lines 1–9,892)

### 3.1 Section Map of `purity.go`

| Line Range | Subsystem / Responsibility | Lines |
| :--- | :--- | ---: |
| `1–20` | Package declaration and imports (`go/ast`, `go/token`, `go/types`, `go/packages`, `closure`, `gotool`, `internal/auditset`). | 20 |
| `22–359` | **Subsystem A1**: View-level subject scan orchestration (`ScanPureDirectives`, `scanViewSubjects`), scan-memo persistence (`packageScanEntry`, `subjectScanEntry`, `entryOf`, `mergeEntries`, `scanFromEntries`), and `subjectScan` state container. | 338 |
| `360–655` | **Subsystem A2**: AST + `types.MethodSet` subject enumeration, `init#<file>#<ordinal>` naming, `//gofresh:pure` & `//gofresh:external` directive extraction, `openWorldTerm` signature check, and ambiguous-declaration detection (`scanSubjectsFromLoaded`, `nodeDeclarationKey`, `objectDeclarationKey`, `hasDirective`, `recvTypeName`). | 296 |
| `657–784` | **Subsystem B1**: Shared-dynamic-state key helpers (`dynamicVarKey`), `attributedUse` / `pendingReturnDisposition` structs, callee unwrapping (`unwrapCallee`, `plainCalleeFunc`), and passive explain-hook emitters (`explainMark`, `explainDeferralMark`). | 128 |
| `785–1846` | **Subsystem B2**: Lexical seam & hook-bracketing recognizer (`bracketedSeamNodes`) — 1,062 lines recognizing (1) mutex-bracketed unexported `sync/atomic.Pointer[T]` hooks and (2) lexically bracketed save-and-restore or zero-reset seams on package variables/fields. | 1,062 |
| `1848–3636` | **Subsystem B3**: Package-level dynamic carrier use & escape classifier (`recordDynamicGlobalUses`) — 1,789 lines walking AST declarations/bodies, computing init-local carrier aliases (`initAliasedLocals`) with a multi-pass parameter seed fixpoint, classifying exempt init-flow calls (`scanExemptCalls`), classifying program-code reads/mutations/escapes (`walkBody`), attributing named-function/method sites, and solving a package-local fixed point over functions that return range-bound carrier aliases (`pendingReturns`). | 1,789 |
| `3638–3894` | **Subsystem B4**: Signature-carrier type predicates (`typeCarriesSignature`, `callResultHandsOut`) and closure-environment capture leak-free prover (`environmentFreeFuncLit`, `environmentFreeFuncLitJudged`). | 257 |
| `3896–4637` | **Subsystem B5**: Function-field & dispatch-table registrant classifier (`fieldRegMark`, `classifyFieldRegistrants`, `classifyRegistrantFlow`, `classifyRegistrantComposite`, `classifyFieldRegistrantValue`, `classifyLiteralRegistrant`) and package-wide environment-carrying store auditor (`recordEnvCarryingRegistrations`, `plainNamedCalleeFn`). | 742 |
| `4639–6310` | **Subsystem B6**: Constructor return-environment-free & parameter-storage-insertion prover (`auditedValuePlane`, `returnEnvFreeFunctions`, `recordReturnFieldRegistrants`) — 1,672 lines implementing a full intra-procedural alias/backing-link, freshness (`freshObj`), slot-vs-deep write (`deepWrite`), union-find (`aliasFind`), and fixpoint use-resolution engine. | 1,672 |
| `6312–7395` | **Subsystem B7**: Bound-value leak-free & retention-free dataflow engine (`initOnlyReachableHelpers`, `boundValueLeakFree`, `boundValueLeakFreeDeferred`, `boundValueLeakFreeJudged`, `boundValueRetentionFreeJudged`, `boundValueJudged`), parameter summary prover (`paramLeakFreeFunctions`), and receiver retention-free method prover (`receiverRetentionFreeMethods`). | 1,084 |
| `7397–7831` | **Subsystem B8**: `sync.Once` memo-fill helpers (`fillSelection`, `typeReachesOnce`, `onceFieldCount`, `dataMemoMethod`, `auditedOnceDo`, `onceFieldOfDo`) and intra-package direct-call-site indexer (`callSiteIndex`, `callSiteParam`, `directCallSites`, `initOnlyHelpers`, `funcParamsOf`, `resolveParam`, `judgeExpr`). | 435 |
| `7833–7961` | **Subsystem B9**: Generic `sync.*` variable call walker (`walkSyncVarCalls`) and unexported `sync.Map` carrier-free data-memo prover (`dataMemoVars`). | 129 |
| `7963–8230` | **Subsystem B10**: Closed unexported struct interface-field devirtualizer (`closedInterfaceFields`, `closedFieldDispatchTargets`, `unexportedDispatchTargets`). | 268 |
| `8232–9048` | **Subsystem B11**: Receiver read-only method prover (`receiverReadOnlyMethods` — 708 lines with taint fixpoint, `sync.Once` memo fill admission, sibling method chaining, and closed-interface dispatch) plus receiver/result helper predicates (`instantiatedResultsHandOutNothing`, `auditedImmutableType`, `immutableRuntimeType`, `interfaceReceiver`, `methodFactKey`, `auditedSynchronization`). | 817 |
| `9050–9319` | **Subsystem B12**: Content-proven `sync.Pool` analyzer (`auditedPooling`, `provenSharedPools`, `provenPoolContentType`, `provenPoolCallConforms`, `recvTypeNameOf`). | 270 |
| `9321–9892` | **Subsystem B13**: Cross-package function reference-region scanner (`recordFunctionReferenceRegions`), object-closed interface sentinel prover (`recordOpaqueDynamicVars`), and mutable/alias carrier type predicates (`typeHandsOutMutableReach`, `rangeBindsAlias`, `typeHandsOutDynamicAlias`, `eachCompositeLitValue`). | 572 |

### 3.2 Complete Type, Constant, Variable, and Function Inventory of `purity.go`

#### Constants & Package-Level Variables
- [`sharedDynamicStatePrefix`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L47) (`L47`): `"package graph shares mutated dynamic state: "` — diagnostic prefix for downgraded subjects.
- [`scanEntryVersion`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L221) (`L221`): `const scanEntryVersion = 5` — schema/wording version for persisted `packageScanEntry`.
- [`elemPositionField`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L3941) (`L3941`): `const elemPositionField = "\x02"` — reserved sentinel field name representing a carrier's own element population (for `legs[token](args)` dispatch tables).
- [`auditedValuePlane`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4643-L4647) (`L4643-4647`): `map[string]bool{"slices\x00Clone": true, "slices\x00Concat": true, "maps\x00Clone": true}` — closed set of value-cloning standard functions in `returnEnvFreeFunctions`.

#### Types in `purity.go`
- [`subjectScanEntry`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L224-L239) (`L224-239`): JSON-persisted per-subject scan metadata (9 fields).
- [`packageScanEntry`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L243-L246) (`L243-246`): JSON-persisted per-package scan map (`Version`, `Subjects`).
- [`attestationDischarges`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L252-L255) (`L252-255`): Value struct holding `singleSubject` and `packageProcess` comma-joined discharge strings.
- [`subjectScan`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L328-L356) (`L328-356`): In-memory subject scan result (`pure`, `known`, `openWorld`, `external`, `downgradeReason`, `downgradeCulprit`, `vouchDischarges`, `discharges`, `ambiguous`).
- [`attributedUse`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L690-L706) (`L690-706`): Carrier use attributed to a named function or method (`fn`, `key`, `escape`, `method`, `literal`).
- [`pendingReturnDisposition`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L762-L766) (`L762-766`): Range-bound alias returned by an unexported function (`fn`, `keys`, `attrFn`).
- [`fieldRegMark`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L3900-L3905) (`L3900-3905`): Registered-population disposition for a func-typed struct field or element (`class` `'d'` or `'p'`, `field`, `idx`, `param`).
- [`callSiteIndex`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7521-L7531) (`L7521-7531`): Intra-package direct call-site and parameter-write index (`info`, `callable`, `funcParams`, `params`, `written`, `escaped`, `calls`, `bareCallRefs`, `bareEscaped`).
- [`callSiteParam`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7533-L7540) (`L7533-7540`): Parameter descriptor (`fn`, `index`, `variadic`).

#### Functions & Methods in `purity.go` (with Nested Closure Breakdown)
1. [`ScanPureDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L36-L42) (`L36-42`): Public entry point returning `scan.directivePure`.
2. [`scanSubjectsInWithBuildFlagsEnv`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L49-L58) (`L49-58`): Creates a throwaway `closure.Hasher` and calls `scanViewSubjects`.
3. [`scanViewSubjects`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L71-L215) (`L71-215`): Orchestrates scan-memo lookup (`closure.LoadScanFacts`), graph metadata listing (`hasher.GraphMetadata`), module-cache test-variant refusal (`L129-133`), typed package loading (`closure.LoadViewPackages`), dynamic-state derivation (`deriveViewDynamicState`), subject scanning (`scanSubjectsFromLoaded`), RTA reachability culprit discharge (`dischargeUnreachableCulprits` / `dischargeBinaryUnreachableCulprits`), and scan-memo persistence (`closure.StoreScanFacts`).
4. [`entryOf`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L258-L274) (`L258-274`): Projects `subjectScan` for one package into `packageScanEntry`.
5. [`mergeEntries`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L277-L311) (`L277-311`): Merges cached `packageScanEntry` maps into `subjectScan`.
6. [`scanFromEntries`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L314-L323) (`L314-323`): Allocates `subjectScan` from cached entries when all view packages hit the scan memo.
7. [`(*subjectScan).directivePure`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L358) (`L358`): Predicate lookup in `s.pure`.
8. [`scanSubjectsFromLoaded`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L365-L564) (`L365-564`): Walks AST `FuncDecl`s (`L421-489`) and `types.MethodSet`s (`L493-527`) for requested packages; assigns `init#<file>#<ordinal>` names (`L442-463`); checks `//gofresh:pure` and `//gofresh:external` (refusing conflicts on `L467-475` and `L516-518`); computes `openWorldTerm`; strips directives on ambiguous declarations (`L538-541`); attaches `state.downgraded`, `state.culprits`, `state.vouchDischarges`, `state.attestationDischarges` (`L549-562`).
9. [`openWorldTerm`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L572-L574) (`L572-574`): Thin wrapper around `closure.SignatureOpenWorldTerm(..., closure.CarrierPolicyConsumer)`.
10. [`typeMayCarryUnknownDynamic`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L576-L578) (`L576-578`): Thin wrapper around `closure.WalkDynamicCarrier(..., closure.CarrierPolicyConsumer)`.
11. [`nodeDeclarationKey`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L587-L595) (`L587-595`): Formats `filename:offset` for an `ast.Node`.
12. [`objectDeclarationKey`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L597-L613) (`L597-613`): Formats `filename:offset` (or `pkg.Name` / `universe:...`) for a `types.Object`.
13. [`hasDirective`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L618-L628) (`L618-628`): Exact line match in `*ast.CommentGroup`.
14. [`recvTypeName`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L634-L655) (`L634-655`): Strips parens, pointer star, and generic indices from `fd.Recv`.
15. [`dynamicVarKey`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L662-L667) (`L662-667`): Formats `pkgPath.VarName` for a `*types.Var`.
16. [`recordDynamicGlobalMutations`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L681-L683) (`L681-683`): Test/convenience wrapper around `recordDynamicGlobalUses`.
17. [`unwrapCallee`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L712-L725) (`L712-725`): Strips `*ast.ParenExpr`, `*ast.IndexExpr`, `*ast.IndexListExpr` from a call's `Fun`.
18. [`plainCalleeFunc`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L733-L755) (`L733-755`): Resolves `fun` to a receiverless `*types.Func` (origin) and its package path.
19. [`explainMark`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L771-L775) (`L771-775`): Fires `explainHooks.Load().site` if armed.
20. [`explainDeferralMark`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L779-L783) (`L779-783`): Fires `explainHooks.Load().deferral` if armed.
21. [`bracketedSeamNodes`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L793-L1846) (`L793-1846`):
    - `L798-885`: Collects `addrTaken` package vars and `uninitDecls` (zero-initialized package vars not written in `init` or `initHelpers`).
    - `L887-917` (`stmtMayExitBeforeRestore`): Checks for `return`, branch, `panic`, `Fatal*`, `FailNow`, `Skip*`, `Goexit`, `Exit`.
    - `L919-1243`: **Arm 1 — Mutex-bracketed unexported `sync/atomic.Pointer[T]` hook variables**:
      - `loadResultSafe` (`L1011-1093`): Checks that `v.Load()` is only compared to `nil`, field-selected, or bound once to a local used only for `==`/`!=` or field selection.
      - `funcBracketsAtomic` (`L1094-1222`): Verifies sequential body (`no go`, `no .Parallel()`), statement order `mu.Lock()` (`lockIdx`) < `defer mu.Unlock()` (`unlockIdx`) < `defer v.Store(nil)` (`resetIdx`) < any non-nil `v.Store(...)`, with no early exit before `resetIdx`.
    - `L1245-1844`: **Arm 2 — Lexically bracketed save-and-restore or zero-reset seams**:
      - `candidateVar` (`L1247-1257`), `seamTarget` (`L1264-1300`), `isZeroExpr` (`L1301-1317`).
      - Per-`FuncDecl` inspection (`L1331-1843`): checks sequentiality, single-write immutable locals (`immutableLocal`), escaping closures (`returnedTargets`), whole-vs-field write mixing (`mixedBaseVar`), `defer func() { ... }()` or `t.Cleanup(func() { ... })` restores (`cleanupClosureBody` `L1505-1538`), inner-block poisoning (`poisonedKeys` `L1644-1691`), deferred restore span validation (`L1723-1777`), and inline save-and-restore span validation (`L1779-1841`).
22. [`recordDynamicGlobalUses`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L1865-L3636) (`L1865-3636`):
    - `L1871-1940`: Helpers `dynamicPackageVar`, `resolve`, `markTargets`, and setup of `initOnlyParams` / `paramSeeds`.
    - `L1946-2328` (`initAliasedLocals`): Fixed-point alias analysis over init-flow bodies (`rhsKeys`, `linkKeys`, `storeLink`, `markRHSMethodValues`, `bind`), tracking composite bindings, `copy`, and seeding `initOnlyParams` across helper call sites.
    - `L2332-2400` (`carrierArgVar`, `deferCarrierArgs`): Extracts direct alias-handing carrier arguments for parameter deferral.
    - `L2409-2463` (`poolCarrierIdent`, `dischargePool`): Recognizes package-level `sync.Pool` (or array/slice of `sync.Pool`) receivers.
    - `L2488-2600` (`markExemptEscapes`, `scanExemptCalls`): Scans calls inside init-exempt regions, deferring plain function args to `initParamUses` and static non-interface methods to `initMethodUses` (or discharging `sync.Pool` Get/Put).
    - `L2602-3011` (`walkBody`): Main AST visitor classifying statements/expressions in program code:
      - `AssignStmt` (`L2627-2656`), `IncDecStmt` (`L2657-2658`), `RangeStmt` (`L2659-2785`, invoking `boundValueLeakFreeJudged` on loop bodies and recording `pendingReturns`), `SendStmt` (`L2786-2787`), `UnaryExpr` `&`/`<-` (`L2788-2802`), `IndexExpr` (`L2803-2812`), `BinaryExpr` `==`/`!=` (`L2813-2817`), `GoStmt` (`L2818-2828`), `CallExpr` (`L2829-2902`, handling `len`/`cap`/`delete`/`clear`, `deferCarrierArgs`, and dispatch-table `legs[token](arg)` `elemUses`), `SelectorExpr` (`L2903-2986`, handling `sync.Pool`, `dataMemos`, `exemptSeamNodes`, `methodUses` deferral, and pointer-receiver mutation), `Ident` catch-all escape (`L2987-3007`).
    - `L3016-3037`: Multi-pass seeding loop for `initOnlyParams`.
    - `L3038-3292`: Top-level declaration loop attributing uses in methods (`L3042-3123`) and plain named functions (`L3124-3208`), walking `initOnly` helpers (`L3209-3237`), `init` functions (`L3238-3265`), and `GenDecl` initializers (`L3271-3290`).
    - `L3293-3635`: Package-local fixed-point solver (`scanSites`) for `pendingReturns` (functions returning range-bound carrier aliases).
23. [`typeCarriesSignature`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L3645-L3677) (`L3645-3677`): Recursive `types.Type` walk checking if a type can hand out a `*types.Signature` (excluding `*types.Interface`).
24. [`callResultHandsOut`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L3684-L3698) (`L3684-3698`): Checks if a result type or tuple element satisfies `typeHandsOutMutableReach` or `typeCarriesSignature`.
25. [`environmentFreeFuncLit`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L3713-L3715) (`L3713-3715`) & [`environmentFreeFuncLitJudged`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L3722-L3894) (`L3722-3894`): Finds free variables (`freeVars`) of a `*ast.FuncLit`, closes over local aliases in `enclosing` (`aliasEdges` `L3762-3848`), and verifies `boundValueLeakFreeJudged` over `lit.Body` and every sibling `FuncLit` or `GoStmt` sharing any root variable.
26. [`classifyFieldRegistrants`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L3914-L3924) (`L3914-3924`): Entry point for classifying values stored into func-typed fields or carrier storage.
27. [`unparenExpr`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L3926-L3934) (`L3926-3934`): Strips `*ast.ParenExpr`.
28. [`classifyRegistrantFlow`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L3950-L4005) (`L3950-4005`): Structural classifier over expressions flowing into carrier storage.
29. [`identUseOrDef`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4007-L4015) (`L4007-4015`): Looks up `ident` in `TypesInfo.Uses` then `TypesInfo.Defs`.
30. [`classifyRegistrantComposite`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4022-L4064) (`L4022-4064`): Classifies struct/map/slice/array composite literals for field registrant marks.
31. [`classifyFieldRegistrantValue`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4073-L4112) (`L4073-4112`): Emits `'d'` (defer to named function's parameter facts) or `'p'` (poison) for a func-typed field store.
32. [`classifyLiteralRegistrant`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4114-L4152) (`L4114-4152`): Runs `boundValueLeakFreeJudged` per parameter of a registered `*ast.FuncLit`.
33. [`recordEnvCarryingRegistrations`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4171-L4607) (`L4171-4607`): Walks direct stores in functions and package initializers (`walkStores`, `handleStore`, `computeLocalAliases`, `carrying`), recording `envCarrying`, `envCalls`, `fieldDefer`, and `fieldPoison`.
34. [`plainNamedCalleeFn`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4615-L4637) (`L4615-4637`): Resolves `*ast.CallExpr` to a receiverless `*types.Func` (NOTE: near-duplicate of `plainCalleeFunc` at `L733-755`!).
35. [`returnEnvFreeFunctions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4666-L6159) (`L4666-6159`): 1,494-line intra-procedural + conditional-edge prover for constructor return values and parameter-storage insertions:
    - `L4800-4985`: Helpers `breakIdents`, `breakTargets`, `chainRoot`, `breakBase`, `sharesHeader`, `pairLink`, `linkValue`, `linkBacking`.
    - `L5010-5078` (`bindLocal`): Records local binding sources and `pendingStores`.
    - `L5079-5426`: Body inspection collecting `pendingStores`, `stmtCallDeps`, and `pendingInsertionUses` (`classifyLit`, `classifyArg`).
    - `L5432-5486`: Ascending fixpoint for `freshObj` (`srcFresh`).
    - `L5498-5575` (`deepWrite`): Distinguishes owned-spine slot writes from deep writes (`insertionWrites`).
    - `L5579-5674`: Propagates `localBroken` / `captureBroken` across `aliasPairs` and `heldPairs`; builds union-find (`aliasFind`) and `componentMembers`.
    - `L5700-5915` (`judgeLocal`, `free`): Recursive expression freedom evaluator with cycle tolerance on binding chains.
    - `L5929-6024` (`resolveUses`, `propagateUses`): Fixpoint resolution of `pendingInsertionUses`.
    - `L6039-6080`: Per-parameter `insFree` / `insDeps` derivation.
    - `L6081-6114`: `explainHooks` wrapper around `free` to report refusal clauses.
    - `L6115-6156`: Return statement inspection and call to `recordReturnFieldRegistrants`.
36. [`recordReturnFieldRegistrants`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L6172-L6310) (`L6172-6310`): Collects `retDefer` and `retPoison` field population marks from a proven constructor's body.
37. [`initOnlyReachableHelpers`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L6320-L6325) (`L6320-6325`): Wrapper calling `directCallSites(p).initOnlyHelpers()`.
38. [`boundValueLeakFree`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L6345-L6347) (`L6345-6347`), [`boundValueLeakFreeDeferred`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L6349-L6351) (`L6349-6351`), [`boundValueLeakFreeJudged`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L6379-L6381) (`L6379-6381`), [`boundValueRetentionFreeJudged`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L6389-L6391) (`L6389-6391`), and [`boundValueJudged`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L6393-L7055) (`L6393-7055`): 663-line AST taint + allowed-use consumption engine proving that values rooted in `roots` never leak (or, under `tolerateRootedStores`, never outlive/escape).
39. [`paramLeakFreeFunctions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7068-L7294) (`L7068-7294`): Computes per-parameter leak-free (`proven`, `deps`) and retention-free (`retention`, `retentionDeps`) facts and intra-package fixed points.
40. [`receiverRetentionFreeMethods`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7309-L7395) (`L7309-7395`): Computes intra-package fixed point of methods whose receiver is retention-free under `boundValueRetentionFreeJudged`.
41. [`fillSelection`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7406-L7412) (`L7406-7412`), [`typeReachesOnce`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7416-L7440) (`L7416-7440`), [`onceFieldCount`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7444-L7459) (`L7444-7459`), [`dataMemoMethod`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7463-L7465) (`L7463-7465`), [`auditedOnceDo`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7469-L7473) (`L7469-7473`), [`onceFieldOfDo`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7479-L7512) (`L7479-7512`): `sync.Once` and `sync.Map` memo helper predicates.
42. [`directCallSites`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7543-L7716) (`L7543-7716`), [`(*callSiteIndex).initOnlyHelpers`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7720-L7763) (`L7720-7763`), [`(*callSiteIndex).funcParamsOf`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7767-L7775) (`L7767-7775`), [`(*callSiteIndex).resolveParam`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7786-L7811) (`L7786-7811`), [`(*callSiteIndex).judgeExpr`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7817-L7831) (`L7817-7831`): Package-local call-site indexer and parameter-argument back-propagator.
43. [`walkSyncVarCalls`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7841-L7902) (`L7841-7902`): Shared AST walker for package-level `sync.Map` and `sync.Pool` candidate eviction.
44. [`dataMemoVars`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7917-L7961) (`L7917-7961`): Identifies unexported `sync.Map` package variables whose `Load`/`Store`/`LoadOrStore` calls only pass carrier-free types.
45. [`closedInterfaceFields`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L7978-L8165) (`L7978-8165`), [`closedFieldDispatchTargets`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L8172-L8202) (`L8172-8202`), [`unexportedDispatchTargets`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L8217-L8230) (`L8217-8230`): Closed-world concrete type resolver for unexported interface fields and unexported interface methods.
46. [`receiverReadOnlyMethods`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L8245-L8952) (`L8245-8952`): 708-line intra-package fixed-point prover for read-only receiver methods (including `onceFill` admission `L8528-8578` and closed-interface/sibling chaining `L8814-8858`).
47. [`instantiatedResultsHandOutNothing`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L8960-L8979) (`L8960-8979`), [`auditedImmutableType`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L8986-L8991) (`L8986-8991`), [`immutableRuntimeType`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L8996-L9003) (`L8996-9003`), [`interfaceReceiver`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9007-L9018) (`L9007-9018`), [`methodFactKey`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9023-L9040) (`L9023-9040`), [`auditedSynchronization`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9046-L9048) (`L9046-9048`), [`auditedPooling`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9063-L9065) (`L9063-9065`): Method/type classification helpers.
48. [`provenSharedPools`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9100-L9180) (`L9100-9180`), [`provenPoolContentType`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9206-L9267) (`L9206-9267`), [`provenPoolCallConforms`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9274-L9293) (`L9274-9293`), [`recvTypeNameOf`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9297-L9319) (`L9297-9319`): Content-proven `sync.Pool` analyzer.
49. [`recordFunctionReferenceRegions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9337-L9447) (`L9337-9447`): Scans AST declarations to classify references to plain named functions into `"init"`, `"prog"`, `<callerKey>`, or `"lit:<callerKey>"`.
50. [`recordOpaqueDynamicVars`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9469-L9810) (`L9469-9810`): Audits interface-typed package variables for object-closure (`nil`, constant expressions, `reflect.Type`, `errors.New`, `fmt.Errorf` over audited args, or sibling interface vars via `deps`).
51. [`typeHandsOutMutableReach`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9821-L9849) (`L9821-9849`), [`rangeBindsAlias`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9853-L9869) (`L9853-9869`), [`typeHandsOutDynamicAlias`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9877-L9879) (`L9877-9879`), [`eachCompositeLitValue`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9881-L9892) (`L9881-9892`): Tail type/AST helpers.
---

## 4. Exhaustive Line-by-Line Inventory of `dynamicstate.go` (Lines 1–2,896)

### 4.1 High-Level Subsystem Map of `dynamicstate.go`

| Subsystem | Line Range | Lines | Core Responsibility |
| :--- | :--- | ---: | :--- |
| **1. `dynamicStateFact` Persistence Schema** | [`L27-280`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L27-L280) | 254 | Defines the 31-field JSON-serialized per-package dynamic state summary persisted via `closure.StoreDynamicStateFacts` |
| **2. Per-Package Fact Extraction (`dynamicStateFactOf`)** | [`L288-637`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L288-L637) | 350 | Orchestrates all `purity.go` AST passes on a single `*packages.Package`, packs string-encoded edges into `dynamicStateFact`, and scans method/variable/protobuf directives |
| **3. View & Cone State Containers + Process Cache** | [`L643-699`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L643-L699) | 57 | Defines `processFactCache` (`sync.Map`), `viewDynamicState`, and `coneDynamicState` |
| **4. RTA / Binary Reachability Culprit Discharge** | [`L716-895`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L716-L895) | 180 | Bridges `viewDynamicState` culprit sites to `closure.Hasher.ComputeRootedFunctions` and `ComputeBinaryRootedFunctions` to prune unreachable culprits |
| **5. Audited Third-Party Source Listing & Proto Headers** | [`L907-952`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L907-L952) | 46 | Defines `auditedSourceListing` (`golang.org/x/sys/unix.mapper`, `gopkg.in/yaml.v3.structMap`) and `generatedProtoHeader` |
| **6. Culprit Diagnostic Formatting Model** | [`L954-1071`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L954-L1071) | 118 | Defines `culpritVerb`, `culpritChannel`, `dynCulprit`, `culpritSiteSet`, and `(*viewDynamicState).methodDirectives` |
| **7. View-Level Fact Derivation & Caching (`deriveViewDynamicState`)** | [`L1073-1289`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L1073-L1289) | 217 | Orchestrates 3-tier fact derivation (mutable local ASTs, intermediate `.test` recompilation ASTs, and disk/process-cached pinned module facts) |
| **8. Cross-Package Relational Solver (`composeDynamicState`)** | [`L1300-2279`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L1300-L2279) | 980 | Resolves deferred uses, cross-package `initOnlyFn`/`initReachFn` closures, `AttributedUses`, `CarrierLinks`, 4 discharge channels, and import-graph culprit ranking; plus `dynamicStateCone` and `pinnedBuckets` |
| **9. Cross-Package Fixed-Point Solvers (`resolveEnvAudit`, `newDeferralResolution`)** | [`L2290-2713`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2290-L2713) | 424 | Solves joint least fixed point for `ReturnEnvFree`/`ParamInsertionFree`, transitive parameter leak/retention freedom, `Opaque` break propagation, and struct field/element population proofs |
| **10. String-Encoded Tuple Framing Helpers** | [`L2719-2896`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2719-L2896) | 178 | 19 ad-hoc string framing/parsing helpers splitting and joining `\x00` (NUL), `\x01` (SOH), and `\x02` (STX) tuples |

---

### 4.2 Complete Inventory of Package-Level Variables & Types in `dynamicstate.go`

#### Package-Level Variables
- [`processFactCache`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L643) (`L643`): `sync.Map` storing `[]dynamicStateFact` keyed by `factScope + "\x00" + bucket + "\x00" + node.PkgPath`. Never evicted for the lifetime of the `gofresh` process.
- [`auditedSourceListing`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L907-L916) (`L907-916`): `auditset.VersionListing` hardcoding two third-party package-variable exemptions:
  - `golang.org/x/sys/unix.mapper` (`v0.0.0-20220829200755-d48e67d00261` through `v0.42.0`)
  - `gopkg.in/yaml.v3.structMap` (`v3.0.0-20200313102051-9f266ea9e77c` through `v3.0.1`)

#### Types in `dynamicstate.go`
1. [`dynamicStateFact`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L27-L280) (`L27-280`): 31-field struct with JSON tags (`declares`, `mutates`, `escapes`, `opaque`, `pool_discharges`, `single_subject_vars`, `generated_proto_vars`, `generated_grpc_vars`, `receiver_read_only`, `receiver_retention_free`, `method_uses`, `param_leak_free`, `param_leak_free_deps`, `param_retention_free`, `param_retention_free_deps`, `param_uses`, `init_param_uses`, `init_method_uses`, `carrier_links`, `field_param_uses`, `elem_param_uses`, `field_param_defer`, `field_param_poison`, `return_field_param_defer`, `return_field_param_poison`, `attributed_uses`, `func_refs`, `opacity_breaks`, `opaque_deps`, `env_carrying`, `env_callable`, `env_call_uses`, `return_env_free`, `return_env_deps`, `param_insertion_free`, `return_env_insertion_deps`, `param_insertion_deps`, `pure_methods`, `external_methods`). Actually **39 struct fields** (31 groups of facts)!
2. [`viewDynamicState`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L651-L688) (`L651-688`): View-wide dynamic state result holding `cones map[string]coneDynamicState`, plus legacy/convenience fields (`downgraded`, `culprits`, `vouchDischarges`, `attestationDischarges`, `rootCulprits`, `culpritSites`).
3. [`coneDynamicState`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L692-L699) (`L692-699`): Per-view-package cone dynamic state result holding `downgraded map[string]bool`, `culprit map[string]Subject`, `vouchDischarges map[string]string`, `attestationDischarges map[string]string`, `rootCulprits map[string]map[string]dynCulprit`, and `culpritSites map[string]map[string]culpritSiteSet`.
4. [`culpritVerb`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L954-L973) (`L954-973`): `uint8` enum (`culpritMutated`, `culpritEscapes`, `culpritEnvCarrying`) with `clause() string`.
5. [`culpritChannel`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L975-L1006) (`L975-1006`): `uint8` enum (`channelCallerVouch`, `channelCallerVouchEnvFree`, `channelRestructureOrDirective`, `channelRestructureDirectiveSingleSubjectOnly`, `channelRestructureUnbackedDirective`) with `clause(pkgPath, key string) string`.
6. [`dynCulprit`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L1012-L1029) (`L1012-1029`): Struct (`pkgPath`, `key`, `verb`, `channel`) with `reasonBody() string` and `subject() Subject`.
7. [`culpritSiteSet`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L1035-L1038) (`L1035-1038`): Struct (`fns map[string]bool`, `unattributed bool`).
8. [`deferralResolution`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2290-L2316) (`L2290-2316`): Holds resolved cross-package sets (`receiverReadOnly`, `receiverRetentionFree`, `paramLeakFree`, `paramRetentionFree`, `returnEnvFree`, `notOpaque`, `fieldDefer`, `fieldPoison`, `returnFieldDefer`, `returnFieldPoison`).
9. [`envAuditResolution`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2329-L2334) (`L2329-2334`): Holds joint fixed-point maps (`returnEnvFree`, `paramInsertionFree`, `returnEnvDeps`, `returnEnvInsDeps`, `paramInsDeps`) with `(*envAuditResolution).depResolved` (`L2336-2377`).
10. [`fieldPosition`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2719-L2722) (`L2719-2722`): Struct (`varKey`, `fieldName string`).
11. [`attributedUseRecord`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2724-L2728) (`L2724-2728`): Struct (`fnKey`, `varKey`, `kind string`).

---

### 4.3 Complete Function-by-Function Inventory of `dynamicstate.go`

1. [`dynamicStateFactOf`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L288-L637) (`L288-637`):
   - `L290-335`: Runs `initOnlyReachableHelpers(p)`, `provenSharedPools(p)`, `recordDynamicGlobalUses(audited, p, initHelpers, poolVars, ...)`, `recordFunctionReferenceRegions(p)`, `recordOpaqueDynamicVars(p)`, and `recordEnvCarryingRegistrations(audited, p)`.
   - `L336-393`: Packs `mutated`, `escaped`, `PoolDischarges`, `MethodUses`, `InitMethodUses`, `ParamUses`, `InitParamUses`, `CarrierLinks`, `FieldParamUses`, `ElemParamUses`, `FieldParamDefer`, `FieldParamPoison`, `AttributedUses`, `FuncRefs`, `EnvCarrying`, `EnvCallable`, `EnvCallUses`, `Opaque`, `OpacityBreaks`, and `OpaqueDeps` into sorted string slices on `dynamicStateFact`.
   - `L394-414`: Runs `receiverReadOnlyMethods(audited, p)` and `receiverRetentionFreeMethods(audited, p)`.
   - `L415-436`: Runs `paramLeakFreeFunctions(audited, p)` and packs `ParamLeakFree`, `ParamLeakFreeDeps`, `ParamRetentionFree`, `ParamRetentionFreeDeps`.
   - `L437-513`: Runs `returnEnvFreeFunctions(audited, p)` and packs `ReturnEnvFree`, `ReturnEnvDeps`, `ParamInsertionFree`, `ReturnEnvInsertionDeps`, `ParamInsertionDeps`, `ReturnFieldParamDefer`, `ReturnFieldParamPoison`.
   - `L514-522`: Scans package scope for non-audited dynamic-carrier variables to populate `Declares`.
   - `L523-547`: Scans AST `FuncDecl`s with receivers for `//gofresh:pure` and `//gofresh:external` to populate `PureMethods` and `ExternalMethods`.
   - `L548-586`: Scans AST `GenDecl(token.VAR)` comments for `//gofresh:single-subject` (or inline comments when `singleSubject` is true) to populate `SingleSubjectVars`.
   - `L587-635`: Scans generated files (`generatedmark.HasGeneratedComment`) with `generatedProtoHeader` (`"protoc-gen-go"` or `"protoc-gen-go-grpc"`) to populate `GeneratedProtoVars` and `GeneratedGrpcVars`.
2. [`dischargeUnreachableCulprits`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L716-L764) (`L716-764`): Builds `closure.ReachabilityRequest` per view package with `state.culpritSites`, calls `hasher.ComputeRootedFunctions(analysisCtx, requests)`, and updates `cone.downgraded`, `cone.culprit`, and `cone.attestationDischarges` via `dischargeCulprits`.
3. [`dischargeCut`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L778-L790) (`L778-790`): Distinguishes caller cancellation (`ctx.Err() != nil`) from analysis budget exhaustion (`analysisCtx.Err() != nil`).
4. [`dischargeBinaryUnreachableCulprits`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L811-L858) (`L811-858`): Calls `hasher.ComputeBinaryRootedFunctions(analysisCtx, paths)` and discharges culprits not present in compiled test binary symbol tables.
5. [`dischargeCulprits`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L869-L884) (`L869-884`): Checks each culprit's `culpritSiteSet` against `proof.Fns`; if `sites.unattributed` is false and no site is in `proof.Fns`, marks the culprit discharged.
6. [`joinDischargedKeys`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L888-L895) (`L888-895`): Joins discharged keys into sorted comma-separated list for `attestationDischarges`.
7. [`generatedProtoHeader`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L928-L952) (`L928-952`): Parses `"// Code generated by "` header line for `"protoc-gen-go-grpc"` or `"protoc-gen-go"`.
8. [`(culpritVerb).clause`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L962-L973) (`L962-973`), [`(culpritChannel).clause`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L989-L1006) (`L989-1006`), [`(dynCulprit).reasonBody`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L1019-L1021) (`L1019-1021`), [`(dynCulprit).subject`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L1023-L1029) (`L1023-1029`): Diagnostic message builders.
9. [`(*viewDynamicState).methodDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L1045-L1071) (`L1045-1071`): Formats `"pkgPath.(TypeName).MethodName"` for `m *types.Func` and checks whether the method is downgraded in `viewPackage`'s cone.
10. [`deriveViewDynamicState`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L1073-L1289) (`L1073-1289`):
    - `L1096-1111`: Computes `dynamicStateFactOf` directly for mutable local packages already in `load.Packages`.
    - `L1117-1150`: Identifies missing intermediate `.test` variant packages (`len(node.PackageFiles) > 0`), groups them by `TestVariant`, calls `closure.LoadViewGraph`, and computes `dynamicStateFactOf`.
    - `L1152-1254`: Identifies pinned external packages, computes module-cone buckets (`pinnedBuckets`), checks `processFactCache` and disk cache (`closure.LoadDynamicStateFacts`), batch-loads cache misses via `closure.LoadViewPackages`, computes `dynamicStateFactOf`, and persists via `closure.StoreDynamicStateFacts`.
    - `L1259-1288`: Runs `composeDynamicState` for each `vp` in `viewPackages` and merges into `viewDynamicState`.
11. [`composeDynamicState`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L1300-L2141) (`L1300-2141`):
    - `L1301-1330`: Extracts cone via `dynamicStateCone`, unions `Mutates`, `Escapes`, `EnvCarrying`.
    - `L1332-1350`: Calls `newDeferralResolution(facts, cone)`.
    - `L1354-1473`: Evaluates deferred `EnvCallUses`, `MethodUses`, `InitMethodUses`, `ParamUses`, `InitParamUses`, `FieldParamUses`, and `ElemParamUses` against `deferrals`.
    - `L1479-1555`: Builds cross-package function reference graph from `FuncRefs` and computes two worklist fixed points: `initOnlyFn` (`L1494-1519`) and `initReachFn` (`L1531-1555`).
    - `L1566-1667`: Computes `unattributedMark`, discharges init-only attributed uses that remain non-escaped and non-env-carrying (`initDischarged`), and promotes surviving `AttributedUses` into `mutated`, `escaped`, or `envCarrying` while recording `fnSites`.
    - `L1673-1699`: Propagates `mutated`, `escaped`, and `envCarrying` across `carrierLinkGraph` (in both directions for `mutated`/`escaped`, and `src -> dst` for `envCarrying`).
    - `L1715-1869`: Computes four discharge channels: `vouchedOut` (`L1723-1739`), `auditedSourceOut` (`L1749-1767`), `directiveDischargedOut` (`L1800-1825`), and `generatedProtoOut` (`L1860-1869`, gated on hardcoded `google.golang.org/protobuf` `<= v1.36.11` and `google.golang.org/grpc` `<= v1.82.1`).
    - `L1877-2055`: Ranks culprits per package (preferring unbacked-directive culprits, then `mutated`, `escaped`, `envCarrying` in lexicographic key order) and builds `pkgSites`.
    - `L2057-2140`: Walks each package's transitive import cone to populate `state.downgraded`, `state.culprit`, `state.rootCulprits`, `state.culpritSites`, `state.vouchDischarges`, and `state.attestationDischarges`.
12. [`dynamicStateCone`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2150-L2202) (`L2150-2202`): Extracts the transitive package cone for `viewPackage` (including its `.test` binary root if present).
13. [`pinnedBuckets`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2212-L2279) (`L2212-2279`): Computes SHA-256 over reachable module `Path@Version` pairs for each pinned package; marks packages reaching any mutable module or `Replace != nil` as `unkeyable`.
14. [`(*envAuditResolution).depResolved`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2336-L2377) (`L2336-2377`) and [`resolveEnvAudit`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2380-L2457) (`L2380-2457`): Joint descending fixed-point solver over `ReturnEnvFree` and `ParamInsertionFree`.
15. [`newDeferralResolution`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2459-L2612) (`L2459-2612`) and [`(*deferralResolution).fieldPopulationProves`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L2620-L2713) (`L2620-2713`): Solves cross-package `paramLeakFree`, `paramRetentionFree`, `notOpaque` (with `OpaqueDeps` break propagation), `resolveEnvAudit`, and field/element population deferrals.
16. **19 String-Encoding Helpers** (`L2719-2896`): `encodeAttributedUse` (`L2731`), `parseAttributedUse` (`L2735`), `formatSOHEdge` (`L2749`), `parseSOHEdge` (`L2753`), `formatNULPair` (`L2762`), `parseNULPair` (`L2766`), `isFuncFactKey` (`L2777`), `isParamFactKey` (`L2784`), `parseParamUse` (`L2798`), `parseFieldParamUse` (`L2807`), `parseElemParamUse` (`L2818`), `parseReturnEnvDepEdge` (`L2829`), `parseReturnEnvInsertionDepEdge` (`L2837`), `parseParamInsertionDepEdge` (`L2846`), `parseParamDepEdge` (`L2856`), `parseOpaqueDepEdge` (`L2865`), `parseFieldParamDefer` (`L2873`), `parseFieldParamPoison` (`L2881`), `carrierLinkGraph` (`L2886`).

---

## 5. Deep Architectural & Subsystem Analysis

### 5.1 What `purity.go` and `dynamicstate.go` Actually Compute

Despite the filename `purity.go`, 98% of the 12,788 lines across `purity.go` and `dynamicstate.go` are **not** a general function purity checker. Instead, they form a **two-phase relational static analysis engine** for two specifications:
1. **`REQ-closure-shared-dynamic-state`**: Proving whether any package in a test target's transitive import cone declares a package-level dynamic carrier (`var`) that is mutated after `init()`, escapes to callers, or stores an environment-coupled (`os.Getenv`, `os.Args`, etc.) value; or whether all such variables are discharged via:
   - Read-only / retention-free / leak-free / object-closed (`Opaque`) / `sync.Pool` / `sync.Map` / `sync.Once` / `init()`-only proofs,
   - Caller vouches (`--vouch`),
   - Directives (`//gofresh:single-subject`, `//gofresh:pure`, `//gofresh:external`),
   - Audited source listings (`auditedSourceListing` and generated protobuf/gRPC descriptors), or
   - Whole-program RTA / binary symbol table unreachability (`dischargeUnreachableCulprits` / `dischargeBinaryUnreachableCulprits`).
2. **Test-Boundary Purity (`subjectScanEntry`)**: Scanning each `Test*` / `Fuzz*` function in the target package (`scanPackageTests`, `L1750-1915`) to check:
   - Whether it calls `t.Parallel()` (unless `--single-subject`),
   - Whether it mutates or reads non-discharged package state (`testBodyMutatesPackageState`),
   - Whether its direct/transitive callees have disallowed effects or un-vouched boundaries (`testBodyImpureAccess`).

### 5.2 The Two-Phase Relational Architecture (and Its Impedance Mismatches)

The engine splits analysis into:
- **Phase 1: Intra-Package AST Fact Extraction (`purity.go` + `dynamicStateFactOf` in `dynamicstate.go:288-637`)**
  - Operates on `go/ast` + `go/types` for a single `*packages.Package`.
  - Runs **seven separate intra-package fixed-point or dataflow passes** over the package's AST (`initOnlyReachableHelpers`, `provenSharedPools`, `recordDynamicGlobalUses`, `recordFunctionReferenceRegions`, `recordOpaqueDynamicVars`, `recordEnvCarryingRegistrations`, `receiverReadOnlyMethods`, `receiverRetentionFreeMethods`, `paramLeakFreeFunctions`, `returnEnvFreeFunctions`).
  - Because Phase 1 only has `go/types` signatures (not AST bodies) for imported packages, whenever a function passes a global variable, parameter, or struct field to an imported function/method, Phase 1 **cannot resolve the call**. Instead, it emits **deferred string edges** (`MethodUses`, `InitMethodUses`, `ParamUses`, `InitParamUses`, `FieldParamUses`, `ElemParamUses`, `ParamLeakFreeDeps`, `ParamRetentionFreeDeps`, `ReturnEnvDeps`, `ReturnEnvInsertionDeps`, `ParamInsertionDeps`, `OpaqueDeps`, `EnvCallUses`, `CarrierLinks`, `AttributedUses`, `FuncRefs`) into `dynamicStateFact`.
- **Phase 2: Cross-Package Relational Fixed-Point Solver (`composeDynamicState` + `newDeferralResolution` + `resolveEnvAudit` in `dynamicstate.go:1300-2713`)**
  - Loads `dynamicStateFact` slices for every package in the cone.
  - Parses all string-encoded edges (`\x00`, `\x01`, `\x02`) back into maps and runs **eight more cross-package fixed-point loops**:
    1. `paramLeakFree` descending fixed point (`dynamicstate.go:2484-2499`),
    2. `paramRetentionFree` descending fixed point (`dynamicstate.go:2500-2515`),
    3. `notOpaque` break propagation fixed point (`dynamicstate.go:2553-2567`),
    4. `resolveEnvAudit` joint descending fixed point over `ReturnEnvFree` and `ParamInsertionFree` (`dynamicstate.go:2380-2457`),
    5. `initOnlyFn` ascending fixed point over `FuncRefs` (`dynamicstate.go:1494-1519`),
    6. `initReachFn` ascending fixed point over `FuncRefs` (`dynamicstate.go:1531-1555`),
    7. `carrierLinkGraph` reachability fixed point (`dynamicstate.go:1673-1699`),
    8. Import-cone culprit propagation (`dynamicstate.go:2057-2140`).

**Why this split is Architecturally Costly:**
Every time a local analysis in `purity.go` needs cross-package awareness (e.g., `returnEnvFreeFunctions` needing `ParamInsertionFree`, or `recordDynamicGlobalUses` needing `FieldParamUses` + `FieldParamDefer` + `ReturnFieldParamDefer`), the author had to:
1. Invent a new intra-package solver in `purity.go`,
2. Invent 2–5 new string-encoded edge fields on `dynamicStateFact`,
3. Write custom `\x00`/`\x01`/`\x02` pack/unpack helpers at the bottom of `dynamicstate.go`,
4. Write a parallel cross-package fixed-point solver in `dynamicstate.go` (`resolveEnvAudit`, `newDeferralResolution`, `fieldPopulationProves`) that re-implements the same monotonicity rules over string keys that `purity.go` implemented over `*types.Func` and `*types.Var`!
---

## 6. Cross-Package & Intra-File Duplication / Split-Brain Analysis

### 6.1 Cross-Package Split-Brain: Root (`purity.go` + `dynamicstate.go`) vs. `closure/`

The single largest architectural anomaly in `gofresh` is that the static program analysis is split across two packages (`gofresh` root vs. `closure/`), duplicating the same domain concepts on two different IRs (`go/ast` in root vs. `golang.org/x/tools/go/ssa` in `closure/`):

| Domain Responsibility | Root Package (`purity.go` / `dynamicstate.go` — AST IR) | `closure/` Package (SSA / Types IR) | Duplication & Split-Brain Consequence |
| :--- | :--- | :--- | :--- |
| **Fresh Allocation & Owned-Spine Tracking** | [`returnEnvFreeFunctions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4696-L6158) (`freshObj`, `exprFresh`, `deepWrite`, `linkBacking`, `aliasPairs`) + [`initAliasedLocals`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L1946-L2028) (`freshExpr`) | [`closure/freshpath.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/freshpath.go#L1-L250) (`freshParamAnalysis`, `freshPathValue`, ` freshPathMethodAllowed`, `freshReceiverSummary`) | Both engines track whether a local variable/parameter is backed solely by a fresh composite literal, `new(T)`, `make(...)`, or a constructor returning a fresh allocation, and whether field writes stay on the owned spine vs. mutating deep shared state. One is written on AST statements; the other is written on SSA values. |
| **Struct Field / Slice Element Store Attribution** | [`recordDynamicGlobalUses`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L2043-L3539) (`fieldDefer`, `fieldPoison`, `fieldParamUses`, `elemParamUses`) + [`recordReturnFieldRegistrants`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L6172-L6310) | [`closure/attribution.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/attribution.go#L1-L250) (`structFieldStores`, `enumeratedRootSites`, `isMapDelete`) | Both engines track which function or constructor populates which field/key of a global struct/slice/map and whether any store "poisons" the field with an unprovable value. |
| **Disallowed Effects & Stdlib Audit Tables** | [`impureCallInPackage`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L276-L328), [`stdlibPureExceptions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L152-L176), [`stdlibRootCheckCalls`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L194-L216), [`envReadFunctions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4403-L4416), [`auditedSynchronization`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9046-L9048), [`auditedPooling`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9063-L9065) | [`closure/effects.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/effects.go#L15-L185) (`disallowedStdlibPackages`, `disallowedStdlibFunctions`, `DisallowedTypesCall`, `DisallowedTypesVar`, `IsVouchablePackage`, `IsPurelyFunctionalPackage`) + [`closure/toolchainaudit.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/toolchainaudit.go#L15-L215) (`AuditedToolchainGlobals`, `AuditedToolchainSyncHolders`, `AuditedToolchainPoolHolders`) | Stdlib classification rules are fragmented across 4 files in 2 packages. `purity.go` imports `closure.DisallowedTypesCall`, `closure.AuditedToolchainGlobals`, etc., and then layers its own `stdlibPureExceptions` and `stdlibRootCheckCalls` on top. |
| **Whole-Program Reachability vs. Attribution** | [`recordFunctionReferenceRegions`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9337-L9447) + `initOnlyFn`/`initReachFn` (`dynamicstate.go:1494-1555`) + [`dischargeUnreachableCulprits`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L716-L764) | [`closure/analyzer.go`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/closure/analyzer.go#L1-L250) (`ComputeRootedFunctions`, `ComputeBinaryRootedFunctions`, RTA callgraph) | `purity.go` builds an AST-level function reference graph (`FuncRefs`) to prove `init()`-only reachability, and when that fails, `dynamicstate.go` hands `culpritSites` back to `closure.Hasher.ComputeRootedFunctions` to run SSA/RTA reachability! |
| **Fact Cache Persistence Plumbing** | `dynamicstate.go` (`deriveViewDynamicState`) and `purity.go` (`loadOrScanViewPackages`) | `closure/` (`closure.LoadDynamicStateFacts`, `closure.StoreDynamicStateFacts`, `closure.LoadScanFacts`, `closure.StoreScanFacts`, `closure.LoadViewPackages`, `closure.LoadViewGraph`) | `closure/` owns the cache directory and `go/packages` loader, but because `dynamicStateFact` and `packageScanEntry` are defined in the root package, `closure/` exposes raw `[]byte` load/store hooks specifically for the root package to serialize its private structs. |

**Why did this end up in the root package?**
Historically, `ScanPureDirectives` and `scanTestFunctions` started as a small AST pass in `purity.go` checking `Test*` bodies in the root package, where `Subject` and `Reason` live. When `REQ-closure-shared-dynamic-state` grew to require deep inter-procedural proofs (read-only receivers, parameter leak/retention freedom, constructor environment freedom, `sync.Pool`/`sync.Once`/`sync.Map` proofs, protobuf exemptions, RTA culprit discharge), every new proof pass was bolted onto `purity.go` and `dynamicstate.go` so it could directly construct `Subject` and `Reason` values—rather than moving the entire static analysis engine into `closure/` (or an `internal/analysis` package) and mapping findings to `Subject`/`Reason` at the reporting boundary.

---

### 6.2 Six-Way Intra-File Duplication of Local Alias / Taint / Escape Analysis in `purity.go`

Inside `purity.go` alone, **six separate functions** implement their own bespoke local variable aliasing, backing-object propagation, and taint/escape fixed-point loops over Go ASTs:

1. **`initAliasedLocals`** ([`purity.go:1946-2028`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L1946-L2028)):
   - Tracks `fresh map[*types.Var]bool` and `tainted map[*types.Var]map[*types.Var]bool` inside `init()` via an iterating worklist over `ast.AssignStmt`, `ast.ValueSpec`, and `ast.RangeStmt`.
2. **`environmentFreeFuncLitJudged`** ([`purity.go:3742-4035`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L3742-L4035)):
   - Builds `aliasEdges []aliasEdge` (`dst`, `src *types.Var`) and runs a worklist fixed point (`L3834-3846`) to propagate `envLocal[*types.Var]` across assignments, declarations, and range statements.
3. **`recordEnvCarryingRegistrations` (`computeLocalAliases`)** ([`purity.go:4237-4323`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4237-L4323)):
   - Builds `edges []edge` (`dst`, `src *types.Var`) and runs a worklist fixed point (`L4310-4320`) to propagate `tainted[*types.Var]` from `exprReachesEnv` across `AssignStmt`, `ValueSpec`, and `RangeStmt`.
   - **Note**: `computeLocalAliases` (`L4237-4323`) and the alias loop in `environmentFreeFuncLitJudged` (`L3762-3846`) are nearly line-for-line identical!
4. **`returnEnvFreeFunctions`** ([`purity.go:4696-6158`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L4696-L6158)):
   - Builds `backing map[*types.Var]map[*types.Var]bool`, `freshObj map[*types.Var]bool`, `aliasPairs []varPair`, `heldPairs []varPair`, union-find `aliasFind`, and recursive `judgeLocal`/`free`.
5. **`boundValueJudged`** ([`purity.go:6393-7055`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L6393-L7055)):
   - Builds `tainted map[*types.Var]bool`, `carrierReaching map[*types.Var]bool`, `rooted(ast.Expr)`, `rootIdent(ast.Expr)`, `consume(ast.Expr)`, and runs a taint fixed point (`L6583-6635`) followed by an allowed-use verification walk (`L6639-7052`).
6. **`receiverReadOnlyMethods`** ([`purity.go:8245-8952`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L8245-L8952)):
   - Builds `tainted map[*types.Var]bool`, `rooted(ast.Expr)`, `rootIdent(ast.Expr)`, `consume(ast.Expr)`, `methodValueBind(ast.Expr)`, and runs a taint fixed point (`L8392-8456`) followed by an allowed-use verification walk (`L8461-8790`).

---

### 6.3 Exact Function & Block Clones Inside `purity.go` and `dynamicstate.go`

1. **`boundValueJudged` (`purity.go:6554-6677`) vs. `receiverReadOnlyMethods` (`purity.go:8349-8495`)**:
   - Both functions define identical nested closures `rooted(expr ast.Expr) bool`, `rootIdent(expr ast.Expr) *ast.Ident`, `consume(expr ast.Expr)`, `consumeValueBind(expr ast.Expr)` / `methodValueBind(expr ast.Expr)`, and an identical taint-propagation fixed-point loop over `ast.AssignStmt`, `ast.ValueSpec`, and `ast.RangeStmt`.
   - `receiverReadOnlyMethods` is literally a specialized clone of `boundValueJudged` with `roots = {recvVar}` plus `onceFill` admission (`L8528-8578`) and closed-interface field dispatch (`L8668-8696`).
2. **`plainCalleeFunc` (`purity.go:733-755`) vs. `plainNamedCalleeFn` (`purity.go:4615-4637`)**:
   - Both unwrap `ast.IndexExpr` and `ast.IndexListExpr`, resolve `*ast.Ident` or `*ast.SelectorExpr` via `p.TypesInfo.Uses`, check `*types.Func`, and reject `sig.Recv() != nil`.
   - **Subtle inconsistency bug hazard**: `plainCalleeFunc` (`L751-753`) normalizes generic instantiations via `if orig := fn.Origin(); orig != nil { fn = orig }`, whereas `plainNamedCalleeFn` (`L4635`) omits `fn.Origin()`! Callers of `plainNamedCalleeFn` instead call `fn.Origin()` manually at some call sites (`L5045`, `L5327`, `L5819`) and forget at others (`L4542`, `L6213`).
3. **Method Receiver Type Unwrapping (3 copies)**:
   - [`methodFactKey`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9023-L9040) (`purity.go:9023-9040`),
   - [`recvTypeNameOf`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L9297-L9319) (`purity.go:9297-9319`), and
   - [`(*viewDynamicState).methodDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/dynamicstate.go#L1045-L1071) (`dynamicstate.go:1045-1071`)
   all repeat the exact same `types.Unalias(recv.Type())` -> unwrap `*types.Pointer` -> `types.Unalias` -> `*types.Named` extraction.
4. **Intra-Package vs. Cross-Package Fixed-Point Duplication**:
   - `paramLeakFreeFunctions` (`purity.go:7225-7277`) runs two descending fixed-point loops (`proven` over `deps`, `retention` over `retentionDeps`). Then `newDeferralResolution` (`dynamicstate.go:2484-2515`) runs the **exact same two descending fixed-point loops** over `ParamLeakFree`/`ParamLeakFreeDeps` and `ParamRetentionFree`/`ParamRetentionFreeDeps`.
   - `recordOpaqueDynamicVars` (`purity.go:9560-9576`) runs a descending fixed-point loop over `opaque` and `deps`. Then `newDeferralResolution` (`dynamicstate.go:2553-2567`) runs the **exact same fixed-point loop** over `notOpaque` and `OpaqueDeps`.
   - `returnEnvFreeFunctions` (`purity.go:5929-6079`) resolves intra-package `pendingInsertionUses` and `stmtCallDeps`. Then `resolveEnvAudit` (`dynamicstate.go:2380-2457`) runs a cross-package joint descending fixed-point loop over `ReturnEnvFree` and `ParamInsertionFree`.

---

## 7. Catalogue of Ad-Hoc Special Cases, Syntactic Pattern-Matching Patches, and Fragilities

Because `purity.go` operates on raw syntax (`go/ast`) rather than canonical SSA instructions, real-world Go idioms in the standard library and popular modules forced a series of hyper-specific syntactic pattern-matching patches:

1. **`bracketedSeamNodes` (`purity.go:633-726`, `L884-1091`, `L2067-2146`) — 1,054 Lines of Syntactic Save/Restore Matching**:
   - Matches 5 specific AST shapes of save/restore ("seam") patterns:
     - `saved := pkgVar; defer func() { pkgVar = saved }()`
     - `defer func(saved T) { pkgVar = saved }(pkgVar)`
     - `t.Cleanup(func() { pkgVar = saved })`
     - Inline straight-line `saved := pkgVar; ...; pkgVar = saved` (`L977-1091`)
     - Helper returning a restore closure `restore := swapHelper(&pkgVar, val); defer restore()` (`helperReturnsRestoreFunc`, `L1099-1452`)
   - **Fragility**: Relies on statement list indexing (`list[i]`, `list[j]`), structural AST comparison (`sameTargetExpr`, `L1647-1666`), and absence of `return`/`BranchStmt`/`GoStmt` between `i` and `j`.
2. **`onceFieldCount(recvType) == 1` (`purity.go:7444-7459`, `L8533`)**:
   - `receiverReadOnlyMethods` admits lazy initialization via `sync.Once.Do` (`onceFill`) **only if** the receiver struct has *at most one* `sync.Once` field (`onceFieldCount(recv.Type()) == 1`). A struct with two independent lazy-initialized caches (two `sync.Once` fields) fails this check arbitrarily.
3. **`provenSharedPools` (`purity.go:9100-9319`)**:
   - Hardcodes recognition of `sync.Pool` variables where `Get()` / `Put()` are called only within the declaring package and `Put(x)` is immediately preceded in the same basic-block statement list by `x.Reset()` (`provenPoolCallConforms`, `L9274-9293`) or a slice-reslicing reset `s = s[:0]`.
4. **Hardcoded Module Versions in `composeDynamicState` (`dynamicstate.go:1838-1851`)**:
   - While `auditedSourceListing` (`dynamicstate.go:907-916`) uses `internal/auditset.VersionListing`, `composeDynamicState` (`L1838-1851`) hardcodes raw string version comparisons:
     - `m.Path == "google.golang.org/protobuf" && auditset.CompareSemver(m.Version, "v1.36.11") <= 0`
     - `m.Path == "google.golang.org/grpc" && auditset.CompareSemver(m.Version, "v1.82.1") <= 0`
   - Any upgrade to `google.golang.org/protobuf` `v1.36.12+` or `google.golang.org/grpc` `v1.82.2+` silently stops discharging `GeneratedProtoVars` / `GeneratedGrpcVars` until `dynamicstate.go:1841` is edited and `gofresh` is rebuilt!
5. **`ScanPureDirectives` (`purity.go:472-502`) Unnecessary Heavy Computation**:
   - `ScanPureDirectives` is a public function documented as scanning packages for `//gofresh:pure` directives. Yet at `purity.go:484`, it unconditionally calls `deriveViewDynamicState(ctx, hasher, "", cfg.BuildFlags, viewLoad, targetPaths, nil, false, false)`—triggering full transitive cone fact derivation, disk cache reads/writes, and cross-package fixed-point composition—only to discard `dynState` when `funcHasPureDirective(decl)` is true! (And `scanDirectiveFile` only adds functions where `funcHasPureDirective(decl)` is true anyway!)
6. **Stringly-Typed Byte Delimiter Framing (`\x00`, `\x01`, `\x02`, `"lit:"`)**:
   - `dynamicStateFact` serializes relational tuples as strings using control characters (`\x00`, `\x01`, `\x02`) inside JSON string arrays. This requires 19 custom string-splitting helpers (`dynamicstate.go:2719-2896`) and makes the schema opaque, brittle, and allocation-heavy.
7. **Unbounded Process-Global `processFactCache` (`dynamicstate.go:643`)**:
   - `var processFactCache sync.Map` is a package-level singleton rather than a field on `closure.Hasher` or an analysis session struct.

---

## 8. Concrete Decomposition & Unification Architecture

To turn this 12,788-line monolith into a clean, maintainable, first-principles architecture:

### Step 1: Fix `ScanPureDirectives` Immediately (Zero-Risk Fast Path)
- [`ScanPureDirectives`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L472-L502) and [`scanDirectiveFile`](file:///home/nikolas/repos/github.com/greatliontech/gofresh/purity.go#L504-L535) only return entries where `funcHasPureDirective(decl)` is true, and when `hasDirective` is true, `impureExprInFile` is only called if `!hasDirective` (`L522`).
- Therefore, `deriveViewDynamicState` in `ScanPureDirectives` (`L484`) is 100% dead work! Removing the `deriveViewDynamicState` call from `ScanPureDirectives` eliminates an entire dependency-cone load and relational solve from directive scanning.

### Step 2: Consolidate the 6 Local AST Alias/Taint Engines in `purity.go` into One Shared Intra-Procedural Dataflow Helper
- Extract a single unified intra-procedural AST dataflow representation (`localFlowGraph` over `*types.Var`) that computes:
  - Variable-to-variable alias/value-flow edges (`AssignStmt`, `ValueSpec`, `RangeStmt`, composite/slice/map element flow),
  - Fresh allocation roots (`freshObj`),
  - Root-variable taint reachability (`rooted`, `rootIdent`, `tainted`), and
  - Allowed-use consumption (`consume`, `methodValueBind`).
- Replace the 6 duplicated engines (`initAliasedLocals`, `environmentFreeFuncLitJudged`, `computeLocalAliases`, `returnEnvFreeFunctions`'s alias pass, `boundValueJudged`, and `receiverReadOnlyMethods`) with calls to this single parameterized helper.
- Unify `plainCalleeFunc` and `plainNamedCalleeFn` (always normalizing `fn.Origin()`), and unify `methodFactKey` / `recvTypeNameOf` / `methodDirectives`.

### Step 3: Replace Stringly-Typed `\x00`/`\x01`/`\x02` Edge Slices in `dynamicStateFact` with Structured Types
- Replace the 19 `\x00`/`\x01`/`\x02` string-packing helpers (`dynamicstate.go:2719-2896`) with typed Go structs (`MethodUseFact`, `ParamUseFact`, `FieldParamUseFact`, `DepEdgeFact`, `AttributedUseFact`, `FuncRefFact`) on `dynamicStateFact`.
- Eliminate the duplicated intra-package vs. cross-package fixed-point solvers: emit local facts + dependency edges once during `dynamicStateFactOf`, and solve the fixed points once in `newDeferralResolution` / `resolveEnvAudit` (or use a single generic monotone fixed-point solver `solveDescendingFixedPoint[K comparable](proven map[K]bool, deps map[K][]K)`).

### Step 4: Move the Static Analysis Engine Out of the Root Package into Focused Subpackages
- Move `dynamicstate.go` and the 15 subsystems of `purity.go` out of the root `gofresh` package into `closure/` (or `internal/dynstate/`):
  - **`internal/dynstate/fact.go`**: Typed `Fact` schema, `FactOf(p *packages.Package)`, and directive/protobuf header scanners.
  - **`internal/dynstate/localflow.go`**: Unified AST local alias, fresh-allocation, and taint/consumption analyzer (serving read-only receivers, retention/leak-free params, env-free returns, and ` opaque` vars).
  - **`internal/dynstate/seam.go`**: Bracketed save/restore seam and `init()`-only mutation discharge.
  - **`internal/dynstate/syncproof.go`**: `sync.Once`, `sync.Map` (`dataMemoVars`), and `sync.Pool` (`provenSharedPools`) discharge analyzers.
  - **`internal/dynstate/compose.go`**: Cross-package fixed-point solver (`composeDynamicState`, `newDeferralResolution`, `resolveEnvAudit`) and RTA culprit discharge integration.
  - **`internal/testscan/scan.go`**: Test-boundary scanner (`scanPackageTests`, `testBodyMutatesPackageState`, `testBodyImpureAccess`, `explain.go` hooks).
- Keep the root `gofresh` package strictly as the thin domain/CLI coordination layer (`Subject`, `Reason`, `Verify`, `Plan`, `Status`, `ScanPureDirectives`).
