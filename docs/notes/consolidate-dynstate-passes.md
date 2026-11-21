# Chunk 5 Working Notes: Consolidate `internal/dynstate` Confinement, Freshness, Summary & Discharge Passes (`<= ~1,050` LOC Everywhere)

## Architecture & Completed Consolidations

1. **Unified Value-Purity & Fresh-Allocation Classifier (`value_classify.go`, `flow_fresh.go`):**
   - Extended `valuePurityPolicy` in `value_classify.go` (`allowSyncNoCopy`, `forbidUnsafeSizeBuiltins`, `ignoreSizeAndIndexArgs`, `preserveAppendBasePlace`, `skipAppendElemCheck`, `allocTypeOK`, `convertOK`, `elemOK`) and eliminated `evalFreshAllocValue` / `freshAllocEvalPolicy` from `flow_fresh.go`, routing both `isFreshLocalOnceValue` and `computeOutflowFreshOwnedLocals` directly through `checkPureOrFreshValue` while retiring vestigial `forbidConstOrNilShort`, `forbidScalarLit`, `allowNilAppendBase`, and `allowCarryingTypes` flags uncovered via `gomutant ephemeral` probes.

2. **Declarative `confinementEngine` Modes & `summary_leakfree.go` Decomposition (`<= 901` LOC max):**
   - Retired `internal/dynstate/summary_leakfree.go` (`3,796` LOC) into cohesive files (`confinement_engine.go`, `confinement_taint.go`, `confinement_ops.go`, `confinement_pkg_solve.go`, `confinement_once_fill.go`) plus two unified declarative mode files:
     - `confinement_enclosing.go` (`confinementModeEnclosingRoots`): collapsed `enclosingConfinesRoots` onto `*confinementEngine`.
     - `confinement_once_memo.go` (`confinementModeOnceMemoRecv`): collapsed `verifyOnceMemoRecvUsesInBody` onto `*confinementEngine`.
   - **Discovered & Fixed Soundness/Ordering Defect in `confinementModeOnceMemoRecv`:**
     - `runOnceMemoRecv` previously collected single-def local receiver aliases (`recvAliases`) and `inputFieldLocals` via `ForEachSyncOp` only, then ran `if isRecvVar(dst.Obj) { return false }` in `checkOps` *before* `if dst.IsBareVar() && (recvAliases[dst.Obj] || inputFieldLocals[dst.Obj]) { continue }` (making single-def local receiver alias skips unreachable), AND `CallIIFE` / `ValMakeClosure` recursed with `recvVar` alone rather than `st.recvAliases`.
     - Fixed by counting definitions via `flowir.VisitAllOps`, recording exact `allowedLocalBindOps`, checking `st.allowedLocalBindOps[op]` before rejecting `dst.Obj`, and propagating `st.recvAliases` through `verifyOnceMemoRecvUsesWithAliases` into nested `CallIIFE` and `ValMakeClosure` scopes. Added permanent causal `detail` strings on `once_memo_type` rejection trace events in `discharges_once_memo.go` and verified both positive (`alias := ix; _ = alias.prefix`) and negative (`sibling_iife_recv_alias_bare_escape` -> `recv_confinement_rejected:Sum`) controls via `trace.Recorder`.

3. **Explicit Analyzer Structs & Cohesive File Splits (`100% <= 991` LOC across `internal/dynstate/...`):**
   - `summary_env_stores.go` (`2,674` LOC) -> `summary_env_settled.go` (`898` LOC), `summary_env_registrants.go` (`538` LOC), and `summary_env_stores.go` (`826` LOC, `envRegScanner` struct replacing 22-parameter `recordEnvCarryingRegistrations`).
   - `summary_env_returns.go` (`2,445` LOC) -> `summary_env_returns.go` (`448` LOC), `summary_env_returns_collect.go` (`871` LOC), `summary_env_returns_tables.go` (`531` LOC), and `summary_env_returns_eval.go` (`688` LOC) on explicit `outflowAnalyzer` struct; removed dead `(*outflowEvalCtx).resetMemo`.
   - `summary_uses.go` (`1,975` LOC) -> `summary_uses.go` (`797` LOC), `summary_uses_walk.go` (`657` LOC, `globalBodyWalk`), and `summary_uses_returns.go` (`584` LOC) on explicit `globalUseScanner` + `useSinkScope` (eliminating formal-parameter variable pointer swapping and updating `facts_derive.go`).
   - `carrier_aliases.go` (`874` LOC) -> `carrier_aliases_values.go` (`438` LOC) + `carrier_aliases.go` (`451` LOC, explicit `carrierAliasSolver` struct).
   - `cone_flowir.go` (`957` LOC) -> `cone_flowir.go` (`570` LOC) + `cone_flowir_stdlib.go` (`385` LOC), retiring duplicate `isTrueStdlibInPkg` wrapper in favor of `syntaxutil.IsTrueStdlibInPkg`.
   - `discharges_mapping.go` (`1,005` LOC) -> `discharges_mapping.go` (`469` LOC) + `discharges_mapping_body.go` (`542` LOC), retiring dead `verifyMappingVar` wrapper; also retired dead `verifyMemoVar` wrapper from `discharges_memo.go`.
   - `discharges_once_memo_cone.go` (`1,011` LOC) -> `discharges_once_memo_ctor.go` (`420` LOC) + `discharges_once_memo_cone.go` (`605` LOC); retired duplicate `isUniverseErrorType` from `discharges_once_memo_recv.go` in favor of `syntaxutil.IsErrorType` across 40 call sites.

4. **Mutation Probe Verification (`11/11` Killed, `0` Survivors):**
   - `1_allowNonMutableReach_sigLeafGate` (`value_classify.go`) -> killed by `SmuggledLocalClosureHook` (`TestUnifiedValueClassifierStoresAndReturnsEdgeCases`).
   - `2_preserveAppendBasePlace` (`value_classify.go`) -> killed by `SmuggleAppendSpareCap` (`TestUnifiedValueClassifierStoresAndReturnsEdgeCases`).
   - `3_ignoreSizeAndIndexArgs_AllocMake` (`value_classify.go`) -> killed by `BuildSizedFuncSlice` (`TestUnifiedValueClassifierStoresAndReturnsEdgeCases`).
   - `4_onceMemo_CallIIFE_recvAliases` (`confinement_once_memo.go`) -> killed by `sibling_iife_recv_alias_bare_escape` (`TestUnifiedFlowIRMemoizersAndMappingRegions`).
   - `5_enclosingRoots_aliasClosure` (`confinement_enclosing.go`) -> killed by `AliasedCleanSliceHook` (`TestUnifiedValueClassifierStoresAndReturnsEdgeCases`).
   - `6_outflowAnalyzer_insModeParamGuard` (`summary_env_returns_eval.go`) -> killed by `InsertReboundFnParam` (`TestUnifiedValueClassifierStoresAndReturnsEdgeCases`).
   - `7_globalUseScanner_useSinkScopeFlush` (`summary_uses_returns.go`) -> killed by `TestPropertyAttributedEncloserReachabilityAndForeclosureTheorem`.
   - `8_carrierAliasSolver_propagateMem` (`carrier_aliases.go`) -> killed by `TestPropertyLocalCarrierAliasAndSiblingFieldStateDriftOracle`.
   - `9_pkgConf_resolveWants` (`confinement_pkg_solve.go`) -> killed by `UnconfinedParamHook` (`TestUnifiedValueClassifierStoresAndReturnsEdgeCases`).
   - `10_onceMemo_ValInvalid_failClosed` (`confinement_once_memo.go`) -> killed by `TestUnifiedValueClassifierStoresAndReturnsEdgeCases`.
   - `11_skipContainerElems_AllocCompositeLit` (`value_classify.go`) -> killed by `BuildFreshPtrHolder` (`TestUnifiedValueClassifierStoresAndReturnsEdgeCases`).

## Round 1 Adversarial Review Dispositions

- **Finding 1 (`[LOW]` Behavioral — Introduced):** Confirmed & Fixed. Removed `forbidUnsafeSizeBuiltins` from `valuePurityPolicy` (`value_classify.go`) and `flow_fresh.go` so compile-time `unsafe.Sizeof`/`Alignof`/`Offsetof` queries evaluate uniformly across direct and wrapped constant expressions; added `onceLayoutMemo.Get` and `BuildLayoutFuncSlice` regression checks in `flowir_unification_test.go`.
- **Finding 2 (`[LOW]` Behavioral / Fail-Closed Guard — Adjacent):** Confirmed & Fixed. Hardened `checkOnceMemoValueTree` (`confinement_once_memo.go`) to fail closed on `flowir.ValInvalid`, nil-body `ValMakeClosure`, and nil-body `CallIIFE`; added direct unit assertions and mutation probe `10_onceMemo_ValInvalid_failClosed`.
- **Finding 3 (`[LOW]` Consolidation — Introduced):** Confirmed & Fixed. Replaced `skipAppendElemCheck` with `skipContainerElems` across `AllocCompositeLit` and `append`, decoupled `ignoreSizeAndIndexArgs` strictly to `AllocMake` size/cap arguments and `AllocCompositeLit` index keys, unified `AllocCompositeLit`'s element loop, and kept `v.ElemType == nil` unconditionally fail-closed; added probe `11_skipContainerElems_AllocCompositeLit`.
- **Finding 4 (`[LOW]` Consolidation — Introduced):** Confirmed & Fixed. Unified parameter/method confinement want resolution into `(*packageConfinementSummary).resolveWants` (`confinement_pkg_solve.go`), and unified `enclReachOrStr`/`outflowReachOrAddrOrStr` and `elemHandsOutReach`/`outflowElemReach` into `typeHandsOutReachOrAddr` and `containerElemHandsOutReach` (`value_classify.go`).
- **Finding 5 (`[LOW]` Consolidation — Introduced):** Confirmed & Fixed. Unified `placeMapKeysSmuggle` and `placeMapKeysSmuggleInOnceFill` in `confinement_engine.go` into a single `(*confinementEngine).placeMapKeysSmuggle(pl, allowEmptyCarrier, reachKeySmuggles)`.
- **Finding 6 (`[LOW]` Consolidation / Redundant State — Introduced):** Confirmed & Fixed. Removed duplicate `judgedRangeVars` from `globalBodyWalk` (`summary_uses_walk.go`), using `w.s.activeJudgedRangeVars` as the single source of truth.
- **Finding 7 (`[NIT]` Vestigial Plumbing — Adjacent):** Confirmed & Fixed. Removed unused `needsErrorProof` return value and parameter across `discharges_once_memo_ctor.go`, `discharges_once_memo.go`, and `discharges_once_memo_cone.go`.
- **Finding 8 (`[NIT]` Consolidation — Adjacent):** Confirmed & Fixed. Expressed `mapperBodyReassignsOrAddrsRecv`, `countFieldMentionsInBody`, and `pkgHasStructDerefWriteFlowIR` in `discharges_mapping_body.go` via `flowir.VisitAllOps`.

## Execution & Verification Checklist
- [x] Unify `evalFreshAllocValue` into `checkPureOrFreshValue` (`value_classify.go`, `flow_fresh.go`).
- [x] Decompose `summary_leakfree.go` into `confinement_*.go` and collapse `enclosingConfinesRoots` and `verifyOnceMemoRecvUsesInBody` onto declarative modes of `confinementEngine`.
- [x] Refactor `summary_env_stores.go` (`envRegScanner`), `summary_env_returns.go` (`outflowAnalyzer`), and `summary_uses.go` (`globalUseScanner` + `useSinkScope`) into cohesive files (`<= ~1,050` LOC) and update `facts_derive.go`.
- [x] Split `carrier_aliases.go` (`carrierAliasSolver`), `cone_flowir.go`, `discharges_mapping.go`, and `discharges_once_memo_cone.go`, retiring duplicate stdlib/error-type/dead wrappers (`0` dead candidates across all 5 `dynstate` packages).
- [x] Verify 9/9 `gomutant ephemeral` probes (`0` survivors).
- [ ] Re-pin/verify static `stipulator` bindings, run dual-toolchain `dynstate` suite, converge independent adversarial review to `ZERO FINDINGS`, delete `docs/notes/consolidate-dynstate-passes.md`, and commit Chunk 5.
