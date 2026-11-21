# Chunk 5 Working Notes: Consolidate `internal/dynstate` Confinement, Freshness, Summary & Discharge Passes (`<= ~1,050` LOC Everywhere)

## Architecture & Consolidation Plan

1. **Unified Value-Purity & Fresh-Allocation Classifier (`value_classify.go`, `flow_fresh.go`):**
   - Extend `valuePurityPolicy` in `value_classify.go` (`allowSyncNoCopy`, `typeGuard`, `convertGuard`, `elemPred`, `ignoreSizeAndIndexArgs`, `allowNilPlaceAppendBase`, `skipAppendElemCheck`, `forbidEllipsisAppend`) so `isFreshLocalOnceValue` and `computeOutflowFreshOwnedLocals` (`flow_fresh.go`) route directly through `checkPureOrFreshValue` without a duplicate `evalFreshAllocValue` `switch v.Kind` walker, preserving `make([]T, n)` variable-capacity / slice-index semantics and sync-noCopy handling.

2. **Declarative `confinementEngine` Modes & `summary_leakfree.go` Decomposition (`<= ~900` LOC per file):**
   - Introduce explicit `confinementMode` (`confinementModeBoundValue`, `confinementModeReceiver`, `confinementModeEnclosingRoots`, `confinementModeOnceMemoRecv`) on `confinementEngine`, collapsing `enclosingConfinesRoots` (formerly `summary_env_stores.go`) and `verifyOnceMemoRecvUsesInBody` (formerly `discharges_once_memo_recv.go`) onto `confinementEngine` methods while preserving every mode's exact alias, single-definition, origin, sibling-method, and deferral invariants.
   - Decompose `summary_leakfree.go` (`3,796` LOC) into cohesive files:
     - `confinement_engine.go`: `confinementMode`, `confinementEngine`, entrypoints (`confineFlowRoots`, `boundValue*`), root/place/read/store helpers, shared call/method deferral helpers.
     - `confinement_taint.go`: `flowVarTaintConfig`, `propagateFlowVarTaint`, `propagateTaint`, `propagateExternalReaching`.
     - `confinement_ops.go`: `checkBody`, `checkOp`, `checkReturnResult`, `checkAssignLHS`, `checkAssignOp`, `checkValue`, `checkCall`, `checkCallArgs`.
     - `confinement_enclosing.go`: `rootOriginPolicy`, `enclosingConfinementConfig`, `enclosingConfinesRoots` (`confinementModeEnclosingRoots`).
     - `confinement_once_memo.go`: `onceMemoRecvConfig`, `verifyOnceMemoRecvUsesInBody` (`confinementModeOnceMemoRecv`).
     - `confinement_pkg_solve.go`: `packageConfinementSummary`, `receiverRetentionFreeMethods`, `closedInterfaceFields`, `solvePackageConfinement` (`syntaxutil.SolveBipartiteLFP` + `PruneUnsatisfiedDeps`).
     - `confinement_once_fill.go`: `onceDoAdmission`, `collectPackageOnceFieldUsage`, `onceFillValueSmuggles`, `computeOnceDoFieldAdmissions`, `findAdmittedReceiverOnceDo`.

3. **Explicit Analyzer Structs & Cohesive File Splits (`<= ~950` LOC everywhere):**
   - `summary_env_stores.go` (`2,674` LOC) -> `summary_env_settled.go` (`settledGlobalMap`, `isSettledReachArgValue`, `settledPackageDataGlobals`, `closureExtractsNoCarrierFromRoots`), `summary_env_registrants.go` (`fieldRegMark`, `classify*Registrant*`), and `summary_env_stores.go` (`envRegConfig` + `envRegScanner` struct replacing the 22-arg `recordEnvCarryingRegistrations` closure soup).
   - `summary_env_returns.go` (`2,445` LOC) -> `summary_env_returns.go` (`closureOutflowSummaries`, `outflowEvalCtx`, `outflowAnalyzer` struct, `analyzeClosureOutflowSummaries`, `recordReturnFieldRegistrants`), `summary_env_returns_collect.go` (body bind/store/hazard collection & union-find setup), and `summary_env_returns_eval.go` (`evalFree`, `checkPlainCallReachArgSeen`, `computeResolvedUses`, parameter-insertion & return evaluation).
   - `summary_uses.go` (`1,975` LOC) -> `summary_uses.go` (`globalUseConfig`, `useSinkScope` eliminating parameter-variable pointer swapping, `globalUseScanner` struct, body/op/call walking), and `summary_uses_returns.go` (attributed declaration scoped passes + transitive unexported returner call-site confinement solver).
   - `carrier_aliases.go` (`874` LOC) -> `carrier_aliases_values.go` (value/link extraction & nested walkers) + `carrier_aliases.go` (`carrierAliasConfig` + explicit `carrierAliasSolver` struct).
   - `cone_flowir.go` (`957` LOC) -> `cone_flowir.go` + `cone_flowir_stdlib.go` (retiring duplicate `isTrueStdlibInPkg` wrapper).
   - `discharges_mapping.go` (`1,005` LOC) -> `discharges_mapping.go` + `discharges_mapping_body.go`.
   - `discharges_once_memo_cone.go` (`1,011` LOC) -> `discharges_once_memo_ctor.go` + `discharges_once_memo_cone.go` (retiring duplicate `isUniverseErrorType` in favor of `syntaxutil.IsErrorType`).

## Execution & Verification Checklist
- [ ] Unify `evalFreshAllocValue` into `checkPureOrFreshValue` (`value_classify.go`, `flow_fresh.go`).
- [ ] Decompose `summary_leakfree.go` into `confinement_*.go` and collapse `enclosingConfinesRoots` and `verifyOnceMemoRecvUsesInBody` onto declarative modes of `confinementEngine`.
- [ ] Refactor `summary_env_stores.go` (`envRegScanner`), `summary_env_returns.go` (`outflowAnalyzer`), and `summary_uses.go` (`globalUseScanner` + `useSinkScope`) into cohesive files (`<= ~1,050` LOC) and update `facts_derive.go`.
- [ ] Split `carrier_aliases.go` (`carrierAliasSolver`), `cone_flowir.go`, `discharges_mapping.go`, and `discharges_once_memo_cone.go`, retiring duplicate stdlib/error-type wrappers.
- [ ] Verify 100% of `internal/dynstate` production files are `<= ~1,050` LOC, run `go build`, `go vet`, dual-toolchain (`godst` + vanilla Go `1.27.4`) `-race -failfast`, targeted `gomutant ephemeral` probes (`0` survivors), static `stipulator`, converge independent adversarial review to `ZERO FINDINGS`, delete `docs/notes/consolidate-dynstate-passes.md`, and commit Chunk 5.
