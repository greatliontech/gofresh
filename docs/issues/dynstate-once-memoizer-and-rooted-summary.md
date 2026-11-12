# `sync.Once` Memoizer LHS Disqualification, `ComputeRootedFunctions` Missing `progSummary` & Redundant `dynstate` Recomputation

- **Status:** Open
- **Governing contract:** [`docs/specs/closure.md`](../specs/closure.md) (`REQ-closure-shared-dynamic-state`, `REQ-closure-dynamic-state-memo`, `REQ-closure-scan-memo`), [`docs/specs/guards.md`](../specs/guards.md), [`docs/specs/explain.md`](../specs/explain.md) (`REQ-explain-chain`)
- **Lands:** Chunk 2 in [`docs/plans/plan.md`](../plans/plan.md)

## Problem

1. **`onceFill` Omits `consume(lhs)` on `sync.Once` Struct-Pointer Memoizers (`internal/dynstate/summary_leakfree.go`)**
   - A standard `sync.Once` struct memoizer method:
     ```go
     func (e *Embedded) Document() (*Document, error) {
         e.once.Do(func() { e.doc, e.err = Parse(e.src) })
         return e.doc, e.err
     }
     ```
     is recognized at the statement level by `onceFill[stmt] = true` ([`internal/dynstate/summary_leakfree.go`](../../internal/dynstate/summary_leakfree.go) lines 1131–1142).
   - At `*ast.AssignStmt` (`lines 1243–1245`), when `recvRooted(lhs)` and `onceFill[n]` hold, the check avoids setting `disqualified[key] = true` on the assignment statement itself, **but omits `consume(lhs)`**.
   - When `ast.Inspect` subsequently visits the child `*ast.SelectorExpr` nodes `e.doc` (`*Document`) and `e.err` (`error`) on the assignment LHS (`lines 1450–1460`), `!allowed[syntaxutil.RootIdent(n.X)]` holds and `refconfine.CallResultHandsOut(p.TypesInfo.TypeOf(n))` returns `true` for pointer/interface types, setting `disqualified["Embedded.Document"] = true` (alongside checking read-only receiver byte-slice inputs such as `e.src` passed to `Parse(e.src)` inside `once.Do`).
   - Disqualifying `(*Embedded).Document` marks package-level `embeddedGuidance` variables as mutated (`SharedDynamicStateCause`), poisoning `996` out of `1,069` test subjects in `gomutant` and forcing `SingleSubjectExecution` fallback across the entire module.

2. **`ComputeRootedFunctions` Never Initializes `progSummary` and Resets `getProvFP()` on Every Subject**
   - In `rootedGroup` ([`internal/closure/rooted.go`](../../internal/closure/rooted.go) line 139), `attributedReachableSets` runs on `prog` without calling `getSummary(ctx, h.SelectionAudited(), h.source.pureDelegates, prog)`.
   - Inside `provenanceBFSWithCandidates` ([`internal/closure/attribution_provenance.go`](../../internal/closure/attribution_provenance.go) lines 1860–1885), `lookupSummaryForProg(prog, audited)` therefore returns `nil`, leaving `fp.summary = nil`, `fp.inProgramSites = false`, `fp.programSites = nil`, and `fp.programValueRef = nil`.
   - Furthermore, `getProvFP()` is local to `provenanceBFSWithCandidates` and calls `fp.resetDynamicMemos()` on every invocation (`3,207` resets across `1,069` subjects, taking `8m05s`), even though `getProvFP()` operates with `fp.subjectRoot == nil && fp.enumRoot == nil` and is completely subject-independent.

3. **Execution-Mode Fact-Cache Fragmentation, Unchanged Mutable-Snapshot Recomputation & `dischargeUnreachableCulprits` Cost**
   - `(s AnalysisScope) Facts()` ([`internal/closure/scope.go`](../../internal/closure/scope.go) lines 100–112) appends `|single-subject-execution` and `|package-process-execution`, and `dynstate.FactOf` gates `SingleSubjectSites` population on `singleSubject`, fragmenting the `dynamicstate` disk cache across `GeneralExecution`, `PackageExecution`, and `SingleSubjectExecution` even though per-package AST/type `dynstate.Fact` derivation is independent of `PackageProcess` (`PackageProcess` only governs `dynstate.Compose`) and can unconditionally populate `SingleSubjectSites`.
   - On `MutableLocalPackage` targets, `observeSnapshot` calls `observeView` twice (`first` and `second`) and skips memo reuse in `scanViewSubjectsWithMemo` ([`scan.go`](../../scan.go)) even when the package's source file digests are identical across both passes, causing `6x` `dynstate.FactOf` recomputations (`1m45s` on `gofresh/internal/closure`, `1m26s` on `stipulator/internal/backends/golang`).
   - `dischargeUnreachableCulprits` ([`scan.go`](../../scan.go) lines 463–506) runs RTA reachability across every symbol with candidate culprits in `scan.known` (`616` symbols in `pew/cmd/pew`, `1,069` in `gomutant`).

## Soundness Constraints & Resolution Scope

1. **`onceFill` Confinement (`paramLeakFree` & `!smuggles`)**:
   - In `receiverReadOnlyMethods` ([`internal/dynstate/summary_leakfree.go`](../../internal/dynstate/summary_leakfree.go) lines 1235–1460), call `consume(lhs)` for `onceFill`-admitted receiver field assignments **only when `!carrierReach(rhs)` (`!smuggles`) holds** so `once.Do` cannot store a package-scope mutable dynamic carrier into receiver state and hand it out via the getter.
   - For receiver fields (such as `e.src []byte`) passed as arguments inside `once.Do`, require `dynstate`'s **`paramLeakFree`** (`boundValueLeakFreeJudged` with `returns == nil` — mutation-free AND retention-free parameter confinement, wired across both local and imported `dynstate.Fact`s in the fixed point, **not** closure `EffectFree` purity which allows in-place slice mutation or subslice retention in the returned struct), and bump `DynamicStateStrategy` ([`session.go`](../../session.go) line 154).
2. **`ComputeRootedFunctions` `progSummary` & Shared `provFP`**:
   - Initialize `getSummary` before `attributedReachableSets` in `ComputeRootedFunctions` ([`internal/closure/rooted.go`](../../internal/closure/rooted.go)) and hoist/share subject-independent `provFP` memos across the batch.
3. **`(AnalysisScope).Facts()` vs. `(AnalysisScope).Scan()` Separation & `scanfacts` Integrity**:
   - Update `REQ-closure-dynamic-state-memo` in [`docs/specs/closure.md`](../specs/closure.md) lines 2221–2234 (which currently states that persistent `dynamicstate` fact memo keys carry execution attestations), always populate `SingleSubjectSites` in `dynstate.FactOf`, and remove `|single-subject-execution` and `|package-process-execution` from `(s AnalysisScope) Facts()` ([`internal/closure/scope.go`](../../internal/closure/scope.go) lines 100–112), **while explicitly moving `|single-subject-execution` and `|package-process-execution` onto `(s AnalysisScope) Scan()` (`lines 117–125`)** so execution-mode-dependent `scanfacts` entries (`dynstate.Compose` and single-subject / package-process culprit discharges) never cross into `GeneralExecution` (`REQ-closure-scan-memo`).
   - Key in-session `MutableLocalPackage` `dynstate.Fact` reuse by exact package source-file digests so unchanged `first` and `second` passes in `observeSnapshot` derive `FactOf` once.
   - Preserve whole-package `scanfacts` completeness in `scanViewSubjectsWithMemo` ([`scan.go`](../../scan.go) lines 190–193): never persist partially discharged sibling symbols into whole-package `scanfacts` (any subject-subset narrowing of culprit discharge must only apply on non-persisted paths or track per-subject discharge explicitly).
