# `sync.Once` Memoizer LHS Confinement, `OnceMemoType` Discharge (`gomutant.embeddedGuidance`) & Cross-Package `EnvSummary` Edges

- **Status:** Open
- **Governing contract:** [`docs/specs/closure.md`](../specs/closure.md) (`REQ-closure-shared-dynamic-state`, `REQ-closure-shared-dynamic-state-receiver-proof`, `REQ-closure-shared-dynamic-state-leak-free`, `REQ-closure-shared-dynamic-state-parameter-facts`, `REQ-closure-shared-dynamic-state-registration-audit`, `REQ-closure-shared-dynamic-state-memo`), [`docs/specs/guards.md`](../specs/guards.md), [`docs/specs/explain.md`](../specs/explain.md) (`REQ-explain-chain`)
- **Lands:** Chunk 4 in [`docs/plans/plan.md`](../plans/plan.md)

## Problem

1. **`onceFill` LHS Disqualification, `OnceMemoType` Discharge & `freshstruct` 2-Level Map Gaps (`gomutant.embeddedGuidance`)**
   - A standard `sync.Once` struct-pointer memoizer (`var embeddedGuidance = guidance.Embed("gomutant", guidanceSrc)` of type `*guidance.Embedded`):
     ```go
     func (e *Embedded) Document() (*Document, error) {
         e.once.Do(func() { e.doc, e.err = Parse(e.src) })
         return e.doc, e.err
     }
     ```
     currently fails receiver-read-only confinement because `onceFill`-admitted receiver field assignments (`e.doc, e.err = Parse(e.src)`) do not consume their LHS field projections (causing pointer/interface fields `*Document` and `error` to trip `CallResultHandsOut`) and do not propagate cross-package `paramLeakFree` wants on read-only receiver inputs (`e.src []byte`) passed to `Parse`.
   - Furthermore, because methods on `*Embedded` return pointers, slices, and `error` (`InstantiatedResultsHandOutNothing == false`), `methodUses` never defers them: discharging unexported `var V = Ctor(args...)` memoizer globals across `GeneralExecution`, `PackageExecution`, and `SingleSubjectExecution` (`996` out of `1,069` test subjects in `gomutant`) also requires mechanical first-principles `OnceMemoType` + `OnceMemoVarCandidate` verification under `REQ-closure-shared-dynamic-state-memo`.
   - Inside `guidance.Parse`, writing through a 2-level map field (`doc.index[s] = map[string]int{}` and `doc.index[s][spelling] = vi`) and reading a 2-valued scalar comma-ok lookup (`prev, taken := doc.index[s][spelling]`) on fresh local `doc := &Document{...}` hit two gaps in `internal/dynstate/internal/freshstruct` (`constructors.go` and `escape_uses.go`), falsely marking `Document` in `MutatedStructTypes`.

2. **Cross-Package `EnvSummary` Confinement Hard-Rejection (`internal/dynstate` & `explain.go`)**
   - `wantsResolve` in `internal/dynstate` currently hard-rejects cross-package `ParamKey` (`want.Func.Pkg != ownPath`) and `MethodKey` (`want.Pkg != ownPath`) confinement wants rather than serializing dedicated `ParamLeakFree` / `ReadOnly` edge maps on `EnvSummary` and solving them in `ResolveEnvAudit` (and rendering unproven edges in [`explain.go`](../../explain.go) `envAuditTrail`, `REQ-explain-chain`).

## Soundness Constraints & Resolution Scope

1. **`onceFill` Confinement (`!smuggles` & `paramLeakFree`), `OnceMemoType` + `OnceMemoVarCandidate` & `freshstruct` Fixes**:
   - Update `REQ-closure-shared-dynamic-state-receiver-proof`, `REQ-closure-shared-dynamic-state-leak-free`, and `REQ-closure-shared-dynamic-state-memo` in [`docs/specs/closure.md`](../specs/closure.md) (and re-pin `.stipulator/bindings/closure.textproto`).
   - On top of Chunk 3's `flowir` confinement engine, consume `onceFill`-admitted receiver field LHSs **only when `!smuggles` holds** (`lhs` is carrier-free, and whenever `TypeHandsOutMutableReach(lhsT)`, `lhs` is an unexported receiver field whose `rhs` reads no mutable-reach/carrier package global or non-receiver parameter, preserving `TestOnceFilledMemoKeepsTheProof`) and record `ReceiverReadOnlyParamDeps`, `ReceiverReadOnlyDeps`, and `ParamLeakFreeMethodDeps` for read-only receiver inputs and cross-package receiver-read-only methods.
   - Implement mechanical first-principles `OnceMemoTypeFact` + `OnceMemoVarCandidate` verification in `internal/dynstate/discharges_memo.go` (verifying an all-unexported-field struct `T` with 1 `sync.Once` field used at 1 `recv.once.Do(func() { ... })` site in 1 getter on `*T`, carrier-free constructor-only input fields, `once.Do`-only memoized fields that are carrier-free or `error` constructed via `nil`/`errors.New`/`fmt.Errorf` without `%p`, pure deterministic `once.Do` compute cone, non-mutating/non-escaping sibling methods, `GuardTypes` covering all reachable named structs with unexported ref/container fields confined to `p`, and unexported single-def `var V = Ctor(args...)` over unmutated/unescaped carrier-free inputs used exclusively as `V.Method(...)`, composed across variants against `!mutatedStructs[T]`, `!mutatedStructs[g]`, and `resolution.ParamLeakFree`).
   - Extend `internal/dynstate/internal/freshstruct` (`constructors.go` and `escape_uses.go`) to recognize fresh `*types.Map` sub-containers on fresh local struct fields and scalar 2-valued comma-ok reads.
2. **Cross-Package `EnvSummary` Edges & `explain.go` / `docs/specs/explain.md` Integration**:
   - Update `REQ-closure-shared-dynamic-state-parameter-facts` and `REQ-closure-shared-dynamic-state-registration-audit` in [`docs/specs/closure.md`](../specs/closure.md) and `REQ-explain-chain` in [`docs/specs/explain.md`](../specs/explain.md) (re-pinning `.stipulator/bindings/closure.textproto` and `.stipulator/bindings/explain.textproto`).
   - Add dedicated serialized `ReturnEnvParamDeps`, `ReturnEnvMethodDeps`, `ParamInsertionParamDeps`, `ParamInsertionMethodDeps`, and `EnvCallParamUses` edge maps on `EnvSummary` (never reusing `RetDeps`, which `FieldPopulationProves` at `fixpoint_env.go` treats strictly as `ReturnEnvFree`, and keeping `localBroken` conservative whenever value structs with `func` fields can flow into parameter-insertion sinks after a cross-package pointer-receiver call), feed `r.ParamLeakFree` and `r.ReadOnly` from `NewDeferralResolution` into `ResolveEnvAudit` and `envAuditTrail` in [`explain.go`](../../explain.go) (emitting terminating `"edge"` links when an environment-audit proof fails on an unproven `ParamLeakFree` parameter or `ReadOnly` method edge, `REQ-explain-chain`), and bump `DynamicStateStrategy`.
