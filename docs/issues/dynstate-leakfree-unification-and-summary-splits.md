# Unify Dual AST Leak-Free Dataflow Walkers (`summary_leakfree.go`) & Split Oversized `summary_uses.go` / `summary_env.go`

- **Status:** Open
- **Governing contract:** [`docs/specs/closure.md`](../specs/closure.md) (`REQ-closure-shared-dynamic-state`), [`docs/specs/guards.md`](../specs/guards.md)
- **Lands:** Chunk 7 in [`docs/plans/plan.md`](../plans/plan.md)

## Problem

1. **Duplicate AST Leak-Free Walkers and `sync.Once.Do` Exemption Verifiers in `internal/dynstate/summary_leakfree.go` (`1,486` lines)**
   - `boundValueJudged` ([`internal/dynstate/summary_leakfree.go`](../../internal/dynstate/summary_leakfree.go) lines 49–513, `465` lines) and `receiverReadOnlyMethods` (`lines 974–1486`, `513` lines) maintain ~350 lines of parallel AST taint propagation and read/call consumption arms (`AssignStmt`, `ValueSpec`, `IncDecStmt`, `SendStmt`, `UnaryExpr`, `RangeStmt`, `ReturnStmt`, `CallExpr`, `IndexExpr`, `SelectorExpr`, `BinaryExpr`, `Ident`).
   - The same file also maintains two separate `sync.Once.Do` receiver-fill exemption verifiers (`onceBodyFillsReceiver` at `lines 718–817` for bound local structs vs. inline `onceExemptions` at `lines 1109–1189` inside `receiverReadOnlyMethods`), creating a concrete maintenance hazard whenever confinement rules evolve (as seen with `onceFill` LHS consumption and `paramLeakFree` argument confinement in Chunk 2).

2. **Multi-Concern `2,000`-Line Summary Files in `internal/dynstate` (`summary_uses.go`, `summary_env.go`)**
   - [`internal/dynstate/summary_uses.go`](../../internal/dynstate/summary_uses.go) (`2,010` lines) combines general AST dynamic-global use tracking (`recordDynamicGlobalUses`, lines 1–1400) with `sync.Map`/`sync.Pool`/function-reference-region/opaque-var verifiers (`walkSyncVarCalls`, `dataMemoVars`, `provenSharedPools`, `recordFunctionReferenceRegions`, `recordOpaqueDynamicVars`, lines 1402–2010).
   - [`internal/dynstate/summary_env.go`](../../internal/dynstate/summary_env.go) (`1,977` lines) combines store-plane environment-free function-literal and field-registrant classification (`lines 1–702`) with return-plane audited value and return-field registrant derivation (`lines 704–1977`).

## Resolution Scope

1. Factor a single parameterized AST confinement/consumption engine and shared `sync.Once.Do` receiver-fill verifier in [`internal/dynstate/summary_leakfree.go`](../../internal/dynstate/summary_leakfree.go) serving both `boundValueJudged` and `receiverReadOnlyMethods` without weakening either's escape/return or receiver-mutation invariants (preserving all stipulator-bound witness test names in `internal/dynstate/dynstate_test.go`).
2. Split `summary_uses.go` (`summary_uses.go` + `summary_uses_sync_opaque.go`) and `summary_env.go` (`summary_env_stores.go` + `summary_env_returns.go`) within `package dynstate` along those subsystem seams.
