# The direct-call-site index is built three times

Three walks in `purity.go` answer "which unexported plain functions are
only ever called directly, and what does each call site pass": the
init-only helper judgment (`initOnlyReachableHelpers` and the
qualified-helper parameter binding beside it), the environment-free
registration audit's callee resolution, and the closed-interface-field
judgment's parameter provenance (`closedInterfaceFields`). Each rebuilds
the same rule — a function referenced anywhere but as a direct call's
callee has escaped, a call through a generic instantiation still counts,
the argument at a parameter's position carries into it — over its own
`ast.Inspect` of every file, and each spells the callee-unwrapping
ladder (parenthesis, index, index-list) for itself.

The collapse: one per-package call-site index — callable functions,
their parameters by position, direct call sites, escaped functions —
built once and consulted by all three judgments, with one
`unwrapCallee` for the ladder. Invariants preserved: every consumer's
fail-closed default on an escaped or unresolvable callee; the per-variant
scoping (the index is built from the variant's own syntax).

Lands: with the next judgment that needs call-site provenance, or with
docs/issues/flag-surface-one-table.md's collapse (the same one-index
shape).
