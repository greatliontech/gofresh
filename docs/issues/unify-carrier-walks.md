# One carrier walk instead of three sibling recursions

`purity.go typeMayCarryUnknownDynamic`, `closure/attribution.go
typeMayCarryDynamic`, and `purity.go typeHandsOutDynamicAlias` are
near-identical structural recursions differing in exactly two policy
points: the TypeParam arm (external fresh-map bounds entry vs the
shared-seen constraint recursion) and the leaf semantics of the
alias-handing judgment (Signature is not an alias; element positions
delegate to the carries-dynamic question). The audited atomic
transparency's tier split (two introduced M findings, review of
2026-08-22) was representable exactly because the rule lives in three
bodies; that RULE is now single-sourced
(`closure.AuditedAtomicPointerElem`), but any future carrier-rule
change re-litigates the same divergence class across the remaining
arms.

The collapse: one exported walk in `closure/`, parameterized by the
TypeParam policy and the leaf table, consumed by all three call
surfaces — REQ-closure-analysis's "same carrier rule at every tier"
becomes a single code object. The TypeParam cycle-guard semantics
(shared seen map vs fresh map at the bounds entry) are
behavior-bearing and must be preserved per call surface; that is the
delicate part and why this is its own change set.

Lands: with the next reachability-scoping change (the same window as
unify-discharge-walks and binary-roots-single-mask-union).
