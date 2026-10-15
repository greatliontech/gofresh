# Remaining direct-call provenance walks

The provenance walks in `purity.go` answer "which unexported plain functions are
only ever called directly, and what does each call site pass": the
init-only helper judgment (`initOnlyReachableHelpers` and the
qualified-helper parameter binding beside it), the environment-free
registration audit's callee resolution, and the closed-interface-field
judgment's parameter provenance (`closedInterfaceFields`). These consumers
distinguish direct callees from escaped references and carry arguments into
parameters, but their admitted syntax differs. The shared index unwraps
generic instantiations and parentheses; the init-only helper walk recognizes
a direct `ast.Ident` callee and conservatively rejects those other forms.
The common
index already serves some judgments; this is the remaining duplication,
not a request to build that index again.

The collapse: one per-package call-site index — callable functions,
their parameters by position, direct call sites, escaped functions —
built once and consulted through each judgment's explicit policy. The
index and the unwrapping ladder landed for the
two field-and-memo judgments (`callSiteIndex`, `directCallSites`,
`resolveParam`); what remains is the init-only helper walk's own copy
and the judge shape — `memberTypes` and `carrierFree` are two judges
over one resolver, each restating the concrete-type or carrier-free
test. Invariants preserved: every consumer's
fail-closed default on an escaped or unresolvable callee; the per-variant
scoping (the index is built from the variant's own syntax). Preserve the
init-region and direct-call restrictions, or separately justify and witness
any deliberate precision change using generic and parenthesized init calls.

Lands: docs/plans/tooling-redesign.md 7.8.
