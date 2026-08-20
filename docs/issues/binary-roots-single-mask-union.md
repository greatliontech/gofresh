# Binary-scoped root inventory: one all-roots walk

ComputeBinaryRootedFunctions unions per-root inventories via
ComputeRootedFunctions — ⌈N/64⌉ attributed RTA analyses plus N
provenance walks for a union that needs no per-root separation. A
single mask covering every harness root over one rta.Analyze yields
the same set in one walk, and drops the N materialized per-root maps.
The per-root path stays for the per-subject (single-subject) scoping,
which genuinely needs attribution.

Lands: with the next reachability-scoping change.
