# Repeated runtime-type parameter scans

`closure/internal/rta/rta.go` calls `ContainsTypeParam` before checking whether
`addRuntimeType` has any new subject-mask bits to propagate. Admitting a recursive
named type visits its pointer and then the named type again; the repeated visit
rescans the type graph even though its mask delta is already zero. This is
avoidable preparation, not a demonstrated incorrect reachability result.

The October 2026 closure attribution run at `2e04355` attributed approximately
4.47 GB of cumulative allocation and 12.22 parent CPU-seconds (0.72% of samples)
to this structural scan. Those totals include necessary scans and do not measure
recoverable savings. The run's independent PGO fixture conflicted with its global
CPU profiler; it is not a passing gate or a complete performance comparison.

The narrow experiment moves the zero-delta check before the structural guard,
retaining that guard for every nonzero delta and preserving downstream delta-only
propagation. Check lookup behavior for parameter/union shapes before changing
the order. An existing mask is not general authority to omit the guard for a
new delta: the map uses `types.Identical`, while the structural predicate inspects
representations such as explicit unions and receiver parameters. No global cache
or additional pass-scoped memo is justified by the present measurements.

Compare guard-node work, allocations and time for self-referential named types
and staggered/overlapping masks. Preserve complete result masks, generic-origin
and nested-local-parameter refusals, and unsupported-shape error behavior. Use
the existing attributed-versus-independent RTA oracles alongside a focused
benchmark. The admission-order change is a separate RTA change set from assembly
file observation; its small measured CPU share does not establish a gate-speed
benefit before that experiment.

Lands: docs/plans/tooling-redesign.md 7.7a.
