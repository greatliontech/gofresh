# Per-subject closure analysis costs more than the tests it saves

Lands: 6

## Context

Measured on stipulator's witness-freshness gate (127 top-level tests, one
`Engine` with `WithDir`, one `Prime`, then a Check or Capture per test):
the engine phase burns ~57 CPU-minutes and ~12 GB RSS before a single test
runs. The verdicts are correct; the economics are inverted — the analysis
costs more wall time than executing the full suite it lets the caller skip,
so a freshness-gated run is slower than the uncached run it replaces on
trees of this size.

The cost shape: package loading and SSA construction are shared per Prime,
but each subject pays its own RTA reachability pass over the whole program.
N subjects in one tree means N near-identical whole-program traversals that
differ only in their root.

## Resolution

Amortize reachability across subjects of one Prime: one multi-root pass
that attributes reachable functions per root (or a shared call-graph built
once, per-root closure extracted by walk), and a memory ceiling story for
the shared program representation. The per-subject hash semantics
(REQ-closure) must not change — only the traversal economics.
