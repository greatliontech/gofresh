# Declaration refinement widens on dependency-heavy benchmark programs

Lands: before a consumer relies on refined mode to recover reuse for a
dependency-heavy benchmark package.

## Context

The representative Observer package `./tests/benchmarks` contains 39 benchmarks
and the durable L/XL workloads for which Pew refinement is intended. Maximal
capture of all 39 subjects completed in 14.66 seconds at about 20.6 MB peak RSS.
The attributed declaration-RTA capture exceeded a caller-supplied 25-minute
budget at about 3.24 GB peak RSS and returned cancellation safely after
cancellation checkpoints were added between subject projections.

A one-subject capture of
`BenchmarkDashboard_P95LatencyByRoute_Long` completed in 1m40s–2m11s at about
3.0–3.15 GB peak RSS. An equal-length edit confined to sibling
`BenchmarkDashboard_LogVolumeBySeverity` made both maximal and refined evidence
stale. The refinement had widened to maximal after reaching a pinned Pebble
interface method whose cache declaration index did not contain a direct function
declaration. On this bounded realistic sample, maximal false-staled 1/1 irrelevant
edits and the current refinement recovered 0/1.

The generated test-main registration initializer and generated `go_asm.h`
handling were separately removed as unnecessary whole-closure widening sources.
Cache interface methods are now attributed through their declaring interface,
generic cache functions normalize through both SSA and go/types origins, and
computed/interface sites carry per-subject RTA resolution evidence while roots
that can receive unknown callable state remain open-world. The first surviving
Observer widening is an unassigned package test-hook function variable in
`x/net/http2`; proving it immutable requires whole-program store, alias, assembly,
unsafe, and linkname analysis rather than a package-specific exception. Existing
differential and closure correctness tests continue to require every uncertain
edge to widen rather than under-cover.

The bounded non-standard-library SSA experiment was rejected. Loading every
non-standard dependency as a source root completed all 39 subjects in 2m50s at
about 3.97 GB peak RSS under default GC, but every subject reached an unsummarized
standard-library body and therefore widened safely to maximal plus unverifiable.
Restricting source roots to the non-standard import leaf frontier produced an
incoherent test-variant graph that panicked during SSA construction, so it failed
the unavailable-not-crash criterion before measurement. Omitting standard-library
bodies cannot become a recording strategy without complete toolchain-derived
callback, interface, external-effect, registry, reflection, assembly, and linkname
summaries; signature heuristics or API allowlists would admit false valid results.

## Resolution

Evaluate this remaining strategy shape against the existing precise closure corpus
and Observer sample:

1. Retain declaration-RTA and prove immutable callable globals through complete
   store, alias, assembly, unsafe, and linkname analysis where that proof is
   available.

Accept a refinement for consumer use only when it remains differential-equivalent
to the sound corpus, completes under an explicit caller budget, and demonstrates
false-stale recovery on realistic relevant and irrelevant edits. Any uncertain
prototype result remains unavailable rather than valid.
