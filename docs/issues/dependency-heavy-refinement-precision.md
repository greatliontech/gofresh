# Declaration refinement widens on dependency-heavy benchmark programs

Lands: before a consumer relies on refined mode to recover reuse for a
dependency-heavy benchmark package, and only after re-measuring the
open-world population under the shared-dynamic-state mutation analysis
(REQ-closure-shared-dynamic-state) shows the residual is worth the
alias-level extension below. The re-measurement requires the Observer
sample corpus, which is not on this machine: the measurement is
blocked until that consuming corpus (or an equivalent dependency-heavy
benchmark tree) is available locally.

## Context

The representative Observer package `./tests/benchmarks` contains 39 benchmarks
and the durable L/XL workloads for which Pew refinement is intended. Widening
sources already eliminated: the generated test-main registration initializer
and `go_asm.h` whole-closure widening; cache interface methods now attribute
through their declaring interface; generic cache functions normalize through
both SSA and go/types origins. The bounded non-standard-library SSA experiment
was rejected (every subject reached an unsummarized standard-library body and
widened; the leaf-frontier variant failed the unavailable-not-crash criterion;
omitting standard-library bodies would need complete toolchain-derived
summaries to avoid false valid results).

## Current-engine evaluation

Measured on the Observer sample, single process:

- Maximal view of all 39 subjects: 1m39s cold / 17.4s warm, ~1.7–1.85 GB peak
  RSS.
- Refined capture of `BenchmarkDashboard_P95LatencyByRoute_Long`: 1m24s within
  a 6-minute budget; the recording is unverifiable with reason "subject
  accepts caller-supplied dynamic behavior".
- False-stale recovery on an equal-length edit proven confined to sibling
  `BenchmarkDashboard_LogVolumeBySeverity` (argument-order swap in its query
  call): 0/1 — the check returned `stale refinement` after 1m25s. An earlier
  run of the same probe agreed on every disposition (capture 1m16s
  unverifiable with the same reason, check 1m20s stale). Process-wide peak
  across view constructions, capture, and check: ~4.9–5.0 GB.

The surviving blocker is structural, not a single widener. Since this was
measured, the type-level blanket has been narrowed: only variables the
program can mutate after initialization downgrade
(REQ-closure-shared-dynamic-state) — by-value carriers clear when no write,
address capture, or pointer-receiver method use exists, while alias-handing
carriers (interface values, pointers/maps/slices reaching dynamic state)
still downgrade on ANY use, fail-closed. The dependency-heavy population
below is dominated by alias-handing shapes (interface-typed registries,
unsafe-laden protobuf internals), so clearing it still requires the
SSA-level value-flow analysis previously concluded: The Observer benchmark graph contains 2,486 such variables across 233
of its 460 module-scoped packages (696 packages in the full import graph
including the standard library). Top offenders in order: otel semconv v1.41.0
(615), protobuf internal/impl (173), x/text/language (86),
x/text/internal/language/compact (81), gogoproto (76), arrow-go
internal/utils (73),
gogo/protobuf types (56), GoSQLX sql/ast (54), parquet-go (52), x/net/http2
(52). Clearing open-world therefore requires proving immutability for the
reachable portion of that population — whole-program store, alias, assembly,
unsafe, and linkname analysis, as previously concluded for the single
x/net/http2 test-hook variable.

## Resolution

Unchanged acceptance bar: retain declaration-RTA; a refinement becomes
consumer-usable only when it is differential-equivalent to the sound corpus,
completes under an explicit caller budget, and demonstrates false-stale
recovery on realistic relevant and irrelevant edits — with the immutability
proof above as the identified mechanism and its measured proof surface as the
cost anchor. Any uncertain prototype result remains unavailable rather than
valid.
