# go1.27 generic-method shapes break closure reachability ("unsupported analysis shape: Int")

The owning filing for the defect both consumers reported
independently (gomutant docs/issues/go127-generic-method-closure-
analysis.md, binary v0.40.2 on gofresh v0.82.0; pew's twin on
gofresh v0.76.0; both protodb close-out campaigns, 2026-08-23): the
go1.27 standard library's generic-method shapes — math/rand/v2's
`rand.go:213` is the reproducer ("method must have no type
parameters", "Int (function) is not a type", collapsing to
"unsupported analysis shape: Int") — fail the closure/reachability
analysis on binaries BUILT with go1.27. The toolchain rebuild
cleared only the go/packages parse skew (verified 2026-08-24:
rebuilt gomutant went from 4/50 to 37/50 targets measured on
tugboat); this failure is in the analysis layer and spans every
gofresh version both consumers ride (v0.76 and v0.82), so the fix
lands here once and both tools bump.

## Impact

Any tree whose oracle closure reaches an affected stdlib shape loses
freshness evidence for the whole target: campaigns skip or mark
unverifiable, and with the fleet moving to go1.27 the affected
surface is every project. This blocks the queued re-baselines
(tugboat's whole-store pew re-record and node-target campaign
completion) from producing trustworthy evidence.

## Fix directions (from the consumer filings)

Teach the reachability analysis the generic-method shape outright
(go1.27 made it a stdlib reality, not an edge case), or degrade
per-shape: skip exactly the unanalyzable EDGE, keep the target
measurable with a widened oracle set and the imprecision named on
the record — never skip the whole target for one edge.

Lands: with the go1.27 analysis support (fleet toolchain moved
2026-08-24; every consumer campaign is exposed) — then gomutant and
pew bump.
