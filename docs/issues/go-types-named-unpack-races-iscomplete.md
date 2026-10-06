# go/types: `Named.unpack` races `Checker.isComplete` under concurrent package checking

Lands: a listed toolchain whose `go/types.(*Checker).isComplete` reads
a Named's `fromRHS` under the Named's lock (or whose `unpack` no
longer writes it outside one) — checked by reading
`src/go/types/cycles.go` and `named.go` of the release the fleet's
gate pins; the consumers' race tiers turn back on at that pin.

## What was observed

stipulator's first CI run through the fleet's gate (greatliontech/actions
go-gate.yml, run 37470828996, 2026-10-06, stock go1.27.1 on a 4-vCPU
runner, x/tools v0.47.0) failed its race tier on one report inside
`internal/backends/golang` (`TestPolicyVouchReachesTheCaptureEngine`,
0.14 s):

- Read at `go/types.(*Checker).isComplete` (cycles.go:122): `rhs =
  t.fromRHS` on a `*Named`, no lock held — called from the selector
  check of one package's checker.
- Previous write at `go/types.(*Named).unpack` (named.go:244):
  `n.fromRHS = n.expandRHS()` for an instantiated Named (`n.inst !=
  nil`), under `n.mu` — called from `Named.Underlying` in another
  package's checker.
- Both goroutines are `x/tools/go/packages.(*loader).refine`'s errgroup
  workers of ONE `packages.Load`: the loader type-checks packages
  concurrently once their imports are done, and two importers of a
  common package share that package's exported types, an instantiated
  generic among them.

The same two sites, with the same locking, are in go1.27.0
(`cycles.go:111` and `named.go`), so the listed toolchains carry it
alike; the development fork is built on the same sources. The race is
timing-dependent: stipulator's own policy runs the same package under
the detector at every band-close self-check without having hit it, and
gofresh's race tier (the closure package, four gate runs) has not hit
it either — every consumer whose race tier loads packages through
x/tools is exposed.

## Why it is the toolchain's

No code of the fleet appears in either stack: the reader and the
writer are go/types' own, driven by x/tools' documented concurrency.
Nothing a consumer changes in its tree removes the race, and the race
detector offers no exclusion by package.

## Disposition at stipulator chunk 321 (2026-10-06)

The gate's race tier judges the TREE's races; a red whose only report
is the toolchain's judges nothing about the commit and blocks the
release on a cause no commit can fix. stipulator's gate therefore runs
its race tier OFF (the policy's own race invocations stay the tree's
race evidence at the band-close self-check, as before the gate), and
turns it back on when the pin named above lands. gofresh's race tier
stays on while it passes — a pass is evidence of the tree and the
toolchain alike; a red carrying only this report takes the same
disposition. Reporting the race upstream is an external act the fleet's
owner takes or declines; the sites above are the report's content.

When the tier returns it runs sharded as gofresh's does (the gate's
`race-shards` input): the partition judgment — every Test, Example
and Fuzz function in exactly one shard — then moves to a home both
callers read (the gate's own `go test -list` step over each shard's
regex, or a fleet package) rather than a second copy of gofresh's
raceshards_test.go.
