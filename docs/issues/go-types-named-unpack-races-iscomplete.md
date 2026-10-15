# go/types: `Named.unpack` races `Checker.isComplete` under concurrent package checking

Lands: docs/plans/tooling-redesign.md 9.3.

The active plan owns verification of the gate's actual toolchain and race
capability. Restore affected race coverage when a listed pin eliminates the
reported unsynchronized read/write pair, with the relevant workload checked;
this filing does not assert that today's installed toolchain still has it.

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

The report also identified the same locking in go1.27.0
(`cycles.go:111` and `named.go`) and the then-used development fork's base.
It was timing-dependent: the recorded Stipulator self-checks and four
Gofresh closure race runs had not hit it. Those historical passes do not
refute the reported race, and those historical source checks do not establish
the status of a later installed toolchain.

## Why it is the toolchain's

No code of the fleet appears in either stack: the reader and the
writer are go/types' own, driven by x/tools' documented concurrency.
An application-source fix does not repair those toolchain sites. Judge a
corrected pin or a justified loader change by the actual concurrent workload;
do not label an unrelated test failure as this race.

## Recorded gate response (2026-10-06)

The gate's race tier judges the TREE's races; a red whose only report
is the toolchain's judges nothing about the commit and blocks the
release on a toolchain cause. Stipulator's gate therefore disabled
its race tier (the policy's own race invocations retained the tree's
race evidence at the band-close self-check, as before the gate), and
restoration depended on a corrected pin. Gofresh's race tier remained on.
Those are historical dispositions, not a blanket authorization to disable
another failing tier. Classify any new report against its actual stacks and
toolchain, and retain unrelated race findings and assurance obligations.

If the restored tier uses shards as gofresh's does (the gate's
`race-shards` input), the partition judgment — every Test, Example
and Fuzz function in exactly one shard — belongs in a home both
callers can read (the gate's own `go test -list` step over each shard's
regex, or a fleet package) rather than a second copy of gofresh's
raceshards_test.go.
