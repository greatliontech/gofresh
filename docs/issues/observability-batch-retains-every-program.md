# ComputeObservabilityBatch retains every package's whole-program SSA for the Hasher's lifetime

Lands: 5

## Observed

`ComputeObservabilityBatch` loads each package group through
`Hasher.loadCached`, which stores the whole-program SSA in `h.progs` with
no release path — no `delete(h.progs, ...)` exists anywhere. A capture
batch over a many-package view therefore grows peak RSS with the package
count instead of the largest single test binary.

Measured anchor: a 33-fixture-package table driven through the same
caching load peaked at 10.4 GB RSS, against 614 MB for the identical
analysis with a load-locally-release-per-call discipline (plain run, no
race; the race detector multiplies both). The removed refined batch path
kept the bounded-peak discipline explicitly ("peak SSA memory bounded by
the largest package test binary rather than the total subject set");
observability never adopted it.

## Tension to resolve

Retention is also what saves re-loads within one capture batch (the same
package can appear in several groups' dependency work). The fix must
resolve memory and re-load cost together — release-after-group as the
removed batch did, or a bounded cache — not trade one for the other.
