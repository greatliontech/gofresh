# Shared-dynamic-state downgrade fires on any use of alias carriers

The shared-dynamic-state mutation walk marks alias-handing carriers —
interface-, map-, slice-, channel-, and pointer-typed package-level
variables — as "mutated" on **any use at all** (documented fail-closed
in `recordDynamicGlobalMutations`, purity.go). The declaring package
then opens (dynamicstate.go's mutated∩declared composition), and the
import walk downgrades every view package whose graph reaches an open
package; the view marks every subject of a downgraded package
unverifiable (purity.go's downgrade loop).

Measured consequence on the first field corpus at scale: error
sentinels (`var ErrX = errors.New(...)` — reading one via `errors.Is`
counts as mutation), first-party registry maps, a property-testing
library's internal caches (pgregory.net/rapid), and the generated
test-main's own registration tables (`tests`, `benchmarks`,
`fuzzTargets`) each open their packages, and the contagion downgraded
essentially the whole corpus: 2,407 of 2,775 executed witnesses
refused, single-package probe confirming the downgrade chain
end-to-end. The whole-view caller-enumeration narrowing operates on
the argument channel and cannot rescue a downgraded package — the two
channels are disjoint.

Second defect, same home: the downgrade emits the same reason string
as signature-carried dynamism ("subject accepts caller-supplied
dynamic behavior", view.go), so consumers cannot distinguish the
channels. The field baseline's class attribution was mis-binned by
this conflation: what read as argument-dynamism was package
downgrades.

Fix direction (spec-tier — routes through
REQ-closure-shared-dynamic-state, the fail-closed any-use judgment is
that requirement's current collapse): mutation should require a
demonstrated write through the alias (or a reachable write), not any
read; init-exempt startup state (the harness registration tables are
the existing init exemption's unrecognized analog) and never-mutated
sentinels must read closed. The reason string split is part of the
same change.

Lands: cross-tool train chunk 21.
