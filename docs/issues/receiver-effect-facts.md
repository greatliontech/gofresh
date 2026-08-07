# Pointer-receiver method reads mark as mutation

A pointer-receiver method USE on a package-level dynamic carrier is an
address capture under REQ-closure-shared-dynamic-state's by-value
rule, so a pure read like `registry.Get(name)` marks the variable
mutated and opens its package - the read side of every
registration-shaped API stays downgraded even when nothing writes
post-init.

Mechanism (user decision: full tool-side precision, all rungs): per-package
method facts record whether a method demonstrably writes
receiver-reachable state (field stores through the receiver, passing
the receiver or its aliases to writers, address captures) - derived in
the method's declaring package, fact-compatible and memoizable. A
call site then marks mutation only when the resolved method's fact
says receiver-writing; an unresolvable or unknown method keeps the
fail-closed address-capture mark. Interface-dispatched calls resolve
against every in-graph implementation or stay fail-closed. The field
registry demands two further rungs in this chunk: generic receivers
(Declarations[A]) participate in the proof, and the audited
synchronization set - sync.Mutex/RWMutex lock operations are
receiver-neutral by source audit, since lock state cannot change
dispatch - so mutex-guarded read paths can prove read-only. The
returned-alias rung (reflect.Type returns) is chunk 24's
returned-alias-disposition doc.

Mid-chunk finding: the audited synchronization set must exist at BOTH
tiers - the receiver-effect proof (landed) and the external-effect
classification, where a mutex-guarded subject currently refuses with
"reaches sync (potential external dependence)" from the import-level
potentialExternal fallback (closure/maximal.go) before the
shared-dynamic-state discharge even matters. The admission: a sync
import whose every file use is Mutex/RWMutex does not set
potentialExternal, and the RTA analyzer's unaudited-standard-operation
branch admits the audited lock methods - an ObservationRTA bump (@14),
the audited-harness admission pattern. Pinned red by the
mutex-guarded-read fixture; every other receiver-effect fixture
(discharges and refusals alike, generic receiver included) is green.

Lands: cross-tool train chunk 23 (this doc's own chunk).

Lands: cross-tool train chunk 23.
