# Pointer-receiver method reads mark as mutation

A pointer-receiver method USE on a package-level dynamic carrier is an
address capture under REQ-closure-shared-dynamic-state's by-value
rule, so a pure read like `registry.Get(name)` marks the variable
mutated and opens its package - the read side of every
registration-shaped API stays downgraded even when nothing writes
post-init.

Mechanism (user decision: full tool-side precision): per-package
method facts record whether a method demonstrably writes
receiver-reachable state (field stores through the receiver, passing
the receiver or its aliases to writers, address captures) - derived in
the method's declaring package, fact-compatible and memoizable. A
call site then marks mutation only when the resolved method's fact
says receiver-writing; an unresolvable or unknown method keeps the
fail-closed address-capture mark. Interface-dispatched calls resolve
against every in-graph implementation or stay fail-closed.

Lands: cross-tool train chunk 23.
