# Receiver-captured function values launder receiver writes

A function value stored in receiver state whose closure captures the
receiver (a constructor installing `t.c.f = func() { t.n++ }`) reads as
reach-free under the carrier rules - Signature hands out no writable
reach - so a method binding it (`x := r.c; x.f()`) proves
receiver-read-only, yet calling the binding mutates receiver state the
served verdict assumed stable. Reproduces identically on the tree
predating the receiver-effect work: the hole is the settled model's
Signature classification, not the taint paths. Discharging it needs
closure-capture awareness (a func value whose literal captures
mutable-reach state is itself mutable reach) or a fail-closed
Signature reclassification with an audited-pure-func carve-out.

Lands: the next gofresh plan.
