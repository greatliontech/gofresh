# Extract the immutable observation facts into one shared struct

Three constructors hand-build near-identical View literals — `newView`,
`View.Sibling`, and `newSeededValidationView` (view.go) — each copying
the same immutable per-generation observation facts (snapshot, maximal
closures, guards, purity, source-file union and per-subject lists, file
digests, test-variant ledgers) field by field around a small
transactional half (seal, captured/observable proofs, runtime
attachments). The sharing contract ("read-only after construction") is
conventional, enforced by review, not by shape.

A shared derive-constructor was reviewed and rejected twice: it would
either copy the View struct (copying its `sync.RWMutex`) or take every
field as a parameter — a bag no clearer than the literals. The shape
that avoids both horns: extract the facts into one mutex-free
`observationFacts` struct held by the View (by pointer or value); the
three constructors shrink to facts assembly plus a small
transactional-state literal, and read-only sharing becomes structural
rather than conventional. `viewObservation` already carries most of the
same fields, so the facts struct could also unify it with the View's
fact half, removing `newView`'s field-by-field adoption.

Sizeable: touches most read sites in view.go. Invariants preserved:
per-generation coherence (facts constructed once per observation),
per-transaction seal/attachment semantics (stay on the View), the
guard family capture (rides the facts).

Lands: user decision.
