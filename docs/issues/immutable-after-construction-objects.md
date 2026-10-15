# Object-closed struct pointers: immutability after construction as a proven property

A package-level variable of pointer-to-struct type whose struct is
declared in the package — pgregory.net/rapid's `anyRuneGen`, a
`*Generator[rune]` handed to `StringOf` — refuses as "escapes writable":
the object-closed discharge covers interface variables whose every
store is an audited immutable construction (`errors.New`, a reflect
type, a constant), never a struct the package itself defines.

The desired property is immutability of every reachable part after
construction, not merely private fields and read-only methods. A constructor
can store a pointer, slice, map or interface supplied by a caller that retains
a writable alias; a private field then changes without any method on the
containing object writing it. The proof must close external aliases, all
construction inputs, reachable mutable storage and exported escape paths as
well as method effects, writes, conversions and returned values. Private
fields alone do not justify that every value of the type is immutable.

Only an established whole-object proof could make escapes harmless while
retaining rebinding as mutation. Its evidence and compatibility consequences
follow the canonical derived-fact rules, not the earlier proposal's assertion
that a new discharge would need no record change.

What blocks it today is a fixpoint across three judgments. The
receiver-effect proof refuses the receiver in a call-argument position
(rapid's `Filter` passes `g` to `filter(g, fn)`); admitting it means
deferring to the callee parameter's leak-free fact, and that proof
(`boundValueLeakFree`) counts a parameter stored into a composite
literal as an escape — `filter` stores `g` into `&filteredGen{g: g}`.
Resolving both refusals requires proving that a value handed into another
construction acquires no uncontrolled mutable alias; calling the resulting
type immutable cannot be the premise of its own proof. The
immutability of S depends on the proofs of S's methods, which depend on
the leak-freeness of the functions they call, which depends on the
immutability of the types those functions construct — a per-package
fixpoint over types, with the deferred-want machinery the parameter
and method facts already use carrying the cross-package edges to
composition, and a new fact (immutable type keys) in the persisted
record.

The consumers' standing rapid vouch (`pgregory.net/rapid:anyRuneGen`)
cannot be trimmed merely from the private-field argument. Retire it only
after the exact admitted dependency and reachable object graph are covered.

Lands: docs/plans/tooling-redesign.md 7.8.
