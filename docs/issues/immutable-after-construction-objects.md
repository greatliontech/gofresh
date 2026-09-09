# Object-closed struct pointers: immutability after construction as a proven property

A package-level variable of pointer-to-struct type whose struct is
declared in the package — pgregory.net/rapid's `anyRuneGen`, a
`*Generator[rune]` handed to `StringOf` — refuses as "escapes writable":
the object-closed discharge covers interface variables whose every
store is an audited immutable construction (`errors.New`, a reflect
type, a constant), never a struct the package itself defines.

The property is provable: a struct type S is immutable after
construction when its fields are all unexported, every method in its
method set is proven read-only by the receiver-effect proof (the
once-filled memo included), no field of S is assigned or address-taken
outside a composite literal or a proven method, no conversion into S
exists, and every method's result hands out no mutable reach or is
itself an immutable-after-construction type. Then every *S value is
immutable whatever expression produced it, a package-level *S variable
is object-closed — escapes are not mutation, method calls are the
proof's, rebinding stays mutation — and the discharge is the engine's
own verdict, no attestation, no record.

What blocks it today is a fixpoint across three judgments. The
receiver-effect proof refuses the receiver in a call-argument position
(rapid's `Filter` passes `g` to `filter(g, fn)`); admitting it means
deferring to the callee parameter's leak-free fact, and that proof
(`boundValueLeakFree`) counts a parameter stored into a composite
literal as an escape — `filter` stores `g` into `&filteredGen{g: g}`.
Both refusals dissolve under one rule: a value handed into the
construction of an immutable-after-construction type is not leaked,
because no holder of the constructed object can reach it. So the
immutability of S depends on the proofs of S's methods, which depend on
the leak-freeness of the functions they call, which depends on the
immutability of the types those functions construct — a per-package
fixpoint over types, with the deferred-want machinery the parameter
and method facts already use carrying the cross-package edges to
composition, and a new fact (immutable type keys) in the persisted
record.

The consumers' standing rapid vouch (`pgregory.net/rapid:anyRuneGen`)
cannot be trimmed before this lands; the chunk-99 close-out records
that deviation.

Lands: cross-tool train chunk 193
