# Returned alias values keep receiver reads fail-closed

A method proven receiver-read-only can still hand out receiver-reachable
state through its RETURN values: `Lookup(name) (A, reflect.Type, bool)`
returns an interface value aliasing registry internals, so a caller
could in principle mutate what the registry stores. Until returned
alias-handing values get an object-closure-style disposition (audited
immutable types - reflect.Type is runtime-canonical and immutable by
audit; comparable type parameters; value copies), the receiver-effect
discharge refuses any method returning an alias-handing type, and the
field registry's read path stays downgraded.

Mechanism (user decision: build all rungs): extend the audited set with
returned-type judgments - a return type that is provably immutable
(audited stdlib types such as reflect.Type; non-alias value shapes) does
not break the read-only proof; anything else keeps the refusal.

Lands: cross-tool train chunk 24.
