# The enumerated dynamic-target fallback lacks the init exemption the static path has

`closure/analyzer.go`'s two unaudited-standard fallbacks disagree on
the init family: the static call path (`classifyCalleeEffect`)
exempts a callee named `init` by name before refusing an unaudited
standard operation, while the enumerated dynamic-target path (the
loop over a resolved site's targets in `analyzeReachability`) applies
the fallback to every non-source-only standard target, so a target
named `init`, `init#N`, or a synthetic `init$N` closure refuses as
"reaches unaudited standard operation <pkg>.init$N" although its body
is walked exactly as a named init's is. Chunk 122's charter counted
~58 such refusals in the 2026-08-26 field histogram (gofresh v0.85).

On main (v0.98.4) the state is not reachable through any constructed
shape: a static call to a standard closure is impossible; an
unresolved dynamic call (a standard func-typed global such as
`flag.Usage`, a std-returned cancel func) widens as a computed call
before any target is named; a subject-closed dynamic call resolves to
the subject's own closures only. The path exists in the code; no
input on main reaches it.

Fix shape when a report arrives: one `initFamily(name)` predicate
(init, init#N, init$N, nested) consulted by both fallbacks, the
dynamic site gaining the exemption the static site has; the walk of
the target's body carries its effects. Pin with the reporting shape.

Lands: when a field report shows a "reaches unaudited standard
operation <pkg>.init$N" refusal on a current gofresh.
