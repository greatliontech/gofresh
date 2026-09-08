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

The report arrived (the chunk-125 sweep over the pinned cerebro tree,
gofresh v0.98.10): 961 of 2,119 subjects refuse at the STARTUP walk —
"startup effect: reaches unaudited standard operation
encoding/json/v2.init$2" (493), internal/godebugs.init$1 (290),
crypto/internal/fips140/aes.init#2$1 (178) — not at the subject
walk's enumerated arm. The mechanism: the startup and test-main walks
(`closure/observability.go`, the `reachable.dynamicTargets[site]`
loops) classify every target of a dynamic site's whole-mask
signature-class projection, so an initializer's func-value call of
type `func(string) bool` reaches internal/godebugs' `Old` closure and
every other standard closure of that signature; the static
`name != "init"` exemption never applies because these targets are
closures (init$N), and applying an init-family exemption to them would
be UNSOUND: a standard body is never walked, so an exemption admits the
closure's effects unjudged. The sound narrowing is the operand's:
resolve the site through the closed-value walk before the RTA
fallback, as the subject walk's resolved sites do — chartered as chunk
179, which this doc rides.

Lands: 179
