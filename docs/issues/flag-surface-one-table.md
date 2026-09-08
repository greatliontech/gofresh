# Package flag's admitted surface is answered by four tables

Four places answer "what does package flag admit": the audited symbol
row `flagSymbols` in `internal/auditset` (the FlagSet forms, consulted
by every tier's unaudited-standard fallback), the registration families
`flagRegistrationSymbol`/`flagValueRegistration`/`flagPointerRegistration`
in `closure/observability.go` (sinks admitted at the fold and both direct
walks, judged by their storage), the class-B gate in `closure/effects.go`
(flag is outside it, so the fallback ladder is what refuses the rest by
name), and the refused-rows table in `closure/audited_test.go` (which
asserts the pure predicate alone, so Bool/BoolVar sit in it while being
admitted as sinks). The never-enter list is stated twice in prose —
`flagSymbols`' comment and `flagRegistrationSymbol`'s.

Beside it, the file fold's selector arm (`closure/maximal.go`) and the
walk's direct-call fallback (`closure/analyzer.go`) run the same "standard
path, not exempt, not audited → unaudited-standard effect" ladder over an
AST selector and an SSA callee respectively, with the same message string
— so a refusal's tier is undiagnosable from its reason alone (the fold's
tier prefix is added later by the proof composition).

The provenance judgment added a third syntactic escape walk beside
`registrationAddressComputation` and `judgeCarrier`
(`confinedLocalStorage`): each enumerates a value's referrers, admits a
sanctioned set, and fails closed on the default arm. The flag-name
knowledge then has four spellings — `flagSymbols`,
`flagRegistrationSymbol`, `flagProvenSetMethod`, `flagProvenSetUse` —
with ErrorHandling in two of them independently.

The collapse: one flag surface, `auditset.FlagSurface(name) → {audited |
registration | refused}`, consulted by `flagRegistrationSymbol` and
`Symbol` alike, with the refused-rows test derived from it; and one
symbol ladder shared by the fold and the walk, differing only in the
operand's reading. Invariants preserved: the registration families stay
sinks judged by storage; the parsed-input channels stay refused by name
at every tier; the tier a refusal came from stays observable.

Lands: with docs/issues/classb-arms-one-table.md's collapse (the same
one-table shape for every audited package), or when a fifth flag
surface site is added.
