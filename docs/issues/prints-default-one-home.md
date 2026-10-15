# Pew retains a local printed-default predicate

REQ-guidance-render's CLI lint takes, per registered knob, whether the
flag library prints a default for it (guidance.Registered's value); a
consumer derives that fact from pflag's own printing rule — the zero
value of the flag's type prints nothing, so a string "0" prints while
an int 0 does not, with pflag's fallback set of zero spellings for
other types. Gomutant and Stipulator read the shared predicate. Pew's
`cmd/pew/guidance_test.go` still carries `zeroDefault` and passes its inverse
to the already-adopted shared Coverage judgment.

The existing fleet home takes the two strings pflag exposes —
`guidance.PrintsDefault(flagType, defValue string) bool` — without a pflag
dependency in gofresh. Its type-cliff pins preserve the printing rule. Read it
from Pew's registration walk in place of the last local switch.

Invariants preserved: the lint's fact keeps pflag's rule exactly; a
consumer's registration carries the same value it does today.

Lands: docs/plans/tooling-redesign.md 5.6.

Keep the consumer's independent comparison against pflag's actual rendering
for every registered flag type. The shared table covers pflag's own value
types, not an arbitrary custom concrete type reporting the same type name.
Coverage-lint adoption is complete and is not part of this residual.
