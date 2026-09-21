# The printed-default predicate lives in three consumers

REQ-guidance-render's CLI lint takes, per registered knob, whether the
flag library prints a default for it (guidance.Registered's value); a
consumer derives that fact from pflag's own printing rule — the zero
value of the flag's type prints nothing, so a string "0" prints while
an int 0 does not, with pflag's fallback set of zero spellings for
other types. stipulator (internal/cmd/guidance_test.go), gomutant (its
CLI registration test), and pew (cmd/pew/guidance_test.go) each carry
the same type switch, each pinned or unpinned on its own.

The collapse: one fleet home taking the two strings pflag exposes —
`guidance.PrintsDefault(flagType, defValue string) bool` — needing no
pflag dependency in gofresh, pinned once at every type's cliff, and
read by each consumer's registration walk.

Invariants preserved: the lint's fact keeps pflag's rule exactly; a
consumer's registration carries the same value it does today.

Lands: cross-tool train chunk 184 (the knob-clause chunk behind 266,
where the projection's CLI rules are next reworked).
