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

The gofresh half landed at cross-tool train chunk 300 (2026-10-07):
guidance.PrintsDefault(flagType, defValue) is the table, pinned at
every type's cliff.

Lands: the consumer bumps reading gofresh's 300 release — stipulator
290r, pew 320 (gomutant's arm landed at 324) — where each registration walk reads
PrintsDefault and the three type switches delete.

Rider (audit 332): guidance.PrintsDefault mirrors pflag v1.0.9 with no oracle in gofresh (no pflag dependency; the pin compares literals) — each consumer's bump pins PrintsDefault against pflag's own rendering for every flag type it registers, so a pflag move reds at the consumer.
