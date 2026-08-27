# Range-over-func subjects read open-world through their own yield

A subject ranging over a function iterator (`for v := range seq`)
refuses observability with "subject reachability is not closed:
computed function call in ... calling parameter yield": the iterator's
yield is a function parameter, and the enumeration's closed-value walk
does not recognize the range statement's own desugared callback as the
closing caller — although the yield closure is constructed BY the
range statement in the subject's own frame, the one provenance the
walk was built to admit. The shape corpus pins the current refusal
(shapecorpus: "range over function iterator", observable=false) so
any flip is a red canary; admitting the range-desugared callback would
flip the pin deliberately.

Lands: with the precision/discharge band (cross-tool train chunks
116-125), ordered by field mass at its triage.
