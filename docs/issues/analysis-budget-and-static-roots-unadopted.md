# Two spec-bound options have no adopter

`gofresh.WithAnalysisBudget` (overview.md: precise analysis "expressed
through a caller-supplied analysis budget, never through cancellation")
and `runtimeinput.WithStaticInputRoot` (runtime-inputs.md: the testlog
ingest "MUST accept caller-declared static-input roots") are each the
one acceptance of a clause, and across gofresh and its three consumers
nothing calls either — the mechanisms behind them (the bounded analysis
context; the static-root guard pairing) run only under the options'
own tests. Like the dirty inspector, each is a capability awaiting its
adopter or a clause to retire; deleting the option deletes the clause's
acceptance, so neither moves without the spec.

Lands: user decision — adopt (name the consumer and its call) or
retire (amend the two clauses), per option.
