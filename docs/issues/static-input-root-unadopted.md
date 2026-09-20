# WithStaticInputRoot has no adopter

`runtimeinput.WithStaticInputRoot` (runtime-inputs.md: the testlog ingest
"MUST accept caller-declared static-input roots") is the one acceptance of
its clause, and across gofresh and its three consumers nothing calls it —
the static-root guard pairing runs only under the option's own tests. Like
the dirty inspector, it is a capability awaiting its adopter or a clause to
retire; deleting the option deletes the clause's acceptance, so it does not
move without the spec.

Lands: user decision — adopt (name the consumer and its call) or retire
(amend the clause).
