# WithStaticInputRoot has no adopter

`runtimeinput.WithStaticInputRoot` (runtime-inputs.md: the testlog ingest
"MUST accept caller-declared static-input roots") is the one acceptance of
its clause, and across gofresh and its three consumers nothing calls it —
the static-root guard pairing runs only under the option's own tests. Like
the dirty inspector, it is a capability awaiting its adopter or a clause to
retire; deleting the option deletes the clause's acceptance, so it does not
move without the spec.

Lands: cross-tool train chunk 243 — retire the option and amend the clause
(derived 2026-09-29: pre-v1, no caller across the four repos).
