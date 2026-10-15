# WithStaticInputRoot has no adopter

`runtimeinput.WithStaticInputRoot` (runtime-inputs.md: the testlog ingest
"MUST accept caller-declared static-input roots") is the one acceptance of
its clause, and across gofresh and its three consumers nothing calls it —
the static-root guard pairing runs only under the option's own tests. Retire
this unused option and the corresponding clause obligation together in the
owning implementation slot, with bindings and references reconciled. Repeat
the four-repository caller inventory before removal. Deleting the option alone
would contradict the clause; adding a speculative adopter is not the remedy.

Lands: docs/plans/tooling-redesign.md 5.6.
