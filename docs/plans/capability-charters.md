# Capability charters

Conditional capabilities have no automatic implementation slot. Each entry's
issue document carries its scope and deciding condition; this register is the
cross-repository index. The active tooling-redesign roadmap's 9.4 gate owns
their retention and disposition. An observed activation is triaged into an
explicit implementation charter before work begins; merely mapping a condition
to the final census does not commission the capability.

| charter | repo | activates when |
|---|---|---|
| proto-backend | stipulator | a party outside the repository consumes stipulator's protos — a module importing gen/stipulator/v1, or a non-Go consumer of proto/stipulator/v1 |
| out-of-process-backends | stipulator | a specific second-language backend is planned; activation precedes deciding its protocol, and the existing Go resolver is not a generic-backend contract |
| prover-trust-tiers | stipulator | a proposed heuristic analyzer would otherwise enter the analyzer-proof evidence tier |
| performance-evidence-axis | stipulator | an identified corpus commissions measurement-backed performance acceptance; freshness alone cannot prove a threshold |
| structural-call-absence-verb | stipulator | an identified structural requirement needs a call-absence proof that the signature/import assertions demonstrably cannot carry; direct and indirect-call scope is settled before a new prover is admitted |
| remote-bench-execution | pew | a dedicated benchmark machine is provisioned and an identified dev or CI workflow requires measurements on that host |
