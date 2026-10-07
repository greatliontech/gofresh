# Observation completion lacks an outcome-evidence premise

`REQ-inputs-completed-observation` and `WithCompletedProcess` require normal
termination and agreement between behavior-affecting operation outcomes and
guarded values. `ProducerIngest` carries health, identity, environment, brackets,
and declarations; `ProducerFrame.Observe` supplies `WithCompletedProcess` without
an independent outcome-evidence input.

The static observability proof establishes which effects can be represented.
Testlog identities and pre/post value brackets do not establish returned values,
byte counts, or errors. For example, a benchmark can ignore an allowed read error,
emit samples and exit successfully while the parent subsequently hashes the
unchanged file successfully. This is a code-supported missing implication, not
a claimed reproduced false-valid incident.

Gomutant's `internal/engine/run.go` observation paths and stipulator's
`internal/backends/golang/observe.go` use the shared facade with process-health
checks, without independent operation-outcome evidence. Pew currently selects
no observation-based freshness lift; its proposed adoption needs this premise
settled first.

The repair requires a coherent shared claim model and producer adapters, rather
than another automatically populated assertion. Distinguish verified facts,
explicit caller assertions, and missing evidence. Existing observed records need
an explicit compatibility judgment when producer construction and evidence
representation are repaired; previously asserted completion must not silently
become verified outcome evidence.
Execution is held for this contract work because changing one consumer alone
would leave the shared construction claim inconsistent.

Lands: pew performance-evidence plan chunk 6 (shared producer migration after the outcome-support capability in chunk 5).
