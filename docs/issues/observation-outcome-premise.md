# Producer migration to execution-bound outcome evidence

`REQ-inputs-completed-observation` requires normal termination and independently
established operation-outcome agreement. The shared facade now accepts a
completion receipt and analysis-issued support bound to the same frame, process
and environment. The fleet adapters must adopt that boundary and the v2 manifest.

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

The adapter migration must prepare support before the actual contributing
execution, over its complete subject set and exact inherited environment.
Mutated or otherwise transformed executables need support for their actual
operation model, not a borrowed baseline proof. Unsupported executions carry
honest incomplete evidence. Legacy manifests regenerate; asserted historical
completion never becomes verified outcome evidence through a dependency bump.

Lands: pew performance-evidence plan chunk 6 (shared producer migration after the outcome-support capability in chunk 5).
