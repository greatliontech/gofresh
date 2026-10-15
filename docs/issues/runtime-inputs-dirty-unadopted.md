# REQ-inputs-dirty specifies a capability no consumer selects

`REQ-inputs-dirty` (docs/specs/runtime-inputs.md) states the dirty-
provenance inspection: a `CommitInspector` a caller supplies so a
recording can carry whether its inputs were committed. Across gofresh
and its three consumers no type implements `CommitInspector`, `Dirty`
has only test callers (runtimeinput/dirty.go).
The clause specifies a mechanism nothing selects. Gomutant derives its
committed-baseline provenance directly from git; that is not an adopter of
this interface. Retire the unused API and its clause together in the owning
implementation change, reconciling bindings and references and checking the
four repositories again before removal. Do not add an adopter merely to
preserve an unused mechanism or delete the API while its contract still
requires it.

Lands: docs/plans/tooling-redesign.md 5.6.
