# REQ-inputs-dirty specifies a capability no consumer selects

`REQ-inputs-dirty` (docs/specs/runtime-inputs.md) states the dirty-
provenance inspection: a `CommitInspector` a caller supplies so a
recording can carry whether its inputs were committed. Across gofresh
and its three consumers no type implements `CommitInspector`, `Dirty`
has no caller, and `DirtyEnv` only test callers (runtimeinput/dirty.go).
The clause specifies a mechanism nothing selects, so it is either a
capability awaiting its adopter — gomutant's committed-baseline
provenance is the plausible one, where a finding's `Dirty` is derived
today from git directly — or a clause to retire with its code.

Lands: user decision — adopt (gomutant's baseline reads it) or retire the
clause and the inspector.
