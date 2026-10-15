# Runtime-input adoption and composition retain implicit contexts

The remaining context gap is in `FromState`, adoption, identity conversions
(`Absolute`/`Relative`) and merge, including the revalidation and
state-reconstruction work they reach. These paths can use private background
contexts rather than the owning operation's caller context. A cancelled unit
must not continue input or environment observation under that substitute.

`Describe` and `Paths` decode/project a manifest; they do not spawn `go env`.
They are not evidence for the former claim that every context-less entry
launches an environment query. The context-aware producing form already owns
finalization under its closing context; preserve it while closing the
remaining composition paths.

Apply REQ-fresh-context and REQ-fresh-unit-exclusion at each observation
endpoint. An explicit bounded closing phase is permitted; a concealed
background continuation is not. Sharing within one coherent phase must not
reuse an earlier endpoint's observation as a later validation.

Lands: docs/plans/tooling-redesign.md 5.5.
