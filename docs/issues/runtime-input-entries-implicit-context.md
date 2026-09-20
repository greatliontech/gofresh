# runtimeinput's ctx-less entries run their Go commands under an implicit context

Adopt, Absolute, Relative, FromTestLog, Merge, Describe and Paths take
no context, yet each runs `go env` (through the roots query) and the
module-view revalidation under context.Background() internally — the
same wrapper-passed-ambient-value shape the environment axis collapsed
(one explicit-environment form per entry). A caller cancelling a
freshness pass cannot stop these; a hung `go` under a broken toolchain
holds the pass. One form per entry on the context axis — ctx first,
the internal Background sites deleted — is the same collapse one
release later; every consumer's call gains a ctx at its bump.

Lands: cross-tool train chunk 243 (the public-surface sweep — the API-surface chunk
the earlier condition named; slotted at audit 261).
