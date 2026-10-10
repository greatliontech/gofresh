# The memo layer's remaining collapses: one per-directory memo type, one read path, one derivation result type

The per-file memos (file scan, compartment parse) are one
load/serve/record/flush shape written twice over a per-directory entry
(closure/filememo.go); a generic per-directory memo type would collapse
them and align with the observability memo's merge discipline. Beside
them, five file-read paths exist — the Hasher's once-per-call read, the
listing record's derivation, the cgo include walk, the bare per-file
scan, and the compartment's own source — three of them digesting the
bytes the fold digests; one read path per pass is the collapse.

Adjacent, same altitude: the dynamic-state derivation's result type
serves two roles — the per-pass state (per-view-package cones,
downgrades, discharge records, culprit inventories) and the per-cone
composition state (the flat fact map the fixed points read) — so each
role carries fields the other never sets. Splitting the composition
result into its own type makes each unrepresentable.

## Claim-specific source dependencies

Canonical closure equivalence is not raw-source identity. For example,
`closure/observability.go`'s `flagRegistrationFacts` embeds the registration's
line and column in its persisted refusal. Inserting a blank line before
`register` in `closure/fixtures/flagregescape/flagregescape.go` does not move
the canonical production closure used while analyzing `flagregdep.TestProd`,
but changes the freshly derived diagnostic. A memo keyed only by canonical
core plus compartment can return the older position. This is a source-level
payload-dependency mismatch, not a reproduced verdict flip.

The implementation needs sufficient source identity for such cached output,
or it regenerates source coordinates outside the memo from the current
coherent snapshot. Its deciding regression compares cold, warm and discarded
memo answers across the layout-only edit, retaining the public closure's
deliberate equivalence. The dependency repair precedes the broader mechanical
folds so those folds cannot preserve an incomplete identity by accident.

Lands: docs/plans/tooling-redesign.md 3.2a for payload dependencies; 7.8 for
the remaining memo/read-path/derivation-result folds (retained charter 203).
