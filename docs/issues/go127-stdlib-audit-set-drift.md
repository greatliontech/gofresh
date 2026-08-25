# go1.27 drifts the audited stdlib set — observability proofs flip

Pre-existing at HEAD on go1.27 (worktree-verified e52a804, found
2026-08-25 while landing an unrelated change set):
TestReadOnlyObservabilityProof fails across ~4 fixture arms in two
directions. Read-only subjects (dyncaller, dyninitcollide) now read
NON-observable with "reaches unaudited standard operation
encoding/base32.EncodedLen" — a go1.27 stdlib path change routes
their closures through an operation the audited set does not carry —
and one observablebad arm flips its refusal REASON ("open subject
world" where the pin expects the unaudited-os.File scan reason),
i.e. the classification order shifted, not just a missing row.

Consequence: under go1.27, freshness evidence degrades
conservatively (subjects read unobservable → uncacheable → judged
runs re-execute) — the safe direction, but it re-opens the
whole-store uncacheability class the fleet just paid down, and the
reason-order flip means consumers' reason-matching behavior can
change.

The fix is the audited-set review this repo already contemplates
(docs/issues/audited-source-set-table.md: one version-keyed table):
walk the go1.27 stdlib delta against the audited operations, key the
set by language series, and re-pin the proof fixtures. The
version-keyed-table collapse and this review are one visit.

Lands: with the go1.27 audited-set review (tool phase; blocks
trusting freshness observability on go1.27 trees — the fleet is
already on go1.27).
