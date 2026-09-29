# stipulator check red on three requirements (fleet sweep 2026-09-28)

The weekly fleet sweep's `stipulator check` over this repo returned its
first verdict since the sweep began (every earlier sweep's gofresh
check ended NOT MEASURED — the 3600 s budget, or a cancelled execution
phase), and it fails:

- violation: REQ-fresh-fingerprint-data is red and no gap excuses it
- violation: REQ-fresh-observation-data is red and no gap excuses it
- violation: REQ-guard-buildconfig is red and no gap excuses it

The rows file behind the report (45 rows) carries no stale-pin or
broken-witness row for the three — only the violation lines — so the
check's summary view does not say which binding turned each red.
Undiagnosed. The tree the sweep measured is HEAD `b34f15cf` (the
chunk-279 landing plus plan and issue commits; nothing has landed
locally since 2026-09-22). The likely proximate is in the reflog:
between the last attempted verdict and this one, chunk 274 published
the fingerprint's record form as its own wire form ("the fingerprint's
record form is its own — one wire form"), chunk 265 moved every
engine spawn under an installed runner, and chunk 279 folded the
refusal clause into the runtime-input identity with
`ToolchainProvenance.Check` returning its sample — the two `fresh-*-data`
requirements bind the record form 274 rewrote, and `guard-buildconfig`
binds the provenance and build-configuration guard 265/279 touched.
Bindings pinned on the pre-274 record shape or the pre-279 provenance
check would go red under exactly these three. But a re-bind is per
requirement with the bound bodies read, never a blanket, and any row
that stays red after re-binding is a genuine regression — the
diagnosis is the first step, not assumed.

The 42 `uncovered` rows beside the reds (bound witnesses classified
example-grade — "no property driver or analyzer call in the bound
body" — across the closure, fresh, guard, guidance, inputs, purity,
and vouch requirements) are pass-class rows the check reports on every
estate; they are context, not this doc's claim.

Scanned: the index and all 44 docs — none tracks this repo's own check
verdict or names any of the three requirements; the consolidation and
design docs (audited-set-versions-decoupled, attestation-keyed-record,
json-record-readers-one-home) touch neighbouring code with no check
row of their own, so the rows here are disjoint from every existing
doc.

Lands: cross-tool train chunk 289 — the diagnosis chunk chartered for this report (2026-09-29 replan); directly after 277 in the lane, before the fourth re-audit band
