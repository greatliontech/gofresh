# The audited-pure set and the two strategy versions that must move with it are three edits

Widening the audited-pure package set changes what the per-file effect
scan and the walk tiers admit, so a widening must move
`effectScanStrategy` (the persisted scan's memo scope) and
`ObservationRTA` (the recorded proof's strategy) together with the set.
Nothing couples the three: the math/big admission moved the set and
`ObservationRTA` and left `effectScanStrategy` behind until review
caught it — a warm consumer store would have served scans computed
under the narrower set, refusing every subject of a package the
widening admitted, while a cold store admitted.

The collapse: derive the versions from the set — a digest of the audited
sets (internal/auditset's tables and the package set) folded into both
memo scopes, so an edit to a table cannot land without moving every
scope that consults it; or one `auditedSetVersion` constant that both
strategies compose, with a test that the constant's history matches the
tables' (the weaker rung). Invariants preserved: REQ-closure-effect-
scan-memo's "any change that can move an effect set bumps it";
REQ-closure-observability-analysis's "widening rides the
strategy-version bump".

Lands: the next widening of an audited set, or with the next change to
either strategy version.
