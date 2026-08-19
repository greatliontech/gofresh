# Dynamic-state strategy version rides no evidence record

`DynamicStateStrategy` keys only the persistent fact cache
(`factScope`, view.go:253). Unlike `ObservationRTA` — which rides
recorded evidence as `ObservationProof.Strategy` and is refused at
check time (view.go:1458) — no `Fingerprint` field carries the
dynamic-state strategy, and no check compares it. A future
dynamic-state bump that changes a VERDICT without moving any
fingerprint field would let stale recorded evidence serve silently
under semantics it was not computed by. Every bump so far has been
verdict-monotone (admissions only) or moved a recorded field
(SingleSubjectDischarges), so no demonstrated path exists today; the
gap is the missing structural twin of the RTA-side guard.

Candidate fix: record the dynamic-state strategy on the fingerprint
exactly as ObservationProof.Strategy, refusing a mismatch at check.

Lands: with the first dynamic-state strategy bump that narrows or
reshapes a verdict for unchanged fingerprint fields — or folded into
the next Fingerprint-surface change.
