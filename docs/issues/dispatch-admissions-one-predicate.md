# The dispatch admission has two encodings at the walk's computed-call site

`closure/analyzer.go`'s scanCall grants the dispatch admission by two
routes: `resolved` (the site RTA-resolved, the world closed, the operand
subject-closed) and the subject-determined invoke admission
(`subjectDeterminedInvokes`, which additionally requires every
enumerated target to be an indexed, non-test-main function — the
clause REQ-closure-observability-analysis states as part of the
admission). The `resolved` route admits on operand provenance alone.
The chunk-124 rider widened the operand class reaching the `resolved`
route (a callee's parameter now crosses for every subject), so the two
encodings judge more sites differently than before. No reachable
witness of a wrong verdict: a test-main-package target would need the
scan's test-main early return to hide an effect at a subject-flow
invoke, and `scanFunction` cuts those frames on the caller side.

The collapse: one predicate over (site, operand, targets) consulted
by both the computed-call and the invoke arms, with the target-class
clause stated once. The narrowed dispatch added a third route beside
the two — the operand's collected functions resolving the site by
themselves (`heldKnown` in scanCall, `narrowedTargets` at the loops)
— so three encodings now grant one admission.

Lands: with docs/issues/invoke-targets-narrowed-by-operand.md — the
invoke form's narrowing is where the computed-call and invoke arms
must meet in one predicate.
