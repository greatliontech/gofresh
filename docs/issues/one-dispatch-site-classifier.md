# five parallel dispatch/effect classifiers should collapse to one site classifier

The observability walks grew five partial implementations of one
judgment — "what does this call site dispatch, and is its provenance
attributable":

- `scanCall`'s classification ladder (classB → unaudited fallback →
  OpenFile/syscall arms → harness admission → wrapper-receiver widen)
  and `recordDirectCallEffect`'s startup cascade duplicate the ladder
  minus the admission and file-handle arms, drifting one arm at a time.
- The wrapper-receiver judgment appears twice with only the closed-value
  walk differing: the subject arm (subjectClosedDynamicValue) and
  `testMainDispatchClosed` (locallyClosedDynamicValue).
- `subjectClosedParameter` re-derives `freshParamAnalysis.paramEligible`'s
  refusal set (dynamic targeting, free variables, variadic, zero callers)
  and mirrors `paramArgFreshMemo`'s all-sites loop without its memo.
- `scanFunction`'s std body-cut disjunction is a growing category
  (file-I/O kinds, atomic observability operations, harness logging).
- The legacy single-reason projection selects incrementally in
  `recordExternalEffect` while the proof refusal selects post hoc over
  the sorted projection; one post-hoc derivation over the effect set
  could serve both and unify their tie rules (projection order vs
  lexicographic), and the two order-independence test scaffolds would
  merge with it.

Sketch: one site classifier owning (a) callee classification (the
classB ladder, shared by subject and startup tiers), (b) dispatch-shape
resolution (direct invoke, computed call, synthetic interface-method
wrapper with its receiver extraction), and (c) provenance judgment
parameterized by the closed-value walk (fp-aware or local projection) —
with the tier-specific consequences (record, admit, widen) left at the
call sites. Invariants preserved: walk-end classification, startup
uniform blocking, the harness admission's target-set and provenance
bounds, batch equivalence. Deletes: recordDirectCallEffect's cascade,
testMainDispatchClosed, the duplicated eligibility checks.

Lands: startup-effect-precision plan chunk 8.
