# Plan: evidence-tier collapse — one capture, one check, no tier verbs

Spec: `docs/specs/` (overview.md and closure.md for the freshness
contract and the hierarchical check; runtime-inputs.md untouched).
Removes the caller-facing maximal/refined verb split: the contract is
"serve iff provably equivalent", tiers are internal proof strategies,
and the only surface is an optional refinement budget (zero default —
today's behavior). Every chunk runs the adversarial loop and both
corpora stay green.

- [ ] 1. Spec: one capture/check surface; refined evidence rides the
  record when the view carries a refinement budget; the check is always
  hierarchical; a strategy choice can never invalidate a record
- [ ] 2. API collapse: Refined verbs deleted from Engine and View
  (clean break, pre-v1); Check/CheckBatch subsume hierarchical
  checking; WithRefinementBudget option gates refined capture
- [ ] 3. Consumer migration: stipulator to the collapsed surface;
  corpus gates green in both repos
- [ ] 4. Refinement open-world re-measurement on the Observer sample
  (now locally available) under the shared-dynamic-state narrowing,
  driven through the collapsed surface; disposition of
  dependency-heavy-refinement-precision per its own acceptance bar
- [ ] 5. Final sweep + close-out gate: full suites, race, releases,
  corpus double-checks green, plan deletion
