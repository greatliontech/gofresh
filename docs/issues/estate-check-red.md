# gofresh's own stipulator estate is red (fleet sweep 2026-08-27)

The sweep's first run found this repo's `stipulator check` failing:
REQ-inputs-fresh-mutation, REQ-vouch-discharge, and REQ-vouch-recorded
red with no excusing gaps. Two mechanisms, both measured:

1. The closure package's WITNESS run times out at the policy's 30m —
   18m inside TestReadOnlyObservabilityProof under the witness
   environment (race detector + the width-capped producer env) while
   the plain suite completes the whole package in ~8m. The witness-env
   cost of the analysis-heavy observability proofs needs its own
   diagnosis: policy timeout, test partitioning, or a real slowdown.
2. 28 stale/uncovered rows: the train's gofresh chunks (callee
   insertions, type-parameter walk, shape corpus) landed reviewed
   content changes without pin re-consent — `stipulator check` was not
   run at those change sets' gates, a process slip this filing makes
   loud. Re-consent is owned work, but per requirement with the moved
   bodies read, never a blind blanket.

Lands: cross-tool train chunk 135 (chartered by this filing).
