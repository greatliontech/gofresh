# Refined analysis treats a missing subject root as batch-fatal

Lands: when declaration-RTA refinement degrades a missing subject root to
subject-local unavailable evidence the way observability analysis does.

## Observed

A subject whose symbol is absent from its loaded test-binary program's roots —
for example a production symbol that is not a root of a package whose only test
variant is an external test package — degrades to a subject-local unavailable
observation proof in `ComputeObservabilityBatch`, but `ComputeBatch` still
fails the whole request set with `closure: subject X not found in P`.

Consequences: a drifted observed batch check containing one unrootable subject
marks every drifted subject in the batch — including other packages' —
unverifiable with `precise analysis unavailable`, and capturing observed-refined
evidence for an unrootable subject fails outright while observed-only capture
succeeds with an unavailable proof. Both outcomes are in the safe direction
(unverifiable or error, never a false valid), but the two precise tiers now
disposition the same subject-local fact inconsistently.

## Resolution

Give refinement the same subject-local degradation: a missing root yields
unavailable refined evidence for that subject alone, sibling subjects analyze
normally, and the batched check and capture paths stop coupling unrelated
subjects to one unrootable symbol.
