# Refined batch checking couples subjects across packages on load failure

Lands: when refined batch analysis degrades a package-local load or analysis
failure to subject-local unavailable evidence the way the observability tier's
per-subject isolation retry does.

## Observed

A missing subject root now degrades subject-locally in `ComputeBatch`, but a
package-local *analysis failure* — a package that fails to load, or an
ambiguous-subject-roots error — still fails the whole refined request: the view
marks every drifted subject `Unverifiable "refinement unavailable"` even when
the failing package is unrelated to theirs, and the closure-level batch error
propagates outright. The observability tier already isolates this class: on a
batch error it retries each subject independently so a failure reached only by
one subject can never deny a sibling's proof.

Both outcomes are in the safe direction (unverifiable, never a false valid),
but the two precise tiers disposition the same package-local fact
inconsistently, and healthy-package subjects lose analysis they would receive
independently.

## Resolution

Give the refined tier the same isolation the observability tier has: on a
batch analysis failure, retry per subject (or degrade per package group) so
only subjects of the failing package receive unavailable refined evidence, and
sibling packages' subjects analyze normally.
