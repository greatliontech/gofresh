# A sealed observation cannot adopt or widen a persisted manifest union

Lands: when a consumer needs to merge fresh completed observations into a
persisted manifest union without re-running every contributing process.

## Observed

A consumer that persists a completed-process manifest union and later
re-executes a subset of contributing processes cannot soundly reconstruct the
widened union: observations are sealed at completion and there is no operation
that adopts a persisted manifest as a completed observation or unions fresh
completed state into it. gomutant's candidate-granular evidence splice hits
this: when the re-executed processes' completed union does not equal the
record's persisted union, the spliced finding must be marked non-reusable
instead of carrying a soundly widened union, so a serve that legitimately
observed one additional input costs the whole record's reusability.

## Resolution

Provide a sound union or adoption operation over completed observation state —
one whose result is attributable and whose digest semantics match a fresh
merged observation — or state why sealing must exclude it.
