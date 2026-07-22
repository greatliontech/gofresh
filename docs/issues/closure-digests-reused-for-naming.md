# Validation naming re-reads files the closure tier already hashed

Lands: when the closure tier's own per-file digests flow into the view's
fileDigests, eliminating the second ReadFile+SHA per source identity per
observation and closing the read-to-read attribution window in the same move
(the digests would then come from the exact bytes the compared closure hash
was built over).

## Observed

observeView's digest pass re-reads and re-hashes every source file
moments after closure computation read the same bytes (hashFiles already
computes the identical 32-hex truncated SHA-256 per file and discards it).
Cost: one extra read+hash per identity per observation, including every
validation's fresh observation - a small constant factor against the SSA
analysis, graded acceptable; the attribution window it leaves is best-effort
honest (wrong-naming unreachable, non-causal naming requires in-window
mutation the contract already excludes on the construction side).

## Resolution

Plumb per-file digests out of closure.hashFiles to the observation instead
of re-hashing in view.go.
