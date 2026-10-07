# Source hashing and index traversal have cancellation gaps

Lands: cross-tool train chunk 315 (the source-digest traversal's owner; audit 332).

docs/notes/suite-runtime.md records, from the 2026-09 suite measurement,
that cancellation gaps in source hashing and index traversal "need their
own causal verification before a production change" — a deferral that
lived in the note alone. The traversal keeps walking after its context
ends until the next file boundary; the cost is bounded by one file's
digest today, and the gap is in which call sites check the context
between files. 315 states the check points and pins a cancelled
traversal's exit at the next file boundary.
