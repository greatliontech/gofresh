# The CLI lint accepts a default form the projection silently drops

REQ-guidance-render's usage projection drops a knob clause's trailing
`(default X)` unconditionally, on the rationale that the flag library
prints the default itself — true only for a flag registered with a
non-zero default. A flag registered zero whose default is derived (a
`<module>/benchmarks` store directory, "the repository's parent") and
spelled in that form loses the fact from the served help: the
projection drops it and the library prints nothing, and the CLI lint
(REQ-guidance-coverage's registration fact) never fires, since it
refuses a spelled default only for a flag registered WITH a printed
default — the exact complement of this set. Measured at pew 275.C:
five knobs (four `bench-dir`, `ab --worktree-dir`) lost their derived
defaults from `--help` at the fold, caught by a reviewer's help dump,
not by the judgment.

The collapse: the coverage judgment refuses a `(default X)` form in
the first clause of a knob registered with a zero default on the CLI
— that spelling is guaranteed to vanish from the served help, so it
is the same class of defect the lint already names for the other
direction; the consumer spells a derived default in the clause's
prose instead (pew's shape: "`<module>/benchmarks` unless given").

Invariants preserved: the lint's fact is still the registration's;
a non-zero default's form keeps being dropped and printed once.

Lands: cross-tool train chunk 184 (the knob-clause chunk behind 266,
where the projection's CLI rules are next reworked).
