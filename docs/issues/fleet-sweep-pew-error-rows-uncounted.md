# The fleet sweep's pew rows count stale/unrecorded arms but not refused package stores

Field report from tugboat (filed uncommitted in this tree, the
standing channel), 2026-09-30.

`pew status` over tugboat's store refuses five of its nine package
stores at load (an `error <pkg> (store: recording ... carries a line
past benchfmt's scanner bound ...)` row each — pew's own defect,
filed there as loader-refuses-pre-format-3-ledger-lines-remedy-
circular). The sweep's judge logs for 2026-09-21 and 2026-09-28
report "tugboat pew, 10 stale (format). Identical." — the ten
readable stale arms — and nothing about the refused packages, whose
arms contribute no rows at all. A refused package store is the worst
state the whole-store verdict can be in (its arms are neither valid
nor stale — invisible), and the sweep's row file cannot see it.

Expected: the gatherer treats an `error` row (a package store pew
could not load) as its own defect class in the row file and the
judge — a widening, never "identical" — so a store that lost five
packages to a loader change does not read as a healthy ten-stale
store for two weeks.

Lands: awaiting triage.
