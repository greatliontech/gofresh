# Bound persistent memo disk retention

Lands: tooling-redesign 7.9a, before consumer cleanup in 7.9b and 7.9c.

## Evidence and diagnosis

The user's 2026-10-15 disk-pressure report measured `~/.cache/gofresh`
at 16 GiB: `scanfacts` 6.7 GiB, `listing` 4.8 GiB, and
`toolchain-source` 2.8 GiB dominate. Both gomutant and stipulator use
this shared library store. `closure/internal/cachefile/cachefile.go`
publishes content-keyed entries without global retention or collection;
superseded keys accumulate across source/toolchain changes.

This is an operational disk-growth defect, not evidence of an incorrect
freshness verdict. The existing storage contract explicitly makes every
entry disposable: absence, corruption, or failed publication recomputes.

## Required outcome

Provide bounded disk retention and an operator-accessible cleanup path
through the consumers, with one shared implementation for these memos.
Report usage and reclaimed/skipped bytes. Preserve the distinction between
evicting an optimization and judging evidence stale: eviction changes cost,
never the verdict. Do not introduce calendar-based freshness judgments.

Collection must tolerate concurrent reads/publication, preserve active
temporary writes, and handle obsolete memo versions and abandoned keys.
Document the retention controls and cold-analysis cost. Exercise eviction,
concurrent publication, unreadable entries, and recomputation equivalence;
demonstrate the configured disk bound under repeated key churn. Numeric
defaults must be justified by measured store sizes and refill costs.
