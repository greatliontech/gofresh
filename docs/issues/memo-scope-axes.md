# Memo scope strings are assembled ad hoc in three places

The persistent memos key their entries under a scope string joined by
hand at three sites: the observation pass's fact scope (view.go), the
scan memo's scope (purity.go, fact scope plus the sorted vouch set), and
the closure package's testing-scan and observability scopes
(closure/memo.go). Each site decides which axes it joins; an axis one
memo needs and another omits is invisible until a served entry is
wrong.

Collapse: one scope value with typed axes (strategy version, toolchain,
build configuration, execution attestations, vouches), rendered to the
string once, with each memo declaring the axes it reads — an omission
then fails to compile rather than serving stale facts.

The listing memo adds a fourth site (closure/listingmemo.go), and the
four memos each carry their own Load/Store wrapper pair over the shared
cache-file mechanism — one memo type parameterised by directory and
payload would replace them. Adjacent to the same collapse: the listing
memo's verification and the closure fold's hashFiles read and digest
the same bytes in one pass; a shared path→digest cache holding the full
digest (the fold's) alongside the truncated one would halve the warm
read cost.

Adjacent, same altitude: the dynamic-state derivation's result type
serves two roles — the per-pass state (per-view-package cones,
downgrades, discharge records, culprit inventories) and the per-cone
composition state (the flat fact map the fixed points read) — so each
role carries fields the other never sets. Splitting the composition
result into its own type makes each unrepresentable.

Lands: chunk 154 (the knob-derivation sub-chunk that consolidates the
memo configuration).
