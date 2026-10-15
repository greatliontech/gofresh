# The memo layer's remaining collapses: one per-directory memo type, one read path, one derivation result type

The per-file memos (file scan, compartment parse) are one
load/serve/record/flush shape written twice over a per-directory entry
(closure/filememo.go); a generic per-directory memo type would collapse
them and align with the observability memo's merge discipline. Beside
them, five file-read paths exist — the Hasher's once-per-call read, the
listing record's derivation, the cgo include walk, the bare per-file
scan, and the compartment's own source — three of them digesting the
bytes the fold digests; one read path per pass is the collapse.

Adjacent, same altitude: the dynamic-state derivation's result type
serves two roles — the per-pass state (per-view-package cones,
downgrades, discharge records, culprit inventories) and the per-cone
composition state (the flat fact map the fixed points read) — so each
role carries fields the other never sets. Splitting the composition
result into its own type makes each unrepresentable.

The selected content, admission-policy and source-spelling identities have
already been completed for the affected memo claims. Preserve them in these
mechanical folds: a shared container does not imply a shared dependency set.

The closed toolchain-audit work also left its proposed per-judged-run standard
source digest memo unresolved. Current content reads are part of establishing
each generation, not merely waste. Measure repeated digest cost under 7.7
before choosing reuse within an owned immutable generation; never share an
answer across source generations on a version label, pathname or operation
name alone. This is a cost question, not an already-demonstrated retention bug
or a mandate to implement the previously proposed memo.

Lands: docs/plans/tooling-redesign.md 7.8.
