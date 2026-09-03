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

Lands: when a third per-file derivation is memoized or the fold's read
paths are next changed (the per-directory memo and the read path), and
when the dynamic-state derivation is next changed (the result type).
