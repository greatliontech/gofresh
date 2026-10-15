# Three per-file memos with one load-serve-pend-merge shape

`closure/filememo.go` and `closure/canonical.go` carry three
persistent per-file memos — the effect scan, the compartment ledger
parse, and the canonical member digest — each with its own complete
dependency key and scope. The compartment payload also names its source
member: identical bytes in `a_test.go` and `b_test.go` cannot share a
name-bearing ledger answer. Each memo is
written as its own load-on-first-use, serve-from-store-or-pending,
record-pending, merge-on-flush block (`fileScan`/`recordFileScan`,
`variantParseMemo.Parsed`/`Record`, `canonicalFileDigest`, and the
three arms of `flushFileMemos`). Shared load, pending-entry and merge
mechanics can hold that discipline once, while each caller supplies its
complete payload-specific key, including the compartment member filename.
A same-bytes/different-name regression must retain distinct declaration and
header filenames. Invariants preserved: a hit is
byte-equivalent to recomputation (REQ-closure-effect-scan-memo,
REQ-closure-test-variant-ledger, REQ-closure-canonical-member);
a pass's misses merge once per package directory; the persisted-scan
count.

Content, admission-policy and source-position dependencies are already part
of the current memo boundaries. The residual is parallel memo mechanics,
not permission to replace those boundaries with one incomplete common key.

Lands: docs/plans/tooling-redesign.md 7.8.
