# Three per-file memos with one load-serve-pend-merge shape

`closure/filememo.go` and `closure/canonical.go` carry three
persistent per-file memos — the effect scan, the compartment ledger
parse, and the canonical member digest — each keyed by (package
directory, byte digest) under its own strategy+toolchain scope, each
written as its own load-on-first-use, serve-from-store-or-pending,
record-pending, merge-on-flush block (`fileScan`/`recordFileScan`,
`variantParseMemo.Parsed`/`Record`, `canonicalFileDigest`, and the
three arms of `flushFileMemos`). One generic memo — a
`fileMemo[T]{dir string; scope func() string; entries, pending
map[string]map[string]T}` with `serve(dir, digest)`, `record(dir,
digest, T)`, `flush()` — would hold the discipline once, the three
memos being three instances with their payload types, and
`flushFileMemos` one loop. Invariants preserved: a hit is
byte-equivalent to recomputation (REQ-closure-effect-scan-memo,
REQ-closure-test-variant-compartment, REQ-closure-canonical-member);
a pass's misses merge once per package directory; the persisted-scan
count.

Lands: cross-tool train chunk 203
