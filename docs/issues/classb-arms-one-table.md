# The class-B classifier is nine per-package arms beside a gate

`closure/effects.go`'s classBEffect classifies effect-bearing standard
operations through per-package `if pkgPath == …` arms (fmt, os, syscall
and x/sys/unix, testing, net, net/http, the templates, plugin,
crypto/rand), gated on classBPackages so that the maximal tier's
dot-import backstop and the classifier read one package set. The gate
makes a disagreement unrepresentable while it exists, but its
deletion is not test-distinguishable — no arm for an unlisted package
exists to disagree — so the guard rests on review, the weakest rung.

The collapse: one table keyed by package then symbol → effect kind
and reason (an `internal/auditset`-style table beside the pure and
symbol sets), consumed by one lookup; the package set IS the table's
keys, the gate disappears with the hazard, and a widening is a row.
Two candidates ride the same window: the entropy class joining
`stdBodyCut` (a crypto/rand body is complete at its call site exactly
as a classified file read is; the walk today descends into
crypto/rand.Read and records its linkname as a linkage effect — a
recorded-effect move owing its own ObservationRTA bump), and whether
entropy deserves its own effect kind rather than riding Native (the
shared rank is what lets an entropy read outrank an ambient input in
the same file).

Lands: with the next change to classBEffect's own arms — the
classifier's effect table, not the pure-side symbol tables, which
grew three times (reflect's Elem, time's method forms, reflect's
view surface) without touching it.
