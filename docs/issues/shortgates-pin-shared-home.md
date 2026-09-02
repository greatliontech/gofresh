# The fast-tier gate pin exists as three byte-identical copies

`shortgates_test.go` — the checker that keeps every `-short` gate a
skipping statement of a Test/Fuzz body and out of fixture strings —
is the same text in gofresh, gomutant, and stipulator, with only the
package clause differing; one fix has already been replayed three
times (the string-literal arm, the closure rule). The shared home is a
small exported package in gofresh (the dependency both consumers
already carry), each repo's pin collapsing to a call. It waits on a
gofresh release the consumers bump to, which Band P's first chunk
makes.

Lands: cross-tool train chunk 154's release (gofresh
docs/plans/cross-tool-train.md), the consumers bumping in 155 and 156.
