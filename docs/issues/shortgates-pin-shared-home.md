# The fast-tier gate pin's consumers still carry their own copies

The checker that keeps every `-short` gate a skipping statement of a
Test/Fuzz body and out of fixture strings lives in gofresh as the
exported package `github.com/greatliontech/gofresh/shortgates`, whose
`Pin(t, root)` is the one call a repository's partition collapses to;
gofresh's own root pin is that call. gomutant, stipulator, and pew
still carry byte-identical copies of the former checker in their
`shortgates_test.go`; each collapses to the call at its bump to the
gofresh release that carries the package.

Lands: the consumers' bumps — cross-tool train chunks 155
(stipulator), 156 (gomutant), and 157 (pew), gofresh
docs/plans/cross-tool-train.md.
