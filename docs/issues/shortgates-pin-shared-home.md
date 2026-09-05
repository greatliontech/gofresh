# The fast-tier gate pin's consumers still carry their own copies

The checker that keeps every `-short` gate a skipping statement of a
Test/Fuzz body and out of fixture strings lives in gofresh as the
exported package `github.com/greatliontech/gofresh/shortgates`, whose
`Pin(t, root)` is the one call a repository's partition collapses to;
gofresh's own root pin is that call, and stipulator's and gomutant's
are too. pew still carries a byte-identical copy of the former checker
in its `shortgates_test.go`; it collapses to the call at its bump to
the gofresh release that carries the package.

Lands: pew's bump — cross-tool train chunk 157, gofresh
docs/plans/cross-tool-train.md.
