# reflect's audited symbols sit outside the shared symbol-table shape

`internal/auditset` holds `reflectSymbols` as a bare `[]string` scanned
by `slices.Contains` through its own predicate `ReflectSymbol`, while
every peer surface admitted by symbol (`timeSymbols`, `urlSymbols`,
`filepathSymbols`, `flagSymbols`) is a `map[string]bool` reached through
`Symbol` and the `symbolTables` union. reflect is admitted by symbol
exactly as they are; the odd shape is why it sits outside
`symbolTables`, outside the disjointness pin against `purePackages` and
the always-external tree, and behind a second consulting predicate
(`auditedRuntimeTypeSymbol` in `closure/maximal.go`) in the
`auditedStandardSymbol` ladder.

The collapse: `reflectSymbols` becomes a `symbolTables` entry; the
`ReflectSymbol` predicate and `auditedRuntimeTypeSymbol` are deleted,
the ladder's class-B arm admitting reflect through `auditset.Symbol`
alone; the exactness pin and the disjointness pin cover the row like
its peers; the bare-name premise (the SSA tiers match methods by name)
moves into the table's doc comment. Invariants preserved: the admitted
reflect names are exactly the audited ones; no reflect name is admitted
through two predicates.

Lands: with docs/issues/classb-arms-one-table.md's collapse (the same
window as flag-surface-one-table), or the next reflect symbol audit.
