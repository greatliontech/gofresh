# Consumer bindings judge served knob strings by grammars of their own

REQ-guidance-single-source says a consuming repo's binding compares
each served knob string with the projection — the package's
served-bytes judgment (`Document.Served`) its form — never through a grammar
of its own. Stipulator has adopted that judgment. Pew's
`cmd/pew/guidance_test.go` still compares against local `cliUsage` and
`firstClause` grammars (the latter decrements parenthesis depth unguarded
where Clause floors at zero).
gomutant's two bindings compare the served string with the projection
directly — the property itself, conformant; Served is the one form
available to them.

The repair: each binding reads Document.Served over the strings the
face serves (the usage on the CLI, the clause on the MCP) and keeps its
literal anchors (a few knobs pinned to literal strings) as the
independence belt stipulator 169 established — the grammars delete.

gomutant needs nothing: its direct comparison is the property; Served
is available to it, not owed.

Pew already calls the shared Coverage lint. Coverage enumerates names and
checks default spellings; that adoption does not remove these separate
served-string grammars.

Lands: docs/plans/tooling-redesign.md 5.6.
