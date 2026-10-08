# Consumer bindings judge served knob strings by grammars of their own

REQ-guidance-single-source says a consuming repo's binding compares
each served knob string with the projection — the package's
served-bytes judgment (Document.Served, landed at cross-tool train
chunk 300) its form — never through a grammar of its own. Two
consumers still derive the string with a local grammar and compare
against that: stipulator's internal/cmd/guidance_test.go cliUsage (cuts
only a trailing " (default …)" where the projection strips every one
by depth) and firstClause, and its internal/mcpserver/guidance_test.go
firstClause; pew's
cmd/pew/guidance_test.go cliUsage and firstClause (the latter
decrements parenthesis depth unguarded where Clause floors at zero).
gomutant's two bindings compare the served string with the projection
directly — the property itself, conformant; Served is the one form
available to them.

The repair: each binding reads Document.Served over the strings the
face serves (the usage on the CLI, the clause on the MCP) and keeps its
literal anchors (a few knobs pinned to literal strings) as the
independence belt stipulator 169 established — the grammars delete.

gomutant needs nothing: its direct comparison is the property; Served
is available to it, not owed.

Lands: pew's bump behind gofresh 300 — pew 320, where its grammars
delete (stipulator's deleted at 290r).
