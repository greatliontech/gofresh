# a dotless module path classifies as standard library and disables the startup walk

`isStdImportPath` treats any import path whose first element carries no
dot as standard-library. A local module legally named without a dot
(`module probe`) therefore has every one of its functions filtered by
`nonStandardFunctions`: the startup effect walk — recorded effects and
the test-main dispatch widen alike — runs over an empty set, and every
startup refusal silently disappears (observed while probing the
observability-precision plan's chunk 5: identical fixtures flip every
disposition between `module probe` and `module example.com/probe`).
The classification should consult the module graph the Hasher already
lists rather than a path-shape heuristic.

Lands: the next gofresh plan.
