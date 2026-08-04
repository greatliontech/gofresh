# Fresh-mutation proof does not cover in-module scratch minting

**Lands:** the fresh-mutation observability extension admits
`os.MkdirTemp`/`os.CreateTemp` results rooted in the module tree as
fresh capabilities, or the widening is settled infeasible in the
runtime-inputs spec.

The fresh-mutation extension (REQ-inputs-fresh-mutation) treats a
`testing.TempDir` result as an opaque fresh directory capability and
admits proven-fresh reads recordless — the declaration-free, statically
sound answer to run-scratch noise. `os.MkdirTemp(dir, pattern)` gives
the same freshness guarantee wherever `dir` points (EEXIST-retry
ensures creation), including inside the package directory — the shape
benches use when they must measure the package medium's real fsync
behavior rather than tmpfs. Widening the capability source to
in-module `MkdirTemp`/`CreateTemp` calls whose `dir` argument derives
from the guarded frame identity would make disciplined in-module
scratch recordless with no caller declaration, leaving the enforced
scratch namespace (REQ-inputs-scratch-namespace) as the fallback for
flow the analysis cannot follow (capabilities escaping through
structs, interfaces, goroutines — the extension's existing fail-closed
boundaries).

Scope note: the value is bounded by how much real bench code the flow
discipline admits; the tugboat `node` bench (the motivating field
case) threads scratch dirs through struct state, which today's graph
refuses. Measure admission rates on real consumers before investing.
