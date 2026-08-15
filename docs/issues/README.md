# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[explain-chain-unpinned-clauses](explain-chain-unpinned-clauses.md)** — REQ-explain-chain's
  link-order and edge-terminated-chain clauses have no pinning witness, and
  REQ-explain-bounded's deferral-arm bound is unexercised end-to-end; all are
  example-pin extensions of the existing fixture family. *Lands: cross-tool train chunk 16.*
- **[fresh-mutation-in-module-scratch](fresh-mutation-in-module-scratch.md)** — the
  fresh-mutation proof admits only `testing.TempDir`-rooted scratch; widening the
  capability source to in-module `MkdirTemp`/`CreateTemp` would make disciplined
  in-module scratch recordless with no caller declaration, the declaration-free
  complement to the enforced scratch namespace.
  *Lands: cross-tool train chunk 16.*
