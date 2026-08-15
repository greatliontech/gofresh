# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[bracket-declared-static-inputs](bracket-declared-static-inputs.md)** — repo-anchored static
  inputs (go.mod, committed trees, session dot-dirs) defeat observation brackets wholesale:
  1,440 of cerebro's 2,407 uncacheable witnesses; admit declared static inputs and exclude
  non-corpus dot-dirs. *Lands: with the check-view-cardinality fix family.*
- **[purity-bars-dynamic-and-fmt](purity-bars-dynamic-and-fmt.md)** — the caller-supplied-dynamic
  and fmt-taint bars refuse ~955 benign cerebro witnesses; narrow to escaping dynamism and
  sink-keyed fmt taint. *Lands: with the bracket item — the classifier half.*
- **[explain-chain-unpinned-clauses](explain-chain-unpinned-clauses.md)** — REQ-explain-chain's
  link-order and edge-terminated-chain clauses have no pinning witness, and
  REQ-explain-bounded's deferral-arm bound is unexercised end-to-end; all are
  example-pin extensions of the existing fixture family. *Lands: when the explain
  surface next changes, or with the chunk that extends the explain test surface.*
- **[fresh-mutation-in-module-scratch](fresh-mutation-in-module-scratch.md)** — the
  fresh-mutation proof admits only `testing.TempDir`-rooted scratch; widening the
  capability source to in-module `MkdirTemp`/`CreateTemp` would make disciplined
  in-module scratch recordless with no caller declaration, the declaration-free
  complement to the enforced scratch namespace.
  *Lands: a field measurement shows the flow discipline admits real bench
  scratch shapes.*
