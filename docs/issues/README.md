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
- **[one-dispatch-site-classifier](one-dispatch-site-classifier.md)** — the observability
  walks grew five partial implementations of one call-site judgment (classification
  ladders, wrapper-receiver provenance, parameter eligibility, body cuts, diagnostic
  selection); sketch for collapsing them onto one site classifier.
  *Lands: startup-effect-precision plan, per each doc.*
- **[explain-chain-unpinned-clauses](explain-chain-unpinned-clauses.md)** — REQ-explain-chain's
  link-order and edge-terminated-chain clauses have no pinning witness, and
  REQ-explain-bounded's deferral-arm bound is unexercised end-to-end; all are
  example-pin extensions of the existing fixture family. *Lands: when the explain
  surface next changes, or with the chunk that extends the explain test surface.*
- **[observation-facts-struct](observation-facts-struct.md)** — newView, View.Sibling, and
  newSeededValidationView hand-build near-identical View literals around the same immutable
  observation facts; extracting the facts into one mutex-free struct makes read-only sharing
  structural and collapses the three literals (and possibly viewObservation) into one shape.
  *Lands: user decision.*
- **[fresh-mutation-in-module-scratch](fresh-mutation-in-module-scratch.md)** — the
  fresh-mutation proof admits only `testing.TempDir`-rooted scratch; widening the
  capability source to in-module `MkdirTemp`/`CreateTemp` would make disciplined
  in-module scratch recordless with no caller declaration, the declaration-free
  complement to the enforced scratch namespace.
  *Lands: a field measurement shows the flow discipline admits real bench
  scratch shapes.*
- **[runtimeinput-producer-facade](runtimeinput-producer-facade.md)** — stipulator, gomutant,
  and pew hand-assemble the same completed-observation conjunction; pew's first copy diverged
  on env fidelity before review caught it; a runtimeinput facade would collapse all three.
  *Lands: startup-effect-precision plan, per each doc.*
