# Issues

Parked deferrals. Each entry carries a `Lands:` trigger; the doc is deleted
when its work lands (git holds history).

- **[dotless-module-paths-classified-standard](dotless-module-paths-classified-standard.md)** — isStdImportPath
  treats any dotless first path element as standard-library, so a module named without a
  dot has its whole startup walk silently filtered out and every startup refusal
  (effects and the test-main dispatch widen alike) disabled.
  *Lands: the next gofresh plan.*
- **[one-dispatch-site-classifier](one-dispatch-site-classifier.md)** — the observability
  walks grew five partial implementations of one call-site judgment (classification
  ladders, wrapper-receiver provenance, parameter eligibility, body cuts, diagnostic
  selection); sketch for collapsing them onto one site classifier.
  *Lands: the next gofresh plan.*
- **[startup-effect-precision](startup-effect-precision.md)** — with the subject-tier
  walls down, 99.5% of cerebro's 2,119 subjects still refuse at STARTUP on
  argument-insensitive classifications (fmt.Fprintf into local buffers, math/big and
  fixed-argument time construction, std init closures); measured histogram inside.
  *Lands: the next gofresh plan — this is its charter.*
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
  *Lands: the extension admits in-module minting, or the widening is settled
  infeasible in the runtime-inputs spec.*
- **[runtimeinput-producer-facade](runtimeinput-producer-facade.md)** — stipulator, gomutant,
  and pew hand-assemble the same completed-observation conjunction; pew's first copy diverged
  on env fidelity before review caught it; a runtimeinput facade would collapse all three.
  *Lands: the next gofresh plan.*
