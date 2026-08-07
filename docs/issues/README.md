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
- **[dotless-module-paths-classified-standard](dotless-module-paths-classified-standard.md)** — isStdImportPath
  treats any dotless first path element as standard-library, so a module named without a
  dot has its whole startup walk silently filtered out and every startup refusal
  (effects and the test-main dispatch widen alike) disabled.
  *Lands: startup-effect-precision plan, per each doc.*
- **[one-dispatch-site-classifier](one-dispatch-site-classifier.md)** — the observability
  walks grew five partial implementations of one call-site judgment (classification
  ladders, wrapper-receiver provenance, parameter eligibility, body cuts, diagnostic
  selection); sketch for collapsing them onto one site classifier.
  *Lands: startup-effect-precision plan, per each doc.*
- **[enumeration-targets-over-approximated](enumeration-targets-over-approximated.md)** — a
  subject-closed dispatch pins its value set exactly, but the recorded target set is RTA's
  whole-mask over-approximation; an init-flow closure of matching signature drags initializer
  content into sibling subjects — spurious refusals, never false valids. *Lands: the next
  gofresh plan, with the startup-effect precision family.*
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
  *Lands: startup-effect-precision plan, per each doc.*
- **[unnamed-external-dependence-verdict](unnamed-external-dependence-verdict.md)** —
  effects added by the unaudited-standard-operation arm never feed the preferred-reason
  selection, so subjects they refuse serve a bare "external dependence" with no package
  or symbol named. *Lands: when the reason selection next changes, or with the first
  field diagnosis blocked on an unnamed verdict.*
- **[func-value-self-capture](func-value-self-capture.md)** — receiver-stored func values
  whose closures capture the receiver read as reach-free, laundering receiver writes
  through proven-read-only bindings; pre-existing Signature-classification hole. *Lands:
  the next gofresh plan.*
