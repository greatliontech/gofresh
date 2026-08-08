# Qualified cross-package stores are never value-audited — audited constructions fail-close

Spurious-refusal direction (never false Valid). The spec's
object-closure clause audits "a direct store the auditing package
resolves to the variable, from any package" for provably-immutable
audited constructions. The implementation value-audits only
identifier-shaped store targets; any selector-shaped target
(`reg.Err = errors.New("configured")` in a sibling package's init —
the ordinary spelling of a cross-package store) routes to the
unattributable-store fail arm and breaks the closure even when the
stored value is an audited construction. Only dot-imported stores
currently receive the cross-package value audit.

Fork for the spec-amend channel (user decides; spec wins by default):

- Default (spec as written): attribute selector-shaped stores — resolve
  the `SelectorExpr` target to the foreign interface package variable
  and run the same value audit as identifier stores.
- Alternative: amend the clause to sanction the current fail-close —
  "a direct store the auditing package resolves to the variable"
  becomes "an unqualified identifier store (dot-import included)".

Lands: startup-effect-precision plan, per each doc.
