# Non-target subtree appearances in audited function bodies break closure over writeless reads

Precision loss, fail-closed direction, introduced with the
audit-every-plain-function widening: the unattributable-store fail arm
fails every interface package variable appearing anywhere in a store's
target subtree. In a graph-proven init-only function, `index[Err] =
name` — `Err` a map key, a provably-writeless read under the carrier
rules — now records an opacity break; before the widening the
(exported, hence unaudited) function left the variable closed and its
escapes discharged. The flip is Valid → Unverifiable and re-refuses
exactly the registration-constructor corpus shape the cross-package
init-only work targets, wherever a registry indexes by a sentinel.

Fork for the spec-amend channel (user decides; spec wins by default):

- Default (spec as written — its precision sentence says a
  never-mutated variable confers no downgrade): narrow the fail arm to
  genuine store targets, discharging provably-writeless appearances
  (map keys, index reads) by the same judgment the carrier read rules
  already encode.
- Alternative: amend the clause to sanction the fail-close — "any
  appearance of an interface variable inside an unattributable store's
  target subtree breaks the closure, wherever it occurs".

Lands: cross-tool train chunk 32.
