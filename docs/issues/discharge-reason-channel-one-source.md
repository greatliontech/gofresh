# The discharge reason's channel clause is composed at two points

The shared-dynamic-state downgrade's reason — the culprit, the verb
(is mutated, escapes writable), and the discharge channel that names
the remedy — is composed at two points of `composeDynamicState` in
`dynamicstate.go`, each spelling the verb literals and calling
`dischargeChannel` for itself. The channel is a string the composition
derives from the culprit's facts; nothing carried by the discharge
machinery represents it, so a reason naming a channel the engine will
not honor for that culprit is representable, and the two spellings can
drift.

The collapse: one reason composition keyed by a channel enum the
discharge machinery carries with the culprit — the verb literals and
the channel clause spelled once, and a reason naming an unhonored
channel unrepresentable. (The culprit walk itself is one function,
`dischargeCulprits`, since the discharge-walk fold.)

Lands: docs/plans/tooling-redesign.md 7.1.

REQ-fresh-verdict requires structured causes independently of prose. Carry
the deciding channel as a semantic fact and render it once; do not establish
authority by parsing the resulting remedy string. Shared producing adoption
at 5.2c is a secondary constituent of this boundary.
