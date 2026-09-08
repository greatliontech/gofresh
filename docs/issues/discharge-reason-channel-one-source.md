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

Lands: with the next change to the downgrade reason's composition.
