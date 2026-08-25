# Unlisted-toolchain refusals do not name their cause

On an unlisted toolchain release every toolchain-source admission drops
and subjects refuse with their ordinary classifications ("reaches
unaudited standard operation fmt.Sprintf", ...). gofresh's own suite
gets the named canary (TestAuditedToolchainCoversRunningToolchain), but
a downstream consumer sees only the scatter of generic refusals — the
exact discovery shape the keying was built to prevent, one artifact
short: the refusal reason should name the unaudited toolchain release
so one line of any consumer's output points at the walk needed.

Lands: user decision (a reason-plumb through the classification sites
is its own design; the fleet's provenance guards and the canary cover
the first-party surfaces today).
