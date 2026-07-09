# Purity assertions

The unverifiable verdict is conservative on purpose: a subject that reads a fixed
fixture file in setup reaches an unverifiable dependence and is refused reuse, even
though that read never changes its behavior. A purity assertion is how the author
recovers reuse — taking responsibility that a named dependence is behavior-irrelevant.
gofresh never infers purity; it accepts an assertion as input and records it as an
explicit act.

**purity assertion** (term): a caller's or author's declaration that a subject's
unverifiable dependence is behavior-irrelevant, overriding that subject's unverifiable
verdict at the declarer's responsibility.

**REQ-purity-input** (structural): gofresh MUST accept a purity assertion as an input
to freshness evaluation, a predicate over subjects, so that a whole-run assertion and
a per-symbol one reduce to the same engine input and gofresh itself never decides
purity — the mechanism is one, the ways of sourcing it many.

**REQ-purity-override** (behavior): A purity assertion for a subject MUST suppress all
of that subject's unverifiability — both its closure's unverifiable-dependence marker
and its runtime-input manifest's own blind spots — so a subject that only reads a
fixed asserted input can reach valid, while every hashable guard it still has, the
closure hash and the observed-input digest and the toolchain and build guards, keeps
holding and still stales the result on a real change.

**REQ-purity-directive** (behavior): A durable source directive `//gofresh:pure` on a
symbol MUST be honored as a purity assertion for that subject by every consumer of the
engine — so purity is a property of the code, written once and respected by every tool
that shares the engine, rather than a per-tool invocation flag re-applied for each,
with a caller's global assertion remaining available for a whole-run override.

**REQ-purity-responsibility** (behavior): A purity assertion MUST be recorded as an
explicit, attributable act, gofresh never silently assuming purity — so overriding an
unverifiable verdict is always the declarer taking responsibility, visible in the
record, never a hidden default that could mask a real external dependence.
