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
of that subject's *inferred* unverifiability — both its closure's
unverifiable-dependence marker and its runtime-input manifest's own blind spots — so a
subject that only reads a fixed asserted input can reach valid, while every hashable
guard it still has, the closure hash and the observed-input digest and the toolchain
and build guards, keeps holding and still stales the result on a real change. An
explicit external-state declaration is not inferred unverifiability and is never
suppressed (REQ-external-precedence).

**REQ-purity-directive** (behavior): A durable source directive `//gofresh:pure` on a
symbol MUST be honored as a purity assertion for that subject by every consumer of the
engine — so purity is a property of the code, written once and respected by every tool
that shares the engine, rather than a per-tool invocation flag re-applied for each,
with a caller's global assertion remaining available for a whole-run override.
Directive discovery uses the same executable build flags as closure analysis: a
directive in a mutually exclusive file not selected into the recorded build cannot
confer purity on the selected declaration. Discovery belongs to the same analysis
view as that declaration's closure, so an old directive cannot override a newly
selected or edited declaration through process-lifetime scanner state. When
production, in-package-test, or external-test variants collapse distinct
declarations onto the same subject identity, capture is refused rather than allowing
one declaration's directive to confer purity on another.

**REQ-purity-responsibility** (behavior): A purity assertion MUST be recorded as an
explicit, attributable act, gofresh never silently assuming purity — so overriding an
unverifiable verdict is always the declarer taking responsibility, visible in the
record, never a hidden default that could mask a real external dependence. The
recorded attribution is empty when absent, otherwise exactly `caller assertion`,
`source directive`, or `caller assertion and source directive`; unknown attribution
values confer no responsibility and cannot override unverifiability.

**external-state assertion** (term): an author's declaration that a subject depends on
state outside every hashable guard, so its results are never reusable on the strength
of those guards alone — the dual of a purity assertion: purity recovers reuse from
inferred unverifiability, externality declares unverifiability outright.

**REQ-external-directive** (behavior): A durable source directive `//gofresh:external`
on a symbol MUST be honored by every consumer of the engine as that subject's
external-state assertion: whenever the subject's guards hold, its verdict is
unverifiable with the reason `external directive`, so a subject the author knows
depends on external state is never reused on hashable guards alone — while a failing
guard still reports stale, externality withholding reuse without ever masking guard
information. Externality survives every evidence tier: a matching declaration-RTA
refinement after maximal drift, and completed observation evidence, still verdict
unverifiable — no finer analysis of the subject's body outweighs the author's
declaration about its environment. Discovery follows the same rules as the purity
directive: the producing build's executable flags select it, it belongs to the same
analysis view as the declaration's closure, and variant collapse onto one subject
identity refuses capture.

**REQ-external-precedence** (behavior): An external-state assertion MUST NOT be
overridden by any purity assertion or observation evidence: a declaration carrying
both `//gofresh:pure` and `//gofresh:external` is refused at observation (the
declarations contradict — one vouches reuse, the other forbids it), a caller's purity
assertion over a directive-external subject confers nothing and records no
attribution, and observation-completeness evidence never upgrades an external
subject's verdict. The contradiction refusal is scoped to declarations yielding the
scan's subjects — the requested packages' declarations and method declarations
promoted into their subjects; a conflicted declaration elsewhere in the loaded graph
is its own package's defect, surfacing when that package is scanned, never bricking
a dependent that cannot fix it. Purity recovers reuse from what the engine could not
verify; it never overrides what the author verified to be external.

**REQ-purity-observation-separation** (invariant): An observation-completeness
assertion MUST NOT be treated as a purity assertion: it vouches that the recognized
harness completed its observations, while the engine's separate observability proof
establishes which reachable effects that stream can cover. It does not suppress
runtime-manifest unverifiability or a closure effect outside the admitted observation
set.
