# Explain: verdict derivation chains

Every refusal gofresh emits is the end of a derivation the analysis
walked; explain makes that derivation an observable result instead of
an internal state. The capability exists for the working loop —
agents and tools diagnosing a refusal must reach its full chain
through one call, never by instrumenting the library.

**REQ-explain-chain** (behavior): Given a view and a dynamic-state
culprit — a package path and variable name a verdict's reason names —
the explain surface MUST return the culprit's derivation chain: the
culprit arm (mutation, writable escape, or environment audit), and
per arm the sites that decided it. An environment-audit chain names,
in order, the registration store site, each unresolved dependency
edge (caller package and function to callee package and function),
and for the first function whose proof failed, the innermost refusing
expression with its position and the spec clause family that refused
it, one of the closed clause set: "write or capture broke the
binding", "a binding source refused", "a stored value refused",
"callee outside the audited set and dependency channel", "a literal
element refused", "an unadmitted derivation shape", or "an
unrecognized return shape". A registration naming the culprit lands
from any package, own or foreign - the chain's store and edge links
name the registering package. A
mutation or escape chain names the deciding site with its position.
An escape or mutation decided at composition — a deferred call
argument, a deferred method use, or a field-position use whose
resolvent no fact proves — names the deferring use site as its
deciding site and carries the unproven resolvent (the callee
parameter, the method, or the field position, with the unproven
registrant parameter when one decided the population), its clause one
of the deferral clause set: "a deferred argument's parameter
unproven", "a deferred method use unproven", "the registered
population refused the field position". The deferral resolves over
the same composed proof state the verdict used.
Chains describe refusals; a Valid verdict has no chain, a
registration whose every dependency edge resolves contributes none,
and a deferral every fact proves contributes none. The one exception
is a vouch-discharged variable: its chain still derives on request —
the vouch suppresses the verdict's downgrade, never the derivation a
caller audits (REQ-vouch-recorded).
An environment-audit refusal that is the fixed point of a dependency
cycle, or whose callee lies outside the loaded scope, has no single
refusing expression: its chain ends at the edges.

**REQ-explain-vocabulary** (behavior): Chain links MUST name their
refusal in the closure contract's vocabulary — the clause families
this spec suite defines — never in implementation identifiers.
Positions are file and line in the analyzed source.

**REQ-explain-bounded** (behavior): A chain MUST be bounded: link
counts are capped with the omitted remainder counted, and the deepest
link — the innermost refusing expression or the first unresolvable
edge — is never among the omitted. A truncation is never silent.

**REQ-explain-passive** (behavior): The normal analysis path MUST NOT
construct chains: explain re-derives on demand against the same view,
and a run that never asks for a chain performs no chain work.
