# REQ-explain-chain: two clauses have no pinning witness

**Lands: when the explain surface next changes, or with the chunk that
extends the explain test surface.**

The bound witnesses (`TestExplainChains`, `TestExplainDeferralChains`)
exercise the arms, link kinds, foreign-package registration, test
variants, the Valid-verdict empty chain, and the vouch-discharged
derivation — but two normative clauses have no assertion:

- **Link order.** "names, in order, the registration store site, each
  unresolved dependency edge …" — the tests assert link presence, not
  sequence (the mutation-leads case aside). A permutation of the
  emitted links would pass every current assertion.
- **Edge-terminated chains.** "An environment-audit refusal that is the
  fixed point of a dependency cycle, or whose callee lies outside the
  loaded scope, has no single refusing expression: its chain ends at
  the edges." Neither the cycle fixed point nor the outside-scope
  callee shape has a fixture.

Both are example-pin extensions of the existing fixture family; the
cycle shape needs a two-package registration loop, the scope shape a
dependency the loader excludes.

Adjacent, same trigger: **REQ-explain-bounded's deferral-arm bound is
unexercised end-to-end.** The environment-audit return's bound is
pinned by a 30-deep surface derivation, but the deferral/mutation/
escape arm's bound call is deletable with every test passing — no
deferral fixture exceeds the link cap. Needs a fixture producing 25+
deferral observations for one culprit.
