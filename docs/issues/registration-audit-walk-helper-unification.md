# Three break-walks and three literal-element walks in one audit

The registration-audit review recorded duplicated shape-walk logic in the
environment-free registration audit: three near-identical
break-walks (breakTargets, breakReachIn, and the deep-write arm's
inlined copy), three composite-literal element walks with the same
key/value unwrapping (linkBacking's arm, classifyLit, free's arm),
and classifyArg's shape switch mirroring linkBacking's. One
`breakIdents(expr, gate)` helper and one literal-element iterator
would collapse them; the resolver-side duplication was already
collapsed (`resolveEnvAudit`). Share the traversal only after checking each
walk's gates and targets; the intended change preserves their distinct proof
conditions and fail-closed defaults.

Lands: docs/plans/tooling-redesign.md 7.8.
