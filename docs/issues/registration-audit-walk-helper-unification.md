# Three break-walks and three literal-element walks in one audit

The chunk-83 review counted the duplicated shape-walk logic in the
environment-free registration audit: three near-identical
break-walks (breakTargets, breakReachIn, and the deep-write arm's
inlined copy), three composite-literal element walks with the same
key/value unwrapping (linkBacking's arm, classifyLit, free's arm),
and classifyArg's shape switch mirroring linkBacking's. One
`breakIdents(expr, gate)` helper and one literal-element iterator
would collapse them; the resolver-side duplication was already
collapsed in-chunk (resolveEnvAudit). Behavior-preserving refactor —
the walks differ only in their gates and targets.

Lands: with cross-tool train chunk 106 (the next gofresh audit-plane
chunk; redefer at its triage if 106's scope lands elsewhere).
