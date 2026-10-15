# Closure sub-contract paragraphs still bundle independently editable rules

The closure mega-requirements were decomposed so that an edit to one
sub-rule re-consents that rule alone and a cite names a rule. The remaining
bundles include
`REQ-closure-shared-dynamic-state-escape-narrowings` (historically about 3,600 words
— object-closed interfaces, init-flow aliasing, leak-free carriers, the
return-position and parameter facts, the registration audit, the
init-flow definition),
`REQ-closure-shared-dynamic-state-audited-discharges` (historically about 1,900 words
— the six audited sets interleaved with the own-code discharges, kept
together so the split reordered nothing), and
`REQ-closure-observability-audited-set` (historically about 1,000 words).
The surviving base `REQ-closure-observability-analysis` also includes the
benchmark-pacing rule. These word counts describe the decomposition report,
not a fresh census. An edit to
any one narrowing re-consents every binding on its paragraph, and a
cite of the paragraph names the bundle rather than the rule.

The cite rule the split follows is one sentence: a comment restating
one sub-rule cites that sub-rule's ID; only a comment about the whole
judgment cites the base ID. Applied once across the production code
when the three paragraphs split, it stops the next editor re-deriving
the boundary.

The split is the same byte-preserving carve at sentence boundaries the
first decomposition used, one MUST elevated per new paragraph, every
binding and cite retargeted through the tool.

Lands: docs/plans/tooling-redesign.md 9.2.

Reconcile every constituent's bindings and wrap-aware citations as part of
the split; no source, evidence or compatibility rule changes merely because
its paragraph gains an identity.
