# explain answers "not a culprit" for a culprit the check refused

Measured 2026-10-05 at stipulator chunk 309's close over tugboat
c6685f1: the check refused 100 witnesses on
`transport/grpctransport/transportpb.File_transport_grpctransport_transportpb_transport_proto
is mutated`, and `stipulator explain --package
github.com/greatliontech/tugboat/transport/grpctransport/transportpb
--symbol File_transport_grpctransport_transportpb_transport_proto`
over the same tree, store and binary answered "no chain — … is not a
culprit in the policy views" (stipulator's ExplainDynamicState walks
every populated group's engine and view; every one returned an empty
chain).

That historical report remains an exact reproduction question, not a verified
current defect. Its broad diagnosis is refuted by `explain.go`:
`ExplainDynamicState` loads with `packages.LoadAllSyntax | packages.NeedModule`,
and `explainCulprit` visits the loaded graph, collecting module-owned
dependencies as well as roots and re-deriving their facts with hooks. It does
not simply omit every dependency or answer only from cached dependency facts.

Reproduce the named descriptor with the same selection, assertions and source
generation on both paths. Compare the deciding culprit facts and explanation
hooks, including composition-time decisions. REQ-explain-passive permits the
ask to describe a later tree, so matching a historical verdict's name alone
does not establish an explanation defect in the current tree.

Expected: a chain for every culprit a verdict names, or a refusal
naming a demonstrated reason none derives. Do not replace the missing chain
with the disproved claim that dependencies lie outside the re-derivation.

Lands: docs/plans/tooling-redesign.md 8.3.
