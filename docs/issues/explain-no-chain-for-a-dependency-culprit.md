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

View.ExplainDynamicState "re-loads the view's own package scope — test
variants included — and re-runs the analysis with observation hooks
armed". The descriptor's mutation is not in that scope: it is marked in
the dependency's persisted facts (the generated package and the
protobuf runtime that fills it), and the composition that refuses the
witness reads those facts, not a re-derivation with hooks. So a culprit
declared and mutated outside the view's own packages — the common shape
for a dependency culprit — yields an empty chain, and the surface
reports the culprit the check named as no culprit at all.

Expected: a chain for every culprit a verdict names, or a refusal
naming why none derives ("the culprit is marked in dependency facts;
re-derivation covers the view's packages"), never "not a culprit".

Lands: cross-tool train chunk 241 (explain's seam and hookset key).
