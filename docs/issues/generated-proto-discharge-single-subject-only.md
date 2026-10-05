# The generated-proto descriptor discharge is gated on the single-subject attestation alone

Measured 2026-10-05 at stipulator chunk 309's close: a cold check over
tugboat c6685f1 under the package-process attestation refused 100 of
its 1,098 witnesses on one dynamic-state culprit —
`transport/grpctransport/transportpb.File_transport_grpctransport_transportpb_transport_proto
is mutated` — a protoc-gen-go descriptor under the audited runtime
(google.golang.org/protobuf v1.36.11, google.golang.org/grpc v1.82.1).

The generated-proto cluster is admitted only under the single-subject
attestation: `generatedProtoOut` (dynamicstate.go) returns false unless
`singleSubject`, and REQ-closure-shared-dynamic-state's prose places the
cluster as "the directive's generated-file sibling … under the caller's
attestation". The cluster's own argument, as the spec states it, is
content-invariance: the audited runtime builds the descriptor once at
initialization and fills it lazily as a function of the compiled-in
schema. That argument binds no execution model — a package-process
binary's lazy fill is the same function of the same schema — so the
single-subject gate is a conservative placement, not a soundness
boundary, and every package-process consumer (gomutant, stipulator)
refuses every witness reaching a generated descriptor.

Expected: the cluster's discharge available under either attestation
(the per-subject reachability judgment is not needed for it; the
runtime audit is), recorded on the evidence as today, with the clause
sentence moved from the directive's sibling to its own channel. The
soundness argument is the spec's existing one; the design of where the
channel sits is 202's (the dynamic-state tier home).

Lands: cross-tool train chunk 202.
