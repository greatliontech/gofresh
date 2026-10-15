# The generated-proto descriptor discharge is gated on the single-subject attestation alone

Measured 2026-10-05 at stipulator chunk 309's close: a cold check over
tugboat c6685f1 under the package-process attestation refused 100 of
its 1,098 witnesses on one dynamic-state culprit —
`transport/grpctransport/transportpb.File_transport_grpctransport_transportpb_transport_proto
is mutated` — a protoc-gen-go descriptor under the audited runtime
(google.golang.org/protobuf v1.36.11, google.golang.org/grpc v1.82.1).

The generated-proto cluster is admitted only under the single-subject
attestation: `generatedProtoOut` (dynamicstate.go) returns false unless
`singleSubject`, and REQ-closure-shared-dynamic-state-audited-discharges places the
cluster as "the directive's generated-file sibling … under the caller's
attestation". The cluster's own argument, as the spec states it, is
content-invariance: the audited runtime builds the descriptor once at
initialization and fills it lazily as a function of the compiled-in schema.
That is the basis to investigate package-process eligibility, not by itself
permission to discard the contract's attestation gate. Establish that shared
population, exposed aliases, writes and observable runtime behavior preserve
the admitted property before widening the discharge. The generated-file
channel already covers both own-code and dependency files under its existing
single-subject and audited-runtime prerequisites.

Decide and enforce the package-process refinement from that proof, retaining
the audited runtime/version and generated-header boundaries and recording
the authority actually used. Until then the existing refusal stands. The
in-module descriptor report is another instance of this same residual, not
a reason to extend dependency vouches to mutable-local state.

Lands: docs/plans/tooling-redesign.md 7.8.
