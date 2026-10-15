# In-module generated descriptors: the package-process discharge residual

Historical report from tugboat (2026-09-30).

Observed: after tugboat collapsed its own shared status-error var
(the errInboundClosed escape, restructured to a per-call constructor),
the next shared-dynamic-state culprit on every grpctransport witness
(~100 subjects) is the generated protobuf descriptor:
`transport/grpctransport/transportpb.File_transport_grpctransport_transportpb_transport_proto
is mutated (dischargeable by restructuring the state, or by the
//gofresh:single-subject directive on the declaration under the
caller's single-subject attestation)`. The writes are protoc-gen-go's
generated init exactly: the descriptor assigned from the type builder,
the message-info slice its builder fills, the go-types and dep-index
tables cleared after use — once, at package init, by nothing
afterwards.

Tugboat also reported adding four generated variables to its policy and
vouch files without changing the refusal. That is consistent with the vouch's
dependency-only scope, not evidence that in-module generated state has no
channel. REQ-closure-shared-dynamic-state-audited-discharges and
`dynamicstate.go`'s `generatedProtoOut` already discharge recognized own-code
and dependency generated descriptors under the single-subject assertion and
the audited runtime versions. The generated header is the regeneration-stable
source leg; a hand-written directive is not required for that channel.

The residual is the package-process case tracked in
`generated-proto-discharge-single-subject-only.md`. Establish its shared-state
and alias argument before extending that discharge. Do not extend local
vouches or treat any generated marker as a generic init-once proof. Preserve
this report's original attempted vouches and refusal as historical evidence,
not as a current reproduction of a missing in-module channel.

Lands: docs/plans/tooling-redesign.md 7.8.
