# Attestation-keyed discharge record

Two execution-model attestations now mean two option fields, two
factScope markers, two evidence fields (SingleSubjectDischarges,
PackageProcessDischarges), two observationFacts maps, two pairing
checks, and two entries in View.Sibling's fact copy. The Sibling copy
omission that reached a consumer e2e before any gofresh test
(the packageProcessDischarges carry, fixed with the whole-fingerprint
sibling-equality pin) is the demonstrated cost of the per-field
plumbing. A common record keyed by positive execution-model assertions could
carry those facts once while preserving the published evidence fields and
each assertion's distinct authority. This is a consolidation candidate, not
an instruction to manufacture another assertion or rewrite historical support.

Lands: docs/plans/tooling-redesign.md 7.1.

The plan owns the two-mode consolidation judgment. A future third positive
attestation makes the expansion question concrete only if such a capability
is actually introduced. `GeneralExecution` is the absence of these positive
assertions, not a third assertion and not a reason to add another discharge.
