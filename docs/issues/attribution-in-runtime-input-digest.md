# The refusal attribution rides the runtime-input manifest and digest

REQ-inputs-refusal-attribution appends to a classification refusal the
observation that produced the refused path — the operation, its logged
name, and the producing process's own directory. The observation folds
the whole reason, attribution included, into the manifest's unverifiable
entries and into the runtime-input digest (`stateFromManifest` hashes
`"unverifiable <reason>"`), so a machine-local record's manifest and
digest carry the checkout's directory: re-measuring the same tree from
another checkout, or after moving the repository, yields a different
manifest and digest for the same instability, and a consumer comparing
recorded evidence whole — gomutant's attestation pin view keeps
RuntimeInputs/RuntimeDigest/RuntimeReason — sheds every attestation on
the finding. The attribution is diagnostic detail, fresh per measurement
(the clause's own words); the digest is the identity of the inputs'
state, which the directory is not part of.

Derived answer: the manifest and digest fold `RefusalClause(reason)` —
the clause — while the recorded reason keeps its attribution whole for
the readers that reproduce state (a recorded path's resolved target is
part of the evidence gomutant's layer re-check compares whole,
REQ-result-layers). Invariants preserved: a relinked out-of-tree target
still fails the whole-reason reproduction; an exemption record still
matches the clause.

Lands: 279
