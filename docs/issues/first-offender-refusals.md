# Sibling and CheckBatch membership refusals name only the first offender

`View.Sibling` (view.go, the membership refusal) and `prepareRecorded`
(the kind and membership refusals behind `CheckBatch`) refuse on the
first offending subject, and `prepareRecorded` iterates a map, so which
offender a caller sees is nondeterministic across runs. The construction
refusal for unknown subjects now names every offender at once
(`UnknownSubjectsError`, REQ-fresh-preparation); these two are the same
"decided per declaration" shape and should refuse the same way — one
batch-collecting helper, typed errors, deterministic order.

Lands: a consumer narrows a batch by a Sibling or CheckBatch membership
refusal (today none does; stipulator's served resolution narrows by the
construction refusal only).
