# Sibling and CheckBatch membership refusals name only the first offender

`View.Sibling` (view.go, the membership refusal) and `prepareRecorded`
(the kind and membership refusals behind `CheckBatch`) refuse on the
first offending subject, and `prepareRecorded` iterates a map, so which
offender a caller sees is nondeterministic across runs. The construction
refusal for unknown subjects now names every offender at once
(`UnknownSubjectsError`, REQ-fresh-preparation); these two are the same
"decided per declaration" shape and should refuse the same way — one
batch-collecting helper, typed errors, deterministic order.

Lands: docs/plans/tooling-redesign.md 5.2c.

The obligation is already live in REQ-fresh-preparation: an unknown-subject
batch refusal names every unknown subject once in request order. It is not
conditional on a future consumer narrowing a batch. Preserve the separate
kind/shape refusal precedence when consolidating membership collection; a
map-backed request still needs a deterministic account of its full set.
