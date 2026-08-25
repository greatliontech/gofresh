# `-tags dst` build selections are outside the toolchain-source audit key

The audited toolchain releases (closure/toolchainaudit.go) cover the
DEFAULT build selection: the godst deltas in the audited surface (sync,
time, testing) were verified compile-time-dead untagged. A `-tags dst`
analysis selects the live hook bodies — the chatty printer's bubble
output legs, the wrapped testlog writer, the sync/time hooks — whose
audit against the admission bar has not been walked, yet the key
(runtime.Version() membership) cannot see build tags, so a dst-tagged
view is admitted on the default selection's audit. The spec records the
scope ("the audits cover the DEFAULT build selection"; a tag-swapped
selection is outside the key), but nothing enforces it: a consumer
analyzing a dst-tagged test config today gets default-selection
admissions.

The fix is either a tag-aware key (the admission predicates learn the
analysis' build selection and refuse tag sets whose deltas are
unwalked) or a walked dst-tagged audit added to the record with the tag
in the listing. Blocks trusting freshness observability for dst-tagged
legs specifically.

Lands: with the first judged run over a dst-tagged build selection
(tugboat DST-leg campaigns are the first candidate — currently paused
with the tool phase).
