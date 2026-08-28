# Walk the dst selection for the toolchain-audit key

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

The ENFORCEMENT landed with the two-axis audit key (train chunk 126):
the admission predicates answer per (release, build selection), a
dst-tagged analysis now refuses every stdlib admission loudly —
announced on the unaudited-toolchain diagnostic face — instead of
inheriting the default selection's audit, and the race selection was
walked and listed in the same change (the audited surface's selected
non-test source is byte-identical under plain -race). What REMAINS is
the dst-selection WALK itself: time/dst_tz.go (the fence-conditioned
zone resolution against the class-B time claims),
testing/dst_hostio.go (the host-stream slot against the harness
channel claims), sync's dst-and-race hook seam, and the os
fault-injection surface (~19k lines: dst_fd.go, dst_root.go,
dst_disk_fault.go and siblings) against the observation producer
model (REQ-inputs-observable-read-set's admitted-wrapper audit and
the completed-observation conjunction). Walking it lists "dst" (and
"dst,race" for the DST legs' actual selection) in
closure/toolchainaudit.go's selections axis, flipping dst-tagged
analyses from loud refusal to audited admissions.

Lands: with the first judged run over a dst-tagged build selection
(tugboat DST-leg campaigns are the first candidate — currently paused
with the tool phase; until then dst-tagged analyses refuse soundly,
so no consumer serves unsound admissions).
