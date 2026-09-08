# One culprit-discharge walk

dischargeUnreachableCulprits (per-subject, attested) and
dischargeBinaryUnreachableCulprits (per-package, package-process)
duplicate the culprit walk line-for-line except the proof lookup and
the destination discharge map. One walk parameterized by
(proof, record-destination) collapses both; the recording-prefix
semantics (stop at the first survivor) stay shared by construction
instead of by parallel maintenance.

Lands: 179 (the next reachability-scoping change).
