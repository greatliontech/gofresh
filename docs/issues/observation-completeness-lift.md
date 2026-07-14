# Completeness lift: assertion-vouched unverifiability needs subject-tier observability

Lands: when a consumer needs unverifiable-by-file-I/O subjects served
from a freshness cache and accepts per-subject (tier2/refined)
analysis cost for them.

The idea: a caller-owned completeness assertion — "the producing
harness observed every file and environment read of the subject's
process" (true of Go's test harness, modulo direct system calls and
foreign code) — recorded in the fingerprint beside the purity
assertion, lifting closure unverifiability when every dependence is
process-observable and the runtime-input guard verifies.
REQ-inputs-evidence-not-proof already leaves the door open ("absent
an explicit completeness proof").

A full implementation was built and withdrawn after adversarial
review proved it unsound as designed. The findings that any future
attempt must clear:

1. **The maximal tier cannot claim observability.** Its per-file scan
   is an existence scan: it stops at the first classified reason,
   selects one reason per package, and parks unclassified
   external-capable imports in a "potential external dependence"
   residue that a classified hit shadows. A forall ("every dependence
   is observable") derived from it admits wall-clock, process-exec,
   and unclassified dependences. Observability is a property only the
   per-subject call-graph tier (tier2 / declaration-RTA refinement)
   can compute — which is the expensive engine (whole-program SSA)
   the witness path avoids today.
2. **The reason taxonomy over-admits mutation classes.** Substring
   "mutation" matches "(path mutation)" (os.Remove/Rename — no
   testlog hook) and direct-syscall creates — the spec's own named
   escape. The observable set must be exact producer suffixes with
   the os-level discriminator, pinned against real producer strings,
   never guesses.
3. **The drifted-refinement path strips dispositions.** Re-attaching
   a maximal unverifiability onto a refined closure must also carry
   (or conservatively clear) observability, or cgo/open-world
   dependences lift through the drift path.

Also required: amend REQ-inputs-evidence-not-proof to license a
recorded caller-owned assertion explicitly (assertion is not proof;
the clauses must agree on which word governs).

The consumer pressure that motivated this (stipulator's witness cache
collapsing to pure-only subjects) is better relieved first by
single-run architecture on the consumer side — the gate consuming the
check phase's outcomes instead of re-witnessing.
