# Summed resident held sets can count shared pages more than once

Lands: docs/plans/tooling-redesign.md 7.7.

## Source-traced failure mode

A reading taken while a descendant sits between its clone and its exec
counts the parent's held set twice: Go's forkExec clones with
CLONE_VM|CLONE_VFORK, so the child's status reports the parent's
RssAnon and RssShmem until execve replaces its memory map. The
family-room rule (REQ-fresh-resident-readings) adds every member's held
set back to the host's available memory, so the room rises by the
parent's whole held set — gigabytes for a campaign server mid-run —
and a ceiling derived from that reading by half of it. An install made
from that transient reading stands until the next
derivation (gomutant's server derives at every tool call's start, so
a call beginning while another call spawns an oracle can install it).

## Mechanism

resident/host.go's walk reads each descendant's /proc status and sums
the held lines; nothing distinguishes a member that shares an
ancestor's memory map from one that owns its own. The clause names
the walk's blind spots on the low side (unmapped tmpfs files, kernel
allocations, a hidden descendant — "the room errs low, never high");
this is a high-side case, acknowledged in the code's
"transient and small" comment. Persistent shared mappings are another
high-side case: a page mapped by several family members can appear in each
member's `RssShmem`. This is not exclusively a vfork timing problem, and a
summed process counter is not a count of unique physical pages.

## Required attribution

Measure the shared-address-space and persistent-shared-mapping cases against
the actual kernel quantities before changing arithmetic. Equal byte counters
and one thread do not prove a shared address space; two independent processes
can report equal totals. Taking the smaller of two samples neither identifies
shared pages nor proves the transient has ended. These former heuristic fixes
cannot establish the clause's low-only error claim.

Separate reported per-process sums, unique physical ownership, soft GC targets
and physical admission. Reconcile REQ-fresh-resident-readings' claimed bound
with what the sampler can actually establish, retaining operator-limit rules
and truthful unknown states. No particular deduplication formula is selected
by this filing. The original report arose from Gomutant's per-call ceiling
review; its source argument is not a new runtime measurement.
