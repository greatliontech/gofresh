# The resident walk counts a child in its vfork window twice

Lands: cross-tool train chunk 314 (the resident class; a release)

## Symptom

A reading taken while a descendant sits between its clone and its exec
counts the parent's held set twice: Go's forkExec clones with
CLONE_VM|CLONE_VFORK, so the child's status reports the parent's
RssAnon and RssShmem until execve replaces its memory map. The
family-room rule (REQ-fresh-resident-readings) adds every member's held
set back to the host's available memory, so the room rises by the
parent's whole held set — gigabytes for a campaign server mid-run —
and a ceiling derived from that reading by half of it. The window is
microseconds; an install made from it stands until the next
derivation (gomutant's server derives at every tool call's start, so
a call beginning while another call spawns an oracle can install it).

## Mechanism

resident/host.go's walk reads each descendant's /proc status and sums
the held lines; nothing distinguishes a member that shares an
ancestor's memory map from one that owns its own. The clause names
the walk's blind spots on the low side (unmapped tmpfs files, kernel
allocations, a hidden descendant — "the room errs low, never high");
this is the one high-side case, acknowledged only in the code's
"transient and small" comment.

## Candidate

Skip a member whose memory map is an ancestor's: on Linux
/proc/<pid>/stat carries no mm identity, but a child in the vfork
window has its parent's `VmSize`, `VmRSS`, `RssAnon` and `RssShmem`
byte for byte and its own `Threads: 1` — read as a copy of the
parent's held set when every held line equals the parent's at the same
reading, or read `/proc/<pid>/status`'s `Vm*` lines after a retry when
the child's state is `D` with the parent's values; or sample the
family twice and take the smaller held sum (a vfork window never
spans two walks). The clause's "never high" then holds for the family
as read. Effect today: GC slack on the server (a soft limit cuts
nothing), never a refusal.

Filed from gomutant 324.E's review (the server's per-call derivation
no longer gated on nothing in flight).
