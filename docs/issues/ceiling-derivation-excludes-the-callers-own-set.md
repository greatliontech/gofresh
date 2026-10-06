# The ceiling derivation excludes the caller's own resident set

`resident.Ceiling` derives from the host's available memory halved
(REQ-fresh-resident-readings). Available memory excludes the deriving
process's own resident set and its children's, so a derivation taken
while the process holds a working set — a long-lived server re-deriving
under an in-flight request, an operation re-deriving per call as
stipulator's reporter does — counts that set as the host's unavailable
memory and installs a ceiling below what the process already holds: a
16 GiB host under a run holding 6 GiB of heap with 6 GiB of oracle
children has about 3 GiB available, and a re-derivation then installs
1.5 GiB under a 6 GiB live heap, so the collector runs continuously, up
to the runtime's GC CPU cap, for the rest of the run — a throughput
collapse, never a cut (gomutant's 308.B review, round 2). gomutant
avoids it by deriving only when no call is in flight; a derivation from
available plus the process's own resident set (the sampler reads both
in one walk: resident.Readings) would make every call site safe,
stipulator's per-operation install included.

Lands: cross-tool train chunk 326 (the resident release: the derivation from available plus the process's own set, and the children's budget exported from the one reading — before stipulator 290.2b/322 and gomutant 214 fold onto resident; audit 316).