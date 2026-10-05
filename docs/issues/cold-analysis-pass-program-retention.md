# A cold analysis pass holds every program it loaded for the pass's life

Measured 2026-10-05 at gomutant chunk 308's open (the machine alone,
the parent's VmHWM sampled every five seconds through one target of
gomutant's own derived campaign — 796 subjects over 5 oracle packages,
9 candidates):

- warm memos: 0.54 GB high-water mark over the whole run, committed in
  3m30s — the views, the proofs and the attach each served from the
  persistent memo;
- cold memos (a fresh cache home): the SAME run reached 3.47 GB — 0.78
  GB at the oracle observation, 1.9 GB thirty seconds into "proving
  oracle closure freshness", 3.2 GB at nine minutes, 33 minutes to the
  commit; the resident set fell to 0.41 GB when the pass ended.

Nothing the consumer retains explains it: a view keeps facts (digests
and string maps), the Hasher is built per CaptureObservedBatch call and
dropped after it. Inside the call the Hasher keeps every program it
loads (`progs` by import path) for the pass's whole life, so a cold
pass over N packages holds the typed and SSA form of their union's
closure until the last subject is judged; chunk 305 released the
discharge's programs per rooted group, the fold, proof and observation
passes keep theirs. The 311 and m1 measurements over twenty targets
(3.6 GB through the proof pass, 8.4 GB at the first attach's cold
observation and fold) are the same shape at the campaign's scale; the
consumer's ceiling (gomutant's oracle derivation, stipulator's
Available/2) can only bound the heap the runtime collects, never the
live set a pass needs at once.

Expected: the pass's live set bounded by what its current subject needs
— programs released per package group as the discharge does (305's
shape), or the pass partitioned so a package's program is loaded,
judged and dropped before the next — stated as the clause's cost model
with the measured numbers as its anchor; the analysis budget's memory
sibling, if any, derives from it.

Lands: cross-tool train chunk 314 (chartered 2026-10-05 from this
measurement; a release, after 313 in the lane).
