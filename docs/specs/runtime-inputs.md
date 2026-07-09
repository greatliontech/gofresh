# Observed runtime inputs

Source is not the only thing a subject's behavior depends on: a run can read an
environment variable or a file that is not source at all. The runtime-inputs guard
records the identities a run observes and re-checks them, a code guard distinct from
the source closure. Its hard limit — the reason it can stale a changed input but can
never on its own prove the absence of an unobserved one — is the subject of the
invariant below, and is why observing inputs never silently promotes a subject past
its unverifiable dependence.

**runtime input** (term): a non-source value a subject reads at run time — an
environment variable's value or a file's content — whose change can move behavior
with no source change.

**runtime-input manifest** (term): the recorded set of observed runtime-input
identities — environment variable names and file paths, values never stored in clear
text — re-hashed at check time to detect a change.

**dirty recording** (term): a recording whose source or inputs are not faithfully
reproducible from its recorded commit, usable for working-tree reuse but barred as a
baseline.

## The guard

**REQ-inputs-guard** (behavior): The runtime-inputs guard MUST record a
runtime-input manifest of the identities a subject's run observes together with a
digest over their current content, then at check time re-hash those same identities
and compare, staling the result when the digest moves — it is a code guard, bearing
on any result whose non-source inputs can change, and a missing file hashes as
missing so an input appearing or disappearing moves the guard.

**REQ-inputs-evidence-not-proof** (invariant): A runtime-input manifest MUST be
treated as evidence of the identities it observed, never as proof that every
reachable input was observed — so a matching digest can move a logged input change to
stale, but can never on its own promote a subject's closure-level file dependence to
valid; absent an explicit completeness proof, a subject reaching an unobserved
unverifiable dependence stays unverifiable.

**REQ-inputs-absent-asserted** (behavior): A fingerprint carrying no runtime-input
manifest MUST be read as the caller's assertion that the subject's run observed no
runtime inputs, the guard holding vacuously — the engine never runs the subject and
cannot see what a run observed, so the manifest is the caller's to supply exactly as
the build inputs and the commit are, and a caller that attaches none takes
responsibility the same way. An observation-free run still encodes as an empty
manifest distinct from no manifest at all, so absence is always a deliberate
assertion, never a capture accident; a caller that runs subjects through the test
harness attaches what the testlog yields.

**REQ-inputs-dirty** (behavior): A recording backed by a module-local input absent at
its recorded commit — gitignored, untracked, or created during the run — MUST be
marked as a dirty recording, because such an input is not reproducible from that
commit so the recording is not faithful to it; the mark bars it as a baseline while
leaving it usable for working-tree reuse.

**REQ-inputs-unbounded** (behavior): An observed input whose full observed value the
analysis cannot bound — a metadata-only inspection, a directory or symlink resolving
outside the module, a relative path under a working-directory change the run stream
cannot confirm was absent — MUST be treated as unverifiable rather than valid, since
an input identity that cannot be pinned is not proof of a stable input.
