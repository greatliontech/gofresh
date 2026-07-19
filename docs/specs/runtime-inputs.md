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

**runtime-input manifest encoding** (term): version 1 is the unpadded base64url
encoding of a compact JSON object whose keys, in order, are `v`, optional `env`,
optional `paths`, and optional `unverifiable`; `v` is `1`, `env` and `unverifiable`
are arrays of strings, and `paths` is an array of objects with keys `k` and `p`,
where `k` is `rel` for a slash-separated module-relative path or `abs` for a clean
absolute host path. Each array is a set encoded once per member in lexical order;
paths order first by `k`, then `p`, comparing valid UTF-8 bytes. JSON strings use the
compact escaping emitted by Go's `encoding/json`: quote, reverse solidus, and control
characters are escaped; less-than, greater-than, ampersand, U+2028, and U+2029 use
lowercase `\u` escapes; other non-control Unicode is UTF-8. Producers emit only this
canonical form. Readers require the complete base64url and decoded JSON bytes to be
canonical, rejecting malformed or duplicate identities, duplicate or unknown fields,
invalid UTF-8, alternate ordering or escaping, trailing data, and unsupported versions
rather than silently dropping evidence.

**dirty recording** (term): a recording whose source or inputs are not faithfully
reproducible from its recorded commit, usable for working-tree reuse but barred as a
baseline.

**observation bracket** (term): a fingerprint over a caller-declared set of
candidate runtime-input roots — module-relative or clean absolute paths, each a
regular file, a directory tree, or absent — captured before the producing process
starts and revalidated when its testlog becomes an observation, so a change to any
bracketed object persisting across the run-to-observation span is detected. The
fingerprint observes content and metadata together, so a restoration that does not
reproduce the recorded metadata still moves the bracket — toward recomputation,
never reuse.

## The guard

**REQ-inputs-guard** (behavior): The runtime-inputs guard MUST record a
runtime-input manifest of the identities a subject's run observes together with a
digest over their current content, then at check time re-hash those same identities
and compare, staling the result when the digest moves — it is a code guard, bearing
on any result whose non-source inputs can change, and a missing file hashes as
missing so an input appearing or disappearing moves the guard.

**REQ-inputs-path-identities** (behavior): A caller MUST be able to enumerate every
path identity in a validated runtime-input manifest as its materialized absolute
path under a supplied module directory, preserving canonical manifest order and
including both module-relative and external identities, so caller-owned producer
actions can reject mutations that would invalidate their completed observation. The
same enumeration surface discloses the manifest's environment-variable names and
unverifiable observation dispositions — identities only, environment values never in
clear text — so a consumer can explain a digest mismatch by naming what the run was
recorded to observe. Per-input movement attribution is outside the manifest's
evidence: it records identities and one combined digest, not per-input digests.

**REQ-inputs-observation-coherence** (invariant): The caller MUST exclude runtime
input mutation throughout each producing run and its observation finalization, and
while merge, dirty inspection, or a current check observes inputs. Merge revalidates
every completed child state against its one merge-time view before unioning their
identities, rejecting children finalized under values that no longer agree; Gofresh
also re-observes around a check to detect ordinary drift. It cannot prove the absence
of a mutation-and-restore interval within one observation or construct an atomic
snapshot spanning process environment, several files, and directory trees; allowing
such an interval forfeits the proof that the digest describes the run or check.
Every environment-aware finalization, merge, absolute conversion, dirty inspection,
and current check uses the same complete process environment as the producing or
checking process; ambient convenience operations use the ambient environment at the
operation. Mixing an explicitly configured process with ambient environment hashing
is not coherent evidence.

**REQ-inputs-context** (behavior): Context-aware current checks MUST observe
caller cancellation before and between environment identities, path identities,
directory members, and file-read chunks, returning the context error without a
partial state. Context-free checks retain identical hashing semantics under an
unbounded background context.

**REQ-inputs-merge** (behavior): A caller combining observations from several
processes MUST be able to merge their independently completed states as a deterministic
manifest set union, with no shared mutable manifest or cross-process lock. Before
union, each child's recorded digest and disposition are re-evaluated against the same
merge-time module view; a structurally unfinished or malformed child, or any
disagreement, is refused, while a finalized state explicitly recording observation
incompleteness is accepted as unverifiable evidence. Every
environment identity, path identity, and unverifiable reason from every accepted
child appears once in the canonical result. Merge is commutative, associative, and
idempotent; its digest is computed from the merged manifest against that current
view. Merging zero states deliberately produces the encoded observation-free
manifest, while an empty, malformed, or unsupported manifest supplied in a state is
refused rather than treated as no observation.

**REQ-inputs-incomplete** (behavior): A caller whose producing process did not
complete normal observation finalization MUST be able to construct a canonical
runtime-input state carrying a non-empty attributable incompleteness reason, no
fabricated identities, and an unverifiable disposition. The state participates in
ordinary deterministic merge, so one incomplete process makes the merged evidence
unverifiable without being confused with an explicit completed empty observation.

**REQ-inputs-absolute-identities** (behavior): A caller combining process
observations rooted at different module directories MUST be able to revalidate each
completed state against its original module view and convert every module-relative
path identity to the equivalent clean absolute identity without changing environment
identities or suppressing unverifiability. Any dynamic unverifiable disposition from
the original module-relative interpretation is carried into the converted manifest;
conversion may strengthen the disposition when absolute directory semantics are more
conservative, but never weakens it. The converted states then participate in ordinary
merge under any caller root without interpreting one module's relative path under
another module.

**REQ-inputs-evidence-not-proof** (invariant): A runtime-input manifest MUST be
treated as evidence of the identities it observed, never as proof that every
reachable input was observed — so a matching digest can move a logged input change to
stale, but can never on its own promote a subject's closure-level file dependence to
valid; absent the recognized attributable observation-completeness assertion and
compatible observability proof required together by the freshness contract, a subject
reaching an unobserved unverifiable dependence stays unverifiable.

## Observation completeness

**REQ-inputs-observable-read-set** (invariant): The read-only observability proof
MUST model the Go test observation producer as exposing exactly the operation names
`getenv`, `open`, `stat`, and `chdir`, starting after package initialization when user
test-main flow calls into the harness; account for the producer omitting an
empty identity or one containing a newline; `open` not encoding access flags; `stat`
not recording returned metadata; every operation omitting its return values, byte
counts, and errors; and mutation and child-process operations producing no record.
The identity-only stream does not establish the outcome part of an
observation-completeness assertion by itself. The toolchain guard pins producer
behavior and the observability strategy identity pins the engine's interpretation
of it. Against that model, the base read-only proof admits only subject-time `os.Getenv`,
`os.LookupEnv`, `os.Open`, `os.ReadFile`, and
`os.ReadDir` effects whose identity arguments are proven non-empty, valid UTF-8, free
of carriage return and newline, and reproducibly resolvable. On a read-only file
handle obtained from that admitted acquisition, only `Close`, `Name`, `Read`,
`ReadAt`, and `Seek` are admitted. An admitted standard-library wrapper is classified
atomically at its audited public operation: implementation-internal syscall or native
steps solely realizing that same logged effect do not become duplicate subject
effects, while callbacks, additional effects, and returned-value methods remain
independently classified; any descriptor escape or unaudited implementation path
blocks the proof. On a directory entry returned by an admitted `ReadDir`, only `Name`,
`IsDir`, and `Type` are admitted. Every method of
every result value is audited independently, unknown methods block, and metadata
returning methods such as `File.Stat` and `DirEntry.Info` block because their complete
values are not hashed. `File.ReadDir` also blocks because filesystem enumeration order
is not represented by the canonical directory digest. Each admitted operation's
behavior-affecting return values, byte counts, and errors must be established as
derivable from its guarded environment value or hashed regular-file or sorted-directory
value; an identity observation alone never establishes that fact. Every other
environment, filesystem, network, process, metadata,
mutation, direct-syscall, native, linked, or unknown effect blocks the proof;
`os.Environ`, `os.Stat`, `os.Lstat`, process execution, and every
filesystem mutation or `os.OpenFile` use not admitted by the fresh-mutation extension
are explicitly outside the set. An addition to either
the producer hook set or the admitted set is a contract change, never inferred from a
matching diagnostic string.

**REQ-inputs-completed-observation** (invariant): Testlog bytes MUST become a completed
observation only through a construction path gated by the caller's verified normal
termination of that producing process, its evidence that every behavior-affecting
admitted-operation outcome agreed with the guarded value, and an observation bracket
satisfying REQ-inputs-value-binding. EOF, including EOF exactly at a line boundary,
is neither termination nor outcome evidence. Exactly one completed
or incomplete observation is required for every process contributing to the result. A
process without every gate is represented through the incomplete-observation
constructor; merge refuses a state that claims completion without them, and one
incomplete child keeps the deterministic union unverifiable.

**REQ-inputs-value-binding** (invariant): A completed observation MUST be
constructible only against an observation bracket captured before its producing
process started. Strictly after the manifest digest's last input read, the bracket
is revalidated with the same hashing semantics as its capture: an unchanged
fingerprint binds the digest of every bracket-covered recorded path identity to the
values read at any time in the capture-to-revalidation span, up to an intra-span
mutation-and-restore interval — the residual REQ-inputs-observation-coherence
already declares unprovable; a restore is tolerated only when it reproduces content
and metadata alike. An observed identity is bracket-covered only when the object it
materializes to under kernel path-walk semantics resolves, after every symlink in
the walk, to a path under a declared root's own resolved path, and every symlink
the walk traverses — directory components included — itself lies under a
declared root's resolved path, so each traversed link's target is fingerprinted
and a retarget moves the bracket rather than silently rebinding the identity.
The walk is read from the capture module view's resolved root for a
module-relative identity and, for an absolute one, from the resolved position
of its covering root — the declared absolute root whose path lexically
contains the identity. An absolute root is fingerprinted through its full
chain, so a retarget above the root moves its digest unless the new object is
content-and-metadata identical — the tolerated-restore class, under which the
bound values are identical by construction. An identity whose
resolution chain leaves every root at any step, or that is lexically under a
root but resolving outside every root, is unverifiable, never bound; and an
unchanged bracket binds only covered identities carrying no other unverifiable
disposition. A revalidation finding the bracket moved — including a root whose
object changed type, appeared, or disappeared — records an attributable
unverifiable reason for the observation, and a recorded path identity covered by no
root records an attributable per-identity unverifiable reason; in both cases the
observation still constructs, converts, merges, and checks as unverifiable
evidence, never as bound, so the failure direction is always recomputation. A
bracket captured after the process started, interpreted under a different module
view than its capture, or revalidated with different hashing semantics is refused
rather than read as unchanged. Environment identities require no bracket:
observation coherence already requires digesting from the exact complete
environment the producing process inherited, which binds their observed values by
construction.

**REQ-inputs-bracket-coverage** (invariant): A declared root MUST be fingerprinted
with the hashing semantics its materialized object would receive as an observed
identity of its kind; a root those semantics refuse to hash makes the bracket unverifiable
rather than silently narrowing coverage. A declared root that is absent
fingerprints as absent, so an input created, deleted, rewritten, or retyped under a
root during the span moves the bracket. Coverage is per declared root, never
inferred: an observed identity resolving under no root is uncovered however near a
root it lies, and declaring a root is the caller's assertion that the surface it
names was mutation-free for the span, carrying the same soundness responsibility as
an exclusion. A bracket accepts caller-declared root exclusions with the semantics
and responsibility of REQ-inputs-exclusions — the identical identity and every
identity extending it past a separator — removing the excluded subtree from the
fingerprint and from coverage alike, so a volatile bookkeeping tree under a
module-scale root does not make every bracket environmental noise; an excluded
identity a run then observes is uncovered, never bound. The bracket never weakens a
disposition: every observation the manifest treats as unverifiable remains
unverifiable when bracketed.

**REQ-inputs-observation-disposition** (invariant): Runtime-manifest
unverifiability MUST NOT be suppressible by an observability proof. Malformed or unrecognized
records, incomplete observations, `stat` metadata, `chdir`, `PWD`, unrepresentable
identities, unhashable values, external directories or symlink targets, and unknown
or caller-supplied reasons all remain unverifiable. Thus proof can replace only the
closure-level conservatism for its admitted effects; the manifest must independently
be complete, recognized, and fully hashable.

**REQ-inputs-path-congruence** (invariant): A validity-bearing observed path identity
MUST materialize to the same filesystem object under the checker that the producing
operation addressed under kernel path-walk semantics. The observation is
unverifiable when this cannot be established, including any raw path with a `..`
component that may cross a symlink before lexical cleaning and any relative path
after a working-directory change. Lexical normalization alone never discharges this
obligation.

**REQ-inputs-fresh-mutation** (invariant): The fresh-mutation observability extension MAY admit
a filesystem mutation only when subject-local value and alias analysis proves its
target was freshly created within the same observed run, every result used as an
existence or metadata probe is bounded, every read of the target is derived solely
from guarded source or runtime inputs, and destructive cleanup cannot erase a
pre-existing consumed value before finalization. `OpenFile` additionally requires
proved non-mutating flags or a proved-fresh target. Rename, hard-link, symlink, direct
syscall, and process operations remain inadmissible because they can transport or
introduce unobserved state.

The recognized fresh-mutation extension treats a `testing.TempDir` result as an opaque
fresh directory capability and derives child capabilities only by joining portable
constant basename components. The capability may not affect behavior as a string or
escape the recognized operation graph. A guarded `os.WriteFile` of source-constant
bytes establishes its target as freshly created. `os.ReadFile` may consume a fresh
capability. `os.Remove` and `os.RemoveAll` require the exact target to be the fresh
directory root or to have a preceding guarded creation that applies on every path to
the operation. Every fresh-path `os.OpenFile` requires that preceding file creation;
zero-flag `os.OpenFile` is non-mutating and may instead address an ordinary
reproducible identity. Mutation errors and handle
existence may affect control flow only through direct nil checks, and generated names,
handles, and probe results may not escape. Unknown flags, path transforms, aliases,
ordering, or uses fail the proof closed.

**REQ-inputs-absent-asserted** (behavior): A fingerprint carrying no runtime-input
manifest MUST be read as the caller's assertion that the subject's run observed no
runtime inputs, the guard holding vacuously — the engine never runs the subject and
cannot see what a run observed, so the manifest is the caller's to supply exactly as
the build inputs and the commit are, and a caller that attaches none takes
responsibility the same way. An observation-free run still encodes as an empty
manifest distinct from no manifest at all, so absence is always a deliberate
assertion, never a capture accident; a caller that runs subjects through the test
harness attaches what the testlog yields.

**REQ-inputs-exclusions** (behavior): Observation construction from a test-harness
log MUST accept caller-declared path exclusions — each a non-empty identity-form
path (module-relative or clean absolute), an empty pattern refused rather than
read as anything — and record neither a path identity nor any per-path
disposition for an excluded observation, while leaving working-directory
tracking and every non-excluded observation unchanged. A pattern excludes
exactly the identical identity of its kind, plus every identity of that kind
that extends it past a path separator — the pattern followed by a separator as
a string prefix — so the root listings `.` and `/` exclude only themselves,
never the identities beneath them. Exclusion is per identity, never per
content: a directory identity that remains recorded still digests everything
its hash walks, so a caller silencing a volatile subtree excludes both the
subtree and every recorded ancestor listing whose digest observes it. An
exclusion is the caller's assertion that the excluded paths are not inputs of
the subject: it carries the same soundness responsibility as attaching no
manifest, and it is how a caller meets observation coherence for volatile
paths it cannot hold still — a VCS bookkeeping directory mutated by unrelated
tooling makes every digest over it environmental noise rather than evidence.
Environment identities are never excludable through path exclusions.

**REQ-inputs-dirty** (behavior): A recording backed by a module-local input whose
Git-representable state is not reproducible from its recorded commit MUST be marked
as a dirty recording, because the recording is not faithful to that commit; the mark
bars it as a baseline while leaving it usable for working-tree reuse. The comparison
includes absence, regular-file content and executable mode, symlink target, and
directory tree membership and member state, thereby covering gitignored, untracked,
modified, or run-created inputs and targets reached through committed symlinks. Dirty
evidence is the caller-facing result of testing every module-relative identity in the
final merged manifest after revalidating that completed state against the same current
module view; if the state moved the inspection is refused, and if any identity is not
reproducible the result is dirty. The commit and dirty mark do not enter the
fingerprint or validity predicate, and an inspection failure or unrepresentable
comparison is returned rather than interpreted as clean.

**REQ-inputs-unbounded** (behavior): An observed input whose full observed value the
analysis cannot bound — a metadata-only inspection, a directory or symlink resolving
outside the module, a relative path under a working-directory change the run stream
cannot confirm was absent, or `PWD` whose value the Go test harness derives separately
for each package process — MUST be treated as unverifiable rather than valid, since an
input identity that cannot be pinned under the shared checking environment is not
proof of a stable input.
