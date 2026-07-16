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
actions can reject mutations that would invalidate their completed observation.

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
of it. Against that model, the proof admits only subject-time `os.Getenv`,
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
`os.Environ`, `os.OpenFile`, `os.Stat`, `os.Lstat`, process execution, and every
filesystem mutation are explicitly outside the read-only set. An addition to either
the producer hook set or the admitted set is a contract change, never inferred from a
matching diagnostic string.

**REQ-inputs-completed-observation** (invariant): Testlog bytes MUST become a completed
observation only through a construction path gated by the caller's verified normal
termination of that producing process and its evidence that every behavior-affecting
admitted-operation outcome agreed with the guarded value. EOF, including EOF exactly
at a line boundary, is neither termination nor outcome evidence. Exactly one completed
or incomplete observation is required for every process contributing to the result. A
process without both gates is represented through the incomplete-observation
constructor; merge refuses a state that claims completion without them, and one
incomplete child keeps the deterministic union unverifiable.

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

**REQ-inputs-fresh-mutation** (invariant): A later observability extension MAY admit
a filesystem mutation only when subject-local value and alias analysis proves its
target was freshly created within the same observed run, every result used as an
existence or metadata probe is bounded, every read of the target is derived solely
from guarded source or runtime inputs, and destructive cleanup cannot erase a
pre-existing consumed value before finalization. `OpenFile` additionally requires
proved non-mutating flags or a proved-fresh target. Rename, hard-link, symlink, direct
syscall, and process operations remain inadmissible because they can transport or
introduce unobserved state.

Lands: 5.

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
