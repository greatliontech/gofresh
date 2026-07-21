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
text — each carrying the digest of the input state the producing run saw, re-hashed
at check time to detect a change and to name which input moved.

**runtime-input manifest encoding** (term): the one canonical encoding is the unpadded
base64url encoding of a compact JSON object whose keys, in order, are `v`, optional
`env`, optional `paths`, and optional `unverifiable`; `v` is `1`, `unverifiable` is an
array of strings, `env` is an array of objects with keys `n` (the variable name) and
`d`, and `paths` is an array of objects with keys `k`, `p`, and `d`, where `k` is
`rel` for a slash-separated module-relative path or `abs` for a clean absolute host
path. Each `d` is that input's entry digest: 32 lowercase hex characters of truncated
SHA-256 — for an environment input over its presence and value hash, for a path input
over the identity-framed object-state stream (content, mode, size, modification time;
a module-relative directory's membership walk; an external directory's existence
marker) — so the combined state digest is the fold, in
canonical manifest order, of the version, each identity with its entry digest, and
each recorded unverifiable reason, and a mismatch attributes to named inputs. The
per-entry digest is a deterministic function of one input's state: whoever holds a
manifest can confirm a guessed value of a single low-entropy environment input
offline, a narrower confirmation than the whole-fold guess the combined digest alone
permitted — callers holding secret environment values exclude them from observation
or treat the manifest itself as sensitive. Each
array is a set encoded once per identity in lexical order; paths order first by `k`,
then `p`, comparing valid UTF-8 bytes. JSON strings use the compact escaping emitted
by Go's `encoding/json`: quote, reverse solidus, and control characters are escaped;
less-than, greater-than, ampersand, U+2028, and U+2029 use lowercase `\u` escapes;
other non-control Unicode is UTF-8. Producers emit only this canonical form. Readers
require the complete base64url and decoded JSON bytes to be canonical, rejecting
malformed or duplicate identities, malformed digests, duplicate or unknown fields,
invalid UTF-8, alternate ordering or escaping, trailing data, and unsupported
versions rather than silently dropping evidence — exactly one schema is ever
readable, and an encoding produced by an older tool fails validation and regenerates.

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
recorded to observe. The same surface attributes a digest mismatch to the moved
inputs by identity: each entry's recorded digest compared against its current
recompute names exactly the movers, environment inputs by name alone with values
undisclosed.

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

**REQ-inputs-adoption** (behavior): A caller holding a persisted encoded manifest
MUST be able to re-admit it as a completed observation under an attributable
process identity of the caller's choosing. Adoption validates the manifest
against the one canonical encoding, re-evaluates every recorded identity's
digest against the adoption-time module view and environment, and refuses any
disagreement naming the moved inputs — a persisted union whose evidence the
current view contradicts never re-enters silently. The adopted state
participates in ordinary merge, and its digest semantics are identical to a
fresh observation of the same identities under the same view, so a consumer
re-executing a subset of contributing processes widens a persisted union by
merging the adopted state with the fresh completed observations. Adoption
re-admits recorded evidence; it observes nothing new and confers no
completeness beyond what the persisted manifest recorded. Its trust posture is
the caller-trusted persistence class recorded fingerprints already occupy on
the check path: the manifest's producer-provenance is unauthenticatable, no
observation bracket backs the re-admitted values (value-binding governs fresh
observation only), and a caller who fabricates persisted evidence deceives
only itself — exactly as with a fabricated recorded fingerprint. An adopted
observation's process identity therefore attributes the adoption, never a
verified producing process.

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

**REQ-inputs-value-binding** (invariant): A completed observation of newly read
values — one whose evidence originates from a producing process's testlog rather
than from re-admitted persisted evidence (REQ-inputs-adoption) — MUST be
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
unverifiable when bracketed. The stat-metadata seal for an identity under a
declared root — outside every declared exclusion, whose subtrees are unspanned
and keep the seal — is decided at parse time and never recorded at all: an
admission the manifest bakes in, not a removal (REQ-inputs-unbounded), so
recomputation from the persisted manifest reproduces the same reasons with or
without the bracket in hand.

**REQ-inputs-observation-disposition** (invariant): Runtime-manifest
unverifiability MUST NOT be suppressible by an observability proof. Malformed or unrecognized
records, incomplete observations, `stat` metadata, `chdir`, `PWD`, unrepresentable
identities, unhashable values, external directories or symlink targets, and unknown
or caller-supplied reasons all remain unverifiable. Thus proof can replace only the
closure-level conservatism for its admitted effects; the manifest must independently
be complete, recognized, and fully hashable. A guard-covered read
(REQ-inputs-guard-covered) is outside this invariant's subject matter: it never
becomes a recorded observation, so there is no disposition to suppress — the covering
guard, not a proof, carries its evidence.

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

**REQ-inputs-guard-covered** (behavior): Observation construction from a test-harness
log MUST accept three classes of caller-declared guard-covered root — the producing
toolchain's GOROOT; the producing environment's GOMODCACHE covering its
version-addressed extracted module trees while its `cache/` download subtree (version
lists, lock files: mutable metadata no guard pins) stays observed; and the producing
environment's GOCACHE, its discovered `fuzz` corpus excepted — each a clean
absolute path from the same environment the producing run used. The build
cache's admission is toolchain-mediated observational equivalence rather than
per-object immutability: everything else under it, the mutable action index and
its bookkeeping included, is machinery whose consumption through the go
toolchain yields behavior determined by inputs the fingerprint already pins —
sources through the closure, the toolchain through its guard, the build
configuration — so any correct cache state is observationally equivalent,
re-observing it adds no protection, and its churn under concurrent builds
forfeits reuse for free. The `fuzz` subtree is the counterexample and stays
observed: a discovered corpus a `-fuzz` producing run consumes semantically,
derivable from nothing the fingerprint pins. A cache violating Go's contract
is outside this model's trust boundary exactly as a corrupted GOROOT is, and a
subject reading cache objects as data rather than through the toolchain is
outside the admitted observation set exactly as covered-tree metadata
dependence already is. A read records neither
a path identity nor any per-path disposition when it is provably inside a declared
root's covered region: inside in its recorded form (the declared path or its resolved
form — a symlinked root appears both ways), the existing object it resolves to inside,
and every symlink the kernel walk traverses inside — a chain that leaves the region
and re-enters is a mutable rebinding point outside every guard and stays observed,
exactly as value-binding coverage treats bracket roots. Missing, uninspectable, or
ambiguously resolved objects stay observed. Covered content is already pinned by
evidence the fingerprint carries — GOROOT by the toolchain guard, extracted module
trees by immutable version pinning, the closure model's own collapse for stdlib and
cached dependencies — so re-observing it adds no protection and forfeits reuse; a
subject depending on a covered tree's *metadata* beyond what the covering guard pins
is outside the collapse and outside the admitted observation set alike. The caller's
soundness inputs are exactly two, and their blast radius is stated: a declared root
that does not correspond to the producing environment's directory silently vacates
observation for everything beneath it, and the declared roots' link topology rides the
same hold-still span REQ-inputs-observation-coherence already places on the caller —
guards pin covered content, never the shape of the path that reached it.

**REQ-inputs-ephemeral-root** (behavior): Observation construction from a
test-harness log MUST accept caller-declared ephemeral temp roots — the
producing environment's temp directories, each a clean absolute path — whose
OWN identity, in its declared or resolved form, records neither a path
identity nor a per-path disposition: temp-tree creation machinery stats the
root to mint fresh per-run subtrees, no state a subject observes flows from
the root's existing content (name-collision retries are invisible salt), and
the root's listing is volatile machine noise no guard could pin — so any
writable root is observationally equivalent and re-observing it converts
environmental machinery into a standing refusal. Beyond the root identity,
a deeper read under a declared root whose object is ABSENT at observation
ingest likewise records nothing: it is per-run scratch by construction —
state that outlived the run would still be present, and a pre-existing file
a subject read still exists at ingest and stays observed and digested. The
scratch admission is fail-closed on resolution: the absent path's nearest
existing ancestor must itself resolve under the root's resolved form, so a
traversal through an existing link escaping the root stays observed; a
since-vanished link component that redirected the runtime read is the
class's accepted residual, one process run wide, alongside the stated
assumption that concurrently executing witnesses do not mutate one
another's inputs. A subject consuming-and-removing persistent external
state under the root — making external input masquerade as scratch — is
outside the admitted observation set (such a subject is not rerunnable
deterministically regardless). Otherwise every deeper read stays observed,
an unresolvable root declares nothing, a root lying inside the module tree
in either form is refused outright — it would vacate a content-bearing
module digest, not an external refusal — and the wrong-root blast radius
for admissible roots is one external identity wide by construction. A
subject reading the root's listing as data is outside the admitted
observation set, exactly as covered-tree metadata and
cache-objects-as-data dependence already are.

**REQ-inputs-null-sink** (behavior): Opens and stats of exactly `/dev/null` —
the unix contentless sink device; on platforms whose sink is not an absolute
path (windows `NUL`) nothing is admitted and the reads stay observed,
cost-only — MUST record neither a path identity nor a per-path disposition: every read observes immediate end-of-file and every
write is discarded, so no state a subject observes flows through the identity
and any conforming kernel is observationally equivalent. The admission is the
literal cleaned identity alone — no other device node shares it: `/dev/zero`
is a readable value stream and the random devices are genuine nondeterministic
inputs, all staying observed — and a path merely resolving to the same device
through another name stays observed; the admission is lexical identity, never
device topology. A subject depending on the sink's metadata beyond its
existence is outside the admitted observation set, exactly as covered-tree
metadata dependence already is.

**REQ-inputs-external-dir-existence** (behavior): A `stat` of an absolute directory
outside the module tree MUST record an ordinary absolute-path identity whose digest
binds existence-as-a-directory alone: path-creation machinery probes ancestors —
`/home` on the way to a user cache directory — consuming exactly "exists and is a
directory", so the record revalidates equal while the directory exists and moves
when it vanishes or becomes a non-directory. The entry is exempt from value-binding
bracket coverage exactly as machine-fact identities are — existence equality at
revalidation is its binding, with the same one-process-run in-window residual;
that residual also covers an external object recorded as a file or absence that a
third party turns into a directory inside the ingest's own classify-to-digest
window, which rebinds as existence instead of sealing, and — via the
absent-stat clause's vanish direction — a directory vanishing between the
probe and ingest, which binds absence.
Opening or listing an external directory keeps ordinary classification
(listing-as-data stays outside the admitted observation set), and metadata
dependence beyond existence is outside the admitted observation set exactly as
covered-tree metadata already is.

**REQ-inputs-absent-stat** (behavior): A `stat` resolving to an ABSENT identity
outside the module tree MUST record the identity with no metadata disposition:
absence is the entire observable state, the missing-arm digest revalidates equal
while the identity stays absent and stales exactly when it appears, and the
entry is exempt from value-binding bracket coverage exactly as the other
existence bindings are, with an in-window residual that is WIDER here than the
sibling classes' and is accepted by name: an identity appearing between the
probe and ingest binds presence the run never saw, and — the vanish direction —
an identity present at the probe that vanishes before ingest binds absence
although the run may have consumed it, a probe-to-ingest window as wide as the
run itself, realistic as a package upgrade or uninstall racing a test run; both
serve until the identity next moves. Executable PATH-probe misses — every
`LookPath` candidate that is not there — are the motivating class; a present
target keeps ordinary stat classification.

**REQ-inputs-machine-identity** (behavior): The allowlisted stable-machine-fact
identities — `/proc/cpuinfo`, `/proc/meminfo`, and `/proc/sys/kernel/osrelease`,
the sources the projection's own gatherer reads — MUST digest as the stable
machine projection REQ-guard-machine defines (CPU model and microarchitecture,
core counts, total memory, operating system and kernel version), never as raw
content or stat metadata: their bytes and mtimes are volatile on every read
while everything a subject could branch on — a core-count skip, a memory-gated
path — is the projection, so a record over them revalidates equal on the same
machine and moves exactly when the hardware or kernel actually changed. The
entry stays an ordinary absolute-path input on the wire; only its digest
function differs, and an ungatherable projection is unhashable, never silently
skipped. A subject branching on the allowlisted files' transient content —
cpu MHz lines, flag details, available-memory counters — is outside the
admitted observation set, exactly as covered-tree metadata and
listing-as-data dependence already are. The allowlisted identities are exempt
from value-binding bracket coverage: the binding they get is projection
equality at revalidation, which catches every change landing after the seal.
The residual is a projection change inside the read-to-seal window that
persists — seal and every later check are both post-change, so equality
holds while the subject branched on the pre-change value; memory hot-add on
a resizing virtual machine is the realistic instance — a case a pre-run
bracket would catch, accepted here because the window is one process run
wide and the facts change only by operator action; a change that reverts
before the next check evades the bracket and the projection alike. Identities
outside the allowlist keep ordinary classification — the
transient-condition surfaces REQ-guard-machine-transient excludes from machine
identity are exactly what this clause must never absorb.

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
analysis cannot bound — a metadata-only inspection of an identity outside every
DECLARED bracket root (a stat under a declared root never takes the seal at all:
the bracket fingerprint observes content and metadata together over the whole
span, and the entry digest binds both thereafter — an admission decided at
parse time, so the bracket never removes a recorded reason), a directory or symlink resolving
outside the module (the existence-bound stat form of an external directory
excepted, REQ-inputs-external-dir-existence), a relative path under a
working-directory change the run stream cannot confirm was absent, or `PWD` whose value the Go test harness derives separately
for each package process — MUST be treated as unverifiable rather than valid, since an
input identity that cannot be pinned under the shared checking environment is not
proof of a stable input. One `PWD` posture IS bounded and admits recordless: a
frozen environment carrying `PWD` equal to the package directory the process spawned
in — the value the subject reads is then fully determined by the frame identity the
record already pins, so re-observing it adds no protection; any other posture,
including an absent or divergent `PWD`, seals as before.
