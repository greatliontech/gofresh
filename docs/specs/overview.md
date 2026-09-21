# gofresh — source-closure freshness for cached results

gofresh decides whether a cached result about a Go symbol — a benchmark's
measurement, a test's verdict, a mutation finding — is still trustworthy for the
current source tree, or must be recomputed. It fingerprints the source a symbol
depends on and the environment that produced the result, and reports a verdict by
comparing a stored fingerprint against the current one. It never runs the symbol
and never owns the result store: it answers one question — *is this still fresh?* —
and leaves measuring and storing to the caller.

Beside that one question, this module is also the fleet's shared
substrate: infrastructure every consuming tool needs identically lives
here once — today the tool-resident guidance format
([guidance.md](guidance.md)); the go-command policy
(REQ-fresh-go-command-policy) — one runner for every `go` command
gofresh spawns itself, the engine's installed one or the plain one,
under one complete normalized environment (deterministic order, duplicate keys refused, `PWD` derived
from the command's directory, the ordinary loader pinned; one setter
keeping that order) that the package loader's `go list` children carry
— `x/tools` appends its own `PWD=<dir>`, the same derivation, and
spawns them outside the runner's hook; one process-boundary rule a
consumer's runner applies to every command it prepares — the child in
its own process group, a cancellation sweeping the group, an
already-gone group the process-done case, a wait delay bounding the
reap (a named delay, else the policy's default, never unbounded), a
quit grace on a cause the consumer names, the reap then bounded by the
grace and the delay together — with the prepared command a consumer
streams itself and the collected run keeping a cleanly exited process's
answer beside a descendant's pipe hold — the toolchain sample, the
environment snapshot, and the runtime-input roots probe serving that
answer when it is whole — and bounding a failed command's diagnostics
in its refusal; one pass-scoped go-environment reader
taking the pass's one snapshot on its first key; one canonical
directory resolution and its degrading coordinate; and the toolchain
sample below — each a consumer's obligation met once (the `gotool`
package), a consumer's runner reaching the commands that consumer
spawns through it and, installed on an engine by its option, every go
command that engine spawns itself — the loader's `x/tools` children
excepted, as stated; the
fast-tier partition pin — one call pinning that a repository's every
`testing.Short` gate is a skipping statement of a Test or Fuzz body, at
its head or after the cheap controls it deliberately runs first, a
subtest or fuzz body counting as a body and any other closure not, never
in a helper the full tier could not see through, and never in a fixture
source, where it would change what the full tier analyzes — and that the
walk found at least one gate, at the root and below it (its contract
lives with the `shortgates` package); and the language-shape canary
corpus — the source shapes every tool's frontend must parse and judge,
one exported home each consumer wraps with its own harness, so the
canaries' content cannot drift between consumers, though a consumer
pinned to an older release runs an older corpus (the `shapecorpus`
package) — because the fleet's tools already depend on this module, and
a second home would mean a second implementation.

## Documents

- [closure.md](closure.md) — the source closure and its tiers.
- [guards.md](guards.md) — the guards beside the closure.
- [runtime-inputs.md](runtime-inputs.md) — observed runtime inputs.
- [purity.md](purity.md) — purity assertions and vouches.
- [explain.md](explain.md) — verdict derivation chains.
- [guidance.md](guidance.md) — the tool-resident guidance format.

## Vocabulary

**subject** (term): the named Go symbol whose freshness is tracked — a function
reachable as an analysis root, such as a benchmark, a test, or any callable a
caller keys a cached result on. The unit of freshness. An `init` function,
which Go keeps unaddressable by name, is a subject under the declaration
ledger's positional identity — the symbol `init#<file>#<ordinal>`, where
`<file>` is the declaring file's base name in the pure-Go compilation and
`<ordinal>` counts the file's receiverless init declarations in declaration
order, 0-based, independent of whether analysis resolves each one. The
identity is file-scoped: inits elsewhere in the package neither shift it nor
make it unresolvable. An init declared in a cgo-processed file is not
addressable — the compilation's file names there are cache artifacts, not
the declaring file.

**source closure** (term): the set of source declarations whose change could alter
a subject's runtime behavior — the functions its body transitively reaches, the
constants, types, and package-level variables they reference, the package
initialization whose side effects the subject can observe, and the embedded files
read through them. Standard-library declarations are excluded; module dependencies
are included.

**guard** (term): one comparable fact about how a result was produced, recorded
with the result and re-evaluated against the current tree. A guard holds when its
recorded and current values agree; a failing guard makes the result stale.

**code guard** (term): a guard over inputs that determine the compiled code and
data behind a result — the source closure, the observed runtime inputs, the
toolchain identity, and the build configuration. A code guard bears on every
subject whatever the result's kind.

**measurement guard** (term): a guard over the execution environment that can move
a timing measurement without changing a pass/fail outcome — the machine
fingerprint and the runtime configuration. A measurement guard bears only on a
result that is a measurement.

**verdict** (term): the freshness answer for a subject's stored result against the
current tree — one of valid, stale, or unverifiable.

**fingerprint** (term): the recorded evidence a verdict is computed from — the
subject's maximal source-closure hash, its package's test-variant compartment
hash, optional
attributable observation-completeness assertion and observability proof evidence, any
attributable purity assertion used to override unverifiability, the result kind
selecting its applicable guards, and the value of every applicable guard.

**observation-completeness assertion** (term): an attributable caller declaration
that every process contributing to a subject's result ran under the recognized
observation harness; that exactly one completed or incomplete observation was attached
for each such process; and that every behavior-affecting outcome of an admitted
operation agreed with the guarded value recorded for it, with any exceptional or
partial outcome not derivable from that value making the process observation
incomplete. It vouches for how the run was observed, not for which effects the subject
can reach.

**observability proof** (term): optional, caller-selected, versioned per-subject
evidence that whole-program analysis found every behavior-affecting non-source effect
reachable by the subject and proved each one representable by the recognized
observation stream. It is an engine proof, distinct from the caller's
observation-completeness assertion and from a purity assertion.

**analysis view** (term): one bounded observation of selected source, build and
environment inputs, purity assertions, and every derived analysis object used to
fingerprint or check a caller-supplied subject set. A view is immutable after it is
constructed; sharing within it may change cost, never what it observes.

**unverifiable dependence** (term): a runtime dependence on state that is not
source and cannot be hashed — file or network I/O, a runtime-loaded plugin, an
externally linked C library — so that a subject reaching it can be neither proven
valid nor shown stale by source alone.

## The contract

**REQ-fresh-verdict** (behavior): gofresh MUST report a subject's stored
fingerprint as exactly one verdict against the current tree — valid when every
applicable guard holds over a sound over-approximation of the source closure, so
the stored result may be reused; stale when some applicable guard demonstrably
fails, so the result is recomputed; unverifiable when every guard would hold but
the source closure reaches an unverifiable dependence, so validity can be neither
proven nor refuted and the result is recomputed with the reason recorded. A
verdict's reason is human-oriented diagnostic data: its wording is not a stable
vocabulary and carries no contract beyond accompanying its status — with one
exception: the reason "test variants" is stable vocabulary a consumer may
discriminate on, reporting test-variant compartment drift under an unchanged
core, or a recording that predates the compartment and fails closed
(REQ-closure-test-variant-identity).

**REQ-fresh-sound** (invariant): A subject MUST be reported valid only when every
applicable guard provably holds over a source closure that is a superset of the
source able to affect the subject — every gap in the static picture resolved to a
precise edge, widened to the maximal sound closure, or downgraded to unverifiable,
never silently dropped, and absence of proof yielding unverifiable rather than
valid.

> The one forbidden outcome is a false valid: a result reported reusable while the
> source or environment behind it has changed. Over-approximation — a spurious
> stale or unverifiable — is always safe. Every other requirement serves this one.

**REQ-fresh-observation-conjunction** (invariant): Closure-level external-input
unverifiability MUST be suppressed by observation only when a recognized attributable
observation-completeness assertion, compatible observability proof, completed runtime
manifest, matching runtime digest, and every ordinary applicable guard all hold. The
proof suppresses only the closure effects it proves observable; any runtime-manifest
unverifiability or other closure blind spot still prevents validity. Purity remains a
separate, broader caller-responsible override.

**REQ-fresh-observation-compatibility** (invariant): Recorded observability evidence
MUST be usable only when its non-empty recognized strategy/version, subject identity,
maximal closure hash, assertion attribution, and complete disposition agree with its
integrity evidence. An unchanged maximal hash may retain compatible evidence; after
maximal drift the recording is stale on its closure before any observability
evidence is consulted (REQ-fresh-hierarchical-check), and missing,
unrecognized, incomplete, or inconsistent evidence never suppresses
unverifiability. Changing any proof rule that can change a disposition requires a new
strategy/version identity even when source is unchanged.

**REQ-fresh-observation-data** (invariant): The observation-completeness assertion
attribution and observability proof strategy/version, subject, disposition, and
integrity evidence MUST be fingerprint constituents exposed as data beside
purity, result kind, and guard values, their record form the fingerprint's
(REQ-fresh-fingerprint-record). Empty assertion and proof evidence means the lift was not selected; partial,
unknown, or internally inconsistent evidence confers no proof.

**REQ-fresh-observation-lifecycle** (invariant): Observability proof MUST be selected
explicitly by the caller for capture, checking, and producer validation. A producer
captures the proof from the same pre-execution analysis view as its closure, attaches
the completed runtime evidence after execution, and persists only after validation
re-establishes every selected tier against the post-execution view. Historical
recordings cannot be upgraded to observability evidence without rerunning the
subject.

**REQ-fresh-guard-set** (behavior): A caller MUST check a result under the code
guards always, and under the measurement guards only when the result is a timing
measurement — so a benchmark measurement is guarded against machine and runtime
configuration drift, while a test verdict, which neither can change, is not.

**REQ-fresh-go-command-policy** (behavior): Every `go` command gofresh
spawns itself MUST run through the go-command policy's runner: under one
complete normalized environment (deterministic order, duplicate keys
refused, `PWD` derived from the command's directory, the ordinary loader
pinned; one setter keeping that order), under the process-boundary rule
its runner carries where the runner carries one — the plain runner
carries none; a consumer's runner applies the one rule to every command
it prepares (the child in its own process group, a cancellation sweeping
the group, an already-gone group the process-done case, a wait delay
bounding the reap — a named delay, else the policy's default — and a quit
grace on a cause the consumer names, the reap then bounded by the grace
and the delay together) — reading go's environment through one
pass-scoped reader whose
one snapshot every same-pass key reads, resolving directories to one
canonical coordinate with its degrading form; and a runner installed on
an engine by its option reaches every go command that engine spawns
itself — the loader's `x/tools` children excepted, which carry the
policy's environment and spawn outside any hook — while a consumer's
runner reaches the commands that consumer spawns through it; and the
policy's structured readers — the toolchain sample, the environment
snapshot, a consumer's runtime-input roots probe — serve the answer a
cleanly exited process wrote beside a descendant's pipe hold past the
wait delay when it is whole by the reader's own test (a go version's
first line; a document that parses to its keys) and the context is
live — a caller's cancellation is never answered from the hold — and
refuse a torn answer naming the hold. Enforced by
`TestEngineSpawnsThroughTheInstalledRunner`,
`TestEngineSpawnSitesReadARunner`,
`TestTakeEnvSnapshotServesTheSalvagedAnswer`,
`TestRootsProbeServesTheSalvagedAnswer`, and
`TestSalvagedRefusesUnderACancelledContext`.

**REQ-fresh-toolchain-skew** (behavior): A consumer MUST refuse to judge
records under a language-series disagreement between the analyzing
binary's build toolchain and the ambient toolchain of the tree's module,
sampled by `go env GOVERSION` in the target module's directory (never
the tool's own working directory: under GOTOOLCHAIN=auto the selected
toolchain is per module) — the sample gofresh's go-command policy
performs for every consumer, so no consumer spells the sampling contract
itself: memoized per directory coordinate and environment for a
sampler's lifetime, a cancelled sample never memoized, the answer a
cleanly exited process wrote kept when a descendant holds its pipe past
the wait delay, and composed with this judgment into the one typed
provenance refusal every consumer's judged run answers with — an
unidentifiable ambient toolchain named with the frontend and the cause,
a breaking skew in this clause's words. Enforced by
`TestSampleGoVersionRunsInTheModuleDirectory` and
`TestToolchainProvenanceIsOneRefusal`.
Within a major the refusal is directional — a frontend older than the
ambient series refuses, since it predates the sources' language, while a
newer frontend reads older language under the Go 1 compatibility
promise; across majors both directions refuse; an unidentifiable version
on either side refuses. This is the guard the closure identity's
exclusion of the analyzing frontend rests on
(REQ-closure-identity-strategy).

**REQ-fresh-commit-independent** (invariant): The validity predicate MUST depend
only on the guards, never on the raw commit identity of the recording or of the
current tree — two recordings that agree on every guard but differ in commit
receiving the same verdict, so an unrelated commit never invalidates a result
whose inputs are unchanged.

**REQ-fresh-fingerprint-data** (structural): A fingerprint MUST be exposed as its
constituent guard values, maximal closure hash, test-variant compartment hash, the
closure identity's derivation (REQ-closure-identity-strategy in
[closure.md](closure.md)), the shared-dynamic-state facts' derivation, and
optional attributable observation-completeness assertion and observability proof
evidence, attributable purity assertion, runtime-input evidence, and result kind
as data, and published in one record form (REQ-fresh-fingerprint-record) — the
caller stores that form beside its result and pins its own further facts beside
it (REQ-fresh-caller-pins), never a second encoding of the fingerprint's own.

**REQ-fresh-fingerprint-record** (wire): The fingerprint's record form MUST be
one JSON object, encoded and decoded by the fingerprint itself: the keys
`maximalClosure`, `testVariantClosure`, `toolchain`, `buildConfig`, and numeric
`resultKind` always present, in that relative order; `machine` and
`runtimeConfig` (the measurement guards), `observationAssertion`,
`observationProof`, `purityAssertion`, `dynamicStateVouches`,
`singleSubjectDischarges`, `packageProcessDischarges`, `dynamicStateStrategy`,
`closureStrategy`, `runtimeInputs`, and `runtimeDigest` each present exactly
when its value is non-empty, in the order listed between `buildConfig` and
`resultKind`; the guards flattened to their four keys; the observation proof an
object of `strategy`, `package`, `symbol`, `observable`, `reason` (present
exactly when non-empty), and `evidence`, present exactly when the proof is
non-zero. Decoding an encoded fingerprint yields it exactly, and a record
decodes only when it is the form's own encoding of what it decodes to up to
insignificant whitespace — a reordered or empty-valued record is refused, an
indented one decodes, a parent document being free to indent its nested values —
so encoding a decoded record yields the record's compact bytes exactly, and a
consumer derives a record's name from the value's encoding. The form owns its
escaping: the bytes are the same under any parent encoder's escaping setting. A
strategy key absent from a record decodes to the empty strategy, which the check
judges stale (REQ-closure-dynamic-state-memo, REQ-closure-identity-strategy) —
absence is never filled in. A decoder refuses — naming a well-formed record's
fault in the record's own vocabulary, never an internal type; malformed JSON is
the encoding library's refusal — a key the form does not define, a duplicated
key, an explicit null, trailing data after the object (where the entry point has
not already refused it), a proof without its observable, a positive proof
carrying a reason, and every fingerprint the validity ladder refuses — a result
kind that is neither code-result nor measurement (zero is a recording written
without one) and a code-result fingerprint carrying a measurement guard
(REQ-guard-selective-capture); the encoder refuses the ladder's refusals so an
invalid record is never written, and the ladder is exposed as data for a caller
assembling a fingerprint another way. A refused record decodes to nothing.
Observation evidence a decoded proof carries that the check finds inconsistent
confers no proof (REQ-fresh-observation-data) but is not a decoding refusal — a
stored record stays readable. Enforced by TestFingerprintRecordIsTheFleetForm,
TestFingerprintRecordRoundTrips, TestFingerprintRecordRefusals.

> Compatibility posture of the test-variant partition: every recording captured
> before the compartment existed is stale exactly once against a partitioned
> check — a package with test files no longer folds them into its recomputed
> core, so the recorded core cannot match, and a package without test files
> carries an empty recorded compartment, which fails closed
> (REQ-closure-test-variant-identity). This one-time global
> staleness is accepted: recomputing every pre-partition result is the safe
> direction, and the alternative — honoring old evidence whose covered set
> differs from the current computation — would be a false valid waiting to
> happen.

**REQ-fresh-hierarchical-check** (behavior): A check MUST compare the maximal closure
first. When the maximal hash is unchanged, the test-variant compartment is
compared next: a drifted or absent recorded compartment is stale with reason
"test variants" (REQ-closure-test-variant-identity). When the maximal hash
changed, the recording is stale. Guards other than the source closure still
apply normally after source equivalence is established.

**REQ-fresh-coherent-view** (invariant): Every closure, guard, selected source file,
purity assertion, package listing, syntax tree, SSA program, and reachability fact
used by one fingerprint or verdict MUST belong to the same analysis view — never a
mixture of cached metadata from an earlier tree with bytes or environment values
from a later one — because a mixed generation can agree with a recording while
describing no build that existed. Analysis state does not cross view
generations: constructing a current-tree view re-observes the tree and
environment rather than inheriting first-use state from an older view,
while sibling views derived from one parent share that parent's single
observation by contract (REQ-fresh-producer-view's sibling clause) —
one generation, never a mixture. The complete process environment used
for Go commands and package loading is immutable analysis configuration: by default
the environment captured when the engine is constructed, or an explicit complete
environment supplied by the caller. Values the go command additionally reads from
its environment file are not immutable: a later analysis bracket may reuse the
view's construction-time reading only for module-cache resolution, must
revalidate build-flag values live before any load whose derivations persist,
and relies on its closing observation's fresh reading to refuse any
guard-covered drift. Every source load, Go invocation, purity scan,
and guard observation in the view uses that same environment, so workspace mode,
persistent Go configuration, toolchain selection, and source selection cannot differ
between the closure and the binary the guards describe. The host process selects the
`go` launcher before that complete environment is inherited, matching Go's command
execution and package-loader semantics; `GOTOOLCHAIN` inside the environment selects
the effective toolchain. A command with an explicit working directory derives `PWD`
from that directory, matching package loading rather than inheriting a stale lexical
path that could select a different automatic workspace. External
`GOPACKAGESDRIVER` source providers are refused,
and absent driver configuration is pinned off only in the internal package-loader
environment, without changing the caller environment observed by commands, guards,
or runtime inputs, because the ordinary Go loader is the source model the closure and
guards represent. Checking re-observes the view's inputs around its
runtime-input and precise-analysis windows to detect ordinary drift — any change
persisting to an observation makes the check fail with the view-changed error —
but, like producer validation, it cannot prove the absence of a
mutation-and-restore interval between agreeing observations. Observations split
by purpose: an observation that becomes the record — view construction —
requires the agreement pair, because a torn recorded fact describes no build
that existed; a comparison-only observation — validation against already
captured facts — requires no agreement pair: a single observation suffices —
or, for an analysis bracket or a runtime-input window, it opens on
already-agreed facts and reads only at close — because a torn read can only compare unequal and
refuse, and an equal torn read is exactly the excluded restore interval.
A caller whose check verdicts are consumed only under a later successful
validation of the same view can defer each check's closing base
observation to that validation: the validation's one comparison
observation closes every deferred interval at once — a change persisting
to it refuses there, and the refusal discards the provisional verdicts
with it — while the change-and-restore residual widens from each check's
own close to the validation, carried by the same caller-owned
execution-span exclusion that producer validation states
(REQ-fresh-producer-view).

**REQ-fresh-producer-view** (behavior): A caller producing results for several
subjects MUST persist fingerprints captured before execution, with runtime-input
evidence attached afterward, only when their shared producer analysis view still
validates against the source, build inputs, guards, purity assertions, and every
closure tier captured after execution. The caller owns execution and excludes source or build-input mutation while
the view is constructed and the producing build is read; validation detects ordinary
drift but cannot prove the absence of a change-and-restore interval the caller
allowed. Beside the caller's context error (REQ-fresh-context), a validation
has three typed refusals, each matched by identity: a
subject the view held that the source no longer declares is the unknown-subjects
value (REQ-fresh-preparation); an observation proof the analysis could not
re-derive is the analysis-unavailable refusal; and drift is the view-changed
refusal — the view no longer describes the current source, build, guard, or
purity state and its results must not be persisted — which names its drift:
the class and, where
subject-scoped, the subject, and for source and closure drift the differing
source identities themselves — membership changes named exactly, content
drift best-effort from construction-time per-file digests — so a consumer's
refusal can name the moved file instead of only the subject; an unattributable
content drift keeps the bare refusal, naming being advisory where detection
is the comparison itself. The naming is advisory prose for a human or an
error-wrapping consumer, never a machine grammar; construction-time
agreement refusals name identically — the construction race is the one
refusal with no reproduction path afterward. A view also derives sibling
views over subsets of its subjects: a sibling's recorded facts are
exclusively the parent's one observation — closures, guards, purity,
source identities, digests, ledgers, and captured observation proofs —
so derivation itself observes nothing, and a caller whose parent
captured proofs batch-wide runs one producer transaction per measured
subset for one observation; the sibling owns its transaction
(runtime-evidence attachment and its own validation seal, with a sealed
parent still free to derive). Comparison-side observation is unchanged:
a sibling's validation re-observes the tree exactly as any view's, an
observed capture over a subject whose proof the parent never captured
computes it fresh, and a subject outside the parent refuses.

**REQ-fresh-context** (behavior): Analysis-view construction, checking —
maximal and observed alike — and producer validation MUST honor caller
cancellation before and between source, guard, runtime-input, precise-analysis,
and comparison observations, returning the context error rather than a partial
view, verdict, or successful validation. One operation observes one caller
context: no observation phase of a cancelled operation continues under a private
uncancellable context. The context bounds observation work; a producer validation
attempt still seals its original view against later capture. Bounding only the
optional precise-analysis tier while still answering from cheaper evidence is
expressed through a caller-supplied analysis budget, never through cancellation:
a proof refused under an exhausted budget names the budget in its unavailable
reason, the pass reports the exhaustion once with the count of subjects it left
unproven, and a validation the budget cut reports the unavailability only after
every other check of the validation passed, the runtime-input comparison closing
the proof pass included.

**REQ-fresh-preparation** (invariant): Every refusal an operation can decide from
inputs it already holds — the package listing, the recorded record's shape, kind,
and membership, the attachment set, the caller's declarations — MUST fire before
the operation pays any cost the refusal makes moot: before the typed load, the
closure fold, the observation window, or any process it spawns for work the
refusal moots. A refusal that surfaces after such a cost is wasted work the
caller could not avoid, and the partial result it interrupts is never a partial
verdict (REQ-fresh-context): preparation refuses the whole batch before any
window opens, and a refusal decided per subject — a subject the selected source
does not declare — names every such subject of the batch at once, each once, in
the batch's request order, so the caller narrows its batch in one step. That
refusal is one typed value carrying exactly that set, and the same typed value
names, from any re-observation of a built view — a validation, an observed
capture, a check window's close — a subject the view held that the source no
longer declares.

**REQ-fresh-progress** (behavior): An operation MUST report, through the
caller's progress sink, each unit of work at the moment it begins — an
observation pass, a runtime-input observation, a package's listing, typed load,
program load, closure fold, and observability slice — naming the unit and, where
the operation knows it, its position among the operation's units; once per
operation and memo class, the distinct packages a persistent memo served in
place of a unit; and, when an operation returns its caller's context error, what
it persisted before stopping, so a rerun's served set is known. A phase that
carries a diagnostic — an unaudited toolchain selection, an unavailable
analysis's per-subject provenance, an exhausted analysis budget with the count
of subjects it left unproven, a listing this build cannot model, what a cancelled
operation persisted — delivers it on the event's own diagnostic field,
never on the error channel and never on any memoized, hashed surface, so a
consumer prints the diagnostics alone and a walk-order-dependent payload reaches
the operator without entering an identity. The event renders its own diagnostic
line — the phase, the package where the event names one, and the detail, a
multi-line one folded onto the single line — and a consumer printing diagnostics
without a rendering of its own prints that rendering, the sink it installs
serializing its writes, so every tool's log spells an engine diagnostic one way.
The per-unit phase set is exported beside the event, so a consumer's keep-alive
names a stretch for exactly the units and never spells the set itself. Progress
events are keep-alive facts about work, never verdict evidence.

**REQ-fresh-view-source-identities** (behavior): An analysis view MUST expose the
exact mutable source-file identities whose bytes contribute to each subject's
maximal closure or its package's test-variant compartment and their view-wide
union, excluding standard-library and
immutable module-cache source represented by other guards. Subject-local queries
must not include identities contributed only by another subject in the same
view, so a producer can prove whether the selected bytes behind each result are
reproducible from caller-owned provenance without reimplementing closure file
selection.

## Composition

A caller's record is rarely about a single subject. A mutation kill-sheet is keyed
on the mutated symbol *and* every test that vouches for it, and re-measures when
any of them moves; it also pins facts no source analysis can see, such as the
mutation engine's operator-set version and its per-symbol budget. gofresh answers
freshness for one subject; assembling those answers, and adding domain pins, is the
caller's.

**REQ-fresh-compose** (behavior): gofresh MUST fingerprint one subject at a time
and leave composition to the caller — a record keyed on several subjects, such as a
mutated symbol together with the tests that vouch for it, is fresh only when every
subject's fingerprint is valid, so multi-subject freshness is the caller's
conjunction over per-subject verdicts.

**REQ-fresh-caller-pins** (behavior): A caller MAY pin further facts that gofresh
does not model — an engine or operator-set version, a budget, any domain input —
beside a subject's fingerprint, and a change to such a pin stales the caller's
record on its own terms, independently of the subject's verdict.
