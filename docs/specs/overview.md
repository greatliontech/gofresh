# gofresh — source-closure freshness for cached results

gofresh decides whether a cached result about a Go symbol — a benchmark's
measurement, a test's verdict, a mutation finding — is still trustworthy for the
current source tree, or must be recomputed. It fingerprints the source a symbol
depends on and the environment that produced the result, and reports a verdict by
comparing a stored fingerprint against the current one. It never runs the symbol
and never owns the result store: it answers one question — *is this still fresh?* —
and leaves measuring and storing to the caller.

## Vocabulary

**subject** (term): the named Go symbol whose freshness is tracked — a function
reachable as an analysis root, such as a benchmark, a test, or any callable a
caller keys a cached result on. The unit of freshness.

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
subject's maximal source-closure hash, optional refinement evidence, optional
attributable observation-completeness assertion and observability proof evidence, any
attributable purity assertion used to override unverifiability, the result kind
selecting its applicable guards, and the value of every applicable guard.

**refinement evidence** (term): an optional recording of a narrower sound source
closure: its hash, unverifiable-dependence disposition, and stable strategy/version
and subject identities. It can recover reuse after maximal closure drift but never
substitute for the maximal closure recording.

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
vocabulary and carries no contract beyond accompanying its status.

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
integrity evidence. An unchanged maximal hash may retain compatible evidence; maximal
drift requires current caller-selected proof analysis, and missing,
unrecognized, incomplete, or inconsistent evidence never suppresses
unverifiability. Changing any proof rule that can change a disposition requires a new
strategy/version identity even when source is unchanged.

**REQ-fresh-observation-data** (invariant): The observation-completeness assertion
attribution and observability proof strategy/version, subject, disposition, and
integrity evidence MUST be fingerprint constituents exposed as data beside refinement,
purity, result kind, and guard values. They carry no engine-owned persistence or wire
format. Empty assertion and proof evidence means the lift was not selected; partial,
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

**REQ-fresh-commit-independent** (invariant): The validity predicate MUST depend
only on the guards, never on the raw commit identity of the recording or of the
current tree — two recordings that agree on every guard but differ in commit
receiving the same verdict, so an unrelated commit never invalidates a result
whose inputs are unchanged.

**REQ-fresh-fingerprint-data** (structural): A fingerprint MUST be exposed as its
constituent guard values, maximal closure hash, optional refinement evidence, and
optional attributable observation-completeness assertion and observability proof
evidence, attributable purity assertion, and result kind as data, carrying no
persistence or wire format of its own — the caller owns how a
fingerprint is serialized and stored beside its result. Refinement support is
explicit rather than inferred: a refined recording carries a non-empty recognized
strategy/version identity and complete, internally consistent refined evidence; a
maximal-only recording carries none.

**REQ-fresh-hierarchical-check** (behavior): A check MUST compare the maximal closure
before considering refinement. When the maximal hash is unchanged, it does not run
refinement analysis. When the maximal hash changed, a maximal-only recording is
stale; a refined recording under the current recognized strategy computes the
current refined closure and remains reusable only when the refined hashes agree.
A refined hash mismatch is stale. Guards other than the source closure still apply
normally after source equivalence is established.

**REQ-fresh-refinement-failclosed** (behavior): Refinement runs only under an
explicit caller-declared refinement budget on the analysis view — one capture and
one check exist, with no per-operation tier selection: under a declared budget a
capture carries refined evidence and a drifted check consumes a recording's
compatible refined evidence by computing current refinement, each refinement
operation bounded by the declared budget; absent any declaration refinement never
runs and a drifted recording is stale on its maximal closure regardless of the
refined evidence it carries — the evidence persists for a later budgeted check.
gofresh MUST NOT infer whether a subject is expensive enough to refine: cost
consent is the caller's, declared once per view. Missing,
incomplete, or incompatible recorded refinement after maximal drift is stale. A
current refinement that is unavailable, fails, or exhausts the declared
budget is unverifiable or stale, never valid; caller cancellation returns the
context error rather than a verdict. A caller can declare an unbounded budget
explicitly. When a budgeted operation needs both refinement and an observation
proof, the shared precise-analysis pass is one refinement operation for budget
purposes, and validation-time refinement inherits the producer view's declared
budget. The strategy choice can never invalidate a record: any view checks
any recording, and validation revalidates whatever the view captured.

**REQ-fresh-refinement-disposition** (invariant): When a compatible refined recording
avoids current refinement because the maximal closure is unchanged, its recorded
unverifiable-dependence disposition MUST remain applicable: the unchanged maximal hash
proves that every source input from which that disposition was derived is unchanged.
When maximal drift causes current refinement, the newly computed refined disposition
applies. Unrecognized or incomplete refinement evidence is never used to suppress
the current maximal closure's conservative unverifiability.

**REQ-fresh-coherent-view** (invariant): Every closure, guard, selected source file,
purity assertion, package listing, syntax tree, SSA program, and reachability fact
used by one fingerprint or verdict MUST belong to the same analysis view — never a
mixture of cached metadata from an earlier tree with bytes or environment values
from a later one — because a mixed generation can agree with a recording while
describing no build that existed. Analysis state does not cross view boundaries;
constructing a current-tree view re-observes the tree and environment rather than
inheriting first-use state from an older view. The complete process environment used
for Go commands and package loading is immutable analysis configuration: by default
the environment captured when the engine is constructed, or an explicit complete
environment supplied by the caller. Every source load, Go invocation, purity scan,
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
mutation-and-restore interval between agreeing observations.

**REQ-fresh-producer-view** (behavior): A caller producing results for several
subjects MUST persist fingerprints captured before execution, with runtime-input
evidence attached afterward, only when their shared producer analysis view still
validates against the source, build inputs, guards, purity assertions, and every
closure tier captured after execution. Maximal mode captures and validates only
maximal evidence; refined mode captures and validates maximal and refined evidence
under caller-selected refinement operations. Historical maximal-only evidence cannot
be upgraded to refined evidence after execution, so switching policy requires one
rerun. The caller owns execution and excludes source or build-input mutation while
the view is constructed and the producing build is read; validation detects ordinary
drift but cannot prove the absence of a change-and-restore interval the caller
allowed.

**REQ-fresh-context** (behavior): Analysis-view construction, checking —
maximal, refined, and observed alike — and producer validation MUST honor caller
cancellation before and between source, guard, runtime-input, precise-analysis,
and comparison observations, returning the context error rather than a partial
view, verdict, or successful validation. One operation observes one caller
context: no observation phase of a cancelled operation continues under a private
uncancellable context. The context bounds observation work; a producer validation
attempt still seals its original view against later capture. Bounding only the
optional precise-analysis tier while still answering from cheaper evidence is
expressed through a caller-supplied analysis budget, never through cancellation.

**REQ-fresh-view-source-identities** (behavior): An analysis view MUST expose the
exact mutable source-file identities whose bytes contribute to each subject's
maximal closure and their view-wide union, excluding standard-library and
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
