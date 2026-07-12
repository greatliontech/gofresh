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
subject's maximal source-closure hash, optional refinement evidence, any attributable
purity assertion used to override unverifiability, the result kind selecting its
applicable guards, and the value of every applicable guard.

**refinement evidence** (term): an optional recording of a narrower sound source
closure: its hash, unverifiable-dependence disposition, and stable strategy/version
and subject identities. It can recover reuse after maximal closure drift but never
substitute for the maximal closure recording.

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
proven nor refuted and the result is recomputed with the reason recorded.

**REQ-fresh-sound** (invariant): A subject MUST be reported valid only when every
applicable guard provably holds over a source closure that is a superset of the
source able to affect the subject — every gap in the static picture resolved to a
precise edge, widened to the maximal sound closure, or downgraded to unverifiable,
never silently dropped, and absence of proof yielding unverifiable rather than
valid.

> The one forbidden outcome is a false valid: a result reported reusable while the
> source or environment behind it has changed. Over-approximation — a spurious
> stale or unverifiable — is always safe. Every other requirement serves this one.

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
attributable purity assertion and result kind as data, carrying no persistence or wire format of its own — the caller owns how a
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

**REQ-fresh-refinement-failclosed** (behavior): Refinement is performed only through
a caller-selected refined operation, under the caller's cancellation or budget;
gofresh MUST NOT infer whether a subject is expensive enough to refine. Missing,
incomplete, or incompatible recorded refinement after maximal drift is stale. A
current refinement that is unavailable, fails, is cancelled, or exhausts its
caller-supplied budget is unverifiable or stale, never valid. A caller can select an
unbounded refinement operation explicitly.

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
guards represent.

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

**REQ-fresh-view-source-identities** (behavior): An analysis view MUST expose the
exact mutable source-file identities whose bytes contribute to its maximal closure,
excluding standard-library and immutable module-cache source represented by other
guards, so a producer can prove whether those selected bytes are reproducible from
caller-owned provenance without reimplementing closure file selection.

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
