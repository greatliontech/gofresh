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
subject's source-closure hash together with the value of every applicable guard.

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
constituent guard values and closure hash as data, carrying no persistence or wire
format of its own — the caller owns how a fingerprint is serialized and stored
beside its result.

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
