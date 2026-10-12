# Runtime PWD can disappear from reusable evidence

Lands: docs/plans/tooling-redesign.md 5.1t, before another consumer adopts
the built-artifact boundary; release the correction before consumer adoption.

`runtimeinput/runtimeinput.go` admits a `getenv PWD` operation without an
identity when the value equals the actual process directory. Its premise is
that the persisted evidence already binds that directory. The explicit session
form permits two runtime directories beside the same compilation description:
`session.go` supplies the runtime PWD, while `view.go` composes the complete
build guard from the build environment. The runtime guard covers GOGC, GODEBUG,
GOMEMLIMIT and GOMAXPROCS, not PWD. `outcomeSubject` binds source/build policy,
not the runtime directory. The manifest records no frame identity.

Consequently, a subject reading PWD can run under two truthful environments
whose values differ while its reusable dependency evidence agrees. This is a
source-traced path, not a completed two-session reproduction. It requires no
dishonest execution assertion or mutation during a protected interval.

The runtime-input spec's recordless-PWD rationale contradicts its separate
statement that a manifest carries no frame identity. Reconcile that premise
with the soundness and runtime-relevance contracts rather than broadening the
caller assertion to invent a missing persisted dependency.

The deciding regression uses one retained artifact and unchanged build inputs,
two existing runtime directories, and an admitted constant-name getenv subject.
Produce, finalize, serialize/reload and check its native evidence across those
sessions. Keep same-directory and unrelated-runtime-value controls, truthful
and nontruthful PWD, and legacy entry points. Establish the behavior before
choosing whether to record the input or refuse unsupported dependence.

Historical records that omitted the dependency cannot acquire it from current
analysis or decoding. Define and enforce their eligibility at every affected
checking path. Identity-only diagnostics remain identity-only; runtime PWD must
not be folded into a compilation description that did not govern it.
