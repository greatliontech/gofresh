# Guards

A guard is one comparable fact about how a result was produced. The source closure
is the first guard; this document defines the rest and the rule that binds them —
each is a drift check compared by exact equality, and a fingerprint that cannot
evaluate an applicable guard is stale, never valid. The split between code guards,
which bear on every result, and measurement guards, which bear only on a timing
result, is fixed here per guard.

**toolchain guard** (term): the guard over the Go toolchain identity that built the
result.

**build-configuration guard** (term): the code guard over the build-affecting inputs
that determine generated code without moving the toolchain or the source closure.

**machine guard** (term): the measurement guard over the stable physical-machine
facts on which a timing measurement was taken.

**runtime-configuration guard** (term): the measurement guard over the Go
runtime-configuration environment the measured process inherited.

## Comparison

**REQ-guard-equality** (behavior): The toolchain guard, build-configuration guard,
machine guard, and runtime-configuration guard MUST each be evaluated by exact
equality between the recorded value and the current value — every one is a drift
check asking "the same as when this was recorded?", not a normalization across
environments, so any difference makes the result stale.

## Code guards

**REQ-guard-toolchain** (behavior): The toolchain guard MUST record the Go toolchain
identity — the version string including any experiment or custom suffix that affects
code generation — so a toolchain change, which moves the standard library and
generated code the closure deliberately does not hash, stales every result recorded
under the old toolchain. This reported identity is not proof that selected
standard-library source has unchanged content or justified semantics. Dependent
analysis and recorded proof additionally obey REQ-fresh-dependency-identities
and [closure.md](closure.md); the label
does not replace complete selected-content evidence, a checked derivation or
its compatibility judgment.
The identity is read from the pass's one environment
snapshot (`GOVERSION` with `GOHOSTOS/GOHOSTARCH`), byte-identical to the `go version`
line minus its prefix, so a pass samples its toolchain once; a snapshot answering
any of the three empty refuses the capture naming the key — a derived identity is
never non-empty over an empty part. Enforced by
`TestToolchainGuardIsGoVersionsOwnForm`.

**REQ-guard-buildconfig** (behavior): The build-configuration guard MUST digest every
build-affecting input that can change generated code without moving the toolchain or
the source closure — the target platform `GOOS` and `GOARCH`, the codegen feature
level (`GOAMD64`, `GOARM`, `GOARM64`, `GO386`, `GOEXPERIMENT`), the cgo toolchain
environment (`CGO_ENABLED`, the `CGO_*FLAGS`, `CC`, `CXX`, the `PKG_CONFIG*`
variables), the `GOFLAGS` build flags, and the build inputs the caller supplies —
because each changes the compiled binary, and so any result about it, independently
of the timing environment; the target platform lives here rather than in the machine
guard precisely so it is still checked when measurement guards are off. The build
inputs are the build-affecting parts of the invocation the engine cannot observe from
`go env` — CLI flags passed outside `GOFLAGS` (`-tags`, `-gcflags`, `-ldflags`,
`-pgo`) and PGO profile content — which the caller supplies, since only the
result owner knows the actual build description. An explicitly declared empty
set accepts responsibility that no additional build inputs were used;
accidentally missing information about a producing build is not that declaration.
Toolchain defaults that consume inputs, including an applicable default PGO
profile, remain inputs even when the caller supplied no corresponding flag.
Caller-supplied inputs have two disjoint forms: executable build flags select
the source and configuration used by every source-dependent analysis, including
purity directives, and also enter the digest; opaque build evidence such as a PGO
profile's content digest enters the digest but cannot select source. A build flag
presented as opaque evidence is refused rather than hashed without being applied,
because the resulting guard and closure would describe different binaries. A build
flag whose selected source the analysis cannot represent, such as a Go overlay, is
also refused rather than evaluated against different disk content. The engine's
complete Go-command environment is applied identically to package loading and guard
capture; it selects source and toolchain rather than riding as opaque evidence, while
the relevant values observed through `go env` and the process environment enter the
guard digest under this clause.

> Placing `GOOS`/`GOARCH` in the code-guard digest, not the machine fingerprint, is
> deliberate: a non-timing consumer (a mutation kill-sheet) runs with measurement
> guards off, yet a cross-compile still changes the compiled code and thus the
> result. A code-determining input must be a code guard, or it is a false-valid hole
> for exactly the consumers that drop measurement guards.

**REQ-guard-explicit-build** (behavior): An explicitly described producing
build MUST retain its complete normalized compilation environment separately
from the runtime environment of its retained artifact. The ordinary package
driver is pinned and the command directory supplies PWD before that description
is used by analysis or compilation. Equality of selected environment keys or of
Go's reported settings alone does not license different compilation environments:
a compiler wrapper can consume other variables. The explicit form's build guard
includes all raw compilation-environment entries, every resolved Go setting,
ordered executable flags and the explicitly present additional-input declaration,
including a present-empty declaration. A declared GOENV file is additionally a
raw-byte dependency; absent, present and disabled remain distinct. These mutable
resolved inputs are re-observed at closing, not cached for the session's lifetime.
The guard's additional domain is `gofresh/build-description@1`; its environment
identity uses SHA-256 over counted, byte-length-framed strings, preserving invalid
UTF-8 and absent versus empty entries. The generated work-directory operand in
Go's GOGCCFLAGS prefix-map argument alone is normalized: the recognized file/debug
prefix-map flag and destination `/tmp/go-build` remain, while its absolute
`go-build`-prefixed temporary source directory is replaced by a fixed marker.
Multiple mappings, malformed quoting or an unrecognized mapping refuse admission.
Other compiler flags remain identity-bearing. This relies on the stated ordinary
compiler/linker and toolchain-cache integrity premise, including honoring that
prefix mapping; it does not assert that wrappers ignore arbitrary environment
variables. Additional compiler-file inputs remain the executor's declared-input
responsibility. Existing legacy construction accepts an omitted producer override
or an exactly equal normalized producer environment; a distinct producer
environment refuses with the explicit build/runtime migration remedy. A later
description or decoder cannot upgrade historical evidence into this guard domain.

**REQ-guard-buildconfig-failclosed** (behavior, refines REQ-guard-buildconfig): An
observable build input the build-configuration guard cannot parse — a malformed
`go env` output — MUST fail closed, the capture refused, rather than digest to a
value that could stay stable across different generated code, since a guard that
silently misses a build input is a false valid. A build input the engine cannot
observe — a CLI pass-through or PGO content — is not silently dropped either: it is
the caller's to supply, and the guard digests exactly what is supplied.

## Measurement guards

**REQ-guard-machine** (behavior): The machine guard MUST hash the stable
physical-machine facts whose change plausibly shifts a timing measurement — CPU model
and microarchitecture, physical and logical core counts, total memory, and operating
system and kernel version — so it drifts with the hardware and platform a measurement
was taken on; it bears only on a timing result and is not applied to a pass/fail one.

**REQ-guard-machine-transient** (behavior, refines REQ-guard-machine): The machine
guard MUST exclude transient run conditions — CPU governor, turbo or boost state,
thermal or load state, process pinning — because they are set deliberately for a run
and would read differently at check time, staling every result spuriously; enforcing
good run conditions is the caller's to do at run time, never baked into machine
identity.

**REQ-guard-runtimeconfig** (behavior): The runtime-configuration guard MUST digest
the Go runtime-configuration environment the measured process inherits — `GOGC`,
`GODEBUG`, `GOMEMLIMIT`, and an explicitly set `GOMAXPROCS` — read by the runtime
before execution and able to move allocation and scheduling behavior with no other
guard moving; it bears only on a timing result, an unset `GOMAXPROCS` deferring to
the core count the machine guard already covers.
The runtime guard's encoding uses the domain `gofresh/runtime-config@1` followed
by a newline, then the decimal key count and a colon. In the order `GOGC`,
`GODEBUG`, `GOMEMLIMIT`, `GOMAXPROCS`, each key and value is prefixed with its
decimal byte length and a colon. An absent value contributes the empty value.
The guard is the first 16 bytes of SHA-256, encoded as lowercase hexadecimal.
Newlines and key-shaped text inside values cannot change field boundaries.
Historical delimiter-only guards remain readable but do not acquire the new
encoding's identity; comparison requires a new measurement rather than rewriting
the recording.

**REQ-guard-runtime-relevance** (invariant): A behavior-affecting runtime or
machine dependency of a code result MUST be guarded by evidence applicable to
that result, proven irrelevant under its declared model, discharged by an
explicit assertion whose contract covers it, or left unverifiable. Omission of
measurement-only fields supplies none of those grounds. Equality of inherited
environment values alone does not guard an in-process mutation of the relevant
state; an admitted method accounts for that mutation or refuses it. The
measurement-only runtime-configuration and machine fields keep their encoding
and result-kind rules; a code-result record cannot acquire them as a substitute
for establishing relevance and appropriate evidence.

## Recording and recomputation

**REQ-guard-recompute** (behavior): A subject's maximal closure hash for its
recorded commit MUST be recorded at run time from the
working tree. A newly constructed current analysis view recomputes the maximal hash
— never reconstructing a historical build — so a verdict needs no fragile
checkout and rests only on the current view and recorded evidence. Several subjects
can share one explicitly bounded current view; a prior producer or current view never
silently becomes the next check's current state.

**REQ-guard-cache** (invariant): Persisted closure evidence MUST be treated as
memoization keyed by complete dependency identities, not a commit address or
reported toolchain label alone — source membership/content, resolved build
configuration, subject scope, inference rules, checked subordinate claims and
selected implementation content on which the fact depends
(REQ-fresh-dependency-identities and REQ-closure-observability-toolchain-key) — never
as the source of truth, so recomputing or discarding it never changes source
equivalence, and evidence that disagrees with recomputation from source can never
make an unsound result look valid.

**REQ-guard-view-lifetime** (invariant): Guard observations MUST remain scoped
to the source/build generation and, in the explicit split form, the runtime
binding whose configuration they describe, never memoized by module directory
across generations or bindings. A derived sibling view shares its parent's
source/build observation and the same runtime binding's guards
(REQ-fresh-producer-view's sibling clause). Each view re-observes compilation facts under its
engine's immutable complete compilation environment; constructing a new engine captures
later ambient compilation-environment drift. An explicit runtime binding owns
its complete runtime environment separately: applicable runtime guards are
derived and checked under that binding without replacing compilation facts or
another binding's guards. A producer view therefore freezes the guards
inherited by its producing process. A newly observed source/build generation
captures toolchain and build drift; a newly admitted runtime binding captures
its applicable machine and runtime-configuration guards, independently of other
bindings. Closing re-observes the complete applicable guard set under those same
compilation and runtime configurations.

**REQ-guard-completeness** (invariant): A recorded fingerprint missing a value
required to evaluate a guard that applies to its result MUST be treated as stale, not
valid — validity requires proof, so an unevaluable guard is absence of proof, and a
recording written before a guard existed re-measures rather than being trusted.

**REQ-guard-selective-capture** (behavior): An analysis view MUST capture exactly the
guards applicable to its caller-declared result kind. A code-result view captures the
code guards and leaves machine and runtime-configuration values absent without
probing machine support; a measurement view additionally captures both measurement
guards. In the explicit split form, the source/build generation captures the
source/build guards and its runtime binding captures the applicable measurement
guards; neither another binding nor a later generation overwrites either set.
Observed runtime-input evidence belongs to its producing unit and retained
record, and is checked under the selected runtime binding for both result kinds;
it is never shared source/build state. The view's
result kind is fixed at construction and a check under another kind is refused.
Every fingerprint records that nonzero kind and a check derives its
view policy from the recording rather than accepting a replacement kind from the
caller; missing or mismatched kind evidence is refused. Unavailable measurement
support therefore cannot block a code result, and a measurement recording cannot be
validated under code-only guards. A code-kind fingerprint carrying non-empty
measurement guard values is internally inconsistent and refused rather than treated
as permission to ignore them. This selective capture policy does not discharge
runtime or machine effects that can change the code result; their evidence is
governed separately by REQ-guard-runtime-relevance.
