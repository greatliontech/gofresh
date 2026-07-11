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
under the old toolchain.

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
`-pgo`) and PGO profile content — which the caller supplies as it does the commit,
since only the caller knows how it built; a caller that passes none asserts it used
none. Caller-supplied inputs have two disjoint forms: executable build flags select
the source and configuration used by every source-dependent analysis, including
purity directives, and also enter the digest; opaque build evidence such as a PGO
profile's content digest enters the digest but cannot select source. A build flag
presented as opaque evidence is refused rather than hashed without being applied,
because the resulting guard and closure would describe different binaries. A build
flag whose selected source the analysis cannot represent, such as a Go overlay, is
also refused rather than evaluated against different disk content.

> Placing `GOOS`/`GOARCH` in the code-guard digest, not the machine fingerprint, is
> deliberate: a non-timing consumer (a mutation kill-sheet) runs with measurement
> guards off, yet a cross-compile still changes the compiled code and thus the
> result. A code-determining input must be a code guard, or it is a false-valid hole
> for exactly the consumers that drop measurement guards.

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

## Recording and recomputation

**REQ-guard-recompute** (behavior): A subject's maximal closure hash and any selected
refinement evidence for its recorded commit MUST be recorded at run time from the
working tree. A newly constructed current analysis view recomputes the maximal hash
and, only after maximal drift under a caller-selected refined check, the current
refinement — never reconstructing a historical build — so a verdict needs no fragile
checkout and rests only on the current view and recorded evidence. Several subjects
can share one explicitly bounded current view; a prior producer or current view never
silently becomes the next check's current state.

**REQ-guard-cache** (invariant): Persisted closure evidence MUST be treated as
memoization keyed only by immutable inputs — the commit, the toolchain, the build
configuration, the subject identity, and for refinement its strategy/version — never
as the source of truth, so recomputing or discarding it never changes source
equivalence, and evidence that disagrees with recomputation from source can never
make an unsound result look valid.

**REQ-guard-view-lifetime** (invariant): Environment guards MUST be re-observed for
every new analysis view, with capture shared only by subjects inside that view and
never memoized by module directory across views. A producer view
therefore freezes the guards inherited by its producing process, while a later
current view sees toolchain, build, machine, or runtime-configuration drift.

**REQ-guard-completeness** (invariant): A recorded fingerprint missing a value
required to evaluate a guard that applies to its result MUST be treated as stale, not
valid — validity requires proof, so an unevaluable guard is absence of proof, and a
recording written before a guard existed re-measures rather than being trusted.

**REQ-guard-selective-capture** (behavior): An analysis view MUST capture exactly the
guards applicable to its caller-declared result kind. A code-result view captures the
code guards and leaves machine and runtime-configuration values absent without
probing machine support; a measurement view additionally captures both measurement
guards. The view's result kind is fixed at construction and a check under another
kind is refused. Every fingerprint records that nonzero kind and a check derives its
view policy from the recording rather than accepting a replacement kind from the
caller; missing or mismatched kind evidence is refused. Unavailable measurement
support therefore cannot block a code result, and a measurement recording cannot be
validated under code-only guards. A code-kind fingerprint carrying non-empty
measurement guard values is internally inconsistent and refused rather than treated
as permission to ignore them.
