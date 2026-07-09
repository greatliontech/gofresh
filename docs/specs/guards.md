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
variables), and the build flags (`GOFLAGS` and build-affecting pass-throughs) —
because each changes the compiled binary, and so any result about it, independently
of the timing environment; the target platform lives here rather than in the machine
guard precisely so it is still checked when measurement guards are off.

> Placing `GOOS`/`GOARCH` in the code-guard digest, not the machine fingerprint, is
> deliberate: a non-timing consumer (a mutation kill-sheet) runs with measurement
> guards off, yet a cross-compile still changes the compiled code and thus the
> result. A code-determining input must be a code guard, or it is a false-valid hole
> for exactly the consumers that drop measurement guards.

**REQ-guard-buildconfig-failclosed** (behavior, refines REQ-guard-buildconfig): A
build-affecting input the build-configuration guard cannot parse or bound MUST fail
closed, the recording refused, rather than digest to a value that could stay stable
across different generated code — a guard that silently misses a build input is a
false valid, so an unrepresentable input is a hard capture error, never a best-effort
digest.

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

**REQ-guard-recompute** (behavior): A subject's closure hash for its recorded commit
MUST be recorded at run time from the working tree, and its closure hash for the
current tree recomputed on demand at check time and the two compared — never
reconstructing a historical build — so a verdict needs no fragile checkout and rests
only on the current tree and the recorded value.

**REQ-guard-cache** (invariant): A persisted closure hash MUST be treated as a
memoization keyed only by immutable inputs — the commit, the toolchain, and the build
configuration — never as the source of truth, so recomputing or discarding it never
changes a verdict, and a cache that disagrees with recomputation from source can
never make an unsound result look valid.

**REQ-guard-completeness** (invariant): A recorded fingerprint missing a value
required to evaluate a guard that applies to its result MUST be treated as stale, not
valid — validity requires proof, so an unevaluable guard is absence of proof, and a
recording written before a guard existed re-measures rather than being trusted.
