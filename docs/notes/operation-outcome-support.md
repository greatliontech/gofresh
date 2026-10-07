# Operation-outcome support: failure-sensitive feasibility

The [runtime-input contract](../specs/runtime-inputs.md) requires operation-outcome
support independently of process completion. Identity logs and stable guarded
values cannot establish this premise for ordinary filesystem reads. Environment
lookups offer a narrower candidate derivation, provided the complete producing
execution is proved to satisfy its assumptions.

## Filesystem counterexample

On Linux with `go1.27.1-X:nodwarf5`, an isolated Go test binary reads a fixed
21-byte regular file using `os.ReadFile`, prints the returned length and error,
and finishes without failing the test. The same binary runs normally and under
`strace` syscall fault injection, restricted to the input file:

- `-f -P <input> -e trace=read,openat -e inject=read:error=EIO`
- `-f -P <input> -e trace=read,openat -e inject=read:error=EIO:when=2`
- `-f -P <input> -e trace=read,openat -e inject=openat:error=EMFILE`

Each invocation receives its own `-test.testlogfile`. The experiment checks
the exit status, byte-for-byte identity-log equality, and unchanged input content
hash, mode, size, modification time and change time after every invocation.
The harness also retains stdout and asserts the reported API return values below
and an injected-failure marker in each fault trace. The standalone recipe below
exposes those outputs for inspection without depending on that harness.

| Execution | Returned bytes | Returned error | Exit |
|---|---:|---|---:|
| Ordinary read | 21 | nil | 0 |
| First read fails | 0 | EIO | 0 |
| Read after content delivery fails | 21 | EIO | 0 |
| Open fails | 0 | EMFILE | 0 |

Every capture contains the same header and one `open <input>` identity. The
trace marks the failed syscall as injected. The third row matters independently
of the first-read failure: content equality alone would overlook a returned
error even after all content was delivered.

A second test opens the same file and performs two ten-byte `Read` calls. Without
injection both return ten bytes and nil. With the second read injected to return
EIO, the first still returns ten bytes and nil, while the second returns zero and
EIO. Both test invocations exit zero and produce identical identity logs; the
same file-state checks hold. This supplies a partial-delivery case without
changing the file or restoring it during execution.

An ordinary failing-test control performs the read and calls `t.Error`. It emits
the same identity log and exits one with the normal test failure report. That
outcome is distinct from a crash or kill: a completion receipt must describe
harness completion separately from the result's pass/fail verdict.

These are counterexamples to the proposed implication from stable values,
identity capture and process health to operation-outcome agreement. They are
not end-to-end cached-verdict reproductions: the diagnostic printing and fault
injector are experiment machinery, and no observability proof or freshness
verdict was evaluated. They establish neither a historical false-valid incident
nor coverage of every filesystem failure mode.

## Why environment lookup is different

The audited Linux Go implementation routes `os.Getenv` and `os.LookupEnv` through
`syscall.Getenv`, which reads the process's initialized environment map under a
read lock. There is no fallible filesystem delivery in that lookup. For a
representable key under an unchanged complete process environment, the returned
value and presence bit are derivable from that environment. Absence and a
present empty string remain different guarded states.

Three fresh-process controls looked up one fixed key under an absent binding,
an empty binding and the value `supported`. They returned respectively
`("", false)`, `("", true)` and `("supported", true)`. All exited zero and
emitted the same `getenv` identity. Here the exact inherited environment, not
the identity log alone, supplies the distinguishing value.

This is a candidate supported operation class, not an implemented support
constructor. Its proof obligations include:

- The audited toolchain and platform implement the modeled lookup semantics.
- The environment hashed is exactly the complete environment inherited by the
  contributing process, with platform key semantics preserved.
- No initialization, user test-main flow, subject, cleanup, sibling or concurrent
  contributor changes the relevant environment or bypasses the admitted effect
  model. A subject-only absence of `Setenv` is insufficient.
- The recognized capture covers the required execution and representable keys;
  missing or unflushed capture is never an empty-effect proof.
- The operation inventory independently proves that every relevant effect is
  supported. An empty log or a log containing only `getenv` cannot establish
  that inventory, because unsupported and omitted operations may emit nothing.

The Linux source inspection does not establish another platform's lookup
semantics. Unknown platform/toolchain behavior remains unsupported until audited.

## Consequences for shared evidence construction

The closure observability boolean reports admission, with a reason on refusal.
It admits filesystem operations conditionally on the producer's outcome premise;
that boolean does not distinguish an environment-only effect inventory from an
inventory needing direct filesystem outcome evidence. The separate outcome
inventory identifies the admitted derivation, without claiming it has been tied
to an actual execution. Reusing the admission boolean as an outcome-support token
would repeat the original circular inference.

A sound derivation therefore needs an independently established, versioned
effect inventory over the result-contributing execution, bound to its selected
source/build facts and environment. Proven empty effects and proven immutable
environment lookups can be distinguished from effects whose outcomes remain
unsupported. This inventory must survive the same attachment, merge and
persistence compatibility rules as the premise it supports; old observations
cannot acquire it from a new decoder or a successful later read.

For filesystem operations, direct evidence must account for returned values,
counts and errors at the admitted operation boundary, including partial delivery
and handle state. Syscall tracing in this experiment is a fault injector and
diagnostic witness, not an adopted portable outcome-capture method. A separate
instrumented rerun cannot supply evidence for an earlier timed run, and
instrumentation of the actual timed run must retain its measurement identity.

Until a method establishes those facts, filesystem outcomes remain unsupported.
The explicit purity override remains separate; it does not transform missing
outcome evidence into verified support.

## Reproducing the operation results

The following standalone fixture reproduces the operation-result observations on
Linux with Go and `strace`. Use an isolated directory at
`/tmp/opencode/outcome-support-probe` and save this as `probe_test.go`, with
`input.txt` containing exactly `stable guarded bytes` and a trailing newline
(21 bytes). Both the probe and the tracer use the same absolute input name:
relative open names did not reliably trigger path-filtered open fault injection
in the tested tracer. Check that each intended failure is marked injected in
its trace, rather than assuming the injection options took effect.
The printed operation results are the evidence to inspect against the tables
above. The identity logs alone are insufficient.

```go
package outcomeprobe

import (
    "fmt"
    "os"
    "testing"
)

func TestIgnoredReadError(t *testing.T) {
    data, err := os.ReadFile("/tmp/opencode/outcome-support-probe/input.txt")
    fmt.Printf("read bytes=%d error=%v\n", len(data), err)
}

func TestPartialReadError(t *testing.T) {
    f, err := os.Open("/tmp/opencode/outcome-support-probe/input.txt")
    if err != nil {
        t.Fatal(err)
    }
    defer f.Close()
    buf := make([]byte, 10)
    n1, err1 := f.Read(buf)
    n2, err2 := f.Read(buf)
    fmt.Printf("first bytes=%d error=%v; second bytes=%d error=%v\n",
        n1, err1, n2, err2)
}

func TestEnvironment(t *testing.T) {
    value, present := os.LookupEnv("OUTCOME_PROBE_VALUE")
    fmt.Printf("environment value=%q present=%t\n", value, present)
}

func TestNormallyCompletedFailure(t *testing.T) {
    _, _ = os.ReadFile("/tmp/opencode/outcome-support-probe/input.txt")
    t.Error("ordinary test failure")
}
```

Compile with `go test -c -o probe.test probe_test.go`. Select the
`go1.27.1-X:nodwarf5` toolchain to reproduce the audited selection, and record
`go version` when testing a different one. The environment source audit is
`$(go env GOROOT)/src/os/env.go` and `src/syscall/env_unix.go` under that same
GOROOT.

Run the ordinary case with:

```sh
./probe.test -test.v -test.run='^TestIgnoredReadError$' -test.testlogfile=normal.log
```

For each fault, run the following, replacing `<fault>` with the injection
expression and `<case>` with a unique output name. Retain the displayed stdout
as the API-result transcript alongside the trace and identity log.

```sh
strace -f -P "$PWD/input.txt" -e trace=read,openat -e inject=<fault> \
  -o <case>.trace ./probe.test -test.v -test.run='^TestIgnoredReadError$' \
  -test.testlogfile=<case>.log
```

Use `read:error=EIO`, `read:error=EIO:when=2`, and `openat:error=EMFILE`.
Repeat the ordinary and second-read-failure commands with
`-test.run='^TestPartialReadError$'`. For the environment controls run
`-test.run='^TestEnvironment$'` under `env -u OUTCOME_PROBE_VALUE`,
`env OUTCOME_PROBE_VALUE=`, and `env OUTCOME_PROBE_VALUE=supported`, each with
its own capture file. Finally select `TestNormallyCompletedFailure` without
injection and expect exit one with the ordinary FAIL report. File-read cases
otherwise exit zero; environment cases exit zero. Compare each matching test's
identity logs byte-for-byte and verify the input's content and stat fields
before and after the executions.
