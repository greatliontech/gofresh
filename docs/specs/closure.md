# The source closure

The source closure is the heart of freshness: the set of declarations whose change
could move a subject's behavior. Getting it *sound* — always a superset of what can
affect the subject — is the whole obligation, because the one forbidden outcome is a
subject reported valid while source it depends on has changed. This document defines
what the closure covers and how every gap in the static picture is dispositioned so
the covered set never narrows below the truth.

**blind spot** (term): a runtime-reachable code path the static call graph does not
see — dispatch chosen from runtime data, a computed call, a linked side effect — so
that trusting the call graph alone would under-cover the closure.

**maximal closure** (term): every reachable non-standard-library package hashed
whole; the sound floor that every blind spot widens to and the closure never falls
below.

**pinned dependency** (term): a reachable module dependency whose resolved source is
immutable under the module cache, identified by its module path and version rather
than hashed per declaration.

**mutable-local dependency** (term): a reachable dependency whose resolved source is
not under the module cache — the main module, a local `replace`, a workspace `use`,
or a vendored tree — carrying no version or checksum signal, so its content can
change silently.

## What the closure covers

**REQ-closure-coverage** (invariant): The source closure of a subject MUST include
not only the functions its call graph reaches but every constant, type, and
package-level variable those functions reference, the initialization of every
package contributing a reached declaration, and the files embedded and read through
them — so that flipping a referenced constant, changing a referenced type's layout,
editing an `init` side effect the subject observes, or editing an embedded data file
moves the closure hash even when every function body is byte-identical.

**REQ-closure-stdlib-cut** (behavior): The closure MUST exclude standard-library
declarations from the hash while still traversing call edges through them — the
standard library changes only when the toolchain changes, which is already a guard,
so hashing thousands of constant-per-toolchain files is redundant, yet a callback
from a standard-library function back into the subject's own code stays reachable and
hashed.

## Tiers and the sound floor

**REQ-closure-floor** (invariant): The closure hash MUST default to the maximal
closure and narrow below it only where the narrowing is proven not to drop source
able to affect the subject — so soundness holds by construction, the worst case
being the maximal source set and never less, and every precision gain being a
provably safe shrink rather than an optimistic guess.

## Blind spots

**REQ-closure-blindspot** (behavior): Every blind spot MUST take exactly one of three
dispositions, each chosen never to under-cover:

- **resolved** — the missing edge has a statically known target read directly (a
  `//go:linkname` naming its target, an assembly function whose `.s` is already
  hashed and whose symbol call-refs are scanned); add the edge, no widening.
- **widened** — the target is somewhere in analyzed source but cannot be enumerated
  (`reflect` dispatch, an `unsafe` computed call, a non-standard type converted to an
  interface, startup flow not proven complete); widen to the maximal closure.
- **downgraded** — behavior depends on state that is not source (file or network I/O,
  `plugin.Open`, an externally linked C library); the subject's verdict becomes
  unverifiable, its closure never reported valid on source alone.

A blind spot is never left to silently narrow the closure; when no disposition can be
proven, it widens.

## Analysis requirements

**REQ-closure-analysis** (behavior): Reachability analysis MUST build whole-program
SSA with standard-library bodies present and generic instantiations materialized, and
root the reachability walk at the subject, every linked package initializer, and — for
a subject that executes through the test harness (one declared in a test file) — the
test main — bodies present so a user method dispatched inside a standard-library
function stays visible, generics materialized so each instantiation dispatches
concretely, initializer roots included so a concrete type registered in `init` and
later observed through global state and interface dispatch is covered even when the
subject never names the registering package, the test main rooted for a test subject
so setup it runs before the subject (state a production subject never sees) is in the
closure; a narrower root or edge set is taken only when proven to preserve the same
startup and global-flow coverage. Package loading, dependency enumeration, and every
other source-selection step use the caller's executable build flags, so the closure
describes the binary whose build-configuration guard is recorded rather than a
different default build.

## Cross-module dependencies

**REQ-closure-mutable-local** (invariant): A mutable-local dependency reached by the
subject MUST be hashed by its source content, never pinned by module version — such
source resolves to a working directory with no version or checksum signal, so pinning
it by version would leave a silent content edit invisible and report the subject valid
while its dependency moved, the exact false valid the closure exists to prevent.

**REQ-closure-pinned-dep** (behavior): A pinned dependency reached by the subject
SHOULD be identified by its module path and version rather than hashed per
declaration — content and version are equivalent for a version-locked module, so the
pin captures every possible change through the one event that causes it, a `go.mod` or
`go.sum` bump, including an init-registered driver or codec the subject never names,
at coarse but sound module granularity.
