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
whole, excluding the subject package's own test-variant source, which the
test-variant compartment covers; the sound floor that every blind spot widens to
and the closure never falls below.

**test-variant compartment** (term): the hash over the subject package's own
test-only files — the in-package (`pkg [pkg.test]`) and external
(`pkg_test [pkg.test]`) test-variant file sets minus the base package's file
set — recorded beside the maximal closure so a sibling-test edit is
distinguishable from every other drift.

**declaration ledger** (term): the deterministic, syntax-derived list of the
compartment's top-level declarations and per-file header identities, exposed as
data for a consumer to persist at capture and diff at check.

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

**REQ-closure-view-maximal** (behavior): A multi-subject analysis view MUST use the
maximal selected test-binary closure of each subject's package as its default source
guard, hashing every non-standard dependency whole and salting that package closure
with the subject identity. The subject package's own test-variant nodes' source
members are excluded from that core hash: their production members already ride the
base package's contribution, and their test-only members fold into the test-variant
compartment instead (REQ-closure-test-variant-compartment). Test-only dependency
nodes — packages reachable only through test imports — remain core contributions
whole, dependency nodes recompiled against the test binary included, because a new
package's initialization enters the test binary's behavior. Subjects in one package
therefore observe the same source set without making fingerprints transferable
between identities; an unrelated sibling edit may still stale them together — the
deliberately safe price for analysis whose time and live memory are bounded
independently of subject count — but a sibling-test edit now stales them through the
compartment, where a consumer can recognize it, rather than through the core.

**REQ-closure-test-variant-compartment** (behavior): A fingerprint MUST record,
beside the maximal closure, the subject package's test-variant compartment: the
hash over the package's own test-only files — each own test-variant node's file
set minus the base package's file set, in-package and external variants folded
together — under the same per-file name-and-content-hash discipline as the core's
file folding, unsalted, so every subject of one package shares the compartment
that describes the package. A package with no test files records the defined
constant empty-set identity, stable for as long as the package has none; the
empty string is never a computed compartment, so an empty recorded compartment
identifies a recording that predates the compartment and fails closed to stale
with reason "test variants". Verdicts order the comparison after the core: an unchanged
core with a drifted compartment is stale with the stable reason
"test variants" — the one verdict reason a consumer may discriminate on — and
no observation evidence rescues it, because gofresh renders
no judgment about which test-variant deltas are benign. A drifted core is
stale on the closure. Both unchanged keep the prior semantics
exactly. A subject declared in a test file has its own body in the
compartment, so an edited recorded test moves the compartment — that is the
partition working, not a leak. A package whose core contribution widens to its
whole directory (opaque assembly, cgo callback blind spots) may keep test files
in the core as well: sound, merely undiscriminated. The compartment's
declaration ledger is a read surface over the same bytes the compartment hash
folded, derived by syntax-only parsing at the view's observation — never a
re-read that could straddle a later edit — and served at capture and at check:
per declaration the file (relative to the package directory), the kind (func,
method, init, var, const, or type; TestMain is an ordinary func with its name
visible), the name, the receiver type text for methods, and a content hash over
the declaration's source range with its doc comment, grouped specs hashed
individually and positions Go gives semantics folded into the hash — a const
spec's ordinal within its group (iota and implicit expression repetition), a
var spec's and an init function's ordinal within its file (package-level
initialization order) — so an insertion that shifts a sibling's value or a
reorder of initialization surfaces as changed declarations, never as a silent
add or an empty delta; per directive-shaped comment (`//go:…` other than
`//go:build`, wherever it sits in the file) a "directive" entry named by its
verb and hashed over its text, because directives are behavior-bearing from
any position — `//go:debug` ahead of the package clause, a floating
`//go:linkname` inside a group span — and build constraints are the one
exclusion, compiling to nothing under the current configuration while any
membership change they cause already surfaces as declaration and file-header
movement; per file a header identity — for a compiled Go member, over the
non-declaration remainder: package clause, imports, build constraints, and
comments outside declarations; for every other member, over the whole
content, marked embedded and carrying no declarations. Membership comes from
go list's file-kind facts, never the file name: a test-only embedded
fixture whose name ends in .go is data — never parsed, never contributing
declarations, its movement defeating inertness like any embedded member's.
The kinds are not a partition: a member both compiled and embedded (a
sibling test file names it in a go:embed directive) keeps its parsed
declarations while carrying the embedded whole-content header, so any
movement in its bytes — which unchanged code reads as data — defeats
inertness fail-closed.
The ledger is deterministically sorted. The inertness judgment is rendered
modulo position metadata: any header edit shifts unchanged declarations'
source positions, and a line directive remaps them — positions are
diagnostics, not behavior, for this judgment. Two ledgers
diff into a classified delta — added, changed, and removed declarations plus
per-file header changes, deterministic for any pair — carrying gofresh's one
Go-semantics judgment: the delta is inert exactly when no declaration changed
or was removed and every added declaration is one no unchanged declaration can
observe — a plain function (no receiver, not init, not TestMain), a const, or
a type, whose accompanying methods would surface as their own added entries.
The positional folding above is what keeps that whitelist honest: a const
inserted mid-group or a reordered var or init reads as changed sibling
declarations, so only additions that leave every existing declaration's
meaning intact classify as added. Directive entries are outside the
whitelist, so any directive movement — added, changed, or removed — defeats
inertness; header benignity below covers only the directive-free remainder.
Each rejected kind names the mechanism that reaches unchanged code: a package
var's initializer runs during test-binary initialization; an init function
likewise; TestMain replaces the harness entry wrapping every unchanged test; a
method can flip interface satisfaction observed by unchanged type assertions
and dispatch. Go-file header-only changes — imports, build-constraint text,
comments outside declarations — never defeat inertness: this is where the
judgment leans on the partition rule, because test-only dependency nodes stay
in the core, so the core equality under which a consumer reads this delta
already proves no new dependency package entered the test binary, and an
import edit among already-present packages is init-benign. An embedded
member's header movement defeats inertness fail-closed — whatever the file's
name: test-only embedded bytes feed unchanged declarations that read them.
Inertness is
Go-semantics data — it claims the delta cannot change the behavior of any
unchanged declaration and nothing more; what inertness licenses is the
consumer's policy, never gofresh's.

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

**REQ-closure-shared-dynamic-state** (invariant): A package-level variable able to
carry dynamic behavior — a function, an interface, a channel of dynamic carriers,
or an unsafe pointer anywhere in its type — that the analyzed program can mutate
after initialization is
process-shared dynamic state no per-subject closure can attribute, because a prior
subject's execution in the same process can have changed it: every subject whose
package graph links the owning package MUST be unverifiable. Mutation is judged
fail-closed by carrier shape. A by-value carrier (a function value, or a struct,
array, or tuple of by-value carriers) is mutated exactly by a write, an address
capture, or a pointer-receiver method use outside `init` flow anywhere in the
program — reads copy and cannot reach the shared cell. An alias-handing carrier —
an interface value (its concrete object is shared), a channel, or a pointer, map,
or slice reaching a dynamic carrier, or an unsafe pointer — hands shared mutable
access to every reader, so ANY use outside initialization is mutation-equivalent.
Function bodies nested in package-level declarations are program code, not
initialization; non-Go writes need no rule here — packages built with cgo or
assembly sources are already downgraded whole by the native-code and linkage
blind-spot dispositions. A dynamic-capable variable the program never mutates under these
rules is ordinary source — the closure hashes its initializer like any
declaration — and confers no downgrade; the unconditional type-level blanket would
refuse verifiability to nearly every real program, since hook-typed package
variables are ubiquitous.

## Analysis requirements

**REQ-closure-analysis** (behavior): The observability proof's precise analysis MUST build
whole-program SSA with standard-library bodies present and generic instantiations
materialized, and root the reachability walk at the subject, every linked source
package initializer, and — for a subject that executes through the test harness (one
declared in a test file) — the user-defined test main. The toolchain-generated test
main's registration initializer is not a source initializer and does not root every
alternative test or benchmark into a caller-selected subject. Standard-library
bodies remain present so a user method dispatched inside a
standard-library function stays visible, generics materialized so each instantiation
dispatches concretely, initializer roots included so a concrete type registered in
`init` and later observed through global state and interface dispatch is covered even
when the subject never names the registering package, the test main rooted for a test
subject so setup it runs before the subject (state a production subject never sees)
is in the closure; a narrower root or edge set is taken only when proven to preserve
the same startup and global-flow coverage. A parameterized subject is open to
caller-chosen instantiations, and its openness is decided on the
type-parameter list itself (a signature walk alone misses zero-parameter
generics), identically at every tier: a constraint that provably bounds
its type set away from dynamic carriers — methodless, with at least one
bounding element whose every term is free of dynamic reach under the same
carrier rule ordinary parameters answer to (interface, function, and
unsafe reach open; a channel opens exactly when its element does);
`any` and `comparable` bound nothing — closes
the caller's choice, anything else keeps the subject open-world,
where observability refuses exactly as for any
open subject world. A
constraint-bounded parameterized subject analyzes closed: its
materialized in-binary instantiations root the reachability walk — each
dispatches concretely, so instantiation-reached content enters the
observability effect set, and a subject with no
in-binary instantiation is analyzed on the origin fold's own static
reachability, since
no concretized behavior of it exists in the analyzed binary. In every case the
origin body is never a traversal surface (open over type parameters, it is
not a runtime dispatch surface), and its origin declaration remains the
subject's own content. An analysis shape the reachability walk cannot classify degrades
that analysis to unavailable evidence, never a process failure. A subject
name declared by two distinct functions of one test binary — the package
and its external test package may legally share a top-level name — is
subject-local ambiguity: that subject degrades to unavailable evidence
with a diagnostic naming the collision, and sibling subjects analyze
normally; a name the package never declares at all remains a caller
error. Maximal
closure and precise-analysis package
loading, dependency enumeration, and every other source-selection step use the
caller's executable build flags, so both tiers describe the binary whose
build-configuration guard is recorded rather than a different default build.

**REQ-closure-observability-analysis** (invariant): An observability proof MUST use the
whole-program SSA, standard-library bodies, generic instantiations, executable
build selection, and subject attribution of REQ-closure-analysis, and preserves
root provenance: any external effect attributable to a package initializer or to
user test-main flow rather than the subject is outside subject-time observation and
blocks the proof, while subject flow is classified against the admitted observation
set. Every reachable call and effect is classified to the walk's end; the preferred
human diagnostic is derived afterward and can never select which facts participate. A complete maximal-tier negative scan
may reject opaque linkage, native code, process execution, dot imports, unaudited
standard-library access, or other unclassified external-capable syntax, but can never
grant the proof on its own. The audited-pure standard set — packages and named
operations through which every ambient effect must enter via a flagged
constructor or global of an effect-bearing package, adding no
testlog-invisible input channel of their own (fmt's Sprint family included:
argument methods stay visible to reachability) — is deliberately bounded by
two exclusions that are soundness, not caution: reflect defeats static
reachability itself, and registration-shaped covert channels — flag registration returns
pointers whose values change at Parse, and gob registration mutates a
package-global type registry a sibling subject's decode can depend on —
are channels the testlog cannot audit. Widening the
audited set changes proof semantics and rides the strategy-version bump like
any other proof change. The admitted observation set includes the guard-pinned
toolchain accessor — exactly `runtime.GOROOT`, never the runtime package's other
surfaces — whose value the toolchain guard already fixes, together with read-position
uses of paths derived from it through constant-component joins: reads under the
toolchain root are guard-covered at observation, so proving them observable claims
nothing the record does not pin. The admission is consulted at the subject-effect
stage only: startup effects remain uniformly blocking (a package initializer
calling the accessor blocks like any other startup effect), a dynamic reference to
the accessor stays refused, and among handle-producing opens exactly the read-only
`os.Open` shape is admitted. Pinned paths are never admissible in mutation
positions — freshness licenses mutation, pinning never does — and a write through a
pinned path blocks on its own effect.

**REQ-closure-batch-equivalence** (invariant): Sharing closure computation across an
analysis view's subjects MUST produce, for every subject, the same evidence as
computing that subject independently: a batched subject's
source-file set is exactly the set an independent maximal view would expose,
while the view-wide set is their union, and a batched subject's core maximal
hash and test-variant compartment are
exactly the pair an independent computation of that subject would produce.

**REQ-closure-observability-batch-equivalence** (invariant): Sharing observability
analysis across subjects MUST yield exactly the proof disposition, complete effect set,
root provenance, and diagnostic that independent analysis of each subject under the
same view would yield, with the same startup and test-harness roots. Dynamic-function
and interface-dispatch facts are attributed to the subjects that reach both sides of
their cross-product; a fact reachable only from one subject does not create an edge
for another — no effect or proof fact reached only by one subject can confer
or deny another subject's proof. Batching is bounded so attributed state can be
discarded incrementally rather than growing with every subject in the view.

## Cross-module dependencies

**REQ-closure-observability-memo** (behavior): Observability proofs MAY be
served from a persistent memo because the proof is a pure function of its
key's complete input identity: the caller-supplied scope (the proof-strategy
version and the code guards — toolchain and build configuration) plus the
package test-binary closure hash, which pins every mutable source byte the
analyzed program is built from (stdlib rides the toolchain guard,
version-locked cache dependencies their version pins, per
REQ-closure-mutable-local and REQ-closure-pinned-dep). A memo hit is
byte-equivalent to recomputation — including recorded unrooted-subject
dispositions — and a full-group hit skips the program load entirely. The
memo is a cache, never a record: it lives under the user cache directory,
writes atomically, and a missing, unreadable, corrupt, or key-mismatched
entry recomputes silently; no entry is trusted beyond its key — the key IS
the freshness. Entries accumulate one per closure version and the cache is
deletable wholesale at any time. A violation of the caller's quiescence
obligation (REQ-fresh-producer-view) can persist through the memo until the
key moves — the memo widens that contract-excluded window's blast radius
from one process to the cache, never its reachability. Changing proof
semantics — including diagnostic text, which recorded evidence binds —
without bumping the strategy version
was already a violation of the recorded-evidence contract; the memo adds no
new versioning obligation.

REQ-closure-observability-memo: enforced by
`TestObservabilityMemoServesEquivalentProofsWithoutLoading` and
`TestObservabilityMemoMissesOnScopeAndSourceChange`.

**REQ-closure-dynamic-state-memo** (behavior): Per-package shared-dynamic-state
facts — the dynamic-capable package-level variables a package declares, the
variable identities its code mutates after initialization
(REQ-closure-shared-dynamic-state), and its method-directive declarations — MAY
be served from a persistent memo for version-pinned packages, because each fact
is a pure function of its key's complete input identity: the caller's scope
(the fact-strategy version and the code guards — toolchain and build
configuration) plus the module's version pin and the version signature of every
pinned module reachable from its packages, its type environment's complete
version surface (the standard library rides the toolchain guard). A
mutable-local package's facts are never memoized — its source carries no
version signal (REQ-closure-mutable-local) — and derive fresh from each
observation pass's own load; a process-lifetime cache is sound exactly for
keyed pinned facts and never holds a mutable-local derivation, so no stale
process state can override newer local source. A pinned module whose import
cone reaches any mutable-local node is unkeyable — part of its type
environment carries no version signal — and its facts derive fresh every
pass, entering no cache layer: a pinned key must never launder mutable-local
state. A test-cycle intermediate recompilation is scanned from its own
compilation through a dependency-expanded load of its tested packages,
performed only when that shape exists — test-added declarations can lawfully
change its resolutions, and its plain form need not compile. Module mode is
assumed: a module-less tree classes every package standard and contributes
no facts, exactly the analysis's declaration side, which never admitted
module-less declarations. Standard-library packages
contribute no facts: the analysis's declaration side excludes module-less
packages, toolchain source cannot reach module variables (imports are
acyclic), and toolchain source is not an authoring surface for gofresh
directives. A memo hit is fact-equivalent to recomputation. The memo is a
cache, never a record — the observability memo's discipline verbatim: a
sibling user-cache directory, atomic writes, silent recomputation on any
miss, corruption, or key mismatch, deletable wholesale at any time; changing
fact semantics bumps the fact-strategy version.

REQ-closure-dynamic-state-memo: enforced by
`TestDynamicStateFactsServePinnedPackagesWithoutLoading`,
`TestDynamicStateFactRoundTripCarriesMutationsAndMethodDirectives`,
`TestDynamicStateFactStoreMissesOnScopeAndBucketChange`,
`TestPinnedBucketsMoveWithImportConeVersions`,
`TestPinnedBucketsExcludeModulesReachingMutableLocalSource`,
`TestPinnedFactsWithMutableLocalTypeEnvironmentDeriveFreshEachPass`,
`TestIntermediateRecompilationsScanFromTheirOwnCompilation`, and
`TestDynamicStateLocalFactsDeriveFreshEachScan`.

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
