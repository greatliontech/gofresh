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
whole directory (non-toolchain assembly, cgo callback blind spots) may keep test files
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
add or an empty delta; beside the hash, the declaration's referenced names —
every identifier appearing in its declaring node, selector members and local
names included, the blank identifier (which resolves nothing) excluded, and
a const spec with an omitted expression list folding in its group's
governing spec's references and declared names — the blank name included,
as the ledger edge to an unnamed governor — since Go repeats that list
textually and the compiled code resolves names the spec never
writes — a syntax-only
over-approximation of
the top-level names the declaration's compiled code can resolve by
identifier, derived from the bytes the content hash folds — equal hashes
carry equal reference lists, with the one stated exception of an
omitted-list const spec, whose fold also tracks its group's governing list:
there the governing spec's declared names always ride the fold — the blank
name included, naming the ledger entry itself when the governor declares
nothing else — and any change
in that list is that governing entry's own movement, so a consumer walking
the current ledger's references still observes every movement an unchanged
declaration can textually repeat; the list is
served for a consumer to attribute a delta to the declarations that can
reach it — gofresh renders no reachability judgment, and directive entries
carry no references; and the declaring file's package clause name, so a
consumer can tell the two compartment packages' same-named declarations
apart — a method's receiver type resolves within its own package only; the
clause is part of the delta's declaration identity, because a
package-clause-only rename re-homes every declaration semantically (methods
re-attach across same-named types, unexported access changes) while
touching no declaration's bytes: the rename surfaces as removed and added
declarations, never as an empty delta hiding behind its licensed header
change;
per directive-shaped comment (`//go:…` other than
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
  `//go:linkname` naming its target); add the edge, no widening.
- **widened** — the target is somewhere in analyzed source but cannot be enumerated
  (`reflect` dispatch, an `unsafe` computed call, a non-standard type converted to an
  interface, startup flow not proven complete); widen to the maximal closure.
- **downgraded** — behavior depends on state that is not source (file or network I/O,
  `plugin.Open`, an externally linked C library, non-toolchain assembly); the
  subject's verdict becomes
  unverifiable, its closure never reported valid on source alone.

A blind spot is never left to silently narrow the closure; when no disposition can be
proven, it widens. Assembly is never an analysis surface: an
assembly-bearing mutable-local package contributes its whole directory to the
hash, a reached non-toolchain assembly-bearing package widens the subject and
blocks its observability proof, and toolchain assembly rides the toolchain
guard like every other toolchain source.

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
open subject world. A non-generic function subject whose ordinary
signature carries dynamic reach closes the same way a bounded generic
does — by enumeration, never by signature shape alone (a
receiver-bearing subject keeps its signature-shaped open world: a
method's interface invocability leaves no reference the scan can see —
a pointer-receiver invoke synthesizes no wrapper and takes no
address): it analyzes closed
exactly when every reference to it in the whole analyzed program is a
direct static call from a body the enumeration can judge and, at every
such site, each argument in
a dynamic-reaching position closes in the calling function's own frame
(locally constructed values under the closed-value walk with no
cross-boundary crossing — the caller's parameters, loads, and call
results refuse), in which case the sites' closed function values root
the reachability walk under the subject's provenance and their
materialized concrete types enter the runtime-type walk, so everything
the caller can actually hand the subject is analyzed view content whose
edit moves the subject's closure — a caller-passed closure executing in
subject flow contributes its effects to the subject's effect set exactly
as an instantiation's body does. Anything else keeps the open world:
zero enumerable references (absence of provenance, refused, never a
vacuous pass), any reference that is not a direct static call (an
address capture, a stored value, a wrapper, a dynamic invocation of the
subject), any call held by a body the enumeration cannot judge as a
caller (a synthetic function — wrapper re-dispatch, package
initializer — or a parameterized origin, whose arguments are never
judged), any unclosed dynamic-position argument, or a subject reached
through the harness's own dispatch rather than enumerable sites — with
the one standing exception the tiers already share: a harness-signature
subject's single dynamic-reaching parameter is the recognized harness's
own value, governed by the harness admissions, and confers no open
world. The
enumeration is decided against the same analyzed binary the walk
describes, so a caller added later changes the closure and re-measures
rather than serving under an enumeration it was never part of. A
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
human diagnostic is derived afterward and can never select which facts
participate: a refusal names the highest-ranked blocking effect under one
cause-preference order shared with the legacy single-reason projection —
structural findings, mutations, and every classification not expressly
down-ranked (standard input, network, plugin, native, linkage included)
rank top; then the generic file read; then ambient formatting and
environment; then the unaudited and test-runtime classifications; the
legacy projection alone adds one weakest stratum below all of these, the
audited harness fact — with the refusal's ties resolved by the effect
projection's total order and the legacy projection's ties resolved
lexicographically on the reason text, so both diagnostics are
deterministic and causal-first. A complete maximal-tier negative scan
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
are channels the testlog cannot audit. One admission in the audited set is
operand-sensitive: fmt's writer-first print family (Fprint, Fprintf,
Fprintln) is Sprint-equivalent value computation exactly when the writer
operand provably pins every dynamic type it can carry to an audited
in-memory sink — `*bytes.Buffer` or `*strings.Builder`, whose write appends
to process memory and acquires nothing ambient — judged by a closed-value
walk under the dispatch admissions' discipline: the pinning MakeInterface's
concrete type decides, subject-attributed parameter crossing included, and
startup flow, carrying no subject attribution, closes locally constructed
writers only; an unproven writer — an interface-typed value the walk
cannot trace to pinning MakeInterfaces (a loaded interface, a call result,
any mixed or enumeration-refused provenance) — keeps the formatted-output
classification, while a concrete `*bytes.Buffer`/`*strings.Builder`
expression pins regardless of which instance it denotes (which instance
receives the bytes never changes which write runs — the footing a direct
write on the audited type already has), a dynamically reached Fprint keeps it
regardless of site arguments (they belong to the dynamic signature, not
fmt's shape), and the maximal scan's package-level Fprint finding, blind to
operands, narrows to a diagnostic so the writer-sensitive tiers decide.
Widening the
audited set changes proof semantics and rides the strategy-version bump like
any other proof change. The audited set carries the testing harness's
failure/logging channel — exactly the testing-package symbols named `Fatal`,
`Fatalf`, `Error`, `Errorf`, `Log`, `Logf`, `Skip`, `Skipf`, `SkipNow`,
`Fail`, and `FailNow`, matched by package and symbol name; the admission is
sound only while every testing-package declaration of an audited name is the
harness's shared embedded core or an outcome-only delegate to it (today:
the core plus `(*F).Fail`, a misuse panic delegating to the core), and the
toolchain's declaration inventory is walked by an enforcement test so drift
refuses instead of silently widening — whose
output lands only in the harness's own in-memory buffer and
the run's captured output, both already part of the recorded test outcome: the
channel is output-only for outcome bits (the run-flag presentation state the
logging path reads shapes recorded-output bytes only and is outside the
proof's claim), argument method sets stay visible to reachability
exactly as fmt's Sprint family, and the walk records the reached call as an
admitted harness fact instead of descending into harness internals. The
admission applies to statically and RTA-resolved callees only — an
unresolvable reference stays refused like any other — and the harness's
ambient-input and mutation surfaces (`Setenv`, `Chdir`, `TempDir`, the
runtime-configuration reads) keep their own classifications. An interface
dispatch the walk cannot resolve widens the subject world — the synthetic
interface-method wrapper family (any interface, the harness included)
carries the same obligation in the closed-value walk itself: a bound
wrapper's closure value closes only through its captured receiver, a
thunk value never closes (its receiver arrives at call sites the value
walk cannot see) and a static thunk call judges its receiver argument, so
a wrapper over sibling-planted shared state refuses exactly as the direct
invoke would, whatever carried the wrapper to the call — with one
harness-dispatch admission: a site does not widen when its RTA-enumerated,
subject-attributed target set is non-empty and entirely audited harness
methods AND the dispatch operand's dynamic types are fully determined by
the subject's own flow — the operand derives from local construction or
from a parameter whose function is not dynamically targeted, closes over
nothing, is not variadic, and has at least one subject-attributed call
site, every such site feeding a subject-closed value (zero enumerable
callers is absence of provenance, refused, never a vacuous pass); a load
from shared mutable state refuses, because analysis is
subject-scoped while the process heap is shared, so a sibling subject's
runtime flow can plant an implementation the subject's attributed
enumeration cannot see. A target set containing any non-harness method
keeps the widen regardless of that target's own effects, because
classifiability is a property of the dispatch shape, never of what the
extra target happens to do. The maximal scan's receiver-escape rejection
is package-scan diagnostic, not a package blocker: every subject-tier
dispatch on an escaped harness value is classified — admitted only under
this admission, widened or effect-recorded otherwise — and user test-main
flow, the one startup flow that can dispatch a test-planted value after
the harness run, widens the startup result on any dispatch whose provenance
is not locally closed — the operand under the same wrapper-carrying
closed-value walk, with a static thunk call judged by its receiver
argument, because the wrapper family's toolchain-attributed bodies
perform the real dispatch where no walk records effects; the planted
channel is a load from shared mutable state, while a test-main's own
constructions keep their classification — blocking the proof like any
other startup effect. Initializer flow keeps attributed-effect recording alone:
nothing is plantable before tests run, so an initializer's unattributed
dispatch is not the demonstrated channel and stays unwidened. The admitted observation set includes the guard-pinned
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
analyzed program is built from: the core closure hash joined with the
test-variant compartment identity, since the compartment partition keeps
test-only bytes out of the core while the analyzed binary compiles both
(stdlib rides the toolchain guard, version-locked cache dependencies their
version pins, per REQ-closure-mutable-local and REQ-closure-pinned-dep). A memo hit is
byte-equivalent to recomputation — including recorded unrooted-subject
dispositions — and a full-group hit skips the program load entirely. The
memo is a cache, never a record: it lives under the user cache directory,
writes atomically, and a missing, unreadable, corrupt, or key-mismatched
entry recomputes silently; no entry is trusted beyond its key — the key IS
the freshness. Entries accumulate one per closure version and the cache is
deletable wholesale at any time. Proofs persist as each attribution slice
completes: an analysis deadline expiring mid-group forfeits only the
interrupted slice's proofs, and a later pass serves every completed
slice's from the memo. A violation of the caller's quiescence
obligation (REQ-fresh-producer-view) can persist through the memo until the
key moves — the memo widens that contract-excluded window's blast radius
from one process to the cache, never its reachability. Changing proof
semantics — including diagnostic text, which recorded evidence binds —
without bumping the strategy version
was already a violation of the recorded-evidence contract; the memo adds no
new versioning obligation.

REQ-closure-observability-memo: enforced by
`TestObservabilityMemoServesEquivalentProofsWithoutLoading`,
`TestObservabilityMemoMissesOnScopeAndSourceChange`, and
`TestObservabilityMemoKeepsCompletedSlicesOnDeadline`.

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

**REQ-closure-effect-scan-memo** (behavior): The fold of a version-pinned
package's per-file effect scans MAY be served from a persistent memo,
because that fold is a pure syntactic function of its key's complete input
identity: the scan-strategy version and the toolchain identity, plus the
module's version pin, the package's import path, and the identity — with
its Go/cgo partition — of the file set the current listing selects for it.
No type-environment signature participates, because the per-file scan reads
no types (the typed testing-effect scan is separately governed).
Package-level effect facts — assembly, system objects, cgo linkage
metadata — are functions of the live listing's build configuration, which
the key does not carry: every pass recomputes them from the listing in hand
and they are never persisted. A mutable-local package's files are never
served from this memo — the classification is the resolved source living
outside the module cache, and any version the listing reports for a
replacement does not attest that source — every pass re-reads them. A
memo hit is byte-equivalent to recomputation — the
effect set, its order, and the preferred diagnostic alike. The memo is a
cache, never a record — the observability memo's discipline verbatim: a
sibling user-cache directory, atomic writes, silent recomputation on any
miss, corruption, or key mismatch, deletable wholesale at any time;
changing scan semantics — classification tables included — bumps the
scan-strategy version.

REQ-closure-effect-scan-memo: enforced by
`TestEffectScanMemoServesPinnedPackagesWithoutReads`,
`TestEffectScanMemoMissesOnScopeAndFileSetChange`, and
`TestEffectScanMemoFoldMatchesInlineFold`.

**REQ-closure-testing-scan-memo** (behavior): A package's typed
testing-effect scan MAY be served from a persistent memo, because the scan
is a pure function of its key's complete input identity: the scan-strategy
version plus the caller-supplied memo scope — which carries the code
guards, toolchain and build configuration, that the type environment
depends on — plus the package test-binary closure hash, which pins every
mutable source byte the environment is built from. The caller-supplied
scope is the observability memo's scope: one scope channel arms every
closure memo that needs the caller's guards. A hit serves before any
type-environment load; without a caller-supplied scope the memo is
disabled, and a closure-hash derivation failure disables it for that
package — fail-open to recomputation. A memo hit is byte-equivalent to
recomputation — the effect set, its order, and the preferred diagnostic
alike, an effect-free scan included. The memo is a cache, never a record —
the observability memo's discipline verbatim: a sibling user-cache
directory, atomic writes, silent recomputation on any miss, corruption, or
key mismatch, deletable wholesale at any time; changing scan semantics —
the testing classification table included — bumps the scan-strategy
version.

REQ-closure-testing-scan-memo: enforced by
`TestTestingScanMemoServesWithoutTypeLoad` and
`TestTestingScanMemoMissesOnScopeAndSourceChange`.

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
