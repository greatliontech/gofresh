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
proven, it widens. At the file-scan floor, a file whose every
`//go:linkname` directive is the two-argument pull form naming a target
in the audited linkname-target set — `runtime.getAuxv`,
`runtime.vgetrandom`, and `syscall.prlimit`, each a read-only standard
trampoline whose effect class the file's remaining classifications
already carry — drops exactly the opaque-linkage effect and keeps every
other effect it bears; a one-argument form, an unparsable directive, or
an unaudited target keeps the opaque floor, fail-closed; and because a
`//go:linkname` file necessarily imports `unsafe`, the file's unsafe
classifications remain as the effect backstop — dropping the opaque
flag never leaves an audited-linkname file effect-silent. The set
grows only by source audit. Assembly is never an analysis surface: an
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
package graph links the owning package MUST be unverifiable — unless a
recorded discharge channel of this requirement lifts it: a caller vouch for
the specific variable (REQ-vouch-discharge in
[purity.md](purity.md); version-pinned dependencies only, the acceptance
recorded on the evidence), an audited-set admission (the synchronization,
pooling, mapping, and memoization sets below), the author's
`//gofresh:single-subject` variable directive and the generated-proto
descriptor cluster under the caller's attestation,
or the reachability judgments — the attestation-scoped per-subject
judgment and the unattested-model binary-scoped judgment — each defined
below with its own bounds and recording discipline, and nothing else.
(The refusal reason's own contract, the discharge channel it names
included, is REQ-closure-shared-dynamic-state-reason.)
The audited atomic transparency governs every carrier walk of this
judgment — the trigger above, the openness a parameter, receiver, or
constraint term confers on its subject (REQ-closure-analysis), and
the alias-handing read judgment below: each walk sees the toolchain's
`sync/atomic.Pointer[T]` as `*T`. The ground is a source audit of the
toolchain's type: its internal unsafe pointer is an implementation
cell the zero-width `*T` field and the whole method set type-pin to
`*T`, never an unsafe channel; a shadowing module is a load error (an
ambiguous import), so no type-checked program carries a foreign
`sync/atomic`; a defined wrapper type inherits no methods and its
cell is reached only through an address conversion the escape rules
already mark, so it keeps the fail-closed judgment; and a
dynamic-carrying `*T` still triggers everywhere. One rule at every
tier, riding the toolchain guard — no attestation, no evidence
record.
Mutation is judged
fail-closed by carrier shape. A by-value carrier (a function value, or a struct,
array, or tuple of by-value carriers) is mutated exactly by a write, an address
capture, or a pointer-receiver method use outside `init` flow anywhere in the
program — reads copy and cannot reach the shared cell. An alias-handing carrier —
an interface value (its concrete object is shared), a channel, or a pointer, map,
or slice reaching a dynamic carrier, or an unsafe pointer — hands shared mutable
access through the value, so it is judged by use shape, still fail-closed: a read
that provably cannot write — indexing or iterating the carrier, taking its length
or capacity, or comparing it — is not mutation, and the indexing and iteration
discharges hold only when the produced value hands out no mutable reach — a
pointer, map, slice, channel, or interface anywhere in it refuses; a function
value is program code judged where written, not write access (an indexed-out
map still writes through) — but a signature-carrying value IS its
environment: a rooted signature-carrying read handed out — returned,
bound, or passed — refuses on the value plane whatever the reach walk
says of its type, only its call staying tolerated with the call's own
pricing — a pricing that extends to the call's results: a call through a
rooted callee refuses, in every consumption position, when any of its
results hands out mutable reach or carries a signature, exactly as an
indexed-out value is priced; a void or all-scalar result set hands out
nothing — and a comma-ok existence read whose extracted
element lands in a blank is writeless on any carrier — no value is
produced to hand out — and never for a channel (ranging a channel
receives); a write through the carrier, growth or deletion, a send or receive, an
address capture, or a rebinding is mutation; every other use — escaping the value
into a call argument, a store, a return, a binding, a method call on it, or a
type assertion — is mutation-equivalent, because the receiving code may write
what it was handed. An address capture reaches the variable's own cell or a
chain into it; taking the address of a composite literal captures the fresh
object alone, its element references remaining escapes, while a capture
nested inside the literal marks through its own shape. A direct method CALL on a statically-typed non-interface
carrier is judged by the method's own receiver-effect proof instead: the
declaring package proves a method unable to write receiver-reachable state —
the receiver never stands in a write position and never escapes, values read
off it are tracked as the receiver's own — a binding whose type hands out
mutable reach taints its local (a value copy that cannot write back flows
freely), a receiver-rooted read is judged at its outermost selector or index
step by the value it produces — an intermediate reach-bearing step is
evaluation, not a handout — a conversion of a receiver-reachable value admits
exactly when its result type hands out no mutable reach and the operand is
not a method value (a method value carries its receiver whatever the result
type says; an aliasing conversion keeps the escape), a bind whose target
outlives the body — a package-level variable — refuses whenever the target's
type hands out mutable reach (a reach-free copy flows; the proof's tracked
bindings die with the body, and an outliving alias escapes it — a sibling
call's results bound to such a target refuse identically), a write
through or an escape of a tainted value refuses, and only the method's own
return position hands one out — a return inside a nested function literal is
an escape position, since the literal outlives the body carrying what it
captured and no call-site result judgment sees through a signature — and it chains only into sibling methods already proven or into
the audited synchronization set — and a call to a proven method marks nothing,
generic receivers included, provided the call site's instantiated result types
each hand out no mutable reach or are audited-immutable (reflect.Type,
runtime-canonical and never written after construction; reflect.TypeOf, its
pure constructor, admitted with it at the effect classification tiers); a call to any unproven,
unresolvable, or interface-dispatched method, and any method VALUE bind, keeps
the fail-closed mark. The audited synchronization set — sync.Mutex and
sync.RWMutex with their lock operations, receiver-neutral and never
process-external because lock state cannot change dispatch — is admitted
identically at the effect classification tiers, and grows only by source
audit. The audited pooling set — `sync.Pool` with its `Get` and `Put`
operations — is admitted by source audit at two tiers with two
distinct grounds. At the effect classification tiers the admission is
unconditional and receiver-neutral exactly as lock state's: `Get` and
`Put` touch only process memory fed by the analyzed program, so they
introduce no external input channel whatever the execution schedule.
The shared-dynamic-state discharge holds on two grounds. Under the
caller-attested single-subject-process execution model — each subject
measured in a process of its own — every in-process `Put` site
lies in the subject's own rooted flow, so pool contents are a function
of the analyzed source and the subject alone (without the attestation,
sibling subjects sharing a process communicate through pool contents —
a prior subject's `Put` plants a value a later subject's `Get`
dispatches on — and a pool the content proof below does not cover
keeps the fail-closed judgment at every use);
the contents' contractual removability at any time is why the values
need no per-item pricing at the call. Under the attestation, a `Get`
or `Put` method call on a pool-typed carrier, the carrier being a
package-level `sync.Pool` variable or an element of a package-level
array or slice of `sync.Pool` indexed directly on the variable, is not
mutation of the pool variable, while the values passed and produced
keep their own full pricing, and every other use — a write, a
rebinding, an address capture, an escape of the pool value, or a
`New`-field access outside `init` flow — keeps the fail-closed
judgment. The content-proven discharge is the attestation's
engine-proven sibling, admitting the same `Get` and `Put` calls in
any execution model: the cross-subject channel the attestation
otherwise closes is the planted value's dispatch plane, so a pool
whose contents provably carry no dispatch needs no execution model at
all. A pool is content-proven exactly when its owning package's
syntax shows every content source and every use conforming: an
unexported package-level `sync.Pool` variable — unexported so every
reference site lies in the owning package's compilation variants,
whose marks are keyed variant-blind and union at composition: a
dirty site in any variant downgrades every subject linking the
package, stricter than per-variant and never weaker — declared with
a composite literal whose single field is a `New` function literal
with no named results and no defer statement in its own body (a
deferred call is the only channel that can rewrite a named result or
recover a panic into a zero-valued nil-interface return — either
retypes or nils the produced value after the return expressions the
derivation reads — and a named result is refused even without one: a
racing goroutine can write it too), every return
of that literal one identical type `T` — never untyped, and free of
dynamic carriers under the invariant's own trigger predicate (an
interface is itself such a carrier, so interface-typed contents
refuse there) — and the variable's every other appearance in the
package being exactly the receiver of a `Get` or `Put` call — any
other appearance, a `New`-field access or an initializer-flow write
included, evicts the proof wholesale. `Put`-argument conformance
stays per site: a `Put` whose argument's static type is not exactly
`T` is not admitted and keeps its own fail-closed mark. Contents are
then always of type `T` under every schedule — every plant is `T`,
and with the literal's post-return channels closed every completed
`New` produces `T`, so the interface value `Get` yields is never
nil; a panic that propagates out of `New` stays outside the proof's
claims exactly as under the attestation, since removability leaves
whether `New` runs undetermined in every execution model — and no
type assertion, type
switch, or method dispatch can distinguish subject orders; what stays
order-sensitive is the data plane, which the invariant's type-level
trigger already leaves out of scope (a mutable data-only package
variable is never a culprit). Like the memoization set's, this
discharge is the engine's own verdict, not a caller assertion: it
needs no attestation and rides no evidence record. An exported pool,
an element of a package-level array or slice of `sync.Pool`, and
every shape the proof cannot see keep the attestation requirement.
The attestation is part of the persisted fact identity, so
attested and unattested sessions never serve each other's facts, and a
load-bearing attestation is recorded on the subject's evidence exactly
as a vouch discharge is — naming the discharged pool variables,
auditable and never silent (REQ-vouch-recorded in
[purity.md](purity.md)). The set grows only by source audit. The
audited mapping set — `golang.org/x/sys/unix`'s package-level `mapper`
bookkeeping, written by the mapping calls (`Mmap`, `Munmap`, and their
variants) — is admitted in any execution model, on the deepened
source audit and exactly for the audited versions of the
version-pinned module (v0.8.0, v0.26.0, v0.33.0, v0.40.0, v0.43.0,
v0.45.0, v0.46.0, v0.47.0 — the per-GOOS declaration split included;
an unaudited version, later or earlier, refuses fail-closed until its
source is audited, exactly the memoization set's rule): mapper's
state is
process-local, fed exclusively by the analyzed program's own mapping
calls; its callable fields (`mmap`, `munmap`, `mremap`) are written
only in the variable's declarations, so no schedule can change
dispatch through the carrier; and its bookkeeping maps each live
mapping's last-byte address to its data-only byte slice, which hands
out no dynamic carrier. Cross-subject entries are disjoint while
their mappings live (the kernel's contract); the raw-pointer paths
(`MunmapPtr`, `MremapPtr`) leave entries stale, and a reissued address could
then steer `Munmap`'s error-plane outcome by subject order — an
exposure that is unobservable exactly because any subject able to
observe it calls the mapping syscalls itself and those keep their
own fail-closed classification at the observability tiers, which is
therefore part of this discharge's ground, not merely an adjacent
fact. The discharge spans the variable's mutation, escape, and
environment-audit marks alike (the raw callable-field reads the
`*Ptr` paths take are covered by the init-only-fields leg of the
audit). Like the memoization set's, the discharge is
the engine's own source-audited verdict: no attestation, no evidence
record. It covers exactly the named variable in the
shared-dynamic-state judgment — a mutable-local checkout keeps every
mark and every other variable of the module keeps its own judgment.
The set grows
only by source audit. The `//gofresh:single-subject` variable
directive is the mapping set's own-code dual: a durable in-source
directive on a package-level variable declaration — discovered under
the same build-flag-selected source discipline as `//gofresh:pure`
(REQ-purity-directive in [purity.md](purity.md)) — declaring, on the
author's authority, that the variable's state is subject-own under
the single-subject-process execution model: process-local, fed only
by the program's own rooted flow, no cross-subject channel when each
subject owns its process. Both legs are required — the directive is
the author's half and the caller's attestation the protocol's half;
either alone confers nothing. The discharge covers the variable's
mutation, escape, and environment-audit refusals alike (the
declaration covers the variable's state wholesale), applies in
mutable-local packages only — the exact inverse of the vouch
boundary: a vouch crosses the version-pinned line because dependency
code cannot be edited, the directive covers exactly the code its
author edits and reviews, and a dependency's directive confers
nothing — is honored only when every build-flag-selected compilation
variant declaring the variable carries it (a variant without the
directive keeps every mark, fail-closed), and a load-bearing
discharge is recorded on the subject's evidence with the
attestation's other discharges (REQ-vouch-recorded in
[purity.md](purity.md)). The generated-proto descriptor cluster is the
directive's generated-file sibling: a package-level variable declared
in a protoc-generated file of the audited generator set — a
pre-package comment line reading "Code generated by <generator> ... DO
NOT EDIT." for exactly protoc-gen-go and protoc-gen-go-grpc, each name
token-bound so an unaudited prefix-sharing sibling (protoc-gen-gogo)
never matches — the
regeneration-stable in-source assertion no hand directive could
survive regeneration to make — holds the protobuf runtime's build-once
descriptor state and its lazy message-info memo, content-invariant
functions of the compiled-in schema audited at the pinned
google.golang.org/protobuf runtime for protoc-gen-go output and the
pinned google.golang.org/grpc runtime for protoc-gen-go-grpc output —
exactly the audited versions (protobuf v1.36.11; grpc v1.82.1): an
unaudited version, an absent runtime, or a mutable-local checkout
refuses fail-closed until its source is audited. Under the caller's single-subject
attestation such a variable's shared-dynamic-state marks discharge,
own-code and pinned-dependency generated files alike (the header is
the author's half, the attestation the protocol's half — the
directive's two-leg trust model applied to the generated idiom). A
pinned dependency's generated header confers where its hand directive
would be refused because the soundness rests on the audited pinned
runtime, not on the dependency author's judgment: the header only
classifies which variables the runtime carries, an actor forging a
generated header inside a dependency is a supply-chain-level
compromise outside this judgment's threat model, and a hand directive
is a semantic claim only the code's own reviewer can stand behind. A
load-bearing discharge riding the subject's evidence with the
attestation's other discharges; a hand-written sibling file's
variables keep every mark. The audited memoization set —
`gopkg.in/yaml.v3`'s `structMap`, a mutex-guarded type-to-structInfo
cache filled at exactly one site by a pure function of the type
(field ordering by struct index, no map-iteration order in stored
data, no options input, values never rewritten after the store) — is
admitted by source audit for the version-pinned module, exactly
the audited variable, and exactly the audited versions (v3.0.0 and
v3.0.1): the audit is a property of those versions' source that no
other version inherits, so an unaudited version — later or earlier —
refuses fail-closed until its source is audited. The derivation is
content-invariant, so a prior
subject's population changes timing and internal pointer identity
that never leave the package's unexported internals, never a
looked-up value — so the discharge needs no
execution attestation and rides no evidence record (it is the
engine's own source-audited verdict, not a caller assertion; the
pooling set's content proof and the mapping set's deepened audit
reach the same class by their own grounds). The set
is the source-audited precursor of a structural get-or-compute
discharge; its entries retire to that proof when it lands. It grows
only by source audit. Under the caller-attested single-subject-process
execution model the judgment additionally scopes per subject: the
hazard is a prior subject's execution in the same process, and under
the attestation there is none — the only code that executes is the
subject's own rooted flow: the subject flow and, where the subject
runs through the harness, the user TestMain flow. Package
initialization is deliberately outside the rooted set, on the model's
own ground: with no prior subject in the process, the whole
subject-owned process's state — initialization, init-spawned
goroutines, and all — is a function of the hashed source, the priced
inputs, and scheduling noise alone, so a marking site the
post-initialization rooted flow cannot execute adds no channel the
closure hash and the input pricing do not already cover (a
goroutine LITERAL spawned at init leaves unattributed marks that never
discharge; a NAMED go-callee's marks attribute and ride this
whole-process ground itself — the racing writer is source-determined
state plus scheduling noise, exactly what the ground prices). A culprit none of
whose marking sites the rooted flow can execute cannot have been
perturbed by anything but initialization: its state is an
init-determined constant for the subject's execution, and the
downgrade lifts for that subject
alone — the next reachable culprit, if any, names the refusal instead.
The reachability proof is the attributed RTA the observability proof
rides, at least as wide as that tier's dispatch and reflection
widenings, and the discharge is fail-closed on every gap: an
open-world widening or an unrooted subject symbol grants nothing (no
proof, no discharge — the judgment then stands whole), a mark without
function attribution — an init-flow refusal's, a deferral
failure's, a malformed fact's, one crossed over a carrier link, or a
literal's outside any named body —
forecloses the discharge for its variable, and a variable with any
rooted marking site keeps every mark. Named functions and methods
alike are attributable sites (a method's under its type-qualified
name). A function literal's or go statement's marks nested in a named
body are literal-borne sites of the enclosing declaration — the
mutation, escape, and carrier-method-use classes alike, while the
remaining use classes (parameter, field, and element deferrals,
carrier links) keep their fact-immediate composition: executing
the literal requires the encloser to have produced it, so the
encloser's unreachability bounds the literal wherever the value
travels — but the value outlives the encloser's frame, so a
literal-borne mark never discharges by init-only flow, and it
forecloses outright whenever init flow can reach the encloser
(transitively over the reference regions): an init-created
literal can be stored and executed past initialization by flows no
site names. The reference regions bound literal contexts by the same
encloser principle: a literal-context reference, a go-statement
callee, and a value reference nested in NAMED flow each record
against the enclosing named function — never provable init-only (the
value or deferred body outlives the frame), init-REACHABLE exactly
when the encloser is, because the reference cannot execute and the
value cannot be handed out unless the encloser ran — while the same
reference in init flow or a method body records as bare program code,
poisoned everywhere: its creation site the regions cannot bound. A METHOD encloser forecloses its literal-borne marks
outright: methods are outside the reference-region graph, so their
init reach is unknowable — fail-closed (a method's DIRECT marks keep
their attributed siting; they execute only while the method runs). A direct use needs no such foreclosure — it executes only
while its encloser runs, so an init-only encloser makes it
init-determined and an unreachable one makes it dead. An environment-audit refusal rides the variable's use-site
inventory when the variable's type is not directly callable — the
value-plane rule already marks every extraction able to execute the
carried value — while a callable variable keeps a markless execution
channel (its call is a tolerated read) and its environment refusal
never discharges. The inventory is per variable and class-blind: any
foreclosing mark keeps every rank's refusal for that
variable. The audited discharge channels
— pooling, mapping, memoization, the vouches, and the
`//gofresh:single-subject` directive — decide before this scoping and
are never weakened by it: they remain the channels for state the
subject's own rooted flow DOES write, while the reachability scoping
covers the sibling-only state no channel needed to name (the
oracle-shaped directive use — an arming site unreachable from the
subject — is subsumed by it; the directive remains for rooted
subject-own state). A load-bearing scoping — one that discharged a
culprit for the subject — records the discharged variables on that
subject's evidence with the attestation's other discharges,
canonically and never silently (REQ-vouch-recorded in
[purity.md](purity.md)): the discharges are attestation-borne exactly
as the audited sets' are. Under the caller-attested PACKAGE-PROCESS
execution model — every process that runs a measured subject is the
subject package's OWN test binary, under any subject schedule — the
judgment scopes to the analyzed BINARY instead: the multi-subject
hazard is a sibling subject's execution in the same process, and under
this attestation every sibling is itself one of the binary's harness
roots — the Test, Benchmark, Fuzz, and Example functions of both test
variants, each riding the user TestMain flow where the harness runs
one — so the quantification widens from the subject's rooted flow to
the union of every harness root's post-initialization attributed
reach, and a culprit none of whose marking sites that union can
execute is init-determined state for EVERY subject of the binary,
whatever the process's subject schedule: the downgrade lifts for the
binary's subjects together. The attestation is weaker than the
single-subject one — it bounds WHICH binary runs, never how many
subjects share it — and the single-subject judgment takes precedence
where both hold (each is sound under its own model; neither dominates
the other's discharges); without either attestation no reachability judgment
applies, because an unattested consumer may run the subject through
any binary at all, whose roots the analysis never saw. Package
initialization stays outside the rooted set on the same ground —
with no root reaching a site, no prior subject wrote it, and
initialization remains a function of the hashed source, the priced
inputs, and scheduling noise. The judgment is fail-closed on every
gap of the per-subject form plus its own: an ambiguous harness-named
root (the two test variants sharing a top-level name — the binary
runs one of the colliders and the inventory cannot say which) or any
harness root's open-world widening leaves the binary's inventory
incomplete, and an incomplete inventory grants nothing; harness
membership is judged by name alone (a name-matching function the
harness would refuse only widens the root set — a spurious root
withholds a discharge, never grants one); a binary declaring no
harness roots is vacuously complete with an empty inventory (nothing
executes past initialization in its test process). A load-bearing
judgment — one that discharged a culprit for the binary's subjects —
records the discharged prefix of the culprit walk on each subject's
evidence (the walk stops at the first survivor, which names the
downgrade), canonically and never silently, attestation-borne exactly
as the per-subject scoping's (REQ-vouch-recorded in
[purity.md](purity.md)); the attestation is part of the persisted
fact identity, so option-on and option-off sessions never serve each
other's facts. One narrowing applies to
the escape class alone: an
interface-typed variable is object-closed when every attributable `init`-flow
store — a direct store the auditing package resolves to the variable, from any
package — is a provably-immutable audited construction (`errors.New`; any
value of static type `reflect.Type` whatever expression produced it — the
interface is sealed by unexported methods, so its every referent is the
runtime's canonical type descriptor, never written after construction, a
`reflect.TypeOf` result, a chained view method's result, and a rebind from
another descriptor alike, the producing expression's operands keeping their
own pricing at the use walks;
a direct `fmt.Errorf` call whose every argument is audited — a constant, a
nested audited construction, or a variable reference as below, the chained
admission recorded as a dependency
edge and falling with the referent's closure at composition whatever the
declaration or store order, any other argument shape refusing fail-closed, the
judgment structural over all arguments and never a reading of the format
string; a constant-valued expression — a literal, a named constant, a folded
expression — whose boxed basic-kind value carries no mutable reach at all, so
no holder of the stored value can write through it; a reference to a
package-level interface-typed variable — sibling or imported, a bare
identifier or a qualified selector, resolved semantically by the type checker
(a dot-imported name resolves to its one object; no textual ambiguity
survives type checking) — itself object-closed, the re-export idiom's shape,
recorded as a dependency edge falling with the referent's closure at
composition, a referent no fact declares (a module-less package's variable,
which no audit covers) refusing fail-closed there;
the nil zero value), the initializer included; an init-flow appearance the audit cannot
attribute — an indirect or range-bound store, an address capture, or a
non-audited value — breaks the closure from whichever package performs it. No holder of
an object-closed value can mutate the shared object, so escapes of the value are
not mutation, while rebinding the variable remains mutation everywhere; the
discharge extends to method calls and method-value binds through the
variable, because every admissible referent's method set is read-only over
immutable data by the same source audit (`errorString` and the fmt wrap
errors' `Error` and `Unwrap`, the runtime type descriptors' view methods), a
constant-boxed referent dispatches value-receiver copies that cannot reach
the box, and a nil referent panics before writing. The
audited-construction set grows only by source audit. An escape never
discharges by init flow — the alias outlives initialization. Proven
init-only functions are scanned for escapes under the full use-shape
rules; `init` bodies and qualified helpers are scanned exactly for
alias-creating bindings — an init-flow local bound from a carrier by
whole-identifier assignment or declaration, by range binding, as a
builtin copy destination, as a qualified helper's parameter bound at
an init call site (carried across bodies to the same fixpoint, under
the alias-handing type gate of the value's landing type — a non-spread
variadic argument lands as the element, boxing into an interface keeps
the gate's fail-close — for the direct, parenthesized, and
generic-instantiated call spellings; a conversion-wrapped or
func-value spelling refuses fail-closed through the escape backstop
instead), or
through a composite target (a struct field, element, or indirection
store binds its base coarsely — the whole base is the carrier),
chained to a fixpoint,
is the carrier inside nested program code —
while init-flow stores and calls stay exempt from the mutation marks;
a carrier call-argument still earns its deferral or the fail-closed
escape wherever it appears, and a carrier method-call receiver in init
flow — handed to the callee exactly as an argument is — defers to the
method's receiver retention fact: statically dispatched non-interface
methods whose results hand out nothing, the receiver a bare identifier
naming the package variable (an expression or foreign-qualified
receiver keeps the escape), the method provably never
escaping or outliving its receiver while writes through it are
tolerated (init flow's own exempt shape), an unproven, dispatched,
result-handing, or value-bound method keeping the fail-closed escape —
a bound method value retains its receiver past initialization. An init-flow
bind or store whose target is itself a carrier links the two keys as
one storage — mutation, escape, and environment marks crossing the
pair symmetrically and transitively at composition, since the shared
backing is one object under every name it carries — reach-free
sources recording no key and staying unlinked. Two further narrowings
discharge specific escape shapes by proof: a carrier passed as a direct
call argument to a plain named function — a deferred call included, a go
statement's arguments never, since the goroutine runs concurrently, and
init flow like program code, since the alias outlives initialization —
defers to that parameter's leak-free fact, recorded by the declaring
package (the bound value provably never writes, escapes, or outlives
the call, with every unrecognized use refusing) and resolved at
composition, absence refusing, a carrier argument to any other callee
shape keeping the fail-closed escape. A callee that writes its
parameter refuses the program-code deferral; an init-flow argument
defers instead to the parameter's retention fact — the bound value
provably never escapes or outlives the call, its writes through the
binding tolerated exactly as the region's own stores are exempt, the
write-path element and field reads feeding those stores priced as
writes rather than handouts — recorded beside the leak-free grade,
chained and resolved identically with either grade satisfying an
edge, absence refusing; and a range binding over an alias-handing
carrier discharges the iteration read when every alias-handing bound
value is proven leak-free over the loop body by the same judgment,
fail-closed on any other binding shape — where the leak-free judgment
recognizes the call of a func-typed field of a bound value: the target
is the field read the read shapes already judge, and the callee receives
only its arguments, judged like any call — a rooted alias-handing
argument through such a field call deferring to the field position's
registered population: every value the environment-free registration
audit admits into the carrier contributes a recorded disposition for
each func-signature field it can populate — a plain named registrant
defers each parameter index to that parameter's leak-free fact, an
audited literal registrant is judged at registration with its own
deferrals carried, and a proven return-environment-free constructor's
results contribute the constructor's recorded field marks, joined
through the carrier's constructor-registration pairs transitively over
the proof's dependency edges — while a method expression, a
re-registration the walk cannot attribute, and every other shape poison
the position or the whole population (a method value never reaches the
population: its receiver environment already refuses the carrier at
admission), marks pooling by field name
across composite levels since a nested value can become a judged
binding through the taint chain; at composition the use discharges only
when no poison covers the position, every deferral resolves against the
leak-free union, and every constructor resolves, any malformed record
marking the declaring fact's variables fail-closed — and a carrier
argument to a callee-position index read of another carrier (the
dispatch-table shape) defers identically to the dispatch carrier's
element population, a reserved position the same records carry: a bare
registered function dispositions per parameter index exactly as a
field registrant does, a registered literal is judged at registration,
and a proven constructor contributes its whole body's value-position
dispositions through the return-environment-free channel - every
bare-function reference dispositions per parameter index, callees
handed a tracked binding or producing a signature-carrying result join
their own recorded populations over the proof's dependency edges, a
callee or receiver the proof cannot attribute breaks the binding it
reaches, and every other signature-carrying value-position shape
poisons the element position, fail-closed; go statements never defer,
and init flow keeps the escape; and where a rooted
alias-handing argument to a plain named function defers to that
parameter's leak-free fact exactly as a carrier argument does — the
binding proof records the parameter keys it relies on, the range
discharge carries them as the carrier's deferred argument marks resolved
at composition, and a parameter's own fact-time proof chains
through same-package parameters to an intra-package fixed point with
mutual recursion refusing, while a chain touching a foreign parameter
records conditional edges naming the parameters it depends on,
resolved at composition to a least fixed point exactly as the
constructor proofs resolve - cycles and absence refusing; and a method
call on a bound value defers identically to the method's
receiver-read-only fact — statically dispatched non-interface receivers
only, the call's instantiated results handing out no mutable reach —
carried as the carrier's deferred method-use marks in the existing
encoding, an unproven method marking mutation fail-closed, with a
fact-time parameter proof chaining only through same-package
receiver-read-only methods; inside the
judgment as at the discharge, no call within a go statement's subtree
defers its arguments or its method receivers — a goroutine literal
wrapping the call is the
same concurrent execution as the direct spelling. A third narrowing
admits return-position handouts: a range binding returned by an
unexported plain named function discharges when every in-package use of
that function contains the handed-out alias — a call result bound to
identifiers proven leak-free over the using body by the same judgment,
deferrals included, a discarded result, or return-position propagation
chaining the disposition to the propagating function's own callers,
resolved to a package-local fixed point; a value reference, an
argument- or composite-position result, a binding the walk cannot
judge, propagation through an exported function, a method, or a
package-level literal, and a return inside a nested literal refuse,
restoring the escape — deferred marks collected en route remain, the
escape dominating at composition. Package-level literals and
initializer expressions are use sites like any body — a direct
initializer-position call is contained only when every alias-handing
result lands in a blank. The disposition is package-local and adds no
persisted encoding — deferrals it collects ride the existing
parameter-fact marks. Persisted parameter facts key
package path, function name, and zero-based parameter index NUL-joined
— a variadic call's trailing arguments key the final declared
parameter's index;
deferred argument marks join the variable key to that parameter key —
an entry a consumer cannot parse marks every variable its fact declares,
fail-closed like every malformed-fact arm (a malformed deferral of a
foreign variable keeps only the declaring fact's marks — the accepted
residual every malformed-fact arm shares).
Every admitted read path is sound only under the environment-free
registration audit: a function-carrying value a package's direct code
stores into a carrier — its own or a foreign one, initializer
expressions and builtin copies included, a store through a local alias
of the carrier resolved to it, stores inside nested literals
and go statements excluded as program code the mutation rules refuse on
their own — must be environment-free. A plain named function, a method
expression, and nil carry no environment; a function literal is
environment-free when every variable it references from an enclosing
function scope proves leak-free under the use-shape judgment over the
literal's body and over every sibling literal of the enclosing body
referencing the variable's alias set — the set closed over every
whole-identifier binding, range binding, and builtin copy of the
enclosing body whose source expression reaches an enclosing-function
variable of mutable reach, address, reslice, wrapping, and call-result
chains included by the source walk, since a shared environment is one
object under every name it carries and however many carriers its
closures reach — with a
reference to the alias set from a go statement's call outside any
literal refusing outright. A call result whose callee is a plain named
function — a bare identifier or package-qualified selector,
receiverless, explicit generic instantiation included with the
dependency key instantiation-independent — defers to that callee's
return-environment-free proof:
the store records the callee against the carrier, the call's arguments
judged recursively by this audit (a carrying argument poisons the
store), and composition admits the store exactly when the proof
resolves. The declaring package proves a function
return-environment-free by judging every return expression under this
audit with parameters assumed environment-free — the caller's
obligation, discharged at each call site by the recursive argument
judgment, and an argument that is itself a plain-named-callee call
defers identically, its callee joining the recorded set; a
signature-carrying local judges by every binding source that reaches
it, to a fixed point, where a source judges through the caller-judged
derivations — a whole-identifier bind of a judged value, a multi-value
bind sharing one judged call, a range binding over a judged container
whose elements are the value itself — slices, arrays, pointers to
arrays, maps, strings,
integers; a channel's elements are sender-supplied and a function
range's yield-supplied, so those bindings break — a field read of a
judged value, an element read of a judged container (the same
containers the range clause admits; the comma-ok form's second
result is boolean and free), a cyclic binding chain among the
derivation edges judging by its external sources and stores alone —
recirculation contributes no new values — an append
of judged elements (an append onto the binding itself flowing only the
new elements), a conversion of a judged value, an instantiated
reference of a named function, a call of an audited value-plane
standard helper with judged arguments — slices.Clone, slices.Concat,
and maps.Clone, a closed set whose results carry exactly their
arguments' values — and a call of a plain named callee with
judged arguments, explicit generic instantiation included with the
dependency key instantiation-independent — and a zero-valued
declaration binds the nil zero value, environment-free. An element,
field, slice-step, or dereference write of a present value is a
store. A slot write — one whose chain stays on the root's owned
spine: for a root bound only from body-owned storage (fresh
allocations, appends and conversions over them, and values read back
out of such containers, transitively), an initial dereference of the
root's own pointer, selector steps over struct values, and at most
one index in final position taken on the root's own header, past its
own dereference and slice steps over that same header at most — a
header reached through a selector may have
arrived inside a held copy, invisible to body-ownership; for any
other root, selector steps over
struct values alone — lands in the root's own storage, and the base
stays judged exactly when everything stored into it judges, the
store set unioned across names sharing one storage (index operands
and other subexpressions stay reads). Any other chain may write
storage the root does not own and breaks the root outright —
fail-closed. A valueless write, and any store into a parameter's
storage or a name sharing it, break the caller's assumption
outright. Every bind and store links its target (for a store, the
written base) to each reach-bearing tracked name its source
expression reaches, the link kind following the value that flows: a
header-sharing value — pointers, slices, maps, and every non-copy
shape, appends and their nested or non-plain bases, conversions,
call results, and literals embedding a tracked value included —
makes the two names one storage, breaks, stores, and the parameter
refusal all crossing the pair; a struct or array value is a copy
holding reach into its origin — breaks cross the pair fail-closed,
while the holder's own storage stays its own. Range bindings link at
the container's kind: a value-array range copies its elements and
links held; every other container links as sharing — fail-closed.
Reach-free values stay unlinked as independent storage. While any
other derivation, an address capture of the binding — an ident-rooted operand breaking its
base binding, a call-rooted operand breaking every tracked name it
reaches (the call may hand back any of their backing), and a
composite-literal operand addressing fresh storage whose embedded
tracked reach the bind link carries in bind position and the
returned-literal audit in return position, while in argument position
the embedded tracked names break — the callee holds a write path into
their backing the population sweep never sees; audited value-plane
callees, proven non-mutating, keep the exemption; builtin callees are
likewise exempt, append and copy never holding the argument beyond the
call, their destinations covered by the bind link and the copy
target-break — the implicit
address of a pointer-receiver method use included, exempting methods
the declaring package proves receiver-read-only — or any bind
position or address
capture of a parameter, breaks the binding or the parameter's
caller-judged assumption outright; a returned literal is audited exactly as a registered
literal with the constructor body as its enclosing scope, its
collected parameter and method wants resolving against the declaring
package's own facts only; a plain-named-callee result inside a return
expression records a dependency edge, the proofs resolving at
composition to a least fixed point over the edges; naked returns and
every unrecognized signature-carrying shape refuse the proof. Cycles
and absent proofs keep the store's poison — fail-closed. Every other
value shape — a bound method value, a call through anything but a
plain name (builtin make and new excepted: they construct empty or
zero values, and no function value rides them), a parameter, an opaque
local or variable of
function-carrying type — is beyond the audit; the one further
call-shaped
admission is append of judged elements onto the stored-to carrier
itself, whose result carries only what its operands did. A carrier that
receives a value outside the audit refuses every observer, whatever the
read shape, with a culprit naming the variable and this audit: a
registered closure's environment can write state the settled verdict
assumed stable. The audited carrier keys ride the per-package fact as a
plain key list, unioned at composition; mutation and writable-escape
culprits outrank this one.
`init` flow is the initializer expressions, the `init` bodies, and the
init-only-reachable functions: plain named functions — exported included —
whose every reference, in every package of the analyzed graph, is a direct
call from an initializer expression, an `init` body, or another such function,
resolved to a graph-wide least fixed point at composition from per-package
reference-region facts (mutually recursive candidates refuse — deliberate
conservatism, and a function no fact references refuses by absence); any value
reference, any receiver, or any reference from ordinary program code — a
nested function literal wherever it appears, and a go statement launched from
init flow in its entirety, callee and arguments alike, since the goroutine
outlives initialization (a deferred init call stays init flow) — refuses the
class fail-closed anywhere in the graph. Carrier mutations and method uses in
such a function's direct body attribute to it and are judged by the resolved
class; literals and go statements nested inside it remain program code. A
persisted attribution a consumer cannot parse marks every variable its fact
declares — fail-closed like every malformed-fact arm. A qualified in-package
helper's stores stay audited for object-closure exactly as an `init` body's
are. Function bodies nested in package-level declarations,
in `init` bodies, or in qualified helpers are program code, not initialization;
non-Go writes need no rule here — packages built with cgo or
assembly sources are already downgraded whole by the native-code and linkage
blind-spot dispositions. The toolchain-generated test-main package is startup
scaffolding, not an analysis surface: its registration tables contribute neither
declarations nor mutations, the same disposition REQ-closure-analysis gives its
registration initializer. A dynamic-capable variable the program never
mutates under these rules is ordinary source — the closure hashes its initializer like any
declaration — and confers no downgrade; the unconditional type-level blanket would
refuse verifiability to nearly every real program, since hook-typed package
variables are ubiquitous.

**REQ-closure-shared-dynamic-state-reason** (behavior): The shared-dynamic-state
downgrade's refusal reason MUST name the owning package and a mutated variable,
be distinct from the signature-dynamism refusal — the two channels are
separately actionable — AND name the discharge channel the culprit's boundary
affords, so a correct refusal is never a dead end: a version-pinned dependency
variable names the caller-vouch channel by the variable's canonical identity
with the vouch's full audit obligation (for a function-value carrier that
obligation includes the registered values' environment-freedom, since the lift
covers the environment-audit rank too); a mutable-local variable names the
restructure and the single-subject directive with its attestation caveat. The
reason may illustrate a consumer CLI spelling, but the channel and identity are
the contract — consumers differ in how vouches are supplied.

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
unsafe reach open; a channel opens exactly when its element does; the
toolchain's `sync/atomic.Pointer[T]` reads as `*T` under the audited
atomic transparency, REQ-closure-shared-dynamic-state);
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
root provenance: any external effect attributable to a package initializer
rather than the subject is outside subject-time observation and blocks the
proof, while subject flow is classified against the admitted observation
set. User test-main flow classifies within subject-time observation: the
test log installs in the toolchain-generated test-main package's
initializer — after every dependency initializer and before the user test
main — so a user test-main read is a bracketed observation input, admitted
per effect through the same per-site observation admissions subject flow
answers to, with a blocking test-main effect refusing under its own
reason. The canonical test-main epilogue `os.Exit` is harness protocol,
not an effect: it runs post-bracket and adds no input channel to any
subject's execution (an exit before the harness run means no measurement
ever runs — an execution condition, not an observability leak). The
observed walk admits it throughout user test-main flow — helpers
included, since an exit anywhere in that flow means the harness
protocol ended or never ran a measurement — while the package-scan
backstop scopes its admission to the syntactic `TestMain(*testing.M)`
declaration, the conservative direction for text the scan cannot
attribute to flow. Every reachable call and effect is classified to the walk's end; the preferred
human diagnostic is derived afterward and can never select which facts
participate: a refusal names the highest-ranked blocking effect under one
cause-preference order shared with the legacy single-reason projection —
the maximal tier's package diagnostic is an instance of that projection
and owes the same order, selecting over its blocking effects together
with the plain always-external import candidates — an always-external
package imported under any non-dot, non-blank spelling names its
package reason at that
class's rank even where no use blocks, because the import is the
scan's strongest name for the dependence, while the unused import
itself bears no verdict and never widens the effect set; the dot and
blank spellings record the effect outright —
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
grant the proof on its own. The unsafe reference class is narrowed out
of the scan's blocking set: an in-scope `unsafe.Pointer` reference is
diagnostic only, because the subject walk prices every attributed
unsafe-typed value and a subject world the walk cannot close refuses
independently — a subject reaching unsafe-typed state still refuses at
its own tier, while a sibling declaration's unsafe (an
operator-grammar fixture, a low-level helper file) no longer blocks a
clean subject's proof; the package's other operations (unsafe.Slice,
unsafe.String, and kin) keep the scan block, because their call sites
carry no unsafe-typed value the walk can price and a fabricated slice
or string is a testlog-invisible read. The audited-pure standard set — packages and named
operations through which every ambient effect must enter via a flagged
constructor or global of an effect-bearing package, adding no
testlog-invisible input channel of their own and no machine-variant
results (fmt's Sprint family included: argument methods stay visible to
reachability; math/big's value constructors NewInt, NewFloat, and NewRat
included: software arithmetic over their operands, no CPU dispatch;
time.Date included: calendar arithmetic over its operands, the ambient
timezone channel entering only through the Location globals and
constructors, which stay flagged — time.UTC is an exported mutable
variable and refuses like any other; execution-free references
included: an audited type or constant name — fmt.Stringer, time.Time,
time.Month and its twelve constants, math/big's Int, Float, and Rat —
declares or denotes and executes nothing, every dispatch through a
value of such a type classified at its own site, and the pure value
methods sharing an audited name admitted with it) —
is deliberately bounded by
two exclusions that are soundness, not caution: reflect defeats static
reachability itself, so only its invoke-nothing members are admitted —
the runtime-type set and the structural comparator DeepEqual, which
performs no method call and compares function values by nil-ness alone —
and registration-shaped covert channels — flag registration returns
pointers whose values change at Parse, and gob registration mutates a
package-global type registry a sibling subject's decode can depend on —
are channels the testlog cannot audit. The registration WRITE itself is
tier-scoped: standard flag registration through the value and pointer
families (Bool through Duration and their *Var forms) reached in
startup or user test-main flow is a process-local registry mutation
admitted by those walks and by the package-scan backstop — the
registered storage holds the default until Parse runs, in harness flow
at the earliest. That admission is sound only paired with a
program-wide sink judgment at every statically dispatched registration
call site — a dynamically dispatched family-named target keeps its
classification, since no sink can be judged there: the registered
storage (a pointer-family call's target argument, every store of a
value-family result) must trace, through field and index selections,
to a package-level variable. A traced variable refuses any later
reference in every analyzed flow — subject, test-main, and startup
alike — as the channel's read side: a subject or test-main reference
reads state Parse can have written, including the unparsed default,
and a startup reference is at best a default read and at worst an
escape of the storage's address into subject-reachable state, an alias
the trace cannot follow. A sink that does not trace blocks every
subject sharing the program. Parse, Lookup, and the
callback families (Var, TextVar, Func, BoolFunc — arbitrary code at
Parse) keep the exclusion everywhere, and subject-flow registration
keeps the exclusion whole. One admission in the audited set is
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
runtime-configuration reads) keep their own classifications. The audited
set likewise carries the harness's subtest drivers — exactly `(*T).Run`
and `(*B).Run`, matched by receiver and name: the driver allocates a
child harness handle, prints run-boundary bytes into the recorded
output, keeps write-only harness bookkeeping no testing API hands back,
consults run-filter state that shapes selection and recorded-output
bytes only — outside the proof's claim exactly as the logging path's
presentation state — and runs the caller-supplied callback on a
harness-managed goroutine it waits for, returning only an outcome bit.
The callback is subject flow: its body is walked and classified at its
own sites, and the walk records the reached driver as an admitted
harness fact instead of descending into harness internals. A parallel
subtest defers its body past the driver's return; `Parallel` keeps its
test-runtime classification, so the interleaved shape refuses.
Receiver discrimination is load-bearing: `(*M).Run` is test-main flow,
not a subtest driver, and keeps its classification, and `(*F).Fuzz` is
no admission candidate at all — it dispatches its target reflectively
(an unwalked body can earn no proof), consumes corpus files that are
semantic inputs, and can coordinate worker processes — refusing at the
subject tier, while the package-scan findings for the driver names,
blind to receivers, narrow to diagnostics so the subject tiers decide.
The driver admission applies to static callees only — a driver reached
as a dynamic target or through a bound value keeps its classification,
the conservative refusal — and the toolchain's declaration inventory of
the driver names is walked by an enforcement test so drift refuses
instead of silently widening. The audited property-testing harness —
exactly `pgregory.net/rapid` — extends the same discipline to a
third-party harness package: its bodies are cut from every walk and
from the package-scan backstop, because everything ambient in them is
the harness's own protocol (the run configuration it reads and the
clock it paces by surface in its harness-log summary line on every
outcome, its failure artifacts are output-only reproduction files, and
its value generation is process-local PRNG state seeded by that same
log-surfaced configuration), and the property callback is subject
flow, walked and classified at its own sites through the harness's
dispatch. The audit is version-gated — it names the releases it
covers (v1.3.0) plus local source, a deliberate choice rather than a
silent registry upgrade, and an unlisted release keeps the package's
ordinary classification. The audit is sound only paired with a
boundary gate on every flow that can call into the harness — subject,
test-main, and startup alike: each dynamic-carrying argument of a
statically dispatched harness call must be judged closed, where the judgment
admits exactly the subject-closed value walk, the harness's own
handed-in handle at parameter position (the property harness's `T`
and the standard harness's `T`/`B`/`TB` — constructed only by their
harness behind unexported fields and handed per-invocation; a handle
loaded from shared state is a sibling invocation's value and refuses
like any other load), a gate-passing harness call result (the wrapped
callback and generator values, closed for dispatch judgment wherever
they later cross a gate), and a locally built variadic slice of
judged elements; every other value — a load from shared mutable
state, a generator laundered through an ordinary parameter whose
callers pass unjudged values — widens the subject world. Harness-
owned TYPES confer no admission by themselves: a gated call's closure
is per-subject provenance, never a per-program fact a sibling's flow
could have supplied. A named harness function reached as a dynamic
target keeps the conservative refusal — no static site exists to gate
the crossing — while an anonymous harness function (the wrapped
callback MakeCheck returns) is admitted as a subject-flow dynamic
target: it exists only because a gated harness call in some analyzed
flow created it, which is exactly why every flow carries the gate;
the test-main and startup arms stay stricter and refuse every
dynamically reached harness target. Importing the audited harness
keeps the package unverifiable at the closure tier — the audit admits
observation, never purity: a property run's outcome rides the
harness's log-surfaced run configuration, not the sources alone, so
the package scan records an admitted harness fact where it exempts
the harness's files. An open-world refusal names the dispatch edge
that widened it — the enclosing function and, for an unresolved
interface invoke, the receiver interface type and method it
dispatches, or, for a computed call, the stably-identified value it
calls (a parameter, or a value read from a named package-level
variable, naming the edge by the variable) — so the
refusal points at the specific dispatch rather than the bare shape;
the naming carries no source position, so it stays portable across
checkouts and stable under the lexicographic-least selection that
picks one edge deterministically from the widened set. An interface
dispatch the walk cannot resolve widens the subject world — the synthetic
interface-method wrapper family (any interface, the harness included)
carries the same obligation in the closed-value walk itself: a bound
wrapper's closure value closes only through its captured receiver, a
thunk value never closes (its receiver arrives at call sites the value
walk cannot see) and a static thunk call judges its receiver argument, so
a wrapper over sibling-planted shared state refuses exactly as the direct
invoke would, whatever carried the wrapper to the call — with one
subject-determined dispatch admission: a site does not widen when its
RTA-enumerated, subject-attributed target set is non-empty, every
target is an audited harness method or an analyzed function of an
indexed non-test-main package (an unindexed or test-main target
refuses the admission; a harness method classifies as the admitted
harness fact, a standard-library target classifies through the audited
symbol tables exactly as an enumerated dynamic target always has, and
every other target's body classifies its own effects into the subject
exactly as reachable content always does),
AND the dispatch operand's dynamic types are fully determined by
the subject's own flow — the operand derives from local construction or
from a parameter whose function is not dynamically targeted, closes over
nothing, is not variadic, and has at least one subject-attributed call
site, every such site feeding a subject-closed value (zero enumerable
callers is absence of provenance, refused, never a vacuous pass); a load
from shared mutable state refuses, because analysis is
subject-scoped while the process heap is shared, so a sibling subject's
runtime flow can plant an implementation the subject's attributed
enumeration cannot see. The subject-determined operand is the
admission's soundness pillar: it proves the runtime callee's concrete
type was materialized in subject-attributed flow, so the enumerated
target set contains it and its effects were classified — the admission
keys on dispatch shape (operand provenance and target analyzability),
never on what any target's effects happen to be; the effects then
refuse or admit on their own terms. The maximal scan's receiver-escape rejection
is package-scan diagnostic, not a package blocker: every subject-tier
dispatch on an escaped harness value is classified — admitted only under
this admission, widened or effect-recorded otherwise — and user test-main
flow, the one flow classified within subject-time observation that can
dispatch a test-planted value after the harness run, refuses on any
dispatch whose provenance is not locally closed — the operand under the
same wrapper-carrying closed-value walk, with a static thunk call judged
by its receiver argument, because the wrapper family's
toolchain-attributed bodies perform the real dispatch where no walk
records effects; the planted channel is a load from shared mutable
state, while a test-main's own calls and constructions keep their
per-effect classification. Initializer flow keeps attributed-effect recording alone:
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
memo is a cache, never a record: it lives under the user cache directory by
default — the consumer may redirect the store root or disable persistence
process-wide through one knob covering every memo class, and no knob position
changes a verdict, only what is recomputed — writes atomically, and a missing,
unreadable, corrupt, or key-mismatched entry recomputes silently; no entry is
trusted beyond its key — the key IS the freshness. Entries accumulate one per closure version and the cache is
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
sibling directory under the consumer-controlled store, atomic writes, silent
recomputation on any miss, corruption, or key mismatch, deletable wholesale
at any time; changing fact semantics bumps the fact-strategy version.

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
sibling directory under the consumer-controlled store, atomic writes,
silent recomputation on any miss, corruption, or key mismatch, deletable
wholesale at any time; changing scan semantics — classification tables
included — bumps the scan-strategy version.

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
