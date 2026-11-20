# The source closure

The source closure is the heart of freshness: the set of declarations whose change
could move a subject's behavior. Getting it *sound* — always a superset of what can
affect the subject — is the whole obligation, because the one forbidden outcome is a
subject reported valid while source it depends on has changed. This document defines
what the closure covers and how every gap in the static picture is dispositioned so
the covered set never narrows below the truth.

Implementation claims follow REQ-closure-observability-toolchain-key and
REQ-fresh-dependency-identities. The operation
families below specify properties and use-site obligations to verify, not
permission obtained by recognizing a package, declaration, type, version or
generated-file label. Every positive implementation claim requires a checked
derivation over its selected implementation, including the subordinate claims
it uses. A summary may replace walking a body only with that authority.
Conservative classifications remain available without a positive proof, and
explicit caller assertions retain their separate authority.

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
compartment's top-level declarations and per-file header identities, together
with binding evidence over its compiled files and the base package's Go files,
exposed as data for a consumer to persist at capture and diff at check.

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
package contributing a reached declaration, the files embedded and read through
them, and, whenever `runtime/debug` participates in the dependency graph, the
mutable-local module and workspace manifests (`go.mod`, `go.sum`, `go.work`,
`go.work.sum`, and `vendor/modules.txt`) from which the Go build embeds module,
dependency-checksum, vendor, and default-`GODEBUG` metadata — so that flipping a referenced constant, changing a
referenced type's layout, editing an `init` side effect the subject observes,
editing an embedded data file, or editing module metadata read through
`runtime/debug.ReadBuildInfo` moves the closure hash even when every function
body is byte-identical.

**REQ-closure-stdlib-cut** (behavior): The closure MUST exclude standard-library
declarations from the hash while still traversing call edges through them — the
standard-library dependency is represented by toolchain evidence rather than
duplicated in every subject's closure. A reported version alone does not
establish source-content identity or implementation semantics: analyses obey
REQ-fresh-dependency-identities and REQ-closure-observability-toolchain-key. Excluding
standard declarations from the closure hash does not exclude their dependencies
from implementation identity or grant a semantic claim about their behavior. A callback
from a standard-library function back into the subject's own code still stays
reachable and hashed.

## Tiers and the sound floor

**REQ-closure-floor** (invariant): The closure hash MUST default to the maximal
closure and narrow below it only where the narrowing is proven not to drop source
able to affect the subject — so soundness holds by construction, the worst case
being the maximal source set and never less, and every precision gain being a
provably safe shrink rather than an optimistic guess.

**REQ-closure-view-maximal** (behavior): A multi-subject analysis view MUST
preserve the source guard separately from implementation refinement:

- **maximal-identity** — The default source guard is the maximal selected
  test-binary closure of each subject's package, hashing every non-standard
  dependency whole — each member by its canonical form where
  REQ-closure-canonical-member affords one, by its bytes otherwise — together
  with the mutable-local module and workspace manifests (`go.mod`, `go.sum`,
  `go.work`, `go.work.sum`, and `vendor/modules.txt`) whenever `runtime/debug`
  enters the dependency graph (whose existing manifest files also join the
  view's source-file inventory under REQ-fresh-view-source-identities), and salting
  that package closure with the subject identity. The subject package's own
  test-variant nodes' source members are excluded from that core hash: their
  production members already ride the base package's contribution, and their
  test-only members fold into the test-variant compartment instead
  (REQ-closure-test-variant-hash). Test-only dependency nodes remain core
  contributions whole, including dependency nodes recompiled against the test
  binary, because a new package's initialization enters its behavior. Subjects
  in one package observe the same source set without making fingerprints
  transferable between identities. An unrelated sibling edit may still stale
  them together — the safe price for hashing whose time and live memory are
  bounded independently of subject count — while a sibling-test edit stales
  through the compartment rather than the core.
- **implementation-refinement** — A checked per-subject implementation claim
  may refine ordinary maximal-tier unverifiability without narrowing or
  replacing either hash. It identifies the structured blocker and its subject,
  selected source, startup dependencies and effect scope, and establishes the
  exact obligation represented by that blocker. Discharge covers only those
  typed blockers; a diagnostic string, package name or undifferentiated proof
  bit cannot select them. Every other blocker and applicable guard remains
  decisive. Nominal Go bodies alone cannot discharge runtime dependences:
  REQ-closure-observability-toolchain-key additionally binds the claim to
  selected standard-library implementations. This refinement grants
  no observation coverage, delivery, outcome or harness-completion authority,
  and retains the declared model's machine, timing and termination limits.

**REQ-closure-test-variant-hash** (behavior): A fingerprint MUST record,
beside the maximal closure, the subject package's test-variant compartment: the
hash over the package's own test-only files — each own test-variant node's file
set minus the base package's file set, in-package and external variants folded
together — under the same per-file name-and-content-hash discipline as the core's
file folding, unsalted, so every subject of one package shares the compartment
that describes the package. Under one listing configuration — the build
selection, the platform and cgo environment the listing runs under, and the
toolchain — and one identity strategy (REQ-closure-identity-strategy, which
excludes the analyzing frontend by design), equal
compartment hashes carry equal compartment declarations and raw header identities
(the ledger surface is REQ-closure-test-variant-ledger): those entries are a function of the bytes
the hash folds, of that configuration, and of that strategy alone — a member's
kind as the toolchain lists it follows its own name and constraints and its
siblings' embed directives, which the hash folds, under the configuration —
while the hash is unsalted by any of them, so a ledger is a fact of the hash,
the configuration, and the strategy together, never of the hash alone.
The complete ledger additionally describes base-file bindings and effective
import names, so its identity also depends on the core closure. Consumer
obligation: a consumer keying complete ledgers per compartment hash keys per
core identity, listing configuration and identity strategy too. Enforced by
`TestCompartmentLedgerIsAFunctionOfTheHashUnderOneListingConfiguration`
and
`TestCompartmentHashIsUnsaltedByTheListingConfigurationAndTheLedgerIsNot`.

**REQ-closure-test-variant-identity** (behavior): A package with no test files
MUST record the defined
constant empty-set identity, stable for as long as the package has none; the
empty string is never a computed compartment, so an empty recorded compartment
identifies a recording that predates the compartment and fails closed to stale
with reason "test variants". Verdicts order the comparison after the core: an unchanged
core with a drifted compartment is stale with the stable reason
"test variants" — the one verdict reason a consumer may discriminate on — and
no observation evidence alone rescues it. The effective compartment is the
producing compartment unless an explicit consumer-selected inert extension
established a recognized applicability endpoint
(REQ-fresh-applicability-transform in [overview.md](overview.md)). A drifted core is
stale on the closure. Both unchanged keep the prior semantics
exactly. A subject declared in a test file has its own body in the
compartment, so an edited recorded test moves the compartment — that is the
partition working, not a leak. A package whose core contribution widens to its
whole directory (non-toolchain assembly, cgo callback blind spots) may keep test files
in the core as well: sound, merely undiscriminated.

**REQ-closure-test-variant-ledger** (behavior): A compiled member's
ledger derivation — its declarations and header — may be served from a
persistent memo under the member's name and content digest, scoped by
a parse-strategy version and the analyzing frontend's version (the
frontend the analyzing process parses with — a cache-miss defense, never
the analyzed selection's toolchain, which is a guard) and batched per
package directory, because it is a pure function of those bytes; the compartment hash itself is recomputed
from the bytes every pass, and the memo follows the observability
memo's discipline verbatim. The compartment's
declaration ledger MUST be a read surface over the same bytes the compartment hash
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
served to attribute a delta to the declarations that can
reach it, and directive entries
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
inertness fail-closed. Beside each compiled file's header, the ledger carries
its package clause, sorted syntax-reference union over its declarations, and
deterministically ordered import bindings (effective local name and import path). Default import
names come from the selected package listing, never from path basenames;
an unresolved name makes the evidence incomplete. Binding evidence also
covers every base Go file, including cgo source, because in-package
test additions can rebind identifiers in production code recompiled with tests.
Base entries carry only the file name and binding evidence, no raw header hash:
the canonical core guards their source, and ordinary base comments do not move
the binding evidence. Base-file evidence and listing-resolved import names do
not enter the compartment hash. Parse memos retain
unresolved syntactic import spellings; listing-derived names are resolved only
in the observation's caller-owned ledger.
Binding evidence carries the recognized strategy `gofresh/test-variant-bindings@1`.
Missing or unknown strategy, missing compiled-file binding evidence, or an
incomplete import-name resolution cannot establish inertness. Consumer obligation:
persist the strategy, base-file evidence, and per-file binding evidence with
the recorded ledger. A historical ledger cannot be upgraded by filling these
fields from the current tree; a new producing capture is required. The ledger
is deterministically sorted; cloning it shares no mutable binding storage.

**REQ-closure-test-variant-inertness** (behavior): The inertness judgment is rendered
modulo position metadata: any header edit shifts unchanged declarations'
source positions, and a line directive remaps them — positions are
diagnostics, not behavior, for this judgment. Two ledgers
diff into a classified delta — added, changed, and removed declarations plus
per-file header changes, deterministic for any pair — carrying gofresh's one
Go-semantics judgment: the delta MUST be judged inert exactly when both ledgers
carry recognized complete binding evidence, their base-file evidence agrees,
no declaration changed or was removed, every added declaration is a plain
function (no receiver, not init, not TestMain), a const, or a type, and the
binding checks below hold. Accompanying methods surface as their own added
entries. The positional folding above guards that whitelist: a const
inserted mid-group or a reordered var or init reads as changed sibling
declarations. Additions can still shadow identifiers resolved by unchanged
code, so positional folding alone does not prove inertness. Directive entries are outside the
whitelist, so any directive movement — added, changed, or removed — defeats
inertness; header benignity below covers only the directive-free remainder.
Each rejected kind names the mechanism that reaches unchanged code: a package
var's initializer runs during test-binary initialization; an init function
likewise; TestMain replaces the harness entry wrapping every unchanged test; a
method can flip interface satisfaction observed by unchanged type assertions
and dispatch. Binding checks cover every previously compiled file, base files
included, within its own package: an added nonblank declaration name must not
intersect that file's recorded reference surface, and every import binding
whose local name is in that surface must retain its import path. Blank imports
bind nothing. A dot-import path-set change defeats the check whenever that
file has references. A previously compiled file must retain its package and
binding evidence. These checks deliberately use a syntax over-approximation:
local names and selector members can cause conservative refusals, never an
optimistic acceptance. Additions whose names are absent from existing surfaces,
and imports used only by new code, remain admissible. Missing binding proof in
a manually assembled delta is not inertness evidence.
Go-file comments and build-constraint text may move without defeating
inertness when the declaration, membership, and binding checks hold. Import
edits must pass the binding checks even when dependencies stay the same:
core equality establishes dependency membership, not file-local name binding.
The judgment still relies on core equality because new dependency packages'
initialization is guarded there. An embedded
member's header movement defeats inertness fail-closed — whatever the file's
name: test-only embedded bytes feed unchanged declarations that read them.
Inertness is
Go-semantics data — the universal delta check (`TestVariantDelta.Inert`) claims
the delta cannot change the behavior of any unchanged declaration in the
package, and the subject-scoped check (`InertForSubject`) claims the delta cannot change the
behavior of a specific subject by computing the transitive syntactic reference
cone of that subject across the prior ledger's declarations (including all
`init`, `var`, `directive`, and `TestMain` declarations and any compartment
declarations referenced by base files, propagating exported references from
the `_test` package to the base package and matching methods by reachable
receiver type) and requiring that no declaration in that cone changed or was
removed, every added declaration is an inert kind whose name does not shadow
any reachable or base-file reference, no embedded file header changed, and
every file containing a reachable declaration retains its package and import
bindings for all reachable references. What inertness licenses is the
consumer's policy, never gofresh's.
The consumer may select the explicit extension check to license reuse under
this judgment. Ordinary checking never implicitly licenses a new delta; it
only recognizes an already recorded endpoint.

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

A conservative blocker is a candidate for the checked refinement in
REQ-closure-view-maximal only when its represented obligation is proved
satisfied. A demonstrated external dependence cannot be dropped merely because
some reached value computation is verified; unaccounted effects or opaque
leaves retain their own downgrade.

A blind spot is never left to silently narrow the closure; when no disposition can be
proven, it widens. At the file-scan floor, a two-argument pull-form
`//go:linkname` identifies a target but proves nothing about its implementation.
Dropping the opaque-linkage effect requires a checked derivation that resolves
the selected target and accounts for every claim-relevant effect through it;
all other effect classifications remain. This obligation applies equally to
`runtime.getAuxv`, `runtime.vgetrandom`, `syscall.prlimit`, `internal/cpu.HWCap`
(admitted at the Tier-2 observability refinement while retaining the conservative
file-scan floor when bound via a type-matched `uint` two-argument pull-form
scalar package-variable directive, provided the bound variable and every
non-standard peer bound to the same target in the program carry no initializer,
no stores, and no address escapes across syntax and SSA and reside in packages
free of external cgo, non-header native source, and unverified assembly), and
any other target.
A one-argument form, unparsable directive or unsupported target retains the
opaque floor. An assembly-bearing mutable-local package contributes its whole
directory to the hash, and reached non-toolchain assembly widens the subject
and blocks its observability proof unless the selection targets `amd64` or
`arm64`, the owning package has no external cgo
or non-header native source, the package's `.s` and `.h` files satisfy
package-level safety (valid preprocessor directives, 3-operand `RODATA`-only
`GLOBL` definitions non-colliding with Go declarations, literal-only `DATA`
directives targeting those `RODATA` `GLOBL`s, `$`-prefixed frame sizes and
only `NOPROF`/`NOSPLIT`/`NOFRAME`/`TOPFRAME` flags on `TEXT` definitions with
zero `init` `TEXT` definitions,
and zero stray top-level instructions — leaving pure-Go `init` and sibling
entrypoints unblocked by unreached unverified `TEXT` symbols, marking
`Observability.RequiresSingleSubject` whenever any loaded non-standard package
in the binary retains an unverified assembly entrypoint, undischarged `(SB)`
symbol reference, linknamed or Go-bodied intra-package assembly callee, or
carrier-bearing Go assembly stub so shared-process
execution models refuse fail-closed while single-subject execution admits the
clean subject, and keeping whole-package write-hazard gates strictly
conditioned on every `TEXT` symbol in the package passing verification), and
each reached `TEXT` entrypoint (plus every
intra-package `TEXT` helper transitively reached via direct `CALL` or tail-jump)
passes mechanical source verification under the selected architecture's ISA
rules: zero stores, read-modify-writes, indirect writes, memory/return/stack
escapes, or address-bit branches on `(SB)` symbol addresses, read-only `(SB)`
data references (including read-only `BT`/`BTW`/`BTL`/`BTQ` bit tests alongside
comparison/test mnemonics) restricted to verified assembly `RODATA` `GLOBL`s,
carrier-free pointer-free and slice-free Go value globals proven free of
post-initialization writes and address/slice escapes across syntax and SSA across
all loaded compartments, and writer-free `internal/cpu.HWCap` (while Tier-1
maximal closure scans continue to treat all non-toolchain `.s` packages as
unverifiable), zero `TLS`, segment/system-register,
or goroutine-register accesses (including entry `R14` reads before a full-width
overwrite on `amd64`), preprocessor-aware `ABI0` control flow with zero
non-returning fall-off at `TEXT` end, operandless `RET`, and branches/calls
restricted to local labels, non-escaping PC-relative offsets, or verified
linkname-free and Go-body-free intra-package `TEXT` helpers on linkname-free
plain non-method function stubs with
carrier-free and `uintptr`-free Go signatures,
and architecture-partitioned instruction/opcode classification admitting pure
register/stack/memory-argument computation and static CPU-feature queries
(`amd64` canonical straight-line `CPUID` leaf wrappers loading a `uint32` leaf
and zero or `uint32` subleaf into `(AX, CX)` and storing unmodified
`(AX, BX, CX, DX)` into four `uint32` results when call-site leaf values are
statically bounded and leaf-1 `EBX[31:24]`, leaf-`0x0b`/`0x1f`/`0x80000026` `EDX`,
and leaf-`0x8000001e` per-core APIC/unit topology fields are unused or masked out,
`amd64` `XGETBV`, `arm64` static feature/ID `MRS`/`MOVD` system-register reads and
SVE vector-length `WORD` encodings, and Darwin commpage capability bits) at
the Tier-2 observability refinement while classifying direct `CPUID` subject roots,
non-canonical or unmasked `CPUID` uses, hardware counters, RNGs, syscalls, traps,
transactional or control/system-register operations, per-core APIC ID reads, and
unrecognized raw opcode emissions as opaque native effects.
Selected toolchain assembly participates
in implementation dependence identity; hashing it is not a semantic proof.
Any claim reaching an unsupported opaque leaf refuses under
REQ-closure-observability-toolchain-key, including a leaf behind an otherwise analyzed trampoline.

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
recorded on the evidence), a checked implementation discharge (the synchronization,
closed static-composite, pooling, mapping, and memoization claims below), the author's
`//gofresh:single-subject` variable directive and the init-settled
builder-and-capsule cluster under the caller's attestation, a read-only pointer-sharing
named-struct package-variable alias inheriting one of those binary-wide
type-guarded capsule or composite discharges while strictly preserving its
target's attestation and recording discipline,
or the reachability judgments — the attestation-scoped per-subject
judgment and the unattested-model binary-scoped judgment — each defined
below with its own bounds and recording discipline, and nothing else.
The judgment is per package graph: the program that can mutate the
variable is the subject package's own test binary, so the marks that
open an owning package for a subject, the deferrals they resolve
against, and the discharges that lift them are derived from the facts
of that package's graph alone — a mutation linked only by another view
package's binary opens nothing — and a view batching several packages
yields for each exactly the judgment its solitary view yields (the
dynamic-state form of REQ-closure-observability-batch-equivalence).
(The refusal reason's own contract, the discharge channel it names
included, is REQ-closure-shared-dynamic-state-reason.)

**REQ-closure-shared-dynamic-state-carrier-free** (invariant): A package-level variable whose type carries none of the carriers
REQ-closure-shared-dynamic-state names — a plain
scalar or any other carrier-free type — is deliberately outside this
net: its direct mutation is per-process-deterministic content the
whole-graph hash already covers, compile-time layout queries
(`unsafe.Sizeof`, `unsafe.Alignof`, and `unsafe.Offsetof`) evaluate to
compile-time constants already covered by the code guards without
touching runtime memory, and an unsafe-mediated mutation of
it refuses on the channel it uses — a write through an
`unsafe.Pointer`-typed value refuses at the subject walk when reached and,
when present in unreached code of any loaded non-standard package in the
test binary without a mechanical read-only or layout-confined proof, marks
the observability proof single-subject-only (REQ-closure-observability-unsafe,
while the maximal-tier unverifiable judgment keeps the whole-package scan
block), whereas `unsafe.Slice`,
`unsafe.String`, and the package's other runtime operations keep the
maximal-tier and package-wide scan block, their call sites carrying no
`unsafe.Pointer`-typed value the walk can price; the non-Go write
channels — assembly, `//go:linkname`, cgo — MUST remain scan blockers.

**REQ-closure-shared-dynamic-state-atomic** (invariant): Checked atomic transparency governs every carrier walk of this
judgment — REQ-closure-shared-dynamic-state's trigger, the openness a
parameter, receiver, or constraint term confers on its subject
(REQ-closure-analysis), and
REQ-closure-shared-dynamic-state-mutation-shape's alias-handing read
judgment: each walk MUST see the toolchain's
`sync/atomic.Pointer[T]` as `*T` only when a checked derivation establishes
the selected implementation's transparency. The required property is that
its internal unsafe pointer is an implementation
cell the zero-width `*T` field and the whole method set type-pin to
`*T`, never an unsafe channel, including through its native or intrinsic
operations; a shadowing module is a load error (an
ambiguous import), so no type-checked program carries a foreign
`sync/atomic`; a defined wrapper type inherits no methods and its
cell is reached only through an address conversion the escape rules
already mark, so it keeps the fail-closed judgment; and a
dynamic-carrying `*T` still triggers everywhere. One rule at every
tier, retaining the derivation's dependencies and authority rather than
requiring an attestation. An unproved implementation keeps the ordinary unsafe
carrier classification; type shape or a toolchain guard alone cannot discharge it.

**REQ-closure-shared-dynamic-state-mutation-shape** (invariant): Mutation MUST be judged
fail-closed by carrier shape. A by-value carrier (a function value, or a struct,
array, or tuple of by-value carriers) is mutated exactly by a write, an address
capture, or a pointer-receiver method use outside `init` flow anywhere in the
program — reads copy and cannot reach the shared cell. An alias-handing carrier —
an interface value (its concrete object is shared), a channel, or a pointer, map,
or slice reaching a dynamic carrier, or an unsafe pointer — hands shared mutable
access through the value, so it is judged by use shape, still fail-closed: a read
that provably cannot write — indexing or iterating the carrier, taking its length
or capacity, querying its compile-time size, alignment, or field offset, or comparing it — is not mutation, and the indexing and iteration
discharges hold only when the produced value hands out no mutable reach or raw `uintptr` address — a
pointer, map, slice, channel, interface, or `uintptr` anywhere in it refuses; a function
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
address capture, or a rebinding is mutation, whereas index keys and slice bounds
inside left-hand-side assignment targets or ranged expressions are evaluated as
rvalue reads under their own use shape rather than treated as mutated targets of
the assignment or range; every other use — escaping the value
into a call argument, a store, a return, a binding, a method call on it, or a
type assertion — is mutation-equivalent, because the receiving code may write
what it was handed. An address capture reaches the variable's own cell or a
chain into it; taking the address of a composite literal captures the fresh
object alone, its element references remaining escapes, while a capture
nested inside the literal marks through its own shape; when a local alias holds a
carrier only in interior reach rather than at its own root header, an access,
write, or non-carrier-capable address capture staying within the local's own
single root header (or bare-addressed pointer dereference) marks neither
mutation nor escape of the embedded carrier, whereas escaping the local, taking a
carrier-capable address, or crossing into interior reach (including container
writes through a slice, map, or channel hop) marks its interior carrier set. A lexically bracketed
save-and-restore or zero-reset write to a same-package non-alias-handing,
non-mutable-reach package variable (or field thereof, without mixing
whole-struct and field writes on the same variable) whose address is never
taken directly or via an implicit pointer-receiver method selection, inside a
sequential plain package function (not a method, no `go` statement, no callable
`.Parallel` reference or concrete/composite/parameter-supplied `.Parallel`
carrier, no escaping closure writing the target, no unexempted nested-closure
write, neither escaping as a function value nor reachable in the program graph
from init flow, a method, a `go` statement, or a `.Parallel`-bearing scope, and
no control-flow exit either between the first write and the callable-scope
`defer` / `testing` `Cleanup` / inline restore or inside the restore closure
prior to the restore assignment) that either restores the single unmutated saved
value or resets an unexported uninitialized otherwise-unwritten package variable
to its zero value — with `testing` `Cleanup` restores restricted to unmutated
concrete `*testing.T`, `*testing.B`, or `*testing.F` handles in `*_test.go`
whose provenance flows solely from uncalled top-level test, benchmark, or fuzz
runner entries through synchronous sub-runners and sequential unexported or
local helpers without mixing `defer`/inline and `Cleanup` restores along a call
path — or, under an audited toolchain, a non-escaping `Load` or top-level
`Store` call on an uninitialized unexported same-package
`sync/atomic.Pointer[T]` variable whose address is never taken and whose `Store`
calls, if any, reside in such sequential plain package functions and are
serialized under a single unexported package-level `sync.Mutex` with `Lock()`,
`defer Unlock()`, and `defer Store(nil)` executed in that order before any
non-nil `Store` or control-flow exit, restores the variable's state on exit and
marks neither mutation nor environment registration.

**REQ-closure-shared-dynamic-state-receiver-proof** (invariant): A direct method CALL on a statically-typed non-interface
carrier MUST be judged by the method's own receiver-effect proof instead of
REQ-closure-shared-dynamic-state-mutation-shape's mutation-equivalence: the
declaring package proves a method unable to write receiver-reachable state —
the receiver never stands in a write position and never escapes, with one
exception, the once-filled memo: a write to an unexported receiver-rooted field
or element (or a local alias tainted exclusively from such fields without
smuggling) whose selection hands out no mutable reach and carries no signature
or synchronization primitive, provided the underlying field has no aliased or
non-pure composite-literal initialization in the package and is referenced
nowhere outside this method's once-body or synchronous top-level statements
following that Do call (with written map keys likewise carrying no unknown
dynamic carrier, signature, or synchronization primitive and smuggling no
external mutable reach) — or to a direct
unexported field reached from the dereferenced pointer receiver over by-value
struct steps alone whose type hands out mutable reach while carrying no unknown
dynamic behavior, signature, or by-value synchronization primitive, provided
the field has no non-zero composite-literal initialization in the package, is
referenced nowhere outside this method's once-body or synchronous top-level statements
following that Do call, receives a value whose derivation inside the once-body
reads no package-level or outer variable carrying mutable reach, unknown
dynamic behavior, or a signature (and calls no non-audited function), and suffers no element or subfield mutation
inside the once-body unless initialized from a fresh local allocation — placed
directly in the function literal a receiver-rooted sync.Once's Do runs — the
Once selected from the pointer receiver's identifier itself, the unique
sync.Once reachable on the receiver's type across nested or embedded structs
(including embedded struct pointers) and arrays, unexported, with that single
Do call as its sole reference in the package (forbidding struct conversions and
non-zero composite-literal elements on its enclosing struct), the fill's targets reaching no Once — so no second
literal, second memo, other package, shared pointer, receiver copy, or re-arm
can make two fills observable — fills at most once per receiver, so every subject observes the
same value whichever subject filled it — the get-or-compute idiom,
warm/cold-equivalent by construction — neither the receiver itself nor any
receiver-derived synchronization primitive is copied by value, no goroutine or
non-synchronous nested function literal references the receiver or a tainted
binding, values read
off it are tracked as the receiver's own — a binding whose type hands out
mutable reach, carries a raw `uintptr` address, carries a signature, or reaches a synchronization primitive by
value taints its local (a value copy that cannot write back, reconstruct an unsafe pointer, or copy synchronization state flows
freely, and compile-time size, alignment, and field-offset queries read types without evaluating runtime memory), a receiver-rooted read is judged at its outermost selector or index
step by the value it produces — an intermediate reach-bearing step is
evaluation, not a handout — a conversion of a receiver-reachable value admits
when its result type hands out no mutable reach or raw `uintptr` address (or converts between a string and a fresh byte or rune slice copy) and the operand is
not a method value (a method value carries its receiver whatever the result
type says; an aliasing conversion keeps the escape, and a non-blank type-assertion or type-switch narrowing of a non-signature value into a signature-carrying type refuses), a bind whose target
outlives the body — a package-level variable — refuses whenever the target's
type hands out mutable reach or a raw `uintptr` address (a reach-free copy flows; the proof's tracked
bindings die with the body, and an outliving alias escapes it — a sibling
call's results bound to such a target refuse identically), a write
through or an escape of a tainted value refuses, and only the method's own
return position hands one out — a return inside a nested function literal is
an escape position, since the literal outlives the body carrying what it
captured and no call-site result judgment sees through a signature — and it chains into sibling receiver-read-only methods, foreign statically dispatched non-interface receiver-read-only methods whose instantiated results hand out no mutable reach or raw `uintptr` address, and leak-free plain-function parameters for non-signature-carrying arguments (over conditional method and parameter edges resolved jointly with parameter leak-free proofs at composition, retention proofs remaining intra-package, and go-statement subtrees never deferring) or into
checked synchronization claims under
REQ-closure-shared-dynamic-state-audited-discharges, a dispatch of an UNEXPORTED method through a
receiver-reachable interface value chaining into every in-package
declaration of that name under the same fixed point (only the package's own
types can declare it, and a composite promotes one of those declarations;
no declaration means a nil value and refuses), and a dispatch of an exported
method through the receiver's own closed interface field — an unexported
field of the receiver's type whose every store in the package, a promoted
field's store included (the field being the same variable), carries a value
of concrete in-package static type, a parameter of an unexported plain
function called only directly, never itself written in the body, resolving
through every call site's argument the same way; any other stored shape, an
escape of the field's address, or a conversion into the struct type from
another leaving the field open — chaining into every member's
declaration of the method (a member promoting it refuses), while any other
exported dispatch keeps the escape, a composite being able to promote it
from a foreign type — and a call to a proven method marks nothing,
generic receivers included, provided the call site's instantiated result types
each hand out no mutable reach or raw `uintptr` address or have checked immutable-implementation claims
(for reflect.Type this requires runtime-canonical descriptors never written
after construction, and for reflect.TypeOf a separately checked pure-constructor
claim at the effect classification tiers; for go/constant.Value this requires
that every runtime implementation in go/constant is an unexported value or
pointer type with no exported mutation surface); a call to any unproven,
unresolvable, or interface-dispatched method, and any method VALUE bind, keeps
the fail-closed mark.

**REQ-closure-shared-dynamic-state-audited-discharges** (invariant): A synchronization discharge — sync.Mutex and
sync.RWMutex with their lock operations, sync.Cond, sync.NewCond, and sync.Locker with Cond's Wait, Signal, and Broadcast operations, and sync.Once's Do (a done flag
under a mutex running the caller's own function once, program code judged
where it is written), never process-external at the effect classification tiers because lock and condition-wait state introduce no ambient channel — MUST require a
checked derivation of those properties for the selected implementation,
including its native leaves; for receiver-read-only, parameter-leak-free, and
retention-only confinement, only the callback-free, Locker-free operations
(`Mutex` and `RWMutex` lock operations plus `Cond.Signal` and `Cond.Broadcast`)
invoked synchronously in place on an uncopied synchronization receiver
(rejecting value copies of `Mutex`, `RWMutex`, `Cond`, and `Once`, since `Cond`
anchors address identity on first use and panics when copied) are
receiver-neutral on their own, while `Cond.Wait` dispatches through `Cond.L`
and `Once.Do` mutates `Once`'s persistent flag unless discharged as a
once-filled memo under REQ-closure-shared-dynamic-state-receiver-proof (or as a
non-goroutine inline literal on an uncopied receiver under retention-only
confinement, where rooted stores into carrier- or signature-capable slots carry
only provably nil/zero carrier slots, rooted stores into mutable-reach slots
read no external mutable or carrier state, and no goroutine or non-synchronous
closure references a tracked root). At the effect classification tiers,
the synchronization discharge stands alongside scalar `sync/atomic` types (`Bool`, `Int32`,
`Int64`, `Uint32`, `Uint64`, `Uintptr`), their top-level scalar operations, and
their scalar receiver methods (`Load`, `Store`, `Add`, `Swap`,
`CompareAndSwap`, `And`, `Or`), which read and write process-memory scalars fed
by the analyzed program alone while leaving `atomic.Value` and pointer-atomic
operations to their own carrier rules. Alongside synchronization, a closed
static-composite package global discharges without execution attestation when
every compilation variant declaring the non-directive variable initializes it
once as a composite-literal tree rooted at a methodless non-empty non-standard named
struct (by value or single-level pointer) whose complete reachable field and
element schema consists solely of non-`uintptr` pure scalars initialized from
compile-time constants, by-value methodless non-empty non-standard named structs, arrays
or slices of by-value methodless non-empty non-standard named structs, non-generic
function signatures bound only to `nil`, `unsafe.Pointer`-free typed `nil`, or
bare non-generic top-level functions (including signature conversions),
and interfaces bound only to `nil`, compile-time scalar constants, or
`unsafe.Pointer`-free typed `nil` values, provided the variable suffers no
post-declaration write, pointer-root address capture, subplace mutation,
slicing, or non-scalar subplace escape and none of its reachable named struct
types undergoes struct or slice/array element mutation anywhere in the analyzed
binary. Likewise, a non-directive single-definition package variable of
single-level pointer-to-named-struct type initialized directly from another
package variable of identical pointer type (or the address of a by-value
package variable of that named struct type) and free of post-declaration
writes, address captures, and mutating builtins across all declaring variants
inherits its target's binary-wide type-guarded capsule, static-composite, or
once-memoizer discharge (requiring direct-method-call-only references along the
entire alias chain for once-memoizers, never propagating pool, mapping,
mutex-map memo, harness, directive, or caller-vouch discharges, and strictly
preserving whether the target requires and records single-subject attestation).

**REQ-closure-shared-dynamic-state-pool** (invariant): Pooling — `sync.Pool` with its `Get` and `Put`
operations — MUST have two distinct claims at two tiers, each requiring its own
checked derivation. At the effect classification tiers the required claim is
receiver-neutral and independent of the execution-model assertion: `Get` and
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
all. Conditional on the checked pooling implementation claims, a pool is
content-proven exactly when its owning package's
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
discharge is the engine's own derived verdict, not a caller assertion: it
needs no attestation, but retains its checked derivation dependencies. An exported pool,
an element of a package-level array or slice of `sync.Pool`, and
every shape the proof cannot see keep the attestation requirement.
Per-package facts record both the unattested pool marks and the candidate
pool discharges unconditionally so attested and unattested sessions share
the same persisted per-package fact identity while composition applies the
attestation, and a
load-bearing attestation is recorded on the subject's evidence exactly
as a vouch discharge is — naming the discharged pool variables,
auditable and never silent (REQ-vouch-recorded in
[purity.md](purity.md)). Every additional implementation discharge requires the
same generic checked derivation.

**REQ-closure-shared-dynamic-state-mapping** (invariant): The mapping claim —
`golang.org/x/sys/unix`'s package-level `mapper`
bookkeeping, written by the mapping calls (`Mmap`, `Munmap`, and their
variants) — MUST be admissible in any execution model only under a checked
derivation over the selected module and its dependencies, including the
per-GOOS declaration split and any claim-relevant kernel or native behavior.
Version pins identify source; they confer no behavioral approval. The required
properties are that mapper's
state is
process-local, fed exclusively by the analyzed program's own mapping
calls; its callable fields (`mmap`, `munmap`, `mremap`) are written
only in the variable's declarations, so no schedule can change
dispatch through the carrier; and its bookkeeping maps each live
mapping's last-byte address to its data-only byte slice, which hands
out no dynamic carrier. Cross-subject entries are disjoint while
their mappings live, a property that itself requires established semantic
support rather than an assumed kernel summary; the raw-pointer paths
(`MunmapPtr`, `MremapPtr`) leave entries stale, and a reissued address could
then steer `Munmap`'s error-plane outcome by subject order — an
exposure that is unobservable exactly because any subject able to
observe it calls the mapping syscalls itself and those keep their
own fail-closed classification at the observability tiers, which is
therefore part of this discharge's ground, not merely an adjacent
fact. The discharge spans the variable's mutation, escape, and
environment-audit marks alike (the raw callable-field reads the
`*Ptr` paths take are covered by the init-only-fields leg of the
derivation). Like the memoization claim, the discharge is
the engine's own derived verdict: no attestation, with complete checked
dependencies. It covers only variables for which these properties are
established. A module version or mutable-local origin neither establishes nor
refutes the claim; missing semantic support retains the marks.

**REQ-closure-shared-dynamic-state-directive** (invariant): The `//gofresh:single-subject` variable
directive is the mapping set's own-code dual: a durable in-source
directive on a package-level variable declaration — discovered under
the same build-flag-selected source discipline as `//gofresh:pure`
(REQ-purity-directive in [purity.md](purity.md)) — declaring, on the
author's authority, that the variable's state is subject-own under
the single-subject-process execution model: process-local, fed only
by the program's own rooted flow, no cross-subject channel when each
subject owns its process. Both legs MUST be required — the directive is
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
[purity.md](purity.md)).

**REQ-closure-shared-dynamic-state-proto** (invariant): An init-settled builder-and-capsule cluster
(such as a generated schema descriptor cluster) is an
implementation claim about build-once initialization state and lazy once-memoized
capsule structures: the stored values are content-invariant functions of compiled-in
inputs. Discharge MUST require a checked derivation over the selected
source, its builder and lazy-capsule runtime packages, and all subordinate implementation claims
(including single-assignment `init()` builder construction, `sync.Once` or atomic-pointer
capsule initialization dominance before sub-struct pointer handouts, exported-field
nil-guard initialization, stateless or local-`sync.Once` closure captures, pure snapshot
validation, immutable capsule guards across interface-typed containers, and post-init
carrier-write sink isolation across the graph),
together with the caller's single-subject-process assertion (whereas closed
static composite tables free of lazy runtime mutation
discharge attestation-free under
REQ-closure-shared-dynamic-state-audited-discharges, and read-only
pointer-sharing named-struct package-variable aliases targeting cluster
capsules inherit the attested discharge and record alongside the
cluster variable). A
generated-file header, package path, field or method name, generator name, or runtime version is neither an author
assertion nor a proof. The same derivation rules apply to generated and
handwritten source, pinned dependencies and mutable-local checkouts. A
load-bearing execution-model assertion remains recorded with its discharged
variables; unsupported implementation behavior retains the marks.

**REQ-closure-shared-dynamic-state-memo** (invariant): The memoization claim —
`gopkg.in/yaml.v3`'s `structMap`, a mutex-guarded type-to-structInfo
cache filled at exactly one site by a pure function of the type
(field ordering by struct index, no map-iteration order in stored
data, no options input, values never rewritten after the store) — MUST be
admissible only when a checked derivation establishes those properties for
the selected implementation, with no version-approved exception. The required
property is that the memoized computation is
content-invariant, so a prior
subject's population changes timing and internal pointer identity
that never leave the package's unexported internals, never a
looked-up value — so the discharge needs no
execution attestation, while retaining checked dependencies (it is the
engine's own derived verdict, not a caller assertion; pooling and mapping
reach the same authority class by their own checked grounds). This is a
structural get-or-compute claim, with every synchronization and implementation
premise independently justified. The data memo is its content-typed
form, the engine's own verdict: an unexported package-level variable of
type sync.Map by value whose every use in its package is the receiver
of a Load, Store, or LoadOrStore call whose key and value arguments have
static types carrying no dynamic behavior — an interface-typed parameter
resolving through every direct call site's argument the same way, a
written, escaped, or uncalled function's parameter, and the trailing
parameter of a variadic function, refusing —
never holds a carrier, so it is the data-only variable this invariant
leaves out and its calls mark nothing, under no attestation but with the
checked map implementation claim required below; any other use — Range, Delete, Swap, CompareAndSwap,
CompareAndDelete, Clear, the address taken, the variable passed, bound, or
rebound — and an exported or pointer variable keep every mark. A second
content-invariant form is the once-populated immutable struct memoizer,
likewise needing no execution attestation: a non-directive package-level
variable initialized once at declaration by a direct call to a verified
constructor returning `*T` for a named struct `T` (every non-literal
mutable-reach argument at that constructor call being an unexported
single-definition carrier-free package variable free of mutations and
reference-confined across all remaining uses in its package), where the
memoizer variable itself is never written or address-taken and every
non-initializer reference across the analyzed graph — whether on the root
variable or along a chain of read-only `*T` package-variable aliases — is a
direct method call on `*T` (or a read-only `*T` package-variable alias
initializer whose own downstream references across the graph are all direct
method calls on `*T`); in `T`'s declaring package (intersected across compilation variants), `T`
partitions its fields into a single unexported `sync.Once` reachable nowhere
else and referenced solely by one `recv.once.Do(func() { ... })` statement in a
two-statement getter method on `*T` with unnamed results that immediately
returns `recv`'s memo fields (forbidding struct conversions into `T`), one or
more unexported memo fields written solely by top-level assignments in that
`once.Do` literal (never non-zero in any composite literal, never mutated
elsewhere, and read solely in that getter's return statement, with an `error`
memo field or `error` panic operand admitted only when every `error` value produced in the `once.Do`
compute cone originates from `nil`, audited pure standard-library
string/wrapping error constructors over scalar and cone-verified `error`
operands, or cone calls whose declared result slot has predeclared type `error`
rather than a concrete type converted to `error`), and optional unexported
carrier-free constructor-populated input fields never mutated and confined
across every read in `T`'s methods (conditional plain-function parameter
dependencies resolved against the composed leak-free set), with `T`'s `once.Do`
compute cone pure and deterministic (no goroutines, channels, map iteration,
ambient calls, or non-settled global reads, and no writes outside cone-local
allocations and the memo fields), every sibling method on `*T` confining its
receiver without mutating or escaping `T`, executing within a pure cone free of
goroutines, channels, deferred calls, ambient calls, global writes, non-settled
global reads, composite literals of guarded structs carrying unexported
reference fields, or unverified interface dispatches (admitting `error.Error()`
and confined non-`error` caller interface parameters that never escape into
aggregates or globals), proving pure `error` origins whenever the cone returns or panics with an `error` value,
and restricting every non-scalar, non-`error` result slot to either a guarded
named struct or pointer thereto in `T`'s verified closure or a carrier-free
value freshly allocated per call, every unexported reference or container field
in `T`'s reachable type closure proven freshly constructed and read-only
confined in `T`'s package, every exported field on structs reachable from the
getter's results restricted to scalars, by-value structs, pointers to non-empty
named structs, or slices/arrays of non-empty named structs, and `T` together
with every non-empty named struct reachable in `T`'s type closure guarded
binary-wide so any non-fresh struct or element mutation across the graph (raw `uintptr` addresses being excluded from scalar slots) revokes
the discharge fail-closed. At the
effect classification tiers the memo claim covers sync.Map itself and
its Load, Store, and LoadOrStore — process-memory reads and writes fed by
the analyzed program alone, requiring a checked implementation derivation
independent of execution-model assertions, as the pooling claim does, the values stored and produced keeping
their own pricing, and a file that merely declares a sync.Map recording no
effect at the file fold — while the map's other operations keep the
unsupported fallback at the walks unless their own checked claims establish
the required properties. No method name proves the selected body's effects.

**REQ-closure-shared-dynamic-state-reachability** (invariant): Under the caller-attested single-subject-process
execution model the shared-dynamic-state judgment MUST additionally scope per subject: the
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
widenings, and precise analysis under the caller's analysis budget
exactly as that proof is (REQ-fresh-context in
[overview.md](overview.md)): a pass the budget cuts leaves every
culprit of the pass standing — undischarged, the judgment whole, never
validity, its reason naming the budget — reports the exhaustion once
with the count of subjects left undischarged, and persists nothing of
the cut package's derivation (a later pass derives it cold); and the
discharge is fail-closed on every gap: an
open-world widening or an unrooted subject symbol grants nothing (no
proof, no discharge — the judgment then stands whole), a mark without
function attribution — an init-flow refusal's, a deferral
failure's, a malformed fact's, one crossed over a carrier link, or a
literal's outside any named body —
forecloses the discharge for its variable, and a variable with any
rooted marking site keeps every mark. Named functions and methods
alike are attributable sites (a method's under its type-qualified
name) for direct and literal-borne mutation, escape, carrier-method,
and carrier-parameter marks, while field and element deferrals and
carrier links keep their fact-immediate composition. A function
literal's or go statement's marks nested in a named body are
literal-borne sites of the enclosing declaration: executing
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
init reach is unknowable — fail-closed. Direct marks in a named body
follow the same outliving-alias rule: a direct synchronous in-place
mutation executes only while its encloser runs, so an init-only plain
encloser makes it init-determined and an unreachable encloser makes it
dead, whereas a direct escape, a direct carrier-method call without a
retention-free receiver proof, or a direct carrier-parameter call
without a retention-free parameter proof can plant an alias into
external storage that outlives the call — under an init-only plain
encloser a direct carrier-method or carrier-parameter deferral
discharges only when its retention-free proof holds, and whenever init
flow can reach the encloser or the encloser is a method any direct
mark lacking that synchronous-completion guarantee forecloses
reachability discharge outright. An environment-audit refusal on a
non-callable variable attributes to the plain named post-init
function(s) whose stores (direct or via an unproven constructor call)
registered the environment-carrying value when every such registration
sits in a plain named function unreachable from init flow, whereas any
initializer/init-flow, init-reachable, or method-borne
environment-carrying registration forecloses reachability discharge
outright because a non-callable container still admits markless
post-init execution channels (indexing a scalar-returning function
element, reading or calling a function field, or passing the container
to a receiver-read-only method or leak-free helper), while a directly
callable variable keeps a markless execution channel (its call is a
tolerated read) and its environment refusal never discharges. The inventory is per variable and class-blind: any
foreclosing mark keeps every rank's refusal for that
variable. The checked implementation and explicit assertion discharge channels
— pooling, mapping, memoization, verified property-harness package
globals, the vouches, and the
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
as the implementation discharges using that assertion are. Under the caller-attested PACKAGE-PROCESS
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
applies, because an unattested consumer may run the subject under any
root set at all — a harness the analysis never saw — so no rooted
flow bounds the sites a prior subject executed; the analyzed program
itself stays the subject package's own graph, the code the maximal
closure prices, exactly as the whole-graph judgment above assumes — a
consumer linking foreign code into the subject's process is outside
the fingerprint's model altogether, the foreign bytes being in no key. Package
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
scan-memo identity (REQ-closure-scan-memo), while per-package facts stay
execution-model-independent so option-on and option-off sessions share
pinned per-package facts without ever serving each other's scan verdicts.

**REQ-closure-shared-dynamic-state-escape-narrowings** (invariant): One narrowing applies to
the escape class alone (the escape marks
REQ-closure-shared-dynamic-state-mutation-shape defines): an
interface-typed variable MUST be object-closed when every attributable `init`-flow
store — a direct store the auditing package resolves to the variable, from any
package — is a construction with a checked immutability derivation
(`errors.New`; a value of static type `reflect.Type` only when the selected
implementation proves every possible referent is a runtime-canonical type
descriptor never written after construction — the interface's unexported
methods alone do not prove this — a
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
immutable data by the same checked derivation (`errorString` and the fmt wrap
errors' `Error` and `Unwrap`, the runtime type descriptors' view methods), a
constant-boxed referent dispatches value-receiver copies that cannot reach
the box, and a nil referent panics before writing. The
construction claim requires checked implementation evidence at every new
selection; a familiar type or constructor name supplies none.

**REQ-closure-shared-dynamic-state-init-aliasing** (invariant): An escape MUST NOT
discharge by init flow — the alias outlives initialization. Proven
init-only functions are scanned for escapes under the full use-shape
rules, including composite or in-place carrier stores into formal parameters
and result expressions or named result variables whose types
can hand out carrier-derived state or mutable reach; `init` bodies and
qualified helpers are scanned exactly for
alias-creating bindings — an init-flow local bound from a carrier by
whole-identifier assignment or declaration, by range binding, as a
builtin copy or append destination, as a qualified helper's parameter bound at
an init call site (carried across bodies to the same fixpoint, under
the mutable-reach type gate of the value's landing type — a non-spread
variadic argument lands as the element, boxing into an interface keeps
the gate's fail-close — for the direct, parenthesized, and
generic-instantiated call spellings; a conversion-wrapped or
func-value spelling refuses fail-closed through the escape backstop
instead), or
through a composite target or shared local backing memory (a struct field,
element, channel send, map key, type-switch binding, or indirection store
propagates across co-aliased local backing storage — including pointer
addressing, value-array slicing, `unsafe.Pointer`/`uintptr` and `unsafe` pointer/slice/string header derivations, `min`/`max` selections, and shared slice/map/channel headers — tracking
root-header carrier aliases separately from interior-reach carrier aliases so
writes through bare-addressed pointers reach the addressed local's root header
while fresh composite holders carry embedded carriers in interior reach),
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
tolerated when carrier- or signature-capable targets and written map keys carry
only provably nil or zero carrier slots and mutable-reach targets and written
map keys read no external mutable or carrier state, an unproven, dispatched,
result-handing, or value-bound method keeping the fail-closed escape —
a bound method value retains its receiver past initialization. An init-flow
bind or store whose target is itself a carrier (propagated across local aliases, `unsafe` pointer/slice/string header derivations, and `min`/`max` selections, while ignoring compile-time size/alignment/offset operands and slice/string length operands) — or an init-flow store
of an admitted environment-free closure capturing an init-flow local
alias of a dynamic-capable package variable, non-directive when declared in the same package — links the two keys as
one storage — mutation, escape, and environment marks crossing the
pair symmetrically and transitively at composition and foreclosing
reachability discharge on the crossed target, since the shared
backing is one object under every name it carries — reach-free
sources recording no key and object-closed carriers staying unlinked at
composition.

**REQ-closure-shared-dynamic-state-leak-free** (invariant): Two further narrowings
MUST discharge specific escape shapes by proof: a carrier passed as a direct
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
binding tolerated when carrier- or signature-capable targets and written map
keys carry only provably nil or zero carrier slots and mutable-reach targets
and written map keys read no external mutable or carrier state, the
write-path element and field reads feeding those stores priced as
writes rather than handouts — recorded beside the leak-free grade,
chained and resolved identically with either grade satisfying an
edge, absence refusing; and a range binding over an alias-handing
carrier discharges the iteration read when every alias-handing bound
value is proven leak-free over the loop body by the same judgment,
fail-closed on any other binding shape — where the leak-free judgment
recognizes the call of a func-typed field of a bound value (while refusing non-blank type-assertion or type-switch narrowing of a non-signature value into a signature-carrying type): the target
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
when the carrier itself suffers no mutation, escape, unproven method or argument
deferral, or environment-carrying registration (population marks and
carrier links pooling across shared storage), no poison covers the
position, every deferral resolves against the leak-free union, and every
constructor resolves, any malformed record marking the declaring fact's
variables fail-closed — and a carrier
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
encoding, an unproven method marking mutation fail-closed, with
parameter leak-free and pointer-receiver read-only proofs solving
jointly to a single least fixed point within the declaring package at
fact time and across packages at composition over conditional
parameter-to-parameter, parameter-to-method, method-to-method, and
method-to-parameter edges (cycles, absence, and malformed edge records
refusing, any malformed edge record marking the declaring fact's
variables fail-closed, while retention proofs remain intra-package); inside the
judgment as at the discharge, no call within a go statement's subtree
defers its arguments or its method receivers — a goroutine literal
wrapping the call is the
same concurrent execution as the direct spelling.

**REQ-closure-shared-dynamic-state-parameter-facts** (invariant): A third narrowing
MUST admit return-position handouts: a range binding returned by an
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
residual every malformed-fact arm shares). On the registration
audit's plane the callees-join-their-populations rule binds through
per-parameter argument-storage insertion facts, keyed exactly as the
parameter facts above: the declaring package proves, per parameter,
that everything the function stores into storage reachable from that
parameter — slot and unattributable-depth stores alike, across header
aliases and value-copied composite holders sharing interior reach —
judges under the audit's own value and mutable-reach argument
judgments, a stored parameter neither rebound, capture-broken, nor
use-poisoned satisfying the check once every in-body write into its
shared header or interior reach so judges (folding any deferred
insertion uses on it into the parameter's insertion dependencies) so
caller-supplied contents remain the caller's obligation, discharged at
each deferring call site: every argument of
the call judges under the audit's value judgment, to a poison
fixpoint, and a call with an unjudgeable argument poisons the storage
it was handed instead of deferring — a parameter handed onward to a
plain named callee chaining through that callee's own insertion fact,
and a capture-broken component poisoning the parameter outright —
absence is poison, fail-closed. A caller's plain-named call to an
callee without a checked value-plane claim (a checked non-mutating helper
claim can discharge only the effects it proves absent) classifies every argument by the write path its
value hands the callee, gating on the value's OWN type — a value
handing no mutable reach copies, so element reads, copied function
values, and fresh-and-copying derivations (make and new, append and
value-plane clones with checked copying claims whose container elements hand no reach,
conversions of clean operands) classify nothing: a tracked
chain-rooted argument whose value hands out mutable reach defers over
a conditional edge naming the callee's parameter key, resolved with
the return-environment-free proofs in one least fixed point — the
insertion conditions and any foreign or conditional parameter-leak-free
and receiver-read-only confinement edges ride their own dedicated edge
lists, gated against the composed parameter-leak-free and
receiver-read-only sets so the return proofs' constructor edge list
stays a pure function-key channel for its population-join consumers,
and the resolution has one implementation serving verdict composition
and explain alike — while a composite-literal argument,
plain, addressed, or Go's elided address-of in a pointer-element
literal (which carries no address syntax to see), breaks its embedded
reach-bearing tracked names fail-closed, and a call-rooted or
otherwise unattributable argument value breaks every reach-bearing
tracked name it reaches. Unnamed and blank parameters are
insertion-free by construction; variadic trailing arguments key the
final declared parameter's index.

**REQ-closure-shared-dynamic-state-registration-audit** (invariant): Every admitted read path is sound only under the environment-free
registration audit: a function-carrying value a package's direct code
stores into a carrier — its own or a foreign one, initializer
expressions, nested function literals, go statements, and builtin copies or appends included, with a store through a local alias
resolved to the local's root-header carrier set when the write stays within the local's own single root header (or bare-addressed pointer dereference) and to the local's full interior-reach carrier set whenever the write crosses a second pointer, slice, map, channel, interface, embedded-pointer, or type-parameter hop or writes into a slice or channel container — MUST be environment-free. A plain named function, a method
expression, and nil carry no environment; a function literal is
environment-free when every variable it references from an enclosing
function scope proves leak-free under the use-shape judgment over the
literal's body and over every sibling literal of the enclosing body
referencing the variable's alias set — the set closed across the
enclosing body (nested closures and go statements included) over
every local binding, composite/indexed/field/map-key/channel write,
type-switch binding, builtin copy or append, and non-builtin call
connecting a local root to an enclosing-scope variable via mutable
reach, place address-of, value-array slicing, or implicit
pointer-receiver method-value addressing, since a shared environment is one
object under every name it carries and however many carriers its
closures reach — AND every root in that alias set has a confined origin (excluding channel or function-iterator range bindings, excluding non-scalar enclosing receivers and named results, excluding non-scalar enclosing parameters for directly registered literals outside synchronous init-only helpers while admitting caller-obligated unbroken parameters for returned literals and call-site-verified parameters of unexported synchronous init-only helpers where non-spread variadic calls allocate a fresh slice and spread calls require pure fresh slice data, verifying single-definition unmutated/unaddressed non-directive same-package signature sources with constructor edges propagated, rejecting type-switch narrowing into a signature-carrying type, and requiring mutable-reach local roots (including raw `uintptr` addresses) to initialize solely from pure fresh data over variable-free append bases, fresh allocations, value-plane clones over clean operands, settled unexported package data, or — in synchronous init flow — dynamic carriers, unbroken and non-directive when declared in the same package, from which neither the literal nor any sibling closure extracts or invokes a carrier, signature, or mutable-reach value, recorded as init-flow carrier links, with any signature-carrying operand boxed into an interface or composite within those roots satisfying this signature audit), with a
reference to the alias set from a go statement's call outside any
literal refusing outright. A call result whose callee is a plain named
function — a bare identifier or package-qualified selector,
receiverless, explicit generic instantiation included with the
dependency key instantiation-independent — defers to that callee's
return-environment-free proof:
the store records the callee against the carrier, the call's arguments
judged recursively by this audit (a signature-carrying argument — including one boxed into an interface conversion or mutable-reach composite — that fails
this audit, or a mutable-reach argument on a non-value-plane callee proven neither leak-free at that callee parameter — locally or over a conditional registration parameter-use edge resolved against the composed leak-free set — nor fresh or settled over
unmutated unexported package data — an unexported single-definition carrier-free and non-copy-sync-free package variable initialized from pure fresh data over variable-free append bases and settled siblings, unmutated and confined across all package declarations, and embedding mutable reach into at most one unbroken non-directive carrier matching the store target, either unexported or exported when closure-only or alias-handing with that single declaration use and no function-body references — poisons the
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
new elements), a non-assertion conversion of a judged value (type-assertion and type-switch narrowings refusing), an instantiated
reference of a named function, a call of a value-plane helper with judged
arguments and a checked claim that its results carry exactly those arguments'
values — slices.Clone, slices.Concat and maps.Clone require this same
implementation proof, including their copying and native dependencies — and a call of a plain named callee with
judged signature-carrying arguments and clean, caller-parameter-obligated, leak-free-parameter-confined, or settled mutable-reach arguments, explicit generic instantiation included with the
dependency key instantiation-independent — and a zero-valued
declaration binds the nil zero value, environment-free. An element,
field, slice-step, or dereference write of a present value is a
store. A slot write — one whose chain stays on the root's owned
spine: for a root bound only by direct bindings (comma-ok map element
reads included) from body-owned storage (fresh allocations, slice
reslices, appends, and conversions over them, and index reads out of
body-owned maps or slices whose stored elements are themselves
body-owned), an initial dereference of the root's own pointer,
selector steps over by-value struct fields (excluding promoted fields
reached through embedded pointers), and at most one index in final
position taken on the root's own header, past its own dereference and
slice steps over that same header at most — a header reached through
a selector or a container holding caller reach may have
arrived inside a held copy, invisible to body-ownership; for any
other root, selector steps over
by-value struct fields alone — lands in the root's own storage, and the base
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
their backing the population sweep never sees; value-plane
callees with checked non-mutation claims keep that scoped exemption; builtin callees are
likewise exempt, append and copy never holding the argument beyond the
call, their destinations covered by the bind link, spare-capacity element-write tracking onto slice-header bases (breaking non-header append bases when elements are appended), and the copy
target-break and source-element judgment — the implicit
address of a pointer-receiver method use included, exempting methods
proven receiver-read-only locally or over conditional method-confinement
edges (while keeping tracked caller-insertion aliasing conservative when
auto-addressing a carrier-bearing value receiver) — or any bind
position or address
capture of a parameter, breaks the binding or the parameter's
caller-judged assumption outright; a returned or registered literal is
audited with its enclosing scope's collected foreign or conditional
parameter and method wants recorded on dedicated confinement edges and
resolved at composition against the composed parameter-leak-free and
receiver-read-only sets (any malformed confinement-edge record marking
the declaring fact's variables fail-closed); a plain-named-callee result inside a return
expression records a dependency edge, the proofs resolving at
composition to a least fixed point over the edges; naked returns and
every unrecognized signature-carrying shape refuse the proof. Cycles
and absent proofs keep the store's poison — fail-closed. Every other
value shape — a bound method value, a call through anything but a
plain name (builtin make and type-operand new excepted: they construct empty or
zero values, while Go's expression-operand new judges its operand), a parameter, an opaque
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

**REQ-closure-shared-dynamic-state-init-flow** (invariant): `init` flow is the initializer expressions, the `init` bodies, and the
init-only-reachable functions: plain named functions — exported included —
whose every reference, in every package of the analyzed graph, is a direct
call from an initializer expression, an `init` body, or another such function,
resolved to a graph-wide least fixed point at composition from per-package
reference-region facts (mutually recursive candidates refuse — deliberate
conservatism, and a function no fact references refuses by absence); any value
reference, any receiver, or any reference from ordinary program code — a
nested function literal wherever it appears, and a go statement launched from
init flow in its entirety, callee and arguments alike, since the goroutine
outlives initialization (a deferred init call stays init flow) — MUST refuse the
class fail-closed anywhere in the graph. Carrier mutations and method uses in
such a function's direct body attribute to it and are judged by the resolved
class; literals and go statements nested inside it remain program code. A
persisted attribution a consumer cannot parse marks every variable its fact
declares — fail-closed like every malformed-fact arm. A qualified in-package
helper's stores stay audited for object-closure exactly as an `init` body's
are. Function bodies nested in package-level declarations,
in `init` bodies, or in qualified helpers are program code, not initialization;
non-Go writes need no rule here — packages built with cgo or package-unsafe
assembly sources are already downgraded whole by the native-code and linkage
blind-spot dispositions, packages retaining unverified assembly entrypoints
require single-subject execution (`Observability.RequiresSingleSubject`), and
mechanically verified assembly is barred from writing Go variables, referencing
dynamic-carrier Go variables, or accepting dynamic-carrier types. The toolchain-generated test-main package's registration
tables may be excluded from this mutation judgment only under a checked
scaffolding claim that they introduce no relevant mutation or dispatch channel
beyond the declared harness model. Their implementation dependencies remain
covered, as REQ-closure-analysis requires for its registration initializer.
A dynamic-capable variable the program never
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
restructure and the single-subject directive with its attestation caveat
— per attestation: with none, the directive and the attestation (the
caller's own half to give); under the single-subject attestation, the
directive; under the package-process attestation, which the directive's
discharge does not ride, the restructure alone as the remedy, the
directive named as present and unbacked where the declaration carries it
and as single-subject-only where it does not, so that consumer is never
pointed at an attestation its model forbids nor at a directive that would
only move it to the unbacked text. The
reason may illustrate a consumer CLI spelling, but the channel and identity are
the contract — consumers differ in how vouches are supplied.

**REQ-closure-refusal-channels** (behavior): The sibling refusal families MUST
name their discharge channel exactly as the shared-dynamic-state family does, so
no correct refusal is a dead end. An ambient-effect refusal — a network, plugin,
or native reach, which no finer tier analyzes and no directive below the
subject bounds — names the reached operation and the subject-level channel:
restructuring the subject away from the reach, or the subject's purity
responsibility — the `//gofresh:pure` directive on its declaration or the
caller's purity assertion (REQ-purity-directive and REQ-purity-responsibility
in [purity.md](purity.md)); the composition is the effect's, so every reason
of the kind carries it at every tier. The signature-dynamism refusal names the
conferring term — the first type parameter, receiver, or parameter whose type
carries dynamic reach under REQ-closure-analysis's openness rule — and its
channel: bounding that type away from dynamic carriers, or the purity
responsibility; the term is the persisted open-world fact itself, so an open
subject without its term is unrepresentable. A refusal depending on an
unsupported implementation claim carries that claim's failed premise and
dependency path under REQ-closure-observability-toolchain-key. It does not attribute unrelated
refusals to a global disabled-admission state. An author's external declaration
and an ambiguous identity are their own causes. The reached operation, the
conferring term, the channel, and the attributed premise are the contract; the spellings are
illustrative.

## Analysis requirements

**REQ-closure-analysis** (behavior): The observability proof's precise analysis MUST build
whole-program SSA with standard-library bodies present and generic instantiations
materialized, and root the reachability walk at the subject, every linked source
package initializer, and — for a subject that executes through the test harness (one
declared in a test file) — the user-defined test main. The toolchain-generated test
main's registration initializer does not by itself root every alternative test
or benchmark into a caller-selected subject. Excluding those roots requires the
declared execution scope and a checked claim that the selected harness and
generated registration implementation preserve it. Generated scaffolding
remains an implementation dependency even where it is not an ordinary source
initializer. Standard-library
bodies remain present so a user method dispatched inside a
standard-library function stays visible, generics materialized so each instantiation
dispatches concretely, initializer roots included so a concrete type registered in
`init` and later observed through global state and interface dispatch is covered even
when the subject never names the registering package, the test main rooted for a test
subject so setup it runs before the subject (state a production subject never sees)
is in the closure; a narrower root or edge set is taken only when proven to preserve
the same startup and global-flow coverage (specifically, dead conditional branches
and short-circuit `&&`/`||` merges guarded by compile-time boolean constants or by
non-zero checks of non-escaped, non-linknamed, cgo- and unverified-assembly-free
zero-valued package globals proven unmutated across synchronous startup flow — or
across the whole analyzed program for asynchronous or callback startup frames —
are pruned from startup reachability and effect attribution). The runtime-type walk skips any
type mentioning a type parameter wholesale: such a type denotes no
runtime type — only fully concrete instantiations exist at runtime, and
they enter the walk through their own instantiation and interface sites
— so a type-parameterized shape reaching the walk contributes nothing
instead of failing the analysis. An analysis failure the walk cannot
classify (an unsupported shape outside that class) isolates to the
subject that provoked it: the batch bisects until the failing subject
degrades alone, carrying the failure as its own unavailable evidence —
the memoized, hashed refusal reason is ONE fixed string, byte-stable
across recomputation, and every walk-order-dependent payload (the
panic value, the visited function) rides the diagnostic channel at
refusal time — while every batch sibling keeps its result; failure
classes other than unsupported shapes remain batch-wide. Whether a
failure is package-scoped is decided by its own probe — the shared
init and harness roots analyzed alone — never by bisection-half
coincidence (two independent subject-scoped provocations on opposite
halves must isolate individually, not darken their sound siblings); a
package-scoped failure degrades every subject at once with the
probe's own correctly attributed error. A parameterized subject is open to
caller-chosen instantiations, and its openness is decided on the
type-parameter list itself (a signature walk alone misses zero-parameter
generics), identically at every tier: a constraint that provably bounds
its type set away from dynamic carriers — methodless, with at least one
bounding element whose every term is free of dynamic reach under the same
carrier rule ordinary parameters answer to (interface, function, and
unsafe reach open; a channel opens exactly when its element does; the
toolchain's `sync/atomic.Pointer[T]` reads as `*T` only under the checked
atomic transparency, REQ-closure-shared-dynamic-state-atomic);
`any` and `comparable` bound nothing — closes
the caller's choice, anything else keeps the subject open-world,
where observability refuses exactly as for any
open subject world. A non-generic function subject whose ordinary
signature carries dynamic reach closes the same way a bounded generic
does — by enumeration, never by signature shape alone (a
receiver-bearing subject on a first-party named struct closes only when
its non-receiver parameters supply no dynamic reach — parameters whose body uses
are confined to carrier-free operations such as `==`/`!=` equality comparisons
supply none, and an audited cancellation-only `context.Context` parameter whose
body uses are confined to `Done`/`Err` supplies none when every caller across
the analyzed program passes a closed timerless `context.Context` — and either its
receiver supplies no dynamic reach or every dynamic-reaching field it
loads is populated exclusively by closed stores across the whole
analyzed program with no unjudged whole-struct or reflective write; any
other receiver-bearing subject keeps its signature-shaped open world, as
a method's interface invocability leaves no reference the scan can see):
it analyzes closed
exactly when every reference to it in the whole analyzed program is a
direct static call from a body the enumeration can judge (concrete generic
instantiations included; uninstantiated parameterized origins excluded) and, at every
such site, each argument in
a dynamic-reaching position whose parameter supplies dynamic reach in the body
closes in the calling function's own frame
(locally constructed values under the closed-value walk with no
cross-boundary crossing — the caller's parameters, loads, and call
results refuse, except a load from a closed cell: a local allocation whose
every use, across the closures that capture it, is a store of a closed
value, a load, a field or index address over the cell whose referrers
likewise satisfy the closed-cell rule, or a closure creation binding it —
the recursive local closure's own cell), in which case the sites' closed function values root
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
rather than serving under an enumeration it was never part of. An
enumeration-closed subject's function-value dispatch drops, from its
target set, every whole-program signature collision whose
address-taking references all lie in initializer flow — an
init-parented closure, a bound-method wrapper an initializer
materializes, a named function registered there — sound because a
subject-closed operand can hold an init-planted value only through a
shared-state load the closed-value walk refuses; other collisions may
remain and refuse conservatively. The drop applies only at sites in
user frames — a standard-library frame's computed dispatch never
proves its operand, so a std-frame site keeps the whole-mask drag,
spurious but never unsound — and interface dispatch resolves through
runtime-type flow, outside this value-provenance judgment. A
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
set. Classifying user test-main flow within subject-time observation requires
a checked derivation that the selected test log installs in the generated
test-main initializer, after every dependency initializer and before the user
test main, and remains effective through every covered phase. Under that
premise a user test-main read is a bracketed observation input, admitted
per effect through the same per-site observation admissions subject flow
answers to, with a blocking test-main effect refusing under its own
reason. The canonical test-main epilogue `os.Exit` can be treated as harness
protocol only under a checked claim that it runs post-bracket and adds no
input channel or lost required observation. An exit before the harness run
supplies no subject execution or completion evidence.

**REQ-closure-observability-benchmark-pacing** (invariant): The benchmark harness's
pacing likewise MUST require a checked protocol claim: the iteration count
`b.N`, the `b.Loop` protocol, and the timer controls (ResetTimer, StartTimer,
StopTimer) are the harness's own — the count derived from its flags and its
previous iteration's timing, the controls moving only its clock and allocation
bookkeeping — and never an input to the measured computation, whose
per-iteration result the benchmark contract makes invariant in the count, the
count's own inputs — the harness's pacing flags — being run conditions the
caller sets deliberately, never a guard of this engine's
(REQ-guard-machine-transient's principle in [guards.md](guards.md)) — an
obligation on every consumer serving measurement results: its recording
identity carries the pacing flags, or a benchmark whose outcome branches on the
count is served across a flag change. Conditional on that declared result model
and the checked implementation claim, they are harness facts, the file fold
recording nothing for them and the walk retaining the claim — a harness
protocol claim is no purity evidence. A checked summary can replace descent
into the harness body,
while every other benchmark surface keeps its class: Elapsed and RunParallel
their test-runtime classification, and the harness's remaining surface
(ReportMetric, ReportAllocs, SetBytes) requires body analysis or its own
checked summary, never a package-wide exemption.

**REQ-closure-observability-testmain-exit** (invariant): The observed walk can apply
the exit protocol claim throughout user test-main flow, helpers included,
only where its completion and delivery premises hold, while the package-scan
backstop MUST scope its admission to the syntactic `TestMain(*testing.M)`
declaration, the conservative direction for text the scan cannot
attribute to flow.

**REQ-closure-outcome-inventory** (invariant): Analysis MUST distinguish an
observable effect set from a set whose operation outcomes have an admitted
derivation. The `gofresh/immutable-environment@1` derivation is available only
when checked implementation claims establish its semantics under the actual
selected build and the observability proof succeeds
and every external input effect in subject and user test-main flow is an admitted
`os.Getenv` or `os.LookupEnv` operation, including the empty effect set. Checked
harness logging, benchmark pacing and closed subtest execution retain their
existing protocol meaning; they do not introduce an external input outcome, and
their user callbacks remain subject to the same complete effect judgment.
Initialization effects, unclosed reachability, unavailable analysis, and every
ordinary observability refusal preclude the derivation. Filesystem operations,
fresh scratch operations and other admitted effects confer no support under this
method. When the observability proof succeeds under an audited toolchain
selection and neither subject flow nor user test-main flow reaches any external
input operation at all (only checked harness protocol facts such as harness
logging, benchmark pacing, closed subtest execution, checked property-harness
execution, and the canonical test-main
epilogue `os.Exit`), the observability disposition additionally records static
effect-free reachability (`Observability.EffectFree`), bound into the proof's
integrity evidence under the `gofresh/static-reachability@1` outcome method so
that an identity-only completed observation with matching runtime-input guards
is admitted without requiring runtime operation-outcome support.
The inventory is a static prerequisite, not a process receipt or evidence
that the analyzed subjects actually executed under the supplied environment;
construction still owes those premises and the complete contributing-subject set.
The derivation assumes the complete inherited environment is held unchanged for
the contributing execution, including initialization, cleanup and concurrent
contributors; a separate checked derivation must establish that return values
and presence bits follow from that complete environment, with no additional
unaccounted initialization, synchronization or native input. Neither Linux nor
any other platform name establishes these semantics. A positive observation admission alone, an empty
identity log, a purity assertion, or a missing cached inventory cannot supply
the `gofresh/immutable-environment@1` derivation when external input effects are
reachable. Warm and cold analysis report the same inventory, and its method
identity participates in analysis compatibility.

**REQ-closure-observability-cause-order** (invariant): Every reachable call and effect MUST be classified to the observability walk's
(REQ-closure-observability-analysis) end; the preferred
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
environment; then the unsupported-implementation and test-runtime classifications; the
legacy projection alone adds one weakest stratum below all of these, the
checked harness fact — with the refusal's ties resolved by the effect
projection's total order and the legacy projection's ties resolved
lexicographically on the reason text, so both diagnostics are
deterministic and causal-first. A complete maximal-tier negative scan
may reject opaque linkage, native code, process execution, dot imports, unsupported
standard-library access, or other unclassified external-capable syntax, but can never
grant the proof on its own.

**REQ-closure-observability-unsafe** (invariant): Compile-time layout intrinsics in
package `unsafe` (`Sizeof`, `Alignof`, and `Offsetof`) evaluate solely to compile-time
`uintptr` constants determined by the hashed source, toolchain, and build configuration
without executing runtime code or dereferencing runtime memory, so both the maximal
file scan and the observability scan admit them (while continuing to hash the
declaring file and walk operand syntax for type and symbol dependencies; dot-importing
`unsafe` remains blocked). For a subject whose reachability
is closed, the package-scan backstop for the observability proof
(REQ-closure-observability-analysis) MUST both scope ordinary function, method,
`type`, and `const` declarations to the declarations and named `types.Object`s
reached by the subject, package initialization (`init` and package-level
variable initializers), and `TestMain` — while keeping package-level and
file-level constructs (imports, directives, cgo, assembly, `init`, `TestMain`,
and top-level `var` declarations) and explicit package-wide process or memory
hazards (runtime `unsafe` operations other than `unsafe.Pointer` and the compile-time
layout intrinsics, `os.Exit` outside
`TestMain`, and process-environment or working-directory mutations such as
`Setenv`, `Unsetenv`, `Clearenv`, `Chdir`, and `Fchdir` on `testing`, `os`,
`syscall`, or `golang.org/x/sys/`) blocking across the whole package (excluding
`if` bodies inside synchronous-startup-only declarations guarded by non-zero
checks of verified unmutated zero-valued package globals) — and
narrow the `unsafe.Pointer` reference class out of the package-scan backstop's
unconditional blocking set: a subject reaching `unsafe.Pointer`-typed state
still refuses at its own walk tier, an unreached `unsafe` use across the binary's
loaded non-standard packages that is mechanically proven memory-safe and read-only
(compile-time `Sizeof`/`Alignof`/`Offsetof`, reference-confined read-only
`StringData` or `Slice(StringData, len)` projections, padding-free pure rvalue scalar bitcast
reads within source size and alignment bounds, and read-only or immutable-capsule
isomorphic value-layout pointer casts) leaves clean sibling subjects observable
under every execution model, and any un-confined `unsafe.Pointer` capability in a
loaded non-standard package of the test binary marks the observability disposition
single-subject-only (`Observability.RequiresSingleSubject`) so shared-process
execution models refuse fail-closed on the un-confined sibling `unsafe.Pointer`
channel while caller-attested single-subject-process execution admits the clean
subject's proof; the package's other runtime operations (`unsafe.Slice`,
`unsafe.String`, `unsafe.Add`, and kin) keep the package-wide scan block, because
their call sites carry no `unsafe.Pointer`-typed value the walk can price and a
fabricated slice or string is a testlog-invisible read. The SSA builder's internal
iterator and deferred-call stack handles and `sync.notifyList` runtime wait-queue
cells are opaque runtime tokens, not source unsafe values; their source operands
and callbacks remain independently judged.

**REQ-closure-observability-audited-set** (invariant): A value-computation
claim MUST establish that every ambient effect enters through an independently
classified operand, constructor or global, with no unaccounted observation
channel or machine-variant result. It requires a checked derivation over the
selected implementation, not membership in a package or symbol set. The same
claim and its dependencies govern the file fold and precise walks; a fold
unable to resolve the declaration or discharge a premise cannot grant it.
The following families state the properties such derivations must establish:

- Formatting and string scanning, including fmt's Sprint, Append, Errorf, and
  Sscan families, compute from their operands; formatted and scanned argument
  methods (`String`, `GoString`, `Error`, `Format`, `Scan`) remain visible to
  reachability and independently classified, while writer-first formatting and
  reader-first scanning (`Fprint*`, `Fscan*`) require proven in-memory stream
  operands under REQ-closure-observability-writer-sink.
- Arithmetic such as `math/big`, compile-time constants in package `math`
  (`MaxInt*`, `MinInt*`, `MaxUint*`, `MaxFloat*`, `SmallestNonzeroFloat*`, `Pi`,
  `E`, `Phi`, `Sqrt*`, `Ln*`, `Log*`), and universally CPU-feature-free IEEE-754
  exact functions in package `math` (`Abs`, `Ceil`, `Copysign`, `Dim`,
  `Float32bits`, `Float32frombits`, `Float64bits`, `Float64frombits`, `Floor`,
  `Frexp`, `Hypot`, `Ilogb`, `Inf`, `IsInf`, `IsNaN`, `Ldexp`, `Logb`, `Max`,
  `Min`, `Mod`, `Modf`, `NaN`, `Nextafter`, `Nextafter32`, `Pow10`, `Remainder`,
  `Round`, `RoundToEven`, `Signbit`, `Sqrt`, `Trunc`) must establish result
  invariance across any CPU-selected kernels, including relevant native and
  assembly implementations, with no `init` hooks or mutable package globals. At
  the observability tier (where `BuildConfig` guards the target platform and
  architecture feature level), additional exported `math` functions (excluding
  compiler-intrinsic `FMA`, whose compiler-lowered fallback under a fixed
  `BuildConfig` branches on runtime CPU features) may be admitted only when
  mechanical pruning of compile-time boolean constants and transitive Go and
  Plan 9 `.s` call/symbol verification over the selected `math` implementation
  establish zero runtime `internal/cpu` feature reads and zero writable assembly
  globals; runtime CPU-feature-dispatched approximations and `FMA` retain their
  refusal (REQ-guard-runtime-relevance). Memoization and scratch pooling must
  not introduce an observable input channel. Supplied random sources retain
  their own input obligations. Any use of approximate arithmetic, such as buffer
  sizing or iteration seeding, must be shown unable to change the claimed
  result. A package name does not prove bit-identical kernels or make a native
  leaf transparent.
- Fixed-argument time computation, including Date, FixedZone, ParseDuration,
  calendar and clock-field accessors, zone views, rounding, formatting,
  comparison and duration arithmetic, and package-function `time.Unix`,
  `time.UnixMilli`, and `time.UnixMicro` when immediately chained into `.UTC()`
  or `.In(loc)` where `loc` is produced by `time.FixedZone` (stripping the
  ambient `time.Local` zone before any zone decomposition can observe `$TZ` or
  `/etc/localtime`), must establish dependence only on its arguments and
  guarded implementation inputs. Clock reads, unstripped `time.Unix*` calls,
  local-zone state, zone-database loads and mutable exported globals retain
  their effects. Method and package-function forms such as After, UTC, Unix,
  Location and AddDate are judged by the selected declaration and receiver, not
  shared spelling. A claim relying on time.UTC stability must cover every write
  or escaping alias in the analyzed program, including harness and generated
  code. A location accessor that hands out mutable package state cannot inherit
  a value-computation claim. A bound method wrapper needs a checked delegation
  argument as well as the target's claim.
- URL escaping and composition, including QueryEscape, QueryUnescape,
  PathEscape, PathUnescape, User, UserPassword and the URL, Values and Userinfo
  value operations, must establish string computation over operands alone.
  Parse, ParseRequestURI, ParseQuery, JoinPath and methods that consult runtime
  debug settings retain that dependence unless separately guarded or discharged.
  Importing net/url does not grant a blanket exception to external-effect
  classification, and a code result does not acquire a measurement-only
  runtime-configuration guard (REQ-guard-runtime-relevance).
- Lexical filepath operations, including Clean, IsLocal, Localize, ToSlash,
  FromSlash, SplitList, Split, Join, Ext, IsAbs, Rel, Base, Dir, VolumeName,
  Match and HasPrefix, must establish computation over operands and the selected
  platform alone. Working-directory and filesystem operations such as Abs,
  EvalSymlinks, Glob, Walk and WalkDir keep their own input obligations.
- Encoding, hashing, container, and cryptographic mode operations such as
  base32 and base64, `crypto/sha256`, `crypto/md5`, `hash/crc32`, `hash/fnv`,
  `slices` (`Clone`, `Compact`, `Contains`, `Delete`, `Equal`, `Index`,
  `Insert`, `IsSorted`, `Max`, `Min`, `Replace`, `Reverse`, `Sort`, and their
  `*Func` variants), `maps` (`Clone`, `Copy`, `DeleteFunc`, `Equal`,
  `EqualFunc`), `encoding/binary`'s `BigEndian` and `LittleEndian` byte-order
  globals, `io.NopCloser`, `io.LimitReader`, `io.TeeReader`, and
  `io.MultiReader` / `io.MultiWriter` over closed operands,
  `crypto/fips140.WithoutEnforcement` (which sets a goroutine-local bypass flag
  around a caller-supplied callback whose body is walked and classified at the
  call site), `crypto/fips140.Enforced` (which reads the immutable
  startup-resolved FIPS enforcement bit), and `runtime.GOOS` and
  `runtime.GOARCH` compile-time platform constants must establish computation over
  supplied data and guarded build/runtime configuration alone; io-interface
  wrappers retain the effects of their concrete operands, and exported encoding
  variables require state analysis.
- Deterministic context construction, value propagation, and cancellation
  (`context.Background`, `context.TODO`, `context.WithCancel`,
  `context.WithCancelCause`, `context.WithoutCancel`, `context.WithValue`,
  `context.Cause`, the `Context` read methods `Deadline`, `Done`, `Err`,
  `Value`, the `Canceled` and `DeadlineExceeded` sentinel errors, and the test
  harness lifecycle context `(*testing.T).Context`, `(*testing.B).Context`,
  `(*testing.F).Context`, and `testing.TB.Context` under a checked derivation
  that `(*testing.common).Context` returns the harness's per-test cancellation
  context without ambient clock or I/O acquisition) must
  establish process-local state over caller-supplied parent contexts, keys,
  values, and causes alone, with wall-clock timer constructors (`WithDeadline`,
  `WithTimeout`, and their `*Cause` variants) and asynchronous cancellation
  callbacks (`AfterFunc`) retaining their refusals, and sentinel globals
  (`io.Discard`, `io.EOF`, `io.ErrClosedPipe`, `io.ErrNoProgress`,
  `io.ErrShortBuffer`, `io.ErrShortWrite`, `io.ErrUnexpectedEOF`,
  `fs.ErrInvalid`, `fs.ErrPermission`, `fs.ErrExist`, `fs.ErrNotExist`,
  `fs.ErrClosed`, `fs.SkipAll`, `fs.SkipDir`, `os.ErrInvalid`,
  `os.ErrPermission`, `os.ErrExist`, `os.ErrNotExist`, `os.ErrClosed`,
  `os.ErrNoDeadline`, `os.ErrDeadlineExceeded`, `filepath.SkipAll`,
  `filepath.SkipDir`, `strconv.ErrRange`, `strconv.ErrSyntax`,
  `binary.BigEndian`, `binary.LittleEndian`, `context.Canceled`, and
  `context.DeadlineExceeded` admitted only when no code in the analyzed program
  writes or takes their address outside package initialization, plus non-standard
  `error` package variables in cgo-, unverified-assembly-, and linkname-free
  packages admitted only when initialized by a single static `errors.New` store
  in synthetic package variable initialization with no other writes — `func
  init()` bodies included — or address-taking across the analyzed program).
- Go syntax, token, scanner, AST, and parser computation (`go/build/constraint`,
  `go/token`, `go/scanner`, `go/ast`, and `go/parser`) must establish
  process-memory computation over caller-supplied source buffers and syntax
  trees under checked derivations over the selected standard-library
  implementation: `go/parser.ParseExpr` computes over its string argument;
  `go/parser.ParseFile` and `go/parser.ParseExprFrom` admit at the observability
  tier only when `src` provably originates at non-nil `MakeInterface` values over
  `string`, `[]byte`, non-reader concrete types, or admitted in-memory
  `io.Reader` operands (REQ-closure-observability-writer-sink) and `mode`
  excludes `parser.Trace`; `go/scanner.PrintError` requires an admitted
  in-memory `io.Writer` operand; `go/parser.ParseDir`, `src == nil` file reads,
  `parser.Trace`, `go/ast.Print`, and reflection-dispatching `go/ast.Fprint`
  retain their filesystem, output, and reflection refusals.
- Build-info parsing and embedded module metadata (`runtime/debug`):
  `ParseBuildInfo` and `(*BuildInfo).String` compute deterministically over
  caller-supplied strings and structs under a checked `runtime/debug`
  derivation; `ReadBuildInfo` admits only when both `runtime/debug` and
  `runtime`'s `modinfo` backing storage satisfy checked source derivations, the
  closure folds mutable-local module and workspace metadata (`go.mod`, `go.sum`,
  `go.work`, `go.work.sum`, `vendor/modules.txt`), and effective `-buildvcs`
  resolution across `GOFLAGS` and explicit build flags omits VCS revision and
  dirty-tree stamping
  (`-buildvcs=false` on `package main` at the maximal tier; `-buildvcs=false` or
  `-buildvcs=auto` on test binaries at the observability tier; `-buildvcs=true`
  or unparseable flags refused under REQ-fresh-commit-independent).

**REQ-closure-observability-entropy** (invariant): Entropy operations, including crypto/rand's Read, Text, Prime and Int and
unseeded math/rand sources, MUST retain their input classification unless a checked
claim accounts for every relevant source. A supplied reader, familiar API name
or reported Go release does not prove which source the implementation uses.
Mutable exported globals, including Reader, io.EOF-shaped variables and
flag.CommandLine, require their own state judgment; the registration claim in
REQ-closure-observability-flag-registration is not a global-read exemption.
Local `math/rand.Rand` generators constructed via `math/rand.New` and
`math/rand.NewSource` and their integer and IEEE-754 float sampling methods
(`Float32`, `Float64`, `Int`, `Int31`, `Int31n`, `Int63`, `Int63n`, `Intn`,
`Perm`, `Read`, `Seed`, `Shuffle`, `Uint32`, `Uint64`) compute deterministically
over the caller's seed and the receiver's own state; top-level package sampling
functions (which read the unseeded global generator) and non-uniform
transcendental distributions (`ExpFloat64`, `NormFloat64`, `Zipf`, whose
exponential/logarithmic and table-driven sampling paths are not admitted in the
`math/rand` receiver set)
retain their refusal.

**REQ-closure-observability-declaration-bindings** (invariant): A reference to a type or constant can be execution-free under language
semantics once its declaration and use are resolved. It supplies no claim about
a method with the same name or dispatch through a value of that type.
Import bindings MUST come from the selected package declarations; a name heuristic
may conservatively flag an effect but cannot authorize a positive claim.
Reflection and registration retain the additional obligations below
(REQ-closure-observability-reflect-exclusion and
REQ-closure-observability-flag-registration).

**REQ-closure-observability-reflect-exclusion** (invariant): Reflection can defeat
static reachability itself, so an invoke-nothing claim MUST establish both
absence of hidden dispatch and the required state/effect bounds under
REQ-closure-observability-audited-set. Candidate properties include immutable
runtime-type views and the descriptor-view surface of Type — Kind, Name,
String, PkgPath, Size, Align, FieldAlign, Bits, NumField, Field,
FieldByIndex, FieldByName, FieldByNameFunc (its callback resolved by the
enumeration at reflect's own match site whether constant or loaded, a
constant scanned as an operand besides — classified either way), NumMethod,
Len, NumIn, NumOut, In, Out,
IsVariadic, ChanDir, Comparable, Implements, AssignableTo, ConvertibleTo,
CanSeq, CanSeq2, and the Overflow queries, with Key judged against the
descriptor's actual receiver — with the Kind and ChanDir constants, the
StructField and StructTag shapes with Get and Lookup. Each declaration needs
its own checked claim, including Value members, String methods and unexported
descriptor forms; a shared name transfers no authority. The required property
is a read of the descriptor or of the memory its operand pins. For the Elem
accessors, the required claims are a canonical-descriptor read for (Type).Elem
and a dereference of operand-pinned interface words or pointers for (Value).Elem,
with the exceptional kind cases accounted for and every Value producer retaining
its own judgment. For DeepEqual, the required claim excludes hidden method
calls and compares function values by nil-ness alone. Method and MethodByName
(they build callable Values: the
reflective-dispatch channel, with the Call family and MakeFunc), the Value
producers, the address results Pointer and UnsafePointer with the two Kind
constants sharing those names (and the deprecated Ptr), and the hand-out
Interface and Slice retain their conservative refusals. Merely recognizing
one of these names is never evidence that the selected implementation lacks
another effect, and an unsupported native descriptor operation blocks the claim.

**REQ-closure-observability-flag-registration** (invariant): Registration-shaped covert channels — flag registration returns
pointers whose values change at Parse, and gob registration mutates a
package-global type registry a sibling subject's decode can depend on —
are channels an identity log alone cannot justify. The registration WRITE itself MUST be
tier-scoped and conditional on a checked implementation claim: standard flag registration through the value and pointer
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
subject sharing the program. A computed call whose operand the closed-value
walk closes through shapes naming its functions — function constants,
closure creations, phis, tuple extractions, and type changes over them, a
closed cell's stores, the attributed parameter crossing's arguments — takes
those functions, within the enumeration's own set, as its targets at every
walk (subject, startup, and test-main alike): a recursive local closure's
call reaches its own closure, never every closure of its signature the mask
carries, and a standard closure among a site's targets is never exempted by
its init-family name — its body is unwalked, so only the operand's own
functions can stand in for the class; an operand naming no function at all
(a nil value) leaves the site nothing to classify; an operand the walk
closes without naming a function (a gate-passing harness result), an open
operand, an invoke, or a static call keeps the enumeration's targets whole.
Where the subject walk's own scan reaches a computed call the enumeration
did not attribute — a frame the object drain scans for a referenced
initializer's content — the operand's functions resolve the site by
themselves when every one is analyzed content of a package whose bodies
this walk scans — first-party and indexed, neither standard, nor a
dependency, nor the generated test main, nor a summarized harness — each
such body being scanned by the walk's own rule for the closures it meets; a
held function of any other class keeps the computed-call refusal. The FlagSet
forms identify claims every tier must judge consistently — CommandLine, NewFlagSet, the
FlagSet, Flag, Value, Getter, and ErrorHandling names, and the
ContinueOnError, ExitOnError, and PanicOnError constants — so a
method-form registration on the default set or on a set any flow
constructs rides the same sink judgment through its receiver argument, provided
the selected implementation's checked claim establishes that constructing
a set is an allocation with no additional effect in every covered flow. A startup-flow
replacement of the default set adds no channel (the storage judgment is
per registration call, set-blind), and the ErrorHandling accessor requires
its own checked claim that its field is written only at construction and by
Init, which refuses; a
subject-time read of CommandLine keeps the standard-global refusal, and
every other flag name keeps its class in every flow — Parse, Parsed,
Lookup, Set, Args, NArg, Arg, NFlag, Visit, VisitAll, PrintDefaults,
Output, SetOutput, Init, Usage, Name, UnquoteUsage, and ErrHelp refuse
by name, as do the callback families (Var, TextVar, Func, BoolFunc —
arbitrary code at Parse) — and subject-flow registration keeps the
exclusion whole through the storage judgment: a target that is no
package-level variable poisons the sink. A set the program itself
closes is ordinary state, exempt from the mark and the poison: a set
flag.NewFlagSet constructs whose every use is the receiver of a
statically dispatched registration, Parse, or ErrorHandling call — or
the one store, in an initializer's own frame, into a package-level
variable of the program's own modules whose every other use is a load
used the same way — and whose every Parse passes nil or a literal slice of string
constants, with every registration, Parse, and ErrorHandling site in an
initializer's own frame for a package-held set (its registrations then
initializer-flow writes to package-level storage) or in the constructing
function's own frame for a function-local set (its registrations then
targeting that function's own locals, used only as loads, stores,
selections, and the registration itself) — a site inside a closure
literal or launched as a goroutine proves nothing; such a set's Parse
and registrations are admitted in the flow that proves them, while its
parsed-state readers keep their class,
the default set is never proven (flag.Parse reads os.Args), a set
stored into a standard variable is never proven (the standard bodies
load it unscanned), and every other shape keeps the mark-and-poison
judgment.

**REQ-closure-observability-writer-sink** (invariant): Stream-parameterized
standard operations (REQ-closure-observability-audited-set) — writer-first
formatting (`fmt.Fprint`, `fmt.Fprintf`, `fmt.Fprintln`, and
`go/scanner.PrintError`) and reader-first scanning (`fmt.Fscan`, `fmt.Fscanf`,
`fmt.Fscanln`, and `io.Reader` sources passed to `go/parser.ParseFile` and
`go/parser.ParseExprFrom`) — MUST be admitted as pure in-memory value
computation only when checked implementation semantics hold and the stream
operand provably pins every dynamic type and wrapper instance it can carry to an
in-memory stream or no-op discard sink that acquires nothing ambient: for
writers, `*bytes.Buffer`, `*strings.Builder`, an unmutated `io.Discard` sentinel
global, carrier-free concrete `hash.Hash` implementations from verified pure
hash packages (`crypto/md5`, `crypto/sha1`, `crypto/sha256`, `crypto/sha512`,
`crypto/internal/fips140/sha256`, `crypto/internal/fips140/sha512`,
`crypto/internal/fips140/sha3`, `hash/adler32`, `hash/crc32`, `hash/crc64`,
`hash/fnv`, plus `crypto/hmac` constructed over closed pure hash factories;
process-seeded `hash/maphash` excluded), and alias-confined `*bufio.Writer` and
`*text/tabwriter.Writer` instances whose construction and every `Reset`/`Init`
rebind (and `ReadFrom` reader) recursively target admitted in-memory streams
without escaping to unverified code capable of type-asserting and rebinding the
wrapper; for readers, `*strings.Reader`, `*bytes.Reader`, `*bytes.Buffer`, and
alias-confined `*bufio.Reader` instances whose construction and every `Reset`
rebind (and `WriteTo` writer) recursively target admitted in-memory streams.
Stream provenance is judged by the closed-value walk under the dispatch
admissions' discipline: concrete non-wrapper types pin directly, interface-typed
operands require pinning `MakeInterface` (or unmutated sentinel) origins with
subject-attributed parameter and closure-capture crossings, and startup flow
closes locally constructed streams without subject attribution; an unproven
interface stream or escaping wrapper retains its output or input classification,
dynamically reached calls retain their classification regardless of site
arguments, and the maximal scan's operand-blind findings narrow to diagnostics
so the operand-sensitive tiers decide.

**REQ-closure-observability-toolchain-key** (invariant): Toolchain evidence MUST
preserve these distinct obligations:

- **semantic-authority** — Every selected-implementation claim retains its
  complete dependence identity separately from its checked derivation under
  REQ-fresh-dependency-identities and REQ-fresh-toolchain-dependencies. This applies
  at every tier, including value computation, observation operations,
  synchronization, pooling, immutable types, atomic transparency, harness
  protocol, writer sinks and linkage. There is no whole-selection approval
  Boolean, approved digest row, flavor gate or declaration-name license.
  Failure of one premise blocks its dependent claims, not independent claims
  about the same selection. Changed inference semantics requires a
  distinguishable compatibility judgment; a cache-layout change alone changes
  no semantic authority. Compiler/linker correctness supplies no native,
  intrinsic or instrumented behavior beyond REQ-fresh-dependency-identities.
- **selected-inventory** — The shared standard-library inventory covers `std`
  and its dependencies and every standard package in the actual subject graph,
  including selected Go, native, assembly, object and embedded members. Actual
  subject-graph standard nodes agree with that inventory's selected members
  before it can justify a capture or memo. Wildcard discovery alone cannot
  establish that agreement. An over-wide inventory is permitted.
- **implementation-dependencies** — Each claim additionally identifies all of
  its implementation dependencies transitively, including implicitly linked
  packages, detector runtimes, the cgo bridge where linked, selected runtime
  and native code, and generated harness dependencies such as
  testing/internal/testdeps. Missing dependencies refuse the dependent claim.
  Module implementation dependencies retain their own complete identities;
  their version pins are not semantic proofs.
- **effective-selection** — Inventory selection uses the analysis' effective
  environment and explicit build flags as the go command does, including
  GOFLAGS merging and explicit overrides. Platform, cgo, tags, experiments,
  instrumentation and FIPS selections contribute actual selected files and
  further claim-relevant inputs. A rejected build configuration yields no
  substitute selection. The reported version and language-series skew judgment
  remain distinct from selected content and semantic authority.
- **content-identity** — Membership, names and bytes determine selected-file
  identity. File digests use unsigned big-endian 64-bit lengths framing each
  name and its contents; raw NUL bytes cannot encode a different inventory.
  An actually selected empty member set has its empty-sequence identity;
  failed listing or unreadable selected content is missing evidence, not an
  empty selection. Digests are derived from the selected files whenever a
  selection is listed or its digest memo misses, and may be served from a
  stamp-gated digest memo while every recorded directory and entry stamp holds.
  Identical content under another label supplies only the same content
  identity, not a proof of behavior.
- **inventory-memo** — Selection inventories and their selected-file digests
  may be memoized per complete toolchain selection scope — record
  representation, explicit flags, toolchain-relevant pass snapshot identity
  (excluding module-local GOMOD and GOWORK paths) and discovery roots and rules
  — retaining the shared inventory, graph reconciliation, and package digests.
  Changing discovery dependencies requires re-listing. A scope-bound integrity
  commitment rejects incomplete payloads; it does not authenticate a coherently
  replaced private payload and commitment. A record serves only while every
  listed directory, the GOROOT/src discovery tree under the go command's search
  rules, explicitly selected package directories outside that search, every
  selected embed pattern's discovery tree, shared toolchain assembly headers
  under GOROOT/pkg/include, and snapshot-mode FIPS selection inputs under
  GOROOT/lib/fips140 carry exactly their recorded entries and kinds, sizes,
  modification times and change times. This includes FIPS aliases,
  archives and verification inputs, empty directories and embed-member
  discovery. A platform without change times never serves this memo. A moved
  tree re-lists. A discovery inventory containing symlinks, or a discovery
  directory reached through one, is not memoized: every construction re-lists,
  so changing followed constraints or embedded membership cannot serve an
  unstamped selection. These rules change cost, not semantic authority.
- **cancellation** — Digest traversal checks context before every file read,
  ending a cancelled construction at the next file boundary with cancellation,
  never a successful partial construction. A read in progress is not interrupted.
  The shared package-file walk and source-discovery traversal check context at
  every entry. Individual directory-stamp reads and stored-stamp comparisons
  are not interrupted, bounded by the recorded directory inventory.
- **observation-premises** — Coverage, delivery and outcome binding are distinct
  under REQ-inputs-producer-premises. Delivery establishes by mechanical source
  verification (without Go-version or toolchain-flavor allowlists, pruning only
  compile-time constant and proven-inactive runtime/function-variable gates)
  that every required `Getenv`, `Open`, `Stat`, and `Chdir` observation (across
  both path-based `os.Chdir` and descriptor-based `(*os.File).Chdir`, plus
  `testing`'s non-parallel `Chdir`/`Setenv`/LIFO `Cleanup` restoration protocol)
  reaches finalization — whether through buffered `io.Writer` sinks or direct
  descriptor/runtime line writers — or its write/flush failure is monotonically
  latched onto `StopTestLog` to prevent supported completion. A hook name,
  release label, declaration canary or successful execution cannot establish
  this. When `observation-premises` holds and the analyzed test binary's
  non-standard packages reach no raw `Chdir`/`Fchdir`/`Chroot`/`PivotRoot`/`Unshare`/`Exec`/`SetCurrentDirectory` or
  unverified `Syscall`, no non-`testing.TB` `Chdir` interface dispatch, no
  `PWD`-mutating `Setenv`/`Unsetenv`/`Clearenv`, no cgo, no unverified
  assembly, no startup or test-main `testing.Chdir`, and only intact symlink-free `testing.Chdir` targets (`Observability.TrackedChdirSafe`),
  unreached sibling `testing.Chdir` declarations do not widen subject-scoped
  Tier-2 package scans, while any subject reaching `testing.Chdir` itself
  remains unobservable. The result owner still supplies the actual harness completion receipt; a
  delivery derivation supplies no receipt for a particular process.
- **claim-rechecking** — Changed selected content or other claim dependencies
  require rechecking affected derivations under REQ-fresh-dependency-identities,
  never approval by adding a row. Diagnostics identify failed selection
  observations, dependency disagreements or unsupported claims with their
  deciding premises and dependency paths. Structured causes and human
  projections agree; one refusal cannot masquerade as a complete claim inventory.

**REQ-closure-observability-harness-logging** (invariant): A harness logging
claim MUST establish the selected implementation's failure/logging channel
properties for the resolved operation — including `Fatal`,
`Fatalf`, `Error`, `Errorf`, `Log`, `Logf`, `Skip`, `Skipf`, `SkipNow`,
`Fail`, and `FailNow`. Each resolved declaration requires a checked derivation
that it is the harness's shared core or an outcome-only delegate with these
properties; neither package/name matching nor a declaration-inventory canary
establishes the claim. The required behavior is that
output lands only in the harness's own in-memory buffer and
the run's captured output, both already part of the recorded test outcome: the
channel is output-only for outcome bits (the run-flag presentation state the
logging path reads shapes recorded-output bytes only and is outside the
proof's claim), argument method sets stay visible to reachability
exactly as fmt's Sprint family, and the walk records the reached call as an
checked harness fact whose derivation justifies summarizing the internals. The
admission applies to statically and RTA-resolved callees only — an
unresolvable reference stays refused like any other — and the harness's
ambient-input and mutation surfaces (`Setenv`, `Chdir`, `TempDir`, the
runtime-configuration reads) keep their own classifications.

**REQ-closure-observability-subtest-driver** (invariant): A subtest-driver
claim MUST establish the selected driver's protocol by checked derivation.
For `(*T).Run` and `(*B).Run`, the required properties are that the driver allocates a
child harness handle, prints run-boundary bytes into the recorded
output, keeps write-only harness bookkeeping no testing API hands back,
consults run-filter state that shapes selection and recorded-output
bytes only — outside the proof's claim exactly as the logging path's
presentation state — and runs the caller-supplied callback on a
harness-managed goroutine it waits for, returning only an outcome bit.
The callback is subject flow: its body is walked and classified at its
own sites, and the walk records the reached driver as an admitted
harness fact backed by that checked derivation instead of descending into
harness internals again. A parallel
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
the conservative refusal. Receiver and declaration resolution locate the
implementation to verify; a name-inventory canary can detect drift but cannot
prove the driver body, callback completion or observation delivery.

**REQ-closure-observability-property-harness** (invariant): A property-testing
harness package MUST be summarized at a walk or
package-scan boundary only under a checked derivation over its selected Go
sources and types (importing `testing`, zero native, assembly, `unsafe`, `embed`,
or `go:linkname` channels, and exclusively allowed standard-library packages)
proving that everything ambient in the summarized behavior is
the harness's own protocol (its run configuration is read solely from
`<UPPER_PKG>_*` environment variables and `<pkg>.*` flags derived from the
package's identifier, the clock it paces by drives only its harness-log summary
and shrink budget, its failure and debug artifacts are failfile replay inputs
under `testdata/<pkg>` or its configured failfile flag and atomic/diagnostic
outputs, its value generation uses process-local PRNG state seeded by its harness
configuration or per-run entropy, and every helper reading ambient clocks,
entropy, flags, environment-derived state, filesystem failfiles, or `testing`
mode queries is caller-confined to `init()` or harness execution entrypoints),
and the property callback is subject
flow, walked and classified at its own sites through the harness's
dispatch. Package paths, symbol names, version pins, and local-source identity
never establish protocol semantics. Unsupported harness or subordinate toolchain
behavior retains its ordinary classification. Exported functions or methods
returning a type parameter (rather than a verified generator, sealed handle, error,
scalar, or void) must either require a sealed execution handle parameter (a harness
handle struct with no exported fields, `*testing.T`, or `testing.TB` — never an
unsealed caller-implementable interface), be a pure single-argument identity function,
or be a variadic-seed generator sample method whose body deterministically overrides
the base entropy seed whenever the explicit seed slice is non-empty;
calling such a sample method without a statically non-empty explicit seed slice draws
unlogged per-call entropy outside a `testing.TB`-logged property run and
classifies as non-observable randomness across subject, test-main, and startup
flows. The checked claim is sound only paired with a
boundary gate on every flow that can call into the harness — subject,
test-main, and startup alike: each dynamic-carrying argument of a
statically dispatched harness call must be judged closed, where the judgment
admits exactly the subject-closed value walk, a handed-in sealed handle at
parameter position (the property harness's unexported-field handle struct
and the standard harness's `T`/`B`/`TB` — constructed only by their
harness and handed per-invocation; a handle loaded from shared state,
synthesized as `nil`, or passed via an unsealed interface refuses),
a gate-passing harness call result (excluding unseeded sample calls — closed for
dispatch judgment wherever it later crosses a gate), and a locally built variadic slice of
judged elements; every other value — a load from shared mutable
state, a generator laundered through an ordinary parameter whose
callers pass unjudged values — widens the subject world. Harness-
owned types confer no admission by themselves: a gated call's closure
is per-subject provenance, never a per-program fact a sibling's flow
could have supplied. A named harness function reached via a computed
function-value call keeps the conservative refusal — no static site
exists to gate the crossing — whereas in subject flow an anonymous
harness wrapper closure is admitted only when every dynamic-carrying call
argument is closed and any leading harness handle or logger parameter receives a
handed-in sealed handle,
and a named harness method (other than a variadic-seed sample method) reached via interface invoke is admitted
only when every dynamic-carrying invoke argument passes the boundary
gate and every non-harness interface boxing of a type mentioning the
receiver's origin across the subject's RTA-reachable functions occurs
in subject flow over a gate-passing receiver or variadic slice; the
test-main and startup arms stay stricter and refuse every dynamically
reached harness target. Importing the property harness
keeps the package unverifiable at the closure tier — the checked protocol claim admits
observation, never purity: a property run's outcome rides the
harness's log-surfaced run configuration, not the sources alone, so
the package scan records an admitted harness fact where it exempts
the harness's files. When the property-harness package's own sources pass
that full mechanical verification under an audited toolchain across every
compilation variant and without cross-package direct writes, the
shared-dynamic-state judgment likewise discharges the harness package's
own declared unexported globals without caller vouch or execution
attestation while keeping every struct-mutation, parameter, and receiver
obligation active on caller-declared variables of harness types.

**REQ-closure-observability-dispatch** (invariant): An open-world refusal MUST name the dispatch edge
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
target is a harness method with a checked protocol claim or an analyzed function of an
indexed non-test-main package (an unindexed or test-main target
refuses the admission; a harness method classifies as the admitted
harness fact, a standard-library target requires its own checked implementation
claim or body analysis, and
every other target's body classifies its own effects into the subject
exactly as reachable content always does),
AND the dispatch operand's dynamic types are fully determined by
the subject's own flow — the operand derives from local construction
(including local `*ssa.MakeSlice` allocations whose indexed element stores
close under the walk — even when stored into a struct field whose loads across
the analyzed program only index or range over the slice without mutating or
escaping its elements — and local `*ssa.MakeMap` allocations whose map-update
values close under the walk and never escape to unanalyzed mutators),
from an immutable closure-captured variable or bound method wrapper receiver
(`*ssa.FreeVar` resolved through all `MakeClosure` bindings of the enclosing
closure),
from an unmutated standard-library sentinel global (`io.Discard`,
`io.EOF`, `io.ErrClosedPipe`, `io.ErrNoProgress`, `io.ErrShortBuffer`,
`io.ErrShortWrite`, `io.ErrUnexpectedEOF`, `fs.ErrInvalid`,
`fs.ErrPermission`, `fs.ErrExist`, `fs.ErrNotExist`, `fs.ErrClosed`,
`fs.SkipAll`, `fs.SkipDir`, `os.ErrInvalid`, `os.ErrPermission`,
`os.ErrExist`, `os.ErrNotExist`, `os.ErrClosed`, `os.ErrNoDeadline`,
`os.ErrDeadlineExceeded`, `filepath.SkipAll`, `filepath.SkipDir`,
`binary.BigEndian`, `binary.LittleEndian`, `context.Canceled`,
`context.DeadlineExceeded`) whose package initializer
stores a carrier-free concrete value that no code in the analyzed program
writes or takes the address of outside package initialization,
from the return expressions of a static call to an audited
standard-library function (or to `context.Context.Err()` on a closed standard
context receiver when `context.Canceled` is unmutated, or to `os.Getwd()` /
`path/filepath.Abs` for `error.Error()` dispatch when the `os` sentinel error
globals and `os.PathError` / `os.SyscallError` wrappers are unmutated, or to
`go/parser.ParseExpr` / admitted `go/parser.ParseExprFrom` resolving concrete
`*go/ast.*` expression types) or a
reached non-recursive, non-variadic,
non-dynamically-targeted in-module function whose dynamic-carrying arguments
themselves close under the closed-value walk, or
from a parameter of a non-escaping function or local closure (including closures
with enumerable `MakeClosure` free-variable bindings and closures invoked
exclusively through confined local cells, `Phi`s, or `FreeVar`s with zero value
escape outside call-target positions) that is not variadic (or, for non-function
parameters under audited toolchain selection, whose variadic slice argument
closes under the walk),
and has at least one subject-attributed call
site, every such site feeding a subject-closed value (zero enumerable
callers is absence of provenance, refused, never a vacuous pass), with
an interface invoke's target set narrowed to the concrete types its
closed operand wraps when every resolved method has an analyzed or
audited body (including promoted interface method wrappers on concrete structs
that embed an interface whose embedded field is populated exclusively by
closed stores, and `go/ast` node interfaces `ast.Node`, `ast.Expr`, `ast.Stmt`,
`ast.Decl`, and `ast.Spec` under an audited closed-world program only when
binary-wide declared, operand, `MakeInterface`, and runtime-type inspection
proves zero non-`go/ast` concrete types implement that interface, defeating
external interface-embedding method overrides) — the
crossing holding for every closed-world subject whatever its own enumeration
state, an iterator's yield bound by the subject's range statement or call the
canonical shape, and the subject-attributed sites being the subject's own
provenance frames, an initializer's call to the same function startup flow the
startup walk judges; a load
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
toolchain-attributed bodies perform the real dispatch, whose effect accounting
requires body analysis or a checked wrapper-delegation claim; the planted channel is a load from shared mutable
state, while a test-main's own calls and constructions keep their
per-effect classification. Initializer flow keeps attributed-effect recording alone:
nothing is plantable before tests run, so an initializer's unattributed
dispatch is not the demonstrated channel and stays unwidened.

**REQ-closure-observability-guard-pinned** (invariant): The admitted observation set MUST include the guard-pinned
toolchain accessor — exactly `runtime.GOROOT`, never the runtime package's other
surfaces — only when a checked implementation derivation establishes the
accessor's effect and value relation and evidence guards its behavior-relevant value, together
with read-position uses of paths derived from it through constant-component
joins only where the read content is covered by the recorded evidence. A
reported version does not by itself fix the root's path or every file beneath
it. An unsupported root value or uncovered read stays unverifiable, so the
admission claims nothing the record does not pin. The admission is consulted at the subject-effect
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

Every memo below follows REQ-fresh-dependency-identities and
REQ-closure-observability-toolchain-key. Where a derivation uses implementation semantics,
its scope includes the complete selected implementation content, checked
subordinate claims and inference rules, not merely a version or a Boolean
admission verdict. Changing any such dependency rechecks the affected claim;
cache membership supplies no semantic authority.
The memo's encoding/layout identity and the compatibility of evidence it
computes are distinct obligations. Stating a toolchain guard in a key does
not waive the dependency evidence required by that key's actual derivation.
Likewise a canonical closure hash pins the source equivalence its contract
defines, not every raw source byte. Each memo carrying position-bearing or
other source-spelling-sensitive output includes sufficient additional source
identity to reproduce that payload, or derives that output outside the memo
from the current coherent snapshot. When recomputation completes, removing a
memo does not change its derived answer, including any diagnostics it promises
to reproduce. A miss can consume an analysis budget that a hit would satisfy;
the resulting unavailability or interruption is not a contradictory completed
derivation and grants no additional authority.

**REQ-closure-observability-memo** (behavior): Observability proofs MAY be
served from a persistent memo because the proof is a pure function of its
key's complete input identity: the analysis scope (the proof derivation,
memo representation, analyzing frontend, code guards, selected implementation
content, checked subordinate claims and inference rules) plus the
package test-binary closure hash, which combines the core's source equivalence
with the test-variant compartment identity, since the compartment partition
keeps test-only bytes out of the core while the analyzed binary compiles both
(stdlib rides the complete toolchain evidence, version-locked cache dependencies their
version pins, per REQ-closure-mutable-local and REQ-closure-pinned-dep), plus
the source dependencies of any additional persisted payload such as positions
— independent of the caller's execution-model attestations, because execution-conditional
premises such as `Observability.RequiresSingleSubject` are derived and persisted
execution-agnostically alongside the shared-process refusal diagnostic for caller
projection and check-time enforcement.
A memo hit is
byte-equivalent to recomputation — including recorded unrooted-subject
dispositions — and a full-group hit skips the program load entirely. The
memo is a cache, never a record: it lives under the user cache directory by
default — the consumer may redirect the store root through one knob covering
every memo class, changing what is recomputed but not the authority or meaning
of a completed derivation; a miss can leave analysis unavailable under the
same budget — writes atomically, and a missing, unreadable, corrupt, or
key-mismatched entry recomputes silently; no entry is
trusted beyond its complete dependencies and retained checked authority — key
agreement alone cannot supply a missing derivation. Entries accumulate across
closure versions under a shared byte retention bound (`DefaultMemoMaxBytes` =
2 GiB across all memo classes,
explicitly collectable via `PruneMemos`, and inspectable without mutation via
`PreviewPruneMemos`, which preserves in-flight `.cache-*`
writes, reclaims obsolete memo classes and abandoned keys alongside active
ones, and reports used, reclaimed, and remaining bytes plus removed and
skipped entry counts); eviction changes only cold recomputation cost, never
freshness or verdict authority, and the cache is deletable wholesale at any
time. Proofs persist as each attribution slice
completes: an analysis deadline expiring mid-group forfeits only the
interrupted slice's proofs, and a later pass serves every completed
slice's from the memo. A violation of the caller's quiescence
obligation (REQ-fresh-producer-view) can persist through the memo until the
key moves — the memo widens that contract-excluded window's blast radius
from one process to the cache, never its reachability. Changing proof
semantics requires a distinguishable derivation identity and, when the
meaning of recorded proof changes, a compatibility judgment. A memo-layout
change alone moves its memo identity, not the meaning of historical evidence.
Diagnostic bytes that an encoding includes in its integrity evidence remain
integrity-bound; rewriting those bytes cannot silently preserve that seal.

**REQ-closure-dynamic-state-memo** (behavior): Per-package shared-dynamic-state
facts — the dynamic-capable package-level variables a package declares, the
variable identities its code mutates after initialization
(REQ-closure-shared-dynamic-state-mutation-shape), and its method-directive declarations — MAY
be served from a persistent memo for version-pinned packages, because each fact
is a pure function of its key's complete input identity: the caller's scope
(the fact derivation and memo representation, analyzing frontend, code guards,
dependent selected implementation content, and checked subordinate claims and
inference rules — independent of the caller's execution-model attestations,
because per-package facts record execution-conditional pool candidates and
marks side by side for composition to evaluate, so attested and unattested
sessions share persisted pinned facts) plus the module's version pin and the version signature of every
pinned module reachable from its packages, its type environment's complete
version surface (the standard library rides its complete toolchain evidence). A
mutable-local package's facts are never memoized by version — its source
carries no version signal (REQ-closure-mutable-local) — and derive from live
source, reusable within a session only under a key binding the fact scope,
listing identity, reachable pinned module versions, and live byte digests of
every file in its transitive local import cone, or serve as part of a view
package's whole scan under the package scan key of REQ-closure-scan-memo,
whose content digest is the signal a version cannot give; an unverified
process-lifetime cache is sound only for keyed pinned facts and never
holds a mutable-local derivation without live content digests, so no stale process state can override
newer local source. A pinned module whose import
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
contribute no ordinary module-variable declaration facts: this declaration
inventory excludes module-less packages, standard source cannot directly name
module variables through imports, and it is not an authoring surface for
gofresh directives. This inventory boundary establishes no absence of
standard-library state, callbacks or effects. Any dependent implementation
claim still requires checked state and effect derivations; omitting a standard
declaration here cannot discharge it. A memo hit is fact-equivalent to recomputation. The memo is a
cache, never a record — the observability memo's discipline verbatim: a
sibling directory under the consumer-controlled store, atomic writes, silent
recomputation on any miss, corruption, or key mismatch, deletable wholesale
at any time; changing fact semantics bumps the fact-strategy version.

**REQ-closure-effect-scan-memo** (behavior): The fold of a version-pinned
package's per-file effect scans MAY be served from a persistent memo,
because that fold is a deterministic function of selected syntax and any
checked classification claims, under its key's complete input
identity: the scan-strategy version and the analyzing frontend's version
(the frontend the analyzing process scans with, a cache-miss defense
distinct from the analyzed selection's toolchain, a guard) — joined by
the selected implementation content, checked subordinate claims and inference
rules on which its classifications depend, for every selection including the
default; an admission Boolean cannot distinguish those dependencies — plus the
module's version pin, the package's import path, and the identity — with
its Go/cgo partition — of the file set the current listing selects for it.
The per-file scan reads no types, so it contributes no direct type-environment
signature (the typed testing-effect scan is separately governed). A checked
classification claim still retains every dependency of its own derivation,
including any type environment it used; the syntax-only consumer cannot erase it.
Package-level effect facts — assembly, system objects, cgo linkage
metadata — are functions of the live listing's build configuration, which
the key does not carry: every pass recomputes them from the listing in hand
and they are never persisted. A mutable-local package's fold is never
served from this memo — the classification is the resolved source living
outside the module cache, and any version the listing reports for a
replacement does not attest that source — every pass re-reads every
file; what serves for such a file is its own per-file scan, under
the file's content digest joined with this memo's scope, because the
scan is a pure function of the bytes the digest names: the bytes are
read and digested every pass, the parse alone is served, and the entries
batch per package directory. A memo hit is byte-equivalent to
recomputation — the effect set, its order, and the preferred diagnostic
alike. The memo is a
cache, never a record — the observability memo's discipline verbatim: a
sibling directory under the consumer-controlled store, atomic writes,
silent recomputation on any miss, corruption, or key mismatch, deletable
wholesale at any time; changing scan semantics — classification tables
included — bumps the scan-strategy version.

**REQ-closure-testing-scan-memo** (behavior): A package's typed
testing-effect scan MAY be served from a persistent memo, because the scan
is a pure function of its key's complete input identity: the scan-strategy
version and memo representation plus the code guards, selected toolchain
content, checked subordinate claims and inference rules that the type environment and classification
depend on, plus the analyzing frontend's version,
plus the package test-binary closure
hash, which pins the combined core and test-variant source equivalence,
plus any additional source dependencies of its persisted payload.
The guards come from the caller's one analysis scope, set once per
pass, which arms every closure memo that needs them. A hit serves
before any type-environment load; without the caller's guards the memo is
disabled, and a closure-hash derivation failure disables it for that
package — fail-open to recomputation. A memo hit is byte-equivalent to
recomputation — the effect set, its order, and the preferred diagnostic
alike, an effect-free scan included. The memo is a cache, never a record —
the observability memo's discipline verbatim: a sibling directory of the
consumer-controlled store, atomic writes, silent recomputation on any miss,
corruption, or key mismatch, deletable wholesale at any time; changing scan
semantics — the testing classification table included — bumps the
scan-strategy version.

**REQ-closure-scan-memo** (behavior): A view package's scan — the
shared-dynamic-state facts of its typed test-binary program, the
directive, dynamic-signature, external, and ambiguity marks of every
subject the package declares, and the discharges the caller's vouches and
execution attestations carried for them — MAY be served whole from a
persistent memo, because every output is a pure function of its key's
complete input identity — the shared-dynamic-state judgment reads the
package's own graph and nothing of its sibling view packages
(REQ-closure-shared-dynamic-state): the fact-strategy version, the analyzing frontend's version, and the code guards
(toolchain and build configuration), dependent selected implementation content,
checked subordinate claims and inference rules, the memo representation, the execution attestations (including the rooted-functions derivation identity when an attestation arms reachability discharges), and the
caller's vouch set — the scope — plus the package scan key: the maximal
closure hash joined with the test-variant compartment identity, which
pins the core and test-variant source equivalence of the test binary's graph
and every pinned version it is built from (the standard library rides its
complete toolchain evidence), plus any additional source dependencies of its
persisted payload. A served package takes no part in the pass's typed load, its
derivation, or its discharges; the load runs over the missed packages
alone, and only whole-package complete scans (never budget-cut packages) are
persisted. A memo hit is output-equivalent to recomputation. The memo is a
cache, never a record — the observability memo's discipline verbatim: a
sibling directory of the consumer-controlled store, atomic writes, silent
recomputation on any miss, corruption, key mismatch, or entry-shape
mismatch, deletable wholesale at any time; changing scan semantics bumps
the fact-strategy version.

**REQ-closure-listing-memo** (behavior): A package's dependency listing — the
toolchain's own account of the test binary's graph, from which every
closure fold, package scan key, and graph metadata of a pass derives —
MAY be served from a persistent memo, because the listing is a
deterministic function of inputs the memo can re-verify: the scope — the
pass's environment snapshot (toolchain, module cache, build
configuration, flags in the environment), the working directory, and the
build flags — and, recorded beside the stored listing, every file-system
input the listing consulted: for every mutable-local package directory
in the graph its entry names and kinds, the effective kind or absence of each
symlink's target, and the bytes of every source-kind regular
file (build constraints and import lines live there; an excluded file's
edit can include it; a non-regular or dangling entry contributes its
classification without source bytes, so retyping it cannot serve an old
listing), the entry classifications of every directory under its embed
patterns' roots (membership the listing resolves), the module files
of every module the module graph reads — go.mod, go.sum, and vendor/modules.txt
of each module contributing a package (a vendored node rides the vendor tree),
of the active GOMOD module when resolved, of every module the workspace uses,
and transitively of every local replacement target those module or workspace
files name, package or no package of it in the listing — the vendor manifest of
the main module and, under a workspace, of the workspace root, the workspace
file and its sum file as the environment resolved them or the workspace file's
absence along the directory's ancestors, and, along every intermediate directory
between the working directory and the outermost containing module root, the
content of each existing nested submodule go.mod (with its module graph) or the
verified absence (via Lstat; dangling symlinks fail closed) of each go.mod that
did not exist at capture time; the
toolchain-generated test main's own bytes may be derived outside this listing
memo, but any inputs selecting its graph or supporting a harness claim remain
dependencies of their respective judgments;
version-pinned modules are immutable under the pin go.sum carries, and
the standard library's listing dependencies ride complete selected-source
evidence rather than the snapshot's reported version alone. The inputs that
can change membership, imports or embedded-file discovery remain dependencies
even when the selected version string is unchanged. A hit re-verifies every recorded input
byte for byte — the served listing IS the listing a spawn would produce
— and any difference, unreadable input, or unmodellable pass (a flag
naming a module file outside the model, no main module
containing the working directory, a module or workspace file the build
cannot parse — reported as a diagnostic) spawns the toolchain; the record's
own shape is part of its scope, so an entry of another shape is never
decoded. Cache, never record: the observability memo's discipline
verbatim — user-cache sibling, atomic writes, silent recomputation on any
miss, corruption, or entry-shape mismatch, deletable wholesale.

**REQ-closure-mutable-local** (invariant): A mutable-local dependency reached by the
subject MUST be hashed by its source content, never pinned by module version — such
source resolves to a working directory with no version or checksum signal, so pinning
it by version would leave a silent content edit invisible and report the subject valid
while its dependency moved, the exact false valid the closure exists to prevent.

**REQ-closure-canonical-member** (behavior): A compiled Go member of a
mutable-local package that no `go:embed` directive names MUST contribute its
canonical form to the package's core contribution, never its bytes: the
member's token stream — each token's kind and literal, every semicolon kept as
one token whether written or inserted by the scanner, so the stream determines
the syntax tree — with every comment dropped except the classes the toolchain
or gofresh reads as behavior, each retained at its position in the stream
together with its attachment — whether its comment group (comments on
consecutive lines) is the lead group of the token that follows, ending on the
line before it — positions read as written, never as a `//line`
directive adjusts them, exactly as the parser reads them, so a directive
between a comment and its declaration leaves the attachment standing:
the parser's doc rule, which decides whether a directive
documents the declaration that follows or floats free, a blank line or a
block comment on the declaration's own line breaking it: directive-shaped
comments (`//go:…`, `//gofresh:…`, any tool's `//<name>:…`, in the line or
the block form — the analyzer reads a linkname out of either), cgo's
`//export`, the legacy `+build` constraint in any spelling go/build reads
(vet's build-tag check fails the build when it disagrees with the
`//go:build` line), the cgo preamble (every comment
immediately preceding `import "C"`, or the `"C"` path inside an import group),
and the standard Go generated-file marker (`// Code generated … DO NOT EDIT.`);
`//line` directives are not retained, they remap positions. Whitespace,
layout, and every other comment reach the binary only as source positions,
which this judgment rules diagnostics, not behavior (as the compartment
ledger's inertness already does), so a comment-only edit, and a layout edit
that inserts no statement break, leaves every identity standing, while any
token change — an inserted semicolon included, so a one-line body reflowed
into a block is a new form — and any change to a retained comment or its
attachment, moves it. Every other member contributes its bytes: embedded data
whatever its name, a compiled member a directive embeds too (its bytes reach
unchanged code as data), C, assembly, the rest of a package folded whole for a
cgo callback or non-toolchain assembly, and a compiled member the scanner
refuses (text without a form). The test-variant compartment keeps its own
fold (REQ-closure-test-variant-ledger): its header identity folds
comments outside declarations by design. The canonical digest is derived from
the same bytes the effect scan parses and memoized under the member's byte
digest beside it, so a byte-equal pass pays the read alone. The residual is
named, not new: a subject observing its own source position can change output
under a layout-only edit, exactly as under a header-only edit the ledger rules
inert.

**REQ-closure-identity-strategy** (invariant): The closure identity's derivation
— what the maximal closure and the test-variant compartment fold and how: each
hash's membership rule and its byte-or-form discipline (the compartment's
empty sentinel included), the canonical member form, and the compartment's
ledger derivation — MUST be a fingerprint constituent exposed as data beside
the two hashes, composed from every such derivation's own version so that a
change to any of them moves it by construction, never restated where it
could lag; the value is opaque, compared for equality only, never parsed for
which derivation moved. The analyzing frontend — the Go version the
analyzing process scans and parses with — is not a constituent, by
design: the canonical member form and the ledger's declarations are a
scanner's tokens and a parser's declarations over valid Go sources,
which Go's compatibility promise fixes across frontends in the forward
direction — a newer frontend reads older language, and new syntax
appears only in sources that changed — so composing it would move every
consumer's records on each upgrade of the consumer's build toolchain for
hashes that did not move; the reverse direction, a source newer than the
frontend, is refused at the provenance boundary by the toolchain-skew
check (REQ-fresh-toolchain-skew). Every persistent memo holding a derivation the
analyzing frontend made keys on the frontend — the syntax-level memos as
a cache-miss defense, the type-level memos (proofs, facts, scans) as a
correctness key, their payloads being the frontend's own; the listing
memo alone does not, its payload being the analyzed toolchain's own
account re-verified against its inputs (REQ-closure-listing-memo). Two hashes folded under different derivations say nothing
about each other's source: a consumer keying a judgment to a closure hash —
gofresh's own check serves by the hash alone, which is self-describing, but a
consumer carrying a judgment across records compares identities — compares two
records within one derivation and bridges a derivation change rather than
reading it as source motion. An empty recorded derivation is not a
recognized one: records predating the constituent exist under two folds (the
byte fold and the first canonical form), so an empty value is incomparable
and a consumer bridges it exactly as a differing one.

**REQ-closure-pinned-dep** (behavior): A pinned dependency reached by the subject
SHOULD be identified by its module path and version rather than hashed per
declaration — content and version are equivalent for a version-locked module, so the
pin captures every possible change through the one event that causes it, a `go.mod` or
`go.sum` bump, including an init-registered driver or codec the subject never names,
at coarse but sound module granularity.
