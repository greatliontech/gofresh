# Replace toolchain-variation admission with generic verification

Lands: docs/plans/tooling-redesign.md 5.1w.7.

Constituents: 5.1w.1 settles the contract; 5.1w.2-3 establish useful semantic
derivations; 5.1w.4-5 establish sound producing evidence; 5.1w.6 migrates every
claim consumer and dependent cache. This work precedes Stipulator 5.2d/5.2e.

## Demonstrated structural defect

`closure/toolchainaudit.go` stores approved selected-package digest chains.
`closure/toolchainsource.go` admits a selection when one expanded chain covers
all running keys. Matching is by content, not the diagnostic label, but it is
still manual approval of implementation combinations. The nodwarf5 row changes
only `internal/goexperiment`, followed by separate race, platform and cgo rows.
Its own comment says the change introduces no effectful standard-library body.

One `SelectionAudited` answer gates ordinary source-only classifications,
shared-state analysis, observability and outcome support. An unmatched key can
therefore withdraw unrelated summaries; compatible changes require additional
combination rows rather than composition of their semantic derivations. These
are concrete maintenance and precision costs, not a demonstrated false-valid
path in the current fail-closed registry.

## Required replacement

The governing contract is [implementation verification](../specs/implementation-verification.md).
The user selected generic implementation verification, retaining the existing
trust boundary rather than assuming additional platform/observation guarantees.
No toolchain label, selected-content whitelist, capability-name declaration or
equivalent indirect variation registry may authorize a semantic claim. Hashes
retain dependency identity; cold derivation must establish the same authority
as a valid memo hit. Unknown native and observation-delivery premises remain
explicitly unsupported, never ordinary Go conformance by implication.

The same obligation applies when a checked claim would otherwise borrow a
version-approved dependency or generated-code summary as an unchecked premise.
Those summaries migrate with their consumers; module/version/content identities
continue to detect drift, and explicit caller vouches remain assertions under
their own rules. Moving the approval lookup to a subordinate summary does not
establish independent checking.

Acceptance requires useful end-to-end positives, not merely refusing every
selection. The existing SSA infrastructure does not itself verify arbitrary
native leaves or the bodies currently replaced by audited summaries. Complete
that work, migrate every consumer and remove the old mechanisms before closing.

## Summary-consumer inventory

Each row is an implementation premise to replace, not a newly approved summary.
The first computation vertical lands at 5.1w.2, required native/runtime
derivations at 5.1w.3, observation claims at 5.1w.5, and all remaining consumer
adoption at 5.1w.6. The shared mechanism is removed at 5.1w.7. Preserve the
existing useful cases and add changed-implementation negatives for each family.

| Claim family | Current mechanism | Deciding replacement obligation |
|---|---|---|
| Whole-package computation | `internal/auditset` pure packages; `closure.isSourceOnlyStandardPackage` | Reachable computation, callbacks and initialization, including machine-dependent kernels |
| Symbol/receiver computation | `closure.auditedStandardCallee`, receiver tables | Actual return/effect bounds; familiar receiver or method names confer nothing |
| Synchronization, Once, Pool, Map | `purity.go` synchronization/pooling/data-memo rules | Concurrency, retained population and callback bounds, with execution-model assertions kept separate |
| Atomic-pointer transparency | `closure.AuditedAtomicPointerElem` | Selected storage/type-flow, unsafe and native operation semantics |
| Immutable constructions | `recordOpaqueDynamicVars`, `immutableRuntimeType` | Actual object closure, retention and descriptor immutability; these rules are not all gated by selection approval |
| Container clone/concat | `auditedValuePlane` | Return population, mutation and alias bounds, including runtime linkname targets |
| Flag registration | `flagRegistrationFacts`, `flagSetProvenance` | Selected registration/parser effects in addition to caller storage provenance |
| Formatting sinks | `inMemoryFormattedSink`, writer-type tables | Formatter callbacks and actual writer effects, not receiver-name approval |
| Standard harness families | `stdBodyCut`, harness logging/subtest/pacing rules | Complete callback and phase coverage under the declared result model |
| Environment/file wrappers | `classBEffect`, `observableCallEffect`, returned-handle rules | Separate coverage, aliases/path identities and operation outcomes; no hidden native-body exemption |
| Linkname floor | `auditedLinknameTargets` | Actual linkage and target effects, retaining every residual uncertainty |
| Observation delivery | `harnessPremisePackages`, approved testing/testdeps content | Required-record delivery or failure before supported completion, including short writes, buffering and cleanup |
| Environment outcomes | `immutableEnvironmentMethod` | Actual lookup/state/return semantics, including initialization, hooks and contributing environment mutations |
| Rapid harness | `auditedPropertyHarnessModule`, body/provenance cuts | Actual selected harness/callback behavior, including mutable-local replacements |
| x/sys mapper | `auditedSourceListing`, `auditedSourceOut` | Callable stability, bookkeeping/alias bounds and the still-required syscall refusal |
| yaml metadata memo | `auditedSourceListing`, `auditedSourceOut` | Generic get-or-compute invariance, initialization, publication and nonescaping immutable values |
| Generated protobuf state | `generatedProtoHeader`, `generatedProtoOut` | Actual generated bodies, schema dependence and selected runtime mutation/retention behavior |
| Generated gRPC registration | `GeneratedGrpcVars`, `generatedProtoOut` | Actual descriptor/callback capture and nonmutation, with network effects independently judged |

Shared consumers include maximal and precise classification, attributed startup
and subject traversal, root purity/dynamic-state analysis, source certificates,
observation/outcome preparation, native capture/check/closing and their memos.
Every cached claim retains selected-content and semantic-rule dependencies;
neither a cache hit nor a reused third-party summary bypasses checking authority.

The native boundary is concrete: environment lookup reaches runtime startup
state and synchronization; test-log delivery reaches buffering, writer wrappers
and syscall assembly; even `maps.Clone` reaches a bodyless runtime linkname.
Replacing these with named semantic aliases would leave the original proof
obligation unmet. No syscall-outcome or timing guarantee follows merely from
compiling the Go wrapper or observing one successful execution.

## Compiler-selected implementation counterexample

The first uncommitted source-computation prototype incorrectly discharged a
runtime refusal after checking only the nominal Go bodies. An isolated
`math/bits` selection with a scalar `OnesCount64` fallback returning zero passed
that grammar. The actual compiler substituted a CPU-feature-dependent POPCNT
operation with the Go body as fallback. Under `GOAMD64=v1`, one retained binary
returned 1 normally and 0 with `GODEBUG=cpu.popcnt=off`, while code-result
fingerprints agreed and public checking returned Valid without purity or
observation authority. The retained regression is
`TestComputationAcceptanceCompilerIntrinsicRuntimeDispatch` in the prototype
checkpoint below; its mainline acceptance belongs to 5.1w.2b. The reproduction preserves the selected library's
exports, replaces the two de Bruijn byte-array variables with byte-identical
constant strings, and replaces the linknamed error variables with constant
strings, so package storage/directives do not independently defeat the source
grammar. A production-only subject calls `bits.OnesCount64`; its driver prints
that result for input 1. The driver is compiled once, and both executions and
the content check retain exactly that binary. The differing runtime settings
leave the code-result fingerprints equal.

The prototype's runtime grant is cut off until 5.1w.2b establishes actual
compiler-selected implementation correspondence. Its source checker is not that
correspondence. Preserve the useful positive acceptance tests; their unfinished
gate cannot be closed by weakening them to accept universal refusal. Necessary
native/translation work from 5.1w.3b precedes that grant. An intrinsic-name
denylist, an assumption that an edited fallback satisfies the intrinsic's
contract, or silently disabling optimization would not repair the agreed model.

Retained artifact bytes provide a concrete evidence anchor. Compiler objects,
late intermediate representations, symbols and debug information can propose
scope and derivations, but need checked correspondence and complete coverage,
including inline instances and dispatch. The current opaque `BindBuilt` identity
is an execution-owner declaration, not readable code or an implementation proof.
Extend the existing generation/build boundary with the required bound evidence
rather than introducing a parallel execution framework.

## Retained public-adoption prototype

The six-file prototype is preserved byte-for-byte at
`a3d9ebae5d69fdf45c46c76d3aefea392a0d3053` on branch
`reconcile/computation-adoption-prototype`, based on
`88a069fc8789ec934c7e165cd1a08c7ce8e3258b`:

- `closure/dependencies.go`
- `closure/maximal.go`
- `closure/policymemo_test.go`
- `closure/computation_integration_linux_test.go`
- `closure/computation_public_linux_test.go`
- `computation_acceptance_test.go`

This is unvalidated WIP, not release-ready; do not merge it wholesale. It is the
post-cutoff prototype: it retains the intrinsic counterexample fixture, but its
maximal consumer no longer contains the original unsound runtime grant. That
consumer loads and checks source, then retains every conservative refusal. Its
discharge comments are obsolete. A direct stock-Go run confirms that
`TestComputationSelectedImplementations` fails its useful-positive assertion with
`compiler-selected implementation binding is unavailable`. Preserve that positive
expectation; refusal is not equivalent acceptance.

Extract and adapt the checkpoint's obligations at their existing landing slots:

| Lands | Required integration |
|---|---|
| 5.1w.2b, including 5.1w.2b.4 | Useful selected-source/callback positives and the retained intrinsic-dispatch regression before restoring maximal runtime discharge; unsupported effect, native and initialization negatives remain required. |
| 5.1w.6 | Replace the disabled consumer attempt with actual checked-claim integration; bind the complete adopted semantic dependencies in policy/memos, retaining cancellation, cold/warm/discarded-cache equivalence, capture/check/closing, historical evidence and measurement guards. Reconsider `toolchain-policy@2` with that integration rather than landing the prototype's identity change alone. |
| 5.1w.7 | Run these positive and adversarial cases as required release gates and remove superseded mechanisms; do not delete positives or make them expect universal refusal. |

The checkpoint is recovery and acceptance material, not authority for current
reuse. Mainline keeps the committed conservative consumer while these already
scheduled prerequisites are completed.

## Acceptance and architectural exit conditions

Lands: 5.1w.2b.4 for the first public proof thread, 5.1w.6 for complete consumer
and memo adoption, and 5.1w.7 for preserved-family acceptance and removal.

The retained `TestComputationAcceptanceUnlistedSource` and
`TestComputationOrdinaryCaptureCheck` cases define useful new-proof acceptance,
old-content staleness, cold/warm/discarded-cache agreement and closing drift.
`TestComputationAcceptanceCompilerIntrinsicRuntimeDispatch` and
`TestComputationAcceptanceUnsupportedSelectedSource` retain the deciding
adversarial cases. Adapt their construction to the actual public API without
weakening their authority assertions or substituting a private native invocation
for the ordinary test/benchmark workflow. Genuine source-only support remains
separate from observation delivery and actual producing applicability.

These assertions are preserved in the checkpoint rather than integrated into
current public qualification. The new top-level computation/correspondence
checkers have no production-classification callers yet, while the approval
registry still supplies those consumers. Passing subordinate proof suites does
not close this validation gap. The first integrated path must acquire and compose
its evidence through production code rather than test-private proof orchestration.

The remaining bootstrap/compiler route also needs consumer-bounded architectural
qualification. The dependency-path analysis lands at 9.4a before starting
5.1w.2b.3b.2a.2.2.2.2.16b.1c: identify each missing edge's production caller,
required evidence, reusable mechanism, deciding positive/adversarial test and
ordered implementation slot. Resolve genuine trust or population forks with the
user before extending the route; a first accepted consumer does not discharge
the other supported families. Process-input construction at
5.1w.2b.3b.2a.2.2.2.2.16b.2 must
consume owned launch inputs without fixture-authored physical placement; .17
qualifies increasing finite input shapes and cumulative proof budgets; .19 checks
the completed bootstrap interface against its typed-state consumer. Before
extending the frontend at 5.1w.2b.3b.2a.2.3, establish the concrete dependency path
to the public acceptance case and justify each scope by its downstream claim.
Repeated full-history copying and actual callee replay are sound mechanisms, but
their present implementation alone does not establish that this larger consumer
fits its resource bounds. Structural feasibility belongs at those slots; the
full performance pass retains its existing post-adoption order.

## Public adoption boundary

### First consumer and dependency path

The first ordinary thread is the existing `TestScalar` fixture in
`closure/computation_callback_selected_test.go`: its selected computation calls
`unicode/utf16.IsSurrogate`, and its optimized body has an independently checked
return with the failing source branch excluded. The local proof deliberately
leaves initialization, actual use, harness and applicability open. The public
acceptance case is `TestComputationOrdinaryCaptureCheck_TestScalar`: stock and
harmless custom selected source must acquire the same generic proof authority,
old selected-content evidence must stale, and a fresh custom production must
qualify without an approval row or purity assertion. This first thread does not
complete callbacks, benchmark pacing, environment verification or the remaining
supported families.

The production path is `Session.Snapshot` / `observeView` /
`ComputeMaximalBatch`, then `BindArtifact`, unit registration and close, native
record serialization, and `RuntimeBinding.Check` / checking close. Its missing
edges have separate owners:

| Edge | Required change | Lands |
|---|---|---|
| Shared typed load to later proof acquisition | Retain exact selected-source ownership and complete conservative blockers without a second unrelated load. | 5.1w.2b.4a |
| Bound source/native facts to ordinary implementation authority | Complete actual-use, initialization, harness and selected-implementation coverage for the producing artifact; retain its historical scope at current checking. Local callback or startup certificates cannot supply it. | 9.4a.1-2 qualify the route; 5.1w.2b.3 and 5.1w.2b.4d implement and consume it. |
| Inspected artifact to preparation | Admit immutable scoped claims and select residual obligations for the whole runnable roster before execution. | 5.1w.2b.4b/d |
| Prepared evidence to close | Validate each unit's dependencies and obligations without mutating its shared snapshot or borrowing sibling authority. | 5.1w.2b.4b |
| Producing theorem to current check | Retain sufficient historical evidence and check its original producing binding, compatible proof, complete current selection agreement and applicable runtime dependencies. | 5.1w.2b.4c/d |
| Checked claims to warm serving | Include complete rule/premise/dependency identities; deleting disposable memos changes cost, not authority. | 5.1w.2b.4c; all remaining consumers at 5.1w.6 |

### Evidence ownership and applicability

The lifecycle refactor separates three concepts currently combined in
`closure.Closure`: immutable source identity, conservative implementation
blockers, and evidence-dependent disposition. `observeView` classifies before
`BindArtifact` can observe a producing executable; registration only retains and
validates that artifact, while closing compares classifications as snapshot
facts. Mutating the snapshot after artifact analysis would leak authority between
siblings; comparing a refined closure with an artifact-free conservative closure
would instead reject the refinement. The causal repair is immutable base facts
plus scoped checked claims and transaction-local applicability, not a comparison
exception or a local bypass of observer preparation.

One evidence-selection operation must prepare the complete runnable roster's
residual obligations. Source-only support, identity-only diagnostics, observation
coverage, delivery, operation outcomes and terminal completion retain distinct
authority. `producingUnit.register` currently sends every non-diagnostic unit
through `PrepareOutcomeSupport` and `CaptureObservedBatch`; that control split
cannot represent the new independent source-only channel merely by relabeling
diagnostic units. Existing singleton/package/retry and closing ownership remains
the common lifecycle.

Historical artifact bytes are proof inputs, not automatically live current
filesystem dependencies. The historical-result rule in
[evidence](../specs/evidence.md) retains a complete artifact theorem within the
original recording's scope. Current checking establishes its original truthful
producing binding, sufficient retained proof, compatible premises and rules,
complete source/build-selection agreement or a separately licensed applicability
endpoint, applicable runtime guards and consumer conditions. Unchanged complete
selection preserves the historical artifact's membership in that selection;
membership alone proves no behavior.

This corrects the earlier requirement to prove the same effect bound for every
permitted rebuild before retaining a historical result. That universal theorem
is needed for a selection-wide claim, not for keeping an established theorem
attached to its own result. The governing model does not promise identical future
outcomes: supported runtime observations likewise guard the identities actually
read by the contributing execution, rather than every input another permitted
execution could read. A direct existing-channel experiment confirmed that a
completed no-read execution remains valid after an unread environment value
changes, although the same binary can subsequently take its language-permitted
read branch and fail. This comparison concerns applicability scope; it supplies
no native implementation proof. It neither creates a certified-only population
nor transfers historical support to a fresh production. Hidden build dependencies
and unguarded runtime dispatch remain obligations, not language nondeterminism.

The target is one native record carrying sufficient immutable historical evidence
to check its claimed authority, with the existing disposable memos providing only
acceleration. A digest or stored approval bit is insufficient. Current checking
admits each record's own evidence against the freshly observed source/build,
selected-implementation, rule and applicability dependencies; it does not claim to
have inspected a new executable or repair missing producing facts. The original
executable's deletion and disposable-cache eviction must preserve a successfully
supported historical claim. The historical rule governs applicability; sufficient
native-record representation and its implementation still land at 5.1w.2b.4c.
Existing records acquire no such authority.

### Unestablished proof mechanism

Compiler-bootstrap execution is a chosen applicability construction, not a
requirement of the governing contract. Two legitimate mechanisms remain: prove
the relevant selected lowering association and use the existing implicit-language
premise, or independently prove the needed native behavior, including the slow
path. Matching call shapes, source proximity, labels or compiler metadata close
neither argument. The existing local native and source proofs establish neither
complete mechanism for the ordinary consumer yet.

The historical-applicability rule is settled at 9.4a.1. The next work is
9.4a.2's complete actual-artifact lowering/native bridge and 9.4a.3's
consumer-sized composition qualification. The selected `testing.tRunner`
stack-check/retry fragment is the
initial bridge candidate, not an approved helper or an assertion of feasibility.
If it needs a compiler-state invariant, name that invariant and its influencing
path before scheduling its smallest prerequisite. Do not presume that replaying
the compiler from ELF entry is necessary, or that calling the alternative
translation validation makes it complete. The existing continuation/history and
callee-replay costs require qualification against the same required population.
9.4a remains open until these results establish the bounded implementation path;
the lifecycle design and additional plan slots alone do not close it.

The compiler-origin candidate at 5.1w.2b.3b.2a.2.4 checks a normal-return postcondition
of selected intrinsic-table construction. Fresh map replacement can eliminate
dependence on arbitrary prior table contents; inductive projected-key summaries
can cover all configuration branches without reconstructing their exact values.
The complete source construction includes SIMD registrars, actual helper and
callback arguments, and invoked factory bodies. Stored builder closures are not
invoked merely by insertion. The checker derives the resulting package-key
exclusion from actual typed writes; neither compiler names nor a list of approved
package strings supplies a rule. This is one selected substitution mechanism,
not a census of every implementation-changing route.

This theorem concerns normal return, not intermediate effects or termination.
An opaque formatting call followed on every continuation by unrecovered panic
cannot reach that invocation's normal return, but its effects remain unknown.
Recovery and other feasible normal exits invalidate such an exclusion unless
accounted for. The conditional lookup theorem uses the actual normalized key:
the compiler's runtime-package-object special case means a raw package path alone
is insufficient. Initialization-to-use preservation, mutable predicate targets
and package-object association remain separate obligations at 5.1w.2b.3b.2a.2.5. Closing
the construction experiment supplies none of those facts by implication.

The selected source continuation exposes a concrete preservation boundary before
parsing or compiler worker creation. After `gc.Main` calls `ssagen.InitTables`,
it calls `noder.LoadPackage(flag.Args())`; that function unconditionally calls
`base.Timer.Start`, whose append operation evaluates `time.Now`. Its bodyless
`time.runtimeNow` call requires selected linkage and an applicable frame. Treating
the time result as arbitrary does not establish that obtaining it preserves the
actual table reference/backing or the installed predicate values. The construction
postcondition supplies the map fact, not those earlier predicate assignments.

On the selected Linux/amd64 native path, the linked clock implementation obtains
the current thread state from machine context, writes runtime bookkeeping fields,
may switch to the runtime stack, and calls the target loaded from
`runtime.vdsoClockgettimeSym`; the alternative path invokes `clock_gettime`.
Passing no protected pointer does not exclude these ambient writes. A closed
source alias/escape analysis therefore cannot alone establish the required
preservation. The source model's custom simulation branches require checked
selection or coverage too; comments about their elimination are not evidence.
There is no demonstrated harmful table write here: this is a missing applicable
frame, including disjointness from protected storage and actual indirect-target
coverage. The existing native-frame contract keeps vDSO functions as selected
implementations, not primitives approved by their names or ABI.

At 5.1w.2b.3b.2a.2.5, use this boundary if the actual-artifact bridge requires
the compiler-origin route; historical-result retention alone does not require
it. Establish that consumer need at 9.4a.2 before expanding native prefixes.
A deciding positive must cover the complete selected clock
call's protected-state frame on stock and custom Go, composed with the actual
construction poststate and independently established predicate bindings. It must
cover every feasible native arm and derive required runtime/scratch separation;
an invented entry heap, syscall-only proof or synthetic safe leaf is insufficient.
Controls must reject protected writes without passed pointers, overlapping
scratch, callbacks redirecting predicates and missing or conflicting indirect
target evidence. Even a complete clock frame would leave the remaining
construction-to-use interval and compiler-source/executable association open.
No bounded complete application route is established by this source inventory.

The deciding acquisition experiment subsequently captured the initial auxiliary
vector, mappings and complete mapped vDSO bytes from separately owned stock and
custom compiler children stopped at successful exec. Both unmodified compilers
then completed a real compilation. The capture checked executable identity and
rejected a sibling child's PID, a different expected executable, a truncated
image and disagreement between the auxiliary-vector address and mapping base.
This establishes a practical private acquisition seam, not transparency of
tracing for arbitrary builds, historical producing applicability, or the target
of either later indirect call. The diagnostic compilation is not a replacement
for a producing compilation; a Go-cache hit may execute no compiler at all.

Applying the existing admission rules to those actual inputs exposes two
structural boundaries. First, the checked construction poststate owns a logical
map backing, while native storage admission covers ordinary scalar/aggregate
objects, not that map's native footprint. The selected map-valued global also
lacks an admitted storage representation. An address/extent proposal or geometry
certificate alone cannot establish that these bytes carry this logical map fact.
Normal-return poststates cannot be promoted through the complete-effect packet
gate to manufacture that association. Second, the captured vDSO is a dynamic
mapped image, while the native image checker admits static executable images.
Relaxing that format check would not supply loading, mutable kernel-data,
indirect-target, loop, timestamp-instruction or clock-syscall semantics.

The actual selected construction still passes on both compilers; the experimental
native-admission checks reproduce refusals, not complete clock-frame positives.
Within this compiler-origin candidate, the first refactoring obligation is the
checked association between a logical poststate and its native supporting storage,
with scope and ownership preserved. Establish that relation's complete application path before designing
a replacement storage interface. Dynamic-image acquisition and semantics remain
separate obligations. Runtime resolver execution, pointer/mapping preservation
through both target loads, the whole caller frame and the consuming theorem's
applicability are still missing. Neither decoding more clock instructions nor
retaining one observed mapped image closes those gaps. They remain at
5.1w.2b.3b.2a.2.5; this experiment does not reopen bootstrap-prefix expansion or
close the parent gate.

The runtime-context producer audit gives a concrete cutoff. The existing rooted
native fixtures establish the initial TLS/context/machine pointer writes and
carry them through the checked argument prefix to the unexecuted `sysargs` call.
These are numeric image/stack facts under retained entry premises, not a typed
ownership world at the compiler's timing call. No checked continuation crosses
that call and the later scheduler initialization, goroutine creation and
resumption to reach the required boundary. In the selected source, `execute`
assigns the running goroutine's machine link, and `gogo` installs TLS, R14 and
the saved stack pointer. The runtime stack's saved SP is established separately
by `mstart1`; newly allocated goroutine stacks come through `stackalloc`, and
reused goroutines retain their own lifetime obligations. Those source locations
identify candidate producers, not checked native facts. The main goroutine is
unlocked from its OS thread before the application main call, so initial
`g0`/`m0` identities cannot simply be carried forward as the compiler's current
context. A local checked ownership invariant could replace whole-bootstrap
replay, but its establishment and preservation producer is still missing. This
is a derivation obligation under the existing contract, not a reason to add an
ABI-correctness or runtime-isolation assumption.

A context-local ownership invariant is also insufficient. The selected
`stackalloc` cache-hit branch pops an unsafe numeric extent from a stack cache.
An entry model can have valid current context links and disjoint current stacks
while its free-list head overlaps protected map support. Checking the later
context assignments would not reject that model. This is a counterexample to
the proposed local induction, not a reachable corruption demonstrated in Go.
Excluding it requires allocation-instance ownership across acquisition, cache/pool
transfer, relocation and retirement: stack pools return spans to the heap,
retired machines release their runtime stacks, and GC can trigger stack shrinking.
A simultaneous resource invariant can keep map support abstract, but its base,
transition closure and actual source/native association must be checked. This
candidate remains subject to the actual consumer-need gate above; the historical
applicability correction grants none of its missing runtime facts.

The user selected existing test/benchmark workflows as the public acceptance
target when offered an opt-in Linux/amd64 traced scalar-call protocol. Native
entry and source/native relation checks remain useful subordinate mechanisms,
but a scalar-return fixture does not complete test, benchmark or environment
verification. Tracing may be investigated privately; a new public tracing or
program-build API, or a helper process on every cache hit, is not the selected
adoption path. Resolve actual ordinary-consumer coverage at 5.1w.2b.3b and retain
the useful-positive gates before admitting runtime reuse.

Profile cold preparation, repeated proofs and consumer-level serving costs under
the existing workflow. Compare the same accepted/refused populations; excluding
unsupported work or weakening a proof cannot be reported as an optimization.

The field report about go1.27.2-X:nodwarf5 lacks exact binary/library identities
and moved-key evidence. This architectural finding does not diagnose every
reported record or assert that an absent label alone prevents content matching.
