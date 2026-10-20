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
| Bound source/native facts to ordinary implementation authority | Complete actual-use, initialization, harness and selected-implementation coverage; establish claim-specific current applicability. Local callback or startup certificates cannot supply it. | 9.4a.1-2 qualify the route; 5.1w.2b.3 and 5.1w.2b.4d implement and consume it. |
| Inspected artifact to preparation | Admit immutable scoped claims and select residual obligations for the whole runnable roster before execution. | 5.1w.2b.4b/d |
| Prepared evidence to close | Validate each unit's dependencies and obligations without mutating its shared snapshot or borrowing sibling authority. | 5.1w.2b.4b |
| Producing theorem to current check | Retain sufficient historical evidence and check the applicable selection theorem and current dependencies. | 5.1w.2b.4c/d |
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
filesystem dependencies. Conversely, retaining yesterday's executable does not
prove a property of every implementation allowed by today's selection. A complete
artifact theorem, universal over its runtime states, needs a separately checked
selection-stability argument before it can authorize artifact-free current reuse.
That argument preserves the particular public proposition, not native addresses,
frame layouts or exact numerical equalities the proposition does not require.
The correct-cache premise in [runtime inputs](../specs/runtime-inputs.md) concerns
cache-state independence; it does not silently remove the implementation latitude
retained by [implementation verification](../specs/implementation-verification.md).

The target is one native record carrying sufficient immutable historical evidence
to check its claimed authority, with the existing disposable memos providing only
acceleration. A digest or stored approval bit is insufficient. Current checking
admits each record's own evidence against the freshly observed source/build,
selected-implementation, rule and applicability dependencies; it does not claim to
have inspected a new executable or repair missing producing facts. The original
executable's deletion and disposable-cache eviction must preserve a successfully
established selection-applicable claim. This requires an explicit evidence
contract before implementation; existing records acquire no such authority.

### Unestablished proof mechanism

Compiler-bootstrap execution is a chosen applicability construction, not a
requirement of the governing contract. Two legitimate mechanisms remain: prove
the relevant selected lowering association and use the existing implicit-language
premise, or independently prove the needed native behavior, including the slow
path. Matching call shapes, source proximity, labels or compiler metadata close
neither argument. The existing local native and source proofs establish neither
complete mechanism for the ordinary consumer yet.

The next work is therefore 9.4a.1's precise selection-applicability rule, followed
by 9.4a.2's complete lowering/native bridge and 9.4a.3's consumer-sized composition
qualification. The selected `testing.tRunner` stack-check/retry fragment is the
initial bridge candidate, not an approved helper or an assertion of feasibility.
If it needs a compiler-state invariant, name that invariant and its influencing
path before scheduling its smallest prerequisite. Do not presume that replaying
the compiler from ELF entry is necessary, or that calling the alternative
translation validation makes it complete. The existing continuation/history and
callee-replay costs require qualification against the same required population.
9.4a remains open until these results establish the bounded implementation path;
the lifecycle design and additional plan slots alone do not close it.

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
