# Implementation verification

Implementation verification establishes particular semantic claims about the
implementation selected for a result. It does not prove arbitrary programs correct
or promise that every selected implementation can be verified. Its governing
contract is the soundness and authority boundary in [overview.md](overview.md) and
[evidence.md](evidence.md). [Closure](closure.md) defines the source and reachability
obligations; [runtime inputs](runtime-inputs.md) define producing observations;
[purity](purity.md) defines the independent assertion channels.

This document governs the semantic authority of implementation-dependent claims
throughout those analyses, including standard-library, runtime, harness and
module-dependency claims. A source inventory identifies what was selected. A
checked derivation establishes what that implementation permits the engine to
conclude. Neither function substitutes for the other.

## Claims and dependencies

**implementation claim** (term): a proposition about selected implementation
behavior needed by a freshness judgment, with an explicit scope and premises.
Examples include absence of an external input channel, a receiver-effect bound,
an observation coverage property, reliable observation delivery, or an operation's
outcome relation to guarded inputs. These are separate propositions even when
they concern the same implementation.

**implementation dependence identity** (term): the identity of all selected
implementation inputs on which a claim depends, including their membership,
content and relevant selection configuration. It identifies dependencies, not
their semantic properties or the truth of the claim.

**checked derivation** (term): evidence whose inference steps, premises and
dependency bindings a checker has validated against the selected implementation
and identified semantic rules. An accepted claim is conditional on the explicitly
retained premises; a proposed summary alone is not a checked derivation.

**REQ-impl-claim-scope** (invariant): Every accepted implementation claim MUST
identify its proposition, covered subjects or implementation scope, relevant
execution phase and model, dependencies, and all premises used. Composition
retains these bounds: a claim about one receiver, invocation, build selection or
phase cannot establish an unqualified property of its package or another run.
Its accepted-authority account distinguishes observed facts, checked derivations
and attributable assertions under REQ-fresh-authority-account.

**REQ-impl-dependence-identity** (invariant): Implementation dependence identity
MUST cover every input that can change the claimed fact, transitively, including
implementation bodies, data, initialization, generated and embedded inputs,
linkage, relevant instrumentation and native dependencies. A sound
over-approximation is permitted. Sharing an inventory does not permit a claim
to omit a dependency outside that inventory. Missing or conflicting dependency
evidence prevents accepting the dependent claim. Equality of complete identities
establishes input agreement alone, never semantic authority.

**REQ-impl-build-selection** (invariant): The implementation described by a
claim MUST be the implementation selected by the actual effective build under
the coherent-view and producing-binding contracts. Selection includes applicable
platform, architecture, tags, experiments, cgo, race or other instrumentation,
module and toolchain resolution, and their generated or linked inputs. Source
available in a distribution but not selected into that build cannot justify it.
The claim's inventory must agree with the actual subject graph, including
implicitly linked dependencies; discovery over a default package set alone is
insufficient. An unavailable selection yields no claim about substitute bytes.

Compiler substitution and lowering belong to this binding. A selected Go body
may be only a fallback for an intrinsic or a runtime-selected implementation;
proving that body's effect bound does not establish the executed operation's
bound. Before a source-derived claim authorizes runtime reuse, checked evidence
must cover the selected replacement, fallback and dispatch conditions, or
establish that the source claim applies to every selected implementation.
Relevant CPU-feature or runtime-configuration inputs remain dependencies even
when nominal source and compilation flags agree. A compiler report identifying
a substitution is discovery data, not proof of its semantic properties.

## Semantic authority

**REQ-impl-no-approval-registry** (invariant): Semantic acceptance MUST NOT be
selected by a registry of approved implementation names, versions, flavors,
packages, symbols, generated-file labels or content digests. Those values may
locate and identify inputs; none is a proof of their behavior. A previously
reviewed implementation cannot confer its conclusions on selected source by
approval membership. The same generic semantic rules apply to first-party,
dependency, standard-library and runtime implementations; a source change is
judged by those rules rather than requiring a new approval entry.

**REQ-impl-compositional-derivation** (invariant): An implementation claim MUST
follow from the selected implementation through checked semantic inference and
composition of independently justified subordinate claims. Every subordinate
claim must establish the property its consumer uses under premises that hold at
that use. Callbacks, dynamic dispatch, aliases, shared state, initialization,
concurrency and exceptional control flow must be covered whenever they can
affect the proposition. Recursion requires a justified inductive or fixed-point
argument, never a cycle of mutually assumed conclusions. An unreachable or
irrelevant implementation fragment may be excluded only by a checked argument
establishing that exclusion for the claim's scope.

**REQ-impl-premise-boundary** (invariant): A derivation MUST expose the minimal
language, machine, primitive-effect, compiler/linker and executor premises on which it relies, without
enlarging those existing model premises into trust in library or native
implementation behavior. The existing compiler/linker-correctness and
toolchain-mediated-cache-integrity premises permit interpreting the selected
program under the identified language semantics, including faithful lowering
of implicit language operations. Foundational instruction-set and primitive
external-effect semantics are the machine model already required to execute
the verifier and observe files or processes, not an approval of selected
library implementations. Every use identifies the relevant model, configuration
and applicability conditions. The executor remains
responsible for truthful build and execution bindings, declared scope and
hold-still spans. Neither premise establishes an unproved standard-library,
runtime, harness, intrinsic or foreign-operation summary. Every additional
semantic conclusion requires checked derivation; every applicable caller
assertion retains its separate named authority and cannot become a derived fact.

Language-defined operations may be interpreted under their language contract.
That contract's nondeterminism, implementation latitude and exceptional outcomes
remain in the model. A native derivation interprets the actual selected
instructions under an identified instruction-set model, including relevant
machine state, faults, memory behavior and nondeterminism. Primitive external
effects retain their possible inputs, outputs, failures and partial effects;
a syscall relation alone does not establish that its outcomes follow from a
guarded value. That stronger relation requires its own checked argument and
execution premises. An operation cannot become a primitive merely by being
named, hashed or given a handwritten summary. A library or runtime routine,
syscall wrapper, hook or compiler-specific intrinsic with behavior beyond the
language premise requires its own checked implementation derivation. An explicit
source call to such a routine is not an implicit language operation merely
because the compiler also uses it when lowering language constructs.
Compiler correctness does not assert equivalence between an intrinsic and an
arbitrarily edited library fallback, nor discharge the selected dispatch's
runtime inputs. Such equivalence or irrelevance requires checked evidence under
REQ-impl-build-selection. Changing the requested compilation to avoid a proof
obligation changes the producing description and requires the result owner's
explicit selection; it cannot silently justify the originally requested build.

These foundations permit particular proofs, not universal verification of a
machine or its environment. A proof retains the declared result model's
scheduling, timing and termination limits; an effect bound does not establish
deterministic timing, termination or identical future execution. A missing or
inapplicable machine model leaves the dependent claim unsupported.

**REQ-impl-opaque-leaves** (invariant): A reachable implementation boundary whose
semantics are needed for a claim but lack a checked derivation or an applicable
foundational premise under REQ-impl-premise-boundary MUST leave that claim unsupported. This includes
native code, foreign calls, unresolved linkage and opaque runtime or
instrumentation behavior. An interface description, matching hash, package
origin or handwritten behavioral summary cannot discharge the boundary. A
checked derivation may establish that the boundary cannot affect the particular
claim; merely failing to observe an effect cannot establish that exclusion.

## Independent checking

**REQ-impl-independent-check** (invariant): Positive semantic authority MUST
come from checking a proposed derivation against identified rules and its bound
inputs, independently of the proposer's asserted conclusions. The checker must
validate each inference and its prerequisites, the claimed source selection and
dependency coverage, and the applicability of any subordinate evidence. It must
not accept an effect classification, reachability exclusion or summary merely
because the analysis proposing the claim reports it. Reusing the same unchecked
conclusion through another representation is not independent checking.

This boundary does not require a particular process arrangement or language
representation. The checker and its admitted inference rules are part of the
verification mechanism whose correctness the engine owes; naming them does not
turn arbitrary implementation summaries into trusted axioms. Checkable evidence
identifies enough of its inputs and reasoning to repeat this judgment without
trusting the proposing analysis's final answer. An unrecognized rule, missing
step, unsatisfied side condition or incomplete input binding grants no proof.

**REQ-impl-claim-refusal** (behavior): A failed or unavailable premise MUST
refuse the claim that depends on it and every conclusion requiring that claim,
with the failed premise and dependency path exposed as structured facts.
Independent claims retain their own judgments. An incomplete search, exhausted
budget or unsupported semantic operation is absence of proof, not proof that
the property is false. Demonstrated source or guard drift retains its ordinary
stale disposition; an unsupported optional refinement cannot erase that drift.
Cancellation obeys REQ-fresh-context and supplies no partial positive proof.

## Conditional native-entry derivations

A native-entry derivation is a conditional implementation fact about execution
from one identified entry under an explicit machine interface. It is subordinate
evidence under the existing claim and authority contracts, not a new invocation
result model. The inspected artifact of REQ-fresh-inspected-artifact supplies
observed inputs; inspection alone establishes none of the following semantics.

**REQ-impl-native-entry** (invariant): An accepted native-entry derivation MUST
establish its stated value, dependence or effect bound under these obligations:

- **bound-interface** — The claim identifies the observed artifact and immutable
  bytes it describes, the entry within its executable image, the machine model
  and rule identities, and the entry/return interface. The interface specifies
  input and output locations, bit widths and value interpretation, required
  preserved context, and all preconditions. Unspecified entry registers, bits,
  flags and scratch state remain arbitrary. An ABI name or document interprets
  an interface; it does not establish that an actual caller obeys it. Applying
  the conditional claim later requires establishing that interface and its
  preconditions at the relevant use.
- **machine-applicability** — Instruction-set mode, feature requirements,
  applicable address and memory semantics, valid code mappings and code-integrity
  premises are explicit. Faults, undefined results and nondeterminism remain in
  the model unless a justified precondition excludes them. Assumptions about
  asynchronous interference, scheduling, external termination or protected
  execution context are exposed, not inferred from successful sample executions.
  Foundational instruction and primitive-effect semantics follow
  REQ-impl-premise-boundary; decoding an instruction form under those rules is
  distinct from approving a native function by name or handwritten summary.
- **image-binding** — Instruction bytes come from the bound artifact's actual
  executable-image mapping, with bounds, address arithmetic and mapping ambiguity
  checked. Claim-relevant relocation, loading and non-file-backed content are
  accounted for or refused, never replaced with convenient file bytes. Symbols,
  debug tables, compiler reports and proposed extents can locate candidates but
  cannot establish entry applicability, instruction boundaries or proof coverage.
  Changing that metadata cannot supply missing instruction evidence.
- **reachable-coverage** — Starting at the bound entry, the checker establishes
  actual instruction boundaries and every reachable successor from decoded bytes.
  Fallthrough, both conditional successors, call targets and continuations, returns
  and applicable fault outcomes are accounted for. Omitting a path requires a
  checked argument under the declared preconditions. A symbol-size limit, debug
  range, proposed block list or byte budget is never a successful stopping rule.
  Truncated or unavailable bytes, incompatible overlapping decodes, a transfer
  into an unestablished instruction boundary, unresolved successors, unsupported
  operations or exhausted exploration leave the dependent claim unsupported.
  A bounded checker may refuse cycles or other unsupported control flow, but
  cannot omit their paths. Cancellation supplies no partial positive derivation.
- **state-transfer** — Checked transfers preserve the selected instruction's
  actual operand order, addressing form, widths, register aliases, partial-write
  preservation or extension, modular arithmetic and defined or undefined flag
  behavior. A familiar mnemonic cannot authorize an unchecked operand form or
  turn a memory access into register computation. Output projection uses exactly
  the declared result bits: a narrow result does not imply canonical values in
  the rest of its register. An input-dependence claim establishes its bound for
  every admissible entry state, including arbitrary scratch state; undeclared
  incoming values or undefined flags cannot silently become initialized inputs.
  An effect-only claim still checks the transfers and path facts its effect
  bound needs; an accepted instruction inventory alone proves no value relation.
- **effects-and-return** — The claim states exactly which effects and outcomes
  it bounds. An absence-of-ordinary-data-access or call claim does not erase
  instruction fetch or the return mechanism's effects and faults. A return may
  end the scoped path only under the explicit continuation interface, including
  any required valid protected return slot and preservation of caller context.
  That slot's contents are control context, not an implicit scalar input to a
  value computation. Other data accesses, calls, wrappers and runtime helpers
  need their own checked accounting or refusal; a successful run or familiar
  callee name cannot hide a slow path. The returned state must satisfy every
  projected result, dependence and context-preservation property actually claimed.
- **independent-evidence** — A proposer may supply candidate entries, mappings,
  paths or state relations. Under REQ-impl-independent-check the checker
  re-derives reachable coverage and validates transfers against the actual bound
  bytes and identified semantic rules, rather than accepting the proposer's
  conclusions or a disassembly listing as premises. Evidence retains immutable
  input ownership and the complete artifact, interface, model, rule and
  subordinate-claim dependencies required by REQ-impl-derivation-reuse.
- **composition-boundary** — The accepted fact grants only its conditional
  native-entry proposition. An effect or input-dependence bound does not establish
  equivalence to a source value specification, execution of that entry, termination,
  timing behavior or a whole-process property. It does not cover surrounding
  dispatch, startup, other lowering choices or inline instances merely because
  they share a source name. Ordinary source-subject reuse still requires the
  independently checked correspondence and complete implementation coverage of
  REQ-impl-build-selection, together with its producing/current evidence and
  ordinary guards. This derivation alone selects no public invocation result
  model, supplies no historical execution authority and discharges no maximal-tier
  blocker.

## Conditional numeric source/native correspondence

Numeric correspondence relates a selected source computation to a bound native
entry. It is a subordinate all-input fact, not a result about a sampled execution
or a replacement for the existing test and benchmark result models.

**REQ-impl-numeric-correspondence** (invariant): An accepted conditional numeric
source/native relation MUST satisfy these obligations:

- **bound-scope** — The source side identifies the exact selected typed root,
  specialization and call context, its owning source/build snapshot, language
  semantics, and argument/result interpretations. Architecture-dependent word
  widths come from that build, not the verifier host. Every substituted source
  callee belongs to the same coherent selection with its exact context and
  dependencies. The native side identifies the immutable observed image, entry,
  machine model and checked interface of REQ-impl-native-entry. The relation
  explicitly maps source arguments to native inputs and source results to the
  projected native output bits, retaining all preconditions and preserved-context
  obligations. Matching names or digests cannot replace these bindings.
- **all-input-relation** — The checked proposition relates typed scalar values,
  effects and exceptional outcomes for every admitted input and every admissible
  native entry state, including arbitrary unspecified scratch bits and flags.
  Signed interpretation and narrow result projection remain distinct from
  unspecified high register bits. Equality of returned values alone cannot erase
  a source hook, discarded call, other effect or exceptional path. Completion and
  machine premises remain explicit; a normal-return premise cannot silently
  dispose of behavior the claimed relation must cover. Sample agreement, a native
  input-dependence bound or independent effect-free classifications do not prove
  this relation. Two pure computations with the same interface qualify only if
  their typed values and the other claimed behaviors actually correspond; the
  proposition is semantic, not equality of declaration names.
- **control-and-calls** — Coverage includes every source and native branch and
  terminal path within the bound scopes. A merged source value, including a phi,
  uses its actual predecessor and path condition; an omitted branch requires a
  checked exclusion. Call substitution preserves argument binding, the callee's
  value relation, effects, exceptional behavior and continuation under the exact
  context. A default source body, unchecked purity flag or separately proved
  fallback cannot stand in for a selected intrinsic, dispatch or native instance.
  Inlining within the checked entry may be related without a surviving call, but
  only through checked semantics of that actual entry. The relation covers no
  other inline copy or implementation instance by implication.
- **checked-equality** — Proposed equalities or rewrites are checked locally
  against identified source and native semantics under REQ-impl-independent-check.
  Each inference establishes its width, overflow or modular-wrap, signedness,
  range and path side conditions where relevant; arithmetic normalization cannot
  replace a partial or exceptional operation with an unjustified total one.
  Native transfers retain the instruction semantics of REQ-impl-native-entry.
  A bounded arithmetic rewrite calculus may establish equality, but a proposed
  equivalent-expression flag, matching hash or unverified expected result is no
  inference rule. Unclosed control or call cycles, incomplete path relations,
  unsupported operations, unproved equality, exhausted budgets or cancellation
  produce no positive correspondence certificate. No bounded prefix is treated
  as the complete computation.
- **certificate-authority** — The certificate retains the source root, contexts,
  typed output projections, native image and interface, preconditions, proved
  value/effect/exception relation and preserved-context relation, with their
  complete dependencies and rule identities. Reuse follows
  REQ-impl-derivation-reuse. Observed source and artifact inputs, derived relations
  and attributable executor assertions remain distinguishable; neither possession
  of the certificate nor an interface description authenticates actual invocation.
- **composition-boundary** — A function-local relation may leave initialization,
  actual-use linkage, surrounding dispatch and harness obligations explicitly
  open. It cannot remove those obligations from whole-source effect checking or
  supply ordinary source-subject implementation coverage. Source-only reasoning
  remains independent of observation support under REQ-impl-authority-channels;
  a selected observation obligation is not discharged by correspondence. This
  certificate introduces no public result model or invocation protocol, proves
  no general termination or timing property, and grants no maximal-tier discharge.
  Ordinary runtime reuse still requires the complete coverage of
  REQ-impl-build-selection and separately established producing, current and
  historical applicability evidence under the existing result model.

## Observation obligations

**REQ-impl-observation-claims** (invariant): Observation-based support MUST
establish independently the claims it uses about coverage, delivery and outcome
binding. Coverage establishes that every behavior-relevant effect within the
claimed scope is represented with the required information, including relevant
initialization, cleanup and concurrent execution. Delivery establishes that a
required record reaches the finalized observation or that loss prevents
supported completion, including buffering, flush and error paths. Outcome
binding establishes that every behavior-relevant operation outcome is determined
by the guarded state and declared premises, or is otherwise accounted for by
the admitted outcome method. Return values, errors, partial effects and
exceptional outcomes are included when relevant. No one of these claims implies
either of the others.

**REQ-impl-observation-execution** (invariant): Checked implementation claims
about an observation mechanism MUST remain separate from the evidence that the
particular contributing executions used that mechanism and satisfied its
premises. The producing obligations, completion receipts, contributor roster,
actual environment, capture bindings and span protection remain required under
REQ-inputs-producer-premises and the unit contracts. A successful process, empty
log or matching digest supplies none of the missing semantic claims; a static
derivation supplies no historical execution receipt.

**REQ-impl-authority-channels** (invariant): Implementation verification MUST
apply only to the claims a result's selected evidence channel requires.
Source-only freshness and source-derived certificates retain their own
dependency and soundness obligations without acquiring an operation-outcome
proof requirement. Identity-only observations retain their guard authority
without becoming supported observations. Explicit purity, externality,
execution-model assertions and vouches keep their specified scope, precedence
and attribution; none is silently derived or promoted into implementation
proof. An assertion can discharge only the obligation its own rule authorizes,
and cannot override demonstrated guard drift.

## Reuse and history

**REQ-impl-derivation-reuse** (invariant): Reusing a checked derivation MUST
require agreement of its complete dependencies, premises and recognized rule
semantics. Cold derivation and warm reuse must establish the same claim under
the same authority. A cache may reuse checked subordinate evidence or the
completed check when those dependencies still hold; otherwise it must rerun or
recheck the affected derivation, or report it unavailable. Cache acceptance must
not depend on approval-registry membership. Rule identity, semantic
compatibility, dependency identity and cache representation remain distinct
under REQ-fresh-dependency-identities. Integrity commitments alone cannot supply
omitted reasoning or authenticate a substituted cache payload.

**REQ-impl-historical-authority** (invariant): Historical records MUST retain
their original producing identity, dependencies and authority. Evidence admitted
under an older approval or proof policy gains no implementation-verification
authority from decoding, matching current source, assigning a new policy identity
or running a present analysis. A recognized compatibility judgment may preserve
only claims whose required producing evidence and semantic justification it
actually establishes. Missing historical premises remain missing; new execution
produces new evidence. Unsupported historical proof does not revoke independent
source-only or explicit assertion authority, nor bypass any failing guard.

These obligations specify the meaning and checkability of evidence, not a new
wire encoding or a requirement to persist every intermediate proof step. A
published representation must be capable of establishing the authority claimed
for it; a representation unable to do so cannot advertise that authority.
