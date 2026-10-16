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
