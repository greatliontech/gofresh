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
  preconditions at the relevant use. An effect-only interface may have no result
  locations or result bits; it does not invent a scalar output to represent
  completion, and retains its return and context-preservation obligations.
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

## Conditional native transitions

A native transition relates machine states at an entry and a declared cut before
the cut instruction executes. It is subordinate evidence for composing native
segments, not a return theorem, completed bootstrap or public invocation model.
An executable's declared entry identifies an input to this judgment; it does not
establish that a process actually entered there.

Transition expressions can also range over outcomes introduced by independently
checked primitive effects. Such outcomes are quantified possibilities, not
observations or replacement entry inputs. Their executed occurrences, selector
relations, identified semantics and applicability conditions remain explicit.

In an acyclic branching scope, instruction occurrences carry derived reach
conditions. Accesses and primitive effects inherit their instruction's condition;
filtering the retained order by those conditions gives the executed trace.
Listing a conditional occurrence does not assert that every execution performs it.
An optional primitive outcome has meaning only under that occurrence's condition.
Names reserved for inactive outcomes are mathematical totalizations, not produced
responses: varying them cannot change an active trace or final result.

Entry carry, zero and sign-XOR-overflow predicates may be retained as explicitly
bound arbitrary Boolean inputs for the supported conditional instructions. Their
architectural meanings and identities survive later flag overwrites; generated
slot numbers supply no substitute for that binding. These predicates imply no
separately observed sign, overflow, auxiliary-carry or parity value.

The ordinary x86-64 CPU-query model interprets the exact CPUID instruction at the
architectural machine layer identified by the transition. CPUID must be available
and enabled at the executing privilege level, with applicable faulting controls
disabled. Transactional or enclave contexts that substitute an abort or exception,
and layer-visible interception requiring an unproved handler, are outside this
model. Instruction mapping, isolation, debug and failure conditions remain
separate prerequisites. These are configuration predicates establishing the
ordinary successor, not an assumption that a particular query completed normally.

The query captures the low 32 bits of RAX and RCX before writing its results. Its
four independently unconstrained 32-bit outcomes replace EAX, EBX, ECX and EDX,
zero-extending into their full registers. Other general-purpose registers,
architectural flags and ordinary memory are unchanged. The ordered primitive event
retains architectural serialization; it supplies no latency, cache, TLB or host-state
claim. Independent outcomes over-approximate responses and establish no repeatability,
vendor identity, reserved-bit constraint or feature consistency across queries.
Even an overwritten result leaves its query and selector dependencies present.

This model admits native and ISA-conforming virtual processors. Implementation
mechanisms below the identified layer may include microcode or transparent VM exits;
their names or versions confer no authority. A layer-visible exception handler or
additional ordinary-memory effect needs its own checked composition. The model does
not establish actual process applicability or observe any CPU response.

**REQ-impl-native-transition** (invariant): An accepted conditional native
entry-to-cut transition MUST satisfy these obligations:

- **bound-scope** — The claim binds its immutable image, entry, cut, machine and
  inference rules, admissible entry states, memory conditions and interference
  exclusions. An executable-entry claim starts at the entry read from that image's
  executable format, rather than a substituted symbol or proposed start. All
  unspecified register bits, flags and memory remain arbitrary. Entry facts and
  their authority are retained separately from derived outputs; an expected output
  is not an input premise. Retained entry-flag predicates have explicit
  architectural meanings and unchanged identities across later overwrites.
  The image, instruction and machine applicability
  obligations of REQ-impl-native-entry remain required.
- **complete-cut** — The checker reconstructs every reachable instruction and
  successor before the cut from bound image bytes. It establishes the cut as a
  reachable instruction boundary and retains its decoded instruction separately
  as unexecuted boundary evidence. Every maximal path in the claimed scope reaches
  that cut; cycles require a checked finite-progress argument or refusal. A fault
  or unsupported transfer before the cut cannot be hidden by assuming normal
  completion. Applicable synchronous faults must be excluded by established
  premises. Proposed extents, symbol sizes, instruction counts and exhausted
  budgets never establish an endpoint. Calls, returns, indirect transfers and
  external effects require their actual rules and obligations or refusal, not a
  fabricated return or silently truncated successor inventory. Reach conditions
  derive from the actual bound predicate state; taken and fallthrough edges
  partition their incoming condition, and joins preserve their complete union.
  Graph closure alone cannot justify replacing a derived reach expression with
  true or excluding an arm. An excluded transfer requires independently checked
  impossibility under the retained premises; unresolved paths remain required.
- **symbolic-origins** — An address origin is universally quantified over its
  declared bounds, congruence and memory predicates, not a sampled runtime address.
  Pointer provenance identifies the origin and checked byte offset and agrees with
  the derived scalar value. Numerical equality alone supplies no provenance.
  Offset arithmetic and full access extents preserve canonical-address and
  nonwrapping conditions for every admissible origin. Alignment transfers derive
  their new offsets from the actual mask, origin congruence and operand semantics;
  they cannot use alignment of an invented concrete base. An address envelope
  grants neither access permission nor initial contents. One-past pointers may be
  represented but cannot authorize a read. Pointer-word provenance survives a
  memory round trip only through its complete correctly ordered bytes; partial or
  overlapping writes invalidate affected provenance.
- **state-and-effects** — The checker derives the claimed register, flag and
  byte-memory relations from exact operand forms and execution order. Instruction
  fetch and every data access remain accounted for, including writes whose final
  value happens to equal the old value. Memory outside the write footprint and
  claimed preserved context remain unchanged under the retained frame premises.
  Undefined flags stay undefined; omitting a flag value from a projection does not
  establish that the flag was preserved.
  Image zero-fill or source-language zero initialization supplies no initial
  native-memory value without its applicable initialization relation. Raw input
  words and pointer bytes acquire no argument, environment or Go-object meaning
  from a familiar address or symbol. Every non-entry outcome variable has an
  independently checked primitive-occurrence origin with explicit selector,
  semantics and applicability bindings; proposals cannot supply its value or
  authorize its introduction. Primitive effects remain distinct from ordinary
  data accesses and from observations, including when their results are overwritten.
  Conditional occurrences retain their derived instruction guards and execution
  order. Their guard and selectors precede their outcomes and depend on no outcome
  from that occurrence or a later one. Merged scalar and byte states preserve
  guard/value correlations; pointer, preservation and definedness claims must hold
  on every contributing path. Inactive outcome names cannot affect the filtered
  executed trace or the final state.
- **independent-evidence** — Candidate endpoints, instruction inventories and
  state relations are proposals. The checker validates their coverage, transfers,
  origin side conditions and dependencies independently of proposed conclusions.
  Cancellation, exhausted bounds, empty or inconsistent entry conditions, or any
  unclosed obligation yield no transition certificate. Evidence retains owned
  inputs and all image, interface, origin, rule and subordinate dependencies under
  REQ-impl-derivation-reuse; copying a projection grants no authority.
- **conditional-composition** — A successor transition starts at the checked cut
  under the same bound image and compatible origin, state, memory and machine
  premises. The cut instruction belongs to that successor's executed scope.
  Composition preserves original entry variables, prior primitive-outcome
  identities and the complete ordered effect dependencies. New occurrences have
  distinct outcome identities; neither a replacement entry state nor an unbound
  additional input can stand in for a checked primitive effect.
  The predecessor's cut must be a common boundary of every path being extended.
  Reconstructed prefix and suffix coverage exclude bypass, overlapping instruction
  decoding and re-entry into an executed prefix. Initial predicate identities,
  occurrence guards and the final reach expression remain retained dependencies;
  continuation does not restart reachability at an invented true condition or
  reset resource allowances per path.
  Origin names, matching output bytes or digests cannot replace this relation.
  The transition remains distinct from normal-return, complete-function,
  source-startup and completed-bootstrap evidence. Applying it to an ordinary
  process additionally establishes actual image/entry binding and the applicable
  process-entry layout and memory relation; no observed stack address is required
  when that relation establishes the symbolic premises. Numeric native storage
  still needs checked source-storage, representation and linkage correspondence
  before it can supply source state. The transition grants no historical execution
  authority, source-subject coverage or public runtime discharge.

## Conditional numeric source/native correspondence

Numeric correspondence relates a selected source computation to a bound native
entry. It is a subordinate all-input fact, not a result about a sampled execution
or a replacement for the existing test and benchmark result models.
An effect-only correspondence may have no scalar results and may admit a pointer
argument proved unused on both sides: no access through it or escape of it is
assumed harmless. The argument retains its typed interface and transfer relation;
absence of result bits does not remove effect or exceptional-outcome obligations.

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

## Conditional descriptor and callback transfer

**REQ-impl-callback-transfer** (invariant): A conditional readonly-descriptor or
callback-transfer claim MUST satisfy the following obligations in addition to
REQ-impl-native-entry. It composes the existing instruction and correspondence
rules, not a separate set of approved native callees.

- **descriptor-binding** — A readonly descriptor claim identifies its region,
  bounds, representation and context in the bound artifact's actual loaded-image
  mapping. Readability, non-writability and integrity for the claimed span are
  established under explicit loading and memory premises, including relevant
  aliases; section labels alone establish none of them. Address arithmetic,
  width, endianness, mapping ambiguity, file-backed and zero-fill bounds, and
  relevant relocations are accounted for or refused. The decoded target is bound
  to an admitted executable mapping and checked entry/interface; a wrapper at
  that entry retains its own obligations. Readonly descriptor bytes do not make
  a selecting registration header, row, backing array or other carrier readonly.
  Writable registration state requires its own mutation and use provenance.
- **decoded-transfer** — The claim retains the antecedent that the incoming
  value designates that descriptor with the stated region and context provenance.
  A supplied address or a matching descriptor word does not establish it.
  Independently checked actual load and call instructions establish the target,
  argument locations and interpretations, closure context, preserved frame and
  return/continuation relation. Coverage follows REQ-impl-native-entry through
  every successor and applicable nil or fault outcome within the stated scope;
  target and continuation instruction boundaries are established, not inferred
  from symbol extents. The callee's checked claim applies at the actual target
  with all its preconditions, and its returned state satisfies the continuation
  interface. Direct or devirtualized calls require the corresponding checked
  transfer. Unproved incoming provenance may remain an explicit condition of the
  local lemma, never a derived fact about a caller or registration use.
- **language-transport** — Under REQ-impl-premise-boundary, a checked transport
  relation may use faithful lowering of an identified source-language operation,
  such as function-value copying, aggregate selection, concrete interface
  dispatch, closure or goroutine argument capture, or defer/return. It binds the
  exact selected typed operation and context to the actual fragment, with its
  complete boundaries, continuations and logical-state/frame relation. Transport
  establishes which value is carried or invoked, not the selected target's
  semantics. Explicit calls and their selected replacements retain
  REQ-impl-build-selection and their own effect/frame obligations. Helper names,
  ABI labels and table/compiler metadata may locate candidate implementations;
  none establishes this association, provenance, coverage or a callee summary.
- **conditional-composition** — Isolation, stack-space, memory and frame
  restrictions remain explicit conditions. Applying a native lemma to an ordinary
  Go callback requires a checked relation showing that permitted implicit
  lowering and suspension/resumption preserve its logical state and account for
  relevant intervening effects; it cannot silently assume an isolated invocation
  or an ample stack. An unavailable transport or frame relation leaves that
  composition unsupported. A local descriptor/transfer fact alone establishes
  neither the selected generated main's actual registration-to-use chain nor
  harness scope preservation, noninterference or runtime applicability. Those
  obligations, producing/current evidence and existing test/benchmark result
  models remain governed by the existing contracts; this fact grants no public
  discharge and requires no new tracing or invocation protocol.

## Conditional source-region transport

**REQ-impl-region-transport** (invariant): An accepted source-region transport
claim MUST establish its stated construction-to-use relation under these
obligations, using the existing selection, independent-checking and composition
contracts:

- **bound-scope** — The claim binds the source owner's exact selected typed
  syntax and control-flow representation, source/build snapshot, specialization,
  roots and bounded call contexts. A registration claim identifies the actual
  selected main and initialization construction and the actual consuming call
  operand reached from it. Names, generated-file labels and metadata locate
  candidates only; a regenerated template or unused lookalike table supplies no
  use provenance. Entry-state premises, covered paths and terminal uses are
  explicit. Source selection establishes identity, not an effect bound, and a
  local transport scope cannot weaken a whole-startup claim's obligations.
- **inductive-transfer** — Proposed block-entry states and invariants are checked
  against the actual control-flow graph and typed operations. Every admitted
  initial state is included in the entry invariant; on every edge, the checked
  transfer of the predecessor invariant is included in the successor invariant.
  Inclusion means coverage of all represented concrete states, not agreement of
  proposal labels. This includes every backedge and the actual predecessor/value
  association of each phi, with path conditions and exceptional outcomes retained.
  Excluding an edge requires a checked argument. Loops and recursive contexts
  require inductive justification at their boundaries, not finite unrolling or
  mutually assumed summaries. The invariant at each claimed use entails the
  claimed operand relation. Unsupported transfers, unclosed invariants, exhausted
  bounds or cancellation yield no partial positive certificate.
- **memory-and-callables** — The finite typed region model distinguishes selected
  globals, allocation sites with bounded context, closure environments, formal
  inputs and unknown memory; locations retain field/index paths and their possible
  overlaps. It distinguishes a singleton object from a summary of possibly many
  objects. Replacing an old location fact with a store's value requires a proven
  exact singleton target; possible aliases, summary objects and unknown indices
  require conservative updates retaining every possible old and new value at
  overlapping locations. Unknown writes invalidate affected facts unless their
  frame is justified. Repeated allocation at one site initializes the new object,
  not earlier escaped instances represented by the same summary. A callable
  retains its target together with its captured environment identity and value
  relation; target identity alone is insufficient. Aggregate transport preserves
  claim-relevant correlations, including each registration row's name/function
  pairing. Separate name and target sets cannot establish that pairing; lost
  correlation must widen the relation or refuse the dependent claim.
- **context-and-effects** — Calls bind actual arguments, receivers, captured
  environments and concrete interface values to the exact callee context.
  Preservation across a call requires a checked read/write/escape/callback and
  continuation relation, or an explicit retained premise. An unknown call cannot
  be modeled solely by an arbitrary return while preserving memory and excluding
  callbacks without justification. Language-defined copying and capture establish
  the values captured at the specified evaluation point, not stability of their
  reachable heap or completion of the invoked work. Goroutine and deferred calls
  retain their own execution, continuation and exceptional effects; concurrency
  or delayed mutation cannot disappear into a value-transport fact.
- **conditional-composition** — A local positive may relate registration
  construction to an actual consuming operand while retaining explicit imported
  initialization, intervening-frame, concurrency, callee, native and harness
  premises. It does not skip initialization side effects: an omitted phase's
  influence on the entry state or transported relation remains a premise whose
  applicability must be established before composition. Such a fact proves no
  whole-program registration coverage, callee behavior, harness noninterference
  or runtime applicability by itself. Native use still requires
  REQ-impl-callback-transfer and REQ-impl-build-selection. Evidence retains the
  checked relation, premises, source/context and subordinate dependencies under
  REQ-impl-derivation-reuse; no special function name supplies semantic authority.
  Existing result models and producing/current obligations remain in force, with
  no public discharge or tracing protocol supplied by this local relation.

## Conditional native frame bounds

**REQ-impl-native-frame** (invariant): A checked native read/write/frame claim
MUST derive its effect bound under REQ-impl-native-entry and the following
obligations. A frame specifies permitted accesses and preserved state, not merely
equality of memory before and after execution.

- **region-interface** — The interface identifies byte regions, their read/write
  permissions, extents, lifetimes and possible aliases or overlaps, together with
  the origins and allowed ranges of entry pointers in registers and stack memory,
  including the stack pointer. Access bounds include the full operand width and
  checked address arithmetic, overflow and alignment under the selected machine
  model. Required initial contents, protected return context and preserved logical
  context are explicit; unspecified state remains arbitrary. Code and data
  mappings, permissions, loading, relocation and dynamic target dependencies must
  support the claimed accesses under the identified model. Missing or unsupported
  mapping or loading semantics refuse the dependent claim.
- **instruction-effects** — Independent checking derives every reachable read,
  write, control transfer and fault effect from actual selected instructions,
  including implicit accesses and relevant atomic or ordering semantics. Every
  possible access is included in the claimed bound, with permissions and possible
  faults checked; permission to write a region does not establish its contents
  or disjointness from protected state. Stores invalidate overlapping value and
  pointer facts unless checked byte-level transfer re-establishes them. A stack
  spill/reload preserves provenance only through the actual stored and loaded
  bytes, widths, intervening writes and aliases. Unknown loaded pointers retain
  their uncertainty: treating them as scalar results cannot justify subsequent
  addressing, dispatch or heap stability. The decoded control-flow graph is
  covered under REQ-impl-native-entry; any proposed invariants include all admitted
  entry states and are preserved on every edge, including backedges. Finite unrolling,
  unclosed invariants, unsupported effects, exhausted bounds or cancellation
  provide no accepted prefix of a frame theorem.
- **calls-and-primitives** — Each call composes a separately checked callee frame
  at the actual target, arguments, context and continuation under
  REQ-impl-callback-transfer. Callee writes, escapes, callbacks and exceptional
  effects remain accounted for as required by REQ-impl-region-transport; an
  arbitrary return value is no substitute. Primitive external effects use only
  identified instruction-set or operating-system semantics under
  REQ-impl-premise-boundary, with exact argument and applicability preconditions.
  A syscall relation retains its reads, writes, partial effects, failures and
  nondeterministic outcomes, including effects before failure. Wrappers and vDSO
  functions remain selected implementations requiring derivation; names, hashes
  and ABI labels cannot turn them into primitive aliases. Unresolved dynamic
  targets or unavailable callee/primitive models leave the dependent frame
  unsupported.
- **composition-boundary** — A frame may retain explicit memory, isolation,
  stack and interference premises; applying it to ordinary Go execution still
  requires the checked lifting and suspension/resumption relation of
  REQ-impl-callback-transfer. The source-language implicit-lowering boundary is
  unchanged. Absence of writes outside the stated regions establishes neither
  value/outcome determinism nor harness relevance or noninterference. An unused
  clock result does not establish the clock implementation's frame. Whole-harness
  composition must separately establish the relevance/noninterference and
  value/outcome properties required by its claimed proposition and declared result
  model, and discharge the local premises. Complete dependencies and
  producing/current applicability remain
  required under REQ-impl-build-selection and REQ-impl-derivation-reuse; this
  subordinate theorem supplies no execution evidence, public result model or
  runtime-reuse discharge by itself.

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
