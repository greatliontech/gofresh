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

Implementation coverage follows the claim's scope. A selection-wide source claim
must cover the implementations it ranges over. Retaining a complete proof about
the actual historical artifact for its original execution result instead follows
REQ-fresh-historical-implementation in [evidence.md](evidence.md); it does not
transfer that proof to an uninspected rebuild. Every relevant implementation and
dispatch arm within the historical claim still requires coverage, and a new
production needs its own bound admission. This distinction supplies no missing
source/native correspondence or runtime-selector evidence.

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
execution premises. This does not require inventing outcomes absent from the
identified primitive: an exact argument/outcome relation may establish a unique
result once its argument and applicability conditions are checked. Success is
then a derived consequence, not an additional entry assumption or a rule for
arbitrary syscalls. An operation cannot become a primitive merely by being
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

In an acyclic branching scope of dynamic activations, instruction occurrences
carry derived reach conditions. Accesses and primitive effects inherit their
instruction's condition; filtering the retained order by those conditions gives
the executed trace.
Listing a conditional occurrence does not assert that every execution performs it.
An optional primitive outcome has meaning only under that occurrence's condition.
Names reserved for inactive outcomes are mathematical totalizations, not produced
responses: varying them cannot change an active trace or final result.

Entry carry, zero and sign-XOR-overflow predicates may be retained as explicitly
bound arbitrary Boolean inputs for the supported conditional instructions. Their
architectural meanings and identities survive later flag overwrites; generated
slot numbers supply no substitute for that binding. These predicates imply no
separately observed sign, overflow, auxiliary-carry or parity value.

The direction flag has a separate arbitrary Boolean entry value; an ABI name or
an assumed normal call supplies no clear-direction fact. CLD clears that flag
without changing arithmetic flags, registers or ordinary memory. Its current
value follows the actual path through joins, calls, continuations and return,
retaining the original input identity. Composition associates a callee's entry
direction with the caller's actual current direction rather than introducing a
fresh value. Other admitted operations preserve it unless their identified
semantics state otherwise. The instruction definition is the CLD entry in the
[Intel instruction-set manual](https://intel.github.io/SDM/sdm.html).

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

An optional ordinary legacy-SSE2 model requires available and enabled SSE/SSE2,
an execution context in which the selected instructions do not cause device-not-
available or invalid-opcode faults, and stable architectural vector and floating
control state under the retained interference conditions. It grants no AVX or
floating arithmetic semantics. Scalar memory loads into XMM registers read exactly
four or eight bytes, copy their bit patterns without numerical conversion, and
zero the remaining bits of that 128-bit destination. Legacy encodings preserve
the higher architectural vector state. Unspecified initial XMM bits remain
arbitrary and retain their identities across branches, calls and continuations.

An admitted legacy register-to-register XORPS computes the bitwise exclusive OR
of both complete incoming 128-bit operands and replaces only that destination's
low 128 bits. Overlapping operands use their values before the write; equal
operands therefore clear the complete destination. This is a bit operation, not
a floating comparison or conversion: all bit patterns are admitted without a
floating exception or status change. It preserves arithmetic and direction
flags, ordinary memory, floating control/status and higher architectural vector
state. Its encoding and operand form remain checked, and its SSE applicability
is the same explicit machine premise as other admitted legacy SSE operations.
The instruction definition is the XORPS entry in the Intel instruction-set manual.

Unordered scalar comparisons interpret the low binary32 or binary64 operands.
The supported no-floating-exception relation must establish from the actual
incoming values that neither operand is a signaling NaN or a nonzero subnormal.
This is a checked operand condition, not an assumed normal successor. Quiet NaNs,
infinities, normal values and both signed zeros are admitted. An unordered result
sets carry, zero and parity; an ordered less-than result sets only carry; ordered
equality sets only zero, with the two zeros comparing equal; ordered greater-than
clears all three. Overflow, sign and auxiliary carry are cleared. The comparison
changes neither operand nor floating status/control state. The retained rounding,
exception-mask and flush controls need no fixed values for this operand domain.
A feasible excluded operand class refuses this bounded relation instead of erasing
its possible exception or status effect. A parity branch consumes its actual
defined parity value, never an invented independent input after a comparison.
The instruction definitions are the MOVSS, MOVSD, UCOMISS and UCOMISD entries
and SIMD exception rules in the [Intel instruction-set manual](https://intel.github.io/SDM/sdm.html);
these define machine semantics, not approval of a selected library or compiler.

Ordinary register increment computes its operand-width modular sum with one and
derives overflow, auxiliary carry, sign, zero and parity from that addition. It
preserves the actual incoming carry state, including its definedness and value.
Subtract-with-borrow captures both incoming operands and the current defined carry
before any destination write. It computes their operand-width modular difference
minus that carry. Carry records unsigned borrow, auxiliary carry records low-nibble
borrow, and overflow uses the original operand signs and final result sign.
A prior entry carry cannot replace a current carry changed by intervening work.
Scalar register AND computes the bitwise conjunction, clears carry and overflow,
derives sign, zero and parity, and leaves auxiliary carry undefined. A written
32-bit general-purpose destination zeroes its upper half.

An ordinary 32-bit register left shift by CL captures the incoming count even
when the destination overlaps the count register. The effective count is the low
five bits; the result is the low 32 bits of the shifted value, with the destination's
upper 32 bits cleared even for effective count zero. Effective zero preserves all
incoming arithmetic flags. Otherwise carry is the last bit shifted out, sign,
zero and parity describe the result, and auxiliary carry is undefined. Overflow
is defined only for effective count one, as result sign XOR carry; for larger
counts it is undefined. A flag is guaranteed defined only across the complete
represented incoming scope. A mixture of defined and undefined cases cannot be
reported as guaranteed defined; lack of that guarantee does not assert that every
case is undefined. Available combined predicates remain distinct from individual
flag projections. Count-dependent guarantees require checked incoming-path
implications, retaining the same original inputs and cumulative proof account;
no unavailable old flag or predicate is replaced by a fresh input.

An ordinary x86-64 locked 32- or 64-bit memory compare/exchange is an architectural
read/modify/write occurrence. It reads the current four or eight destination bytes
and compares their unsigned bit pattern with incoming EAX or RAX. Equality writes
the incoming matching-width source-register value to the destination and leaves
the full RAX unchanged; inequality writes the read value back to the destination
and replaces EAX or RAX with that value. A 32-bit failure zero-extends the loaded
EAX into RAX; a 32-bit success preserves the incoming high RAX bits. The operand-
width subtraction of the original destination from the incoming accumulator
defines CF, PF, AF, ZF, SF and OF in both arms; other flags remain unchanged. The
failure arm retains its write cycle and write-permission obligation even though
the destination bytes are unchanged.
The lock prefix belongs to that instruction, not a separate executed operation.
The occurrence retains its indivisible memory operation and architectural locked
ordering with respect to memory operations; it is not reduced to an ordinary
conditional store. An isolated-prefix theorem records this ordering without
establishing a concurrent library's history, language-level synchronization,
global execution schedule or timing property.

An ordinary locked byte AND or OR reads and writes exactly one byte. Its result
is the corresponding bitwise operation on the incoming destination and selected
byte-register or immediate operand. It clears carry and overflow, derives zero,
sign and parity from the byte result, and leaves auxiliary carry undefined.
The register operand is not written. Even unchanged-byte results retain the
write, write permission and indivisible read/write ordering occurrence. Atomic
effect evidence identifies the actual operation and width; a narrower operation
cannot supply a wider source relation through a shared operation name.

Applicability requires the exact supported memory form, full-width canonical
nonwrapping extent, read and write permissions, and ordinary coherent RAM under
the retained mapping, alias and interference conditions. Alignment and applicable
lock-fault controls must establish the ordinary successor, including split/bus-lock
and transactional restrictions where relevant; assuming that the operation
completed normally is insufficient. A register destination, unsupported prefix,
width or address form gains no locked-memory semantics. Natural operand alignment
and a power-of-two cache line of at least eight bytes establish no page/cache-line
split for the supported one-, four- and eight-byte forms. Missing applicability
refuses an executed occurrence. Every read/write and ordering occurrence survives
later result overwrites and composition. Byte condition-code stores write exactly
zero or one according to their actual defined flag predicate, change no flags,
and write only their selected byte; other register bits or memory bytes remain
as derived, not implicitly zeroed. A byte TEST reads precisely its operand bytes:
their bitwise conjunction sets SF, ZF and PF, clears CF and OF, leaves AF undefined
and preserves other flags without writing its operands. Wider tests require
their wider incoming-bit facts independently.

The ordinary Linux x86-64 `ARCH_SET_FS` primitive relates a decoded native
`SYSCALL` occurrence to the executing thread's effective FS base. Its scope
identifies native 64-bit syscall dispatch: the low 32 bits of RAX select syscall
158, the low 32 bits of RDI select operation `0x1002`, and RSI carries the unsigned
64-bit base. It identifies the applicable user-address ceiling and conventional
architectural SYSCALL entry with SYSRET/IRET user return; alternative entry
mechanisms require their own relation. Compatibility or x32 dispatch, unsupported
selectors and unavailable applicability do not acquire this relation. User-mode
FSGSBASE availability is not a prerequisite for this operating-system operation.
The scope excludes behavior-changing seccomp, ptrace, syscall-user-dispatch,
probe and signal interposition over the occurrence and any interval relying on
the established thread state. Transparent scheduling and virtual-machine handling
that preserve the exposed state are permitted. Debug, exceptional return and
other machine-context conditions must be covered or explicitly excluded under
the machine model; a premise that the syscall succeeded is not applicability.
Other entry/return work, including restartable-sequence handling, is admitted
only if it preserves the stated exposed-state relation or has its own checked
composition.

For the unsigned scalar base argument below the applicable `TASK_SIZE_MAX`, the
operation returns raw RAX zero and establishes that base as the current thread's
effective FS base. It neither dereferences that argument nor allocates user
storage, and has no allocation, user-memory-access or interruptible-wait failure
in this arm. An argument at or above the ceiling returns raw `-EPERM` and leaves
the effective FS base unchanged. These are the permitted operation outcomes
under the stated applicability, not libc's return/errno convention or arbitrary
64-bit responses. The ceiling is part of the identified configuration; for the
ordinary 4-KiB, 48- and 57-bit address configurations it is respectively
`2^47 - 4096` and `2^56 - 4096`. Argument validity alone establishes neither
mapping nor permission for a later access through the base.

The composed syscall entry/return relation retains the decoded next instruction
address in RCX and the incoming architectural RFLAGS with RF cleared in R11.
Under an ordinary 64-bit user-return context with valid architectural flag bits
and no virtual-8086, nested-task or single-step return condition, returned RFLAGS
are those saved flags with the architectural reserved-bit normalization; in
particular carry, zero, sign, overflow, parity, auxiliary carry and direction
are preserved, and RF is cleared. General-purpose registers other than RAX,
RCX and R11, including RSP, are preserved. Control returns to the decoded
successor in the same thread's 64-bit user mode with the native user CS/SS of
the identified entry/return configuration, not arbitrary incoming selectors
assumed preserved. Ordinary user byte-memory is
unchanged by this operation; its kernel/thread-state effect is retained
separately. These conclusions concern the complete applicable entry/dispatch/
return primitive, not the hardware `SYSCALL` instruction alone.

An effective FS base is distinct from an FS selector or a kernel bookkeeping
field. The primitive permits implementations using a segment descriptor or a
base-register update; success asserts neither a zero selector nor equality of a
particular kernel field to the base. Selector or other context outputs not fixed
by the identified relation remain constrained only by that relation, with checked
occurrence origins for genuinely unspecified values. They are not silently
preserved, reset to zero or inferred from a projected output's absence. Failure
retains the prior FS state. Neither arm changes another thread's FS state or
establishes a language-level TLS object.

The interface is described by [arch_prctl(2)](https://man7.org/linux/man-pages/man2/arch_prctl.2.html).
Source locators for the operation and its composition include Linux
[process_64.c](https://github.com/torvalds/linux/blob/v6.18/arch/x86/kernel/process_64.c),
[page_64.h](https://github.com/torvalds/linux/blob/v6.18/arch/x86/include/asm/page_64.h),
[fsgsbase.h](https://github.com/torvalds/linux/blob/v6.18/arch/x86/include/asm/fsgsbase.h),
[entry_64.S](https://github.com/torvalds/linux/blob/v6.18/arch/x86/entry/entry_64.S),
[syscall_64.c](https://github.com/torvalds/linux/blob/v6.18/arch/x86/entry/syscall_64.c)
and [syscall-common.c](https://github.com/torvalds/linux/blob/v6.18/kernel/entry/syscall-common.c).
The [descriptor-backed path](https://github.com/torvalds/linux/blob/v4.4/arch/x86/kernel/process_64.c)
also illustrates why effective base and selector are distinct. These locate
semantic definitions, not approved kernel versions or evidence that an actual
execution satisfies the primitive's applicability conditions.

A restricted static-ELF root-loading relation may refine declared image storage.
It is a partial relation over the same owned ELF64 little-endian x86-64 image,
with static addresses, zero load bias and the identified 4-KiB mapping semantics.
For checked file-backed logical bytes it supplies the corresponding owned file
bytes. For checked readable, writable, non-executable zero-fill ranges it supplies
zeros. Unsupported initialization ranges remain arbitrary; an unrelated readonly
zero-fill tail does not invalidate justified facts for an independent range.
The relation does not use section names, symbol names, kernel-version labels or
content approval as initialization authority.

Known-value coverage requires checked logical extents, file bounds, permissions,
mapping operations and backing independence. Page prefixes, padding and gaps
provide no additional usable storage or generic zero facts. Every other loading
operation must either preserve the claimed bytes, mappings and relevant backing,
or preclude entry. Ignored failures may have partial effects and cannot be assumed
effect-free. Unsupported global reservations, remappings or accumulated zero-fill
operations defeat affected coverage unless their noninterference is established.
The model retains loading-failure outcomes and actual-loader applicability; it
does not establish that a process reached the image's entry.

The checked relation determines coverage, while the root's existing image footprint
determines which bytes are represented. Covered bytes receive derived scalar facts;
uncovered bytes remain fresh arbitrary inputs, including mixed known and unknown
words. Selecting the relation requires a fresh root judgment. Continuations retain
current bytes after all intervening writes and never reapply initial values.
Equal-byte independent images cannot borrow the relation. Initialized numeric bytes
acquire no pointer or source-storage provenance, and the arbitrary-image model
remains available without this refinement.

**REQ-impl-process-entry** (invariant): An accepted argument, environment,
auxiliary-vector or inherited-descriptor interpretation of a native process
entry MUST satisfy these obligations:

- **bound-entry** — The claim identifies the selected immutable executable,
  identified machine/loading/entry relation, original process-input authority,
  admitted entry-state population and interference conditions. Direct entry and
  entry after an interpreter or wrapper retain their distinct loading and
  intervening-state obligations. Exec failure or termination before entry cannot
  provide an entry state. A conditional relation may describe well-formed states;
  production application separately establishes actual artifact execution,
  launch-input correspondence and applicability of that relation. A kernel
  version, symbol name, matching source or successful diagnostic run establishes
  none of those facts.
- **ordered-inputs** — Counts and vector extents follow from the entry relation.
  In the native 64-bit Linux ELF model, let the original stack origin be S,
  argument count A, environment count E and vector base V=S+8. The count word
  represents A; V[0..A) contains argument pointers, V[A] is NULL,
  V[A+1..A+1+E) contains environment pointers and V[A+1+E] is NULL.
  Auxiliary pairs begin at V+8(A+E+2). Counts are mathematical nonnegative
  integers, with all selected count conversions, increments and address
  calculations justified. For the selected consumer's signed 32-bit scan through
  these separators, A+E+2 <= INT32_MAX suffices; another selected consumer may
  establish its own checked arithmetic argument without using this index shape.
  Input order, duplicates, empty strings and bytes remain represented; argv[0]
  need not be the executable pathname. Any empty-vector adjustment belongs to
  the identified entry relation. Arbitrary scalar words and numeric addresses
  supply no count or vector meaning on their own.
- **storage-and-progress** — Every used slot, string, payload and native frame
  has established backing, extent, permissions, lifetime and alias relations.
  Pointer bytes correspond to their represented targets; numerical coincidence
  supplies no provenance. Universal origin domains retain admissible relocation
  and alignment without a sampled stack address. Full accesses are canonical
  and nonwrapping, with necessary separation from image, control and private
  storage. Logical string termination alone authorizes no wider overread.
  Unsafe language views grant neither backing nor allocation ownership.
  Completed scans require checked progress under the admitted population; an
  established first terminator may supply a decreasing remaining-distance rank.
  Analysis budgets are not execution bounds. Each later scan or parser retains
  its own coverage, access and progress obligations.
- **state-through-use** — Input stability applies through the actual relevant
  reads, not indefinitely. The relation accounts for input copying, intervening
  native/loader effects, selected-program writes and external interference.
  The actual selected copying and alias behavior determines lifetimes and
  effects. For example, non-copying argument strings, copied environment strings
  and writable random payloads retain their distinct obligations where those
  are the selected operations. Source initialization
  cannot stand in for native bytes, and native numeric stores require checked
  selected-source linkage and representation before supplying typed state.
- **auxiliary-and-kernel-state** — Auxiliary entries remain an ordered sequence
  through the first AT_NULL, with accessible bounds. Unknown or duplicate keys
  cannot silently disappear; exclusion, uniqueness or irrelevance requires the
  entry relation or checked consumer behavior. Entries retain their identified
  interpretations, including null or absent meanings; uninterpreted entries may
  remain raw ordered words. Scalar entries agree with their identified
  configuration where used. Interpreting or using a value as a pointer requires
  target provenance, backing, permissions and extent; merely retaining an
  address-valued entry does not assert backing at that address. AT_RANDOM
  supplies its accessible 16-byte payload, not an
  assumption that any byte is nonzero. AT_SECURE follows the exec security
  relation, not an environment assertion. A vDSO entry does not itself prove
  parser safety, progress or callable implementation semantics. Empty-auxv
  fallback is excluded only when established entry facts and checked control
  justify that exclusion. Inherited descriptors are separate post-exec kernel
  state, accounting for close-on-exec and subsequent changes. Relevant flags,
  open-file-description identity, aliasing, contents, offsets and operation
  outcomes need their own relations; descriptor numbers, stack bytes and
  security flags do not establish them.
- **applicability-and-outcomes** — The claim retains failures, faults, partial
  effects and termination alternatives relevant to its admitted model. An entry
  relation may describe the successful exec branch while retaining the other
  exec outcomes. A composed transition must still prove complete-cut or return
  coverage under its admitted entry conditions; conditional normal completion
  cannot discharge that obligation by assuming startup succeeded. Actual launch
  inputs and the producer's normalized
  environment are related to the admitted raw vectors; this does not relax the
  producer's duplicate-refusing normalization contract. Runtime transformations
  such as early environment lookup, secure rewriting and descriptor preparation
  retain their actual order and outcomes. The resulting relation remains
  subordinate to source-storage correspondence, complete bootstrap/use/harness
  coverage and producing applicability. A nonvacuous conditional theorem alone
  is not public runtime-reuse authority.

**REQ-impl-native-transition** (invariant): An accepted conditional native
entry-to-cut transition MUST satisfy these obligations:

- **bound-scope** — The claim binds its immutable image, entry, cut, machine and
  inference rules, admissible entry states, memory conditions and interference
  exclusions. An executable-entry claim starts at the entry read from that image's
  executable format, rather than a substituted symbol or proposed start.
  Conditional-region claims instead bind an explicitly selected entry within the
  same owned image, independently of a proposed instruction inventory. The claim
  retains which entry authority it uses; a conditional-region entry establishes
  no reachability from the executable entry or omitted prefix. Its initial state
  includes every state admitted by its explicit entry and frame premises. It
  cannot apply the executable's root-loading initialization relation. Current
  memory remains arbitrary except as constrained by explicitly retained entry-state
  relations or established by checked composition. An entry-state relation identifies
  its owned locations, widths, interpretations and original entry variables. The
  checker establishes that the complete interface admits a state and proves its
  transfers for every state satisfying the relation. A satisfying valuation can
  establish nonvacuity only, never replace universal reasoning or restrict the
  theorem to that valuation. These relations are antecedents of the conditional
  claim, not evidence that an actual execution satisfies them. Applying the claim
  requires independently establishing them from the actual incoming state.
  All unspecified register bits, flags and memory remain arbitrary. Entry facts and
  their authority are retained separately from derived outputs; expected outputs
  and normal completion cannot substitute for entry-state premises. Retained
  predicates may include consequences checked under the original origin domain
  without adding caller premises. In particular, a current unsigned word below
  a nonwrapping original-origin-minus-distance is also below the original origin;
  the reverse inference supplies no space for a child activation. The original
  stronger relation remains retained, and no such equivalence is asserted outside
  its origin domain. Retained
  entry-flag predicates have explicit
  architectural meanings and unchanged identities across later overwrites.
  The scope retains active call/return context and any per-thread machine state
  needed by its transfers. Unspecified entry FS state remains arbitrary; an
  expected TLS base, a caller-supplied TLS heap or an assumed syscall result
  cannot replace a derivation from the actual incoming state.
  The image, instruction and machine applicability
  obligations of REQ-impl-native-entry remain required.
- **complete-cut** — The checker reconstructs bound instruction bytes and every
  successor required by the admitted transfers before the cut. It establishes the
  cut as a reachable instruction boundary and retains its decoded instruction
  separately as unexecuted boundary evidence. Every execution from an admissible
  entry state reaches that cut; cycles require a checked finite-progress argument
  or refusal. A numeric cut selects the first encounter with that address and
  requires one activation context in the stopped scope. Ambiguous contexts and
  continuation to a later occurrence of the same numeric cut refuse. An explicit
  occurrence locator is distinct from a numeric first-hit cut and retains the
  same complete-cut obligations.
  An anchored locator binds the unexecuted boundary of an actual checked
  predecessor and selects the first target-address encounter after that boundary
  executes. Its authority retains the endpoint mode, anchor and resolved cut
  occurrence. A fresh-root claim cannot assert an inherited anchor. The checker,
  independently of discovery, requires the anchor to execute and every feasible
  suffix encounter at the target to stop at the selected common cut, with one
  activation and compatible frames. When target and anchor addresses agree, the
  cut is a distinct later occurrence. Existing prefix occurrences retain their
  dispositions even when their addresses equal the new target; an independently
  excluded boundary does not become a cut encounter through address equality.
  Matching occurrence coordinates from another proof supply no anchor authority.
  A finite occurrence witness may establish progress when the checker validates
  every actual successor and its activation transition, includes all admitted
  initial states, and establishes a well-founded occurrence rank that strictly
  decreases along every execution edge. Every terminal is the selected common cut
  or has an independently checked false incoming condition. A supported transfer
  deferred beyond a proposed unfolding remains a distinct residual-frontier
  obligation, not an unsupported operation or a successful endpoint. A feasible
  residual frontier refuses; the discovery bound supplies no execution premise.
  Occurrence membership is exact and root-connected, while instruction-byte
  occupancy remains image-wide: distinct occurrences cannot hide overlapping or
  inconsistent decoding. Both conditional successor slots remain required even
  when their decoded target addresses agree.
  A structurally decoded boundary without an admitted transfer may
  terminate discovery only when an independently checked proof establishes that
  its complete incoming execution condition is false for every admissible state.
  Evidence retains that boundary's bytes, extent, incoming control dependencies
  and exclusion proof. This grants no execution, effect, target, return or
  continuation semantics for the excluded operation. Without that proof,
  unsupported or unresolved transfers refuse. A proposal may select a direct
  call as such a boundary instead of supplying an admitted callee transfer.
  The checker then proves its full incoming occurrence guard false without
  interpreting the target, pushing a return word or inventing an after-call
  state. Expansion choices are untrusted search choices, not premises; an
  expanded callee may itself contain independently excluded boundaries.
  The same choice may leave register self-XOR, register-register arithmetic,
  increment, variable-count scalar shift, subtract-with-borrow, CLD,
  supported legacy SSE transfers,
  an explicitly or implicitly locked read/modify/write, a condition-code byte
  store, a byte TEST, a memory CMP or a NOP as a structural
  boundary rather than expand its admitted transfer. Operand-form selection
  preserves automatic transfer of the previously admitted register CMP and
  register/immediate TEST at 32 or 64 bits. A structural boundary's complete
  incoming guard must be proved false; admitting an instruction's semantics does
  not force discovery into an independently excluded arm's successors. Selecting
  expansion still requires the actual supported operand form and complete successor
  coverage.
  Invalid bytes at the selected boundary remain a refusal, and cancellation
  or budget exhaustion cannot select a successful fallback boundary.
  Truncation, unavailable bytes,
  incompatible decoding, cancellation and exhausted exploration never establish
  an endpoint. A fault
  or unsupported transfer before the cut cannot be hidden by assuming normal
  completion. Applicable synchronous faults must be excluded by established
  premises. Proposed extents, symbol sizes, instruction counts and exhausted
  budgets never establish an endpoint. Executed calls, returns, indirect transfers and
  external effects require their actual rules and obligations or refusal, not a
  fabricated return or silently truncated successor inventory. Reach conditions
  derive from the actual bound predicate state; taken and fallthrough edges
  partition their incoming condition, and joins preserve their complete union.
  Graph closure alone cannot justify replacing a derived reach expression with
  true or excluding an arm. An excluded transfer requires independently checked
  impossibility under the retained premises; unresolved paths remain required.
  A direct call's target and return address derive from its actual encoding and
  checked instruction extent, including displacement extension and address
  arithmetic. Coverage enters that target under the current state and active
  continuation; a call is not a fallthrough with an arbitrary result. A return
  reads the actual current return word and establishes its executable target,
  instruction boundary and compatibility with the active continuation. An
  expected return label alone cannot establish return-word integrity or restore
  the caller's state. Relevant protected-return mechanisms, faults and context
  changes remain machine obligations. A root return lacking a checked continuation
  cannot substitute for reaching the common cut.
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
  A claim with multiple address origins retains one joint admissible placement
  relation. Each accessible logical backing has an owned identity, byte extent,
  address relation, permissions and lifetime. Different identities alone prove
  neither separation nor unequal pointer values. The checker establishes that
  the complete placement and memory relation is inhabited and proves transfers
  for every admitted placement, not only for a satisfying example. Every used
  address, full extent and pointer offset preserves canonical nonwrapping bounds
  throughout that joint domain. Placement constraints are retained antecedents,
  not observations of an actual process or freely imported scalar conclusions.
  Logical object membership and finite extents do not require concrete distances
  from the stack origin. Relocating a fixed layout alone does not establish a
  relation that permits variable distances between input objects.
  All addressing paths into an admitted shared backing resolve to the same
  current bytes and provenance lanes. Views or alternative coordinates of shared
  storage cannot introduce independent initial values or hide overlapping writes.
  Distinct backings whose accessible extents could alias require a checked shared
  storage relation or a separation premise established for the entire admitted
  placement population; unsupported overlap refuses. Image, stack, thread-relative
  and process-input accesses retain one coherent memory relation. A new address
  origin grants neither storage nor permissions, initial values or input meaning.
  Segment-relative addressing uses the applicable thread's effective base and
  exact address-size, displacement and full-width operand semantics. It resolves
  into the same owned byte-memory as ordinary addressing, with canonical,
  nonwrapping extents and existing permissions. A checked base-setting primitive
  may transport provenance only from its actual argument through its established
  state relation. Equal scalar addresses do not create provenance, a separate TLS
  heap, new storage or new permissions; unsupported resolution refuses the access.
  A full-width comparison may use the checked pointer/value invariant for two
  offsets of the same exact origin. When both values are nonwrapping throughout
  the original low-canonical domain, offset order establishes unsigned and signed
  order and equality. This is an origin-domain inference, not an unconditional
  scalar identity. Partial-width values, foreign origins, opaque entry-value
  lineage and numerical coincidence supply no such inference. Actual operand
  reads remain accounted for; refined flag projections and branch predicates
  agree, while other flags retain their checked instruction semantics.
- **state-and-effects** — The checker derives the claimed register, flag and
  byte-memory relations from exact operand forms and execution order. Instruction
  fetch and every data access remain accounted for, including writes whose final
  value happens to equal the old value. Memory outside the write footprint and
  claimed preserved context remain unchanged under the retained frame premises.
  Undefined flags stay undefined; omitting a flag value from a projection does not
  establish that the flag was preserved.
  Direction-state transport retains both its original entry identity and actual
  current Boolean value. Arithmetic-flag replacement cannot overwrite it, and
  calls and returns do not implicitly restore a saved direction value.
  Image zero-fill or source-language zero initialization supplies no initial
  native-memory value without its applicable initialization relation. Such facts
  derive from owned file/zero-fill coverage under the identified loading relation
  and apply only at the original root. Uncovered bytes remain arbitrary, and
  subsequent writes supersede initial facts. Raw input
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
  Repeated executions of the same instruction have distinct owned occurrence
  identities. Instruction guards, accesses, primitive effects, abstractions and
  boundaries identify those exact occurrences; equal addresses or activation
  names cannot collapse them. Occurrence coordinates have meaning only within
  their owning evidence. Call activation follows the actual invoking occurrence,
  independently of loop progress; repeated calls at one address cannot share
  an activation merely because their target and continuation addresses agree.
  Calls, pushes, pops, returns and explicit stack adjustments derive their exact
  stack-pointer, byte-memory, flag and register effects, including implicit return
  stores and loads. Adjusting the stack pointer grants no storage, initialization
  or access permission. Every accessed slot must be admitted by the root memory
  relation; additional requirements need a fresh root judgment, never strengthened
  inherited permissions. Restoring the stack pointer or returning from a call
  neither rolls back writes nor erases accesses or primitive effects. A per-thread
  effect survives result-register overwrites and ordinary call return. Later
  context changes require a checked preservation or replacement relation before
  using that state; equal program counters cannot establish thread identity.
- **independent-evidence** — Candidate endpoints, instruction inventories and
  state relations are proposals. The checker validates their coverage, transfers,
  origin side conditions and dependencies independently of proposed conclusions.
  Cancellation, exhausted bounds, empty or inconsistent entry conditions, or any
  unclosed obligation yield no transition certificate. Evidence retains owned
  inputs and all image, interface, origin, rule and subordinate dependencies under
  REQ-impl-derivation-reuse; copying a projection grants no authority.
  A scalar-call conclusion or a read/write frame bound alone is insufficient to
  supply a complete symbolic successor state. Using such subordinate evidence
  requires a checked relation covering every state component and ordered effect
  that the continuation consumes; an adapter cannot invent that authority.
- **conditional-composition** — A successor transition starts at the checked cut
  under the same bound image and compatible origin, state, memory, activation,
  thread and machine premises. The cut instruction belongs to that successor's
  executed scope. Composition retains the original entry authority and entry;
  extending a conditional-region claim never upgrades it to executable-entry
  reachability. Root inclusion, transfer closure, complete-cut coverage and the
  preserved frame remain obligations over the entire composed scope. The cut's
  retained actual instruction and incoming state must suffice for the successor's
  claimed uses; a matching numeric boundary alone does not establish that relation.
  A newly required primitive or context premise must follow from
  the predecessor's retained conditions or be established by a fresh root
  judgment; continuation cannot strengthen them silently.
  Composition preserves original entry variables, prior primitive-outcome
  identities and the complete ordered effect dependencies. New occurrences have
  distinct outcome identities; neither a replacement entry state nor an unbound
  additional input can stand in for a checked primitive effect.
  Extension retains the predecessor's logical backing identities, joint placement
  predicates, input variables, current bytes and lifetimes together. Application
  may instantiate or rename independently rooted backing and input identities
  through a checked association with the actual incoming state; literal identity
  equality is not required. The association preserves the joint placement
  conditions, current bytes and provenance, admitted aliases, permissions,
  complete access extents and applicable lifetimes. Several views may resolve to
  the same shared storage; the association does not impose injectivity on views.
  Fresh roots instantiate fresh owned input variables. Immutable layout
  descriptions may be shared but confer no cross-root execution identity.
  Equal names, numeric addresses or byte projections do not
  authorize importing an unrelated backing, strengthening its conditions or
  reapplying initial input values. Private-frame expiration and control-word
  protection continue to apply through every coordinate for the same storage.
  The predecessor's cut must be a common boundary of every path being extended.
  Reconstructed prefix and suffix coverage exclude bypass, overlapping instruction
  decoding and unaccounted re-entry into an executed prefix. Composition retains
  the predecessor's exact occurrence identities, edges and exclusions; extending
  its unexecuted cut cannot redirect an edge into an old executed occurrence.
  An anchored extension inherits that exact boundary and current state; it cannot
  leave the anchor unexecuted as a new cut or a successful unfolding frontier.
  A fresh occurrence may execute previously covered bytes only through checked
  transfers and progress evidence. Repeated execution of the same instruction,
  within one activation or in distinct activations, requires distinct checked
  dynamic occurrences, including their primitive-outcome origins, or refusal;
  a program-counter-only identity cannot collapse them. Active return contexts
  survive cuts and compose only through compatible joins; differing contexts
  must retain their path association or refuse, never select one silently.
  Initial predicate identities, occurrence guards and the final reach expression
  remain retained dependencies; continuation does not restart reachability at an
  invented true condition or
  reset resource allowances per path, call, return or continuation. Checked
  exclusions retain their original boundary and guard dependencies; continuation
  neither reapplies initial image values nor turns an excluded operation into a
  fictional executed continuation.
  Origin names, matching output bytes or digests cannot replace this relation.
  The transition remains distinct from normal-return, complete-function,
  source-startup and completed-bootstrap evidence. Applying it to an ordinary
  process additionally establishes actual image/entry binding and the applicable
  process-entry layout and memory relation; no observed stack address is required
  when that relation establishes the symbolic premises. Numeric native storage
  still needs checked source-storage, representation and linkage correspondence
  before it can supply source state. The transition grants no historical execution
  authority, source-subject coverage or public runtime discharge.

## Conditional native return completion

**REQ-impl-native-return** (invariant, refines REQ-impl-native-entry): An accepted
conditional callee-return relation MUST establish these obligations:

- **entry-and-continuation** — The claim binds the actual callee entry in its
  owned image and an explicit incoming continuation interface, including the
  control word's location, interpretation and validity, protected storage and
  caller context. Entry relations satisfy REQ-impl-native-transition's ownership,
  consistency and universal-coverage obligations. An incoming continuation is a
  conditional context premise, not evidence of an executed caller or an invented
  CALL inside the callee's coverage. A control word supplies no scalar argument
  or expected computation result. Unsupported protected-return mechanisms refuse.
- **complete-return** — Every admitted entry state reaches a checked return to
  the declared continuation. Coverage includes the prologue, body, epilogue,
  actual return transfer and every applicable exceptional path. Excluding a slow
  or throwing arm requires proving its complete incoming guard false under the
  retained entry relation; a normal-completion assumption is insufficient. The
  return reads the actual current control word and establishes its executable
  target and compatible continuation boundary. Stopping before RET, reaching a
  numeric cut or observing restored stack-pointer bits is not return completion.
- **restored-frame** — Every stack access has established extent, permissions,
  backing and alias conditions. Stack-pointer arithmetic grants no memory. Saved
  and restored context is related to its original entry values, including required
  definedness and provenance; a never-written mask cannot certify a restored
  register. The actual final stack-pointer relation includes return's advancement.
  Protected control storage remains protected throughout, not merely equal at the
  endpoints. Restoring registers or leaving a frame erases no stack write or access.
- **complete-effects** — The returned state and ordered effects cover every
  admitted transfer, including implicit accesses and primitive effects whose values
  are discarded. Administrative frame effects remain recorded. Hiding them in a
  source projection requires checked ownership, disjointness, nonescape and
  preservation relative to the source representation; equal final globals alone
  cannot establish correspondence. Return completion supplies no result bits
  where the selected interface has no scalar result.
  Private-frame projection retains a fresh-root ownership and lifetime premise
  excluding observation through preexisting aliases as well as newly exposed
  ones. Preserving an incoming pointer does not establish this premise. Released
  scratch contents remain in the concrete state; later dependent reads require
  initialization or explicit checking against that state. Bounds, permissions and
  an actual CALL establish neither exclusive ownership nor nonobservability.
  An executable-entry claim may instead retain an explicit finite scratch
  ownership antecedent ending at the first actual arrival at an independently
  decoded instruction boundary. The deadline is fixed by the original root;
  declaring it supplies no progress or eventual-arrival proof. Ownership ends
  before that boundary's instruction executes. Before borrowing, every earlier
  deadline occurrence must be established unreachable, and a current deadline
  boundary grants no new use. A borrowed invocation must remain within the
  lifetime through its actual return; its final transfer may arrive at the
  deadline, but it cannot reach the deadline earlier and continue borrowing.
  Deadline decoding must agree with established instruction occupancy. Later
  continuations retain the declaration, occurrence history and residual bytes,
  without renewing expired ownership. A source projection must establish that
  its complete claimed use lies within the admitted lifetime. This remains a
  conditional ownership premise; actual process-entry ownership is a separate
  applicability obligation, not a fact derived from permissions or isolation.
- **composition** — Evidence retains its original entry authority, entry
  relations, input identities, complete current state, continuation, ordered
  effects and cumulative resource account. An entry-to-cut predecessor can supply
  current state but cannot acquire new premises during continuation. Completed
  return evidence is distinct from entry-to-cut evidence and is usable only where
  the caller establishes the callee's interface from its actual incoming state.
  Copying projections or matching endpoint addresses supplies no such relation.
  Direct application binds the exact subordinate theorem to the decoded CALL
  target, actual post-CALL input state and active continuation. Application may
  instead begin at the theorem's entry already reached within the innermost
  active CALL. The owned prefix then establishes intervening wrapper and tail
  transfers; it does not pretend that the original CALL targeted the later body.
  The current stack pointer must identify that invocation's actual control slot,
  and the theorem must return to its actual continuation. Entry associations and
  preserved-register conclusions are relative to this selected body-entry state,
  not to an earlier state before wrapper effects. Shifted origin domains,
  memory permissions, current entry relations, flag definedness, context and
  any private lifetime follow from the unchanged caller premises. Child private
  storage may inherit a containing parent lifetime; its control word remains
  protected throughout the child scope, including against unchanged-value writes.
  For active-entry application, that protection includes all intervening
  descendant writes after the initiating CALL's own control-word store, not only
  writes after the later body entry.
  A prior modeled context change does not alone invalidate application: the
  current state must satisfy the callee's identified machine and primitive
  models. Callee inputs associate with that actual current state, including the
  effective FS state when required. Original caller context history remains
  cumulative; callee-relative preservation cannot become a claim that the
  caller's original context was unchanged.
  The returned execution must discharge that child activation and restore the
  parent's active continuation context. Checked re-execution under the caller
  state may supply the complete successor while retaining the applicable callee
  theorem; copied callee outputs cannot stand for that relation. Construction,
  premise discharge and retained dependencies share the caller's cumulative
  resource account. Source-level use additionally establishes the actual typed
  call, current represented state and corresponding dynamic effect occurrences;
  callee-local input or primitive-outcome names cannot silently become caller inputs.
  Embedding callee occurrence evidence uses an injective, consistent mapping of
  occurrences, edges, residual frontiers and activation ancestry under the actual
  invoking call. The completed return consumes the exact retained return
  occurrence and actual protected control word. Equal addresses do not authorize
  borrowing another invocation's return or an earlier iteration's effect guard.
  Retained occurrence associations identify the exact checked embedding,
  including excluded boundaries, residual frontiers and terminal return. They
  confer no independent authority and do not associate the new parent
  continuation with a child occurrence. Specialization may exclude an originally
  conditional transfer; access counts or a fixed index offset cannot replace
  actual occurrence and effect association.
  This conditional fact grants no executable-root reachability, source-storage
  association, historical execution authority or ordinary runtime discharge.

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
  A bounded region relation may instead bind an actual source operation's
  evaluated operands before its execution and a native transition's unexecuted
  boundary, retaining the full selected source root and the exact covered prefix.
  A proposed representation of typed source storage by owned image or
  origin-relative stack extents is an untrusted scope witness. Its object and
  allocation-instance identity, lifetime, selected-layout extent, subobject offset,
  width, alignment, byte interpretation, source and native ownership, and pointer
  provenance must be checked against the actual transfers and uses. Distinct
  simultaneously live represented objects have disjoint extents; subobject aliases
  retain their common owning bytes. Protected control storage cannot be reassigned
  as ordinary local storage. Names, addresses and equal initial bytes supply no
  association, and stack-relative coordinates require the retained native origin.
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
  For represented globals, the initial relation includes arbitrary prior typed
  values and corresponding native bytes, rather than proposed final values.
  Objects introduced by checked source allocations instead retain their derived
  language initialization and current contents.
  A source claim admitting arbitrary initial globals retains compatible native
  entry states for every such valuation. One satisfying joint valuation cannot
  narrow that source domain. Administrative entry predicates can preserve this
  independence through checked separation from the represented source storage.
  Checked transfer closure establishes the represented current state and actual
  operands at the cut for every such initial state and arbitrary native scratch
  state. Every source observable effect, exceptional path and callback, every
  actual native access, and preservation outside the permitted write footprint
  must be accounted for. Equal endpoints cannot hide an extra effect or a read
  before overwrite. This requires a checked effect relation, not necessarily
  one-to-one source/native access traces: permitted elimination, combining and
  administrative steps require their own checked justification.
  Source allocation establishes language initialization, not values of arbitrary
  native stack bytes. Before a native read or callee operation depends on those
  contents, the relation establishes the relevant materialized bytes. Eliminating
  an ordinary source access requires checked isolation and value, effect and
  dependent-use justification. Eliminating a source allocation and its storage
  additionally requires checked nonescape; elimination supplies no native address.
  Ordinary combined accesses require complete byte, value and ordering
  coverage, including any accessed padding. Atomic groups remain indivisible.
  For this bounded ordinary typed-source correspondence, direction is preserved
  caller context. At corresponding published boundaries and return, the native
  direction must equal its incoming value under the existing entry conditions;
  neither arithmetic-flag clobbering nor an assumed clear entry erases this duty.
  Represented storage cannot be hidden as administrative private-frame traffic.
  An ended source lifetime does not reset or discard residual native bytes, nor
  require dead local bytes to recover their initial language values.
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
  as the complete computation. A completed-function relation includes the actual
  source return and native return completion under REQ-impl-native-return; an
  operand boundary or an unexecuted return instruction remains a prefix.
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
  A region representation remains fixed throughout its claimed composition.
  Each continuation must establish that representation against its actual uses
  or consume a separately established interface carrying the required relation.
  The witness supplies no unrestricted source-object-to-address fact, complete
  function equivalence, or semantics for an unexecuted call or native operation.
  Multiple representations are permitted when their complete claimed behavior
  satisfies the relation; uniqueness is not a premise. Whole-source actual-use
  coverage and reachability of a conditional native region remain separate proofs.
  A rooted application retains the exact complete correspondence and its checked
  native application rather than replacing the original source, native theorem or
  representation. For every admitted root state, the actual body-entry bytes and
  registers must supply a total typed source valuation satisfying the original
  input relation. Boolean storage requires established canonical encoding;
  adding a desired encoding as a fresh antecedent is insufficient. Source
  initialization cannot supply missing native bytes. Stack-coordinate translation
  is confined to the retained body representation and its materialization and
  lifetime account; eliminated storage acquires no address. Actual occurrence
  associations carry nested effects without equating access counts. The rooted
  successor retains earlier wrapper and primitive effects, residual bytes and
  original context history. The original source-model antecedent, scoped model
  consequences and broader process, compiler, use and harness obligations remain
  explicit.

## Selected assembly call references

A selected assembly reference supplies the source-side meaning of a bodyless
typed call through its selected package's assembly interface. It is not evidence
that an out-of-line copy was emitted, linked, reached or used instead of an
intrinsic. Actual native instances retain their separate correspondence proof.

**REQ-impl-assembly-reference** (invariant): Substitution of a selected assembly
reference at a source call MUST satisfy these obligations:

- **owned-selection** — The exact typed declaration, signature, package identity
  and directives, selected assembly membership and bytes, transitive include
  bytes and resolution, preprocessor state, assembler options and relevant build
  configuration belong to one immutable source/build owner. A filename inventory
  is insufficient. Resolution includes search precedence and evidence excluding
  earlier shadowing inputs, including generated include namespaces; an unavailable
  earlier search entry cannot be assumed empty. Generated content requires its
  own derivation or owned selected bytes. Complete preprocessing and definition
  boundaries must be checked even when only one body's instruction semantics
  are needed. Unsupported syntax capable of changing selection, definitions or
  the claimed body, and competing opaque providers, prevent the binding.
- **current-action-acquisition** — A current assembly reference may acquire its
  inputs from a fresh compilation action bound to the same immutable typed-source
  selection. That selection retains the requested roots and package instances,
  including test and profile variants, directory, complete effective environment,
  toolchain, build options and additional inputs. Actual compiler source membership,
  package/import bindings and effective options must agree with that owner;
  matching a package name alone is insufficient. The acquisition observes the
  actual final assembler invocation at its process boundary: tool, working
  directory, source operands, qualified package, ordered options, include paths,
  macro definitions and response-file inputs. All selected assembly providers
  must be covered. Diagnostic command listings and preliminary symbol/ABI scans
  can locate actions but cannot establish their execution or final inputs. In
  particular, a preliminary scan's empty generated header cannot stand for the
  final assembler's header.

  Capture occurs while the action's real namespace exists. Independently checked
  preprocessing of every selected provider determines the complete include read
  set, selected bytes and preceding failed lookups. Under the ordinary Go
  assembler interface, relative includes first try the assembler's working
  directory, then its top-level source directory, then the ordered include
  directories; nesting does not implicitly add the containing header's directory.
  The action directory's precedence over toolchain includes is retained. No
  generated directory is presumed empty or limited to familiar filenames.
  Capture establishes agreeing path/content and lookup observations and protects
  them through that action's input-use interval. Relevant namespace and content
  mutations, including creation of an earlier candidate, invalidate acquisition;
  loss of mutation observation refuses acquisition; incomplete observation supplies
  no protection. Descriptor release alone establishes no namespace or content
  mutation. Unobserved mutation channels, including native AIO, memory-mapped and
  remote writes, mount substitution, and kernel/filesystem notification gaps,
  remain under caller-owned exclusion; agreeing endpoints do not prove the
  absence of an intervening mutation. Source/build exclusion
  and mutation-and-restore residuals remain explicit under
  REQ-fresh-coherent-view and REQ-fresh-producer-view. Transient inputs are copied
  and validated before their namespace is released; subsequent cleanup supplies
  neither a missing observation nor evidence of an earlier absence.

  An execution-forcing acquisition may change cache-execution policy and its own
  output destination, while preserving source selection and all ordinary
  compilation options, including optimization, instrumentation, profile selection
  and per-package assembler/compiler flags. An interposed capture boundary must
  transparently forward the real tool's arguments, environment, working directory,
  streams, version queries and exit disposition. Unsupported preexisting
  interposition is refused rather than silently replaced. A cache hit without
  the required final actions establishes no action evidence. Missing provider
  actions, disagreement with the typed owner, drift, incomplete input capture,
  cancellation or exhausted bounds publishes no packet. This is acquisition of
  current reference inputs, not observation of a historical compilation. Its
  newly built output cannot replace the independently owned native image or
  establish correspondence by output equality. No public build/tracing protocol
  or helper execution on ordinary result-cache hits follows from this facility.
- **operational-binding** — The checker applies an identified Go assembly/source
  interface under REQ-impl-premise-boundary to the actual declaration and complete
  provider scope. Package qualification, symbol escaping, visibility, declaration
  directives, definition ABI and provider uniqueness determine the reference;
  matching a proposed symbol string is insufficient. For the ordinary package
  interface, a leading middle-dot assembly name denotes the current package's
  qualified symbol, an unannotated external `TEXT` definition uses ABI0, and its
  definition supplies that bodyless declaration's reference only when the resolved
  identity and typed interface agree. File-local definitions do not silently
  provide external declarations. Explicit redirects, aliases, duplicate/weak
  definitions and foreign or opaque inputs that could compete must be resolved
  under the same interface or refused. This reference's provider scope is the
  selected package's complete compilation unit: its typed definitions and linkage
  directives, all preprocessed assembly definitions and other contributing inputs
  are checked at the resolved symbol/ABI key. An assembler-generated definition
  inventory may propose that key, but the checker reconstructs it from owned
  inputs. External link candidates are not assumed absent; a local reference
  binding makes no claim about the final linker's inclusion or choice of an
  out-of-line implementation.
  A replacement or redirection affecting the actual native instance must still
  satisfy its complete extensional correspondence.

  The supported one-argument `//go:linkname local` keeps the default qualified
  object-symbol identity and permits linkname access; `//go:linknamestd local`
  keeps that same identity while restricting such access to standard-library
  references. These are binding/access directives, not behavioral summaries.
  Their actual local declaration and directive-file `unsafe` import must be
  checked, with duplicate, malformed or unsupported forms refused. A two-argument
  form redirects identity and cannot be ignored as if it were the one-argument
  form. A `//go:noescape` directive records a compiler-facing obligation; the
  reference's escape/frame claim must be proved from its body. The interface
  defines these naming and ABI operations, not arbitrary metadata truth or
  correctness of selected library code. Compiler/assembler implementation source
  can locate the interface's definitions; reading it supplies no implementation
  theorem or approval exemption.
- **body-and-interface** — Independently checked interpretation of the owned
  preprocessed body derives its complete argument/result, control, memory,
  ordering, escape and exceptional-outcome relation under an identified assembly
  language and ISA. Actual signature widths, alignment and ABI layout determine
  stack and result locations; operand names or comments do not. Flags, local-frame
  size, implicit prologue/epilogue, pseudo-operations and complete return behavior
  are accounted for. In the ordinary amd64 ABI0 interface, a zero-local-frame
  leaf with the checked `NOSPLIT` flag has no stack-check or frame-allocation
  prologue; its argument base is eight bytes above entry RSP. This conclusion
  requires the complete body and effective flags, not the token `NOSPLIT` alone.
  Unsupported instrumentation, frame transformations or pseudo-operations refuse.
  Assembly-source instructions may share an instruction-transfer kernel with
  decoded native instructions through checked normalization, retaining their
  different input authority. Manufactured instruction bytes cannot become
  observed executable bytes or an image-owned certificate by relabeling.
- **reference-frame** — Typed arguments are marshalled by the checked ABI
  relation into reference-private storage, and results are decoded from their
  complete declared representation. Unspecified bytes and scratch state remain
  arbitrary. Private storage has established extent, permissions, lifetime,
  disjointness from represented source storage and protected continuation, and
  nonescaping ownership; a return must read the preserved return word and satisfy
  the reference continuation. Its complete accesses and effects remain in the
  reference derivation. Hiding administrative reference accesses in the source
  projection requires the checked disjointness, nonescape and preservation
  relation. The private frame is a specification device, not an assertion that
  the actual inline implementation allocated that frame, nor permission to add
  storage to an existing native transition. Reads/writes of represented storage,
  including failed compare/exchange writeback, and ordering effects cannot be
  hidden with the private frame.
- **checked-substitution** — The source-region checker applies the derived
  relation at the exact retained call occurrence, selected callee, evaluated
  arguments, pointer provenance, incoming heap and call context. It independently
  establishes every precondition and transfers the complete relevant successor
  state, return value, frame and effect relation. Callee names and preapproved
  assembly bodies select no transfer rule. The reference theorem covers all
  admissible arguments and referenced-memory values; a compare/exchange reference
  includes independent current, comparison and replacement values and both
  outcomes. Constant specialization at a particular call requires checked
  inference. Using this reference in source/native correspondence additionally
  requires independently checking the actual optimized native region against
  this source computation with the fixed representation, every feasible
  path and exceptional arm accounted for, and each claimed memory/operand use
  justified. A changed source assembly body requires re-derivation; semantic
  disagreement within the admitted source/native scope defeats correspondence
  even if compiler substitution leaves native bytes unchanged. Intrinsic tables
  or compiler reports can suggest candidates, not establish equality. Reference,
  source-region and native-continuation evidence retain their original owners,
  entry authority, current states, complete dependencies and cumulative resource
  accounts. Cancellation or exhausted bounds publishes no partial proof. This
  reference supplies no ordinary runtime discharge, whole-function coverage,
  executable-root reachability or historical execution authority.

The ordinary interface is described by the Go assembly guide (`doc/asm.html`)
and compiler directive documentation (`src/cmd/compile/doc.go`). Interface
definition locators include `cmd/asm/internal/asm/parse.go` (qualification and
definition ABI), `cmd/asm/internal/lex/input.go` and `cmd/go/internal/work/gc.go`
(preprocessing and include selection), `cmd/compile/internal/noder/noder.go` and
`writer.go` (linkname directives), `cmd/compile/internal/ssagen/abi.go` (definition
ABI association), and `cmd/link/internal/loader/loader.go` (linkname access).
These are locators within the selected toolchain, not approved paths or versions.

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
  A normal-return postcondition is a distinct scope: it describes the state of
  that invocation only if it returns normally. It asserts neither eventual
  return, absence of exceptional outcomes nor an effect bound on intermediate
  execution. Its consumers retain that distinction; it cannot supply complete
  effects, prefix safety or native return completion.
- **inductive-transfer** — Proposed block-entry states and invariants are checked
  against the actual control-flow graph and typed operations. Every admitted
  initial state is included in the entry invariant; on every edge, the checked
  transfer of the predecessor invariant is included in the successor invariant.
  Inclusion means coverage of all represented concrete states, not agreement of
  proposal labels. This includes every backedge and the actual predecessor/value
  association of each phi, with path conditions and exceptional outcomes retained.
  Excluding an edge requires a checked argument. Loops and recursive contexts
  require inductive justification at their boundaries, not finite unfolding alone
  or mutually assumed summaries. A complete finite occurrence witness can supply
  that justification only when independently checked typed transfers cover every
  required edge and phi predecessor, all admitted initial states are included,
  and every residual frontier is independently proved unreachable. At each static
  boundary, the union of complete correlated entry relations for occurrences of
  that boundary supplies its invariant; independent projections of their
  components do not. A checked well-founded occurrence rank strictly decreasing
  along every execution edge establishes finite progress, separately from those
  invariants; the discovery bound is not an execution premise. The invariant at
  each claimed use entails the claimed operand relation. Unsupported transfers,
  unclosed invariants, exhausted
  bounds or cancellation yield no partial positive certificate.
  Widening and joining must over-approximate every incoming state. Common
  facts may survive when their ownership and meaning agree in every alternative;
  absence of a fact means unknown, not an empty value. Independently abstracted
  collection projections cannot reconstruct exact correlated rows or operands.
  An inductive safety or normal-return postcondition requires preservation on
  backedges, but does not acquire a termination obligation or a progress theorem.
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
  An opaque continuation retains established allocation-instance and cardinality
  facts only through its checked predecessor and non-reexecution evidence; it
  neither recreates the object nor resets its current contents. A proposed heap
  or allocation-shaped identity alone cannot establish freshness or singleton
  status. Conservative typed unknown contents may include an unsupported scalar's
  initialized value while retaining object type and lifetime; they establish no
  exact bits, scalar equality, or native initialization. Abstracting an unsupported
  initialized scalar leaf to typed unknown does not by itself discard independently
  established facts about supported aggregate siblings.
  Map references retain their backing identity separately from the contents they
  reference. All aliases observe updates to that same backing; replacing one
  reference with a fresh empty map does not clear its previous backing or other
  aliases. Nil, fresh empty contents and unknown incoming contents remain
  distinct. Repeated allocations cannot initialize older instances represented
  by an allocation summary.

  Allocation cardinality is scoped to the checked activation. A validated
  straight-line entry-to-use segment ending before its block's successor edges
  cannot repeat an allocation merely because the enclosing function is cyclic.
  That local non-reexecution fact preserves incoming aliases to earlier instances;
  it does not apply to child calls' wider control flow, later loop iterations or
  a continuation that can cross a backedge. Whole-function control facts remain
  distinct from the narrower scoped relation.

  A channel construction's normal-return postcondition retains a fresh logical
  identity for the actual language allocation and its bounded context, selected
  element type and direction, and checked capacity in the common nonnegative
  signed 32-bit range. The bounded capacity relation refuses unknown, negative
  or out-of-range capacities. It establishes neither existence of a successful
  construction nor absence of allocation failure, panic or other exceptional
  outcomes. Capacity representability and payload-layout bounds alone cannot
  establish those outcomes. Strict invariant and complete finite-occurrence
  scopes require independently checked allocation-outcome evidence before
  producing a construction value or effect; without it, reachable construction
  refuses even for zero or one capacity and without deferred control. No named
  runtime, capacity threshold or success assertion supplies that evidence.
  Validation of an incoming channel handle remains distinct from proving its
  construction. Allocation-free nil-channel length and capacity and independently
  excluded unreachable constructions retain their own supported relations.
  Copying, direction narrowing, aggregate
  fields and captured environments preserve aliases and immutable capacity.
  Identity equality requires established singleton cardinality; recurrent sites
  and merged activations cannot equate their different concrete instances.
  Checked predecessor continuity preserves existing identities without replaying
  allocation. Channel identity and capacity establish no contents, closed state,
  stable length, send/receive/select/close effects or concurrent-use completion.
  They grant no addressable backing, native layout, allocation lifetime ownership
  or separation from the current native stack. Those require independently checked
  storage and implementation correspondence, not the implicit language operation.

  A projected map-key summary over-approximates every key present in the backing,
  including keys whose stored values are zero or nil. A projection used to prove
  absence respects the key type's equality; ignored fields and unavailable
  components cannot supply distinguishing evidence. An insertion accounts for
  its actual destination key, through the actual receiver, aliases and argument
  flow. Each projection may widen independently to unknown. Such a summary may
  establish a definite lookup miss when the actual query cannot match any
  represented key; it supplies no invented matching key, payload, cardinality or
  correlation between projections. Unknown mutations invalidate affected facts
  unless a checked frame excludes them.
- **conditional-storage-model** — A source derivation interpreting integer/float
  bit views identifies its storage model separately from language semantics and
  from selected native applicability. A binary32/binary64 model gives exact bit
  encodings, byte order and typed access interpretation; selected type sizes and
  alignment alone do not establish that model's applicability. A conditional
  source proof may use this model as an explicit antecedent. Every dependent
  claim, call substitution and continuation retains that antecedent and its scope;
  copying values or heaps cannot erase it. Before such a conclusion authorizes
  runtime reuse, checked selected-implementation correspondence must establish
  the relevant actual storage, operations and uses under the identified machine
  model, and checked surrounding composition must establish their entry-state
  premises. A version, name, source example, equal width or successful execution
  cannot discharge these conditions.
  A complete source/native relation may discharge the model-dependent value,
  effect, control and exceptional-outcome consequences for its exact selected
  scope under the retained machine/entry conditions and original input relation.
  This scoped discharge leaves the original source antecedent intact. It grants
  neither an unqualified encoding theorem nor applicability to another invocation,
  inline copy, prefix or source-only conclusion. When pure computations or storage
  are eliminated, checked isolation, value and complete dependent-use reasoning
  may establish the same claimed consequences without asserting a physical object
  or operation that does not exist. Actual native floating operations still require
  their own checked operand, exception/status and preserved-context conditions;
  final byte equality alone cannot discharge them.
  A permitted bit view preserves the live object's allocation identity, lifetime,
  offset and owning bytes, with checked extent and alignment for both views.
  Reads and writes use one canonical object state, so an alias cannot retain stale
  contents after a write through another view. Pointer provenance supplies no
  numeric address, and bit reinterpretation supplies no numeric conversion rule.
  Unsupported address arithmetic, escaping views or unestablished object/layout
  relations yield no dependent proof. Source initialization establishes language
  values only, never native bytes.
  Exact float values distinguish bit identity from language equality. IEEE
  equality makes every NaN unequal, including to itself, and opposite signed zeros
  equal; abstract state identity may still distinguish those zeros and identify
  identical NaN encodings. Typed constants obey target-precision rounding to
  nearest, ties to even, and unsigned zero; bit views may introduce signed zero,
  infinities and NaNs. Native floating-point exception/status conditions remain
  separate obligations: language equality alone does not discharge them.
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

  A bounded non-unwinding deferred-execution relation retains an ordered pending
  stack in each whole correlated activation state. Actual fresh function entry
  establishes an empty local stack by language semantics. At a mid-body entry,
  absence is unknown: a known stack requires checked predecessor continuity or
  an explicit retained conditional control antecedent. Registration captures the
  actual registration occurrence, callable and environment, receiver and evaluated
  argument values without executing the call. The registration's actual target
  defer list must be respected: a local-stack antecedent cannot retarget an
  explicitly designated alternate list. Such a target requires checked provenance
  and effects for that list or refuses, including in retained captures supplied
  at a later conditional entry. Pointer and captured-cell identity
  survives; registration does not freeze reachable heap contents. Draining removes
  the last capture before dispatch, checks its complete invocation against the
  current heap, and retains every checked successor. The child has its own fresh
  stack, while remaining parent captures stay suspended and rooted. Nested drains
  follow that same rule. A completed return requires a known-empty stack; its
  results follow the actual post-drain loads rather than an early result snapshot.

  This relation admits only operations and reachable callees whose complete
  safety follows under their actual inputs. Possible panic, uncertain partial
  operations, unknown targets, opaque leaves and unsupported exceptional control
  refuse, including when a deferred recovery could produce a normal outcome.
  No normal-return-only subordinate can establish that safety, including a
  channel constructor whose exceptional exit a caller could recover. Recursion and
  recurrent registration or drain sites may conservatively refuse. The invariant
  safety arm establishes no termination claim; complete finite occurrence evidence
  retains its separate coverage and progress obligations. Stack order and capture
  relations cannot disappear under inclusion or widening: incompatible bounded
  control shapes refuse. Continuations preserve pending work, current heap and
  original control antecedents without replaying registration or draining twice.

  Interpreting builtin recover as nil requires an established typed no-active-
  unwind scope, propagated through checked ordinary calls and normal deferred
  dispatch. At a conditional root this is an explicit retained entry antecedent,
  unless checked surrounding startup supplies it. Neither a fresh empty local
  stack nor a strict safety claim establishes that scope: the root could itself
  be invoked as a defer during an outer panic. Unknown entry scope supplies no
  recover result. Parent-panic recovery and Goexit behavior require their own
  checked semantics; a routine's name supplies none. Normal-return-only scopes
  continue to refuse deferred and concurrent control and retain their existing
  exceptional exclusions. Native and reference consumers without the corresponding
  control and antecedent accounting refuse these source evidence arms.

  An outcome-sensitive source relation is distinct from the non-unwinding scope.
  It retains all admitted normal and abrupt continuations over correlated logical
  stores and activation-local deferred work. An implicit channel construction may
  produce its language-defined fresh handle, initiate a panic, or fail to complete;
  a successful construction is not an entry assumption. At success or language-
  panic initiation, unrelated pre-existing program locations retain their values
  after the actual operand evaluations. This logical frame follows the implicit
  operation's language semantics: it grants no arbitrary program stores or
  callbacks, but excludes neither evaluated operand effects, subsequent deferred
  execution nor independently admitted interference. It supplies no frame for
  explicit runtime calls, private allocator bookkeeping, physical resources or
  native memory ownership. Unknown recovered payloads confer no callable or
  method-effect authority.

  Panic activity is distinct from its payload, including a nil payload wherever
  the identified panic model permits one. Direct recovery eligibility belongs to
  the particular deferred invocation of the panicking activation; ordinary helper
  calls cannot inherit it. A recovery consumes that eligible panic at most once.
  Successful recovery does not end the recovering deferred invocation; its
  remaining execution and effects are checked. If that invocation returns normally,
  remaining defers of the recovering activation execute against the current heap,
  and normal completion uses its actual result continuation, never the instruction
  after the panic. A replacement panic or other abrupt outcome retains its own
  propagation. Nested unwinding distinguishes recovery confined within a deferred
  invocation, after which suspended outer unwinding resumes, from propagation
  that supersedes or aborts that outer control.
  A non-returning operation supplies no ordinary successor. Unsupported exceptional
  control, an unclosed execution frontier or exhausted checking bounds refuses
  the dependent proof rather than truncating the outcome set.

  An open checked source relation may retain every unfinished execution as an
  owned frontier, including its suspended caller and deferred continuations,
  current logical store, panic and recovery state, and actual instruction
  occurrence. Such a frontier establishes only the checked prefix relation; it
  is neither a return nor a noncompletion outcome. Resumption binds its checked
  predecessor and retains the original premises, object identities, pending work,
  complete alternatives and cumulative resource account. It cannot recreate an
  entry from a copied heap, replay completed operations or enlarge a scope whose
  boundary established non-reexecution. Independent resumptions cannot mutate
  their predecessor or each other's preparation. Any remaining feasible frontier
  prevents complete-activation authority or terminal-conditioned projection.

  A terminal-conditioned conclusion is projected only after the complete relation
  is established. Every matching outcome must entail the claimed property;
  recovered failures which can reach that terminal remain included. The terminal
  predicate cannot justify an exclusion while deriving the relation itself.
  Application requires independently bound actual execution and terminal facts;
  normal process completion establishes neither a passing subject verdict nor
  execution of a particular callback. No such projection supplies strict safety,
  native completion, source purity or an intermediate-effect bound.

  A bodyless call may instead consume the checked selected-assembly relation of
  REQ-impl-assembly-reference at that exact occurrence and context. The relation
  supplies its derived result and complete relevant heap/effects, never an
  expected return or caller-authored preserved-state summary. Continuing a checked
  region retains its current source state and the original source owner, entry,
  call contexts and resource account; copying a heap projection cannot establish
  a successor or restart the proof budget. Independently proved false guards may
  exclude throwing or other opaque arms without granting them call semantics.
  For a normal-return postcondition only, a checked continuation with no normal
  exit from the claimed invocation may exclude that outcome from the returned
  state relation. Every ordinary successor of the continuation is accounted for;
  an assumed nonreturning callee, a discovery bound or a cycle alone is not such
  evidence. Deferred recovery, callbacks and other control transfers capable of
  producing a normal return must be covered or refuse the exclusion. An opaque
  call on an excluded outcome retains arbitrary effects and exceptional or
  divergent behavior: exclusion supplies no purity, frame or intermediate-state
  theorem. A caller that recovers an exceptional exit cannot apply the callee's
  normal-return postcondition as though that invocation returned normally.

  Reusing a checked abstract call relation requires proving that its input
  relation includes the actual arguments, captured environment and incoming
  state, with a checked association of object identities, aliases and lifetimes.
  Applying the relation preserves its justified frame and accounts for every
  possible normal successor; exceptional scope remains explicit. Equal function
  names or cached output heaps cannot replace this judgment. Shared evidence and
  each application retain their complete dependencies and cumulative resource
  accounts, without renewing allocation identities or resetting allowances.
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
  entry states and are preserved on every edge, including backedges. Finite
  unfolding alone, unclosed invariants, unsupported effects, exhausted bounds or
  cancellation provide no accepted prefix of a frame theorem.
  Complete finite occurrence evidence may establish coverage and progress under
  REQ-impl-native-transition only with all required transfers checked and every
  residual frontier independently proved unreachable; no incomplete prefix
  acquires frame authority through its discovery bound.
- **calls-and-primitives** — Each call derives its frame by checked execution of
  the callee or composes a separately checked callee frame at the actual target,
  arguments, context and continuation under REQ-impl-callback-transfer and, when
  supplying an entry-to-cut state, REQ-impl-native-transition. Callee writes,
  escapes, callbacks and exceptional effects remain accounted for as required by
  REQ-impl-region-transport; an arbitrary return value is no substitute. Primitive external effects use only
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
