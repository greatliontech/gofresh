package nativeproof

import (
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// TransitionRules identifies the conditional symbolic-origin transition rules,
// including initialized image roots, guarded exclusions, decoder, expression,
// pointer-lane, bounded conditional entry/return relations and CPUID dependencies.
const TransitionRules = "gofresh/native-transition@18;" + ValueRules + ";" + cpuidRules + ";" + archSetFSRules + ";" + imageInitializationRules + ";" + TransferRules

// LockedMemoryModel requires cacheable write-back coherent RAM, power-of-two cache
// lines of at least eight bytes aligned to their size, and enabled architectural
// locked memory operations outside transactional/enclave contexts, with no
// applicable bus/split-lock, debug or virtualization fault/interposition. The
// checker establishes natural alignment for each admitted one-, four- or eight-byte
// operand, preventing page/cache-line splitting.
// Mapping, alias and interference
// conditions remain required. This is configuration, not a normal-return premise.
const LockedMemoryModel = "x86-64/aligned-locked-memory-ordinary-ram@1"

const archSetFSRules = "gofresh/native-linux-arch-set-fs@1"

// LinuxAMD64SyscallModel identifies conventional native 64-bit SYSCALL dispatch
// and SYSRET/IRET return in the same thread, with ordinary architectural flags
// (no VM/NT/TF return condition), valid user CS/SS, and no behavior-changing
// seccomp, ptrace, user dispatch, probes, signals or other entry/return work.
// Transparent scheduling/VM handling preserves the exposed state. This is an
// explicit applicability premise, not an observed syscall or success assertion.
// User FSGSBASE enablement is not required. UserAddressBits selects the ceiling.
const LinuxAMD64SyscallModel = "linux/x86-64/native-uninterposed-syscall@1"

const cpuidRules = "gofresh/native-cpuid@1"

// CPUIDModel identifies the ordinary x86-64 architectural CPUID step: available
// and enabled at the executing privilege level, with applicable faulting controls
// disabled, outside transactional/enclave abort or exception contexts and without
// a guest-visible exception or unproved handler path. ISA-conforming virtual CPUs,
// microcode and transparent host VM exits below this layer are admitted. This is
// a configuration predicate, not an assumption of normal completion or an observed
// response. Fetch, isolation, debug and other machine premises remain required.
const CPUIDModel = "x86-64/cpuid-enabled-architectural-step@1"

// RelativeSpan is a half-open byte extent relative to the single stack origin.
// An envelope permits its End as a pointer, but grants no memory permission.
type RelativeSpan struct{ Start, End int64 }

// OriginDomain quantifies S over inclusive low-canonical bounds and S % Modulus
// == Residue. Modulus must be a positive power of two. Declared external memory
// must additionally be page-disjoint from every image mapping. These conditions
// are conjunctive and must admit at least one S; no concrete runtime S is input.
type OriginDomain struct{ Min, Max, Modulus, Residue uint64 }

// RelativeRegion declares stable ordinary RAM and bounds the accesses this proof
// may use, independently of the address envelope. Mapping premises require every
// granted permission; false grants none without asserting that the underlying
// page lacks it. Overlapping regions must agree on their declared permissions.
type RelativeRegion struct {
	Bytes              RelativeSpan
	Readable, Writable bool
}

// TransitionConditions retains machine, loading, fault and interference premises
// for an entry-to-cut scope. A continuation retains these as premises over the
// entire longer scope, not as observed stability facts from its predecessor.
// Machine uses MachineModel's baseline execution restrictions;
// no implicit return slot or normal-completion premise is imported. ReturnContext
// separately declares an incoming callee continuation. EntryState asserts
// applicability of the declared symbolic state at the bound entry. InstructionMapping
// has Conditions' static ELF/4KiB meaning. IsolatedExecution excludes asynchronous
// behavior-changing interference, external termination and unmodeled thread or
// context replacement before the cut. Identified primitive effects and
// transparent scheduling preserving the exposed state remain accounted for.
// MemoryMapping, NoHiddenAliases and UnalignedAccess have FrameConditions' ordinary
// RAM, stable permissions, distinct-byte and alignment-exception meanings.
type TransitionConditions struct {
	Machine string
	// SSE optionally selects SSEModel. Its vector state and unchanged floating
	// context belong to the original root and cannot be added by continuation.
	SSE string
	// CPUID is optional for scopes that do not execute a query. Executing CPUID
	// requires CPUIDModel; an unknown nonempty model is unsupported in any scope.
	CPUID string
	// LockedMemory is optional; executing memory CMPXCHG32/64, XCHG64, XADD64
	// or byte AND/OR requires LockedMemoryModel and the checked locking form.
	// Continuations inherit it unchanged; selecting it requires a fresh root.
	LockedMemory string
	// Syscall is optional; nonempty selects LinuxAMD64SyscallModel. Address bits
	// must then be 48 or 57, identifying TASK_SIZE_MAX, not a kernel approval label.
	Syscall                                           string
	UserAddressBits                                   int
	InstructionMapping, EntryState, IsolatedExecution bool
	MemoryMapping, NoHiddenAliases, UnalignedAccess   bool
}

// TransitionInterface declares only entry premises. RSP is the fresh origin S;
// other registers and flags are arbitrary except for explicit entry relations.
// Each Words offset introduces a
// fresh arbitrary 64-bit scalar in eight readable bytes, with no pointer or
// process-argument meaning. Other declared bytes are fresh arbitrary bytes;
// undeclared memory remains arbitrary and inaccessible. Expected outputs and
// caller-supplied symbolic values are deliberately absent.
type TransitionInterface struct {
	Origin   OriginDomain
	Envelope RelativeSpan
	Regions  []RelativeRegion
	// ImageRegions grants access only within these absolute extents. Permissions
	// come from the owned PT_LOAD mappings. Initial bytes are arbitrary unless
	// covered by Initialization. Instruction fetch is separate.
	ImageRegions []Span
	// Initialization optionally refines root image bytes under its retained loading
	// applicability condition. Only a fresh root check may select this relation.
	Initialization ImageInitialization
	// EntryImagePointers binds distinct full GPRs other than RSP to owned,
	// declared readable image addresses. It grants no additional dereference
	// permission. EntryWordUpperBounds constrains current arbitrary image bytes,
	// never ELF data initialization. Both are conditional-region root premises;
	// ELF roots refuse them and continuations inherit them without additions.
	EntryImagePointers   []TransitionEntryImagePointer
	EntryWordUpperBounds []TransitionEntryWordUpperBound
	// ReturnContext optionally binds an incoming callee continuation. Only a
	// fresh conditional root can select it. Its original S[0:8] control word is
	// protected against every write, independently of memory write permissions.
	ReturnContext *TransitionReturnContext
	// PrivateFrame optionally retains a separate ownership/lifetime antecedent.
	// It grants neither permissions nor automatic projection of frame effects.
	PrivateFrame *TransitionPrivateFrame
	Words        []int64
	Conditions   TransitionConditions
}

// TransitionEntryImagePointer requires the original full register bits to equal
// Address and assigns owned image provenance. It supplies no source-object or
// runtime meaning. Address must identify a declared readable mapped byte.
type TransitionEntryImagePointer struct {
	Register Register
	Address  uint64
}

// TransitionEntryWordUpperBound requires the unsigned little-endian 64-bit word
// in eight declared readable image bytes at Address to be strictly less than
// original RSP + OriginOffset. The signed offset must be canonical and nonwrapping
// throughout the origin domain. Overlapping relations refer to the same bytes.
// These image extents also expose the complete memory dependency of the entry
// relations for consumers checking separation from a source representation.
type TransitionEntryWordUpperBound struct {
	Address      uint64
	OriginOffset int64
}

// TransitionLimits bounds graph/expression work and finite declared memory.
// Zero selects defaults; exhaustion never establishes an endpoint. Continuations
// inherit the root's normalized limits, cumulative construction work and complete
// instruction inventory (including the new unexecuted cut).
type TransitionLimits struct {
	RelationLimits
	Regions, Bytes int
	// LiveStateBytes bounds aggregate live node states, including byte maps.
	LiveStateBytes int
}

// TransitionProposal is an untrusted complete entry-to-cut instruction inventory.
// The checker obtains Entry independently from the owned ELF header or explicit
// conditional-region entry argument; the proposal cannot select that authority. The cut node
// has no executed successors; its actual instruction is retained separately.
// Unsupported structural terminals also have no successors; only the checker
// can establish their exclusions. A continuation supplies the complete inventory
// from the original entry, including those terminals.
type TransitionProposal struct {
	ImageDigest [32]byte
	Entry, Cut  uint64
	Root        TransitionOccurrenceID
	Nodes       []TransitionNode
	// After zero selects the numeric whole-root first hit. Nonzero selects the
	// first target encounter after the opaque predecessor's boundary executes;
	// checking requires exact equality with that predecessor-owned boundary ID.
	After TransitionOccurrenceID
}

// TransitionEndpointMode identifies the checked endpoint selection rule.
type TransitionEndpointMode uint8

const (
	// TransitionNumericFirstHit selects the original scope's first target hit.
	TransitionNumericFirstHit TransitionEndpointMode = iota + 1
	// TransitionFirstAfter selects the first target hit after its bound anchor.
	TransitionFirstAfter
)

// TransitionEndpoint is a non-authorizing endpoint projection. Cut is the
// independently resolved common occurrence, not a caller-selected node. Actual
// callee completion may anchor the same rule at its exact checked terminal RET.
type TransitionEndpoint struct {
	Mode        TransitionEndpointMode
	Anchor, Cut TransitionOccurrenceID
}

// TransitionOccurrenceID identifies one node within its owning proof. Zero is invalid.
type TransitionOccurrenceID uint64

// TransitionActivationID identifies an actual call activation within its proof.
// Zero is the root; a child is identified by its invoking CALL occurrence.
type TransitionActivationID uint64

// TransitionNode proposes one finite occurrence and its ordered decoded edge slots.
// Expanded selects an optional transfer. Frontier instead defers a supported
// transfer and requires an independently checked false incoming guard. Neither
// choice supplies execution semantics. Activation and decreasing rank are derived.
type TransitionNode struct {
	ID                 TransitionOccurrenceID
	PC                 uint64
	Size               uint8
	Successors         []TransitionOccurrenceID
	Expanded, Frontier bool
}

// TransitionOptions controls untrusted discovery only. MaxOccurrences bounds
// path depth, leaving decoded residual frontiers; zero requests acyclic discovery.
// The resource limits remain refusal boundaries, never successful endpoints.
type TransitionOptions struct {
	MaxOccurrences int
	Expansions     []TransitionExpansion
}

// TransitionExpansion selects a static optional form in an activation during
// discovery. ID zero selects every repeat; a nonzero ID selects that occurrence
// only. Checked projections always carry the exact occurrence ID. Unselected
// optional forms require a false incoming guard, even when semantics are available.
type TransitionExpansion struct {
	ID      TransitionOccurrenceID
	Context TransitionActivationID
	PC      uint64
	// AllActivations is discovery-only: select this exact static form in each
	// discovered activation. Checked projections always qualify the occurrence.
	AllActivations bool
}

// TransitionPointer is a closed provenance sum. Nil means no provenance. Its
// address arms identify a symbolic stack origin or an owned image mapping.
// A private entry-value arm retains caller value/provenance lineage without any
// address capability. Equality of scalar values never creates these facts.
// Distinct arms do not prove numerical
// inequality outside the declared, disjoint memory footprints.
type TransitionPointer interface{ transitionPointer() }

// OriginPointer associates an exact signed offset with the fresh scalar origin.
type OriginPointer struct {
	Origin br.Term
	Offset int64
}

func (OriginPointer) transitionPointer() {}

// ImagePointer identifies an address within one owned logical load (including
// its canonical one-past address). The private backing owner survives Image's
// container snapshots, but not independent construction from equal bytes.
type ImagePointer struct {
	Address uint64
	owner   *byte
	load    int
}

func (ImagePointer) transitionPointer() {}

// entryValueLineage is parametric caller context, not a third address space.
// Complete ordered word copies preserve the original bits and any caller-side
// provenance; arithmetic, partial writes and incomplete lanes cannot recreate it.
// Distinct tokens assert neither inequality nor nonaliasing. Actual application
// substitutes the caller's existing value/provenance, never an address from bits.
type entryValueLineage struct{ value br.Term }

func (entryValueLineage) transitionPointer() {}

func addressCapability(p TransitionPointer) TransitionPointer {
	switch p.(type) {
	case OriginPointer, ImagePointer:
		return p
	}
	return nil
}

// TransitionLocation is a byte coordinate in the single current memory map.
// Image selects an absolute low-canonical address; otherwise Offset is relative
// to S. The namespaces are disjoint only for declared accessible memory.
type TransitionLocation struct {
	Image  bool
	Offset int64
}

// TransitionValue is a scalar relation with separately justified provenance.
type TransitionValue struct {
	Value   br.Term
	Pointer TransitionPointer
}

// TransitionByte is a byte relation at a tagged stack/image location. PointerLane
// is meaningful only with a non-nil Pointer and reconstructs provenance only
// when all eight ordered lanes of the same pointer are loaded together.
type TransitionByte struct {
	TransitionLocation
	Value       br.Term
	Pointer     TransitionPointer
	PointerLane uint8
}

// TransitionWord records a fresh arbitrary input word, not an expected output.
type TransitionWord struct {
	Offset int64
	Value  br.Term
}

// TransitionAccess retains a conditional full-operand access. ID identifies the
// owning instruction guard; filtering those guards yields execution order.
type TransitionAccess struct {
	ID      TransitionOccurrenceID
	PC      uint64
	Context TransitionActivationID
	Kind    AccessKind
	Bytes   RelativeSpan
	// Image selects absolute low-canonical coordinates in Bytes.
	Image bool
	// Value is the read value or supplied write value at this exact occurrence,
	// at the full access width. Later writes cannot replace this dependency.
	Value br.Term
}

// PrimitiveEffect is a closed sum of checked machine/OS primitive occurrences.
// Each ID inherits its exact instruction occurrence's guard. Filtering those guards supplies the
// occurrence order and interleaving with other transfers. These are dependencies,
// not observations or claims that every listed occurrence executes.
type PrimitiveEffect interface{ primitiveEffect() }

// CPUIDEffect retains a serializing architectural query even when all results
// are overwritten. Leaf/Subleaf are the old low RAX/RCX bits; each result is an
// independent arbitrary BV32 in this occurrence's private scope. It claims no
// repeatability, feature consistency, latency, cache, TLB or host-state behavior.
type CPUIDEffect struct {
	ID                                             TransitionOccurrenceID
	PC                                             uint64
	Context                                        TransitionActivationID
	Leaf, Subleaf                                  br.Term
	ResultsEAX, ResultsEBX, ResultsECX, ResultsEDX br.Term
}

func (CPUIDEffect) primitiveEffect() {}

// ArchSetFSEffect retains the exact raw result/effective-base relation. R11's
// analysis abstraction is recorded separately; it is not an OS outcome variable.
// The operation preserves ordinary user memory and other GPRs, writes RCX to
// next IP, saves RF-cleared flags in R11, clears RF on return and establishes
// native user CS/SS. Effective FS success does not specify its selector.
type ArchSetFSEffect struct {
	ID                                                        TransitionOccurrenceID
	PC                                                        uint64
	Context                                                   TransitionActivationID
	Number, Operation, Base, Valid, Result, BeforeFS, AfterFS br.Term
}

func (ArchSetFSEffect) primitiveEffect() {}

// LockedCompareExchangeEffect groups two adjacent accesses into one indivisible
// locked RMW occurrence, with architectural locked ordering relative to memory
// operations. ReadAccess and WriteAccess index the complete cumulative Accesses.
// The write always occurs, including failed writeback. Before, Compare and
// Replacement are captured before any write; After and Accumulator are the
// derived memory and RAX outputs, and Success is their equality predicate. This
// event survives result overwrites and supplies no concurrent-history theorem.
// Width is the memory width in bytes (4 or 8); Accumulator is always full RAX.
type LockedCompareExchangeEffect struct {
	ID                                                        TransitionOccurrenceID
	PC                                                        uint64
	Context                                                   TransitionActivationID
	Width                                                     int
	ReadAccess, WriteAccess                                   int
	Before, Compare, Replacement, After, Accumulator, Success br.Term
}

func (LockedCompareExchangeEffect) primitiveEffect() {}

// LockedLogicalEffect retains an indivisible byte AND/OR and architectural locked
// ordering, including unchanged writes. Kind is AND or OR, Width is one byte, and
// access indices identify the adjacent read/write in the cumulative access trace.
// Before and Operand are incoming values; After is their bitwise result.
type LockedLogicalEffect struct {
	ID                      TransitionOccurrenceID
	PC                      uint64
	Context                 TransitionActivationID
	Kind                    x86asm.Op
	Width                   int
	ReadAccess, WriteAccess int
	Before, Operand, After  br.Term
}

func (LockedLogicalEffect) primitiveEffect() {}

// LockedExchange64Effect retains an indivisible memory XCHG with architectural
// locked ordering, including its implicit lock without a LOCK prefix. Access
// indices address the cumulative access trace; the write occurs even for equal
// values. All scalar inputs precede the memory and register writes.
type LockedExchange64Effect struct {
	ID                                   TransitionOccurrenceID
	PC                                   uint64
	Context                              TransitionActivationID
	ReadAccess, WriteAccess              int
	Before, Replacement, After, Register br.Term
}

func (LockedExchange64Effect) primitiveEffect() {}

// LockedExchangeAdd64Effect retains an indivisible LOCK XADD and architectural
// locked ordering. Before and Delta are incoming values; Register is the old
// memory and After its modular sum. Even a zero delta retains both accesses.
type LockedExchangeAdd64Effect struct {
	ID                             TransitionOccurrenceID
	PC                             uint64
	Context                        TransitionActivationID
	ReadAccess, WriteAccess        int
	Before, Delta, After, Register br.Term
}

func (LockedExchangeAdd64Effect) primitiveEffect() {}

// TransitionAbstraction records deliberate loss of precision, not machine
// nondeterminism. Value universally over-approximates the saved architectural
// RFLAGS at this occurrence. Predicates retain its available incoming flag
// dependencies; no correlation with Value is claimed. Every actual saved value
// is included, and a consumer needing that lost correlation must refuse.
type TransitionAbstraction struct {
	ID         TransitionOccurrenceID
	PC         uint64
	Context    TransitionActivationID
	Value      br.Term
	Predicates TransitionPredicates
}

// TransitionThread is the current root thread's effective FS state. No TLS
// storage is allocated. ContextChanged invalidates blanket unchanged-context
// claims; the retained syscall effects specify the actual architectural relation.
type TransitionThread struct {
	FS                TransitionValue
	SelectorPreserved bool
	ContextChanged    bool
}

// TransitionFrame is an active checked call's continuation and actual stack slot.
// It carries no saved caller heap/register snapshot and grants no permissions.
type TransitionFrame struct {
	ID           TransitionOccurrenceID
	Context      TransitionActivationID
	Call, Return uint64
	Slot         OriginPointer
}

// TransitionFlag describes an architectural status independently of projection.
// Preserved flags retain their arbitrary entry value; Defined flags may have no
// projected value. Defined=false means definedness is not guaranteed across the
// complete scope, not that every execution leaves the flag undefined. Unavailable
// values have no invented symbolic replacement.
type TransitionFlag struct {
	Preserved, Defined bool
	Value              br.Term
}

// TransitionFlags covers the arithmetic flags. Direction is a separate always-
// defined Boolean. Other flag/context components follow the retained primitive/
// context relations when a syscall executes.
type TransitionFlags struct{ CF, OF, SF, ZF, AF, PF TransitionFlag }

// TransitionPredicates binds the three independent architectural entry predicates.
// SFXorOF means SF != OF, not either architectural flag separately.
type TransitionPredicates struct{ CF, ZF, SFXorOF br.Term }

// GuardedInstruction is the sole occurrence guard. Accesses and primitive effects
// inherit it by ID. Filtering this topological inventory gives the executed order.
type GuardedInstruction struct {
	ID TransitionOccurrenceID
	Span
	Guard   br.Term
	Context TransitionActivationID
}

// CutBoundary records a decoded but unexecuted instruction. Its bytes
// establish the boundary, not that its effects have been modeled.
type CutBoundary struct {
	ID          TransitionOccurrenceID
	PC          uint64
	Context     TransitionActivationID
	Instruction x86asm.Inst
	Bytes       []byte
}

// ExcludedBoundary is diagnostic structural coverage, not an executed fetch or
// transfer. The opaque certificate separately owns the exact checked false proof.
type ExcludedBoundary struct {
	CutBoundary
	Guard br.Term
	// Frontier distinguishes a deferred supported transfer from an unsupported boundary.
	Frontier bool
}

// TransitionBound is a cloned, non-authorizing projection. Origin exclusions are
// half-open scalar-S intervals induced by external/image-page disjointness, not
// chosen runtime bases. Registers and Memory are derived cut relations; memory
// outside FrameWrite footprints and preserved GPRs are unchanged. Primitive effects
// and Thread account for context changes; absence of a projection is not preservation.
// Instructions contains guarded fetch occurrences. Filtering their guards gives
// the executed trace. Boundary and ExcludedBoundaries are unexecuted.
type TransitionBound struct {
	Endpoint    TransitionEndpoint
	ImageDigest [32]byte
	Rules       string
	Entry       uint64
	// ConditionalRegion distinguishes a local entry premise from the ELF root.
	// This projection cannot select or change the opaque certificate's authority.
	ConditionalRegion bool
	Interface         TransitionInterface
	Origin            br.Term
	// EntryPredicate is the immutable conjunction of the typed entry relations
	// and their checked consequences under the retained origin domain, or true
	// when empty. Origin bounds/congruence and ExcludedOrigins remain
	// separate applicability predicates. Every occurrence starts under this
	// conjunction; a satisfying nonvacuity valuation is never projected.
	EntryPredicate    br.Term
	ExcludedOrigins   []Span
	InitialRegisters  [16]br.Term
	InitialVectors    TransitionVectors
	Vectors           TransitionVectors
	SSE               TransitionSSEContext
	InitialPredicates TransitionPredicates
	// InitialDirection is the arbitrary original DF input, independent of arithmetic
	// predicates and optional machine models. Direction is its current path-derived
	// value; calls and returns do not save or restore it implicitly.
	InitialDirection br.Term
	Direction        br.Term
	InitialMemory    []TransitionByte
	Words            []TransitionWord
	Registers        [16]TransitionValue
	Memory           []TransitionByte
	Preserved        Masks
	Flags            TransitionFlags
	Instructions     []GuardedInstruction
	// CutGuard is the derived reach expression, never inferred from graph closure.
	CutGuard           br.Term
	Accesses           []TransitionAccess
	PrimitiveEffects   []PrimitiveEffect
	Abstractions       []TransitionAbstraction
	InitialFS          br.Term
	Thread             TransitionThread
	Frames             []TransitionFrame
	Expansions         []TransitionExpansion
	Boundary           CutBoundary
	ExcludedBoundaries []ExcludedBoundary
}

// TransitionCertificate owns a conditional entry-to-cut theorem. It supplies no
// return, frame, value-call, source-startup or runtime reuse evidence by itself.
// CheckTransitionReturn can separately complete an eligible actual root RET.
// Its zero value carries no authority; projections cannot reconstruct it.
type TransitionCertificate struct{ checked *checkedTransition }
type checkedTransition struct {
	// witness is the sole owned structural occurrence inventory.
	witness TransitionProposal
	image   *Image
	bound   TransitionBound
	limits  TransitionLimits
	work    int
	// Private predicates and checked exclusion witnesses supplement the bound's
	// sole state/structural snapshot. No builder or predecessor is retained.
	flags          [flagCount]br.Term
	exclusions     []br.Witness
	justifications []br.Witness
	// coverageGuard binds the exact root of the complete-cut induction: incoming
	// guards are edge partitions and complete unions, and all other terminals
	// have independently checked false witnesses. The expression is not rewritten.
	coverageGuard br.Term
}

func cloneTransitionInterface(f TransitionInterface) TransitionInterface {
	f.Regions = append([]RelativeRegion(nil), f.Regions...)
	f.ImageRegions = append([]Span(nil), f.ImageRegions...)
	f.Words = append([]int64(nil), f.Words...)
	f.EntryImagePointers = append([]TransitionEntryImagePointer(nil), f.EntryImagePointers...)
	f.EntryWordUpperBounds = append([]TransitionEntryWordUpperBound(nil), f.EntryWordUpperBounds...)
	if f.ReturnContext != nil {
		c := *f.ReturnContext
		c.Preserved = append([]Register(nil), c.Preserved...)
		f.ReturnContext = &c
	}
	if f.PrivateFrame != nil {
		frame := *f.PrivateFrame
		f.PrivateFrame = &frame
	}
	return f
}

// Bound returns owned mutable projections and immutable expression handles.
func (c TransitionCertificate) Bound() (TransitionBound, bool) {
	if c.checked == nil {
		return TransitionBound{}, false
	}
	return cloneTransitionBound(c.checked.bound), true
}

// BoundFor projects only a theorem over this exact owned image. Equal bytes in a
// separately constructed image cannot borrow its provenance or entry relation.
func (c TransitionCertificate) BoundFor(im *Image) (TransitionBound, bool) {
	if c.checked == nil || !sameImage(c.checked.image, im) {
		return TransitionBound{}, false
	}
	return c.Bound()
}

func cloneTransitionBound(b TransitionBound) TransitionBound {
	b.Interface = cloneTransitionInterface(b.Interface)
	b.ExcludedOrigins = append([]Span(nil), b.ExcludedOrigins...)
	b.InitialMemory = append([]TransitionByte(nil), b.InitialMemory...)
	b.Words = append([]TransitionWord(nil), b.Words...)
	b.Memory = append([]TransitionByte(nil), b.Memory...)
	b.Instructions = append([]GuardedInstruction(nil), b.Instructions...)
	b.Accesses = append([]TransitionAccess(nil), b.Accesses...)
	b.PrimitiveEffects = append([]PrimitiveEffect(nil), b.PrimitiveEffects...)
	b.Abstractions = append([]TransitionAbstraction(nil), b.Abstractions...)
	b.Frames = append([]TransitionFrame(nil), b.Frames...)
	b.Expansions = append([]TransitionExpansion(nil), b.Expansions...)
	b.Boundary.Bytes = append([]byte(nil), b.Boundary.Bytes...)
	b.ExcludedBoundaries = append([]ExcludedBoundary(nil), b.ExcludedBoundaries...)
	for j := range b.ExcludedBoundaries {
		b.ExcludedBoundaries[j].Bytes = append([]byte(nil), b.ExcludedBoundaries[j].Bytes...)
	}
	return b
}
