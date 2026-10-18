package nativeproof

import (
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// TransitionRules identifies the conditional symbolic-origin transition rules,
// including initialized image roots, guarded exclusions, decoder, expression,
// pointer-lane and CPUID dependencies.
const TransitionRules = "gofresh/native-transition@10;" + ValueRules + ";" + cpuidRules + ";" + archSetFSRules + ";" + imageInitializationRules + ";" + TransferRules

// Locked64Model requires cacheable write-back coherent RAM, power-of-two cache
// lines of at least eight bytes aligned to their size, and enabled architectural
// locked memory operations outside transactional/enclave contexts, with no
// applicable bus/split-lock, debug or virtualization fault/interposition. The
// checker establishes eight-byte alignment, preventing page/cache-line splitting.
// Mapping, alias and interference
// conditions remain required. This is configuration, not a normal-return premise.
const Locked64Model = "x86-64/aligned-locked64-ordinary-ram@1"

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
// no return slot or normal-completion premise is imported. EntryState asserts
// applicability of the declared symbolic state at the bound entry. InstructionMapping
// has Conditions' static ELF/4KiB meaning. IsolatedExecution excludes asynchronous
// behavior-changing interference, external termination and unmodeled thread or
// context replacement before the cut. Identified primitive effects and
// transparent scheduling preserving the exposed state remain accounted for.
// MemoryMapping, NoHiddenAliases and UnalignedAccess have FrameConditions' ordinary
// RAM, stable permissions, distinct-byte and alignment-exception meanings.
type TransitionConditions struct {
	Machine string
	// CPUID is optional for scopes that do not execute a query. Executing CPUID
	// requires CPUIDModel; an unknown nonempty model is unsupported in any scope.
	CPUID string
	// Locked64 is optional; executing a locked CMPXCHG64 requires Locked64Model.
	// Continuations inherit it unchanged; selecting it requires a fresh root.
	Locked64 string
	// Syscall is optional; nonempty selects LinuxAMD64SyscallModel. Address bits
	// must then be 48 or 57, identifying TASK_SIZE_MAX, not a kernel approval label.
	Syscall                                           string
	UserAddressBits                                   int
	InstructionMapping, EntryState, IsolatedExecution bool
	MemoryMapping, NoHiddenAliases, UnalignedAccess   bool
}

// TransitionInterface declares only entry premises. RSP is the fresh origin S;
// all other registers and flags are arbitrary. Each Words offset introduces a
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
	Words          []int64
	Conditions     TransitionConditions
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
	Nodes       []Node
	// Expansions selects candidate coverage for TransitionExpansionRequired's
	// operation/operand families. An unselected occurrence is a structural
	// terminal requiring a checked false full incoming guard.
	Expansions []TransitionExpansion
}

// TransitionExpansion is an untrusted search choice, not a semantic premise. Context
// is the activation path emitted by discovery (empty at the bound root); PC names
// an actual optional operation/form within it (TransitionExpansionRequired). Only admitted operand forms can
// execute; selecting an unsupported form grants no semantics. Duplicate, unused or
// other choices refuse.
// Each ancestor CALL appends '/' and its PC in exactly sixteen lowercase hex
// digits, outermost first. This is a candidate coordinate, not an execution ID
// or persisted evidence. A proposer can expose a child's context by stopping at
// that child's first unexecuted boundary before proposing a longer scope.
// Unselected optional operations retain their structural-terminal interpretation,
// including when no primitive applicability condition is available.
type TransitionExpansion struct {
	Context string
	PC      uint64
}

// TransitionPointer is a closed provenance sum. Nil means no provenance. Its
// arms identify a symbolic stack origin or an owned image mapping; equality of
// scalar values never creates either. Distinct arms do not prove numerical
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

// TransitionAccess retains a conditional full-operand access. Context and PC identify
// the owning instruction guard; filtering those guards yields execution order.
type TransitionAccess struct {
	PC      uint64
	Context string
	Kind    AccessKind
	Bytes   RelativeSpan
	// Image selects absolute low-canonical coordinates in Bytes.
	Image bool
	// Value is the read value or supplied write value at this exact occurrence,
	// at the full access width. Later writes cannot replace this dependency.
	Value br.Term
}

// PrimitiveEffect is a closed sum of checked machine/OS primitive occurrences.
// Each activation/PC inherits its instruction's guard. Filtering those guards supplies the
// occurrence order and interleaving with other transfers. These are dependencies,
// not observations or claims that every listed occurrence executes.
type PrimitiveEffect interface{ primitiveEffect() }

// CPUIDEffect retains a serializing architectural query even when all results
// are overwritten. Leaf/Subleaf are the old low RAX/RCX bits; each result is an
// independent arbitrary BV32 in this occurrence's private scope. It claims no
// repeatability, feature consistency, latency, cache, TLB or host-state behavior.
type CPUIDEffect struct {
	PC                                             uint64
	Context                                        string
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
	PC                                                        uint64
	Context                                                   string
	Number, Operation, Base, Valid, Result, BeforeFS, AfterFS br.Term
}

func (ArchSetFSEffect) primitiveEffect() {}

// LockedCompareExchange64Effect groups two adjacent accesses into one indivisible
// locked RMW occurrence, with architectural locked ordering relative to memory
// operations. ReadAccess and WriteAccess index the complete cumulative Accesses.
// The write always occurs, including failed writeback. Before, Compare and
// Replacement are captured before any write; After and Accumulator are the
// derived memory and RAX outputs, and Success is their equality predicate. This
// event survives result overwrites and supplies no concurrent-history theorem.
type LockedCompareExchange64Effect struct {
	PC                                                        uint64
	Context                                                   string
	ReadAccess, WriteAccess                                   int
	Before, Compare, Replacement, After, Accumulator, Success br.Term
}

func (LockedCompareExchange64Effect) primitiveEffect() {}

// TransitionAbstraction records deliberate loss of precision, not machine
// nondeterminism. Value universally over-approximates the saved architectural
// RFLAGS at this occurrence. Predicates retain its available incoming flag
// dependencies; no correlation with Value is claimed. Every actual saved value
// is included, and a consumer needing that lost correlation must refuse.
type TransitionAbstraction struct {
	PC         uint64
	Context    string
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
	Context      string
	Call, Return uint64
	Slot         OriginPointer
}

// TransitionFlag describes an architectural status independently of projection.
// Preserved flags retain their arbitrary entry value; Defined flags may have no
// projected value. Undefined flags have no invented symbolic value.
type TransitionFlag struct {
	Preserved, Defined bool
	Value              br.Term
}

// TransitionFlags covers the arithmetic flags. Every other flag/context component
// follows the retained primitive/context relations when a syscall executes.
type TransitionFlags struct{ CF, OF, SF, ZF, AF, PF TransitionFlag }

// TransitionPredicates binds the three independent architectural entry predicates.
// SFXorOF means SF != OF, not either architectural flag separately.
type TransitionPredicates struct{ CF, ZF, SFXorOF br.Term }

// GuardedInstruction is the sole occurrence guard. Accesses and primitive effects
// inherit it by activation/PC. Filtering this topological inventory gives the executed order.
type GuardedInstruction struct {
	Span
	Guard   br.Term
	Context string
}

// CutBoundary records a decoded but unexecuted instruction. Its bytes
// establish the boundary, not that its effects have been modeled.
type CutBoundary struct {
	PC          uint64
	Context     string
	Instruction x86asm.Inst
	Bytes       []byte
}

// ExcludedBoundary is diagnostic structural coverage, not an executed fetch or
// transfer. The opaque certificate separately owns the exact checked false proof.
type ExcludedBoundary struct {
	CutBoundary
	Guard br.Term
}

// TransitionBound is a cloned, non-authorizing projection. Origin exclusions are
// half-open scalar-S intervals induced by external/image-page disjointness, not
// chosen runtime bases. Registers and Memory are derived cut relations; memory
// outside FrameWrite footprints and preserved GPRs are unchanged. Primitive effects
// and Thread account for context changes; absence of a projection is not preservation.
// Instructions contains guarded fetch occurrences. Filtering their guards gives
// the executed trace. Boundary and ExcludedBoundaries are unexecuted.
type TransitionBound struct {
	ImageDigest [32]byte
	Rules       string
	Entry       uint64
	// ConditionalRegion distinguishes a local entry premise from the ELF root.
	// This projection cannot select or change the opaque certificate's authority.
	ConditionalRegion bool
	Interface         TransitionInterface
	Origin            br.Term
	ExcludedOrigins   []Span
	InitialRegisters  [16]br.Term
	InitialPredicates TransitionPredicates
	InitialMemory     []TransitionByte
	Words             []TransitionWord
	Registers         [16]TransitionValue
	Memory            []TransitionByte
	Preserved         Masks
	Flags             TransitionFlags
	Instructions      []GuardedInstruction
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

// TransitionCertificate owns a conditional entry-to-cut theorem. It cannot be
// converted to return, frame, value-call, source-startup or runtime reuse evidence.
// Its zero value carries no authority; projections cannot reconstruct it.
type TransitionCertificate struct{ checked *checkedTransition }
type checkedTransition struct {
	image  *Image
	bound  TransitionBound
	limits TransitionLimits
	work   int
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
