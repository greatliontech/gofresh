// Package nativeproof checks conditional value, effect, input and callback-transfer
// bounds in an immutable ELF image. It is an internal proof prerequisite, not a
// source-equivalence, whole-program, execution, termination, or freshness API.
//
// The caller supplies the invocation interface and machine conditions explicitly;
// no Go ABI table, symbol name, symbol size, compiler label, or hash establishes
// them. Under those conditions, Check's acyclic leaf graph has no data memory
// operations or calls except the specified near-return slot read. Branch
// decisions and declared result bits depend only on declared input bits and
// instruction constants; selected preserved bits are never written. Undeclared
// scratch bits and incoming arithmetic flags are arbitrary. Instruction fetch,
// RET's stack read and RSP increment, and the excluded surrounding execution are
// expressly part of the conditional model.
//
// The trusted mechanism comprises debug/elf's structural reader, the pinned
// x/arch/x86asm decoder, and this package's operand interpretation, mapping, graph
// and abstract transfer rules. Shared operand interpretation sign-extends disp32
// for 64-bit addressing while retaining full-width absolute moffs addresses;
// domain-specific encoding and form checks still govern admission.
// Structural decoding recognizes operand-free VEX.128/256.0F.WIG 77 directly
// from its prefix and opcode, retaining exactly the VZEROUPPER/VZEROALL bytes
// without borrowing a following instruction as ModRM. This includes both VEX
// prefix lengths, requires reserved vvvv=1111 and pp=00, and grants no VEX
// execution semantics. Other VEX/EVEX entries in the pinned decoder's three
// opcode-map tables require ModRM; structural decoding checks its presence
// before the decoder selects an operand form. The decoder checks subsequent
// SIB, displacement, immediate and is4-selector availability itself.
// Successful bare VEX/EVEX decoding retains 64-bit mode/address context and
// left-aligned opcode/ModRM/SIB bits under x86asm's convention; DataSize remains
// its scalar size attribute, not vector width. Non-SIB mod=00,r/m=101 memory
// operands retain RIP and signed disp32 with PC-relative length/offset metadata;
// SIB's no-base form remains distinct. Structural admission rejects explicit
// invalid-prefix markers, not ignored prefixes or valid unsupported operations
// (including UD2). These repairs confer no vector execution authority.
// The proposer supplies only an untrusted instruction/edge inventory. The
// checker independently decodes reachable image bytes and computes transfers;
// it never uses a proposed semantic summary. Known-bit/definedness propagation
// is conservative, with no path-value exclusion or functional source relation.
// All conditional successors are checked, cycles and unsupported operations
// refuse, and no size or exploration budget can terminate a successful proof.
// DeriveRelation additionally interprets the checked graph as immutable scalar
// expressions, retaining exact register projections and path-conditioned merges.
// A separate equality checker must relate those expressions to selected source;
// neither input dependence nor symbolic evaluation alone establishes that relation.
// A zero-result interface retains the complete effect and return obligations.
//
// CheckDescriptor binds a readonly loaded entry word to a checked same-image
// target. CheckCall verifies a local decoded transfer through that target,
// including descriptor and declared stack-argument reads, the protected eight-byte
// CALL write, argument/context identity and the return transition. Its incoming
// descriptor provenance, loaded-memory integrity and invocation/frame conditions
// remain explicit premises. It does not establish which registration row selected
// the descriptor, or lift isolated invocation to ordinary Go suspension/resumption.
// CallbackRules identifies this composition separately from the leaf RuleModel.
//
// CheckFrame derives byte-region read/write footprints and context preservation
// through a bounded acyclic graph. Its memory permissions, entry pointer ranges,
// lifetimes, return slot and absence of hidden aliases are explicit conditions;
// image overlap and load permissions are independently checked. Stores invalidate
// overlapping pointer-byte facts, and only checked full-word spills/reloads
// preserve pointer provenance. Unknown loaded values cannot authorize addressing.
// The frame does not establish memory-value or scalar-output determinism, source
// correspondence, or whole-harness noninterference. Calls and external primitives
// remain unsupported in this domain. FrameRules identifies these distinct rules;
// ordinary Go isolation and suspension/resumption lifting remain open obligations.
//
// CheckValueCall adds a distinct conditional value/frame scope: explicit entry
// constants and checked immutable image bytes, a bounded state-sensitive graph,
// and one actual direct CALL through every callee return. The enabled-SSE2 model
// interprets exact scalar/vector forms; decoded predicates alone exclude paths.
// Its output is the derived memory result and complete access/frame bound at the
// immediate decoded continuation, not a scalar-register or enclosing-caller
// result. Unknown bits/bytes remain arbitrary, undefined flags remain unsupported
// when consumed, and CPU selectors or loops are never removed by ABI/CPU labels.
// ValueCallRules and ValueCallMachine retain this scope separately: neither the
// old leaf Certificate nor FrameCertificate can express its initial-value facts.
//
// CheckTransition establishes a distinct ELF-entry-to-unexecuted-cut relation.
// One fresh stack origin is universally quantified over explicit bounds,
// congruence and external/image-page disjointness; joint nonemptiness is checked
// before deriving state. Relative address envelopes, memory permissions and
// arbitrary initial byte/word contents are separate. Exact scalar expressions
// share the value calculus, while origin arithmetic and alignment justify their
// pointer provenance under the retained conditions. Full ordered pointer lanes
// survive spills and reloads; numeric coincidence cannot create an origin.
// The transition grammar admits byte/32/64-bit MOV (including base/displacement
// and RIP-relative accesses), full-width LEA, constant SUB, justified alignment
// AND, nonwriting 32/64-bit CMP/TEST and the ten direct conditions over CF, ZF and
// SF!=OF, alongside relative JMP/fallthrough, constant ADD, direct near CALL,
// register PUSH/POP and near RET. Stack operations use the same current bytes;
// CALL stores the actual decoded continuation and RET proves equality of its
// current readable return word to that active context. PUSH/POP of RSP retain
// architectural ordering. Restored RSP does not roll back writes or effects.
// Exact unprefixed CPUID requires the optional
// CPUIDModel architectural-step condition. Each checked occurrence introduces
// four independent BV32 outcomes in a fresh private scope, zero-extends their
// register writes and destroys destination provenance. An ordered value-form
// primitive record retains old selectors and outcomes even after overwrite;
// free-variable analysis of final state alone cannot establish purity. The event
// retains ISA serialization, not timing or host-state claims. These quantified
// outcomes are not hardware observations or caller-provided expected values.
// Narrow register writes clear pointer provenance; partial memory overwrites
// clear affected pointer lanes even when the scalar bytes agree. One instruction
// occurrence owns each reach guard; accesses and primitive effects inherit it by
// activation and PC. Identical image bytes may execute in separate activations;
// their guards and outcome scopes never collapse. Call-free domains accept only
// root-context inventories. Filtering the deterministic topological order gives the actual trace. An
// inactive query's arbitrary outcome totalizations cannot affect that trace or
// the merged state. Registers, private predicates and every declared byte merge
// by guarded ITE; provenance survives only identical facts on all contributing
// arms. Entry predicates retain explicit immutable architectural identities even
// after flag overwrites. Structurally valid unsupported transfers can terminate
// discovery only with independently proposed and checked BOOL-false proofs for
// their complete incoming guards. Their bytes/extents remain structural coverage,
// without fetch, call, return or other execution effects. Structural decoding
// failure and discovered cycles always refuse. Complete-cut induction combines
// exact edge partitions, complete incoming unions and checked false terminals;
// its actual symbolic reach term remains unchanged, never replaced by closure.
// The cut instruction is not executed or relabeled RET. Arithmetic flag values
// may be unprojected, never invented or mistaken for preservation. No normal
// return, source storage, process-argument meaning, completed bootstrap or public
// runtime authority follows from this conditional state relation.
//
// ProposeTransition's optional occurrence-qualified expansion choices are
// untrusted search input. By default CALL and SYSCALL remain structural terminals,
// accepted only with an independent proof that the complete incoming guard is
// false. An excluded CALL has no push, target inspection or invented continuation;
// even an unmapped or cyclic target is outside that excluded scope. An expanded
// callee may contain its own independently excluded boundaries. Unused, duplicate
// or wrong-operation choices refuse. No budget/cancellation failure substitutes
// a successful boundary. A numeric cut means first hit, with exactly one
// activation context in the stopped graph; ambiguous contexts and advancing to a
// later occurrence of the same numeric cut are unsupported. The resolved context
// is retained, so later explicit occurrence selection can preserve this theorem.
//
// LinuxAMD64SyscallModel and its explicit 48/57-bit address configuration admit
// the ordinary native ARCH_SET_FS relation. Actual low RAX/RDI selectors must be
// checked; valid unsigned RSI establishes zero and the effective FS base, while
// an invalid base yields raw -EPERM without changing FS. Unknown validity retains
// both outcomes. Pointer/value agreement and checked origin bounds may establish
// that the whole argument range is valid. This supplies neither mapping nor a
// pointer from an equal scalar. FS displacement-only MOV accesses resolve through
// argument-derived provenance into the existing byte map, with full-width,
// canonical arithmetic and existing permissions. The arbitrary initial FS input
// supplies no TLS heap. Syscall effects survive overwrites and returns.
// RCX is the decoded next IP and the three status predicates are preserved.
// R11's unprojected deterministic saved flags have a distinct occurrence-scoped
// analysis abstraction: all actual values are included, with no claimed Linux
// nondeterminism or fabricated entry flags. Context changes invalidate blanket
// preservation; no zero FS selector is asserted. Actual executor applicability,
// source-storage correspondence and ordinary runtime reuse remain separate.
//
// Root image footprints select absolute bytes in the owned PT_LOAD mappings;
// permissions and backing-alias checks share the frame domain's mapping policy.
// Their initial values are fresh arbitrary scalars, including readonly and BSS
// bytes, unless the root explicitly selects CheckImageInitialization's opaque
// partial relation. Under StaticELFInitialization, checked logical file bytes
// acquire owned file values and independent readable/writable/non-executable BSS
// acquires zeros. Readonly BSS remains unknown, including partial clears on ignored
// failure. Page/backing aliases and aggregate loading-operation footprints govern
// coverage; padding adds no storage. The relation shares immutable image backing,
// refuses equal-byte foreign owners and retains actual-loader applicability.
// It never allocates BSS or creates pointers from initialized scalars. Stack and image
// provenance have separate coordinates in one current byte state. Checked RIP
// address formation can introduce image provenance; matching scalar bits cannot.
// Ordered lanes preserve either pointer kind across mixed-memory spills and
// reloads. Representable pointers alone grant no access, and pointer-kind tags do
// not prove numerical inequality outside the declared disjoint footprints.
//
// CheckTransitionContinuation consumes only an immutable predecessor and a full
// root-to-new-cut proposal. It reconstructs the prefix stopping at the old cut,
// checks exact membership/edges, including excluded terminals and their private
// proof roots, and that the old cut separates every feasible full path,
// inherits the same symbolic inputs and derived state, and executes only the
// suffix. Normalized root limits and cumulative work also govern inherited terms,
// copies, nested exclusion search/checking and the combined graph, including
// primitive-only roots; a new segment
// cannot reset those bounds. Aggregate live node-state bytes are bounded before
// allocation; consumed states are released rather than enumerating whole paths.
// Original entry, initial predicates, guards and prior outcome identities survive,
// while new occurrences and sibling queries have distinct scopes. Mapping
// and interference conditions remain premises over the longer scope, rather than
// actual stability facts inferred from the predecessor. No replacement image,
// interface, heap, expected result or per-segment limits can be supplied. Initial
// image facts are applied only at the root; continuation restores current bytes,
// including conditional writes, without reinitializing them.
//
// NewImage binds a copied byte image, not a filesystem or execution observation.
// Its consumer must supply the existing inspected-artifact ownership and span
// binding before composing this claim. Even that composition supplies neither
// source-instance/startup coverage nor runtime-reuse authority.
package nativeproof
