package closure

import (
	"context"
	"fmt"
	"go/constant"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

const globalOperandRules = "gofresh/global-operand-correspondence@2;" + regionRules + ";" + nativeproof.TransitionRules

// globalRepresentation is an untrusted, scope-local witness, not compiler object
// placement or an authoritative types.Var-to-address map. Its source/image owners
// are part of the proposal, independently checked against both opaque endpoints.
type globalRepresentation struct {
	source  *program
	image   *nativeproof.Image
	globals [2]globalImageBinding
}

type globalImageBinding struct {
	global  *ssa.Global
	address uint64
}

// globalOperandCorrespondence relates one complete straight-line source prefix
// to one conditional native region before a decoded CMPXCHG boundary. It proves
// operand preparation, not the call/intrinsic's semantics or dispatch equivalence.
// No source heap is constructed from native projections. The source kernel starts
// at top; the mathematical initial relation interprets the retained arbitrary
// eight native bytes as that global's uint64 value. Proving each endpoint over
// independently arbitrary prior states is stronger than this paired antecedent.
//
// The representation remains fixed within this certificate. Consumers must
// check it at their actual uses or establish a transporting interface. It is
// not startup state, an ELF-root path, or a whole-source implementation grant.
type globalOperandCorrespondence struct {
	rules          string
	source         *sourceOperandPrefix
	native         nativeproof.TransitionCertificate
	representation globalRepresentation
	initial        [2]br.Term
	equalities     []br.Witness
	open           computationCorrespondenceObligations
	work, limit    int
}

type globalCorrespondenceLimits struct{ work int }

// This account spans equality construction and all later source/native
// continuations. Subordinate engines retain their own structural limits too.
type correspondenceContext struct {
	context.Context
	work, limit int
}

func (c *correspondenceContext) Err() error {
	if err := c.Context.Err(); err != nil {
		return err
	}
	if c.work >= c.limit {
		return fmt.Errorf("global correspondence: cumulative proof work exhausted")
	}
	c.work++
	return nil
}

// checkGlobalOperandCorrespondence consumes opaque independently derived endpoints
// and checks their effect/frame and actual operand relation. There is deliberately
// no expected-value input. Source objects remain under their immutable owner.
func checkGlobalOperandCorrespondence(ctx context.Context, source computationSource, root *ssa.Function, call *ssa.Call, image *nativeproof.Image, entry, cut uint64, prefix *sourceOperandPrefix, native nativeproof.TransitionCertificate, rho globalRepresentation, options ...globalCorrespondenceLimits) (*globalOperandCorrespondence, error) {
	fail := func(s string) (*globalOperandCorrespondence, error) {
		return nil, fmt.Errorf("global operand correspondence: %s", s)
	}
	if ctx == nil || image == nil || rho.image == nil || source.prog == nil || rho.source != source.prog || root == nil || prefix == nil || prefix.region == nil || prefix.region.packet == nil {
		return fail("missing or foreign source/image owner")
	}
	limit := 2_000_000
	if len(options) > 1 {
		return fail("more than one proof budget")
	}
	if len(options) == 1 {
		limit = options[0].work
	}
	if limit < 1 || limit > 20_000_000 {
		return fail("invalid proof work budget")
	}
	// Freeze containers before context callbacks can replace a caller's image.
	ownedImage, representationImage := *image, *rho.image
	rho.image = &representationImage
	meter := &correspondenceContext{Context: ctx, limit: limit}
	ctx = meter
	packet := prefix.region.packet
	if packet.rules != regionRules || packet.input.owner != source.prog.Prog || packet.input.root != root || prefix.region.root.function != root || prefix.call != call || packet.prefix == nil || len(packet.observations) != 1 || len(prefix.operands) != 3 {
		return fail("source prefix scope/owner differs")
	}
	b, ok := native.BoundFor(&ownedImage)
	if _, represented := native.BoundFor(rho.image); !ok || !represented || b.Rules != nativeproof.TransitionRules || !b.ConditionalRegion || b.Entry != entry || b.Boundary.PC != cut {
		return fail("native prefix scope/owner differs")
	}
	if len(b.Instructions) > 256 || len(b.InitialMemory) > 4096 || len(b.Memory) > 4096 {
		return fail("finite operand-prefix composition budget exceeded")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for i, binding := range rho.globals {
		g := binding.global
		if g == nil || g.Pkg == nil || g.Pkg.Prog != source.prog.Prog || source.prog.Prog.Package(g.Pkg.Pkg) != g.Pkg || g.Pkg.Members[g.Name()] != g || binding.address >= 1<<47 || binding.address > (1<<47)-8 {
			return fail("unowned global or invalid image extent")
		}
		p, ok := g.Type().Underlying().(*types.Pointer)
		if !ok || !types.Identical(p.Elem(), types.Typ[types.Uint64]) || prefix.region.root.pkg.TypesSizes.Sizeof(p.Elem()) != 8 || prefix.region.root.pkg.TypesSizes.Sizeof(g.Type()) != 8 {
			return fail("representation requires selected uint64 storage")
		}
		for _, old := range rho.globals[:i] {
			if old.global == g || binding.address < old.address+8 && old.address < binding.address+8 {
				return fail("aliased source objects or overlapping image extents")
			}
		}
	}
	// This finite grammar has exactly one overwrite of each object followed by
	// one ordinary load. Keeping that load in the checked source trace rules out
	// reads before overwrite, hooks and discarded extra effects even at equal endpoints.
	events := packet.prefix.events
	if len(events) != 3 || !events[0].write || !events[1].write || events[2].write || events[0].global == events[1].global {
		return fail("source effect population is outside the bounded relation")
	}
	address := func(g *ssa.Global) (uint64, bool) {
		for _, p := range rho.globals {
			if p.global == g {
				return p.address, true
			}
		}
		return 0, false
	}
	for _, e := range events {
		if _, ok := address(e.global); !ok {
			return fail("source effect is outside represented storage")
		}
		if _, ok := regionUint64(e.value); !ok {
			return fail("source read/write is not established independently of prior state")
		}
	}
	var written regionValue
	for _, e := range events[:2] {
		if e.global == events[2].global {
			written = e.value
		}
	}
	loaded, isValue := events[2].instruction.(ssa.Value)
	if !isValue || !regionSameValue(written, events[2].value) || call.Call.Args[1] != loaded || !regionSameValue(prefix.operands[1], events[2].value) {
		return fail("source operand load lacks its preceding overwrite relation")
	}
	ptr := prefix.operands[0]
	pointed, ok := ptr.location.object.site.(*ssa.Global)
	if ptr.kind != regionPointer || ptr.location.object.kind != regionGlobal || len(ptr.location.path) != 0 || !ok {
		return fail("source pointer operand lacks exact global provenance")
	}
	ptrAddress, ok := address(pointed)
	if !ok {
		return fail("source pointer operand is outside the representation")
	}
	// Decode evidence supplies the actual native operand shape only. No semantics
	// of this unexecuted atomic operation (or of the source callee) are asserted.
	boundary := b.Boundary.Instruction
	mem, isMemory := boundary.Args[0].(x86asm.Mem)
	if boundary.Op != x86asm.CMPXCHG || boundary.MemBytes != 8 || boundary.Mode != 64 || boundary.AddrSize != 64 || !isMemory || mem.Base != x86asm.RCX || mem.Index != 0 || mem.Disp != 0 || mem.Segment != 0 || boundary.Args[1] != x86asm.RDX || boundary.Args[2] != nil || boundary.Args[3] != nil || len(b.Boundary.Bytes) != 5 || string(b.Boundary.Bytes) != "\xf0\x48\x0f\xb1\x11" {
		return fail("cut is not the exact unexecuted native operand boundary")
	}
	if len(b.PrimitiveEffects) != 0 || len(b.Abstractions) != 0 || len(b.Frames) != 0 || len(b.ExcludedBoundaries) != 0 || b.Thread.ContextChanged || len(b.Accesses) != 2 {
		return fail("native effects or frame are outside the bounded relation")
	}
	for reg := nativeproof.RAX; reg <= nativeproof.R15; reg++ {
		if reg != nativeproof.RAX && reg != nativeproof.RCX && reg != nativeproof.RDX && b.Preserved[reg] != ^uint64(0) {
			return fail("native administrative context is not preserved")
		}
	}
	for i, access := range b.Accesses {
		a, _ := address(events[i].global)
		if !access.Image || access.Kind != nativeproof.FrameWrite || access.Bytes.Start != int64(a) || access.Bytes.End != int64(a+8) {
			return fail("native access population differs from represented source writes")
		}
	}
	nativePointer, ok := b.Registers[nativeproof.RCX].Pointer.(nativeproof.ImagePointer)
	if !ok || nativePointer.Address != ptrAddress {
		return fail("native pointer provenance differs from actual source operand")
	}
	builder := br.NewBuilder(4096)
	proof := &globalOperandCorrespondence{rules: globalOperandRules, source: prefix, native: native, representation: rho,
		open: computationCorrespondenceObligations{true, true, true, true, true}}
	prove := func(left, right br.Term) error {
		w, err := br.Prove(ctx, left, right, br.Limits{})
		if err == nil {
			proof.equalities = append(proof.equalities, w)
		}
		return err
	}
	truth, _ := builder.Const(br.Bool(), 1)
	for _, ins := range b.Instructions {
		if err := prove(ins.Guard, truth); err != nil {
			return nil, err
		}
	}
	if err := prove(b.CutGuard, truth); err != nil {
		return nil, err
	}
	for i, binding := range rho.globals {
		initial, err := globalNativeWord(ctx, builder, b.InitialMemory, binding.address)
		if err != nil {
			return nil, err
		}
		proof.initial[i] = initial
		current, err := globalNativeWord(ctx, builder, b.Memory, binding.address)
		if err != nil {
			return nil, err
		}
		v := readRegionLocation(packet.observations[0].state, regionLocation{object: regionObject{kind: regionGlobal, site: binding.global}}, types.Typ[types.Uint64])
		x, ok := regionUint64(v)
		if !ok {
			return fail("source current heap is not established")
		}
		term, _ := builder.Const(br.Bits(64), x)
		if err := prove(term, current); err != nil {
			return nil, err
		}
	}
	for i, reg := range []nativeproof.Register{nativeproof.RCX, nativeproof.RAX, nativeproof.RDX} {
		x := ptrAddress
		if i != 0 {
			var ok bool
			x, ok = regionUint64(prefix.operands[i])
			if !ok {
				return fail("source scalar operand is not a checked uint64")
			}
		}
		term, _ := builder.Const(br.Bits(64), x)
		if err := prove(term, b.Registers[reg].Value); err != nil {
			return nil, err
		}
	}
	// The native certificate frames all memory outside its actual writes. Retain
	// explicit equalities for declared unrelated bytes too, including arbitrary
	// initial payloads; missing projection never becomes a preservation assertion.
	currentMemory := make(map[nativeproof.TransitionLocation]nativeproof.TransitionByte, len(b.Memory))
	for _, current := range b.Memory {
		currentMemory[current.TransitionLocation] = current
	}
	for _, old := range b.InitialMemory {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		written := false
		for _, p := range rho.globals {
			written = written || old.Image && old.Offset >= int64(p.address) && old.Offset < int64(p.address+8)
		}
		if written {
			continue
		}
		current, found := currentMemory[old.TransitionLocation]
		if !found {
			return fail("unrelated byte is absent from the current frame")
		}
		if old.Pointer != current.Pointer || old.PointerLane != current.PointerLane {
			return fail("unrelated byte provenance changed")
		}
		if err := prove(old.Value, current.Value); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proof.work, proof.limit = meter.work, meter.limit
	return proof, nil
}

func regionUint64(v regionValue) (uint64, bool) {
	if v.kind != regionConstant || v.scalar == nil || !types.Identical(v.typ, types.Typ[types.Uint64]) || v.scalar.Kind() != constant.Int {
		return 0, false
	}
	return constant.Uint64Val(v.scalar)
}

// Concat orders low bytes before high bytes under the selected little-endian
// machine model. Duplicate or missing coordinates cannot become a word relation.
func globalNativeWord(ctx context.Context, b *br.Builder, memory []nativeproof.TransitionByte, address uint64) (br.Term, error) {
	var word br.Term
	for lane := 0; lane < 8; lane++ {
		var value br.Term
		for _, cell := range memory {
			if err := ctx.Err(); err != nil {
				return br.Term{}, err
			}
			if cell.Image && cell.Offset == int64(address)+int64(lane) {
				if value.Valid() {
					return br.Term{}, fmt.Errorf("global operand correspondence: duplicate byte")
				}
				value = cell.Value
			}
		}
		if value.Sort() != br.Bits(8) {
			return br.Term{}, fmt.Errorf("global operand correspondence: missing byte")
		}
		if lane == 0 {
			word = value
			continue
		}
		var err error
		word, err = b.Make(br.Concat, br.Bits(8*(lane+1)), 0, word, value)
		if err != nil {
			return br.Term{}, err
		}
	}
	return word, nil
}
