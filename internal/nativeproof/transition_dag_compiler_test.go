package nativeproof

import (
	"bytes"
	"debug/elf"
	"reflect"
	"testing"
	"testing/quick"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	to "github.com/greatliontech/gofresh/internal/nativeproof/internal/transitionoracle"
)

// Actual bytes are independently parsed to locate a candidate common boundary
// and data footprints. They confer no source association or initial value. The
// production checker independently reconstructs the graph and permissions.
func actualGuardedLayout(t testing.TB, im *Image, firstQuery uint64) (dagLayout, int, uint64, uint64) {
	t.Helper()
	queue := []uint64{firstQuery + 2}
	seen := map[uint64]bool{}
	cut, flag, version := uint64(0), uint64(0), uint64(0)
	for len(queue) > 0 {
		pc := queue[0]
		queue = queue[1:]
		if seen[pc] {
			continue
		}
		seen[pc] = true
		if len(seen) > 128 {
			t.Fatal("actual discovery did not close within search allowance")
		}
		raw, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		d, err := to.Parse(raw, pc)
		if err != nil {
			t.Fatal("actual guarded candidate", err)
		}
		if d.Intent.Operation == to.Load && d.Intent.RIP {
			if cut != 0 && cut != pc {
				t.Fatal("multiple candidate common loads")
			}
			cut = pc
			continue
		}
		if d.Intent.RIP && (d.Intent.Operation == to.Store || d.Intent.Operation == to.StoreImmediate) {
			address := uint64(int64(d.Next) + d.Intent.SignedDisp)
			switch d.Intent.Width {
			case 8:
				if flag != 0 {
					t.Fatal("multiple byte footprints")
				}
				flag = address
			case 32:
				if version != 0 {
					t.Fatal("multiple dword footprints")
				}
				version = address
			default:
				t.Fatal("unexpected candidate partial-store width")
			}
		}
		if d.Intent.Operation == to.Jump {
			queue = append(queue, d.Target)
		} else {
			queue = append(queue, d.Next)
			if d.Intent.Operation == to.Branch {
				queue = append(queue, d.Target)
			}
		}
	}
	if cut == 0 || flag == 0 || version == 0 {
		t.Fatal("actual guarded candidate incomplete")
	}
	x := dagLayout{stateLayout: stateLayout{im: im, digest: im.digest}}
	byPC := map[uint64]int{im.entry: 0}
	queue = []uint64{im.entry}
	var edges [][]uint64
	for at := 0; at < len(queue); at++ {
		if at >= 256 {
			t.Fatal("actual entry inventory exceeds discovery allowance")
		}
		pc := queue[at]
		raw, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		d, err := to.Parse(raw, pc)
		if err != nil {
			t.Fatal(err)
		}
		x.pcs = append(x.pcs, pc)
		x.encoded = append(x.encoded, append([]byte(nil), raw[:d.Length]...))
		x.intents = append(x.intents, d.Intent)
		var next []uint64
		if pc != cut {
			if d.Intent.Operation == to.Jump {
				next = []uint64{d.Target}
			} else {
				next = []uint64{d.Next}
				if d.Intent.Operation == to.Branch {
					next = append(next, d.Target)
				}
			}
		}
		edges = append(edges, next)
		for _, p := range next {
			if _, ok := byPC[p]; !ok {
				byPC[p] = len(queue)
				queue = append(queue, p)
			}
		}
	}
	x.edges = make([][]int, len(edges))
	for j, next := range edges {
		for _, pc := range next {
			x.edges[j] = append(x.edges[j], byPC[pc])
		}
	}
	f, err := elf.NewFile(bytes.NewReader(im.data))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Memsz != 0 {
			x.mappings = append(x.mappings, interfaceMapping{start: p.Vaddr, end: p.Vaddr + p.Memsz, file: p.Off, filesz: p.Filesz, read: p.Flags&elf.PF_R != 0, write: p.Flags&elf.PF_W != 0, execute: p.Flags&elf.PF_X != 0})
		}
	}
	return x, byPC[cut], flag, version
}

func checkOptimizedGuarded(t testing.TB, im *Image, oldFace TransitionInterface, firstQuery uint64) {
	t.Helper()
	x, cut, flag, version := actualGuardedLayout(t, im, firstQuery)
	face := cloneTransitionInterface(oldFace)
	face.Conditions.CPUID = CPUIDModel
	face.ImageRegions = append(face.ImageRegions, Span{flag, flag + 1}, Span{version, version + 4})
	firstAfter := 0
	for j, pc := range x.pcs {
		if pc == firstQuery+2 {
			firstAfter = j
		}
	}
	type valuation struct {
		first, second [4]uint32
		raw           [512]byte
		inactive      [32]byte
	}
	var valuations []valuation
	population := [][4]uint32{{0, 0x756e6547, 0x6c65746e, 0x49656e69}, {1, 0, 0x6c65746e, 0x49656e69}, {1, 0x756e6547, 0x6c65746e, 0}, {1, 0x756e6547, 0, 0x49656e69}, {1, 0x756e6547, 0x6c65746e, 0x49656e69}}
	for _, second := range [][4]uint32{{0, 0, 0, 0}, {0xffffffff, 0x80000000, 0x12345678, 0x87654321}} {
		for _, first := range population {
			valuations = append(valuations, valuation{first: first, second: second, raw: [512]byte{17}})
		}
	}
	if err := quick.Check(func(first, second [4]uint32, raw [512]byte, inactive [32]byte) bool {
		for class := 0; class < 5; class++ {
			valuations = append(valuations, valuation{cpuControlClass(first, class), second, raw, inactive})
		}
		return true
	}, &quick.Config{MaxCount: 24}); err != nil {
		t.Fatal(err)
	}
	root, err := CheckTransition(t.Context(), im, face, x.proposal(firstAfter), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := root.Bound()
	continued, err := CheckTransitionContinuation(t.Context(), root, x.proposal(cut))
	if err != nil {
		t.Fatal(err)
	}
	direct, err := CheckTransition(t.Context(), im, face, x.proposal(cut), TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	assertTransitionAlpha(t, direct, continued)
	after, _ := root.Bound()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("actual predecessor changed")
	}
	check := func(first, second [4]uint32, raw, inactive []byte) {
		{
			initial := stateRawInitial(face, raw)
			initial.outcomes = [][4]uint32{first, second}
			for _, certificate := range []TransitionCertificate{direct, continued} {
				dagAssert(t, certificate, x, cut, face, initial, inactive)
				b := certificate.checked.bound
				values := stateBindings(t, certificate, face, initial)
				if len(b.PrimitiveEffects) != 2 {
					t.Fatal("actual query inventory is not two guarded occurrences")
				}
				for j, effect := range b.PrimitiveEffects {
					e := effect.(CPUIDEffect)
					tuple := first
					if j == 1 {
						tuple = second
					}
					for k, v := range []br.Term{e.ResultsEAX, e.ResultsEBX, e.ResultsECX, e.ResultsEDX} {
						values[v] = uint64(tuple[k])
					}
				}
				N := first[0] != 0
				V := N && first[1] == 0x756e6547 && first[3] == 0x49656e69 && first[2] == 0x6c65746e
				query := b.PrimitiveEffects[1].(CPUIDEffect)
				for _, occ := range b.Instructions {
					if occ.Start == query.PC && (stateEval(t, occ.Guard, values) != 0) != N {
						t.Fatal("actual second query guard differs from N")
					}
				}
				if N && (stateEval(t, query.Leaf, values) != 1 || stateEval(t, query.Subleaf, values) != uint64(first[2])) {
					t.Fatal("actual second selectors are not leaf1/subleaf first ECX")
				}
				for j, reg := range []Register{RAX, RBX, RCX, RDX} {
					want := first[j]
					if N {
						want = second[j]
					}
					if stateEval(t, b.Registers[reg].Value, values) != uint64(want) {
						t.Fatal("actual final query register differs")
					}
				}
				for _, cell := range b.Memory {
					if !cell.Image {
						continue
					}
					address := uint64(cell.Offset)
					if address == flag {
						want := uint64(initial.memory[stateLocation{true, int64(flag)}].value)
						if V {
							want = 1
						}
						if stateEval(t, cell.Value, values) != want {
							t.Fatal("actual guarded byte value differs")
						}
					}
					if address >= version && address < version+4 {
						want := uint64(initial.memory[stateLocation{true, int64(address)}].value)
						if N {
							want = uint64(byte(second[0] >> (8 * (address - version))))
						}
						if stateEval(t, cell.Value, values) != want {
							t.Fatal("actual guarded dword value differs")
						}
					}
				}
			}
		}
	}
	for _, v := range valuations {
		check(v.first, v.second, v.raw[:], v.inactive[:])
	}
	t.Logf("conditional guarded DAG: first query=%#x common unexecuted load=%#x byte=%#x dword=%#x; five control populations, arbitrary initial bytes, independent second tuples; no execution/source/loader-initialization claim", firstQuery, x.pcs[cut], flag, version)
	checkOptimizedInitialized(t, im, face, x.pcs[cut])
}

// Each map is surjective onto its control class: already-satisfying words are
// unchanged. Only the class's defining comparisons constrain an input word.
func cpuControlClass(first [4]uint32, class int) [4]uint32 {
	if class == 0 {
		first[0] = 0
		return first
	}
	if first[0] == 0 {
		first[0] = 1
	}
	mismatch := func(v, w uint32) uint32 {
		if v == w {
			return v ^ 1
		}
		return v
	}
	switch class {
	case 1:
		first[1] = mismatch(first[1], 0x756e6547)
	case 2:
		first[1] = 0x756e6547
		first[3] = mismatch(first[3], 0x49656e69)
	case 3:
		first[1], first[3] = 0x756e6547, 0x49656e69
		first[2] = mismatch(first[2], 0x6c65746e)
	case 4:
		first[1], first[3], first[2] = 0x756e6547, 0x49656e69, 0x6c65746e
	}
	return first
}
