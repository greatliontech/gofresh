package nativeproof

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"golang.org/x/arch/x86/x86asm"
)

// cutPropertyImage keeps an actual mapped byte before entry even for an empty
// fetch window. Artifact suffix bytes never enlarge PT_LOAD. All successful
// windows here occupy the same image pages, keeping origin exclusions fixed.
func cutPropertyImage(t testing.TB, window, artifact []byte, moved bool) *Image {
	t.Helper()
	body := append([]byte(nil), window...)
	if moved {
		body = append([]byte{0x48, 0x89, 0xe0}, body...)
	}
	raw := elfBytes(body)
	binary.LittleEndian.PutUint64(raw[72:], 0xfff)
	binary.LittleEndian.PutUint64(raw[80:], testEntry-1)
	binary.LittleEndian.PutUint64(raw[96:], uint64(len(body)+1))
	binary.LittleEndian.PutUint64(raw[104:], uint64(len(body)+1))
	raw = append(raw, artifact...)
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return im
}

// This inventory is constructed from fixture layout, never from ProposeTransition.
func cutPropertyProposal(im *Image, size int, moved bool) TransitionProposal {
	p := TransitionProposal{ImageDigest: im.digest, Entry: testEntry, Cut: testEntry}
	if moved {
		p.Cut += 3
		p.Nodes = append(p.Nodes, Node{PC: testEntry, Size: 3, Successors: []uint64{p.Cut}})
	}
	p.Nodes = append(p.Nodes, Node{PC: p.Cut, Size: uint8(size)})
	return p
}

func checkCutProperty(t testing.TB, im *Image, size int, moved bool) (TransitionBound, error) {
	t.Helper()
	c, err := CheckTransition(t.Context(), im, transitionFace(), cutPropertyProposal(im, size, moved), TransitionLimits{})
	if err != nil {
		transitionRefused(t, c, err)
		return TransitionBound{}, err
	}
	b, ok := c.Bound()
	if !ok {
		t.Fatal("success without bound")
	}
	return b, nil
}

func assertCutEncodingRefused(t testing.TB, window, artifact []byte, fullSize int, moved bool) {
	t.Helper()
	im := cutPropertyImage(t, window, artifact, moved)
	pc := uint64(testEntry)
	if moved {
		pc += 3
	}
	// Check structural admission itself, so a shorter fabricated decode cannot
	// hide behind an inventory-size mismatch in CheckTransition.
	if i, _, err := decodeBytes(im, pc); err == nil {
		t.Fatalf("invalid/incomplete window %x decoded as %#v with artifact %x", window, i, artifact)
	}
	if _, err := checkCutProperty(t, im, fullSize, moved); err == nil {
		t.Fatalf("invalid/incomplete window %x certified with artifact %x", window, artifact)
	}
}

func assertCutOnly(t testing.TB, b TransitionBound, code []byte, moved bool) {
	t.Helper()
	cut := uint64(testEntry)
	var fetches []Span
	if moved {
		cut += 3
		fetches = []Span{{testEntry, cut}}
	}
	if b.Entry != testEntry || b.Boundary.PC != cut || b.Boundary.Instruction.Len != len(code) || !bytes.Equal(b.Boundary.Bytes, code) || !reflect.DeepEqual(straightFetches(t, b), fetches) || len(b.Accesses) != 0 {
		t.Fatalf("cut/fetch binding: %+v", b)
	}
	if !reflect.DeepEqual(b.Memory, b.InitialMemory) {
		t.Fatal("unexecuted cut changed memory")
	}
	for r, got := range b.Registers {
		want := b.InitialRegisters[r]
		var pointer TransitionPointer
		preserved := ^uint64(0)
		if Register(r) == RSP {
			pointer = OriginPointer{Origin: b.Origin}
		}
		if moved && Register(r) == RAX {
			want = b.InitialRegisters[RSP]
			pointer = OriginPointer{Origin: b.Origin}
			preserved = 0
		}
		if got.Value != want || got.Pointer != pointer || b.Preserved[r] != preserved {
			t.Fatalf("register %d: %+v", r, got)
		}
	}
	f := TransitionFlag{Preserved: true, Defined: true}
	if b.Flags != (TransitionFlags{f, f, f, f, f, f}) {
		t.Fatal("unexecuted cut changed flags", b.Flags)
	}
}

// cutReference is an INTEGRATION oracle: the trusted pinned decoder plus the
// independently stated local corrections. It is not a second ISA decoder or
// independent instruction-semantics proof. Known-form generation below supplies
// intent-first expectations for the repaired surface without this oracle.
func cutReference(raw []byte) (x86asm.Inst, bool) {
	if len(raw) == 0 {
		return x86asm.Inst{}, false
	}
	p := 0
	switch raw[0] {
	case 0xc5:
		p = 2
	case 0xc4:
		p = 3
	case 0x62:
		p = 4
	}
	if p != 0 {
		if len(raw) <= p {
			return x86asm.Inst{}, false
		}
		if raw[p] == 0x77 && (p == 2 || p == 3 && raw[1]&31 == 1) {
			if raw[p-1]&0x7b != 0x78 {
				return x86asm.Inst{}, false
			}
			i := x86asm.Inst{Op: x86asm.VZEROUPPER, Opcode: 0x77000000, Mode: 64, AddrSize: 64, DataSize: 32, Len: p + 1}
			if raw[p-1]&4 != 0 {
				i.Op = x86asm.VZEROALL
			}
			for n, b := range raw[:p] {
				i.Prefix[n] = x86asm.Prefix(b)
			}
			return i, true
		}
		if len(raw) < p+2 {
			return x86asm.Inst{}, false
		}
	}
	i, err := x86asm.Decode(raw, 64)
	if err != nil || i.Op == 0 || i.Len < 1 || i.Len > len(raw) {
		return x86asm.Inst{}, false
	}
	for _, prefix := range i.Prefix {
		if prefix&x86asm.PrefixInvalid != 0 {
			return x86asm.Inst{}, false
		}
	}
	if p != 0 {
		i.Mode, i.AddrSize = 64, 64
		opbytes := raw[p : p+2]
		mod, rm := raw[p+1]>>6, raw[p+1]&7
		if mod != 3 && rm == 4 {
			opbytes = raw[p : p+3]
		}
		for n, b := range opbytes {
			i.Opcode |= uint32(b) << (24 - 8*n)
		}
		if mod == 0 && rm == 5 {
			for n, a := range i.Args {
				if m, ok := a.(x86asm.Mem); ok {
					m.Base = x86asm.RIP
					i.Args[n] = m
					i.PCRel = 4
					i.PCRelOff = p + 2
				}
			}
		}
	}
	// The legacy decoder exposes unsigned disp32, except full-width moffs.
	if i.Mode == 64 && i.AddrSize == 64 && !(i.Opcode>>24 >= 0xa0 && i.Opcode>>24 <= 0xa3) {
		for n, a := range i.Args {
			if m, ok := a.(x86asm.Mem); ok {
				m.Disp = int64(int32(m.Disp))
				i.Args[n] = m
			}
		}
	}
	return i, true
}

func cutSeeds(t testing.TB) [][]byte {
	seeds := [][]byte{nil}
	for _, s := range []string{"90", "c3", "0f0b", "0fa2", "0f05", "f0c3", "f3c3", "c5f877", "c4e1fc77", "488b05ffffffff", "48a10000000001000000"} {
		seeds = append(seeds, hexBytes(t, s))
	}
	for _, tc := range vectorCutEncodings {
		seeds = append(seeds, hexBytes(t, tc.code))
	}
	return seeds
}

func FuzzTransitionCutBinding(f *testing.F) {
	for _, seed := range cutSeeds(f) {
		for _, moved := range []bool{false, true} {
			f.Add(seed, uint8(len(seed)), moved, uint8(0), []byte{0xc3, 0xff})
			f.Add(seed, uint8(0), moved, uint8(4), seed)
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte, available uint8, moved bool, perturb uint8, artifact []byte) {
		raw = raw[:min(len(raw), 15)]
		artifact = artifact[:min(len(artifact), 15)]
		n := int(available) % (len(raw) + 1)
		im := cutPropertyImage(t, raw[:n], append(append([]byte(nil), raw[n:]...), artifact...), moved)
		want, valid := cutReference(raw[:n])
		size := want.Len
		if !valid {
			size = 1
		}
		b, err := checkCutProperty(t, im, size, moved)
		if !valid {
			if err == nil {
				t.Fatalf("invalid/incomplete window accepted: %x", raw[:n])
			}
			return
		}
		if err != nil {
			t.Fatalf("reference-valid window %x refused: %v", raw[:n], err)
		}
		assertCutOnly(t, b, raw[:want.Len], moved)
		if b.ImageDigest != im.digest || b.Rules != TransitionRules || !reflect.DeepEqual(b.Boundary.Instruction, want) {
			t.Fatalf("context differs: %#v want %#v", b.Boundary.Instruction, want)
		}
		// Exercise every refusal family for each positive input; fuzzing chooses
		// the changed byte/PC magnitude, not whether tampering is tested at all.
		for mutation := 0; mutation < 7; mutation++ {
			p := cutPropertyProposal(im, size, moved)
			last := len(p.Nodes) - 1
			switch mutation {
			case 0:
				p.Nodes = p.Nodes[:last]
			case 1:
				p.Nodes[last].Size = uint8((size+int(perturb)%14)%15 + 1)
			case 2:
				p.Nodes[last].PC += 1 + uint64(perturb)
			case 3:
				p.Nodes[last].Successors = []uint64{p.Cut + uint64(size)}
			case 4:
				p.ImageDigest[int(perturb)%32] ^= 1
			case 5:
				p.Entry += 1 + uint64(perturb)
			case 6:
				if moved {
					p.Nodes[0].Successors[0]++
				} else {
					p.Nodes = append(p.Nodes, p.Nodes[0])
				}
			}
			c, err := CheckTransition(t.Context(), im, transitionFace(), p, TransitionLimits{})
			transitionRefused(t, c, err)
		}
	})
}

// Compare complete state syntax modulo a bijection of fresh variable scopes.
// Digests bind the intentionally different artifacts and are not equality tests.
func assertCutStateAlpha(t testing.TB, a, b TransitionBound) {
	t.Helper()
	forward, backward := map[br.Scope]br.Scope{}, map[br.Scope]br.Scope{}
	var term func(br.Term, br.Term)
	term = func(x, y br.Term) {
		p, q := x.View(), y.View()
		if x.Valid() != y.Valid() || p.Op != q.Op || p.Sort != q.Sort || p.Immediate != q.Immediate || p.Scratch != q.Scratch || len(p.Args) != len(q.Args) {
			t.Fatal("state term changed modulo input names")
		}
		if p.Op == br.Variable {
			if v, ok := forward[p.Scope]; ok && v != q.Scope {
				t.Fatal("inconsistent alpha map")
			}
			if v, ok := backward[q.Scope]; ok && v != p.Scope {
				t.Fatal("non-bijective alpha map")
			}
			forward[p.Scope], backward[q.Scope] = q.Scope, p.Scope
		}
		for i := range p.Args {
			term(p.Args[i], q.Args[i])
		}
	}
	// The walker visits every exported projection field; only image identity
	// differs by construction, and Term's private arena is compared via View.
	a.ImageDigest, b.ImageDigest = [32]byte{}, [32]byte{}
	var walk func(reflect.Value, reflect.Value)
	termType := reflect.TypeOf(br.Term{})
	walk = func(x, y reflect.Value) {
		if x.Type() != y.Type() {
			t.Fatal("state field type changed")
		}
		if x.Type() == termType {
			term(x.Interface().(br.Term), y.Interface().(br.Term))
			return
		}
		if x.Type() == reflect.TypeOf(ImagePointer{}) {
			if x.Interface().(ImagePointer) != y.Interface().(ImagePointer) {
				t.Fatal("image pointer changed")
			}
			return
		}
		if x.Type() == reflect.TypeOf(ImageInitialization{}) {
			if x.Interface().(ImageInitialization) != y.Interface().(ImageInitialization) {
				t.Fatal("initialization capability changed")
			}
			return
		}
		switch x.Kind() {
		case reflect.Interface:
			if x.IsNil() || y.IsNil() {
				if x.IsNil() != y.IsNil() {
					t.Fatal("pointer kind changed")
				}
				return
			}
			walk(x.Elem(), y.Elem())
		case reflect.Struct:
			for n := 0; n < x.NumField(); n++ {
				walk(x.Field(n), y.Field(n))
			}
		case reflect.Array, reflect.Slice:
			if x.Len() != y.Len() {
				t.Fatal("state layout changed")
			}
			for n := 0; n < x.Len(); n++ {
				walk(x.Index(n), y.Index(n))
			}
		default:
			if !reflect.DeepEqual(x.Interface(), y.Interface()) {
				t.Fatalf("state field changed: %v != %v", x, y)
			}
		}
	}
	walk(reflect.ValueOf(a), reflect.ValueOf(b))
}

func FuzzTransitionCutSelfDelimitation(f *testing.F) {
	for _, seed := range cutSeeds(f) {
		f.Add(seed, []byte{0xc3, 0x04, 0x85, 0xff}, true)
	}
	f.Fuzz(func(t *testing.T, raw, tail []byte, moved bool) {
		raw = raw[:min(len(raw), 15)]
		want, valid := cutReference(raw)
		size := want.Len
		if !valid {
			size = 1
		}
		b, err := checkCutProperty(t, cutPropertyImage(t, raw, nil, moved), size, moved)
		if !valid {
			if err == nil {
				t.Fatalf("invalid window accepted: %x", raw)
			}
			return
		}
		if err != nil {
			t.Fatalf("positive baseline refused: %x: %v", raw, err)
		}
		l := b.Boundary.Instruction.Len
		code := raw[:l]
		exact, err := checkCutProperty(t, cutPropertyImage(t, code, nil, moved), l, moved)
		if err != nil {
			t.Fatalf("exact length refused: %x: %v", code, err)
		}
		assertCutOnly(t, exact, code, moved)
		assertCutStateAlpha(t, b, exact)
		for n := 0; n < l; n++ {
			for _, unmapped := range [][]byte{nil, code[n:]} {
				assertCutEncodingRefused(t, code[:n], unmapped, l, moved)
			}
		}
		// Fixed 15-byte geometry; changes after L must preserve the complete
		// instruction and state, not just its mnemonic or length.
		for variant := 0; variant < 2; variant++ {
			window := make([]byte, 15)
			copy(window, code)
			for n := l; n < len(window); n++ {
				v := byte(n * 37)
				if len(tail) > 0 {
					v = tail[(n-l)%len(tail)]
				}
				if variant != 0 {
					v = ^v
				}
				window[n] = v
			}
			x, err := checkCutProperty(t, cutPropertyImage(t, window, tail[:min(len(tail), 15)], moved), l, moved)
			if err != nil {
				t.Fatalf("tail changed admission: %x: %v", window, err)
			}
			assertCutStateAlpha(t, exact, x)
		}
	})
}
