package nativeproof

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"testing"
)

const testBase uint64 = 0x400000
const testEntry = testBase + 0x1000

func face(inputs, results Masks) Interface {
	return Interface{Inputs: inputs, Results: results, Preserved: Masks{RBP: math.MaxUint64, R14: math.MaxUint64}, Conditions: Conditions{
		Machine: MachineModel, InstructionMapping: true, ReturnSlot: true, EntryInputs: true, IsolatedInvocation: true,
	}}
}

func hexBytes(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A genuine ELF program-header mapping, deliberately without any section or
// symbol table. The code is not at a guessed .text or virtual-address file offset.
func elfBytes(code []byte) []byte {
	b := make([]byte, 0x1000+len(code))
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	u16 := func(off int, x uint16) { binary.LittleEndian.PutUint16(b[off:], x) }
	u64 := func(off int, x uint64) { binary.LittleEndian.PutUint64(b[off:], x) }
	u16(16, 2)
	u16(18, 62)
	binary.LittleEndian.PutUint32(b[20:], 1)
	u64(24, testEntry)
	u64(32, 64)
	u16(52, 64)
	u16(54, 56)
	u16(56, 1)
	binary.LittleEndian.PutUint32(b[64:], 1)
	binary.LittleEndian.PutUint32(b[68:], 5)
	u64(72, 0x1000)
	u64(80, testEntry)
	u64(96, uint64(len(code)))
	u64(104, uint64(len(code)))
	u64(112, 0x1000)
	copy(b[0x1000:], code)
	return b
}

func image(t testing.TB, code []byte) *Image {
	t.Helper()
	im, err := NewImage(context.Background(), elfBytes(code))
	if err != nil {
		t.Fatal(err)
	}
	return im
}

func prove(t testing.TB, im *Image, entry uint64, f Interface) (Certificate, error) {
	t.Helper()
	p, err := Propose(context.Background(), im, entry, f)
	if err != nil {
		return Certificate{}, err
	}
	return Check(context.Background(), im, entry, f, p)
}

func requireRefusal(t testing.TB, c Certificate, err error, premise string) *Refusal {
	t.Helper()
	if _, ok := c.Bound(); ok {
		t.Fatal("refusal supplied a certificate")
	}
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("wanted structured %s refusal, got %v", premise, err)
	}
	if r.Premise != premise {
		t.Fatalf("wanted %s, got %+v", premise, r)
	}
	if len(r.Path) == 0 || r.Path[len(r.Path)-1] != r.PC {
		t.Fatalf("missing dependency path: %+v", r)
	}
	return r
}

// These byte strings are ordinarily optimized compiler outputs, captured in the
// reconnaissance fixture. The self-contained ELF mapping intentionally supplies
// no names or bounds. The separate compiler fixture checks live default output.
var kernels = []struct {
	name, code      string
	inputs, results Masks
}{
	{"Add", "4801d8c3", Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}, Masks{RAX: math.MaxUint64}},
	{"AddCompare", "488d0c184839c80f97c34889c8c3", Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}, Masks{RAX: math.MaxUint64, RBX: 0xff}},
	{"Branch", "4839c376044801d8c34831d8c3", Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}, Masks{RAX: math.MaxUint64}},
	{"Normalize", "3dffff1000770e8d880028ffff81f9000800007306b8fdff0000c3c3", Masks{RAX: 0xffffffff}, Masks{RAX: 0xffffffff}},
	{"IsSurrogate", "3d00d800007c0a3d00e000000f9cc0eb0231c0c3", Masks{RAX: 0xffffffff}, Masks{RAX: 0xff}},
	{"EncodeRune", "050000ffff3dffff0f007608b8fdff000089c3c389c3c1e80a0500d8000081e3ff03000081c300dc0000c3", Masks{RAX: 0xffffffff}, Masks{RAX: 0xffffffff, RBX: 0xffffffff}},
	{"OnesCount64", "4889c148d1e848ba55555555555555554821d04821ca488d0c024889ca48c1e90248bb33333333333333334821d94821d34801d94889ca48c1e9044801d148ba0f0f0f0f0f0f0f0f4821ca4889d148c1ea084801d14889ca48c1e9104801d14889ca48c1e920488d041183e07fc3", Masks{RAX: math.MaxUint64}, Masks{RAX: math.MaxUint64}},
}

func TestOptimizedKernelBytesThroughELF(t *testing.T) {
	for _, k := range kernels {
		t.Run(k.name, func(t *testing.T) {
			code := hexBytes(t, k.code)
			im := image(t, code)
			c, err := prove(t, im, testEntry, face(k.inputs, k.results))
			if err != nil {
				t.Fatal(err)
			}
			b, ok := c.Bound()
			if !ok || b.ImageDigest != sha256.Sum256(elfBytes(code)) || b.Entry != testEntry || b.Rules != RuleModel {
				t.Fatalf("incomplete bound: %+v", b)
			}
			last := uint64(0)
			for _, span := range b.Instructions {
				last = max(last, span.End)
			}
			if last != testEntry+uint64(len(code)) {
				t.Fatalf("coverage ended at %#x", last)
			}
		})
	}
}

func TestInstructionAndInputRefusals(t *testing.T) {
	full := face(Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}, Masks{RAX: math.MaxUint64})
	for _, tt := range []struct {
		name, code, premise string
		f                   Interface
	}{
		{"load", "488b00c3", "data-memory", full},
		{"store", "488900c3", "data-memory", full},
		{"memory-compare", "483900c3", "data-memory", full},
		{"CPU-load", "0fb60d7ad10f00c3", "data-memory", full},
		{"CPU-instruction", "f3480fb8c0c3", "instruction-prefix", full},
		{"native-callback", "ffd1c3", "instruction-semantics", full},
		{"direct-call", "e800000000c3", "instruction-semantics", full},
		{"syscall", "0f05c3", "instruction-semantics", full},
		{"unknown", "0f0bc3", "instruction-semantics", full},
		{"truncated", "48b8", "instruction-decode", full},
		{"unknown-input", "4801d8c3", "result-input-bound", face(Masks{RAX: math.MaxUint64}, Masks{RAX: math.MaxUint64})},
		{"same-width-is-not-same-input", "4889c8c3", "result-input-bound", full},
		{"unknown-flags", "7701c3c3", "flag-input-bound", full},
		{"undefined-shift-overflow", "48c1e8020f9cc0c3", "flag-input-bound", full},
		{"zero-shift-keeps-unknown-flags", "48c1e8000f97c0c3", "flag-input-bound", full},
		{"partial-byte", "b001c3", "result-input-bound", face(Masks{}, Masks{RAX: math.MaxUint64})},
		{"partial-word", "66b80100c3", "result-input-bound", face(Masks{}, Masks{RAX: math.MaxUint64})},
		{"high-byte-not-low", "b401c3", "result-input-bound", face(Masks{}, Masks{RAX: 0xff})},
		{"carry-unbound-bit", "4883c001c3", "result-input-bound", face(Masks{RAX: 0xfe}, Masks{RAX: 0xfe})},
		{"preserved-context", "4531f6c3", "preserved-register", full},
		{"stack-pointer", "4889c4c3", "return-interface", full},
		{"ret-immediate", "c20800", "return-interface", full},
		{"ret-zero-immediate", "c20000", "return-interface", full},
		{"prefixed-ret", "48c3", "return-interface", full},
		{"far-ret", "cb", "instruction-semantics", full},
		{"indirect-jump", "ffe0", "control-target", full},
		{"cycle", "ebfe", "acyclic-control", full},
		{"fallthrough-outside-image", "90", "instruction-mapping", full},
		{"jump-outside-image", "eb7f", "instruction-mapping", full},
		{"negative-target-overflow", "e900000080", "control-target", full},
		{"overlap", "39c074ff90c3", "instruction-overlap", full},
		{"hidden-memory-branch", "39c07401c3488b00c3", "data-memory", full},
		{"unproved-dead-branch", "39c07501c3488b00c3", "data-memory", full},
		{"hidden-cycle-branch", "39c07401c3ebfe", "acyclic-control", full},
		{"hidden-unknown-result-branch", "39c07401c34889c8c3", "result-input-bound", full},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := prove(t, image(t, hexBytes(t, tt.code)), testEntry, tt.f)
			r := requireRefusal(t, c, err, tt.premise)
			if r.Path[0] != testEntry {
				t.Fatalf("wrong root: %+v", r)
			}
		})
	}
}

func TestDefinedBitsAliasesAndPreservation(t *testing.T) {
	for _, tt := range []struct {
		name, code string
		f          Interface
	}{
		{"self-xor", "4831c0c3", face(Masks{}, Masks{RAX: math.MaxUint64})},
		{"32-zero-extension", "b801000000c3", face(Masks{}, Masks{RAX: math.MaxUint64})},
		{"32-copy-zero-extension", "89c8c3", face(Masks{RCX: 0xffffffff}, Masks{RAX: math.MaxUint64})},
		{"byte-result", "b001c3", face(Masks{}, Masks{RAX: 0xff})},
		{"high-byte-result", "b401c3", face(Masks{}, Masks{RAX: 0xff00})},
		{"high-to-low", "88e0c3", face(Masks{RAX: 0xff00}, Masks{RAX: 0xff})},
		{"word-result", "66b80100c3", face(Masks{}, Masks{RAX: 0xffff})},
		{"and-clears-unknown", "482500000000c3", face(Masks{}, Masks{RAX: math.MaxUint64})},
		{"sparse-mask", "4825ff000000c3", face(Masks{RAX: 0xff}, Masks{RAX: math.MaxUint64})},
		{"shift-high-zero", "48c1e820c3", face(Masks{RAX: 0xffffffff00000000}, Masks{RAX: math.MaxUint64})},
		{"low-add-only", "4883c001c3", face(Masks{RAX: 0xff}, Masks{RAX: 0xff})},
		{"zero-shift-keeps-known-flags", "39c048c1e8000f97c0c3", face(Masks{RAX: math.MaxUint64}, Masks{RAX: 0xff})},
		{"nops", "90669031c0c3", face(Masks{}, Masks{RAX: math.MaxUint64})},
		{"extended-register", "41b0014488c0c3", face(Masks{}, Masks{RAX: 0xff})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := prove(t, image(t, hexBytes(t, tt.code)), testEntry, tt.f); err != nil {
				t.Fatal(err)
			}
		})
	}
	f := face(Masks{RAX: 0xffffffffffffff00}, Masks{RAX: math.MaxUint64})
	f.Preserved[RAX] = 0xffffffffffffff00
	if _, err := prove(t, image(t, hexBytes(t, "b001c3")), testEntry, f); err != nil {
		t.Fatal(err)
	}
	c, err := prove(t, image(t, hexBytes(t, "b801000000c3")), testEntry, f)
	requireRefusal(t, c, err, "preserved-register")
}

func TestIllegalAndUnsupportedPrefixes(t *testing.T) {
	f := face(Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}, Masks{RAX: math.MaxUint64})
	for _, code := range []string{
		"f04801d8c3", "f34801d8c3", "f24801d8c3", "644801d8c3", "654801d8c3", "2e4801d8c3",
		"674801d8c3", "66664889c0c3", "484889c0c3", "486689c0c3", "664801d8c3", "f390c3",
		"f3c3", "66c3", "67c3", "c5f9efc0c3", "62f17c4857c0c3",
	} {
		t.Run(code, func(t *testing.T) {
			c, err := prove(t, image(t, hexBytes(t, code)), testEntry, f)
			if err == nil {
				t.Fatal("illegal/unsupported prefix admitted")
			}
			if _, ok := c.Bound(); ok {
				t.Fatal("positive on prefix refusal")
			}
		})
	}
}

func TestProposalIsNotAuthority(t *testing.T) {
	im := image(t, hexBytes(t, kernels[2].code))
	f := face(kernels[2].inputs, kernels[2].results)
	for _, mutate := range []struct {
		name   string
		change func(*Proposal)
	}{
		{"omitted-branch", func(p *Proposal) {
			for j := range p.Nodes {
				if len(p.Nodes[j].Successors) == 2 {
					p.Nodes[j].Successors = p.Nodes[j].Successors[:1]
					return
				}
			}
		}},
		{"omitted-node", func(p *Proposal) { p.Nodes = p.Nodes[:len(p.Nodes)-1] }},
		{"forged-size", func(p *Proposal) { p.Nodes[0].Size++ }},
		{"invented-node", func(p *Proposal) { p.Nodes = append(p.Nodes, Node{PC: testEntry + 100, Size: 1}) }},
		{"duplicate-node", func(p *Proposal) { p.Nodes = append(p.Nodes, p.Nodes[0]) }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			p, err := Propose(context.Background(), im, testEntry, f)
			if err != nil {
				t.Fatal(err)
			}
			mutate.change(&p)
			c, err := Check(context.Background(), im, testEntry, f, p)
			requireRefusal(t, c, err, "proposal-inventory")
		})
	}
	for _, mutate := range []func(*Proposal){
		func(p *Proposal) { p.Interface.Inputs[RCX] = math.MaxUint64 },
		func(p *Proposal) { p.Interface.Results[RAX] = 0xff },
		func(p *Proposal) { p.Entry++ },
	} {
		p, err := Propose(context.Background(), im, testEntry, f)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&p)
		c, err := Check(context.Background(), im, testEntry, f, p)
		requireRefusal(t, c, err, "proposal-binding")
	}
	if _, ok := (Certificate{}).Bound(); ok {
		t.Fatal("zero certificate authorized")
	}
}

func TestImmutableImageAndCertificate(t *testing.T) {
	raw := elfBytes(hexBytes(t, "31c0c3"))
	im, err := NewImage(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	f := face(Masks{}, Masks{RAX: math.MaxUint64})
	p, err := Propose(context.Background(), im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	raw[0x1000] = 0xcc
	c, err := Check(context.Background(), im, testEntry, f, p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.Bound()
	p.Nodes[0].Size = 15
	p.Interface.Inputs[RAX] = 1
	copyOfBound := b
	copyOfBound.Instructions = append([]Span(nil), b.Instructions...)
	b.Instructions[0].Start = 0
	b.Interface.Results[RAX] = 0
	now, _ := c.Bound()
	if !reflect.DeepEqual(copyOfBound, now) {
		t.Fatal("caller mutated checked ownership")
	}
	other := image(t, hexBytes(t, "89d8c3"))
	q, err := Propose(context.Background(), other, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := Check(context.Background(), other, testEntry, f, q)
	requireRefusal(t, bad, err, "result-input-bound")
}

func TestMachinePremisesAreRequired(t *testing.T) {
	im := image(t, hexBytes(t, "31c0c3"))
	for _, mutate := range []func(*Interface){
		func(f *Interface) { f.Conditions.Machine = "GOAMD64=v1" },
		func(f *Interface) { f.Conditions.InstructionMapping = false },
		func(f *Interface) { f.Conditions.ReturnSlot = false },
		func(f *Interface) { f.Conditions.EntryInputs = false },
		func(f *Interface) { f.Conditions.IsolatedInvocation = false },
	} {
		f := face(Masks{}, Masks{RAX: math.MaxUint64})
		mutate(&f)
		c, err := prove(t, im, testEntry, f)
		requireRefusal(t, c, err, "machine-premises")
	}
}

func TestELFMappingRefusals(t *testing.T) {
	for _, tt := range []struct {
		name, premise string
		change        func([]byte)
	}{
		{"class", "image-format", func(b []byte) { b[4] = 1 }},
		{"endianness", "image-format", func(b []byte) { b[5] = 2 }},
		{"architecture", "image-format", func(b []byte) { binary.LittleEndian.PutUint16(b[18:], 183) }},
		{"PIE", "image-format", func(b []byte) { binary.LittleEndian.PutUint16(b[16:], 3) }},
		{"dynamic", "image-relocation", func(b []byte) { binary.LittleEndian.PutUint32(b[64:], 2) }},
		{"interpreter", "image-relocation", func(b []byte) { binary.LittleEndian.PutUint32(b[64:], 3) }},
		{"relocation-section", "image-relocation", func(b []byte) {
			binary.LittleEndian.PutUint64(b[40:], 0x200)
			binary.LittleEndian.PutUint16(b[58:], 64)
			binary.LittleEndian.PutUint16(b[60:], 2)
			binary.LittleEndian.PutUint32(b[0x244:], 9)
			binary.LittleEndian.PutUint64(b[0x278:], 24)
		}},
		{"writable-code", "image-mapping", func(b []byte) { binary.LittleEndian.PutUint32(b[68:], 7) }},
		{"exec-not-readable", "image-mapping", func(b []byte) { binary.LittleEndian.PutUint32(b[68:], 1) }},
		{"filesz-overflow", "image-format", func(b []byte) { binary.LittleEndian.PutUint64(b[96:], math.MaxUint64) }},
		{"offset-overflow", "image-format", func(b []byte) { binary.LittleEndian.PutUint64(b[72:], math.MaxUint64) }},
		{"VA-overflow", "image-mapping", func(b []byte) { binary.LittleEndian.PutUint64(b[80:], math.MaxUint64) }},
		{"memsz-overflow", "image-mapping", func(b []byte) { binary.LittleEndian.PutUint64(b[104:], math.MaxUint64) }},
		{"noncanonical", "image-mapping", func(b []byte) { binary.LittleEndian.PutUint64(b[80:], 1<<47) }},
		{"filesz-exceeds-memsz", "image-mapping", func(b []byte) { binary.LittleEndian.PutUint64(b[104:], 1) }},
		{"bad-alignment", "image-mapping", func(b []byte) { binary.LittleEndian.PutUint64(b[112:], 3) }},
		{"misaligned-load", "image-mapping", func(b []byte) { binary.LittleEndian.PutUint64(b[80:], testEntry+1) }},
		{"overlap", "image-mapping", func(b []byte) { binary.LittleEndian.PutUint16(b[56:], 2); copy(b[120:176], b[64:120]) }},
		{"page-overlap", "image-mapping", func(b []byte) {
			binary.LittleEndian.PutUint16(b[56:], 2)
			copy(b[120:176], b[64:120])
			binary.LittleEndian.PutUint64(b[128:], 0x1002)
			binary.LittleEndian.PutUint64(b[136:], testEntry+2)
			binary.LittleEndian.PutUint64(b[152:], 1)
			binary.LittleEndian.PutUint64(b[160:], 1)
			binary.LittleEndian.PutUint64(b[96:], 2)
			binary.LittleEndian.PutUint64(b[104:], 2)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := elfBytes(hexBytes(t, "31c0c3"))
			tt.change(b)
			im, err := NewImage(context.Background(), b)
			if im != nil {
				t.Fatal("bad image admitted")
			}
			requireRefusal(t, Certificate{}, err, tt.premise)
		})
	}
	for _, tt := range []struct {
		name   string
		change func([]byte)
	}{
		{"non-executable", func(b []byte) { binary.LittleEndian.PutUint32(b[68:], 4) }},
		{"zero-fill", func(b []byte) { binary.LittleEndian.PutUint64(b[96:], 0) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := elfBytes(hexBytes(t, "31c0c3"))
			tt.change(b)
			im, err := NewImage(context.Background(), b)
			if err != nil {
				t.Fatal(err)
			}
			c, err := prove(t, im, testEntry, face(Masks{}, Masks{RAX: math.MaxUint64}))
			requireRefusal(t, c, err, "instruction-mapping")
		})
	}
}

func TestAddressArithmeticBoundaries(t *testing.T) {
	for _, tt := range []struct {
		base  uint64
		delta int64
		want  uint64
		ok    bool
	}{
		{0, -1, math.MaxUint64, false}, {math.MaxUint64, 1, 0, false},
		{1 << 63, math.MinInt64, 0, true}, {0, math.MinInt64, 1 << 63, false},
		{math.MaxUint64 - 1, 1, math.MaxUint64, true}, {1, -1, 0, true},
	} {
		got, ok := relative(tt.base, tt.delta)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("relative(%d,%d)=(%d,%v)", tt.base, tt.delta, got, ok)
		}
	}
}

func TestCancellationNeverPublishes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if im, err := NewImage(ctx, elfBytes([]byte{0xc3})); im != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("image cancellation: %v", err)
	}
	im := image(t, hexBytes(t, kernels[0].code))
	f := face(kernels[0].inputs, kernels[0].results)
	if _, err := Propose(ctx, im, testEntry, f); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	p, err := Propose(context.Background(), im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Check(ctx, im, testEntry, f, p)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, ok := c.Bound(); ok {
		t.Fatal("cancelled certificate")
	}
}
