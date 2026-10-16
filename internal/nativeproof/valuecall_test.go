package nativeproof

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// Ordinary selected amd64 assembly bytes. Names and symbol sizes play no part
// in these synthetic images; the actual compiled-image test rediscovers them.
const searchBodyHex = "66480f6ec0660f60c0660f60c0660f70c0004883fb107c584889f74883fb200f8791000000488d441ef0eb190f1f4000f30f6f0f660f74c8660fd7d10fbcd275254883c7104839c772e64889c7f30f6f08660f74c8660fd7d10fbcd2750849c700ffffffffc34829f74801d7498938c34885db74e9488d461066a9f00f7419f30f6f0e660f74c8660fd7d10fbcd274ce39da73ca498910c3f30f6f4c1ef0660f74c8660fd7d189d9d3e2c1ea100fbcd274ac498910c3803d27de3100010f8562ffffff66480f6ec04c8d5c1ee0c4e27d78c8660f1f8400000000000f1f440000c5fe6f17c5ed74d9c4e27d17db75264883c7204c39df7ce84c89dfc5fe6f17c5ed74d9c4e27d17db750bc5f87749c700ffffffffc3c5fdd7d30fbcd24829f74801fa498910c5f877c3"
const searchEntryHex = "488b742408488b5c24108a4424184c8d442420e988feffff"
const valueData = testBase + 0x2000
const valueStack = uint64(0x70000000)

func TestValueCallSSEEncoding(t *testing.T) {
	for _, code := range []string{"66480f6ec0", "660f60c0", "660f70c000", "f30f6f0e", "660f74c8", "660fd7d1"} {
		im := image(t, hexBytes(t, code))
		i, _, err := decodeValueCall(im, testEntry)
		if err != nil {
			raw, _ := x86asm.Decode(hexBytes(t, code), 64)
			t.Errorf("%s: %v; decoded=%+v prefixes=%#v", code, err, raw, raw.Prefix)
		} else {
			t.Log(i.String())
		}
	}
	for _, code := range []string{"6666480f6ec0", "f366480f6ec0", "664a0f6ec0", "f34889c0", "66f30f6f0e", "67f30f6f0e", "f30f7f0e", "66480f60c0", "660f6ec0", "c5f87749c700ffffffffc3"} {
		im := image(t, hexBytes(t, code))
		if _, _, err := decodeValueCall(im, testEntry); err == nil {
			t.Fatalf("unsupported SIMD/prefix form admitted: %s", code)
		}
	}
}

func valueCallFixture(t testing.TB, text string, needle byte, pageEnd, scratch bool) ([]byte, ValueCallRequest) {
	t.Helper()
	code := make([]byte, 0x278)
	prefix := hexBytes(t, "0fb6094889042448895c2408884c2410")
	if scratch {
		prefix = append(prefix, hexBytes(t, "4c89c8")...)
	} // AX high bits arbitrary before the callee's AL load
	call := len(prefix)
	prefix = append(prefix, 0xe8, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(prefix[call+1:], uint32(0x260-len(prefix)))
	continuation := testEntry + uint64(len(prefix))
	prefix = append(prefix, 0x45, 0x0f, 0x57, 0xff) // decoded boundary; XMM15 clear is outside this scope
	copy(code, prefix)
	copy(code[0x100:], hexBytes(t, searchBodyHex))
	copy(code[0x260:], hexBytes(t, searchEntryHex))
	raw := elfBytes(code)
	raw = append(raw, make([]byte, 0x4000-len(raw))...)
	binary.LittleEndian.PutUint16(raw[56:], 2)
	binary.LittleEndian.PutUint32(raw[120:], 1)
	binary.LittleEndian.PutUint32(raw[124:], 4)
	binary.LittleEndian.PutUint64(raw[128:], 0x2000)
	binary.LittleEndian.PutUint64(raw[136:], valueData)
	binary.LittleEndian.PutUint64(raw[152:], 0x2000)
	binary.LittleEndian.PutUint64(raw[160:], 0x2000)
	binary.LittleEndian.PutUint64(raw[168:], 4096)
	for j := 0x2000; j < len(raw); j++ {
		raw[j] = '~'
	}
	p := valueData + 0x200
	if pageEnd {
		p = valueData + 0xffa
	}
	copy(raw[p-testBase:], text)
	q := valueData + 0x100
	raw[q-testBase] = needle
	window := Span{p, p + 16}
	if (p+16)&0xff0 == 0 {
		window = Span{p + uint64(len(text)) - 16, p + uint64(len(text))}
	}
	// Long contexts still have mapped bytes, but must not borrow a short-path
	// proof when the length makes the selector/loops reachable.
	if len(text) >= 16 {
		window = Span{p, p + uint64(len(text)) + 16}
	}
	f := ValueCallInterface{
		Regions:  []ByteRegion{{window, true, false, true}, {Span{q, q + 1}, true, false, true}, {Span{valueStack - 16, valueStack + 80}, true, true, false}},
		Pointers: []RegisterPointer{{RAX, RegionPointer{0, p - window.Start, p - window.Start}}, {RCX, RegionPointer{1, 0, 0}}},
		Stack:    RegionPointer{2, 16, 16}, Protected: []Span{{valueStack + 48, valueStack + 56}}, Preserved: Masks{RBP: math.MaxUint64, R14: math.MaxUint64},
		Scalars: []RegisterConstant{{RBX, math.MaxUint64, uint64(len(text))}}, Readonly: []Span{window, {q, q + 1}}, Results: []Span{{valueStack + 24, valueStack + 32}},
		Conditions: ValueCallConditions{Machine: ValueCallMachine, InstructionMapping: true, MemoryMapping: true, ImageBytesMapped: true, NoHiddenAliases: true, UnalignedAccess: true, IsolatedInvocation: true, EntryState: true},
	}
	f.PreservedXMM[15] = true
	return raw, ValueCallRequest{testEntry, testEntry + 0x260, continuation, f}
}

func checkValueFixture(t testing.TB, raw []byte, r ValueCallRequest) (ValueCall, error) {
	t.Helper()
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		return ValueCall{}, err
	}
	return CheckValueCall(t.Context(), im, r, FrameLimits{})
}
func valueCallRefusal(t testing.TB, c ValueCall, err error) {
	t.Helper()
	if _, ok := c.Bound(); ok || err == nil {
		t.Fatalf("invalid scope produced evidence: %v", err)
	}
}

func TestValueCallShortSearch(t *testing.T) {
	for _, pageEnd := range []bool{false, true} {
		for _, tc := range []struct {
			name, text string
			needle     byte
		}{
			{"missing", "test.short", '='}, {"first", "=abcdefghi", '='}, {"last", "abcdefghi=", '='}, {"other-name", "alpha.beta", '.'},
			{"empty", "", '='}, {"single", "x", 'x'}, {"last15", "abcdefghijklmn=", '='},
		} {
			t.Run(tc.name+map[bool]string{false: "/forward", true: "/page-end"}[pageEnd], func(t *testing.T) {
				raw, r := valueCallFixture(t, tc.text, tc.needle, pageEnd, true)
				c, err := checkValueFixture(t, raw, r)
				if err != nil {
					t.Fatal(err)
				}
				b, ok := c.Bound()
				want := uint64(int64(bytes.IndexByte([]byte(tc.text), tc.needle)))
				xmmWrites := uint16(3)
				if len(tc.text) == 0 {
					xmmWrites = 1
				}
				if !ok || len(b.Results) != 1 || b.Results[0].Value != want || b.ReturnedRSP != valueStack || b.CalleeEntryRSP != valueStack-8 || b.XMMWrites != xmmWrites || b.Continuation.Span.Start != r.Continuation {
					t.Fatalf("wrong connected result: %+v", b)
				}
				for _, ins := range b.Instructions {
					if ins.Span.Start >= testEntry+0x1f6 && ins.Span.Start < testEntry+0x260 {
						t.Fatal("short input inspected CPU dispatch")
					}
				}
				im, err := NewImage(t.Context(), raw)
				if err != nil {
					t.Fatal(err)
				}
				checkValueCallOracle(t, im, b, 12)
			})
		}
	}
}

func TestValueCallPaddingIsNotString(t *testing.T) {
	for _, end := range []bool{false, true} {
		raw, r := valueCallFixture(t, "test.short", '=', end, false)
		p := r.Interface.Regions[0].Bytes.Start + r.Interface.Pointers[0].Pointer.Min
		padding := p + 10
		if end {
			padding = p - 1
		}
		raw[padding-testBase] = '='
		c, err := checkValueFixture(t, raw, r)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := c.Bound()
		if b.Results[0].Value != math.MaxUint64 {
			t.Fatal("padding match leaked into string result")
		}
	}
}

func TestValueCallZeroLengthNeedsNoDataLoad(t *testing.T) {
	b, r := valueCallFixture(t, "", '=', false, false)
	r.Interface.Pointers = r.Interface.Pointers[1:]
	r.Interface.Scalars = append(r.Interface.Scalars, RegisterConstant{RAX, math.MaxUint64, 0})
	r.Interface.Readonly = r.Interface.Readonly[1:]
	c, err := checkValueFixture(t, b, r)
	if err != nil {
		t.Fatal(err)
	}
	bound, _ := c.Bound()
	if bound.Results[0].Value != math.MaxUint64 {
		t.Fatal(bound.Results)
	}
	for _, a := range bound.Accesses {
		if a.Width == 16 {
			t.Fatal("zero length still claimed a vector load")
		}
	}
}

func TestValueCallWrongImageDoesNotBorrow(t *testing.T) {
	raw, r := valueCallFixture(t, "test.short", '=', false, false)
	good, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := CheckValueCall(t.Context(), good, r, FrameLimits{})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := cert.Bound()
	replaceValueCallee(t, raw, r, "c3")
	other, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := CheckValueCall(t.Context(), other, r, FrameLimits{})
	valueCallRefusal(t, bad, err)
	*good = *other
	after, _ := cert.Bound()
	if !reflect.DeepEqual(before, after) || cert.checked.image.digest == other.digest {
		t.Fatal("certificate followed a caller-owned image replacement")
	}
}

func TestValueCallBoundaryRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte, *ValueCallRequest)
	}{
		{"wrong-target", func(_ []byte, r *ValueCallRequest) { r.Target++ }},
		{"wrong-valid-target", func(b []byte, r *ValueCallRequest) {
			r.Target = testEntry + 0x40
			replaceValueCallee(t, b, *r, "48c74424202a000000c3")
		}},
		{"wrong-continuation", func(_ []byte, r *ValueCallRequest) { r.Continuation++ }},
		{"wrong-input-slot", func(b []byte, _ *ValueCallRequest) { b[0x1000+0x260+4] = 16 }},
		{"corrupt-pointer-argument", func(b []byte, r *ValueCallRequest) {
			replaceValueCallee(t, b, *r, "c6442408ff488b742408488b5c24108a4424184c8d442420e983feffff")
		}},
		{"unbound-values", func(_ []byte, r *ValueCallRequest) { r.Interface.Readonly = nil }},
		{"writable-bytes", func(b []byte, _ *ValueCallRequest) { binary.LittleEndian.PutUint32(b[124:], 6) }},
		{"aliased-bytes", func(b []byte, _ *ValueCallRequest) {
			binary.LittleEndian.PutUint16(b[56:], 3)
			copy(b[176:232], b[120:176])
			binary.LittleEndian.PutUint32(b[180:], 6)
			binary.LittleEndian.PutUint64(b[192:], testBase+0x5000)
		}},
		{"truncated-wide-load", func(b []byte, _ *ValueCallRequest) { binary.LittleEndian.PutUint64(b[152:], 0x20a) }},
		{"logical-only-region", func(_ []byte, r *ValueCallRequest) {
			r.Interface.Regions[0].Bytes.End -= 6
			r.Interface.Readonly[0].End -= 6
		}},
		{"result-return-overlap", func(_ []byte, r *ValueCallRequest) { r.Interface.Results = []Span{{valueStack - 8, valueStack}} }},
		{"result-protected-overlap", func(_ []byte, r *ValueCallRequest) {
			r.Interface.Protected = append(r.Interface.Protected, r.Interface.Results[0])
		}},
		{"push-not-writable", func(_ []byte, r *ValueCallRequest) { r.Interface.Regions[2].Writable = false }},
		{"push-outside-stack", func(_ []byte, r *ValueCallRequest) {
			r.Interface.Regions[2].Bytes.Start = valueStack
			r.Interface.Stack.Min = 0
			r.Interface.Stack.Max = 0
			r.Interface.Regions = append(r.Interface.Regions, ByteRegion{Span{valueStack - 8, valueStack}, true, true, false})
		}},
		{"partially-known-length", func(_ []byte, r *ValueCallRequest) { r.Interface.Scalars[0].Bits = 0xff }},
		{"no-loaded-byte-premise", func(_ []byte, r *ValueCallRequest) { r.Interface.Conditions.ImageBytesMapped = false }},
		{"no-sse-model", func(_ []byte, r *ValueCallRequest) { r.Interface.Conditions.Machine = MachineModel }},
		{"clobbered-XMM-context", func(_ []byte, r *ValueCallRequest) { r.Interface.PreservedXMM[0] = true }},
		{"callee-omitted", func(b []byte, _ *ValueCallRequest) { b[0x1260] = 0xc3 }},
		{"undefined-BSF-use", func(b []byte, _ *ValueCallRequest) { b[0x1100+0x8e] = 0x90; b[0x1100+0x8f] = 0x90 }}, // replace JZ after BSF
		{"prefix-call-omitted", func(b []byte, _ *ValueCallRequest) { b[0x1010] = 0xc3 }},
		{"return-clobber", func(b []byte, _ *ValueCallRequest) {
			b[0x1260] = 0x48
			b[0x1261] = 0x89
			b[0x1262] = 0x1c
			b[0x1263] = 0x24
		}},
		{"contradictory-pointer", func(_ []byte, r *ValueCallRequest) {
			r.Interface.Scalars = append(r.Interface.Scalars, RegisterConstant{RAX, math.MaxUint64, 0})
		}},
		{"expected-output-input", func(_ []byte, r *ValueCallRequest) {
			r.Interface.StackValues = []MemoryConstant{{valueStack + 24, 8, math.MaxUint64}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, r := valueCallFixture(t, "test.short", '=', false, false)
			tc.change(b, &r)
			c, err := checkValueFixture(t, b, r)
			valueCallRefusal(t, c, err)
		})
	}
	for _, length := range []int{32, 33, 64} {
		b, r := valueCallFixture(t, string(bytes.Repeat([]byte{'x'}, length)), '=', false, false)
		c, err := checkValueFixture(t, b, r)
		valueCallRefusal(t, c, err)
	}
}

func replaceValueCallee(t testing.TB, raw []byte, r ValueCallRequest, code string) {
	t.Helper()
	body := hexBytes(t, code)
	offset := r.Target - testEntry
	copy(raw[0x1000+offset:], body)
	end := offset + uint64(len(body))
	if end > binary.LittleEndian.Uint64(raw[96:]) {
		binary.LittleEndian.PutUint64(raw[96:], end)
		binary.LittleEndian.PutUint64(raw[104:], end)
	}
}

func TestValueCallBranchesAndIntegerSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       uint64
	}{
		{"unknown-both", "4d85c9740a48c7442420ffffffffc348c7442420ffffffffc3", math.MaxUint64},
		{"signed-compare", "48c7c0ffffffff4883f8017c0a48c744242000000000c348c744242001000000c3", 1},
		{"BSF-index-zero", "b8010000000fbcc0740a48c744242000000000c348c7442420ffffffffc3", 0},
		{"CL-masked", "b922000000ba01000000d3e24889542420c3", 4},
		{"CL-zero-keeps-flags", "31d2b920000000ba01000000d3e2750a48c744242001000000c348c744242002000000c3", 1},
		{"proved-dead-syscall", "31c085c0750a48c744242001000000c30f05c3", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, r := valueCallFixture(t, "test.short", '=', false, false)
			replaceValueCallee(t, b, r, tc.body)
			c, err := checkValueFixture(t, b, r)
			if err != nil {
				t.Fatal(err)
			}
			bound, _ := c.Bound()
			if bound.Results[0].Value != tc.want {
				t.Fatal("wrong native result", bound.Results)
			}
			if tc.name == "unknown-both" {
				if len(bound.Branches) != 1 || len(bound.Branches[0].Successors) != 2 {
					t.Fatal("unknown successor omitted")
				}
			}
			im, err := NewImage(t.Context(), b)
			if err != nil {
				t.Fatal(err)
			}
			checkValueCallOracle(t, im, bound, 20)
		})
	}
	for _, body := range []string{
		"4d85c9740a48c7442420ffffffffc348c744242000000000c3", // terminal disagreement
		"4d85c9740a48c7442420ffffffffc3c3",                   // one path omits the result write
		"31c00fbcc04889442420c3",                             // undefined BSF destination is not zero
		"31c00fbcc048c1e8204889442420c3",                     // nor is its high half assumed cleared
		"ba01000000c1e2020f9cc04889542420c3",                 // SHL count two leaves OF undefined
		"ebfe",                                               // reachable cycle
		"e800000000c3",                                       // nested call
	} {
		b, r := valueCallFixture(t, "test.short", '=', false, false)
		replaceValueCallee(t, b, r, body)
		c, err := checkValueFixture(t, b, r)
		valueCallRefusal(t, c, err)
	}
}

func TestValueCallCalleeMustProduceResult(t *testing.T) {
	b, r := valueCallFixture(t, "test.short", '=', false, false)
	prefix := hexBytes(t, "0fb6094889042448895c2408884c241048c7442418ffffffff")
	call := len(prefix)
	prefix = append(prefix, 0xe8, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(prefix[call+1:], uint32(0x260-len(prefix)))
	r.Continuation = testEntry + uint64(len(prefix))
	prefix = append(prefix, 0xc3)
	copy(b[0x1000:], prefix)
	replaceValueCallee(t, b, r, "c3")
	c, err := checkValueFixture(t, b, r)
	valueCallRefusal(t, c, err)
}

func FuzzValueCallShortSearch(f *testing.F) {
	for _, seed := range [][]byte{[]byte("test.short"), []byte("=abcdefghi"), []byte("abcdefghi="), {}, []byte{0, 255, '='}} {
		f.Add(seed, byte('='), false, byte('='))
	}
	f.Fuzz(func(t *testing.T, text []byte, needle byte, end bool, padding byte) {
		if len(text) > 15 {
			text = text[:15]
		}
		b, r := valueCallFixture(t, string(text), needle, end, true)
		p := r.Interface.Regions[0].Bytes.Start + r.Interface.Pointers[0].Pointer.Min
		for a := r.Interface.Regions[0].Bytes.Start; a < r.Interface.Regions[0].Bytes.End; a++ {
			if a < p || a >= p+uint64(len(text)) {
				b[a-testBase] = padding
			}
		}
		c, err := checkValueFixture(t, b, r)
		if err != nil {
			t.Fatal(err)
		}
		bound, _ := c.Bound()
		if bound.Results[0].Value != uint64(int64(bytes.IndexByte(text, needle))) {
			t.Fatal("native search result disagrees with byte specification")
		}
		im, err := NewImage(t.Context(), b)
		if err != nil {
			t.Fatal(err)
		}
		checkValueCallOracle(t, im, bound, 2)
	})
}

func TestValueCallOwnsAndCancels(t *testing.T) {
	raw, r := valueCallFixture(t, "test.short", '=', false, true)
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	count := &imageCallbackContext{Context: t.Context()}
	want, err := CheckValueCall(count, im, r, FrameLimits{})
	if err != nil {
		t.Fatal(err)
	}
	wb, _ := want.Bound()
	for at := 1; at <= count.calls; at++ {
		supplied := *im
		q := r
		q.Interface = cloneValueCallInterface(r.Interface)
		ctx := &imageCallbackContext{Context: t.Context(), onErr: func(n int) {
			if n == at {
				supplied = Image{}
				q.Interface.Scalars[0].Value = 99
				q.Interface.Readonly[0].End = 0
				q.Interface.Results[0].End = 0
				q.Interface.Pointers[0].Pointer.Min = 999
			}
		}}
		got, err := CheckValueCall(ctx, &supplied, q, FrameLimits{})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := got.Bound()
		if !reflect.DeepEqual(wb, b) {
			t.Fatal("callback changed owned values/image")
		}
		cancelCtx, cancel := context.WithCancel(t.Context())
		ctx = &imageCallbackContext{Context: cancelCtx, onErr: func(n int) {
			if n == at {
				cancel()
			}
		}}
		got, err = CheckValueCall(ctx, im, r, FrameLimits{})
		cancel()
		if _, ok := got.Bound(); ok || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled result: %v", err)
		}
	}
	b, _ := want.Bound()
	b.Results[0].Value = 0
	b.Instructions[0].Bytes[0] = 0
	b.Request.Interface.Scalars[0].Value = 0
	b.Branches[0].Successors[0] = 0
	now, _ := want.Bound()
	if !reflect.DeepEqual(now, wb) {
		t.Fatal("projection mutated certificate")
	}
	for _, l := range []FrameLimits{{Instructions: 1}, {States: 1}, {StateBytes: 1}, {RegionBytes: 1}, {Regions: 1}, {Work: 1}} {
		c, err := CheckValueCall(t.Context(), im, r, l)
		valueCallRefusal(t, c, err)
	}
	if _, ok := (ValueCall{}).Bound(); ok {
		t.Fatal("zero certificate")
	}
}
