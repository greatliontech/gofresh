package nativeproof

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"testing"
)

// Each abstract value describes two independently chosen concrete states with
// agreeing declared bits. Constant-bit claims must hold in both states too.
func sampleValue(r *rand.Rand, width int) (value, uint64, uint64) {
	d := r.Uint64() & mask(width)
	k := r.Uint64() & d
	c := r.Uint64() & k
	x := r.Uint64() & mask(width)
	x = x&^k | c
	y := r.Uint64()&mask(width)&^d | x&d
	return value{d, k &^ c, c}, x, y
}

func testDefinedness(t testing.TB, seed uint64, rounds int) {
	t.Helper()
	r := rand.New(rand.NewPCG(seed, seed^0x6a09e667f3bcc909))
	for step := 0; step < rounds; step++ {
		width := 32 + 32*r.IntN(2)
		a, x1, x2 := sampleValue(r, width)
		b, y1, y2 := sampleValue(r, width)
		shift := r.IntN(width)
		for _, tc := range []struct {
			name          string
			abstract      value
			first, second uint64
		}{
			{"add", add(a, b, width), x1 + y1, x2 + y2},
			{"xor", xor(a, b, width), x1 ^ y1, x2 ^ y2},
			{"and", and(a, b, width), x1 & y1, x2 & y2},
			{"shr", shr(a, shift, width), x1 >> shift, x2 >> shift},
			{"lea-scale", shl(a, min(shift, 3), width), x1 << min(shift, 3), x2 << min(shift, 3)},
		} {
			v := tc.abstract
			if v.zero&v.one != 0 || (v.zero|v.one)&^v.defined != 0 || v.defined&^mask(width) != 0 {
				t.Fatalf("invalid %s abstract state: %+v", tc.name, v)
			}
			if (tc.first^tc.second)&v.defined != 0 {
				t.Fatalf("%s depends on scratch: a=%+v b=%+v result=%+v x=%#x/%#x y=%#x/%#x", tc.name, a, b, v, x1, x2, y1, y2)
			}
			if (tc.first|tc.second)&v.zero != 0 || tc.first&v.one != v.one || tc.second&v.one != v.one {
				t.Fatalf("false %s constant claim: %+v", tc.name, v)
			}
		}
	}
}

func TestAbstractDependenceAgainstConcreteBitvectors(t *testing.T) {
	testDefinedness(t, 0x243f6a8885a308d3, 10000)
}

func FuzzAbstractDependence(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(math.MaxUint64))
	f.Add(uint64(0x123456789abcdef))
	f.Fuzz(func(t *testing.T, seed uint64) { testDefinedness(t, seed, 20) })
}

func FuzzMappedInstructions(f *testing.F) {
	for _, k := range kernels {
		f.Add(hexBytes(f, k.code))
	}
	for _, s := range []string{"f04801d8c3", "39c074ff90c3", "ebfe", "488b00c3", "48", "c20800",
		"488d80f8ffffffc3", "488d84d800000080c3", "488d04ddffffff7fc3", "488d05f8ffffffc3", "48a1f8ffffff01000000c3"} {
		f.Add(hexBytes(f, s))
	}
	f.Fuzz(func(t *testing.T, code []byte) {
		if len(code) == 0 || len(code) > 256 {
			t.Skip()
		}
		im := image(t, code)
		in := Masks{}
		for i := range in {
			if i != int(RSP) {
				in[i] = math.MaxUint64
			}
		}
		face := face(in, Masks{RAX: math.MaxUint64})
		p, err := Propose(t.Context(), im, testEntry, face)
		if err != nil {
			return
		}
		c, err := Check(t.Context(), im, testEntry, face, p)
		if err != nil {
			if _, ok := c.Bound(); ok {
				t.Fatal("refusal authorized")
			}
			return
		}
		b, ok := c.Bound()
		if !ok || len(b.Instructions) == 0 {
			t.Fatal("empty successful proof")
		}
		// A proposer cannot truncate even one checked node after a success.
		p.Nodes = p.Nodes[:len(p.Nodes)-1]
		bad, err := Check(t.Context(), im, testEntry, face, p)
		requireRefusal(t, bad, err, "proposal-inventory")
	})
}

func FuzzELFAdmission(f *testing.F) {
	f.Add(elfBytes([]byte{0x31, 0xc0, 0xc3}))
	f.Add([]byte("not ELF"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<16 {
			t.Skip()
		}
		im, err := NewImage(t.Context(), raw)
		if err != nil {
			if im != nil {
				t.Fatal("partial image on refusal")
			}
			return
		}
		if im == nil || len(im.loads) == 0 {
			t.Fatal("missing bound image")
		}
		// Even an admitted image does not confer entry proof authority.
		_, _ = prove(t, im, testEntry, face(Masks{}, Masks{RAX: math.MaxUint64}))
	})
}

type checkpointContext struct {
	context.Context
	remaining int
}

func (c *checkpointContext) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}
	return nil
}

func TestCancellationWithinTraversalAndChecking(t *testing.T) {
	code := make([]byte, 129)
	for i := range code {
		code[i] = 0x90
	}
	code[len(code)-1] = 0xc3
	im := image(t, code)
	f := face(Masks{RAX: math.MaxUint64}, Masks{RAX: math.MaxUint64})
	p, err := Propose(t.Context(), im, testEntry, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []int{2, 16, 130, 260, 400, 600} {
		ctx := &checkpointContext{Context: context.Background(), remaining: at}
		c, err := Check(ctx, im, testEntry, f, p)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("checkpoint %d: %v", at, err)
		}
		if _, ok := c.Bound(); ok {
			t.Fatal("partial checked result")
		}
	}
	ctx := &checkpointContext{Context: context.Background(), remaining: 3}
	if im, err := NewImage(ctx, make([]byte, 256<<10)); im != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("copy cancellation: %v", err)
	}
}
