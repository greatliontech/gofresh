package closure

import (
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func checkRootedWordPopulation(t testing.TB, width int, value, mask uint64, symbolic bool) {
	t.Helper()
	b := br.NewBuilder(256)
	originalScope, currentScope := br.NewScope(), br.NewScope()
	bytes := map[br.Term]br.Term{}
	var word br.Term
	var assignments []br.Assignment
	for lane := range width {
		original, err := b.Input(br.Bits(8), originalScope, uint64(lane))
		if err != nil {
			t.Fatal(err)
		}
		v := value >> uint(8*lane) & 255
		m := mask >> uint(8*lane) & 255
		current, err := b.Const(br.Bits(8), v^m)
		if symbolic {
			current, err = b.Input(br.Bits(8), currentScope, uint64(lane))
			assignments = append(assignments, br.Assignment{Variable: current, Value: v})
			constant, e := b.Const(br.Bits(8), m)
			if e != nil {
				t.Fatal(e)
			}
			current, err = b.Make(br.BitXor, br.Bits(8), 0, current, constant)
		}
		if err != nil {
			t.Fatal(err)
		}
		bytes[original] = current
		if lane == 0 {
			word = original
		} else {
			word, err = b.Make(br.Concat, br.Bits((lane+1)*8), 0, word, original)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	actual, err := rootedGlobalWord(t.Context(), b, word, bytes)
	if err != nil {
		t.Fatal(err)
	}
	got, err := br.Eval(t.Context(), actual, assignments, br.Limits{})
	want := (value ^ mask) & (^uint64(0) >> uint(64-8*width))
	if err != nil || got != want || actual.Sort() != br.Bits(8*width) {
		t.Fatalf("%d-byte current word: got=%#x want=%#x: %v", width, got, want, err)
	}
}

func TestRootedGlobalWordPopulation(t *testing.T) {
	values := []uint64{0, 1, ^uint64(0), 0x8000000000000000, 0x0102030405060708, 0x8001800280038004, 0xff00ff00ff00ff00, 0x0000000100000000}
	for width := 1; width <= 8; width++ {
		for _, value := range values {
			for _, mask := range values {
				for _, symbolic := range []bool{false, true} {
					checkRootedWordPopulation(t, width, value, mask, symbolic)
				}
			}
		}
	}
}

func FuzzRootedGlobalWord(f *testing.F) {
	f.Add(uint8(0), uint64(0), ^uint64(0), true)
	f.Add(uint8(7), uint64(0x0102030405060708), uint64(0x8001800280038004), true)
	f.Add(uint8(3), ^uint64(0), uint64(0), false)
	f.Fuzz(func(t *testing.T, width uint8, value, mask uint64, symbolic bool) {
		checkRootedWordPopulation(t, int(width%8)+1, value, mask, symbolic)
	})
}
