package transitionoracle

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func FuzzIntentEncoding(f *testing.F) {
	descriptors := allDescriptors()
	// Each finite descriptor starts reachable, while independent full-width
	// words keep the byte-payload domains intact under fuzz mutation.
	for index := range descriptors {
		f.Add(uint32(index), uint64(0xfedcba9876543210), int64(-0x12345678), uint64(1<<32), []byte{0xff, 0x66})
	}
	f.Fuzz(func(t *testing.T, selector uint32, immediate uint64, displacement int64, pc uint64, tail []byte) {
		desc := descriptors[uint64(selector)%uint64(len(descriptors))]
		i := withPayload(desc, immediate, displacement)
		b := roundTrip(t, i, desc.Encoding)
		next := new(big.Int).SetUint64(pc)
		next.Add(next, big.NewInt(int64(len(b))))
		target := new(big.Int).Set(next)
		if i.Operation == Jump || i.Operation == Branch {
			target.Add(target, big.NewInt(i.SignedDisp))
		}
		valid := next.IsUint64() && target.IsUint64()
		d, err := Parse(append(append([]byte{}, b...), tail...), pc)
		if (err == nil) != valid {
			t.Fatalf("%x @ %x: %+v %v; integer validity %v", b, pc, d, err, valid)
		}
		if !valid {
			if d != (Decoded{}) {
				t.Fatal("partial refusal")
			}
			return
		}
		if d.Intent != i || d.Encoding != desc.Encoding || d.Length != len(b) || d.Next != next.Uint64() {
			t.Fatalf("parse: %+v", d)
		}
		if (i.Operation == Jump || i.Operation == Branch) && d.Target != target.Uint64() {
			t.Fatalf("target: %+v; want %s", d, target)
		}
	})
}

func FuzzRawParse(f *testing.F) {
	for _, text := range []string{
		"", "0f", "0fa2", "660fa2", "48", "4889c0", "4f8b5f80", "4dc784e588776655123456f8",
		"4fbf1032547698badcfe", "b8ffffffff", "41bf00000080", "4f83e480",
		"4f2d00000080", "4f25ffffffff", "eb80", "e9ffffff7f", "4b8b0424",
		"498b042500000000", "67488b00", "664889c0", "c5f877", "488b04",
		"49ffc7", "d3e1", "45d3e7", "4519c7", "451bf8", "4121d1", "4423ca",
		"ffcf", "48d3e0", "4819c0", "4821c0", "66d3e0", "d3e8",
	} {
		b, _ := hex.DecodeString(text)
		f.Add(b, uint64(1<<32))
	}
	f.Fuzz(func(t *testing.T, code []byte, pc uint64) {
		d, err := Parse(code, pc)
		if err != nil {
			if d != (Decoded{}) {
				t.Fatal("partial refusal")
			}
			return
		}
		if d.Length < 2 || d.Length > 15 || d.Length > len(code) {
			t.Fatalf("length %d from %x", d.Length, code)
		}
		b, err := Encode(d.Intent, d.Encoding)
		if err != nil || !bytes.Equal(b, code[:d.Length]) {
			t.Fatalf("spelling changed: %x -> %x %v", code, b, err)
		}
		short, err := Parse(code[:d.Length], pc)
		if err != nil || short != d {
			t.Fatalf("tail affected parse: %+v / %+v %v", d, short, err)
		}
		assertIntegerPayloads(t, code, d)
		if d.Intent.Operation == Jump || d.Intent.Operation == Branch {
			assertTarget(t, d, pc)
		}
		for n := 0; n < d.Length; n++ {
			if partial, err := Parse(code[:n], pc); err == nil || partial != (Decoded{}) {
				t.Fatalf("proper prefix decoded: %x -> %+v %v", code[:n], partial, err)
			}
		}
	})
}
