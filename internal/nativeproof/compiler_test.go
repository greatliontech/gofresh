package nativeproof

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"golang.org/x/arch/x86/x86asm"
)

// Names discover entries only. The proof receives no names, symbol sizes, or
// source annotations. Address-taking retains the ordinary optimized bodies,
// including the actual software population count beside its intrinsic caller.
const compilerFixture = `package main
import("fmt";"math/bits";"os";"strconv";"unicode/utf16")
func Add(x,y uint64) uint64{return x+y}
func AddCompare(x,y uint64)(uint64,bool){s:=x+y;return s,s<x}
func Branch(x,y uint64)uint64{if x<y{return x+y};return x^y}
func Normalize(r rune)rune{if r<0||r>0x10ffff||utf16.IsSurrogate(r){return 0xfffd};return r}
func NormalizeVia(r rune,f func(rune)bool)rune{if r<0||r>0x10ffff||f(r){return 0xfffd};return r}
func Count(x uint64)int{return bits.OnesCount64(x)}
var binary=map[string]func(uint64,uint64)uint64{"add":Add,"branch":Branch}
var pairs=map[string]func(uint64,uint64)(uint64,bool){"pair":AddCompare}
var normalizers=map[string]func(rune)rune{"normalize":Normalize}
var predicates=map[string]func(rune)bool{"surrogate":utf16.IsSurrogate}
var encoders=map[string]func(rune)(rune,rune){"encode":utf16.EncodeRune}
var counters=map[string]func(uint64)int{"count":Count,"fallback":bits.OnesCount64}
var callbacks=map[string]func(rune,func(rune)bool)rune{"callback":NormalizeVia}
func main(){op:=os.Args[1];x,_:=strconv.ParseUint(os.Args[2],0,64);y,_:=strconv.ParseUint(os.Args[3],0,64)
if f:=binary[op];f!=nil{fmt.Println(f(x,y))}else if f:=pairs[op];f!=nil{a,b:=f(x,y);fmt.Println(a,b)}else if f:=normalizers[op];f!=nil{fmt.Println(f(rune(x)))}else if f:=predicates[op];f!=nil{fmt.Println(f(rune(x)))}else if f:=encoders[op];f!=nil{a,b:=f(rune(x));fmt.Println(a,b)}else if f:=counters[op];f!=nil{fmt.Println(f(x))}else if f:=callbacks[op];f!=nil{fmt.Println(f(rune(x),predicates["surrogate"]))}
fmt.Println("direct-normalize",Normalize(rune(x)))}
`

func buildCompilerFixture(t testing.TB) ([]byte, []elf.Symbol, map[string]uint64) {
	t.Helper()
	dir := t.TempDir()
	for name, text := range map[string]string{"go.mod": "module example.com/nativekernels\n\ngo 1.27\n", "main.go": compilerFixture} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := os.Environ()
	for key, val := range map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "GOWORK": "off", "GOENV": "off", "GOFLAGS": "", "GOEXPERIMENT": "", "GOTOOLCHAIN": "local"} {
		env = gotool.SetEnv(env, key, val)
	}
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	if _, err := runner.Run(t.Context(), dir, env, "build", "-o", "kernels", "."); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "kernels"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	entries := make(map[string]uint64)
	for _, s := range syms {
		entries[s.Name] = s.Value
	}
	return raw, syms, entries
}

func kernelSymbol(name string) string {
	if name == "OnesCount64" {
		return "math/bits.OnesCount64"
	}
	if name == "IsSurrogate" || name == "EncodeRune" {
		return "unicode/utf16." + name
	}
	return "main." + name
}

func TestDefaultOptimizedCompilerArtifact(t *testing.T) {
	if testing.Short() {
		t.Skip("builds one ordinary optimized linux/amd64 fixture")
	}
	raw, syms, entries := buildCompilerFixture(t)
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range kernels {
		name := kernelSymbol(k.name)
		t.Run(k.name, func(t *testing.T) {
			entry, ok := entries[name]
			if !ok {
				t.Fatalf("fixture did not retain %s", name)
			}
			if _, err := prove(t, im, entry, face(k.inputs, k.results)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, name := range []string{"main.Count", "main.NormalizeVia"} {
		entry, ok := entries[name]
		if !ok {
			t.Fatalf("fixture did not retain %s", name)
		}
		c, err := prove(t, im, entry, face(Masks{RAX: math.MaxUint64, RBX: math.MaxUint64}, Masks{RAX: math.MaxUint64}))
		r := requireRefusal(t, c, err, "data-memory")
		if r.PC != entry {
			t.Fatalf("expected actual stack-growth guard read, got %+v", r)
		}
	}
	// Independently locate the real CPU-selector load in Count's bytes, then
	// demonstrate that its actual mapping refuses without relying on its name.
	// The symbol extent is discovery only, never supplied to the checker.
	var count elf.Symbol
	for _, s := range syms {
		if s.Name == "main.Count" {
			count = s
		}
	}
	foundLoad, foundFeature, foundCall := false, false, false
	for pc := count.Value; pc < count.Value+count.Size; {
		b, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		i, err := x86asm.Decode(b, 64)
		if err != nil || i.Len == 0 {
			t.Fatalf("fixture discovery at %#x: %v", pc, err)
		}
		if i.Op == x86asm.MOVZX {
			if mem, ok := i.Args[1].(x86asm.Mem); ok && mem.Base == x86asm.RIP {
				foundLoad = true
				c, err := prove(t, im, pc, face(Masks{RAX: math.MaxUint64}, Masks{RAX: math.MaxUint64}))
				r := requireRefusal(t, c, err, "data-memory")
				if r.PC != pc {
					t.Fatal(r)
				}
			}
		}
		foundFeature = foundFeature || i.Op == x86asm.POPCNT
		foundCall = foundCall || i.Op == x86asm.CALL
		pc += uint64(i.Len)
	}
	if !foundLoad || !foundFeature || !foundCall {
		t.Fatalf("ordinary CPU dispatch fixture changed: selector=%v feature=%v call=%v", foundLoad, foundFeature, foundCall)
	}
}

func TestDecoderBoundariesAgainstGNU(t *testing.T) {
	objdump, err := exec.LookPath("objdump")
	if err != nil {
		t.Skip("independent GNU decoder not installed")
	}
	var raw []byte
	for _, k := range kernels {
		raw = append(raw, hexBytes(t, k.code)...)
	}
	// The connected memory/value domain adds the real legacy-SSE2 short-search
	// forms. Check their boundaries beside the original integer population.
	// Include the VEX tail: structural boundary evidence also serves unexecuted
	// cuts, independently of which forms receive execution semantics.
	raw = append(raw, hexBytes(t, searchBodyHex)...)
	// Canonical ZO forms, including both W values of the WIG three-byte prefix.
	for _, code := range []string{"c5f877", "c5fc77", "c4e17877", "c4e17c77", "c4e1f877", "c4e1fc77"} {
		raw = append(raw, hexBytes(t, code)...)
	}
	for _, tc := range vectorCutEncodings {
		raw = append(raw, hexBytes(t, tc.code)...)
	}
	// Broad register-form sample with varying ModRM, REX extension and width.
	for _, op := range []byte{0x89, 0x01, 0x31, 0x21, 0x39} {
		for modrm := 0xc0; modrm <= 0xff; modrm++ {
			for _, rex := range []byte{0x40, 0x48, 0x4d} {
				raw = append(raw, rex, op, byte(modrm))
			}
		}
	}
	file := filepath.Join(t.TempDir(), "instructions.bin")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), objdump, "-D", "-b", "binary", "-m", "i386:x86-64", "--insn-width=16", file).Output()
	if err != nil {
		t.Fatal(err)
	}
	gnu := make(map[int]int)
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(parts[0]), ":"), 16, 64)
		if err != nil {
			continue
		}
		encoded, err := hex.DecodeString(strings.Join(strings.Fields(parts[1]), ""))
		if err != nil || len(encoded) == 0 {
			t.Fatalf("unexpected GNU output %q", line)
		}
		gnu[int(addr)] = len(encoded)
	}
	count := 0
	im := image(t, raw)
	for at := 0; at < len(raw); {
		i, _, err := decodeBytes(im, testEntry+uint64(at))
		if err != nil || i.Len == 0 {
			t.Fatalf("decode at %d: %v", at, err)
		}
		if gnu[at] != i.Len {
			t.Fatalf("decoder disagreement at %#x: native=%d GNU=%d", at, i.Len, gnu[at])
		}
		count++
		at += i.Len
	}
	if count != len(gnu) {
		t.Fatalf("decoder inventories differ: %d vs %d", count, len(gnu))
	}
}
