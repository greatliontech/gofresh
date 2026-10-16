package nativeproof

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"golang.org/x/arch/x86/x86asm"
)

// This is a normal package-test build. Testing's own registration retains these
// callbacks naturally. Constant folding is intentional: a void RET still needs
// full effect/return checking and actual load/CALL transport, not an AX fiction.
const callbackCompilerFixture = `package callbacks
import "testing"
func scalar(x uint32) uint32 { return x+1 }
func TestScalar(t *testing.T) { if scalar(7) != 8 { t.Fail() } }
func TestAnotherName(t *testing.T) { if scalar(11) != 12 { t.Fail() } }
`

func buildCallbackFixture(t *testing.T) ([]byte, map[string]elf.Symbol) {
	t.Helper()
	dir := t.TempDir()
	for name, text := range map[string]string{"go.mod": "module example.com/nativecallbacks\n\ngo 1.27\n", "callback_test.go": callbackCompilerFixture} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env := os.Environ()
	for key, val := range map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "GOWORK": "off", "GOENV": "off", "GOFLAGS": "", "GOEXPERIMENT": "", "GOTOOLCHAIN": "local"} {
		env = gotool.SetEnv(env, key, val)
	}
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	if _, err := runner.Run(t.Context(), dir, env, "test", "-c", "-o", "callbacks.test", "."); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "callbacks.test"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	symbols, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	entries := make(map[string]elf.Symbol)
	for _, s := range symbols {
		entries[s.Name] = s
	}
	return raw, entries
}

func TestDefaultOptimizedPackageCallbackTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("builds an ordinary optimized package-test artifact")
	}
	raw, syms := buildCallbackFixture(t)
	im, err := NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	// Symbol size only bounds candidate discovery. It never reaches CheckCall.
	runner := syms["testing.tRunner"]
	if runner.Value == 0 {
		t.Fatal("fixture lacks tRunner candidate")
	}
	type candidate struct {
		pc  uint64
		ins x86asm.Inst
	}
	var recent []candidate
	var entry, continuation uint64
	var argumentOffset int64
	for pc := runner.Value; pc < runner.Value+runner.Size; {
		b, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		i, err := x86asm.Decode(b, 64)
		if err != nil || i.Len == 0 {
			t.Fatalf("discovery decode at %#x: %v", pc, err)
		}
		recent = append(recent, candidate{pc, i})
		if i.Op == x86asm.CALL && len(recent) >= 3 {
			load, arg := recent[len(recent)-3], recent[len(recent)-2]
			mem, memOK := load.ins.Args[1].(x86asm.Mem)
			stack, stackOK := arg.ins.Args[1].(x86asm.Mem)
			if load.ins.Op == x86asm.MOV && memOK && mem.Base == x86asm.RDX && mem.Disp == 0 && mem.Index == 0 &&
				arg.ins.Op == x86asm.MOV && arg.ins.Args[0] == x86asm.RAX && stackOK && stack.Base == x86asm.RSP && stack.Index == 0 && i.Args[0] == load.ins.Args[0] {
				entry, continuation, argumentOffset = load.pc, pc+uint64(i.Len), stack.Disp
				break
			}
		}
		pc += uint64(i.Len)
	}
	if entry == 0 {
		t.Fatal("ordinary selected harness has no supported candidate load/argument/CALL fragment")
	}
	// The linker need not expose function-descriptor symbols. The selected
	// generated tests header is a discovery candidate for its two initialized
	// rows. This layout inspection supplies addresses, never row immutability or
	// a proof of actual selection/use. Both are intentionally still open.
	header := syms["main.tests"].Value
	if header == 0 {
		t.Fatal("missing generated registration candidate")
	}
	word := func(address uint64) uint64 {
		for _, m := range im.loads {
			if address >= m.va && address-m.va <= m.filesz && m.filesz-(address-m.va) >= 8 {
				return binary.LittleEndian.Uint64(im.data[m.off+address-m.va:])
			}
		}
		t.Fatalf("candidate word %#x is not file-backed", address)
		return 0
	}
	rows := word(header)
	if word(header+8) != 2 || rows == 0 {
		t.Fatal("fixture registration discovery changed")
	}
	for row, name := range []string{"TestScalar", "TestAnotherName"} {
		t.Run(name, func(t *testing.T) {
			target := syms["example.com/nativecallbacks."+name]
			address := word(rows + uint64(row)*24 + 16)
			if target.Value == 0 || address == 0 {
				t.Fatalf("missing target/descriptor proposal for %s: %#x %#x", name, target.Value, address)
			}
			callee, err := prove(t, im, target.Value, face(Masks{RAX: math.MaxUint64}, Masks{}))
			if err != nil {
				t.Fatal(err)
			}
			d, err := CheckDescriptor(t.Context(), im, address, callee, descriptorConditions())
			if err != nil {
				t.Fatal(err)
			}
			f := callFace()
			f.Arguments[0].From.Offset = argumentOffset
			c, err := CheckCall(t.Context(), im, entry, continuation, d, f, 0)
			if err != nil {
				t.Fatal(err)
			}
			b, ok := c.Bound()
			if !ok || b.Descriptor.Target.Entry != target.Value || b.CallWrite.End-b.CallWrite.Start != 8 || b.Interface.Results != (Masks{}) {
				t.Fatal("missing actual call/void interface evidence")
			}
			// The same genuine tRunner still refuses a whole-entry leaf proof;
			// this local success has not silently supplied prologue/harness facts.
			whole, err := prove(t, im, runner.Value, face(Masks{RAX: math.MaxUint64}, Masks{}))
			requireRefusal(t, whole, err, "data-memory")
			// Actual generated registration storage is writable. Reading its
			// initialized descriptor pointer cannot prove mutation/use provenance.
			for _, writable := range []uint64{header, rows + 16} {
				bad, err := CheckDescriptor(t.Context(), im, writable, callee, descriptorConditions())
				if _, ok := bad.Bound(); ok {
					t.Fatal("writable generated registration became readonly evidence")
				}
				requireRefusal(t, Certificate{}, err, "descriptor-mapping")
			}
		})
	}
}
