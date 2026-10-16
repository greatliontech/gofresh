package closure

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

func TestComputationCallbackSelectedTestBodies(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and builds default-optimized selected package-test callbacks")
	}
	const pkg = "example.com/callbacksource"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod": "module " + pkg + "\n\ngo 1.27\n",
		"p.go":   "package p\nimport \"unicode/utf16\"\nfunc F(r rune)bool{return utf16.IsSurrogate(r)}\n",
		"p_test.go": `package p
import ("testing"; "os")
func TestSibling(t *testing.T){}
func TestScalar(t *testing.T){if !F(0xd800){t.Fail()}}
func TestUnproven(t *testing.T){if F(0){t.Fail()}else{t.Fail()}}
var unknown rune
func TestRuntimeUnknown(t *testing.T){if !F(unknown){t.Fail()}}
func TestAmbient(t *testing.T){os.Getenv("CALLBACK_SOURCE")}
`,
	})
	env := os.Environ()
	for key, value := range map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "GOWORK": "off"} {
		env = gotool.SetEnv(env, key, value)
	}
	h, err := newAtEnv(t.Context(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	loader := newFixturePrograms(t, h)
	loader.supply(t, pkg)
	metas, err := h.list(pkg)
	if err != nil {
		t.Fatal(err)
	}
	source := computationSource{prog: loader.loaded, metas: metas}
	artifact := filepath.Join(dir, "callback.test")
	command := append([]string{"test", "-c", "-o", artifact}, h.buildFlags...)
	command = append(command, ".")
	if _, err := (gotool.Runner{}).Run(t.Context(), dir, h.packageEnv, command...); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	image, err := nativeproof.NewImage(t.Context(), raw)
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
	entries := map[string]uint64{}
	var runner elf.Symbol
	for _, symbol := range syms {
		entries[symbol.Name] = symbol.Value
		if symbol.Name == "testing.tRunner" {
			runner = symbol
		}
	}
	callEntry, continuation, argumentOffset := discoverCallbackCall(t, raw, f, runner)
	header := entries["main.tests"]
	if header == 0 {
		t.Fatal("missing generated registration candidate")
	}
	word := func(address uint64) uint64 {
		b := callbackCandidateBytes(t, raw, f, address, 8)
		if len(b) != 8 {
			t.Fatal("truncated candidate word")
		}
		return binary.LittleEndian.Uint64(b)
	}
	rows := word(header)
	if rows == 0 || word(header+8) != 5 {
		t.Fatal("selected generated registration layout changed")
	}
	args := []computationScalarLocation{{nativeproof.RAX, 0, 64}}
	face := correspondenceFace(args, nil)
	for row, name := range []string{"TestSibling", "TestScalar"} {
		t.Run(name, func(t *testing.T) {
			root := source.prog.Roots[name]
			entry := entries[pkg+"."+name]
			if root == nil || entry == 0 {
				t.Fatal("actual selected callback absent")
			}
			request := callbackRequest(nil)
			request.calleeEntry, request.descriptor = entry, word(rows+uint64(row)*24+16)
			request.callee, request.arguments = face, args
			request.callEntry, request.continuation = callEntry, continuation
			request.call.Arguments[0].From.Offset = argumentOffset
			assembly, err := deriveComputationCallback(t.Context(), source, root, image, request)
			if err != nil {
				t.Fatal(err)
			}
			assertCallbackOpen(t, assembly)
			c := assembly.correspondence
			requireCorrespondenceWitnesses(t, c, 0)
			if c.source.root.parameters[0].name != "*testing.T" || c.source.root.parameters[0].pointerBits != 64 {
				t.Fatal("lost selected testing pointer interface")
			}
			bound, ok := c.native.Bound()
			if !ok || bound.Entry != entry || len(bound.Instructions) != 1 || bound.Interface.Results != (nativeproof.Masks{}) {
				t.Fatalf("default-optimized callback did not prove its RET: %+v", bound)
			}
			if name == "TestScalar" {
				requireSourceExclusions(t, c.source)
				found := false
				for _, dep := range c.source.dependencies {
					found = found || dep.function == "unicode/utf16.IsSurrogate"
				}
				if !found {
					t.Fatal("constant failure-branch proof bypassed actual selected callee")
				}
			}
			if c.open != (computationCorrespondenceObligations{true, true, true, true, true}) || c.source.open != (computationRelationObligations{true, true, true, true, true}) {
				t.Fatal("body theorem acquired startup/harness/runtime authority")
			}
			transfer, ok := assembly.transfer.Bound()
			if !ok || transfer.Descriptor.Target.Entry != entry || transfer.Descriptor.Target.Interface != face || transfer.Continuation.Span.Start != continuation {
				t.Fatal("source and actual CALL did not bind the same target/interface/continuation")
			}
			for _, change := range []func(*computationCallbackRequest){
				func(r *computationCallbackRequest) { r.descriptor = word(rows + 2*24 + 16) }, // actual effectful sibling target
				func(r *computationCallbackRequest) { r.continuation++ },
				func(r *computationCallbackRequest) { r.call.ContextRegister = nativeproof.R8 },
				func(r *computationCallbackRequest) { r.call.Arguments[0].From.Offset++ },
			} {
				bad := request
				bad.call.Arguments = append([]nativeproof.ArgumentTransfer(nil), request.call.Arguments...)
				change(&bad)
				if got, err := deriveComputationCallback(t.Context(), source, root, image, bad); got != nil || err == nil {
					t.Fatal("altered actual candidate acquired assembly")
				}
			}
			for _, writable := range []uint64{header, rows + uint64(row)*24 + 16} {
				d, err := nativeproof.CheckDescriptor(t.Context(), image, writable, c.native.Effects(), request.descriptorConditions)
				if _, ok := d.Bound(); ok || err == nil {
					t.Fatal("writable registration bytes became descriptor/use authority")
				}
			}
			otherImage, err := nativeproof.NewImage(t.Context(), raw)
			if err != nil {
				t.Fatal(err)
			}
			foreign, err := nativeproof.CheckDescriptor(t.Context(), otherImage, request.descriptor, c.native.Effects(), request.descriptorConditions)
			if _, ok := foreign.Bound(); ok || err == nil {
				t.Fatal("same named callback in byte-identical image borrowed source-correspondence evidence")
			}
			// Alter the actual CALL operand while leaving the descriptor and
			// callback body intact. Discovery labels cannot repair the broken flow.
			changed := append([]byte(nil), raw...)
			callBytes := callbackCandidateBytes(t, changed, f, transfer.Call, 2)
			if len(callBytes) != 2 || callBytes[0] != 0xff || callBytes[1] != 0xd1 {
				t.Fatal("fixture's register CALL encoding changed")
			}
			callBytes[1] = 0xd3 // CALL RBX instead of the descriptor-loaded RCX
			changedImage, err := nativeproof.NewImage(t.Context(), changed)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := deriveComputationCallback(t.Context(), source, root, changedImage, request); got != nil || err == nil {
				t.Fatal("actual CALL operand alteration acquired assembly")
			}
			t.Logf("same-image %s: target=%#x descriptor=%#x call=%#x continuation=%#x; registration/source-call/lifting/harness/applicability open", name, entry, request.descriptor, transfer.Call, continuation)
		})
	}
	for _, name := range []string{"TestUnproven", "TestRuntimeUnknown", "TestAmbient"} {
		if c, err := deriveComputationCorrespondence(t.Context(), source, source.prog.Roots[name], image, entries[pkg+".TestSibling"], face, args, nil); c != nil || err == nil {
			t.Fatal("reachable source effect corresponded to RET", name)
		}
	}
}

// These helpers discover candidates only. Neither disassembly, symbol extents,
// registration layout nor labels are passed as semantic evidence to the assembly.
// The existing checkers independently read its owned image and close each scope.
func callbackCandidateBytes(t *testing.T, raw []byte, f *elf.File, address uint64, count int) []byte {
	t.Helper()
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || address < p.Vaddr {
			continue
		}
		delta := address - p.Vaddr
		if delta >= p.Filesz {
			continue
		}
		n := min(uint64(count), p.Filesz-delta)
		start := p.Off + delta
		if start > uint64(len(raw)) || n > uint64(len(raw))-start {
			t.Fatal("candidate exceeds file backing")
		}
		return raw[start : start+n]
	}
	t.Fatalf("candidate %#x has no file backing", address)
	return nil
}

func discoverCallbackCall(t *testing.T, raw []byte, f *elf.File, runner elf.Symbol) (uint64, uint64, int64) {
	t.Helper()
	if runner.Value == 0 {
		t.Fatal("missing caller discovery candidate")
	}
	type candidate struct {
		pc          uint64
		instruction x86asm.Inst
	}
	var previous [2]candidate
	for pc, count := runner.Value, 0; pc-runner.Value < runner.Size && count < len(raw); count++ {
		i, err := x86asm.Decode(callbackCandidateBytes(t, raw, f, pc, 15), 64)
		if err != nil || i.Len <= 0 {
			t.Fatalf("caller candidate decode at %#x: %v", pc, err)
		}
		load, arg := previous[0], previous[1]
		mem, memOK := load.instruction.Args[1].(x86asm.Mem)
		stack, stackOK := arg.instruction.Args[1].(x86asm.Mem)
		if i.Op == x86asm.CALL && load.instruction.Op == x86asm.MOV && memOK && mem.Base == x86asm.RDX && mem.Index == 0 && mem.Disp == 0 &&
			arg.instruction.Op == x86asm.MOV && arg.instruction.Args[0] == x86asm.RAX && stackOK && stack.Base == x86asm.RSP && stack.Index == 0 && i.Args[0] == load.instruction.Args[0] {
			return load.pc, pc + uint64(i.Len), stack.Disp
		}
		previous[0], previous[1] = previous[1], candidate{pc, i}
		pc += uint64(i.Len)
	}
	t.Fatal("selected caller has no supported load/argument/CALL candidate")
	return 0, 0, 0
}
