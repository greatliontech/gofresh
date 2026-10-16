package nativeproof

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"golang.org/x/arch/x86/x86asm"
)

const valueCallCompilerFixture = `package search
import("flag";"strings";"testing")
func Probe(s string)bool{return strings.Contains(s,"=")}
var probes=map[string]func(string)bool{"probe":Probe}
var names=[]string{"test.short","alpha.beta","=abcdefghi","abcdefghi="}
func TestDiscovery(t *testing.T){
 f:=flag.NewFlagSet("inspect",flag.ContinueOnError);f.Bool("test.short",false,"")
 for _,name:=range names{_ = probes["probe"](name)}
}
`

func TestValueCallDefaultOptimizedArtifact(t *testing.T) {
	if testing.Short() {
		t.Skip("builds an ordinary optimized package-test artifact")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("native selected ELF/amd64 fixture")
	}
	dir := t.TempDir()
	for file, text := range map[string]string{"go.mod": "module example.com/valuecall\n\ngo 1.27\n", "search_test.go": valueCallCompilerFixture} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Preserve the requested normal build environment, including CGO and flags.
	runner := gotool.Runner{Containment: &gotool.Containment{}}
	if _, err := runner.Run(t.Context(), dir, os.Environ(), "test", "-c", "-o", "search.test", "."); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "search.test"))
	if err != nil {
		t.Fatal(err)
	}
	im, err := NewImage(t.Context(), raw)
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
	var caller, probe elf.Symbol
	var target, header uint64
	for _, symbol := range syms {
		if symbol.Name == "internal/stringslite.Index" {
			caller = symbol
		}
		if symbol.Name == "internal/bytealg.IndexByteString.abi0" {
			target = symbol.Value
		}
		if symbol.Name == "example.com/valuecall.Probe" {
			probe = symbol
		}
		if symbol.Name == "example.com/valuecall.names" {
			header = symbol.Value
		}
	}
	if caller.Value == 0 || target == 0 {
		t.Fatal("missing native call candidates")
	}
	// Metadata bounds candidate discovery only. No proposed instructions or
	// symbol sizes enter CheckValueCall, which decodes all feasible successors.
	var recent []uint64
	var entry, continuation uint64
	for pc := caller.Value; pc-caller.Value < caller.Size; {
		b, err := im.instructionBytes(pc)
		if err != nil {
			t.Fatal(err)
		}
		i, err := x86asm.Decode(b, 64)
		if err != nil || i.Len == 0 {
			t.Fatal("candidate decode", err)
		}
		recent = append(recent, pc)
		if rel, ok := i.Args[0].(x86asm.Rel); i.Op == x86asm.CALL && ok && pc+uint64(i.Len)+uint64(rel) == target && len(recent) >= 5 {
			start := recent[len(recent)-5]
			b, _ := im.instructionBytes(start)
			first, err := x86asm.Decode(b, 64)
			if mem, ok := first.Args[1].(x86asm.Mem); err == nil && first.Op == x86asm.MOVZX && ok && first.Args[0] == x86asm.ECX && mem.Base == x86asm.RCX && mem.Disp == 0 {
				entry, continuation = start, pc+uint64(i.Len)
				break
			}
		}
		pc += uint64(i.Len)
	}
	if entry == 0 {
		t.Fatal("no supported actual needle-load/marshaling/CALL candidate")
	}
	var needle uint64
	for pc := probe.Value; pc-probe.Value < probe.Size; {
		b, _ := im.instructionBytes(pc)
		i, err := x86asm.Decode(b, 64)
		if err != nil || i.Len == 0 {
			t.Fatal("probe discovery decode", err)
		}
		if mem, ok := i.Args[1].(x86asm.Mem); i.Op == x86asm.LEA && i.Args[0] == x86asm.RCX && ok && mem.Base == x86asm.RIP {
			candidate := pc + uint64(i.Len) + uint64(mem.Disp)
			data, _, err := im.readonlyBytes(candidate, 1, "discovery", "discovery")
			if err == nil && data[0] == '=' {
				needle = candidate
				break
			}
		}
		pc += uint64(i.Len)
	}
	if needle == 0 || header == 0 {
		t.Fatal("missing actual literal/carrier candidates")
	}
	word := func(address uint64) uint64 {
		for _, load := range im.loads {
			if address >= load.va && address-load.va <= load.filesz && load.filesz-(address-load.va) >= 8 {
				return binary.LittleEndian.Uint64(im.data[load.off+address-load.va:])
			}
		}
		t.Fatal("unbacked carrier word")
		return 0
	}
	rows := word(header)
	if word(header+8) != 4 {
		t.Fatal("fixture carrier shape changed")
	}
	for row, text := range []string{"test.short", "alpha.beta", "=abcdefghi", "abcdefghi="} {
		t.Run(text, func(t *testing.T) {
			p := word(rows + uint64(row)*16)
			if word(rows+uint64(row)*16+8) != uint64(len(text)) {
				t.Fatal("literal length candidate differs")
			}
			data, _, err := im.readonlyBytes(p, uint64(len(text)), "discovery", "discovery")
			if err != nil || !bytes.Equal(data, []byte(text)) {
				t.Fatal("literal candidate differs", err)
			}
			window := Span{p, p + 16}
			if (p+16)&0xff0 == 0 {
				window = Span{p + uint64(len(text)) - 16, p + uint64(len(text))}
			}
			_, r := valueCallFixture(t, text, '=', false, false)
			r.Entry, r.Target, r.Continuation = entry, target, continuation
			r.Interface.Regions[0].Bytes = window
			r.Interface.Regions[1].Bytes = Span{needle, needle + 1}
			r.Interface.Readonly = []Span{window, {needle, needle + 1}}
			r.Interface.Pointers[0].Pointer = RegionPointer{0, p - window.Start, p - window.Start}
			c, err := CheckValueCall(t.Context(), im, r, FrameLimits{})
			if err != nil {
				t.Fatal(err)
			}
			b, _ := c.Bound()
			want := uint64(int64(bytes.IndexByte([]byte(text), '=')))
			if b.Results[0].Value != want {
				t.Fatalf("derived result %#x != %#x", b.Results[0].Value, want)
			}
			checkValueCallOracle(t, im, b, 20)
			t.Logf("entry=%#x CALL=%#x target=%#x continuation=%#x result[%#x]=%#x; source-call/lifting/harness/applicability open", entry, b.Call, target, continuation, b.Results[0].Bytes.Start, b.Results[0].Value)
		})
	}
}
