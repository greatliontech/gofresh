package closure

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

// Inspect the selected compiler itself, retaining its actual optimization and
// image. Source/symbol names locate candidates only. The proof receives exact
// typed objects, owned bytes and an untrusted map, never these labels or sizes.
func TestGlobalOperandCorrespondenceSelectedRuntimeArtifact(t *testing.T) {
	if testing.Short() {
		t.Skip("loads the selected compiler source graph and inspects its optimized executable")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/representation\n\ngo 1.27\n"})
	s, _, h := loadSourceCommandFixture(t, dir, "cmd/compile")
	identity, err := h.runner.Run(t.Context(), h.dir, h.env, "env", "GOVERSION", "GOROOT", "GOTOOLDIR", "GOFLAGS", "GOEXPERIMENT", "GOAMD64", "GOOS", "GOARCH")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(identity)), "\n")
	if len(lines) != 8 || lines[6] != "linux" || lines[7] != "amd64" {
		t.Fatalf("selected native model requires linux/amd64: %q", identity)
	}
	path := filepath.Join(lines[2], "compile")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	if expected := os.Getenv("GOFRESH_REPRESENTATION_COMPILER_SHA256"); expected != "" && digest != expected {
		t.Fatalf("fixture artifact moved: actual=%s expected=%s", digest, expected)
	}
	t.Logf("selected identity: %q compiler=%s SHA256=%s; original artifact bytes and optimization retained", identity, path, digest)
	var root *ssa.Function
	var globals [2]*ssa.Global
	for _, p := range s.prog.Pkgs {
		if p.PkgPath == "runtime" {
			pkg := s.prog.Prog.Package(p.Types)
			root = pkg.Func("testAtomic64")
			globals = [2]*ssa.Global{pkg.Members["test_z64"].(*ssa.Global), pkg.Members["test_x64"].(*ssa.Global)}
		}
	}
	if root == nil {
		t.Fatal("selected runtime source root absent")
	}
	var call *ssa.Call
	for _, ins := range root.Blocks[0].Instrs {
		if c, ok := ins.(*ssa.Call); ok {
			call = c
			break
		}
	}
	if call == nil {
		t.Fatal("actual first source call absent")
	}
	limits := defaultRegistrationLimits()
	// Whole-runtime selected-syntax binding is intentionally larger than a tiny
	// synthetic package. Exhaustion still refuses; the prefix grammar stays small.
	limits.source = selectedSourceLimits{work: 20_000_000, depth: 256, bytes: 256 << 20}
	prefix, err := checkSourceOperandPrefix(t.Context(), s, root, call, limits)
	if err != nil {
		t.Fatal(err)
	}
	im, err := nativeproof.NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	e, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	syms, err := e.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	locations := map[string]uint64{}
	for _, symbol := range syms {
		locations[symbol.Name] = symbol.Value
	}
	a := [2]uint64{locations["runtime.test_z64"], locations["runtime.test_x64"]}
	function := locations["runtime.testAtomic64"]
	if a[0] == 0 || a[1] == 0 || function == 0 {
		t.Fatal("candidate symbols absent")
	}
	decode := func(pc uint64) x86asm.Inst {
		for _, p := range e.Progs {
			if p.Type == elf.PT_LOAD && pc >= p.Vaddr && pc-p.Vaddr < p.Filesz {
				off := p.Off + pc - p.Vaddr
				end := min(uint64(len(raw)), min(off+15, p.Off+p.Filesz))
				i, err := x86asm.Decode(raw[off:end], 64)
				if err != nil {
					t.Fatal(err)
				}
				return i
			}
		}
		t.Fatalf("candidate PC %#x unavailable", pc)
		return x86asm.Inst{}
	}
	var entry, cut uint64
	var expansions []nativeproof.TransitionExpansion
	for pc, n := function, 0; n < 64; n++ {
		i := decode(pc)
		if entry != 0 && i.Op == x86asm.XOR {
			expansions = append(expansions, nativeproof.TransitionExpansion{PC: pc})
		}
		if i.Op == x86asm.MOV && i.MemBytes == 8 {
			if m, ok := i.Args[0].(x86asm.Mem); ok && m.Base == x86asm.RIP && entry == 0 {
				entry = pc
			}
		}
		if i.Op == x86asm.CMPXCHG {
			cut = pc
			break
		}
		pc += uint64(i.Len)
	}
	if entry == 0 || cut <= entry {
		t.Fatal("bounded candidate discovery did not locate the operand region")
	}
	face := globalNativeFace([]nativeproof.Span{{Start: a[0], End: a[0] + 8}, {Start: a[1], End: a[1] + 8}})
	p, err := nativeproof.ProposeRegionTransition(t.Context(), im, entry, cut, nativeproof.TransitionLimits{}, nativeproof.TransitionOptions{Expansions: expansions})
	if err != nil {
		t.Fatal(err)
	}
	native, err := nativeproof.CheckRegionTransition(t.Context(), im, entry, face, p, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	rho := globalRho(s, globalNativeFixture{image: im}, globals, a)
	proof, err := checkGlobalOperandCorrespondence(t.Context(), s, root, call, im, entry, cut, prefix, native, rho)
	if err != nil {
		t.Fatal(err)
	}
	if proof == nil || proof.account == nil || len(proof.account.equalities) < 5 {
		t.Fatal("missing actual correspondence witnesses")
	}
	b, _ := native.Bound()
	t.Logf("selected source=%s first call=%s; conditional native [%#x,%#x), %d instructions, %d accesses; globals=%#x/%#x; unexecuted=%x; %d universal equalities", prefix.region.root.identity.position, root.Prog.Fset.Position(call.Pos()), entry, cut, len(b.Instructions), len(b.Accesses), a[0], a[1], b.Boundary.Bytes, len(proof.account.equalities))
	// Check both genuine foreign-owner evidence and the unchanged-image map swap,
	// not merely malformed addresses or a sampled output disagreement.
	swapped := rho
	swapped.bindings = append([]storageBinding(nil), rho.bindings...)
	swapped.bindings[0].base, swapped.bindings[1].base = nativeproof.ImageAddress(a[1]), nativeproof.ImageAddress(a[0])
	if c, err := checkGlobalOperandCorrespondence(t.Context(), s, root, call, im, entry, cut, prefix, native, swapped); c != nil || err == nil {
		t.Fatal("actual map-only swap accepted")
	}
	foreign, err := nativeproof.NewImage(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := checkGlobalOperandCorrespondence(t.Context(), s, root, call, foreign, entry, cut, prefix, native, rho); c != nil || err == nil {
		t.Fatal("actual equal-byte foreign owner accepted")
	}
	// A cut after the first store exercises inherited current bytes. It cannot
	// reapply loading, reset arbitrary inputs or choose a new root kind.
	first := entry + uint64(decode(entry).Len)
	p0, err := nativeproof.ProposeRegionTransition(t.Context(), im, entry, first, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	prior, err := nativeproof.CheckRegionTransition(t.Context(), im, entry, face, p0, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	p, err = nativeproof.ProposeTransitionContinuation(t.Context(), prior, cut, nativeproof.TransitionOptions{Expansions: expansions})
	if err != nil {
		t.Fatal(err)
	}
	continued, err := nativeproof.CheckTransitionContinuation(t.Context(), prior, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkGlobalOperandCorrespondence(t.Context(), s, root, call, im, entry, cut, prefix, continued, rho); err != nil {
		t.Fatal(err)
	}
	t.Log("positive is scoped operand preparation only; atomic/fallback/dispatch semantics, omitted prologue, ELF-entry reachability, whole-source actual use and bootstrap remain open")
}
