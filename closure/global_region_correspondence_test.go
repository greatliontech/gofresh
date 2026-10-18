package closure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"go/types"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

type pairedIntent struct {
	current, old, replacement, secondOld, secondReplacement uint64
}

func (i pairedIntent) outcomes() (bool, uint64, bool, uint64) {
	first, middle := i.current == i.old, i.current
	if first {
		middle = i.replacement
	}
	second, final := middle == i.secondOld, middle
	if second {
		final = i.secondReplacement
	}
	return first, middle, second, final
}

type pairedNativeFixture struct {
	globalNativeFixture
	use, next                    [2]uint64
	expansions                   []nativeproof.TransitionExpansion
	firstSet, replacementOperand int
	omitAtomic                   bool
}

func setPairedAtomicModel(face *nativeproof.TransitionInterface) {
	face.Conditions.Locked64 = nativeproof.Locked64Model
}

func globalRegionReference(t testing.TB, source computationSource, target *ssa.Function, captureLimits ...assemblyCaptureLimits) *assemblyReference {
	t.Helper()
	if source.owner == nil {
		t.Fatal("typed source was not constructed with its selected build owner")
	}
	provider, err := source.owner.packageFor(target)
	if err != nil {
		t.Fatal(err)
	}
	limits := assemblyCaptureLimits{}
	if len(captureLimits) > 1 {
		t.Fatal("more than one capture budget")
	}
	if len(captureLimits) == 1 {
		limits = captureLimits[0]
	}
	packet, err := acquireSelectedAssembly(t.Context(), source.owner, provider, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("captured cumulative resource usage=%+v", packet.packet.Usage())
	for _, provider := range packet.providerTexts() {
		t.Logf("captured final assembler provider=%s package=%s cwd=%s tool=%s argv=%q include=%q defines=%v expanded-lines=%d", provider.Source, provider.Invocation.Package, provider.Invocation.CWD, provider.Invocation.Tool, provider.Invocation.Args, provider.Invocation.IncludeDirs, provider.Invocation.Defines, len(provider.Lines))
	}
	files := packet.packet.Files()
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		t.Logf("captured input=%s bytes=%d SHA256=%x", path, len(files[path]), sha256.Sum256(files[path]))
	}
	for _, lookup := range packet.packet.Lookups() {
		t.Logf("captured include=%q selected=%s earlier-failed=%q", lookup.Name, lookup.Selected, lookup.Failed)
	}
	ref, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

// The encoder starts with the existing independent operand-prefix fixture. The
// suffix emits two RMW/result uses and explicit failure arms. The pure global
// guard loads are legally eliminated in this synthetic isolated region; the
// ordinary installed compiler fixture exercises their retained native form.
func pairedNativeImage(t testing.TB, a [2]uint64, intent pairedIntent, dataBase uint64, payload []byte, extra ...string) pairedNativeFixture {
	t.Helper()
	f := globalNativeImage(t, a, [3]uint64{intent.current, intent.old, intent.replacement}, a[0], dataBase, payload, "")
	const base = uint64(0x401000)
	code := slices.Clone(f.raw[4096 : 4096+int(f.cut-base)])
	p := pairedNativeFixture{globalNativeFixture: f}
	first, _, second, _ := intent.outcomes()
	var failures []int
	pc := func() uint64 { return base + uint64(len(code)) }
	for index, expect := range []bool{first, second} {
		p.expansions = append(p.expansions, nativeproof.TransitionExpansion{PC: pc()})
		code = append(code, 0xf0, 0x48, 0x0f, 0xb1, 0x11)
		p.expansions = append(p.expansions, nativeproof.TransitionExpansion{PC: pc()})
		if index == 0 {
			p.firstSet = 4096 + len(code) + 2
			code = append(code, 0x40, 0x0f, 0x94, 0xc6) // SETE SIL
			p.use[index] = pc()
			p.expansions = append(p.expansions, nativeproof.TransitionExpansion{PC: pc()})
			code = append(code, 0x40, 0x84, 0xf6) // TEST SIL,SIL
		} else {
			code = append(code, 0x0f, 0x94, 0xc2) // SETE DL
			p.use[index] = pc()
			p.expansions = append(p.expansions, nativeproof.TransitionExpansion{PC: pc()})
			code = append(code, 0x84, 0xd2) // TEST DL,DL
		}
		branch := byte(0x85) // unexpected true
		if expect {
			branch = 0x84 // unexpected false
		}
		code = append(code, 0x0f, branch)
		failures = append(failures, len(code))
		code = append(code, 0, 0, 0, 0)
		if index == 0 {
			if len(extra) == 1 && extra[0] == "extra-write" {
				storePC := pc()
				code = append(code, 0x48, 0xc7, 0x05)
				code = binary.LittleEndian.AppendUint32(code, uint32(int64(dataBase+120)-int64(storePC+11)))
				code = append(code, 0, 0, 0, 0)
			}
			code = append(code, 0x48, 0xb8)
			code = binary.LittleEndian.AppendUint64(code, intent.secondOld)
			storePC := pc()
			code = append(code, 0x48, 0x89, 0x05)
			code = binary.LittleEndian.AppendUint32(code, uint32(int64(a[1])-int64(storePC+7)))
			code = append(code, 0x48, 0xba)
			p.replacementOperand = 4096 + len(code)
			code = binary.LittleEndian.AppendUint64(code, intent.secondReplacement)
			if len(extra) == 1 && extra[0] == "wrong-second-target" {
				addressPC := pc()
				code = append(code, 0x48, 0x8d, 0x0d)
				code = binary.LittleEndian.AppendUint32(code, uint32(int64(a[1])-int64(addressPC+7)))
			}
			p.next[index] = pc()
		}
	}
	p.next[1] = pc()
	code = append(code, 0x48, 0x8b, 0x15)
	code = binary.LittleEndian.AppendUint32(code, uint32(int64(a[0])-int64(p.next[1]+7)))
	code = append(code, 0xc3)
	// A direct call is a structural boundary. The proof must establish its full
	// incoming condition false, and cannot manufacture a returned result. Each
	// phase has its own terminal, so the successor does not re-enter an already
	// excluded predecessor occurrence through another branch.
	for _, displacement := range failures {
		errorPC := pc()
		binary.LittleEndian.PutUint32(code[displacement:], uint32(int64(errorPC)-int64(base+uint64(displacement)+4)))
		code = append(code, 0xe8, 0, 0, 0, 0, 0xc3)
	}
	copy(p.raw[4096:], code)
	binary.LittleEndian.PutUint64(p.raw[64+32:], uint64(len(code)))
	binary.LittleEndian.PutUint64(p.raw[64+40:], uint64(len(code)))
	var err error
	p.image, err = nativeproof.NewImage(t.Context(), p.raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func pairedSteps(t testing.TB, f pairedNativeFixture, calls [3]*ssa.Call) []globalCorrespondenceStep {
	t.Helper()
	decode := globalCandidateDecoder(t, f.raw)
	var steps []globalCorrespondenceStep
	for index := range 2 {
		step := globalCorrespondenceStep{call: calls[index+1]}
		for j, cut := range []uint64{f.use[index], f.next[index]} {
			var expansions []nativeproof.TransitionExpansion
			for _, candidate := range f.expansions {
				if candidate.PC < cut && nativeproof.TransitionExpansionRequired(decode(candidate.PC)) {
					expansions = append(expansions, candidate)
				}
			}
			proposal, err := nativeproof.ProposeRegionTransition(t.Context(), f.image, f.entry, cut, nativeproof.TransitionLimits{}, expansions...)
			if err != nil {
				t.Fatal(err)
			}
			if j == 0 {
				step.use = proposal
			} else {
				step.next = proposal
			}
		}
		steps = append(steps, step)
	}
	return steps
}

// This decoder locates candidate operand forms only. Its bytes are independently
// reconstructed from the opaque image by native checking, and it supplies no
// transfer, reachability or selected-source association authority.
func globalCandidateDecoder(t testing.TB, raw []byte) func(uint64) x86asm.Inst {
	t.Helper()
	image, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	programs := image.Progs
	if err := image.Close(); err != nil {
		t.Fatal(err)
	}
	return func(pc uint64) x86asm.Inst {
		t.Helper()
		for _, load := range programs {
			if load.Type != elf.PT_LOAD || pc < load.Vaddr || pc-load.Vaddr >= load.Filesz {
				continue
			}
			offset := load.Off + pc - load.Vaddr
			end := min(uint64(len(raw)), min(offset+15, load.Off+load.Filesz))
			i, err := x86asm.Decode(raw[offset:end], 64)
			if err != nil {
				t.Fatal(err)
			}
			return i
		}
		t.Fatalf("candidate instruction %#x has no retained file bytes", pc)
		return x86asm.Inst{}
	}
}

func pairedCalls(t testing.TB, root *ssa.Function, target *ssa.Function) [3]*ssa.Call {
	t.Helper()
	var calls []*ssa.Call
	for _, block := range root.Blocks {
		for _, instruction := range block.Instrs {
			if call, ok := instruction.(*ssa.Call); ok && (call.Call.StaticCallee() == target || len(call.Call.Args) == 1 && call.Call.Args[0].Type().String() == "*uint64") {
				calls = append(calls, call)
			}
		}
	}
	slices.SortFunc(calls, func(a, b *ssa.Call) int { return int(a.Pos() - b.Pos()) })
	if len(calls) < 3 || calls[0].Call.StaticCallee() != target || calls[1].Call.StaticCallee() != target {
		t.Fatal("source call candidates are absent")
	}
	return [3]*ssa.Call{calls[0], calls[1], calls[2]}
}

func pairedOperandProof(t testing.TB, source computationSource, root *ssa.Function, calls [3]*ssa.Call, globals [2]*ssa.Global, addresses [2]uint64, fixture pairedNativeFixture, limits ...globalCorrespondenceLimits) *globalOperandCorrespondence {
	t.Helper()
	prefix, err := checkSourceOperandPrefix(t.Context(), source, root, calls[0], defaultRegistrationLimits())
	if err != nil {
		t.Fatal(err)
	}
	face := fixture.face
	if !fixture.omitAtomic {
		setPairedAtomicModel(&face)
	}
	proposal, err := nativeproof.ProposeRegionTransition(t.Context(), fixture.image, fixture.entry, fixture.cut, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	native, err := nativeproof.CheckRegionTransition(t.Context(), fixture.image, fixture.entry, face, proposal, nativeproof.TransitionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	rho := globalRho(source, fixture.globalNativeFixture, globals, addresses)
	proof, err := checkGlobalOperandCorrespondence(t.Context(), source, root, calls[0], fixture.image, fixture.entry, fixture.cut, prefix, native, rho, limits...)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestGlobalRegionCorrespondencePopulation(t *testing.T) {
	if testing.Short() {
		t.Skip("captures actual current assembly actions for the owned source population")
	}
	rng := rand.New(rand.NewSource(0x504149524544))
	var intents []pairedIntent
	var sourceText strings.Builder
	sourceText.WriteString("package main\nimport \"example.com/paired/ops\"\nfunc load(p *uint64) uint64{return *p}\n")
	for index := range 16 {
		intent := pairedIntent{current: rng.Uint64(), old: rng.Uint64(), replacement: rng.Uint64(), secondOld: rng.Uint64(), secondReplacement: rng.Uint64()}
		if index&1 != 0 {
			intent.old = intent.current
		}
		if index&4 != 0 {
			intent.replacement = intent.current
		}
		_, middle, _, _ := intent.outcomes()
		if index&2 != 0 {
			intent.secondOld = middle
		}
		if index&8 != 0 {
			intent.secondReplacement = middle
		}
		first, _, second, final := intent.outcomes()
		intents = append(intents, intent)
		fmt.Fprintf(&sourceText, "var z%d,x%d uint64\nfunc F%d(){z%d=%d;x%d=%d;if ops.Swap(&z%d,x%d,%d)!=%t{panic(1)};if x%d!=%d{panic(2)};x%d=%d;if ops.Swap(&z%d,x%d,%d)!=%t{panic(3)};if x%d!=%d||z%d!=%d{panic(4)};_ = load(&z%d)}\n", index, index, index, index, intent.current, index, intent.old, index, index, intent.replacement, first, index, intent.old, index, intent.secondOld, index, index, intent.secondReplacement, second, index, intent.secondOld, index, final, index)
	}
	sourceText.WriteString("var zh,xh,side uint64\nfunc hook(){side++}\nfunc FHook(){zh=42;xh=0;if ops.Swap(&zh,xh,1){panic(1)};hook();xh=42;if !ops.Swap(&zh,xh,1){panic(2)};_ = load(&zh)}\n")
	sourceText.WriteString("func main(){")
	for index := range intents {
		fmt.Fprintf(&sourceText, "F%d();", index)
	}
	sourceText.WriteString("}\n")
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":          "module example.com/paired\n\ngo 1.27\n",
		"main.go":         sourceText.String(),
		"ops/ops.go":      "package ops\n//go:noescape\nfunc Swap(p *uint64, old, new uint64) bool\n",
		"ops/ops_amd64.s": "#include \"textflag.h\"\nTEXT ·Swap(SB),NOSPLIT,$0-25\nMOVQ p+0(FP),BX\nMOVQ old+8(FP),AX\nMOVQ new+16(FP),CX\nLOCK\nCMPXCHGQ CX,0(BX)\nSETEQ ret+24(FP)\nRET\n",
	})
	source, main, _ := loadSourceCommandFixture(t, dir, "example.com/paired")
	var target *ssa.Function
	for _, pkg := range source.prog.Pkgs {
		if pkg.PkgPath == "example.com/paired/ops" {
			target = source.prog.Prog.Package(pkg.Types).Func("Swap")
		}
	}
	if target == nil {
		t.Fatal("selected assembly declaration is absent")
	}
	reference := globalRegionReference(t, source, target)
	refs := map[*ssa.Function]*assemblyReference{target: reference}
	var unchangedNative pairedNativeFixture
	for index, intent := range intents {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			root := main.Pkg.Func(fmt.Sprintf("F%d", index))
			calls := pairedCalls(t, root, target)
			globals := [2]*ssa.Global{main.Pkg.Members[fmt.Sprintf("z%d", index)].(*ssa.Global), main.Pkg.Members[fmt.Sprintf("x%d", index)].(*ssa.Global)}
			base := uint64(0x700000 + index*4096)
			addresses := [2]uint64{base + 8, base + 80}
			payload := make([]byte, 128)
			_, _ = rng.Read(payload)
			for _, permuted := range []bool{false, true} {
				a := addresses
				if permuted {
					a[0], a[1] = a[1], a[0]
				}
				fixture := pairedNativeImage(t, a, intent, base, payload)
				prior := pairedOperandProof(t, source, root, calls, globals, a, fixture)
				steps := pairedSteps(t, fixture, calls)
				proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, steps, refs)
				if err != nil {
					t.Fatalf("permuted=%t: %v", permuted, err)
				}
				assertPairedSource(t, proof, intent, globals)
				if !permuted && index == 3 {
					unchangedNative = fixture
					checkPairedRefusals(t, source, root, calls, globals, a, fixture, prior, steps, refs, intent, base, payload)
				}
			}
		})
	}
	t.Run("source-hook-after-reference", func(t *testing.T) {
		root := main.Pkg.Func("FHook")
		calls := pairedCalls(t, root, target)
		globals := [2]*ssa.Global{main.Pkg.Members["zh"].(*ssa.Global), main.Pkg.Members["xh"].(*ssa.Global)}
		addresses := [2]uint64{0x800008, 0x800050}
		fixture := pairedNativeImage(t, addresses, pairedIntent{42, 0, 1, 42, 1}, 0x800000, nil)
		prior := pairedOperandProof(t, source, root, calls, globals, addresses, fixture)
		proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, pairedSteps(t, fixture, calls), refs)
		var failure *regionOperationFailure
		if proof != nil || !errors.As(err, &failure) {
			t.Fatalf("source hook did not refuse at its actual operation: %v", err)
		}
		call, ok := failure.instruction.(*ssa.Call)
		if !ok || call.Call.StaticCallee() != main.Pkg.Func("hook") {
			t.Fatalf("source hook failed for another operation: %v", failure.instruction)
		}
	})
	t.Run("edited-selected-assembly-unchanged-inline", func(t *testing.T) {
		path := filepath.Join(dir, "ops", "ops_amd64.s")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.Replace(string(body), "SETEQ", "SETNE", 1)), 0600); err != nil {
			t.Fatal(err)
		}
		changedSource, changedMain, _ := loadSourceCommandFixture(t, dir, "example.com/paired")
		var changedTarget *ssa.Function
		for _, pkg := range changedSource.prog.Pkgs {
			if pkg.PkgPath == "example.com/paired/ops" {
				changedTarget = changedSource.prog.Prog.Package(pkg.Types).Func("Swap")
			}
		}
		if changedTarget == nil {
			t.Fatal("edited selected declaration absent")
		}
		changedReference := globalRegionReference(t, changedSource, changedTarget)
		root := changedMain.Pkg.Func("F3")
		calls := pairedCalls(t, root, changedTarget)
		globals := [2]*ssa.Global{changedMain.Pkg.Members["z3"].(*ssa.Global), changedMain.Pkg.Members["x3"].(*ssa.Global)}
		addresses := [2]uint64{0x703008, 0x703050}
		prior := pairedOperandProof(t, changedSource, root, calls, globals, addresses, unchangedNative)
		proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, pairedSteps(t, unchangedNative, calls), map[*ssa.Function]*assemblyReference{changedTarget: changedReference})
		var failure *regionOperationFailure
		if proof != nil || !errors.As(err, &failure) {
			t.Fatalf("edited reference did not expose its live source failure arm: %v", err)
		}
		guard, ok := calls[0].Block().Instrs[len(calls[0].Block().Instrs)-1].(*ssa.If)
		if !ok || failure.instruction.Block() != guard.Block().Succs[0] {
			t.Fatalf("edited reference failed before its actual Boolean consumer: %v", failure.instruction)
		}
	})
	t.Log("16 independently generated uint64 populations, four outcome pairs, two consistent layouts each; baseline acquisition plus edited selected-assembly/unchanged-inline control")
}

func assertPairedSource(t testing.TB, proof *globalRegionCorrespondence, intent pairedIntent, globals [2]*ssa.Global) {
	t.Helper()
	first, middle, second, final := intent.outcomes()
	if proof == nil || len(proof.phases) != 2 || len(proof.equalities) == 0 {
		t.Fatal("missing paired evidence")
	}
	for i, want := range []struct {
		result bool
		value  uint64
	}{{first, middle}, {second, final}} {
		trace := proof.phases[i].source.region.packet.trace
		if len(trace.calls) != 1 || trace.calls[0].result != want.result || trace.calls[0].value != want.value {
			t.Fatalf("phase %d differs from independent intent", i)
		}
		lockedReads, lockedWrites := 0, 0
		for _, access := range trace.accesses {
			if access.locked {
				if access.write {
					lockedWrites++
				} else {
					lockedReads++
				}
			}
		}
		if lockedReads != 1 || lockedWrites != 1 {
			t.Fatalf("phase %d lost its indivisible read/write cycle", i)
		}
	}
	state := proof.phases[1].source.region.packet.observations[0].state
	for i, want := range []uint64{final, intent.secondOld} {
		value, ok := regionUint64(readRegionLocation(state, regionLocation{object: regionObject{kind: regionGlobal, site: globals[i]}}, globals[i].Type().Underlying().(*types.Pointer).Elem()))
		if !ok || value != want {
			t.Fatalf("final global %d=%d known=%t want=%d", i, value, ok, want)
		}
	}
}

func checkPairedRefusals(t *testing.T, source computationSource, root *ssa.Function, calls [3]*ssa.Call, globals [2]*ssa.Global, addresses [2]uint64, fixture pairedNativeFixture, prior *globalOperandCorrespondence, steps []globalCorrespondenceStep, refs map[*ssa.Function]*assemblyReference, intent pairedIntent, dataBase uint64, payload []byte) {
	for _, mutation := range []struct {
		name   string
		offset int
		xor    byte
	}{{"wrong-result", fixture.firstSet, 1}, {"wrong-replacement", fixture.replacementOperand, 1}} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := fixture
			changed.raw = slices.Clone(fixture.raw)
			changed.raw[mutation.offset] ^= mutation.xor
			var err error
			changed.image, err = nativeproof.NewImage(t.Context(), changed.raw)
			if err != nil {
				t.Fatal(err)
			}
			base := pairedOperandProof(t, source, root, calls, globals, addresses, changed)
			candidate := pairedSteps(t, changed, calls)
			if proof, err := continueGlobalOperandCorrespondence(t.Context(), base, candidate, refs); proof != nil || err == nil || !strings.Contains(err.Error(), "bitrelation") {
				t.Fatalf("consumer mutation=%v proof=%v", err, proof != nil)
			}
		})
	}
	t.Run("widened-Boolean-use", func(t *testing.T) {
		changed := fixture
		changed.raw = slices.Clone(fixture.raw)
		offset := int(fixture.use[0]-0x401000) + 4096
		changed.raw[offset], changed.raw[offset+1] = 0x48, 0x85 // TEST RSI,RSI
		var err error
		changed.image, err = nativeproof.NewImage(t.Context(), changed.raw)
		if err != nil {
			t.Fatal(err)
		}
		base := pairedOperandProof(t, source, root, calls, globals, addresses, changed)
		proof, err := continueGlobalOperandCorrespondence(t.Context(), base, pairedSteps(t, changed, calls), refs)
		if proof != nil || err == nil || !strings.Contains(err.Error(), "exactly one byte") {
			t.Fatalf("widened use: %v", err)
		}
	})
	t.Run("live-throwing-arm", func(t *testing.T) {
		changed := fixture
		changed.raw = slices.Clone(fixture.raw)
		offset := int(fixture.use[0]-0x401000) + 4096
		changed.raw[offset+4] ^= 1 // JE <-> JNE after the three-byte TEST
		var err error
		changed.image, err = nativeproof.NewImage(t.Context(), changed.raw)
		if err != nil {
			t.Fatal(err)
		}
		base := pairedOperandProof(t, source, root, calls, globals, addresses, changed)
		proof, err := continueGlobalOperandCorrespondence(t.Context(), base, pairedSteps(t, changed, calls), refs)
		var refusal *nativeproof.Refusal
		if proof != nil || !errors.As(err, &refusal) || refusal.Premise != "transition-guard" {
			t.Fatalf("live error arm: %v", err)
		}
	})
	t.Run("extra-native-write", func(t *testing.T) {
		changed := pairedNativeImage(t, addresses, intent, dataBase, payload, "extra-write")
		base := pairedOperandProof(t, source, root, calls, globals, addresses, changed)
		proof, err := continueGlobalOperandCorrespondence(t.Context(), base, pairedSteps(t, changed, calls), refs)
		if proof != nil || err == nil || !strings.Contains(err.Error(), "read/write population") {
			t.Fatalf("extra native effect: %v", err)
		}
	})
	t.Run("different-intervening-store", func(t *testing.T) {
		changedIntent := intent
		changedIntent.secondOld ^= 1
		changed := pairedNativeImage(t, addresses, changedIntent, dataBase, payload)
		base := pairedOperandProof(t, source, root, calls, globals, addresses, changed)
		proof, err := continueGlobalOperandCorrespondence(t.Context(), base, pairedSteps(t, changed, calls), refs)
		if proof != nil || err == nil || !strings.Contains(err.Error(), "bitrelation") {
			t.Fatalf("intervening store: %v", err)
		}
	})
	t.Run("wrong-second-target", func(t *testing.T) {
		changed := pairedNativeImage(t, addresses, intent, dataBase, payload, "wrong-second-target")
		base := pairedOperandProof(t, source, root, calls, globals, addresses, changed)
		proof, err := continueGlobalOperandCorrespondence(t.Context(), base, pairedSteps(t, changed, calls), refs)
		if proof != nil || err == nil || !strings.Contains(err.Error(), "source pointer provenance") {
			t.Fatalf("wrong current pointer target: %v", err)
		}
	})
	t.Run("cannot-strengthen-root-applicability", func(t *testing.T) {
		changed := fixture
		changed.omitAtomic = true
		base := pairedOperandProof(t, source, root, calls, globals, addresses, changed)
		proof, err := continueGlobalOperandCorrespondence(t.Context(), base, steps, refs)
		var refusal *nativeproof.Refusal
		if proof != nil || !errors.As(err, &refusal) || refusal.Premise != "transition-primitive-premise" {
			t.Fatalf("strengthened root: %v", err)
		}
	})
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if proof, err := continueGlobalOperandCorrespondence(cancelled, prior, steps, refs); proof != nil || err == nil {
		t.Fatal("cancelled continuation published")
	}
	if proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, steps, nil); proof != nil || err == nil {
		t.Fatal("missing checked reference accepted")
	}
	wrong := slices.Clone(steps)
	wrong[0].call = calls[0]
	if proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, wrong, refs); proof != nil || err == nil {
		t.Fatal("nonadvancing source boundary accepted")
	}
	// The current native state cannot be resupplied through the API. Starting the
	// second proposed segment without its opaque predecessor must fail coverage.
	wrong = slices.Clone(steps)
	wrong[0].use = steps[1].use
	if proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, wrong, refs); proof != nil || err == nil {
		t.Fatal("unrelated Boolean-use boundary accepted")
	}
	low := *prior
	low.limit = low.work + 1
	if proof, err := continueGlobalOperandCorrespondence(t.Context(), &low, steps, refs); proof != nil || err == nil || !strings.Contains(err.Error(), "work exhausted") {
		t.Fatalf("cumulative bound: %v", err)
	}
}
