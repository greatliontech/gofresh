package closure

import (
	"bytes"
	"errors"
	"fmt"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/assemblycapture"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

type globalReferenceEffectsSelection struct {
	source    computationSource
	root      *ssa.Function
	target    *ssa.Function
	calls     [3]*ssa.Call
	globals   [2]*ssa.Global
	reference *assemblyReference
}

func loadGlobalReferenceEffectsSelection(t *testing.T, dir string) globalReferenceEffectsSelection {
	t.Helper()
	const path = "example.com/referenceeffects"
	source, main, _ := loadSourceCommandFixture(t, dir, path)
	var target *ssa.Function
	for _, pkg := range source.prog.Pkgs {
		if pkg.PkgPath == path+"/ops" {
			target = source.prog.Prog.Package(pkg.Types).Func("Swap")
		}
	}
	if target == nil {
		t.Fatal("selected assembly declaration is absent")
	}
	root := main.Pkg.Func("F")
	return globalReferenceEffectsSelection{
		source: source, root: root, target: target,
		calls:     pairedCalls(t, root, target),
		globals:   [2]*ssa.Global{main.Pkg.Members["z"].(*ssa.Global), main.Pkg.Members["x"].(*ssa.Global)},
		reference: globalRegionReference(t, source, target),
	}
}

func globalReferenceEffectsFixture(t *testing.T) (string, string, pairedIntent, [2]uint64, pairedNativeFixture, globalReferenceEffectsSelection) {
	t.Helper()
	// Failure first, success second. The ordinary write controls below therefore
	// exercise an unchanged failed-RMW writeback and a changed successful value.
	intent := pairedIntent{current: 42, old: 0, replacement: 1, secondOld: 42, secondReplacement: 7}
	first, _, second, final := intent.outcomes()
	dir := t.TempDir()
	body := "#include \"textflag.h\"\n" + strings.Replace(assemblyReferenceUnitBody, ",4,", ",NOSPLIT,", 1)
	// A nil panic payload keeps the failure arm's first operation the panic
	// itself, rather than an unrelated interface-construction boundary.
	writeTree(t, dir, map[string]string{
		"go.mod": "module example.com/referenceeffects\n\ngo 1.27\n",
		"main.go": fmt.Sprintf(`package main
import "example.com/referenceeffects/ops"
var z, x uint64
func load(p *uint64) uint64 { return *p }
func F() {
 z = %d; x = %d
 if ops.Swap(&z, x, %d) != %t { panic(nil) }
 if x != %d { panic(nil) }
 x = %d
 if ops.Swap(&z, x, %d) != %t { panic(nil) }
 if x != %d || z != %d { panic(nil) }
 _ = load(&z)
}
func main() { F() }
`, intent.current, intent.old, intent.replacement, first, intent.old, intent.secondOld, intent.secondReplacement, second, intent.secondOld, final),
		"ops/ops.go":      "package ops\n//go:noescape\nfunc Swap(ptr *uint64, old, replacement uint64) bool\n",
		"ops/ops_amd64.s": body,
	})
	addresses := [2]uint64{0x700008, 0x700050}
	native := pairedNativeImage(t, addresses, intent, 0x700000, []byte{0xa5, 0x61, 0x39})
	selection := loadGlobalReferenceEffectsSelection(t, dir)
	return dir, body, intent, addresses, native, selection
}

func globalReferenceEffectsPositive(t *testing.T, selection globalReferenceEffectsSelection, fixture pairedNativeFixture, addresses [2]uint64, intent pairedIntent) *globalOperandCorrespondence {
	t.Helper()
	prior := pairedOperandProof(t, selection.source, selection.root, selection.calls, selection.globals, addresses, fixture)
	proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, pairedSteps(t, fixture, selection.calls), map[*ssa.Function]*assemblyReference{selection.target: selection.reference})
	if err != nil {
		t.Fatalf("normal selected reference/unchanged inline positive: %v", err)
	}
	assertPairedSource(t, proof, intent, selection.globals)
	return prior
}

func globalReferenceTextflagLookup(t *testing.T, reference *assemblyReference) (assemblycapture.Provider, assemblycapture.Lookup, []byte) {
	t.Helper()
	packet := reference.checked.acquisition
	providers := packet.providerTexts()
	if len(providers) != 1 {
		t.Fatalf("expected one actual provider, got %d", len(providers))
	}
	var lookups []assemblycapture.Lookup
	for _, lookup := range packet.packet.Lookups() {
		if lookup.Name == "textflag.h" {
			lookups = append(lookups, lookup)
		}
	}
	if len(lookups) != 1 {
		t.Fatalf("textflag lookup was not retained exactly once: %+v", lookups)
	}
	header, found := packet.packet.Files()[lookups[0].Selected]
	if !found || len(header) == 0 {
		t.Fatal("selected textflag bytes were not retained")
	}
	return providers[0], lookups[0], header
}

func TestGlobalReferenceCWDTextflagChangesBoolean(t *testing.T) {
	if testing.Short() {
		t.Skip("acquires actual final assembler inputs and checks selected-source/inline composition")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("real selected assembly acquisition requires Linux amd64")
	}
	dir, _, intent, addresses, native, baseline := globalReferenceEffectsFixture(t)
	globalReferenceEffectsPositive(t, baseline, native, addresses, intent)
	provider, lookup, header := globalReferenceTextflagLookup(t, baseline.reference)
	localHeader := filepath.Join(provider.Invocation.CWD, "textflag.h")
	relative, err := filepath.Rel(dir, provider.Invocation.CWD)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		t.Fatal("fixture assembler CWD is not in the owned temporary tree")
	}
	rootHeader := filepath.Join(baseline.reference.checked.acquisition.selectionEnv()["GOROOT"], "pkg", "include", "textflag.h")
	if filepath.Clean(lookup.Selected) != filepath.Clean(rootHeader) || len(lookup.Failed) == 0 || filepath.Clean(lookup.Failed[0]) != filepath.Clean(localHeader) || !slices.Contains(provider.Invocation.IncludeDirs, filepath.Dir(rootHeader)) {
		t.Fatalf("baseline did not establish CWD-before-GOROOT lookup precedence: cwd=%s lookup=%+v includes=%v", provider.Invocation.CWD, lookup, provider.Invocation.IncludeDirs)
	}
	// Preserve the valid flags from the actually selected owned header. Only the
	// instruction macro changes: an invalid NOSPLIT value would test refusal of
	// frame prerequisites instead of interpretation of the shadowed instruction.
	shadow := append(bytes.Clone(header), []byte("\n#define SETEQ SETNE\n")...)
	if err := os.WriteFile(localHeader, shadow, 0600); err != nil {
		t.Fatal(err)
	}
	changed := loadGlobalReferenceEffectsSelection(t, dir)
	changedProvider, changedLookup, changedHeader := globalReferenceTextflagLookup(t, changed.reference)
	if changedProvider.Invocation.CWD != provider.Invocation.CWD || filepath.Clean(changedLookup.Selected) != filepath.Clean(localHeader) || len(changedLookup.Failed) != 0 || !bytes.Equal(changedHeader, shadow) || !slices.Contains(changedProvider.Invocation.IncludeDirs, filepath.Dir(rootHeader)) {
		t.Fatalf("actual final assembler did not select the CWD shadow ahead of the retained GOROOT include: %+v", changedLookup)
	}
	if !bytes.Equal(baseline.reference.checked.acquisition.packet.Files()[provider.Source], changed.reference.checked.acquisition.packet.Files()[changedProvider.Source]) {
		t.Fatal("top-level assembly changed instead of the CWD header")
	}
	if changed.reference.checked.relation.definition.flags != baseline.reference.checked.relation.definition.flags || !changed.reference.checked.relation.returnProof.Valid() || !changed.reference.checked.relation.booleanProof.Valid() {
		t.Fatal("shadowed body did not retain valid flags, return and Boolean derivations")
	}
	setNotEqual, setEqual := 0, 0
	for _, line := range changedProvider.Lines {
		if len(line.Tokens) > 0 {
			switch line.Tokens[0] {
			case "SETNE":
				setNotEqual++
			case "SETEQ":
				setEqual++
			}
		}
	}
	if setNotEqual != 1 || setEqual != 0 {
		t.Fatal("the captured expanded source did not carry the SETEQ-to-SETNE change")
	}
	_, middle, _, _ := intent.outcomes()
	for _, args := range [][3]uint64{{intent.current, intent.old, intent.replacement}, {middle, intent.secondOld, intent.secondReplacement}} {
		ordinary, err := baseline.reference.evaluate(t.Context(), args[0], args[1], args[2])
		if err != nil {
			t.Fatal(err)
		}
		inverted, err := changed.reference.evaluate(t.Context(), args[0], args[1], args[2])
		if err != nil {
			t.Fatal("valid shadowed reference could not be applied:", err)
		}
		if ordinary.Value != inverted.Value || assemblyReferenceBool(t, ordinary.Result) == assemblyReferenceBool(t, inverted.Result) || !slices.Equal(ordinary.Accesses, inverted.Accesses) {
			t.Fatalf("shadow did not change only the derived Boolean: ordinary=%+v shadow=%+v", ordinary, inverted)
		}
	}
	// This is a fresh successful operand proof for the changed source owner and
	// the very same independently owned native image. The failure must then be
	// the now-live Boolean error arm, not acquisition, provider or owner binding.
	prior := pairedOperandProof(t, changed.source, changed.root, changed.calls, changed.globals, addresses, native)
	proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, pairedSteps(t, native, changed.calls), map[*ssa.Function]*assemblyReference{changed.target: changed.reference})
	var failure *regionOperationFailure
	if proof != nil || !errors.As(err, &failure) {
		t.Fatalf("changed CWD-header reference did not reject unchanged inline execution at its source operation: %v", err)
	}
	guard, ok := changed.calls[0].Block().Instrs[len(changed.calls[0].Block().Instrs)-1].(*ssa.If)
	_, panics := failure.instruction.(*ssa.Panic)
	if !ok || !panics || failure.instruction.Block() != guard.Block().Succs[0] {
		t.Fatalf("shadowed reference failed before its actual Boolean failure arm: %v", failure.instruction)
	}
	t.Logf("final assembler CWD shadow selected=%s before GOROOT=%s; valid frame, inverted Boolean, unchanged inline rejected at %s", changedLookup.Selected, rootHeader, failure.instruction)
}

func TestGlobalReferenceSameValueWriteRejectsUnchangedInline(t *testing.T) {
	if testing.Short() {
		t.Skip("acquires an edited assembly body and compares complete reference/native effects")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("real selected assembly acquisition requires Linux amd64")
	}
	dir, body, intent, addresses, native, baseline := globalReferenceEffectsFixture(t)
	globalReferenceEffectsPositive(t, baseline, native, addresses, intent)
	// MOV does not change the condition-code result, and loading/storing the
	// current target leaves its final bytes unchanged in both CAS outcomes. The
	// ordinary write remains an additional effect even on failed-CAS writeback.
	edited := strings.Replace(body, "\tRET", "\tMOVQ (BX), DX\n\tMOVQ DX, (BX)\n\tRET", 1)
	if edited == body {
		t.Fatal("same-value write edit missed the actual return")
	}
	if err := os.WriteFile(filepath.Join(dir, "ops", "ops_amd64.s"), []byte(edited), 0600); err != nil {
		t.Fatal(err)
	}
	changed := loadGlobalReferenceEffectsSelection(t, dir)
	if !changed.reference.checked.relation.returnProof.Valid() || !changed.reference.checked.relation.booleanProof.Valid() {
		t.Fatal("valid edited source did not establish its full reference frame/result")
	}
	first, middle, second, final := intent.outcomes()
	for index, args := range [][3]uint64{{intent.current, intent.old, intent.replacement}, {middle, intent.secondOld, intent.secondReplacement}} {
		ordinary, err := baseline.reference.evaluate(t.Context(), args[0], args[1], args[2])
		if err != nil {
			t.Fatal(err)
		}
		withWrite, err := changed.reference.evaluate(t.Context(), args[0], args[1], args[2])
		if err != nil {
			t.Fatal("valid edited reference failed application:", err)
		}
		wantResult, wantValue := []bool{first, second}[index], []uint64{middle, final}[index]
		wantAccesses := []assemblyReferenceAccess{{false, true, args[0], 8}, {true, true, wantValue, 8}, {false, false, wantValue, 8}, {true, false, wantValue, 8}}
		if withWrite.Value != ordinary.Value || assemblyReferenceBool(t, withWrite.Result) != assemblyReferenceBool(t, ordinary.Result) || withWrite.Value != wantValue || assemblyReferenceBool(t, withWrite.Result) != wantResult || !slices.Equal(withWrite.Accesses, wantAccesses) {
			t.Fatalf("phase %d did not preserve scalar results and retain the additional ordinary write: normal=%+v edited=%+v", index, ordinary, withWrite)
		}
	}
	prior := pairedOperandProof(t, changed.source, changed.root, changed.calls, changed.globals, addresses, native)
	steps := pairedSteps(t, native, changed.calls)
	refs := map[*ssa.Function]*assemblyReference{changed.target: changed.reference}
	currentSource, currentNative := prior.source, prior.native
	comparison := &globalRegionCorrespondence{root: prior}
	traces := append([]*regionEffectTrace(nil), prior.account.traces...)
	accesses := append([]regionEffectAccess(nil), prior.account.accesses...)
	for index, step := range steps {
		source, err := checkSourceOperandContinuation(t.Context(), currentSource, step.call, refs)
		if err != nil {
			t.Fatal("same-value reference did not pass its source Boolean/global guards:", err)
		}
		trace := source.region.packet.trace
		if trace == nil || len(trace.calls) != 1 {
			t.Fatal("source continuation lost the exact checked reference application")
		}
		application := trace.calls[0]
		location := regionLocation{object: regionObject{kind: regionGlobal, site: changed.globals[0]}}
		current, currentOK := regionUint64(readRegionLocation(application.proof.initial, location, types.Typ[types.Uint64]))
		updated, updatedOK := regionUint64(readRegionLocation(application.outcome.state, location, types.Typ[types.Uint64]))
		if application.proof.at != changed.calls[index] || !currentOK || !updatedOK || current != []uint64{intent.current, middle}[index] || updated != []uint64{middle, final}[index] || assemblyReferenceBool(t, application.outcome.value) != []bool{first, second}[index] {
			t.Fatal("source application scalars differ before effect comparison")
		}
		var fromCall []assemblyReferenceAccess
		for _, access := range trace.accesses {
			if access.instruction == changed.calls[index] {
				if access.location.object != location.object || len(access.location.path) != 0 {
					t.Fatal("reference effect was mapped to another singleton")
				}
				value, exact := regionUint64(access.value)
				if !exact {
					t.Fatal("reference effect lost its exact typed value")
				}
				fromCall = append(fromCall, assemblyReferenceAccess{access.write, access.locked, value, 8})
			}
		}
		value := []uint64{middle, final}[index]
		if !slices.Equal(fromCall, []assemblyReferenceAccess{{false, true, current, 8}, {true, true, value, 8}, {false, false, value, 8}, {true, false, value, 8}}) {
			t.Fatalf("ordinary reference accesses were dropped during exact-call substitution: %+v", fromCall)
		}
		before, ok := currentNative.BoundFor(native.image)
		if !ok {
			t.Fatal("native predecessor lost its original image")
		}
		use, err := nativeproof.CheckTransitionContinuation(t.Context(), currentNative, step.use)
		if err != nil {
			t.Fatal("unchanged native Boolean prefix is invalid:", err)
		}
		consuming, ok := use.BoundFor(native.image)
		if !ok {
			t.Fatal("native Boolean prefix lost image ownership")
		}
		if err := comparison.checkBooleanUse(t.Context(), currentSource, currentNative, before, use, consuming, application); err != nil {
			t.Fatal("edited reference and unchanged native Boolean/current/result relations must match:", err)
		}
		afterNative, err := nativeproof.CheckTransitionContinuation(t.Context(), use, step.next)
		if err != nil {
			t.Fatal("unchanged native phase is invalid:", err)
		}
		after, ok := afterNative.BoundFor(native.image)
		if !ok {
			t.Fatal("native continuation lost image ownership")
		}
		layout, err := checkStorageAuthority(t.Context(), source, after, prior.representation, storageProtectedFootprints(t.Context(), after))
		if err != nil {
			t.Fatal(err)
		}
		traces = append(traces, trace)
		accesses = append(accesses, trace.accesses...)
		account := &globalFunctionCorrespondence{representation: prior.representation, layout: layout, antecedent: after.EntryPredicate, traces: traces, accesses: accesses}
		if err := account.checkStorageValues(t.Context(), br.NewBuilder(4096), source.region.packet.observations[0].state, after.Memory, true); err != nil {
			t.Fatal("same-value edit changed the full represented heap or preserved native bytes:", err)
		}
		if err := account.checkStorageFrame(t.Context(), after); err != nil {
			t.Fatal("same-value edit changed preserved native bytes:", err)
		}
		if err := account.checkEffects(t.Context(), after); err == nil || !strings.Contains(err.Error(), "native effect has missing or surplus byte coverage") {
			t.Fatalf("phase %d did not refuse specifically at its ordered-effect relation: %v", index, err)
		}
		currentSource, currentNative = source, afterNative
	}
	// Verify the final scalar source state independently of the rejection. Both
	// phases and both outcomes are valid; the extra write is the deciding gap.
	state := currentSource.region.packet.observations[0].state
	for index, want := range []uint64{final, intent.secondOld} {
		got, known := regionUint64(readRegionLocation(state, regionLocation{object: regionObject{kind: regionGlobal, site: changed.globals[index]}}, types.Typ[types.Uint64]))
		if !known || got != want {
			t.Fatalf("final source global %d=%d known=%t want=%d", index, got, known, want)
		}
	}
	proof, err := continueGlobalOperandCorrespondence(t.Context(), prior, steps, refs)
	if proof != nil || err == nil || !strings.Contains(err.Error(), "native effect has missing or surplus byte coverage") {
		t.Fatalf("unchanged native paired correspondence did not reject the extra same-value reference write: %v", err)
	}
	t.Log("real edited assembly and both source phases succeeded; Boolean, current value, final heap and native frame matched; ordered ordinary reference writes rejected unchanged inline correspondence")
}
