package closure

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
)

// This bounded grammar varies real instruction operands and effects: eight
// pointer registers, four replacement registers, both result predicates, swapped
// argument slots, a register-staged result, and an optional signed immediate
// post-write. The integer oracle below does not interpret instruction terms.
type assemblyReferencePropertyProgram struct {
	body, pointer            string
	inverted, swapped, extra bool
	constant                 uint64
}

func assemblyReferencePropertyBody(shape uint16, literal uint64) assemblyReferencePropertyProgram {
	p := assemblyReferencePropertyProgram{
		pointer:  []string{"BX", "DX", "SI", "DI", "R8", "R10", "R12", "R14"}[shape&7],
		inverted: shape&32 != 0,
		swapped:  shape&64 != 0,
		extra:    shape&256 != 0,
		constant: uint64(int64(int32(literal))),
	}
	replacement := []string{"CX", "R9", "R11", "R13"}[(shape>>3)&3]
	comparisonOffset, replacementOffset := 8, 16
	if p.swapped {
		comparisonOffset, replacementOffset = replacementOffset, comparisonOffset
	}
	set := "SETEQ"
	if p.inverted {
		set = "SETNE"
	}
	result := set + " result+24(FP)\n"
	if shape&128 != 0 {
		result = set + " R15\nMOVB R15, result+24(FP)\n"
	}
	p.body = fmt.Sprintf("TEXT ·Swap(SB),4,$0-25\nMOVQ arbitrary+0(FP), %s\nMOVQ comparison+%d(FP), AX\nMOVQ replacement+%d(FP), %s\nLOCK\nCMPXCHGQ %s, 0(%s)\n%s", p.pointer, comparisonOffset, replacementOffset, replacement, replacement, p.pointer, result)
	if p.extra {
		p.body += fmt.Sprintf("MOVQ $%d, 0(%s)\n", int64(p.constant), p.pointer)
	}
	p.body += "RET\n"
	return p
}

func (p assemblyReferencePropertyProgram) oracle(current, old, replacement uint64) assemblyReferenceResult {
	comparison, next := old, replacement
	if p.swapped {
		comparison, next = replacement, old
	}
	success := current == comparison
	value := current
	if success {
		value = next
	}
	accesses := []assemblyReferenceAccess{{false, true, current}, {true, true, value}}
	if p.extra {
		value = p.constant
		accesses = append(accesses, assemblyReferenceAccess{true, false, value})
	}
	return assemblyReferenceResult{Value: value, Result: success != p.inverted, Accesses: accesses}
}

func assemblyReferencePropertyResult(t testing.TB, got, want assemblyReferenceResult) {
	t.Helper()
	if got.Value != want.Value || got.Result != want.Result || !slices.Equal(got.Accesses, want.Accesses) {
		t.Fatalf("relation = %+v; integer oracle = %+v", got, want)
	}
}

// FuzzAssemblyReferenceBodyAndPrivateFrame tests the body-and-interface and
// reference-frame clauses of REQ-impl-assembly-reference. Samples cover only the
// grammar above and sixteen controlled violations; they are not a whole-ISA or
// universal equivalence proof and confer no selected-source binding authority.
func FuzzAssemblyReferenceBodyAndPrivateFrame(f *testing.F) {
	for i := range 16 {
		f.Add(uint64(i)*0x100000001, ^uint64(i), uint64(i)<<60|uint64(i)*0x10203041, uint16(i*37), uint8(i))
	}
	f.Fuzz(func(t *testing.T, current, old, replacement uint64, shape uint16, fault uint8) {
		p := assemblyReferencePropertyBody(shape, replacement)
		r := assemblyReferenceUnitRelation(t, p.body)
		// Always exercise success and failure as well as the independent fuzz
		// triple, including when replacement happens to equal the current value.
		comparison := old
		if p.swapped {
			comparison = replacement
		}
		for _, value := range []uint64{current, comparison, comparison ^ 1} {
			assemblyReferencePropertyResult(t, assemblyReferenceUnitApply(t, r, value, old, replacement), p.oracle(value, old, replacement))
		}

		if r.frame.arguments != ([3]assemblyReferenceSlot{{8, 8}, {16, 8}, {24, 8}}) || r.frame.result != (assemblyReferenceSlot{32, 1}) || r.frame.size != 33 {
			t.Fatal("typed ABI0 layout changed")
		}
		// Retain every administrative access in order, but project only the
		// represented target's accesses (checked above, including failed RMW).
		wantAccesses := []assemblyReferenceSymbolicAccess{
			{space: r.frame.frameSpace, offset: 8, width: 8},
			{space: r.frame.frameSpace, offset: 16, width: 8},
			{space: r.frame.frameSpace, offset: 24, width: 8},
			{space: r.frame.targetSpace, width: 8, locked: true},
			{space: r.frame.targetSpace, width: 8, write: true, locked: true},
			{space: r.frame.frameSpace, offset: 32, width: 1, write: true},
		}
		if p.swapped {
			wantAccesses[1].offset, wantAccesses[2].offset = 24, 16
		}
		if p.extra {
			wantAccesses = append(wantAccesses, assemblyReferenceSymbolicAccess{space: r.frame.targetSpace, width: 8, write: true})
		}
		wantAccesses = append(wantAccesses, assemblyReferenceSymbolicAccess{space: r.frame.frameSpace, width: 8, returning: true})
		if len(r.accesses) != len(wantAccesses) {
			t.Fatalf("complete access count = %d, want %d", len(r.accesses), len(wantAccesses))
		}
		for i, want := range wantAccesses {
			got := r.accesses[i]
			if got.space != want.space || got.offset != want.offset || got.width != want.width || got.write != want.write || got.locked != want.locked || got.returning != want.returning || !got.value.Valid() || i > 0 && got.statement < r.accesses[i-1].statement {
				t.Fatalf("complete access %d = %+v, want %+v", i, got, want)
			}
		}
		if r.accesses[3].statement != r.accesses[4].statement {
			t.Fatal("locked read/write did not retain one RMW instruction")
		}
		if !r.booleanProof.Valid() || !r.returnProof.Valid() {
			t.Fatal("missing complete result or protected-return derivation")
		}
		boolean, _ := r.booleanProof.Roots()
		if boolean != r.private[32].value {
			t.Fatal("Boolean proof does not cover the complete declared result byte")
		}
		returned, original := r.returnProof.Roots()
		if returned != r.returnWord || original.View().Op != br.Variable || !original.View().Scratch {
			t.Fatal("return was not proved against arbitrary incoming control context")
		}
		for i := range 8 {
			v := r.private[i].value.View()
			if v.Op != br.Extract || v.Immediate != uint64(i*8) || len(v.Args) != 1 || v.Args[0] != original {
				t.Fatalf("return-word byte %d was not preserved", i)
			}
		}
		// Evaluate the administrative continuation with a generated aligned,
		// canonical origin; its expected increment is ordinary integer code.
		sp := current & ((1 << 46) - 8)
		resumed, err := br.Eval(t.Context(), r.returnedSP, []br.Assignment{{Variable: r.registers[nativeproof.RSP].value, Value: sp}}, br.Limits{})
		if err != nil || resumed != sp+8 {
			t.Fatalf("return continuation = %#x, want %#x: %v", resumed, sp+8, err)
		}

		frame := assemblyReferenceUnitFrame(t)
		badBody := p.body
		switch fault % 16 {
		case 0:
			frame.targetSpace = frame.frameSpace
		case 1:
			frame.permissions[3].write = false
		case 2:
			frame.permissions[3].read = false
		case 3:
			frame.permissions[0].read = false
		case 4:
			frame.permissions[2].write = false
		case 5:
			frame.result.width = 2
		case 6:
			frame.arguments[shape%3].offset++
		case 7:
			frame.size--
		case 8:
			frame.permissions = append(frame.permissions, frame.permissions[shape%4])
		case 9:
			badBody = strings.Replace(badBody, "RET\n", fmt.Sprintf("MOVQ $%d, 0(SP)\nRET\n", int64(p.constant)), 1)
		case 10:
			badBody = strings.Replace(badBody, "result+24(FP)", "result+25(FP)", 1)
		case 11:
			badBody = strings.Replace(badBody, "result+24(FP)", "result+16(FP)", 1)
		case 12:
			badBody = strings.Replace(badBody, "RET\n", "", 1)
		case 13:
			badBody = strings.Replace(badBody, "RET\n", fmt.Sprintf("MOVQ %s, 0(%s)\nRET\n", p.pointer, p.pointer), 1)
		case 14:
			badBody = strings.Replace(badBody, "RET\n", fmt.Sprintf("MOVQ $%d, BP\nRET\n", int64(p.constant)), 1)
		case 15:
			offset := 8
			if p.swapped {
				offset = 16
			}
			badBody = strings.Replace(badBody, fmt.Sprintf("MOVQ comparison+%d(FP), AX\n", offset), "", 1)
		}
		definitions, err := assemblyReferenceUnitParse(t, badBody)
		if err != nil || len(definitions) != 1 {
			t.Fatalf("fault %d must reach frame/body interpretation: %v", fault%16, err)
		}
		bad, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], frame)
		if err == nil || bad != nil {
			t.Fatalf("fault %d acquired a relation", fault%16)
		}
	})
}

// FuzzAssemblyReferenceSelectedOwnershipAndBinding tests owned-selection and
// operational-binding with actual source selection and final assembler capture.
// Its bounded grammar varies package/declaration identities, qualified spelling,
// body operands, access directives and a transitive choice between opposite
// header definitions. Negative modes are file-local-only, competing DUPOK
// providers and a redirect. Eight seeds sample this grammar; unsupported build
// configurations and the rest of the assembly language are outside its claim.
func FuzzAssemblyReferenceSelectedOwnershipAndBinding(f *testing.F) {
	if testing.Short() {
		f.Skip("loads generated typed source and captures actual final assembler actions")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		f.Skip("selected assembly acquisition uses Linux amd64")
	}
	for i, seed := range []uint64{0, 0x1934, 0x2248, 0x3b7c, 0x4481, 0x5db5, 0x66ca, 0x7fff} {
		f.Add(seed, uint64(i)<<61, ^uint64(i), uint64(i)*0x100000001)
	}
	f.Fuzz(func(t *testing.T, seed, current, old, replacement uint64) {
		mode := seed & 3
		name := fmt.Sprintf("Operation%d", (seed>>4)&255)
		pkg := fmt.Sprintf("example.com/ref%d", (seed>>12)&15)
		p := assemblyReferencePropertyBody(uint16(seed>>2), replacement)
		// RESULT is selected only through a transitive captured header. The
		// other header exists with the opposite meaning, so ignoring selection
		// or include bytes cannot satisfy both predicates in the corpus.
		set, otherSet := "SETEQ", "SETNE"
		if p.inverted {
			set, otherSet = otherSet, set
		}
		header := int((seed >> 11) & 1)
		symbol := "·" + name
		if seed&16 != 0 {
			symbol = strings.ReplaceAll(strings.ReplaceAll(pkg, ".", "·"), "/", "∕") + "·" + name
		}
		body := strings.Replace(p.body, "·Swap", symbol, 1)
		body = strings.Replace(body, set, "RESULT", 1)
		goSource := fmt.Sprintf("package p\n//go:noescape\nfunc %s(ptr *uint64, old, replacement uint64) bool\n", name)
		directive := []string{"", "//go:linkname " + name + "\n", "//go:linknamestd " + name + "\n"}[(seed>>9)%3]
		files := map[string]string{
			"go.mod":       "module " + pkg + "\n\ngo 1.27\n",
			"p.go":         goSource,
			"linkname.go":  "package p\nimport _ \"unsafe\"\n" + directive,
			"body_amd64.s": "#include \"operation.h\"\n" + body,
			"operation.h":  fmt.Sprintf("#include \"choice%d.h\"\n", header),
		}
		files[fmt.Sprintf("choice%d.h", header)] = "#define RESULT " + set + "\n"
		files[fmt.Sprintf("choice%d.h", 1-header)] = "#define RESULT " + otherSet + "\n"
		switch mode {
		case 1:
			files["p.go"] += fmt.Sprintf("func Local%d(ptr *uint64, old, replacement uint64) bool\n", seed&255)
			files["body_amd64.s"] += strings.Replace(p.body, "·Swap(SB)", fmt.Sprintf("·Local%d<>(SB)", seed&255), 1)
		case 2:
			files["body_amd64.s"] = strings.Replace(files["body_amd64.s"], ",4,", ",6,", 1)
			files["second_amd64.s"] = files["body_amd64.s"]
		case 3:
			files["linkname.go"] = "package p\nimport _ \"unsafe\"\n//go:linkname " + name + " remote." + name + "\n"
		}
		dir := t.TempDir()
		writeTree(t, dir, files)
		// The helper begins the selection before loading typed source. No
		// authorizing packet is assembled from the generated text by this test.
		source := assemblyReferenceSelectedSource(t, dir)
		target := source.prog.Roots[name]
		packet := assemblyReferenceSelectedPacket(t, source, target)
		r, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
		if mode >= 2 {
			want := "unsupported or weak TEXT flags"
			if mode == 3 {
				want = "unsupported, malformed or redirecting declaration directive"
			} else if len(packet.providerTexts()) != 2 {
				t.Fatal("capture omitted a competing provider")
			}
			if err == nil || r != nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("mode %d must refuse at binding after successful acquisition: %v", mode, err)
			}
			return
		}
		if err != nil {
			t.Fatal("unambiguous selected provider refused:", err)
		}
		if err := r.boundTo(source, target); err != nil {
			t.Fatal(err)
		}
		comparison := old
		if p.swapped {
			comparison = replacement
		}
		check := func(reference *assemblyReference) {
			t.Helper()
			for _, value := range []uint64{current, comparison, comparison ^ 1} {
				got, err := reference.evaluate(t.Context(), value, old, replacement)
				if err != nil {
					t.Fatal(err)
				}
				assemblyReferencePropertyResult(t, got, p.oracle(value, old, replacement))
			}
		}
		check(r)
		if mode == 1 {
			local := source.prog.Roots[fmt.Sprintf("Local%d", seed&255)]
			bad, err := checkAssemblyReference(t.Context(), source, local, packet, assemblyReferenceLimits{})
			if err == nil || bad != nil || !strings.Contains(err.Error(), "no unique external selected TEXT provider") {
				t.Fatalf("file-local definition supplied an external declaration: %v", err)
			}
		}
		copyTarget := *target
		if err := r.boundTo(source, &copyTarget); err == nil {
			t.Fatal("copied declaration borrowed checked reference")
		}
		if bad, err := checkAssemblyReference(t.Context(), source, &copyTarget, packet, assemblyReferenceLimits{}); err == nil || bad != nil {
			t.Fatal("copied declaration borrowed selected acquisition")
		}
		foreign := assemblyReferenceSelectedSource(t, dir)
		if err := r.boundTo(foreign, foreign.prog.Roots[name]); err == nil {
			t.Fatal("equal-content independent owner borrowed reference")
		}
		if bad, err := checkAssemblyReference(t.Context(), foreign, foreign.prog.Roots[name], packet, assemblyReferenceLimits{}); err == nil || bad != nil || !strings.Contains(err.Error(), "acquisition belongs to another selected package owner") {
			t.Fatalf("foreign owner did not refuse at acquisition binding: %v", err)
		}
		// Provider projections are caller-owned copies, including token and
		// invocation slices. Mutating them must not change packet authority or
		// the relation subsequently derived from that same packet.
		for _, projection := range packet.providerTexts() {
			for i := range projection.Lines {
				projection.Lines[i].Text = otherSet
				for j := range projection.Lines[i].Tokens {
					projection.Lines[i].Tokens[j] = otherSet
				}
			}
			for i := range projection.Invocation.ExpandedArgs {
				projection.Invocation.ExpandedArgs[i] = "-race"
			}
		}
		after, err := checkAssemblyReference(t.Context(), source, target, packet, assemblyReferenceLimits{})
		if err != nil {
			t.Fatal("projection mutation changed owned packet:", err)
		}
		if err := after.boundTo(source, target); err != nil {
			t.Fatal(err)
		}
		check(r)
		check(after)
	})
}
