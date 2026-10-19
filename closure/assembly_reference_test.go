package closure

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"go/types"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"text/scanner"
	"unicode"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/internal/assemblycapture"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

const assemblyReferenceUnitBody = `TEXT ·Swap(SB),4,$0-25
	MOVQ ptr+0(FP), BX
	MOVQ old+8(FP), AX
	MOVQ replacement+16(FP), CX
	LOCK
	CMPXCHGQ CX, 0(BX)
	SETEQ ret+24(FP)
	RET
`

// These fixtures exercise the independent parser and interpreter only. They
// never construct a selectedAssemblyPacket or an authorizing assemblyReference.
// Selected acquisition and owner binding have separate integration tests.
func assemblyReferenceUnitProvider(t testing.TB, text, file string) assemblycapture.Provider {
	t.Helper()
	var s scanner.Scanner
	s.Init(strings.NewReader(text))
	s.Whitespace = 1<<' ' | 1<<'\t' | 1<<'\r'
	s.Mode = scanner.ScanIdents | scanner.ScanInts | scanner.ScanStrings | scanner.ScanComments | scanner.SkipComments
	s.IsIdentRune = func(r rune, i int) bool {
		return unicode.IsLetter(r) || r == '_' || r == '·' || r == '∕' || i > 0 && unicode.IsDigit(r)
	}
	s.Error = func(_ *scanner.Scanner, message string) { t.Fatal(message) }
	var lines []assemblycapture.Line
	line := assemblycapture.Line{File: file, Line: 1}
	for {
		kind := s.Scan()
		if kind == '\n' || kind == scanner.EOF {
			line.Text = strings.Join(line.Tokens, " ")
			if len(line.Tokens) > 0 {
				lines = append(lines, line)
			}
			line = assemblycapture.Line{File: file, Line: s.Position.Line + 1}
			if kind == scanner.EOF {
				break
			}
			continue
		}
		line.Tokens = append(line.Tokens, s.TokenText())
	}
	args := []string{"-p", "example.com/ref", "-I", "/owned/include", "-D", "GOARCH_amd64", "-o", "/owned/body.o", file}
	return assemblycapture.Provider{Source: file, Lines: lines, Invocation: assemblycapture.Invocation{Tool: "/owned/tool/asm", CWD: "/owned", Package: "example.com/ref", Args: slices.Clone(args), ExpandedArgs: args, IncludeDirs: []string{"/owned/include"}, Defines: []string{"GOARCH_amd64"}}}
}

func assemblyReferenceUnitFrame(t testing.TB) assemblyReferenceFrame {
	t.Helper()
	sig := types.NewSignatureType(nil, nil, nil, types.NewTuple(types.NewVar(0, nil, "ptr", types.NewPointer(types.Typ[types.Uint64])), types.NewVar(0, nil, "old", types.Typ[types.Uint64]), types.NewVar(0, nil, "replacement", types.Typ[types.Uint64])), types.NewTuple(types.NewVar(0, nil, "", types.Typ[types.Bool])), false)
	f, err := assemblyReferenceABI(sig, types.SizesFor("gc", "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func assemblyReferenceUnitParse(t testing.TB, text string) ([]assemblyReferenceDefinition, error) {
	t.Helper()
	m := &assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}
	return assemblyReferenceDefinitions(m, []assemblycapture.Provider{assemblyReferenceUnitProvider(t, text, "/owned/body.s")}, "example.com/ref")
}

func assemblyReferenceUnitRelation(t testing.TB, text string) *assemblyReferenceRelation {
	t.Helper()
	definitions, err := assemblyReferenceUnitParse(t, text)
	if err != nil {
		t.Fatal(err)
	}
	if len(definitions) != 1 {
		t.Fatal("unit fixture needs exactly one definition")
	}
	r, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], assemblyReferenceUnitFrame(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func assemblyReferenceUnitApply(t testing.TB, r *assemblyReferenceRelation, current uint64, arguments ...uint64) assemblyReferenceResult {
	t.Helper()
	result, err := assemblyReferenceApply(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, r, append([]uint64{current}, arguments...))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assemblyReferenceBool(t testing.TB, value regionValue) bool {
	t.Helper()
	if !types.Identical(value.typ, types.Typ[types.Bool]) || value.kind != regionConstant || value.scalar == nil || value.scalar.Kind() != constant.Bool {
		t.Fatalf("reference did not return a typed Boolean: %+v", value)
	}
	return constant.BoolVal(value.scalar)
}

func TestAssemblyReferenceUniversalOperandsAndBothWriteCycles(t *testing.T) {
	r := assemblyReferenceUnitRelation(t, assemblyReferenceUnitBody)
	if !r.booleanProof.Valid() || !r.returnProof.Valid() {
		t.Fatal("missing Boolean/return derivations")
	}
	if len(r.accesses) != 7 {
		t.Fatalf("full accesses=%d, want three arguments, RMW pair, result and return", len(r.accesses))
	}
	if !slices.Equal(r.frame.arguments, []assemblyReferenceSlot{{8, 8}, {16, 8}, {24, 8}}) || r.frame.result != (assemblyReferenceSlot{32, 1}) {
		t.Fatal("wrong typed ABI0 slot derivation")
	}
	// This oracle is ordinary integer code independent of the instruction-term
	// builder and scalar equality checker. Generated values do not prove the
	// theorem; they check the universal implementation's two independent arms.
	rng := rand.New(rand.NewPCG(0x173b, 0x729e))
	cases := [][3]uint64{{0, 0, 0}, {0, 1, 9}, {^uint64(0), ^uint64(0), 0}, {1 << 63, 0, 1 << 63}, {3, 7, 7}}
	for range 128 {
		current, old, replacement := rng.Uint64(), rng.Uint64(), rng.Uint64()
		cases = append(cases, [3]uint64{current, old, replacement}, [3]uint64{current, current, replacement})
	}
	for _, values := range cases {
		current, old, replacement := values[0], values[1], values[2]
		want := current
		if current == old {
			want = replacement
		}
		got := assemblyReferenceUnitApply(t, r, current, old, replacement)
		if got.Value != want || assemblyReferenceBool(t, got.Result) != (current == old) {
			t.Fatalf("%x: got %+v, want value %#x and result %v", values, got, want, current == old)
		}
		if !slices.Equal(got.Accesses, []assemblyReferenceAccess{{false, true, current}, {true, true, want}}) {
			t.Fatalf("%x: lost ordered locked read/write cycle: %+v", values, got.Accesses)
		}
	}
}

func TestAssemblyReferenceSourceEditsDeriveDifferentRelations(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		value      uint64
		result     bool
		accesses   int
	}{
		{"set-not-equal", strings.Replace(assemblyReferenceUnitBody, "SETEQ", "SETNE", 1), 9, false, 2},
		{"comparison-slot", strings.Replace(assemblyReferenceUnitBody, "old+8(FP)", "old+16(FP)", 1), 5, false, 2},
		{"replacement-slot", strings.Replace(assemblyReferenceUnitBody, "replacement+16(FP)", "replacement+8(FP)", 1), 5, true, 2},
		{"extra-write", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVQ $73, (BX)\n\tRET", 1), 73, true, 3},
		{"flag-overwrite", strings.Replace(assemblyReferenceUnitBody, "\tSETEQ", "\tCMPQ CX, $8\n\tSETEQ", 1), 9, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := assemblyReferenceUnitRelation(t, tc.body)
			got := assemblyReferenceUnitApply(t, r, 5, 5, 9)
			if got.Value != tc.value || assemblyReferenceBool(t, got.Result) != tc.result || len(got.Accesses) != tc.accesses {
				t.Fatalf("edited source not reflected: %+v", got)
			}
		})
	}
	// Result flag inversion does not invert the memory-write condition.
	r := assemblyReferenceUnitRelation(t, strings.Replace(assemblyReferenceUnitBody, "SETEQ", "SETNE", 1))
	got := assemblyReferenceUnitApply(t, r, 5, 7, 9)
	if !assemblyReferenceBool(t, got.Result) || got.Value != 5 || got.Accesses[1].Value != 5 {
		t.Fatal("SETNE changed failure writeback")
	}
}

func TestAssemblyReferenceBodyAndFrameRefusals(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"result-in-argument", strings.Replace(assemblyReferenceUnitBody, "ret+24(FP)", "ret+16(FP)", 1)},
		{"result-outside-frame", strings.Replace(assemblyReferenceUnitBody, "ret+24(FP)", "ret+25(FP)", 1)},
		{"return-word-write", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVQ $0, 0(SP)\n\tRET", 1)},
		{"redirected-return", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tRET ·Other(SB)", 1)},
		{"missing-return", strings.Replace(assemblyReferenceUnitBody, "\tRET", "", 1)},
		{"tail-operations", assemblyReferenceUnitBody + "MOVQ $0, (BX)\n"},
		{"scratch-comparison", strings.Replace(assemblyReferenceUnitBody, "\tMOVQ old+8(FP), AX\n", "", 1)},
		{"no-boolean-store", strings.Replace(assemblyReferenceUnitBody, "\tSETEQ ret+24(FP)\n", "", 1)},
		{"noncanonical-boolean", strings.Replace(assemblyReferenceUnitBody, "SETEQ ret+24(FP)", "MOVB $2, ret+24(FP)", 1)},
		{"partial-pointer-load", strings.Replace(assemblyReferenceUnitBody, "MOVQ ptr+0(FP)", "MOVL ptr+0(FP)", 1)},
		{"pointer-escape", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVQ BX, (BX)\n\tRET", 1)},
		{"stack-write", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVQ AX, SP\n\tRET", 1)},
		{"frame-context-write", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVQ $0, BP\n\tRET", 1)},
		{"partial-frame-context-write", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVL AX, BP\n\tRET", 1)},
		{"byte-frame-context-write", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tSETNE BP\n\tRET", 1)},
		{"non-leaf", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tCALL ·Other(SB)\n\tRET", 1)},
		{"prologue", strings.Replace(assemblyReferenceUnitBody, ",4,$0-25", ",0,$0-25", 1)},
		{"local-frame", strings.Replace(assemblyReferenceUnitBody, "$0-25", "$8-25", 1)},
		{"argument-size", strings.Replace(assemblyReferenceUnitBody, "$0-25", "$0-24", 1)},
		{"wrong-abi", strings.Replace(assemblyReferenceUnitBody, "·Swap(SB)", "·Swap<ABIInternal>(SB)", 1)},
		{"unlocked", strings.Replace(assemblyReferenceUnitBody, "\tLOCK\n", "", 1)},
		{"split-prefix", strings.Replace(assemblyReferenceUnitBody, "\tCMPXCHGQ", "\tMOVQ AX, AX\n\tCMPXCHGQ", 1)},
		{"duplicate-prefix", strings.Replace(assemblyReferenceUnitBody, "\tLOCK", "\tLOCK\n\tLOCK", 1)},
		{"out-of-bounds-target", strings.Replace(assemblyReferenceUnitBody, "0(BX)", "8(BX)", 1)},
		{"partial-target", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVB $0, (BX)\n\tRET", 1)},
		{"memory-immediate-sign-extension", strings.Replace(assemblyReferenceUnitBody, "\tRET", "\tMOVQ $4294967295, (BX)\n\tRET", 1)},
		{"compare-immediate-sign-extension", strings.Replace(assemblyReferenceUnitBody, "\tSETEQ", "\tCMPQ AX, $4294967295\n\tSETEQ", 1)},
		{"test-immediate-sign-extension", strings.Replace(assemblyReferenceUnitBody, "\tSETEQ", "\tTESTQ $4294967295, AX\n\tSETEQ", 1)},
		{"byte-immediate-overflow", strings.Replace(assemblyReferenceUnitBody, "SETEQ ret+24(FP)", "MOVB $256, ret+24(FP)", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			definitions, err := assemblyReferenceUnitParse(t, tc.body)
			if err != nil {
				t.Fatal("test must reach body interpreter:", err)
			}
			r, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], assemblyReferenceUnitFrame(t))
			if err == nil || r != nil {
				t.Fatal("invalid body/frame acquired relation")
			}
		})
	}
	definitions, err := assemblyReferenceUnitParse(t, assemblyReferenceUnitBody)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*assemblyReferenceFrame)
	}{
		{"frame-alias", func(f *assemblyReferenceFrame) { f.targetSpace = f.frameSpace }},
		{"no-read", func(f *assemblyReferenceFrame) { f.permissions[3].read = false }},
		{"no-write-failure", func(f *assemblyReferenceFrame) { f.permissions[3].write = false }},
		{"no-return-read", func(f *assemblyReferenceFrame) { f.permissions[0].read = false }},
		{"no-result-write", func(f *assemblyReferenceFrame) { f.permissions[2].write = false }},
		{"permission-alias", func(f *assemblyReferenceFrame) {
			f.permissions = append(f.permissions, assemblyReferencePermission{f.targetSpace, 0, 8, false, false})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := assemblyReferenceUnitFrame(t)
			tc.change(&f)
			r, err := assemblyReferenceInterpret(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, definitions[0], f)
			if err == nil || r != nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
}

func TestAssemblyReferenceGenericBodyAndRegisterAliases(t *testing.T) {
	// A valid relation need not implement compare/exchange at all. The selected
	// instructions, not the signature or symbol, determine its result/effects.
	r := assemblyReferenceUnitRelation(t, "TEXT ·Different(SB),4,$0-25\nMOVB $1, ret+24(FP)\nRET\n")
	got := assemblyReferenceUnitApply(t, r, 17, 23, 31)
	if got.Value != 17 || !assemblyReferenceBool(t, got.Result) || len(got.Accesses) != 0 {
		t.Fatal("ordinary constant body acquired a canned operation summary", got)
	}
	for _, tc := range []struct {
		body   string
		result bool
	}{
		{strings.Replace(assemblyReferenceUnitBody, "SETEQ ret+24(FP)", "SETEQ R8\nMOVB R8, ret+24(FP)", 1), true},
		{strings.Replace(assemblyReferenceUnitBody, "SETEQ ret+24(FP)", "SETEQ AH\nMOVB AH, ret+24(FP)", 1), true},
		{strings.Replace(assemblyReferenceUnitBody, "SETEQ ret+24(FP)", "MOVQ $-1, R8\nSETEQ R8\nTESTB R8, R8\nSETNE ret+24(FP)", 1), true},
		{strings.Replace(assemblyReferenceUnitBody, "SETEQ ret+24(FP)", "MOVQ $-1, R8\nSETEQ R8\nTESTQ R8, R8\nSETEQ ret+24(FP)", 1), false},
	} {
		r := assemblyReferenceUnitRelation(t, tc.body)
		got := assemblyReferenceUnitApply(t, r, 5, 5, 9)
		if got.Value != 9 || assemblyReferenceBool(t, got.Result) != tc.result {
			t.Fatalf("partial register/flag semantics: %+v", got)
		}
	}
	// A literal full-register MOVQ has a true 64-bit immediate form; unlike a
	// memory MOVQ or CMPQ immediate, it must not be truncated/sign-extended.
	r = assemblyReferenceUnitRelation(t, strings.Replace(assemblyReferenceUnitBody, "MOVQ old+8(FP), AX", "MOVQ $4294967295, AX", 1))
	got = assemblyReferenceUnitApply(t, r, 4294967295, 7, 9)
	if !assemblyReferenceBool(t, got.Result) || got.Value != 9 {
		t.Fatal("64-bit register immediate was sign-extended", got)
	}
}

func TestAssemblyReferenceCompleteDefinitionInventory(t *testing.T) {
	other := "TEXT ·Other(SB),4,$0-0\nRET\n"
	for _, tc := range []struct{ name, body string }{
		{"duplicate", assemblyReferenceUnitBody + assemblyReferenceUnitBody},
		{"unknown-before", "UNKNOWN\n" + assemblyReferenceUnitBody},
		{"unknown-after", assemblyReferenceUnitBody + other + "ALIAS ·Swap, ·Other\n"},
		{"weak-provider", assemblyReferenceUnitBody + strings.Replace(other, ",4,", ",2,", 1)},
		{"bad-sibling-frame", assemblyReferenceUnitBody + strings.Replace(other, "$0-0", "$unknown", 1)},
		{"data-provider", assemblyReferenceUnitBody + "DATA ·Swap(SB)/8, $0\n"},
		{"global-provider", assemblyReferenceUnitBody + "GLOBL ·Swap(SB),$8\n"},
		{"preprocessor-leftover", assemblyReferenceUnitBody + "#include \"more.h\"\n"},
		{"definition-in-operand", assemblyReferenceUnitBody + other + "MOVQ AX, TEXT ·Swap(SB),4,$0-25\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if defs, err := assemblyReferenceUnitParse(t, tc.body); err == nil || defs != nil {
				t.Fatal("incomplete or competing provider inventory accepted")
			}
		})
	}
	defs, err := assemblyReferenceUnitParse(t, other+assemblyReferenceUnitBody+strings.Replace(other, "Other", "Last", 1))
	if err != nil || len(defs) != 3 {
		t.Fatalf("full ordinary inventory: %v %v", defs, err)
	}
	defs, err = assemblyReferenceUnitParse(t, strings.Replace(assemblyReferenceUnitBody, "·Swap(SB)", "·Swap<>(SB)", 1))
	if err != nil || defs[0].symbol.local == "" {
		t.Fatalf("file-local definition lost its namespace: %v", err)
	}
	defs, err = assemblyReferenceUnitParse(t, strings.Replace(assemblyReferenceUnitBody, "·Swap(SB)", "example·com∕ref·Swap(SB)", 1))
	if err != nil || defs[0].symbol.name != "example.com/ref.Swap" {
		t.Fatalf("qualified definition: %v %v", defs, err)
	}
	defs, err = assemblyReferenceUnitParse(t, strings.ReplaceAll(assemblyReferenceUnitBody, "\n", ";"))
	if err != nil || len(defs) != 1 || len(defs[0].body) != 7 {
		t.Fatalf("semicolon boundaries: %v", err)
	}
}

func TestAssemblyReferenceInvocationOptions(t *testing.T) {
	for _, flag := range []string{"-shared", "-dynlink", "-spectre=all", "-gensymabis", "-d=maymorestack=x", "-race"} {
		t.Run(flag, func(t *testing.T) {
			p := assemblyReferenceUnitProvider(t, assemblyReferenceUnitBody, "/owned/body.s")
			p.Invocation.ExpandedArgs = append([]string{flag}, p.Invocation.ExpandedArgs...)
			if _, err := assemblyReferenceDefinitions(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, []assemblycapture.Provider{p}, "example.com/ref"); err == nil {
				t.Fatal("unsupported transformation accepted")
			}
		})
	}
	p := assemblyReferenceUnitProvider(t, assemblyReferenceUnitBody, "/owned/body.s")
	p.Invocation.Package = "foreign"
	if _, err := assemblyReferenceDefinitions(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, []assemblycapture.Provider{p}, "example.com/ref"); err == nil {
		t.Fatal("wrong qualified package accepted")
	}
	p = assemblyReferenceUnitProvider(t, assemblyReferenceUnitBody, "/owned/body.s")
	p.Invocation.IncludeDirs = []string{"/shadow"}
	if _, err := assemblyReferenceDefinitions(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, []assemblycapture.Provider{p}, "example.com/ref"); err == nil {
		t.Fatal("altered include selection projection accepted")
	}
}

func TestAssemblyReferenceCancellationAndCumulativeBudget(t *testing.T) {
	r := assemblyReferenceUnitRelation(t, assemblyReferenceUnitBody)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if result, err := assemblyReferenceApply(&assemblyReferenceMeter{Context: ctx, limits: defaultAssemblyReferenceLimits()}, r, []uint64{1, 1, 2}); !errors.Is(err, context.Canceled) || len(result.Accesses) != 0 {
		t.Fatalf("cancellation returned authority: %+v %v", result, err)
	}
	base := &assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}
	if _, err := assemblyReferenceApply(base, r, []uint64{1, 1, 2}); err != nil {
		t.Fatal(err)
	}
	spent := base.work
	for _, bound := range []int{1, spent / 2, spent - 1} {
		limits := defaultAssemblyReferenceLimits()
		limits.work = bound
		if result, err := assemblyReferenceApply(&assemblyReferenceMeter{Context: t.Context(), limits: limits}, r, []uint64{1, 1, 2}); err == nil || len(result.Accesses) != 0 {
			t.Fatalf("budget %d accepted partial specialization", bound)
		}
	}
	// The enclosing region-style context charges repeated calls to one account.
	shared := &assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}
	shared.limits.work = spent + spent/2
	if _, err := assemblyReferenceApply(&assemblyReferenceMeter{Context: shared, limits: defaultAssemblyReferenceLimits()}, r, []uint64{1, 1, 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := assemblyReferenceApply(&assemblyReferenceMeter{Context: shared, limits: defaultAssemblyReferenceLimits()}, r, []uint64{1, 1, 2}); err == nil {
		t.Fatal("second specialization reset its caller budget")
	}
	for _, change := range []func(*assemblyReferenceLimits){func(l *assemblyReferenceLimits) { l.bytes = 1 }, func(l *assemblyReferenceLimits) { l.instructions = 2 }, func(l *assemblyReferenceLimits) { l.work = 1 }} {
		limits := defaultAssemblyReferenceLimits()
		change(&limits)
		if defs, err := assemblyReferenceDefinitions(&assemblyReferenceMeter{Context: t.Context(), limits: limits}, []assemblycapture.Provider{assemblyReferenceUnitProvider(t, assemblyReferenceUnitBody, "/owned/body.s")}, "example.com/ref"); err == nil || defs != nil {
			t.Fatal("parser accepted exhausted inventory")
		}
	}
}

func TestAssemblyReferenceSpecializationDoesNotAssignScratch(t *testing.T) {
	b := br.NewBuilder(0)
	scope := br.NewScope()
	scratch, err := b.Scratch(br.Bits(64), scope, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := assemblyReferenceConstant(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, scratch); err == nil {
		t.Fatal("arbitrary scratch acquired a sampled result")
	}
	zero, err := b.Make(br.BitXor, br.Bits(64), 0, scratch, scratch)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := assemblyReferenceConstant(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, zero); err != nil || got != 0 {
		t.Fatalf("universal scratch elimination: %d %v", got, err)
	}
}

// Use a second source file for link access, as actual package-wide Go directives
// need not be attached to the target declaration. This fixture creates only
// ordinary typed syntax; it cannot create an acquisition or checked reference.
func assemblyReferenceDirectiveFixture(t testing.TB, code, directives string) (*selectedSourceBinder, *packages.Package, selectedSourcePackage, error) {
	t.Helper()
	fset := token.NewFileSet()
	var syntax []*ast.File
	for i, text := range []string{"package p\n" + code, "package p\n" + directives} {
		file, err := parser.ParseFile(fset, fmt.Sprintf("/owned/%d.go", i), text, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		syntax = append(syntax, file)
	}
	typed := types.NewPackage("example.com/ref", "p")
	ssaPkg, info, err := ssautil.BuildPackage(&types.Config{Importer: assemblyReferenceUnsafeImporter{}, Sizes: types.SizesFor("gc", "amd64")}, fset, typed, syntax, ssa.SanityCheckFunctions)
	if err != nil {
		t.Fatal(err)
	}
	p := &packages.Package{ID: typed.Path(), PkgPath: typed.Path(), Name: "p", Types: typed, TypesInfo: info, TypesSizes: types.SizesFor("gc", "amd64"), Fset: fset, Syntax: syntax, CompiledGoFiles: []string{"/owned/0.go", "/owned/1.go"}}
	source := computationSource{prog: &program{Prog: ssaPkg.Prog, Pkgs: []*packages.Package{p}}, metas: []listPkg{{ImportPath: p.ID, Dir: "/owned", GoFiles: []string{"0.go", "1.go"}}}}
	b, err := newSelectedSourceBinder(t.Context(), source, ssaPkg.Func("Swap"), defaultAssemblyReferenceLimits().source)
	if err != nil {
		return nil, p, selectedSourcePackage{}, err
	}
	inventory, err := b.selectedPackage(ssaPkg.Func("Swap"), p)
	return b, p, inventory, err
}

type assemblyReferenceUnsafeImporter struct{}

func (assemblyReferenceUnsafeImporter) Import(path string) (*types.Package, error) {
	if path == "unsafe" {
		return types.Unsafe, nil
	}
	return nil, fmt.Errorf("unsupported fixture import %s", path)
}

func TestAssemblyReferencePackageWideDirectives(t *testing.T) {
	code := "//go:noescape\nfunc Swap(ptr *uint64,old,replacement uint64) bool\nfunc Other(){}\n"
	for _, directive := range []string{"//go:linkname Swap", "//go:linknamestd Swap", "//go:linknamestd Swap\n//go:linkname Other"} {
		b, p, inventory, err := assemblyReferenceDirectiveFixture(t, code, "import _ \"unsafe\"\n"+directive+"\n")
		if err != nil {
			t.Fatal(err)
		}
		if err := assemblyReferenceDirectives(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, b, p, inventory); err != nil {
			t.Fatal(err)
		}
	}
	for _, directive := range []string{"//go:linknamestd Swap remote.Name", "//go:linkname Swap remote.Name", "//go:linknamestd Missing", "//go:linkname Swap\n//go:linknamestd Swap", "//go:linknamestd", "//go:unknown Swap"} {
		b, p, inventory, err := assemblyReferenceDirectiveFixture(t, code, "import _ \"unsafe\"\n"+directive+"\n")
		if err != nil {
			t.Fatal(err)
		}
		if err := assemblyReferenceDirectives(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, b, p, inventory); err == nil {
			t.Fatalf("accepted %s", directive)
		}
	}
	b, p, inventory, err := assemblyReferenceDirectiveFixture(t, "import _ \"unsafe\"\n"+code, "//go:linknamestd Swap\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := assemblyReferenceDirectives(&assemblyReferenceMeter{Context: t.Context(), limits: defaultAssemblyReferenceLimits()}, b, p, inventory); err == nil {
		t.Fatal("unsafe import in another file authorized directive")
	}
}

func TestAssemblyReferenceOwnerCannotBeManufactured(t *testing.T) {
	s := relationFixture(t, "func F(){}\nfunc Swap(ptr *uint64,old,replacement uint64)bool", 64)
	target := s.prog.Prog.Package(s.prog.Pkgs[0].Types).Func("Swap")
	if r, err := checkAssemblyReference(t.Context(), s, target, nil, assemblyReferenceLimits{}); err == nil || r != nil {
		t.Fatal("detached typed declaration acquired assembly authority")
	}
	var empty assemblyReference
	if err := empty.boundTo(s, target); err == nil {
		t.Fatal("zero reference acquired ownership")
	}
	if _, err := empty.evaluate(t.Context(), 1, 1, 2); err == nil {
		t.Fatal("zero reference acquired semantics")
	}
}
