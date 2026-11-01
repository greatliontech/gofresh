package closure

import (
	"context"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/closure/internal/compartment"
	"github.com/greatliontech/gofresh/internal/testvariant"
)

type memCompartmentSource map[string]string

func (m memCompartmentSource) ReadFile(path string) ([]byte, [32]byte, error) {
	s, ok := m[path]
	if !ok {
		return nil, [32]byte{}, os.ErrNotExist
	}
	b := []byte(s)
	return b, sha256.Sum256(b), nil
}

//gofresh:pure
func TestCPreprocessorEdgeMatrix(t *testing.T) {
	// 1. Self-recursive and mutually recursive macros terminate without overflowing and preserve symbol extraction.
	defs := map[string][]cppMacroDef{}
	collectCPPMacrosFromText(`
#define SELF(x) SELF(x) + x
#define MUT_A MUT_B
#define MUT_B MUT_A + runtime.nanotime
#define PASTE(a, b) a ## . ## b
#define STR(x) #x
#define VAR_STD(p, ...) p(__VA_ARGS__)
#define VAR_NAMED(p, args...) p(args)
#define MULTI runtime.nanotime
#define MULTI other.PureSym
`, defs)

	for _, tc := range []struct {
		name     string
		line     string
		wantSub  string
		overflow bool
	}{
		{"self_recursive", "SELF(targetSym)", "targetSym", false},
		{"mutually_recursive", "MUT_A", "runtime.nanotime", false},
		{"token_pasting", "PASTE(runtime, nanotime)", "runtime.nanotime", false},
		{"stringizing", "STR(  hello   \"world\"  )", `"hello \"world\""`, false},
		{"variadic_std", "VAR_STD(call, a, b, c)", "call(a, b, c)", false},
		{"variadic_named", "VAR_NAMED(call, x, y)", "call(x, y)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			states, primary, overflow := expandCPPLineAllChoices(tc.line, defs)
			if overflow != tc.overflow {
				t.Fatalf("expandCPPLineAllChoices(%q) overflow = %v, want %v", tc.line, overflow, tc.overflow)
			}
			matched := strings.Contains(primary, tc.wantSub)
			for _, st := range states {
				if strings.Contains(st, tc.wantSub) {
					matched = true
				}
			}
			if !matched {
				t.Fatalf("expandCPPLineAllChoices(%q) states=%v primary=%q, missing %q", tc.line, states, primary, tc.wantSub)
			}
		})
	}

	// Multi-definition macro expands all candidate branches.
	multiStates, _, multiOverflow := expandCPPLineAllChoices("MULTI", defs)
	if multiOverflow {
		t.Fatal("MULTI expansion unexpectedly overflowed")
	}
	hasRuntime, hasOther := false, false
	for _, st := range multiStates {
		if strings.Contains(st, "runtime.nanotime") {
			hasRuntime = true
		}
		if strings.Contains(st, "other.PureSym") {
			hasOther = true
		}
	}
	if !hasRuntime || !hasOther {
		t.Fatalf("MULTI states = %v, want both runtime.nanotime and other.PureSym", multiStates)
	}

	// 2. Budget overflow fail-closed: state explosion (maxCPPExpandedStatesPerLine), depth limit (maxCPPExpansionDepth),
	// and logical line byte limit (maxNonGoLogicalLineBytes).
	blowupDefs := map[string][]cppMacroDef{}
	var blowupSrc strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&blowupSrc, "#define B%d 0\n#define B%d 1\n", i, i)
	}
	collectCPPMacrosFromText(blowupSrc.String(), blowupDefs)
	_, _, stateOverflow := expandCPPLineAllChoices("B0 + B1 + B2 + B3 + B4 + B5 + B6 + B7 + B8 + B9", blowupDefs)
	if !stateOverflow {
		t.Fatal("expected state budget overflow on 2^10 multi-def combinations")
	}

	depthDefs := map[string][]cppMacroDef{}
	var depthSrc strings.Builder
	for i := 0; i < maxCPPExpansionDepth+5; i++ {
		fmt.Fprintf(&depthSrc, "#define D%d(x) D%d(x)\n", i, i+1)
	}
	fmt.Fprintf(&depthSrc, "#define D%d(x) x\n", maxCPPExpansionDepth+5)
	collectCPPMacrosFromText(depthSrc.String(), depthDefs)
	// Nested normal-arg evaluation triggers cur.depth+1 > maxCPPExpansionDepth.
	nestedCall := "x"
	for i := 0; i < maxCPPExpansionDepth+3; i++ {
		nestedCall = fmt.Sprintf("D0(%s)", nestedCall)
	}
	_, _, depthOverflow := expandCPPLineAllChoices(nestedCall, depthDefs)
	if !depthOverflow {
		t.Fatal("expected depth budget overflow on deeply nested macro calls")
	}

	hugeLine := strings.Repeat("a", maxNonGoLogicalLineBytes+10)
	if !scanPreprocessedNonGoSymbolRefs("pkg", nil, []string{hugeLine}, map[string]bool{}, map[string]bool{}, map[string]bool{}) {
		t.Fatal("expected scanPreprocessedNonGoSymbolRefs to report overflow on huge line")
	}

	// 3. C string literal normalization across prefixes, hex/octal/unicode escapes, and adjacent concatenation.
	norm := normalizeCStringLiterals(`L"\x72\165\u006e" u8"time." u"\U0000006e" U"anotime"`, true)
	if norm != `"runtime.nanotime"` {
		t.Fatalf("normalizeCStringLiterals = %q, want %q", norm, `"runtime.nanotime"`)
	}

	// 4. verifyAssemblyFile forbidden instructions, split middle-dot symbols, macro-qualified symbols, and unapproved #include.
	for _, badAsm := range []struct {
		name    string
		pkgPath string
		file    string
		src     string
		wantErr string
	}{
		{"syscall_inst", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tSYSCALL\n\tRET\n", "forbidden instruction SYSCALL"},
		{"rdtsc_inst", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tRDTSC\n\tRET\n", "forbidden instruction RDTSC"},
		{"cntvct_inst", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tMRS CNTVCT_EL0, R0\n\tRET\n", "forbidden instruction CNTVCT_EL0"},
		{"ta_trap", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tTA $0x10\n\tRET\n", "raw trap instruction TA"},
		{"int_trap", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tINT $0x80\n\tRET\n", "software interrupt instruction"},
		{"split_middledot", "pkg/a", "asm.s", "TEXT ·F(SB), $0\n\tCALL runtime ·nanotime(SB)\n\tRET\n", "split package-qualified symbol"},
		{"macro_middledot", "pkg/a", "asm.s", "#define PKG runtime\nTEXT ·F(SB), $0\n\tCALL PKG·nanotime(SB)\n\tRET\n", "forbidden package token runtime"},
		{"unapproved_include", "pkg/a", "asm.s", "#include \"secret.h\"\nTEXT ·F(SB), $0\n\tRET\n", "unapproved #include"},
		{"forbidden_path_include", "pkg/a", "asm.s", "#include \"../textflag.h\"\nTEXT ·F(SB), $0\n\tRET\n", "forbidden path in #include"},
		{"header_lowercase_define", "pkg/a", "hdr.h", "#define nanotime 1\n", "shadows lowercase package identifier"},
	} {
		t.Run(badAsm.name, func(t *testing.T) {
			err := verifyAssemblyFile(badAsm.pkgPath, badAsm.file, badAsm.src, nil)
			if err == nil || !strings.Contains(err.Error(), badAsm.wantErr) {
				t.Fatalf("verifyAssemblyFile(%s) error = %v, want substring %q", badAsm.name, err, badAsm.wantErr)
			}
		})
	}

	// 5. cgoEscapingInclude fail-closed refusal on raw string, bare macro #include, empty #include <>, and symlink escape.
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	outsideDir := filepath.Join(root, "outside")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, outsideDir, "secret.h", "#define X 1\n")
	if err := os.Symlink(outsideDir, filepath.Join(pkgDir, "symdir")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, pkgDir, "sym.c", `#include "symdir/secret.h"`)
	lp := &listPkg{Dir: pkgDir}
	if esc, err := cgoEscapingInclude(lp, []string{"sym.c"}); err != nil || esc == "" {
		t.Fatalf("cgoEscapingInclude(symlink dir) = (%q, %v), want non-empty escaping path", esc, err)
	}

	writeFile(t, pkgDir, "macro_inc.c", "#include HEADER_MACRO\n")
	if _, err := cgoEscapingInclude(lp, []string{"macro_inc.c"}); err == nil || !strings.Contains(err.Error(), "unresolved cgo include") {
		t.Fatalf("cgoEscapingInclude(bare macro) error = %v, want unresolved cgo include", err)
	}

	writeFile(t, pkgDir, "empty_inc.c", "#include <   >\n")
	if _, err := cgoEscapingInclude(lp, []string{"empty_inc.c"}); err == nil || !strings.Contains(err.Error(), "empty cgo include directive") {
		t.Fatalf("cgoEscapingInclude(empty <>) error = %v, want empty cgo include directive", err)
	}

	writeFile(t, pkgDir, "empty_quoted_inc.c", "#include \"\"\n")
	if _, err := cgoEscapingInclude(lp, []string{"empty_quoted_inc.c"}); err == nil || !strings.Contains(err.Error(), "empty cgo include directive") {
		t.Fatalf("cgoEscapingInclude(empty \"\") error = %v, want empty cgo include directive", err)
	}

	if err := os.Symlink(filepath.Join(outsideDir, "secret.h"), filepath.Join(pkgDir, "symfile.h")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, pkgDir, "symfile.c", `#include "symfile.h"`)
	if esc, err := cgoEscapingInclude(lp, []string{"symfile.c"}); err != nil || esc == "" {
		t.Fatalf("cgoEscapingInclude(symlink file) = (%q, %v), want non-empty escaping path", esc, err)
	}

	// Accessing p.Dir through a symlinked ancestor directory must not falsely report
	// an in-package regular header as escaping, while still catching escaping symlinks.
	writeFile(t, pkgDir, "local.h", "#define LOCAL_OK 1\n")
	writeFile(t, pkgDir, "local.c", `#include "local.h"`)
	symParent := filepath.Join(root, "symparent")
	if err := os.Symlink(pkgDir, symParent); err != nil {
		t.Fatal(err)
	}
	lpSymAncestor := &listPkg{Dir: symParent}
	if esc, err := cgoEscapingInclude(lpSymAncestor, []string{"local.c"}); err != nil || esc != "" {
		t.Fatalf("cgoEscapingInclude(symlinked p.Dir ancestor with local.h) = (%q, %v), want (\"\", nil)", esc, err)
	}
	if esc, err := cgoEscapingInclude(lpSymAncestor, []string{"symfile.c"}); err != nil || esc == "" {
		t.Fatalf("cgoEscapingInclude(symlinked p.Dir ancestor with escaping file symlink) = (%q, %v), want non-empty escaping path", esc, err)
	}

	writeFile(t, pkgDir, "raw_str.c", "const char *s = R\"raw(/*\n#include \"../outside/secret.h\"\n*/)raw\";\n")
	if _, err := cgoEscapingInclude(lp, []string{"raw_str.c"}); err == nil || !strings.Contains(err.Error(), "unsupported cgo raw string") {
		t.Fatalf("cgoEscapingInclude(raw string) error = %v, want unsupported cgo raw string", err)
	}
}

//gofresh:pure
func TestInertForSubjectClosureSoundnessBridge(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/bridge\n\ngo 1.24\n")
	writeFile(t, dir, "prod.go", `package bridge

func ProdAdd(a, b int) int { return a + b }
`)
	baseTestSrc := `package bridge

import (
	"os"
	"testing"
)

const (
	envAKey = "ENV_A_V1"
	envBKey = "ENV_B_V1"
)

func helperA(x int) int {
	_ = os.Getenv(envAKey)
	return ProdAdd(x, 1)
}

func helperB(x int) int {
	_ = os.Getenv(envBKey)
	return ProdAdd(x, 2)
}

func TestA(t *testing.T) {
	if helperA(1) != 2 {
		t.Fatal("bad")
	}
}

func TestB(t *testing.T) {
	if helperB(1) != 3 {
		t.Fatal("bad")
	}
}
`
	writeFile(t, dir, "bridge_test.go", baseTestSrc)

	type subjectState struct {
		maxHash         string
		obs             Observability
		rooted          RootedFunctions
		compartmentHash map[string]string
	}

	computeState := func() (testvariant.TestVariantLedger, map[Subject]subjectState) {
		h := newInMemoryHasherAt(t, dir)
		subjs := []Subject{
			{Package: "example.com/bridge", Symbol: "TestA"},
			{Package: "example.com/bridge", Symbol: "TestB"},
			{Package: "example.com/bridge", Symbol: "ProdAdd"},
		}
		maxClosures, _, err := h.ComputeMaximalBatch(subjs)
		if err != nil {
			t.Fatalf("ComputeMaximalBatch: %v", err)
		}
		ledger, err := h.TestVariantLedger("example.com/bridge")
		if err != nil {
			t.Fatalf("TestVariantLedger: %v", err)
		}
		obs, err := h.ComputeObservabilityBatch(subjs)
		if err != nil {
			t.Fatalf("ComputeObservabilityBatch: %v", err)
		}
		rooted, err := h.ComputeRootedFunctions(context.Background(), subjs)
		if err != nil {
			t.Fatalf("ComputeRootedFunctions: %v", err)
		}
		out := make(map[Subject]subjectState, len(subjs))
		for _, s := range subjs {
			rootedFns := make(map[string]bool, len(rooted[s].Fns))
			const prefix = "example.com/bridge\x00"
			for fnKey, ok := range rooted[s].Fns {
				if ok && strings.HasPrefix(fnKey, prefix) {
					rootedFns[strings.TrimPrefix(fnKey, prefix)] = true
				}
			}
			compHashes := map[string]string{}
			for _, decl := range ledger.Declarations {
				switch decl.Kind {
				case "init", "var", "directive":
					compHashes[decl.Kind+":"+decl.Name+":"+decl.Hash] = decl.Hash
				case "func":
					if rootedFns[decl.Name] {
						compHashes["func:"+decl.Name] = decl.Hash
					}
				case "method":
					if rootedFns[decl.Receiver+"."+decl.Name] {
						compHashes["method:"+decl.Receiver+"."+decl.Name] = decl.Hash
					}
				}
			}
			out[s] = subjectState{
				maxHash:         maxClosures[s].Hash,
				obs:             obs[s],
				rooted:          rooted[s],
				compartmentHash: compHashes,
			}
		}
		return ledger, out
	}

	beforeLedger, beforeStates := computeState()

	mutations := []struct {
		name      string
		testSrc   string
		wantInert map[string]bool
	}{
		{
			name:    "add_sibling_test_TestC",
			testSrc: baseTestSrc + "\nfunc TestC(t *testing.T) { _ = os.Getenv(\"ENV_C\"); _ = ProdAdd(3, 4) }\n",
			wantInert: map[string]bool{
				"TestA":   true,
				"TestB":   true,
				"ProdAdd": true,
			},
		},
		{
			name: "edit_TestB_and_helperB_only",
			testSrc: strings.Replace(
				strings.Replace(baseTestSrc, `"ENV_B_V1"`, `"ENV_B_V2"`, 1),
				"helperB(1) != 3", "helperB(1) != 21", 1,
			),
			wantInert: map[string]bool{
				"TestA":   true,
				"TestB":   false,
				"ProdAdd": true,
			},
		},
		{
			name: "edit_helperA_used_by_TestA",
			testSrc: strings.Replace(
				strings.Replace(baseTestSrc, `"ENV_A_V1"`, `"ENV_A_V2"`, 1),
				"return ProdAdd(x, 1)", "return ProdAdd(x, 100)", 1,
			),
			wantInert: map[string]bool{
				"TestA":   false,
				"TestB":   true,
				"ProdAdd": true,
			},
		},
		{
			name:    "add_package_var_in_test_compartment",
			testSrc: baseTestSrc + "\nvar addedGlobal = os.Getenv(\"ENV_VAR\")\n",
			wantInert: map[string]bool{
				"TestA":   false,
				"TestB":   false,
				"ProdAdd": false,
			},
		},
		{
			name:    "add_init_in_test_compartment",
			testSrc: baseTestSrc + "\nfunc init() { _ = os.Getenv(\"ENV_INIT\") }\n",
			wantInert: map[string]bool{
				"TestA":   false,
				"TestB":   false,
				"ProdAdd": false,
			},
		},
	}

	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			writeFile(t, dir, "bridge_test.go", m.testSrc)
			afterLedger, afterStates := computeState()
			for sym, want := range m.wantInert {
				gotInert := testvariant.InertForSubject(beforeLedger, afterLedger, sym)
				if gotInert != want {
					t.Fatalf("InertForSubject(%s) = %v, want %v", sym, gotInert, want)
				}
				subj := Subject{Package: "example.com/bridge", Symbol: sym}
				equalState := reflect.DeepEqual(beforeStates[subj], afterStates[subj])
				if gotInert && !equalState {
					t.Fatalf("InertForSubject(%s) = true, but compiled subject state moved:\nbefore=%+v\nafter =%+v", sym, beforeStates[subj], afterStates[subj])
				}
				if !gotInert && equalState {
					t.Fatalf("InertForSubject(%s) = false, but compiled subject state was unchanged (test would pass for wrong reason): %+v", sym, beforeStates[subj])
				}
			}
		})
	}
}

//gofresh:pure
func FuzzInertForSubjectClosureSoundnessBridge(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{1, 0, 2, 1})
	f.Add([]byte{0, 3, 1, 2})
	f.Add([]byte{2, 1, 0, 3})
	f.Add([]byte{3, 3, 3, 3})

	prodSrc := `package p

func ProdAdd(a, b int) int { return a + b }
`
	baseATest := `package p

import "testing"

type box[T any] struct{ v T }

func (b *box[T]) get() T { return b.v }

const (
	govA = 10
	omitA
)

func helperA(x int) int {
	b := box[int]{v: x}
	return ProdAdd(b.get(), omitA)
}

func TestA(t *testing.T) {
	if helperA(1) == 0 {
		t.Fatal("bad")
	}
}
`
	buildVariantBTest := func(b []byte) string {
		var sb strings.Builder
		sb.WriteString("package p\n\n")
		if b[0]%4 != 3 {
			sb.WriteString("import \"testing\"\n\n")
		}
		switch b[0] % 4 {
		case 0:
			sb.WriteString("func helperB(x int) int { return ProdAdd(x, 2) }\n")
		case 1:
			sb.WriteString("func helperB(x int) int { return ProdAdd(x, 200) }\n")
		case 2:
			sb.WriteString("func helperB(x int) int { return ProdAdd(x, 2) }\nfunc extraHelper() int { return 99 }\n")
		case 3:
			// omit helperB and TestB
		}
		if b[0]%4 != 3 {
			if b[1]%2 == 0 {
				sb.WriteString("func TestB(t *testing.T) { _ = helperB(1) }\n")
			} else {
				sb.WriteString("func TestB(t *testing.T) { _ = helperB(99) }\n")
			}
		}
		switch b[2] % 5 {
		case 0:
			// no extra declarations
		case 1:
			sb.WriteString("var globalMut = ProdAdd(1, 2)\n")
		case 2:
			sb.WriteString("func init() { _ = ProdAdd(3, 4) }\n")
		case 3:
			sb.WriteString("func (b box[T]) extraMethod() T { return b.v }\n")
		case 4:
			sb.WriteString("const ExportedForExt = 77\n")
		}
		return sb.String()
	}

	buildVariantATest := func(b []byte) string {
		src := baseATest
		switch b[3] % 4 {
		case 0:
			// unchanged
		case 1:
			// insert blank const governor before omitA
			src = strings.Replace(src, "govA = 10\n\tomitA", "govA = 10\n\t_ = 999\n\tomitA", 1)
		case 2:
			// edit helperA body
			src = strings.Replace(src, "ProdAdd(b.get(), omitA)", "ProdAdd(b.get(), 42)", 1)
		case 3:
			// edit (*box[T]).get
			src = strings.Replace(src, "func (b *box[T]) get() T { return b.v }", "func (b *box[T]) get() T { var z T; return z }", 1)
		}
		return src
	}

	parseAndTypecheck := func(t testing.TB, aSrc, bSrc string) (testvariant.TestVariantLedger, map[string]string) {
		t.Helper()
		fset := token.NewFileSet()
		var syntax []*ast.File
		for _, pair := range []struct{ name, src string }{
			{"prod.go", prodSrc},
			{"a_test.go", aSrc},
			{"b_test.go", bSrc},
		} {
			af, err := parser.ParseFile(fset, pair.name, pair.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("ParseFile(%s): %v", pair.name, err)
			}
			syntax = append(syntax, af)
		}
		info := &types.Info{
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
		}
		conf := types.Config{Importer: importer.Default()}
		pkg, err := conf.Check("example.com/p", fset, syntax, info)
		if err != nil {
			t.Fatalf("types.Check: %v", err)
		}

		// Compute real TestVariantLedger via compartment.ComputeIdentity + AddBaseBindings.
		srcMap := memCompartmentSource{
			"prod.go":   prodSrc,
			"a_test.go": aSrc,
			"b_test.go": bSrc,
		}
		compiledGo := map[string]bool{
			"a_test.go": true,
			"b_test.go": true,
		}
		id, err := compartment.ComputeIdentity("", []string{"a_test.go", "b_test.go"}, compiledGo, nil, nil, srcMap, nil)
		if err != nil {
			t.Fatalf("ComputeIdentity: %v", err)
		}
		if err := compartment.AddBaseBindings(&id, []string{"prod.go"}, map[string]string{"testing": "testing"}, srcMap, nil); err != nil {
			t.Fatalf("AddBaseBindings: %v", err)
		}

		// Ground-truth semantic digest for TestA from type-checked AST + resolved constant values + method set of box.
		declHashes := map[string]string{}
		for _, d := range id.Ledger.Declarations {
			if d.Kind == "init" || d.Kind == "var" || d.Kind == "directive" {
				declHashes["global:"+d.Kind+":"+d.Name+":"+d.Hash] = d.Hash
			}
			if d.Name == "TestA" || d.Name == "helperA" || d.Name == "box" || d.Receiver == "(*box[T])" || d.Receiver == "box[T]" {
				declHashes[d.Kind+":"+d.Receiver+"."+d.Name] = d.Hash
			}
		}
		if cObj, ok := pkg.Scope().Lookup("omitA").(*types.Const); ok {
			declHashes["constVal:omitA"] = cObj.Val().ExactString()
		}
		return id.Ledger, declHashes
	}

	beforeLedger, beforeSemantic := parseAndTypecheck(f, baseATest, buildVariantBTest([]byte{0, 0, 0, 0}))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 4 {
			return
		}
		aSrc := buildVariantATest(data)
		bSrc := buildVariantBTest(data)
		afterLedger, afterSemantic := parseAndTypecheck(t, aSrc, bSrc)

		inertTestA := testvariant.InertForSubject(beforeLedger, afterLedger, "TestA")
		inertMethod := testvariant.InertForSubject(beforeLedger, afterLedger, "*box.get")
		if inertTestA && !reflect.DeepEqual(beforeSemantic, afterSemantic) {
			t.Fatalf("InertForSubject(TestA) = true, but type-checked semantic state changed:\nbefore=%v\nafter =%v", beforeSemantic, afterSemantic)
		}
		if inertMethod && beforeSemantic["method:(*box[T]).get"] != afterSemantic["method:(*box[T]).get"] {
			t.Fatalf("InertForSubject(*box.get) = true, but (*box[T]).get changed")
		}
	})
}

//gofresh:pure
func FuzzCPreprocessor(f *testing.F) {
	f.Add("#define A B\n#define B A\nA\n")
	f.Add("#define P(x, y) x ## y\n#define S(x) #x\nP(run, time.nanotime)\nS(a \"b\" c)\n")
	f.Add("L\"\\x72\\165\\u006e\" \\\n\"time·nanotime\"\n")
	f.Add("/* comment */ #include \"hdr.h\" // line\\\ncontinuation\nTEXT ·F(SB), $0\n\tSYSCALL\n")
	f.Add("const char *s = R\"delim(/* not a comment */)delim\";\n")

	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 4096 {
			return
		}
		_ = normalizeCStringLiterals(src, true)
		_ = normalizeCStringLiterals(src, false)
		_ = stripAssemblyComments(src, true, true)
		_ = stripAssemblyComments(src, false, false)
		_, _ = stripCComments(src)
		_ = verifyAssemblyFile("example.com/pkg", "fuzz.s", src, nil)

		rtOut := map[string]bool{}
		extOut := map[string]bool{}
		idOut := map[string]bool{}
		_ = scanPreprocessedNonGoSymbolRefs("example.com/pkg", []string{src}, []string{src}, rtOut, extOut, idOut)
	})
}
