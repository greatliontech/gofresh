package closure

import (
	"context"
	"crypto/sha256"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/closure/internal/compartment"
	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
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
func TestRawAndEscapedCgoImportPreambleDetectionAndCanonicalDigest(t *testing.T) {
	for _, spell := range []struct {
		name string
		imp  string
	}{
		{"raw_single", "import `C`"},
		{"raw_grouped", "import (\n\t`C`\n)"},
		{"hex_escaped", `import "\x43"`},
		{"octal_escaped", `import "\103"`},
	} {
		t.Run(spell.name, func(t *testing.T) {
			srcA := "package p\n\n// #define CGO_FLAG 1\n// #include \"local.h\"\n" + spell.imp + "\n\nfunc F() int { return 1 }\n"
			srcB := "package p\n\n// #define CGO_FLAG 2\n// #include \"local.h\"\n" + spell.imp + "\n\nfunc F() int { return 1 }\n"

			if !cprep.SourceMayImportC(srcA) {
				t.Fatalf("SourceMayImportC(%s) = false, want true", spell.name)
			}
			preamble, err := cprep.GoCgoPreamble([]byte(srcA))
			if err != nil {
				t.Fatalf("GoCgoPreamble(%s): %v", spell.name, err)
			}
			if !strings.Contains(preamble, "#define CGO_FLAG 1") || !strings.Contains(preamble, `#include "local.h"`) {
				t.Fatalf("GoCgoPreamble(%s) = %q, missing preamble directives", spell.name, preamble)
			}
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "p.go", srcA, parser.ParseComments)
			if err != nil {
				t.Fatalf("ParseFile(%s): %v", spell.name, err)
			}
			extracted := strings.Join(cprep.ExtractFileCgoPreambles(f), "\n")
			if !strings.Contains(extracted, "#define CGO_FLAG 1") {
				t.Fatalf("ExtractFileCgoPreambles(%s) = %q, missing #define CGO_FLAG 1", spell.name, extracted)
			}
			digA, okA := canonicalDigest([]byte(srcA))
			digB, okB := canonicalDigest([]byte(srcB))
			if !okA || !okB {
				t.Fatalf("canonicalDigest(%s) ok = (%v, %v), want (true, true)", spell.name, okA, okB)
			}
			if digA == digB {
				t.Fatalf("canonicalDigest(%s) did not change when cgo preamble changed: %s", spell.name, digA)
			}
		})
	}
}
