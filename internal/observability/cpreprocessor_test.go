package observability

import (
	"context"

	"reflect"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/testvariant"
)

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
