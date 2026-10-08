package compartment

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/greatliontech/gofresh/closure/testvariant"
)

func TestInertnessPreservesExistingBindings(t *testing.T) {
	for _, tc := range []struct {
		name, before, after string
		inert               bool
	}{
		{"constant shadow", "func F() bool { return true }", "const true = false", false},
		{"function shadow", "func F() int { return len([]int{1}) }", "func len([]int) int { return 2 }", false},
		{"type shadow", "func F() int { return int(256) }", "type int = uint16", false},
		{"iota shadow", "const A = iota", "const iota = 4", false},
		{"unused universe shadow", "func F() {}", "const true = false", true},
		{"ordinary growth", "func F() {}", "func TestSibling() {}\nconst Extra = 1\ntype Helper struct{}", true},
		{"import swap", "import (x \"one\"; _ \"two\")\nfunc F() int { return x.Value }", "swap", false},
		{"new code import", "func F() {}", "import x \"one\"\nfunc G() int { return x.Value }", true},
		{"comment", "func F() {}", "// ordinary comment", true},
		{"dot import swap", "import . \"one\"\nfunc F() int { return Value }", "dot", false},
		{"unused blank import", "func F() {}", "import _ \"one\"", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := "package p\n" + tc.before + "\n"
			after := before + tc.after + "\n"
			switch tc.after {
			case "swap":
				after = "package p\nimport (_ \"one\"; x \"two\")\nfunc F() int { return x.Value }\n"
			case "dot":
				after = "package p\nimport . \"two\"\nfunc F() int { return Value }\n"
			}
			if tc.name == "new code import" {
				after = "package p\nimport x \"one\"\nfunc F() {}\nfunc G() int { return x.Value }\n"
			}
			if tc.name == "unused blank import" {
				after = "package p\nimport _ \"one\"\nfunc F() {}\n"
			}
			a, b := parseLedger(t, "p_test.go", before), parseLedger(t, "p_test.go", after)
			if got := testvariant.DiffTestVariantLedgers(a, b).Inert(); got != tc.inert {
				t.Fatalf("inert = %v, want %v", got, tc.inert)
			}
		})
	}
}

func TestBindingEvidenceFailsClosedAndClones(t *testing.T) {
	l := parseLedger(t, "p_test.go", "package p\nimport x \"one\"\nfunc F() { x.F() }\n")
	for _, damage := range []func(*testvariant.TestVariantLedger){
		func(l *testvariant.TestVariantLedger) { l.BindingStrategy = "" },
		func(l *testvariant.TestVariantLedger) { l.BindingStrategy = "future" },
		func(l *testvariant.TestVariantLedger) { l.FileHeaders[0].Bindings = nil },
		func(l *testvariant.TestVariantLedger) { l.FileHeaders[0].Bindings.Imports[0].Name = "" },
		func(l *testvariant.TestVariantLedger) {
			l.FileHeaders[0].Bindings = nil
			l.FileHeaders[0].Embedded = true
		},
	} {
		bad := l.Clone()
		damage(&bad)
		if testvariant.DiffTestVariantLedgers(bad, l).Inert() || testvariant.DiffTestVariantLedgers(l, bad).Inert() {
			t.Fatal("missing/unknown evidence accepted")
		}
	}
	l.BaseFiles = append(l.BaseFiles, l.FileHeaders[0])
	copy := l.Clone()
	copy.FileHeaders[0].Bindings.Imports[0].Path = "changed"
	copy.BaseFiles[0].Bindings.References[0] = "changed"
	if reflect.DeepEqual(copy, l) || l.FileHeaders[0].Bindings.Imports[0].Path != "one" || l.BaseFiles[0].Bindings.References[0] == "changed" {
		t.Fatal("clone shares binding storage")
	}
	if (testvariant.TestVariantDelta{}).Inert() {
		t.Fatal("zero delta supplied binding proof")
	}
}

func TestBindingLedgerRoundTrip(t *testing.T) {
	before := parseLedger(t, "p_test.go", "package p\nfunc Helper() {}\n")
	base := parseLedger(t, "p.go", "package p\nfunc Value() bool { return true }\n")
	before.BaseFiles = base.FileHeaders
	after := parseLedger(t, "p_test.go", "package p\nfunc Helper() {}\nconst true = false\n")
	after.BaseFiles = base.FileHeaders
	data, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	var back testvariant.TestVariantLedger
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, back) {
		t.Fatal("binding evidence lost in JSON round trip")
	}
	if testvariant.DiffTestVariantLedgers(back, after).Inert() {
		t.Fatal("persisted base reference failed to reject shadow")
	}
	// An adapter predating the binding fields cannot supply proof merely by
	// round-tripping the fields it knows.
	legacy, err := json.Marshal(struct {
		Declarations []testvariant.TestVariantDeclaration
		FileHeaders  []testvariant.TestVariantFileHeader
	}{before.Declarations, before.FileHeaders})
	if err != nil {
		t.Fatal(err)
	}
	var old testvariant.TestVariantLedger
	if err := json.Unmarshal(legacy, &old); err != nil {
		t.Fatal(err)
	}
	if testvariant.DiffTestVariantLedgers(old, before).Inert() {
		t.Fatal("legacy adapter silently supplied binding proof")
	}
}

// The grammar varies the shadowed universe name, the observing package, the
// observing file's base/test role, and whether the name is referenced at all.
func FuzzBindingGrowth(f *testing.F) {
	for i := uint8(0); i < 32; i++ {
		f.Add(i)
	}
	f.Fuzz(func(t *testing.T, seed uint8) {
		names := []string{"true", "len", "int"}
		uses := []string{"func F() bool { return true }", "func F() int { return len([]int{1}) }", "func F() int { return 1 }"}
		adds := []string{"const true = false", "func len([]int) int { return 2 }", "type int = uint16"}
		i := int(seed) % len(names)
		pkg := "p"
		if seed&4 != 0 {
			pkg = "p_test"
		}
		body := uses[i]
		if seed&8 != 0 {
			body = "func F() {}"
		}
		before := parseLedger(t, "old_test.go", fmt.Sprintf("package %s\n%s\n", pkg, body))
		if seed&16 != 0 {
			before.BaseFiles, before.FileHeaders, before.Declarations = before.FileHeaders, nil, nil
		}
		after := before.Clone()
		added := parseLedger(t, "new_test.go", "package p\n"+adds[i]+"\n")
		after.Declarations = append(after.Declarations, added.Declarations...)
		after.FileHeaders = append(after.FileHeaders, added.FileHeaders...)
		want := pkg != "p" || seed&8 != 0
		if got := testvariant.DiffTestVariantLedgers(before, after).Inert(); got != want {
			t.Fatalf("seed %d, shadow %s: inert %v, want %v", seed, names[i], got, want)
		}
	})
}
