package shortgates

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The checker's every arm is pinned over synthetic sources: the shapes
// it must admit and each shape it must refuse, so a neutered arm fails
// here rather than passing silently over a tree that happens to be
// clean.
func TestCheckDetectsEachViolation(t *testing.T) {
	const gate = "if testing." + "Short() {\n\t\tt.Skip(\"x\")\n\t}\n"
	cases := []struct {
		name     string
		src      string
		mismatch bool
		problem  string
	}{
		{"gate at the head of a test", "func TestA(t *testing.T) {\n\t" + gate + "\t_ = 1\n}\n", false, ""},
		{"gate after cheap controls", "func TestA(t *testing.T) {\n\t_ = 1\n\t" + gate + "}\n", false, ""},
		{"gate in a t.Run subtest body counts", "func TestA(t *testing.T) {\n\tt.Run(\"s\", func(t *testing.T) {\n\t\t" + gate + "\t})\n}\n", false, ""},
		{"gate in a fuzz body counts", "func FuzzA(f *testing.F) {\n\tf.Fuzz(func(t *testing.T, s string) {\n\t\t" + gate + "\t})\n}\n", false, ""},
		{"gate in an uninvoked closure", "func TestA(t *testing.T) {\n\t_ = func() {\n\t\t" + gate + "\t}\n}\n", true, ""},
		{"gate in a helper", "func helper(t *testing.T) {\n\t" + gate + "}\n\nfunc TestA(t *testing.T) { helper(t) }\n", true, ""},
		{"gate text in a raw string literal", "func TestA(t *testing.T) {\n\t_ = `package p\n\nfunc TestX(t *testing.T) {\n\t" + gate + "}\n`\n}\n", false, "string literal"},
		{"gate text in an interpreted string literal", "func TestA(t *testing.T) {\n\t_ = \"func TestX(t *testing.T) {\\n\\tif testing." + "Short() {\\n\\t\\tt.Skip(\\\"x\\\")\\n\\t}\\n}\\n\"\n}\n", false, "string literal"},
		{"gate that does not skip", "func TestA(t *testing.T) {\n\tif testing." + "Short() {\n\t\tt.Log(\"gated\")\n\t}\n}\n", false, "does not skip"},
		{"gate that skips and does more", "func TestA(t *testing.T) {\n\tif testing." + "Short() {\n\t\tt.Log(\"x\")\n\t\tt.Skip(\"x\")\n\t}\n}\n", false, "does not skip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "case_test.go", "package p\n\nimport \"testing\"\n\n"+tc.src, 0)
			if err != nil {
				t.Fatal(err)
			}
			rep := Check(fset, map[string]*ast.File{"case_test.go": f})
			if got := rep.Anywhere != rep.InBodies; got != tc.mismatch {
				t.Errorf("mismatch = %t (anywhere %d, in bodies %d), want %t", got, rep.Anywhere, rep.InBodies, tc.mismatch)
			}
			joined := strings.Join(rep.Problems, "\n")
			if tc.problem == "" && joined != "" {
				t.Errorf("unexpected problems:\n%s", joined)
			}
			if tc.problem != "" && !strings.Contains(joined, tc.problem) {
				t.Errorf("problems %q do not name %q", joined, tc.problem)
			}
		})
	}
}

// Walk scopes the tree — testdata skipped, root and descent recorded —
// and each violation class shows in the report it returns.
func TestWalkScopesTheTreeAndReportsEachClass(t *testing.T) {
	const gate = "if testing." + "Short() {\n\t\tt.Skip(\"x\")\n\t}\n"
	write := func(t *testing.T, files map[string]string) string {
		t.Helper()
		dir := t.TempDir()
		for name, content := range files {
			path := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	clean := write(t, map[string]string{
		"a_test.go":          "package p\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {\n\t" + gate + "}\n",
		"sub/b_test.go":      "package sub\n\nimport \"testing\"\n\nfunc TestB(t *testing.T) {\n\t" + gate + "}\n",
		"testdata/x_test.go": "package x\n\nimport \"testing\"\n\nfunc helper(t *testing.T) {\n\t" + gate + "}\n",
	})
	rep, err := Walk(clean)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Anywhere != 2 || rep.InBodies != 2 || len(rep.Problems) != 0 || !rep.AtRoot || !rep.Descended {
		t.Fatalf("clean tree: %+v (testdata must be skipped, both gates counted in bodies)", rep)
	}
	helperTree := write(t, map[string]string{
		"a_test.go":     "package p\n\nimport \"testing\"\n\nfunc helper(t *testing.T) {\n\t" + gate + "}\n\nfunc TestA(t *testing.T) { helper(t) }\n",
		"sub/b_test.go": "package sub\n\nimport \"testing\"\n\nfunc TestB(t *testing.T) {\n\t" + gate + "}\n",
	})
	if rep, _ := Walk(helperTree); rep.Anywhere != 2 || rep.InBodies != 1 {
		t.Fatalf("helper gate: %+v", rep)
	}
	rootless := write(t, map[string]string{
		"sub/b_test.go": "package sub\n\nimport \"testing\"\n\nfunc TestB(t *testing.T) {\n\t" + gate + "}\n",
	})
	if rep, _ := Walk(rootless); rep.AtRoot || !rep.Descended {
		t.Fatalf("rootless tree: %+v", rep)
	}
	flat := write(t, map[string]string{
		"a_test.go": "package p\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {\n\t" + gate + "}\n",
	})
	if rep, _ := Walk(flat); !rep.AtRoot || rep.Descended {
		t.Fatalf("flat tree: %+v", rep)
	}
	unparsable := write(t, map[string]string{"a_test.go": "package p\n\nfunc {"})
	if _, err := Walk(unparsable); err == nil {
		t.Fatal("an unparsable test file walked cleanly")
	}
}

// recorder is a Failer that records what Pin reported: errors
// accumulate, a fatal stops the pin the way the testing package's would.
type recorder struct {
	errors []string
	fatal  string
}

type fatalStop struct{}

func (r *recorder) Helper()           {}
func (r *recorder) Error(args ...any) { r.errors = append(r.errors, fmt.Sprint(args...)) }
func (r *recorder) Fatal(args ...any) { r.fatal = fmt.Sprint(args...); panic(fatalStop{}) }
func (r *recorder) Fatalf(format string, args ...any) {
	r.fatal = fmt.Sprintf(format, args...)
	panic(fatalStop{})
}

// pin runs Pin against root with a recorder and returns it.
func pin(root string) *recorder {
	r := &recorder{}
	func() {
		defer func() {
			if v := recover(); v != nil {
				if _, stopped := v.(fatalStop); !stopped {
					panic(v)
				}
			}
		}()
		Pin(r, root)
	}()
	return r
}

// Pin's every arm fires on the tree that violates it and none on a
// clean tree: the walk error, the per-gate problems, the root and
// descent reach, the helper mismatch, and the gate-free tree.
func TestPinFailsEachArm(t *testing.T) {
	const gate = "if testing." + "Short() {\n\t\tt.Skip(\"x\")\n\t}\n"
	write := func(t *testing.T, files map[string]string) string {
		t.Helper()
		dir := t.TempDir()
		for name, content := range files {
			path := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	test := func(body string) string {
		return "package p\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {\n\t" + body + "}\n"
	}
	sub := "package sub\n\nimport \"testing\"\n\nfunc TestB(t *testing.T) {\n\t" + gate + "}\n"
	clean := pin(write(t, map[string]string{"a_test.go": test(gate), "sub/b_test.go": sub}))
	if clean.fatal != "" || len(clean.errors) != 0 {
		t.Fatalf("clean tree failed: fatal %q, errors %v", clean.fatal, clean.errors)
	}
	for name, tc := range map[string]struct {
		files  map[string]string
		fatal  string
		errors int
	}{
		"walk error":               {map[string]string{"a_test.go": "package p\n\nfunc {", "sub/b_test.go": sub}, "expected", 0},
		"gate that does not skip":  {map[string]string{"a_test.go": test("if testing." + "Short() {\n\t\tt.Log(\"x\")\n\t}\n"), "sub/b_test.go": sub}, "", 1},
		"no test file at the root": {map[string]string{"sub/b_test.go": sub}, "reached no test file", 0},
		"no descent":               {map[string]string{"a_test.go": test(gate)}, "did not descend", 0},
		"gate in a helper":         {map[string]string{"a_test.go": "package p\n\nimport \"testing\"\n\nfunc helper(t *testing.T) {\n\t" + gate + "}\n\nfunc TestA(t *testing.T) { helper(t) }\n", "sub/b_test.go": sub}, "sits in a helper", 0},
		"no gates":                 {map[string]string{"a_test.go": test(""), "sub/b_test.go": "package sub\n\nimport \"testing\"\n\nfunc TestB(t *testing.T) {}\n"}, "no gates found", 0},
	} {
		r := pin(write(t, tc.files))
		if !strings.Contains(r.fatal, tc.fatal) || len(r.errors) != tc.errors {
			t.Errorf("%s: fatal %q (want %q), errors %v (want %d)", name, r.fatal, tc.fatal, r.errors, tc.errors)
		}
	}
}
