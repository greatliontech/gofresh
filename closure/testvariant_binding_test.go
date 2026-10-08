package closure

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure/testvariant"
	"github.com/greatliontech/gofresh/gotool"
)

func TestTestVariantInertnessRejectsRebinding(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over a fixture")
	}
	t.Setenv("GOFRESH_BINDING_A", "true")
	t.Setenv("GOFRESH_BINDING_B", "false")
	for _, tc := range []struct{ name, production, test, after string }{
		{"benchmark environment with file-reading sibling", "package p\n", "package p\nimport (\"testing\"; \"fmt\"; \"os\")\nfunc BenchmarkEnv(b *testing.B) { if true { fmt.Println(\"VALUE\", os.Getenv(\"GOFRESH_BINDING_A\")) } else { fmt.Println(\"VALUE\", os.Getenv(\"GOFRESH_BINDING_B\")) } }\nfunc TestValue(t *testing.T) { BenchmarkEnv(nil) }\nfunc TestReadsFile(t *testing.T) { _, _ = os.ReadFile(\"fixture\") }\n", "\nconst true = false\n"},
		{"test universe", "package p\n", "package p\nimport (\"testing\"; \"fmt\")\nfunc TestValue(t *testing.T) { fmt.Println(\"VALUE\", true) }\n", "\nconst true = false\n"},
		{"production universe", "package p\nfunc Value() bool { return true }\n", "package p\nimport (\"testing\"; \"fmt\")\nfunc TestValue(t *testing.T) { fmt.Println(\"VALUE\", Value()) }\n", "\nconst true = false\n"},
		{"import alias", "package p\n", "package p\nimport (\"testing\"; \"fmt\"; x \"example.com/binding/a\"; _ \"example.com/binding/b\")\nfunc TestValue(t *testing.T) { fmt.Println(\"VALUE\", x.Value) }\n", "swap"},
		{"declared import name", "package p\n", "package p\nimport (\"testing\"; \"fmt\"; \"example.com/binding/a\"; _ \"example.com/binding/b\")\nfunc TestValue(t *testing.T) { fmt.Println(\"VALUE\", a.Value) }\n", "swap-default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTestVariantModule(t, map[string]string{
				"go.mod": "module example.com/binding\n\ngo 1.26\n",
				"p.go":   tc.production, "p_test.go": tc.test,
				"a/a.go": "package a\nconst Value = true\n", "b/b.go": "package a\nconst Value = false\n",
			})
			run := func(want string) {
				t.Helper()
				out, err := (gotool.Runner{}).Run(context.Background(), dir, os.Environ(), "test", "-count=1", "-v", "-run=^TestValue$", ".")
				if err != nil || !strings.Contains(string(out), "VALUE "+want) {
					t.Fatalf("runtime: want %s, got %s, %v", want, out, err)
				}
			}
			subject := Subject{Package: "example.com/binding", Symbol: "TestValue"}
			if tc.name == "benchmark environment with file-reading sibling" {
				subject.Symbol = "BenchmarkEnv"
			}
			beforeCore := computeAt(t, dir, subject)[subject]
			if subject.Symbol == "BenchmarkEnv" && !beforeCore.Unverifiable {
				t.Fatal("file-reading sibling did not preserve the conservative external-input floor")
			}
			before := ledgerAt(t, dir, subject.Package)
			run("true")
			afterSource := tc.test + tc.after
			if tc.after == "swap" {
				afterSource = strings.ReplaceAll(strings.ReplaceAll(tc.test, `x "example.com/binding/a"`, `_ "example.com/binding/a"`), `_ "example.com/binding/b"`, `x "example.com/binding/b"`)
			}
			if tc.after == "swap-default" {
				afterSource = strings.ReplaceAll(strings.ReplaceAll(tc.test, `; "example.com/binding/a"`, `; _ "example.com/binding/a"`), `_ "example.com/binding/b"`, `"example.com/binding/b"`)
			}
			if err := os.WriteFile(filepath.Join(dir, "p_test.go"), []byte(afterSource), 0o644); err != nil {
				t.Fatal(err)
			}
			run("false")
			afterCore := computeAt(t, dir, subject)[subject]
			if beforeCore.Hash != afterCore.Hash {
				t.Fatal("fixture moved core")
			}
			delta := testvariant.DiffTestVariantLedgers(before, ledgerAt(t, dir, subject.Package))
			if len(delta.Changed)+len(delta.Removed) != 0 {
				t.Fatalf("fixture changed declaration bytes: %+v", delta)
			}
			if delta.Inert() {
				t.Fatalf("behavior changed under unchanged core and declarations, but delta is inert: %+v", delta)
			}
		})
	}
}

func TestTestVariantBindingGuardAllowsUnrelatedGrowth(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over a fixture")
	}
	const beforeSource = "package p\nimport (\"testing\"; _ \"fmt\")\nfunc TestValue(t *testing.T) {}\n"
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":    "module example.com/binding\n\ngo 1.26\n",
		"p.go":      "package p\nfunc Value() int { return 1 }\n",
		"p_test.go": beforeSource,
	})
	subject := Subject{Package: "example.com/binding", Symbol: "TestValue"}
	core := computeAt(t, dir, subject)[subject].Hash
	before := ledgerAt(t, dir, subject.Package)
	afterSource := strings.Replace(beforeSource, `_ "fmt"`, `"fmt"`, 1) + "\n// harmless header comment\nfunc Helper() string { return fmt.Sprint(Extra) }\nconst Extra = 2\ntype Other struct{}\nfunc TestSibling(t *testing.T) { if Helper() != \"2\" { t.Fatal(Helper()) } }\n"
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("// harmless base comment\npackage p\nfunc Value() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p_test.go"), []byte(afterSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (gotool.Runner{}).Run(context.Background(), dir, os.Environ(), "test", "-count=1", "."); err != nil {
		t.Fatal(err)
	}
	if computeAt(t, dir, subject)[subject].Hash != core {
		t.Fatal("unrelated growth changed dependency core")
	}
	if delta := testvariant.DiffTestVariantLedgers(before, ledgerAt(t, dir, subject.Package)); !delta.Inert() {
		t.Fatalf("unrelated declarations and new-code import refused: %+v", delta)
	}
}
