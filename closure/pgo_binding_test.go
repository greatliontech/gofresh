package closure

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/closure/internal/compartment"
	"github.com/greatliontech/gofresh/closure/testvariant"
	"github.com/greatliontech/gofresh/gotool"
)

func TestPGOBuildCopiesRetainImportBindings(t *testing.T) {
	if testing.Short() {
		t.Skip("lists and builds a main-package test binary with a real PGO profile")
	}
	const pkg = "example.com/pgobindings"
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":            "module " + pkg + "\n\ngo 1.27.0\n",
		"main.go":           "package main\nimport \"example.com/pgobindings/dependency\"\nfunc main() { declared.Value() }\n",
		"main_test.go":      "package main\nimport (\"testing\"; \"example.com/pgobindings/dependency\")\nfunc TestValue(t *testing.T) { if declared.Value() != 1 { t.Fatal(\"wrong value\") } }\n",
		"dependency/dep.go": "package declared\nfunc Value() int { return 1 }\n",
	})
	var profile bytes.Buffer
	if err := pprof.StartCPUProfile(&profile); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Millisecond)
	for time.Now().Before(deadline) {
	}
	pprof.StopCPUProfile()
	if err := os.WriteFile(filepath.Join(dir, "default.pgo"), profile.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	control, _ := ledgerUnder(t, dir, nil, []string{"-pgo=off"}, pkg)
	if !testvariant.DiffTestVariantLedgers(control, control).Inert() {
		t.Fatal("ordinary ledger control has incomplete binding evidence")
	}
	for _, flags := range [][]string{nil, {"-pgo=auto"}, {"-pgo=" + filepath.Join(dir, "default.pgo")}} {
		h := hasherUnder(t, dir, nil, flags)
		listed, err := h.list(pkg)
		if err != nil {
			t.Fatal(err)
		}
		decorated := false
		for _, p := range listed {
			if p.SourcePath() == "testing" && p.ImportPath != p.SourcePath() {
				decorated = true
			}
		}
		if !decorated && len(flags) == 0 {
			t.Fatal("default-PGO fixture did not produce the decorated dependency")
		}
		ledger, err := h.TestVariantLedger(pkg)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(ledger, control) {
			t.Fatalf("PGO changed source-name binding evidence under %v:\n got %+v\nwant %+v", flags, ledger, control)
		}
		if !testvariant.DiffTestVariantLedgers(ledger, ledger).Inert() {
			t.Fatalf("PGO ledger refused its unchanged source under %v", flags)
		}
		// Pin the declared name, not a coincidentally correct path basename.
		if got := ledger.BaseFiles[0].Bindings.Imports; !reflect.DeepEqual(got, []testvariant.TestVariantImport{{Name: "declared", Path: pkg + "/dependency"}}) {
			t.Fatalf("base-file import = %+v", got)
		}
		args := append([]string{"test", "-count=1"}, flags...)
		args = append(args, ".")
		if output, err := (gotool.Runner{}).Run(t.Context(), dir, os.Environ(), args...); err != nil {
			t.Fatalf("the listed PGO test binary does not execute: %v\n%s", err, output)
		}
	}
}

func TestSyntheticTestPackageCannotReplaceAnImportBinding(t *testing.T) {
	const pkg = "example.com/bindings"
	dir := writeTestVariantModule(t, map[string]string{
		"p.go":        "package p\n",
		"ext_test.go": "package p_test\nimport \"example.com/bindings_test\"\nfunc Example() { declared.Value() }\n",
	})
	module := &listMod{Path: pkg, Main: true, Dir: dir}
	real := listPkg{ImportPath: pkg + "_test", Name: "declared", Dir: filepath.Join(dir, "dependency")}
	synthetic := listPkg{ImportPath: pkg + "_test [" + pkg + ".test]", ForTest: pkg, Name: "p_test", Dir: dir, Module: module, GoFiles: []string{"ext_test.go"}}
	for _, copies := range [][]listPkg{{real, synthetic, real}, {synthetic, real, synthetic}} {
		h := &Hasher{lists: map[string][]listPkg{pkg: append([]listPkg{
			{ImportPath: pkg, Name: "p", Dir: dir, Module: module, GoFiles: []string{"p.go"}},
		}, copies...)}, testVariants: map[string]compartment.Identity{}}
		ledger, err := h.TestVariantLedger(pkg)
		if err != nil {
			t.Fatal(err)
		}
		if len(ledger.FileHeaders) != 1 || len(ledger.FileHeaders[0].Bindings.Imports) != 1 {
			t.Fatalf("missing external-test binding evidence: %+v", ledger)
		}
		if got := ledger.FileHeaders[0].Bindings.Imports[0]; got.Path != pkg+"_test" || got.Name != "" {
			t.Fatalf("conflicting declaration was resolved by listing order: %+v", got)
		}
		if testvariant.DiffTestVariantLedgers(ledger, ledger).Inert() {
			t.Fatal("conflicting import-name evidence authorized inertness")
		}
	}
}
