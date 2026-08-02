package closure

import (
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// The audited-pure widening: subjects reaching pure standard
// computation prove observable, while the two soundness exclusions -
// flag registration (covert Parse-time channel) and reflect (defeats
// reachability) - stay blocked
// (REQ-closure-observability-analysis's audited-set boundary).
func TestAuditedPureWideningAndExclusions(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"pure", "flagged", "mirrored"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, dir, "go.mod", "module example.com/audited\n\ngo 1.26\n")
	writeFile(t, dir, "pure/pure.go", `package pure

import (
	"bufio"
	"fmt"
	"strings"
)

func Formats(x float64) string {
	r := bufio.NewReader(strings.NewReader(fmt.Sprintf("%.2f", x)))
	line, _ := r.ReadString('\n')
	return line
}
`)
	writeFile(t, dir, "pure/pure_test.go", `package pure

import "testing"

func TestFormats(t *testing.T) {
	if Formats(4) == "" {
		t.Fatal("formats")
	}
}
`)
	writeFile(t, dir, "mirrored/mirrored.go", `package mirrored

import "reflect"

func Reflected(v any) string { return reflect.TypeOf(v).Name() }
`)
	writeFile(t, dir, "mirrored/mirrored_test.go", `package mirrored

import "testing"

func TestReflected(t *testing.T) {
	_ = Reflected(1)
}
`)
	writeFile(t, dir, "flagged/flagged.go", `package flagged

import "flag"

var verbose = flag.Bool("audited-verbose", false, "covert channel")

func Registered() bool { return *verbose }
`)
	writeFile(t, dir, "flagged/flagged_test.go", `package flagged

import "testing"

func TestRegistered(t *testing.T) {
	_ = Registered()
}
`)
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch([]Subject{
		{Package: "example.com/audited/pure", Symbol: "Formats"},
		{Package: "example.com/audited/mirrored", Symbol: "Reflected"},
		{Package: "example.com/audited/flagged", Symbol: "Registered"},
	})
	if err != nil {
		t.Fatal(err)
	}
	formats := proofs[Subject{Package: "example.com/audited/pure", Symbol: "Formats"}]
	if !formats.Observable {
		t.Fatalf("pure fmt/bufio subject unobservable: %+v", formats)
	}
	registered := proofs[Subject{Package: "example.com/audited/flagged", Symbol: "Registered"}]
	if registered.Observable || !strings.Contains(registered.Reason, "flag") {
		t.Fatalf("flag-registration subject = %+v, want blocked on the covert channel", registered)
	}
	reflected := proofs[Subject{Package: "example.com/audited/mirrored", Symbol: "Reflected"}]
	if reflected.Observable || (!strings.Contains(reflected.Reason, "reflect") && !strings.Contains(reflected.Reason, "reachability")) {
		t.Fatalf("reflect subject = %+v, want blocked on reachability", reflected)
	}
}

// The harness failure/logging channel is exactly the output-only method
// list; the harness's ambient-input and mutation surfaces and its
// structural operations stay outside it
// (REQ-closure-observability-analysis's audited-set boundary).
func TestAuditedHarnessLoggingBounds(t *testing.T) {
	for _, name := range []string{"Fatal", "Fatalf", "Error", "Errorf", "Log", "Logf", "Skip", "Skipf", "SkipNow", "Fail", "FailNow"} {
		if !auditedHarnessLogging("testing", name) {
			t.Errorf("auditedHarnessLogging(testing, %s) = false, want audited", name)
		}
	}
	for _, name := range []string{"Setenv", "Chdir", "TempDir", "Run", "Cleanup", "Helper", "Short", "Deadline", "Context", "Parallel", "Name", "Failed", "Skipped"} {
		if auditedHarnessLogging("testing", name) {
			t.Errorf("auditedHarnessLogging(testing, %s) = true, want outside the audited set", name)
		}
	}
	if auditedHarnessLogging("os", "Fatal") || auditedHarnessLogging("log", "Fatal") {
		t.Error("auditedHarnessLogging admits a non-testing package")
	}
}

// A subject whose only reachable effect is the audited harness channel
// earns the observation proof yet stays unverifiable in the legacy
// projection: the admission is observation evidence, never purity
// evidence.
func TestHarnessLoggingIsNotPurityEvidence(t *testing.T) {
	h, err := New()
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/closure/fixtures/harnesslog"
	result, err := computeTier2Result(h, pkg, "TestLogOnly")
	if err != nil {
		t.Fatal(err)
	}
	if !result.unverifiable {
		t.Fatal("harness-logging-only subject reports verifiable in the legacy projection")
	}
	if !strings.Contains(result.reason, "test harness logging") {
		t.Fatalf("legacy reason = %q, want the harness-logging classification", result.reason)
	}
	found := false
	for _, effect := range result.effects {
		if effect.packagePath == "testing" && effect.symbol == "Log" {
			found = true
			if !effect.observable {
				t.Fatal("audited harness fact recorded as blocking")
			}
		}
	}
	if !found {
		t.Fatalf("effects = %+v, want the recorded testing.Log harness fact", result.effects)
	}
	// A subject mixing the harness channel with a causal effect must keep
	// the causal reason in the legacy projection: the harness fact ranks
	// below every other classification.
	mixed, err := computeTier2Result(h, pkg, "TestReadFileFatal")
	if err != nil {
		t.Fatal(err)
	}
	if !mixed.unverifiable || !strings.Contains(mixed.reason, "file I/O") {
		t.Fatalf("mixed-effect legacy reason = %q, want the file I/O cause over harness logging", mixed.reason)
	}
	// A weakest-rank sibling (the ambient clock's unaudited-standard read)
	// must also win: the harness fact is strictly weakest, never a tie it
	// can take lexicographically.
	sibling, err := computeTier2Result(h, "github.com/greatliontech/gofresh/closure/fixtures/harnessclock", "TestLogAmbientClock")
	if err != nil {
		t.Fatal(err)
	}
	if !sibling.unverifiable || !strings.Contains(sibling.reason, "unaudited standard operation") {
		t.Fatalf("rank-sibling legacy reason = %q, want the unaudited-standard cause over harness logging", sibling.reason)
	}
}

// The harness-channel admission is sound only while every testing-package
// declaration of an audited name is the harness's shared embedded core or
// an outcome-only delegate to it. This walks the toolchain's actual
// declarations, so a drifting toolchain fails here instead of silently
// widening the admission (REQ-closure-observability-analysis).
func TestHarnessLoggingDeclarationInventory(t *testing.T) {
	// Source mode is load-bearing: export data materializes only the
	// exported surface, and the admission must refuse an audited-name
	// method on an unexported body-local type too.
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo
	pkgs, err := packages.Load(&packages.Config{Mode: mode}, "testing")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 1 || pkgs[0].Types == nil {
		t.Fatalf("loaded %d packages for testing, want one with types", len(pkgs))
	}
	if len(pkgs[0].Syntax) == 0 {
		t.Fatal("testing loaded without syntax — the inventory no longer type-checks from source and cannot see unexported declarations")
	}
	audited := map[string]bool{}
	for _, name := range []string{"Fatal", "Fatalf", "Error", "Errorf", "Log", "Logf", "Skip", "Skipf", "SkipNow", "Fail", "FailNow"} {
		audited[name] = true
	}
	scope := pkgs[0].Types.Scope()
	for _, typeName := range scope.Names() {
		object := scope.Lookup(typeName)
		if _, isFunc := object.(*types.Func); isFunc && audited[object.Name()] {
			// The classifier matches by package and symbol name alone, so a
			// package-level function declaration would be admitted too.
			t.Errorf("testing declares audited harness name %s as a package-level function — re-audit the harness-logging channel before trusting this toolchain", object.Name())
			continue
		}
		named, ok := object.Type().(*types.Named)
		if !ok {
			continue
		}
		for i := 0; i < named.NumMethods(); i++ {
			method := named.Method(i)
			if !audited[method.Name()] || typeName == "common" {
				continue
			}
			if typeName == "F" && method.Name() == "Fail" {
				// Audited by hand: an outcome-only misuse panic delegating
				// to the shared core (the spec's recorded exception).
				continue
			}
			t.Errorf("testing.%s declares audited harness name %s outside the shared core — re-audit the harness-logging channel before trusting this toolchain", typeName, method.Name())
		}
	}
	if scope.Lookup("common") == nil {
		t.Error("testing package no longer declares the shared embedded core type this audit assumes — re-audit the harness-logging channel")
	}
}
