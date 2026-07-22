package closure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
