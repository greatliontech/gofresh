package gofresh

import (
	"os"
	"runtime"
	"testing"
)

func TestRuntimeBindingRefusesDelimiterCollision(t *testing.T) {
	if testing.Short() {
		t.Skip("observes source and measurement guard generations")
	}
	if runtime.GOOS != "linux" {
		t.Skip("measurement support requires Linux")
	}
	dir := writeViewModule(t, "package view\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	first := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: []string{"GOGC=200\nGODEBUG=x", "GODEBUG=y"}})
	second := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: []string{"GOGC=200", "GODEBUG=x\nGODEBUG=y"}})
	recorded, err := first.CurrentFacts(t.Context(), subject)
	if err != nil {
		t.Fatal(err)
	}
	current, err := second.CurrentFacts(t.Context(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if recorded.Guards.BuildConfig != current.Guards.BuildConfig || recorded.Guards.Machine != current.Guards.Machine {
		t.Fatal("runtime-only control changed compilation or machine identity")
	}
	if verdict, err := first.Check(t.Context(), subject, recorded); err != nil || verdict.Status != Valid {
		t.Fatalf("same runtime configuration did not pass: %+v %v", verdict, err)
	}
	if verdict, err := second.Check(t.Context(), subject, recorded); err != nil || verdict.Status != Stale || verdict.Reason != "runtimeconfig" {
		t.Fatalf("distinct runtime configuration was not refused: %+v %v", verdict, err)
	}
}
