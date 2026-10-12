package gofresh

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/gotool"
)

func TestSessionOwnsItsDescriptions(t *testing.T) {
	dir := t.TempDir()
	build := BuildDescription{Directory: dir, Environment: append(os.Environ(), "FRESH_BUILD_OWNED=original"), Flags: []string{"-tags=owned"}, Inputs: []string{"profile:original"}}
	runEnv := append(os.Environ(), "FRESH_RUNTIME_OWNED=original")
	pure := []Subject{{Package: "example.com/p", Symbol: "F"}}
	vouches := []string{"example.com/dep:State"}
	containment := &gotool.Containment{WaitDelay: time.Second}
	policy := SessionPolicy{PureSubjects: pure, Vouches: vouches, Runner: gotool.Runner{Containment: containment, Prepare: func(*exec.Cmd) {
		build.Environment[len(build.Environment)-1] = "FRESH_BUILD_OWNED=changed"
		runEnv[len(runEnv)-1] = "FRESH_RUNTIME_OWNED=changed"
		build.Flags[0], build.Inputs[0] = "-tags=changed", "profile:changed"
		pure[0].Symbol, vouches[0] = "G", "example.com/dep:Other"
		containment.WaitDelay = 5 * time.Second
	}}}
	s, err := NewSession(context.Background(), build, RuntimeDescription{Environment: runEnv}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := gotool.LookupEnv(s.build.Environment, "FRESH_BUILD_OWNED"); value != "original" {
		t.Fatalf("build env borrowed: %q", value)
	}
	if value, _ := gotool.LookupEnv(s.engine.evidenceEnv(), "FRESH_RUNTIME_OWNED"); value != "original" {
		t.Fatalf("runtime env borrowed: %q", value)
	}
	if !slices.Equal(s.build.Flags, []string{"-tags=owned"}) || !slices.Equal(s.build.Inputs, []string{"profile:original"}) {
		t.Fatalf("build description borrowed flags/inputs: %q %q", s.build.Flags, s.build.Inputs)
	}
	if !s.engine.assumePure(Subject{Package: "example.com/p", Symbol: "F"}) || s.engine.assumePure(pure[0]) {
		t.Fatal("purity set borrowed")
	}
	if !s.engine.dynamicStateVouches["example.com/dep.State"] || s.engine.dynamicStateVouches["example.com/dep.Other"] {
		t.Fatal("vouch set borrowed")
	}
	if s.engine.runner.Containment.WaitDelay != time.Second {
		t.Fatal("containment value borrowed")
	}
	projection := &Snapshot{session: s, view: &View{packages: []string{"example.com/p"}}}
	first, err := projection.BuildDescription("example.com/p")
	if err != nil {
		t.Fatal(err)
	}
	first.Environment[0], first.Flags[0], first.Inputs[0] = "CHANGED=1", "-tags=changed", "profile:changed"
	second, err := projection.BuildDescription("example.com/p")
	if err != nil {
		t.Fatal(err)
	}
	if second.Environment[0] == "CHANGED=1" || second.Flags[0] != "-tags=owned" || second.Inputs[0] != "profile:original" {
		t.Fatal("returned description aliases its session")
	}
}
