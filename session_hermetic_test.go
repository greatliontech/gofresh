//go:build unix

package gofresh

import (
	"context"
	"github.com/greatliontech/gofresh/gotool"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// The directory is resolved by the filesystem after rebasing: via/.. names
// the link target's parent, not the build directory. The expected directory is
// independently constructed, never obtained from the resolver under test.
func TestSessionRuntimeDirectoryPreservesSymlinkParents(t *testing.T) {
	build, destination := t.TempDir(), t.TempDir()
	destination, err := filepath.EvalSymlinks(destination)
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(destination, "child")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(child, filepath.Join(build, "via")); err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(t.Context(), BuildDescription{Directory: build, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{Runner: hermeticEnvRunner()})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &Snapshot{session: session, kind: CodeResult}
	binding := bindTestRuntime(t, snapshot, RuntimeDescription{Directory: "via/.."})
	if binding.runtime.dir != destination {
		t.Fatalf("runtime directory = %q, want filesystem parent %q", binding.runtime.dir, destination)
	}
	if pwd, _ := gotool.LookupEnv(binding.runtime.env, "PWD"); pwd != destination {
		t.Fatalf("runtime PWD = %q, want %q", pwd, destination)
	}
}

func TestSessionOwnsItsDescriptions(t *testing.T) {
	dir := t.TempDir()
	build := BuildDescription{Directory: dir, Environment: append(os.Environ(), "FRESH_BUILD_OWNED=original"), Flags: []string{"-tags=owned"}, Inputs: []string{"profile:original"}}
	pure := []Subject{{Package: "example.com/p", Symbol: "F"}}
	vouches := []string{"example.com/dep.State"}
	containment := &gotool.Containment{WaitDelay: time.Second}
	policy := SessionPolicy{PureSubjects: pure, Vouches: vouches, Runner: gotool.Runner{Containment: containment, Prepare: func(cmd *exec.Cmd) {
		build.Environment[len(build.Environment)-1] = "FRESH_BUILD_OWNED=changed"
		build.Flags[0], build.Inputs[0] = "-tags=changed", "profile:changed"
		pure[0].Symbol, vouches[0] = "G", "example.com/dep.Other"
		containment.WaitDelay = 5 * time.Second
		if len(cmd.Args) >= 3 && cmd.Args[1] == "env" && cmd.Args[2] == "-json" {
			if sh, err := exec.LookPath("sh"); err == nil {
				cmd.Path = sh
				cmd.Args = []string{"sh", "-c", `printf '{"GOFLAGS":""}'`}
			}
		}
	}}}
	s, err := NewSession(context.Background(), build, policy)
	if err != nil {
		t.Fatal(err)
	}
	if value, _ := gotool.LookupEnv(s.build.Environment, "FRESH_BUILD_OWNED"); value != "original" {
		t.Fatalf("build env borrowed: %q", value)
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
	projection := &Snapshot{session: s, kind: CodeResult, packages: []string{"example.com/p"}}
	runEnv := append(os.Environ(), "FRESH_RUNTIME_OWNED=original")
	binding := bindTestRuntime(t, projection, RuntimeDescription{Environment: runEnv})
	runEnv[len(runEnv)-1] = "FRESH_RUNTIME_OWNED=changed"
	if value, _ := gotool.LookupEnv(binding.runtime.env, "FRESH_RUNTIME_OWNED"); value != "original" {
		t.Fatalf("runtime env borrowed: %q", value)
	}
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
