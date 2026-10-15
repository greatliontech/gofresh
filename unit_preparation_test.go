package gofresh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/runtimeinput"
)

func TestUnitRefusesScratchDeclarationsBeforePreparation(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs a subject snapshot")
	}
	dir := t.TempDir()
	for name, text := range map[string]string{
		"go.mod": "module example.com/prepare\n\ngo 1.27.0\n",
		"p.go":   "package p\nfunc F() int { return 1 }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/prepare", Symbol: "F"}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	execution := bindTestRuntime(t, snapshot, RuntimeDescription{})
	bound, err := snapshot.BindBuilt(subject.Package, "executor-declared-artifact")
	if err != nil {
		t.Fatal(err)
	}
	for _, ns := range []runtimeinput.ScratchNamespace{{Dir: ".", Pattern: "bad/name"}, {Dir: "..", Pattern: "scratch-*"}, {Dir: "", Pattern: "scratch-*"}, {Dir: ".", Pattern: ""}} {
		t.Run(ns.Dir+":"+ns.Pattern, func(t *testing.T) {
			u, err := execution.Begin(subject)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Abort()
			_, err = u.Register(t.Context(), bound, ProcessDescription{Identity: "worker", ScratchNamespaces: []runtimeinput.ScratchNamespace{{Dir: ".", Pattern: "valid-*"}, ns}})
			if err == nil || !strings.Contains(err.Error(), "scratch namespace") {
				t.Fatalf("declaration admitted: %v", err)
			}
			if u.producing.execution != nil || u.producing.phase != unitOpen {
				t.Fatal("invalid declaration reached producing preparation")
			}
			if _, err := u.Register(t.Context(), bound, ProcessDescription{Identity: "worker", ScratchNamespaces: []runtimeinput.ScratchNamespace{{Dir: ".", Pattern: "valid-*"}}}); err != nil {
				t.Fatalf("valid declaration after input refusal: %v", err)
			}
		})
	}
}
