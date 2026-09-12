package gotool

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testEnv is the ambient environment with the named keys replaced —
// the policy refuses a duplicate, so a test never appends blindly.
func testEnv(t *testing.T, pins ...string) []string {
	t.Helper()
	env := make([]string, 0, len(os.Environ())+len(pins))
	for _, entry := range os.Environ() {
		keep := true
		key, _, _ := split(entry)
		for _, pin := range pins {
			if pinKey, _, _ := split(pin); EqualEnvKey(key, pinKey) {
				keep = false
			}
		}
		if keep {
			env = append(env, entry)
		}
	}
	return append(env, pins...)
}

// The toolchain sample runs in the target module's directory under the
// caller's environment: the version it answers is the one the go
// command selects THERE (REQ-fresh-toolchain-skew).
func TestSampleGoVersionRunsInTheModuleDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/sample\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := testEnv(t, "GOTOOLCHAIN=local", "GOFLAGS=")
	var seen string
	r := Runner{Prepare: func(cmd *exec.Cmd) { seen = cmd.Dir }}
	got, err := r.SampleGoVersion(context.Background(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if seen != dir {
		t.Fatalf("the sample ran in %q, want the module directory %q", seen, dir)
	}
	if !strings.HasPrefix(got, "go") || strings.ContainsAny(got, " \n") {
		t.Fatalf("sample = %q, want one go version token", got)
	}
	// The reference is an independent spawn in the same directory under
	// the policy's environment for it: the sample is that answer, trimmed.
	ref := exec.Command("go", "env", "GOVERSION")
	refEnv, err := EnvForCommand(env, dir)
	if err != nil {
		t.Fatal(err)
	}
	ref.Dir, ref.Env = dir, refEnv
	want, err := ref.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.TrimSpace(string(want)) {
		t.Fatalf("sample = %q, want the directory's own answer %q", got, strings.TrimSpace(string(want)))
	}
}

// The runner's spawn policy sees the command before it starts, with
// its directory and the policy's environment already set: a hook that
// edits cmd.Env edits the environment the child runs under.
func TestRunnerPrepareSeesTheCommandBeforeItStarts(t *testing.T) {
	dir := t.TempDir()
	var prepared *exec.Cmd
	var preparedDir string
	var preparedEnv []string
	r := Runner{Prepare: func(cmd *exec.Cmd) {
		if cmd.Process != nil {
			t.Fatal("the hook saw a started command")
		}
		prepared, preparedDir, preparedEnv = cmd, cmd.Dir, slices.Clone(cmd.Env)
	}}
	if _, err := r.Run(context.Background(), dir, testEnv(t, "GOFLAGS="), "env", "GOOS"); err != nil {
		t.Fatal(err)
	}
	if prepared == nil || len(prepared.Args) < 2 || prepared.Args[1] != "env" {
		t.Fatalf("the hook did not see the go command: %v", prepared)
	}
	if preparedDir != dir {
		t.Fatalf("the hook saw Dir %q, want %q already set", preparedDir, dir)
	}
	if pwd, ok := LookupEnv(preparedEnv, "PWD"); !ok || pwd != dir {
		t.Fatalf("the hook saw PWD %q (present %v) in %d entries, want the policy's %q already set", pwd, ok, len(preparedEnv), dir)
	}
}

// The canonical directory follows symlinks and applies `..` after the
// link it followed: the raw spelling is never cleaned first, which
// would fold `via/..` onto the link's own parent.
func TestCanonicalDirWalksThroughALinkBeforeDotDot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	got, err := CanonicalDir(link)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("CanonicalDir(link) = %q, want the real directory %q", got, want)
	}
	// `link/..` walks THROUGH the link to the target's parent; a lexical
	// clean would fold it onto the link's own parent. The raw string is
	// built by concatenation — filepath.Join would clean it first.
	nested := filepath.Join(root, "elsewhere", "target")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	through := filepath.Join(root, "via")
	if err := os.Symlink(nested, through); err != nil {
		t.Fatal(err)
	}
	got, err = CanonicalDir(through + string(os.PathSeparator) + "..")
	if err != nil {
		t.Fatal(err)
	}
	wantParent, err := filepath.EvalSymlinks(filepath.Join(root, "elsewhere"))
	if err != nil {
		t.Fatal(err)
	}
	if got != wantParent {
		t.Fatalf("CanonicalDir(via/..) = %q, want the target's parent %q (a lexical clean answers %q)", got, wantParent, filepath.Clean(through+"/.."))
	}
	// The relative form walks the same way from the working directory.
	t.Chdir(root)
	if got, err := CanonicalDir("via" + string(os.PathSeparator) + ".."); err != nil || got != wantParent {
		t.Fatalf("relative CanonicalDir(via/..) = %q, %v; want %q", got, err, wantParent)
	}
}
