package runtimeinput

import (
	"os"
	"path/filepath"
	"testing"
)

// Reads provably inside a declared static-input root — a committed
// tree and the go.mod file — record neither identity nor disposition,
// while the identical log without the declaration records and seals as
// before (REQ-inputs-static-inputs).
func TestStaticInputRootsSkipPinnedReads(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.MkdirAll(filepath.Join(moduleDir, "cmd", "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	pinned := filepath.Join(moduleDir, "cmd", "tool", "main.go")
	if err := os.WriteFile(pinned, []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gomod := filepath.Join(moduleDir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := "open " + pinned + "\nstat " + pinned + "\nopen " + gomod + "\nstat " + gomod + "\n"

	st, err := FromTestLog([]byte(log), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "pkg")),
		WithStaticInputRoot("cmd"), WithStaticInputRoot("go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Unverifiable {
		t.Fatalf("static-covered reads sealed unverifiable: %s", st.Reason)
	}
	d, err := Describe(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 0 || len(d.Unverifiable) != 0 {
		t.Fatalf("static-covered reads recorded: %+v", d)
	}

	bare, err := FromTestLog([]byte(log), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "pkg")))
	if err != nil {
		t.Fatal(err)
	}
	bareState, err := CompletedState(bare)
	if err != nil {
		t.Fatal(err)
	}
	if !bareState.Unverifiable {
		t.Fatal("undeclared out-of-bracket reads did not seal unverifiable")
	}
}

// The static region's boundary is fail-closed exactly as the
// guard-covered class's: a missing object under the root, and a
// symlink chain escaping it, stay observed (REQ-inputs-static-inputs).
func TestStaticInputResolutionIsFailClosed(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	static := filepath.Join(moduleDir, "cmd")
	if err := os.MkdirAll(static, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "mutable.txt")
	if err := os.WriteFile(outside, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(static, "escape.txt")); err != nil {
		t.Fatal(err)
	}

	missing := "open " + filepath.Join(static, "gone.go") + "\n"
	st, err := FromTestLog([]byte(missing), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "pkg")),
		WithStaticInputRoot("cmd"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := Describe(st.Manifest, moduleDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Paths) != 1 || d.Paths[0] != filepath.Join(static, "gone.go") {
		t.Fatalf("missing object under static root not observed: %+v", d)
	}

	escape := "open " + filepath.Join(static, "escape.txt") + "\n"
	st, err = FromTestLog([]byte(escape), moduleDir, packageDir,
		WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "pkg")),
		WithStaticInputRoot("cmd"))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unverifiable {
		t.Fatal("escaping symlink under static root skipped observation")
	}
}

// Malformed static-root declarations are refused loudly: absolute
// paths, module escapes, and the module root itself — a whole-module
// static declaration is the attach-no-manifest assertion in disguise
// (REQ-inputs-static-inputs).
func TestStaticInputRootRejectsMalformedDeclarations(t *testing.T) {
	for _, root := range []string{"", "/abs", "..", "../up", "."} {
		var cfg testLogConfig
		WithStaticInputRoot(root)(&cfg)
		if cfg.err == nil {
			t.Errorf("static root %q accepted", root)
		}
	}
}

// A static root must resolve strictly inside the module tree, loudly:
// a committed symlink to the module root would vacate everything (the
// attach-no-manifest assertion in disguise), an external target's
// content is unpinnable by any committed record (git records the link
// string), and an unresolvable root is a typo'd repo surface — all
// refuse at ingest rather than declaring nothing or everything
// (REQ-inputs-static-inputs).
func TestStaticInputRootRefusesUnsoundResolutions(t *testing.T) {
	moduleDir, packageDir := testDirs(t)
	if err := os.Symlink(".", filepath.Join(moduleDir, "self")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(moduleDir, "vendor-ext")); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"self", "vendor-ext", "no-such-surface"} {
		_, err := FromTestLog([]byte("# test log\n"), moduleDir, packageDir,
			WithCompletedProcess("worker"), WithBracket(testBracket(t, moduleDir, "pkg")),
			WithStaticInputRoot(root))
		if err == nil {
			t.Errorf("static root %q accepted", root)
		}
	}
}
