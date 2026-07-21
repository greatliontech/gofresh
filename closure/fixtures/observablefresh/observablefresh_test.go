package observablefresh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTempDirWriteReadCleanup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture")
	if err := os.WriteFile(path, []byte("guarded"), 0o600); err != nil {
		return
	}
	_, _ = os.ReadFile(path)
	_ = os.Remove(path)
	_ = os.RemoveAll(dir)
}

func TestTempDirOpenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture")
	if err := os.WriteFile(path, []byte("guarded"), 0o600); err != nil {
		return
	}
	file, _ := os.OpenFile(path, os.O_TRUNC|os.O_WRONLY, 0o600)
	if file != nil {
		_ = file.Close()
	}
	_ = os.RemoveAll(dir)
}

var executeDestructiveFixture bool

func TestRemoveOrdinary(*testing.T) {
	if executeDestructiveFixture {
		_ = os.Remove("fixture")
	}
}

func TestOpenFileMutatesOrdinary(*testing.T) {
	if executeDestructiveFixture {
		file, _ := os.OpenFile("fixture", os.O_TRUNC|os.O_WRONLY, 0o600)
		if file != nil {
			_ = file.Close()
		}
	}
}

func TestRemoveNeverCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	if err := os.Remove(path); err == nil {
		t.Fatal("removed a path that was never created")
	}
}

func TestOpenFileMutatesNeverCreated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	file, _ := os.OpenFile(path, os.O_TRUNC|os.O_WRONLY, 0o600)
	if file != nil {
		_ = file.Close()
	}
}

func TestOpenFileUnknownFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("guarded"), 0o600); err != nil {
		return
	}
	file, _ := os.OpenFile(path, 0x10000, 0o600)
	if file != nil {
		_ = file.Close()
	}
}

func TestOpenFreshDirectoryRead(t *testing.T) {
	file, _ := os.OpenFile(t.TempDir(), 0, 0)
	if file != nil {
		buffer := make([]byte, 1)
		_, _ = file.Read(buffer)
		_ = file.Close()
	}
}

func TestWriteFileUncheckedBeforeRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	_ = os.WriteFile(path, []byte("guarded"), 0o600)
	_, _ = os.ReadFile(path)
}

func TestWriteFileMutationBeforeRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		return
	}
	_ = os.WriteFile(path, []byte("second"), 0o600)
	_, _ = os.ReadFile(path)
}

func TestWriteFileMutationAcrossLoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		return
	}
	for range 2 {
		_, _ = os.ReadFile(path)
		_ = os.WriteFile(path, []byte("second"), 0o600)
	}
}

type pathAlias string

func TestWriteFileMutationThroughAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		return
	}
	alias := pathAlias(path)
	_ = os.WriteFile(string(alias), []byte("second"), 0o600)
	_, _ = os.ReadFile(path)
}

func TestWriteFileMutationThroughDuplicateJoin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		return
	}
	alias := filepath.Join(dir, "fixture")
	_ = os.WriteFile(alias, []byte("second"), 0o600)
	_, _ = os.ReadFile(path)
}

func TestAncestorCleanupBeforeRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		return
	}
	_ = os.RemoveAll(dir)
	_, _ = os.ReadFile(path)
}

func TestJoinParentTraversal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "..")
	_, _ = os.ReadFile(path)
}

func TestReservedDevicePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "NUL")
	_, _ = os.ReadFile(path)
}

func TestPathConcatenation(t *testing.T) {
	dir := t.TempDir()
	_, _ = os.ReadFile(dir + "/fixture")
}

func TestGeneratedPathComparison(t *testing.T) {
	dir := t.TempDir()
	if dir == "" {
		t.Fatal("empty temporary directory")
	}
}

func readHelper(path string) {
	_, _ = os.ReadFile(path)
}

func TestFreshPathHelperEscape(t *testing.T) {
	readHelper(filepath.Join(t.TempDir(), "fixture"))
}

func consumePath(string) {}

func TestFreshPathNoopEscape(t *testing.T) {
	consumePath(t.TempDir())
}

var escapedPath string

var fileOpened bool

func TestFreshFileProbeEscape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	file, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	fileOpened = file != nil
	if file != nil {
		_ = file.Close()
	}
}

func TestFreshFileNameEscape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	file, _ := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if file != nil && file.Name() == "" {
		t.Fatal("empty file name")
	}
}

func TestFreshPathGlobalEscape(t *testing.T) {
	escapedPath = t.TempDir()
}

// The boundary extension: a helper receiving a fresh capability at
// every call site, using it only inside the recognized operation graph.
func writeReadCleanupHelper(dir string) {
	target := filepath.Join(dir, "helper.txt")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		return
	}
	_, _ = os.ReadFile(target)
	_ = os.Remove(target)
}

func TestFreshPathHelperFullDiscipline(t *testing.T) {
	writeReadCleanupHelper(t.TempDir())
}

// The helper called twice within ONE subject, once with a non-fresh
// argument: every attributed call site must pass fresh, so the whole
// subject refuses. (A non-fresh call site in a DIFFERENT subject is
// invisible here: attribution is per subject, and only this subject's
// sites execute in its solo run.)
func mixedHelper(dir string) {
	target := filepath.Join(dir, "mixed.txt")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		return
	}
}

func TestFreshPathHelperMixedCallers(t *testing.T) {
	mixedHelper(t.TempDir())
	mixedHelper("/tmp/fixture-ordinary")
}

// Recursion refuses fail-closed: the capability's freshness would
// depend on itself.
func recursiveHelper(dir string, depth int) {
	if depth == 0 {
		return
	}
	target := filepath.Join(dir, "r.txt")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		return
	}
	recursiveHelper(dir, depth-1)
}

func TestFreshPathHelperRecursive(t *testing.T) {
	recursiveHelper(t.TempDir(), 2)
}

// A goroutine crossing refuses: concurrent consumption is outside the
// recognized operation graph.
func TestFreshPathHelperGoroutine(t *testing.T) {
	dir := t.TempDir()
	done := make(chan struct{})
	go func() {
		writeReadCleanupHelper(dir)
		close(done)
	}()
	<-done
}

// A helper leaking the capability outside the graph refuses even with
// fresh arguments at every site.
func leakHelper(dir string) {
	escapedPath = dir
}

func TestFreshPathHelperLeak(t *testing.T) {
	leakHelper(t.TempDir())
}

// A direct go-statement call site refuses: concurrent consumption of
// the capability is outside the graph even with a fresh argument.
func TestFreshPathHelperDirectGo(t *testing.T) {
	dir := t.TempDir()
	go writeReadCleanupHelper(dir)
}

// A call site inside a loop refuses: multiplicity is outside the
// recognized operation graph's ordering discipline.
func TestFreshPathHelperInLoop(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		writeReadCleanupHelper(dir)
	}
}

// A closure callee refuses even with a disciplined body: free-variable
// state is outside what the boundary analysis audits, so closures stay
// out fail-closed.
func TestFreshPathHelperClosureCallee(t *testing.T) {
	sink := 0
	helper := func(dir string) {
		target := filepath.Join(dir, "c.txt")
		if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
			sink++
			return
		}
		_ = os.Remove(target)
	}
	helper(t.TempDir())
	_ = sink
}
