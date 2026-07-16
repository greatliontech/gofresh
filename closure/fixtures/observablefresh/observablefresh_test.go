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
