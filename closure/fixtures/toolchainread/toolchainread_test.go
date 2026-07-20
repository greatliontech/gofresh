package toolchainread

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAccessorAlone(*testing.T) {
	_ = runtime.GOROOT()
}

func TestReadVersion(*testing.T) {
	_, _ = os.ReadFile(filepath.Join(runtime.GOROOT(), "VERSION"))
}

func TestOpenUnderToolchain(*testing.T) {
	file, _ := os.Open(filepath.Join(runtime.GOROOT(), "VERSION"))
	if file != nil {
		_ = file.Close()
	}
}

func TestReadDirUnderToolchain(*testing.T) {
	entries, _ := os.ReadDir(filepath.Join(runtime.GOROOT(), "src"))
	for _, entry := range entries {
		_ = entry.Name()
		_ = entry.IsDir()
		_ = entry.Type()
	}
}

func TestWriteIntoToolchain(*testing.T) {
	_ = os.WriteFile(filepath.Join(runtime.GOROOT(), "scratch.txt"), []byte("x"), 0o644)
}

func TestDynamicComponent(*testing.T) {
	name := os.Getenv("GOFRESH_COMPONENT")
	_, _ = os.ReadFile(filepath.Join(runtime.GOROOT(), name))
}
