package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPurityScanUsesSuppliedEnvironment(t *testing.T) {
	dir := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/envpurity\n\ngo 1.26.4\n")
	write("default.go", "//go:build !special\n\npackage envpurity\n\nfunc F() {}\n")
	write("special.go", "//go:build special\n\npackage envpurity\n\n//gofresh:pure\nfunc F() {}\n")
	env := environmentWith(map[string]string{"GOFLAGS": "-tags=special", "GOWORK": "off"})
	pure, known, _, _, err := scanSubjectsInWithBuildFlagsEnv(context.Background(), dir, env, nil, "example.com/envpurity")
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/envpurity", Symbol: "F"}
	if !known[subject] || !pure(subject) {
		t.Fatalf("supplied GOFLAGS did not select pure declaration: known=%v pure=%v", known[subject], pure(subject))
	}
}
