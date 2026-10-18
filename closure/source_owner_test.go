package closure

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

func TestSelectedSourceOwnerParserAndInstances(t *testing.T) {
	if testing.Short() {
		t.Skip("typed source ownership load")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("fixture assembly is amd64")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":           "module example.com/owned\n\ngo 1.27.0\n",
		"main.go":          "package main\nimport \"example.com/owned/ops\"\nvar X uint64\nfunc main(){ops.Swap(&X,0,1)}\n",
		"ops/ops.go":       "package ops\nfunc Swap(p *uint64,old,next uint64) bool\n",
		"ops/directive.go": "package ops\nimport _ \"unsafe\"\n//go:linkname Swap\n",
		"ops/ops.s":        "#include \"textflag.h\"\nTEXT ·Swap(SB),NOSPLIT,$0-25\nMOVQ p+0(FP),BX\nMOVQ old+8(FP),AX\nMOVQ next+16(FP),CX\nLOCK\nCMPXCHGQ CX,(BX)\nSETEQ ret+24(FP)\nRET\n",
	})
	reader := gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ())
	source, err := loadSelectedSource(t.Context(), reader, nil, false, ".")
	if err != nil {
		t.Fatal(err)
	}
	if source.owner == nil || source.owner.prog != source.prog {
		t.Fatal("source owner was not attached during load")
	}
	var targetFound bool
	for _, pkg := range source.prog.Pkgs {
		if pkg.PkgPath != "example.com/owned/ops" {
			continue
		}
		target := source.prog.Prog.Package(pkg.Types).Func("Swap")
		provider, err := source.owner.packageFor(target)
		if err != nil {
			t.Fatal(err)
		}
		if provider != pkg {
			t.Fatal("provider instance was replaced")
		}
		files := source.owner.sourceFiles(provider)
		if string(files[filepath.Join(dir, "ops", "directive.go")]) != "package ops\nimport _ \"unsafe\"\n//go:linkname Swap\n" {
			t.Fatal("package-wide directive bytes absent")
		}
		files[filepath.Join(dir, "ops", "ops.go")][0] = 'X'
		if source.owner.sourceFiles(provider)[filepath.Join(dir, "ops", "ops.go")][0] == 'X' {
			t.Fatal("source projection aliases owner")
		}
		targetFound = true
	}
	if !targetFound {
		t.Fatal("typed target absent")
	}
	if _, err := source.owner.packageFor(nil); err == nil {
		t.Fatal("owner accepted absent target")
	}
	if err := os.WriteFile(filepath.Join(dir, "ops", "ops.go"), []byte("package ops\nfunc Swap(p *uint64,old,next uint64) bool\nconst Changed=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.owner.selection.Validate(t.Context()); err == nil {
		t.Fatal("typed-owner drift accepted")
	}
}
