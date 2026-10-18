package closure

import (
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

// loadCompilerStartupFixture loads the selected compiler as an ordinary command,
// not its test binary. The command name locates the source; it grants no startup,
// lowering, or executable-correspondence authority.
func loadCompilerStartupFixture(t *testing.T) (computationSource, *ssa.Function) {
	t.Helper()
	const path = "cmd/compile"
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/compilerstartup\n\ngo 1.27\n"})
	source, main, _ := loadSourceCommandFixture(t, dir, path)
	return source, main
}

func loadSourceCommandFixture(t *testing.T, dir, path string) (computationSource, *ssa.Function, *Hasher) {
	t.Helper()
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	source, err := loadSelectedSource(t.Context(), h.PassReader(), h.buildFlags, false, path)
	if err != nil {
		t.Fatal(err)
	}
	roots := source.owner.roots
	if len(roots) != 1 || roots[0].PkgPath != path || roots[0].Name != "main" {
		t.Fatal("selected command root is absent or ambiguous")
	}
	main := source.prog.Prog.Package(roots[0].Types).Func("main")
	if main == nil || len(main.Blocks) == 0 {
		t.Fatal("selected main has no source body")
	}
	return source, main, h
}
