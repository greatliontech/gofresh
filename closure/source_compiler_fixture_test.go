package closure

import (
	"bytes"
	"sort"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/closure/internal/listing"
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
	roots, err := packages.Load(&packages.Config{
		Context: t.Context(), Mode: packages.LoadAllSyntax | packages.NeedModule,
		Dir: h.dir, Env: h.packageEnv, BuildFlags: h.buildFlags,
	}, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 1 || roots[0].PkgPath != path || roots[0].Name != "main" {
		t.Fatal("selected command root is absent or ambiguous")
	}
	var all []*packages.Package
	packages.Visit(roots, nil, func(p *packages.Package) {
		for _, err := range p.Errors {
			t.Error(err)
		}
		all = append(all, p)
	})
	if t.Failed() {
		t.FailNow()
	}
	// The two input inventories use the same selected environment and flags.
	// No source-audit registry is consulted to interpret compiler initialization.
	args := append([]string{"-json", "-deps"}, h.buildFlags...)
	args = append(args, path)
	out, err := h.runner.List(t.Context(), h.dir, h.env, args...)
	if err != nil {
		t.Fatal(err)
	}
	metas, err := listing.Parse(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	prog, _ := ssautil.AllPackages(roots, ssa.InstantiateGenerics)
	selected := prog.AllPackages()
	sort.Slice(selected, func(i, j int) bool { return selected[i].Pkg.Path() < selected[j].Pkg.Path() })
	for _, p := range selected {
		if err := t.Context().Err(); err != nil {
			t.Fatal(err)
		}
		p.Build()
	}
	main := prog.Package(roots[0].Types).Func("main")
	if main == nil || len(main.Blocks) == 0 {
		t.Fatal("selected main has no source body")
	}
	return computationSource{prog: &program{PkgPath: path, Prog: prog, Pkgs: all, Roots: map[string]*ssa.Function{"main": main}}, metas: metas}, main, h
}
