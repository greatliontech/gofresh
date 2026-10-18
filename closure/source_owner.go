package closure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/assemblycapture"
)

// selectedSourceOwner is established while loading the typed program. The
// parser's own byte inputs, exact package instances and original root request
// remain attached to it; a later filename inventory cannot create this owner.
type selectedSourceOwner struct {
	selection *assemblycapture.Selection
	prog      *program
	packages  map[*packages.Package]string
	roots     []*packages.Package
}

// loadSelectedSource is the source-owned constructor for current-action
// references. It retains command/test mode, ordered flags, full environment,
// original patterns and exact root instances without changing optimization or
// instrumentation. Ordinary source analyses can continue to use unowned inputs;
// those inputs cannot authorize assembly acquisition.
func loadSelectedSource(ctx context.Context, reader *gotool.EnvReader, flags []string, tests bool, patterns ...string) (computationSource, error) {
	if ctx == nil || reader == nil {
		return computationSource{}, fmt.Errorf("selected source: context or reader absent")
	}
	selection, err := assemblycapture.BeginSelection(ctx, reader.Runner, assemblycapture.Request{Dir: reader.Dir, Env: reader.Env, Flags: flags, Tests: tests, Roots: patterns})
	if err != nil {
		return computationSource{}, err
	}
	request := selection.Request()
	env, err := gotool.EnvForPackages(request.Env)
	if err != nil {
		return computationSource{}, err
	}
	var mu sync.Mutex
	parsed := map[string][]byte{}
	parseFile := func(fset *token.FileSet, name string, src []byte) (*ast.File, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if src == nil {
			var err error
			src, err = os.ReadFile(name)
			if err != nil {
				return nil, err
			}
		}
		src = slices.Clone(src)
		name = filepath.Clean(name)
		mu.Lock()
		prior, seen := parsed[name]
		if seen && !bytes.Equal(prior, src) {
			mu.Unlock()
			return nil, fmt.Errorf("selected source: parser input changed during load: %s", name)
		}
		parsed[name] = src
		mu.Unlock()
		return parser.ParseFile(fset, name, src, parser.ParseComments|parser.AllErrors)
	}
	roots, err := packages.Load(&packages.Config{Context: ctx, Mode: packages.LoadAllSyntax | packages.NeedModule | packages.NeedForTest, Tests: tests, Dir: request.Dir, Env: env, BuildFlags: selection.LoadFlags(), ParseFile: parseFile}, request.Roots...)
	if err != nil {
		return computationSource{}, err
	}
	owner := &selectedSourceOwner{selection: selection, packages: map[*packages.Package]string{}, roots: slices.Clone(roots)}
	var all []*packages.Package
	var loadErr error
	packages.Visit(roots, nil, func(p *packages.Package) {
		if len(p.Errors) != 0 && loadErr == nil {
			loadErr = fmt.Errorf("selected source: %s: %v", p.ID, p.Errors)
		}
		owner.packages[p] = p.ID
		all = append(all, p)
	})
	if loadErr != nil {
		return computationSource{}, loadErr
	}
	views := map[string]assemblycapture.Package{}
	for _, p := range selection.Packages() {
		views[p.ID] = p
	}
	seen := map[string]bool{}
	for _, p := range all {
		v, ok := views[p.ID]
		if !ok || seen[p.ID] || p.Types == nil || p.Name != v.Name || p.PkgPath != v.Path || p.ForTest != v.ForTest {
			return computationSource{}, fmt.Errorf("selected source: typed package instance disagrees with root selection: %s", p.ID)
		}
		seen[p.ID] = true
		if p.PkgPath == "unsafe" {
			continue
		}
		want := slices.Sorted(slices.Values(v.GoFiles))
		got := slices.Clone(p.CompiledGoFiles)
		for i := range got {
			got[i] = filepath.Clean(got[i])
		}
		slices.Sort(got)
		if !slices.Equal(want, got) || len(p.Syntax) != len(got) {
			return computationSource{}, fmt.Errorf("selected source: typed source membership differs: %s", p.ID)
		}
		for raw, id := range v.Imports {
			if p.Imports[raw] == nil || p.Imports[raw].ID != id {
				return computationSource{}, fmt.Errorf("selected source: typed import binding differs: %s -> %s", p.ID, raw)
			}
		}
		if len(v.Imports) != len(p.Imports) {
			return computationSource{}, fmt.Errorf("selected source: typed import inventory differs: %s", p.ID)
		}
	}
	// go list also retains implicitly linked build dependencies which the
	// typed source import graph need not visit. Those remain owned build inputs,
	// never fabricated packages.Package instances or typed source declarations.
	var rootIDs []string
	for _, p := range roots {
		rootIDs = append(rootIDs, p.ID)
	}
	if err = selection.Seal(ctx, parsed, rootIDs); err != nil {
		return computationSource{}, err
	}
	prog, _ := ssautil.AllPackages(roots, ssa.InstantiateGenerics)
	selected := prog.AllPackages()
	sort.Slice(selected, func(i, j int) bool { return selected[i].Pkg.Path() < selected[j].Pkg.Path() })
	for _, p := range selected {
		if err = ctx.Err(); err != nil {
			return computationSource{}, err
		}
		p.Build()
	}
	rootPath := ""
	if len(roots) > 0 {
		rootPath = roots[0].PkgPath
	}
	program := &program{PkgPath: rootPath, Prog: prog, Pkgs: all, Roots: map[string]*ssa.Function{}}
	for _, p := range roots {
		if s := prog.Package(p.Types); s != nil {
			for name, member := range s.Members {
				if fn, ok := member.(*ssa.Function); ok {
					program.Roots[name] = fn
				}
			}
		}
	}
	owner.prog = program
	// Use the already owned listing projection, not another unbracketed list.
	var metas []listPkg
	for _, v := range selection.Packages() {
		m := listPkg{ImportPath: v.ID, Name: v.Name, Dir: v.Dir, ForTest: v.ForTest, Standard: v.Standard}
		for _, path := range v.GoFiles {
			m.GoFiles = append(m.GoFiles, path)
		}
		for _, path := range v.Assembly {
			m.SFiles = append(m.SFiles, path)
		}
		for _, id := range v.Imports {
			m.Imports = append(m.Imports, id)
		}
		slices.Sort(m.Imports)
		m.EmbedFiles = slices.Clone(v.EmbedFiles)
		// Preserve every opaque category and module from the owned list. The
		// conversion only crosses the two existing listing representations.
		if data := selection.PackageJSON(v.ID); data != nil {
			if err = json.Unmarshal(data, &m); err != nil {
				return computationSource{}, err
			}
		}
		metas = append(metas, m)
	}
	return computationSource{prog: program, metas: metas, owner: owner}, nil
}

func (o *selectedSourceOwner) packageFor(fn *ssa.Function) (*packages.Package, error) {
	if o == nil || o.prog == nil || fn == nil || fn.Prog != o.prog.Prog || fn.Pkg == nil {
		return nil, fmt.Errorf("selected source: callable belongs to another owner")
	}
	for p := range o.packages {
		if p.Types == fn.Pkg.Pkg && o.prog.Prog.Package(p.Types) == fn.Pkg {
			return p, nil
		}
	}
	return nil, fmt.Errorf("selected source: callable package instance absent")
}

func (o *selectedSourceOwner) sourceFiles(p *packages.Package) map[string][]byte {
	if o == nil || o.selection == nil {
		return nil
	}
	id, ok := o.packages[p]
	if !ok {
		return nil
	}
	return o.selection.SourceFiles(id)
}
