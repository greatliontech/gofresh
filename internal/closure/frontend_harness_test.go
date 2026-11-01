package closure

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	progpkg "github.com/greatliontech/gofresh/internal/closure/internal/program"
	"github.com/greatliontech/gofresh/internal/testenv"
)

func parseAndTypecheckDAG(t testing.TB, virtualDir string, filesByPkg map[string]map[string]string) []*packages.Package {
	t.Helper()
	return testenv.ParseAndTypecheckDAG(t, virtualDir, filesByPkg)
}

var cachedUnixListPkgOnce = sync.OnceValue(func() *listPkg {
	uPkg, err := testenv.CachedStdlibPackageErr(os.Environ(), "golang.org/x/sys/unix")
	if err != nil || uPkg == nil || len(uPkg.GoFiles) == 0 {
		return nil
	}
	dir := filepath.Dir(uPkg.GoFiles[0])
	var goFiles, sFiles []string
	for _, f := range uPkg.GoFiles {
		goFiles = append(goFiles, filepath.Base(f))
	}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".s") {
				sFiles = append(sFiles, e.Name())
			}
		}
	}
	modDir := filepath.Dir(dir)
	var modVersion string
	if _, after, ok := strings.Cut(filepath.Base(modDir), "@"); ok {
		modVersion = after
	}
	return &listPkg{
		ImportPath: "golang.org/x/sys/unix",
		Name:       "unix",
		Dir:        dir,
		GoFiles:    goFiles,
		SFiles:     sFiles,
		Module: &listMod{
			Path:    "golang.org/x/sys",
			Version: modVersion,
			Dir:     modDir,
			Main:    false,
		},
	}
})

func buildInMemorySSAFromFiles(ctx context.Context, virtualDir, pkgMain string, filesByPkg map[string]map[string]string) (*progpkg.Program, []listPkg, []*packages.Package, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	pkgs, resolvedDir, err := testenv.ParseAndTypecheckDAGWithStdlibErr(os.Environ(), virtualDir, filesByPkg)
	if err != nil {
		return nil, nil, nil, err
	}
	prog, err := progpkg.FromPackages(ctx, pkgMain, pkgs)
	if err != nil {
		return nil, nil, nil, err
	}

	mod := &listMod{
		Path: "example.com",
		Dir:  resolvedDir,
		Main: true,
	}
	var metas []listPkg
	reachesUnix := false
	for _, p := range prog.Pkgs {
		if p.PkgPath == "golang.org/x/sys/unix" {
			reachesUnix = true
		}
	}

	byPkgPath := make(map[string]*packages.Package, len(pkgs))
	for _, p := range pkgs {
		byPkgPath[p.PkgPath] = p
	}

	for _, p := range pkgs {
		basePath := strings.TrimSuffix(p.PkgPath, "_test")
		pkgDir := filepath.Join(resolvedDir, filepath.FromSlash(basePath))
		var imps []string
		for imp := range p.Imports {
			imps = append(imps, imp)
		}
		slices.Sort(imps)

		var allGo, baseGo, testOnlyGo, sFiles, sysoFiles []string
		for _, full := range p.CompiledGoFiles {
			base := filepath.Base(full)
			allGo = append(allGo, base)
			if strings.HasSuffix(base, "_test.go") {
				testOnlyGo = append(testOnlyGo, base)
			} else {
				baseGo = append(baseGo, base)
			}
		}
		if rawFiles, ok := filesByPkg[p.PkgPath]; ok {
			for name := range rawFiles {
				switch {
				case strings.HasSuffix(name, ".s"):
					sFiles = append(sFiles, name)
				case strings.HasSuffix(name, ".syso"):
					sysoFiles = append(sysoFiles, name)
				}
			}
			slices.Sort(sFiles)
			slices.Sort(sysoFiles)
		}

		if strings.HasSuffix(p.PkgPath, "_test") {
			if _, hasPrimary := byPkgPath[basePath]; !hasPrimary {
				metas = append(metas, listPkg{
					ImportPath: basePath,
					Name:       strings.TrimSuffix(p.Name, "_test"),
					Dir:        pkgDir,
					Module:     mod,
				})
			}
			metas = append(metas, listPkg{
				ImportPath: fmt.Sprintf("%s [%s.test]", p.PkgPath, p.ForTest),
				Name:       p.Name,
				Dir:        pkgDir,
				GoFiles:    allGo,
				Imports:    imps,
				ForTest:    p.ForTest,
				Module:     mod,
			})
			continue
		}

		var baseImps []string
		baseImpSet := map[string]bool{}
		for _, af := range p.Syntax {
			fname := filepath.Base(p.Fset.PositionFor(af.Pos(), false).Filename)
			if strings.HasSuffix(fname, "_test.go") {
				continue
			}
			for _, spec := range af.Imports {
				imp := strings.Trim(spec.Path.Value, `"`)
				if !baseImpSet[imp] {
					baseImpSet[imp] = true
					baseImps = append(baseImps, imp)
				}
			}
		}
		slices.Sort(baseImps)

		metas = append(metas, listPkg{
			ImportPath: p.PkgPath,
			Name:       p.Name,
			Dir:        pkgDir,
			GoFiles:    baseGo,
			SFiles:     sFiles,
			SysoFiles:  sysoFiles,
			Imports:    baseImps,
			Module:     mod,
		})
		if p.ForTest != "" && len(testOnlyGo) > 0 {
			metas = append(metas, listPkg{
				ImportPath: fmt.Sprintf("%s [%s.test]", p.PkgPath, p.ForTest),
				Name:       p.Name,
				Dir:        pkgDir,
				GoFiles:    allGo,
				SFiles:     sFiles,
				SysoFiles:  sysoFiles,
				Imports:    imps,
				ForTest:    p.ForTest,
				Module:     mod,
			})
		}
	}
	if reachesUnix {
		if uMeta := cachedUnixListPkgOnce(); uMeta != nil {
			metas = append(metas, *uMeta)
		}
	}
	return prog, metas, pkgs, nil
}

// buildInMemorySSA constructs a *program.Program, []listPkg metadata slice, and
// []*packages.Package DAG in memory from virtual file maps without spawning any
// per-test `go list` or `packages.Load` subprocess.
func buildInMemorySSA(t testing.TB, virtualDir, pkgMain string, filesByPkg map[string]map[string]string) (*progpkg.Program, []listPkg, []*packages.Package) {
	t.Helper()
	if virtualDir == "" {
		virtualDir = t.TempDir()
	}
	prog, metas, pkgs, err := buildInMemorySSAFromFiles(context.Background(), virtualDir, pkgMain, filesByPkg)
	if err != nil {
		t.Fatal(err)
	}
	return prog, metas, pkgs
}

// supplyInMemoryPackage builds an in-memory *program.Program and listing for
// pkgMain from filesByPkg and registers both in h so subsequent Compute* calls
// analyze pkgMain without spawning `go list` or `packages.Load`.
func supplyInMemoryPackage(t testing.TB, h *Hasher, pkgMain string, filesByPkg map[string]map[string]string) *progpkg.Program {
	t.Helper()
	prog, metas, _ := buildInMemorySSA(t, "", pkgMain, filesByPkg)
	h.progs[pkgMain] = prog
	h.lists[pkgMain] = metas
	return prog
}

func loadRegisteredInMemoryFixture(ctx context.Context, pkgPath string) (*progpkg.Program, []listPkg, bool, error) {
	filesByPkg, ok := inMemoryFixtureRegistry[pkgPath]
	if !ok {
		return nil, nil, false, nil
	}
	prog, metas, _, err := buildInMemorySSAFromFiles(ctx, "", pkgPath, filesByPkg)
	if err != nil {
		return nil, nil, true, err
	}
	return prog, metas, true, nil
}

func supplyRegisteredFixtures(t testing.TB, h *Hasher, pkgPaths ...string) {
	t.Helper()
	seen := map[string]bool{}
	for _, pkgPath := range pkgPaths {
		if seen[pkgPath] {
			continue
		}
		seen[pkgPath] = true
		prog, metas, ok, err := loadRegisteredInMemoryFixture(h.ctx, pkgPath)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			h.progs[pkgPath] = prog
			h.lists[pkgPath] = metas
		}
	}
}
