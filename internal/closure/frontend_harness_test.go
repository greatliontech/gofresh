package closure

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/gotool"
	progpkg "github.com/greatliontech/gofresh/internal/closure/internal/program"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/testvariant"
)

// TestMain gives this test binary its own memo root under os.TempDir so a
// test calling SetMemoRoot("") — or constructing a Hasher without calling
// isolateProofCache — never reads or writes the developer's real
// ~/.cache/gofresh store (and never collides with a concurrent test binary
// sharing the machine). GOCACHE is resolved and pinned first so child `go`
// commands under GOENV=off keep the warm build cache rather than falling back
// into the fresh XDG_CACHE_HOME.
func TestMain(m *testing.M) {
	if cache, err := gotool.GoBuildCache(context.Background(), os.Environ()); err == nil && cache != "" {
		_ = os.Setenv("GOCACHE", cache)
	}
	tmp, err := os.MkdirTemp("", "gofresh-closure-test-cache-*")
	if err == nil {
		_ = os.Setenv("XDG_CACHE_HOME", tmp)
	}
	code := m.Run()
	if tmp != "" {
		_ = os.RemoveAll(tmp)
	}
	testenv.CleanupShared()
	os.Exit(code)
}

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

func extractEmbedMatches(af *ast.File, available []string) []string {
	var patterns []string
	for _, cg := range af.Comments {
		for _, c := range cg.List {
			if after, ok := strings.CutPrefix(c.Text, "//go:embed "); ok {
				patterns = append(patterns, strings.Fields(after)...)
			}
		}
	}
	if len(patterns) == 0 {
		return nil
	}
	matched := map[string]bool{}
	for _, pat := range patterns {
		pat = strings.TrimPrefix(pat, "all:")
		for _, f := range available {
			if ok, _ := path.Match(pat, f); ok || f == pat || strings.HasPrefix(f, pat+"/") {
				matched[f] = true
			}
		}
	}
	var out []string
	for f := range matched {
		out = append(out, f)
	}
	slices.Sort(out)
	return out
}

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
	prog.GOARCH = runtime.GOARCH

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

		var availableRaw []string
		rawFiles, ok := filesByPkg[p.PkgPath]
		if !ok {
			rawFiles = filesByPkg[basePath]
		}
		for name := range rawFiles {
			availableRaw = append(availableRaw, name)
		}
		slices.Sort(availableRaw)

		var allGo, baseGo, testOnlyGo, hFiles, sFiles, sysoFiles, baseEmbed, allEmbed []string
		for _, full := range p.CompiledGoFiles {
			base := filepath.Base(full)
			allGo = append(allGo, base)
			if strings.HasSuffix(base, "_test.go") {
				testOnlyGo = append(testOnlyGo, base)
			} else {
				baseGo = append(baseGo, base)
			}
		}
		for _, name := range availableRaw {
			switch {
			case strings.HasSuffix(name, ".h"):
				hFiles = append(hFiles, name)
			case strings.HasSuffix(name, ".s"):
				sFiles = append(sFiles, name)
			case strings.HasSuffix(name, ".syso"):
				sysoFiles = append(sysoFiles, name)
			}
		}

		var baseImps []string
		baseImpSet := map[string]bool{}
		baseEmbedSet := map[string]bool{}
		allEmbedSet := map[string]bool{}
		for _, af := range p.Syntax {
			fname := filepath.Base(p.Fset.PositionFor(af.Pos(), false).Filename)
			isTest := strings.HasSuffix(fname, "_test.go")
			for _, emb := range extractEmbedMatches(af, availableRaw) {
				if !allEmbedSet[emb] {
					allEmbedSet[emb] = true
					allEmbed = append(allEmbed, emb)
				}
				if !isTest && !baseEmbedSet[emb] {
					baseEmbedSet[emb] = true
					baseEmbed = append(baseEmbed, emb)
				}
			}
			if isTest {
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
		slices.Sort(baseEmbed)
		slices.Sort(allEmbed)

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
				EmbedFiles: allEmbed,
				Imports:    imps,
				ForTest:    p.ForTest,
				Module:     mod,
			})
			continue
		}

		metas = append(metas, listPkg{
			ImportPath: p.PkgPath,
			Name:       p.Name,
			Dir:        pkgDir,
			GoFiles:    baseGo,
			HFiles:     hFiles,
			SFiles:     sFiles,
			SysoFiles:  sysoFiles,
			EmbedFiles: baseEmbed,
			Imports:    baseImps,
			Module:     mod,
		})
		if p.ForTest != "" && (len(testOnlyGo) > 0 || len(allEmbed) > len(baseEmbed)) {
			metas = append(metas, listPkg{
				ImportPath: fmt.Sprintf("%s [%s.test]", p.PkgPath, p.ForTest),
				Name:       p.Name,
				Dir:        pkgDir,
				GoFiles:    allGo,
				HFiles:     hFiles,
				SFiles:     sFiles,
				SysoFiles:  sysoFiles,
				EmbedFiles: allEmbed,
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

type cachedRegisteredFixture struct {
	prog  *progpkg.Program
	metas []listPkg
}

var (
	registeredFixtureMu    sync.Mutex
	registeredFixtureCache = map[string]cachedRegisteredFixture{}
)

func loadRegisteredInMemoryFixture(ctx context.Context, pkgPath string) (*progpkg.Program, []listPkg, bool, error) {
	filesByPkg, ok := inMemoryFixtureRegistry[pkgPath]
	if !ok {
		return nil, nil, false, nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, nil, true, err
		}
	}
	registeredFixtureMu.Lock()
	defer registeredFixtureMu.Unlock()
	if cached, found := registeredFixtureCache[pkgPath]; found {
		cloned := *cached.prog
		cloned.PkgScopeProbe = nil
		cloned.Summaries = nil
		cloned.MutatedGlobals = nil
		cloned.GOARCH = runtime.GOARCH
		cloned.ReadSource = nil
		return &cloned, cached.metas, true, nil
	}
	prog, metas, _, err := buildInMemorySSAFromFiles(ctx, "", pkgPath, filesByPkg)
	if err != nil {
		return nil, nil, true, err
	}
	registeredFixtureCache[pkgPath] = cachedRegisteredFixture{prog: prog, metas: metas}
	cloned := *prog
	cloned.PkgScopeProbe = nil
	cloned.Summaries = nil
	cloned.MutatedGlobals = nil
	cloned.GOARCH = runtime.GOARCH
	cloned.ReadSource = nil
	return &cloned, metas, true, nil
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

type scannedDirPkg struct {
	pkgPath        string
	pkgDir         string
	pkgName        string
	baseGo         []string
	testGo         []string
	xtestGo        []string
	hFiles         []string
	sFiles         []string
	sysoFiles      []string
	baseEmbed      []string
	testEmbed      []string
	xtestEmbed     []string
	baseImports    []string
	testImports    []string
	xtestImports   []string
	allFilesInDir  map[string]string
}

func uniqueSortedStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	cp := append([]string(nil), s...)
	slices.Sort(cp)
	return slices.Compact(cp)
}

// primeHasherFromDir scans an on-disk module directory dir, builds []listPkg
// metadata and in-memory *program.Program instances for every package in dir
// without invoking `go list` or `packages.Load`, and registers them on h.
func primeHasherFromDir(t testing.TB, h *Hasher, dir string) {
	if t != nil {
		t.Helper()
	}
	if dir == "" {
		return
	}
	gomodBytes, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return
	}
	if strings.Contains(string(gomodBytes), "replace ") {
		return
	}
	var modPath string
	for _, line := range strings.Split(string(gomodBytes), "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "module "); ok {
			modPath = strings.TrimSpace(after)
			break
		}
	}
	if modPath == "" {
		return
	}
	mod := &listMod{
		Path: modPath,
		Dir:  dir,
		Main: true,
	}

	bctx := build.Default
	if h.snapshot != nil {
		if v := h.snapshot.Value("GOOS"); v != "" {
			bctx.GOOS = v
		}
		if v := h.snapshot.Value("GOARCH"); v != "" {
			bctx.GOARCH = v
		}
		bctx.CgoEnabled = h.snapshot.Value("CGO_ENABLED") == "1"
	}
	for _, kv := range h.env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "GOOS":
			if v != "" {
				bctx.GOOS = v
			}
		case "GOARCH":
			if v != "" {
				bctx.GOARCH = v
			}
		case "CGO_ENABLED":
			bctx.CgoEnabled = v == "1"
		}
	}
	for i := 0; i < len(h.buildFlags); i++ {
		f := h.buildFlags[i]
		if after, ok := strings.CutPrefix(f, "-tags="); ok {
			bctx.BuildTags = append(bctx.BuildTags, strings.FieldsFunc(after, func(r rune) bool { return r == ',' || r == ' ' })...)
		} else if f == "-tags" && i+1 < len(h.buildFlags) {
			i++
			bctx.BuildTags = append(bctx.BuildTags, strings.FieldsFunc(h.buildFlags[i], func(r rune) bool { return r == ',' || r == ' ' })...)
		}
	}

	pkgDirsMap := map[string]string{}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if p != dir && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor") {
				return filepath.SkipDir
			}
			entries, rerr := os.ReadDir(p)
			if rerr != nil {
				return nil
			}
			for _, e := range entries {
				if !e.IsDir() && (strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), ".s") || strings.HasSuffix(e.Name(), ".syso")) {
					rel, _ := filepath.Rel(dir, p)
					pkgPath := modPath
					if rel != "." {
						pkgPath = modPath + "/" + filepath.ToSlash(rel)
					}
					pkgDirsMap[pkgPath] = p
					break
				}
			}
		}
		return nil
	})
	if err != nil || len(pkgDirsMap) == 0 {
		return
	}

	scannedByPath := make(map[string]*scannedDirPkg, len(pkgDirsMap))
	fset := token.NewFileSet()
	for pkgPath, pkgDir := range pkgDirsMap {
		sp := &scannedDirPkg{
			pkgPath:       pkgPath,
			pkgDir:        pkgDir,
			allFilesInDir: map[string]string{},
		}
		var availableRel []string
		_ = filepath.WalkDir(pkgDir, func(fp string, d fs.DirEntry, werr error) error {
			if werr != nil || fp == pkgDir {
				return nil
			}
			rel, _ := filepath.Rel(pkgDir, fp)
			relSlash := filepath.ToSlash(rel)
			if d.IsDir() {
				// Skip sub-packages (which have their own pkgDirsMap entry)
				if _, isSubPkg := pkgDirsMap[pkgPath+"/"+relSlash]; isSubPkg {
					return filepath.SkipDir
				}
				return nil
			}
			if b, rerr := os.ReadFile(fp); rerr == nil {
				sp.allFilesInDir[relSlash] = string(b)
				availableRel = append(availableRel, relSlash)
			}
			return nil
		})
		slices.Sort(availableRel)

		entries, _ := os.ReadDir(pkgDir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			switch {
			case strings.HasSuffix(name, ".h"):
				if ok, _ := bctx.MatchFile(pkgDir, name); ok {
					sp.hFiles = append(sp.hFiles, name)
				}
			case strings.HasSuffix(name, ".s"):
				if ok, _ := bctx.MatchFile(pkgDir, name); ok {
					sp.sFiles = append(sp.sFiles, name)
				}
			case strings.HasSuffix(name, ".syso"):
				if ok, _ := bctx.MatchFile(pkgDir, name); ok {
					sp.sysoFiles = append(sp.sysoFiles, name)
				}
			case strings.HasSuffix(name, ".go"):
				if ok, _ := bctx.MatchFile(pkgDir, name); !ok {
					continue
				}
				src := sp.allFilesInDir[name]
				af, perr := parser.ParseFile(fset, filepath.Join(pkgDir, name), src, parser.ParseComments)
				if perr != nil {
					af, _ = parser.ParseFile(fset, filepath.Join(pkgDir, name), src, parser.ImportsOnly|parser.ParseComments)
				}
				if af == nil {
					af, _ = parser.ParseFile(fset, filepath.Join(pkgDir, name), src, parser.PackageClauseOnly|parser.ParseComments)
				}
				var clause string
				if af != nil && af.Name != nil {
					clause = af.Name.Name
				}
				var imps []string
				if af != nil {
					for _, spec := range af.Imports {
						if imp, uerr := strconv.Unquote(spec.Path.Value); uerr == nil {
							imps = append(imps, imp)
						}
					}
				}
				var embeds []string
				if af != nil {
					embeds = extractEmbedMatches(af, availableRel)
				}
				isTest := strings.HasSuffix(name, "_test.go")
				isExt := isTest && strings.HasSuffix(clause, "_test")
				if !isTest {
					if sp.pkgName == "" && clause != "" {
						sp.pkgName = clause
					}
					sp.baseGo = append(sp.baseGo, name)
					sp.baseImports = append(sp.baseImports, imps...)
					sp.baseEmbed = append(sp.baseEmbed, embeds...)
				} else if !isExt {
					if sp.pkgName == "" && clause != "" {
						sp.pkgName = clause
					}
					sp.testGo = append(sp.testGo, name)
					sp.testImports = append(sp.testImports, imps...)
					sp.testEmbed = append(sp.testEmbed, embeds...)
				} else {
					if sp.pkgName == "" && clause != "" {
						sp.pkgName = strings.TrimSuffix(clause, "_test")
					}
					sp.xtestGo = append(sp.xtestGo, name)
					sp.xtestImports = append(sp.xtestImports, imps...)
					sp.xtestEmbed = append(sp.xtestEmbed, embeds...)
				}
			}
		}
		if sp.pkgName == "" {
			sp.pkgName = path.Base(pkgPath)
		}
		sp.baseGo = uniqueSortedStrings(sp.baseGo)
		sp.testGo = uniqueSortedStrings(sp.testGo)
		sp.xtestGo = uniqueSortedStrings(sp.xtestGo)
		sp.hFiles = uniqueSortedStrings(sp.hFiles)
		sp.sFiles = uniqueSortedStrings(sp.sFiles)
		sp.sysoFiles = uniqueSortedStrings(sp.sysoFiles)
		sp.baseEmbed = uniqueSortedStrings(sp.baseEmbed)
		sp.testEmbed = uniqueSortedStrings(sp.testEmbed)
		sp.xtestEmbed = uniqueSortedStrings(sp.xtestEmbed)
		sp.baseImports = uniqueSortedStrings(sp.baseImports)
		sp.testImports = uniqueSortedStrings(sp.testImports)
		sp.xtestImports = uniqueSortedStrings(sp.xtestImports)
		scannedByPath[pkgPath] = sp
	}

	allPkgPaths := make([]string, 0, len(scannedByPath))
	for pkgPath := range scannedByPath {
		allPkgPaths = append(allPkgPaths, pkgPath)
	}
	slices.Sort(allPkgPaths)

	for _, targetPkg := range allPkgPaths {
		rootSP := scannedByPath[targetPkg]
		if len(rootSP.baseGo) == 0 && len(rootSP.testGo) == 0 && len(rootSP.xtestGo) == 0 && len(rootSP.sFiles) == 0 && len(rootSP.sysoFiles) == 0 {
			continue
		}
		// Compute transitive dependency cone in scannedByPath starting from targetPkg (including its test imports).
		inCone := map[string]bool{}
		var coneOrder []string
		var visitDep func(p string)
		visitDep = func(p string) {
			if inCone[p] {
				return
			}
			sp, ok := scannedByPath[p]
			if !ok {
				return
			}
			inCone[p] = true
			for _, imp := range sp.baseImports {
				visitDep(imp)
			}
			coneOrder = append(coneOrder, p)
		}
		inCone[targetPkg] = true
		for _, imp := range rootSP.baseImports {
			visitDep(imp)
		}
		for _, imp := range rootSP.testImports {
			visitDep(imp)
		}
		for _, imp := range rootSP.xtestImports {
			if imp != targetPkg {
				visitDep(imp)
			}
		}
		coneOrder = append(coneOrder, targetPkg)

		var metas []listPkg
		stdImportsSeen := map[string]bool{}
		addStdImports := func(imps []string) {
			for _, imp := range imps {
				if _, isUser := scannedByPath[imp]; isUser || imp == "C" || imp == "unsafe" || stdImportsSeen[imp] {
					continue
				}
				stdImportsSeen[imp] = true
				if h != nil && h.source.inventory != nil {
					if inv, ok := h.source.inventory[imp]; ok {
						metas = append(metas, listPkg{
							ImportPath: imp,
							Name:       implicitImportName(imp),
							Standard:   true,
							Dir:        inv.Dir,
							GoFiles:    inv.Files,
						})
						continue
					}
				}
				metas = append(metas, listPkg{
					ImportPath: imp,
					Name:       implicitImportName(imp),
				})
			}
		}
		targetFilesByPkg := make(map[string]map[string]string, len(coneOrder))
		targetPkgDirs := make(map[string]string, len(coneOrder))
		for _, p := range coneOrder {
			sp := scannedByPath[p]
			targetPkgDirs[p] = sp.pkgDir
			addStdImports(sp.baseImports)
			if p != targetPkg {
				// Dependency node: only production files are compiled.
				prodMap := make(map[string]string, len(sp.baseGo)+len(sp.hFiles)+len(sp.sFiles)+len(sp.sysoFiles))
				for _, f := range sp.baseGo {
					prodMap[f] = sp.allFilesInDir[f]
				}
				for _, f := range sp.hFiles {
					prodMap[f] = sp.allFilesInDir[f]
				}
				for _, f := range sp.sFiles {
					prodMap[f] = sp.allFilesInDir[f]
				}
				for _, f := range sp.sysoFiles {
					prodMap[f] = sp.allFilesInDir[f]
				}
				targetFilesByPkg[p] = prodMap
				metas = append(metas, listPkg{
					ImportPath: sp.pkgPath,
					Name:       sp.pkgName,
					Dir:        sp.pkgDir,
					GoFiles:    sp.baseGo,
					HFiles:     sp.hFiles,
					SFiles:     sp.sFiles,
					SysoFiles:  sp.sysoFiles,
					EmbedFiles: sp.baseEmbed,
					Imports:    sp.baseImports,
					Module:     mod,
				})
				continue
			}
			addStdImports(sp.testImports)
			addStdImports(sp.xtestImports)
			matchedMap := make(map[string]string, len(sp.baseGo)+len(sp.testGo)+len(sp.xtestGo)+len(sp.hFiles)+len(sp.sFiles)+len(sp.sysoFiles))
			for _, f := range sp.baseGo {
				matchedMap[f] = sp.allFilesInDir[f]
			}
			for _, f := range sp.testGo {
				matchedMap[f] = sp.allFilesInDir[f]
			}
			for _, f := range sp.xtestGo {
				matchedMap[f] = sp.allFilesInDir[f]
			}
			for _, f := range sp.hFiles {
				matchedMap[f] = sp.allFilesInDir[f]
			}
			for _, f := range sp.sFiles {
				matchedMap[f] = sp.allFilesInDir[f]
			}
			for _, f := range sp.sysoFiles {
				matchedMap[f] = sp.allFilesInDir[f]
			}
			targetFilesByPkg[p] = matchedMap
			metas = append(metas, listPkg{
				ImportPath: sp.pkgPath,
				Name:       sp.pkgName,
				Dir:        sp.pkgDir,
				GoFiles:    sp.baseGo,
				HFiles:     sp.hFiles,
				SFiles:     sp.sFiles,
				SysoFiles:  sp.sysoFiles,
				EmbedFiles: sp.baseEmbed,
				Imports:    sp.baseImports,
				Module:     mod,
			})
			if len(sp.testGo) > 0 || len(sp.testEmbed) > 0 {
				metas = append(metas, listPkg{
					ImportPath: fmt.Sprintf("%s [%s.test]", sp.pkgPath, sp.pkgPath),
					Name:       sp.pkgName,
					Dir:        sp.pkgDir,
					GoFiles:    uniqueSortedStrings(append(append([]string(nil), sp.baseGo...), sp.testGo...)),
					HFiles:     sp.hFiles,
					SFiles:     sp.sFiles,
					SysoFiles:  sp.sysoFiles,
					EmbedFiles: uniqueSortedStrings(append(append([]string(nil), sp.baseEmbed...), sp.testEmbed...)),
					Imports:    uniqueSortedStrings(append(append([]string(nil), sp.baseImports...), sp.testImports...)),
					ForTest:    sp.pkgPath,
					Module:     mod,
				})
			}
			if len(sp.xtestGo) > 0 || len(sp.xtestEmbed) > 0 {
				metas = append(metas, listPkg{
					ImportPath: fmt.Sprintf("%s_test [%s.test]", sp.pkgPath, sp.pkgPath),
					Name:       sp.pkgName + "_test",
					Dir:        sp.pkgDir,
					GoFiles:    sp.xtestGo,
					EmbedFiles: sp.xtestEmbed,
					Imports:    sp.xtestImports,
					ForTest:    sp.pkgPath,
					Module:     mod,
				})
			}
		}
		h.lists[targetPkg] = metas
		if pkgs, perr := testenv.ParseAndTypecheckInPlaceWithStdlib(os.Environ(), dir, targetPkgDirs, targetFilesByPkg); perr == nil {
			h.progs[targetPkg] = &program{PkgPath: targetPkg, Pkgs: pkgs}
			primedHasherMu.Lock()
			if primedHasherPkgs[h] == nil {
				primedHasherPkgs[h] = map[string][]*packages.Package{}
			}
			if primedHasherLists[h] == nil {
				primedHasherLists[h] = map[string][]listPkg{}
			}
			primedHasherPkgs[h][targetPkg] = pkgs
			primedHasherLists[h][targetPkg] = metas
			primedHasherMu.Unlock()
		}
	}
}

var (
	primedHasherMu    sync.Mutex
	primedHasherPkgs  = map[*Hasher]map[string][]*packages.Package{}
	primedHasherLists = map[*Hasher]map[string][]listPkg{}
	eligibleHashers   = map[*Hasher]bool{}
)

func markHasherEligible(h *Hasher) {
	if h == nil {
		return
	}
	primedHasherMu.Lock()
	eligibleHashers[h] = true
	primedHasherMu.Unlock()
}

func unprimeHasher(h *Hasher) {
	if h == nil {
		return
	}
	primedHasherMu.Lock()
	delete(primedHasherPkgs, h)
	delete(primedHasherLists, h)
	delete(eligibleHashers, h)
	primedHasherMu.Unlock()
}

func lookupPrimedHasherPkg(h *Hasher, pkgPath string) ([]*packages.Package, []listPkg, bool) {
	if h == nil {
		return nil, nil, false
	}
	primedHasherMu.Lock()
	defer primedHasherMu.Unlock()
	pkgs := primedHasherPkgs[h][pkgPath]
	metas := primedHasherLists[h][pkgPath]
	if len(metas) == 0 && h.lists != nil {
		metas = h.lists[pkgPath]
	}
	return pkgs, metas, len(pkgs) > 0
}

func init() {
	analysisTestHooks.listOnMiss = func(h *Hasher, pkgPath string) ([]listPkg, bool) {
		if h == nil || h.runner.Prepare != nil || len(h.buildFlags) > 0 {
			return nil, false
		}
		if h.ctx != nil && h.ctx.Err() != nil {
			return nil, false
		}
		primedHasherMu.Lock()
		eligible := eligibleHashers[h]
		primedHasherMu.Unlock()
		if !eligible {
			return nil, false
		}
		if h.dir == "" {
			if _, metas, ok, err := loadRegisteredInMemoryFixture(h.ctx, pkgPath); ok && err == nil {
				return metas, true
			}
			return nil, false
		}
		primeHasherFromDir(nil, h, h.dir)
		if metas, ok := h.lists[pkgPath]; ok {
			return metas, true
		}
		return nil, false
	}
	analysisTestHooks.loadProgramOnMiss = func(ctx context.Context, h *Hasher, pkgPath string) (*program, bool, error) {
		if h == nil || h.runner.Prepare != nil || len(h.buildFlags) > 0 {
			return nil, false, nil
		}
		if ctx != nil && ctx.Err() != nil {
			return nil, false, nil
		}
		primedHasherMu.Lock()
		eligible := eligibleHashers[h]
		primedHasherMu.Unlock()
		if !eligible {
			return nil, false, nil
		}
		if h.dir == "" {
			if inMemProg, metas, ok, err := loadRegisteredInMemoryFixture(ctx, pkgPath); ok {
				if err == nil && h.lists[pkgPath] == nil {
					h.lists[pkgPath] = metas
				}
				return inMemProg, true, err
			}
			return nil, false, nil
		}
		pkgs, metas, ok := lookupPrimedHasherPkg(h, pkgPath)
		if !ok {
			primeHasherFromDir(nil, h, h.dir)
			pkgs, metas, ok = lookupPrimedHasherPkg(h, pkgPath)
		}
		if !ok || len(pkgs) == 0 {
			return nil, false, nil
		}
		built, err := progpkg.FromPackages(ctx, pkgPath, pkgs)
		if err == nil && h.lists[pkgPath] == nil && len(metas) > 0 {
			h.lists[pkgPath] = metas
		}
		return built, true, err
	}
	analysisTestHooks.testingPackagesOnMiss = func(h *Hasher, pkgPath string) *program {
		if h == nil || h.runner.Prepare != nil || len(h.buildFlags) > 0 {
			return nil
		}
		if h.ctx != nil && h.ctx.Err() != nil {
			return nil
		}
		primedHasherMu.Lock()
		eligible := eligibleHashers[h]
		primedHasherMu.Unlock()
		if !eligible {
			return nil
		}
		if h.dir == "" {
			if inMemProg, _, ok, err := loadRegisteredInMemoryFixture(h.ctx, pkgPath); ok && err == nil {
				return inMemProg
			}
			return nil
		}
		pkgs, _, ok := lookupPrimedHasherPkg(h, pkgPath)
		if !ok {
			primeHasherFromDir(nil, h, h.dir)
			pkgs, _, ok = lookupPrimedHasherPkg(h, pkgPath)
		}
		if ok {
			return &program{PkgPath: pkgPath, Pkgs: pkgs}
		}
		return nil
	}
}

var cachedHostSnapshotOnce = sync.OnceValues(func() (*gotool.EnvSnapshot, error) {
	dir, err := os.MkdirTemp("", "gofresh-closure-env-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	return (gotool.Runner{}).TakeEnvSnapshot(context.Background(), dir, os.Environ())
})

func newInMemoryHasher(t testing.TB, buildFlags ...string) *Hasher {
	t.Helper()
	return newInMemoryHasherAt(t, t.TempDir(), buildFlags...)
}

func newInMemoryHasherAt(t testing.TB, dir string, buildFlags ...string) *Hasher {
	t.Helper()
	snap, err := cachedHostSnapshotOnce()
	if err != nil {
		t.Fatal(err)
	}
	if dir == "" {
		dir = t.TempDir()
	}
	reader := gotool.PrimedEnvReader(gotool.Runner{}, dir, os.Environ(), snap)
	h, err := NewAt(context.Background(), reader, buildFlags...)
	if err != nil {
		t.Fatal(err)
	}
	if len(buildFlags) == 0 {
		markHasherEligible(h)
		primeHasherFromDir(t, h, dir)
		t.Cleanup(func() { unprimeHasher(h) })
	}
	return h
}

// The tests' ambient forms: the process environment and a background
// context, spelled once here — the public entries name both.
func newAt(dir string, buildFlags ...string) (*Hasher, error) {
	var h *Hasher
	var err error
	if snap, snapErr := cachedHostSnapshotOnce(); snapErr == nil {
		h, err = NewAt(context.Background(), gotool.PrimedEnvReader(gotool.Runner{}, dir, os.Environ(), snap), buildFlags...)
	} else {
		h, err = NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()), buildFlags...)
	}
	if err == nil && len(buildFlags) == 0 {
		markHasherEligible(h)
		if dir != "" {
			primeHasherFromDir(nil, h, dir)
		}
	}
	return h, err
}

func newAtEnv(ctx context.Context, dir string, env []string, buildFlags ...string) (*Hasher, error) {
	return NewAt(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags...)
}

func loadViewPackagesEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*ViewLoad, error) {
	return LoadViewPackages(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags, pkgPaths...)
}

// cgoEnabled reports the go command's resolved CGO_ENABLED — the
// setting every listing obeys: without cgo the go command refuses a
// race listing.
func cgoEnabled(t *testing.T) bool {
	t.Helper()
	snapshot, err := cachedHostSnapshotOnce()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.Value("CGO_ENABLED") == "1"
}

func isolateProofCache(t *testing.T) {
	t.Helper()
	cache, err := gotool.GoBuildCache(context.Background(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOCACHE", cache)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

// unauditedTagGOROOT constructs an isolated GOROOT copy of the host toolchain
// with a tag-gated file in package strings (`//go:build badstd`) that declares
// an unapproved single-argument push linkname.
func unauditedTagGOROOT(t *testing.T) string {
	t.Helper()
	return testenv.UnauditedTagGOROOT(t, os.Environ())
}

// computeTier2ResultAndReach runs the per-subject precise-analysis pipeline
// the observability proof is built on — program load, subject rooting,
// package listing, attributed reachability, and the analyzer projection —
// for a single subject, returning the raw analyzer result plus the names of
// the subject-reachable functions (the attribution surface the analyzer
// projects), so root-resolution tests assert reach directly. A symbol that
// cannot be rooted in the loaded test-binary program is a subject-local
// error naming the subject; a name declared by both the package and its
// external test package errors naming the ambiguity.
//
// The program and listing are loaded locally and released with the call
// unless already cached on the Hasher: table tests share one Hasher
// across many fixture packages, and retaining every whole-program SSA
// would grow peak memory with the table instead of the largest single
// test binary.
func computeTier2ResultAndReach(h *Hasher, pkgPath, symbol string) (tier2Result, map[string]bool, error) {
	_, retainList := h.lists[pkgPath]
	if _, ok := h.progs[pkgPath]; ok {
		retainList = true
	}
	defer func() {
		if !retainList {
			delete(h.lists, pkgPath)
		}
	}()
	prog := h.progs[pkgPath]
	if prog != nil && prog.Prog == nil && len(prog.Pkgs) > 0 {
		built, err := progpkg.FromPackages(h.ctx, pkgPath, prog.Pkgs)
		if err != nil {
			return tier2Result{}, nil, err
		}
		prog = built
		h.progs[pkgPath] = built
	}
	if prog == nil {
		if inMemProg, metas, ok, err := loadRegisteredInMemoryFixture(h.ctx, pkgPath); ok {
			if err != nil {
				return tier2Result{}, nil, err
			}
			prog = inMemProg
			h.lists[pkgPath] = metas
		} else if pkgs, metas, ok := lookupPrimedHasherPkg(h, pkgPath); ok && len(pkgs) > 0 {
			built, err := progpkg.FromPackages(h.ctx, pkgPath, pkgs)
			if err != nil {
				return tier2Result{}, nil, err
			}
			prog = built
			if len(metas) > 0 && h.lists[pkgPath] == nil {
				h.lists[pkgPath] = metas
			}
		} else {
			var err error
			prog, err = progpkg.Load(h.ctx, h.dir, h.packageEnv, h.buildFlags, pkgPath)
			if err != nil {
				return tier2Result{}, nil, err
			}
		}
	}
	if prog.Roots[symbol] == nil {
		if prog.Ambiguous[symbol] {
			return tier2Result{}, nil, fmt.Errorf("closure: subject name %s is ambiguous in %s (declared by both the package and its external test package)", symbol, pkgPath)
		}
		return tier2Result{}, nil, fmt.Errorf("closure: subject %s not found in %s", symbol, pkgPath)
	}
	metas, err := h.list(pkgPath)
	if err != nil {
		return tier2Result{}, nil, err
	}
	reachable, err := attributedReachableSets(h.ctx, true, h.source.pureDelegates, prog, []Subject{{Package: pkgPath, Symbol: symbol}})
	if err != nil {
		return tier2Result{}, nil, err
	}
	result, err := h.tier2Reachable(newTier2Base(h, prog, metas), reachable[0])
	if err != nil {
		return tier2Result{}, nil, err
	}
	reach := make(map[string]bool, len(reachable[0].functions))
	for fn := range reachable[0].functions {
		if fn != nil {
			reach[fn.String()] = true
		}
	}
	return result, reach, nil
}

func computeTier2Result(h *Hasher, pkgPath, symbol string) (tier2Result, error) {
	result, _, err := computeTier2ResultAndReach(h, pkgPath, symbol)
	return result, err
}

// fixturePrograms shares loaded representation, never analysis results, for
// unchanged fixtures under one Hasher's configuration. Only the latest SSA
// program is held; its own PkgPath is the key, so a failed replacement cannot
// leave a stale key beside a nil program. An explicit roster additionally holds
// one typed preparation for the parent. Its source/dependencies and effective
// build configuration stay quiescent through cleanup. Source-editing and
// independent-load tests do not use this helper. The owner and its callers are
// sequential, including lazy type/SSA method construction.
type fixturePrograms struct {
	h      *Hasher
	loaded *program
	// An explicit immutable roster opts into one typed generation. Preparation
	// is lazy: a table whose subtests are all filtered out loads nothing.
	roster                []string
	prepared              *progpkg.Prepared
	prepareErr            error
	attempted             bool
	prepare               func(context.Context, string, []string, []string, ...string) (*progpkg.Prepared, error)
	typedLoads, ssaBuilds int
}

func newFixturePrograms(t *testing.T, h *Hasher, roster ...string) *fixturePrograms {
	t.Helper()
	f := &fixturePrograms{h: h, prepare: progpkg.Prepare}
	for _, path := range roster {
		if !slices.Contains(f.roster, path) {
			f.roster = append(f.roster, path)
		}
	}
	t.Cleanup(f.release)
	return f
}

func (f *fixturePrograms) supply(t *testing.T, pkgPath string) {
	t.Helper()
	if err := f.acquire(pkgPath); err != nil {
		t.Fatalf("load fixture %s: %v", pkgPath, err)
	}
}

func (f *fixturePrograms) acquire(pkgPath string) error {
	if f.h.ctx != nil {
		if err := f.h.ctx.Err(); err != nil {
			f.releaseProgram()
			return err
		}
	}
	if len(f.roster) > 0 && !slices.Contains(f.roster, pkgPath) {
		f.releaseProgram()
		return fmt.Errorf("fixture %s is outside the immutable roster", pkgPath)
	}
	if f.loaded == nil || f.loaded.PkgPath != pkgPath {
		f.releaseProgram()
		if len(f.roster) > 0 && !f.attempted {
			f.attempted = true
			f.typedLoads++
			var diskRoster []string
			for _, r := range f.roster {
				if _, ok := inMemoryFixtureRegistry[r]; ok {
					continue
				}
				if _, _, ok := lookupPrimedHasherPkg(f.h, r); ok {
					continue
				}
				diskRoster = append(diskRoster, r)
			}
			if len(diskRoster) > 0 {
				f.prepared, f.prepareErr = f.prepare(f.h.ctx, f.h.dir, f.h.packageEnv, f.h.buildFlags, diskRoster...)
			}
		}
		// Cancellation never licenses an independent fallback, including a
		// context error returned by a preparation whose context is still live.
		if err := f.h.ctx.Err(); err != nil {
			return err
		}
		if errors.Is(f.prepareErr, context.Canceled) || errors.Is(f.prepareErr, context.DeadlineExceeded) {
			return f.prepareErr
		}
		// Cache only successful fixture loads, as the precise-analysis
		// driver's local-load path does. A failed case still fails the test;
		// later cases retain their opportunity to load and assert independently.
		var p *program
		var err error
		f.ssaBuilds++
		if inMemProg, metas, ok, inMemErr := loadRegisteredInMemoryFixture(f.h.ctx, pkgPath); ok {
			p, err = inMemProg, inMemErr
			if err == nil {
				f.h.lists[pkgPath] = metas
			}
		} else if pkgs, metas, ok := lookupPrimedHasherPkg(f.h, pkgPath); ok && len(pkgs) > 0 && f.prepareErr == nil {
			p, err = progpkg.FromPackages(f.h.ctx, pkgPath, pkgs)
			if err == nil && len(metas) > 0 && f.h.lists[pkgPath] == nil {
				f.h.lists[pkgPath] = metas
			}
		} else if f.prepared != nil {
			p, err = f.prepared.Build(f.h.ctx, pkgPath)
		} else {
			// Only a load-wide operational preparation failure reaches this
			// fallback. Per-root selection/load errors remain Build errors.
			f.typedLoads++
			p, err = progpkg.Load(f.h.ctx, f.h.dir, f.h.packageEnv, f.h.buildFlags, pkgPath)
		}
		if err != nil {
			return err
		}
		f.loaded = p
	}
	// Reset analysis-failure discrimination; only structural SSA caches may
	// carry across these otherwise independent singleton analyses.
	f.loaded.PkgScopeProbe = nil
	f.h.progs[pkgPath] = f.loaded
	return nil
}

func (f *fixturePrograms) releaseProgram() {
	if f.loaded != nil {
		delete(f.h.progs, f.loaded.PkgPath)
		if _, ok := inMemoryFixtureRegistry[f.loaded.PkgPath]; ok {
			delete(f.h.lists, f.loaded.PkgPath)
		}
		f.loaded = nil
	}
}

func (f *fixturePrograms) release() {
	f.releaseProgram()
	f.prepared = nil
	f.roster = nil
	f.prepareErr = nil
}

// checkPreparationCounts uses the actually entered subtests' transitions, so
// legitimate -run filtering retains the same cost assertions.
func (f *fixturePrograms) checkPreparationCounts(t *testing.T, transitions int) {
	t.Helper()
	wantLoads := 0
	if transitions > 0 {
		wantLoads = 1
	}
	if f.typedLoads != wantLoads || f.ssaBuilds != transitions {
		t.Errorf("fixture preparation: typed loads=%d SSA builds=%d, want %d/%d", f.typedLoads, f.ssaBuilds, wantLoads, transitions)
	}
}

func TestFixtureProgramSupplyKeepsOnlyLoadedRepresentation(t *testing.T) {
	h := &Hasher{progs: map[string]*program{}}
	owner := newFixturePrograms(t, h)
	p := &program{PkgPath: "example.com/fixture", PkgScopeProbe: map[bool]error{true: errors.New("prior analysis")}}
	owner.loaded = p
	owner.supply(t, p.PkgPath)
	if p.PkgScopeProbe != nil || h.progs[p.PkgPath] != p {
		t.Fatal("supplying loaded representation retained failure analysis or lost the actual program")
	}
	owner.release()
	if owner.loaded != nil || len(h.progs) != 0 {
		t.Fatal("release retained the fixture's loaded representation")
	}
	var childOwner *fixturePrograms
	t.Run("owner cleanup", func(t *testing.T) {
		childOwner = newFixturePrograms(t, h)
		childOwner.loaded = p
		childOwner.supply(t, p.PkgPath)
	})
	if childOwner.loaded != nil || len(h.progs) != 0 {
		t.Fatal("the completed owner's cleanup retained its program")
	}
}

func writeFile(t testing.TB, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeTree materialises files under dir (directories created as
// needed; a path ending in "/" is an empty directory).
func writeTree(t testing.TB, dir string, files map[string]string) {
	t.Helper()
	for p, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func writeTestVariantModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, files)
	return dir
}

func listingEnv(goflags, gowork string) []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key == "GOENV" || key == "GOFLAGS" || key == "GOWORK" {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "GOENV=off", "GOFLAGS="+goflags, "GOWORK="+gowork)
}

func hasherUnder(t *testing.T, dir string, env []string, buildFlags []string) *Hasher {
	t.Helper()
	snap, err := cachedHostSnapshotOnce()
	if err != nil {
		t.Fatal(err)
	}
	reader := gotool.PrimedEnvReader(gotool.Runner{}, dir, os.Environ(), snap)
	h, err := NewAt(context.Background(), reader)
	if err != nil {
		t.Fatal(err)
	}
	if env != nil {
		h.env = env
	}
	if buildFlags != nil {
		h.buildFlags = append([]string(nil), buildFlags...)
	}
	markHasherEligible(h)
	primeHasherFromDir(t, h, dir)
	t.Cleanup(func() { unprimeHasher(h) })
	return h
}

func computeAt(t *testing.T, dir string, subjects ...Subject) map[Subject]Closure {
	t.Helper()
	return computeUnder(t, dir, nil, nil, subjects...)
}

func computeUnder(t *testing.T, dir string, env []string, buildFlags []string, subjects ...Subject) map[Subject]Closure {
	t.Helper()
	h := hasherUnder(t, dir, env, buildFlags)
	defer unprimeHasher(h)
	closures, _, err := h.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	return closures
}

func ledgerAt(t *testing.T, dir, pkgPath string) testvariant.TestVariantLedger {
	t.Helper()
	ledger, _ := ledgerUnder(t, dir, nil, nil, pkgPath)
	return ledger
}

func ledgerUnder(t *testing.T, dir string, env []string, buildFlags []string, pkgPath string) (testvariant.TestVariantLedger, []string) {
	t.Helper()
	h := hasherUnder(t, dir, env, buildFlags)
	defer unprimeHasher(h)
	ledger, err := h.TestVariantLedger(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	return ledger, append([]string(nil), h.testVariants[pkgPath].Files...)
}

func reachContains(reach map[string]bool, parts ...string) bool {
	for name := range reach {
		all := true
		for _, part := range parts {
			if !strings.Contains(name, part) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func stringSliceContains(values []string, target string) bool {
	return slices.Contains(values, target)
}

func environmentWith(settings ...string) []string {
	base := os.Environ()
	keys := make(map[string]bool, len(settings))
	for _, entry := range settings {
		key, _, _ := strings.Cut(entry, "=")
		keys[key] = true
	}
	out := make([]string, 0, len(base)+len(settings))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if !keys[key] {
			out = append(out, entry)
		}
	}
	return append(out, settings...)
}

func requireBareAxis(t *testing.T, name, notice, attribution string) {
	t.Helper()
	if !strings.HasPrefix(notice, "toolchain-selection audit: "+attribution+" — ") {
		t.Errorf("%s: attribution %q is not the notice's axis (%q)", name, attribution, notice)
	}
	for _, forbidden := range []string{"admission", "walked against", "never admitted", "listed and readable", "—"} {
		if strings.Contains(attribution, forbidden) {
			t.Errorf("%s: attribution %q carries %q — consequence or remedy text", name, attribution, forbidden)
		}
	}
}

func hasEffectReason(effects []externalEffect, want string) bool {
	for _, effect := range effects {
		if strings.Contains(effect.reason, want) {
			return true
		}
	}
	return false
}

type cancelAfterContext struct {
	context.Context
	remaining int
}

func (c *cancelAfterContext) Err() error {
	if c.remaining <= 0 {
		return context.Canceled
	}
	c.remaining--
	return nil
}

// Synthetic stdlib fixture sources shared across hermetic and integration
// toolchain-surface verifier tests.
const syntheticInternalTestlogSrc = `package testlog
import "sync/atomic"
type Interface interface {
	Getenv(string)
	Stat(string)
	Open(string)
	Chdir(string)
}
var logger atomic.Pointer[Interface]
func SetLogger(impl Interface) {
	if !logger.CompareAndSwap(nil, &impl) {
		panic("testlog: SetLogger must be called only once")
	}
}
func Logger() Interface {
	impl := logger.Load()
	if impl == nil {
		return nil
	}
	return *impl
}
func Getenv(name string) {
	if log := Logger(); log != nil {
		log.Getenv(name)
	}
}
func Open(name string) {
	if log := Logger(); log != nil {
		log.Open(name)
	}
}
func Stat(name string) {
	if log := Logger(); log != nil {
		log.Stat(name)
	}
}
func Chdir(name string) {
	if log := Logger(); log != nil {
		log.Chdir(name)
	}
}
`

const syntheticOSSrc = `package os
import (
	"errors"
	"internal/testlog"
	"io"
	"syscall"
)
var ErrInvalid = errors.New("invalid argument")
var ErrClosed = errors.New("file already closed")
type PathError struct {
	Op   string
	Path string
	Err  error
}
func (e *PathError) Error() string { return e.Op }
type pollFD struct {
	Sysfd int
}
func (fd *pollFD) Read(p []byte) (int, error)  { return 0, io.EOF }
func (fd *pollFD) Write(p []byte) (int, error) { return len(p), nil }
func (fd *pollFD) Close() error                { return nil }
type file struct {
	pfd  pollFD
	name string
}
type File struct {
	*file
}
func newFile(fd int, name string) *File {
	return &File{&file{pfd: pollFD{Sysfd: fd}, name: name}}
}
func Exit(code int) {
	if code == 0 && testlog.PanicOnExit0() {
		panic("os.Exit(0)")
	}
	syscall.Exit(code)
}
func Getenv(key string) string {
	testlog.Getenv(key)
	return ""
}
func LookupEnv(key string) (string, bool) {
	testlog.Getenv(key)
	return "", false
}
func Open(name string) (*File, error) {
	return OpenFile(name, 0, 0)
}
func Create(name string) (*File, error) {
	return OpenFile(name, 1, 0o666)
}
func OpenFile(name string, flag int, perm uint32) (*File, error) {
	testlog.Open(name)
	return openFileNolog(name, flag, perm)
}
func openFileNolog(name string, flag int, perm uint32) (*File, error) {
	r, err := syscall.Open(name, flag, perm)
	if err != nil {
		return nil, &PathError{Op: "open", Path: name, Err: err}
	}
	return newFile(r, name), nil
}
func openDir(name string) (*File, error) {
	testlog.Open(name)
	return &File{&file{name: name}}, nil
}
func statOrZero(f *File) int64 {
	return 0
}
func readFileContents(statSize int64, read func([]byte) (int, error)) ([]byte, error) {
	var buf [1]byte
	_, err := read(buf[:])
	if err == io.EOF {
		return nil, nil
	}
	return nil, err
}
func (f *File) Read(b []byte) (int, error) {
	if err := f.checkValid("read"); err != nil {
		return 0, err
	}
	return f.pfd.Read(b)
}
func ReadFile(name string) ([]byte, error) {
	f, err := Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readFileContents(statOrZero(f), f.Read)
}
func ReadDir(name string) ([]any, error) {
	f, err := openDir(name)
	_ = f
	return nil, err
}
func Stat(name string) (any, error) {
	testlog.Stat(name)
	return nil, nil
}
func Lstat(name string) (any, error) {
	testlog.Stat(name)
	return nil, nil
}
func Getwd() (string, error) {
	dir, err := syscall.Getwd()
	return dir, err
}
func Chdir(dir string) error {
	if e := syscall.Chdir(dir); e != nil {
		testlog.Open(dir)
		return &PathError{Op: "chdir", Path: dir, Err: e}
	}
	if log := testlog.Logger(); log != nil {
		wd, err := Getwd()
		if err == nil {
			log.Chdir(wd)
		}
	}
	return nil
}
func (f *File) checkValid(op string) error {
	if f == nil {
		return ErrInvalid
	}
	return nil
}
func (f *File) wrapErr(op string, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	return &PathError{Op: op, Path: f.name, Err: err}
}
func (f *File) Write(b []byte) (n int, err error) {
	if err := f.checkValid("write"); err != nil {
		return 0, err
	}
	n, e := f.write(b)
	if n < 0 {
		n = 0
	}
	if n != len(b) {
		err = io.ErrShortWrite
	}
	if e != nil {
		err = f.wrapErr("write", e)
	}
	return n, err
}
func (f *File) WriteString(s string) (n int, err error) {
	return f.Write([]byte(s))
}
func (f *File) write(b []byte) (n int, err error) {
	n, err = f.pfd.Write(b)
	return n, err
}
func (f *File) Fd() uintptr {
	return f.fd()
}
func (f *File) fd() uintptr {
	if f == nil {
		return ^(uintptr(0))
	}
	return uintptr(f.pfd.Sysfd)
}
func (f *File) Close() error {
	if f == nil {
		return ErrInvalid
	}
	return f.file.close()
}
func (file *file) close() error {
	if file == nil {
		return syscall.EINVAL
	}
	var err error
	if e := file.pfd.Close(); e != nil {
		err = &PathError{Op: "close", Path: file.name, Err: e}
	}
	return err
}
`

const syntheticBufioSrc = `package bufio
import "io"
const defaultBufSize = 4096
type Writer struct {
	err error
	buf []byte
	n   int
	wr  io.Writer
}
func NewWriterSize(w io.Writer, size int) *Writer {
	b, ok := w.(*Writer)
	if ok && len(b.buf) >= size {
		return b
	}
	if size <= 0 {
		size = defaultBufSize
	}
	return &Writer{
		buf: make([]byte, size),
		wr:  w,
	}
}
func NewWriter(w io.Writer) *Writer {
	return NewWriterSize(w, defaultBufSize)
}
func (b *Writer) Available() int { return len(b.buf) - b.n }
func (b *Writer) Buffered() int  { return b.n }
func (b *Writer) Flush() error {
	if b.err != nil {
		return b.err
	}
	if b.n == 0 {
		return nil
	}
	n, err := b.wr.Write(b.buf[0:b.n])
	if n < b.n && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		if n > 0 && n < b.n {
			copy(b.buf[0:b.n-n], b.buf[n:b.n])
		}
		b.n -= n
		b.err = err
		return err
	}
	b.n = 0
	return nil
}
func (b *Writer) WriteByte(c byte) error {
	if b.err != nil {
		return b.err
	}
	if b.Available() <= 0 && b.Flush() != nil {
		return b.err
	}
	b.buf[b.n] = c
	b.n++
	return nil
}
func (b *Writer) WriteString(s string) (int, error) {
	var sw io.StringWriter
	tryStringWriter := true
	nn := 0
	for len(s) > b.Available() && b.err == nil {
		var n int
		if b.Buffered() == 0 && sw == nil && tryStringWriter {
			sw, tryStringWriter = b.wr.(io.StringWriter)
		}
		if b.Buffered() == 0 && tryStringWriter {
			n, b.err = sw.WriteString(s)
		} else {
			n = copy(b.buf[b.n:], s)
			b.n += n
			b.Flush()
		}
		nn += n
		s = s[n:]
	}
	if b.err != nil {
		return nn, b.err
	}
	n := copy(b.buf[b.n:], s)
	b.n += n
	nn += n
	return nn, nil
}
`

const syntheticTestdepsSrc = `package testdeps
import (
	"bufio"
	"internal/testlog"
	"io"
	"strings"
	"sync"
)
type TestDeps struct{}
type testLog struct {
	mu  sync.Mutex
	w   *bufio.Writer
	set bool
}
func (l *testLog) Getenv(key string) { l.add("getenv", key) }
func (l *testLog) Open(name string)  { l.add("open", name) }
func (l *testLog) Stat(name string)  { l.add("stat", name) }
func (l *testLog) Chdir(name string) { l.add("chdir", name) }
func (l *testLog) add(op, name string) {
	if strings.Contains(name, "\n") || name == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w == nil {
		return
	}
	l.w.WriteString(op)
	l.w.WriteByte(' ')
	l.w.WriteString(name)
	l.w.WriteByte('\n')
}
var log testLog
func (TestDeps) StartTestLog(w io.Writer) {
	log.mu.Lock()
	log.w = bufio.NewWriter(w)
	if !log.set {
		log.set = true
		testlog.SetLogger(&log)
		log.w.WriteString("# test log\n")
	}
	log.mu.Unlock()
}
func (TestDeps) StopTestLog() error {
	log.mu.Lock()
	defer log.mu.Unlock()
	err := log.w.Flush()
	log.w = nil
	return err
}
`

const syntheticTestingInlineSrc = `package testing
import (
	"context"
	"flag"
	"io"
	"os"
)
var testlog = flag.String("test.testlogfile", "", "")
type common struct{ ctx context.Context }
func (c *common) checkFuzzFn(string) {}
func (c *common) Context() context.Context { c.checkFuzzFn("Context"); return c.ctx }
type testDeps interface {
	StartTestLog(io.Writer)
	StopTestLog() error
}
type M struct {
	deps  testDeps
	tests []InternalTest
}
type InternalTest struct {
	Name string
	F    func(*T)
}
type T struct{ common }
func MainStart(d testDeps) *M { return &M{deps: d} }
func runTests(tests []InternalTest) bool {
	for _, it := range tests {
		it.F(&T{})
	}
	return true
}
func (m *M) Run() int {
	flag.Parse()
	if *testlog != "" {
		f, err := os.Create(*testlog)
		if err != nil {
			os.Exit(2)
		}
		m.deps.StartTestLog(f)
		_ = runTests(m.tests)
		if err := m.deps.StopTestLog(); err != nil {
			panic(err)
		}
		if err := f.Close(); err != nil {
			os.Exit(2)
		}
		return 0
	}
	_ = runTests(m.tests)
	return 0
}
`

const syntheticTestingSplitSrc = `package testing
import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)
var (
	initRan     bool
	testlog     *string
	matchList   *string
	cpuProfile  *string
	testlogFile *os.File
)
func Init() {
	if initRan {
		return
	}
	initRan = true
	testlog = flag.String("test.testlogfile", "", "")
	matchList = flag.String("test.list", "", "")
	cpuProfile = flag.String("test.cpuprofile", "", "")
}
type common struct{ ctx context.Context }
func (c *common) checkFuzzFn(string) {}
func (c *common) Context() context.Context { c.checkFuzzFn("Context"); return c.ctx }
type testDeps interface {
	StartTestLog(io.Writer)
	StopTestLog() error
}
type M struct {
	deps      testDeps
	tests     []InternalTest
	afterOnce sync.Once
	exitCode  int
	numRun    int
}
type InternalTest struct {
	Name string
	F    func(*T)
}
type T struct{ common }
func MainStart(d testDeps, tests []InternalTest) *M {
	Init()
	return &M{deps: d, tests: tests}
}
func runTests(tests []InternalTest) bool {
	for _, it := range tests {
		it.F(&T{})
	}
	return true
}
func (m *M) Run() (code int) {
	defer func() {
		code = m.exitCode
	}()
	m.numRun++
	if !flag.Parsed() {
		flag.Parse()
	}
	if *matchList != "" {
		m.exitCode = 0
		return
	}
	m.before()
	defer m.after()
	m.startAlarm()
	if !runTests(m.tests) {
		m.exitCode = 1
		return
	}
	m.exitCode = 0
	return
}
func (m *M) before() {
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return
		}
		_ = f.Close()
	}
	if *testlog != "" {
		f, err := os.Create(*testlog)
		if err != nil {
			os.Exit(2)
		}
		m.deps.StartTestLog(f)
		testlogFile = f
	}
}
func (m *M) after() {
	m.afterOnce.Do(func() {
		m.writeProfiles()
	})
}
func (m *M) writeProfiles() {
	if *testlog != "" {
		if err := m.deps.StopTestLog(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
		if err := testlogFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
	}
	if *cpuProfile != "" {
		coverReport()
	}
}
func coverReport() {
	if _, err := os.Create("cov"); err != nil {
		os.Exit(2)
	}
}
func (m *M) startAlarm() {
	_ = time.AfterFunc(time.Minute, func() {
		m.after()
		panic("test timed out")
	})
}
`

func mustMutateFixture(t *testing.T, src, old, new string) string {
	t.Helper()
	if !strings.Contains(src, old) {
		t.Fatalf("fixture source does not contain %q", old)
	}
	return strings.Replace(src, old, new, 1)
}

// The analyzing frontend is spelled once and every persistent memo
// scope holding a frontend derivation composes it — the three
// syntax-level scopes and the four type-level ones (through the shared
// guard key); the listing memo, the analyzed toolchain's own account,
// does not — while the closure identity excludes it by design and the
// composed identity strategy is pinned as a conscious golden, so a
// reverted bump cannot pass unseen. The source half of the pin walks the
// closure package and its internal packages for any other spelling of
// runtime.Version, allowing only the helper, the toolchain audit's own
// key sites, and the selection degradation; that half observes the
// tree, so an overlay probe never reaches it — the value half above
// carries the probe-able claims (REQ-closure-identity-strategy).
func TestMemoScopesKeyOnTheOneFrontendSpelling(t *testing.T) {
	frontend := runtime.Version()
	if AnalyzingFrontend() != frontend {
		t.Fatalf("AnalyzingFrontend = %q, want %q", AnalyzingFrontend(), frontend)
	}
	if canonicalScope() != canonicalStrategy+" "+frontend || variantParseScope() != variantParseStrategy+" "+frontend {
		t.Fatalf("syntax memo scopes %q, %q do not compose the frontend %q", canonicalScope(), variantParseScope(), frontend)
	}
	if got := (&Hasher{selectionResolved: true, source: sourceDigests{Content: "content", Policy: "policy"}}).effectScanScope(); !strings.HasPrefix(got, effectScanStrategy+" "+frontend) {
		t.Fatalf("effect scan scope %q does not compose the frontend", got)
	}
	scope := AnalysisScope{Toolchain: "go1.x", BuildConfig: "cfg", ProofStrategy: "proofs@1", FactStrategy: "facts@1", toolchainContent: "content", admissionPolicy: "policy"}
	for name, value := range map[string]string{"Proofs": scope.Proofs(), "TestingScan": scope.TestingScan(), "Facts": scope.Facts(), "Scan": scope.Scan()} {
		if !strings.Contains(value, "|"+frontend) {
			t.Errorf("type-level memo scope %s = %q does not compose the frontend", name, value)
		}
	}
	if strings.Contains(IdentityStrategy, frontend) {
		t.Fatalf("the identity strategy %q composes the analyzing frontend", IdentityStrategy)
	}
	if want := "gofresh/closure@1 gofresh/canonical-member@2 gofresh/variant-parse@2"; IdentityStrategy != want {
		t.Fatalf("the identity strategy is %q, want the composed %q — a derivation moved, or a bump was reverted; update the golden consciously", IdentityStrategy, want)
	}
	allowed := map[string]bool{"AnalyzingFrontend": true, "resolveSelection": true, "toolchainSourceScope": true, "NewAt": true}
	tracked := map[string]bool{"canonicalScope": false, "effectScanScope": false, "variantParseScope": false, "guards": false}
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != "." && !strings.HasPrefix(path, "internal") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			return err
		}
		// The whole file is walked — package-level initializers included
		// — with the enclosing function tracked, and every mention of
		// runtime.Version counts, called or not.
		var enclosing []string
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				enclosing = enclosing[:len(enclosing)-1]
				return false
			}
			name := "<package level>"
			if fn, ok := n.(*ast.FuncDecl); ok {
				name = fn.Name.Name
			} else if len(enclosing) > 0 {
				name = enclosing[len(enclosing)-1]
			}
			enclosing = append(enclosing, name)
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "runtime" && sel.Sel.Name == "Version" && !allowed[name] {
					t.Errorf("%s: %s spells runtime.Version outside the frontend helper and the toolchain audit", path, name)
				}
			}
			if call, ok := n.(*ast.CallExpr); ok {
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "AnalyzingFrontend" {
					if _, isTracked := tracked[name]; isTracked {
						tracked[name] = true
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for scope, reads := range tracked {
		if !reads {
			t.Errorf("memo scope %s does not read AnalyzingFrontend", scope)
		}
	}
}

// TestSSAHandlesDoNotInventSourceUnsafePointers exercises the iterator and
// defer-stack handles introduced by the SSA builder, beside real source
// unsafe pointers (REQ-closure-observability-unsafe).
func TestSSAHandlesDoNotInventSourceUnsafePointers(t *testing.T) {
	cases := []struct {
		name, source string
		observable   bool
	}{
		{"maprange", `package p
func Subject() int { n := 0; for k, v := range map[int]int{1: 2} { n += k+v }; return n }
`, true},
		{"stringrange", `package p
func Subject() int { n := 0; for _, r := range "abc" { n += int(r) }; return n }
`, true},
		{"deferredrange", `package p
func values(yield func(int) bool) { yield(3) }
func Subject() (n int) { for v := range values { defer func() { n += v }() }; return }
`, true},
		{"sourceunsafe", `package p
import "unsafe"
type rangeIter unsafe.Pointer
func Subject() int { n := 3; p := rangeIter(unsafe.Pointer(&n)); return *(*int)(p) }
`, false},
	}
	h := newInMemoryHasher(t)
	var subjects []Subject
	for _, tc := range cases {
		pkgPath := "example.com/ssahandles/" + tc.name
		supplyInMemoryPackage(t, h, pkgPath, map[string]map[string]string{
			pkgPath: {"p.go": tc.source},
		})
		subjects = append(subjects, Subject{Package: pkgPath, Symbol: "Subject"})
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range cases {
		p := proofs[subjects[i]]
		if p.Observable != tc.observable || !tc.observable && !strings.Contains(p.Reason, "unsafe pointer") {
			t.Errorf("%s: %+v, want observable=%v", tc.name, p, tc.observable)
		}
	}
}

func TestSSAHandleRecognitionKeepsSourceAndUnknownTypes(t *testing.T) {
	named := func(pkg, name string, underlying types.Type) types.Type {
		var p *types.Package
		if pkg != "" {
			p = types.NewPackage(pkg, "ssa")
		}
		return types.NewNamed(types.NewTypeName(token.NoPos, p, name, nil), underlying, nil)
	}
	for _, tc := range []struct {
		name string
		typ  types.Type
		want bool
	}{
		{"iterator", named("$ssa", "rangeIter", types.Typ[types.UnsafePointer]), true},
		{"defer stack", named("$ssa", "deferStack", types.Typ[types.UnsafePointer]), true},
		{"source name", named("example.com/ssa", "rangeIter", types.Typ[types.UnsafePointer]), false},
		{"unknown token", named("$ssa", "other", types.Typ[types.UnsafePointer]), false},
		{"changed representation", named("$ssa", "rangeIter", types.Typ[types.Int]), false},
		{"no package", named("", "rangeIter", types.Typ[types.UnsafePointer]), false},
		{"source pointer", types.Typ[types.UnsafePointer], false},
	} {
		if got := ssaOpaqueHandle(tc.typ); got != tc.want {
			t.Errorf("%s: handle=%v, want %v", tc.name, got, tc.want)
		}
	}
}
