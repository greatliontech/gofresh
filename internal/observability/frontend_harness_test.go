package observability

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	gobuild "go/build"
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
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/trace"
)

type (
	listMod       = gotool.ListedModule
	Closure       = closure.Closure
	AnalysisScope = closure.AnalysisScope
)

const (
	PurityResponsibility = closure.PurityResponsibility
	BlockerTestRuntime   = closure.BlockerTestRuntime
)

var (
	auditedLinknamesOnly  = closure.AuditedLinknamesOnly
	preferredEffectReason = closure.PreferredEffectReason
	implicitImportName    = closure.ImplicitImportName
)

// TestMain gives this test binary its own memo root under os.TempDir so a
// test calling SetMemoRoot("") — or constructing a Hasher without calling
// isolateProofCache — never reads or writes the developer's real
// ~/.cache/gofresh store (and never collides with a concurrent test binary
// sharing the machine). GOCACHE is resolved and pinned first so child `go`
// commands under GOENV=off keep the warm build cache rather than falling back
// into the fresh XDG_CACHE_HOME.
func TestMain(m *testing.M) {
	trace.Refresh(os.Getenv(trace.EnvTrace), os.Getenv(trace.EnvTraceFile))
	if cache, err := testenv.GoBuildCache(context.Background(), os.Environ()); err == nil && cache != "" {
		_ = os.Setenv("GOCACHE", cache)
	}
	tmp, err := os.MkdirTemp("", "gofresh-closure-test-cache-*")
	if err == nil {
		_ = os.Setenv("XDG_CACHE_HOME", tmp)
	}
	tmpRun, err := os.MkdirTemp("", "gofresh-closure-tmp-*")
	if err == nil {
		_ = os.Setenv("TMPDIR", tmpRun)
	}
	code := m.Run()
	if tmp != "" {
		_ = os.RemoveAll(tmp)
	}
	if tmpRun != "" {
		_ = os.RemoveAll(tmpRun)
	}
	testenv.CleanupShared()
	os.Exit(code)
}

func parseAndTypecheckDAG(t testing.TB, virtualDir string, filesByPkg map[string]map[string]string) []*packages.Package {
	t.Helper()
	return testenv.ParseAndTypecheckDAG(t, virtualDir, filesByPkg)
}

var (
	cachedUnixListPkgMu   sync.Mutex
	cachedUnixListPkgVal  *listPkg
	cachedUnixListPkgDone bool
)

func cachedUnixListPkgOnce() *listPkg {
	cachedUnixListPkgMu.Lock()
	defer cachedUnixListPkgMu.Unlock()
	if cachedUnixListPkgDone {
		return cachedUnixListPkgVal
	}
	cachedUnixListPkgDone = true
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
				if matched, mErr := gobuild.Default.MatchFile(dir, e.Name()); mErr == nil && matched {
					sFiles = append(sFiles, e.Name())
				}
			}
		}
	}
	modDir := filepath.Dir(dir)
	var modVersion string
	if _, after, ok := strings.Cut(filepath.Base(modDir), "@"); ok {
		modVersion = after
	}
	cachedUnixListPkgVal = &listPkg{
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
	return cachedUnixListPkgVal
}

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

func buildInMemorySSAFromFiles(ctx context.Context, virtualDir, pkgMain string, filesByPkg map[string]map[string]string) (*Program, []listPkg, []*packages.Package, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, nil, err
	}
	pkgs, resolvedDir, cleanup, err := testenv.ParseAndTypecheckDAGWithStdlibErr(os.Environ(), virtualDir, filesByPkg)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	prog, err := FromPackages(ctx, pkgMain, pkgs)
	if err != nil {
		cleanup()
		return nil, nil, nil, nil, err
	}
	prog.GOARCH = runtime.GOARCH

	mod := &listMod{
		Path: "example.com",
		Dir:  resolvedDir,
		Main: true,
	}
	if gomod := filepath.Join(resolvedDir, "go.mod"); gomod != "" {
		if _, statErr := os.Stat(gomod); statErr == nil {
			mod.GoMod = gomod
		}
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
	return prog, metas, pkgs, cleanup, nil
}

// buildInMemorySSA constructs a *program.Program, []listPkg metadata slice, and
// []*packages.Package DAG in memory from virtual file maps without spawning any
// per-test `go list` or `packages.Load` subprocess.
func buildInMemorySSA(t testing.TB, virtualDir, pkgMain string, filesByPkg map[string]map[string]string) (*Program, []listPkg, []*packages.Package) {
	t.Helper()
	if virtualDir == "" {
		virtualDir = t.TempDir()
	}
	prog, metas, pkgs, cleanup, err := buildInMemorySSAFromFiles(context.Background(), virtualDir, pkgMain, filesByPkg)
	if err != nil {
		t.Fatal(err)
	}
	if cleanup != nil {
		t.Cleanup(cleanup)
	}
	return prog, metas, pkgs
}

// supplyInMemoryPackage builds an in-memory *Program and listing for
// pkgMain from filesByPkg and registers both in h so subsequent Compute* calls
// analyze pkgMain without spawning `go list` or `packages.Load`.
func supplyInMemoryPackage(t testing.TB, h *Prover, pkgMain string, filesByPkg map[string]map[string]string) *Program {
	t.Helper()
	prog, metas, _ := buildInMemorySSA(t, "", pkgMain, filesByPkg)
	h.progs[pkgMain] = prog
	h.SetListedPackagesForTest(pkgMain, metas)
	return prog
}

type cachedRegisteredFixture struct {
	prog    *Program
	metas   []listPkg
	cleanup func()
}

func cloneRegisteredFixtureProgram(src *Program) *Program {
	cloned := *src
	cloned.PkgScopeProbe = nil
	cloned.summaries = programSummaries{}
	cloned.MutatedGlobals = nil
	cloned.GOARCH = runtime.GOARCH
	cloned.Source = nil
	cloned.SourceSnapshot = nil
	return &cloned
}

func loadRegisteredInMemoryFixture(ctx context.Context, cache map[string]cachedRegisteredFixture, pkgPath string) (*Program, []listPkg, func(), bool, error) {
	filesByPkg, ok := inMemoryFixtureRegistry[pkgPath]
	if !ok {
		return nil, nil, nil, false, nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, true, err
		}
	}
	if cache != nil {
		if cached, found := cache[pkgPath]; found {
			return cloneRegisteredFixtureProgram(cached.prog), slices.Clone(cached.metas), nil, true, nil
		}
	}
	prog, metas, _, cleanup, err := buildInMemorySSAFromFiles(ctx, "", pkgPath, filesByPkg)
	if err != nil {
		return nil, nil, nil, true, err
	}
	if cache != nil {
		cache[pkgPath] = cachedRegisteredFixture{prog: prog, metas: metas, cleanup: cleanup}
		return cloneRegisteredFixtureProgram(prog), slices.Clone(metas), nil, true, nil
	}
	return cloneRegisteredFixtureProgram(prog), slices.Clone(metas), cleanup, true, nil
}

func supplyRegisteredFixtures(t testing.TB, h *Prover, pkgPaths ...string) {
	t.Helper()
	seen := map[string]bool{}
	for _, pkgPath := range pkgPaths {
		if seen[pkgPath] {
			continue
		}
		seen[pkgPath] = true
		prog, metas, cleanup, ok, err := loadRegisteredInMemoryFixture(h.Context(), nil, pkgPath)
		if err != nil {
			t.Fatal(err)
		}
		if cleanup != nil {
			t.Cleanup(cleanup)
		}
		if ok {
			h.progs[pkgPath] = prog
			h.SetListedPackagesForTest(pkgPath, metas)
		}
	}
}

type scannedDirPkg struct {
	pkgPath       string
	pkgDir        string
	pkgName       string
	baseGo        []string
	testGo        []string
	xtestGo       []string
	hFiles        []string
	sFiles        []string
	sysoFiles     []string
	baseEmbed     []string
	testEmbed     []string
	xtestEmbed    []string
	baseImports   []string
	testImports   []string
	xtestImports  []string
	allFilesInDir map[string]string
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
func primeHasherFromDir(t testing.TB, h *Prover, dir string) {
	if t != nil {
		t.Helper()
	}
	var st *inMemoryHasherState
	if h != nil && h.loadProgramOnMiss != nil {
		_, _, _ = h.loadProgramOnMiss(nil, nil, "")
		st = newInMemoryHasherState()
		bindInMemoryHasherState(h, st)
	}
	primeHasherIntoState(t, h, dir, st)
}

func primeHasherIntoState(t testing.TB, h *Prover, dir string, st *inMemoryHasherState) {
	if t != nil {
		t.Helper()
	}
	if h == nil || h.Hasher == nil || dir == "" {
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
		Path:  modPath,
		Dir:   dir,
		GoMod: filepath.Join(dir, "go.mod"),
		Main:  true,
	}

	bctx := gobuild.Default
	if v := h.SnapshotGOOS(); v != "" {
		bctx.GOOS = v
	}
	if v := h.EffectiveGOARCH(); v != "" {
		bctx.GOARCH = v
	}
	for _, kv := range h.PackageEnv() {
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
	bflags := h.BuildFlags()
	for i := 0; i < len(bflags); i++ {
		f := bflags[i]
		if after, ok := strings.CutPrefix(f, "-tags="); ok {
			bctx.BuildTags = append(bctx.BuildTags, strings.FieldsFunc(after, func(r rune) bool { return r == ',' || r == ' ' })...)
		} else if f == "-tags" && i+1 < len(bflags) {
			i++
			bctx.BuildTags = append(bctx.BuildTags, strings.FieldsFunc(bflags[i], func(r rune) bool { return r == ',' || r == ' ' })...)
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
				if h != nil && h.Hasher != nil {
					if invDir, invFiles, ok := h.Selection().StandardPackageMeta(imp); ok {
						metas = append(metas, listPkg{
							ImportPath: imp,
							Name:       implicitImportName(imp),
							Standard:   true,
							Dir:        invDir,
							GoFiles:    invFiles,
						})
						continue
					}
				}
				metas = append(metas, listPkg{
					ImportPath: imp,
					Name:       implicitImportName(imp),
					Standard:   isStdImportPath(imp),
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
		h.SetListedPackagesForTest(targetPkg, metas)
		if pkgs, perr := testenv.ParseAndTypecheckInPlaceWithStdlib(os.Environ(), dir, targetPkgDirs, targetFilesByPkg); perr == nil {
			h.progs[targetPkg] = &program{PkgPath: targetPkg, Pkgs: pkgs}
			if st != nil {
				st.pkgs[targetPkg] = pkgs
				st.lists[targetPkg] = metas
			}
		}
	}
}

type inMemoryHasherState struct {
	pkgs     map[string][]*packages.Package
	lists    map[string][]listPkg
	fixtures map[string]cachedRegisteredFixture
}

func newInMemoryHasherState() *inMemoryHasherState {
	return &inMemoryHasherState{
		pkgs:     map[string][]*packages.Package{},
		lists:    map[string][]listPkg{},
		fixtures: map[string]cachedRegisteredFixture{},
	}
}

func (st *inMemoryHasherState) lookupPrimedPkg(h *Prover, pkgPath string) ([]*packages.Package, []listPkg, bool) {
	if st == nil || h == nil {
		return nil, nil, false
	}
	pkgs := st.pkgs[pkgPath]
	metas := st.lists[pkgPath]
	if len(metas) == 0 && h.Hasher != nil {
		metas, _ = h.LookupListedPackagesForTest(pkgPath)
	}
	return pkgs, metas, len(pkgs) > 0
}

func (st *inMemoryHasherState) cleanup() {
	if st == nil {
		return
	}
	for _, entry := range st.fixtures {
		if entry.cleanup != nil {
			entry.cleanup()
		}
	}
	clear(st.fixtures)
}

func bindInMemoryHasherState(h *Prover, st *inMemoryHasherState) {
	h.SetListOnMissForTest(func(bh *closure.Hasher, pkgPath string) ([]listPkg, bool) {
		if bh == nil && pkgPath == "" {
			st.cleanup()
			return nil, false
		}
		if bh == nil || bh.HasCustomRunner() || len(bh.BuildFlags()) > 0 {
			return nil, false
		}
		if bh.Context() != nil && bh.Context().Err() != nil {
			return nil, false
		}
		if bh.Dir() == "" {
			if _, metas, _, ok, err := loadRegisteredInMemoryFixture(bh.Context(), st.fixtures, pkgPath); ok && err == nil {
				return metas, true
			}
			return nil, false
		}
		primeHasherIntoState(nil, h, bh.Dir(), st)
		if metas, ok := bh.LookupListedPackagesForTest(pkgPath); ok {
			return metas, true
		}
		return nil, false
	})
	h.loadProgramOnMiss = func(ctx context.Context, p *Prover, pkgPath string) (*program, bool, error) {
		if p == nil && pkgPath == "" {
			st.cleanup()
			return nil, false, nil
		}
		if p == nil || p.Hasher == nil || p.HasCustomRunner() || len(p.BuildFlags()) > 0 {
			return nil, false, nil
		}
		if ctx != nil && ctx.Err() != nil {
			return nil, false, nil
		}
		if p.Dir() == "" {
			if inMemProg, metas, _, ok, err := loadRegisteredInMemoryFixture(ctx, st.fixtures, pkgPath); ok {
				if _, had := p.LookupListedPackagesForTest(pkgPath); err == nil && !had {
					p.SetListedPackagesForTest(pkgPath, metas)
				}
				return inMemProg, true, err
			}
			return nil, false, nil
		}
		pkgs, metas, ok := st.lookupPrimedPkg(p, pkgPath)
		if !ok {
			primeHasherIntoState(nil, p, p.Dir(), st)
			pkgs, metas, ok = st.lookupPrimedPkg(p, pkgPath)
		}
		if !ok || len(pkgs) == 0 {
			return nil, false, nil
		}
		built, err := FromPackages(ctx, pkgPath, pkgs)
		if _, had := p.LookupListedPackagesForTest(pkgPath); err == nil && !had && len(metas) > 0 {
			p.SetListedPackagesForTest(pkgPath, metas)
		}
		return built, true, err
	}
	h.testingPackagesOnMiss = func(p *Prover, pkgPath string) *program {
		if p == nil || p.Hasher == nil || p.HasCustomRunner() || len(p.BuildFlags()) > 0 {
			return nil
		}
		if p.Context() != nil && p.Context().Err() != nil {
			return nil
		}
		if p.Dir() == "" {
			if inMemProg, _, _, ok, err := loadRegisteredInMemoryFixture(p.Context(), st.fixtures, pkgPath); ok && err == nil {
				return inMemProg
			}
			return nil
		}
		pkgs, _, ok := st.lookupPrimedPkg(p, pkgPath)
		if !ok {
			primeHasherIntoState(nil, p, p.Dir(), st)
			pkgs, _, ok = st.lookupPrimedPkg(p, pkgPath)
		}
		if ok {
			return &program{PkgPath: pkgPath, Pkgs: pkgs}
		}
		return nil
	}
}

func markHasherEligible(h *Prover) {
	if h == nil {
		return
	}
	bindInMemoryHasherState(h, newInMemoryHasherState())
}

func unprimeHasher(h *Prover) {
	if h == nil {
		return
	}
	if h.loadProgramOnMiss != nil {
		_, _, _ = h.loadProgramOnMiss(nil, nil, "")
	}
	if h.Hasher != nil {
		h.SetListOnMissForTest(nil)
	}
	h.loadProgramOnMiss = nil
	h.testingPackagesOnMiss = nil
}

var (
	cachedHostSnapshotMu  sync.Mutex
	cachedHostSnapshotVal *gotool.EnvSnapshot
)

func cachedHostSnapshotOnce() (*gotool.EnvSnapshot, error) {
	cachedHostSnapshotMu.Lock()
	defer cachedHostSnapshotMu.Unlock()
	if cachedHostSnapshotVal != nil {
		return cachedHostSnapshotVal, nil
	}
	dir, err := os.MkdirTemp("", "gofresh-observability-env-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	snap, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), dir, os.Environ())
	if err != nil {
		return nil, err
	}
	cachedHostSnapshotVal = snap
	return snap, nil
}

func newInMemoryHasher(t testing.TB, buildFlags ...string) *Prover {
	t.Helper()
	return newInMemoryHasherAt(t, t.TempDir(), buildFlags...)
}

func newInMemoryHasherAt(t testing.TB, dir string, buildFlags ...string) *Prover {
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

func newAt(dir string, buildFlags ...string) (*Prover, error) {
	var h *Prover
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

func newAtEnv(ctx context.Context, dir string, env []string, buildFlags ...string) (*Prover, error) {
	return NewAt(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags...)
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
	cache, err := testenv.GoBuildCache(context.Background(), os.Environ())
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
func computeTier2ResultAndReach(h *Prover, pkgPath, symbol string) (tier2Result, map[string]bool, error) {
	origList, hadList := h.LookupListedPackagesForTest(pkgPath)
	_, hadProg := h.progs[pkgPath]
	defer func() {
		if !hadProg {
			if hadList {
				h.SetListedPackagesForTest(pkgPath, origList)
			} else {
				h.DeleteListedPackagesForTest(pkgPath)
			}
		}
	}()
	prog := h.progs[pkgPath]
	if prog != nil && prog.Prog == nil && len(prog.Pkgs) > 0 {
		built, err := FromPackages(h.Context(), pkgPath, prog.Pkgs)
		if err != nil {
			return tier2Result{}, nil, err
		}
		prog = built
		h.progs[pkgPath] = built
	}
	if prog == nil {
		if inMemProg, metas, cleanup, ok, err := loadRegisteredInMemoryFixture(h.Context(), nil, pkgPath); ok {
			if err != nil {
				return tier2Result{}, nil, err
			}
			if cleanup != nil {
				defer cleanup()
			}
			prog = inMemProg
			h.SetListedPackagesForTest(pkgPath, metas)
		} else if h.loadProgramOnMiss != nil {
			built, handled, err := h.loadProgramOnMiss(h.Context(), h, pkgPath)
			if handled {
				if err != nil {
					return tier2Result{}, nil, err
				}
				prog = built
			}
		}
		if prog == nil {
			var err error
			prog, err = Load(h.Context(), h.Dir(), h.PackageEnv(), h.BuildFlags(), pkgPath)
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
	metas, err := h.List(pkgPath)
	if err != nil {
		return tier2Result{}, nil, err
	}
	reachable, err := attributedReachableSets(h.Context(), true, h.PureDelegates(), prog, []Subject{{Package: pkgPath, Symbol: symbol}})
	if err != nil {
		return tier2Result{}, nil, err
	}
	result, err := tier2Reachable(h.Hasher, newTier2Base(h.Hasher, prog, metas), reachable[0])
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

func computeTier2Result(h *Prover, pkgPath, symbol string) (tier2Result, error) {
	result, _, err := computeTier2ResultAndReach(h, pkgPath, symbol)
	return result, err
}

type fixturePrograms struct {
	h        *Prover
	loaded   *program
	fixtures map[string]cachedRegisteredFixture
	// An explicit immutable roster opts into one typed generation. Preparation
	// is lazy: a table whose subtests are all filtered out loads nothing.
	roster                []string
	prepared              *Prepared
	prepareErr            error
	attempted             bool
	prepare               func(context.Context, string, []string, []string, ...string) (*Prepared, error)
	typedLoads, ssaBuilds int
}

func newFixturePrograms(t *testing.T, h *Prover, roster ...string) *fixturePrograms {
	t.Helper()
	f := &fixturePrograms{
		h:        h,
		fixtures: map[string]cachedRegisteredFixture{},
		prepare:  Prepare,
	}
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
	if f.h.Hasher != nil && f.h.Context() != nil {
		if err := f.h.Context().Err(); err != nil {
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
				if existing := f.h.progs[r]; existing != nil && (existing.Prog != nil || len(existing.Pkgs) > 0) {
					continue
				}
				if f.h.testingPackagesOnMiss != nil && f.h.testingPackagesOnMiss(f.h, r) != nil {
					continue
				}
				diskRoster = append(diskRoster, r)
			}
			if len(diskRoster) > 0 {
				f.prepared, f.prepareErr = f.prepare(f.h.Context(), f.h.Dir(), f.h.PackageEnv(), f.h.BuildFlags(), diskRoster...)
			}
		}
		if f.h.Hasher != nil && f.h.Context() != nil {
			if err := f.h.Context().Err(); err != nil {
				return err
			}
		}
		if errors.Is(f.prepareErr, context.Canceled) || errors.Is(f.prepareErr, context.DeadlineExceeded) {
			return f.prepareErr
		}
		var p *program
		var err error
		handled := false
		f.ssaBuilds++
		var ctx context.Context
		if f.h.Hasher != nil {
			ctx = f.h.Context()
		}
		if inMemProg, metas, _, ok, inMemErr := loadRegisteredInMemoryFixture(ctx, f.fixtures, pkgPath); ok {
			handled = true
			p, err = inMemProg, inMemErr
			if err == nil && f.h.Hasher != nil {
				f.h.SetListedPackagesForTest(pkgPath, metas)
			}
		} else if existing := f.h.progs[pkgPath]; existing != nil && len(existing.Pkgs) > 0 && existing.Prog == nil && f.prepareErr == nil {
			handled = true
			p, err = FromPackages(ctx, pkgPath, existing.Pkgs)
		} else if f.prepareErr == nil && f.h.loadProgramOnMiss != nil {
			if built, ok, loadErr := f.h.loadProgramOnMiss(ctx, f.h, pkgPath); ok {
				handled = true
				p, err = built, loadErr
			}
		}
		if !handled {
			if f.prepared != nil {
				p, err = f.prepared.Build(ctx, pkgPath)
			} else {
				f.typedLoads++
				p, err = Load(ctx, f.h.Dir(), f.h.PackageEnv(), f.h.BuildFlags(), pkgPath)
			}
		}
		if err != nil {
			return err
		}
		f.loaded = p
	}
	f.loaded.PkgScopeProbe = nil
	f.h.progs[pkgPath] = f.loaded
	return nil
}

func (f *fixturePrograms) releaseProgram() {
	if f.loaded != nil {
		delete(f.h.progs, f.loaded.PkgPath)
		if _, ok := inMemoryFixtureRegistry[f.loaded.PkgPath]; ok && f.h.Hasher != nil {
			f.h.DeleteListedPackagesForTest(f.loaded.PkgPath)
		}
		f.loaded = nil
	}
}

func (f *fixturePrograms) release() {
	f.releaseProgram()
	for _, entry := range f.fixtures {
		if entry.cleanup != nil {
			entry.cleanup()
		}
	}
	f.fixtures = nil
	f.prepared = nil
	f.roster = nil
	f.prepareErr = nil
}

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
	h := &Prover{Hasher: &closure.Hasher{}, progs: map[string]*program{}}
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
		if strings.Contains(effect.Reason, want) {
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
