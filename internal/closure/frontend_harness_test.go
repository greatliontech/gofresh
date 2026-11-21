package closure

import (
	"context"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
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
	"fmt"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/cprep"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/toolchain"
	"github.com/greatliontech/gofresh/internal/trace"
)

type (
	externalEffect     = ExternalEffect
	externalEffectKind = ExternalEffectKind
	maximalEffectScan  = MaximalEffectScan
	funcDeclKey        = FuncDeclKey
	pkgVarKey          = PkgVarKey
)

const (
	externalEffectOpaque             = ExternalEffectOpaque
	externalEffectStandardInput      = ExternalEffectStandardInput
	externalEffectFormattedOutput    = ExternalEffectFormattedOutput
	externalEffectEnvironment        = ExternalEffectEnvironment
	externalEffectFileIO             = ExternalEffectFileIO
	externalEffectFilesystemMutation = ExternalEffectFilesystemMutation
	externalEffectPathMutation       = ExternalEffectPathMutation
	externalEffectTestRuntime        = ExternalEffectTestRuntime
	externalEffectNetwork            = ExternalEffectNetwork
	externalEffectPlugin             = ExternalEffectPlugin
	externalEffectNative             = ExternalEffectNative
	externalEffectLinkage            = ExternalEffectLinkage
	externalEffectUnauditedStandard  = ExternalEffectUnauditedStandard
)

var (
	opaqueExternalEffect        = OpaqueExternalEffect
	symbolExternalEffect        = SymbolExternalEffect
	unauditedStandardEffect     = UnauditedStandardEffect
	appendExternalEffect        = AppendExternalEffect
	effectCauseRank             = EffectCauseRank
	effectLess                  = EffectLess
	preferEffectReason          = PreferEffectReason
	preferredEffectReason       = PreferredEffectReason
	classBEffect                = ClassBEffect
	classBReason                = ClassBReason
	classBPureStandard          = ClassBPureStandard
	auditedStandardSymbol                = AuditedStandardSymbol
	admittedPureStandardOrDelegateSymbol = AdmittedPureStandardOrDelegateSymbol
	hasRawGoLinkname                     = cprep.HasRawGoLinkname
	isSourceOnlyStandardPackage = IsSourceOnlyStandardPackage
	isStandardFallbackExempt    = IsStandardFallbackExempt
	fmtFprintFamily             = FmtFprintFamily
	fmtFscanFamily              = FmtFscanFamily
	flagRegistrationSymbol      = FlagRegistrationSymbol
	isCompileTimeUnsafeIntrinsic = IsCompileTimeUnsafeIntrinsic
	propertyHarnessFact         = PropertyHarnessFact
	isPropertyHarnessFact       = IsPropertyHarnessFact
	maximalObservabilityBlocker = MaximalObservabilityBlocker
	hasExternalCgo              = HasExternalCgo
	hasExternalCgoMeta          = HasExternalCgoMeta
	listPkgHasNativeOrEmbed     = ListPkgHasNativeOrEmbed
	isStdImportPath             = syntaxutil.IsStandardLibraryPkgPath
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
func primeHasherFromDir(t testing.TB, h *Hasher, dir string) {
	if t != nil {
		t.Helper()
	}
	var st *inMemoryHasherState
	if h != nil && h.listOnMiss != nil {
		h.listOnMiss(nil, "")
		st = newInMemoryHasherState()
		bindInMemoryHasherState(h, st)
	}
	primeHasherIntoState(t, h, dir, st)
}

func primeHasherIntoState(t testing.TB, h *Hasher, dir string, st *inMemoryHasherState) {
	if t != nil {
		t.Helper()
	}
	if h == nil || dir == "" {
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
				if h != nil {
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
		h.lists[targetPkg] = metas
		if pkgs, perr := testenv.ParseAndTypecheckInPlaceWithStdlib(os.Environ(), dir, targetPkgDirs, targetFilesByPkg); perr == nil {
			if st != nil {
				st.pkgs[targetPkg] = pkgs
				st.lists[targetPkg] = metas
			}
		}
	}
}

type inMemoryHasherState struct {
	pkgs  map[string][]*packages.Package
	lists map[string][]listPkg
}

func newInMemoryHasherState() *inMemoryHasherState {
	return &inMemoryHasherState{
		pkgs:  map[string][]*packages.Package{},
		lists: map[string][]listPkg{},
	}
}

func (st *inMemoryHasherState) lookupPrimedPkg(h *Hasher, pkgPath string) ([]*packages.Package, []listPkg, bool) {
	if st == nil || h == nil {
		return nil, nil, false
	}
	pkgs := st.pkgs[pkgPath]
	metas := st.lists[pkgPath]
	if len(metas) == 0 && h.lists != nil {
		metas = h.lists[pkgPath]
	}
	return pkgs, metas, len(pkgs) > 0
}

func (st *inMemoryHasherState) cleanup() {
	if st == nil {
		return
	}
	clear(st.pkgs)
	clear(st.lists)
}

func bindInMemoryHasherState(h *Hasher, st *inMemoryHasherState) {
	h.listOnMiss = func(h *Hasher, pkgPath string) ([]listPkg, bool) {
		if h == nil && pkgPath == "" {
			st.cleanup()
			return nil, false
		}
		if h == nil || h.runner.Prepare != nil || len(h.buildFlags) > 0 || h.dir == "" {
			return nil, false
		}
		if h.ctx != nil && h.ctx.Err() != nil {
			return nil, false
		}
		primeHasherIntoState(nil, h, h.dir, st)
		if metas, ok := h.lists[pkgPath]; ok {
			return metas, true
		}
		return nil, false
	}
	h.SetLoadedPackagesLookup(func(pkgPath string) []*packages.Package {
		if h == nil || h.runner.Prepare != nil || len(h.buildFlags) > 0 || h.dir == "" {
			return nil
		}
		if h.ctx != nil && h.ctx.Err() != nil {
			return nil
		}
		if pkgPath == "" {
			for _, pkgs := range st.pkgs {
				if len(pkgs) > 0 {
					return pkgs
				}
			}
			return nil
		}
		pkgs, _, ok := st.lookupPrimedPkg(h, pkgPath)
		if !ok {
			primeHasherIntoState(nil, h, h.dir, st)
			pkgs, _, ok = st.lookupPrimedPkg(h, pkgPath)
		}
		if ok {
			return pkgs
		}
		return nil
	})
}

func markHasherEligible(h *Hasher) {
	if h == nil {
		return
	}
	bindInMemoryHasherState(h, newInMemoryHasherState())
}

func unprimeHasher(h *Hasher) {
	if h == nil {
		return
	}
	if h.listOnMiss != nil {
		h.listOnMiss(nil, "")
	}
	h.listOnMiss = nil
	h.SetLoadedPackagesLookup(nil)
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
	dir, err := os.MkdirTemp("", "gofresh-closure-env-*")
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
	if toolchain.AnalyzingFrontend() != frontend {
		t.Fatalf("AnalyzingFrontend = %q, want %q", toolchain.AnalyzingFrontend(), frontend)
	}
	if canonicalScope() != canonicalStrategy+" "+frontend || variantParseScope() != variantParseStrategy+" "+frontend {
		t.Fatalf("syntax memo scopes %q, %q do not compose the frontend %q", canonicalScope(), variantParseScope(), frontend)
	}
	if got := (&Hasher{selection: toolchain.SelectionForTest(true, "", "", "content", "policy", nil, nil)}).effectScanScope(); !strings.HasPrefix(got, effectScanStrategy+" "+frontend) {
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
	if want := "gofresh/closure@2 gofresh/canonical-member@3 gofresh/variant-parse@2"; IdentityStrategy != want {
		t.Fatalf("the identity strategy is %q, want the composed %q — a derivation moved, or a bump was reverted; update the golden consciously", IdentityStrategy, want)
	}
	allowed := map[string]bool{"AnalyzingFrontend": true, "resolveSelection": true, "toolchainSourceScope": true, "NewAt": true}
	tracked := map[string]bool{"canonicalScope": false, "effectScanScope": false, "variantParseScope": false, "guards": false}
	fset := token.NewFileSet()
	for _, root := range []string{".", "../toolchain", "../observability"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
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
					calledFrontend := false
					switch fn := call.Fun.(type) {
					case *ast.Ident:
						calledFrontend = fn.Name == "AnalyzingFrontend"
					case *ast.SelectorExpr:
						calledFrontend = fn.Sel.Name == "AnalyzingFrontend"
					}
					if calledFrontend {
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
	}
	for scope, reads := range tracked {
		if !reads {
			t.Errorf("memo scope %s does not read AnalyzingFrontend", scope)
		}
	}
}

