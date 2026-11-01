package testenv

import (
	"context"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/gotool"
)

var preloadedStdlibRoots = []string{
	"archive/zip",
	"bufio",
	"bytes",
	"cmp",
	"context",
	"crypto",
	"crypto/fips140",
	"crypto/rand",
	"crypto/sha1",
	"crypto/sha256",
	"crypto/sha3",
	"embed",
	"encoding/base32",
	"encoding/base64",
	"encoding/binary",
	"encoding/hex",
	"encoding/json",
	"errors",
	"flag",
	"fmt",
	"go/ast",
	"go/constant",
	"go/format",
	"go/importer",
	"go/parser",
	"go/scanner",
	"go/token",
	"go/types",
	"go/version",
	"golang.org/x/sys/unix",
	"hash",
	"hash/crc32",
	"html/template",
	"image/color",
	"io",
	"io/fs",
	"log",
	"maps",
	"math",
	"math/big",
	"math/rand",
	"math/rand/v2",
	"net",
	"net/http",
	"net/url",
	"os",
	"os/exec",
	"path",
	"path/filepath",
	"reflect",
	"regexp",
	"runtime",
	"runtime/debug",
	"runtime/pprof",
	"slices",
	"sort",
	"strconv",
	"strings",
	"sync",
	"sync/atomic",
	"syscall",
	"testing",
	"testing/fstest",
	"testing/iotest",
	"testing/quick",
	"text/template",
	"time",
	"unicode",
	"unicode/utf16",
	"unicode/utf8",
	"unsafe",
}

type stdlibCache struct {
	fset   *token.FileSet
	byPath map[string]*packages.Package
}

var (
	cachedStdlibMu  sync.Mutex
	cachedStdlibVal *stdlibCache
)

func getStdlibCache(baseEnv []string) (*stdlibCache, error) {
	cachedStdlibMu.Lock()
	defer cachedStdlibMu.Unlock()
	if cachedStdlibVal != nil {
		return cachedStdlibVal, nil
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("testenv: runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	env, err := gotool.PreserveBuildCache(context.Background(), baseEnv)
	if err != nil {
		return nil, err
	}
	roots, err := gotool.LoadPackages(
		context.Background(),
		packages.LoadAllSyntax|packages.NeedModule|packages.NeedForTest,
		repoRoot,
		env,
		nil,
		preloadedStdlibRoots...,
	)
	if err != nil {
		return nil, err
	}
	var fset *token.FileSet
	byPath := make(map[string]*packages.Package, 256)
	isHeaderOnlyStdPkg := func(path string) bool {
		if strings.Contains(path, ".") {
			return false
		}
		switch path {
		case "slices", "maps", "cmp", "sync", "io", "context", "testing", "fmt", "errors", "strings", "bytes",
			"reflect", "path/filepath", "crypto/sha1", "crypto/sha256", "crypto/internal/fips140/sha256",
			"text/template", "sort":
			return false
		default:
			return true
		}
	}
	packages.Visit(roots, nil, func(p *packages.Package) {
		if fset == nil && p.Fset != nil {
			fset = p.Fset
		}
		if p.PkgPath != "" && p.ForTest == "" && !strings.HasSuffix(p.PkgPath, ".test") && !strings.HasSuffix(p.PkgPath, "_test") && !strings.Contains(p.ID, " [") {
			if isHeaderOnlyStdPkg(p.PkgPath) {
				byPath[p.PkgPath] = &packages.Package{
					ID:      p.ID,
					Name:    p.Name,
					PkgPath: p.PkgPath,
					Types:   p.Types,
					Fset:    p.Fset,
				}
			} else {
				byPath[p.PkgPath] = p
			}
		}
	})
	for _, p := range byPath {
		if len(p.Imports) == 0 {
			continue
		}
		for impPath := range p.Imports {
			if replacement, ok := byPath[impPath]; ok {
				p.Imports[impPath] = replacement
			}
		}
	}
	if byPath["unsafe"] == nil {
		byPath["unsafe"] = &packages.Package{
			ID:      "unsafe",
			Name:    "unsafe",
			PkgPath: "unsafe",
			Types:   types.Unsafe,
			Fset:    fset,
		}
	}
	cachedStdlibVal = &stdlibCache{fset: fset, byPath: byPath}
	return cachedStdlibVal, nil
}

// CachedStdlibPackageErr returns the pre-loaded *packages.Package for a
// standard library package (or golang.org/x/sys/unix) from the process-wide
// in-memory cache.
func CachedStdlibPackageErr(env []string, pkgPath string) (*packages.Package, error) {
	cache, err := getStdlibCache(env)
	if err != nil {
		return nil, err
	}
	return cache.byPath[pkgPath], nil
}

// CachedStdlibPackage returns the pre-loaded *packages.Package for a standard
// library package (or golang.org/x/sys/unix) from the process-wide in-memory cache.
func CachedStdlibPackage(t testing.TB, env []string, pkgPath string) *packages.Package {
	t.Helper()
	pkg, err := CachedStdlibPackageErr(env, pkgPath)
	if err != nil {
		t.Fatalf("CachedStdlibPackage: %v", err)
	}
	return pkg
}

var (
	defaultImporterMu    sync.Mutex
	defaultImporterCache = map[string]*types.Package{}
	baseDefaultImporter  = importer.Default()
)

func cachedExportImporter(path string) (*types.Package, error) {
	if path == "unsafe" {
		return types.Unsafe, nil
	}
	defaultImporterMu.Lock()
	defer defaultImporterMu.Unlock()
	if pkg, ok := defaultImporterCache[path]; ok {
		return pkg, nil
	}
	pkg, err := baseDefaultImporter.Import(path)
	if err != nil {
		return nil, err
	}
	defaultImporterCache[path] = pkg
	return pkg, nil
}

type mapImporterFunc func(path string) (*types.Package, error)

func (f mapImporterFunc) Import(path string) (*types.Package, error) {
	return f(path)
}

// ParseAndTypecheckDAG parses and type-checks a multi-package DAG of in-memory
// Go source files without invoking any `go` subprocess, returning topological
// *packages.Package nodes suitable for AST and go/types analyses (such as
// internal/dynstate).
func ParseAndTypecheckDAG(t testing.TB, virtualDir string, filesByPkg map[string]map[string]string) []*packages.Package {
	t.Helper()
	if virtualDir == "" {
		virtualDir = t.TempDir()
	}
	pkgs, err := parseAndTypecheckDAG(nil, virtualDir, nil, filesByPkg, false)
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

// ParseAndTypecheckInPlace parses and type-checks an on-disk module directory
// whose files have already been read into filesByPkg and whose per-package
// directories are recorded in pkgDirs, without writing files or invoking any
// `go` subprocess.
func ParseAndTypecheckInPlace(moduleDir string, pkgDirs map[string]string, filesByPkg map[string]map[string]string) ([]*packages.Package, error) {
	return parseAndTypecheckDAG(nil, moduleDir, pkgDirs, filesByPkg, false)
}

// ParseAndTypecheckInPlaceWithStdlib parses and type-checks an on-disk module
// directory in place linked against the process-wide cached standard library
// *packages.Package graph, without writing files or invoking any `go` subprocess.
func ParseAndTypecheckInPlaceWithStdlib(env []string, moduleDir string, pkgDirs map[string]string, filesByPkg map[string]map[string]string) ([]*packages.Package, error) {
	return parseAndTypecheckDAG(env, moduleDir, pkgDirs, filesByPkg, true)
}

// ParseAndTypecheckDAGWithStdlib parses and type-checks a multi-package DAG of
// in-memory Go source files linked against the process-wide cached standard
// library *packages.Package graph, returning *packages.Package nodes suitable
// for whole-program SSA construction via program.FromPackages.
func ParseAndTypecheckDAGWithStdlib(t testing.TB, env []string, virtualDir string, filesByPkg map[string]map[string]string) []*packages.Package {
	t.Helper()
	if virtualDir == "" {
		virtualDir = t.TempDir()
	}
	pkgs, err := parseAndTypecheckDAG(env, virtualDir, nil, filesByPkg, true)
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

// ParseAndTypecheckDAGWithStdlibErr is the error-returning form of
// ParseAndTypecheckDAGWithStdlib for callers without a testing.TB handle.
// When virtualDir is empty, a temporary directory is allocated and registered
// for removal by CleanupShared.
func ParseAndTypecheckDAGWithStdlibErr(env []string, virtualDir string, filesByPkg map[string]map[string]string) ([]*packages.Package, string, error) {
	if virtualDir == "" {
		tmp, err := os.MkdirTemp("", "gofresh-inmem-pkg-*")
		if err != nil {
			return nil, "", err
		}
		sharedOverlaysMu.Lock()
		sharedOverlayDirs = append(sharedOverlayDirs, tmp)
		sharedOverlaysMu.Unlock()
		virtualDir = tmp
	}
	pkgs, err := parseAndTypecheckDAG(env, virtualDir, nil, filesByPkg, true)
	if err != nil {
		return nil, "", err
	}
	return pkgs, virtualDir, nil
}

type parsedPkgUnit struct {
	pkgPath   string
	basePath  string
	forTest   string
	pkgDir    string
	pkgName   string
	filenames []string
	fullPaths []string
	goFiles   []string
	syntax    []*ast.File
	imports   []string
}

func parseAndTypecheckDAG(env []string, virtualDir string, pkgDirs map[string]string, filesByPkg map[string]map[string]string, linkStdlib bool) ([]*packages.Package, error) {
	var fset *token.FileSet
	var stdCache *stdlibCache
	if linkStdlib {
		var err error
		stdCache, err = getStdlibCache(env)
		if err != nil {
			return nil, fmt.Errorf("getStdlibCache: %w", err)
		}
		fset = stdCache.fset
	} else {
		fset = token.NewFileSet()
	}

	rawPkgPaths := make([]string, 0, len(filesByPkg))
	for pkgPath := range filesByPkg {
		rawPkgPaths = append(rawPkgPaths, pkgPath)
	}
	slices.Sort(rawPkgPaths)

	unitsByPath := make(map[string]*parsedPkgUnit, len(rawPkgPaths))
	var unitPaths []string

	addUnit := func(u *parsedPkgUnit) {
		if _, exists := unitsByPath[u.pkgPath]; !exists {
			unitPaths = append(unitPaths, u.pkgPath)
		}
		unitsByPath[u.pkgPath] = u
	}

	for _, pkgPath := range rawPkgPaths {
		fileMap := filesByPkg[pkgPath]
		basePath := strings.TrimSuffix(pkgPath, "_test")
		pkgDir := pkgDirs[basePath]
		if pkgDir == "" {
			pkgDir = filepath.Join(virtualDir, filepath.FromSlash(basePath))
			if err := os.MkdirAll(pkgDir, 0o755); err != nil {
				return nil, fmt.Errorf("MkdirAll(%s): %w", pkgDir, err)
			}
		}
		names := make([]string, 0, len(fileMap))
		for name := range fileMap {
			names = append(names, name)
		}
		slices.Sort(names)

		type parsedFile struct {
			name     string
			fullPath string
			astFile  *ast.File
		}
		var primaryFiles, extTestFiles []parsedFile
		for _, name := range names {
			src := fileMap[name]
			fullPath := filepath.Join(pkgDir, name)
			if pkgDirs == nil {
				if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
					return nil, fmt.Errorf("MkdirAll(%s): %w", filepath.Dir(fullPath), err)
				}
				if err := os.WriteFile(fullPath, []byte(src), 0o644); err != nil {
					return nil, fmt.Errorf("WriteFile(%s): %w", fullPath, err)
				}
			}
			if !strings.HasSuffix(name, ".go") || strings.Contains(name, "/") {
				continue
			}
			af, err := parser.ParseFile(fset, fullPath, src, parser.ParseComments)
			if err != nil {
				return nil, fmt.Errorf("ParseFile(%s/%s): %w", pkgPath, name, err)
			}
			pf := parsedFile{name: name, fullPath: fullPath, astFile: af}
			if !strings.HasSuffix(pkgPath, "_test") && strings.HasSuffix(af.Name.Name, "_test") {
				extTestFiles = append(extTestFiles, pf)
			} else {
				primaryFiles = append(primaryFiles, pf)
			}
		}
		buildUnit := func(uPath string, pfs []parsedFile, hasSiblingExt bool) (*parsedPkgUnit, error) {
			u := &parsedPkgUnit{
				pkgPath:  uPath,
				basePath: basePath,
				pkgDir:   pkgDir,
			}
			hasTestFile := hasSiblingExt || strings.HasSuffix(uPath, "_test")
			impSet := map[string]bool{}
			for _, pf := range pfs {
				if u.pkgName == "" {
					u.pkgName = pf.astFile.Name.Name
				}
				if strings.HasSuffix(pf.name, "_test.go") {
					hasTestFile = true
				}
				u.filenames = append(u.filenames, pf.name)
				u.fullPaths = append(u.fullPaths, pf.fullPath)
				if !strings.HasSuffix(pf.name, "_test.go") {
					u.goFiles = append(u.goFiles, pf.fullPath)
				}
				u.syntax = append(u.syntax, pf.astFile)
				for _, spec := range pf.astFile.Imports {
					imp, err := strconv.Unquote(spec.Path.Value)
					if err != nil {
						return nil, fmt.Errorf("unquote import in %s/%s: %w", uPath, pf.name, err)
					}
					impSet[imp] = true
				}
			}
			for imp := range impSet {
				u.imports = append(u.imports, imp)
			}
			slices.Sort(u.imports)
			if hasTestFile {
				u.forTest = basePath
			}
			return u, nil
		}
		if len(primaryFiles) > 0 {
			u, err := buildUnit(pkgPath, primaryFiles, pkgDirs == nil && len(extTestFiles) > 0)
			if err != nil {
				return nil, err
			}
			addUnit(u)
		}
		if len(extTestFiles) > 0 {
			u, err := buildUnit(pkgPath+"_test", extTestFiles, true)
			if err != nil {
				return nil, err
			}
			addUnit(u)
		}
	}

	if pkgDirs == nil {
		// Ensure sibling package knows about explicitly keyed pkgPath+"_test".
		for _, uPath := range unitPaths {
			if strings.HasSuffix(uPath, "_test") {
				base := strings.TrimSuffix(uPath, "_test")
				if primary, ok := unitsByPath[base]; ok {
					primary.forTest = base
				}
			}
		}
	}

	// Topological sort over unitPaths.
	var ordered []*parsedPkgUnit
	state := make(map[string]int, len(unitPaths)) // 0=unvisited, 1=visiting, 2=visited
	var visit func(string) error
	visit = func(uPath string) error {
		switch state[uPath] {
		case 2:
			return nil
		case 1:
			return fmt.Errorf("ParseAndTypecheckDAG: import cycle involving %s", uPath)
		}
		state[uPath] = 1
		u := unitsByPath[uPath]
		for _, imp := range u.imports {
			if _, ok := unitsByPath[imp]; ok {
				if err := visit(imp); err != nil {
					return err
				}
			}
		}
		state[uPath] = 2
		ordered = append(ordered, u)
		return nil
	}
	slices.Sort(unitPaths)
	for _, uPath := range unitPaths {
		if err := visit(uPath); err != nil {
			return nil, err
		}
	}

	builtByPath := make(map[string]*packages.Package, len(ordered))
	typesByPath := make(map[string]*types.Package, len(ordered))

	imp := mapImporterFunc(func(path string) (*types.Package, error) {
		if tp, ok := typesByPath[path]; ok {
			return tp, nil
		}
		if linkStdlib {
			if sp, ok := stdCache.byPath[path]; ok && sp.Types != nil {
				return sp.Types, nil
			}
		}
		return cachedExportImporter(path)
	})

	result := make([]*packages.Package, 0, len(ordered))
	for _, u := range ordered {
		info := &types.Info{
			Types:        make(map[ast.Expr]types.TypeAndValue),
			Defs:         make(map[*ast.Ident]types.Object),
			Uses:         make(map[*ast.Ident]types.Object),
			Implicits:    make(map[ast.Node]types.Object),
			Instances:    make(map[*ast.Ident]types.Instance),
			Scopes:       make(map[ast.Node]*types.Scope),
			Selections:   make(map[*ast.SelectorExpr]*types.Selection),
			FileVersions: make(map[*ast.File]string),
		}
		tpkg := types.NewPackage(u.pkgPath, u.pkgName)
		conf := &types.Config{
			Importer: imp,
		}
		if err := types.NewChecker(conf, fset, tpkg, info).Files(u.syntax); err != nil {
			return nil, fmt.Errorf("typecheck %s: %w", u.pkgPath, err)
		}
		typesByPath[u.pkgPath] = tpkg

		id := u.pkgPath
		if u.forTest != "" {
			id = fmt.Sprintf("%s [%s.test]", u.pkgPath, u.forTest)
		}
		importsMap := make(map[string]*packages.Package, len(u.imports))
		for _, impPath := range u.imports {
			if dep, ok := builtByPath[impPath]; ok {
				importsMap[impPath] = dep
				continue
			}
			if linkStdlib {
				if sp, ok := stdCache.byPath[impPath]; ok {
					importsMap[impPath] = sp
					continue
				}
			}
			if tp, err := imp.Import(impPath); err == nil {
				importsMap[impPath] = &packages.Package{
					ID:      impPath,
					Name:    tp.Name(),
					PkgPath: impPath,
					Types:   tp,
					Fset:    fset,
				}
			}
		}
		pkg := &packages.Package{
			ID:              id,
			Name:            u.pkgName,
			PkgPath:         u.pkgPath,
			Dir:             u.pkgDir,
			ForTest:         u.forTest,
			GoFiles:         u.goFiles,
			CompiledGoFiles: u.fullPaths,
			Syntax:          u.syntax,
			Types:           tpkg,
			TypesInfo:       info,
			TypesSizes:      types.SizesFor("gc", runtime.GOARCH),
			Fset:            fset,
			Imports:         importsMap,
			Module: &packages.Module{
				Path: u.basePath,
				Main: true,
				Dir:  virtualDir,
			},
		}
		builtByPath[u.pkgPath] = pkg
		result = append(result, pkg)
	}
	return result, nil
}
