package testenv

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
)

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
// When virtualDir is empty, a temporary directory is allocated and removed by
// the returned cleanup function (or immediately when parsing/typechecking fails).
func ParseAndTypecheckDAGWithStdlibErr(env []string, virtualDir string, filesByPkg map[string]map[string]string) ([]*packages.Package, string, func(), error) {
	cleanup := func() {}
	if virtualDir == "" {
		tmp, err := os.MkdirTemp("", "gofresh-inmem-pkg-*")
		if err != nil {
			return nil, "", nil, err
		}
		cleanup = sync.OnceFunc(func() {
			_ = os.RemoveAll(tmp)
		})
		virtualDir = tmp
	}
	pkgs, err := parseAndTypecheckDAG(env, virtualDir, nil, filesByPkg, true)
	if err != nil {
		cleanup()
		return nil, "", nil, err
	}
	return pkgs, virtualDir, cleanup, nil
}

type parsedPkgUnit struct {
	pkgPath    string
	basePath   string
	forTest    string
	pkgDir     string
	pkgName    string
	filenames  []string
	fullPaths  []string
	goFiles    []string
	otherFiles []string
	syntax     []*ast.File
	imports    []string
}

func isPackageOtherFileExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".h", ".hh", ".hpp", ".hxx", ".f", ".for", ".f90", ".s", ".swig", ".swigcxx", ".syso":
		return true
	default:
		return false
	}
}

func parseAndTypecheckDAG(env []string, virtualDir string, pkgDirs map[string]string, filesByPkg map[string]map[string]string, linkStdlib bool) ([]*packages.Package, error) {
	var stdCache *stdlibMetaCache
	if linkStdlib {
		var err error
		stdCache, err = getStdlibMetaCache(env)
		if err != nil {
			return nil, fmt.Errorf("getStdlibMetaCache: %w", err)
		}
	}
	fset := token.NewFileSet()

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
		var otherFiles []string
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
			if strings.Contains(name, "/") {
				continue
			}
			if !strings.HasSuffix(name, ".go") {
				if isPackageOtherFileExt(filepath.Ext(name)) {
					otherFiles = append(otherFiles, fullPath)
				}
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
			if !strings.HasSuffix(uPath, "_test") {
				u.otherFiles = otherFiles
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
	typesByPath := make(map[string]*types.Package, len(ordered)+64)
	typesByPath["unsafe"] = types.Unsafe
	fallbackImp := newLocalExportImporter()
	var dagStdPkgs map[string]*packages.Package
	var dagStdHeaders map[string]*packages.Package
	if linkStdlib {
		userImports := make(map[string]bool)
		for _, u := range ordered {
			for _, impPath := range u.imports {
				userImports[impPath] = true
			}
		}
		active := stdCache.activeStdlibForImports(userImports)
		var err error
		dagStdPkgs, dagStdHeaders, err = stdCache.materialize(fset, typesByPath, active, fallbackImp)
		if err != nil {
			return nil, err
		}
	} else {
		dagStdHeaders = map[string]*packages.Package{
			"unsafe": {
				ID:      "unsafe",
				Name:    "unsafe",
				PkgPath: "unsafe",
				Types:   types.Unsafe,
				Fset:    fset,
			},
		}
	}

	imp := stdCache.newStdImporter(fset, typesByPath, dagStdHeaders, fallbackImp)

	var dagSizes types.Sizes
	if stdCache != nil {
		dagSizes = stdCache.typesSizes()
	} else {
		dagSizes = effectiveTypesSizes(env)
	}
	result := make([]*packages.Package, 0, len(ordered))
	for _, u := range ordered {
		info := newTypesInfo()
		tpkg := types.NewPackage(u.pkgPath, u.pkgName)
		conf := &types.Config{
			Importer: imp,
			Sizes:    dagSizes,
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
			if sp, ok := dagStdPkgs[impPath]; ok {
				importsMap[impPath] = sp
				continue
			}
			if sp, ok := dagStdHeaders[impPath]; ok {
				importsMap[impPath] = sp
				continue
			}
			if tp, err := imp.Import(impPath); err == nil {
				if sp, ok := dagStdHeaders[impPath]; ok {
					importsMap[impPath] = sp
					continue
				}
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
			OtherFiles:      u.otherFiles,
			Syntax:          u.syntax,
			Types:           tpkg,
			TypesInfo:       info,
			TypesSizes:      dagSizes,
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
