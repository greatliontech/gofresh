package testenv

import (
	"bytes"
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
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/go-x-tools/go/gcexportdata"
	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/gotool"
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

type stdlibSourceFile struct {
	path    string
	content string
}

type stdlibPkgMeta struct {
	id            string
	name          string
	pkgPath       string
	goFiles       []string
	compiledPaths []string
	compiledFiles []stdlibSourceFile
	imports       []string
}

type stdlibMetaCache struct {
	byPath      map[string]stdlibPkgMeta
	topoOrder   []string
	goarch      string
	exportMu    sync.RWMutex
	exportBytes map[string][]byte
}

func (c *stdlibMetaCache) typesSizes() types.Sizes {
	if c != nil && c.goarch != "" {
		if sz := types.SizesFor("gc", c.goarch); sz != nil {
			return sz
		}
	}
	return types.SizesFor("gc", runtime.GOARCH)
}

func effectiveGOARCH(env []string) string {
	if arch, _ := gotool.LookupEnv(env, "GOARCH"); arch != "" {
		return arch
	}
	return runtime.GOARCH
}

func effectiveTypesSizes(env []string) types.Sizes {
	if sz := types.SizesFor("gc", effectiveGOARCH(env)); sz != nil {
		return sz
	}
	return types.SizesFor("gc", runtime.GOARCH)
}

func stdlibEnvCacheKey(normalizedEnv []string) string {
	var b strings.Builder
	for _, key := range []string{
		"PATH",
		"GOROOT",
		"GOTOOLCHAIN",
		"GOOS",
		"GOARCH",
		"CGO_ENABLED",
		"GOEXPERIMENT",
		"GOFLAGS",
		"GOAMD64",
		"GOARM",
		"GOARM64",
	} {
		val, _ := gotool.LookupEnv(normalizedEnv, key)
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(val)
		b.WriteByte('\x00')
	}
	return b.String()
}

var (
	cachedStdlibMu    sync.Mutex
	cachedStdlibByEnv = map[string]*stdlibMetaCache{}
)

func isFullCandidateStdPkg(path string) bool {
	if strings.Contains(path, ".") {
		return true
	}
	if strings.HasPrefix(path, "encoding/json") || strings.HasPrefix(path, "crypto/") {
		return true
	}
	switch path {
	case "slices", "maps", "cmp", "sync", "sync/atomic", "io", "context", "testing", "fmt", "errors", "strings", "bytes",
		"reflect", "path/filepath", "crypto", "text/template", "sort", "strconv", "internal/strconv":
		return true
	default:
		return false
	}
}

func getStdlibMetaCache(baseEnv []string) (*stdlibMetaCache, error) {
	env, err := PreserveBuildCache(context.Background(), baseEnv)
	if err != nil {
		return nil, err
	}
	cacheKey := stdlibEnvCacheKey(env)
	cachedStdlibMu.Lock()
	defer cachedStdlibMu.Unlock()
	if cached, ok := cachedStdlibByEnv[cacheKey]; ok && cached != nil {
		return cached, nil
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("testenv: runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	roots, err := gotool.LoadPackages(
		context.Background(),
		packages.NeedName|packages.NeedFiles|packages.NeedCompiledGoFiles|packages.NeedImports|packages.NeedDeps|packages.NeedModule|packages.NeedForTest,
		repoRoot,
		env,
		nil,
		preloadedStdlibRoots...,
	)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]stdlibPkgMeta, 256)
	var visitErr error
	packages.Visit(roots, nil, func(p *packages.Package) {
		if visitErr != nil || p.PkgPath == "" || p.ForTest != "" || strings.HasSuffix(p.PkgPath, ".test") || strings.HasSuffix(p.PkgPath, "_test") || strings.Contains(p.ID, " [") {
			return
		}
		var imps []string
		for impPath := range p.Imports {
			imps = append(imps, impPath)
		}
		slices.Sort(imps)
		var compiled []stdlibSourceFile
		if isFullCandidateStdPkg(p.PkgPath) {
			compiled = make([]stdlibSourceFile, 0, len(p.CompiledGoFiles))
			for _, fpath := range p.CompiledGoFiles {
				raw, rerr := os.ReadFile(fpath)
				if rerr != nil {
					visitErr = fmt.Errorf("ReadFile(%s): %w", fpath, rerr)
					return
				}
				compiled = append(compiled, stdlibSourceFile{path: fpath, content: string(raw)})
			}
		}
		byPath[p.PkgPath] = stdlibPkgMeta{
			id:            p.ID,
			name:          p.Name,
			pkgPath:       p.PkgPath,
			goFiles:       slices.Clone(p.GoFiles),
			compiledPaths: slices.Clone(p.CompiledGoFiles),
			compiledFiles: compiled,
			imports:       imps,
		}
	})
	if visitErr != nil {
		return nil, visitErr
	}
	if _, ok := byPath["unsafe"]; !ok {
		byPath["unsafe"] = stdlibPkgMeta{
			id:      "unsafe",
			name:    "unsafe",
			pkgPath: "unsafe",
		}
	}
	allPaths := make([]string, 0, len(byPath))
	for p := range byPath {
		allPaths = append(allPaths, p)
	}
	slices.Sort(allPaths)
	visited := make(map[string]bool, len(byPath))
	var topo []string
	var walk func(string)
	walk = func(p string) {
		if visited[p] {
			return
		}
		visited[p] = true
		meta, ok := byPath[p]
		if !ok {
			return
		}
		for _, imp := range meta.imports {
			walk(imp)
		}
		topo = append(topo, p)
	}
	for _, p := range allPaths {
		walk(p)
	}
	entry := &stdlibMetaCache{
		byPath:      byPath,
		topoOrder:   topo,
		goarch:      effectiveGOARCH(env),
		exportBytes: map[string][]byte{},
	}
	cachedStdlibByEnv[cacheKey] = entry
	return entry, nil
}

func (c *stdlibMetaCache) ensureExportBytes(path string) ([]byte, bool) {
	if path == "unsafe" {
		return nil, false
	}
	c.exportMu.RLock()
	cached, seen := c.exportBytes[path]
	c.exportMu.RUnlock()
	if seen {
		return cached, len(cached) > 0
	}
	meta, ok := c.byPath[path]
	if !ok || meta.name == "" || meta.name == "main" || len(meta.compiledPaths) == 0 {
		c.exportMu.Lock()
		if existing, okE := c.exportBytes[path]; okE {
			c.exportMu.Unlock()
			return existing, len(existing) > 0
		}
		c.exportBytes[path] = nil
		c.exportMu.Unlock()
		return nil, false
	}
	depBytes := make(map[string][]byte, len(meta.imports))
	for _, imp := range meta.imports {
		if imp == "unsafe" {
			continue
		}
		b, okB := c.ensureExportBytes(imp)
		if !okB {
			c.exportMu.Lock()
			if existing, okE := c.exportBytes[path]; okE {
				c.exportMu.Unlock()
				return existing, len(existing) > 0
			}
			c.exportBytes[path] = nil
			c.exportMu.Unlock()
			return nil, false
		}
		depBytes[imp] = b
	}
	c.exportMu.RLock()
	cached, seen = c.exportBytes[path]
	c.exportMu.RUnlock()
	if seen {
		return cached, len(cached) > 0
	}

	missFset := token.NewFileSet()
	var files []*ast.File
	if len(meta.compiledFiles) == len(meta.compiledPaths) && len(meta.compiledFiles) > 0 {
		files = make([]*ast.File, 0, len(meta.compiledFiles))
		for _, sf := range meta.compiledFiles {
			af, err := parser.ParseFile(missFset, sf.path, sf.content, parser.AllErrors|parser.SkipObjectResolution)
			if err != nil || af == nil {
				files = nil
				break
			}
			files = append(files, af)
		}
	} else {
		files = make([]*ast.File, 0, len(meta.compiledPaths))
		for _, fpath := range meta.compiledPaths {
			src, err := os.ReadFile(fpath)
			if err != nil {
				files = nil
				break
			}
			af, err := parser.ParseFile(missFset, fpath, src, parser.AllErrors|parser.SkipObjectResolution)
			if err != nil || af == nil {
				files = nil
				break
			}
			files = append(files, af)
		}
	}
	var built []byte
	if len(files) > 0 {
		missTypes := map[string]*types.Package{"unsafe": types.Unsafe}
		importDep := func(impPath string) (*types.Package, error) {
			if tp, okT := missTypes[impPath]; okT && tp.Complete() {
				return tp, nil
			}
			b, okB := depBytes[impPath]
			if !okB {
				var okEnsure bool
				b, okEnsure = c.ensureExportBytes(impPath)
				if !okEnsure {
					return nil, fmt.Errorf("missing export data for %s", impPath)
				}
			}
			return gcexportdata.Read(bytes.NewReader(b), missFset, missTypes, impPath)
		}
		tpkg := types.NewPackage(meta.pkgPath, meta.name)
		hadErr := false
		conf := &types.Config{
			Importer:         mapImporterFunc(importDep),
			IgnoreFuncBodies: true,
			Sizes:            c.typesSizes(),
			Error:            func(error) { hadErr = true },
		}
		if err := types.NewChecker(conf, missFset, tpkg, nil).Files(files); err == nil && !hadErr && tpkg.Complete() {
			var buf bytes.Buffer
			if err := gcexportdata.Write(&buf, missFset, tpkg); err == nil && buf.Len() > 0 {
				built = bytes.Clone(buf.Bytes())
			}
		}
	}
	c.exportMu.Lock()
	if existing, okE := c.exportBytes[path]; okE {
		c.exportMu.Unlock()
		return existing, len(existing) > 0
	}
	c.exportBytes[path] = built
	c.exportMu.Unlock()
	return built, len(built) > 0
}

func (c *stdlibMetaCache) activeStdlibForImports(userImports map[string]bool) map[string]bool {
	reachable := make(map[string]bool, len(userImports)*4)
	var visit func(string)
	visit = func(p string) {
		if reachable[p] {
			return
		}
		reachable[p] = true
		if meta, ok := c.byPath[p]; ok {
			for _, imp := range meta.imports {
				visit(imp)
			}
		}
	}
	for imp := range userImports {
		visit(imp)
	}

	active := map[string]bool{
		"slices": true,
		"maps":   true,
		"cmp":    true,
		"sync":   true,
	}
	hasCrypto := userImports["crypto"] || userImports["hash"]
	hasJSON := false
	for imp := range userImports {
		if strings.HasPrefix(imp, "crypto/") {
			hasCrypto = true
		}
		if strings.HasPrefix(imp, "encoding/json") {
			hasJSON = true
		}
		switch imp {
		case "testing", "testing/quick", "testing/fstest", "testing/iotest":
			active["testing"] = true
			active["context"] = true
			active["sync/atomic"] = true
		case "fmt", "log":
			active["fmt"] = true
			active["io"] = true
			active["bytes"] = true
			active["strings"] = true
			active["errors"] = true
		case "strings":
			active["strings"] = true
			active["io"] = true
		case "bytes":
			active["bytes"] = true
			active["io"] = true
		case "io", "io/fs", "bufio":
			active["io"] = true
			active["errors"] = true
		case "errors":
			active["errors"] = true
		case "strconv":
			active["strconv"] = true
			active["internal/strconv"] = true
			active["errors"] = true
		case "context":
			active["context"] = true
			active["errors"] = true
		case "sort":
			active["sort"] = true
		case "reflect":
			active["reflect"] = true
		case "path/filepath":
			active["path/filepath"] = true
		case "text/template", "html/template":
			active["text/template"] = true
			active["fmt"] = true
			active["io"] = true
			active["reflect"] = true
			active["strings"] = true
			active["bytes"] = true
		}
	}
	if hasCrypto {
		active["crypto"] = true
		for p := range reachable {
			if strings.HasPrefix(p, "crypto/") {
				active[p] = true
			}
		}
	}
	if hasJSON {
		active["bytes"] = true
		active["strings"] = true
		active["io"] = true
		active["errors"] = true
		for p := range reachable {
			if strings.HasPrefix(p, "encoding/json") {
				active[p] = true
			}
		}
	}
	for p := range reachable {
		if strings.Contains(p, ".") {
			active[p] = true
		}
	}
	for p := range active {
		if !reachable[p] {
			delete(active, p)
		}
	}
	return active
}

func newTypesInfo() *types.Info {
	return &types.Info{
		Types:        make(map[ast.Expr]types.TypeAndValue),
		Defs:         make(map[*ast.Ident]types.Object),
		Uses:         make(map[*ast.Ident]types.Object),
		Implicits:    make(map[ast.Node]types.Object),
		Instances:    make(map[*ast.Ident]types.Instance),
		Scopes:       make(map[ast.Node]*types.Scope),
		Selections:   make(map[*ast.SelectorExpr]*types.Selection),
		FileVersions: make(map[*ast.File]string),
	}
}

func (c *stdlibMetaCache) newStdImporter(fset *token.FileSet, typesByPath map[string]*types.Package, headerByPath map[string]*packages.Package, fallback types.Importer) types.Importer {
	return mapImporterFunc(func(path string) (*types.Package, error) {
		if tp, ok := typesByPath[path]; ok && tp.Complete() {
			return tp, nil
		}
		if c != nil {
			if meta, ok := c.byPath[path]; ok {
				if expBytes, okExp := c.ensureExportBytes(path); okExp {
					tp, err := gcexportdata.Read(bytes.NewReader(expBytes), fset, typesByPath, path)
					if err != nil {
						return nil, err
					}
					headerByPath[path] = &packages.Package{
						ID:      meta.id,
						Name:    meta.name,
						PkgPath: meta.pkgPath,
						GoFiles: meta.goFiles,
						Types:   tp,
						Fset:    fset,
					}
					return tp, nil
				}
			}
		}
		tp, err := fallback.Import(path)
		if err != nil {
			return nil, err
		}
		typesByPath[path] = tp
		headerByPath[path] = &packages.Package{
			ID:      path,
			Name:    tp.Name(),
			PkgPath: path,
			Types:   tp,
			Fset:    fset,
		}
		return tp, nil
	})
}

func (c *stdlibMetaCache) materialize(fset *token.FileSet, typesByPath map[string]*types.Package, active map[string]bool, fallback types.Importer) (map[string]*packages.Package, map[string]*packages.Package, error) {
	typesByPath["unsafe"] = types.Unsafe
	headerByPath := map[string]*packages.Package{
		"unsafe": {
			ID:      "unsafe",
			Name:    "unsafe",
			PkgPath: "unsafe",
			Types:   types.Unsafe,
			Fset:    fset,
		},
	}
	fullByPath := make(map[string]*packages.Package, len(active))
	stdImp := c.newStdImporter(fset, typesByPath, headerByPath, fallback)

	stdSizes := c.typesSizes()
	for _, p := range c.topoOrder {
		if !active[p] {
			continue
		}
		meta, ok := c.byPath[p]
		if !ok || len(meta.compiledFiles) == 0 {
			continue
		}
		syntax := make([]*ast.File, 0, len(meta.compiledFiles))
		compiledPaths := make([]string, 0, len(meta.compiledFiles))
		for _, sf := range meta.compiledFiles {
			parseMode := parser.SkipObjectResolution
			if gotool.StringNeedsCommentParse(sf.content) {
				parseMode |= parser.ParseComments
			}
			af, err := parser.ParseFile(fset, sf.path, sf.content, parseMode)
			if err != nil {
				return nil, nil, fmt.Errorf("parse stdlib %s (%s): %w", p, sf.path, err)
			}
			syntax = append(syntax, af)
			compiledPaths = append(compiledPaths, sf.path)
		}
		info := newTypesInfo()
		tpkg := types.NewPackage(meta.pkgPath, meta.name)
		conf := &types.Config{Importer: stdImp, Sizes: stdSizes}
		if err := types.NewChecker(conf, fset, tpkg, info).Files(syntax); err != nil {
			return nil, nil, fmt.Errorf("typecheck stdlib %s: %w", p, err)
		}
		typesByPath[p] = tpkg
		pkg := &packages.Package{
			ID:              meta.id,
			Name:            meta.name,
			PkgPath:         meta.pkgPath,
			GoFiles:         meta.goFiles,
			CompiledGoFiles: compiledPaths,
			Syntax:          syntax,
			Types:           tpkg,
			TypesInfo:       info,
			TypesSizes:      stdSizes,
			Fset:            fset,
		}
		fullByPath[p] = pkg
		headerByPath[p] = &packages.Package{
			ID:      meta.id,
			Name:    meta.name,
			PkgPath: meta.pkgPath,
			GoFiles: meta.goFiles,
			Types:   tpkg,
			Fset:    fset,
		}
	}

	for p, full := range fullByPath {
		meta := c.byPath[p]
		if len(meta.imports) == 0 {
			continue
		}
		imps := make(map[string]*packages.Package, len(meta.imports))
		for _, impPath := range meta.imports {
			if ac, ok := fullByPath[impPath]; ok {
				imps[impPath] = ac
			} else if hdr, ok := headerByPath[impPath]; ok {
				imps[impPath] = hdr
			} else if tp, err := stdImp.Import(impPath); err == nil {
				imps[impPath] = &packages.Package{
					ID:      impPath,
					Name:    tp.Name(),
					PkgPath: impPath,
					Types:   tp,
					Fset:    fset,
				}
			}
		}
		full.Imports = imps
	}
	return fullByPath, headerByPath, nil
}

// CachedStdlibPackageErr returns a *packages.Package for a standard library
// package (or golang.org/x/sys/unix) materialized from the carrier-free
// metadata cache.
func CachedStdlibPackageErr(env []string, pkgPath string) (*packages.Package, error) {
	cache, err := getStdlibMetaCache(env)
	if err != nil {
		return nil, err
	}
	meta, ok := cache.byPath[pkgPath]
	if !ok {
		return nil, nil
	}
	fset := token.NewFileSet()
	typesByPath := make(map[string]*types.Package)
	fallback := newLocalExportImporter()
	if len(meta.compiledFiles) > 0 {
		full, _, err := cache.materialize(fset, typesByPath, map[string]bool{pkgPath: true}, fallback)
		if err != nil {
			return nil, err
		}
		return full[pkgPath], nil
	}
	var tp *types.Package
	if pkgPath == "unsafe" {
		tp = types.Unsafe
	} else if expBytes, okExp := cache.ensureExportBytes(pkgPath); okExp {
		tp, err = gcexportdata.Read(bytes.NewReader(expBytes), fset, typesByPath, pkgPath)
		if err != nil {
			return nil, err
		}
	}
	return &packages.Package{
		ID:      meta.id,
		Name:    meta.name,
		PkgPath: meta.pkgPath,
		GoFiles: meta.goFiles,
		Types:   tp,
		Fset:    fset,
	}, nil
}

// CachedStdlibPackage returns a *packages.Package for a standard library
// package (or golang.org/x/sys/unix) materialized from the carrier-free
// metadata cache.
func CachedStdlibPackage(t testing.TB, env []string, pkgPath string) *packages.Package {
	t.Helper()
	pkg, err := CachedStdlibPackageErr(env, pkgPath)
	if err != nil {
		t.Fatalf("CachedStdlibPackage: %v", err)
	}
	return pkg
}

func newLocalExportImporter() types.Importer {
	base := importer.Default()
	cache := map[string]*types.Package{}
	return mapImporterFunc(func(path string) (*types.Package, error) {
		if path == "unsafe" {
			return types.Unsafe, nil
		}
		if pkg, ok := cache[path]; ok {
			return pkg, nil
		}
		pkg, err := base.Import(path)
		if err != nil {
			return nil, err
		}
		cache[path] = pkg
		return pkg, nil
	})
}

type mapImporterFunc func(path string) (*types.Package, error)

func (f mapImporterFunc) Import(path string) (*types.Package, error) {
	return f(path)
}
