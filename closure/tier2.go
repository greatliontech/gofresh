package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/internal/gotool"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type asmMacro struct {
	funcLike bool
	params   []string
	body     string
}

// program is the loaded whole-program SSA for one package's test binary, cached
// so per-benchmark Compute calls amortize the dominant load cost (§7.4).
type program struct {
	prog     *ssa.Program
	pkgs     []*packages.Package
	roots    map[string]*ssa.Function // benchmark function name → its SSA function
	testMain *ssa.Function
}

// loadCached loads (once) and returns the whole-program SSA for pkgPath.
func (h *Hasher) loadCached(pkgPath string) (*program, error) {
	if p, ok := h.progs[pkgPath]; ok {
		return p, nil
	}
	p, err := load(pkgPath)
	if err != nil {
		return nil, err
	}
	h.progs[pkgPath] = p
	return p, nil
}

// loadConfig is the shared packages.Config for both the single-package load and
// the batched Prime: all-dependency syntax (stdlib bodies included, §7.4) with the
// ForTest linkage needed to distinguish a package's test-binary variants.
func loadConfig() *packages.Config {
	return &packages.Config{Mode: packages.LoadAllSyntax | packages.NeedForTest, Tests: true}
}

// load builds whole-program SSA for pkgPath's test binary from a single-package
// packages.Load. It is the fallback path (and the exact behavior Prime reproduces
// per package); Prime shares one Load across many packages but each still gets its
// own program from only its own roots. A load error is fatal — analyzing a partial
// program could miss reachable code and report a stale result valid (INV-1).
func load(pkgPath string) (*program, error) {
	roots, err := packages.Load(loadConfig(), pkgPath)
	if err != nil {
		return nil, fmt.Errorf("closure: load %s: %w", pkgPath, err)
	}
	return buildProgram(pkgPath, roots)
}

// Prime warms the per-package SSA cache for pkgPaths with one shared
// packages.Load, so the stdlib and shared dependencies are parsed and
// type-checked once for the whole set rather than once per package (§7.4 — the
// dominant residual cost of a multi-package `pew status`). Each package still gets
// its own ssa.Program built from only its own test-binary roots (rootsForBinary),
// so the analysis — including the per-binary init-root set RTA depends on (see the
// roots loop in tier2) — is byte-identical to the single-package load; Prime
// shares only the parse/type-check front-end, never the SSA program.
//
// It is best-effort: a batch-load failure, or a package whose closure fails to
// build, leaves that package uncached, and its first Compute falls back to a
// single load — preserving both per-package error isolation and the exact
// single-load result. Already-cached packages are skipped. Equivalence to the
// per-package load is pinned by TestBatchLoadMatchesPerPackage.
func (h *Hasher) Prime(pkgPaths []string) {
	var need []string
	seen := map[string]bool{}
	for _, p := range pkgPaths {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if _, ok := h.progs[p]; !ok {
			need = append(need, p)
		}
	}
	if len(need) == 0 {
		return
	}
	roots, err := packages.Load(loadConfig(), need...)
	if err != nil {
		return // fall back to lazy single loads; the error resurfaces there
	}
	for _, p := range need {
		prog, err := buildProgram(p, rootsForBinary(roots, p))
		if err != nil {
			continue // leave uncached; loadCached single-loads and surfaces the error
		}
		h.progs[p] = prog
	}
}

// rootsForBinary selects, from a batched packages.Load result, exactly the root
// packages a single packages.Load(pkgPath) with Tests returns: the package and its
// in-package/external test variants (ForTest==pkgPath) plus the generated
// test-main (PkgPath==pkgPath+".test"). Feeding exactly these to
// ssautil.AllPackages reproduces the per-package program's package set, so RTA's
// per-binary init roots (tier2) are unchanged. Selecting too few would shrink that
// set and under-cover the closure (INV-1) — this must match the single-load root
// set exactly, which TestBatchLoadMatchesPerPackage pins over real fixtures.
func rootsForBinary(all []*packages.Package, pkgPath string) []*packages.Package {
	var rs []*packages.Package
	for _, p := range all {
		if p.PkgPath == pkgPath || p.ForTest == pkgPath || p.PkgPath == pkgPath+".test" {
			rs = append(rs, p)
		}
	}
	return rs
}

// buildProgram builds whole-program SSA for one package's test binary from its
// root packages (generics instantiated, so RTA traverses real edges through std
// and dispatches generic instantiations concretely). A load error is fatal — a
// partial program could miss reachable code and report a stale result valid
// (INV-1).
func buildProgram(pkgPath string, roots []*packages.Package) (*program, error) {
	var errs []string
	var rootErrs []string
	var all []*packages.Package
	seen := map[*packages.Package]bool{}
	packages.Visit(roots, nil, func(p *packages.Package) {
		if seen[p] {
			return
		}
		seen[p] = true
		all = append(all, p)
		for _, e := range p.Errors {
			errs = append(errs, e.Error())
		}
	})
	if len(errs) > 0 {
		return nil, fmt.Errorf("closure: load %s: %s", pkgPath, strings.Join(errs, "; "))
	}

	prog, _ := ssautil.AllPackages(roots, ssa.InstantiateGenerics)
	prog.Build()

	// Index every top-level function as a candidate root, keyed by name, so any
	// subject — a benchmark, a test, or a production function — is rootable by name
	// (§ closure REQ-closure-analysis). Collect from the test-variant packages
	// (ForTest == pkgPath): each compiles the package WITH its test files, so it
	// holds both the production symbols and the test/benchmark symbols. Fall back to
	// the plain package only when no test variant exists — collecting a production
	// symbol from both the plain package and its test variant would key one name to
	// two distinct ssa.Functions and read as an ambiguous root.
	funcRoots := map[string]*ssa.Function{}
	var testMain *ssa.Function
	var rootPkgs []*packages.Package
	for _, p := range all {
		if p.ForTest == pkgPath {
			rootPkgs = append(rootPkgs, p)
		}
	}
	if len(rootPkgs) == 0 {
		for _, p := range all {
			if p.PkgPath == pkgPath {
				rootPkgs = append(rootPkgs, p)
			}
		}
	}
	for _, p := range rootPkgs {
		if p.Types == nil {
			continue
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			fn, ok := scope.Lookup(name).(*types.Func)
			if !ok {
				continue
			}
			f := prog.FuncValue(fn)
			if f == nil {
				continue
			}
			if name == "TestMain" {
				if testMain != nil && testMain != f {
					rootErrs = append(rootErrs, name)
					continue
				}
				testMain = f
				continue
			}
			if prev := funcRoots[name]; prev != nil && prev != f {
				rootErrs = append(rootErrs, name)
				continue
			}
			funcRoots[name] = f
		}
	}
	if len(rootErrs) > 0 {
		return nil, fmt.Errorf("closure: ambiguous subject roots in %s: %s", pkgPath, strings.Join(rootErrs, ", "))
	}
	return &program{prog: prog, pkgs: all, roots: funcRoots, testMain: testMain}, nil
}


// Compute returns the source closure for one subject of pkgPath — a top-level
// function named by symbol, whether a benchmark, a test, or a production function.
func (h *Hasher) Compute(pkgPath, symbol string) (Closure, error) {
	tr, err := h.tier2(pkgPath, symbol)
	if err != nil {
		return Closure{}, err
	}
	var hash string
	if tr.widen {
		hash, err = h.maximalHash(pkgPath)
	} else {
		hash, err = hashContributions(pkgPath, tr.contribs)
	}
	if err != nil {
		return Closure{}, err
	}
	return Closure{Hash: hash, Unverifiable: tr.unverifiable, Reason: tr.reason}, nil
}

type tier2Result struct {
	contribs     []string
	widen        bool
	widenReason  string
	unverifiable bool
	reason       string
}

func (h *Hasher) tier2Contributions(pkgPath, bench string) ([]string, bool, error) {
	tr, err := h.tier2(pkgPath, bench)
	if err != nil {
		return nil, false, err
	}
	return tr.contribs, tr.widen, nil
}

func (h *Hasher) tier2(pkgPath, bench string) (tier2Result, error) {
	prog, err := h.loadCached(pkgPath)
	if err != nil {
		return tier2Result{}, err
	}
	root := prog.roots[bench]
	if root == nil {
		return tier2Result{}, fmt.Errorf("closure: subject %s not found in %s", bench, pkgPath)
	}
	metas, err := h.list(pkgPath)
	if err != nil {
		return tier2Result{}, err
	}

	a := newTier2Analyzer(h, prog, metas)
	if err := a.addLinkedCacheModules(); err != nil {
		return tier2Result{}, err
	}

	// RTA is rooted at the benchmark plus TestMain and every package init, so
	// startup/global side effects a benchmark observes without naming the
	// registering package are covered (§7.4). File I/O reached anywhere in this
	// closure is Class-B `unverifiable` regardless of when it runs (§7.3-B, §7.8):
	// the runtime-input manifest is evidence, never a completeness proof, so the
	// closure never promotes observed file I/O to `valid`.
	roots := []*ssa.Function{root}
	if prog.testMain != nil {
		roots = append(roots, prog.testMain)
	}
	for _, p := range prog.prog.AllPackages() {
		if init := p.Func("init"); init != nil {
			roots = append(roots, init)
		}
	}
	res := rta.Analyze(roots, true)
	if res == nil {
		return tier2Result{}, fmt.Errorf("closure: RTA returned no result for %s.%s", pkgPath, bench)
	}
	for fn := range res.Reachable {
		a.rtaReach[fn] = true
	}
	for fn := range res.Reachable {
		a.addFunction(fn)
		if idx := a.idxForFunction(fn); idx != nil && idx.std {
			continue
		}
		a.scanFunction(fn)
	}
	a.drainObjects()
	for {
		pkgCount := len(a.filePkgs)
		if err := a.addReachedPackageFiles(); err != nil {
			return tier2Result{}, err
		}
		a.drainObjects()
		if len(a.filePkgs) == pkgCount {
			break
		}
	}
	return a.result(), nil
}

type pkgIndex struct {
	pkg            *packages.Package
	ssa            *ssa.Package
	meta           *listPkg
	id             string
	path           string
	dir            string
	std            bool
	testMain       bool
	cache          bool
	mutable        bool
	decls          map[types.Object]ast.Node
	vars           []ast.Node
	inits          []ast.Node
	imports        []ast.Node
	wasmImport     bool
	linknames      map[types.Object]string
	linknameByName map[string]string
	linknameDocs   map[types.Object]ast.Node
}

type tier2Analyzer struct {
	h                *Hasher
	prog             *program
	metas            []listPkg
	metaByPath       map[string]*listPkg
	idxByTypes       map[*types.Package]*pkgIndex
	idxByPath        map[string]*pkgIndex
	objByName        map[string]types.Object
	objsByLinkTarget map[string][]types.Object

	seenObjects map[types.Object]bool
	objectQueue []types.Object
	seenTypes   map[string]bool
	seenDecls   map[string]bool
	seenPkgs    map[*pkgIndex]bool
	filePkgs    map[*pkgIndex]bool
	rtaReach    map[*ssa.Function]bool
	scanned     map[*ssa.Function]bool
	seenContrib map[string]bool
	contribs    []string

	widen        bool
	widenReason  string
	unverifiable bool
	reason       string
}

func newTier2Analyzer(h *Hasher, prog *program, metas []listPkg) *tier2Analyzer {
	a := &tier2Analyzer{
		h:                h,
		prog:             prog,
		metas:            metas,
		metaByPath:       map[string]*listPkg{},
		idxByTypes:       map[*types.Package]*pkgIndex{},
		idxByPath:        map[string]*pkgIndex{},
		objByName:        map[string]types.Object{},
		objsByLinkTarget: map[string][]types.Object{},
		seenObjects:      map[types.Object]bool{},
		seenTypes:        map[string]bool{},
		seenDecls:        map[string]bool{},
		seenPkgs:         map[*pkgIndex]bool{},
		filePkgs:         map[*pkgIndex]bool{},
		rtaReach:         map[*ssa.Function]bool{},
		scanned:          map[*ssa.Function]bool{},
		seenContrib:      map[string]bool{},
	}
	for i := range metas {
		m := &metas[i]
		a.metaByPath[m.ImportPath] = m
	}
	for _, p := range prog.pkgs {
		idx := a.buildIndex(p)
		if idx == nil {
			continue
		}
		if p.Types != nil {
			a.idxByTypes[p.Types] = idx
		}
		a.idxByPath[idx.id] = idx
		if idx.path != "" {
			a.idxByPath[idx.path] = idx
		}
		for obj := range idx.decls {
			if obj == nil || obj.Pkg() == nil || obj.Name() == "" {
				continue
			}
			a.objByName[obj.Pkg().Path()+"."+obj.Name()] = obj
		}
		for obj, target := range idx.linknames {
			a.addReverseLinkname(target, obj)
		}
		if idx.pkg != nil && idx.pkg.Types != nil {
			for name, target := range idx.linknameByName {
				if obj := idx.pkg.Types.Scope().Lookup(name); obj != nil {
					a.addReverseLinkname(target, obj)
				}
			}
		}
	}
	return a
}

func (a *tier2Analyzer) addReverseLinkname(target string, obj types.Object) {
	if target == "" || obj == nil {
		return
	}
	for _, existing := range a.objsByLinkTarget[target] {
		if existing == obj {
			return
		}
	}
	a.objsByLinkTarget[target] = append(a.objsByLinkTarget[target], obj)
}

func (a *tier2Analyzer) buildIndex(p *packages.Package) *pkgIndex {
	if p == nil || p.Types == nil {
		return nil
	}
	meta := a.metaForPackage(p)
	path := p.Types.Path()
	std := p.Module == nil && isStdImportPath(path)
	if meta != nil {
		std = meta.Standard
	}
	idx := &pkgIndex{
		pkg:            p,
		ssa:            a.prog.prog.Package(p.Types),
		meta:           meta,
		id:             p.ID,
		path:           path,
		dir:            p.Dir,
		std:            std,
		testMain:       strings.HasSuffix(p.ID, ".test") || strings.HasSuffix(path, ".test"),
		decls:          map[types.Object]ast.Node{},
		linknames:      map[types.Object]string{},
		linknameByName: map[string]string{},
		linknameDocs:   map[types.Object]ast.Node{},
	}
	if meta != nil {
		idx.dir = meta.Dir
		idx.cache = meta.Module != nil && !meta.Module.Main && a.h.underCache(meta.Dir)
	} else if p.Module != nil {
		idx.cache = !p.Module.Main && a.h.underCache(p.Dir)
	}
	idx.mutable = !idx.std && !idx.testMain && !idx.cache
	if idx.id == "" {
		idx.id = path
	}

	for _, f := range p.Syntax {
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
				text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
				text = strings.TrimSpace(strings.TrimSuffix(text, "*/"))
				fields := strings.Fields(text)
				if len(fields) >= 3 && fields[0] == "go:linkname" {
					idx.linknameByName[fields[1]] = fields[2]
				}
				if len(fields) >= 2 && fields[0] == "go:linkname" {
					if obj := p.Types.Scope().Lookup(fields[1]); obj != nil {
						idx.linknameDocs[obj] = cg
					}
				}
				if strings.HasPrefix(text, "go:wasmimport") {
					idx.wasmImport = true
				}
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.Name == "init" {
					idx.inits = append(idx.inits, d)
				}
				if obj := p.TypesInfo.Defs[d.Name]; obj != nil {
					idx.decls[obj] = d
				}
				for local, target := range linknamesFromDoc(d.Doc) {
					if obj := p.Types.Scope().Lookup(local); obj != nil {
						idx.linknames[obj] = target
					}
				}
			case *ast.GenDecl:
				if d.Tok == token.IMPORT {
					idx.imports = append(idx.imports, d)
				}
				genLinknames := linknamesFromDoc(d.Doc)
				for local, target := range genLinknames {
					if obj := p.Types.Scope().Lookup(local); obj != nil {
						idx.linknames[obj] = target
					}
				}
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.ValueSpec:
						specLinknames := linknamesFromDoc(s.Doc)
						for local, target := range specLinknames {
							if obj := p.Types.Scope().Lookup(local); obj != nil {
								idx.linknames[obj] = target
							}
						}
						node := ast.Node(s)
						if d.Tok == token.CONST {
							// A later const spec can inherit expression/type/iota context from
							// earlier specs, so a used const hashes the whole group.
							node = d
						}
						if d.Tok == token.VAR {
							idx.vars = append(idx.vars, s)
							if len(genLinknames) > 0 {
								node = d
							}
						}
						for _, name := range s.Names {
							if obj := p.TypesInfo.Defs[name]; obj != nil {
								idx.decls[obj] = node
							}
						}
					case *ast.TypeSpec:
						if obj := p.TypesInfo.Defs[s.Name]; obj != nil {
							idx.decls[obj] = s
						}
					}
				}
			}
		}
	}
	return idx
}

func (a *tier2Analyzer) metaForPackage(p *packages.Package) *listPkg {
	for _, key := range []string{p.ID, p.PkgPath} {
		if key == "" {
			continue
		}
		if m := a.metaByPath[key]; m != nil {
			return m
		}
	}
	if p.Types != nil {
		if m := a.metaByPath[p.Types.Path()]; m != nil {
			return m
		}
	}
	return nil
}

func (a *tier2Analyzer) addLinkedCacheModules() error {
	for _, p := range a.metas {
		if p.Standard || p.Module == nil || p.Module.Main || !a.h.underCache(p.Dir) {
			continue
		}
		rel := strings.TrimPrefix(filepath.Clean(p.Module.Dir), a.h.modCache+string(filepath.Separator))
		a.addContribution("cache:" + filepath.ToSlash(rel))
	}
	return nil
}

func (a *tier2Analyzer) addFunction(fn *ssa.Function) {
	if fn == nil {
		return
	}
	if origin := fn.Origin(); origin != nil {
		fn = origin
	}
	idx := a.idxForFunction(fn)
	if idx == nil || idx.std || idx.cache || idx.testMain {
		return
	}
	if fn.Synthetic == "package initializer" || (fn.Name() == "init" && fn.Object() == nil) {
		a.addStartupPackage(idx)
		return
	}
	if obj := fn.Object(); obj != nil {
		a.enqueueObject(obj)
		return
	}
	if parent := fn.Parent(); parent != nil {
		a.addFunction(parent)
	}
}

func (a *tier2Analyzer) addStartupPackage(idx *pkgIndex) {
	if idx == nil || !idx.mutable {
		return
	}
	a.markPackage(idx)
	for _, n := range idx.vars {
		a.addDecl(idx, "startup-var", n)
		a.scanNodeRefs(idx, n)
	}
	for _, n := range idx.inits {
		a.addDecl(idx, "init", n)
		a.scanNodeRefs(idx, n)
	}
}

func (a *tier2Analyzer) scanFunction(fn *ssa.Function) {
	if fn == nil {
		return
	}
	idx := a.idxForFunction(fn)
	if idx == nil || idx.testMain {
		return
	}
	if !idx.std {
		a.markFilePackage(idx)
		if obj := fn.Object(); obj != nil {
			if target := a.linknameTarget(idx, obj); target != "" {
				a.addLinknameTarget(target)
			}
		}
	}
	if len(fn.Blocks) == 0 {
		return
	}
	if a.scanned[fn] {
		return
	}
	a.scanned[fn] = true
	suppressNestedFileIO := idx.std && isFileIOReason(classBReasonForFunction(fn))
	if !idx.std && idx.wasmImport {
		a.markUnverifiable("reaches go:wasmimport")
	}
	if idx.cache && hasExternalCgoMeta(idx.meta) {
		a.markUnverifiable("reaches cgo external library")
	}
	if idx.cache {
		a.scanCacheFunctionRefs(idx, fn)
	}
	if idx.std && isFileIOReason(classBReasonForFunction(fn)) {
		return
	}
	var ops [16]*ssa.Value
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			if v, ok := instr.(ssa.Value); ok {
				a.addType(v.Type())
				if !idx.std && typeUsesUnsafePointer(v.Type()) {
					a.requestWiden("unsafe pointer reachable in " + idx.id)
				}
			}
			for _, op := range instr.Operands(ops[:0]) {
				if op == nil || *op == nil {
					continue
				}
				a.scanValue(*op)
			}
			fromRTA := a.rtaReach[fn]
			if idx.std {
				fromRTA = false
			}
			a.scanInstruction(idx, instr, fromRTA, suppressNestedFileIO)
		}
	}
}

func (a *tier2Analyzer) scanCacheFunctionRefs(idx *pkgIndex, fn *ssa.Function) {
	if idx == nil || fn == nil {
		return
	}
	obj := fn.Object()
	if obj == nil {
		if fn.Synthetic == "package initializer" || fn.Name() == "init" {
			for _, n := range idx.vars {
				a.scanNodeRefs(idx, n)
			}
			for _, n := range idx.inits {
				a.scanNodeRefs(idx, n)
			}
		}
		return
	}
	node := idx.decls[obj]
	if node == nil {
		a.requestWiden("missing cache function declaration for " + obj.String())
		return
	}
	a.scanNodeRefs(idx, node)
}

func (a *tier2Analyzer) scanValue(v ssa.Value) {
	if v == nil {
		return
	}
	a.addType(v.Type())
	if typeUsesUnsafePointer(v.Type()) {
		if idx := a.idxForFunction(v.Parent()); idx != nil && !idx.std {
			a.requestWiden("unsafe pointer reachable in " + idx.id)
		}
	}
	switch x := v.(type) {
	case *ssa.Global:
		if obj := x.Object(); obj != nil {
			a.enqueueObject(obj)
		}
	case *ssa.Function:
		a.addFunction(x)
	}
}

func (a *tier2Analyzer) scanInstruction(idx *pkgIndex, instr ssa.Instruction, fromRTA, suppressNestedFileIO bool) {
	switch x := instr.(type) {
	case ssa.CallInstruction:
		a.scanCall(idx, x.Common(), fromRTA, suppressNestedFileIO)
	case *ssa.MakeInterface:
		a.addInterfaceMethodSet(x.X.Type())
	}
}

func (a *tier2Analyzer) scanCall(callerIdx *pkgIndex, c *ssa.CallCommon, fromRTA, suppressNestedFileIO bool) {
	if c == nil {
		return
	}
	callerStd := callerIdx != nil && callerIdx.std
	if c.IsInvoke() && !fromRTA && !callerStd {
		a.requestWiden("interface invoke outside RTA")
	}
	if !c.IsInvoke() && c.StaticCallee() == nil {
		if _, ok := c.Value.(*ssa.Builtin); !ok && !callerStd {
			a.requestWiden("computed function call")
		}
	}
	callee := c.StaticCallee()
	if callee == nil {
		return
	}
	pkgPath := funcPkgPath(callee)
	name := callee.Name()
	if obj := callee.Object(); obj != nil {
		name = obj.Name()
	}
	reason := classBReason(pkgPath, name)
	if osOpenFileMayMutate(callee, pkgPath, name, c) {
		reason = "reaches os.OpenFile (filesystem mutation)"
	}
	if reason == "" && syscallOpenMayCreate(pkgPath, name, c) {
		reason = "reaches " + pkgPath + "." + name + " (filesystem mutation)"
	}
	if reason != "" {
		if callerStd && isFilesystemMutationReason(reason) {
			return
		}
		if !(suppressNestedFileIO && isFileIOReason(reason)) {
			a.markUnverifiable(reason)
		}
	}
	calleeStd := isStdImportPath(pkgPath)
	if !fromRTA || (!callerStd && calleeStd && !isBenchmarkHarnessPath(pkgPath)) {
		a.scanFunction(callee)
	}
	if !callerStd && pkgPath == "reflect" && (name == "Call" || name == "CallSlice" || name == "MakeFunc" || name == "MethodByName") {
		a.requestWiden("reflect dispatch")
	}
}

func (a *tier2Analyzer) addInterfaceMethodSet(t types.Type) {
	if !a.hasNonStdNamedType(t) {
		return
	}
	for _, mt := range []types.Type{t, types.NewPointer(t)} {
		set := types.NewMethodSet(mt)
		for i := 0; i < set.Len(); i++ {
			if fn, ok := set.At(i).Obj().(*types.Func); ok {
				a.enqueueObject(fn)
			}
		}
	}
}

func (a *tier2Analyzer) hasNonStdNamedType(t types.Type) bool {
	found := false
	seen := map[string]bool{}
	var walk func(types.Type)
	walk = func(t types.Type) {
		if t == nil || found {
			return
		}
		key := types.TypeString(t, nil)
		if seen[key] {
			return
		}
		seen[key] = true
		switch tt := t.(type) {
		case *types.Named:
			if obj := tt.Obj(); obj != nil && obj.Pkg() != nil {
				if idx := a.idxByTypes[obj.Pkg()]; idx != nil {
					if !idx.std {
						found = true
						return
					}
				} else if !isStdImportPath(obj.Pkg().Path()) {
					found = true
					return
				}
			}
			walk(tt.Underlying())
		case *types.Pointer:
			walk(tt.Elem())
		case *types.Slice:
			walk(tt.Elem())
		case *types.Array:
			walk(tt.Elem())
		case *types.Map:
			walk(tt.Key())
			walk(tt.Elem())
		case *types.Chan:
			walk(tt.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{tt.Params(), tt.Results()} {
				for i := 0; tuple != nil && i < tuple.Len(); i++ {
					walk(tuple.At(i).Type())
				}
			}
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				walk(tt.Field(i).Type())
			}
		}
	}
	walk(t)
	return found
}

func (a *tier2Analyzer) drainObjects() {
	for len(a.objectQueue) > 0 {
		obj := a.objectQueue[0]
		a.objectQueue = a.objectQueue[1:]
		a.addObject(obj)
	}
}

func (a *tier2Analyzer) enqueueObject(obj types.Object) {
	if obj == nil || obj.Pkg() == nil || a.seenObjects[obj] {
		return
	}
	a.seenObjects[obj] = true
	a.objectQueue = append(a.objectQueue, obj)
}

func (a *tier2Analyzer) addObject(obj types.Object) {
	if obj == nil || obj.Pkg() == nil {
		return
	}
	idx := a.idxByTypes[obj.Pkg()]
	if idx == nil {
		if !isStdImportPath(obj.Pkg().Path()) {
			a.requestWiden("missing source metadata for " + obj.Pkg().Path())
		}
		return
	}
	a.addReverseLinknameTargets(obj)
	if fn, ok := obj.(*types.Func); ok {
		if reason := classBReason(obj.Pkg().Path(), obj.Name()); reason != "" {
			a.markUnverifiable(reason)
		}
		if ssaFn := a.prog.prog.FuncValue(fn); ssaFn != nil {
			a.scanFunction(ssaFn)
		}
	}
	if !idx.std {
		if target := a.linknameTarget(idx, obj); target != "" {
			a.addLinknameTarget(target)
		}
	}
	if idx.std || idx.testMain {
		return
	}
	if !isPackageLevelObject(obj) {
		return
	}
	node := idx.decls[obj]
	if idx.cache {
		a.addType(obj.Type())
		if node != nil {
			a.scanNodeRefs(idx, node)
		} else if _, ok := obj.(*types.Func); !ok {
			a.requestWiden("missing declaration for " + obj.String())
		}
		if fn, ok := obj.(*types.Func); ok {
			if ssaFn := a.prog.prog.FuncValue(fn); ssaFn != nil {
				a.scanFunction(ssaFn)
			}
		}
		return
	}
	if node == nil {
		if _, ok := obj.(*types.Func); ok {
			// A func object with no source decl node is source-free: buildIndex
			// records a decl for every FuncDecl (incl. asm bodies and generic
			// origins), so this is a synthetic/instantiated func whose real body,
			// if any, is hashed through RTA (addFunction resolves fn.Origin() for
			// every reachable instantiation — incl. methods RTA marks reachable
			// when their concrete type is converted to an interface). Hashing its
			// signature suffices; widening here would only lose precision. A
			// non-func with no node is genuinely missing source → widen.
			a.addType(obj.Type())
			return
		}
		a.requestWiden("missing declaration for " + obj.String())
		return
	}
	a.markPackage(idx)
	if linkDoc := idx.linknameDocs[obj]; linkDoc != nil {
		a.addDecl(idx, "linkname "+obj.String(), linkDoc)
	}
	a.addDecl(idx, obj.String(), node)
	a.addType(obj.Type())
	a.scanNodeRefs(idx, node)
	if fn, ok := obj.(*types.Func); ok {
		if ssaFn := a.prog.prog.FuncValue(fn); ssaFn != nil {
			a.scanFunction(ssaFn)
		}
	}
}

func (a *tier2Analyzer) addReverseLinknameTargets(obj types.Object) {
	if obj == nil || obj.Pkg() == nil {
		return
	}
	key := obj.Pkg().Path() + "." + obj.Name()
	for _, linked := range a.objsByLinkTarget[key] {
		if linked != obj {
			a.enqueueObject(linked)
		}
	}
}

func (a *tier2Analyzer) linknameTarget(idx *pkgIndex, obj types.Object) string {
	if idx == nil || obj == nil {
		return ""
	}
	if target := idx.linknames[obj]; target != "" {
		return target
	}
	return idx.linknameByName[obj.Name()]
}

func (a *tier2Analyzer) addLinknameTarget(target string) {
	lastDot := strings.LastIndexByte(target, '.')
	if lastDot < 0 {
		a.requestWiden("unresolved go:linkname target " + target)
		return
	}
	pkgPath, name := target[:lastDot], target[lastDot+1:]
	if reason := classBReason(pkgPath, name); reason != "" {
		a.markUnverifiable(reason)
	}
	obj := a.objByName[pkgPath+"."+name]
	if obj == nil {
		a.requestWiden("unresolved go:linkname target " + target)
		return
	}
	a.enqueueObject(obj)
}

func (a *tier2Analyzer) addType(t types.Type) {
	if t == nil {
		return
	}
	key := types.TypeString(t, nil)
	if a.seenTypes[key] {
		return
	}
	a.seenTypes[key] = true
	switch tt := t.(type) {
	case *types.Named:
		a.enqueueObject(tt.Obj())
		for i := 0; i < tt.TypeArgs().Len(); i++ {
			a.addType(tt.TypeArgs().At(i))
		}
		a.addType(tt.Underlying())
	case *types.Pointer:
		a.addType(tt.Elem())
	case *types.Slice:
		a.addType(tt.Elem())
	case *types.Array:
		a.addType(tt.Elem())
	case *types.Map:
		a.addType(tt.Key())
		a.addType(tt.Elem())
	case *types.Chan:
		a.addType(tt.Elem())
	case *types.Signature:
		a.addTuple(tt.Params())
		a.addTuple(tt.Results())
	case *types.Struct:
		for i := 0; i < tt.NumFields(); i++ {
			a.addType(tt.Field(i).Type())
		}
	}
}

func (a *tier2Analyzer) addTuple(t *types.Tuple) {
	if t == nil {
		return
	}
	for i := 0; i < t.Len(); i++ {
		a.addType(t.At(i).Type())
	}
}

func (a *tier2Analyzer) scanNodeRefs(idx *pkgIndex, node ast.Node) {
	if idx == nil || node == nil || idx.pkg.TypesInfo == nil {
		return
	}
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if obj := idx.pkg.TypesInfo.Uses[x]; obj != nil {
				a.enqueueObject(obj)
				a.addType(obj.Type())
			}
		case *ast.SelectorExpr:
			if sel := idx.pkg.TypesInfo.Selections[x]; sel != nil {
				a.enqueueObject(sel.Obj())
				a.addType(sel.Recv())
			}
		}
		return true
	})
}

func (a *tier2Analyzer) markPackage(idx *pkgIndex) {
	if idx != nil && idx.mutable {
		a.seenPkgs[idx] = true
		a.filePkgs[idx] = true
	}
}

func (a *tier2Analyzer) markFilePackage(idx *pkgIndex) {
	if idx != nil && (idx.mutable || idx.cache) {
		a.filePkgs[idx] = true
	}
}

func (a *tier2Analyzer) addReachedPackageFiles() error {
	pkgs := make([]*pkgIndex, 0, len(a.filePkgs))
	for idx := range a.filePkgs {
		pkgs = append(pkgs, idx)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].id < pkgs[j].id })
	for _, idx := range pkgs {
		if idx.meta == nil {
			a.requestWiden("missing file metadata for " + idx.id)
			continue
		}
		if idx.wasmImport {
			a.markUnverifiable("reaches go:wasmimport")
		}
		if idx.mutable {
			for _, n := range idx.imports {
				a.addDecl(idx, "imports", n)
			}
		}
		if hasExternalCgoMeta(idx.meta) {
			a.markUnverifiable("reaches cgo external library")
		}
		if idx.mutable {
			if hasCgoCallbackBlindspot(idx.meta) {
				modCache := ""
				if a.h != nil {
					modCache = a.h.modCache
				}
				if root := cgoIncludeRootOutsideDir(idx.meta, modCache); root != "" {
					return fmt.Errorf("closure: cgo include root outside package dir: %s", root)
				}
				a.requestWiden("cgo callback source in " + idx.id)
			}
			if err := a.addRelFiles(idx, "embed", idx.meta.EmbedFiles); err != nil {
				return err
			}
			nonGo := append([]string{}, idx.meta.CgoFiles...)
			for _, set := range [][]string{
				idx.meta.CFiles, idx.meta.CXXFiles, idx.meta.MFiles, idx.meta.HFiles, idx.meta.FFiles,
				idx.meta.SFiles, idx.meta.SwigFiles, idx.meta.SwigCXXFiles, idx.meta.SysoFiles,
			} {
				nonGo = append(nonGo, set...)
			}
			if hasCgoCallbackBlindspot(idx.meta) {
				all, err := allPackageFiles(idx.meta.Dir)
				if err != nil {
					return err
				}
				if include, err := cgoEscapingInclude(idx.meta, all); err != nil {
					return err
				} else if include != "" {
					return fmt.Errorf("closure: cgo include escapes package dir: %s", include)
				}
				if err := a.addRelFiles(idx, "file", all); err != nil {
					return err
				}
			} else {
				if err := a.addRelFiles(idx, "file", nonGo); err != nil {
					return err
				}
			}
		}
		asmCalls, computed, opaque, includes, err := asmCallTargets(idx.meta.Dir, idx.meta.SFiles)
		if err != nil {
			return err
		}
		if idx.mutable {
			if err := a.addAbsFiles(idx, "include", includes); err != nil {
				return err
			}
		}
		if computed {
			a.requestWiden("computed asm call in " + idx.id)
		}
		if opaque {
			a.requestWiden("opaque asm preprocessing in " + idx.id)
		}
		for _, target := range asmCalls {
			a.addASMTarget(idx, target)
		}
	}
	return nil
}

func (a *tier2Analyzer) addASMTarget(idx *pkgIndex, target string) {
	name := target
	prefix := ""
	if i := strings.LastIndex(name, "·"); i >= 0 {
		prefix = name[:i]
		name = name[i+len("·"):]
	}
	name = strings.TrimPrefix(name, "·")
	name = strings.TrimPrefix(name, "*")
	if i := strings.IndexByte(name, '<'); i >= 0 {
		name = name[:i]
	}
	obj := a.lookupASMTarget(idx, prefix, name)
	if obj == nil {
		a.requestWiden("unresolved asm call target " + target)
		return
	}
	a.enqueueObject(obj)
}

func (a *tier2Analyzer) lookupASMTarget(idx *pkgIndex, prefix, name string) types.Object {
	if idx == nil || idx.pkg == nil || idx.pkg.Types == nil {
		return nil
	}
	if prefix == "" || prefix == idx.pkg.Name {
		return idx.pkg.Types.Scope().Lookup(name)
	}
	if cand := a.idxByPath[prefix]; cand != nil && cand.pkg != nil && cand.pkg.Types != nil {
		return cand.pkg.Types.Scope().Lookup(name)
	}
	var found types.Object
	seen := map[*pkgIndex]bool{}
	for _, cand := range a.idxByTypes {
		if cand == nil || seen[cand] || cand.pkg == nil || cand.pkg.Types == nil || cand.pkg.Name != prefix {
			continue
		}
		seen[cand] = true
		obj := cand.pkg.Types.Scope().Lookup(name)
		if obj == nil {
			continue
		}
		if found != nil && found != obj {
			return nil
		}
		found = obj
	}
	return found
}

func (a *tier2Analyzer) addRelFiles(idx *pkgIndex, kind string, files []string) error {
	sort.Strings(files)
	for _, f := range files {
		h, err := hashFile(filepath.Join(idx.meta.Dir, f))
		if err != nil {
			return err
		}
		a.addContribution(fmt.Sprintf("%s:%s:%s=%s", kind, idx.id, filepath.ToSlash(f), h))
	}
	return nil
}

func (a *tier2Analyzer) addAbsFiles(idx *pkgIndex, kind string, files []string) error {
	sort.Strings(files)
	for _, path := range files {
		h, err := hashFile(path)
		if err != nil {
			return err
		}
		rel := path
		if idx.meta != nil && idx.meta.Dir != "" {
			if r, err := filepath.Rel(idx.meta.Dir, path); err == nil && !strings.HasPrefix(r, "..") {
				rel = r
			}
		}
		a.addContribution(fmt.Sprintf("%s:%s:%s=%s", kind, idx.id, filepath.ToSlash(rel), h))
	}
	return nil
}

func (a *tier2Analyzer) addDecl(idx *pkgIndex, label string, node ast.Node) {
	if node == nil || idx == nil || idx.pkg.Fset == nil {
		a.requestWiden("missing declaration source")
		return
	}
	pos := nodeStart(node)
	end := node.End()
	file := idx.pkg.Fset.File(pos)
	if file == nil || end == token.NoPos {
		a.requestWiden("missing declaration position")
		return
	}
	startOff := file.Offset(pos)
	endOff := file.Offset(end)
	if endOff < startOff {
		a.requestWiden("invalid declaration range")
		return
	}
	if names := declarationNames(node); names != "" {
		label += " " + names
	}
	key := fmt.Sprintf("%s:%s:%d:%d:%s", idx.id, file.Name(), startOff, endOff, label)
	if a.seenDecls[key] {
		return
	}
	a.seenDecls[key] = true
	content, err := os.ReadFile(file.Name())
	if err != nil {
		a.requestWiden("cannot read declaration source")
		return
	}
	if startOff > len(content) || endOff > len(content) {
		a.requestWiden("declaration range outside file")
		return
	}
	sum := sha256.Sum256(content[startOff:endOff])
	rel := file.Name()
	if idx.dir != "" {
		if r, err := filepath.Rel(idx.dir, file.Name()); err == nil && !strings.HasPrefix(r, "..") {
			rel = r
		}
	}
	a.addContribution(fmt.Sprintf("decl:%s:%s:%d:%s=%s", idx.id, filepath.ToSlash(rel), startOff, label, hex.EncodeToString(sum[:])[:32]))
}

func declarationNames(node ast.Node) string {
	var names []string
	switch n := node.(type) {
	case *ast.GenDecl:
		for _, spec := range n.Specs {
			switch s := spec.(type) {
			case *ast.ValueSpec:
				for _, name := range s.Names {
					names = append(names, name.Name)
				}
			case *ast.TypeSpec:
				names = append(names, s.Name.Name)
			}
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return "[" + strings.Join(names, ",") + "]"
}

func (a *tier2Analyzer) addContribution(c string) {
	if c == "" || a.seenContrib[c] {
		return
	}
	a.seenContrib[c] = true
	a.contribs = append(a.contribs, c)
}

func (a *tier2Analyzer) requestWiden(reason string) {
	if !a.widen {
		a.widen = true
		a.widenReason = reason
	}
}

func (a *tier2Analyzer) markUnverifiable(reason string) {
	// Prefer a non-file-I/O reason when several apply: file I/O is the most common
	// and least specific external dependence, so a network/plugin/cgo cause is the
	// more informative one to surface.
	if !a.unverifiable || (!isFileIOReason(reason) && isFileIOReason(a.reason)) {
		a.reason = reason
	}
	a.unverifiable = true
}

func (a *tier2Analyzer) result() tier2Result {
	sort.Strings(a.contribs)
	return tier2Result{contribs: a.contribs, widen: a.widen, widenReason: a.widenReason, unverifiable: a.unverifiable, reason: a.reason}
}

func isFileIOReason(reason string) bool {
	return strings.Contains(reason, "file I/O")
}

func isFilesystemMutationReason(reason string) bool {
	return strings.Contains(reason, "mutation")
}

func classBReasonForFunction(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	pkgPath := funcPkgPath(fn)
	name := fn.Name()
	if obj := fn.Object(); obj != nil {
		name = obj.Name()
	}
	return classBReason(pkgPath, name)
}

func osOpenFileMayMutate(callee *ssa.Function, pkgPath, name string, c *ssa.CallCommon) bool {
	if pkgPath != "os" || name != "OpenFile" {
		return false
	}
	flagArg := 1
	if callee != nil && callee.Signature != nil && callee.Signature.Recv() != nil {
		flagArg = 2
	}
	if c == nil || len(c.Args) <= flagArg {
		return true
	}
	v, ok := c.Args[flagArg].(*ssa.Const)
	if !ok {
		return true
	}
	if v.Value.Kind() != constant.Int {
		return true
	}
	flags, ok := constant.Int64Val(v.Value)
	if !ok {
		return true
	}
	const mutatingFlags = int64(os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREATE | os.O_TRUNC)
	return flags&mutatingFlags != 0
}

func syscallOpenMayCreate(pkgPath, name string, c *ssa.CallCommon) bool {
	if pkgPath != "syscall" && pkgPath != "golang.org/x/sys/unix" {
		return false
	}
	flagArg := -1
	switch name {
	case "Open":
		flagArg = 1
	case "Openat":
		flagArg = 2
	default:
		return false
	}
	if c == nil || flagArg >= len(c.Args) {
		return true
	}
	v, ok := c.Args[flagArg].(*ssa.Const)
	if !ok {
		return true
	}
	flags, ok := constant.Int64Val(v.Value)
	if !ok {
		return true
	}
	return flags&int64(os.O_CREATE) != 0
}

func (a *tier2Analyzer) idxForFunction(fn *ssa.Function) *pkgIndex {
	for f := fn; f != nil; f = f.Parent() {
		if f.Pkg != nil && f.Pkg.Pkg != nil {
			return a.idxByTypes[f.Pkg.Pkg]
		}
		if obj := f.Object(); obj != nil && obj.Pkg() != nil {
			return a.idxByTypes[obj.Pkg()]
		}
	}
	return nil
}

func funcPkgPath(fn *ssa.Function) string {
	for f := fn; f != nil; f = f.Parent() {
		if f.Pkg != nil && f.Pkg.Pkg != nil {
			return f.Pkg.Pkg.Path()
		}
		if obj := f.Object(); obj != nil && obj.Pkg() != nil {
			return obj.Pkg().Path()
		}
	}
	return ""
}

func isPackageLevelObject(obj types.Object) bool {
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	if obj.Parent() == obj.Pkg().Scope() {
		return true
	}
	_, isFunc := obj.(*types.Func)
	return isFunc
}

func nodeStart(n ast.Node) token.Pos {
	switch x := n.(type) {
	case *ast.FuncDecl:
		if x.Doc != nil {
			return x.Doc.Pos()
		}
	case *ast.ValueSpec:
		if x.Doc != nil {
			return x.Doc.Pos()
		}
	case *ast.TypeSpec:
		if x.Doc != nil {
			return x.Doc.Pos()
		}
	case *ast.GenDecl:
		if x.Doc != nil {
			return x.Doc.Pos()
		}
	}
	return n.Pos()
}

func linknamesFromDoc(doc *ast.CommentGroup) map[string]string {
	out := map[string]string{}
	if doc == nil {
		return out
	}
	for _, c := range doc.List {
		text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		fields := strings.Fields(text)
		if len(fields) >= 3 && fields[0] == "go:linkname" {
			out[fields[1]] = fields[2]
		}
	}
	return out
}

func typeUsesUnsafePointer(t types.Type) bool {
	found := false
	seen := map[string]bool{}
	var walk func(types.Type)
	walk = func(t types.Type) {
		if t == nil || found {
			return
		}
		key := types.TypeString(t, nil)
		if seen[key] {
			return
		}
		seen[key] = true
		if n, ok := t.(*types.Named); ok {
			if obj := n.Obj(); obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "unsafe" && obj.Name() == "Pointer" {
				found = true
				return
			}
		}
		switch tt := t.(type) {
		case *types.Named:
			walk(tt.Underlying())
		case *types.Pointer:
			walk(tt.Elem())
		case *types.Slice:
			walk(tt.Elem())
		case *types.Array:
			walk(tt.Elem())
		case *types.Map:
			walk(tt.Key())
			walk(tt.Elem())
		case *types.Chan:
			walk(tt.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{tt.Params(), tt.Results()} {
				for i := 0; tuple != nil && i < tuple.Len(); i++ {
					walk(tuple.At(i).Type())
				}
			}
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				walk(tt.Field(i).Type())
			}
		}
	}
	walk(t)
	return found
}

func classBReason(pkgPath, name string) string {
	if pkgPath == "os" {
		switch name {
		case "Open", "OpenFile", "ReadFile", "ReadDir", "Stat", "Lstat":
			return "reaches os." + name + " (file I/O)"
		case "Create", "CreateTemp", "WriteFile":
			return "reaches os." + name + " (filesystem mutation)"
		case "CopyFS", "Link", "Mkdir", "MkdirAll", "MkdirTemp", "Remove", "RemoveAll", "Rename", "Symlink":
			return "reaches os." + name + " (path mutation)"
		}
	}
	if pkgPath == "syscall" || pkgPath == "golang.org/x/sys/unix" {
		switch name {
		case "Creat":
			return "reaches " + pkgPath + "." + name + " (filesystem mutation)"
		case "Link", "Linkat", "Mkdir", "Mkdirat", "Rename", "Renameat", "Renameat2", "Rmdir", "Symlink", "Symlinkat", "Unlink", "Unlinkat":
			return "reaches " + pkgPath + "." + name + " (path mutation)"
		}
	}
	if pkgPath == "testing" && name == "TempDir" {
		return "reaches testing.TempDir (path mutation)"
	}
	if pkgPath == "net" {
		switch name {
		case "Dial", "DialContext", "DialTCP", "DialUDP", "DialIP", "Listen", "ListenTCP", "ListenUDP", "ListenIP", "ListenPacket":
			return "reaches net." + name + " (network I/O)"
		}
	}
	if pkgPath == "net/http" {
		switch name {
		case "Get", "Head", "Post", "PostForm", "Do", "ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS":
			return "reaches net/http." + name + " (network I/O)"
		}
	}
	if pkgPath == "html/template" || pkgPath == "text/template" {
		switch name {
		case "ParseFiles", "ParseGlob":
			return "reaches " + pkgPath + "." + name + " (file I/O)"
		}
	}
	if pkgPath == "plugin" && (name == "Open" || name == "Lookup") {
		return "reaches plugin." + name
	}
	return ""
}

func hasExternalCgo(flags []string) bool {
	for _, f := range flags {
		for _, tok := range expandLinkerFlag(f) {
			if isExternalLinkToken(tok) {
				return true
			}
		}
	}
	return false
}

// expandLinkerFlag splits a linker pass-through flag into its sub-arguments. gcc
// carries multiple linker arguments in one comma-joined token (`-Wl,-Bstatic,-lfoo,
// -Bdynamic`), so a `-l` element can hide inside a single whitespace token; without
// expanding it, an external library links unseen and the closure reports `valid`
// while that library changes (§7.3-B, INV-2). `-Xlinker <arg>` needs no expansion —
// go list already emits its argument as a separate token.
func expandLinkerFlag(f string) []string {
	if rest, ok := strings.CutPrefix(f, "-Wl,"); ok {
		return strings.Split(rest, ",")
	}
	return []string{f}
}

func isExternalLinkToken(f string) bool {
	return strings.HasPrefix(f, "-l") || f == "-framework" || strings.Contains(f, "-framework") || strings.HasSuffix(f, ".a") || strings.HasSuffix(f, ".dylib") || strings.HasSuffix(f, ".so") || strings.Contains(f, ".dylib.") || strings.Contains(f, ".so.")
}

func hasExternalCgoMeta(p *listPkg) bool {
	return p != nil && (hasExternalCgo(p.CgoLDFLAGS) || len(p.CgoPkgConfig) > 0)
}

func hasCgoCallbackBlindspot(p *listPkg) bool {
	if p == nil {
		return false
	}
	for _, files := range [][]string{
		p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles,
		p.SwigFiles, p.SwigCXXFiles, p.SysoFiles,
	} {
		if len(files) > 0 {
			return true
		}
	}
	return false
}

func asmCallTargets(dir string, files []string) ([]string, bool, bool, []string, error) {
	var targets []string
	var includes []string
	computed := false
	opaque := false
	for _, f := range files {
		content, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return nil, false, false, nil, fmt.Errorf("closure: read asm %s: %w", filepath.Join(dir, f), err)
		}
		lines, includeOpaque, localIncludes, err := asmExpandedLines(dir, stripASMBlockComments(strings.Split(string(content), "\n")), map[string]bool{})
		if err != nil {
			return nil, false, false, nil, err
		}
		opaque = opaque || includeOpaque
		includes = append(includes, localIncludes...)
		macros := map[string]asmMacro{}
		var scanLines func([]string, map[string]bool) error
		scanLines = func(lines []string, stack map[string]bool) error {
			labels := asmLabels(lines)
			for _, raw := range lines {
				for _, line := range asmStatements(raw) {
					fields := normalizeASMPreprocessorFields(strings.Fields(line))
					macroUpdated, macroOpaque := updateASMMacros(fields, macros)
					opaque = opaque || macroOpaque
					if macroUpdated && !asmIncludeNeedsExpansion(fields) {
						continue
					}
					var expandOpaque bool
					fields, expandOpaque = expandASMFields(fields, macros)
					opaque = opaque || expandOpaque
					includeHandled, err := scanExpandedASMInclude(dir, fields, stack, func(path string) {
						includes = append(includes, path)
					}, func(expanded []string, stack map[string]bool) error {
						return scanLines(expanded, stack)
					}, func() {
						opaque = true
					})
					if err != nil {
						return err
					}
					if includeHandled {
						continue
					}
					macroUpdated, macroOpaque = updateASMMacros(fields, macros)
					opaque = opaque || macroOpaque
					if macroUpdated {
						continue
					}
					for _, stmt := range asmStatements(strings.Join(fields, " ")) {
						target, isComputed, ok := asmTargetFromFields(strings.Fields(stmt), labels)
						computed = computed || isComputed
						if ok {
							targets = append(targets, target)
						}
					}
				}
			}
			return nil
		}
		if err := scanLines(lines, map[string]bool{}); err != nil {
			return nil, false, false, nil, err
		}
	}
	return targets, computed, opaque, includes, nil
}

func scanExpandedASMInclude(dir string, fields []string, stack map[string]bool, addInclude func(string), scan func([]string, map[string]bool) error, markOpaque func()) (bool, error) {
	fields = normalizeASMPreprocessorFields(fields)
	if len(fields) == 0 || fields[0] != "#include" {
		return false, nil
	}
	if len(fields) < 2 || !asmIncludeOperandQuoted(fields) {
		return true, fmt.Errorf("closure: unresolved asm include in %s", dir)
	}
	path, local, ok := asmIncludePath(dir, strings.Trim(fields[1], "\""))
	if !ok {
		return true, fmt.Errorf("closure: unresolved asm include %s", fields[1])
	}
	if local {
		addInclude(path)
	}
	if stack[path] {
		markOpaque()
		return true, nil
	}
	stack[path] = true
	content, err := os.ReadFile(path)
	if err != nil {
		delete(stack, path)
		markOpaque()
		return true, nil
	}
	expanded, childOpaque, childIncludes, err := asmExpandedLines(dir, stripASMBlockComments(strings.Split(string(content), "\n")), stack)
	if err != nil {
		delete(stack, path)
		return true, err
	}
	if childOpaque {
		markOpaque()
	}
	for _, child := range childIncludes {
		addInclude(child)
	}
	err = scan(expanded, stack)
	delete(stack, path)
	return true, err
}

func asmIncludeNeedsExpansion(fields []string) bool {
	return len(fields) >= 2 && fields[0] == "#include" && !asmIncludeOperandQuoted(fields)
}

func asmIncludeOperandQuoted(fields []string) bool {
	return len(fields) >= 2 && strings.HasPrefix(fields[1], "\"") && strings.HasSuffix(fields[1], "\"")
}

func asmTargetFromFields(fields []string, labels map[string]bool) (string, bool, bool) {
	fields = trimASMLabels(fields)
	if len(fields) < 2 {
		if asmSingleOpMayHideCall(fields) {
			return "", true, false
		}
		return "", false, false
	}
	if isASMIndirectCallOp(fields[0]) {
		// Register/computed-target call or jump (e.g. riscv64 `JALR RA, 0(T0)`,
		// mips `JR R5`): the callee is a runtime register value, never a parseable
		// symbol, so it is a computed call → widen to the maximal closure
		// (§7.3-A′). Without this, a ≥3-field indirect mnemonic falls through
		// asmUnknownOpMayHideCall's leaf return and its Go-function-pointer target
		// changes unhashed → false-valid.
		return "", true, false
	}
	if !isASMCallOp(fields[0]) {
		if asmUnknownOpMayHideCall(fields) {
			return "", true, false
		}
		return "", false, false
	}
	target := strings.TrimRight(fields[1], ",")
	sb := strings.Index(target, "(SB)")
	if sb < 0 {
		return "", !isLocalASMTarget(target, labels), false
	}
	if strings.HasPrefix(target, "*") || target[sb+len("(SB)"):] != "" {
		return "", true, false
	}
	target = strings.TrimSuffix(target[:sb], "+0")
	if strings.Contains(target, "+") {
		return "", true, false
	}
	if asmSymbolHasMacroLikeComponent(target) {
		return "", true, false
	}
	return target, false, true
}

func asmSymbolHasMacroLikeComponent(target string) bool {
	if i := strings.LastIndex(target, "·"); i >= 0 {
		if asmTokenLooksMacroLike(target[:i]) || asmExternalDefineMayRewriteSymbol(target[:i]) {
			return true
		}
		target = target[i+len("·"):]
	}
	return asmTokenLooksMacroLike(target) || asmExternalDefineMayRewriteSymbol(target)
}

func asmExternalDefineMayRewriteSymbol(target string) bool {
	return asmExternalDefinesMayRewriteSymbols() && asmTokenCanBeMacroName(target)
}

func asmExternalDefinesMayRewriteSymbols() bool {
	flags := os.Getenv("GOFLAGS")
	if flags == "" {
		if out, err := gotool.Run("env", "GOFLAGS"); err == nil {
			flags = strings.TrimSpace(string(out))
		}
	}
	return strings.Contains(flags, "-asmflags") && strings.Contains(flags, "-D")
}

func asmTokenCanBeMacroName(target string) bool {
	if target == "" {
		return false
	}
	for i, r := range target {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func asmTokenLooksMacroLike(target string) bool {
	if target == "" {
		return false
	}
	hasUpper := false
	for _, r := range target {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return hasUpper
}

func asmSingleOpMayHideCall(fields []string) bool {
	if len(fields) != 1 {
		return false
	}
	op := fields[0]
	if op == "" || strings.HasPrefix(op, "#") || isASMPseudoOp(op) || isASMKnownZeroOp(op) {
		return false
	}
	return true
}

func asmUnknownOpMayHideCall(fields []string) bool {
	if len(fields) < 2 || isASMPseudoOp(fields[0]) {
		return false
	}
	if len(fields) == 2 {
		return true
	}
	if strings.Contains(fields[0], "_") {
		return true
	}
	for _, field := range fields[1:] {
		if strings.Contains(strings.TrimRight(field, ","), "(SB)") {
			return true
		}
	}
	return false
}

func isASMKnownZeroOp(op string) bool {
	if i := strings.IndexByte(op, '.'); i >= 0 {
		op = op[:i]
	}
	switch op {
	case "RET", "NOP":
		return true
	}
	return false
}

func isASMPseudoOp(op string) bool {
	if i := strings.IndexByte(op, '.'); i >= 0 {
		op = op[:i]
	}
	switch op {
	case "TEXT", "DATA", "GLOBL", "FUNCDATA", "PCDATA":
		return true
	}
	return false
}

func trimASMLabels(fields []string) []string {
	for len(fields) > 0 {
		first := fields[0]
		if strings.HasSuffix(first, ":") {
			fields = fields[1:]
			continue
		}
		if i := strings.IndexByte(first, ':'); i > 0 {
			fields[0] = first[i+1:]
			if fields[0] == "" {
				fields = fields[1:]
			}
		}
		return fields
	}
	return fields
}

func isASMCallOp(op string) bool {
	if i := strings.IndexByte(op, '.'); i >= 0 {
		op = op[:i]
	}
	switch op {
	case "CALL", "JMP", "BL", "JAL", "B", "BR":
		return true
	}
	return false
}

// isASMIndirectCallOp reports whether op transfers control through a register or
// otherwise computed target across Go's target architectures. Such a mnemonic's
// callee is never a parseable symbol, so any occurrence is a computed call that
// must widen to the maximal closure (§7.3-A′) — listing them explicitly keeps
// ordinary data-processing instructions (which also carry register operands)
// precise instead of blanket-widening on every register operand.
func isASMIndirectCallOp(op string) bool {
	if i := strings.IndexByte(op, '.'); i >= 0 {
		op = op[:i]
	}
	switch op {
	case "JALR", "JIRL", "JR", "BLR", "BCTRL", "BCTR", "BX", "BLX", "BAL", "CALLIND":
		return true
	}
	return false
}

func asmStatements(line string) []string {
	line = strings.TrimSpace(stripASMLineComment(line))
	if line == "" || strings.HasPrefix(line, "#") {
		return []string{line}
	}
	parts := splitASMStatements(line)
	stmts := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			stmts = append(stmts, part)
		}
	}
	return stmts
}

func splitASMStatements(line string) []string {
	var parts []string
	inString := false
	escaped := false
	start := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		if c == ';' {
			parts = append(parts, line[start:i])
			start = i + 1
		}
	}
	parts = append(parts, line[start:])
	return parts
}

func stripASMLineComment(line string) string {
	inString := false
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		if i+1 < len(line) && line[i:i+2] == "//" {
			return line[:i]
		}
	}
	return line
}

func asmExpandedLines(dir string, lines []string, stack map[string]bool) ([]string, bool, []string, error) {
	out := make([]string, 0, len(lines))
	var includes []string
	opaque := false
	for _, line := range lines {
		out = append(out, line)
		fields := normalizeASMPreprocessorFields(strings.Fields(strings.TrimSpace(stripASMLineComment(line))))
		if len(fields) < 2 || fields[0] != "#include" || !strings.HasPrefix(fields[1], "\"") || !strings.HasSuffix(fields[1], "\"") {
			continue
		}
		path, local, ok := asmIncludePath(dir, strings.Trim(fields[1], "\""))
		if !ok {
			return nil, false, nil, fmt.Errorf("closure: unresolved asm include %s", fields[1])
		}
		if local {
			includes = append(includes, path)
		}
		if stack[path] {
			opaque = true
			continue
		}
		stack[path] = true
		content, err := os.ReadFile(path)
		if err != nil {
			delete(stack, path)
			return nil, false, nil, fmt.Errorf("closure: read asm include %s: %w", path, err)
		}
		included, childOpaque, childIncludes, err := asmExpandedLines(dir, stripASMBlockComments(strings.Split(string(content), "\n")), stack)
		if err != nil {
			delete(stack, path)
			return nil, false, nil, err
		}
		opaque = opaque || childOpaque
		out = append(out, included...)
		includes = append(includes, childIncludes...)
		delete(stack, path)
	}
	return out, opaque, includes, nil
}

func stripASMBlockComments(lines []string) []string {
	out := make([]string, 0, len(lines))
	inComment := false
	for _, line := range lines {
		var b strings.Builder
		inString := false
		escaped := false
		for i := 0; i < len(line); {
			if inComment {
				end := strings.Index(line[i:], "*/")
				if end < 0 {
					break
				}
				i += end + len("*/")
				inComment = false
				continue
			}
			c := line[i]
			if inString {
				b.WriteByte(c)
				i++
				if escaped {
					escaped = false
					continue
				}
				if c == '\\' {
					escaped = true
					continue
				}
				if c == '"' {
					inString = false
				}
				continue
			}
			if c == '"' {
				inString = true
				b.WriteByte(c)
				i++
				continue
			}
			if i+1 < len(line) && line[i:i+2] == "/*" {
				b.WriteByte(' ')
				inComment = true
				i += len("/*")
				continue
			}
			b.WriteByte(c)
			i++
		}
		out = append(out, b.String())
	}
	return out
}

func asmIncludePath(dir, name string) (string, bool, bool) {
	if symlinkDirInPath(name, dir) != "" {
		return "", false, false
	}
	if filepath.IsAbs(name) {
		if _, err := os.Stat(name); err == nil {
			return name, true, true
		}
		return "", false, false
	}
	local := filepath.Join(dir, name)
	if _, err := os.Stat(local); err == nil {
		return local, true, true
	}
	goroot := filepath.Join(runtime.GOROOT(), "pkg", "include", name)
	if _, err := os.Stat(goroot); err == nil {
		return goroot, false, true
	}
	return "", false, false
}

func parseASMMacroSpec(spec string) (string, bool, []string) {
	if i := strings.IndexByte(spec, '('); i >= 0 && strings.HasSuffix(spec, ")") {
		name := spec[:i]
		if name == "" {
			return "", false, nil
		}
		raw := strings.TrimSuffix(spec[i+1:], ")")
		if raw == "" {
			return name, true, nil
		}
		parts := strings.Split(raw, ",")
		params := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				return "", false, nil
			}
			params = append(params, p)
		}
		return name, true, params
	}
	if strings.ContainsAny(spec, "()") {
		return "", false, nil
	}
	return spec, false, nil
}

func updateASMMacros(fields []string, macros map[string]asmMacro) (bool, bool) {
	if len(fields) == 0 {
		return false, false
	}
	switch fields[0] {
	case "#define":
		if len(fields) >= 2 {
			if fields[len(fields)-1] == "\\" {
				return true, true
			}
			name, funcLike, params := parseASMMacroSpec(fields[1])
			if name != "" {
				macros[name] = asmMacro{funcLike: funcLike, params: params, body: strings.Join(fields[2:], " ")}
			} else {
				return true, true
			}
		}
		return true, false
	case "#undef":
		if len(fields) >= 2 {
			delete(macros, fields[1])
		}
		return true, false
	case "#include":
		return true, false
	case "#if", "#ifdef", "#ifndef", "#elif", "#else", "#endif":
		return true, true
	}
	return false, false
}

func normalizeASMPreprocessorFields(fields []string) []string {
	if len(fields) >= 2 && fields[0] == "#" {
		out := make([]string, 0, len(fields)-1)
		out = append(out, "#"+fields[1])
		out = append(out, fields[2:]...)
		return out
	}
	return fields
}

func expandASMMacro(token string, macros map[string]asmMacro) (string, bool, bool) {
	if m, ok := macros[token]; ok && !m.funcLike {
		return m.body, true, false
	}
	open := strings.IndexByte(token, '(')
	if open < 0 || !strings.HasSuffix(token, ")") {
		return "", false, false
	}
	m, ok := macros[token[:open]]
	if !ok || !m.funcLike {
		return "", false, false
	}
	raw := strings.TrimSuffix(token[open+1:], ")")
	args, ok := parseASMMacroArgs(raw)
	if !ok {
		return "", false, true
	}
	if len(args) != len(m.params) {
		return "", false, true
	}
	body := m.body
	for i, p := range m.params {
		body = replaceASMMacroParam(body, p, strings.TrimSpace(args[i]))
	}
	return body, true, false
}

func parseASMMacroArgs(raw string) ([]string, bool) {
	if raw == "" {
		return nil, true
	}
	var args []string
	depth := 0
	start := 0
	for i, r := range raw {
		switch r {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return nil, false
			}
			depth--
		case ',':
			if depth == 0 {
				args = append(args, raw[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, false
	}
	args = append(args, raw[start:])
	return args, true
}

func expandASMFields(fields []string, macros map[string]asmMacro) ([]string, bool) {
	for depth := 0; depth < 64; depth++ {
		expanded := false
		for i := range fields {
			repl, consumed, ok, macroOpaque := expandASMMacroAt(fields, i, macros)
			if macroOpaque {
				return fields, true
			}
			if !ok {
				continue
			}
			replFields := strings.Fields(repl)
			next := make([]string, 0, len(fields)+len(replFields)-consumed)
			next = append(next, fields[:i]...)
			next = append(next, replFields...)
			next = append(next, fields[i+consumed:]...)
			fields = next
			expanded = true
			break
		}
		if !expanded {
			return fields, false
		}
	}
	return fields, true
}

func expandASMMacroAt(fields []string, i int, macros map[string]asmMacro) (string, int, bool, bool) {
	if repl, ok, opaque := expandASMMacro(fields[i], macros); opaque {
		return "", 0, false, true
	} else if ok {
		return repl, 1, true, false
	}
	if repl, ok, opaque := expandASMSymbolMacro(fields[i], macros); opaque {
		return "", 0, false, true
	} else if ok {
		return repl, 1, true, false
	}
	token := fields[i]
	consumed := 1
	if !strings.Contains(token, "(") && i+1 < len(fields) && strings.HasPrefix(fields[i+1], "(") {
		token += fields[i+1]
		consumed = 2
	}
	for strings.Contains(token, "(") && !strings.HasSuffix(token, ")") && i+consumed < len(fields) {
		token += fields[i+consumed]
		consumed++
	}
	if repl, ok, opaque := expandASMMacro(token, macros); opaque {
		return "", 0, false, true
	} else if ok {
		return repl, consumed, true, false
	}
	return "", 0, false, false
}

func expandASMSymbolMacro(field string, macros map[string]asmMacro) (string, bool, bool) {
	suffix := ""
	if strings.HasSuffix(field, ",") {
		suffix = ","
		field = strings.TrimSuffix(field, ",")
	}
	i := strings.LastIndex(field, "·")
	sb := strings.Index(field, "(SB)")
	if i < 0 || sb < 0 || i > sb {
		return "", false, false
	}
	if repl, ok, opaque := expandASMSymbolPrefixMacro(field, i, macros); opaque {
		return "", false, true
	} else if ok {
		return repl + suffix, true, false
	}
	name := field[i+len("·") : sb]
	if strings.ContainsAny(name, "+<") {
		return "", false, false
	}
	m, ok := macros[name]
	if !ok {
		return "", false, false
	}
	if m.funcLike {
		return "", false, true
	}
	body := strings.Fields(m.body)
	if len(body) != 1 || strings.ContainsAny(body[0], "·()+<>,") {
		return "", false, true
	}
	return field[:i+len("·")] + body[0] + field[sb:] + suffix, true, false
}

func expandASMSymbolPrefixMacro(field string, dot int, macros map[string]asmMacro) (string, bool, bool) {
	prefix := field[:dot]
	if prefix == "" || strings.ContainsAny(prefix, "*()+<>,") {
		return "", false, false
	}
	m, ok := macros[prefix]
	if !ok {
		return "", false, false
	}
	if m.funcLike {
		return "", false, true
	}
	body := strings.Fields(m.body)
	if len(body) != 1 || strings.ContainsAny(body[0], "·()+<>,") {
		return "", false, true
	}
	return body[0] + field[dot:], true, false
}

func replaceASMMacroParam(body, param, arg string) string {
	fields := strings.Fields(body)
	for i, field := range fields {
		fields[i] = replaceASMMacroParamField(field, param, arg)
	}
	return strings.Join(fields, " ")
}

func replaceASMMacroParamField(field, param, arg string) string {
	suffix := ""
	if strings.HasSuffix(field, ",") {
		suffix = ","
		field = strings.TrimSuffix(field, ",")
	}
	if field == param {
		return arg + suffix
	}
	if open := strings.IndexByte(field, '('); open > 0 && strings.HasSuffix(field, ")") {
		inner := strings.TrimSuffix(field[open+1:], ")")
		if inner == param {
			return field[:open+1] + arg + ")" + suffix
		}
	}
	if i := strings.LastIndex(field, "·"); i >= 0 {
		if field[:i] == param {
			return arg + field[i:] + suffix
		}
		rest := field[i+len("·"):]
		if end := strings.Index(rest, "(SB)"); end >= 0 {
			name := rest[:end]
			if name == param {
				return field[:i+len("·")] + arg + rest[end:] + suffix
			}
			if strings.HasPrefix(name, param+"+") {
				return field[:i+len("·")] + arg + name[len(param):] + rest[end:] + suffix
			}
		}
	}
	if end := strings.Index(field, "(SB)"); end > 0 {
		if field[:end] == param {
			return arg + field[end:] + suffix
		}
	}
	return field + suffix
}

func asmLabels(lines []string) map[string]bool {
	labels := map[string]bool{}
	for _, line := range lines {
		line = strings.TrimSpace(stripASMLineComment(line))
		if i := strings.IndexByte(line, ':'); i > 0 {
			label := strings.TrimSpace(line[:i])
			if label != "" && !strings.ContainsAny(label, " \t") {
				labels[label] = true
			}
		}
	}
	return labels
}

func isLocalASMTarget(target string, labels map[string]bool) bool {
	if labels[target] || strings.HasSuffix(target, "(PC)") {
		return true
	}
	if target == "" {
		return false
	}
	if last := target[len(target)-1]; last == 'b' || last == 'f' {
		target = target[:len(target)-1]
	}
	if target == "" {
		return false
	}
	for _, r := range target {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isStdImportPath(path string) bool {
	if path == "" || path == "C" {
		return false
	}
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	return !strings.Contains(first, ".")
}

func isBenchmarkHarnessPath(path string) bool {
	return path == "testing" || strings.HasPrefix(path, "testing/")
}
