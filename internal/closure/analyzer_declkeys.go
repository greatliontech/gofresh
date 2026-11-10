package closure

import (
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/closure/internal/toolchain"
)

func typeDeclaringPkg(t types.Type) *types.Package {
	if t == nil {
		return nil
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	switch x := t.(type) {
	case *types.Named:
		if x.Obj() != nil {
			return x.Obj().Pkg()
		}
	case *types.Struct:
		for i := 0; i < x.NumFields(); i++ {
			if pkg := x.Field(i).Pkg(); pkg != nil {
				return pkg
			}
		}
	}
	return nil
}

func funcDeclaringPkg(fn *ssa.Function) *types.Package {
	if isUnnamedStructPromotedWrapper(fn) {
		return unnamedWrapperDeclaringPkg(fn)
	}
	for f := fn; f != nil; f = f.Parent() {
		if f.Pkg != nil && f.Pkg.Pkg != nil {
			return f.Pkg.Pkg
		}
		if obj := f.Object(); obj != nil && obj.Pkg() != nil {
			return obj.Pkg()
		}
		if orig := f.Origin(); orig != nil {
			if orig.Pkg != nil && orig.Pkg.Pkg != nil {
				return orig.Pkg.Pkg
			}
			if obj := orig.Object(); obj != nil && obj.Pkg() != nil {
				return obj.Pkg()
			}
		}
		if f.Signature != nil {
			if recv := f.Signature.Recv(); recv != nil {
				if pkg := typeDeclaringPkg(recv.Type()); pkg != nil {
					return pkg
				}
			} else if strings.HasPrefix(f.Synthetic, "thunk for ") && f.Signature.Params().Len() > 0 {
				if pkg := typeDeclaringPkg(f.Signature.Params().At(0).Type()); pkg != nil {
					return pkg
				}
			}
		}
	}
	return nil
}

func idxForFunctionIn(idxByTypes map[*types.Package]*pkgIndex, fn *ssa.Function) *pkgIndex {
	if pkg := funcDeclaringPkg(fn); pkg != nil {
		return idxByTypes[pkg]
	}
	return nil
}

// invokeEdgeName names the interface-dispatch edge an unresolved invoke
// opens: the enclosing function and the interface method it dispatches
// (receiver interface type qualified by package path, then the method
// name; invoke-mode SSA always carries both). Portable across checkouts
// - it carries no source position, so an unrelated edit never thrashes
// the memoized reason - and stable under the lexicographic-least widen
// selection, which then names a concrete opening edge instead of the
// bare shape (REQ-closure-observability-dispatch).
func invokeEdgeName(c *ssa.CallCommon, caller *ssa.Function) string {
	return caller.String() + " dispatches " +
		types.TypeString(c.Value.Type(), nil) + "." + c.Method.Name()
}

// computedEdgeSuffix names the called value of a computed function call
// where it has a stable identity - a parameter, or a load from a named
// package-level variable (a package-level function called directly is a
// static call per ssa.CallCommon.StaticCallee, so the stably-named
// computed shapes are exactly these) - so the refusal points past the
// enclosing function to the value dispatched. A register-only operand
// adds nothing and the suffix stays empty
// (REQ-closure-observability-dispatch).
func computedEdgeSuffix(c *ssa.CallCommon) string {
	switch v := c.Value.(type) {
	case *ssa.Parameter:
		return " calling parameter " + v.Name()
	case *ssa.UnOp:
		if g, ok := v.X.(*ssa.Global); ok && v.Op == token.MUL {
			return " calling " + g.RelString(nil)
		}
	}
	return ""
}

func funcPkgPath(fn *ssa.Function) string {
	if pkg := funcDeclaringPkg(fn); pkg != nil {
		return pkg.Path()
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

func linknamesFromDoc(doc *ast.CommentGroup) map[string]string {
	if doc == nil {
		return nil
	}
	var out map[string]string
	for _, c := range doc.List {
		if !strings.Contains(c.Text, "go:linkname") {
			continue
		}
		text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		text = strings.TrimSpace(strings.TrimPrefix(text, "/*"))
		text = strings.TrimSpace(strings.TrimSuffix(text, "*/"))
		fields := strings.Fields(text)
		if len(fields) >= 3 && (fields[0] == "go:linkname" || fields[0] == "go:linknamestd") {
			if out == nil {
				out = map[string]string{}
			}
			if prev := out[fields[1]]; prev != "" && prev != fields[2] {
				out[fields[1]] = "<conflict>"
			} else {
				out[fields[1]] = fields[2]
			}
		}
	}
	return out
}

func typeUsesUnsafePointer(t types.Type) bool {
	found := false
	walkTypeGraph(t, false, map[types.Type]bool{}, func(t types.Type) bool {
		if basic, ok := t.(*types.Basic); ok && basic.Kind() == types.UnsafePointer {
			found = true
			return false
		}
		if n, ok := t.(*types.Named); ok {
			if obj := n.Obj(); obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "unsafe" && obj.Name() == "Pointer" {
				found = true
				return false
			}
		}
		return true
	})
	return found
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
// while that library changes (REQ-closure-blindspot, REQ-fresh-verdict). `-Xlinker <arg>` needs no expansion —
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

func hasNonHeaderNativeSource(p *listPkg) bool {
	if p == nil {
		return false
	}
	for _, files := range [][]string{
		p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.FFiles,
		p.SwigFiles, p.SwigCXXFiles, p.SysoFiles,
	} {
		if len(files) > 0 {
			return true
		}
	}
	return false
}

func hasCgoCallbackBlindspot(p *listPkg) bool {
	return hasNonHeaderNativeSource(p) || (p != nil && len(p.HFiles) > 0)
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

// funcDeclKey uniquely identifies an ordinary top-level function or method
// declaration across type-checked package variants and syntactic file scans.
// Package-level init functions and user TestMain declarations are never
// filtered by funcDeclKey.
type funcDeclKey struct {
	dir       string
	pkgClause string
	recv      string
	name      string
}

func funcDeclKeyForAST(dir, pkgClause string, fn *ast.FuncDecl) (funcDeclKey, bool) {
	if fn == nil || fn.Name == nil || fn.Name.Name == "" || fn.Name.Name == "init" {
		return funcDeclKey{}, false
	}
	recv := ""
	if fn.Recv != nil {
		if len(fn.Recv.List) != 1 {
			return funcDeclKey{}, false
		}
		recv = toolchain.RecvBaseTypeName(fn.Recv.List[0].Type)
		if recv == "" {
			return funcDeclKey{}, false
		}
	}
	return funcDeclKey{
		dir:       filepath.Clean(dir),
		pkgClause: pkgClause,
		recv:      recv,
		name:      fn.Name.Name,
	}, true
}

func unreachedASTDecls(dir, pkgClause string, file *ast.File, testMainDecl *ast.FuncDecl, reachedDecls map[funcDeclKey]bool) []ast.Node {
	if reachedDecls == nil || file == nil {
		return nil
	}
	dir = filepath.Clean(dir)
	var unreached []ast.Node
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d == testMainDecl || (d.Name != nil && d.Name.Name == "TestMain") {
				continue
			}
			if key, ok := funcDeclKeyForAST(dir, pkgClause, d); ok && !reachedDecls[key] {
				unreached = append(unreached, d)
			}
		case *ast.GenDecl:
			switch d.Tok {
			case token.TYPE:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || ts.Name == nil || ts.Name.Name == "" || ts.Name.Name == "_" {
						continue
					}
					key := funcDeclKey{dir: dir, pkgClause: pkgClause, name: ts.Name.Name}
					if !reachedDecls[key] {
						unreached = append(unreached, ts)
					}
				}
			case token.CONST:
				hasNamed := false
				anyReached := false
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range vs.Names {
						if name == nil || name.Name == "" {
							continue
						}
						if name.Name == "_" {
							anyReached = true
							continue
						}
						hasNamed = true
						key := funcDeclKey{dir: dir, pkgClause: pkgClause, name: name.Name}
						if reachedDecls[key] {
							anyReached = true
						}
					}
				}
				if hasNamed && !anyReached {
					unreached = append(unreached, d)
				}
			}
		}
	}
	return unreached
}

func subjectReachedDeclKeys(base *tier2Base, reach attributedReachability, subjectObjects map[types.Object]bool) map[funcDeclKey]bool {
	reached, _ := subjectReachedAndStartupOnlyDeclKeys(base, reach, subjectObjects, nil)
	return reached
}

func baseStartupObjectsForReach(base *tier2Base, reach attributedReachability, zeroGlobals map[*ssa.Global]bool) (map[types.Object]bool, bool) {
	if base == nil || !reach.baseStartup || len(reach.cleanupFunctions) != 0 || len(reach.testMainFunctions) != 0 || len(reach.rootedExtraFunctions) != 0 || len(reach.instantiatedOrigins) != 0 {
		return nil, false
	}
	slot := 0
	if len(zeroGlobals) > 0 {
		slot = 1
	}
	if !base.baseStartupObjsDone[slot] {
		baseReach := reach
		baseReach.subjectFunctions = nil
		aux := base.analyzer()
		aux.rtaResolved = baseReach.resolved
		aux.openWorld = baseReach.openWorld
		aux.enumeratedTypes = baseReach.enumeratedTypes
		aux.initBoxedTypes = baseReach.initBoxedTypes
		aux.startupOnly = syncStartupOnlyFunctionsForBase(base, baseReach)
		aux.zeroGlobals = zeroGlobals
		aux.zeroGlobalDecls = zeroGlobalDeclKeys(zeroGlobals)
		for fn := range baseReach.startupFunctions {
			aux.addFunction(fn)
			if idx := aux.idxForFunction(fn); idx == nil || !idx.std {
				aux.scanFunction(fn)
			}
		}
		_ = aux.drainObjects()
		base.baseStartupObjs[slot] = aux.seenObjects
		base.baseStartupObjsDone[slot] = true
	}
	return base.baseStartupObjs[slot], true
}

func subjectReachedAndStartupOnlyDeclKeys(base *tier2Base, reach attributedReachability, subjectObjects map[types.Object]bool, zeroGlobals map[*ssa.Global]bool) (map[funcDeclKey]bool, map[funcDeclKey]bool) {
	startupOnly := syncStartupOnlyFunctionsForBase(base, reach)
	startupObjs, reusedStartupObjs := baseStartupObjectsForReach(base, reach, zeroGlobals)
	if !reusedStartupObjs {
		aux := base.analyzer()
		aux.rtaResolved = reach.resolved
		aux.skipOriginScan = reach.instantiatedOrigins
		aux.openWorld = reach.openWorld
		aux.enumeratedTypes = reach.enumeratedTypes
		aux.initBoxedTypes = reach.initBoxedTypes
		aux.startupOnly = startupOnly
		aux.zeroGlobals = zeroGlobals
		aux.zeroGlobalDecls = zeroGlobalDeclKeys(zeroGlobals)
		for obj := range subjectObjects {
			aux.seenObjects[obj] = true
		}
		for fn := range reach.startupFunctions {
			aux.addFunction(fn)
			if idx := aux.idxForFunction(fn); idx == nil || !idx.std {
				aux.scanFunction(fn)
			}
		}
		for fn := range reach.testMainFunctions {
			aux.addFunction(fn)
			if idx := aux.idxForFunction(fn); idx == nil || !idx.std {
				aux.scanFunction(fn)
			}
		}
		_ = aux.drainObjects()
		startupObjs = aux.seenObjects
	}
	keys := make(map[funcDeclKey]bool, len(startupObjs)+len(subjectObjects)+len(reach.functions)+len(reach.instantiatedOrigins))
	candidateStartupKeys := make(map[funcDeclKey]bool, len(startupOnly))
	nonStartupKeys := make(map[funcDeclKey]bool, len(subjectObjects)+len(reach.subjectFunctions)+len(reach.testMainFunctions)+len(reach.cleanupFunctions)+len(reach.rootedExtraFunctions))
	addObjTo := func(dst map[funcDeclKey]bool, obj types.Object) {
		obj = originObject(obj)
		if obj == nil || obj.Pkg() == nil {
			return
		}
		if idx := base.idxByTypes[obj.Pkg()]; idx != nil {
			if key, ok := idx.funcKeys[obj]; ok {
				dst[key] = true
			}
		}
	}
	addFnSelfTo := func(dst map[funcDeclKey]bool, fn *ssa.Function) {
		if fn == nil {
			return
		}
		if orig := fn.Origin(); orig != nil {
			addObjTo(dst, orig.Object())
		}
		addObjTo(dst, fn.Object())
	}
	addFnTo := func(dst map[funcDeclKey]bool, fn *ssa.Function) {
		for cur := fn; cur != nil; cur = cur.Parent() {
			addFnSelfTo(dst, cur)
		}
	}
	for obj := range startupObjs {
		addObjTo(keys, obj)
	}
	for obj := range subjectObjects {
		if reusedStartupObjs {
			addObjTo(keys, obj)
		}
		addObjTo(nonStartupKeys, obj)
	}
	for fn := range reach.functions {
		addFnTo(keys, fn)
		if !startupOnly[fn] {
			addFnTo(nonStartupKeys, fn)
		}
	}
	for fn := range reach.subjectFunctions {
		addFnTo(keys, fn)
		addFnTo(nonStartupKeys, fn)
	}
	for fn := range reach.startupFunctions {
		addFnTo(keys, fn)
		if startupOnly[fn] {
			addFnSelfTo(candidateStartupKeys, fn)
		} else {
			addFnTo(nonStartupKeys, fn)
		}
	}
	for fn := range reach.cleanupFunctions {
		addFnTo(nonStartupKeys, fn)
	}
	for fn := range reach.testMainFunctions {
		addFnTo(keys, fn)
		addFnTo(nonStartupKeys, fn)
	}
	for fn := range reach.rootedExtraFunctions {
		addFnTo(keys, fn)
		addFnTo(nonStartupKeys, fn)
	}
	for fn := range reach.instantiatedOrigins {
		addFnTo(keys, fn)
	}
	var startupOnlyKeys map[funcDeclKey]bool
	for key := range candidateStartupKeys {
		if !nonStartupKeys[key] {
			if startupOnlyKeys == nil {
				startupOnlyKeys = make(map[funcDeclKey]bool, len(candidateStartupKeys))
			}
			startupOnlyKeys[key] = true
		}
	}
	return keys, startupOnlyKeys
}
