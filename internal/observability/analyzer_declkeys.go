package observability

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
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
	if fn == nil {
		return nil
	}
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		return fn.Pkg.Pkg
	}
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
	forEachGoLinknameDirective([]*ast.CommentGroup{doc}, func(local, target string, valid bool) {
		if !valid || target == "" {
			return
		}
		if out == nil {
			out = map[string]string{}
		}
		if prev := out[local]; prev != "" && prev != target {
			out[local] = "<conflict>"
		} else {
			out[local] = target
		}
	})
	return out
}

func typeUsesUnsafePointer(t types.Type) bool {
	return typeUsesUnsafePointerWith(t, false, nil, nil)
}

func isBenchmarkHarnessPath(path string) bool {
	return path == "testing" || strings.HasPrefix(path, "testing/")
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
