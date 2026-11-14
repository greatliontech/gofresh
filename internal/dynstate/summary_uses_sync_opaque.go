package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func walkSyncVarCalls(p *packages.Package, candidates map[*types.Var]bool, evictNonCallUses bool, judgeCall func(v *types.Var, sel *ast.SelectorExpr, call *ast.CallExpr) (admittedMethod, siteConforms bool)) map[*ast.SelectorExpr]bool {
	if len(candidates) == 0 {
		return nil
	}
	info := p.TypesInfo
	receiver := map[*ast.Ident]bool{}
	conformingBySelector := map[*ast.SelectorExpr]*types.Var{}
	resolveVarIdent := func(expr ast.Expr) *ast.Ident {
		switch e := syntaxutil.UnparenExpr(expr).(type) {
		case *ast.Ident:
			return e
		case *ast.SelectorExpr:
			if x, ok := syntaxutil.UnparenExpr(e.X).(*ast.Ident); ok {
				if _, isPkg := info.Uses[x].(*types.PkgName); isPkg {
					return e.Sel
				}
			}
		}
		return nil
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := syntaxutil.UnparenExpr(call.Fun).(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident := resolveVarIdent(sel.X)
			if ident == nil {
				return true
			}
			v, ok := info.Uses[ident].(*types.Var)
			if !ok || !candidates[v] {
				return true
			}
			admittedMethod, siteConforms := judgeCall(v, sel, call)
			if !admittedMethod {
				delete(candidates, v)
				return true
			}
			receiver[ident] = true
			if siteConforms {
				conformingBySelector[sel] = v
			} else if !evictNonCallUses {
				delete(candidates, v)
			}
			return true
		})
	}
	if evictNonCallUses {
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				ident, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				v, ok := info.Uses[ident].(*types.Var)
				if ok && candidates[v] && !receiver[ident] {
					delete(candidates, v)
				}
				return true
			})
		}
	}
	calls := map[*ast.SelectorExpr]bool{}
	for sel, v := range conformingBySelector {
		if candidates[v] {
			calls[sel] = true
		}
	}
	return calls
}

func dataMemoVars(audited bool, p *packages.Package, callIdx *refconfine.CallSiteIndex) map[*types.Var]bool {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil
	}
	isSyncMap := func(t types.Type) bool {
		named, ok := types.Unalias(t).(*types.Named)
		return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "sync" && named.Obj().Name() == "Map"
	}
	candidates := map[*types.Var]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v.Exported() || !isSyncMap(v.Type()) {
			continue
		}
		candidates[v] = true
	}
	if len(candidates) == 0 {
		return nil
	}
	carrierFree := func(expr ast.Expr) bool {
		if callIdx == nil {
			callIdx = refconfine.BuildCallSiteIndex(p)
		}
		return callIdx.JudgeExpr(expr, func(t types.Type) (bool, bool) {
			if !refconfine.TypeMayCarryUnknownDynamic(audited, t) {
				return true, true
			}
			return false, false
		})
	}
	// Evict any sync.Map candidate referenced outside a direct MemoMethod call
	// (such as `&memo`, `alias := &memo`, or passing `memo` as an argument).
	walkSyncVarCalls(p, candidates, true, func(_ *types.Var, sel *ast.SelectorExpr, call *ast.CallExpr) (bool, bool) {
		if !auditset.MemoMethod("Map", sel.Sel.Name) {
			return false, false
		}
		for _, arg := range call.Args {
			if !carrierFree(arg) {
				return false, false
			}
		}
		return true, true
	})
	return candidates
}

func provenSharedPools(audited bool, p *packages.Package) (proven map[*types.Var]types.Type, calls map[*ast.SelectorExpr]bool) {
	proven = map[*types.Var]types.Type{}
	calls = map[*ast.SelectorExpr]bool{}
	if p.TypesInfo == nil {
		return proven, calls
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				name := vs.Names[0]
				if name.IsExported() {
					continue
				}
				variable, ok := p.TypesInfo.Defs[name].(*types.Var)
				if !ok || variable.Pkg() == nil {
					continue
				}
				named, ok := types.Unalias(variable.Type()).(*types.Named)
				if !ok || named.Obj() == nil || named.Obj().Pkg() == nil ||
					named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Pool" {
					continue
				}
				lit, ok := syntaxutil.UnparenExpr(vs.Values[0]).(*ast.CompositeLit)
				if !ok || len(lit.Elts) != 1 {
					continue
				}
				kv, ok := lit.Elts[0].(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "New" {
					continue
				}
				fnLit, ok := syntaxutil.UnparenExpr(kv.Value).(*ast.FuncLit)
				if !ok {
					continue
				}
				content := provenPoolContentType(audited, p, fnLit)
				if content == nil {
					continue
				}
				proven[variable] = content
			}
		}
	}
	if len(proven) == 0 {
		return proven, calls
	}
	candidates := make(map[*types.Var]bool, len(proven))
	for v := range proven {
		candidates[v] = true
	}
	calls = walkSyncVarCalls(p, candidates, true, func(v *types.Var, sel *ast.SelectorExpr, call *ast.CallExpr) (bool, bool) {
		selection, ok := p.TypesInfo.Selections[sel]
		if !ok || selection.Kind() != types.MethodVal {
			return false, false
		}
		fn, ok := selection.Obj().(*types.Func)
		if !ok || !refconfine.AuditedPooling(audited, fn) {
			return false, false
		}
		return true, provenPoolCallConforms(p, fn, call, proven[v])
	})
	for v := range proven {
		if !candidates[v] {
			delete(proven, v)
		}
	}
	return proven, calls
}

func provenPoolContentType(audited bool, p *packages.Package, lit *ast.FuncLit) types.Type {
	if lit.Type == nil || lit.Type.Results == nil {
		return nil
	}
	for _, field := range lit.Type.Results.List {
		if len(field.Names) > 0 {
			return nil
		}
	}
	var content types.Type
	conforming := true
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if !conforming {
			return false
		}
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		if _, deferred := n.(*ast.DeferStmt); deferred {
			conforming = false
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		if len(ret.Results) != 1 {
			conforming = false
			return false
		}
		tv, ok := p.TypesInfo.Types[ret.Results[0]]
		if !ok || tv.Type == nil {
			conforming = false
			return false
		}
		t := tv.Type
		if basic, isBasic := types.Unalias(t).(*types.Basic); isBasic && basic.Info()&types.IsUntyped != 0 {
			conforming = false
			return false
		}
		if content == nil {
			content = t
		} else if !types.Identical(content, t) {
			conforming = false
			return false
		}
		return true
	})
	if !conforming || content == nil {
		return nil
	}
	if refconfine.TypeMayCarryUnknownDynamic(audited, content) {
		return nil
	}
	return content
}

func provenPoolCallConforms(p *packages.Package, fn *types.Func, call *ast.CallExpr, content types.Type) bool {
	switch fn.Name() {
	case "Get":
		return len(call.Args) == 0
	case "Put":
		if len(call.Args) != 1 {
			return false
		}
		tv, ok := p.TypesInfo.Types[call.Args[0]]
		if !ok || tv.Type == nil {
			return false
		}
		return types.Identical(tv.Type, content)
	default:
		return false
	}
}

func recordFunctionReferenceRegions(p *packages.Package, initOnly map[string]bool, refs map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return
	}
	funcKeyOf := func(obj types.Object) (syntaxutil.FuncKey, bool) {
		fn, ok := obj.(*types.Func)
		if !ok || fn.Pkg() == nil {
			return syntaxutil.FuncKey{}, false
		}
		fn = fn.Origin()
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil {
			return syntaxutil.FuncKey{}, false
		}
		return syntaxutil.FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}, true
	}
	add := func(callee syntaxutil.FuncKey, region syntaxutil.RefRegion) {
		if refs[callee] == nil {
			refs[callee] = map[syntaxutil.RefRegion]bool{}
		}
		refs[callee][region] = true
	}
	literalRegion := func(region syntaxutil.RefRegion) syntaxutil.RefRegion {
		switch region.Kind {
		case syntaxutil.RegionLitFunc:
			return region
		case syntaxutil.RegionFunc:
			return syntaxutil.RefRegion{Kind: syntaxutil.RegionLitFunc, Caller: region.Caller}
		default:
			return syntaxutil.RefRegion{Kind: syntaxutil.RegionProg}
		}
	}
	var scan func(region syntaxutil.RefRegion, root ast.Node)
	scan = func(region syntaxutil.RefRegion, root ast.Node) {
		calls := map[*ast.Ident]bool{}
		ast.Inspect(root, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				if n != root && n.Body != nil {
					scan(literalRegion(region), n.Body)
					return false
				}
			case *ast.GoStmt:
				scan(literalRegion(region), n.Call)
				return false
			case *ast.CallExpr:
				fun := syntaxutil.UnwrapCallee(n.Fun)
				if ident, ok := fun.(*ast.Ident); ok {
					if key, ok := funcKeyOf(p.TypesInfo.Uses[ident]); ok {
						calls[ident] = true
						add(key, region)
					}
				}
				if sel, ok := fun.(*ast.SelectorExpr); ok {
					if key, ok := funcKeyOf(p.TypesInfo.Uses[sel.Sel]); ok {
						calls[sel.Sel] = true
						add(key, region)
					}
				}
			case *ast.Ident:
				if calls[n] {
					return true
				}
				if key, ok := funcKeyOf(p.TypesInfo.Uses[n]); ok {
					add(key, literalRegion(region))
				}
			}
			return true
		})
	}
	initReg := syntaxutil.RefRegion{Kind: syntaxutil.RegionInit}
	progReg := syntaxutil.RefRegion{Kind: syntaxutil.RegionProg}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				switch {
				case decl.Recv != nil:
					if decl.Body != nil {
						scan(progReg, decl.Body)
					}
				case decl.Name != nil && (decl.Name.Name == "init" || initOnly[decl.Name.Name]):
					if decl.Body != nil {
						scan(initReg, decl.Body)
					}
				case decl.Name != nil && decl.Name.Name != "_":
					if decl.Body != nil && p.Types != nil {
						scan(syntaxutil.RefRegion{Kind: syntaxutil.RegionFunc, Caller: syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: decl.Name.Name}}, decl.Body)
					}
				default:
					if decl.Body != nil {
						scan(progReg, decl.Body)
					}
				}
			default:
				scan(initReg, decl)
			}
		}
	}
}

func recordOpaqueDynamicVars(p *packages.Package, opaque, breaks map[string]bool, deps map[string]map[string]bool) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return
	}
	interfacePackageVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		_, isInterface := types.Unalias(variable.Type()).Underlying().(*types.Interface)
		return variable, isInterface
	}
	var auditedImmutable func(expr ast.Expr, storeDeps map[string]bool) bool
	auditedArgument := func(expr ast.Expr, storeDeps map[string]bool) bool {
		if expr == nil {
			return false
		}
		if auditedImmutable(expr, storeDeps) {
			return true
		}
		if storeDeps != nil {
			var target *ast.Ident
			switch e := syntaxutil.UnparenExpr(expr).(type) {
			case *ast.Ident:
				target = e
			case *ast.SelectorExpr:
				if x, ok := syntaxutil.UnparenExpr(e.X).(*ast.Ident); ok {
					if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
						target = e.Sel
					}
				}
			}
			if target != nil {
				if obj, ok := p.TypesInfo.Uses[target]; ok {
					if variable, ok := interfacePackageVar(obj); ok {
						storeDeps[syntaxutil.DynamicVarKey(variable)] = true
						return true
					}
				}
			}
		}
		return false
	}
	auditedImmutable = func(expr ast.Expr, storeDeps map[string]bool) bool {
		expr = syntaxutil.UnparenExpr(expr)
		if expr == nil {
			return false
		}
		if tv, ok := p.TypesInfo.Types[expr]; ok && tv.Value != nil {
			return true
		}
		if t := p.TypesInfo.TypeOf(expr); t != nil && refconfine.ImmutableRuntimeType(t) {
			return true
		}
		switch expr := expr.(type) {
		case *ast.Ident:
			return expr.Name == "nil" && p.TypesInfo.Uses[expr] == types.Universe.Lookup("nil")
		case *ast.CallExpr:
			fn, pkgPath := syntaxutil.PlainCalleeFunc(p, expr.Fun)
			if fn == nil {
				return false
			}
			if pkgPath == "errors" && fn.Name() == "New" {
				return len(expr.Args) == 1 && !expr.Ellipsis.IsValid()
			}
			if pkgPath == "fmt" && fn.Name() == "Errorf" && !expr.Ellipsis.IsValid() {
				for _, arg := range expr.Args {
					if !auditedArgument(arg, storeDeps) {
						return false
					}
				}
				return true
			}
			return false
		default:
			return false
		}
	}

	failed := map[string]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		if variable, ok := interfacePackageVar(scope.Lookup(name)); ok {
			opaque[syntaxutil.DynamicVarKey(variable)] = true
		}
	}

	audit := func(target *ast.Ident, value ast.Expr) {
		if target == nil {
			return
		}
		obj, ok := p.TypesInfo.Defs[target]
		if !ok || obj == nil {
			if obj, ok = p.TypesInfo.Uses[target]; !ok {
				return
			}
		}
		if variable, ok := interfacePackageVar(obj); ok {
			key := syntaxutil.DynamicVarKey(variable)
			storeDeps := map[string]bool{}
			if value == nil || !auditedArgument(value, storeDeps) {
				failed[key] = true
				return
			}
			for dep := range storeDeps {
				if deps == nil {
					break
				}
				if deps[key] == nil {
					deps[key] = map[string]bool{}
				}
				deps[key][dep] = true
			}
		}
	}
	failSubtree := func(expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if obj := syntaxutil.IdentDefOrUse(p.TypesInfo, ident); obj != nil {
				if variable, ok := interfacePackageVar(obj); ok {
					failed[syntaxutil.DynamicVarKey(variable)] = true
				}
			}
			return true
		})
	}
	failTargets := func(expr ast.Expr) {
		for {
			switch t := expr.(type) {
			case *ast.Ident:
				if obj := syntaxutil.IdentDefOrUse(p.TypesInfo, t); obj != nil {
					if variable, ok := interfacePackageVar(obj); ok {
						failed[syntaxutil.DynamicVarKey(variable)] = true
					}
				}
				return
			case *ast.SelectorExpr:
				if obj, ok := p.TypesInfo.Uses[t.Sel]; ok {
					if variable, ok := interfacePackageVar(obj); ok {
						failed[syntaxutil.DynamicVarKey(variable)] = true
						return
					}
				}
				expr = t.X
			case *ast.IndexExpr:
				expr = t.X
			case *ast.SliceExpr:
				expr = t.X
			case *ast.StarExpr:
				expr = t.X
			case *ast.ParenExpr:
				expr = t.X
			default:
				failSubtree(expr)
				return
			}
		}
	}

	inspectBody := func(root ast.Node) {
		ast.Inspect(root, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.ValueSpec:
				if len(n.Values) == 0 {
					return true
				}
				if len(n.Names) != len(n.Values) {
					for _, ident := range n.Names {
						failTargets(ident)
					}
					return true
				}
				for i, ident := range n.Names {
					audit(ident, n.Values[i])
				}
			case *ast.AssignStmt:
				if (n.Tok != token.ASSIGN && n.Tok != token.DEFINE) || len(n.Lhs) != len(n.Rhs) {
					for _, lhs := range n.Lhs {
						failTargets(lhs)
					}
					return true
				}
				for i, lhs := range n.Lhs {
					switch target := syntaxutil.UnparenExpr(lhs).(type) {
					case *ast.Ident:
						audit(target, n.Rhs[i])
					case *ast.SelectorExpr:
						if base, ok := syntaxutil.UnparenExpr(target.X).(*ast.Ident); ok {
							if _, isPkg := p.TypesInfo.Uses[base].(*types.PkgName); isPkg {
								audit(target.Sel, n.Rhs[i])
								continue
							}
						}
						failTargets(lhs)
					default:
						failTargets(lhs)
					}
				}
			case *ast.IncDecStmt:
				failTargets(n.X)
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					if _, composite := syntaxutil.UnparenExpr(n.X).(*ast.CompositeLit); !composite {
						failTargets(n.X)
					}
				}
			case *ast.SliceExpr:
				if t := p.TypesInfo.TypeOf(n.X); t != nil {
					if _, isArr := types.Unalias(t).Underlying().(*types.Array); isArr {
						failTargets(n.X)
					}
				}
			case *ast.RangeStmt:
				if n.Key != nil {
					failTargets(n.Key)
				}
				if n.Value != nil {
					failTargets(n.Value)
				}
			}
			return true
		})
	}

	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			inspectBody(decl)
		}
	}
	for key := range failed {
		delete(opaque, key)
		breaks[key] = true
	}
}
