package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func boundValueLeakFree(audited bool, p *packages.Package, roots map[types.Object]bool, body ast.Node) bool {
	return boundValueLeakFreeJudged(audited, p, roots, body, nil, nil, nil, nil, nil)
}

func boundValueLeakFreeDeferred(audited bool, p *packages.Package, roots map[types.Object]bool, body ast.Node, wants map[syntaxutil.ParamKey]bool) bool {
	return boundValueLeakFreeJudged(audited, p, roots, body, wants, nil, nil, nil, nil)
}

func boundValueLeakFreeJudged(
	audited bool,
	p *packages.Package,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	returns *bool,
	methodWants map[syntaxutil.FuncKey]bool,
	fieldWants map[syntaxutil.FieldPosKey]bool,
	elemWants map[syntaxutil.ElemParamUse]bool,
) bool {
	return boundValueJudged(audited, p, roots, body, wants, returns, methodWants, fieldWants, elemWants, false)
}

func boundValueRetentionFreeJudged(
	audited bool,
	p *packages.Package,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
) bool {
	return boundValueJudged(audited, p, roots, body, wants, nil, methodWants, nil, nil, true)
}

func boundValueJudged(
	audited bool,
	p *packages.Package,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	returns *bool,
	methodWants map[syntaxutil.FuncKey]bool,
	fieldWants map[syntaxutil.FieldPosKey]bool,
	elemWants map[syntaxutil.ElemParamUse]bool,
	tolerateRootedStores bool,
) bool {
	if p == nil || p.TypesInfo == nil || body == nil || len(roots) == 0 {
		return false
	}
	goCalls := map[*ast.CallExpr]bool{}
	goIdents := map[ast.Node]bool{}
	litReturns := map[*ast.ReturnStmt]bool{}
	calleeReads := map[ast.Node]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			for cur := syntaxutil.UnparenExpr(call.Fun); ; {
				switch x := cur.(type) {
				case *ast.SelectorExpr, *ast.Ident:
					calleeReads[x] = true
					goto doneCallee
				case *ast.IndexExpr:
					calleeReads[x] = true
					cur = syntaxutil.UnparenExpr(x.X)
				case *ast.IndexListExpr:
					calleeReads[x] = true
					cur = syntaxutil.UnparenExpr(x.X)
				default:
					goto doneCallee
				}
			}
		doneCallee:
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.GoStmt:
			ast.Inspect(n, func(inner ast.Node) bool {
				if call, ok := inner.(*ast.CallExpr); ok {
					goCalls[call] = true
				}
				if lit, ok := inner.(*ast.FuncLit); ok {
					ast.Inspect(lit, func(deep ast.Node) bool {
						if call, ok := deep.(*ast.CallExpr); ok {
							goCalls[call] = true
						}
						if ident, ok := deep.(*ast.Ident); ok {
							goIdents[ident] = true
						}
						return true
					})
					return false
				}
				return true
			})
		case *ast.FuncLit:
			ast.Inspect(n, func(inner ast.Node) bool {
				if ret, ok := inner.(*ast.ReturnStmt); ok {
					litReturns[ret] = true
				}
				return true
			})
			return false
		}
		return true
	})
	carrierReaching := map[types.Object]bool{}
	carrierReach := func(expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		found := false
		ast.Inspect(expr, func(m ast.Node) bool {
			if found {
				return false
			}
			if ident, ok := m.(*ast.Ident); ok {
				if obj := p.TypesInfo.Uses[ident]; obj != nil {
					if carrierReaching[obj] {
						found = true
						return false
					}
					if variable, ok := obj.(*types.Var); ok && variable.Pkg() != nil &&
						variable.Parent() == variable.Pkg().Scope() &&
						refconfine.TypeMayCarryUnknownDynamic(audited, variable.Type()) {
						found = true
					}
				}
			}
			return true
		})
		return found
	}
	if tolerateRootedStores {
		syntaxutil.PropagateLocalTaint(
			p.TypesInfo,
			body,
			carrierReaching,
			func(types.Object) bool { return true },
			carrierReach,
			carrierReach,
		)
	}
	tainted := map[types.Object]bool{}
	isRoot := func(expr ast.Expr) bool {
		ident, ok := expr.(*ast.Ident)
		if !ok {
			return false
		}
		obj := p.TypesInfo.Uses[ident]
		if obj == nil {
			obj = p.TypesInfo.Defs[ident]
		}
		return obj != nil && (roots[obj] || tainted[obj])
	}
	rooted := func(expr ast.Expr) bool {
		ident := syntaxutil.RootIdent(expr)
		return ident != nil && isRoot(ident)
	}
	syntaxutil.PropagateLocalTaint(
		p.TypesInfo,
		body,
		tainted,
		func(obj types.Object) bool {
			return !roots[obj] && (refconfine.TypeHandsOutMutableReach(obj.Type()) || refconfine.TypeCarriesSignature(obj.Type()))
		},
		rooted,
		rooted,
	)
	allowed := map[ast.Node]bool{}
	consume := func(expr ast.Expr) {
		if ident := syntaxutil.RootIdent(expr); ident != nil {
			allowed[ident] = true
		}
	}
	methodValueBind := func(expr ast.Expr) bool {
		return syntaxutil.IsMethodValueBind(p.TypesInfo, expr)
	}
	leaky := false
	ast.Inspect(body, func(n ast.Node) bool {
		if leaky {
			return false
		}
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, rhs := range n.Rhs {
					if rooted(rhs) {
						if methodValueBind(rhs) {
							leaky = true
						} else if _, ok := n.Lhs[i].(*ast.Ident); ok {
							consume(rhs)
						}
					}
				}
			} else if len(n.Rhs) == 1 && rooted(n.Rhs[0]) {
				if methodValueBind(n.Rhs[0]) {
					leaky = true
				} else {
					allIdent := true
					for _, lhs := range n.Lhs {
						if _, ok := lhs.(*ast.Ident); !ok {
							allIdent = false
						}
					}
					if allIdent {
						consume(n.Rhs[0])
					}
				}
			}
			for i, lhs := range n.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					if obj := syntaxutil.IdentDefOrUse(p.TypesInfo, ident); obj != nil && (roots[obj] || tainted[obj]) {
						if obj.Pos() < body.Pos() || obj.Pos() > body.End() {
							leaky = true
						}
						if fieldWants != nil && refconfine.TypeCarriesSignature(obj.Type()) {
							var rhs ast.Expr
							if len(n.Lhs) == len(n.Rhs) {
								rhs = n.Rhs[i]
							} else if len(n.Rhs) == 1 {
								rhs = n.Rhs[0]
							}
							originDefine := roots[obj] && p.TypesInfo.Defs[ident] != nil
							if (rhs == nil || !rooted(rhs)) && !originDefine {
								leaky = true
							}
						}
					}
					consume(ident)
					continue
				}
				if rooted(lhs) {
					var rhs ast.Expr
					if len(n.Lhs) == len(n.Rhs) {
						rhs = n.Rhs[i]
					} else if len(n.Rhs) == 1 {
						rhs = n.Rhs[0]
					}
					smuggles := false
					if rhs != nil {
						if t := p.TypesInfo.TypeOf(rhs); t == nil ||
							refconfine.TypeHandsOutMutableReach(t) ||
							refconfine.TypeCarriesSignature(t) {
							smuggles = carrierReach(rhs) || t == nil
						}
					}
					if tolerateRootedStores && !smuggles {
						consume(lhs)
					} else {
						leaky = true
					}
				}
			}
		case *ast.ValueSpec:
			if len(n.Names) == len(n.Values) {
				for i, rhs := range n.Values {
					if rooted(rhs) {
						if methodValueBind(rhs) {
							leaky = true
							continue
						}
						consume(rhs)
						allowed[n.Names[i]] = true
					}
				}
			} else if len(n.Values) == 1 && rooted(n.Values[0]) {
				if methodValueBind(n.Values[0]) {
					leaky = true
				} else {
					consume(n.Values[0])
					for _, name := range n.Names {
						allowed[name] = true
					}
				}
			}
		case *ast.IncDecStmt:
			if rooted(n.X) {
				if tolerateRootedStores {
					consume(n.X)
				} else {
					leaky = true
				}
			}
		case *ast.SendStmt:
			if rooted(n.Chan) {
				leaky = true
			}
		case *ast.UnaryExpr:
			if (n.Op == token.AND || n.Op == token.ARROW) && rooted(n.X) {
				leaky = true
			}
		case *ast.RangeStmt:
			for _, bind := range []ast.Expr{n.Key, n.Value} {
				if bind == nil {
					continue
				}
				if ident, ok := bind.(*ast.Ident); ok {
					if obj := syntaxutil.IdentDefOrUse(p.TypesInfo, ident); obj != nil && (roots[obj] || tainted[obj]) {
						if obj.Pos() < body.Pos() || obj.Pos() > body.End() {
							leaky = true
						}
						if fieldWants != nil && refconfine.TypeCarriesSignature(obj.Type()) {
							originDefine := roots[obj] && p.TypesInfo.Defs[ident] != nil
							if !rooted(n.X) && !originDefine {
								leaky = true
							}
						}
					}
					consume(ident)
					continue
				}
				if rooted(bind) {
					smuggles := false
					if t := p.TypesInfo.TypeOf(bind); t == nil ||
						refconfine.TypeHandsOutMutableReach(t) ||
						refconfine.TypeCarriesSignature(t) {
						smuggles = carrierReach(n.X) || t == nil
					}
					if tolerateRootedStores && !smuggles {
						consume(bind)
					} else {
						leaky = true
					}
				}
			}
			if rooted(n.X) {
				if t := p.TypesInfo.TypeOf(n.X); t == nil {
					leaky = true
				} else if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
					leaky = true
				} else {
					for _, bind := range []ast.Expr{n.Key, n.Value} {
						if ident, ok := bind.(*ast.Ident); ok {
							consume(ident)
						} else if bind != nil {
							leaky = true
						}
					}
					consume(n.X)
				}
			}
		case *ast.ReturnStmt:
			for _, result := range n.Results {
				if rooted(result) {
					if t := p.TypesInfo.TypeOf(result); t == nil || refconfine.TypeHandsOutMutableReach(t) {
						if returns != nil && t != nil && !litReturns[n] && !methodValueBind(result) {
							*returns = true
							consume(result)
						} else {
							leaky = true
						}
					} else if methodValueBind(result) || refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(result)) {
						leaky = true
					} else {
						consume(result)
					}
				}
			}
		case *ast.CallExpr:
			if ident, ok := n.Fun.(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "len" || ident.Name == "cap") {
					for _, arg := range n.Args {
						if rooted(arg) {
							consume(arg)
						}
					}
					break
				}
			}
			if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
				if len(n.Args) == 1 && rooted(n.Args[0]) && !methodValueBind(n.Args[0]) {
					if t := p.TypesInfo.TypeOf(n); t != nil && !refconfine.TypeHandsOutMutableReach(t) && !refconfine.TypeCarriesSignature(t) {
						consume(n.Args[0])
					}
				}
				break
			}
			if sel, ok := syntaxutil.UnwrapCallee(n.Fun).(*ast.SelectorExpr); ok && rooted(sel.X) {
				selection, selOK := p.TypesInfo.Selections[sel]
				if selOK && selection.Kind() == types.MethodVal {
					fn, isFunc := selection.Obj().(*types.Func)
					if isFunc && refconfine.AuditedSynchronization(audited, fn) {
						consume(sel.X)
						break
					}
					if isFunc && methodWants != nil && !goCalls[n] && fn.Pkg() != nil && !syntaxutil.InterfaceReceiver(fn) && refconfine.InstantiatedResultsHandOutNothing(audited, selection.Type()) {
						methodWants[syntaxutil.MethodFactKey(fn)] = true
						consume(sel.X)
					} else {
						leaky = true
					}
				} else if selOK && selection.Kind() == types.FieldVal {
				} else {
					leaky = true
				}
			}
			if fun := syntaxutil.UnparenExpr(n.Fun); rooted(fun) {
				if refconfine.CallResultHandsOut(p.TypesInfo.TypeOf(n)) {
					leaky = true
				}
			}
			for i, arg := range n.Args {
				if rooted(arg) {
					if t := p.TypesInfo.TypeOf(arg); t == nil || refconfine.TypeHandsOutMutableReach(t) || refconfine.TypeCarriesSignature(t) {
						deferred := false
						if wants != nil && !goCalls[n] {
							if fn, pkgPath := syntaxutil.PlainCalleeFunc(p, n.Fun); fn != nil {
								if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() == nil && sig.Params().Len() > 0 {
									idx := i
									if sig.Variadic() && idx >= sig.Params().Len()-1 {
										idx = sig.Params().Len() - 1
									}
									wants[syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: pkgPath, Name: fn.Name()}, Index: idx}] = true
									consume(arg)
									deferred = true
								}
							}
						}
						if !deferred && fieldWants != nil && !goCalls[n] {
							if sel, ok := syntaxutil.UnwrapCallee(n.Fun).(*ast.SelectorExpr); ok && rooted(sel.X) {
								if selection, selOK := p.TypesInfo.Selections[sel]; selOK && selection.Kind() == types.FieldVal {
									if sig, sigOK := types.Unalias(selection.Type()).Underlying().(*types.Signature); sigOK && sig.Params().Len() > 0 {
										idx := i
										if sig.Variadic() && idx >= sig.Params().Len()-1 {
											idx = sig.Params().Len() - 1
										}
										fieldWants[syntaxutil.FieldPosKey{Field: sel.Sel.Name, Index: idx}] = true
										consume(arg)
										deferred = true
									}
								}
							}
						}
						if !deferred && elemWants != nil && !goCalls[n] {
							if index, ok := syntaxutil.UnparenExpr(n.Fun).(*ast.IndexExpr); ok {
								if base, ok := syntaxutil.UnparenExpr(index.X).(*ast.Ident); ok {
									obj := p.TypesInfo.Uses[base]
									if v, isVar := obj.(*types.Var); isVar && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
										if sig, sigOK := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(n.Fun)).(*types.Signature); sigOK && sig.Params().Len() > 0 {
											idx := i
											if sig.Variadic() && idx >= sig.Params().Len()-1 {
												idx = sig.Params().Len() - 1
											}
											elemWants[syntaxutil.ElemParamUse{Owner: syntaxutil.DynamicVarKey(v), Index: idx}] = true
											consume(arg)
											deferred = true
										}
									}
								}
							}
						}
						if !deferred {
							leaky = true
						}
					} else if methodValueBind(arg) {
						leaky = true
					} else {
						consume(arg)
					}
				}
			}
		case *ast.IndexExpr:
			if rooted(n.X) && !allowed[syntaxutil.RootIdent(n.X)] {
				if t := p.TypesInfo.TypeOf(n); t == nil || refconfine.TypeHandsOutMutableReach(t) || (!calleeReads[n] && refconfine.TypeCarriesSignature(t)) {
					leaky = true
				} else {
					consume(n.X)
				}
			}
		case *ast.SelectorExpr:
			if rooted(n.X) && !allowed[syntaxutil.RootIdent(n.X)] {
				if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
					break
				}
				if t := p.TypesInfo.TypeOf(n); t == nil || refconfine.TypeHandsOutMutableReach(t) || (!calleeReads[n] && refconfine.TypeCarriesSignature(t)) {
					leaky = true
				} else {
					consume(n.X)
				}
			}
		case *ast.BinaryExpr:
			if n.Op == token.EQL || n.Op == token.NEQ {
				if rooted(n.X) {
					consume(n.X)
				}
				if rooted(n.Y) {
					consume(n.Y)
				}
			}
		case *ast.Ident:
			if isRoot(n) && (goIdents[n] || (!allowed[n] && !calleeReads[n])) {
				leaky = true
			}
		}
		return true
	})
	return !leaky
}

func paramLeakFreeFunctions(
	audited bool,
	p *packages.Package,
	readOnlyLocal, retentionMethods map[string]bool,
) (
	map[syntaxutil.ParamKey]bool,
	map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool,
	map[syntaxutil.ParamKey]bool,
	map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool,
) {
	if p == nil || p.TypesInfo == nil {
		return nil, nil, nil, nil
	}
	proven := map[syntaxutil.ParamKey]bool{}
	allWants := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	retention := map[syntaxutil.ParamKey]bool{}
	allRetentionWants := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	retainOnly := func(obj types.Object, body ast.Node, key syntaxutil.ParamKey) {
		wants := map[syntaxutil.ParamKey]bool{}
		methodWants := map[syntaxutil.FuncKey]bool{}
		if !boundValueRetentionFreeJudged(audited, p, map[types.Object]bool{obj: true}, body, wants, methodWants) {
			return
		}
		for want := range methodWants {
			if want.Pkg != ownPath || !retentionMethods[want.Name] {
				return
			}
		}
		if len(wants) == 0 {
			retention[key] = true
			return
		}
		allRetentionWants[key] = wants
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Type.Params == nil {
				continue
			}
			ownFunc := syntaxutil.FuncKey{Pkg: ownPath, Name: fd.Name.Name}
			index := 0
			for _, field := range fd.Type.Params.List {
				names := field.Names
				if len(names) == 0 {
					names = []*ast.Ident{nil}
				}
				for _, name := range names {
					idx := index
					index++
					key := syntaxutil.ParamKey{Func: ownFunc, Index: idx}
					if name == nil || name.Name == "_" {
						proven[key] = true
						continue
					}
					obj := p.TypesInfo.Defs[name]
					if obj == nil {
						continue
					}
					if !refconfine.TypeHandsOutMutableReach(obj.Type()) {
						continue
					}
					wants := map[syntaxutil.ParamKey]bool{}
					methodWants := map[syntaxutil.FuncKey]bool{}
					if !boundValueLeakFreeJudged(audited, p, map[types.Object]bool{obj: true}, fd.Body, wants, nil, methodWants, nil, nil) {
						retainOnly(obj, fd.Body, key)
						continue
					}
					methodsProven := true
					for want := range methodWants {
						if want.Pkg != ownPath || !readOnlyLocal[want.Name] || !retentionMethods[want.Name] {
							methodsProven = false
							break
						}
					}
					if !methodsProven {
						continue
					}
					if len(wants) == 0 {
						proven[key] = true
						continue
					}
					allWants[key] = wants
				}
			}
		}
	}
	deps := resolveLocalParamDeps(ownPath, proven, allWants, func(need syntaxutil.ParamKey) bool {
		return proven[need]
	})
	retentionDeps := resolveLocalParamDeps(ownPath, retention, allRetentionWants, func(need syntaxutil.ParamKey) bool {
		return retention[need] || proven[need]
	})
	return proven, deps, retention, retentionDeps
}

func resolveLocalParamDeps(ownPath string, proven map[syntaxutil.ParamKey]bool, allWants map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool, satisfied func(syntaxutil.ParamKey) bool) map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool {
	conditional := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	deps := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	for key, wants := range allWants {
		crossPackage := false
		for want := range wants {
			if want.Func.Pkg != ownPath {
				crossPackage = true
				break
			}
		}
		if crossPackage {
			deps[key] = wants
		} else {
			conditional[key] = wants
		}
	}
	syntaxutil.SolveLeastFixedPoint(proven, conditional, satisfied)
	for key, needs := range conditional {
		if satisfied(key) {
			continue
		}
		edges := map[syntaxutil.ParamKey]bool{}
		for need := range needs {
			if !satisfied(need) {
				edges[need] = true
			}
		}
		deps[key] = edges
	}
	return deps
}

func receiverRetentionFreeMethods(audited bool, p *packages.Package, _ map[string]bool) map[string]bool {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	proven := map[string]bool{}
	pending := map[string]map[string]bool{}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name == nil || fd.Body == nil || len(fd.Recv.List) != 1 {
				continue
			}
			recvName := syntaxutil.RecvTypeName(fd)
			if recvName == "" {
				continue
			}
			key := recvName + "." + fd.Name.Name
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			if recvIdent == nil {
				proven[key] = true
				continue
			}
			recvObj := p.TypesInfo.Defs[recvIdent]
			if recvObj == nil {
				continue
			}
			wants := map[syntaxutil.ParamKey]bool{}
			methodWants := map[syntaxutil.FuncKey]bool{}
			if !boundValueRetentionFreeJudged(audited, p, map[types.Object]bool{recvObj: true}, fd.Body, wants, methodWants) {
				continue
			}
			if len(wants) != 0 {
				continue
			}
			needs := map[string]bool{}
			sound := true
			for want := range methodWants {
				if want.Pkg != ownPath {
					sound = false
					break
				}
				needs[want.Name] = true
			}
			if !sound {
				continue
			}
			if len(needs) == 0 {
				proven[key] = true
				continue
			}
			pending[key] = needs
		}
	}
	syntaxutil.SolveLeastFixedPoint(proven, pending, func(need string) bool {
		return proven[need]
	})
	return proven
}

// onceFieldOfDo resolves a call of the shape `x.field.Do(f)` — Do on a
// by-value sync.Once field selected from some value — to that field,
// or nil for every other shape.
func onceFieldOfDo(audited bool, info *types.Info, call *ast.CallExpr) *types.Var {
	if len(call.Args) != 1 {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.MethodVal {
		return nil
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok || !refconfine.AuditedOnceDo(audited, fn) {
		return nil
	}
	fieldSel, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	fieldSelection, ok := info.Selections[fieldSel]
	if !ok || fieldSelection.Kind() != types.FieldVal || len(fieldSelection.Index()) != 1 {
		return nil
	}
	field, ok := fieldSelection.Obj().(*types.Var)
	if !ok {
		return nil
	}
	named, ok := types.Unalias(field.Type()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Once" {
		return nil
	}
	return field
}

func closedInterfaceFields(p *packages.Package, callIdx *refconfine.CallSiteIndex) map[*types.Var][]string {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil
	}
	info := p.TypesInfo
	candidateField := func(field *types.Var) bool {
		if field == nil || !field.IsField() || field.Exported() || field.Pkg() != p.Types {
			return false
		}
		_, isIface := types.Unalias(field.Type()).Underlying().(*types.Interface)
		return isIface
	}
	any := false
	for _, name := range p.Types.Scope().Names() {
		typeName, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := typeName.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields() && !any; i++ {
			any = candidateField(st.Field(i))
		}
	}
	if !any {
		return nil
	}
	if callIdx == nil {
		callIdx = refconfine.BuildCallSiteIndex(p)
	}
	memberTypes := func(expr ast.Expr) ([]string, bool) {
		var members []string
		ok := callIdx.JudgeExpr(expr, func(t types.Type) (bool, bool) {
			if _, isIface := types.Unalias(t).Underlying().(*types.Interface); isIface {
				return false, false
			}
			concrete := types.Unalias(t)
			if ptr, ok := concrete.(*types.Pointer); ok {
				concrete = types.Unalias(ptr.Elem())
			}
			named, ok := concrete.(*types.Named)
			if !ok || named.Obj() == nil || named.Obj().Pkg() != p.Types {
				return true, false
			}
			members = append(members, named.Obj().Name())
			return true, true
		})
		return members, ok
	}
	fieldOf := func(structType types.Type, index int) *types.Var {
		if ptr, ok := types.Unalias(structType).(*types.Pointer); ok {
			structType = ptr.Elem()
		}
		st, ok := types.Unalias(structType).Underlying().(*types.Struct)
		if !ok || index < 0 || index >= st.NumFields() {
			return nil
		}
		if field := st.Field(index); candidateField(field) {
			return field
		}
		return nil
	}
	members := map[*types.Var][]string{}
	open := map[*types.Var]bool{}
	store := func(field *types.Var, value ast.Expr) {
		if !candidateField(field) || open[field] {
			return
		}
		more, ok := memberTypes(value)
		if !ok {
			open[field] = true
			delete(members, field)
			return
		}
		members[field] = append(members[field], more...)
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				t := info.TypeOf(n)
				if t == nil {
					return true
				}
				if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
					t = ptr.Elem()
				}
				for i, elt := range n.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if key, ok := kv.Key.(*ast.Ident); ok {
							if field, ok := info.Uses[key].(*types.Var); ok {
								store(field, kv.Value)
							}
						}
						continue
					}
					store(fieldOf(t, i), elt)
				}
			case *ast.AssignStmt:
				if len(n.Lhs) != len(n.Rhs) {
					for _, lhs := range n.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok {
							if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
								if field, ok := selection.Obj().(*types.Var); ok {
									open[field] = true
									delete(members, field)
								}
							}
						}
					}
					return true
				}
				for i, lhs := range n.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					selection, ok := info.Selections[sel]
					if !ok || selection.Kind() != types.FieldVal {
						continue
					}
					if field, ok := selection.Obj().(*types.Var); ok {
						store(field, n.Rhs[i])
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					if sel, ok := n.X.(*ast.SelectorExpr); ok {
						if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
							if field, ok := selection.Obj().(*types.Var); ok {
								open[field] = true
								delete(members, field)
							}
						}
					}
				}
			case *ast.CallExpr:
				tv, ok := info.Types[n.Fun]
				if !ok || !tv.IsType() || len(n.Args) != 1 {
					return true
				}
				to := info.TypeOf(n)
				if to == nil {
					return true
				}
				if ptr, ok := types.Unalias(to).(*types.Pointer); ok {
					to = ptr.Elem()
				}
				st, ok := types.Unalias(to).Underlying().(*types.Struct)
				if !ok || types.Identical(info.TypeOf(n.Args[0]), to) {
					return true
				}
				for i := 0; i < st.NumFields(); i++ {
					if field := fieldOf(to, i); field != nil {
						open[field] = true
						delete(members, field)
					}
				}
			}
			return true
		})
	}
	closed := map[*types.Var][]string{}
	for field, names := range members {
		if open[field] || len(names) == 0 {
			continue
		}
		sort.Strings(names)
		closed[field] = slices.Compact(names)
	}
	return closed
}

func closedFieldDispatchTargets(info *types.Info, recvObj types.Object, sel *ast.SelectorExpr, name string, closed map[*types.Var][]string, declared map[string]bool) ([]string, bool) {
	fieldSel, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	ident, ok := fieldSel.X.(*ast.Ident)
	if !ok || info.Uses[ident] != recvObj {
		return nil, false
	}
	selection, ok := info.Selections[fieldSel]
	if !ok || selection.Kind() != types.FieldVal || len(selection.Index()) != 1 {
		return nil, false
	}
	field, ok := selection.Obj().(*types.Var)
	if !ok {
		return nil, false
	}
	members, ok := closed[field]
	if !ok {
		return nil, false
	}
	targets := make([]string, 0, len(members))
	for _, member := range members {
		target := member + "." + name
		if !declared[target] {
			return nil, false
		}
		targets = append(targets, target)
	}
	return targets, true
}

func unexportedDispatchTargets(p *packages.Package, selection *types.Selection, fn *types.Func, declaredByName map[string][]string, bodyless map[string]bool) ([]string, bool) {
	if p.Types == nil || fn.Exported() || fn.Pkg() != p.Types || selection.Recv() == nil || bodyless[fn.Name()] {
		return nil, false
	}
	recv := types.Unalias(selection.Recv())
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = types.Unalias(ptr.Elem())
	}
	if _, ok := recv.Underlying().(*types.Interface); !ok {
		return nil, false
	}
	targets := append([]string(nil), declaredByName[fn.Name()]...)
	return targets, len(targets) > 0
}

func receiverReadOnlyMethods(audited bool, p *packages.Package, callIdx *refconfine.CallSiteIndex) map[string]bool {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	type methodBody struct {
		decl *ast.FuncDecl
		recv *ast.Ident
	}
	methods := map[string]methodBody{}
	bodyless := map[string]bool{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Recv != nil && fd.Name != nil && fd.Body == nil {
				bodyless[fd.Name.Name] = true
			}
			if !ok || fd.Recv == nil || fd.Name == nil || fd.Body == nil || len(fd.Recv.List) != 1 {
				continue
			}
			recvName := syntaxutil.RecvTypeName(fd)
			if recvName == "" {
				continue
			}
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			methods[recvName+"."+fd.Name.Name] = methodBody{decl: fd, recv: recvIdent}
		}
	}
	if len(methods) == 0 {
		return nil
	}
	onceSites := map[*types.Var]int{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if field := onceFieldOfDo(audited, p.TypesInfo, call); field != nil {
				onceSites[field]++
			}
			return true
		})
	}
	declaredByName := map[string][]string{}
	declared := map[string]bool{}
	for key := range methods {
		declared[key] = true
		if dot := strings.LastIndex(key, "."); dot >= 0 {
			declaredByName[key[dot+1:]] = append(declaredByName[key[dot+1:]], key)
		}
	}
	closedFields := closedInterfaceFields(p, callIdx)
	for _, keys := range declaredByName {
		sort.Strings(keys)
	}
	disqualified := map[string]bool{}
	chains := map[string]map[string]bool{}
	for key, m := range methods {
		if m.recv == nil {
			continue
		}
		recvObj := p.TypesInfo.Defs[m.recv]
		if recvObj == nil {
			disqualified[key] = true
			continue
		}
		tainted := map[types.Object]bool{}
		isRecv := func(expr ast.Expr) bool {
			ident, ok := expr.(*ast.Ident)
			if !ok {
				return false
			}
			obj := p.TypesInfo.Uses[ident]
			return obj == recvObj || (obj != nil && tainted[obj])
		}
		recvRooted := func(expr ast.Expr) bool {
			ident := syntaxutil.RootIdent(expr)
			return ident != nil && isRecv(ident)
		}
		siblingLeaky := func(sel *ast.SelectorExpr) (bool, bool) {
			selection, ok := p.TypesInfo.Selections[sel]
			if !ok || selection.Kind() != types.MethodVal {
				return false, false
			}
			fn, ok := selection.Obj().(*types.Func)
			if !ok || fn.Pkg() != p.Types {
				return false, false
			}
			if _, sibling := methods[syntaxutil.RecvTypeNameOf(p, sel)+"."+fn.Name()]; !sibling {
				return false, false
			}
			return true, !refconfine.InstantiatedResultsHandOutNothing(audited, selection.Type())
		}
		rhsHandsReceiverValue := func(rhs ast.Expr) bool {
			if recvRooted(rhs) {
				return true
			}
			if call, ok := rhs.(*ast.CallExpr); ok {
				if sel, ok := syntaxutil.UnwrapCallee(call.Fun).(*ast.SelectorExpr); ok && recvRooted(sel.X) {
					if _, leaky := siblingLeaky(sel); leaky {
						return true
					}
				}
			}
			return false
		}
		syntaxutil.PropagateLocalTaint(
			p.TypesInfo,
			m.decl.Body,
			tainted,
			func(obj types.Object) bool {
				return obj != recvObj && refconfine.TypeHandsOutMutableReach(obj.Type())
			},
			rhsHandsReceiverValue,
			recvRooted,
		)
		allowed := map[ast.Node]bool{}
		governedCalls := map[*ast.CallExpr]bool{}
		consume := func(expr ast.Expr) {
			if ident := syntaxutil.RootIdent(expr); ident != nil {
				allowed[ident] = true
			}
		}
		methodValueBind := func(expr ast.Expr) bool {
			return syntaxutil.IsMethodValueBind(p.TypesInfo, expr)
		}
		escapingSink := func(ident *ast.Ident) bool {
			if p.Types == nil {
				return true
			}
			obj := syntaxutil.IdentDefOrUse(p.TypesInfo, ident)
			return obj != nil && obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() && refconfine.TypeHandsOutMutableReach(obj.Type())
		}
		onceFill := map[ast.Node]bool{}
		ast.Inspect(m.decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			field := onceFieldOfDo(audited, p.TypesInfo, call)
			if field == nil || onceSites[field] != 1 || field.Exported() {
				return true
			}
			ident, ok := call.Fun.(*ast.SelectorExpr).X.(*ast.SelectorExpr).X.(*ast.Ident)
			if !ok || p.TypesInfo.Uses[ident] != recvObj || refconfine.OnceFieldCount(recvObj.Type()) != 1 {
				return true
			}
			if _, pointer := types.Unalias(recvObj.Type()).(*types.Pointer); !pointer {
				return true
			}
			lit, ok := call.Args[0].(*ast.FuncLit)
			if !ok {
				return true
			}
			for _, stmt := range lit.Body.List {
				switch stmt := stmt.(type) {
				case *ast.AssignStmt:
					fill := true
					for _, lhs := range stmt.Lhs {
						if recvRooted(lhs) && !refconfine.FillSelection(p.TypesInfo, lhs) {
							fill = false
						}
					}
					if fill {
						onceFill[stmt] = true
					}
				case *ast.IncDecStmt:
					if refconfine.FillSelection(p.TypesInfo, stmt.X) {
						onceFill[stmt] = true
					}
				}
			}
			return true
		})
		innerReturns := map[*ast.ReturnStmt]bool{}
		ast.Inspect(m.decl.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.FuncLit)
			if !ok {
				return true
			}
			ast.Inspect(lit.Body, func(inner ast.Node) bool {
				if r, ok := inner.(*ast.ReturnStmt); ok {
					innerReturns[r] = true
				}
				return true
			})
			return false
		})
		ast.Inspect(m.decl.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				governRHS := func(i int, rhs ast.Expr) {
					call, ok := rhs.(*ast.CallExpr)
					if !ok {
						return
					}
					sel, ok := syntaxutil.UnwrapCallee(call.Fun).(*ast.SelectorExpr)
					if !ok || !recvRooted(sel.X) {
						return
					}
					if sibling, _ := siblingLeaky(sel); !sibling {
						return
					}
					if i >= 0 {
						ident, ok := n.Lhs[i].(*ast.Ident)
						if !ok || escapingSink(ident) {
							return
						}
					} else {
						for _, lhs := range n.Lhs {
							ident, ok := lhs.(*ast.Ident)
							if !ok || escapingSink(ident) {
								return
							}
						}
					}
					governedCalls[call] = true
				}
				if len(n.Lhs) == len(n.Rhs) {
					for i, rhs := range n.Rhs {
						governRHS(i, rhs)
						if recvRooted(rhs) {
							if methodValueBind(rhs) {
								disqualified[key] = true
							} else if ident, ok := n.Lhs[i].(*ast.Ident); ok {
								if escapingSink(ident) {
									disqualified[key] = true
								} else {
									consume(rhs)
								}
							}
						}
					}
				} else if len(n.Rhs) == 1 {
					governRHS(-1, n.Rhs[0])
					if recvRooted(n.Rhs[0]) {
						if methodValueBind(n.Rhs[0]) {
							disqualified[key] = true
						}
						allIdent := true
						sink := false
						for _, lhs := range n.Lhs {
							ident, ok := lhs.(*ast.Ident)
							if !ok {
								allIdent = false
							} else if escapingSink(ident) {
								sink = true
							}
						}
						if allIdent && !methodValueBind(n.Rhs[0]) {
							if sink {
								disqualified[key] = true
							} else {
								consume(n.Rhs[0])
							}
						}
					}
				}
				for _, lhs := range n.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						if p.TypesInfo.Uses[ident] == recvObj || p.TypesInfo.Defs[ident] == recvObj {
							disqualified[key] = true
						}
						consume(ident)
						continue
					}
					if recvRooted(lhs) && !onceFill[n] {
						disqualified[key] = true
					}
				}
			case *ast.ValueSpec:
				governSpecRHS := func(i int, rhs ast.Expr) {
					call, ok := rhs.(*ast.CallExpr)
					if !ok {
						return
					}
					sel, ok := syntaxutil.UnwrapCallee(call.Fun).(*ast.SelectorExpr)
					if !ok || !recvRooted(sel.X) {
						return
					}
					if sibling, _ := siblingLeaky(sel); !sibling {
						return
					}
					if i >= 0 {
						if escapingSink(n.Names[i]) {
							return
						}
					} else {
						for _, name := range n.Names {
							if escapingSink(name) {
								return
							}
						}
					}
					governedCalls[call] = true
				}
				if len(n.Names) == len(n.Values) {
					for i, rhs := range n.Values {
						governSpecRHS(i, rhs)
						if recvRooted(rhs) {
							if methodValueBind(rhs) || escapingSink(n.Names[i]) {
								disqualified[key] = true
								continue
							}
							consume(rhs)
							allowed[n.Names[i]] = true
						}
					}
				} else if len(n.Values) == 1 {
					governSpecRHS(-1, n.Values[0])
					if recvRooted(n.Values[0]) {
						if methodValueBind(n.Values[0]) {
							disqualified[key] = true
						} else {
							sink := false
							for _, name := range n.Names {
								if escapingSink(name) {
									sink = true
								}
							}
							if sink {
								disqualified[key] = true
							} else {
								consume(n.Values[0])
								for _, name := range n.Names {
									allowed[name] = true
								}
							}
						}
					}
				}
			case *ast.IncDecStmt:
				if recvRooted(n.X) && !onceFill[n] {
					disqualified[key] = true
				}
			case *ast.SendStmt:
				if recvRooted(n.Chan) {
					disqualified[key] = true
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND && recvRooted(n.X) {
					disqualified[key] = true
				}
			case *ast.RangeStmt:
				for _, bind := range []ast.Expr{n.Key, n.Value} {
					if bind == nil {
						continue
					}
					if ident, ok := bind.(*ast.Ident); ok {
						if p.TypesInfo.Uses[ident] == recvObj || p.TypesInfo.Defs[ident] == recvObj {
							disqualified[key] = true
						}
						consume(ident)
						continue
					}
					if recvRooted(bind) && !onceFill[n] {
						disqualified[key] = true
					}
				}
				if recvRooted(n.X) {
					t := p.TypesInfo.TypeOf(n.X)
					if t == nil {
						disqualified[key] = true
					} else if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
						disqualified[key] = true
					} else {
						for _, bind := range []ast.Expr{n.Key, n.Value} {
							if ident, ok := bind.(*ast.Ident); ok && ident != nil {
								if escapingSink(ident) {
									disqualified[key] = true
									continue
								}
								consume(ident)
							} else if bind != nil {
								disqualified[key] = true
							}
						}
						consume(n.X)
					}
				}
			case *ast.ReturnStmt:
				if innerReturns[n] {
					for _, result := range n.Results {
						if recvRooted(result) {
							disqualified[key] = true
						}
					}
					break
				}
				for _, result := range n.Results {
					if recvRooted(result) {
						if methodValueBind(result) {
							disqualified[key] = true
							continue
						}
						consume(result)
					}
					if call, ok := result.(*ast.CallExpr); ok {
						if sel, ok := syntaxutil.UnwrapCallee(call.Fun).(*ast.SelectorExpr); ok && recvRooted(sel.X) {
							if sibling, _ := siblingLeaky(sel); sibling {
								governedCalls[call] = true
							}
						}
					}
				}
			case *ast.CallExpr:
				if ident, ok := n.Fun.(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "len" || ident.Name == "cap") {
						for _, arg := range n.Args {
							if recvRooted(arg) {
								consume(arg)
							}
						}
						break
					}
				}
				if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
					if len(n.Args) == 1 && recvRooted(n.Args[0]) && !methodValueBind(n.Args[0]) {
						if !refconfine.CallResultHandsOut(p.TypesInfo.TypeOf(n)) {
							consume(n.Args[0])
						}
					}
					break
				}
				if sel, ok := syntaxutil.UnwrapCallee(n.Fun).(*ast.SelectorExpr); ok && recvRooted(sel.X) {
					if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.MethodVal {
						if fn, ok := selection.Obj().(*types.Func); ok && refconfine.AuditedSynchronization(audited, fn) {
							consume(sel.X)
							break
						}
						if fn, ok := selection.Obj().(*types.Func); ok && fn.Pkg() == p.Types {
							target := syntaxutil.RecvTypeNameOf(p, sel) + "." + fn.Name()
							if _, sibling := methods[target]; sibling {
								if chains[key] == nil {
									chains[key] = map[string]bool{}
								}
								chains[key][target] = true
								consume(sel.X)
								if _, leaky := siblingLeaky(sel); leaky && !governedCalls[n] {
									disqualified[key] = true
								}
								break
							}
							targets, ok := unexportedDispatchTargets(p, selection, fn, declaredByName, bodyless)
							if !ok && !bodyless[fn.Name()] {
								targets, ok = closedFieldDispatchTargets(p.TypesInfo, recvObj, sel, fn.Name(), closedFields, declared)
							}
							if ok {
								if chains[key] == nil {
									chains[key] = map[string]bool{}
								}
								for _, target := range targets {
									chains[key][target] = true
								}
								consume(sel.X)
								if !refconfine.InstantiatedResultsHandOutNothing(audited, selection.Type()) && !governedCalls[n] {
									disqualified[key] = true
								}
								break
							}
						}
					}
					disqualified[key] = true
				}
			case *ast.IndexExpr:
				if recvRooted(n.X) && !allowed[syntaxutil.RootIdent(n.X)] {
					if refconfine.CallResultHandsOut(p.TypesInfo.TypeOf(n)) {
						disqualified[key] = true
					} else {
						consume(n.X)
					}
				}
			case *ast.SelectorExpr:
				if recvRooted(n.X) && !allowed[syntaxutil.RootIdent(n.X)] {
					if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
						disqualified[key] = true
						break
					}
					if refconfine.CallResultHandsOut(p.TypesInfo.TypeOf(n)) {
						disqualified[key] = true
					} else {
						consume(n.X)
					}
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL || n.Op == token.NEQ {
					if recvRooted(n.X) {
						consume(n.X)
					}
					if recvRooted(n.Y) {
						consume(n.Y)
					}
				}
			case *ast.Ident:
				if isRecv(n) && !allowed[n] {
					disqualified[key] = true
				}
			}
			return true
		})
	}
	syntaxutil.SolveReachFixedPoint(disqualified, chains, func(d string) bool { return disqualified[d] })
	readOnly := map[string]bool{}
	for key, m := range methods {
		if m.recv == nil || !disqualified[key] {
			readOnly[key] = true
		}
	}
	return readOnly
}
