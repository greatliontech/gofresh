package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// pendingReturnDisposition is one conditionally discharged range whose
// enclosing function returned the binding: the fn's callers decide, and
// an uncontained handout restores the escape - to the attributed record
// when the range sat in an attributed body, to the immediate marks
// otherwise (REQ-closure-shared-dynamic-state).
type pendingReturnDisposition struct {
	fn     string
	keys   []string
	attrFn syntaxutil.FuncKey
}

func recordDynamicGlobalUses(
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	callIdx *refconfine.CallSiteIndex,
	exemptSeamNodes map[ast.Node]bool,
	mutated, escaped, initOnly map[string]bool,
	methodUses map[string]map[syntaxutil.FuncKey]bool,
	paramUses, initParamUses map[string]map[syntaxutil.ParamKey]bool,
	initMethodUses map[string]map[syntaxutil.FuncKey]bool,
	fieldUses map[string]map[syntaxutil.FieldPosKey]bool,
	elemUses map[string]map[syntaxutil.ElemParamUse]bool,
	carrierLinks map[string]map[string]bool,
	attributed *[]syntaxutil.AttributedUse,
	singleSubject bool,
	poolDischarged map[string]bool,
	hooks *syntaxutil.ExplainHookSet,
) {
	if p == nil || p.TypesInfo == nil {
		return
	}
	if callIdx == nil {
		callIdx = refconfine.BuildCallSiteIndex(p)
	}
	dataMemos := dataMemoVars(audited, p, callIdx)
	dynamicPackageVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		if !refconfine.TypeMayCarryUnknownDynamic(audited, variable.Type()) {
			return nil, false
		}
		return variable, true
	}
	resolve := func(ident *ast.Ident) (types.Object, bool) {
		if obj, ok := p.TypesInfo.Uses[ident]; ok {
			return obj, true
		}
		if obj, ok := p.TypesInfo.Defs[ident]; ok && obj != nil {
			return obj, true
		}
		return nil, false
	}
	var aliasedLocals map[types.Object]map[string]bool
	var currentFn *ast.FuncDecl
	var currentAttrFn syntaxutil.FuncKey
	var pendingReturns []pendingReturnDisposition
	markTargets := func(expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if obj, ok := resolve(ident); ok {
				if variable, ok := dynamicPackageVar(obj); ok {
					syntaxutil.ExplainMark(hooks, p, "mutation", syntaxutil.DynamicVarKey(variable), ident.Pos())
					mutated[syntaxutil.DynamicVarKey(variable)] = true
				} else {
					for key := range aliasedLocals[obj] {
						syntaxutil.ExplainMark(hooks, p, "mutation", key, ident.Pos())
						mutated[key] = true
					}
				}
			}
			return true
		})
	}
	initOnlyParams := callIdx.FuncParamsOf(initOnly)
	paramSeeds := map[types.Object]map[string]bool{}
	paramLinkSeeds := map[types.Object]map[string]bool{}
	paramSeedGrowth := false
	seedingPass := false
	initAliasedLocals := func(body ast.Node) map[types.Object]map[string]bool {
		aliased := map[types.Object]map[string]bool{}
		for obj, keys := range paramSeeds {
			set := map[string]bool{}
			for key := range keys {
				set[key] = true
			}
			aliased[obj] = set
		}
		linkAliased := map[types.Object]map[string]bool{}
		for obj, keys := range paramLinkSeeds {
			set := map[string]bool{}
			for key := range keys {
				set[key] = true
			}
			linkAliased[obj] = set
		}
		rhsKeys := func(expr ast.Expr) map[string]bool {
			keys := map[string]bool{}
			ast.Inspect(expr, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit:
					return false
				case *ast.Ident:
					if obj, ok := resolve(n); ok {
						if variable, ok := dynamicPackageVar(obj); ok {
							keys[syntaxutil.DynamicVarKey(variable)] = true
						} else if source := aliased[obj]; source != nil {
							for key := range source {
								keys[key] = true
							}
						}
					}
				}
				return true
			})
			return keys
		}
		linkKeys := func(expr ast.Expr) map[string]bool {
			keys := map[string]bool{}
			ast.Inspect(expr, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit, *ast.CallExpr:
					return false
				case *ast.Ident:
					if obj, ok := resolve(n); ok {
						if variable, ok := dynamicPackageVar(obj); ok {
							keys[syntaxutil.DynamicVarKey(variable)] = true
						} else if source := linkAliased[obj]; source != nil {
							for key := range source {
								keys[key] = true
							}
						}
					}
				}
				return true
			})
			return keys
		}
		markRHSMethodValues := func(rhs ast.Expr) {
			if seedingPass {
				return
			}
			calledFuns := map[ast.Node]bool{}
			ast.Inspect(rhs, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					calledFuns[syntaxutil.UnparenExpr(call.Fun)] = true
				}
				return true
			})
			ast.Inspect(rhs, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || calledFuns[sel] {
					return true
				}
				if selection, selOK := p.TypesInfo.Selections[sel]; selOK && selection.Kind() == types.MethodVal {
					ast.Inspect(sel.X, func(inner ast.Node) bool {
						if ident, ok := inner.(*ast.Ident); ok {
							if obj, ok := resolve(ident); ok {
								if variable, ok := dynamicPackageVar(obj); ok {
									syntaxutil.ExplainMark(hooks, p, "escape", syntaxutil.DynamicVarKey(variable), ident.Pos())
									escaped[syntaxutil.DynamicVarKey(variable)] = true
								} else {
									for key := range aliased[obj] {
										syntaxutil.ExplainMark(hooks, p, "escape", key, ident.Pos())
										escaped[key] = true
									}
								}
							}
						}
						return true
					})
				}
				return true
			})
		}
		bind := func(target ast.Expr, keys, lkeys map[string]bool) bool {
			if len(keys) == 0 && len(lkeys) == 0 {
				return false
			}
			composite := false
		unwrap:
			for {
				switch t := target.(type) {
				case *ast.ParenExpr:
					target = t.X
				case *ast.SelectorExpr:
					if x, ok := syntaxutil.UnparenExpr(t.X).(*ast.Ident); ok {
						if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
							target = t.Sel
							break unwrap
						}
					}
					target = t.X
					composite = true
				case *ast.IndexExpr:
					target = t.X
					composite = true
				case *ast.SliceExpr:
					target = t.X
					composite = true
				case *ast.StarExpr:
					target = t.X
					composite = true
				default:
					break unwrap
				}
			}
			ident, ok := target.(*ast.Ident)
			if !ok {
				return false
			}
			obj, ok := resolve(ident)
			if !ok {
				return false
			}
			if _, isPkg := obj.(*types.PkgName); isPkg {
				return false
			}
			if variable, pkg := dynamicPackageVar(obj); pkg {
				if carrierLinks != nil && !seedingPass {
					own := syntaxutil.DynamicVarKey(variable)
					for key := range lkeys {
						if key == own {
							continue
						}
						if carrierLinks[own] == nil {
							carrierLinks[own] = map[string]bool{}
						}
						carrierLinks[own][key] = true
					}
				}
				return false
			}
			if len(keys) == 0 {
				return false
			}
			if !composite && !refconfine.TypeHandsOutDynamicAlias(audited, obj.Type()) {
				return false
			}
			changed := false
			if aliased[obj] == nil {
				aliased[obj] = map[string]bool{}
			}
			for key := range keys {
				if !aliased[obj][key] {
					aliased[obj][key] = true
					changed = true
				}
			}
			if len(lkeys) != 0 {
				if linkAliased[obj] == nil {
					linkAliased[obj] = map[string]bool{}
				}
				for key := range lkeys {
					if !linkAliased[obj][key] {
						linkAliased[obj][key] = true
						changed = true
					}
				}
			}
			return changed
		}
		for changed := true; changed; {
			changed = false
			ast.Inspect(body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit, *ast.GoStmt:
					return false
				case *ast.AssignStmt:
					if len(n.Lhs) == len(n.Rhs) {
						for i, rhs := range n.Rhs {
							markRHSMethodValues(rhs)
							if bind(n.Lhs[i], rhsKeys(rhs), linkKeys(rhs)) {
								changed = true
							}
						}
					} else if len(n.Rhs) == 1 {
						markRHSMethodValues(n.Rhs[0])
						keys := rhsKeys(n.Rhs[0])
						lkeys := linkKeys(n.Rhs[0])
						for _, lhs := range n.Lhs {
							if bind(lhs, keys, lkeys) {
								changed = true
							}
						}
					}
				case *ast.ValueSpec:
					if len(n.Names) == len(n.Values) {
						for i, name := range n.Names {
							markRHSMethodValues(n.Values[i])
							if bind(name, rhsKeys(n.Values[i]), linkKeys(n.Values[i])) {
								changed = true
							}
						}
					} else if len(n.Values) == 1 {
						markRHSMethodValues(n.Values[0])
						keys := rhsKeys(n.Values[0])
						lkeys := linkKeys(n.Values[0])
						for _, name := range n.Names {
							if bind(name, keys, lkeys) {
								changed = true
							}
						}
					}
				case *ast.RangeStmt:
					keys := rhsKeys(n.X)
					lkeys := linkKeys(n.X)
					for _, target := range []ast.Expr{n.Key, n.Value} {
						if target != nil && bind(target, keys, lkeys) {
							changed = true
						}
					}
				case *ast.CallExpr:
					if ident, ok := n.Fun.(*ast.Ident); ok && len(n.Args) == 2 {
						if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && ident.Name == "copy" {
							if bind(n.Args[0], rhsKeys(n.Args[1]), linkKeys(n.Args[1])) {
								changed = true
							}
						}
					}
					callee := syntaxutil.UnwrapCallee(n.Fun)
					if ident, ok := callee.(*ast.Ident); ok {
						if fn, ok := p.TypesInfo.Uses[ident].(*types.Func); ok {
							if params := initOnlyParams[fn]; len(params) != 0 {
								variadic := false
								if sig, ok := fn.Type().(*types.Signature); ok {
									variadic = sig.Variadic()
								}
								for i, arg := range n.Args {
									slot := min(i, len(params)-1)
									param := params[slot]
									if param == nil {
										continue
									}
									gateType := param.Type()
									if variadic && slot == len(params)-1 && n.Ellipsis == token.NoPos {
										if slice, ok := types.Unalias(gateType).(*types.Slice); ok {
											gateType = slice.Elem()
										}
									}
									if !refconfine.TypeHandsOutDynamicAlias(audited, gateType) {
										continue
									}
									for key := range rhsKeys(arg) {
										if paramSeeds[param] == nil {
											paramSeeds[param] = map[string]bool{}
										}
										if !paramSeeds[param][key] {
											paramSeeds[param][key] = true
											paramSeedGrowth = true
										}
									}
									for key := range linkKeys(arg) {
										if paramLinkSeeds[param] == nil {
											paramLinkSeeds[param] = map[string]bool{}
										}
										if !paramLinkSeeds[param][key] {
											paramLinkSeeds[param][key] = true
											paramSeedGrowth = true
										}
									}
								}
							}
						}
					}
				}
				return true
			})
		}
		return aliased
	}
	carrierArgVar := func(arg ast.Expr) (*ast.Ident, *types.Var) {
		arg = syntaxutil.UnparenExpr(arg)
		var target *ast.Ident
		switch a := arg.(type) {
		case *ast.Ident:
			target = a
		case *ast.SelectorExpr:
			if x, ok := a.X.(*ast.Ident); ok {
				if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
					target = a.Sel
				}
			}
		}
		if target == nil {
			return nil, nil
		}
		obj, ok := resolve(target)
		if !ok {
			return nil, nil
		}
		variable, ok := dynamicPackageVar(obj)
		if !ok {
			return nil, nil
		}
		if !refconfine.TypeHandsOutDynamicAlias(audited, variable.Type()) {
			return nil, nil
		}
		return target, variable
	}
	deferCarrierArgs := func(n *ast.CallExpr, sink map[string]map[syntaxutil.ParamKey]bool, kind byte, onDeferred func(*ast.Ident)) {
		fn, pkgPath := syntaxutil.PlainCalleeFunc(p, n.Fun)
		if fn == nil {
			return
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil || sig.Params().Len() == 0 {
			return
		}
		for i, arg := range n.Args {
			target, variable := carrierArgVar(arg)
			if target == nil {
				continue
			}
			idx := i
			if sig.Variadic() && idx >= sig.Params().Len()-1 {
				idx = sig.Params().Len() - 1
			}
			key := syntaxutil.DynamicVarKey(variable)
			if sink[key] == nil {
				sink[key] = map[syntaxutil.ParamKey]bool{}
			}
			paramKey := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: pkgPath, Name: fn.Name()}, Index: idx}
			sink[key][paramKey] = true
			syntaxutil.ExplainDeferralMark(hooks, p, kind, key, syntaxutil.DeferralResolvent{Param: paramKey}, target.Pos())
			if onDeferred != nil {
				onDeferred(target)
			}
		}
	}
	poolCarrierIdent := func(recv ast.Expr) (*ast.Ident, *types.Var) {
		ident, isIdent := recv.(*ast.Ident)
		element := false
		if !isIdent {
			index, isIndex := recv.(*ast.IndexExpr)
			if !isIndex {
				return nil, nil
			}
			ident, isIdent = index.X.(*ast.Ident)
			if !isIdent {
				return nil, nil
			}
			element = true
		}
		obj, ok := resolve(ident)
		if !ok {
			return nil, nil
		}
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, nil
		}
		t := types.Unalias(variable.Type())
		if element {
			switch sequence := t.(type) {
			case *types.Array:
				t = types.Unalias(sequence.Elem())
			case *types.Slice:
				t = types.Unalias(sequence.Elem())
			default:
				return nil, nil
			}
		}
		named, ok := t.(*types.Named)
		if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
			return nil, nil
		}
		if named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Pool" {
			return nil, nil
		}
		return ident, variable
	}
	dischargePool := func(variable *types.Var) {
		if poolDischarged != nil {
			poolDischarged[syntaxutil.DynamicVarKey(variable)] = true
		}
	}
	provenCalls := map[*ast.SelectorExpr]bool{}
	if !singleSubject {
		_, provenCalls = provenSharedPools(audited, p)
	}
	markExemptEscapes := func(arg ast.Expr) {
		ast.Inspect(arg, func(inner ast.Node) bool {
			if ident, ok := inner.(*ast.Ident); ok {
				if obj, ok := resolve(ident); ok {
					if variable, ok := dynamicPackageVar(obj); ok {
						if refconfine.TypeHandsOutDynamicAlias(audited, variable.Type()) {
							syntaxutil.ExplainMark(hooks, p, "escape", syntaxutil.DynamicVarKey(variable), ident.Pos())
							escaped[syntaxutil.DynamicVarKey(variable)] = true
						}
					} else {
						for key := range aliasedLocals[obj] {
							syntaxutil.ExplainMark(hooks, p, "escape", key, ident.Pos())
							escaped[key] = true
						}
					}
				}
			}
			return true
		})
	}
	scanExemptCalls := func(body ast.Node) {
		if initParamUses == nil || body == nil {
			return
		}
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				return false
			case *ast.CallExpr:
				if ident, ok := n.Fun.(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						switch ident.Name {
						case "len", "cap", "delete", "clear", "append", "copy":
							return true
						}
					}
				}
				plain := false
				if fn, _ := syntaxutil.PlainCalleeFunc(p, n.Fun); fn != nil {
					plain = true
					deferCarrierArgs(n, initParamUses, 'q', nil)
				} else if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					if selection, selOK := p.TypesInfo.Selections[sel]; selOK && selection.Kind() == types.MethodVal {
						deferred := false
						var poolVar *types.Var
						if fn, fnOK := selection.Obj().(*types.Func); fnOK && (singleSubject || provenCalls[sel]) && refconfine.AuditedPooling(audited, fn) {
							_, poolVar = poolCarrierIdent(sel.X)
						}
						if poolVar != nil {
							dischargePool(poolVar)
							if index, isIndex := sel.X.(*ast.IndexExpr); isIndex {
								markExemptEscapes(index.Index)
							}
							deferred = true
						} else if fn, fnOK := selection.Obj().(*types.Func); fnOK && !syntaxutil.InterfaceReceiver(fn) && refconfine.InstantiatedResultsHandOutNothing(audited, selection.Type()) {
							if ident, idOK := sel.X.(*ast.Ident); idOK {
								if obj, rOK := resolve(ident); rOK {
									if variable, vOK := dynamicPackageVar(obj); vOK {
										key := syntaxutil.DynamicVarKey(variable)
										if initMethodUses[key] == nil {
											initMethodUses[key] = map[syntaxutil.FuncKey]bool{}
										}
										factKey := syntaxutil.MethodFactKey(fn)
										initMethodUses[key][factKey] = true
										syntaxutil.ExplainDeferralMark(hooks, p, 'n', key, syntaxutil.DeferralResolvent{Method: factKey}, sel.Pos())
										deferred = true
									}
								}
							}
						}
						if !deferred {
							markExemptEscapes(sel.X)
						}
					}
				}
				for _, arg := range n.Args {
					if plain {
						if _, variable := carrierArgVar(arg); variable != nil {
							continue
						}
					}
					markExemptEscapes(arg)
				}
			}
			return true
		})
	}
	var skipInteriors map[ast.Node]bool
	walkBody := func(body ast.Node) {
		readContext := map[*ast.Ident]bool{}
		calledSelectors := map[*ast.SelectorExpr]bool{}
		goCalls := map[*ast.CallExpr]bool{}
		markRead := func(expr ast.Expr) {
			switch expr := expr.(type) {
			case *ast.Ident:
				readContext[expr] = true
			case *ast.SelectorExpr:
				readContext[expr.Sel] = true
			}
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if skipInteriors[n] {
				return false
			}
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if exemptSeamNodes[lhs] {
						markRead(lhs)
						if sel, ok := syntaxutil.UnparenExpr(lhs).(*ast.SelectorExpr); ok {
							markRead(sel.X)
						}
						continue
					}
					markTargets(lhs)
					if index, ok := lhs.(*ast.IndexExpr); ok {
						markRead(index.X)
					}
				}
				if len(n.Lhs) == 2 && len(n.Rhs) == 1 {
					if blank, ok := n.Lhs[0].(*ast.Ident); ok && blank.Name == "_" {
						if index, ok := syntaxutil.UnparenExpr(n.Rhs[0]).(*ast.IndexExpr); ok {
							markRead(syntaxutil.UnparenExpr(index.X))
						}
					}
				}
			case *ast.IncDecStmt:
				markTargets(n.X)
			case *ast.RangeStmt:
				if n.Key != nil {
					markTargets(n.Key)
				}
				if n.Value != nil {
					markTargets(n.Value)
				}
				if t := p.TypesInfo.TypeOf(n.X); t != nil {
					if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
						markTargets(n.X)
					} else if !refconfine.RangeBindsAlias(t) {
						markRead(n.X)
					} else if n.Key == nil && n.Value == nil {
						markRead(n.X)
					} else if n.Tok == token.DEFINE && n.Body != nil {
						roots := map[types.Object]bool{}
						sound := true
						for _, bind := range []ast.Expr{n.Key, n.Value} {
							if bind == nil {
								continue
							}
							ident, ok := bind.(*ast.Ident)
							if !ok {
								sound = false
								break
							}
							if obj := p.TypesInfo.Defs[ident]; obj != nil && refconfine.TypeHandsOutMutableReach(obj.Type()) {
								roots[obj] = true
							}
						}
						var wants map[syntaxutil.ParamKey]bool
						var methodWants map[syntaxutil.FuncKey]bool
						var fieldWants map[syntaxutil.FieldPosKey]bool
						var elemWants map[syntaxutil.ElemParamUse]bool
						var returned bool
						var retPtr *bool
						if paramUses != nil {
							wants = map[syntaxutil.ParamKey]bool{}
							if methodUses != nil {
								methodWants = map[syntaxutil.FuncKey]bool{}
							}
							if fieldUses != nil {
								fieldWants = map[syntaxutil.FieldPosKey]bool{}
							}
							if elemUses != nil {
								elemWants = map[syntaxutil.ElemParamUse]bool{}
							}
							if currentFn != nil && currentFn.Recv == nil && currentFn.Name != nil && !currentFn.Name.IsExported() && currentFn.Name.Name != "init" {
								retPtr = &returned
							}
						}
						if sound && (len(roots) == 0 || boundValueLeakFreeJudged(audited, p, roots, n.Body, wants, retPtr, methodWants, fieldWants, elemWants)) {
							if len(wants) == 0 && len(methodWants) == 0 && len(fieldWants) == 0 && len(elemWants) == 0 && !returned {
								markRead(n.X)
							} else {
								var keys []string
								ast.Inspect(n.X, func(inner ast.Node) bool {
									if ident, ok := inner.(*ast.Ident); ok {
										if obj, ok := resolve(ident); ok {
											if variable, ok := dynamicPackageVar(obj); ok {
												keys = append(keys, syntaxutil.DynamicVarKey(variable))
											} else {
												for key := range aliasedLocals[obj] {
													keys = append(keys, key)
												}
											}
										}
									}
									return true
								})
								if len(keys) > 0 {
									for _, key := range keys {
										if paramUses[key] == nil {
											paramUses[key] = map[syntaxutil.ParamKey]bool{}
										}
										for want := range wants {
											paramUses[key][want] = true
											syntaxutil.ExplainDeferralMark(hooks, p, 'p', key, syntaxutil.DeferralResolvent{Param: want}, n.X.Pos())
										}
										if len(methodWants) > 0 && methodUses[key] == nil {
											methodUses[key] = map[syntaxutil.FuncKey]bool{}
										}
										for want := range methodWants {
											methodUses[key][want] = true
											syntaxutil.ExplainDeferralMark(hooks, p, 'm', key, syntaxutil.DeferralResolvent{Method: want}, n.X.Pos())
										}
										if len(fieldWants) > 0 && fieldUses[key] == nil {
											fieldUses[key] = map[syntaxutil.FieldPosKey]bool{}
										}
										for want := range fieldWants {
											pos := syntaxutil.FieldPosKey{Owner: key, Field: want.Field, Index: want.Index}
											fieldUses[key][pos] = true
											syntaxutil.ExplainDeferralMark(hooks, p, 'f', key, syntaxutil.DeferralResolvent{FieldPos: pos}, n.X.Pos())
										}
										if len(elemWants) > 0 && elemUses[key] == nil {
											elemUses[key] = map[syntaxutil.ElemParamUse]bool{}
										}
										for want := range elemWants {
											eu := syntaxutil.ElemParamUse{Key: key, Owner: want.Owner, Index: want.Index}
											elemUses[key][eu] = true
											syntaxutil.ExplainDeferralMark(hooks, p, 'e', key, syntaxutil.DeferralResolvent{ElemUse: eu}, n.X.Pos())
										}
									}
									if returned {
										pendingReturns = append(pendingReturns, pendingReturnDisposition{
											fn:     currentFn.Name.Name,
											keys:   keys,
											attrFn: currentAttrFn,
										})
									}
									markRead(n.X)
								}
							}
						}
					}
				}
			case *ast.SendStmt:
				markTargets(n.Chan)
			case *ast.UnaryExpr:
				if n.Op == token.AND || n.Op == token.ARROW {
					if _, composite := syntaxutil.UnparenExpr(n.X).(*ast.CompositeLit); !composite || n.Op == token.ARROW {
						markTargets(n.X)
					}
				}
			case *ast.IndexExpr:
				if t := p.TypesInfo.TypeOf(n); t == nil || !refconfine.TypeHandsOutMutableReach(t) {
					markRead(n.X)
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL || n.Op == token.NEQ {
					markRead(n.X)
					markRead(n.Y)
				}
			case *ast.GoStmt:
				ast.Inspect(n, func(inner ast.Node) bool {
					if call, ok := inner.(*ast.CallExpr); ok {
						goCalls[call] = true
					}
					return true
				})
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					calledSelectors[sel] = true
				}
				if ident, ok := n.Fun.(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						switch ident.Name {
						case "len", "cap":
							for _, arg := range n.Args {
								markRead(arg)
							}
						case "delete", "clear":
							if len(n.Args) > 0 {
								markTargets(n.Args[0])
							}
						}
					}
				}
				if paramUses != nil && !goCalls[n] {
					deferCarrierArgs(n, paramUses, 'p', func(target *ast.Ident) {
						readContext[target] = true
					})
				}
				if elemUses != nil && !goCalls[n] {
					if index, ok := syntaxutil.UnparenExpr(n.Fun).(*ast.IndexExpr); ok {
						if base, ok := syntaxutil.UnparenExpr(index.X).(*ast.Ident); ok {
							if obj, ok := resolve(base); ok {
								if owner, ok := dynamicPackageVar(obj); ok {
									if sig, ok := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(n.Fun)).(*types.Signature); ok {
										ownerKey := syntaxutil.DynamicVarKey(owner)
										for i, arg := range n.Args {
											ident, ok := syntaxutil.UnparenExpr(arg).(*ast.Ident)
											if !ok {
												continue
											}
											aobj, ok := resolve(ident)
											if !ok {
												continue
											}
											variable, ok := dynamicPackageVar(aobj)
											if !ok || !refconfine.TypeHandsOutDynamicAlias(audited, variable.Type()) {
												continue
											}
											idx := i
											if sig.Variadic() && idx >= sig.Params().Len()-1 {
												idx = sig.Params().Len() - 1
											}
											argKey := syntaxutil.DynamicVarKey(variable)
											want := syntaxutil.ElemParamUse{Key: argKey, Owner: ownerKey, Index: idx}
											if elemUses[argKey] == nil {
												elemUses[argKey] = map[syntaxutil.ElemParamUse]bool{}
											}
											elemUses[argKey][want] = true
											syntaxutil.ExplainDeferralMark(hooks, p, 'e', argKey, syntaxutil.DeferralResolvent{ElemUse: want}, arg.Pos())
											readContext[ident] = true
										}
									}
								}
							}
						}
					}
				}
			case *ast.SelectorExpr:
				if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
					if fn, ok := selection.Obj().(*types.Func); ok {
						if (singleSubject || provenCalls[n]) && calledSelectors[n] && refconfine.AuditedPooling(audited, fn) {
							if ident, variable := poolCarrierIdent(n.X); variable != nil {
								dischargePool(variable)
								readContext[ident] = true
								return true
							}
						}
						if calledSelectors[n] && refconfine.DataMemoMethod(audited, fn) {
							if ident, ok := n.X.(*ast.Ident); ok {
								if obj, ok := resolve(ident); ok {
									if variable, ok := obj.(*types.Var); ok && dataMemos[variable] {
										readContext[ident] = true
										return true
									}
								}
							}
						}
						if calledSelectors[n] && exemptSeamNodes[n] {
							if ident, ok := syntaxutil.UnparenExpr(n.X).(*ast.Ident); ok {
								readContext[ident] = true
							}
							return true
						}
						if methodUses != nil && calledSelectors[n] && !syntaxutil.InterfaceReceiver(fn) && refconfine.InstantiatedResultsHandOutNothing(audited, selection.Type()) {
							if ident, ok := n.X.(*ast.Ident); ok {
								if obj, ok := resolve(ident); ok {
									if variable, ok := dynamicPackageVar(obj); ok {
										key := syntaxutil.DynamicVarKey(variable)
										if methodUses[key] == nil {
											methodUses[key] = map[syntaxutil.FuncKey]bool{}
										}
										factKey := syntaxutil.MethodFactKey(fn)
										methodUses[key][factKey] = true
										syntaxutil.ExplainDeferralMark(hooks, p, 'm', key, syntaxutil.DeferralResolvent{Method: factKey}, n.Pos())
										readContext[ident] = true
										return true
									}
								}
							}
						}
						if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
							if _, pointer := types.Unalias(sig.Recv().Type()).(*types.Pointer); pointer {
								markTargets(n.X)
							}
						}
					}
				}
			case *ast.Ident:
				if readContext[n] {
					return true
				}
				if obj, ok := resolve(n); ok {
					if variable, ok := dynamicPackageVar(obj); ok && refconfine.TypeHandsOutDynamicAlias(audited, variable.Type()) {
						syntaxutil.ExplainMark(hooks, p, "escape", syntaxutil.DynamicVarKey(variable), n.Pos())
						escaped[syntaxutil.DynamicVarKey(variable)] = true
					} else {
						for key := range aliasedLocals[obj] {
							syntaxutil.ExplainMark(hooks, p, "escape", key, n.Pos())
							escaped[key] = true
						}
					}
				}
			}
			return true
		})
	}
	if len(initOnlyParams) != 0 {
		seedingPass = true
		for {
			paramSeedGrowth = false
			for _, file := range p.Syntax {
				for _, decl := range file.Decls {
					switch decl := decl.(type) {
					case *ast.FuncDecl:
						if decl.Recv == nil && decl.Name != nil && decl.Body != nil && (decl.Name.Name == "init" || initOnly[decl.Name.Name]) {
							initAliasedLocals(decl.Body)
						}
					case *ast.GenDecl:
						initAliasedLocals(decl)
					}
				}
			}
			if !paramSeedGrowth {
				break
			}
		}
		seedingPass = false
	}
	walkAttributedDecl := func(decl *ast.FuncDecl, fnKey syntaxutil.FuncKey, setCurrentFn bool) {
		litMutated, litEscaped := map[string]bool{}, map[string]bool{}
		litMethods := map[string]map[syntaxutil.FuncKey]bool{}
		interiors := map[ast.Node]bool{}
		saveLM, saveLE, saveLMU := mutated, escaped, methodUses
		mutated, escaped, methodUses = litMutated, litEscaped, litMethods
		ast.Inspect(decl.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				if n.Body != nil {
					walkBody(n.Body)
					interiors[n] = true
				}
				return false
			case *ast.GoStmt:
				walkBody(n)
				interiors[n] = true
				return false
			}
			return true
		})
		mutated, escaped, methodUses = saveLM, saveLE, saveLMU
		if fnKey.Valid() {
			for key := range litMutated {
				*attributed = append(*attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Literal: true})
			}
			for key := range litEscaped {
				*attributed = append(*attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Escape: true, Literal: true})
			}
			for key, methods := range litMethods {
				for method := range methods {
					*attributed = append(*attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: method, Literal: true})
				}
			}
		} else {
			for key := range litMutated {
				mutated[key] = true
			}
			for key := range litEscaped {
				escaped[key] = true
			}
			for key, methods := range litMethods {
				for method := range methods {
					if methodUses[key] == nil {
						methodUses[key] = map[syntaxutil.FuncKey]bool{}
					}
					methodUses[key][method] = true
				}
			}
		}
		localMutated, localEscaped := map[string]bool{}, map[string]bool{}
		localMethods := map[string]map[syntaxutil.FuncKey]bool{}
		saveM, saveE, saveMU := mutated, escaped, methodUses
		mutated, escaped, methodUses = localMutated, localEscaped, localMethods
		skipInteriors = interiors
		if setCurrentFn {
			currentFn, currentAttrFn = decl, fnKey
		}
		walkBody(decl.Body)
		if setCurrentFn {
			currentFn, currentAttrFn = nil, syntaxutil.FuncKey{}
		}
		skipInteriors = nil
		mutated, escaped, methodUses = saveM, saveE, saveMU
		for key := range localMutated {
			*attributed = append(*attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key})
		}
		for key := range localEscaped {
			*attributed = append(*attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Escape: true})
		}
		for key, methods := range localMethods {
			for method := range methods {
				*attributed = append(*attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: method})
			}
		}
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				var methodKey syntaxutil.FuncKey
				if decl.Recv != nil && decl.Name != nil && attributed != nil && decl.Body != nil && p.Types != nil {
					if fn, ok := p.TypesInfo.Defs[decl.Name].(*types.Func); ok && fn != nil {
						if key := syntaxutil.MethodFactKey(fn); key.Pkg != "" && !strings.HasPrefix(key.Name, ".") {
							methodKey = key
						}
					}
				}
				if methodKey.Valid() {
					walkAttributedDecl(decl, methodKey, false)
					continue
				}
				if decl.Recv == nil && decl.Name != nil && attributed != nil && !initOnly[decl.Name.Name] && decl.Name.Name != "init" && decl.Body != nil {
					var fnKey syntaxutil.FuncKey
					if p.Types != nil {
						fnKey = syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: decl.Name.Name}
					}
					walkAttributedDecl(decl, fnKey, true)
					continue
				}
				if decl.Recv == nil && decl.Name != nil && (decl.Name.Name == "init" || initOnly[decl.Name.Name]) {
					if decl.Body != nil {
						aliasedLocals = initAliasedLocals(decl.Body)
						ast.Inspect(decl.Body, func(n ast.Node) bool {
							switch n := n.(type) {
							case *ast.FuncLit:
								if n.Body != nil {
									walkBody(n.Body)
								}
								return false
							case *ast.GoStmt:
								walkBody(n)
								return false
							}
							return true
						})
						scanExemptCalls(decl.Body)
						aliasedLocals = nil
					}
					continue
				}
				if decl.Body != nil {
					currentFn = decl
					walkBody(decl.Body)
					currentFn = nil
				}
			default:
				aliasedLocals = initAliasedLocals(decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					if lit, ok := n.(*ast.FuncLit); ok && lit.Body != nil {
						walkBody(lit.Body)
						return false
					}
					return true
				})
				scanExemptCalls(decl)
				aliasedLocals = nil
			}
		}
	}
	if len(pendingReturns) > 0 {
		returnerKeys := map[string]map[string]bool{}
		mergeKeys := func(fn string, keys map[string]bool) bool {
			if returnerKeys[fn] == nil {
				returnerKeys[fn] = map[string]bool{}
			}
			changed := false
			for key := range keys {
				if !returnerKeys[fn][key] {
					returnerKeys[fn][key] = true
					changed = true
				}
			}
			return changed
		}
		for _, pending := range pendingReturns {
			set := map[string]bool{}
			for _, key := range pending.keys {
				set[key] = true
			}
			mergeKeys(pending.fn, set)
		}
		plainFuncObjs := map[string]types.Object{}
		for _, file := range p.Syntax {
			for _, decl := range file.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name != nil {
					if obj := p.TypesInfo.Defs[fd.Name]; obj != nil {
						plainFuncObjs[fd.Name.Name] = obj
					}
				}
			}
		}
		bad := map[string]bool{}
		deps := map[string]map[string]bool{}
		scanned := map[string]bool{}
		for {
			var frontier []string
			for fn := range returnerKeys {
				if !scanned[fn] {
					frontier = append(frontier, fn)
					scanned[fn] = true
				}
			}
			if len(frontier) == 0 {
				break
			}
			returnerObjs := map[types.Object]string{}
			for fn := range returnerKeys {
				if obj := plainFuncObjs[fn]; obj != nil {
					returnerObjs[obj] = fn
				}
			}
			frontierSet := map[string]bool{}
			for _, fn := range frontier {
				frontierSet[fn] = true
			}
			depend := func(from, to string) {
				if deps[from] == nil {
					deps[from] = map[string]bool{}
				}
				deps[from][to] = true
			}
			scanSites := func(body ast.Node, siteName string, siteEligible bool) {
				var stack []ast.Node
				ast.Inspect(body, func(n ast.Node) bool {
					if n == nil {
						stack = stack[:len(stack)-1]
						return true
					}
					defer func() { stack = append(stack, n) }()
					ident, ok := n.(*ast.Ident)
					if !ok {
						return true
					}
					obj := p.TypesInfo.Uses[ident]
					if obj == nil {
						return true
					}
					fnName, tracked := returnerObjs[obj]
					if !tracked || !frontierSet[fnName] {
						return true
					}
					if len(stack) == 0 {
						bad[fnName] = true
						return true
					}
					call, ok := stack[len(stack)-1].(*ast.CallExpr)
					if !ok || call.Fun != ast.Expr(ident) {
						bad[fnName] = true
						return true
					}
					var grand ast.Node
					if len(stack) >= 2 {
						grand = stack[len(stack)-2]
					}
					fnObj, isFunc := obj.(*types.Func)
					if !isFunc {
						bad[fnName] = true
						return true
					}
					sig, ok := fnObj.Type().(*types.Signature)
					if !ok {
						bad[fnName] = true
						return true
					}
					var targets []ast.Expr
					switch g := grand.(type) {
					case *ast.ExprStmt, *ast.GoStmt, *ast.DeferStmt:
						return true
					case *ast.ReturnStmt:
						inLit := false
						for _, frame := range stack {
							if _, isLit := frame.(*ast.FuncLit); isLit {
								inLit = true
								break
							}
						}
						if siteEligible && !inLit {
							if mergeKeys(siteName, returnerKeys[fnName]) {
								scanned[siteName] = false
							}
							depend(fnName, siteName)
						} else {
							bad[fnName] = true
						}
						return true
					case *ast.AssignStmt:
						if len(g.Rhs) != 1 || g.Rhs[0] != ast.Expr(call) {
							bad[fnName] = true
							return true
						}
						targets = g.Lhs
					case *ast.ValueSpec:
						if len(g.Values) != 1 || g.Values[0] != ast.Expr(call) {
							bad[fnName] = true
							return true
						}
						for _, name := range g.Names {
							targets = append(targets, name)
						}
					default:
						bad[fnName] = true
						return true
					}
					results := sig.Results()
					if results.Len() != len(targets) {
						bad[fnName] = true
						return true
					}
					roots := map[types.Object]bool{}
					for i, target := range targets {
						tIdent, ok := target.(*ast.Ident)
						if !ok {
							bad[fnName] = true
							return true
						}
						if !refconfine.TypeHandsOutMutableReach(results.At(i).Type()) {
							continue
						}
						if tObj := p.TypesInfo.Defs[tIdent]; tObj != nil {
							roots[tObj] = true
						} else if tObj := p.TypesInfo.Uses[tIdent]; tObj != nil {
							roots[tObj] = true
						}
					}
					if len(roots) == 0 {
						return true
					}
					siteWants := map[syntaxutil.ParamKey]bool{}
					var siteMethodWants map[syntaxutil.FuncKey]bool
					var siteFieldWants map[syntaxutil.FieldPosKey]bool
					var siteElemWants map[syntaxutil.ElemParamUse]bool
					if methodUses != nil {
						siteMethodWants = map[syntaxutil.FuncKey]bool{}
					}
					if fieldUses != nil {
						siteFieldWants = map[syntaxutil.FieldPosKey]bool{}
					}
					if elemUses != nil {
						siteElemWants = map[syntaxutil.ElemParamUse]bool{}
					}
					var siteReturned bool
					var siteRet *bool
					if siteEligible {
						siteRet = &siteReturned
					}
					if !boundValueLeakFreeJudged(audited, p, roots, body, siteWants, siteRet, siteMethodWants, siteFieldWants, siteElemWants) {
						bad[fnName] = true
						return true
					}
					for want := range siteWants {
						for key := range returnerKeys[fnName] {
							if paramUses[key] == nil {
								paramUses[key] = map[syntaxutil.ParamKey]bool{}
							}
							paramUses[key][want] = true
							syntaxutil.ExplainDeferralMark(hooks, p, 'p', key, syntaxutil.DeferralResolvent{Param: want}, call.Pos())
						}
					}
					for want := range siteMethodWants {
						for key := range returnerKeys[fnName] {
							if methodUses[key] == nil {
								methodUses[key] = map[syntaxutil.FuncKey]bool{}
							}
							methodUses[key][want] = true
							syntaxutil.ExplainDeferralMark(hooks, p, 'm', key, syntaxutil.DeferralResolvent{Method: want}, call.Pos())
						}
					}
					for want := range siteFieldWants {
						for key := range returnerKeys[fnName] {
							if fieldUses[key] == nil {
								fieldUses[key] = map[syntaxutil.FieldPosKey]bool{}
							}
							pos := syntaxutil.FieldPosKey{Owner: key, Field: want.Field, Index: want.Index}
							fieldUses[key][pos] = true
							syntaxutil.ExplainDeferralMark(hooks, p, 'f', key, syntaxutil.DeferralResolvent{FieldPos: pos}, call.Pos())
						}
					}
					for want := range siteElemWants {
						for key := range returnerKeys[fnName] {
							if elemUses[key] == nil {
								elemUses[key] = map[syntaxutil.ElemParamUse]bool{}
							}
							eu := syntaxutil.ElemParamUse{Key: key, Owner: want.Owner, Index: want.Index}
							elemUses[key][eu] = true
							syntaxutil.ExplainDeferralMark(hooks, p, 'e', key, syntaxutil.DeferralResolvent{ElemUse: eu}, call.Pos())
						}
					}
					if siteReturned {
						if mergeKeys(siteName, returnerKeys[fnName]) {
							scanned[siteName] = false
						}
						depend(fnName, siteName)
					}
					return true
				})
			}
			var frontierFuncDecls map[*ast.FuncDecl]bool
			hasTopLevelValueUse := idx == nil
			if idx != nil {
				frontierFuncDecls = map[*ast.FuncDecl]bool{}
				for _, fn := range frontier {
					if obj := plainFuncObjs[fn]; obj != nil {
						for _, id := range idx.UsesOf[obj] {
							if fd := idx.EnclFunc[id]; fd != nil {
								frontierFuncDecls[fd] = true
							} else {
								hasTopLevelValueUse = true
							}
						}
					}
				}
			}
			for _, file := range p.Syntax {
				for _, decl := range file.Decls {
					switch decl := decl.(type) {
					case *ast.FuncDecl:
						if decl.Body == nil || (idx != nil && !frontierFuncDecls[decl]) {
							continue
						}
						name := ""
						if decl.Name != nil {
							name = decl.Name.Name
						}
						eligible := decl.Recv == nil && decl.Name != nil && !decl.Name.IsExported() && name != "init"
						scanSites(decl.Body, name, eligible)
					case *ast.GenDecl:
						if !hasTopLevelValueUse {
							continue
						}
						for _, spec := range decl.Specs {
							vs, ok := spec.(*ast.ValueSpec)
							if !ok {
								continue
							}
							for _, value := range vs.Values {
								ast.Inspect(value, func(n ast.Node) bool {
									if lit, ok := n.(*ast.FuncLit); ok {
										if lit.Body != nil {
											scanSites(lit.Body, "", false)
										}
										return false
									}
									if ident, ok := n.(*ast.Ident); ok {
										if obj := p.TypesInfo.Uses[ident]; obj != nil {
											if fnName, tracked := returnerObjs[obj]; tracked && frontierSet[fnName] {
												contained := false
												if call, isCall := value.(*ast.CallExpr); isCall && call.Fun == ast.Expr(ident) {
													if fnObj, isFunc := obj.(*types.Func); isFunc {
														if sig, isSig := fnObj.Type().(*types.Signature); isSig && sig.Results().Len() == len(vs.Names) {
															contained = true
															for i, nameIdent := range vs.Names {
																if nameIdent.Name != "_" && refconfine.TypeHandsOutMutableReach(sig.Results().At(i).Type()) {
																	contained = false
																	break
																}
															}
														}
													}
												}
												if !contained {
													bad[fnName] = true
												}
											}
										}
									}
									return true
								})
							}
						}
					}
				}
			}
		}
		syntaxutil.SolveReachFixedPoint(bad, deps, func(d string) bool { return bad[d] })
		type restoredKey struct {
			fn  syntaxutil.FuncKey
			key string
		}
		restored := map[restoredKey]bool{}
		for _, pending := range pendingReturns {
			if !bad[pending.fn] {
				continue
			}
			for _, key := range pending.keys {
				if pending.attrFn.Valid() {
					rk := restoredKey{fn: pending.attrFn, key: key}
					if !restored[rk] {
						restored[rk] = true
						*attributed = append(*attributed, syntaxutil.AttributedUse{Func: pending.attrFn, Key: key, Escape: true})
					}
				} else {
					syntaxutil.ExplainMark(hooks, p, "escape", key, token.NoPos)
					escaped[key] = true
				}
			}
		}
	}
}

func walkSyncVarCalls(p *packages.Package, candidates map[*types.Var]bool, evictNonCallUses bool, judgeCall func(v *types.Var, sel *ast.SelectorExpr, call *ast.CallExpr) (admittedMethod, siteConforms bool)) map[*ast.SelectorExpr]bool {
	if len(candidates) == 0 {
		return nil
	}
	info := p.TypesInfo
	receiver := map[*ast.Ident]bool{}
	conformingBySelector := map[*ast.SelectorExpr]*types.Var{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
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
	walkSyncVarCalls(p, candidates, false, func(_ *types.Var, sel *ast.SelectorExpr, call *ast.CallExpr) (bool, bool) {
		if !auditset.MemoMethod("Map", sel.Sel.Name) {
			return false, false
		}
		for _, arg := range call.Args {
			if !carrierFree(arg) {
				return true, false
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
				case decl.Name != nil:
					if decl.Body != nil && p.Types != nil {
						scan(syntaxutil.RefRegion{Kind: syntaxutil.RegionFunc, Caller: syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: decl.Name.Name}}, decl.Body)
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
		if auditedImmutable(expr, storeDeps) {
			return true
		}
		if storeDeps != nil {
			var target *ast.Ident
			switch e := syntaxutil.UnparenExpr(expr).(type) {
			case *ast.Ident:
				target = e
			case *ast.SelectorExpr:
				if x, ok := e.X.(*ast.Ident); ok {
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
			sel, ok := expr.Fun.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
			if !ok || fn.Pkg() == nil {
				return false
			}
			if fn.Pkg().Path() == "errors" && fn.Name() == "New" {
				return true
			}
			if fn.Pkg().Path() == "fmt" && fn.Name() == "Errorf" {
				if sig, ok := fn.Type().(*types.Signature); !ok || sig.Recv() != nil {
					return false
				}
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
	audit := func(target ast.Expr, value ast.Expr) {
		ident, ok := target.(*ast.Ident)
		if !ok {
			return
		}
		obj, ok := p.TypesInfo.Defs[ident]
		if !ok || obj == nil {
			if obj, ok = p.TypesInfo.Uses[ident]; !ok {
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
			if obj, ok := p.TypesInfo.Uses[ident]; ok {
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
				if obj, ok := p.TypesInfo.Uses[t]; ok {
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
	failCaptures := func(expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					if _, composite := syntaxutil.UnparenExpr(n.X).(*ast.CompositeLit); !composite {
						failTargets(n.X)
					}
				}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, ident := range vs.Names {
						var value ast.Expr
						if i < len(vs.Values) {
							value = vs.Values[i]
						}
						if len(vs.Values) == 0 {
							continue
						}
						audit(ident, value)
						if value != nil {
							failCaptures(value)
						}
					}
				}
			case *ast.FuncDecl:
				if decl.Recv != nil || decl.Name == nil || decl.Body == nil {
					continue
				}
				ast.Inspect(decl.Body, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.FuncLit:
						return false
					case *ast.AssignStmt:
						for i, lhs := range n.Lhs {
							var value ast.Expr
							if i < len(n.Rhs) {
								value = n.Rhs[i]
							}
							switch target := lhs.(type) {
							case *ast.Ident:
								audit(target, value)
							case *ast.SelectorExpr:
								if base, ok := target.X.(*ast.Ident); ok {
									if _, isPkg := p.TypesInfo.Uses[base].(*types.PkgName); isPkg {
										audit(target.Sel, value)
										continue
									}
								}
								failTargets(lhs)
							default:
								failTargets(lhs)
							}
						}
					case *ast.UnaryExpr:
						if n.Op == token.AND {
							if _, composite := syntaxutil.UnparenExpr(n.X).(*ast.CompositeLit); !composite {
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
		}
	}
	for key := range failed {
		delete(opaque, key)
		breaks[key] = true
	}
}
