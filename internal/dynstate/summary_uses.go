package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// pendingReturnDisposition is one conditionally discharged range whose
// enclosing function returned the binding: the fn's callers decide, and
// an uncontained handout restores the escape — to the attributed record
// when the range sat in an attributed body, to the immediate marks
// otherwise (REQ-closure-shared-dynamic-state).
type pendingReturnDisposition struct {
	fn     string
	keys   []string
	attrFn syntaxutil.FuncKey
	pos    token.Pos
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
	attributedParams *[]syntaxutil.VarParamUse,
	singleSubject bool,
	poolDischarged, poolMutated, poolEscaped map[string]bool,
	poolAttributed *[]syntaxutil.AttributedUse,
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
	isPackageScopeVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
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
	canAliasCarrier := func(t types.Type) bool {
		return refconfine.TypeHandsOutDynamicAlias(audited, t) ||
			refconfine.TypeHandsOutMutableReach(t) ||
			refconfine.TypeReachesSyncNoCopyByValue(t)
	}

	var aliasedLocals map[types.Object]map[string]bool
	var poolMethods map[string]map[syntaxutil.FuncKey]bool
	var currentFn *ast.FuncDecl
	var currentAttrFn syntaxutil.FuncKey
	var currentDeferFn syntaxutil.FuncKey
	var currentDeferLit bool
	var pendingReturns []pendingReturnDisposition
	markTargets := func(expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if obj, ok := resolve(ident); ok {
				if variable, ok := dynamicPackageVar(obj); ok {
					syntaxutil.ExplainAttributedMark(hooks, p, "mutation", syntaxutil.DynamicVarKey(variable), currentDeferFn, currentDeferLit, ident.Pos())
					mutated[syntaxutil.DynamicVarKey(variable)] = true
				} else {
					for key := range aliasedLocals[obj] {
						syntaxutil.ExplainAttributedMark(hooks, p, "mutation", key, currentDeferFn, currentDeferLit, ident.Pos())
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

		var collectRHSKeys func(expr ast.Expr, addressed bool, out map[string]bool)
		collectRHSKeys = func(expr ast.Expr, addressed bool, out map[string]bool) {
			if expr == nil {
				return
			}
			e := syntaxutil.UnparenExpr(expr)
			if !addressed {
				if t := p.TypesInfo.TypeOf(e); t != nil && !canAliasCarrier(t) {
					return
				}
			}
			switch n := e.(type) {
			case *ast.FuncLit:
				return
			case *ast.Ident:
				if obj, ok := resolve(n); ok {
					if variable, ok := dynamicPackageVar(obj); ok {
						out[syntaxutil.DynamicVarKey(variable)] = true
					} else if source := aliased[obj]; source != nil {
						for key := range source {
							out[key] = true
						}
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					collectRHSKeys(n.X, true, out)
					return
				}
				collectRHSKeys(n.X, addressed, out)
			case *ast.SelectorExpr:
				if x, ok := syntaxutil.UnparenExpr(n.X).(*ast.Ident); ok {
					if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
						collectRHSKeys(n.Sel, addressed, out)
						return
					}
				}
				collectRHSKeys(n.X, addressed, out)
			case *ast.IndexExpr:
				collectRHSKeys(n.X, addressed, out)
				collectRHSKeys(n.Index, false, out)
			case *ast.IndexListExpr:
				collectRHSKeys(n.X, addressed, out)
			case *ast.SliceExpr:
				isArr := false
				if t := p.TypesInfo.TypeOf(n.X); t != nil {
					_, isArr = types.Unalias(t).Underlying().(*types.Array)
				}
				collectRHSKeys(n.X, addressed || isArr, out)
				collectRHSKeys(n.Low, false, out)
				collectRHSKeys(n.High, false, out)
				collectRHSKeys(n.Max, false, out)
			case *ast.StarExpr:
				collectRHSKeys(n.X, addressed, out)
			case *ast.TypeAssertExpr:
				collectRHSKeys(n.X, addressed, out)
			case *ast.CompositeLit:
				syntaxutil.EachCompositeLitFlow(p.TypesInfo, n, func(flow ast.Expr, _ bool) bool {
					collectRHSKeys(flow, false, out)
					return true
				})
			case *ast.CallExpr:
				if ident, ok := syntaxutil.UnparenExpr(n.Fun).(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						if ident.Name == "make" || syntaxutil.IsBuiltinNewType(p.TypesInfo, n) ||
							ident.Name == "len" || ident.Name == "cap" {
							return
						}
					}
				}
				collectRHSKeys(n.Fun, false, out)
				for _, arg := range n.Args {
					collectRHSKeys(arg, false, out)
				}
			case *ast.BinaryExpr:
				collectRHSKeys(n.X, false, out)
				collectRHSKeys(n.Y, false, out)
			default:
				ast.Inspect(e, func(sub ast.Node) bool {
					if _, isLit := sub.(*ast.FuncLit); isLit {
						return false
					}
					if id, ok := sub.(*ast.Ident); ok {
						if obj, ok := resolve(id); ok {
							if variable, ok := dynamicPackageVar(obj); ok {
								out[syntaxutil.DynamicVarKey(variable)] = true
							} else if source := aliased[obj]; source != nil {
								for key := range source {
									out[key] = true
								}
							}
						}
					}
					return true
				})
			}
		}
		rhsKeys := func(expr ast.Expr) map[string]bool {
			keys := map[string]bool{}
			collectRHSKeys(expr, false, keys)
			return keys
		}

		// collectLinkKeys collects init-flow carrier storage links without crossing
		// general function calls (preserving TestCarrierStoreLinkRecordedAndCallResultsUnlinked),
		// while traversing type conversions, append, Go 1.26+ new(expr), &place,
		// array [:], and composite literals.
		var collectLinkKeys func(expr ast.Expr, addressed bool, out map[string]bool)
		collectLinkKeys = func(expr ast.Expr, addressed bool, out map[string]bool) {
			if expr == nil {
				return
			}
			e := syntaxutil.UnparenExpr(expr)
			if !addressed {
				if t := p.TypesInfo.TypeOf(e); t != nil && !refconfine.CallResultHandsOut(t) {
					return
				}
			}
			switch n := e.(type) {
			case *ast.FuncLit:
				return
			case *ast.Ident:
				if obj, ok := resolve(n); ok {
					if variable, ok := dynamicPackageVar(obj); ok {
						out[syntaxutil.DynamicVarKey(variable)] = true
					} else if source := linkAliased[obj]; source != nil {
						for key := range source {
							out[key] = true
						}
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					collectLinkKeys(n.X, true, out)
					return
				}
				collectLinkKeys(n.X, addressed, out)
			case *ast.SelectorExpr:
				if x, ok := syntaxutil.UnparenExpr(n.X).(*ast.Ident); ok {
					if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
						collectLinkKeys(n.Sel, addressed, out)
						return
					}
				}
				collectLinkKeys(n.X, addressed, out)
			case *ast.IndexExpr:
				collectLinkKeys(n.X, addressed, out)
			case *ast.IndexListExpr:
				collectLinkKeys(n.X, addressed, out)
			case *ast.SliceExpr:
				isArr := false
				if t := p.TypesInfo.TypeOf(n.X); t != nil {
					_, isArr = types.Unalias(t).Underlying().(*types.Array)
				}
				collectLinkKeys(n.X, addressed || isArr, out)
			case *ast.StarExpr:
				collectLinkKeys(n.X, addressed, out)
			case *ast.TypeAssertExpr:
				collectLinkKeys(n.X, addressed, out)
			case *ast.CompositeLit:
				syntaxutil.EachCompositeLitFlow(p.TypesInfo, n, func(flow ast.Expr, _ bool) bool {
					collectLinkKeys(flow, false, out)
					return true
				})
			case *ast.CallExpr:
				if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() && len(n.Args) == 1 {
					if refconfine.CallResultHandsOut(tv.Type) {
						collectLinkKeys(n.Args[0], false, out)
					}
					return
				}
				if ident, ok := syntaxutil.UnparenExpr(n.Fun).(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						switch ident.Name {
						case "append":
							for _, arg := range n.Args {
								collectLinkKeys(arg, false, out)
							}
						case "new":
							if !syntaxutil.IsBuiltinNewType(p.TypesInfo, n) && len(n.Args) == 1 {
								collectLinkKeys(n.Args[0], false, out)
							}
						}
					}
				}
				// Plain/method/indirect CallExpr results intentionally do not emit CarrierLinks.
				return
			}
		}
		linkKeys := func(expr ast.Expr) map[string]bool {
			keys := map[string]bool{}
			collectLinkKeys(expr, false, keys)
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

		bindObj := func(obj types.Object, pos token.Pos, composite bool, keys, lkeys map[string]bool) bool {
			if obj == nil || (len(keys) == 0 && len(lkeys) == 0) {
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
			if pkgVar, isPkgScope := isPackageScopeVar(obj); isPkgScope {
				if !seedingPass && (composite || refconfine.TypeHandsOutMutableReach(pkgVar.Type())) {
					for key := range lkeys {
						syntaxutil.ExplainMark(hooks, p, "escape", key, pos)
						escaped[key] = true
					}
					for key := range keys {
						syntaxutil.ExplainMark(hooks, p, "escape", key, pos)
						escaped[key] = true
					}
				}
				return false
			}
			if composite && carrierLinks != nil && !seedingPass && len(lkeys) != 0 {
				for own := range aliased[obj] {
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
			}
			changed := false
			if len(keys) != 0 && (composite || canAliasCarrier(obj.Type())) {
				if aliased[obj] == nil {
					aliased[obj] = map[string]bool{}
				}
				for key := range keys {
					if !aliased[obj][key] {
						aliased[obj][key] = true
						changed = true
					}
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

		bind := func(target ast.Expr, keys, lkeys map[string]bool) bool {
			if len(keys) == 0 && len(lkeys) == 0 {
				return false
			}
			origTarget := target
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
			if _, mapKey, isMapW := syntaxutil.LHSMapWriteKey(p.TypesInfo, origTarget); isMapW {
				mergedK := map[string]bool{}
				for k := range keys {
					mergedK[k] = true
				}
				for k := range rhsKeys(mapKey) {
					mergedK[k] = true
				}
				mergedL := map[string]bool{}
				for k := range lkeys {
					mergedL[k] = true
				}
				for k := range linkKeys(mapKey) {
					mergedL[k] = true
				}
				keys, lkeys = mergedK, mergedL
			}
			return bindObj(obj, ident.Pos(), composite, keys, lkeys)
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
				case *ast.TypeSwitchStmt:
					syntaxutil.EachTypeSwitchImplicit(p.TypesInfo, n, func(impVar *types.Var, srcExpr ast.Expr) {
						markRHSMethodValues(srcExpr)
						if bindObj(impVar, n.Pos(), false, rhsKeys(srcExpr), linkKeys(srcExpr)) {
							changed = true
						}
					})
				case *ast.CallExpr:
					if ident, ok := syntaxutil.UnparenExpr(n.Fun).(*ast.Ident); ok && len(n.Args) == 2 {
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
									if !canAliasCarrier(gateType) {
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
			res := syntaxutil.DeferralResolvent{Param: paramKey}
			if kind == 'p' {
				res.EnclosingFn = currentDeferFn
				res.Literal = currentDeferLit
			}
			syntaxutil.ExplainDeferralMark(hooks, p, kind, key, res, target.Pos())
			if onDeferred != nil {
				onDeferred(target)
			}
		}
	}

	identOrPkgQual := func(expr ast.Expr) *ast.Ident {
		switch e := syntaxutil.UnparenExpr(expr).(type) {
		case *ast.Ident:
			return e
		case *ast.SelectorExpr:
			if x, ok := syntaxutil.UnparenExpr(e.X).(*ast.Ident); ok {
				if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
					return e.Sel
				}
			}
		}
		return nil
	}

	poolCarrierIdent := func(recv ast.Expr) (*ast.Ident, *types.Var) {
		recv = syntaxutil.UnparenExpr(recv)
		ident := identOrPkgQual(recv)
		element := false
		if ident == nil {
			index, isIndex := recv.(*ast.IndexExpr)
			if !isIndex {
				return nil, nil
			}
			ident = identOrPkgQual(index.X)
			if ident == nil {
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
	_, provenCalls := provenSharedPools(audited, p)

	var markExemptEscapesExpr func(expr ast.Expr, addressed bool)
	markExemptEscapesExpr = func(expr ast.Expr, addressed bool) {
		if expr == nil {
			return
		}
		e := syntaxutil.UnparenExpr(expr)
		if !addressed {
			if t := p.TypesInfo.TypeOf(e); t != nil && !canAliasCarrier(t) {
				return
			}
		}
		switch n := e.(type) {
		case *ast.FuncLit:
			return
		case *ast.Ident:
			if obj, ok := resolve(n); ok {
				if variable, ok := dynamicPackageVar(obj); ok {
					if addressed || refconfine.TypeHandsOutDynamicAlias(audited, variable.Type()) {
						syntaxutil.ExplainMark(hooks, p, "escape", syntaxutil.DynamicVarKey(variable), n.Pos())
						escaped[syntaxutil.DynamicVarKey(variable)] = true
					}
				} else {
					for key := range aliasedLocals[obj] {
						syntaxutil.ExplainMark(hooks, p, "escape", key, n.Pos())
						escaped[key] = true
					}
				}
			}
		case *ast.UnaryExpr:
			if n.Op == token.AND {
				markExemptEscapesExpr(n.X, true)
				return
			}
			markExemptEscapesExpr(n.X, addressed)
		case *ast.SelectorExpr:
			if x, ok := syntaxutil.UnparenExpr(n.X).(*ast.Ident); ok {
				if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
					markExemptEscapesExpr(n.Sel, addressed)
					return
				}
			}
			markExemptEscapesExpr(n.X, addressed)
		case *ast.IndexExpr:
			markExemptEscapesExpr(n.X, addressed)
			markExemptEscapesExpr(n.Index, false)
		case *ast.IndexListExpr:
			markExemptEscapesExpr(n.X, addressed)
		case *ast.SliceExpr:
			isArr := false
			if t := p.TypesInfo.TypeOf(n.X); t != nil {
				_, isArr = types.Unalias(t).Underlying().(*types.Array)
			}
			markExemptEscapesExpr(n.X, addressed || isArr)
			markExemptEscapesExpr(n.Low, false)
			markExemptEscapesExpr(n.High, false)
			markExemptEscapesExpr(n.Max, false)
		case *ast.StarExpr:
			markExemptEscapesExpr(n.X, addressed)
		case *ast.TypeAssertExpr:
			markExemptEscapesExpr(n.X, addressed)
		case *ast.CompositeLit:
			syntaxutil.EachCompositeLitFlow(p.TypesInfo, n, func(flow ast.Expr, _ bool) bool {
				markExemptEscapesExpr(flow, false)
				return true
			})
		case *ast.CallExpr:
			if ident, ok := syntaxutil.UnparenExpr(n.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
					if ident.Name == "len" || ident.Name == "cap" {
						return
					}
				}
			}
			for _, arg := range n.Args {
				markExemptEscapesExpr(arg, false)
			}
		case *ast.BinaryExpr:
			markExemptEscapesExpr(n.X, false)
			markExemptEscapesExpr(n.Y, false)
		default:
			ast.Inspect(e, func(inner ast.Node) bool {
				if _, isLit := inner.(*ast.FuncLit); isLit {
					return false
				}
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
	}
	markExemptEscapes := func(arg ast.Expr) {
		markExemptEscapesExpr(arg, false)
	}

	scanExemptCalls := func(body ast.Node, fnType *ast.FuncType) {
		if initParamUses == nil || body == nil {
			return
		}
		var resultIdents []*ast.Ident
		if fnType != nil && fnType.Results != nil {
			for _, field := range fnType.Results.List {
				resultIdents = append(resultIdents, field.Names...)
			}
		}
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				return false
			case *ast.ReturnStmt:
				if len(n.Results) == 0 && len(resultIdents) > 0 {
					for _, id := range resultIdents {
						markExemptEscapes(id)
					}
				} else {
					for _, res := range n.Results {
						markExemptEscapes(res)
					}
				}
			case *ast.CallExpr:
				funExpr := syntaxutil.UnparenExpr(n.Fun)
				if ident, ok := funExpr.(*ast.Ident); ok {
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
				} else if sel, ok := funExpr.(*ast.SelectorExpr); ok {
					if selection, selOK := p.TypesInfo.Selections[sel]; selOK && selection.Kind() == types.MethodVal {
						deferred := false
						var poolIdent *ast.Ident
						var poolVar *types.Var
						fn, fnOK := selection.Obj().(*types.Func)
						if fnOK && refconfine.AuditedPooling(audited, fn) {
							poolIdent, poolVar = poolCarrierIdent(sel.X)
						}
						if poolVar != nil {
							dischargePool(poolVar)
							if index, isIndex := syntaxutil.UnparenExpr(sel.X).(*ast.IndexExpr); isIndex {
								markExemptEscapes(index.Index)
							}
							if !provenCalls[sel] {
								if _, vOK := dynamicPackageVar(poolVar); vOK && refconfine.TypeHandsOutDynamicAlias(audited, poolVar.Type()) {
									key := syntaxutil.DynamicVarKey(poolVar)
									if poolEscaped != nil {
										poolEscaped[key] = true
									}
									if !singleSubject {
										if identOrPkgQual(sel.X) != nil && !syntaxutil.InterfaceReceiver(fn) && refconfine.InstantiatedResultsHandOutNothing(audited, selection.Type()) {
											factKey := syntaxutil.MethodFactKey(fn)
											syntaxutil.ExplainDeferralMark(hooks, p, 'n', key, syntaxutil.DeferralResolvent{Method: factKey}, sel.Pos())
										} else if poolIdent != nil {
											syntaxutil.ExplainMark(hooks, p, "escape", key, poolIdent.Pos())
										}
									}
								}
							}
							deferred = true
						} else if fnOK && !syntaxutil.InterfaceReceiver(fn) && refconfine.InstantiatedResultsHandOutNothing(audited, selection.Type()) {
							if ident := identOrPkgQual(sel.X); ident != nil {
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
		var markRead func(expr ast.Expr)
		markRead = func(expr ast.Expr) {
			switch expr := syntaxutil.UnparenExpr(expr).(type) {
			case *ast.Ident:
				readContext[expr] = true
			case *ast.SelectorExpr:
				readContext[expr.Sel] = true
			}
		}
		var markLValueBaseRead func(expr ast.Expr)
		markLValueBaseRead = func(expr ast.Expr) {
			switch expr := syntaxutil.UnparenExpr(expr).(type) {
			case *ast.Ident:
				readContext[expr] = true
			case *ast.SelectorExpr:
				readContext[expr.Sel] = true
				markLValueBaseRead(expr.X)
			case *ast.StarExpr:
				markLValueBaseRead(expr.X)
			case *ast.IndexExpr:
				markLValueBaseRead(expr.X)
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
						markLValueBaseRead(lhs)
						continue
					}
					markTargets(lhs)
					markLValueBaseRead(lhs)
				}
				if len(n.Lhs) == 2 && len(n.Rhs) == 1 {
					if blank, ok := syntaxutil.UnparenExpr(n.Lhs[0]).(*ast.Ident); ok && blank.Name == "_" {
						if index, ok := syntaxutil.UnparenExpr(n.Rhs[0]).(*ast.IndexExpr); ok {
							markRead(index.X)
						}
					}
				}
			case *ast.IncDecStmt:
				markTargets(n.X)
				markLValueBaseRead(n.X)
			case *ast.RangeStmt:
				if n.Key != nil {
					markTargets(n.Key)
					if n.Tok == token.ASSIGN {
						markLValueBaseRead(n.Key)
					}
				}
				if n.Value != nil {
					markTargets(n.Value)
					if n.Tok == token.ASSIGN {
						markLValueBaseRead(n.Value)
					}
				}
				if t := p.TypesInfo.TypeOf(n.X); t != nil {
					if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
						markTargets(n.X)
					} else if !refconfine.RangeBindsAlias(t) && !refconfine.TypeReachesSyncNoCopyByValue(t) {
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
							if obj := p.TypesInfo.Defs[ident]; obj != nil {
								if refconfine.TypeReachesSyncNoCopyByValue(obj.Type()) {
									sound = false
									break
								}
								if refconfine.TypeHandsOutMutableReach(obj.Type()) {
									roots[obj] = true
								}
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
											syntaxutil.ExplainDeferralMark(hooks, p, 'p', key, syntaxutil.DeferralResolvent{Param: want, EnclosingFn: currentDeferFn, Literal: currentDeferLit}, n.X.Pos())
										}
										if len(methodWants) > 0 && methodUses[key] == nil {
											methodUses[key] = map[syntaxutil.FuncKey]bool{}
										}
										for want := range methodWants {
											methodUses[key][want] = true
											syntaxutil.ExplainDeferralMark(hooks, p, 'm', key, syntaxutil.DeferralResolvent{Method: want, EnclosingFn: currentDeferFn, Literal: currentDeferLit}, n.X.Pos())
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
											pos:    n.X.Pos(),
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
			case *ast.SliceExpr:
				if t := p.TypesInfo.TypeOf(n.X); t != nil {
					if _, isArr := types.Unalias(t).Underlying().(*types.Array); isArr {
						markTargets(n.X)
					}
				}
			case *ast.IndexExpr:
				if t := p.TypesInfo.TypeOf(n); t != nil &&
					!refconfine.TypeHandsOutMutableReach(t) &&
					!refconfine.TypeReachesSyncNoCopyByValue(t) {
					markRead(n.X)
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL || n.Op == token.NEQ {
					if tx := p.TypesInfo.TypeOf(n.X); tx != nil && !refconfine.TypeReachesSyncNoCopyByValue(tx) {
						markRead(n.X)
					}
					if ty := p.TypesInfo.TypeOf(n.Y); ty != nil && !refconfine.TypeReachesSyncNoCopyByValue(ty) {
						markRead(n.Y)
					}
				}
			case *ast.GoStmt:
				ast.Inspect(n, func(inner ast.Node) bool {
					if call, ok := inner.(*ast.CallExpr); ok {
						goCalls[call] = true
					}
					return true
				})
			case *ast.CallExpr:
				funExpr := syntaxutil.UnparenExpr(n.Fun)
				if sel, ok := funExpr.(*ast.SelectorExpr); ok {
					calledSelectors[sel] = true
				}
				if ident, ok := funExpr.(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						switch ident.Name {
						case "len", "cap":
							for _, arg := range n.Args {
								markRead(arg)
							}
						case "delete", "clear":
							if len(n.Args) > 0 {
								markTargets(n.Args[0])
								markLValueBaseRead(n.Args[0])
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
					if index, ok := funExpr.(*ast.IndexExpr); ok {
						if base := identOrPkgQual(index.X); base != nil {
							if obj, ok := resolve(base); ok {
								if owner, ok := dynamicPackageVar(obj); ok {
									if sig, ok := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(n.Fun)).(*types.Signature); ok {
										ownerKey := syntaxutil.DynamicVarKey(owner)
										for i, arg := range n.Args {
											ident := identOrPkgQual(arg)
											if ident == nil {
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
						if calledSelectors[n] && refconfine.AuditedPooling(audited, fn) {
							if ident, variable := poolCarrierIdent(n.X); variable != nil {
								dischargePool(variable)
								if !provenCalls[n] {
									if _, vOK := dynamicPackageVar(variable); vOK {
										key := syntaxutil.DynamicVarKey(variable)
										isDirectIdent := identOrPkgQual(n.X) != nil
										if methodUses != nil && isDirectIdent && !syntaxutil.InterfaceReceiver(fn) && refconfine.InstantiatedResultsHandOutNothing(audited, selection.Type()) {
											factKey := syntaxutil.MethodFactKey(fn)
											if poolMethods != nil {
												if poolMethods[key] == nil {
													poolMethods[key] = map[syntaxutil.FuncKey]bool{}
												}
												poolMethods[key][factKey] = true
											} else if poolMutated != nil {
												poolMutated[key] = true
											}
											if !singleSubject {
												syntaxutil.ExplainDeferralMark(hooks, p, 'm', key, syntaxutil.DeferralResolvent{Method: factKey, EnclosingFn: currentDeferFn, Literal: currentDeferLit}, n.Pos())
											}
										} else {
											if sig, sigOK := fn.Type().(*types.Signature); sigOK && sig.Recv() != nil {
												if _, pointer := types.Unalias(sig.Recv().Type()).(*types.Pointer); pointer {
													if !singleSubject {
														syntaxutil.ExplainAttributedMark(hooks, p, "mutation", key, currentDeferFn, currentDeferLit, ident.Pos())
													}
													if poolMutated != nil {
														poolMutated[key] = true
													}
												}
											}
											if refconfine.TypeHandsOutDynamicAlias(audited, variable.Type()) {
												if !singleSubject {
													syntaxutil.ExplainMark(hooks, p, "escape", key, ident.Pos())
												}
												if poolEscaped != nil {
													poolEscaped[key] = true
												}
											}
										}
									}
								}
								readContext[ident] = true
								return true
							}
						}
						if calledSelectors[n] && refconfine.DataMemoMethod(audited, fn) {
							if ident := identOrPkgQual(n.X); ident != nil {
								if obj, ok := resolve(ident); ok {
									if variable, ok := obj.(*types.Var); ok && dataMemos[variable] {
										readContext[ident] = true
										return true
									}
								}
							}
						}
						if calledSelectors[n] && exemptSeamNodes[n] {
							if ident := identOrPkgQual(n.X); ident != nil {
								readContext[ident] = true
							}
							return true
						}
						if methodUses != nil && calledSelectors[n] && !syntaxutil.InterfaceReceiver(fn) && refconfine.InstantiatedResultsHandOutNothing(audited, selection.Type()) {
							if ident := identOrPkgQual(n.X); ident != nil {
								if obj, ok := resolve(ident); ok {
									if variable, ok := dynamicPackageVar(obj); ok {
										key := syntaxutil.DynamicVarKey(variable)
										if methodUses[key] == nil {
											methodUses[key] = map[syntaxutil.FuncKey]bool{}
										}
										factKey := syntaxutil.MethodFactKey(fn)
										methodUses[key][factKey] = true
										syntaxutil.ExplainDeferralMark(hooks, p, 'm', key, syntaxutil.DeferralResolvent{Method: factKey, EnclosingFn: currentDeferFn, Literal: currentDeferLit}, n.Pos())
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
		litPoolMutated, litPoolEscaped := map[string]bool{}, map[string]bool{}
		litPoolMethods := map[string]map[syntaxutil.FuncKey]bool{}
		litMethods := map[string]map[syntaxutil.FuncKey]bool{}
		var litParams map[string]map[syntaxutil.ParamKey]bool
		if paramUses != nil {
			litParams = map[string]map[syntaxutil.ParamKey]bool{}
		}
		interiors := map[ast.Node]bool{}
		saveLM, saveLE, saveLMU, saveLPU := mutated, escaped, methodUses, paramUses
		saveLPM, saveLPE, saveLPMU := poolMutated, poolEscaped, poolMethods
		mutated, escaped, methodUses, paramUses = litMutated, litEscaped, litMethods, litParams
		poolMutated, poolEscaped, poolMethods = litPoolMutated, litPoolEscaped, litPoolMethods
		if fnKey.Valid() {
			currentDeferFn, currentDeferLit = fnKey, true
		}
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
		currentDeferFn, currentDeferLit = syntaxutil.FuncKey{}, false
		mutated, escaped, methodUses, paramUses = saveLM, saveLE, saveLMU, saveLPU
		poolMutated, poolEscaped, poolMethods = saveLPM, saveLPE, saveLPMU
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
			if attributedParams != nil {
				for key, params := range litParams {
					for param := range params {
						*attributedParams = append(*attributedParams, syntaxutil.VarParamUse{Key: key, Param: param, Func: fnKey, Literal: true})
					}
				}
			}
			if poolAttributed != nil {
				for key := range litPoolMutated {
					*poolAttributed = append(*poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Literal: true})
				}
				for key := range litPoolEscaped {
					*poolAttributed = append(*poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Escape: true, Literal: true})
				}
				for key, methods := range litPoolMethods {
					for method := range methods {
						*poolAttributed = append(*poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: method, Literal: true})
					}
				}
			}
		} else {
			for key := range litMutated {
				mutated[key] = true
			}
			for key := range litEscaped {
				escaped[key] = true
			}
			if methodUses != nil {
				for key, methods := range litMethods {
					for method := range methods {
						if methodUses[key] == nil {
							methodUses[key] = map[syntaxutil.FuncKey]bool{}
						}
						methodUses[key][method] = true
					}
				}
			}
			if paramUses != nil {
				for key, params := range litParams {
					for param := range params {
						if paramUses[key] == nil {
							paramUses[key] = map[syntaxutil.ParamKey]bool{}
						}
						paramUses[key][param] = true
					}
				}
			}
			if poolMutated != nil {
				for key := range litPoolMutated {
					poolMutated[key] = true
				}
				for key := range litPoolMethods {
					poolMutated[key] = true
				}
			}
			if poolEscaped != nil {
				for key := range litPoolEscaped {
					poolEscaped[key] = true
				}
			}
		}
		localMutated, localEscaped := map[string]bool{}, map[string]bool{}
		localPoolMutated, localPoolEscaped := map[string]bool{}, map[string]bool{}
		localPoolMethods := map[string]map[syntaxutil.FuncKey]bool{}
		localMethods := map[string]map[syntaxutil.FuncKey]bool{}
		var localParams map[string]map[syntaxutil.ParamKey]bool
		if paramUses != nil {
			localParams = map[string]map[syntaxutil.ParamKey]bool{}
		}
		saveM, saveE, saveMU, savePU := mutated, escaped, methodUses, paramUses
		savePM, savePE, savePMU := poolMutated, poolEscaped, poolMethods
		mutated, escaped, methodUses, paramUses = localMutated, localEscaped, localMethods, localParams
		poolMutated, poolEscaped, poolMethods = localPoolMutated, localPoolEscaped, localPoolMethods
		skipInteriors = interiors
		if setCurrentFn {
			currentFn, currentAttrFn = decl, fnKey
		}
		if fnKey.Valid() {
			currentDeferFn, currentDeferLit = fnKey, false
		}
		walkBody(decl.Body)
		currentDeferFn, currentDeferLit = syntaxutil.FuncKey{}, false
		if setCurrentFn {
			currentFn, currentAttrFn = nil, syntaxutil.FuncKey{}
		}
		skipInteriors = nil
		mutated, escaped, methodUses, paramUses = saveM, saveE, saveMU, savePU
		poolMutated, poolEscaped, poolMethods = savePM, savePE, savePMU
		if fnKey.Valid() {
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
			if attributedParams != nil {
				for key, params := range localParams {
					for param := range params {
						*attributedParams = append(*attributedParams, syntaxutil.VarParamUse{Key: key, Param: param, Func: fnKey})
					}
				}
			}
			if poolAttributed != nil {
				for key := range localPoolMutated {
					*poolAttributed = append(*poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key})
				}
				for key := range localPoolEscaped {
					*poolAttributed = append(*poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Escape: true})
				}
				for key, methods := range localPoolMethods {
					for method := range methods {
						*poolAttributed = append(*poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: method})
					}
				}
			}
		} else {
			for key := range localMutated {
				mutated[key] = true
			}
			for key := range localEscaped {
				escaped[key] = true
			}
			if methodUses != nil {
				for key, methods := range localMethods {
					for method := range methods {
						if methodUses[key] == nil {
							methodUses[key] = map[syntaxutil.FuncKey]bool{}
						}
						methodUses[key][method] = true
					}
				}
			}
			if paramUses != nil {
				for key, params := range localParams {
					for param := range params {
						if paramUses[key] == nil {
							paramUses[key] = map[syntaxutil.ParamKey]bool{}
						}
						paramUses[key][param] = true
					}
				}
			}
			if poolMutated != nil {
				for key := range localPoolMutated {
					poolMutated[key] = true
				}
				for key := range localPoolMethods {
					poolMutated[key] = true
				}
			}
			if poolEscaped != nil {
				for key := range localPoolEscaped {
					poolEscaped[key] = true
				}
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
				if decl.Recv == nil && decl.Name != nil && attributed != nil && !initOnly[decl.Name.Name] && decl.Name.Name != "init" && decl.Name.Name != "_" && decl.Body != nil && p.Types != nil {
					fnKey := syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: decl.Name.Name}
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
						scanExemptCalls(decl.Body, decl.Type)
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
				scanExemptCalls(decl, nil)
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
					// Unwind parenthesized/instantiated callee spine up to enclosing CallExpr.
					callIdxInStack := len(stack) - 1
					for callIdxInStack >= 0 {
						switch stack[callIdxInStack].(type) {
						case *ast.ParenExpr, *ast.IndexExpr, *ast.IndexListExpr:
							callIdxInStack--
						default:
							goto foundCallParent
						}
					}
				foundCallParent:
					if callIdxInStack < 0 {
						bad[fnName] = true
						return true
					}
					call, ok := stack[callIdxInStack].(*ast.CallExpr)
					if !ok || syntaxutil.UnwrapCallee(call.Fun) != ast.Expr(ident) {
						bad[fnName] = true
						return true
					}
					grandIdx := callIdxInStack - 1
					for grandIdx >= 0 {
						if _, isParen := stack[grandIdx].(*ast.ParenExpr); isParen {
							grandIdx--
						} else {
							break
						}
					}
					var grand ast.Node
					if grandIdx >= 0 {
						grand = stack[grandIdx]
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
						if len(g.Rhs) != 1 || syntaxutil.UnparenExpr(g.Rhs[0]) != ast.Expr(call) {
							bad[fnName] = true
							return true
						}
						targets = g.Lhs
					case *ast.ValueSpec:
						if len(g.Values) != 1 || syntaxutil.UnparenExpr(g.Values[0]) != ast.Expr(call) {
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
						tIdent, ok := syntaxutil.UnparenExpr(target).(*ast.Ident)
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
						eligible := decl.Recv == nil && decl.Name != nil && !decl.Name.IsExported() && name != "init" && name != "_"
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
												if call, isCall := syntaxutil.UnparenExpr(value).(*ast.CallExpr); isCall && syntaxutil.UnwrapCallee(call.Fun) == ast.Expr(ident) {
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
						syntaxutil.ExplainAttributedMark(hooks, p, "escape", key, pending.attrFn, false, pending.pos)
						*attributed = append(*attributed, syntaxutil.AttributedUse{Func: pending.attrFn, Key: key, Escape: true})
					}
				} else {
					syntaxutil.ExplainMark(hooks, p, "escape", key, pending.pos)
					escaped[key] = true
				}
			}
		}
	}
}
