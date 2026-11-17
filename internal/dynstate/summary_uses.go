package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

type pendingReturnDisposition struct {
	fn     string
	keys   []string
	attrFn syntaxutil.FuncKey
	pos    token.Pos
}

// recordDynamicGlobalUses classifies mutations, escapes, attributed uses,
// parameter/method/field/element deferrals, pool uses, and init-flow carrier
// storage links across p using pre-lowered flowir.Body representations from fc.
func recordDynamicGlobalUses(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
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
	if fc == nil {
		fc = newPkgFlowCache(audited, p)
	}
	if callIdx == nil {
		callIdx = refconfine.BuildCallSiteIndex(p)
	}
	dataMemos := dataMemoVars(audited, p, fc, callIdx)

	dynamicPackageVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable == nil || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		if !refconfine.TypeMayCarryUnknownDynamic(audited, variable.Type()) {
			return nil, false
		}
		return variable, true
	}

	var aliasedLocals map[types.Object]localCarrierAliases
	var precomputedDeclAliases bool
	var activeJudgedRangeVars map[types.Object]bool
	var poolMethods map[string]map[syntaxutil.FuncKey]bool
	var currentFn *ast.FuncDecl
	var currentAttrFn syntaxutil.FuncKey
	var currentDeferFn syntaxutil.FuncKey
	var currentDeferLit bool
	var inGoOp bool
	var pendingReturns []pendingReturnDisposition

	markMutatedVars := func(vars []*types.Var, pos token.Pos) {
		for _, v := range vars {
			if v == nil {
				continue
			}
			key := syntaxutil.DynamicVarKey(v)
			syntaxutil.ExplainAttributedMark(hooks, p, "mutation", key, currentDeferFn, currentDeferLit, pos)
			mutated[key] = true
		}
	}

	markEscapedVars := func(vars []*types.Var, pos token.Pos) {
		for _, v := range vars {
			if v == nil {
				continue
			}
			key := syntaxutil.DynamicVarKey(v)
			syntaxutil.ExplainMark(hooks, p, "escape", key, pos)
			escaped[key] = true
		}
	}

	poolCarrierPlace := func(pl flowir.Place) (token.Pos, *types.Var, bool) {
		if pl.Obj == nil || pl.Obj.Pkg() == nil || pl.Obj.Parent() != pl.Obj.Pkg().Scope() {
			return token.NoPos, nil, false
		}
		element := false
		if len(pl.Projs) == 1 && pl.Projs[0].Kind == flowir.ProjIndex {
			element = true
		} else if len(pl.Projs) != 0 {
			return token.NoPos, nil, false
		}
		t := types.Unalias(pl.Obj.Type())
		if element {
			switch sequence := t.(type) {
			case *types.Array:
				t = types.Unalias(sequence.Elem())
			case *types.Slice:
				t = types.Unalias(sequence.Elem())
			default:
				return token.NoPos, nil, false
			}
		}
		named, ok := t.(*types.Named)
		if !ok || named.Obj() == nil || named.Obj().Pkg() == nil ||
			named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Pool" {
			return token.NoPos, nil, false
		}
		return pl.RootPos, pl.Obj, !element
	}

	isExemptMethodRecvCall := func(v *flowir.Value) bool {
		if v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallMethod || v.IsMethodExprCall ||
			v.Selection == nil || v.Selection.Kind() != types.MethodVal || v.CalleeFunc == nil {
			return false
		}
		fn := v.CalleeFunc
		if refconfine.AuditedPooling(audited, fn) && v.HasRecvPlace {
			if _, poolVar, _ := poolCarrierPlace(v.RecvPlace); poolVar != nil {
				return true
			}
		}
		if refconfine.DataMemoMethod(audited, fn) && v.HasRecvPlace && v.RecvPlace.IsBareVar() && dataMemos[v.RecvPlace.Obj] {
			return true
		}
		if sel := v.CalleeSelector(); sel != nil && exemptSeamNodes[sel] && v.HasRecvPlace && v.RecvPlace.IsBareVar() {
			return true
		}
		return false
	}

	markPlaceMutated := func(pl flowir.Place, writeContainer bool) {
		if pl.Root == flowir.RootBlank {
			return
		}
		if pl.Obj != nil {
			if activeJudgedRangeVars[pl.Obj] {
				return
			}
			if variable, ok := dynamicPackageVar(pl.Obj); ok {
				markMutatedVars([]*types.Var{variable}, pl.RootPos)
				return
			}
			entry := aliasedLocals[pl.Obj]
			vars := entry.root
			if placeEntersInterior(pl, writeContainer) {
				vars = entry.all
			}
			markMutatedVars(vars, pl.RootPos)
			return
		}
		if pl.Root == flowir.RootTransient && pl.Base != nil {
			vars := collectValueCarrierVars(audited, pl.Base, dynamicPackageVar, aliasedLocals, isExemptMethodRecvCall)
			markMutatedVars(vars, pl.RootPos)
		}
	}

	markValueMutated := func(v *flowir.Value, writeContainer bool) {
		if v == nil {
			return
		}
		switch v.Kind {
		case flowir.ValPlace:
			markPlaceMutated(v.Place, writeContainer)
		case flowir.ValAddrOf:
			markPlaceMutated(v.AddrPlace, false)
		default:
			var walk func(cur *flowir.Value)
			walk = func(cur *flowir.Value) {
				if cur == nil || cur.Kind == flowir.ValMakeClosure {
					return
				}
				if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallIIFE {
					forEachIIFEReturnValue(cur, walk)
					return
				}
				if cur.Kind == flowir.ValPlace {
					markPlaceMutated(cur.Place, writeContainer)
					return
				}
				if cur.Kind == flowir.ValAddrOf {
					markPlaceMutated(cur.AddrPlace, false)
					return
				}
				cur.ForEachChildValue(func(ch *flowir.Value) bool {
					walk(ch)
					return true
				})
			}
			walk(v)
		}
	}

	markPtrRecvMutated := func(recv *flowir.Value, autoAddr bool) {
		if recv == nil {
			return
		}
		if autoAddr {
			markValueMutated(recv, false)
			return
		}
		var walk func(cur *flowir.Value)
		walk = func(cur *flowir.Value) {
			if cur == nil || cur.Kind == flowir.ValMakeClosure {
				return
			}
			if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallIIFE {
				forEachIIFEReturnValue(cur, walk)
				return
			}
			if cur.Kind == flowir.ValPlace {
				derefPl := cur.Place
				derefPl.Projs = append(append([]flowir.Proj(nil), derefPl.Projs...), flowir.Proj{
					Kind:     flowir.ProjDeref,
					BaseType: cur.Type,
				})
				markPlaceMutated(derefPl, false)
				return
			}
			if cur.Kind == flowir.ValAddrOf {
				markPlaceMutated(cur.AddrPlace, false)
				return
			}
			cur.ForEachChildValue(func(ch *flowir.Value) bool {
				walk(ch)
				return true
			})
		}
		walk(recv)
	}

	initOnlyParams := callIdx.FuncParamsOf(initOnly)
	paramSeeds := map[types.Object]localCarrierAliases{}
	paramLinkSeeds := map[types.Object][]*types.Var{}
	paramSeedGrowth := false
	seedingPass := false

	initAliasedLocals := func(b *flowir.Body) map[types.Object]localCarrierAliases {
		cfg := carrierAliasConfig{
			parentAliases:  paramSeeds,
			parentLinks:    paramLinkSeeds,
			carrierVar:     dynamicPackageVar,
			skipMethodRecv: isExemptMethodRecvCall,
			descendNested:  false,
			trackLinks:     true,
			onPlainCall: func(
				callVal *flowir.Value,
				valSources func(*flowir.Value) ([]*types.Var, []*types.Var),
				valLinks func(*flowir.Value) []*types.Var,
			) {
				if callVal.CalleeFunc == nil {
					return
				}
				params := initOnlyParams[callVal.CalleeFunc.Origin()]
				if len(params) == 0 {
					return
				}
				callVal.ForEachArgParam(func(arg *flowir.Value, _ types.Type, _ int, paramIdx int, ok bool, packedVariadic bool) bool {
					if !ok || paramIdx < 0 || paramIdx >= len(params) || arg == nil {
						return true
					}
					param := params[paramIdx]
					if param == nil {
						return true
					}
					gateType := param.Type()
					if packedVariadic {
						if slice, isSlice := types.Unalias(gateType).(*types.Slice); isSlice {
							gateType = slice.Elem()
						}
					}
					if !canAliasCarrierType(audited, gateType) && !isTypeParamType(gateType) {
						return true
					}
					rootSrcs, allSrcs := valSources(arg)
					if packedVariadic {
						rootSrcs = nil
					}
					entry := paramSeeds[param]
					if len(rootSrcs) > 0 && (isRefHeaderType(param.Type()) || isTypeParamType(param.Type())) {
						if appendUniqueVars(&entry.root, rootSrcs) {
							paramSeedGrowth = true
						}
						if appendUniqueVars(&entry.all, rootSrcs) {
							paramSeedGrowth = true
						}
					}
					if appendUniqueVars(&entry.all, allSrcs) {
						paramSeedGrowth = true
					}
					if len(entry.root) > 0 || len(entry.all) > 0 {
						paramSeeds[param] = entry
					}
					lvars := valLinks(arg)
					if len(lvars) > 0 {
						curLinks := paramLinkSeeds[param]
						if appendUniqueVars(&curLinks, lvars) {
							paramLinkSeeds[param] = curLinks
							paramSeedGrowth = true
						}
					}
					return true
				})
			},
		}
		if !seedingPass {
			if carrierLinks != nil {
				cfg.onCarrierLink = func(own, target *types.Var) {
					ownKey := syntaxutil.DynamicVarKey(own)
					targetKey := syntaxutil.DynamicVarKey(target)
					if ownKey == targetKey {
						return
					}
					if carrierLinks[ownKey] == nil {
						carrierLinks[ownKey] = map[string]bool{}
					}
					carrierLinks[ownKey][targetKey] = true
				}
			}
			cfg.onNonCarrierPkgBind = func(pkgVar *types.Var, pos token.Pos, composite bool, allVars, linkVars []*types.Var) {
				if composite || refconfine.CallResultHandsOut(pkgVar.Type()) {
					markEscapedVars(linkVars, pos)
					markEscapedVars(allVars, pos)
				}
			}
			cfg.onParamCompositeBind = func(pos token.Pos, allVars, linkVars []*types.Var) {
				markEscapedVars(linkVars, pos)
				markEscapedVars(allVars, pos)
			}
			cfg.onRHSMethodValue = func(mv *flowir.Value, aliases map[types.Object]localCarrierAliases) {
				if mv == nil || mv.Recv == nil {
					return
				}
				walkTransientTargetValues(mv.Recv, func(cur *flowir.Value) {
					switch cur.Kind {
					case flowir.ValPlace:
						if cur.Place.Obj != nil {
							if variable, ok := dynamicPackageVar(cur.Place.Obj); ok {
								markEscapedVars([]*types.Var{variable}, cur.Place.RootPos)
							} else {
								markEscapedVars(aliases[cur.Place.Obj].all, cur.Place.RootPos)
							}
						}
					case flowir.ValAddrOf:
						if cur.AddrPlace.Obj != nil {
							if variable, ok := dynamicPackageVar(cur.AddrPlace.Obj); ok {
								markEscapedVars([]*types.Var{variable}, cur.AddrPlace.RootPos)
							} else {
								markEscapedVars(aliases[cur.AddrPlace.Obj].all, cur.AddrPlace.RootPos)
							}
						}
					}
				})
			}
		}
		aliased, _ := computeBodyCarrierAliases(audited, fc, b, cfg)
		return aliased
	}

	carrierArgVar := func(arg *flowir.Value) (token.Pos, *types.Var) {
		if arg == nil || arg.Kind != flowir.ValPlace || !arg.Place.IsBareVar() || arg.Place.Obj == nil {
			return token.NoPos, nil
		}
		variable, ok := dynamicPackageVar(arg.Place.Obj)
		if !ok {
			return token.NoPos, nil
		}
		vt := variable.Type()
		if !refconfine.TypeHandsOutDynamicAlias(audited, vt) && !syntaxutil.ContainsUintptr(vt) {
			return token.NoPos, nil
		}
		return arg.Place.RootPos, variable
	}

	deferCarrierArgs := func(callVal *flowir.Value, sink map[string]map[syntaxutil.ParamKey]bool, kind byte) map[int]bool {
		if callVal == nil || callVal.CallKind != flowir.CallPlain || callVal.IsMethodExprCall || callVal.CalleeFunc == nil {
			return nil
		}
		fn := callVal.CalleeFunc.Origin()
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil || sig.Params().Len() == 0 {
			return nil
		}
		var deferredArgIdxs map[int]bool
		for i, arg := range callVal.Args {
			pos, variable := carrierArgVar(arg)
			if variable == nil {
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
			paramKey := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: callVal.CalleePkg, Name: fn.Name()}, Index: idx}
			sink[key][paramKey] = true
			res := syntaxutil.DeferralResolvent{Param: paramKey}
			if kind == 'p' {
				res.EnclosingFn = currentDeferFn
				res.Literal = currentDeferLit
			}
			syntaxutil.ExplainDeferralMark(hooks, p, kind, key, res, pos)
			if deferredArgIdxs == nil {
				deferredArgIdxs = map[int]bool{}
			}
			deferredArgIdxs[i] = true
		}
		return deferredArgIdxs
	}

	dischargePool := func(variable *types.Var) {
		if poolDischarged != nil {
			poolDischarged[syntaxutil.DynamicVarKey(variable)] = true
		}
	}
	recordConfinementSinkUses := func(
		key string,
		wants map[syntaxutil.ParamKey]bool,
		methodWants map[syntaxutil.FuncKey]bool,
		fieldWants map[syntaxutil.FieldPosKey]bool,
		elemWants map[syntaxutil.ElemParamUse]bool,
		enclFn syntaxutil.FuncKey,
		literal bool,
		pos token.Pos,
	) {
		if len(wants) > 0 {
			if paramUses[key] == nil {
				paramUses[key] = map[syntaxutil.ParamKey]bool{}
			}
			for want := range wants {
				paramUses[key][want] = true
				syntaxutil.ExplainDeferralMark(hooks, p, 'p', key, syntaxutil.DeferralResolvent{
					Param:       want,
					EnclosingFn: enclFn,
					Literal:     literal,
				}, pos)
			}
		}
		if len(methodWants) > 0 {
			if methodUses[key] == nil {
				methodUses[key] = map[syntaxutil.FuncKey]bool{}
			}
			for want := range methodWants {
				methodUses[key][want] = true
				syntaxutil.ExplainDeferralMark(hooks, p, 'm', key, syntaxutil.DeferralResolvent{
					Method:      want,
					EnclosingFn: enclFn,
					Literal:     literal,
				}, pos)
			}
		}
		if len(fieldWants) > 0 {
			if fieldUses[key] == nil {
				fieldUses[key] = map[syntaxutil.FieldPosKey]bool{}
			}
			for want := range fieldWants {
				fp := syntaxutil.FieldPosKey{Owner: key, Field: want.Field, Index: want.Index}
				fieldUses[key][fp] = true
				syntaxutil.ExplainDeferralMark(hooks, p, 'f', key, syntaxutil.DeferralResolvent{FieldPos: fp}, pos)
			}
		}
		if len(elemWants) > 0 {
			if elemUses[key] == nil {
				elemUses[key] = map[syntaxutil.ElemParamUse]bool{}
			}
			for want := range elemWants {
				eu := syntaxutil.ElemParamUse{Key: key, Owner: want.Owner, Index: want.Index}
				elemUses[key][eu] = true
				syntaxutil.ExplainDeferralMark(hooks, p, 'e', key, syntaxutil.DeferralResolvent{ElemUse: eu}, pos)
			}
		}
	}
	_, provenCalls := provenSharedPools(audited, p, fc)

	var markExemptEscapesVal func(v *flowir.Value)
	markExemptEscapesPlace := func(pl flowir.Place, vt types.Type, addressed bool) {
		pl.ForEachChildValue(func(cv *flowir.Value) bool {
			markExemptEscapesVal(cv)
			return true
		})
		if pl.Obj != nil {
			if variable, ok := dynamicPackageVar(pl.Obj); ok {
				if addressed || refconfine.TypeHandsOutDynamicAlias(audited, variable.Type()) ||
					syntaxutil.ContainsUintptr(vt) {
					markEscapedVars([]*types.Var{variable}, pl.RootPos)
				}
			} else {
				entry := aliasedLocals[pl.Obj]
				vars := entry.root
				if placeEntersInterior(pl, false) || canAliasCarrierType(audited, vt) || isTypeParamType(vt) {
					vars = entry.all
				}
				markEscapedVars(vars, pl.RootPos)
			}
		}
	}
	markExemptEscapesVal = func(v *flowir.Value) {
		// ValMethodVal receiver escapes across sync/IIFE ops in init and GenDecl
		// scopes are already recorded by initAliasedLocals's onRHSMethodValue pass.
		if v == nil || v.Kind == flowir.ValMakeClosure || v.Kind == flowir.ValMethodVal {
			return
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallIIFE {
			for _, a := range v.Args {
				markExemptEscapesVal(a)
			}
			forEachIIFEReturnValue(v, markExemptEscapesVal)
			return
		}
		isStrBuiltin := v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin &&
			(v.BuiltinName == "String" || v.BuiltinName == "StringData")
		if !isStrBuiltin && v.Type != nil && !canAliasCarrierType(audited, v.Type) && !isTypeParamType(v.Type) {
			return
		}
		switch v.Kind {
		case flowir.ValPlace:
			markExemptEscapesPlace(v.Place, v.Type, false)
		case flowir.ValAddrOf:
			if v.Low != nil {
				markExemptEscapesVal(v.Low)
			}
			if v.High != nil {
				markExemptEscapesVal(v.High)
			}
			if v.Max != nil {
				markExemptEscapesVal(v.Max)
			}
			markExemptEscapesPlace(v.AddrPlace, v.Type, true)
		case flowir.ValCall:
			if v.CallKind == flowir.CallBuiltin {
				switch v.BuiltinName {
				case "len", "cap", "Sizeof", "Alignof", "Offsetof":
					return
				case "Slice", "SliceData", "String", "StringData":
					if len(v.Args) > 0 {
						markExemptEscapesVal(v.Args[0])
					}
					return
				}
			}
			for _, a := range v.Args {
				markExemptEscapesVal(a)
			}
		default:
			v.ForEachChildValue(func(ch *flowir.Value) bool {
				markExemptEscapesVal(ch)
				return true
			})
		}
	}

	scanExemptCalls := func(b *flowir.Body) {
		if initParamUses == nil || b == nil {
			return
		}
		var scanCallTree func(v *flowir.Value)
		scanCallTree = func(v *flowir.Value) {
			if v == nil || v.Kind == flowir.ValMakeClosure {
				return
			}
			if v.Kind == flowir.ValChanRecv {
				markExemptEscapesVal(v.Chan)
				scanCallTree(v.Chan)
				return
			}
			if v.Kind == flowir.ValCall {
				if v.CallKind == flowir.CallIIFE {
					for _, a := range v.Args {
						scanCallTree(a)
					}
					return
				}
				if v.CallKind == flowir.CallBuiltin {
					switch v.BuiltinName {
					case "copy":
						if len(v.Args) == 2 && transientValueHasUnresolvedTarget(v.Args[0]) {
							markExemptEscapesVal(v.Args[1])
						}
						for _, a := range v.Args {
							scanCallTree(a)
						}
						return
					case "Sizeof", "Alignof", "Offsetof":
						return
					case "len", "cap", "delete", "clear", "append", "Add", "Slice", "SliceData", "String", "StringData", "min", "max":
						for _, a := range v.Args {
							scanCallTree(a)
						}
						return
					}
				}
				var deferredArgs map[int]bool
				switch v.CallKind {
				case flowir.CallPlain:
					if !v.IsMethodExprCall && v.CalleeFunc != nil {
						deferredArgs = deferCarrierArgs(v, initParamUses, 'q')
					} else if v.IsMethodExprCall && v.Recv != nil {
						markExemptEscapesVal(v.Recv)
						scanCallTree(v.Recv)
					}
				case flowir.CallMethod:
					if !v.IsMethodExprCall && v.Selection != nil && v.Selection.Kind() == types.MethodVal && v.CalleeFunc != nil {
						deferred := false
						fn := v.CalleeFunc
						sel := v.CalleeSelector()
						var poolPos token.Pos
						var poolVar *types.Var
						var isBarePool bool
						if refconfine.AuditedPooling(audited, fn) && v.HasRecvPlace {
							poolPos, poolVar, isBarePool = poolCarrierPlace(v.RecvPlace)
						}
						if poolVar != nil {
							dischargePool(poolVar)
							v.RecvPlace.ForEachChildValue(func(cv *flowir.Value) bool {
								markExemptEscapesVal(cv)
								scanCallTree(cv)
								return true
							})
							if sel == nil || !provenCalls[sel] {
								if _, vOK := dynamicPackageVar(poolVar); vOK && refconfine.TypeHandsOutDynamicAlias(audited, poolVar.Type()) {
									key := syntaxutil.DynamicVarKey(poolVar)
									if poolEscaped != nil {
										poolEscaped[key] = true
									}
									if !singleSubject {
										if isBarePool && !syntaxutil.InterfaceReceiver(fn) &&
											refconfine.InstantiatedResultsHandOutNothing(audited, v.Selection.Type()) && sel != nil {
											factKey := syntaxutil.MethodFactKey(fn)
											syntaxutil.ExplainDeferralMark(hooks, p, 'n', key, syntaxutil.DeferralResolvent{Method: factKey}, sel.Pos())
										} else if poolPos.IsValid() {
											syntaxutil.ExplainMark(hooks, p, "escape", key, poolPos)
										}
									}
								}
							}
							deferred = true
						} else if !syntaxutil.InterfaceReceiver(fn) &&
							refconfine.InstantiatedResultsHandOutNothing(audited, v.Selection.Type()) &&
							v.HasRecvPlace && v.RecvPlace.IsBareVar() && sel != nil {
							if variable, vOK := dynamicPackageVar(v.RecvPlace.Obj); vOK {
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
						if !deferred && v.Recv != nil {
							markExemptEscapesVal(v.Recv)
							scanCallTree(v.Recv)
						}
					} else if v.Recv != nil {
						markExemptEscapesVal(v.Recv)
						scanCallTree(v.Recv)
					}
				case flowir.CallIndirect:
					if v.Callee != nil {
						scanCallTree(v.Callee)
					}
				}
				for i, a := range v.Args {
					if !deferredArgs[i] {
						if a != nil && a.Kind == flowir.ValPlace &&
							!refconfine.CallResultHandsOut(a.Type) && !isTypeParamType(a.Type) {
							a.Place.ForEachChildValue(func(cv *flowir.Value) bool {
								markExemptEscapesVal(cv)
								return true
							})
						} else {
							markExemptEscapesVal(a)
						}
					}
					scanCallTree(a)
				}
				return
			}
			v.ForEachChildValue(func(ch *flowir.Value) bool {
				scanCallTree(ch)
				return true
			})
		}

		for _, rv := range b.Results {
			if rv != nil && (canAliasCarrierType(audited, rv.Type()) || isTypeParamType(rv.Type())) {
				markEscapedVars(aliasedLocals[rv].all, rv.Pos())
			}
		}

		b.ForEachSyncOp(func(op *flowir.Op) bool {
			if op.Kind == flowir.OpGo {
				return true
			}
			if op.Kind == flowir.OpReturn {
				for _, res := range op.Results {
					markExemptEscapesVal(res)
					scanCallTree(res)
				}
				return true
			}
			if op.Kind == flowir.OpAssign {
				if op.AssignKind == flowir.AssignRange {
					if len(op.Srcs) > 0 && op.Srcs[0] != nil && op.Srcs[0].Type != nil {
						if _, isChan := types.Unalias(op.Srcs[0].Type).Underlying().(*types.Chan); isChan {
							markExemptEscapesVal(op.Srcs[0])
						}
					}
				} else if op.AssignKind != flowir.AssignZeroDecl && op.AssignKind != flowir.AssignIncDec {
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						if dst.Root == flowir.RootTransient && transientValueHasUnresolvedTarget(dst.Base) {
							markExemptEscapesVal(src)
							if _, keyVal, isMapW := dst.AsMapWrite(); isMapW {
								markExemptEscapesVal(keyVal)
							}
						}
						return true
					})
				}
			}
			if op.Kind == flowir.OpChanSend && op.ChanPlace.Obj == nil {
				markExemptEscapesVal(op.SendVal)
			}
			forEachOpTopValues(op, scanCallTree)
			return true
		})
	}

	var walkBody func(b *flowir.Body, descendNested bool)
	walkBody = func(b *flowir.Body, descendNested bool) {
		if b == nil {
			return
		}
		if len(aliasedLocals) > 0 && !precomputedDeclAliases {
			savedAliases := aliasedLocals
			extended, _ := computeBodyCarrierAliases(audited, fc, b, carrierAliasConfig{
				parentAliases:  savedAliases,
				carrierVar:     dynamicPackageVar,
				skipMethodRecv: isExemptMethodRecvCall,
				descendNested:  descendNested,
			})
			aliasedLocals = extended
			defer func() { aliasedLocals = savedAliases }()
		}
		prevJudgedRange := activeJudgedRangeVars
		var judgedRangeVars map[types.Object]bool
		activeJudgedRangeVars = nil
		defer func() { activeJudgedRangeVars = prevJudgedRange }()
		var allowLocalAddrBind bool

		markRecvValueEscaped := func(recv *flowir.Value) {
			if recv == nil {
				return
			}
			walkTransientTargetValues(recv, func(cur *flowir.Value) {
				switch cur.Kind {
				case flowir.ValPlace:
					if cur.Place.Obj != nil && !judgedRangeVars[cur.Place.Obj] {
						if variable, ok := dynamicPackageVar(cur.Place.Obj); ok {
							markEscapedVars([]*types.Var{variable}, cur.Place.RootPos)
						} else {
							markEscapedVars(aliasedLocals[cur.Place.Obj].all, cur.Place.RootPos)
						}
					}
				case flowir.ValAddrOf:
					if cur.AddrPlace.Obj != nil && !judgedRangeVars[cur.AddrPlace.Obj] {
						if variable, ok := dynamicPackageVar(cur.AddrPlace.Obj); ok {
							markEscapedVars([]*types.Var{variable}, cur.AddrPlace.RootPos)
						} else {
							markEscapedVars(aliasedLocals[cur.AddrPlace.Obj].all, cur.AddrPlace.RootPos)
						}
					}
				}
			})
		}

		var walkValue func(v *flowir.Value)
		walkPlaceRead := func(pl flowir.Place, vt types.Type) {
			pl.ForEachChildValue(func(cv *flowir.Value) bool {
				walkValue(cv)
				return true
			})
			if pl.Obj == nil || judgedRangeVars[pl.Obj] {
				return
			}
			// A 1-hop index read whose element hands out no mutable reach and no
			// sync.noCopy value (such as `m[k]` returning int or func()) is writeless.
			if len(pl.Projs) == 1 && pl.Projs[0].Kind == flowir.ProjIndex && vt != nil &&
				!refconfine.TypeHandsOutMutableReach(vt) &&
				!refconfine.TypeReachesSyncNoCopyByValue(vt) &&
				!syntaxutil.ContainsUintptr(vt) {
				return
			}
			if variable, ok := dynamicPackageVar(pl.Obj); ok {
				if refconfine.TypeHandsOutDynamicAlias(audited, variable.Type()) ||
					syntaxutil.ContainsUintptr(vt) {
					markEscapedVars([]*types.Var{variable}, pl.RootPos)
				}
				return
			}
			entry := aliasedLocals[pl.Obj]
			vars := entry.root
			if placeEntersInterior(pl, false) || canAliasCarrierType(audited, vt) || isTypeParamType(vt) {
				vars = entry.all
			}
			markEscapedVars(vars, pl.RootPos)
		}
		walkCallArg := func(a *flowir.Value) {
			if a != nil && a.Kind == flowir.ValPlace &&
				!refconfine.CallResultHandsOut(a.Type) && !isTypeParamType(a.Type) {
				walkPlaceRead(a.Place, a.Type)
				return
			}
			walkValue(a)
		}

		walkValue = func(v *flowir.Value) {
			if v == nil {
				return
			}
			switch v.Kind {
			case flowir.ValMakeClosure:
				if descendNested && v.Closure != nil {
					walkBody(v.Closure, true)
				}
				return

			case flowir.ValPlace:
				walkPlaceRead(v.Place, v.Type)
				return

			case flowir.ValAddrOf:
				isDirectLocalBind := allowLocalAddrBind
				allowLocalAddrBind = false
				v.AddrPlace.ForEachChildValue(func(cv *flowir.Value) bool {
					walkValue(cv)
					return true
				})
				if v.Low != nil {
					walkValue(v.Low)
				}
				if v.High != nil {
					walkValue(v.High)
				}
				if v.Max != nil {
					walkValue(v.Max)
				}
				if v.AddrPlace.Obj != nil && !judgedRangeVars[v.AddrPlace.Obj] {
					if variable, ok := dynamicPackageVar(v.AddrPlace.Obj); ok {
						markMutatedVars([]*types.Var{variable}, v.AddrPlace.RootPos)
						if !isDirectLocalBind {
							markEscapedVars([]*types.Var{variable}, v.AddrPlace.RootPos)
						}
					} else {
						entry := aliasedLocals[v.AddrPlace.Obj]
						vars := entry.root
						canAlias := placeEntersInterior(v.AddrPlace, false) || addrOfSubplaceCanAliasCarrier(audited, v)
						if canAlias {
							vars = entry.all
						}
						markMutatedVars(vars, v.AddrPlace.RootPos)
						if !isDirectLocalBind && canAlias {
							markEscapedVars(vars, v.AddrPlace.RootPos)
						}
					}
				} else if v.AddrPlace.Root == flowir.RootTransient && v.AddrPlace.Base != nil {
					vars := collectValueCarrierVars(audited, v.AddrPlace.Base, dynamicPackageVar, aliasedLocals, isExemptMethodRecvCall)
					markMutatedVars(vars, v.AddrPlace.RootPos)
					if !isDirectLocalBind {
						markEscapedVars(vars, v.AddrPlace.RootPos)
					}
				}
				return

			case flowir.ValChanRecv:
				markValueMutated(v.Chan, true)
				walkValue(v.Chan)
				return

			case flowir.ValCompare:
				for _, side := range []*flowir.Value{v.Left, v.Right} {
					if side == nil {
						continue
					}
					if side.Kind == flowir.ValPlace && len(side.Place.Projs) == 0 &&
						side.Type != nil && !refconfine.TypeReachesSyncNoCopyByValue(side.Type) {
						continue
					}
					walkValue(side)
				}
				return

			case flowir.ValMethodVal:
				if v.Method != nil {
					if sig, ok := v.Method.Type().(*types.Signature); ok && sig.Recv() != nil {
						if _, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer); ptr {
							markPtrRecvMutated(v.Recv, v.AutoAddr)
							markRecvValueEscaped(v.Recv)
						}
					}
				}
				walkValue(v.Recv)
				return

			case flowir.ValCall:
				switch v.CallKind {
				case flowir.CallIIFE:
					for _, a := range v.Args {
						walkValue(a)
					}
					if descendNested && v.IIFE != nil {
						walkBody(v.IIFE, true)
					}
					return

				case flowir.CallBuiltin:
					switch v.BuiltinName {
					case "Sizeof", "Alignof", "Offsetof":
						return
					case "len", "cap":
						for _, a := range v.Args {
							if a != nil && a.Kind == flowir.ValPlace && len(a.Place.Projs) == 0 {
								continue
							}
							walkValue(a)
						}
						return
					case "delete", "clear":
						if len(v.Args) > 0 && v.Args[0] != nil {
							markValueMutated(v.Args[0], true)
							if v.Args[0].Kind == flowir.ValPlace {
								v.Args[0].Place.ForEachChildValue(func(cv *flowir.Value) bool {
									walkValue(cv)
									return true
								})
							} else {
								walkValue(v.Args[0])
							}
							for _, a := range v.Args[1:] {
								walkValue(a)
							}
							return
						}
					}
					for _, a := range v.Args {
						walkValue(a)
					}
					return

				case flowir.CallPlain:
					var deferredArgs map[int]bool
					if paramUses != nil && !inGoOp && !v.IsMethodExprCall {
						deferredArgs = deferCarrierArgs(v, paramUses, 'p')
					}
					if v.IsMethodExprCall && v.Recv != nil {
						walkValue(v.Recv)
					}
					for i, a := range v.Args {
						if deferredArgs[i] {
							continue
						}
						walkCallArg(a)
					}
					return

				case flowir.CallMethod:
					if !v.IsMethodExprCall && v.Selection != nil && v.Selection.Kind() == types.MethodVal && v.CalleeFunc != nil {
						fn := v.CalleeFunc
						sel := v.CalleeSelector()
						if refconfine.AuditedPooling(audited, fn) && v.HasRecvPlace {
							if poolPos, poolVar, isBarePool := poolCarrierPlace(v.RecvPlace); poolVar != nil {
								v.RecvPlace.ForEachChildValue(func(cv *flowir.Value) bool {
									walkValue(cv)
									return true
								})
								for _, a := range v.Args {
									walkCallArg(a)
								}
								dischargePool(poolVar)
								if sel == nil || !provenCalls[sel] {
									if _, vOK := dynamicPackageVar(poolVar); vOK {
										key := syntaxutil.DynamicVarKey(poolVar)
										if methodUses != nil && isBarePool && !syntaxutil.InterfaceReceiver(fn) &&
											refconfine.InstantiatedResultsHandOutNothing(audited, v.Selection.Type()) && sel != nil {
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
												syntaxutil.ExplainDeferralMark(hooks, p, 'm', key, syntaxutil.DeferralResolvent{
													Method:      factKey,
													EnclosingFn: currentDeferFn,
													Literal:     currentDeferLit,
												}, sel.Pos())
											}
										} else {
											if sig, sigOK := fn.Type().(*types.Signature); sigOK && sig.Recv() != nil {
												if _, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer); ptr {
													if !singleSubject {
														syntaxutil.ExplainAttributedMark(hooks, p, "mutation", key, currentDeferFn, currentDeferLit, poolPos)
													}
													if poolMutated != nil {
														poolMutated[key] = true
													}
												}
											}
											if refconfine.TypeHandsOutDynamicAlias(audited, poolVar.Type()) {
												if !singleSubject {
													syntaxutil.ExplainMark(hooks, p, "escape", key, poolPos)
												}
												if poolEscaped != nil {
													poolEscaped[key] = true
												}
											}
										}
									}
								}
								return
							}
						}
						if refconfine.DataMemoMethod(audited, fn) && v.HasRecvPlace && v.RecvPlace.IsBareVar() && dataMemos[v.RecvPlace.Obj] {
							for _, a := range v.Args {
								walkValue(a)
							}
							return
						}
						if sel != nil && exemptSeamNodes[sel] {
							if !(v.HasRecvPlace && v.RecvPlace.IsBareVar()) {
								walkValue(v.Recv)
							}
							for _, a := range v.Args {
								walkValue(a)
							}
							return
						}
						if methodUses != nil && !syntaxutil.InterfaceReceiver(fn) &&
							refconfine.InstantiatedResultsHandOutNothing(audited, v.Selection.Type()) &&
							v.HasRecvPlace && v.RecvPlace.IsBareVar() && sel != nil {
							if variable, vOK := dynamicPackageVar(v.RecvPlace.Obj); vOK {
								key := syntaxutil.DynamicVarKey(variable)
								if methodUses[key] == nil {
									methodUses[key] = map[syntaxutil.FuncKey]bool{}
								}
								factKey := syntaxutil.MethodFactKey(fn)
								methodUses[key][factKey] = true
								syntaxutil.ExplainDeferralMark(hooks, p, 'm', key, syntaxutil.DeferralResolvent{
									Method:      factKey,
									EnclosingFn: currentDeferFn,
									Literal:     currentDeferLit,
								}, sel.Pos())
								for _, a := range v.Args {
									walkCallArg(a)
								}
								return
							}
						}
						if sig, sigOK := fn.Type().(*types.Signature); sigOK && sig.Recv() != nil {
							if _, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer); ptr {
								markPtrRecvMutated(v.Recv, v.AutoAddrRecv)
								markRecvValueEscaped(v.Recv)
							}
						}
					}
					walkValue(v.Recv)
					for _, a := range v.Args {
						walkCallArg(a)
					}
					return

				case flowir.CallIndirect:
					var deferredArgs map[int]bool
					if elemUses != nil && !inGoOp && v.Callee != nil && v.Callee.Kind == flowir.ValPlace &&
						len(v.Callee.Place.Projs) == 1 && v.Callee.Place.Projs[0].Kind == flowir.ProjIndex &&
						v.Callee.Place.Obj != nil && v.CalleeSig != nil {
						if owner, ok := dynamicPackageVar(v.Callee.Place.Obj); ok {
							ownerKey := syntaxutil.DynamicVarKey(owner)
							for i, arg := range v.Args {
								argPos, variable := carrierArgVar(arg)
								if variable == nil {
									continue
								}
								idx := i
								if v.CalleeSig.Variadic() && idx >= v.CalleeSig.Params().Len()-1 {
									idx = v.CalleeSig.Params().Len() - 1
								}
								argKey := syntaxutil.DynamicVarKey(variable)
								want := syntaxutil.ElemParamUse{Key: argKey, Owner: ownerKey, Index: idx}
								if elemUses[argKey] == nil {
									elemUses[argKey] = map[syntaxutil.ElemParamUse]bool{}
								}
								elemUses[argKey][want] = true
								if arg.Raw != nil {
									argPos = arg.Raw.Pos()
								}
								syntaxutil.ExplainDeferralMark(hooks, p, 'e', argKey, syntaxutil.DeferralResolvent{ElemUse: want}, argPos)
								if deferredArgs == nil {
									deferredArgs = map[int]bool{}
								}
								deferredArgs[i] = true
							}
						}
					}
					walkValue(v.Callee)
					for i, a := range v.Args {
						if deferredArgs[i] {
							continue
						}
						walkValue(a)
					}
					return
				}
			}

			v.ForEachChildValue(func(ch *flowir.Value) bool {
				walkValue(ch)
				return true
			})
		}

		b.ForEachSyncOp(func(op *flowir.Op) bool {
			switch op.Kind {
			case flowir.OpAssign:
				if op.AssignKind == flowir.AssignRange {
					for i, dst := range op.Dsts {
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							walkValue(cv)
							return true
						})
						if !(i < len(op.DstDefs) && op.DstDefs[i] && dst.IsBareVar()) {
							markPlaceMutated(dst, false)
						}
					}
					var rngSrc *flowir.Value
					if len(op.Srcs) > 0 {
						rngSrc = op.Srcs[0]
					}
					if rngSrc != nil && rngSrc.Type != nil {
						t := rngSrc.Type
						if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
							markValueMutated(rngSrc, true)
							walkValue(rngSrc)
							return true
						}
						if (!refconfine.RangeBindsAlias(t) && !refconfine.TypeReachesSyncNoCopyByValue(t)) || len(op.Dsts) == 0 {
							if rngSrc.Kind == flowir.ValPlace && len(rngSrc.Place.Projs) == 0 {
								return true
							}
							walkValue(rngSrc)
							return true
						}
						rngStmt, _ := op.StmtAST.(*ast.RangeStmt)
						if rngStmt != nil && rngStmt.Tok == token.DEFINE && op.RangeBody != nil {
							roots := map[types.Object]bool{}
							sound := true
							for i, dst := range op.Dsts {
								if dst.IsBlank() {
									continue
								}
								if !dst.IsBareVar() || dst.Obj == nil || i >= len(op.DstDefs) || !op.DstDefs[i] {
									sound = false
									break
								}
								if refconfine.TypeReachesSyncNoCopyByValue(dst.Obj.Type()) {
									sound = false
									break
								}
								if refconfine.TypeHandsOutMutableReach(dst.Obj.Type()) || syntaxutil.ContainsUintptr(dst.Obj.Type()) {
									roots[dst.Obj] = true
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
								if currentFn != nil && currentFn.Recv == nil && currentFn.Name != nil &&
									!currentFn.Name.IsExported() && currentFn.Name.Name != "init" {
									retPtr = &returned
								}
							}
							if sound && (len(roots) == 0 || boundValueLeakFreeJudged(audited, p, fc, roots, rngStmt.Body, wants, retPtr, methodWants, fieldWants, elemWants)) {
								markRangeBoundObjs := func() {
									for _, dst := range op.Dsts {
										if dst.IsBareVar() && dst.Obj != nil && roots[dst.Obj] {
											if judgedRangeVars == nil {
												judgedRangeVars = map[types.Object]bool{}
												activeJudgedRangeVars = judgedRangeVars
											}
											judgedRangeVars[dst.Obj] = true
										}
									}
								}
								if len(wants) == 0 && len(methodWants) == 0 && len(fieldWants) == 0 && len(elemWants) == 0 && !returned {
									markRangeBoundObjs()
									if rngSrc.Kind == flowir.ValPlace && len(rngSrc.Place.Projs) == 0 {
										return true
									}
									walkValue(rngSrc)
									return true
								}
								srcVars := collectValueCarrierVars(audited, rngSrc, dynamicPackageVar, aliasedLocals, isExemptMethodRecvCall)
								if rngSrc.Kind == flowir.ValPlace && rngSrc.Place.Obj != nil {
									if cv, ok := dynamicPackageVar(rngSrc.Place.Obj); ok {
										appendUniqueVars(&srcVars, []*types.Var{cv})
									}
								}
								if len(srcVars) > 0 {
									var rngPos token.Pos
									if rngSrc.Raw != nil {
										rngPos = rngSrc.Raw.Pos()
									}
									keys := make([]string, 0, len(srcVars))
									for _, sv := range srcVars {
										keys = append(keys, syntaxutil.DynamicVarKey(sv))
									}
									for _, key := range keys {
										recordConfinementSinkUses(key, wants, methodWants, fieldWants, elemWants, currentDeferFn, currentDeferLit, rngPos)
									}
									if returned {
										pendingReturns = append(pendingReturns, pendingReturnDisposition{
											fn:     currentFn.Name.Name,
											keys:   keys,
											attrFn: currentAttrFn,
											pos:    rngPos,
										})
									}
									markRangeBoundObjs()
									if rngSrc.Kind == flowir.ValPlace && len(rngSrc.Place.Projs) == 0 {
										return true
									}
									rngSrc.ForEachChildValue(func(cv *flowir.Value) bool {
										walkValue(cv)
										return true
									})
									return true
								}
							}
						}
					}
					walkValue(rngSrc)
					return true
				}

				if op.AssignKind == flowir.AssignZeroDecl {
					return true
				}
				for _, dst := range op.Dsts {
					dst.ForEachChildValue(func(cv *flowir.Value) bool {
						walkValue(cv)
						return true
					})
					if dst.Raw != nil && exemptSeamNodes[dst.Raw] {
						continue
					}
					if dst.IsBareVar() && syntaxutil.IsLocalVar(dst.Obj) {
						continue
					}
					markPlaceMutated(dst, false)
				}
				if op.AssignKind == flowir.AssignIncDec {
					return true
				}
				if op.AssignKind == flowir.AssignCompound {
					for _, src := range op.Srcs {
						if src != nil && src.Kind == flowir.ValCompositeExpr && len(src.Args) == 2 {
							walkValue(src.Args[1])
						} else {
							walkValue(src)
						}
					}
					return true
				}
				if op.AssignKind == flowir.AssignMulti && len(op.Dsts) == 2 && len(op.Srcs) == 1 && op.Dsts[0].IsBlank() {
					src := op.Srcs[0]
					if src != nil && src.Kind == flowir.ValPlace && len(src.Place.Projs) == 1 && src.Place.Projs[0].Kind == flowir.ProjIndex {
						src.Place.ForEachChildValue(func(cv *flowir.Value) bool {
							walkValue(cv)
							return true
						})
						return true
					}
				}
				for i, src := range op.Srcs {
					if op.AssignKind == flowir.AssignPlain && i < len(op.Dsts) &&
						op.Dsts[i].IsBareVar() && (op.Dsts[i].IsBlank() || op.Dsts[i].Root == flowir.RootLocal) &&
						src != nil && src.Kind == flowir.ValAddrOf {
						prevLocalAddr := allowLocalAddrBind
						allowLocalAddrBind = true
						walkValue(src)
						allowLocalAddrBind = prevLocalAddr
						continue
					}
					walkValue(src)
				}

			case flowir.OpTypeSwitchBind:
				if op.CaseAST == nil {
					walkValue(op.SwitchSrc)
				}

			case flowir.OpChanSend:
				op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
					walkValue(cv)
					return true
				})
				markPlaceMutated(op.ChanPlace, true)
				if op.ChanPlace.Obj == nil && op.ChanPlace.Root != flowir.RootTransient {
					walkValue(op.ChanVal)
				}
				walkValue(op.SendVal)

			case flowir.OpReturn:
				for _, r := range op.Results {
					walkValue(r)
				}

			case flowir.OpDefer:
				walkValue(op.Call)

			case flowir.OpGo:
				if descendNested {
					prevGo := inGoOp
					inGoOp = true
					walkValue(op.Call)
					inGoOp = prevGo
				}

			case flowir.OpExpr:
				walkValue(op.Expr)
			}
			return true
		})
	}

	if len(initOnlyParams) != 0 {
		seedingPass = true
		for {
			paramSeedGrowth = false
			for _, file := range p.Syntax {
				if file == nil {
					continue
				}
				for _, decl := range file.Decls {
					switch decl := decl.(type) {
					case *ast.FuncDecl:
						if decl.Recv == nil && decl.Name != nil && decl.Body != nil && (decl.Name.Name == "init" || initOnly[decl.Name.Name]) {
							initAliasedLocals(fc.funcBody(p, decl))
						}
					case *ast.GenDecl:
						if decl.Tok == token.VAR || decl.Tok == token.CONST {
							initAliasedLocals(fc.body(p, decl))
						}
					}
				}
			}
			if !paramSeedGrowth {
				break
			}
		}
		seedingPass = false
	}

	flushScopeUses := func(
		fnKey syntaxutil.FuncKey,
		literal bool,
		scopeMut, scopeEsc map[string]bool,
		scopeMethods map[string]map[syntaxutil.FuncKey]bool,
		scopeParams map[string]map[syntaxutil.ParamKey]bool,
		scopePoolMut, scopePoolEsc map[string]bool,
		scopePoolMethods map[string]map[syntaxutil.FuncKey]bool,
	) {
		for key := range scopeMut {
			*attributed = append(*attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Literal: literal})
		}
		for key := range scopeEsc {
			*attributed = append(*attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Escape: true, Literal: literal})
		}
		for key, methods := range scopeMethods {
			for m := range methods {
				*attributed = append(*attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: m, Literal: literal})
			}
		}
		if attributedParams != nil {
			for key, params := range scopeParams {
				for pk := range params {
					*attributedParams = append(*attributedParams, syntaxutil.VarParamUse{Key: key, Param: pk, Func: fnKey, Literal: literal})
				}
			}
		} else if paramUses != nil {
			for key, params := range scopeParams {
				if paramUses[key] == nil {
					paramUses[key] = map[syntaxutil.ParamKey]bool{}
				}
				for pk := range params {
					paramUses[key][pk] = true
				}
			}
		}
		if poolAttributed != nil {
			for key := range scopePoolMut {
				*poolAttributed = append(*poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Literal: literal})
			}
			for key := range scopePoolEsc {
				*poolAttributed = append(*poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Escape: true, Literal: literal})
			}
			for key, methods := range scopePoolMethods {
				for m := range methods {
					*poolAttributed = append(*poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: m, Literal: literal})
				}
			}
		} else {
			if poolMutated != nil {
				for key := range scopePoolMut {
					poolMutated[key] = true
				}
				for key := range scopePoolMethods {
					poolMutated[key] = true
				}
			}
			if poolEscaped != nil {
				for key := range scopePoolEsc {
					poolEscaped[key] = true
				}
			}
		}
	}

	walkAttributedDecl := func(decl *ast.FuncDecl, fnKey syntaxutil.FuncKey, setCurrentFn bool) {
		b := fc.funcBody(p, decl)
		if b == nil {
			return
		}
		declAliases, _ := computeBodyCarrierAliases(audited, fc, b, carrierAliasConfig{
			parentAliases:       aliasedLocals,
			carrierVar:          dynamicPackageVar,
			skipMethodRecv:      isExemptMethodRecvCall,
			skipNonBuiltinCalls: true,
			descendNested:       true,
		})
		prevAliases := aliasedLocals
		prevPrecomp := precomputedDeclAliases
		aliasedLocals = declAliases
		precomputedDeclAliases = true
		defer func() {
			aliasedLocals = prevAliases
			precomputedDeclAliases = prevPrecomp
		}()

		runScopedPass := func(literal bool, exec func()) {
			scMut, scEsc := map[string]bool{}, map[string]bool{}
			scPoolMut, scPoolEsc := map[string]bool{}, map[string]bool{}
			scPoolMethods := map[string]map[syntaxutil.FuncKey]bool{}
			scMethods := map[string]map[syntaxutil.FuncKey]bool{}
			var scParams map[string]map[syntaxutil.ParamKey]bool
			if paramUses != nil {
				scParams = map[string]map[syntaxutil.ParamKey]bool{}
			}
			saveM, saveE, saveMU, savePU := mutated, escaped, methodUses, paramUses
			savePM, savePE, savePMU := poolMutated, poolEscaped, poolMethods
			mutated, escaped, methodUses, paramUses = scMut, scEsc, scMethods, scParams
			poolMutated, poolEscaped, poolMethods = scPoolMut, scPoolEsc, scPoolMethods
			if fnKey.Valid() {
				currentDeferFn, currentDeferLit = fnKey, literal
			}
			exec()
			currentDeferFn, currentDeferLit = syntaxutil.FuncKey{}, false
			mutated, escaped, methodUses, paramUses = saveM, saveE, saveMU, savePU
			poolMutated, poolEscaped, poolMethods = savePM, savePE, savePMU
			flushScopeUses(fnKey, literal, scMut, scEsc, scMethods, scParams, scPoolMut, scPoolEsc, scPoolMethods)
		}

		// Pass 1: nested closures (ValMakeClosure / CallIIFE) and OpGo statements -> Literal: true.
		runScopedPass(true, func() {
			forEachNestedLiteralAndGo(b, func(litBody *flowir.Body) {
				walkBody(litBody, true)
			}, func(goOp *flowir.Op) {
				goBody := &flowir.Body{AST: goOp.StmtAST, Ops: []flowir.Op{*goOp}}
				walkBody(goBody, true)
			})
		})

		// Pass 2: synchronous operations in decl.Body only -> Literal: false.
		runScopedPass(false, func() {
			if setCurrentFn {
				currentFn = decl
				currentAttrFn = fnKey
			}
			walkBody(b, false)
			if setCurrentFn {
				currentFn = nil
				currentAttrFn = syntaxutil.FuncKey{}
			}
		})
	}

	for _, file := range p.Syntax {
		if file == nil {
			continue
		}
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
				if decl.Recv == nil && decl.Name != nil && attributed != nil && !initOnly[decl.Name.Name] &&
					decl.Name.Name != "init" && decl.Name.Name != "_" && decl.Body != nil && p.Types != nil {
					fnKey := syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: decl.Name.Name}
					walkAttributedDecl(decl, fnKey, true)
					continue
				}
				if decl.Recv == nil && decl.Name != nil && (decl.Name.Name == "init" || initOnly[decl.Name.Name]) {
					if decl.Body != nil {
						b := fc.funcBody(p, decl)
						aliasedLocals = initAliasedLocals(b)
						forEachNestedLiteralAndGo(b, func(litBody *flowir.Body) {
							walkBody(litBody, true)
						}, func(goOp *flowir.Op) {
							goBody := &flowir.Body{AST: goOp.StmtAST, Ops: []flowir.Op{*goOp}}
							walkBody(goBody, true)
						})
						scanExemptCalls(b)
						aliasedLocals = nil
					}
					continue
				}
				if decl.Body != nil {
					b := fc.funcBody(p, decl)
					declAliases, _ := computeBodyCarrierAliases(audited, fc, b, carrierAliasConfig{
						parentAliases:       aliasedLocals,
						carrierVar:          dynamicPackageVar,
						skipMethodRecv:      isExemptMethodRecvCall,
						skipNonBuiltinCalls: true,
						descendNested:       true,
					})
					prevAliases := aliasedLocals
					prevPrecomp := precomputedDeclAliases
					aliasedLocals = declAliases
					precomputedDeclAliases = true
					currentFn = decl
					walkBody(b, true)
					currentFn = nil
					aliasedLocals = prevAliases
					precomputedDeclAliases = prevPrecomp
				}
			case *ast.GenDecl:
				if decl.Tok == token.VAR || decl.Tok == token.CONST {
					b := fc.body(p, decl)
					aliasedLocals = initAliasedLocals(b)
					forEachNestedLiteralAndGo(b, func(litBody *flowir.Body) {
						walkBody(litBody, true)
					}, nil)
					scanExemptCalls(b)
					aliasedLocals = nil
				} else {
					// Fail closed on any alias-handing dynamic package global referenced inside a type declaration.
					ast.Inspect(decl, func(n ast.Node) bool {
						if id, ok := n.(*ast.Ident); ok {
							if obj, uOK := p.TypesInfo.Uses[id]; uOK {
								if variable, dOK := dynamicPackageVar(obj); dOK && refconfine.TypeHandsOutDynamicAlias(audited, variable.Type()) {
									markEscapedVars([]*types.Var{variable}, id.Pos())
								}
							}
						}
						return true
					})
				}
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
			if file == nil {
				continue
			}
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

			checkTrackedCall := func(v *flowir.Value) (string, *types.Signature, bool) {
				if v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallPlain || v.IsMethodExprCall || v.CalleeFunc == nil {
					return "", nil, false
				}
				orig := v.CalleeFunc.Origin()
				fnName, tracked := returnerObjs[orig]
				if !tracked || !frontierSet[fnName] {
					return "", nil, false
				}
				sig, ok := orig.Type().(*types.Signature)
				if !ok {
					bad[fnName] = true
					return "", nil, false
				}
				return fnName, sig, true
			}

			var scanSites func(rootNode ast.Node, rootBody *flowir.Body, siteName string, siteEligible, topGenDecl bool)
			scanSites = func(rootNode ast.Node, rootBody *flowir.Body, siteName string, siteEligible, topGenDecl bool) {
				if rootBody == nil {
					return
				}
				var walkScope func(b *flowir.Body, inLit bool)
				var scanExpr func(v *flowir.Value, inLit bool)
				scanExpr = func(v *flowir.Value, inLit bool) {
					if v == nil {
						return
					}
					switch v.Kind {
					case flowir.ValMakeClosure:
						if v.Closure != nil {
							if topGenDecl && v.Lit != nil && v.Lit.Body != nil {
								scanSites(v.Lit.Body, v.Closure, "", false, false)
							} else {
								walkScope(v.Closure, true)
							}
						}
						return
					case flowir.ValCall:
						if v.CallKind == flowir.CallIIFE {
							for _, a := range v.Args {
								scanExpr(a, inLit)
							}
							if v.IIFE != nil {
								if topGenDecl && v.IIFE.Block != nil {
									scanSites(v.IIFE.Block, v.IIFE, "", false, false)
								} else {
									walkScope(v.IIFE, true)
								}
							}
							return
						}
						if fnName, _, ok := checkTrackedCall(v); ok {
							bad[fnName] = true
							for _, a := range v.Args {
								scanExpr(a, inLit)
							}
							return
						}
					case flowir.ValPlace:
						if v.Place.Root == flowir.RootFunc && v.Place.Func != nil {
							if fnName, tracked := returnerObjs[v.Place.Func.Origin()]; tracked && frontierSet[fnName] {
								bad[fnName] = true
							}
						}
					}
					v.ForEachChildValue(func(ch *flowir.Value) bool {
						scanExpr(ch, inLit)
						return true
					})
				}

				handleAssignCall := func(op *flowir.Op, callVal *flowir.Value, fnName string, sig *types.Signature, inLit bool) {
					for _, dst := range op.Dsts {
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							scanExpr(cv, inLit)
							return true
						})
					}
					for _, a := range callVal.Args {
						scanExpr(a, inLit)
					}
					results := sig.Results()
					if results == nil || results.Len() != len(op.Dsts) {
						bad[fnName] = true
						return
					}
					roots := map[types.Object]bool{}
					for i, dst := range op.Dsts {
						if dst.IsBlank() {
							continue
						}
						if !dst.IsBareVar() || dst.Obj == nil {
							bad[fnName] = true
							return
						}
						if refconfine.TypeHandsOutMutableReach(results.At(i).Type()) || syntaxutil.ContainsUintptr(results.At(i).Type()) {
							roots[dst.Obj] = true
						}
					}
					if len(roots) == 0 {
						return
					}
					if topGenDecl || rootNode == nil {
						bad[fnName] = true
						return
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
					if !boundValueLeakFreeJudged(audited, p, fc, roots, rootNode, siteWants, siteRet, siteMethodWants, siteFieldWants, siteElemWants) {
						bad[fnName] = true
						return
					}
					var callPos token.Pos
					if callVal.CallAST != nil {
						callPos = callVal.CallAST.Pos()
					}
					for key := range returnerKeys[fnName] {
						recordConfinementSinkUses(key, siteWants, siteMethodWants, siteFieldWants, siteElemWants, syntaxutil.FuncKey{}, false, callPos)
					}
					if siteReturned {
						if mergeKeys(siteName, returnerKeys[fnName]) {
							scanned[siteName] = false
						}
						depend(fnName, siteName)
					}
				}

				walkScope = func(b *flowir.Body, inLit bool) {
					if b == nil {
						return
					}
					b.ForEachSyncOp(func(op *flowir.Op) bool {
						switch op.Kind {
						case flowir.OpExpr:
							if !topGenDecl {
								if _, _, ok := checkTrackedCall(op.Expr); ok {
									for _, a := range op.Expr.Args {
										scanExpr(a, inLit)
									}
									return true
								}
							}
							scanExpr(op.Expr, inLit)
						case flowir.OpDefer, flowir.OpGo:
							if !topGenDecl {
								if _, _, ok := checkTrackedCall(op.Call); ok {
									for _, a := range op.Call.Args {
										scanExpr(a, inLit)
									}
									return true
								}
							}
							scanExpr(op.Call, inLit)
						case flowir.OpReturn:
							for _, res := range op.Results {
								if fnName, _, ok := checkTrackedCall(res); ok {
									if !topGenDecl && siteEligible && !inLit {
										if mergeKeys(siteName, returnerKeys[fnName]) {
											scanned[siteName] = false
										}
										depend(fnName, siteName)
									} else {
										bad[fnName] = true
									}
									for _, a := range res.Args {
										scanExpr(a, inLit)
									}
								} else {
									scanExpr(res, inLit)
								}
							}
						case flowir.OpAssign:
							if (op.AssignKind == flowir.AssignPlain || op.AssignKind == flowir.AssignMulti) && len(op.Srcs) == 1 {
								if fnName, sig, ok := checkTrackedCall(op.Srcs[0]); ok {
									handleAssignCall(op, op.Srcs[0], fnName, sig, inLit)
									return true
								}
							}
							forEachOpTopValues(op, func(v *flowir.Value) {
								scanExpr(v, inLit)
							})
						default:
							forEachOpTopValues(op, func(v *flowir.Value) {
								scanExpr(v, inLit)
							})
						}
						return true
					})
				}

				walkScope(rootBody, false)
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
				if file == nil {
					continue
				}
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
						scanSites(decl.Body, fc.funcBody(p, decl), name, eligible, false)
					case *ast.GenDecl:
						if !hasTopLevelValueUse {
							continue
						}
						if decl.Tok == token.VAR || decl.Tok == token.CONST {
							scanSites(nil, fc.body(p, decl), "", false, true)
						} else {
							ast.Inspect(decl, func(n ast.Node) bool {
								if id, ok := n.(*ast.Ident); ok {
									if obj := p.TypesInfo.Uses[id]; obj != nil {
										if fnName, tracked := returnerObjs[obj]; tracked && frontierSet[fnName] {
											bad[fnName] = true
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
