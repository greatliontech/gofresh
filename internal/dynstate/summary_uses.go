package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type pendingReturnDisposition struct {
	fn     string
	keys   []string
	attrFn syntaxutil.FuncKey
	pos    token.Pos
}

// useSinkScope holds the active mutation, escape, and deferral sink maps for a
// package or attributed function/closure pass, eliminating formal-parameter
// pointer swapping during scoped passes.
type useSinkScope struct {
	mutated     map[string]bool
	escaped     map[string]bool
	methodUses  map[string]map[syntaxutil.FuncKey]bool
	paramUses   map[string]map[syntaxutil.ParamKey]bool
	poolMutated map[string]bool
	poolEscaped map[string]bool
	poolMethods map[string]map[syntaxutil.FuncKey]bool
}

// globalUseScanner classifies mutations, escapes, attributed uses,
// parameter/method/field/element deferrals, pool uses, and init-flow carrier
// storage links across a package using pre-lowered flowir.Body representations.
type globalUseScanner struct {
	audited          bool
	p                *packages.Package
	fc               *pkgFlowCache
	idx              *refconfine.PkgIndex
	callIdx          *refconfine.CallSiteIndex
	exemptSeamNodes  map[ast.Node]bool
	initOnly         map[string]bool
	initParamUses    map[string]map[syntaxutil.ParamKey]bool
	initMethodUses   map[string]map[syntaxutil.FuncKey]bool
	fieldUses        map[string]map[syntaxutil.FieldPosKey]bool
	elemUses         map[string]map[syntaxutil.ElemParamUse]bool
	carrierLinks     map[string]map[string]bool
	attributed       *[]syntaxutil.AttributedUse
	attributedParams *[]syntaxutil.VarParamUse
	singleSubject    bool
	poolDischarged   map[string]bool
	poolAttributed   *[]syntaxutil.AttributedUse
	hooks            *syntaxutil.ExplainHookSet
	sink             useSinkScope

	dataMemos              map[*types.Var]bool
	provenCalls            map[*ast.SelectorExpr]bool
	initOnlyParams         map[*types.Func][]types.Object
	paramSeeds             map[types.Object]localCarrierAliases
	paramLinkSeeds         map[types.Object][]*types.Var
	paramSeedGrowth        bool
	seedingPass            bool
	aliasedLocals          map[types.Object]localCarrierAliases
	precomputedDeclAliases bool
	activeJudgedRangeVars  map[types.Object]bool
	currentFn              *ast.FuncDecl
	currentAttrFn          syntaxutil.FuncKey
	currentDeferFn         syntaxutil.FuncKey
	currentDeferLit        bool
	inGoOp                 bool
	pendingReturns         []pendingReturnDisposition
}

func (s *globalUseScanner) scanPackage() {
	if s.p == nil || s.p.TypesInfo == nil {
		return
	}
	if s.fc == nil {
		s.fc = newPkgFlowCache(s.audited, s.p)
	}
	if s.callIdx == nil {
		s.callIdx = refconfine.BuildCallSiteIndex(s.p)
	}
	s.dataMemos = dataMemoVars(s.audited, s.p, s.fc, s.callIdx)
	_, s.provenCalls = provenSharedPools(s.audited, s.p, s.fc)
	s.initOnlyParams = s.callIdx.FuncParamsOf(s.initOnly)
	s.paramSeeds = map[types.Object]localCarrierAliases{}
	s.paramLinkSeeds = map[types.Object][]*types.Var{}

	if len(s.initOnlyParams) != 0 {
		s.seedingPass = true
		for {
			s.paramSeedGrowth = false
			for _, file := range s.p.Syntax {
				if file == nil {
					continue
				}
				for _, decl := range file.Decls {
					switch decl := decl.(type) {
					case *ast.FuncDecl:
						if decl.Recv == nil && decl.Name != nil && decl.Body != nil && (decl.Name.Name == "init" || s.initOnly[decl.Name.Name]) {
							s.initAliasedLocals(s.fc.funcBody(s.p, decl))
						}
					case *ast.GenDecl:
						if decl.Tok == token.VAR || decl.Tok == token.CONST {
							s.initAliasedLocals(s.fc.body(s.p, decl))
						}
					}
				}
			}
			if !s.paramSeedGrowth {
				break
			}
		}
		s.seedingPass = false
	}

	s.scanDecls()
	s.resolvePendingReturns()
}

func (s *globalUseScanner) dynamicPackageVar(obj types.Object) (*types.Var, bool) {
	variable, ok := obj.(*types.Var)
	if !ok || variable == nil || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
		return nil, false
	}
	if !refconfine.TypeMayCarryUnknownDynamic(s.audited, variable.Type()) {
		return nil, false
	}
	return variable, true
}

func (s *globalUseScanner) markMutatedVars(vars []*types.Var, pos token.Pos) {
	for _, v := range vars {
		if v == nil {
			continue
		}
		key := syntaxutil.DynamicVarKey(v)
		syntaxutil.ExplainAttributedMark(s.hooks, s.p, "mutation", key, s.currentDeferFn, s.currentDeferLit, pos)
		s.sink.mutated[key] = true
	}
}

func (s *globalUseScanner) markEscapedVars(vars []*types.Var, pos token.Pos) {
	for _, v := range vars {
		if v == nil {
			continue
		}
		key := syntaxutil.DynamicVarKey(v)
		syntaxutil.ExplainMark(s.hooks, s.p, "escape", key, pos)
		s.sink.escaped[key] = true
	}
}

func poolCarrierPlace(pl flowir.Place) (token.Pos, *types.Var, bool) {
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

func (s *globalUseScanner) isExemptMethodRecvCall(v *flowir.Value) bool {
	if v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallMethod || v.IsMethodExprCall ||
		v.Selection == nil || v.Selection.Kind() != types.MethodVal || v.CalleeFunc == nil {
		return false
	}
	fn := v.CalleeFunc
	if refconfine.AuditedPooling(s.audited, fn) && v.HasRecvPlace {
		if _, poolVar, _ := poolCarrierPlace(v.RecvPlace); poolVar != nil {
			return true
		}
	}
	if refconfine.DataMemoMethod(s.audited, fn) && v.HasRecvPlace && v.RecvPlace.IsBareVar() && s.dataMemos[v.RecvPlace.Obj] {
		return true
	}
	if sel := v.CalleeSelector(); sel != nil && s.exemptSeamNodes[sel] && v.HasRecvPlace && v.RecvPlace.IsBareVar() {
		return true
	}
	return false
}

func (s *globalUseScanner) markPlaceMutated(pl flowir.Place, writeContainer bool) {
	if pl.Root == flowir.RootBlank {
		return
	}
	if pl.Obj != nil {
		if s.activeJudgedRangeVars[pl.Obj] {
			return
		}
		if variable, ok := s.dynamicPackageVar(pl.Obj); ok {
			s.markMutatedVars([]*types.Var{variable}, pl.RootPos)
			return
		}
		entry := s.aliasedLocals[pl.Obj]
		vars := entry.root
		if flowir.PlaceEntersInterior(pl, writeContainer) {
			vars = entry.all
		}
		s.markMutatedVars(vars, pl.RootPos)
		return
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil {
		vars := collectValueCarrierVars(s.audited, pl.Base, s.dynamicPackageVar, s.aliasedLocals, s.isExemptMethodRecvCall)
		s.markMutatedVars(vars, pl.RootPos)
	}
}

func (s *globalUseScanner) markValueMutated(v *flowir.Value, writeContainer bool) {
	if v == nil {
		return
	}
	switch v.Kind {
	case flowir.ValPlace:
		s.markPlaceMutated(v.Place, writeContainer)
	case flowir.ValAddrOf:
		s.markPlaceMutated(v.AddrPlace, false)
	default:
		var walk func(cur *flowir.Value)
		walk = func(cur *flowir.Value) {
			if cur == nil || cur.Kind == flowir.ValMakeClosure {
				return
			}
			if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallIIFE {
				flowir.ForEachIIFEReturnValue(cur, walk)
				return
			}
			if cur.Kind == flowir.ValPlace {
				s.markPlaceMutated(cur.Place, writeContainer)
				return
			}
			if cur.Kind == flowir.ValAddrOf {
				s.markPlaceMutated(cur.AddrPlace, false)
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

func (s *globalUseScanner) markPtrRecvMutated(recv *flowir.Value, autoAddr bool) {
	if recv == nil {
		return
	}
	if autoAddr {
		s.markValueMutated(recv, false)
		return
	}
	var walk func(cur *flowir.Value)
	walk = func(cur *flowir.Value) {
		if cur == nil || cur.Kind == flowir.ValMakeClosure {
			return
		}
		if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallIIFE {
			flowir.ForEachIIFEReturnValue(cur, walk)
			return
		}
		if cur.Kind == flowir.ValPlace {
			derefPl := cur.Place
			derefPl.Projs = append(append([]flowir.Proj(nil), derefPl.Projs...), flowir.Proj{
				Kind:     flowir.ProjDeref,
				BaseType: cur.Type,
			})
			s.markPlaceMutated(derefPl, false)
			return
		}
		if cur.Kind == flowir.ValAddrOf {
			s.markPlaceMutated(cur.AddrPlace, false)
			return
		}
		cur.ForEachChildValue(func(ch *flowir.Value) bool {
			walk(ch)
			return true
		})
	}
	walk(recv)
}

func (s *globalUseScanner) initAliasedLocals(b *flowir.Body) map[types.Object]localCarrierAliases {
	cfg := carrierAliasConfig{
		parentAliases:  s.paramSeeds,
		parentLinks:    s.paramLinkSeeds,
		carrierVar:     s.dynamicPackageVar,
		skipMethodRecv: s.isExemptMethodRecvCall,
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
			params := s.initOnlyParams[callVal.CalleeFunc.Origin()]
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
				if !canAliasCarrierType(s.audited, gateType) && !isTypeParamType(gateType) {
					return true
				}
				rootSrcs, allSrcs := valSources(arg)
				if packedVariadic {
					rootSrcs = nil
				}
				entry := s.paramSeeds[param]
				if len(rootSrcs) > 0 && (syntaxutil.IsRefHeaderType(param.Type()) || isTypeParamType(param.Type())) {
					if appendUniqueVars(&entry.root, rootSrcs) {
						s.paramSeedGrowth = true
					}
					if appendUniqueVars(&entry.all, rootSrcs) {
						s.paramSeedGrowth = true
					}
				}
				if appendUniqueVars(&entry.all, allSrcs) {
					s.paramSeedGrowth = true
				}
				if len(entry.root) > 0 || len(entry.all) > 0 {
					s.paramSeeds[param] = entry
				}
				lvars := valLinks(arg)
				if len(lvars) > 0 {
					curLinks := s.paramLinkSeeds[param]
					if appendUniqueVars(&curLinks, lvars) {
						s.paramLinkSeeds[param] = curLinks
						s.paramSeedGrowth = true
					}
				}
				return true
			})
		},
	}
	if !s.seedingPass {
		if s.carrierLinks != nil {
			cfg.onCarrierLink = func(own, target *types.Var) {
				ownKey := syntaxutil.DynamicVarKey(own)
				targetKey := syntaxutil.DynamicVarKey(target)
				if ownKey == targetKey {
					return
				}
				if s.carrierLinks[ownKey] == nil {
					s.carrierLinks[ownKey] = map[string]bool{}
				}
				s.carrierLinks[ownKey][targetKey] = true
			}
		}
		cfg.onNonCarrierPkgBind = func(pkgVar *types.Var, pos token.Pos, composite bool, allVars, linkVars []*types.Var) {
			if composite || refconfine.CallResultHandsOut(pkgVar.Type()) {
				s.markEscapedVars(linkVars, pos)
				s.markEscapedVars(allVars, pos)
			}
		}
		cfg.onParamCompositeBind = func(pos token.Pos, allVars, linkVars []*types.Var) {
			s.markEscapedVars(linkVars, pos)
			s.markEscapedVars(allVars, pos)
		}
		cfg.onRHSMethodValue = func(mv *flowir.Value, aliases map[types.Object]localCarrierAliases) {
			if mv == nil || mv.Recv == nil {
				return
			}
			walkTransientTargetValues(mv.Recv, func(cur *flowir.Value) {
				switch cur.Kind {
				case flowir.ValPlace:
					if cur.Place.Obj != nil {
						if variable, ok := s.dynamicPackageVar(cur.Place.Obj); ok {
							s.markEscapedVars([]*types.Var{variable}, cur.Place.RootPos)
						} else {
							s.markEscapedVars(aliases[cur.Place.Obj].all, cur.Place.RootPos)
						}
					}
				case flowir.ValAddrOf:
					if cur.AddrPlace.Obj != nil {
						if variable, ok := s.dynamicPackageVar(cur.AddrPlace.Obj); ok {
							s.markEscapedVars([]*types.Var{variable}, cur.AddrPlace.RootPos)
						} else {
							s.markEscapedVars(aliases[cur.AddrPlace.Obj].all, cur.AddrPlace.RootPos)
						}
					}
				}
			})
		}
	}
	aliased, _ := computeBodyCarrierAliases(s.audited, s.fc, b, cfg)
	return aliased
}

func (s *globalUseScanner) carrierArgVar(arg *flowir.Value) (token.Pos, *types.Var) {
	if arg == nil || arg.Kind != flowir.ValPlace || !arg.Place.IsBareVar() || arg.Place.Obj == nil {
		return token.NoPos, nil
	}
	variable, ok := s.dynamicPackageVar(arg.Place.Obj)
	if !ok {
		return token.NoPos, nil
	}
	vt := variable.Type()
	if !refconfine.TypeHandsOutDynamicAlias(s.audited, vt) && !syntaxutil.ContainsUintptr(vt) {
		return token.NoPos, nil
	}
	return arg.Place.RootPos, variable
}

func (s *globalUseScanner) deferCarrierArgs(callVal *flowir.Value, sink map[string]map[syntaxutil.ParamKey]bool, kind byte) map[int]bool {
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
		pos, variable := s.carrierArgVar(arg)
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
			res.EnclosingFn = s.currentDeferFn
			res.Literal = s.currentDeferLit
		}
		syntaxutil.ExplainDeferralMark(s.hooks, s.p, kind, key, res, pos)
		if deferredArgIdxs == nil {
			deferredArgIdxs = map[int]bool{}
		}
		deferredArgIdxs[i] = true
	}
	return deferredArgIdxs
}

func (s *globalUseScanner) dischargePool(variable *types.Var) {
	if s.poolDischarged != nil {
		s.poolDischarged[syntaxutil.DynamicVarKey(variable)] = true
	}
}

func (s *globalUseScanner) recordConfinementSinkUses(
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
		if s.sink.paramUses[key] == nil {
			s.sink.paramUses[key] = map[syntaxutil.ParamKey]bool{}
		}
		for want := range wants {
			s.sink.paramUses[key][want] = true
			syntaxutil.ExplainDeferralMark(s.hooks, s.p, 'p', key, syntaxutil.DeferralResolvent{
				Param:       want,
				EnclosingFn: enclFn,
				Literal:     literal,
			}, pos)
		}
	}
	if len(methodWants) > 0 {
		if s.sink.methodUses[key] == nil {
			s.sink.methodUses[key] = map[syntaxutil.FuncKey]bool{}
		}
		for want := range methodWants {
			s.sink.methodUses[key][want] = true
			syntaxutil.ExplainDeferralMark(s.hooks, s.p, 'm', key, syntaxutil.DeferralResolvent{
				Method:      want,
				EnclosingFn: enclFn,
				Literal:     literal,
			}, pos)
		}
	}
	if len(fieldWants) > 0 {
		if s.fieldUses[key] == nil {
			s.fieldUses[key] = map[syntaxutil.FieldPosKey]bool{}
		}
		for want := range fieldWants {
			fp := syntaxutil.FieldPosKey{Owner: key, Field: want.Field, Index: want.Index}
			s.fieldUses[key][fp] = true
			syntaxutil.ExplainDeferralMark(s.hooks, s.p, 'f', key, syntaxutil.DeferralResolvent{FieldPos: fp}, pos)
		}
	}
	if len(elemWants) > 0 {
		if s.elemUses[key] == nil {
			s.elemUses[key] = map[syntaxutil.ElemParamUse]bool{}
		}
		for want := range elemWants {
			eu := syntaxutil.ElemParamUse{Key: key, Owner: want.Owner, Index: want.Index}
			s.elemUses[key][eu] = true
			syntaxutil.ExplainDeferralMark(s.hooks, s.p, 'e', key, syntaxutil.DeferralResolvent{ElemUse: eu}, pos)
		}
	}
}

func (s *globalUseScanner) markExemptEscapesPlace(pl flowir.Place, vt types.Type, addressed bool) {
	pl.ForEachChildValue(func(cv *flowir.Value) bool {
		s.markExemptEscapesVal(cv)
		return true
	})
	if pl.Obj != nil {
		if variable, ok := s.dynamicPackageVar(pl.Obj); ok {
			if addressed || refconfine.TypeHandsOutDynamicAlias(s.audited, variable.Type()) ||
				syntaxutil.ContainsUintptr(vt) {
				s.markEscapedVars([]*types.Var{variable}, pl.RootPos)
			}
		} else {
			entry := s.aliasedLocals[pl.Obj]
			vars := entry.root
			if flowir.PlaceEntersInterior(pl, false) || canAliasCarrierType(s.audited, vt) || isTypeParamType(vt) {
				vars = entry.all
			}
			s.markEscapedVars(vars, pl.RootPos)
		}
	}
}

func (s *globalUseScanner) markExemptEscapesVal(v *flowir.Value) {
	// ValMethodVal receiver escapes across sync/IIFE ops in init and GenDecl
	// scopes are already recorded by initAliasedLocals's onRHSMethodValue pass.
	if v == nil || v.Kind == flowir.ValMakeClosure || v.Kind == flowir.ValMethodVal {
		return
	}
	if v.Kind == flowir.ValCall && v.CallKind == flowir.CallIIFE {
		for _, a := range v.Args {
			s.markExemptEscapesVal(a)
		}
		flowir.ForEachIIFEReturnValue(v, s.markExemptEscapesVal)
		return
	}
	isStrBuiltin := v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin &&
		(v.BuiltinName == "String" || v.BuiltinName == "StringData")
	if !isStrBuiltin && v.Type != nil && !canAliasCarrierType(s.audited, v.Type) && !isTypeParamType(v.Type) {
		return
	}
	switch v.Kind {
	case flowir.ValPlace:
		s.markExemptEscapesPlace(v.Place, v.Type, false)
	case flowir.ValAddrOf:
		if v.Low != nil {
			s.markExemptEscapesVal(v.Low)
		}
		if v.High != nil {
			s.markExemptEscapesVal(v.High)
		}
		if v.Max != nil {
			s.markExemptEscapesVal(v.Max)
		}
		s.markExemptEscapesPlace(v.AddrPlace, v.Type, true)
	case flowir.ValCall:
		if v.CallKind == flowir.CallBuiltin {
			switch v.BuiltinName {
			case "len", "cap", "Sizeof", "Alignof", "Offsetof":
				return
			case "Slice", "SliceData", "String", "StringData":
				if len(v.Args) > 0 {
					s.markExemptEscapesVal(v.Args[0])
				}
				return
			}
		}
		for _, a := range v.Args {
			s.markExemptEscapesVal(a)
		}
	default:
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			s.markExemptEscapesVal(ch)
			return true
		})
	}
}

func (s *globalUseScanner) scanExemptCallTree(v *flowir.Value) {
	if v == nil || v.Kind == flowir.ValMakeClosure {
		return
	}
	if v.Kind == flowir.ValChanRecv {
		s.markExemptEscapesVal(v.Chan)
		s.scanExemptCallTree(v.Chan)
		return
	}
	if v.Kind == flowir.ValCall {
		if v.CallKind == flowir.CallIIFE {
			for _, a := range v.Args {
				s.scanExemptCallTree(a)
			}
			return
		}
		if v.CallKind == flowir.CallBuiltin {
			switch v.BuiltinName {
			case "copy":
				if len(v.Args) == 2 && transientValueHasUnresolvedTarget(v.Args[0]) {
					s.markExemptEscapesVal(v.Args[1])
				}
				for _, a := range v.Args {
					s.scanExemptCallTree(a)
				}
				return
			case "Sizeof", "Alignof", "Offsetof":
				return
			case "len", "cap", "delete", "clear", "append", "Add", "Slice", "SliceData", "String", "StringData", "min", "max":
				for _, a := range v.Args {
					s.scanExemptCallTree(a)
				}
				return
			}
		}
		var deferredArgs map[int]bool
		switch v.CallKind {
		case flowir.CallPlain:
			if !v.IsMethodExprCall && v.CalleeFunc != nil {
				deferredArgs = s.deferCarrierArgs(v, s.initParamUses, 'q')
			} else if v.IsMethodExprCall && v.Recv != nil {
				s.markExemptEscapesVal(v.Recv)
				s.scanExemptCallTree(v.Recv)
			}
		case flowir.CallMethod:
			if !v.IsMethodExprCall && v.Selection != nil && v.Selection.Kind() == types.MethodVal && v.CalleeFunc != nil {
				deferred := false
				fn := v.CalleeFunc
				sel := v.CalleeSelector()
				var poolPos token.Pos
				var poolVar *types.Var
				var isBarePool bool
				if refconfine.AuditedPooling(s.audited, fn) && v.HasRecvPlace {
					poolPos, poolVar, isBarePool = poolCarrierPlace(v.RecvPlace)
				}
				if poolVar != nil {
					s.dischargePool(poolVar)
					v.RecvPlace.ForEachChildValue(func(cv *flowir.Value) bool {
						s.markExemptEscapesVal(cv)
						s.scanExemptCallTree(cv)
						return true
					})
					if sel == nil || !s.provenCalls[sel] {
						if _, vOK := s.dynamicPackageVar(poolVar); vOK && refconfine.TypeHandsOutDynamicAlias(s.audited, poolVar.Type()) {
							key := syntaxutil.DynamicVarKey(poolVar)
							if s.sink.poolEscaped != nil {
								s.sink.poolEscaped[key] = true
							}
							if !s.singleSubject {
								if isBarePool && !syntaxutil.InterfaceReceiver(fn) &&
									refconfine.InstantiatedResultsHandOutNothing(s.audited, v.Selection.Type()) && sel != nil {
									factKey := syntaxutil.MethodFactKey(fn)
									syntaxutil.ExplainDeferralMark(s.hooks, s.p, 'n', key, syntaxutil.DeferralResolvent{Method: factKey}, sel.Pos())
								} else if poolPos.IsValid() {
									syntaxutil.ExplainMark(s.hooks, s.p, "escape", key, poolPos)
								}
							}
						}
					}
					deferred = true
				} else if !syntaxutil.InterfaceReceiver(fn) &&
					refconfine.InstantiatedResultsHandOutNothing(s.audited, v.Selection.Type()) &&
					v.HasRecvPlace && v.RecvPlace.IsBareVar() && sel != nil {
					if variable, vOK := s.dynamicPackageVar(v.RecvPlace.Obj); vOK {
						key := syntaxutil.DynamicVarKey(variable)
						if s.initMethodUses[key] == nil {
							s.initMethodUses[key] = map[syntaxutil.FuncKey]bool{}
						}
						factKey := syntaxutil.MethodFactKey(fn)
						s.initMethodUses[key][factKey] = true
						syntaxutil.ExplainDeferralMark(s.hooks, s.p, 'n', key, syntaxutil.DeferralResolvent{Method: factKey}, sel.Pos())
						deferred = true
					}
				}
				if !deferred && v.Recv != nil {
					s.markExemptEscapesVal(v.Recv)
					s.scanExemptCallTree(v.Recv)
				}
			} else if v.Recv != nil {
				s.markExemptEscapesVal(v.Recv)
				s.scanExemptCallTree(v.Recv)
			}
		case flowir.CallIndirect:
			if v.Callee != nil {
				s.scanExemptCallTree(v.Callee)
			}
		}
		for i, a := range v.Args {
			if !deferredArgs[i] {
				if a != nil && a.Kind == flowir.ValPlace &&
					!refconfine.CallResultHandsOut(a.Type) && !isTypeParamType(a.Type) {
					a.Place.ForEachChildValue(func(cv *flowir.Value) bool {
						s.markExemptEscapesVal(cv)
						return true
					})
				} else {
					s.markExemptEscapesVal(a)
				}
			}
			s.scanExemptCallTree(a)
		}
		return
	}
	v.ForEachChildValue(func(ch *flowir.Value) bool {
		s.scanExemptCallTree(ch)
		return true
	})
}

func (s *globalUseScanner) scanExemptCalls(b *flowir.Body) {
	if s.initParamUses == nil || b == nil {
		return
	}
	for _, rv := range b.Results {
		if rv != nil && (canAliasCarrierType(s.audited, rv.Type()) || isTypeParamType(rv.Type())) {
			s.markEscapedVars(s.aliasedLocals[rv].all, rv.Pos())
		}
	}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind == flowir.OpGo {
			return true
		}
		if op.Kind == flowir.OpReturn {
			for _, res := range op.Results {
				s.markExemptEscapesVal(res)
				s.scanExemptCallTree(res)
			}
			return true
		}
		if op.Kind == flowir.OpAssign {
			if op.AssignKind == flowir.AssignRange {
				if len(op.Srcs) > 0 && op.Srcs[0] != nil && op.Srcs[0].Type != nil {
					if _, isChan := types.Unalias(op.Srcs[0].Type).Underlying().(*types.Chan); isChan {
						s.markExemptEscapesVal(op.Srcs[0])
					}
				}
			} else if op.AssignKind != flowir.AssignZeroDecl && op.AssignKind != flowir.AssignIncDec {
				op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
					if dst.Root == flowir.RootTransient && transientValueHasUnresolvedTarget(dst.Base) {
						s.markExemptEscapesVal(src)
						if _, keyVal, isMapW := dst.AsMapWrite(); isMapW {
							s.markExemptEscapesVal(keyVal)
						}
					}
					return true
				})
			}
		}
		if op.Kind == flowir.OpChanSend && op.ChanPlace.Obj == nil {
			s.markExemptEscapesVal(op.SendVal)
		}
		forEachOpTopValues(op, s.scanExemptCallTree)
		return true
	})
}
