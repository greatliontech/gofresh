package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// envRegScanner records, per dynamic-capable package variable (own or foreign),
// whether a package's direct code stores a function-carrying value into it that
// is not provably environment-free.
type envRegScanner struct {
	audited           bool
	p                 *packages.Package
	fc                *pkgFlowCache
	idx               *refconfine.PkgIndex
	callIdx           *refconfine.CallSiteIndex
	initOnly          map[string]bool
	unattestedBroken  map[string]bool
	singleSubjectVars map[string]bool
	settledGlobals    settledGlobalMap
	pkgConf           *packageConfinementSummary
	exemptSeamNodes   map[ast.Node]bool
	hooks             *syntaxutil.ExplainHookSet

	// Outputs.
	envCarrying       map[string]bool
	envCarryingFns    map[string]map[syntaxutil.FuncKey]bool
	envCarryingUnattr map[string]bool
	envCallableVars   map[string]bool
	envCalls          map[syntaxutil.EnvCallUse]bool
	envParamCalls     map[syntaxutil.EnvCallParamUse]bool
	envMethodCalls    map[syntaxutil.EnvCallMethodUse]bool
	carrierLinks      map[syntaxutil.CarrierLink]bool
	fieldDefer        map[syntaxutil.FieldPosKey]map[syntaxutil.ParamKey]bool
	fieldPoison       map[string]map[syntaxutil.FieldParamPoison]bool

	// Per-pass & per-store mutable traversal state.
	ownPath                 string
	localAliases            map[types.Object]localCarrierAliases
	enclosingScope          ast.Node
	currentRegFn            syntaxutil.FuncKey
	currentTargets          []*types.Var
	pendingEnvCalls         map[syntaxutil.FuncKey]bool
	pendingEnvParams        map[syntaxutil.ParamKey]bool
	pendingEnvMethods       map[syntaxutil.FuncKey]bool
	pendingCarrierLinks     map[string]bool
	visitingSingleWriteVars map[*types.Var]bool
	visitingInitParams      map[syntaxutil.ParamKey]bool
	visitingFuncLits        map[*ast.FuncLit]bool
}

func (s *envRegScanner) scanPackage() {
	if s.p == nil || s.p.TypesInfo == nil {
		return
	}
	if s.fc == nil {
		s.fc = newPkgFlowCache(s.audited, s.p)
	}
	if s.p.Types != nil {
		s.ownPath = s.p.Types.Path()
	}
	s.visitingSingleWriteVars = map[*types.Var]bool{}
	s.visitingInitParams = map[syntaxutil.ParamKey]bool{}
	s.visitingFuncLits = map[*ast.FuncLit]bool{}

	for _, file := range s.p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Body != nil {
					if s.ownPath != "" && decl.Recv == nil && decl.Name != nil &&
						!s.initOnly[decl.Name.Name] && decl.Name.Name != "init" &&
						decl.Name.Name != "TestMain" && decl.Name.Name != "_" {
						s.currentRegFn = syntaxutil.FuncKey{Pkg: s.ownPath, Name: decl.Name.Name}
					}
					b := s.fc.funcBody(s.p, decl)
					s.walkStoresBody(b, decl, s.computeLocalAliases(b, nil))
					s.currentRegFn = syntaxutil.FuncKey{}
				}
			case *ast.GenDecl:
				if decl.Tok == token.VAR || decl.Tok == token.CONST {
					b := s.fc.body(s.p, decl)
					s.walkStoresBody(b, nil, s.computeLocalAliases(b, nil))
				}
			}
		}
	}
}

func (s *envRegScanner) carrierVar(obj types.Object) (*types.Var, bool) {
	variable, ok := obj.(*types.Var)
	if !ok || variable == nil || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
		return nil, false
	}
	if !refconfine.TypeMayCarryUnknownDynamic(s.audited, variable.Type()) {
		return nil, false
	}
	return variable, true
}

func (s *envRegScanner) targetVarsForPlace(dst flowir.Place, writeContainer bool) []*types.Var {
	if dst.Root == flowir.RootBlank {
		return nil
	}
	if dst.Obj != nil {
		if cv, isC := s.carrierVar(dst.Obj); isC {
			return []*types.Var{cv}
		}
		if flowir.PlaceEntersInterior(dst, writeContainer) {
			return s.localAliases[dst.Obj].all
		}
		return s.localAliases[dst.Obj].root
	}
	if dst.Root == flowir.RootTransient && dst.Base != nil {
		return collectValueCarrierVars(s.audited, dst.Base, s.carrierVar, s.localAliases, nil)
	}
	return nil
}

func (s *envRegScanner) targetVarsForValue(val *flowir.Value, writeContainer bool) (flowir.Place, bool, []*types.Var) {
	if val == nil {
		return flowir.Place{}, false, nil
	}
	switch val.Kind {
	case flowir.ValPlace:
		return val.Place, true, s.targetVarsForPlace(val.Place, writeContainer)
	case flowir.ValAddrOf:
		if val.IsArraySlice && val.AddrPlace.Obj != nil {
			if cv, isC := s.carrierVar(val.AddrPlace.Obj); isC {
				return flowir.Place{}, false, []*types.Var{cv}
			}
			if flowir.PlaceEntersInterior(val.AddrPlace, false) {
				return flowir.Place{}, false, s.localAliases[val.AddrPlace.Obj].all
			}
			return flowir.Place{}, false, s.localAliases[val.AddrPlace.Obj].root
		}
	}
	return flowir.Place{}, false, collectValueCarrierVars(s.audited, val, s.carrierVar, s.localAliases, nil)
}

func (s *envRegScanner) computeLocalAliases(scopeBody *flowir.Body, parent map[types.Object]localCarrierAliases) map[types.Object]localCarrierAliases {
	aliased, _ := computeBodyCarrierAliases(s.audited, s.fc, scopeBody, carrierAliasConfig{
		parentAliases: parent,
		carrierVar:    s.carrierVar,
		descendNested: true,
	})
	return aliased
}

func (s *envRegScanner) wantsResolve(wants map[syntaxutil.ParamKey]bool, methodWants map[syntaxutil.FuncKey]bool) bool {
	return s.pkgConf.resolveWants(s.ownPath, wants, methodWants, s.pendingEnvParams, s.pendingEnvMethods)
}

func (s *envRegScanner) isSyncInitFlowScope(scope ast.Node) bool {
	if scope == nil {
		return true
	}
	fd, ok := scope.(*ast.FuncDecl)
	if !ok || fd.Recv != nil || fd.Name == nil {
		return false
	}
	return fd.Name.Name == "init" || (!fd.Name.IsExported() && s.initOnly[fd.Name.Name])
}

func (s *envRegScanner) singleWriteTopLevelInit(cv *types.Var) (*flowir.Value, bool) {
	if s.p.Types == nil || cv == nil || cv.Pkg() != s.p.Types || cv.Parent() != s.p.Types.Scope() {
		return nil, false
	}
	if typeHandsOutReachOrAddr(cv.Type()) || refconfine.TypeReachesSyncNoCopyByValue(cv.Type()) {
		return nil, false
	}
	cvKey := syntaxutil.DynamicVarKey(cv)
	if s.unattestedBroken[cvKey] || s.singleSubjectVars[cvKey] {
		return nil, false
	}
	return s.fc.singleWritePkgGlobalInit(s.p, cv)
}

func (s *envRegScanner) carryingAtScope(scope ast.Node, val *flowir.Value) bool {
	prev := s.enclosingScope
	snapCalls := maps.Clone(s.pendingEnvCalls)
	snapParams := maps.Clone(s.pendingEnvParams)
	snapMethods := maps.Clone(s.pendingEnvMethods)
	snapLinks := maps.Clone(s.pendingCarrierLinks)
	s.enclosingScope = scope
	bad := s.carryingValue(val)
	s.enclosingScope = prev
	if bad {
		s.pendingEnvCalls = snapCalls
		s.pendingEnvParams = snapParams
		s.pendingEnvMethods = snapMethods
		s.pendingCarrierLinks = snapLinks
	}
	return bad
}

func (s *envRegScanner) checkCapturedSigOriginAtScope(scope ast.Node, val *flowir.Value) bool {
	if val == nil || val.IsTypeExpr {
		return false
	}
	if !s.carryingAtScope(scope, val) {
		return true
	}
	if !s.isSyncInitFlowScope(scope) {
		return false
	}
	if val.Kind != flowir.ValPlace || !val.Place.IsBareVar() || val.Place.Obj == nil {
		return false
	}
	v := val.Place.Obj
	if s.p.Types != nil && v.Pkg() == s.p.Types && v.Parent() == s.p.Types.Scope() {
		if s.visitingSingleWriteVars[v] {
			return false
		}
		cvInit, ok := s.singleWriteTopLevelInit(v)
		if !ok {
			return false
		}
		s.visitingSingleWriteVars[v] = true
		defer delete(s.visitingSingleWriteVars, v)
		return s.checkCapturedSigOriginAtScope(nil, cvInit)
	}
	if callerFD, isFD := scope.(*ast.FuncDecl); isFD && syntaxutil.IsLocalVar(v) {
		if s.callIdx != nil {
			if cp, isParam := s.callIdx.Params[v]; isParam && !s.callIdx.Written[v] {
				return s.checkInitOnlyParamAtCallSites(callerFD, cp.Index, v)
			}
		}
		if !s.visitingSingleWriteVars[v] && !typeHandsOutReachOrAddr(v.Type()) {
			fnBody := s.fc.funcBody(s.p, callerFD)
			if initVal, ok := s.fc.singleWriteLocalInit(s.p, fnBody, v); ok {
				s.visitingSingleWriteVars[v] = true
				defer delete(s.visitingSingleWriteVars, v)
				return s.checkCapturedSigOriginAtScope(callerFD, initVal)
			}
		}
	}
	return false
}

func (s *envRegScanner) checkInitOnlyParamAtCallSites(fd *ast.FuncDecl, pIdx int, paramVar *types.Var) bool {
	if fd == nil || fd.Recv != nil || fd.Name == nil || fd.Name.IsExported() || !s.initOnly[fd.Name.Name] ||
		s.idx == nil || s.callIdx == nil || paramVar == nil {
		return false
	}
	fn, ok := s.p.TypesInfo.Defs[fd.Name].(*types.Func)
	if !ok || fn == nil || s.callIdx.Escaped[fn] {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || pIdx < 0 || pIdx >= sig.Params().Len() {
		return false
	}
	pk := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: s.ownPath, Name: fn.Name()}, Index: pIdx}
	if s.visitingInitParams[pk] {
		return false
	}
	s.visitingInitParams[pk] = true
	defer delete(s.visitingInitParams, pk)

	isVariadicSlot := sig.Variadic() && pIdx == sig.Params().Len()-1
	for _, call := range s.callIdx.Calls[fn] {
		if call == nil || s.idx.InFuncLit[call] || s.idx.InGoStmt[call] {
			return false
		}
		var callerScope ast.Node
		if callerFD := s.idx.EnclFunc[call]; callerFD != nil {
			callerScope = callerFD
		}
		if !s.isSyncInitFlowScope(callerScope) {
			return false
		}
		if len(call.Args) == 1 && sig.Params().Len() > 1 {
			if _, isTup := s.p.TypesInfo.TypeOf(call.Args[0]).(*types.Tuple); isTup {
				return false
			}
		}
		if !isVariadicSlot || call.Ellipsis.IsValid() {
			if pIdx >= len(call.Args) {
				return false
			}
			argVal := s.fc.exprValue(s.p, call.Args[pIdx])
			if refconfine.TypeReachesSyncNoCopyByValue(paramVar.Type()) {
				return false
			}
			if refconfine.TypeCarriesSignature(paramVar.Type()) && !s.checkCapturedSigOriginAtScope(callerScope, argVal) {
				return false
			}
			if typeHandsOutReachOrAddr(paramVar.Type()) && !isPureFreshDataValue(s.settledGlobals, argVal) {
				return false
			}
			continue
		}
		sl, isSl := types.Unalias(paramVar.Type()).Underlying().(*types.Slice)
		if !isSl {
			return false
		}
		elemT := sl.Elem()
		if refconfine.TypeReachesSyncNoCopyByValue(elemT) {
			return false
		}
		for ai := pIdx; ai < len(call.Args); ai++ {
			argVal := s.fc.exprValue(s.p, call.Args[ai])
			if refconfine.TypeCarriesSignature(elemT) && !s.checkCapturedSigOriginAtScope(callerScope, argVal) {
				return false
			}
			if typeHandsOutReachOrAddr(elemT) && !isPureFreshDataValue(s.settledGlobals, argVal) {
				return false
			}
		}
	}
	return true
}

func (s *envRegScanner) checkLocalCarryingInit(initVal *flowir.Value) bool {
	return s.checkCapturedSigOriginAtScope(s.enclosingScope, initVal)
}

func (s *envRegScanner) carryingValue(val *flowir.Value) bool {
	if val == nil || val.IsTypeExpr {
		return false
	}
	switch val.Kind {
	case flowir.ValScalarLitOrConst:
		return false
	case flowir.ValAllocFresh:
		switch val.AllocKind {
		case flowir.AllocMake, flowir.AllocBuiltinNewType:
			return false
		case flowir.AllocBuiltinNewExpr:
			return len(val.Args) != 1 || val.Ellipsis || s.carryingValue(val.Args[0])
		case flowir.AllocCompositeLit:
			for i := range val.CompositeElts {
				elt := &val.CompositeElts[i]
				if elt.MapKey != nil && s.carryingValue(elt.MapKey) {
					return true
				}
				if elt.Index != nil && s.carryingValue(elt.Index) {
					return true
				}
				if s.carryingValue(elt.Value) {
					return true
				}
			}
			return false
		}
	case flowir.ValMakeClosure:
		if val.Lit == nil || s.visitingFuncLits[val.Lit] {
			return true
		}
		s.visitingFuncLits[val.Lit] = true
		defer delete(s.visitingFuncLits, val.Lit)
		wants := map[syntaxutil.ParamKey]bool{}
		methodWants := map[syntaxutil.FuncKey]bool{}
		var checkParamFn func(int, *types.Var) bool
		if fd, isFD := s.enclosingScope.(*ast.FuncDecl); isFD && s.isSyncInitFlowScope(fd) && fd.Name != nil && fd.Name.Name != "init" {
			checkParamFn = func(pIdx int, pv *types.Var) bool {
				return s.checkInitOnlyParamAtCallSites(fd, pIdx, pv)
			}
		}
		origin := &rootOriginPolicy{
			verifyLocalOrigins:   true,
			allowEnclosingParams: false,
			inInitFlow:           s.isSyncInitFlowScope(s.enclosingScope),
			unattestedBroken:     s.unattestedBroken,
			singleSubjectVars:    s.singleSubjectVars,
			settledGlobals:       s.settledGlobals,
			currentTargets:       s.currentTargets,
			checkCarryingValue:   s.checkLocalCarryingInit,
			checkEnclosingParam:  checkParamFn,
		}
		if !environmentFreeFuncLitWithOrigin(s.audited, s.p, s.fc, val.Lit, s.enclosingScope, wants, methodWants, origin) {
			return true
		}
		if !s.wantsResolve(wants, methodWants) {
			return true
		}
		if origin.inInitFlow && s.pendingCarrierLinks != nil {
			for gvKey := range origin.linkedCarrierGlobals {
				s.pendingCarrierLinks[gvKey] = true
			}
		}
		return false
	case flowir.ValMethodVal:
		return true
	case flowir.ValConvert:
		if !val.IsTypeAssert && val.Arg != nil {
			if val.Arg.IsNil {
				return false
			}
			if !syntaxutil.IsUnsafePointerType(val.Arg.Type) && val.Type != nil {
				if val.Arg.Type != nil && types.Identical(types.Unalias(val.Type).Underlying(), types.Unalias(val.Arg.Type).Underlying()) {
					return s.carryingValue(val.Arg)
				}
				if _, isIface := types.Unalias(val.Type).Underlying().(*types.Interface); isIface {
					return s.carryingValue(val.Arg)
				}
			}
		}
	case flowir.ValCall:
		switch val.CallKind {
		case flowir.CallBuiltin:
			if val.BuiltinName == "append" {
				for _, arg := range val.Args {
					if s.carryingValue(arg) {
						return true
					}
				}
				return false
			}
		case flowir.CallPlain:
			if !val.IsMethodExprCall && val.CalleeFunc != nil {
				fn := val.CalleeFunc.Origin()
				calleeFK := syntaxutil.FuncKey{Pkg: val.CalleePkg, Name: fn.Name()}
				if auditset.ValuePlaneClone(calleeFK.Pkg, calleeFK.Name) {
					for _, arg := range val.Args {
						if s.carryingValue(arg) {
							return true
						}
					}
					return false
				}
				if s.pendingEnvCalls != nil && refconfine.TypeCarriesSignature(val.Type) {
					for _, arg := range val.Args {
						if s.carryingValue(arg) {
							return true
						}
						if arg != nil && arg.Type != nil && typeHandsOutReachOrAddr(arg.Type) {
							if !isSettledReachArgValue(s.audited, s.p, s.fc, s.settledGlobals, s.currentTargets, s.enclosingScope, val.CallAST, s.pkgConf, s.pendingEnvParams, s.pendingEnvMethods, s.checkLocalCarryingInit, arg) {
								return true
							}
						}
					}
					s.pendingEnvCalls[calleeFK] = true
					return false
				}
			}
		}
	case flowir.ValPlace:
		if val.IsNil || val.IsConst || val.Place.Root == flowir.RootConstOrNil {
			return false
		}
		if val.Place.Root == flowir.RootFunc && len(val.Place.Projs) == 0 {
			return false
		}
	}
	return refconfine.TypeCarriesSignature(val.Type)
}

func (s *envRegScanner) isExemptSeamPlace(dst flowir.Place) bool {
	if dst.Raw == nil || len(s.exemptSeamNodes) == 0 {
		return false
	}
	return s.exemptSeamNodes[dst.Raw] || s.exemptSeamNodes[syntaxutil.UnparenExpr(dst.Raw)]
}

func (s *envRegScanner) poisonExemptPlace(dst flowir.Place) {
	if s.fieldPoison == nil {
		return
	}
	for _, variable := range s.targetVarsForPlace(dst, false) {
		key := syntaxutil.DynamicVarKey(variable)
		if s.fieldPoison[key] == nil {
			s.fieldPoison[key] = map[syntaxutil.FieldParamPoison]bool{}
		}
		s.fieldPoison[key][syntaxutil.FieldParamPoison{Owner: key}] = true
	}
}

func flowValuePos(v *flowir.Value) token.Pos {
	if v != nil && v.Raw != nil {
		return v.Raw.Pos()
	}
	return token.NoPos
}

func (s *envRegScanner) handleStoreCore(dst flowir.Place, hasDst bool, targets []*types.Var, rhs *flowir.Value) {
	if len(targets) == 0 {
		return
	}
	var flows []*flowir.Value
	if rhs != nil {
		flows = []*flowir.Value{rhs}
		if rhs.Kind == flowir.ValCall && rhs.CallKind == flowir.CallBuiltin && rhs.BuiltinName == "append" && len(rhs.Args) > 0 {
			base := rhs.Args[0]
			if base != nil && base.Kind == flowir.ValPlace && base.Place.IsBareVar() && base.Place.Obj != nil {
				if variable, ok := s.carrierVar(base.Place.Obj); ok && len(targets) == 1 && variable == targets[0] {
					flows = rhs.Args[1:]
				}
			}
		}
	}
	if hasDst {
		if _, mapKey, ok := dst.AsMapWrite(); ok && mapKey != nil {
			flows = append(flows, mapKey)
		}
	}
	if len(flows) == 0 {
		return
	}
	poison := false
	s.pendingEnvCalls = map[syntaxutil.FuncKey]bool{}
	s.pendingEnvParams = map[syntaxutil.ParamKey]bool{}
	s.pendingEnvMethods = map[syntaxutil.FuncKey]bool{}
	s.pendingCarrierLinks = map[string]bool{}
	prevTargets := s.currentTargets
	s.currentTargets = targets
	var poisonAt, deferredAt token.Pos
	for _, flow := range flows {
		beforeCalls, beforeParams, beforeMethods := len(s.pendingEnvCalls), len(s.pendingEnvParams), len(s.pendingEnvMethods)
		if s.carryingValue(flow) {
			poison = true
			poisonAt = flowValuePos(flow)
			break
		}
		if deferredAt == token.NoPos && (len(s.pendingEnvCalls) > beforeCalls || len(s.pendingEnvParams) > beforeParams || len(s.pendingEnvMethods) > beforeMethods) {
			deferredAt = flowValuePos(flow)
		}
	}
	s.currentTargets = prevTargets
	if poison {
		for _, variable := range targets {
			key := syntaxutil.DynamicVarKey(variable)
			syntaxutil.ExplainStoreMark(s.hooks, s.p, key, poisonAt)
			s.envCarrying[key] = true
			if s.envCallableVars != nil {
				if _, isFunc := types.Unalias(variable.Type()).Underlying().(*types.Signature); isFunc {
					s.envCallableVars[key] = true
				}
			}
			if s.currentRegFn.Valid() {
				if s.envCarryingFns != nil {
					if s.envCarryingFns[key] == nil {
						s.envCarryingFns[key] = map[syntaxutil.FuncKey]bool{}
					}
					s.envCarryingFns[key][s.currentRegFn] = true
				}
			} else if s.envCarryingUnattr != nil {
				s.envCarryingUnattr[key] = true
			}
		}
	} else {
		if len(s.pendingEnvCalls) > 0 || len(s.pendingEnvParams) > 0 || len(s.pendingEnvMethods) > 0 {
			for _, variable := range targets {
				key := syntaxutil.DynamicVarKey(variable)
				if deferredAt != token.NoPos {
					syntaxutil.ExplainStoreMark(s.hooks, s.p, key, deferredAt)
				}
				if s.envCallableVars != nil {
					if _, isFunc := types.Unalias(variable.Type()).Underlying().(*types.Signature); isFunc {
						s.envCallableVars[key] = true
					}
				}
				if s.envCalls != nil {
					for callee := range s.pendingEnvCalls {
						s.envCalls[syntaxutil.EnvCallUse{Key: key, Callee: callee, Func: s.currentRegFn}] = true
					}
				}
				if s.envParamCalls != nil {
					for pk := range s.pendingEnvParams {
						s.envParamCalls[syntaxutil.EnvCallParamUse{Key: key, Param: pk, Func: s.currentRegFn}] = true
					}
				}
				if s.envMethodCalls != nil {
					for mk := range s.pendingEnvMethods {
						s.envMethodCalls[syntaxutil.EnvCallMethodUse{Key: key, Method: mk, Func: s.currentRegFn}] = true
					}
				}
			}
		}
		if s.carrierLinks != nil && len(s.pendingCarrierLinks) > 0 {
			for gvKey := range s.pendingCarrierLinks {
				for _, variable := range targets {
					key := syntaxutil.DynamicVarKey(variable)
					if key != gvKey {
						s.carrierLinks[syntaxutil.CarrierLink{From: key, To: gvKey}] = true
					}
				}
			}
		}
		if s.fieldDefer != nil {
			var marks []fieldRegMark
			for _, flow := range flows {
				classifyFieldRegistrantsValue(s.audited, s.p, s.fc, dst, hasDst, flow, func(m fieldRegMark) {
					marks = append(marks, m)
				})
			}
			for _, variable := range targets {
				key := syntaxutil.DynamicVarKey(variable)
				for _, m := range marks {
					switch m.class {
					case 'd':
						pos := syntaxutil.FieldPosKey{Owner: key, Field: m.field, Index: m.idx}
						if s.fieldDefer[pos] == nil {
							s.fieldDefer[pos] = map[syntaxutil.ParamKey]bool{}
						}
						s.fieldDefer[pos][m.param] = true
					case 'p':
						if s.fieldPoison[key] == nil {
							s.fieldPoison[key] = map[syntaxutil.FieldParamPoison]bool{}
						}
						if m.field == "" {
							s.fieldPoison[key][syntaxutil.FieldParamPoison{Owner: key}] = true
						} else {
							s.fieldPoison[key][syntaxutil.FieldParamPoison{Owner: key, HasPos: true, Field: m.field, Index: m.idx}] = true
						}
					}
				}
			}
		}
	}
	s.pendingEnvCalls = nil
	s.pendingEnvParams = nil
	s.pendingEnvMethods = nil
	s.pendingCarrierLinks = nil
}

func (s *envRegScanner) handleStorePlace(dst flowir.Place, rhs *flowir.Value, rebindable, writeContainer bool) {
	if rebindable && dst.IsBareVar() && dst.Obj != nil {
		if _, isCarrier := s.carrierVar(dst.Obj); !isCarrier {
			return
		}
	}
	targets := s.targetVarsForPlace(dst, writeContainer)
	s.handleStoreCore(dst, true, targets, rhs)
}

func (s *envRegScanner) handleStoreValue(lhsVal, rhs *flowir.Value, writeContainer bool) {
	dst, hasDst, targets := s.targetVarsForValue(lhsVal, writeContainer)
	s.handleStoreCore(dst, hasDst, targets, rhs)
}

func (s *envRegScanner) scanStoreValue(v *flowir.Value) {
	if v == nil {
		return
	}
	switch v.Kind {
	case flowir.ValMakeClosure:
		if v.Closure != nil {
			s.walkStoresBody(v.Closure, v.Lit, s.computeLocalAliases(v.Closure, s.localAliases))
		}
		return
	case flowir.ValCall:
		if v.CallKind == flowir.CallIIFE {
			for _, a := range v.Args {
				s.scanStoreValue(a)
			}
			if v.IIFE != nil {
				var iifeLit *ast.FuncLit
				if v.CallAST != nil {
					iifeLit, _ = syntaxutil.UnparenExpr(v.CallAST.Fun).(*ast.FuncLit)
				}
				s.walkStoresBody(v.IIFE, iifeLit, s.computeLocalAliases(v.IIFE, s.localAliases))
			}
			return
		}
		if v.CallKind == flowir.CallBuiltin {
			switch {
			case v.BuiltinName == "copy" && len(v.Args) == 2:
				s.handleStoreValue(v.Args[0], v.Args[1], true)
			case v.BuiltinName == "append" && len(v.Args) > 1:
				for _, flow := range v.Args[1:] {
					s.handleStoreValue(v.Args[0], flow, true)
				}
			}
		}
	}
	v.ForEachChildValue(func(ch *flowir.Value) bool {
		s.scanStoreValue(ch)
		return true
	})
}

func (s *envRegScanner) walkStoresBody(b *flowir.Body, scope ast.Node, aliases map[types.Object]localCarrierAliases) {
	if b == nil {
		return
	}
	prevScope := s.enclosingScope
	prevAliases := s.localAliases
	s.enclosingScope = scope
	s.localAliases = aliases
	defer func() {
		s.enclosingScope = prevScope
		s.localAliases = prevAliases
	}()

	b.ForEachSyncOp(func(op *flowir.Op) bool {
		switch op.Kind {
		case flowir.OpAssign:
			switch op.AssignKind {
			case flowir.AssignZeroDecl:
				// Uninitialized declarations store no function-carrying values.
			case flowir.AssignIncDec:
				for _, dst := range op.Dsts {
					if _, mapKey, ok := dst.AsMapWrite(); ok && mapKey != nil {
						s.handleStorePlace(dst, nil, false, false)
					}
					dst.ForEachChildValue(func(cv *flowir.Value) bool {
						s.scanStoreValue(cv)
						return true
					})
				}
			case flowir.AssignCompound:
				for i, dst := range op.Dsts {
					var rhs *flowir.Value
					if i < len(op.Srcs) && op.Srcs[i] != nil {
						rhs = op.Srcs[i]
						if rhs.Kind == flowir.ValCompositeExpr && len(rhs.Args) == 2 {
							rhs = rhs.Args[1]
						}
					}
					if s.isExemptSeamPlace(dst) {
						s.poisonExemptPlace(dst)
					} else if rhs != nil {
						s.handleStorePlace(dst, rhs, true, false)
					}
					dst.ForEachChildValue(func(cv *flowir.Value) bool {
						s.scanStoreValue(cv)
						return true
					})
					s.scanStoreValue(rhs)
				}
			case flowir.AssignRange:
				var rngSrc *flowir.Value
				if len(op.Srcs) == 1 {
					rngSrc = op.Srcs[0]
				}
				rs, _ := op.StmtAST.(*ast.RangeStmt)
				isAssignTok := rs != nil && rs.Tok == token.ASSIGN
				for i, dst := range op.Dsts {
					isDef := i < len(op.DstDefs) && op.DstDefs[i]
					if (isAssignTok || !isDef) && rngSrc != nil {
						s.handleStorePlace(dst, rngSrc, true, false)
					}
					dst.ForEachChildValue(func(cv *flowir.Value) bool {
						s.scanStoreValue(cv)
						return true
					})
				}
				for _, src := range op.Srcs {
					s.scanStoreValue(src)
				}
			default:
				for i, dst := range op.Dsts {
					if s.isExemptSeamPlace(dst) {
						s.poisonExemptPlace(dst)
					} else {
						var rhs *flowir.Value
						if len(op.Dsts) == len(op.Srcs) {
							rhs = op.Srcs[i]
						} else if len(op.Srcs) == 1 {
							rhs = op.Srcs[0]
						}
						if rhs != nil {
							s.handleStorePlace(dst, rhs, true, false)
						}
					}
					dst.ForEachChildValue(func(cv *flowir.Value) bool {
						s.scanStoreValue(cv)
						return true
					})
				}
				for _, src := range op.Srcs {
					s.scanStoreValue(src)
				}
			}
		case flowir.OpTypeSwitchBind:
			if op.CaseAST == nil {
				s.scanStoreValue(op.SwitchSrc)
			}
		case flowir.OpChanSend:
			s.handleStoreValue(op.ChanVal, op.SendVal, true)
			s.scanStoreValue(op.ChanVal)
			s.scanStoreValue(op.SendVal)
		case flowir.OpReturn:
			for _, r := range op.Results {
				s.scanStoreValue(r)
			}
		case flowir.OpDefer:
			s.scanStoreValue(op.Call)
		case flowir.OpGo:
			saved := s.enclosingScope
			s.enclosingScope = op.StmtAST
			s.scanStoreValue(op.Call)
			s.enclosingScope = saved
		case flowir.OpExpr:
			s.scanStoreValue(op.Expr)
		}
		return true
	})
}
