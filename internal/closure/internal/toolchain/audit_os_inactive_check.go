package toolchain

import (
	"go/ast"
	"go/token"
	"maps"
	"slices"
)

type osInactiveState struct {
	k                   *PackageInactiveKernel
	pkgDeclCounts       map[string]int
	funcFile            map[*ast.FuncDecl]*ast.File
	fileImportNames     map[*ast.File]map[string]bool
	falseConsts         map[string]bool
	trueConsts          map[string]bool
	osGateFuncs         map[string]string
	nilAccessors        map[string][]string
	falsePreds          map[string][]string
	falseHandledHelpers map[osFalseHelperKey][]string
}

func (s *osInactiveState) identShadowedInFunc(fn *ast.FuncDecl, name string) bool {
	if s == nil || s.k == nil {
		return true
	}
	return s.k.IdentShadowedInFunc(fn, name)
}

func (s *osInactiveState) isPureChain(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) bool {
	return s != nil && s.k != nil && s.k.IsPureChain(expr, fn, params)
}

func (s *osInactiveState) isPureArg(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) bool {
	if s == nil || s.k == nil {
		return false
	}
	if s.isPureChain(expr, fn, params) {
		return true
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		if x.Name == "true" || x.Name == "false" || x.Name == "nil" {
			return s.pkgDeclCounts[x.Name] == 0 && !s.identShadowedInFunc(fn, x.Name)
		}
		if s.trueConsts[x.Name] || s.falseConsts[x.Name] {
			return !s.identShadowedInFunc(fn, x.Name)
		}
	}
	return false
}

func (s *osInactiveState) isPureGuardExpr(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) bool {
	return s != nil && s.k != nil && s.k.IsPureGuardExpr(expr, fn, params)
}

func (s *osInactiveState) isTrueConstIdent(expr ast.Expr, fn *ast.FuncDecl) bool {
	id, ok := unwrapParens(expr).(*ast.Ident)
	if !ok || s.identShadowedInFunc(fn, id.Name) {
		return false
	}
	return (id.Name == "true" && s.pkgDeclCounts["true"] == 0) || s.trueConsts[id.Name]
}

type osFalseEvalEnv[D any] struct {
	st          *osInactiveState
	zeroDep     func() D
	gateDep     func(rtGate string) D
	falsePred   func(name string) (D, bool)
	nilAccessor func(name string) (D, bool)
	merge       func(a, b D) D
}

func evalOSFalseExpr[D any](env osFalseEvalEnv[D], expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) (D, bool) {
	var zero D
	if env.st == nil {
		return zero, false
	}
	expr = unwrapParens(expr)
	if id, okID := expr.(*ast.Ident); okID {
		if id.Name == "false" && env.st.pkgDeclCounts["false"] == 0 && !env.st.identShadowedInFunc(fn, "false") {
			return env.zeroDep(), true
		}
		if env.st.falseConsts[id.Name] && !env.st.identShadowedInFunc(fn, id.Name) {
			return env.zeroDep(), true
		}
		return zero, false
	}
	if call, okC := expr.(*ast.CallExpr); okC && !call.Ellipsis.IsValid() {
		if cID, okID := unwrapParens(call.Fun).(*ast.Ident); okID && !env.st.identShadowedInFunc(fn, cID.Name) {
			if len(call.Args) == 0 {
				if rtGate, okG := env.st.osGateFuncs[cID.Name]; okG {
					return env.gateDep(rtGate), true
				}
				if env.st.k != nil {
					if rtGate, okFV := env.st.k.FalseFuncVars[cID.Name]; okFV {
						return env.gateDep(rtGate), true
					}
				}
			}
			if len(call.Args) == 1 && env.st.isPureChain(call.Args[0], fn, params) {
				if d, okFP := env.falsePred(cID.Name); okFP {
					return d, true
				}
			}
		}
	}
	if bin, okB := expr.(*ast.BinaryExpr); okB {
		switch bin.Op {
		case token.NEQ:
			checkNilAccCall := func(callSide, nilSide ast.Expr) (D, bool) {
				if _, okNil := isIdentNamed(nilSide, "nil"); !okNil || env.st.pkgDeclCounts["nil"] != 0 || env.st.identShadowedInFunc(fn, "nil") {
					return zero, false
				}
				c, okC := unwrapParens(callSide).(*ast.CallExpr)
				if !okC || c.Ellipsis.IsValid() || len(c.Args) != 1 || !env.st.isPureChain(c.Args[0], fn, params) {
					return zero, false
				}
				cID, okID := unwrapParens(c.Fun).(*ast.Ident)
				if !okID || env.st.identShadowedInFunc(fn, cID.Name) {
					return zero, false
				}
				return env.nilAccessor(cID.Name)
			}
			if d, okL := checkNilAccCall(bin.X, bin.Y); okL {
				return d, true
			}
			if d, okR := checkNilAccCall(bin.Y, bin.X); okR {
				return d, true
			}
		case token.LAND:
			if dL, okL := evalOSFalseExpr(env, bin.X, fn, params); okL {
				return dL, true
			}
			if env.st.isPureGuardExpr(bin.X, fn, params) {
				return evalOSFalseExpr(env, bin.Y, fn, params)
			}
		case token.LOR:
			dL, okL := evalOSFalseExpr(env, bin.X, fn, params)
			if !okL {
				return zero, false
			}
			dR, okR := evalOSFalseExpr(env, bin.Y, fn, params)
			if !okR {
				return zero, false
			}
			return env.merge(dL, dR), true
		}
	}
	return zero, false
}

func (s *osInactiveState) evalFalseCond(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) ([]string, bool) {
	if s == nil {
		return nil, false
	}
	env := osFalseEvalEnv[[]string]{
		st:      s,
		zeroDep: func() []string { return make([]string, 0) },
		gateDep: func(rtGate string) []string {
			if rtGate == "" {
				return make([]string, 0)
			}
			return []string{rtGate}
		},
		falsePred: func(name string) ([]string, bool) {
			gates, okFP := s.falsePreds[name]
			if !okFP {
				return nil, false
			}
			return slices.Clone(gates), true
		},
		nilAccessor: func(name string) ([]string, bool) {
			gates, okNA := s.nilAccessors[name]
			if !okNA {
				return nil, false
			}
			return slices.Clone(gates), true
		},
		merge: mergeGateLists,
	}
	return evalOSFalseExpr(env, expr, fn, params)
}

func (s *osInactiveState) evalTrueDisjunction(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) ([]string, bool) {
	if s == nil {
		return nil, false
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.Ident:
		if s.isTrueConstIdent(x, fn) {
			return make([]string, 0), true
		}
	case *ast.UnaryExpr:
		if x.Op == token.NOT {
			return s.evalFalseCond(x.X, fn, params)
		}
	case *ast.BinaryExpr:
		if x.Op == token.LOR {
			if gL, okL := s.evalTrueDisjunction(x.X, fn, params); okL {
				return gL, true
			}
			if s.isPureGuardExpr(x.X, fn, params) {
				return s.evalTrueDisjunction(x.Y, fn, params)
			}
		}
	}
	return nil, false
}

func (s *osInactiveState) checkInactiveHookIf(stmt ast.Stmt, fn *ast.FuncDecl) ([]string, bool) {
	if s == nil || fn == nil {
		return nil, false
	}
	ifs, ok := stmt.(*ast.IfStmt)
	if !ok || ifs.Else != nil {
		return nil, false
	}
	params := map[string]bool{}
	if r := recvVarName(fn); r != "" {
		params[r] = true
	}
	for _, p := range paramNamesFlat(fn.Type.Params) {
		if p != "" && p != "_" {
			params[p] = true
		}
	}
	checkInitHook := func(inner *ast.IfStmt) ([]string, bool) {
		initAs, okA := inner.Init.(*ast.AssignStmt)
		if !okA || initAs.Tok != token.DEFINE || len(initAs.Rhs) != 1 {
			return nil, false
		}
		if len(initAs.Lhs) == 1 {
			vID, okV := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
			if !okV || vID.Name == "" || vID.Name == "_" || vID.Name == "nil" {
				return nil, false
			}
			if call, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr); okC && !call.Ellipsis.IsValid() && len(call.Args) == 1 {
				if calleeID, okFun := unwrapParens(call.Fun).(*ast.Ident); okFun && !s.identShadowedInFunc(fn, calleeID.Name) && s.isPureArg(call.Args[0], fn, params) {
					if s.pkgDeclCounts["nil"] == 0 && !s.identShadowedInFunc(fn, "nil") && condChecksNonZeroErr(inner.Cond) == vID.Name {
						if gates, okNA := s.nilAccessors[calleeID.Name]; okNA {
							return slices.Clone(gates), true
						}
					}
				}
			}
			if s.isPureChain(initAs.Rhs[0], fn, params) && !funcDeclaresAnyParamOrResult(fn, map[string]bool{vID.Name: true}) && !s.fileImportNames[s.funcFile[fn]][vID.Name] {
				extParams := maps.Clone(params)
				extParams[vID.Name] = true
				return s.evalFalseCond(inner.Cond, fn, extParams)
			}
			return nil, false
		}
		call, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
		if !okC || call.Ellipsis.IsValid() {
			return nil, false
		}
		calleeID, okFun := unwrapParens(call.Fun).(*ast.Ident)
		if !okFun || s.identShadowedInFunc(fn, calleeID.Name) {
			return nil, false
		}
		for _, arg := range call.Args {
			if !s.isPureArg(arg, fn, params) {
				return nil, false
			}
		}
		cID, okCond := unwrapParens(inner.Cond).(*ast.Ident)
		if !okCond || cID.Name == "" || cID.Name == "_" {
			return nil, false
		}
		boolIdx := -1
		for idx, lhs := range initAs.Lhs {
			lID, okL := unwrapParens(lhs).(*ast.Ident)
			if !okL || lID.Name == "" {
				return nil, false
			}
			if lID.Name == cID.Name {
				if boolIdx >= 0 {
					return nil, false
				}
				boolIdx = idx
			}
		}
		if boolIdx >= 0 {
			if gates, okH := s.falseHandledHelpers[osFalseHelperKey{name: calleeID.Name, arity: len(initAs.Lhs), boolIdx: boolIdx}]; okH {
				return slices.Clone(gates), true
			}
		}
		return nil, false
	}

	if ifs.Init != nil {
		return checkInitHook(ifs)
	}
	if gates, okF := s.evalFalseCond(ifs.Cond, fn, params); okF {
		return gates, true
	}
	if !s.isTrueConstIdent(ifs.Cond, fn) || len(ifs.Body.List) == 0 || bodyHasControlFlowOrRecoverBypass(ifs.Body) {
		return nil, false
	}
	var acc []string
	for _, bs := range ifs.Body.List {
		subGates, okSub := s.checkInactiveHookIf(bs, fn)
		if !okSub {
			return nil, false
		}
		acc = mergeGateLists(acc, subGates)
	}
	if acc == nil {
		acc = make([]string, 0)
	}
	return acc, true
}
