package toolchain

import (
	"go/ast"
	"go/token"
	"slices"
)

func (s *osInactiveState) isPureChain(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) bool {
	if s == nil {
		return false
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.Ident:
		return params[x.Name]
	case *ast.SelectorExpr:
		return s.isPureChain(x.X, fn, params)
	case *ast.UnaryExpr:
		return x.Op == token.AND && s.isPureChain(x.X, fn, params)
	case *ast.CallExpr:
		if x.Ellipsis.IsValid() || len(x.Args) != 1 {
			return false
		}
		cID, okID := unwrapParens(x.Fun).(*ast.Ident)
		if !okID || !osAllowedPureIntConversions[cID.Name] {
			return false
		}
		if s.pkgDeclCounts[cID.Name] != 0 || s.identShadowedInFunc(fn, cID.Name) {
			return false
		}
		return s.isPureChain(x.Args[0], fn, params)
	default:
		return false
	}
}

func (s *osInactiveState) isPureArg(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) bool {
	if s == nil {
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
	if s == nil {
		return false
	}
	if s.isPureChain(expr, fn, params) {
		return true
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		if x.Name == "nil" || x.Name == "true" || x.Name == "false" {
			return s.pkgDeclCounts[x.Name] == 0 && !s.identShadowedInFunc(fn, x.Name)
		}
		if s.trueConsts[x.Name] || s.falseConsts[x.Name] {
			return !s.identShadowedInFunc(fn, x.Name)
		}
	case *ast.UnaryExpr:
		return x.Op == token.NOT && s.isPureGuardExpr(x.X, fn, params)
	case *ast.BinaryExpr:
		switch x.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ, token.LAND, token.LOR:
			return s.isPureGuardExpr(x.X, fn, params) && s.isPureGuardExpr(x.Y, fn, params)
		}
	}
	return false
}

func (s *osInactiveState) evalFalseCond(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) ([]string, bool) {
	if s == nil {
		return nil, false
	}
	env := osFalseEvalEnv[[]string]{
		st: s,
		zeroDep: func() []string {
			return make([]string, 0)
		},
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
		merge: func(gL, gR []string) []string {
			merged := map[string]bool{}
			for _, g := range gL {
				merged[g] = true
			}
			for _, g := range gR {
				merged[g] = true
			}
			out := sortedKeys(merged)
			if out == nil {
				out = make([]string, 0)
			}
			return out
		},
	}
	return evalOSFalseExpr(env, expr, fn, params)
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
		if len(initAs.Lhs) == 1 && len(call.Args) == 1 {
			vID, okV := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
			if !okV || vID.Name == "" || vID.Name == "_" || vID.Name == "nil" || s.pkgDeclCounts["nil"] != 0 || s.identShadowedInFunc(fn, "nil") || condChecksNonZeroErr(inner.Cond) != vID.Name {
				return nil, false
			}
			if gates, okNA := s.nilAccessors[calleeID.Name]; okNA {
				return slices.Clone(gates), true
			}
			return nil, false
		}
		if len(initAs.Lhs) >= 2 {
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
		}
		return nil, false
	}
	if ifs.Init != nil {
		return checkInitHook(ifs)
	}
	if gates, okF := s.evalFalseCond(ifs.Cond, fn, params); okF {
		return gates, true
	}
	condID, okCID := unwrapParens(ifs.Cond).(*ast.Ident)
	if !okCID || (!s.trueConsts[condID.Name] && !(condID.Name == "true" && s.pkgDeclCounts["true"] == 0)) || s.identShadowedInFunc(fn, condID.Name) || len(ifs.Body.List) != 1 {
		return nil, false
	}
	inner, okIn := ifs.Body.List[0].(*ast.IfStmt)
	if !okIn || inner.Else != nil {
		return nil, false
	}
	if inner.Init == nil {
		return s.evalFalseCond(inner.Cond, fn, params)
	}
	return checkInitHook(inner)
}
