package toolchain

import (
	"go/ast"
	"go/token"
	"maps"
	"strconv"
	"strings"
)

func isSetLoggerTargetForBase(expr ast.Expr, base string) (*ast.Ident, bool) {
	if base == "" {
		return nil, false
	}
	u, ok := unwrapParens(expr).(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return nil, false
	}
	return isIdentNamed(u.X, base)
}

func negatedFieldOnBase(cond ast.Expr) (baseID *ast.Ident, field string, ok bool) {
	u, isNot := unwrapParens(cond).(*ast.UnaryExpr)
	if !isNot || u.Op != token.NOT {
		return nil, "", false
	}
	sel, isSel := unwrapParens(u.X).(*ast.SelectorExpr)
	if !isSel || sel.Sel.Name == "" {
		return nil, "", false
	}
	id, isID := unwrapParens(sel.X).(*ast.Ident)
	if !isID || id.Name == "" {
		return nil, "", false
	}
	return id, sel.Sel.Name, true
}

func isBufioNewWriterForW(expr ast.Expr, wSet map[string]bool) bool {
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if _, ok := isIdentNamed(sel.X, "bufio"); !ok {
		return false
	}
	switch sel.Sel.Name {
	case "NewWriter":
		if len(call.Args) != 1 {
			return false
		}
		wID, ok := unwrapParens(call.Args[0]).(*ast.Ident)
		return ok && wSet[wID.Name]
	case "NewWriterSize":
		if len(call.Args) != 2 || !isPositiveIntLit(call.Args[1]) {
			return false
		}
		wID, ok := unwrapParens(call.Args[0]).(*ast.Ident)
		return ok && wSet[wID.Name]
	default:
		return false
	}
}

func isCommentHeaderWriteCall(call *ast.CallExpr, base, field string) (*ast.Ident, bool) {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return nil, false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "WriteString" {
		return nil, false
	}
	baseID, ok := isSelectorBaseField(sel.X, base, field)
	if !ok {
		return nil, false
	}
	lit, ok := unwrapParens(call.Args[0]).(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return nil, false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil || !strings.HasPrefix(s, "#") || !strings.HasSuffix(s, "\n") || strings.Contains(s[:len(s)-1], "\n") {
		return nil, false
	}
	return baseID, true
}

func allowDeadStubIdents(nodes []ast.Node, k *PackageInactiveKernel, baseName string, wSet map[string]bool, allowedBase, allowedW map[*ast.Ident]bool) bool {
	if len(nodes) == 0 {
		return true
	}
	ok := true
	checkDeadCall := func(call *ast.CallExpr) bool {
		if call == nil || call.Ellipsis.IsValid() {
			return false
		}
		cID, okID := unwrapParens(call.Fun).(*ast.Ident)
		if !okID || k == nil {
			return false
		}
		_, isVoid := k.NoopVoidFuncs[cID.Name]
		_, isNilErr := k.NilErrFuncs[cID.Name]
		_, isEarlyF := k.EarlyFalseFuncs[cID.Name]
		if !isVoid && !isNilErr && !isEarlyF {
			return false
		}
		for _, arg := range call.Args {
			if bID, okB := isSetLoggerTargetForBase(arg, baseName); okB {
				if allowedBase != nil {
					allowedBase[bID] = true
				}
				continue
			}
			if id, okA := unwrapParens(arg).(*ast.Ident); okA {
				if wSet != nil && wSet[id.Name] && allowedW != nil {
					allowedW[id] = true
				}
				continue
			}
			return false
		}
		return true
	}
	for _, root := range nodes {
		ast.Inspect(root, func(n ast.Node) bool {
			if !ok || n == nil {
				return false
			}
			if call, isCall := n.(*ast.CallExpr); isCall {
				if checkDeadCall(call) {
					return false
				}
			}
			return true
		})
	}
	return ok
}

func verifyTestdepsStartFunc(
	fn *ast.FuncDecl,
	fileImportsTestlog, fileImportsBufio bool,
	k *PackageInactiveKernel,
	reqGates map[string]bool,
) (boundBase, boundField, muField, setField, startHelper string, allowedBaseIdents map[*ast.Ident]bool, ok bool) {
	if !fileImportsTestlog || !fileImportsBufio || fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || fn.Recv == nil || len(fn.Recv.List) != 1 || recvTypeName(fn.Recv.List[0].Type) != "TestDeps" {
		return "", "", "", "", "", nil, false
	}
	if fn.Type.Params == nil || fn.Type.Params.NumFields() != 1 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) {
		return "", "", "", "", "", nil, false
	}
	reserved := map[string]bool{"testlog": true, "bufio": true, "true": true, "false": true, "nil": true}
	if funcShadowsAnyIdent(fn, reserved) {
		return "", "", "", "", "", nil, false
	}
	paramNames := fn.Type.Params.List[0].Names
	if len(paramNames) != 1 || paramNames[0].Name == "" || paramNames[0].Name == "_" || reserved[paramNames[0].Name] {
		return "", "", "", "", "", nil, false
	}
	wName := paramNames[0].Name
	wSet := map[string]bool{wName: true}
	localDefs := map[string]bool{wName: true}
	if recv := recvVarName(fn); recv != "" {
		localDefs[recv] = true
	}

	var prunedDead []ast.Node
	prunedList := fn.Body.List
	if k != nil {
		prunedList, _ = k.PruneBlockStmts(fn.Body.List, fn, map[string]bool{wName: true}, reqGates, &prunedDead)
	}

	allowedBaseIdents = map[*ast.Ident]bool{}
	allowedWIdents := map[*ast.Ident]bool{paramNames[0]: true}
	var hasSetLoggerCall, bindsWriter, sawGuard bool

	recordMu := func(bID *ast.Ident, fName string) bool {
		if bID == nil || fName == "" || (boundBase != "" && bID.Name != boundBase) || (boundField != "" && fName == boundField) || (setField != "" && fName == setField) {
			return false
		}
		if muField != "" && muField != fName {
			return false
		}
		if boundBase == "" {
			if localDefs[bID.Name] {
				return false
			}
			boundBase = bID.Name
		}
		muField = fName
		allowedBaseIdents[bID] = true
		return true
	}

	var walkStmts func(stmts []ast.Stmt, inGuard bool) bool
	walkStmts = func(stmts []ast.Stmt, inGuard bool) bool {
		for idx, stmt := range stmts {
			switch s := stmt.(type) {
			case *ast.EmptyStmt:
				continue
			case *ast.ReturnStmt:
				if inGuard || len(s.Results) != 0 || idx != len(stmts)-1 {
					return false
				}
			case *ast.DeferStmt:
				sel, ok := unwrapParens(s.Call.Fun).(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Unlock" || s.Call.Ellipsis.IsValid() || len(s.Call.Args) != 0 {
					return false
				}
				muSel, ok := unwrapParens(sel.X).(*ast.SelectorExpr)
				if !ok {
					return false
				}
				bID, ok := unwrapParens(muSel.X).(*ast.Ident)
				if !ok || !recordMu(bID, muSel.Sel.Name) {
					return false
				}
			case *ast.DeclStmt:
				gd, ok := s.Decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					return false
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || (len(vs.Values) != 0 && len(vs.Values) != len(vs.Names)) {
						return false
					}
					for i, nameID := range vs.Names {
						if nameID.Name == "" || nameID.Name == "_" || wSet[nameID.Name] || (boundBase != "" && nameID.Name == boundBase) {
							return false
						}
						if i < len(vs.Values) {
							if exprReferencesDiscard(vs.Values[i]) {
								return false
							}
							if rhsID, ok := unwrapParens(vs.Values[i]).(*ast.Ident); ok && wSet[rhsID.Name] {
								if inGuard {
									return false
								}
								allowedWIdents[nameID] = true
								allowedWIdents[rhsID] = true
								wSet[nameID.Name] = true
							} else if exprReferencesAnyIdent(vs.Values[i], wSet) {
								return false
							}
						}
						localDefs[nameID.Name] = true
					}
				}
			case *ast.AssignStmt:
				if len(s.Lhs) != 1 || len(s.Rhs) != 1 || exprReferencesDiscard(s.Rhs[0]) {
					return false
				}
				switch s.Tok {
				case token.DEFINE:
					id, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
					if !ok || id.Name == "" || id.Name == "_" || wSet[id.Name] || (boundBase != "" && id.Name == boundBase) {
						return false
					}
					if rhsID, ok := unwrapParens(s.Rhs[0]).(*ast.Ident); ok && wSet[rhsID.Name] {
						if inGuard {
							return false
						}
						allowedWIdents[id] = true
						allowedWIdents[rhsID] = true
						wSet[id.Name] = true
					} else if exprReferencesAnyIdent(s.Rhs[0], wSet) {
						return false
					}
					localDefs[id.Name] = true
				case token.ASSIGN:
					sel, ok := unwrapParens(s.Lhs[0]).(*ast.SelectorExpr)
					if !ok || sel.Sel.Name == "" {
						return false
					}
					baseID, ok := unwrapParens(sel.X).(*ast.Ident)
					if !ok || baseID.Name == "" || baseID.Name == "_" || localDefs[baseID.Name] {
						return false
					}
					if inGuard {
						if !bindsWriter || setField == "" || baseID.Name != boundBase || sel.Sel.Name != setField {
							return false
						}
						if _, ok := isIdentNamed(s.Rhs[0], "true"); !ok {
							return false
						}
						allowedBaseIdents[baseID] = true
						continue
					}
					if bindsWriter || !isBufioNewWriterForW(s.Rhs[0], wSet) {
						return false
					}
					if (boundBase != "" && baseID.Name != boundBase) || (muField != "" && sel.Sel.Name == muField) {
						return false
					}
					call := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
					allowedWIdents[unwrapParens(call.Args[0]).(*ast.Ident)] = true
					boundBase = baseID.Name
					boundField = sel.Sel.Name
					bindsWriter = true
					allowedBaseIdents[baseID] = true
				default:
					return false
				}
			case *ast.ExprStmt:
				call, ok := unwrapParens(s.X).(*ast.CallExpr)
				if !ok {
					return false
				}
				if hID, okH := unwrapParens(call.Fun).(*ast.Ident); okH && !inGuard && bindsWriter && hasSetLoggerCall && startHelper == "" && !call.Ellipsis.IsValid() && len(call.Args) == 2 && !localDefs[hID.Name] {
					bID, okB := isSetLoggerTargetForBase(call.Args[0], boundBase)
					wID, okW := unwrapParens(call.Args[1]).(*ast.Ident)
					if okB && okW && wSet[wID.Name] {
						startHelper = hID.Name
						allowedBaseIdents[bID] = true
						allowedWIdents[wID] = true
						continue
					}
				}
				sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
				if !ok {
					return false
				}
				if sel.Sel.Name == "SetLogger" {
					if _, ok := isIdentNamed(sel.X, "testlog"); !ok || call.Ellipsis.IsValid() || len(call.Args) != 1 || !bindsWriter || hasSetLoggerCall {
						return false
					}
					bID, ok := isSetLoggerTargetForBase(call.Args[0], boundBase)
					if !ok {
						return false
					}
					allowedBaseIdents[bID] = true
					hasSetLoggerCall = true
					continue
				}
				if (sel.Sel.Name == "Lock" || sel.Sel.Name == "Unlock") && !inGuard && !call.Ellipsis.IsValid() && len(call.Args) == 0 {
					muSel, ok := unwrapParens(sel.X).(*ast.SelectorExpr)
					if !ok {
						return false
					}
					bID, ok := unwrapParens(muSel.X).(*ast.Ident)
					if !ok || !recordMu(bID, muSel.Sel.Name) {
						return false
					}
					continue
				}
				if bID, ok := isCommentHeaderWriteCall(call, boundBase, boundField); ok && bindsWriter {
					allowedBaseIdents[bID] = true
					continue
				}
				return false
			case *ast.IfStmt:
				if inGuard || sawGuard || !bindsWriter || s.Init != nil || s.Else != nil {
					return false
				}
				gBaseID, gField, ok := negatedFieldOnBase(s.Cond)
				if !ok || gBaseID.Name != boundBase || gField == boundField || (muField != "" && gField == muField) {
					return false
				}
				setField = gField
				sawGuard = true
				allowedBaseIdents[gBaseID] = true
				if !walkStmts(s.Body.List, true) {
					return false
				}
			case *ast.BlockStmt:
				if !walkStmts(s.List, inGuard) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}

	if !walkStmts(prunedList, false) || !bindsWriter || !hasSetLoggerCall || boundBase == "" || boundField == "" {
		return "", "", "", "", "", nil, false
	}
	if !allowDeadStubIdents(prunedDead, k, boundBase, wSet, allowedBaseIdents, allowedWIdents) {
		return "", "", "", "", "", nil, false
	}

	var invalid bool
	walkNonSelectorPropIdents(fn.Body, func(id *ast.Ident) {
		if wSet[id.Name] && !allowedWIdents[id] {
			invalid = true
		}
		if id.Name == boundBase && !allowedBaseIdents[id] {
			invalid = true
		}
	})
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if invalid || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit, *ast.GoStmt, *ast.LabeledStmt, *ast.BranchStmt:
			invalid = true
			return false
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				if id, ok := unwrapParens(node.X).(*ast.Ident); ok && wSet[id.Name] {
					invalid = true
					return false
				}
			}
		}
		return true
	})
	if invalid {
		return "", "", "", "", "", nil, false
	}
	return boundBase, boundField, muField, setField, startHelper, allowedBaseIdents, true
}

func isTargetSinkFlushCall(expr ast.Expr, boundBase, boundField string) (*ast.Ident, bool) {
	if boundBase == "" || boundField == "" {
		return nil, false
	}
	return isZeroArgMethodCallOnSelector(expr, boundBase, boundField, "Flush")
}

func verifyTestdepsStopFunc(
	fn *ast.FuncDecl,
	boundBase, boundField, muField string,
	k *PackageInactiveKernel,
	reqGates map[string]bool,
) (stopHelper string, allowedBaseIdents map[*ast.Ident]bool, ok bool) {
	if boundBase == "" || boundField == "" || fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || fn.Recv == nil || len(fn.Recv.List) != 1 || recvTypeName(fn.Recv.List[0].Type) != "TestDeps" {
		return "", nil, false
	}
	if (fn.Type.Params != nil && fn.Type.Params.NumFields() != 0) || fn.Type.Results == nil || fn.Type.Results.NumFields() != 1 || !funcReturnsErrorLast(fn.Type) {
		return "", nil, false
	}
	if funcShadowsAnyIdent(fn, map[string]bool{boundBase: true, "nil": true, "error": true}) {
		return "", nil, false
	}
	var prunedDead []ast.Node
	prunedList := fn.Body.List
	if k != nil {
		prunedList, _ = k.PruneBlockStmts(fn.Body.List, fn, nil, reqGates, &prunedDead)
	}
	cfg, okCFG := BuildStmtCFG(prunedList)
	if !okCFG || !cfg.EveryPathReturns() {
		return "", nil, false
	}

	namedErr := lastNamedResultIdent(fn.Type.Results)
	type stopPathState struct {
		flushed     bool
		clearedNil  bool
		flushErrVar string
	}
	allFlushErrVars := map[string]bool{}
	outerDeclaredErrVars := map[string]bool{}
	if namedErr != "" {
		outerDeclaredErrVars[namedErr] = true
	}
	allowedBaseIdents = map[*ast.Ident]bool{}
	var sawPropagatedReturn bool

	checkMuLockUnlock := func(call *ast.CallExpr, allowLock bool) bool {
		if muField == "" || call == nil || call.Ellipsis.IsValid() || len(call.Args) != 0 {
			return false
		}
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Unlock" && (!allowLock || sel.Sel.Name != "Lock")) {
			return false
		}
		bID, ok := isSelectorBaseField(sel.X, boundBase, muField)
		if !ok {
			return false
		}
		allowedBaseIdents[bID] = true
		return true
	}

	var walkStmts func(stmts []ast.Stmt, st stopPathState, depth int) (stopPathState, bool)
	walkStmts = func(stmts []ast.Stmt, st stopPathState, depth int) (stopPathState, bool) {
		for idx, stmt := range stmts {
			if idx != len(stmts)-1 && blockAlwaysReturns([]ast.Stmt{stmt}) {
				return st, false
			}
			switch s := stmt.(type) {
			case *ast.EmptyStmt:
				continue
			case *ast.ExprStmt:
				call, ok := unwrapParens(s.X).(*ast.CallExpr)
				if !ok || !checkMuLockUnlock(call, true) {
					return st, false
				}
			case *ast.DeferStmt:
				if !checkMuLockUnlock(s.Call, false) {
					return st, false
				}
			case *ast.AssignStmt:
				if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
					return st, false
				}
				if bID, ok := isTargetSinkFlushCall(s.Rhs[0], boundBase, boundField); ok {
					if st.flushed || (s.Tok != token.DEFINE && s.Tok != token.ASSIGN) {
						return st, false
					}
					id, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
					if !ok || id.Name == "" || id.Name == "_" || id.Name == boundBase || (allFlushErrVars[id.Name] && id.Name != namedErr) {
						return st, false
					}
					if s.Tok == token.DEFINE {
						if depth > 0 && outerDeclaredErrVars[id.Name] {
							return st, false
						}
						if depth == 0 {
							outerDeclaredErrVars[id.Name] = true
						}
					} else if !outerDeclaredErrVars[id.Name] {
						return st, false
					}
					allowedBaseIdents[bID] = true
					allFlushErrVars[id.Name] = true
					st.flushed = true
					st.flushErrVar = id.Name
					continue
				}
				if st.flushed && !st.clearedNil && s.Tok == token.ASSIGN {
					if bID, ok := isSelectorBaseField(s.Lhs[0], boundBase, boundField); ok {
						if _, isNil := isIdentNamed(s.Rhs[0], "nil"); isNil {
							allowedBaseIdents[bID] = true
							st.clearedNil = true
							continue
						}
					}
				}
				return st, false
			case *ast.IfStmt:
				if st.flushed && st.clearedNil && stopHelper == "" && s.Init != nil && s.Else == nil && len(s.Body.List) == 1 {
					initAs, okIn := s.Init.(*ast.AssignStmt)
					bodyAs, okBd := s.Body.List[0].(*ast.AssignStmt)
					if okIn && initAs.Tok == token.DEFINE && len(initAs.Lhs) != 0 && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 && okBd && bodyAs.Tok == token.ASSIGN && len(bodyAs.Lhs) == 1 && len(bodyAs.Rhs) == 1 && condChecksEqErr(s.Cond, st.flushErrVar) {
						berrID, okB1 := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
						hCall, okHC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
						if okB1 && berrID.Name != "" && berrID.Name != "_" && berrID.Name != st.flushErrVar && !allFlushErrVars[berrID.Name] && okHC && !hCall.Ellipsis.IsValid() && len(hCall.Args) == 1 {
							hID, okHID := unwrapParens(hCall.Fun).(*ast.Ident)
							bID, okTgt := isSetLoggerTargetForBase(hCall.Args[0], boundBase)
							_, okLHS := isIdentNamed(bodyAs.Lhs[0], st.flushErrVar)
							_, okRHS := isIdentNamed(bodyAs.Rhs[0], berrID.Name)
							if okHID && okTgt && okLHS && okRHS {
								stopHelper = hID.Name
								allowedBaseIdents[bID] = true
								allFlushErrVars[berrID.Name] = true
								continue
							}
						}
					}
				}
				return st, false
			case *ast.DeclStmt:
				gd, ok := s.Decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					return st, false
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						return st, false
					}
					if len(vs.Values) == 1 {
						if bID, ok := isTargetSinkFlushCall(vs.Values[0], boundBase, boundField); ok {
							if st.flushed || len(vs.Names) != 1 || vs.Names[0].Name == "" || vs.Names[0].Name == "_" || vs.Names[0].Name == boundBase || allFlushErrVars[vs.Names[0].Name] || outerDeclaredErrVars[vs.Names[0].Name] {
								return st, false
							}
							if depth == 0 {
								outerDeclaredErrVars[vs.Names[0].Name] = true
							}
							allowedBaseIdents[bID] = true
							allFlushErrVars[vs.Names[0].Name] = true
							st.flushed = true
							st.flushErrVar = vs.Names[0].Name
							continue
						}
					}
					if len(vs.Values) != 0 {
						return st, false
					}
					for _, id := range vs.Names {
						if id.Name == "" || id.Name == "_" || id.Name == boundBase || allFlushErrVars[id.Name] || (st.flushErrVar != "" && id.Name == st.flushErrVar) || outerDeclaredErrVars[id.Name] {
							return st, false
						}
						if depth == 0 {
							outerDeclaredErrVars[id.Name] = true
						}
					}
				}
			case *ast.BlockStmt:
				subSt, ok := walkStmts(s.List, st, depth+1)
				if !ok {
					return st, false
				}
				if !blockAlwaysReturns(s.List) && subSt.flushErrVar != "" && !outerDeclaredErrVars[subSt.flushErrVar] {
					return st, false
				}
				st = subSt
			case *ast.ReturnStmt:
				if !st.flushed || !st.clearedNil {
					return st, false
				}
				if len(s.Results) == 0 {
					if namedErr == "" || st.flushErrVar != namedErr {
						return st, false
					}
					sawPropagatedReturn = true
					continue
				}
				if len(s.Results) != 1 {
					return st, false
				}
				if id, ok := unwrapParens(s.Results[0]).(*ast.Ident); ok && st.flushErrVar != "" && id.Name == st.flushErrVar {
					sawPropagatedReturn = true
					continue
				}
				return st, false
			default:
				return st, false
			}
		}
		return st, true
	}

	if _, ok := walkStmts(prunedList, stopPathState{}, 0); !ok || !sawPropagatedReturn {
		return "", nil, false
	}
	if !allowDeadStubIdents(prunedDead, k, boundBase, nil, allowedBaseIdents, nil) {
		return "", nil, false
	}

	protectedErrs := map[string]bool{boundBase: true}
	if namedErr != "" {
		protectedErrs[namedErr] = true
	}
	maps.Copy(protectedErrs, allFlushErrVars)
	var bad bool
	walkNonSelectorPropIdents(fn.Body, func(id *ast.Ident) {
		if id.Name == boundBase && !allowedBaseIdents[id] {
			bad = true
		}
	})
	prunedBody := &ast.BlockStmt{List: prunedList}
	ast.Inspect(prunedBody, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit, *ast.GoStmt, *ast.LabeledStmt, *ast.BranchStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			bad = true
			return false
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name != boundBase && protectedErrs[id.Name] {
					bad = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if id, ok := unwrapParens(node.X).(*ast.Ident); ok && protectedErrs[id.Name] {
				bad = true
				return false
			}
		}
		return true
	})
	if bad {
		return "", nil, false
	}
	return stopHelper, allowedBaseIdents, true
}
