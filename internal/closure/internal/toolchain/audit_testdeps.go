package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
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

func verifyTestdepsStartFunc(fn *ast.FuncDecl, fileImportsTestlog, fileImportsBufio bool) (boundBase, boundField, muField, setField string, allowedBaseIdents map[*ast.Ident]bool, ok bool) {
	if !fileImportsTestlog || !fileImportsBufio || fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || fn.Recv == nil || len(fn.Recv.List) != 1 || recvTypeName(fn.Recv.List[0].Type) != "TestDeps" {
		return "", "", "", "", nil, false
	}
	if fn.Type.Params == nil || fn.Type.Params.NumFields() != 1 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) {
		return "", "", "", "", nil, false
	}
	reserved := map[string]bool{"testlog": true, "bufio": true, "true": true, "false": true, "nil": true}
	if funcShadowsAnyIdent(fn, reserved) {
		return "", "", "", "", nil, false
	}
	paramNames := fn.Type.Params.List[0].Names
	if len(paramNames) != 1 || paramNames[0].Name == "" || paramNames[0].Name == "_" || reserved[paramNames[0].Name] {
		return "", "", "", "", nil, false
	}
	wName := paramNames[0].Name
	wSet := map[string]bool{wName: true}
	localDefs := map[string]bool{wName: true}
	if recv := recvVarName(fn); recv != "" {
		localDefs[recv] = true
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

	if !walkStmts(fn.Body.List, false) || !bindsWriter || !hasSetLoggerCall || boundBase == "" || boundField == "" {
		return "", "", "", "", nil, false
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
		return "", "", "", "", nil, false
	}
	return boundBase, boundField, muField, setField, allowedBaseIdents, true
}

func isTargetSinkFlushCall(expr ast.Expr, boundBase, boundField string) (*ast.Ident, bool) {
	if boundBase == "" || boundField == "" {
		return nil, false
	}
	return isZeroArgMethodCallOnSelector(expr, boundBase, boundField, "Flush")
}

func verifyTestdepsStopFunc(fn *ast.FuncDecl, boundBase, boundField, muField string) (map[*ast.Ident]bool, bool) {
	if boundBase == "" || boundField == "" || fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || fn.Recv == nil || len(fn.Recv.List) != 1 || recvTypeName(fn.Recv.List[0].Type) != "TestDeps" {
		return nil, false
	}
	if (fn.Type.Params != nil && fn.Type.Params.NumFields() != 0) || fn.Type.Results == nil || fn.Type.Results.NumFields() != 1 || !funcReturnsErrorLast(fn.Type) {
		return nil, false
	}
	if funcShadowsAnyIdent(fn, map[string]bool{boundBase: true, "nil": true, "error": true}) || !blockAlwaysReturns(fn.Body.List) {
		return nil, false
	}
	namedErr := lastNamedResultIdent(fn.Type.Results)
	type stopPathState struct {
		flushed     bool
		clearedNil  bool
		flushErrVar string
	}
	allFlushErrVars := map[string]bool{}
	allowedBaseIdents := map[*ast.Ident]bool{}
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

	var walkStmts func(stmts []ast.Stmt, st stopPathState) (stopPathState, bool)
	walkStmts = func(stmts []ast.Stmt, st stopPathState) (stopPathState, bool) {
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
					allowedBaseIdents[bID] = true
					allFlushErrVars[id.Name] = true
					st.flushed = true
					st.flushErrVar = id.Name
					continue
				}
				// Require `log.w = nil` AFTER `log.w.Flush()` has already run on this path.
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
							if st.flushed || len(vs.Names) != 1 || vs.Names[0].Name == "" || vs.Names[0].Name == "_" || vs.Names[0].Name == boundBase || allFlushErrVars[vs.Names[0].Name] || (namedErr != "" && vs.Names[0].Name == namedErr) {
								return st, false
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
						if id.Name == boundBase || allFlushErrVars[id.Name] || (st.flushErrVar != "" && id.Name == st.flushErrVar) || (namedErr != "" && id.Name == namedErr) {
							return st, false
						}
					}
				}
			case *ast.BlockStmt:
				var ok bool
				st, ok = walkStmts(s.List, st)
				if !ok {
					return st, false
				}
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
				res := unwrapParens(s.Results[0])
				if id, ok := res.(*ast.Ident); ok && st.flushErrVar != "" && id.Name == st.flushErrVar {
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

	if _, ok := walkStmts(fn.Body.List, stopPathState{}); !ok || !sawPropagatedReturn {
		return nil, false
	}

	protectedErrs := map[string]bool{boundBase: true}
	if namedErr != "" {
		protectedErrs[namedErr] = true
	}
	for k := range allFlushErrVars {
		protectedErrs[k] = true
	}
	var bad bool
	walkNonSelectorPropIdents(fn.Body, func(id *ast.Ident) {
		if id.Name == boundBase && !allowedBaseIdents[id] {
			bad = true
		}
	})
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit, *ast.GoStmt, *ast.LabeledStmt, *ast.BranchStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
			bad = true
			return false
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				if id, ok := unwrapParens(node.X).(*ast.Ident); ok && protectedErrs[id.Name] {
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
	if invalid := bad; invalid {
		return nil, false
	}
	return allowedBaseIdents, true
}

func verifyTestdepsLoggerMethods(loggerType, boundField, muField string, methods map[string]*ast.FuncDecl, methodFiles map[*ast.FuncDecl]*ast.File, fileImportsStrings map[*ast.File]bool) bool {
	if len(methods) != 5 {
		return false
	}
	reserved := map[string]bool{"strings": true, "nil": true, "string": true}
	wantOps := map[string]string{
		"Getenv": "getenv",
		"Open":   "open",
		"Stat":   "stat",
		"Chdir":  "chdir",
	}
	for mName, wantOp := range wantOps {
		fn := methods[mName]
		if fn == nil || fn.Body == nil || fn.Type.TypeParams != nil || fn.Recv == nil || len(fn.Recv.List) != 1 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) || len(fn.Body.List) != 1 || funcShadowsAnyIdent(fn, reserved) {
			return false
		}
		star, ok := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr)
		if !ok {
			return false
		}
		if _, ok := isIdentNamed(star.X, loggerType); !ok {
			return false
		}
		recv := recvVarName(fn)
		pNames := paramNamesFlat(fn.Type.Params)
		if recv == "" || len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || pNames[0] == recv || len(fn.Type.Params.List) != 1 {
			return false
		}
		if _, ok := isIdentNamed(fn.Type.Params.List[0].Type, "string"); !ok {
			return false
		}
		es, ok := fn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := unwrapParens(es.X).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 2 {
			return false
		}
		if _, ok := isSelectorBaseField(call.Fun, recv, "add"); !ok {
			return false
		}
		lit, ok := unwrapParens(call.Args[0]).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		if s, err := strconv.Unquote(lit.Value); err != nil || s != wantOp {
			return false
		}
		if _, ok := isIdentNamed(call.Args[1], pNames[0]); !ok {
			return false
		}
	}

	// Verify (l *testLog) add(op, name string)
	addFn := methods["add"]
	if addFn == nil || addFn.Body == nil || !fileImportsStrings[methodFiles[addFn]] || addFn.Type.TypeParams != nil || addFn.Recv == nil || len(addFn.Recv.List) != 1 || (addFn.Type.Results != nil && addFn.Type.Results.NumFields() != 0) || funcShadowsAnyIdent(addFn, reserved) {
		return false
	}
	star, ok := unwrapParens(addFn.Recv.List[0].Type).(*ast.StarExpr)
	if !ok {
		return false
	}
	if _, ok := isIdentNamed(star.X, loggerType); !ok {
		return false
	}
	recv := recvVarName(addFn)
	pNames := paramNamesFlat(addFn.Type.Params)
	if recv == "" || len(pNames) != 2 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || pNames[0] == pNames[1] || pNames[0] == recv || pNames[1] == recv {
		return false
	}
	for _, fld := range addFn.Type.Params.List {
		if _, ok := isIdentNamed(fld.Type, "string"); !ok {
			return false
		}
	}
	opParam, nameParam := pNames[0], pNames[1]
	if bodyDeclaresAnyIdent(addFn.Body, map[string]bool{recv: true, opParam: true, nameParam: true}) {
		return false
	}

	stmts := addFn.Body.List
	if len(stmts) < 6 {
		return false
	}
	// Stmt 0: if strings.Contains(name, "\n") || name == "" { return }
	isContainsNewline := func(e ast.Expr) bool {
		c, ok := unwrapParens(e).(*ast.CallExpr)
		if !ok || c.Ellipsis.IsValid() || len(c.Args) != 2 {
			return false
		}
		if _, ok := isSelectorBaseField(c.Fun, "strings", "Contains"); !ok {
			return false
		}
		if _, ok := isIdentNamed(c.Args[0], nameParam); !ok {
			return false
		}
		lit, ok := unwrapParens(c.Args[1]).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		v, err := strconv.Unquote(lit.Value)
		return err == nil && v == "\n"
	}
	isEmptyNameEq := func(e ast.Expr) bool {
		b, ok := unwrapParens(e).(*ast.BinaryExpr)
		if !ok || b.Op != token.EQL {
			return false
		}
		check := func(x, y ast.Expr) bool {
			if _, ok := isIdentNamed(x, nameParam); !ok {
				return false
			}
			lit, ok := unwrapParens(y).(*ast.BasicLit)
			return ok && lit.Kind == token.STRING && (lit.Value == `""` || lit.Value == "``")
		}
		return check(b.X, b.Y) || check(b.Y, b.X)
	}
	isEmptyReturnIf := func(s ast.Stmt) (*ast.IfStmt, bool) {
		ifs, ok := s.(*ast.IfStmt)
		if !ok || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
			return nil, false
		}
		ret, ok := ifs.Body.List[0].(*ast.ReturnStmt)
		return ifs, ok && len(ret.Results) == 0
	}

	s0If, ok := isEmptyReturnIf(stmts[0])
	if !ok {
		return false
	}
	orCond, ok := unwrapParens(s0If.Cond).(*ast.BinaryExpr)
	if !ok || orCond.Op != token.LOR || !((isContainsNewline(orCond.X) && isEmptyNameEq(orCond.Y)) || (isEmptyNameEq(orCond.X) && isContainsNewline(orCond.Y))) {
		return false
	}

	pos := 1
	if muField != "" {
		if pos+2 > len(stmts) {
			return false
		}
		lockES, ok1 := stmts[pos].(*ast.ExprStmt)
		deferUnlock, ok2 := stmts[pos+1].(*ast.DeferStmt)
		if !ok1 || !ok2 {
			return false
		}
		if _, ok := isZeroArgMethodCallOnSelector(lockES.X, recv, muField, "Lock"); !ok {
			return false
		}
		if _, ok := isZeroArgMethodCallOnSelector(deferUnlock.Call, recv, muField, "Unlock"); !ok {
			return false
		}
		pos += 2
	}
	if len(stmts)-pos != 5 {
		return false
	}
	// if l.w == nil { return }
	nilIf, ok := isEmptyReturnIf(stmts[pos])
	if !ok {
		return false
	}
	eqCond, ok := unwrapParens(nilIf.Cond).(*ast.BinaryExpr)
	if !ok || eqCond.Op != token.EQL {
		return false
	}
	checkNilWriter := func(x, y ast.Expr) bool {
		_, ok1 := isSelectorBaseField(x, recv, boundField)
		_, ok2 := isIdentNamed(y, "nil")
		return ok1 && ok2
	}
	if !checkNilWriter(eqCond.X, eqCond.Y) && !checkNilWriter(eqCond.Y, eqCond.X) {
		return false
	}
	pos++

	checkWriteIdent := func(s ast.Stmt, wantIdent string) bool {
		es, ok := s.(*ast.ExprStmt)
		if !ok {
			return false
		}
		c, ok := unwrapParens(es.X).(*ast.CallExpr)
		if !ok || c.Ellipsis.IsValid() || len(c.Args) != 1 {
			return false
		}
		sel, ok := unwrapParens(c.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WriteString" {
			return false
		}
		if _, ok := isSelectorBaseField(sel.X, recv, boundField); !ok {
			return false
		}
		_, ok = isIdentNamed(c.Args[0], wantIdent)
		return ok
	}
	checkWriteConstByte := func(s ast.Stmt, want byte) bool {
		es, ok := s.(*ast.ExprStmt)
		if !ok {
			return false
		}
		c, ok := unwrapParens(es.X).(*ast.CallExpr)
		if !ok || c.Ellipsis.IsValid() || len(c.Args) != 1 {
			return false
		}
		sel, ok := unwrapParens(c.Fun).(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if _, ok := isSelectorBaseField(sel.X, recv, boundField); !ok {
			return false
		}
		lit, ok := unwrapParens(c.Args[0]).(*ast.BasicLit)
		if !ok {
			return false
		}
		switch sel.Sel.Name {
		case "WriteByte":
			if lit.Kind != token.CHAR {
				return false
			}
			v, _, tail, err := strconv.UnquoteChar(strings.Trim(lit.Value, "'"), '\'')
			return err == nil && tail == "" && v == rune(want)
		case "WriteString":
			if lit.Kind != token.STRING {
				return false
			}
			v, err := strconv.Unquote(lit.Value)
			return err == nil && len(v) == 1 && v[0] == want
		default:
			return false
		}
	}

	return checkWriteIdent(stmts[pos], opParam) &&
		checkWriteConstByte(stmts[pos+1], ' ') &&
		checkWriteIdent(stmts[pos+2], nameParam) &&
		checkWriteConstByte(stmts[pos+3], '\n')
}

// VerifyTestdepsPackageAST verifies the structural contract of
// package testing/internal/testdeps (TestDeps, StartTestLog, StopTestLog,
// and logger record formatting).
func VerifyTestdepsPackageAST(files []*ast.File) error {
	reserved := map[string]bool{
		"testlog": true, "bufio": true, "strings": true, "sync": true,
		"panic": true, "recover": true, "nil": true, "true": true, "false": true,
	}
	idx, err := indexPackageAST("testing/internal/testdeps", files, reserved, map[string]bool{
		"internal/testlog": true, "bufio": true, "strings": true, "sync": true,
	})
	if err != nil {
		return err
	}
	startFns := idx.funcDeclsByName["StartTestLog"]
	stopFns := idx.funcDeclsByName["StopTestLog"]
	if idx.hasInitFunc || len(idx.bodylessFuncs) > 0 || idx.anyDupTypeMethod || len(idx.dupTopFuncs) > 0 || !idx.hasAnyImport("internal/testlog") || len(startFns) != 1 || len(stopFns) != 1 {
		return fmt.Errorf("testing/internal/testdeps: incomplete or duplicate testlog harness declarations")
	}
	fileImportsBufio := idx.fileImportSet("bufio")
	fileImportsStrings := idx.fileImportSet("strings")
	fileImportsSync := idx.fileImportSet("sync")

	// Verify TestDeps is an empty struct.
	if _, _, ok := idx.VerifyStructFields("TestDeps", nil, false); !ok {
		return fmt.Errorf("testing/internal/testdeps: missing or non-empty TestDeps struct")
	}

	startFn, stopFn := startFns[0], stopFns[0]
	boundBase, boundField, muField, setField, startAllowedBase, ok := verifyTestdepsStartFunc(startFn, idx.hasFileImport(idx.funcFile[startFn], "internal/testlog"), fileImportsBufio[idx.funcFile[startFn]])
	if !ok {
		return fmt.Errorf("testing/internal/testdeps: StartTestLog does not wire bufio.NewWriter and testlog.SetLogger")
	}
	stopAllowedBase, ok := verifyTestdepsStopFunc(stopFn, boundBase, boundField, muField)
	if !ok {
		return fmt.Errorf("testing/internal/testdeps: StopTestLog does not flush %s.%s and propagate error", boundBase, boundField)
	}

	allowedBaseIdents := map[*ast.Ident]bool{}
	for id := range startAllowedBase {
		allowedBaseIdents[id] = true
	}
	for id := range stopAllowedBase {
		allowedBaseIdents[id] = true
	}

	// Locate zero-initialized `var <boundBase> <loggerType>` and verify <loggerType>.
	var loggerType string
	allowedLoggerTypeIdents := map[*ast.Ident]bool{}
	if idx.pkgVarCounts[boundBase] != 1 {
		return fmt.Errorf("testing/internal/testdeps: missing unique var %s declaration", boundBase)
	}
	vs := idx.zeroInitPkgVars[boundBase]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 0 {
		return fmt.Errorf("testing/internal/testdeps: %s must be a zero-initialized package variable", boundBase)
	}
	tID, ok := unwrapParens(vs.Type).(*ast.Ident)
	if !ok || tID.Name == "" || ast.IsExported(tID.Name) {
		return fmt.Errorf("testing/internal/testdeps: %s must have an unexported named logger struct type", boundBase)
	}
	loggerType = tID.Name
	for id := range idx.varDeclIdents[boundBase] {
		allowedBaseIdents[id] = true
	}
	allowedLoggerTypeIdents[tID] = true

	lSpec := idx.uniqueTypeSpec(loggerType)
	if lSpec == nil {
		return fmt.Errorf("testing/internal/testdeps: invalid logger struct %s", loggerType)
	}
	allowedLoggerTypeIdents[lSpec.Name] = true
	requiredLoggerFields := map[string]func(ast.Expr) bool{
		boundField: func(e ast.Expr) bool {
			wStar, ok := unwrapParens(e).(*ast.StarExpr)
			if !ok {
				return false
			}
			_, ok = isSelectorBaseField(wStar.X, "bufio", "Writer")
			return ok
		},
	}
	if muField != "" {
		requiredLoggerFields[muField] = func(e ast.Expr) bool {
			_, ok := isSelectorBaseField(e, "sync", "Mutex")
			return ok
		}
	}
	if setField != "" {
		requiredLoggerFields[setField] = func(e ast.Expr) bool {
			_, ok := isIdentNamed(e, "bool")
			return ok
		}
	}
	_, lFile, ok := idx.VerifyStructFields(loggerType, requiredLoggerFields, true)
	if !ok || !fileImportsBufio[lFile] || (muField != "" && !fileImportsSync[lFile]) {
		return fmt.Errorf("testing/internal/testdeps: invalid logger struct %s", loggerType)
	}

	lMethods := idx.typeMethods[loggerType]
	for _, m := range lMethods {
		if rID := recvTypeIdent(m.Recv.List[0].Type); rID != nil && rID.Name == loggerType {
			allowedLoggerTypeIdents[rID] = true
		}
	}
	if !verifyTestdepsLoggerMethods(loggerType, boundField, muField, lMethods, idx.funcFile, fileImportsStrings) {
		return fmt.Errorf("testing/internal/testdeps: %s methods do not faithfully format testlog records", loggerType)
	}

	// Ensure neither <boundBase> nor <loggerType> is referenced anywhere else in testing/internal/testdeps.
	if !allNonSelectorPropIdentsIn(files, map[string]map[*ast.Ident]bool{
		boundBase:  allowedBaseIdents,
		loggerType: allowedLoggerTypeIdents,
	}) {
		return fmt.Errorf("testing/internal/testdeps: %s or %s referenced outside StartTestLog/StopTestLog", boundBase, loggerType)
	}
	return nil
}
