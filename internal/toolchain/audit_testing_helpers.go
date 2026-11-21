package toolchain

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

func localLogFileIdent(expr ast.Expr) (string, bool) {
	id, ok := unwrapParens(expr).(*ast.Ident)
	if !ok || id.Name == "" || id.Name == "_" || id.Name == "nil" || id.Name == "Discard" {
		return "", false
	}
	return id.Name, true
}

func derefFlagNonEmptyCondIdent(cond ast.Expr) (string, bool) {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return "", false
	}
	checkPair := func(ptrExpr, strExpr ast.Expr) (string, bool) {
		lit, ok := unwrapParens(strExpr).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || (lit.Value != `""` && lit.Value != "``") {
			return "", false
		}
		star, ok := unwrapParens(ptrExpr).(*ast.StarExpr)
		if !ok {
			return "", false
		}
		id, ok := unwrapParens(star.X).(*ast.Ident)
		if !ok || id.Name == "" || id.Name == "_" {
			return "", false
		}
		return id.Name, true
	}
	if name, ok := checkPair(bin.X, bin.Y); ok {
		return name, true
	}
	return checkPair(bin.Y, bin.X)
}

func isBenignStderrDiagStmt(stmt ast.Stmt, hasOSImport, hasFmtImport bool) bool {
	switch s := stmt.(type) {
	case *ast.EmptyStmt:
		return true
	case *ast.ExprStmt:
		if !hasOSImport || !hasFmtImport {
			return false
		}
		call, ok := unwrapParens(s.X).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) < 2 {
			return false
		}
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Fprint" && sel.Sel.Name != "Fprintf" && sel.Sel.Name != "Fprintln") {
			return false
		}
		pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
		if !ok || pkgID.Name != "fmt" {
			return false
		}
		arg0Sel, ok := unwrapParens(call.Args[0]).(*ast.SelectorExpr)
		if !ok || arg0Sel.Sel.Name != "Stderr" {
			return false
		}
		osID, ok := unwrapParens(arg0Sel.X).(*ast.Ident)
		if !ok || osID.Name != "os" {
			return false
		}
		for _, arg := range call.Args {
			if exprHasCallOrFuncLit(arg) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isFailureForcingExitOrPanicStmt(stmt ast.Stmt, errVar string, hasOSImport bool) bool {
	es, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := unwrapParens(es.X).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 1 || exprHasCallOrFuncLit(call.Args[0]) {
		return false
	}
	switch fun := unwrapParens(call.Fun).(type) {
	case *ast.SelectorExpr:
		id, ok := unwrapParens(fun.X).(*ast.Ident)
		return ok && id.Name == "os" && fun.Sel.Name == "Exit" && hasOSImport && isPositiveIntLit(call.Args[0])
	case *ast.Ident:
		if fun.Name != "panic" {
			return false
		}
		arg := unwrapParens(call.Args[0])
		if id, ok := arg.(*ast.Ident); ok && errVar != "" && id.Name == errVar {
			return true
		}
		if lit, ok := arg.(*ast.BasicLit); ok {
			return lit.Kind != token.STRING || (lit.Value != `""` && lit.Value != "``")
		}
		return false
	default:
		return false
	}
}

func isFailureForcingErrHandler(ifs *ast.IfStmt, errVar string, hasOSImport, hasFmtImport bool) bool {
	if ifs == nil || ifs.Else != nil || errVar == "" || errVar == "_" || errVar == "nil" || condChecksNonZeroErr(ifs.Cond) != errVar || ifs.Body == nil || len(ifs.Body.List) == 0 {
		return false
	}
	if bodyMutatesOrTakesAddrOfAny(ifs.Body, map[string]bool{errVar: true}) || bodyDeclaresAnyIdent(ifs.Body, map[string]bool{errVar: true}) {
		return false
	}
	for _, bs := range ifs.Body.List[:len(ifs.Body.List)-1] {
		if !isBenignStderrDiagStmt(bs, hasOSImport, hasFmtImport) {
			return false
		}
	}
	return isFailureForcingExitOrPanicStmt(ifs.Body.List[len(ifs.Body.List)-1], errVar, hasOSImport)
}

func errHandlerTerminalCall(ifs *ast.IfStmt) *ast.CallExpr {
	if ifs == nil || ifs.Body == nil || len(ifs.Body.List) == 0 {
		return nil
	}
	es, ok := ifs.Body.List[len(ifs.Body.List)-1].(*ast.ExprStmt)
	if !ok {
		return nil
	}
	c, _ := unwrapParens(es.X).(*ast.CallExpr)
	return c
}

func hasWritableOSOpenFlag(expr ast.Expr) (hasWrite, hasRdwr, ok bool) {
	expr = unwrapParens(expr)
	if bin, isBin := expr.(*ast.BinaryExpr); isBin {
		if bin.Op != token.OR {
			return false, false, false
		}
		lw, lr, lok := hasWritableOSOpenFlag(bin.X)
		rw, rr, rok := hasWritableOSOpenFlag(bin.Y)
		if !lok || !rok || (lw && rr) || (lr && rw) {
			return false, false, false
		}
		return lw || rw, lr || rr, true
	}
	sel, isSel := expr.(*ast.SelectorExpr)
	if !isSel || !strings.HasPrefix(sel.Sel.Name, "O_") || sel.Sel.Name == "O_RDONLY" {
		return false, false, false
	}
	id, isID := unwrapParens(sel.X).(*ast.Ident)
	if !isID || id.Name != "os" {
		return false, false, false
	}
	return sel.Sel.Name == "O_WRONLY", sel.Sel.Name == "O_RDWR", true
}

func isWritableOSLogOpenCall(call *ast.CallExpr, requiredFlagVar string) bool {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) == 0 || requiredFlagVar == "" {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
	if !ok || pkgID.Name != "os" {
		return false
	}
	pathArg := unwrapParens(call.Args[0])
	star, ok := pathArg.(*ast.StarExpr)
	if !ok {
		return false
	}
	id, ok := unwrapParens(star.X).(*ast.Ident)
	if !ok || id.Name != requiredFlagVar {
		return false
	}
	switch sel.Sel.Name {
	case "Create":
		return len(call.Args) == 1
	case "OpenFile":
		if len(call.Args) != 3 || exprHasCallOrFuncLit(call.Args[2]) {
			return false
		}
		w, rw, ok := hasWritableOSOpenFlag(call.Args[1])
		return ok && (w || rw)
	default:
		return false
	}
}

func canonicalDepsReceiverKey(fn *ast.FuncDecl, call *ast.CallExpr) string {
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	recvX := unwrapParens(sel.X)
	switch r := recvX.(type) {
	case *ast.Ident:
		if r.Name == "" || r.Name == "_" || r.Name == "nil" {
			return ""
		}
		return r.Name
	case *ast.SelectorExpr:
		baseID, ok := unwrapParens(r.X).(*ast.Ident)
		if !ok || baseID.Name == "" || baseID.Name == "_" || r.Sel.Name == "" {
			return ""
		}
		if fn != nil && fn.Recv != nil && len(fn.Recv.List) == 1 && recvTypeName(fn.Recv.List[0].Type) == "M" && recvVarName(fn) == baseID.Name {
			return "<M>." + r.Sel.Name
		}
		return baseID.Name + "." + r.Sel.Name
	default:
		return ""
	}
}

type logFileOpenState struct {
	declared   bool
	opened     bool
	pendingErr string
}

func verifyLogFileOpenPrefix(stmts []ast.Stmt, fileVar, requiredFlagVar string, hasOSImport, hasFmtImport bool, allowedExits map[*ast.CallExpr]bool) bool {
	if !hasOSImport || fileVar == "" {
		return false
	}
	var walk func(list []ast.Stmt, st logFileOpenState) (logFileOpenState, bool)
	walk = func(list []ast.Stmt, st logFileOpenState) (logFileOpenState, bool) {
		for _, raw := range list {
			switch s := raw.(type) {
			case *ast.EmptyStmt:
			case *ast.DeclStmt:
				gd, ok := s.Decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					return st, false
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Values) != 0 {
						return st, false
					}
					for _, id := range vs.Names {
						if id.Name == fileVar {
							if st.declared || st.opened {
								return st, false
							}
							if vs.Type != nil {
								star, ok := unwrapParens(vs.Type).(*ast.StarExpr)
								if !ok {
									return st, false
								}
								sel, ok := unwrapParens(star.X).(*ast.SelectorExpr)
								if !ok || sel.Sel.Name != "File" {
									return st, false
								}
								pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
								if !ok || pkgID.Name != "os" {
									return st, false
								}
							}
							st.declared = true
						}
					}
				}
			case *ast.AssignStmt:
				if (s.Tok != token.DEFINE && s.Tok != token.ASSIGN) || len(s.Lhs) != 2 || len(s.Rhs) != 1 || st.opened || st.pendingErr != "" {
					return st, false
				}
				fID, ok1 := unwrapParens(s.Lhs[0]).(*ast.Ident)
				eID, ok2 := unwrapParens(s.Lhs[1]).(*ast.Ident)
				if !ok1 || !ok2 || fID.Name != fileVar || eID.Name == "" || eID.Name == "_" || eID.Name == "nil" || eID.Name == fileVar {
					return st, false
				}
				if s.Tok == token.ASSIGN && !st.declared {
					return st, false
				}
				call, ok := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
				if !ok || !isWritableOSLogOpenCall(call, requiredFlagVar) {
					return st, false
				}
				st.declared = true
				st.opened = true
				st.pendingErr = eID.Name
			case *ast.IfStmt:
				if s.Init != nil {
					return st, false
				}
				if s.Else == nil {
					if st.opened && st.pendingErr != "" && condChecksNonZeroErr(s.Cond) == st.pendingErr {
						if !isFailureForcingErrHandler(s, st.pendingErr, hasOSImport, hasFmtImport) {
							return st, false
						}
						if allowedExits != nil {
							if c := errHandlerTerminalCall(s); c != nil {
								allowedExits[c] = true
							}
						}
						st.pendingErr = ""
						continue
					}
					if st.opened && st.pendingErr != "" && condChecksEqErr(s.Cond, st.pendingErr) && len(s.Body.List) == 1 {
						if es, ok := s.Body.List[0].(*ast.ExprStmt); ok {
							if call, ok2 := unwrapParens(es.X).(*ast.CallExpr); ok2 && !call.Ellipsis.IsValid() && len(call.Args) == 2 && !exprHasCallOrFuncLit(call.Args[0]) && !exprHasCallOrFuncLit(call.Args[1]) {
								if sel, ok3 := unwrapParens(call.Fun).(*ast.SelectorExpr); ok3 && sel.Sel.Name == "Seek" {
									if rID, ok4 := unwrapParens(sel.X).(*ast.Ident); ok4 && rID.Name == fileVar {
										continue
									}
								}
							}
						}
					}
					return st, false
				}
				if isConstantOrTrivialCond(s.Cond) {
					return st, false
				}
				var elseList []ast.Stmt
				switch el := s.Else.(type) {
				case *ast.BlockStmt:
					elseList = el.List
				case *ast.IfStmt:
					elseList = []ast.Stmt{el}
				default:
					return st, false
				}
				stThen, okThen := walk(s.Body.List, st)
				stElse, okElse := walk(elseList, st)
				if !okThen || !okElse || stThen.declared != stElse.declared || stThen.opened != stElse.opened || stThen.pendingErr != stElse.pendingErr {
					return st, false
				}
				st = stThen
			default:
				return st, false
			}
		}
		return st, true
	}
	finalState, ok := walk(stmts, logFileOpenState{})
	return ok && finalState.declared && finalState.opened && finalState.pendingErr == ""
}

func verifyTestingStartLogArg(arg ast.Expr, files []*ast.File, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl, k *packageInactiveKernel, reqGates map[string]bool) (string, string, bool) {
	arg = unwrapParens(arg)
	switch expr := arg.(type) {
	case *ast.Ident:
		fileVar, ok := localLogFileIdent(expr)
		return fileVar, "", ok
	case *ast.UnaryExpr, *ast.CompositeLit:
		lit, wType := compositeWriterLit(expr)
		if lit == nil || wType == "" {
			return "", "", false
		}
		var fileVar string
		matchFile := func(src ast.Expr) bool {
			name, ok := localLogFileIdent(src)
			if !ok || (fileVar != "" && fileVar != name) {
				return false
			}
			fileVar = name
			return true
		}
		binding, ok := extractCompositeWriterBinding(lit, matchFile)
		if !ok || fileVar == "" || !verifyTestingCustomWriter(wType, lit, binding, files, topFuncs, typeMethods, k, reqGates) {
			return "", "", false
		}
		return fileVar, "", true
	case *ast.CallExpr:
		if expr.Ellipsis.IsValid() {
			return "", "", false
		}
		wrapId, ok := unwrapParens(expr.Fun).(*ast.Ident)
		if !ok || len(expr.Args) == 0 {
			return "", "", false
		}
		fileVar, ok := localLogFileIdent(expr.Args[0])
		if !ok {
			return "", "", false
		}
		for _, extraArg := range expr.Args[1:] {
			badExtra := false
			ast.Inspect(extraArg, func(n ast.Node) bool {
				if badExtra || n == nil {
					return false
				}
				if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.AND {
					if id, ok2 := unwrapParens(u.X).(*ast.Ident); ok2 && id.Name == fileVar {
						badExtra = true
						return false
					}
				}
				return true
			})
			if badExtra {
				return "", "", false
			}
		}
		wrapFn := topFuncs[wrapId.Name]
		if wrapFn == nil || wrapFn.Body == nil || wrapFn.Type == nil || wrapFn.Type.Params == nil || wrapFn.Type.Results == nil || wrapFn.Type.Results.NumFields() != 1 {
			return "", "", false
		}
		pNames := paramNamesFlat(wrapFn.Type.Params)
		if len(pNames) == 0 || len(pNames) != len(expr.Args) || pNames[0] == "" || pNames[0] == "_" {
			return "", "", false
		}
		wrapStmts := wrapFn.Body.List
		if k != nil {
			wrapStmts, _ = k.pruneBlockStmts(wrapFn.Body.List, wrapFn, map[string]bool{pNames[0]: true}, reqGates, nil)
		}
		if !blockAlwaysReturns(wrapStmts) {
			return "", "", false
		}
		fileParam := pNames[0]
		if bodyMutatesOrTakesAddrOfAny(wrapFn.Body, map[string]bool{fileParam: true}) || bodyDeclaresAnyIdent(wrapFn.Body, map[string]bool{fileParam: true}) {
			return "", "", false
		}
		isWrapFileSource := func(src ast.Expr) bool {
			id, ok := unwrapParens(src).(*ast.Ident)
			return ok && id.Name == fileParam
		}
		var sawReturn bool
		valid := true
		ast.Inspect(&ast.BlockStmt{List: wrapStmts}, func(n ast.Node) bool {
			if !valid || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.FuncLit, *ast.DeferStmt, *ast.GoStmt, *ast.LabeledStmt, *ast.BranchStmt,
				*ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
				valid = false
				return false
			case *ast.IfStmt:
				if isConstantOrTrivialCond(node.Cond) {
					valid = false
					return false
				}
			case *ast.ReturnStmt:
				sawReturn = true
				if len(node.Results) != 1 {
					valid = false
					return false
				}
				res := unwrapParens(node.Results[0])
				if isWrapFileSource(res) {
					return false
				}
				if lit, wType := compositeWriterLit(res); lit != nil && wType != "" {
					if binding, ok := extractCompositeWriterBinding(lit, isWrapFileSource); ok && verifyTestingCustomWriter(wType, lit, binding, files, topFuncs, typeMethods, k, reqGates) {
						return false
					}
				}
				valid = false
				return false
			}
			return true
		})
		if !sawReturn || !valid {
			return "", "", false
		}
		return fileVar, wrapId.Name, true
	default:
		return "", "", false
	}
}

type verifiedStartInfo struct {
	file          *ast.File
	fn            *ast.FuncDecl
	topStmt       ast.Stmt
	declBlock     *ast.BlockStmt
	declTargetIdx int
	fileVar       string
	recvKey       string
	flagGuard     string
	openExits     map[*ast.CallExpr]bool
}

type verifiedStopInfo struct {
	file         *ast.File
	fn           *ast.FuncDecl
	topStmt      ast.Stmt
	parentBlk    *ast.BlockStmt
	stmtPos      int
	afterStopPos int
	recvKey      string
	flagGuard    string
	stopExit     *ast.CallExpr
}

type testingExitSite struct {
	file      *ast.File
	call      *ast.CallExpr
	encFn     *ast.FuncDecl
	ancestors []ast.Node
}

func flagStringEmptyDefaultName(call *ast.CallExpr) (string, bool) {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) != 3 {
		return "", false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "String" {
		return "", false
	}
	pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
	if !ok || pkgID.Name != "flag" {
		return "", false
	}
	litName, ok := unwrapParens(call.Args[0]).(*ast.BasicLit)
	if !ok || litName.Kind != token.STRING {
		return "", false
	}
	parsedName, err := strconv.Unquote(litName.Value)
	if err != nil || parsedName == "" {
		return "", false
	}
	litDef, ok := unwrapParens(call.Args[1]).(*ast.BasicLit)
	if !ok || litDef.Kind != token.STRING || (litDef.Value != `""` && litDef.Value != "``") {
		return "", false
	}
	if exprHasCallOrFuncLit(call.Args[2]) {
		return "", false
	}
	return parsedName, true
}

func isBenignFlagInitRegStmt(stmt ast.Stmt, seenFlags map[string]bool) bool {
	var call *ast.CallExpr
	var isVarCall bool
	switch s := stmt.(type) {
	case *ast.EmptyStmt:
		return true
	case *ast.AssignStmt:
		if s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
			return false
		}
		lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
		if !ok || lhsID.Name == "" || lhsID.Name == "_" {
			return false
		}
		c, ok := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return false
		}
		call = c
	case *ast.ExprStmt:
		c, ok := unwrapParens(s.X).(*ast.CallExpr)
		if !ok {
			return false
		}
		call = c
		isVarCall = true
	default:
		return false
	}
	if call.Ellipsis.IsValid() || len(call.Args) != 3 {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
	if !ok || pkgID.Name != "flag" {
		return false
	}
	var nameLitExpr, usageLitExpr ast.Expr
	if isVarCall {
		if sel.Sel.Name != "Var" {
			return false
		}
		u, ok := unwrapParens(call.Args[0]).(*ast.UnaryExpr)
		if !ok || u.Op != token.AND {
			return false
		}
		if _, ok := unwrapParens(u.X).(*ast.Ident); !ok {
			return false
		}
		nameLitExpr = call.Args[1]
		usageLitExpr = call.Args[2]
	} else {
		switch sel.Sel.Name {
		case "Bool", "Int", "Int64", "Uint", "Uint64", "String", "Float64", "Duration":
		default:
			return false
		}
		nameLitExpr = call.Args[0]
		defExpr := unwrapParens(call.Args[1])
		if exprHasCallOrFuncLit(defExpr) {
			defCall, ok := defExpr.(*ast.CallExpr)
			if !ok || defCall.Ellipsis.IsValid() || len(defCall.Args) != 1 || exprHasCallOrFuncLit(defCall.Args[0]) {
				return false
			}
			defSel, ok := unwrapParens(defCall.Fun).(*ast.SelectorExpr)
			if !ok || defSel.Sel.Name != "GOMAXPROCS" {
				return false
			}
			rtID, ok := unwrapParens(defSel.X).(*ast.Ident)
			if !ok || rtID.Name != "runtime" {
				return false
			}
		}
		usageLitExpr = call.Args[2]
	}
	nameLit, ok := unwrapParens(nameLitExpr).(*ast.BasicLit)
	if !ok || nameLit.Kind != token.STRING {
		return false
	}
	flagName, err := strconv.Unquote(nameLit.Value)
	if err != nil || flagName == "" || seenFlags[flagName] {
		return false
	}
	usageLit, ok := unwrapParens(usageLitExpr).(*ast.BasicLit)
	if !ok || usageLit.Kind != token.STRING {
		return false
	}
	seenFlags[flagName] = true
	return true
}

func blockHasFailureForcingClose(stmts []ast.Stmt, targetVar string, hasOS, hasFmt bool) (*ast.Ident, *ast.CallExpr, bool) {
	closeCallAssign := func(stmt ast.Stmt) (string, *ast.Ident) {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok || (as.Tok != token.DEFINE && as.Tok != token.ASSIGN) || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return "", nil
		}
		errID, ok := unwrapParens(as.Lhs[0]).(*ast.Ident)
		if !ok || errID.Name == "" || errID.Name == "_" || errID.Name == "nil" {
			return "", nil
		}
		call, ok := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
			return "", nil
		}
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Close" {
			return "", nil
		}
		recvID, ok := unwrapParens(sel.X).(*ast.Ident)
		if !ok || recvID.Name != targetVar {
			return "", nil
		}
		return errID.Name, recvID
	}
	for i := 0; i < len(stmts); i++ {
		if ifs, isIf := stmts[i].(*ast.IfStmt); isIf && ifs.Init != nil {
			if errVar, recvID := closeCallAssign(ifs.Init); recvID != nil {
				if isFailureForcingErrHandler(ifs, errVar, hasOS, hasFmt) {
					return recvID, errHandlerTerminalCall(ifs), true
				}
				return nil, nil, false
			}
		}
		if i+1 < len(stmts) {
			if errVar, recvID := closeCallAssign(stmts[i]); recvID != nil {
				if ifs, isIf := stmts[i+1].(*ast.IfStmt); isIf && ifs.Init == nil && isFailureForcingErrHandler(ifs, errVar, hasOS, hasFmt) {
					return recvID, errHandlerTerminalCall(ifs), true
				}
				return nil, nil, false
			}
		}
		if !isBenignStderrDiagStmt(stmts[i], hasOS, hasFmt) {
			return nil, nil, false
		}
	}
	return nil, nil, false
}

func verifyTestingContextDecl(fn *ast.FuncDecl) bool {
	if fn == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil || len(fn.Body.List) != 2 {
		return false
	}
	recvField := fn.Recv.List[0]
	if len(recvField.Names) != 1 || recvField.Names[0].Name == "" {
		return false
	}
	recvName := recvField.Names[0].Name
	star, ok := recvField.Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	recvIdent, ok := star.X.(*ast.Ident)
	if !ok || recvIdent.Name != "common" {
		return false
	}
	if fn.Type.Params != nil && fn.Type.Params.NumFields() != 0 {
		return false
	}
	if fn.Type.Results == nil || fn.Type.Results.NumFields() != 1 {
		return false
	}
	exprStmt, ok := fn.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "checkFuzzFn" {
		return false
	}
	if id, ok := sel.X.(*ast.Ident); !ok || id.Name != recvName {
		return false
	}
	if lit, ok := call.Args[0].(*ast.BasicLit); !ok || lit.Kind != token.STRING || lit.Value != `"Context"` {
		return false
	}
	retStmt, ok := fn.Body.List[1].(*ast.ReturnStmt)
	if !ok || len(retStmt.Results) != 1 {
		return false
	}
	retSel, ok := retStmt.Results[0].(*ast.SelectorExpr)
	if !ok || retSel.Sel.Name != "ctx" {
		return false
	}
	retRecv, ok := retSel.X.(*ast.Ident)
	return ok && retRecv.Name == recvName
}

func flattenStraightLineTestingStmts(stmts []ast.Stmt) ([]ast.Stmt, bool) {
	var out []ast.Stmt
	for _, st := range stmts {
		switch s := st.(type) {
		case *ast.EmptyStmt:
			continue
		case *ast.BlockStmt:
			sub, ok := flattenStraightLineTestingStmts(s.List)
			if !ok {
				return nil, false
			}
			out = append(out, sub...)
		case *ast.ReturnStmt, *ast.BranchStmt, *ast.LabeledStmt, *ast.IfStmt,
			*ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.GoStmt:
			return nil, false
		case *ast.ExprStmt:
			if isAbortExprStmt(s) {
				return nil, false
			}
			out = append(out, st)
		default:
			out = append(out, st)
		}
	}
	return out, true
}

func testingStmtMayExitOrLoop(root ast.Stmt) bool {
	bad := false
	ast.Inspect(root, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt, *ast.BranchStmt, *ast.LabeledStmt,
			*ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.GoStmt:
			bad = true
			return false
		case *ast.ExprStmt:
			if isAbortExprStmt(x) {
				bad = true
				return false
			}
		}
		return true
	})
	return bad
}

func testingCleanupVarOnlyAssignedAt(body *ast.BlockStmt, cleanupVar string, allowedAssign *ast.AssignStmt) bool {
	ok := true
	ast.Inspect(body, func(n ast.Node) bool {
		if !ok || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			if x == allowedAssign {
				return true
			}
			for _, lhs := range x.Lhs {
				if _, isTarget := isIdentNamed(lhs, cleanupVar); isTarget {
					ok = false
					return false
				}
			}
		case *ast.IncDecStmt:
			if _, isTarget := isIdentNamed(x.X, cleanupVar); isTarget {
				ok = false
				return false
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				if _, isTarget := isIdentNamed(x.X, cleanupVar); isTarget {
					ok = false
					return false
				}
			}
		case *ast.RangeStmt:
			for _, e := range []ast.Expr{x.Key, x.Value} {
				if _, isTarget := isIdentNamed(e, cleanupVar); isTarget {
					ok = false
					return false
				}
			}
		}
		return true
	})
	return ok
}

func verifyTestingCleanupsFieldConfined(files []*ast.File, cleanupsField string, approvedSels map[*ast.SelectorExpr]bool) bool {
	ok := true
	for _, f := range files {
		lenArgSels := map[*ast.SelectorExpr]bool{}
		for _, decl := range f.Decls {
			fn, isFn := decl.(*ast.FuncDecl)
			if isFn && funcShadowsAnyIdent(fn, map[string]bool{"len": true}) {
				continue
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				c, okC := n.(*ast.CallExpr)
				if !okC || c.Ellipsis.IsValid() || len(c.Args) != 1 {
					return true
				}
				if _, okLen := isIdentNamed(c.Fun, "len"); okLen {
					if sel, okS := unwrapParens(c.Args[0]).(*ast.SelectorExpr); okS && sel.Sel != nil && sel.Sel.Name == cleanupsField {
						lenArgSels[sel] = true
					}
				}
				return true
			})
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if !ok || n == nil {
				return false
			}
			if sel, okS := n.(*ast.SelectorExpr); okS && sel.Sel != nil && sel.Sel.Name == cleanupsField {
				if !approvedSels[sel] && !lenArgSels[sel] {
					ok = false
					return false
				}
			}
			return true
		})
	}
	return ok
}

func isTestingChdirCleanupPanicStmt(stmt ast.Stmt, errVar string) bool {
	if isFailureForcingExitOrPanicStmt(stmt, errVar, false) {
		return true
	}
	es, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := unwrapParens(es.X).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	if _, okP := isIdentNamed(call.Fun, "panic"); !okP {
		return false
	}
	bin, okB := unwrapParens(call.Args[0]).(*ast.BinaryExpr)
	if !okB || bin.Op != token.ADD {
		return false
	}
	lit, okL := unwrapParens(bin.X).(*ast.BasicLit)
	if !okL || lit.Kind != token.STRING || lit.Value == `""` || lit.Value == "``" {
		return false
	}
	_, okErr := isZeroArgMethodCallOnIdent(bin.Y, errVar, "Error")
	return okErr
}
