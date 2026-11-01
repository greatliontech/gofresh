package closure

import (
	"fmt"
	"go/ast"
	"go/token"
	"slices"
	"strconv"
	"strings"
)

func verifyInternalTestlogPackageAST(files []*ast.File) error {
	reserved := map[string]bool{
		"atomic": true, "Interface": true, "logger": true,
		"SetLogger": true, "Logger": true, "Getenv": true, "Open": true, "Stat": true,
		"panic": true, "nil": true, "string": true,
	}
	declReserved := map[string]bool{
		"atomic": true, "panic": true, "nil": true, "string": true,
	}
	idx, err := indexPackageAST("internal/testlog", files, declReserved, map[string]bool{
		"sync/atomic": true, "sync": true,
	})
	if err != nil {
		return err
	}
	for _, f := range files {
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			switch path {
			case "sync/atomic", "sync":
			case "unsafe":
				if imp.Name == nil || imp.Name.Name != "_" {
					return fmt.Errorf("internal/testlog: non-blank import of unsafe forbidden")
				}
			default:
				return fmt.Errorf("internal/testlog: unapproved import %q", path)
			}
		}
	}
	if idx.hasInitFunc || idx.hasMethods || len(idx.bodylessFuncs) > 0 || len(idx.dupTopFuncs) > 0 {
		return fmt.Errorf("internal/testlog: invalid function or method declarations")
	}
	is := idx.uniqueTypeSpec("Interface")
	if is == nil || idx.pkgDeclCounts["Interface"] != 1 || idx.pkgVarCounts["logger"] != 1 || idx.pkgDeclCounts["logger"] != 1 {
		return fmt.Errorf("internal/testlog: missing or duplicate Interface/logger declarations")
	}
	loggerSpec := idx.zeroInitPkgVars["logger"]
	if loggerSpec == nil || len(loggerSpec.Names) != 1 || len(loggerSpec.Values) != 0 || !idx.hasFileImport(idx.pkgVarFiles["logger"], "sync/atomic") {
		return fmt.Errorf("internal/testlog: invalid logger variable declaration")
	}
	idxExpr, ok := unwrapParens(loggerSpec.Type).(*ast.IndexExpr)
	if !ok {
		return fmt.Errorf("internal/testlog: logger is not atomic.Pointer[Interface]")
	}
	if _, ok := isSelectorBaseField(idxExpr.X, "atomic", "Pointer"); !ok {
		return fmt.Errorf("internal/testlog: logger base type is not atomic.Pointer")
	}
	if _, ok := isIdentNamed(idxExpr.Index, "Interface"); !ok {
		return fmt.Errorf("internal/testlog: logger type arg is not Interface")
	}
	topFuncs := idx.topFuncs
	for _, name := range []string{"SetLogger", "Logger", "Getenv", "Open", "Stat"} {
		if topFuncs[name] == nil || idx.pkgDeclCounts[name] != 1 {
			return fmt.Errorf("internal/testlog: missing or shadowed %s function", name)
		}
	}

	// Verify Interface declares exact 4 methods Getenv, Stat, Open, Chdir(string).
	if is.Assign.IsValid() || is.TypeParams != nil {
		return fmt.Errorf("internal/testlog: invalid Interface type declaration")
	}
	it, ok := unwrapParens(is.Type).(*ast.InterfaceType)
	if !ok || it.Methods == nil {
		return fmt.Errorf("internal/testlog: Interface is not an interface")
	}
	wantMethods := map[string]bool{"Getenv": true, "Stat": true, "Open": true, "Chdir": true}
	seenMethods := map[string]bool{}
	for _, m := range it.Methods.List {
		if len(m.Names) != 1 || !wantMethods[m.Names[0].Name] || seenMethods[m.Names[0].Name] {
			return fmt.Errorf("internal/testlog: unexpected method in Interface")
		}
		ft, ok := m.Type.(*ast.FuncType)
		if !ok || ft.TypeParams != nil || ft.Params == nil || ft.Params.NumFields() != 1 || len(ft.Params.List) != 1 || (ft.Results != nil && ft.Results.NumFields() != 0) {
			return fmt.Errorf("internal/testlog: unexpected signature for Interface.%s", m.Names[0].Name)
		}
		if _, ok := isIdentNamed(ft.Params.List[0].Type, "string"); !ok {
			return fmt.Errorf("internal/testlog: Interface.%s parameter is not string", m.Names[0].Name)
		}
		seenMethods[m.Names[0].Name] = true
	}
	if len(seenMethods) != len(wantMethods) {
		return fmt.Errorf("internal/testlog: incomplete Interface method set")
	}

	allowedLoggerIdents := map[*ast.Ident]bool{loggerSpec.Names[0]: true}

	// Verify SetLogger(impl Interface): if !logger.CompareAndSwap(nil, &impl) { panic("...") }
	setFn := topFuncs["SetLogger"]
	if setFn == nil || setFn.Type.TypeParams != nil || setFn.Type.Params == nil || setFn.Type.Params.NumFields() != 1 || len(setFn.Type.Params.List) != 1 || (setFn.Type.Results != nil && setFn.Type.Results.NumFields() != 0) || len(setFn.Body.List) != 1 {
		return fmt.Errorf("internal/testlog: invalid SetLogger signature or body")
	}
	setParams := paramNamesFlat(setFn.Type.Params)
	if len(setParams) != 1 || setParams[0] == "" || setParams[0] == "_" || reserved[setParams[0]] || funcShadowsAnyIdent(setFn, reserved) {
		return fmt.Errorf("internal/testlog: invalid SetLogger parameter")
	}
	if _, ok := isIdentNamed(setFn.Type.Params.List[0].Type, "Interface"); !ok {
		return fmt.Errorf("internal/testlog: SetLogger parameter is not Interface")
	}
	setIf, ok := setFn.Body.List[0].(*ast.IfStmt)
	if !ok || setIf.Init != nil || setIf.Else != nil || len(setIf.Body.List) != 1 {
		return fmt.Errorf("internal/testlog: SetLogger body is not single CAS guard")
	}
	notExpr, ok := unwrapParens(setIf.Cond).(*ast.UnaryExpr)
	if !ok || notExpr.Op != token.NOT {
		return fmt.Errorf("internal/testlog: SetLogger missing negated CAS condition")
	}
	casCall, ok := unwrapParens(notExpr.X).(*ast.CallExpr)
	if !ok || casCall.Ellipsis.IsValid() || len(casCall.Args) != 2 {
		return fmt.Errorf("internal/testlog: SetLogger invalid CompareAndSwap call")
	}
	casSel, ok := unwrapParens(casCall.Fun).(*ast.SelectorExpr)
	if !ok || casSel.Sel.Name != "CompareAndSwap" {
		return fmt.Errorf("internal/testlog: SetLogger does not call CompareAndSwap")
	}
	casLogID, ok := isIdentNamed(casSel.X, "logger")
	if !ok {
		return fmt.Errorf("internal/testlog: SetLogger CompareAndSwap receiver is not logger")
	}
	allowedLoggerIdents[casLogID] = true
	if _, ok := isIdentNamed(casCall.Args[0], "nil"); !ok {
		return fmt.Errorf("internal/testlog: SetLogger CAS old value is not nil")
	}
	ampImpl, ok := unwrapParens(casCall.Args[1]).(*ast.UnaryExpr)
	if !ok || ampImpl.Op != token.AND {
		return fmt.Errorf("internal/testlog: SetLogger CAS new value is not &impl")
	}
	if _, ok := isIdentNamed(ampImpl.X, setParams[0]); !ok {
		return fmt.Errorf("internal/testlog: SetLogger CAS new value does not bind impl")
	}
	if !isFailureForcingExitOrPanicStmt(setIf.Body.List[0], "", false) {
		return fmt.Errorf("internal/testlog: SetLogger duplicate call does not panic")
	}

	// Verify Logger() Interface: impl := logger.Load(); if impl == nil { return nil }; return *impl
	getFn := topFuncs["Logger"]
	if getFn == nil || getFn.Type.TypeParams != nil || (getFn.Type.Params != nil && getFn.Type.Params.NumFields() != 0) || getFn.Type.Results == nil || getFn.Type.Results.NumFields() != 1 || len(getFn.Type.Results.List) != 1 || len(getFn.Type.Results.List[0].Names) != 0 || len(getFn.Body.List) != 3 || funcShadowsAnyIdent(getFn, reserved) {
		return fmt.Errorf("internal/testlog: invalid Logger signature or body")
	}
	if _, ok := isIdentNamed(getFn.Type.Results.List[0].Type, "Interface"); !ok {
		return fmt.Errorf("internal/testlog: Logger result is not Interface")
	}
	loadAs, ok := getFn.Body.List[0].(*ast.AssignStmt)
	if !ok || loadAs.Tok != token.DEFINE || len(loadAs.Lhs) != 1 || len(loadAs.Rhs) != 1 {
		return fmt.Errorf("internal/testlog: Logger missing logger.Load() assignment")
	}
	ptrID, ok := unwrapParens(loadAs.Lhs[0]).(*ast.Ident)
	if !ok || ptrID.Name == "" || ptrID.Name == "_" || reserved[ptrID.Name] {
		return fmt.Errorf("internal/testlog: Logger invalid local pointer name")
	}
	loadLogID, ok := isZeroArgMethodCallOnIdent(loadAs.Rhs[0], "logger", "Load")
	if !ok {
		return fmt.Errorf("internal/testlog: Logger does not call logger.Load()")
	}
	allowedLoggerIdents[loadLogID] = true
	nilIf, ok := getFn.Body.List[1].(*ast.IfStmt)
	if !ok || nilIf.Init != nil || nilIf.Else != nil || !condChecksEqErr(nilIf.Cond, ptrID.Name) || len(nilIf.Body.List) != 1 {
		return fmt.Errorf("internal/testlog: Logger missing nil check")
	}
	if nilRet, ok := nilIf.Body.List[0].(*ast.ReturnStmt); !ok || len(nilRet.Results) != 1 {
		return fmt.Errorf("internal/testlog: Logger invalid nil return")
	} else if _, ok := isIdentNamed(nilRet.Results[0], "nil"); !ok {
		return fmt.Errorf("internal/testlog: Logger nil branch does not return nil")
	}
	derefRet, ok := getFn.Body.List[2].(*ast.ReturnStmt)
	if !ok || len(derefRet.Results) != 1 {
		return fmt.Errorf("internal/testlog: Logger missing dereference return")
	}
	starExpr, ok := unwrapParens(derefRet.Results[0]).(*ast.StarExpr)
	if !ok {
		return fmt.Errorf("internal/testlog: Logger does not dereference loaded pointer")
	}
	if _, ok := isIdentNamed(starExpr.X, ptrID.Name); !ok {
		return fmt.Errorf("internal/testlog: Logger dereferences wrong identifier")
	}

	// Verify Getenv, Open, Stat (and Chdir if declared as a package function).
	verifyDispatch := func(op string) bool {
		fn := topFuncs[op]
		if fn == nil || fn.Type.TypeParams != nil || fn.Type.Params == nil || fn.Type.Params.NumFields() != 1 || len(fn.Type.Params.List) != 1 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) || len(fn.Body.List) != 1 || funcShadowsAnyIdent(fn, reserved) {
			return false
		}
		if _, ok := isIdentNamed(fn.Type.Params.List[0].Type, "string"); !ok {
			return false
		}
		pNames := paramNamesFlat(fn.Type.Params)
		if len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || reserved[pNames[0]] || bodyDeclaresAnyIdent(fn.Body, map[string]bool{pNames[0]: true}) {
			return false
		}
		ifs, ok := fn.Body.List[0].(*ast.IfStmt)
		if !ok || ifs.Init == nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
			return false
		}
		initAs, ok := ifs.Init.(*ast.AssignStmt)
		if !ok || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 1 || len(initAs.Rhs) != 1 {
			return false
		}
		lID, ok := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
		if !ok || lID.Name == "" || lID.Name == "_" || lID.Name == pNames[0] || reserved[lID.Name] {
			return false
		}
		lCall, ok := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
		if !ok || lCall.Ellipsis.IsValid() || len(lCall.Args) != 0 {
			return false
		}
		if _, ok := isIdentNamed(lCall.Fun, "Logger"); !ok {
			return false
		}
		if condChecksNonZeroErr(ifs.Cond) != lID.Name {
			return false
		}
		es, ok := ifs.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return false
		}
		opCall, ok := unwrapParens(es.X).(*ast.CallExpr)
		if !ok || opCall.Ellipsis.IsValid() || len(opCall.Args) != 1 {
			return false
		}
		if _, ok := isSelectorBaseField(opCall.Fun, lID.Name, op); !ok {
			return false
		}
		_, ok = isIdentNamed(opCall.Args[0], pNames[0])
		return ok
	}
	for _, op := range []string{"Getenv", "Open", "Stat"} {
		if !verifyDispatch(op) {
			return fmt.Errorf("internal/testlog: missing or invalid %s hook dispatcher", op)
		}
	}
	if topFuncs["Chdir"] != nil && !verifyDispatch("Chdir") {
		return fmt.Errorf("internal/testlog: invalid Chdir hook dispatcher")
	}

	// Ensure logger is never referenced anywhere else in internal/testlog.
	if !allNonSelectorPropIdentsIn(files, map[string]map[*ast.Ident]bool{"logger": allowedLoggerIdents}) {
		return fmt.Errorf("internal/testlog: unexpected reference to logger outside SetLogger/Logger")
	}
	return nil
}

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
	if bad {
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

func verifyTestdepsPackageAST(files []*ast.File) error {
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
	tdSpec := idx.uniqueTypeSpec("TestDeps")
	if tdSpec == nil || tdSpec.Assign.IsValid() || tdSpec.TypeParams != nil {
		return fmt.Errorf("testing/internal/testdeps: missing or invalid TestDeps type")
	}
	if tdStruct, ok := unwrapParens(tdSpec.Type).(*ast.StructType); !ok || (tdStruct.Fields != nil && len(tdStruct.Fields.List) != 0) {
		return fmt.Errorf("testing/internal/testdeps: TestDeps must be an empty struct")
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
	if lSpec == nil || lSpec.Assign.IsValid() || lSpec.TypeParams != nil {
		return fmt.Errorf("testing/internal/testdeps: invalid logger struct %s", loggerType)
	}
	allowedLoggerTypeIdents[lSpec.Name] = true
	lFile := idx.typeSpecFile[lSpec]
	lStruct, ok := unwrapParens(lSpec.Type).(*ast.StructType)
	if !ok || lStruct.Fields == nil {
		return fmt.Errorf("testing/internal/testdeps: %s is not a struct", loggerType)
	}
	lFields := map[string]ast.Expr{}
	for _, fld := range lStruct.Fields.List {
		if len(fld.Names) == 0 {
			return fmt.Errorf("testing/internal/testdeps: embedded field on %s forbidden", loggerType)
		}
		for _, id := range fld.Names {
			lFields[id.Name] = fld.Type
		}
	}
	// Verify boundField is *bufio.Writer, muField (if used) is sync.Mutex, setField (if used) is bool.
	wStar, ok := unwrapParens(lFields[boundField]).(*ast.StarExpr)
	if !ok || !fileImportsBufio[lFile] {
		return fmt.Errorf("testing/internal/testdeps: %s.%s is not *bufio.Writer", loggerType, boundField)
	}
	if _, ok := isSelectorBaseField(wStar.X, "bufio", "Writer"); !ok {
		return fmt.Errorf("testing/internal/testdeps: %s.%s is not *bufio.Writer", loggerType, boundField)
	}
	if muField != "" {
		if !fileImportsSync[lFile] {
			return fmt.Errorf("testing/internal/testdeps: missing sync import for %s.%s", loggerType, muField)
		}
		if _, ok := isSelectorBaseField(lFields[muField], "sync", "Mutex"); !ok {
			return fmt.Errorf("testing/internal/testdeps: %s.%s is not sync.Mutex", loggerType, muField)
		}
	}
	if setField != "" {
		if _, ok := isIdentNamed(lFields[setField], "bool"); !ok {
			return fmt.Errorf("testing/internal/testdeps: %s.%s is not bool", loggerType, setField)
		}
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

func syscallWriteSinkKind(call *ast.CallExpr) string {
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := unwrapParens(sel.X).(*ast.Ident)
	if !ok || id.Name != "syscall" {
		return ""
	}
	switch sel.Sel.Name {
	case "Write":
		return "write2"
	case "Syscall", "RawSyscall", "Syscall6":
		return "raw3"
	default:
		return ""
	}
}

func isSysWriteConstExpr(expr ast.Expr) bool {
	sel, ok := unwrapParens(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "SYS_WRITE" {
		return false
	}
	id, ok := unwrapParens(sel.X).(*ast.Ident)
	return ok && id.Name == "syscall"
}


type testingWriterBinding struct {
	fileFields map[string]bool
	fdFields   map[string]bool
	fileVars   map[string]bool
	fdVars     map[string]bool
	emptyVars  map[string]bool
	sliceVar   string
}


func isProvablyEmptyByteSliceArg(expr ast.Expr, binding testingWriterBinding) bool {
	switch e := unwrapParens(expr).(type) {
	case *ast.Ident:
		return e.Name == "nil" || binding.emptyVars[e.Name]
	case *ast.BasicLit:
		return e.Kind == token.STRING && (e.Value == `""` || e.Value == "``")
	case *ast.CompositeLit:
		return len(e.Elts) == 0 && e.Type != nil && isByteSliceType(e.Type)
	case *ast.CallExpr:
		if e.Ellipsis.IsValid() || len(e.Args) != 1 || !isByteSliceType(e.Fun) {
			return false
		}
		switch a := unwrapParens(e.Args[0]).(type) {
		case *ast.Ident:
			return a.Name == "nil"
		case *ast.BasicLit:
			return a.Kind == token.STRING && (a.Value == `""` || a.Value == "``")
		default:
			return false
		}
	default:
		return false
	}
}


func isSliceZeroElemUintptrExpr(expr ast.Expr, sliceName string) (*ast.UnaryExpr, []*ast.CallExpr, bool) {
	if sliceName == "" {
		return nil, nil, false
	}
	uptrCall, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || len(uptrCall.Args) != 1 || uptrCall.Ellipsis.IsValid() {
		return nil, nil, false
	}
	uptrID, ok := unwrapParens(uptrCall.Fun).(*ast.Ident)
	if !ok || uptrID.Name != "uintptr" {
		return nil, nil, false
	}
	ptrCall, ok := unwrapParens(uptrCall.Args[0]).(*ast.CallExpr)
	if !ok || len(ptrCall.Args) != 1 || ptrCall.Ellipsis.IsValid() {
		return nil, nil, false
	}
	ptrSel, ok := unwrapParens(ptrCall.Fun).(*ast.SelectorExpr)
	if !ok || ptrSel.Sel.Name != "Pointer" {
		return nil, nil, false
	}
	unsafeID, ok := unwrapParens(ptrSel.X).(*ast.Ident)
	if !ok || unsafeID.Name != "unsafe" {
		return nil, nil, false
	}
	inner := unwrapParens(ptrCall.Args[0])
	if amp, ok := inner.(*ast.UnaryExpr); ok && amp.Op == token.AND {
		idx, ok := unwrapParens(amp.X).(*ast.IndexExpr)
		if !ok || !isZeroIntLit(idx.Index) {
			return nil, nil, false
		}
		sID, ok := unwrapParens(idx.X).(*ast.Ident)
		if !ok || sID.Name != sliceName {
			return nil, nil, false
		}
		return amp, []*ast.CallExpr{uptrCall, ptrCall}, true
	}
	if sdCall, ok := inner.(*ast.CallExpr); ok && len(sdCall.Args) == 1 && !sdCall.Ellipsis.IsValid() {
		sdSel, ok := unwrapParens(sdCall.Fun).(*ast.SelectorExpr)
		if !ok || sdSel.Sel.Name != "SliceData" {
			return nil, nil, false
		}
		uID, ok := unwrapParens(sdSel.X).(*ast.Ident)
		if !ok || uID.Name != "unsafe" {
			return nil, nil, false
		}
		sID, ok := unwrapParens(sdCall.Args[0]).(*ast.Ident)
		if !ok || sID.Name != sliceName {
			return nil, nil, false
		}
		return nil, []*ast.CallExpr{uptrCall, ptrCall, sdCall}, true
	}
	return nil, nil, false
}

func isSliceLenUintptrExpr(expr ast.Expr, sliceName string) bool {
	uptrCall, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || len(uptrCall.Args) != 1 || uptrCall.Ellipsis.IsValid() {
		return false
	}
	uptrID, ok := unwrapParens(uptrCall.Fun).(*ast.Ident)
	if !ok || uptrID.Name != "uintptr" {
		return false
	}
	return isLenOfIdentCall(uptrCall.Args[0], sliceName)
}

func isFdMethodCallOnSource(expr ast.Expr, isFileSource func(ast.Expr) bool) bool {
	expr = unwrapParens(expr)
	if conv, ok := expr.(*ast.CallExpr); ok && len(conv.Args) == 1 {
		if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
			expr = unwrapParens(conv.Args[0])
		}
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Fd" && isFileSource(sel.X)
}

func extractCompositeWriterBinding(lit *ast.CompositeLit, isFileSource func(ast.Expr) bool) (testingWriterBinding, bool) {
	if lit == nil || len(lit.Elts) == 0 {
		return testingWriterBinding{}, false
	}
	b := testingWriterBinding{
		fileFields: map[string]bool{},
		fdFields:   map[string]bool{},
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return testingWriterBinding{}, false
		}
		keyID, ok := unwrapParens(kv.Key).(*ast.Ident)
		if !ok || keyID.Name == "" {
			return testingWriterBinding{}, false
		}
		val := unwrapParens(kv.Value)
		if isFileSource(val) {
			b.fileFields[keyID.Name] = true
		} else if isFdMethodCallOnSource(val, isFileSource) {
			b.fdFields[keyID.Name] = true
		}
	}
	if len(b.fileFields) == 0 && len(b.fdFields) == 0 {
		return testingWriterBinding{}, false
	}
	return b, true
}

func isBoundFileTargetExpr(fn *ast.FuncDecl, expr ast.Expr, binding testingWriterBinding) bool {
	expr = unwrapParens(expr)
	switch e := expr.(type) {
	case *ast.Ident:
		return binding.fileVars[e.Name]
	case *ast.SelectorExpr:
		recv := recvVarName(fn)
		if recv != "" {
			if id, ok := unwrapParens(e.X).(*ast.Ident); ok && id.Name == recv {
				return binding.fileFields[e.Sel.Name]
			}
		}
	}
	return false
}

func isBoundFdTargetExpr(fn *ast.FuncDecl, expr ast.Expr, binding testingWriterBinding) bool {
	expr = unwrapParens(expr)
	if conv, ok := expr.(*ast.CallExpr); ok && len(conv.Args) == 1 {
		if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
			expr = unwrapParens(conv.Args[0])
		}
	}
	switch e := expr.(type) {
	case *ast.Ident:
		return binding.fdVars[e.Name]
	case *ast.SelectorExpr:
		recv := recvVarName(fn)
		if recv != "" {
			if id, ok := unwrapParens(e.X).(*ast.Ident); ok && id.Name == recv {
				return binding.fdFields[e.Sel.Name]
			}
		}
	case *ast.CallExpr:
		return isFdMethodCallOnSource(e, func(src ast.Expr) bool {
			return isBoundFileTargetExpr(fn, src, binding)
		})
	}
	return false
}

func isUnderlyingBoundWriteCall(fn *ast.FuncDecl, call *ast.CallExpr, binding testingWriterBinding) bool {
	if call.Ellipsis.IsValid() {
		return false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Write" || len(call.Args) != 1 {
		return false
	}
	return isBoundFileTargetExpr(fn, sel.X, binding)
}

func isBoundSyscallWriteCall(fn *ast.FuncDecl, call *ast.CallExpr, binding testingWriterBinding) string {
	if call.Ellipsis.IsValid() {
		return ""
	}
	kind := syscallWriteSinkKind(call)
	switch kind {
	case "write2":
		if len(call.Args) == 2 && isBoundFdTargetExpr(fn, call.Args[0], binding) {
			return "write2"
		}
	case "raw3":
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		validArity := (sel.Sel.Name == "Syscall" || sel.Sel.Name == "RawSyscall") && len(call.Args) == 4
		if sel.Sel.Name == "Syscall6" && len(call.Args) == 6 && isZeroIntLit(call.Args[4]) && isZeroIntLit(call.Args[5]) {
			validArity = true
		}
		if validArity && isSysWriteConstExpr(call.Args[0]) && isBoundFdTargetExpr(fn, call.Args[1], binding) {
			return "raw3"
		}
	}
	return ""
}

func deriveCalleeBinding(callerFn *ast.FuncDecl, callerRecv string, callerBinding testingWriterBinding, callerPayloadProtected map[string]bool, call *ast.CallExpr, helperRecv string, helperDecl *ast.FuncDecl, sinkArgSource func(ast.Expr) (string, bool)) (testingWriterBinding, string, bool) {
	if call.Ellipsis.IsValid() {
		return testingWriterBinding{}, "", false
	}
	callee := testingWriterBinding{
		fileVars:  map[string]bool{},
		fdVars:    map[string]bool{},
		emptyVars: map[string]bool{},
	}
	if helperRecv != "" && helperRecv == callerRecv {
		callee.fileFields = callerBinding.fileFields
		callee.fdFields = callerBinding.fdFields
	}
	pNames := paramNamesFlat(helperDecl.Type.Params)
	if len(call.Args) != len(pNames) {
		return testingWriterBinding{}, "", false
	}
	byteSliceParams := byteSliceParamIdents(helperDecl.Type.Params)
	var matchedChunk string
	for i, arg := range call.Args {
		pName := pNames[i]
		if pName != "" && pName != "_" {
			if isBoundFileTargetExpr(callerFn, arg, callerBinding) && !exprRefsIdentOutsideLen(arg, callerPayloadProtected) {
				callee.fileVars[pName] = true
				continue
			}
			if isBoundFdTargetExpr(callerFn, arg, callerBinding) && !exprRefsIdentOutsideLen(arg, callerPayloadProtected) {
				callee.fdVars[pName] = true
				continue
			}
			if byteSliceParams[pName] {
				if srcChunk, ok := sinkArgSource(arg); ok {
					if callee.sliceVar != "" {
						return testingWriterBinding{}, "", false
					}
					callee.sliceVar = pName
					matchedChunk = srcChunk
					continue
				}
				if isProvablyEmptyByteSliceArg(arg, callerBinding) && !bodyDeclaresAnyIdent(helperDecl.Body, map[string]bool{pName: true}) && !bodyMutatesOrTakesAddrOfAny(helperDecl.Body, map[string]bool{pName: true}) {
					callee.emptyVars[pName] = true
					continue
				}
			}
		}
		if exprHasCallOrFuncLit(arg) || exprRefsIdentOutsideLen(arg, callerPayloadProtected) {
			return testingWriterBinding{}, "", false
		}
	}
	if callee.sliceVar == "" {
		return testingWriterBinding{}, "", false
	}
	return callee, matchedChunk, true
}

func resolveLocalHelper(recvType string, fn *ast.FuncDecl, call *ast.CallExpr, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl) (string, *ast.FuncDecl, bool) {
	switch fun := unwrapParens(call.Fun).(type) {
	case *ast.Ident:
		if decl, ok := topFuncs[fun.Name]; ok {
			return "", decl, true
		}
	case *ast.SelectorExpr:
		recv := recvVarName(fn)
		if recv != "" && recvType != "" {
			if id, ok := unwrapParens(fun.X).(*ast.Ident); ok && id.Name == recv {
				if decl, ok := typeMethods[recvType][fun.Sel.Name]; ok {
					return recvType, decl, true
				}
			}
		}
	}
	return "", nil, false
}

func isWrappedErrStructPtr(expr ast.Expr, errName string) bool {
	u, ok := unwrapParens(expr).(*ast.UnaryExpr)
	if !ok || u.Op != token.AND {
		return false
	}
	lit, ok := unwrapParens(u.X).(*ast.CompositeLit)
	if !ok || lit.Type == nil {
		return false
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := unwrapParens(kv.Value).(*ast.Ident); ok && id.Name == errName {
			return true
		}
	}
	return false
}

func exprIsUntaintedErrResult(expr ast.Expr, errName string) bool {
	expr = unwrapParens(expr)
	if id, ok := expr.(*ast.Ident); ok && id.Name == errName {
		return true
	}
	return isWrappedErrStructPtr(expr, errName)
}

func condChecksNonZeroErr(cond ast.Expr) string {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return ""
	}
	lhs, rhs := unwrapParens(bin.X), unwrapParens(bin.Y)
	if id, ok := lhs.(*ast.Ident); ok {
		if rID, ok := rhs.(*ast.Ident); ok && rID.Name == "nil" {
			return id.Name
		}
		if lit, ok := rhs.(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "0" {
			return id.Name
		}
	}
	if id, ok := rhs.(*ast.Ident); ok {
		if lID, ok := lhs.(*ast.Ident); ok && lID.Name == "nil" {
			return id.Name
		}
		if lit, ok := lhs.(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "0" {
			return id.Name
		}
	}
	return ""
}

func condChecksEqErr(cond ast.Expr, wantIdent string) bool {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	lhs, rhs := unwrapParens(bin.X), unwrapParens(bin.Y)
	if id, ok := lhs.(*ast.Ident); ok && id.Name == wantIdent {
		if rID, ok := rhs.(*ast.Ident); ok && rID.Name == "nil" {
			return true
		}
	}
	if id, ok := rhs.(*ast.Ident); ok && id.Name == wantIdent {
		if lID, ok := lhs.(*ast.Ident); ok && lID.Name == "nil" {
			return true
		}
	}
	return false
}

func isTransientErrnoEq(expr ast.Expr, errName string) bool {
	bin, ok := unwrapParens(expr).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	id, ok := unwrapParens(bin.X).(*ast.Ident)
	if !ok || id.Name != errName {
		return false
	}
	sel, ok := unwrapParens(bin.Y).(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "EINTR" && sel.Sel.Name != "EAGAIN") {
		return false
	}
	pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
	return ok && pkgID.Name == "syscall"
}

func isTransientErrnoRetryIf(s *ast.IfStmt, errName string) bool {
	if s.Init != nil || s.Else != nil || len(s.Body.List) != 1 {
		return false
	}
	br, ok := s.Body.List[0].(*ast.BranchStmt)
	if !ok || br.Tok != token.CONTINUE {
		return false
	}
	cond := unwrapParens(s.Cond)
	if isTransientErrnoEq(cond, errName) {
		return true
	}
	bin, ok := cond.(*ast.BinaryExpr)
	return ok && bin.Op == token.LOR && isTransientErrnoEq(bin.X, errName) && isTransientErrnoEq(bin.Y, errName)
}

func isLenSlicePositiveCond(cond ast.Expr, sliceName string) bool {
	if sliceName == "" {
		return false
	}
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || (bin.Op != token.GTR && bin.Op != token.NEQ) {
		return false
	}
	return isLenOfIdentCall(bin.X, sliceName) && isZeroIntLit(bin.Y)
}

func isCountPositiveCond(cond ast.Expr, countAliases map[string]bool) bool {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.GTR {
		return false
	}
	id, ok := unwrapParens(bin.X).(*ast.Ident)
	return ok && countAliases[id.Name] && isZeroIntLit(bin.Y)
}

func isCountAdvanceSliceAssign(s *ast.AssignStmt, sliceName string, countAliases map[string]bool) bool {
	if s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		return false
	}
	lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
	if !ok || lhsID.Name != sliceName {
		return false
	}
	sl, ok := unwrapParens(s.Rhs[0]).(*ast.SliceExpr)
	if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
		return false
	}
	baseID, ok := unwrapParens(sl.X).(*ast.Ident)
	if !ok || baseID.Name != sliceName {
		return false
	}
	low := unwrapParens(sl.Low)
	if conv, isCall := low.(*ast.CallExpr); isCall && len(conv.Args) == 1 && !conv.Ellipsis.IsValid() {
		if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
			low = unwrapParens(conv.Args[0])
		}
	}
	advID, ok := low.(*ast.Ident)
	return ok && countAliases[advID.Name]
}

func isChunkAdvanceSliceAssign(s *ast.AssignStmt, sliceName, activeChunk string) bool {
	if activeChunk == "" || s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		return false
	}
	lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
	if !ok || lhsID.Name != sliceName {
		return false
	}
	sl, ok := unwrapParens(s.Rhs[0]).(*ast.SliceExpr)
	if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
		return false
	}
	baseID, ok := unwrapParens(sl.X).(*ast.Ident)
	return ok && baseID.Name == sliceName && isLenOfIdentCall(sl.Low, activeChunk)
}

func isMonotonicLatchIf(s *ast.IfStmt, chunkErrVar, accumErrVar, namedCountResult, activeChunk string, requireCountUpdate bool) (updatedCount bool, ok bool) {
	checkArm := func(arm *ast.IfStmt) bool {
		if arm == nil || arm.Init != nil || arm.Else != nil || len(arm.Body.List) != 1 {
			return false
		}
		bin, ok := unwrapParens(arm.Cond).(*ast.BinaryExpr)
		if !ok || bin.Op != token.LAND {
			return false
		}
		if condChecksNonZeroErr(bin.X) != chunkErrVar || !condChecksEqErr(bin.Y, accumErrVar) {
			return false
		}
		assign, ok := arm.Body.List[0].(*ast.AssignStmt)
		if !ok || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return false
		}
		lhsID, ok := unwrapParens(assign.Lhs[0]).(*ast.Ident)
		rhsID, ok2 := unwrapParens(assign.Rhs[0]).(*ast.Ident)
		return ok && ok2 && lhsID.Name == accumErrVar && rhsID.Name == chunkErrVar
	}
	if checkArm(s) {
		if requireCountUpdate {
			return false, false
		}
		return false, true
	}
	if s.Init != nil || s.Else == nil {
		return false, false
	}
	condRequiresNilBoth := false
	if bin, ok := unwrapParens(s.Cond).(*ast.BinaryExpr); ok && bin.Op == token.LAND {
		condRequiresNilBoth = (condChecksEqErr(bin.X, chunkErrVar) && condChecksEqErr(bin.Y, accumErrVar)) ||
			(condChecksEqErr(bin.Y, chunkErrVar) && condChecksEqErr(bin.X, accumErrVar))
	}
	if !condRequiresNilBoth {
		return false, false
	}
	elseIf, ok := s.Else.(*ast.IfStmt)
	if !ok || !checkArm(elseIf) {
		return false, false
	}
	if requireCountUpdate {
		if namedCountResult == "" || activeChunk == "" || len(s.Body.List) != 1 {
			return false, false
		}
		addStmt, ok := s.Body.List[0].(*ast.AssignStmt)
		if !ok || addStmt.Tok != token.ADD_ASSIGN || len(addStmt.Lhs) != 1 || len(addStmt.Rhs) != 1 {
			return false, false
		}
		lhsID, ok := unwrapParens(addStmt.Lhs[0]).(*ast.Ident)
		if !ok || lhsID.Name != namedCountResult || !isLenOfIdentCall(addStmt.Rhs[0], activeChunk) {
			return false, false
		}
		return true, true
	}
	if len(s.Body.List) != 0 {
		return false, false
	}
	return false, true
}


type writerBlockMode int

const (
	writerBlockPlain writerBlockMode = iota
	writerBlockSliceLoop
	writerBlockChunkLoop
)

type writerPathState struct {
	liveErr                        string
	lastChunk                      string
	lastSinkResultArity            int
	activeChunk                    string
	liveCountVar                   string
	sliceParamMutated              bool
	sliceAdvancedInLoop            bool
	chunkAdvancedInLoop            bool
	sawSinkInLoop                  bool
	dischargedLoop                 bool
	dischargedFullSlice1ResultSink bool
	discharged2ResultSink          bool
	latchedSink                    bool
	latchedCount                   bool
}

func verifyTestingWriterFunc(recvType string, fn *ast.FuncDecl, binding testingWriterBinding, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl, visiting map[string]bool) bool {
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.Results == nil || binding.sliceVar == "" {
		return false
	}
	writerReserved := map[string]bool{
		"len": true, "append": true, "make": true, "copy": true, "clear": true,
		"uintptr": true, "int": true, "byte": true, "nil": true, "error": true,
		"unsafe": true, "syscall": true, "os": true,
	}
	if funcShadowsAnyIdent(fn, writerReserved) {
		return false
	}
	numResults := fn.Type.Results.NumFields()
	if (numResults != 1 && (numResults != 2 || !firstResultIsInt(fn.Type.Results))) || !funcReturnsErrorLast(fn.Type) {
		return false
	}
	if !blockAlwaysReturns(fn.Body.List) {
		return false
	}
	visitKey := recvType + "." + fn.Name.Name + fmt.Sprintf("|%s|%v|%v|%v|%v|%v", binding.sliceVar, sortedKeys(binding.fileFields), sortedKeys(binding.fdFields), sortedKeys(binding.fileVars), sortedKeys(binding.fdVars), sortedKeys(binding.emptyVars))
	if visiting[visitKey] {
		return false
	}
	visiting[visitKey] = true
	defer delete(visiting, visitKey)

	protectedSinks := map[string]bool{}
	for k := range binding.fileVars {
		protectedSinks[k] = true
	}
	for k := range binding.fdVars {
		protectedSinks[k] = true
	}
	for k := range binding.emptyVars {
		protectedSinks[k] = true
	}
	if recv := recvVarName(fn); recv != "" {
		protectedSinks[recv] = true
		if !blockOnlySelectsOnIdent(fn.Body, recv) {
			return false
		}
	}
	if bodyMutatesOrTakesAddrOfAny(fn.Body, protectedSinks) {
		return false
	}

	sliceParam := binding.sliceVar
	namedErrResult := lastNamedResultIdent(fn.Type.Results)
	namedCountResult := firstNamedIntResultIdent(fn.Type.Results)

	localClosures := map[string]*ast.FuncType{}
	verifiedClosureLits := map[*ast.FuncLit]bool{}
	allowedSliceZeroAmps := map[*ast.UnaryExpr]bool{}
	allowedPayloadCalls := map[*ast.CallExpr]bool{}
	allowedPayloadAssigns := map[*ast.AssignStmt]bool{}
	allowedPayloadValueSpecs := map[*ast.ValueSpec]bool{}
	allErrNames := map[string]bool{}
	allCountNames := map[string]bool{}
	allLoopCountNames := map[string]bool{}
	allChunkNames := map[string]bool{}
	allBufNames := map[string]bool{}
	currentPayloadProtected := func() map[string]bool {
		m := map[string]bool{sliceParam: true}
		for k := range allChunkNames {
			m[k] = true
		}
		for k := range allBufNames {
			m[k] = true
		}
		for k := range binding.emptyVars {
			m[k] = true
		}
		return m
	}
	var namedErrBoundDirectly, everLatched bool
	if namedErrResult != "" {
		allErrNames[namedErrResult] = true
	}
	if namedCountResult != "" {
		allCountNames[namedCountResult] = true
	}

	// Per-loop auxiliary name tables, active only inside their respective loop walks.
	var loopCountAliases map[string]bool
	var sawLenZeroExitReturn bool
	var chunkVars map[string]bool
	var freshBufVars map[string]bool
	var bufChunkSource map[string]string

	isProtectedIdent := func(name string) bool {
		return localClosures[name] != nil || allErrNames[name] || allCountNames[name] || allLoopCountNames[name] || allChunkNames[name] || allBufNames[name] || protectedSinks[name]
	}

	bindFreshErrIdent := func(expr ast.Expr) (string, bool) {
		id, ok := unwrapParens(expr).(*ast.Ident)
		if !ok || id.Name == "" || id.Name == "_" || id.Name == sliceParam || localClosures[id.Name] != nil || allCountNames[id.Name] || allLoopCountNames[id.Name] || allChunkNames[id.Name] || allBufNames[id.Name] || protectedSinks[id.Name] {
			return "", false
		}
		if id.Name == namedErrResult {
			if namedErrBoundDirectly || everLatched {
				return "", false
			}
			namedErrBoundDirectly = true
			return id.Name, true
		}
		if allErrNames[id.Name] {
			return "", false
		}
		allErrNames[id.Name] = true
		return id.Name, true
	}

	sinkSliceSource := func(expr ast.Expr, st writerPathState, mode writerBlockMode) (string, bool) {
		id, ok := unwrapParens(expr).(*ast.Ident)
		if !ok || id.Name == "" {
			return "", false
		}
		switch mode {
		case writerBlockPlain:
			if id.Name == sliceParam && !st.sliceParamMutated {
				return sliceParam, true
			}
		case writerBlockSliceLoop:
			if id.Name == sliceParam && !st.sliceAdvancedInLoop {
				return sliceParam, true
			}
		case writerBlockChunkLoop:
			if st.chunkAdvancedInLoop {
				return "", false
			}
			if id.Name == sliceParam {
				return sliceParam, true
			}
			if chunkVars[id.Name] {
				return id.Name, true
			}
			if srcChunk, ok := bufChunkSource[id.Name]; ok && srcChunk != "" {
				return srcChunk, true
			}
		}
		return "", false
	}

	isValidTailSinkCall := func(call *ast.CallExpr, wantResults int, st writerPathState, mode writerBlockMode) bool {
		if mode != writerBlockPlain || call.Ellipsis.IsValid() {
			return false
		}
		if id, isID := unwrapParens(call.Fun).(*ast.Ident); isID {
			if cType := localClosures[id.Name]; cType != nil && cType.Results.NumFields() == wantResults && len(call.Args) == 1 {
				if _, ok := sinkSliceSource(call.Args[0], st, mode); ok {
					allowedPayloadCalls[call] = true
					return true
				}
				return false
			}
		}
		if wantResults == 2 && isUnderlyingBoundWriteCall(fn, call, binding) {
			if _, ok := sinkSliceSource(call.Args[0], st, mode); ok {
				allowedPayloadCalls[call] = true
				return true
			}
			return false
		}
		helperRecv, helperDecl, isLocal := resolveLocalHelper(recvType, fn, call, topFuncs, typeMethods)
		if !isLocal || helperDecl.Type == nil || helperDecl.Type.Results == nil || helperDecl.Type.Results.NumFields() != wantResults || !funcReturnsErrorLast(helperDecl.Type) {
			return false
		}
		if wantResults == 2 && !firstResultIsInt(helperDecl.Type.Results) {
			return false
		}
		calleeBinding, _, boundOK := deriveCalleeBinding(fn, recvType, binding, currentPayloadProtected(), call, helperRecv, helperDecl, func(arg ast.Expr) (string, bool) {
			return sinkSliceSource(arg, st, mode)
		})
		if boundOK && verifyTestingWriterFunc(helperRecv, helperDecl, calleeBinding, topFuncs, typeMethods, visiting) {
			allowedPayloadCalls[call] = true
			return true
		}
		return false
	}

	classifySinkAssignCall := func(lhsLen int, call *ast.CallExpr, st writerPathState, mode writerBlockMode) (isSink bool, chunkUsed string, ok bool) {
		if id, isID := unwrapParens(call.Fun).(*ast.Ident); isID {
			if cType, isClosure := localClosures[id.Name]; isClosure {
				if call.Ellipsis.IsValid() || len(call.Args) != 1 || lhsLen != cType.Results.NumFields() {
					return true, "", false
				}
				srcChunk, argOK := sinkSliceSource(call.Args[0], st, mode)
				if argOK {
					allowedPayloadCalls[call] = true
				}
				return true, srcChunk, argOK
			}
		}
		if helperRecv, helperDecl, isLocal := resolveLocalHelper(recvType, fn, call, topFuncs, typeMethods); isLocal {
			if helperDecl.Type == nil || helperDecl.Type.Results == nil || helperDecl.Type.Results.NumFields() == 0 {
				return false, "", false
			}
			if !funcReturnsErrorLast(helperDecl.Type) {
				return false, "", true
			}
			if lhsLen != helperDecl.Type.Results.NumFields() || (lhsLen == 2 && !firstResultIsInt(helperDecl.Type.Results)) {
				return true, "", false
			}
			calleeBinding, srcChunk, boundOK := deriveCalleeBinding(fn, recvType, binding, currentPayloadProtected(), call, helperRecv, helperDecl, func(arg ast.Expr) (string, bool) {
				return sinkSliceSource(arg, st, mode)
			})
			if !boundOK {
				return true, "", false
			}
			if !verifyTestingWriterFunc(helperRecv, helperDecl, calleeBinding, topFuncs, typeMethods, visiting) {
				return true, "", false
			}
			allowedPayloadCalls[call] = true
			return true, srcChunk, true
		}
		switch isBoundSyscallWriteCall(fn, call, binding) {
		case "write2":
			if mode != writerBlockSliceLoop || lhsLen != 2 {
				return true, "", false
			}
			srcChunk, argOK := sinkSliceSource(call.Args[1], st, mode)
			if !argOK || srcChunk != sliceParam {
				return true, "", false
			}
			allowedPayloadCalls[call] = true
			return true, srcChunk, true
		case "raw3":
			if mode != writerBlockSliceLoop || lhsLen != 3 || st.sliceAdvancedInLoop {
				return true, "", false
			}
			amp, innerCalls, ptrOK := isSliceZeroElemUintptrExpr(call.Args[2], sliceParam)
			if !ptrOK || !isSliceLenUintptrExpr(call.Args[3], sliceParam) {
				return true, "", false
			}
			if amp != nil {
				allowedSliceZeroAmps[amp] = true
			}
			allowedPayloadCalls[call] = true
			for _, ic := range innerCalls {
				allowedPayloadCalls[ic] = true
			}
			return true, sliceParam, true
		}
		if syscallWriteSinkKind(call) != "" {
			return true, "", false
		}
		if isUnderlyingBoundWriteCall(fn, call, binding) {
			if lhsLen != 2 {
				return true, "", false
			}
			srcChunk, argOK := sinkSliceSource(call.Args[0], st, mode)
			if argOK {
				allowedPayloadCalls[call] = true
			}
			return true, srcChunk, argOK
		}
		if sel, isSel := unwrapParens(call.Fun).(*ast.SelectorExpr); isSel && sel.Sel.Name == "Write" {
			return true, "", false
		}
		return false, "", true
	}

	verifySinkClosureLit := func(name string, lit *ast.FuncLit, mode writerBlockMode, inBranch bool) bool {
		if mode != writerBlockPlain || inBranch || lit == nil || lit.Type == nil || lit.Type.Results == nil || !funcReturnsErrorLast(lit.Type) {
			return false
		}
		cRes := lit.Type.Results.NumFields()
		if cRes != 1 && (cRes != 2 || !firstResultIsInt(lit.Type.Results)) {
			return false
		}
		cSlice := singleByteSliceParamIdent(lit.Type.Params)
		if cSlice == "" || name == "" || name == "_" || isProtectedIdent(name) || name == sliceParam {
			return false
		}
		closureEmpty := map[string]bool{}
		for k := range binding.emptyVars {
			if k != cSlice && !bodyDeclaresAnyIdent(lit.Body, map[string]bool{k: true}) && !bodyMutatesOrTakesAddrOfAny(lit.Body, map[string]bool{k: true}) {
				closureEmpty[k] = true
			}
		}
		closureBinding := testingWriterBinding{
			fileFields: binding.fileFields,
			fdFields:   binding.fdFields,
			fileVars:   binding.fileVars,
			fdVars:     binding.fdVars,
			emptyVars:  closureEmpty,
			sliceVar:   cSlice,
		}
		synth := &ast.FuncDecl{Name: &ast.Ident{Name: name}, Type: lit.Type, Body: lit.Body}
		if !verifyTestingWriterFunc(recvType, synth, closureBinding, topFuncs, typeMethods, visiting) {
			return false
		}
		verifiedClosureLits[lit] = true
		localClosures[name] = lit.Type
		return true
	}

	recordSinkCountLHS := func(lhsExprs []ast.Expr, st *writerPathState, mode writerBlockMode, chunkUsed string) bool {
		switch len(lhsExprs) {
		case 1:
			if mode == writerBlockSliceLoop {
				return false
			}
			st.liveCountVar = ""
			return true
		case 2, 3:
			countID, ok := unwrapParens(lhsExprs[0]).(*ast.Ident)
			if !ok || countID.Name == "" || countID.Name == sliceParam || localClosures[countID.Name] != nil || allErrNames[countID.Name] || allChunkNames[countID.Name] || allBufNames[countID.Name] || protectedSinks[countID.Name] {
				return false
			}
			if countID.Name == "_" {
				if !(mode == writerBlockPlain && numResults == 1 && len(lhsExprs) == 2) {
					return false
				}
				st.liveCountVar = ""
				return true
			}
			if len(lhsExprs) == 3 {
				r2ID, ok := unwrapParens(lhsExprs[1]).(*ast.Ident)
				if !ok || r2ID.Name == countID.Name || r2ID.Name == sliceParam || isProtectedIdent(r2ID.Name) {
					return false
				}
			}
			switch mode {
			case writerBlockSliceLoop:
				allLoopCountNames[countID.Name] = true
				loopCountAliases[countID.Name] = true
			case writerBlockPlain:
				if chunkUsed != sliceParam {
					return false
				}
				if allCountNames[countID.Name] && countID.Name != namedCountResult {
					return false
				}
				allCountNames[countID.Name] = true
				st.liveCountVar = countID.Name
			case writerBlockChunkLoop:
				if countID.Name == namedCountResult {
					return false
				}
				allCountNames[countID.Name] = true
			}
			return true
		default:
			return false
		}
	}

	checkValidCountReturnExpr := func(expr ast.Expr, st writerPathState) bool {
		expr = unwrapParens(expr)
		if st.liveErr != "" && isZeroIntLit(expr) {
			return true
		}
		if id, ok := expr.(*ast.Ident); ok {
			if st.liveCountVar != "" && id.Name == st.liveCountVar && (st.liveErr != "" || st.discharged2ResultSink) {
				return true
			}
			if namedCountResult != "" && id.Name == namedCountResult && st.latchedCount {
				return true
			}
		}
		if st.liveErr == "" && st.dischargedFullSlice1ResultSink && !st.sliceParamMutated && isLenOfIdentCall(expr, sliceParam) {
			return true
		}
		return false
	}

	checkReturn := func(ret *ast.ReturnStmt, st writerPathState, allowNilFromLoop bool, mode writerBlockMode) bool {
		switch len(ret.Results) {
		case 0:
			if namedErrResult == "" {
				return false
			}
			if numResults == 2 {
				if namedCountResult == "" {
					return false
				}
				if st.liveErr != "" && st.liveErr == namedErrResult && st.liveCountVar == namedCountResult {
					return true
				}
				if st.liveErr == "" && st.latchedSink && st.latchedCount {
					return true
				}
				return false
			}
			if st.liveErr != "" && st.liveErr == namedErrResult {
				return true
			}
			if st.liveErr == "" && st.latchedSink {
				return true
			}
			return false
		case 1:
			if numResults > 1 {
				if st.liveErr != "" {
					return false
				}
				call, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
				return ok && isValidTailSinkCall(call, numResults, st, mode)
			}
			fallthrough
		default:
			if len(ret.Results) != numResults {
				return false
			}
			last := unwrapParens(ret.Results[numResults-1])
			if numResults == 1 && st.liveErr == "" {
				if call, ok := last.(*ast.CallExpr); ok && isValidTailSinkCall(call, 1, st, mode) {
					return true
				}
			}
			if numResults == 2 && !checkValidCountReturnExpr(ret.Results[0], st) {
				return false
			}
			if st.liveErr != "" && exprIsUntaintedErrResult(last, st.liveErr) {
				return true
			}
			if st.liveErr == "" {
				if id, ok := last.(*ast.Ident); ok && namedErrResult != "" && id.Name == namedErrResult && st.latchedSink {
					return true
				}
				if id, ok := last.(*ast.Ident); ok && id.Name == "nil" && (allowNilFromLoop || (numResults == 2 && (st.dischargedFullSlice1ResultSink || st.discharged2ResultSink))) {
					return true
				}
			}
			return false
		}
	}

	applySinkAssign := func(lhsExprs []ast.Expr, srcChunk string, st writerPathState, mode writerBlockMode) (writerPathState, bool) {
		if st.liveErr != "" {
			return st, false
		}
		if !recordSinkCountLHS(lhsExprs, &st, mode, srcChunk) {
			return st, false
		}
		errName, bound := bindFreshErrIdent(lhsExprs[len(lhsExprs)-1])
		if !bound {
			return st, false
		}
		st.liveErr = errName
		st.lastChunk = srcChunk
		st.lastSinkResultArity = len(lhsExprs)
		if mode == writerBlockChunkLoop {
			st.activeChunk = srcChunk
		}
		if mode == writerBlockSliceLoop {
			st.sawSinkInLoop = true
		}
		st.dischargedLoop = false
		st.dischargedFullSlice1ResultSink = false
		st.discharged2ResultSink = false
		return st, true
	}

	var walkBlock func(stmts []ast.Stmt, st writerPathState, inErrCheckFor string, mode writerBlockMode, inBranch bool) (writerPathState, bool)
	walkBlock = func(stmts []ast.Stmt, st writerPathState, inErrCheckFor string, mode writerBlockMode, inBranch bool) (writerPathState, bool) {
		for idx, stmt := range stmts {
			if idx != len(stmts)-1 && blockAlwaysReturns([]ast.Stmt{stmt}) {
				return st, false
			}
			switch s := stmt.(type) {
			case *ast.EmptyStmt:
				continue
			case *ast.ExprStmt:
				call, isCall := unwrapParens(s.X).(*ast.CallExpr)
				if isCall {
					if id, isID := unwrapParens(call.Fun).(*ast.Ident); isID && localClosures[id.Name] != nil {
						return st, false
					}
					if _, helperDecl, isLocal := resolveLocalHelper(recvType, fn, call, topFuncs, typeMethods); isLocal && funcReturnsErrorLast(helperDecl.Type) {
						return st, false
					}
					if syscallWriteSinkKind(call) != "" {
						return st, false
					}
					if sel, isSel := unwrapParens(call.Fun).(*ast.SelectorExpr); isSel && sel.Sel.Name == "Write" {
						return st, false
					}
				}
			case *ast.DeferStmt:
				if _, isLit := unwrapParens(s.Call.Fun).(*ast.FuncLit); isLit {
					return st, false
				}
				if _, helperDecl, isLocal := resolveLocalHelper(recvType, fn, s.Call, topFuncs, typeMethods); isLocal && funcReturnsErrorLast(helperDecl.Type) {
					return st, false
				}
			case *ast.DeclStmt:
				gd, isGen := s.Decl.(*ast.GenDecl)
				if !isGen {
					continue
				}
				for _, spec := range gd.Specs {
					vs, isVal := spec.(*ast.ValueSpec)
					if !isVal {
						continue
					}
					if len(vs.Values) == 0 {
						if idType, isID := unwrapParens(vs.Type).(*ast.Ident); isID && idType.Name == "error" {
							for _, n := range vs.Names {
								if n.Name == "" || n.Name == "_" || n.Name == sliceParam || isProtectedIdent(n.Name) {
									return st, false
								}
							}
						} else {
							for _, n := range vs.Names {
								if n.Name == sliceParam || isProtectedIdent(n.Name) {
									return st, false
								}
							}
						}
						continue
					}
					if len(vs.Names) == 1 && len(vs.Values) == 1 {
						if lit, isLit := unwrapParens(vs.Values[0]).(*ast.FuncLit); isLit {
							if !verifySinkClosureLit(vs.Names[0].Name, lit, mode, inBranch) {
								return st, false
							}
							continue
						}
					}
					if len(vs.Values) == 1 {
						if call, isCall := unwrapParens(vs.Values[0]).(*ast.CallExpr); isCall {
							isSink, srcChunk, callOK := classifySinkAssignCall(len(vs.Names), call, st, mode)
							if !callOK {
								return st, false
							}
							if isSink {
								lhsExprs := make([]ast.Expr, len(vs.Names))
								for i, n := range vs.Names {
									lhsExprs[i] = n
								}
								var sinkOK bool
								st, sinkOK = applySinkAssign(lhsExprs, srcChunk, st, mode)
								if !sinkOK {
									return st, false
								}
								allowedPayloadValueSpecs[vs] = true
								continue
							}
						}
					}
					for _, n := range vs.Names {
						if n.Name == sliceParam || isProtectedIdent(n.Name) {
							return st, false
						}
					}
				}
			case *ast.AssignStmt:
				if len(s.Lhs) == 1 && len(s.Rhs) == 1 {
					if lit, isLit := unwrapParens(s.Rhs[0]).(*ast.FuncLit); isLit {
						id, isID := unwrapParens(s.Lhs[0]).(*ast.Ident)
						if !isID || !verifySinkClosureLit(id.Name, lit, mode, inBranch) {
							return st, false
						}
						continue
					}
				}
				if len(s.Rhs) == 1 {
					if call, isCall := unwrapParens(s.Rhs[0]).(*ast.CallExpr); isCall {
						isSink, srcChunk, callOK := classifySinkAssignCall(len(s.Lhs), call, st, mode)
						if !callOK {
							return st, false
						}
						if isSink {
							var sinkOK bool
							st, sinkOK = applySinkAssign(s.Lhs, srcChunk, st, mode)
							if !sinkOK {
								return st, false
							}
							allowedPayloadAssigns[s] = true
							continue
						}
					}
				}
				// Wrapping `err = &os.PathError{..., Err: err}` inside `if err != nil`.
				if s.Tok == token.ASSIGN && len(s.Lhs) == 1 && len(s.Rhs) == 1 && st.liveErr != "" && inErrCheckFor == st.liveErr {
					if id, isID := unwrapParens(s.Lhs[0]).(*ast.Ident); isID && id.Name == st.liveErr && isWrappedErrStructPtr(s.Rhs[0], st.liveErr) {
						continue
					}
				}
				// Slice-draining write loop helpers: `n := int(r1)`, `if errno != 0 { n = 0 }`, and `b = b[n:]` / `b = b[int(r1):]`.
				if mode == writerBlockSliceLoop && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
					if s.Tok == token.DEFINE {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && lhsID.Name != "" && lhsID.Name != "_" && lhsID.Name != sliceParam && !isProtectedIdent(lhsID.Name) {
							rhs := unwrapParens(s.Rhs[0])
							if conv, isCall := rhs.(*ast.CallExpr); isCall && len(conv.Args) == 1 && !conv.Ellipsis.IsValid() {
								if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
									rhs = unwrapParens(conv.Args[0])
								}
							}
							if srcID, ok := rhs.(*ast.Ident); ok && loopCountAliases[srcID.Name] {
								allLoopCountNames[lhsID.Name] = true
								loopCountAliases[lhsID.Name] = true
								continue
							}
						}
					}
					if s.Tok == token.ASSIGN && st.liveErr != "" && inErrCheckFor == st.liveErr {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && loopCountAliases[lhsID.Name] && isZeroIntLit(s.Rhs[0]) {
							continue
						}
					}
					if isCountAdvanceSliceAssign(s, sliceParam, loopCountAliases) {
						if st.sliceAdvancedInLoop {
							return st, false
						}
						st.sliceAdvancedInLoop = true
						allowedPayloadAssigns[s] = true
						continue
					}
				}
				// Chunking loop helpers: `chunk := payload`, `chunk = chunk[:cut]`, `buf := make([]byte, 0, ...)`, `buf = append(buf, ...)`, and `payload = payload[len(chunk):]`.
				if mode == writerBlockChunkLoop && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
					if s.Tok == token.DEFINE && !st.chunkAdvancedInLoop && st.activeChunk == "" {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && lhsID.Name != "" && lhsID.Name != "_" && lhsID.Name != sliceParam && !isProtectedIdent(lhsID.Name) {
							if rhsID, ok := unwrapParens(s.Rhs[0]).(*ast.Ident); ok && rhsID.Name == sliceParam {
								chunkVars[lhsID.Name] = true
								allChunkNames[lhsID.Name] = true
								allowedPayloadAssigns[s] = true
								continue
							}
							if makeCall, ok := unwrapParens(s.Rhs[0]).(*ast.CallExpr); ok && !makeCall.Ellipsis.IsValid() && len(makeCall.Args) >= 2 && len(makeCall.Args) <= 3 {
								if makeID, ok := unwrapParens(makeCall.Fun).(*ast.Ident); ok && makeID.Name == "make" && isByteSliceType(makeCall.Args[0]) && isZeroIntLit(makeCall.Args[1]) {
									if len(makeCall.Args) == 3 && exprRefsIdentOutsideLen(makeCall.Args[2], currentPayloadProtected()) {
										return st, false
									}
									freshBufVars[lhsID.Name] = true
									allBufNames[lhsID.Name] = true
									allowedPayloadCalls[makeCall] = true
									allowedPayloadAssigns[s] = true
									continue
								}
							}
						}
					}
					if s.Tok == token.ASSIGN && !st.chunkAdvancedInLoop && st.activeChunk == "" {
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && chunkVars[lhsID.Name] {
							sl, ok := unwrapParens(s.Rhs[0]).(*ast.SliceExpr)
							if !ok || sl.Slice3 || sl.Low != nil || sl.High == nil || isZeroIntLit(sl.High) || exprRefsIdentOutsideLen(sl.High, currentPayloadProtected()) {
								return st, false
							}
							baseID, ok := unwrapParens(sl.X).(*ast.Ident)
							if !ok || baseID.Name != lhsID.Name {
								return st, false
							}
							allowedPayloadAssigns[s] = true
							continue
						}
						if lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident); ok && freshBufVars[lhsID.Name] {
							appCall, ok := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
							if !ok || !appCall.Ellipsis.IsValid() || len(appCall.Args) != 2 {
								return st, false
							}
							appID, ok := unwrapParens(appCall.Fun).(*ast.Ident)
							if !ok || appID.Name != "append" {
								return st, false
							}
							dstID, ok := unwrapParens(appCall.Args[0]).(*ast.Ident)
							if !ok || dstID.Name != lhsID.Name {
								return st, false
							}
							if srcID, ok := unwrapParens(appCall.Args[1]).(*ast.Ident); ok && (srcID.Name == sliceParam || chunkVars[srcID.Name]) {
								if bufChunkSource[lhsID.Name] != "" {
									return st, false
								}
								bufChunkSource[lhsID.Name] = srcID.Name
								allowedPayloadCalls[appCall] = true
								allowedPayloadAssigns[s] = true
								continue
							}
							if bufChunkSource[lhsID.Name] == "" && isProvablyEmptyByteSliceArg(appCall.Args[1], binding) {
								allowedPayloadCalls[appCall] = true
								allowedPayloadAssigns[s] = true
								continue
							}
							return st, false
						}
					}
					if isChunkAdvanceSliceAssign(s, sliceParam, st.activeChunk) {
						if st.chunkAdvancedInLoop || st.liveErr != "" {
							return st, false
						}
						st.chunkAdvancedInLoop = true
						allowedPayloadAssigns[s] = true
						continue
					}
				}
				payloadProtectedNow := currentPayloadProtected()
				for _, lhs := range s.Lhs {
					switch target := unwrapParens(lhs).(type) {
					case *ast.Ident:
						if target.Name == sliceParam || isProtectedIdent(target.Name) {
							return st, false
						}
					case *ast.IndexExpr:
						if exprReferencesAnyIdent(target.X, payloadProtectedNow) {
							return st, false
						}
					case *ast.StarExpr:
						if exprReferencesAnyIdent(target.X, payloadProtectedNow) {
							return st, false
						}
					}
				}
				for _, rhs := range s.Rhs {
					var hasFuncLit bool
					ast.Inspect(rhs, func(n ast.Node) bool {
						if _, ok := n.(*ast.FuncLit); ok {
							hasFuncLit = true
							return false
						}
						return true
					})
					if hasFuncLit {
						return st, false
					}
				}
			case *ast.IfStmt:
				if s.Init != nil {
					return st, false
				}
				// Monotonic latch in chunking loops: `if chunkErr == nil && err == nil { written += len(chunk) } else if chunkErr != nil && err == nil { err = chunkErr }`
				if mode == writerBlockChunkLoop && !inBranch && st.liveErr != "" && namedErrResult != "" && !namedErrBoundDirectly {
					if updatedCount, latchOK := isMonotonicLatchIf(s, st.liveErr, namedErrResult, namedCountResult, st.activeChunk, numResults == 2); latchOK {
						everLatched = true
						st.latchedSink = true
						if updatedCount && namedCountResult != "" {
							st.latchedCount = true
						}
						st.liveErr = ""
						continue
					}
				}
				// Transient EINTR/EAGAIN retry inside a slice-draining write loop.
				if mode == writerBlockSliceLoop && !inBranch && st.liveErr != "" && isTransientErrnoRetryIf(s, st.liveErr) {
					continue
				}
				// Guarded slice advance `if n > 0 { b = b[n:] }` inside a slice-draining write loop.
				if mode == writerBlockSliceLoop && !inBranch && s.Else == nil && len(s.Body.List) == 1 && isCountPositiveCond(s.Cond, loopCountAliases) {
					if as, ok := s.Body.List[0].(*ast.AssignStmt); ok && isCountAdvanceSliceAssign(as, sliceParam, loopCountAliases) {
						if st.sliceAdvancedInLoop {
							return st, false
						}
						st.sliceAdvancedInLoop = true
						allowedPayloadAssigns[as] = true
						continue
					}
				}
				// Chunking loop exit `if len(payload) == 0 { return written, err }` after advancing payload.
				if mode == writerBlockChunkLoop && !inBranch && st.liveErr == "" && st.chunkAdvancedInLoop && s.Else == nil && len(s.Body.List) == 1 && isSliceLenZeroCond(s.Cond, sliceParam) {
					if ret, isRet := s.Body.List[0].(*ast.ReturnStmt); isRet {
						if !checkReturn(ret, st, false, mode) {
							return st, false
						}
						sawLenZeroExitReturn = true
						continue
					}
				}
				entrySt := st
				checkedErr := condChecksNonZeroErr(s.Cond)
				savedAllErrs := make(map[string]bool, len(allErrNames))
				for k, v := range allErrNames {
					savedAllErrs[k] = v
				}
				savedAllCounts := make(map[string]bool, len(allCountNames))
				for k, v := range allCountNames {
					savedAllCounts[k] = v
				}
				thenSt, thenOK := walkBlock(s.Body.List, entrySt, checkedErr, mode, true)
				if !thenOK {
					return st, false
				}
				thenRet := blockAlwaysReturns(s.Body.List)
				dischargeCheckedErr := func(base writerPathState) writerPathState {
					next := base
					if mode == writerBlockPlain && base.lastChunk == sliceParam {
						if base.lastSinkResultArity == 1 {
							next.dischargedFullSlice1ResultSink = true
						} else if base.lastSinkResultArity == 2 {
							next.discharged2ResultSink = true
						}
					}
					next.liveErr = ""
					return next
				}
				if s.Else == nil {
					if thenRet {
						if entrySt.liveErr != "" && checkedErr == entrySt.liveErr {
							st = dischargeCheckedErr(entrySt)
						} else if mode == writerBlockChunkLoop && entrySt.liveErr == "" {
							// Forbid arbitrary early returns from a chunking loop before draining sliceParam.
							return st, false
						} else {
							st = entrySt
						}
					} else {
						if thenSt != entrySt {
							return st, false
						}
						st = entrySt
					}
					continue
				}
				var elseStmts []ast.Stmt
				switch el := s.Else.(type) {
				case *ast.BlockStmt:
					elseStmts = el.List
				case *ast.IfStmt:
					elseStmts = []ast.Stmt{el}
				default:
					return st, false
				}
				if entrySt.liveErr == "" {
					if thenSt.liveErr != "" && !savedAllErrs[thenSt.liveErr] {
						delete(allErrNames, thenSt.liveErr)
					}
					if thenSt.liveCountVar != "" && !savedAllCounts[thenSt.liveCountVar] {
						delete(allCountNames, thenSt.liveCountVar)
					}
				}
				elseEntry := entrySt
				if thenRet && entrySt.liveErr != "" && checkedErr == entrySt.liveErr {
					elseEntry = dischargeCheckedErr(entrySt)
				}
				elseSt, elseOK := walkBlock(elseStmts, elseEntry, "", mode, true)
				if thenSt.liveErr != "" {
					allErrNames[thenSt.liveErr] = true
				}
				if thenSt.liveCountVar != "" {
					allCountNames[thenSt.liveCountVar] = true
				}
				if !elseOK {
					return st, false
				}
				elseRet := blockAlwaysReturns(elseStmts)
				switch {
				case thenRet && elseRet:
					st = writerPathState{}
				case thenRet && !elseRet:
					st = elseSt
				case !thenRet && elseRet:
					st = thenSt
				default:
					if thenSt != elseSt {
						return st, false
					}
					st = thenSt
				}
			case *ast.ForStmt:
				isPureNonSinkLoop := func(loop *ast.ForStmt) bool {
					if loop.Cond == nil {
						return false
					}
					loopPayloadProtected := currentPayloadProtected()
					var bad bool
					ast.Inspect(loop, func(n ast.Node) bool {
						if bad || n == nil {
							return false
						}
						switch node := n.(type) {
						case *ast.ReturnStmt, *ast.FuncLit, *ast.DeferStmt, *ast.GoStmt, *ast.LabeledStmt, *ast.SendStmt:
							bad = true
							return false
						case *ast.BranchStmt:
							if node.Tok == token.GOTO || node.Label != nil {
								bad = true
								return false
							}
						case *ast.CallExpr:
							if syscallWriteSinkKind(node) != "" {
								bad = true
								return false
							}
							if sel, ok := unwrapParens(node.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Write" {
								bad = true
								return false
							}
							if id, ok := unwrapParens(node.Fun).(*ast.Ident); ok && (localClosures[id.Name] != nil || topFuncs[id.Name] != nil) {
								bad = true
								return false
							}
						case *ast.AssignStmt:
							for _, lhs := range node.Lhs {
								switch target := unwrapParens(lhs).(type) {
								case *ast.Ident:
									if target.Name == sliceParam || isProtectedIdent(target.Name) {
										bad = true
										return false
									}
								case *ast.IndexExpr:
									if exprReferencesAnyIdent(target.X, loopPayloadProtected) {
										bad = true
										return false
									}
								case *ast.StarExpr:
									if exprReferencesAnyIdent(target.X, loopPayloadProtected) {
										bad = true
										return false
									}
								}
							}
						case *ast.IncDecStmt:
							id, ok := unwrapParens(node.X).(*ast.Ident)
							if !ok || id.Name == sliceParam || isProtectedIdent(id.Name) || loopPayloadProtected[id.Name] {
								bad = true
								return false
							}
						}
						return true
					})
					return !bad
				}
				if s.Init != nil || s.Post != nil {
					if !isPureNonSinkLoop(s) {
						return st, false
					}
					continue
				}
				if s.Cond != nil {
					if mode == writerBlockPlain && !inBranch && isLenSlicePositiveCond(s.Cond, sliceParam) && !st.sliceParamMutated && st.liveErr == "" {
						var badLoopBranch bool
						for _, ls := range s.Body.List {
							if _, isBr := ls.(*ast.BranchStmt); isBr {
								badLoopBranch = true
								break
							}
							if ifs, isIf := ls.(*ast.IfStmt); isIf {
								ast.Inspect(ifs, func(n ast.Node) bool {
									if badLoopBranch || n == nil {
										return false
									}
									switch bn := n.(type) {
									case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
										return false
									case *ast.BranchStmt:
										if bn.Tok == token.BREAK || bn.Tok == token.GOTO || bn.Label != nil {
											badLoopBranch = true
											return false
										}
										if bn.Tok == token.CONTINUE {
											if n != ifs.Body.List[0] || len(ifs.Body.List) != 1 || ifs.Else != nil {
												badLoopBranch = true
												return false
											}
										}
									}
									return true
								})
							}
						}
						if badLoopBranch {
							return st, false
						}
						loopCountAliases = map[string]bool{}
						loopSt, loopOK := walkBlock(s.Body.List, writerPathState{}, "", writerBlockSliceLoop, false)
						if !loopOK || loopSt.liveErr != "" || !loopSt.sawSinkInLoop || !loopSt.sliceAdvancedInLoop {
							return st, false
						}
						st.sliceParamMutated = true
						st.dischargedLoop = true
						st.dischargedFullSlice1ResultSink = false
						st.discharged2ResultSink = false
						continue
					}
					if !isPureNonSinkLoop(s) {
						return st, false
					}
					continue
				}
				// Unconditional `for { ... }` chunking loop.
				if mode != writerBlockPlain || inBranch || st.liveErr != "" || st.sliceParamMutated {
					return st, false
				}
				var hasOuterBranch bool
				ast.Inspect(s.Body, func(n ast.Node) bool {
					if hasOuterBranch || n == nil {
						return false
					}
					switch bn := n.(type) {
					case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.FuncLit:
						return false
					case *ast.BranchStmt:
						if bn.Tok == token.BREAK || bn.Tok == token.CONTINUE || bn.Tok == token.GOTO || bn.Label != nil {
							hasOuterBranch = true
							return false
						}
					}
					return true
				})
				if hasOuterBranch {
					return st, false
				}
				sawLenZeroExitReturn = false
				chunkVars = map[string]bool{}
				freshBufVars = map[string]bool{}
				bufChunkSource = map[string]string{}
				loopSt, loopOK := walkBlock(s.Body.List, writerPathState{}, "", writerBlockChunkLoop, false)
				if !loopOK || loopSt.liveErr != "" || !loopSt.chunkAdvancedInLoop || !sawLenZeroExitReturn {
					return st, false
				}
				st.sliceParamMutated = true
			case *ast.ReturnStmt:
				if mode == writerBlockChunkLoop && st.liveErr == "" {
					// Chunking loop exits when liveErr == "" must go through `if len(sliceParam) == 0 { return ... }` after advancing.
					return st, false
				}
				if !checkReturn(s, st, st.dischargedLoop && inErrCheckFor == "", mode) {
					return st, false
				}
				st.liveErr = ""
			case *ast.IncDecStmt:
				id, ok := unwrapParens(s.X).(*ast.Ident)
				if !ok || id.Name == sliceParam || isProtectedIdent(id.Name) {
					return st, false
				}
			case *ast.BlockStmt:
				var blkOK bool
				st, blkOK = walkBlock(s.List, st, inErrCheckFor, mode, inBranch)
				if !blkOK {
					return st, false
				}
			default:
				return st, false
			}
		}
		return st, true
	}

	endSt, ok := walkBlock(fn.Body.List, writerPathState{}, "", writerBlockPlain, false)
	if !ok || endSt.liveErr != "" {
		return false
	}

	// Whole-body post-check: forbid labels/goto/labeled-branches, taking addresses of
	// protected/slice variables (other than validated `&b[0]` inside `RawSyscall`),
	// unverified closures, closure mutation/aliasing of outer protected variables, ++/-- on
	// protected vars or indexed/dereferenced operands, defers referencing protected vars,
	// and any unapproved payload/chunk/buf/empty-var aliasing, mutation, or call escape.
	payloadProtected := currentPayloadProtected()
	protectedAll := map[string]bool{sliceParam: true}
	for k := range localClosures {
		protectedAll[k] = true
	}
	for k := range allErrNames {
		protectedAll[k] = true
	}
	for k := range allCountNames {
		protectedAll[k] = true
	}
	for k := range allLoopCountNames {
		protectedAll[k] = true
	}
	for k := range allChunkNames {
		protectedAll[k] = true
	}
	for k := range allBufNames {
		protectedAll[k] = true
	}
	for k := range protectedSinks {
		protectedAll[k] = true
	}

	var postCheckBad bool
	var inspectNoNestedClosures func(node ast.Node)
	inspectNoNestedClosures = func(node ast.Node) {
		if postCheckBad || node == nil {
			return
		}
		switch x := node.(type) {
		case *ast.FuncLit:
			if !verifiedClosureLits[x] {
				postCheckBad = true
				return
			}
			// Do not descend into verified sink closures with the outer variable names
			// (the inner closure has already passed its own whole-body post-check);
			// verify the inner closure does not mutate outer protected variables or
			// reference outer non-empty payload/chunk/buf variables.
			outerProtected := map[string]bool{}
			for k := range protectedAll {
				outerProtected[k] = true
			}
			outerPayload := map[string]bool{sliceParam: true}
			for k := range allChunkNames {
				outerPayload[k] = true
			}
			for k := range allBufNames {
				outerPayload[k] = true
			}
			for _, p := range paramNamesFlat(x.Type.Params) {
				delete(outerProtected, p)
				delete(outerPayload, p)
			}
			if bodyMutatesOrTakesAddrOfAny(x.Body, outerProtected) || exprReferencesAnyIdent(x.Body, outerPayload) {
				postCheckBad = true
			}
			return
		case *ast.GoStmt, *ast.LabeledStmt, *ast.SendStmt:
			postCheckBad = true
			return
		case *ast.BranchStmt:
			if x.Tok == token.GOTO || x.Label != nil {
				postCheckBad = true
				return
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND && !allowedSliceZeroAmps[x] {
				if id, ok := unwrapParens(x.X).(*ast.Ident); ok && protectedAll[id.Name] {
					postCheckBad = true
					return
				}
				if exprReferencesAnyIdent(x.X, payloadProtected) {
					postCheckBad = true
					return
				}
			}
		case *ast.IncDecStmt:
			id, ok := unwrapParens(x.X).(*ast.Ident)
			if !ok || protectedAll[id.Name] || payloadProtected[id.Name] {
				postCheckBad = true
				return
			}
		case *ast.DeferStmt:
			if _, isLit := unwrapParens(x.Call.Fun).(*ast.FuncLit); isLit {
				postCheckBad = true
				return
			}
			if exprReferencesAnyIdent(x.Call, protectedAll) || exprReferencesAnyIdent(x.Call, payloadProtected) {
				postCheckBad = true
				return
			}
		case *ast.ValueSpec:
			if !allowedPayloadValueSpecs[x] {
				for _, v := range x.Values {
					if lit, isLit := unwrapParens(v).(*ast.FuncLit); isLit && verifiedClosureLits[lit] {
						continue
					}
					if exprRefsIdentOutsideLen(v, payloadProtected) {
						postCheckBad = true
						return
					}
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				switch target := unwrapParens(lhs).(type) {
				case *ast.IndexExpr:
					if exprReferencesAnyIdent(target.X, payloadProtected) {
						postCheckBad = true
						return
					}
				case *ast.StarExpr:
					if exprReferencesAnyIdent(target.X, payloadProtected) {
						postCheckBad = true
						return
					}
				}
			}
			if !allowedPayloadAssigns[x] {
				for _, rhs := range x.Rhs {
					if lit, isLit := unwrapParens(rhs).(*ast.FuncLit); isLit && verifiedClosureLits[lit] {
						continue
					}
					if exprRefsIdentOutsideLen(rhs, payloadProtected) {
						postCheckBad = true
						return
					}
				}
			}
		case *ast.ReturnStmt:
			for _, res := range x.Results {
				if call, ok := unwrapParens(res).(*ast.CallExpr); ok && (allowedPayloadCalls[call] || isOneArgLenIdentCall(call)) {
					continue
				}
				if exprRefsIdentOutsideLen(res, payloadProtected) {
					postCheckBad = true
					return
				}
			}
		case *ast.CallExpr:
			if !allowedPayloadCalls[x] && !isOneArgLenIdentCall(x) {
				if exprRefsIdentOutsideLen(x.Fun, payloadProtected) {
					postCheckBad = true
					return
				}
				for _, arg := range x.Args {
					if exprRefsIdentOutsideLen(arg, payloadProtected) {
						postCheckBad = true
						return
					}
				}
			}
		}
		ast.Inspect(node, func(ch ast.Node) bool {
			if ch == node {
				return true
			}
			inspectNoNestedClosures(ch)
			return false
		})
	}
	inspectNoNestedClosures(fn.Body)
	return !postCheckBad
}


func verifyTestingCustomWriter(typeName string, allowedLit *ast.CompositeLit, binding testingWriterBinding, files []*ast.File, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl) bool {
	if typeName == "" || ast.IsExported(typeName) || allowedLit == nil || (len(binding.fileFields) == 0 && len(binding.fdFields) == 0) {
		return false
	}
	allBoundFields := map[string]bool{}
	for k := range binding.fileFields {
		allBoundFields[k] = true
	}
	for k := range binding.fdFields {
		allBoundFields[k] = true
	}

	var matchedSpecs []*ast.TypeSpec
	allowedTypeIdents := map[*ast.Ident]bool{}
	if litTypeID, ok := unwrapParens(allowedLit.Type).(*ast.Ident); ok && litTypeID.Name == typeName {
		allowedTypeIdents[litTypeID] = true
	} else {
		return false
	}

	var methodDecls []*ast.FuncDecl
	for _, f := range files {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				if d.Tok != token.TYPE {
					continue
				}
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if ok && ts.Name.Name == typeName {
						matchedSpecs = append(matchedSpecs, ts)
						allowedTypeIdents[ts.Name] = true
					}
				}
			case *ast.FuncDecl:
				if d.Recv != nil && len(d.Recv.List) == 1 {
					if rID := recvTypeIdent(d.Recv.List[0].Type); rID != nil && rID.Name == typeName {
						allowedTypeIdents[rID] = true
						methodDecls = append(methodDecls, d)
					}
				}
			}
		}
	}
	if len(matchedSpecs) != 1 {
		return false
	}
	ts := matchedSpecs[0]
	if ts.Assign.IsValid() || ts.TypeParams != nil {
		return false
	}
	st, ok := unwrapParens(ts.Type).(*ast.StructType)
	if !ok || st.Fields == nil {
		return false
	}
	declaredFields := map[string]bool{}
	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			return false
		}
		for _, fn := range field.Names {
			declaredFields[fn.Name] = true
		}
	}
	for bf := range allBoundFields {
		if !declaredFields[bf] {
			return false
		}
	}

	// Verify typeName is referenced nowhere else in package testing (no other
	// composite literals, zero-value vars, new(...), fields, params, or type assertions).
	if !allNonSelPropIdentsIn(files, typeName, allowedTypeIdents) {
		return false
	}

	// Verify every method on typeName keeps the receiver unescaped and never
	// mutates or takes the address of any bound field.
	for _, m := range methodDecls {
		if m.Body == nil {
			return false
		}
		recv := recvVarName(m)
		if recv == "" {
			continue
		}
		if bodyMutatesOrTakesAddrOfAny(m.Body, map[string]bool{recv: true}) || !blockOnlySelectsOnIdent(m.Body, recv) || nodeMutatesOrTakesAddrOfSelector(m.Body, recv, allBoundFields) {
			return false
		}
	}

	methods := typeMethods[typeName]
	if methods == nil || len(methods) != len(methodDecls) {
		return false
	}
	if methods["ReadFrom"] != nil {
		return false
	}
	if wsFn := methods["WriteString"]; wsFn != nil {
		wsRecv := recvVarName(wsFn)
		if wsRecv == "" || wsFn.Body == nil || len(wsFn.Body.List) != 1 || wsFn.Type == nil || wsFn.Type.Params == nil || wsFn.Type.Results == nil || wsFn.Type.Params.NumFields() != 1 || len(wsFn.Type.Params.List) != 1 || len(wsFn.Type.Params.List[0].Names) != 1 || wsFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wsFn.Type.Results) || !funcReturnsErrorLast(wsFn.Type) {
			return false
		}
		if _, ok := isIdentNamed(wsFn.Type.Params.List[0].Type, "string"); !ok {
			return false
		}
		sParam := wsFn.Type.Params.List[0].Names[0].Name
		if sParam == "" || sParam == "_" || sParam == wsRecv || funcShadowsAnyIdent(wsFn, map[string]bool{"byte": true, "string": true, "int": true, "error": true}) {
			return false
		}
		ret, ok := wsFn.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return false
		}
		wCall, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
		if !ok || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
			return false
		}
		if _, ok := isSelectorBaseField(wCall.Fun, wsRecv, "Write"); !ok {
			return false
		}
		conv, ok := unwrapParens(wCall.Args[0]).(*ast.CallExpr)
		if !ok || conv.Ellipsis.IsValid() || len(conv.Args) != 1 || !isByteSliceType(conv.Fun) {
			return false
		}
		if _, ok := isIdentNamed(conv.Args[0], sParam); !ok {
			return false
		}
	}
	writeFn := methods["Write"]
	if writeFn == nil || writeFn.Body == nil || writeFn.Type == nil || writeFn.Type.Params == nil || writeFn.Type.Results == nil || writeFn.Type.Results.NumFields() != 2 || !firstResultIsInt(writeFn.Type.Results) || !funcReturnsErrorLast(writeFn.Type) {
		return false
	}
	binding.sliceVar = singleByteSliceParamIdent(writeFn.Type.Params)
	if binding.sliceVar == "" {
		return false
	}
	return verifyTestingWriterFunc(typeName, writeFn, binding, topFuncs, typeMethods, map[string]bool{})
}

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

func verifyTestingStartLogArg(arg ast.Expr, files []*ast.File, topFuncs map[string]*ast.FuncDecl, typeMethods map[string]map[string]*ast.FuncDecl) (string, string, bool) {
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
		if !ok || fileVar == "" || !verifyTestingCustomWriter(wType, lit, binding, files, topFuncs, typeMethods) {
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
		if !blockAlwaysReturns(wrapFn.Body.List) {
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
		ast.Inspect(wrapFn.Body, func(n ast.Node) bool {
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
					if binding, ok := extractCompositeWriterBinding(lit, isWrapFileSource); ok && verifyTestingCustomWriter(wType, lit, binding, files, topFuncs, typeMethods) {
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

func verifyTestingPackageAST(files []*ast.File, runtimePullLinknames, selfPushLinknames map[string]bool) error {
	pkgReserved := map[string]bool{
		"os":      true,
		"fmt":     true,
		"io":      true,
		"flag":    true,
		"sync":    true,
		"syscall": true,
		"panic":   true,
		"recover": true,
		"new":     true,
		"len":     true,
		"append":  true,
		"make":    true,
		"copy":    true,
		"clear":   true,
		"uintptr": true,
		"int":     true,
		"byte":    true,
		"string":  true,
		"bool":    true,
		"nil":     true,
		"error":   true,
		"true":    true,
		"false":   true,
	}
	idx, err := indexPackageAST("testing", files, pkgReserved, map[string]bool{
		"os": true, "fmt": true, "io": true, "flag": true, "sync": true, "syscall": true,
	})
	if err != nil {
		return err
	}
	if idx.anyDupTypeMethod || len(idx.dupTopFuncs) > 0 {
		return fmt.Errorf("testing: duplicate method or function declarations")
	}
	for _, d := range idx.bodylessFuncs {
		if d.Recv != nil || !runtimePullLinknames[d.Name.Name] {
			return fmt.Errorf("testing: unexpected bodyless function %s", d.Name.Name)
		}
	}
	var hasValidContextMethod, hasInvalidContextMethod bool
	for _, d := range idx.funcDeclsByName["Context"] {
		if verifyTestingContextDecl(d) {
			hasValidContextMethod = true
		} else {
			hasInvalidContextMethod = true
		}
	}
	fileImportsOS := idx.fileImportSet("os")
	fileImportsFmt := idx.fileImportSet("fmt")
	fileImportsIO := idx.fileImportSet("io")
	fileImportsFlag := idx.fileImportSet("flag")
	fileImportsSync := idx.fileImportSet("sync")
	fileImportsSyscall := idx.fileImportSet("syscall")
	funcFile := idx.funcFile
	topFuncs := idx.topFuncs
	dupTopFuncs := idx.dupTopFuncs
	typeMethods := idx.typeMethods
	pkgVarCounts := idx.pkgValueCounts
	zeroInitPkgVars := idx.zeroInitPkgVars
	zeroInitBoolVars := idx.zeroInitBoolVars
	initPkgVars := idx.initPkgVars
	initPkgVarFile := idx.initPkgVarFile
	flagAllowedDeclIdents := idx.varDeclIdents
	recordAllowedFlagIdent := func(name string, id *ast.Ident) {
		if name == "" || name == "_" || id == nil {
			return
		}
		if flagAllowedDeclIdents[name] == nil {
			flagAllowedDeclIdents[name] = map[*ast.Ident]bool{}
		}
		flagAllowedDeclIdents[name][id] = true
	}
	for sym := range runtimePullLinknames {
		if fn := topFuncs[sym]; fn == nil || fn.Body != nil {
			return fmt.Errorf("testing: runtime pull linkname %s missing bodyless declaration", sym)
		}
	}
	for sym := range selfPushLinknames {
		if fn := topFuncs[sym]; fn == nil || fn.Body == nil {
			return fmt.Errorf("testing: push linkname %s missing concrete top-level function", sym)
		}
	}

	// Count all occurrences of "Main" across files to verify legacy func Main is unreferenced.
	mainIdentCount := 0
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "Main" {
				mainIdentCount++
			}
			return true
		})
	}

	// Package-wide Exit / flag / raw-syscall audit: prevent exit-0 and flag-mutation bypasses anywhere in testing.
	var mRunExitCalls []*ast.CallExpr
	var osExitSites []testingExitSite
	flagRegCounts := map[string]int{}
	for _, f := range files {
		directCalls := map[*ast.SelectorExpr]*ast.CallExpr{}
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && !call.Ellipsis.IsValid() {
				if sel, ok2 := unwrapParens(call.Fun).(*ast.SelectorExpr); ok2 {
					directCalls[sel] = call
				}
			}
			return true
		})
		var exitErr error
		ast.Inspect(f, func(n ast.Node) bool {
			if exitErr != nil || n == nil {
				return false
			}
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Set" {
				if innerSel, okS := unwrapParens(sel.X).(*ast.SelectorExpr); okS && innerSel.Sel.Name == "CommandLine" {
					exitErr = fmt.Errorf("testing: forbidden CommandLine.Set reference")
					return false
				}
			}
			pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
			if !ok {
				return true
			}
			switch pkgID.Name {
			case "CommandLine":
				if sel.Sel.Name == "Set" {
					exitErr = fmt.Errorf("testing: forbidden CommandLine.Set reference")
					return false
				}
			case "flag":
				if !fileImportsFlag[f] {
					exitErr = fmt.Errorf("testing: flag selector without unaliased flag import")
					return false
				}
				call := directCalls[sel]
				switch sel.Sel.Name {
				case "Parsed", "Parse", "Usage":
					if call == nil || len(call.Args) != 0 {
						exitErr = fmt.Errorf("testing: flag.%s must be a direct 0-argument call", sel.Sel.Name)
						return false
					}
				case "Bool", "Int", "Int64", "Uint", "Uint64", "String", "Float64", "Duration", "Var":
					if call == nil || len(call.Args) != 3 {
						exitErr = fmt.Errorf("testing: flag.%s must be a direct 3-argument call", sel.Sel.Name)
						return false
					}
					nameIdx := 0
					if sel.Sel.Name == "Var" {
						nameIdx = 1
					}
					nameLit, okL := unwrapParens(call.Args[nameIdx]).(*ast.BasicLit)
					if !okL || nameLit.Kind != token.STRING {
						exitErr = fmt.Errorf("testing: flag.%s requires literal flag name", sel.Sel.Name)
						return false
					}
					parsedName, uErr := strconv.Unquote(nameLit.Value)
					if uErr != nil || parsedName == "" {
						exitErr = fmt.Errorf("testing: invalid flag.%s name literal", sel.Sel.Name)
						return false
					}
					flagRegCounts[parsedName]++
				default:
					exitErr = fmt.Errorf("testing: forbidden flag.%s reference", sel.Sel.Name)
					return false
				}
			case "syscall":
				switch sel.Sel.Name {
				case "Exit", "Syscall", "Syscall6", "RawSyscall6":
					exitErr = fmt.Errorf("testing: forbidden syscall.%s reference", sel.Sel.Name)
					return false
				case "RawSyscall":
					call := directCalls[sel]
					if call == nil || len(call.Args) != 4 || !fileImportsSyscall[f] {
						exitErr = fmt.Errorf("testing: forbidden or non-SYS_WRITE syscall.RawSyscall")
						return false
					}
					sysSel, ok := unwrapParens(call.Args[0]).(*ast.SelectorExpr)
					if !ok || sysSel.Sel.Name != "SYS_WRITE" {
						exitErr = fmt.Errorf("testing: syscall.RawSyscall allowed only for SYS_WRITE")
						return false
					}
					sysPkg, ok := unwrapParens(sysSel.X).(*ast.Ident)
					if !ok || sysPkg.Name != "syscall" {
						exitErr = fmt.Errorf("testing: syscall.RawSyscall requires syscall.SYS_WRITE")
						return false
					}
				}
			case "os":
				if sel.Sel.Name != "Exit" {
					return true
				}
				call := directCalls[sel]
				if call == nil || len(call.Args) != 1 || !fileImportsOS[f] {
					exitErr = fmt.Errorf("testing: os.Exit must be a direct 1-argument call")
					return false
				}
				encFn, encAncestors := findEnclosingFuncAndAncestors(f, call)
				if encFn == nil || funcShadowsAnyIdent(encFn, map[string]bool{"os": true}) {
					exitErr = fmt.Errorf("testing: os.Exit outside verified function declaration")
					return false
				}
				isMRun := encFn.Recv != nil && len(encFn.Recv.List) == 1 && recvTypeName(encFn.Recv.List[0].Type) == "M" && encFn.Name.Name == "Run"
				if !exprHasCallOrFuncLit(call.Args[0]) && isPositiveIntLit(call.Args[0]) {
					if isMRun {
						mRunExitCalls = append(mRunExitCalls, call)
					}
					osExitSites = append(osExitSites, testingExitSite{
						file:      f,
						call:      call,
						encFn:     encFn,
						ancestors: encAncestors,
					})
					return true
				}
				if encFn.Recv == nil && encFn.Name.Name == "Main" && !dupTopFuncs["Main"] && !selfPushLinknames["Main"] && mainIdentCount == 1 && len(encAncestors) == 3 && len(encFn.Body.List) == 1 {
					return true
				}
				exitErr = fmt.Errorf("testing: non-positive or unverified os.Exit in %s", encFn.Name.Name)
				return false
			}
			return true
		})
		if exitErr != nil {
			return exitErr
		}
	}
	if flagRegCounts["test.testlogfile"] != 1 || flagRegCounts["test.list"] > 1 {
		return fmt.Errorf("testing: duplicate or missing test.testlogfile/test.list flag registration")
	}

	// Discover unexported package-level string-pointer flags registered for
	// "test.testlogfile" and "test.list" with empty default "", via either Form A
	// (package-level var initializer) or Form B (once-guarded Init() called by MainStart),
	// and verify neither the pointer nor *pointer is mutated or address-taken elsewhere.
	varWriteCount := map[string]int{}
	flagAddrTaken := map[string]bool{}
	flagDerefMutated := map[string]bool{}
	recordLHSWrite := func(lhs ast.Expr) {
		switch x := unwrapParens(lhs).(type) {
		case *ast.Ident:
			if x.Name != "" && x.Name != "_" {
				varWriteCount[x.Name]++
			}
		case *ast.StarExpr:
			if id, ok := unwrapParens(x.X).(*ast.Ident); ok && id.Name != "" && id.Name != "_" {
				flagDerefMutated[id.Name] = true
			}
		}
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					recordLHSWrite(lhs)
				}
			case *ast.RangeStmt:
				if node.Key != nil {
					recordLHSWrite(node.Key)
				}
				if node.Value != nil {
					recordLHSWrite(node.Value)
				}
			case *ast.IncDecStmt:
				recordLHSWrite(node.X)
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					switch x := unwrapParens(node.X).(type) {
					case *ast.Ident:
						flagAddrTaken[x.Name] = true
					case *ast.StarExpr:
						if id, ok := unwrapParens(x.X).(*ast.Ident); ok {
							flagAddrTaken[id.Name] = true
						}
					}
				}
			}
			return true
		})
	}

	testlogfileFlagVars := map[string]bool{}
	listFlagVars := map[string]bool{}
	emptyDefaultStringFlags := map[string]bool{}
	flagInitFunc := map[string]*ast.FuncDecl{}

	// Form A: var fv = flag.String("...", "", ...)
	for fv, initExpr := range initPkgVars {
		f := initPkgVarFile[fv]
		if ast.IsExported(fv) || pkgVarCounts[fv] != 1 || varWriteCount[fv] != 0 || flagAddrTaken[fv] || flagDerefMutated[fv] || !fileImportsFlag[f] {
			continue
		}
		call, ok := unwrapParens(initExpr).(*ast.CallExpr)
		if !ok {
			continue
		}
		if flagName, ok := flagStringEmptyDefaultName(call); ok {
			switch flagName {
			case "test.testlogfile":
				testlogfileFlagVars[fv] = true
			case "test.list":
				listFlagVars[fv] = true
			default:
				emptyDefaultStringFlags[fv] = true
			}
		}
	}

	// Form B: zero-init var fv assigned once at top level of a 0-arg/0-result Init-style function.
	for name, fn := range topFuncs {
		f := funcFile[fn]
		if fn == nil || fn.Body == nil || !fileImportsFlag[f] || name == "MainStart" || name == "Main" {
			continue
		}
		if (fn.Type.Params != nil && fn.Type.Params.NumFields() != 0) || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) {
			continue
		}
		if funcShadowsAnyIdent(fn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			continue
		}
		startCheckIdx := 0
		if len(fn.Body.List) >= 2 {
			if ifs, ok := fn.Body.List[0].(*ast.IfStmt); ok && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if ret, ok2 := ifs.Body.List[0].(*ast.ReturnStmt); ok2 && len(ret.Results) == 0 {
					if onceID, ok3 := unwrapParens(ifs.Cond).(*ast.Ident); ok3 && !ast.IsExported(onceID.Name) && zeroInitBoolVars[onceID.Name] && pkgVarCounts[onceID.Name] == 1 && varWriteCount[onceID.Name] == 1 && !flagAddrTaken[onceID.Name] && !funcShadowsAnyIdent(fn, map[string]bool{onceID.Name: true}) {
						if as1, ok4 := fn.Body.List[1].(*ast.AssignStmt); ok4 && as1.Tok == token.ASSIGN && len(as1.Lhs) == 1 && len(as1.Rhs) == 1 {
							_, okL := isIdentNamed(as1.Lhs[0], onceID.Name)
							_, okR := isIdentNamed(as1.Rhs[0], "true")
							if okL && okR {
								startCheckIdx = 2
							}
						}
					}
				}
			}
		}
		seenFlags := map[string]bool{}
		for idx := startCheckIdx; idx < len(fn.Body.List); idx++ {
			stmt := fn.Body.List[idx]
			if as, ok := stmt.(*ast.AssignStmt); ok && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if lhsID, ok2 := unwrapParens(as.Lhs[0]).(*ast.Ident); ok2 && !ast.IsExported(lhsID.Name) && zeroInitPkgVars[lhsID.Name] != nil && pkgVarCounts[lhsID.Name] == 1 && varWriteCount[lhsID.Name] == 1 && !flagAddrTaken[lhsID.Name] && !flagDerefMutated[lhsID.Name] && !funcShadowsAnyIdent(fn, map[string]bool{lhsID.Name: true}) {
					if call, ok3 := unwrapParens(as.Rhs[0]).(*ast.CallExpr); ok3 {
						if flagName, okName := flagStringEmptyDefaultName(call); okName && !seenFlags[flagName] {
							recordAllowedFlagIdent(lhsID.Name, lhsID)
							switch flagName {
							case "test.testlogfile":
								testlogfileFlagVars[lhsID.Name] = true
								flagInitFunc[lhsID.Name] = fn
							case "test.list":
								listFlagVars[lhsID.Name] = true
								flagInitFunc[lhsID.Name] = fn
							default:
								emptyDefaultStringFlags[lhsID.Name] = true
								flagInitFunc[lhsID.Name] = fn
							}
						}
					}
				}
			}
			if !isBenignFlagInitRegStmt(stmt, seenFlags) {
				break
			}
		}
	}
	if len(testlogfileFlagVars) == 0 {
		return fmt.Errorf("testing: missing verified test.testlogfile flag registration")
	}

	stopLogAssign := func(stmt ast.Stmt) (string, *ast.CallExpr) {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok || (as.Tok != token.DEFINE && as.Tok != token.ASSIGN) || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return "", nil
		}
		id, ok := unwrapParens(as.Lhs[0]).(*ast.Ident)
		if !ok || id.Name == "" || id.Name == "_" || id.Name == "nil" {
			return "", nil
		}
		call, ok := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 || !isMethodCallNamed(call, "StopTestLog") {
			return "", nil
		}
		return id.Name, call
	}

	validateCallAncestors := func(fn *ast.FuncDecl, ancestors []ast.Node, stmtIdx int) (flagGuard string, topStmt ast.Stmt, ok bool) {
		if fn == nil || stmtIdx < 1 || stmtIdx >= len(ancestors) {
			return "", nil, false
		}
		ts, isStmt := ancestors[1].(ast.Stmt)
		if !isStmt {
			return "", nil, false
		}
		for i := 0; i < stmtIdx; i++ {
			switch node := ancestors[i].(type) {
			case *ast.BlockStmt:
				childStmt, isStmt := ancestors[i+1].(ast.Stmt)
				if !isStmt {
					return "", nil, false
				}
				foundIdx := -1
				for j, bs := range node.List {
					if bs == childStmt {
						foundIdx = j
						break
					}
				}
				if foundIdx < 0 {
					return "", nil, false
				}
				for _, prior := range node.List[:foundIdx] {
					if stmtAlwaysTerminates(prior) {
						return "", nil, false
					}
				}
			case *ast.IfStmt:
				if node.Init != nil || node.Else != nil || ancestors[i+1] != node.Body || flagGuard != "" {
					return "", nil, false
				}
				fg, ok := derefFlagNonEmptyCondIdent(node.Cond)
				if !ok || !testlogfileFlagVars[fg] || funcShadowsAnyIdent(fn, map[string]bool{fg: true}) {
					return "", nil, false
				}
				flagGuard = fg
			default:
				return "", nil, false
			}
		}
		if flagGuard == "" {
			return "", nil, false
		}
		return flagGuard, ts, true
	}

	blockDeclaresVarBefore := func(blk *ast.BlockStmt, limit int, varName string) bool {
		for _, raw := range blk.List[:limit] {
			switch s := raw.(type) {
			case *ast.DeclStmt:
				if gd, ok := s.Decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
					for _, spec := range gd.Specs {
						if vs, ok2 := spec.(*ast.ValueSpec); ok2 {
							for _, id := range vs.Names {
								if id.Name == varName {
									return true
								}
							}
						}
					}
				}
			case *ast.AssignStmt:
				if s.Tok == token.DEFINE {
					for _, lhs := range s.Lhs {
						if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == varName {
							return true
						}
					}
				}
			}
		}
		return false
	}

	var hasInvalidStartCall bool
	var verifiedStarts []verifiedStartInfo

	for _, f := range files {
		var startCalls []*ast.CallExpr
		ast.Inspect(f, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && isMethodCallNamed(call, "StartTestLog") {
				startCalls = append(startCalls, call)
			}
			return true
		})
		for _, call := range startCalls {
			if len(call.Args) != 1 || call.Ellipsis.IsValid() || !fileImportsOS[f] {
				hasInvalidStartCall = true
				continue
			}
			fileVar, wrapName, ok := verifyTestingStartLogArg(call.Args[0], files, topFuncs, typeMethods)
			if !ok || fileVar == "" {
				hasInvalidStartCall = true
				continue
			}
			fn, ancestors := findEnclosingFuncAndAncestors(f, call)
			if fn == nil || len(ancestors) < 2 {
				hasInvalidStartCall = true
				continue
			}
			reserved := map[string]bool{}
			for k := range pkgReserved {
				reserved[k] = true
			}
			if wrapName != "" {
				reserved[wrapName] = true
			}
			if funcShadowsAnyIdent(fn, reserved) || funcDeclaresParamOrResult(fn, fileVar) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
				hasInvalidStartCall = true
				continue
			}
			es, ok := ancestors[len(ancestors)-2].(*ast.ExprStmt)
			if !ok || unwrapParens(es.X) != call {
				hasInvalidStartCall = true
				continue
			}
			flagGuard, topStmt, ok := validateCallAncestors(fn, ancestors, len(ancestors)-2)
			if !ok {
				hasInvalidStartCall = true
				continue
			}
			recvKey := canonicalDepsReceiverKey(fn, call)
			if recvKey == "" {
				hasInvalidStartCall = true
				continue
			}
			var declBlock *ast.BlockStmt
			declTargetIdx := -1
			for i := len(ancestors) - 3; i >= 0; i-- {
				blk, isBlk := ancestors[i].(*ast.BlockStmt)
				if !isBlk {
					continue
				}
				childStmt := ancestors[i+1].(ast.Stmt)
				idx := slices.Index(blk.List, childStmt)
				if idx < 0 {
					break
				}
				if blockDeclaresVarBefore(blk, idx, fileVar) {
					declBlock = blk
					declTargetIdx = idx
					break
				}
			}
			if declBlock == nil || declTargetIdx <= 0 || declBlock.List[declTargetIdx] != es {
				hasInvalidStartCall = true
				continue
			}
			openExits := map[*ast.CallExpr]bool{}
			if !verifyLogFileOpenPrefix(declBlock.List[:declTargetIdx], fileVar, flagGuard, fileImportsOS[f], fileImportsFmt[f], openExits) {
				hasInvalidStartCall = true
				continue
			}
			verifiedStarts = append(verifiedStarts, verifiedStartInfo{
				file:          f,
				fn:            fn,
				topStmt:       topStmt,
				declBlock:     declBlock,
				declTargetIdx: declTargetIdx,
				fileVar:       fileVar,
				recvKey:       recvKey,
				flagGuard:     flagGuard,
				openExits:     openExits,
			})
		}
	}

	verifiedStopCalls := map[*ast.CallExpr]verifiedStopInfo{}
	recordCandidateStop := func(f *ast.File, parentBlk *ast.BlockStmt, stmtPos, afterStopPos int, errVar string, call *ast.CallExpr, handler *ast.IfStmt) {
		if !isFailureForcingErrHandler(handler, errVar, fileImportsOS[f], fileImportsFmt[f]) {
			return
		}
		fn, ancestors := findEnclosingFuncAndAncestors(f, parentBlk.List[stmtPos])
		if fn == nil || len(ancestors) < 2 {
			return
		}
		if funcShadowsAnyIdent(fn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			return
		}
		flagGuard, topStmt, ok := validateCallAncestors(fn, ancestors, len(ancestors)-1)
		if !ok {
			return
		}
		recvKey := canonicalDepsReceiverKey(fn, call)
		if recvKey == "" {
			return
		}
		matchedStart := false
		for _, st := range verifiedStarts {
			if st.recvKey == recvKey && flagGuard == st.flagGuard {
				matchedStart = true
				break
			}
		}
		if !matchedStart {
			return
		}
		verifiedStopCalls[call] = verifiedStopInfo{
			file:         f,
			fn:           fn,
			topStmt:      topStmt,
			parentBlk:    parentBlk,
			stmtPos:      stmtPos,
			afterStopPos: afterStopPos,
			recvKey:      recvKey,
			flagGuard:    flagGuard,
			stopExit:     errHandlerTerminalCall(handler),
		}
	}

	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			blk, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			for i, s := range blk.List {
				if ifs, isIf := s.(*ast.IfStmt); isIf {
					if errVar, call := stopLogAssign(ifs.Init); call != nil {
						recordCandidateStop(f, blk, i, i+1, errVar, call, ifs)
					}
				}
				if i+1 < len(blk.List) {
					if errVar, call := stopLogAssign(s); call != nil {
						if ifs, isIf := blk.List[i+1].(*ast.IfStmt); isIf && ifs.Init == nil {
							recordCandidateStop(f, blk, i, i+2, errVar, call, ifs)
						}
					}
				}
			}
			return true
		})
	}

	var hasCheckedStopCall, hasDiscardedStopCall bool
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if isMethodCallNamed(call, "StopTestLog") {
				if _, ok := verifiedStopCalls[call]; ok {
					hasCheckedStopCall = true
				} else {
					hasDiscardedStopCall = true
				}
			}
			return true
		})
	}
	if len(verifiedStarts) != 1 || hasInvalidStartCall || len(verifiedStopCalls) != 1 || !hasCheckedStopCall || hasDiscardedStopCall {
		return fmt.Errorf("testing: missing, duplicate, unchecked, or error-dropping StartTestLog/StopTestLog calls")
	}

	st := verifiedStarts[0]
	var sp verifiedStopInfo
	for _, info := range verifiedStopCalls {
		sp = info
	}
	if st.recvKey != sp.recvKey || st.flagGuard == "" || st.flagGuard != sp.flagGuard {
		return fmt.Errorf("testing: StartTestLog and StopTestLog receiver or flag guard mismatch")
	}

	stmtMutatesOrClosesVar := func(stmt ast.Stmt, varName string, allowClose bool) bool {
		bad := false
		ast.Inspect(stmt, func(n ast.Node) bool {
			if bad || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == varName {
						bad = true
						return false
					}
				}
			case *ast.RangeStmt:
				for _, lhs := range []ast.Expr{node.Key, node.Value} {
					if lhs != nil {
						if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == varName {
							bad = true
							return false
						}
					}
				}
			case *ast.IncDecStmt:
				if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name == varName {
					bad = true
					return false
				}
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name == varName {
						bad = true
						return false
					}
				}
			case *ast.CallExpr:
				if !allowClose {
					if sel, ok := unwrapParens(node.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
						if id, ok2 := unwrapParens(sel.X).(*ast.Ident); ok2 && id.Name == varName {
							bad = true
							return false
						}
					}
				}
			}
			return true
		})
		return bad
	}

	closeExits := map[*ast.CallExpr]bool{}
	if st.fn == sp.fn && st.declBlock == sp.parentBlk {
		if sp.stmtPos <= st.declTargetIdx {
			return fmt.Errorf("testing: StopTestLog must follow StartTestLog")
		}
		for _, midStmt := range st.declBlock.List[st.declTargetIdx+1 : sp.stmtPos] {
			if stmtAlwaysTerminates(midStmt) || stmtMutatesOrClosesVar(midStmt, st.fileVar, false) {
				return fmt.Errorf("testing: unsafe statement between StartTestLog and StopTestLog")
			}
		}
		for _, afterStmt := range sp.parentBlk.List[sp.afterStopPos:] {
			if stmtMutatesOrClosesVar(afterStmt, st.fileVar, true) {
				return fmt.Errorf("testing: unsafe mutation of testlog file after StopTestLog")
			}
		}
		_, closeExit, ok := blockHasFailureForcingClose(sp.parentBlk.List[sp.afterStopPos:], st.fileVar, fileImportsOS[sp.file], fileImportsFmt[sp.file])
		if !ok {
			return fmt.Errorf("testing: missing failure-forcing Close on testlog file after StopTestLog")
		}
		if closeExit != nil {
			closeExits[closeExit] = true
		}
		for _, exitCall := range mRunExitCalls {
			if !st.openExits[exitCall] && exitCall != sp.stopExit && !closeExits[exitCall] {
				return fmt.Errorf("testing: non-positive or unverified os.Exit in Run")
			}
		}
	} else {
		if len(mRunExitCalls) > 0 {
			return fmt.Errorf("testing: non-positive or unverified os.Exit in Run")
		}
		logFileAliases := map[string]*ast.AssignStmt{}
		for _, tailStmt := range st.declBlock.List[st.declTargetIdx+1:] {
			if stmtAlwaysTerminates(tailStmt) {
				return fmt.Errorf("testing: terminating statement after StartTestLog in start block")
			}
			if as, isAs := tailStmt.(*ast.AssignStmt); isAs && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if rhsID, ok := unwrapParens(as.Rhs[0]).(*ast.Ident); ok && rhsID.Name == st.fileVar {
					if lhsID, ok2 := unwrapParens(as.Lhs[0]).(*ast.Ident); ok2 && lhsID.Name != "" && lhsID.Name != "_" && lhsID.Name != st.fileVar {
						if _, dup := logFileAliases[lhsID.Name]; dup {
							return fmt.Errorf("testing: duplicate assignment to testlog file alias %s", lhsID.Name)
						}
						logFileAliases[lhsID.Name] = as
						continue
					}
				}
			}
			if stmtMutatesOrClosesVar(tailStmt, st.fileVar, false) {
				return fmt.Errorf("testing: unsafe mutation or premature Close on testlog file")
			}
		}
		if len(logFileAliases) == 0 {
			return fmt.Errorf("testing: split StartTestLog/StopTestLog missing saved testlog file variable")
		}
		allowedAliasIdents := map[*ast.Ident]bool{}
		for alias, bindAssign := range logFileAliases {
			if ast.IsExported(alias) || zeroInitPkgVars[alias] == nil || pkgVarCounts[alias] != 1 {
				return fmt.Errorf("testing: testlog file alias %s must be a unique unexported zero-initialized package var", alias)
			}
			if funcShadowsAnyIdent(st.fn, map[string]bool{alias: true}) || funcShadowsAnyIdent(sp.fn, map[string]bool{alias: true}) {
				return fmt.Errorf("testing: testlog file alias %s shadowed in lifecycle function", alias)
			}
			if lhsID, ok := unwrapParens(bindAssign.Lhs[0]).(*ast.Ident); ok {
				allowedAliasIdents[lhsID] = true
			}
			for _, f := range files {
				for _, decl := range f.Decls {
					if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
						for _, spec := range gd.Specs {
							if vs, ok2 := spec.(*ast.ValueSpec); ok2 && len(vs.Values) == 0 {
								for _, id := range vs.Names {
									if id.Name == alias {
										allowedAliasIdents[id] = true
									}
								}
							}
						}
					}
				}
			}
			closeRecvID, closeExit, ok := blockHasFailureForcingClose(sp.parentBlk.List[sp.afterStopPos:], alias, fileImportsOS[sp.file], fileImportsFmt[sp.file])
			if !ok || closeRecvID == nil {
				return fmt.Errorf("testing: missing failure-forcing %s.Close() after StopTestLog", alias)
			}
			if closeExit != nil {
				closeExits[closeExit] = true
			}
			allowedAliasIdents[closeRecvID] = true
		}
		if !allNonSelPropIdentsInSet(files, logFileAliases, allowedAliasIdents) {
			return fmt.Errorf("testing: unsafe mutation or unchecked Close on saved testlog file")
		}
	}

	if hasInvalidContextMethod {
		return fmt.Errorf("testing: (*common).Context has unexpected shape")
	}
	if !hasValidContextMethod {
		return fmt.Errorf("testing: missing (*common).Context")
	}
	if !verifyTestingMRunTestlogWiring(files, funcFile, topFuncs, typeMethods, st, sp, flagInitFunc, flagAllowedDeclIdents, listFlagVars, emptyDefaultStringFlags, osExitSites, closeExits, fileImportsOS, fileImportsFmt, fileImportsIO, fileImportsFlag, fileImportsSync, pkgReserved) {
		return fmt.Errorf("testing: (*M).Run does not wire MainStart deps through verified StartTestLog/StopTestLog")
	}
	return nil
}

func verifyTestingMRunTestlogWiring(
	files []*ast.File,
	funcFile map[*ast.FuncDecl]*ast.File,
	topFuncs map[string]*ast.FuncDecl,
	typeMethods map[string]map[string]*ast.FuncDecl,
	st verifiedStartInfo,
	sp verifiedStopInfo,
	flagInitFunc map[string]*ast.FuncDecl,
	flagAllowedDeclIdents map[string]map[*ast.Ident]bool,
	listFlagVars map[string]bool,
	emptyDefaultStringFlags map[string]bool,
	osExitSites []testingExitSite,
	closeExits map[*ast.CallExpr]bool,
	fileImportsOS map[*ast.File]bool,
	fileImportsFmt map[*ast.File]bool,
	fileImportsIO map[*ast.File]bool,
	fileImportsFlag map[*ast.File]bool,
	fileImportsSync map[*ast.File]bool,
	pkgReserved map[string]bool,
) bool {
	mainStart := topFuncs["MainStart"]
	mMethods := typeMethods["M"]
	runFn := mMethods["Run"]
	if mainStart == nil || mainStart.Body == nil || mainStart.Type == nil || mainStart.Type.Params == nil || mainStart.Type.Results == nil || mainStart.Type.Results.NumFields() != 1 || runFn == nil || runFn.Body == nil || runFn.Type == nil {
		return false
	}
	if (runFn.Type.Params != nil && runFn.Type.Params.NumFields() != 0) || runFn.Type.Results == nil || runFn.Type.Results.NumFields() != 1 {
		return false
	}
	if funcShadowsAnyIdent(mainStart, pkgReserved) || bodyHasControlFlowOrRecoverBypass(mainStart.Body) || !blockAlwaysReturns(mainStart.Body.List) {
		return false
	}
	if funcShadowsAnyIdent(runFn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(runFn.Body) {
		return false
	}
	runRecv := recvVarName(runFn)
	if runRecv == "" {
		return false
	}

	// Verify unique type M struct declaration, collect its fields, and track all allowed M idents.
	allowedMIdents := map[*ast.Ident]bool{}
	var mStruct *ast.StructType
	var mStructFile *ast.File
	mTypeSpecs := 0
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok || ts.Name == nil || ts.Name.Name != "M" {
					continue
				}
				mTypeSpecs++
				if stType, ok := ts.Type.(*ast.StructType); ok && !ts.Assign.IsValid() {
					mStruct = stType
					mStructFile = f
					allowedMIdents[ts.Name] = true
				}
			}
		}
	}
	if mTypeSpecs != 1 || mStruct == nil || mStruct.Fields == nil {
		return false
	}
	if len(mainStart.Type.Results.List) != 1 || len(mainStart.Type.Results.List[0].Names) != 0 {
		return false
	}
	msResStar, okMSStar := unwrapParens(mainStart.Type.Results.List[0].Type).(*ast.StarExpr)
	if !okMSStar {
		return false
	}
	msResID, okMSID := unwrapParens(msResStar.X).(*ast.Ident)
	if !okMSID || msResID.Name != "M" {
		return false
	}
	allowedMIdents[msResID] = true

	mFields := map[string]ast.Expr{}
	mFieldIdents := map[string]*ast.Ident{}
	for _, fld := range mStruct.Fields.List {
		if len(fld.Names) == 0 {
			return false
		}
		for _, id := range fld.Names {
			if _, dup := mFields[id.Name]; dup {
				return false
			}
			mFields[id.Name] = fld.Type
			mFieldIdents[id.Name] = id
		}
	}

	pNames := paramNamesFlat(mainStart.Type.Params)
	if len(pNames) == 0 || pNames[0] == "" || pNames[0] == "_" {
		return false
	}
	depsParam := pNames[0]
	if bodyMutatesOrTakesAddrOfAny(mainStart.Body, map[string]bool{depsParam: true}) || bodyDeclaresAnyIdent(mainStart.Body, map[string]bool{depsParam: true}) {
		return false
	}
	var depsField string
	mainStartValid := true
	sawMainStartReturn := false
	ast.Inspect(mainStart.Body, func(n ast.Node) bool {
		if !mainStartValid || n == nil {
			return false
		}
		if _, isFL := n.(*ast.FuncLit); isFL {
			mainStartValid = false
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		sawMainStartReturn = true
		if len(ret.Results) != 1 {
			mainStartValid = false
			return false
		}
		u, ok := unwrapParens(ret.Results[0]).(*ast.UnaryExpr)
		if !ok || u.Op != token.AND {
			mainStartValid = false
			return false
		}
		lit, tName := compositeWriterLit(ret.Results[0])
		if lit == nil || tName != "M" {
			mainStartValid = false
			return false
		}
		litTypeID, okLT := unwrapParens(lit.Type).(*ast.Ident)
		if !okLT || litTypeID.Name != "M" {
			mainStartValid = false
			return false
		}
		allowedMIdents[litTypeID] = true
		var retDepsField string
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				mainStartValid = false
				return false
			}
			kID, ok1 := unwrapParens(kv.Key).(*ast.Ident)
			if !ok1 || kID.Name == "" {
				mainStartValid = false
				return false
			}
			if vID, ok2 := unwrapParens(kv.Value).(*ast.Ident); ok2 && vID.Name == depsParam {
				if retDepsField != "" {
					mainStartValid = false
					return false
				}
				retDepsField = kID.Name
			}
		}
		if retDepsField == "" || (depsField != "" && depsField != retDepsField) {
			mainStartValid = false
			return false
		}
		depsField = retDepsField
		return false
	})
	if !mainStartValid || !sawMainStartReturn || depsField == "" || ast.IsExported(depsField) || mFields[depsField] == nil {
		return false
	}

	// Verify every method on M has a pointer receiver *M whose receiver variable is only field/method-selected,
	// never mutated, address-taken, or used to invoke (*M).Run recursively, and verify no other M ident exists in testing.
	for _, mFn := range mMethods {
		if mFn == nil || mFn.Body == nil || mFn.Recv == nil || len(mFn.Recv.List) != 1 || len(mFn.Recv.List[0].Names) > 1 {
			return false
		}
		rStar, okRS := unwrapParens(mFn.Recv.List[0].Type).(*ast.StarExpr)
		if !okRS {
			return false
		}
		rID, okRID := unwrapParens(rStar.X).(*ast.Ident)
		if !okRID || rID.Name != "M" {
			return false
		}
		allowedMIdents[rID] = true
		if rv := recvVarName(mFn); rv != "" {
			if bodyMutatesOrTakesAddrOfAny(mFn.Body, map[string]bool{rv: true}) || !blockOnlySelectsOnIdent(mFn.Body, rv) {
				return false
			}
			callsSelfRun := false
			ast.Inspect(mFn.Body, func(n ast.Node) bool {
				if callsSelfRun || n == nil {
					return false
				}
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Run" {
					if xID, okX := unwrapParens(sel.X).(*ast.Ident); okX && xID.Name == rv {
						callsSelfRun = true
						return false
					}
				}
				return true
			})
			if callsSelfRun {
				return false
			}
		}
	}
	if !allNonSelPropIdentsIn(files, "M", allowedMIdents) {
		return false
	}

	// Ensure M.<depsField> is never reassigned, incremented, or address-taken anywhere in testing.
	for _, f := range files {
		if nodeMutatesOrTakesAddrOfSelector(f, "", map[string]bool{depsField: true}) {
			return false
		}
	}
	wantRecvKey := "<M>." + depsField
	if st.recvKey != wantRecvKey || sp.recvKey != wantRecvKey {
		return false
	}

	// Helper verifying that any flag pointer var used by the lifecycle appears ONLY at its
	// allowed declaration/Init sites or as the direct operand of a *<fv> dereference.
	verifyFlagPtrIdentOnlyDereferenced := func(fv string) bool {
		allowed := flagAllowedDeclIdents[fv]
		if fv == "" || len(allowed) == 0 {
			return false
		}
		ok := true
		for _, f := range files {
			var stack []ast.Node
			var walk func(n ast.Node)
			walk = func(n ast.Node) {
				if !ok || n == nil {
					return
				}
				switch node := n.(type) {
				case *ast.SelectorExpr:
					stack = append(stack, node)
					walk(node.X)
					stack = stack[:len(stack)-1]
					return
				case *ast.Ident:
					if node.Name == fv && !allowed[node] {
						starOK := false
						for idx := len(stack) - 1; idx >= 0; idx-- {
							if _, isParen := stack[idx].(*ast.ParenExpr); isParen {
								continue
							}
							if star, isStar := stack[idx].(*ast.StarExpr); isStar && unwrapParens(star.X) == node {
								starOK = true
							}
							break
						}
						if !starOK {
							ok = false
						}
					}
					return
				}
				stack = append(stack, n)
				ast.Inspect(n, func(ch ast.Node) bool {
					if ch == n {
						return true
					}
					walk(ch)
					return false
				})
				stack = stack[:len(stack)-1]
			}
			walk(f)
			if !ok {
				return false
			}
		}
		return true
	}

	// Helper verifying that any Form B flag var used by the lifecycle has its Init-style
	// function called unconditionally at top level of MainStart before return &M{...}.
	verifyFlagInitCalledInMainStart := func(fv string) bool {
		initFn := flagInitFunc[fv]
		if initFn == nil {
			return true
		}
		if funcShadowsAnyIdent(mainStart, map[string]bool{initFn.Name.Name: true}) {
			return false
		}
		for _, stmt := range mainStart.Body.List {
			if stmtAlwaysTerminates(stmt) {
				return false
			}
			switch s := stmt.(type) {
			case *ast.EmptyStmt, *ast.DeclStmt, *ast.AssignStmt:
			case *ast.ExprStmt:
				if call, ok := unwrapParens(s.X).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 0 {
					if id, ok2 := unwrapParens(call.Fun).(*ast.Ident); ok2 && id.Name == initFn.Name.Name {
						return true
					}
				}
			default:
				return false
			}
		}
		return false
	}
	if !verifyFlagInitCalledInMainStart(st.flagGuard) || !verifyFlagPtrIdentOnlyDereferenced(st.flagGuard) {
		return false
	}

	// Check optional named-result exitCode defer at runFn.Body.List[0]:
	// defer func() { <code> = m.<exitCodeField> }()
	var exitCodeField string
	var exitCodeDefer *ast.DeferStmt
	if len(runFn.Type.Results.List) == 1 && len(runFn.Type.Results.List[0].Names) == 1 && len(runFn.Body.List) > 0 {
		codeName := runFn.Type.Results.List[0].Names[0].Name
		if ds, ok := runFn.Body.List[0].(*ast.DeferStmt); ok && codeName != "" && codeName != "_" {
			if fl, ok2 := unwrapParens(ds.Call.Fun).(*ast.FuncLit); ok2 && !ds.Call.Ellipsis.IsValid() && len(ds.Call.Args) == 0 && (fl.Type.Params == nil || fl.Type.Params.NumFields() == 0) && (fl.Type.Results == nil || fl.Type.Results.NumFields() == 0) && fl.Body != nil && len(fl.Body.List) == 1 {
				if as, ok3 := fl.Body.List[0].(*ast.AssignStmt); ok3 && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
					_, okL := isIdentNamed(as.Lhs[0], codeName)
					if sel, okR := unwrapParens(as.Rhs[0]).(*ast.SelectorExpr); okL && okR {
						if rID, okRecv := unwrapParens(sel.X).(*ast.Ident); okRecv && rID.Name == runRecv && sel.Sel.Name != "" && sel.Sel.Name != depsField && !ast.IsExported(sel.Sel.Name) {
							if fType, okFld := unwrapParens(mFields[sel.Sel.Name]).(*ast.Ident); okFld && fType.Name == "int" {
								exitCodeField = sel.Sel.Name
								exitCodeDefer = ds
							}
						}
					}
				}
			}
		}
	}
	if exitCodeField != "" {
		// Ensure exitCodeField is never written or address-taken outside runFn, and never address-taken inside runFn.
		badExitCode := false
		for _, f := range files {
			for _, decl := range f.Decls {
				ast.Inspect(decl, func(n ast.Node) bool {
					if badExitCode || n == nil {
						return false
					}
					switch node := n.(type) {
					case *ast.UnaryExpr:
						if node.Op == token.AND {
							if sel, ok := unwrapParens(node.X).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
								badExitCode = true
								return false
							}
						}
					case *ast.FuncLit:
						if decl == runFn {
							ast.Inspect(node.Body, func(fnN ast.Node) bool {
								if badExitCode || fnN == nil {
									return false
								}
								switch inner := fnN.(type) {
								case *ast.AssignStmt:
									for _, lhs := range inner.Lhs {
										if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
											badExitCode = true
											return false
										}
									}
								case *ast.RangeStmt:
									for _, lhs := range []ast.Expr{inner.Key, inner.Value} {
										if lhs != nil {
											if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
												badExitCode = true
												return false
											}
										}
									}
								}
								return true
							})
						}
					case *ast.AssignStmt:
						if decl != runFn {
							for _, lhs := range node.Lhs {
								if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
									badExitCode = true
									return false
								}
							}
						}
					case *ast.RangeStmt:
						for _, lhs := range []ast.Expr{node.Key, node.Value} {
							if lhs != nil {
								if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
									badExitCode = true
									return false
								}
							}
						}
					case *ast.IncDecStmt:
						if sel, ok := unwrapParens(node.X).(*ast.SelectorExpr); ok && sel.Sel.Name == exitCodeField {
							badExitCode = true
							return false
						}
					case *ast.KeyValueExpr:
						if kID, ok := unwrapParens(node.Key).(*ast.Ident); ok && kID.Name == exitCodeField {
							badExitCode = true
							return false
						}
					}
					return true
				})
			}
		}
		if badExitCode {
			return false
		}
	}

	// Build function/method graph over testing declarations:
	// - runnerDecl: seeded by .F / .Fn callback selectors and canonical runner names, closed backwards over callers.
	// - forward closures for os.Exit reachability auditing across per-case runners, core test/bench/fuzz runners,
	//   example runners, and active testlog lifecycle helpers.
	allDecls := []*ast.FuncDecl{}
	declByName := map[string][]*ast.FuncDecl{}
	for _, f := range files {
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				allDecls = append(allDecls, fn)
				declByName[fn.Name.Name] = append(declByName[fn.Name.Name], fn)
			}
		}
	}
	collectDirectCallees := func(nodes []ast.Node, excludeSels map[*ast.SelectorExpr]bool) []*ast.FuncDecl {
		seen := map[*ast.FuncDecl]bool{}
		var out []*ast.FuncDecl
		var walk func(n ast.Node)
		walk = func(n ast.Node) {
			if n == nil {
				return
			}
			switch node := n.(type) {
			case *ast.ValueSpec:
				if node.Type != nil {
					walk(node.Type)
				}
				for _, v := range node.Values {
					walk(v)
				}
			case *ast.KeyValueExpr:
				walk(node.Value)
			case *ast.SelectorExpr:
				if !excludeSels[node] {
					for _, target := range declByName[node.Sel.Name] {
						if target.Recv != nil && target != runFn && !seen[target] {
							seen[target] = true
							out = append(out, target)
						}
					}
				}
				walk(node.X)
			case *ast.Ident:
				for _, target := range declByName[node.Name] {
					if target.Recv == nil && target != mainStart && !seen[target] {
						seen[target] = true
						out = append(out, target)
					}
				}
			default:
				ast.Inspect(node, func(ch ast.Node) bool {
					if ch == node {
						return true
					}
					walk(ch)
					return false
				})
			}
		}
		for _, root := range nodes {
			walk(root)
		}
		return out
	}
	forwardClosure := func(seeds map[*ast.FuncDecl]bool, excludeSels map[*ast.SelectorExpr]bool) map[*ast.FuncDecl]bool {
		reached := map[*ast.FuncDecl]bool{}
		var queue []*ast.FuncDecl
		for fn := range seeds {
			if fn != nil && fn.Body != nil && !reached[fn] {
				reached[fn] = true
				queue = append(queue, fn)
			}
		}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, callee := range collectDirectCallees([]ast.Node{cur.Body}, excludeSels) {
				if !reached[callee] {
					reached[callee] = true
					queue = append(queue, callee)
				}
			}
		}
		return reached
	}

	seedRunnerNames := map[string]bool{
		"tRunner": true, "fRunner": true, "run1": true, "runN": true,
		"runTests": true, "runBenchmarks": true, "runExamples": true,
		"runFuzzTests": true, "runFuzzing": true,
		"RunTests": true, "RunBenchmarks": true, "RunExamples": true, "Benchmark": true,
	}
	perCaseExecSeedNames := map[string]bool{
		"tRunner": true, "fRunner": true, "run1": true, "runN": true,
		"Loop": true, "loopSlow": true, "ResetTimer": true, "StartTimer": true, "StopTimer": true,
	}
	coreTestBenchFuzzSeedNames := map[string]bool{
		"tRunner": true, "fRunner": true, "run1": true, "runN": true,
		"Loop": true, "loopSlow": true, "ResetTimer": true, "StartTimer": true, "StopTimer": true,
		"runTests": true, "runBenchmarks": true, "runFuzzTests": true, "runFuzzing": true,
		"RunTests": true, "RunBenchmarks": true, "Benchmark": true,
	}
	paramsMentionIdent := func(fl *ast.FieldList, target string) bool {
		if fl == nil {
			return false
		}
		hit := false
		for _, fld := range fl.List {
			ast.Inspect(fld.Type, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && id.Name == target {
					hit = true
					return false
				}
				return true
			})
		}
		return hit
	}

	runnerDecl := map[*ast.FuncDecl]bool{}
	perCaseExecSeeds := map[*ast.FuncDecl]bool{}
	coreTestBenchFuzzSeeds := map[*ast.FuncDecl]bool{}
	declCallees := map[*ast.FuncDecl][]*ast.FuncDecl{}
	for _, fn := range allDecls {
		if fn != runFn {
			if seedRunnerNames[fn.Name.Name] {
				runnerDecl[fn] = true
			}
			if perCaseExecSeedNames[fn.Name.Name] {
				perCaseExecSeeds[fn] = true
			}
			if coreTestBenchFuzzSeedNames[fn.Name.Name] {
				coreTestBenchFuzzSeeds[fn] = true
			}
		}
		hasFFnSel := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "F" || sel.Sel.Name == "Fn") {
				hasFFnSel = true
				return false
			}
			return true
		})
		if hasFFnSel && fn != runFn {
			runnerDecl[fn] = true
			if !paramsMentionIdent(fn.Type.Params, "InternalExample") {
				coreTestBenchFuzzSeeds[fn] = true
			}
		}
		declCallees[fn] = collectDirectCallees([]ast.Node{fn.Body}, nil)
	}
	for changed := true; changed; {
		changed = false
		for _, fn := range allDecls {
			if runnerDecl[fn] || fn == runFn {
				continue
			}
			for _, target := range declCallees[fn] {
				if runnerDecl[target] {
					runnerDecl[fn] = true
					changed = true
					break
				}
			}
		}
	}
	stmtCallsRunner := func(stmt ast.Stmt) bool {
		for _, target := range collectDirectCallees([]ast.Node{stmt}, nil) {
			if seedRunnerNames[target.Name.Name] || runnerDecl[target] {
				return true
			}
		}
		return false
	}

	exitSitesByFunc := map[*ast.FuncDecl][]testingExitSite{}
	for _, site := range osExitSites {
		if site.encFn == nil || site.encFn.Name.Name == "init" {
			return false
		}
		exitSitesByFunc[site.encFn] = append(exitSitesByFunc[site.encFn], site)
	}
	perCaseExecReachable := forwardClosure(perCaseExecSeeds, nil)
	for fn := range perCaseExecReachable {
		if len(exitSitesByFunc[fn]) > 0 {
			return false
		}
	}
	coreTestBenchFuzzReachable := forwardClosure(coreTestBenchFuzzSeeds, nil)
	allRunnerForwardReachable := forwardClosure(runnerDecl, nil)

	isBenignRunnerReachableExitSite := func(site testingExitSite) bool {
		idx := len(site.ancestors) - 1
		if idx < 4 || site.ancestors[idx] != site.call {
			return false
		}
		idx--
		for idx >= 0 {
			if _, isParen := site.ancestors[idx].(*ast.ParenExpr); !isParen {
				break
			}
			idx--
		}
		if idx < 3 {
			return false
		}
		es, okES := site.ancestors[idx].(*ast.ExprStmt)
		ifBlk, okIB := site.ancestors[idx-1].(*ast.BlockStmt)
		ifs, okIF := site.ancestors[idx-2].(*ast.IfStmt)
		parentBlk, okPB := site.ancestors[idx-3].(*ast.BlockStmt)
		if !okES || !okIB || !okIF || !okPB || unwrapParens(es.X) != site.call || ifs.Body != ifBlk || ifs.Else != nil || len(ifBlk.List) == 0 || ifBlk.List[len(ifBlk.List)-1] != es {
			return false
		}
		errVar := condChecksNonZeroErr(ifs.Cond)
		if errVar == "" {
			return false
		}
		hasOS := fileImportsOS[site.file]
		hasFmt := fileImportsFmt[site.file]
		for _, pre := range ifBlk.List[:len(ifBlk.List)-1] {
			if isBenignStderrDiagStmt(pre, hasOS, hasFmt) {
				continue
			}
			// Allow `if os.IsExist(errVar) { continue }` in temp-file open loop.
			if innerIf, okIn := pre.(*ast.IfStmt); okIn && innerIf.Init == nil && innerIf.Else == nil && hasOS && len(innerIf.Body.List) == 1 {
				if br, okBr := innerIf.Body.List[0].(*ast.BranchStmt); okBr && br.Tok == token.CONTINUE && br.Label == nil {
					if ieCall, okIEC := unwrapParens(innerIf.Cond).(*ast.CallExpr); okIEC && !ieCall.Ellipsis.IsValid() && len(ieCall.Args) == 1 {
						_, okSel := isSelectorBaseField(ieCall.Fun, "os", "IsExist")
						_, okArg := isIdentNamed(ieCall.Args[0], errVar)
						if okSel && okArg {
							continue
						}
					}
				}
			}
			return false
		}
		// Form 1: Pre-case filter/skip regex validation in unexported matcher constructor (`newMatcher`):
		// `if err := <ident>.verify(<arg0>, <p0>); err != nil { ... os.Exit(1) }`
		if ifs.Init != nil {
			if runnerDecl[site.encFn] || site.encFn.Recv != nil || ast.IsExported(site.encFn.Name.Name) || site.encFn.Type.Params == nil || site.encFn.Type.Results == nil || site.encFn.Type.Results.NumFields() != 1 {
				return false
			}
			fnParams := paramNamesFlat(site.encFn.Type.Params)
			if len(fnParams) != 4 || fnParams[0] == "" || fnParams[0] == "_" {
				return false
			}
			if _, isFT := unwrapParens(site.encFn.Type.Params.List[0].Type).(*ast.FuncType); !isFT {
				return false
			}
			initAs, okA := ifs.Init.(*ast.AssignStmt)
			if !okA || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 1 || len(initAs.Rhs) != 1 {
				return false
			}
			if _, okLHS := isIdentNamed(initAs.Lhs[0], errVar); !okLHS {
				return false
			}
			vCall, okVC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
			if !okVC || vCall.Ellipsis.IsValid() || len(vCall.Args) != 2 || exprHasCallOrFuncLit(vCall.Args[0]) {
				return false
			}
			if _, okP0 := isIdentNamed(vCall.Args[1], fnParams[0]); !okP0 {
				return false
			}
			vSel, okVS := unwrapParens(vCall.Fun).(*ast.SelectorExpr)
			if !okVS || vSel.Sel.Name != "verify" {
				return false
			}
			if _, okBase := unwrapParens(vSel.X).(*ast.Ident); !okBase {
				return false
			}
			verifyDecls := declByName["verify"]
			if len(verifyDecls) == 0 {
				return false
			}
			for _, vd := range verifyDecls {
				if runnerDecl[vd] || len(exitSitesByFunc[vd]) > 0 {
					return false
				}
			}
			return true
		}
		// Form 2: Example stdout-capture OS failure (`os.Pipe`, `os.OpenFile`, `io.Copy`, `<file>.Seek`),
		// prohibited anywhere reachable from core Test/Benchmark/Fuzz runners.
		if coreTestBenchFuzzReachable[site.encFn] {
			return false
		}
		ifIdx := slices.Index(parentBlk.List, ast.Stmt(ifs))
		if ifIdx <= 0 {
			return false
		}
		for pos := ifIdx - 1; pos >= 0; pos-- {
			stPrev := parentBlk.List[pos]
			if as, okA := stPrev.(*ast.AssignStmt); okA && (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) >= 2 && len(as.Rhs) == 1 {
				if _, okLast := isIdentNamed(as.Lhs[len(as.Lhs)-1], errVar); okLast {
					if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: parentBlk.List[pos+1 : ifIdx]}, map[string]bool{errVar: true}) {
						return false
					}
					opCall, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
					if !okC || opCall.Ellipsis.IsValid() {
						return false
					}
					if _, okPipe := isSelectorBaseField(opCall.Fun, "os", "Pipe"); okPipe && hasOS && len(opCall.Args) == 0 {
						return true
					}
					if _, okOF := isSelectorBaseField(opCall.Fun, "os", "OpenFile"); okOF && hasOS && len(opCall.Args) == 3 {
						return true
					}
					if _, okCopy := isSelectorBaseField(opCall.Fun, "io", "Copy"); okCopy && fileImportsIO[site.file] && len(opCall.Args) == 2 {
						return true
					}
					if sSel, okSeek := unwrapParens(opCall.Fun).(*ast.SelectorExpr); okSeek && sSel.Sel.Name == "Seek" && len(opCall.Args) == 2 && !exprHasCallOrFuncLit(opCall.Args[0]) && !exprHasCallOrFuncLit(opCall.Args[1]) {
						if _, okRecv := unwrapParens(sSel.X).(*ast.Ident); okRecv {
							return true
						}
					}
					return false
				}
			}
			if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: []ast.Stmt{stPrev}}, map[string]bool{errVar: true}) {
				return false
			}
		}
		return false
	}

	for fn := range allRunnerForwardReachable {
		for _, site := range exitSitesByFunc[fn] {
			if !isBenignRunnerReachableExitSite(site) {
				return false
			}
		}
	}

	stmtsHaveNoNonRunnerHelperExit := func(stmts []ast.Stmt, excludeSels map[*ast.SelectorExpr]bool) bool {
		seeds := map[*ast.FuncDecl]bool{}
		nodes := make([]ast.Node, 0, len(stmts))
		for _, s := range stmts {
			if s != nil {
				nodes = append(nodes, s)
			}
		}
		for _, callee := range collectDirectCallees(nodes, excludeSels) {
			if !runnerDecl[callee] {
				seeds[callee] = true
			}
		}
		for fn := range forwardClosure(seeds, excludeSels) {
			if !runnerDecl[fn] && len(exitSitesByFunc[fn]) > 0 {
				return false
			}
		}
		return true
	}

	bodyHasGoexit := func(body *ast.BlockStmt) bool {
		hit := false
		ast.Inspect(body, func(n ast.Node) bool {
			if hit || n == nil {
				return false
			}
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "Goexit" {
				hit = true
				return false
			}
			return true
		})
		return hit
	}
	if bodyHasGoexit(runFn.Body) {
		return false
	}

	// Find flag.Parse() or if !flag.Parsed() { flag.Parse() } at top level of (*M).Run.
	runFile := funcFile[runFn]
	if !fileImportsFlag[runFile] {
		return false
	}
	isFlagCall0 := func(expr ast.Expr, fnName string) bool {
		call, ok := unwrapParens(expr).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
			return false
		}
		sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != fnName {
			return false
		}
		pkgID, ok := unwrapParens(sel.X).(*ast.Ident)
		return ok && pkgID.Name == "flag"
	}
	parseIdx := -1
	for i, stmt := range runFn.Body.List {
		if es, ok := stmt.(*ast.ExprStmt); ok && isFlagCall0(es.X, "Parse") {
			parseIdx = i
			break
		}
		if ifs, ok := stmt.(*ast.IfStmt); ok && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
			if u, okU := unwrapParens(ifs.Cond).(*ast.UnaryExpr); okU && u.Op == token.NOT && isFlagCall0(u.X, "Parsed") {
				if es, okE := ifs.Body.List[0].(*ast.ExprStmt); okE && isFlagCall0(es.X, "Parse") {
					parseIdx = i
					break
				}
			}
		}
	}
	if parseIdx < 0 {
		return false
	}

	// Validate pre-StartTestLog statements in (*M).Run:
	// - No runner calls and no unconditional top-level termination.
	// - Every ReturnStmt either returns a positive exit code (directly when exitCodeField == "",
	//   or preceded immediately by m.<exitCodeField> = <posIntLit> when exitCodeField != "")
	//   OR sits inside a post-Parse `if *<listFlag> != ""` block for a verified test.list flag.
	verifyRunPreStartSlice := func(limit int) bool {
		for idx, top := range runFn.Body.List[:limit] {
			if stmtAlwaysTerminates(top) || stmtCallsRunner(top) {
				return false
			}
			allowedZeroReturn := false
			if idx > parseIdx {
				if ifs, ok := top.(*ast.IfStmt); ok && ifs.Init == nil && ifs.Else == nil {
					if lf, ok2 := derefFlagNonEmptyCondIdent(ifs.Cond); ok2 && listFlagVars[lf] && !funcShadowsAnyIdent(runFn, map[string]bool{lf: true}) && verifyFlagInitCalledInMainStart(lf) && verifyFlagPtrIdentOnlyDereferenced(lf) {
						allowedZeroReturn = true
					}
				}
			}
			var checkPreBlock func(blk *ast.BlockStmt) bool
			checkPreBlock = func(blk *ast.BlockStmt) bool {
				if blk == nil {
					return true
				}
				for j, s := range blk.List {
					switch node := s.(type) {
					case *ast.ReturnStmt:
						if allowedZeroReturn {
							if exitCodeField != "" && len(node.Results) != 0 {
								return false
							}
							continue
						}
						if exitCodeField == "" {
							if len(node.Results) != 1 || exprHasCallOrFuncLit(node.Results[0]) || !isPositiveIntLit(node.Results[0]) {
								return false
							}
						} else {
							if len(node.Results) != 0 || j == 0 {
								return false
							}
							prevAs, ok := blk.List[j-1].(*ast.AssignStmt)
							if !ok || prevAs.Tok != token.ASSIGN || len(prevAs.Lhs) != 1 || len(prevAs.Rhs) != 1 || exprHasCallOrFuncLit(prevAs.Rhs[0]) || !isPositiveIntLit(prevAs.Rhs[0]) {
								return false
							}
							sel, ok := unwrapParens(prevAs.Lhs[0]).(*ast.SelectorExpr)
							if !ok || sel.Sel.Name != exitCodeField {
								return false
							}
							if rID, ok2 := unwrapParens(sel.X).(*ast.Ident); !ok2 || rID.Name != runRecv {
								return false
							}
						}
					case *ast.IfStmt:
						if !checkPreBlock(node.Body) {
							return false
						}
						switch el := node.Else.(type) {
						case nil:
						case *ast.BlockStmt:
							if !checkPreBlock(el) {
								return false
							}
						case *ast.IfStmt:
							if !checkPreBlock(&ast.BlockStmt{List: []ast.Stmt{el}}) {
								return false
							}
						default:
							return false
						}
					case *ast.BlockStmt:
						if !checkPreBlock(node) {
							return false
						}
					case *ast.GoStmt:
						return false
					case *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt:
						hasRetOrGo := false
						ast.Inspect(node, func(n ast.Node) bool {
							if _, isFL := n.(*ast.FuncLit); isFL {
								return false
							}
							switch n.(type) {
							case *ast.ReturnStmt, *ast.GoStmt:
								hasRetOrGo = true
								return false
							}
							return true
						})
						if hasRetOrGo {
							return false
						}
					}
				}
				return true
			}
			if topIf, ok := top.(*ast.IfStmt); ok {
				if !checkPreBlock(topIf.Body) {
					return false
				}
				if topIf.Else != nil {
					if !checkPreBlock(&ast.BlockStmt{List: []ast.Stmt{topIf.Else}}) {
						return false
					}
				}
			} else {
				hasRetOrGo := false
				ast.Inspect(top, func(n ast.Node) bool {
					if _, isFL := n.(*ast.FuncLit); isFL {
						return false
					}
					switch n.(type) {
					case *ast.ReturnStmt, *ast.GoStmt:
						hasRetOrGo = true
						return false
					}
					return true
				})
				if hasRetOrGo {
					return false
				}
			}
		}
		return true
	}

	verifyOnlyAllowedDefersInRun := func(allowedAfterDefer *ast.DeferStmt) bool {
		badDeferOrGo := false
		ast.Inspect(runFn.Body, func(n ast.Node) bool {
			if badDeferOrGo || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.DeferStmt:
				if node != exitCodeDefer && node != allowedAfterDefer {
					badDeferOrGo = true
					return false
				}
			case *ast.GoStmt:
				badDeferOrGo = true
				return false
			}
			return true
		})
		return !badDeferOrGo
	}

	// Mode 1: Inline StartTestLog and StopTestLog directly in (*M).Run.
	if st.fn == runFn && sp.fn == runFn {
		if !verifyOnlyAllowedDefersInRun(nil) {
			return false
		}
		startTopIdx := slices.Index(runFn.Body.List, st.topStmt)
		stopTopIdx := slices.Index(runFn.Body.List, sp.topStmt)
		if startTopIdx < 0 || stopTopIdx < startTopIdx || parseIdx >= startTopIdx {
			return false
		}
		if !verifyRunPreStartSlice(startTopIdx) {
			return false
		}
		checkNoRetOrGo := func(stmts []ast.Stmt) bool {
			for _, mid := range stmts {
				if stmtAlwaysTerminates(mid) {
					return false
				}
				hasRetOrGo := false
				ast.Inspect(mid, func(n ast.Node) bool {
					switch n.(type) {
					case *ast.ReturnStmt, *ast.GoStmt:
						hasRetOrGo = true
						return false
					}
					return true
				})
				if hasRetOrGo {
					return false
				}
			}
			return true
		}
		if st.topStmt == sp.topStmt {
			if st.declBlock != sp.parentBlk {
				return false
			}
			for _, pre := range st.declBlock.List[:st.declTargetIdx] {
				if stmtCallsRunner(pre) {
					return false
				}
			}
			if !checkNoRetOrGo(st.declBlock.List[st.declTargetIdx+1 : sp.stmtPos]) {
				return false
			}
			if !stmtsHaveNoNonRunnerHelperExit(st.declBlock.List[st.declTargetIdx+1:], nil) {
				return false
			}
			for _, post := range sp.parentBlk.List[sp.stmtPos:] {
				if stmtCallsRunner(post) {
					return false
				}
			}
			if !slices.ContainsFunc(sp.parentBlk.List[sp.afterStopPos:], stmtAlwaysTerminates) {
				for _, post := range runFn.Body.List[stopTopIdx+1:] {
					if stmtCallsRunner(post) {
						return false
					}
				}
			}
		} else {
			if stmtCallsRunner(st.topStmt) || stmtCallsRunner(sp.topStmt) {
				return false
			}
			if !checkNoRetOrGo(runFn.Body.List[startTopIdx+1 : stopTopIdx]) {
				return false
			}
			if !stmtsHaveNoNonRunnerHelperExit(st.declBlock.List[st.declTargetIdx+1:], nil) || !stmtsHaveNoNonRunnerHelperExit(runFn.Body.List[startTopIdx+1:stopTopIdx+1], nil) {
				return false
			}
			for _, post := range runFn.Body.List[stopTopIdx+1:] {
				if stmtCallsRunner(post) {
					return false
				}
			}
		}
		return true
	}

	// Mode 2: Split lifecycle via unexported *M methods: m.<before>() + defer m.<after>() in (*M).Run.
	if st.fn == runFn || sp.fn == runFn || st.fn == sp.fn {
		return false
	}
	beforeName := st.fn.Name.Name
	stopMethodName := sp.fn.Name.Name
	if ast.IsExported(beforeName) || ast.IsExported(stopMethodName) || mMethods[beforeName] != st.fn || mMethods[stopMethodName] != sp.fn {
		return false
	}
	isZeroArgVoidMMethod := func(fn *ast.FuncDecl) bool {
		return fn != nil && fn.Body != nil && recvVarName(fn) != "" &&
			(fn.Type.Params == nil || fn.Type.Params.NumFields() == 0) &&
			(fn.Type.Results == nil || fn.Type.Results.NumFields() == 0)
	}
	if !isZeroArgVoidMMethod(st.fn) || !isZeroArgVoidMMethod(sp.fn) {
		return false
	}

	beforeIdx := -1
	var afterName string
	var afterDeferStmt *ast.DeferStmt
	var beforeCallSel, afterDeferSel *ast.SelectorExpr
	for i := 0; i+1 < len(runFn.Body.List); i++ {
		es, ok1 := runFn.Body.List[i].(*ast.ExprStmt)
		ds, ok2 := runFn.Body.List[i+1].(*ast.DeferStmt)
		if !ok1 || !ok2 {
			continue
		}
		bCall, okB := unwrapParens(es.X).(*ast.CallExpr)
		if !okB || bCall.Ellipsis.IsValid() || len(bCall.Args) != 0 || ds.Call.Ellipsis.IsValid() || len(ds.Call.Args) != 0 {
			continue
		}
		bSel, okBS := unwrapParens(bCall.Fun).(*ast.SelectorExpr)
		aSel, okAS := unwrapParens(ds.Call.Fun).(*ast.SelectorExpr)
		if !okBS || !okAS || bSel.Sel.Name != beforeName {
			continue
		}
		bRecv, okBR := unwrapParens(bSel.X).(*ast.Ident)
		aRecv, okAR := unwrapParens(aSel.X).(*ast.Ident)
		if okBR && okAR && bRecv.Name == runRecv && aRecv.Name == runRecv {
			beforeIdx = i
			afterName = aSel.Sel.Name
			afterDeferStmt = ds
			beforeCallSel = bSel
			afterDeferSel = aSel
			break
		}
	}
	if beforeIdx < 0 || parseIdx >= beforeIdx || ast.IsExported(afterName) {
		return false
	}
	afterFn := mMethods[afterName]
	if !isZeroArgVoidMMethod(afterFn) || afterFn == runFn || afterFn == st.fn {
		return false
	}
	if funcShadowsAnyIdent(afterFn, pkgReserved) || bodyHasControlFlowOrRecoverBypass(afterFn.Body) {
		return false
	}
	if bodyHasGoexit(st.fn.Body) || bodyHasGoexit(afterFn.Body) || bodyHasGoexit(sp.fn.Body) {
		return false
	}
	if !verifyOnlyAllowedDefersInRun(afterDeferStmt) || !verifyRunPreStartSlice(beforeIdx) {
		return false
	}

	// Verify st.fn (before): no runners, no Defer/Go, no top-level termination before StartTestLog,
	// pre-StartTestLog returns only inside `if ... err != nil`, and no returns at/after StartTestLog.
	startInBeforeIdx := slices.Index(st.fn.Body.List, st.topStmt)
	if startInBeforeIdx < 0 || stmtCallsRunner(&ast.BlockStmt{List: st.fn.Body.List}) {
		return false
	}
	hasDeferOrGo := func(body *ast.BlockStmt) bool {
		hit := false
		ast.Inspect(body, func(n ast.Node) bool {
			if hit || n == nil {
				return false
			}
			switch n.(type) {
			case *ast.DeferStmt, *ast.GoStmt:
				hit = true
				return false
			}
			return true
		})
		return hit
	}
	if hasDeferOrGo(st.fn.Body) || hasDeferOrGo(afterFn.Body) || hasDeferOrGo(sp.fn.Body) {
		return false
	}
	for _, pre := range st.fn.Body.List[:startInBeforeIdx] {
		if stmtAlwaysTerminates(pre) {
			return false
		}
		var outerOptFlagOK bool
		if topIf, ok := pre.(*ast.IfStmt); ok && topIf.Init == nil && topIf.Else == nil {
			if fg, ok2 := derefFlagNonEmptyCondIdent(topIf.Cond); ok2 && emptyDefaultStringFlags[fg] && !funcShadowsAnyIdent(st.fn, map[string]bool{fg: true}) && verifyFlagInitCalledInMainStart(fg) && verifyFlagPtrIdentOnlyDereferenced(fg) {
				outerOptFlagOK = true
			}
		}
		var checkBeforeStmt func(s ast.Stmt, underErrIf bool) bool
		checkBeforeStmt = func(s ast.Stmt, underErrIf bool) bool {
			switch node := s.(type) {
			case nil, *ast.EmptyStmt, *ast.DeclStmt, *ast.AssignStmt, *ast.ExprStmt, *ast.IncDecStmt:
				hasLit := false
				ast.Inspect(s, func(n ast.Node) bool {
					if _, ok := n.(*ast.FuncLit); ok {
						hasLit = true
						return false
					}
					return true
				})
				return !hasLit
			case *ast.ReturnStmt:
				return outerOptFlagOK && underErrIf && len(node.Results) == 0
			case *ast.BlockStmt:
				for _, child := range node.List {
					if !checkBeforeStmt(child, underErrIf) {
						return false
					}
				}
				return true
			case *ast.IfStmt:
				isErrIf := underErrIf || (node.Else == nil && condChecksNonZeroErr(node.Cond) != "")
				if !checkBeforeStmt(node.Body, isErrIf) {
					return false
				}
				if node.Else != nil && !checkBeforeStmt(node.Else, false) {
					return false
				}
				return true
			default:
				return false
			}
		}
		if !checkBeforeStmt(pre, false) {
			return false
		}
	}
	for _, post := range st.fn.Body.List[startInBeforeIdx:] {
		hasRet := false
		ast.Inspect(post, func(n ast.Node) bool {
			if _, ok := n.(*ast.ReturnStmt); ok {
				hasRet = true
				return false
			}
			return true
		})
		if hasRet {
			return false
		}
	}

	// Verify afterFn -> sp.fn wiring and sp.fn head position.
	if stmtCallsRunner(&ast.BlockStmt{List: afterFn.Body.List}) || stmtCallsRunner(&ast.BlockStmt{List: sp.fn.Body.List}) {
		return false
	}
	if len(sp.fn.Body.List) == 0 || sp.fn.Body.List[0] != sp.topStmt || sp.stmtPos != 0 {
		return false
	}
	var spCallSel *ast.SelectorExpr
	var onceField string
	var onceSelIdent *ast.Ident
	if afterFn != sp.fn {
		if len(afterFn.Body.List) == 0 {
			return false
		}
		afterRecv := recvVarName(afterFn)
		s0, ok := afterFn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return false
		}
		c0, ok := unwrapParens(s0.X).(*ast.CallExpr)
		if !ok || c0.Ellipsis.IsValid() {
			return false
		}
		sel0, ok := unwrapParens(c0.Fun).(*ast.SelectorExpr)
		if !ok {
			return false
		}
		if rID, okR := unwrapParens(sel0.X).(*ast.Ident); okR && rID.Name == afterRecv && sel0.Sel.Name == stopMethodName && len(c0.Args) == 0 {
			spCallSel = sel0
		} else if sel0.Sel.Name == "Do" && len(c0.Args) == 1 {
			fSel, okFS := unwrapParens(sel0.X).(*ast.SelectorExpr)
			if !okFS {
				return false
			}
			rID, okR := unwrapParens(fSel.X).(*ast.Ident)
			fl, okFL := unwrapParens(c0.Args[0]).(*ast.FuncLit)
			if !okR || !okFL || rID.Name != afterRecv || ast.IsExported(fSel.Sel.Name) || (fl.Type.Params != nil && fl.Type.Params.NumFields() != 0) || (fl.Type.Results != nil && fl.Type.Results.NumFields() != 0) || fl.Body == nil || len(fl.Body.List) != 1 {
				return false
			}
			innerES, okIE := fl.Body.List[0].(*ast.ExprStmt)
			if !okIE {
				return false
			}
			innerCall, okIC := unwrapParens(innerES.X).(*ast.CallExpr)
			if !okIC || innerCall.Ellipsis.IsValid() || len(innerCall.Args) != 0 {
				return false
			}
			innerSel, okIS := unwrapParens(innerCall.Fun).(*ast.SelectorExpr)
			if !okIS || innerSel.Sel.Name != stopMethodName {
				return false
			}
			if innerRecv, okIR := unwrapParens(innerSel.X).(*ast.Ident); !okIR || innerRecv.Name != afterRecv {
				return false
			}
			// Verify onceField has type sync.Once on M.
			onceTypeSel, okOT := unwrapParens(mFields[fSel.Sel.Name]).(*ast.SelectorExpr)
			if !okOT || onceTypeSel.Sel.Name != "Once" || !fileImportsSync[mStructFile] {
				return false
			}
			if syncID, okSID := unwrapParens(onceTypeSel.X).(*ast.Ident); !okSID || syncID.Name != "sync" {
				return false
			}
			onceField = fSel.Sel.Name
			onceSelIdent = fSel.Sel
			spCallSel = innerSel
		} else {
			return false
		}
	}

	// Verify call-site and field-reference isolation across the entire testing package for:
	// - onceField (only M struct field decl and afterFn's single m.<onceField>.Do)
	// - beforeName (only m.<before>() at runFn.Body.List[beforeIdx])
	// - stopMethodName when afterFn != sp.fn (only m.<sp>() at stmt 0 of afterFn)
	// - afterName (only defer m.<after>() in runFn, plus optional panic-terminating alarm FuncLit
	//   inside an unexported *M method called exclusively in runFn.Body.List[beforeIdx+2:])
	var extraAfterHelperNames = map[string]bool{}
	alarmAfterSels := map[*ast.SelectorExpr]bool{}
	isolatedOK := true
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if !isolatedOK || n == nil {
				return false
			}
			if id, isID := n.(*ast.Ident); isID && onceField != "" && id.Name == onceField {
				if id != mFieldIdents[onceField] && id != onceSelIdent {
					isolatedOK = false
					return false
				}
			}
			sel, isSel := n.(*ast.SelectorExpr)
			if !isSel {
				return true
			}
			switch sel.Sel.Name {
			case beforeName:
				if sel != beforeCallSel {
					isolatedOK = false
					return false
				}
			case stopMethodName:
				if afterFn != sp.fn && sel != spCallSel {
					isolatedOK = false
					return false
				}
			case afterName:
				if sel == afterDeferSel {
					return true
				}
				// Secondary call allowed only as stmt 0 of a panic-terminating FuncLit inside an unexported *M method.
				encFn, anc := findEnclosingFuncAndAncestors(f, sel)
				if encFn == nil || encFn == runFn || encFn == st.fn || encFn == afterFn || encFn == sp.fn || ast.IsExported(encFn.Name.Name) || mMethods[encFn.Name.Name] != encFn || funcShadowsAnyIdent(encFn, pkgReserved) {
					isolatedOK = false
					return false
				}
				hRecv := recvVarName(encFn)
				if hRecv == "" {
					isolatedOK = false
					return false
				}
				rID, okR := unwrapParens(sel.X).(*ast.Ident)
				if !okR || rID.Name != hRecv {
					isolatedOK = false
					return false
				}
				// Locate enclosing FuncLit in anc: ... -> FuncLit -> BlockStmt -> ExprStmt -> CallExpr -> sel
				if len(anc) < 5 {
					isolatedOK = false
					return false
				}
				callNode, ok1 := anc[len(anc)-2].(*ast.CallExpr)
				esNode, ok2 := anc[len(anc)-3].(*ast.ExprStmt)
				blkNode, ok3 := anc[len(anc)-4].(*ast.BlockStmt)
				flNode, ok4 := anc[len(anc)-5].(*ast.FuncLit)
				if !ok1 || !ok2 || !ok3 || !ok4 || callNode.Ellipsis.IsValid() || len(callNode.Args) != 0 || unwrapParens(callNode.Fun) != sel || unwrapParens(esNode.X) != callNode || flNode.Body != blkNode || len(blkNode.List) < 2 || blkNode.List[0] != esNode {
					isolatedOK = false
					return false
				}
				// Verify FuncLit body has no ReturnStmt, LabeledStmt, BranchStmt, DeferStmt, ForStmt, or recover,
				// and ends with unconditional panic(...).
				badFL := false
				ast.Inspect(blkNode, func(fnNode ast.Node) bool {
					if badFL || fnNode == nil {
						return false
					}
					if innerFL, isFL := fnNode.(*ast.FuncLit); isFL {
						badFL = innerFL != flNode
						return false
					}
					switch x := fnNode.(type) {
					case *ast.ReturnStmt, *ast.LabeledStmt, *ast.BranchStmt, *ast.DeferStmt, *ast.ForStmt, *ast.SelectStmt:
						badFL = true
						return false
					case *ast.CallExpr:
						if cid, ok := unwrapParens(x.Fun).(*ast.Ident); ok && cid.Name == "recover" {
							badFL = true
							return false
						}
					}
					return true
				})
				if badFL || funcLitShadowsAnyIdent(flNode, map[string]bool{"panic": true}) {
					isolatedOK = false
					return false
				}
				lastES, okLast := blkNode.List[len(blkNode.List)-1].(*ast.ExprStmt)
				if !okLast {
					isolatedOK = false
					return false
				}
				pCall, okPC := unwrapParens(lastES.X).(*ast.CallExpr)
				if !okPC || pCall.Ellipsis.IsValid() || len(pCall.Args) != 1 {
					isolatedOK = false
					return false
				}
				if pID, okPID := unwrapParens(pCall.Fun).(*ast.Ident); !okPID || pID.Name != "panic" {
					isolatedOK = false
					return false
				}
				extraAfterHelperNames[encFn.Name.Name] = true
				alarmAfterSels[sel] = true
			}
			return true
		})
		if !isolatedOK {
			return false
		}
	}

	// Any helper method containing a secondary m.<after>() panic FuncLit (e.g. startAlarm)
	// may only be referenced inside runFn.Body.List[beforeIdx+2:].
	if len(extraAfterHelperNames) > 0 {
		allowedHelperSels := map[*ast.SelectorExpr]bool{}
		for _, postStmt := range runFn.Body.List[beforeIdx+2:] {
			ast.Inspect(postStmt, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 0 {
					if sel, ok2 := unwrapParens(call.Fun).(*ast.SelectorExpr); ok2 && extraAfterHelperNames[sel.Sel.Name] {
						if rID, ok3 := unwrapParens(sel.X).(*ast.Ident); ok3 && rID.Name == runRecv {
							allowedHelperSels[sel] = true
						}
					}
				}
				return true
			})
		}
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				if !isolatedOK || n == nil {
					return false
				}
				if sel, ok := n.(*ast.SelectorExpr); ok && extraAfterHelperNames[sel.Sel.Name] && !allowedHelperSels[sel] {
					isolatedOK = false
					return false
				}
				return true
			})
		}
		if !isolatedOK {
			return false
		}
	}

	// Verify Mode 2 os.Exit containment across active testlog lifecycle:
	// - Direct os.Exit in st.fn (`before`) allowed ONLY in st.openExits or before startInBeforeIdx.
	// - Zero direct os.Exit in afterFn (when afterFn != sp.fn) and extraAfterHelperNames.
	// - Direct os.Exit inside sp.fn.Body.List[0] (`if *testlog != ""`) allowed ONLY in sp.stopExit or closeExits.
	// - Zero os.Exit in any non-runner helper reachable from active lifecycle statement slices.
	ancestorsTouchSlice := func(ancestors []ast.Node, slice []ast.Stmt) bool {
		for _, anc := range ancestors {
			if s, ok := anc.(ast.Stmt); ok && slices.Contains(slice, s) {
				return true
			}
		}
		return false
	}
	for _, site := range exitSitesByFunc[st.fn] {
		if !st.openExits[site.call] && !ancestorsTouchSlice(site.ancestors, st.fn.Body.List[:startInBeforeIdx]) {
			return false
		}
	}
	if afterFn != sp.fn && len(exitSitesByFunc[afterFn]) > 0 {
		return false
	}
	for helperName := range extraAfterHelperNames {
		if len(exitSitesByFunc[mMethods[helperName]]) > 0 {
			return false
		}
	}
	for _, site := range exitSitesByFunc[sp.fn] {
		if ancestorsTouchSlice(site.ancestors, sp.fn.Body.List[:1]) && site.call != sp.stopExit && !closeExits[site.call] {
			return false
		}
	}
	excludeActiveSels := map[*ast.SelectorExpr]bool{}
	if afterDeferSel != nil {
		excludeActiveSels[afterDeferSel] = true
	}
	if spCallSel != nil {
		excludeActiveSels[spCallSel] = true
	}
	for sel := range alarmAfterSels {
		excludeActiveSels[sel] = true
	}
	if !stmtsHaveNoNonRunnerHelperExit(st.declBlock.List[st.declTargetIdx+1:], excludeActiveSels) ||
		!stmtsHaveNoNonRunnerHelperExit(st.fn.Body.List[startInBeforeIdx+1:], excludeActiveSels) ||
		!stmtsHaveNoNonRunnerHelperExit(runFn.Body.List[beforeIdx+1:], excludeActiveSels) ||
		!stmtsHaveNoNonRunnerHelperExit(sp.fn.Body.List[:1], excludeActiveSels) {
		return false
	}
	if afterFn != sp.fn && !stmtsHaveNoNonRunnerHelperExit(afterFn.Body.List, excludeActiveSels) {
		return false
	}

	return true
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
