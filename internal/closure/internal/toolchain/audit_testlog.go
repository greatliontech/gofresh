package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
)

// VerifyInternalTestlogPackageAST verifies the structural contract of
// package internal/testlog (Interface, logger atomic.Pointer[Interface],
// SetLogger, Logger, and Getenv/Open/Stat/Chdir dispatchers).
func VerifyInternalTestlogPackageAST(files []*ast.File) error {
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
	setFn, _, okSet := idx.VerifyFuncPreamble("", "SetLogger", false, reserved)
	if !okSet || setFn.Type.Params == nil || setFn.Type.Params.NumFields() != 1 || len(setFn.Type.Params.List) != 1 || (setFn.Type.Results != nil && setFn.Type.Results.NumFields() != 0) || len(setFn.Body.List) != 1 {
		return fmt.Errorf("internal/testlog: invalid SetLogger signature or body")
	}
	setParams := paramNamesFlat(setFn.Type.Params)
	if len(setParams) != 1 || setParams[0] == "" || setParams[0] == "_" {
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
	getFn, _, okGet := idx.VerifyFuncPreamble("", "Logger", false, reserved)
	if !okGet || (getFn.Type.Params != nil && getFn.Type.Params.NumFields() != 0) || getFn.Type.Results == nil || getFn.Type.Results.NumFields() != 1 || len(getFn.Type.Results.List) != 1 || len(getFn.Type.Results.List[0].Names) != 0 || len(getFn.Body.List) != 3 {
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
		fn, _, ok := idx.VerifyFuncPreamble("", op, false, reserved)
		if !ok || fn.Type.Params == nil || fn.Type.Params.NumFields() != 1 || len(fn.Type.Params.List) != 1 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) || len(fn.Body.List) != 1 {
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
