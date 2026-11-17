package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
)

func verifyOSFileStructTypes(idx *PackageASTIndex) error {
	fileTypeSpec := idx.uniqueTypeSpec("File")
	if idx.pkgDeclCounts["File"] != 1 || fileTypeSpec == nil || fileTypeSpec.Assign.IsValid() || fileTypeSpec.TypeParams != nil {
		return fmt.Errorf("os: missing or invalid File type declaration")
	}
	fst, ok := unwrapParens(fileTypeSpec.Type).(*ast.StructType)
	if !ok || fst.Fields == nil || len(fst.Fields.List) != 1 || len(fst.Fields.List[0].Names) != 0 {
		return fmt.Errorf("os: File must be a struct with a single embedded *file field")
	}
	star, ok := unwrapParens(fst.Fields.List[0].Type).(*ast.StarExpr)
	if !ok {
		return fmt.Errorf("os: File embedded field is not a pointer")
	}
	if _, ok := isIdentNamed(star.X, "file"); !ok {
		return fmt.Errorf("os: File embedded field is not *file")
	}
	rst, _, ok := idx.VerifyStructFields("file", map[string]func(ast.Expr) bool{
		"name": func(e ast.Expr) bool { _, ok := isIdentNamed(e, "string"); return ok },
	}, true)
	if !ok {
		return fmt.Errorf("os: invalid file struct declaration")
	}
	var sawFD bool
	for _, fld := range rst.Fields.List {
		for _, id := range fld.Names {
			if id.Name == "pfd" || id.Name == "sysfd" {
				sawFD = true
			}
		}
	}
	if !sawFD {
		return fmt.Errorf("os: file struct missing pfd/sysfd field")
	}
	return nil
}

func verifyOSExitIntegrity(files []*ast.File, exitFn *ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsTestlog, fileImportsSyscall map[*ast.File]bool, osReserved map[string]bool) error {
	if exitFn == nil || exitFn.Body == nil || exitFn.Type == nil || exitFn.Type.TypeParams != nil {
		return fmt.Errorf("os: missing Exit function")
	}
	if !fileImportsTestlog[funcFile[exitFn]] || !fileImportsSyscall[funcFile[exitFn]] {
		return fmt.Errorf("os: file defining Exit missing internal/testlog or syscall import")
	}
	if funcShadowsAnyIdent(exitFn, osReserved) || bodyHasControlFlowOrRecoverBypass(exitFn.Body) {
		return fmt.Errorf("os: Exit shadows reserved identifier or has control-flow/recover bypass")
	}
	pNames := paramNamesFlat(exitFn.Type.Params)
	if len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || len(exitFn.Type.Params.List) != 1 || (exitFn.Type.Results != nil && exitFn.Type.Results.NumFields() != 0) {
		return fmt.Errorf("os: Exit invalid signature")
	}
	if _, okInt := isIdentNamed(exitFn.Type.Params.List[0].Type, "int"); !okInt {
		return fmt.Errorf("os: Exit parameter is not int")
	}
	codeParam := pNames[0]
	if bodyMutatesOrTakesAddrOfAny(exitFn.Body, map[string]bool{codeParam: true}) || bodyDeclaresAnyIdent(exitFn.Body, map[string]bool{codeParam: true}) {
		return fmt.Errorf("os: Exit mutates or shadows %s", codeParam)
	}
	if len(exitFn.Body.List) != 2 && len(exitFn.Body.List) != 3 {
		return fmt.Errorf("os: Exit unexpected statement count %d", len(exitFn.Body.List))
	}
	s0, ok := exitFn.Body.List[0].(*ast.IfStmt)
	if !ok || s0.Init != nil || s0.Else != nil || len(s0.Body.List) != 1 {
		return fmt.Errorf("os: Exit missing PanicOnExit0 guard")
	}
	andBin, ok := unwrapParens(s0.Cond).(*ast.BinaryExpr)
	if !ok || andBin.Op != token.LAND {
		return fmt.Errorf("os: Exit guard condition is not &&")
	}
	eqBin, ok := unwrapParens(andBin.X).(*ast.BinaryExpr)
	if !ok || eqBin.Op != token.EQL {
		return fmt.Errorf("os: Exit guard LHS is not == 0")
	}
	_, okCodeL := isIdentNamed(eqBin.X, codeParam)
	_, okCodeR := isIdentNamed(eqBin.Y, codeParam)
	if !((okCodeL && isZeroIntLit(eqBin.Y)) || (isZeroIntLit(eqBin.X) && okCodeR)) {
		return fmt.Errorf("os: Exit guard does not compare %s == 0", codeParam)
	}
	if _, okPOE := isZeroArgMethodCallOnIdent(andBin.Y, "testlog", "PanicOnExit0"); !okPOE {
		return fmt.Errorf("os: Exit guard does not call testlog.PanicOnExit0()")
	}
	pES, ok := s0.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return fmt.Errorf("os: Exit guard body is not panic statement")
	}
	pCall, ok := unwrapParens(pES.X).(*ast.CallExpr)
	if !ok || pCall.Ellipsis.IsValid() || len(pCall.Args) != 1 {
		return fmt.Errorf("os: Exit guard invalid panic call")
	}
	if _, okP := isIdentNamed(pCall.Fun, "panic"); !okP {
		return fmt.Errorf("os: Exit guard does not call panic")
	}
	if lit, okLit := unwrapParens(pCall.Args[0]).(*ast.BasicLit); !okLit || lit.Kind != token.STRING {
		return fmt.Errorf("os: Exit panic argument must be string literal")
	}

	allowedBeforeExit := map[*ast.Ident]bool{}
	beforeExitDecls := 0
	for _, f := range files {
		for _, decl := range f.Decls {
			if fn, okF := decl.(*ast.FuncDecl); okF && fn.Recv == nil && fn.Name != nil && fn.Name.Name == "runtime_beforeExit" {
				beforeExitDecls++
				if fn.Body != nil || beforeExitDecls > 1 {
					return fmt.Errorf("os: invalid or duplicate runtime_beforeExit declaration")
				}
				allowedBeforeExit[fn.Name] = true
			}
		}
	}
	if len(exitFn.Body.List) == 3 {
		s1, okES := exitFn.Body.List[1].(*ast.ExprStmt)
		if !okES {
			return fmt.Errorf("os: Exit middle statement is not runtime_beforeExit call")
		}
		beCall, okC := unwrapParens(s1.X).(*ast.CallExpr)
		if !okC || beCall.Ellipsis.IsValid() || len(beCall.Args) != 1 {
			return fmt.Errorf("os: Exit invalid runtime_beforeExit call")
		}
		beID, okID := isIdentNamed(beCall.Fun, "runtime_beforeExit")
		_, okArg := isIdentNamed(beCall.Args[0], codeParam)
		if !okID || !okArg {
			return fmt.Errorf("os: Exit middle statement does not call runtime_beforeExit(%s)", codeParam)
		}
		allowedBeforeExit[beID] = true
	}

	lastES, ok := exitFn.Body.List[len(exitFn.Body.List)-1].(*ast.ExprStmt)
	if !ok {
		return fmt.Errorf("os: Exit final statement is not syscall.Exit call")
	}
	sysCall, ok := unwrapParens(lastES.X).(*ast.CallExpr)
	if !ok || sysCall.Ellipsis.IsValid() || len(sysCall.Args) != 1 {
		return fmt.Errorf("os: Exit invalid syscall.Exit call")
	}
	sysSel, ok := unwrapParens(sysCall.Fun).(*ast.SelectorExpr)
	if !ok || sysSel.Sel.Name != "Exit" {
		return fmt.Errorf("os: Exit does not call syscall.Exit")
	}
	if _, okSys := isIdentNamed(sysSel.X, "syscall"); !okSys {
		return fmt.Errorf("os: Exit final call receiver is not syscall")
	}
	if _, okArg := isIdentNamed(sysCall.Args[0], codeParam); !okArg {
		return fmt.Errorf("os: Exit does not forward %s to syscall.Exit", codeParam)
	}

	var exitLeak bool
	for _, f := range files {
		walkNonSelectorPropIdents(f, func(id *ast.Ident) {
			if id.Name == "Exit" && id != exitFn.Name {
				exitLeak = true
			}
			if id.Name == "runtime_beforeExit" && !allowedBeforeExit[id] {
				exitLeak = true
			}
		})
		ast.Inspect(f, func(n ast.Node) bool {
			if exitLeak || n == nil {
				return false
			}
			if sel, okS := n.(*ast.SelectorExpr); okS && sel != sysSel && (sel.Sel.Name == "Exit" || sel.Sel.Name == "ExitProcess") {
				if _, okSys := isIdentNamed(sel.X, "syscall"); okSys {
					exitLeak = true
					return false
				}
			}
			return true
		})
		if exitLeak {
			return fmt.Errorf("os: forbidden process-termination reference outside Exit")
		}
	}
	return nil
}

func verifyOSEpipecheck(fn *ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsSyscall map[*ast.File]bool, osNoFileReserved, osAnyLinknameLocals map[string]bool) error {
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || osAnyLinknameLocals["epipecheck"] {
		return fmt.Errorf("os: missing or invalid epipecheck")
	}
	if funcShadowsAnyIdent(fn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return fmt.Errorf("os: epipecheck shadows reserved identifier or has control-flow bypass")
	}
	pNames := paramNamesFlat(fn.Type.Params)
	if len(pNames) != 2 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) {
		return fmt.Errorf("os: epipecheck invalid signature")
	}
	if len(fn.Body.List) == 0 {
		return nil
	}
	if len(fn.Body.List) != 1 || !fileImportsSyscall[funcFile[fn]] {
		return fmt.Errorf("os: epipecheck unexpected body")
	}
	ifs, ok := fn.Body.List[0].(*ast.IfStmt)
	if !ok || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
		return fmt.Errorf("os: epipecheck body is not single EPIPE guard")
	}
	isEpipeCmp := func(expr ast.Expr) bool {
		bin, okB := unwrapParens(expr).(*ast.BinaryExpr)
		if !okB || bin.Op != token.EQL {
			return false
		}
		_, okE := isIdentNamed(bin.X, pNames[1])
		_, okSys := isSelectorBaseField(bin.Y, "syscall", "EPIPE")
		return okE && okSys
	}
	condOK := isEpipeCmp(ifs.Cond)
	if !condOK {
		if andBin, okA := unwrapParens(ifs.Cond).(*ast.BinaryExpr); okA && andBin.Op == token.LAND {
			_, okStd := isSelectorBaseField(andBin.Y, pNames[0], "stdoutOrErr")
			condOK = isEpipeCmp(andBin.X) && okStd
		}
	}
	es, okES := ifs.Body.List[0].(*ast.ExprStmt)
	if !condOK || !okES {
		return fmt.Errorf("os: epipecheck invalid condition or call")
	}
	sc, okC := unwrapParens(es.X).(*ast.CallExpr)
	if !okC || sc.Ellipsis.IsValid() || len(sc.Args) != 0 {
		return fmt.Errorf("os: epipecheck invalid sigpipe call")
	}
	if _, okSig := isIdentNamed(sc.Fun, "sigpipe"); !okSig {
		return fmt.Errorf("os: epipecheck does not call sigpipe()")
	}
	return nil
}

func verifyOSFileFdMethods(fdExported, fdLower *ast.FuncDecl, osNoFileReserved map[string]bool, skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool) error {
	if fdExported == nil || fdExported.Body == nil || len(fdExported.Body.List) != 1 || funcShadowsAnyIdent(fdExported, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fdExported.Body) {
		return fmt.Errorf("os: missing or invalid (*File).Fd")
	}
	expRecv := recvVarName(fdExported)
	if expRecv == "" || (fdExported.Type.Params != nil && fdExported.Type.Params.NumFields() != 0) || fdExported.Type.Results == nil || fdExported.Type.Results.NumFields() != 1 || len(fdExported.Type.Results.List) != 1 {
		return fmt.Errorf("os: (*File).Fd invalid signature")
	}
	if _, okU := isIdentNamed(fdExported.Type.Results.List[0].Type, "uintptr"); !okU {
		return fmt.Errorf("os: (*File).Fd result is not uintptr")
	}
	expRet, ok := fdExported.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(expRet.Results) != 1 {
		return fmt.Errorf("os: (*File).Fd does not return single expression")
	}
	if _, okCall := isZeroArgMethodCallOnIdent(expRet.Results[0], expRecv, "fd"); !okCall {
		return fmt.Errorf("os: (*File).Fd does not delegate to %s.fd()", expRecv)
	}

	if fdLower == nil || fdLower.Body == nil || len(fdLower.Body.List) < 2 || funcShadowsAnyIdent(fdLower, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fdLower.Body) {
		return fmt.Errorf("os: missing or invalid (*File).fd")
	}
	lowRecv := recvVarName(fdLower)
	if lowRecv == "" || (fdLower.Type.Params != nil && fdLower.Type.Params.NumFields() != 0) || fdLower.Type.Results == nil || fdLower.Type.Results.NumFields() != 1 || len(fdLower.Type.Results.List) != 1 {
		return fmt.Errorf("os: (*File).fd invalid signature")
	}
	if _, okU := isIdentNamed(fdLower.Type.Results.List[0].Type, "uintptr"); !okU {
		return fmt.Errorf("os: (*File).fd result is not uintptr")
	}
	if bodyMutatesOrTakesAddrOfAny(fdLower.Body, map[string]bool{lowRecv: true}) || bodyDeclaresAnyIdent(fdLower.Body, map[string]bool{lowRecv: true}) {
		return fmt.Errorf("os: (*File).fd mutates or shadows receiver")
	}
	ifs0, ok := fdLower.Body.List[0].(*ast.IfStmt)
	if !ok || ifs0.Init != nil || ifs0.Else != nil || !condChecksEqErr(ifs0.Cond, lowRecv) || len(ifs0.Body.List) != 1 {
		return fmt.Errorf("os: (*File).fd missing nil receiver guard")
	}
	ret0, ok := ifs0.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret0.Results) != 1 {
		return fmt.Errorf("os: (*File).fd invalid nil receiver return")
	}
	badNilRet := false
	ast.Inspect(ret0.Results[0], func(n ast.Node) bool {
		if badNilRet || n == nil {
			return false
		}
		if c, okC := n.(*ast.CallExpr); okC {
			if _, okConv := isIdentNamed(c.Fun, "uintptr"); !okConv || c.Ellipsis.IsValid() || len(c.Args) != 1 {
				badNilRet = true
				return false
			}
		}
		return true
	})
	if badNilRet {
		return fmt.Errorf("os: (*File).fd nil guard contains forbidden call")
	}
	pos := 1
	for pos < len(fdLower.Body.List)-1 && skipInactiveHookIf(fdLower.Body.List[pos], fdLower) {
		pos++
	}
	for _, mid := range fdLower.Body.List[pos : len(fdLower.Body.List)-1] {
		if ifs, okI := mid.(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
			if _, okNB := isSelectorBaseField(ifs.Cond, lowRecv, "nonblock"); okNB {
				if es, okES := ifs.Body.List[0].(*ast.ExprStmt); okES {
					if _, okSB := isZeroArgMethodCallOnSelector(es.X, lowRecv, "pfd", "SetBlocking"); okSB {
						continue
					}
				}
			}
		}
		if as, okA := mid.(*ast.AssignStmt); okA && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if _, okBlank := isIdentNamed(as.Lhs[0], "_"); okBlank {
				if _, okDis := isZeroArgMethodCallOnSelector(as.Rhs[0], lowRecv, "pfd", "DisassociateIOCP"); okDis {
					continue
				}
			}
		}
		return fmt.Errorf("os: (*File).fd unexpected statement before final return")
	}
	lastRet, ok := fdLower.Body.List[len(fdLower.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(lastRet.Results) != 1 {
		return fmt.Errorf("os: (*File).fd invalid final return")
	}
	convCall, ok := unwrapParens(lastRet.Results[0]).(*ast.CallExpr)
	if !ok || convCall.Ellipsis.IsValid() || len(convCall.Args) != 1 {
		return fmt.Errorf("os: (*File).fd final return is not uintptr(...) conversion")
	}
	if _, okU := isIdentNamed(convCall.Fun, "uintptr"); !okU {
		return fmt.Errorf("os: (*File).fd final return is not uintptr(...)")
	}
	_, okSysfdDirect := isSelectorBaseField(convCall.Args[0], lowRecv, "sysfd")
	var okPFDSysfd bool
	if sel, okS := unwrapParens(convCall.Args[0]).(*ast.SelectorExpr); okS && sel.Sel.Name == "Sysfd" {
		_, okPFDSysfd = isSelectorBaseField(sel.X, lowRecv, "pfd")
	}
	if !okSysfdDirect && !okPFDSysfd {
		return fmt.Errorf("os: (*File).fd does not return uintptr(%s.pfd.Sysfd) or uintptr(%s.sysfd)", lowRecv, lowRecv)
	}
	return nil
}

func verifyOSTestlogChdirTail(label string, tail []ast.Stmt) error {
	if len(tail) != 2 {
		return fmt.Errorf("os: %s missing trailing testlog.Logger().Chdir + return nil", label)
	}
	logIf, ok := tail[0].(*ast.IfStmt)
	if !ok || logIf.Init == nil || logIf.Else != nil || len(logIf.Body.List) != 2 {
		return fmt.Errorf("os: %s missing testlog.Logger() block", label)
	}
	logInit, ok := logIf.Init.(*ast.AssignStmt)
	if !ok || logInit.Tok != token.DEFINE || len(logInit.Lhs) != 1 || len(logInit.Rhs) != 1 {
		return fmt.Errorf("os: %s invalid testlog.Logger() assignment", label)
	}
	logID, ok1 := unwrapParens(logInit.Lhs[0]).(*ast.Ident)
	logCall, ok2 := unwrapParens(logInit.Rhs[0]).(*ast.CallExpr)
	if !ok1 || !ok2 || logID.Name == "" || logID.Name == "_" || condChecksNonZeroErr(logIf.Cond) != logID.Name || logCall.Ellipsis.IsValid() || len(logCall.Args) != 0 {
		return fmt.Errorf("os: %s invalid testlog.Logger() guard", label)
	}
	if _, okSel := isSelectorBaseField(logCall.Fun, "testlog", "Logger"); !okSel {
		return fmt.Errorf("os: %s does not call testlog.Logger()", label)
	}
	wdAs, ok := logIf.Body.List[0].(*ast.AssignStmt)
	if !ok || wdAs.Tok != token.DEFINE || len(wdAs.Lhs) != 2 || len(wdAs.Rhs) != 1 {
		return fmt.Errorf("os: %s missing Getwd() assignment", label)
	}
	wdID, ok1 := unwrapParens(wdAs.Lhs[0]).(*ast.Ident)
	wdErrID, ok2 := unwrapParens(wdAs.Lhs[1]).(*ast.Ident)
	wdCall, ok3 := unwrapParens(wdAs.Rhs[0]).(*ast.CallExpr)
	if !ok1 || !ok2 || !ok3 || wdID.Name == "" || wdID.Name == "_" || wdErrID.Name == "" || wdErrID.Name == "_" || wdID.Name == wdErrID.Name || wdCall.Ellipsis.IsValid() || len(wdCall.Args) != 0 {
		return fmt.Errorf("os: %s invalid Getwd() call", label)
	}
	if _, okFun := isIdentNamed(wdCall.Fun, "Getwd"); !okFun {
		return fmt.Errorf("os: %s does not call Getwd()", label)
	}
	wdIf, ok := logIf.Body.List[1].(*ast.IfStmt)
	if !ok || wdIf.Init != nil || wdIf.Else != nil || !condChecksEqErr(wdIf.Cond, wdErrID.Name) || len(wdIf.Body.List) != 1 {
		return fmt.Errorf("os: %s missing if err == nil guard around log.Chdir", label)
	}
	chES, ok := wdIf.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return fmt.Errorf("os: %s log.Chdir not an expression statement", label)
	}
	chCall, ok := unwrapParens(chES.X).(*ast.CallExpr)
	if !ok || chCall.Ellipsis.IsValid() || len(chCall.Args) != 1 {
		return fmt.Errorf("os: %s invalid log.Chdir call", label)
	}
	if _, okSel := isSelectorBaseField(chCall.Fun, logID.Name, "Chdir"); !okSel {
		return fmt.Errorf("os: %s does not call %s.Chdir", label, logID.Name)
	}
	if _, okArg := isIdentNamed(chCall.Args[0], wdID.Name); !okArg {
		return fmt.Errorf("os: %s does not pass %s to %s.Chdir", label, wdID.Name, logID.Name)
	}
	retNil, ok := tail[1].(*ast.ReturnStmt)
	if !ok || len(retNil.Results) != 1 {
		return fmt.Errorf("os: %s missing trailing return nil", label)
	}
	if _, okNil := isIdentNamed(retNil.Results[0], "nil"); !okNil {
		return fmt.Errorf("os: %s trailing return is not nil", label)
	}
	return nil
}

func verifyOSFileChdir(
	fn, increfFn *ast.FuncDecl,
	funcFile map[*ast.FuncDecl]*ast.File,
	fileImportsTestlog, fileImportsSyscall map[*ast.File]bool,
	osReserved map[string]bool,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
) error {
	if fn == nil || fn.Body == nil || len(fn.Body.List) < 4 || !fileImportsTestlog[funcFile[fn]] || funcShadowsAnyIdent(fn, osReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return fmt.Errorf("os: missing or invalid (*File).Chdir")
	}
	recv := recvVarName(fn)
	if recv == "" || (fn.Type.Params != nil && fn.Type.Params.NumFields() != 0) || !funcReturnsErrorLast(fn.Type) || fn.Type.Results.NumFields() != 1 {
		return fmt.Errorf("os: (*File).Chdir invalid signature")
	}
	if bodyMutatesOrTakesAddrOfAny(fn.Body, map[string]bool{recv: true}) || bodyDeclaresAnyIdent(fn.Body, map[string]bool{recv: true}) {
		return fmt.Errorf("os: (*File).Chdir mutates or shadows receiver")
	}
	checkEntryGuard := func(st ast.Stmt, method string) bool {
		ifs, ok := st.(*ast.IfStmt)
		if !ok || ifs.Init == nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
			return false
		}
		as, ok := ifs.Init.(*ast.AssignStmt)
		if !ok || (as.Tok != token.DEFINE && as.Tok != token.ASSIGN) || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return false
		}
		eID, ok1 := unwrapParens(as.Lhs[0]).(*ast.Ident)
		call, ok2 := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || eID.Name == "" || eID.Name == "_" || condChecksNonZeroErr(ifs.Cond) != eID.Name || call.Ellipsis.IsValid() || len(call.Args) != 1 {
			return false
		}
		if _, okSel := isSelectorBaseField(call.Fun, recv, method); !okSel {
			return false
		}
		ret, ok := ifs.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return false
		}
		_, okErr := isIdentNamed(ret.Results[0], eID.Name)
		return okErr
	}

	stmts := fn.Body.List
	var allowedDefer *ast.DeferStmt
	pos := 0
	isPlan9 := false
	if checkEntryGuard(stmts[0], "checkValid") {
		pos = 1
	} else if checkEntryGuard(stmts[0], "incref") && len(stmts) >= 5 && increfFn != nil && fileImportsSyscall[funcFile[fn]] {
		increfRecv := recvVarName(increfFn)
		if increfRecv == "" || len(increfFn.Body.List) < 2 || funcShadowsAnyIdent(increfFn, osReserved) || bodyHasControlFlowOrRecoverBypass(increfFn.Body) {
			return fmt.Errorf("os: (*File).incref invalid body")
		}
		if g0, okG := increfFn.Body.List[0].(*ast.IfStmt); !okG || g0.Init != nil || g0.Else != nil || !condChecksEqErr(g0.Cond, increfRecv) || len(g0.Body.List) != 1 {
			return fmt.Errorf("os: (*File).incref missing nil receiver guard")
		} else if r0, okR0 := g0.Body.List[0].(*ast.ReturnStmt); !okR0 || len(r0.Results) != 1 {
			return fmt.Errorf("os: (*File).incref invalid nil return")
		} else if _, okEI := isIdentNamed(r0.Results[0], "ErrInvalid"); !okEI {
			return fmt.Errorf("os: (*File).incref does not return ErrInvalid")
		}
		ds, okD := stmts[1].(*ast.DeferStmt)
		if !okD {
			return fmt.Errorf("os: (*File).Chdir incref missing defer decref()")
		}
		if _, okDec := isZeroArgMethodCallOnIdent(ds.Call, recv, "decref"); !okDec {
			return fmt.Errorf("os: (*File).Chdir defer does not call %s.decref()", recv)
		}
		allowedDefer = ds
		isPlan9 = true
		pos = 2
	} else {
		return fmt.Errorf("os: (*File).Chdir missing checkValid or incref guard")
	}

	bad := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit, *ast.GoStmt, *ast.SendStmt:
			bad = true
			return false
		case *ast.DeferStmt:
			if node != allowedDefer {
				bad = true
				return false
			}
		}
		return true
	})
	if bad {
		return fmt.Errorf("os: (*File).Chdir contains unexpected defer/closure/go")
	}

	for pos < len(stmts) && skipInactiveHookIf(stmts[pos], fn) {
		pos++
	}
	if len(stmts)-pos != 3 {
		return fmt.Errorf("os: (*File).Chdir unexpected statement count after guard")
	}
	fcIf, ok := stmts[pos].(*ast.IfStmt)
	if !ok || fcIf.Init == nil || fcIf.Else != nil || len(fcIf.Body.List) != 1 {
		return fmt.Errorf("os: (*File).Chdir missing Fchdir error guard")
	}
	fcAs, ok := fcIf.Init.(*ast.AssignStmt)
	fcRet, okR := fcIf.Body.List[0].(*ast.ReturnStmt)
	if !ok || !okR || fcAs.Tok != token.DEFINE || len(fcAs.Lhs) != 1 || len(fcAs.Rhs) != 1 || len(fcRet.Results) != 1 {
		return fmt.Errorf("os: (*File).Chdir invalid Fchdir guard structure")
	}
	eID, ok1 := unwrapParens(fcAs.Lhs[0]).(*ast.Ident)
	fcCall, ok2 := unwrapParens(fcAs.Rhs[0]).(*ast.CallExpr)
	if !ok1 || !ok2 || eID.Name == "" || eID.Name == "_" || condChecksNonZeroErr(fcIf.Cond) != eID.Name || fcCall.Ellipsis.IsValid() {
		return fmt.Errorf("os: (*File).Chdir invalid Fchdir call")
	}
	if !isPlan9 {
		if len(fcCall.Args) != 0 {
			return fmt.Errorf("os: (*File).Chdir pfd.Fchdir must take 0 args")
		}
		if _, okPFD := isZeroArgMethodCallOnSelector(fcAs.Rhs[0], recv, "pfd", "Fchdir"); !okPFD {
			return fmt.Errorf("os: (*File).Chdir does not call %s.pfd.Fchdir()", recv)
		}
	} else {
		if len(fcCall.Args) != 1 {
			return fmt.Errorf("os: (*File).Chdir syscall.Fchdir must take 1 arg")
		}
		_, okSC := isSelectorBaseField(fcCall.Fun, "syscall", "Fchdir")
		_, okSysfd := isSelectorBaseField(fcCall.Args[0], recv, "sysfd")
		if !okSC || !okSysfd {
			return fmt.Errorf("os: (*File).Chdir does not call syscall.Fchdir(%s.sysfd)", recv)
		}
	}
	errRes := unwrapParens(fcRet.Results[0])
	wrappedOK := false
	if weCall, okWE := errRes.(*ast.CallExpr); okWE && !weCall.Ellipsis.IsValid() && len(weCall.Args) == 2 {
		_, okSel := isSelectorBaseField(weCall.Fun, recv, "wrapErr")
		_, okArg := isIdentNamed(weCall.Args[1], eID.Name)
		wrappedOK = okSel && okArg
	} else if u, okU := errRes.(*ast.UnaryExpr); okU && u.Op == token.AND {
		if cl, tName := compositeWriterLit(errRes); cl != nil && tName == "PathError" {
			for _, elt := range cl.Elts {
				if kv, okKV := elt.(*ast.KeyValueExpr); okKV {
					if kID, okK := unwrapParens(kv.Key).(*ast.Ident); okK && kID.Name == "Err" {
						_, wrappedOK = isIdentNamed(kv.Value, eID.Name)
					}
				}
			}
		}
	}
	if !wrappedOK {
		return fmt.Errorf("os: (*File).Chdir does not propagate wrapped Fchdir error")
	}
	return verifyOSTestlogChdirTail("(*File).Chdir", stmts[pos+1:])
}

