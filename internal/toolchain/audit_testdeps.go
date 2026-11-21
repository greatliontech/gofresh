package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"strconv"
	"strings"
)

func verifyTestdepsLoggerMethods(
	loggerType, boundField, muField string,
	methods map[string]*ast.FuncDecl,
	methodFiles map[*ast.FuncDecl]*ast.File,
	fileImportsStrings map[*ast.File]bool,
	k *packageInactiveKernel,
	reqGates map[string]bool,
) (hostAddHelper string, ok bool) {
	if len(methods) != 5 {
		return "", false
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
			return "", false
		}
		star, ok := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr)
		if !ok {
			return "", false
		}
		if _, ok := isIdentNamed(star.X, loggerType); !ok {
			return "", false
		}
		recv := recvVarName(fn)
		pNames := paramNamesFlat(fn.Type.Params)
		if recv == "" || len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || pNames[0] == recv || len(fn.Type.Params.List) != 1 {
			return "", false
		}
		if _, ok := isIdentNamed(fn.Type.Params.List[0].Type, "string"); !ok {
			return "", false
		}
		es, ok := fn.Body.List[0].(*ast.ExprStmt)
		if !ok {
			return "", false
		}
		call, ok := unwrapParens(es.X).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) != 2 {
			return "", false
		}
		if _, ok := isSelectorBaseField(call.Fun, recv, "add"); !ok {
			return "", false
		}
		lit, ok := unwrapParens(call.Args[0]).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return "", false
		}
		if s, err := strconv.Unquote(lit.Value); err != nil || s != wantOp {
			return "", false
		}
		if _, ok := isIdentNamed(call.Args[1], pNames[0]); !ok {
			return "", false
		}
	}

	addFn := methods["add"]
	if addFn == nil || addFn.Body == nil || !fileImportsStrings[methodFiles[addFn]] || addFn.Type.TypeParams != nil || addFn.Recv == nil || len(addFn.Recv.List) != 1 || (addFn.Type.Results != nil && addFn.Type.Results.NumFields() != 0) || funcShadowsAnyIdent(addFn, reserved) {
		return "", false
	}
	star, ok := unwrapParens(addFn.Recv.List[0].Type).(*ast.StarExpr)
	if !ok {
		return "", false
	}
	if _, ok := isIdentNamed(star.X, loggerType); !ok {
		return "", false
	}
	recv := recvVarName(addFn)
	pNames := paramNamesFlat(addFn.Type.Params)
	if recv == "" || len(pNames) != 2 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || pNames[0] == pNames[1] || pNames[0] == recv || pNames[1] == recv {
		return "", false
	}
	for _, fld := range addFn.Type.Params.List {
		if _, ok := isIdentNamed(fld.Type, "string"); !ok {
			return "", false
		}
	}
	opParam, nameParam := pNames[0], pNames[1]
	if bodyDeclaresAnyIdent(addFn.Body, map[string]bool{recv: true, opParam: true, nameParam: true}) {
		return "", false
	}

	stmts := addFn.Body.List
	if k != nil {
		stmts, _ = k.pruneBlockStmts(addFn.Body.List, addFn, map[string]bool{recv: true, opParam: true, nameParam: true}, reqGates, nil)
	}
	// Also prune leading `if <earlyFalseFunc>(l, op, name) { return }` (e.g. inactive bubble hook).
	isEmptyReturnIf := func(s ast.Stmt) (*ast.IfStmt, bool) {
		ifs, ok := s.(*ast.IfStmt)
		if !ok || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
			return nil, false
		}
		ret, ok := ifs.Body.List[0].(*ast.ReturnStmt)
		return ifs, ok && len(ret.Results) == 0
	}
	if len(stmts) < 6 {
		return "", false
	}
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

	s0If, ok := isEmptyReturnIf(stmts[0])
	if !ok {
		return "", false
	}
	orCond, ok := unwrapParens(s0If.Cond).(*ast.BinaryExpr)
	if !ok || orCond.Op != token.LOR || !((isContainsNewline(orCond.X) && isEmptyNameEq(orCond.Y)) || (isEmptyNameEq(orCond.X) && isContainsNewline(orCond.Y))) {
		return "", false
	}

	pos := 1
	if muField != "" {
		if pos+2 > len(stmts) {
			return "", false
		}
		lockES, ok1 := stmts[pos].(*ast.ExprStmt)
		deferUnlock, ok2 := stmts[pos+1].(*ast.DeferStmt)
		if !ok1 || !ok2 {
			return "", false
		}
		if _, ok := isZeroArgMethodCallOnSelector(lockES.X, recv, muField, "Lock"); !ok {
			return "", false
		}
		if _, ok := isZeroArgMethodCallOnSelector(deferUnlock.Call, recv, muField, "Unlock"); !ok {
			return "", false
		}
		pos += 2
	}
	if pos >= len(stmts) {
		return "", false
	}
	nilIf, ok := isEmptyReturnIf(stmts[pos])
	if !ok {
		return "", false
	}
	eqCond, ok := unwrapParens(nilIf.Cond).(*ast.BinaryExpr)
	if !ok || eqCond.Op != token.EQL {
		return "", false
	}
	checkNilWriter := func(x, y ast.Expr) bool {
		_, ok1 := isSelectorBaseField(x, recv, boundField)
		_, ok2 := isIdentNamed(y, "nil")
		return ok1 && ok2
	}
	if !checkNilWriter(eqCond.X, eqCond.Y) && !checkNilWriter(eqCond.Y, eqCond.X) {
		return "", false
	}
	pos++

	// Optional locked direct-fd fast path: `if <hostAddHelper>(l, op, name) { return }`
	if pos < len(stmts) {
		if hIf, okH := isEmptyReturnIf(stmts[pos]); okH {
			if hCall, okC := unwrapParens(hIf.Cond).(*ast.CallExpr); okC && !hCall.Ellipsis.IsValid() && len(hCall.Args) == 3 {
				hID, okHID := unwrapParens(hCall.Fun).(*ast.Ident)
				_, okA0 := isIdentNamed(hCall.Args[0], recv)
				_, okA1 := isIdentNamed(hCall.Args[1], opParam)
				_, okA2 := isIdentNamed(hCall.Args[2], nameParam)
				if okHID && okA0 && okA1 && okA2 {
					hostAddHelper = hID.Name
					pos++
				}
			}
		}
	}
	if len(stmts)-pos != 4 {
		return "", false
	}

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

	ok = checkWriteIdent(stmts[pos], opParam) &&
		checkWriteConstByte(stmts[pos+1], ' ') &&
		checkWriteIdent(stmts[pos+2], nameParam) &&
		checkWriteConstByte(stmts[pos+3], '\n')
	return hostAddHelper, ok
}

// verifyTestdepsPackageAST verifies the structural contract of
// package testing/internal/testdeps without external runtime linkname pulls.
func verifyTestdepsPackageAST(files []*ast.File) error {
	reqGates, reqWriters, err := verifyTestdepsPackageASTWithPulls(files, nil, nil)
	if err != nil {
		return err
	}
	if len(reqGates) > 0 || len(reqWriters) > 0 {
		return fmt.Errorf("testing/internal/testdeps: requires cross-package runtime verification (%v, %v)", reqGates, reqWriters)
	}
	return nil
}

// verifyTestdepsPackageASTWithPulls verifies package testing/internal/testdeps,
// returning any required inactive runtime.* gates and verified runtime.* line writers.
func verifyTestdepsPackageASTWithPulls(files []*ast.File, runtimePullMap map[string]string, anyLinknameLocals map[string]bool) ([]string, []string, error) {
	reserved := map[string]bool{
		"testlog": true, "bufio": true, "strings": true, "sync": true,
		"panic": true, "recover": true, "nil": true, "true": true, "false": true,
	}
	idx, err := indexPackageAST("testing/internal/testdeps", files, reserved, map[string]bool{
		"internal/testlog": true, "bufio": true, "strings": true, "sync": true,
	})
	if err != nil {
		return nil, nil, err
	}
	startFns := idx.funcDeclsByName["StartTestLog"]
	stopFns := idx.funcDeclsByName["StopTestLog"]
	if idx.hasInitFunc || idx.anyDupTypeMethod || len(idx.dupTopFuncs) > 0 || !idx.hasAnyImport("internal/testlog") || len(startFns) != 1 || len(stopFns) != 1 {
		return nil, nil, fmt.Errorf("testing/internal/testdeps: incomplete or duplicate testlog harness declarations")
	}
	for _, bf := range idx.bodylessFuncs {
		if bf.Recv != nil || !strings.HasPrefix(runtimePullMap[bf.Name.Name], "runtime.") {
			return nil, nil, fmt.Errorf("testing/internal/testdeps: unexpected bodyless function %s", bf.Name.Name)
		}
	}
	k := newPackageInactiveKernel(idx, files, runtimePullMap, anyLinknameLocals)
	reqGates := map[string]bool{}

	fileImportsBufio := idx.fileImportSet("bufio")
	fileImportsStrings := idx.fileImportSet("strings")
	fileImportsSync := idx.fileImportSet("sync")

	if _, _, ok := idx.verifyStructFields("TestDeps", nil, false); !ok {
		return nil, nil, fmt.Errorf("testing/internal/testdeps: missing or non-empty TestDeps struct")
	}

	startFn, stopFn := startFns[0], stopFns[0]
	boundBase, boundField, muField, setField, startHelper, startAllowedBase, ok := verifyTestdepsStartFunc(startFn, idx.hasFileImport(idx.funcFile[startFn], "internal/testlog"), fileImportsBufio[idx.funcFile[startFn]], k, reqGates)
	if !ok {
		return nil, nil, fmt.Errorf("testing/internal/testdeps: StartTestLog does not wire bufio.NewWriter and testlog.SetLogger")
	}
	stopHelper, stopAllowedBase, ok := verifyTestdepsStopFunc(stopFn, boundBase, boundField, muField, k, reqGates)
	if !ok {
		return nil, nil, fmt.Errorf("testing/internal/testdeps: StopTestLog does not flush %s.%s and propagate error", boundBase, boundField)
	}

	allowedBaseIdents := map[*ast.Ident]bool{}
	maps.Copy(allowedBaseIdents, startAllowedBase)
	maps.Copy(allowedBaseIdents, stopAllowedBase)

	if idx.pkgVarCounts[boundBase] != 1 {
		return nil, nil, fmt.Errorf("testing/internal/testdeps: missing unique var %s declaration", boundBase)
	}
	vs := idx.zeroInitPkgVars[boundBase]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 0 {
		return nil, nil, fmt.Errorf("testing/internal/testdeps: %s must be a zero-initialized package variable", boundBase)
	}
	tID, ok := unwrapParens(vs.Type).(*ast.Ident)
	if !ok || tID.Name == "" || ast.IsExported(tID.Name) {
		return nil, nil, fmt.Errorf("testing/internal/testdeps: %s must have an unexported named logger struct type", boundBase)
	}
	loggerType := tID.Name
	maps.Copy(allowedBaseIdents, idx.varDeclIdents[boundBase])
	allowedLoggerTypeIdents := map[*ast.Ident]bool{tID: true}

	lSpec := idx.uniqueTypeSpec(loggerType)
	if lSpec == nil {
		return nil, nil, fmt.Errorf("testing/internal/testdeps: invalid logger struct %s", loggerType)
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
	_, lFile, ok := idx.verifyStructFields(loggerType, requiredLoggerFields, true)
	if !ok || !fileImportsBufio[lFile] || (muField != "" && !fileImportsSync[lFile]) {
		return nil, nil, fmt.Errorf("testing/internal/testdeps: invalid logger struct %s", loggerType)
	}

	lMethods := idx.typeMethods[loggerType]
	for _, m := range lMethods {
		if rID := recvTypeIdent(m.Recv.List[0].Type); rID != nil && rID.Name == loggerType {
			allowedLoggerTypeIdents[rID] = true
		}
	}
	hostAddHelper, ok := verifyTestdepsLoggerMethods(loggerType, boundField, muField, lMethods, idx.funcFile, fileImportsStrings, k, reqGates)
	if !ok {
		return nil, nil, fmt.Errorf("testing/internal/testdeps: %s methods do not faithfully format testlog records", loggerType)
	}

	var reqLineWriters []string
	hasAnyDirectFdHook := startHelper != "" || stopHelper != "" || hostAddHelper != ""
	if hasAnyDirectFdHook {
		var fdOK bool
		reqLineWriters, fdOK = verifyTestdepsDirectFdState(idx, files, k, loggerType, boundField, startHelper, stopHelper, hostAddHelper, runtimePullMap, allowedLoggerTypeIdents, reqGates)
		if !fdOK {
			return nil, nil, fmt.Errorf("testing/internal/testdeps: invalid direct-fd testlog state hooks (%s, %s, %s)", startHelper, stopHelper, hostAddHelper)
		}
	}

	// Allow *<loggerType> parameter types on proven-inactive EarlyFalseFuncs / NoopVoidFuncs / NilErrFuncs.
	markStubLoggerParamType := func(fnName string) {
		fn := idx.topFuncs[fnName]
		if fn == nil || fn.Type == nil || fn.Type.Params == nil {
			return
		}
		for _, fld := range fn.Type.Params.List {
			if star, okS := unwrapParens(fld.Type).(*ast.StarExpr); okS {
				if id, okID := isIdentNamed(star.X, loggerType); okID {
					allowedLoggerTypeIdents[id] = true
				}
			}
		}
	}
	for fnName := range k.EarlyFalseFuncs {
		markStubLoggerParamType(fnName)
	}
	for fnName := range k.NoopVoidFuncs {
		markStubLoggerParamType(fnName)
	}
	for fnName := range k.NilErrFuncs {
		markStubLoggerParamType(fnName)
	}

	if !allNonSelectorPropIdentsIn(files, map[string]map[*ast.Ident]bool{
		boundBase:  allowedBaseIdents,
		loggerType: allowedLoggerTypeIdents,
	}) {
		return nil, nil, fmt.Errorf("testing/internal/testdeps: %s or %s referenced outside StartTestLog/StopTestLog", boundBase, loggerType)
	}
	return sortedKeys(reqGates), reqLineWriters, nil
}
