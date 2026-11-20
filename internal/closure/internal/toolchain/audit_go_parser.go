package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"

	"github.com/greatliontech/gofresh/internal/auditset"
)

// VerifyGoParserPackageAST verifies the structural AST contract for go/parser.
func VerifyGoParserPackageAST(files []*ast.File) error {
	if len(files) == 0 {
		return fmt.Errorf("go/parser: no AST files")
	}
	if err := verifyClosedPackageImports("go/parser", files, allowedGoParserImports); err != nil {
		return err
	}
	idx, err := indexPackageAST("go/parser", files, goParserReservedIdents, allowedGoParserImports)
	if err != nil {
		return err
	}
	if idx.hasInitFunc || len(idx.bodylessFuncs) > 0 || len(idx.dupTopFuncs) > 0 || idx.anyDupTypeMethod {
		return fmt.Errorf("go/parser: unexpected init, bodyless, or duplicate function declaration")
	}
	if !verifyGoParserTraceConstBit(files) {
		return fmt.Errorf("go/parser: Trace constant bit (1 << 3) mismatch")
	}

	varNames := map[string]bool{}
	for name, cnt := range idx.pkgVarCounts {
		if cnt != 1 || ast.IsExported(name) {
			return fmt.Errorf("go/parser: forbidden exported or duplicate package var %q", name)
		}
		initExpr, ok := idx.initPkgVars[name]
		if !ok || (!isTokenBoolMapLit(initExpr) && !isNewASTObjectCall(initExpr)) {
			return fmt.Errorf("go/parser: unapproved package var %q initializer", name)
		}
		varNames[name] = true
	}
	if err := verifyPkgVarsNeverMutatedOrAddressed("go/parser", files, varNames, nil); err != nil {
		return err
	}

	if err := verifyGoParserEntrypoints(idx); err != nil {
		return err
	}
	initAssign, err := verifyGoParserTraceFieldAssignment(idx, files)
	if err != nil {
		return err
	}
	_ = initAssign

	kernel := NewPackageInactiveKernel(idx, files, nil, nil)
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if err := verifyNoConcurrencyOrBuiltinPrint("go/parser", fn); err != nil {
				return err
			}
			if err := verifyGoParserFuncBody(fn, kernel); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyGoParserTraceConstBit(files []*ast.File) bool {
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			firstIotaShift := false
			for iotaIdx, sp := range gd.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 {
					firstIotaShift = false
					continue
				}
				if iotaIdx == 0 && len(vs.Values) == 1 && isOneShiftIota(vs.Values[0]) {
					firstIotaShift = true
				} else if iotaIdx > 0 && len(vs.Values) != 0 {
					if vs.Names[0].Name == "Trace" {
						return isTraceBitExpr(vs.Values[0])
					}
					firstIotaShift = false
					continue
				}
				if vs.Names[0].Name == "Trace" {
					return (firstIotaShift && iotaIdx == 3 && len(vs.Values) == 0) || (len(vs.Values) == 1 && isTraceBitExpr(vs.Values[0]))
				}
			}
		}
	}
	return false
}

func isOneShiftIota(expr ast.Expr) bool {
	be, ok := unwrapParens(expr).(*ast.BinaryExpr)
	if !ok || be.Op != token.SHL {
		return false
	}
	lit, okL := unwrapParens(be.X).(*ast.BasicLit)
	_, okR := isIdentNamed(be.Y, "iota")
	return okL && lit.Kind == token.INT && lit.Value == "1" && okR
}

func isTraceBitExpr(expr ast.Expr) bool {
	switch e := unwrapParens(expr).(type) {
	case *ast.BasicLit:
		return e.Kind == token.INT && (e.Value == "8" || e.Value == "0x8")
	case *ast.BinaryExpr:
		if e.Op != token.SHL {
			return false
		}
		l, okL := unwrapParens(e.X).(*ast.BasicLit)
		r, okR := unwrapParens(e.Y).(*ast.BasicLit)
		return okL && okR && l.Kind == token.INT && l.Value == "1" && r.Kind == token.INT && r.Value == "3"
	default:
		return false
	}
}

func verifyGoParserEntrypoints(idx *PackageASTIndex) error {
	rsFn, _, okRS := idx.VerifyFuncPreamble("", "readSource", false, goParserReservedIdents)
	if !okRS || rsFn.Type.Params == nil || rsFn.Type.Params.NumFields() != 2 || len(rsFn.Body.List) < 2 {
		return fmt.Errorf("go/parser: missing or invalid readSource")
	}
	srcParam := paramIdentAt(rsFn.Type.Params, 1)
	firstIf, okIf := rsFn.Body.List[0].(*ast.IfStmt)
	if srcParam == "" || !okIf || firstIf.Init != nil || firstIf.Else != nil || !isIdentNonNilCond(firstIf.Cond, srcParam) || !blockAlwaysReturns(firstIf.Body.List) {
		return fmt.Errorf("go/parser: readSource must return inside initial if %s != nil guard", srcParam)
	}
	var nonNilOSErr error
	WalkLexicalAST(firstIf.Body, funcInitialLexicalScope(rsFn), nil, nil, func(base, sel string) {
		if base == "os" && nonNilOSErr == nil {
			nonNilOSErr = fmt.Errorf("go/parser: forbidden os.%s inside readSource non-nil branch", sel)
		}
	})
	if nonNilOSErr != nil {
		return nonNilOSErr
	}

	peFn, _, okPE := idx.VerifyFuncPreamble("", "ParseExpr", false, goParserReservedIdents)
	if !okPE || peFn.Type.Params == nil || peFn.Type.Params.NumFields() != 1 || len(peFn.Body.List) != 1 {
		return fmt.Errorf("go/parser: missing or invalid ParseExpr")
	}
	xParam := paramIdentAt(peFn.Type.Params, 0)
	ret, okRet := peFn.Body.List[0].(*ast.ReturnStmt)
	if xParam == "" || !okRet || len(ret.Results) != 1 {
		return fmt.Errorf("go/parser: ParseExpr must be a single return statement")
	}
	call, okCall := unwrapParens(ret.Results[0]).(*ast.CallExpr)
	if !okCall || call.Ellipsis.IsValid() || len(call.Args) != 4 {
		return fmt.Errorf("go/parser: ParseExpr must call 4-arg ParseExprFrom")
	}
	if _, okFun := isIdentNamed(call.Fun, "ParseExprFrom"); !okFun {
		return fmt.Errorf("go/parser: ParseExpr must delegate to ParseExprFrom")
	}
	srcConv, okConv := unwrapParens(call.Args[2]).(*ast.CallExpr)
	if !okConv || srcConv.Ellipsis.IsValid() || len(srcConv.Args) != 1 || !isByteSliceType(srcConv.Fun) {
		return fmt.Errorf("go/parser: ParseExpr must pass []byte(%s) to ParseExprFrom", xParam)
	}
	if _, okArg := isIdentNamed(srcConv.Args[0], xParam); !okArg {
		return fmt.Errorf("go/parser: ParseExpr []byte conversion must wrap parameter %s", xParam)
	}
	modeLit, okMode := unwrapParens(call.Args[3]).(*ast.BasicLit)
	if !okMode || modeLit.Kind != token.INT || modeLit.Value != "0" {
		return fmt.Errorf("go/parser: ParseExpr must pass mode 0 to ParseExprFrom")
	}

	for _, name := range []string{"ParseFile", "ParseExprFrom", "ParseDir"} {
		fn := idx.topFuncs[name]
		if idx.pkgDeclCounts[name] != 1 || idx.dupTopFuncs[name] || fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil ||
			funcShadowsAnyIdent(fn, goParserReservedIdents) || fn.Type.Params == nil || fn.Type.Params.NumFields() != 4 {
			return fmt.Errorf("go/parser: missing or invalid %s declaration", name)
		}
		if name == "ParseFile" || name == "ParseExprFrom" {
			srcP := paramIdentAt(fn.Type.Params, 2)
			modeP := paramIdentAt(fn.Type.Params, 3)
			if srcP == "" || modeP == "" || bodyMutatesOrTakesAddrOfAny(fn.Body, map[string]bool{srcP: true, modeP: true}) {
				return fmt.Errorf("go/parser: %s must have immutable src and mode parameters", name)
			}
			sawReadSource, sawInit := false, false
			readSourceIdents, readSourceCalls := 0, 0
			initSels, initCalls := 0, 0
			var callErr error
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if callErr != nil || n == nil {
					return false
				}
				switch node := n.(type) {
				case *ast.Ident:
					if node.Name == "readSource" {
						readSourceIdents++
					}
				case *ast.SelectorExpr:
					if node.Sel != nil && node.Sel.Name == "init" {
						initSels++
					}
				case *ast.CallExpr:
					if _, isRS := isIdentNamed(node.Fun, "readSource"); isRS {
						if node.Ellipsis.IsValid() || len(node.Args) != 2 {
							callErr = fmt.Errorf("go/parser: invalid readSource call arity in %s", name)
							return false
						}
						if _, okArg := isIdentNamed(node.Args[1], srcP); !okArg {
							callErr = fmt.Errorf("go/parser: readSource in %s must forward %s", name, srcP)
							return false
						}
						sawReadSource = true
						readSourceCalls++
					} else if sel, isSel := unwrapParens(node.Fun).(*ast.SelectorExpr); isSel && sel.Sel != nil && sel.Sel.Name == "init" {
						if node.Ellipsis.IsValid() || len(node.Args) != 3 {
							callErr = fmt.Errorf("go/parser: invalid .init call arity in %s", name)
							return false
						}
						if _, okArg := isIdentNamed(node.Args[2], modeP); !okArg {
							callErr = fmt.Errorf("go/parser: .init in %s must forward %s", name, modeP)
							return false
						}
						sawInit = true
						initCalls++
					}
				}
				return true
			})
			if callErr != nil {
				return callErr
			}
			if !sawReadSource || !sawInit || readSourceIdents != readSourceCalls || initSels != initCalls {
				return fmt.Errorf("go/parser: %s must call readSource(_, %s) and p.init(_, _, %s) without aliasing", name, srcP, modeP)
			}
		}
	}
	return nil
}

func verifyGoParserTraceFieldAssignment(idx *PackageASTIndex, files []*ast.File) (*ast.AssignStmt, error) {
	initFn, _, ok := idx.VerifyFuncPreamble("parser", "init", true, goParserReservedIdents)
	if !ok || initFn.Type.Params == nil || initFn.Type.Params.NumFields() != 3 {
		return nil, fmt.Errorf("go/parser: missing or invalid (*parser).init")
	}
	recvVar := recvVarName(initFn)
	modeParam := paramIdentAt(initFn.Type.Params, 2)
	if recvVar == "" || modeParam == "" {
		return nil, fmt.Errorf("go/parser: unnamed receiver or mode parameter on (*parser).init")
	}
	var allowedAssign *ast.AssignStmt
	for _, st := range initFn.Body.List {
		as, ok := st.(*ast.AssignStmt)
		if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		if _, okSel := isSelectorBaseField(as.Lhs[0], recvVar, "trace"); !okSel {
			continue
		}
		if !isModeBitNonZeroExpr(as.Rhs[0], modeParam, "Trace") {
			return nil, fmt.Errorf("go/parser: (*parser).init assigns unapproved expression to %s.trace", recvVar)
		}
		if allowedAssign != nil {
			return nil, fmt.Errorf("go/parser: duplicate %s.trace assignment in (*parser).init", recvVar)
		}
		allowedAssign = as
	}
	if allowedAssign == nil {
		return nil, fmt.Errorf("go/parser: missing %s.trace = %s&Trace != 0 in (*parser).init", recvVar, modeParam)
	}

	for _, f := range files {
		bad := false
		ast.Inspect(f, func(n ast.Node) bool {
			if bad || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.AssignStmt:
				if node == allowedAssign {
					return true
				}
				for _, lhs := range node.Lhs {
					if sel, ok := unwrapParens(lhs).(*ast.SelectorExpr); ok && sel.Sel.Name == "trace" {
						bad = true
						return false
					}
				}
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					if sel, ok := unwrapParens(node.X).(*ast.SelectorExpr); ok && sel.Sel.Name == "trace" {
						bad = true
						return false
					}
				}
			case *ast.KeyValueExpr:
				if id, ok := unwrapParens(node.Key).(*ast.Ident); ok && id.Name == "trace" {
					bad = true
					return false
				}
			}
			return true
		})
		if bad {
			return nil, fmt.Errorf("go/parser: forbidden mutation or initialization of .trace outside (*parser).init")
		}
	}
	return allowedAssign, nil
}

func verifyGoParserFuncBody(fn *ast.FuncDecl, kernel *PackageInactiveKernel) error {
	recvType := ""
	if fn.Recv != nil && len(fn.Recv.List) == 1 {
		recvType = recvTypeName(fn.Recv.List[0].Type)
	}
	fnKey := fn.Name.Name
	if recvType != "" {
		fnKey = recvType + "." + fn.Name.Name
	}
	isReadSource := fnKey == "readSource"
	isParseDir := fnKey == "ParseDir"
	isSourceEntry := fnKey == "ParseFile" || fnKey == "ParseExprFrom"
	isTraceSink := fnKey == "parser.printTrace" || fnKey == "trace" || fnKey == "un" || fnKey == "resolver.trace"

	prunedStmts, _ := kernel.PruneBlockStmts(fn.Body.List, fn, nil, nil, nil)
	prunedBody := &ast.BlockStmt{List: prunedStmts}

	if !isSourceEntry {
		badInit := false
		ast.Inspect(prunedBody, func(n ast.Node) bool {
			if badInit || n == nil {
				return false
			}
			if sel, isSel := n.(*ast.SelectorExpr); isSel && sel.Sel != nil && sel.Sel.Name == "init" {
				// Allow s.scanner.Init(...) (capital Init), forbid parser (*parser).init outside ParseFile/ParseExprFrom.
				badInit = true
				return false
			}
			return true
		})
		if badInit {
			return fmt.Errorf("go/parser: forbidden .init reference outside ParseFile/ParseExprFrom in %s", fnKey)
		}
	}

	var qErr error
	WalkLexicalAST(prunedBody, funcInitialLexicalScope(fn),
		func(ident string) {
			if qErr != nil {
				return
			}
			if ident == "ParseDir" {
				qErr = fmt.Errorf("go/parser: forbidden internal call to ParseDir in %s", fnKey)
			}
			if ident == "readSource" && !isSourceEntry {
				qErr = fmt.Errorf("go/parser: forbidden call to readSource in %s", fnKey)
			}
		},
		nil,
		func(base, sel string) {
			if qErr != nil {
				return
			}
			switch base {
			case "os":
				if isReadSource && sel == "ReadFile" {
					return
				}
				if isParseDir && sel == "ReadDir" {
					return
				}
				qErr = fmt.Errorf("go/parser: forbidden os.%s in %s", sel, fnKey)
			case "fs":
				if !isParseDir || sel != "FileInfo" {
					qErr = fmt.Errorf("go/parser: forbidden fs.%s in %s", sel, fnKey)
				}
			case "filepath":
				if !auditset.Symbol("path/filepath", sel) {
					qErr = fmt.Errorf("go/parser: forbidden filepath.%s in %s", sel, fnKey)
				}
			case "io":
				if !isReadSource || (sel != "Reader" && sel != "ReadAll") {
					qErr = fmt.Errorf("go/parser: forbidden io.%s in %s", sel, fnKey)
				}
			case "fmt":
				if isTraceSink && (sel == "Print" || sel == "Printf" || sel == "Println") {
					return
				}
				if !auditset.Symbol("fmt", sel) {
					qErr = fmt.Errorf("go/parser: forbidden fmt.%s in %s", sel, fnKey)
				}
			case "ast":
				if sel == "Print" || sel == "Fprint" || sel == "NotNilFilter" {
					qErr = fmt.Errorf("go/parser: forbidden ast.%s in %s", sel, fnKey)
				}
			case "scanner":
				if !auditset.Symbol("go/scanner", sel) {
					qErr = fmt.Errorf("go/parser: forbidden scanner.%s in %s", sel, fnKey)
				}
			case "token":
				if !auditset.Symbol("go/token", sel) {
					qErr = fmt.Errorf("go/parser: forbidden token.%s in %s", sel, fnKey)
				}
			case "bytes", "errors", "constraint", "strings":
			default:
				qErr = fmt.Errorf("go/parser: unapproved qualified reference %s.%s in %s", base, sel, fnKey)
			}
		},
	)
	if qErr != nil {
		return qErr
	}
	if isTraceSink {
		return nil
	}
	parserRecv := ""
	if recvType == "parser" {
		parserRecv = recvVarName(fn)
	}
	return verifyTraceCallsGated(fnKey, fn, prunedBody, kernel, parserRecv, fnKey == "parser.init")
}

func verifyTraceCallsGated(fnKey string, fn *ast.FuncDecl, body *ast.BlockStmt, kernel *PackageInactiveKernel, parserRecv string, allowInitFieldAssign bool) error {
	var traceErr error
	var walk func(n ast.Node, guarded bool)
	walk = func(n ast.Node, guarded bool) {
		if traceErr != nil || n == nil {
			return
		}
		switch x := n.(type) {
		case *ast.FuncLit:
			walk(x.Body, false)
			return
		case *ast.IfStmt:
			if x.Init != nil {
				walk(x.Init, guarded)
			}
			if x.Init == nil {
				if _, isFalse := kernel.EvalFalseExpr(x.Cond, fn, nil); isFalse {
					if x.Else != nil {
						walk(x.Else, guarded)
					}
					return
				}
			}
			condGuarded := guarded || (parserRecv != "" && condRequiresFieldTrue(x.Cond, parserRecv, "trace"))
			if !condGuarded {
				walk(x.Cond, guarded)
			}
			walk(x.Body, condGuarded)
			if x.Else != nil {
				walk(x.Else, guarded)
			}
			return
		case *ast.AssignStmt:
			if allowInitFieldAssign && len(x.Lhs) == 1 {
				if _, ok := isSelectorBaseField(x.Lhs[0], parserRecv, "trace"); ok {
					for _, rhs := range x.Rhs {
						walk(rhs, guarded)
					}
					return
				}
			}
		case *ast.Ident:
			if !guarded && (x.Name == "trace" || x.Name == "un" || x.Name == "printTrace") {
				traceErr = fmt.Errorf("go/parser: unguarded %s reference in %s", x.Name, fnKey)
				return
			}
		case *ast.SelectorExpr:
			if x.Sel != nil && !guarded && (x.Sel.Name == "printTrace" || x.Sel.Name == "trace") {
				traceErr = fmt.Errorf("go/parser: unguarded .%s reference in %s", x.Sel.Name, fnKey)
				return
			}
		}
		ast.Inspect(n, func(ch ast.Node) bool {
			if ch == nil || ch == n {
				return true
			}
			walk(ch, guarded)
			return false
		})
	}
	walk(body, false)
	return traceErr
}

func condRequiresFieldTrue(cond ast.Expr, baseIdent, field string) bool {
	switch c := unwrapParens(cond).(type) {
	case *ast.SelectorExpr:
		_, ok := isSelectorBaseField(c, baseIdent, field)
		return ok
	case *ast.BinaryExpr:
		return c.Op == token.LAND && (condRequiresFieldTrue(c.X, baseIdent, field) || condRequiresFieldTrue(c.Y, baseIdent, field))
	default:
		return false
	}
}

func isModeBitNonZeroExpr(expr ast.Expr, modeIdent, bitIdent string) bool {
	be, ok := unwrapParens(expr).(*ast.BinaryExpr)
	if !ok || be.Op != token.NEQ {
		return false
	}
	lit, okLit := unwrapParens(be.Y).(*ast.BasicLit)
	if !okLit || lit.Kind != token.INT || lit.Value != "0" {
		return false
	}
	andExpr, okAnd := unwrapParens(be.X).(*ast.BinaryExpr)
	if !okAnd || andExpr.Op != token.AND {
		return false
	}
	_, okM := isIdentNamed(andExpr.X, modeIdent)
	_, okB := isIdentNamed(andExpr.Y, bitIdent)
	return okM && okB
}

func isIdentNonNilCond(expr ast.Expr, ident string) bool {
	be, ok := unwrapParens(expr).(*ast.BinaryExpr)
	if !ok || be.Op != token.NEQ {
		return false
	}
	_, okX := isIdentNamed(be.X, ident)
	_, okNil := isIdentNamed(be.Y, "nil")
	return okX && okNil
}


func isTokenBoolMapLit(expr ast.Expr) bool {
	cl, ok := unwrapParens(expr).(*ast.CompositeLit)
	if !ok {
		return false
	}
	mt, ok := unwrapParens(cl.Type).(*ast.MapType)
	if !ok {
		return false
	}
	if _, okK := isSelectorBaseField(mt.Key, "token", "Token"); !okK {
		return false
	}
	if _, okV := isIdentNamed(mt.Value, "bool"); !okV {
		return false
	}
	for _, elt := range cl.Elts {
		kv, okKV := unwrapParens(elt).(*ast.KeyValueExpr)
		if !okKV {
			return false
		}
		sel, okSel := unwrapParens(kv.Key).(*ast.SelectorExpr)
		if !okSel {
			return false
		}
		if _, okTok := isIdentNamed(sel.X, "token"); !okTok {
			return false
		}
		vID, okVal := unwrapParens(kv.Value).(*ast.Ident)
		if !okVal || (vID.Name != "true" && vID.Name != "false") {
			return false
		}
	}
	return true
}

func isNewASTObjectCall(expr ast.Expr) bool {
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	if _, okNew := isIdentNamed(call.Fun, "new"); !okNew {
		return false
	}
	_, okObj := isSelectorBaseField(call.Args[0], "ast", "Object")
	return okObj
}
