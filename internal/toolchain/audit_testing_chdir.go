package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
)

// verifyTestingChdirAST verifies package testing's Chdir, Setenv, and LIFO
// Cleanup contracts in standalone unit tests without external runtime gates.
func verifyTestingChdirAST(files []*ast.File) error {
	idx, err := indexPackageAST("testing", files, nil, map[string]bool{"os": true})
	if err != nil {
		return err
	}
	k := newPackageInactiveKernel(idx, files, nil, nil)
	reqGates := map[string]bool{}
	if err := verifyTestingChdirSetenvCleanup(idx, files, k, reqGates); err != nil {
		return err
	}
	if len(reqGates) > 0 {
		return fmt.Errorf("testing: Chdir/Setenv/Cleanup requires cross-package runtime gate verification %v", sortedKeys(reqGates))
	}
	return nil
}

func verifyTestingChdirSetenvCleanup(idx *packageASTIndex, files []*ast.File, k *packageInactiveKernel, reqGates map[string]bool) error {
	commonMethods := idx.typeMethods["common"]
	tMethods := idx.typeMethods["T"]
	if commonMethods == nil || tMethods == nil {
		return fmt.Errorf("testing: missing common or T method table for Chdir/Setenv/Cleanup")
	}

	cleanupsField, err := verifyTestingCommonCleanup(idx, files, commonMethods["Cleanup"], commonMethods["runCleanup"], k, reqGates)
	if err != nil {
		return err
	}
	_ = cleanupsField

	if err := verifyTestingCommonSetenv(idx, commonMethods["Setenv"], k, reqGates); err != nil {
		return err
	}
	if err := verifyTestingCommonChdir(idx, commonMethods["Chdir"], k, reqGates); err != nil {
		return err
	}
	if err := verifyTestingWrapperChdir("T", tMethods["Chdir"], true, k, reqGates); err != nil {
		return err
	}
	for _, rType := range []string{"B", "F"} {
		if m := idx.typeMethods[rType]; m != nil && m["Chdir"] != nil {
			if err := verifyTestingWrapperChdir(rType, m["Chdir"], false, k, reqGates); err != nil {
				return err
			}
		}
	}
	if tMethods["Setenv"] != nil {
		if err := verifyTestingWrapperSetenv("T", tMethods["Setenv"], k, reqGates); err != nil {
			return err
		}
	}
	if cpFn := idx.topFuncs["checkParallel"]; cpFn != nil {
		cpParams := paramNamesFlat(cpFn.Type.Params)
		if cpFn.Body == nil || cpFn.Type == nil || len(cpParams) != 1 || cpParams[0] == "" || cpParams[0] == "_" ||
			(cpFn.Type.Results != nil && cpFn.Type.Results.NumFields() != 0) ||
			bodyHasControlFlowOrRecoverBypass(cpFn.Body) || len(cpFn.Body.List) != 1 {
			return fmt.Errorf("testing: invalid top-level checkParallel wrapper")
		}
		starT, okStar := unwrapParens(cpFn.Type.Params.List[0].Type).(*ast.StarExpr)
		_, okT := false, false
		if okStar {
			_, okT = isIdentNamed(starT.X, "T")
		}
		es, okES := cpFn.Body.List[0].(*ast.ExprStmt)
		var delegOK bool
		if okT && okES {
			if c, okC := unwrapParens(es.X).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 0 {
				_, delegOK = isSelectorBaseField(c.Fun, cpParams[0], "checkParallel")
			}
		}
		if !delegOK {
			return fmt.Errorf("testing: top-level checkParallel must delegate directly to (*T).checkParallel")
		}
	}
	return nil
}

func verifyTestingCommonCleanup(idx *packageASTIndex, files []*ast.File, cleanupFn, runCleanupFn *ast.FuncDecl, k *packageInactiveKernel, reqGates map[string]bool) (string, error) {
	reserved := map[string]bool{"append": true, "len": true, "nil": true, "recover": true}
	if cleanupFn == nil || cleanupFn.Body == nil || cleanupFn.Type == nil || cleanupFn.Type.Params == nil || cleanupFn.Type.Params.NumFields() != 1 || (cleanupFn.Type.Results != nil && cleanupFn.Type.Results.NumFields() != 0) || funcShadowsAnyIdent(cleanupFn, reserved) || bodyHasControlFlowOrRecoverBypass(cleanupFn.Body) {
		return "", fmt.Errorf("testing: missing or invalid (*common).Cleanup")
	}
	cRecv := recvVarName(cleanupFn)
	pNames := paramNamesFlat(cleanupFn.Type.Params)
	if cRecv == "" || len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || pNames[0] == cRecv {
		return "", fmt.Errorf("testing: invalid (*common).Cleanup receiver or parameter")
	}
	if ft, ok := unwrapParens(cleanupFn.Type.Params.List[0].Type).(*ast.FuncType); !ok || (ft.Params != nil && ft.Params.NumFields() != 0) || (ft.Results != nil && ft.Results.NumFields() != 0) {
		return "", fmt.Errorf("testing: (*common).Cleanup parameter is not func()")
	}
	fParam := pNames[0]
	if bodyMutatesOrTakesAddrOfAny(cleanupFn.Body, map[string]bool{cRecv: true, fParam: true}) {
		return "", fmt.Errorf("testing: (*common).Cleanup mutates receiver or callback parameter")
	}

	stmts, _ := k.pruneBlockStmts(cleanupFn.Body.List, cleanupFn, map[string]bool{cRecv: true, "append": true}, reqGates, nil)
	flatCleanupStmts, okFlat := flattenStraightLineTestingStmts(stmts)
	if !okFlat || funcShadowsAnyIdent(cleanupFn, map[string]bool{"append": true}) {
		return "", fmt.Errorf("testing: (*common).Cleanup must execute in straight-line control flow")
	}
	approvedCleanupsSels := map[*ast.SelectorExpr]bool{}
	wrappedFnVars := map[string]bool{fParam: true}
	var cleanupsField string
	var appendAssign *ast.AssignStmt
	for _, st := range flatCleanupStmts {
		as, ok := st.(*ast.AssignStmt)
		if !ok {
			continue
		}
		if len(as.Lhs) == 1 && len(as.Rhs) == 1 && as.Tok == token.DEFINE {
			if lhsID, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && lhsID.Name != "" && lhsID.Name != "_" {
				if fl, okFL := unwrapParens(as.Rhs[0]).(*ast.FuncLit); okFL && fl.Body != nil && !bodyHasControlFlowOrRecoverBypass(fl.Body) &&
					!bodyMutatesOrTakesAddrOfAny(fl.Body, map[string]bool{fParam: true}) && !bodyDeclaresAnyIdent(fl.Body, map[string]bool{fParam: true}) {
					flPruned, _ := k.pruneBlockStmts(fl.Body.List, nil, nil, reqGates, nil)
					flFlat, okFLFlat := flattenStraightLineTestingStmts(flPruned)
					if okFLFlat {
						calledF := false
						for _, bs := range flFlat {
							if es, okES := bs.(*ast.ExprStmt); okES {
								if c, okC := unwrapParens(es.X).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 0 {
									if _, okFID := isIdentNamed(c.Fun, fParam); okFID {
										calledF = true
									}
								}
							}
						}
						if calledF {
							wrappedFnVars[lhsID.Name] = true
							continue
						}
					}
				}
			}
		}
		if len(as.Lhs) == 1 && len(as.Rhs) == 1 && as.Tok == token.ASSIGN {
			if lhsSel, okL := unwrapParens(as.Lhs[0]).(*ast.SelectorExpr); okL {
				if _, okBase := isIdentNamed(lhsSel.X, cRecv); okBase {
					appCall, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
					if okC && !appCall.Ellipsis.IsValid() && len(appCall.Args) == 2 {
						_, okApp := isIdentNamed(appCall.Fun, "append")
						_, okArg0 := isSelectorBaseField(appCall.Args[0], cRecv, lhsSel.Sel.Name)
						arg0Sel, _ := unwrapParens(appCall.Args[0]).(*ast.SelectorExpr)
						arg1ID, okArg1 := unwrapParens(appCall.Args[1]).(*ast.Ident)
						if okApp && okArg0 && arg0Sel != nil && okArg1 && wrappedFnVars[arg1ID.Name] && appendAssign == nil {
							cleanupsField = lhsSel.Sel.Name
							appendAssign = as
							approvedCleanupsSels[lhsSel] = true
							approvedCleanupsSels[arg0Sel] = true
							continue
						}
					}
				}
			}
		}
		for _, lhs := range as.Lhs {
			if lhsID, okID := unwrapParens(lhs).(*ast.Ident); okID {
				delete(wrappedFnVars, lhsID.Name)
			}
		}
	}
	if cleanupsField == "" || appendAssign == nil {
		return "", fmt.Errorf("testing: (*common).Cleanup does not append callback to cleanups slice")
	}

	// Verify (*common).runCleanup drains cleanups via an unconditional LIFO loop.
	if runCleanupFn == nil || runCleanupFn.Body == nil || recvVarName(runCleanupFn) == "" || funcShadowsAnyIdent(runCleanupFn, map[string]bool{"len": true, "nil": true}) {
		return "", fmt.Errorf("testing: missing or invalid (*common).runCleanup")
	}
	rcRecv := recvVarName(runCleanupFn)
	rcStmts, _ := k.pruneBlockStmts(runCleanupFn.Body.List, runCleanupFn, map[string]bool{rcRecv: true}, reqGates, nil)
	if len(rcStmts) == 0 {
		return "", fmt.Errorf("testing: empty (*common).runCleanup")
	}
	for _, pre := range rcStmts[:len(rcStmts)-1] {
		if testingStmtMayExitOrLoop(pre) {
			return "", fmt.Errorf("testing: (*common).runCleanup may exit before draining loop")
		}
	}
	drainLoop, okLoop := rcStmts[len(rcStmts)-1].(*ast.ForStmt)
	if !okLoop || drainLoop.Init != nil || drainLoop.Post != nil || drainLoop.Body == nil {
		return "", fmt.Errorf("testing: (*common).runCleanup must end with unconditional draining loop")
	}
	truncAssign, okDrain := verifyTestingRunCleanupDrainLoop(k, runCleanupFn, rcRecv, cleanupsField, drainLoop, reqGates, approvedCleanupsSels)
	if !okDrain || truncAssign == nil {
		return "", fmt.Errorf("testing: (*common).runCleanup does not execute %s.%s in LIFO order", rcRecv, cleanupsField)
	}
	if !verifyTestingCleanupsFieldConfined(files, cleanupsField, approvedCleanupsSels) {
		return "", fmt.Errorf("testing: unapproved mutation or address-of on .%s field", cleanupsField)
	}
	return cleanupsField, nil
}

func verifyTestingRunCleanupDrainLoop(
	k *packageInactiveKernel,
	fn *ast.FuncDecl,
	rcRecv, cleanupsField string,
	drainLoop *ast.ForStmt,
	reqGates map[string]bool,
	approvedCleanupsSels map[*ast.SelectorExpr]bool,
) (*ast.AssignStmt, bool) {
	loopStmts, _ := k.pruneBlockStmts(drainLoop.Body.List, fn, map[string]bool{rcRecv: true}, reqGates, nil)
	isLastIdxExpr := func(e ast.Expr, lastVars map[string]bool) bool {
		e = unwrapParens(e)
		if id, ok := e.(*ast.Ident); ok && lastVars[id.Name] {
			return true
		}
		bin, ok := e.(*ast.BinaryExpr)
		if !ok || bin.Op != token.SUB {
			return false
		}
		lit1, ok1 := unwrapParens(bin.Y).(*ast.BasicLit)
		lc, okLC := unwrapParens(bin.X).(*ast.CallExpr)
		if !ok1 || lit1.Kind != token.INT || lit1.Value != "1" || !okLC || lc.Ellipsis.IsValid() || len(lc.Args) != 1 {
			return false
		}
		_, okLen := isIdentNamed(lc.Fun, "len")
		_, okField := isSelectorBaseField(lc.Args[0], rcRecv, cleanupsField)
		return okLen && okField
	}
	isLenPositiveCond := func(e ast.Expr) bool {
		bin, ok := unwrapParens(e).(*ast.BinaryExpr)
		if !ok || bin.Op != token.GTR || !isZeroIntLit(bin.Y) {
			return false
		}
		lc, okLC := unwrapParens(bin.X).(*ast.CallExpr)
		if !okLC || lc.Ellipsis.IsValid() || len(lc.Args) != 1 {
			return false
		}
		_, okLen := isIdentNamed(lc.Fun, "len")
		_, okField := isSelectorBaseField(lc.Args[0], rcRecv, cleanupsField)
		return okLen && okField
	}

	if drainLoop.Cond != nil {
		if !isLenPositiveCond(drainLoop.Cond) {
			return nil, false
		}
		flat, okFlat := flattenStraightLineTestingStmts(loopStmts)
		if !okFlat {
			return nil, false
		}
		lastVars := map[string]bool{}
		var cleanupVar string
		var popAssign, truncAssign *ast.AssignStmt
		var invoked bool
		for _, st := range flat {
			switch s := st.(type) {
			case *ast.AssignStmt:
				if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
					return nil, false
				}
				if lhsID, okL := unwrapParens(s.Lhs[0]).(*ast.Ident); okL && s.Tok == token.DEFINE {
					if lhsID.Name != cleanupVar && !lastVars[lhsID.Name] && isLastIdxExpr(s.Rhs[0], nil) {
						lastVars[lhsID.Name] = true
						continue
					}
					if ix, okIX := unwrapParens(s.Rhs[0]).(*ast.IndexExpr); okIX && cleanupVar == "" && !lastVars[lhsID.Name] {
						if _, okF := isSelectorBaseField(ix.X, rcRecv, cleanupsField); okF && isLastIdxExpr(ix.Index, lastVars) {
							if popSel, okPS := unwrapParens(ix.X).(*ast.SelectorExpr); okPS {
								approvedCleanupsSels[popSel] = true
								cleanupVar = lhsID.Name
								popAssign = s
								continue
							}
						}
					}
				}
				if s.Tok == token.ASSIGN && truncAssign == nil {
					if _, okLHS := isSelectorBaseField(s.Lhs[0], rcRecv, cleanupsField); okLHS {
						if sl, okS := unwrapParens(s.Rhs[0]).(*ast.SliceExpr); okS && !sl.Slice3 && sl.Low == nil && sl.High != nil {
							if _, okBase := isSelectorBaseField(sl.X, rcRecv, cleanupsField); okBase && isLastIdxExpr(sl.High, lastVars) {
								lhsSel, _ := unwrapParens(s.Lhs[0]).(*ast.SelectorExpr)
								baseSel, _ := unwrapParens(sl.X).(*ast.SelectorExpr)
								if lhsSel != nil && baseSel != nil {
									approvedCleanupsSels[lhsSel] = true
									approvedCleanupsSels[baseSel] = true
									truncAssign = s
									continue
								}
							}
						}
					}
				}
				return nil, false
			case *ast.ExprStmt:
				if c, okC := unwrapParens(s.X).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 0 && cleanupVar != "" && truncAssign != nil {
					if _, okID := isIdentNamed(c.Fun, cleanupVar); okID {
						invoked = true
						continue
					}
				}
				return nil, false
			default:
				return nil, false
			}
		}
		if cleanupVar == "" || popAssign == nil || truncAssign == nil || !invoked || !testingCleanupVarOnlyAssignedAt(drainLoop.Body, cleanupVar, popAssign) {
			return nil, false
		}
		return truncAssign, true
	}

	var cleanupVar string
	var popAssign, truncAssign *ast.AssignStmt
	var sawPopIf, sawNilExitIf, sawInvokeAfterExit bool
	for _, st := range loopStmts {
		switch s := st.(type) {
		case *ast.DeclStmt:
			gd, okG := s.Decl.(*ast.GenDecl)
			if !okG || gd.Tok != token.VAR || len(gd.Specs) != 1 {
				return nil, false
			}
			vs, okV := gd.Specs[0].(*ast.ValueSpec)
			if !okV || len(vs.Names) != 1 || len(vs.Values) != 0 || cleanupVar != "" {
				return nil, false
			}
			cleanupVar = vs.Names[0].Name
		case *ast.IfStmt:
			if s.Init != nil || s.Else != nil {
				return nil, false
			}
			if cleanupVar != "" && !sawPopIf && isLenPositiveCond(s.Cond) {
				popFlat, okFlat := flattenStraightLineTestingStmts(s.Body.List)
				if !okFlat {
					return nil, false
				}
				lastVars := map[string]bool{}
				var gotPop, gotTrunc bool
				for _, ps := range popFlat {
					as, okA := ps.(*ast.AssignStmt)
					if !okA || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
						return nil, false
					}
					if lhsID, okL := unwrapParens(as.Lhs[0]).(*ast.Ident); okL {
						if as.Tok == token.DEFINE && lhsID.Name != cleanupVar && isLastIdxExpr(as.Rhs[0], nil) {
							lastVars[lhsID.Name] = true
							continue
						}
						if as.Tok == token.ASSIGN && lhsID.Name == cleanupVar && popAssign == nil {
							if ix, okIX := unwrapParens(as.Rhs[0]).(*ast.IndexExpr); okIX {
								if _, okF := isSelectorBaseField(ix.X, rcRecv, cleanupsField); okF && isLastIdxExpr(ix.Index, lastVars) {
									if popSel, okPS := unwrapParens(ix.X).(*ast.SelectorExpr); okPS {
										approvedCleanupsSels[popSel] = true
										gotPop = true
										popAssign = as
										continue
									}
								}
							}
						}
					}
					if as.Tok == token.ASSIGN && truncAssign == nil {
						if _, okLHS := isSelectorBaseField(as.Lhs[0], rcRecv, cleanupsField); okLHS {
							if sl, okS := unwrapParens(as.Rhs[0]).(*ast.SliceExpr); okS && !sl.Slice3 && sl.Low == nil && sl.High != nil {
								if _, okBase := isSelectorBaseField(sl.X, rcRecv, cleanupsField); okBase && isLastIdxExpr(sl.High, lastVars) {
									lhsSel, _ := unwrapParens(as.Lhs[0]).(*ast.SelectorExpr)
									baseSel, _ := unwrapParens(sl.X).(*ast.SelectorExpr)
									if lhsSel != nil && baseSel != nil {
										approvedCleanupsSels[lhsSel] = true
										approvedCleanupsSels[baseSel] = true
										gotTrunc = true
										truncAssign = as
										continue
									}
								}
							}
						}
					}
					return nil, false
				}
				if !gotPop || !gotTrunc {
					return nil, false
				}
				sawPopIf = true
				continue
			}
			if sawPopIf && !sawNilExitIf && condChecksEqErr(s.Cond, cleanupVar) && len(s.Body.List) == 1 {
				if _, okR := s.Body.List[0].(*ast.ReturnStmt); okR {
					sawNilExitIf = true
					continue
				}
			}
			return nil, false
		case *ast.ExprStmt:
			if testingStmtMayExitOrLoop(s) {
				return nil, false
			}
			if c, okC := unwrapParens(s.X).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 0 {
				if _, okID := isIdentNamed(c.Fun, cleanupVar); okID {
					if !sawNilExitIf {
						return nil, false
					}
					sawInvokeAfterExit = true
					continue
				}
			}
		case *ast.EmptyStmt:
			continue
		default:
			return nil, false
		}
	}
	if !sawPopIf || !sawNilExitIf || !sawInvokeAfterExit || popAssign == nil || truncAssign == nil || !testingCleanupVarOnlyAssignedAt(drainLoop.Body, cleanupVar, popAssign) {
		return nil, false
	}
	return truncAssign, true
}

func isTestingCheckHelperStmt(st ast.Stmt, recv string) bool {
	es, ok := st.(*ast.ExprStmt)
	if !ok {
		return false
	}
	c, ok := unwrapParens(es.X).(*ast.CallExpr)
	if !ok || c.Ellipsis.IsValid() {
		return false
	}
	sel, ok := unwrapParens(c.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if _, okR := isIdentNamed(sel.X, recv); !okR {
		return false
	}
	switch sel.Sel.Name {
	case "checkFuzzFn":
		return len(c.Args) == 1
	case "checkParallel":
		return len(c.Args) == 0
	}
	return false
}

func isTestingFatalErrIf(ifs *ast.IfStmt, recv, errVar string) bool {
	if ifs == nil || ifs.Else != nil || condChecksNonZeroErr(ifs.Cond) != errVar || len(ifs.Body.List) != 1 {
		return false
	}
	es, ok := ifs.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	c, ok := unwrapParens(es.X).(*ast.CallExpr)
	if !ok || c.Ellipsis.IsValid() || len(c.Args) == 0 {
		return false
	}
	sel, ok := unwrapParens(c.Fun).(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Fatal" && sel.Sel.Name != "Fatalf") {
		return false
	}
	_, okR := isIdentNamed(sel.X, recv)
	return okR
}

func verifyTestingCommonSetenv(idx *packageASTIndex, fn *ast.FuncDecl, k *packageInactiveKernel, reqGates map[string]bool) error {
	reserved := map[string]bool{"os": true, "string": true, "nil": true}
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.Params == nil || fn.Type.Params.NumFields() != 2 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) || funcShadowsAnyIdent(fn, reserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return fmt.Errorf("testing: missing or invalid (*common).Setenv")
	}
	if k.fileImportPath(idx.funcFile[fn], "os") != "os" {
		return fmt.Errorf("testing: (*common).Setenv file missing unaliased os import")
	}
	recv := recvVarName(fn)
	pNames := paramNamesFlat(fn.Type.Params)
	if recv == "" || len(pNames) != 2 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || pNames[0] == pNames[1] {
		return fmt.Errorf("testing: (*common).Setenv invalid parameters")
	}
	for _, fld := range fn.Type.Params.List {
		if _, ok := isIdentNamed(fld.Type, "string"); !ok {
			return fmt.Errorf("testing: (*common).Setenv parameter type is not string")
		}
	}
	keyParam, valParam := pNames[0], pNames[1]
	if bodyMutatesOrTakesAddrOfAny(fn.Body, map[string]bool{recv: true, keyParam: true, valParam: true}) {
		return fmt.Errorf("testing: (*common).Setenv mutates receiver or key/value parameters")
	}

	stmts, _ := k.pruneBlockStmts(fn.Body.List, fn, map[string]bool{recv: true, keyParam: true, valParam: true}, reqGates, nil)
	pos := 0
	for pos < len(stmts) && isTestingCheckHelperStmt(stmts[pos], recv) {
		pos++
	}
	if len(stmts)-pos != 3 {
		return fmt.Errorf("testing: (*common).Setenv unexpected statement count")
	}

	// 1. prevValue, ok := os.LookupEnv(key)
	luAs, okLA := stmts[pos].(*ast.AssignStmt)
	if !okLA || luAs.Tok != token.DEFINE || len(luAs.Lhs) != 2 || len(luAs.Rhs) != 1 {
		return fmt.Errorf("testing: (*common).Setenv missing os.LookupEnv assignment")
	}
	prevID, okP := unwrapParens(luAs.Lhs[0]).(*ast.Ident)
	okID, okO := unwrapParens(luAs.Lhs[1]).(*ast.Ident)
	luCall, okLC := unwrapParens(luAs.Rhs[0]).(*ast.CallExpr)
	if !okP || !okO || !okLC || prevID.Name == "" || prevID.Name == "_" || okID.Name == "" || okID.Name == "_" || prevID.Name == okID.Name || luCall.Ellipsis.IsValid() || len(luCall.Args) != 1 {
		return fmt.Errorf("testing: (*common).Setenv invalid os.LookupEnv call")
	}
	_, okLUSel := isSelectorBaseField(luCall.Fun, "os", "LookupEnv")
	_, okLUKey := isIdentNamed(luCall.Args[0], keyParam)
	if !okLUSel || !okLUKey {
		return fmt.Errorf("testing: (*common).Setenv does not call os.LookupEnv(%s)", keyParam)
	}

	// 2. if err := os.Setenv(key, value); err != nil { c.Fatalf(...) }
	setIf, okSI := stmts[pos+1].(*ast.IfStmt)
	if !okSI || setIf.Init == nil {
		return fmt.Errorf("testing: (*common).Setenv missing os.Setenv error guard")
	}
	setInit, okSIn := setIf.Init.(*ast.AssignStmt)
	if !okSIn || setInit.Tok != token.DEFINE || len(setInit.Lhs) != 1 || len(setInit.Rhs) != 1 {
		return fmt.Errorf("testing: (*common).Setenv invalid os.Setenv init")
	}
	errID, okE := unwrapParens(setInit.Lhs[0]).(*ast.Ident)
	setCall, okSC := unwrapParens(setInit.Rhs[0]).(*ast.CallExpr)
	if !okE || !okSC || errID.Name == "" || errID.Name == "_" || !isTestingFatalErrIf(setIf, recv, errID.Name) || setCall.Ellipsis.IsValid() || len(setCall.Args) != 2 {
		return fmt.Errorf("testing: (*common).Setenv does not fail test on os.Setenv error")
	}
	_, okSSel := isSelectorBaseField(setCall.Fun, "os", "Setenv")
	_, okSK := isIdentNamed(setCall.Args[0], keyParam)
	_, okSV := isIdentNamed(setCall.Args[1], valParam)
	if !okSSel || !okSK || !okSV {
		return fmt.Errorf("testing: (*common).Setenv does not call os.Setenv(%s, %s)", keyParam, valParam)
	}

	// 3. if ok { c.Cleanup(func() { os.Setenv(key, prevValue) }) } else { c.Cleanup(func() { os.Unsetenv(key) }) }
	restIf, okRI := stmts[pos+2].(*ast.IfStmt)
	if !okRI || restIf.Init != nil || restIf.Else == nil {
		return fmt.Errorf("testing: (*common).Setenv missing if ok / else cleanup registration")
	}
	if _, okC := isIdentNamed(restIf.Cond, okID.Name); !okC {
		return fmt.Errorf("testing: (*common).Setenv cleanup branch condition is not %s", okID.Name)
	}
	elseBlk, okEB := restIf.Else.(*ast.BlockStmt)
	if !okEB || len(restIf.Body.List) != 1 || len(elseBlk.List) != 1 {
		return fmt.Errorf("testing: (*common).Setenv cleanup arms unexpected shape")
	}
	checkCleanupOSCall := func(st ast.Stmt, wantFn string, wantArgs ...string) bool {
		es, okES := st.(*ast.ExprStmt)
		if !okES {
			return false
		}
		cc, okCC := unwrapParens(es.X).(*ast.CallExpr)
		if !okCC || cc.Ellipsis.IsValid() || len(cc.Args) != 1 {
			return false
		}
		if _, okCl := isSelectorBaseField(cc.Fun, recv, "Cleanup"); !okCl {
			return false
		}
		fl, okFL := unwrapParens(cc.Args[0]).(*ast.FuncLit)
		if !okFL || fl.Body == nil || len(fl.Body.List) != 1 || (fl.Type.Params != nil && fl.Type.Params.NumFields() != 0) {
			return false
		}
		var innerCall *ast.CallExpr
		switch s0 := fl.Body.List[0].(type) {
		case *ast.ExprStmt:
			innerCall, _ = unwrapParens(s0.X).(*ast.CallExpr)
		case *ast.AssignStmt:
			if s0.Tok == token.ASSIGN && len(s0.Rhs) == 1 {
				innerCall, _ = unwrapParens(s0.Rhs[0]).(*ast.CallExpr)
			}
		}
		if innerCall == nil || innerCall.Ellipsis.IsValid() || len(innerCall.Args) != len(wantArgs) {
			return false
		}
		if _, okOS := isSelectorBaseField(innerCall.Fun, "os", wantFn); !okOS {
			return false
		}
		for i, w := range wantArgs {
			if _, okA := isIdentNamed(innerCall.Args[i], w); !okA {
				return false
			}
		}
		return true
	}
	if !checkCleanupOSCall(restIf.Body.List[0], "Setenv", keyParam, prevID.Name) || !checkCleanupOSCall(elseBlk.List[0], "Unsetenv", keyParam) {
		return fmt.Errorf("testing: (*common).Setenv cleanup closures do not restore/unset %s", keyParam)
	}
	return nil
}

func verifyTestingCommonChdir(idx *packageASTIndex, fn *ast.FuncDecl, k *packageInactiveKernel, reqGates map[string]bool) error {
	reserved := map[string]bool{"os": true, "runtime": true, "string": true, "nil": true, "panic": true}
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.Params == nil || fn.Type.Params.NumFields() != 1 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) || funcShadowsAnyIdent(fn, reserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return fmt.Errorf("testing: missing or invalid (*common).Chdir")
	}
	f := idx.funcFile[fn]
	if k.fileImportPath(f, "os") != "os" || k.fileImportPath(f, "runtime") != "runtime" {
		return fmt.Errorf("testing: (*common).Chdir file missing os or runtime import")
	}
	recv := recvVarName(fn)
	pNames := paramNamesFlat(fn.Type.Params)
	if recv == "" || len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || pNames[0] == recv {
		return fmt.Errorf("testing: (*common).Chdir invalid parameter")
	}
	if _, ok := isIdentNamed(fn.Type.Params.List[0].Type, "string"); !ok {
		return fmt.Errorf("testing: (*common).Chdir parameter type is not string")
	}
	dirParam := pNames[0]
	if bodyMutatesOrTakesAddrOfAny(fn.Body, map[string]bool{recv: true}) {
		return fmt.Errorf("testing: (*common).Chdir mutates receiver")
	}

	stmts, _ := k.pruneBlockStmts(fn.Body.List, fn, map[string]bool{recv: true}, reqGates, nil)
	pos := 0
	for pos < len(stmts) && isTestingCheckHelperStmt(stmts[pos], recv) {
		pos++
	}
	if len(stmts)-pos != 5 {
		return fmt.Errorf("testing: (*common).Chdir unexpected statement count")
	}

	// 1. oldwd, err := os.Open("."); if err != nil { c.Fatal(err) }
	openAs, okOA := stmts[pos].(*ast.AssignStmt)
	openIf, okOI := stmts[pos+1].(*ast.IfStmt)
	if !okOA || !okOI || openAs.Tok != token.DEFINE || len(openAs.Lhs) != 2 || len(openAs.Rhs) != 1 || openIf.Init != nil {
		return fmt.Errorf("testing: (*common).Chdir missing os.Open(\".\") + error check")
	}
	oldwdID, okOW := unwrapParens(openAs.Lhs[0]).(*ast.Ident)
	openErrID, okOE := unwrapParens(openAs.Lhs[1]).(*ast.Ident)
	openCall, okOC := unwrapParens(openAs.Rhs[0]).(*ast.CallExpr)
	if !okOW || !okOE || !okOC || oldwdID.Name == "" || oldwdID.Name == "_" || openErrID.Name == "" || openErrID.Name == "_" || oldwdID.Name == openErrID.Name || !isTestingFatalErrIf(openIf, recv, openErrID.Name) || openCall.Ellipsis.IsValid() || len(openCall.Args) != 1 {
		return fmt.Errorf("testing: (*common).Chdir invalid os.Open(\".\") guard")
	}
	_, okOpenSel := isSelectorBaseField(openCall.Fun, "os", "Open")
	dotLit, okDot := unwrapParens(openCall.Args[0]).(*ast.BasicLit)
	if !okOpenSel || !okDot || dotLit.Kind != token.STRING || dotLit.Value != `"."` {
		return fmt.Errorf("testing: (*common).Chdir does not open \".\" before os.Chdir")
	}
	if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: stmts[pos+1:]}, map[string]bool{oldwdID.Name: true}) {
		return fmt.Errorf("testing: (*common).Chdir mutates or takes address of %s", oldwdID.Name)
	}

	// 2. if err := os.Chdir(dir); err != nil { c.Fatal(err) }
	chIf, okCI := stmts[pos+2].(*ast.IfStmt)
	if !okCI || chIf.Init == nil {
		return fmt.Errorf("testing: (*common).Chdir missing os.Chdir error guard")
	}
	chInit, okCIn := chIf.Init.(*ast.AssignStmt)
	if !okCIn || (chInit.Tok != token.DEFINE && chInit.Tok != token.ASSIGN) || len(chInit.Lhs) != 1 || len(chInit.Rhs) != 1 {
		return fmt.Errorf("testing: (*common).Chdir invalid os.Chdir init")
	}
	chErrID, okCE := unwrapParens(chInit.Lhs[0]).(*ast.Ident)
	chCall, okCC := unwrapParens(chInit.Rhs[0]).(*ast.CallExpr)
	if !okCE || !okCC || !isTestingFatalErrIf(chIf, recv, chErrID.Name) || chCall.Ellipsis.IsValid() || len(chCall.Args) != 1 {
		return fmt.Errorf("testing: (*common).Chdir does not fail test on os.Chdir error")
	}
	_, okChSel := isSelectorBaseField(chCall.Fun, "os", "Chdir")
	_, okChArg := isIdentNamed(chCall.Args[0], dirParam)
	if !okChSel || !okChArg {
		return fmt.Errorf("testing: (*common).Chdir does not call os.Chdir(%s)", dirParam)
	}

	// 3. switch runtime.GOOS { case "windows", "plan9": default: if !filepath.IsAbs(dir) { dir, err = os.Getwd(); if err != nil { c.Fatal(err) } }; c.Setenv("PWD", dir) }
	sw, okSW := stmts[pos+3].(*ast.SwitchStmt)
	if !okSW || sw.Init != nil || sw.Tag == nil || sw.Body == nil || len(sw.Body.List) != 2 {
		return fmt.Errorf("testing: (*common).Chdir missing runtime.GOOS PWD switch")
	}
	if _, okGOOS := isSelectorBaseField(sw.Tag, "runtime", "GOOS"); !okGOOS {
		return fmt.Errorf("testing: (*common).Chdir switch tag is not runtime.GOOS")
	}
	var defBody []ast.Stmt
	sawNonPosixCase := false
	for _, cl := range sw.Body.List {
		cc, okCC := cl.(*ast.CaseClause)
		if !okCC {
			return fmt.Errorf("testing: (*common).Chdir invalid switch clause")
		}
		if cc.List == nil {
			defBody = cc.Body
			continue
		}
		if len(cc.Body) != 0 {
			return fmt.Errorf("testing: (*common).Chdir non-default GOOS case must be empty")
		}
		for _, expr := range cc.List {
			lit, okL := unwrapParens(expr).(*ast.BasicLit)
			if !okL || lit.Kind != token.STRING || (lit.Value != `"windows"` && lit.Value != `"plan9"`) {
				return fmt.Errorf("testing: (*common).Chdir unexpected GOOS exclusion %v", expr)
			}
		}
		sawNonPosixCase = true
	}
	if !sawNonPosixCase || len(defBody) != 2 {
		return fmt.Errorf("testing: (*common).Chdir invalid default PWD branch")
	}
	absIf, okAI := defBody[0].(*ast.IfStmt)
	pwdES, okPES := defBody[1].(*ast.ExprStmt)
	if !okAI || !okPES || absIf.Init != nil || absIf.Else != nil || len(absIf.Body.List) != 2 {
		return fmt.Errorf("testing: (*common).Chdir default branch missing IsAbs + Setenv(\"PWD\", dir)")
	}
	uNot, okUN := unwrapParens(absIf.Cond).(*ast.UnaryExpr)
	if !okUN || uNot.Op != token.NOT {
		return fmt.Errorf("testing: (*common).Chdir IsAbs guard not negated")
	}
	absCall, okAC := unwrapParens(uNot.X).(*ast.CallExpr)
	if !okAC || absCall.Ellipsis.IsValid() || len(absCall.Args) != 1 {
		return fmt.Errorf("testing: (*common).Chdir invalid IsAbs call")
	}
	absSel, okAS := unwrapParens(absCall.Fun).(*ast.SelectorExpr)
	_, okAbsDir := isIdentNamed(absCall.Args[0], dirParam)
	if !okAS || absSel.Sel.Name != "IsAbs" || !okAbsDir {
		return fmt.Errorf("testing: (*common).Chdir does not check IsAbs(%s)", dirParam)
	}
	fpAlias, okFP := unwrapParens(absSel.X).(*ast.Ident)
	if !okFP || (k.fileImportPath(f, fpAlias.Name) != "path/filepath" && k.fileImportPath(f, fpAlias.Name) != "internal/filepathlite") {
		return fmt.Errorf("testing: (*common).Chdir IsAbs package is not path/filepath")
	}
	gwAs, okGA := absIf.Body.List[0].(*ast.AssignStmt)
	gwIf, okGI := absIf.Body.List[1].(*ast.IfStmt)
	if !okGA || !okGI || (gwAs.Tok != token.ASSIGN && gwAs.Tok != token.DEFINE) || len(gwAs.Lhs) != 2 || len(gwAs.Rhs) != 1 {
		return fmt.Errorf("testing: (*common).Chdir invalid os.Getwd() resolution")
	}
	_, okGDir := isIdentNamed(gwAs.Lhs[0], dirParam)
	gwErrID, okGE := unwrapParens(gwAs.Lhs[1]).(*ast.Ident)
	gwCall, okGC := unwrapParens(gwAs.Rhs[0]).(*ast.CallExpr)
	if !okGDir || !okGE || !okGC || !isTestingFatalErrIf(gwIf, recv, gwErrID.Name) || gwCall.Ellipsis.IsValid() || len(gwCall.Args) != 0 {
		return fmt.Errorf("testing: (*common).Chdir os.Getwd() error not checked")
	}
	if _, okGWSel := isSelectorBaseField(gwCall.Fun, "os", "Getwd"); !okGWSel {
		return fmt.Errorf("testing: (*common).Chdir does not call os.Getwd()")
	}
	pwdCall, okPC := unwrapParens(pwdES.X).(*ast.CallExpr)
	if !okPC || pwdCall.Ellipsis.IsValid() || len(pwdCall.Args) != 2 {
		return fmt.Errorf("testing: (*common).Chdir invalid c.Setenv(\"PWD\", dir) call")
	}
	_, okPWDSel := isSelectorBaseField(pwdCall.Fun, recv, "Setenv")
	pwdLit, okPLit := unwrapParens(pwdCall.Args[0]).(*ast.BasicLit)
	_, okPWDDir := isIdentNamed(pwdCall.Args[1], dirParam)
	if !okPWDSel || !okPLit || pwdLit.Kind != token.STRING || pwdLit.Value != `"PWD"` || !okPWDDir {
		return fmt.Errorf("testing: (*common).Chdir does not call %s.Setenv(\"PWD\", %s)", recv, dirParam)
	}

	// 4. c.Cleanup(func() { err := oldwd.Chdir(); oldwd.Close(); if err != nil { panic(...) } })
	clES, okCES := stmts[pos+4].(*ast.ExprStmt)
	if !okCES {
		return fmt.Errorf("testing: (*common).Chdir missing trailing c.Cleanup")
	}
	clCall, okCC2 := unwrapParens(clES.X).(*ast.CallExpr)
	if !okCC2 || clCall.Ellipsis.IsValid() || len(clCall.Args) != 1 {
		return fmt.Errorf("testing: (*common).Chdir invalid c.Cleanup call")
	}
	if _, okClSel := isSelectorBaseField(clCall.Fun, recv, "Cleanup"); !okClSel {
		return fmt.Errorf("testing: (*common).Chdir does not register restoration via %s.Cleanup", recv)
	}
	fl, okFL := unwrapParens(clCall.Args[0]).(*ast.FuncLit)
	if !okFL || fl.Body == nil || len(fl.Body.List) < 2 || len(fl.Body.List) > 3 || (fl.Type.Params != nil && fl.Type.Params.NumFields() != 0) || bodyHasControlFlowOrRecoverBypass(fl.Body) {
		return fmt.Errorf("testing: (*common).Chdir cleanup closure unexpected shape")
	}
	restoreAs, okRA := fl.Body.List[0].(*ast.AssignStmt)
	if !okRA || restoreAs.Tok != token.DEFINE || len(restoreAs.Lhs) != 1 || len(restoreAs.Rhs) != 1 {
		return fmt.Errorf("testing: (*common).Chdir cleanup missing err := oldwd.Chdir()")
	}
	rErrID, okRE := unwrapParens(restoreAs.Lhs[0]).(*ast.Ident)
	_, okOldChdir := isZeroArgMethodCallOnIdent(restoreAs.Rhs[0], oldwdID.Name, "Chdir")
	if !okRE || rErrID.Name == "" || rErrID.Name == "_" || !okOldChdir {
		return fmt.Errorf("testing: (*common).Chdir cleanup does not call %s.Chdir()", oldwdID.Name)
	}
	var sawPanicGuard, sawClose bool
	for _, s := range fl.Body.List[1:] {
		switch st := s.(type) {
		case *ast.ExprStmt:
			if _, okCl := isZeroArgMethodCallOnIdent(st.X, oldwdID.Name, "Close"); okCl {
				sawClose = true
				continue
			}
		case *ast.AssignStmt:
			if st.Tok == token.ASSIGN && len(st.Lhs) == 1 && len(st.Rhs) == 1 {
				_, okBlank := isIdentNamed(st.Lhs[0], "_")
				_, okCl := isZeroArgMethodCallOnIdent(st.Rhs[0], oldwdID.Name, "Close")
				if okBlank && okCl {
					sawClose = true
					continue
				}
			}
		case *ast.IfStmt:
			if st.Init == nil && st.Else == nil && condChecksNonZeroErr(st.Cond) == rErrID.Name && len(st.Body.List) == 1 && isTestingChdirCleanupPanicStmt(st.Body.List[0], rErrID.Name) {
				sawPanicGuard = true
				continue
			}
		}
		return fmt.Errorf("testing: (*common).Chdir cleanup contains unexpected statement")
	}
	if !sawPanicGuard || !sawClose {
		return fmt.Errorf("testing: (*common).Chdir cleanup missing Close() or panic on failed Chdir restore")
	}
	return nil
}

func verifyTestingWrapperChdir(typeName string, fn *ast.FuncDecl, required bool, k *packageInactiveKernel, reqGates map[string]bool) error {
	if fn == nil {
		if required {
			return fmt.Errorf("testing: missing (*%s).Chdir", typeName)
		}
		return nil
	}
	if fn.Body == nil || fn.Type == nil || fn.Type.Params == nil || fn.Type.Params.NumFields() != 1 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return fmt.Errorf("testing: invalid (*%s).Chdir signature or body", typeName)
	}
	recv := recvVarName(fn)
	pNames := paramNamesFlat(fn.Type.Params)
	if recv == "" || len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" {
		return fmt.Errorf("testing: invalid (*%s).Chdir receiver or parameter", typeName)
	}
	if _, ok := isIdentNamed(fn.Type.Params.List[0].Type, "string"); !ok {
		return fmt.Errorf("testing: (*%s).Chdir parameter is not string", typeName)
	}
	stmts, _ := k.pruneBlockStmts(fn.Body.List, fn, map[string]bool{recv: true, pNames[0]: true}, reqGates, nil)
	if len(stmts) != 2 {
		return fmt.Errorf("testing: (*%s).Chdir must call checkParallel() then common.Chdir(dir)", typeName)
	}
	es0, ok0 := stmts[0].(*ast.ExprStmt)
	es1, ok1 := stmts[1].(*ast.ExprStmt)
	if !ok0 || !ok1 {
		return fmt.Errorf("testing: (*%s).Chdir statements must be calls", typeName)
	}
	if _, okCP := isZeroArgMethodCallOnIdent(es0.X, recv, "checkParallel"); !okCP {
		return fmt.Errorf("testing: (*%s).Chdir missing %s.checkParallel()", typeName, recv)
	}
	c1, okC1 := unwrapParens(es1.X).(*ast.CallExpr)
	if !okC1 || c1.Ellipsis.IsValid() || len(c1.Args) != 1 {
		return fmt.Errorf("testing: (*%s).Chdir invalid common.Chdir call", typeName)
	}
	sel1, okS1 := unwrapParens(c1.Fun).(*ast.SelectorExpr)
	_, okArg := isIdentNamed(c1.Args[0], pNames[0])
	if !okS1 || sel1.Sel.Name != "Chdir" || !okArg {
		return fmt.Errorf("testing: (*%s).Chdir does not forward %s to common.Chdir", typeName, pNames[0])
	}
	if _, okCommon := isSelectorBaseField(sel1.X, recv, "common"); !okCommon {
		return fmt.Errorf("testing: (*%s).Chdir does not call %s.common.Chdir", typeName, recv)
	}
	return nil
}

func verifyTestingWrapperSetenv(typeName string, fn *ast.FuncDecl, k *packageInactiveKernel, reqGates map[string]bool) error {
	if fn.Body == nil || fn.Type == nil || fn.Type.Params == nil || fn.Type.Params.NumFields() != 2 || (fn.Type.Results != nil && fn.Type.Results.NumFields() != 0) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return fmt.Errorf("testing: invalid (*%s).Setenv signature or body", typeName)
	}
	recv := recvVarName(fn)
	pNames := paramNamesFlat(fn.Type.Params)
	if recv == "" || len(pNames) != 2 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" {
		return fmt.Errorf("testing: invalid (*%s).Setenv receiver or parameters", typeName)
	}
	stmts, _ := k.pruneBlockStmts(fn.Body.List, fn, map[string]bool{recv: true}, reqGates, nil)
	if len(stmts) != 2 {
		return fmt.Errorf("testing: (*%s).Setenv must call checkParallel() then common.Setenv(key, value)", typeName)
	}
	es0, ok0 := stmts[0].(*ast.ExprStmt)
	es1, ok1 := stmts[1].(*ast.ExprStmt)
	if !ok0 || !ok1 {
		return fmt.Errorf("testing: (*%s).Setenv statements must be calls", typeName)
	}
	if _, okCP := isZeroArgMethodCallOnIdent(es0.X, recv, "checkParallel"); !okCP {
		return fmt.Errorf("testing: (*%s).Setenv missing %s.checkParallel()", typeName, recv)
	}
	c1, okC1 := unwrapParens(es1.X).(*ast.CallExpr)
	if !okC1 || c1.Ellipsis.IsValid() || len(c1.Args) != 2 {
		return fmt.Errorf("testing: (*%s).Setenv invalid common.Setenv call", typeName)
	}
	sel1, okS1 := unwrapParens(c1.Fun).(*ast.SelectorExpr)
	_, okA0 := isIdentNamed(c1.Args[0], pNames[0])
	_, okA1 := isIdentNamed(c1.Args[1], pNames[1])
	_, okCommon := isSelectorBaseField(sel1.X, recv, "common")
	if !okS1 || sel1.Sel.Name != "Setenv" || !okCommon || !okA0 || !okA1 {
		return fmt.Errorf("testing: (*%s).Setenv does not forward to %s.common.Setenv", typeName, recv)
	}
	return nil
}
