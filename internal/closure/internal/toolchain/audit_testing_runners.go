package toolchain

import (
	"go/ast"
	"go/token"
	"slices"
)

func verifyTestingMRunModes(
	files []*ast.File,
	runFn *ast.FuncDecl,
	runRecv string,
	mMethods map[string]*ast.FuncDecl,
	st verifiedStartInfo,
	sp verifiedStopInfo,
	parseIdx int,
	exitCodeField string,
	exitCodeDefer *ast.DeferStmt,
	listFlagVars map[string]bool,
	emptyDefaultStringFlags map[string]bool,
	pkgReserved map[string]bool,
	mFields map[string]ast.Expr,
	mFieldIdents map[string]*ast.Ident,
	mStructFile *ast.File,
	fileImportsSync map[*ast.File]bool,
	exitSitesByFunc map[*ast.FuncDecl][]testingExitSite,
	closeExits map[*ast.CallExpr]bool,
	bodyHasGoexit func(*ast.BlockStmt) bool,
	verifyFlagInitCalledInMainStart func(string) bool,
	verifyFlagPtrIdentOnlyDereferenced func(string) bool,
	stmtCallsRunner func(ast.Stmt) bool,
	stmtsHaveNoNonRunnerHelperExit func([]ast.Stmt, map[*ast.SelectorExpr]bool) bool,
) bool {
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
