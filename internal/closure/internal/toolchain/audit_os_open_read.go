package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"maps"
)

func isDirinfoSwapCloseIf(st ast.Stmt, rcRecv string, dirInfoCloseFn *ast.FuncDecl, osNoFileReserved, osAnyLinknameLocals map[string]bool) bool {
	ifs, ok := st.(*ast.IfStmt)
	if !ok || ifs.Init == nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
		return false
	}
	initAs, ok := ifs.Init.(*ast.AssignStmt)
	if !ok || initAs.Tok != token.DEFINE || len(initAs.Lhs) != 1 || len(initAs.Rhs) != 1 {
		return false
	}
	infoID, ok := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
	if !ok || infoID.Name == "" || infoID.Name == "_" || condChecksNonZeroErr(ifs.Cond) != infoID.Name {
		return false
	}
	swapCall, ok := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
	if !ok || swapCall.Ellipsis.IsValid() || len(swapCall.Args) != 1 {
		return false
	}
	if _, okNil := isIdentNamed(swapCall.Args[0], "nil"); !okNil {
		return false
	}
	swapSel, ok := unwrapParens(swapCall.Fun).(*ast.SelectorExpr)
	if !ok || swapSel.Sel.Name != "Swap" {
		return false
	}
	if _, okDI := isSelectorBaseField(swapSel.X, rcRecv, "dirinfo"); !okDI {
		return false
	}
	es, ok := ifs.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	if _, okCl := isZeroArgMethodCallOnIdent(es.X, infoID.Name, "close"); !okCl {
		return false
	}
	if dirInfoCloseFn == nil || dirInfoCloseFn.Body == nil || osAnyLinknameLocals["close"] || funcShadowsAnyIdent(dirInfoCloseFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(dirInfoCloseFn.Body) {
		return false
	}
	badDirClose := false
	ast.Inspect(dirInfoCloseFn.Body, func(n ast.Node) bool {
		if badDirClose || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.DeferStmt, *ast.GoStmt, *ast.FuncLit:
			badDirClose = true
			return false
		case *ast.Ident:
			if x.Name == "testlog" {
				badDirClose = true
				return false
			}
		case *ast.ReturnStmt:
			if len(x.Results) != 0 {
				badDirClose = true
				return false
			}
		}
		return true
	})
	return !badDirClose
}

func verifyOSOpenFileNolog(fn *ast.FuncDecl, allTopFuncs map[string]*ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsSyscall map[*ast.File]bool, osNoFileReserved, osAnyLinknameLocals map[string]bool, skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool) error {
	if fn == nil || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || osAnyLinknameLocals["openFileNolog"] {
		return fmt.Errorf("os: missing or invalid openFileNolog")
	}
	if funcShadowsAnyIdent(fn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
		return fmt.Errorf("os: openFileNolog shadows reserved identifier or has control-flow/recover bypass")
	}
	pNames := paramNamesFlat(fn.Type.Params)
	if len(pNames) != 3 || pNames[0] == "" || pNames[0] == "_" || pNames[1] == "" || pNames[1] == "_" || pNames[2] == "" || pNames[2] == "_" {
		return fmt.Errorf("os: openFileNolog invalid parameters")
	}
	if fn.Type.Results == nil || fn.Type.Results.NumFields() != 2 || !funcReturnsErrorLast(fn.Type) {
		return fmt.Errorf("os: openFileNolog invalid results")
	}
	if starF, okS := unwrapParens(fn.Type.Results.List[0].Type).(*ast.StarExpr); !okS {
		return fmt.Errorf("os: openFileNolog first result is not *File")
	} else if _, okF := isIdentNamed(starF.X, "File"); !okF {
		return fmt.Errorf("os: openFileNolog first result is not *File")
	}
	p0 := pNames[0]
	if bodyMutatesOrTakesAddrOfAny(fn.Body, map[string]bool{p0: true}) || bodyDeclaresAnyIdent(fn.Body, map[string]bool{p0: true}) {
		return fmt.Errorf("os: openFileNolog mutates or shadows %s", p0)
	}
	pos := 0
	for pos < len(fn.Body.List) && skipInactiveHookIf(fn.Body.List[pos], fn) {
		pos++
	}
	if len(fn.Body.List) < pos+3 {
		return fmt.Errorf("os: openFileNolog body too short")
	}

	isVerifiedFileLit := func(expr ast.Expr, fdNames map[string]bool, wantName string) bool {
		outerLit, outerType := compositeWriterLit(expr)
		if outerLit == nil || outerType != "File" || len(outerLit.Elts) != 1 {
			return false
		}
		innerExpr := outerLit.Elts[0]
		if kv, okKV := innerExpr.(*ast.KeyValueExpr); okKV {
			if _, okKey := isIdentNamed(kv.Key, "file"); !okKey {
				return false
			}
			innerExpr = kv.Value
		}
		innerLit, innerType := compositeWriterLit(innerExpr)
		if innerLit == nil || innerType != "file" {
			return false
		}
		var sawName, sawFD bool
		for _, elt := range innerLit.Elts {
			kv, okKV := elt.(*ast.KeyValueExpr)
			if !okKV {
				return false
			}
			kID, okK := unwrapParens(kv.Key).(*ast.Ident)
			if !okK {
				return false
			}
			switch kID.Name {
			case "name":
				if _, okN := isIdentNamed(kv.Value, wantName); !okN {
					return false
				}
				sawName = true
			case "sysfd":
				if vID, okV := unwrapParens(kv.Value).(*ast.Ident); !okV || !fdNames[vID.Name] {
					return false
				}
				sawFD = true
			case "pfd":
				pfdLit, okCL := unwrapParens(kv.Value).(*ast.CompositeLit)
				if !okCL {
					return false
				}
				for _, pElt := range pfdLit.Elts {
					pkv, okPKV := pElt.(*ast.KeyValueExpr)
					if !okPKV {
						return false
					}
					if _, okSys := isIdentNamed(pkv.Key, "Sysfd"); okSys {
						vID, okV := unwrapParens(pkv.Value).(*ast.Ident)
						if !okV || !fdNames[vID.Name] {
							return false
						}
						sawFD = true
					}
				}
			}
		}
		return sawName && sawFD
	}

	verifyNewFileHelper := func(nfFn *ast.FuncDecl) bool {
		if nfFn == nil || nfFn.Body == nil || osAnyLinknameLocals[nfFn.Name.Name] || funcShadowsAnyIdent(nfFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(nfFn.Body) {
			return false
		}
		nfParams := paramNamesFlat(nfFn.Type.Params)
		if len(nfParams) < 2 || nfParams[0] == "" || nfParams[0] == "_" || nfParams[1] == "" || nfParams[1] == "_" {
			return false
		}
		fdP, nameP := nfParams[0], nfParams[1]
		if bodyMutatesOrTakesAddrOfAny(nfFn.Body, map[string]bool{fdP: true, nameP: true}) || bodyDeclaresAnyIdent(nfFn.Body, map[string]bool{fdP: true, nameP: true}) {
			return false
		}
		hasTestlog := false
		ast.Inspect(nfFn.Body, func(n ast.Node) bool {
			if id, okID := n.(*ast.Ident); okID && id.Name == "testlog" {
				hasTestlog = true
				return false
			}
			return !hasTestlog
		})
		if hasTestlog || len(nfFn.Body.List) == 0 {
			return false
		}
		fdAliases := map[string]bool{fdP: true}
		scanIdx := 0
		if as0, okA := nfFn.Body.List[0].(*ast.AssignStmt); okA && as0.Tok == token.DEFINE && len(as0.Lhs) == 1 && len(as0.Rhs) == 1 {
			if aID, okID := unwrapParens(as0.Lhs[0]).(*ast.Ident); okID && aID.Name != "" && aID.Name != "_" {
				if conv, okC := unwrapParens(as0.Rhs[0]).(*ast.CallExpr); okC && !conv.Ellipsis.IsValid() && len(conv.Args) == 1 {
					if _, okArg := isIdentNamed(conv.Args[0], fdP); okArg {
						_, okInt := isIdentNamed(conv.Fun, "int")
						_, okH := isSelectorBaseField(conv.Fun, "syscall", "Handle")
						if (okInt || okH) && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: nfFn.Body.List[1:]}, map[string]bool{aID.Name: true}) {
							fdAliases[aID.Name] = true
							scanIdx = 1
						}
					}
				}
			}
		}
		if scanIdx < len(nfFn.Body.List) {
			if ifs, okI := nfFn.Body.List[scanIdx].(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if rNil, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(rNil.Results) == 1 {
					if _, okN := isIdentNamed(rNil.Results[0], "nil"); okN && !exprContainsAnyCall(ifs.Cond) {
						scanIdx++
					}
				}
			}
		}
		if scanIdx == len(nfFn.Body.List)-1 {
			if ret, okR := nfFn.Body.List[scanIdx].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
				if isVerifiedFileLit(ret.Results[0], fdAliases, nameP) {
					return true
				}
				if c, okC := unwrapParens(ret.Results[0]).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) >= 2 {
					if cFun, okF := unwrapParens(c.Fun).(*ast.Ident); okF && cFun.Name == "newFile" {
						if a0, ok0 := unwrapParens(c.Args[0]).(*ast.Ident); ok0 && fdAliases[a0.Name] {
							if _, ok1 := isIdentNamed(c.Args[1], nameP); ok1 && nfFn.Name.Name != "newFile" {
								return allTopFuncs["newFile"] != nil
							}
						}
					}
				}
			}
		}
		fDeclIdx := -1
		var nfVar string
		for idx := scanIdx; idx < len(nfFn.Body.List); idx++ {
			if as, okA := nfFn.Body.List[idx].(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if vID, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && vID.Name != "" && vID.Name != "_" && isVerifiedFileLit(as.Rhs[0], fdAliases, nameP) {
					fDeclIdx = idx
					nfVar = vID.Name
					break
				}
			}
		}
		if fDeclIdx < 0 || nfVar == "" {
			return false
		}
		if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: nfFn.Body.List[fDeclIdx+1:]}, map[string]bool{nfVar: true}) || bodyDeclaresAnyIdent(&ast.BlockStmt{List: nfFn.Body.List[fDeclIdx+1:]}, map[string]bool{nfVar: true}) {
			return false
		}
		badPost := false
		for _, st := range nfFn.Body.List[:fDeclIdx] {
			ast.Inspect(st, func(n ast.Node) bool {
				if _, isFL := n.(*ast.FuncLit); isFL {
					return false
				}
				if _, okR := n.(*ast.ReturnStmt); okR && st != nfFn.Body.List[scanIdx-1] {
					badPost = true
					return false
				}
				return !badPost
			})
		}
		for _, st := range nfFn.Body.List[fDeclIdx+1:] {
			ast.Inspect(st, func(n ast.Node) bool {
				if badPost || n == nil {
					return false
				}
				if as, okA := n.(*ast.AssignStmt); okA {
					for _, lhs := range as.Lhs {
						if sel, okS := unwrapParens(lhs).(*ast.SelectorExpr); okS {
							if _, okB := isIdentNamed(sel.X, nfVar); okB && (sel.Sel.Name == "file" || sel.Sel.Name == "pfd" || sel.Sel.Name == "sysfd" || sel.Sel.Name == "name") {
								badPost = true
								return false
							}
							if sel.Sel.Name == "Sysfd" {
								if _, okPFD := isSelectorBaseField(sel.X, nfVar, "pfd"); okPFD {
									badPost = true
									return false
								}
							}
						}
					}
				}
				return true
			})
			ast.Inspect(st, func(n ast.Node) bool {
				if badPost || n == nil {
					return false
				}
				if _, isFL := n.(*ast.FuncLit); isFL {
					return false
				}
				if r, okR := n.(*ast.ReturnStmt); okR {
					if len(r.Results) != 1 {
						badPost = true
						return false
					}
					if _, okV := isIdentNamed(r.Results[0], nfVar); !okV {
						badPost = true
						return false
					}
				}
				return true
			})
		}
		lastRet, okLR := nfFn.Body.List[len(nfFn.Body.List)-1].(*ast.ReturnStmt)
		if badPost || !okLR || len(lastRet.Results) != 1 {
			return false
		}
		_, okFinal := isIdentNamed(lastRet.Results[0], nfVar)
		return okFinal
	}

	matchNewFileCall := func(expr ast.Expr) (string, bool) {
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) < 2 {
			return "", false
		}
		fnID, okF := unwrapParens(c.Fun).(*ast.Ident)
		if !okF {
			return "", false
		}
		if _, okName := isIdentNamed(c.Args[1], p0); !okName {
			return "", false
		}
		switch fnID.Name {
		case "newFile":
			fdID, okFD := unwrapParens(c.Args[0]).(*ast.Ident)
			if !okFD || fdID.Name == "" || fdID.Name == "_" || !verifyNewFileHelper(allTopFuncs["newFile"]) {
				return "", false
			}
			return fdID.Name, true
		case "NewFile":
			if len(c.Args) != 2 {
				return "", false
			}
			uConv, okConv := unwrapParens(c.Args[0]).(*ast.CallExpr)
			if !okConv || uConv.Ellipsis.IsValid() || len(uConv.Args) != 1 {
				return "", false
			}
			if _, okU := isIdentNamed(uConv.Fun, "uintptr"); !okU {
				return "", false
			}
			fdID, okFD := unwrapParens(uConv.Args[0]).(*ast.Ident)
			nfExported := allTopFuncs["NewFile"]
			if !okFD || fdID.Name == "" || fdID.Name == "_" || nfExported == nil || nfExported.Body == nil || osAnyLinknameLocals["NewFile"] || len(nfExported.Body.List) == 0 {
				return "", false
			}
			nfExpParams := paramNamesFlat(nfExported.Type.Params)
			if len(nfExpParams) != 2 {
				return "", false
			}
			lastExp, okLE := nfExported.Body.List[len(nfExported.Body.List)-1].(*ast.ReturnStmt)
			if !okLE || len(lastExp.Results) != 1 {
				return "", false
			}
			delCall, okDC := unwrapParens(lastExp.Results[0]).(*ast.CallExpr)
			if !okDC || delCall.Ellipsis.IsValid() || len(delCall.Args) != 2 {
				return "", false
			}
			_, okDelFun := isIdentNamed(delCall.Fun, "newFileFromNewFile")
			_, okD0 := isIdentNamed(delCall.Args[0], nfExpParams[0])
			_, okD1 := isIdentNamed(delCall.Args[1], nfExpParams[1])
			if !okDelFun || !okD0 || !okD1 || !verifyNewFileHelper(allTopFuncs["newFileFromNewFile"]) {
				return "", false
			}
			if allTopFuncs["newFile"] != nil && !verifyNewFileHelper(allTopFuncs["newFile"]) {
				return "", false
			}
			return fdID.Name, true
		default:
			return "", false
		}
	}

	lastRet, ok := fn.Body.List[len(fn.Body.List)-1].(*ast.ReturnStmt)
	if !ok || len(lastRet.Results) != 2 {
		return fmt.Errorf("os: openFileNolog missing trailing 2-value return")
	}
	if _, okNil := isIdentNamed(lastRet.Results[1], "nil"); !okNil {
		return fmt.Errorf("os: openFileNolog final return error is not nil")
	}

	var wantFDVar string
	fConstructIdx := -1
	if fdV, okInline := matchNewFileCall(lastRet.Results[0]); okInline {
		wantFDVar = fdV
		fConstructIdx = len(fn.Body.List) - 1
	} else if fVarID, okFV := unwrapParens(lastRet.Results[0]).(*ast.Ident); okFV && fVarID.Name != "" && fVarID.Name != "_" {
		for candIdx := len(fn.Body.List) - 2; candIdx >= pos && candIdx >= len(fn.Body.List)-3; candIdx-- {
			as, okA := fn.Body.List[candIdx].(*ast.AssignStmt)
			if !okA || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				continue
			}
			if _, okLHS := isIdentNamed(as.Lhs[0], fVarID.Name); !okLHS {
				continue
			}
			fdV, okNF := matchNewFileCall(as.Rhs[0])
			if !okNF {
				continue
			}
			tailOK := !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: fn.Body.List[candIdx+1:]}, map[string]bool{fVarID.Name: true})
			for _, tailSt := range fn.Body.List[candIdx+1 : len(fn.Body.List)-1] {
				tAs, okTA := tailSt.(*ast.AssignStmt)
				if !okTA || tAs.Tok != token.ASSIGN || len(tAs.Lhs) != 1 || len(tAs.Rhs) != 1 || exprContainsAnyCall(tAs.Rhs[0]) {
					tailOK = false
					break
				}
				sel, okS := unwrapParens(tAs.Lhs[0]).(*ast.SelectorExpr)
				if !okS || sel.Sel.Name != "SysFile" {
					tailOK = false
					break
				}
				if _, okPFD := isSelectorBaseField(sel.X, fVarID.Name, "pfd"); !okPFD {
					tailOK = false
					break
				}
			}
			if tailOK {
				wantFDVar = fdV
				fConstructIdx = candIdx
				break
			}
		}
	}
	if fConstructIdx < pos+2 || wantFDVar == "" {
		return fmt.Errorf("os: openFileNolog missing verified newFile construction")
	}

	isPathErrorReturn := func(ret *ast.ReturnStmt) bool {
		if ret == nil || len(ret.Results) != 2 {
			return false
		}
		if _, okNil := isIdentNamed(ret.Results[0], "nil"); !okNil {
			return false
		}
		u, okU := unwrapParens(ret.Results[1]).(*ast.UnaryExpr)
		lit, tName := compositeWriterLit(ret.Results[1])
		if !okU || u.Op != token.AND || lit == nil || tName != "PathError" {
			return false
		}
		for _, elt := range lit.Elts {
			if kv, okKV := elt.(*ast.KeyValueExpr); okKV {
				if _, okE := isIdentNamed(kv.Key, "Err"); okE {
					_, isNilErr := isIdentNamed(kv.Value, "nil")
					return !isNilErr
				}
			}
		}
		return false
	}

	badMidReturn := false
	for _, st := range fn.Body.List[pos:fConstructIdx] {
		if _, isBareRet := st.(*ast.ReturnStmt); isBareRet {
			return fmt.Errorf("os: openFileNolog unexpected unconditional return before newFile")
		}
		ast.Inspect(st, func(n ast.Node) bool {
			if badMidReturn || n == nil {
				return false
			}
			if _, isFL := n.(*ast.FuncLit); isFL {
				return false
			}
			if ret, okR := n.(*ast.ReturnStmt); okR && !isPathErrorReturn(ret) {
				badMidReturn = true
				return false
			}
			return true
		})
		if badMidReturn {
			return fmt.Errorf("os: openFileNolog early return does not return (nil, &PathError)")
		}
	}

	verifyIgnoringEINTR := func(igFn *ast.FuncDecl) bool {
		return verifyOSIgnoringEINTR(igFn, funcFile, fileImportsSyscall, osNoFileReserved, osAnyLinknameLocals)
	}

	verifyJoinPathHelper := func(jpFn *ast.FuncDecl) bool {
		if jpFn == nil || jpFn.Body == nil || osAnyLinknameLocals["joinPath"] || funcShadowsAnyIdent(jpFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(jpFn.Body) {
			return false
		}
		hasTestlog := false
		ast.Inspect(jpFn.Body, func(n ast.Node) bool {
			if id, okID := n.(*ast.Ident); okID && id.Name == "testlog" {
				hasTestlog = true
				return false
			}
			return !hasTestlog
		})
		return !hasTestlog
	}

	isMinusOneLit := func(expr ast.Expr) bool {
		u, okU := unwrapParens(expr).(*ast.UnaryExpr)
		if !okU || u.Op != token.SUB {
			return false
		}
		lit, okL := unwrapParens(u.X).(*ast.BasicLit)
		return okL && lit.Kind == token.INT && lit.Value == "1"
	}

	verifyOpenHelper := func(opFn *ast.FuncDecl) bool {
		if opFn == nil || opFn.Body == nil || osAnyLinknameLocals["open"] || !fileImportsSyscall[funcFile[opFn]] || funcShadowsAnyIdent(opFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(opFn.Body) {
			return false
		}
		opParams := paramNamesFlat(opFn.Type.Params)
		if len(opParams) != 3 || opParams[0] == "" || opParams[0] == "_" || len(opFn.Body.List) < 2 {
			return false
		}
		if bodyMutatesOrTakesAddrOfAny(opFn.Body, map[string]bool{opParams[0]: true}) || bodyDeclaresAnyIdent(opFn.Body, map[string]bool{opParams[0]: true}) {
			return false
		}
		hasTestlog := false
		ast.Inspect(opFn.Body, func(n ast.Node) bool {
			if id, okID := n.(*ast.Ident); okID && id.Name == "testlog" {
				hasTestlog = true
				return false
			}
			return !hasTestlog
		})
		if hasTestlog {
			return false
		}
		lastRet, okLR := opFn.Body.List[len(opFn.Body.List)-1].(*ast.ReturnStmt)
		if !okLR || len(lastRet.Results) != 3 {
			return false
		}
		fdRetID, okFD := unwrapParens(lastRet.Results[0]).(*ast.Ident)
		errRetID, okER := unwrapParens(lastRet.Results[2]).(*ast.Ident)
		if !okFD || !okER || fdRetID.Name == "" || errRetID.Name == "" {
			return false
		}
		checkedErrIfRets := map[*ast.ReturnStmt]bool{}
		ast.Inspect(&ast.BlockStmt{List: opFn.Body.List[:len(opFn.Body.List)-1]}, func(n ast.Node) bool {
			if ifs, okI := n.(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if eName := condChecksNonZeroErr(ifs.Cond); eName != "" {
					if r, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(r.Results) == 3 && isMinusOneLit(r.Results[0]) {
						if _, okE := isIdentNamed(r.Results[2], eName); okE {
							checkedErrIfRets[r] = true
						}
					}
				}
			}
			return true
		})
		badEarlyRet := false
		ast.Inspect(&ast.BlockStmt{List: opFn.Body.List[:len(opFn.Body.List)-1]}, func(n ast.Node) bool {
			if badEarlyRet || n == nil {
				return false
			}
			if r, okR := n.(*ast.ReturnStmt); okR {
				if checkedErrIfRets[r] {
					return false
				}
				if len(r.Results) != 3 || !isMinusOneLit(r.Results[0]) {
					badEarlyRet = true
					return false
				}
				sel, okS := unwrapParens(r.Results[2]).(*ast.SelectorExpr)
				if !okS || sel.Sel.Name == "" {
					badEarlyRet = true
					return false
				}
				if _, okSys := isIdentNamed(sel.X, "syscall"); !okSys {
					badEarlyRet = true
					return false
				}
			}
			return true
		})
		if badEarlyRet {
			return false
		}
		opPathAliases := map[string]bool{opParams[0]: true}
		sawSyscallOpen := false
		for idx := 0; idx < len(opFn.Body.List)-1; idx++ {
			st := opFn.Body.List[idx]
			if as, okA := st.(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if aID, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && aID.Name != "" && aID.Name != "_" {
					if _, okSrc := isIdentNamed(as.Rhs[0], opParams[0]); okSrc {
						afterIdx := idx + 1
						if afterIdx < len(opFn.Body.List)-1 {
							if ifs, okI := opFn.Body.List[afterIdx].(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 3 {
								s0, ok0 := ifs.Body.List[0].(*ast.AssignStmt)
								s1, ok1 := ifs.Body.List[1].(*ast.IfStmt)
								s2, ok2 := ifs.Body.List[2].(*ast.AssignStmt)
								if ok0 && ok1 && ok2 && s0.Tok == token.DEFINE && len(s0.Lhs) == 2 && len(s0.Rhs) == 1 && s2.Tok == token.ASSIGN && len(s2.Lhs) == 1 && len(s2.Rhs) == 1 {
									wdID, okWD := unwrapParens(s0.Lhs[0]).(*ast.Ident)
									wdErrID, okWE := unwrapParens(s0.Lhs[1]).(*ast.Ident)
									wdCall, okWC := unwrapParens(s0.Rhs[0]).(*ast.CallExpr)
									_, okAliasLHS := isIdentNamed(s2.Lhs[0], aID.Name)
									jpCall, okJC := unwrapParens(s2.Rhs[0]).(*ast.CallExpr)
									if okWD && okWE && okWC && okAliasLHS && okJC && wdID.Name != "" && wdID.Name != "_" && wdErrID.Name != "" && !wdCall.Ellipsis.IsValid() && len(wdCall.Args) == 0 && !jpCall.Ellipsis.IsValid() && len(jpCall.Args) == 2 && condChecksNonZeroErr(s1.Cond) == wdErrID.Name && len(s1.Body.List) == 1 {
										_, okGetwd := isSelectorBaseField(wdCall.Fun, "syscall", "Getwd")
										_, okJP := isIdentNamed(jpCall.Fun, "joinPath")
										_, okJA0 := isIdentNamed(jpCall.Args[0], wdID.Name)
										_, okJA1 := isIdentNamed(jpCall.Args[1], opParams[0])
										_, okRet := s1.Body.List[0].(*ast.ReturnStmt)
										if okGetwd && okJP && okJA0 && okJA1 && okRet && verifyJoinPathHelper(allTopFuncs["joinPath"]) {
											afterIdx++
										}
									}
								}
							}
						}
						if !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: opFn.Body.List[afterIdx:]}, map[string]bool{aID.Name: true}) && !bodyDeclaresAnyIdent(&ast.BlockStmt{List: opFn.Body.List[idx+1:]}, map[string]bool{aID.Name: true}) {
							opPathAliases[aID.Name] = true
							continue
						}
					}
				}
			}
			as, okA := st.(*ast.AssignStmt)
			if !okA || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
				continue
			}
			if _, okL0 := isIdentNamed(as.Lhs[0], fdRetID.Name); !okL0 {
				continue
			}
			if _, okL1 := isIdentNamed(as.Lhs[1], errRetID.Name); !okL1 {
				continue
			}
			sc, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
			if !okC || sc.Ellipsis.IsValid() || len(sc.Args) < 1 {
				continue
			}
			if _, okSel := isSelectorBaseField(sc.Fun, "syscall", "Open"); okSel {
				if pID, okP := unwrapParens(sc.Args[0]).(*ast.Ident); okP && opPathAliases[pID.Name] && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: opFn.Body.List[idx+1:]}, map[string]bool{fdRetID.Name: true, errRetID.Name: true}) {
					sawSyscallOpen = true
					break
				}
			}
		}
		return sawSyscallOpen
	}

	pathAliases := map[string]bool{p0: true}
	openIdx := -1
	var openErrVar string
	for idx := pos; idx < fConstructIdx-1; idx++ {
		st := fn.Body.List[idx]
		if as, okA := st.(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if pID, okP := unwrapParens(as.Lhs[0]).(*ast.Ident); okP && pID.Name != "" && pID.Name != "_" {
				if flCall, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr); okC && !flCall.Ellipsis.IsValid() && len(flCall.Args) == 1 {
					_, okFL := isIdentNamed(flCall.Fun, "fixLongPath")
					_, okArg := isIdentNamed(flCall.Args[0], p0)
					flFn := allTopFuncs["fixLongPath"]
					if okFL && okArg && flFn != nil && flFn.Body != nil && !osAnyLinknameLocals["fixLongPath"] && !funcShadowsAnyIdent(flFn, osNoFileReserved) && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: fn.Body.List[idx+1:]}, map[string]bool{pID.Name: true}) {
						pathAliases[pID.Name] = true
						continue
					}
				}
			}
		}
		// Form 1: ignoringEINTR(func() error { <wantFDVar>, ..., <eVar> = open(<p0>, ...); return <eVar> })
		if es, okES := st.(*ast.ExprStmt); okES {
			if igCall, okC := unwrapParens(es.X).(*ast.CallExpr); okC && !igCall.Ellipsis.IsValid() && len(igCall.Args) == 1 {
				if _, okIG := isIdentNamed(igCall.Fun, "ignoringEINTR"); okIG && verifyIgnoringEINTR(allTopFuncs["ignoringEINTR"]) && verifyOpenHelper(allTopFuncs["open"]) {
					if fl, okFL := unwrapParens(igCall.Args[0]).(*ast.FuncLit); okFL && fl.Body != nil && len(fl.Body.List) == 2 {
						inAs, okIA := fl.Body.List[0].(*ast.AssignStmt)
						inRet, okIR := fl.Body.List[1].(*ast.ReturnStmt)
						if okIA && okIR && inAs.Tok == token.ASSIGN && len(inAs.Lhs) == 3 && len(inAs.Rhs) == 1 && len(inRet.Results) == 1 {
							_, okFD := isIdentNamed(inAs.Lhs[0], wantFDVar)
							eID, okE := unwrapParens(inAs.Lhs[2]).(*ast.Ident)
							opCall, okOC := unwrapParens(inAs.Rhs[0]).(*ast.CallExpr)
							if okFD && okE && okOC && eID.Name != "" && eID.Name != "_" && eID.Name != wantFDVar && !opCall.Ellipsis.IsValid() && len(opCall.Args) == 3 {
								_, okOpFun := isIdentNamed(opCall.Fun, "open")
								_, okOpArg := isIdentNamed(opCall.Args[0], p0)
								_, okRetE := isIdentNamed(inRet.Results[0], eID.Name)
								if okOpFun && okOpArg && okRetE {
									openIdx = idx
									openErrVar = eID.Name
									break
								}
							}
						}
					}
				}
			}
		}
		// Form 2: <wantFDVar>, <eVar> := syscall.Open(<path>, ...)
		if as, okA := st.(*ast.AssignStmt); okA && (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) == 2 && len(as.Rhs) == 1 && fileImportsSyscall[funcFile[fn]] {
			_, okFD := isIdentNamed(as.Lhs[0], wantFDVar)
			eID, okE := unwrapParens(as.Lhs[1]).(*ast.Ident)
			sc, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
			if okFD && okE && okC && eID.Name != "" && eID.Name != "_" && eID.Name != wantFDVar && !sc.Ellipsis.IsValid() && len(sc.Args) >= 2 {
				if _, okSel := isSelectorBaseField(sc.Fun, "syscall", "Open"); okSel {
					if pArg, okPA := unwrapParens(sc.Args[0]).(*ast.Ident); okPA && pathAliases[pArg.Name] {
						openIdx = idx
						openErrVar = eID.Name
						break
					}
				}
			}
		}
		// Form 3 (Plan 9): if ... { <wantFDVar>, <eVar> = syscall.Create(<p0>, ...) } else { <wantFDVar>, <eVar> = syscall.Open(<p0>, ...); [if IsNotExist(<eVar>) && ... { <wantFDVar>, <eVar> = syscall.Create(<p0>, ...); if <eVar> != nil { return nil, &PathError{...} } }] }
		if ifs, okI := st.(*ast.IfStmt); okI && ifs.Else != nil && fileImportsSyscall[funcFile[fn]] {
			elseBlk, okEB := ifs.Else.(*ast.BlockStmt)
			if okEB && len(ifs.Body.List) == 1 && (len(elseBlk.List) == 1 || len(elseBlk.List) == 2) {
				as1, okA1 := ifs.Body.List[0].(*ast.AssignStmt)
				as2, okA2 := elseBlk.List[0].(*ast.AssignStmt)
				if okA1 && okA2 && as1.Tok == token.ASSIGN && as2.Tok == token.ASSIGN && len(as1.Lhs) == 2 && len(as1.Rhs) == 1 && len(as2.Lhs) == 2 && len(as2.Rhs) == 1 {
					_, okFD1 := isIdentNamed(as1.Lhs[0], wantFDVar)
					_, okFD2 := isIdentNamed(as2.Lhs[0], wantFDVar)
					e1, okE1 := unwrapParens(as1.Lhs[1]).(*ast.Ident)
					e2, okE2 := unwrapParens(as2.Lhs[1]).(*ast.Ident)
					c1, okC1 := unwrapParens(as1.Rhs[0]).(*ast.CallExpr)
					c2, okC2 := unwrapParens(as2.Rhs[0]).(*ast.CallExpr)
					if okFD1 && okFD2 && okE1 && okE2 && okC1 && okC2 && e1.Name != "" && e1.Name != "_" && e1.Name != wantFDVar && e1.Name == e2.Name && !c1.Ellipsis.IsValid() && !c2.Ellipsis.IsValid() && len(c1.Args) >= 1 && len(c2.Args) >= 1 {
						_, okCr := isSelectorBaseField(c1.Fun, "syscall", "Create")
						_, okOp := isSelectorBaseField(c2.Fun, "syscall", "Open")
						_, okP1 := isIdentNamed(c1.Args[0], p0)
						_, okP2 := isIdentNamed(c2.Args[0], p0)
						elseTailOK := len(elseBlk.List) == 1
						if len(elseBlk.List) == 2 {
							subIf, okSI := elseBlk.List[1].(*ast.IfStmt)
							if okSI && subIf.Init == nil && subIf.Else == nil && len(subIf.Body.List) == 2 {
								as3, okA3 := subIf.Body.List[0].(*ast.AssignStmt)
								errSubIf, okEI := subIf.Body.List[1].(*ast.IfStmt)
								if okA3 && okEI && as3.Tok == token.ASSIGN && len(as3.Lhs) == 2 && len(as3.Rhs) == 1 && errSubIf.Init == nil && errSubIf.Else == nil && condChecksNonZeroErr(errSubIf.Cond) == e1.Name && len(errSubIf.Body.List) == 1 {
									_, okFD3 := isIdentNamed(as3.Lhs[0], wantFDVar)
									_, okE3 := isIdentNamed(as3.Lhs[1], e1.Name)
									c3, okC3 := unwrapParens(as3.Rhs[0]).(*ast.CallExpr)
									subRet, okSR := errSubIf.Body.List[0].(*ast.ReturnStmt)
									if okFD3 && okE3 && okC3 && okSR && !c3.Ellipsis.IsValid() && len(c3.Args) >= 1 && isPathErrorReturn(subRet) {
										_, okCr3 := isSelectorBaseField(c3.Fun, "syscall", "Create")
										_, okP3 := isIdentNamed(c3.Args[0], p0)
										elseTailOK = okCr3 && okP3
									}
								}
							}
						}
						if okCr && okOp && okP1 && okP2 && elseTailOK {
							openIdx = idx
							openErrVar = e1.Name
							break
						}
					}
				}
			}
		}
	}
	if openIdx < 0 || openErrVar == "" {
		return fmt.Errorf("os: openFileNolog missing verified syscall.Open acquisition")
	}
	errIf, ok := fn.Body.List[openIdx+1].(*ast.IfStmt)
	if !ok || errIf.Init != nil || errIf.Else != nil || condChecksNonZeroErr(errIf.Cond) != openErrVar || len(errIf.Body.List) != 1 {
		return fmt.Errorf("os: openFileNolog missing error check immediately after open")
	}
	errRet, ok := errIf.Body.List[0].(*ast.ReturnStmt)
	if !ok || !isPathErrorReturn(errRet) {
		return fmt.Errorf("os: openFileNolog error check does not return &PathError")
	}
	if bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: fn.Body.List[openIdx+1 : fConstructIdx]}, map[string]bool{wantFDVar: true}) || bodyDeclaresAnyIdent(&ast.BlockStmt{List: fn.Body.List[openIdx+1:]}, map[string]bool{wantFDVar: true}) {
		return fmt.Errorf("os: openFileNolog mutates or shadows descriptor %s before newFile", wantFDVar)
	}
	return nil
}

func verifyOSReadFile(rfFn *ast.FuncDecl, rfP0 string, allTopFuncs, allFileMethods, allRawFileMethods map[string]*ast.FuncDecl, osNoFileReserved, osAnyLinknameLocals map[string]bool, skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool) error {
	if len(rfFn.Body.List) != 4 {
		return fmt.Errorf("os: ReadFile must have canonical 4-statement Open/Close/readFileContents body")
	}
	s0, ok0 := rfFn.Body.List[0].(*ast.AssignStmt)
	s1, ok1 := rfFn.Body.List[1].(*ast.IfStmt)
	s2, ok2 := rfFn.Body.List[2].(*ast.DeferStmt)
	s3, ok3 := rfFn.Body.List[3].(*ast.ReturnStmt)
	if !ok0 || (s0.Tok != token.DEFINE && s0.Tok != token.ASSIGN) || len(s0.Lhs) != 2 || len(s0.Rhs) != 1 || !ok1 || s1.Init != nil || s1.Else != nil || len(s1.Body.List) != 1 || !ok2 || !ok3 || len(s3.Results) != 1 {
		return fmt.Errorf("os: ReadFile invalid canonical body shape")
	}
	fID, okF := unwrapParens(s0.Lhs[0]).(*ast.Ident)
	eID, okE := unwrapParens(s0.Lhs[1]).(*ast.Ident)
	openCall, okOC := unwrapParens(s0.Rhs[0]).(*ast.CallExpr)
	if !okF || !okE || !okOC || fID.Name == "" || fID.Name == "_" || eID.Name == "" || eID.Name == "_" || fID.Name == eID.Name || openCall.Ellipsis.IsValid() || len(openCall.Args) != 1 {
		return fmt.Errorf("os: ReadFile first statement must be f, err := Open(%s)", rfP0)
	}
	_, okOpenFun := isIdentNamed(openCall.Fun, "Open")
	_, okOpenArg := isIdentNamed(openCall.Args[0], rfP0)
	if !okOpenFun || !okOpenArg || condChecksNonZeroErr(s1.Cond) != eID.Name {
		return fmt.Errorf("os: ReadFile Open call or error guard invalid")
	}
	errRet, okER := s1.Body.List[0].(*ast.ReturnStmt)
	if !okER || len(errRet.Results) != 2 {
		return fmt.Errorf("os: ReadFile error guard invalid return")
	}
	_, okNil0 := isIdentNamed(errRet.Results[0], "nil")
	_, okErr1 := isIdentNamed(errRet.Results[1], eID.Name)
	if !okNil0 || !okErr1 {
		return fmt.Errorf("os: ReadFile error guard does not return nil, %s", eID.Name)
	}
	if _, okClose := isZeroArgMethodCallOnIdent(s2.Call, fID.Name, "Close"); !okClose {
		return fmt.Errorf("os: ReadFile missing defer %s.Close()", fID.Name)
	}
	rfcCall, okRFC := unwrapParens(s3.Results[0]).(*ast.CallExpr)
	if !okRFC || rfcCall.Ellipsis.IsValid() || len(rfcCall.Args) != 2 {
		return fmt.Errorf("os: ReadFile final return is not readFileContents(statOrZero(f), f.Read)")
	}
	if _, okRFCFun := isIdentNamed(rfcCall.Fun, "readFileContents"); !okRFCFun {
		return fmt.Errorf("os: ReadFile does not call readFileContents")
	}
	sozCall, okSOZ := unwrapParens(rfcCall.Args[0]).(*ast.CallExpr)
	if !okSOZ || sozCall.Ellipsis.IsValid() || len(sozCall.Args) != 1 {
		return fmt.Errorf("os: ReadFile first arg to readFileContents is not statOrZero(%s)", fID.Name)
	}
	_, okSOZFun := isIdentNamed(sozCall.Fun, "statOrZero")
	_, okSOZArg := isIdentNamed(sozCall.Args[0], fID.Name)
	_, okReadSel := isSelectorBaseField(rfcCall.Args[1], fID.Name, "Read")
	if !okSOZFun || !okSOZArg || !okReadSel {
		return fmt.Errorf("os: ReadFile arguments to readFileContents are not (statOrZero(%s), %s.Read)", fID.Name, fID.Name)
	}

	type workItem struct {
		kind       string // "top", "file", "raw"
		name       string
		arg0IsFile bool
	}
	queue := []workItem{
		{kind: "top", name: "readFileContents"},
		{kind: "top", name: "statOrZero", arg0IsFile: true},
		{kind: "file", name: "Read"},
	}
	seen := map[workItem]bool{}
	enqueue := func(it workItem) {
		if !seen[it] {
			seen[it] = true
			queue = append(queue, it)
		}
	}
	for _, it := range queue {
		seen[it] = true
	}

	forbiddenTopCalls := map[string]bool{
		"Open": true, "OpenFile": true, "Create": true, "Stat": true, "Lstat": true,
		"Getenv": true, "LookupEnv": true, "Chdir": true, "ReadDir": true, "openDir": true,
		"Exit": true, "NewFile": true, "newFile": true,
	}
	forbiddenSyscallSels := map[string]bool{
		"Open": true, "Creat": true, "Stat": true, "Lstat": true,
		"Chdir": true, "Fchdir": true, "Getenv": true, "Exit": true, "ExitProcess": true,
	}
	collectPtrTypeIdents := func(fl *ast.FieldList, targetType string, dst map[string]bool) {
		if fl == nil {
			return
		}
		for _, fld := range fl.List {
			star, okS := unwrapParens(fld.Type).(*ast.StarExpr)
			if !okS {
				continue
			}
			if _, okT := isIdentNamed(star.X, targetType); !okT {
				continue
			}
			for _, id := range fld.Names {
				if id.Name != "" && id.Name != "_" {
					dst[id.Name] = true
				}
			}
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		var hFn *ast.FuncDecl
		switch cur.kind {
		case "top":
			hFn = allTopFuncs[cur.name]
		case "file":
			hFn = allFileMethods[cur.name]
		case "raw":
			hFn = allRawFileMethods[cur.name]
		}
		if hFn == nil || hFn.Body == nil || osAnyLinknameLocals[cur.name] || funcShadowsAnyIdent(hFn, map[string]bool{"testlog": true, "syscall": true}) {
			return fmt.Errorf("os: ReadFile helper %s:%s missing, bodyless, linknamed, or shadowing reserved identifier", cur.kind, cur.name)
		}
		fileVars := map[string]bool{}
		rawFileVars := map[string]bool{}
		collectPtrTypeIdents(hFn.Recv, "File", fileVars)
		collectPtrTypeIdents(hFn.Type.Params, "File", fileVars)
		collectPtrTypeIdents(hFn.Recv, "file", rawFileVars)
		collectPtrTypeIdents(hFn.Type.Params, "file", rawFileVars)
		if cur.arg0IsFile && cur.kind == "top" {
			hParams := paramNamesFlat(hFn.Type.Params)
			if len(hParams) >= 1 && hParams[0] != "" && hParams[0] != "_" && !bodyMutatesOrTakesAddrOfAny(hFn.Body, map[string]bool{hParams[0]: true}) && !bodyDeclaresAnyIdent(hFn.Body, map[string]bool{hParams[0]: true}) {
				fileVars[hParams[0]] = true
			}
		}

		pos := 0
		for pos < len(hFn.Body.List) && skipInactiveHookIf(hFn.Body.List[pos], hFn) {
			pos++
		}
		var helperErr error
		var inspectHelperNode func(n ast.Node, curFileVars map[string]bool)
		inspectHelperNode = func(n ast.Node, curFileVars map[string]bool) {
			if helperErr != nil || n == nil {
				return
			}
			if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, hFn) {
				return
			}
			if ts, okTS := n.(*ast.TypeSwitchStmt); okTS {
				var switchTarget string
				var boundName string
				switch as := ts.Assign.(type) {
				case *ast.ExprStmt:
					if ta, okTA := unwrapParens(as.X).(*ast.TypeAssertExpr); okTA && ta.Type == nil {
						if id, okID := unwrapParens(ta.X).(*ast.Ident); okID {
							switchTarget = id.Name
						}
					}
				case *ast.AssignStmt:
					if as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						if lhsID, okL := unwrapParens(as.Lhs[0]).(*ast.Ident); okL {
							if ta, okTA := unwrapParens(as.Rhs[0]).(*ast.TypeAssertExpr); okTA && ta.Type == nil {
								if id, okID := unwrapParens(ta.X).(*ast.Ident); okID {
									switchTarget = id.Name
									boundName = lhsID.Name
								}
							}
						}
					}
				}
				if switchTarget != "" && curFileVars[switchTarget] && ts.Init == nil && ts.Body != nil {
					for _, rawClause := range ts.Body.List {
						cc, okCC := rawClause.(*ast.CaseClause)
						if !okCC {
							continue
						}
						if len(cc.List) == 1 {
							star, okS := unwrapParens(cc.List[0]).(*ast.StarExpr)
							if okS {
								if _, okF := isIdentNamed(star.X, "File"); okF {
									nextFV := maps.Clone(curFileVars)
									if boundName != "" && boundName != "_" {
										nextFV[boundName] = true
									}
									for _, bs := range cc.Body {
										inspectHelperNode(bs, nextFV)
									}
									continue
								}
							}
							if cID, okID := unwrapParens(cc.List[0]).(*ast.Ident); okID && (cID.Name == "string" || cID.Name == "int" || cID.Name == "uintptr") {
								continue
							}
						}
						for _, bs := range cc.Body {
							inspectHelperNode(bs, curFileVars)
						}
					}
					return
				}
			}
			switch x := n.(type) {
			case *ast.Ident:
				if x.Name == "testlog" {
					helperErr = fmt.Errorf("os: ReadFile helper %s:%s references testlog", cur.kind, cur.name)
					return
				}
			case *ast.SelectorExpr:
				if baseID, okB := unwrapParens(x.X).(*ast.Ident); okB {
					if baseID.Name == "syscall" && forbiddenSyscallSels[x.Sel.Name] {
						helperErr = fmt.Errorf("os: ReadFile helper %s:%s references syscall.%s", cur.kind, cur.name, x.Sel.Name)
						return
					}
					if curFileVars[baseID.Name] && x.Sel.Name != "Close" {
						if allFileMethods[x.Sel.Name] != nil {
							enqueue(workItem{kind: "file", name: x.Sel.Name})
						} else if allRawFileMethods[x.Sel.Name] != nil {
							enqueue(workItem{kind: "raw", name: x.Sel.Name})
						}
					}
					if rawFileVars[baseID.Name] && x.Sel.Name != "close" && allRawFileMethods[x.Sel.Name] != nil {
						enqueue(workItem{kind: "raw", name: x.Sel.Name})
					}
				} else if innerSel, okIS := unwrapParens(x.X).(*ast.SelectorExpr); okIS && innerSel.Sel.Name == "file" {
					if baseID, okB := unwrapParens(innerSel.X).(*ast.Ident); okB && curFileVars[baseID.Name] && x.Sel.Name != "close" && allRawFileMethods[x.Sel.Name] != nil {
						enqueue(workItem{kind: "raw", name: x.Sel.Name})
					}
				}
			case *ast.CallExpr:
				if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
					if forbiddenTopCalls[cID.Name] {
						helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls forbidden %s", cur.kind, cur.name, cID.Name)
						return
					}
					if osAnyLinknameLocals[cID.Name] {
						helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls linknamed %s", cur.kind, cur.name, cID.Name)
						return
					}
					if allTopFuncs[cID.Name] != nil {
						a0File := false
						if !x.Ellipsis.IsValid() && len(x.Args) >= 1 {
							if aID, okA := unwrapParens(x.Args[0]).(*ast.Ident); okA && curFileVars[aID.Name] {
								a0File = true
							}
						}
						enqueue(workItem{kind: "top", name: cID.Name, arg0IsFile: a0File})
					}
				} else if cSel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
					if baseID, okB := unwrapParens(cSel.X).(*ast.Ident); okB {
						if curFileVars[baseID.Name] && cSel.Sel.Name != "Close" {
							if allFileMethods[cSel.Sel.Name] != nil {
								enqueue(workItem{kind: "file", name: cSel.Sel.Name})
							} else if allRawFileMethods[cSel.Sel.Name] != nil {
								enqueue(workItem{kind: "raw", name: cSel.Sel.Name})
							} else {
								helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls unknown *File method %s", cur.kind, cur.name, cSel.Sel.Name)
								return
							}
						}
						if rawFileVars[baseID.Name] && cSel.Sel.Name != "close" {
							if allRawFileMethods[cSel.Sel.Name] == nil {
								helperErr = fmt.Errorf("os: ReadFile helper %s:%s calls unknown *file method %s", cur.kind, cur.name, cSel.Sel.Name)
								return
							}
							enqueue(workItem{kind: "raw", name: cSel.Sel.Name})
						}
					}
				}
			}
			ast.Inspect(n, func(ch ast.Node) bool {
				if ch == n {
					return true
				}
				inspectHelperNode(ch, curFileVars)
				return false
			})
		}
		for _, st := range hFn.Body.List[pos:] {
			inspectHelperNode(st, fileVars)
			if helperErr != nil {
				return helperErr
			}
		}
	}
	return nil
}

func verifyOSIgnoringEINTR(igFn *ast.FuncDecl, funcFile map[*ast.FuncDecl]*ast.File, fileImportsSyscall map[*ast.File]bool, osNoFileReserved, osAnyLinknameLocals map[string]bool) bool {
	if osAnyLinknameLocals["ignoringEINTR"] {
		return false
	}
	return VerifyIgnoringEINTRHelper(igFn, fileImportsSyscall[funcFile[igFn]], osNoFileReserved, 1)
}
