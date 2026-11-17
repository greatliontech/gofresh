package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"slices"
)

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

func verifyOSSameFile(
	allTopFuncs map[string]*ast.FuncDecl,
	nonAliasStructSpecs map[string]*ast.TypeSpec,
	pkgDeclCounts map[string]int,
	osReserved, osNoFileReserved, osAnyLinknameLocals map[string]bool,
	osInactive *osInactiveState,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
) (string, error) {
	sf := allTopFuncs["SameFile"]
	if sf == nil || sf.Body == nil || sf.Type == nil || sf.Type.TypeParams != nil || !funcHasUnnamedResults(sf.Type, 1) || pkgDeclCounts["SameFile"] != 1 || osAnyLinknameLocals["SameFile"] || funcShadowsAnyIdent(sf, osReserved) || bodyHasControlFlowOrRecoverBypass(sf.Body) {
		return "", fmt.Errorf("os: invalid SameFile helper")
	}
	if _, okBool := isIdentNamed(sf.Type.Results.List[0].Type, "bool"); !okBool {
		return "", fmt.Errorf("os: SameFile does not return bool")
	}
	sfParams := paramNamesFlat(sf.Type.Params)
	if len(sfParams) != 2 || sfParams[0] == "" || sfParams[0] == "_" || sfParams[1] == "" || sfParams[1] == "_" || sfParams[0] == sfParams[1] || bodyMutatesOrTakesAddrOfAny(sf.Body, map[string]bool{sfParams[0]: true, sfParams[1]: true}) {
		return "", fmt.Errorf("os: SameFile invalid parameters")
	}
	if nonAliasStructSpecs["fileStat"] == nil || pkgDeclCounts["fileStat"] != 1 {
		return "", fmt.Errorf("os: missing unique fileStat struct definition")
	}

	matchPtrStructTypeAssert := func(st ast.Stmt, wantParam string) (string, string, string, bool) {
		as, okA := st.(*ast.AssignStmt)
		if !okA || as.Tok != token.DEFINE || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
			return "", "", "", false
		}
		vID, okV := unwrapParens(as.Lhs[0]).(*ast.Ident)
		okID, okO := unwrapParens(as.Lhs[1]).(*ast.Ident)
		ta, okTA := unwrapParens(as.Rhs[0]).(*ast.TypeAssertExpr)
		if !okV || !okO || !okTA || ta.Type == nil || vID.Name == "" || vID.Name == "_" || okID.Name == "" || okID.Name == "_" || vID.Name == okID.Name {
			return "", "", "", false
		}
		if _, okX := isIdentNamed(ta.X, wantParam); !okX {
			return "", "", "", false
		}
		star, okS := unwrapParens(ta.Type).(*ast.StarExpr)
		if !okS {
			return "", "", "", false
		}
		tID, okT := unwrapParens(star.X).(*ast.Ident)
		if !okT || tID.Name == "" {
			return "", "", "", false
		}
		return vID.Name, okID.Name, tID.Name, true
	}

	pos := 0
	for pos < len(sf.Body.List) && skipInactiveHookIf(sf.Body.List[pos], sf) {
		pos++
	}

	var disjointAltStruct string
	if pos < len(sf.Body.List) {
		var candInner *ast.IfStmt
		if outerIf, okOut := sf.Body.List[pos].(*ast.IfStmt); okOut && outerIf.Else == nil {
			if outerIf.Init != nil {
				candInner = outerIf
			} else if cID, okC := unwrapParens(outerIf.Cond).(*ast.Ident); okC && (cID.Name == "true" || (osInactive != nil && osInactive.trueConsts[cID.Name])) && !funcShadowsAnyIdent(sf, map[string]bool{cID.Name: true}) && len(outerIf.Body.List) == 1 {
				if inIf, okIn := outerIf.Body.List[0].(*ast.IfStmt); okIn && inIf.Else == nil {
					candInner = inIf
				}
			}
		}
		if candInner != nil && candInner.Init != nil && len(candInner.Body.List) == 1 {
			initAs, okIA := candInner.Init.(*ast.AssignStmt)
			retSt, okRS := candInner.Body.List[0].(*ast.ReturnStmt)
			if okIA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 2 && len(initAs.Rhs) == 1 && okRS && len(retSt.Results) == 1 {
				sID, okS := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
				hID, okH := unwrapParens(initAs.Lhs[1]).(*ast.Ident)
				hc, okHC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
				if okS && okH && okHC && !hc.Ellipsis.IsValid() && len(hc.Args) == 2 && sID.Name != "" && sID.Name != "_" && hID.Name != "" && hID.Name != "_" && sID.Name != hID.Name {
					_, okCond := isIdentNamed(candInner.Cond, hID.Name)
					_, okRet := isIdentNamed(retSt.Results[0], sID.Name)
					_, okA0 := isIdentNamed(hc.Args[0], sfParams[0])
					_, okA1 := isIdentNamed(hc.Args[1], sfParams[1])
					calleeID, okCallee := unwrapParens(hc.Fun).(*ast.Ident)
					if okCond && okRet && okA0 && okA1 && okCallee && !ast.IsExported(calleeID.Name) && pkgDeclCounts[calleeID.Name] == 1 && !osAnyLinknameLocals[calleeID.Name] && !funcShadowsAnyIdent(sf, map[string]bool{calleeID.Name: true}) {
						hFn := allTopFuncs[calleeID.Name]
						if hFn != nil && hFn.Body != nil && hFn.Type != nil && hFn.Type.TypeParams == nil && hFn.Type.Results != nil && hFn.Type.Results.NumFields() == 2 && !funcShadowsAnyIdent(hFn, map[string]bool{"false": true, "bool": true}) && !bodyHasControlFlowOrRecoverBypass(hFn.Body) {
							resAllBool := true
							hResNames := map[string]bool{}
							for _, fld := range hFn.Type.Results.List {
								if _, okB := isIdentNamed(fld.Type, "bool"); !okB {
									resAllBool = false
									break
								}
								for _, id := range fld.Names {
									hResNames[id.Name] = true
								}
							}
							qParams := paramNamesFlat(hFn.Type.Params)
							if resAllBool && len(qParams) == 2 && qParams[0] != "" && qParams[0] != "_" && qParams[1] != "" && qParams[1] != "_" && qParams[0] != qParams[1] && !bodyMutatesOrTakesAddrOfAny(hFn.Body, map[string]bool{qParams[0]: true, qParams[1]: true}) {
								hPos := 0
								for hPos < len(hFn.Body.List) && skipInactiveHookIf(hFn.Body.List[hPos], hFn) {
									hPos++
								}
								if hPos+3 <= len(hFn.Body.List) {
									d1, ok1, st1, m1 := matchPtrStructTypeAssert(hFn.Body.List[hPos], qParams[0])
									d2, ok2, st2, m2 := matchPtrStructTypeAssert(hFn.Body.List[hPos+1], qParams[1])
									gIf, okGI := hFn.Body.List[hPos+2].(*ast.IfStmt)
									distinctLocals := d1 != d2 && d1 != ok2 && ok1 != d2 && ok1 != ok2 && !hResNames[d1] && !hResNames[ok1] && !hResNames[d2] && !hResNames[ok2] && d1 != qParams[0] && d1 != qParams[1] && ok1 != qParams[0] && ok1 != qParams[1] && d2 != qParams[0] && d2 != qParams[1] && ok2 != qParams[0] && ok2 != qParams[1]
									if m1 && m2 && distinctLocals && st1 == st2 && !ast.IsExported(st1) && st1 != "fileStat" && nonAliasStructSpecs[st1] != nil && pkgDeclCounts[st1] == 1 && okGI && gIf.Init == nil && gIf.Else == nil && len(gIf.Body.List) == 1 {
										binAnd, okBA := unwrapParens(gIf.Cond).(*ast.BinaryExpr)
										gRet, okGR := gIf.Body.List[0].(*ast.ReturnStmt)
										if okBA && binAnd.Op == token.LAND && okGR && len(gRet.Results) == 2 {
											uL, okUL := unwrapParens(binAnd.X).(*ast.UnaryExpr)
											uR, okUR := unwrapParens(binAnd.Y).(*ast.UnaryExpr)
											_, okF0 := isIdentNamed(gRet.Results[0], "false")
											_, okF1 := isIdentNamed(gRet.Results[1], "false")
											if okUL && okUR && uL.Op == token.NOT && uR.Op == token.NOT && okF0 && okF1 {
												_, l1 := isIdentNamed(uL.X, ok1)
												_, r2 := isIdentNamed(uR.X, ok2)
												_, l2 := isIdentNamed(uL.X, ok2)
												_, r1 := isIdentNamed(uR.X, ok1)
												if (l1 && r2) || (l2 && r1) {
													disjointAltStruct = st1
													pos++
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	rem := sf.Body.List[pos:]
	if len(rem) != 4 {
		return "", fmt.Errorf("os: SameFile unexpected statement count %d", len(rem))
	}
	fs1, ok1, st1, m1 := matchPtrStructTypeAssert(rem[0], sfParams[0])
	fs2, ok2, st2, m2 := matchPtrStructTypeAssert(rem[1], sfParams[1])
	if !m1 || !m2 || st1 != "fileStat" || st2 != "fileStat" || fs1 == fs2 || fs1 == ok2 || ok1 == fs2 || ok1 == ok2 {
		return "", fmt.Errorf("os: SameFile missing (*fileStat) type assertions")
	}
	gIf, okGI := rem[2].(*ast.IfStmt)
	if !okGI || gIf.Init != nil || gIf.Else != nil || len(gIf.Body.List) != 1 {
		return "", fmt.Errorf("os: SameFile missing (!ok1 || !ok2) guard")
	}
	binOr, okBO := unwrapParens(gIf.Cond).(*ast.BinaryExpr)
	gRet, okGR := gIf.Body.List[0].(*ast.ReturnStmt)
	if !okBO || binOr.Op != token.LOR || !okGR || len(gRet.Results) != 1 {
		return "", fmt.Errorf("os: SameFile invalid (!ok1 || !ok2) guard")
	}
	uL, okUL := unwrapParens(binOr.X).(*ast.UnaryExpr)
	uR, okUR := unwrapParens(binOr.Y).(*ast.UnaryExpr)
	_, okFalse := isIdentNamed(gRet.Results[0], "false")
	if !okUL || !okUR || uL.Op != token.NOT || uR.Op != token.NOT || !okFalse {
		return "", fmt.Errorf("os: SameFile guard does not return false on !ok1 || !ok2")
	}
	_, l1 := isIdentNamed(uL.X, ok1)
	_, r2 := isIdentNamed(uR.X, ok2)
	_, l2 := isIdentNamed(uL.X, ok2)
	_, r1 := isIdentNamed(uR.X, ok1)
	if !((l1 && r2) || (l2 && r1)) {
		return "", fmt.Errorf("os: SameFile guard does not check (!%s || !%s)", ok1, ok2)
	}
	lastRet, okLR := rem[3].(*ast.ReturnStmt)
	if !okLR || len(lastRet.Results) != 1 {
		return "", fmt.Errorf("os: SameFile missing final return")
	}
	smCall, okSMC := unwrapParens(lastRet.Results[0]).(*ast.CallExpr)
	if !okSMC || smCall.Ellipsis.IsValid() || len(smCall.Args) != 2 {
		return "", fmt.Errorf("os: SameFile final return does not call sameFile")
	}
	_, okSMFun := isIdentNamed(smCall.Fun, "sameFile")
	_, c01 := isIdentNamed(smCall.Args[0], fs1)
	_, c12 := isIdentNamed(smCall.Args[1], fs2)
	_, c02 := isIdentNamed(smCall.Args[0], fs2)
	_, c11 := isIdentNamed(smCall.Args[1], fs1)
	if !okSMFun || !((c01 && c12) || (c02 && c11)) {
		return "", fmt.Errorf("os: SameFile does not delegate to sameFile(%s, %s)", fs1, fs2)
	}

	// Verify platform sameFile(fs1, fs2 *fileStat) bool compares corresponding fields across both arguments.
	sm := allTopFuncs["sameFile"]
	if sm == nil || sm.Body == nil || sm.Type == nil || sm.Type.TypeParams != nil || !funcHasUnnamedResults(sm.Type, 1) || pkgDeclCounts["sameFile"] != 1 || osAnyLinknameLocals["sameFile"] || funcShadowsAnyIdent(sm, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(sm.Body) || len(sm.Body.List) == 0 {
		return "", fmt.Errorf("os: invalid sameFile implementation")
	}
	if _, okBool := isIdentNamed(sm.Type.Results.List[0].Type, "bool"); !okBool {
		return "", fmt.Errorf("os: sameFile does not return bool")
	}
	smParams := paramNamesFlat(sm.Type.Params)
	if len(smParams) != 2 || smParams[0] == "" || smParams[0] == "_" || smParams[1] == "" || smParams[1] == "_" || smParams[0] == smParams[1] || bodyMutatesOrTakesAddrOfAny(sm.Body, map[string]bool{smParams[0]: true, smParams[1]: true}) {
		return "", fmt.Errorf("os: sameFile invalid parameters")
	}
	for _, fld := range sm.Type.Params.List {
		star, okS := unwrapParens(fld.Type).(*ast.StarExpr)
		if !okS {
			return "", fmt.Errorf("os: sameFile parameter is not *fileStat")
		}
		if _, okFS := isIdentNamed(star.X, "fileStat"); !okFS {
			return "", fmt.Errorf("os: sameFile parameter is not *fileStat")
		}
	}

	side0 := map[string]bool{smParams[0]: true}
	side1 := map[string]bool{smParams[1]: true}
	errVars := map[string]bool{}
	for _, st := range sm.Body.List[:len(sm.Body.List)-1] {
		switch s := st.(type) {
		case *ast.AssignStmt:
			if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
				return "", fmt.Errorf("os: sameFile unexpected assignment")
			}
			lhsID, okL := unwrapParens(s.Lhs[0]).(*ast.Ident)
			if !okL || lhsID.Name == "" || lhsID.Name == "_" || side0[lhsID.Name] || side1[lhsID.Name] {
				return "", fmt.Errorf("os: sameFile invalid local assignment")
			}
			if ta, okTA := unwrapParens(s.Rhs[0]).(*ast.TypeAssertExpr); okTA && s.Tok == token.DEFINE && ta.Type != nil {
				sel, okSel := unwrapParens(ta.X).(*ast.SelectorExpr)
				if !okSel {
					return "", fmt.Errorf("os: sameFile invalid type assertion target")
				}
				bID, okB := unwrapParens(sel.X).(*ast.Ident)
				if !okB || (!side0[bID.Name] && !side1[bID.Name]) {
					return "", fmt.Errorf("os: sameFile type assertion not rooted on parameter")
				}
				if side0[bID.Name] {
					side0[lhsID.Name] = true
				} else {
					side1[lhsID.Name] = true
				}
				continue
			}
			if c, okC := unwrapParens(s.Rhs[0]).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 0 {
				if sel, okSel := unwrapParens(c.Fun).(*ast.SelectorExpr); okSel && sel.Sel.Name == "loadFileId" {
					if bID, okB := unwrapParens(sel.X).(*ast.Ident); okB && (bID.Name == smParams[0] || bID.Name == smParams[1]) {
						errVars[lhsID.Name] = true
						continue
					}
				}
			}
			return "", fmt.Errorf("os: sameFile unexpected helper statement")
		case *ast.IfStmt:
			eVar := condChecksNonZeroErr(s.Cond)
			if s.Init != nil || s.Else != nil || !errVars[eVar] || len(s.Body.List) != 1 {
				return "", fmt.Errorf("os: sameFile unexpected guard statement")
			}
			r, okR := s.Body.List[0].(*ast.ReturnStmt)
			if !okR || len(r.Results) != 1 {
				return "", fmt.Errorf("os: sameFile guard does not return false")
			}
			if _, okF := isIdentNamed(r.Results[0], "false"); !okF {
				return "", fmt.Errorf("os: sameFile guard does not return false")
			}
		default:
			return "", fmt.Errorf("os: sameFile unexpected statement before return")
		}
	}

	extractSideFieldChain := func(expr ast.Expr) (int, []string, bool) {
		var fields []string
		cur := unwrapParens(expr)
		for {
			sel, okS := cur.(*ast.SelectorExpr)
			if !okS {
				break
			}
			fields = append(fields, sel.Sel.Name)
			cur = unwrapParens(sel.X)
		}
		if len(fields) == 0 {
			return -1, nil, false
		}
		id, okID := cur.(*ast.Ident)
		if !okID {
			return -1, nil, false
		}
		slices.Reverse(fields)
		if side0[id.Name] {
			return 0, fields, true
		}
		if side1[id.Name] {
			return 1, fields, true
		}
		return -1, nil, false
	}
	var verifyEqConj func(expr ast.Expr) bool
	verifyEqConj = func(expr ast.Expr) bool {
		bin, okB := unwrapParens(expr).(*ast.BinaryExpr)
		if !okB {
			return false
		}
		if bin.Op == token.LAND {
			return verifyEqConj(bin.X) && verifyEqConj(bin.Y)
		}
		if bin.Op != token.EQL {
			return false
		}
		sL, fL, okL := extractSideFieldChain(bin.X)
		sR, fR, okR := extractSideFieldChain(bin.Y)
		return okL && okR && sL != sR && slices.Equal(fL, fR)
	}

	smRet, okSMR := sm.Body.List[len(sm.Body.List)-1].(*ast.ReturnStmt)
	if !okSMR || len(smRet.Results) != 1 || !verifyEqConj(smRet.Results[0]) {
		return "", fmt.Errorf("os: sameFile return does not compare corresponding fields of both fileStat values")
	}
	return disjointAltStruct, nil
}

