package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"slices"
	"strconv"
)

func verifyOSGetwdClimbBodyAndHelpers(
	files []*ast.File,
	gwFn *ast.FuncDecl,
	gwStmts []ast.Stmt,
	topParentLoop *ast.ForStmt,
	topParentLoopIdx int,
	sawSyscallGetwd bool,
	usedGetwdCache, usedIgnoringEINTR2, usedNewSyscallError, usedOpenDirNolog bool,
	usedSameFile, usedStatHelpers, usedFstatNolog, usedFileStatInGetwd bool,
	allowedReturns map[*ast.ReturnStmt]bool,
	allowedSyscallGetwdSels map[*ast.SelectorExpr]bool,
	dotVars, rootVars, fdVarsInLoop, pdVarsInLoop, parentLoopVars, shape2ReturnedDirVars map[string]bool,
	dotSeedAssigns, rootSeedAssigns, fdSeedAssigns, pdSeedAssigns map[*ast.AssignStmt]bool,
	parentInitAssigns, parentStepAssigns, shape1Assigns map[*ast.AssignStmt]bool,
	allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods map[string]*ast.FuncDecl,
	nonAliasStructSpecs map[string]*ast.TypeSpec,
	pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts map[string]int,
	funcFile map[*ast.FuncDecl]*ast.File,
	fileImportsSyscall map[*ast.File]bool,
	osReserved, osNoFileReserved, osAnyLinknameLocals map[string]bool,
	osInactive *osInactiveState,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
	stmtUnwrapLabel func(ast.Stmt) ast.Stmt,
	isSameFileCallPair func(ast.Expr) (string, string, bool),
	collectCompoundStmtMutations func(ast.Node, map[string]bool, map[string]bool),
	stmtsMutateIdentBefore func([]ast.Stmt, ast.Node, string) bool,
) error {
	// Verify Shape 5 if the trailing statement of Getwd is `return <dirVar>, nil`.
	shape5Verified := false
	shape5DirVar := ""
	if lastRet, okLR := stmtUnwrapLabel(gwStmts[len(gwStmts)-1]).(*ast.ReturnStmt); okLR && !allowedReturns[lastRet] {
		if len(lastRet.Results) == 2 {
			dirID, okD := unwrapParens(lastRet.Results[0]).(*ast.Ident)
			_, okNil := isIdentNamed(lastRet.Results[1], "nil")
			if okD && okNil && dirID.Name != "" && dirID.Name != "_" && topParentLoop != nil && topParentLoopIdx >= 1 {
				resetAs, okRA := stmtUnwrapLabel(gwStmts[topParentLoopIdx-1]).(*ast.AssignStmt)
				resetOK := false
				if okRA && (resetAs.Tok == token.ASSIGN || resetAs.Tok == token.DEFINE) && len(resetAs.Lhs) == 1 && len(resetAs.Rhs) == 1 {
					_, okLHS := isIdentNamed(resetAs.Lhs[0], dirID.Name)
					lit, okLit := unwrapParens(resetAs.Rhs[0]).(*ast.BasicLit)
					resetOK = okLHS && okLit && lit.Kind == token.STRING && lit.Value == `""`
				}
				afterUnmutated := !stmtsMutateIdentBefore(gwStmts[topParentLoopIdx+1:], lastRet, dirID.Name)
				if resetOK && afterUnmutated {
					// Verify outer loop break guards and all assignments to dirID inside topParentLoop.
					loopOK := len(dotVars) > 0 && len(rootVars) > 0
					sawClimbAssign := false
					var checkOuterLoop func(stmts []ast.Stmt, encIfs []*ast.IfStmt, nestedLoop bool, validNamesVars, lstatVars, rangeElemVars map[string]bool)
					checkOuterLoop = func(stmts []ast.Stmt, encIfs []*ast.IfStmt, nestedLoop bool, validNamesVars, lstatVars, rangeElemVars map[string]bool) {
						if !loopOK {
							return
						}
						curNames := maps.Clone(validNamesVars)
						curLstat := maps.Clone(lstatVars)
						for i, raw := range stmts {
							if _, isLbl := raw.(*ast.LabeledStmt); isLbl {
								clear(curNames)
								clear(curLstat)
							}
							s := stmtUnwrapLabel(raw)
							if ds, okDS := s.(*ast.DeclStmt); okDS {
								if gd, okGD := ds.Decl.(*ast.GenDecl); okGD {
									for _, spec := range gd.Specs {
										if vs, okVS := spec.(*ast.ValueSpec); okVS {
											for _, id := range vs.Names {
												delete(curNames, id.Name)
												delete(curLstat, id.Name)
												if rangeElemVars[id.Name] || id.Name == dirID.Name {
													loopOK = false
													return
												}
											}
										}
									}
								}
							}
							if as, okA := s.(*ast.AssignStmt); okA {
								for _, lhs := range as.Lhs {
									if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
										delete(curNames, id.Name)
										delete(curLstat, id.Name)
										if rangeElemVars[id.Name] {
											loopOK = false
											return
										}
									}
								}
								// Track `names, err := fd.Readdirnames(...)` guarded by `if err != nil { ... return ... }`.
								if (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
									nID, okN := unwrapParens(as.Lhs[0]).(*ast.Ident)
									eID, okE := unwrapParens(as.Lhs[1]).(*ast.Ident)
									rc, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
									if okN && okE && okC && !rc.Ellipsis.IsValid() && nID.Name != "" && nID.Name != "_" && nID.Name != eID.Name {
										if sel, okS := unwrapParens(rc.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Readdirnames" && eID.Name != "" && eID.Name != "_" && i+1 < len(stmts) {
											if fdID, okFD := unwrapParens(sel.X).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
												if gIf, okGI := stmts[i+1].(*ast.IfStmt); okGI && gIf.Init == nil && gIf.Else == nil && condChecksNonZeroErr(gIf.Cond) == eID.Name && len(gIf.Body.List) > 0 {
													if _, okLastRet := gIf.Body.List[len(gIf.Body.List)-1].(*ast.ReturnStmt); okLastRet {
														curNames[nID.Name] = true
													}
												}
											}
										}
										if _, okLS := isIdentNamed(rc.Fun, "lstatNolog"); okLS && len(rc.Args) == 1 {
											usedStatHelpers = true
											curLstat[nID.Name] = true
										}
									}
								}
								for idxLHS, lhs := range as.Lhs {
									if _, okT := isIdentNamed(lhs, dirID.Name); okT {
										if as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || idxLHS != 0 {
											loopOK = false
											return
										}
										// Must be `"/" + <rangeElem> + <dirVar>` inside `if SameFile(<lstatVar>, <dotVar>)`.
										addOuter, okAO := unwrapParens(as.Rhs[0]).(*ast.BinaryExpr)
										if !okAO || addOuter.Op != token.ADD {
											loopOK = false
											return
										}
										addInner, okAI := unwrapParens(addOuter.X).(*ast.BinaryExpr)
										_, okTail := isIdentNamed(addOuter.Y, dirID.Name)
										if !okAI || addInner.Op != token.ADD || !okTail {
											loopOK = false
											return
										}
										slashLit, okSL := unwrapParens(addInner.X).(*ast.BasicLit)
										elemID, okEL := unwrapParens(addInner.Y).(*ast.Ident)
										if !okSL || slashLit.Kind != token.STRING || slashLit.Value != `"/"` || !okEL || !rangeElemVars[elemID.Name] {
											loopOK = false
											return
										}
										guardedByLstatSameFile := false
										for _, enc := range encIfs {
											if enc.Init == nil {
												if a0, a1, okSF := isSameFileCallPair(enc.Cond); okSF {
													if (curLstat[a0] && dotVars[a1]) || (curLstat[a1] && dotVars[a0]) {
														guardedByLstatSameFile = true
														break
													}
												}
											}
										}
										if !guardedByLstatSameFile {
											loopOK = false
											return
										}
										sawClimbAssign = true
										usedSameFile = true
									}
								}
							}
							switch x := s.(type) {
							case *ast.BranchStmt:
								if x.Tok == token.BREAK && !nestedLoop {
									if x.Label != nil || len(encIfs) == 0 {
										loopOK = false
										return
									}
									innerEnc := encIfs[len(encIfs)-1]
									a0, a1, okSF := isSameFileCallPair(innerEnc.Cond)
									if !okSF || !((pdVarsInLoop[a0] && rootVars[a1]) || (pdVarsInLoop[a1] && rootVars[a0])) {
										loopOK = false
										return
									}
									usedSameFile = true
								}
							case *ast.IfStmt:
								if x.Init != nil {
									loopOK = false
									return
								}
								nextIfs := append(slices.Clone(encIfs), x)
								checkOuterLoop(x.Body.List, nextIfs, nestedLoop, curNames, curLstat, rangeElemVars)
								if x.Else != nil {
									if eb, okEB := x.Else.(*ast.BlockStmt); okEB {
										checkOuterLoop(eb.List, encIfs, nestedLoop, curNames, curLstat, rangeElemVars)
									} else if ei, okEI := x.Else.(*ast.IfStmt); okEI {
										checkOuterLoop([]ast.Stmt{ei}, encIfs, nestedLoop, curNames, curLstat, rangeElemVars)
									} else {
										loopOK = false
										return
									}
								}
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.ForStmt:
								checkOuterLoop(x.Body.List, encIfs, true, curNames, curLstat, rangeElemVars)
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.RangeStmt:
								if x.Key != nil {
									if kID, okK := unwrapParens(x.Key).(*ast.Ident); okK && (kID.Name == dirID.Name || rangeElemVars[kID.Name]) {
										loopOK = false
										return
									}
								}
								if x.Value != nil {
									if vID, okV := unwrapParens(x.Value).(*ast.Ident); okV && (vID.Name == dirID.Name || rangeElemVars[vID.Name]) {
										loopOK = false
										return
									}
								}
								nextElem := maps.Clone(rangeElemVars)
								if rX, okRX := unwrapParens(x.X).(*ast.Ident); okRX && curNames[rX.Name] && x.Value != nil {
									if vID, okV := unwrapParens(x.Value).(*ast.Ident); okV && vID.Name != "" && vID.Name != "_" {
										nextElem[vID.Name] = true
									}
								}
								checkOuterLoop(x.Body.List, encIfs, true, curNames, curLstat, nextElem)
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.BlockStmt:
								checkOuterLoop(x.List, encIfs, nestedLoop, curNames, curLstat, rangeElemVars)
								mut, pwd := map[string]bool{}, map[string]bool{}
								collectCompoundStmtMutations(x, mut, pwd)
								for m := range mut {
									delete(curNames, m)
									delete(curLstat, m)
								}
							case *ast.AssignStmt, *ast.DeclStmt, *ast.ExprStmt, *ast.ReturnStmt, *ast.EmptyStmt:
							default:
								loopOK = false
								return
							}
						}
					}
					checkOuterLoop(topParentLoop.Body.List, nil, false, map[string]bool{}, map[string]bool{}, map[string]bool{})
					if loopOK && sawClimbAssign {
						allowedReturns[lastRet] = true
						shape5Verified = true
						shape5DirVar = dirID.Name
					}
				}
			}
		}
	}

	// Whole-body structural audit: enforce loop label bounds, ban defer/go/closures/address-taking,
	// ensure every syscall.Getwd reference is Shape 1, ensure every ReturnStmt is in allowedReturns,
	// and verify dot/root/Shape-2 variable assignment discipline.
	var walkErr error
	var walkStmt func(n ast.Node, loopLabels map[string]bool, insideParentLoop bool)
	walkStmt = func(n ast.Node, loopLabels map[string]bool, insideParentLoop bool) {
		if walkErr != nil || n == nil {
			return
		}
		switch x := n.(type) {
		case *ast.DeferStmt, *ast.GoStmt, *ast.FuncLit, *ast.SendStmt, *ast.IncDecStmt:
			walkErr = fmt.Errorf("os: Getwd contains forbidden defer/go/closure/send/incdec")
			return
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				walkErr = fmt.Errorf("os: Getwd contains forbidden address-taking expression")
				return
			}
		case *ast.LabeledStmt:
			if len(loopLabels) == 0 || !loopLabels[x.Label.Name] {
				walkErr = fmt.Errorf("os: Getwd contains label outside loop")
				return
			}
			walkStmt(x.Stmt, loopLabels, insideParentLoop)
			return
		case *ast.BranchStmt:
			switch x.Tok {
			case token.FALLTHROUGH:
				walkErr = fmt.Errorf("os: Getwd contains fallthrough")
				return
			case token.BREAK, token.CONTINUE:
				if x.Label != nil {
					walkErr = fmt.Errorf("os: Getwd contains labeled break/continue")
					return
				}
			case token.GOTO:
				if x.Label == nil || !loopLabels[x.Label.Name] {
					walkErr = fmt.Errorf("os: Getwd contains goto outside enclosing loop")
					return
				}
			}
			return
		case *ast.ForStmt:
			nextLabels := maps.Clone(loopLabels)
			if nextLabels == nil {
				nextLabels = map[string]bool{}
			}
			for _, st := range x.Body.List {
				if ls, okLS := st.(*ast.LabeledStmt); okLS && ls.Label != nil {
					nextLabels[ls.Label.Name] = true
				}
			}
			nextInParent := insideParentLoop || x == topParentLoop
			if x.Init != nil {
				walkStmt(x.Init, nextLabels, nextInParent)
			}
			if x.Cond != nil {
				walkStmt(x.Cond, nextLabels, nextInParent)
			}
			if x.Post != nil {
				walkStmt(x.Post, nextLabels, nextInParent)
			}
			for _, st := range x.Body.List {
				walkStmt(st, nextLabels, nextInParent)
			}
			return
		case *ast.RangeStmt:
			for _, expr := range []ast.Expr{x.Key, x.Value} {
				if expr == nil {
					continue
				}
				if rID, okID := unwrapParens(expr).(*ast.Ident); okID {
					if dotVars[rID.Name] || rootVars[rID.Name] || fdVarsInLoop[rID.Name] || pdVarsInLoop[rID.Name] || parentLoopVars[rID.Name] || shape2ReturnedDirVars[rID.Name] {
						walkErr = fmt.Errorf("os: Getwd tracked variable %s overwritten by range clause", rID.Name)
						return
					}
				}
			}
		case *ast.ValueSpec:
			for idx, id := range x.Names {
				if dotVars[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd dot variable %s initialized outside statNolog(\".\")", id.Name)
					return
				}
				if rootVars[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd root variable %s initialized outside statNolog(\"/\")", id.Name)
					return
				}
				if fdVarsInLoop[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd fd variable %s initialized outside openDirNolog", id.Name)
					return
				}
				if pdVarsInLoop[id.Name] && len(x.Values) != 0 {
					walkErr = fmt.Errorf("os: Getwd pd variable %s initialized outside verified fd stat", id.Name)
					return
				}
				if parentLoopVars[id.Name] {
					walkErr = fmt.Errorf("os: Getwd parent variable %s redeclared", id.Name)
					return
				}
				if shape2ReturnedDirVars[id.Name] && idx < len(x.Values) {
					walkErr = fmt.Errorf("os: Getwd hint variable %s has unexpected ValueSpec initializer", id.Name)
					return
				}
			}
		case *ast.AssignStmt:
			for idxLHS, lhs := range x.Lhs {
				lID, okID := unwrapParens(lhs).(*ast.Ident)
				if !okID {
					continue
				}
				if dotVars[lID.Name] && !dotSeedAssigns[x] {
					stepOK := insideParentLoop && x.Tok == token.ASSIGN && len(x.Lhs) == 1 && len(x.Rhs) == 1
					if stepOK {
						if rhsID, okR := unwrapParens(x.Rhs[0]).(*ast.Ident); !okR || !pdVarsInLoop[rhsID.Name] {
							stepOK = false
						}
					}
					if !stepOK {
						walkErr = fmt.Errorf("os: Getwd dot variable %s assigned from unverified source", lID.Name)
						return
					}
				}
				if rootVars[lID.Name] && !rootSeedAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd root variable %s reassigned", lID.Name)
					return
				}
				if fdVarsInLoop[lID.Name] && !fdSeedAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd fd variable %s reassigned", lID.Name)
					return
				}
				if pdVarsInLoop[lID.Name] && !pdSeedAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd pd variable %s reassigned", lID.Name)
					return
				}
				if parentLoopVars[lID.Name] && !parentInitAssigns[x] && !parentStepAssigns[x] {
					walkErr = fmt.Errorf("os: Getwd parent variable %s reassigned", lID.Name)
					return
				}
				if shape2ReturnedDirVars[lID.Name] && !shape1Assigns[x] {
					if insideParentLoop && shape5Verified && lID.Name == shape5DirVar {
						// Verified by checkOuterLoop to be "/" + name + dir.
						continue
					}
					hintOK := !insideParentLoop && (x.Tok == token.ASSIGN || x.Tok == token.DEFINE) && len(x.Lhs) == 1 && len(x.Rhs) == 1 && idxLHS == 0
					if hintOK {
						rhs := unwrapParens(x.Rhs[0])
						if lit, okLit := rhs.(*ast.BasicLit); okLit && lit.Kind == token.STRING && lit.Value == `""` {
							// allowed reset
						} else if _, okCache := isSelectorBaseField(rhs, "getwdCache", "dir"); okCache {
							usedGetwdCache = true
						} else if c, okC := rhs.(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 1 {
							_, okGE := isIdentNamed(c.Fun, "Getenv")
							aLit, okAL := unwrapParens(c.Args[0]).(*ast.BasicLit)
							hintOK = okGE && okAL && aLit.Kind == token.STRING && aLit.Value == `"PWD"`
						} else {
							hintOK = false
						}
					}
					if !hintOK {
						walkErr = fmt.Errorf("os: Getwd hint variable %s assigned from unverified source", lID.Name)
						return
					}
				}
			}
		case *ast.Ident:
			if x.Name == "testlog" {
				walkErr = fmt.Errorf("os: Getwd references testlog")
				return
			}
		case *ast.SelectorExpr:
			if _, okSG := isSelectorBaseField(x, "syscall", "Getwd"); okSG && !allowedSyscallGetwdSels[x] {
				walkErr = fmt.Errorf("os: Getwd references syscall.Getwd outside verified return pair")
				return
			}
			if _, okSys := isIdentNamed(x.X, "syscall"); okSys && (x.Sel.Name == "Chdir" || x.Sel.Name == "Fchdir") {
				walkErr = fmt.Errorf("os: Getwd calls syscall.%s", x.Sel.Name)
				return
			}
		case *ast.CallExpr:
			if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
				switch cID.Name {
				case "recover", "Chdir", "Fchdir":
					walkErr = fmt.Errorf("os: Getwd calls forbidden %s", cID.Name)
					return
				case "ignoringEINTR2":
					usedIgnoringEINTR2 = true
				case "NewSyscallError":
					usedNewSyscallError = true
				case "SameFile":
					usedSameFile = true
				case "openDirNolog":
					usedOpenDirNolog = true
				case "statNolog", "lstatNolog":
					usedStatHelpers = true
				case "fstatNolog":
					usedStatHelpers = true
					usedFstatNolog = true
				}
			} else if sel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Stat" && len(x.Args) == 0 {
				usedStatHelpers = true
				usedFileStatInGetwd = true
			}
		case *ast.ReturnStmt:
			if !allowedReturns[x] {
				walkErr = fmt.Errorf("os: Getwd contains unverified return statement")
				return
			}
		}
		ast.Inspect(n, func(ch ast.Node) bool {
			if ch == n {
				return true
			}
			walkStmt(ch, loopLabels, insideParentLoop)
			return false
		})
	}
	for _, st := range gwStmts {
		walkStmt(st, nil, false)
		if walkErr != nil {
			return walkErr
		}
	}
	if !sawSyscallGetwd {
		return fmt.Errorf("os: Getwd does not invoke syscall.Getwd")
	}

	if usedGetwdCache {
		if pkgDeclCounts["getwdCache"] != 1 {
			return fmt.Errorf("os: invalid getwdCache declaration count")
		}
		var cacheDeclIdent *ast.Ident
		for _, f := range files {
			for _, decl := range f.Decls {
				gd, okGD := decl.(*ast.GenDecl)
				if !okGD || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, okVS := spec.(*ast.ValueSpec)
					if !okVS || len(vs.Names) != 1 || vs.Names[0].Name != "getwdCache" {
						continue
					}
					if len(vs.Values) != 0 {
						return fmt.Errorf("os: getwdCache must be zero-initialized")
					}
					if _, okST := unwrapParens(vs.Type).(*ast.StructType); !okST {
						return fmt.Errorf("os: getwdCache must be an unexported anonymous struct")
					}
					cacheDeclIdent = vs.Names[0]
				}
			}
		}
		if cacheDeclIdent == nil {
			return fmt.Errorf("os: missing getwdCache var declaration")
		}
		postLoopAssigns := map[*ast.AssignStmt]bool{}
		if shape5Verified && topParentLoopIdx >= 0 && topParentLoopIdx+1 < len(gwStmts) {
			for _, st := range gwStmts[topParentLoopIdx+1:] {
				ast.Inspect(st, func(n ast.Node) bool {
					if as, okA := n.(*ast.AssignStmt); okA {
						postLoopAssigns[as] = true
					}
					return true
				})
			}
		}
		fileHasUnaliasedImport := func(f *ast.File, want string) bool {
			if f == nil {
				return false
			}
			for _, imp := range f.Imports {
				if imp.Name != nil {
					continue
				}
				if p, err := strconv.Unquote(imp.Path.Value); err == nil && p == want {
					return true
				}
			}
			return false
		}
		chdirFn := allTopFuncs["Chdir"]
		chdirParam0 := ""
		chdirAbsIfs := map[*ast.IfStmt]bool{}
		if chdirFn != nil && chdirFn.Body != nil && chdirFn.Type != nil && fileHasUnaliasedImport(funcFile[chdirFn], "internal/filepathlite") && !funcShadowsAnyIdent(chdirFn, map[string]bool{"filepathlite": true, "getwdCache": true}) {
			if pNames := paramNamesFlat(chdirFn.Type.Params); len(pNames) == 1 && pNames[0] != "" && pNames[0] != "_" && !stmtsMutateIdentBefore(chdirFn.Body.List, nil, pNames[0]) {
				chdirParam0 = pNames[0]
				absAssignCounts := map[string]int{}
				absVerifiedVars := map[string]bool{}
				ast.Inspect(chdirFn.Body, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.AssignStmt:
						for i, lhs := range x.Lhs {
							if id, okID := unwrapParens(lhs).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
								absAssignCounts[id.Name]++
								if len(x.Lhs) == 1 && len(x.Rhs) == 1 && i == 0 && (x.Tok == token.DEFINE || x.Tok == token.ASSIGN) {
									if c, okC := unwrapParens(x.Rhs[0]).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 1 {
										_, okFP := isSelectorBaseField(c.Fun, "filepathlite", "IsAbs")
										_, okP0 := isIdentNamed(c.Args[0], chdirParam0)
										if okFP && okP0 {
											absVerifiedVars[id.Name] = true
										}
									}
								}
							}
						}
					case *ast.ValueSpec:
						for _, id := range x.Names {
							if id.Name != "" && id.Name != "_" {
								absAssignCounts[id.Name]++
							}
						}
					}
					return true
				})
				ast.Inspect(chdirFn.Body, func(n ast.Node) bool {
					if ifs, okI := n.(*ast.IfStmt); okI && ifs.Init == nil {
						if cID, okID := unwrapParens(ifs.Cond).(*ast.Ident); okID && absVerifiedVars[cID.Name] && absAssignCounts[cID.Name] == 1 {
							chdirAbsIfs[ifs] = true
						}
					}
					return true
				})
			}
		}
		for _, f := range files {
			for _, decl := range f.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					var gdErr error
					ast.Inspect(d, func(n ast.Node) bool {
						if gdErr != nil || n == nil {
							return false
						}
						if id, okID := n.(*ast.Ident); okID && id.Name == "getwdCache" && id != cacheDeclIdent {
							gdErr = fmt.Errorf("os: unexpected package-level reference to getwdCache")
							return false
						}
						return true
					})
					if gdErr != nil {
						return gdErr
					}
				case *ast.FuncDecl:
					if d.Body == nil {
						continue
					}
					mentionsCache := false
					ast.Inspect(d.Body, func(n ast.Node) bool {
						if id, okID := n.(*ast.Ident); okID && id.Name == "getwdCache" {
							mentionsCache = true
							return false
						}
						return true
					})
					if !mentionsCache {
						continue
					}
					if funcShadowsAnyIdent(d, map[string]bool{"getwdCache": true}) {
						return fmt.Errorf("os: function %s shadows getwdCache", d.Name.Name)
					}
					validBaseIdents := map[*ast.Ident]bool{}
					ast.Inspect(d.Body, func(n ast.Node) bool {
						if sel, okS := n.(*ast.SelectorExpr); okS {
							if bID, okB := unwrapParens(sel.X).(*ast.Ident); okB && bID.Name == "getwdCache" && (sel.Sel.Name == "Lock" || sel.Sel.Name == "Unlock" || sel.Sel.Name == "dir") {
								validBaseIdents[bID] = true
							}
						}
						return true
					})
					var cacheErr error
					var auditCache func(n ast.Node, inAbsBody bool)
					auditCache = func(n ast.Node, inAbsBody bool) {
						if cacheErr != nil || n == nil {
							return
						}
						if ifs, okI := n.(*ast.IfStmt); okI {
							if skipInactiveHookIf(ifs, d) {
								return
							}
							if ifs.Init != nil {
								auditCache(ifs.Init, inAbsBody)
							}
							auditCache(ifs.Cond, inAbsBody)
							auditCache(ifs.Body, inAbsBody || chdirAbsIfs[ifs])
							if ifs.Else != nil {
								auditCache(ifs.Else, inAbsBody)
							}
							return
						}
						switch x := n.(type) {
						case *ast.Ident:
							if x.Name == "getwdCache" && !validBaseIdents[x] {
								cacheErr = fmt.Errorf("os: unsupported getwdCache reference in %s", d.Name.Name)
								return
							}
						case *ast.UnaryExpr:
							if x.Op == token.AND {
								if _, okCD := isSelectorBaseField(x.X, "getwdCache", "dir"); okCD {
									cacheErr = fmt.Errorf("os: address taken of getwdCache.dir in %s", d.Name.Name)
									return
								}
							}
						case *ast.IncDecStmt:
							if _, okCD := isSelectorBaseField(x.X, "getwdCache", "dir"); okCD {
								cacheErr = fmt.Errorf("os: inc/dec on getwdCache.dir in %s", d.Name.Name)
								return
							}
						case *ast.RangeStmt:
							for _, expr := range []ast.Expr{x.Key, x.Value} {
								if expr != nil {
									if _, okCD := isSelectorBaseField(expr, "getwdCache", "dir"); okCD {
										cacheErr = fmt.Errorf("os: range write to getwdCache.dir in %s", d.Name.Name)
										return
									}
								}
							}
						case *ast.AssignStmt:
							for idxLHS, lhs := range x.Lhs {
								if _, okCD := isSelectorBaseField(lhs, "getwdCache", "dir"); okCD {
									writeOK := false
									if x.Tok == token.ASSIGN {
										if len(x.Lhs) == 1 && len(x.Rhs) == 1 {
											rhs := unwrapParens(x.Rhs[0])
											if lit, okL := rhs.(*ast.BasicLit); okL && lit.Kind == token.STRING && lit.Value == `""` {
												writeOK = true
											} else if d == gwFn && shape5Verified && postLoopAssigns[x] {
												_, writeOK = isIdentNamed(rhs, shape5DirVar)
											} else if d == chdirFn && inAbsBody && chdirParam0 != "" {
												_, writeOK = isIdentNamed(rhs, chdirParam0)
											}
										} else if len(x.Lhs) == 2 && len(x.Rhs) == 1 && idxLHS == 0 && fileImportsSyscall[f] && !funcShadowsAnyIdent(d, map[string]bool{"syscall": true}) {
											_, okBlank := isIdentNamed(x.Lhs[1], "_")
											if c, okC := unwrapParens(x.Rhs[0]).(*ast.CallExpr); okBlank && okC && !c.Ellipsis.IsValid() && len(c.Args) == 0 {
												_, writeOK = isSelectorBaseField(c.Fun, "syscall", "Getwd")
											}
										}
									}
									if !writeOK {
										cacheErr = fmt.Errorf("os: unverified write to getwdCache.dir in %s", d.Name.Name)
										return
									}
								}
							}
						}
						ast.Inspect(n, func(ch ast.Node) bool {
							if ch == n {
								return true
							}
							auditCache(ch, inAbsBody)
							return false
						})
					}
					auditCache(d.Body, false)
					if cacheErr != nil {
						return cacheErr
					}
				}
			}
		}
	}

	if usedIgnoringEINTR2 {
		ig2 := allTopFuncs["ignoringEINTR2"]
		if pkgDeclCounts["ignoringEINTR2"] != 1 || osAnyLinknameLocals["ignoringEINTR2"] || !verifyIgnoringEINTRHelper(ig2, fileImportsSyscall[funcFile[ig2]], osReserved, 2) {
			return fmt.Errorf("os: invalid ignoringEINTR2 helper")
		}
	}
	if usedNewSyscallError {
		nse := allTopFuncs["NewSyscallError"]
		if nse == nil || nse.Body == nil || nse.Type == nil || nse.Type.TypeParams != nil || !funcHasUnnamedResults(nse.Type, 1) || pkgDeclCounts["NewSyscallError"] != 1 || osAnyLinknameLocals["NewSyscallError"] || nonAliasStructSpecs["SyscallError"] == nil || pkgDeclCounts["SyscallError"] != 1 || funcShadowsAnyIdent(nse, map[string]bool{"nil": true, "error": true, "SyscallError": true}) || bodyHasControlFlowOrRecoverBypass(nse.Body) || len(nse.Body.List) != 2 {
			return fmt.Errorf("os: invalid NewSyscallError helper")
		}
		nseParams := paramNamesFlat(nse.Type.Params)
		if len(nseParams) != 2 || nseParams[0] == "" || nseParams[0] == "_" || nseParams[1] == "" || nseParams[1] == "_" || nseParams[0] == nseParams[1] || bodyMutatesOrTakesAddrOfAny(nse.Body, map[string]bool{nseParams[1]: true}) {
			return fmt.Errorf("os: NewSyscallError invalid parameters")
		}
		ifs, okI := nse.Body.List[0].(*ast.IfStmt)
		ret1, okR1 := nse.Body.List[1].(*ast.ReturnStmt)
		if !okI || ifs.Init != nil || ifs.Else != nil || !condChecksEqErr(ifs.Cond, nseParams[1]) || len(ifs.Body.List) != 1 || !okR1 || len(ret1.Results) != 1 {
			return fmt.Errorf("os: NewSyscallError unexpected body")
		}
		ret0, okR0 := ifs.Body.List[0].(*ast.ReturnStmt)
		if !okR0 || len(ret0.Results) != 1 {
			return fmt.Errorf("os: NewSyscallError nil branch does not return single value")
		}
		if _, okNil := isIdentNamed(ret0.Results[0], "nil"); !okNil {
			return fmt.Errorf("os: NewSyscallError nil branch does not return nil")
		}
		u, okU := unwrapParens(ret1.Results[0]).(*ast.UnaryExpr)
		cl, tName := compositeWriterLit(ret1.Results[0])
		if !okU || u.Op != token.AND || cl == nil || tName != "SyscallError" {
			return fmt.Errorf("os: NewSyscallError does not return &SyscallError")
		}
		bindsErrField := false
		if len(cl.Elts) == 2 {
			_, kv0 := cl.Elts[0].(*ast.KeyValueExpr)
			_, kv1 := cl.Elts[1].(*ast.KeyValueExpr)
			if !kv0 && !kv1 {
				_, bindsErrField = isIdentNamed(cl.Elts[1], nseParams[1])
			}
		}
		if !bindsErrField {
			for _, elt := range cl.Elts {
				kv, okKV := elt.(*ast.KeyValueExpr)
				if !okKV {
					bindsErrField = false
					break
				}
				if kID, okK := kv.Key.(*ast.Ident); okK && kID.Name == "Err" {
					_, bindsErrField = isIdentNamed(kv.Value, nseParams[1])
				}
			}
		}
		if !bindsErrField {
			return fmt.Errorf("os: NewSyscallError does not bind error parameter in SyscallError")
		}
	}
	if usedOpenDirNolog {
		odFn := allTopFuncs["openDirNolog"]
		if odFn == nil || odFn.Body == nil || odFn.Type == nil || odFn.Type.TypeParams != nil || pkgDeclCounts["openDirNolog"] != 1 || osAnyLinknameLocals["openDirNolog"] || funcShadowsAnyIdent(odFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(odFn.Body) {
			return fmt.Errorf("os: invalid openDirNolog helper")
		}
		odParams := paramNamesFlat(odFn.Type.Params)
		if len(odParams) != 1 || odParams[0] == "" || odParams[0] == "_" || odFn.Type.Results == nil || odFn.Type.Results.NumFields() != 2 || !funcReturnsErrorLast(odFn.Type) {
			return fmt.Errorf("os: openDirNolog invalid signature")
		}
		if starF, okS := unwrapParens(odFn.Type.Results.List[0].Type).(*ast.StarExpr); !okS {
			return fmt.Errorf("os: openDirNolog first result is not *File")
		} else if _, okF := isIdentNamed(starF.X, "File"); !okF {
			return fmt.Errorf("os: openDirNolog first result is not *File")
		}
		odPos := 0
		for odPos < len(odFn.Body.List) && skipInactiveHookIf(odFn.Body.List[odPos], odFn) {
			odPos++
		}
		if odPos >= len(odFn.Body.List) {
			return fmt.Errorf("os: openDirNolog empty body")
		}
		var odErr error
		for _, st := range odFn.Body.List[odPos:] {
			ast.Inspect(st, func(n ast.Node) bool {
				if odErr != nil || n == nil {
					return false
				}
				if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, odFn) {
					return false
				}
				switch x := n.(type) {
				case *ast.Ident:
					if x.Name == "testlog" {
						odErr = fmt.Errorf("os: openDirNolog references testlog")
						return false
					}
				case *ast.SelectorExpr:
					if _, okSys := isIdentNamed(x.X, "syscall"); okSys {
						switch x.Sel.Name {
						case "Chdir", "Fchdir", "Unlink", "Rmdir", "Rename":
							odErr = fmt.Errorf("os: openDirNolog calls syscall.%s", x.Sel.Name)
							return false
						}
					}
				case *ast.CallExpr:
					if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
						if osAnyLinknameLocals[cID.Name] {
							odErr = fmt.Errorf("os: openDirNolog calls linknamed %s", cID.Name)
							return false
						}
						switch cID.Name {
						case "Open", "OpenFile", "Create", "Stat", "Lstat", "Chdir", "Fchdir", "Remove", "Rename", "Truncate", "openDir":
							odErr = fmt.Errorf("os: openDirNolog calls forbidden %s", cID.Name)
							return false
						case "fstatNolog":
							usedStatHelpers = true
							usedFstatNolog = true
						case "statNolog", "lstatNolog":
							usedStatHelpers = true
						}
					} else if sel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Stat" && len(x.Args) == 0 {
						usedStatHelpers = true
						usedFileStatInGetwd = true
					}
				}
				return true
			})
			if odErr != nil {
				return odErr
			}
		}
	}
	var disjointAltStruct string
	if usedSameFile {
		var err error
		disjointAltStruct, err = verifyOSSameFile(allTopFuncs, nonAliasStructSpecs, pkgDeclCounts, osReserved, osNoFileReserved, osAnyLinknameLocals, osInactive, skipInactiveHookIf)
		if err != nil {
			return err
		}
	}
	if usedStatHelpers || usedSameFile {
		if err := verifyOSNologStatHelpers(allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods, pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts, funcFile, fileImportsSyscall, osInactive, osNoFileReserved, osAnyLinknameLocals, disjointAltStruct, usedSameFile, usedFstatNolog, usedFileStatInGetwd, skipInactiveHookIf); err != nil {
			return err
		}
	}
	return nil
}
