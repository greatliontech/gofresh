package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"strings"
)

func verifyOSGetwd(
	files []*ast.File,
	gwFn *ast.FuncDecl,
	allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods map[string]*ast.FuncDecl,
	nonAliasStructSpecs map[string]*ast.TypeSpec,
	pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts map[string]int,
	funcFile map[*ast.FuncDecl]*ast.File,
	fileImportsSyscall map[*ast.File]bool,
	verifiedNonNilOSErrIdents, osReserved, osNoFileReserved, osAnyLinknameLocals map[string]bool,
	osInactive *osInactiveState,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
) error {
	if gwFn == nil || gwFn.Body == nil || gwFn.Type == nil || gwFn.Type.TypeParams != nil || osAnyLinknameLocals["Getwd"] {
		return fmt.Errorf("os: missing or invalid Getwd")
	}
	if !fileImportsSyscall[funcFile[gwFn]] || funcShadowsAnyIdent(gwFn, osReserved) {
		return fmt.Errorf("os: Getwd missing syscall import or shadows reserved identifier")
	}
	if (gwFn.Type.Params != nil && gwFn.Type.Params.NumFields() != 0) || gwFn.Type.Results == nil || gwFn.Type.Results.NumFields() != 2 || len(gwFn.Type.Results.List) != 2 || !funcReturnsErrorLast(gwFn.Type) {
		return fmt.Errorf("os: Getwd invalid signature")
	}
	if _, okStr := isIdentNamed(gwFn.Type.Results.List[0].Type, "string"); !okStr {
		return fmt.Errorf("os: Getwd first result is not string")
	}
	pos := 0
	for pos < len(gwFn.Body.List) && skipInactiveHookIf(gwFn.Body.List[pos], gwFn) {
		pos++
	}
	gwStmts := gwFn.Body.List[pos:]
	if len(gwStmts) == 0 {
		return fmt.Errorf("os: Getwd empty body")
	}
	for _, topSt := range gwStmts[:len(gwStmts)-1] {
		if _, isBareRet := topSt.(*ast.ReturnStmt); isBareRet {
			return fmt.Errorf("os: Getwd has unconditional early return")
		}
	}

	stmtUnwrapLabel := func(st ast.Stmt) ast.Stmt {
		for {
			ls, ok := st.(*ast.LabeledStmt)
			if !ok {
				return st
			}
			st = ls.Stmt
		}
	}
	isNonEmptyStrLit := func(expr ast.Expr) bool {
		lit, ok := unwrapParens(expr).(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return false
		}
		unq, err := strconv.Unquote(lit.Value)
		return err == nil && unq != ""
	}
	isSameFileCallPair := func(expr ast.Expr) (string, string, bool) {
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
			return "", "", false
		}
		if _, okSF := isIdentNamed(c.Fun, "SameFile"); !okSF {
			return "", "", false
		}
		a0, ok0 := unwrapParens(c.Args[0]).(*ast.Ident)
		a1, ok1 := unwrapParens(c.Args[1]).(*ast.Ident)
		if !ok0 || !ok1 || a0.Name == "" || a0.Name == "_" || a1.Name == "" || a1.Name == "_" {
			return "", "", false
		}
		return a0.Name, a1.Name, true
	}
	isDirectOrWrappedErrExpr := func(expr ast.Expr, wantErr string) bool {
		if _, okDirect := isIdentNamed(expr, wantErr); okDirect {
			return true
		}
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
			return false
		}
		_, okNSE := isIdentNamed(c.Fun, "NewSyscallError")
		_, okErr := isIdentNamed(c.Args[1], wantErr)
		return okNSE && isNonEmptyStrLit(c.Args[0]) && okErr
	}
	isVerifiedConstErrArg := func(expr ast.Expr) bool {
		if sel, okS := unwrapParens(expr).(*ast.SelectorExpr); okS {
			_, okSys := isIdentNamed(sel.X, "syscall")
			return okSys && strings.HasPrefix(sel.Sel.Name, "E") && len(sel.Sel.Name) > 1
		}
		if id, okID := unwrapParens(expr).(*ast.Ident); okID {
			return verifiedNonNilOSErrIdents[id.Name] && !funcShadowsAnyIdent(gwFn, map[string]bool{id.Name: true})
		}
		return false
	}
	isVerifiedConstGetwdErr := func(expr ast.Expr) bool {
		if isVerifiedConstErrArg(expr) {
			return true
		}
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
			return false
		}
		_, okNSE := isIdentNamed(c.Fun, "NewSyscallError")
		return okNSE && isNonEmptyStrLit(c.Args[0]) && isVerifiedConstErrArg(c.Args[1])
	}
	condChecksAbsSlashPrefix := func(cond ast.Expr, dirVar string) bool {
		found := false
		var check func(e ast.Expr)
		check = func(e ast.Expr) {
			if found || e == nil {
				return
			}
			bin, okB := unwrapParens(e).(*ast.BinaryExpr)
			if !okB {
				return
			}
			if bin.Op == token.LAND {
				check(bin.X)
				check(bin.Y)
				return
			}
			if bin.Op != token.EQL {
				return
			}
			matchIdxSlash := func(idxSide, charSide ast.Expr) bool {
				ix, okIX := unwrapParens(idxSide).(*ast.IndexExpr)
				lit, okL := unwrapParens(charSide).(*ast.BasicLit)
				if !okIX || !okL || !isZeroIntLit(ix.Index) {
					return false
				}
				if _, okD := isIdentNamed(ix.X, dirVar); !okD {
					return false
				}
				return lit.Kind == token.CHAR && lit.Value == `'/'`
			}
			if matchIdxSlash(bin.X, bin.Y) || matchIdxSlash(bin.Y, bin.X) {
				found = true
			}
		}
		check(cond)
		return found
	}
	isParentLenBoundCond := func(cond ast.Expr, parentLoopVars map[string]bool) bool {
		bin, okB := unwrapParens(cond).(*ast.BinaryExpr)
		if !okB {
			return false
		}
		checkLenLit := func(lenSide, litSide ast.Expr) bool {
			c, okC := unwrapParens(lenSide).(*ast.CallExpr)
			lit, okL := unwrapParens(litSide).(*ast.BasicLit)
			if !okC || !okL || c.Ellipsis.IsValid() || len(c.Args) != 1 || lit.Kind != token.INT {
				return false
			}
			if _, okLen := isIdentNamed(c.Fun, "len"); !okLen {
				return false
			}
			pID, okP := unwrapParens(c.Args[0]).(*ast.Ident)
			if !okP || !parentLoopVars[pID.Name] {
				return false
			}
			n, err := strconv.ParseInt(lit.Value, 0, 64)
			return err == nil && n >= 64
		}
		switch bin.Op {
		case token.GEQ, token.GTR:
			return checkLenLit(bin.X, bin.Y)
		case token.LEQ, token.LSS:
			return checkLenLit(bin.Y, bin.X)
		default:
			return false
		}
	}
	condChecksNonEmptyStr := func(cond ast.Expr, dirVar string) bool {
		found := false
		var check func(e ast.Expr)
		check = func(e ast.Expr) {
			if found || e == nil {
				return
			}
			bin, okB := unwrapParens(e).(*ast.BinaryExpr)
			if !okB {
				return
			}
			if bin.Op == token.LAND {
				check(bin.X)
				check(bin.Y)
				return
			}
			matchLenCall := func(side ast.Expr) bool {
				c, okC := unwrapParens(side).(*ast.CallExpr)
				if !okC || c.Ellipsis.IsValid() || len(c.Args) != 1 {
					return false
				}
				_, okLen := isIdentNamed(c.Fun, "len")
				_, okD := isIdentNamed(c.Args[0], dirVar)
				return okLen && okD
			}
			parseIntSide := func(side ast.Expr) (int64, bool) {
				lit, okL := unwrapParens(side).(*ast.BasicLit)
				if !okL || lit.Kind != token.INT {
					return 0, false
				}
				n, err := strconv.ParseInt(lit.Value, 0, 64)
				return n, err == nil
			}
			switch bin.Op {
			case token.GTR:
				if matchLenCall(bin.X) {
					if n, ok := parseIntSide(bin.Y); ok && n >= 0 {
						found = true
					}
				}
			case token.LSS:
				if matchLenCall(bin.Y) {
					if n, ok := parseIntSide(bin.X); ok && n >= 0 {
						found = true
					}
				}
			case token.GEQ:
				if matchLenCall(bin.X) {
					if n, ok := parseIntSide(bin.Y); ok && n >= 1 {
						found = true
					}
				}
			case token.LEQ:
				if matchLenCall(bin.Y) {
					if n, ok := parseIntSide(bin.X); ok && n >= 1 {
						found = true
					}
				}
			case token.NEQ:
				isEmpty := func(side ast.Expr) bool {
					lit, okL := unwrapParens(side).(*ast.BasicLit)
					return okL && lit.Kind == token.STRING && lit.Value == `""`
				}
				_, okLX := isIdentNamed(bin.X, dirVar)
				_, okLY := isIdentNamed(bin.Y, dirVar)
				if (okLX && isEmpty(bin.Y)) || (okLY && isEmpty(bin.X)) {
					found = true
				}
			}
		}
		check(cond)
		return found
	}
	isGetenvPWDCall := func(expr ast.Expr) bool {
		c, okC := unwrapParens(expr).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 1 {
			return false
		}
		_, okGE := isIdentNamed(c.Fun, "Getenv")
		lit, okLit := unwrapParens(c.Args[0]).(*ast.BasicLit)
		return okGE && okLit && lit.Kind == token.STRING && lit.Value == `"PWD"`
	}
	collectCompoundStmtMutations := func(node ast.Node, mutated, assignedPWD map[string]bool) {
		ast.Inspect(node, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range x.Lhs {
					if id, okID := unwrapParens(lhs).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
						if len(x.Lhs) == len(x.Rhs) && i < len(x.Rhs) && isGetenvPWDCall(x.Rhs[i]) {
							assignedPWD[id.Name] = true
						}
					}
				}
			case *ast.ValueSpec:
				for i, id := range x.Names {
					if id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
						if i < len(x.Values) && isGetenvPWDCall(x.Values[i]) {
							assignedPWD[id.Name] = true
						}
					}
				}
			case *ast.RangeStmt:
				if x.Key != nil {
					if id, okK := unwrapParens(x.Key).(*ast.Ident); okK && id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
					}
				}
				if x.Value != nil {
					if id, okV := unwrapParens(x.Value).(*ast.Ident); okV && id.Name != "" && id.Name != "_" {
						mutated[id.Name] = true
					}
				}
			case *ast.IncDecStmt:
				if id, okID := unwrapParens(x.X).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
					mutated[id.Name] = true
				}
			}
			return true
		})
	}
	stmtsMutateIdentBefore := func(list []ast.Stmt, stopAt ast.Node, target string) bool {
		mutated := false
		stopped := false
		for _, s := range list {
			ast.Inspect(s, func(n ast.Node) bool {
				if mutated || stopped || n == nil {
					return false
				}
				if stopAt != nil && n == stopAt {
					stopped = true
					return false
				}
				switch x := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range x.Lhs {
						if _, okID := isIdentNamed(lhs, target); okID {
							mutated = true
							return false
						}
					}
				case *ast.ValueSpec:
					for _, id := range x.Names {
						if id.Name == target {
							mutated = true
							return false
						}
					}
				case *ast.RangeStmt:
					if x.Key != nil {
						if _, okK := isIdentNamed(x.Key, target); okK {
							mutated = true
							return false
						}
					}
					if x.Value != nil {
						if _, okV := isIdentNamed(x.Value, target); okV {
							mutated = true
							return false
						}
					}
				case *ast.IncDecStmt:
					if _, okID := isIdentNamed(x.X, target); okID {
						mutated = true
						return false
					}
				}
				return true
			})
			if mutated || stopped {
				break
			}
		}
		return mutated
	}
	isCheckedErrGuardIf := func(st ast.Stmt, wantErr string) (*ast.ReturnStmt, bool) {
		ifs, okI := st.(*ast.IfStmt)
		if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 || condChecksNonZeroErr(ifs.Cond) != wantErr {
			return nil, false
		}
		ret, okR := ifs.Body.List[0].(*ast.ReturnStmt)
		if !okR || len(ret.Results) != 2 {
			return nil, false
		}
		r0Lit, ok0 := unwrapParens(ret.Results[0]).(*ast.BasicLit)
		_, ok1 := isIdentNamed(ret.Results[1], wantErr)
		if !ok0 || r0Lit.Kind != token.STRING || r0Lit.Value != `""` || !ok1 {
			return nil, false
		}
		return ret, true
	}
	isCloseCallOn := func(st ast.Stmt, fdVar string) bool {
		es, okE := st.(*ast.ExprStmt)
		if !okE {
			return false
		}
		c, okC := unwrapParens(es.X).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
			return false
		}
		_, okSel := isSelectorBaseField(c.Fun, fdVar, "Close")
		return okSel
	}

	var sawSyscallGetwd, usedIgnoringEINTR2, usedNewSyscallError, usedSameFile, usedStatHelpers, usedOpenDirNolog, usedFstatNolog, usedFileStatInGetwd, usedGetwdCache bool
	allowedSyscallGetwdSels := map[*ast.SelectorExpr]bool{}
	allowedReturns := map[*ast.ReturnStmt]bool{}
	validErrIfs := map[*ast.IfStmt]string{}
	dotSeedAssigns := map[*ast.AssignStmt]bool{}
	rootSeedAssigns := map[*ast.AssignStmt]bool{}
	fdSeedAssigns := map[*ast.AssignStmt]bool{}
	pdSeedAssigns := map[*ast.AssignStmt]bool{}
	shape1Assigns := map[*ast.AssignStmt]bool{}
	parentInitAssigns := map[*ast.AssignStmt]bool{}
	parentStepAssigns := map[*ast.AssignStmt]bool{}
	dotVars := map[string]bool{}
	rootVars := map[string]bool{}
	fdVarsInLoop := map[string]bool{}
	pdVarsInLoop := map[string]bool{}
	shape2ReturnedDirVars := map[string]bool{}
	parentLoopVars := map[string]bool{}
	var topParentLoop *ast.ForStmt
	topParentLoopIdx := -1
	sawLoopInGetwd := false

	var verifyBlock func(stmts []ast.Stmt, enclosingIfs []*ast.IfStmt, inLoop bool, pwdUncheckedVars, validErrVars map[string]bool) error
	verifyBlock = func(stmts []ast.Stmt, enclosingIfs []*ast.IfStmt, inLoop bool, pwdUncheckedVars, validErrVars map[string]bool) error {
		curPWD := maps.Clone(pwdUncheckedVars)
		curValidErr := maps.Clone(validErrVars)
		for idx := 0; idx < len(stmts); idx++ {
			raw := stmts[idx]
			if _, isLbl := raw.(*ast.LabeledStmt); isLbl {
				clear(curValidErr)
			}
			st := stmtUnwrapLabel(raw)

			if ds, okDS := st.(*ast.DeclStmt); okDS {
				if gd, okGD := ds.Decl.(*ast.GenDecl); okGD {
					for _, spec := range gd.Specs {
						if vs, okVS := spec.(*ast.ValueSpec); okVS {
							for i, id := range vs.Names {
								if id.Name != "" && id.Name != "_" {
									delete(curValidErr, id.Name)
									if i < len(vs.Values) && isGetenvPWDCall(vs.Values[i]) {
										curPWD[id.Name] = true
									} else if len(vs.Values) == 0 {
										delete(curPWD, id.Name)
									} else if i < len(vs.Values) {
										if lit, okLit := unwrapParens(vs.Values[i]).(*ast.BasicLit); okLit && lit.Kind == token.STRING && lit.Value == `""` {
											delete(curPWD, id.Name)
										}
									}
								}
							}
						}
					}
				}
			}

			if as, okA := st.(*ast.AssignStmt); okA {
				// Track PWD vs getwdCache.dir hint state on 1-LHS assignments.
				if len(as.Lhs) == 1 && len(as.Rhs) == 1 {
					if lID, okL := unwrapParens(as.Lhs[0]).(*ast.Ident); okL && lID.Name != "" && lID.Name != "_" {
						if isGetenvPWDCall(as.Rhs[0]) {
							curPWD[lID.Name] = true
						} else if _, okCache := isSelectorBaseField(as.Rhs[0], "getwdCache", "dir"); okCache {
							usedGetwdCache = true
							delete(curPWD, lID.Name)
						} else if lit, okLit := unwrapParens(as.Rhs[0]).(*ast.BasicLit); okLit && lit.Kind == token.STRING && lit.Value == `""` {
							delete(curPWD, lID.Name)
						}
					}
				}

				producesValidErr := false
				var validErrName string
				if (as.Tok == token.DEFINE || as.Tok == token.ASSIGN) && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
					l0, ok0 := unwrapParens(as.Lhs[0]).(*ast.Ident)
					l1, ok1 := unwrapParens(as.Lhs[1]).(*ast.Ident)
					c, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
					if ok0 && ok1 && okC && !c.Ellipsis.IsValid() && l0.Name != "" && l0.Name != "_" && l1.Name != "_" && l0.Name != l1.Name {
						if l1.Name != "" {
							if _, okLS := isIdentNamed(c.Fun, "lstatNolog"); okLS && len(c.Args) == 1 {
								usedStatHelpers = true
								producesValidErr = true
								validErrName = l1.Name
							}
						}
					}
					if ok0 && ok1 && okC && !c.Ellipsis.IsValid() && l0.Name != "" && l0.Name != "_" && l1.Name != "" && l1.Name != "_" && l0.Name != l1.Name {
						// Shape 1: <dVar>, <eVar> =|:= syscall.Getwd() | ignoringEINTR2(syscall.Getwd).
						var sgSel *ast.SelectorExpr
						if _, okSG := isSelectorBaseField(c.Fun, "syscall", "Getwd"); okSG && len(c.Args) == 0 {
							sgSel = unwrapParens(c.Fun).(*ast.SelectorExpr)
						} else if _, okIG := isIdentNamed(c.Fun, "ignoringEINTR2"); okIG && len(c.Args) == 1 {
							if _, okSG := isSelectorBaseField(c.Args[0], "syscall", "Getwd"); okSG {
								sgSel = unwrapParens(c.Args[0]).(*ast.SelectorExpr)
							}
						}
						if sgSel != nil {
							producesValidErr = true
							validErrName = l1.Name
							if idx+1 >= len(stmts) {
								return fmt.Errorf("os: Getwd syscall.Getwd call missing immediate return")
							}
							nextSt := stmts[idx+1]
							var matchedRet *ast.ReturnStmt
							if ret, okR := nextSt.(*ast.ReturnStmt); okR && len(ret.Results) == 2 {
								if _, okD := isIdentNamed(ret.Results[0], l0.Name); okD && isDirectOrWrappedErrExpr(ret.Results[1], l1.Name) {
									matchedRet = ret
								}
							} else if ifs, okI := nextSt.(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
								if ret, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 2 {
									if _, okD := isIdentNamed(ret.Results[0], l0.Name); okD && isDirectOrWrappedErrExpr(ret.Results[1], l1.Name) {
										matchedRet = ret
									}
								}
							}
							if matchedRet == nil {
								return fmt.Errorf("os: Getwd syscall.Getwd result (%s, %s) not immediately returned with its error", l0.Name, l1.Name)
							}
							allowedSyscallGetwdSels[sgSel] = true
							allowedReturns[matchedRet] = true
							shape1Assigns[as] = true
							delete(curPWD, l0.Name)
							sawSyscallGetwd = true
						}

						// Seed dot/root/Shape 2 via statNolog(...).
						if _, okSN := isIdentNamed(c.Fun, "statNolog"); okSN && len(c.Args) == 1 {
							usedStatHelpers = true
							producesValidErr = true
							validErrName = l1.Name
							if lit, okLit := unwrapParens(c.Args[0]).(*ast.BasicLit); okLit && lit.Kind == token.STRING {
								if (lit.Value == `"."` || lit.Value == `"/"`) && idx+1 < len(stmts) {
									if errRet, okG := isCheckedErrGuardIf(stmts[idx+1], l1.Name); okG {
										allowedReturns[errRet] = true
										if lit.Value == `"."` {
											dotSeedAssigns[as] = true
											dotVars[l0.Name] = true
										} else {
											rootSeedAssigns[as] = true
											rootVars[l0.Name] = true
										}
									}
								}
							} else if dirArgID, okDA := unwrapParens(c.Args[0]).(*ast.Ident); okDA && !inLoop && !sawLoopInGetwd && dirArgID.Name != "" && dirArgID.Name != "_" && dirArgID.Name != l0.Name && dirArgID.Name != l1.Name && idx+1 < len(stmts) {
								if ifs, okI := stmts[idx+1].(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
									if bin, okB := unwrapParens(ifs.Cond).(*ast.BinaryExpr); okB && bin.Op == token.LAND && condChecksEqErr(bin.X, l1.Name) {
										if a0, a1, okSF := isSameFileCallPair(bin.Y); okSF {
											dotCand := ""
											if a0 == l0.Name && dotVars[a1] {
												dotCand = a1
											} else if a1 == l0.Name && dotVars[a0] {
												dotCand = a0
											}
											if dotCand != "" {
												if ret, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 2 {
													_, okRD := isIdentNamed(ret.Results[0], dirArgID.Name)
													_, okRN := isIdentNamed(ret.Results[1], "nil")
													if okRD && okRN {
														hasNonEmptyGuard := false
														for _, enc := range enclosingIfs {
															if condChecksNonEmptyStr(enc.Cond, dirArgID.Name) {
																hasNonEmptyGuard = true
																break
															}
														}
														if !hasNonEmptyGuard {
															return fmt.Errorf("os: Getwd hint %s returned without non-empty guard", dirArgID.Name)
														}
														if curPWD[dirArgID.Name] {
															hasSlashGuard := false
															for _, enc := range enclosingIfs {
																if condChecksAbsSlashPrefix(enc.Cond, dirArgID.Name) {
																	hasSlashGuard = true
																	break
																}
															}
															if !hasSlashGuard {
																return fmt.Errorf("os: Getwd PWD hint %s returned without leading '/' guard", dirArgID.Name)
															}
														}
														allowedReturns[ret] = true
														shape2ReturnedDirVars[dirArgID.Name] = true
														usedSameFile = true
													}
												}
											}
										}
									}
								}
							}
						}

						// Loop parent openDirNolog(parent), Readdirnames, and fstatNolog(fd)/fd.Stat() seeds.
						if inLoop {
							if _, okOD := isIdentNamed(c.Fun, "openDirNolog"); okOD && len(c.Args) == 1 {
								if pID, okP := unwrapParens(c.Args[0]).(*ast.Ident); okP && parentLoopVars[pID.Name] {
									producesValidErr = true
									validErrName = l1.Name
									if idx+1 < len(stmts) {
										if errRet, okG := isCheckedErrGuardIf(stmts[idx+1], l1.Name); okG {
											allowedReturns[errRet] = true
											fdSeedAssigns[as] = true
											fdVarsInLoop[l0.Name] = true
											usedOpenDirNolog = true
										}
									}
								}
							}
							if sel, okS := unwrapParens(c.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Readdirnames" {
								if fdID, okFD := unwrapParens(sel.X).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
									producesValidErr = true
									validErrName = l1.Name
								}
							}
							var fdStatTarget string
							var isFstatCall, isFileStatCall bool
							if _, okFN := isIdentNamed(c.Fun, "fstatNolog"); okFN && len(c.Args) == 1 {
								if fdID, okFD := unwrapParens(c.Args[0]).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
									fdStatTarget = fdID.Name
									isFstatCall = true
								}
							} else if sel, okS := unwrapParens(c.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Stat" && len(c.Args) == 0 {
								if fdID, okFD := unwrapParens(sel.X).(*ast.Ident); okFD && fdVarsInLoop[fdID.Name] {
									fdStatTarget = fdID.Name
									isFileStatCall = true
								}
							}
							if fdStatTarget != "" {
								usedStatHelpers = true
								producesValidErr = true
								validErrName = l1.Name
								if isFstatCall {
									usedFstatNolog = true
								}
								if isFileStatCall {
									usedFileStatInGetwd = true
								}
								guardIdx := idx + 1
								if guardIdx < len(stmts) && isCloseCallOn(stmts[guardIdx], fdStatTarget) {
									guardIdx++
								}
								if guardIdx < len(stmts) {
									if errRet, okG := isCheckedErrGuardIf(stmts[guardIdx], l1.Name); okG {
										allowedReturns[errRet] = true
										pdSeedAssigns[as] = true
										pdVarsInLoop[l0.Name] = true
									}
								}
							}
						}
					}
				}
				for _, lhs := range as.Lhs {
					if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
						delete(curValidErr, id.Name)
					}
				}
				if producesValidErr && validErrName != "" && validErrName != "_" {
					curValidErr[validErrName] = true
				}
			}

			switch x := st.(type) {
			case *ast.ReturnStmt:
				if len(x.Results) != 2 {
					return fmt.Errorf("os: Getwd return must have 2 explicit results")
				}
				if !allowedReturns[x] {
					if lit, okL := unwrapParens(x.Results[0]).(*ast.BasicLit); okL && lit.Kind == token.STRING {
						if lit.Value == `"/"` {
							_, okNil := isIdentNamed(x.Results[1], "nil")
							hasRootSameFile := false
							for _, enc := range enclosingIfs {
								if enc.Init == nil {
									if a0, a1, okSF := isSameFileCallPair(enc.Cond); okSF {
										if (rootVars[a0] && dotVars[a1]) || (rootVars[a1] && dotVars[a0]) {
											hasRootSameFile = true
											break
										}
									}
								}
							}
							if okNil && hasRootSameFile {
								allowedReturns[x] = true
								usedSameFile = true
								usedStatHelpers = true
							}
						} else if lit.Value == `""` && len(enclosingIfs) > 0 {
							if eID, okE := unwrapParens(x.Results[1]).(*ast.Ident); okE && eID.Name != "" && eID.Name != "_" && eID.Name != "nil" {
								for _, enc := range enclosingIfs {
									if validErrIfs[enc] == eID.Name && !stmtsMutateIdentBefore(enc.Body.List, x, eID.Name) {
										allowedReturns[x] = true
										break
									}
								}
							}
							if !allowedReturns[x] && isVerifiedConstGetwdErr(x.Results[1]) {
								for _, enc := range enclosingIfs {
									if (validErrIfs[enc] != "" && !stmtsMutateIdentBefore(enc.Body.List, x, validErrIfs[enc])) || isParentLenBoundCond(enc.Cond, parentLoopVars) {
										allowedReturns[x] = true
										break
									}
								}
							}
						}
					}
				}
			case *ast.IfStmt:
				if x.Init != nil {
					return fmt.Errorf("os: Getwd contains unexpected if init statement")
				}
				if checkedErr := condChecksNonZeroErr(x.Cond); checkedErr != "" && curValidErr[checkedErr] {
					validErrIfs[x] = checkedErr
				}
				nextIfs := append(slices.Clone(enclosingIfs), x)
				if err := verifyBlock(x.Body.List, nextIfs, inLoop, curPWD, curValidErr); err != nil {
					return err
				}
				if x.Else != nil {
					switch eb := x.Else.(type) {
					case *ast.BlockStmt:
						if err := verifyBlock(eb.List, enclosingIfs, inLoop, curPWD, curValidErr); err != nil {
							return err
						}
					case *ast.IfStmt:
						if err := verifyBlock([]ast.Stmt{eb}, enclosingIfs, inLoop, curPWD, curValidErr); err != nil {
							return err
						}
					default:
						return fmt.Errorf("os: Getwd unexpected else clause")
					}
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.ForStmt:
				sawLoopInGetwd = true
				if !inLoop && x.Cond == nil && topParentLoop == nil {
					topParentLoop = x
					topParentLoopIdx = idx
					initAs, okIA := x.Init.(*ast.AssignStmt)
					postAs, okPA := x.Post.(*ast.AssignStmt)
					if okIA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 && okPA && postAs.Tok == token.ASSIGN && len(postAs.Lhs) == 1 && len(postAs.Rhs) == 1 {
						if pID, okP := unwrapParens(initAs.Lhs[0]).(*ast.Ident); okP && pID.Name != "" && pID.Name != "_" {
							lit, okL := unwrapParens(initAs.Rhs[0]).(*ast.BasicLit)
							_, okPostLHS := isIdentNamed(postAs.Lhs[0], pID.Name)
							postBin, okPB := unwrapParens(postAs.Rhs[0]).(*ast.BinaryExpr)
							if okL && lit.Kind == token.STRING && lit.Value == `".."` && okPostLHS && okPB && postBin.Op == token.ADD {
								stepLit, okSL := unwrapParens(postBin.X).(*ast.BasicLit)
								_, okStepVar := isIdentNamed(postBin.Y, pID.Name)
								if okSL && stepLit.Kind == token.STRING && stepLit.Value == `"../"` && okStepVar {
									parentLoopVars[pID.Name] = true
									parentInitAssigns[initAs] = true
									parentStepAssigns[postAs] = true
								}
							}
						}
					}
				}
				if err := verifyBlock(x.Body.List, enclosingIfs, true, curPWD, curValidErr); err != nil {
					return err
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.RangeStmt:
				sawLoopInGetwd = true
				if err := verifyBlock(x.Body.List, enclosingIfs, true, curPWD, curValidErr); err != nil {
					return err
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.BlockStmt:
				if err := verifyBlock(x.List, enclosingIfs, inLoop, curPWD, curValidErr); err != nil {
					return err
				}
				mut, pwd := map[string]bool{}, map[string]bool{}
				collectCompoundStmtMutations(x, mut, pwd)
				for m := range mut {
					delete(curValidErr, m)
				}
				for p := range pwd {
					curPWD[p] = true
				}
			case *ast.AssignStmt, *ast.DeclStmt, *ast.ExprStmt, *ast.BranchStmt, *ast.EmptyStmt:
			default:
				return fmt.Errorf("os: Getwd contains unexpected statement %T", st)
			}
		}
		return nil
	}

	if err := verifyBlock(gwStmts, nil, false, map[string]bool{}, map[string]bool{}); err != nil {
		return err
	}

	return verifyOSGetwdClimbBodyAndHelpers(
		files, gwFn, gwStmts,
		topParentLoop, topParentLoopIdx, sawSyscallGetwd,
		usedGetwdCache, usedIgnoringEINTR2, usedNewSyscallError, usedOpenDirNolog,
		usedSameFile, usedStatHelpers, usedFstatNolog, usedFileStatInGetwd,
		allowedReturns, allowedSyscallGetwdSels,
		dotVars, rootVars, fdVarsInLoop, pdVarsInLoop, parentLoopVars, shape2ReturnedDirVars,
		dotSeedAssigns, rootSeedAssigns, fdSeedAssigns, pdSeedAssigns,
		parentInitAssigns, parentStepAssigns, shape1Assigns,
		allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods,
		nonAliasStructSpecs,
		pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts,
		funcFile, fileImportsSyscall,
		osReserved, osNoFileReserved, osAnyLinknameLocals,
		osInactive, skipInactiveHookIf,
		stmtUnwrapLabel, isSameFileCallPair, collectCompoundStmtMutations, stmtsMutateIdentBefore,
	)
}
