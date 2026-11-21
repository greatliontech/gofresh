package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
)

func verifyOSFileMethods(
	topFuncs, allTopFuncs, fileMethods, rawFileMethods map[string]*ast.FuncDecl,
	dirInfoCloseFn *ast.FuncDecl,
	funcFile map[*ast.FuncDecl]*ast.File,
	fileImportsTestlog, fileImportsIO, fileImportsSyscall, fileImportsUnsafe, fileImportsRuntime map[*ast.File]bool,
	osReserved, osNoFileReserved, osAnyLinknameLocals map[string]bool,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
) error {
	// 7. Verify (*os.File) write/close/fd sink delivery: checkValid, wrapErr, Write, WriteString, write, Fd, fd, Close, (*file).close.
	{
		cvFn := fileMethods["checkValid"]
		if cvFn == nil || len(cvFn.Body.List) < 2 || funcShadowsAnyIdent(cvFn, osReserved) || bodyHasControlFlowOrRecoverBypass(cvFn.Body) {
			return fmt.Errorf("os: missing or invalid (*File).checkValid")
		}
		cvRecv := recvVarName(cvFn)
		if cvRecv == "" || cvFn.Type.Params == nil || cvFn.Type.Params.NumFields() != 1 || !funcReturnsErrorLast(cvFn.Type) || cvFn.Type.Results.NumFields() != 1 {
			return fmt.Errorf("os: (*File).checkValid invalid signature")
		}
		ifs, ok := cvFn.Body.List[0].(*ast.IfStmt)
		if !ok || ifs.Init != nil || ifs.Else != nil || !condChecksEqErr(ifs.Cond, cvRecv) || len(ifs.Body.List) != 1 {
			return fmt.Errorf("os: (*File).checkValid missing nil receiver guard")
		}
		ret, ok := ifs.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 {
			return fmt.Errorf("os: (*File).checkValid invalid nil return")
		}
		if _, okErr := isIdentNamed(ret.Results[0], "ErrInvalid"); !okErr {
			return fmt.Errorf("os: (*File).checkValid does not return ErrInvalid")
		}
	}

	{
		weFn := fileMethods["wrapErr"]
		if weFn == nil || len(weFn.Body.List) < 2 || funcShadowsAnyIdent(weFn, osReserved) || bodyHasControlFlowOrRecoverBypass(weFn.Body) || !blockAlwaysReturns(weFn.Body.List) {
			return fmt.Errorf("os: missing or invalid (*File).wrapErr")
		}
		weParams := paramNamesFlat(weFn.Type.Params)
		if recvVarName(weFn) == "" || len(weParams) != 2 || weParams[1] == "" || weParams[1] == "_" || !funcReturnsErrorLast(weFn.Type) || weFn.Type.Results.NumFields() != 1 {
			return fmt.Errorf("os: (*File).wrapErr invalid signature")
		}
		errParam := weParams[1]
		if bodyDeclaresAnyIdent(weFn.Body, map[string]bool{errParam: true}) {
			return fmt.Errorf("os: (*File).wrapErr shadows error parameter")
		}
		badWrapErr := false
		ast.Inspect(weFn.Body, func(n ast.Node) bool {
			if badWrapErr || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.DeferStmt, *ast.FuncLit:
				badWrapErr = true
				return false
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					if id, ok := unwrapParens(node.X).(*ast.Ident); ok && id.Name == errParam {
						badWrapErr = true
						return false
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					if id, ok := unwrapParens(lhs).(*ast.Ident); ok && id.Name == errParam {
						if node.Tok != token.ASSIGN || i >= len(node.Rhs) {
							badWrapErr = true
							return false
						}
						if _, okEC := isIdentNamed(node.Rhs[i], "ErrClosed"); !okEC {
							badWrapErr = true
							return false
						}
					}
				}
			case *ast.ReturnStmt:
				if len(node.Results) != 1 {
					badWrapErr = true
					return false
				}
				if _, okID := isIdentNamed(node.Results[0], errParam); okID {
					return false
				}
				u, okU := unwrapParens(node.Results[0]).(*ast.UnaryExpr)
				_, tName := compositeWriterLit(node.Results[0])
				if !okU || u.Op != token.AND || tName != "PathError" {
					badWrapErr = true
					return false
				}
			}
			return true
		})
		if badWrapErr {
			return fmt.Errorf("os: (*File).wrapErr may swallow non-nil error")
		}
	}

	{
		wFn := fileMethods["Write"]
		if wFn == nil || len(wFn.Body.List) < 5 || !fileImportsIO[funcFile[wFn]] || funcShadowsAnyIdent(wFn, osReserved) || bodyHasControlFlowOrRecoverBypass(wFn.Body) {
			return fmt.Errorf("os: missing or invalid (*File).Write")
		}
		wRecv := recvVarName(wFn)
		wParams := paramNamesFlat(wFn.Type.Params)
		if wRecv == "" || len(wParams) != 1 || wParams[0] == "" || wParams[0] == "_" || wFn.Type.Results == nil || wFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wFn.Type.Results) || !funcReturnsErrorLast(wFn.Type) {
			return fmt.Errorf("os: (*File).Write invalid signature")
		}
		bParam := wParams[0]
		if bodyMutatesOrTakesAddrOfAny(wFn.Body, map[string]bool{wRecv: true, bParam: true}) || bodyDeclaresAnyIdent(wFn.Body, map[string]bool{wRecv: true, bParam: true}) {
			return fmt.Errorf("os: (*File).Write mutates receiver or slice parameter")
		}
		// List[0]: if err := f.checkValid("write"); err != nil { return 0, err }
		s0, ok := wFn.Body.List[0].(*ast.IfStmt)
		if !ok || s0.Init == nil || s0.Else != nil || len(s0.Body.List) != 1 {
			return fmt.Errorf("os: (*File).Write missing checkValid guard")
		}
		cvAs, ok := s0.Init.(*ast.AssignStmt)
		if !ok || (cvAs.Tok != token.DEFINE && cvAs.Tok != token.ASSIGN) || len(cvAs.Lhs) != 1 || len(cvAs.Rhs) != 1 {
			return fmt.Errorf("os: (*File).Write invalid checkValid assignment")
		}
		cvErrID, ok1 := unwrapParens(cvAs.Lhs[0]).(*ast.Ident)
		cvCall, ok2 := unwrapParens(cvAs.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || cvErrID.Name == "" || cvErrID.Name == "_" || condChecksNonZeroErr(s0.Cond) != cvErrID.Name || cvCall.Ellipsis.IsValid() || len(cvCall.Args) != 1 {
			return fmt.Errorf("os: (*File).Write invalid checkValid call")
		}
		if _, okSel := isSelectorBaseField(cvCall.Fun, wRecv, "checkValid"); !okSel {
			return fmt.Errorf("os: (*File).Write does not call %s.checkValid", wRecv)
		}
		cvRet, ok := s0.Body.List[0].(*ast.ReturnStmt)
		if !ok || len(cvRet.Results) != 2 || !isZeroIntLit(cvRet.Results[0]) {
			return fmt.Errorf("os: (*File).Write invalid checkValid return")
		}
		if _, okErr := isIdentNamed(cvRet.Results[1], cvErrID.Name); !okErr {
			return fmt.Errorf("os: (*File).Write checkValid does not propagate error")
		}

		// List[1]: n, e := f.write(b)
		s1, ok := wFn.Body.List[1].(*ast.AssignStmt)
		if !ok || (s1.Tok != token.DEFINE && s1.Tok != token.ASSIGN) || len(s1.Lhs) != 2 || len(s1.Rhs) != 1 {
			return fmt.Errorf("os: (*File).Write missing %s.write(%s) assignment", wRecv, bParam)
		}
		nID, ok1 := unwrapParens(s1.Lhs[0]).(*ast.Ident)
		eID, ok2 := unwrapParens(s1.Lhs[1]).(*ast.Ident)
		wrCall, ok3 := unwrapParens(s1.Rhs[0]).(*ast.CallExpr)
		if !ok1 || !ok2 || !ok3 || nID.Name == "" || nID.Name == "_" || eID.Name == "" || eID.Name == "_" || nID.Name == eID.Name || wrCall.Ellipsis.IsValid() || len(wrCall.Args) != 1 {
			return fmt.Errorf("os: (*File).Write invalid %s.write call", wRecv)
		}
		if _, okSel := isSelectorBaseField(wrCall.Fun, wRecv, "write"); !okSel {
			return fmt.Errorf("os: (*File).Write does not call %s.write", wRecv)
		}
		if _, okArg := isIdentNamed(wrCall.Args[0], bParam); !okArg {
			return fmt.Errorf("os: (*File).Write does not forward %s to %s.write", bParam, wRecv)
		}

		resNames := paramNamesFlat(wFn.Type.Results)
		var errVar string
		if len(resNames) == 2 && resNames[1] != "" && resNames[1] != "_" {
			errVar = resNames[1]
		}
		if errVar == eID.Name {
			return fmt.Errorf("os: (*File).Write aliases raw error and returned error")
		}
		var sawShortWrite, sawWrapErr bool
		for idx := 2; idx < len(wFn.Body.List)-1; idx++ {
			st := wFn.Body.List[idx]
			if ifs, isIf := st.(*ast.IfStmt); isIf && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
				if bin, okB := unwrapParens(ifs.Cond).(*ast.BinaryExpr); okB {
					// Optional: if n < 0 { n = 0 }
					if bin.Op == token.LSS && isZeroIntLit(bin.Y) {
						if _, okN := isIdentNamed(bin.X, nID.Name); okN && !sawShortWrite {
							if as, okA := ifs.Body.List[0].(*ast.AssignStmt); okA && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 && isZeroIntLit(as.Rhs[0]) {
								if _, okNL := isIdentNamed(as.Lhs[0], nID.Name); okNL {
									continue
								}
							}
						}
					}
					// Required: if n != len(b) { err = io.ErrShortWrite }
					if bin.Op == token.NEQ && isLenOfIdentCall(bin.Y, bParam) {
						if _, okN := isIdentNamed(bin.X, nID.Name); okN && !sawShortWrite && !sawWrapErr {
							if as, okA := ifs.Body.List[0].(*ast.AssignStmt); okA && (as.Tok == token.ASSIGN || as.Tok == token.DEFINE) && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
								lhsErr, okL := unwrapParens(as.Lhs[0]).(*ast.Ident)
								_, okSW := isSelectorBaseField(as.Rhs[0], "io", "ErrShortWrite")
								if okL && okSW && lhsErr.Name != "" && lhsErr.Name != "_" && lhsErr.Name != nID.Name && lhsErr.Name != eID.Name && (errVar == "" || errVar == lhsErr.Name) {
									errVar = lhsErr.Name
									sawShortWrite = true
									continue
								}
							}
						}
					}
				}
				// Required: if e != nil { err = f.wrapErr("write", e) }
				if condChecksNonZeroErr(ifs.Cond) == eID.Name && sawShortWrite && !sawWrapErr && errVar != "" {
					if as, okA := ifs.Body.List[0].(*ast.AssignStmt); okA && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						_, okL := isIdentNamed(as.Lhs[0], errVar)
						weCall, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
						if okL && okC && !weCall.Ellipsis.IsValid() && len(weCall.Args) == 2 {
							_, okSel := isSelectorBaseField(weCall.Fun, wRecv, "wrapErr")
							_, okArg := isIdentNamed(weCall.Args[1], eID.Name)
							if okSel && okArg {
								sawWrapErr = true
								continue
							}
						}
					}
				}
			}
			// Optional: epipecheck(f, e)
			if es, isES := st.(*ast.ExprStmt); isES {
				if c, okC := unwrapParens(es.X).(*ast.CallExpr); okC && !c.Ellipsis.IsValid() && len(c.Args) == 2 {
					_, ok0 := isIdentNamed(c.Args[0], wRecv)
					_, ok1 := isIdentNamed(c.Args[1], eID.Name)
					if cFun, okFun := unwrapParens(c.Fun).(*ast.Ident); okFun && cFun.Name == "epipecheck" && ok0 && ok1 {
						if err := verifyOSEpipecheck(allTopFuncs["epipecheck"], funcFile, fileImportsSyscall, osNoFileReserved, osAnyLinknameLocals); err != nil {
							return err
						}
						continue
					}
				}
			}
			return fmt.Errorf("os: (*File).Write unexpected statement at index %d", idx)
		}
		if !sawShortWrite || !sawWrapErr || errVar == "" {
			return fmt.Errorf("os: (*File).Write missing ErrShortWrite or wrapErr propagation")
		}
		lastRet, ok := wFn.Body.List[len(wFn.Body.List)-1].(*ast.ReturnStmt)
		if !ok || len(lastRet.Results) != 2 {
			return fmt.Errorf("os: (*File).Write invalid final return")
		}
		_, okRN := isIdentNamed(lastRet.Results[0], nID.Name)
		_, okRE := isIdentNamed(lastRet.Results[1], errVar)
		if !okRN || !okRE {
			return fmt.Errorf("os: (*File).Write final return does not return (%s, %s)", nID.Name, errVar)
		}
	}

	{
		wsFn := fileMethods["WriteString"]
		if wsFn == nil || (len(wsFn.Body.List) != 1 && len(wsFn.Body.List) != 2) || funcShadowsAnyIdent(wsFn, osReserved) || bodyHasControlFlowOrRecoverBypass(wsFn.Body) {
			return fmt.Errorf("os: missing or invalid (*File).WriteString")
		}
		wsRecv := recvVarName(wsFn)
		wsParams := paramNamesFlat(wsFn.Type.Params)
		if wsRecv == "" || len(wsParams) != 1 || wsParams[0] == "" || wsParams[0] == "_" || wsFn.Type.Results == nil || wsFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wsFn.Type.Results) || !funcReturnsErrorLast(wsFn.Type) {
			return fmt.Errorf("os: (*File).WriteString invalid signature")
		}
		sParam := wsParams[0]
		if len(wsFn.Body.List) == 1 {
			ret, ok := wsFn.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return fmt.Errorf("os: (*File).WriteString invalid 1-stmt return")
			}
			wCall, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
			if !ok || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
				return fmt.Errorf("os: (*File).WriteString invalid Write delegation")
			}
			if _, okSel := isSelectorBaseField(wCall.Fun, wsRecv, "Write"); !okSel {
				return fmt.Errorf("os: (*File).WriteString does not call %s.Write", wsRecv)
			}
			conv, ok := unwrapParens(wCall.Args[0]).(*ast.CallExpr)
			if !ok || conv.Ellipsis.IsValid() || len(conv.Args) != 1 {
				return fmt.Errorf("os: (*File).WriteString invalid []byte conversion")
			}
			at, okAT := unwrapParens(conv.Fun).(*ast.ArrayType)
			_, okByte := isIdentNamed(at.Elt, "byte")
			_, okS := isIdentNamed(conv.Args[0], sParam)
			if !okAT || at.Len != nil || !okByte || !okS {
				return fmt.Errorf("os: (*File).WriteString does not convert %s to []byte", sParam)
			}
		} else {
			if !fileImportsUnsafe[funcFile[wsFn]] {
				return fmt.Errorf("os: (*File).WriteString unsafe.Slice form missing unsafe import")
			}
			as, ok := wsFn.Body.List[0].(*ast.AssignStmt)
			if !ok || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return fmt.Errorf("os: (*File).WriteString invalid unsafe.Slice assignment")
			}
			bID, ok1 := unwrapParens(as.Lhs[0]).(*ast.Ident)
			slCall, ok2 := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
			if !ok1 || !ok2 || bID.Name == "" || bID.Name == "_" || slCall.Ellipsis.IsValid() || len(slCall.Args) != 2 || !isLenOfIdentCall(slCall.Args[1], sParam) {
				return fmt.Errorf("os: (*File).WriteString invalid unsafe.Slice call")
			}
			if _, okSel := isSelectorBaseField(slCall.Fun, "unsafe", "Slice"); !okSel {
				return fmt.Errorf("os: (*File).WriteString does not call unsafe.Slice")
			}
			sdCall, ok := unwrapParens(slCall.Args[0]).(*ast.CallExpr)
			if !ok || sdCall.Ellipsis.IsValid() || len(sdCall.Args) != 1 {
				return fmt.Errorf("os: (*File).WriteString invalid unsafe.StringData call")
			}
			_, okSDSel := isSelectorBaseField(sdCall.Fun, "unsafe", "StringData")
			_, okSArg := isIdentNamed(sdCall.Args[0], sParam)
			if !okSDSel || !okSArg {
				return fmt.Errorf("os: (*File).WriteString does not pass %s to unsafe.StringData", sParam)
			}
			ret, ok := wsFn.Body.List[1].(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return fmt.Errorf("os: (*File).WriteString invalid return")
			}
			wCall, ok := unwrapParens(ret.Results[0]).(*ast.CallExpr)
			if !ok || wCall.Ellipsis.IsValid() || len(wCall.Args) != 1 {
				return fmt.Errorf("os: (*File).WriteString invalid Write call")
			}
			_, okWSel := isSelectorBaseField(wCall.Fun, wsRecv, "Write")
			_, okBArg := isIdentNamed(wCall.Args[0], bID.Name)
			if !okWSel || !okBArg {
				return fmt.Errorf("os: (*File).WriteString does not return %s.Write(%s)", wsRecv, bID.Name)
			}
		}
	}

	{
		wrFn := fileMethods["write"]
		if wrFn == nil || len(wrFn.Body.List) < 2 || funcShadowsAnyIdent(wrFn, osReserved) || bodyHasControlFlowOrRecoverBypass(wrFn.Body) {
			return fmt.Errorf("os: missing or invalid (*File).write")
		}
		wrRecv := recvVarName(wrFn)
		wrParams := paramNamesFlat(wrFn.Type.Params)
		if wrRecv == "" || len(wrParams) != 1 || wrParams[0] == "" || wrParams[0] == "_" || wrFn.Type.Results == nil || wrFn.Type.Results.NumFields() != 2 || !firstResultIsInt(wrFn.Type.Results) || !funcReturnsErrorLast(wrFn.Type) {
			return fmt.Errorf("os: (*File).write invalid signature")
		}
		bParam := wrParams[0]
		if bodyMutatesOrTakesAddrOfAny(wrFn.Body, map[string]bool{wrRecv: true, bParam: true}) || bodyDeclaresAnyIdent(wrFn.Body, map[string]bool{wrRecv: true, bParam: true}) {
			return fmt.Errorf("os: (*File).write mutates receiver or slice parameter")
		}
		pos := 0
		for pos < len(wrFn.Body.List) && skipInactiveHookIf(wrFn.Body.List[pos], wrFn) {
			pos++
		}
		validPosixWrite := false
		if pos+1 < len(wrFn.Body.List) {
			if as, ok := wrFn.Body.List[pos].(*ast.AssignStmt); ok && (as.Tok == token.ASSIGN || as.Tok == token.DEFINE) && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
				nID, ok1 := unwrapParens(as.Lhs[0]).(*ast.Ident)
				eID, ok2 := unwrapParens(as.Lhs[1]).(*ast.Ident)
				pfdCall, ok3 := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
				if ok1 && ok2 && ok3 && nID.Name != "" && nID.Name != "_" && eID.Name != "" && eID.Name != "_" && nID.Name != eID.Name && !pfdCall.Ellipsis.IsValid() && len(pfdCall.Args) == 1 {
					if _, okArg := isIdentNamed(pfdCall.Args[0], bParam); okArg {
						if wSel, okS := unwrapParens(pfdCall.Fun).(*ast.SelectorExpr); okS && wSel.Sel.Name == "Write" {
							if _, okPFD := isSelectorBaseField(wSel.X, wrRecv, "pfd"); okPFD {
								midOK := true
								for _, mid := range wrFn.Body.List[pos+1 : len(wrFn.Body.List)-1] {
									es, okES := mid.(*ast.ExprStmt)
									if !okES {
										midOK = false
										break
									}
									kc, okKC := unwrapParens(es.X).(*ast.CallExpr)
									if !okKC || kc.Ellipsis.IsValid() || len(kc.Args) != 1 {
										midOK = false
										break
									}
									_, okKA := isSelectorBaseField(kc.Fun, "runtime", "KeepAlive")
									_, okKArg := isIdentNamed(kc.Args[0], wrRecv)
									if !okKA || !okKArg {
										midOK = false
										break
									}
								}
								if ret, okR := wrFn.Body.List[len(wrFn.Body.List)-1].(*ast.ReturnStmt); midOK && okR && len(ret.Results) == 2 {
									_, okRN := isIdentNamed(ret.Results[0], nID.Name)
									_, okRE := isIdentNamed(ret.Results[1], eID.Name)
									if okRN && okRE {
										validPosixWrite = true
									}
								}
							}
						}
					}
				}
			}
		}
		validPlan9Write := false
		if !validPosixWrite && pos == 0 && len(wrFn.Body.List) == 4 && fileImportsSyscall[funcFile[wrFn]] {
			// Plan 9: writeLock guard, defer writeUnlock, len(b) == 0 guard, return fixCount(syscall.Write(f.sysfd, b)).
			s0, ok0 := wrFn.Body.List[0].(*ast.IfStmt)
			s1, ok1 := wrFn.Body.List[1].(*ast.DeferStmt)
			s2, ok2 := wrFn.Body.List[2].(*ast.IfStmt)
			s3, ok3 := wrFn.Body.List[3].(*ast.ReturnStmt)
			fcFn := topFuncs["fixCount"]
			if ok0 && ok1 && ok2 && ok3 && s0.Else == nil && s2.Init == nil && s2.Else == nil && len(s3.Results) == 1 && fcFn != nil && len(fcFn.Body.List) == 2 && !funcShadowsAnyIdent(fcFn, osReserved) && !bodyHasControlFlowOrRecoverBypass(fcFn.Body) {
				if _, okUnlock := isZeroArgMethodCallOnIdent(s1.Call, wrRecv, "writeUnlock"); okUnlock {
					if bin, okB := unwrapParens(s2.Cond).(*ast.BinaryExpr); okB && bin.Op == token.EQL && isLenOfIdentCall(bin.X, bParam) && isZeroIntLit(bin.Y) && len(s2.Body.List) == 1 {
						if zRet, okZR := s2.Body.List[0].(*ast.ReturnStmt); okZR && len(zRet.Results) == 2 && isZeroIntLit(zRet.Results[0]) {
							if _, okNil := isIdentNamed(zRet.Results[1], "nil"); okNil {
								if fcCall, okFC := unwrapParens(s3.Results[0]).(*ast.CallExpr); okFC && !fcCall.Ellipsis.IsValid() && len(fcCall.Args) == 1 {
									if _, okFCID := isIdentNamed(fcCall.Fun, "fixCount"); okFCID {
										if sc, okSC := unwrapParens(fcCall.Args[0]).(*ast.CallExpr); okSC && !sc.Ellipsis.IsValid() && len(sc.Args) == 2 {
											_, okSCSel := isSelectorBaseField(sc.Fun, "syscall", "Write")
											_, okSysfd := isSelectorBaseField(sc.Args[0], wrRecv, "sysfd")
											_, okBArg := isIdentNamed(sc.Args[1], bParam)
											fcParams := paramNamesFlat(fcFn.Type.Params)
											if okSCSel && okSysfd && okBArg && len(fcParams) == 2 {
												if fcRet, okFCR := fcFn.Body.List[1].(*ast.ReturnStmt); okFCR && len(fcRet.Results) == 2 {
													_, okFN := isIdentNamed(fcRet.Results[0], fcParams[0])
													_, okFE := isIdentNamed(fcRet.Results[1], fcParams[1])
													if okFN && okFE && !bodyMutatesOrTakesAddrOfAny(fcFn.Body, map[string]bool{fcParams[1]: true}) {
														validPlan9Write = true
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
		if !validPosixWrite && !validPlan9Write {
			return fmt.Errorf("os: (*File).write has unverified implementation")
		}
	}

	if err := verifyOSFileFdMethods(fileMethods["Fd"], fileMethods["fd"], osNoFileReserved, skipInactiveHookIf); err != nil {
		return err
	}

	{
		clFn := fileMethods["Close"]
		if clFn == nil || len(clFn.Body.List) < 2 || funcShadowsAnyIdent(clFn, osReserved) || bodyHasControlFlowOrRecoverBypass(clFn.Body) {
			return fmt.Errorf("os: missing or invalid (*File).Close")
		}
		clRecv := recvVarName(clFn)
		if clRecv == "" || (clFn.Type.Params != nil && clFn.Type.Params.NumFields() != 0) || !funcReturnsErrorLast(clFn.Type) || clFn.Type.Results.NumFields() != 1 {
			return fmt.Errorf("os: (*File).Close invalid signature")
		}
		ifs0, ok := clFn.Body.List[0].(*ast.IfStmt)
		if !ok || ifs0.Init != nil || ifs0.Else != nil || !condChecksEqErr(ifs0.Cond, clRecv) || len(ifs0.Body.List) != 1 {
			return fmt.Errorf("os: (*File).Close missing nil receiver guard")
		}
		if ret0, okR := ifs0.Body.List[0].(*ast.ReturnStmt); !okR || len(ret0.Results) != 1 {
			return fmt.Errorf("os: (*File).Close invalid nil receiver return")
		} else if _, okEI := isIdentNamed(ret0.Results[0], "ErrInvalid"); !okEI {
			return fmt.Errorf("os: (*File).Close nil receiver guard does not return ErrInvalid")
		}
		pos := 1
		for pos < len(clFn.Body.List) && skipInactiveHookIf(clFn.Body.List[pos], clFn) {
			pos++
		}
		if len(clFn.Body.List) != pos+1 {
			return fmt.Errorf("os: (*File).Close unexpected statements before f.file.close()")
		}
		retClose, ok := clFn.Body.List[pos].(*ast.ReturnStmt)
		if !ok || len(retClose.Results) != 1 {
			return fmt.Errorf("os: (*File).Close invalid final return")
		}
		cCall, ok := unwrapParens(retClose.Results[0]).(*ast.CallExpr)
		if !ok || cCall.Ellipsis.IsValid() || len(cCall.Args) != 0 {
			return fmt.Errorf("os: (*File).Close invalid close() call")
		}
		cSel, ok := unwrapParens(cCall.Fun).(*ast.SelectorExpr)
		if !ok || cSel.Sel.Name != "close" {
			return fmt.Errorf("os: (*File).Close does not call f.file.close()")
		}
		if _, okFile := isSelectorBaseField(cSel.X, clRecv, "file"); !okFile {
			return fmt.Errorf("os: (*File).Close receiver is not %s.file", clRecv)
		}
	}

	{
		rcFn := rawFileMethods["close"]
		if rcFn == nil || len(rcFn.Body.List) < 3 || funcShadowsAnyIdent(rcFn, osNoFileReserved) || bodyHasControlFlowOrRecoverBypass(rcFn.Body) {
			return fmt.Errorf("os: missing or invalid (*file).close")
		}
		rcRecv := recvVarName(rcFn)
		if rcRecv == "" || (rcFn.Type.Params != nil && rcFn.Type.Params.NumFields() != 0) || !funcReturnsErrorLast(rcFn.Type) || rcFn.Type.Results.NumFields() != 1 {
			return fmt.Errorf("os: (*file).close invalid signature")
		}
		if bodyMutatesOrTakesAddrOfAny(rcFn.Body, map[string]bool{rcRecv: true}) || bodyDeclaresAnyIdent(rcFn.Body, map[string]bool{rcRecv: true}) {
			return fmt.Errorf("os: (*file).close mutates or shadows receiver")
		}
		isSetFinalizerNilStmt := func(st ast.Stmt) bool {
			if !fileImportsRuntime[funcFile[rcFn]] {
				return false
			}
			es, okES := st.(*ast.ExprStmt)
			if !okES {
				return false
			}
			c, okC := unwrapParens(es.X).(*ast.CallExpr)
			if !okC || c.Ellipsis.IsValid() || len(c.Args) != 2 {
				return false
			}
			_, okSF := isSelectorBaseField(c.Fun, "runtime", "SetFinalizer")
			_, okR := isIdentNamed(c.Args[0], rcRecv)
			_, okN := isIdentNamed(c.Args[1], "nil")
			return okSF && okR && okN
		}
		validPFDClose := false
		if ifs0, ok0 := rcFn.Body.List[0].(*ast.IfStmt); ok0 && ifs0.Init == nil && ifs0.Else == nil && condChecksEqErr(ifs0.Cond, rcRecv) && len(ifs0.Body.List) == 1 {
			if ret0, okR0 := ifs0.Body.List[0].(*ast.ReturnStmt); okR0 && len(ret0.Results) == 1 {
				_, okNilEI := isIdentNamed(ret0.Results[0], "ErrInvalid")
				_, okNilEINVAL := isSelectorBaseField(ret0.Results[0], "syscall", "EINVAL")
				if okNilEI || (fileImportsSyscall[funcFile[rcFn]] && okNilEINVAL) {
					var errVar string
					pfdCloseIdx := -1
					directReturnOnErr := false
					preOK := true
					for idx := 1; idx < len(rcFn.Body.List)-1; idx++ {
						st := rcFn.Body.List[idx]
						if pfdCloseIdx < 0 && skipInactiveHookIf(st, rcFn) {
							continue
						}
						if isDirinfoSwapCloseIf(st, rcRecv, dirInfoCloseFn, osNoFileReserved, osAnyLinknameLocals) {
							continue
						}
						if ds, isDS := st.(*ast.DeclStmt); isDS {
							if gd, okGD := ds.Decl.(*ast.GenDecl); okGD && gd.Tok == token.VAR && len(gd.Specs) == 1 {
								if vs, okVS := gd.Specs[0].(*ast.ValueSpec); okVS && len(vs.Names) == 1 && len(vs.Values) == 0 {
									if _, okErrT := isIdentNamed(vs.Type, "error"); okErrT && errVar == "" {
										errVar = vs.Names[0].Name
										continue
									}
								}
							}
						}
						if ifs, isIf := st.(*ast.IfStmt); isIf && ifs.Init != nil && ifs.Else == nil {
							if initAs, okA := ifs.Init.(*ast.AssignStmt); okA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 {
								eID, okE := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
								pcCall, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
								if okE && okC && eID.Name != "" && eID.Name != "_" && condChecksNonZeroErr(ifs.Cond) == eID.Name && !pcCall.Ellipsis.IsValid() && len(pcCall.Args) == 0 {
									if pcSel, okS := unwrapParens(pcCall.Fun).(*ast.SelectorExpr); okS && pcSel.Sel.Name == "Close" {
										if _, okPFD := isSelectorBaseField(pcSel.X, rcRecv, "pfd"); okPFD {
											if len(ifs.Body.List) == 1 {
												if rStmt, okRS := ifs.Body.List[0].(*ast.ReturnStmt); okRS && len(rStmt.Results) == 1 {
													_, okRetE := isIdentNamed(rStmt.Results[0], eID.Name)
													u, okU := unwrapParens(rStmt.Results[0]).(*ast.UnaryExpr)
													_, tName := compositeWriterLit(rStmt.Results[0])
													if okRetE || (okU && u.Op == token.AND && tName == "PathError") {
														pfdCloseIdx = idx
														directReturnOnErr = true
														break
													}
												}
											}
											if errVar != "" && len(ifs.Body.List) >= 1 {
												lastAssign, okLA := ifs.Body.List[len(ifs.Body.List)-1].(*ast.AssignStmt)
												if okLA && lastAssign.Tok == token.ASSIGN && len(lastAssign.Lhs) == 1 && len(lastAssign.Rhs) == 1 {
													_, okL := isIdentNamed(lastAssign.Lhs[0], errVar)
													u, okU := unwrapParens(lastAssign.Rhs[0]).(*ast.UnaryExpr)
													_, tName := compositeWriterLit(lastAssign.Rhs[0])
													preErrOK := true
													for _, preS := range ifs.Body.List[:len(ifs.Body.List)-1] {
														preIf, okPI := preS.(*ast.IfStmt)
														if !okPI || preIf.Init != nil || preIf.Else != nil || len(preIf.Body.List) != 1 || exprContainsAnyCall(preIf.Cond) {
															preErrOK = false
															break
														}
														preAs, okPA := preIf.Body.List[0].(*ast.AssignStmt)
														if !okPA || preAs.Tok != token.ASSIGN || len(preAs.Lhs) != 1 || len(preAs.Rhs) != 1 {
															preErrOK = false
															break
														}
														_, okPL := isIdentNamed(preAs.Lhs[0], eID.Name)
														_, okPR := isIdentNamed(preAs.Rhs[0], "ErrClosed")
														if !okPL || !okPR {
															preErrOK = false
															break
														}
													}
													if okL && okU && u.Op == token.AND && tName == "PathError" && preErrOK {
														pfdCloseIdx = idx
														break
													}
												}
											}
										}
									}
								}
							}
						}
						preOK = false
						break
					}
					if preOK && pfdCloseIdx >= 1 {
						postOK := true
						for _, postSt := range rcFn.Body.List[pfdCloseIdx+1 : len(rcFn.Body.List)-1] {
							if !isSetFinalizerNilStmt(postSt) {
								postOK = false
								break
							}
						}
						if lastRet, okLR := rcFn.Body.List[len(rcFn.Body.List)-1].(*ast.ReturnStmt); postOK && okLR && len(lastRet.Results) == 1 {
							if directReturnOnErr {
								if _, okNil := isIdentNamed(lastRet.Results[0], "nil"); okNil {
									validPFDClose = true
								}
							} else if errVar != "" {
								if _, okEV := isIdentNamed(lastRet.Results[0], errVar); okEV {
									validPFDClose = true
								}
							}
						}
					}
				}
			}
		}
		validPlan9Close := false
		if !validPFDClose && len(rcFn.Body.List) >= 3 {
			decFn := rawFileMethods["decref"]
			desFn := rawFileMethods["destroy"]
			if decFn != nil && desFn != nil && len(decFn.Body.List) == 2 && len(desFn.Body.List) == 3 &&
				fileImportsSyscall[funcFile[desFn]] &&
				!funcShadowsAnyIdent(decFn, osNoFileReserved) && !bodyHasControlFlowOrRecoverBypass(decFn.Body) &&
				!funcShadowsAnyIdent(desFn, osNoFileReserved) && !bodyHasControlFlowOrRecoverBypass(desFn.Body) {
				decRecv := recvVarName(decFn)
				desRecv := recvVarName(desFn)
				// 1. (*file).close List[0]: if !file.fdmu.IncrefAndClose() { return &PathError{...} }
				ifs0, okI0 := rcFn.Body.List[0].(*ast.IfStmt)
				var closeGuardOK bool
				if okI0 && ifs0.Init == nil && ifs0.Else == nil && len(ifs0.Body.List) == 1 {
					if u0, okU0 := unwrapParens(ifs0.Cond).(*ast.UnaryExpr); okU0 && u0.Op == token.NOT {
						if icCall, okIC := unwrapParens(u0.X).(*ast.CallExpr); okIC && !icCall.Ellipsis.IsValid() && len(icCall.Args) == 0 {
							if icSel, okS := unwrapParens(icCall.Fun).(*ast.SelectorExpr); okS && icSel.Sel.Name == "IncrefAndClose" {
								if _, okFDMU := isSelectorBaseField(icSel.X, rcRecv, "fdmu"); okFDMU {
									if r0, okR0 := ifs0.Body.List[0].(*ast.ReturnStmt); okR0 && len(r0.Results) == 1 {
										_, okEC := isIdentNamed(r0.Results[0], "ErrClosed")
										uPE, okUPE := unwrapParens(r0.Results[0]).(*ast.UnaryExpr)
										_, tPE := compositeWriterLit(r0.Results[0])
										closeGuardOK = okEC || (okUPE && uPE.Op == token.AND && tPE == "PathError")
									}
								}
							}
						}
					}
				}
				// 2. (*file).decref: if file.fdmu.Decref() { return file.destroy() }; return nil
				var decOK bool
				if decRecv != "" && (decFn.Type.Params == nil || decFn.Type.Params.NumFields() == 0) && funcReturnsErrorLast(decFn.Type) && decFn.Type.Results.NumFields() == 1 {
					if dIf, okDI := decFn.Body.List[0].(*ast.IfStmt); okDI && dIf.Init == nil && dIf.Else == nil && len(dIf.Body.List) == 1 {
						if dCall, okDC := unwrapParens(dIf.Cond).(*ast.CallExpr); okDC && !dCall.Ellipsis.IsValid() && len(dCall.Args) == 0 {
							if dSel, okDS := unwrapParens(dCall.Fun).(*ast.SelectorExpr); okDS && dSel.Sel.Name == "Decref" {
								if _, okFDMU := isSelectorBaseField(dSel.X, decRecv, "fdmu"); okFDMU {
									if dRet, okDR := dIf.Body.List[0].(*ast.ReturnStmt); okDR && len(dRet.Results) == 1 {
										if _, okDest := isZeroArgMethodCallOnIdent(dRet.Results[0], decRecv, "destroy"); okDest {
											if dNil, okDN := decFn.Body.List[1].(*ast.ReturnStmt); okDN && len(dNil.Results) == 1 {
												_, decOK = isIdentNamed(dNil.Results[0], "nil")
											}
										}
									}
								}
							}
						}
					}
				}
				// 3. (*file).destroy: var err error; if e := syscall.Close(file.sysfd); e != nil { err = &PathError{...} }; return err
				var desOK bool
				if desRecv != "" && (desFn.Type.Params == nil || desFn.Type.Params.NumFields() == 0) && funcReturnsErrorLast(desFn.Type) && desFn.Type.Results.NumFields() == 1 && !bodyMutatesOrTakesAddrOfAny(desFn.Body, map[string]bool{desRecv: true}) {
					var desErrVar string
					if ds, okDS := desFn.Body.List[0].(*ast.DeclStmt); okDS {
						if gd, okGD := ds.Decl.(*ast.GenDecl); okGD && gd.Tok == token.VAR && len(gd.Specs) == 1 {
							if vs, okVS := gd.Specs[0].(*ast.ValueSpec); okVS && len(vs.Names) == 1 && len(vs.Values) == 0 {
								if _, okET := isIdentNamed(vs.Type, "error"); okET {
									desErrVar = vs.Names[0].Name
								}
							}
						}
					}
					if desErrVar != "" {
						if sIf, okSI := desFn.Body.List[1].(*ast.IfStmt); okSI && sIf.Init != nil && sIf.Else == nil && len(sIf.Body.List) == 1 {
							if sInit, okSIn := sIf.Init.(*ast.AssignStmt); okSIn && sInit.Tok == token.DEFINE && len(sInit.Lhs) == 1 && len(sInit.Rhs) == 1 {
								seID, okSE := unwrapParens(sInit.Lhs[0]).(*ast.Ident)
								scCall, okSC := unwrapParens(sInit.Rhs[0]).(*ast.CallExpr)
								if okSE && okSC && seID.Name != "" && seID.Name != "_" && condChecksNonZeroErr(sIf.Cond) == seID.Name && !scCall.Ellipsis.IsValid() && len(scCall.Args) == 1 {
									_, okSCSel := isSelectorBaseField(scCall.Fun, "syscall", "Close")
									_, okSysfd := isSelectorBaseField(scCall.Args[0], desRecv, "sysfd")
									if okSCSel && okSysfd {
										if eAs, okEA := sIf.Body.List[0].(*ast.AssignStmt); okEA && eAs.Tok == token.ASSIGN && len(eAs.Lhs) == 1 && len(eAs.Rhs) == 1 {
											_, okEL := isIdentNamed(eAs.Lhs[0], desErrVar)
											_, okER := isIdentNamed(eAs.Rhs[0], seID.Name)
											uPE, okUPE := unwrapParens(eAs.Rhs[0]).(*ast.UnaryExpr)
											_, tPE := compositeWriterLit(eAs.Rhs[0])
											if okEL && (okER || (okUPE && uPE.Op == token.AND && tPE == "PathError")) {
												if dLast, okDL := desFn.Body.List[2].(*ast.ReturnStmt); okDL && len(dLast.Results) == 1 {
													_, desOK = isIdentNamed(dLast.Results[0], desErrVar)
												}
											}
										}
									}
								}
							}
						}
					}
				}
				if closeGuardOK && decOK && desOK {
					if as, okA := rcFn.Body.List[1].(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						eID, okE := unwrapParens(as.Lhs[0]).(*ast.Ident)
						midClean := true
						for _, mid := range rcFn.Body.List[2 : len(rcFn.Body.List)-1] {
							if !isSetFinalizerNilStmt(mid) {
								midClean = false
								break
							}
						}
						_, okDecref := isZeroArgMethodCallOnIdent(as.Rhs[0], rcRecv, "decref")
						if okE && eID.Name != "" && eID.Name != "_" && midClean && okDecref && !bodyMutatesOrTakesAddrOfAny(&ast.BlockStmt{List: rcFn.Body.List[2:]}, map[string]bool{eID.Name: true}) {
							if lr, okLR := rcFn.Body.List[len(rcFn.Body.List)-1].(*ast.ReturnStmt); okLR && len(lr.Results) == 1 {
								if _, okRE := isIdentNamed(lr.Results[0], eID.Name); okRE {
									validPlan9Close = true
								}
							}
						}
					}
				}
			}
		}
		if !validPFDClose && !validPlan9Close {
			return fmt.Errorf("os: (*file).close has unverified implementation")
		}
	}

	if err := verifyOSFileChdir(fileMethods["Chdir"], fileMethods["incref"], funcFile, fileImportsTestlog, fileImportsSyscall, osReserved, skipInactiveHookIf); err != nil {
		return err
	}
	return nil
}
