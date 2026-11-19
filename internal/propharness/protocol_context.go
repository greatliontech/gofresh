package propharness

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// verifyHarnessProtocolCallContexts enforces the contextual call, namespace,
// failfile-path, joined-synctest-bubble, and imported-variable invariants over
// a candidate harness package, returning the subset of categoryA globals whose
// initialization depends on command-line flags or environment variables.
func verifyHarnessProtocolCallContexts(
	audited bool,
	g *harnessGraph,
	categoryA map[*types.Var]bool,
) (map[*types.Var]bool, string) {
	pkg := g.pkg
	info := g.info
	pkgTypes := g.pkgTypes
	sc := g.screen
	declFuncs := g.declFuncs
	initOnly := g.initOnly
	callSites := g.callSitesByFunc

	failfileVars, failfileParams, failfileResults := computeHarnessFailfileProvenance(g, categoryA)
	envFlagVars := collectEnvFlagCategoryAVars(g, categoryA)

	var validEnvStringParam func(fn *types.Func, pIdx int, seen map[harnessParamKey]bool) bool
	validEnvStringParam = func(fn *types.Func, pIdx int, seen map[harnessParamKey]bool) bool {
		if fn == nil || !initOnly[fn] || fn.Signature().Variadic() {
			return false
		}
		params := fn.Signature().Params()
		if pIdx < 0 || pIdx >= params.Len() {
			return false
		}
		key := harnessParamKey{fn: fn, idx: pIdx}
		if seen[key] {
			return true
		}
		seen[key] = true
		sites := callSites[fn]
		if len(sites) == 0 {
			return false
		}
		for _, site := range sites {
			if site.Ellipsis.IsValid() || pIdx >= len(site.Args) {
				return false
			}
			arg := site.Args[pIdx]
			if constStringPrefix(info, arg, sc.envPrefix) {
				continue
			}
			argIdent, ok := ast.Unparen(arg).(*ast.Ident)
			if !ok {
				return false
			}
			paramObj, ok := info.Uses[argIdent].(*types.Var)
			if !ok || paramObj == nil {
				return false
			}
			callerFn, callerIdx := g.findFuncParamIndex(paramObj)
			if callerFn == nil || !validEnvStringParam(callerFn, callerIdx, seen) {
				return false
			}
		}
		return true
	}

	var validInitLookupParam func(fn *types.Func, pIdx int, seen map[harnessParamKey]bool) bool
	validInitLookupParam = func(fn *types.Func, pIdx int, seen map[harnessParamKey]bool) bool {
		if fn == nil || !initOnly[fn] || fn.Signature().Variadic() {
			return false
		}
		params := fn.Signature().Params()
		if pIdx < 0 || pIdx >= params.Len() {
			return false
		}
		key := harnessParamKey{fn: fn, idx: pIdx}
		if seen[key] {
			return true
		}
		seen[key] = true
		paramVar := params.At(pIdx)
		fd := declFuncs[fn]
		if fd == nil || fd.Body == nil {
			return false
		}
		allowedIdents := map[*ast.Ident]bool{}
		okBody := true
		var inspectBody func(n ast.Node, inLit bool)
		inspectBody = func(n ast.Node, inLit bool) {
			if !okBody || n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				inspectBody(x.Type, true)
				inspectBody(x.Body, true)
				return
			case *ast.GoStmt:
				inspectBody(x.Call, true)
				return
			case *ast.CallExpr:
				if funID, ok := syntaxutil.UnwrapCallee(x.Fun).(*ast.Ident); ok && info.Uses[funID] == paramVar {
					if inLit || x.Ellipsis.IsValid() || len(x.Args) != 1 {
						okBody = false
						return
					}
					allowedIdents[funID] = true
					keyArg := x.Args[0]
					if !constStringPrefix(info, keyArg, sc.envPrefix) {
						argID, ok := ast.Unparen(keyArg).(*ast.Ident)
						if !ok {
							okBody = false
							return
						}
						pObj, ok := info.Uses[argID].(*types.Var)
						if !ok || pObj == nil {
							okBody = false
							return
						}
						ownerFn, ownerIdx := g.findFuncParamIndex(pObj)
						if ownerFn != fn || !validEnvStringParam(fn, ownerIdx, map[harnessParamKey]bool{}) {
							okBody = false
							return
						}
					}
				} else {
					callee := resolveHarnessFuncExpr(info, x.Fun)
					for argIdx, arg := range x.Args {
						if argID, ok := ast.Unparen(arg).(*ast.Ident); ok && info.Uses[argID] == paramVar {
							if inLit || x.Ellipsis.IsValid() || callee == nil || declFuncs[callee.Origin()] == nil || !validInitLookupParam(callee.Origin(), argIdx, seen) {
								okBody = false
								return
							}
							allowedIdents[argID] = true
						}
					}
				}
			case *ast.Ident:
				if info.Uses[x] == paramVar && !allowedIdents[x] {
					okBody = false
					return
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if !okBody || child == nil {
					return false
				}
				if child == n {
					return true
				}
				inspectBody(child, inLit)
				return false
			})
		}
		inspectBody(fd.Body, false)
		return okBody
	}

	sawTBLogf := false
	okAll := true
	failReason := ""
	fail := func(msg string) {
		if okAll {
			okAll = false
			failReason = msg
		}
	}

	checkTree := func(root ast.Node, inInitRoot bool, enclosingFD *ast.FuncDecl, enclosingFn *types.Func) {
		approvedIdents := map[*ast.Ident]bool{}
		var tempFileVars map[*types.Var]bool
		if enclosingFD != nil && enclosingFD.Body != nil {
			tempFileVars = collectHarnessTempFileVars(g, enclosingFD.Body, categoryA, failfileVars, failfileParams, failfileResults)
		}
		isFailfile := func(e ast.Expr) bool {
			return isHarnessFailfileExpr(g, e, categoryA, failfileVars, failfileParams, failfileResults)
		}

		var walk func(n ast.Node, inInitExec bool, inLit bool, inFlagBoolGuard bool)
		walk = func(n ast.Node, inInitExec bool, inLit bool, inFlagBoolGuard bool) {
			if !okAll || n == nil {
				return
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				walk(x.Type, false, true, false)
				walk(x.Body, false, true, false)
				return
			case *ast.GoStmt:
				if inInitRoot || inLit || enclosingFD == nil || enclosingFD.Body == nil ||
					!verifyJoinedSynctestGoStmt(info, pkgTypes, enclosingFD.Body, x) {
					fail("unjoined go stmt")
					return
				}
				walk(x.Call, false, true, false)
				return
			case *ast.IfStmt:
				if x.Init != nil {
					walk(x.Init, inInitExec, inLit, inFlagBoolGuard)
				}
				walk(x.Cond, inInitExec, inLit, inFlagBoolGuard)
				condGuard := inFlagBoolGuard || (!inLit && isCategoryABoolFieldExpr(info, x.Cond, categoryA))
				walk(x.Body, inInitExec, inLit, condGuard)
				if x.Else != nil {
					walk(x.Else, inInitExec, inLit, inFlagBoolGuard)
				}
				return
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if rootImportedVar(info, lhs, pkgTypes) != nil {
						fail("assign imported var")
						return
					}
				}
			case *ast.IncDecStmt:
				if rootImportedVar(info, x.X, pkgTypes) != nil {
					fail("incdec imported var")
					return
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && rootImportedVar(info, x.Key, pkgTypes) != nil) ||
						(x.Value != nil && rootImportedVar(info, x.Value, pkgTypes) != nil) {
						fail("range assign imported var")
						return
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && rootImportedVar(info, x.X, pkgTypes) != nil {
					fail("addr imported var")
					return
				}
			case *ast.CallExpr:
				if arg0, ok := mutatingBuiltinFirstArg(info, x); ok && rootImportedVar(info, arg0, pkgTypes) != nil {
					fail("builtin mutate imported var")
					return
				}
				callee := resolveHarnessFuncExpr(info, x.Fun)
				if callee != nil {
					if callee.Name() == "Logf" && callee.Signature().Recv() != nil {
						sawTBLogf = true
					}
					if callee.Pkg() != nil && callee.Pkg() != pkgTypes {
						impPath := callee.Pkg().Path()
						switch {
						case impPath == "flag":
							if !inInitExec || x.Ellipsis.IsValid() || len(x.Args) != 4 {
								fail("flag call outside init or bad arity: " + callee.Name())
								return
							}
							if !isAddrOfCarrierFreeFlagField(audited, info, x.Args[0], g.pkgVarSet) || !constStringPrefix(info, x.Args[1], sc.flagPrefix) {
								fail("flag call bad target or prefix (want " + sc.flagPrefix + "): " + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "os" && (callee.Name() == "LookupEnv" || callee.Name() == "Getenv"):
							if !inInitExec || x.Ellipsis.IsValid() || len(x.Args) != 1 || !constStringPrefix(info, x.Args[0], sc.envPrefix) {
								fail("os env call bad context or prefix (want " + sc.envPrefix + "): " + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "os" && callee.Signature().Recv() == nil:
							if !verifyHarnessOSFuncCall(info, enclosingFD, enclosingFn, inInitRoot, inLit, inFlagBoolGuard, callee.Name(), x, isFailfile, tempFileVars) {
								fail("os func call failed: os." + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "path/filepath" && callee.Name() == "Glob":
							if inInitRoot || enclosingFn == nil || enclosingFn.Exported() || x.Ellipsis.IsValid() || len(x.Args) != 1 || !isFailfile(x.Args[0]) {
								fail("filepath.Glob failed")
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "log" && callee.Name() == "New":
							if !x.Ellipsis.IsValid() && len(x.Args) == 3 {
								if stdoutIdent := osStdoutIdent(info, x.Args[0]); stdoutIdent != nil {
									approvedIdents[stdoutIdent] = true
								}
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case impPath == "html/template":
							if !verifyHarnessTemplateCall(audited, info, pkgTypes, callee, x) {
								fail("html/template call failed: " + callee.Name())
								return
							}
							markCalleeIdentApproved(x.Fun, approvedIdents)
						case harnessProtocolStdImports[impPath]:
							markCalleeIdentApproved(x.Fun, approvedIdents)
						}
					} else if declFuncs[callee.Origin()] != nil && initOnly[callee.Origin()] && inInitExec && !x.Ellipsis.IsValid() {
						for argIdx, arg := range x.Args {
							if envIdent := osEnvLookupIdent(info, arg); envIdent != nil {
								if !validInitLookupParam(callee.Origin(), argIdx, map[harnessParamKey]bool{}) {
									fail("invalid init lookup param: " + callee.Name())
									return
								}
								approvedIdents[envIdent] = true
							}
						}
					}
				}
			case *ast.Ident:
				if !approvedIdents[x] {
					if obj := info.Uses[x]; obj != nil && obj.Pkg() != nil {
						switch obj.Pkg().Path() {
						case "flag", "html/template", "reflect":
							if _, isFn := obj.(*types.Func); isFn {
								fail("unapproved " + obj.Pkg().Path() + " ref: " + obj.Name())
								return
							}
						case "os":
							if _, isFn := obj.(*types.Func); isFn || obj.Name() == "Stdout" {
								fail("unapproved os ref: " + obj.Name())
								return
							}
						case "path/filepath":
							if fn, isFn := obj.(*types.Func); isFn && fn.Name() == "Glob" {
								fail("unapproved filepath.Glob ref")
								return
							}
						}
					}
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if !okAll || child == nil {
					return false
				}
				if child == n {
					return true
				}
				walk(child, inInitExec, inLit, inFlagBoolGuard)
				return false
			})
		}
		walk(root, inInitRoot, false, false)
	}

	for _, af := range pkg.Syntax {
		for _, decl := range af.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				inInit := false
				var fn *types.Func
				if d.Recv == nil && d.Name.Name == "init" {
					inInit = true
				} else if fnObj, ok := info.Defs[d.Name].(*types.Func); ok && fnObj != nil {
					fn = fnObj.Origin()
					if d.Recv == nil && initOnly[fn] {
						inInit = true
					}
				}
				checkTree(d.Body, inInit, d, fn)
			case *ast.GenDecl:
				checkTree(d, true, nil, nil)
			}
			if !okAll {
				return nil, failReason
			}
		}
	}

	if !sawTBLogf {
		return nil, "missing TB.Logf"
	}
	return envFlagVars, ""
}

func markCalleeIdentApproved(fun ast.Expr, approved map[*ast.Ident]bool) {
	switch x := syntaxutil.UnwrapCallee(fun).(type) {
	case *ast.Ident:
		approved[x] = true
	case *ast.SelectorExpr:
		if x.Sel != nil {
			approved[x.Sel] = true
		}
	}
}

func verifyJoinedSynctestGoStmt(info *types.Info, pkgTypes *types.Package, body *ast.BlockStmt, goStmt *ast.GoStmt) bool {
	if body == nil || goStmt == nil || goStmt.Call == nil || goStmt.Call.Ellipsis.IsValid() || len(goStmt.Call.Args) != 0 {
		return false
	}
	lit, ok := ast.Unparen(goStmt.Call.Fun).(*ast.FuncLit)
	if !ok || lit.Body == nil || len(lit.Body.List) == 0 {
		return false
	}

	goIdx := -1
	for i, st := range body.List {
		if st == goStmt {
			goIdx = i
			break
		}
	}
	if goIdx <= 0 || goIdx+1 >= len(body.List) {
		return false
	}

	syncIdx := -1
	var synctestCallback ast.Node
	for i, st := range lit.Body.List {
		es, isES := st.(*ast.ExprStmt)
		if !isES {
			continue
		}
		call, isC := ast.Unparen(es.X).(*ast.CallExpr)
		if !isC || len(call.Args) != 2 {
			continue
		}
		if callee := resolveHarnessFuncExpr(info, call.Fun); callee != nil && callee.Pkg() != nil &&
			callee.Pkg().Path() == "testing/synctest" && callee.Name() == "Test" {
			if syncIdx != -1 {
				return false
			}
			syncIdx = i
			synctestCallback = call.Args[1]
		}
	}
	if syncIdx == -1 {
		return false
	}

	hasExtraGo := false
	var scanOutsideBubble func(n ast.Node)
	scanOutsideBubble = func(n ast.Node) {
		if n == nil || hasExtraGo || n == synctestCallback {
			return
		}
		if _, isGo := n.(*ast.GoStmt); isGo {
			hasExtraGo = true
			return
		}
		ast.Inspect(n, func(child ast.Node) bool {
			if child == nil || hasExtraGo {
				return false
			}
			if child == n {
				return true
			}
			scanOutsideBubble(child)
			return false
		})
	}
	scanOutsideBubble(lit.Body)
	if hasExtraGo {
		return false
	}

	var chVar *types.Var
	if lastSt, isSend := lit.Body.List[len(lit.Body.List)-1].(*ast.SendStmt); isSend && syncIdx < len(lit.Body.List)-1 {
		if chID, isID := ast.Unparen(lastSt.Chan).(*ast.Ident); isID {
			if v, isV := info.Uses[chID].(*types.Var); isV && v != nil && v.Parent() != pkgTypes.Scope() {
				badBefore := false
				for i := 0; i < len(lit.Body.List)-1; i++ {
					ast.Inspect(lit.Body.List[i], func(n ast.Node) bool {
						if n == synctestCallback || badBefore || n == nil {
							return false
						}
						switch n.(type) {
						case *ast.DeferStmt, *ast.ReturnStmt:
							badBefore = true
							return false
						case *ast.FuncLit:
							return false
						}
						return true
					})
				}
				if !badBefore {
					chVar = v
				}
			}
		}
	} else {
		deferIdx := -1
		var deferLit *ast.FuncLit
		for i := 0; i < syncIdx; i++ {
			ds, isDS := lit.Body.List[i].(*ast.DeferStmt)
			if !isDS {
				continue
			}
			if deferIdx != -1 || ds.Call == nil || ds.Call.Ellipsis.IsValid() || len(ds.Call.Args) != 0 {
				return false
			}
			dl, isFL := ast.Unparen(ds.Call.Fun).(*ast.FuncLit)
			if !isFL || dl.Body == nil || len(dl.Body.List) == 0 {
				return false
			}
			deferIdx = i
			deferLit = dl
		}
		if deferIdx != -1 && deferLit != nil {
			if sendSt, isSend := deferLit.Body.List[len(deferLit.Body.List)-1].(*ast.SendStmt); isSend {
				if chID, isID := ast.Unparen(sendSt.Chan).(*ast.Ident); isID {
					if v, isV := info.Uses[chID].(*types.Var); isV && v != nil && v.Parent() != pkgTypes.Scope() {
						badDefer := false
						for i := 0; i <= deferIdx; i++ {
							if i == deferIdx {
								continue
							}
							ast.Inspect(lit.Body.List[i], func(n ast.Node) bool {
								if badDefer || n == nil {
									return false
								}
								switch n.(type) {
								case *ast.ReturnStmt, *ast.DeferStmt, *ast.BranchStmt:
									badDefer = true
									return false
								case *ast.FuncLit:
									return false
								}
								return true
							})
						}
						for i := 0; i < len(deferLit.Body.List)-1; i++ {
							ast.Inspect(deferLit.Body.List[i], func(n ast.Node) bool {
								if badDefer || n == nil {
									return false
								}
								switch n.(type) {
								case *ast.ReturnStmt, *ast.BranchStmt, *ast.GoStmt:
									badDefer = true
									return false
								case *ast.FuncLit:
									return false
								}
								return true
							})
						}
						if !badDefer {
							chVar = v
						}
					}
				}
			}
		}
	}
	if chVar == nil {
		return false
	}

	defIdx := -1
	for i := 0; i < goIdx; i++ {
		as, isAS := body.List[i].(*ast.AssignStmt)
		if !isAS || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			continue
		}
		id, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !isID || info.Defs[id] != chVar {
			continue
		}
		if !isMakeChanCall(info, as.Rhs[0]) {
			return false
		}
		defIdx = i
		break
	}
	if defIdx == -1 {
		return false
	}

	isRecvOnCh := func(e ast.Expr) bool {
		un, isUn := ast.Unparen(e).(*ast.UnaryExpr)
		if !isUn || un.Op != token.ARROW {
			return false
		}
		id, isID := ast.Unparen(un.X).(*ast.Ident)
		return isID && info.Uses[id] == chVar
	}
	isTopLevelUnconditionalRecv := func(st ast.Stmt) bool {
		switch s := st.(type) {
		case *ast.ExprStmt:
			return isRecvOnCh(s.X)
		case *ast.AssignStmt:
			return len(s.Rhs) == 1 && (len(s.Lhs) == 1 || len(s.Lhs) == 2) && isRecvOnCh(s.Rhs[0])
		case *ast.IfStmt:
			if s.Init != nil {
				as, isAS := s.Init.(*ast.AssignStmt)
				return isAS && len(as.Rhs) == 1 && (len(as.Lhs) == 1 || len(as.Lhs) == 2) && isRecvOnCh(as.Rhs[0])
			}
			if isRecvOnCh(s.Cond) {
				return true
			}
			if bin, isBin := ast.Unparen(s.Cond).(*ast.BinaryExpr); isBin && (bin.Op == token.EQL || bin.Op == token.NEQ) {
				return isRecvOnCh(bin.X) || isRecvOnCh(bin.Y)
			}
		}
		return false
	}

	recvIdx := -1
	for i := goIdx + 1; i < len(body.List); i++ {
		if isTopLevelUnconditionalRecv(body.List[i]) {
			recvIdx = i
			break
		}
	}
	if recvIdx == -1 {
		return false
	}

	badBetween := false
	for i := goIdx + 1; i < recvIdx; i++ {
		ast.Inspect(body.List[i], func(n ast.Node) bool {
			if badBetween || n == nil {
				return false
			}
			switch n.(type) {
			case *ast.ReturnStmt, *ast.BranchStmt, *ast.GoStmt:
				badBetween = true
				return false
			case *ast.FuncLit:
				return false
			}
			return true
		})
	}
	if badBetween {
		return false
	}

	refCount := 0
	ast.Inspect(body, func(n ast.Node) bool {
		if id, isID := n.(*ast.Ident); isID && (info.Defs[id] == chVar || info.Uses[id] == chVar) {
			refCount++
		}
		return true
	})
	return refCount == 3
}
