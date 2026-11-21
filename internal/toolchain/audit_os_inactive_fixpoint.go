package toolchain

import (
	"go/ast"
	"go/token"
	"maps"
	"slices"
)

func discoverOSInactiveState(idx *packageASTIndex, files []*ast.File, osRuntimePullMap map[string]string, osAnyLinknameLocals map[string]bool) *osInactiveState {
	k := newPackageInactiveKernel(idx, files, osRuntimePullMap, osAnyLinknameLocals)
	idx = k.idx
	st := &osInactiveState{
		k:                   k,
		pkgDeclCounts:       idx.pkgDeclCounts,
		funcFile:            idx.funcFile,
		fileImportNames:     k.fileImportNames,
		falseConsts:         k.FalseConsts,
		trueConsts:          k.TrueConsts,
		osGateFuncs:         k.FalseGates,
		nilAccessors:        map[string][]string{},
		falsePreds:          map[string][]string{},
		falseHandledHelpers: map[osFalseHelperKey][]string{},
	}
	if k.hasDotImport || k.builtinsShadowed {
		return st
	}

	tableStructs, activeTables, mutSitesByTable := discoverOSStateTables(k, idx, files, osAnyLinknameLocals)
	pureIndexHelpers := discoverOSPureIndexHelpers(k, idx, files, osAnyLinknameLocals)

	type depPair struct {
		gates map[string]bool
		tabs  map[string]bool
	}
	cloneDep := func(d depPair) depPair {
		out := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
		for g := range d.gates {
			if g != "" {
				out.gates[g] = true
			}
		}
		maps.Copy(out.tabs, d.tabs)
		return out
	}
	mergeDep := func(dst *depPair, src depPair) {
		for g := range src.gates {
			if g != "" {
				dst.gates[g] = true
			}
		}
		maps.Copy(dst.tabs, src.tabs)
	}

	funcParamSet := func(fn *ast.FuncDecl) map[string]bool {
		out := map[string]bool{}
		if fn == nil {
			return out
		}
		if r := recvVarName(fn); r != "" {
			out[r] = true
		}
		for _, p := range paramNamesFlat(fn.Type.Params) {
			if p != "" && p != "_" {
				out[p] = true
			}
		}
		return out
	}

	type rule3CallSite struct {
		caller *ast.FuncDecl
		call   *ast.CallExpr
	}
	rule3CandFuncs := map[string]*ast.FuncDecl{}
	for fnName, fn := range idx.topFuncs {
		if ast.IsExported(fnName) || idx.pkgDeclCounts[fnName] != 1 || osAnyLinknameLocals[fnName] || fn.Body == nil {
			continue
		}
		shadowedByImport := false
		for _, f := range files {
			if k.fileImportNames[f][fnName] {
				shadowedByImport = true
				break
			}
		}
		if !shadowedByImport {
			rule3CandFuncs[fnName] = fn
		}
	}
	rule3CallSites := map[string][]rule3CallSite{}
	rule3AllowedIdents := map[string]map[*ast.Ident]bool{}
	for fnName, fn := range rule3CandFuncs {
		rule3AllowedIdents[fnName] = map[*ast.Ident]bool{fn.Name: true}
	}
	if len(rule3CandFuncs) > 0 {
		for _, f := range files {
			for _, decl := range f.Decls {
				caller, okF := decl.(*ast.FuncDecl)
				if !okF || caller.Body == nil {
					continue
				}
				ast.Inspect(caller.Body, func(n ast.Node) bool {
					call, okC := n.(*ast.CallExpr)
					if !okC {
						return true
					}
					cID, okID := unwrapParens(call.Fun).(*ast.Ident)
					if !okID || rule3CandFuncs[cID.Name] == nil {
						return true
					}
					rule3CallSites[cID.Name] = append(rule3CallSites[cID.Name], rule3CallSite{caller: caller, call: call})
					rule3AllowedIdents[cID.Name][cID] = true
					return true
				})
			}
		}
		for fnName := range filterNonSelPropIdentsInSet(files, rule3AllowedIdents) {
			delete(rule3CandFuncs, fnName)
			delete(rule3CallSites, fnName)
		}
	}

	var finalNilAcc, finalFalsePreds map[string]depPair
	var finalTableGates map[string]map[string]bool
	for {
		nilAcc := map[string]depPair{}
		falsePreds := map[string]depPair{}

		evalEnv := osFalseEvalEnv[depPair]{
			st:      st,
			zeroDep: func() depPair { return depPair{gates: map[string]bool{}, tabs: map[string]bool{}} },
			gateDep: func(rtGate string) depPair {
				d := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				if rtGate != "" {
					d.gates[rtGate] = true
				}
				return d
			},
			falsePred: func(name string) (depPair, bool) {
				fp, okFP := falsePreds[name]
				if !okFP {
					return depPair{}, false
				}
				return cloneDep(fp), true
			},
			nilAccessor: func(name string) (depPair, bool) {
				na, okNA := nilAcc[name]
				if !okNA {
					return depPair{}, false
				}
				return cloneDep(na), true
			},
			merge: func(a, b depPair) depPair {
				out := cloneDep(a)
				mergeDep(&out, b)
				return out
			},
		}
		evalFalse := func(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) (depPair, bool) {
			return evalOSFalseExpr(evalEnv, expr, fn, params)
		}

		for {
			innerChanged := false
			for fnName, fn := range idx.topFuncs {
				if ast.IsExported(fnName) || idx.pkgDeclCounts[fnName] != 1 || osAnyLinknameLocals[fnName] || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
					continue
				}
				pNames := paramNamesFlat(fn.Type.Params)
				if len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || !funcHasUnnamedResults(fn.Type, 1) || len(fn.Type.Results.List) != 1 {
					continue
				}
				pSet := map[string]bool{pNames[0]: true}
				if _, isBoolRes := isIdentNamed(fn.Type.Results.List[0].Type, "bool"); isBoolRes {
					if st.identShadowedInFunc(fn, "bool") || st.identShadowedInFunc(fn, "nil") || st.identShadowedInFunc(fn, "false") || st.identShadowedInFunc(fn, "true") {
						continue
					}
					if _, already := falsePreds[fnName]; already {
						continue
					}
					stmts := fn.Body.List
					if len(stmts) == 1 {
						if ifs, okI := stmts[0].(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && st.isTrueConstIdent(ifs.Cond, fn) {
							stmts = ifs.Body.List
						}
					}
					if len(stmts) == 1 {
						if ret, okR := stmts[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
							if d, okF := evalFalse(ret.Results[0], fn, pSet); okF {
								falsePreds[fnName] = d
								innerChanged = true
							}
						}
					}
					continue
				}
				if _, already := nilAcc[fnName]; already || st.identShadowedInFunc(fn, "nil") || st.identShadowedInFunc(fn, "false") || st.identShadowedInFunc(fn, "true") {
					continue
				}
				fnFile := idx.funcFile[fn]
				var proveBlockReturnsNil func(stmts []ast.Stmt, knownNil map[string]bool, declaredLocals map[string]bool, acc *depPair) bool
				proveBlockReturnsNil = func(stmts []ast.Stmt, knownNil map[string]bool, declaredLocals map[string]bool, acc *depPair) bool {
					for i := 0; i < len(stmts); i++ {
						switch s := stmts[i].(type) {
						case *ast.ReturnStmt:
							if len(s.Results) != 1 {
								return false
							}
							rID, okID := unwrapParens(s.Results[0]).(*ast.Ident)
							return okID && (rID.Name == "nil" || knownNil[rID.Name])
						case *ast.ExprStmt:
							kc, okKC := unwrapParens(s.X).(*ast.CallExpr)
							if !okKC || kc.Ellipsis.IsValid() || len(kc.Args) != 1 || !st.isPureChain(kc.Args[0], fn, pSet) {
								return false
							}
							rSel, okRS := unwrapParens(kc.Fun).(*ast.SelectorExpr)
							if !okRS || rSel.Sel.Name != "KeepAlive" {
								return false
							}
							rPkg, okRP := unwrapParens(rSel.X).(*ast.Ident)
							if !okRP || k.fileImportPath(fnFile, rPkg.Name) != "runtime" || funcShadowsAnyIdent(fn, map[string]bool{rPkg.Name: true}) || declaredLocals[rPkg.Name] {
								return false
							}
						case *ast.AssignStmt:
							if s.Tok == token.DEFINE && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
								vID, okV := unwrapParens(s.Lhs[0]).(*ast.Ident)
								c, okC := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
								if !okV || !okC || vID.Name == "" || vID.Name == "_" || declaredLocals[vID.Name] || c.Ellipsis.IsValid() || len(c.Args) != 1 {
									return false
								}
								if cID, okCID := unwrapParens(c.Fun).(*ast.Ident); okCID && !st.identShadowedInFunc(fn, cID.Name) && !declaredLocals[cID.Name] && st.isPureChain(c.Args[0], fn, pSet) {
									na, okNA := nilAcc[cID.Name]
									if !okNA {
										return false
									}
									mergeDep(acc, na)
									declaredLocals[vID.Name] = true
									knownNil[vID.Name] = true
									continue
								}
							}
							if s.Tok == token.DEFINE && len(s.Lhs) == 2 && len(s.Rhs) == 1 && i+2 < len(stmts) {
								idxID, okI0 := unwrapParens(s.Lhs[0]).(*ast.Ident)
								okVarID, okI1 := unwrapParens(s.Lhs[1]).(*ast.Ident)
								ic, okIC := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
								if !okI0 || !okI1 || !okIC || idxID.Name == "" || idxID.Name == "_" || okVarID.Name == "" || okVarID.Name == "_" || idxID.Name == okVarID.Name || declaredLocals[idxID.Name] || declaredLocals[okVarID.Name] || ic.Ellipsis.IsValid() || len(ic.Args) != 1 || !st.isPureChain(ic.Args[0], fn, pSet) {
									return false
								}
								ihID, okIH := unwrapParens(ic.Fun).(*ast.Ident)
								if !okIH || !pureIndexHelpers[ihID.Name] || st.identShadowedInFunc(fn, ihID.Name) || declaredLocals[ihID.Name] {
									return false
								}
								guardIf, okGI := stmts[i+1].(*ast.IfStmt)
								getAs, okGA := stmts[i+2].(*ast.AssignStmt)
								if !okGI || guardIf.Init != nil || guardIf.Else != nil || len(guardIf.Body.List) != 1 || !okGA || getAs.Tok != token.DEFINE || len(getAs.Lhs) != 1 || len(getAs.Rhs) != 1 {
									return false
								}
								uNot, okUN := unwrapParens(guardIf.Cond).(*ast.UnaryExpr)
								gRet, okGR := guardIf.Body.List[0].(*ast.ReturnStmt)
								if !okUN || uNot.Op != token.NOT || !okGR || len(gRet.Results) != 1 {
									return false
								}
								_, okVarMatch := isIdentNamed(uNot.X, okVarID.Name)
								_, okRetNil := isIdentNamed(gRet.Results[0], "nil")
								if !okVarMatch || !okRetNil {
									return false
								}
								declaredLocals[idxID.Name] = true
								declaredLocals[okVarID.Name] = true
								sVarID, okSV := unwrapParens(getAs.Lhs[0]).(*ast.Ident)
								getCall, okGC := unwrapParens(getAs.Rhs[0]).(*ast.CallExpr)
								if !okSV || sVarID.Name == "" || sVarID.Name == "_" || declaredLocals[sVarID.Name] || !okGC || getCall.Ellipsis.IsValid() || len(getCall.Args) != 1 {
									return false
								}
								_, okIdxArg := isIdentNamed(getCall.Args[0], idxID.Name)
								getSel, okGS := unwrapParens(getCall.Fun).(*ast.SelectorExpr)
								if !okIdxArg || !okGS {
									return false
								}
								tabID, okTID := unwrapParens(getSel.X).(*ast.Ident)
								if !okTID || st.identShadowedInFunc(fn, tabID.Name) || declaredLocals[tabID.Name] {
									return false
								}
								vc, okTab := activeTables[tabID.Name]
								if !okTab || !tableStructs[vc.structName].readNilMethods[getSel.Sel.Name] {
									return false
								}
								acc.tabs[tabID.Name] = true
								declaredLocals[sVarID.Name] = true
								knownNil[sVarID.Name] = true
								i += 2
								continue
							}
							return false
						case *ast.IfStmt:
							if s.Else != nil {
								return false
							}
							if s.Init == nil {
								if st.isTrueConstIdent(s.Cond, fn) {
									rest := append(slices.Clone(s.Body.List), stmts[i+1:]...)
									return proveBlockReturnsNil(rest, maps.Clone(knownNil), maps.Clone(declaredLocals), acc)
								}
								if d, okF := evalFalse(s.Cond, fn, pSet); okF {
									mergeDep(acc, d)
									continue
								}
								if nzVar := condChecksNonZeroErr(s.Cond); nzVar != "" && knownNil[nzVar] {
									continue
								}
								if condChecksEqErr(s.Cond, pNames[0]) && len(s.Body.List) == 1 {
									if r0, okR0 := s.Body.List[0].(*ast.ReturnStmt); okR0 && len(r0.Results) == 1 {
										if _, okN := isIdentNamed(r0.Results[0], "nil"); okN {
											continue
										}
									}
								}
								for kn := range knownNil {
									if condChecksEqErr(s.Cond, kn) && proveBlockReturnsNil(s.Body.List, maps.Clone(knownNil), maps.Clone(declaredLocals), acc) {
										return true
									}
								}
								return false
							}
							if initAs, okA := s.Init.(*ast.AssignStmt); okA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 {
								vID, okV := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
								c, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
								if okV && okC && vID.Name != "" && vID.Name != "_" && vID.Name != "nil" && condChecksNonZeroErr(s.Cond) == vID.Name && !c.Ellipsis.IsValid() && len(c.Args) == 1 && st.isPureChain(c.Args[0], fn, pSet) {
									if cID, okCID := unwrapParens(c.Fun).(*ast.Ident); okCID && !st.identShadowedInFunc(fn, cID.Name) && !declaredLocals[cID.Name] {
										if na, okNA := nilAcc[cID.Name]; okNA {
											mergeDep(acc, na)
											continue
										}
									}
								}
							}
							return false
						default:
							return false
						}
					}
					return false
				}
				acc := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				if proveBlockReturnsNil(fn.Body.List, map[string]bool{}, map[string]bool{pNames[0]: true}, &acc) {
					nilAcc[fnName] = acc
					innerChanged = true
				}
			}
			if !innerChanged {
				break
			}
		}

		deadIfDeps := map[*ast.IfStmt]depPair{}
		for _, f := range files {
			for _, decl := range f.Decls {
				fn, okF := decl.(*ast.FuncDecl)
				if !okF || fn.Body == nil {
					continue
				}
				pSet := funcParamSet(fn)
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					ifs, okI := n.(*ast.IfStmt)
					if !okI {
						return true
					}
					if ifs.Init == nil && ifs.Else == nil && !bodyHasControlFlowOrRecoverBypass(ifs.Body) {
						if d, okF := evalFalse(ifs.Cond, fn, pSet); okF {
							deadIfDeps[ifs] = d
							return false
						}
					}
					return true
				})
			}
		}

		nodeDeadDep := func(fn *ast.FuncDecl, target ast.Node) (depPair, bool) {
			var found bool
			var out depPair
			var walk func(n ast.Node, cur *depPair)
			walk = func(n ast.Node, cur *depPair) {
				if found || n == nil {
					return
				}
				if n == target {
					if cur != nil {
						out = cloneDep(*cur)
						found = true
					}
					return
				}
				if ifs, okI := n.(*ast.IfStmt); okI {
					if d, okD := deadIfDeps[ifs]; okD {
						next := cloneDep(d)
						if cur != nil {
							mergeDep(&next, *cur)
						}
						for _, bs := range ifs.Body.List {
							walk(bs, &next)
						}
						return
					}
				}
				ast.Inspect(n, func(ch ast.Node) bool {
					if ch == n {
						return true
					}
					walk(ch, cur)
					return false
				})
			}
			walk(fn.Body, nil)
			return out, found
		}

		nodeContainsCall := func(root *ast.IfStmt, target *ast.CallExpr) bool {
			if root == nil || target == nil {
				return false
			}
			hit := false
			ast.Inspect(root, func(n ast.Node) bool {
				if n == target {
					hit = true
					return false
				}
				return !hit
			})
			return hit
		}

		unreachableFuncs := map[string]depPair{}
		seedRule1Head := map[string]*ast.IfStmt{}
		for fnName, fn := range idx.topFuncs {
			if idx.pkgDeclCounts[fnName] != 1 || fn.Body == nil || len(fn.Body.List) == 0 {
				continue
			}
			ifs, okI := fn.Body.List[0].(*ast.IfStmt)
			if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 || bodyHasControlFlowOrRecoverBypass(ifs.Body) {
				continue
			}
			if _, okRet := ifs.Body.List[0].(*ast.ReturnStmt); !okRet {
				continue
			}
			negTarget := ifs.Cond
			for {
				orBin, okOr := unwrapParens(negTarget).(*ast.BinaryExpr)
				if !okOr || orBin.Op != token.LOR {
					break
				}
				negTarget = orBin.X
			}
			if uNot, okU := unwrapParens(negTarget).(*ast.UnaryExpr); okU && uNot.Op == token.NOT {
				if d, okF := evalFalse(uNot.X, fn, nil); okF {
					unreachableFuncs[fnName] = d
					seedRule1Head[fnName] = ifs
				}
			}
		}

		for {
			uChanged := false
			for fnName := range rule3CandFuncs {
				if _, already := unreachableFuncs[fnName]; already {
					continue
				}
				agg := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				allCovered := true
				for _, site := range rule3CallSites[fnName] {
					caller := site.caller
					if caller.Recv == nil {
						if callerUnreach, isCallerUnreach := unreachableFuncs[caller.Name.Name]; isCallerUnreach && !nodeContainsCall(seedRule1Head[caller.Name.Name], site.call) {
							mergeDep(&agg, callerUnreach)
							continue
						}
					}
					if dDead, okD := nodeDeadDep(caller, site.call); okD {
						mergeDep(&agg, dDead)
						continue
					}
					allCovered = false
					break
				}
				if allCovered {
					unreachableFuncs[fnName] = agg
					uChanged = true
				}
			}
			if !uChanged {
				break
			}
		}

		evicted := false
		curTableDeps := map[string]depPair{}
		for vName := range activeTables {
			agg := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
			covered := true
			for _, site := range mutSitesByTable[vName] {
				if site.fn.Recv == nil {
					if uDep, okU := unreachableFuncs[site.fn.Name.Name]; okU && !nodeContainsCall(seedRule1Head[site.fn.Name.Name], site.call) {
						mergeDep(&agg, uDep)
						continue
					}
				}
				if dDead, okD := nodeDeadDep(site.fn, site.call); okD {
					mergeDep(&agg, dDead)
					continue
				}
				covered = false
				break
			}
			if !covered {
				delete(activeTables, vName)
				evicted = true
				continue
			}
			curTableDeps[vName] = agg
		}
		if evicted {
			continue
		}

		for {
			tChanged := false
			for vName, dp := range curTableDeps {
				for depTab := range dp.tabs {
					if other, okO := curTableDeps[depTab]; okO {
						for g := range other.gates {
							if !dp.gates[g] {
								dp.gates[g] = true
								tChanged = true
							}
						}
					}
				}
				curTableDeps[vName] = dp
			}
			if !tChanged {
				break
			}
		}
		finalTableGates = map[string]map[string]bool{}
		for vName, dp := range curTableDeps {
			finalTableGates[vName] = dp.gates
		}
		finalNilAcc = nilAcc
		finalFalsePreds = falsePreds
		break
	}

	resolveDepGates := func(dp depPair) []string {
		merged := map[string]bool{}
		for g := range dp.gates {
			if g != "" {
				merged[g] = true
			}
		}
		for t := range dp.tabs {
			for g := range finalTableGates[t] {
				if g != "" {
					merged[g] = true
				}
			}
		}
		out := sortedKeys(merged)
		if out == nil {
			out = make([]string, 0)
		}
		return out
	}

	for name, dp := range finalNilAcc {
		st.nilAccessors[name] = resolveDepGates(dp)
	}
	for name, dp := range finalFalsePreds {
		st.falsePreds[name] = resolveDepGates(dp)
	}

	// Discover unexported false-handled tuple helpers (allowing pure early-zero-return guards
	// and pure-read local bindings before a `return ..., false, ...` or `if <trueDisj> { return ..., false, ... }`).
	identShadowedAtHead := func(fn *ast.FuncDecl, name string) bool {
		return funcDeclaresParamOrResult(fn, name) || k.fileImportNames[idx.funcFile[fn]][name]
	}
	isPureZeroResult := func(fn *ast.FuncDecl, expr ast.Expr) bool {
		expr = unwrapParens(expr)
		if id, okID := expr.(*ast.Ident); okID {
			if (id.Name == "nil" || id.Name == "false") && idx.pkgDeclCounts[id.Name] == 0 && !identShadowedAtHead(fn, id.Name) {
				return true
			}
			return st.falseConsts[id.Name] && !identShadowedAtHead(fn, id.Name)
		}
		if isZeroIntLit(expr) {
			return true
		}
		lit, okL := expr.(*ast.BasicLit)
		return okL && lit.Kind == token.STRING && lit.Value == `""`
	}

	for hName, fn := range idx.topFuncs {
		if ast.IsExported(hName) || idx.pkgDeclCounts[hName] != 1 || osAnyLinknameLocals[hName] || fn.Body == nil || len(fn.Body.List) == 0 || fn.Type == nil || fn.Type.TypeParams != nil || fn.Type.Results == nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			continue
		}
		numRes := fn.Type.Results.NumFields()
		if numRes < 2 || identShadowedAtHead(fn, "false") || identShadowedAtHead(fn, "nil") || identShadowedAtHead(fn, "bool") {
			continue
		}
		zeroFalseIdxs := func(ret *ast.ReturnStmt) map[int]bool {
			if len(ret.Results) != numRes {
				return nil
			}
			out := map[int]bool{}
			for i, r := range ret.Results {
				rID, okID := unwrapParens(r).(*ast.Ident)
				if !okID || (rID.Name != "false" && (!st.falseConsts[rID.Name] || identShadowedAtHead(fn, rID.Name))) {
					continue
				}
				if _, okBool := isIdentNamed(funcResultFieldTypeAt(fn.Type.Results, i), "bool"); !okBool {
					continue
				}
				othersZero := true
				for j, other := range ret.Results {
					if j != i && !isPureZeroResult(fn, other) {
						othersZero = false
						break
					}
				}
				if othersZero {
					out[i] = true
				}
			}
			return out
		}

		pureScope := funcParamSet(fn)
		var candIdxs map[int]bool
		intersectIdxs := func(s map[int]bool) bool {
			if len(s) == 0 {
				return false
			}
			if candIdxs == nil {
				candIdxs = s
				return true
			}
			for k := range candIdxs {
				if !s[k] {
					delete(candIdxs, k)
				}
			}
			return len(candIdxs) > 0
		}

		for _, stmt := range fn.Body.List {
			switch s0 := stmt.(type) {
			case *ast.ReturnStmt:
				if intersectIdxs(zeroFalseIdxs(s0)) {
					for bIdx := range candIdxs {
						st.falseHandledHelpers[osFalseHelperKey{name: hName, arity: numRes, boolIdx: bIdx}] = make([]string, 0)
					}
				}
			case *ast.AssignStmt:
				if s0.Tok == token.DEFINE && len(s0.Lhs) == 1 && len(s0.Rhs) == 1 {
					vID, okV := unwrapParens(s0.Lhs[0]).(*ast.Ident)
					if okV && vID.Name != "" && vID.Name != "_" && !pureScope[vID.Name] && !k.fileImportNames[idx.funcFile[fn]][vID.Name] && st.isPureChain(s0.Rhs[0], fn, pureScope) {
						mutated := false
						seenDef := false
						ast.Inspect(fn.Body, func(n ast.Node) bool {
							if mutated || n == nil {
								return false
							}
							if n == s0 {
								seenDef = true
								return false
							}
							if !seenDef {
								return true
							}
							if as, okA := n.(*ast.AssignStmt); okA {
								for _, lhs := range as.Lhs {
									if _, okID := isIdentNamed(lhs, vID.Name); okID {
										mutated = true
										return false
									}
								}
							}
							if inc, okI := n.(*ast.IncDecStmt); okI {
								if _, okID := isIdentNamed(inc.X, vID.Name); okID {
									mutated = true
									return false
								}
							}
							if u, okU := n.(*ast.UnaryExpr); okU && u.Op == token.AND {
								if _, okID := isIdentNamed(u.X, vID.Name); okID {
									mutated = true
									return false
								}
							}
							return true
						})
						if !mutated {
							pureScope[vID.Name] = true
							continue
						}
					}
				}
			case *ast.IfStmt:
				if s0.Init == nil && s0.Else == nil && len(s0.Body.List) == 1 {
					if ret, okR := s0.Body.List[0].(*ast.ReturnStmt); okR {
						if gates, okG := st.evalTrueDisjunction(s0.Cond, fn, pureScope); okG {
							if intersectIdxs(zeroFalseIdxs(ret)) {
								for bIdx := range candIdxs {
									st.falseHandledHelpers[osFalseHelperKey{name: hName, arity: numRes, boolIdx: bIdx}] = gates
								}
							}
						} else if st.isPureGuardExpr(s0.Cond, fn, pureScope) && intersectIdxs(zeroFalseIdxs(ret)) {
							continue
						}
					}
				}
			}
			break
		}
	}

	return st
}
