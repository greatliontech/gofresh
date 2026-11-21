package propharness

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func isMakeChanCall(info *types.Info, e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || (len(call.Args) != 1 && len(call.Args) != 2) {
		return false
	}
	b := syntaxutil.LookupBuiltin(info, syntaxutil.UnwrapCallee(call.Fun))
	if b == nil || b.Name() != "make" {
		return false
	}
	chType := info.TypeOf(call.Args[0])
	if chType == nil {
		return false
	}
	if _, isCh := types.Unalias(chType).Underlying().(*types.Chan); !isCh {
		return false
	}
	if len(call.Args) == 2 {
		tv, okTV := info.Types[call.Args[1]]
		if !okTV || tv.Value == nil || tv.Value.Kind() != constant.Int {
			return false
		}
		capVal, exact := constant.Int64Val(tv.Value)
		if !exact || (capVal != 0 && capVal != 1) {
			return false
		}
	}
	return true
}

func isFailfileStringOrSliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Basic:
		return u.Kind() == types.String
	case *types.Slice:
		b, ok := types.Unalias(u.Elem()).Underlying().(*types.Basic)
		return ok && b.Kind() == types.String
	}
	return false
}

func isEmptyFailfileReset(info *types.Info, e ast.Expr) bool {
	e = ast.Unparen(e)
	if constStringEq(info, e, "") {
		return true
	}
	if id, ok := e.(*ast.Ident); ok && info.Uses[id] == types.Universe.Lookup("nil") {
		return true
	}
	cl, ok := e.(*ast.CompositeLit)
	return ok && len(cl.Elts) == 0 && isFailfileStringOrSliceType(info.TypeOf(cl))
}

func isCategoryABoolFieldExpr(info *types.Info, e ast.Expr, categoryA map[*types.Var]bool) bool {
	sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	st := info.TypeOf(sel)
	if st == nil {
		return false
	}
	b, ok := types.Unalias(st).Underlying().(*types.Basic)
	if !ok || b.Kind() != types.Bool {
		return false
	}
	baseID, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := info.Uses[baseID].(*types.Var)
	return ok && categoryA[v]
}

func isHarnessFailfileExpr(
	g *harnessGraph,
	e ast.Expr,
	categoryA map[*types.Var]bool,
	failfileVars map[*types.Var]bool,
	failfileParams map[*types.Var]bool,
	failfileResults map[harnessParamKey]bool,
) bool {
	info := g.info
	if e == nil {
		return false
	}
	e = ast.Unparen(e)
	if !isFailfileStringOrSliceType(info.TypeOf(e)) {
		return false
	}
	switch x := e.(type) {
	case *ast.Ident:
		v, ok := info.Uses[x].(*types.Var)
		return ok && (failfileVars[v] || failfileParams[v])
	case *ast.SelectorExpr:
		if baseID, ok := ast.Unparen(x.X).(*ast.Ident); ok {
			if v, ok := info.Uses[baseID].(*types.Var); ok && categoryA[v] {
				return true
			}
		}
	case *ast.CompositeLit:
		if len(x.Elts) == 0 {
			return false
		}
		saw := false
		for _, elt := range x.Elts {
			if isEmptyFailfileReset(info, elt) {
				continue
			}
			if isHarnessFailfileExpr(g, elt, categoryA, failfileVars, failfileParams, failfileResults) {
				saw = true
				continue
			}
			return false
		}
		return saw
	case *ast.CallExpr:
		if b := syntaxutil.LookupBuiltin(info, syntaxutil.UnwrapCallee(x.Fun)); b != nil && b.Name() == "append" && len(x.Args) >= 2 {
			saw := false
			for _, arg := range x.Args {
				if isEmptyFailfileReset(info, arg) {
					continue
				}
				if isHarnessFailfileExpr(g, arg, categoryA, failfileVars, failfileParams, failfileResults) {
					saw = true
					continue
				}
				return false
			}
			return saw
		}
		callee := resolveHarnessFuncExpr(info, x.Fun)
		if callee == nil || x.Ellipsis.IsValid() {
			return false
		}
		if callee.Pkg() != nil && callee.Pkg().Path() == "path/filepath" {
			switch callee.Name() {
			case "Join":
				if len(x.Args) < 2 {
					return false
				}
				for _, arg := range x.Args {
					if tv, ok := info.Types[arg]; ok && tv.Value != nil && tv.Value.Kind() == constant.String && strings.Contains(constant.StringVal(tv.Value), "..") {
						return false
					}
				}
				if constStringEq(info, x.Args[0], "testdata") && constStringEq(info, x.Args[1], g.screen.failfileSubdir) {
					return true
				}
				return isHarnessFailfileExpr(g, x.Args[0], categoryA, failfileVars, failfileParams, failfileResults)
			case "Dir", "Clean", "Glob":
				return len(x.Args) == 1 && isHarnessFailfileExpr(g, x.Args[0], categoryA, failfileVars, failfileParams, failfileResults)
			}
			return false
		}
		orig := callee.Origin()
		if g.declFuncs[orig] != nil && !orig.Exported() && orig.Signature().Results().Len() == 1 {
			return failfileResults[harnessParamKey{fn: orig, idx: 0}]
		}
	}
	return false
}

func computeHarnessFailfileProvenance(
	g *harnessGraph,
	categoryA map[*types.Var]bool,
) (map[*types.Var]bool, map[*types.Var]bool, map[harnessParamKey]bool) {
	info := g.info
	pkgScope := g.pkgTypes.Scope()
	declFuncs := g.declFuncs

	failfileVars := map[*types.Var]bool{}
	failfileParams := map[*types.Var]bool{}
	failfileResults := map[harnessParamKey]bool{}

	isFF := func(e ast.Expr) bool {
		return isHarnessFailfileExpr(g, e, categoryA, failfileVars, failfileParams, failfileResults)
	}

	for changed := true; changed; {
		changed = false
		for fn, fd := range declFuncs {
			if fn.Exported() || fd == nil || fd.Body == nil {
				continue
			}
			paramSet := map[*types.Var]bool{}
			for i := 0; i < fn.Signature().Params().Len(); i++ {
				paramSet[fn.Signature().Params().At(i)] = true
			}
			totalWrites := map[*types.Var]int{}
			validWrites := map[*types.Var]int{}
			positiveWrites := map[*types.Var]int{}
			addrTaken := map[*types.Var]bool{}
			isSelfAppend := func(target *types.Var, rhs ast.Expr) (valid, positive bool) {
				call, ok := ast.Unparen(rhs).(*ast.CallExpr)
				if !ok || len(call.Args) < 2 {
					return false, false
				}
				b := syntaxutil.LookupBuiltin(info, syntaxutil.UnwrapCallee(call.Fun))
				if b == nil || b.Name() != "append" || lookupLocalVar(info, pkgScope, call.Args[0]) != target {
					return false, false
				}
				sawPos := false
				for _, arg := range call.Args[1:] {
					if isEmptyFailfileReset(info, arg) {
						continue
					}
					if isFF(arg) {
						sawPos = true
						continue
					}
					return false, false
				}
				return true, sawPos
			}

			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch s := n.(type) {
				case *ast.ValueSpec:
					for i, nm := range s.Names {
						v, ok := info.Defs[nm].(*types.Var)
						if !ok || v == nil || v.Parent() == pkgScope || paramSet[v] || !isFailfileStringOrSliceType(v.Type()) {
							continue
						}
						if i < len(s.Values) {
							totalWrites[v]++
							if isEmptyFailfileReset(info, s.Values[i]) {
								validWrites[v]++
							} else if isFF(s.Values[i]) {
								validWrites[v]++
								positiveWrites[v]++
							}
						}
					}
				case *ast.AssignStmt:
					if len(s.Rhs) == 1 && len(s.Lhs) > 1 {
						call, isCall := ast.Unparen(s.Rhs[0]).(*ast.CallExpr)
						var callee *types.Func
						if isCall {
							callee = resolveHarnessFuncExpr(info, call.Fun)
						}
						for i, lhs := range s.Lhs {
							v := lookupLocalVar(info, pkgScope, lhs)
							if v == nil || paramSet[v] || !isFailfileStringOrSliceType(v.Type()) {
								continue
							}
							totalWrites[v]++
							if callee != nil && !call.Ellipsis.IsValid() {
								if callee.Pkg() != nil && callee.Pkg().Path() == "path/filepath" && callee.Name() == "Glob" && i == 0 && len(call.Args) == 1 && isFF(call.Args[0]) {
									validWrites[v]++
									positiveWrites[v]++
								} else if orig := callee.Origin(); declFuncs[orig] != nil && !orig.Exported() && failfileResults[harnessParamKey{fn: orig, idx: i}] {
									validWrites[v]++
									positiveWrites[v]++
								}
							}
						}
					} else {
						for i, lhs := range s.Lhs {
							v := lookupLocalVar(info, pkgScope, lhs)
							if v == nil || paramSet[v] || !isFailfileStringOrSliceType(v.Type()) {
								continue
							}
							totalWrites[v]++
							if (s.Tok == token.ASSIGN || s.Tok == token.DEFINE) && i < len(s.Rhs) {
								if isEmptyFailfileReset(info, s.Rhs[i]) {
									validWrites[v]++
								} else if isFF(s.Rhs[i]) {
									validWrites[v]++
									positiveWrites[v]++
								} else if s.Tok == token.ASSIGN {
									if okSA, posSA := isSelfAppend(v, s.Rhs[i]); okSA {
										validWrites[v]++
										if posSA {
											positiveWrites[v]++
										}
									}
								}
							}
						}
					}
				case *ast.RangeStmt:
					if s.Key != nil {
						if kv := lookupLocalVar(info, pkgScope, s.Key); kv != nil && !paramSet[kv] && isFailfileStringOrSliceType(kv.Type()) {
							totalWrites[kv]++
						}
					}
					if s.Value != nil {
						if vv := lookupLocalVar(info, pkgScope, s.Value); vv != nil && !paramSet[vv] && isFailfileStringOrSliceType(vv.Type()) {
							totalWrites[vv]++
							if isFF(s.X) {
								validWrites[vv]++
								positiveWrites[vv]++
							}
						}
					}
				case *ast.UnaryExpr:
					if s.Op == token.AND {
						if v := lookupLocalVar(info, pkgScope, s.X); v != nil {
							addrTaken[v] = true
						}
					}
				}
				return true
			})

			for v, tot := range totalWrites {
				if tot > 0 && validWrites[v] == tot && positiveWrites[v] > 0 && !addrTaken[v] && !failfileVars[v] {
					failfileVars[v] = true
					changed = true
				}
			}

			if !g.initOnly[fn] {
				resTuple := fn.Signature().Results()
				for rIdx := 0; rIdx < resTuple.Len(); rIdx++ {
					key := harnessParamKey{fn: fn, idx: rIdx}
					if failfileResults[key] || !isFailfileStringOrSliceType(resTuple.At(rIdx).Type()) {
						continue
					}
					allValid, sawPos := true, false
					ast.Inspect(fd.Body, func(n ast.Node) bool {
						if !allValid || n == nil {
							return false
						}
						if _, isLit := n.(*ast.FuncLit); isLit {
							return false
						}
						ret, ok := n.(*ast.ReturnStmt)
						if !ok {
							return true
						}
						if rIdx >= len(ret.Results) {
							allValid = false
							return false
						}
						rExpr := ret.Results[rIdx]
						if isEmptyFailfileReset(info, rExpr) {
							return true
						}
						if isFF(rExpr) {
							sawPos = true
							return true
						}
						allValid = false
						return false
					})
					if allValid && sawPos {
						failfileResults[key] = true
						changed = true
					}
				}
			}

			if !g.isFuncValueTaken(fn) && !fn.Signature().Variadic() && len(g.callSitesByFunc[fn]) > 0 {
				params := fn.Signature().Params()
				for pIdx := 0; pIdx < params.Len(); pIdx++ {
					pv := params.At(pIdx)
					if failfileParams[pv] || g.isReassignedParam(pv) || !isFailfileStringOrSliceType(pv.Type()) {
						continue
					}
					allSitesOK, sawPos := true, false
					for _, site := range g.callSitesByFunc[fn] {
						if site.Ellipsis.IsValid() || pIdx >= len(site.Args) {
							allSitesOK = false
							break
						}
						arg := site.Args[pIdx]
						if isEmptyFailfileReset(info, arg) {
							continue
						}
						if isFF(arg) {
							sawPos = true
							continue
						}
						allSitesOK = false
						break
					}
					if allSitesOK && sawPos {
						failfileParams[pv] = true
						changed = true
					}
				}
			}
		}
	}

	return failfileVars, failfileParams, failfileResults
}

func collectHarnessTempFileVars(
	g *harnessGraph,
	body *ast.BlockStmt,
	categoryA map[*types.Var]bool,
	failfileVars map[*types.Var]bool,
	failfileParams map[*types.Var]bool,
	failfileResults map[harnessParamKey]bool,
) map[*types.Var]bool {
	info := g.info
	pkgScope := g.pkgTypes.Scope()
	totalWrites := map[*types.Var]int{}
	createTempWrites := map[*types.Var]int{}
	addrTaken := map[*types.Var]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			isCT := false
			if len(s.Rhs) == 1 && len(s.Lhs) == 2 {
				if call, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 2 {
					if callee := resolveHarnessFuncExpr(info, call.Fun); callee != nil && callee.Pkg() != nil &&
						callee.Pkg().Path() == "os" && callee.Name() == "CreateTemp" &&
						isHarnessFailfileExpr(g, call.Args[0], categoryA, failfileVars, failfileParams, failfileResults) {
						isCT = true
					}
				}
			}
			for i, lhs := range s.Lhs {
				v := lookupLocalVar(info, pkgScope, lhs)
				if v == nil {
					continue
				}
				totalWrites[v]++
				if isCT && i == 0 && (s.Tok == token.DEFINE || s.Tok == token.ASSIGN) {
					createTempWrites[v]++
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if v := lookupLocalVar(info, pkgScope, s.X); v != nil {
					addrTaken[v] = true
				}
			}
		}
		return true
	})
	out := map[*types.Var]bool{}
	for v, c := range createTempWrites {
		if c == 1 && totalWrites[v] == 1 && !addrTaken[v] {
			out[v] = true
		}
	}
	return out
}

func isTempFileNameCall(info *types.Info, e ast.Expr, tempFileVars map[*types.Var]bool) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
		return false
	}
	sel, ok := syntaxutil.UnwrapCallee(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Name" {
		return false
	}
	baseID, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := info.Uses[baseID].(*types.Var)
	return ok && tempFileVars[v]
}

func isDebugVisHTMLName(info *types.Info, body *ast.BlockStmt, e ast.Expr) bool {
	isSprintfHTML := func(expr ast.Expr) bool {
		call, ok := ast.Unparen(expr).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() || len(call.Args) < 1 {
			return false
		}
		callee := resolveHarnessFuncExpr(info, call.Fun)
		if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "fmt" || callee.Name() != "Sprintf" {
			return false
		}
		tv, ok := info.Types[call.Args[0]]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
			return false
		}
		fmtStr := constant.StringVal(tv.Value)
		return strings.HasSuffix(fmtStr, ".html") && !strings.ContainsAny(fmtStr, `/\`) && !strings.Contains(fmtStr, "..")
	}
	if isSprintfHTML(e) {
		return true
	}
	if body == nil {
		return false
	}
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok {
		return false
	}
	targetVar, ok := info.Uses[id].(*types.Var)
	if !ok || targetVar == nil {
		return false
	}
	writes := 0
	valid := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				if lID, ok := ast.Unparen(lhs).(*ast.Ident); ok && (info.Defs[lID] == targetVar || info.Uses[lID] == targetVar) {
					writes++
					if i < len(s.Rhs) && (s.Tok == token.DEFINE || s.Tok == token.ASSIGN) && isSprintfHTML(s.Rhs[i]) {
						valid = true
					}
				}
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if lID, ok := ast.Unparen(s.X).(*ast.Ident); ok && info.Uses[lID] == targetVar {
					writes += 2
				}
			}
		}
		return true
	})
	return writes == 1 && valid
}

func verifyHarnessOSFuncCall(
	info *types.Info,
	enclosingFD *ast.FuncDecl,
	enclosingFn *types.Func,
	inInitRoot bool,
	inLit bool,
	inFlagBoolGuard bool,
	fnName string,
	call *ast.CallExpr,
	isFailfile func(ast.Expr) bool,
	tempFileVars map[*types.Var]bool,
) bool {
	if call.Ellipsis.IsValid() {
		return false
	}
	switch fnName {
	case "Getpid":
		return len(call.Args) == 0
	case "IsNotExist":
		return len(call.Args) == 1
	case "Open":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 1 && isFailfile(call.Args[0])
	case "MkdirAll", "CreateTemp":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 2 && isFailfile(call.Args[0])
	case "Remove":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 1 && isTempFileNameCall(info, call.Args[0], tempFileVars)
	case "Rename":
		return !inInitRoot && enclosingFn != nil && !enclosingFn.Exported() && len(call.Args) == 2 &&
			isTempFileNameCall(info, call.Args[0], tempFileVars) && isFailfile(call.Args[1])
	case "Create":
		var body *ast.BlockStmt
		if enclosingFD != nil {
			body = enclosingFD.Body
		}
		return !inInitRoot && !inLit && enclosingFn != nil && !enclosingFn.Exported() &&
			inFlagBoolGuard && len(call.Args) == 1 && isDebugVisHTMLName(info, body, call.Args[0])
	}
	return false
}

func verifyHarnessTemplateCall(
	audited bool,
	info *types.Info,
	pkgTypes *types.Package,
	callee *types.Func,
	call *ast.CallExpr,
) bool {
	if !audited || info == nil || pkgTypes == nil || callee == nil || call == nil || call.Ellipsis.IsValid() {
		return false
	}
	if callee.Signature().Recv() == nil {
		switch callee.Name() {
		case "New":
			return len(call.Args) == 1
		case "Must":
			return len(call.Args) == 1 || len(call.Args) == 2
		default:
			return false
		}
	}
	sel, ok := syntaxutil.UnwrapCallee(call.Fun).(*ast.SelectorExpr)
	if !ok || info.Selections[sel] == nil || info.Selections[sel].Kind() != types.MethodVal {
		return false
	}
	switch callee.Name() {
	case "Parse":
		return len(call.Args) == 1
	case "Execute":
		return len(call.Args) == 2 && isMethodlessCarrierFreeHarnessData(audited, pkgTypes, info.TypeOf(call.Args[1]))
	default:
		return false
	}
}

func isMethodlessCarrierFreeHarnessData(audited bool, pkgTypes *types.Package, t types.Type) bool {
	if !audited || pkgTypes == nil || t == nil || refconfine.TypeMayCarryUnknownDynamic(audited, t) {
		return false
	}
	top := types.Unalias(t)
	if ptr, ok := top.(*types.Pointer); ok {
		top = types.Unalias(ptr.Elem())
	}
	named, ok := top.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() != pkgTypes || named.Obj().Exported() {
		return false
	}
	if _, isStruct := named.Underlying().(*types.Struct); !isStruct {
		return false
	}
	return !typeTreeHasAnyMethods(t, map[types.Type]bool{})
}

func typeTreeHasAnyMethods(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	if types.NewMethodSet(t).Len() > 0 {
		return true
	}
	if _, isPtr := t.(*types.Pointer); !isPtr && !types.IsInterface(t) && types.NewMethodSet(types.NewPointer(t)).Len() > 0 {
		return true
	}
	switch x := t.Underlying().(type) {
	case *types.Pointer:
		return typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Slice:
		return typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Array:
		return typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Map:
		return typeTreeHasAnyMethods(x.Key(), seen) || typeTreeHasAnyMethods(x.Elem(), seen)
	case *types.Struct:
		for i := 0; i < x.NumFields(); i++ {
			if typeTreeHasAnyMethods(x.Field(i).Type(), seen) {
				return true
			}
		}
	}
	return false
}
