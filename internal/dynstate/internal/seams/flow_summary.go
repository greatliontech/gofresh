package seams

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// AnalyzeCallGraph builds the intra-package and cross-package sequential and
// parallel call/dataflow graph for package p.
func AnalyzeCallGraph(p *packages.Package) CallGraph {
	var out CallGraph
	if p == nil || p.TypesInfo == nil {
		return out
	}
	stdPaths := collectStdTestingFreePaths(p)
	allDeclFuncs := map[*types.Func]*ast.FuncDecl{}
	declFuncs := map[*types.Func]*ast.FuncDecl{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil || fd.Name.Name == "init" || fd.Name.Name == "_" || fd.Body == nil {
				continue
			}
			fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
			if !ok || fn == nil {
				continue
			}
			fn = fn.Origin()
			allDeclFuncs[fn] = fd
			if fd.Recv == nil {
				declFuncs[fn] = fd
			}
		}
	}
	out.DeclPlainFuncs = declFuncs

	g := newParGraph(p, stdPaths, allDeclFuncs, declFuncs)
	g.buildAndSolve(&out)

	directCalleeIdents := map[*ast.Ident]bool{}
	for _, fd := range declFuncs {
		goCalls := map[*ast.CallExpr]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if gs, ok := n.(*ast.GoStmt); ok && gs.Call != nil {
				goCalls[gs.Call] = true
			}
			return true
		})
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || goCalls[call] {
				return true
			}
			if callee, _ := syntaxutil.PlainCalleeFunc(p, call.Fun); callee != nil {
				switch fun := syntaxutil.UnwrapCallee(call.Fun).(type) {
				case *ast.Ident:
					directCalleeIdents[fun] = true
				case *ast.SelectorExpr:
					directCalleeIdents[fun.Sel] = true
				}
			}
			return true
		})
	}

	blocked := map[*types.Func]bool{}
	nonSeqUses := map[syntaxutil.FuncKey]bool{}
	recordNonSeqCallee := func(fn *types.Func) {
		if fn == nil || fn.Pkg() == nil {
			return
		}
		fn = fn.Origin()
		if declFuncs[fn] != nil {
			blocked[fn] = true
			if fn.Exported() {
				nonSeqUses[syntaxutil.FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}] = true
			}
			return
		}
		if (p.Types == nil || fn.Pkg() != p.Types) && !g.isStdCallee(fn) {
			nonSeqUses[syntaxutil.FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}] = true
		}
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || directCalleeIdents[id] {
				return true
			}
			fn, ok := p.TypesInfo.Uses[id].(*types.Func)
			if !ok || fn == nil || fn.Pkg() == nil {
				return true
			}
			fn = fn.Origin()
			sig, ok := fn.Type().(*types.Signature)
			if !ok || sig == nil || sig.Recv() != nil {
				return true
			}
			recordNonSeqCallee(fn)
			return true
		})
	}
	out.Blocked = blocked
	if len(declFuncs) == 0 {
		for k := range nonSeqUses {
			out.NonSeqFuncUses = append(out.NonSeqFuncUses, k)
		}
		slices.SortFunc(out.NonSeqFuncUses, syntaxutil.FuncKey.Compare)
		return out
	}

	resolvePkgFunc := func(expr ast.Expr) *types.Func {
		fn, _ := syntaxutil.PlainCalleeFunc(p, expr)
		if fn == nil || declFuncs[fn] == nil {
			return nil
		}
		return fn
	}

	paramIndexForArg := func(callee *types.Func, argIdx int, isEllipsis bool) (int, bool) {
		sig, ok := callee.Type().(*types.Signature)
		if !ok || sig == nil {
			return 0, false
		}
		return sigParamIndexForArg(sig, argIdx, isEllipsis)
	}

	isTestingSyncCallbackArg := func(call *ast.CallExpr, argIdx int) bool {
		switch testingSyncMethodName(p.TypesInfo, call) {
		case "Run":
			return len(call.Args) == 2 && argIdx == 1
		case "Cleanup", "Fuzz":
			return len(call.Args) == 1 && argIdx == 0
		}
		return false
	}

	litCallsParallelHelper := func(lit *ast.FuncLit) bool {
		if lit == nil {
			return false
		}
		found := false
		checkType := func(t types.Type) {
			if found || t == nil {
				return
			}
			if h := g.typeHubID(t); h >= 0 && g.reachesPar[h] {
				found = true
				return
			}
			if len(g.typeParamObjIDs) > 0 {
				for _, tp := range g.collectTypeParams(t) {
					if tpID, ok := g.typeParamObjIDs[tp]; ok && g.reachesPar[tpID] {
						found = true
						return
					}
				}
			}
		}
		ast.Inspect(lit, func(n ast.Node) bool {
			if found || n == nil {
				return false
			}
			if expr, isExpr := n.(ast.Expr); isExpr {
				if tv, ok := p.TypesInfo.Types[expr]; ok && tv.Type != nil {
					checkType(tv.Type)
				}
			}
			if cc, isCC := n.(*ast.CaseClause); isCC {
				if impObj := p.TypesInfo.Implicits[cc]; impObj != nil {
					checkType(impObj.Type())
				}
			}
			if id, ok := n.(*ast.Ident); ok {
				if inst, ok := p.TypesInfo.Instances[id]; ok {
					checkType(inst.Type)
					if inst.TypeArgs != nil {
						for i := 0; i < inst.TypeArgs.Len(); i++ {
							checkType(inst.TypeArgs.At(i))
						}
					}
				}
				if defObj := p.TypesInfo.Defs[id]; defObj != nil {
					checkType(defObj.Type())
				}
				switch obj := p.TypesInfo.Uses[id].(type) {
				case *types.Func:
					if obj != nil {
						checkType(obj.Type())
						fn := obj.Origin()
						if eID, ok := g.execIDs[fn]; ok && g.reachesPar[eID] {
							found = true
							return false
						}
						if (p.Types == nil || fn.Pkg() != p.Types) && !g.isStdCallee(fn) {
							if fk, ok := syntaxutil.CallableFactKey(fn); ok {
								if cID, ok := g.crossIDs[fk]; ok && g.reachesPar[cID] {
									found = true
									return false
								}
							}
						}
					}
				case *types.Var:
					if obj != nil {
						checkType(obj.Type())
						if v, ok := g.isSamePkgNonFieldVar(obj); ok {
							if vID, ok := g.varIDs[v]; ok && g.reachesPar[vID] {
								found = true
								return false
							}
						} else if (p.Types == nil || obj.Pkg() != p.Types) && obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() && !g.isStdPkg(obj.Pkg()) {
							fk := syntaxutil.FuncKey{Pkg: obj.Pkg().Path(), Name: obj.Name()}
							if cID, ok := g.crossIDs[fk]; ok && g.reachesPar[cID] {
								found = true
								return false
							}
						}
					}
				case *types.TypeName:
					if obj != nil {
						checkType(obj.Type())
					}
				}
			}
			return !found
		})
		return found
	}

	type callArgRef struct {
		call   *ast.CallExpr
		argIdx int
	}
	type pkgArgRef struct {
		callee   *types.Func
		paramIdx int
	}
	type identOcc struct {
		id            *ast.Ident
		inGo          bool
		enclosingLits []*ast.FuncLit
	}
	type litInfo struct {
		lit           *ast.FuncLit
		inGo          bool
		enclosingLits []*ast.FuncLit
		directCall    bool
		testingSync   bool
		pkgCallArg    *pkgArgRef
		boundLocal    types.Object
	}
	type fnScopeInfo struct {
		fd              *ast.FuncDecl
		paramIdxByObj   map[types.Object]int
		paramIdents     map[int][]identOcc
		localLits       map[types.Object][]*ast.FuncLit
		localReadIdents map[types.Object][]identOcc
		lits            []*litInfo
		directCallIdent map[*ast.Ident]bool
		callArgIdent    map[*ast.Ident]callArgRef
	}

	nonSeqParam := map[*types.Func]map[int]bool{}
	markNonSeqParam := func(fn *types.Func, pIdx int) bool {
		if nonSeqParam[fn] == nil {
			nonSeqParam[fn] = map[int]bool{}
		}
		if nonSeqParam[fn][pIdx] {
			return false
		}
		nonSeqParam[fn][pIdx] = true
		return true
	}
	nonSeqLit := map[*ast.FuncLit]bool{}
	nonSeqLocal := map[types.Object]bool{}

	scopes := map[*types.Func]*fnScopeInfo{}
	for fn, fd := range declFuncs {
		fnReachesPar := g.reachesPar[g.execFuncID(fn)]
		info := &fnScopeInfo{
			fd:              fd,
			paramIdxByObj:   map[types.Object]int{},
			paramIdents:     map[int][]identOcc{},
			localLits:       map[types.Object][]*ast.FuncLit{},
			localReadIdents: map[types.Object][]identOcc{},
			directCallIdent: map[*ast.Ident]bool{},
			callArgIdent:    map[*ast.Ident]callArgRef{},
		}
		sigVars := map[types.Object]bool{}
		recordFieldListVars := func(fl *ast.FieldList) {
			if fl == nil {
				return
			}
			for _, field := range fl.List {
				for _, name := range field.Names {
					if obj := p.TypesInfo.Defs[name]; obj != nil {
						sigVars[obj] = true
					}
				}
			}
		}
		if fd.Type != nil {
			recordFieldListVars(fd.Type.Params)
			recordFieldListVars(fd.Type.Results)
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.FuncLit); ok && lit.Type != nil {
				recordFieldListVars(lit.Type.Params)
				recordFieldListVars(lit.Type.Results)
			}
			return true
		})
		if fd.Type != nil && fd.Type.Params != nil {
			idx := 0
			for _, field := range fd.Type.Params.List {
				if len(field.Names) == 0 {
					if fnReachesPar {
						markNonSeqParam(fn, idx)
					}
					idx++
					continue
				}
				for _, name := range field.Names {
					if obj := p.TypesInfo.Defs[name]; obj != nil {
						info.paramIdxByObj[obj] = idx
					}
					if fnReachesPar {
						markNonSeqParam(fn, idx)
					}
					idx++
				}
			}
		}

		isLocalVar := func(obj types.Object) bool {
			v, ok := obj.(*types.Var)
			if !ok || v == nil || v.IsField() || p.Types == nil || v.Pkg() != p.Types || v.Parent() == p.Types.Scope() {
				return false
			}
			return !sigVars[v]
		}

		goCalls := map[*ast.CallExpr]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if gs, ok := n.(*ast.GoStmt); ok && gs.Call != nil {
				goCalls[gs.Call] = true
			}
			return true
		})

		litDirectCall := map[*ast.FuncLit]bool{}
		litTestingSync := map[*ast.FuncLit]bool{}
		litPkgCallArg := map[*ast.FuncLit]*pkgArgRef{}
		litBoundLocal := map[*ast.FuncLit]types.Object{}
		validWriteIdent := map[*ast.Ident]bool{}

		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if goCalls[node] {
					return true
				}
				switch fun := ast.Unparen(node.Fun).(type) {
				case *ast.Ident:
					info.directCallIdent[fun] = true
				case *ast.FuncLit:
					litDirectCall[fun] = true
				}
				callee := resolvePkgFunc(node.Fun)
				for argIdx, arg := range node.Args {
					switch a := ast.Unparen(arg).(type) {
					case *ast.Ident:
						info.callArgIdent[a] = callArgRef{call: node, argIdx: argIdx}
					case *ast.FuncLit:
						if isTestingSyncCallbackArg(node, argIdx) {
							litTestingSync[a] = true
						}
						if callee != nil {
							if pIdx, ok := paramIndexForArg(callee, argIdx, node.Ellipsis.IsValid()); ok {
								litPkgCallArg[a] = &pkgArgRef{callee: callee, paramIdx: pIdx}
							}
						}
					}
				}
			case *ast.ValueSpec:
				if len(node.Values) == 0 {
					for _, name := range node.Names {
						if obj := p.TypesInfo.Defs[name]; isLocalVar(obj) {
							validWriteIdent[name] = true
						}
					}
				} else if len(node.Names) == len(node.Values) {
					for i, name := range node.Names {
						obj := p.TypesInfo.Defs[name]
						if !isLocalVar(obj) {
							continue
						}
						if lit, ok := ast.Unparen(node.Values[i]).(*ast.FuncLit); ok && litBoundLocal[lit] == nil {
							validWriteIdent[name] = true
							info.localLits[obj] = append(info.localLits[obj], lit)
							litBoundLocal[lit] = obj
						} else if rhsID, ok := ast.Unparen(node.Values[i]).(*ast.Ident); ok {
							if _, isNil := p.TypesInfo.Uses[rhsID].(*types.Nil); isNil {
								validWriteIdent[name] = true
							} else {
								nonSeqLocal[obj] = true
							}
						} else {
							nonSeqLocal[obj] = true
						}
					}
				}
			case *ast.AssignStmt:
				if (node.Tok == token.DEFINE || node.Tok == token.ASSIGN) && len(node.Lhs) == len(node.Rhs) {
					for i, lhs := range node.Lhs {
						id, ok := ast.Unparen(lhs).(*ast.Ident)
						if !ok {
							continue
						}
						obj := syntaxutil.IdentDefOrUse(p.TypesInfo, id)
						if !isLocalVar(obj) {
							continue
						}
						if lit, ok := ast.Unparen(node.Rhs[i]).(*ast.FuncLit); ok && litBoundLocal[lit] == nil {
							validWriteIdent[id] = true
							info.localLits[obj] = append(info.localLits[obj], lit)
							litBoundLocal[lit] = obj
						} else if rhsID, ok := ast.Unparen(node.Rhs[i]).(*ast.Ident); ok {
							if _, isNil := p.TypesInfo.Uses[rhsID].(*types.Nil); isNil {
								validWriteIdent[id] = true
							} else {
								nonSeqLocal[obj] = true
							}
						} else {
							nonSeqLocal[obj] = true
						}
					}
				}
			}
			return true
		})

		var litStack []*ast.FuncLit
		goDepth := 0
		var walkCtx func(ast.Node)
		walkCtx = func(n ast.Node) {
			if n == nil {
				return
			}
			switch node := n.(type) {
			case *ast.GoStmt:
				goDepth++
				if node.Call != nil {
					walkCtx(node.Call)
				}
				goDepth--
				return
			case *ast.FuncLit:
				li := &litInfo{
					lit:           node,
					inGo:          goDepth > 0,
					enclosingLits: slices.Clone(litStack),
					directCall:    litDirectCall[node],
					testingSync:   litTestingSync[node],
					pkgCallArg:    litPkgCallArg[node],
					boundLocal:    litBoundLocal[node],
				}
				if bodyHasParallelSelector(p.TypesInfo, node.Body) || litCallsParallelHelper(node) {
					nonSeqLit[node] = true
				}
				info.lits = append(info.lits, li)
				if node.Type != nil {
					walkCtx(node.Type)
				}
				litStack = append(litStack, node)
				if node.Body != nil {
					walkCtx(node.Body)
				}
				litStack = litStack[:len(litStack)-1]
				return
			case *ast.Ident:
				obj := syntaxutil.IdentDefOrUse(p.TypesInfo, node)
				if pIdx, isParam := info.paramIdxByObj[obj]; isParam {
					info.paramIdents[pIdx] = append(info.paramIdents[pIdx], identOcc{
						id:            node,
						inGo:          goDepth > 0,
						enclosingLits: slices.Clone(litStack),
					})
				} else if isLocalVar(obj) && !validWriteIdent[node] {
					info.localReadIdents[obj] = append(info.localReadIdents[obj], identOcc{
						id:            node,
						inGo:          goDepth > 0,
						enclosingLits: slices.Clone(litStack),
					})
				}
				return
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if child == nil || child == n {
					return true
				}
				walkCtx(child)
				return false
			})
		}
		walkCtx(fd.Body)
		scopes[fn] = info
	}

	occIsSequential := func(info *fnScopeInfo, occ identOcc) bool {
		if occ.inGo {
			return false
		}
		for _, enc := range occ.enclosingLits {
			if nonSeqLit[enc] {
				return false
			}
		}
		if info.directCallIdent[occ.id] {
			return true
		}
		ref, ok := info.callArgIdent[occ.id]
		if !ok {
			return false
		}
		if isTestingSyncCallbackArg(ref.call, ref.argIdx) {
			return true
		}
		callee := resolvePkgFunc(ref.call.Fun)
		if callee == nil {
			return false
		}
		pIdx, ok := paramIndexForArg(callee, ref.argIdx, ref.call.Ellipsis.IsValid())
		if !ok {
			return false
		}
		return !nonSeqParam[callee][pIdx]
	}

	for changed := true; changed; {
		changed = false
		for fn, info := range scopes {
			for _, li := range info.lits {
				if nonSeqLit[li.lit] {
					continue
				}
				enclosingBad := li.inGo
				if !enclosingBad {
					for _, enc := range li.enclosingLits {
						if nonSeqLit[enc] {
							enclosingBad = true
							break
						}
					}
				}
				seqAttached := li.directCall || li.testingSync ||
					(li.pkgCallArg != nil && !nonSeqParam[li.pkgCallArg.callee][li.pkgCallArg.paramIdx]) ||
					(li.boundLocal != nil && !nonSeqLocal[li.boundLocal])
				if enclosingBad || !seqAttached {
					nonSeqLit[li.lit] = true
					changed = true
				}
			}
			for localObj := range info.localLits {
				if nonSeqLocal[localObj] {
					continue
				}
				for _, occ := range info.localReadIdents[localObj] {
					if !occIsSequential(info, occ) {
						nonSeqLocal[localObj] = true
						changed = true
						break
					}
				}
			}
			for pIdx, occs := range info.paramIdents {
				if nonSeqParam[fn][pIdx] {
					continue
				}
				for _, occ := range occs {
					if !occIsSequential(info, occ) {
						if markNonSeqParam(fn, pIdx) {
							changed = true
						}
						break
					}
				}
			}
		}
	}

	edges := map[*types.Func]map[*types.Func]bool{}
	addEdge := func(from, to *types.Func) {
		if from == nil || to == nil {
			return
		}
		if edges[from] == nil {
			edges[from] = map[*types.Func]bool{}
		}
		edges[from][to] = true
	}
	crossEdges := map[*types.Func]map[syntaxutil.FuncKey]bool{}
	addCrossEdge := func(from *types.Func, to syntaxutil.FuncKey) {
		if from == nil || !to.Valid() {
			return
		}
		if crossEdges[from] == nil {
			crossEdges[from] = map[syntaxutil.FuncKey]bool{}
		}
		crossEdges[from][to] = true
	}

	for callerFn, info := range scopes {
		fd := info.fd
		seedSubtree := func(root ast.Node) {
			visitedLits := map[*ast.FuncLit]bool{}
			var mark func(ast.Node)
			mark = func(sub ast.Node) {
				if sub == nil {
					return
				}
				ast.Inspect(sub, func(n ast.Node) bool {
					switch node := n.(type) {
					case *ast.CallExpr:
						if callee, _ := syntaxutil.PlainCalleeFunc(p, node.Fun); callee != nil {
							recordNonSeqCallee(callee)
						}
					case *ast.Ident:
						for _, lit := range info.localLits[p.TypesInfo.Uses[node]] {
							if !visitedLits[lit] {
								visitedLits[lit] = true
								mark(lit.Body)
							}
						}
					}
					return true
				})
			}
			mark(root)
		}

		if g.reachesPar[g.execFuncID(callerFn)] {
			blocked[callerFn] = true
			seedSubtree(fd.Body)
		}

		for _, li := range info.lits {
			if nonSeqLit[li.lit] {
				seedSubtree(li.lit.Body)
			}
		}

		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.GoStmt:
				seedSubtree(node)
			case *ast.CallExpr:
				callee, calleePkg := syntaxutil.PlainCalleeFunc(p, node.Fun)
				if callee == nil {
					return true
				}
				if declFuncs[callee] != nil {
					addEdge(callerFn, callee)
					if sp := nonSeqParam[callee]; len(sp) > 0 {
						for argIdx, arg := range node.Args {
							if pIdx, ok := paramIndexForArg(callee, argIdx, node.Ellipsis.IsValid()); ok && sp[pIdx] {
								seedSubtree(arg)
							}
						}
					}
				} else if (p.Types == nil || callee.Pkg() != p.Types) && !g.isStdCallee(callee) {
					addCrossEdge(callerFn, syntaxutil.FuncKey{Pkg: calleePkg, Name: callee.Name()})
				}
			}
			return true
		})
	}

	queue := make([]*types.Func, 0, len(blocked))
	for fn := range blocked {
		queue = append(queue, fn)
	}
	for len(queue) > 0 {
		cur := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for callee := range edges[cur] {
			if !blocked[callee] {
				blocked[callee] = true
				queue = append(queue, callee)
			}
		}
	}
	for fn := range blocked {
		if fn.Pkg() != nil && fn.Exported() {
			nonSeqUses[syntaxutil.FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}] = true
		}
		for crossCallee := range crossEdges[fn] {
			nonSeqUses[crossCallee] = true
		}
	}

	if p.Types != nil {
		isSeqRoot := func(fn *types.Func) bool {
			return fn != nil && declFuncs[fn] != nil &&
				(fn.Exported() || (p.Name == "main" && fn.Name() == "main"))
		}
		seenSeqEdge := map[syntaxutil.FuncDepEdge]bool{}
		recordSeqEdge := func(from, to syntaxutil.FuncKey) {
			if !from.Valid() || !to.Valid() || from == to {
				return
			}
			edge := syntaxutil.FuncDepEdge{Func: from, Callee: to}
			if !seenSeqEdge[edge] {
				seenSeqEdge[edge] = true
				out.SeqFuncEdges = append(out.SeqFuncEdges, edge)
			}
		}
		for rootFn := range declFuncs {
			if !isSeqRoot(rootFn) {
				continue
			}
			rootKey := syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: rootFn.Name()}
			visited := map[*types.Func]bool{rootFn: true}
			stack := []*types.Func{rootFn}
			for len(stack) > 0 {
				cur := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if cur != rootFn && isSeqRoot(cur) {
					recordSeqEdge(rootKey, syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: cur.Name()})
					continue
				}
				for crossCallee := range crossEdges[cur] {
					recordSeqEdge(rootKey, crossCallee)
				}
				for next := range edges[cur] {
					if !visited[next] {
						visited[next] = true
						stack = append(stack, next)
					}
				}
			}
		}
		slices.SortFunc(out.SeqFuncEdges, syntaxutil.FuncDepEdge.Compare)
	}

	for k := range nonSeqUses {
		out.NonSeqFuncUses = append(out.NonSeqFuncUses, k)
	}
	slices.SortFunc(out.NonSeqFuncUses, syntaxutil.FuncKey.Compare)
	out.NonSeqLits = nonSeqLit
	out.IntraEdges = edges
	return out
}
