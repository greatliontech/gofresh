package seams

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (g *parGraph) wireNodeSelf(id int, n ast.Node) {
	if expr, isExpr := n.(ast.Expr); isExpr {
		if tv, ok := g.p.TypesInfo.Types[expr]; ok && tv.Type != nil {
			g.addParEdge(id, g.typeHubID(tv.Type))
			g.wireTypeParamsOfType(id, tv.Type)
		}
	}
	switch node := n.(type) {
	case *ast.CaseClause:
		if impObj := g.p.TypesInfo.Implicits[node]; impObj != nil {
			g.addParEdge(id, g.typeHubID(impObj.Type()))
			g.wireTypeParamsOfType(id, impObj.Type())
		}
	case *ast.SelectorExpr:
		if isParallelSelector(g.p.TypesInfo, node) {
			g.reachesPar[id] = true
		}
	case *ast.Ident:
		if inst, ok := g.p.TypesInfo.Instances[node]; ok {
			g.addParEdge(id, g.typeHubID(inst.Type))
			g.wireTypeParamsOfType(id, inst.Type)
			if inst.TypeArgs != nil {
				for i := 0; i < inst.TypeArgs.Len(); i++ {
					g.addParEdge(id, g.typeHubID(inst.TypeArgs.At(i)))
					g.wireTypeParamsOfType(id, inst.TypeArgs.At(i))
				}
			}
		}
		if defObj := g.p.TypesInfo.Defs[node]; defObj != nil {
			g.addParEdge(id, g.typeHubID(defObj.Type()))
			g.wireTypeParamsOfType(id, defObj.Type())
		}
		if useObj := g.p.TypesInfo.Uses[node]; useObj != nil {
			if fnObj, isFn := useObj.(*types.Func); isFn && g.anyDirectCalleeIdent[node] {
				g.addParEdge(id, g.typeHubID(fnObj.Type()))
				if !g.isStdCallee(fnObj) {
					g.recordMethodTarget(id, fnObj)
				}
			} else {
				g.recordObjOnNode(id, useObj, false)
			}
		}
	}
}

func (g *parGraph) astSubtreeID(n ast.Node) int {
	if n == nil {
		return -1
	}
	if id, ok := g.subtreeIDs[n]; ok {
		return id
	}
	id := g.newNode()
	g.subtreeIDs[n] = id
	g.wireNodeSelf(id, n)

	switch node := n.(type) {
	case *ast.FuncLit:
		ast.Inspect(node, func(litNode ast.Node) bool {
			if litNode == nil {
				return false
			}
			if litNode != node {
				g.wireNodeSelf(id, litNode)
			}
			return true
		})
		return id
	case *ast.CallExpr:
		if tv, isType := g.p.TypesInfo.Types[node.Fun]; !isType || !tv.IsType() {
			var resType types.Type
			if tvCall, ok := g.p.TypesInfo.Types[node]; ok {
				resType = tvCall.Type
			}
			if !g.typeMayCarryParallel(resType) {
				return id
			}
			if declFn, funIdent := g.resolveConcreteDeclCallee(node); declFn != nil {
				g.addParEdge(id, g.returnID(declFn))
				if funIdent != nil {
					if inst, ok := g.p.TypesInfo.Instances[funIdent]; ok {
						g.addParEdge(id, g.typeHubID(inst.Type))
						g.wireTypeParamsOfType(id, inst.Type)
						if inst.TypeArgs != nil {
							for i := 0; i < inst.TypeArgs.Len(); i++ {
								g.addParEdge(id, g.typeHubID(inst.TypeArgs.At(i)))
								g.wireTypeParamsOfType(id, inst.TypeArgs.At(i))
							}
						}
					}
				}
				return id
			}
		}
	}

	ast.Inspect(n, func(cur ast.Node) bool {
		if cur == nil {
			return false
		}
		if cur == n {
			return true
		}
		switch cur.(type) {
		case *ast.FuncLit, *ast.CallExpr:
			g.addParEdge(id, g.astSubtreeID(cur))
			return false
		}
		g.wireNodeSelf(id, cur)
		return true
	})
	return id
}

func (g *parGraph) bindSubtree(ownerID int, sub ast.Node) {
	if ownerID < 0 || sub == nil {
		return
	}
	g.addParEdge(ownerID, g.astSubtreeID(sub))
}

func (g *parGraph) scanExecSubtree(execID int, root ast.Node) {
	if execID < 0 || root == nil {
		return
	}
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if expr, isExpr := n.(ast.Expr); isExpr {
			if tv, ok := g.p.TypesInfo.Types[expr]; ok && tv.Type != nil {
				g.addParEdge(execID, g.typeHubID(tv.Type))
			}
		}
		switch node := n.(type) {
		case *ast.CaseClause:
			if impObj := g.p.TypesInfo.Implicits[node]; impObj != nil {
				g.addParEdge(execID, g.typeHubID(impObj.Type()))
			}
		case *ast.SelectorExpr:
			if isParallelSelector(g.p.TypesInfo, node) {
				g.reachesPar[execID] = true
			}
		case *ast.Ident:
			if inst, ok := g.p.TypesInfo.Instances[node]; ok {
				g.addParEdge(execID, g.typeHubID(inst.Type))
				if inst.TypeArgs != nil {
					for i := 0; i < inst.TypeArgs.Len(); i++ {
						g.addParEdge(execID, g.typeHubID(inst.TypeArgs.At(i)))
					}
				}
			}
			if defObj := g.p.TypesInfo.Defs[node]; defObj != nil {
				g.addParEdge(execID, g.typeHubID(defObj.Type()))
			}
			if useObj := g.p.TypesInfo.Uses[node]; useObj != nil {
				g.recordObjOnNode(execID, useObj, true)
			}
		}
		return true
	})
}

func (g *parGraph) exprWriteThroughTargets(expr ast.Expr) []int {
	if expr == nil {
		return nil
	}
	if cached, ok := g.exprWTMemo[expr]; ok {
		return cached
	}
	var outTargets []int
	appendTarget := func(id int) {
		if id < 0 {
			return
		}
		for _, ex := range outTargets {
			if ex == id {
				return
			}
		}
		outTargets = append(outTargets, id)
	}
	appendTargets := func(ids []int) {
		for _, id := range ids {
			appendTarget(id)
		}
	}
	appendConcreteFuncReturnWriteTarget := func(fn *types.Func) {
		if fn == nil || fn.Pkg() == nil {
			return
		}
		origFn := fn.Origin()
		if g.allDecls[origFn] != nil {
			appendTarget(g.returnWriteID(origFn))
			return
		}
		if (g.p.Types == nil || origFn.Pkg() != g.p.Types) && !g.isStdCallee(origFn) {
			origSig, _ := origFn.Type().(*types.Signature)
			if g.funcMayReturnMutableAlias(origSig) {
				if fk, ok := syntaxutil.CallableFactKey(origFn); ok {
					appendTarget(g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#rw"}))
				}
			}
		}
	}
	appendYieldCallbackWriteHubs := func(root types.Type) {
		var visited map[types.Type]bool
		var walk func(t types.Type)
		walk = func(t types.Type) {
			if t == nil {
				return
			}
			switch u := t.(type) {
			case *types.Alias, *types.Named, *types.Tuple, *types.TypeParam, *types.Union, *types.Signature:
			case *types.Interface:
				if u.NumEmbeddeds() == 0 {
					return
				}
			default:
				return
			}
			if visited[t] {
				return
			}
			if visited == nil {
				visited = map[types.Type]bool{}
			}
			visited[t] = true
			switch u := t.(type) {
			case *types.Alias:
				walk(types.Unalias(u))
			case *types.Named:
				walk(u.Underlying())
			case *types.Tuple:
				for i := 0; i < u.Len(); i++ {
					walk(u.At(i).Type())
				}
			case *types.TypeParam:
				walk(u.Constraint())
			case *types.Interface:
				for i := 0; i < u.NumEmbeddeds(); i++ {
					walk(u.EmbeddedType(i))
				}
			case *types.Union:
				for i := 0; i < u.Len(); i++ {
					if term := u.Term(i); term != nil {
						walk(term.Type())
					}
				}
			case *types.Signature:
				if u.Results() != nil {
					for i := 0; i < u.Results().Len(); i++ {
						walk(u.Results().At(i).Type())
					}
				}
				if u.Params() != nil {
					for i := 0; i < u.Params().Len(); i++ {
						pType := u.Params().At(i).Type()
						forEachCallableSignature(pType, func(cu *types.Signature) {
							if cu.Params() != nil {
								for k := 0; k < cu.Params().Len(); k++ {
									if g.typeMayCarryMutableAlias(cu.Params().At(k).Type()) {
										appendTarget(g.dynHubWriteID(cu, k))
									}
								}
							}
						})
						walk(pType)
					}
				}
			}
		}
		walk(root)
	}
	switch e := expr.(type) {
	case *ast.ParenExpr:
		appendTargets(g.exprWriteThroughTargets(e.X))
	case *ast.StarExpr:
		appendTargets(g.exprWriteThroughTargets(e.X))
	case *ast.IndexExpr:
		appendTargets(g.exprWriteThroughTargets(e.X))
	case *ast.IndexListExpr:
		appendTargets(g.exprWriteThroughTargets(e.X))
	case *ast.SliceExpr:
		appendTargets(g.exprWriteThroughTargets(e.X))
	case *ast.TypeAssertExpr:
		appendTargets(g.exprWriteThroughTargets(e.X))
	case *ast.UnaryExpr:
		switch e.Op {
		case token.AND:
			appendTarget(g.targetVarID(extractTargetVar(g.p.TypesInfo, e.X)))
			appendTargets(g.exprWriteThroughTargets(e.X))
		case token.ARROW:
			appendTargets(g.exprWriteThroughTargets(e.X))
		}
	case *ast.Ident:
		switch obj := syntaxutil.IdentDefOrUse(g.p.TypesInfo, e).(type) {
		case *types.Var:
			appendTarget(g.targetVarWriteThroughID(obj))
		case *types.Func:
			appendConcreteFuncReturnWriteTarget(obj)
		}
	case *ast.SelectorExpr:
		if selInfo := g.p.TypesInfo.Selections[e]; selInfo == nil {
			switch obj := g.p.TypesInfo.Uses[e.Sel].(type) {
			case *types.Var:
				appendTarget(g.targetVarWriteThroughID(obj))
			case *types.Func:
				appendConcreteFuncReturnWriteTarget(obj)
			}
		} else {
			switch selInfo.Kind() {
			case types.MethodVal, types.MethodExpr:
				fn, _ := selInfo.Obj().(*types.Func)
				var origFn *types.Func
				var origSig *types.Signature
				if fn != nil {
					origFn = fn.Origin()
					origSig, _ = origFn.Type().(*types.Signature)
				}
				isIface := isInterfaceMethodSelection(selInfo, origFn)
				if isIface {
					if origFn != nil {
						appendTarget(g.ifaceReturnWriteID(origFn.Name(), origSig))
					}
				} else {
					appendConcreteFuncReturnWriteTarget(origFn)
				}
				if selInfo.Kind() == types.MethodVal {
					appendTargets(g.methodRecvWriteTargets(e.X, isIface, origSig))
				}
			default:
				appendTargets(g.exprWriteThroughTargets(e.X))
			}
		}
	case *ast.FuncLit:
		appendTarget(g.litReturnWriteID(e))
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			appendTargets(g.exprWriteThroughTargets(elt))
		}
	case *ast.KeyValueExpr:
		appendTargets(g.exprWriteThroughTargets(e.Key))
		appendTargets(g.exprWriteThroughTargets(e.Value))
	case *ast.CallExpr:
		if tvFun, isType := g.p.TypesInfo.Types[e.Fun]; isType && tvFun.IsType() {
			if len(e.Args) == 1 {
				appendTargets(g.exprWriteThroughTargets(e.Args[0]))
			}
			break
		}
		tvCall, ok := g.p.TypesInfo.Types[e]
		if !ok || !g.typeMayCarryMutableAlias(tvCall.Type) {
			break
		}
		if lit, ok := ast.Unparen(e.Fun).(*ast.FuncLit); ok {
			appendTarget(g.litReturnWriteID(lit))
			break
		}
		appendBuiltinWriteThrough := func(b *types.Builtin) {
			if b == nil {
				return
			}
			switch b.Name() {
			case "append", "Slice", "SliceData", "Add":
				if len(e.Args) >= 1 {
					appendTargets(g.exprWriteThroughTargets(e.Args[0]))
				}
			case "new":
				if len(e.Args) == 1 {
					if tvArg, ok := g.p.TypesInfo.Types[e.Args[0]]; !ok || !tvArg.IsType() {
						appendTargets(g.exprWriteThroughTargets(e.Args[0]))
					}
				}
			}
		}
		switch fun := syntaxutil.UnwrapCallee(e.Fun).(type) {
		case *ast.Ident:
			if b, isBuiltin := g.p.TypesInfo.Uses[fun].(*types.Builtin); isBuiltin {
				appendBuiltinWriteThrough(b)
				break
			}
			if fn, ok := g.p.TypesInfo.Uses[fun].(*types.Func); ok && fn != nil {
				if g.isStdCallee(fn.Origin()) {
					for _, arg := range e.Args {
						appendTargets(g.exprWriteThroughTargets(arg))
					}
				} else {
					appendConcreteFuncReturnWriteTarget(fn)
				}
			} else if tv, ok := g.p.TypesInfo.Types[e.Fun]; ok && tv.Type != nil {
				forEachCallableSignature(tv.Type, func(sig *types.Signature) {
					appendTarget(g.dynReturnWriteID(sig))
					appendTargets(g.exprWriteThroughTargets(e.Fun))
				})
			}
		case *ast.SelectorExpr:
			if selInfo, isSel := g.p.TypesInfo.Selections[fun]; isSel && selInfo != nil {
				switch selInfo.Kind() {
				case types.MethodVal, types.MethodExpr:
					fn, _ := selInfo.Obj().(*types.Func)
					var origFn *types.Func
					var origSig *types.Signature
					if fn != nil {
						origFn = fn.Origin()
						origSig, _ = origFn.Type().(*types.Signature)
					}
					if isInterfaceMethodSelection(selInfo, origFn) {
						if origFn != nil {
							appendTarget(g.ifaceReturnWriteID(origFn.Name(), origSig))
						}
						if selInfo.Kind() == types.MethodVal {
							appendTargets(g.methodRecvWriteTargets(fun.X, true, origSig))
						} else if len(e.Args) >= 1 {
							appendTargets(g.methodRecvWriteTargets(e.Args[0], true, origSig))
						}
					} else if origFn != nil {
						if g.isStdCallee(origFn) {
							if selInfo.Kind() == types.MethodVal {
								appendTargets(g.methodRecvWriteTargets(fun.X, false, origSig))
							}
							for _, arg := range e.Args {
								appendTargets(g.exprWriteThroughTargets(arg))
							}
						} else {
							appendConcreteFuncReturnWriteTarget(origFn)
						}
					}
				case types.FieldVal:
					if tv, ok := g.p.TypesInfo.Types[e.Fun]; ok && tv.Type != nil {
						forEachCallableSignature(tv.Type, func(sig *types.Signature) {
							appendTarget(g.dynReturnWriteID(sig))
							appendTargets(g.exprWriteThroughTargets(e.Fun))
						})
					}
				}
			} else if b, isBuiltin := g.p.TypesInfo.Uses[fun.Sel].(*types.Builtin); isBuiltin {
				appendBuiltinWriteThrough(b)
			} else if fn, ok := g.p.TypesInfo.Uses[fun.Sel].(*types.Func); ok && fn != nil {
				if g.isStdCallee(fn.Origin()) {
					for _, arg := range e.Args {
						appendTargets(g.exprWriteThroughTargets(arg))
					}
				} else {
					appendConcreteFuncReturnWriteTarget(fn)
				}
			} else if tv, ok := g.p.TypesInfo.Types[e.Fun]; ok && tv.Type != nil {
				forEachCallableSignature(tv.Type, func(sig *types.Signature) {
					appendTarget(g.dynReturnWriteID(sig))
					appendTargets(g.exprWriteThroughTargets(e.Fun))
				})
			}
		default:
			if tv, ok := g.p.TypesInfo.Types[e.Fun]; ok && tv.Type != nil {
				forEachCallableSignature(tv.Type, func(sig *types.Signature) {
					appendTarget(g.dynReturnWriteID(sig))
					appendTargets(g.exprWriteThroughTargets(e.Fun))
				})
			}
		}
	}
	if tv, ok := g.p.TypesInfo.Types[expr]; ok && tv.Type != nil && !tv.IsType() {
		appendYieldCallbackWriteHubs(tv.Type)
	}
	g.exprWTMemo[expr] = outTargets
	return outTargets
}

func (g *parGraph) methodRecvWriteTargets(recvExpr ast.Expr, isIface bool, origSig *types.Signature) []int {
	if recvExpr == nil {
		return nil
	}
	var outTargets []int
	appendTarget := func(id int) {
		if id < 0 {
			return
		}
		for _, ex := range outTargets {
			if ex == id {
				return
			}
		}
		outTargets = append(outTargets, id)
	}
	for _, wt := range g.exprWriteThroughTargets(recvExpr) {
		appendTarget(wt)
	}
	recvIsPtr := false
	if origSig != nil && origSig.Recv() != nil && origSig.Recv().Type() != nil {
		_, recvIsPtr = types.Unalias(origSig.Recv().Type()).(*types.Pointer)
	}
	if isIface || recvIsPtr {
		appendTarget(g.targetVarID(extractTargetVar(g.p.TypesInfo, recvExpr)))
	}
	return outTargets
}

func (g *parGraph) addrTargets(n ast.Node) []int {
	if n == nil {
		return nil
	}
	if cached, ok := g.addrTargetsMemo[n]; ok {
		return cached
	}
	var outTargets []int
	if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.AND {
		if tID := g.targetVarID(extractTargetVar(g.p.TypesInfo, u.X)); tID >= 0 {
			outTargets = append(outTargets, tID)
		}
		outTargets = append(outTargets, g.exprWriteThroughTargets(u.X)...)
	}
	ast.Inspect(n, func(child ast.Node) bool {
		if child == nil || child == n {
			return true
		}
		if sub := g.addrTargets(child); len(sub) > 0 {
			outTargets = append(outTargets, sub...)
		}
		return false
	})
	g.addrTargetsMemo[n] = outTargets
	return outTargets
}

