package seams

import (
	"go/ast"
	"go/types"
	"strconv"

	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func (g *parGraph) wireAllVarWritesAndCalls() {
	p := g.p

	linkArgWriteBack := func(arg ast.Expr, calleeWriteID int) {
		if calleeWriteID < 0 || arg == nil {
			return
		}
		for _, wt := range g.exprWriteThroughTargets(arg) {
			g.addParEdge(wt, calleeWriteID)
		}
	}

	callbackSigWithCarrierParam := func(arg ast.Expr) *types.Signature {
		if arg == nil {
			return nil
		}
		tv, ok := p.TypesInfo.Types[arg]
		if !ok || tv.Type == nil || tv.IsType() {
			return nil
		}
		var found *types.Signature
		forEachCallableSignature(tv.Type, func(cbSig *types.Signature) {
			if found != nil || cbSig.Params() == nil || cbSig.Params().Len() == 0 {
				return
			}
			for k := 0; k < cbSig.Params().Len(); k++ {
				if g.typeMayCarryParallel(cbSig.Params().At(k).Type()) {
					found = cbSig
					return
				}
			}
		})
		return found
	}

	wireCallbackArgFromSources := func(cbArg ast.Expr, cbSig *types.Signature, srcExprs []ast.Expr, srcWTs []int) {
		if cbArg == nil || cbSig == nil || cbSig.Params() == nil {
			return
		}
		var carrierSrcs []ast.Expr
		for _, src := range srcExprs {
			if src == nil || src == cbArg {
				continue
			}
			var st types.Type
			if stv, ok := p.TypesInfo.Types[src]; ok {
				st = stv.Type
			}
			if st == nil || g.typeMayCarryParallel(st) {
				carrierSrcs = append(carrierSrcs, src)
			}
		}
		if len(carrierSrcs) == 0 && len(srcWTs) == 0 {
			return
		}
		wireSlot := func(readID, writeID int, paramType types.Type) {
			if readID >= 0 && g.typeMayCarryParallel(paramType) {
				for _, src := range carrierSrcs {
					g.bindSubtree(readID, src)
				}
			}
			if writeID >= 0 && g.typeMayCarryMutableAlias(paramType) {
				for _, swt := range srcWTs {
					g.addParEdge(swt, writeID)
				}
			}
		}
		wireDynFallback := func() {
			for k := 0; k < cbSig.Params().Len(); k++ {
				pType := cbSig.Params().At(k).Type()
				wireSlot(g.dynHubID(cbSig, k), g.dynHubWriteID(cbSig, k), pType)
			}
		}
		wireFuncTarget := func(fn *types.Func) {
			if fn == nil || fn.Pkg() == nil {
				wireDynFallback()
				return
			}
			fn = fn.Origin()
			if g.allDecls[fn] != nil {
				for k := 0; k < cbSig.Params().Len(); k++ {
					wireSlot(g.paramID(fn, k), g.paramWriteID(fn, k), cbSig.Params().At(k).Type())
				}
				return
			}
			if (p.Types == nil || fn.Pkg() != p.Types) && !g.isStdCallee(fn) {
				if fk, ok := syntaxutil.CallableFactKey(fn); ok {
					for k := 0; k < cbSig.Params().Len(); k++ {
						pType := cbSig.Params().At(k).Type()
						readHub := -1
						if g.typeMayCarryParallel(pType) {
							readHub = g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#" + strconv.Itoa(k)})
						}
						writeHub := -1
						if g.typeMayCarryMutableAlias(pType) {
							writeHub = g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#w#" + strconv.Itoa(k)})
						}
						wireSlot(readHub, writeHub, pType)
					}
					return
				}
			}
			wireDynFallback()
		}
		if lit, ok := ast.Unparen(cbArg).(*ast.FuncLit); ok {
			if lit.Type != nil && lit.Type.Params != nil {
				pIdx := 0
				for _, field := range lit.Type.Params.List {
					if len(field.Names) == 0 {
						pIdx++
						continue
					}
					for _, name := range field.Names {
						if pIdx < cbSig.Params().Len() {
							if v, ok := g.isSamePkgNonFieldVar(p.TypesInfo.Defs[name]); ok {
								wireSlot(g.bindVarID(v), g.varWriteThroughID(v), cbSig.Params().At(pIdx).Type())
							}
						}
						pIdx++
					}
				}
			}
			return
		}
		switch cb := syntaxutil.UnwrapCallee(cbArg).(type) {
		case *ast.Ident:
			if fn, ok := p.TypesInfo.Uses[cb].(*types.Func); ok && fn != nil {
				wireFuncTarget(fn)
				return
			}
		case *ast.SelectorExpr:
			if selInfo, isSel := p.TypesInfo.Selections[cb]; isSel && selInfo != nil {
				fn, _ := selInfo.Obj().(*types.Func)
				var origFn *types.Func
				var origSig *types.Signature
				if fn != nil {
					origFn = fn.Origin()
					origSig, _ = origFn.Type().(*types.Signature)
				}
				isIface := isInterfaceMethodSelection(selInfo, origFn)
				switch selInfo.Kind() {
				case types.MethodVal:
					for _, rwt := range g.methodRecvWriteTargets(cb.X, isIface, origSig) {
						for _, src := range carrierSrcs {
							g.bindSubtree(rwt, src)
						}
						for _, swt := range srcWTs {
							g.addParEdge(swt, rwt)
						}
					}
					if isIface && origFn != nil {
						for k := 0; k < cbSig.Params().Len(); k++ {
							pType := cbSig.Params().At(k).Type()
							wireSlot(g.ifaceHubID(origFn.Name(), k), g.ifaceHubWriteID(origFn.Name(), k), pType)
						}
						return
					}
					if origFn != nil {
						wireFuncTarget(origFn)
						return
					}
				case types.MethodExpr:
					if cbSig.Params().Len() >= 1 && origFn != nil {
						recvType := cbSig.Params().At(0).Type()
						if isIface {
							wireSlot(g.ifaceRecvID(origFn.Name()), g.ifaceRecvWriteID(origFn.Name()), recvType)
							for k := 1; k < cbSig.Params().Len(); k++ {
								pType := cbSig.Params().At(k).Type()
								wireSlot(g.ifaceHubID(origFn.Name(), k-1), g.ifaceHubWriteID(origFn.Name(), k-1), pType)
							}
							return
						}
						if g.allDecls[origFn] != nil {
							wireSlot(g.recvID(origFn), g.recvWriteID(origFn), recvType)
							for k := 1; k < cbSig.Params().Len(); k++ {
								wireSlot(g.paramID(origFn, k-1), g.paramWriteID(origFn, k-1), cbSig.Params().At(k).Type())
							}
							return
						}
						if (p.Types == nil || origFn.Pkg() != p.Types) && !g.isStdCallee(origFn) {
							if fk, ok := syntaxutil.CallableFactKey(origFn); ok {
								recvRead := -1
								if g.typeMayCarryParallel(recvType) {
									recvRead = g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#recv"})
								}
								recvWrite := -1
								if g.typeMayCarryMutableAlias(recvType) {
									recvWrite = g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#wrecv"})
								}
								wireSlot(recvRead, recvWrite, recvType)
								for k := 1; k < cbSig.Params().Len(); k++ {
									pType := cbSig.Params().At(k).Type()
									readHub := -1
									if g.typeMayCarryParallel(pType) {
										readHub = g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#" + strconv.Itoa(k-1)})
									}
									writeHub := -1
									if g.typeMayCarryMutableAlias(pType) {
										writeHub = g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#w#" + strconv.Itoa(k-1)})
									}
									wireSlot(readHub, writeHub, pType)
								}
								return
							}
						}
					}
				}
			} else if fn, ok := p.TypesInfo.Uses[cb.Sel].(*types.Func); ok && fn != nil {
				wireFuncTarget(fn)
				return
			}
		}
		wireDynFallback()
	}

	wireCallSiteCallbacks := func(args []ast.Expr, extraSrcExprs []ast.Expr, extraWTs []int, lazyExtraWTExpr ast.Expr) {
		for argIdx, arg := range args {
			cbSig := callbackSigWithCarrierParam(arg)
			if cbSig == nil {
				continue
			}
			srcs := make([]ast.Expr, 0, len(extraSrcExprs)+len(args))
			srcs = append(srcs, extraSrcExprs...)
			wts := make([]int, 0, len(extraWTs)+len(args))
			wts = append(wts, extraWTs...)
			if lazyExtraWTExpr != nil {
				wts = append(wts, g.exprWriteThroughTargets(lazyExtraWTExpr)...)
			}
			for j, other := range args {
				if j == argIdx || other == nil {
					continue
				}
				srcs = append(srcs, other)
				wts = append(wts, g.exprWriteThroughTargets(other)...)
			}
			wireCallbackArgFromSources(arg, cbSig, srcs, wts)
		}
	}

	wireDynamicCallArgs := func(sig *types.Signature, args []ast.Expr, isEllipsis bool, funExpr ast.Expr) {
		if sig == nil || sig.Params() == nil {
			return
		}
		for argIdx, arg := range args {
			if pIdx, ok := sigParamIndexForArg(sig, argIdx, isEllipsis); ok && g.typeMayCarryParallel(sig.Params().At(pIdx).Type()) {
				g.bindSubtree(g.dynHubID(sig, pIdx), arg)
				if g.typeMayCarryMutableAlias(sig.Params().At(pIdx).Type()) {
					linkArgWriteBack(arg, g.dynHubWriteID(sig, pIdx))
				}
			}
		}
		var extraSrcs []ast.Expr
		if funExpr != nil {
			extraSrcs = []ast.Expr{funExpr}
		}
		wireCallSiteCallbacks(args, extraSrcs, nil, funExpr)
	}

	wireInterfaceCallArgs := func(methodName string, sig *types.Signature, args []ast.Expr, isEllipsis bool, recvExpr ast.Expr, recvWTs []int) {
		if methodName == "" || sig == nil || sig.Params() == nil {
			return
		}
		for argIdx, arg := range args {
			if pIdx, ok := sigParamIndexForArg(sig, argIdx, isEllipsis); ok && g.typeMayCarryParallel(sig.Params().At(pIdx).Type()) {
				g.bindSubtree(g.ifaceHubID(methodName, pIdx), arg)
				if g.typeMayCarryMutableAlias(sig.Params().At(pIdx).Type()) {
					linkArgWriteBack(arg, g.ifaceHubWriteID(methodName, pIdx))
				}
			}
		}
		var extraSrcs []ast.Expr
		if recvExpr != nil {
			extraSrcs = []ast.Expr{recvExpr}
		}
		wireCallSiteCallbacks(args, extraSrcs, recvWTs, nil)
	}

	wireConcreteFuncArgs := func(callee *types.Func, args []ast.Expr, isEllipsis bool) {
		if callee == nil || callee.Pkg() == nil {
			return
		}
		callee = callee.Origin()
		sig, ok := callee.Type().(*types.Signature)
		if !ok || sig == nil || sig.Params() == nil {
			return
		}
		if g.allDecls[callee] != nil {
			for argIdx, arg := range args {
				if pIdx, ok := sigParamIndexForArg(sig, argIdx, isEllipsis); ok {
					g.bindSubtree(g.paramID(callee, pIdx), arg)
					linkArgWriteBack(arg, g.paramWriteID(callee, pIdx))
				}
			}
			return
		}
		if (p.Types == nil || callee.Pkg() != p.Types) && !g.isStdCallee(callee) {
			baseKey, ok := syntaxutil.CallableFactKey(callee)
			if !ok {
				return
			}
			for argIdx, arg := range args {
				if pIdx, ok := sigParamIndexForArg(sig, argIdx, isEllipsis); ok && g.typeMayCarryParallel(sig.Params().At(pIdx).Type()) {
					paramKey := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#" + strconv.Itoa(pIdx)}
					g.bindSubtree(g.crossID(paramKey), arg)
					if g.typeMayCarryMutableAlias(sig.Params().At(pIdx).Type()) {
						paramWriteKey := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#w#" + strconv.Itoa(pIdx)}
						linkArgWriteBack(arg, g.crossID(paramWriteKey))
					}
				}
			}
			return
		}
		if g.isStdCallee(callee) && len(args) >= 2 {
			wireCallSiteCallbacks(args, nil, nil, nil)
			for argIdx, arg := range args {
				pIdx, ok := sigParamIndexForArg(sig, argIdx, isEllipsis)
				if !ok {
					continue
				}
				paramType := sig.Params().At(pIdx).Type()
				if sig.Variadic() && pIdx == sig.Params().Len()-1 && !isEllipsis {
					if sl, ok := paramType.(*types.Slice); ok {
						paramType = sl.Elem()
					}
				}
				if !g.stdParamMayAcceptCarrierWrite(paramType) {
					continue
				}
				wts := g.exprWriteThroughTargets(arg)
				if len(wts) == 0 {
					continue
				}
				for j, other := range args {
					if j == argIdx {
						continue
					}
					var otherType types.Type
					if tv, ok := p.TypesInfo.Types[other]; ok {
						otherType = tv.Type
					}
					if otherType == nil || g.typeMayCarryParallel(otherType) {
						for _, wt := range wts {
							g.bindSubtree(wt, other)
						}
						for _, rwt := range g.exprWriteThroughTargets(other) {
							for _, wt := range wts {
								g.addParEdge(rwt, wt)
							}
						}
					}
				}
			}
		}
	}

	wireNonBareWrite := func(lhs, rhs ast.Expr) {
		rhsWTs := g.exprWriteThroughTargets(rhs)
		if tID := g.targetVarID(extractTargetVar(p.TypesInfo, lhs)); tID >= 0 {
			g.bindSubtree(tID, rhs)
			for _, rwt := range rhsWTs {
				g.addParEdge(rwt, tID)
			}
		}
		for _, wt := range g.exprWriteThroughTargets(lhs) {
			g.bindSubtree(wt, rhs)
			for _, rwt := range rhsWTs {
				g.addParEdge(rwt, wt)
			}
		}
	}

	isBuiltinCall := func(n ast.Node, name string) (*ast.CallExpr, bool) {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return nil, false
		}
		ident, ok := syntaxutil.UnwrapCallee(call.Fun).(*ast.Ident)
		if !ok || ident.Name != name {
			return nil, false
		}
		_, isBuiltin := p.TypesInfo.Uses[ident].(*types.Builtin)
		return call, isBuiltin
	}

	expandCallArgs := func(args []ast.Expr, isEllipsis bool) []ast.Expr {
		if len(args) != 1 || isEllipsis {
			return args
		}
		tv, ok := p.TypesInfo.Types[args[0]]
		if !ok || tv.Type == nil {
			return args
		}
		tup, ok := tv.Type.(*types.Tuple)
		if !ok || tup.Len() <= 1 {
			return args
		}
		expanded := make([]ast.Expr, tup.Len())
		for i := range expanded {
			expanded[i] = args[0]
		}
		return expanded
	}

	wireStdMethodArgWritesFromRecv := func(origFn *types.Func, args []ast.Expr, isEllipsis bool, recvExpr ast.Expr, recvWTs []int) {
		if origFn == nil || !g.isStdCallee(origFn) || len(args) == 0 || recvExpr == nil {
			return
		}
		sig, ok := origFn.Origin().Type().(*types.Signature)
		if !ok || sig == nil || sig.Params() == nil {
			return
		}
		var recvType types.Type
		if tv, ok := p.TypesInfo.Types[recvExpr]; ok {
			recvType = tv.Type
		}
		recvMayCarry := recvType == nil || g.typeMayCarryParallel(recvType)
		var recvSrcs []ast.Expr
		if recvMayCarry {
			recvSrcs = []ast.Expr{recvExpr}
		}
		wireCallSiteCallbacks(args, recvSrcs, recvWTs, nil)
		if !recvMayCarry {
			return
		}
		for argIdx, arg := range args {
			pIdx, ok := sigParamIndexForArg(sig, argIdx, isEllipsis)
			if !ok {
				continue
			}
			paramType := sig.Params().At(pIdx).Type()
			if sig.Variadic() && pIdx == sig.Params().Len()-1 && !isEllipsis {
				if sl, ok := paramType.(*types.Slice); ok {
					paramType = sl.Elem()
				}
			}
			if !g.stdParamMayAcceptCarrierWrite(paramType) {
				continue
			}
			for _, wt := range g.exprWriteThroughTargets(arg) {
				g.bindSubtree(wt, recvExpr)
				for _, rwt := range recvWTs {
					g.addParEdge(rwt, wt)
				}
			}
		}
	}

	seedVarWrites := func(root ast.Node) {
		if root == nil {
			return
		}
		ast.Inspect(root, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			if vs, ok := n.(*ast.ValueSpec); ok && vs.Type != nil {
				for _, name := range vs.Names {
					if tID := g.targetVarID(extractTargetVar(p.TypesInfo, name)); tID >= 0 {
						g.bindSubtree(tID, vs.Type)
					}
				}
			}
			_, isCopy := isBuiltinCall(n, "copy")
			syntaxutil.EachLocalBinding(p.TypesInfo, n, func(lhs, rhs ast.Expr) {
				if g.isBareVarExpr(lhs) && !isCopy {
					lhsVar := extractTargetVar(p.TypesInfo, lhs)
					if lhsID := g.targetVarID(lhsVar); lhsID >= 0 {
						g.bindSubtree(lhsID, rhs)
					}
					if lhsWT := g.targetVarWriteThroughID(lhsVar); lhsWT >= 0 {
						for _, rwt := range g.exprWriteThroughTargets(rhs) {
							g.addParEdge(rwt, lhsWT)
						}
					}
					return
				}
				wireNonBareWrite(lhs, rhs)
			})
			switch node := n.(type) {
			case *ast.TypeSwitchStmt:
				if assign, ok := node.Assign.(*ast.AssignStmt); ok && len(assign.Rhs) == 1 && node.Body != nil {
					if ta, ok := ast.Unparen(assign.Rhs[0]).(*ast.TypeAssertExpr); ok && ta.X != nil {
						rhsWTs := g.exprWriteThroughTargets(ta.X)
						for _, stmt := range node.Body.List {
							cc, ok := stmt.(*ast.CaseClause)
							if !ok {
								continue
							}
							impVar, ok := g.isSamePkgNonFieldVar(p.TypesInfo.Implicits[cc])
							if !ok {
								continue
							}
							if impID := g.bindVarID(impVar); impID >= 0 {
								g.bindSubtree(impID, ta.X)
							}
							if impWT := g.varWriteThroughID(impVar); impWT >= 0 {
								for _, rwt := range rhsWTs {
									g.addParEdge(rwt, impWT)
								}
							}
						}
					}
				}
			case *ast.RangeStmt:
				if node.X != nil {
					if tv, ok := p.TypesInfo.Types[node.X]; ok && tv.Type != nil {
						forEachCallableSignature(tv.Type, func(seqSig *types.Signature) {
							if seqSig.Params() == nil || seqSig.Params().Len() != 1 {
								return
							}
							forEachCallableSignature(seqSig.Params().At(0).Type(), func(yieldSig *types.Signature) {
								if yieldSig.Params() == nil {
									return
								}
								for slotIdx, bindExpr := range []ast.Expr{node.Key, node.Value} {
									if bindExpr == nil || slotIdx >= yieldSig.Params().Len() {
										continue
									}
									yhID := g.dynHubID(yieldSig, slotIdx)
									yhwID := g.dynHubWriteID(yieldSig, slotIdx)
									mayAlias := g.typeMayCarryMutableAlias(yieldSig.Params().At(slotIdx).Type())
									if g.isBareVarExpr(bindExpr) {
										kvVar := extractTargetVar(p.TypesInfo, bindExpr)
										g.addParEdge(g.targetVarID(kvVar), yhID)
										if mayAlias {
											g.addParEdge(yhwID, g.targetVarWriteThroughID(kvVar))
										}
									} else {
										tID := g.targetVarID(extractTargetVar(p.TypesInfo, bindExpr))
										g.addParEdge(tID, yhID)
										if mayAlias {
											g.addParEdge(yhwID, tID)
										}
										for _, wt := range g.exprWriteThroughTargets(bindExpr) {
											g.addParEdge(wt, yhID)
											if mayAlias {
												g.addParEdge(yhwID, wt)
											}
										}
									}
								}
							})
						})
					}
				}
			case *ast.SendStmt:
				wireNonBareWrite(node.Chan, node.Value)
			case *ast.CallExpr:
				if tv, isType := p.TypesInfo.Types[node.Fun]; isType && tv.IsType() {
					return true
				}
				isEllipsis := node.Ellipsis.IsValid()
				callArgs := expandCallArgs(node.Args, isEllipsis)
				if copyCall, isCp := isBuiltinCall(node, "copy"); isCp {
					if len(copyCall.Args) == 1 && len(callArgs) == 2 {
						wireNonBareWrite(callArgs[0], callArgs[1])
					}
					return true
				}
				if _, isApp := isBuiltinCall(node, "append"); isApp {
					if len(callArgs) >= 2 {
						for _, elem := range callArgs[1:] {
							wireNonBareWrite(callArgs[0], elem)
						}
					}
					return true
				}
				// Address-taken expressions (&v) in Fun or Args can be written by the callee from sibling inputs.
				allCallInputsID := -1
				ensureAllCallInputs := func() int {
					if allCallInputsID < 0 {
						allCallInputsID = g.newNode()
						g.bindSubtree(allCallInputsID, node.Fun)
						for _, other := range node.Args {
							g.bindSubtree(allCallInputsID, other)
						}
					}
					return allCallInputsID
				}
				if funTargets := g.addrTargets(node.Fun); len(funTargets) > 0 {
					inID := ensureAllCallInputs()
					for _, tID := range funTargets {
						g.addParEdge(tID, inID)
					}
				}
				for _, arg := range node.Args {
					targets := g.addrTargets(arg)
					if len(targets) == 0 {
						continue
					}
					inID := ensureAllCallInputs()
					for _, tID := range targets {
						g.addParEdge(tID, inID)
					}
				}
				switch fun := syntaxutil.UnwrapCallee(node.Fun).(type) {
				case *ast.Ident:
					if fn, ok := p.TypesInfo.Uses[fun].(*types.Func); ok && fn != nil {
						wireConcreteFuncArgs(fn, callArgs, isEllipsis)
					} else if tv, ok := p.TypesInfo.Types[node.Fun]; ok && tv.Type != nil {
						forEachCallableSignature(tv.Type, func(sig *types.Signature) {
							wireDynamicCallArgs(sig, callArgs, isEllipsis, node.Fun)
						})
					}
				case *ast.SelectorExpr:
					if selInfo, isSel := p.TypesInfo.Selections[fun]; isSel && selInfo != nil {
						switch selInfo.Kind() {
						case types.MethodVal:
							fn, _ := selInfo.Obj().(*types.Func)
							var origFn *types.Func
							var origSig *types.Signature
							if fn != nil {
								origFn = fn.Origin()
								origSig, _ = origFn.Type().(*types.Signature)
							}
							isIface := isInterfaceMethodSelection(selInfo, origFn)
							recvWTs := g.methodRecvWriteTargets(fun.X, isIface, origSig)
							for _, arg := range callArgs {
								for _, rwt := range recvWTs {
									g.bindSubtree(rwt, arg)
									for _, awt := range g.exprWriteThroughTargets(arg) {
										g.addParEdge(awt, rwt)
									}
								}
							}
							sig, _ := selInfo.Type().Underlying().(*types.Signature)
							if isIface {
								if origFn != nil {
									g.bindSubtree(g.ifaceRecvID(origFn.Name()), fun.X)
									irw := g.ifaceRecvWriteID(origFn.Name())
									for _, rwt := range recvWTs {
										g.addParEdge(rwt, irw)
									}
									wireInterfaceCallArgs(origFn.Name(), sig, callArgs, isEllipsis, fun.X, recvWTs)
								}
							} else if origFn != nil {
								if g.allDecls[origFn] != nil {
									g.bindSubtree(g.recvID(origFn), fun.X)
									rwRecv := g.recvWriteID(origFn)
									for _, rwt := range recvWTs {
										g.addParEdge(rwt, rwRecv)
									}
								} else if (p.Types == nil || origFn.Pkg() != p.Types) && !g.isStdCallee(origFn) {
									if fk, ok := syntaxutil.CallableFactKey(origFn); ok {
										if origSig != nil && origSig.Recv() != nil && g.typeMayCarryParallel(origSig.Recv().Type()) {
											g.bindSubtree(g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#recv"}), fun.X)
										}
										if origSig != nil && origSig.Recv() != nil && g.typeMayCarryMutableAlias(origSig.Recv().Type()) {
											crw := g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#wrecv"})
											for _, rwt := range recvWTs {
												g.addParEdge(rwt, crw)
											}
										}
									}
								} else if g.isStdCallee(origFn) {
									wireStdMethodArgWritesFromRecv(origFn, callArgs, isEllipsis, fun.X, recvWTs)
								}
								wireConcreteFuncArgs(origFn, callArgs, isEllipsis)
							}
						case types.MethodExpr:
							if len(callArgs) >= 1 {
								fn, _ := selInfo.Obj().(*types.Func)
								var origFn *types.Func
								var origSig *types.Signature
								if fn != nil {
									origFn = fn.Origin()
									origSig, _ = origFn.Type().(*types.Signature)
								}
								isIface := isInterfaceMethodSelection(selInfo, origFn)
								recvWTs := g.methodRecvWriteTargets(callArgs[0], isIface, origSig)
								for _, arg := range callArgs[1:] {
									for _, rwt := range recvWTs {
										g.bindSubtree(rwt, arg)
										for _, awt := range g.exprWriteThroughTargets(arg) {
											g.addParEdge(awt, rwt)
										}
									}
								}
								if origFn != nil {
									if isIface {
										g.bindSubtree(g.ifaceRecvID(origFn.Name()), callArgs[0])
										irw := g.ifaceRecvWriteID(origFn.Name())
										for _, rwt := range recvWTs {
											g.addParEdge(rwt, irw)
										}
										wireInterfaceCallArgs(origFn.Name(), origSig, callArgs[1:], isEllipsis, callArgs[0], recvWTs)
									} else {
										if g.allDecls[origFn] != nil {
											g.bindSubtree(g.recvID(origFn), callArgs[0])
											rwRecv := g.recvWriteID(origFn)
											for _, rwt := range recvWTs {
												g.addParEdge(rwt, rwRecv)
											}
										} else if (p.Types == nil || origFn.Pkg() != p.Types) && !g.isStdCallee(origFn) {
											if fk, ok := syntaxutil.CallableFactKey(origFn); ok {
												if origSig != nil && origSig.Recv() != nil && g.typeMayCarryParallel(origSig.Recv().Type()) {
													g.bindSubtree(g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#recv"}), callArgs[0])
												}
												if origSig != nil && origSig.Recv() != nil && g.typeMayCarryMutableAlias(origSig.Recv().Type()) {
													crw := g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#wrecv"})
													for _, rwt := range recvWTs {
														g.addParEdge(rwt, crw)
													}
												}
											}
										} else if g.isStdCallee(origFn) {
											wireStdMethodArgWritesFromRecv(origFn, callArgs[1:], isEllipsis, callArgs[0], recvWTs)
										}
										wireConcreteFuncArgs(origFn, callArgs[1:], isEllipsis)
									}
								}
							}
						case types.FieldVal:
							if tv, ok := p.TypesInfo.Types[node.Fun]; ok && tv.Type != nil {
								forEachCallableSignature(tv.Type, func(sig *types.Signature) {
									wireDynamicCallArgs(sig, callArgs, isEllipsis, node.Fun)
								})
							}
						}
					} else if fn, ok := p.TypesInfo.Uses[fun.Sel].(*types.Func); ok && fn != nil {
						wireConcreteFuncArgs(fn, callArgs, isEllipsis)
					} else if tv, ok := p.TypesInfo.Types[node.Fun]; ok && tv.Type != nil {
						forEachCallableSignature(tv.Type, func(sig *types.Signature) {
							wireDynamicCallArgs(sig, callArgs, isEllipsis, node.Fun)
						})
					}
				case *ast.FuncLit:
					if fun.Type != nil && fun.Type.Params != nil {
						if tv, ok := p.TypesInfo.Types[fun]; ok && tv.Type != nil {
							if sig, ok := tv.Type.Underlying().(*types.Signature); ok {
								var paramVars []*types.Var
								for _, field := range fun.Type.Params.List {
									if len(field.Names) == 0 {
										paramVars = append(paramVars, nil)
										continue
									}
									for _, name := range field.Names {
										v, _ := g.isSamePkgNonFieldVar(p.TypesInfo.Defs[name])
										paramVars = append(paramVars, v)
									}
								}
								for argIdx, arg := range callArgs {
									if pIdx, ok := sigParamIndexForArg(sig, argIdx, isEllipsis); ok && pIdx < len(paramVars) && paramVars[pIdx] != nil {
										g.bindSubtree(g.bindVarID(paramVars[pIdx]), arg)
										linkArgWriteBack(arg, g.varWriteThroughID(paramVars[pIdx]))
									}
								}
							}
						}
					}
				default:
					if tv, ok := p.TypesInfo.Types[node.Fun]; ok && tv.Type != nil {
						forEachCallableSignature(tv.Type, func(sig *types.Signature) {
							wireDynamicCallArgs(sig, callArgs, isEllipsis, node.Fun)
						})
					}
				}
			}
			return true
		})
	}

	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				seedVarWrites(d)
			case *ast.FuncDecl:
				if d.Body != nil {
					seedVarWrites(d.Body)
				}
			}
		}
	}
}
