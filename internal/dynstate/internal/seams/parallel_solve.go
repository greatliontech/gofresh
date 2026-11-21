package seams

import (
	"go/ast"
	"go/types"
	"slices"
	"strconv"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (g *parGraph) buildAndSolve(out *callGraph) {
	p := g.p
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if tv, isType := p.TypesInfo.Types[call.Fun]; isType && tv.IsType() {
				return true
			}
			if lit, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
				g.directCallFuncLits[lit] = true
				return true
			}
			switch fun := syntaxutil.UnwrapCallee(call.Fun).(type) {
			case *ast.Ident:
				g.anyDirectCalleeIdent[fun] = true
			case *ast.SelectorExpr:
				g.anyDirectCalleeIdent[fun.Sel] = true
			}
			return true
		})
	}

	seenStdValueFuncs := map[stdValueFunc]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || g.anyDirectCalleeIdent[id] {
				return true
			}
			useFn, ok := p.TypesInfo.Uses[id].(*types.Func)
			if !ok || useFn == nil || useFn.Pkg() == nil {
				return true
			}
			fn := useFn.Origin()
			if g.allDecls[fn] != nil {
				if sig, ok := fn.Type().(*types.Signature); ok && sig != nil && sig.Recv() == nil {
					g.valueTakenDeclFuncs[fn] = true
				}
			} else if (p.Types == nil || fn.Pkg() != p.Types) && !g.isStdCallee(fn) {
				if sig, ok := fn.Type().(*types.Signature); ok && sig != nil && sig.Recv() == nil {
					if fk, ok := syntaxutil.CallableFactKey(fn); ok {
						g.valueTakenCrossSigs[fk] = sig
					}
				}
			} else if g.isStdCallee(fn) {
				if origSig, ok := fn.Type().(*types.Signature); ok && origSig != nil && origSig.Recv() == nil {
					var instSig *types.Signature
					if inst, hasInst := p.TypesInfo.Instances[id]; hasInst && inst.Type != nil {
						instSig, _ = inst.Type.Underlying().(*types.Signature)
					}
					if instSig == nil {
						instSig, _ = useFn.Type().Underlying().(*types.Signature)
					}
					if instSig != nil {
						sv := stdValueFunc{origSig: origSig, instSig: instSig}
						if !seenStdValueFuncs[sv] {
							seenStdValueFuncs[sv] = true
							g.valueTakenStdFuncs = append(g.valueTakenStdFuncs, sv)
						}
					}
				}
			}
			return true
		})
	}

	for fn := range g.allDecls {
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig == nil {
			continue
		}
		if sig.TypeParams() != nil {
			for i := 0; i < sig.TypeParams().Len(); i++ {
				_ = g.typeParamID(fn, i)
			}
		}
		if sig.RecvTypeParams() != nil && sig.RecvTypeParams().Len() > 0 {
			g.hasGenericRecvDeclFunc = true
			for i := 0; i < sig.RecvTypeParams().Len(); i++ {
				_ = g.recvTypeParamID(fn, i)
			}
		}
	}

	for ident, inst := range p.TypesInfo.Instances {
		if inst.TypeArgs == nil {
			continue
		}
		useFn, ok := p.TypesInfo.Uses[ident].(*types.Func)
		if !ok || useFn == nil {
			continue
		}
		origFn := useFn.Origin()
		origSig, ok := origFn.Type().(*types.Signature)
		if !ok || origSig == nil || origSig.Recv() != nil || origSig.TypeParams() == nil {
			continue
		}
		nTP := min(inst.TypeArgs.Len(), origSig.TypeParams().Len())
		if g.allDecls[origFn] != nil {
			for i := range nTP {
				g.wireTypeArg(g.typeParamID(origFn, i), inst.TypeArgs.At(i))
			}
		} else if (p.Types == nil || origFn.Pkg() != p.Types) && !g.isStdCallee(origFn) {
			if baseKey, ok := syntaxutil.CallableFactKey(origFn); ok {
				for i := range nTP {
					tpKey := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#tp#" + strconv.Itoa(i)}
					g.wireTypeArg(g.crossID(tpKey), inst.TypeArgs.At(i))
				}
			}
		}
	}

	seenInstTypes := map[types.Type]bool{}
	var wireInstantiatedNamedTypes func(types.Type)
	wireInstantiatedNamedTypes = func(t types.Type) {
		if t == nil {
			return
		}
		if _, isBasic := t.(*types.Basic); isBasic {
			return
		}
		if seenInstTypes[t] {
			return
		}
		seenInstTypes[t] = true
		switch u := t.(type) {
		case *types.Alias:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					wireInstantiatedNamedTypes(targs.At(i))
				}
			}
			wireInstantiatedNamedTypes(types.Unalias(u))
		case *types.Named:
			targs := u.TypeArgs()
			if targs != nil {
				for i := 0; i < targs.Len(); i++ {
					wireInstantiatedNamedTypes(targs.At(i))
				}
			}
			origNamed := u.Origin()
			if targs != nil && targs.Len() > 0 && origNamed != nil && origNamed.Obj() != nil && origNamed.Obj().Pkg() != nil &&
				(origNamed.Obj().Pkg() == p.Types || !g.isStdPkg(origNamed.Obj().Pkg())) {
				for mi := 0; mi < origNamed.NumMethods(); mi++ {
					m := origNamed.Method(mi)
					if m == nil || m.Pkg() == nil {
						continue
					}
					m = m.Origin()
					mSig, ok := m.Type().(*types.Signature)
					if !ok || mSig == nil || mSig.RecvTypeParams() == nil {
						continue
					}
					nRTP := min(targs.Len(), mSig.RecvTypeParams().Len())
					if g.allDecls[m] != nil {
						for ti := range nRTP {
							g.wireTypeArg(g.recvTypeParamID(m, ti), targs.At(ti))
						}
					} else if (p.Types == nil || m.Pkg() != p.Types) && !g.isStdCallee(m) {
						if baseKey, ok := syntaxutil.CallableFactKey(m); ok {
							for ti := range nRTP {
								rtpKey := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#rtp#" + strconv.Itoa(ti)}
								g.wireTypeArg(g.crossID(rtpKey), targs.At(ti))
							}
						}
					}
				}
			}
			if origNamed != nil && origNamed.Obj() != nil && origNamed.Obj().Pkg() != nil && origNamed.Obj().Pkg() != p.Types && g.isStdPkg(origNamed.Obj().Pkg()) {
				return
			}
			wireInstantiatedNamedTypes(u.Underlying())
		case *types.Pointer:
			wireInstantiatedNamedTypes(u.Elem())
		case *types.Slice:
			wireInstantiatedNamedTypes(u.Elem())
		case *types.Array:
			wireInstantiatedNamedTypes(u.Elem())
		case *types.Chan:
			wireInstantiatedNamedTypes(u.Elem())
		case *types.Map:
			wireInstantiatedNamedTypes(u.Key())
			wireInstantiatedNamedTypes(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				wireInstantiatedNamedTypes(u.Field(i).Type())
			}
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				wireInstantiatedNamedTypes(u.At(i).Type())
			}
		case *types.Signature:
			if u.Recv() != nil {
				wireInstantiatedNamedTypes(u.Recv().Type())
			}
			wireInstantiatedNamedTypes(u.Params())
			wireInstantiatedNamedTypes(u.Results())
		case *types.Interface:
			for i := 0; i < u.NumExplicitMethods(); i++ {
				wireInstantiatedNamedTypes(u.ExplicitMethod(i).Type())
			}
			for i := 0; i < u.NumEmbeddeds(); i++ {
				wireInstantiatedNamedTypes(u.EmbeddedType(i))
			}
		case *types.TypeParam:
			wireInstantiatedNamedTypes(u.Constraint())
		case *types.Union:
			for i := 0; i < u.Len(); i++ {
				if term := u.Term(i); term != nil {
					wireInstantiatedNamedTypes(term.Type())
				}
			}
		}
	}
	if len(p.TypesInfo.Instances) > 0 || g.hasGenericRecvDeclFunc {
		for _, tv := range p.TypesInfo.Types {
			wireInstantiatedNamedTypes(tv.Type)
		}
		for _, obj := range p.TypesInfo.Defs {
			if obj != nil {
				wireInstantiatedNamedTypes(obj.Type())
			}
		}
		for _, obj := range p.TypesInfo.Uses {
			if obj != nil {
				wireInstantiatedNamedTypes(obj.Type())
			}
		}
		for _, inst := range p.TypesInfo.Instances {
			wireInstantiatedNamedTypes(inst.Type)
			if inst.TypeArgs != nil {
				for i := 0; i < inst.TypeArgs.Len(); i++ {
					wireInstantiatedNamedTypes(inst.TypeArgs.At(i))
				}
			}
		}
		for _, obj := range p.TypesInfo.Implicits {
			if obj != nil {
				wireInstantiatedNamedTypes(obj.Type())
			}
		}
	} else {
		// Even without explicit syntax Instances in p, an imported non-std
		// symbol used in p could reference an already-instantiated generic
		// receiver type, so walk Uses/Defs/Implicits only.
		for _, obj := range p.TypesInfo.Defs {
			if obj != nil {
				wireInstantiatedNamedTypes(obj.Type())
			}
		}
		for _, obj := range p.TypesInfo.Uses {
			if obj != nil {
				wireInstantiatedNamedTypes(obj.Type())
			}
		}
		for _, obj := range p.TypesInfo.Implicits {
			if obj != nil {
				wireInstantiatedNamedTypes(obj.Type())
			}
		}
	}

	wireReturnBody := func(rID, rwID int, body *ast.BlockStmt) {
		if body == nil || (rID < 0 && rwID < 0) {
			return
		}
		var walkRet func(ast.Node)
		walkRet = func(n ast.Node) {
			if n == nil {
				return
			}
			switch node := n.(type) {
			case *ast.FuncLit:
				return
			case *ast.ReturnStmt:
				for _, resExpr := range node.Results {
					if rID >= 0 {
						g.bindSubtree(rID, resExpr)
					}
					if rwID >= 0 {
						for _, wt := range g.exprWriteThroughTargets(resExpr) {
							g.addParEdge(wt, rwID)
						}
					}
				}
				return
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if child == nil || child == n {
					return true
				}
				walkRet(child)
				return false
			})
		}
		walkRet(body)
	}

	for fn, fd := range g.allDecls {
		_ = g.execFuncID(fn)
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig == nil {
			continue
		}
		if fd.Recv != nil {
			for _, field := range fd.Recv.List {
				for _, name := range field.Names {
					if v, ok := g.isSamePkgNonFieldVar(p.TypesInfo.Defs[name]); ok {
						g.addParEdge(g.bindVarID(v), g.recvID(fn))
						if rwRecv := g.recvWriteID(fn); rwRecv >= 0 {
							g.varWriteThroughIDs[v] = rwRecv
							g.addParEdge(g.bindVarID(v), rwRecv)
						}
					}
				}
			}
		}
		if fd.Type != nil && fd.Type.Params != nil {
			pIdx := 0
			for _, field := range fd.Type.Params.List {
				if len(field.Names) == 0 {
					pIdx++
					continue
				}
				for _, name := range field.Names {
					if v, ok := g.isSamePkgNonFieldVar(p.TypesInfo.Defs[name]); ok {
						g.addParEdge(g.bindVarID(v), g.paramID(fn, pIdx))
						if pwID := g.paramWriteID(fn, pIdx); pwID >= 0 {
							g.varWriteThroughIDs[v] = pwID
							g.addParEdge(g.bindVarID(v), pwID)
						}
					}
					pIdx++
				}
			}
		}
		rID := g.returnID(fn)
		rwID := g.returnWriteID(fn)
		if fd.Type != nil && fd.Type.Results != nil {
			for _, field := range fd.Type.Results.List {
				for _, name := range field.Names {
					if v, ok := g.isSamePkgNonFieldVar(p.TypesInfo.Defs[name]); ok {
						g.addParEdge(rID, g.bindVarID(v))
						if rwID >= 0 {
							g.addParEdge(g.varWriteThroughID(v), rwID)
						}
					}
				}
			}
		}
		wireReturnBody(rID, rwID, fd.Body)
		if sig.Recv() != nil {
			g.addParEdge(g.recvID(fn), g.ifaceRecvID(fn.Name()))
			g.addParEdge(g.ifaceRecvWriteID(fn.Name()), g.recvWriteID(fn))
			g.addParEdge(rwID, g.ifaceReturnWriteID(fn.Name(), sig))
		}
		if g.valueTakenDeclFuncs[fn] {
			g.addParEdge(rwID, g.dynReturnWriteID(sig))
		}
		if sig.Params() != nil {
			for i := 0; i < sig.Params().Len(); i++ {
				pID := g.paramID(fn, i)
				if pID < 0 {
					continue
				}
				pwID := g.paramWriteID(fn, i)
				if sig.Recv() != nil {
					g.addParEdge(pID, g.ifaceHubID(fn.Name(), i))
					g.addParEdge(g.ifaceHubWriteID(fn.Name(), i), pwID)
				}
				if g.valueTakenDeclFuncs[fn] {
					g.addParEdge(pID, g.dynHubID(sig, i))
					g.addParEdge(g.dynHubWriteID(sig, i), pwID)
				}
			}
		}
	}

	for fk, sig := range g.valueTakenCrossSigs {
		if g.funcMayReturnMutableAlias(sig) {
			g.addParEdge(g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#rw"}), g.dynReturnWriteID(sig))
		}
		if sig.Params() == nil {
			continue
		}
		for i := 0; i < sig.Params().Len(); i++ {
			if !g.typeMayCarryParallel(sig.Params().At(i).Type()) {
				continue
			}
			crossParam := g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#" + strconv.Itoa(i)})
			g.addParEdge(crossParam, g.dynHubID(sig, i))
			if g.typeMayCarryMutableAlias(sig.Params().At(i).Type()) {
				crossParamWrite := g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#w#" + strconv.Itoa(i)})
				g.addParEdge(g.dynHubWriteID(sig, i), crossParamWrite)
			}
		}
	}

	wireStdValueDynamicHubs := func(origSig, instSig *types.Signature, paramShift int, extraAliasSources []int, recvExpr ast.Expr) {
		if instSig == nil {
			return
		}
		nInst := 0
		if instSig.Params() != nil {
			nInst = instSig.Params().Len()
		}
		if drw := g.dynReturnWriteID(instSig); drw >= 0 {
			for _, rwt := range extraAliasSources {
				g.addParEdge(rwt, drw)
			}
			for i := range nInst {
				if g.typeMayCarryMutableAlias(instSig.Params().At(i).Type()) {
					g.addParEdge(g.dynHubWriteID(instSig, i), drw)
				}
			}
		}
		if origSig == nil || origSig.Params() == nil {
			return
		}
		for i := paramShift; i < nInst; i++ {
			instParamType := instSig.Params().At(i).Type()
			forEachCallableSignature(instParamType, func(cbSig *types.Signature) {
				if cbSig.Params() == nil {
					return
				}
				for k := 0; k < cbSig.Params().Len(); k++ {
					cbParamType := cbSig.Params().At(k).Type()
					if !g.typeMayCarryParallel(cbParamType) {
						continue
					}
					for j := range nInst {
						if j == i {
							continue
						}
						jType := instSig.Params().At(j).Type()
						if g.typeMayCarryParallel(jType) {
							g.addParEdge(g.dynHubID(cbSig, k), g.dynHubID(instSig, j))
						}
						if g.typeMayCarryMutableAlias(cbParamType) && g.typeMayCarryMutableAlias(jType) {
							g.addParEdge(g.dynHubWriteID(instSig, j), g.dynHubWriteID(cbSig, k))
						}
					}
				}
			})
			origIdx := i - paramShift
			if origIdx < 0 || origIdx >= origSig.Params().Len() {
				continue
			}
			origParamType := origSig.Params().At(origIdx).Type()
			if origSig.Variadic() && origIdx == origSig.Params().Len()-1 {
				if sl, ok := origParamType.(*types.Slice); ok {
					origParamType = sl.Elem()
				}
			}
			if !g.stdParamMayAcceptCarrierWrite(origParamType) || !g.typeMayCarryMutableAlias(instParamType) {
				continue
			}
			dhw := g.dynHubWriteID(instSig, i)
			if recvExpr != nil {
				g.bindSubtree(dhw, recvExpr)
			}
			for j := range nInst {
				if j == i {
					continue
				}
				if g.typeMayCarryParallel(instSig.Params().At(j).Type()) {
					g.addParEdge(dhw, g.dynHubID(instSig, j))
				}
			}
		}
	}
	for _, sv := range g.valueTakenStdFuncs {
		wireStdValueDynamicHubs(sv.origSig, sv.instSig, 0, nil, nil)
	}
	if p.Types != nil {
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			if v, ok := scope.Lookup(name).(*types.Var); ok && v != nil && !v.IsField() && v.Exported() && v.Name() != "_" {
				_ = g.bindVarID(v)
				_ = g.varWriteThroughID(v)
			}
		}
	}

	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncLit:
				tv, ok := p.TypesInfo.Types[node]
				if !ok || tv.Type == nil {
					return true
				}
				sig, ok := tv.Type.Underlying().(*types.Signature)
				if !ok || sig == nil {
					return true
				}
				lrwID := g.litReturnWriteID(node)
				if node.Type != nil && node.Type.Results != nil && lrwID >= 0 {
					for _, field := range node.Type.Results.List {
						for _, name := range field.Names {
							if v, ok := g.isSamePkgNonFieldVar(p.TypesInfo.Defs[name]); ok {
								g.addParEdge(g.varWriteThroughID(v), lrwID)
							}
						}
					}
				}
				wireReturnBody(-1, lrwID, node.Body)
				isIIFE := g.directCallFuncLits[node]
				if !isIIFE && lrwID >= 0 {
					g.addParEdge(lrwID, g.dynReturnWriteID(sig))
				}
				if node.Type != nil && node.Type.Params != nil {
					pIdx := 0
					for _, field := range node.Type.Params.List {
						if len(field.Names) == 0 {
							pIdx++
							continue
						}
						for _, name := range field.Names {
							if v, ok := g.isSamePkgNonFieldVar(p.TypesInfo.Defs[name]); ok {
								_ = g.varWriteThroughID(v)
								if !isIIFE {
									g.addParEdge(g.bindVarID(v), g.dynHubID(sig, pIdx))
									g.addParEdge(g.dynHubWriteID(sig, pIdx), g.varWriteThroughID(v))
								}
							}
							pIdx++
						}
					}
				}
			case *ast.SelectorExpr:
				if g.anyDirectCalleeIdent[node.Sel] {
					return true
				}
				selInfo, isSel := p.TypesInfo.Selections[node]
				if !isSel || selInfo == nil {
					return true
				}
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
					boundSig, _ := selInfo.Type().Underlying().(*types.Signature)
					if boundSig == nil {
						return true
					}
					recvWTs := g.methodRecvWriteTargets(node.X, isIface, origSig)
					if boundSig.Params() != nil {
						for i := 0; i < boundSig.Params().Len(); i++ {
							if g.typeMayCarryParallel(boundSig.Params().At(i).Type()) {
								dh := g.dynHubID(boundSig, i)
								for _, rwt := range recvWTs {
									g.addParEdge(rwt, dh)
								}
							}
						}
					}
					if isIface {
						if origFn != nil {
							g.bindSubtree(g.ifaceRecvID(origFn.Name()), node.X)
							irw := g.ifaceRecvWriteID(origFn.Name())
							for _, rwt := range recvWTs {
								g.addParEdge(rwt, irw)
							}
							if boundSig.Params() != nil {
								for i := 0; i < boundSig.Params().Len(); i++ {
									if g.typeMayCarryParallel(boundSig.Params().At(i).Type()) {
										g.addParEdge(g.ifaceHubID(origFn.Name(), i), g.dynHubID(boundSig, i))
										g.addParEdge(g.dynHubWriteID(boundSig, i), g.ifaceHubWriteID(origFn.Name(), i))
									}
								}
							}
							drw := g.dynReturnWriteID(boundSig)
							g.addParEdge(g.ifaceReturnWriteID(origFn.Name(), boundSig), drw)
							for _, rwt := range recvWTs {
								g.addParEdge(rwt, drw)
							}
						}
					} else if origFn != nil {
						if g.allDecls[origFn] != nil {
							g.bindSubtree(g.recvID(origFn), node.X)
							rwRecv := g.recvWriteID(origFn)
							for _, rwt := range recvWTs {
								g.addParEdge(rwt, rwRecv)
							}
							if boundSig.Params() != nil {
								for i := 0; i < boundSig.Params().Len(); i++ {
									g.addParEdge(g.paramID(origFn, i), g.dynHubID(boundSig, i))
									g.addParEdge(g.dynHubWriteID(boundSig, i), g.paramWriteID(origFn, i))
								}
							}
							g.addParEdge(g.returnWriteID(origFn), g.dynReturnWriteID(boundSig))
						} else if (p.Types == nil || origFn.Pkg() != p.Types) && !g.isStdCallee(origFn) {
							if fk, ok := syntaxutil.CallableFactKey(origFn); ok {
								if origSig != nil && origSig.Recv() != nil && g.typeMayCarryParallel(origSig.Recv().Type()) {
									g.bindSubtree(g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#recv"}), node.X)
								}
								if origSig != nil && origSig.Recv() != nil && g.typeMayCarryMutableAlias(origSig.Recv().Type()) {
									crw := g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#wrecv"})
									for _, rwt := range recvWTs {
										g.addParEdge(rwt, crw)
									}
								}
								if boundSig.Params() != nil {
									for i := 0; i < boundSig.Params().Len(); i++ {
										if g.typeMayCarryParallel(boundSig.Params().At(i).Type()) {
											g.addParEdge(g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#" + strconv.Itoa(i)}), g.dynHubID(boundSig, i))
											if g.typeMayCarryMutableAlias(boundSig.Params().At(i).Type()) {
												g.addParEdge(g.dynHubWriteID(boundSig, i), g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#w#" + strconv.Itoa(i)}))
											}
										}
									}
								}
								if g.funcMayReturnMutableAlias(boundSig) {
									g.addParEdge(g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#rw"}), g.dynReturnWriteID(boundSig))
								}
							}
						} else if g.isStdCallee(origFn) {
							wireStdValueDynamicHubs(origSig, boundSig, 0, recvWTs, node.X)
						}
					}
				case types.MethodExpr:
					exprSig, _ := selInfo.Type().Underlying().(*types.Signature)
					if exprSig == nil || exprSig.Params() == nil || exprSig.Params().Len() < 1 {
						return true
					}
					recvSlot := g.dynHubID(exprSig, 0)
					recvSlotWrite := g.dynHubWriteID(exprSig, 0)
					for i := 0; i+1 < exprSig.Params().Len(); i++ {
						if g.typeMayCarryParallel(exprSig.Params().At(i + 1).Type()) {
							g.addParEdge(recvSlotWrite, g.dynHubID(exprSig, i+1))
						}
					}
					if isIface {
						if origFn != nil {
							g.addParEdge(g.ifaceRecvID(origFn.Name()), recvSlot)
							g.addParEdge(recvSlotWrite, g.ifaceRecvWriteID(origFn.Name()))
							for i := 0; i+1 < exprSig.Params().Len(); i++ {
								if g.typeMayCarryParallel(exprSig.Params().At(i + 1).Type()) {
									g.addParEdge(g.ifaceHubID(origFn.Name(), i), g.dynHubID(exprSig, i+1))
									g.addParEdge(g.dynHubWriteID(exprSig, i+1), g.ifaceHubWriteID(origFn.Name(), i))
								}
							}
							drw := g.dynReturnWriteID(exprSig)
							g.addParEdge(g.ifaceReturnWriteID(origFn.Name(), origSig), drw)
							g.addParEdge(recvSlotWrite, drw)
						}
					} else if origFn != nil {
						if g.allDecls[origFn] != nil {
							g.addParEdge(g.recvID(origFn), recvSlot)
							g.addParEdge(recvSlotWrite, g.recvWriteID(origFn))
							for i := 0; i+1 < exprSig.Params().Len(); i++ {
								g.addParEdge(g.paramID(origFn, i), g.dynHubID(exprSig, i+1))
								g.addParEdge(g.dynHubWriteID(exprSig, i+1), g.paramWriteID(origFn, i))
							}
							g.addParEdge(g.returnWriteID(origFn), g.dynReturnWriteID(exprSig))
						} else if (p.Types == nil || origFn.Pkg() != p.Types) && !g.isStdCallee(origFn) {
							if fk, ok := syntaxutil.CallableFactKey(origFn); ok {
								if g.typeMayCarryParallel(exprSig.Params().At(0).Type()) {
									g.addParEdge(g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#recv"}), recvSlot)
								}
								if g.typeMayCarryMutableAlias(exprSig.Params().At(0).Type()) {
									g.addParEdge(recvSlotWrite, g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#wrecv"}))
								}
								for i := 0; i+1 < exprSig.Params().Len(); i++ {
									if g.typeMayCarryParallel(exprSig.Params().At(i + 1).Type()) {
										g.addParEdge(g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#" + strconv.Itoa(i)}), g.dynHubID(exprSig, i+1))
										if g.typeMayCarryMutableAlias(exprSig.Params().At(i + 1).Type()) {
											g.addParEdge(g.dynHubWriteID(exprSig, i+1), g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#w#" + strconv.Itoa(i)}))
										}
									}
								}
								if g.funcMayReturnMutableAlias(exprSig) {
									g.addParEdge(g.crossID(syntaxutil.FuncKey{Pkg: fk.Pkg, Name: fk.Name + "#rw"}), g.dynReturnWriteID(exprSig))
								}
							}
						} else if g.isStdCallee(origFn) {
							wireStdValueDynamicHubs(origSig, exprSig, 1, []int{recvSlotWrite}, nil)
						}
					}
				}
			}
			return true
		})
	}

	g.wireAllVarWritesAndCalls()
	for fn, fd := range g.allDecls {
		eID := g.execFuncID(fn)
		if fd.Recv != nil {
			g.scanExecSubtree(eID, fd.Recv)
		}
		if fd.Type != nil {
			g.scanExecSubtree(eID, fd.Type)
		}
		g.scanExecSubtree(eID, fd.Body)
	}

	revPar := make([][]int, len(g.adj))
	for u, row := range g.adj {
		for _, v := range row {
			revPar[v] = append(revPar[v], u)
		}
	}
	var parQueue []int
	for id, par := range g.reachesPar {
		if par {
			parQueue = append(parQueue, id)
		}
	}
	for len(parQueue) > 0 {
		cur := parQueue[len(parQueue)-1]
		parQueue = parQueue[:len(parQueue)-1]
		for _, prev := range revPar[cur] {
			if !g.reachesPar[prev] {
				g.reachesPar[prev] = true
				parQueue = append(parQueue, prev)
			}
		}
	}

	parallelFuncSet := map[syntaxutil.FuncKey]bool{}
	for id, fk := range g.rootKeys {
		if fk.Valid() && g.reachesPar[id] {
			parallelFuncSet[fk] = true
		}
	}
	for fk := range parallelFuncSet {
		out.ParallelFuncs = append(out.ParallelFuncs, fk)
	}
	slices.SortFunc(out.ParallelFuncs, syntaxutil.FuncKey.Compare)

	canReachRoot := make([]bool, len(g.adj))
	var rootQueue []int
	for id, fk := range g.rootKeys {
		if fk.Valid() {
			canReachRoot[id] = true
			rootQueue = append(rootQueue, id)
		}
	}
	for len(rootQueue) > 0 {
		cur := rootQueue[len(rootQueue)-1]
		rootQueue = rootQueue[:len(rootQueue)-1]
		for _, prev := range revPar[cur] {
			if !canReachRoot[prev] {
				canReachRoot[prev] = true
				rootQueue = append(rootQueue, prev)
			}
		}
	}

	if g.p.Types != nil && g.p.Types.Path() != "" {
		pkgPath := g.p.Types.Path()
		canReachFromRoot := make([]bool, len(g.adj))
		for id, fk := range g.rootKeys {
			if fk.Valid() && !g.reachesPar[id] {
				canReachFromRoot[id] = true
				rootQueue = append(rootQueue, id)
			}
		}
		for len(rootQueue) > 0 {
			cur := rootQueue[len(rootQueue)-1]
			rootQueue = rootQueue[:len(rootQueue)-1]
			for _, next := range g.adj[cur] {
				if !canReachFromRoot[next] && canReachRoot[next] && !g.reachesPar[next] && !g.rootKeys[next].Valid() {
					canReachFromRoot[next] = true
					rootQueue = append(rootQueue, next)
				}
			}
		}
		type hubCandidate struct {
			id       int
			inRoots  []syntaxutil.FuncKey
			outRoots []syntaxutil.FuncKey
		}
		var hubCandidates []hubCandidate
		hubStamp := make([]uint32, len(g.adj))
		var hubEpoch uint32
		var hubStack []int
		for id := range g.adj {
			if g.rootKeys[id].Valid() || g.reachesPar[id] || !canReachFromRoot[id] || !canReachRoot[id] {
				continue
			}
			liveIn := 0
			for _, prev := range revPar[id] {
				if prev != id && !g.reachesPar[prev] && canReachFromRoot[prev] {
					liveIn++
				}
			}
			if liveIn < 2 {
				continue
			}
			liveOut := 0
			for _, next := range g.adj[id] {
				if next != id && canReachRoot[next] {
					liveOut++
				}
			}
			if liveOut < 2 || liveIn*liveOut <= liveIn+liveOut {
				continue
			}
			hubEpoch++
			hubStamp[id] = hubEpoch
			hubStack = append(hubStack[:0], id)
			var inRoots []syntaxutil.FuncKey
			for len(hubStack) > 0 {
				cur := hubStack[len(hubStack)-1]
				hubStack = hubStack[:len(hubStack)-1]
				if cur != id && g.rootKeys[cur].Valid() {
					if !g.reachesPar[cur] {
						inRoots = append(inRoots, g.rootKeys[cur])
					}
					continue
				}
				for _, prev := range revPar[cur] {
					if hubStamp[prev] != hubEpoch && !g.reachesPar[prev] && canReachFromRoot[prev] {
						hubStamp[prev] = hubEpoch
						hubStack = append(hubStack, prev)
					}
				}
			}
			slices.SortFunc(inRoots, syntaxutil.FuncKey.Compare)
			inRoots = slices.Compact(inRoots)
			if len(inRoots) < 2 {
				continue
			}
			hubEpoch++
			hubStamp[id] = hubEpoch
			hubStack = append(hubStack[:0], id)
			var outRoots []syntaxutil.FuncKey
			for len(hubStack) > 0 {
				cur := hubStack[len(hubStack)-1]
				hubStack = hubStack[:len(hubStack)-1]
				if cur != id && g.rootKeys[cur].Valid() {
					outRoots = append(outRoots, g.rootKeys[cur])
					continue
				}
				for _, next := range g.adj[cur] {
					if hubStamp[next] != hubEpoch && canReachRoot[next] {
						hubStamp[next] = hubEpoch
						hubStack = append(hubStack, next)
					}
				}
			}
			slices.SortFunc(outRoots, syntaxutil.FuncKey.Compare)
			outRoots = slices.Compact(outRoots)
			if len(outRoots) < 2 || len(inRoots)*len(outRoots) <= len(inRoots)+len(outRoots) {
				continue
			}
			hubCandidates = append(hubCandidates, hubCandidate{
				id:       id,
				inRoots:  inRoots,
				outRoots: outRoots,
			})
		}
		slices.SortFunc(hubCandidates, func(a, b hubCandidate) int {
			if c := slices.CompareFunc(a.inRoots, b.inRoots, syntaxutil.FuncKey.Compare); c != 0 {
				return c
			}
			return slices.CompareFunc(a.outRoots, b.outRoots, syntaxutil.FuncKey.Compare)
		})
		hubSeq := 0
		for i, cand := range hubCandidates {
			if i > 0 && (slices.CompareFunc(cand.inRoots, hubCandidates[i-1].inRoots, syntaxutil.FuncKey.Compare) != 0 ||
				slices.CompareFunc(cand.outRoots, hubCandidates[i-1].outRoots, syntaxutil.FuncKey.Compare) != 0) {
				hubSeq++
			}
			g.rootKeys[cand.id] = syntaxutil.FuncKey{Pkg: pkgPath, Name: "#par#" + strconv.Itoa(hubSeq)}
		}
	}

	seenParEdge := map[syntaxutil.FuncDepEdge]bool{}
	seenStamp := make([]uint32, len(g.adj))
	var epoch uint32
	var dfsStack []int
	for rootID, rootKey := range g.rootKeys {
		if !rootKey.Valid() || g.reachesPar[rootID] || len(g.adj[rootID]) == 0 {
			continue
		}
		epoch++
		seenStamp[rootID] = epoch
		dfsStack = append(dfsStack[:0], rootID)
		for len(dfsStack) > 0 {
			cur := dfsStack[len(dfsStack)-1]
			dfsStack = dfsStack[:len(dfsStack)-1]
			if cur != rootID && g.rootKeys[cur].Valid() {
				if g.rootKeys[cur] != rootKey {
					edge := syntaxutil.FuncDepEdge{Func: rootKey, Callee: g.rootKeys[cur]}
					if !seenParEdge[edge] {
						seenParEdge[edge] = true
						out.ParallelEdges = append(out.ParallelEdges, edge)
					}
				}
				continue
			}
			for _, next := range g.adj[cur] {
				if seenStamp[next] != epoch && canReachRoot[next] {
					seenStamp[next] = epoch
					dfsStack = append(dfsStack, next)
				}
			}
		}
	}
	slices.SortFunc(out.ParallelEdges, syntaxutil.FuncDepEdge.Compare)
}
