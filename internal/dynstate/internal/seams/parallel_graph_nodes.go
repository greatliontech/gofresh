package seams

import (
	"go/ast"
	"go/types"
	"strconv"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (g *parGraph) typeParamID(fn *types.Func, idx int) int {
	if fn == nil || idx < 0 {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.TypeParams() == nil || idx >= sig.TypeParams().Len() {
		return -1
	}
	pk := parParamKey{fn: fn, idx: idx}
	if id, ok := g.typeParamIDs[pk]; ok {
		return id
	}
	id := g.newNode()
	g.typeParamIDs[pk] = id
	g.typeParamObjIDs[sig.TypeParams().At(idx)] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#tp#" + strconv.Itoa(idx)}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) recvTypeParamID(fn *types.Func, idx int) int {
	if fn == nil || idx < 0 {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.RecvTypeParams() == nil || idx >= sig.RecvTypeParams().Len() {
		return -1
	}
	pk := parParamKey{fn: fn, idx: idx}
	if id, ok := g.recvTypeParamIDs[pk]; ok {
		return id
	}
	id := g.newNode()
	g.recvTypeParamIDs[pk] = id
	g.typeParamObjIDs[sig.RecvTypeParams().At(idx)] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#rtp#" + strconv.Itoa(idx)}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) wireTypeParamsOfType(ownerID int, t types.Type) {
	if ownerID < 0 || t == nil || len(g.typeParamObjIDs) == 0 {
		return
	}
	for _, tp := range g.collectTypeParams(t) {
		if tpID, ok := g.typeParamObjIDs[tp]; ok {
			g.addParEdge(ownerID, tpID)
		}
	}
}

func (g *parGraph) execFuncID(fn *types.Func) int {
	if fn == nil {
		return -1
	}
	fn = fn.Origin()
	if id, ok := g.execIDs[fn]; ok {
		return id
	}
	id := g.newNode()
	g.execIDs[fn] = id
	if fn.Exported() || (g.p.Name == "main" && g.plainDecls[fn] != nil && fn.Name() == "main") {
		if fk, ok := syntaxutil.CallableFactKey(fn); ok {
			g.rootKeys[id] = fk
		}
	}
	return id
}

func (g *parGraph) bindVarID(v *types.Var) int {
	if v == nil || !g.typeMayCarryParallel(v.Type()) {
		return -1
	}
	if id, ok := g.varIDs[v]; ok {
		return id
	}
	id := g.newNode()
	g.varIDs[v] = id
	g.wireTypeParamsOfType(id, v.Type())
	if g.p.Types != nil && v.Parent() == g.p.Types.Scope() && v.Exported() && v.Name() != "_" {
		fk := syntaxutil.FuncKey{Pkg: g.p.Types.Path(), Name: v.Name()}
		if fk.Valid() {
			g.rootKeys[id] = fk
		}
	}
	return id
}

func (g *parGraph) varWriteThroughID(v *types.Var) int {
	if v == nil || v.IsField() || v.Name() == "_" || g.p.Types == nil || v.Pkg() != g.p.Types || !g.typeMayCarryMutableAlias(v.Type()) {
		return -1
	}
	if id, ok := g.varWriteThroughIDs[v]; ok {
		return id
	}
	id := g.newNode()
	g.varWriteThroughIDs[v] = id
	g.addParEdge(g.bindVarID(v), id)
	if v.Parent() == g.p.Types.Scope() && v.Exported() {
		fk := syntaxutil.FuncKey{Pkg: g.p.Types.Path(), Name: v.Name() + "#w"}
		if fk.Valid() {
			g.rootKeys[id] = fk
		}
	}
	return id
}

func (g *parGraph) returnID(fn *types.Func) int {
	if fn == nil {
		return -1
	}
	fn = fn.Origin()
	if id, ok := g.returnIDs[fn]; ok {
		return id
	}
	id := g.newNode()
	g.returnIDs[fn] = id
	return id
}

func (g *parGraph) returnWriteID(fn *types.Func) int {
	if fn == nil {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || !g.funcMayReturnMutableAlias(sig) {
		return -1
	}
	if id, ok := g.returnWriteIDs[fn]; ok {
		return id
	}
	id := g.newNode()
	g.returnWriteIDs[fn] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#rw"}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) litReturnWriteID(lit *ast.FuncLit) int {
	if lit == nil {
		return -1
	}
	if id, ok := g.litReturnWriteIDs[lit]; ok {
		return id
	}
	tv, ok := g.p.TypesInfo.Types[lit]
	if !ok || tv.Type == nil {
		return -1
	}
	sig, ok := tv.Type.Underlying().(*types.Signature)
	if !ok || !g.funcMayReturnMutableAlias(sig) {
		return -1
	}
	id := g.newNode()
	g.litReturnWriteIDs[lit] = id
	return id
}

func (g *parGraph) recvID(fn *types.Func) int {
	if fn == nil {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.Recv() == nil || !g.typeMayCarryParallel(sig.Recv().Type()) {
		return -1
	}
	if id, ok := g.recvIDs[fn]; ok {
		return id
	}
	id := g.newNode()
	g.recvIDs[fn] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#recv"}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) recvWriteID(fn *types.Func) int {
	if fn == nil {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.Recv() == nil || !g.typeMayCarryMutableAlias(sig.Recv().Type()) {
		return -1
	}
	if id, ok := g.recvWriteIDs[fn]; ok {
		return id
	}
	id := g.newNode()
	g.recvWriteIDs[fn] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#wrecv"}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) paramID(fn *types.Func, idx int) int {
	if fn == nil || idx < 0 {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.Params() == nil || idx >= sig.Params().Len() || !g.typeMayCarryParallel(sig.Params().At(idx).Type()) {
		return -1
	}
	pk := parParamKey{fn: fn, idx: idx}
	if id, ok := g.paramIDs[pk]; ok {
		return id
	}
	id := g.newNode()
	g.paramIDs[pk] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#" + strconv.Itoa(idx)}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) paramWriteID(fn *types.Func, idx int) int {
	if fn == nil || idx < 0 {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.Params() == nil || idx >= sig.Params().Len() || !g.typeMayCarryMutableAlias(sig.Params().At(idx).Type()) {
		return -1
	}
	pk := parParamKey{fn: fn, idx: idx}
	if id, ok := g.paramWriteIDs[pk]; ok {
		return id
	}
	id := g.newNode()
	g.paramWriteIDs[pk] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#w#" + strconv.Itoa(idx)}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) crossID(fk syntaxutil.FuncKey) int {
	if !fk.Valid() {
		return -1
	}
	if id, ok := g.crossIDs[fk]; ok {
		return id
	}
	id := g.newNode()
	g.crossIDs[fk] = id
	g.rootKeys[id] = fk
	return id
}

func (g *parGraph) dynHubID(sig *types.Signature, idx int) int {
	if sig == nil || sig.Params() == nil || idx < 0 {
		return -1
	}
	nRes := 0
	if sig.Results() != nil {
		nRes = sig.Results().Len()
	}
	return g.crossID(syntaxutil.FuncKey{
		Pkg:  "*",
		Name: "#dyn#" + strconv.Itoa(sig.Params().Len()) + ":" + strconv.Itoa(nRes) + "#" + strconv.Itoa(idx),
	})
}

func (g *parGraph) dynHubWriteID(sig *types.Signature, idx int) int {
	if sig == nil || sig.Params() == nil || idx < 0 {
		return -1
	}
	nRes := 0
	if sig.Results() != nil {
		nRes = sig.Results().Len()
	}
	return g.crossID(syntaxutil.FuncKey{
		Pkg:  "*",
		Name: "#dynw#" + strconv.Itoa(sig.Params().Len()) + ":" + strconv.Itoa(nRes) + "#" + strconv.Itoa(idx),
	})
}

func (g *parGraph) dynReturnWriteID(sig *types.Signature) int {
	if !g.funcMayReturnMutableAlias(sig) {
		return -1
	}
	nParams := 0
	if sig.Params() != nil {
		nParams = sig.Params().Len()
	}
	return g.crossID(syntaxutil.FuncKey{
		Pkg:  "*",
		Name: "#dynrw#" + strconv.Itoa(nParams) + ":" + strconv.Itoa(sig.Results().Len()),
	})
}

func (g *parGraph) ifaceRecvID(methodName string) int {
	if methodName == "" {
		return -1
	}
	if ast.IsExported(methodName) {
		return g.crossID(syntaxutil.FuncKey{Pkg: "*", Name: methodName + "#recv"})
	}
	if id, ok := g.unexpIfaceRecvHubs[methodName]; ok {
		return id
	}
	id := g.newNode()
	g.unexpIfaceRecvHubs[methodName] = id
	return id
}

func (g *parGraph) ifaceRecvWriteID(methodName string) int {
	if methodName == "" {
		return -1
	}
	if ast.IsExported(methodName) {
		return g.crossID(syntaxutil.FuncKey{Pkg: "*", Name: methodName + "#wrecv"})
	}
	if id, ok := g.unexpIfaceRecvWriteHubs[methodName]; ok {
		return id
	}
	id := g.newNode()
	g.unexpIfaceRecvWriteHubs[methodName] = id
	return id
}

func (g *parGraph) ifaceHubID(methodName string, idx int) int {
	if methodName == "" || idx < 0 {
		return -1
	}
	if ast.IsExported(methodName) {
		return g.crossID(syntaxutil.FuncKey{Pkg: "*", Name: methodName + "#" + strconv.Itoa(idx)})
	}
	sk := ifaceSlotKey{name: methodName, idx: idx}
	if id, ok := g.unexpIfaceHubs[sk]; ok {
		return id
	}
	id := g.newNode()
	g.unexpIfaceHubs[sk] = id
	return id
}

func (g *parGraph) ifaceHubWriteID(methodName string, idx int) int {
	if methodName == "" || idx < 0 {
		return -1
	}
	if ast.IsExported(methodName) {
		return g.crossID(syntaxutil.FuncKey{Pkg: "*", Name: methodName + "#w#" + strconv.Itoa(idx)})
	}
	sk := ifaceSlotKey{name: methodName, idx: idx}
	if id, ok := g.unexpIfaceWriteHubs[sk]; ok {
		return id
	}
	id := g.newNode()
	g.unexpIfaceWriteHubs[sk] = id
	return id
}

func (g *parGraph) ifaceReturnWriteID(methodName string, sig *types.Signature) int {
	if methodName == "" || !g.funcMayReturnMutableAlias(sig) {
		return -1
	}
	if ast.IsExported(methodName) {
		return g.crossID(syntaxutil.FuncKey{Pkg: "*", Name: methodName + "#rw"})
	}
	if id, ok := g.unexpIfaceRetWriteHubs[methodName]; ok {
		return id
	}
	id := g.newNode()
	g.unexpIfaceRetWriteHubs[methodName] = id
	return id
}

func (g *parGraph) isSamePkgNonFieldVar(obj types.Object) (*types.Var, bool) {
	v, ok := obj.(*types.Var)
	if !ok || v == nil || v.IsField() || v.Name() == "_" || g.p.Types == nil || v.Pkg() != g.p.Types {
		return nil, false
	}
	return v, true
}

func (g *parGraph) targetVarID(v *types.Var) int {
	if v == nil || v.IsField() || v.Pkg() == nil || v.Name() == "_" || !g.typeMayCarryParallel(v.Type()) {
		return -1
	}
	if g.p.Types != nil && v.Pkg() == g.p.Types {
		return g.bindVarID(v)
	}
	if (g.p.Types == nil || v.Pkg() != g.p.Types) && v.Parent() == v.Pkg().Scope() && !g.isStdPkg(v.Pkg()) {
		return g.crossID(syntaxutil.FuncKey{Pkg: v.Pkg().Path(), Name: v.Name()})
	}
	return -1
}

func (g *parGraph) targetVarWriteThroughID(v *types.Var) int {
	if v == nil || v.IsField() || v.Pkg() == nil || v.Name() == "_" || !g.typeMayCarryMutableAlias(v.Type()) {
		return -1
	}
	if g.p.Types != nil && v.Pkg() == g.p.Types {
		return g.varWriteThroughID(v)
	}
	if (g.p.Types == nil || v.Pkg() != g.p.Types) && v.Parent() == v.Pkg().Scope() && !g.isStdPkg(v.Pkg()) {
		return g.crossID(syntaxutil.FuncKey{Pkg: v.Pkg().Path(), Name: v.Name() + "#w"})
	}
	return -1
}

func (g *parGraph) isBareVarExpr(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if e.Name == "_" {
			return true
		}
		v, ok := syntaxutil.IdentDefOrUse(g.p.TypesInfo, e).(*types.Var)
		return ok && v != nil && !v.IsField()
	case *ast.SelectorExpr:
		if g.p.TypesInfo.Selections[e] != nil {
			return false
		}
		v, ok := g.p.TypesInfo.Uses[e.Sel].(*types.Var)
		return ok && v != nil && !v.IsField()
	default:
		return false
	}
}

func (g *parGraph) recordMethodTarget(ownerID int, m *types.Func) {
	if ownerID < 0 || m == nil || m.Pkg() == nil {
		return
	}
	m = m.Origin()
	if g.allDecls[m] != nil {
		g.addParEdge(ownerID, g.execFuncID(m))
	} else if (g.p.Types == nil || m.Pkg() != g.p.Types) && m.Exported() && !g.isStdCallee(m) {
		if fk, ok := syntaxutil.CallableFactKey(m); ok {
			g.addParEdge(ownerID, g.crossID(fk))
		}
	}
}

func (g *parGraph) typeHubID(t types.Type) int {
	if t == nil {
		return -1
	}
	if _, isBasic := t.(*types.Basic); isBasic {
		return -1
	}
	if h, ok := g.typeHubs[t]; ok {
		return h
	}
	ms := g.collectTypeMethods(t)
	if len(ms) == 0 {
		g.typeHubs[t] = -1
		return -1
	}
	h := g.newNode()
	g.typeHubs[t] = h
	for _, m := range ms {
		g.recordMethodTarget(h, m)
	}
	return h
}

func (g *parGraph) wireTypeArg(slotID int, targ types.Type) {
	if slotID < 0 || targ == nil {
		return
	}
	g.addParEdge(slotID, g.typeHubID(targ))
	g.wireTypeParamsOfType(slotID, targ)
}

func (g *parGraph) recordObjOnNode(ownerID int, obj types.Object, execOnlyPkgVars bool) {
	if ownerID < 0 || obj == nil {
		return
	}
	g.addParEdge(ownerID, g.typeHubID(obj.Type()))
	switch target := obj.(type) {
	case *types.Func:
		g.recordMethodTarget(ownerID, target)
	case *types.Var:
		if target.IsField() || target.Pkg() == nil || target.Name() == "_" {
			return
		}
		if _, ok := g.isSamePkgNonFieldVar(target); ok {
			if !execOnlyPkgVars || target.Parent() == g.p.Types.Scope() {
				g.addParEdge(ownerID, g.bindVarID(target))
			}
		} else if (g.p.Types == nil || target.Pkg() != g.p.Types) && target.Parent() == target.Pkg().Scope() && !g.isStdPkg(target.Pkg()) {
			g.addParEdge(ownerID, g.crossID(syntaxutil.FuncKey{Pkg: target.Pkg().Path(), Name: target.Name()}))
		}
	}
}

func (g *parGraph) resolveConcreteDeclCallee(call *ast.CallExpr) (*types.Func, *ast.Ident) {
	if tv, isType := g.p.TypesInfo.Types[call.Fun]; isType && tv.IsType() {
		return nil, nil
	}
	switch fun := syntaxutil.UnwrapCallee(call.Fun).(type) {
	case *ast.Ident:
		if fn, ok := g.p.TypesInfo.Uses[fun].(*types.Func); ok && fn != nil {
			fn = fn.Origin()
			if g.allDecls[fn] != nil {
				return fn, fun
			}
		}
	case *ast.SelectorExpr:
		if selInfo, isSel := g.p.TypesInfo.Selections[fun]; isSel && selInfo != nil {
			if selInfo.Kind() == types.MethodVal || selInfo.Kind() == types.MethodExpr {
				fn, _ := selInfo.Obj().(*types.Func)
				var origFn *types.Func
				if fn != nil {
					origFn = fn.Origin()
				}
				if origFn != nil && !isInterfaceMethodSelection(selInfo, origFn) && g.allDecls[origFn] != nil {
					return origFn, fun.Sel
				}
			}
		} else if fn, ok := g.p.TypesInfo.Uses[fun.Sel].(*types.Func); ok && fn != nil {
			fn = fn.Origin()
			if g.allDecls[fn] != nil {
				return fn, fun.Sel
			}
		}
	}
	return nil, nil
}
