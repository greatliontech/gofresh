package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// auditedValuePlane names the standard value-plane helpers whose results carry
// exactly their arguments' values — clone and concatenation shapes with no
// environment of their own. A closed set: absence keeps the refusal.
var auditedValuePlane = map[syntaxutil.FuncKey]bool{
	{Pkg: "slices", Name: "Clone"}:  true,
	{Pkg: "slices", Name: "Concat"}: true,
	{Pkg: "maps", Name: "Clone"}:    true,
}

func lowerEnclosingScope(info *types.Info, pkg *types.Package, enclosing ast.Node) *flowir.Body {
	switch n := enclosing.(type) {
	case nil:
		return nil
	case *ast.FuncDecl:
		return flowir.LowerFunc(info, pkg, n)
	case *ast.FuncLit:
		return flowir.LowerFuncLit(info, pkg, n)
	default:
		return flowir.LowerNode(info, pkg, n)
	}
}

// settledGlobalMap maps each proven settled unexported package data global to
// the set of single-definition carrier variables whose top-level initializer
// embeds its mutable reach directly (empty when never embedded in a carrier).
type settledGlobalMap map[*types.Var]map[*types.Var]bool

func (m settledGlobalMap) hasUnembedded(v *types.Var) bool {
	if m == nil || v == nil {
		return false
	}
	carriers, ok := m[v]
	return ok && len(carriers) == 0
}

func (m settledGlobalMap) allowedForTargets(v *types.Var, targets []*types.Var) bool {
	if m == nil || v == nil {
		return false
	}
	carriers, ok := m[v]
	if !ok {
		return false
	}
	if len(carriers) == 0 {
		return true
	}
	return len(targets) == 1 && carriers[targets[0]]
}

func isPureFreshDataExpr(p *packages.Package, settledGlobals settledGlobalMap, expr ast.Expr) bool {
	return isPureFreshDataExprWith(p, expr, settledGlobals.hasUnembedded)
}

func isPureFreshDataExprWith(p *packages.Package, expr ast.Expr, allowVar func(*types.Var) bool) bool {
	if p == nil || p.TypesInfo == nil || expr == nil {
		return false
	}
	e := syntaxutil.UnparenExpr(expr)
	et := p.TypesInfo.TypeOf(e)
	if et == nil || refconfine.TypeCarriesSignature(et) || refconfine.TypeReachesSyncNoCopyByValue(et) {
		return false
	}
	if tv, ok := p.TypesInfo.Types[e]; ok && tv.Value != nil {
		return true
	}
	switch v := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		obj := syntaxutil.IdentDefOrUse(p.TypesInfo, v)
		if obj == nil {
			return false
		}
		if _, isNil := obj.(*types.Nil); isNil {
			return true
		}
		if _, isConst := obj.(*types.Const); isConst {
			return true
		}
		if gv, ok := obj.(*types.Var); ok && allowVar != nil && allowVar(gv) {
			return true
		}
		return false
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			_, isComp := syntaxutil.UnparenExpr(v.X).(*ast.CompositeLit)
			return isComp && isPureFreshDataExprWith(p, v.X, allowVar)
		}
		if v.Op == token.ADD || v.Op == token.SUB || v.Op == token.NOT || v.Op == token.XOR {
			return isPureFreshDataExprWith(p, v.X, allowVar)
		}
		return false
	case *ast.BinaryExpr:
		return isPureFreshDataExprWith(p, v.X, allowVar) && isPureFreshDataExprWith(p, v.Y, allowVar)
	case *ast.CompositeLit:
		t := p.TypesInfo.TypeOf(v)
		if t == nil || refconfine.TypeCarriesSignature(t) || refconfine.TypeReachesSyncNoCopyByValue(t) {
			return false
		}
		return syntaxutil.EachCompositeLitFlow(p.TypesInfo, v, func(elt ast.Expr, _ bool) bool {
			return isPureFreshDataExprWith(p, elt, allowVar)
		})
	case *ast.CallExpr:
		if ident, ok := syntaxutil.UnparenExpr(v.Fun).(*ast.Ident); ok {
			if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
				switch ident.Name {
				case "make":
					for i := 1; i < len(v.Args); i++ {
						if !isPureFreshDataExprWith(p, v.Args[i], allowVar) {
							return false
						}
					}
					t := p.TypesInfo.TypeOf(v)
					return !refconfine.TypeCarriesSignature(t) && !refconfine.TypeReachesSyncNoCopyByValue(t)
				case "new":
					t := p.TypesInfo.TypeOf(v)
					if syntaxutil.IsBuiltinNewType(p.TypesInfo, v) {
						return !refconfine.TypeCarriesSignature(t) && !refconfine.TypeReachesSyncNoCopyByValue(t)
					}
					return len(v.Args) == 1 && !v.Ellipsis.IsValid() &&
						!refconfine.TypeCarriesSignature(t) && !refconfine.TypeReachesSyncNoCopyByValue(t) &&
						isPureFreshDataExprWith(p, v.Args[0], allowVar)
				case "append":
					t := p.TypesInfo.TypeOf(v)
					if len(v.Args) == 0 || refconfine.TypeCarriesSignature(t) || refconfine.TypeReachesSyncNoCopyByValue(t) {
						return false
					}
					// Appending onto a variable's slice could mutate its spare capacity;
					// require a variable-free fresh base expression for append.
					if !isPureFreshDataExprWith(p, v.Args[0], nil) {
						return false
					}
					for _, a := range v.Args[1:] {
						if !isPureFreshDataExprWith(p, a, allowVar) {
							return false
						}
					}
					return true
				}
				return false
			}
		}
		if tv, ok := p.TypesInfo.Types[v.Fun]; ok && tv.IsType() && len(v.Args) == 1 && !v.Ellipsis.IsValid() {
			return !syntaxutil.IsUnsafePointerType(tv.Type) &&
				!refconfine.TypeCarriesSignature(tv.Type) &&
				!refconfine.TypeReachesSyncNoCopyByValue(tv.Type) &&
				isPureFreshDataExprWith(p, v.Args[0], allowVar)
		}
		if fn, pkgPath := syntaxutil.PlainCalleeFunc(p, v.Fun); fn != nil {
			fk := syntaxutil.FuncKey{Pkg: pkgPath, Name: fn.Name()}
			t := p.TypesInfo.TypeOf(v)
			if auditedValuePlane[fk] && !refconfine.TypeCarriesSignature(t) && !refconfine.TypeReachesSyncNoCopyByValue(t) {
				for _, a := range v.Args {
					if !isPureFreshDataExprWith(p, a, allowVar) {
						return false
					}
				}
				return true
			}
		}
	}
	return false
}

// isSettledReachArg reports whether expr, appearing as a mutable-reach argument
// to a plain constructor call at a registration site (whose signature plane was
// already verified by carrying(expr)), introduces no unsettled mutable reach.
func isSettledReachArg(
	audited bool,
	p *packages.Package,
	settledGlobals settledGlobalMap,
	currentTargets []*types.Var,
	enclosing ast.Node,
	exemptCall *ast.CallExpr,
	paramLeakFree map[syntaxutil.ParamKey]bool,
	readOnly map[string]bool,
	checkSigOrigin func(ast.Expr) bool,
	expr ast.Expr,
) bool {
	return isSettledReachArgSeen(audited, p, settledGlobals, currentTargets, enclosing, exemptCall, paramLeakFree, readOnly, checkSigOrigin, expr, map[*types.Var]bool{})
}

func isSettledReachArgSeen(
	audited bool,
	p *packages.Package,
	settledGlobals settledGlobalMap,
	currentTargets []*types.Var,
	enclosing ast.Node,
	exemptCall *ast.CallExpr,
	paramLeakFree map[syntaxutil.ParamKey]bool,
	readOnly map[string]bool,
	checkSigOrigin func(ast.Expr) bool,
	expr ast.Expr,
	visiting map[*types.Var]bool,
) bool {
	if p == nil || p.TypesInfo == nil || expr == nil {
		return false
	}
	e := syntaxutil.UnparenExpr(expr)
	t := p.TypesInfo.TypeOf(e)
	if t == nil || refconfine.TypeReachesSyncNoCopyByValue(t) {
		return false
	}
	if !refconfine.TypeHandsOutMutableReach(t) {
		if refconfine.TypeCarriesSignature(t) {
			return checkSigOrigin != nil && checkSigOrigin(e)
		}
		return true
	}
	if isPureFreshDataExpr(p, settledGlobals, e) {
		return true
	}
	recur := func(sub ast.Expr) bool {
		return isSettledReachArgSeen(audited, p, settledGlobals, currentTargets, enclosing, exemptCall, paramLeakFree, readOnly, checkSigOrigin, sub, visiting)
	}
	switch n := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.CompositeLit:
		return syntaxutil.EachCompositeLitFlow(p.TypesInfo, n, func(elt ast.Expr, _ bool) bool {
			return recur(elt)
		})
	case *ast.UnaryExpr:
		if n.Op == token.AND {
			_, isComp := syntaxutil.UnparenExpr(n.X).(*ast.CompositeLit)
			return isComp && recur(n.X)
		}
		return false
	case *ast.CallExpr:
		if ident, ok := syntaxutil.UnparenExpr(n.Fun).(*ast.Ident); ok {
			if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
				switch ident.Name {
				case "make":
					return true
				case "new":
					if syntaxutil.IsBuiltinNewType(p.TypesInfo, n) {
						return true
					}
					return len(n.Args) == 1 && !n.Ellipsis.IsValid() && recur(n.Args[0])
				case "append":
					if len(n.Args) == 0 || !isPureFreshDataExprWith(p, n.Args[0], nil) {
						return false
					}
					for _, a := range n.Args[1:] {
						if !recur(a) {
							return false
						}
					}
					return true
				}
				return false
			}
		}
		if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() && len(n.Args) == 1 && !n.Ellipsis.IsValid() {
			return !syntaxutil.IsUnsafePointerType(tv.Type) && recur(n.Args[0])
		}
		if fn, pkgPath := syntaxutil.PlainCalleeFunc(p, n.Fun); fn != nil {
			fk := syntaxutil.FuncKey{Pkg: pkgPath, Name: fn.Name()}
			if auditedValuePlane[fk] {
				for _, a := range n.Args {
					if !recur(a) {
						return false
					}
				}
				return true
			}
		}
		return false
	case *ast.Ident:
		obj := syntaxutil.IdentDefOrUse(p.TypesInfo, n)
		if obj == nil {
			return false
		}
		if _, isNil := obj.(*types.Nil); isNil {
			return true
		}
		if _, isConst := obj.(*types.Const); isConst {
			return true
		}
		v, ok := obj.(*types.Var)
		if !ok {
			return false
		}
		if v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
			return settledGlobals.allowedForTargets(v, currentTargets)
		}
		if !syntaxutil.IsLocalVar(v) || enclosing == nil || visiting[v] {
			return false
		}
		enclBody := lowerEnclosingScope(p.TypesInfo, p.Types, enclosing)
		if enclBody == nil || !enclBody.OwnsVar(v) {
			return false
		}
		if v == enclBody.Recv || enclBody.ResultSet[v] {
			return false
		}
		if _, isParam := enclBody.ParamIndex[v]; isParam {
			return false
		}
		visiting[v] = true
		defer delete(visiting, v)
		defs := 0
		var initRaw ast.Expr
		enclBody.ForEachSyncOp(func(op *flowir.Op) bool {
			if op.Kind == flowir.OpAssign {
				op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
					if dst.Obj == v {
						if dst.IsBareVar() && isDef && src != nil && src.Raw != nil {
							defs++
							initRaw = src.Raw
						} else {
							defs = 2
						}
					}
					return true
				})
			}
			return true
		})
		if defs != 1 || initRaw == nil || !isSettledReachArgSeen(audited, p, settledGlobals, currentTargets, enclosing, nil, paramLeakFree, readOnly, checkSigOrigin, initRaw, visiting) {
			return false
		}
		wants := map[syntaxutil.ParamKey]bool{}
		methodWants := map[syntaxutil.FuncKey]bool{}
		roots := map[types.Object]bool{v: true}
		origin := &rootOriginPolicy{
			verifyLocalOrigins: true,
			settledGlobals:     settledGlobals,
			currentTargets:     currentTargets,
			checkCarryingExpr:  checkSigOrigin,
		}
		if !enclosingConfinesRoots(audited, p, enclosing, nil, exemptCall, roots, wants, methodWants, origin) {
			return false
		}
		ownPath := ""
		if p.Types != nil {
			ownPath = p.Types.Path()
		}
		for w := range wants {
			if w.Func.Pkg != ownPath || !paramLeakFree[w] {
				return false
			}
		}
		for mw := range methodWants {
			if mw.Pkg != ownPath || !readOnly[mw.Name] {
				return false
			}
		}
		return true
	}
	return false
}

func elemHandsOutMutableReach(t types.Type) bool {
	if t == nil {
		return true
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Slice:
		return refconfine.TypeHandsOutMutableReach(u.Elem())
	case *types.Map:
		return refconfine.TypeHandsOutMutableReach(u.Key()) || refconfine.TypeHandsOutMutableReach(u.Elem())
	default:
		return true
	}
}

func varSetEqual(a, b map[*types.Var]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// settledPackageDataGlobals identifies unexported non-carrier package-scope
// variables initialized from pure fresh data expressions and never mutated or
// leaked anywhere in p, recording any single-definition unbroken carrier whose
// initializer directly embeds the global's mutable reach.
func settledPackageDataGlobals(
	audited bool,
	p *packages.Package,
	paramLeakFree map[syntaxutil.ParamKey]bool,
	readOnly map[string]bool,
	unattestedBroken map[string]bool,
	singleSubjectVars map[string]bool,
) settledGlobalMap {
	if p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil
	}
	ownPath := p.Types.Path()
	funcDecls := map[*types.Func]*ast.FuncDecl{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name != nil && fd.Body != nil {
				if fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok && fn != nil {
					funcDecls[fn] = fd
				}
			}
		}
	}

	candidates := map[*types.Var]ast.Expr{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != len(vs.Values) {
					continue
				}
				for i, name := range vs.Names {
					if name == nil || name.IsExported() || name.Name == "_" {
						continue
					}
					v, ok := p.TypesInfo.Defs[name].(*types.Var)
					if !ok || v == nil || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
						continue
					}
					if refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) ||
						refconfine.TypeReachesSyncNoCopyByValue(v.Type()) {
						continue
					}
					candidates[v] = vs.Values[i]
				}
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	// Fixed-point seed: keep candidates whose own initializer is pure fresh data.
	settled := settledGlobalMap{}
	settledRawExported := map[*types.Var]bool{}
	inSettledVar := func(gv *types.Var) bool {
		_, ok := settled[gv]
		return ok
	}
	for changed := true; changed; {
		changed = false
		for v, initExpr := range candidates {
			if _, ok := settled[v]; ok {
				continue
			}
			if isPureFreshDataExprWith(p, initExpr, inSettledVar) {
				settled[v] = map[*types.Var]bool{}
				changed = true
			}
		}
	}
	if len(settled) == 0 {
		return nil
	}

	wantsResolve := func(wants map[syntaxutil.ParamKey]bool, methodWants map[syntaxutil.FuncKey]bool) bool {
		for w := range wants {
			if w.Func.Pkg != ownPath || !paramLeakFree[w] {
				return false
			}
		}
		for mw := range methodWants {
			if mw.Pkg != ownPath || !readOnly[mw.Name] {
				return false
			}
		}
		return true
	}

	carrierSafeForEmbedding := func(carrier *types.Var, ownSpec *ast.ValueSpec, embedsRawData bool) bool {
		if carrier == nil {
			return false
		}
		key := syntaxutil.DynamicVarKey(carrier)
		if unattestedBroken[key] || singleSubjectVars[key] {
			return false
		}
		if carrier.Exported() && embedsRawData && !refconfine.TypeHandsOutDynamicAlias(audited, carrier.Type()) {
			return false
		}
		for _, file := range p.Syntax {
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok || vs == ownSpec {
							continue
						}
						if subtreeUsesObj(p.TypesInfo, vs, carrier) {
							return false
						}
					}
				case *ast.FuncDecl:
					if d.Body == nil || d.Name == nil {
						continue
					}
					if !subtreeUsesObj(p.TypesInfo, d.Body, carrier) {
						continue
					}
					wants := map[syntaxutil.ParamKey]bool{}
					mw := map[syntaxutil.FuncKey]bool{}
					if !enclosingConfinesRoots(audited, p, d, nil, nil, map[types.Object]bool{carrier: true}, wants, mw, nil) ||
						!wantsResolve(wants, mw) {
						return false
					}
				}
			}
		}
		return true
	}

	checkTopValueSpecUse := func(g *types.Var, vs *ast.ValueSpec, embeddedOut map[*types.Var]bool, embeddedRawExported *bool) bool {
		if len(vs.Names) == 1 && len(vs.Values) == 1 {
			if lhsVar, ok := p.TypesInfo.Defs[vs.Names[0]].(*types.Var); ok && lhsVar != nil {
				carriersOfLHS, inSettled := settled[lhsVar]
				isCarrierLHS := refconfine.TypeMayCarryUnknownDynamic(audited, lhsVar.Type())
				if !inSettled && !isCarrierLHS && refconfine.TypeHandsOutMutableReach(lhsVar.Type()) {
					return false
				}
				exprBody := flowir.LowerNode(p.TypesInfo, p.Types, vs.Values[0])
				if exprBody == nil || len(exprBody.Ops) != 1 || exprBody.Ops[0].Kind != flowir.OpExpr || exprBody.Ops[0].Expr == nil {
					return false
				}
				okSpec := true
				embedsReach := false
				embedsRawData := false
				var checkVal func(v *flowir.Value)
				checkVal = func(v *flowir.Value) {
					if !okSpec || v == nil {
						return
					}
					switch v.Kind {
					case flowir.ValPlace:
						if v.Place.Obj == g && refconfine.TypeHandsOutMutableReach(g.Type()) &&
							(len(v.Place.Projs) == 0 || v.Type == nil || refconfine.TypeHandsOutMutableReach(v.Type)) {
							embedsReach = true
							embedsRawData = true
						}
					case flowir.ValAddrOf:
						if v.AddrPlace.Obj == g {
							okSpec = false
							return
						}
					case flowir.ValMethodVal:
						if v.Recv != nil && valueMentionsVar(v.Recv, g) {
							okSpec = false
							return
						}
					case flowir.ValMakeClosure:
						if v.Lit != nil && subtreeUsesObj(p.TypesInfo, v.Lit.Body, g) {
							wants := map[syntaxutil.ParamKey]bool{}
							mw := map[syntaxutil.FuncKey]bool{}
							if !enclosingConfinesRoots(audited, p, v.Lit, nil, nil, map[types.Object]bool{g: true}, wants, mw, nil) ||
								!wantsResolve(wants, mw) {
								okSpec = false
								return
							}
						}
						return
					case flowir.ValCall:
						if v.CallKind == flowir.CallBuiltin && (v.BuiltinName == "len" || v.BuiltinName == "cap") {
							for _, arg := range v.Args {
								if arg != nil && arg.Kind == flowir.ValPlace && arg.Place.Obj == g && len(arg.Place.Projs) == 0 {
									continue
								}
								checkVal(arg)
							}
							return
						}
						if v.CallKind == flowir.CallPlain && v.CalleeFunc != nil {
							fk := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()}
							if auditedValuePlane[fk] {
								shallowSafe := !elemHandsOutMutableReach(v.Type)
								for _, arg := range v.Args {
									if shallowSafe && arg != nil && arg.Kind == flowir.ValPlace && arg.Place.Obj == g && len(arg.Place.Projs) == 0 {
										continue
									}
									checkVal(arg)
								}
								return
							}
							for i, arg := range v.Args {
								if !valueMentionsVar(arg, g) {
									continue
								}
								if !refconfine.TypeHandsOutMutableReach(g.Type()) && !(v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj == g) {
									continue
								}
								if v.Type == nil || refconfine.TypeHandsOutMutableReach(v.Type) || refconfine.TypeReachesSyncNoCopyByValue(v.Type) {
									okSpec = false
									return
								}
								pIdx, pOK := v.ParamIndexForArg(i)
								if !pOK {
									okSpec = false
									return
								}
								pk := syntaxutil.ParamKey{Func: fk, Index: pIdx}
								confinementOK := fk.Pkg == ownPath && paramLeakFree[pk] && !refconfine.CallResultHandsOut(v.Type)
								if !confinementOK && arg != nil && arg.Kind == flowir.ValPlace && arg.Place.Obj == g && len(arg.Place.Projs) == 0 {
									if fd := funcDecls[v.CalleeFunc]; fd != nil {
										fnBody := flowir.LowerFunc(p.TypesInfo, p.Types, fd)
										if fnBody != nil && pIdx < len(fnBody.Params) && fnBody.Params[pIdx] != nil {
											wants := map[syntaxutil.ParamKey]bool{}
											mw := map[syntaxutil.FuncKey]bool{}
											pRoot := map[types.Object]bool{fnBody.Params[pIdx]: true}
											if enclosingConfinesRoots(audited, p, fd, nil, nil, pRoot, wants, mw, nil) &&
												wantsResolve(wants, mw) {
												confinementOK = true
											}
										}
									}
								}
								if !confinementOK {
									okSpec = false
									return
								}
							}
							for _, arg := range v.Args {
								if arg != nil && arg.Kind == flowir.ValPlace && arg.Place.Obj == g && len(arg.Place.Projs) == 0 {
									continue
								}
								checkVal(arg)
							}
							return
						}
						for _, arg := range v.Args {
							if valueMentionsVar(arg, g) && (refconfine.TypeHandsOutMutableReach(g.Type()) || (v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj == g)) {
								okSpec = false
								return
							}
						}
					}
					v.ForEachChildValue(func(ch *flowir.Value) bool {
						checkVal(ch)
						return okSpec
					})
				}
				checkVal(exprBody.Ops[0].Expr)
				if !okSpec {
					return false
				}
				if embedsReach {
					switch {
					case inSettled:
						for c := range carriersOfLHS {
							embeddedOut[c] = true
						}
						if embedsRawData && settledRawExported[lhsVar] {
							*embeddedRawExported = true
						}
						return len(embeddedOut) <= 1
					case isCarrierLHS:
						if !carrierSafeForEmbedding(lhsVar, vs, embedsRawData) {
							return false
						}
						embeddedOut[lhsVar] = true
						if embedsRawData && lhsVar.Exported() {
							*embeddedRawExported = true
						}
						return len(embeddedOut) <= 1
					default:
						return false
					}
				}
				return true
			}
		}
		return false
	}

	for changed := true; changed; {
		changed = false
		for g := range settled {
			keep := true
			embedded := map[*types.Var]bool{}
			rawExported := false
			usedInFuncDecl := false
			specUses := 0
			for dep := range settled {
				if dep == g || !refconfine.TypeHandsOutMutableReach(dep.Type()) || !subtreeUsesObj(p.TypesInfo, candidates[g], dep) {
					continue
				}
				for c := range settled[dep] {
					embedded[c] = true
				}
				if settledRawExported[dep] {
					rawExported = true
				}
				if len(embedded) > 1 {
					keep = false
					break
				}
			}
			for _, file := range p.Syntax {
				if !keep {
					break
				}
				for _, decl := range file.Decls {
					if !keep {
						break
					}
					switch d := decl.(type) {
					case *ast.FuncDecl:
						if d.Body == nil || !subtreeUsesObj(p.TypesInfo, d.Body, g) {
							continue
						}
						usedInFuncDecl = true
						wants := map[syntaxutil.ParamKey]bool{}
						mw := map[syntaxutil.FuncKey]bool{}
						if !enclosingConfinesRoots(audited, p, d, nil, nil, map[types.Object]bool{g: true}, wants, mw, nil) ||
							!wantsResolve(wants, mw) {
							keep = false
						}
					case *ast.GenDecl:
						for _, spec := range d.Specs {
							vs, ok := spec.(*ast.ValueSpec)
							if !ok {
								continue
							}
							isOwnSpec := false
							for _, nm := range vs.Names {
								if p.TypesInfo.Defs[nm] == g {
									isOwnSpec = true
									break
								}
							}
							if isOwnSpec {
								for i, nm := range vs.Names {
									if p.TypesInfo.Defs[nm] == g {
										continue
									}
									if i < len(vs.Values) && subtreeUsesObj(p.TypesInfo, vs.Values[i], g) {
										keep = false
										break
									}
								}
								continue
							}
							if !subtreeUsesObj(p.TypesInfo, vs, g) {
								continue
							}
							specUses++
							if !checkTopValueSpecUse(g, vs, embedded, &rawExported) {
								keep = false
								break
							}
						}
					}
				}
			}
			if keep && rawExported && (usedInFuncDecl || specUses > 1) {
				keep = false
			}
			if keep && !isPureFreshDataExprWith(p, candidates[g], inSettledVar) {
				keep = false
			}
			if !keep {
				delete(settled, g)
				delete(settledRawExported, g)
				changed = true
			} else if !varSetEqual(embedded, settled[g]) || settledRawExported[g] != rawExported {
				settled[g] = embedded
				settledRawExported[g] = rawExported
				changed = true
			}
		}
	}
	return settled
}

func subtreeUsesObj(info *types.Info, root ast.Node, target types.Object) bool {
	if info == nil || root == nil || target == nil {
		return false
	}
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		if id, ok := n.(*ast.Ident); ok {
			if info.Uses[id] == target || info.Defs[id] == target {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func valueMentionsVar(v *flowir.Value, target *types.Var) bool {
	if v == nil || target == nil {
		return false
	}
	hit := false
	v.WalkValues(func(cur *flowir.Value) bool {
		if hit {
			return false
		}
		switch cur.Kind {
		case flowir.ValPlace:
			if cur.Place.Obj == target {
				hit = true
				return false
			}
		case flowir.ValAddrOf:
			if cur.AddrPlace.Obj == target {
				hit = true
				return false
			}
		case flowir.ValMethodVal:
			if cur.HasRecvPlace && cur.RecvPlace.Obj == target {
				hit = true
				return false
			}
		case flowir.ValMakeClosure:
			if cur.Closure != nil && cur.Closure.FreeVars[target] {
				hit = true
				return false
			}
		}
		return true
	})
	return hit
}

func closureExtractsNoCarrierFromRoots(audited bool, b *flowir.Body, carrierAliasRoots map[types.Object]bool) bool {
	if b == nil || len(carrierAliasRoots) == 0 {
		return true
	}
	isScalarType := func(t types.Type) bool {
		return t != nil &&
			!refconfine.CallResultHandsOut(t) &&
			!refconfine.TypeMayCarryUnknownDynamic(audited, t)
	}
	ok := true
	var checkVal func(v *flowir.Value)
	checkVal = func(v *flowir.Value) {
		if !ok || v == nil {
			return
		}
		switch v.Kind {
		case flowir.ValInvalid:
			ok = false
			return
		case flowir.ValPlace:
			if v.Place.Obj != nil && carrierAliasRoots[v.Place.Obj] {
				if len(v.Place.Projs) == 0 || !isScalarType(v.Type) {
					ok = false
					return
				}
				v.Place.ForEachChildValue(func(cv *flowir.Value) bool {
					checkVal(cv)
					return ok
				})
				return
			}
		case flowir.ValAddrOf:
			if v.AddrPlace.Obj != nil && carrierAliasRoots[v.AddrPlace.Obj] {
				ok = false
				return
			}
		case flowir.ValMethodVal:
			if v.HasRecvPlace && v.RecvPlace.Obj != nil && carrierAliasRoots[v.RecvPlace.Obj] {
				ok = false
				return
			}
		case flowir.ValMakeClosure:
			if v.Closure == nil || !closureExtractsNoCarrierFromRoots(audited, v.Closure, carrierAliasRoots) {
				ok = false
			}
			return
		case flowir.ValCompare:
			for _, a := range v.Args {
				if a != nil && a.Kind == flowir.ValPlace && a.Place.IsBareVar() && carrierAliasRoots[a.Place.Obj] {
					continue
				}
				checkVal(a)
				if !ok {
					return
				}
			}
			return
		case flowir.ValCall:
			if v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj != nil && carrierAliasRoots[v.RecvPlace.Obj] {
				ok = false
				return
			}
			if v.CallKind == flowir.CallIIFE {
				if v.IIFE == nil || !closureExtractsNoCarrierFromRoots(audited, v.IIFE, carrierAliasRoots) {
					ok = false
					return
				}
				for _, a := range v.Args {
					checkVal(a)
					if !ok {
						return
					}
				}
				return
			}
			if v.CallKind == flowir.CallBuiltin && (v.BuiltinName == "len" || v.BuiltinName == "cap") {
				for _, a := range v.Args {
					if a != nil && a.Kind == flowir.ValPlace && a.Place.IsBareVar() && carrierAliasRoots[a.Place.Obj] {
						continue
					}
					checkVal(a)
					if !ok {
						return
					}
				}
				return
			}
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			checkVal(ch)
			return ok
		})
	}

	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if !ok {
			return false
		}
		switch op.Kind {
		case flowir.OpAssign:
			if op.AssignKind == flowir.AssignRange && len(op.Srcs) == 1 && op.Srcs[0] != nil &&
				op.Srcs[0].Kind == flowir.ValPlace && op.Srcs[0].Place.IsBareVar() && carrierAliasRoots[op.Srcs[0].Place.Obj] {
				if op.Srcs[0].Type == nil {
					ok = false
					return false
				}
				switch types.Unalias(op.Srcs[0].Type).Underlying().(type) {
				case *types.Chan, *types.Signature:
					ok = false
					return false
				}
				for _, dst := range op.Dsts {
					if dst.IsBlank() {
						continue
					}
					if !dst.IsBareVar() || dst.Obj == nil || !isScalarType(dst.Obj.Type()) {
						ok = false
						return false
					}
				}
				return true
			}
			if op.AssignKind == flowir.AssignMulti && len(op.Dsts) == 2 && len(op.Srcs) == 1 && op.Srcs[0] != nil &&
				op.Srcs[0].Kind == flowir.ValPlace && op.Srcs[0].Place.Obj != nil && carrierAliasRoots[op.Srcs[0].Place.Obj] &&
				len(op.Srcs[0].Place.Projs) == 1 && op.Srcs[0].Place.Projs[0].Kind == flowir.ProjIndex {
				for _, dst := range op.Dsts {
					if dst.IsBlank() {
						continue
					}
					if !dst.IsBareVar() || dst.Obj == nil || !isScalarType(dst.Obj.Type()) {
						ok = false
						return false
					}
				}
				op.Srcs[0].Place.ForEachChildValue(func(cv *flowir.Value) bool {
					checkVal(cv)
					return ok
				})
				return ok
			}
			for _, dst := range op.Dsts {
				if dst.Obj != nil && carrierAliasRoots[dst.Obj] {
					ok = false
					return false
				}
				dst.ForEachChildValue(func(cv *flowir.Value) bool {
					checkVal(cv)
					return ok
				})
			}
			for _, src := range op.Srcs {
				checkVal(src)
			}
		case flowir.OpTypeSwitchBind:
			if op.SwitchDst != nil && carrierAliasRoots[op.SwitchDst] {
				ok = false
				return false
			}
			checkVal(op.SwitchSrc)
		case flowir.OpChanSend:
			if op.ChanPlace.Obj != nil && carrierAliasRoots[op.ChanPlace.Obj] {
				ok = false
				return false
			}
			op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
				checkVal(cv)
				return ok
			})
			checkVal(op.ChanVal)
			checkVal(op.SendVal)
		case flowir.OpReturn:
			if op.IsNaked {
				for _, res := range b.Results {
					if carrierAliasRoots[res] {
						ok = false
						return false
					}
				}
			}
			for _, r := range op.Results {
				checkVal(r)
			}
		case flowir.OpDefer, flowir.OpGo:
			checkVal(op.Call)
		case flowir.OpExpr:
			checkVal(op.Expr)
		}
		return ok
	})
	return ok
}

type rootOriginPolicy struct {
	verifyLocalOrigins   bool
	allowEnclosingParams bool
	inInitFlow           bool
	nestedClosure        bool
	unattestedBroken     map[string]bool
	singleSubjectVars    map[string]bool
	settledGlobals       settledGlobalMap
	currentTargets       []*types.Var
	checkCarryingExpr    func(ast.Expr) bool
	checkCarryingValue   func(*flowir.Value) bool
	checkEnclosingParam  func(pIdx int, paramVar *types.Var) bool
	carrierAliasRoots    map[types.Object]bool
	linkedCarrierGlobals map[string]bool
}

// enclosingConfinesRoots verifies that enclosing never mutates, rebinds after
// initialization, addresses, spawns goroutines with, or leaks mutable backing
// storage of roots outside selfLit (and exemptCall when non-nil).
func enclosingConfinesRoots(
	audited bool,
	p *packages.Package,
	enclosing ast.Node,
	selfLit *ast.FuncLit,
	exemptCall *ast.CallExpr,
	roots map[types.Object]bool,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
	origin *rootOriginPolicy,
) bool {
	if p == nil || p.TypesInfo == nil || enclosing == nil {
		return false
	}
	if len(roots) == 0 {
		return true
	}
	enclBody := lowerEnclosingScope(p.TypesInfo, p.Types, enclosing)
	if enclBody == nil {
		return false
	}

	var exemptMap map[*ast.CallExpr]bool
	if exemptCall != nil {
		exemptMap = map[*ast.CallExpr]bool{exemptCall: true}
	}
	aliases := flowir.BuildEnclosingMemAliasesExcept(
		enclBody,
		func(o types.Object) bool { return syntaxutil.IsLocalVar(o) || roots[o] },
		refconfine.TypeHandsOutMutableReach,
		exemptMap,
	)
	for changed := true; changed; {
		changed = false
		for r := range roots {
			for nb := range aliases[r] {
				if !roots[nb] {
					roots[nb] = true
					changed = true
				}
			}
		}
	}

	var globalRoots []*types.Var
	for r := range roots {
		if r == nil || refconfine.TypeReachesSyncNoCopyByValue(r.Type()) {
			return false
		}
		v, ok := r.(*types.Var)
		if !ok {
			return false
		}
		if syntaxutil.IsLocalVar(v) {
			if origin != nil && !origin.nestedClosure {
				if !enclBody.OwnsVar(v) {
					return false
				}
				nonScalar := refconfine.TypeHandsOutMutableReach(v.Type()) ||
					refconfine.TypeCarriesSignature(v.Type()) ||
					refconfine.TypeMayCarryUnknownDynamic(audited, v.Type())
				if nonScalar && (v == enclBody.Recv || enclBody.ResultSet[v]) {
					return false
				}
				if nonScalar && !origin.allowEnclosingParams {
					if pIdx, isParam := enclBody.ParamIndex[v]; isParam {
						if origin.checkEnclosingParam == nil || !origin.checkEnclosingParam(pIdx, v) {
							return false
						}
					}
				}
			} else {
				if !enclBody.OwnsVar(v) && !enclBody.FreeVars[v] {
					return false
				}
				if origin != nil && origin.verifyLocalOrigins {
					if v == enclBody.Recv || enclBody.ResultSet[v] {
						return false
					}
					if _, isParam := enclBody.ParamIndex[v]; isParam {
						return false
					}
				}
			}
		} else {
			globalRoots = append(globalRoots, v)
		}
	}

	usedCarrierGlobal := false
	var isCleanRootInitValue func(v *flowir.Value) bool
	isCleanRootInitValue = func(v *flowir.Value) bool {
		if v == nil || v.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(v.Type) {
			return false
		}
		if !refconfine.TypeHandsOutMutableReach(v.Type) {
			if !refconfine.TypeCarriesSignature(v.Type) {
				return true
			}
			if v.Kind == flowir.ValPlace && (v.Place.Root == flowir.RootConstOrNil || v.Place.Root == flowir.RootFunc) {
				return true
			}
			if origin != nil && origin.checkCarryingValue != nil {
				return origin.checkCarryingValue(v)
			}
			if origin != nil && origin.checkCarryingExpr != nil && v.Raw != nil {
				return origin.checkCarryingExpr(v.Raw)
			}
			return false
		}
		var settled settledGlobalMap
		var targets []*types.Var
		if origin != nil {
			settled = origin.settledGlobals
			targets = origin.currentTargets
		}
		if v.Raw != nil && isPureFreshDataExpr(p, settled, v.Raw) {
			return true
		}
		switch v.Kind {
		case flowir.ValScalarLitOrConst:
			return true
		case flowir.ValPlace:
			if v.Place.Root == flowir.RootConstOrNil || v.Place.Root == flowir.RootFunc {
				return true
			}
			if v.Place.Root == flowir.RootPkgGlobal {
				gv := v.Place.Obj
				if gv == nil {
					return false
				}
				if settled.allowedForTargets(gv, targets) {
					return true
				}
				if origin != nil && origin.inInitFlow && !origin.nestedClosure && len(v.Place.Projs) == 0 &&
					!gv.IsField() && gv.Pkg() != nil && gv.Parent() == gv.Pkg().Scope() &&
					refconfine.TypeMayCarryUnknownDynamic(audited, gv.Type()) {
					gvKey := syntaxutil.DynamicVarKey(gv)
					if (p.Types == nil || gv.Pkg() != p.Types || !origin.unattestedBroken[gvKey]) && !origin.singleSubjectVars[gvKey] {
						if origin.linkedCarrierGlobals == nil {
							origin.linkedCarrierGlobals = map[string]bool{}
						}
						origin.linkedCarrierGlobals[gvKey] = true
						usedCarrierGlobal = true
						return true
					}
				}
				return false
			}
			if v.Place.Obj != nil && roots[v.Place.Obj] {
				if origin != nil && origin.carrierAliasRoots[v.Place.Obj] {
					usedCarrierGlobal = true
				}
				return true
			}
			if v.Place.Root == flowir.RootTransient && v.Place.Base != nil {
				return isCleanRootInitValue(v.Place.Base)
			}
			return false
		case flowir.ValAllocFresh:
			switch v.AllocKind {
			case flowir.AllocMake, flowir.AllocBuiltinNewType:
				return true
			case flowir.AllocBuiltinNewExpr:
				return len(v.Args) == 1 && isCleanRootInitValue(v.Args[0])
			case flowir.AllocCompositeLit:
				for i := range v.CompositeElts {
					if v.CompositeElts[i].MapKey != nil && !isCleanRootInitValue(v.CompositeElts[i].MapKey) {
						return false
					}
					if v.CompositeElts[i].Value != nil && !isCleanRootInitValue(v.CompositeElts[i].Value) {
						return false
					}
				}
				return true
			}
		case flowir.ValConvert:
			if v.IsTypeAssert {
				return v.Arg != nil && isCleanRootInitValue(v.Arg)
			}
			return !syntaxutil.IsUnsafePointerType(v.Type) && v.Arg != nil && isCleanRootInitValue(v.Arg)
		case flowir.ValCall:
			if v.CallKind == flowir.CallBuiltin {
				switch v.BuiltinName {
				case "make":
					return true
				case "new":
					if v.CallAST != nil && syntaxutil.IsBuiltinNewType(p.TypesInfo, v.CallAST) {
						return true
					}
					return len(v.Args) == 1 && !v.Ellipsis && isCleanRootInitValue(v.Args[0])
				case "append":
					if len(v.Args) == 0 || v.Args[0] == nil || v.Args[0].Raw == nil ||
						!isPureFreshDataExprWith(p, v.Args[0].Raw, nil) {
						return false
					}
					for _, a := range v.Args[1:] {
						if !isCleanRootInitValue(a) {
							return false
						}
					}
					return true
				}
				return false
			}
			if v.CallKind == flowir.CallPlain && v.CalleeFunc != nil && !v.IsMethodExprCall {
				fk := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()}
				if auditedValuePlane[fk] {
					for _, a := range v.Args {
						if !isCleanRootInitValue(a) {
							return false
						}
					}
					return true
				}
			}
		}
		return false
	}

	isOuterOrSigVar := func(v *types.Var) bool {
		if v == nil || !syntaxutil.IsLocalVar(v) {
			return true
		}
		if v == enclBody.Recv || enclBody.ResultSet[v] {
			return true
		}
		if _, isParam := enclBody.ParamIndex[v]; isParam {
			return true
		}
		return v.Pos() < enclBody.BodyStart || v.Pos() > enclBody.BodyEnd
	}

	// valMutableRoots collects mutable-reach roots whose backing memory may be
	// handed out by evaluating v.
	var valMutableRoots func(v *flowir.Value, out map[*types.Var]bool)
	placeMutableRoots := func(pl flowir.Place, out map[*types.Var]bool) {
		if pl.Obj != nil && roots[pl.Obj] && refconfine.CallResultHandsOut(pl.Obj.Type()) {
			out[pl.Obj] = true
		}
		if pl.Root == flowir.RootTransient && pl.Base != nil {
			valMutableRoots(pl.Base, out)
		}
	}
	valMutableRoots = func(v *flowir.Value, out map[*types.Var]bool) {
		if v == nil {
			return
		}
		if selfLit != nil && v.Kind == flowir.ValMakeClosure && v.Lit == selfLit {
			return
		}
		if exemptCall != nil && v.Kind == flowir.ValCall && v.CallAST == exemptCall {
			return
		}
		if v.Kind != flowir.ValAddrOf && v.Kind != flowir.ValMethodVal &&
			v.Type != nil && !refconfine.CallResultHandsOut(v.Type) {
			return
		}
		switch v.Kind {
		case flowir.ValPlace:
			if len(v.Place.Projs) > 0 && v.Type != nil &&
				!refconfine.TypeHandsOutMutableReach(v.Type) &&
				!refconfine.TypeReachesSyncNoCopyByValue(v.Type) {
				return
			}
			placeMutableRoots(v.Place, out)
		case flowir.ValAddrOf:
			if v.AddrPlace.Obj != nil && roots[v.AddrPlace.Obj] {
				out[v.AddrPlace.Obj] = true
			} else if v.AddrPlace.Root == flowir.RootTransient && v.AddrPlace.Base != nil {
				valMutableRoots(v.AddrPlace.Base, out)
			}
		case flowir.ValMethodVal:
			if v.HasRecvPlace && v.RecvPlace.Obj != nil && roots[v.RecvPlace.Obj] {
				out[v.RecvPlace.Obj] = true
			}
			valMutableRoots(v.Recv, out)
		case flowir.ValAllocFresh:
			switch v.AllocKind {
			case flowir.AllocBuiltinNewExpr:
				for _, a := range v.Args {
					valMutableRoots(a, out)
				}
			case flowir.AllocCompositeLit:
				for i := range v.CompositeElts {
					valMutableRoots(v.CompositeElts[i].MapKey, out)
					valMutableRoots(v.CompositeElts[i].Value, out)
				}
			}
		case flowir.ValMakeClosure:
			if v.Closure != nil {
				for fv := range v.Closure.FreeVars {
					if roots[fv] && refconfine.CallResultHandsOut(fv.Type()) {
						out[fv] = true
					}
				}
				for _, gv := range globalRoots {
					if v.Lit != nil && refconfine.CallResultHandsOut(gv.Type()) && subtreeUsesObj(p.TypesInfo, v.Lit.Body, gv) {
						out[gv] = true
					}
				}
			}
		case flowir.ValCall:
			valMutableRoots(v.Recv, out)
			valMutableRoots(v.Callee, out)
			for _, a := range v.Args {
				valMutableRoots(a, out)
			}
		case flowir.ValConvert:
			valMutableRoots(v.Arg, out)
		case flowir.ValChanRecv:
			valMutableRoots(v.Chan, out)
		case flowir.ValCompositeExpr:
			for _, a := range v.Args {
				valMutableRoots(a, out)
			}
		}
	}
	suppliesMutableRoot := func(v *flowir.Value) bool {
		m := map[*types.Var]bool{}
		valMutableRoots(v, m)
		return len(m) > 0
	}

	var valTouchesAnyRoot func(v *flowir.Value) bool
	valTouchesAnyRoot = func(v *flowir.Value) bool {
		if v == nil {
			return false
		}
		hit := false
		v.WalkValues(func(cur *flowir.Value) bool {
			if hit {
				return false
			}
			switch cur.Kind {
			case flowir.ValPlace:
				if cur.Place.Obj != nil && roots[cur.Place.Obj] {
					hit = true
					return false
				}
			case flowir.ValAddrOf:
				if cur.AddrPlace.Obj != nil && roots[cur.AddrPlace.Obj] {
					hit = true
					return false
				}
			case flowir.ValMethodVal:
				if cur.HasRecvPlace && cur.RecvPlace.Obj != nil && roots[cur.RecvPlace.Obj] {
					hit = true
					return false
				}
			case flowir.ValMakeClosure:
				if cur.Closure != nil {
					for fv := range cur.Closure.FreeVars {
						if roots[fv] {
							hit = true
							return false
						}
					}
				}
				if cur.Lit != nil {
					for _, gv := range globalRoots {
						if subtreeUsesObj(p.TypesInfo, cur.Lit.Body, gv) {
							hit = true
							return false
						}
					}
				}
			case flowir.ValCall:
				if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil {
					for fv := range cur.IIFE.FreeVars {
						if roots[fv] {
							hit = true
							return false
						}
					}
					if cur.IIFE.AST != nil {
						for _, gv := range globalRoots {
							if subtreeUsesObj(p.TypesInfo, cur.IIFE.AST, gv) {
								hit = true
								return false
							}
						}
					}
				}
			}
			return true
		})
		return hit
	}

	definedOnce := map[types.Object]bool{}
	sound := true

	var checkValue func(v *flowir.Value)
	checkValue = func(v *flowir.Value) {
		if !sound || v == nil {
			return
		}
		if selfLit != nil && v.Kind == flowir.ValMakeClosure && v.Lit == selfLit {
			return
		}
		if exemptCall != nil && v.Kind == flowir.ValCall && v.CallAST == exemptCall {
			return
		}
		switch v.Kind {
		case flowir.ValInvalid:
			sound = false
			return
		case flowir.ValAddrOf:
			if v.AddrPlace.Obj != nil && roots[v.AddrPlace.Obj] {
				sound = false
				return
			}
			if v.AddrPlace.Root == flowir.RootTransient && suppliesMutableRoot(v.AddrPlace.Base) {
				sound = false
				return
			}
		case flowir.ValMethodVal:
			if v.AutoAddr && v.HasRecvPlace && v.RecvPlace.Obj != nil && roots[v.RecvPlace.Obj] {
				sound = false
				return
			}
			if suppliesMutableRoot(v.Recv) {
				sound = false
				return
			}
		case flowir.ValChanRecv:
			if suppliesMutableRoot(v.Chan) {
				sound = false
				return
			}
		case flowir.ValMakeClosure:
			if v.Lit == nil || v.Closure == nil {
				sound = false
				return
			}
			localRoots := map[types.Object]bool{}
			subRoots := map[types.Object]bool{}
			for fv := range v.Closure.FreeVars {
				if roots[fv] {
					subRoots[fv] = true
					if syntaxutil.IsLocalVar(fv) {
						localRoots[fv] = true
					}
				}
			}
			for _, gv := range globalRoots {
				if subtreeUsesObj(p.TypesInfo, v.Lit.Body, gv) {
					subRoots[gv] = true
				}
			}
			if len(localRoots) > 0 && !boundValueClosureEnvLeakFreeJudged(audited, p, localRoots, v.Lit.Body, wants, methodWants) {
				sound = false
				return
			}
			if len(subRoots) > 0 {
				var subOrigin *rootOriginPolicy
				if origin != nil {
					cp := *origin
					cp.nestedClosure = true
					subOrigin = &cp
				}
				if !enclosingConfinesRoots(audited, p, v.Lit, selfLit, exemptCall, subRoots, wants, methodWants, subOrigin) {
					sound = false
					return
				}
			}
			return
		case flowir.ValCall:
			switch v.CallKind {
			case flowir.CallBuiltin:
				switch v.BuiltinName {
				case "delete", "clear", "close":
					if len(v.Args) > 0 && suppliesMutableRoot(v.Args[0]) {
						sound = false
						return
					}
				case "copy":
					if len(v.Args) > 0 && suppliesMutableRoot(v.Args[0]) {
						sound = false
						return
					}
					if len(v.Args) == 2 && suppliesMutableRoot(v.Args[1]) &&
						(v.Args[0] == nil || elemHandsOutMutableReach(v.Args[0].Type)) {
						sound = false
						return
					}
				case "append":
					if len(v.Args) > 0 && suppliesMutableRoot(v.Args[0]) {
						sound = false
						return
					}
					if len(v.Args) >= 2 &&
						(v.Args[0] == nil || v.Args[0].Raw == nil || !isPureFreshDataExprWith(p, v.Args[0].Raw, nil)) {
						for _, a := range v.Args[1:] {
							if suppliesMutableRoot(a) {
								sound = false
								return
							}
						}
					}
				}
			case flowir.CallPlain:
				if v.CalleeFunc == nil {
					for _, a := range v.Args {
						if suppliesMutableRoot(a) {
							sound = false
							return
						}
					}
					break
				}
				fk := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()}
				if !auditedValuePlane[fk] {
					for i, a := range v.Args {
						if !suppliesMutableRoot(a) {
							continue
						}
						pIdx, pOK := v.ParamIndexForArg(i)
						if wants == nil || !pOK {
							sound = false
							return
						}
						wants[syntaxutil.ParamKey{Func: fk, Index: pIdx}] = true
					}
				}
			case flowir.CallMethod:
				for _, a := range v.Args {
					if suppliesMutableRoot(a) {
						sound = false
						return
					}
				}
				recvMutable := suppliesMutableRoot(v.Recv) ||
					(v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj != nil && roots[v.RecvPlace.Obj])
				if recvMutable {
					if v.IsMethodExprCall || v.Selection == nil {
						sound = false
						return
					}
					fn, ok := v.Selection.Obj().(*types.Func)
					if !ok || fn == nil || syntaxutil.InterfaceReceiver(fn) || refconfine.AuditedSynchronization(audited, fn) {
						sound = false
						return
					}
					if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
						_, ptrRecv := types.Unalias(sig.Recv().Type()).(*types.Pointer)
						if ptrRecv || refconfine.TypeHandsOutMutableReach(sig.Recv().Type()) {
							if methodWants == nil {
								sound = false
								return
							}
							methodWants[syntaxutil.MethodFactKey(fn)] = true
						}
					}
				}
			case flowir.CallIIFE:
				if valTouchesAnyRoot(v) {
					sound = false
					return
				}
			default:
				if suppliesMutableRoot(v.Callee) {
					sound = false
					return
				}
				for _, a := range v.Args {
					if suppliesMutableRoot(a) {
						sound = false
						return
					}
				}
			}
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			checkValue(ch)
			return sound
		})
	}

	enclBody.ForEachSyncOp(func(op *flowir.Op) bool {
		if !sound {
			return false
		}
		switch op.Kind {
		case flowir.OpAssign:
			if op.AssignKind == flowir.AssignRange {
				if len(op.Srcs) != 1 || op.Srcs[0] == nil || op.Srcs[0].Type == nil {
					sound = false
					return false
				}
				bindsRoot := false
				for _, dst := range op.Dsts {
					if dst.Obj != nil && roots[dst.Obj] {
						bindsRoot = true
						break
					}
				}
				switch types.Unalias(op.Srcs[0].Type).Underlying().(type) {
				case *types.Chan:
					if bindsRoot || suppliesMutableRoot(op.Srcs[0]) {
						sound = false
						return false
					}
				case *types.Signature:
					if bindsRoot || suppliesMutableRoot(op.Srcs[0]) || valTouchesAnyRoot(op.Srcs[0]) {
						sound = false
						return false
					}
				}
			}
			op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
				dst.ForEachChildValue(func(cv *flowir.Value) bool {
					checkValue(cv)
					return sound
				})
				if !sound {
					return false
				}
				if dst.Obj != nil && roots[dst.Obj] {
					if !dst.IsBareVar() || !isDef || isOuterOrSigVar(dst.Obj) ||
						op.AssignKind == flowir.AssignCompound || op.AssignKind == flowir.AssignIncDec ||
						definedOnce[dst.Obj] {
						sound = false
						return false
					}
					definedOnce[dst.Obj] = true
					if op.AssignKind != flowir.AssignZeroDecl {
						if src == nil {
							sound = false
							return false
						}
						usedCarrierGlobal = false
						if origin != nil && origin.verifyLocalOrigins && refconfine.TypeHandsOutMutableReach(dst.Obj.Type()) {
							if !isCleanRootInitValue(src) {
								sound = false
								return false
							}
							if usedCarrierGlobal {
								if origin.carrierAliasRoots == nil {
									origin.carrierAliasRoots = map[types.Object]bool{}
								}
								origin.carrierAliasRoots[dst.Obj] = true
							}
						}
						isBareCarrierAlias := usedCarrierGlobal && src.Kind == flowir.ValPlace && len(src.Place.Projs) == 0
						if !isBareCarrierAlias && origin != nil && refconfine.TypeCarriesSignature(dst.Obj.Type()) {
							if !origin.nestedClosure && origin.checkCarryingValue != nil {
								if !origin.checkCarryingValue(src) {
									sound = false
									return false
								}
							} else if !origin.nestedClosure && origin.checkCarryingExpr != nil {
								if src.Raw == nil || !origin.checkCarryingExpr(src.Raw) {
									sound = false
									return false
								}
							}
						}
					}
				} else if dst.Root == flowir.RootTransient && suppliesMutableRoot(dst.Base) {
					sound = false
					return false
				}
				if _, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil && suppliesMutableRoot(keyVal) {
					sound = false
					return false
				}
				if src != nil && suppliesMutableRoot(src) {
					allowedDst := dst.IsBlank() ||
						(dst.IsBareVar() && syntaxutil.IsLocalVar(dst.Obj) && roots[dst.Obj] && isDef && !isOuterOrSigVar(dst.Obj))
					if !allowedDst {
						sound = false
						return false
					}
				}
				return sound
			})
			for _, src := range op.Srcs {
				checkValue(src)
				if !sound {
					return false
				}
			}

		case flowir.OpTypeSwitchBind:
			checkValue(op.SwitchSrc)
			if !sound {
				return false
			}
			if op.SwitchDst != nil && roots[op.SwitchDst] {
				if definedOnce[op.SwitchDst] || op.SwitchSrc == nil {
					sound = false
					return false
				}
				definedOnce[op.SwitchDst] = true
				usedCarrierGlobal = false
				if origin != nil && origin.verifyLocalOrigins && refconfine.TypeHandsOutMutableReach(op.SwitchDst.Type()) {
					if !isCleanRootInitValue(op.SwitchSrc) {
						sound = false
						return false
					}
					if usedCarrierGlobal {
						if origin.carrierAliasRoots == nil {
							origin.carrierAliasRoots = map[types.Object]bool{}
						}
						origin.carrierAliasRoots[op.SwitchDst] = true
					}
				}
				if refconfine.TypeCarriesSignature(op.SwitchDst.Type()) {
					if op.SwitchSrc.Type == nil || !types.Identical(op.SwitchDst.Type(), op.SwitchSrc.Type) {
						sound = false
						return false
					}
					if !usedCarrierGlobal && origin != nil && !origin.nestedClosure {
						if origin.checkCarryingValue != nil {
							if !origin.checkCarryingValue(op.SwitchSrc) {
								sound = false
								return false
							}
						} else if origin.checkCarryingExpr != nil {
							if op.SwitchSrc.Raw == nil || !origin.checkCarryingExpr(op.SwitchSrc.Raw) {
								sound = false
								return false
							}
						}
					}
				}
			} else if op.SwitchDst != nil && op.SwitchSrc != nil && suppliesMutableRoot(op.SwitchSrc) &&
				(op.SwitchDst.Type() == nil ||
					refconfine.TypeHandsOutMutableReach(op.SwitchDst.Type()) ||
					refconfine.TypeCarriesSignature(op.SwitchDst.Type()) ||
					refconfine.TypeReachesSyncNoCopyByValue(op.SwitchDst.Type())) {
				sound = false
				return false
			}

		case flowir.OpChanSend:
			if (op.ChanPlace.Obj != nil && roots[op.ChanPlace.Obj]) ||
				suppliesMutableRoot(op.ChanVal) || suppliesMutableRoot(op.SendVal) {
				sound = false
				return false
			}
			checkValue(op.ChanVal)
			checkValue(op.SendVal)

		case flowir.OpReturn:
			if op.IsNaked {
				for _, res := range enclBody.Results {
					if roots[res] {
						sound = false
						return false
					}
				}
			}
			for _, resVal := range op.Results {
				checkValue(resVal)
				if !sound {
					return false
				}
				m := map[*types.Var]bool{}
				valMutableRoots(resVal, m)
				for r := range m {
					if _, isParam := enclBody.ParamIndex[r]; !isParam {
						sound = false
						return false
					}
				}
			}

		case flowir.OpDefer:
			checkValue(op.Call)

		case flowir.OpGo:
			if valTouchesAnyRoot(op.Call) {
				sound = false
				return false
			}

		case flowir.OpExpr:
			checkValue(op.Expr)
		}
		return sound
	})
	if sound && origin != nil && len(origin.carrierAliasRoots) > 0 {
		for changed := true; changed; {
			changed = false
			for r := range origin.carrierAliasRoots {
				for nb := range aliases[r] {
					if !origin.carrierAliasRoots[nb] {
						origin.carrierAliasRoots[nb] = true
						changed = true
					}
				}
			}
		}
		visitAllBodyOps(enclBody, func(op *flowir.Op) {
			if !sound {
				return
			}
			checkLitVal := func(v *flowir.Value) {
				if !sound || v == nil {
					return
				}
				v.WalkValues(func(cur *flowir.Value) bool {
					if !sound {
						return false
					}
					if cur.Kind == flowir.ValMakeClosure && cur.Lit != selfLit {
						if cur.Closure == nil || !closureExtractsNoCarrierFromRoots(audited, cur.Closure, origin.carrierAliasRoots) {
							sound = false
							return false
						}
					}
					return true
				})
			}
			switch op.Kind {
			case flowir.OpAssign:
				for _, dst := range op.Dsts {
					dst.ForEachChildValue(func(cv *flowir.Value) bool { checkLitVal(cv); return sound })
				}
				for _, src := range op.Srcs {
					checkLitVal(src)
				}
			case flowir.OpTypeSwitchBind:
				checkLitVal(op.SwitchSrc)
			case flowir.OpChanSend:
				op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool { checkLitVal(cv); return sound })
				checkLitVal(op.ChanVal)
				checkLitVal(op.SendVal)
			case flowir.OpReturn:
				for _, r := range op.Results {
					checkLitVal(r)
				}
			case flowir.OpDefer, flowir.OpGo:
				checkLitVal(op.Call)
			case flowir.OpExpr:
				checkLitVal(op.Expr)
			}
		})
	}
	return sound
}

// environmentFreeFuncLit reports whether a function literal registered into a
// carrier is provably environment-free: every variable it references from an
// enclosing function scope proves leak-free and unmutated.
func environmentFreeFuncLit(audited bool, p *packages.Package, lit *ast.FuncLit, enclosing ast.Node) bool {
	return environmentFreeFuncLitJudged(audited, p, lit, enclosing, nil, nil)
}

// environmentFreeFuncLitJudged additionally collects parameter and method wants
// when the caller supplies sinks, instead of refusing deferrable shapes outright.
func environmentFreeFuncLitJudged(
	audited bool,
	p *packages.Package,
	lit *ast.FuncLit,
	enclosing ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
) bool {
	return environmentFreeFuncLitWithOrigin(audited, p, lit, enclosing, wants, methodWants, &rootOriginPolicy{
		verifyLocalOrigins: true,
	})
}

func environmentFreeFuncLitWithOrigin(
	audited bool,
	p *packages.Package,
	lit *ast.FuncLit,
	enclosing ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
	origin *rootOriginPolicy,
) bool {
	if p == nil || p.TypesInfo == nil || lit == nil || lit.Body == nil {
		return false
	}
	litBody := flowir.LowerFuncLit(p.TypesInfo, p.Types, lit)
	if litBody == nil {
		return false
	}
	roots := make(map[types.Object]bool, len(litBody.FreeVars))
	for fv := range litBody.FreeVars {
		roots[fv] = true
	}
	if len(roots) == 0 {
		return true
	}
	if enclosing == nil {
		return false
	}
	if !enclosingConfinesRoots(audited, p, enclosing, lit, nil, roots, wants, methodWants, origin) {
		return false
	}
	if origin != nil && len(origin.carrierAliasRoots) > 0 && !closureExtractsNoCarrierFromRoots(audited, litBody, origin.carrierAliasRoots) {
		return false
	}
	localRoots := make(map[types.Object]bool, len(roots))
	for r := range roots {
		if syntaxutil.IsLocalVar(r) {
			localRoots[r] = true
		}
	}
	if len(localRoots) > 0 && !boundValueClosureEnvLeakFreeJudged(audited, p, localRoots, lit.Body, wants, methodWants) {
		return false
	}
	return true
}

// fieldRegMark is one registered-population disposition for a func-signature
// struct field a carrier can hand out: class 'd' defers the field position to a
// parameter's leak-free fact, class 'p' poisons it. A poison with field ""
// covers the whole population, idx -1 every index.
type fieldRegMark struct {
	class byte
	field string
	idx   int
	param syntaxutil.ParamKey
}

// classifyFieldRegistrants derives the registered-population marks of one
// admitted registration store.
func classifyFieldRegistrants(audited bool, p *packages.Package, lhs, rhs ast.Expr, emit func(fieldRegMark)) {
	if sel, ok := syntaxutil.UnparenExpr(lhs).(*ast.SelectorExpr); ok {
		if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.FieldVal {
			if _, isSig := types.Unalias(selection.Type()).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantValue(audited, p, sel.Sel.Name, rhs, emit)
				return
			}
		}
	}
	classifyRegistrantFlow(audited, p, rhs, emit)
}

func classifyRegistrantFlow(audited bool, p *packages.Package, expr ast.Expr, emit func(fieldRegMark)) {
	switch e := syntaxutil.UnparenExpr(expr).(type) {
	case *ast.CompositeLit:
		classifyRegistrantComposite(audited, p, e, emit)
		return
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			classifyRegistrantFlow(audited, p, e.X, emit)
			return
		}
	case *ast.FuncLit:
		classifyLiteralRegistrant(audited, p, syntaxutil.ElemPositionField, e, emit)
		return
	case *ast.BasicLit:
		return
	case *ast.CallExpr:
		if ident, ok := syntaxutil.UnparenExpr(e.Fun).(*ast.Ident); ok {
			if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
				if ident.Name == "make" || syntaxutil.IsBuiltinNewType(p.TypesInfo, e) {
					return
				}
			}
		}
		for _, arg := range e.Args {
			classifyRegistrantFlow(audited, p, arg, emit)
		}
		return
	case *ast.Ident:
		if obj := syntaxutil.IdentDefOrUse(p.TypesInfo, e); obj != nil {
			switch obj.(type) {
			case *types.Func:
				classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, e, emit)
				return
			case *types.Nil:
				return
			}
		}
	case *ast.SelectorExpr:
		if _, isSelection := p.TypesInfo.Selections[e]; !isSelection {
			if obj, ok := p.TypesInfo.Uses[e.Sel]; ok {
				if _, isFunc := obj.(*types.Func); isFunc {
					classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, e, emit)
					return
				}
			}
		}
	case *ast.IndexExpr, *ast.IndexListExpr:
		if fn, _ := syntaxutil.PlainCalleeFunc(p, e); fn != nil {
			classifyFieldRegistrantValue(audited, p, syntaxutil.ElemPositionField, e, emit)
			return
		}
	}
	if refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(syntaxutil.UnparenExpr(expr))) {
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

func classifyRegistrantComposite(audited bool, p *packages.Package, lit *ast.CompositeLit, emit func(fieldRegMark)) {
	t := p.TypesInfo.TypeOf(lit)
	if t == nil {
		emit(fieldRegMark{class: 'p', idx: -1})
		return
	}
	u := types.Unalias(t).Underlying()
	if ptr, ok := u.(*types.Pointer); ok {
		u = types.Unalias(ptr.Elem()).Underlying()
	}
	switch u := u.(type) {
	case *types.Struct:
		for i, elt := range lit.Elts {
			var field *types.Var
			value := elt
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				value = kv.Value
				if key, ok := kv.Key.(*ast.Ident); ok {
					for j := 0; j < u.NumFields(); j++ {
						if u.Field(j).Name() == key.Name {
							field = u.Field(j)
							break
						}
					}
				}
			} else if i < u.NumFields() {
				field = u.Field(i)
			}
			if field == nil {
				emit(fieldRegMark{class: 'p', idx: -1})
				continue
			}
			if _, isSig := types.Unalias(field.Type()).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantValue(audited, p, field.Name(), value, emit)
				continue
			}
			classifyRegistrantFlow(audited, p, value, emit)
		}
	case *types.Map, *types.Slice, *types.Array:
		syntaxutil.EachCompositeLitFlow(p.TypesInfo, lit, func(flow ast.Expr, _ bool) bool {
			classifyRegistrantFlow(audited, p, flow, emit)
			return true
		})
	default:
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

func classifyFieldRegistrantValue(audited bool, p *packages.Package, field string, value ast.Expr, emit func(fieldRegMark)) {
	deferNamed := func(fn *types.Func) bool {
		if fn == nil || fn.Pkg() == nil {
			return false
		}
		fn = fn.Origin()
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil {
			return false
		}
		fk := syntaxutil.FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}
		for idx := 0; idx < sig.Params().Len(); idx++ {
			emit(fieldRegMark{class: 'd', field: field, idx: idx, param: syntaxutil.ParamKey{Func: fk, Index: idx}})
		}
		return true
	}
	switch v := syntaxutil.UnparenExpr(value).(type) {
	case *ast.FuncLit:
		classifyLiteralRegistrant(audited, p, field, v, emit)
		return
	case *ast.Ident:
		if obj := syntaxutil.IdentDefOrUse(p.TypesInfo, v); obj != nil {
			if _, isNil := obj.(*types.Nil); isNil {
				return
			}
			if fn, ok := obj.(*types.Func); ok && deferNamed(fn) {
				return
			}
		}
	case *ast.SelectorExpr:
		if _, isSelection := p.TypesInfo.Selections[v]; !isSelection {
			if x, ok := v.X.(*ast.Ident); ok {
				if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
					if fn, ok := p.TypesInfo.Uses[v.Sel].(*types.Func); ok && deferNamed(fn) {
						return
					}
				}
			}
		}
	case *ast.IndexExpr, *ast.IndexListExpr:
		if fn, _ := syntaxutil.PlainCalleeFunc(p, v); fn != nil && deferNamed(fn) {
			return
		}
	}
	emit(fieldRegMark{class: 'p', field: field, idx: -1})
}

func classifyLiteralRegistrant(audited bool, p *packages.Package, field string, lit *ast.FuncLit, emit func(fieldRegMark)) {
	if lit.Type == nil || lit.Body == nil {
		emit(fieldRegMark{class: 'p', field: field, idx: -1})
		return
	}
	idx := 0
	if lit.Type.Params != nil {
		for _, group := range lit.Type.Params.List {
			names := group.Names
			if len(names) == 0 {
				idx++
				continue
			}
			for _, name := range names {
				if name.Name == "_" {
					idx++
					continue
				}
				obj := p.TypesInfo.Defs[name]
				if obj == nil {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
					idx++
					continue
				}
				wants := map[syntaxutil.ParamKey]bool{}
				if boundValueLeakFreeJudged(audited, p, map[types.Object]bool{obj: true}, lit.Body, wants, nil, nil, nil, nil) {
					for want := range wants {
						emit(fieldRegMark{class: 'd', field: field, idx: idx, param: want})
					}
				} else {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
				}
				idx++
			}
		}
	}
}

type localCarrierAliases struct {
	root []*types.Var
	all  []*types.Var
}

func isRefHeaderType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch types.Unalias(t).Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Interface:
		return true
	}
	return false
}

func isTypeParamType(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := types.Unalias(t).Underlying().(*types.TypeParam)
	return ok
}

// placeEntersInterior reports whether accessing p (and, when writeContainer is
// true, writing into the slice/channel header designated by p as in copy,
// append, or channel send) crosses an interior pointer, slice, map, channel, or
// interface hop beyond p.Obj's own single root header.
func placeEntersInterior(p flowir.Place, writeContainer bool) bool {
	if p.Obj == nil || p.Obj.Type() == nil || isTypeParamType(p.Obj.Type()) {
		return true
	}
	usedHeader := !isRefHeaderType(p.Obj.Type())
	crossHop := func() bool {
		if usedHeader {
			return true
		}
		usedHeader = true
		return false
	}
	for _, proj := range p.Projs {
		if proj.BaseType == nil || isTypeParamType(proj.BaseType) {
			return true
		}
		baseU := types.Unalias(proj.BaseType).Underlying()
		switch proj.Kind {
		case flowir.ProjDeref:
			if crossHop() {
				return true
			}
		case flowir.ProjIndex:
			switch baseU.(type) {
			case *types.Array:
				// Inline array element: no pointer/header indirection.
			case *types.Pointer, *types.Slice, *types.Map:
				if crossHop() {
					return true
				}
			default:
				return true
			}
		case flowir.ProjSlice:
			switch baseU.(type) {
			case *types.Slice, *types.Array:
				// Re-slicing a slice or inline array yields a slice view without an extra hop.
			case *types.Pointer:
				if crossHop() {
					return true
				}
			default:
				return true
			}
		case flowir.ProjField:
			cur := baseU
			if ptr, isPtr := cur.(*types.Pointer); isPtr {
				if crossHop() {
					return true
				}
				cur = types.Unalias(ptr.Elem()).Underlying()
			}
			if proj.Selection == nil {
				return true
			}
			idx := proj.Selection.Index()
			for _, fi := range idx[:len(idx)-1] {
				st, ok := cur.(*types.Struct)
				if !ok || fi < 0 || fi >= st.NumFields() {
					return true
				}
				ft := st.Field(fi).Type()
				if isTypeParamType(ft) {
					return true
				}
				fu := types.Unalias(ft).Underlying()
				if ptr, isPtr := fu.(*types.Pointer); isPtr {
					if crossHop() {
						return true
					}
					cur = types.Unalias(ptr.Elem()).Underlying()
				} else {
					cur = fu
				}
			}
		default:
			return true
		}
	}
	if writeContainer {
		if crossHop() {
			return true
		}
	}
	return false
}

func visitAllBodyOps(b *flowir.Body, fn func(*flowir.Op)) {
	if b == nil {
		return
	}
	var scanVal func(v *flowir.Value)
	scanVal = func(v *flowir.Value) {
		if v == nil {
			return
		}
		if v.Kind == flowir.ValMakeClosure && v.Closure != nil {
			visitAllBodyOps(v.Closure, fn)
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallIIFE && v.IIFE != nil {
			visitAllBodyOps(v.IIFE, fn)
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			scanVal(ch)
			return true
		})
	}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		fn(op)
		switch op.Kind {
		case flowir.OpAssign:
			for _, dst := range op.Dsts {
				dst.ForEachChildValue(func(cv *flowir.Value) bool {
					scanVal(cv)
					return true
				})
			}
			for _, src := range op.Srcs {
				scanVal(src)
			}
		case flowir.OpTypeSwitchBind:
			scanVal(op.SwitchSrc)
		case flowir.OpChanSend:
			op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
				scanVal(cv)
				return true
			})
			scanVal(op.ChanVal)
			scanVal(op.SendVal)
		case flowir.OpReturn:
			for _, r := range op.Results {
				scanVal(r)
			}
		case flowir.OpDefer, flowir.OpGo:
			scanVal(op.Call)
		case flowir.OpExpr:
			scanVal(op.Expr)
		}
		return true
	})
}

func appendUniqueVars(dst *[]*types.Var, sources []*types.Var) bool {
	if len(sources) == 0 {
		return false
	}
	have := make(map[*types.Var]bool, len(*dst))
	for _, v := range *dst {
		have[v] = true
	}
	changed := false
	for _, v := range sources {
		if v != nil && !have[v] {
			*dst = append(*dst, v)
			have[v] = true
			changed = true
		}
	}
	return changed
}

// recordEnvCarryingRegistrations records, per dynamic-capable package variable
// (own or foreign), whether this package's direct code stores a
// function-carrying value into it that is not provably environment-free.
func recordEnvCarryingRegistrations(
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	callIdx *refconfine.CallSiteIndex,
	initOnly map[string]bool,
	unattestedBroken map[string]bool,
	singleSubjectVars map[string]bool,
	settledGlobals settledGlobalMap,
	paramLeakFree map[syntaxutil.ParamKey]bool,
	readOnly map[string]bool,
	exemptSeamNodes map[ast.Node]bool,
	envCarrying map[string]bool,
	envCarryingFns map[string]map[syntaxutil.FuncKey]bool,
	envCarryingUnattr map[string]bool,
	envCallableVars map[string]bool,
	envCalls map[syntaxutil.EnvCallUse]bool,
	carrierLinks map[syntaxutil.CarrierLink]bool,
	fieldDefer map[syntaxutil.FieldPosKey]map[syntaxutil.ParamKey]bool,
	fieldPoison map[string]map[syntaxutil.FieldParamPoison]bool,
	hooks *syntaxutil.ExplainHookSet,
) {
	if p == nil || p.TypesInfo == nil {
		return
	}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	resolve := func(ident *ast.Ident) (types.Object, bool) {
		if obj, ok := p.TypesInfo.Uses[ident]; ok {
			return obj, true
		}
		if obj, ok := p.TypesInfo.Defs[ident]; ok && obj != nil {
			return obj, true
		}
		return nil, false
	}
	carrierVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable == nil || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		if !refconfine.TypeMayCarryUnknownDynamic(audited, variable.Type()) {
			return nil, false
		}
		return variable, true
	}
	var localAliases map[types.Object]localCarrierAliases
	collectAllTargetVars := func(expr ast.Expr, aliases map[types.Object]localCarrierAliases) []*types.Var {
		var vars []*types.Var
		ast.Inspect(expr, func(n ast.Node) bool {
			if _, isLit := n.(*ast.FuncLit); isLit {
				return false
			}
			if ident, ok := n.(*ast.Ident); ok {
				if obj, ok := resolve(ident); ok {
					if variable, ok := carrierVar(obj); ok {
						appendUniqueVars(&vars, []*types.Var{variable})
					} else {
						appendUniqueVars(&vars, aliases[obj].all)
					}
				}
			}
			return true
		})
		return vars
	}
	collectValueTargetVars := func(v *flowir.Value, aliases map[types.Object]localCarrierAliases) []*types.Var {
		if v == nil {
			return nil
		}
		var vars []*types.Var
		addObj := func(u *types.Var) {
			if u == nil {
				return
			}
			if cv, isC := carrierVar(u); isC {
				appendUniqueVars(&vars, []*types.Var{cv})
			} else {
				appendUniqueVars(&vars, aliases[u].all)
			}
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			switch cur.Kind {
			case flowir.ValMakeClosure:
				return false
			case flowir.ValPlace:
				addObj(cur.Place.Obj)
			case flowir.ValAddrOf:
				addObj(cur.AddrPlace.Obj)
			case flowir.ValMethodVal:
				if cur.HasRecvPlace {
					addObj(cur.RecvPlace.Obj)
				}
			case flowir.ValCall:
				if cur.AutoAddrRecv && cur.HasRecvPlace {
					addObj(cur.RecvPlace.Obj)
				}
				if cur.CallKind == flowir.CallIIFE {
					return false
				}
			}
			return true
		})
		return vars
	}
	targetVars := func(expr ast.Expr, writeContainer bool) []*types.Var {
		if expr == nil {
			return nil
		}
		exprBody := flowir.LowerNode(p.TypesInfo, p.Types, expr)
		if exprBody != nil && len(exprBody.Ops) == 1 && exprBody.Ops[0].Kind == flowir.OpExpr && exprBody.Ops[0].Expr != nil {
			val := exprBody.Ops[0].Expr
			switch val.Kind {
			case flowir.ValPlace:
				dst := val.Place
				if dst.Root == flowir.RootBlank {
					return nil
				}
				if dst.Obj != nil {
					if cv, isC := carrierVar(dst.Obj); isC {
						return []*types.Var{cv}
					}
					if placeEntersInterior(dst, writeContainer) {
						return localAliases[dst.Obj].all
					}
					return localAliases[dst.Obj].root
				}
				if dst.Root == flowir.RootTransient && dst.Base != nil {
					return collectValueTargetVars(dst.Base, localAliases)
				}
			case flowir.ValAddrOf:
				if val.IsArraySlice && val.AddrPlace.Obj != nil {
					if cv, isC := carrierVar(val.AddrPlace.Obj); isC {
						return []*types.Var{cv}
					}
					if placeEntersInterior(val.AddrPlace, false) {
						return localAliases[val.AddrPlace.Obj].all
					}
					return localAliases[val.AddrPlace.Obj].root
				}
			}
		}
		return collectAllTargetVars(expr, localAliases)
	}
	computeLocalAliases := func(scopeNode ast.Node, parent map[types.Object]localCarrierAliases) map[types.Object]localCarrierAliases {
		aliased := map[types.Object]localCarrierAliases{}
		for obj, entry := range parent {
			aliased[obj] = localCarrierAliases{
				root: append([]*types.Var(nil), entry.root...),
				all:  append([]*types.Var(nil), entry.all...),
			}
		}
		lowered := lowerEnclosingScope(p.TypesInfo, p.Types, scopeNode)
		if lowered == nil {
			return aliased
		}
		memAliases := flowir.BuildScopedMemAliases(lowered, syntaxutil.IsLocalVar, refconfine.TypeHandsOutMutableReach)
		addrTakenBare := map[*types.Var]bool{}
		visitAllBodyOps(lowered, func(op *flowir.Op) {
			checkAddr := func(v *flowir.Value) {
				if v == nil {
					return
				}
				v.WalkValues(func(cur *flowir.Value) bool {
					if cur.Kind == flowir.ValAddrOf && !cur.IsArraySlice && cur.AddrPlace.IsBareVar() {
						addrTakenBare[cur.AddrPlace.Obj] = true
					}
					if cur.Kind == flowir.ValMethodVal && cur.AutoAddr && cur.HasRecvPlace && cur.RecvPlace.IsBareVar() {
						addrTakenBare[cur.RecvPlace.Obj] = true
					}
					if cur.Kind == flowir.ValCall && cur.AutoAddrRecv && cur.HasRecvPlace && cur.RecvPlace.IsBareVar() {
						addrTakenBare[cur.RecvPlace.Obj] = true
					}
					return true
				})
			}
			switch op.Kind {
			case flowir.OpAssign:
				for _, dst := range op.Dsts {
					dst.ForEachChildValue(func(cv *flowir.Value) bool { checkAddr(cv); return true })
				}
				for _, src := range op.Srcs {
					checkAddr(src)
				}
			case flowir.OpTypeSwitchBind:
				checkAddr(op.SwitchSrc)
			case flowir.OpChanSend:
				op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool { checkAddr(cv); return true })
				checkAddr(op.ChanVal)
				checkAddr(op.SendVal)
			case flowir.OpReturn:
				for _, r := range op.Results {
					checkAddr(r)
				}
			case flowir.OpDefer, flowir.OpGo:
				checkAddr(op.Call)
			case flowir.OpExpr:
				checkAddr(op.Expr)
			}
		})

		addAliases := func(dst types.Object, rootSrcs, allSrcs []*types.Var) bool {
			if dst == nil || (len(rootSrcs) == 0 && len(allSrcs) == 0) {
				return false
			}
			if _, isC := carrierVar(dst); isC {
				return false
			}
			entry := aliased[dst]
			changed := false
			if len(rootSrcs) > 0 && (isRefHeaderType(dst.Type()) || isTypeParamType(dst.Type())) {
				if appendUniqueVars(&entry.root, rootSrcs) {
					changed = true
				}
				if appendUniqueVars(&entry.all, rootSrcs) {
					changed = true
				}
			}
			if appendUniqueVars(&entry.all, allSrcs) {
				changed = true
			}
			if changed {
				aliased[dst] = entry
			}
			return changed
		}

		valSources := func(v *flowir.Value) (rootSrcs, allSrcs []*types.Var) {
			if v == nil {
				return nil, nil
			}
			allSrcs = collectValueTargetVars(v, aliased)
			if len(allSrcs) == 0 {
				return nil, nil
			}
			switch v.Kind {
			case flowir.ValAllocFresh:
				return nil, allSrcs
			case flowir.ValPlace:
				if v.Place.IsBareVar() {
					if cv, isC := carrierVar(v.Place.Obj); isC {
						if isRefHeaderType(cv.Type()) || isTypeParamType(cv.Type()) {
							return []*types.Var{cv}, allSrcs
						}
						return nil, allSrcs
					}
					return aliased[v.Place.Obj].root, allSrcs
				}
				if v.Place.Obj != nil && len(v.Place.Projs) == 1 && v.Place.Projs[0].Kind == flowir.ProjSlice {
					if cv, isC := carrierVar(v.Place.Obj); isC {
						return []*types.Var{cv}, allSrcs
					}
					return aliased[v.Place.Obj].root, allSrcs
				}
				return allSrcs, allSrcs
			case flowir.ValAddrOf:
				if v.AddrPlace.Obj != nil {
					if _, isC := carrierVar(v.AddrPlace.Obj); isC {
						return allSrcs, allSrcs
					}
					if v.IsArraySlice {
						if placeEntersInterior(v.AddrPlace, false) {
							return allSrcs, allSrcs
						}
						return aliased[v.AddrPlace.Obj].root, allSrcs
					}
					if v.AddrPlace.IsBareVar() {
						return nil, allSrcs
					}
					if !placeEntersInterior(v.AddrPlace, false) {
						return aliased[v.AddrPlace.Obj].root, allSrcs
					}
				}
				return allSrcs, allSrcs
			default:
				return allSrcs, allSrcs
			}
		}

		propagateMem := func(obj *types.Var, derefStore bool, rootSrcs, allSrcs []*types.Var) bool {
			if len(memAliases[obj]) == 0 {
				return false
			}
			changed := false
			visited := map[types.Object]bool{obj: true}
			queue := []types.Object{obj}
			for len(queue) > 0 {
				cur := queue[len(queue)-1]
				queue = queue[:len(queue)-1]
				for next := range memAliases[cur] {
					if visited[next] {
						continue
					}
					visited[next] = true
					var nextRoot []*types.Var
					if derefStore {
						if nv, ok := next.(*types.Var); ok && addrTakenBare[nv] {
							nextRoot = rootSrcs
						}
					}
					if addAliases(next, nextRoot, allSrcs) {
						changed = true
					}
					queue = append(queue, next)
				}
			}
			return changed
		}

		bindObj := func(obj *types.Var, composite, inPlace, derefStore bool, rootSrcs, allSrcs []*types.Var) bool {
			if obj == nil || (len(rootSrcs) == 0 && len(allSrcs) == 0) || !syntaxutil.IsLocalVar(obj) {
				return false
			}
			if !composite && !inPlace && !refconfine.TypeHandsOutMutableReach(obj.Type()) && !isTypeParamType(obj.Type()) {
				return false
			}
			var ownRoot []*types.Var
			if (!composite && !inPlace) || (derefStore && addrTakenBare[obj]) {
				ownRoot = rootSrcs
			}
			changed := addAliases(obj, ownRoot, allSrcs)
			if propagateMem(obj, derefStore, rootSrcs, allSrcs) {
				changed = true
			}
			return changed
		}

		bindPlace := func(dst flowir.Place, rootSrcs, allSrcs []*types.Var, inPlace bool) bool {
			if len(rootSrcs) == 0 && len(allSrcs) == 0 {
				return false
			}
			derefStore := !inPlace && len(dst.Projs) >= 1 && dst.Projs[len(dst.Projs)-1].Kind == flowir.ProjDeref
			if dst.Obj != nil {
				return bindObj(dst.Obj, !dst.IsBareVar(), inPlace, derefStore, rootSrcs, allSrcs)
			}
			if dst.Root == flowir.RootTransient && dst.Base != nil {
				changed := false
				dst.Base.WalkValues(func(cur *flowir.Value) bool {
					if cur.Kind == flowir.ValMakeClosure {
						return false
					}
					if cur.Kind == flowir.ValPlace && cur.Place.Obj != nil {
						if bindObj(cur.Place.Obj, true, !derefStore, derefStore, rootSrcs, allSrcs) {
							changed = true
						}
					} else if cur.Kind == flowir.ValAddrOf && cur.AddrPlace.Obj != nil {
						if bindObj(cur.AddrPlace.Obj, true, !derefStore, derefStore, rootSrcs, allSrcs) {
							changed = true
						}
					}
					return true
				})
				return changed
			}
			return false
		}

		bindValTarget := func(target *flowir.Value, allSrcs []*types.Var) bool {
			if target == nil || len(allSrcs) == 0 {
				return false
			}
			if target.Kind == flowir.ValPlace {
				return bindPlace(target.Place, nil, allSrcs, true)
			}
			changed := false
			target.WalkValues(func(cur *flowir.Value) bool {
				if cur.Kind == flowir.ValMakeClosure {
					return false
				}
				if cur.Kind == flowir.ValPlace && cur.Place.Obj != nil {
					if bindObj(cur.Place.Obj, true, true, false, nil, allSrcs) {
						changed = true
					}
				} else if cur.Kind == flowir.ValAddrOf && cur.AddrPlace.Obj != nil {
					if bindObj(cur.AddrPlace.Obj, true, true, false, nil, allSrcs) {
						changed = true
					}
				}
				return true
			})
			return changed
		}

		for changed := true; changed; {
			changed = false
			var scanCallBinds func(v *flowir.Value)
			scanCallBinds = func(v *flowir.Value) {
				if v == nil || v.Kind == flowir.ValMakeClosure {
					return
				}
				if v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin {
					switch {
					case v.BuiltinName == "copy" && len(v.Args) == 2:
						_, allSrcs := valSources(v.Args[1])
						if bindValTarget(v.Args[0], allSrcs) {
							changed = true
						}
					case v.BuiltinName == "append" && len(v.Args) >= 2:
						for _, elem := range v.Args[1:] {
							_, allSrcs := valSources(elem)
							if bindValTarget(v.Args[0], allSrcs) {
								changed = true
							}
						}
					}
				}
				v.ForEachChildValue(func(ch *flowir.Value) bool {
					scanCallBinds(ch)
					return true
				})
			}
			visitAllBodyOps(lowered, func(op *flowir.Op) {
				switch op.Kind {
				case flowir.OpAssign:
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						rootSrcs, allSrcs := valSources(src)
						if op.AssignKind == flowir.AssignRange {
							rootSrcs = allSrcs
						}
						if bindPlace(dst, rootSrcs, allSrcs, false) {
							changed = true
						}
						if mapPlace, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil {
							_, keyAll := valSources(keyVal)
							if bindPlace(mapPlace, nil, keyAll, true) {
								changed = true
							}
						}
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							scanCallBinds(cv)
							return true
						})
						return true
					})
					for _, src := range op.Srcs {
						scanCallBinds(src)
					}
				case flowir.OpTypeSwitchBind:
					if op.SwitchDst != nil && syntaxutil.IsLocalVar(op.SwitchDst) {
						rootSrcs, allSrcs := valSources(op.SwitchSrc)
						if bindObj(op.SwitchDst, false, false, false, rootSrcs, allSrcs) {
							changed = true
						}
					}
					scanCallBinds(op.SwitchSrc)
				case flowir.OpChanSend:
					_, sendAll := valSources(op.SendVal)
					if bindPlace(op.ChanPlace, nil, sendAll, true) {
						changed = true
					}
					scanCallBinds(op.ChanVal)
					scanCallBinds(op.SendVal)
				case flowir.OpReturn:
					for _, r := range op.Results {
						scanCallBinds(r)
					}
				case flowir.OpDefer, flowir.OpGo:
					scanCallBinds(op.Call)
				case flowir.OpExpr:
					scanCallBinds(op.Expr)
				}
			})
		}
		return aliased
	}

	wantsResolve := func(wants map[syntaxutil.ParamKey]bool, methodWants map[syntaxutil.FuncKey]bool) bool {
		for w := range wants {
			if w.Func.Pkg != ownPath || !paramLeakFree[w] {
				return false
			}
		}
		for mw := range methodWants {
			if mw.Pkg != ownPath || !readOnly[mw.Name] {
				return false
			}
		}
		return true
	}

	isSyncInitFlowScope := func(scope ast.Node) bool {
		if scope == nil {
			return true
		}
		fd, ok := scope.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || fd.Name == nil {
			return false
		}
		return fd.Name.Name == "init" || (!fd.Name.IsExported() && initOnly[fd.Name.Name])
	}

	type singleWriteCacheEntry struct {
		initExpr ast.Expr
		ok       bool
	}
	singleWriteCache := map[*types.Var]singleWriteCacheEntry{}
	singleWriteTopLevelInit := func(cv *types.Var) (ast.Expr, bool) {
		if p.Types == nil || cv == nil || cv.Pkg() != p.Types || cv.Parent() != p.Types.Scope() {
			return nil, false
		}
		if cached, seen := singleWriteCache[cv]; seen {
			return cached.initExpr, cached.ok
		}
		fail := func() (ast.Expr, bool) {
			singleWriteCache[cv] = singleWriteCacheEntry{}
			return nil, false
		}
		if refconfine.TypeHandsOutMutableReach(cv.Type()) || refconfine.TypeReachesSyncNoCopyByValue(cv.Type()) {
			return fail()
		}
		cvKey := syntaxutil.DynamicVarKey(cv)
		if unattestedBroken[cvKey] || singleSubjectVars[cvKey] {
			return fail()
		}
		defs := 0
		var initExpr ast.Expr
		mutatedOrAddressed := false
		scanLowered := func(b *flowir.Body) {
			if b == nil || mutatedOrAddressed {
				return
			}
			visitAllBodyOps(b, func(op *flowir.Op) {
				if mutatedOrAddressed {
					return
				}
				checkAddrVal := func(v *flowir.Value) {
					if v == nil || mutatedOrAddressed {
						return
					}
					v.WalkValues(func(cur *flowir.Value) bool {
						if mutatedOrAddressed {
							return false
						}
						switch cur.Kind {
						case flowir.ValAddrOf:
							if cur.AddrPlace.Obj == cv {
								mutatedOrAddressed = true
								return false
							}
						case flowir.ValMethodVal:
							if cur.AutoAddr && cur.HasRecvPlace && cur.RecvPlace.Obj == cv {
								mutatedOrAddressed = true
								return false
							}
						case flowir.ValCall:
							if cur.AutoAddrRecv && cur.HasRecvPlace && cur.RecvPlace.Obj == cv {
								mutatedOrAddressed = true
								return false
							}
						}
						return true
					})
				}
				switch op.Kind {
				case flowir.OpAssign:
					for _, dst := range op.Dsts {
						if dst.Obj == cv {
							mutatedOrAddressed = true
							return
						}
						dst.ForEachChildValue(func(ch *flowir.Value) bool { checkAddrVal(ch); return !mutatedOrAddressed })
					}
					for _, src := range op.Srcs {
						checkAddrVal(src)
					}
				case flowir.OpTypeSwitchBind:
					if op.SwitchDst == cv {
						mutatedOrAddressed = true
						return
					}
					checkAddrVal(op.SwitchSrc)
				case flowir.OpChanSend:
					if op.ChanPlace.Obj == cv {
						mutatedOrAddressed = true
						return
					}
					op.ChanPlace.ForEachChildValue(func(ch *flowir.Value) bool { checkAddrVal(ch); return !mutatedOrAddressed })
					checkAddrVal(op.ChanVal)
					checkAddrVal(op.SendVal)
				case flowir.OpReturn:
					for _, r := range op.Results {
						checkAddrVal(r)
					}
				case flowir.OpDefer, flowir.OpGo:
					checkAddrVal(op.Call)
				case flowir.OpExpr:
					checkAddrVal(op.Expr)
				}
			})
		}
		for _, file := range p.Syntax {
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						for i, nm := range vs.Names {
							if nm != nil && p.TypesInfo.Defs[nm] == cv {
								defs++
								if d.Tok == token.VAR && len(vs.Names) == len(vs.Values) {
									initExpr = vs.Values[i]
								} else {
									mutatedOrAddressed = true
								}
							}
						}
						for _, val := range vs.Values {
							scanLowered(flowir.LowerNode(p.TypesInfo, p.Types, val))
						}
					}
				case *ast.FuncDecl:
					if d.Body != nil {
						scanLowered(flowir.LowerFunc(p.TypesInfo, p.Types, d))
					}
				}
				if mutatedOrAddressed || defs > 1 {
					return fail()
				}
			}
		}
		if defs != 1 || initExpr == nil || mutatedOrAddressed {
			return fail()
		}
		singleWriteCache[cv] = singleWriteCacheEntry{initExpr: initExpr, ok: true}
		return initExpr, true
	}

	var enclosingScope ast.Node
	var currentRegFn syntaxutil.FuncKey
	var currentTargets []*types.Var
	var pendingEnvCalls map[syntaxutil.FuncKey]bool
	var pendingCarrierLinks map[string]bool
	var carrying func(expr ast.Expr) bool
	visitingSingleWriteVars := map[*types.Var]bool{}
	visitingInitParams := map[syntaxutil.ParamKey]bool{}

	carryingAtScope := func(scope ast.Node, expr ast.Expr) bool {
		prev := enclosingScope
		enclosingScope = scope
		defer func() { enclosingScope = prev }()
		return carrying(expr)
	}

	var checkCapturedSigOriginAtScope func(scope ast.Node, expr ast.Expr) bool
	var checkInitOnlyParamAtCallSites func(fd *ast.FuncDecl, pIdx int, paramVar *types.Var) bool

	checkCapturedSigOriginAtScope = func(scope ast.Node, expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		if !carryingAtScope(scope, expr) {
			return true
		}
		if !isSyncInitFlowScope(scope) {
			return false
		}
		var targetIdent *ast.Ident
		switch u := syntaxutil.UnparenExpr(expr).(type) {
		case *ast.Ident:
			targetIdent = u
		case *ast.SelectorExpr:
			if x, ok := syntaxutil.UnparenExpr(u.X).(*ast.Ident); ok {
				if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
					targetIdent = u.Sel
				}
			}
		}
		if targetIdent == nil {
			return false
		}
		obj, ok := resolve(targetIdent)
		if !ok {
			return false
		}
		v, ok := obj.(*types.Var)
		if !ok || v == nil {
			return false
		}
		if p.Types != nil && v.Pkg() == p.Types && v.Parent() == p.Types.Scope() {
			if visitingSingleWriteVars[v] {
				return false
			}
			cvInit, ok := singleWriteTopLevelInit(v)
			if !ok {
				return false
			}
			visitingSingleWriteVars[v] = true
			defer delete(visitingSingleWriteVars, v)
			return checkCapturedSigOriginAtScope(nil, cvInit)
		}
		if callerFD, isFD := scope.(*ast.FuncDecl); isFD && syntaxutil.IsLocalVar(v) {
			if callIdx != nil {
				if cp, isParam := callIdx.Params[v]; isParam && !callIdx.Written[v] {
					return checkInitOnlyParamAtCallSites(callerFD, cp.Index, v)
				}
			}
			if !visitingSingleWriteVars[v] && !refconfine.TypeHandsOutMutableReach(v.Type()) {
				fnBody := flowir.LowerFunc(p.TypesInfo, p.Types, callerFD)
				if fnBody != nil && fnBody.OwnsVar(v) && v != fnBody.Recv && !fnBody.ResultSet[v] {
					if _, isParam := fnBody.ParamIndex[v]; !isParam {
						defs := 0
						var initRaw ast.Expr
						bad := false
						visitAllBodyOps(fnBody, func(op *flowir.Op) {
							if bad {
								return
							}
							checkAddr := func(val *flowir.Value) {
								if val == nil || bad {
									return
								}
								val.WalkValues(func(cur *flowir.Value) bool {
									if (cur.Kind == flowir.ValAddrOf && cur.AddrPlace.Obj == v) ||
										(cur.Kind == flowir.ValMethodVal && cur.AutoAddr && cur.HasRecvPlace && cur.RecvPlace.Obj == v) ||
										(cur.Kind == flowir.ValCall && cur.AutoAddrRecv && cur.HasRecvPlace && cur.RecvPlace.Obj == v) {
										bad = true
										return false
									}
									return true
								})
							}
							switch op.Kind {
							case flowir.OpAssign:
								op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
									if dst.Obj == v {
										if dst.IsBareVar() && isDef && src != nil && src.Raw != nil &&
											op.AssignKind != flowir.AssignCompound && op.AssignKind != flowir.AssignIncDec {
											defs++
											initRaw = src.Raw
										} else {
											bad = true
										}
									}
									dst.ForEachChildValue(func(cv *flowir.Value) bool { checkAddr(cv); return !bad })
									return !bad
								})
								for _, src := range op.Srcs {
									checkAddr(src)
								}
							case flowir.OpTypeSwitchBind:
								if op.SwitchDst == v {
									bad = true
								}
								checkAddr(op.SwitchSrc)
							case flowir.OpChanSend:
								if op.ChanPlace.Obj == v {
									bad = true
								}
								checkAddr(op.ChanVal)
								checkAddr(op.SendVal)
							case flowir.OpReturn:
								for _, r := range op.Results {
									checkAddr(r)
								}
							case flowir.OpDefer, flowir.OpGo:
								checkAddr(op.Call)
							case flowir.OpExpr:
								checkAddr(op.Expr)
							}
						})
						if !bad && defs == 1 && initRaw != nil {
							visitingSingleWriteVars[v] = true
							defer delete(visitingSingleWriteVars, v)
							return checkCapturedSigOriginAtScope(callerFD, initRaw)
						}
					}
				}
			}
		}
		return false
	}

	checkInitOnlyParamAtCallSites = func(fd *ast.FuncDecl, pIdx int, paramVar *types.Var) bool {
		if fd == nil || fd.Recv != nil || fd.Name == nil || fd.Name.IsExported() || !initOnly[fd.Name.Name] ||
			idx == nil || callIdx == nil || paramVar == nil {
			return false
		}
		fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
		if !ok || fn == nil || callIdx.Escaped[fn] {
			return false
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig == nil || pIdx < 0 || pIdx >= sig.Params().Len() {
			return false
		}
		pk := syntaxutil.ParamKey{Func: syntaxutil.FuncKey{Pkg: ownPath, Name: fn.Name()}, Index: pIdx}
		if visitingInitParams[pk] {
			return false
		}
		visitingInitParams[pk] = true
		defer delete(visitingInitParams, pk)

		isVariadicSlot := sig.Variadic() && pIdx == sig.Params().Len()-1
		for _, call := range callIdx.Calls[fn] {
			if call == nil || idx.InFuncLit[call] || idx.InGoStmt[call] {
				return false
			}
			var callerScope ast.Node
			if callerFD := idx.EnclFunc[call]; callerFD != nil {
				callerScope = callerFD
			}
			if !isSyncInitFlowScope(callerScope) {
				return false
			}
			if len(call.Args) == 1 && sig.Params().Len() > 1 {
				if _, isTup := p.TypesInfo.TypeOf(call.Args[0]).(*types.Tuple); isTup {
					return false
				}
			}
			if !isVariadicSlot || call.Ellipsis.IsValid() {
				if pIdx >= len(call.Args) {
					return false
				}
				arg := call.Args[pIdx]
				if refconfine.TypeReachesSyncNoCopyByValue(paramVar.Type()) {
					return false
				}
				if refconfine.TypeCarriesSignature(paramVar.Type()) && !checkCapturedSigOriginAtScope(callerScope, arg) {
					return false
				}
				if refconfine.TypeHandsOutMutableReach(paramVar.Type()) && !isPureFreshDataExpr(p, settledGlobals, arg) {
					return false
				}
				continue
			}
			sl, isSl := types.Unalias(paramVar.Type()).Underlying().(*types.Slice)
			if !isSl {
				return false
			}
			elemT := sl.Elem()
			if refconfine.TypeReachesSyncNoCopyByValue(elemT) {
				return false
			}
			for ai := pIdx; ai < len(call.Args); ai++ {
				arg := call.Args[ai]
				if refconfine.TypeCarriesSignature(elemT) && !checkCapturedSigOriginAtScope(callerScope, arg) {
					return false
				}
				if refconfine.TypeHandsOutMutableReach(elemT) && !isPureFreshDataExpr(p, settledGlobals, arg) {
					return false
				}
			}
		}
		return true
	}

	checkLocalCarryingInit := func(initExpr ast.Expr) bool {
		return checkCapturedSigOriginAtScope(enclosingScope, initExpr)
	}

	carrying = func(expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		switch e := syntaxutil.UnparenExpr(expr).(type) {
		case *ast.CompositeLit:
			return !syntaxutil.EachCompositeLitFlow(p.TypesInfo, e, func(flow ast.Expr, _ bool) bool {
				return !carrying(flow)
			})
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				return carrying(e.X)
			}
		case *ast.FuncLit:
			wants := map[syntaxutil.ParamKey]bool{}
			methodWants := map[syntaxutil.FuncKey]bool{}
			var checkParamFn func(int, *types.Var) bool
			if fd, isFD := enclosingScope.(*ast.FuncDecl); isFD && isSyncInitFlowScope(fd) && fd.Name != nil && fd.Name.Name != "init" {
				checkParamFn = func(pIdx int, pv *types.Var) bool {
					return checkInitOnlyParamAtCallSites(fd, pIdx, pv)
				}
			}
			origin := &rootOriginPolicy{
				verifyLocalOrigins:   true,
				allowEnclosingParams: false,
				inInitFlow:           isSyncInitFlowScope(enclosingScope),
				unattestedBroken:     unattestedBroken,
				singleSubjectVars:    singleSubjectVars,
				settledGlobals:       settledGlobals,
				currentTargets:       currentTargets,
				checkCarryingExpr:    checkLocalCarryingInit,
				checkEnclosingParam:  checkParamFn,
			}
			if !environmentFreeFuncLitWithOrigin(audited, p, e, enclosingScope, wants, methodWants, origin) {
				return true
			}
			if !wantsResolve(wants, methodWants) {
				return true
			}
			if origin.inInitFlow && pendingCarrierLinks != nil {
				for gvKey := range origin.linkedCarrierGlobals {
					pendingCarrierLinks[gvKey] = true
				}
			}
			return false
		case *ast.BasicLit:
			return false
		case *ast.CallExpr:
			if ident, ok := syntaxutil.UnparenExpr(e.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
					switch ident.Name {
					case "make":
						return false
					case "new":
						if syntaxutil.IsBuiltinNewType(p.TypesInfo, e) {
							return false
						}
						return len(e.Args) != 1 || carrying(e.Args[0])
					case "append":
						for _, arg := range e.Args {
							if carrying(arg) {
								return true
							}
						}
						return false
					}
				}
			}
			if tv, ok := p.TypesInfo.Types[e.Fun]; ok && tv.IsType() && len(e.Args) == 1 && !e.Ellipsis.IsValid() {
				argT := p.TypesInfo.TypeOf(e.Args[0])
				if argT != nil && types.Identical(types.Unalias(tv.Type).Underlying(), types.Unalias(argT).Underlying()) {
					return carrying(e.Args[0])
				}
				if id, isId := syntaxutil.UnparenExpr(e.Args[0]).(*ast.Ident); isId {
					if _, isNil := syntaxutil.IdentDefOrUse(p.TypesInfo, id).(*types.Nil); isNil {
						return false
					}
				}
				if _, isIface := types.Unalias(tv.Type).Underlying().(*types.Interface); isIface {
					return carrying(e.Args[0])
				}
			}
			if fn, pkgPath := syntaxutil.PlainCalleeFunc(p, e.Fun); fn != nil {
				calleeFK := syntaxutil.FuncKey{Pkg: pkgPath, Name: fn.Name()}
				if auditedValuePlane[calleeFK] {
					for _, arg := range e.Args {
						if carrying(arg) {
							return true
						}
					}
					return false
				}
				if pendingEnvCalls != nil && refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(e)) {
					for _, arg := range e.Args {
						if carrying(arg) {
							return true
						}
						if argT := p.TypesInfo.TypeOf(arg); argT != nil && refconfine.TypeHandsOutMutableReach(argT) {
							if !isSettledReachArg(audited, p, settledGlobals, currentTargets, enclosingScope, e, paramLeakFree, readOnly, checkLocalCarryingInit, arg) {
								return true
							}
						}
					}
					pendingEnvCalls[calleeFK] = true
					return false
				}
			}
		case *ast.Ident:
			if obj, ok := resolve(e); ok {
				switch obj.(type) {
				case *types.Func, *types.Nil, *types.Const:
					return false
				}
			}
		case *ast.SelectorExpr:
			if selection, ok := p.TypesInfo.Selections[e]; ok {
				switch selection.Kind() {
				case types.MethodExpr:
					return false
				case types.MethodVal:
					return true
				}
				break
			}
			if obj, ok := p.TypesInfo.Uses[e.Sel]; ok {
				switch obj.(type) {
				case *types.Func, *types.Const:
					return false
				}
			}
		case *ast.IndexExpr, *ast.IndexListExpr:
			if fn, _ := syntaxutil.PlainCalleeFunc(p, e); fn != nil {
				return false
			}
		}
		return refconfine.TypeCarriesSignature(p.TypesInfo.TypeOf(syntaxutil.UnparenExpr(expr)))
	}

	poisonExemptTargets := func(lhs ast.Expr) {
		if fieldPoison == nil {
			return
		}
		for _, variable := range targetVars(lhs, false) {
			key := syntaxutil.DynamicVarKey(variable)
			if fieldPoison[key] == nil {
				fieldPoison[key] = map[syntaxutil.FieldParamPoison]bool{}
			}
			fieldPoison[key][syntaxutil.FieldParamPoison{Owner: key}] = true
		}
	}

	handleStore := func(lhs, rhs ast.Expr, rebindable, writeContainer bool) {
		if rebindable {
			if ident, ok := syntaxutil.UnparenExpr(lhs).(*ast.Ident); ok {
				if obj, ok := resolve(ident); ok {
					if _, isCarrier := carrierVar(obj); !isCarrier {
						return
					}
				}
			}
		}
		targets := targetVars(lhs, writeContainer)
		if len(targets) == 0 {
			return
		}
		flows := []ast.Expr{rhs}
		if call, ok := syntaxutil.UnparenExpr(rhs).(*ast.CallExpr); ok && len(call.Args) > 0 {
			if ident, ok := syntaxutil.UnparenExpr(call.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && ident.Name == "append" {
					var baseIdent *ast.Ident
					switch base := syntaxutil.UnparenExpr(call.Args[0]).(type) {
					case *ast.Ident:
						baseIdent = base
					case *ast.SelectorExpr:
						if x, ok := base.X.(*ast.Ident); ok {
							if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
								baseIdent = base.Sel
							}
						}
					}
					if baseIdent != nil {
						if obj, ok := resolve(baseIdent); ok {
							if variable, ok := carrierVar(obj); ok && len(targets) == 1 && variable == targets[0] {
								flows = call.Args[1:]
							}
						}
					}
				}
			}
		}
		if _, mapKey, ok := syntaxutil.LHSMapWriteKey(p.TypesInfo, lhs); ok {
			flows = append(flows, mapKey)
		}
		poison := false
		pendingEnvCalls = map[syntaxutil.FuncKey]bool{}
		pendingCarrierLinks = map[string]bool{}
		prevTargets := currentTargets
		currentTargets = targets
		var poisonAt token.Pos
		for _, flow := range flows {
			if carrying(flow) {
				poison = true
				poisonAt = flow.Pos()
				break
			}
		}
		currentTargets = prevTargets
		if poison {
			for _, variable := range targets {
				key := syntaxutil.DynamicVarKey(variable)
				syntaxutil.ExplainStoreMark(hooks, p, key, poisonAt)
				envCarrying[key] = true
				if envCallableVars != nil {
					if _, isFunc := types.Unalias(variable.Type()).Underlying().(*types.Signature); isFunc {
						envCallableVars[key] = true
					}
				}
				if currentRegFn.Valid() {
					if envCarryingFns != nil {
						if envCarryingFns[key] == nil {
							envCarryingFns[key] = map[syntaxutil.FuncKey]bool{}
						}
						envCarryingFns[key][currentRegFn] = true
					}
				} else if envCarryingUnattr != nil {
					envCarryingUnattr[key] = true
				}
			}
		} else {
			if len(pendingEnvCalls) > 0 {
				for _, variable := range targets {
					key := syntaxutil.DynamicVarKey(variable)
					if envCallableVars != nil {
						if _, isFunc := types.Unalias(variable.Type()).Underlying().(*types.Signature); isFunc {
							envCallableVars[key] = true
						}
					}
					if envCalls != nil {
						for callee := range pendingEnvCalls {
							envCalls[syntaxutil.EnvCallUse{Key: key, Callee: callee, Func: currentRegFn}] = true
						}
					}
				}
			}
			if carrierLinks != nil && len(pendingCarrierLinks) > 0 {
				for gvKey := range pendingCarrierLinks {
					for _, variable := range targets {
						key := syntaxutil.DynamicVarKey(variable)
						if key != gvKey {
							carrierLinks[syntaxutil.CarrierLink{From: key, To: gvKey}] = true
						}
					}
				}
			}
			if fieldDefer != nil {
				var marks []fieldRegMark
				for _, flow := range flows {
					classifyFieldRegistrants(audited, p, lhs, flow, func(m fieldRegMark) {
						marks = append(marks, m)
					})
				}
				for _, variable := range targets {
					key := syntaxutil.DynamicVarKey(variable)
					for _, m := range marks {
						switch m.class {
						case 'd':
							pos := syntaxutil.FieldPosKey{Owner: key, Field: m.field, Index: m.idx}
							if fieldDefer[pos] == nil {
								fieldDefer[pos] = map[syntaxutil.ParamKey]bool{}
							}
							fieldDefer[pos][m.param] = true
						case 'p':
							if fieldPoison[key] == nil {
								fieldPoison[key] = map[syntaxutil.FieldParamPoison]bool{}
							}
							if m.field == "" {
								fieldPoison[key][syntaxutil.FieldParamPoison{Owner: key}] = true
							} else {
								fieldPoison[key][syntaxutil.FieldParamPoison{Owner: key, HasPos: true, Field: m.field, Index: m.idx}] = true
							}
						}
					}
				}
			}
		}
		pendingEnvCalls = nil
		pendingCarrierLinks = nil
	}

	var walkStores func(body ast.Node, scope ast.Node, aliases map[types.Object]localCarrierAliases)
	walkStores = func(body ast.Node, scope ast.Node, aliases map[types.Object]localCarrierAliases) {
		if expr, ok := body.(ast.Expr); ok {
			if lit, isLit := syntaxutil.UnparenExpr(expr).(*ast.FuncLit); isLit {
				if lit.Body != nil {
					walkStores(lit.Body, lit, computeLocalAliases(lit, aliases))
				}
				return
			}
		}
		prevScope := enclosingScope
		prevAliases := localAliases
		enclosingScope = scope
		localAliases = aliases
		defer func() {
			enclosingScope = prevScope
			localAliases = prevAliases
		}()

		ast.Inspect(body, func(n ast.Node) bool {
			if n == body {
				return true
			}
			switch n := n.(type) {
			case *ast.FuncLit:
				if n.Body != nil {
					walkStores(n.Body, n, computeLocalAliases(n, aliases))
				}
				return false
			case *ast.GoStmt:
				if n.Call != nil {
					walkStores(n.Call, n, aliases)
				}
				return false
			case *ast.CallExpr:
				if ident, ok := syntaxutil.UnparenExpr(n.Fun).(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						switch {
						case ident.Name == "copy" && len(n.Args) == 2:
							handleStore(n.Args[0], n.Args[1], false, true)
						case ident.Name == "append" && len(n.Args) > 1:
							for _, flow := range n.Args[1:] {
								handleStore(n.Args[0], flow, false, true)
							}
						}
					}
				}
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, lhs := range n.Lhs {
						if exemptSeamNodes[lhs] {
							poisonExemptTargets(lhs)
							continue
						}
						handleStore(lhs, n.Rhs[i], true, false)
					}
				} else if len(n.Rhs) == 1 {
					for _, lhs := range n.Lhs {
						if exemptSeamNodes[lhs] {
							poisonExemptTargets(lhs)
							continue
						}
						handleStore(lhs, n.Rhs[0], true, false)
					}
				}
			case *ast.IncDecStmt:
				if _, mapKey, ok := syntaxutil.LHSMapWriteKey(p.TypesInfo, n.X); ok {
					handleStore(n.X, mapKey, false, false)
				}
			case *ast.RangeStmt:
				for _, bind := range []ast.Expr{n.Key, n.Value} {
					if bind != nil && n.Tok == token.ASSIGN {
						handleStore(bind, n.X, true, false)
					}
				}
			case *ast.SendStmt:
				handleStore(n.Chan, n.Value, false, true)
			}
			return true
		})
	}

	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Body != nil {
					if ownPath != "" && decl.Recv == nil && decl.Name != nil &&
						!initOnly[decl.Name.Name] && decl.Name.Name != "init" &&
						decl.Name.Name != "TestMain" && decl.Name.Name != "_" {
						currentRegFn = syntaxutil.FuncKey{Pkg: ownPath, Name: decl.Name.Name}
					}
					walkStores(decl.Body, decl, computeLocalAliases(decl, nil))
					currentRegFn = syntaxutil.FuncKey{}
				}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					if len(vs.Names) == len(vs.Values) {
						for i, name := range vs.Names {
							handleStore(name, vs.Values[i], true, false)
							walkStores(vs.Values[i], nil, nil)
						}
					} else if len(vs.Values) == 1 {
						for _, name := range vs.Names {
							handleStore(name, vs.Values[0], true, false)
						}
						walkStores(vs.Values[0], nil, nil)
					}
				}
			}
		}
	}
}
