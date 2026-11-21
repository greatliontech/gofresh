package flowir

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (l *lowerer) tryLowerPlace(expr ast.Expr) (Place, bool) {
	if expr == nil {
		return Place{}, false
	}
	unp := syntaxutil.UnparenExpr(expr)
	switch e := unp.(type) {
	case *ast.Ident:
		if e.Name == "_" {
			return Place{
				Root:    RootBlank,
				RootPos: e.Pos(),
				RootRaw: e,
				Type:    l.info.TypeOf(expr),
				Raw:     expr,
			}, true
		}
		obj := syntaxutil.IdentDefOrUse(l.info, e)
		switch o := obj.(type) {
		case *types.Var:
			rk := l.classifyVarRoot(o)
			if rk == RootInvalid {
				return Place{}, false
			}
			return Place{
				Root:    rk,
				RootPos: e.Pos(),
				RootRaw: e,
				Obj:     o,
				Type:    l.info.TypeOf(expr),
				Raw:     expr,
			}, true
		case *types.Func:
			return Place{
				Root:    RootFunc,
				RootPos: e.Pos(),
				RootRaw: e,
				Func:    o,
				FuncPkg: pkgPathOf(o, l.pkg),
				Type:    l.info.TypeOf(expr),
				Raw:     expr,
			}, true
		case *types.Const, *types.Nil:
			return Place{
				Root:       RootConstOrNil,
				RootPos:    e.Pos(),
				RootRaw:    e,
				ConstOrNil: o,
				Type:       l.info.TypeOf(expr),
				Raw:        expr,
			}, true
		default:
			return Place{}, false
		}

	case *ast.SelectorExpr:
		if id, ok := syntaxutil.UnparenExpr(e.X).(*ast.Ident); ok {
			if _, isPkg := l.info.Uses[id].(*types.PkgName); isPkg {
				obj := l.info.Uses[e.Sel]
				switch o := obj.(type) {
				case *types.Var:
					return Place{
						Root:    RootPkgGlobal,
						RootPos: e.Sel.Pos(),
						RootRaw: e,
						Obj:     o,
						Type:    l.info.TypeOf(expr),
						Raw:     expr,
					}, true
				case *types.Func:
					return Place{
						Root:    RootFunc,
						RootPos: e.Sel.Pos(),
						RootRaw: e,
						Func:    o,
						FuncPkg: pkgPathOf(o, l.pkg),
						Type:    l.info.TypeOf(expr),
						Raw:     expr,
					}, true
				case *types.Const:
					return Place{
						Root:       RootConstOrNil,
						RootPos:    e.Sel.Pos(),
						RootRaw:    e,
						ConstOrNil: o,
						Type:       l.info.TypeOf(expr),
						Raw:        expr,
					}, true
				default:
					return Place{}, false
				}
			}
		}
		sel := l.info.Selections[e]
		if sel == nil {
			return Place{}, false
		}
		switch sel.Kind() {
		case types.FieldVal:
			fVar, _ := sel.Obj().(*types.Var)
			base := l.lowerPlace(e.X)
			base.Projs = append(base.Projs, Proj{
				Kind:      ProjField,
				Field:     fVar,
				Selection: sel,
				Indirect:  sel.Indirect(),
				BaseType:  l.info.TypeOf(e.X),
				Type:      l.info.TypeOf(e),
				Raw:       e,
			})
			base.Type = l.info.TypeOf(expr)
			base.Raw = expr
			return base, true
		case types.MethodExpr:
			l.scanTypeExprNestedHazards(e.X)
			fn, _ := sel.Obj().(*types.Func)
			return Place{
				Root:         RootFunc,
				RootPos:      e.Sel.Pos(),
				RootRaw:      e,
				Func:         fn,
				FuncPkg:      pkgPathOf(fn, l.pkg),
				IsMethodExpr: true,
				Type:         l.info.TypeOf(expr),
				Raw:          expr,
			}, true
		default:
			return Place{}, false
		}

	case *ast.IndexExpr:
		if tv, ok := l.info.Types[syntaxutil.UnparenExpr(e.Index)]; ok && tv.IsType() {
			l.scanTypeExprNestedHazards(e.Index)
			base, ok := l.tryLowerPlace(e.X)
			if !ok {
				return Place{}, false
			}
			base.Type = l.info.TypeOf(expr)
			base.Raw = expr
			return base, true
		}
		base := l.lowerPlace(e.X)
		base.Projs = append(base.Projs, Proj{
			Kind:     ProjIndex,
			Key:      l.lowerValue(e.Index),
			BaseType: l.info.TypeOf(e.X),
			Type:     l.info.TypeOf(e),
			Raw:      e,
		})
		base.Type = l.info.TypeOf(expr)
		base.Raw = expr
		return base, true

	case *ast.IndexListExpr:
		for _, idx := range e.Indices {
			l.scanTypeExprNestedHazards(idx)
		}
		base, ok := l.tryLowerPlace(e.X)
		if !ok {
			return Place{}, false
		}
		base.Type = l.info.TypeOf(expr)
		base.Raw = expr
		return base, true

	case *ast.SliceExpr:
		if typeMayBeValueArray(l.info.TypeOf(e.X)) {
			return Place{}, false
		}
		base := l.lowerPlace(e.X)
		var lowV, highV, maxV *Value
		if e.Low != nil {
			lowV = l.lowerValue(e.Low)
		}
		if e.High != nil {
			highV = l.lowerValue(e.High)
		}
		if e.Max != nil {
			maxV = l.lowerValue(e.Max)
		}
		base.Projs = append(base.Projs, Proj{
			Kind:     ProjSlice,
			Low:      lowV,
			High:     highV,
			Max:      maxV,
			BaseType: l.info.TypeOf(e.X),
			Type:     l.info.TypeOf(e),
			Raw:      e,
		})
		base.Type = l.info.TypeOf(expr)
		base.Raw = expr
		return base, true

	case *ast.StarExpr:
		if tv, ok := l.info.Types[e]; ok && tv.IsType() {
			return Place{}, false
		}
		base := l.lowerPlace(e.X)
		base.Projs = append(base.Projs, Proj{
			Kind:     ProjDeref,
			BaseType: l.info.TypeOf(e.X),
			Type:     l.info.TypeOf(e),
			Raw:      e,
		})
		base.Type = l.info.TypeOf(expr)
		base.Raw = expr
		return base, true
	}
	return Place{}, false
}

func (l *lowerer) lowerPlace(expr ast.Expr) Place {
	if p, ok := l.tryLowerPlace(expr); ok {
		return p
	}
	var rootPos token.Pos
	if expr != nil {
		rootPos = expr.Pos()
	}
	return Place{
		Root:    RootTransient,
		RootPos: rootPos,
		RootRaw: syntaxutil.UnparenExpr(expr),
		Base:    l.lowerValue(expr),
		Type:    l.info.TypeOf(expr),
		Raw:     expr,
	}
}

func (l *lowerer) lowerValue(expr ast.Expr) *Value {
	v := l.lowerValueRaw(expr)
	if v != nil && expr != nil {
		if tv, ok := l.info.Types[syntaxutil.UnparenExpr(expr)]; ok && tv.Value != nil {
			v.IsConst = true
		}
	}
	return v
}

func (l *lowerer) lowerValueRaw(expr ast.Expr) *Value {
	if expr == nil {
		return nil
	}
	if tv, ok := l.info.Types[syntaxutil.UnparenExpr(expr)]; ok && tv.IsType() {
		l.scanTypeExprNestedHazards(expr)
		return &Value{
			Kind:       ValScalarLitOrConst,
			Type:       tv.Type,
			Raw:        expr,
			IsTypeExpr: true,
		}
	}
	unp := syntaxutil.UnparenExpr(expr)
	switch e := unp.(type) {
	case *ast.BasicLit:
		return &Value{
			Kind: ValScalarLitOrConst,
			Type: l.info.TypeOf(expr),
			Raw:  expr,
		}

	case *ast.FuncLit:
		child := LowerFuncLit(l.info, l.pkg, e)
		if child == nil && e.Type != nil {
			l.scanTypeExprNestedHazards(e.Type)
		}
		l.bubbleChild(child)
		return &Value{
			Kind:    ValMakeClosure,
			Type:    l.info.TypeOf(expr),
			Raw:     expr,
			Lit:     e,
			Closure: child,
		}

	case *ast.CompositeLit:
		return l.lowerCompositeLit(e, expr)

	case *ast.UnaryExpr:
		switch e.Op {
		case token.AND:
			if comp, ok := syntaxutil.UnparenExpr(e.X).(*ast.CompositeLit); ok {
				return l.lowerCompositeLit(comp, expr)
			}
			return &Value{
				Kind:      ValAddrOf,
				Type:      l.info.TypeOf(expr),
				Raw:       expr,
				AddrPlace: l.lowerPlace(e.X),
			}
		case token.ARROW:
			return &Value{
				Kind: ValChanRecv,
				Type: l.info.TypeOf(expr),
				Raw:  expr,
				Chan: l.lowerValue(e.X),
			}
		default:
			return &Value{
				Kind: ValCompositeExpr,
				Type: l.info.TypeOf(expr),
				Raw:  expr,
				Args: []*Value{l.lowerValue(e.X)},
			}
		}

	case *ast.BinaryExpr:
		if e.Op == token.EQL || e.Op == token.NEQ {
			return &Value{
				Kind:      ValCompare,
				Type:      l.info.TypeOf(expr),
				Raw:       expr,
				CompareOp: e.Op,
				Left:      l.lowerValue(e.X),
				Right:     l.lowerValue(e.Y),
			}
		}
		return &Value{
			Kind: ValCompositeExpr,
			Type: l.info.TypeOf(expr),
			Raw:  expr,
			Args: []*Value{l.lowerValue(e.X), l.lowerValue(e.Y)},
		}

	case *ast.SliceExpr:
		if typeMayBeValueArray(l.info.TypeOf(e.X)) {
			var lowV, highV, maxV *Value
			if e.Low != nil {
				lowV = l.lowerValue(e.Low)
			}
			if e.High != nil {
				highV = l.lowerValue(e.High)
			}
			if e.Max != nil {
				maxV = l.lowerValue(e.Max)
			}
			return &Value{
				Kind:         ValAddrOf,
				Type:         l.info.TypeOf(expr),
				Raw:          expr,
				AddrPlace:    l.lowerPlace(e.X),
				IsArraySlice: true,
				Low:          lowV,
				High:         highV,
				Max:          maxV,
			}
		}

	case *ast.SelectorExpr:
		if sel := l.info.Selections[e]; sel != nil && sel.Kind() == types.MethodVal {
			fn, _ := sel.Obj().(*types.Func)
			rp, hasRP := l.tryLowerPlace(e.X)
			return &Value{
				Kind:         ValMethodVal,
				Type:         l.info.TypeOf(expr),
				Raw:          expr,
				Recv:         l.lowerValue(e.X),
				RecvPlace:    rp,
				HasRecvPlace: hasRP,
				Method:       fn,
				Selection:    sel,
				AutoAddr:     selectionImplicitlyAddressesRecv(l.info, e, sel),
			}
		}

	case *ast.TypeAssertExpr:
		if e.Type != nil {
			l.scanTypeExprNestedHazards(e.Type)
		}
		return &Value{
			Kind:         ValConvert,
			Type:         l.info.TypeOf(expr),
			Raw:          expr,
			Arg:          l.lowerValue(e.X),
			IsTypeAssert: true,
		}

	case *ast.CallExpr:
		return l.lowerCall(e, expr)
	}

	if p, ok := l.tryLowerPlace(expr); ok {
		if p.Root == RootConstOrNil {
			_, isNil := p.ConstOrNil.(*types.Nil)
			return &Value{
				Kind:  ValScalarLitOrConst,
				Type:  l.info.TypeOf(expr),
				Raw:   expr,
				IsNil: isNil,
			}
		}
		return &Value{
			Kind:  ValPlace,
			Type:  l.info.TypeOf(expr),
			Raw:   expr,
			Place: p,
		}
	}
	return &Value{
		Kind: ValInvalid,
		Type: l.info.TypeOf(expr),
		Raw:  expr,
	}
}

func (l *lowerer) lowerCompositeLit(lit *ast.CompositeLit, outerExpr ast.Expr) *Value {
	if lit.Type != nil {
		l.scanTypeExprNestedHazards(lit.Type)
	}
	litT := l.info.TypeOf(lit)
	elemT := litT
	if ptr, ok := syntaxutil.UnderlyingType(elemT).(*types.Pointer); ok {
		elemT = ptr.Elem()
	}
	st, isStruct := syntaxutil.UnderlyingType(elemT).(*types.Struct)
	isMap := syntaxutil.TypeMayBeMap(elemT)

	elts := make([]CompositeElt, 0, len(lit.Elts))
	for i, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if isStruct {
				var fVar *types.Var
				if keyID, ok := kv.Key.(*ast.Ident); ok {
					fVar, _ = l.info.Uses[keyID].(*types.Var)
				}
				elts = append(elts, CompositeElt{
					Field: fVar,
					Value: l.lowerValue(kv.Value),
				})
			} else if isMap {
				elts = append(elts, CompositeElt{
					MapKey: l.lowerValue(kv.Key),
					Value:  l.lowerValue(kv.Value),
				})
			} else {
				elts = append(elts, CompositeElt{
					Index: l.lowerValue(kv.Key),
					Value: l.lowerValue(kv.Value),
				})
			}
			continue
		}
		var fVar *types.Var
		if isStruct && st != nil && i < st.NumFields() {
			fVar = st.Field(i)
		}
		elts = append(elts, CompositeElt{
			Field: fVar,
			Value: l.lowerValue(elt),
		})
	}
	return &Value{
		Kind:          ValAllocFresh,
		Type:          l.info.TypeOf(outerExpr),
		Raw:           outerExpr,
		AllocKind:     AllocCompositeLit,
		ElemType:      elemT,
		CompositeElts: elts,
	}
}

func (l *lowerer) lowerCall(call *ast.CallExpr, outerExpr ast.Expr) *Value {
	// 1. Type conversion `T(x)`
	if tv, ok := l.info.Types[syntaxutil.UnparenExpr(call.Fun)]; ok && tv.IsType() {
		l.scanTypeExprNestedHazards(call.Fun)
		if len(call.Args) == 1 && !call.Ellipsis.IsValid() {
			return &Value{
				Kind: ValConvert,
				Type: l.info.TypeOf(outerExpr),
				Raw:  outerExpr,
				Arg:  l.lowerValue(call.Args[0]),
			}
		}
		return &Value{
			Kind: ValInvalid,
			Type: l.info.TypeOf(outerExpr),
			Raw:  outerExpr,
		}
	}

	calleeSel, _ := unwrapCalleeSelector(l.info, call.Fun)

	// 2. Builtin call
	if b := syntaxutil.LookupBuiltin(l.info, call.Fun); b != nil {
		switch b.Name() {
		case "make":
			if len(call.Args) > 0 {
				l.scanTypeExprNestedHazards(call.Args[0])
			}
			var sizeArgs []*Value
			if len(call.Args) > 1 {
				sizeArgs = l.lowerValues(call.Args[1:])
			}
			return &Value{
				Kind:      ValAllocFresh,
				Type:      l.info.TypeOf(outerExpr),
				Raw:       outerExpr,
				AllocKind: AllocMake,
				Args:      sizeArgs,
			}
		case "new":
			if syntaxutil.IsBuiltinNewType(l.info, call) {
				if len(call.Args) > 0 {
					l.scanTypeExprNestedHazards(call.Args[0])
				}
				return &Value{
					Kind:      ValAllocFresh,
					Type:      l.info.TypeOf(outerExpr),
					Raw:       outerExpr,
					AllocKind: AllocBuiltinNewType,
				}
			}
			return &Value{
				Kind:      ValAllocFresh,
				Type:      l.info.TypeOf(outerExpr),
				Raw:       outerExpr,
				AllocKind: AllocBuiltinNewExpr,
				Args:      l.lowerValues(call.Args),
				Ellipsis:  call.Ellipsis.IsValid(),
			}
		default:
			var valArgs []*Value
			for _, a := range call.Args {
				if tv, ok := l.info.Types[syntaxutil.UnparenExpr(a)]; ok && tv.IsType() {
					l.scanTypeExprNestedHazards(a)
					continue
				}
				valArgs = append(valArgs, l.lowerValue(a))
			}
			return &Value{
				Kind:        ValCall,
				Type:        l.info.TypeOf(outerExpr),
				Raw:         outerExpr,
				CallKind:    CallBuiltin,
				CallAST:     call,
				CalleeSel:   calleeSel,
				BuiltinName: b.Name(),
				Args:        valArgs,
				Ellipsis:    call.Ellipsis.IsValid(),
			}
		}
	}

	// 3. Direct IIFE `(func(...) { ... })(args...)`
	if lit, ok := syntaxutil.UnparenExpr(call.Fun).(*ast.FuncLit); ok {
		child := LowerFuncLit(l.info, l.pkg, lit)
		if child == nil && lit.Type != nil {
			l.scanTypeExprNestedHazards(lit.Type)
		}
		l.bubbleChild(child)
		return &Value{
			Kind:      ValCall,
			Type:      l.info.TypeOf(outerExpr),
			Raw:       outerExpr,
			CallKind:  CallIIFE,
			CallAST:   call,
			CalleeSig: sigOf(l.info.TypeOf(lit)),
			IIFE:      child,
			Args:      l.lowerValues(call.Args),
			Ellipsis:  call.Ellipsis.IsValid(),
		}
	}

	// 4. Plain named function call (bare, package-qualified, or generic-instantiated)
	if fn, pkgPath, sig := l.resolvePlainCallee(call.Fun); fn != nil {
		return &Value{
			Kind:       ValCall,
			Type:       l.info.TypeOf(outerExpr),
			Raw:        outerExpr,
			CallKind:   CallPlain,
			CallAST:    call,
			CalleeSel:  calleeSel,
			CalleeFunc: fn,
			CalleePkg:  pkgPath,
			CalleeSig:  sig,
			Args:       l.lowerValues(call.Args),
			Ellipsis:   call.Ellipsis.IsValid(),
		}
	}

	// 5. Method call `x.M(args...)` or method-expression call `(*T).M(recv, args...)`
	if calleeSel != nil {
		if selection := l.info.Selections[calleeSel]; selection != nil {
			switch selection.Kind() {
			case types.MethodVal:
				fn, _ := selection.Obj().(*types.Func)
				rp, hasRP := l.tryLowerPlace(calleeSel.X)
				return &Value{
					Kind:         ValCall,
					Type:         l.info.TypeOf(outerExpr),
					Raw:          outerExpr,
					CallKind:     CallMethod,
					CallAST:      call,
					CalleeSel:    calleeSel,
					CalleeFunc:   fn,
					CalleePkg:    pkgPathOf(fn, l.pkg),
					CalleeSig:    sigOf(selection.Type()),
					Selection:    selection,
					AutoAddrRecv: selectionImplicitlyAddressesRecv(l.info, calleeSel, selection),
					Recv:         l.lowerValue(calleeSel.X),
					RecvPlace:    rp,
					HasRecvPlace: hasRP,
					Args:         l.lowerValues(call.Args),
					Ellipsis:     call.Ellipsis.IsValid(),
				}
			case types.MethodExpr:
				l.scanTypeExprNestedHazards(calleeSel.X)
				if len(call.Args) >= 1 {
					fn, _ := selection.Obj().(*types.Func)
					rp, hasRP := l.tryLowerPlace(call.Args[0])
					return &Value{
						Kind:             ValCall,
						Type:             l.info.TypeOf(outerExpr),
						Raw:              outerExpr,
						CallKind:         CallMethod,
						CallAST:          call,
						CalleeSel:        calleeSel,
						CalleeFunc:       fn,
						CalleePkg:        pkgPathOf(fn, l.pkg),
						CalleeSig:        stripMethodExprRecvParam(sigOf(selection.Type())),
						Selection:        selection,
						IsMethodExprCall: true,
						Recv:             l.lowerValue(call.Args[0]),
						RecvPlace:        rp,
						HasRecvPlace:     hasRP,
						Args:             l.lowerValues(call.Args[1:]),
						Ellipsis:         call.Ellipsis.IsValid(),
					}
				}
			}
		}
	}

	// 6. Indirect call (func var, signature struct field, dispatch-map index, etc.)
	return &Value{
		Kind:      ValCall,
		Type:      l.info.TypeOf(outerExpr),
		Raw:       outerExpr,
		CallKind:  CallIndirect,
		CallAST:   call,
		CalleeSel: calleeSel,
		Callee:    l.lowerValue(call.Fun),
		CalleeSig: sigOf(l.info.TypeOf(call.Fun)),
		Args:      l.lowerValues(call.Args),
		Ellipsis:  call.Ellipsis.IsValid(),
	}
}

func (l *lowerer) resolvePlainCallee(fun ast.Expr) (*types.Func, string, *types.Signature) {
	instSig := sigOf(l.info.TypeOf(syntaxutil.UnparenExpr(fun)))
	cur := syntaxutil.UnparenExpr(fun)
	for {
		switch x := cur.(type) {
		case *ast.IndexListExpr:
			for _, idx := range x.Indices {
				l.scanTypeExprNestedHazards(idx)
			}
			cur = syntaxutil.UnparenExpr(x.X)
		case *ast.IndexExpr:
			if tv, ok := l.info.Types[syntaxutil.UnparenExpr(x.Index)]; ok && tv.IsType() {
				l.scanTypeExprNestedHazards(x.Index)
				cur = syntaxutil.UnparenExpr(x.X)
				continue
			}
			return nil, "", nil
		default:
			goto unwrapped
		}
	}
unwrapped:
	switch x := cur.(type) {
	case *ast.Ident:
		fn, ok := l.info.Uses[x].(*types.Func)
		if !ok || fn == nil {
			return nil, "", nil
		}
		fnSig := sigOf(fn.Type())
		if fnSig == nil || fnSig.Recv() != nil {
			return nil, "", nil
		}
		if instSig == nil {
			instSig = fnSig
		}
		return fn, pkgPathOf(fn, l.pkg), instSig
	case *ast.SelectorExpr:
		id, ok := syntaxutil.UnparenExpr(x.X).(*ast.Ident)
		if !ok {
			return nil, "", nil
		}
		if _, isPkg := l.info.Uses[id].(*types.PkgName); !isPkg {
			return nil, "", nil
		}
		fn, ok := l.info.Uses[x.Sel].(*types.Func)
		if !ok || fn == nil {
			return nil, "", nil
		}
		fnSig := sigOf(fn.Type())
		if fnSig == nil || fnSig.Recv() != nil {
			return nil, "", nil
		}
		if instSig == nil {
			instSig = fnSig
		}
		return fn, pkgPathOf(fn, l.pkg), instSig
	default:
		return nil, "", nil
	}
}

func unwrapCalleeSelector(info *types.Info, fun ast.Expr) (*ast.SelectorExpr, bool) {
	cur := syntaxutil.UnparenExpr(fun)
	for {
		switch x := cur.(type) {
		case *ast.IndexListExpr:
			cur = syntaxutil.UnparenExpr(x.X)
		case *ast.IndexExpr:
			if tv, ok := info.Types[syntaxutil.UnparenExpr(x.Index)]; ok && tv.IsType() {
				cur = syntaxutil.UnparenExpr(x.X)
				continue
			}
			return nil, false
		case *ast.SelectorExpr:
			return x, true
		default:
			return nil, false
		}
	}
}

func selectionImplicitlyAddressesRecv(info *types.Info, sel *ast.SelectorExpr, selection *types.Selection) bool {
	if info == nil || sel == nil || selection == nil {
		return false
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok || fn == nil {
		return false
	}
	sig := sigOf(fn.Type())
	if sig == nil || sig.Recv() == nil {
		return false
	}
	if _, wantsPtr := syntaxutil.UnderlyingType(sig.Recv().Type()).(*types.Pointer); !wantsPtr {
		return false
	}
	curT := info.TypeOf(sel.X)
	if curT == nil {
		return true
	}
	if _, isPtr := syntaxutil.UnderlyingType(curT).(*types.Pointer); isPtr {
		return false
	}
	idx := selection.Index()
	for k := 0; k < len(idx)-1; k++ {
		st, ok := syntaxutil.UnderlyingType(curT).(*types.Struct)
		if !ok || idx[k] < 0 || idx[k] >= st.NumFields() {
			return true
		}
		curT = st.Field(idx[k]).Type()
		if _, isPtr := syntaxutil.UnderlyingType(curT).(*types.Pointer); isPtr {
			return false
		}
	}
	return true
}

func stripMethodExprRecvParam(sig *types.Signature) *types.Signature {
	if sig == nil || sig.Params() == nil || sig.Params().Len() == 0 {
		return sig
	}
	n := sig.Params().Len()
	vars := make([]*types.Var, n-1)
	for i := 1; i < n; i++ {
		vars[i-1] = sig.Params().At(i)
	}
	return types.NewSignatureType(nil, nil, nil, types.NewTuple(vars...), sig.Results(), sig.Variadic())
}

func typeMayBeValueArray(t types.Type) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t)
	if tp, ok := u.(*types.TypeParam); ok {
		iface, ok := tp.Underlying().(*types.Interface)
		if !ok {
			return false
		}
		return ifaceAdmitsArray(iface, make(map[*types.Interface]bool))
	}
	_, isArr := u.Underlying().(*types.Array)
	return isArr
}

func ifaceAdmitsArray(iface *types.Interface, seen map[*types.Interface]bool) bool {
	if iface == nil || seen[iface] {
		return false
	}
	seen[iface] = true
	for i := 0; i < iface.NumEmbeddeds(); i++ {
		switch emb := types.Unalias(iface.EmbeddedType(i)).(type) {
		case *types.Union:
			for j := 0; j < emb.Len(); j++ {
				if _, isArr := syntaxutil.UnderlyingType(emb.Term(j).Type()).(*types.Array); isArr {
					return true
				}
			}
		case *types.Interface:
			if ifaceAdmitsArray(emb, seen) {
				return true
			}
		default:
			if _, isArr := syntaxutil.UnderlyingType(emb).(*types.Array); isArr {
				return true
			}
		}
	}
	return false
}

func sigOf(t types.Type) *types.Signature {
	if t == nil {
		return nil
	}
	sig, _ := syntaxutil.UnderlyingType(t).(*types.Signature)
	return sig
}

func pkgPathOf(fn *types.Func, fallback *types.Package) string {
	if fn != nil && fn.Pkg() != nil {
		return fn.Pkg().Path()
	}
	if fallback != nil {
		return fallback.Path()
	}
	return ""
}
