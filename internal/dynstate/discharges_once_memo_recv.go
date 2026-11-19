package dynstate

import (
	"go/ast"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func verifyOnceMemoMethodRecvConfinement(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	pkgConf *packageConfinementSummary,
	ownerNamed *types.Named,
	mfn *types.Func,
	mfd *ast.FuncDecl,
	isGetter bool,
	doStmt *ast.ExprStmt,
	doLit *ast.FuncLit,
	onceField *types.Var,
	memoFields map[*types.Var]bool,
	inputFields map[*types.Var]bool,
	inputParamDeps map[syntaxutil.ParamKey]bool,
) bool {
	sig, ok := mfn.Type().(*types.Signature)
	if !ok || sig.TypeParams().Len() > 0 || sig.RecvTypeParams().Len() > 0 || sig.Recv() == nil {
		return false
	}
	recvVar := sig.Recv()
	if !syntaxutil.IsPtrToNamed(recvVar.Type(), ownerNamed) {
		return false
	}
	for ri := 0; ri < sig.Results().Len(); ri++ {
		rt := sig.Results().At(ri).Type()
		if typeReachesNamedOrSyncOnce(rt, ownerNamed) {
			return false
		}
	}
	if isGetter {
		if doStmt == nil {
			return false
		}
		doIdx := slices.Index(mfd.Body.List, ast.Stmt(doStmt))
		if doIdx < 0 {
			return false
		}
		for _, pre := range mfd.Body.List[:doIdx] {
			if exprMentionsAnyVar(p.TypesInfo, pre, memoFields) {
				return false
			}
		}
	}
	b := fc.funcBody(p, mfd)
	if b == nil {
		return false
	}
	return verifyOnceMemoRecvUsesInBody(
		audited,
		p,
		fc,
		pkgConf,
		ownerNamed,
		recvVar,
		onceField,
		isGetter,
		memoFields,
		inputFields,
		nil,
		doLit,
		b,
		inputParamDeps,
	)
}

func verifyOnceMemoRecvUsesInBody(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	pkgConf *packageConfinementSummary,
	ownerNamed *types.Named,
	recvVar *types.Var,
	onceField *types.Var,
	allowMemoAccess bool,
	memoFields map[*types.Var]bool,
	inputFields map[*types.Var]bool,
	allowedMemoAssigns []*ast.AssignStmt,
	allowedDoLit *ast.FuncLit,
	b *flowir.Body,
	inputParamDeps map[syntaxutil.ParamKey]bool,
) bool {
	allowedAssignNodes := map[ast.Node]bool{}
	for _, as := range allowedMemoAssigns {
		allowedAssignNodes[as] = true
	}

	// Collect any single-def bare local aliases of recvVar or of recvVar.<inputField>.
	recvAliases := map[*types.Var]bool{recvVar: true}
	inputFieldLocals := map[*types.Var]bool{}
	defCount := map[*types.Var]int{}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind == flowir.OpAssign {
			for _, dst := range op.Dsts {
				if dst.IsBareVar() {
					defCount[dst.Obj]++
				}
			}
		}
		return true
	})

	isRecvVar := func(v *types.Var) bool {
		return v != nil && recvAliases[v]
	}

	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignPlain && len(op.Dsts) == 1 && len(op.Srcs) == 1 {
			dst := op.Dsts[0]
			src := op.Srcs[0]
			if dst.IsBareVar() && dst.Root == flowir.RootLocal && defCount[dst.Obj] == 1 && src.Kind == flowir.ValPlace {
				if src.Place.IsBareVar() && recvAliases[src.Place.Obj] {
					recvAliases[dst.Obj] = true
				} else if isRecvVar(src.Place.Obj) && len(src.Place.Projs) == 1 &&
					src.Place.Projs[0].Kind == flowir.ProjField && inputFields[src.Place.Projs[0].Field] &&
					refconfine.TypeCarriesMutableRef(src.Place.Projs[0].Field.Type()) {
					inputFieldLocals[dst.Obj] = true
				}
			}
		}
		return true
	})

	// Judge any local variables initialized from a mutable-reach inputField.
	if len(inputFieldLocals) > 0 && b.AST != nil {
		roots := make(map[types.Object]bool, len(inputFieldLocals))
		for lv := range inputFieldLocals {
			roots[lv] = true
		}
		wants := map[syntaxutil.ParamKey]bool{}
		methodWants := map[syntaxutil.FuncKey]bool{}
		fieldWants := map[syntaxutil.FieldPosKey]bool{}
		elemWants := map[syntaxutil.ElemParamUse]bool{}
		var returns bool
		if !boundValueLeakFreeJudged(audited, p, fc, roots, b.AST, wants, &returns, methodWants, fieldWants, elemWants) {
			return false
		}
		if returns || len(fieldWants) > 0 || len(elemWants) > 0 {
			return false
		}
		for mw := range methodWants {
			if mw.Pkg != p.Types.Path() || !pkgConf.readOnly[mw.Name] {
				return false
			}
		}
		for pw := range wants {
			if !recordOrVerifyOnceMemoParamDep(p.Types.Path(), pkgConf, pw, inputParamDeps) {
				return false
			}
		}
	}

	ok := true
	checkValueTree := func(rootVal *flowir.Value, allowPostDoMemoReturn bool) {
		if rootVal == nil || !ok {
			return
		}
		if allowPostDoMemoReturn && rootVal.Kind == flowir.ValPlace &&
			isRecvVar(rootVal.Place.Obj) && len(rootVal.Place.Projs) == 1 &&
			rootVal.Place.Projs[0].Kind == flowir.ProjField && memoFields[rootVal.Place.Projs[0].Field] {
			return
		}

		// Track ValPlace nodes already consumed as valid CallMethod receivers, OpExpr once.Do, or pure call args.
		consumedPlaces := map[*flowir.Value]bool{}

		var visit func(v *flowir.Value)
		visit = func(v *flowir.Value) {
			if v == nil || !ok {
				return
			}
			switch v.Kind {
			case flowir.ValAddrOf, flowir.ValMethodVal:
				if (v.Kind == flowir.ValAddrOf && isRecvVar(v.AddrPlace.Obj)) ||
					(v.Kind == flowir.ValMethodVal && ((v.Recv != nil && valueTouchesVars(v.Recv, recvAliases)) || (v.HasRecvPlace && isRecvVar(v.RecvPlace.Obj)))) {
					ok = false
					return
				}
			case flowir.ValMakeClosure:
				if v.Lit == allowedDoLit {
					return
				}
				if v.Closure != nil {
					for fv := range v.Closure.FreeVars {
						if isRecvVar(fv) {
							ok = false
							return
						}
					}
					if !verifyOnceMemoRecvUsesInBody(
						audited, p, fc, pkgConf, ownerNamed, recvVar, nil, false,
						memoFields, inputFields, nil, nil, v.Closure, inputParamDeps,
					) {
						ok = false
						return
					}
				}
				return
			case flowir.ValCall:
				if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
					if !verifyOnceMemoRecvUsesInBody(
						audited, p, fc, pkgConf, ownerNamed, recvVar, nil, false,
						memoFields, inputFields, nil, nil, v.IIFE, inputParamDeps,
					) {
						ok = false
						return
					}
				}
				// Check getter's e.once.Do(doLit).
				if v.CallKind == flowir.CallMethod && onceField != nil && v.CalleeFunc != nil &&
					v.CalleeFunc.Pkg() != nil && v.CalleeFunc.Pkg().Path() == "sync" && v.CalleeFunc.Name() == "Do" &&
					len(v.Args) == 1 && v.Args[0].Kind == flowir.ValMakeClosure && v.Args[0].Lit == allowedDoLit &&
					v.HasRecvPlace && isRecvVar(v.RecvPlace.Obj) && len(v.RecvPlace.Projs) == 1 &&
					v.RecvPlace.Projs[0].Kind == flowir.ProjField && v.RecvPlace.Projs[0].Field == onceField {
					if v.Recv != nil {
						consumedPlaces[v.Recv] = true
					}
					return
				}
				// Direct method call on *T: recv may be bare recvVar!
				if v.CallKind == flowir.CallMethod && v.Recv != nil && v.Recv.Kind == flowir.ValPlace &&
					v.Recv.Place.IsBareVar() && isRecvVar(v.Recv.Place.Obj) {
					if v.Selection == nil || len(v.Selection.Index()) != 1 || v.CalleeFunc == nil ||
						v.CalleeFunc.Pkg() != p.Types {
						ok = false
						return
					}
					if recvSig, okSig := v.CalleeFunc.Type().(*types.Signature); !okSig || recvSig.Recv() == nil ||
						!syntaxutil.IsPtrToNamed(recvSig.Recv().Type(), ownerNamed) {
						ok = false
						return
					}
					consumedPlaces[v.Recv] = true
				}
				// Plain or builtin call with mutable-reach inputField argument e.<inf>.
				for ai, arg := range v.Args {
					if arg == nil || arg.Kind != flowir.ValPlace || !isRecvVar(arg.Place.Obj) ||
						len(arg.Place.Projs) != 1 || arg.Place.Projs[0].Kind != flowir.ProjField ||
						!inputFields[arg.Place.Projs[0].Field] ||
						!refconfine.TypeCarriesMutableRef(arg.Type) {
						continue
					}
					if v.CallKind == flowir.CallBuiltin && (v.BuiltinName == "len" || v.BuiltinName == "cap") {
						consumedPlaces[arg] = true
						continue
					}
					if v.CallKind == flowir.CallPlain && !v.IsMethodExprCall && v.CalleeFunc != nil && v.CalleeFunc.Origin() == v.CalleeFunc && v.CalleeFunc.Pkg() != nil {
						if isReadOnlyInputSliceStdlibCallee(p, v.CalleeFunc) {
							consumedPlaces[arg] = true
							continue
						}
						if !v.Ellipsis {
							if pi, okPI := v.ParamIndexForArg(ai); okPI {
								pk := syntaxutil.ParamKey{
									Func:  syntaxutil.FuncKey{Pkg: v.CalleeFunc.Pkg().Path(), Name: v.CalleeFunc.Name()},
									Index: pi,
								}
								if pk.Valid() && recordOrVerifyOnceMemoParamDep(p.Types.Path(), pkgConf, pk, inputParamDeps) {
									consumedPlaces[arg] = true
									continue
								}
							}
						}
					}
				}
			case flowir.ValConvert:
				if !v.IsTypeAssert && v.Arg != nil && v.Arg.Kind == flowir.ValPlace &&
					isRecvVar(v.Arg.Place.Obj) && len(v.Arg.Place.Projs) == 1 &&
					v.Arg.Place.Projs[0].Kind == flowir.ProjField && inputFields[v.Arg.Place.Projs[0].Field] &&
					!refconfine.TypeCarriesMutableRef(v.Type) {
					consumedPlaces[v.Arg] = true
				}
			case flowir.ValPlace:
				if consumedPlaces[v] {
					return
				}
				if isRecvVar(v.Place.Obj) {
					if len(v.Place.Projs) == 0 {
						ok = false
						return
					}
					p0 := v.Place.Projs[0]
					if p0.Kind != flowir.ProjField || !inputFields[p0.Field] {
						ok = false
						return
					}
					if refconfine.TypeCarriesMutableRef(v.Type) {
						ok = false
						return
					}
				}
			}
			v.ForEachChildValue(func(ch *flowir.Value) bool {
				visit(ch)
				return ok
			})
		}
		visit(rootVal)
	}

	var checkOps func(cur *flowir.Body)
	checkOps = func(cur *flowir.Body) {
		if cur == nil || !ok {
			return
		}
		for i := range cur.Ops {
			if !ok {
				return
			}
			op := &cur.Ops[i]
			switch op.Kind {
			case flowir.OpAssign:
				if allowedAssignNodes[op.StmtAST] {
					for _, src := range op.Srcs {
						checkValueTree(src, false)
					}
					continue
				}
				for _, dst := range op.Dsts {
					if isRecvVar(dst.Obj) {
						ok = false
						return
					}
					dst.ForEachChildValue(func(cv *flowir.Value) bool {
						checkValueTree(cv, false)
						return ok
					})
				}
				if op.AssignKind == flowir.AssignPlain && len(op.Dsts) == 1 && len(op.Srcs) == 1 {
					dst := op.Dsts[0]
					if dst.IsBareVar() && (recvAliases[dst.Obj] || inputFieldLocals[dst.Obj]) {
						continue
					}
				}
				for _, src := range op.Srcs {
					checkValueTree(src, false)
				}
				if op.RangeBody != nil {
					checkOps(op.RangeBody)
				}
			case flowir.OpReturn:
				for _, r := range op.Results {
					checkValueTree(r, allowMemoAccess)
				}
			case flowir.OpTypeSwitchBind:
				if op.SwitchDst != nil && isRecvVar(op.SwitchDst) {
					ok = false
					return
				}
				checkValueTree(op.SwitchSrc, false)
			case flowir.OpChanSend:
				if isRecvVar(op.ChanPlace.Obj) {
					ok = false
					return
				}
				checkValueTree(op.ChanVal, false)
				checkValueTree(op.SendVal, false)
			case flowir.OpGo:
				if op.Call != nil && valueTouchesVars(op.Call, recvAliases) {
					ok = false
					return
				}
				checkValueTree(op.Call, false)
			case flowir.OpDefer:
				if op.Call != nil && valueTouchesVars(op.Call, recvAliases) {
					ok = false
					return
				}
				checkValueTree(op.Call, false)
			case flowir.OpExpr:
				checkValueTree(op.Expr, false)
			}
		}
	}
	checkOps(b)
	return ok
}

func recordOrVerifyOnceMemoParamDep(
	ownPath string,
	pkgConf *packageConfinementSummary,
	pk syntaxutil.ParamKey,
	inputParamDeps map[syntaxutil.ParamKey]bool,
) bool {
	provenLocal, conditional := pkgConf.classifyParam(ownPath, pk)
	if provenLocal {
		return true
	}
	if conditional {
		inputParamDeps[pk] = true
		return true
	}
	return false
}

func isConfinedDirectCallClosureVar(p *packages.Package, fc *pkgFlowCache, idx *refconfine.PkgIndex, lv *types.Var) bool {
	if lv == nil || idx.DefCounts[lv] != 1 || fc.varHasExplicitWriteOrAddr(p, lv) {
		return false
	}
	for _, uid := range idx.UsesOf[lv] {
		if !idx.CalleeIdents[uid] {
			return false
		}
	}
	return true
}

func verifyOnceMemoCtorCallArg(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	arg ast.Expr,
) bool {
	if arg == nil {
		return false
	}
	arg = ast.Unparen(arg)
	argT := p.TypesInfo.TypeOf(arg)
	if argT == nil || refconfine.TypeMayCarryUnknownDynamic(audited, argT) || refconfine.TypeCarriesSignature(argT) {
		return false
	}
	if !refconfine.TypeCarriesMutableRef(argT) && !syntaxutil.ContainsUintptr(argT) {
		return true
	}
	if isPureConstantOrCompositeDataValue(fc.exprValue(p, arg)) {
		return true
	}
	id, isID := arg.(*ast.Ident)
	if !isID {
		return false
	}
	v, _ := p.TypesInfo.Uses[id].(*types.Var)
	if v == nil || v.IsField() || v.Pkg() != p.Types || v.Parent() != p.Types.Scope() || v.Exported() {
		return false
	}
	return verifyReadOnlyCarrierFreeGlobalVar(audited, p, fc, idx, v, id, false)
}

func verifyReadOnlyCarrierFreeGlobalVar(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	v *types.Var,
	exemptIdent *ast.Ident,
	requirePureInit bool,
) bool {
	if v == nil || v.Exported() || idx.DefCounts[v] != 1 || hasVarGofreshDirective(idx, v) {
		return false
	}
	if refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) || refconfine.TypeCarriesSignature(v.Type()) {
		return false
	}
	vs := idx.VarSpecs[v]
	if vs == nil || len(vs.Names) != 1 {
		return false
	}
	if len(vs.Values) > 1 {
		return false
	}
	if len(vs.Values) == 1 && !isPureConstantOrCompositeDataValue(fc.exprValue(p, vs.Values[0])) {
		return false
	}
	if requirePureInit && len(vs.Values) == 0 {
		return false
	}
	if fc.varHasExplicitWriteOrAddr(p, v) {
		return false
	}
	if !refconfine.TypeCarriesMutableRef(v.Type()) {
		return true
	}
	otherUses := map[*ast.Ident]bool{}
	for _, uid := range idx.UsesOf[v] {
		if uid == exemptIdent {
			continue
		}
		otherUses[uid] = true
	}
	if len(otherUses) == 0 {
		return true
	}
	return refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
		Index:                         idx,
		AllowReturnFromUnexportedFunc: false,
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			id, isID := ast.Unparen(expr).(*ast.Ident)
			if !isID || !otherUses[id] {
				return false, false
			}
			return refconfine.IsDirectMutableRef(v.Type()), true
		},
	})
}

func allIntraPkgVarUsesAreDirectMethodCalls(p *packages.Package, idx *refconfine.PkgIndex, v *types.Var, exemptUseIdents map[*ast.Ident]bool) bool {
	for _, uid := range idx.UsesOf[v] {
		if exemptUseIdents[uid] {
			continue
		}
		if !isDirectNonPromotedMethodCallIdent(p, idx, uid) {
			return false
		}
	}
	return true
}

func isReadOnlyInputSliceStdlibCallee(p *packages.Package, fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil || !syntaxutil.IsTrueStdlibInPkg(p, fn.Pkg().Path()) {
		return false
	}
	traits := auditset.DeterministicStdCallTraits(fn.Pkg().Path(), fn.Name())
	return traits.ReadOnlySliceInspect || traits.ReadOnlySliceCopy
}

func lookupAnyPkgScopeVar(p *packages.Package, expr ast.Expr) *types.Var {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if v, ok := p.TypesInfo.Uses[e].(*types.Var); ok && v != nil && !v.IsField() && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
			return v
		}
	case *ast.SelectorExpr:
		if p.TypesInfo.Selections[e] == nil {
			if v, ok := p.TypesInfo.Uses[e.Sel].(*types.Var); ok && v != nil && !v.IsField() && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
				return v
			}
		}
	}
	return nil
}

func lookupRootPkgScopeVarAnyPkg(p *packages.Package, expr ast.Expr) *types.Var {
	cur := ast.Unparen(expr)
	for {
		if v := lookupAnyPkgScopeVar(p, cur); v != nil {
			return v
		}
		switch e := cur.(type) {
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				cur = ast.Unparen(e.X)
				continue
			}
		case *ast.IndexExpr:
			cur = ast.Unparen(e.X)
			continue
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
			continue
		case *ast.StarExpr:
			cur = ast.Unparen(e.X)
			continue
		}
		return nil
	}
}

func typeReachesNamedOrSyncOnce(root types.Type, target *types.Named) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if named, ok := t.(*types.Named); ok {
			orig := named.Origin()
			if orig == target || syntaxutil.IsNamedInPkg(orig, "sync", "Once") {
				hit = true
				return
			}
			for i := 0; i < named.TypeArgs().Len(); i++ {
				walk(named.TypeArgs().At(i))
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				walk(u.Params().At(i).Type())
			}
			for i := 0; i < u.Results().Len(); i++ {
				walk(u.Results().At(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func typeReachesStruct(root types.Type, target *types.Named) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if named, ok := t.(*types.Named); ok && named.Origin() == target {
			hit = true
			return
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func isUniverseErrorType(t types.Type) bool {
	if t == nil {
		return false
	}
	errObj := types.Universe.Lookup("error")
	return errObj != nil && types.Identical(types.Unalias(t), errObj.Type())
}

func isScalarBasicType(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	if !ok || b.Kind() == types.Uintptr {
		return false
	}
	return (b.Info() & (types.IsBoolean | types.IsInteger | types.IsFloat | types.IsComplex | types.IsString)) != 0
}

func isBasicStringType(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && (b.Info()&types.IsString) != 0
}

func exprMentionsVar(info *types.Info, expr ast.Expr, target *types.Var) bool {
	if info == nil || expr == nil || target == nil {
		return false
	}
	hit := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if hit || n == nil {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && info.Uses[id] == target {
			hit = true
			return false
		}
		return true
	})
	return hit
}

func exprMentionsAnyVar(info *types.Info, node ast.Node, targets map[*types.Var]bool) bool {
	if info == nil || node == nil || len(targets) == 0 {
		return false
	}
	hit := false
	ast.Inspect(node, func(n ast.Node) bool {
		if hit || n == nil {
			return false
		}
		if id, ok := n.(*ast.Ident); ok {
			if v, okV := info.Uses[id].(*types.Var); okV && targets[v] {
				hit = true
				return false
			}
		}
		return true
	})
	return hit
}

func valueTouchesVars(v *flowir.Value, vars map[*types.Var]bool) bool {
	if v == nil || len(vars) == 0 {
		return false
	}
	hit := false
	v.WalkValues(func(cur *flowir.Value) bool {
		if hit {
			return false
		}
		switch cur.Kind {
		case flowir.ValPlace:
			if vars[cur.Place.Obj] {
				hit = true
				return false
			}
		case flowir.ValAddrOf:
			if vars[cur.AddrPlace.Obj] {
				hit = true
				return false
			}
		case flowir.ValMethodVal:
			if cur.HasRecvPlace && vars[cur.RecvPlace.Obj] {
				hit = true
				return false
			}
		case flowir.ValCall:
			if cur.HasRecvPlace && vars[cur.RecvPlace.Obj] {
				hit = true
				return false
			}
		case flowir.ValMakeClosure:
			if cur.Closure != nil {
				for fv := range cur.Closure.FreeVars {
					if vars[fv] {
						hit = true
						return false
					}
				}
			}
		}
		return true
	})
	return hit
}
