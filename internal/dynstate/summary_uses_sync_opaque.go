package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func walkSyncVarCalls(
	p *packages.Package,
	fc *pkgFlowCache,
	candidates map[*types.Var]bool,
	evictNonCallUses bool,
	judgeCall func(v *types.Var, sel *ast.SelectorExpr, callVal *flowir.Value) (admittedMethod, siteConforms bool),
) map[*ast.SelectorExpr]bool {
	if len(candidates) == 0 || p == nil || p.TypesInfo == nil {
		return nil
	}
	conformingBySelector := map[*ast.SelectorExpr]*types.Var{}

	evict := func(obj *types.Var) {
		if evictNonCallUses && obj != nil {
			delete(candidates, obj)
		}
	}

	var scanVal func(v *flowir.Value)
	var scanBody func(b *flowir.Body, topGenDecl bool)
	scanPlace := func(pl flowir.Place) {
		if pl.Obj != nil && candidates[pl.Obj] {
			evict(pl.Obj)
		}
		pl.ForEachChildValue(func(cv *flowir.Value) bool {
			scanVal(cv)
			return true
		})
	}
	scanVal = func(v *flowir.Value) {
		if v == nil {
			return
		}
		switch v.Kind {
		case flowir.ValMakeClosure:
			if v.Closure != nil {
				scanBody(v.Closure, false)
			}
			return
		case flowir.ValCall:
			if v.CallKind == flowir.CallIIFE {
				for _, a := range v.Args {
					scanVal(a)
				}
				if v.IIFE != nil {
					scanBody(v.IIFE, false)
				}
				return
			}
			if v.CallKind == flowir.CallMethod && !v.IsMethodExprCall && v.HasRecvPlace && v.RecvPlace.IsBareVar() && candidates[v.RecvPlace.Obj] {
				cand := v.RecvPlace.Obj
				sel := v.CalleeSelector()
				if sel == nil {
					delete(candidates, cand)
				} else {
					admittedMethod, siteConforms := judgeCall(cand, sel, v)
					if !admittedMethod {
						delete(candidates, cand)
					} else if siteConforms {
						conformingBySelector[sel] = cand
					} else if !evictNonCallUses {
						delete(candidates, cand)
					}
				}
				for _, a := range v.Args {
					scanVal(a)
				}
				return
			}
		case flowir.ValPlace:
			scanPlace(v.Place)
			return
		case flowir.ValAddrOf:
			scanPlace(v.AddrPlace)
			if v.Low != nil {
				scanVal(v.Low)
			}
			if v.High != nil {
				scanVal(v.High)
			}
			if v.Max != nil {
				scanVal(v.Max)
			}
			return
		case flowir.ValMethodVal:
			if v.HasRecvPlace && v.RecvPlace.Obj != nil && candidates[v.RecvPlace.Obj] {
				evict(v.RecvPlace.Obj)
			}
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			scanVal(ch)
			return true
		})
	}

	scanBody = func(b *flowir.Body, topGenDecl bool) {
		if b == nil {
			return
		}
		b.ForEachSyncOp(func(op *flowir.Op) bool {
			switch op.Kind {
			case flowir.OpAssign:
				_, isVS := op.StmtAST.(*ast.ValueSpec)
				for i, dst := range op.Dsts {
					isDef := i < len(op.DstDefs) && op.DstDefs[i]
					if topGenDecl && isVS && isDef && dst.IsBareVar() {
						continue
					}
					scanPlace(dst)
				}
				for _, src := range op.Srcs {
					scanVal(src)
				}
			case flowir.OpTypeSwitchBind:
				scanVal(op.SwitchSrc)
			case flowir.OpChanSend:
				scanPlace(op.ChanPlace)
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

	for _, file := range p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				scanBody(fc.funcBody(p, d), false)
			case *ast.GenDecl:
				if d.Tok == token.VAR || d.Tok == token.CONST {
					scanBody(fc.body(p, d), true)
				} else if evictNonCallUses {
					ast.Inspect(d, func(n ast.Node) bool {
						if id, ok := n.(*ast.Ident); ok {
							if v, ok := p.TypesInfo.Uses[id].(*types.Var); ok && candidates[v] {
								delete(candidates, v)
							}
						}
						return true
					})
				}
			}
		}
	}

	calls := map[*ast.SelectorExpr]bool{}
	for sel, v := range conformingBySelector {
		if candidates[v] {
			calls[sel] = true
		}
	}
	return calls
}

func dataMemoVars(audited bool, p *packages.Package, fc *pkgFlowCache, callIdx *refconfine.CallSiteIndex) map[*types.Var]bool {
	if p == nil || p.TypesInfo == nil || p.Types == nil || !syntaxutil.IsTrueStdlibInPkg(p, "sync") {
		return nil
	}
	isSyncMap := func(t types.Type) bool {
		named, ok := types.Unalias(t).(*types.Named)
		return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "sync" && named.Obj().Name() == "Map"
	}
	writeInfos := fc.ensureVarWriteInfos(p)
	isEmptySyncMapLit := func(val *flowir.Value) bool {
		if val == nil || val.Kind != flowir.ValAllocFresh || val.AllocKind != flowir.AllocCompositeLit || len(val.CompositeElts) != 0 {
			return false
		}
		_, isPtr := types.Unalias(val.Type).Underlying().(*types.Pointer)
		return !isPtr && isSyncMap(val.Type)
	}
	candidates := map[*types.Var]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v.Exported() || !isSyncMap(v.Type()) {
			continue
		}
		st := writeInfos[v]
		if st == nil || st.defs != 1 || st.hasNonPlainDef || st.hasPostDefWrite ||
			st.hasExplicitAddr || st.hasChanSend || st.hasBuiltinMut ||
			(!st.hasZeroDecl && !isEmptySyncMapLit(st.initVal)) {
			continue
		}
		candidates[v] = true
	}
	if len(candidates) == 0 {
		return nil
	}
	carrierFree := func(arg *flowir.Value) bool {
		if arg == nil || arg.Raw == nil {
			return false
		}
		if callIdx == nil {
			callIdx = refconfine.BuildCallSiteIndex(p)
		}
		return callIdx.JudgeExpr(arg.Raw, func(t types.Type) (bool, bool) {
			if !refconfine.TypeMayCarryUnknownDynamic(audited, t) {
				return true, true
			}
			return false, false
		})
	}
	// Evict any sync.Map candidate referenced outside a direct MemoMethod call
	// (such as `&memo`, `alias := &memo`, or passing `memo` as an argument).
	walkSyncVarCalls(p, fc, candidates, true, func(_ *types.Var, sel *ast.SelectorExpr, callVal *flowir.Value) (bool, bool) {
		if !auditset.MemoMethod("Map", sel.Sel.Name) {
			return false, false
		}
		for _, arg := range callVal.Args {
			if !carrierFree(arg) {
				return false, false
			}
		}
		return true, true
	})
	return candidates
}

func provenSharedPools(audited bool, p *packages.Package, fc *pkgFlowCache) (proven map[*types.Var]types.Type, calls map[*ast.SelectorExpr]bool) {
	proven = map[*types.Var]types.Type{}
	calls = map[*ast.SelectorExpr]bool{}
	if p == nil || p.TypesInfo == nil {
		return proven, calls
	}
	for _, file := range p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				vsBody := fc.body(p, vs)
				if vsBody == nil || len(vsBody.Ops) != 1 || vsBody.Ops[0].Kind != flowir.OpAssign ||
					len(vsBody.Ops[0].Dsts) != 1 || len(vsBody.Ops[0].Srcs) != 1 {
					continue
				}
				dst := vsBody.Ops[0].Dsts[0]
				if !dst.IsBareVar() || dst.Obj == nil || dst.Obj.Exported() || dst.Obj.Pkg() == nil {
					continue
				}
				named, ok := types.Unalias(dst.Obj.Type()).(*types.Named)
				if !ok || named.Obj() == nil || named.Obj().Pkg() == nil ||
					named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Pool" {
					continue
				}
				rhs := vsBody.Ops[0].Srcs[0]
				if rhs == nil || rhs.Kind != flowir.ValAllocFresh || rhs.AllocKind != flowir.AllocCompositeLit || len(rhs.CompositeElts) != 1 {
					continue
				}
				if _, isPtr := types.Unalias(rhs.Type).Underlying().(*types.Pointer); isPtr {
					continue
				}
				elt := rhs.CompositeElts[0]
				if elt.Field == nil || elt.Field.Name() != "New" || elt.Value == nil ||
					elt.Value.Kind != flowir.ValMakeClosure || elt.Value.Closure == nil {
					continue
				}
				// Preserve keyed `sync.Pool{New: func() any { ... }}` requirement (rejecting unkeyed literals).
				if lit, ok := syntaxutil.UnparenExpr(vs.Values[0]).(*ast.CompositeLit); !ok || len(lit.Elts) != 1 {
					continue
				} else if _, isKV := lit.Elts[0].(*ast.KeyValueExpr); !isKV {
					continue
				}
				content := provenPoolContentType(audited, elt.Value.Lit, elt.Value.Closure)
				if content == nil {
					continue
				}
				proven[dst.Obj] = content
			}
		}
	}
	if len(proven) == 0 {
		return proven, calls
	}
	candidates := make(map[*types.Var]bool, len(proven))
	for v := range proven {
		candidates[v] = true
	}
	calls = walkSyncVarCalls(p, fc, candidates, true, func(v *types.Var, _ *ast.SelectorExpr, callVal *flowir.Value) (bool, bool) {
		if callVal.Selection == nil || callVal.Selection.Kind() != types.MethodVal || callVal.CalleeFunc == nil {
			return false, false
		}
		if !refconfine.AuditedPooling(audited, callVal.CalleeFunc) {
			return false, false
		}
		return true, provenPoolCallConforms(callVal.CalleeFunc, callVal, proven[v])
	})
	for v := range proven {
		if !candidates[v] {
			delete(proven, v)
		}
	}
	return proven, calls
}

func provenPoolContentType(audited bool, lit *ast.FuncLit, b *flowir.Body) types.Type {
	if lit == nil || lit.Type == nil || lit.Type.Results == nil || b == nil {
		return nil
	}
	for _, field := range lit.Type.Results.List {
		if len(field.Names) > 0 {
			return nil
		}
	}
	var content types.Type
	conforming := true
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		switch op.Kind {
		case flowir.OpDefer:
			conforming = false
			return false
		case flowir.OpReturn:
			if len(op.Results) != 1 || op.Results[0] == nil || op.Results[0].Type == nil {
				conforming = false
				return false
			}
			t := op.Results[0].Type
			if basic, isBasic := types.Unalias(t).(*types.Basic); isBasic && basic.Info()&types.IsUntyped != 0 {
				conforming = false
				return false
			}
			if content == nil {
				content = t
			} else if !types.Identical(content, t) {
				conforming = false
				return false
			}
		}
		return true
	})
	if !conforming || content == nil {
		return nil
	}
	if refconfine.TypeMayCarryUnknownDynamic(audited, content) {
		return nil
	}
	return content
}

func provenPoolCallConforms(fn *types.Func, callVal *flowir.Value, content types.Type) bool {
	if fn == nil || callVal == nil || callVal.Ellipsis {
		return false
	}
	switch fn.Name() {
	case "Get":
		return len(callVal.Args) == 0
	case "Put":
		if len(callVal.Args) != 1 || callVal.Args[0] == nil || callVal.Args[0].Type == nil {
			return false
		}
		return types.Identical(callVal.Args[0].Type, content)
	default:
		return false
	}
}

func recordFunctionReferenceRegions(
	p *packages.Package,
	fc *pkgFlowCache,
	initOnly map[string]bool,
	refs map[syntaxutil.FuncKey]map[syntaxutil.RefRegion]bool,
) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return
	}
	funcKeyOf := func(obj types.Object) (syntaxutil.FuncKey, bool) {
		fn, ok := obj.(*types.Func)
		if !ok || fn == nil || fn.Pkg() == nil {
			return syntaxutil.FuncKey{}, false
		}
		fn = fn.Origin()
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil {
			return syntaxutil.FuncKey{}, false
		}
		return syntaxutil.FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}, true
	}
	add := func(callee syntaxutil.FuncKey, region syntaxutil.RefRegion) {
		if refs[callee] == nil {
			refs[callee] = map[syntaxutil.RefRegion]bool{}
		}
		refs[callee][region] = true
	}
	literalRegion := func(region syntaxutil.RefRegion) syntaxutil.RefRegion {
		switch region.Kind {
		case syntaxutil.RegionLitFunc:
			return region
		case syntaxutil.RegionFunc:
			return syntaxutil.RefRegion{Kind: syntaxutil.RegionLitFunc, Caller: region.Caller}
		default:
			return syntaxutil.RefRegion{Kind: syntaxutil.RegionProg}
		}
	}

	var scanBody func(region syntaxutil.RefRegion, b *flowir.Body)
	var scanVal func(region syntaxutil.RefRegion, v *flowir.Value)
	scanVal = func(region syntaxutil.RefRegion, v *flowir.Value) {
		if v == nil {
			return
		}
		switch v.Kind {
		case flowir.ValMakeClosure:
			if v.Closure != nil {
				scanBody(literalRegion(region), v.Closure)
			}
			return
		case flowir.ValCall:
			switch v.CallKind {
			case flowir.CallIIFE:
				for _, a := range v.Args {
					scanVal(region, a)
				}
				if v.IIFE != nil {
					scanBody(literalRegion(region), v.IIFE)
				}
				return
			case flowir.CallPlain:
				if !v.IsMethodExprCall && v.CalleeFunc != nil {
					if key, ok := funcKeyOf(v.CalleeFunc); ok {
						add(key, region)
					}
					for _, a := range v.Args {
						scanVal(region, a)
					}
					return
				}
			}
		case flowir.ValPlace:
			if v.Place.Root == flowir.RootFunc && v.Place.Func != nil {
				if key, ok := funcKeyOf(v.Place.Func); ok {
					add(key, literalRegion(region))
				}
			}
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			scanVal(region, ch)
			return true
		})
	}
	scanBody = func(region syntaxutil.RefRegion, b *flowir.Body) {
		if b == nil {
			return
		}
		b.ForEachSyncOp(func(op *flowir.Op) bool {
			if op.Kind == flowir.OpGo {
				scanVal(literalRegion(region), op.Call)
				return true
			}
			forEachOpTopValues(op, func(v *flowir.Value) {
				scanVal(region, v)
			})
			return true
		})
	}

	initReg := syntaxutil.RefRegion{Kind: syntaxutil.RegionInit}
	progReg := syntaxutil.RefRegion{Kind: syntaxutil.RegionProg}
	for _, file := range p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Body == nil {
					continue
				}
				b := fc.funcBody(p, decl)
				switch {
				case decl.Recv != nil:
					scanBody(progReg, b)
				case decl.Name != nil && (decl.Name.Name == "init" || initOnly[decl.Name.Name]):
					scanBody(initReg, b)
				case decl.Name != nil && decl.Name.Name != "_":
					scanBody(syntaxutil.RefRegion{
						Kind:   syntaxutil.RegionFunc,
						Caller: syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: decl.Name.Name},
					}, b)
				default:
					scanBody(progReg, b)
				}
			case *ast.GenDecl:
				if decl.Tok == token.VAR || decl.Tok == token.CONST {
					scanBody(initReg, fc.body(p, decl))
				} else {
					ast.Inspect(decl, func(n ast.Node) bool {
						if id, ok := n.(*ast.Ident); ok {
							if key, ok := funcKeyOf(p.TypesInfo.Uses[id]); ok {
								add(key, literalRegion(initReg))
							}
						}
						return true
					})
				}
			}
		}
	}
}

func recordOpaqueDynamicVars(p *packages.Package, fc *pkgFlowCache, opaque, breaks map[string]bool, deps map[string]map[string]bool) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return
	}
	interfacePackageVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		_, isInterface := types.Unalias(variable.Type()).Underlying().(*types.Interface)
		return variable, isInterface
	}
	var auditedImmutable func(v *flowir.Value, storeDeps map[string]bool) bool
	auditedArgument := func(v *flowir.Value, storeDeps map[string]bool) bool {
		if v == nil || v.IsTypeExpr {
			return false
		}
		if auditedImmutable(v, storeDeps) {
			return true
		}
		if storeDeps != nil && v.Kind == flowir.ValPlace && v.Place.IsBareVar() && v.Place.Obj != nil {
			if variable, ok := interfacePackageVar(v.Place.Obj); ok {
				storeDeps[syntaxutil.DynamicVarKey(variable)] = true
				return true
			}
		}
		return false
	}
	auditedImmutable = func(v *flowir.Value, storeDeps map[string]bool) bool {
		if v == nil || v.IsTypeExpr {
			return false
		}
		if v.IsConst || v.IsNil {
			return true
		}
		if v.Type != nil && refconfine.ImmutableRuntimeType(v.Type) {
			return true
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallPlain && !v.IsMethodExprCall && !v.Ellipsis && v.CalleeFunc != nil {
			if v.CalleePkg == "errors" && v.CalleeFunc.Name() == "New" {
				return len(v.Args) == 1
			}
			if v.CalleePkg == "fmt" && v.CalleeFunc.Name() == "Errorf" {
				for _, arg := range v.Args {
					if !auditedArgument(arg, storeDeps) {
						return false
					}
				}
				return true
			}
		}
		return false
	}

	failed := map[string]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		if variable, ok := interfacePackageVar(scope.Lookup(name)); ok {
			opaque[syntaxutil.DynamicVarKey(variable)] = true
		}
	}

	audit := func(obj types.Object, value *flowir.Value) {
		if variable, ok := interfacePackageVar(obj); ok {
			key := syntaxutil.DynamicVarKey(variable)
			storeDeps := map[string]bool{}
			if value == nil || !auditedArgument(value, storeDeps) {
				failed[key] = true
				return
			}
			for dep := range storeDeps {
				if deps == nil {
					break
				}
				if deps[key] == nil {
					deps[key] = map[string]bool{}
				}
				deps[key][dep] = true
			}
		}
	}

	failValueVars := func(v *flowir.Value) {
		walkTransientTargetValues(v, func(cur *flowir.Value) {
			if cur.Kind == flowir.ValPlace && cur.Place.Obj != nil {
				if variable, ok := interfacePackageVar(cur.Place.Obj); ok {
					failed[syntaxutil.DynamicVarKey(variable)] = true
				}
			} else if cur.Kind == flowir.ValAddrOf && cur.AddrPlace.Obj != nil {
				if variable, ok := interfacePackageVar(cur.AddrPlace.Obj); ok {
					failed[syntaxutil.DynamicVarKey(variable)] = true
				}
			}
		})
	}
	failPlace := func(pl flowir.Place) {
		if pl.Obj != nil {
			if variable, ok := interfacePackageVar(pl.Obj); ok {
				failed[syntaxutil.DynamicVarKey(variable)] = true
			}
			return
		}
		if pl.Root == flowir.RootTransient && pl.Base != nil {
			failValueVars(pl.Base)
		}
	}
	scanAddrOf := func(v *flowir.Value) {
		if v == nil {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			if cur.Kind == flowir.ValAddrOf {
				failPlace(cur.AddrPlace)
			}
			return true
		})
	}

	inspectBody := func(b *flowir.Body) {
		if b == nil {
			return
		}
		visitAllBodyOps(b, func(op *flowir.Op) {
			switch op.Kind {
			case flowir.OpAssign:
				switch op.AssignKind {
				case flowir.AssignZeroDecl:
					// Uninitialized declaration `var ErrFoo error` leaves zero-value nil intact.
				case flowir.AssignPlain:
					if len(op.Dsts) != len(op.Srcs) {
						for _, dst := range op.Dsts {
							failPlace(dst)
						}
					} else {
						for i, dst := range op.Dsts {
							if dst.IsBareVar() && dst.Obj != nil {
								audit(dst.Obj, op.Srcs[i])
							} else {
								failPlace(dst)
							}
						}
					}
				default:
					for _, dst := range op.Dsts {
						failPlace(dst)
					}
				}
				for _, dst := range op.Dsts {
					dst.ForEachChildValue(func(cv *flowir.Value) bool {
						scanAddrOf(cv)
						return true
					})
				}
				for _, src := range op.Srcs {
					scanAddrOf(src)
				}
			default:
				forEachOpTopValues(op, scanAddrOf)
			}
		})
	}

	for _, file := range p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				inspectBody(fc.funcBody(p, d))
			case *ast.GenDecl:
				if d.Tok == token.VAR || d.Tok == token.CONST {
					inspectBody(fc.body(p, d))
				}
			}
		}
	}
	for key := range failed {
		delete(opaque, key)
		breaks[key] = true
	}
}
