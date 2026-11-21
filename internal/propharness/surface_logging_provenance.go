package propharness

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type loggingFuncParam struct {
	fn  *types.Func
	idx int
}

func isFmtOrErrorInterfaceMethod(fn *types.Func) bool {
	if fn == nil || fn.Signature() == nil || fn.Signature().Recv() == nil {
		return false
	}
	sig := fn.Signature()
	if sig.Variadic() {
		return false
	}
	switch fn.Name() {
	case "String", "GoString", "Error":
		return sig.Params().Len() == 0 && sig.Results().Len() == 1 && isStringType(sig.Results().At(0).Type())
	case "Format":
		if sig.Params().Len() != 2 || sig.Results().Len() != 0 {
			return false
		}
		p0, ok0 := types.Unalias(sig.Params().At(0).Type()).(*types.Named)
		p1, ok1 := types.Unalias(sig.Params().At(1).Type()).Underlying().(*types.Basic)
		return ok0 && p0.Obj() != nil && p0.Obj().Pkg() != nil &&
			p0.Obj().Pkg().Path() == "fmt" && p0.Obj().Name() == "State" &&
			ok1 && p1.Kind() == types.Int32
	default:
		return false
	}
}

func ifaceHasUnexportedMethodInPkg(iface *types.Interface, pkg *types.Package) bool {
	if iface == nil || pkg == nil {
		return false
	}
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if m != nil && !m.Exported() && m.Pkg() == pkg {
			return true
		}
	}
	return false
}

// computePureIntraPkgFuncs computes via greatest fixed point over normalized
// flowir.Body representations the intra-package functions and methods that
// perform zero observable mutations or ambient effects (allowing only local
// variable and fresh make-slice writes).
func computePureIntraPkgFuncs(g *harnessGraph) map[*types.Func]bool {
	bodies := make(map[*types.Func]*flowir.Body, len(g.allDecls))
	pure := make(map[*types.Func]bool, len(g.allDecls))
	for fn, fd := range g.allDecls {
		if fd == nil || fd.Body == nil {
			continue
		}
		b := flowir.LowerFunc(g.info, g.pkgTypes, fd)
		if b == nil {
			continue
		}
		bodies[fn] = b
		pure[fn] = true
	}

	for changed := true; changed; {
		changed = false
		for fn := range pure {
			body := bodies[fn]
			freshSlices := map[*types.Var]bool{}
			for i := range body.Ops {
				op := &body.Ops[i]
				if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignPlain &&
					len(op.Dsts) == 1 && len(op.DstDefs) == 1 && op.DstDefs[0] && len(op.Srcs) == 1 {
					dst := op.Dsts[0]
					src := op.Srcs[0]
					if dst.IsBareVar() && dst.Root == flowir.RootLocal &&
						src != nil && src.Kind == flowir.ValAllocFresh && src.AllocKind == flowir.AllocMake &&
						varNeverReassigned(g.idx, dst.Obj) {
						if _, isSl := types.Unalias(dst.Obj.Type()).Underlying().(*types.Slice); isSl {
							freshSlices[dst.Obj] = true
						}
					}
				}
			}

			var checkVal func(*flowir.Value) bool
			checkVal = func(v *flowir.Value) bool {
				if v == nil {
					return true
				}
				switch v.Kind {
				case flowir.ValInvalid, flowir.ValAddrOf, flowir.ValMethodVal, flowir.ValMakeClosure, flowir.ValChanRecv:
					return false
				case flowir.ValPlace:
					switch v.Place.Root {
					case flowir.RootPkgGlobal:
						if v.Place.Obj == nil || !varNeverReassigned(g.idx, v.Place.Obj) {
							return false
						}
					case flowir.RootFunc:
						if v.Place.Func == nil {
							return false
						}
						orig := v.Place.Func.Origin()
						if orig.Pkg() == g.pkgTypes {
							if !pure[orig] {
								return false
							}
						} else {
							tr := auditset.DeterministicStdCallTraits(v.Place.FuncPkg, orig.Name())
							if orig.Signature() == nil || orig.Signature().Recv() != nil ||
								sigContainsFuncType(orig.Signature()) ||
								strings.HasPrefix(orig.Name(), "Append") || orig.Name() == "NewBuffer" ||
								tr.InPlaceContainerMutate || !tr.PureScalarOrValue {
								return false
							}
						}
					}
				case flowir.ValAllocFresh:
					if v.AllocKind != flowir.AllocMake {
						return false
					}
					if _, isSl := types.Unalias(v.Type).Underlying().(*types.Slice); !isSl {
						return false
					}
				case flowir.ValCall:
					switch v.CallKind {
					case flowir.CallBuiltin:
						if v.BuiltinName != "len" && v.BuiltinName != "cap" {
							return false
						}
					case flowir.CallPlain:
						if v.CalleeFunc == nil {
							return false
						}
						orig := v.CalleeFunc.Origin()
						if orig.Pkg() == g.pkgTypes {
							if !pure[orig] {
								return false
							}
						} else if v.CalleePkg == "fmt" {
							if orig.Name() != "Sprint" && orig.Name() != "Sprintf" && orig.Name() != "Sprintln" {
								return false
							}
							for _, a := range v.Args {
								if a == nil || !isSafePureLogFormatArgType(g, pure, a.Type, fn, false, map[types.Type]bool{}) {
									return false
								}
							}
						} else {
							if orig.Signature() == nil || orig.Signature().Recv() != nil ||
								sigContainsFuncType(orig.Signature()) ||
								strings.HasPrefix(orig.Name(), "Append") || orig.Name() == "NewBuffer" {
								return false
							}
							tr := auditset.DeterministicStdCallTraits(v.CalleePkg, orig.Name())
							if (!tr.PureScalarOrValue && !tr.ValuePlaneClone && !tr.ReadOnlySliceInspect) || tr.InPlaceContainerMutate {
								return false
							}
						}
					case flowir.CallMethod:
						if v.CalleeFunc == nil || v.CalleeSig == nil || v.CalleeSig.Recv() == nil {
							return false
						}
						orig := v.CalleeFunc.Origin()
						if orig.Pkg() == g.pkgTypes {
							if iface, isIface := v.CalleeSig.Recv().Type().Underlying().(*types.Interface); isIface {
								if orig.Name() != "String" || v.CalleeSig.Params().Len() != 0 ||
									v.CalleeSig.Results().Len() != 1 || !isStringType(v.CalleeSig.Results().At(0).Type()) ||
									!isPureSealedIntraPkgIface(g, pure, iface, fn, false, map[types.Type]bool{}) {
									return false
								}
							} else if !pure[orig] {
								return false
							}
						} else {
							switch v.CalleePkg {
							case "reflect":
								if !syntaxutil.IsReflectType(v.CalleeSig.Recv().Type()) {
									return false
								}
								switch orig.Name() {
								case "Name", "String", "PkgPath", "Kind":
								default:
									return false
								}
							case "time":
								named, okN := types.Unalias(v.CalleeSig.Recv().Type()).(*types.Named)
								if !okN || named.Obj() == nil || named.Obj().Name() != "Duration" || orig.Name() != "String" {
									return false
								}
							default:
								return false
							}
						}
					default:
						return false
					}
				}
				return v.ForEachChildValue(checkVal)
			}

			okBody := body.ForEachSyncOp(func(op *flowir.Op) bool {
				switch op.Kind {
				case flowir.OpAssign:
					for _, dst := range op.Dsts {
						if dst.IsBlank() {
							continue
						}
						if dst.IsBareVar() && (dst.Root == flowir.RootLocal || dst.Root == flowir.RootResult) {
							continue
						}
						if dst.Root == flowir.RootLocal && freshSlices[dst.Obj] &&
							len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjIndex &&
							(op.AssignKind == flowir.AssignPlain || op.AssignKind == flowir.AssignMulti) {
							continue
						}
						return false
					}
				case flowir.OpTypeSwitchBind, flowir.OpReturn, flowir.OpBranch, flowir.OpExpr:
				default:
					return false
				}
				return op.ForEachValue(checkVal)
			})
			if !okBody {
				delete(pure, fn)
				changed = true
			}
		}
	}
	return pure
}

// isSafePureLogFormatArgType checks that formatting a value of static type t
// cannot invoke any mutating or external formatting hook (rejecting unsealed
// interfaces, external non-scalar named types, intra-package named types with
// impure formatting/error methods, and — unless allowScopedTypeParams holds —
// type parameters).
func isSafePureLogFormatArgType(
	g *harnessGraph,
	pureFns map[*types.Func]bool,
	t types.Type,
	enclFn *types.Func,
	allowScopedTypeParams bool,
	seen map[types.Type]bool,
) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return true
	}
	seen[t] = true

	switch u := t.(type) {
	case *types.Basic:
		return u.Kind() != types.UnsafePointer
	case *types.TypeParam:
		if !allowScopedTypeParams || enclFn == nil || enclFn.Signature() == nil {
			return false
		}
		var recvTPs *types.TypeParamList
		if enclFn.Signature().Recv() != nil {
			if rn, ok := types.Unalias(enclFn.Signature().Recv().Type()).(*types.Pointer); ok {
				if named, okN := types.Unalias(rn.Elem()).(*types.Named); okN {
					recvTPs = named.Origin().TypeParams()
				}
			} else if named, okN := types.Unalias(enclFn.Signature().Recv().Type()).(*types.Named); okN {
				recvTPs = named.Origin().TypeParams()
			}
		}
		return typeParamInCallableScope(u, enclFn.Signature(), recvTPs)
	case *types.Named:
		if u.Obj() == nil || u.Obj().Pkg() == nil {
			return false
		}
		if targs := u.TypeArgs(); targs != nil {
			for i := 0; i < targs.Len(); i++ {
				if !isSafePureLogFormatArgType(g, pureFns, targs.At(i), enclFn, allowScopedTypeParams, seen) {
					return false
				}
			}
		}
		if u.Obj().Pkg() != g.pkgTypes {
			pPath := u.Obj().Pkg().Path()
			firstSeg := pPath
			if sl := strings.IndexByte(firstSeg, '/'); sl >= 0 {
				firstSeg = firstSeg[:sl]
			}
			if strings.IndexByte(firstSeg, '.') >= 0 {
				return false
			}
			basic, isBasic := u.Underlying().(*types.Basic)
			return isBasic && basic.Kind() != types.UnsafePointer
		}
		orig := u.Origin()
		for fn := range g.allDecls {
			if !isFmtOrErrorInterfaceMethod(fn) {
				continue
			}
			rt := types.Unalias(fn.Signature().Recv().Type())
			if ptr, isP := rt.(*types.Pointer); isP {
				rt = types.Unalias(ptr.Elem())
			}
			if rNamed, okN := rt.(*types.Named); okN && rNamed.Origin() == orig && !pureFns[fn] {
				return false
			}
		}
		return isSafePureLogFormatArgType(g, pureFns, u.Underlying(), enclFn, allowScopedTypeParams, seen)
	case *types.Interface:
		return isPureSealedIntraPkgIface(g, pureFns, u, enclFn, allowScopedTypeParams, seen)
	case *types.Pointer:
		return isSafePureLogFormatArgType(g, pureFns, u.Elem(), enclFn, allowScopedTypeParams, seen)
	case *types.Slice:
		return isSafePureLogFormatArgType(g, pureFns, u.Elem(), enclFn, allowScopedTypeParams, seen)
	case *types.Array:
		return isSafePureLogFormatArgType(g, pureFns, u.Elem(), enclFn, allowScopedTypeParams, seen)
	case *types.Map:
		return isSafePureLogFormatArgType(g, pureFns, u.Key(), enclFn, allowScopedTypeParams, seen) &&
			isSafePureLogFormatArgType(g, pureFns, u.Elem(), enclFn, allowScopedTypeParams, seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if !isSafePureLogFormatArgType(g, pureFns, u.Field(i).Type(), enclFn, allowScopedTypeParams, seen) {
				return false
			}
		}
		return true
	case *types.Chan:
		return true
	case *types.Signature:
		return false
	default:
		return false
	}
}

func sigContainsFuncType(sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	seen := map[types.Type]bool{}
	var hasSig func(types.Type) bool
	hasSig = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if seen[t] {
			return false
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Signature:
			return true
		case *types.Pointer:
			return hasSig(u.Elem())
		case *types.Slice:
			return hasSig(u.Elem())
		case *types.Array:
			return hasSig(u.Elem())
		case *types.Map:
			return hasSig(u.Key()) || hasSig(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if hasSig(u.Field(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if hasSig(sig.Params().At(i).Type()) {
			return true
		}
	}
	for i := 0; i < sig.Results().Len(); i++ {
		if hasSig(sig.Results().At(i).Type()) {
			return true
		}
	}
	return false
}

func isPureSealedIntraPkgIface(
	g *harnessGraph,
	pureFns map[*types.Func]bool,
	iface *types.Interface,
	enclFn *types.Func,
	allowScopedTypeParams bool,
	seen map[types.Type]bool,
) bool {
	if !ifaceHasUnexportedMethodInPkg(iface, g.pkgTypes) {
		return false
	}
	unexpNames := map[string]bool{}
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if m != nil && !m.Exported() && m.Pkg() == g.pkgTypes {
			unexpNames[m.Name()] = true
		}
	}
	for _, named := range g.declaredNamedTypes {
		if named == nil || named.Obj() == nil {
			continue
		}
		if named.TypeParams().Len() > 0 {
			hasEmbedded := false
			if st, okSt := named.Underlying().(*types.Struct); okSt {
				for i := 0; i < st.NumFields(); i++ {
					if st.Field(i).Embedded() {
						hasEmbedded = true
						break
					}
				}
			}
			matchesSeal := hasEmbedded
			if !matchesSeal {
				for fn := range g.allDecls {
					if fn.Signature() == nil || fn.Signature().Recv() == nil {
						continue
					}
					rt := types.Unalias(fn.Signature().Recv().Type())
					if ptr, isP := rt.(*types.Pointer); isP {
						rt = types.Unalias(ptr.Elem())
					}
					if rNamed, okN := rt.(*types.Named); okN && rNamed.Origin() == named && unexpNames[fn.Name()] {
						matchesSeal = true
						break
					}
				}
			}
			if matchesSeal {
				return false
			}
			continue
		}
		if !types.Implements(named, iface) && !types.Implements(types.NewPointer(named), iface) {
			continue
		}
		if named.Obj().Exported() || !isSafePureLogFormatArgType(g, pureFns, named, enclFn, allowScopedTypeParams, seen) {
			return false
		}
	}
	for _, tv := range g.info.Types {
		if tv.Type == nil {
			continue
		}
		ut := types.Unalias(tv.Type)
		if ptr, isP := ut.(*types.Pointer); isP {
			ut = types.Unalias(ptr.Elem())
		}
		st, isUnnamedSt := ut.(*types.Struct)
		if !isUnnamedSt {
			continue
		}
		if !types.Implements(st, iface) && !types.Implements(types.NewPointer(st), iface) {
			continue
		}
		mset := types.NewMethodSet(types.NewPointer(st))
		for i := 0; i < mset.Len(); i++ {
			fn, okFn := mset.At(i).Obj().(*types.Func)
			if okFn && isFmtOrErrorInterfaceMethod(fn) && (fn.Pkg() != g.pkgTypes || !pureFns[fn.Origin()]) {
				return false
			}
		}
		if !isSafePureLogFormatArgType(g, pureFns, st, enclFn, allowScopedTypeParams, seen) {
			return false
		}
	}
	return true
}

func isSinglePanicConstStub(info *types.Info, fd *ast.FuncDecl) bool {
	if fd == nil || fd.Body == nil || len(fd.Body.List) != 1 {
		return false
	}
	es, ok := fd.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := ast.Unparen(es.X).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	b := syntaxutil.LookupBuiltin(info, syntaxutil.UnwrapCallee(call.Fun))
	if b == nil || b.Name() != "panic" {
		return false
	}
	_, isLit := ast.Unparen(call.Args[0]).(*ast.BasicLit)
	return isLit
}

func funcBodyContainsAnyCall(info *types.Info, fd *ast.FuncDecl) bool {
	if fd == nil || fd.Body == nil {
		return false
	}
	sawCall := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if sawCall || n == nil {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && !info.Types[syntaxutil.UnwrapCallee(call.Fun)].IsType() {
			sawCall = true
			return false
		}
		return true
	})
	return sawCall
}

func isZeroFieldNoopLoggerExpr(g *harnessGraph, pureFns map[*types.Func]bool, e ast.Expr) bool {
	e = ast.Unparen(e)
	if un, isUn := e.(*ast.UnaryExpr); isUn && un.Op == token.AND {
		e = ast.Unparen(un.X)
	}
	cl, ok := e.(*ast.CompositeLit)
	if !ok || len(cl.Elts) != 0 {
		return false
	}
	named, ok := types.Unalias(g.info.TypeOf(cl)).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() != g.pkgTypes {
		return false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || st.NumFields() != 0 {
		return false
	}
	for fn, fd := range g.allDecls {
		sig := fn.Signature()
		if sig == nil || sig.Recv() == nil {
			continue
		}
		rt := types.Unalias(sig.Recv().Type())
		if ptr, isP := rt.(*types.Pointer); isP {
			rt = types.Unalias(ptr.Elem())
		}
		rNamed, okN := rt.(*types.Named)
		if !okN || rNamed.Origin() != named.Origin() {
			continue
		}
		if isSinglePanicConstStub(g.info, fd) {
			continue
		}
		// Non-panic methods on a 0-field noop logger must be pure and perform
		// zero calls (so Log/Logf discard args without invoking fmt.Sprint*).
		if !pureFns[fn] || funcBodyContainsAnyCall(g.info, fd) {
			return false
		}
	}
	return true
}

func isFormalParamIdentInEnclosingFunc(info *types.Info, idx *refconfine.PkgIndex, id *ast.Ident) bool {
	if id == nil || idx == nil {
		return false
	}
	pv, _ := info.Uses[id].(*types.Var)
	if pv == nil || !varNeverReassigned(idx, pv) {
		return false
	}
	checkFieldList := func(fl *ast.FieldList) bool {
		if fl == nil {
			return false
		}
		for _, fld := range fl.List {
			for _, nm := range fld.Names {
				if info.Defs[nm] == pv {
					return true
				}
			}
		}
		return false
	}
	for cur := idx.ParentMap[id]; cur != nil; cur = idx.ParentMap[cur] {
		switch fn := cur.(type) {
		case *ast.FuncLit:
			if fn.Type != nil && checkFieldList(fn.Type.Params) {
				return true
			}
		case *ast.FuncDecl:
			return fn.Type != nil && checkFieldList(fn.Type.Params)
		}
	}
	return false
}

func funcReachesOnlyDriversOrWrappers(g *harnessGraph, fn *types.Func) bool {
	if fn == nil || g.allDecls[fn] == nil || g.initOnly[fn] || g.initReached[fn] {
		return false
	}
	sc := g.screen
	visited := map[*types.Func]bool{fn: true}
	queue := []*types.Func{fn}
	sawDriverOrWrapper := false
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if g.initReached[cur] {
			return false
		}
		if cur.Exported() {
			if !sc.driverFuncs[cur] && !sc.wrapperFuncs[cur] {
				return false
			}
			sawDriverOrWrapper = true
		} else if g.isFuncValueTaken(cur) {
			return false
		}
		for caller := range g.strictCallersOf[cur] {
			if !visited[caller] {
				visited[caller] = true
				queue = append(queue, caller)
			}
		}
	}
	return sawDriverOrWrapper
}

// verifyStdoutBackedLoggerField proves that every write or struct-literal
// initialization of fv (*log.Logger field on HandleStruct) across non-driver
// execution paths supplies nil or log.New(os.Stdout, ...), never an in-memory
// buffer readable by non-driver callers.
func verifyStdoutBackedLoggerField(g *harnessGraph, fv *types.Var) bool {
	info := g.info
	idx := g.idx
	isSafeLoggerRHS := func(rhs ast.Expr, enclFn *types.Func) bool {
		rhs = ast.Unparen(rhs)
		if isNilIdent(info, rhs) || isLogNewStdoutCall(info, rhs) {
			return true
		}
		if enclFn != nil && funcReachesOnlyDriversOrWrappers(g, enclFn) {
			return true
		}
		pid, isID := rhs.(*ast.Ident)
		if !isID || enclFn == nil || enclFn.Exported() || g.isFuncValueTaken(enclFn) {
			return false
		}
		pv, _ := info.Uses[pid].(*types.Var)
		if pv == nil || !varNeverReassigned(idx, pv) {
			return false
		}
		sig := enclFn.Signature()
		if sig == nil {
			return false
		}
		paramIdx := -1
		for i := 0; i < sig.Params().Len(); i++ {
			if sig.Params().At(i) == pv {
				paramIdx = i
				break
			}
		}
		if paramIdx < 0 {
			return false
		}
		for _, cuid := range idx.UsesOf[enclFn] {
			call, isC := idx.ParentUnparen(cuid).(*ast.CallExpr)
			if !isC || ast.Unparen(call.Fun) != cuid || call.Ellipsis.IsValid() || paramIdx >= len(call.Args) {
				return false
			}
			arg := ast.Unparen(call.Args[paramIdx])
			if isNilIdent(info, arg) || isLogNewStdoutCall(info, arg) {
				continue
			}
			callerFD := idx.EnclFunc[call]
			var callerFn *types.Func
			if callerFD != nil && callerFD.Name != nil {
				if cfn, _ := info.Defs[callerFD.Name].(*types.Func); cfn != nil {
					callerFn = cfn.Origin()
				}
			}
			if callerFn != nil && funcReachesOnlyDriversOrWrappers(g, callerFn) {
				continue
			}
			return false
		}
		return true
	}

	for _, uid := range idx.UsesOf[fv] {
		enclFD := idx.EnclFunc[uid]
		var enclFn *types.Func
		if enclFD != nil && enclFD.Name != nil {
			if fn, _ := info.Defs[enclFD.Name].(*types.Func); fn != nil {
				enclFn = fn.Origin()
			}
		}
		par := idx.ParentUnparen(uid)
		if kv, isKV := par.(*ast.KeyValueExpr); isKV && kv.Key == uid {
			if !isSafeLoggerRHS(kv.Value, enclFn) {
				return false
			}
			continue
		}
		sel, isSel := par.(*ast.SelectorExpr)
		if !isSel || sel.Sel != uid {
			return false
		}
		if exprIsAddrTaken(idx, sel) {
			return false
		}
		if as, isAs := idx.ParentUnparen(sel).(*ast.AssignStmt); isAs {
			wroteHere := false
			for li, lhs := range as.Lhs {
				if ast.Unparen(lhs) == sel {
					wroteHere = true
					if as.Tok != token.ASSIGN || len(as.Lhs) != len(as.Rhs) || !isSafeLoggerRHS(as.Rhs[li], enclFn) {
						return false
					}
				}
			}
			if wroteHere {
				continue
			}
		}
		if refconfine.IdentOrExprIsWritten(idx, sel) {
			return false
		}
	}
	return true
}

// verifyTrustedLoggerIfaceFieldsAndParams computes via greatest fixed point the
// HandleStruct logger-interface fields and intra-package logger-interface
// parameters whose values on every non-driver execution path are guaranteed to
// be nil, an authentic formal *testing.T/*testing.B/*testing.F parameter, or a
// 0-field pure-noop struct literal.
func verifyTrustedLoggerIfaceFieldsAndParams(
	g *harnessGraph,
	pureFns map[*types.Func]bool,
	candFields map[*types.Var]bool,
	isKnownHandleLoggerIface func(types.Type) bool,
) (map[*types.Var]bool, map[loggingFuncParam]bool) {
	info := g.info
	idx := g.idx
	sc := g.screen

	trustedFields := make(map[*types.Var]bool, len(candFields))
	for f := range candFields {
		trustedFields[f] = true
	}

	trustedParams := map[loggingFuncParam]bool{}
	paramVarToKey := map[*types.Var]loggingFuncParam{}
	for fn, fd := range g.declFuncs {
		if fd == nil || fd.Body == nil || fn.Signature() == nil {
			continue
		}
		params := fn.Signature().Params()
		for i := 0; i < params.Len(); i++ {
			pv := params.At(i)
			if !isKnownHandleLoggerIface(pv.Type()) || idx.DefCounts[pv] > 1 {
				continue
			}
			key := loggingFuncParam{fn: fn, idx: i}
			paramVarToKey[pv] = key
			if funcReachesOnlyDriversOrWrappers(g, fn) || (!fn.Exported() && !g.isFuncValueTaken(fn)) {
				trustedParams[key] = true
			}
		}
	}

	isTrustedIfaceSource := func(rhs ast.Expr, enclFn *types.Func) bool {
		rhs = ast.Unparen(rhs)
		if isNilIdent(info, rhs) || isZeroFieldNoopLoggerExpr(g, pureFns, rhs) {
			return true
		}
		if enclFn != nil && funcReachesOnlyDriversOrWrappers(g, enclFn) {
			return true
		}
		if pid, isID := rhs.(*ast.Ident); isID {
			if rhsT := info.TypeOf(pid); rhsT != nil && isTestingHandlePtrType(rhsT) &&
				isFormalParamIdentInEnclosingFunc(info, idx, pid) {
				return true
			}
		}
		if sel, isSel := rhs.(*ast.SelectorExpr); isSel {
			fv, _ := info.Uses[sel.Sel].(*types.Var)
			if fv != nil && trustedFields[fv] && sc.isHandleStructPtr(info.TypeOf(sel.X)) {
				return true
			}
		}
		if pid, isID := rhs.(*ast.Ident); isID {
			pv, _ := info.Uses[pid].(*types.Var)
			if enclFn != nil {
				if key, ok := paramVarToKey[pv]; ok && key.fn == enclFn && trustedParams[key] {
					return true
				}
			}
			if pv != nil && varNeverReassigned(idx, pv) && idx.VarSpecs[pv] == nil {
				if enclFD := idx.EnclFunc[pid]; enclFD != nil && enclFD.Body != nil {
					var defRHS ast.Expr
					ast.Inspect(enclFD.Body, func(n ast.Node) bool {
						if defRHS != nil || n == nil {
							return false
						}
						as, okAs := n.(*ast.AssignStmt)
						if !okAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
							return true
						}
						if lid, okID := ast.Unparen(as.Lhs[0]).(*ast.Ident); okID && info.Defs[lid] == pv {
							defRHS = ast.Unparen(as.Rhs[0])
							return false
						}
						return true
					})
					if sel, isSel := defRHS.(*ast.SelectorExpr); isSel {
						fv, _ := info.Uses[sel.Sel].(*types.Var)
						if fv != nil && trustedFields[fv] && sc.isHandleStructPtr(info.TypeOf(sel.X)) {
							return true
						}
					}
				}
			}
		}
		return false
	}

	for changed := true; changed; {
		changed = false
		for key := range trustedParams {
			fn := key.fn
			pv := fn.Signature().Params().At(key.idx)
			okParam := true
			for _, u := range idx.UsesOf[pv] {
				if exprIsAddrTaken(idx, u) {
					okParam = false
					break
				}
				if as, isAs := idx.ParentUnparen(u).(*ast.AssignStmt); isAs {
					for li, lhs := range as.Lhs {
						if ast.Unparen(lhs) == u {
							if as.Tok != token.ASSIGN || len(as.Lhs) != len(as.Rhs) ||
								(!isNilIdent(info, as.Rhs[li]) && !isZeroFieldNoopLoggerExpr(g, pureFns, as.Rhs[li])) {
								okParam = false
								break
							}
						}
					}
					if !okParam {
						break
					}
					continue
				}
				if refconfine.IdentOrExprIsWritten(idx, u) {
					okParam = false
					break
				}
			}
			if okParam && !funcReachesOnlyDriversOrWrappers(g, fn) {
				if fn.Exported() || g.isFuncValueTaken(fn) {
					okParam = false
				} else {
					for _, cuid := range idx.UsesOf[fn] {
						call, isC := idx.ParentUnparen(cuid).(*ast.CallExpr)
						if !isC || ast.Unparen(call.Fun) != cuid || call.Ellipsis.IsValid() || key.idx >= len(call.Args) {
							okParam = false
							break
						}
						callerFD := idx.EnclFunc[call]
						var callerFn *types.Func
						if callerFD != nil && callerFD.Name != nil {
							if cfn, _ := info.Defs[callerFD.Name].(*types.Func); cfn != nil {
								callerFn = cfn.Origin()
							}
						}
						if !isTrustedIfaceSource(call.Args[key.idx], callerFn) {
							okParam = false
							break
						}
					}
				}
			}
			if !okParam {
				delete(trustedParams, key)
				changed = true
			}
		}

		for fv := range trustedFields {
			okField := true
			for _, uid := range idx.UsesOf[fv] {
				enclFD := idx.EnclFunc[uid]
				var enclFn *types.Func
				if enclFD != nil && enclFD.Name != nil {
					if fn, _ := info.Defs[enclFD.Name].(*types.Func); fn != nil {
						enclFn = fn.Origin()
					}
				}
				par := idx.ParentUnparen(uid)
				if kv, isKV := par.(*ast.KeyValueExpr); isKV && kv.Key == uid {
					if !isTrustedIfaceSource(kv.Value, enclFn) {
						okField = false
						break
					}
					continue
				}
				sel, isSel := par.(*ast.SelectorExpr)
				if !isSel || sel.Sel != uid {
					okField = false
					break
				}
				if exprIsAddrTaken(idx, sel) {
					okField = false
					break
				}
				if as, isAs := idx.ParentUnparen(sel).(*ast.AssignStmt); isAs {
					wroteHere := false
					for li, lhs := range as.Lhs {
						if ast.Unparen(lhs) == sel {
							wroteHere = true
							if as.Tok != token.ASSIGN || len(as.Lhs) != len(as.Rhs) || !isTrustedIfaceSource(as.Rhs[li], enclFn) {
								okField = false
								break
							}
						}
					}
					if !okField {
						break
					}
					if wroteHere {
						continue
					}
				}
				if refconfine.IdentOrExprIsWritten(idx, sel) {
					okField = false
					break
				}
			}
			if !okField {
				delete(trustedFields, fv)
				changed = true
			}
		}
	}
	return trustedFields, trustedParams
}
