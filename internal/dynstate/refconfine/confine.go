package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// Config configures mechanical read-only reference and pointer confinement
// across all syntax trees of a type-checked package.
//
// The engine tracks two monotonic properties over variables and intra-package
// call/return boundaries:
//   - isRef: the expression directly evaluates to a protected slice, map,
//     pointer, channel, or (when AllowIntraPkgInterfaceParam is set) an
//     intra-package opaque interface parameter. Mutating its elements or
//     pointee (x[i] = ..., *x = ..., p.f = ..., clear/copy/delete/append(x, ...),
//     &x[i], &p.f), type-asserting it, or invoking interface methods on it is
//     rejected.
//   - isCarrier: the expression evaluates to either a protected direct ref or a
//     composite value (struct/array, or fresh local container of carriers)
//     holding one. Projecting a field or element from a carrier yields isRef
//     when the projected component is a direct ref, or isCarrier when it still
//     contains one, while scalar projections evaluate untainted.
type Config struct {
	// Index optionally supplies the precomputed package syntax and confinement
	// index so callers running multiple confinement checks on p do not rebuild it.
	Index *PkgIndex

	// IsImmutablePtr optionally classifies a pointer type (such as an immutable
	// handle whose fields are separately verified write-once) as non-mutable.
	IsImmutablePtr func(types.Type) bool

	// SeedExpr reports whether expr directly introduces a protected reference/
	// pointer (isRef == true) or a composite value carrying one (isCarrier == true).
	SeedExpr func(expr ast.Expr) (isRef bool, isCarrier bool)

	// SeedStructOrigin optionally reports whether selecting fields from a named
	// struct origin declared in p.Types introduces protected references/pointers.
	SeedStructOrigin func(*types.Named) bool

	// CanBeSeedStructCapsule optionally reports whether an unexported non-generic
	// named struct origin declared in p.Types (with zero exported fields) may be
	// promoted into an active seed-struct capsule when a CompositeLit stores a
	// tainted reference/carrier into one of its fields. Promoted capsules are
	// additionally verified inside VerifyReadOnlyRefConfinement to have zero
	// direct field writes, whole-struct dereference writes, or field address-takes.
	CanBeSeedStructCapsule func(*types.Named) bool

	// AllowCompositeLitIntoSeedStruct permits storing tainted values into fields
	// of a CompositeLit of an unexported named struct S in p.Types when S.Origin()
	// is an active seed struct (via SeedStructOrigin or CanBeSeedStructCapsule),
	// because every subsequent field selection on S anywhere in p re-seeds taint.
	AllowCompositeLitIntoSeedStruct bool

	// AllowReturnFromUnexportedFunc propagates tainted return values from
	// concrete, non-generic, non-value-taken unexported functions/methods in
	// p.Types to their intra-package call sites, while still rejecting returns
	// from exported, generic, value-taken, or literal functions.
	AllowReturnFromUnexportedFunc bool

	// AllowIntraPkgInterfaceParam permits passing tainted arguments to interface
	// parameters of concrete, non-generic intra-package callees by marking the
	// parameter tainted (which still forbids type assertions, type switches,
	// interface method calls, assignments, returns, and unapproved forwarding).
	AllowIntraPkgInterfaceParam bool

	// AllowImmutableInterfaceElem optionally reports whether indexing or ranging
	// over containerExpr projects interface elements separately verified at all
	// store sites to carry zero mutable references.
	AllowImmutableInterfaceElem func(containerExpr ast.Expr) bool

	// AllowScalarTypeParamProjection permits projecting *types.TypeParam elements
	// as untainted scalars when all generic instantiations of shared seed structs
	// are verified to bind carrier-free, non-interface type arguments.
	AllowScalarTypeParamProjection bool

	// IsExemptField optionally reports whether reading an exported struct field
	// fv (without crossing an embedded pointer) yields a value whose own internal
	// reference/carrier fields are separately verified read-confined across p.Syntax.
	IsExemptField func(*types.Var) bool

	// AllowCallArg optionally approves passing a tainted argument arg (at argIdx)
	// to an external or protocol CallExpr verified to read arg without mutating
	// or retaining it.
	AllowCallArg func(call *ast.CallExpr, argIdx int, arg ast.Expr) bool

	// AllowMethodRecv optionally approves invoking a verified read-only method
	// callee on a tainted receiver expression recvExpr.
	AllowMethodRecv func(call *ast.CallExpr, callee *types.Func, recvExpr ast.Expr) bool

	// AllowAssignTarget optionally approves assigning a non-erased tainted
	// value rhs into a non-ident, non-slice-index target lhs (such as copying
	// an opaque unexported foreign struct value into a verified fresh target).
	AllowAssignTarget func(lhs, rhs ast.Expr, rhsIsRef bool) bool

	// ForbidNonNilSeedStructPtrCompare rejects non-nil pointer identity
	// comparisons (==/!=, switch tags/cases, and map keys) on pointers to
	// SeedStructOrigin structs, enforces recursive composite erasure checks
	// (assignErasesSeedStruct) on any type mentioning a SeedStructOrigin, and
	// forbids direct mutations or interior address-takes on SeedStructOrigin
	// structs outside AllowSeedStructMutationInFunc.
	ForbidNonNilSeedStructPtrCompare bool

	// AllowSeedStructMutationInFunc optionally names the sole *ast.FuncDecl
	// inside which synchronous mutations and interior address-takes on
	// SeedStructOrigin structs are permitted when ForbidNonNilSeedStructPtrCompare
	// is set.
	AllowSeedStructMutationInFunc *ast.FuncDecl
}

// VerifyReadOnlyRefConfinement verifies that every protected reference, pointer,
// or composite carrier seeded by cfg across p.Syntax remains strictly read-only
// and confined without element/pointee writes, address-takes, container-builtin
// mutations, interface/unsafe/pointer type erasures, or unapproved escapes.
func VerifyReadOnlyRefConfinement(p *packages.Package, cfg Config) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil {
		return false
	}
	idx := cfg.Index
	if idx == nil {
		idx = BuildPkgIndex(p)
		if idx == nil {
			return false
		}
	}
	info := p.TypesInfo
	isDirectRef := func(t types.Type) bool {
		return IsDirectMutableRefWith(t, cfg.IsImmutablePtr)
	}
	carriesRef := func(t types.Type) bool {
		return TypeCarriesMutableRefWith(t, cfg.IsImmutablePtr)
	}
	elemHasHandle := func(t types.Type) bool {
		return TypeContainsRefOrPointerWith(t, cfg.IsImmutablePtr)
	}
	isOpaqueIfaceOrTP := func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if _, isTP := t.(*types.TypeParam); isTP {
			return !cfg.AllowScalarTypeParamProjection
		}
		return types.IsInterface(t)
	}
	carriesRefOrIface := func(root types.Type) bool {
		seen := map[types.Type]bool{}
		hit := false
		var walk func(t types.Type)
		walk = func(t types.Type) {
			if t == nil || hit {
				return
			}
			t = types.Unalias(t)
			if cfg.IsImmutablePtr != nil && cfg.IsImmutablePtr(t) {
				return
			}
			if seen[t] {
				return
			}
			seen[t] = true
			if isDirectRef(t) || isOpaqueIfaceOrTP(t) {
				hit = true
				return
			}
			switch u := t.Underlying().(type) {
			case *types.Array:
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
	projectedClassify := func(et types.Type, containerExpr ast.Expr) (bool, bool) {
		if isDirectRef(et) {
			return true, true
		}
		if isOpaqueIfaceOrTP(et) {
			if containerExpr != nil && cfg.AllowImmutableInterfaceElem != nil && cfg.AllowImmutableInterfaceElem(containerExpr) {
				return false, false
			}
			return true, true
		}
		if carriesRefOrIface(et) {
			return false, true
		}
		return false, false
	}

	capsuleStructs := map[*types.Named]bool{}
	isSeedStruct := func(st *types.Named) bool {
		if st == nil {
			return false
		}
		orig := st.Origin()
		if capsuleStructs[orig] {
			return true
		}
		return cfg.SeedStructOrigin != nil && cfg.SeedStructOrigin(orig)
	}

	selChainHitsSeedStruct := func(sel *ast.SelectorExpr) bool {
		if cfg.SeedStructOrigin == nil && cfg.CanBeSeedStructCapsule == nil {
			return false
		}
		cur := ast.Expr(sel)
		for cur != nil {
			switch x := ast.Unparen(cur).(type) {
			case *ast.SelectorExpr:
				selInfo := info.Selections[x]
				if selInfo == nil || selInfo.Kind() != types.FieldVal {
					return false
				}
				hit := false
				syntaxutil.ForEachSelectionHopStruct(selInfo, func(st *types.Named) {
					if isSeedStruct(st) {
						hit = true
					}
				})
				if hit {
					return true
				}
				cur = x.X
			case *ast.IndexExpr:
				if st := syntaxutil.DerefNamedStruct(info.TypeOf(x)); isSeedStruct(st) {
					return true
				}
				cur = x.X
			case *ast.SliceExpr:
				cur = x.X
			case *ast.StarExpr:
				if st := syntaxutil.DerefNamedStruct(info.TypeOf(x.X)); isSeedStruct(st) {
					return true
				}
				cur = x.X
			default:
				return false
			}
		}
		return false
	}

	funcValueTaken := idx.FuncValueTaken
	calledMethodSels := idx.CalledMethodSels
	declBodies := idx.DeclBodies
	returnEnclFunc := idx.ReturnEnclFunc
	resultVarFunc := idx.ResultVarFunc
	litResultVars := idx.LitResultVars

	isNonGenericConcretePkgCallee := func(callee *types.Func) bool {
		if callee == nil || callee.Pkg() != p.Types || callee.Origin() != callee {
			return false
		}
		sig, ok := callee.Type().(*types.Signature)
		return ok && sig.TypeParams().Len() == 0 && sig.RecvTypeParams().Len() == 0
	}

	resolveConcretePkgCallee := func(fun ast.Expr) *types.Func {
		switch fn := ast.Unparen(fun).(type) {
		case *ast.Ident:
			if _, hasInst := info.Instances[fn]; hasInst {
				return nil
			}
			if callee, ok := info.Uses[fn].(*types.Func); ok && isNonGenericConcretePkgCallee(callee) {
				return callee
			}
		case *ast.SelectorExpr:
			if fn.Sel != nil {
				if _, hasInst := info.Instances[fn.Sel]; hasInst {
					return nil
				}
			}
			if selInfo := info.Selections[fn]; selInfo != nil {
				if types.IsInterface(selInfo.Recv()) || selInfo.Kind() == types.MethodExpr {
					return nil
				}
			}
			if callee, ok := info.Uses[fn.Sel].(*types.Func); ok && isNonGenericConcretePkgCallee(callee) {
				return callee
			}
		}
		return nil
	}

	canPropagateReturn := func(fn *types.Func) bool {
		if !cfg.AllowReturnFromUnexportedFunc ||
			fn == nil ||
			fn.Exported() ||
			!isNonGenericConcretePkgCallee(fn) ||
			funcValueTaken[fn.Origin()] {
			return false
		}
		sig, ok := fn.Type().(*types.Signature)
		return ok && sig.Recv() == nil
	}

	boundPkgMethodRecv := func(sel *ast.SelectorExpr) (*types.Var, bool) {
		if sel == nil || calledMethodSels[sel] {
			return nil, false
		}
		if sel.Sel != nil {
			if _, hasInst := info.Instances[sel.Sel]; hasInst {
				return nil, false
			}
		}
		selInfo := info.Selections[sel]
		if selInfo == nil || selInfo.Kind() != types.MethodVal || types.IsInterface(selInfo.Recv()) || len(selInfo.Index()) != 1 {
			return nil, false
		}
		mObj, ok := selInfo.Obj().(*types.Func)
		if !ok || mObj == nil {
			return nil, false
		}
		orig := mObj.Origin()
		if orig == nil || orig.Pkg() != p.Types || declBodies[orig] == nil {
			return nil, false
		}
		origSig, ok := orig.Type().(*types.Signature)
		if !ok || origSig.Recv() == nil || origSig.TypeParams().Len() > 0 {
			return nil, false
		}
		rv := origSig.Recv()
		if _, recvIsPtr := types.Unalias(rv.Type()).(*types.Pointer); recvIsPtr {
			xt := info.TypeOf(sel.X)
			if xt == nil {
				return nil, false
			}
			if _, xIsPtr := types.Unalias(xt).(*types.Pointer); !xIsPtr {
				return nil, false
			}
		}
		if origSig.RecvTypeParams().Len() > 0 {
			recvSt := syntaxutil.DerefNamedStruct(info.TypeOf(sel.X))
			if recvSt == nil {
				return nil, false
			}
			targs := recvSt.TypeArgs()
			if targs == nil || targs.Len() != origSig.RecvTypeParams().Len() {
				return nil, false
			}
			for i := 0; i < targs.Len(); i++ {
				ta := types.Unalias(targs.At(i))
				if _, isTP := ta.(*types.TypeParam); isTP {
					if !(cfg.AllowScalarTypeParamProjection && isSeedStruct(recvSt)) {
						return nil, false
					}
					continue
				}
				if carriesRefOrIface(ta) {
					return nil, false
				}
			}
		}
		return rv, true
	}

	isAllowedSeedStructCompositeLit := func(cl *ast.CompositeLit) bool {
		if !cfg.AllowCompositeLitIntoSeedStruct || (cfg.SeedStructOrigin == nil && len(capsuleStructs) == 0) {
			return false
		}
		lt := info.TypeOf(cl)
		if lt == nil {
			return false
		}
		lt = types.Unalias(lt)
		if ptr, isP := lt.(*types.Pointer); isP {
			lt = types.Unalias(ptr.Elem())
		}
		named, isN := lt.(*types.Named)
		if !isN || named.Obj() == nil || named.Obj().Pkg() != p.Types || named.Obj().Exported() {
			return false
		}
		if _, isSt := named.Underlying().(*types.Struct); !isSt {
			return false
		}
		return isSeedStruct(named)
	}

	assignErasesTaint := func(dstT, srcT types.Type) bool {
		if dstT == nil || srcT == nil {
			return true
		}
		d := types.Unalias(dstT)
		s := types.Unalias(srcT)
		if b, isB := d.Underlying().(*types.Basic); isB && b.Kind() == types.UnsafePointer {
			return true
		}
		if _, isIface := d.Underlying().(*types.Interface); isIface {
			return true
		}
		if dPtr, isDP := d.Underlying().(*types.Pointer); isDP {
			if sPtr, isSP := s.Underlying().(*types.Pointer); isSP {
				if !types.Identical(types.Unalias(dPtr.Elem()), types.Unalias(sPtr.Elem())) {
					return true
				}
			}
		}
		if _, isDS := d.Underlying().(*types.Struct); isDS {
			if _, isSS := s.Underlying().(*types.Struct); isSS {
				if !types.Identical(d, s) {
					return true
				}
			}
		}
		return false
	}

	indexValueType := func(ix *ast.IndexExpr) types.Type {
		et := info.TypeOf(ix)
		if tup, isTup := et.(*types.Tuple); isTup && tup.Len() > 0 {
			return tup.At(0).Type()
		}
		return et
	}

	type retSlot struct {
		fn  *types.Func
		idx int
	}
	errorType := types.Universe.Lookup("error").Type()
	taintedRef := map[*types.Var]bool{}
	taintedCarrier := map[*types.Var]bool{}
	taintedRetRef := map[retSlot]bool{}
	taintedRetCarrier := map[retSlot]bool{}
	taintedRetAnyRef := map[*types.Func]bool{}
	taintedRetAnyCarrier := map[*types.Func]bool{}

	var classifyExpr func(expr ast.Expr) (isRef bool, isCarrier bool)
	var classifyMultiReturnSlot func(rhs ast.Expr, slot int, slotType types.Type) (isRef bool, isCarrier bool)
	var exprMutatesTaintedTarget func(expr ast.Expr) bool

	classifyExpr = func(expr ast.Expr) (bool, bool) {
		expr = ast.Unparen(expr)
		if expr == nil {
			return false, false
		}
		if cfg.SeedExpr != nil {
			if sRef, sCar := cfg.SeedExpr(expr); sRef || sCar {
				return sRef, sRef || sCar
			}
		}
		switch e := expr.(type) {
		case *ast.Ident:
			if v, ok := info.Uses[e].(*types.Var); ok && v != nil {
				return taintedRef[v], taintedRef[v] || taintedCarrier[v]
			}
			return false, false

		case *ast.SelectorExpr:
			selInfo := info.Selections[e]
			if selInfo != nil && selInfo.Kind() == types.FieldVal {
				if cfg.IsExemptField != nil && !syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
					if fv, isFV := selInfo.Obj().(*types.Var); isFV && cfg.IsExemptField(fv) {
						return false, false
					}
				}
				ft := selInfo.Type()
				if selChainHitsSeedStruct(e) {
					if isDirectRef(ft) {
						return true, true
					}
					if carriesRef(ft) {
						return false, true
					}
				}
				_, bCar := classifyExpr(e.X)
				if bCar {
					return projectedClassify(ft, e.X)
				}
				return false, false
			}
			if selInfo != nil && selInfo.Kind() == types.MethodVal && !calledMethodSels[e] {
				if _, bCar := classifyExpr(e.X); bCar || exprMutatesTaintedTarget(e.X) || selChainHitsSeedStruct(e) || isSeedStruct(syntaxutil.DerefNamedStruct(info.TypeOf(e.X))) {
					if _, okM := boundPkgMethodRecv(e); !okM {
						return true, true
					}
				}
			}
			return false, false

		case *ast.IndexExpr:
			_, bCar := classifyExpr(e.X)
			if bCar {
				return projectedClassify(indexValueType(e), e.X)
			}
			return false, false

		case *ast.SliceExpr:
			bRef, bCar := classifyExpr(e.X)
			if bRef {
				return true, true
			}
			if bCar {
				return false, true
			}
			return false, false

		case *ast.StarExpr:
			_, bCar := classifyExpr(e.X)
			if bCar {
				return projectedClassify(info.TypeOf(e), e.X)
			}
			return false, false

		case *ast.UnaryExpr:
			if e.Op == token.AND {
				if cl, isCL := ast.Unparen(e.X).(*ast.CompositeLit); isCL && isAllowedSeedStructCompositeLit(cl) {
					return false, false
				}
				bRef, bCar := classifyExpr(e.X)
				if exprMutatesTaintedTarget(e.X) {
					return true, true
				}
				if bRef || bCar {
					return false, true
				}
				return false, false
			}
			if e.Op == token.ARROW {
				_, cCar := classifyExpr(e.X)
				if cCar {
					et := indexValueTypeFromType(info.TypeOf(e))
					return isDirectRef(et), true
				}
			}
			return false, false

		case *ast.CompositeLit:
			if isAllowedSeedStructCompositeLit(e) {
				return false, false
			}
			for _, elt := range e.Elts {
				val := elt
				if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
					if _, kCar := classifyExpr(kv.Key); kCar {
						return false, true
					}
					val = kv.Value
				}
				if _, vCar := classifyExpr(val); vCar {
					return false, true
				}
			}
			return false, false

		case *ast.CallExpr:
			fun := ast.Unparen(e.Fun)
			if info.Types[fun].IsType() && len(e.Args) == 1 {
				aRef, aCar := classifyExpr(e.Args[0])
				if !aCar {
					return false, false
				}
				dstT := info.Types[fun].Type
				if !elemHasHandle(dstT) && !syntaxutil.ContainsUintptr(dstT) {
					return false, false
				}
				return aRef || isDirectRef(dstT), true
			}
			if b := syntaxutil.LookupBuiltin(info, fun); b != nil {
				switch b.Name() {
				case "make", "new", "len", "cap", "Sizeof", "Alignof", "Offsetof":
					return false, false
				case "append":
					if len(e.Args) == 0 {
						return false, false
					}
					dRef, dCar := classifyExpr(e.Args[0])
					elemTainted := false
					var slElem types.Type
					if sl, ok := syntaxutil.UnderlyingType(info.TypeOf(e)).(*types.Slice); ok {
						slElem = sl.Elem()
					}
					for _, arg := range e.Args[1:] {
						_, aCar := classifyExpr(arg)
						if !aCar {
							continue
						}
						if e.Ellipsis.IsValid() {
							if elemHasHandle(slElem) {
								elemTainted = true
							}
						} else {
							elemTainted = true
						}
					}
					return dRef, dRef || dCar || elemTainted
				}
			}
			if callee := resolveConcretePkgCallee(e.Fun); callee != nil {
				if taintedRetAnyRef[callee] || taintedRetAnyCarrier[callee] {
					return taintedRetAnyRef[callee], true
				}
				return false, false
			}
			return false, false

		case *ast.TypeAssertExpr:
			_, xCar := classifyExpr(e.X)
			if xCar {
				return true, true
			}
			return false, false
		}

		hit := false
		ast.Inspect(expr, func(child ast.Node) bool {
			if hit || child == nil {
				return false
			}
			if child == expr {
				return true
			}
			if ce, ok := child.(ast.Expr); ok {
				if _, cCar := classifyExpr(ce); cCar {
					hit = true
				}
				return false
			}
			return true
		})
		if hit {
			et := info.TypeOf(expr)
			if isDirectRef(et) || types.IsInterface(et) {
				return true, true
			}
			if carriesRefOrIface(et) {
				return false, true
			}
		}
		return false, false
	}

	exprMutatesTaintedTarget = func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		switch x := expr.(type) {
		case *ast.StarExpr:
			if bRef, _ := classifyExpr(x.X); bRef {
				return true
			}
			return exprMutatesTaintedTarget(x.X)
		case *ast.IndexExpr:
			xt := info.TypeOf(x.X)
			if xt != nil {
				switch types.Unalias(xt).Underlying().(type) {
				case *types.Slice, *types.Map, *types.Pointer:
					if bRef, _ := classifyExpr(x.X); bRef {
						return true
					}
				}
			}
			return exprMutatesTaintedTarget(x.X)
		case *ast.SelectorExpr:
			if selInfo := info.Selections[x]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				if xt := info.TypeOf(x.X); xt != nil {
					if _, isPtr := types.Unalias(xt).Underlying().(*types.Pointer); isPtr {
						if bRef, _ := classifyExpr(x.X); bRef {
							return true
						}
					}
				}
				if syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
					if _, bCar := classifyExpr(x.X); bCar {
						return true
					}
				}
				return exprMutatesTaintedTarget(x.X)
			}
		case *ast.SliceExpr:
			return exprMutatesTaintedTarget(x.X)
		}
		return false
	}

	markVarTaint := func(v *types.Var, addRef, addCar bool) bool {
		if v == nil || !addCar {
			return false
		}
		progressed := false
		if !taintedCarrier[v] {
			taintedCarrier[v] = true
			progressed = true
		}
		if addRef && !taintedRef[v] {
			taintedRef[v] = true
			progressed = true
		}
		return progressed
	}

	isEligibleCapsule := func(orig *types.Named) bool {
		if orig == nil || orig.Obj() == nil || orig.Obj().Pkg() != p.Types || orig.Obj().Exported() || orig.TypeParams().Len() > 0 {
			return false
		}
		st, isSt := orig.Underlying().(*types.Struct)
		if !isSt {
			return false
		}
		for i := 0; i < st.NumFields(); i++ {
			if st.Field(i).Exported() {
				return false
			}
		}
		return true
	}

	classifyMultiReturnSlot = func(rhs ast.Expr, slot int, slotType types.Type) (bool, bool) {
		rhs = ast.Unparen(rhs)
		if rhs == nil {
			return false, false
		}
		if call, isCall := rhs.(*ast.CallExpr); isCall {
			if cfg.SeedExpr != nil {
				if _, sCar := cfg.SeedExpr(call); sCar {
					if isDirectRef(slotType) {
						return true, true
					}
					if carriesRef(slotType) {
						return false, true
					}
					if isOpaqueIfaceOrTP(slotType) && !types.Identical(slotType, errorType) {
						return true, true
					}
					return false, false
				}
			}
			if callee := resolveConcretePkgCallee(call.Fun); callee != nil {
				rk := retSlot{fn: callee, idx: slot}
				return taintedRetRef[rk], taintedRetRef[rk] || taintedRetCarrier[rk]
			}
			return false, false
		}
		if _, rCar := classifyExpr(rhs); !rCar || slot != 0 {
			return false, false
		}
		if ix, isIX := rhs.(*ast.IndexExpr); isIX {
			return projectedClassify(slotType, ix.X)
		}
		return projectedClassify(slotType, nil)
	}

	for {
		clear(taintedRef)
		clear(taintedCarrier)
		clear(taintedRetRef)
		clear(taintedRetCarrier)
		clear(taintedRetAnyRef)
		clear(taintedRetAnyCarrier)

		changed := true
		for changed {
			changed = false
			for _, file := range p.Syntax {
				ast.Inspect(file, func(n ast.Node) bool {
					if n == nil {
						return false
					}
					switch s := n.(type) {
					case *ast.SelectorExpr:
						if selInfo := info.Selections[s]; selInfo != nil && selInfo.Kind() == types.MethodVal && !calledMethodSels[s] {
							xRef, xCar := classifyExpr(s.X)
							mutX := exprMutatesTaintedTarget(s.X)
							seedX := selChainHitsSeedStruct(s) || isSeedStruct(syntaxutil.DerefNamedStruct(info.TypeOf(s.X)))
							if xCar || mutX || seedX {
								if rv, okM := boundPkgMethodRecv(s); okM {
									_, recvIsPtr := types.Unalias(rv.Type()).(*types.Pointer)
									addRef := xRef || mutX || recvIsPtr || isDirectRef(rv.Type())
									if markVarTaint(rv, addRef, true) {
										changed = true
									}
								}
							}
						}

					case *ast.AssignStmt:
						if len(s.Lhs) == len(s.Rhs) {
							for i, lhs := range s.Lhs {
								rRef, rCar := classifyExpr(s.Rhs[i])
								if !rCar {
									continue
								}
								if v := syntaxutil.LookupIdentVar(info, lhs); v != nil {
									if markVarTaint(v, rRef, true) {
										changed = true
									}
								} else if ix, isIX := ast.Unparen(lhs).(*ast.IndexExpr); isIX {
									if bv := syntaxutil.LookupIdentVar(info, ix.X); bv != nil {
										if markVarTaint(bv, false, true) {
											changed = true
										}
									}
								}
							}
						} else if len(s.Lhs) > 1 && len(s.Rhs) == 1 {
							rhsTup, _ := info.TypeOf(s.Rhs[0]).(*types.Tuple)
							for i, lhs := range s.Lhs {
								v := syntaxutil.LookupIdentVar(info, lhs)
								if v == nil {
									continue
								}
								slotT := v.Type()
								if rhsTup != nil && i < rhsTup.Len() {
									slotT = rhsTup.At(i).Type()
								}
								if pRef, pCar := classifyMultiReturnSlot(s.Rhs[0], i, slotT); pCar {
									addRef := pRef || isOpaqueIfaceOrTP(v.Type())
									if markVarTaint(v, addRef, true) {
										changed = true
									}
								}
							}
						}

					case *ast.ValueSpec:
						if len(s.Names) == len(s.Values) {
							for i, nm := range s.Names {
								rRef, rCar := classifyExpr(s.Values[i])
								if !rCar {
									continue
								}
								if v, ok := info.Defs[nm].(*types.Var); ok && v != nil {
									if markVarTaint(v, rRef, true) {
										changed = true
									}
								}
							}
						} else if len(s.Names) > 1 && len(s.Values) == 1 {
							rhsTup, _ := info.TypeOf(s.Values[0]).(*types.Tuple)
							for i, nm := range s.Names {
								v, ok := info.Defs[nm].(*types.Var)
								if !ok || v == nil {
									continue
								}
								slotT := v.Type()
								if rhsTup != nil && i < rhsTup.Len() {
									slotT = rhsTup.At(i).Type()
								}
								if pRef, pCar := classifyMultiReturnSlot(s.Values[0], i, slotT); pCar {
									addRef := pRef || isOpaqueIfaceOrTP(v.Type())
									if markVarTaint(v, addRef, true) {
										changed = true
									}
								}
							}
						}

					case *ast.RangeStmt:
						_, xCar := classifyExpr(s.X)
						if xCar {
							for _, bindExpr := range []ast.Expr{s.Key, s.Value} {
								if bindExpr == nil {
									continue
								}
								if v := syntaxutil.LookupIdentVar(info, bindExpr); v != nil {
									if pRef, pCar := projectedClassify(v.Type(), s.X); pCar {
										if markVarTaint(v, pRef, true) {
											changed = true
										}
									}
								}
							}
						}

					case *ast.CallExpr:
						callee := resolveConcretePkgCallee(s.Fun)
						if callee == nil {
							return true
						}
						sig, ok := callee.Type().(*types.Signature)
						if !ok {
							return true
						}
						if sel, isSel := ast.Unparen(s.Fun).(*ast.SelectorExpr); isSel && sig.Recv() != nil {
							if selInfo := info.Selections[sel]; selInfo != nil && selInfo.Kind() == types.MethodVal {
								rv := sig.Recv()
								xRef, xCar := classifyExpr(sel.X)
								if xCar {
									addRef := xRef || (isDirectRef(rv.Type()) && exprMutatesTaintedTarget(sel.X))
									if markVarTaint(rv, addRef, true) {
										changed = true
									}
								}
							}
						}
						if len(s.Args) == 1 {
							if tup, isTup := info.TypeOf(s.Args[0]).(*types.Tuple); isTup {
								for pi := 0; pi < sig.Params().Len() && pi < tup.Len(); pi++ {
									sRef, sCar := classifyMultiReturnSlot(s.Args[0], pi, tup.At(pi).Type())
									if !sCar {
										continue
									}
									pv := sig.Params().At(pi)
									addRef := sRef || (cfg.AllowIntraPkgInterfaceParam && types.IsInterface(pv.Type()))
									if markVarTaint(pv, addRef, true) {
										changed = true
									}
								}
								return true
							}
						}
						for i, arg := range s.Args {
							aRef, aCar := classifyExpr(arg)
							if !aCar {
								continue
							}
							paramIdx := i
							isNonEllipsisVariadic := false
							if sig.Variadic() && i >= sig.Params().Len()-1 {
								paramIdx = sig.Params().Len() - 1
								isNonEllipsisVariadic = !s.Ellipsis.IsValid()
							}
							if paramIdx < sig.Params().Len() {
								pv := sig.Params().At(paramIdx)
								if isNonEllipsisVariadic {
									if markVarTaint(pv, false, true) {
										changed = true
									}
								} else {
									addRef := aRef || (cfg.AllowIntraPkgInterfaceParam && types.IsInterface(pv.Type()))
									if markVarTaint(pv, addRef, true) {
										changed = true
									}
								}
							}
						}

					case *ast.ReturnStmt:
						fn := returnEnclFunc[s]
						if !canPropagateReturn(fn) {
							return true
						}
						if len(s.Results) == 0 {
							sig := fn.Signature()
							for ri := 0; ri < sig.Results().Len(); ri++ {
								rv := sig.Results().At(ri)
								rk := retSlot{fn: fn, idx: ri}
								if taintedCarrier[rv] && !taintedRetCarrier[rk] {
									taintedRetCarrier[rk] = true
									taintedRetAnyCarrier[fn] = true
									changed = true
								}
								if taintedRef[rv] && !taintedRetRef[rk] {
									taintedRetRef[rk] = true
									taintedRetAnyRef[fn] = true
									changed = true
								}
							}
						} else if len(s.Results) == 1 {
							if tup, isTup := info.TypeOf(s.Results[0]).(*types.Tuple); isTup {
								for ri := 0; ri < tup.Len(); ri++ {
									rRef, rCar := classifyMultiReturnSlot(s.Results[0], ri, tup.At(ri).Type())
									rk := retSlot{fn: fn, idx: ri}
									if rCar && !taintedRetCarrier[rk] {
										taintedRetCarrier[rk] = true
										taintedRetAnyCarrier[fn] = true
										changed = true
									}
									if rRef && !taintedRetRef[rk] {
										taintedRetRef[rk] = true
										taintedRetAnyRef[fn] = true
										changed = true
									}
								}
								return true
							}
							rRef, rCar := classifyExpr(s.Results[0])
							rk := retSlot{fn: fn, idx: 0}
							if rCar && !taintedRetCarrier[rk] {
								taintedRetCarrier[rk] = true
								taintedRetAnyCarrier[fn] = true
								changed = true
							}
							if rRef && !taintedRetRef[rk] {
								taintedRetRef[rk] = true
								taintedRetAnyRef[fn] = true
								changed = true
							}
						} else {
							for ri, r := range s.Results {
								rRef, rCar := classifyExpr(r)
								rk := retSlot{fn: fn, idx: ri}
								if rCar && !taintedRetCarrier[rk] {
									taintedRetCarrier[rk] = true
									taintedRetAnyCarrier[fn] = true
									changed = true
								}
								if rRef && !taintedRetRef[rk] {
									taintedRetRef[rk] = true
									taintedRetAnyRef[fn] = true
									changed = true
								}
							}
						}
					}
					return true
				})
			}
		}

		promoted := false
		if cfg.AllowCompositeLitIntoSeedStruct && cfg.CanBeSeedStructCapsule != nil {
			for _, file := range p.Syntax {
				ast.Inspect(file, func(n ast.Node) bool {
					cl, isCL := n.(*ast.CompositeLit)
					if !isCL {
						return true
					}
					st := syntaxutil.DerefNamedStruct(info.TypeOf(cl))
					if st == nil {
						return true
					}
					orig := st.Origin()
					if isSeedStruct(orig) || !isEligibleCapsule(orig) || !cfg.CanBeSeedStructCapsule(orig) {
						return true
					}
					for _, elt := range cl.Elts {
						val := elt
						if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
							val = kv.Value
						}
						if _, vCar := classifyExpr(val); vCar {
							capsuleStructs[orig] = true
							promoted = true
							break
						}
					}
					return true
				})
			}
		}
		if !promoted {
			break
		}
	}

	// Reject any tainted package-scope variable or disallowed named result variable.
	for v := range taintedCarrier {
		if v.Parent() == p.Types.Scope() || litResultVars[v] {
			return false
		}
		if fn, isRes := resultVarFunc[v]; isRes && !canPropagateReturn(fn) {
			return false
		}
	}

	// Identify local container variables whose backing storage is provably freshly
	// allocated in the declaring function (from precomputed idx.FreshContainerCandidates)
	// and not directly tainted as a protected reference.
	localFreshContainer := make(map[*types.Var]bool, len(idx.FreshContainerCandidates))
	for v := range idx.FreshContainerCandidates {
		if !taintedRef[v] {
			localFreshContainer[v] = true
		}
	}

	// Track `v = append(v, elem)` statements where v is a fresh local slice variable.
	selfAssignedAppendCalls := map[*ast.CallExpr]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			lv := syntaxutil.LookupIdentVar(info, as.Lhs[0])
			if lv == nil || !localFreshContainer[lv] {
				return true
			}
			call, ok := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if syntaxutil.LookupIdentVar(info, call.Args[0]) == lv {
				selfAssignedAppendCalls[call] = true
			}
			return true
		})
	}

	// Verify promoted capsule structs have zero direct field writes, whole-struct
	// dereference writes, or interior field address-takes anywhere in p.Syntax.
	if len(capsuleStructs) > 0 && !verifyCapsuleStructsWriteFree(p, capsuleStructs) {
		return false
	}

	isPtrToSeedStruct := func(t types.Type) bool {
		if t == nil {
			return false
		}
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		st, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && isSeedStruct(st)
	}
	typeContainsPtrToSeedStruct := func(root types.Type) bool {
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
			if isPtrToSeedStruct(t) {
				hit = true
				return
			}
			switch u := t.Underlying().(type) {
			case *types.Array:
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

	seedStructTypeViolated := func(dstT, srcT types.Type) bool {
		if cfg.ForbidNonNilSeedStructPtrCompare {
			if typeMentionsSeedStruct(srcT, isSeedStruct) {
				if dstT == nil || syntaxutil.IsUnsafePointerType(dstT) {
					return true
				}
				if assignErasesSeedStruct(srcT, dstT, isSeedStruct) {
					return true
				}
			}
		}
		srcSt := syntaxutil.DerefNamedStruct(srcT)
		if !isSeedStruct(srcSt) {
			return false
		}
		if dstT == nil {
			return true
		}
		d := types.Unalias(dstT)
		if _, isTP := d.(*types.TypeParam); isTP {
			return true
		}
		if iface, isIface := d.Underlying().(*types.Interface); isIface {
			return cfg.ForbidNonNilSeedStructPtrCompare || iface.NumMethods() == 0
		}
		return !types.Identical(d, types.Unalias(srcT))
	}

	ok := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !ok || n == nil {
				return false
			}
			inSyncAllowed := !cfg.ForbidNonNilSeedStructPtrCompare || idx.IsSyncInFuncDecl(n, cfg.AllowSeedStructMutationInFunc)
			switch s := n.(type) {
			case *ast.BinaryExpr:
				if cfg.ForbidNonNilSeedStructPtrCompare && (s.Op == token.EQL || s.Op == token.NEQ) {
					lt := info.TypeOf(s.X)
					rt := info.TypeOf(s.Y)
					if (isPtrToSeedStruct(lt) && !syntaxutil.IsNilIdent(info, s.Y)) ||
						(isPtrToSeedStruct(rt) && !syntaxutil.IsNilIdent(info, s.X)) {
						ok = false
						return false
					}
				}

			case *ast.SwitchStmt:
				if cfg.ForbidNonNilSeedStructPtrCompare && s.Tag != nil && isPtrToSeedStruct(info.TypeOf(s.Tag)) && s.Body != nil {
					for _, st := range s.Body.List {
						if cc, okCC := st.(*ast.CaseClause); okCC {
							for _, ce := range cc.List {
								if !syntaxutil.IsNilIdent(info, ce) {
									ok = false
									return false
								}
							}
						}
					}
				}

			case *ast.CaseClause:
				if cfg.ForbidNonNilSeedStructPtrCompare {
					for _, ce := range s.List {
						if !syntaxutil.IsNilIdent(info, ce) && isPtrToSeedStruct(info.TypeOf(ce)) {
							ok = false
							return false
						}
					}
				}

			case *ast.MapType:
				if cfg.ForbidNonNilSeedStructPtrCompare && typeContainsPtrToSeedStruct(info.TypeOf(s.Key)) {
					ok = false
					return false
				}

			case *ast.SelectorExpr:
				if selInfo := info.Selections[s]; selInfo != nil && selInfo.Kind() == types.MethodVal && !calledMethodSels[s] {
					if _, xCar := classifyExpr(s.X); xCar || exprMutatesTaintedTarget(s.X) || selChainHitsSeedStruct(s) || isSeedStruct(syntaxutil.DerefNamedStruct(info.TypeOf(s.X))) {
						if _, okM := boundPkgMethodRecv(s); !okM {
							ok = false
							return false
						}
					}
				}

			case *ast.TypeAssertExpr:
				if _, xCar := classifyExpr(s.X); xCar {
					ok = false
					return false
				}

			case *ast.TypeSwitchStmt:
				switch a := s.Assign.(type) {
				case *ast.ExprStmt:
					if ta, isTA := ast.Unparen(a.X).(*ast.TypeAssertExpr); isTA {
						if _, xCar := classifyExpr(ta.X); xCar {
							ok = false
							return false
						}
					}
				case *ast.AssignStmt:
					if len(a.Rhs) == 1 {
						if ta, isTA := ast.Unparen(a.Rhs[0]).(*ast.TypeAssertExpr); isTA {
							if _, xCar := classifyExpr(ta.X); xCar {
								ok = false
								return false
							}
						}
					}
				}

			case *ast.AssignStmt:
				for _, lhs := range s.Lhs {
					if exprMutatesTaintedTarget(lhs) || (!inSyncAllowed && exprHitsStructPred(info, lhs, isSeedStruct, true)) {
						ok = false
						return false
					}
					if ix, isIX := ast.Unparen(lhs).(*ast.IndexExpr); isIX {
						if xt := info.TypeOf(ix.X); xt != nil {
							if _, isMap := types.Unalias(xt).Underlying().(*types.Map); isMap {
								if _, kCar := classifyExpr(ix.Index); kCar {
									ok = false
									return false
								}
							}
						}
					}
				}
				if len(s.Lhs) == len(s.Rhs) {
					for i, lhs := range s.Lhs {
						if (!syntaxutil.IsBlankIdent(lhs) || cfg.ForbidNonNilSeedStructPtrCompare) && seedStructTypeViolated(info.TypeOf(lhs), info.TypeOf(s.Rhs[i])) {
							ok = false
							return false
						}
						rRef, rCar := classifyExpr(s.Rhs[i])
						if !rCar {
							continue
						}
						if syntaxutil.IsBlankIdent(lhs) {
							continue
						}
						if v := syntaxutil.LookupIdentVar(info, lhs); v != nil {
							if assignErasesTaint(v.Type(), info.TypeOf(s.Rhs[i])) {
								ok = false
								return false
							}
							continue
						}
						if ix, isIX := ast.Unparen(lhs).(*ast.IndexExpr); isIX {
							if bv := syntaxutil.LookupIdentVar(info, ix.X); bv != nil && localFreshContainer[bv] {
								if !assignErasesTaint(info.TypeOf(ix), info.TypeOf(s.Rhs[i])) {
									continue
								}
							}
						}
						if cfg.AllowAssignTarget != nil &&
							!assignErasesTaint(info.TypeOf(lhs), info.TypeOf(s.Rhs[i])) &&
							cfg.AllowAssignTarget(lhs, s.Rhs[i], rRef) {
							continue
						}
						ok = false
						return false
					}
				} else if len(s.Lhs) > 1 && len(s.Rhs) == 1 {
					rhsT := info.TypeOf(s.Rhs[0])
					rhsTup, _ := rhsT.(*types.Tuple)
					if rhsTup != nil {
						for i, lhs := range s.Lhs {
							if i < rhsTup.Len() && (!syntaxutil.IsBlankIdent(lhs) || cfg.ForbidNonNilSeedStructPtrCompare) && seedStructTypeViolated(info.TypeOf(lhs), rhsTup.At(i).Type()) {
								ok = false
								return false
							}
						}
					} else if cfg.ForbidNonNilSeedStructPtrCompare && seedStructTypeViolated(info.TypeOf(s.Lhs[0]), rhsT) {
						ok = false
						return false
					}
					for i, lhs := range s.Lhs {
						var srcElemT types.Type
						if rhsTup != nil && i < rhsTup.Len() {
							srcElemT = rhsTup.At(i).Type()
						} else {
							srcElemT = info.TypeOf(lhs)
						}
						if _, sCar := classifyMultiReturnSlot(s.Rhs[0], i, srcElemT); !sCar {
							continue
						}
						if syntaxutil.IsBlankIdent(lhs) {
							continue
						}
						v := syntaxutil.LookupIdentVar(info, lhs)
						if v == nil || assignErasesTaint(v.Type(), srcElemT) {
							ok = false
							return false
						}
					}
				}

			case *ast.ValueSpec:
				if len(s.Names) == len(s.Values) {
					for i, nm := range s.Names {
						if nm.Name != "_" || cfg.ForbidNonNilSeedStructPtrCompare {
							if v, _ := info.Defs[nm].(*types.Var); v != nil && seedStructTypeViolated(v.Type(), info.TypeOf(s.Values[i])) {
								ok = false
								return false
							}
						}
						if _, rCar := classifyExpr(s.Values[i]); rCar {
							if nm.Name == "_" {
								continue
							}
							v, _ := info.Defs[nm].(*types.Var)
							if v == nil || assignErasesTaint(v.Type(), info.TypeOf(s.Values[i])) {
								ok = false
								return false
							}
						}
					}
				} else if len(s.Names) > 1 && len(s.Values) == 1 {
					rhsT := info.TypeOf(s.Values[0])
					rhsTup, _ := rhsT.(*types.Tuple)
					if rhsTup != nil {
						for i, nm := range s.Names {
							if i < rhsTup.Len() && (nm.Name != "_" || cfg.ForbidNonNilSeedStructPtrCompare) {
								if v, _ := info.Defs[nm].(*types.Var); v != nil && seedStructTypeViolated(v.Type(), rhsTup.At(i).Type()) {
									ok = false
									return false
								}
							}
						}
					} else if cfg.ForbidNonNilSeedStructPtrCompare {
						if v, _ := info.Defs[s.Names[0]].(*types.Var); v != nil && seedStructTypeViolated(v.Type(), rhsT) {
							ok = false
							return false
						}
					}
					for i, nm := range s.Names {
						var srcElemT types.Type
						if rhsTup != nil && i < rhsTup.Len() {
							srcElemT = rhsTup.At(i).Type()
						} else if v, _ := info.Defs[nm].(*types.Var); v != nil {
							srcElemT = v.Type()
						}
						if _, sCar := classifyMultiReturnSlot(s.Values[0], i, srcElemT); !sCar {
							continue
						}
						if nm.Name == "_" {
							continue
						}
						v, _ := info.Defs[nm].(*types.Var)
						if v == nil || (srcElemT != nil && assignErasesTaint(v.Type(), srcElemT)) {
							ok = false
							return false
						}
					}
				}

			case *ast.IncDecStmt:
				if exprMutatesTaintedTarget(s.X) || (!inSyncAllowed && exprHitsStructPred(info, s.X, isSeedStruct, true)) {
					ok = false
					return false
				}

			case *ast.RangeStmt:
				if s.Tok == token.ASSIGN {
					if (s.Key != nil && (exprMutatesTaintedTarget(s.Key) || (!inSyncAllowed && exprHitsStructPred(info, s.Key, isSeedStruct, true)))) ||
						(s.Value != nil && (exprMutatesTaintedTarget(s.Value) || (!inSyncAllowed && exprHitsStructPred(info, s.Value, isSeedStruct, true)))) {
						ok = false
						return false
					}
					if _, xCar := classifyExpr(s.X); xCar {
						for _, bindExpr := range []ast.Expr{s.Key, s.Value} {
							if bindExpr == nil || syntaxutil.IsBlankIdent(bindExpr) {
								continue
							}
							if _, pCar := projectedClassify(info.TypeOf(bindExpr), s.X); !pCar {
								continue
							}
							if syntaxutil.LookupIdentVar(info, bindExpr) == nil {
								ok = false
								return false
							}
						}
					}
				}

			case *ast.UnaryExpr:
				if s.Op == token.AND && (exprMutatesTaintedTarget(s.X) || (!inSyncAllowed && exprHitsStructPred(info, s.X, isSeedStruct, false))) {
					ok = false
					return false
				}
				if s.Op == token.ARROW {
					if _, cCar := classifyExpr(s.X); cCar {
						ok = false
						return false
					}
				}

			case *ast.SendStmt:
				if chT := info.TypeOf(s.Chan); chT != nil {
					if ch, isCh := types.Unalias(chT).Underlying().(*types.Chan); isCh {
						if seedStructTypeViolated(ch.Elem(), info.TypeOf(s.Value)) {
							ok = false
							return false
						}
					} else if cfg.ForbidNonNilSeedStructPtrCompare && typeMentionsSeedStruct(info.TypeOf(s.Value), isSeedStruct) {
						ok = false
						return false
					}
				}
				if _, chCar := classifyExpr(s.Chan); chCar {
					ok = false
					return false
				}
				if _, vCar := classifyExpr(s.Value); vCar {
					ok = false
					return false
				}

			case *ast.CompositeLit:
				clT := info.TypeOf(s)
				if clT == nil {
					return true
				}
				baseT := types.Unalias(clT)
				if ptr, isP := baseT.(*types.Pointer); isP {
					baseT = types.Unalias(ptr.Elem())
				}
				_, isSlice := baseT.Underlying().(*types.Slice)
				_, isArray := baseT.Underlying().(*types.Array)
				_, isMap := baseT.Underlying().(*types.Map)
				stUnder, isStruct := baseT.Underlying().(*types.Struct)
				allowedSeedSt := isStruct && isAllowedSeedStructCompositeLit(s)

				for idx, elt := range s.Elts {
					val := elt
					var dstElemT types.Type
					if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
						if !isStruct {
							if isMap && seedStructTypeViolated(baseT.Underlying().(*types.Map).Key(), info.TypeOf(kv.Key)) {
								ok = false
								return false
							}
							if _, kCar := classifyExpr(kv.Key); kCar {
								ok = false
								return false
							}
						}
						val = kv.Value
						if isStruct {
							if fk, isID := kv.Key.(*ast.Ident); isID {
								if fv, isV := info.Uses[fk].(*types.Var); isV && fv != nil {
									dstElemT = fv.Type()
								}
							}
						} else if isMap {
							dstElemT = baseT.Underlying().(*types.Map).Elem()
						}
					} else if isStruct && idx < stUnder.NumFields() {
						dstElemT = stUnder.Field(idx).Type()
					}
					if isSlice {
						dstElemT = baseT.Underlying().(*types.Slice).Elem()
					} else if isArray {
						dstElemT = baseT.Underlying().(*types.Array).Elem()
					}
					if seedStructTypeViolated(dstElemT, info.TypeOf(val)) {
						ok = false
						return false
					}
					if _, vCar := classifyExpr(val); !vCar {
						continue
					}
					if !isSlice && !isArray && !allowedSeedSt {
						ok = false
						return false
					}
					if dstElemT == nil || assignErasesTaint(dstElemT, info.TypeOf(val)) {
						ok = false
						return false
					}
				}

			case *ast.ReturnStmt:
				fn := returnEnclFunc[s]
				if len(s.Results) == 1 && cfg.ForbidNonNilSeedStructPtrCompare {
					if tup, isTup := info.TypeOf(s.Results[0]).(*types.Tuple); isTup {
						for ti := 0; ti < tup.Len(); ti++ {
							rT := tup.At(ti).Type()
							if fn != nil && fn.Signature().Results() != nil && ti < fn.Signature().Results().Len() {
								if seedStructTypeViolated(fn.Signature().Results().At(ti).Type(), rT) {
									ok = false
									return false
								}
							} else if typeMentionsSeedStruct(rT, isSeedStruct) {
								ok = false
								return false
							}
						}
					}
				}
				for ri, r := range s.Results {
					if fn != nil {
						res := fn.Signature().Results()
						if ri < res.Len() {
							if seedStructTypeViolated(res.At(ri).Type(), info.TypeOf(r)) {
								ok = false
								return false
							}
						} else if cfg.ForbidNonNilSeedStructPtrCompare && typeMentionsSeedStruct(info.TypeOf(r), isSeedStruct) {
							ok = false
							return false
						}
					} else if isSeedStruct(syntaxutil.DerefNamedStruct(info.TypeOf(r))) ||
						(cfg.ForbidNonNilSeedStructPtrCompare && typeMentionsSeedStruct(info.TypeOf(r), isSeedStruct)) {
						ok = false
						return false
					}
					if _, rCar := classifyExpr(r); !rCar {
						continue
					}
					if !canPropagateReturn(fn) {
						ok = false
						return false
					}
					res := fn.Signature().Results()
					if ri >= res.Len() || assignErasesTaint(res.At(ri).Type(), info.TypeOf(r)) {
						ok = false
						return false
					}
				}

			case *ast.CallExpr:
				if !inSyncAllowed && callMutatesSeedStructContainer(info, s, isSeedStruct) {
					ok = false
					return false
				}
				fun := ast.Unparen(s.Fun)
				if info.Types[fun].IsType() && len(s.Args) == 1 {
					if seedStructTypeViolated(info.Types[fun].Type, info.TypeOf(s.Args[0])) {
						ok = false
						return false
					}
					if _, aCar := classifyExpr(s.Args[0]); aCar {
						if assignErasesTaint(info.Types[fun].Type, info.TypeOf(s.Args[0])) {
							ok = false
							return false
						}
					}
					return true
				}

				if callCallErasesSeedStruct(info, s, seedStructTypeViolated, cfg.AllowCallArg) {
					ok = false
					return false
				}

				if sel, isSel := fun.(*ast.SelectorExpr); isSel {
					if selInfo := info.Selections[sel]; selInfo != nil && selInfo.Kind() == types.MethodVal {
						if _, rCar := classifyExpr(sel.X); rCar {
							if callee := resolveConcretePkgCallee(s.Fun); callee != nil {
								// Taint propagated to callee's receiver parameter.
							} else if !types.IsInterface(selInfo.Recv()) && cfg.AllowMethodRecv != nil {
								mFn, _ := selInfo.Obj().(*types.Func)
								if !cfg.AllowMethodRecv(s, mFn, sel.X) {
									ok = false
									return false
								}
							} else {
								ok = false
								return false
							}
						}
					} else if _, fCar := classifyExpr(s.Fun); fCar {
						ok = false
						return false
					}
				} else if _, fCar := classifyExpr(s.Fun); fCar {
					ok = false
					return false
				}

				for argIdx, arg := range s.Args {
					aRef, aCar := classifyExpr(arg)
					if !aCar {
						continue
					}
					if b := syntaxutil.LookupBuiltin(info, fun); b != nil {
						if b.Name() == "len" || b.Name() == "cap" || b.Name() == "Sizeof" || b.Name() == "Alignof" || b.Name() == "Offsetof" {
							continue
						}
						if b.Name() == "append" {
							if argIdx == 0 {
								if !aRef && selfAssignedAppendCalls[s] {
									continue
								}
								ok = false
								return false
							}
							if s.Ellipsis.IsValid() {
								if sl, isSl := syntaxutil.UnderlyingType(info.TypeOf(arg)).(*types.Slice); isSl && !elemHasHandle(sl.Elem()) {
									continue
								}
							} else if selfAssignedAppendCalls[s] {
								if sl, isSl := syntaxutil.UnderlyingType(info.TypeOf(s)).(*types.Slice); isSl && !assignErasesTaint(sl.Elem(), info.TypeOf(arg)) {
									continue
								}
							}
							ok = false
							return false
						}
						if b.Name() == "copy" && argIdx == 1 {
							if sl, isSl := syntaxutil.UnderlyingType(info.TypeOf(arg)).(*types.Slice); isSl && !elemHasHandle(sl.Elem()) {
								continue
							}
						}
						ok = false
						return false
					}

					if callee := resolveConcretePkgCallee(s.Fun); callee != nil {
						sig, okSig := callee.Type().(*types.Signature)
						if !okSig {
							ok = false
							return false
						}
						if len(s.Args) == 1 {
							if tup, isTup := info.TypeOf(s.Args[0]).(*types.Tuple); isTup {
								if tup.Len() != sig.Params().Len() {
									ok = false
									return false
								}
								erased := false
								for ti := 0; ti < tup.Len(); ti++ {
									st := tup.At(ti).Type()
									if _, sCar := classifyMultiReturnSlot(s.Args[0], ti, st); !sCar {
										continue
									}
									pt := sig.Params().At(ti).Type()
									if !(cfg.AllowIntraPkgInterfaceParam && types.IsInterface(pt)) && assignErasesTaint(pt, st) {
										erased = true
										break
									}
								}
								if !erased {
									continue
								}
								ok = false
								return false
							}
						}
						paramIdx := argIdx
						isNonEllipsisVariadic := false
						if sig.Variadic() && argIdx >= sig.Params().Len()-1 {
							paramIdx = sig.Params().Len() - 1
							isNonEllipsisVariadic = !s.Ellipsis.IsValid()
						}
						if paramIdx < sig.Params().Len() {
							pt := sig.Params().At(paramIdx).Type()
							if isNonEllipsisVariadic {
								if sl, isSl := types.Unalias(pt).Underlying().(*types.Slice); isSl {
									pt = sl.Elem()
								}
							}
							if (cfg.AllowIntraPkgInterfaceParam && types.IsInterface(pt)) || !assignErasesTaint(pt, info.TypeOf(arg)) {
								continue
							}
						}
					}

					if cfg.AllowCallArg != nil && cfg.AllowCallArg(s, argIdx, arg) {
						continue
					}

					ok = false
					return false
				}
			}
			return true
		})
	}
	return ok
}
