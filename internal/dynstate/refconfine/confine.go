package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
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

	// AllowCompositeLitFieldPropagation permits storing tainted values into
	// fields of a CompositeLit of an unexported, non-generic named struct S in
	// p.Types (having zero exported fields, zero package-scope variable bindings,
	// and zero mentions in exported function/method signatures in p.Types) by
	// propagating taint per-field to every selection of those fields across
	// p.Syntax while still allowing writes to untainted sibling fields of S.
	AllowCompositeLitFieldPropagation bool

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

	// OnReject optionally receives the source position and diagnostic clause of
	// the first confinement violation encountered during verification.
	OnReject func(pos token.Pos, clause string)
}

func allocCompositeLitAST(v *flowir.Value) *ast.CompositeLit {
	if v == nil || v.Kind != flowir.ValAllocFresh || v.AllocKind != flowir.AllocCompositeLit || v.Raw == nil {
		return nil
	}
	cur := ast.Unparen(v.Raw)
	if un, ok := cur.(*ast.UnaryExpr); ok && un.Op == token.AND {
		cur = ast.Unparen(un.X)
	}
	cl, _ := cur.(*ast.CompositeLit)
	return cl
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
	flowCache := idx.FlowCache(p)
	if flowCache == nil {
		return false
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
			if containerExpr != nil && cfg.AllowImmutableInterfaceElem != nil && cfg.AllowImmutableInterfaceElem(ast.Unparen(containerExpr)) {
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
	propagatedStructs := map[*types.Named]bool{}
	propagatedFields := map[*types.Var]bool{}
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
	isPropagatedStruct := func(st *types.Named) bool {
		return st != nil && propagatedStructs[st.Origin()]
	}
	selectionHitsFieldSet := func(selInfo *types.Selection, fields map[*types.Var]bool) bool {
		if selInfo == nil || selInfo.Kind() != types.FieldVal || len(fields) == 0 {
			return false
		}
		if fv, ok := selInfo.Obj().(*types.Var); ok && fv != nil && fields[fv.Origin()] {
			return true
		}
		curT := selInfo.Recv()
		for _, fIdx := range selInfo.Index() {
			if curT == nil {
				break
			}
			u := types.Unalias(curT)
			if ptr, ok := u.(*types.Pointer); ok {
				u = types.Unalias(ptr.Elem())
			}
			st, ok := u.Underlying().(*types.Struct)
			if !ok || fIdx < 0 || fIdx >= st.NumFields() {
				break
			}
			fv := st.Field(fIdx)
			if fields[fv.Origin()] {
				return true
			}
			curT = fv.Type()
		}
		return false
	}

	var placeHitsStructPred func(pl flowir.Place, match func(*types.Named) bool, includeStarRoot bool) bool
	placeHitsStructPred = func(pl flowir.Place, match func(*types.Named) bool, includeStarRoot bool) bool {
		if match == nil {
			return false
		}
		for i := len(pl.Projs) - 1; i >= 0; i-- {
			pr := pl.Projs[i]
			switch pr.Kind {
			case flowir.ProjField:
				if pr.Selection == nil || pr.Selection.Kind() != types.FieldVal {
					return false
				}
				hit := false
				syntaxutil.ForEachSelectionHopStruct(pr.Selection, func(st *types.Named) {
					if st != nil && (match(st) || match(st.Origin())) {
						hit = true
					}
				})
				if hit {
					return true
				}
			case flowir.ProjDeref:
				if includeStarRoot {
					if st := syntaxutil.DerefNamedStruct(pr.BaseType); st != nil && (match(st) || match(st.Origin())) {
						return true
					}
				}
			case flowir.ProjIndex:
				if pr.Type != nil {
					if st, ok := types.Unalias(pr.Type).(*types.Named); ok && st.Obj() != nil && (match(st) || match(st.Origin())) {
						return true
					}
				}
			case flowir.ProjSlice:
			}
		}
		if pl.Root == flowir.RootTransient && pl.Base != nil && pl.Base.Kind == flowir.ValAddrOf && pl.Base.IsArraySlice {
			return placeHitsStructPred(pl.Base.AddrPlace, match, includeStarRoot)
		}
		return false
	}

	var placeChainHitsSeedStruct func(pl flowir.Place) bool
	placeChainHitsSeedStruct = func(pl flowir.Place) bool {
		if cfg.SeedStructOrigin == nil && cfg.CanBeSeedStructCapsule == nil {
			return false
		}
		for i := len(pl.Projs) - 1; i >= 0; i-- {
			pr := pl.Projs[i]
			switch pr.Kind {
			case flowir.ProjField:
				if pr.Selection == nil || pr.Selection.Kind() != types.FieldVal {
					return false
				}
				hit := false
				syntaxutil.ForEachSelectionHopStruct(pr.Selection, func(st *types.Named) {
					if isSeedStruct(st) {
						hit = true
					}
				})
				if hit {
					return true
				}
			case flowir.ProjIndex:
				if isSeedStruct(syntaxutil.DerefNamedStruct(pr.Type)) {
					return true
				}
			case flowir.ProjDeref:
				if isSeedStruct(syntaxutil.DerefNamedStruct(pr.BaseType)) {
					return true
				}
			case flowir.ProjSlice:
			}
		}
		if pl.Root == flowir.RootTransient && pl.Base != nil && pl.Base.Kind == flowir.ValAddrOf && pl.Base.IsArraySlice {
			return placeChainHitsSeedStruct(pl.Base.AddrPlace)
		}
		return false
	}

	var placeChainHitsPropagatedField func(pl flowir.Place) bool
	placeChainHitsPropagatedField = func(pl flowir.Place) bool {
		if len(propagatedFields) == 0 {
			return false
		}
		for i := len(pl.Projs) - 1; i >= 0; i-- {
			pr := pl.Projs[i]
			if pr.Kind == flowir.ProjField {
				if pr.Selection == nil || pr.Selection.Kind() != types.FieldVal {
					return false
				}
				if selectionHitsFieldSet(pr.Selection, propagatedFields) {
					return true
				}
			}
		}
		if pl.Root == flowir.RootTransient && pl.Base != nil && pl.Base.Kind == flowir.ValAddrOf && pl.Base.IsArraySlice {
			return placeChainHitsPropagatedField(pl.Base.AddrPlace)
		}
		return false
	}

	var placeHitsPropagated func(pl flowir.Place, includeWholeOrStarStruct bool) bool
	placeHitsPropagated = func(pl flowir.Place, includeWholeOrStarStruct bool) bool {
		if len(propagatedStructs) == 0 {
			return false
		}
		if includeWholeOrStarStruct && pl.Type != nil {
			if st, ok := types.Unalias(pl.Type).(*types.Named); ok && propagatedStructs[st.Origin()] {
				return true
			}
		}
		for i := len(pl.Projs) - 1; i >= 0; i-- {
			pr := pl.Projs[i]
			switch pr.Kind {
			case flowir.ProjField:
				if pr.Selection == nil || pr.Selection.Kind() != types.FieldVal {
					return false
				}
				if selectionHitsFieldSet(pr.Selection, propagatedFields) {
					return true
				}
			case flowir.ProjDeref:
				if includeWholeOrStarStruct {
					if st := syntaxutil.DerefNamedStruct(pr.BaseType); st != nil && propagatedStructs[st.Origin()] {
						return true
					}
				}
			}
		}
		if pl.Root == flowir.RootTransient && pl.Base != nil && pl.Base.Kind == flowir.ValAddrOf && pl.Base.IsArraySlice {
			return placeHitsPropagated(pl.Base.AddrPlace, includeWholeOrStarStruct)
		}
		return false
	}

	valueOrPlaceHitsStructPred := func(v *flowir.Value, pl flowir.Place, hasPl bool, match func(*types.Named) bool, includeStarRoot bool) bool {
		if hasPl {
			return placeHitsStructPred(pl, match, includeStarRoot)
		}
		if v != nil {
			if v.Kind == flowir.ValPlace {
				return placeHitsStructPred(v.Place, match, includeStarRoot)
			}
			if v.Kind == flowir.ValAddrOf && v.IsArraySlice {
				return placeHitsStructPred(v.AddrPlace, match, includeStarRoot)
			}
		}
		return false
	}

	valueOrPlaceHitsPropagated := func(v *flowir.Value, pl flowir.Place, hasPl bool, includeWholeOrStarStruct bool) bool {
		if hasPl {
			return placeHitsPropagated(pl, includeWholeOrStarStruct)
		}
		if v != nil {
			if v.Kind == flowir.ValPlace {
				return placeHitsPropagated(v.Place, includeWholeOrStarStruct)
			}
			if v.Kind == flowir.ValAddrOf && v.IsArraySlice {
				return placeHitsPropagated(v.AddrPlace, includeWholeOrStarStruct)
			}
			if includeWholeOrStarStruct && v.Type != nil {
				if st, ok := types.Unalias(v.Type).(*types.Named); ok && propagatedStructs[st.Origin()] {
					return true
				}
			}
		}
		return false
	}

	funcValueTaken := idx.FuncValueTaken
	isNonGenericConcretePkgCallee := func(callee *types.Func) bool {
		if callee == nil || callee.Pkg() != p.Types || callee.Origin() != callee {
			return false
		}
		sig, ok := callee.Type().(*types.Signature)
		return ok && sig.TypeParams().Len() == 0 && sig.RecvTypeParams().Len() == 0
	}
	resolveConcretePkgCalleeVal := func(v *flowir.Value) *types.Func {
		if v == nil || v.Kind != flowir.ValCall {
			return nil
		}
		if v.CallKind != flowir.CallPlain && !(v.CallKind == flowir.CallMethod && !v.IsMethodExprCall) {
			return nil
		}
		if v.Selection != nil && v.Selection.Recv() != nil && types.IsInterface(v.Selection.Recv()) {
			return nil
		}
		if v.CalleeSel != nil && v.CalleeSel.Sel != nil {
			if _, hasInst := info.Instances[v.CalleeSel.Sel]; hasInst {
				return nil
			}
		}
		if v.CallAST != nil {
			if id, isID := ast.Unparen(v.CallAST.Fun).(*ast.Ident); isID {
				if _, hasInst := info.Instances[id]; hasInst {
					return nil
				}
			}
		}
		if isNonGenericConcretePkgCallee(v.CalleeFunc) {
			return v.CalleeFunc
		}
		return nil
	}

	pkgIfaceMethodNames := map[string]bool{}
	noteIfaceMethods := func(t types.Type) {
		if t == nil {
			return
		}
		if iface, ok := types.Unalias(t).Underlying().(*types.Interface); ok {
			for i := 0; i < iface.NumMethods(); i++ {
				m := iface.Method(i)
				if m != nil && m.Pkg() == p.Types {
					pkgIfaceMethodNames[m.Name()] = true
				}
			}
		}
	}
	for _, tv := range info.Types {
		noteIfaceMethods(tv.Type)
	}
	for _, obj := range info.Defs {
		if obj != nil {
			noteIfaceMethods(obj.Type())
		}
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
		if !ok {
			return false
		}
		if sig.Recv() == nil {
			return true
		}
		return !types.IsInterface(sig.Recv().Type()) && !pkgIfaceMethodNames[fn.Name()]
	}

	hasDeclBody := func(orig *types.Func) bool {
		if orig == nil {
			return false
		}
		fd := idx.FuncDecls[orig]
		return fd != nil && fd.Body != nil && !(fd.Recv == nil && fd.Name != nil && fd.Name.Name == "init")
	}

	boundPkgMethodRecvVal := func(v *flowir.Value) (*types.Var, bool) {
		if v == nil || v.Kind != flowir.ValMethodVal || v.Selection == nil {
			return nil, false
		}
		if sel, isSel := ast.Unparen(v.Raw).(*ast.SelectorExpr); isSel && sel.Sel != nil {
			if _, hasInst := info.Instances[sel.Sel]; hasInst {
				return nil, false
			}
		}
		selInfo := v.Selection
		if selInfo.Kind() != types.MethodVal || selInfo.Recv() == nil || types.IsInterface(selInfo.Recv()) || len(selInfo.Index()) != 1 {
			return nil, false
		}
		mObj, ok := selInfo.Obj().(*types.Func)
		if !ok || mObj == nil {
			return nil, false
		}
		orig := mObj.Origin()
		if orig == nil || orig.Pkg() != p.Types || !hasDeclBody(orig) {
			return nil, false
		}
		origSig, ok := orig.Type().(*types.Signature)
		if !ok || origSig.Recv() == nil || origSig.TypeParams().Len() > 0 {
			return nil, false
		}
		rv := origSig.Recv()
		if _, recvIsPtr := types.Unalias(rv.Type()).(*types.Pointer); recvIsPtr {
			if v.Recv == nil || v.Recv.Type == nil {
				return nil, false
			}
			if _, xIsPtr := types.Unalias(v.Recv.Type).(*types.Pointer); !xIsPtr {
				return nil, false
			}
		}
		if origSig.RecvTypeParams().Len() > 0 {
			var recvT types.Type
			if v.Recv != nil {
				recvT = v.Recv.Type
			}
			recvSt := syntaxutil.DerefNamedStruct(recvT)
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
		if cl == nil || !cfg.AllowCompositeLitIntoSeedStruct || (cfg.SeedStructOrigin == nil && len(capsuleStructs) == 0) {
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

	var classifyPlace func(pl flowir.Place) (isRef bool, isCarrier bool)
	var classifyValue func(v *flowir.Value) (isRef bool, isCarrier bool)
	var classifyMultiReturnSlot func(rhs *flowir.Value, slot int, slotType types.Type) (isRef bool, isCarrier bool)
	var placeMutatesTaintedTarget func(pl flowir.Place) bool

	isAllowedPropagatedCompositeLit := func(v *flowir.Value, cl *ast.CompositeLit) bool {
		if cl == nil || !cfg.AllowCompositeLitFieldPropagation || len(propagatedStructs) == 0 {
			return false
		}
		st := syntaxutil.DerefNamedStruct(info.TypeOf(cl))
		if st == nil || !propagatedStructs[st.Origin()] {
			return false
		}
		for i := range v.CompositeElts {
			elt := &v.CompositeElts[i]
			if _, vCar := classifyValue(elt.Value); vCar {
				if elt.Field == nil || !propagatedFields[elt.Field.Origin()] {
					return false
				}
			}
		}
		return true
	}
	isAllowedStructCompositeLit := func(v *flowir.Value) bool {
		cl := allocCompositeLitAST(v)
		return isAllowedSeedStructCompositeLit(cl) || isAllowedPropagatedCompositeLit(v, cl)
	}

	checkSeedExpr := func(expr ast.Expr) (bool, bool, bool) {
		if cfg.SeedExpr == nil || expr == nil {
			return false, false, false
		}
		unp := ast.Unparen(expr)
		if sRef, sCar := cfg.SeedExpr(unp); sRef || sCar {
			return sRef, sRef || sCar, true
		}
		return false, false, false
	}

	classifyPlacePrefix := func(pl flowir.Place, projCount int) (bool, bool) {
		var curRef, curCar bool
		prevRaw := pl.RootRaw
		if sRef, sCar, ok := checkSeedExpr(pl.RootRaw); ok {
			curRef, curCar = sRef, sCar
		} else if projCount == 0 && pl.Raw != nil && ast.Unparen(pl.Raw) != pl.RootRaw {
			if sRef, sCar, ok := checkSeedExpr(pl.Raw); ok {
				return sRef, sCar
			}
		}
		if !curRef && !curCar {
			switch pl.Root {
			case flowir.RootLocal, flowir.RootParam, flowir.RootRecv, flowir.RootResult, flowir.RootOuterVar, flowir.RootPkgGlobal:
				if pl.Obj != nil {
					curRef = taintedRef[pl.Obj]
					curCar = curRef || taintedCarrier[pl.Obj]
				}
			case flowir.RootTransient:
				if pl.Base != nil {
					curRef, curCar = classifyValue(pl.Base)
					if pl.Base.Raw != nil {
						prevRaw = ast.Unparen(pl.Base.Raw)
					}
				}
			}
		}
		for i := 0; i < projCount; i++ {
			pr := pl.Projs[i]
			if sRef, sCar, ok := checkSeedExpr(pr.Raw); ok {
				curRef, curCar = sRef, sCar
				prevRaw = pr.Raw
				continue
			}
			prefix := pl
			prefix.Projs = pl.Projs[:i+1]
			prefix.Type = pr.Type
			prefix.Raw = pr.Raw
			switch pr.Kind {
			case flowir.ProjField:
				if pr.Selection != nil && pr.Selection.Kind() == types.FieldVal {
					if cfg.IsExemptField != nil && !syntaxutil.SelectionCrossesEmbeddedPointer(pr.Selection) {
						if fv, isFV := pr.Selection.Obj().(*types.Var); isFV && cfg.IsExemptField(fv) {
							curRef, curCar = false, false
							prevRaw = pr.Raw
							continue
						}
					}
					ft := pr.Selection.Type()
					if placeChainHitsPropagatedField(prefix) {
						curRef, curCar = projectedClassify(ft, prevRaw)
					} else {
						seeded := false
						if placeChainHitsSeedStruct(prefix) {
							if isDirectRef(ft) {
								curRef, curCar = true, true
								seeded = true
							} else if carriesRef(ft) {
								curRef, curCar = false, true
								seeded = true
							}
						}
						if !seeded {
							if curCar {
								curRef, curCar = projectedClassify(ft, prevRaw)
							} else {
								curRef, curCar = false, false
							}
						}
					}
				} else {
					curRef, curCar = false, false
				}
			case flowir.ProjIndex:
				if curCar {
					curRef, curCar = projectedClassify(indexValueTypeFromType(pr.Type), prevRaw)
				} else {
					curRef, curCar = false, false
				}
			case flowir.ProjSlice:
				if curRef {
					curRef, curCar = true, true
				} else if curCar {
					curRef, curCar = false, true
				} else {
					curRef, curCar = false, false
				}
			case flowir.ProjDeref:
				if curCar {
					curRef, curCar = projectedClassify(pr.Type, prevRaw)
				} else {
					curRef, curCar = false, false
				}
			}
			prevRaw = pr.Raw
		}
		return curRef, curCar
	}

	classifyPlace = func(pl flowir.Place) (bool, bool) {
		return classifyPlacePrefix(pl, len(pl.Projs))
	}

	placeMutatesTaintedTarget = func(pl flowir.Place) bool {
		for i := len(pl.Projs) - 1; i >= 0; i-- {
			pr := pl.Projs[i]
			switch pr.Kind {
			case flowir.ProjDeref:
				if bRef, _ := classifyPlacePrefix(pl, i); bRef {
					return true
				}
			case flowir.ProjIndex:
				if pr.BaseType != nil {
					switch types.Unalias(pr.BaseType).Underlying().(type) {
					case *types.Slice, *types.Map, *types.Pointer:
						if bRef, _ := classifyPlacePrefix(pl, i); bRef {
							return true
						}
					}
				}
			case flowir.ProjField:
				if pr.Selection != nil && pr.Selection.Kind() == types.FieldVal {
					if pr.BaseType != nil {
						if _, isPtr := types.Unalias(pr.BaseType).Underlying().(*types.Pointer); isPtr {
							if bRef, _ := classifyPlacePrefix(pl, i); bRef {
								return true
							}
						}
					}
					if syntaxutil.SelectionCrossesEmbeddedPointer(pr.Selection) {
						if _, bCar := classifyPlacePrefix(pl, i); bCar {
							return true
						}
					}
				}
			case flowir.ProjSlice:
			}
		}
		if pl.Root == flowir.RootTransient && pl.Base != nil {
			if pl.Base.Kind == flowir.ValPlace {
				return placeMutatesTaintedTarget(pl.Base.Place)
			}
			if pl.Base.Kind == flowir.ValAddrOf && pl.Base.IsArraySlice {
				return placeMutatesTaintedTarget(pl.Base.AddrPlace)
			}
		}
		return false
	}

	valueMutatesTaintedTarget := func(v *flowir.Value) bool {
		if v == nil {
			return false
		}
		if v.Kind == flowir.ValPlace {
			return placeMutatesTaintedTarget(v.Place)
		}
		if v.Kind == flowir.ValAddrOf && v.IsArraySlice {
			return placeMutatesTaintedTarget(v.AddrPlace)
		}
		return false
	}

	methodValHasTaintedOrSeedRecv := func(v *flowir.Value) (xRef, xCar, mutX, seedX bool) {
		if v == nil || v.Recv == nil {
			return false, false, false, false
		}
		xRef, xCar = classifyValue(v.Recv)
		if v.HasRecvPlace {
			mutX = placeMutatesTaintedTarget(v.RecvPlace)
		} else {
			mutX = valueMutatesTaintedTarget(v.Recv)
		}
		rxSt := syntaxutil.DerefNamedStruct(v.Recv.Type)
		seedX = isSeedStruct(rxSt) || isPropagatedStruct(rxSt)
		if !seedX && v.HasRecvPlace {
			seedX = placeChainHitsSeedStruct(v.RecvPlace) || placeChainHitsPropagatedField(v.RecvPlace)
		}
		return xRef, xCar, mutX, seedX
	}

	classifyValue = func(v *flowir.Value) (bool, bool) {
		if v == nil {
			return false, false
		}
		if sRef, sCar, ok := checkSeedExpr(v.Raw); ok {
			return sRef, sCar
		}
		switch v.Kind {
		case flowir.ValPlace:
			return classifyPlace(v.Place)

		case flowir.ValMethodVal:
			_, xCar, mutX, seedX := methodValHasTaintedOrSeedRecv(v)
			if xCar || mutX || seedX {
				if _, okM := boundPkgMethodRecvVal(v); !okM {
					return true, true
				}
			}
			return false, false

		case flowir.ValAddrOf:
			bRef, bCar := classifyPlace(v.AddrPlace)
			if v.IsArraySlice {
				if bRef {
					return true, true
				}
				if bCar {
					return false, true
				}
				return false, false
			}
			if placeMutatesTaintedTarget(v.AddrPlace) {
				return true, true
			}
			if bRef || bCar {
				return false, true
			}
			return false, false

		case flowir.ValChanRecv:
			if _, cCar := classifyValue(v.Chan); cCar {
				et := indexValueTypeFromType(v.Type)
				return isDirectRef(et), true
			}
			return false, false

		case flowir.ValAllocFresh:
			switch v.AllocKind {
			case flowir.AllocMake, flowir.AllocBuiltinNewType:
				return false, false
			case flowir.AllocBuiltinNewExpr:
				if len(v.Args) == 1 {
					if _, aCar := classifyValue(v.Args[0]); aCar {
						return false, true
					}
				}
				return false, false
			case flowir.AllocCompositeLit:
				if isAllowedStructCompositeLit(v) {
					return false, false
				}
				for i := range v.CompositeElts {
					elt := &v.CompositeElts[i]
					if elt.MapKey != nil {
						if _, kCar := classifyValue(elt.MapKey); kCar {
							return false, true
						}
					}
					if _, vCar := classifyValue(elt.Value); vCar {
						return false, true
					}
				}
				return false, false
			}
			return false, false

		case flowir.ValConvert:
			if v.IsTypeAssert {
				if _, xCar := classifyValue(v.Arg); xCar {
					return true, true
				}
				return false, false
			}
			aRef, aCar := classifyValue(v.Arg)
			if !aCar {
				return false, false
			}
			if !elemHasHandle(v.Type) && !syntaxutil.ContainsUintptr(v.Type) {
				return false, false
			}
			return aRef || isDirectRef(v.Type), true

		case flowir.ValCall:
			if v.CallKind == flowir.CallBuiltin {
				if v.BuiltinName == "append" && len(v.Args) > 0 {
					dRef, dCar := classifyValue(v.Args[0])
					elemTainted := false
					var slElem types.Type
					if sl, ok := syntaxutil.UnderlyingType(v.Type).(*types.Slice); ok {
						slElem = sl.Elem()
					}
					for _, arg := range v.Args[1:] {
						_, aCar := classifyValue(arg)
						if !aCar {
							continue
						}
						if v.Ellipsis {
							if elemHasHandle(slElem) {
								elemTainted = true
							}
						} else {
							elemTainted = true
						}
					}
					return dRef, dRef || dCar || elemTainted
				}
				return false, false
			}
			if callee := resolveConcretePkgCalleeVal(v); callee != nil {
				if taintedRetAnyRef[callee] || taintedRetAnyCarrier[callee] {
					return taintedRetAnyRef[callee], true
				}
				return false, false
			}
			return false, false

		case flowir.ValCompositeExpr:
			hit := false
			for _, a := range v.Args {
				if _, aCar := classifyValue(a); aCar {
					hit = true
					break
				}
			}
			if hit {
				if v.Type == nil || isDirectRef(v.Type) || types.IsInterface(v.Type) {
					return true, true
				}
				if carriesRefOrIface(v.Type) {
					return false, true
				}
			}
			return false, false

		default:
			return false, false
		}
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

	markContainerIndexWrite := func(dst flowir.Place) bool {
		if dst.Obj == nil || len(dst.Projs) != 1 || dst.Projs[0].Kind != flowir.ProjIndex {
			return false
		}
		return markVarTaint(dst.Obj, false, true)
	}

	isEligibleCapsule := func(orig *types.Named) bool {
		if orig == nil || orig.Obj() == nil || orig.Obj().Pkg() != p.Types || orig.Obj().Exported() || orig.TypeParams().Len() > 0 {
			return false
		}
		st, isSt := orig.Underlying().(*types.Struct)
		return isSt && structHasNoExportedFieldsDeep(st)
	}

	classifyMultiReturnSlot = func(rhs *flowir.Value, slot int, slotType types.Type) (bool, bool) {
		if rhs == nil {
			return false, false
		}
		if rhs.Kind == flowir.ValCall && rhs.CallAST != nil {
			if _, sCar, ok := checkSeedExpr(rhs.CallAST); ok && sCar {
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
			if callee := resolveConcretePkgCalleeVal(rhs); callee != nil {
				rk := retSlot{fn: callee, idx: slot}
				return taintedRetRef[rk], taintedRetRef[rk] || taintedRetCarrier[rk]
			}
			return false, false
		}
		if _, rCar := classifyValue(rhs); !rCar || slot != 0 {
			return false, false
		}
		if rhs.Kind == flowir.ValPlace && len(rhs.Place.Projs) > 0 {
			lastIdx := len(rhs.Place.Projs) - 1
			if rhs.Place.Projs[lastIdx].Kind == flowir.ProjIndex {
				containerRaw := rhs.Place.RootRaw
				if lastIdx > 0 {
					containerRaw = rhs.Place.Projs[lastIdx-1].Raw
				}
				return projectedClassify(slotType, containerRaw)
			}
		}
		return projectedClassify(slotType, nil)
	}

	walkAllBodies := func(visitBody func(b *flowir.Body, enclFunc *types.Func, inSyncAllowed bool) bool) bool {
		var walkRec func(b *flowir.Body, enclFunc *types.Func, inSyncAllowed bool) bool
		walkRec = func(b *flowir.Body, enclFunc *types.Func, inSyncAllowed bool) bool {
			if b == nil {
				return true
			}
			if !visitBody(b, enclFunc, inSyncAllowed) {
				return false
			}
			walkChildClosures := func(v *flowir.Value, childSync bool) bool {
				if v == nil {
					return true
				}
				cont := true
				v.WalkValues(func(cur *flowir.Value) bool {
					if !cont {
						return false
					}
					switch cur.Kind {
					case flowir.ValMakeClosure:
						if cur.Closure != nil && !walkRec(cur.Closure, nil, !cfg.ForbidNonNilSeedStructPtrCompare) {
							cont = false
							return false
						}
					case flowir.ValCall:
						if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil && !walkRec(cur.IIFE, nil, !cfg.ForbidNonNilSeedStructPtrCompare) {
							cont = false
							return false
						}
					}
					return true
				})
				return cont
			}
			for i := range b.Ops {
				op := &b.Ops[i]
				childSync := inSyncAllowed
				if op.Kind == flowir.OpGo {
					childSync = !cfg.ForbidNonNilSeedStructPtrCompare
				}
				if !op.ForEachValue(func(v *flowir.Value) bool { return walkChildClosures(v, childSync) }) {
					return false
				}
				if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
					if !walkRec(op.RangeBody, enclFunc, inSyncAllowed) {
						return false
					}
				}
			}
			return true
		}

		for _, fd := range flowCache.FuncDecls {
			b := flowCache.FuncBody(fd)
			if b == nil {
				continue
			}
			var fn *types.Func
			if fd.Name != nil && !(fd.Recv == nil && fd.Name.Name == "init") {
				fn, _ = info.Defs[fd.Name].(*types.Func)
			}
			inSync := !cfg.ForbidNonNilSeedStructPtrCompare || (cfg.AllowSeedStructMutationInFunc != nil && fd == cfg.AllowSeedStructMutationInFunc)
			if !walkRec(b, fn, inSync) {
				return false
			}
		}
		for _, gd := range flowCache.GenDecls {
			b := flowCache.Body(gd)
			if b == nil {
				continue
			}
			if !walkRec(b, nil, !cfg.ForbidNonNilSeedStructPtrCompare) {
				return false
			}
		}
		return true
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
			taintVal := func(v *flowir.Value) {
				if v == nil {
					return
				}
				v.WalkValues(func(cur *flowir.Value) bool {
					switch cur.Kind {
					case flowir.ValMethodVal:
						xRef, xCar, mutX, seedX := methodValHasTaintedOrSeedRecv(cur)
						if xCar || mutX || seedX {
							if rv, okM := boundPkgMethodRecvVal(cur); okM {
								_, recvIsPtr := types.Unalias(rv.Type()).(*types.Pointer)
								addRef := xRef || mutX || recvIsPtr || isDirectRef(rv.Type())
								if markVarTaint(rv, addRef, true) {
									changed = true
								}
							}
						}
					case flowir.ValCall:
						if cur.CallKind == flowir.CallBuiltin && cur.BuiltinName == "copy" && len(cur.Args) == 2 {
							if _, srcCar := classifyValue(cur.Args[1]); srcCar {
								if cur.Args[0] != nil && cur.Args[0].Kind == flowir.ValPlace && cur.Args[0].Place.Obj != nil {
									if markVarTaint(cur.Args[0].Place.Obj, false, true) {
										changed = true
									}
								}
							}
							return true
						}
						callee := resolveConcretePkgCalleeVal(cur)
						if callee == nil {
							return true
						}
						sig, ok := callee.Type().(*types.Signature)
						if !ok {
							return true
						}
						if cur.CallKind == flowir.CallMethod && !cur.IsMethodExprCall && sig.Recv() != nil && cur.Recv != nil {
							rv := sig.Recv()
							xRef, xCar := classifyValue(cur.Recv)
							if xCar {
								mutRecv := false
								if cur.HasRecvPlace {
									mutRecv = placeMutatesTaintedTarget(cur.RecvPlace)
								} else {
									mutRecv = valueMutatesTaintedTarget(cur.Recv)
								}
								addRef := xRef || cur.AutoAddrRecv || (isDirectRef(rv.Type()) && mutRecv)
								if markVarTaint(rv, addRef, true) {
									changed = true
								}
							}
						}
						isTupleUnpack := len(cur.Args) == 1 && !cur.Ellipsis && cur.Args[0] != nil && cur.Args[0].Type != nil
						if isTupleUnpack {
							_, isTupleUnpack = types.Unalias(cur.Args[0].Type).(*types.Tuple)
						}
						cur.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, slotIdx int, paramIdx int, okP bool, packedVariadic bool) bool {
							if !okP {
								return true
							}
							var aRef, aCar bool
							if isTupleUnpack {
								aRef, aCar = classifyMultiReturnSlot(arg, slotIdx, slotType)
							} else {
								aRef, aCar = classifyValue(arg)
							}
							if !aCar {
								return true
							}
							pv := sig.Params().At(paramIdx)
							if packedVariadic {
								if markVarTaint(pv, false, true) {
									changed = true
								}
							} else {
								addRef := aRef || (cfg.AllowIntraPkgInterfaceParam && types.IsInterface(pv.Type()))
								if markVarTaint(pv, addRef, true) {
									changed = true
								}
							}
							return true
						})
					}
					return true
				})
			}

			walkAllBodies(func(b *flowir.Body, enclFunc *types.Func, _ bool) bool {
				for i := range b.Ops {
					op := &b.Ops[i]
					op.ForEachValue(func(v *flowir.Value) bool { taintVal(v); return true })
					switch op.Kind {
					case flowir.OpAssign:
						switch op.AssignKind {
						case flowir.AssignPlain:
							op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
								rRef, rCar := classifyValue(src)
								if !rCar {
									return true
								}
								if dst.IsBareVar() {
									if markVarTaint(dst.Obj, rRef, true) {
										changed = true
									}
								} else if markContainerIndexWrite(dst) {
									changed = true
								}
								return true
							})
						case flowir.AssignMulti:
							if len(op.Srcs) == 1 && op.Srcs[0] != nil {
								rhs := op.Srcs[0]
								rhsTup, _ := rhs.Type.(*types.Tuple)
								for idxDst, dst := range op.Dsts {
									if !dst.IsBareVar() {
										continue
									}
									slotT := dst.Type
									if rhsTup != nil && idxDst < rhsTup.Len() {
										slotT = rhsTup.At(idxDst).Type()
									}
									pRef, pCar := classifyMultiReturnSlot(rhs, idxDst, slotT)
									if !pCar {
										continue
									}
									addRef := pRef || isOpaqueIfaceOrTP(dst.Obj.Type())
									if markVarTaint(dst.Obj, addRef, true) {
										changed = true
									}
								}
							}
						case flowir.AssignRange:
							if len(op.Srcs) == 1 && op.Srcs[0] != nil {
								rngX := op.Srcs[0]
								if _, xCar := classifyValue(rngX); xCar {
									for _, dst := range op.Dsts {
										if !dst.IsBareVar() {
											continue
										}
										pRef, pCar := projectedClassify(dst.Type, rngX.Raw)
										if pCar && markVarTaint(dst.Obj, pRef, true) {
											changed = true
										}
									}
								}
							}
						}

					case flowir.OpTypeSwitchBind:
						if op.SwitchDst != nil {
							if _, sCar := classifyValue(op.SwitchSrc); sCar {
								if markVarTaint(op.SwitchDst, true, true) {
									changed = true
								}
							}
						}

					case flowir.OpReturn:
						if !canPropagateReturn(enclFunc) {
							continue
						}
						markRetSlot := func(ri int, rRef, rCar bool) {
							rk := retSlot{fn: enclFunc, idx: ri}
							if rCar && !taintedRetCarrier[rk] {
								taintedRetCarrier[rk] = true
								taintedRetAnyCarrier[enclFunc] = true
								changed = true
							}
							if rRef && !taintedRetRef[rk] {
								taintedRetRef[rk] = true
								taintedRetAnyRef[enclFunc] = true
								changed = true
							}
						}
						if op.IsNaked {
							sig := enclFunc.Signature()
							for ri := 0; ri < sig.Results().Len(); ri++ {
								rv := sig.Results().At(ri)
								markRetSlot(ri, taintedRef[rv], taintedCarrier[rv])
							}
						} else if len(op.Results) == 1 && op.Results[0] != nil {
							if tup, isTup := op.Results[0].Type.(*types.Tuple); isTup {
								for ri := 0; ri < tup.Len(); ri++ {
									rRef, rCar := classifyMultiReturnSlot(op.Results[0], ri, tup.At(ri).Type())
									markRetSlot(ri, rRef, rCar)
								}
								continue
							}
							rRef, rCar := classifyValue(op.Results[0])
							markRetSlot(0, rRef, rCar)
						} else {
							for ri, r := range op.Results {
								rRef, rCar := classifyValue(r)
								markRetSlot(ri, rRef, rCar)
							}
						}
					}
				}
				return true
			})
		}

		promoted := false
		if (cfg.AllowCompositeLitIntoSeedStruct && cfg.CanBeSeedStructCapsule != nil) || cfg.AllowCompositeLitFieldPropagation {
			promoteVal := func(v *flowir.Value) {
				if v == nil {
					return
				}
				v.WalkValues(func(cur *flowir.Value) bool {
					cl := allocCompositeLitAST(cur)
					if cl == nil {
						return true
					}
					st := syntaxutil.DerefNamedStruct(info.TypeOf(cl))
					if st == nil {
						return true
					}
					orig := st.Origin()
					if isSeedStruct(orig) || !isEligibleCapsule(orig) {
						return true
					}
					if cfg.AllowCompositeLitIntoSeedStruct && cfg.CanBeSeedStructCapsule != nil && cfg.CanBeSeedStructCapsule(orig) {
						for i := range cur.CompositeElts {
							if _, vCar := classifyValue(cur.CompositeElts[i].Value); vCar {
								capsuleStructs[orig] = true
								promoted = true
								break
							}
						}
					}
					if cfg.AllowCompositeLitFieldPropagation && !isSeedStruct(orig) {
						for i := range cur.CompositeElts {
							elt := &cur.CompositeElts[i]
							if _, vCar := classifyValue(elt.Value); vCar && elt.Field != nil {
								if !propagatedStructs[orig] {
									propagatedStructs[orig] = true
									promoted = true
								}
								if !propagatedFields[elt.Field.Origin()] {
									propagatedFields[elt.Field.Origin()] = true
									promoted = true
								}
							}
						}
					}
					return true
				})
			}
			walkAllBodies(func(b *flowir.Body, _ *types.Func, _ bool) bool {
				for i := range b.Ops {
					b.Ops[i].ForEachValue(func(v *flowir.Value) bool { promoteVal(v); return true })
				}
				return true
			})
		}
		if !promoted {
			break
		}
	}

	reject := func(pos token.Pos, clause string) bool {
		if cfg.OnReject != nil {
			cfg.OnReject(pos, clause)
		}
		return false
	}
	valPos := func(v *flowir.Value) token.Pos {
		if v != nil && v.Raw != nil {
			return v.Raw.Pos()
		}
		return token.NoPos
	}

	// Reject any tainted package-scope variable or disallowed named result variable.
	for v := range taintedCarrier {
		if v.Parent() == p.Types.Scope() {
			return reject(v.Pos(), "tainted package-scope variable "+v.Name())
		}
	}
	if !walkAllBodies(func(b *flowir.Body, enclFunc *types.Func, _ bool) bool {
		if len(b.Results) == 0 {
			return true
		}
		if !canPropagateReturn(enclFunc) {
			for _, rv := range b.Results {
				if rv != nil && taintedCarrier[rv] {
					return reject(rv.Pos(), "tainted named result variable "+rv.Name())
				}
			}
		}
		return true
	}) {
		return false
	}

	// Identify local container variables whose backing storage is provably freshly
	// allocated in the declaring body over FlowIR and not directly tainted as a
	// protected reference.
	localFreshContainer := map[*types.Var]bool{}
	{
		freshCand := map[*types.Var]bool{}
		freshDisq := map[*types.Var]bool{}
		isFreshContainerInit := func(v *types.Var, src *flowir.Value) bool {
			if src == nil || src.IsNil {
				return true
			}
			if src.Kind == flowir.ValAllocFresh {
				if src.AllocKind == flowir.AllocMake {
					return true
				}
				if src.AllocKind == flowir.AllocCompositeLit && src.Type != nil {
					switch types.Unalias(src.Type).Underlying().(type) {
					case *types.Slice, *types.Array, *types.Map:
						return true
					}
				}
			}
			if src.Kind == flowir.ValCall && src.CallKind == flowir.CallBuiltin && src.BuiltinName == "append" &&
				len(src.Args) > 0 && src.Args[0] != nil && src.Args[0].Kind == flowir.ValPlace &&
				src.Args[0].Place.IsBareVar() && src.Args[0].Place.Obj == v {
				return true
			}
			return false
		}
		scanFreshVal := func(v *flowir.Value) {
			if v == nil {
				return
			}
			v.WalkValues(func(cur *flowir.Value) bool {
				switch cur.Kind {
				case flowir.ValAddrOf:
					if !cur.IsArraySlice && cur.AddrPlace.Obj != nil {
						freshDisq[cur.AddrPlace.Obj] = true
					}
				case flowir.ValCall:
					if cur.AutoAddrRecv && cur.HasRecvPlace && cur.RecvPlace.Obj != nil {
						freshDisq[cur.RecvPlace.Obj] = true
					}
				case flowir.ValMethodVal:
					if cur.AutoAddr && cur.HasRecvPlace && cur.RecvPlace.Obj != nil {
						freshDisq[cur.RecvPlace.Obj] = true
					}
				}
				return true
			})
		}
		walkAllBodies(func(b *flowir.Body, _ *types.Func, _ bool) bool {
			for i := range b.Ops {
				op := &b.Ops[i]
				op.ForEachValue(func(v *flowir.Value) bool { scanFreshVal(v); return true })
				switch op.Kind {
				case flowir.OpAssign:
					switch op.AssignKind {
					case flowir.AssignZeroDecl:
						for _, dst := range op.Dsts {
							if dst.IsBareVar() && dst.Obj != nil {
								if dst.Root == flowir.RootLocal {
									freshCand[dst.Obj] = true
								} else {
									freshDisq[dst.Obj] = true
								}
							}
						}
					case flowir.AssignPlain:
						op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
							if dst.IsBareVar() && dst.Obj != nil {
								if dst.Root != flowir.RootLocal {
									freshDisq[dst.Obj] = true
									return true
								}
								freshCand[dst.Obj] = true
								if !isFreshContainerInit(dst.Obj, src) {
									freshDisq[dst.Obj] = true
								}
							}
							return true
						})
					case flowir.AssignMulti, flowir.AssignCompound, flowir.AssignIncDec, flowir.AssignRange:
						for _, dst := range op.Dsts {
							if dst.IsBareVar() && dst.Obj != nil {
								freshDisq[dst.Obj] = true
							}
						}
					}
				case flowir.OpTypeSwitchBind:
					if op.SwitchDst != nil {
						freshDisq[op.SwitchDst] = true
					}
				}
			}
			return true
		})
		for v := range freshCand {
			if !freshDisq[v] && !taintedRef[v] {
				localFreshContainer[v] = true
			}
		}
	}

	// Track `v = append(v, elem)` statements where v is a fresh local slice variable.
	selfAssignedAppendCalls := map[*ast.CallExpr]bool{}
	walkAllBodies(func(b *flowir.Body, _ *types.Func, _ bool) bool {
		for i := range b.Ops {
			op := &b.Ops[i]
			if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignPlain &&
				len(op.Dsts) == 1 && len(op.Srcs) == 1 && len(op.DstDefs) == 1 && !op.DstDefs[0] &&
				op.Dsts[0].IsBareVar() && localFreshContainer[op.Dsts[0].Obj] {
				src := op.Srcs[0]
				if src != nil && src.Kind == flowir.ValCall && src.CallKind == flowir.CallBuiltin &&
					src.BuiltinName == "append" && src.CallAST != nil && len(src.Args) > 0 &&
					src.Args[0] != nil && src.Args[0].Kind == flowir.ValPlace &&
					src.Args[0].Place.IsBareVar() && src.Args[0].Place.Obj == op.Dsts[0].Obj {
					selfAssignedAppendCalls[src.CallAST] = true
				}
			}
		}
		return true
	})

	// Verify promoted capsule structs have zero direct field writes, whole-struct
	// dereference writes, or interior field address-takes anywhere in p.Syntax.
	if len(capsuleStructs) > 0 && !verifyCapsuleStructsWriteFree(p, capsuleStructs) {
		return reject(token.NoPos, "capsule struct write-free check failed")
	}

	// Verify field-propagated structs cannot be stored in package-scope variables,
	// surfaced in exported function/type/method signatures, or instantiated into
	// generic type parameters.
	if len(propagatedStructs) > 0 {
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			switch x := obj.(type) {
			case *types.Var:
				if typeMentionsSeedStruct(x.Type(), isPropagatedStruct) {
					return reject(x.Pos(), "field-propagated struct in package-scope variable "+x.Name())
				}
			case *types.Func:
				if x.Exported() && typeMentionsSeedStruct(x.Type(), isPropagatedStruct) {
					return reject(x.Pos(), "field-propagated struct in exported function signature "+x.Name())
				}
			case *types.TypeName:
				if x.Exported() {
					if typeMentionsSeedStruct(x.Type(), isPropagatedStruct) {
						return reject(x.Pos(), "field-propagated struct in exported type "+x.Name())
					}
					if named, isN := types.Unalias(x.Type()).(*types.Named); isN {
						mset := types.NewMethodSet(types.NewPointer(named))
						for mi := 0; mi < mset.Len(); mi++ {
							if m := mset.At(mi).Obj(); m != nil && m.Exported() && typeMentionsSeedStruct(m.Type(), isPropagatedStruct) {
								return reject(m.Pos(), "field-propagated struct in exported method signature "+m.Name())
							}
						}
					}
				}
			}
		}
		for id, inst := range info.Instances {
			if inst.TypeArgs != nil {
				for ti := 0; ti < inst.TypeArgs.Len(); ti++ {
					if typeMentionsSeedStruct(inst.TypeArgs.At(ti), isPropagatedStruct) {
						return reject(id.Pos(), "field-propagated struct in generic type argument")
					}
				}
			}
		}
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

	if cfg.ForbidNonNilSeedStructPtrCompare {
		hasMapWithSeedKey := func(root types.Type) bool {
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
				switch u := t.Underlying().(type) {
				case *types.Map:
					if typeContainsPtrToSeedStruct(u.Key()) {
						hit = true
						return
					}
					walk(u.Key())
					walk(u.Elem())
				case *types.Pointer:
					walk(u.Elem())
				case *types.Slice:
					walk(u.Elem())
				case *types.Array:
					walk(u.Elem())
				case *types.Chan:
					walk(u.Elem())
				case *types.Struct:
					for i := 0; i < u.NumFields(); i++ {
						walk(u.Field(i).Type())
					}
				case *types.Signature:
					if u.Params() != nil {
						for i := 0; i < u.Params().Len(); i++ {
							walk(u.Params().At(i).Type())
						}
					}
					if u.Results() != nil {
						for i := 0; i < u.Results().Len(); i++ {
							walk(u.Results().At(i).Type())
						}
					}
				}
			}
			walk(root)
			return hit
		}
		for expr, tv := range info.Types {
			if hasMapWithSeedKey(tv.Type) {
				return reject(expr.Pos(), "map keyed by protected struct pointer")
			}
		}
		for id, obj := range info.Defs {
			if obj != nil && hasMapWithSeedKey(obj.Type()) {
				return reject(id.Pos(), "map keyed by protected struct pointer")
			}
		}
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
		if len(propagatedStructs) > 0 && typeMentionsSeedStruct(srcT, isPropagatedStruct) {
			if dstT == nil || syntaxutil.IsUnsafePointerType(dstT) || assignErasesSeedStruct(srcT, dstT, isPropagatedStruct) {
				return true
			}
		}
		srcSt := syntaxutil.DerefNamedStruct(srcT)
		if !isSeedStruct(srcSt) && !isPropagatedStruct(srcSt) {
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
			return cfg.ForbidNonNilSeedStructPtrCompare || iface.NumMethods() == 0 || isPropagatedStruct(srcSt)
		}
		return !types.Identical(d, types.Unalias(srcT))
	}

	checkLHSPlaceOK := func(dst flowir.Place, isFreshDef bool, inSyncAllowed bool) bool {
		if placeMutatesTaintedTarget(dst) ||
			(!inSyncAllowed && placeHitsStructPred(dst, isSeedStruct, true)) ||
			placeHitsPropagated(dst, !isFreshDef) {
			return reject(dst.RootPos, "mutates tainted or protected target")
		}
		if _, key, isMapW := dst.AsMapWrite(); isMapW && key != nil {
			if _, kCar := classifyValue(key); kCar {
				return reject(valPos(key), "tainted map key")
			}
		}
		return true
	}

	var checkValueOK func(v *flowir.Value, inSyncAllowed bool) bool
	checkValueOK = func(v *flowir.Value, inSyncAllowed bool) bool {
		if v == nil {
			return true
		}
		switch v.Kind {
		case flowir.ValPlace:
			return v.Place.ForEachChildValue(func(cv *flowir.Value) bool { return checkValueOK(cv, inSyncAllowed) })

		case flowir.ValCompare:
			if cfg.ForbidNonNilSeedStructPtrCompare && (v.CompareOp == token.EQL || v.CompareOp == token.NEQ) && v.Left != nil && v.Right != nil {
				if (isPtrToSeedStruct(v.Left.Type) && !v.Right.IsNil) ||
					(isPtrToSeedStruct(v.Right.Type) && !v.Left.IsNil) {
					return reject(valPos(v), "non-nil seed struct pointer comparison")
				}
			}
			return checkValueOK(v.Left, inSyncAllowed) && checkValueOK(v.Right, inSyncAllowed)

		case flowir.ValMethodVal:
			if v.Selection != nil && v.Selection.Kind() == types.MethodVal && !v.Selection.Indirect() && SelectionHasPointerReceiver(v.Selection) {
				if (!inSyncAllowed && valueOrPlaceHitsStructPred(v.Recv, v.RecvPlace, v.HasRecvPlace, isSeedStruct, false)) ||
					valueOrPlaceHitsPropagated(v.Recv, v.RecvPlace, v.HasRecvPlace, false) {
					return reject(valPos(v), "auto-addressed pointer-receiver method value on protected struct")
				}
			}
			_, xCar, mutX, seedX := methodValHasTaintedOrSeedRecv(v)
			if xCar || mutX || seedX {
				if _, okM := boundPkgMethodRecvVal(v); !okM {
					return reject(valPos(v), "unapproved bound method value")
				}
			}
			return checkValueOK(v.Recv, inSyncAllowed)

		case flowir.ValAddrOf:
			if placeMutatesTaintedTarget(v.AddrPlace) ||
				(!inSyncAllowed && placeHitsStructPred(v.AddrPlace, isSeedStruct, false)) ||
				placeHitsPropagated(v.AddrPlace, false) {
				return reject(valPos(v), "address-of or array-slice on tainted or protected place")
			}
			return v.ForEachChildValue(func(cv *flowir.Value) bool { return checkValueOK(cv, inSyncAllowed) })

		case flowir.ValChanRecv:
			if _, cCar := classifyValue(v.Chan); cCar {
				return reject(valPos(v), "receive from tainted channel")
			}
			return checkValueOK(v.Chan, inSyncAllowed)

		case flowir.ValConvert:
			if v.IsTypeAssert {
				if _, xCar := classifyValue(v.Arg); xCar {
					return reject(valPos(v), "type assertion on tainted value")
				}
				return checkValueOK(v.Arg, inSyncAllowed)
			}
			if v.Arg != nil {
				if seedStructTypeViolated(v.Type, v.Arg.Type) {
					return reject(valPos(v), "seed struct conversion violation")
				}
				if _, aCar := classifyValue(v.Arg); aCar {
					if assignErasesTaint(v.Type, v.Arg.Type) {
						return reject(valPos(v), "conversion erases taint")
					}
				}
			}
			return checkValueOK(v.Arg, inSyncAllowed)

		case flowir.ValAllocFresh:
			switch v.AllocKind {
			case flowir.AllocBuiltinNewType:
				return true
			case flowir.AllocBuiltinNewExpr:
				if len(v.Args) == 1 && v.Args[0] != nil {
					if seedStructTypeViolated(nil, v.Args[0].Type) {
						return reject(valPos(v), "new(expr) on protected struct")
					}
					if _, aCar := classifyValue(v.Args[0]); aCar {
						return reject(valPos(v), "new(expr) on tainted value")
					}
					return checkValueOK(v.Args[0], inSyncAllowed)
				}
				return true
			case flowir.AllocMake:
				for _, a := range v.Args {
					if a == nil {
						continue
					}
					if seedStructTypeViolated(nil, a.Type) {
						return reject(valPos(a), "make arg seed struct violation")
					}
					if _, aCar := classifyValue(a); aCar {
						return reject(valPos(a), "make arg tainted")
					}
					if !checkValueOK(a, inSyncAllowed) {
						return false
					}
				}
				return true
			case flowir.AllocCompositeLit:
				cl := allocCompositeLitAST(v)
				if cl == nil {
					return v.ForEachChildValue(func(cv *flowir.Value) bool { return checkValueOK(cv, inSyncAllowed) })
				}
				clT := info.TypeOf(cl)
				if clT == nil {
					return v.ForEachChildValue(func(cv *flowir.Value) bool { return checkValueOK(cv, inSyncAllowed) })
				}
				baseT := types.Unalias(clT)
				if ptr, isP := baseT.(*types.Pointer); isP {
					baseT = types.Unalias(ptr.Elem())
				}
				_, isSlice := baseT.Underlying().(*types.Slice)
				_, isArray := baseT.Underlying().(*types.Array)
				_, isMap := baseT.Underlying().(*types.Map)
				_, isStruct := baseT.Underlying().(*types.Struct)
				allowedSeedSt := isStruct && isAllowedStructCompositeLit(v)

				for i := range v.CompositeElts {
					elt := &v.CompositeElts[i]
					if elt.MapKey != nil {
						if isMap && seedStructTypeViolated(baseT.Underlying().(*types.Map).Key(), elt.MapKey.Type) {
							return reject(valPos(elt.MapKey), "map key seed struct violation")
						}
						if _, kCar := classifyValue(elt.MapKey); kCar {
							return reject(valPos(elt.MapKey), "tainted composite map key")
						}
						if !checkValueOK(elt.MapKey, inSyncAllowed) {
							return false
						}
					}
					if elt.Index != nil && !checkValueOK(elt.Index, inSyncAllowed) {
						return false
					}
					if elt.Value == nil {
						continue
					}
					if !checkValueOK(elt.Value, inSyncAllowed) {
						return false
					}
					var dstElemT types.Type
					switch {
					case isSlice:
						dstElemT = baseT.Underlying().(*types.Slice).Elem()
					case isArray:
						dstElemT = baseT.Underlying().(*types.Array).Elem()
					case isMap:
						dstElemT = baseT.Underlying().(*types.Map).Elem()
					case isStruct && elt.Field != nil:
						dstElemT = elt.Field.Type()
					}
					if seedStructTypeViolated(dstElemT, elt.Value.Type) {
						return reject(valPos(elt.Value), "composite element seed struct violation")
					}
					if _, vCar := classifyValue(elt.Value); !vCar {
						continue
					}
					if !isSlice && !isArray && !allowedSeedSt {
						return reject(valPos(elt.Value), "tainted composite element in disallowed type")
					}
					if dstElemT == nil || assignErasesTaint(dstElemT, elt.Value.Type) {
						return reject(valPos(elt.Value), "composite element erases taint")
					}
				}
				return true
			}
			return true

		case flowir.ValCall:
			if !inSyncAllowed && v.CallAST != nil && callMutatesSeedStructContainer(info, v.CallAST, isSeedStruct) {
				return reject(valPos(v), "call mutates seed struct container")
			}
			if v.CallKind == flowir.CallMethod && !v.IsMethodExprCall && v.Selection != nil &&
				v.Selection.Kind() == types.MethodVal && !v.Selection.Indirect() && SelectionHasPointerReceiver(v.Selection) {
				if (!inSyncAllowed && valueOrPlaceHitsStructPred(v.Recv, v.RecvPlace, v.HasRecvPlace, isSeedStruct, false)) ||
					valueOrPlaceHitsPropagated(v.Recv, v.RecvPlace, v.HasRecvPlace, false) {
					return reject(valPos(v), "auto-addressed pointer-receiver method call on protected struct")
				}
			}
			if callValueErasesSeedStruct(v, seedStructTypeViolated, cfg.AllowCallArg) {
				return reject(valPos(v), "call arg erases seed struct")
			}

			if v.CallKind == flowir.CallMethod && !v.IsMethodExprCall && v.Selection != nil && v.Selection.Kind() == types.MethodVal {
				if _, rCar := classifyValue(v.Recv); rCar {
					if callee := resolveConcretePkgCalleeVal(v); callee != nil {
						// Taint propagated to callee's receiver parameter.
					} else if v.Selection.Recv() != nil && !types.IsInterface(v.Selection.Recv()) && cfg.AllowMethodRecv != nil && v.CallAST != nil && v.CalleeSel != nil {
						mFn, _ := v.Selection.Obj().(*types.Func)
						if !cfg.AllowMethodRecv(v.CallAST, mFn, v.CalleeSel.X) {
							return reject(valPos(v), "disallowed method call on tainted receiver")
						}
					} else {
						return reject(valPos(v), "unapproved method call on tainted receiver")
					}
				}
			} else if v.Callee != nil {
				if _, fCar := classifyValue(v.Callee); fCar {
					return reject(valPos(v), "indirect call on tainted callee")
				}
			}

			if !v.ForEachChildValue(func(cv *flowir.Value) bool { return checkValueOK(cv, inSyncAllowed) }) {
				return false
			}

			if v.CallKind == flowir.CallBuiltin {
				for argIdx, arg := range v.Args {
					if arg == nil {
						continue
					}
					aRef, aCar := classifyValue(arg)
					if !aCar {
						continue
					}
					if v.BuiltinName == "len" || v.BuiltinName == "cap" || v.BuiltinName == "Sizeof" || v.BuiltinName == "Alignof" || v.BuiltinName == "Offsetof" {
						continue
					}
					if v.BuiltinName == "append" {
						if argIdx == 0 {
							if !aRef && v.CallAST != nil && selfAssignedAppendCalls[v.CallAST] {
								continue
							}
							return reject(valPos(arg), "append into non-fresh or tainted-ref slice")
						}
						if v.Ellipsis {
							if sl, isSl := syntaxutil.UnderlyingType(arg.Type).(*types.Slice); isSl && !elemHasHandle(sl.Elem()) {
								continue
							}
						} else if v.CallAST != nil && selfAssignedAppendCalls[v.CallAST] {
							if sl, isSl := syntaxutil.UnderlyingType(v.Type).(*types.Slice); isSl && !assignErasesTaint(sl.Elem(), arg.Type) {
								continue
							}
						}
						return reject(valPos(arg), "append of tainted element")
					}
					if v.BuiltinName == "copy" && argIdx == 1 {
						if sl, isSl := syntaxutil.UnderlyingType(arg.Type).(*types.Slice); isSl && !elemHasHandle(sl.Elem()) {
							continue
						}
					}
					if v.CallAST != nil && argIdx < len(v.CallAST.Args) && cfg.AllowCallArg != nil && cfg.AllowCallArg(v.CallAST, argIdx, v.CallAST.Args[argIdx]) {
						continue
					}
					return reject(valPos(arg), "tainted argument to builtin "+v.BuiltinName)
				}
				return true
			}

			if v.IsMethodExprCall {
				if v.Recv != nil {
					if _, rCar := classifyValue(v.Recv); rCar {
						if !(v.CallAST != nil && len(v.CallAST.Args) > 0 && cfg.AllowCallArg != nil && cfg.AllowCallArg(v.CallAST, 0, v.CallAST.Args[0])) {
							return reject(valPos(v.Recv), "tainted receiver in method expression call")
						}
					}
				}
				for i, arg := range v.Args {
					if arg == nil {
						continue
					}
					if _, aCar := classifyValue(arg); !aCar {
						continue
					}
					rawIdx := i + 1
					if v.CallAST != nil && rawIdx < len(v.CallAST.Args) && cfg.AllowCallArg != nil && cfg.AllowCallArg(v.CallAST, rawIdx, v.CallAST.Args[rawIdx]) {
						continue
					}
					return reject(valPos(arg), "tainted argument in method expression call")
				}
				return true
			}

			callee := resolveConcretePkgCalleeVal(v)
			isTupleUnpack := len(v.Args) == 1 && !v.Ellipsis && v.Args[0] != nil && v.Args[0].Type != nil
			if isTupleUnpack {
				_, isTupleUnpack = types.Unalias(v.Args[0].Type).(*types.Tuple)
			}
			callOK := true
			v.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, slotIdx int, paramIdx int, okP bool, packedVariadic bool) bool {
				var aCar bool
				if isTupleUnpack {
					_, aCar = classifyMultiReturnSlot(arg, slotIdx, slotType)
				} else {
					_, aCar = classifyValue(arg)
				}
				if !aCar {
					return true
				}
				if callee != nil {
					if !okP {
						callOK = reject(valPos(arg), "missing formal param on intra-pkg call")
						return false
					}
					pt := v.FormalParamSlotType(paramIdx, packedVariadic)
					if (cfg.AllowIntraPkgInterfaceParam && !packedVariadic && pt != nil && types.IsInterface(pt)) || !assignErasesTaint(pt, slotType) {
						return true
					}
				}
				if !isTupleUnpack && v.CallAST != nil && slotIdx < len(v.CallAST.Args) && cfg.AllowCallArg != nil && cfg.AllowCallArg(v.CallAST, slotIdx, v.CallAST.Args[slotIdx]) {
					return true
				}
				callOK = reject(valPos(arg), "unapproved tainted call argument")
				return false
			})
			return callOK

		default:
			return v.ForEachChildValue(func(cv *flowir.Value) bool { return checkValueOK(cv, inSyncAllowed) })
		}
	}

	return walkAllBodies(func(b *flowir.Body, enclFunc *types.Func, inSyncAllowed bool) bool {
		for i := range b.Ops {
			op := &b.Ops[i]
			switch op.Kind {
			case flowir.OpAssign:
				for _, dst := range op.Dsts {
					if !dst.ForEachChildValue(func(cv *flowir.Value) bool { return checkValueOK(cv, inSyncAllowed) }) {
						return false
					}
				}
				for _, src := range op.Srcs {
					if !checkValueOK(src, inSyncAllowed) {
						return false
					}
				}
				switch op.AssignKind {
				case flowir.AssignZeroDecl:
					for idxDst, dst := range op.Dsts {
						isDef := idxDst < len(op.DstDefs) && op.DstDefs[idxDst] && dst.IsBareVar()
						if !checkLHSPlaceOK(dst, isDef, inSyncAllowed) {
							return false
						}
					}

				case flowir.AssignIncDec:
					for _, dst := range op.Dsts {
						if !checkLHSPlaceOK(dst, false, inSyncAllowed) {
							return false
						}
					}

				case flowir.AssignCompound:
					for idxDst, dst := range op.Dsts {
						if !checkLHSPlaceOK(dst, false, inSyncAllowed) {
							return false
						}
						if idxDst < len(op.Srcs) && op.Srcs[idxDst] != nil && len(op.Srcs[idxDst].Args) == 2 {
							rhs := op.Srcs[idxDst].Args[1]
							if rhs != nil {
								if seedStructTypeViolated(dst.Type, rhs.Type) {
									return reject(valPos(rhs), "compound assign seed struct violation")
								}
								if _, rCar := classifyValue(rhs); rCar {
									return reject(valPos(rhs), "compound assign tainted rhs")
								}
							}
						}
					}

				case flowir.AssignPlain:
					pairsOK := true
					op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
						if !checkLHSPlaceOK(dst, isDef && dst.IsBareVar(), inSyncAllowed) {
							pairsOK = false
							return false
						}
						if src == nil {
							return true
						}
						if !dst.IsBlank() && seedStructTypeViolated(dst.Type, src.Type) {
							pairsOK = reject(valPos(src), "assign seed struct violation")
							return false
						}
						rRef, rCar := classifyValue(src)
						if !rCar || dst.IsBlank() {
							return true
						}
						if dst.IsBareVar() {
							if assignErasesTaint(dst.Obj.Type(), src.Type) {
								pairsOK = reject(valPos(src), "assign to bare var erases taint")
								return false
							}
							return true
						}
						if len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjIndex && dst.Obj != nil && localFreshContainer[dst.Obj] {
							if !assignErasesTaint(dst.Type, src.Type) {
								return true
							}
						}
						if cfg.AllowAssignTarget != nil && dst.Raw != nil && src.Raw != nil &&
							!assignErasesTaint(dst.Type, src.Type) &&
							cfg.AllowAssignTarget(dst.Raw, src.Raw, rRef) {
							return true
						}
						pairsOK = reject(valPos(src), "assign tainted value to non-bare target")
						return false
					})
					if !pairsOK {
						return false
					}

				case flowir.AssignMulti:
					for idxDst, dst := range op.Dsts {
						isDef := idxDst < len(op.DstDefs) && op.DstDefs[idxDst] && dst.IsBareVar()
						if !checkLHSPlaceOK(dst, isDef, inSyncAllowed) {
							return false
						}
					}
					if len(op.Srcs) == 1 && op.Srcs[0] != nil {
						rhs := op.Srcs[0]
						rhsTup, _ := rhs.Type.(*types.Tuple)
						if rhsTup != nil {
							for idxDst, dst := range op.Dsts {
								if idxDst < rhsTup.Len() && !dst.IsBlank() && seedStructTypeViolated(dst.Type, rhsTup.At(idxDst).Type()) {
									return reject(valPos(rhs), "multi-assign seed struct violation")
								}
							}
						} else if len(op.Dsts) > 0 && !op.Dsts[0].IsBlank() && seedStructTypeViolated(op.Dsts[0].Type, rhs.Type) {
							return reject(valPos(rhs), "comma-ok assign seed struct violation")
						}
						for idxDst, dst := range op.Dsts {
							srcElemT := dst.Type
							if rhsTup != nil && idxDst < rhsTup.Len() {
								srcElemT = rhsTup.At(idxDst).Type()
							}
							if _, sCar := classifyMultiReturnSlot(rhs, idxDst, srcElemT); !sCar {
								continue
							}
							if dst.IsBlank() {
								continue
							}
							if !dst.IsBareVar() || (srcElemT != nil && assignErasesTaint(dst.Obj.Type(), srcElemT)) {
								return reject(valPos(rhs), "multi-assign tainted value to non-bare or erasing target")
							}
						}
					}

				case flowir.AssignRange:
					for idxDst, dst := range op.Dsts {
						isDef := idxDst < len(op.DstDefs) && op.DstDefs[idxDst]
						if !isDef && !dst.IsBlank() && !checkLHSPlaceOK(dst, false, inSyncAllowed) {
							return false
						}
					}
					if len(op.Srcs) == 1 && op.Srcs[0] != nil {
						rngX := op.Srcs[0]
						if _, xCar := classifyValue(rngX); xCar {
							for idxDst, dst := range op.Dsts {
								isDef := idxDst < len(op.DstDefs) && op.DstDefs[idxDst]
								if isDef || dst.IsBlank() {
									continue
								}
								if _, pCar := projectedClassify(dst.Type, rngX.Raw); !pCar {
									continue
								}
								if !dst.IsBareVar() {
									return reject(valPos(rngX), "range over tainted container into non-bare target")
								}
							}
						}
					}
				}

			case flowir.OpTypeSwitchBind:
				if !checkValueOK(op.SwitchSrc, inSyncAllowed) {
					return false
				}
				if _, sCar := classifyValue(op.SwitchSrc); sCar {
					return reject(valPos(op.SwitchSrc), "type switch on tainted value")
				}
				if cfg.ForbidNonNilSeedStructPtrCompare && op.SwitchAST != nil && op.SwitchAST.Body != nil {
					for _, raw := range op.SwitchAST.Body.List {
						if cc, okCC := raw.(*ast.CaseClause); okCC {
							for _, ce := range cc.List {
								if !syntaxutil.IsNilIdent(info, ce) && isPtrToSeedStruct(info.TypeOf(ce)) {
									return reject(ce.Pos(), "type switch case on pointer to seed struct")
								}
							}
						}
					}
				}

			case flowir.OpChanSend:
				if !op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool { return checkValueOK(cv, inSyncAllowed) }) ||
					!checkValueOK(op.ChanVal, inSyncAllowed) || !checkValueOK(op.SendVal, inSyncAllowed) {
					return false
				}
				if op.ChanVal != nil && op.SendVal != nil {
					if ch, isCh := syntaxutil.UnderlyingType(op.ChanVal.Type).(*types.Chan); isCh {
						if seedStructTypeViolated(ch.Elem(), op.SendVal.Type) {
							return reject(valPos(op.SendVal), "channel send seed struct violation")
						}
					} else if (cfg.ForbidNonNilSeedStructPtrCompare && typeMentionsSeedStruct(op.SendVal.Type, isSeedStruct)) ||
						(len(propagatedStructs) > 0 && typeMentionsSeedStruct(op.SendVal.Type, isPropagatedStruct)) {
						return reject(valPos(op.SendVal), "channel send mentions protected struct")
					}
				}
				if _, chCar := classifyValue(op.ChanVal); chCar {
					return reject(valPos(op.ChanVal), "send on tainted channel")
				}
				if _, vCar := classifyValue(op.SendVal); vCar {
					return reject(valPos(op.SendVal), "send of tainted value")
				}

			case flowir.OpReturn:
				for _, r := range op.Results {
					if !checkValueOK(r, inSyncAllowed) {
						return false
					}
				}
				if len(op.Results) == 1 && op.Results[0] != nil && (cfg.ForbidNonNilSeedStructPtrCompare || len(propagatedStructs) > 0) {
					if tup, isTup := op.Results[0].Type.(*types.Tuple); isTup {
						for ti := 0; ti < tup.Len(); ti++ {
							rT := tup.At(ti).Type()
							if enclFunc != nil && enclFunc.Signature().Results() != nil && ti < enclFunc.Signature().Results().Len() {
								if seedStructTypeViolated(enclFunc.Signature().Results().At(ti).Type(), rT) {
									return reject(valPos(op.Results[0]), "tuple return seed struct violation")
								}
							} else if (cfg.ForbidNonNilSeedStructPtrCompare && typeMentionsSeedStruct(rT, isSeedStruct)) ||
								(len(propagatedStructs) > 0 && typeMentionsSeedStruct(rT, isPropagatedStruct)) {
								return reject(valPos(op.Results[0]), "tuple return mentions protected struct")
							}
						}
					}
				}
				for ri, r := range op.Results {
					if r == nil {
						continue
					}
					if enclFunc != nil {
						res := enclFunc.Signature().Results()
						if ri < res.Len() {
							if seedStructTypeViolated(res.At(ri).Type(), r.Type) {
								return reject(valPos(r), "return seed struct violation")
							}
						} else if (cfg.ForbidNonNilSeedStructPtrCompare && typeMentionsSeedStruct(r.Type, isSeedStruct)) ||
							(len(propagatedStructs) > 0 && typeMentionsSeedStruct(r.Type, isPropagatedStruct)) {
							return reject(valPos(r), "return mentions protected struct")
						}
					} else if isSeedStruct(syntaxutil.DerefNamedStruct(r.Type)) ||
						(cfg.ForbidNonNilSeedStructPtrCompare && typeMentionsSeedStruct(r.Type, isSeedStruct)) ||
						(len(propagatedStructs) > 0 && typeMentionsSeedStruct(r.Type, isPropagatedStruct)) {
						return reject(valPos(r), "closure return mentions protected struct")
					}
					if len(op.Results) == 1 {
						if tup, isTup := r.Type.(*types.Tuple); isTup {
							for ti := 0; ti < tup.Len(); ti++ {
								st := tup.At(ti).Type()
								if _, sCar := classifyMultiReturnSlot(r, ti, st); !sCar {
									continue
								}
								if !canPropagateReturn(enclFunc) {
									return reject(valPos(r), "disallowed tuple return of tainted value")
								}
								res := enclFunc.Signature().Results()
								if ti >= res.Len() || assignErasesTaint(res.At(ti).Type(), st) {
									return reject(valPos(r), "tuple return erases taint")
								}
							}
							continue
						}
					}
					if _, rCar := classifyValue(r); !rCar {
						continue
					}
					if !canPropagateReturn(enclFunc) {
						return reject(valPos(r), "disallowed return of tainted value")
					}
					res := enclFunc.Signature().Results()
					if ri >= res.Len() || assignErasesTaint(res.At(ri).Type(), r.Type) {
						return reject(valPos(r), "return erases taint")
					}
				}

			case flowir.OpDefer:
				if !checkValueOK(op.Call, inSyncAllowed) {
					return false
				}

			case flowir.OpGo:
				if !checkValueOK(op.Call, !cfg.ForbidNonNilSeedStructPtrCompare) {
					return false
				}

			case flowir.OpExpr:
				if cfg.ForbidNonNilSeedStructPtrCompare {
					switch st := op.StmtAST.(type) {
					case *ast.CaseClause:
						if op.Expr != nil && !op.Expr.IsNil && isPtrToSeedStruct(op.Expr.Type) {
							return reject(valPos(op.Expr), "switch case on pointer to seed struct")
						}
					case *ast.SwitchStmt:
						if op.Expr != nil && isPtrToSeedStruct(op.Expr.Type) && st.Body != nil {
							for _, raw := range st.Body.List {
								if cc, okCC := raw.(*ast.CaseClause); okCC {
									for _, ce := range cc.List {
										if !syntaxutil.IsNilIdent(info, ce) {
											return reject(ce.Pos(), "switch on pointer to seed struct with non-nil case")
										}
									}
								}
							}
						}
					}
				}
				if !checkValueOK(op.Expr, inSyncAllowed) {
					return false
				}
			}
		}
		return true
	})
}
