package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
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

type retSlot struct {
	fn  *types.Func
	idx int
}

type refConfinementSolver struct {
	p         *packages.Package
	info      *types.Info
	idx       *PkgIndex
	flowCache *flowir.PkgCache
	cfg       Config
	errorType types.Type

	pkgIfaceMethodNames map[string]bool
	capsuleStructs      map[*types.Named]bool
	propagatedStructs   map[*types.Named]bool
	propagatedFields    map[*types.Var]bool

	taintedRef           map[*types.Var]bool
	taintedCarrier       map[*types.Var]bool
	taintedRetRef        map[retSlot]bool
	taintedRetCarrier    map[retSlot]bool
	taintedRetAnyRef     map[*types.Func]bool
	taintedRetAnyCarrier map[*types.Func]bool

	localFreshContainer     map[*types.Var]bool
	selfAssignedAppendCalls map[*ast.CallExpr]bool
}

// VerifyReadOnlyRefConfinement verifies that every protected reference, pointer,
// or composite carrier seeded by cfg across p.Syntax remains strictly read-only
// and confined without element/pointee writes, address-takes, container-builtin
// mutations, interface/unsafe/pointer type erasures, or unapproved escapes.
func VerifyReadOnlyRefConfinement(p *packages.Package, cfg Config) bool {
	s := newRefConfinementSolver(p, cfg)
	if s == nil {
		return false
	}
	s.solveTaintAndCapsules()
	if !s.verifyGlobalPreChecks() {
		return false
	}
	s.discoverLocalFreshContainers()
	if !s.verifyCapsuleAndSeedStructGlobals() {
		return false
	}
	return s.walkAllBodies(s.checkBodyOpsOK)
}

func newRefConfinementSolver(p *packages.Package, cfg Config) *refConfinementSolver {
	if p == nil || p.Types == nil || p.TypesInfo == nil {
		return nil
	}
	idx := cfg.Index
	if idx == nil {
		idx = BuildPkgIndex(p)
		if idx == nil {
			return nil
		}
	}
	flowCache := idx.FlowCache(p)
	if flowCache == nil {
		return nil
	}
	info := p.TypesInfo
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
	return &refConfinementSolver{
		p:                       p,
		info:                    info,
		idx:                     idx,
		flowCache:               flowCache,
		cfg:                     cfg,
		errorType:               types.Universe.Lookup("error").Type(),
		pkgIfaceMethodNames:     pkgIfaceMethodNames,
		capsuleStructs:          map[*types.Named]bool{},
		propagatedStructs:       map[*types.Named]bool{},
		propagatedFields:        map[*types.Var]bool{},
		taintedRef:              map[*types.Var]bool{},
		taintedCarrier:          map[*types.Var]bool{},
		taintedRetRef:           map[retSlot]bool{},
		taintedRetCarrier:       map[retSlot]bool{},
		taintedRetAnyRef:        map[*types.Func]bool{},
		taintedRetAnyCarrier:    map[*types.Func]bool{},
		localFreshContainer:     map[*types.Var]bool{},
		selfAssignedAppendCalls: map[*ast.CallExpr]bool{},
	}
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

func valPos(v *flowir.Value) token.Pos {
	if v != nil && v.Raw != nil {
		return v.Raw.Pos()
	}
	return token.NoPos
}

func (s *refConfinementSolver) reject(pos token.Pos, clause string) bool {
	if s.cfg.OnReject != nil {
		s.cfg.OnReject(pos, clause)
	}
	return false
}

func (s *refConfinementSolver) isDirectRef(t types.Type) bool {
	return IsDirectMutableRefWith(t, s.cfg.IsImmutablePtr)
}

func (s *refConfinementSolver) carriesRef(t types.Type) bool {
	return TypeCarriesMutableRefWith(t, s.cfg.IsImmutablePtr)
}

func (s *refConfinementSolver) elemHasHandle(t types.Type) bool {
	return TypeContainsRefOrPointerWith(t, s.cfg.IsImmutablePtr)
}

func (s *refConfinementSolver) isOpaqueIfaceOrTP(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if _, isTP := t.(*types.TypeParam); isTP {
		return !s.cfg.AllowScalarTypeParamProjection
	}
	return types.IsInterface(t)
}

func (s *refConfinementSolver) carriesRefOrIface(root types.Type) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if s.cfg.IsImmutablePtr != nil && s.cfg.IsImmutablePtr(t) {
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if s.isDirectRef(t) || s.isOpaqueIfaceOrTP(t) {
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

func (s *refConfinementSolver) projectedClassify(et types.Type, containerExpr ast.Expr) (bool, bool) {
	if s.isDirectRef(et) {
		return true, true
	}
	if s.isOpaqueIfaceOrTP(et) {
		if containerExpr != nil && s.cfg.AllowImmutableInterfaceElem != nil && s.cfg.AllowImmutableInterfaceElem(ast.Unparen(containerExpr)) {
			return false, false
		}
		return true, true
	}
	if s.carriesRefOrIface(et) {
		return false, true
	}
	return false, false
}

func (s *refConfinementSolver) isSeedStruct(st *types.Named) bool {
	if st == nil {
		return false
	}
	orig := st.Origin()
	if s.capsuleStructs[orig] {
		return true
	}
	return s.cfg.SeedStructOrigin != nil && s.cfg.SeedStructOrigin(orig)
}

func (s *refConfinementSolver) isPropagatedStruct(st *types.Named) bool {
	return st != nil && s.propagatedStructs[st.Origin()]
}

func selectionHitsFieldSet(selInfo *types.Selection, fields map[*types.Var]bool) bool {
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

func placeHitsStructPred(pl flowir.Place, match func(*types.Named) bool, includeStarRoot bool) bool {
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

func (s *refConfinementSolver) placeChainHitsSeedStruct(pl flowir.Place) bool {
	if s.cfg.SeedStructOrigin == nil && s.cfg.CanBeSeedStructCapsule == nil {
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
				if s.isSeedStruct(st) {
					hit = true
				}
			})
			if hit {
				return true
			}
		case flowir.ProjIndex:
			if s.isSeedStruct(syntaxutil.DerefNamedStruct(pr.Type)) {
				return true
			}
		case flowir.ProjDeref:
			if s.isSeedStruct(syntaxutil.DerefNamedStruct(pr.BaseType)) {
				return true
			}
		case flowir.ProjSlice:
		}
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil && pl.Base.Kind == flowir.ValAddrOf && pl.Base.IsArraySlice {
		return s.placeChainHitsSeedStruct(pl.Base.AddrPlace)
	}
	return false
}

func (s *refConfinementSolver) placeChainHitsPropagatedField(pl flowir.Place) bool {
	if len(s.propagatedFields) == 0 {
		return false
	}
	for i := len(pl.Projs) - 1; i >= 0; i-- {
		pr := pl.Projs[i]
		if pr.Kind == flowir.ProjField {
			if pr.Selection == nil || pr.Selection.Kind() != types.FieldVal {
				return false
			}
			if selectionHitsFieldSet(pr.Selection, s.propagatedFields) {
				return true
			}
		}
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil && pl.Base.Kind == flowir.ValAddrOf && pl.Base.IsArraySlice {
		return s.placeChainHitsPropagatedField(pl.Base.AddrPlace)
	}
	return false
}

func (s *refConfinementSolver) placeHitsPropagated(pl flowir.Place, includeWholeOrStarStruct bool) bool {
	if len(s.propagatedStructs) == 0 {
		return false
	}
	if includeWholeOrStarStruct && pl.Type != nil {
		if st, ok := types.Unalias(pl.Type).(*types.Named); ok && s.propagatedStructs[st.Origin()] {
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
			if selectionHitsFieldSet(pr.Selection, s.propagatedFields) {
				return true
			}
		case flowir.ProjDeref:
			if includeWholeOrStarStruct {
				if st := syntaxutil.DerefNamedStruct(pr.BaseType); st != nil && s.propagatedStructs[st.Origin()] {
					return true
				}
			}
		}
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil && pl.Base.Kind == flowir.ValAddrOf && pl.Base.IsArraySlice {
		return s.placeHitsPropagated(pl.Base.AddrPlace, includeWholeOrStarStruct)
	}
	return false
}

func valueOrPlaceHitsStructPred(v *flowir.Value, pl flowir.Place, hasPl bool, match func(*types.Named) bool, includeStarRoot bool) bool {
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

func (s *refConfinementSolver) valueOrPlaceHitsPropagated(v *flowir.Value, pl flowir.Place, hasPl bool, includeWholeOrStarStruct bool) bool {
	if hasPl {
		return s.placeHitsPropagated(pl, includeWholeOrStarStruct)
	}
	if v != nil {
		if v.Kind == flowir.ValPlace {
			return s.placeHitsPropagated(v.Place, includeWholeOrStarStruct)
		}
		if v.Kind == flowir.ValAddrOf && v.IsArraySlice {
			return s.placeHitsPropagated(v.AddrPlace, includeWholeOrStarStruct)
		}
		if includeWholeOrStarStruct && v.Type != nil {
			if st, ok := types.Unalias(v.Type).(*types.Named); ok && s.propagatedStructs[st.Origin()] {
				return true
			}
		}
	}
	return false
}

func (s *refConfinementSolver) isNonGenericConcretePkgCallee(callee *types.Func) bool {
	if callee == nil || callee.Pkg() != s.p.Types || callee.Origin() != callee {
		return false
	}
	sig, ok := callee.Type().(*types.Signature)
	return ok && sig.TypeParams().Len() == 0 && sig.RecvTypeParams().Len() == 0
}

func (s *refConfinementSolver) resolveConcretePkgCalleeVal(v *flowir.Value) *types.Func {
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
		if _, hasInst := s.info.Instances[v.CalleeSel.Sel]; hasInst {
			return nil
		}
	}
	if v.CallAST != nil {
		if id, isID := ast.Unparen(v.CallAST.Fun).(*ast.Ident); isID {
			if _, hasInst := s.info.Instances[id]; hasInst {
				return nil
			}
		}
	}
	if s.isNonGenericConcretePkgCallee(v.CalleeFunc) {
		return v.CalleeFunc
	}
	return nil
}

func (s *refConfinementSolver) canPropagateReturn(fn *types.Func) bool {
	if !s.cfg.AllowReturnFromUnexportedFunc ||
		fn == nil ||
		fn.Exported() ||
		!s.isNonGenericConcretePkgCallee(fn) ||
		s.idx.FuncValueTaken[fn.Origin()] {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	if sig.Recv() == nil {
		return true
	}
	return !types.IsInterface(sig.Recv().Type()) && !s.pkgIfaceMethodNames[fn.Name()]
}

func (s *refConfinementSolver) hasDeclBody(orig *types.Func) bool {
	if orig == nil {
		return false
	}
	fd := s.idx.FuncDecls[orig]
	return fd != nil && fd.Body != nil && !(fd.Recv == nil && fd.Name != nil && fd.Name.Name == "init")
}

func (s *refConfinementSolver) boundPkgMethodRecvVal(v *flowir.Value) (*types.Var, bool) {
	if v == nil || v.Kind != flowir.ValMethodVal || v.Selection == nil {
		return nil, false
	}
	if sel, isSel := ast.Unparen(v.Raw).(*ast.SelectorExpr); isSel && sel.Sel != nil {
		if _, hasInst := s.info.Instances[sel.Sel]; hasInst {
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
	if orig == nil || orig.Pkg() != s.p.Types || !s.hasDeclBody(orig) {
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
				if !(s.cfg.AllowScalarTypeParamProjection && s.isSeedStruct(recvSt)) {
					return nil, false
				}
				continue
			}
			if s.carriesRefOrIface(ta) {
				return nil, false
			}
		}
	}
	return rv, true
}

func (s *refConfinementSolver) isAllowedSeedStructCompositeLit(cl *ast.CompositeLit) bool {
	if cl == nil || !s.cfg.AllowCompositeLitIntoSeedStruct || (s.cfg.SeedStructOrigin == nil && len(s.capsuleStructs) == 0) {
		return false
	}
	lt := s.info.TypeOf(cl)
	if lt == nil {
		return false
	}
	lt = types.Unalias(lt)
	if ptr, isP := lt.(*types.Pointer); isP {
		lt = types.Unalias(ptr.Elem())
	}
	named, isN := lt.(*types.Named)
	if !isN || named.Obj() == nil || named.Obj().Pkg() != s.p.Types || named.Obj().Exported() {
		return false
	}
	if _, isSt := named.Underlying().(*types.Struct); !isSt {
		return false
	}
	return s.isSeedStruct(named)
}

func assignErasesTaint(dstT, srcT types.Type) bool {
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

func (s *refConfinementSolver) isPtrToSeedStruct(t types.Type) bool {
	if t == nil {
		return false
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	st, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && s.isSeedStruct(st)
}

func (s *refConfinementSolver) typeContainsPtrToSeedStruct(root types.Type) bool {
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
		if s.isPtrToSeedStruct(t) {
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

func (s *refConfinementSolver) seedStructTypeViolated(dstT, srcT types.Type) bool {
	if s.cfg.ForbidNonNilSeedStructPtrCompare {
		if typeMentionsSeedStruct(srcT, s.isSeedStruct) {
			if dstT == nil || syntaxutil.IsUnsafePointerType(dstT) {
				return true
			}
			if assignErasesSeedStruct(srcT, dstT, s.isSeedStruct) {
				return true
			}
		}
	}
	if len(s.propagatedStructs) > 0 && typeMentionsSeedStruct(srcT, s.isPropagatedStruct) {
		if dstT == nil || syntaxutil.IsUnsafePointerType(dstT) || assignErasesSeedStruct(srcT, dstT, s.isPropagatedStruct) {
			return true
		}
	}
	srcSt := syntaxutil.DerefNamedStruct(srcT)
	if !s.isSeedStruct(srcSt) && !s.isPropagatedStruct(srcSt) {
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
		return s.cfg.ForbidNonNilSeedStructPtrCompare || iface.NumMethods() == 0 || s.isPropagatedStruct(srcSt)
	}
	return !types.Identical(d, types.Unalias(srcT))
}

func (s *refConfinementSolver) walkAllBodies(visitBody func(b *flowir.Body, enclFunc *types.Func, inSyncAllowed bool) bool) bool {
	var walkRec func(b *flowir.Body, enclFunc *types.Func, inSyncAllowed bool) bool
	walkRec = func(b *flowir.Body, enclFunc *types.Func, inSyncAllowed bool) bool {
		if b == nil {
			return true
		}
		if !visitBody(b, enclFunc, inSyncAllowed) {
			return false
		}
		walkChildClosures := func(v *flowir.Value) bool {
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
					if cur.Closure != nil && !walkRec(cur.Closure, nil, !s.cfg.ForbidNonNilSeedStructPtrCompare) {
						cont = false
						return false
					}
				case flowir.ValCall:
					if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil && !walkRec(cur.IIFE, nil, !s.cfg.ForbidNonNilSeedStructPtrCompare) {
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
			if !op.ForEachValue(walkChildClosures) {
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

	for _, fd := range s.flowCache.FuncDecls {
		b := s.flowCache.FuncBody(fd)
		if b == nil {
			continue
		}
		var fn *types.Func
		if fd.Name != nil && !(fd.Recv == nil && fd.Name.Name == "init") {
			fn, _ = s.info.Defs[fd.Name].(*types.Func)
		}
		inSync := !s.cfg.ForbidNonNilSeedStructPtrCompare || (s.cfg.AllowSeedStructMutationInFunc != nil && fd == s.cfg.AllowSeedStructMutationInFunc)
		if !walkRec(b, fn, inSync) {
			return false
		}
	}
	for _, gd := range s.flowCache.GenDecls {
		b := s.flowCache.Body(gd)
		if b == nil {
			continue
		}
		if !walkRec(b, nil, !s.cfg.ForbidNonNilSeedStructPtrCompare) {
			return false
		}
	}
	return true
}
