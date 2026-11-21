package dynstate

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

// deriveOnceMemoTypes mechanically verifies named struct types in p that satisfy
// the once-populated immutable struct memoizer contract
// (REQ-closure-shared-dynamic-state-memo), returning the verified type facts and
// the top-level once.Do memo-field assignment nodes exempted from
// MutatedStructTypes in p.
func deriveOnceMemoTypes(
	ctx context.Context,
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	freshCache *freshstruct.FreshLocalsCache,
	pkgConf *packageConfinementSummary,
) ([]syntaxutil.OnceMemoTypeFact, map[ast.Node]bool) {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 || p.Module == nil || idx == nil || pkgConf == nil {
		return nil, nil
	}
	target := dynstateTarget(p)
	if !onceMemoPkgDirectivesClean(p) || !syntaxutil.IsTrueStdlibInPkg(p, "sync") {
		emitDischargeReject(ctx, target, "once_memo_type", target, "pkg_directives_or_sync_unclean", "")
		return nil, nil
	}

	if freshCache == nil {
		freshCache = freshstruct.NewFreshLocalsCache(p, idx)
	}
	pkgFresh := freshstruct.ComputePackageFreshConstructors(p, idx, nil)
	funcDecls := map[*types.Func]*ast.FuncDecl{}
	convertedStructs := collectConvertedTargetStructs(p)
	compositeLitsByStruct := map[*types.Named][]*ast.CompositeLit{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name != nil && fd.Body != nil {
				if fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok && fn != nil {
					funcDecls[fn] = fd
				}
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if named, okN := types.Unalias(p.TypesInfo.TypeOf(cl)).(*types.Named); okN && named.Obj() != nil && named.Obj().Pkg() == p.Types {
				compositeLitsByStruct[named] = append(compositeLitsByStruct[named], cl)
			}
			return true
		})
	}

	settledCache := map[*types.Var]bool{}
	settledChecked := map[*types.Var]bool{}
	isSettledConeGlobal := func(v *types.Var) bool {
		if v == nil || v.Pkg() != p.Types || v.IsField() || v.Parent() != p.Types.Scope() {
			return false
		}
		if settledChecked[v] {
			return settledCache[v]
		}
		settledChecked[v] = true
		ok := verifyReadOnlyCarrierFreeGlobalVar(audited, p, fc, idx, v, nil, true)
		settledCache[v] = ok
		return ok
	}

	var out []syntaxutil.OnceMemoTypeFact
	exemptNodes := map[ast.Node]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok || tn == nil || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok || named.TypeParams().Len() > 0 || convertedStructs[named] {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok || st.NumFields() < 2 {
			continue
		}
		fact, memoAssigns, ok := verifyOnceMemoStructType(
			audited,
			p,
			fc,
			idx,
			pkgConf,
			freshCache,
			pkgFresh,
			funcDecls,
			compositeLitsByStruct[named],
			isSettledConeGlobal,
			named,
			st,
		)
		if !ok || !fact.Valid() {
			if trace.Enabled(ctx, trace.DomainDynstate, target) {
				hasOnceField := false
				for fi := 0; fi < st.NumFields(); fi++ {
					if syntaxutil.IsNamedInPkg(st.Field(fi).Type(), "sync", "Once") {
						hasOnceField = true
						break
					}
				}
				if hasOnceField {
					emitDischargeRejectAt(ctx, p, target, "once_memo_type", p.Types.Path()+"."+tn.Name(), "struct_verification_failed", "", tn.Pos())
				}
			}
			continue
		}
		out = append(out, fact)
		for _, as := range memoAssigns {
			exemptNodes[as] = true
		}
	}
	slices.SortFunc(out, syntaxutil.OnceMemoTypeFact.Compare)
	if len(exemptNodes) == 0 {
		exemptNodes = nil
	}
	return out, exemptNodes
}

// deriveOnceMemoCandidates collects non-directive package-level *T variables in
// p initialized once at declaration by a direct constructor call with confined
// arguments and referenced intra-package solely as direct method call receivers
// (or direct-methods-only ReadOnlyVarAliases).
func deriveOnceMemoCandidates(
	ctx context.Context,
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	singleSubjectSet map[string]bool,
	exemptUseIdents map[*ast.Ident]bool,
) []syntaxutil.OnceMemoVarCandidate {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 || p.Module == nil || idx == nil {
		return nil
	}
	target := dynstateTarget(p)
	if !onceMemoConsumerPkgClean(p, idx) {
		emitDischargeReject(ctx, target, "once_memo_var", target, "pkg_directives_or_cgo_unclean", "")
		return nil
	}
	var out []syntaxutil.OnceMemoVarCandidate
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v == nil || v.IsField() || idx.DefCounts[v] != 1 {
			continue
		}
		if !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			continue
		}
		varKey := syntaxutil.DynamicVarKey(v)
		if singleSubjectSet[varKey] || hasVarGofreshDirective(idx, v) {
			continue
		}
		ptr, ok := types.Unalias(v.Type()).(*types.Pointer)
		if !ok {
			continue
		}
		if _, isElemPtr := types.Unalias(ptr.Elem()).(*types.Pointer); isElemPtr {
			continue
		}
		tRef, tNamed, tSt, ok := syntaxutil.TypeRefOfStructFull(ptr.Elem())
		if !ok || tNamed == nil || tNamed.TypeArgs().Len() > 0 || tSt == nil || tSt.NumFields() == 0 || !tRef.Valid() {
			continue
		}
		vs := idx.VarSpecs[v]
		if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
			continue
		}
		call, ok := ast.Unparen(vs.Values[0]).(*ast.CallExpr)
		if !ok || call.Ellipsis.IsValid() {
			continue
		}
		ctorFn := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
		if ctorFn == nil || ctorFn.Origin() != ctorFn || ctorFn.Pkg() == nil || ctorFn.Pkg().Path() != tRef.Pkg {
			continue
		}
		ctorSig, ok := ctorFn.Type().(*types.Signature)
		if !ok || ctorSig.Recv() != nil || ctorSig.TypeParams().Len() > 0 {
			continue
		}
		ctorKey := syntaxutil.FuncKey{Pkg: tRef.Pkg, Name: ctorFn.Name()}
		if !ctorKey.Valid() {
			continue
		}
		argsOK := true
		for _, arg := range call.Args {
			if !verifyOnceMemoCtorCallArg(audited, p, fc, idx, arg) {
				argsOK = false
				break
			}
		}
		if !argsOK {
			if trace.Enabled(ctx, trace.DomainDynstate, target) {
				emitDischargeRejectAt(ctx, p, target, "once_memo_var", varKey, "ctor_arg_rejected", ctorKey.Display(), call.Pos())
			}
			continue
		}
		if fc.varHasExplicitWriteOrAddr(p, v) || !allIntraPkgVarUsesAreDirectMethodCalls(p, idx, v, exemptUseIdents) {
			if trace.Enabled(ctx, trace.DomainDynstate, target) {
				emitDischargeRejectAt(ctx, p, target, "once_memo_var", varKey, "non_method_or_mutating_var_use", ctorKey.Display(), v.Pos())
			}
			continue
		}
		cand := syntaxutil.OnceMemoVarCandidate{
			Key:         varKey,
			Type:        tRef,
			Constructor: ctorKey,
		}
		if cand.Valid() {
			out = append(out, cand)
		}
	}
	slices.SortFunc(out, syntaxutil.OnceMemoVarCandidate.Compare)
	return out
}

func onceMemoBaseDirectivesClean(p *packages.Package) (hasUnsafeImport bool, ok bool) {
	if len(p.OtherFiles) > 0 {
		return false, false
	}
	if len(p.CompiledGoFiles) > 0 && len(p.CompiledGoFiles) != len(p.GoFiles) {
		return false, false
	}
	if p.Imports["C"] != nil || p.Imports["runtime/cgo"] != nil {
		return false, false
	}
	if p.Imports["unsafe"] != nil {
		hasUnsafeImport = true
	}
	for _, file := range p.Syntax {
		for _, imp := range file.Imports {
			if imp.Path == nil {
				continue
			}
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "C" || path == "runtime/cgo" {
				return false, false
			}
			if path == "unsafe" {
				hasUnsafeImport = true
			}
		}
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if strings.HasPrefix(c.Text, "//go:linkname") || strings.HasPrefix(c.Text, "/*go:linkname") {
					return false, false
				}
			}
		}
	}
	return hasUnsafeImport, true
}

func onceMemoPkgDirectivesClean(p *packages.Package) bool {
	hasUnsafe, ok := onceMemoBaseDirectivesClean(p)
	return ok && !hasUnsafe
}

func onceMemoConsumerPkgClean(p *packages.Package, idx *refconfine.PkgIndex) bool {
	hasUnsafe, ok := onceMemoBaseDirectivesClean(p)
	if !ok {
		return false
	}
	if !hasUnsafe {
		return true
	}
	return consumerUnsafeUsesConfined(p, idx)
}

func consumerUnsafeUsesConfined(p *packages.Package, idx *refconfine.PkgIndex) bool {
	if p == nil || p.TypesInfo == nil || idx == nil {
		return false
	}
	for _, tv := range p.TypesInfo.Types {
		if tv.Type != nil && syntaxutil.IsUnsafePointerType(tv.Type) {
			return false
		}
	}
	stringDataCalls := map[*ast.CallExpr]bool{}
	for ident, obj := range p.TypesInfo.Uses {
		switch u := obj.(type) {
		case *types.TypeName:
			if u.Pkg() != nil && u.Pkg().Path() == "unsafe" {
				return false
			}
		case *types.Builtin:
			switch u.Name() {
			case "Sizeof", "Alignof", "Offsetof":
				continue
			case "StringData":
				var funExpr ast.Expr = ident
				if sel, isSel := idx.ParentMap[ident].(*ast.SelectorExpr); isSel && sel.Sel == ident && p.TypesInfo.Selections[sel] == nil {
					funExpr = sel
				}
				call, isCall := idx.ParentUnparen(funExpr).(*ast.CallExpr)
				if !isCall || ast.Unparen(call.Fun) != funExpr || len(call.Args) != 1 || call.Ellipsis.IsValid() {
					return false
				}
				stringDataCalls[call] = true
			case "Add", "Slice", "SliceData", "String":
				return false
			}
		}
	}
	if len(stringDataCalls) == 0 {
		return true
	}
	return refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
		Index:                         idx,
		AllowReturnFromUnexportedFunc: false,
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			call, ok := ast.Unparen(expr).(*ast.CallExpr)
			if !ok || !stringDataCalls[call] {
				return false, false
			}
			return true, true
		},
	})
}

func hasVarGofreshDirective(idx *refconfine.PkgIndex, v *types.Var) bool {
	if idx == nil || v == nil {
		return false
	}
	vs := idx.VarSpecs[v]
	if vs != nil {
		if syntaxutil.HasDirective(vs.Doc, "//gofresh:pure") || syntaxutil.HasDirective(vs.Doc, "//gofresh:single-subject") {
			return true
		}
	}
	if gd := idx.VarGenDecls[v]; gd != nil {
		if syntaxutil.HasDirective(gd.Doc, "//gofresh:pure") || syntaxutil.HasDirective(gd.Doc, "//gofresh:single-subject") {
			return true
		}
	}
	return false
}

func collectConvertedTargetStructs(p *packages.Package) map[*types.Named]bool {
	out := map[*types.Named]bool{}
	markReach := func(t types.Type) {
		seen := map[types.Type]bool{}
		var walk func(cur types.Type)
		walk = func(cur types.Type) {
			if cur == nil {
				return
			}
			cur = types.Unalias(cur)
			if seen[cur] {
				return
			}
			seen[cur] = true
			if named, ok := cur.(*types.Named); ok {
				if _, isSt := named.Underlying().(*types.Struct); isSt {
					out[named.Origin()] = true
				}
			}
			switch u := cur.Underlying().(type) {
			case *types.Pointer:
				walk(u.Elem())
			case *types.Array:
				walk(u.Elem())
			case *types.Slice:
				walk(u.Elem())
			case *types.Struct:
				for i := 0; i < u.NumFields(); i++ {
					walk(u.Field(i).Type())
				}
			}
		}
		walk(t)
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
				return true
			}
			tv := p.TypesInfo.Types[ast.Unparen(call.Fun)]
			if !tv.IsType() || tv.Type == nil {
				return true
			}
			if syntaxutil.IsNilIdent(p.TypesInfo, call.Args[0]) {
				return true
			}
			dstT := types.Unalias(tv.Type)
			srcT := types.Unalias(p.TypesInfo.TypeOf(call.Args[0]))
			if srcT != nil && !types.Identical(dstT, srcT) {
				markReach(dstT)
				markReach(srcT)
			}
			return true
		})
	}
	return out
}

func verifyOnceMemoStructType(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	pkgConf *packageConfinementSummary,
	freshCache *freshstruct.FreshLocalsCache,
	pkgFresh *freshstruct.PkgFreshConstructors,
	funcDecls map[*types.Func]*ast.FuncDecl,
	structLits []*ast.CompositeLit,
	isSettledConeGlobal func(*types.Var) bool,
	named *types.Named,
	st *types.Struct,
) (syntaxutil.OnceMemoTypeFact, []*ast.AssignStmt, bool) {
	var zero syntaxutil.OnceMemoTypeFact
	tRef := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: named.Obj().Name()}
	if !tRef.Valid() {
		return zero, nil, false
	}
	// Forbid value-receiver methods so method calls on T or *T never value-copy T.once.
	if types.NewMethodSet(named).Len() != 0 {
		return zero, nil, false
	}

	var onceField *types.Var
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Exported() || f.Embedded() {
			return zero, nil, false
		}
		if syntaxutil.IsNamedInPkg(f.Type(), "sync", "Once") {
			if onceField != nil {
				return zero, nil, false
			}
			onceField = f
			continue
		}
		if typeReachesNamedOrSyncOnce(f.Type(), named) {
			return zero, nil, false
		}
	}
	if onceField == nil {
		return zero, nil, false
	}

	// Verify onceField is referenced solely by one recv.once.Do(func() { ... }) in getterFD.
	onceUses := idx.UsesOf[onceField]
	if len(onceUses) != 1 {
		return zero, nil, false
	}
	getterFD, getterRecv, doStmt, doLit, ok := matchOnceMemoGetterDoCall(p, idx, named, onceUses[0])
	if !ok {
		return zero, nil, false
	}

	// Extract memoFields written at top level of doLit.Body.
	memoFields, memoAssigns, memoRHSByField, ok := extractOnceMemoFields(p, fc, getterRecv, onceField, doLit)
	if !ok || len(memoFields) == 0 {
		return zero, nil, false
	}
	if !verifyOnceMemoFieldUsesInGetter(p, idx, getterFD, getterRecv, doStmt, doLit, memoFields, memoAssigns) {
		return zero, nil, false
	}

	inputFields := map[*types.Var]bool{}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f == onceField || memoFields[f] {
			continue
		}
		if refconfine.TypeMayCarryUnknownDynamic(audited, f.Type()) || refconfine.TypeCarriesSignature(f.Type()) {
			return zero, nil, false
		}
		inputFields[f] = true
	}

	// Check every composite literal of T in p.Syntax and ensure inputFields are never mutated/addressed.
	for _, cl := range structLits {
		for _, elt := range cl.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return zero, nil, false
			}
			kid, isID := ast.Unparen(kv.Key).(*ast.Ident)
			if !isID {
				return zero, nil, false
			}
			fld, _ := p.TypesInfo.Uses[kid].(*types.Var)
			if fld == nil || !inputFields[fld] {
				return zero, nil, false
			}
		}
	}
	for inf := range inputFields {
		for _, uid := range idx.UsesOf[inf] {
			if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
				continue
			}
			sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
			if !isSel || sel.Sel != uid || refconfine.ExprPrefixIsWrittenOrAddrTaken(p, idx, sel) {
				return zero, nil, false
			}
		}
	}

	// Collect verified constructors of *T in p.
	var constructors []syntaxutil.FuncKey
	for fn, fd := range funcDecls {
		if fd.Recv != nil || fd.Name == nil || fd.Name.Name == "init" || fn.Origin() != fn {
			continue
		}
		sig, okSig := fn.Type().(*types.Signature)
		if !okSig || sig.TypeParams().Len() > 0 || sig.Results().Len() != 1 {
			continue
		}
		if !syntaxutil.IsPtrToNamed(sig.Results().At(0).Type(), named) {
			continue
		}
		if verifyOnceMemoConstructor(audited, p, fc, idx, pkgFresh, fd, sig, named, inputFields) {
			ck := syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: fn.Name()}
			if ck.Valid() {
				constructors = append(constructors, ck)
			}
		}
	}
	if len(constructors) == 0 {
		return zero, nil, false
	}
	slices.SortFunc(constructors, syntaxutil.FuncKey.Compare)

	// Verify reachable type closure of memoFields & getter results, GuardTypes, and unexported ref fields.
	getterFn, _ := p.TypesInfo.Defs[getterFD.Name].(*types.Func)
	if getterFn == nil {
		return zero, nil, false
	}
	guardTypes, guardSet, unexpRefStructs, needsErrorProof, ok := verifyOnceMemoResultClosure(
		p,
		idx,
		freshCache,
		pkgFresh,
		funcDecls,
		named,
		tRef,
		getterFD,
		memoFields,
		memoRHSByField,
	)
	if !ok {
		return zero, nil, false
	}

	// Verify doLit's pure deterministic compute cone and error origins.
	inputParamDeps := map[syntaxutil.ParamKey]bool{}
	if !verifyOnceMemoComputeCone(
		audited,
		p,
		fc,
		idx,
		pkgConf,
		funcDecls,
		isSettledConeGlobal,
		named,
		getterRecv,
		inputFields,
		memoFields,
		memoAssigns,
		doLit,
		needsErrorProof,
		inputParamDeps,
	) {
		return zero, nil, false
	}

	// Verify receiver confinement across all methods on *T, and pure deterministic
	// cone + guarded/fresh result closure across all sibling methods on *T.
	ptrMSet := types.NewMethodSet(types.NewPointer(named))
	if ptrMSet.Len() == 0 {
		return zero, nil, false
	}
	ptrMethodSet := make(map[*types.Func]*ast.FuncDecl, ptrMSet.Len())
	for i := 0; i < ptrMSet.Len(); i++ {
		msel := ptrMSet.At(i)
		if len(msel.Index()) != 1 {
			return zero, nil, false
		}
		mfn, okFn := msel.Obj().(*types.Func)
		if !okFn || mfn == nil || mfn.Origin() != mfn || mfn.Pkg() != p.Types {
			return zero, nil, false
		}
		mfd := funcDecls[mfn]
		if mfd == nil || mfd.Body == nil {
			return zero, nil, false
		}
		ptrMethodSet[mfn] = mfd
	}
	for i := 0; i < ptrMSet.Len(); i++ {
		mfn := ptrMSet.At(i).Obj().(*types.Func)
		mfd := ptrMethodSet[mfn]
		if !verifyOnceMemoMethodRecvConfinement(
			audited,
			p,
			fc,
			pkgConf,
			named,
			mfn,
			mfd,
			mfd == getterFD,
			doStmt,
			doLit,
			onceField,
			memoFields,
			inputFields,
			inputParamDeps,
		) {
			return zero, nil, false
		}
		if mfd != getterFD {
			if !verifyOnceMemoSiblingMethod(
				audited,
				p,
				fc,
				idx,
				pkgFresh,
				funcDecls,
				isSettledConeGlobal,
				named,
				getterFn,
				ptrMethodSet,
				guardSet,
				unexpRefStructs,
				mfn,
				mfd,
			) {
				return zero, nil, false
			}
		}
	}

	var depSlice []syntaxutil.ParamKey
	if len(inputParamDeps) > 0 {
		depSlice = make([]syntaxutil.ParamKey, 0, len(inputParamDeps))
		for pk := range inputParamDeps {
			depSlice = append(depSlice, pk)
		}
		slices.SortFunc(depSlice, syntaxutil.ParamKey.Compare)
	}
	return syntaxutil.OnceMemoTypeFact{
		Type:           tRef,
		Constructors:   constructors,
		GuardTypes:     guardTypes,
		InputParamDeps: depSlice,
	}, memoAssigns, true
}

func matchOnceMemoGetterDoCall(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	named *types.Named,
	onceIdent *ast.Ident,
) (*ast.FuncDecl, *types.Var, *ast.ExprStmt, *ast.FuncLit, bool) {
	onceSel, ok := idx.ParentUnparen(onceIdent).(*ast.SelectorExpr)
	if !ok || onceSel.Sel != onceIdent {
		return nil, nil, nil, nil, false
	}
	recvIdent, ok := ast.Unparen(onceSel.X).(*ast.Ident)
	if !ok {
		return nil, nil, nil, nil, false
	}
	recvVar, _ := p.TypesInfo.Uses[recvIdent].(*types.Var)
	if recvVar == nil || !syntaxutil.IsPtrToNamed(recvVar.Type(), named) {
		return nil, nil, nil, nil, false
	}
	doSel, ok := idx.ParentUnparen(onceSel).(*ast.SelectorExpr)
	if !ok || ast.Unparen(doSel.X) != onceSel || doSel.Sel.Name != "Do" {
		return nil, nil, nil, nil, false
	}
	doFn, _ := p.TypesInfo.Uses[doSel.Sel].(*types.Func)
	if doFn == nil || doFn.Pkg() == nil || doFn.Pkg().Path() != "sync" || doFn.Name() != "Do" {
		return nil, nil, nil, nil, false
	}
	doCall, ok := idx.ParentUnparen(doSel).(*ast.CallExpr)
	if !ok || ast.Unparen(doCall.Fun) != doSel || len(doCall.Args) != 1 || doCall.Ellipsis.IsValid() {
		return nil, nil, nil, nil, false
	}
	flowCache := idx.FlowCache(p)
	doLit, ok := ast.Unparen(doCall.Args[0]).(*ast.FuncLit)
	if !ok || doLit.Body == nil || doLit.Type == nil ||
		(doLit.Type.Params != nil && len(doLit.Type.Params.List) > 0) ||
		(doLit.Type.Results != nil && len(doLit.Type.Results.List) > 0) ||
		flowCache == nil || flowCache.LitBody(doLit) == nil || flowCache.LitBody(doLit).HasGoto {
		return nil, nil, nil, nil, false
	}
	doStmt, ok := idx.ParentUnparen(doCall).(*ast.ExprStmt)
	if !ok {
		return nil, nil, nil, nil, false
	}
	getterFD, ok := idx.ParentMap[idx.ParentMap[doStmt]].(*ast.FuncDecl)
	if !ok || getterFD.Body == nil || getterFD.Type == nil || idx.ParentMap[doStmt] != getterFD.Body ||
		getterFD.Recv == nil || len(getterFD.Recv.List) != 1 || len(getterFD.Recv.List[0].Names) != 1 ||
		p.TypesInfo.Defs[getterFD.Recv.List[0].Names[0]] != recvVar ||
		flowCache.FuncBody(getterFD) == nil || flowCache.FuncBody(getterFD).HasGoto {
		return nil, nil, nil, nil, false
	}
	if getterFD.Type.Results != nil {
		for _, rf := range getterFD.Type.Results.List {
			if len(rf.Names) > 0 {
				return nil, nil, nil, nil, false
			}
		}
	}
	if len(getterFD.Body.List) != 2 || getterFD.Body.List[0] != ast.Stmt(doStmt) {
		return nil, nil, nil, nil, false
	}
	if _, isRet := getterFD.Body.List[1].(*ast.ReturnStmt); !isRet {
		return nil, nil, nil, nil, false
	}
	return getterFD, recvVar, doStmt, doLit, true
}

func extractOnceMemoFields(
	p *packages.Package,
	fc *pkgFlowCache,
	getterRecv *types.Var,
	onceField *types.Var,
	doLit *ast.FuncLit,
) (map[*types.Var]bool, []*ast.AssignStmt, map[*types.Var][]ast.Expr, bool) {
	doIR := fc.litBody(p, doLit)
	if doIR == nil || doLit == nil || doLit.Body == nil {
		return nil, nil, nil, false
	}
	topStmts := map[ast.Node]bool{}
	for _, st := range doLit.Body.List {
		if as, ok := st.(*ast.AssignStmt); ok {
			topStmts[as] = true
		}
	}

	memoFields := map[*types.Var]bool{}
	var memoAssigns []*ast.AssignStmt
	rhsByField := map[*types.Var][]ast.Expr{}
	topAssignSet := map[*ast.AssignStmt]bool{}

	placeTouchesGetterRecv := func(pl flowir.Place) bool {
		if pl.Obj == getterRecv {
			return true
		}
		hit := false
		flowir.ForEachPlaceRootVar(pl, func(rv *types.Var) {
			if rv == getterRecv {
				hit = true
			}
		})
		return hit
	}

	for i := range doIR.Ops {
		op := &doIR.Ops[i]
		if op.Kind != flowir.OpAssign || !topStmts[op.StmtAST] {
			continue
		}
		touchesRecv := false
		for _, dst := range op.Dsts {
			if placeTouchesGetterRecv(dst) {
				touchesRecv = true
				break
			}
		}
		if !touchesRecv {
			continue
		}
		as, ok := op.StmtAST.(*ast.AssignStmt)
		if !ok || as.Tok != token.ASSIGN || (op.AssignKind != flowir.AssignPlain && op.AssignKind != flowir.AssignMulti) {
			return nil, nil, nil, false
		}
		topAssignSet[as] = true
		memoAssigns = append(memoAssigns, as)
		for di, dst := range op.Dsts {
			if dst.Obj != getterRecv || len(dst.Projs) != 1 || dst.Projs[0].Kind != flowir.ProjField {
				return nil, nil, nil, false
			}
			fld := dst.Projs[0].Field
			if fld == nil || !fld.IsField() || fld == onceField {
				return nil, nil, nil, false
			}
			memoFields[fld] = true
			if op.AssignKind == flowir.AssignPlain {
				if di >= len(op.Srcs) || op.Srcs[di] == nil || op.Srcs[di].Raw == nil {
					return nil, nil, nil, false
				}
				rhsByField[fld] = append(rhsByField[fld], op.Srcs[di].Raw)
			} else {
				if len(op.Srcs) != 1 || op.Srcs[0] == nil || op.Srcs[0].Raw == nil {
					return nil, nil, nil, false
				}
				rhsByField[fld] = append(rhsByField[fld], op.Srcs[0].Raw)
			}
		}
	}

	// Ensure no non-top-level operation writes to getterRecv and no value inside doLit reads memoFields.
	bad := false
	placeReadsMemoField := func(pl flowir.Place) bool {
		for _, pr := range pl.Projs {
			if pr.Kind == flowir.ProjField && pr.Field != nil && memoFields[pr.Field] {
				return true
			}
		}
		return false
	}
	var scanBody func(b *flowir.Body)
	scanVal := func(v *flowir.Value) {
		if v == nil || bad {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			if bad {
				return false
			}
			switch cur.Kind {
			case flowir.ValPlace:
				if placeReadsMemoField(cur.Place) {
					bad = true
					return false
				}
			case flowir.ValAddrOf:
				if placeReadsMemoField(cur.AddrPlace) {
					bad = true
					return false
				}
			case flowir.ValMethodVal:
				if cur.HasRecvPlace && placeReadsMemoField(cur.RecvPlace) {
					bad = true
					return false
				}
			case flowir.ValCall:
				if cur.HasRecvPlace && placeReadsMemoField(cur.RecvPlace) {
					bad = true
					return false
				}
				if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil {
					scanBody(cur.IIFE)
				}
			case flowir.ValMakeClosure:
				if cur.Closure != nil {
					scanBody(cur.Closure)
				}
			}
			return !bad
		})
	}
	scanBody = func(b *flowir.Body) {
		if b == nil || bad {
			return
		}
		for i := range b.Ops {
			op := &b.Ops[i]
			if op.Kind == flowir.OpAssign {
				if as, isAS := op.StmtAST.(*ast.AssignStmt); isAS && topAssignSet[as] {
					for _, src := range op.Srcs {
						scanVal(src)
					}
					continue
				}
				for _, dst := range op.Dsts {
					if placeTouchesGetterRecv(dst) || placeReadsMemoField(dst) {
						bad = true
						return
					}
				}
			}
			op.ForEachValue(func(v *flowir.Value) bool {
				scanVal(v)
				return !bad
			})
			if !bad && op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
				scanBody(op.RangeBody)
			}
		}
	}
	scanBody(doIR)
	if bad {
		return nil, nil, nil, false
	}
	return memoFields, memoAssigns, rhsByField, true
}

func verifyOnceMemoFieldUsesInGetter(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	getterFD *ast.FuncDecl,
	getterRecv *types.Var,
	doStmt *ast.ExprStmt,
	doLit *ast.FuncLit,
	memoFields map[*types.Var]bool,
	memoAssigns []*ast.AssignStmt,
) bool {
	if len(getterFD.Body.List) != 2 || getterFD.Body.List[0] != ast.Stmt(doStmt) {
		return false
	}
	retStmt, isRet := getterFD.Body.List[1].(*ast.ReturnStmt)
	if !isRet {
		return false
	}
	getterFn, _ := p.TypesInfo.Defs[getterFD.Name].(*types.Func)
	if getterFn == nil {
		return false
	}
	getterSig, _ := getterFn.Type().(*types.Signature)
	if getterSig == nil || len(retStmt.Results) == 0 || len(retStmt.Results) != getterSig.Results().Len() {
		return false
	}
	allowedRetIdents := map[*ast.Ident]bool{}
	returnedMemoFields := map[*types.Var]bool{}
	for _, r := range retStmt.Results {
		sel, isSel := ast.Unparen(r).(*ast.SelectorExpr)
		if !isSel || refconfine.ExprPrefixIsWrittenOrAddrTaken(p, idx, sel) {
			return false
		}
		rid, isRID := ast.Unparen(sel.X).(*ast.Ident)
		if !isRID || p.TypesInfo.Uses[rid] != getterRecv {
			return false
		}
		fld, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
		if fld == nil || !memoFields[fld] {
			return false
		}
		allowedRetIdents[sel.Sel] = true
		returnedMemoFields[fld] = true
	}
	for mf := range memoFields {
		if !returnedMemoFields[mf] {
			return false
		}
	}

	allowedLHS := map[*ast.Ident]bool{}
	for _, as := range memoAssigns {
		for _, lhs := range as.Lhs {
			if sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok {
				allowedLHS[sel.Sel] = true
			}
		}
	}
	for mf := range memoFields {
		for _, uid := range idx.UsesOf[mf] {
			if allowedLHS[uid] || allowedRetIdents[uid] {
				continue
			}
			if uid.Pos() >= doLit.Pos() && uid.Pos() <= doLit.End() {
				return false
			}
			return false
		}
	}
	return true
}
