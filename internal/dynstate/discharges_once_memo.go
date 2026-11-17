package dynstate

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// deriveOnceMemoTypes mechanically verifies named struct types in p that satisfy
// the once-populated immutable struct memoizer contract
// (REQ-closure-shared-dynamic-state-memo), returning the verified type facts and
// the top-level once.Do memo-field assignment nodes exempted from
// MutatedStructTypes in p.
func deriveOnceMemoTypes(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	pkgConf *packageConfinementSummary,
) ([]syntaxutil.OnceMemoTypeFact, map[ast.Node]bool) {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 || p.Module == nil || idx == nil || pkgConf == nil {
		return nil, nil
	}
	if !onceMemoPkgDirectivesClean(p) {
		return nil, nil
	}

	freshCache := freshstruct.NewFreshLocalsCache(p, idx)
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
// arguments and referenced intra-package solely as direct method call receivers.
func deriveOnceMemoCandidates(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	singleSubjectSet map[string]bool,
) []syntaxutil.OnceMemoVarCandidate {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 || p.Module == nil || idx == nil {
		return nil
	}
	if !onceMemoConsumerPkgClean(p, idx) {
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
			continue
		}
		if fc.varHasExplicitWriteOrAddr(p, v) || !allIntraPkgVarUsesAreDirectMethodCalls(p, idx, v) {
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
	memoFields, memoAssigns, memoRHSByField, ok := extractOnceMemoFields(p, getterRecv, onceField, doLit)
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
	doLit, ok := ast.Unparen(doCall.Args[0]).(*ast.FuncLit)
	if !ok || doLit.Body == nil || doLit.Type == nil ||
		(doLit.Type.Params != nil && len(doLit.Type.Params.List) > 0) ||
		(doLit.Type.Results != nil && len(doLit.Type.Results.List) > 0) ||
		funcBodyHasGotoOutsideClosures(doLit.Body) {
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
		funcBodyHasGotoOutsideClosures(getterFD.Body) {
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
	getterRecv *types.Var,
	onceField *types.Var,
	doLit *ast.FuncLit,
) (map[*types.Var]bool, []*ast.AssignStmt, map[*types.Var][]ast.Expr, bool) {
	memoFields := map[*types.Var]bool{}
	var memoAssigns []*ast.AssignStmt
	rhsByField := map[*types.Var][]ast.Expr{}
	topAssignSet := map[*ast.AssignStmt]bool{}

	for _, stmt := range doLit.Body.List {
		as, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}
		touchesRecv := false
		for _, lhs := range as.Lhs {
			if exprMentionsVar(p.TypesInfo, lhs, getterRecv) {
				touchesRecv = true
				break
			}
		}
		if !touchesRecv {
			continue
		}
		if as.Tok != token.ASSIGN {
			return nil, nil, nil, false
		}
		topAssignSet[as] = true
		memoAssigns = append(memoAssigns, as)
		for i, lhs := range as.Lhs {
			sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
			if !isSel {
				return nil, nil, nil, false
			}
			rid, isRID := ast.Unparen(sel.X).(*ast.Ident)
			if !isRID || p.TypesInfo.Uses[rid] != getterRecv {
				return nil, nil, nil, false
			}
			fld, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
			if fld == nil || !fld.IsField() || fld == onceField {
				return nil, nil, nil, false
			}
			memoFields[fld] = true
			if len(as.Lhs) == len(as.Rhs) {
				rhsByField[fld] = append(rhsByField[fld], as.Rhs[i])
			} else if len(as.Rhs) == 1 {
				rhsByField[fld] = append(rhsByField[fld], as.Rhs[0])
			} else {
				return nil, nil, nil, false
			}
		}
	}

	// Ensure no nested statement inside doLit.Body writes to getterRecv or reads memoFields.
	bad := false
	ast.Inspect(doLit.Body, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			if topAssignSet[x] {
				for _, rhs := range x.Rhs {
					if exprMentionsAnyVar(p.TypesInfo, rhs, memoFields) {
						bad = true
						return false
					}
				}
				return false
			}
			for _, lhs := range x.Lhs {
				if exprMentionsVar(p.TypesInfo, lhs, getterRecv) {
					bad = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if exprMentionsVar(p.TypesInfo, x.X, getterRecv) {
				bad = true
				return false
			}
		case *ast.Ident:
			if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && memoFields[v] {
				bad = true
				return false
			}
		}
		return true
	})
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

func verifyOnceMemoConstructor(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	pkgFresh *freshstruct.PkgFreshConstructors,
	fd *ast.FuncDecl,
	sig *types.Signature,
	named *types.Named,
	inputFields map[*types.Var]bool,
) bool {
	if !pkgFresh.ReturnsFreshAllocation(fd) || funcBodyHasGotoOutsideClosures(fd.Body) {
		return false
	}
	paramSet := map[*types.Var]bool{}
	mutableParams := map[*types.Var]bool{}
	for i := 0; i < sig.Params().Len(); i++ {
		pv := sig.Params().At(i)
		if refconfine.TypeMayCarryUnknownDynamic(audited, pv.Type()) ||
			refconfine.TypeCarriesSignature(pv.Type()) ||
			typeReachesNamedOrSyncOnce(pv.Type(), named) {
			return false
		}
		paramSet[pv] = true
		if refconfine.TypeCarriesMutableRef(pv.Type()) {
			mutableParams[pv] = true
		}
	}

	b := fc.funcBody(p, fd)
	if b == nil {
		return false
	}
	var matchAllowedInputInit func(val *flowir.Value) (*ast.Ident, bool)
	matchAllowedInputInit = func(val *flowir.Value) (*ast.Ident, bool) {
		if val == nil {
			return nil, false
		}
		switch val.Kind {
		case flowir.ValScalarLitOrConst:
			return nil, true
		case flowir.ValPlace:
			if val.Place.Root == flowir.RootConstOrNil {
				return nil, true
			}
			if !val.Place.IsBareVar() || !paramSet[val.Place.Obj] {
				return nil, false
			}
			if mutableParams[val.Place.Obj] {
				id, ok := ast.Unparen(val.Place.Raw).(*ast.Ident)
				return id, ok
			}
			return nil, true
		case flowir.ValConvert:
			if val.IsTypeAssert || val.Arg == nil {
				return nil, false
			}
			if !refconfine.TypeCarriesMutableRef(val.Arg.Type) && !refconfine.TypeCarriesMutableRef(val.Type) {
				return matchAllowedInputInit(val.Arg)
			}
			if (syntaxutil.IsByteSliceType(val.Type) && isBasicStringType(val.Arg.Type)) ||
				(isBasicStringType(val.Type) && syntaxutil.IsByteSliceType(val.Arg.Type)) {
				return matchAllowedInputInit(val.Arg)
			}
			return nil, false
		case flowir.ValCall:
			if val.CallKind == flowir.CallPlain && !val.IsMethodExprCall && val.CalleeFunc != nil && val.CalleeFunc.Pkg() != nil {
				pkgPath := val.CalleeFunc.Pkg().Path()
				if (pkgPath == "bytes" || pkgPath == "slices") && val.CalleeFunc.Name() == "Clone" && !val.Ellipsis && len(val.Args) == 1 {
					return matchAllowedInputInit(val.Args[0])
				}
			}
			if val.CallKind == flowir.CallBuiltin && val.BuiltinName == "append" && val.Ellipsis && len(val.Args) == 2 {
				if val.Args[0] != nil && syntaxutil.IsTypedNilSliceConv(p, val.Args[0].Raw) {
					return matchAllowedInputInit(val.Args[1])
				}
			}
		}
		return nil, false
	}

	allowedParamUses := map[*ast.Ident]bool{}
	checkCompositeInit := func(alloc *flowir.Value) bool {
		if alloc == nil || alloc.Kind != flowir.ValAllocFresh || alloc.AllocKind != flowir.AllocCompositeLit ||
			!syntaxutil.IsPtrToNamed(alloc.Type, named) {
			return false
		}
		for _, elt := range alloc.CompositeElts {
			if elt.Field == nil || !inputFields[elt.Field] {
				return false
			}
			id, ok := matchAllowedInputInit(elt.Value)
			if !ok {
				return false
			}
			if id != nil {
				allowedParamUses[id] = true
			}
		}
		return true
	}

	var ctorLocal *types.Var
	returnedDirectLit := false
	for i := range b.Ops {
		op := &b.Ops[i]
		switch op.Kind {
		case flowir.OpReturn:
			if len(op.Results) != 1 {
				return false
			}
			res := op.Results[0]
			if res.Kind == flowir.ValAllocFresh && res.AllocKind == flowir.AllocCompositeLit {
				if ctorLocal != nil || !checkCompositeInit(res) {
					return false
				}
				returnedDirectLit = true
				continue
			}
			if res.Kind == flowir.ValPlace && res.Place.IsBareVar() && res.Place.Root == flowir.RootLocal &&
				ctorLocal != nil && res.Place.Obj == ctorLocal {
				continue
			}
			return false
		case flowir.OpAssign:
			if op.AssignKind != flowir.AssignPlain || len(op.Dsts) != 1 || len(op.Srcs) != 1 {
				return false
			}
			dst := op.Dsts[0]
			src := op.Srcs[0]
			if dst.IsBareVar() && dst.Root == flowir.RootLocal && dst.Obj != nil {
				if returnedDirectLit || ctorLocal != nil || !checkCompositeInit(src) {
					return false
				}
				ctorLocal = dst.Obj
				continue
			}
			if dst.Root == flowir.RootLocal && ctorLocal != nil && dst.Obj == ctorLocal &&
				len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjField && inputFields[dst.Projs[0].Field] {
				id, ok := matchAllowedInputInit(src)
				if !ok {
					return false
				}
				if id != nil {
					allowedParamUses[id] = true
				}
				continue
			}
			return false
		default:
			return false
		}
	}

	// Every use of any mutable-reach parameter in C must be one of the allowed inputField initializers.
	for pv := range mutableParams {
		for _, uid := range idx.UsesOf[pv] {
			if !allowedParamUses[uid] {
				return false
			}
		}
	}
	return true
}

func verifyOnceMemoResultClosure(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshstruct.FreshLocalsCache,
	pkgFresh *freshstruct.PkgFreshConstructors,
	funcDecls map[*types.Func]*ast.FuncDecl,
	ownerNamed *types.Named,
	ownerRef syntaxutil.TypeRef,
	getterFD *ast.FuncDecl,
	memoFields map[*types.Var]bool,
	memoRHSByField map[*types.Var][]ast.Expr,
) ([]syntaxutil.TypeRef, map[syntaxutil.TypeRef]bool, map[*types.Named]bool, bool, bool) {
	guardSet := map[syntaxutil.TypeRef]bool{ownerRef: true}
	visitedStructs := map[*types.Named]bool{}
	unexpRefStructs := map[*types.Named]bool{}
	var unexportedRefFields []struct {
		owner *types.Named
		field *types.Var
	}
	needsErrorProof := false

	var checkExportedClosureType func(t types.Type, allowTopError bool) bool
	var checkReachableStruct func(sn *types.Named) bool

	checkReachableStruct = func(sn *types.Named) bool {
		if sn == nil || sn.Obj() == nil || sn.Obj().Pkg() == nil || sn.TypeArgs().Len() > 0 {
			return false
		}
		sn = sn.Origin()
		if sn == ownerNamed || syntaxutil.IsNamedInPkg(sn, "sync", "Once") {
			return false
		}
		st, ok := sn.Underlying().(*types.Struct)
		if !ok || st.NumFields() == 0 {
			return false
		}
		ref := syntaxutil.TypeRef{Pkg: sn.Obj().Pkg().Path(), Name: sn.Obj().Name()}
		if !ref.Valid() {
			return false
		}
		guardSet[ref] = true
		if visitedStructs[sn] {
			return true
		}
		visitedStructs[sn] = true

		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if typeReachesNamedOrSyncOnce(f.Type(), ownerNamed) {
				return false
			}
			if f.Exported() {
				if !checkExportedClosureType(f.Type(), false) {
					return false
				}
				continue
			}
			// Unexported fields require defining-package visibility to prove freshness + confinement.
			if sn.Obj().Pkg() != p.Types {
				return false
			}
			if !checkUnexportedClosureType(f.Type(), checkReachableStruct) {
				return false
			}
			if refconfine.TypeCarriesMutableRef(f.Type()) {
				unexpRefStructs[sn] = true
				unexportedRefFields = append(unexportedRefFields, struct {
					owner *types.Named
					field *types.Var
				}{owner: sn, field: f})
			}
		}
		return true
	}

	checkExportedClosureType = func(t types.Type, allowTopError bool) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if allowTopError && isUniverseErrorType(t) {
			needsErrorProof = true
			return true
		}
		if named, ok := t.(*types.Named); ok {
			if _, isSt := named.Underlying().(*types.Struct); isSt {
				return checkReachableStruct(named)
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Basic:
			return u.Kind() != types.UnsafePointer && u.Kind() != types.Uintptr && u.Kind() != types.Invalid
		case *types.Pointer:
			elemNamed, ok := types.Unalias(u.Elem()).(*types.Named)
			if !ok {
				return false
			}
			return checkReachableStruct(elemNamed)
		case *types.Slice:
			elemNamed, ok := types.Unalias(u.Elem()).(*types.Named)
			if !ok {
				return false
			}
			return checkReachableStruct(elemNamed)
		case *types.Array:
			if isScalarBasicType(u.Elem()) {
				return true
			}
			elemNamed, ok := types.Unalias(u.Elem()).(*types.Named)
			if !ok {
				return false
			}
			return checkReachableStruct(elemNamed)
		default:
			return false
		}
	}

	for mf := range memoFields {
		if !checkExportedClosureType(mf.Type(), true) {
			return nil, nil, nil, false, false
		}
	}
	if getterFn, ok := p.TypesInfo.Defs[getterFD.Name].(*types.Func); ok && getterFn != nil {
		if sig, okSig := getterFn.Type().(*types.Signature); okSig {
			for ri := 0; ri < sig.Results().Len(); ri++ {
				if !checkExportedClosureType(sig.Results().At(ri).Type(), true) {
					return nil, nil, nil, false, false
				}
			}
		}
	}

	// Prove every unexported reference/container field in T's reachable struct closure
	// is freshly constructed in each memo RHS compute cone AND read-only confined across p.
	for _, entry := range unexportedRefFields {
		uf := entry.field
		for mf, rhsList := range memoRHSByField {
			if !typeReachesStruct(mf.Type(), entry.owner) {
				continue
			}
			for _, rhs := range rhsList {
				call, isCall := ast.Unparen(rhs).(*ast.CallExpr)
				if !isCall {
					return nil, nil, nil, false, false
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
				if callee == nil || callee.Pkg() != p.Types {
					return nil, nil, nil, false, false
				}
				cfd := funcDecls[callee]
				if cfd == nil || !pkgFresh.ReturnsFreshAllocation(cfd) || !pkgFresh.IsFieldFreshInCone(cfd, uf) {
					return nil, nil, nil, false, false
				}
			}
		}

		readSels := map[*ast.SelectorExpr]bool{}
		for _, uid := range idx.UsesOf[uf] {
			if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
				continue
			}
			sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
			if !isSel || sel.Sel != uid {
				return nil, nil, nil, false, false
			}
			syncFD := idx.SyncEnclFuncDecl(sel)
			fresh, freshEsc := freshCache.Get(syncFD)
			if freshstruct.IsRootedAtFreshLocal(p, sel, fresh, freshEsc) || pkgFresh.IsFreshMutationTarget(syncFD, sel) {
				continue
			}
			if refconfine.ExprPrefixIsWrittenOrAddrTaken(p, idx, sel) {
				return nil, nil, nil, false, false
			}
			readSels[sel] = true
		}
		if len(readSels) > 0 {
			if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
				Index:                         idx,
				AllowReturnFromUnexportedFunc: false,
				SeedExpr: func(expr ast.Expr) (bool, bool) {
					sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
					if !isSel || !readSels[sel] {
						return false, false
					}
					return refconfine.IsDirectMutableRef(p.TypesInfo.TypeOf(sel)), true
				},
			}) {
				return nil, nil, nil, false, false
			}
		}
	}

	out := make([]syntaxutil.TypeRef, 0, len(guardSet))
	for ref := range guardSet {
		out = append(out, ref)
	}
	slices.SortFunc(out, func(a, b syntaxutil.TypeRef) int {
		if a.Key() < b.Key() {
			return -1
		}
		if a.Key() > b.Key() {
			return 1
		}
		return 0
	})
	return out, guardSet, unexpRefStructs, needsErrorProof, true
}

func checkUnexportedClosureType(t types.Type, checkStruct func(*types.Named) bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok {
		if _, isSt := named.Underlying().(*types.Struct); isSt {
			return checkStruct(named)
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() != types.UnsafePointer && u.Kind() != types.Invalid
	case *types.Pointer:
		if isScalarBasicType(u.Elem()) {
			return true
		}
		elemNamed, ok := types.Unalias(u.Elem()).(*types.Named)
		return ok && checkStruct(elemNamed)
	case *types.Slice:
		return checkUnexportedClosureType(u.Elem(), checkStruct)
	case *types.Array:
		return checkUnexportedClosureType(u.Elem(), checkStruct)
	case *types.Map:
		return isScalarBasicType(u.Key()) && checkUnexportedClosureType(u.Elem(), checkStruct)
	default:
		return false
	}
}

func verifyOnceMemoComputeCone(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	pkgConf *packageConfinementSummary,
	funcDecls map[*types.Func]*ast.FuncDecl,
	isSettledConeGlobal func(*types.Var) bool,
	ownerNamed *types.Named,
	getterRecv *types.Var,
	inputFields map[*types.Var]bool,
	memoFields map[*types.Var]bool,
	memoAssigns []*ast.AssignStmt,
	doLit *ast.FuncLit,
	needsErrorProof bool,
	inputParamDeps map[syntaxutil.ParamKey]bool,
) bool {
	coneFuncs := map[*types.Func]*ast.FuncDecl{}
	var queue []*ast.BlockStmt
	queue = append(queue, doLit.Body)

	localClosuresInBlock := func(blk *ast.BlockStmt) map[*types.Var]*ast.FuncLit {
		res := map[*types.Var]*ast.FuncLit{}
		ast.Inspect(blk, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || as.Tok != token.DEFINE || len(as.Lhs) != len(as.Rhs) {
				return true
			}
			for i, lhs := range as.Lhs {
				id, isID := ast.Unparen(lhs).(*ast.Ident)
				lit, isLit := ast.Unparen(as.Rhs[i]).(*ast.FuncLit)
				if !isID || !isLit {
					continue
				}
				lv, _ := p.TypesInfo.Defs[id].(*types.Var)
				if isConfinedDirectCallClosureVar(p, fc, idx, lv) {
					res[lv] = lit
				}
			}
			return true
		})
		return res
	}

	for len(queue) > 0 {
		blk := queue[0]
		queue = queue[1:]
		localClos := localClosuresInBlock(blk)
		okBlk := true
		ast.Inspect(blk, func(n ast.Node) bool {
			if !okBlk || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.GoStmt, *ast.DeferStmt, *ast.SendStmt, *ast.SelectStmt:
				okBlk = false
				return false
			case *ast.UnaryExpr:
				if x.Op == token.ARROW {
					okBlk = false
					return false
				}
			case *ast.RangeStmt:
				switch syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x.X)).(type) {
				case *types.Map, *types.Chan, *types.Signature:
					okBlk = false
					return false
				}
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && lookupAnyPkgScopeVar(p, x.Key) != nil) ||
						(x.Value != nil && lookupAnyPkgScopeVar(p, x.Value) != nil) {
						okBlk = false
						return false
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if lookupRootPkgScopeVarAnyPkg(p, lhs) != nil {
						okBlk = false
						return false
					}
				}
			case *ast.IncDecStmt:
				if lookupRootPkgScopeVarAnyPkg(p, x.X) != nil {
					okBlk = false
					return false
				}
			case *ast.BinaryExpr:
				if x.Op == token.EQL || x.Op == token.NEQ {
					if isPointerIdentityComparison(p.TypesInfo, x.X, x.Y) {
						okBlk = false
						return false
					}
				}
			case *ast.Ident:
				if gv, isV := p.TypesInfo.Uses[x].(*types.Var); isV && gv != nil && !gv.IsField() &&
					gv.Pkg() != nil && gv.Parent() == gv.Pkg().Scope() {
					if !isSettledConeGlobal(gv) {
						okBlk = false
						return false
					}
				}
				if !idx.CalleeIdents[x] {
					if fnObj, isFn := p.TypesInfo.Uses[x].(*types.Func); isFn && fnObj != nil {
						sig, okSig := fnObj.Type().(*types.Signature)
						if !okSig || sig.Recv() != nil || fnObj.Origin() != fnObj || fnObj.Pkg() == nil {
							okBlk = false
							return false
						}
						if fnObj.Pkg() == p.Types {
							cfd := funcDecls[fnObj]
							if cfd == nil || cfd.Body == nil || funcBodyHasGotoOutsideClosures(cfd.Body) {
								okBlk = false
								return false
							}
							if _, seen := coneFuncs[fnObj]; !seen {
								coneFuncs[fnObj] = cfd
								queue = append(queue, cfd.Body)
							}
						} else if !isPureDeterministicConeStdlibFuncValue(fnObj, sig) {
							okBlk = false
							return false
						}
					}
				}
			case *ast.FuncLit:
				isAllowedLocalClos := false
				for _, lc := range localClos {
					if lc == x {
						isAllowedLocalClos = true
						break
					}
				}
				if !isAllowedLocalClos {
					okBlk = false
					return false
				}
			case *ast.CallExpr:
				if tv := p.TypesInfo.Types[ast.Unparen(x.Fun)]; tv.IsType() {
					if syntaxutil.IsUnsafePointerType(tv.Type) {
						okBlk = false
						return false
					}
					return true
				}
				if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(x.Fun)); b != nil {
					switch b.Name() {
					case "recover", "close", "println", "print":
						okBlk = false
						return false
					case "delete", "clear", "copy", "append":
						if len(x.Args) > 0 && lookupRootPkgScopeVarAnyPkg(p, x.Args[0]) != nil {
							okBlk = false
							return false
						}
					case "panic":
						if len(x.Args) != 1 {
							okBlk = false
							return false
						}
						pt := p.TypesInfo.TypeOf(x.Args[0])
						if isUniverseErrorType(pt) {
							needsErrorProof = true
						} else if !isScalarBasicType(pt) {
							okBlk = false
							return false
						}
					}
					return true
				}
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
					if lv, isV := p.TypesInfo.Uses[cid].(*types.Var); isV && localClos[lv] != nil {
						return true
					}
				}
				if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
					if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil &&
						(types.IsInterface(selInfo.Recv()) || selInfo.Kind() == types.MethodExpr) {
						okBlk = false
						return false
					}
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
				if callee == nil || callee.Origin() != callee || callee.Pkg() == nil {
					okBlk = false
					return false
				}
				if callee.Pkg() == p.Types {
					cfd := funcDecls[callee]
					if cfd == nil || cfd.Body == nil || funcBodyHasGotoOutsideClosures(cfd.Body) {
						okBlk = false
						return false
					}
					if _, seen := coneFuncs[callee]; !seen {
						coneFuncs[callee] = cfd
						queue = append(queue, cfd.Body)
					}
					return true
				}
				if !isPureDeterministicConeStdlibCall(p, x, callee) {
					okBlk = false
					return false
				}
			}
			return true
		})
		if !okBlk {
			return false
		}
	}

	// Verify getterRecv references inside doLit.Body (memoAssigns LHS + confined inputField reads).
	doIR := fc.litBody(p, doLit)
	if doIR == nil || !verifyOnceMemoRecvUsesInBody(
		audited,
		p,
		fc,
		pkgConf,
		ownerNamed,
		getterRecv,
		nil,
		true,
		memoFields,
		inputFields,
		memoAssigns,
		doLit,
		doIR,
		inputParamDeps,
	) {
		return false
	}

	_ = needsErrorProof
	if !verifyConeErrorOrigins(p, fc, idx, doLit, memoFields, memoAssigns, coneFuncs) {
		return false
	}
	return true
}

func verifyConeErrorOrigins(
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	doLit *ast.FuncLit,
	memoFields map[*types.Var]bool,
	memoAssigns []*ast.AssignStmt,
	coneFuncs map[*types.Func]*ast.FuncDecl,
) bool {
	doSig, _ := p.TypesInfo.TypeOf(doLit).(*types.Signature)
	if doSig == nil {
		return false
	}
	return verifyConeErrorOriginsInScopes(
		p,
		fc,
		idx,
		doSig,
		doLit.Body,
		memoFields,
		memoAssigns,
		coneFuncs,
		nil,
		false,
		false,
	)
}

func verifyConeErrorOriginsInScopes(
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	rootSig *types.Signature,
	rootBody *ast.BlockStmt,
	memoFields map[*types.Var]bool,
	memoAssigns []*ast.AssignStmt,
	coneFuncs map[*types.Func]*ast.FuncDecl,
	trustedErrCallees map[*types.Func]bool,
	allowConfinedNonErrIfaceParams bool,
	allowRootErrParams bool,
) bool {
	if rootSig == nil || rootBody == nil {
		return false
	}
	blocks := make([]*ast.BlockStmt, 0, 1+len(coneFuncs))
	blocks = append(blocks, rootBody)
	for _, fd := range coneFuncs {
		blocks = append(blocks, fd.Body)
	}

	paramDisallowed := func(pt types.Type) bool {
		if typeReachesUniverseError(pt) {
			return true
		}
		if allowConfinedNonErrIfaceParams && types.IsInterface(pt) {
			return false
		}
		return refconfine.TypeMayCarryUnknownDynamic(true, pt)
	}

	rootParams := make(map[*types.Var]bool, rootSig.Params().Len())
	for i := 0; i < rootSig.Params().Len(); i++ {
		pv := rootSig.Params().At(i)
		rootParams[pv] = true
		pt := pv.Type()
		if allowRootErrParams && isUniverseErrorType(pt) {
			continue
		}
		if paramDisallowed(pt) {
			return false
		}
	}

	// Collect all error-typed local/result variables across rootBody and coneFuncs;
	// reject error parameters or compound types containing unknown dynamic interfaces.
	for fn := range coneFuncs {
		sig, _ := fn.Type().(*types.Signature)
		if sig == nil {
			return false
		}
		if sig.Recv() != nil && refconfine.TypeMayCarryUnknownDynamic(true, sig.Recv().Type()) {
			return false
		}
		for i := 0; i < sig.Params().Len(); i++ {
			if paramDisallowed(sig.Params().At(i).Type()) {
				return false
			}
		}
		for i := 0; i < sig.Results().Len(); i++ {
			rt := sig.Results().At(i).Type()
			if refconfine.TypeMayCarryUnknownDynamic(true, rt) && !isUniverseErrorType(rt) {
				return false
			}
		}
	}

	localClosures := map[*types.Var]*ast.FuncLit{}
	for _, blk := range blocks {
		ast.Inspect(blk, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || as.Tok != token.DEFINE || len(as.Lhs) != len(as.Rhs) {
				return true
			}
			for i, lhs := range as.Lhs {
				id, isID := ast.Unparen(lhs).(*ast.Ident)
				lit, isLit := ast.Unparen(as.Rhs[i]).(*ast.FuncLit)
				if !isID || !isLit {
					continue
				}
				lv, _ := p.TypesInfo.Defs[id].(*types.Var)
				if isConfinedDirectCallClosureVar(p, fc, idx, lv) {
					localClosures[lv] = lit
				}
			}
			return true
		})
	}
	for _, lit := range localClosures {
		sig, ok := p.TypesInfo.TypeOf(lit).(*types.Signature)
		if !ok {
			return false
		}
		for i := 0; i < sig.Params().Len(); i++ {
			if paramDisallowed(sig.Params().At(i).Type()) {
				return false
			}
		}
		for i := 0; i < sig.Results().Len(); i++ {
			rt := sig.Results().At(i).Type()
			if refconfine.TypeMayCarryUnknownDynamic(true, rt) && !isUniverseErrorType(rt) {
				return false
			}
		}
	}

	resolveVerifiedConeCallSig := func(call *ast.CallExpr) *types.Signature {
		if call == nil {
			return nil
		}
		if sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr); isSel {
			if si := p.TypesInfo.Selections[sel]; si != nil &&
				(types.IsInterface(si.Recv()) || si.Kind() == types.MethodExpr) {
				return nil
			}
		}
		if cid, isID := ast.Unparen(call.Fun).(*ast.Ident); isID {
			if lv, isV := p.TypesInfo.Uses[cid].(*types.Var); isV && localClosures[lv] != nil {
				sig, _ := p.TypesInfo.TypeOf(localClosures[lv]).(*types.Signature)
				return sig
			}
		}
		callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
		if callee == nil || callee.Pkg() == nil {
			return nil
		}
		if coneFuncs[callee] != nil || trustedErrCallees[callee] {
			sig, _ := callee.Type().(*types.Signature)
			return sig
		}
		return nil
	}

	var isPureErrorExpr func(expr ast.Expr, depth int) bool
	isPureErrorExpr = func(expr ast.Expr, depth int) bool {
		if expr == nil || depth > 16 {
			return false
		}
		expr = ast.Unparen(expr)
		if syntaxutil.IsNilIdent(p.TypesInfo, expr) {
			return true
		}
		switch e := expr.(type) {
		case *ast.Ident:
			v, _ := p.TypesInfo.Uses[e].(*types.Var)
			if v == nil || v.IsField() || v.Parent() == p.Types.Scope() || !isUniverseErrorType(v.Type()) {
				return false
			}
			if rootParams[v] {
				return allowRootErrParams
			}
			return true
		case *ast.CallExpr:
			if csig := resolveVerifiedConeCallSig(e); csig != nil {
				return csig.Results().Len() == 1 && isUniverseErrorType(csig.Results().At(0).Type())
			}
			callee := syntaxutil.ResolveCalledFuncObj(p, e.Fun)
			if callee == nil || callee.Pkg() == nil {
				return false
			}
			pkgPath := callee.Pkg().Path()
			if pkgPath == "errors" && callee.Name() == "New" && len(e.Args) == 1 && !e.Ellipsis.IsValid() {
				return isBasicStringType(p.TypesInfo.TypeOf(e.Args[0]))
			}
			if pkgPath == "fmt" && callee.Name() == "Errorf" && len(e.Args) >= 1 && !e.Ellipsis.IsValid() {
				return verifyPureFmtErrorfCall(p, e, func(arg ast.Expr) bool {
					return isPureErrorExpr(arg, depth+1)
				})
			}
		}
		return false
	}

	// Verify every assignment to an error-typed variable, every error-typed return expression,
	// and every error sink / call argument across all cone blocks.
	checkErrorAssign := func(lhsT types.Type, slotIdx int, rhs ast.Expr, multiCall bool) bool {
		if !isUniverseErrorType(lhsT) {
			return true
		}
		if multiCall {
			call, ok := ast.Unparen(rhs).(*ast.CallExpr)
			if !ok {
				return false
			}
			csig := resolveVerifiedConeCallSig(call)
			return csig != nil && slotIdx >= 0 && slotIdx < csig.Results().Len() &&
				isUniverseErrorType(csig.Results().At(slotIdx).Type())
		}
		return isPureErrorExpr(rhs, 0)
	}

	memoAssignSet := map[*ast.AssignStmt]bool{}
	for _, as := range memoAssigns {
		memoAssignSet[as] = true
		if len(as.Lhs) == len(as.Rhs) {
			for i, lhs := range as.Lhs {
				sel, _ := ast.Unparen(lhs).(*ast.SelectorExpr)
				fld, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
				if fld != nil && memoFields[fld] && isUniverseErrorType(fld.Type()) {
					if !checkErrorAssign(fld.Type(), i, as.Rhs[i], false) {
						return false
					}
				}
			}
		} else if len(as.Rhs) == 1 {
			for i, lhs := range as.Lhs {
				sel, _ := ast.Unparen(lhs).(*ast.SelectorExpr)
				fld, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
				if fld != nil && memoFields[fld] && isUniverseErrorType(fld.Type()) {
					if !checkErrorAssign(fld.Type(), i, as.Rhs[0], true) {
						return false
					}
				}
			}
		}
	}

	type sigBody struct {
		sig  *types.Signature
		body *ast.BlockStmt
	}
	scopes := make([]sigBody, 0, 1+len(coneFuncs)+len(localClosures))
	scopes = append(scopes, sigBody{sig: rootSig, body: rootBody})
	for fn, fd := range coneFuncs {
		sig, _ := fn.Type().(*types.Signature)
		if sig == nil {
			return false
		}
		scopes = append(scopes, sigBody{sig: sig, body: fd.Body})
	}
	for _, lit := range localClosures {
		sig, _ := p.TypesInfo.TypeOf(lit).(*types.Signature)
		if sig == nil {
			return false
		}
		scopes = append(scopes, sigBody{sig: sig, body: lit.Body})
	}

	for _, sc := range scopes {
		okErr := true
		ast.Inspect(sc.body, func(n ast.Node) bool {
			if !okErr || n == nil {
				return false
			}
			if _, isLit := n.(*ast.FuncLit); isLit {
				return false
			}
			switch x := n.(type) {
			case *ast.UnaryExpr:
				if x.Op == token.AND && isUniverseErrorType(p.TypesInfo.TypeOf(x.X)) {
					okErr = false
					return false
				}
			case *ast.RangeStmt:
				if (x.Key != nil && isUniverseErrorType(p.TypesInfo.TypeOf(x.Key))) ||
					(x.Value != nil && isUniverseErrorType(p.TypesInfo.TypeOf(x.Value))) {
					okErr = false
					return false
				}
			case *ast.CaseClause:
				if imp, isV := p.TypesInfo.Implicits[x].(*types.Var); isV && isUniverseErrorType(imp.Type()) {
					okErr = false
					return false
				}
			case *ast.CallExpr:
				if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(x.Fun)); b != nil {
					if b.Name() == "panic" && len(x.Args) == 1 && isUniverseErrorType(p.TypesInfo.TypeOf(x.Args[0])) {
						if !isPureErrorExpr(x.Args[0], 0) {
							okErr = false
							return false
						}
					}
					return true
				}
				if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
					if si := p.TypesInfo.Selections[sel]; si != nil && types.IsInterface(si.Recv()) {
						if isUniverseErrorType(si.Recv()) {
							if sel.Sel.Name != "Error" || len(x.Args) != 0 || x.Ellipsis.IsValid() || !isPureErrorExpr(sel.X, 0) {
								okErr = false
								return false
							}
						}
						return true
					}
				}
				if csig := resolveVerifiedConeCallSig(x); csig != nil {
					nParams := csig.Params().Len()
					if len(x.Args) == 1 && nParams > 1 && !x.Ellipsis.IsValid() && !csig.Variadic() {
						for pi := 0; pi < nParams; pi++ {
							if !checkErrorAssign(csig.Params().At(pi).Type(), pi, x.Args[0], true) {
								okErr = false
								return false
							}
						}
						return true
					}
					for ai, arg := range x.Args {
						var pt types.Type
						if csig.Variadic() && ai >= nParams-1 {
							sliceT := csig.Params().At(nParams - 1).Type()
							if x.Ellipsis.IsValid() {
								if typeReachesUniverseError(sliceT) && !syntaxutil.IsNilIdent(p.TypesInfo, arg) {
									okErr = false
									return false
								}
								continue
							}
							sl, okSL := types.Unalias(sliceT).Underlying().(*types.Slice)
							if !okSL {
								okErr = false
								return false
							}
							pt = sl.Elem()
						} else if ai < nParams {
							pt = csig.Params().At(ai).Type()
						} else {
							okErr = false
							return false
						}
						if typeReachesUniverseError(pt) {
							if !isUniverseErrorType(pt) || !checkErrorAssign(pt, ai, arg, false) {
								okErr = false
								return false
							}
						}
					}
					return true
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
				if callee != nil && callee.Pkg() != nil && callee.Pkg().Path() == "fmt" && callee.Name() == "Errorf" {
					if !verifyPureFmtErrorfCall(p, x, func(arg ast.Expr) bool {
						return isPureErrorExpr(arg, 0)
					}) {
						okErr = false
						return false
					}
				}
			case *ast.AssignStmt:
				if memoAssignSet[x] {
					return true
				}
				if len(x.Lhs) == len(x.Rhs) {
					for i, lhs := range x.Lhs {
						if !checkErrorAssign(p.TypesInfo.TypeOf(lhs), i, x.Rhs[i], false) {
							okErr = false
							return false
						}
					}
				} else if len(x.Rhs) == 1 {
					for i, lhs := range x.Lhs {
						if !checkErrorAssign(p.TypesInfo.TypeOf(lhs), i, x.Rhs[0], true) {
							okErr = false
							return false
						}
					}
				}
			case *ast.ValueSpec:
				if len(x.Names) == len(x.Values) {
					for i, nm := range x.Names {
						if !checkErrorAssign(p.TypesInfo.TypeOf(nm), i, x.Values[i], false) {
							okErr = false
							return false
						}
					}
				} else if len(x.Values) == 1 {
					for i, nm := range x.Names {
						if !checkErrorAssign(p.TypesInfo.TypeOf(nm), i, x.Values[0], true) {
							okErr = false
							return false
						}
					}
				}
			case *ast.ReturnStmt:
				if len(x.Results) == 0 {
					return true
				}
				if len(x.Results) == 1 && sc.sig.Results().Len() > 1 {
					for ti := 0; ti < sc.sig.Results().Len(); ti++ {
						if !checkErrorAssign(sc.sig.Results().At(ti).Type(), ti, x.Results[0], true) {
							okErr = false
							return false
						}
					}
					return true
				}
				if len(x.Results) != sc.sig.Results().Len() {
					okErr = false
					return false
				}
				for ri, r := range x.Results {
					if !checkErrorAssign(sc.sig.Results().At(ri).Type(), ri, r, false) {
						okErr = false
						return false
					}
				}
			}
			return true
		})
		if !okErr {
			return false
		}
	}
	return true
}

func typeReachesUniverseError(root types.Type) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if isUniverseErrorType(t) {
			hit = true
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if named, ok := t.(*types.Named); ok {
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
		}
	}
	walk(root)
	return hit
}

func verifyPureFmtErrorfCall(p *packages.Package, call *ast.CallExpr, isPureErr func(ast.Expr) bool) bool {
	if len(call.Args) == 0 || call.Ellipsis.IsValid() {
		return false
	}
	return verifyPureFmtFormatArgs(p, call.Args[0], call.Args[1:], isPureErr)
}

func verifyPureFmtFormatArgs(p *packages.Package, fmtExpr ast.Expr, args []ast.Expr, isPureErr func(ast.Expr) bool) bool {
	tv := p.TypesInfo.Types[fmtExpr]
	if tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	fmtStr := constant.StringVal(tv.Value)
	argIdx := 0
	ok := auditset.ScanFmtDirectives(fmtStr, func(d auditset.FmtDirective) bool {
		// Reject explicit argument indexing %[n], dynamic '*' width/precision,
		// escaped '%*%' forms, and pointer-address verbs (%p, %#v).
		if d.HasArgIndex || d.DynamicWidth || d.DynamicPrec || d.Verb == '%' || d.ExposesPointerIdentity() {
			return false
		}
		if argIdx >= len(args) {
			return false
		}
		arg := args[argIdx]
		argIdx++
		if d.Verb == 'w' {
			return isPureErr(arg)
		}
		return isScalarBasicType(p.TypesInfo.TypeOf(arg))
	})
	return ok && argIdx == len(args)
}

func verifyOnceMemoSiblingMethod(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	pkgFresh *freshstruct.PkgFreshConstructors,
	funcDecls map[*types.Func]*ast.FuncDecl,
	isSettledConeGlobal func(*types.Var) bool,
	ownerNamed *types.Named,
	getterFn *types.Func,
	ptrMethodSet map[*types.Func]*ast.FuncDecl,
	guardSet map[syntaxutil.TypeRef]bool,
	unexpRefStructs map[*types.Named]bool,
	mfn *types.Func,
	mfd *ast.FuncDecl,
) bool {
	if funcBodyHasGotoOutsideClosures(mfd.Body) {
		return false
	}
	mSig, ok := mfn.Type().(*types.Signature)
	if !ok || mSig.TypeParams().Len() > 0 || mSig.RecvTypeParams().Len() > 0 {
		return false
	}

	// 1. Verify sibling method body and transitive helper cone purity (skipping getterFn
	// and other *T methods, which are verified directly in ptrMethodSet).
	sibConeFuncs := map[*types.Func]*ast.FuncDecl{}
	sawErrorSink := false
	for pi := 0; pi < mSig.Params().Len(); pi++ {
		if typeReachesUniverseError(mSig.Params().At(pi).Type()) {
			sawErrorSink = true
			break
		}
	}
	type coneUnit struct {
		sig  *types.Signature
		body *ast.BlockStmt
	}
	queue := []coneUnit{{sig: mSig, body: mfd.Body}}
	for len(queue) > 0 {
		unit := queue[0]
		queue = queue[1:]

		allowedIfaceVars := collectConfinedCallerInterfaceVars(p, idx, unit.sig, unit.body)
		localClos := map[*types.Var]*ast.FuncLit{}
		ast.Inspect(unit.body, func(n ast.Node) bool {
			as, isAS := n.(*ast.AssignStmt)
			if !isAS || as.Tok != token.DEFINE || len(as.Lhs) != len(as.Rhs) {
				return true
			}
			for i, lhs := range as.Lhs {
				id, isID := ast.Unparen(lhs).(*ast.Ident)
				lit, isLit := ast.Unparen(as.Rhs[i]).(*ast.FuncLit)
				if !isID || !isLit {
					continue
				}
				lv, _ := p.TypesInfo.Defs[id].(*types.Var)
				if isConfinedDirectCallClosureVar(p, fc, idx, lv) {
					localClos[lv] = lit
				}
			}
			return true
		})

		okBlk := true
		ast.Inspect(unit.body, func(n ast.Node) bool {
			if !okBlk || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.GoStmt, *ast.DeferStmt, *ast.SendStmt, *ast.SelectStmt:
				okBlk = false
				return false
			case *ast.UnaryExpr:
				if x.Op == token.ARROW {
					okBlk = false
					return false
				}
			case *ast.BinaryExpr:
				if x.Op == token.EQL || x.Op == token.NEQ {
					if isPointerIdentityComparison(p.TypesInfo, x.X, x.Y) {
						okBlk = false
						return false
					}
				}
			case *ast.CompositeLit:
				// Structs in guardSet carrying unexported ref fields (e.g. Document.index)
				// may only be constructed in doLit's verified fresh constructor cone.
				if ct := p.TypesInfo.TypeOf(x); ct != nil {
					if cn, isN := types.Unalias(ct).(*types.Named); isN && unexpRefStructs[cn.Origin()] {
						okBlk = false
						return false
					}
				}
			case *ast.RangeStmt:
				switch syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x.X)).(type) {
				case *types.Chan, *types.Signature:
					okBlk = false
					return false
				}
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && lookupAnyPkgScopeVar(p, x.Key) != nil) ||
						(x.Value != nil && lookupAnyPkgScopeVar(p, x.Value) != nil) {
						okBlk = false
						return false
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if lookupRootPkgScopeVarAnyPkg(p, lhs) != nil {
						okBlk = false
						return false
					}
				}
			case *ast.IncDecStmt:
				if lookupRootPkgScopeVarAnyPkg(p, x.X) != nil {
					okBlk = false
					return false
				}
			case *ast.Ident:
				if gv, isV := p.TypesInfo.Uses[x].(*types.Var); isV && gv != nil && !gv.IsField() &&
					gv.Pkg() != nil && gv.Parent() == gv.Pkg().Scope() {
					if !isSettledConeGlobal(gv) {
						okBlk = false
						return false
					}
				}
				if !idx.CalleeIdents[x] {
					if fnObj, isFn := p.TypesInfo.Uses[x].(*types.Func); isFn && fnObj != nil {
						sig, okSig := fnObj.Type().(*types.Signature)
						if !okSig || sig.Recv() != nil || fnObj.Origin() != fnObj || fnObj.Pkg() == nil {
							okBlk = false
							return false
						}
						if fnObj.Pkg() == p.Types {
							cfd := funcDecls[fnObj]
							if cfd == nil || cfd.Body == nil || funcBodyHasGotoOutsideClosures(cfd.Body) {
								okBlk = false
								return false
							}
							if _, seen := sibConeFuncs[fnObj]; !seen {
								sibConeFuncs[fnObj] = cfd
								queue = append(queue, coneUnit{sig: sig, body: cfd.Body})
							}
						} else if !isPureDeterministicConeStdlibFuncValue(fnObj, sig) {
							okBlk = false
							return false
						}
					}
				}
			case *ast.FuncLit:
				isAllowedLocalClos := false
				for _, lc := range localClos {
					if lc == x {
						isAllowedLocalClos = true
						break
					}
				}
				if !isAllowedLocalClos {
					okBlk = false
					return false
				}
			case *ast.CallExpr:
				if tv := p.TypesInfo.Types[ast.Unparen(x.Fun)]; tv.IsType() {
					if syntaxutil.IsUnsafePointerType(tv.Type) {
						okBlk = false
						return false
					}
					return true
				}
				if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(x.Fun)); b != nil {
					switch b.Name() {
					case "recover", "close", "println", "print":
						okBlk = false
						return false
					case "delete", "clear", "copy", "append":
						if len(x.Args) > 0 && lookupRootPkgScopeVarAnyPkg(p, x.Args[0]) != nil {
							okBlk = false
							return false
						}
					case "panic":
						if len(x.Args) != 1 {
							okBlk = false
							return false
						}
						pt := p.TypesInfo.TypeOf(x.Args[0])
						if isUniverseErrorType(pt) {
							sawErrorSink = true
						} else if !isScalarBasicType(pt) {
							okBlk = false
							return false
						}
					}
					return true
				}
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
					if lv, isV := p.TypesInfo.Uses[cid].(*types.Var); isV && localClos[lv] != nil {
						closSig, okCS := p.TypesInfo.TypeOf(localClos[lv]).(*types.Signature)
						hasErr, argsOK := checkSiblingCallIfaceArgs(audited, p, closSig, x, allowedIfaceVars)
						if !okCS || !argsOK {
							okBlk = false
							return false
						}
						if hasErr {
							sawErrorSink = true
						}
						return true
					}
				}
				if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
					if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil {
						if selInfo.Kind() == types.MethodExpr {
							okBlk = false
							return false
						}
						if types.IsInterface(selInfo.Recv()) {
							if isUniverseErrorType(selInfo.Recv()) && sel.Sel.Name == "Error" && len(x.Args) == 0 && !x.Ellipsis.IsValid() {
								sawErrorSink = true
								return true
							}
							rid, isRID := ast.Unparen(sel.X).(*ast.Ident)
							if isRID {
								if rv, _ := p.TypesInfo.Uses[rid].(*types.Var); rv != nil && allowedIfaceVars[rv] {
									return true
								}
							}
							okBlk = false
							return false
						}
					}
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
				if callee == nil || callee.Origin() != callee || callee.Pkg() == nil {
					okBlk = false
					return false
				}
				if callee == getterFn || ptrMethodSet[callee] != nil {
					csig, okSig := callee.Type().(*types.Signature)
					hasErr, argsOK := checkSiblingCallIfaceArgs(audited, p, csig, x, allowedIfaceVars)
					if !okSig || !argsOK {
						okBlk = false
						return false
					}
					if hasErr {
						sawErrorSink = true
					}
					return true
				}
				if callee.Pkg() == p.Types {
					csig, okSig := callee.Type().(*types.Signature)
					cfd := funcDecls[callee]
					if !okSig || cfd == nil || cfd.Body == nil || funcBodyHasGotoOutsideClosures(cfd.Body) {
						okBlk = false
						return false
					}
					hasErr, argsOK := checkSiblingCallIfaceArgs(audited, p, csig, x, allowedIfaceVars)
					if !argsOK {
						okBlk = false
						return false
					}
					if hasErr {
						sawErrorSink = true
					}
					if _, seen := sibConeFuncs[callee]; !seen {
						sibConeFuncs[callee] = cfd
						queue = append(queue, coneUnit{sig: csig, body: cfd.Body})
					}
					return true
				}
				if !isPureDeterministicConeStdlibCall(p, x, callee) {
					okBlk = false
					return false
				}
				if callee.Pkg().Path() == "fmt" && callee.Name() == "Errorf" {
					sawErrorSink = true
				}
			}
			return true
		})
		if !okBlk {
			return false
		}
	}

	trusted := make(map[*types.Func]bool, 1+len(ptrMethodSet))
	trusted[getterFn] = true
	for pm := range ptrMethodSet {
		trusted[pm] = true
	}
	allowRootErrParams := !mfn.Exported() && isUnexportedInternalOnlyPtrMethod(p, idx, ptrMethodSet, mfn)

	// 2. Verify every result slot of mfn: error origins + guarded or fresh-per-call closure.
	checkedErrors := false
	for ri := 0; ri < mSig.Results().Len(); ri++ {
		rt := mSig.Results().At(ri).Type()
		if refconfine.TypeCarriesSignature(rt) || typeReachesNamedOrSyncOnce(rt, ownerNamed) {
			return false
		}
		if isScalarOrScalarArrayType(rt) {
			continue
		}
		if isUniverseErrorType(rt) {
			if !checkedErrors {
				if !verifyConeErrorOriginsInScopes(p, fc, idx, mSig, mfd.Body, nil, nil, sibConeFuncs, trusted, true, allowRootErrParams) {
					return false
				}
				checkedErrors = true
			}
			continue
		}
		if refconfine.TypeMayCarryUnknownDynamic(audited, rt) {
			return false
		}
		if isSingleGuardSetStructOrPtr(rt, guardSet) {
			continue
		}
		if ri == 0 && siblingReturnsFreshStructValue(audited, pkgFresh, mfd, rt, ownerNamed) {
			continue
		}
		if sl, isSL := types.Unalias(rt).Underlying().(*types.Slice); isSL && isScalarBasicType(sl.Elem()) {
			if funcSlotReturnsFreshScalarSlice(p, fc, idx, funcDecls, mfd, ri, map[*ast.FuncDecl]bool{}) {
				continue
			}
		}
		return false
	}
	if sawErrorSink && !checkedErrors {
		if !verifyConeErrorOriginsInScopes(p, fc, idx, mSig, mfd.Body, nil, nil, sibConeFuncs, trusted, true, allowRootErrParams) {
			return false
		}
	}
	return true
}

func isUnexportedInternalOnlyPtrMethod(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	ptrMethodSet map[*types.Func]*ast.FuncDecl,
	mfn *types.Func,
) bool {
	if mfn == nil || mfn.Exported() {
		return false
	}
	ptrDeclSet := make(map[*ast.FuncDecl]bool, len(ptrMethodSet))
	for _, fd := range ptrMethodSet {
		if fd != nil {
			ptrDeclSet[fd] = true
		}
	}
	for _, uid := range idx.UsesOf[mfn] {
		sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
		if !isSel || sel.Sel != uid {
			return false
		}
		si := p.TypesInfo.Selections[sel]
		if si == nil || si.Kind() != types.MethodVal {
			return false
		}
		call, isCall := idx.ParentUnparen(sel).(*ast.CallExpr)
		if !isCall || ast.Unparen(call.Fun) != sel {
			return false
		}
		enclFD := idx.SyncEnclFuncDecl(call)
		if enclFD == nil || !ptrDeclSet[enclFD] {
			return false
		}
	}
	return true
}

// checkSiblingCallIfaceArgs enforces that any non-error interface argument passed
// to csig originates from nil or an allowed caller interface variable, rejects
// compound unknown-dynamic non-error arguments unless nil, and reports whether
// any formal parameter reaches universe error.
func checkSiblingCallIfaceArgs(
	audited bool,
	p *packages.Package,
	csig *types.Signature,
	call *ast.CallExpr,
	allowedIfaceVars map[*types.Var]bool,
) (hasErrParam bool, ok bool) {
	if csig == nil || call == nil {
		return false, false
	}
	nParams := csig.Params().Len()
	for pi := 0; pi < nParams; pi++ {
		if typeReachesUniverseError(csig.Params().At(pi).Type()) {
			hasErrParam = true
			break
		}
	}
	if len(call.Args) == 1 && nParams > 1 && !call.Ellipsis.IsValid() && !csig.Variadic() {
		for pi := 0; pi < nParams; pi++ {
			pt := csig.Params().At(pi).Type()
			if !isUniverseErrorType(pt) && (types.IsInterface(pt) || refconfine.TypeMayCarryUnknownDynamic(audited, pt)) {
				return hasErrParam, false
			}
		}
		return hasErrParam, true
	}
	checkOne := func(pt types.Type, arg ast.Expr) bool {
		if types.IsInterface(pt) {
			if isUniverseErrorType(pt) {
				return true
			}
			if syntaxutil.IsNilIdent(p.TypesInfo, arg) {
				return true
			}
			aid, isAID := ast.Unparen(arg).(*ast.Ident)
			av, _ := p.TypesInfo.Uses[aid].(*types.Var)
			return isAID && av != nil && allowedIfaceVars[av]
		}
		if !typeReachesUniverseError(pt) && refconfine.TypeMayCarryUnknownDynamic(audited, pt) {
			return syntaxutil.IsNilIdent(p.TypesInfo, arg)
		}
		return true
	}
	for ai, arg := range call.Args {
		var pt types.Type
		if csig.Variadic() && ai >= nParams-1 {
			sliceT := csig.Params().At(nParams - 1).Type()
			if call.Ellipsis.IsValid() {
				if !typeReachesUniverseError(sliceT) && refconfine.TypeMayCarryUnknownDynamic(audited, sliceT) {
					if !syntaxutil.IsNilIdent(p.TypesInfo, arg) {
						return hasErrParam, false
					}
				}
				continue
			}
			sl, okSL := types.Unalias(sliceT).Underlying().(*types.Slice)
			if !okSL {
				return hasErrParam, false
			}
			pt = sl.Elem()
		} else if ai < nParams {
			pt = csig.Params().At(ai).Type()
		} else {
			return hasErrParam, false
		}
		if !checkOne(pt, arg) {
			return hasErrParam, false
		}
	}
	return hasErrParam, true
}

func collectConfinedCallerInterfaceVars(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	sig *types.Signature,
	body *ast.BlockStmt,
) map[*types.Var]bool {
	allowed := map[*types.Var]bool{}
	if sig == nil || body == nil {
		return allowed
	}
	candidates := map[*types.Var]bool{}
	for i := 0; i < sig.Params().Len(); i++ {
		pv := sig.Params().At(i)
		if types.IsInterface(pv.Type()) && !isUniverseErrorType(pv.Type()) {
			candidates[pv] = true
			allowed[pv] = true
		}
	}
	if len(candidates) == 0 {
		return allowed
	}

	// Propagate to local variables assigned solely from method calls on already-allowed
	// interface variables (e.g., prop, ok := node.Property(name)).
	type localDef struct {
		rhsList []ast.Expr
		slots   []int
		multi   []bool
		bad     bool
	}
	localDefs := map[*types.Var]*localDef{}
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			if len(x.Lhs) == len(x.Rhs) {
				for i, lhs := range x.Lhs {
					id, isID := ast.Unparen(lhs).(*ast.Ident)
					if !isID {
						continue
					}
					v, _ := p.TypesInfo.Defs[id].(*types.Var)
					if v == nil {
						v, _ = p.TypesInfo.Uses[id].(*types.Var)
					}
					if v == nil || candidates[v] || !types.IsInterface(v.Type()) || isUniverseErrorType(v.Type()) {
						if v != nil && candidates[v] {
							delete(allowed, v)
						}
						continue
					}
					d := localDefs[v]
					if d == nil {
						d = &localDef{}
						localDefs[v] = d
					}
					if x.Tok != token.DEFINE && x.Tok != token.ASSIGN {
						d.bad = true
					}
					d.rhsList = append(d.rhsList, x.Rhs[i])
					d.slots = append(d.slots, i)
					d.multi = append(d.multi, false)
				}
			} else if len(x.Rhs) == 1 {
				for i, lhs := range x.Lhs {
					id, isID := ast.Unparen(lhs).(*ast.Ident)
					if !isID {
						continue
					}
					v, _ := p.TypesInfo.Defs[id].(*types.Var)
					if v == nil {
						v, _ = p.TypesInfo.Uses[id].(*types.Var)
					}
					if v == nil || candidates[v] || !types.IsInterface(v.Type()) || isUniverseErrorType(v.Type()) {
						if v != nil && candidates[v] {
							delete(allowed, v)
						}
						continue
					}
					d := localDefs[v]
					if d == nil {
						d = &localDef{}
						localDefs[v] = d
					}
					if x.Tok != token.DEFINE && x.Tok != token.ASSIGN {
						d.bad = true
					}
					d.rhsList = append(d.rhsList, x.Rhs[0])
					d.slots = append(d.slots, i)
					d.multi = append(d.multi, true)
				}
			}
		}
		return true
	})

	changed := true
	for changed {
		changed = false
		for lv, d := range localDefs {
			if allowed[lv] || d.bad || len(d.rhsList) == 0 {
				continue
			}
			allOK := true
			for k, rhs := range d.rhsList {
				call, isCall := ast.Unparen(rhs).(*ast.CallExpr)
				if !isCall {
					allOK = false
					break
				}
				sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
				if !isSel {
					allOK = false
					break
				}
				si := p.TypesInfo.Selections[sel]
				rid, isRID := ast.Unparen(sel.X).(*ast.Ident)
				if si == nil || !types.IsInterface(si.Recv()) || !isRID {
					allOK = false
					break
				}
				rv, _ := p.TypesInfo.Uses[rid].(*types.Var)
				if rv == nil || !allowed[rv] {
					allOK = false
					break
				}
				if d.multi[k] {
					msig, _ := si.Type().(*types.Signature)
					if msig == nil || d.slots[k] >= msig.Results().Len() || !types.Identical(msig.Results().At(d.slots[k]).Type(), lv.Type()) {
						allOK = false
						break
					}
				}
			}
			if allOK {
				allowed[lv] = true
				changed = true
			}
		}
	}

	// Disqualify any interface var whose address is taken, returned, or stored in a composite/map/slice/field.
	for v := range allowed {
		for _, uid := range idx.UsesOf[v] {
			par := idx.ParentUnparen(uid)
			switch x := par.(type) {
			case *ast.SelectorExpr:
				if ast.Unparen(x.X) != uid {
					delete(allowed, v)
				}
			case *ast.BinaryExpr:
				if (x.Op != token.EQL && x.Op != token.NEQ) || (!syntaxutil.IsNilIdent(p.TypesInfo, x.X) && !syntaxutil.IsNilIdent(p.TypesInfo, x.Y)) {
					delete(allowed, v)
				}
			case *ast.CallExpr:
				if ast.Unparen(x.Fun) == uid ||
					p.TypesInfo.Types[ast.Unparen(x.Fun)].IsType() ||
					syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(x.Fun)) != nil {
					delete(allowed, v)
				}
			default:
				delete(allowed, v)
			}
			if !allowed[v] {
				break
			}
		}
	}
	return allowed
}

func isScalarOrScalarArrayType(t types.Type) bool {
	if isScalarBasicType(t) {
		return true
	}
	if arr, ok := types.Unalias(t).Underlying().(*types.Array); ok {
		return isScalarOrScalarArrayType(arr.Elem())
	}
	return false
}

func isSingleGuardSetStructOrPtr(t types.Type, guardSet map[syntaxutil.TypeRef]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if ptr, isPtr := t.(*types.Pointer); isPtr {
		t = types.Unalias(ptr.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.TypeArgs().Len() > 0 {
		return false
	}
	named = named.Origin()
	if _, isSt := named.Underlying().(*types.Struct); !isSt {
		return false
	}
	ref := syntaxutil.TypeRef{Pkg: named.Obj().Pkg().Path(), Name: named.Obj().Name()}
	return ref.Valid() && guardSet[ref]
}

func siblingReturnsFreshStructValue(
	audited bool,
	pkgFresh *freshstruct.PkgFreshConstructors,
	mfd *ast.FuncDecl,
	rt types.Type,
	ownerNamed *types.Named,
) bool {
	if pkgFresh == nil || mfd == nil || !pkgFresh.ReturnsFreshAllocation(mfd) {
		return false
	}
	t := types.Unalias(rt)
	if ptr, isPtr := t.(*types.Pointer); isPtr {
		t = types.Unalias(ptr.Elem())
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok || st.NumFields() == 0 {
		return false
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		ft := f.Type()
		if refconfine.TypeMayCarryUnknownDynamic(audited, ft) ||
			refconfine.TypeCarriesSignature(ft) ||
			typeReachesNamedOrSyncOnce(ft, ownerNamed) {
			return false
		}
		if !refconfine.TypeCarriesMutableRef(ft) {
			continue
		}
		if !pkgFresh.IsFieldFreshInCone(mfd, f) {
			return false
		}
		// Nested elements inside a fresh container field must themselves carry no
		// unverified inner mutable references (e.g. []KnobUsage where KnobUsage is pure strings).
		switch u := types.Unalias(ft).Underlying().(type) {
		case *types.Slice:
			if refconfine.TypeCarriesMutableRef(u.Elem()) || syntaxutil.ContainsUintptr(u.Elem()) {
				return false
			}
		case *types.Map:
			if !isScalarBasicType(u.Key()) || refconfine.TypeCarriesMutableRef(u.Elem()) || syntaxutil.ContainsUintptr(u.Elem()) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func funcSlotReturnsFreshScalarSlice(
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	funcDecls map[*types.Func]*ast.FuncDecl,
	fd *ast.FuncDecl,
	slotIdx int,
	seen map[*ast.FuncDecl]bool,
) bool {
	if fd == nil || fd.Body == nil || slotIdx < 0 || seen[fd] || funcBodyHasGotoOutsideClosures(fd.Body) {
		return false
	}
	fn, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
	if fn == nil {
		return false
	}
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || slotIdx >= sig.Results().Len() {
		return false
	}
	sl, isSL := types.Unalias(sig.Results().At(slotIdx).Type()).Underlying().(*types.Slice)
	if !isSL || !isScalarBasicType(sl.Elem()) {
		return false
	}

	seen[fd] = true
	defer delete(seen, fd)

	b := fc.funcBody(p, fd)
	if b == nil {
		return false
	}

	var allOps []*flowir.Op
	var collectOps func(cur *flowir.Body)
	collectOps = func(cur *flowir.Body) {
		if cur == nil {
			return
		}
		for i := range cur.Ops {
			op := &cur.Ops[i]
			allOps = append(allOps, op)
			if op.RangeBody != nil {
				collectOps(op.RangeBody)
			}
		}
	}
	collectOps(b)

	isDirectIntraPkgCallFreshSlot := func(v *flowir.Value, cSlot int, forbidVar *types.Var) bool {
		if v == nil || v.Kind != flowir.ValCall || v.CalleeFunc == nil ||
			v.CalleeFunc.Origin() != v.CalleeFunc || v.CalleeFunc.Pkg() != p.Types {
			return false
		}
		switch v.CallKind {
		case flowir.CallPlain:
			if v.IsMethodExprCall {
				return false
			}
		case flowir.CallMethod:
			if v.Selection != nil && types.IsInterface(v.Selection.Recv()) {
				return false
			}
		default:
			return false
		}
		if forbidVar != nil {
			if v.Recv != nil && exprMentionsVar(p.TypesInfo, v.Recv.Raw, forbidVar) {
				return false
			}
			for _, a := range v.Args {
				if a != nil && exprMentionsVar(p.TypesInfo, a.Raw, forbidVar) {
					return false
				}
			}
		}
		return funcSlotReturnsFreshScalarSlice(p, fc, idx, funcDecls, funcDecls[v.CalleeFunc], cSlot, seen)
	}

	var isFreshSliceExpr func(v *flowir.Value, selfVar *types.Var, freshLocals map[*types.Var]bool) (*ast.Ident, bool)
	isFreshSliceExpr = func(v *flowir.Value, selfVar *types.Var, freshLocals map[*types.Var]bool) (*ast.Ident, bool) {
		if v == nil {
			return nil, false
		}
		switch v.Kind {
		case flowir.ValScalarLitOrConst:
			if syntaxutil.IsNilIdent(p.TypesInfo, v.Raw) {
				return nil, true
			}
			return nil, false
		case flowir.ValPlace:
			if v.Place.Root == flowir.RootConstOrNil {
				return nil, true
			}
			if v.Place.IsBareVar() && v.Place.Root == flowir.RootLocal && v.Place.Obj != nil {
				if (selfVar != nil && v.Place.Obj == selfVar) || freshLocals[v.Place.Obj] {
					id, ok := ast.Unparen(v.Place.Raw).(*ast.Ident)
					return id, ok
				}
			}
			return nil, false
		case flowir.ValConvert:
			if !v.IsTypeAssert && v.Arg != nil && syntaxutil.IsNilIdent(p.TypesInfo, v.Arg.Raw) {
				return nil, true
			}
			return nil, false
		case flowir.ValAllocFresh:
			if v.AllocKind == flowir.AllocMake || v.AllocKind == flowir.AllocCompositeLit {
				return nil, true
			}
			return nil, false
		case flowir.ValCall:
			if v.CallKind == flowir.CallBuiltin && v.BuiltinName == "append" && len(v.Args) >= 1 {
				for _, a := range v.Args[1:] {
					if selfVar != nil && a != nil && exprMentionsVar(p.TypesInfo, a.Raw, selfVar) {
						return nil, false
					}
				}
				if v.Args[0] != nil && syntaxutil.IsTypedNilSliceConv(p, v.Args[0].Raw) {
					return nil, true
				}
				return isFreshSliceExpr(v.Args[0], selfVar, freshLocals)
			}
			if v.CalleeSig != nil && v.CalleeSig.Results().Len() == 1 && isDirectIntraPkgCallFreshSlot(v, 0, selfVar) {
				return nil, true
			}
		}
		return nil, false
	}

	isAllowedLocalSliceReadIdent := func(uid *ast.Ident) bool {
		par := idx.ParentUnparen(uid)
		call, isCall := par.(*ast.CallExpr)
		if !isCall || call.Ellipsis.IsValid() || len(call.Args) != 1 || ast.Unparen(call.Args[0]) != uid {
			return false
		}
		if bn := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(call.Fun)); bn != nil {
			return bn.Name() == "len" || bn.Name() == "cap"
		}
		callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
		if callee == nil || callee.Pkg() == nil {
			return false
		}
		switch callee.Pkg().Path() {
		case "sort":
			switch callee.Name() {
			case "Strings", "Ints", "Float64s":
				return true
			}
		case "slices":
			switch callee.Name() {
			case "Sort", "Reverse":
				return true
			}
		}
		return false
	}

	candidates := map[*types.Var]bool{}
	for _, op := range allOps {
		if op.Kind != flowir.OpAssign {
			continue
		}
		for _, dst := range op.Dsts {
			if dst.IsBareVar() && dst.Root == flowir.RootLocal && dst.Obj != nil {
				if lvSl, okSL := types.Unalias(dst.Obj.Type()).Underlying().(*types.Slice); okSL && isScalarBasicType(lvSl.Elem()) {
					candidates[dst.Obj] = true
				}
			}
		}
	}

	for {
		evicted := false
		for lv := range candidates {
			consumedReads := map[*ast.Ident]bool{}
			writesOK := true
			for _, op := range allOps {
				switch op.Kind {
				case flowir.OpAssign:
					for di, dst := range op.Dsts {
						if dst.Obj != lv {
							continue
						}
						if !dst.IsBareVar() {
							writesOK = false
							break
						}
						switch op.AssignKind {
						case flowir.AssignZeroDecl:
						case flowir.AssignPlain:
							if di >= len(op.Srcs) {
								writesOK = false
								break
							}
							rid, ok := isFreshSliceExpr(op.Srcs[di], lv, candidates)
							if !ok {
								writesOK = false
								break
							}
							if rid != nil {
								consumedReads[rid] = true
							}
							if lid, ok := ast.Unparen(dst.Raw).(*ast.Ident); ok {
								consumedReads[lid] = true
							}
						case flowir.AssignMulti:
							if len(op.Srcs) != 1 || !isDirectIntraPkgCallFreshSlot(op.Srcs[0], di, lv) {
								writesOK = false
								break
							}
							if lid, ok := ast.Unparen(dst.Raw).(*ast.Ident); ok {
								consumedReads[lid] = true
							}
						default:
							writesOK = false
						}
					}
				case flowir.OpReturn:
					if slotIdx < len(op.Results) && op.Results[slotIdx] != nil {
						if rid, ok := isFreshSliceExpr(op.Results[slotIdx], nil, candidates); ok && rid != nil && p.TypesInfo.Uses[rid] == lv {
							consumedReads[rid] = true
						}
					}
				}
				if !writesOK {
					break
				}
			}
			if writesOK {
				for _, uid := range idx.UsesOf[lv] {
					if consumedReads[uid] || isAllowedLocalSliceReadIdent(uid) {
						continue
					}
					writesOK = false
					break
				}
			}
			if !writesOK {
				delete(candidates, lv)
				evicted = true
			}
		}
		if !evicted {
			break
		}
	}

	sawReturn := false
	for _, op := range allOps {
		if op.Kind != flowir.OpReturn {
			continue
		}
		sawReturn = true
		if len(op.Results) == 1 && sig.Results().Len() > 1 {
			if !isDirectIntraPkgCallFreshSlot(op.Results[0], slotIdx, nil) {
				return false
			}
			continue
		}
		if slotIdx >= len(op.Results) {
			return false
		}
		if _, ok := isFreshSliceExpr(op.Results[slotIdx], nil, candidates); !ok {
			return false
		}
	}
	return sawReturn
}

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
						if isReadOnlyInputSliceStdlibCallee(v.CalleeFunc) {
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

func isPureDeterministicConeStdlibFuncValue(fn *types.Func, sig *types.Signature) bool {
	if fn == nil || fn.Pkg() == nil || sig == nil || sig.Recv() != nil {
		return false
	}
	switch fn.Pkg().Path() {
	case "unicode", "unicode/utf8", "unicode/utf16", "strconv", "math/bits", "cmp", "path", "strings", "bytes":
	default:
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		pt := sig.Params().At(i).Type()
		if refconfine.TypeMayCarryUnknownDynamic(true, pt) || refconfine.TypeCarriesSignature(pt) || refconfine.TypeCarriesMutableRef(pt) {
			return false
		}
	}
	for i := 0; i < sig.Results().Len(); i++ {
		rt := sig.Results().At(i).Type()
		if refconfine.TypeMayCarryUnknownDynamic(true, rt) && !isUniverseErrorType(rt) {
			return false
		}
		if refconfine.TypeCarriesSignature(rt) {
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

func allIntraPkgVarUsesAreDirectMethodCalls(p *packages.Package, idx *refconfine.PkgIndex, v *types.Var) bool {
	for _, uid := range idx.UsesOf[v] {
		mSel, ok := idx.ParentUnparen(uid).(*ast.SelectorExpr)
		if !ok || ast.Unparen(mSel.X) != uid {
			return false
		}
		selInfo := p.TypesInfo.Selections[mSel]
		if selInfo == nil || selInfo.Kind() != types.MethodVal || len(selInfo.Index()) != 1 {
			return false
		}
		call, ok := idx.ParentUnparen(mSel).(*ast.CallExpr)
		if !ok || ast.Unparen(call.Fun) != mSel {
			return false
		}
	}
	return true
}

func isPureDeterministicConeStdlibCall(p *packages.Package, call *ast.CallExpr, callee *types.Func) bool {
	pkgPath := callee.Pkg().Path()
	firstSeg, _, _ := strings.Cut(pkgPath, "/")
	if strings.Contains(firstSeg, ".") {
		return false
	}
	switch pkgPath {
	case "errors":
		return callee.Name() == "New"
	case "fmt":
		switch callee.Name() {
		case "Errorf":
			return verifyPureFmtErrorfCall(p, call, func(arg ast.Expr) bool {
				return isUniverseErrorType(p.TypesInfo.TypeOf(arg))
			})
		case "Sprintf":
			return verifyPureFmtErrorfCall(p, call, func(ast.Expr) bool { return false })
		case "Fprintf":
			if len(call.Args) < 2 || call.Ellipsis.IsValid() || !isLocalBuilderOrBufferAddr(p, call.Args[0]) {
				return false
			}
			return verifyPureFmtFormatArgs(p, call.Args[1], call.Args[2:], func(ast.Expr) bool { return false })
		case "Sprint", "Sprintln":
			for _, a := range call.Args {
				if !isScalarBasicType(p.TypesInfo.TypeOf(a)) {
					return false
				}
			}
			return true
		}
		return false
	case "strings", "bytes":
		// Reject io.Reader / io.Writer streaming methods; admit value/Builder/Buffer operations.
		sig, ok := callee.Type().(*types.Signature)
		if !ok {
			return false
		}
		for i := 0; i < sig.Params().Len(); i++ {
			if types.IsInterface(sig.Params().At(i).Type()) {
				return false
			}
		}
		for i := 0; i < sig.Results().Len(); i++ {
			if types.IsInterface(sig.Results().At(i).Type()) && !isUniverseErrorType(sig.Results().At(i).Type()) {
				return false
			}
		}
		return true
	case "strconv", "unicode", "unicode/utf8", "unicode/utf16", "math/bits", "cmp", "path":
		return true
	case "sort":
		switch callee.Name() {
		case "Strings", "Ints", "Float64s":
			return len(call.Args) == 1 && !call.Ellipsis.IsValid() && lookupRootPkgScopeVarAnyPkg(p, call.Args[0]) == nil
		}
		return false
	case "slices":
		switch callee.Name() {
		case "Clone", "Contains", "Equal", "Index", "BinarySearch":
			return true
		case "Sort", "Reverse":
			return len(call.Args) == 1 && !call.Ellipsis.IsValid() && lookupRootPkgScopeVarAnyPkg(p, call.Args[0]) == nil
		}
		return false
	}
	return false
}

func isLocalBuilderOrBufferAddr(p *packages.Package, expr ast.Expr) bool {
	un, ok := ast.Unparen(expr).(*ast.UnaryExpr)
	if !ok || un.Op != token.AND {
		return false
	}
	id, ok := ast.Unparen(un.X).(*ast.Ident)
	if !ok {
		return false
	}
	v, _ := p.TypesInfo.Uses[id].(*types.Var)
	if v == nil || v.IsField() || v.Parent() == p.Types.Scope() {
		return false
	}
	named, ok := types.Unalias(v.Type()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return auditset.InMemoryWriterPointerType(named.Obj().Pkg().Path(), named.Obj().Name())
}

func isReadOnlyInputSliceStdlibCallee(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	traits := auditset.DeterministicStdCallTraits(fn.Pkg().Path(), fn.Name())
	return traits.ReadOnlySliceInspect || traits.ReadOnlySliceCopy
}

func isPointerIdentityComparison(info *types.Info, x, y ast.Expr) bool {
	if syntaxutil.IsNilIdent(info, x) || syntaxutil.IsNilIdent(info, y) {
		return false
	}
	for _, op := range []ast.Expr{x, y} {
		t := info.TypeOf(op)
		if t == nil {
			continue
		}
		switch types.Unalias(t).Underlying().(type) {
		case *types.Pointer, *types.Interface, *types.Chan, *types.Signature:
			return true
		}
	}
	return false
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
