package propharness

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
)

// verifyHarnessExportedSurface verifies the exported types, functions, and
// methods of pkg. Exported package-scope variables are rejected up front in
// buildHarnessPkgIndex as the single source of truth.
func verifyHarnessExportedSurface(audited bool, idx *harnessPkgIndex) bool {
	pkgTypes := idx.pkgTypes
	info := idx.info
	allDecls := idx.allDecls
	scope := pkgTypes.Scope()
	if scope == nil {
		return false
	}

	// Exported type T must exist as a struct with zero exported fields.
	tObj, ok := scope.Lookup("T").(*types.TypeName)
	if !ok || tObj == nil || !tObj.Exported() {
		return false
	}
	tNamed, ok := types.Unalias(tObj.Type()).(*types.Named)
	if !ok {
		return false
	}
	tStruct, ok := tNamed.Underlying().(*types.Struct)
	if !ok || !StructHasNoExportedFields(tStruct) {
		return false
	}

	// Exported Check and MakeCheck functions must exist.
	checkFn, ok := scope.Lookup("Check").(*types.Func)
	if !ok || checkFn == nil || !checkFn.Exported() {
		return false
	}
	makeCheckFn, ok := scope.Lookup("MakeCheck").(*types.Func)
	if !ok || makeCheckFn == nil || !makeCheckFn.Exported() {
		return false
	}

	checkedNamed := map[*types.Named]bool{}
	var rule2Queue []*types.Named
	enqueueNamed := func(n *types.Named) {
		if n == nil {
			return
		}
		orig := n.Origin()
		if !checkedNamed[orig] {
			checkedNamed[orig] = true
			rule2Queue = append(rule2Queue, orig)
		}
	}

	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if obj == nil || !obj.Exported() {
			continue
		}
		switch o := obj.(type) {
		case *types.Func:
			sig := o.Signature()
			if !checkHarnessResultTuple(audited, info, allDecls, pkgTypes, tNamed, o, sig, nil, nil, enqueueNamed) {
				return false
			}
		case *types.TypeName:
			if _, isIface := o.Type().Underlying().(*types.Interface); isIface {
				continue
			}
			named, ok := types.Unalias(o.Type()).(*types.Named)
			if !ok {
				continue
			}
			enqueueNamed(named)
		}
	}

	for len(rule2Queue) > 0 {
		cur := rule2Queue[0]
		rule2Queue = rule2Queue[1:]
		if !checkAllExportedMethodsOfNamed(audited, info, allDecls, pkgTypes, tNamed, cur, enqueueNamed) {
			return false
		}
	}

	return true
}

func checkAllExportedMethodsOfNamed(
	audited bool,
	info *types.Info,
	allDecls map[*types.Func]*ast.FuncDecl,
	pkgTypes *types.Package,
	tNamed *types.Named,
	owner *types.Named,
	enqueueNamed func(*types.Named),
) bool {
	if owner == nil {
		return false
	}
	ownerTPs := owner.TypeParams()
	visited := map[types.Type]bool{}
	var walk func(t types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil {
			return true
		}
		t = types.Unalias(t)
		if ptr, ok := t.(*types.Pointer); ok {
			t = types.Unalias(ptr.Elem())
		}
		if visited[t] {
			return true
		}
		visited[t] = true
		if named, ok := t.(*types.Named); ok {
			for i := 0; i < named.NumMethods(); i++ {
				m := named.Method(i)
				if !m.Exported() {
					continue
				}
				if !checkHarnessResultTuple(audited, info, allDecls, pkgTypes, tNamed, m, m.Signature(), owner, ownerTPs, enqueueNamed) {
					return false
				}
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				f := u.Field(i)
				if f.Embedded() {
					if !walk(f.Type()) {
						return false
					}
				}
			}
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				m := u.Method(i)
				if !m.Exported() {
					continue
				}
				if !checkHarnessResultTuple(audited, info, allDecls, pkgTypes, tNamed, m, m.Signature(), owner, ownerTPs, enqueueNamed) {
					return false
				}
			}
		}
		return true
	}
	return walk(owner)
}

func checkHarnessResultTuple(
	audited bool,
	info *types.Info,
	allDecls map[*types.Func]*ast.FuncDecl,
	pkgTypes *types.Package,
	tNamed *types.Named,
	fnObj *types.Func,
	sig *types.Signature,
	recvNamed *types.Named,
	ownerTypeParams *types.TypeParamList,
	enqueueNamed func(*types.Named),
) bool {
	if sig == nil {
		return false
	}
	results := sig.Results()
	for i := 0; i < results.Len(); i++ {
		if !validHarnessExportedResultType(audited, info, allDecls, pkgTypes, tNamed, fnObj, sig, recvNamed, ownerTypeParams, results.At(i).Type(), enqueueNamed) {
			return false
		}
	}
	return true
}

func validHarnessExportedResultType(
	audited bool,
	info *types.Info,
	allDecls map[*types.Func]*ast.FuncDecl,
	pkgTypes *types.Package,
	tNamed *types.Named,
	fnObj *types.Func,
	sig *types.Signature,
	recvNamed *types.Named,
	ownerTypeParams *types.TypeParamList,
	ret types.Type,
	enqueueNamed func(*types.Named),
) bool {
	if ret == nil {
		return false
	}
	unaliased := types.Unalias(ret)

	// 1. Type parameter declared on the generic function or generic receiver itself,
	// provided the callable either requires *T/TB in its parameter list (e.g. Draw),
	// is a pure 1-parameter identity function (e.g. ID[V](v V) V), or is the
	// variadic (*Generator[V]).Example(seed ...int) V method verified to override
	// its PRNG seed from seed[0] when len(seed) > 0.
	if tp, ok := unaliased.(*types.TypeParam); ok {
		inScope := false
		if tps := sig.TypeParams(); tps != nil {
			for i := 0; i < tps.Len(); i++ {
				if tps.At(i) == tp {
					inScope = true
					break
				}
			}
		}
		if !inScope {
			if rtps := sig.RecvTypeParams(); rtps != nil {
				for i := 0; i < rtps.Len(); i++ {
					if rtps.At(i) == tp {
						inScope = true
						break
					}
				}
			}
		}
		if !inScope && ownerTypeParams != nil {
			for i := 0; i < ownerTypeParams.Len(); i++ {
				if ownerTypeParams.At(i) == tp {
					inScope = true
					break
				}
			}
		}
		if !inScope || fnObj == nil {
			return false
		}
		if sigRequiresHarnessHandleOrTB(pkgTypes, tNamed, sig) {
			return true
		}
		fd := allDecls[fnObj.Origin()]
		if sig.Recv() == nil && !sig.Variadic() && sig.Params().Len() == 1 && sig.Results().Len() == 1 &&
			types.Identical(types.Unalias(sig.Params().At(0).Type()), tp) &&
			isPureIdentityFuncDecl(info, fd, sig.Params().At(0)) {
			return true
		}
		if recvNamed != nil && recvNamed.Origin().Obj() != nil &&
			recvNamed.Origin().Obj().Pkg() == pkgTypes && recvNamed.Origin().Obj().Name() == "Generator" &&
			fnObj.Name() == "Example" && sig.Variadic() && sig.Params().Len() == 1 && sig.Results().Len() == 1 &&
			isTypesIntSlice(sig.Params().At(0).Type()) &&
			verifyGeneratorExampleSeedOverride(info, fd, sig.Params().At(0)) {
			return true
		}
		return false
	}

	// 0. Pure value results (scalars, strings, and value arrays/structs of them) that neither
	// carry dynamic dispatch nor hand out pointers, slices, maps, or channels. If a value
	// struct defined in pkgTypes is returned, enqueue it so any promoted exported methods are checked.
	if !refconfine.TypeMayCarryUnknownDynamic(audited, ret) && !typeHandsOutMutableAlias(ret, map[types.Type]bool{}) {
		if named, ok := unaliased.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() == pkgTypes && enqueueNamed != nil {
			enqueueNamed(named)
		}
		return true
	}

	// 2. Pointer to a struct defined in pkgTypes with zero exported or promoted fields
	// (*T, *Generator, *Generator[V], etc.), provided all direct and promoted exported
	// methods on that struct also satisfy this grammar.
	if ptr, ok := unaliased.(*types.Pointer); ok {
		if named, ok := types.Unalias(ptr.Elem()).(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() == pkgTypes {
			if st, ok := named.Underlying().(*types.Struct); ok && StructHasNoExportedFields(st) {
				if enqueueNamed != nil {
					enqueueNamed(named)
				}
				return true
			}
		}
	}

	// 3. Subtest/fuzz/action callback shapes: func(*testing.T), func(*testing.T, []byte), map[string]func(*T).
	if fnSig, ok := unaliased.Underlying().(*types.Signature); ok && fnSig.Recv() == nil && fnSig.Results().Len() == 0 && !fnSig.Variadic() {
		params := fnSig.Params()
		if params.Len() == 1 && isTestingTPtrType(params.At(0).Type()) {
			return true
		}
		if params.Len() == 2 && isTestingTPtrType(params.At(0).Type()) && isTypesByteSlice(params.At(1).Type()) {
			return true
		}
	}
	if mp, ok := unaliased.Underlying().(*types.Map); ok {
		if keyBasic, ok := types.Unalias(mp.Key()).Underlying().(*types.Basic); ok && keyBasic.Kind() == types.String {
			if valSig, ok := types.Unalias(mp.Elem()).Underlying().(*types.Signature); ok &&
				valSig.Recv() == nil && valSig.Results().Len() == 0 && !valSig.Variadic() && valSig.Params().Len() == 1 {
				if ptr, ok := types.Unalias(valSig.Params().At(0).Type()).(*types.Pointer); ok && types.Identical(types.Unalias(ptr.Elem()), tNamed) {
					return true
				}
			}
		}
	}

	// 4. (*T).Context() context.Context and (*T).Output() io.Writer.
	if recvNamed != nil && recvNamed.Origin() == tNamed.Origin() {
		if named, ok := unaliased.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
			p, n := named.Obj().Pkg().Path(), named.Obj().Name()
			if (p == "context" && n == "Context") || (p == "io" && n == "Writer") {
				return true
			}
		}
	}

	return false
}

func sigRequiresHarnessHandleOrTB(pkgTypes *types.Package, tNamed *types.Named, sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	params := sig.Params()
	n := params.Len()
	if sig.Variadic() && n > 0 {
		n--
	}
	for i := 0; i < n; i++ {
		pt := types.Unalias(params.At(i).Type())
		if ptr, isP := pt.(*types.Pointer); isP {
			if named, isN := types.Unalias(ptr.Elem()).(*types.Named); isN && named.Origin() == tNamed.Origin() {
				return true
			}
		}
		if named, isN := pt.(*types.Named); isN && named.Obj() != nil {
			if named.Obj().Pkg() == pkgTypes && named.Obj().Name() == "TB" {
				return true
			}
			if named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "testing" && named.Obj().Name() == "TB" {
				return true
			}
		}
	}
	return false
}

func isPureIdentityFuncDecl(info *types.Info, fd *ast.FuncDecl, param *types.Var) bool {
	if info == nil || fd == nil || fd.Body == nil || param == nil || len(fd.Body.List) != 1 {
		return false
	}
	ret, ok := fd.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	id, ok := ast.Unparen(ret.Results[0]).(*ast.Ident)
	return ok && info.Uses[id] == param
}

func isTypesIntSlice(t types.Type) bool {
	sl, ok := types.Unalias(t).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	b, ok := types.Unalias(sl.Elem()).Underlying().(*types.Basic)
	return ok && b.Kind() == types.Int
}

func verifyGeneratorExampleSeedOverride(info *types.Info, fd *ast.FuncDecl, seedParam *types.Var) bool {
	if info == nil || fd == nil || fd.Body == nil || seedParam == nil || len(fd.Body.List) < 2 {
		return false
	}
	isLenSeedPositive := func(cond ast.Expr) bool {
		bin, ok := ast.Unparen(cond).(*ast.BinaryExpr)
		if !ok {
			return false
		}
		isLenSeed := func(e ast.Expr) bool {
			call, isC := ast.Unparen(e).(*ast.CallExpr)
			if !isC || len(call.Args) != 1 {
				return false
			}
			id, isID := peelHarnessCallee(call.Fun).(*ast.Ident)
			if !isID {
				return false
			}
			b, isB := info.Uses[id].(*types.Builtin)
			if !isB || b.Name() != "len" {
				return false
			}
			argID, isArgID := ast.Unparen(call.Args[0]).(*ast.Ident)
			return isArgID && info.Uses[argID] == seedParam
		}
		isIntConst := func(e ast.Expr, want int64) bool {
			tv, okTV := info.Types[e]
			if !okTV || tv.Value == nil || tv.Value.Kind() != constant.Int {
				return false
			}
			v, exact := constant.Int64Val(tv.Value)
			return exact && v == want
		}
		return (isLenSeed(bin.X) && ((bin.Op == token.GTR && isIntConst(bin.Y, 0)) || (bin.Op == token.NEQ && isIntConst(bin.Y, 0)) || (bin.Op == token.GEQ && isIntConst(bin.Y, 1)))) ||
			(isLenSeed(bin.Y) && ((bin.Op == token.LSS && isIntConst(bin.X, 0)) || (bin.Op == token.NEQ && isIntConst(bin.X, 0)) || (bin.Op == token.LEQ && isIntConst(bin.X, 1))))
	}
	isSeedElem0Expr := func(e ast.Expr) bool {
		cur := ast.Unparen(e)
		if call, isC := cur.(*ast.CallExpr); isC && len(call.Args) == 1 && info.Types[peelHarnessCallee(call.Fun)].IsType() {
			cur = ast.Unparen(call.Args[0])
		}
		idx, isIdx := cur.(*ast.IndexExpr)
		if !isIdx {
			return false
		}
		baseID, isID := ast.Unparen(idx.X).(*ast.Ident)
		if !isID || info.Uses[baseID] != seedParam {
			return false
		}
		tv, okTV := info.Types[idx.Index]
		if !okTV || tv.Value == nil || tv.Value.Kind() != constant.Int {
			return false
		}
		v, exact := constant.Int64Val(tv.Value)
		return exact && v == 0
	}

	// Pattern 1 (rapid@v1.3.0): s := baseSeed(); if len(seed) > 0 { s = uint64(seed[0]) }
	if initAs, okAs := fd.Body.List[0].(*ast.AssignStmt); okAs && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 {
		if sID, okID := ast.Unparen(initAs.Lhs[0]).(*ast.Ident); okID {
			if sVar, okV := info.Defs[sID].(*types.Var); okV && sVar != nil {
				if ifs, okIf := fd.Body.List[1].(*ast.IfStmt); okIf && ifs.Init == nil && ifs.Else == nil &&
					isLenSeedPositive(ifs.Cond) && ifs.Body != nil && len(ifs.Body.List) == 1 {
					if ovAs, okOv := ifs.Body.List[0].(*ast.AssignStmt); okOv && ovAs.Tok == token.ASSIGN && len(ovAs.Lhs) == 1 && len(ovAs.Rhs) == 1 {
						if lhsID, okLID := ast.Unparen(ovAs.Lhs[0]).(*ast.Ident); okLID && info.Uses[lhsID] == sVar && isSeedElem0Expr(ovAs.Rhs[0]) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func isTestingTPtrType(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "testing" && named.Obj().Name() == "T"
}

func isTypesByteSlice(t types.Type) bool {
	sl, ok := types.Unalias(t).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	basic, ok := types.Unalias(sl.Elem()).Underlying().(*types.Basic)
	return ok && basic.Kind() == types.Byte
}

func typeHandsOutMutableAlias(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return true
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() == types.UnsafePointer || u.Kind() == types.Invalid
	case *types.Array:
		return typeHandsOutMutableAlias(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if typeHandsOutMutableAlias(u.Field(i).Type(), seen) {
				return true
			}
		}
		return false
	default:
		return true
	}
}
