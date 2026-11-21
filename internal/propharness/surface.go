package propharness

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// verifyHarnessExportedSurface verifies the exported types, functions, and
// methods of a candidate harness package against the closed return grammar and
// variadic-seed override discipline.
func verifyHarnessExportedSurface(audited bool, g *harnessGraph) (bool, string) {
	pkgTypes := g.pkgTypes
	info := g.info
	allDecls := g.allDecls
	sc := g.screen
	scope := pkgTypes.Scope()
	if scope == nil {
		return false, "missing package scope"
	}

	// Every discovered variadic-seed sample method must mechanically override its
	// PRNG seed from seed[0] whenever len(seed) > 0.
	for mOrig := range sc.seededMethods {
		fd := allDecls[mOrig]
		sig := mOrig.Signature()
		if fd == nil || sig == nil || sig.Params().Len() != 1 {
			return false, "seeded sample method failed seed-override check: " + mOrig.Name()
		}
		baseCall, okOv := verifyGeneratorSeedOverride(info, pkgTypes, fd, sig.Params().At(0))
		if !okOv {
			return false, "seeded sample method failed seed-override check: " + mOrig.Name()
		}
		if baseCall != nil {
			sc.seededBaseSeedCalls[baseCall] = true
		}
	}

	checkedNamed := map[*types.Named]bool{}
	var namedQueue []*types.Named
	enqueueNamed := func(n *types.Named) {
		if n == nil {
			return
		}
		orig := n.Origin()
		if !checkedNamed[orig] {
			checkedNamed[orig] = true
			namedQueue = append(namedQueue, orig)
		}
	}

	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if obj == nil || !obj.Exported() {
			continue
		}
		switch o := obj.(type) {
		case *types.Func:
			if !checkHarnessResultTuple(audited, g, o, o.Signature(), nil, nil, enqueueNamed) {
				return false, "disallowed result type on exported func " + o.Name()
			}
		case *types.TypeName:
			if _, isIface := o.Type().Underlying().(*types.Interface); isIface {
				continue
			}
			if named, ok := types.Unalias(o.Type()).(*types.Named); ok {
				enqueueNamed(named)
			}
		}
	}

	for len(namedQueue) > 0 {
		cur := namedQueue[0]
		namedQueue = namedQueue[1:]
		if !checkAllExportedMethodsOfNamed(audited, g, cur, enqueueNamed) {
			return false, "disallowed exported method result on type " + cur.Obj().Name()
		}
	}
	return true, ""
}

func discoverReflectSynthFuncs(g *harnessGraph) {
	if len(g.reflectSynthSeeds) == 0 {
		return
	}
	visited := map[*types.Func]bool{}
	var queue []*types.Func
	for fn := range g.reflectSynthSeeds {
		visited[fn] = true
		queue = append(queue, fn)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.Exported() {
			g.screen.vp.ReflectSynthFuncs[cur.Name()] = true
		}
		for caller := range g.strictCallersOf[cur] {
			if !visited[caller] {
				visited[caller] = true
				queue = append(queue, caller)
			}
		}
	}
}

func checkAllExportedMethodsOfNamed(
	audited bool,
	g *harnessGraph,
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
				if m.Exported() && !checkHarnessResultTuple(audited, g, m, m.Signature(), owner, ownerTPs, enqueueNamed) {
					return false
				}
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if f := u.Field(i); f.Embedded() && !walk(f.Type()) {
					return false
				}
			}
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				m := u.Method(i)
				if m.Exported() && !checkHarnessResultTuple(audited, g, m, m.Signature(), owner, ownerTPs, enqueueNamed) {
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
	g *harnessGraph,
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
		if !validHarnessExportedResultType(audited, g, fnObj, sig, recvNamed, ownerTypeParams, results.At(i).Type(), enqueueNamed) {
			return false
		}
	}
	return true
}

func validHarnessExportedResultType(
	audited bool,
	g *harnessGraph,
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
	sc := g.screen
	pkgTypes := g.pkgTypes
	unaliased := types.Unalias(ret)

	// 1. Type parameter declared on the generic function or generic receiver:
	// allowed ONLY when guarded by a sealed execution handle (*H where H is a
	// discovered HandleStruct, or stdlib *testing.T/*testing.B/*testing.F/testing.TB;
	// NEVER an unsealed HandleIface), a pure 1-arg identity function, or a
	// verified SeededSampleMethod.
	if tp, ok := unaliased.(*types.TypeParam); ok {
		if !typeParamInCallableScope(tp, sig, ownerTypeParams) || fnObj == nil {
			return false
		}
		if sigRequiresSealedHarnessHandle(sc, sig, false) {
			return true
		}
		fd := g.allDecls[fnObj.Origin()]
		if sig.Recv() == nil && !sig.Variadic() && sig.Params().Len() == 1 && sig.Results().Len() == 1 &&
			types.Identical(types.Unalias(sig.Params().At(0).Type()), tp) &&
			isPureIdentityFuncDecl(g.info, fd, sig.Params().At(0)) {
			return true
		}
		return sc.seededMethods[fnObj.Origin()]
	}

	// 2. Carrier-free value results that hand out zero mutable reach.
	if !refconfine.TypeMayCarryUnknownDynamic(audited, ret) && !refconfine.TypeHandsOutMutableReach(ret) {
		if named, ok := unaliased.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() == pkgTypes && enqueueNamed != nil {
			enqueueNamed(named)
		}
		return true
	}

	// 3. Pointer to a struct defined in pkgTypes with zero exported/promoted fields.
	// Returning a HandleStruct pointer (*H) requires a sealed execution handle in
	// sig so callers cannot mint a detached *H outside a test execution context.
	if ptr, ok := unaliased.(*types.Pointer); ok {
		if named, ok := types.Unalias(ptr.Elem()).(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() == pkgTypes {
			if st, ok := named.Underlying().(*types.Struct); ok && StructHasNoExportedFields(st) {
				if sc.handleStructs[named.Origin()] && !sigRequiresSealedHarnessHandle(sc, sig, true) {
					return false
				}
				if enqueueNamed != nil {
					enqueueNamed(named)
				}
				return true
			}
		}
	}

	// 4. Subtest/fuzz/state-machine callback shapes:
	// func(*testing.T), func(*testing.T, []byte), or map[string]func(*H).
	if isTestingWrapperReturnSig(unaliased) {
		return true
	}
	if mp, ok := unaliased.Underlying().(*types.Map); ok {
		if keyBasic, ok := types.Unalias(mp.Key()).Underlying().(*types.Basic); ok && keyBasic.Kind() == types.String {
			if valSig, ok := types.Unalias(mp.Elem()).Underlying().(*types.Signature); ok &&
				valSig.Recv() == nil && valSig.Results().Len() == 0 && !valSig.Variadic() &&
				valSig.Params().Len() == 1 && sc.isHandleStructPtr(valSig.Params().At(0).Type()) {
				return true
			}
		}
	}

	// 5. HandleStruct methods returning context.Context or io.Writer.
	if recvNamed != nil && sc.handleStructs[recvNamed.Origin()] {
		if named, ok := unaliased.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
			p, n := named.Obj().Pkg().Path(), named.Obj().Name()
			if (p == "context" && n == "Context") || (p == "io" && n == "Writer") {
				return true
			}
		}
	}

	return false
}

func typeParamInCallableScope(tp *types.TypeParam, sig *types.Signature, ownerTypeParams *types.TypeParamList) bool {
	for _, list := range []*types.TypeParamList{sig.TypeParams(), sig.RecvTypeParams(), ownerTypeParams} {
		if list == nil {
			continue
		}
		for i := 0; i < list.Len(); i++ {
			if list.At(i) == tp {
				return true
			}
		}
	}
	return false
}

// sigRequiresSealedHarnessHandle reports whether sig requires a sealed
// execution handle (*H where H is a discovered HandleStruct, or stdlib
// *testing.T/*testing.B/*testing.F/testing.TB). Unsealed package-defined
// HandleIfaces are intentionally excluded because arbitrary user types may
// implement them outside a test execution context.
func sigRequiresSealedHarnessHandle(sc *harnessScreen, sig *types.Signature, checkRecv bool) bool {
	if sig == nil {
		return false
	}
	isSealed := func(t types.Type) bool {
		return sc.isHandleStructPtr(t) || isTestingHandlePtrType(t) || isTestingTBType(t)
	}
	if checkRecv && sig.Recv() != nil && isSealed(sig.Recv().Type()) {
		return true
	}
	params := sig.Params()
	n := params.Len()
	if sig.Variadic() && n > 0 {
		n--
	}
	for i := 0; i < n; i++ {
		if isSealed(params.At(i).Type()) {
			return true
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

func verifyGeneratorSeedOverride(info *types.Info, pkgTypes *types.Package, fd *ast.FuncDecl, seedParam *types.Var) (*ast.CallExpr, bool) {
	if info == nil || fd == nil || fd.Body == nil || seedParam == nil || len(fd.Body.List) < 3 {
		return nil, false
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
			b := syntaxutil.LookupBuiltin(info, syntaxutil.UnwrapCallee(call.Fun))
			if b == nil || b.Name() != "len" {
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
		if call, isC := cur.(*ast.CallExpr); isC && len(call.Args) == 1 && info.Types[syntaxutil.UnwrapCallee(call.Fun)].IsType() {
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
	matchBaseSeedCall := func(e ast.Expr) (*ast.CallExpr, bool) {
		c, isC := ast.Unparen(e).(*ast.CallExpr)
		if !isC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
			return nil, false
		}
		callee := resolveHarnessFuncExpr(info, c.Fun)
		if callee == nil || callee.Pkg() != pkgTypes || callee.Exported() || callee.Signature() == nil || callee.Signature().Recv() != nil {
			return nil, false
		}
		return c, true
	}

	var sVar *types.Var
	var baseSeedCall *ast.CallExpr
	switch st0 := fd.Body.List[0].(type) {
	case *ast.AssignStmt:
		// Pattern 1: s := baseSeed(); if len(seed) > 0 { s = uint64(seed[0]) }
		if st0.Tok == token.DEFINE && len(st0.Lhs) == 1 && len(st0.Rhs) == 1 {
			if sID, okID := ast.Unparen(st0.Lhs[0]).(*ast.Ident); okID {
				if cand, okV := info.Defs[sID].(*types.Var); okV && cand != nil {
					if ifs, okIf := fd.Body.List[1].(*ast.IfStmt); okIf && ifs.Init == nil && ifs.Else == nil &&
						isLenSeedPositive(ifs.Cond) && ifs.Body != nil && len(ifs.Body.List) == 1 {
						if ovAs, okOv := ifs.Body.List[0].(*ast.AssignStmt); okOv && ovAs.Tok == token.ASSIGN && len(ovAs.Lhs) == 1 && len(ovAs.Rhs) == 1 {
							if lhsID, okLID := ast.Unparen(ovAs.Lhs[0]).(*ast.Ident); okLID && info.Uses[lhsID] == cand && isSeedElem0Expr(ovAs.Rhs[0]) {
								if bc, okBC := matchBaseSeedCall(st0.Rhs[0]); okBC {
									sVar = cand
									baseSeedCall = bc
								}
							}
						}
					}
				}
			}
		}
	case *ast.DeclStmt:
		// Pattern 2: var s uint64; if len(seed) > 0 { s = uint64(seed[0]) } else { s = baseSeed() }
		gd, okGD := st0.Decl.(*ast.GenDecl)
		if okGD && gd.Tok == token.VAR && len(gd.Specs) == 1 {
			if vs, okVS := gd.Specs[0].(*ast.ValueSpec); okVS && len(vs.Names) == 1 && len(vs.Values) == 0 {
				if cand, okV := info.Defs[vs.Names[0]].(*types.Var); okV && cand != nil {
					if ifs, okIf := fd.Body.List[1].(*ast.IfStmt); okIf && ifs.Init == nil &&
						isLenSeedPositive(ifs.Cond) && ifs.Body != nil && len(ifs.Body.List) == 1 {
						if elseBlk, okEB := ifs.Else.(*ast.BlockStmt); okEB && len(elseBlk.List) == 1 {
							ovThen, okT := ifs.Body.List[0].(*ast.AssignStmt)
							ovElse, okE := elseBlk.List[0].(*ast.AssignStmt)
							if okT && okE && ovThen.Tok == token.ASSIGN && ovElse.Tok == token.ASSIGN &&
								len(ovThen.Lhs) == 1 && len(ovThen.Rhs) == 1 && len(ovElse.Lhs) == 1 && len(ovElse.Rhs) == 1 {
								tID, okTID := ast.Unparen(ovThen.Lhs[0]).(*ast.Ident)
								eID, okEID := ast.Unparen(ovElse.Lhs[0]).(*ast.Ident)
								if okTID && okEID && info.Uses[tID] == cand && info.Uses[eID] == cand && isSeedElem0Expr(ovThen.Rhs[0]) {
									if bc, okBC := matchBaseSeedCall(ovElse.Rhs[0]); okBC {
										sVar = cand
										baseSeedCall = bc
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if sVar == nil {
		return nil, false
	}

	// Ensure sVar is actually read in the remainder of the method body and is
	// never reassigned or address-taken after statement 1.
	usedAfter := false
	reassignedAfter := false
	for _, rem := range fd.Body.List[2:] {
		ast.Inspect(rem, func(n ast.Node) bool {
			if reassignedAfter || n == nil {
				return false
			}
			switch s := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range s.Lhs {
					if id, ok := ast.Unparen(lhs).(*ast.Ident); ok && (info.Uses[id] == sVar || info.Defs[id] == sVar) {
						reassignedAfter = true
						return false
					}
				}
			case *ast.IncDecStmt:
				if id, ok := ast.Unparen(s.X).(*ast.Ident); ok && info.Uses[id] == sVar {
					reassignedAfter = true
					return false
				}
			case *ast.UnaryExpr:
				if s.Op == token.AND {
					if id, ok := ast.Unparen(s.X).(*ast.Ident); ok && info.Uses[id] == sVar {
						reassignedAfter = true
						return false
					}
				}
			case *ast.Ident:
				if info.Uses[s] == sVar {
					usedAfter = true
				}
			}
			return true
		})
	}
	if !usedAfter || reassignedAfter {
		return nil, false
	}
	return baseSeedCall, true
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

func isTestingHandlePtrType(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return false
	}
	switch named.Obj().Name() {
	case "T", "B", "F":
		return true
	}
	return false
}

func isTestingTBType(t types.Type) bool {
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "testing" && named.Obj().Name() == "TB"
}

func resolveHarnessFuncExpr(info *types.Info, e ast.Expr) *types.Func {
	switch x := syntaxutil.UnwrapCallee(e).(type) {
	case *ast.Ident:
		fn, _ := info.Uses[x].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		if sel := info.Selections[x]; sel != nil {
			fn, _ := sel.Obj().(*types.Func)
			return fn
		}
		if x.Sel != nil {
			fn, _ := info.Uses[x.Sel].(*types.Func)
			return fn
		}
	}
	return nil
}

func recvNamedTypeName(sig *types.Signature) (pkgPath, typeName string) {
	if sig == nil || sig.Recv() == nil {
		return "", ""
	}
	rt := types.Unalias(sig.Recv().Type())
	if ptr, ok := rt.(*types.Pointer); ok {
		rt = types.Unalias(ptr.Elem())
	}
	named, ok := rt.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return "", ""
	}
	return named.Obj().Pkg().Path(), named.Obj().Name()
}
