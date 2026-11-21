package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func sameExprObjectOrConstString(info *types.Info, a, b ast.Expr) bool {
	if info == nil || a == nil || b == nil {
		return false
	}
	a = ast.Unparen(a)
	b = ast.Unparen(b)
	tva, oka := info.Types[a]
	tvb, okb := info.Types[b]
	if oka && okb && tva.Value != nil && tvb.Value != nil {
		return tva.Value.ExactString() == tvb.Value.ExactString()
	}
	ia, oka := a.(*ast.Ident)
	ib, okb := b.(*ast.Ident)
	if !oka || !okb {
		return false
	}
	oa := info.Uses[ia]
	ob := info.Uses[ib]
	if oa == nil || oa != ob {
		return false
	}
	switch v := oa.(type) {
	case *types.Const:
		return true
	case *types.Var:
		// Only local/parameter variables (never package globals that could be
		// concurrently mutated between StringData(s) and len(s)).
		return v.Pkg() != nil && v.Parent() != nil && v.Parent() != v.Pkg().Scope()
	default:
		return false
	}
}

func isUnmutatedLocalIdentInFile(info *types.Info, file *ast.File, ident *ast.Ident) bool {
	if info == nil || file == nil || ident == nil {
		return false
	}
	obj, ok := info.Uses[ident].(*types.Var)
	if !ok || obj == nil || obj.Parent() == nil || (obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope()) {
		return false
	}
	mutated := false
	ast.Inspect(file, func(n ast.Node) bool {
		if mutated || n == nil {
			return false
		}
		switch s := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range s.Lhs {
				id, ok := ast.Unparen(lhs).(*ast.Ident)
				if !ok {
					continue
				}
				// := defining obj is in info.Defs; same-scope := redeclarations
				// and = assignments record obj in info.Uses and overwrite it.
				if s.Tok == token.DEFINE && info.Defs[id] == obj {
					continue
				}
				if info.Uses[id] == obj {
					mutated = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if id, ok := ast.Unparen(s.X).(*ast.Ident); ok && info.Uses[id] == obj {
				mutated = true
				return false
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND {
				if id, ok := ast.Unparen(s.X).(*ast.Ident); ok && info.Uses[id] == obj {
					mutated = true
					return false
				}
			}
		case *ast.RangeStmt:
			if s.Tok == token.ASSIGN {
				for _, r := range []ast.Expr{s.Key, s.Value} {
					if id, ok := ast.Unparen(r).(*ast.Ident); ok && info.Uses[id] == obj {
						mutated = true
						return false
					}
				}
			}
		}
		return true
	})
	return !mutated
}

func innermostAtomicStmt(parentOf map[ast.Node]ast.Node, n ast.Node) ast.Stmt {
	for anc := parentOf[n]; anc != nil; anc = parentOf[anc] {
		switch anc.(type) {
		case *ast.AssignStmt, *ast.IncDecStmt, *ast.SendStmt, *ast.ExprStmt,
			*ast.ReturnStmt, *ast.DeferStmt, *ast.GoStmt, *ast.DeclStmt,
			*ast.RangeStmt, *ast.ForStmt, *ast.IfStmt, *ast.SwitchStmt, *ast.TypeSwitchStmt:
			return anc.(ast.Stmt)
		}
	}
	return nil
}

func isFreshMakeOrEmptyCompositeExpr(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil {
		return false
	}
	switch x := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		b := syntaxutil.LookupBuiltin(info, x.Fun)
		return b != nil && b.Name() == "make"
	case *ast.CompositeLit:
		return len(x.Elts) == 0
	default:
		return false
	}
}

func isStrictRvalueStarOf(info *types.Info, parentOf map[ast.Node]ast.Node, conv *ast.CallExpr) bool {
	star, ok := parentOf[conv].(*ast.StarExpr)
	if !ok || ast.Unparen(star.X) != conv {
		return false
	}
	cur := ast.Node(star)
	for {
		next := parentOf[cur]
		switch nx := next.(type) {
		case *ast.AssignStmt:
			for _, lhs := range nx.Lhs {
				if ast.Unparen(lhs) == cur {
					return false
				}
			}
			return true
		case *ast.IncDecStmt:
			return ast.Unparen(nx.X) != cur
		case *ast.RangeStmt:
			if nx.Tok == token.ASSIGN && (ast.Unparen(nx.Key) == cur || ast.Unparen(nx.Value) == cur) {
				return false
			}
			return true
		case *ast.UnaryExpr:
			return !(nx.Op == token.AND && ast.Unparen(nx.X) == cur)
		case *ast.SliceExpr:
			if ast.Unparen(nx.X) == cur {
				if expr, isE := cur.(ast.Expr); isE {
					if b, isB := types.Unalias(info.TypeOf(expr)).Underlying().(*types.Basic); isB && b.Kind() == types.String {
						return true
					}
				}
				return false
			}
			return true
		case *ast.SelectorExpr:
			if ast.Unparen(nx.X) == cur {
				sel := info.Selections[nx]
				if sel == nil {
					return false
				}
				if sel.Kind() == types.MethodVal {
					return !SelectionHasPointerReceiver(sel) && !sel.Indirect()
				}
				if sel.Kind() == types.FieldVal {
					cur = nx
					continue
				}
				return false
			}
			return true
		case *ast.IndexExpr:
			if ast.Unparen(nx.X) == cur {
				cur = nx
				continue
			}
			return true
		default:
			return true
		}
	}
}

func verifyLocalAddrIsomorphicCastOrigin(
	p *packages.Package,
	file *ast.File,
	parentOf map[ast.Node]ast.Node,
	castCall *ast.CallExpr,
	addrExpr *ast.UnaryExpr,
	localIdent *ast.Ident,
	lv *types.Var,
	srcElem types.Type,
	dstNamed *types.Named,
	dstDeclPkg *packages.Package,
) (ok bool, fatalHazard string) {
	info := p.TypesInfo
	if okImm, immReason := verifyNamedStructImmutableInDeclPkg(dstNamed, dstDeclPkg, p.Types, true, nil); !okImm {
		return false, "dst struct not immutable in decl pkg: " + dstNamed.String() + " (" + immReason + ")"
	}
	isLocalElemImmutablePtr := func(t types.Type) bool {
		ptr, okP := types.Unalias(t).(*types.Pointer)
		if !okP {
			return false
		}
		en, okEN := types.Unalias(ptr.Elem()).(*types.Named)
		if !okEN || en.Obj() == nil {
			return false
		}
		eust, isESt := en.Underlying().(*types.Struct)
		if !isESt || !structHasNoExportedFieldsDeep(eust) {
			return false
		}
		if en.Obj().Pkg() == p.Types {
			okENImm, _ := verifyNamedStructImmutableInDeclPkg(en, p, p.Types, true, nil)
			return okENImm
		}
		return en.Obj().Exported()
	}

	inLoop := false
	var enclBlock ast.Node = file
	var enclFnType *ast.FuncType
	for anc := parentOf[castCall]; anc != nil; anc = parentOf[anc] {
		switch fn := anc.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			inLoop = true
		case *ast.FuncDecl:
			if enclBlock == file {
				enclBlock = fn
				enclFnType = fn.Type
			}
		case *ast.FuncLit:
			if enclBlock == file {
				enclBlock = fn
				enclFnType = fn.Type
			}
		}
	}
	if inLoop || enclBlock == file {
		return false, ""
	}
	if enclFnType != nil && enclFnType.Results != nil {
		for _, rf := range enclFnType.Results.List {
			for _, nm := range rf.Names {
				if info.Defs[nm] == lv {
					return false, ""
				}
			}
		}
	}

	cleanLocal := true
	if TypeHandsOutMutableReach(srcElem) {
		foundInit := false
		ast.Inspect(enclBlock, func(in ast.Node) bool {
			if !cleanLocal || in == nil {
				return false
			}
			switch s := in.(type) {
			case *ast.AssignStmt:
				for li, lhs := range s.Lhs {
					lid, ok := ast.Unparen(lhs).(*ast.Ident)
					if !ok {
						continue
					}
					if s.Tok == token.DEFINE && info.Defs[lid] == lv {
						if foundInit || len(s.Lhs) != len(s.Rhs) || !isFreshMakeOrEmptyCompositeExpr(info, s.Rhs[li]) {
							cleanLocal = false
							return false
						}
						foundInit = true
					} else if info.Uses[lid] == lv {
						cleanLocal = false
						return false
					}
				}
			case *ast.ValueSpec:
				for vi, name := range s.Names {
					if info.Defs[name] == lv {
						if foundInit || (len(s.Values) != 0 && (len(s.Names) != len(s.Values) || !isFreshMakeOrEmptyCompositeExpr(info, s.Values[vi]))) {
							cleanLocal = false
							return false
						}
						foundInit = true
					}
				}
			}
			return true
		})
		if !foundInit {
			cleanLocal = false
		}
	}

	var checkLocal func(ast.Node)
	checkLocal = func(mn ast.Node) {
		if !cleanLocal || mn == nil {
			return
		}
		switch s := mn.(type) {
		case *ast.LabeledStmt:
			cleanLocal = false
			return
		case *ast.BranchStmt:
			if s.Tok == token.GOTO {
				cleanLocal = false
				return
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND && s != addrExpr && syntaxutil.SubtreeMentionsObj(info, s.X, lv) {
				cleanLocal = false
				return
			}
		case *ast.SliceExpr:
			if syntaxutil.SubtreeMentionsObj(info, s.X, lv) {
				cleanLocal = false
				return
			}
		case *ast.SelectorExpr:
			if sel := info.Selections[s]; sel != nil && sel.Kind() == types.MethodVal && syntaxutil.SubtreeMentionsObj(info, s.X, lv) {
				_, recvIsPtr := types.Unalias(sel.Recv()).(*types.Pointer)
				if recvIsPtr || SelectionHasPointerReceiver(sel) {
					cleanLocal = false
					return
				}
			}
		case *ast.FuncLit:
			if mn != enclBlock {
				ast.Inspect(s.Body, func(cn ast.Node) bool {
					if id2, ok := cn.(*ast.Ident); ok && (info.Uses[id2] == lv || info.Defs[id2] == lv) {
						cleanLocal = false
						return false
					}
					return true
				})
				return
			}
		case *ast.Ident:
			if info.Uses[s] == lv && s != localIdent {
				if s.Pos() > castCall.Pos() {
					cleanLocal = false
					return
				}
				if st := innermostAtomicStmt(parentOf, s); st == nil || st.End() >= castCall.Pos() {
					cleanLocal = false
					return
				}
				if TypeHandsOutMutableReach(srcElem) {
					allowedUse := false
					switch par := parentOf[s].(type) {
					case *ast.IndexExpr:
						if ast.Unparen(par.X) == s {
							elemT := info.TypeOf(par)
							if !TypeHandsOutMutableReach(elemT) {
								allowedUse = true
							} else if !TypeCarriesMutableRefWith(elemT, isLocalElemImmutablePtr) && !typeContainsInterfaceWith(elemT, nil) {
								if as, isAs := parentOf[par].(*ast.AssignStmt); isAs && as.Tok == token.ASSIGN {
									for _, lhs := range as.Lhs {
										if ast.Unparen(lhs) == par {
											allowedUse = true
											break
										}
									}
								}
							}
						}
					case *ast.RangeStmt:
						if ast.Unparen(par.X) == s && (par.Value == nil || syntaxutil.IsBlankIdent(par.Value)) {
							allowedUse = true
						}
					case *ast.CallExpr:
						if len(par.Args) == 1 && !par.Ellipsis.IsValid() && ast.Unparen(par.Args[0]) == s {
							if b := syntaxutil.LookupBuiltin(info, par.Fun); b != nil && (b.Name() == "len" || b.Name() == "cap") {
								allowedUse = true
							}
						}
					}
					if !allowedUse {
						cleanLocal = false
						return
					}
				}
			}
		}
		ast.Inspect(mn, func(ch ast.Node) bool {
			if ch == mn || ch == nil {
				return true
			}
			checkLocal(ch)
			return false
		})
	}
	checkLocal(enclBlock)
	if !cleanLocal {
		return false, ""
	}
	for _, sn := range collectSamePkgNamedStructs(srcElem, p.Types) {
		if okSNImm, _ := verifyNamedStructImmutableInDeclPkg(sn, p, p.Types, true, nil); !okSNImm {
			return false, ""
		}
	}
	return true, ""
}

// PackageHasUnconfinedUnsafeMemoryHazard reports whether package p contains any
// unsafe operation or unsafe.Pointer value/conversion (including through
// imported defined/alias types or conversion-free APIs such as
// reflect.Value.UnsafePointer / reflect.NewAt, without p itself importing
// "unsafe") that is not mechanically proven read-only and layout-safe.
//
// Admitted safe shapes:
//  1. Compile-time layout intrinsics: unsafe.Alignof, unsafe.Offsetof, unsafe.Sizeof.
//  2. Read-only unsafe.StringData(s) pointer-identity comparisons (== / !=) and
//     locally reference-confined read-only unsafe.Slice(unsafe.StringData(s), len(s))
//     projections over a constant or unmutated local string binding s.
//  3. Immediate rvalue scalar bitcast reads *(*Dst)(U(srcPtr)) where
//     IsSafeScalarBitcast(sizes, Src, Dst) holds and the dereference is strictly
//     an rvalue read (never assigned, incremented, &-addressed, array-sliced, or
//     invoking a pointer-receiver method).
//  4. Immediate bijective isomorphic-layout casts (*Dst)(U(srcPtr)) where
//     IsomorphicValueLayout(sizes, Src, Dst) holds and either:
//     (a) the cast is immediately dereferenced as an rvalue read producing a
//     mutable-reach-free, uintptr-free value, or
//     (b) Dst is an all-unexported-field named struct verified write-free and
//     interior-reference-confined in its declaring package, any same-package
//     named structs in Src are similarly verified in p, and if srcPtr is &localVar,
//     localVar is fresh (when carrying mutable reach), not a named result, and
//     never mutated or aliased at or after that cast.
func PackageHasUnconfinedUnsafeMemoryHazard(
	p *packages.Package,
	sizes types.Sizes,
	loadedByTypes map[*types.Package]*packages.Package,
) bool {
	return PackageUnsafeMemoryHazardReason(p, sizes, loadedByTypes) != ""
}

// PackageUnsafeMemoryHazardReason returns "" when every unsafe operation or
// unsafe.Pointer value/conversion in p is mechanically proven read-only and
// layout-safe, or a short non-empty diagnostic reason naming the first hazard.
func PackageUnsafeMemoryHazardReason(
	p *packages.Package,
	sizes types.Sizes,
	loadedByTypes map[*types.Package]*packages.Package,
) string {
	if p == nil || p.Types == nil || p.TypesInfo == nil {
		return "missing package types"
	}
	if sizes == nil {
		sizes = p.TypesSizes
	}
	info := p.TypesInfo

	// Reject generic declarations whose type parameters admit unsafe.Pointer
	// and any declared variable/field/parameter whose type exposes unsafe.Pointer.
	for _, defObj := range info.Defs {
		switch obj := defObj.(type) {
		case *types.TypeName:
			if tp, ok := obj.Type().(*types.TypeParam); ok && typeParamAdmitsUnsafePointer(tp) {
				return "typeparam admits unsafe.Pointer: " + obj.Name()
			}
		case *types.Var:
			if valueTypeExposesUnsafePointer(obj.Type(), p.Types) {
				return "declared var/field exposes unsafe.Pointer: " + obj.Name()
			}
		}
	}
	for _, inst := range info.Instances {
		if inst.TypeArgs != nil {
			for i := 0; i < inst.TypeArgs.Len(); i++ {
				if valueTypeExposesUnsafePointer(inst.TypeArgs.At(i), p.Types) {
					return "generic instantiation exposes unsafe.Pointer: " + inst.TypeArgs.At(i).String()
				}
			}
		}
	}

	declPkgFor := func(tpkg *types.Package) *packages.Package {
		if tpkg == nil {
			return nil
		}
		if tpkg == p.Types {
			return p
		}
		if loadedByTypes != nil {
			return loadedByTypes[tpkg]
		}
		return nil
	}

	var seedExprs map[ast.Expr]bool
	noteSeed := func(e ast.Expr) {
		if seedExprs == nil {
			seedExprs = map[ast.Expr]bool{}
		}
		seedExprs[ast.Unparen(e)] = true
	}

	for _, file := range p.Syntax {
		if file == nil {
			continue
		}
		parentOf := map[ast.Node]ast.Node{}
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if _, isParen := n.(*ast.ParenExpr); !isParen {
				for i := len(stack) - 1; i >= 0; i-- {
					if _, pParen := stack[i].(*ast.ParenExpr); !pParen {
						parentOf[n] = stack[i]
						break
					}
				}
			}
			stack = append(stack, n)
			return true
		})

		approvedUPExpr := map[ast.Expr]bool{}
		hazardReason := ""
		ast.Inspect(file, func(n ast.Node) bool {
			if hazardReason != "" || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.Ident:
				obj := info.Uses[x]
				b, isBuiltin := obj.(*types.Builtin)
				if !isBuiltin || b == nil || b.Pkg() != types.Unsafe {
					return true
				}
				var call *ast.CallExpr
				switch par := parentOf[x].(type) {
				case *ast.CallExpr:
					if ast.Unparen(par.Fun) == x {
						call = par
					}
				case *ast.SelectorExpr:
					if par.Sel == x {
						if gp, ok := parentOf[par].(*ast.CallExpr); ok && ast.Unparen(gp.Fun) == par {
							call = gp
						}
					}
				}
				if call == nil {
					hazardReason = "non-call unsafe builtin: " + b.Name()
					return false
				}
				switch b.Name() {
				case "Alignof", "Offsetof", "Sizeof":
					return true
				case "StringData":
					if len(call.Args) != 1 || call.Ellipsis.IsValid() {
						hazardReason = "StringData bad args"
						return false
					}
					if bin, isBin := parentOf[call].(*ast.BinaryExpr); isBin && (bin.Op == token.EQL || bin.Op == token.NEQ) &&
						(ast.Unparen(bin.X) == call || ast.Unparen(bin.Y) == call) {
						return true
					}
					if outer, isOuter := parentOf[call].(*ast.CallExpr); isOuter && len(outer.Args) == 2 && ast.Unparen(outer.Args[0]) == call {
						if ob := syntaxutil.LookupBuiltin(info, outer.Fun); ob != nil && ob.Pkg() == types.Unsafe && ob.Name() == "Slice" {
							return true
						}
					}
					hazardReason = "standalone unsafe.StringData outside ==/!= or unsafe.Slice(StringData(s), len(s))"
					return false
				case "Slice":
					if len(call.Args) != 2 || call.Ellipsis.IsValid() {
						hazardReason = "Slice bad args"
						return false
					}
					sdCall, isSD := ast.Unparen(call.Args[0]).(*ast.CallExpr)
					if !isSD || len(sdCall.Args) != 1 || sdCall.Ellipsis.IsValid() {
						hazardReason = "Slice arg0 not StringData"
						return false
					}
					sdb := syntaxutil.LookupBuiltin(info, sdCall.Fun)
					if sdb == nil || sdb.Pkg() != types.Unsafe || sdb.Name() != "StringData" {
						hazardReason = "Slice arg0 not unsafe.StringData"
						return false
					}
					lenCall, isLen := ast.Unparen(call.Args[1]).(*ast.CallExpr)
					if !isLen || len(lenCall.Args) != 1 || lenCall.Ellipsis.IsValid() {
						hazardReason = "Slice arg1 not len"
						return false
					}
					lb := syntaxutil.LookupBuiltin(info, lenCall.Fun)
					if lb == nil || lb.Name() != "len" || !sameExprObjectOrConstString(info, sdCall.Args[0], lenCall.Args[0]) {
						hazardReason = "Slice len mismatch"
						return false
					}
					if id, isID := ast.Unparen(sdCall.Args[0]).(*ast.Ident); isID {
						if _, isVar := info.Uses[id].(*types.Var); isVar && !isUnmutatedLocalIdentInFile(info, file, id) {
							hazardReason = "Slice mutable string local"
							return false
						}
					}
					noteSeed(call)
					return true
				default:
					hazardReason = "unsafe builtin: " + b.Name()
					return false
				}

			case *ast.CallExpr:
				if approvedUPExpr[x] {
					return true
				}
				tv, ok := info.Types[x.Fun]
				if !ok || !tv.IsType() || len(x.Args) != 1 || x.Ellipsis.IsValid() {
					return true
				}
				dstType := tv.Type
				argExpr := ast.Unparen(x.Args[0])
				srcType := info.TypeOf(argExpr)
				if dstType == nil || srcType == nil {
					hazardReason = "nil conv type"
					return false
				}
				dstIsUP := isUnderlyingUnsafePointer(dstType)
				srcIsUP := isUnderlyingUnsafePointer(srcType)
				if !dstIsUP && !srcIsUP {
					return true
				}
				if dstIsUP && isUntypedNilExpr(info, argExpr) {
					approvedUPExpr[x] = true
					return true
				}
				if dstIsUP {
					outerCall, ok := parentOf[x].(*ast.CallExpr)
					if !ok || len(outerCall.Args) != 1 || outerCall.Ellipsis.IsValid() || ast.Unparen(outerCall.Args[0]) != x {
						hazardReason = "standalone conversion into unsafe.Pointer"
						return false
					}
					otv, ok := info.Types[outerCall.Fun]
					if !ok || !otv.IsType() || isUnderlyingUnsafePointer(otv.Type) {
						hazardReason = "outer conversion not out of unsafe.Pointer"
						return false
					}
					return true
				}
				innerCall, ok := argExpr.(*ast.CallExpr)
				if !ok || len(innerCall.Args) != 1 || innerCall.Ellipsis.IsValid() {
					hazardReason = "conversion from non-immediate unsafe.Pointer"
					return false
				}
				itv, ok := info.Types[innerCall.Fun]
				if !ok || !itv.IsType() || !isUnderlyingUnsafePointer(itv.Type) {
					hazardReason = "inner call not unsafe.Pointer type conv"
					return false
				}
				origExpr := ast.Unparen(innerCall.Args[0])
				if isUntypedNilExpr(info, origExpr) {
					approvedUPExpr[innerCall] = true
					return true
				}
				origPtr, okOrig := types.Unalias(info.TypeOf(origExpr)).(*types.Pointer)
				dstPtr, okDst := types.Unalias(dstType).(*types.Pointer)
				if !okOrig || !okDst || sizes == nil {
					hazardReason = "non-pointer cast endpoint"
					return false
				}
				srcElem := origPtr.Elem()
				dstElem := dstPtr.Elem()

				if IsSafeScalarBitcast(sizes, srcElem, dstElem) && isStrictRvalueStarOf(info, parentOf, x) {
					approvedUPExpr[innerCall] = true
					return true
				}
				if IsomorphicValueLayout(sizes, srcElem, dstElem) {
					if isStrictRvalueStarOf(info, parentOf, x) && !TypeHandsOutMutableReach(dstElem) && !syntaxutil.ContainsUintptr(dstElem) {
						approvedUPExpr[innerCall] = true
						return true
					}
					if dstNamed, okN := types.Unalias(dstElem).(*types.Named); okN && dstNamed.Obj() != nil {
						if dstSt, okSt := dstNamed.Underlying().(*types.Struct); okSt {
							if !structHasNoExportedFieldsDeep(dstSt) {
								hazardReason = "dst struct has exported fields: " + dstNamed.String()
								return false
							}
							dstDeclPkg := declPkgFor(dstNamed.Obj().Pkg())
							srcOriginOK := false
							if un, isAddr := origExpr.(*ast.UnaryExpr); isAddr && un.Op == token.AND {
								if id, isID := ast.Unparen(un.X).(*ast.Ident); isID {
									if lv, isVar := info.Uses[id].(*types.Var); isVar && lv != nil && lv.Parent() != nil && (lv.Pkg() == nil || lv.Parent() != lv.Pkg().Scope()) {
										okLocal, fatalReason := verifyLocalAddrIsomorphicCastOrigin(p, file, parentOf, x, un, id, lv, srcElem, dstNamed, dstDeclPkg)
										if fatalReason != "" {
											hazardReason = fatalReason
											return false
										}
										srcOriginOK = okLocal
									}
								}
							} else if srcNamed, okSN := types.Unalias(srcElem).(*types.Named); okSN && srcNamed.Obj() != nil {
								if srcSt, okSrcSt := srcNamed.Underlying().(*types.Struct); okSrcSt &&
									structHasNoExportedFieldsDeep(srcSt) {
									srcDeclPkg := declPkgFor(srcNamed.Obj().Pkg())
									var exemptIface func(*types.Interface) bool
									if srcNamed.Obj().Pkg() == p.Types && !srcNamed.Obj().Exported() {
										exemptIface = capsulePubliclyConstructedIfacePred(dstNamed, dstDeclPkg)
									}
									if okDstImm, immReason := verifyNamedStructImmutableInDeclPkg(dstNamed, dstDeclPkg, p.Types, false, exemptIface); !okDstImm {
										hazardReason = "dst struct not immutable in decl pkg: " + dstNamed.String() + " (" + immReason + ")"
										return false
									}
									if okSNImm, _ := verifyNamedStructImmutableInDeclPkg(srcNamed, srcDeclPkg, p.Types, false, exemptIface); okSNImm {
										srcOriginOK = true
									}
								}
							}
							if srcOriginOK {
								approvedUPExpr[innerCall] = true
								return true
							}
							hazardReason = "src origin not clean for isomorphic cast to " + dstNamed.String()
							return false
						}
					}
				}
				hazardReason = "unapproved unsafe.Pointer conversion: " + srcElem.String() + " -> " + dstElem.String()
				return false
			}
			return true
		})
		if hazardReason != "" {
			return hazardReason
		}

		// Sweep all runtime value expressions in file so conversion-free
		// unsafe.Pointer channels (e.g. reflect.Value.UnsafePointer + reflect.NewAt,
		// sync/atomic.*Pointer, or composite unsafe.Pointer carriers) cannot bypass
		// conversion inspection.
		ast.Inspect(file, func(n ast.Node) bool {
			if hazardReason != "" || n == nil {
				return false
			}
			expr, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			unp := ast.Unparen(expr)
			if approvedUPExpr[unp] {
				return true
			}
			tv, ok := info.Types[expr]
			if !ok || !tv.IsValue() || tv.Type == nil {
				return true
			}
			if valueTypeExposesUnsafePointer(tv.Type, p.Types) {
				hazardReason = "unapproved unsafe.Pointer value expression: " + tv.Type.String()
				return false
			}
			return true
		})
		if hazardReason != "" {
			return hazardReason
		}
	}

	if len(seedExprs) > 0 {
		idx := BuildPkgIndex(p)
		if !VerifyReadOnlyRefConfinement(p, Config{
			Index: idx,
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				if seedExprs[ast.Unparen(expr)] {
					return true, true
				}
				return false, false
			},
			AllowCallArg: func(call *ast.CallExpr, _ int, _ ast.Expr) bool {
				return isReadOnlyStdSliceCall(info, call)
			},
		}) {
			return "StringData/Slice confinement failed"
		}
	}

	return ""
}
