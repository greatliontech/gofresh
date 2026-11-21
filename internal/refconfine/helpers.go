package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// IsDirectMutableRef reports whether t is directly a slice, map, pointer,
// channel, or unsafe.Pointer handle to shared backing state.
func IsDirectMutableRef(t types.Type) bool {
	return IsDirectMutableRefWith(t, nil)
}

// IsDirectMutableRefWith is like IsDirectMutableRef, treating pointers matched
// by isImmutablePtr as non-mutable handles.
func IsDirectMutableRefWith(t types.Type, isImmutablePtr func(types.Type) bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if isImmutablePtr != nil && isImmutablePtr(t) {
		return false
	}
	switch u := t.Underlying().(type) {
	case *types.Slice, *types.Map, *types.Pointer, *types.Chan:
		return true
	case *types.Basic:
		return u.Kind() == types.UnsafePointer
	}
	return false
}

// TypeCarriesMutableRef reports whether t is a direct mutable reference/pointer
// or a struct/array value that recursively contains one.
func TypeCarriesMutableRef(t types.Type) bool {
	return TypeCarriesMutableRefWith(t, nil)
}

// TypeCarriesMutableRefWith is like TypeCarriesMutableRef, treating pointers
// matched by isImmutablePtr as non-mutable handles.
func TypeCarriesMutableRefWith(root types.Type, isImmutablePtr func(types.Type) bool) bool {
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if isImmutablePtr != nil && isImmutablePtr(t) {
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if IsDirectMutableRefWith(t, isImmutablePtr) {
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
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				walk(u.At(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

// TypeContainsRefOrPointer reports whether t contains any direct mutable
// reference/pointer, interface, function signature, or type parameter.
func TypeContainsRefOrPointer(root types.Type) bool {
	return TypeContainsRefOrPointerWith(root, nil)
}

// TypeContainsRefOrPointerWith is like TypeContainsRefOrPointer, treating
// pointers matched by isImmutablePtr as non-mutable handles.
func TypeContainsRefOrPointerWith(root types.Type, isImmutablePtr func(types.Type) bool) bool {
	if root == nil {
		return true
	}
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if hit {
			return
		}
		if t == nil {
			hit = true
			return
		}
		t = types.Unalias(t)
		if isImmutablePtr != nil && isImmutablePtr(t) {
			return
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if IsDirectMutableRefWith(t, isImmutablePtr) {
			hit = true
			return
		}
		switch u := t.Underlying().(type) {
		case *types.Interface, *types.Signature, *types.TypeParam:
			hit = true
		case *types.Array:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				walk(u.At(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func indexValueTypeFromType(t types.Type) types.Type {
	if tup, isTup := t.(*types.Tuple); isTup && tup.Len() > 0 {
		return tup.At(0).Type()
	}
	return t
}

func callValueErasesSeedStruct(
	v *flowir.Value,
	seedStructTypeViolated func(dstT, srcT types.Type) bool,
	allowCallArg func(call *ast.CallExpr, argIdx int, arg ast.Expr) bool,
) bool {
	if v == nil || v.Kind != flowir.ValCall || v.IsConst {
		return false
	}
	if v.CallKind == flowir.CallBuiltin {
		switch v.BuiltinName {
		case "len", "cap", "Sizeof", "Alignof", "Offsetof":
			return false
		case "append":
			if len(v.Args) >= 2 && v.Args[0] != nil && v.Args[0].Type != nil {
				dstSlice := v.Args[0].Type
				if sl, okSl := types.Unalias(dstSlice).Underlying().(*types.Slice); okSl {
					if v.Ellipsis {
						return v.Args[1] != nil && seedStructTypeViolated(dstSlice, v.Args[1].Type)
					}
					for _, arg := range v.Args[1:] {
						if arg != nil && seedStructTypeViolated(sl.Elem(), arg.Type) {
							return true
						}
					}
				}
			}
			return false
		default:
			for i, arg := range v.Args {
				if arg == nil {
					continue
				}
				if v.CallAST != nil && i < len(v.CallAST.Args) && allowCallArg != nil && allowCallArg(v.CallAST, i, v.CallAST.Args[i]) {
					continue
				}
				if seedStructTypeViolated(nil, arg.Type) {
					return true
				}
			}
			return false
		}
	}

	var originSig *types.Signature
	if v.CalleeFunc != nil && v.CalleeFunc.Origin() != nil {
		if sig, ok := v.CalleeFunc.Origin().Type().(*types.Signature); ok && sig != v.CalleeSig {
			originSig = sig
		}
	}

	formalOriginSlot := func(sig *types.Signature, paramIdx int, packedVariadic bool) types.Type {
		if sig == nil || sig.Params() == nil || paramIdx < 0 || paramIdx >= sig.Params().Len() {
			return nil
		}
		pt := sig.Params().At(paramIdx).Type()
		if packedVariadic && pt != nil {
			if sl, isSl := syntaxutil.UnderlyingType(pt).(*types.Slice); isSl {
				return sl.Elem()
			}
		}
		return pt
	}

	if v.IsMethodExprCall {
		var mExprSig *types.Signature
		if v.Selection != nil {
			mExprSig, _ = syntaxutil.UnderlyingType(v.Selection.Type()).(*types.Signature)
		}
		if v.Recv != nil && len(v.Args) == 0 && v.CallAST != nil && len(v.CallAST.Args) == 1 && !v.Ellipsis {
			if tup, isTup := types.Unalias(v.Recv.Type).(*types.Tuple); isTup && tup.Len() > 1 {
				for ti := 0; ti < tup.Len(); ti++ {
					packed := mExprSig != nil && mExprSig.Variadic() && mExprSig.Params() != nil && ti >= mExprSig.Params().Len()-1
					pIdx := ti
					if packed {
						pIdx = mExprSig.Params().Len() - 1
					}
					dstT := formalOriginSlot(mExprSig, pIdx, packed)
					if seedStructTypeViolated(dstT, tup.At(ti).Type()) {
						return true
					}
					if originSig != nil {
						if ti == 0 && originSig.Recv() != nil {
							if seedStructTypeViolated(originSig.Recv().Type(), tup.At(ti).Type()) {
								return true
							}
						} else if ti > 0 {
							opIdx := ti - 1
							oPacked := originSig.Variadic() && originSig.Params() != nil && opIdx >= originSig.Params().Len()-1
							if oPacked {
								opIdx = originSig.Params().Len() - 1
							}
							if origT := formalOriginSlot(originSig, opIdx, oPacked); origT != nil && seedStructTypeViolated(origT, tup.At(ti).Type()) {
								return true
							}
						}
					}
				}
				return false
			}
		}
		if v.Recv != nil {
			if !(v.CallAST != nil && len(v.CallAST.Args) > 0 && allowCallArg != nil && allowCallArg(v.CallAST, 0, v.CallAST.Args[0])) {
				var recvDstT types.Type
				if mExprSig != nil && mExprSig.Params() != nil && mExprSig.Params().Len() > 0 {
					recvDstT = mExprSig.Params().At(0).Type()
				}
				if seedStructTypeViolated(recvDstT, v.Recv.Type) {
					return true
				}
				if originSig != nil && originSig.Recv() != nil && seedStructTypeViolated(originSig.Recv().Type(), v.Recv.Type) {
					return true
				}
			}
		}
		violated := false
		v.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, slotIdx int, paramIdx int, ok bool, packedVariadic bool) bool {
			rawIdx := slotIdx + 1
			if v.CallAST != nil && len(v.Args) == len(v.CallAST.Args)-1 && rawIdx < len(v.CallAST.Args) &&
				allowCallArg != nil && allowCallArg(v.CallAST, rawIdx, v.CallAST.Args[rawIdx]) {
				return true
			}
			var dstT types.Type
			if ok {
				dstT = v.FormalParamSlotType(paramIdx, packedVariadic)
			}
			if seedStructTypeViolated(dstT, slotType) {
				violated = true
				return false
			}
			if ok && originSig != nil {
				if origT := formalOriginSlot(originSig, paramIdx, packedVariadic); origT != nil && seedStructTypeViolated(origT, slotType) {
					violated = true
					return false
				}
			}
			return true
		})
		return violated
	}

	if v.CalleeSig == nil {
		for i, arg := range v.Args {
			if arg == nil {
				continue
			}
			if v.CallAST != nil && i < len(v.CallAST.Args) && allowCallArg != nil && allowCallArg(v.CallAST, i, v.CallAST.Args[i]) {
				continue
			}
			if seedStructTypeViolated(nil, arg.Type) {
				return true
			}
		}
		return false
	}

	isTupleUnpack := len(v.Args) == 1 && !v.Ellipsis && v.Args[0] != nil && v.Args[0].Type != nil
	if isTupleUnpack {
		_, isTupleUnpack = types.Unalias(v.Args[0].Type).(*types.Tuple)
	}
	violated := false
	v.ForEachArgParam(func(arg *flowir.Value, slotType types.Type, slotIdx int, paramIdx int, ok bool, packedVariadic bool) bool {
		if !isTupleUnpack && v.CallAST != nil && slotIdx < len(v.CallAST.Args) &&
			allowCallArg != nil && allowCallArg(v.CallAST, slotIdx, v.CallAST.Args[slotIdx]) {
			return true
		}
		var dstT types.Type
		if ok {
			dstT = v.FormalParamSlotType(paramIdx, packedVariadic)
		}
		if seedStructTypeViolated(dstT, slotType) {
			violated = true
			return false
		}
		if ok && originSig != nil {
			if origT := formalOriginSlot(originSig, paramIdx, packedVariadic); origT != nil && seedStructTypeViolated(origT, slotType) {
				violated = true
				return false
			}
		}
		return true
	})
	return violated
}

// IdentIsWrittenOrAddrTaken reports whether id appears on the LHS of an
// assignment/inc-dec/range-assign or as the operand of &id.
func IdentIsWrittenOrAddrTaken(idx *PkgIndex, id *ast.Ident) bool {
	if idx == nil || id == nil {
		return false
	}
	if pn, ok := idx.ParentUnparen(id).(*ast.UnaryExpr); ok && pn.Op == token.AND {
		return true
	}
	return IdentOrExprIsWritten(idx, id)
}

// IdentOrExprIsWritten reports whether target appears directly on the LHS of an
// assignment, inc-dec statement, or range assignment.
func IdentOrExprIsWritten(idx *PkgIndex, target ast.Expr) bool {
	if idx == nil || target == nil {
		return false
	}
	switch pn := idx.ParentUnparen(target).(type) {
	case *ast.AssignStmt:
		for _, lhs := range pn.Lhs {
			if ast.Unparen(lhs) == target {
				return true
			}
		}
	case *ast.IncDecStmt:
		if ast.Unparen(pn.X) == target {
			return true
		}
	case *ast.RangeStmt:
		if pn.Tok == token.ASSIGN {
			if (pn.Key != nil && ast.Unparen(pn.Key) == target) ||
				(pn.Value != nil && ast.Unparen(pn.Value) == target) {
				return true
			}
		}
	}
	return false
}

// ExprPrefixIsWrittenOrAddrTaken reports whether expr (or any field, index,
// slice, or dereference projection rooted at expr) is written, passed as the
// target of delete/clear/copy/append, or explicitly address-taken.
func ExprPrefixIsWrittenOrAddrTaken(p *packages.Package, idx *PkgIndex, expr ast.Expr) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || expr == nil {
		return false
	}
	cur := expr
	for {
		par := idx.ParentUnparen(cur)
		if par == nil {
			return false
		}
		switch x := par.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if ast.Unparen(lhs) == cur {
					return true
				}
			}
			return false
		case *ast.IncDecStmt:
			return ast.Unparen(x.X) == cur
		case *ast.RangeStmt:
			return x.Tok == token.ASSIGN && ((x.Key != nil && ast.Unparen(x.Key) == cur) || (x.Value != nil && ast.Unparen(x.Value) == cur))
		case *ast.UnaryExpr:
			return x.Op == token.AND && ast.Unparen(x.X) == cur
		case *ast.CallExpr:
			if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(x.Fun)); b != nil {
				switch b.Name() {
				case "delete", "clear", "copy", "append":
					return len(x.Args) > 0 && ast.Unparen(x.Args[0]) == cur
				}
			}
			return false
		case *ast.SelectorExpr:
			if ast.Unparen(x.X) == cur {
				if selInfo := p.TypesInfo.Selections[x]; selInfo != nil && selInfo.Kind() == types.FieldVal {
					cur = x
					continue
				}
			}
			return false
		case *ast.IndexExpr:
			if ast.Unparen(x.X) == cur {
				cur = x
				continue
			}
			return false
		case *ast.SliceExpr:
			if ast.Unparen(x.X) == cur {
				cur = x
				continue
			}
			return false
		case *ast.StarExpr:
			if ast.Unparen(x.X) == cur {
				cur = x
				continue
			}
			return false
		default:
			return false
		}
	}
}

// TouchesAnyNamedStruct reports whether expr dereferences, indexes, or selects
// a field through any named struct in targets.
func TouchesAnyNamedStruct(p *packages.Package, expr ast.Expr, targets map[*types.Named]bool) bool {
	if p == nil || p.TypesInfo == nil || expr == nil || len(targets) == 0 {
		return false
	}
	cur := ast.Unparen(expr)
	for {
		switch e := cur.(type) {
		case *ast.StarExpr:
			if st := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(e.X)); st != nil && targets[st] {
				return true
			}
			return false
		case *ast.SelectorExpr:
			if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
				hit := false
				syntaxutil.ForEachSelectionHopStruct(selInfo, func(st *types.Named) {
					if targets[st] {
						hit = true
					}
				})
				if hit {
					return true
				}
			}
			cur = ast.Unparen(e.X)
		case *ast.IndexExpr:
			if st := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(e)); st != nil && targets[st] {
				return true
			}
			cur = ast.Unparen(e.X)
		case *ast.SliceExpr:
			cur = ast.Unparen(e.X)
		default:
			return false
		}
	}
}

// CallMutatesNamedStructContainer reports whether call invokes a mutating
// container builtin (delete, clear, copy, append) whose destination touches any
// named struct in targets.
func CallMutatesNamedStructContainer(
	p *packages.Package,
	call *ast.CallExpr,
	targets map[*types.Named]bool,
) bool {
	if p == nil || p.TypesInfo == nil || call == nil || len(call.Args) == 0 || len(targets) == 0 {
		return false
	}
	b := syntaxutil.LookupBuiltin(p.TypesInfo, call.Fun)
	if b == nil {
		return false
	}
	switch b.Name() {
	case "delete", "clear", "copy", "append":
		return TouchesAnyNamedStruct(p, call.Args[0], targets)
	}
	return false
}

// PkgHasAnyMutationOnStructs reports whether any non-exempt AST node in
// p.Syntax mutates or takes the address of a field/element on any named struct
// in targets.
func PkgHasAnyMutationOnStructs(
	p *packages.Package,
	targets map[*types.Named]bool,
	exempt map[ast.Node]bool,
) bool {
	if p == nil || p.TypesInfo == nil || len(targets) == 0 {
		return false
	}
	hit := false
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if hit || n == nil {
				return false
			}
			if exempt != nil && exempt[n] {
				return true
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if TouchesAnyNamedStruct(p, lhs, targets) {
						hit = true
						return false
					}
				}
			case *ast.IncDecStmt:
				if TouchesAnyNamedStruct(p, x.X, targets) {
					hit = true
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && TouchesAnyNamedStruct(p, x.Key, targets)) ||
						(x.Value != nil && TouchesAnyNamedStruct(p, x.Value, targets)) {
						hit = true
						return false
					}
				}
			case *ast.CallExpr:
				if CallMutatesNamedStructContainer(p, x, targets) {
					hit = true
					return false
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if TouchesAnyNamedStruct(p, x.X, targets) {
						hit = true
						return false
					}
				}
			case *ast.SliceExpr:
				if t := p.TypesInfo.TypeOf(x.X); t != nil {
					if _, isArr := types.Unalias(t).Underlying().(*types.Array); isArr && TouchesAnyNamedStruct(p, x.X, targets) {
						hit = true
						return false
					}
				}
			}
			return true
		})
	}
	return hit
}

// SelectionHasPointerReceiver reports whether a MethodVal/MethodExpr selection
// invokes a method whose declared receiver is a pointer type (regardless of
// whether go/types.Selection.Indirect() is false due to implicit &-addressing
// of an addressable value operand).
func SelectionHasPointerReceiver(sel *types.Selection) bool {
	if sel == nil {
		return false
	}
	mFn, ok := sel.Obj().(*types.Func)
	if !ok || mFn == nil || mFn.Signature() == nil || mFn.Signature().Recv() == nil {
		return false
	}
	_, isPtr := types.Unalias(mFn.Signature().Recv().Type()).(*types.Pointer)
	return isPtr
}

// IsByValueFieldChainOnExemptFamily reports whether expr is a by-value field
// selection chain whose final unexported non-pointer field belongs to a struct
// in exemptFam.
func IsByValueFieldChainOnExemptFamily(p *packages.Package, expr ast.Expr, exemptFam map[*types.Named]bool) bool {
	if p == nil || p.TypesInfo == nil || expr == nil || len(exemptFam) == 0 {
		return false
	}
	cur := ast.Unparen(expr)
	for {
		sel, ok := cur.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		selInfo := p.TypesInfo.Selections[sel]
		if selInfo == nil || selInfo.Kind() != types.FieldVal || syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
			return false
		}
		hitExempt := false
		syntaxutil.ForEachSelectionHopStruct(selInfo, func(st *types.Named) {
			if exemptFam[st] {
				hitExempt = true
			}
		})
		if hitExempt {
			fld, _ := selInfo.Obj().(*types.Var)
			if fld == nil || fld.Exported() {
				return false
			}
			_, isPtr := types.Unalias(fld.Type()).(*types.Pointer)
			return !isPtr
		}
		if _, isPtr := types.Unalias(p.TypesInfo.TypeOf(sel.X)).(*types.Pointer); isPtr {
			return false
		}
		cur = ast.Unparen(sel.X)
	}
}

// EnclosingCallOfCalleeIdent returns the *ast.CallExpr in which uid appears as
// the direct callee identifier or selector identifier, or nil.
func EnclosingCallOfCalleeIdent(idx *PkgIndex, uid *ast.Ident) *ast.CallExpr {
	if idx == nil || uid == nil {
		return nil
	}
	par := idx.ParentUnparen(uid)
	if c, isC := par.(*ast.CallExpr); isC && ast.Unparen(c.Fun) == uid {
		return c
	}
	if sel, isS := par.(*ast.SelectorExpr); isS && sel.Sel == uid {
		if c, isC := idx.ParentUnparen(sel).(*ast.CallExpr); isC && ast.Unparen(c.Fun) == sel {
			return c
		}
	}
	return nil
}

// IsInsideExemptWriteOrAddr reports whether n lies inside the LHS of an
// exempted *ast.AssignStmt or inside an exempted &expr *ast.UnaryExpr.
func IsInsideExemptWriteOrAddr(idx *PkgIndex, n ast.Node, exemptMap map[ast.Node]bool) bool {
	if idx == nil || n == nil || len(exemptMap) == 0 {
		return false
	}
	cur := n
	for cur != nil {
		switch pNode := idx.ParentMap[cur].(type) {
		case *ast.AssignStmt:
			if exemptMap[pNode] {
				for _, lhs := range pNode.Lhs {
					if lhs.Pos() <= n.Pos() && n.End() <= lhs.End() {
						return true
					}
				}
			}
		case *ast.UnaryExpr:
			if pNode.Op == token.AND && exemptMap[pNode] {
				return true
			}
		}
		cur = idx.ParentMap[cur]
	}
	return false
}

// ComputeExclusiveConeFromRoots returns the greatest fixed-point cone of
// *ast.FuncDecl declarations reachable from initFDs and extraRootFuncs whose
// every intra-package call site lies synchronously inside the cone (or inside
// allowedLitBlocks).
func ComputeExclusiveConeFromRoots(
	p *packages.Package,
	idx *PkgIndex,
	initFDs []*ast.FuncDecl,
	extraRootFuncs map[*types.Func]bool,
	allowedLitBlocks map[*ast.BlockStmt]bool,
) map[*ast.FuncDecl]bool {
	if p == nil || idx == nil {
		return nil
	}
	enclosingConeFD := func(n ast.Node) *ast.FuncDecl {
		if len(allowedLitBlocks) == 0 {
			return idx.SyncEnclFuncDecl(n)
		}
		for cur := idx.ParentMap[n]; cur != nil; cur = idx.ParentMap[cur] {
			switch x := cur.(type) {
			case *ast.GoStmt:
				return nil
			case *ast.FuncLit:
				if !allowedLitBlocks[x.Body] {
					return nil
				}
			case *ast.FuncDecl:
				return x
			}
		}
		return nil
	}

	forwardReach := func(allowed map[*types.Func]bool) (map[*ast.FuncDecl]bool, map[*types.Func]bool) {
		reachFDs := map[*ast.FuncDecl]bool{}
		reachFuncs := map[*types.Func]bool{}
		var queue []*ast.FuncDecl
		for _, fd := range initFDs {
			if fd != nil && fd.Body != nil && !reachFDs[fd] {
				reachFDs[fd] = true
				queue = append(queue, fd)
			}
		}
		for fn := range extraRootFuncs {
			if fd := idx.FuncDecls[fn]; fd != nil && fd.Body != nil {
				reachFuncs[fn] = true
				if !reachFDs[fd] {
					reachFDs[fd] = true
					queue = append(queue, fd)
				}
			}
		}
		for len(queue) > 0 {
			fd := queue[0]
			queue = queue[1:]
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if n == nil {
					return false
				}
				switch x := n.(type) {
				case *ast.GoStmt:
					return false
				case *ast.FuncLit:
					return allowedLitBlocks[x.Body]
				case *ast.CallExpr:
					callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
					if callee == nil {
						return true
					}
					callee = callee.Origin()
					if callee.Pkg() == p.Types && !callee.Exported() && callee.Name() != "init" &&
						(allowed == nil || allowed[callee]) && !reachFuncs[callee] {
						if cfd := idx.FuncDecls[callee]; cfd != nil && cfd.Body != nil {
							reachFuncs[callee] = true
							if !reachFDs[cfd] {
								reachFDs[cfd] = true
								queue = append(queue, cfd)
							}
						}
					}
				}
				return true
			})
		}
		return reachFDs, reachFuncs
	}

	coneFDs, coneFuncs := forwardReach(nil)
	for {
		changed := false
		for fn := range coneFuncs {
			if extraRootFuncs[fn] {
				continue
			}
			uses := idx.UsesOf[fn]
			if len(uses) == 0 {
				delete(coneFuncs, fn)
				delete(coneFDs, idx.FuncDecls[fn])
				changed = true
				continue
			}
			allInside := true
			for _, uid := range uses {
				call := EnclosingCallOfCalleeIdent(idx, uid)
				if call == nil {
					allInside = false
					break
				}
				encl := enclosingConeFD(call)
				if encl == nil || !coneFDs[encl] {
					allInside = false
					break
				}
			}
			if !allInside {
				delete(coneFuncs, fn)
				delete(coneFDs, idx.FuncDecls[fn])
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	coneFDs, _ = forwardReach(coneFuncs)
	return coneFDs
}

// ComputeExclusiveHelperCone returns the exclusive helper *types.Func cone
// rooted at root.
func ComputeExclusiveHelperCone(p *packages.Package, idx *PkgIndex, root *types.Func) map[*types.Func]bool {
	if root == nil || idx == nil {
		return nil
	}
	coneFDs := ComputeExclusiveConeFromRoots(p, idx, nil, map[*types.Func]bool{root: true}, nil)
	out := map[*types.Func]bool{root: true}
	for fn, fd := range idx.FuncDecls {
		if fd != nil && coneFDs[fd] {
			out[fn] = true
		}
	}
	return out
}
