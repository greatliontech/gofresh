package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
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
		case *types.Interface, *types.Signature, *types.TypeParam:
			hit = true
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

func indexValueTypeFromType(t types.Type) types.Type {
	if tup, isTup := t.(*types.Tuple); isTup && tup.Len() > 0 {
		return tup.At(0).Type()
	}
	return t
}

func callCallErasesSeedStruct(
	info *types.Info,
	call *ast.CallExpr,
	seedStructTypeViolated func(dstT, srcT types.Type) bool,
	allowCallArg func(call *ast.CallExpr, argIdx int, arg ast.Expr) bool,
) bool {
	if len(call.Args) == 0 {
		return false
	}
	if tv, ok := info.Types[call]; ok && tv.Value != nil {
		return false
	}
	fun := ast.Unparen(call.Fun)
	if b := syntaxutil.LookupBuiltin(info, fun); b != nil {
		switch b.Name() {
		case "len", "cap", "Sizeof", "Alignof", "Offsetof":
			return false
		case "append":
			if len(call.Args) >= 2 {
				dstSlice := info.TypeOf(call.Args[0])
				if dstSlice != nil {
					if sl, okSl := types.Unalias(dstSlice).Underlying().(*types.Slice); okSl {
						if call.Ellipsis.IsValid() {
							return seedStructTypeViolated(dstSlice, info.TypeOf(call.Args[1]))
						}
						for _, arg := range call.Args[1:] {
							if seedStructTypeViolated(sl.Elem(), info.TypeOf(arg)) {
								return true
							}
						}
					}
				}
			}
			return false
		}
	}
	sig, isSig := syntaxutil.UnderlyingType(info.TypeOf(fun)).(*types.Signature)
	if !isSig {
		for _, arg := range call.Args {
			if seedStructTypeViolated(nil, info.TypeOf(arg)) {
				return true
			}
		}
		return false
	}
	var originSig *types.Signature
	switch fn := fun.(type) {
	case *ast.Ident:
		if callee, ok := info.Uses[fn].(*types.Func); ok && callee.Origin() != callee {
			originSig, _ = callee.Origin().Type().(*types.Signature)
		}
	case *ast.SelectorExpr:
		if fn.Sel != nil {
			if callee, ok := info.Uses[fn.Sel].(*types.Func); ok && callee.Origin() != callee {
				originSig, _ = callee.Origin().Type().(*types.Signature)
			}
		}
	case *ast.IndexExpr:
		if id, isID := ast.Unparen(fn.X).(*ast.Ident); isID {
			if callee, ok := info.Uses[id].(*types.Func); ok {
				originSig, _ = callee.Origin().Type().(*types.Signature)
			}
		}
	case *ast.IndexListExpr:
		if id, isID := ast.Unparen(fn.X).(*ast.Ident); isID {
			if callee, ok := info.Uses[id].(*types.Func); ok {
				originSig, _ = callee.Origin().Type().(*types.Signature)
			}
		}
	}

	if len(call.Args) == 1 {
		if tup, isTup := info.TypeOf(call.Args[0]).(*types.Tuple); isTup {
			for ti := 0; ti < tup.Len(); ti++ {
				var dstT types.Type
				if ti < sig.Params().Len() {
					dstT = sig.Params().At(ti).Type()
				}
				if seedStructTypeViolated(dstT, tup.At(ti).Type()) {
					return true
				}
				if originSig != nil && ti < originSig.Params().Len() && seedStructTypeViolated(originSig.Params().At(ti).Type(), tup.At(ti).Type()) {
					return true
				}
			}
			return false
		}
	}

	for argIdx, arg := range call.Args {
		if allowCallArg != nil && allowCallArg(call, argIdx, arg) {
			continue
		}
		argT := info.TypeOf(arg)
		paramIdx := argIdx
		isNonEllipsisVariadic := false
		if sig.Variadic() && argIdx >= sig.Params().Len()-1 {
			paramIdx = sig.Params().Len() - 1
			isNonEllipsisVariadic = !call.Ellipsis.IsValid()
		}
		var dstT types.Type
		if paramIdx < sig.Params().Len() {
			dstT = sig.Params().At(paramIdx).Type()
			if isNonEllipsisVariadic {
				if sl, isSl := syntaxutil.UnderlyingType(dstT).(*types.Slice); isSl {
					dstT = sl.Elem()
				}
			}
		}
		if seedStructTypeViolated(dstT, argT) {
			return true
		}
		if originSig != nil && paramIdx < originSig.Params().Len() {
			origT := originSig.Params().At(paramIdx).Type()
			if isNonEllipsisVariadic {
				if sl, isSl := syntaxutil.UnderlyingType(origT).(*types.Slice); isSl {
					origT = sl.Elem()
				}
			}
			if seedStructTypeViolated(origT, argT) {
				return true
			}
		}
	}
	return false
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
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if TouchesAnyNamedStruct(p, x.Args[0], targets) {
								hit = true
								return false
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if TouchesAnyNamedStruct(p, x.X, targets) {
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

// IsSafeAtomicPointerValueArg reports whether conv is the value (non-target)
// argument of sync/atomic.{StorePointer,SwapPointer,CompareAndSwapPointer}.
func IsSafeAtomicPointerValueArg(p *packages.Package, idx *PkgIndex, conv *ast.CallExpr) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || conv == nil {
		return false
	}
	call, ok := idx.ParentUnparen(conv).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "sync/atomic" {
		return false
	}
	switch fn.Name() {
	case "StorePointer", "SwapPointer":
		return len(call.Args) == 2 && ast.Unparen(call.Args[1]) == conv
	case "CompareAndSwapPointer":
		return len(call.Args) == 3 && ast.Unparen(call.Args[2]) == conv
	}
	return false
}

// IsPureAtomicLoadInnerConv reports whether conv is the inner unsafe.Pointer
// conversion inside (*unsafe.Pointer)(unsafe.Pointer(&x)) passed to
// sync/atomic.LoadPointer.
func IsPureAtomicLoadInnerConv(p *packages.Package, idx *PkgIndex, conv *ast.CallExpr) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || conv == nil {
		return false
	}
	outerConv, ok := idx.ParentUnparen(conv).(*ast.CallExpr)
	if !ok || len(outerConv.Args) != 1 || ast.Unparen(outerConv.Args[0]) != conv || !p.TypesInfo.Types[outerConv.Fun].IsType() {
		return false
	}
	ptr, isPtr := types.Unalias(p.TypesInfo.Types[outerConv.Fun].Type).(*types.Pointer)
	if !isPtr || !syntaxutil.IsUnsafePointerType(ptr.Elem()) {
		return false
	}
	call, ok := idx.ParentUnparen(outerConv).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || ast.Unparen(call.Args[0]) != outerConv {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "sync/atomic" && fn.Name() == "LoadPointer"
}

// IsPureAtomicLoadArg reports whether addrExpr (optionally wrapped in
// unsafe.Pointer / *unsafe.Pointer conversions) is the sole argument to a
// sync/atomic.Load* call.
func IsPureAtomicLoadArg(p *packages.Package, idx *PkgIndex, addrExpr *ast.UnaryExpr) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || addrExpr == nil {
		return false
	}
	arg := ast.Expr(addrExpr)
	par := idx.ParentUnparen(addrExpr)
	for range 2 {
		conv, isConv := par.(*ast.CallExpr)
		if !isConv || len(conv.Args) != 1 || ast.Unparen(conv.Args[0]) != arg || !p.TypesInfo.Types[conv.Fun].IsType() {
			break
		}
		convT := types.Unalias(p.TypesInfo.Types[conv.Fun].Type)
		if syntaxutil.IsUnsafePointerType(convT) {
			arg = conv
			par = idx.ParentUnparen(conv)
			continue
		}
		if ptr, isPtr := convT.(*types.Pointer); isPtr && syntaxutil.IsUnsafePointerType(ptr.Elem()) {
			arg = conv
			par = idx.ParentUnparen(conv)
			continue
		}
		break
	}
	call, ok := par.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || ast.Unparen(call.Args[0]) != arg {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "sync/atomic" {
		return false
	}
	switch fn.Name() {
	case "LoadInt32", "LoadInt64", "LoadUint32", "LoadUint64", "LoadUintptr", "LoadPointer":
		return true
	}
	return false
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


