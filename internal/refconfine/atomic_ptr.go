package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func extractTypedAtomicSlotElem(p *packages.Package, arg0 ast.Expr) (types.Type, bool) {
	if p == nil || p.TypesInfo == nil || arg0 == nil {
		return nil, false
	}
	outerConv, ok := ast.Unparen(arg0).(*ast.CallExpr)
	if !ok || len(outerConv.Args) != 1 || !p.TypesInfo.Types[outerConv.Fun].IsType() {
		return nil, false
	}
	outerPtr, isPtr := types.Unalias(p.TypesInfo.Types[outerConv.Fun].Type).(*types.Pointer)
	if !isPtr || !syntaxutil.IsUnsafePointerType(outerPtr.Elem()) {
		return nil, false
	}
	innerConv, ok := ast.Unparen(outerConv.Args[0]).(*ast.CallExpr)
	if !ok || len(innerConv.Args) != 1 || !p.TypesInfo.Types[innerConv.Fun].IsType() ||
		!syntaxutil.IsUnsafePointerType(p.TypesInfo.Types[innerConv.Fun].Type) {
		return nil, false
	}
	slotPtrT, isSlotPtr := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(innerConv.Args[0])).(*types.Pointer)
	if !isSlotPtr {
		return nil, false
	}
	slotElem := types.Unalias(slotPtrT.Elem())
	if syntaxutil.IsUnsafePointerType(slotElem) {
		return nil, false
	}
	if _, isElemPtr := slotElem.Underlying().(*types.Pointer); !isElemPtr {
		return nil, false
	}
	return slotElem, true
}

func isNilOrMatchingUnsafePtrConv(p *packages.Package, expr ast.Expr, wantElem types.Type) bool {
	if p == nil || p.TypesInfo == nil || expr == nil || wantElem == nil {
		return false
	}
	expr = ast.Unparen(expr)
	if syntaxutil.IsNilIdent(p.TypesInfo, expr) {
		return true
	}
	conv, ok := expr.(*ast.CallExpr)
	if !ok || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() ||
		!syntaxutil.IsUnsafePointerType(p.TypesInfo.Types[conv.Fun].Type) {
		return false
	}
	if syntaxutil.IsNilIdent(p.TypesInfo, conv.Args[0]) {
		return true
	}
	argT := p.TypesInfo.TypeOf(conv.Args[0])
	return argT != nil && types.Identical(types.Unalias(argT), types.Unalias(wantElem))
}

func isSafeAtomicPointerResultParent(p *packages.Package, idx *PkgIndex, call *ast.CallExpr, wantElem types.Type, allowNilCompare bool) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || call == nil || wantElem == nil {
		return false
	}
	par := idx.ParentUnparen(call)
	switch pn := par.(type) {
	case *ast.ExprStmt:
		return true
	case *ast.BinaryExpr:
		if !allowNilCompare || (pn.Op != token.EQL && pn.Op != token.NEQ) {
			return false
		}
		if ast.Unparen(pn.X) == call {
			return syntaxutil.IsNilIdent(p.TypesInfo, pn.Y)
		}
		if ast.Unparen(pn.Y) == call {
			return syntaxutil.IsNilIdent(p.TypesInfo, pn.X)
		}
		return false
	case *ast.CallExpr:
		if len(pn.Args) != 1 || ast.Unparen(pn.Args[0]) != call || !p.TypesInfo.Types[pn.Fun].IsType() {
			return false
		}
		dstT := p.TypesInfo.Types[pn.Fun].Type
		return dstT != nil && types.Identical(types.Unalias(dstT), types.Unalias(wantElem))
	default:
		return false
	}
}

// IsSafeAtomicPointerValueArg reports whether conv is a type-matched value
// argument of sync/atomic.{StorePointer,SwapPointer,CompareAndSwapPointer}
// against a (*unsafe.Pointer)(unsafe.Pointer(&typedSlot)) target of identical
// pointer type.
func IsSafeAtomicPointerValueArg(p *packages.Package, idx *PkgIndex, conv *ast.CallExpr) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || conv == nil || len(conv.Args) != 1 {
		return false
	}
	call, ok := idx.ParentUnparen(conv).(*ast.CallExpr)
	if !ok || len(call.Args) < 2 {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "sync/atomic" || !syntaxutil.IsTrueStdlibInPkg(p, "sync/atomic") {
		return false
	}
	slotElem, okSlot := extractTypedAtomicSlotElem(p, call.Args[0])
	if !okSlot || !isNilOrMatchingUnsafePtrConv(p, conv, slotElem) {
		return false
	}
	switch fn.Name() {
	case "StorePointer":
		return len(call.Args) == 2 && ast.Unparen(call.Args[1]) == conv
	case "SwapPointer":
		return len(call.Args) == 2 && ast.Unparen(call.Args[1]) == conv &&
			isSafeAtomicPointerResultParent(p, idx, call, slotElem, true)
	case "CompareAndSwapPointer":
		return len(call.Args) == 3 &&
			(ast.Unparen(call.Args[1]) == conv || ast.Unparen(call.Args[2]) == conv) &&
			isNilOrMatchingUnsafePtrConv(p, call.Args[1], slotElem) &&
			isNilOrMatchingUnsafePtrConv(p, call.Args[2], slotElem)
	}
	return false
}

// IsTypedAtomicLoadResultCast reports whether castCall is (*T)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&typedSlot))))
// where typedSlot has static type identical to *T.
func IsTypedAtomicLoadResultCast(p *packages.Package, idx *PkgIndex, castCall *ast.CallExpr) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || castCall == nil || len(castCall.Args) != 1 || castCall.Ellipsis.IsValid() {
		return false
	}
	tv := p.TypesInfo.Types[ast.Unparen(castCall.Fun)]
	if !tv.IsType() || tv.Type == nil {
		return false
	}
	loadCall, ok := ast.Unparen(castCall.Args[0]).(*ast.CallExpr)
	if !ok || len(loadCall.Args) != 1 || loadCall.Ellipsis.IsValid() {
		return false
	}
	sel, ok := ast.Unparen(loadCall.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "sync/atomic" || fn.Name() != "LoadPointer" || !syntaxutil.IsTrueStdlibInPkg(p, "sync/atomic") {
		return false
	}
	slotElem, okSlot := extractTypedAtomicSlotElem(p, loadCall.Args[0])
	return okSlot && types.Identical(types.Unalias(tv.Type), slotElem)
}

// IsPureAtomicLoadInnerConv reports whether conv is the inner unsafe.Pointer
// conversion inside (*unsafe.Pointer)(unsafe.Pointer(&x)) passed to a
// type-matched sync/atomic.LoadPointer call.
func IsPureAtomicLoadInnerConv(p *packages.Package, idx *PkgIndex, conv *ast.CallExpr) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || conv == nil {
		return false
	}
	outerConv, ok := idx.ParentUnparen(conv).(*ast.CallExpr)
	if !ok || len(outerConv.Args) != 1 || ast.Unparen(outerConv.Args[0]) != conv || !p.TypesInfo.Types[outerConv.Fun].IsType() {
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
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "sync/atomic" || fn.Name() != "LoadPointer" || !syntaxutil.IsTrueStdlibInPkg(p, "sync/atomic") {
		return false
	}
	slotElem, okSlot := extractTypedAtomicSlotElem(p, outerConv)
	return okSlot && isSafeAtomicPointerResultParent(p, idx, call, slotElem, true)
}

// IsAtomicPointerSlotTargetInnerConv reports whether conv is the inner
// unsafe.Pointer(&slot) conversion inside (*unsafe.Pointer)(conv) passed as
// Args[0] to a type-matched sync/atomic.{StorePointer,CompareAndSwapPointer},
// which mutates the pointer slot itself without dereferencing the pointee behind slot.
func IsAtomicPointerSlotTargetInnerConv(p *packages.Package, idx *PkgIndex, conv *ast.CallExpr) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || conv == nil || !syntaxutil.IsTrueStdlibInPkg(p, "sync/atomic") {
		return false
	}
	outerConv, ok := idx.ParentUnparen(conv).(*ast.CallExpr)
	if !ok || len(outerConv.Args) != 1 || ast.Unparen(outerConv.Args[0]) != conv || !p.TypesInfo.Types[outerConv.Fun].IsType() {
		return false
	}
	call, ok := idx.ParentUnparen(outerConv).(*ast.CallExpr)
	if !ok || len(call.Args) < 2 || ast.Unparen(call.Args[0]) != outerConv {
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
	slotElem, okSlot := extractTypedAtomicSlotElem(p, outerConv)
	if !okSlot {
		return false
	}
	switch fn.Name() {
	case "StorePointer":
		return len(call.Args) == 2 && isNilOrMatchingUnsafePtrConv(p, call.Args[1], slotElem)
	case "CompareAndSwapPointer":
		return len(call.Args) == 3 &&
			isNilOrMatchingUnsafePtrConv(p, call.Args[1], slotElem) &&
			isNilOrMatchingUnsafePtrConv(p, call.Args[2], slotElem)
	default:
		return false
	}
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
	if !ok || fn.Pkg() == nil || fn.Pkg().Path() != "sync/atomic" || !syntaxutil.IsTrueStdlibInPkg(p, "sync/atomic") {
		return false
	}
	switch fn.Name() {
	case "LoadInt32", "LoadInt64", "LoadUint32", "LoadUint64", "LoadUintptr":
		return true
	case "LoadPointer":
		slotElem, okSlot := extractTypedAtomicSlotElem(p, call.Args[0])
		if okSlot {
			return isSafeAtomicPointerResultParent(p, idx, call, slotElem, true)
		}
		// Direct atomic.LoadPointer(&rawUnsafePtrField) (e.g. atomicNilMessage.p) is pure
		// iff &rawUnsafePtrField has type *unsafe.Pointer.
		if ptrT, isP := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(addrExpr)).(*types.Pointer); isP && syntaxutil.IsUnsafePointerType(ptrT.Elem()) {
			return true
		}
		return false
	}
	return false
}
