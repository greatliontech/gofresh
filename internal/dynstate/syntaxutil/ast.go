// Package syntaxutil provides shared AST, go/types, place-spine, declaration-key,
// and monotone fixed-point primitives across the dynamic-state analysis packages.
package syntaxutil

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
)

// UnparenExpr strips enclosing *ast.ParenExpr nodes from expr.
func UnparenExpr(expr ast.Expr) ast.Expr {
	return ast.Unparen(expr)
}

// NodeDeclarationKey and ObjectDeclarationKey derive the identity the
// ambiguous-subject refusal compares: one declaration must yield one key no
// matter which build variant sights it. Under Tests: true the same source
// package is visited once per variant with distinct pkg.IDs ("p" and
// "p [p.test]"), so no key may incorporate the sighting variant's identity —
// a variant-dependent key manufactures ambiguity for a single declaration and
// fails the whole package.
func NodeDeclarationKey(pkg *packages.Package, node ast.Node) string {
	if pkg != nil && pkg.Fset != nil && node != nil {
		position := pkg.Fset.PositionFor(node.Pos(), false)
		if position.Filename != "" {
			return fmt.Sprintf("%s:%d", position.Filename, position.Offset)
		}
	}
	var pkgPath string
	if pkg != nil {
		pkgPath = pkg.PkgPath
	}
	if node == nil {
		return fmt.Sprintf("%s:0", pkgPath)
	}
	return fmt.Sprintf("%s:%d", pkgPath, node.Pos())
}

// ObjectDeclarationKey returns the canonical declaration key for obj in pkg.
func ObjectDeclarationKey(pkg *packages.Package, obj types.Object) string {
	if pkg != nil && pkg.Fset != nil && obj != nil {
		position := pkg.Fset.PositionFor(obj.Pos(), false)
		if position.Filename != "" {
			return fmt.Sprintf("%s:%d", position.Filename, position.Offset)
		}
	}
	if obj != nil && obj.Pkg() != nil {
		return obj.Pkg().Path() + "." + obj.Name()
	}
	return fmt.Sprintf("universe:%v", obj)
}

// HasDirective reports whether a doc comment group carries the named gofresh
// directive — a comment line whose text is exactly the directive, the Go
// directive form with no leading space.
func HasDirective(doc *ast.CommentGroup, directive string) bool {
	if doc == nil {
		return false
	}
	for _, c := range doc.List {
		if c.Text == directive {
			return true
		}
	}
	return false
}

// VarWrittenOrAddrTakenInBody reports whether body assigns to, increments/decrements,
// or takes the address of v.
func VarWrittenOrAddrTakenInBody(info *types.Info, body *ast.BlockStmt, v *types.Var) bool {
	if info == nil || body == nil || v == nil {
		return false
	}
	bad := false
	ast.Inspect(body, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch s := n.(type) {
		case *ast.AssignStmt:
			for _, l := range s.Lhs {
				if IsIdentUsingObj(info, l, v) {
					bad = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if IsIdentUsingObj(info, s.X, v) {
				bad = true
				return false
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND && IsIdentUsingObj(info, s.X, v) {
				bad = true
				return false
			}
		}
		return true
	})
	return bad
}

// UnwrapCallee strips parentheses and explicit generic instantiation indices
// (*ast.IndexExpr and *ast.IndexListExpr) from a call's function expression.
func UnwrapCallee(fun ast.Expr) ast.Expr {
	for {
		switch f := fun.(type) {
		case *ast.ParenExpr:
			fun = f.X
		case *ast.IndexExpr:
			fun = f.X
		case *ast.IndexListExpr:
			fun = f.X
		default:
			return fun
		}
	}
}

// PlainCalleeFunc resolves a call's function expression to a plain named
// function origin (without receiver) and its declaring package path. Method
// values, builtins, and function-typed variables resolve to (nil, "").
func PlainCalleeFunc(p *packages.Package, fun ast.Expr) (*types.Func, string) {
	if p == nil || p.TypesInfo == nil {
		return nil, ""
	}
	fun = UnwrapCallee(fun)
	var obj types.Object
	switch f := fun.(type) {
	case *ast.Ident:
		obj = p.TypesInfo.Uses[f]
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
				obj = p.TypesInfo.Uses[f.Sel]
			}
		}
	}
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return nil, ""
	}
	fn = fn.Origin()
	if sig, ok := fn.Type().(*types.Signature); !ok || sig.Recv() != nil {
		return nil, ""
	}
	return fn, fn.Pkg().Path()
}

// RootIdent unwraps selector, index, index-list, dereference, and parenthesized
// spine expressions down to the root identifier, or nil for any other shape.
func RootIdent(expr ast.Expr) *ast.Ident {
	for {
		switch e := expr.(type) {
		case *ast.Ident:
			return e
		case *ast.SelectorExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.IndexListExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		case *ast.ParenExpr:
			expr = e.X
		default:
			return nil
		}
	}
}

// ChainRoot unwraps selector, index, index-list, slice, dereference, and
// parenthesized spine expressions down to the root identifier, or nil.
func ChainRoot(expr ast.Expr) *ast.Ident {
	for {
		switch e := expr.(type) {
		case *ast.Ident:
			return e
		case *ast.SelectorExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.IndexListExpr:
			expr = e.X
		case *ast.SliceExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		case *ast.ParenExpr:
			expr = e.X
		default:
			return nil
		}
	}
}

// IdentDefOrUse resolves ident in info.Defs first, falling back to info.Uses.
func IdentDefOrUse(info *types.Info, ident *ast.Ident) types.Object {
	if info == nil || ident == nil {
		return nil
	}
	if obj := info.Defs[ident]; obj != nil {
		return obj
	}
	return info.Uses[ident]
}

// IdentUseOrDef resolves ident in info.Uses first, falling back to info.Defs.
func IdentUseOrDef(info *types.Info, ident *ast.Ident) types.Object {
	if info == nil || ident == nil {
		return nil
	}
	if obj := info.Uses[ident]; obj != nil {
		return obj
	}
	return info.Defs[ident]
}

// LookupIdentVar resolves expr (after unparenthesizing) to a *types.Var in
// info.Uses or info.Defs, or nil when expr is not a variable identifier.
func LookupIdentVar(info *types.Info, expr ast.Expr) *types.Var {
	if info == nil || expr == nil {
		return nil
	}
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil
	}
	if v, ok := info.Uses[id].(*types.Var); ok {
		return v
	}
	if v, ok := info.Defs[id].(*types.Var); ok {
		return v
	}
	return nil
}

// IsIdentUsingObj reports whether expr (after unparenthesizing) is an
// *ast.Ident whose info.Uses entry equals want.
func IsIdentUsingObj(info *types.Info, expr ast.Expr, want types.Object) bool {
	if info == nil || expr == nil || want == nil {
		return false
	}
	id, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && info.Uses[id] == want
}

// IsNilIdent reports whether expr (after unparenthesizing) resolves to the
// predeclared universe nil object.
func IsNilIdent(info *types.Info, expr ast.Expr) bool {
	return IsIdentUsingObj(info, expr, types.Universe.Lookup("nil"))
}

// IsBlankIdent reports whether expr (after unparenthesizing) is the blank
// identifier "_".
func IsBlankIdent(expr ast.Expr) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && id.Name == "_"
}

// ExprIsFuncLit reports whether expr (after unparenthesizing) is an *ast.FuncLit.
func ExprIsFuncLit(expr ast.Expr) bool {
	_, ok := ast.Unparen(expr).(*ast.FuncLit)
	return ok
}

// LookupBuiltin resolves fun (either a bare identifier or a package-qualified
// selector such as unsafe.Sizeof) to its *types.Builtin, or nil.
func LookupBuiltin(info *types.Info, fun ast.Expr) *types.Builtin {
	if info == nil || fun == nil {
		return nil
	}
	switch f := ast.Unparen(fun).(type) {
	case *ast.Ident:
		b, _ := info.Uses[f].(*types.Builtin)
		return b
	case *ast.SelectorExpr:
		if f.Sel != nil && info.Selections[f] == nil {
			b, _ := info.Uses[f.Sel].(*types.Builtin)
			return b
		}
	}
	return nil
}

// IsMethodValueBind reports whether expr (after callee unwrapping) is a
// selector expression with MethodVal selection kind.
func IsMethodValueBind(info *types.Info, expr ast.Expr) bool {
	sel, ok := UnwrapCallee(expr).(*ast.SelectorExpr)
	if !ok || info == nil {
		return false
	}
	selection, ok := info.Selections[sel]
	return ok && selection.Kind() == types.MethodVal
}

// EachLocalBinding visits each local binding pair (lhs, rhs) introduced by an
// assignment statement, value specification, range statement, or builtin
// copy(dst, src) call. It returns true when n is one of those four shapes.
func EachLocalBinding(info *types.Info, n ast.Node, visit func(lhs, rhs ast.Expr)) bool {
	switch n := n.(type) {
	case *ast.AssignStmt:
		if len(n.Lhs) == len(n.Rhs) {
			for i, lhs := range n.Lhs {
				visit(lhs, n.Rhs[i])
			}
		} else if len(n.Rhs) == 1 {
			for _, lhs := range n.Lhs {
				visit(lhs, n.Rhs[0])
			}
		}
		return true
	case *ast.ValueSpec:
		if len(n.Names) == len(n.Values) {
			for i, name := range n.Names {
				visit(name, n.Values[i])
			}
		} else if len(n.Values) == 1 {
			for _, name := range n.Names {
				visit(name, n.Values[0])
			}
		}
		return true
	case *ast.RangeStmt:
		for _, bind := range []ast.Expr{n.Key, n.Value} {
			if bind != nil {
				visit(bind, n.X)
			}
		}
		return true
	case *ast.CallExpr:
		if info != nil && len(n.Args) == 2 {
			if b := LookupBuiltin(info, n.Fun); b != nil && b.Name() == "copy" {
				visit(n.Args[0], n.Args[1])
				return true
			}
		}
	}
	return false
}

// PropagateLocalTaint computes the least fixed point of tainted local objects
// in body: any identifier bound by an assignment, value specification, range
// statement, or builtin copy(dst, src) call whose source expression satisfies
// rhsTainted (or rangeTainted for a range operand) and whose object satisfies
// allow is added to tainted until convergence.
func PropagateLocalTaint(
	info *types.Info,
	body ast.Node,
	tainted map[types.Object]bool,
	allow func(types.Object) bool,
	rhsTainted func(ast.Expr) bool,
	rangeTainted func(ast.Expr) bool,
) {
	for changed := true; changed; {
		changed = false
		taint := func(ident *ast.Ident) {
			obj := IdentDefOrUse(info, ident)
			if obj == nil || tainted[obj] || !allow(obj) {
				return
			}
			tainted[obj] = true
			changed = true
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if r, isRange := n.(*ast.RangeStmt); isRange {
				if rangeTainted != nil && rangeTainted(r.X) {
					for _, bind := range []ast.Expr{r.Key, r.Value} {
						if ident, ok := bind.(*ast.Ident); ok {
							taint(ident)
						}
					}
				}
				return true
			}
			EachLocalBinding(info, n, func(lhs, rhs ast.Expr) {
				if rhs == nil || !rhsTainted(rhs) {
					return
				}
				if ident, ok := ast.Unparen(lhs).(*ast.Ident); ok {
					taint(ident)
				} else if _, isCall := n.(*ast.CallExpr); isCall {
					if ident := ChainRoot(lhs); ident != nil {
						taint(ident)
					}
				}
			})
			return true
		})
	}
}

// EachCompositeLitValue visits each value expression in lit.Elts (unwrapping
// *ast.KeyValueExpr to kv.Value) until fn returns false.
func EachCompositeLitValue(lit *ast.CompositeLit, fn func(ast.Expr) bool) bool {
	if lit == nil {
		return true
	}
	for _, elt := range lit.Elts {
		v := elt
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			v = kv.Value
		}
		if !fn(v) {
			return false
		}
	}
	return true
}

// IsMutexMethodCall reports whether expr is a zero-argument call to method on
// muVar declared in package "sync".
func IsMutexMethodCall(info *types.Info, expr ast.Expr, muVar *types.Var, method string) bool {
	if info == nil || expr == nil || muVar == nil {
		return false
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != method || !IsIdentUsingObj(info, sel.X, muVar) {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "sync"
}

// IsMutexMethodStmt reports whether st is an *ast.ExprStmt calling method on muVar.
func IsMutexMethodStmt(info *types.Info, st ast.Stmt, muVar *types.Var, method string) bool {
	es, ok := st.(*ast.ExprStmt)
	if !ok {
		return false
	}
	return IsMutexMethodCall(info, es.X, muVar, method)
}

// IsDeferMutexMethodStmt reports whether st is an *ast.DeferStmt calling method on muVar.
func IsDeferMutexMethodStmt(info *types.Info, st ast.Stmt, muVar *types.Var, method string) bool {
	ds, ok := st.(*ast.DeferStmt)
	if !ok {
		return false
	}
	return IsMutexMethodCall(info, ds.Call, muVar, method)
}

// StmtContainsReturnOrBranch reports whether st contains any *ast.ReturnStmt,
// *ast.BranchStmt, *ast.DeferStmt, or *ast.GoStmt.
func StmtContainsReturnOrBranch(st ast.Stmt) bool {
	hit := false
	ast.Inspect(st, func(n ast.Node) bool {
		if hit {
			return false
		}
		switch n.(type) {
		case *ast.ReturnStmt, *ast.BranchStmt, *ast.DeferStmt, *ast.GoStmt:
			hit = true
			return false
		}
		return true
	})
	return hit
}

// SubtreeMentionsObj reports whether root contains any *ast.Ident whose
// info.Uses entry equals obj.
func SubtreeMentionsObj(info *types.Info, root ast.Node, obj types.Object) bool {
	if info == nil || root == nil || obj == nil {
		return false
	}
	hit := false
	ast.Inspect(root, func(n ast.Node) bool {
		if hit {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && info.Uses[id] == obj {
			hit = true
			return false
		}
		return true
	})
	return hit
}

// ResolveCalledFuncObj resolves a call's function expression (after callee
// unwrapping) to its *types.Func origin (whether plain function or method), or
// nil when fun is not a static function/method reference.
func ResolveCalledFuncObj(p *packages.Package, fun ast.Expr) *types.Func {
	if p == nil || p.TypesInfo == nil || fun == nil {
		return nil
	}
	switch fn := UnwrapCallee(fun).(type) {
	case *ast.Ident:
		if f, ok := p.TypesInfo.Uses[fn].(*types.Func); ok {
			return f.Origin()
		}
	case *ast.SelectorExpr:
		if fn.Sel != nil {
			if f, ok := p.TypesInfo.Uses[fn.Sel].(*types.Func); ok {
				return f.Origin()
			}
		}
	}
	return nil
}

// LookupPkgScopeVar resolves expr (after unparenthesizing) to a package-scope
// *types.Var declared in p.Types, or nil.
func LookupPkgScopeVar(p *packages.Package, expr ast.Expr) *types.Var {
	if p == nil || p.Types == nil || p.TypesInfo == nil || expr == nil {
		return nil
	}
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil
	}
	v, ok := p.TypesInfo.Uses[id].(*types.Var)
	if !ok || v == nil || v.IsField() || v.Pkg() != p.Types || v.Parent() != p.Types.Scope() {
		return nil
	}
	return v
}

// RootPkgScopeVar unwraps field selections, indexings, slices, and dereferences
// on expr down to a package-scope *types.Var declared in p.Types, or nil.
func RootPkgScopeVar(p *packages.Package, expr ast.Expr) *types.Var {
	if p == nil || p.Types == nil || p.TypesInfo == nil || expr == nil {
		return nil
	}
	cur := ast.Unparen(expr)
	for {
		if v := LookupPkgScopeVar(p, cur); v != nil {
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

// IsReflectTypeOfCall reports whether expr is a call to reflect.TypeOf.
func IsReflectTypeOfCall(p *packages.Package, expr ast.Expr) bool {
	if p == nil || p.TypesInfo == nil || expr == nil {
		return false
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "reflect" && fn.Name() == "TypeOf"
}

// ExtractSliceVarOrSubslice resolves expr (either a package-scope var ident or
// a 2-index subslice of one) to its package-scope *types.Var and root *ast.Ident.
func ExtractSliceVarOrSubslice(p *packages.Package, expr ast.Expr) (*types.Var, *ast.Ident, bool) {
	if p == nil || expr == nil {
		return nil, nil, false
	}
	expr = ast.Unparen(expr)
	if id, ok := expr.(*ast.Ident); ok {
		v := LookupPkgScopeVar(p, id)
		return v, id, v != nil
	}
	if se, ok := expr.(*ast.SliceExpr); ok && !se.Slice3 {
		if id, okID := ast.Unparen(se.X).(*ast.Ident); okID {
			v := LookupPkgScopeVar(p, id)
			return v, id, v != nil
		}
	}
	return nil, nil, false
}

// IsNonNegConstInt reports whether expr is a non-negative integer constant in info.Types.
func IsNonNegConstInt(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil {
		return false
	}
	tv, ok := info.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return false
	}
	return constant.Sign(tv.Value) >= 0
}

// IsTypedNilStructPtrInPkg reports whether expr is a typed-nil conversion
// (*Struct)(nil) to a named struct declared in pkg.
func IsTypedNilStructPtrInPkg(p *packages.Package, expr ast.Expr, pkg *types.Package) bool {
	if p == nil || p.TypesInfo == nil || expr == nil || pkg == nil {
		return false
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !p.TypesInfo.Types[call.Fun].IsType() || !IsNilIdent(p.TypesInfo, call.Args[0]) {
		return false
	}
	ptr, ok := types.Unalias(p.TypesInfo.Types[call.Fun].Type).(*types.Pointer)
	if !ok {
		return false
	}
	st := DerefNamedStruct(ptr.Elem())
	return st != nil && st.Obj() != nil && st.Obj().Pkg() == pkg
}

// IsMakeFixedSliceCall reports whether expr is a 2-argument make([]T, constLen)
// call with a non-negative constant length.
func IsMakeFixedSliceCall(p *packages.Package, expr ast.Expr) bool {
	if p == nil || p.TypesInfo == nil || expr == nil {
		return false
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return false
	}
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, ok := p.TypesInfo.Uses[id].(*types.Builtin)
	if !ok || b.Name() != "make" || !IsNonNegConstInt(p.TypesInfo, call.Args[1]) {
		return false
	}
	_, isSlice := UnderlyingType(p.TypesInfo.TypeOf(call)).(*types.Slice)
	return isSlice
}

// IsTypedNilSliceConv reports whether expr is a typed-nil slice conversion ([]T)(nil).
func IsTypedNilSliceConv(p *packages.Package, expr ast.Expr) bool {
	if p == nil || p.TypesInfo == nil || expr == nil {
		return false
	}
	conv, isConv := ast.Unparen(expr).(*ast.CallExpr)
	if !isConv || len(conv.Args) != 1 || !p.TypesInfo.Types[conv.Fun].IsType() || !IsNilIdent(p.TypesInfo, conv.Args[0]) {
		return false
	}
	_, isSl := UnderlyingType(p.TypesInfo.Types[conv.Fun].Type).(*types.Slice)
	return isSl
}

// SameFieldTargetExpr reports whether a and b refer to the same variable/field/index chain.
func SameFieldTargetExpr(p *packages.Package, a, b ast.Expr) bool {
	if p == nil || p.TypesInfo == nil || a == nil || b == nil {
		return false
	}
	a = ast.Unparen(a)
	b = ast.Unparen(b)
	switch ea := a.(type) {
	case *ast.Ident:
		eb, ok := b.(*ast.Ident)
		return ok && p.TypesInfo.Uses[ea] != nil && p.TypesInfo.Uses[ea] == p.TypesInfo.Uses[eb]
	case *ast.SelectorExpr:
		eb, ok := b.(*ast.SelectorExpr)
		if !ok || ea.Sel.Name != eb.Sel.Name {
			return false
		}
		sa := p.TypesInfo.Selections[ea]
		sb := p.TypesInfo.Selections[eb]
		if sa == nil || sb == nil || sa.Obj() != sb.Obj() {
			return false
		}
		return SameFieldTargetExpr(p, ea.X, eb.X)
	case *ast.IndexExpr:
		eb, ok := b.(*ast.IndexExpr)
		if !ok || !SameFieldTargetExpr(p, ea.X, eb.X) {
			return false
		}
		tva := p.TypesInfo.Types[ea.Index]
		tvb := p.TypesInfo.Types[eb.Index]
		if tva.Value != nil && tvb.Value != nil {
			return tva.Value.Kind() == tvb.Value.Kind() && constant.Compare(tva.Value, token.EQL, tvb.Value)
		}
		ia, okA := ast.Unparen(ea.Index).(*ast.Ident)
		ib, okB := ast.Unparen(eb.Index).(*ast.Ident)
		if !okA || !okB {
			return false
		}
		iv, okV := p.TypesInfo.Uses[ia].(*types.Var)
		return okV && iv != nil && iv == p.TypesInfo.Uses[ib] && !iv.IsField() && iv.Parent() != p.Types.Scope()
	}
	return false
}


