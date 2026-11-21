package toolchain

import (
	"go/ast"
	"go/token"
	"strconv"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func unwrapParens(expr ast.Expr) ast.Expr {
	return ast.Unparen(expr)
}

func recvTypeIdent(expr ast.Expr) *ast.Ident {
	expr = unwrapParens(expr)
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = unwrapParens(star.X)
	}
	id, _ := expr.(*ast.Ident)
	return id
}

func recvTypeName(expr ast.Expr) string {
	if id := recvTypeIdent(expr); id != nil {
		return id.Name
	}
	return ""
}

func baseTypeIdentName(expr ast.Expr) string {
	expr = unwrapParens(expr)
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		if id, ok := unwrapParens(t.X).(*ast.Ident); ok {
			return id.Name
		}
	case *ast.IndexListExpr:
		if id, ok := unwrapParens(t.X).(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

func recvBaseTypeName(expr ast.Expr) string {
	return syntaxutil.RecvBaseTypeName(expr)
}

func recvVarName(fn *ast.FuncDecl) string {
	if fn == nil || fn.Recv == nil || len(fn.Recv.List) != 1 {
		return ""
	}
	names := fn.Recv.List[0].Names
	if len(names) != 1 || names[0].Name == "_" {
		return ""
	}
	return names[0].Name
}

func funcResultFieldTypeAt(results *ast.FieldList, targetIdx int) ast.Expr {
	if results == nil || targetIdx < 0 {
		return nil
	}
	cur := 0
	for _, fld := range results.List {
		n := len(fld.Names)
		if n == 0 {
			n = 1
		}
		if targetIdx < cur+n {
			return fld.Type
		}
		cur += n
	}
	return nil
}

func funcHasUnnamedResults(ft *ast.FuncType, count int) bool {
	if ft == nil || ft.Results == nil || ft.Results.NumFields() != count || len(ft.Results.List) != count {
		return false
	}
	for _, fld := range ft.Results.List {
		if len(fld.Names) != 0 {
			return false
		}
	}
	return true
}

func isMethodCallNamed(expr ast.Expr, name string) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == name
}

func isIdentNamed(expr ast.Expr, name string) (*ast.Ident, bool) {
	id, ok := unwrapParens(expr).(*ast.Ident)
	return id, ok && id.Name == name
}

func isSelectorBaseField(expr ast.Expr, base, field string) (*ast.Ident, bool) {
	sel, ok := unwrapParens(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != field {
		return nil, false
	}
	return isIdentNamed(sel.X, base)
}

func isZeroArgMethodCallOnSelector(expr ast.Expr, base, field, method string) (*ast.Ident, bool) {
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
		return nil, false
	}
	sel, ok := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return nil, false
	}
	return isSelectorBaseField(sel.X, base, field)
}

func isZeroArgMethodCallOnIdent(expr ast.Expr, base, method string) (*ast.Ident, bool) {
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 0 {
		return nil, false
	}
	return isSelectorBaseField(call.Fun, base, method)
}

func exprReferencesDiscard(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.Ident:
			if x.Name == "Discard" {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if x.Sel.Name == "Discard" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func exprContainsAnyCall(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		if _, ok := n.(*ast.CallExpr); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

func exprHasCallOrFuncLit(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch n.(type) {
		case *ast.CallExpr, *ast.FuncLit:
			found = true
			return false
		}
		return true
	})
	return found
}

func compositeWriterLit(expr ast.Expr) (*ast.CompositeLit, string) {
	expr = unwrapParens(expr)
	if u, ok := expr.(*ast.UnaryExpr); ok && u.Op == token.AND {
		expr = unwrapParens(u.X)
	}
	lit, ok := expr.(*ast.CompositeLit)
	if !ok || lit.Type == nil {
		return nil, ""
	}
	id, ok := unwrapParens(lit.Type).(*ast.Ident)
	if !ok {
		return nil, ""
	}
	return lit, id.Name
}

func funcReturnsErrorLast(ft *ast.FuncType) bool {
	if ft == nil || ft.Results == nil || len(ft.Results.List) == 0 {
		return false
	}
	last := ft.Results.List[len(ft.Results.List)-1]
	id, ok := unwrapParens(last.Type).(*ast.Ident)
	return ok && id.Name == "error"
}

func lastNamedResultIdent(results *ast.FieldList) string {
	if results == nil || len(results.List) == 0 {
		return ""
	}
	last := results.List[len(results.List)-1]
	if len(last.Names) == 0 {
		return ""
	}
	name := last.Names[len(last.Names)-1].Name
	if name == "_" {
		return ""
	}
	return name
}

func paramNamesFlat(params *ast.FieldList) []string {
	if params == nil {
		return nil
	}
	var out []string
	for _, field := range params.List {
		if len(field.Names) == 0 {
			out = append(out, "")
			continue
		}
		for _, n := range field.Names {
			out = append(out, n.Name)
		}
	}
	return out
}

func isByteSliceType(expr ast.Expr) bool {
	arr, ok := unwrapParens(expr).(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	elt, ok := unwrapParens(arr.Elt).(*ast.Ident)
	return ok && elt.Name == "byte"
}

func byteSliceParamIdents(params *ast.FieldList) map[string]bool {
	out := map[string]bool{}
	if params == nil {
		return out
	}
	for _, field := range params.List {
		if !isByteSliceType(field.Type) {
			continue
		}
		for _, n := range field.Names {
			if n.Name != "" && n.Name != "_" {
				out[n.Name] = true
			}
		}
	}
	return out
}

func singleByteSliceParamIdent(params *ast.FieldList) string {
	if params == nil || params.NumFields() != 1 || len(params.List) != 1 || len(params.List[0].Names) != 1 {
		return ""
	}
	if !isByteSliceType(params.List[0].Type) {
		return ""
	}
	name := params.List[0].Names[0].Name
	if name == "" || name == "_" {
		return ""
	}
	return name
}

func firstResultIsInt(results *ast.FieldList) bool {
	if results == nil || len(results.List) == 0 {
		return false
	}
	first := results.List[0]
	id, ok := unwrapParens(first.Type).(*ast.Ident)
	return ok && id.Name == "int"
}

func firstNamedIntResultIdent(results *ast.FieldList) string {
	if results == nil || results.NumFields() != 2 || !firstResultIsInt(results) {
		return ""
	}
	first := results.List[0]
	if len(first.Names) == 0 {
		return ""
	}
	name := first.Names[0].Name
	if name == "_" {
		return ""
	}
	return name
}

func isZeroIntLit(expr ast.Expr) bool {
	lit, ok := unwrapParens(expr).(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
}

func isPositiveIntLit(expr ast.Expr) bool {
	lit, ok := unwrapParens(expr).(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return false
	}
	v, err := strconv.ParseUint(lit.Value, 0, 64)
	return err == nil && v > 0
}

func isOneArgLenIdentCall(call *ast.CallExpr) bool {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	funID, ok := unwrapParens(call.Fun).(*ast.Ident)
	if !ok || funID.Name != "len" {
		return false
	}
	_, ok = unwrapParens(call.Args[0]).(*ast.Ident)
	return ok
}

func isLenOfIdentCall(expr ast.Expr, identName string) bool {
	if identName == "" {
		return false
	}
	call, ok := unwrapParens(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return false
	}
	funID, ok := unwrapParens(call.Fun).(*ast.Ident)
	if !ok || funID.Name != "len" {
		return false
	}
	argID, ok := unwrapParens(call.Args[0]).(*ast.Ident)
	return ok && argID.Name == identName
}

func isSliceLenZeroCond(cond ast.Expr, sliceName string) bool {
	if sliceName == "" {
		return false
	}
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	return (isLenOfIdentCall(bin.X, sliceName) && isZeroIntLit(bin.Y)) ||
		(isZeroIntLit(bin.X) && isLenOfIdentCall(bin.Y, sliceName))
}

func isConstantOrTrivialCond(cond ast.Expr) bool {
	cond = unwrapParens(cond)
	switch e := cond.(type) {
	case nil:
		return true
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return e.Name == "true" || e.Name == "false" || e.Name == "nil"
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return isConstantOrTrivialCond(e.X)
		}
		return exprHasCallOrFuncLit(e.X)
	case *ast.BinaryExpr:
		if exprHasCallOrFuncLit(e.X) || exprHasCallOrFuncLit(e.Y) {
			return true
		}
		if e.Op == token.LAND || e.Op == token.LOR {
			return isConstantOrTrivialCond(e.X) || isConstantOrTrivialCond(e.Y)
		}
		if isConstantOrTrivialCond(e.X) && isConstantOrTrivialCond(e.Y) {
			return true
		}
		if xID, ok := unwrapParens(e.X).(*ast.Ident); ok {
			if yID, ok2 := unwrapParens(e.Y).(*ast.Ident); ok2 && xID.Name == yID.Name {
				return true
			}
		}
		return false
	default:
		return exprHasCallOrFuncLit(cond)
	}
}

func condChecksNonZeroErr(cond ast.Expr) string {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return ""
	}
	lhs, rhs := unwrapParens(bin.X), unwrapParens(bin.Y)
	if id, ok := lhs.(*ast.Ident); ok {
		if rID, ok := rhs.(*ast.Ident); ok && rID.Name == "nil" {
			return id.Name
		}
		if lit, ok := rhs.(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "0" {
			return id.Name
		}
	}
	if id, ok := rhs.(*ast.Ident); ok {
		if lID, ok := lhs.(*ast.Ident); ok && lID.Name == "nil" {
			return id.Name
		}
		if lit, ok := lhs.(*ast.BasicLit); ok && lit.Kind == token.INT && lit.Value == "0" {
			return id.Name
		}
	}
	return ""
}

func condChecksEqErr(cond ast.Expr, wantIdent string) bool {
	bin, ok := unwrapParens(cond).(*ast.BinaryExpr)
	if !ok || bin.Op != token.EQL {
		return false
	}
	lhs, rhs := unwrapParens(bin.X), unwrapParens(bin.Y)
	if id, ok := lhs.(*ast.Ident); ok && id.Name == wantIdent {
		if rID, ok := rhs.(*ast.Ident); ok && rID.Name == "nil" {
			return true
		}
	}
	if id, ok := rhs.(*ast.Ident); ok && id.Name == wantIdent {
		if lID, ok := lhs.(*ast.Ident); ok && lID.Name == "nil" {
			return true
		}
	}
	return false
}

func isCountAdvanceSliceAssign(s *ast.AssignStmt, sliceName string, countAliases map[string]bool) bool {
	if s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		return false
	}
	lhsID, ok := unwrapParens(s.Lhs[0]).(*ast.Ident)
	if !ok || lhsID.Name != sliceName {
		return false
	}
	sl, ok := unwrapParens(s.Rhs[0]).(*ast.SliceExpr)
	if !ok || sl.Slice3 || sl.High != nil || sl.Low == nil {
		return false
	}
	baseID, ok := unwrapParens(sl.X).(*ast.Ident)
	if !ok || baseID.Name != sliceName {
		return false
	}
	low := unwrapParens(sl.Low)
	if conv, isCall := low.(*ast.CallExpr); isCall && len(conv.Args) == 1 && !conv.Ellipsis.IsValid() {
		if cid, ok := unwrapParens(conv.Fun).(*ast.Ident); ok && (cid.Name == "int" || cid.Name == "uintptr") {
			low = unwrapParens(conv.Args[0])
		}
	}
	advID, ok := low.(*ast.Ident)
	return ok && countAliases[advID.Name]
}

// verifyIgnoringEINTRHelper verifies the structural shape of os.ignoringEINTR
// (arity 1) or os.ignoringEINTR2 (arity 2).
func verifyIgnoringEINTRHelper(igFn *ast.FuncDecl, hasUnaliasedSyscall bool, reserved map[string]bool, arity int) bool {
	if (arity != 1 && arity != 2) || igFn == nil || igFn.Body == nil || igFn.Type == nil {
		return false
	}
	if arity == 1 && igFn.Type.TypeParams != nil {
		return false
	}
	if arity == 2 && igFn.Type.TypeParams != nil && igFn.Type.TypeParams.NumFields() > 1 {
		return false
	}
	if !funcHasUnnamedResults(igFn.Type, arity) || funcShadowsAnyIdent(igFn, reserved) || bodyHasControlFlowOrRecoverBypass(igFn.Body) {
		return false
	}
	igParams := paramNamesFlat(igFn.Type.Params)
	if len(igParams) != 1 || igParams[0] == "" || igParams[0] == "_" || len(igFn.Body.List) != 1 {
		return false
	}
	if ret, okRet := igFn.Body.List[0].(*ast.ReturnStmt); okRet && len(ret.Results) == 1 {
		c, okC := unwrapParens(ret.Results[0]).(*ast.CallExpr)
		if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
			return false
		}
		_, okFn := isIdentNamed(c.Fun, igParams[0])
		return okFn
	}
	fs, okFor := igFn.Body.List[0].(*ast.ForStmt)
	if !okFor || !hasUnaliasedSyscall || fs.Init != nil || fs.Cond != nil || fs.Post != nil || len(fs.Body.List) != 2 {
		return false
	}
	as, okA := fs.Body.List[0].(*ast.AssignStmt)
	if !okA || as.Tok != token.DEFINE || len(as.Lhs) != arity || len(as.Rhs) != 1 {
		return false
	}
	var vName, errName string
	if arity == 1 {
		errID, okE := unwrapParens(as.Lhs[0]).(*ast.Ident)
		if !okE || errID.Name == "" || errID.Name == "_" {
			return false
		}
		errName = errID.Name
	} else {
		vID, okV := unwrapParens(as.Lhs[0]).(*ast.Ident)
		errID, okE := unwrapParens(as.Lhs[1]).(*ast.Ident)
		if !okV || !okE || vID.Name == "" || vID.Name == "_" || errID.Name == "" || errID.Name == "_" || vID.Name == errID.Name {
			return false
		}
		vName, errName = vID.Name, errID.Name
	}
	c, okC := unwrapParens(as.Rhs[0]).(*ast.CallExpr)
	if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
		return false
	}
	if _, okFn := isIdentNamed(c.Fun, igParams[0]); !okFn {
		return false
	}
	ifs, okI := fs.Body.List[1].(*ast.IfStmt)
	if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 {
		return false
	}
	condBin, okCB := unwrapParens(ifs.Cond).(*ast.BinaryExpr)
	if !okCB || condBin.Op != token.NEQ {
		return false
	}
	_, okEL := isIdentNamed(condBin.X, errName)
	_, okSysR := isSelectorBaseField(condBin.Y, "syscall", "EINTR")
	_, okSysL := isSelectorBaseField(condBin.X, "syscall", "EINTR")
	_, okER := isIdentNamed(condBin.Y, errName)
	if !((okEL && okSysR) || (okSysL && okER)) {
		return false
	}
	ret, okR := ifs.Body.List[0].(*ast.ReturnStmt)
	if !okR || len(ret.Results) != arity {
		return false
	}
	if arity == 1 {
		_, okRetErr := isIdentNamed(ret.Results[0], errName)
		return okRetErr
	}
	_, okRV := isIdentNamed(ret.Results[0], vName)
	_, okRE := isIdentNamed(ret.Results[1], errName)
	return okRV && okRE
}
