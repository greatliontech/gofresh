package structmut

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type sentinelKind uint8

const (
	sentinelNil sentinelKind = iota + 1
	sentinelString
	sentinelBytes
	sentinelOtherScalar
)

type efaceUnionHelper struct {
	p            *packages.Package
	idx          *refconfine.PkgIndex
	sentinelVars map[*types.Var]sentinelKind
	safe         map[*ast.CallExpr]bool
}

func (efu *efaceUnionHelper) parseEfaceHeaderPtrType(t types.Type) (hdrSt *types.Struct, hTyp, hData *types.Var, ok bool) {
	if t == nil {
		return nil, nil, nil, false
	}
	ptr, isPtr := types.Unalias(t).(*types.Pointer)
	if !isPtr {
		return nil, nil, nil, false
	}
	elem := types.Unalias(ptr.Elem())
	if named, isN := elem.(*types.Named); isN {
		if named.Obj() == nil || named.Obj().Pkg() != efu.p.Types || named.Obj().Exported() || named.TypeParams() != nil {
			return nil, nil, nil, false
		}
		if types.NewMethodSet(types.NewPointer(named)).Len() != 0 {
			return nil, nil, nil, false
		}
	}
	st, isSt := elem.Underlying().(*types.Struct)
	if !isSt {
		return nil, nil, nil, false
	}
	var ptrFields []*types.Var
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if len(ptrFields) == 0 && isZeroSizedPaddingType(f.Type()) && (!f.Embedded() || types.NewMethodSet(types.NewPointer(f.Type())).Len() == 0) {
			continue
		}
		if !syntaxutil.IsUnsafePointerType(f.Type()) || len(ptrFields) >= 2 {
			return nil, nil, nil, false
		}
		ptrFields = append(ptrFields, f)
	}
	if len(ptrFields) != 2 {
		return nil, nil, nil, false
	}
	return st, ptrFields[0], ptrFields[1], true
}

func (efu *efaceUnionHelper) extractSingleAddrEmptyIfaceLocal(convCall *ast.CallExpr) (*types.Var, *ast.UnaryExpr, bool) {
	if convCall == nil || len(convCall.Args) != 1 || convCall.Ellipsis.IsValid() {
		return nil, nil, false
	}
	tv := efu.p.TypesInfo.Types[ast.Unparen(convCall.Fun)]
	if !tv.IsType() || !syntaxutil.IsUnsafePointerType(tv.Type) {
		return nil, nil, false
	}
	un, isUn := ast.Unparen(convCall.Args[0]).(*ast.UnaryExpr)
	if !isUn || un.Op != token.AND {
		return nil, nil, false
	}
	vid, isID := ast.Unparen(un.X).(*ast.Ident)
	if !isID {
		return nil, nil, false
	}
	v, okV := efu.p.TypesInfo.Uses[vid].(*types.Var)
	if !okV || v == nil || v.IsField() || v.Pkg() != efu.p.Types || v.Parent() == efu.p.Types.Scope() {
		return nil, nil, false
	}
	if !isEmptyInterfaceType(v.Type()) || efu.idx.DefCounts[v] != 1 {
		return nil, nil, false
	}
	encl := innermostFuncOrLitBody(efu.idx, convCall)
	if encl == nil || cachedScopeHasGotoOrLabel(efu.p, efu.idx, encl) {
		return nil, nil, false
	}
	for _, u := range efu.idx.UsesOf[v] {
		if u == vid {
			continue
		}
		if refconfine.IdentIsWrittenOrAddrTaken(efu.idx, u) {
			return nil, nil, false
		}
	}
	return v, un, true
}

func (efu *efaceUnionHelper) isUnsafeBuiltinCall(node ast.Node, wantName string) (*ast.CallExpr, bool) {
	expr, isExpr := node.(ast.Expr)
	if !isExpr {
		return nil, false
	}
	call, isCall := ast.Unparen(expr).(*ast.CallExpr)
	if !isCall || call.Ellipsis.IsValid() {
		return nil, false
	}
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		if b, isB := efu.p.TypesInfo.Uses[fn].(*types.Builtin); isB && b.Name() == wantName {
			return call, true
		}
	case *ast.SelectorExpr:
		if b, isB := efu.p.TypesInfo.Uses[fn.Sel].(*types.Builtin); isB && b.Name() == wantName {
			return call, true
		}
	}
	return nil, false
}

func (efu *efaceUnionHelper) isUnmodifiedSingleDefLocal(v *types.Var) bool {
	if v == nil || v.IsField() || v.Pkg() != efu.p.Types || v.Parent() == efu.p.Types.Scope() || efu.idx.DefCounts[v] != 1 {
		return false
	}
	for _, u := range efu.idx.UsesOf[v] {
		if identIsWrittenAddrOrAutoAddr(efu.p, efu.idx, v, u) {
			return false
		}
	}
	return true
}

func (efu *efaceUnionHelper) isZeroInitEmptyIfaceVar(v *types.Var, allowedAddr *ast.Ident) bool {
	if v == nil || v.IsField() || v.Pkg() != efu.p.Types || v.Parent() == efu.p.Types.Scope() ||
		!isEmptyInterfaceType(v.Type()) || efu.idx.DefCounts[v] != 1 {
		return false
	}
	// Must be either a named result parameter (no initializer) or a var x any with 0 Values.
	if vs := efu.idx.VarSpecs[v]; vs != nil && len(vs.Values) > 0 {
		return false
	}
	// Must not be aShortVarDecl := ...
	for _, file := range efu.p.Syntax {
		badDef := false
		ast.Inspect(file, func(n ast.Node) bool {
			if badDef || n == nil {
				return false
			}
			as, isAS := n.(*ast.AssignStmt)
			if !isAS || as.Tok != token.DEFINE {
				return true
			}
			for _, lhs := range as.Lhs {
				if lid, isID := ast.Unparen(lhs).(*ast.Ident); isID && efu.p.TypesInfo.Defs[lid] == v {
					badDef = true
					return false
				}
			}
			return true
		})
		if badDef {
			return false
		}
	}
	for _, u := range efu.idx.UsesOf[v] {
		if u == allowedAddr {
			continue
		}
		if refconfine.IdentIsWrittenOrAddrTaken(efu.idx, u) {
			return false
		}
	}
	return true
}

func collectSafeEfaceHeaderUnsafePtrConvs(p *packages.Package, idx *refconfine.PkgIndex) map[*ast.CallExpr]bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return nil
	}
	safe := map[*ast.CallExpr]bool{}
	efu := &efaceUnionHelper{
		p:    p,
		idx:  idx,
		safe: safe,
	}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return safe
	}

	// parseEfaceHeaderPtrType verifies an unexported package-local 2-word eface
	// header struct (optional leading 0-sized methodless padding fields followed
	// by exactly two unsafe.Pointer fields at Word 0 = Type and Word 1 = Data).

	// extractSingleAddrEmptyIfaceLocal verifies convCall is unsafe.Pointer(&v)
	// on a local/param/result empty-interface variable v with DefCounts == 1 and
	// no other writes or address-takes anywhere in p.

	// Step 1: Discover unexported Word-0 typeOf(t any) unsafe.Pointer helpers and
	// single-def unmutated package-scope type-tag sentinel globals (nilType,
	// boolType..enumType, stringType, bytesType).
	word0HelperConvs := map[*types.Func]*ast.CallExpr{}
	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || fn.Pkg() != p.Types || fn.Exported() || fd.Recv != nil {
			continue
		}
		sig, okS := fn.Type().(*types.Signature)
		if !okS || sig.TypeParams().Len() > 0 || sig.Params().Len() != 1 || sig.Results().Len() != 1 {
			continue
		}
		if !isEmptyInterfaceType(sig.Params().At(0).Type()) || !syntaxutil.IsUnsafePointerType(sig.Results().At(0).Type()) {
			continue
		}
		if len(fd.Body.List) != 1 || cachedScopeHasGotoOrLabel(efu.p, efu.idx, fd.Body) {
			continue
		}
		ret, isRet := fd.Body.List[0].(*ast.ReturnStmt)
		if !isRet || len(ret.Results) != 1 {
			continue
		}
		sel, isSel := ast.Unparen(ret.Results[0]).(*ast.SelectorExpr)
		if !isSel {
			continue
		}
		hdrCast, isCast := ast.Unparen(sel.X).(*ast.CallExpr)
		if !isCast || len(hdrCast.Args) != 1 || hdrCast.Ellipsis.IsValid() {
			continue
		}
		hdrTV := p.TypesInfo.Types[ast.Unparen(hdrCast.Fun)]
		if !hdrTV.IsType() {
			continue
		}
		_, hTyp, _, okHdr := efu.parseEfaceHeaderPtrType(hdrTV.Type)
		if !okHdr {
			continue
		}
		sInfo := p.TypesInfo.Selections[sel]
		if sInfo == nil || sInfo.Kind() != types.FieldVal || sInfo.Obj() != hTyp {
			continue
		}
		innerConv, isInner := ast.Unparen(hdrCast.Args[0]).(*ast.CallExpr)
		if !isInner {
			continue
		}
		pv, _, okPV := efu.extractSingleAddrEmptyIfaceLocal(innerConv)
		if !okPV || pv != sig.Params().At(0) {
			continue
		}
		word0HelperConvs[fn] = innerConv
	}

	sentinelVars := map[*types.Var]sentinelKind{}
	usedWord0Helpers := map[*types.Func]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v == nil || v.Exported() || idx.DefCounts[v] != 1 || !syntaxutil.IsUnsafePointerType(v.Type()) {
			continue
		}
		vs := idx.VarSpecs[v]
		if vs == nil || len(vs.Names) != len(vs.Values) {
			continue
		}
		var initExpr ast.Expr
		for i, nm := range vs.Names {
			if p.TypesInfo.Defs[nm] == v {
				initExpr = vs.Values[i]
				break
			}
		}
		call, isCall := ast.Unparen(initExpr).(*ast.CallExpr)
		if !isCall || len(call.Args) != 1 || call.Ellipsis.IsValid() {
			continue
		}
		callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
		if callee == nil || word0HelperConvs[callee] == nil {
			continue
		}
		written := false
		for _, uid := range idx.UsesOf[v] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				written = true
				break
			}
		}
		if written {
			continue
		}
		arg := call.Args[0]
		if syntaxutil.IsNilIdent(p.TypesInfo, arg) {
			sentinelVars[v] = sentinelNil
			usedWord0Helpers[callee] = true
			continue
		}
		argT := p.TypesInfo.TypeOf(arg)
		if argT == nil || types.IsInterface(argT) {
			continue
		}
		switch u := syntaxutil.UnderlyingType(argT).(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer || u.Kind() == types.Uintptr {
				continue
			}
			if u.Kind() == types.String {
				sentinelVars[v] = sentinelString
			} else {
				sentinelVars[v] = sentinelOtherScalar
			}
			usedWord0Helpers[callee] = true
		case *types.Slice:
			if eb, isB := syntaxutil.UnderlyingType(u.Elem()).(*types.Basic); isB && eb.Kind() == types.Byte {
				sentinelVars[v] = sentinelBytes
				usedWord0Helpers[callee] = true
			}
		}
	}

	// Verify every call to a word0Helper is either initializing a verified
	// sentinelVar or directly compared with == / !=.
	for fn, innerConv := range word0HelperConvs {
		allCallsSafe := true
		for _, uid := range idx.UsesOf[fn] {
			call, isCall := idx.ParentUnparen(uid).(*ast.CallExpr)
			if !isCall || ast.Unparen(call.Fun) != uid {
				allCallsSafe = false
				break
			}
			switch par := idx.ParentUnparen(call).(type) {
			case *ast.BinaryExpr:
				if par.Op != token.EQL && par.Op != token.NEQ {
					allCallsSafe = false
				}
			case *ast.ValueSpec:
				okSpec := false
				for i, val := range par.Values {
					if ast.Unparen(val) == call && i < len(par.Names) {
						if dv, _ := p.TypesInfo.Defs[par.Names[i]].(*types.Var); dv != nil && sentinelVars[dv] != 0 {
							okSpec = true
						}
					}
				}
				if !okSpec {
					allCallsSafe = false
				}
			default:
				allCallsSafe = false
			}
			if !allCallsSafe {
				break
			}
		}
		if allCallsSafe && (usedWord0Helpers[fn] || len(idx.UsesOf[fn]) > 0) {
			safe[innerConv] = true
		}
	}

	efu.sentinelVars = sentinelVars
	efu.verifyEfaceUnionStructs()
	return safe
}
