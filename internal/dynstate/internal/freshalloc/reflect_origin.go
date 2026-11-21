package freshalloc

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// CollectFuncParamVars returns all receiver, parameter, and named-result
// variables declared on functions and closures across p.Syntax.
func CollectFuncParamVars(p *packages.Package) map[*types.Var]bool {
	out := map[*types.Var]bool{}
	if p == nil || p.TypesInfo == nil {
		return out
	}
	addFieldList := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, fld := range fl.List {
			for _, nm := range fld.Names {
				if v, ok := p.TypesInfo.Defs[nm].(*types.Var); ok && v != nil {
					out[v] = true
				}
			}
		}
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch fn := n.(type) {
			case *ast.FuncDecl:
				addFieldList(fn.Recv)
				if fn.Type != nil {
					addFieldList(fn.Type.Params)
					addFieldList(fn.Type.Results)
				}
			case *ast.FuncLit:
				if fn.Type != nil {
					addFieldList(fn.Type.Params)
					addFieldList(fn.Type.Results)
				}
			}
			return true
		})
	}
	return out
}

// TypeMentionsReflectValue reports whether root reaches reflect.Value outside
// reflect.Type, reflect.Method, and reflect.StructField metadata structs.
func TypeMentionsReflectValue(root types.Type) bool {
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
		if syntaxutil.IsNamedInPkg(t, "reflect", "Value") {
			hit = true
			return
		}
		if syntaxutil.IsNamedInPkg(t, "reflect", "Type") ||
			syntaxutil.IsNamedInPkg(t, "reflect", "Method") ||
			syntaxutil.IsNamedInPkg(t, "reflect", "StructField") {
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
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				walk(u.Method(i).Type())
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

func isStdNonValueOfReflectOrigin(p *packages.Package, fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" || !syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() != nil {
		return false
	}
	switch fn.Name() {
	case "New", "NewAt", "Zero", "MakeSlice", "MakeMap", "MakeMapWithSize", "MakeChan", "MakeFunc", "SliceAt":
		return true
	default:
		return false
	}
}

func isNonValueOfReflectExpr(p *packages.Package, expr ast.Expr, allowedLocal *types.Var, nonValueOfCtors map[*types.Func]bool) bool {
	if p == nil || p.TypesInfo == nil || expr == nil {
		return false
	}
	expr = ast.Unparen(expr)
	if id, isID := expr.(*ast.Ident); isID {
		if allowedLocal == nil {
			return false
		}
		v, _ := p.TypesInfo.Uses[id].(*types.Var)
		return v == allowedLocal
	}
	call, isCall := expr.(*ast.CallExpr)
	if !isCall || call.Ellipsis.IsValid() {
		return false
	}
	callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
	if callee == nil {
		return false
	}
	if isStdNonValueOfReflectOrigin(p, callee) || nonValueOfCtors[callee.Origin()] {
		return true
	}
	if callee.Pkg() != nil && callee.Pkg().Path() == "reflect" && syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
		if sig, okS := callee.Type().(*types.Signature); okS && sig.Recv() != nil &&
			syntaxutil.IsNamedInPkg(sig.Recv().Type(), "reflect", "Value") {
			switch callee.Name() {
			case "Elem", "Field", "FieldByName", "FieldByIndex", "Index", "Slice", "Slice3", "Addr", "Convert":
				sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
				return isSel && isNonValueOfReflectExpr(p, sel.X, allowedLocal, nonValueOfCtors)
			}
		}
	}
	return false
}

// CollectNonValueOfReflectConstructors returns intra-package functions whose
// reflect.Value result originates exclusively from fresh non-ValueOf reflect
// constructors (New, Zero, MakeSlice, MakeMap, etc.).
func CollectNonValueOfReflectConstructors(p *packages.Package, idx *refconfine.PkgIndex) map[*types.Func]bool {
	out := map[*types.Func]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return out
	}
	cands := map[*types.Func]*ast.FuncDecl{}
	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || fn.Pkg() != p.Types {
			continue
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Results().Len() != 1 || !syntaxutil.IsNamedInPkg(sig.Results().At(0).Type(), "reflect", "Value") {
			continue
		}
		if sig.Recv() != nil && TypeMentionsReflectValue(sig.Recv().Type()) {
			continue
		}
		badParam := false
		for i := 0; i < sig.Params().Len(); i++ {
			if TypeMentionsReflectValue(sig.Params().At(i).Type()) {
				badParam = true
				break
			}
		}
		if !badParam {
			cands[fn] = fd
		}
	}
	for changed := true; changed; {
		changed = false
		for fn, fd := range cands {
			if out[fn] {
				continue
			}
			allOK := true
			sawRet := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if !allOK || n == nil {
					return false
				}
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
				ret, isRet := n.(*ast.ReturnStmt)
				if !isRet {
					return true
				}
				sawRet = true
				if len(ret.Results) != 1 || !isNonValueOfReflectExpr(p, ret.Results[0], nil, out) {
					allOK = false
					return false
				}
				return true
			})
			if sawRet && allOK {
				out[fn] = true
				changed = true
			}
		}
	}
	return out
}

// IsCallOnNonValueOfLocal reports whether call's reflect.Value receiver chain
// originates from a fresh non-ValueOf constructor or local variable initialized
// exclusively from non-ValueOf origins inside enclScope.
func IsCallOnNonValueOfLocal(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	enclScope ast.Node,
	call *ast.CallExpr,
	nonValueOfCtors map[*types.Func]bool,
	funcParamVars map[*types.Var]bool,
) bool {
	if p == nil || p.TypesInfo == nil || idx == nil || enclScope == nil || call == nil {
		return false
	}
	fc := idx.FlowCache(p)
	if fc == nil {
		return false
	}
	callVal := fc.ExprValue(call)
	if callVal == nil || callVal.Kind != flowir.ValCall || callVal.CallKind != flowir.CallMethod || callVal.IsMethodExprCall || callVal.Recv == nil {
		return false
	}
	base := callVal.Recv
	for base != nil && base.Kind == flowir.ValCall && !base.Ellipsis && !base.IsMethodExprCall {
		fn := base.CalleeFunc
		if fn == nil || fn.Pkg() == nil {
			return false
		}
		if isStdNonValueOfReflectOrigin(p, fn) || nonValueOfCtors[fn.Origin()] {
			return true
		}
		if fn.Pkg().Path() != "reflect" || !syntaxutil.IsTrueStdlibInPkg(p, "reflect") || base.CallKind != flowir.CallMethod || base.Recv == nil {
			return false
		}
		switch fn.Name() {
		case "Elem", "Field", "FieldByName", "FieldByIndex", "Index", "Slice", "Slice3", "Addr", "Convert":
			base = base.Recv
		default:
			return false
		}
	}
	if base == nil || base.Kind != flowir.ValPlace || !base.Place.IsBareVar() {
		return false
	}
	rv := base.Place.Obj
	if rv == nil || funcParamVars[rv] || !syntaxutil.IsNamedInPkg(rv.Type(), "reflect", "Value") ||
		rv.Parent() == p.Types.Scope() || rv.Pos() < enclScope.Pos() || rv.Pos() >= enclScope.End() {
		return false
	}
	scopeBody := fc.ScopeBody(enclScope)
	if scopeBody == nil {
		return false
	}
	sawInit := false
	clean := flowir.ForEachNestedOp(nil, nil, scopeBody, scopeBody, func(_ *types.Func, _ *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
		addrTainted := false
		op.ForEachValue(func(root *flowir.Value) bool {
			root.WalkValues(func(v *flowir.Value) bool {
				if addrTainted || v == nil {
					return false
				}
				switch v.Kind {
				case flowir.ValAddrOf:
					if v.AddrPlace.Obj == rv {
						addrTainted = true
						return false
					}
				case flowir.ValMethodVal:
					if v.AutoAddr && v.HasRecvPlace && v.RecvPlace.Obj == rv {
						addrTainted = true
						return false
					}
				case flowir.ValCall:
					if v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj == rv {
						addrTainted = true
						return false
					}
				}
				return true
			})
			return !addrTainted
		})
		if addrTainted {
			return false
		}
		switch op.Kind {
		case flowir.OpAssign:
			for i, dst := range op.Dsts {
				if dst.Obj != rv {
					continue
				}
				if op.AssignKind == flowir.AssignZeroDecl && dst.IsBareVar() {
					continue
				}
				if op.AssignKind != flowir.AssignPlain || !dst.IsBareVar() || len(op.Dsts) != len(op.Srcs) ||
					op.Srcs[i] == nil || op.Srcs[i].Raw == nil || !isNonValueOfReflectExpr(p, op.Srcs[i].Raw, rv, nonValueOfCtors) {
					return false
				}
				sawInit = true
			}
		case flowir.OpTypeSwitchBind:
			if op.SwitchDst == rv {
				return false
			}
		}
		return true
	})
	return sawInit && clean
}

// PkgCanStepUnexportedReflectField reports whether p references any
// reflect.Value struct-field selector capable of reading an unexported field
// of a ValueOf-derived struct (excluding non-ValueOf constructor chains and
// immediate scalar extractions on exported constant field names).
func PkgCanStepUnexportedReflectField(p *packages.Package, idx *refconfine.PkgIndex) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || !syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
		return false
	}
	isFieldStepFunc := func(fn *types.Func) bool {
		if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" {
			return false
		}
		sig, okSig := fn.Type().(*types.Signature)
		if !okSig || sig.Recv() == nil || !syntaxutil.IsNamedInPkg(sig.Recv().Type(), "reflect", "Value") {
			return false
		}
		switch fn.Name() {
		case "Field", "FieldByName", "FieldByIndex", "FieldByIndexErr", "FieldByNameFunc", "Fields":
			return true
		default:
			return false
		}
	}
	hasAnyFieldStep := false
	for _, obj := range p.TypesInfo.Uses {
		if fn, ok := obj.(*types.Func); ok && isFieldStepFunc(fn) {
			hasAnyFieldStep = true
			break
		}
	}
	if !hasAnyFieldStep {
		return false
	}
	funcParamVars := CollectFuncParamVars(p)
	nonValueOfCtors := CollectNonValueOfReflectConstructors(p, idx)
	pureScalarReflectFDs := collectPureScalarReflectPredicates(p, idx)
	verifiedFieldIdents := map[*ast.Ident]bool{}
	canStep := false
	isImmediateScalarExportedFieldByName := func(call *ast.CallExpr, fn *types.Func) bool {
		if fn.Name() != "FieldByName" || len(call.Args) != 1 || call.Ellipsis.IsValid() {
			return false
		}
		tv, okTV := p.TypesInfo.Types[call.Args[0]]
		if !okTV || tv.Value == nil || tv.Value.Kind() != constant.String {
			return false
		}
		if !token.IsExported(constant.StringVal(tv.Value)) {
			return false
		}
		parSel, isSel := idx.ParentUnparen(call).(*ast.SelectorExpr)
		if !isSel || ast.Unparen(parSel.X) != call || parSel.Sel == nil {
			return false
		}
		parCall, isCall := idx.ParentUnparen(parSel).(*ast.CallExpr)
		if !isCall || ast.Unparen(parCall.Fun) != parSel || len(parCall.Args) != 0 || parCall.Ellipsis.IsValid() {
			return false
		}
		switch parSel.Sel.Name {
		case "Int", "Uint", "Float", "Complex", "Bool", "Len", "Cap", "Kind", "Type", "IsZero", "IsValid":
			return true
		default:
			return false
		}
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if canStep || n == nil {
				return false
			}
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			fn := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
			if !isFieldStepFunc(fn) {
				return true
			}
			if call.Ellipsis.IsValid() {
				canStep = true
				return false
			}
			sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !isSel || sel.Sel == nil {
				canStep = true
				return false
			}
			if selInfo := p.TypesInfo.Selections[sel]; selInfo == nil || selInfo.Kind() != types.MethodVal {
				canStep = true
				return false
			}
			if isImmediateScalarExportedFieldByName(call, fn) {
				verifiedFieldIdents[sel.Sel] = true
				return true
			}
			var enclScope ast.Node
			for cur := idx.ParentMap[call]; cur != nil; cur = idx.ParentMap[cur] {
				if lit, isLit := cur.(*ast.FuncLit); isLit {
					enclScope = lit
					break
				}
				if fd, isFD := cur.(*ast.FuncDecl); isFD {
					enclScope = fd
					break
				}
			}
			if fd, isFD := enclScope.(*ast.FuncDecl); isFD && pureScalarReflectFDs[fd] {
				verifiedFieldIdents[sel.Sel] = true
				return true
			}
			if enclScope == nil || !IsCallOnNonValueOfLocal(p, idx, enclScope, call, nonValueOfCtors, funcParamVars) {
				canStep = true
				return false
			}
			verifiedFieldIdents[sel.Sel] = true
			return true
		})
		if canStep {
			return true
		}
	}
	for id, obj := range p.TypesInfo.Uses {
		if fn, ok := obj.(*types.Func); ok && isFieldStepFunc(fn) && !verifiedFieldIdents[id] {
			return true
		}
	}
	return false
}

func collectPureScalarReflectPredicates(p *packages.Package, idx *refconfine.PkgIndex) map[*ast.FuncDecl]bool {
	out := map[*ast.FuncDecl]bool{}
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return out
	}
	isPureScalar := func(t types.Type) bool {
		if t == nil {
			return false
		}
		b, ok := syntaxutil.UnderlyingType(t).(*types.Basic)
		return ok && b.Kind() != types.UnsafePointer && b.Kind() != types.Uintptr
	}
	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || fn.Pkg() != p.Types || fn.Exported() {
			continue
		}
		sig, okS := fn.Type().(*types.Signature)
		if !okS || sig.Recv() != nil || sig.TypeParams().Len() > 0 || sig.Results().Len() == 0 {
			continue
		}
		pureSig := true
		for i := 0; i < sig.Results().Len(); i++ {
			if !isPureScalar(sig.Results().At(i).Type()) {
				pureSig = false
				break
			}
		}
		for i := 0; pureSig && i < sig.Params().Len(); i++ {
			pt := sig.Params().At(i).Type()
			if !isPureScalar(pt) && !syntaxutil.IsNamedInPkg(pt, "reflect", "Value") {
				pureSig = false
			}
		}
		if !pureSig {
			continue
		}
		localVars := map[*types.Var]bool{}
		for i := 0; i < sig.Params().Len(); i++ {
			if pv := sig.Params().At(i); pv != nil {
				localVars[pv] = true
			}
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if id, isID := n.(*ast.Ident); isID {
				if dv, ok := p.TypesInfo.Defs[id].(*types.Var); ok && dv != nil && !dv.IsField() && dv.Parent() != p.Types.Scope() {
					localVars[dv] = true
				}
			}
			return true
		})
		clean := true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !clean || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.FuncLit, *ast.GoStmt, *ast.SendStmt:
				clean = false
				return false
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if cl, isCL := ast.Unparen(x.X).(*ast.CompositeLit); !isCL || !syntaxutil.IsNamedInPkg(p.TypesInfo.TypeOf(cl), "reflect", "ValueError") {
						clean = false
						return false
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					id, isID := ast.Unparen(lhs).(*ast.Ident)
					if !isID {
						clean = false
						return false
					}
					if id.Name == "_" {
						continue
					}
					v, _ := p.TypesInfo.Uses[id].(*types.Var)
					if v == nil {
						v, _ = p.TypesInfo.Defs[id].(*types.Var)
					}
					if !localVars[v] || !isPureScalar(v.Type()) {
						clean = false
						return false
					}
				}
			case *ast.IncDecStmt:
				id, isID := ast.Unparen(x.X).(*ast.Ident)
				if !isID {
					clean = false
					return false
				}
				v, _ := p.TypesInfo.Uses[id].(*types.Var)
				if !localVars[v] || !isPureScalar(v.Type()) {
					clean = false
					return false
				}
			case *ast.CallExpr:
				if p.TypesInfo.Types[x.Fun].IsType() {
					return true
				}
				if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(x.Fun)); b != nil {
					switch b.Name() {
					case "len", "cap", "real", "imag", "complex", "min", "max", "panic":
						return true
					default:
						clean = false
						return false
					}
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
				if callee == nil || callee.Pkg() == nil {
					clean = false
					return false
				}
				if callee.Origin() == fn {
					return true
				}
				if callee.Pkg().Path() == "math" && syntaxutil.IsTrueStdlibInPkg(p, "math") {
					switch callee.Name() {
					case "Float64bits", "Float32bits", "IsNaN", "IsInf":
						return true
					}
					clean = false
					return false
				}
				if callee.Pkg().Path() == "reflect" && syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
					csig, okCS := callee.Type().(*types.Signature)
					if !okCS || csig.Recv() == nil || !syntaxutil.IsNamedInPkg(csig.Recv().Type(), "reflect", "Value") {
						clean = false
						return false
					}
					switch callee.Name() {
					case "Kind", "Bool", "Int", "Uint", "Float", "Complex", "Len", "Cap",
						"IsNil", "IsZero", "IsValid", "NumField", "Field", "Index", "Elem":
						return true
					}
				}
				clean = false
				return false
			}
			return true
		})
		if clean {
			out[fd] = true
		}
	}
	return out
}
