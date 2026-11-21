package structmut

import (
	"go/ast"
	"go/token"
	"go/types"
	"strconv"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshalloc"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func isEmptyInterfaceType(t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if _, isTP := t.(*types.TypeParam); isTP {
		return false
	}
	iface, ok := t.Underlying().(*types.Interface)
	return ok && iface.NumMethods() == 0
}

func pkgCanBypassReflectFlagRO(p *packages.Package, idx *refconfine.PkgIndex, sawCrossPkgReflectValArg bool, funcParamVars map[*types.Var]bool) (canBypass bool, hasBoundaryEscape bool) {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return false, false
	}
	hasBoundaryEscape = sawCrossPkgReflectValArg || pkgExposesReflectValueBoundary(p)
	if !syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
		return false, hasBoundaryEscape
	}
	importsUnsafe := false
	for _, file := range p.Syntax {
		for _, imp := range file.Imports {
			if imp != nil && imp.Path != nil {
				if uq, err := strconv.Unquote(imp.Path.Value); err == nil && uq == "unsafe" {
					importsUnsafe = true
					break
				}
			}
		}
	}
	isBypassSinkFunc := func(fn *types.Func) bool {
		if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" {
			return false
		}
		sig, okSig := fn.Type().(*types.Signature)
		if !okSig || sig.Recv() == nil || !syntaxutil.IsNamedInPkg(sig.Recv().Type(), "reflect", "Value") {
			return false
		}
		switch fn.Name() {
		case "UnsafePointer", "UnsafeAddr", "Clear", "Bytes", "Pointer", "InterfaceData":
			return true
		default:
			return false
		}
	}
	hasAnySinkRef := false
	for _, obj := range p.TypesInfo.Uses {
		if fn, ok := obj.(*types.Func); ok && isBypassSinkFunc(fn) {
			hasAnySinkRef = true
			break
		}
	}
	if !hasAnySinkRef {
		return false, hasBoundaryEscape
	}
	nonValueOfCtors := freshalloc.CollectNonValueOfReflectConstructors(p, idx)
	verifiedSinkIdents := map[*ast.Ident]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if canBypass || n == nil {
				return false
			}
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			fn := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
			if !isBypassSinkFunc(fn) {
				return true
			}
			if call.Ellipsis.IsValid() {
				canBypass = true
				return false
			}
			sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !isSel || sel.Sel == nil {
				canBypass = true
				return false
			}
			if selInfo := p.TypesInfo.Selections[sel]; selInfo == nil || selInfo.Kind() != types.MethodVal {
				canBypass = true
				return false
			}
			if !importsUnsafe && fn.Name() == "Pointer" {
				if par, isBin := idx.ParentUnparen(call).(*ast.BinaryExpr); isBin && (par.Op == token.EQL || par.Op == token.NEQ) {
					verifiedSinkIdents[sel.Sel] = true
					return true
				}
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
			if enclScope == nil || !freshalloc.IsCallOnNonValueOfLocal(p, idx, enclScope, call, nonValueOfCtors, funcParamVars) {
				canBypass = true
				return false
			}
			verifiedSinkIdents[sel.Sel] = true
			return true
		})
		if canBypass {
			return true, hasBoundaryEscape
		}
	}
	for id, obj := range p.TypesInfo.Uses {
		if fn, ok := obj.(*types.Func); ok && isBypassSinkFunc(fn) && !verifiedSinkIdents[id] {
			return true, hasBoundaryEscape
		}
	}
	return false, hasBoundaryEscape
}

func isMutatingOrEscapingReflectCallee(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return true
	}
	if sig.Recv() == nil {
		switch fn.Name() {
		case "Copy", "Swapper", "NewAt", "SliceAt", "Append", "AppendSlice", "Select":
			return true
		default:
			return false
		}
	}
	switch fn.Name() {
	case "Set", "SetBool", "SetBytes", "SetCap", "SetComplex", "SetFloat",
		"SetInt", "SetIterKey", "SetIterValue", "SetLen", "SetMapIndex",
		"SetPointer", "SetString", "SetUint", "SetZero",
		"Clear", "Grow", "Send", "TrySend", "Close", "Recv", "TryRecv", "Seq", "Seq2",
		"Bytes", "Addr", "UnsafeAddr", "Pointer", "UnsafePointer",
		"InterfaceData":
		return true
	default:
		return false
	}
}

func sigExposesReflectValue(sig *types.Signature) bool {
	if sig == nil {
		return false
	}
	for i := 0; i < sig.Results().Len(); i++ {
		if freshalloc.TypeMentionsReflectValue(sig.Results().At(i).Type()) {
			return true
		}
	}
	for i := 0; i < sig.Params().Len(); i++ {
		pt := sig.Params().At(i).Type()
		if !syntaxutil.IsNamedInPkg(pt, "reflect", "Value") && freshalloc.TypeMentionsReflectValue(pt) {
			return true
		}
	}
	return false
}

func pkgExposesReflectValueBoundary(p *packages.Package) bool {
	if p == nil || p.Types == nil {
		return false
	}
	return pkgExportedAPIReaches(
		p,
		freshalloc.TypeMentionsReflectValue,
		func(t types.Type) bool {
			return !types.IsInterface(t) && freshalloc.TypeMentionsReflectValue(t)
		},
		sigExposesReflectValue,
	)
}
