package structmut

import (
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshalloc"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func typeOrPtrHasMethods(t types.Type) bool {
	if t == nil || freshalloc.IsRuntimeInterfaceType(t) {
		return false
	}
	t = types.Unalias(t)
	if _, isTP := t.(*types.TypeParam); isTP {
		return true
	}
	if types.NewMethodSet(t).Len() > 0 {
		return true
	}
	if _, isPtr := t.Underlying().(*types.Pointer); !isPtr {
		return types.NewMethodSet(types.NewPointer(t)).Len() > 0
	}
	return false
}

func typeHasExternalMethod(curPkg *types.Package, t types.Type) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if ptr, isPtr := t.Underlying().(*types.Pointer); isPtr {
		t = types.Unalias(ptr.Elem())
	}
	if freshalloc.IsRuntimeInterfaceType(t) {
		return false
	}
	if _, isTP := t.(*types.TypeParam); isTP {
		return true
	}
	ms := types.NewMethodSet(types.NewPointer(t))
	for i := 0; i < ms.Len(); i++ {
		fn := ms.At(i).Obj()
		if fn != nil && fn.Pkg() != curPkg {
			return true
		}
	}
	return false
}

func isGoInternalPkgPath(pkgPath string) bool {
	return pkgPath == "internal" ||
		strings.HasPrefix(pkgPath, "internal/") ||
		strings.HasSuffix(pkgPath, "/internal") ||
		strings.Contains(pkgPath, "/internal/")
}

func ifaceSealsOutStdlib(t types.Type, isTrueStdPkg func(*types.Package) bool) bool {
	if !freshalloc.IsRuntimeInterfaceType(t) {
		return false
	}
	iface, isIf := syntaxutil.UnderlyingType(t).(*types.Interface)
	if !isIf || iface.NumMethods() == 0 {
		return false
	}
	seen := map[types.Type]bool{}
	var mentionsNonStdSealedNamed func(cur types.Type) bool
	mentionsNonStdSealedNamed = func(cur types.Type) bool {
		if cur == nil {
			return false
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return false
		}
		seen[cur] = true
		if named, ok := cur.(*types.Named); ok && named.Obj() != nil {
			qPkg := named.Obj().Pkg()
			if qPkg != nil && !isTrueStdPkg(qPkg) && (!named.Obj().Exported() || isGoInternalPkgPath(qPkg.Path())) {
				return true
			}
		}
		switch u := cur.Underlying().(type) {
		case *types.Pointer:
			return mentionsNonStdSealedNamed(u.Elem())
		case *types.Slice:
			return mentionsNonStdSealedNamed(u.Elem())
		case *types.Array:
			return mentionsNonStdSealedNamed(u.Elem())
		case *types.Chan:
			return mentionsNonStdSealedNamed(u.Elem())
		case *types.Map:
			return mentionsNonStdSealedNamed(u.Key()) || mentionsNonStdSealedNamed(u.Elem())
		case *types.Signature:
			for i := 0; i < u.Params().Len(); i++ {
				if mentionsNonStdSealedNamed(u.Params().At(i).Type()) {
					return true
				}
			}
			for i := 0; i < u.Results().Len(); i++ {
				if mentionsNonStdSealedNamed(u.Results().At(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if m == nil {
			continue
		}
		if !m.Exported() && m.Pkg() != nil && !isTrueStdPkg(m.Pkg()) {
			return true
		}
		clear(seen)
		if mentionsNonStdSealedNamed(m.Type()) {
			return true
		}
	}
	return false
}

func isPureByteWriterIface(p *packages.Package, t types.Type) bool {
	if !freshalloc.IsRuntimeInterfaceType(t) {
		return false
	}
	if syntaxutil.IsTrueStdlibInPkg(p, "fmt") && syntaxutil.IsNamedInPkg(t, "fmt", "State") {
		return true
	}
	iface, isIf := syntaxutil.UnderlyingType(t).(*types.Interface)
	if !isIf || iface.NumMethods() == 0 {
		return false
	}
	isErrType := func(rt types.Type) bool {
		if rt == nil {
			return false
		}
		named, ok := types.Unalias(rt).(*types.Named)
		return ok && named.Obj() != nil && named.Obj().Pkg() == nil && named.Obj().Name() == "error"
	}
	isBasicKind := func(rt types.Type, kind types.BasicKind) bool {
		if rt == nil {
			return false
		}
		b, ok := types.Unalias(rt).(*types.Basic)
		return ok && b.Kind() == kind
	}
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if m == nil || !m.Exported() {
			return false
		}
		msig, okS := m.Type().(*types.Signature)
		if !okS || msig.Variadic() || msig.TypeParams().Len() > 0 {
			return false
		}
		switch m.Name() {
		case "Write":
			if msig.Params().Len() != 1 || !syntaxutil.IsByteSliceType(msig.Params().At(0).Type()) ||
				msig.Results().Len() != 2 || !isBasicKind(msig.Results().At(0).Type(), types.Int) || !isErrType(msig.Results().At(1).Type()) {
				return false
			}
		case "WriteString":
			if msig.Params().Len() != 1 || !isBasicKind(msig.Params().At(0).Type(), types.String) ||
				msig.Results().Len() != 2 || !isBasicKind(msig.Results().At(0).Type(), types.Int) || !isErrType(msig.Results().At(1).Type()) {
				return false
			}
		case "WriteByte":
			if msig.Params().Len() != 1 || !isBasicKind(msig.Params().At(0).Type(), types.Byte) ||
				msig.Results().Len() != 1 || !isErrType(msig.Results().At(0).Type()) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func placeCrossesRefIndirection(pl flowir.Place) bool {
	for i := range pl.Projs {
		pr := &pl.Projs[i]
		switch pr.Kind {
		case flowir.ProjDeref:
			return true
		case flowir.ProjField:
			if pr.Indirect {
				return true
			}
		case flowir.ProjIndex:
			if pr.BaseType == nil {
				return true
			}
			bt := types.Unalias(pr.BaseType)
			if _, isTP := bt.(*types.TypeParam); isTP {
				return true
			}
			if _, isArr := bt.Underlying().(*types.Array); !isArr {
				return true
			}
		}
	}
	return false
}
