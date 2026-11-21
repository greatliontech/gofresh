package refconfine

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func verifyNamedStructImmutableInDeclPkg(
	named *types.Named,
	declPkg *packages.Package,
	callerPkg *types.Package,
	allowExportedUnexportedFieldElemPtr bool,
	isExemptIface func(*types.Interface) bool,
) (bool, string) {
	if named == nil || declPkg == nil || declPkg.Types == nil || declPkg.TypesInfo == nil || len(declPkg.Syntax) == 0 {
		return false, "missing declPkg syntax"
	}
	orig := named.Origin()
	if orig == nil || orig.Obj() == nil || orig.Obj().Pkg() != declPkg.Types {
		return false, "origin pkg mismatch"
	}
	capsules := map[*types.Named]bool{orig: true}
	match := func(st *types.Named) bool {
		return st != nil && (capsules[st] || capsules[st.Origin()])
	}
	// Close capsules over intra-package pointer (*A <-> *B) and value (A <-> B)
	// struct conversions so helper conversions such as (*term)(t) or raw(*s)
	// cannot hide mutations or leaks, failing closed on conversions to non-named
	// structs or foreign unsafe conversions.
	unapprovedConv := false
	changed := true
	for changed && !unapprovedConv {
		changed = false
		for _, file := range declPkg.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if unapprovedConv || n == nil {
					return false
				}
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
					return true
				}
				tv, ok := declPkg.TypesInfo.Types[call.Fun]
				if !ok || !tv.IsType() || tv.Type == nil {
					return true
				}
				if isUntypedNilExpr(declPkg.TypesInfo, call.Args[0]) {
					return true
				}
				srcT := declPkg.TypesInfo.TypeOf(call.Args[0])
				dstT := tv.Type
				if !match(syntaxutil.DerefNamedStruct(srcT)) && !match(syntaxutil.DerefNamedStruct(dstT)) {
					return true
				}
				if isUnderlyingUnsafePointer(srcT) || isUnderlyingUnsafePointer(dstT) {
					if declPkg.Types == callerPkg {
						return true
					}
					unapprovedConv = true
					return false
				}
				if types.IsInterface(dstT) {
					return true
				}
				srcU := types.Unalias(srcT)
				dstU := types.Unalias(dstT)
				srcPtr, okSP := srcU.(*types.Pointer)
				dstPtr, okDP := dstU.(*types.Pointer)
				if okSP != okDP {
					unapprovedConv = true
					return false
				}
				if okSP {
					srcU = types.Unalias(srcPtr.Elem())
					dstU = types.Unalias(dstPtr.Elem())
				}
				srcNamed, okS := srcU.(*types.Named)
				dstNamed, okD := dstU.(*types.Named)
				if !okS || !okD || srcNamed.Obj() == nil || dstNamed.Obj() == nil ||
					srcNamed.Obj().Pkg() != declPkg.Types || dstNamed.Obj().Pkg() != declPkg.Types {
					unapprovedConv = true
					return false
				}
				if _, isSSt := srcNamed.Underlying().(*types.Struct); !isSSt {
					unapprovedConv = true
					return false
				}
				if _, isDSt := dstNamed.Underlying().(*types.Struct); !isDSt {
					unapprovedConv = true
					return false
				}
				if !capsules[srcNamed.Origin()] {
					capsules[srcNamed.Origin()] = true
					changed = true
				}
				if !capsules[dstNamed.Origin()] {
					capsules[dstNamed.Origin()] = true
					changed = true
				}
				return true
			})
		}
	}
	if unapprovedConv {
		return false, "unapproved conversion touching capsule"
	}
	for id, inst := range declPkg.TypesInfo.Instances {
		if inst.TypeArgs == nil {
			continue
		}
		var tparams *types.TypeParamList
		switch obj := declPkg.TypesInfo.Uses[id].(type) {
		case *types.Func:
			if sig, ok := obj.Origin().Type().(*types.Signature); ok {
				if sig.TypeParams().Len() > 0 {
					tparams = sig.TypeParams()
				} else {
					tparams = sig.RecvTypeParams()
				}
			}
		case *types.TypeName:
			switch gt := obj.Type().(type) {
			case *types.Named:
				tparams = gt.Origin().TypeParams()
			case *types.Alias:
				tparams = gt.Origin().TypeParams()
			}
		}
		for ti := 0; ti < inst.TypeArgs.Len(); ti++ {
			if !match(syntaxutil.DerefNamedStruct(inst.TypeArgs.At(ti))) {
				continue
			}
			if tparams == nil || ti >= tparams.Len() {
				return false, "capsule instantiated in generic type argument"
			}
			iface, okI := tparams.At(ti).Constraint().Underlying().(*types.Interface)
			if !okI || constraintAdmitsTypeTerm(iface) {
				return false, "capsule instantiated in structural type parameter"
			}
		}
	}
	// Reject any unnamed struct type in declPkg whose underlying layout matches a
	// capsule struct, closing implicit named-to-unnamed struct assignments
	// (`var anon struct{...} = *s`) as well as unnamed struct conversions.
	hasMatchingUnnamedStruct := func(root types.Type) bool {
		seen := map[types.Type]bool{}
		var walk func(types.Type) bool
		walk = func(t types.Type) bool {
			if t == nil {
				return false
			}
			t = types.Unalias(t)
			if seen[t] {
				return false
			}
			seen[t] = true
			if named, isN := t.(*types.Named); isN {
				if targs := named.TypeArgs(); targs != nil {
					for i := 0; i < targs.Len(); i++ {
						if walk(targs.At(i)) {
							return true
						}
					}
				}
				if st, isSt := named.Underlying().(*types.Struct); isSt {
					for i := 0; i < st.NumFields(); i++ {
						if walk(st.Field(i).Type()) {
							return true
						}
					}
					return false
				}
			}
			switch u := t.Underlying().(type) {
			case *types.Struct:
				for capOrig := range capsules {
					if capSt, ok := capOrig.Underlying().(*types.Struct); ok && types.IdenticalIgnoreTags(u, capSt) {
						return true
					}
				}
				for i := 0; i < u.NumFields(); i++ {
					if walk(u.Field(i).Type()) {
						return true
					}
				}
			case *types.Pointer:
				return walk(u.Elem())
			case *types.Slice:
				return walk(u.Elem())
			case *types.Array:
				return walk(u.Elem())
			case *types.Chan:
				return walk(u.Elem())
			case *types.Map:
				return walk(u.Key()) || walk(u.Elem())
			case *types.Tuple:
				for i := 0; i < u.Len(); i++ {
					if walk(u.At(i).Type()) {
						return true
					}
				}
			case *types.Signature:
				return walk(u.Params()) || walk(u.Results())
			}
			return false
		}
		return walk(root)
	}
	for _, tv := range declPkg.TypesInfo.Types {
		if tv.IsValue() && hasMatchingUnnamedStruct(tv.Type) {
			return false, "unnamed struct matching capsule layout in declPkg"
		}
	}
	for _, defObj := range declPkg.TypesInfo.Defs {
		if _, isTN := defObj.(*types.TypeName); !isTN && defObj != nil && hasMatchingUnnamedStruct(defObj.Type()) {
			return false, "unnamed struct def matching capsule layout in declPkg"
		}
	}
	if !verifyCapsuleStructsWriteFree(declPkg, capsules) {
		return false, "verifyCapsuleStructsWriteFree failed"
	}
	// Also reject builtin copy/clear/delete mutations into any field/slice/map
	// rooted on a capsule struct inside declPkg.
	cleanBuiltins := true
	for _, file := range declPkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !cleanBuiltins || n == nil {
				return false
			}
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			b := syntaxutil.LookupBuiltin(declPkg.TypesInfo, call.Fun)
			if b == nil {
				return true
			}
			switch b.Name() {
			case "copy", "clear", "delete":
				if exprHitsStructPred(declPkg.TypesInfo, call.Args[0], match, true) {
					cleanBuiltins = false
					return false
				}
			}
			return true
		})
	}
	if !cleanBuiltins {
		return false, "cleanBuiltins failed"
	}
	return verifyCapsuleInteriorRefsConfined(declPkg, capsules, allowExportedUnexportedFieldElemPtr, isExemptIface)
}

func constraintAdmitsTypeTerm(root *types.Interface) bool {
	seen := map[*types.Interface]bool{}
	var walk func(*types.Interface) bool
	walk = func(it *types.Interface) bool {
		if it == nil || seen[it] {
			return false
		}
		seen[it] = true
		for i := 0; i < it.NumEmbeddeds(); i++ {
			emb := types.Unalias(it.EmbeddedType(i))
			if subIface, ok := emb.Underlying().(*types.Interface); ok {
				if walk(subIface) {
					return true
				}
				continue
			}
			return true
		}
		return false
	}
	return walk(root)
}

func typeContainsInterfaceWith(root types.Type, isExemptIface func(*types.Interface) bool) bool {
	seen := map[types.Type]bool{}
	var walk func(types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if seen[t] {
			return false
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Interface:
			return isExemptIface == nil || !isExemptIface(u)
		case *types.Array:
			return walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if walk(u.Field(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	return walk(root)
}

// verifyCapsuleInteriorRefsConfined routes capsule interior confinement through
// VerifyReadOnlyRefConfinement so every slice, map, channel, non-exempt
// interface, or non-immutable pointer field read from capsules across declPkg is
// confined against external/closure/generic calls, element writes,
// address-takes, RangeStmt, SendStmt, TypeAssertExpr, and exported escapes.
func verifyCapsuleInteriorRefsConfined(
	declPkg *packages.Package,
	capsules map[*types.Named]bool,
	allowExportedUnexportedFieldElemPtr bool,
	isExemptIface func(*types.Interface) bool,
) (bool, string) {
	info := declPkg.TypesInfo
	idx := BuildPkgIndex(declPkg)
	if idx == nil {
		return false, "nil PkgIndex"
	}
	match := func(st *types.Named) bool {
		return st != nil && (capsules[st] || capsules[st.Origin()])
	}
	isImmutableElemPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		named, ok := types.Unalias(ptr.Elem()).(*types.Named)
		if !ok || named.Obj() == nil {
			return false
		}
		ust, isSt := named.Underlying().(*types.Struct)
		if !isSt {
			return false
		}
		if match(named) {
			return true
		}
		return allowExportedUnexportedFieldElemPtr && named.Obj().Exported() && structHasNoExportedFieldsDeep(ust)
	}
	if !VerifyReadOnlyRefConfinement(declPkg, Config{
		Index:                             idx,
		IsImmutablePtr:                    isImmutableElemPtr,
		AllowCompositeLitFieldPropagation: true,
		AllowReturnFromUnexportedFunc:     true,
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
			if !ok {
				return false, false
			}
			si := info.Selections[sel]
			if si == nil || si.Kind() != types.FieldVal {
				return false, false
			}
			fv, _ := si.Obj().(*types.Var)
			if fv == nil {
				return false, false
			}
			hitsCap := false
			syntaxutil.ForEachSelectionHopStruct(si, func(st *types.Named) {
				if match(st) {
					hitsCap = true
				}
			})
			if !hitsCap && !match(syntaxutil.DerefNamedStruct(info.TypeOf(sel.X))) {
				return false, false
			}
			ft := si.Type()
			if IsDirectMutableRefWith(ft, isImmutableElemPtr) {
				return true, true
			}
			if TypeCarriesMutableRefWith(ft, isImmutableElemPtr) || typeContainsInterfaceWith(ft, isExemptIface) {
				return false, true
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, _ int, _ ast.Expr) bool {
			return isReadOnlyStdSliceCall(info, call)
		},
	}) {
		return false, "capsule interior reference confinement failed"
	}
	return true, ""
}

// capsulePubliclyConstructedIfacePred returns a predicate matching non-empty,
// non-void-method interfaces I for which dstDeclPkg publicly exports a
// constructor function accepting a parameter of identical interface type I and
// returning dstNamed or *dstNamed (e.g. go/types.NewTerm(bool, Type) *Term).
func capsulePubliclyConstructedIfacePred(dstNamed *types.Named, dstDeclPkg *packages.Package) func(*types.Interface) bool {
	if dstNamed == nil || dstNamed.Obj() == nil || !dstNamed.Obj().Exported() || dstDeclPkg == nil || dstDeclPkg.Types == nil {
		return nil
	}
	dstOrig := dstNamed.Origin()
	var admitted []*types.Interface
	scope := dstDeclPkg.Types.Scope()
	for _, name := range scope.Names() {
		fn, ok := scope.Lookup(name).(*types.Func)
		if !ok || fn == nil || !fn.Exported() {
			continue
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil || sig.Results().Len() == 0 {
			continue
		}
		returnsDst := false
		for ri := 0; ri < sig.Results().Len(); ri++ {
			rt := types.Unalias(sig.Results().At(ri).Type())
			if ptr, isP := rt.(*types.Pointer); isP {
				rt = types.Unalias(ptr.Elem())
			}
			if rn, isN := rt.(*types.Named); isN && rn.Origin() == dstOrig {
				returnsDst = true
				break
			}
		}
		if !returnsDst {
			continue
		}
		for pi := 0; pi < sig.Params().Len(); pi++ {
			pt := types.Unalias(sig.Params().At(pi).Type())
			iface, okI := pt.Underlying().(*types.Interface)
			if !okI || iface.NumMethods() == 0 {
				continue
			}
			allQueryMethods := true
			for mi := 0; mi < iface.NumMethods(); mi++ {
				msig, okM := iface.Method(mi).Type().(*types.Signature)
				if !okM || msig.Results().Len() == 0 {
					allQueryMethods = false
					break
				}
			}
			if allQueryMethods {
				admitted = append(admitted, iface)
			}
		}
	}
	if len(admitted) == 0 {
		return nil
	}
	return func(cand *types.Interface) bool {
		if cand == nil {
			return false
		}
		for _, okIface := range admitted {
			if types.Identical(cand, okIface) {
				return true
			}
		}
		return false
	}
}

func collectSamePkgNamedStructs(t types.Type, pkg *types.Package) []*types.Named {
	if t == nil || pkg == nil {
		return nil
	}
	seen := map[*types.Named]bool{}
	seenTypes := map[types.Type]bool{}
	var out []*types.Named
	var walk func(types.Type)
	walk = func(cur types.Type) {
		if cur == nil {
			return
		}
		cur = types.Unalias(cur)
		if seenTypes[cur] {
			return
		}
		seenTypes[cur] = true
		if n, ok := cur.(*types.Named); ok && n.Obj() != nil && n.Obj().Pkg() == pkg {
			if _, isSt := n.Underlying().(*types.Struct); isSt {
				orig := n.Origin()
				if !seen[orig] {
					seen[orig] = true
					out = append(out, orig)
				}
			}
		}
		// Only walk value-contained aggregates (arrays and structs) occupying lv's
		// own reinterpreted memory extent; pointer and slice elements are required
		// to be types.Identical by IsomorphicValueLayout.
		switch u := cur.Underlying().(type) {
		case *types.Array:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(t)
	return out
}

// isReadOnlyStdSliceCall reports whether call invokes a standard-library slice
// inspection function that reads its slice arguments synchronously without user
// callbacks, never mutates or retains them, and returns only scalar values
// (never a sub-slice or pointer alias into its input).
func isReadOnlyStdSliceCall(info *types.Info, call *ast.CallExpr) bool {
	if info == nil || call == nil {
		return false
	}
	funExpr := ast.Unparen(call.Fun)
	switch ix := funExpr.(type) {
	case *ast.IndexExpr:
		funExpr = ast.Unparen(ix.X)
	case *ast.IndexListExpr:
		funExpr = ast.Unparen(ix.X)
	}
	sel, ok := funExpr.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return false
	}
	if info.Selections[sel] != nil {
		return false
	}
	fn, ok := info.Uses[sel.Sel].(*types.Func)
	if !ok || fn == nil || fn.Pkg() == nil {
		return false
	}
	return auditset.DeterministicStdCallTraits(fn.Pkg().Path(), fn.Name()).ReadOnlySliceInspect
}
