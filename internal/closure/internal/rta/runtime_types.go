package rta

import (
	"fmt"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func isStdImportPathShape(path string) bool {
	if path == "" || path == "C" {
		return false
	}
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	return !strings.Contains(first, ".")
}

func (r *attributedRTA) isHarnessInternalStdPkg(pkgPath string) bool {
	return r.harnessPkg != "" &&
		pkgPath != "" &&
		pkgPath != r.harnessPkg &&
		(pkgPath != "testing" || r.harnessOnlyTesting) &&
		pkgPath != "context" &&
		!r.userPkgs[pkgPath] &&
		isStdImportPathShape(pkgPath)
}

func isExcludedHarnessStdNamed(obj *types.TypeName) bool {
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	p := obj.Pkg().Path()
	return p == "context" || p == "errors" || (p == "os" && obj.Name() == "File") || (p == "io" && obj.Name() == "discard")
}

func (r *attributedRTA) isPureHarnessInternalStdType(t types.Type) bool {
	if r.harnessPkg == "" || t == nil {
		return false
	}
	t = types.Unalias(t)
	if r.pureHarnessStdTypes != nil {
		if cached, ok := r.pureHarnessStdTypes[t]; ok {
			return cached
		}
	}
	var seen map[types.Type]bool
	sawHarnessStdNamed := false
	var walk func(types.Type) bool
	walk = func(cur types.Type) bool {
		if cur == nil {
			return true
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return true
		}
		if seen == nil {
			seen = make(map[types.Type]bool, 8)
		}
		seen[cur] = true
		switch tt := cur.(type) {
		case *types.Named:
			if obj := tt.Obj(); obj != nil && obj.Pkg() != nil {
				if isExcludedHarnessStdNamed(obj) {
					return false
				}
				p := obj.Pkg().Path()
				if !isStdImportPathShape(p) || r.userPkgs[p] || p == r.harnessPkg || p == "testing" {
					return false
				}
				if r.isHarnessInternalStdPkg(p) {
					sawHarnessStdNamed = true
				}
			}
			if args := tt.TypeArgs(); args != nil {
				for i, n := 0, args.Len(); i < n; i++ {
					if !walk(args.At(i)) {
						return false
					}
				}
			}
			return walk(tt.Underlying())
		case *types.Pointer:
			return walk(tt.Elem())
		case *types.Slice:
			return walk(tt.Elem())
		case *types.Array:
			return walk(tt.Elem())
		case *types.Map:
			return walk(tt.Key()) && walk(tt.Elem())
		case *types.Chan:
			return walk(tt.Elem())
		case *types.Struct:
			for i, n := 0, tt.NumFields(); i < n; i++ {
				if !walk(tt.Field(i).Type()) {
					return false
				}
			}
			return true
		case *types.Tuple:
			for i, n := 0, tt.Len(); i < n; i++ {
				if !walk(tt.At(i).Type()) {
					return false
				}
			}
			return true
		case *types.Signature:
			return walk(tt.Params()) && walk(tt.Results())
		case *types.Interface:
			for i, n := 0, tt.NumMethods(); i < n; i++ {
				if !walk(tt.Method(i).Type()) {
					return false
				}
			}
			return true
		default:
			return true
		}
	}
	res := walk(t) && sawHarnessStdNamed
	if r.pureHarnessStdTypes == nil {
		r.pureHarnessStdTypes = make(map[types.Type]bool, 32)
	}
	r.pureHarnessStdTypes[t] = res
	return res
}

// ContainsTypeParam reports whether t mentions a type parameter or constraint
// union anywhere in its structure. Such a type denotes no runtime type — only
// fully concrete instantiations exist at runtime, and they enter the walk
// through their own MakeInterface and instantiation sites — so the runtime-type
// walk skips it wholesale instead of panicking in the shape switch. The seen
// map (allocated lazily when nil) breaks reference cycles using the unaliased
// type identity.
func ContainsTypeParam(t types.Type, seen map[types.Type]bool) bool {
	for t != nil {
		unaliased := types.Unalias(t)
		switch u := unaliased.(type) {
		case *types.TypeParam, *types.Union:
			return true
		case *types.Basic:
			return false
		case *types.Pointer:
			t = u.Elem()
			continue
		case *types.Slice:
			t = u.Elem()
			continue
		case *types.Array:
			t = u.Elem()
			continue
		case *types.Chan:
			t = u.Elem()
			continue
		}
		if seen != nil && seen[unaliased] {
			return false
		}
		if named, ok := unaliased.(*types.Named); ok {
			if named.TypeParams() != nil && named.TypeArgs() == nil {
				// A generic origin type is never a runtime type.
				return true
			}
			if args := named.TypeArgs(); args != nil {
				for i, n := 0, args.Len(); i < n; i++ {
					if seen == nil {
						seen = make(map[types.Type]bool)
					}
					if ContainsTypeParam(args.At(i), seen) {
						return true
					}
				}
			}
			// A non-interface named type declared at package scope can only
			// reference type parameters from its own TypeParams (already
			// checked via TypeArgs above). Types declared inside generic
			// function bodies have a non-package parent scope and recurse
			// into their Underlying below.
			if obj := named.Obj(); obj != nil && obj.Pkg() != nil && obj.Parent() != nil && obj.Parent() == obj.Pkg().Scope() {
				if _, isIface := named.Underlying().(*types.Interface); !isIface {
					if seen != nil {
						seen[unaliased] = true
					}
					return false
				}
			}
		}
		if seen == nil {
			seen = make(map[types.Type]bool)
		}
		seen[unaliased] = true
		switch u := unaliased.(type) {
		case *types.Map:
			return ContainsTypeParam(u.Key(), seen) || ContainsTypeParam(u.Elem(), seen)
		case *types.Signature:
			if u.TypeParams() != nil || u.RecvTypeParams() != nil {
				return true
			}
			return ContainsTypeParam(u.Params(), seen) || ContainsTypeParam(u.Results(), seen)
		case *types.Tuple:
			for i, n := 0, u.Len(); i < n; i++ {
				if ContainsTypeParam(u.At(i).Type(), seen) {
					return true
				}
			}
			return false
		case *types.Struct:
			for i, n := 0, u.NumFields(); i < n; i++ {
				if ContainsTypeParam(u.Field(i).Type(), seen) {
					return true
				}
			}
			return false
		case *types.Named:
			return ContainsTypeParam(u.Underlying(), seen)
		case *types.Interface:
			for i, n := 0, u.NumEmbeddeds(); i < n; i++ {
				if ContainsTypeParam(u.EmbeddedType(i), seen) {
					return true
				}
			}
			for i, n := 0, u.NumExplicitMethods(); i < n; i++ {
				if ContainsTypeParam(u.ExplicitMethod(i).Type(), seen) {
					return true
				}
			}
			return false
		default:
			return false
		}
	}
	return false
}

// hasTypeParam reports whether t mentions a type parameter, retaining verified
// type-param-free entries in r.typeParamSeen across calls and clearing the map
// only when a true short-circuit leaves an incomplete ancestor spine.
func (r *attributedRTA) hasTypeParam(t types.Type) bool {
	if ContainsTypeParam(t, r.typeParamSeen) {
		clear(r.typeParamSeen)
		return true
	}
	return false
}

// addRuntimeType is adapted from needMethods in go/ssa/builder.go, matching
// upstream RTA's exported-method and recursive runtime-type behavior.
// Intermediate tuple types and underlying types of named types pass skip=true:
// reflection can reach their element and field types, never the tuple or
// unnamed underlying type itself unless materialized independently.
func (r *attributedRTA) addRuntimeType(T types.Type, masks uint64, skip bool) {
	r.visitRuntimeType(T, masks, skip, false, false)
}

func (r *attributedRTA) addHarnessStdRuntimeType(T types.Type, masks uint64, skip bool) {
	r.visitRuntimeType(T, masks, skip, true, false)
}

func (r *attributedRTA) visitRuntimeType(T types.Type, masks uint64, skip, harnessStdPlane, checkedTypeParam bool) {
	if masks == 0 {
		return
	}
	T = types.Unalias(T)
	if harnessStdPlane && !r.isPureHarnessInternalStdType(T) {
		harnessStdPlane = false
	}

	accessTable := &r.runtimeTypes
	traverseTable := &r.traversedTypes
	if harnessStdPlane {
		accessTable = &r.harnessRuntimeTypes
		traverseTable = &r.harnessTraversedTypes
	}

	var prevAccess, accessDelta uint64
	if !skip {
		prevAccess, _ = accessTable.At(T).(uint64)
		accessDelta = masks &^ prevAccess
	}
	prevTraversed, _ := traverseTable.At(T).(uint64)
	traverseDelta := masks &^ prevTraversed
	if accessDelta == 0 && traverseDelta == 0 {
		return
	}
	if !checkedTypeParam && prevTraversed == 0 && r.hasTypeParam(T) {
		return
	}

	var mset *types.MethodSet
	if accessDelta != 0 {
		accessTable.Set(T, prevAccess|accessDelta)
		if _, ok := T.Underlying().(*types.Interface); !ok {
			mset = r.prog.MethodSets.MethodSet(T)
			for i, n := 0, mset.Len(); i < n; i++ {
				sel := mset.At(i)
				if sel.Obj().Exported() && sel.Obj().Type().(*types.Signature).TypeParams() == nil {
					mv := r.prog.MethodValue(sel)
					if harnessStdPlane {
						r.addHarnessStdReachable(mv, accessDelta)
					} else {
						r.addReachable(mv, accessDelta)
						r.addRuntimeMethodFunc(mv, accessDelta)
					}
				}
			}

			cinfo := r.concreteInfo(T, mset)
			if harnessStdPlane {
				cinfo.harnessStdMasks |= accessDelta
				for _, I := range cinfo.implements {
					hSites, _ := r.harnessInvokeSites.At(I).(map[ssa.CallInstruction]uint64)
					for site, siteMasks := range hSites {
						r.addHarnessStdInvokeEdge(site, T, accessDelta&siteMasks, false)
					}
					sites, _ := r.invokeSites.At(I).(map[ssa.CallInstruction]uint64)
					for site, siteMasks := range sites {
						if r.funcPkgPath(site.Parent()) == r.harnessPkg {
							r.addHarnessStdInvokeEdge(site, T, (accessDelta&siteMasks)&^cinfo.masks, true)
						}
					}
				}
			} else {
				cinfo.masks |= accessDelta
				for _, I := range cinfo.implements {
					sites, _ := r.invokeSites.At(I).(map[ssa.CallInstruction]uint64)
					for site, siteMasks := range sites {
						r.addInvokeEdge(site, T, accessDelta&siteMasks)
					}
					if r.harnessPkg != "" {
						hSites, _ := r.harnessInvokeSites.At(I).(map[ssa.CallInstruction]uint64)
						for site, siteMasks := range hSites {
							r.addHarnessStdInvokeEdge(site, T, accessDelta&siteMasks, false)
						}
					}
				}
			}
		}
	}
	if traverseDelta == 0 {
		return
	}
	traverseTable.Set(T, prevTraversed|traverseDelta)

	if mset == nil {
		mset = r.prog.MethodSets.MethodSet(T)
	}
	for i, n := 0, mset.Len(); i < n; i++ {
		method := mset.At(i)
		sig := method.Type().(*types.Signature)
		if sig.TypeParams() == nil {
			r.visitRuntimeType(sig.Params(), traverseDelta, true, harnessStdPlane, false)
			r.visitRuntimeType(sig.Results(), traverseDelta, true, harnessStdPlane, false)
		}
	}

	switch t := T.(type) {
	case *types.Alias:
		panic("unreachable")
	case *types.Basic, *types.Interface:
	case *types.Pointer:
		r.visitRuntimeType(t.Elem(), traverseDelta, false, harnessStdPlane, true)
	case *types.Slice:
		r.visitRuntimeType(t.Elem(), traverseDelta, false, harnessStdPlane, true)
	case *types.Chan:
		r.visitRuntimeType(t.Elem(), traverseDelta, false, harnessStdPlane, true)
	case *types.Map:
		r.visitRuntimeType(t.Key(), traverseDelta, false, harnessStdPlane, true)
		r.visitRuntimeType(t.Elem(), traverseDelta, false, harnessStdPlane, true)
	case *types.Signature:
		if t.Recv() != nil {
			panic(fmt.Sprintf("Signature %s has Recv %s", t, t.Recv()))
		}
		r.visitRuntimeType(t.Params(), traverseDelta, true, harnessStdPlane, true)
		r.visitRuntimeType(t.Results(), traverseDelta, true, harnessStdPlane, true)
	case *types.Named:
		r.visitRuntimeType(types.NewPointer(T), traverseDelta, false, harnessStdPlane, true)
		r.visitRuntimeType(t.Underlying(), traverseDelta, true, harnessStdPlane, true)
	case *types.Array:
		r.visitRuntimeType(t.Elem(), traverseDelta, false, harnessStdPlane, true)
	case *types.Struct:
		for i, n := 0, t.NumFields(); i < n; i++ {
			r.visitRuntimeType(t.Field(i).Type(), traverseDelta, false, harnessStdPlane, true)
		}
	case *types.Tuple:
		for i, n := 0, t.Len(); i < n; i++ {
			r.visitRuntimeType(t.At(i).Type(), traverseDelta, false, harnessStdPlane, true)
		}
	default:
		panic(T)
	}
}

// addWritableRuntimeType traverses runtime types whose composite elements or
// exported struct fields can receive values through reflective container writes
// (such as Value.Set, SetMapIndex, Send, Append, Copy, or Select), recording
// any receiverless function slot signature in reflectWriteSigs.
//
// In Go's reflect package, accessing a non-embedded unexported struct field
// sets flagStickyRO permanently, whereas accessing an unexported embedded
// struct field sets flagEmbedRO (embedRO=true), blocking direct writes to the
// embedded value itself while still permitting writes to promoted exported
// fields inside it. Method sets are not traversed here because method parameter
// and result signatures are never writable container slots.
func (r *attributedRTA) addWritableRuntimeType(T types.Type, masks uint64, embedRO bool) {
	r.visitWritableRuntimeType(T, masks, embedRO, false)
}

func (r *attributedRTA) visitWritableRuntimeType(T types.Type, masks uint64, embedRO, checkedTypeParam bool) {
	if T == nil || masks == 0 {
		return
	}
	T = types.Unalias(T)
	table := &r.writableTypes
	if embedRO {
		table = &r.embedROTypes
	}
	prev, _ := table.At(T).(uint64)
	delta := masks &^ prev
	if delta == 0 {
		return
	}
	if !checkedTypeParam && prev == 0 && r.hasTypeParam(T) {
		return
	}
	table.Set(T, prev|delta)

	switch t := T.(type) {
	case *types.Alias:
		panic("unreachable")
	case *types.Basic, *types.Interface:
	case *types.Pointer:
		r.visitWritableRuntimeType(t.Elem(), delta, embedRO, true)
	case *types.Slice:
		if !embedRO {
			if sig, ok := types.Unalias(t.Elem()).Underlying().(*types.Signature); ok {
				r.addReflectWriteSig(reflectWriteSlice, sig, delta)
			}
			r.visitWritableRuntimeType(t.Elem(), delta, false, true)
		}
	case *types.Array:
		if !embedRO {
			if sig, ok := types.Unalias(t.Elem()).Underlying().(*types.Signature); ok {
				r.addReflectWriteSig(reflectWriteSlice, sig, delta)
			}
			r.visitWritableRuntimeType(t.Elem(), delta, false, true)
		}
	case *types.Chan:
		if !embedRO {
			if sig, ok := types.Unalias(t.Elem()).Underlying().(*types.Signature); ok {
				r.addReflectWriteSig(reflectWriteChan, sig, delta)
			} else {
				r.visitWritableRuntimeType(t.Elem(), delta, false, true)
			}
		}
	case *types.Map:
		if !embedRO {
			if sig, ok := types.Unalias(t.Elem()).Underlying().(*types.Signature); ok {
				r.addReflectWriteSig(reflectWriteMap, sig, delta)
			} else {
				r.visitWritableRuntimeType(t.Elem(), delta, false, true)
			}
			if _, isSig := types.Unalias(t.Key()).Underlying().(*types.Signature); !isSig {
				r.visitWritableRuntimeType(t.Key(), delta, false, true)
			}
		}
	case *types.Signature:
		if !embedRO && t.Recv() == nil {
			r.addReflectWriteSig(reflectWriteSet, t, delta)
		}
	case *types.Named:
		r.visitWritableRuntimeType(t.Underlying(), delta, embedRO, true)
	case *types.Struct:
		for i, n := 0, t.NumFields(); i < n; i++ {
			f := t.Field(i)
			if f.Exported() {
				r.visitWritableRuntimeType(f.Type(), delta, false, true)
			} else if f.Embedded() {
				r.visitWritableRuntimeType(f.Type(), delta, true, true)
			}
		}
	case *types.Tuple:
		for i, n := 0, t.Len(); i < n; i++ {
			r.visitWritableRuntimeType(t.At(i).Type(), delta, embedRO, true)
		}
	default:
		panic(T)
	}
}
