package dynstate

import (
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// localCarrierAliases separates carriers aliased directly at a local's own
// single-hop reference header (root) from all carriers reachable anywhere in
// the local's interior (all). Writes or non-carrier-capable address captures
// staying within the local's own root header (or bare-addressed pointer
// dereference) consult root, whereas escapes, carrier-capable address captures,
// or multi-hop interior accesses consult all.
type localCarrierAliases struct {
	root []*types.Var
	all  []*types.Var
}

func appendUniqueVars(dst *[]*types.Var, srcs []*types.Var) bool {
	changed := false
	for _, v := range srcs {
		if v == nil {
			continue
		}
		found := false
		for _, cur := range *dst {
			if cur == v {
				found = true
				break
			}
		}
		if !found {
			*dst = append(*dst, v)
			changed = true
		}
	}
	return changed
}

func isRefHeaderType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Interface:
		return true
	case *types.Basic:
		return u.Kind() == types.UnsafePointer
	}
	return false
}

func isTypeParamType(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := types.Unalias(t).(*types.TypeParam)
	return ok
}

func canAliasCarrierType(audited, allowString bool, t types.Type) bool {
	return refconfine.TypeHandsOutDynamicAlias(audited, t) ||
		refconfine.TypeHandsOutMutableReach(t) ||
		refconfine.TypeReachesSyncNoCopyByValue(t) ||
		syntaxutil.ContainsUintptr(t) ||
		(allowString && syntaxutil.TypeReachesString(t))
}

func callResultHandsOutOrTuple(allowString bool, t types.Type) bool {
	return refconfine.CallResultHandsOut(t) || (allowString && syntaxutil.TypeReachesString(t))
}

func addrOfSubplaceCanAliasCarrier(audited, allowString bool, v *flowir.Value) bool {
	if v == nil || v.Kind != flowir.ValAddrOf {
		return true
	}
	if v.IsArraySlice {
		if v.Type == nil {
			return true
		}
		sl, ok := types.Unalias(v.Type).Underlying().(*types.Slice)
		if !ok {
			return true
		}
		return canAliasCarrierType(audited, allowString, sl.Elem())
	}
	return v.AddrPlace.Type == nil || canAliasCarrierType(audited, allowString, v.AddrPlace.Type)
}

// placeEntersInterior reports whether accessing or writing through p (with
// writeContainer true for container-mutating operations such as delete, clear,
// channel send, or channel receive) crosses beyond p.Obj's own single-hop
// reference header into interior reach.
func placeEntersInterior(p flowir.Place, writeContainer bool) bool {
	if p.Obj == nil || p.Obj.Type() == nil || isTypeParamType(p.Obj.Type()) {
		return true
	}
	usedHeader := !isRefHeaderType(p.Obj.Type())
	crossHop := func() bool {
		if usedHeader {
			return true
		}
		usedHeader = true
		return false
	}
	for _, proj := range p.Projs {
		if proj.BaseType == nil || isTypeParamType(proj.BaseType) {
			return true
		}
		baseU := types.Unalias(proj.BaseType).Underlying()
		switch proj.Kind {
		case flowir.ProjDeref:
			if crossHop() {
				return true
			}
		case flowir.ProjIndex:
			switch baseU.(type) {
			case *types.Array:
				// Inline array element: no pointer/header indirection.
			case *types.Pointer, *types.Slice, *types.Map:
				if crossHop() {
					return true
				}
			default:
				return true
			}
		case flowir.ProjSlice:
			switch baseU.(type) {
			case *types.Slice, *types.Array:
				// Re-slicing a slice or inline array yields a slice view without an extra hop.
			case *types.Pointer:
				if crossHop() {
					return true
				}
			default:
				return true
			}
		case flowir.ProjField:
			cur := baseU
			if ptr, isPtr := cur.(*types.Pointer); isPtr {
				if crossHop() {
					return true
				}
				cur = types.Unalias(ptr.Elem()).Underlying()
			}
			if proj.Selection == nil {
				return true
			}
			idx := proj.Selection.Index()
			for _, fi := range idx[:len(idx)-1] {
				st, ok := cur.(*types.Struct)
				if !ok || fi < 0 || fi >= st.NumFields() {
					return true
				}
				ft := st.Field(fi).Type()
				if isTypeParamType(ft) {
					return true
				}
				fu := types.Unalias(ft).Underlying()
				if ptr, isPtr := fu.(*types.Pointer); isPtr {
					if crossHop() {
						return true
					}
					cur = types.Unalias(ptr.Elem()).Underlying()
				} else {
					cur = fu
				}
			}
		default:
			return true
		}
	}
	if writeContainer {
		if crossHop() {
			return true
		}
	}
	return false
}

// visitAllBodyOps visits every synchronous operation in b and recursively
// descends into nested ValMakeClosure and CallIIFE bodies (plus OpGo call
// expressions).
func visitAllBodyOps(b *flowir.Body, fn func(*flowir.Op)) {
	if b == nil {
		return
	}
	var scanVal func(v *flowir.Value)
	scanVal = func(v *flowir.Value) {
		if v == nil {
			return
		}
		if v.Kind == flowir.ValMakeClosure && v.Closure != nil {
			visitAllBodyOps(v.Closure, fn)
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallIIFE && v.IIFE != nil {
			visitAllBodyOps(v.IIFE, fn)
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			scanVal(ch)
			return true
		})
	}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind != flowir.OpGo {
			fn(op)
		}
		forEachOpTopValues(op, scanVal)
		return true
	})
}

// visitSyncAndIIFEOps visits every synchronous non-OpGo operation in b and
// recursively descends into synchronous CallIIFE bodies without entering
// uncalled ValMakeClosure bodies or spawned goroutines.
func visitSyncAndIIFEOps(b *flowir.Body, fn func(*flowir.Op)) {
	if b == nil {
		return
	}
	var scanVal func(v *flowir.Value)
	scanVal = func(v *flowir.Value) {
		if v == nil || v.Kind == flowir.ValMakeClosure {
			return
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallIIFE {
			for _, a := range v.Args {
				scanVal(a)
			}
			if v.IIFE != nil {
				visitSyncAndIIFEOps(v.IIFE, fn)
			}
			return
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			scanVal(ch)
			return true
		})
	}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind == flowir.OpGo {
			return true
		}
		fn(op)
		forEachOpTopValues(op, scanVal)
		return true
	})
}

func forEachIIFEReturnValue(v *flowir.Value, fn func(*flowir.Value)) {
	if v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallIIFE || v.IIFE == nil || fn == nil {
		return
	}
	for _, rv := range v.IIFE.Results {
		if rv == nil {
			continue
		}
		fn(&flowir.Value{
			Kind: flowir.ValPlace,
			Type: rv.Type(),
			Place: flowir.Place{
				Root:    flowir.RootResult,
				RootPos: rv.Pos(),
				Obj:     rv,
				Type:    rv.Type(),
			},
		})
	}
	v.IIFE.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind != flowir.OpReturn {
			return true
		}
		for _, res := range op.Results {
			if res != nil {
				fn(res)
			}
		}
		return true
	})
}

func walkTransientTargetValues(root *flowir.Value, fn func(*flowir.Value)) {
	if root == nil || fn == nil {
		return
	}
	var walk func(cur *flowir.Value)
	walk = func(cur *flowir.Value) {
		if cur == nil || cur.Kind == flowir.ValMakeClosure {
			return
		}
		if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallIIFE {
			forEachIIFEReturnValue(cur, walk)
			return
		}
		fn(cur)
		cur.ForEachChildValue(func(ch *flowir.Value) bool {
			walk(ch)
			return true
		})
	}
	walk(root)
}

func forEachOpTopValues(op *flowir.Op, fn func(*flowir.Value)) {
	if op == nil {
		return
	}
	switch op.Kind {
	case flowir.OpAssign:
		for _, dst := range op.Dsts {
			dst.ForEachChildValue(func(cv *flowir.Value) bool {
				fn(cv)
				return true
			})
		}
		for _, src := range op.Srcs {
			fn(src)
		}
	case flowir.OpTypeSwitchBind:
		fn(op.SwitchSrc)
	case flowir.OpChanSend:
		op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
			fn(cv)
			return true
		})
		fn(op.ChanVal)
		fn(op.SendVal)
	case flowir.OpReturn:
		for _, r := range op.Results {
			fn(r)
		}
	case flowir.OpDefer, flowir.OpGo:
		fn(op.Call)
	case flowir.OpExpr:
		fn(op.Expr)
	}
}

func transientValueHasUnresolvedTarget(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	unresolved := false
	walkTransientTargetValues(v, func(cur *flowir.Value) {
		switch cur.Kind {
		case flowir.ValCall:
			if cur.CallKind != flowir.CallIIFE {
				unresolved = true
			}
		case flowir.ValChanRecv:
			unresolved = true
		}
	})
	return unresolved
}

// forEachNestedLiteralAndGo invokes onLit for each immediate nested
// ValMakeClosure or CallIIFE body and invokes onGo for each synchronous OpGo.
func forEachNestedLiteralAndGo(b *flowir.Body, onLit func(*flowir.Body), onGo func(*flowir.Op)) {
	if b == nil {
		return
	}
	var scanVal func(v *flowir.Value)
	scanVal = func(v *flowir.Value) {
		if v == nil {
			return
		}
		if v.Kind == flowir.ValMakeClosure {
			if onLit != nil && v.Closure != nil {
				onLit(v.Closure)
			}
			return
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallIIFE {
			for _, a := range v.Args {
				scanVal(a)
			}
			if onLit != nil && v.IIFE != nil {
				onLit(v.IIFE)
			}
			return
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			scanVal(ch)
			return true
		})
	}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind == flowir.OpGo {
			if onGo != nil {
				onGo(op)
			}
			return true
		}
		forEachOpTopValues(op, scanVal)
		return true
	})
}

func collectValueCarrierVars(
	audited, allowString bool,
	v *flowir.Value,
	carrierVar func(types.Object) (*types.Var, bool),
	aliases map[types.Object]localCarrierAliases,
	skipMethodRecv func(*flowir.Value) bool,
) []*types.Var {
	return collectValueCarrierVarsWithOpts(audited, allowString, v, carrierVar, aliases, skipMethodRecv, false)
}

func collectValueCarrierVarsWithOpts(
	audited, allowString bool,
	v *flowir.Value,
	carrierVar func(types.Object) (*types.Var, bool),
	aliases map[types.Object]localCarrierAliases,
	skipMethodRecv func(*flowir.Value) bool,
	skipNonBuiltinCalls bool,
) []*types.Var {
	if v == nil {
		return nil
	}
	var vars []*types.Var
	addObj := func(u *types.Var) {
		if u == nil {
			return
		}
		if cv, isC := carrierVar(u); isC {
			appendUniqueVars(&vars, []*types.Var{cv})
		} else {
			appendUniqueVars(&vars, aliases[u].all)
		}
	}
	strOK := allowString
	var walk func(cur *flowir.Value)
	walk = func(cur *flowir.Value) {
		if cur == nil || cur.Kind == flowir.ValMakeClosure {
			return
		}
		isStrBuiltin := cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallBuiltin &&
			(cur.BuiltinName == "String" || cur.BuiltinName == "StringData")
		if !isStrBuiltin && cur.Type != nil && !canAliasCarrierType(audited, strOK, cur.Type) && !isTypeParamType(cur.Type) {
			return
		}
		if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallIIFE {
			forEachIIFEReturnValue(cur, walk)
			return
		}
		switch cur.Kind {
		case flowir.ValAllocFresh:
			if cur.AllocKind == flowir.AllocMake || cur.AllocKind == flowir.AllocBuiltinNewType {
				return
			}
		case flowir.ValConvert:
			if !cur.IsTypeAssert && cur.Arg != nil && syntaxutil.IsFreshStringSliceCopy(cur.Arg.Type, cur.Type) {
				return
			}
		case flowir.ValPlace:
			addObj(cur.Place.Obj)
		case flowir.ValAddrOf:
			addObj(cur.AddrPlace.Obj)
		case flowir.ValCall:
			if cur.CallKind == flowir.CallBuiltin {
				switch cur.BuiltinName {
				case "len", "cap", "Sizeof", "Alignof", "Offsetof":
					return
				case "Slice", "SliceData", "String":
					if len(cur.Args) > 0 {
						walk(cur.Args[0])
					}
					return
				case "StringData":
					if len(cur.Args) > 0 {
						prev := strOK
						strOK = true
						walk(cur.Args[0])
						strOK = prev
					}
					return
				}
			}
			if skipNonBuiltinCalls && cur.CallKind != flowir.CallBuiltin {
				return
			}
			if skipMethodRecv != nil && skipMethodRecv(cur) {
				for _, a := range cur.Args {
					walk(a)
				}
				return
			}
			if cur.AutoAddrRecv && cur.HasRecvPlace {
				addObj(cur.RecvPlace.Obj)
			}
		}
		cur.ForEachChildValue(func(ch *flowir.Value) bool {
			walk(ch)
			return true
		})
	}
	walk(v)
	return vars
}

func valueCarrierSources(
	audited, allowString bool,
	v *flowir.Value,
	carrierVar func(types.Object) (*types.Var, bool),
	aliases map[types.Object]localCarrierAliases,
	skipMethodRecv func(*flowir.Value) bool,
	skipNonBuiltinCalls bool,
) (rootSrcs, allSrcs []*types.Var) {
	if v == nil {
		return nil, nil
	}
	allSrcs = collectValueCarrierVarsWithOpts(audited, allowString, v, carrierVar, aliases, skipMethodRecv, skipNonBuiltinCalls)
	if len(allSrcs) == 0 {
		return nil, nil
	}
	switch v.Kind {
	case flowir.ValAllocFresh:
		return nil, allSrcs
	case flowir.ValPlace:
		if v.Place.IsBareVar() {
			if cv, isC := carrierVar(v.Place.Obj); isC {
				if isRefHeaderType(cv.Type()) || isTypeParamType(cv.Type()) {
					return []*types.Var{cv}, allSrcs
				}
				return nil, allSrcs
			}
			return aliases[v.Place.Obj].root, allSrcs
		}
		if v.Place.Obj != nil && len(v.Place.Projs) == 1 && v.Place.Projs[0].Kind == flowir.ProjSlice {
			if cv, isC := carrierVar(v.Place.Obj); isC {
				return []*types.Var{cv}, allSrcs
			}
			return aliases[v.Place.Obj].root, allSrcs
		}
		return allSrcs, allSrcs
	case flowir.ValAddrOf:
		if v.AddrPlace.Obj != nil {
			if _, isC := carrierVar(v.AddrPlace.Obj); isC {
				return allSrcs, allSrcs
			}
			if v.IsArraySlice {
				if placeEntersInterior(v.AddrPlace, false) {
					return allSrcs, allSrcs
				}
				return aliases[v.AddrPlace.Obj].root, allSrcs
			}
			if v.AddrPlace.IsBareVar() {
				return nil, allSrcs
			}
			if !placeEntersInterior(v.AddrPlace, false) {
				return aliases[v.AddrPlace.Obj].root, allSrcs
			}
		}
		return allSrcs, allSrcs
	case flowir.ValCall:
		if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
			var rSrcs []*types.Var
			forEachIIFEReturnValue(v, func(retVal *flowir.Value) {
				rs, _ := valueCarrierSources(audited, allowString, retVal, carrierVar, aliases, skipMethodRecv, skipNonBuiltinCalls)
				appendUniqueVars(&rSrcs, rs)
			})
			return rSrcs, allSrcs
		}
		return allSrcs, allSrcs
	default:
		return allSrcs, allSrcs
	}
}

// collectValueLinkVars collects init-flow carrier storage links without crossing
// general plain/method/indirect function calls, while traversing places,
// &place, array [:], composite literals, Go 1.26+ new(expr), CallResultHandsOut
// conversions/type assertions, and pointer/value-forwarding builtins.
func collectValueLinkVars(
	allowString bool,
	v *flowir.Value,
	carrierVar func(types.Object) (*types.Var, bool),
	linkAliases map[types.Object][]*types.Var,
) []*types.Var {
	if v == nil {
		return nil
	}
	var vars []*types.Var
	addObj := func(u *types.Var) {
		if u == nil {
			return
		}
		if cv, isC := carrierVar(u); isC {
			appendUniqueVars(&vars, []*types.Var{cv})
		} else {
			appendUniqueVars(&vars, linkAliases[u])
		}
	}
	strOK := allowString
	var walkPlaceBase func(pl flowir.Place, addressed bool)
	var walk func(cur *flowir.Value)
	walkPlaceBase = func(pl flowir.Place, addressed bool) {
		if !addressed && pl.Type != nil && !callResultHandsOutOrTuple(strOK, pl.Type) && !isTypeParamType(pl.Type) {
			return
		}
		if pl.Obj != nil {
			addObj(pl.Obj)
			return
		}
		if pl.Root == flowir.RootTransient && pl.Base != nil {
			walk(pl.Base)
		}
	}
	walk = func(cur *flowir.Value) {
		if cur == nil {
			return
		}
		isStrBuiltin := cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallBuiltin &&
			(cur.BuiltinName == "String" || cur.BuiltinName == "StringData")
		if !isStrBuiltin && cur.Type != nil && !callResultHandsOutOrTuple(strOK, cur.Type) {
			return
		}
		switch cur.Kind {
		case flowir.ValPlace:
			walkPlaceBase(cur.Place, false)
		case flowir.ValAddrOf:
			walkPlaceBase(cur.AddrPlace, true)
		case flowir.ValMethodVal:
			if cur.HasRecvPlace {
				walkPlaceBase(cur.RecvPlace, cur.AutoAddr)
			} else {
				walk(cur.Recv)
			}
		case flowir.ValConvert:
			walk(cur.Arg)
		case flowir.ValCompositeExpr:
			for _, a := range cur.Args {
				walk(a)
			}
		case flowir.ValAllocFresh:
			switch cur.AllocKind {
			case flowir.AllocBuiltinNewExpr:
				if len(cur.Args) == 1 && !cur.Ellipsis {
					walk(cur.Args[0])
				}
			case flowir.AllocCompositeLit:
				for i := range cur.CompositeElts {
					elt := &cur.CompositeElts[i]
					if elt.MapKey != nil {
						walk(elt.MapKey)
					}
					if elt.Value != nil {
						walk(elt.Value)
					}
				}
			}
		case flowir.ValCall:
			if cur.CallKind == flowir.CallIIFE {
				forEachIIFEReturnValue(cur, walk)
			} else if cur.CallKind == flowir.CallBuiltin {
				switch cur.BuiltinName {
				case "append", "Add", "min", "max":
					for _, a := range cur.Args {
						walk(a)
					}
				case "Slice", "SliceData", "String":
					if len(cur.Args) > 0 {
						walk(cur.Args[0])
					}
				case "StringData":
					if len(cur.Args) > 0 {
						prev := strOK
						strOK = true
						walk(cur.Args[0])
						strOK = prev
					}
				}
			}
		}
	}
	walk(v)
	return vars
}

type carrierAliasConfig struct {
	allowString          bool
	parentAliases        map[types.Object]localCarrierAliases
	parentLinks          map[types.Object][]*types.Var
	carrierVar           func(types.Object) (*types.Var, bool)
	skipMethodRecv       func(*flowir.Value) bool
	skipNonBuiltinCalls  bool
	descendNested        bool
	trackLinks           bool
	onCarrierLink        func(own, target *types.Var)
	onNonCarrierPkgBind  func(pkgVar *types.Var, pos token.Pos, composite bool, allVars, linkVars []*types.Var)
	onParamCompositeBind func(pos token.Pos, allVars, linkVars []*types.Var)
	onRHSMethodValue     func(mv *flowir.Value, aliases map[types.Object]localCarrierAliases)
	onPlainCall          func(
		callVal *flowir.Value,
		valSources func(*flowir.Value) (rootSrcs, allSrcs []*types.Var),
		valLinks func(*flowir.Value) []*types.Var,
	)
}

func computeBodyCarrierAliases(
	audited bool,
	fc *pkgFlowCache,
	b *flowir.Body,
	cfg carrierAliasConfig,
) (map[types.Object]localCarrierAliases, map[types.Object][]*types.Var) {
	aliased := make(map[types.Object]localCarrierAliases, len(cfg.parentAliases))
	for obj, entry := range cfg.parentAliases {
		aliased[obj] = localCarrierAliases{
			root: append([]*types.Var(nil), entry.root...),
			all:  append([]*types.Var(nil), entry.all...),
		}
	}
	var linkAliased map[types.Object][]*types.Var
	if cfg.trackLinks {
		linkAliased = make(map[types.Object][]*types.Var, len(cfg.parentLinks))
		for obj, lvars := range cfg.parentLinks {
			linkAliased[obj] = append([]*types.Var(nil), lvars...)
		}
	}
	if b == nil || cfg.carrierVar == nil {
		return aliased, linkAliased
	}

	visitOps := func(fn func(*flowir.Op)) {
		if cfg.descendNested {
			visitAllBodyOps(b, fn)
		} else {
			visitSyncAndIIFEOps(b, fn)
		}
	}

	memAliases := fc.scopedLocalCarrierAliases(audited, b, nil)
	addrTakenBare := map[*types.Var]bool{}
	visitOps(func(op *flowir.Op) {
		var checkAddr func(v *flowir.Value)
		checkAddr = func(v *flowir.Value) {
			if v == nil {
				return
			}
			if !cfg.descendNested {
				if v.Kind == flowir.ValMakeClosure {
					return
				}
				if v.Kind == flowir.ValCall && v.CallKind == flowir.CallIIFE {
					for _, a := range v.Args {
						checkAddr(a)
					}
					return
				}
			}
			if v.Kind == flowir.ValAddrOf && !v.IsArraySlice && v.AddrPlace.IsBareVar() {
				addrTakenBare[v.AddrPlace.Obj] = true
			}
			if v.Kind == flowir.ValMethodVal && v.AutoAddr && v.HasRecvPlace && v.RecvPlace.IsBareVar() {
				addrTakenBare[v.RecvPlace.Obj] = true
			}
			if v.Kind == flowir.ValCall && v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.IsBareVar() {
				addrTakenBare[v.RecvPlace.Obj] = true
			}
			v.ForEachChildValue(func(ch *flowir.Value) bool {
				checkAddr(ch)
				return true
			})
		}
		forEachOpTopValues(op, checkAddr)
	})

	addAliases := func(dst types.Object, rootSrcs, allSrcs []*types.Var) bool {
		if dst == nil || (len(rootSrcs) == 0 && len(allSrcs) == 0) {
			return false
		}
		if _, isC := cfg.carrierVar(dst); isC {
			return false
		}
		entry := aliased[dst]
		changed := false
		if len(rootSrcs) > 0 && (isRefHeaderType(dst.Type()) || isTypeParamType(dst.Type())) {
			if appendUniqueVars(&entry.root, rootSrcs) {
				changed = true
			}
			if appendUniqueVars(&entry.all, rootSrcs) {
				changed = true
			}
		}
		if appendUniqueVars(&entry.all, allSrcs) {
			changed = true
		}
		if changed {
			aliased[dst] = entry
		}
		return changed
	}

	addLinkAliases := func(dst types.Object, lvars []*types.Var) bool {
		if !cfg.trackLinks || dst == nil || len(lvars) == 0 {
			return false
		}
		if _, isC := cfg.carrierVar(dst); isC {
			return false
		}
		cur := linkAliased[dst]
		if appendUniqueVars(&cur, lvars) {
			linkAliased[dst] = cur
			return true
		}
		return false
	}

	valSources := func(v *flowir.Value) (rootSrcs, allSrcs []*types.Var) {
		return valueCarrierSources(audited, cfg.allowString, v, cfg.carrierVar, aliased, cfg.skipMethodRecv, cfg.skipNonBuiltinCalls)
	}
	valLinks := func(v *flowir.Value) []*types.Var {
		if !cfg.trackLinks {
			return nil
		}
		return collectValueLinkVars(cfg.allowString, v, cfg.carrierVar, linkAliased)
	}

	isTopParam := make(map[*types.Var]bool, len(b.Params))
	for _, pv := range b.Params {
		if pv != nil {
			isTopParam[pv] = true
		}
	}

	propagateMem := func(obj *types.Var, pos token.Pos, derefStore bool, rootSrcs, allSrcs, lvars []*types.Var) bool {
		if len(memAliases[obj]) == 0 {
			return false
		}
		changed := false
		for next := range memAliases[obj] {
			var nextRoot []*types.Var
			if nv, ok := next.(*types.Var); ok {
				if derefStore && addrTakenBare[nv] {
					nextRoot = rootSrcs
				}
				if cfg.onParamCompositeBind != nil && isTopParam[nv] {
					cfg.onParamCompositeBind(pos, allSrcs, lvars)
				}
			}
			if addAliases(next, nextRoot, allSrcs) {
				changed = true
			}
			if addLinkAliases(next, lvars) {
				changed = true
			}
		}
		return changed
	}

	bindObj := func(obj *types.Var, pos token.Pos, composite, inPlace, derefStore bool, rootSrcs, allSrcs, lvars []*types.Var) bool {
		if obj == nil || (len(rootSrcs) == 0 && len(allSrcs) == 0 && len(lvars) == 0) {
			return false
		}
		if cv, isC := cfg.carrierVar(obj); isC {
			if cfg.onCarrierLink != nil {
				for _, lv := range lvars {
					if lv != cv {
						cfg.onCarrierLink(cv, lv)
					}
				}
			}
			return false
		}
		if obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() {
			if cfg.onNonCarrierPkgBind != nil {
				cfg.onNonCarrierPkgBind(obj, pos, composite || inPlace, allSrcs, lvars)
			}
			return false
		}
		if !syntaxutil.IsLocalVar(obj) {
			return false
		}
		if composite || inPlace {
			if cfg.onParamCompositeBind != nil && isTopParam[obj] {
				cfg.onParamCompositeBind(pos, allSrcs, lvars)
			}
			if cfg.onCarrierLink != nil && len(lvars) > 0 {
				for _, own := range aliased[obj].all {
					for _, lv := range lvars {
						if lv != own {
							cfg.onCarrierLink(own, lv)
						}
					}
				}
			}
		}
		changed := false
		if len(rootSrcs) > 0 || len(allSrcs) > 0 {
			if composite || inPlace || canAliasCarrierType(audited, cfg.allowString, obj.Type()) || isTypeParamType(obj.Type()) {
				var ownRoot []*types.Var
				if (!composite && !inPlace) || (derefStore && addrTakenBare[obj]) {
					ownRoot = rootSrcs
				}
				if addAliases(obj, ownRoot, allSrcs) {
					changed = true
				}
			}
		}
		if addLinkAliases(obj, lvars) {
			changed = true
		}
		if (composite || inPlace) && propagateMem(obj, pos, derefStore, rootSrcs, allSrcs, lvars) {
			changed = true
		}
		return changed
	}

	bindPlace := func(dst flowir.Place, rootSrcs, allSrcs, lvars []*types.Var, inPlace bool) bool {
		if len(rootSrcs) == 0 && len(allSrcs) == 0 && len(lvars) == 0 {
			return false
		}
		derefStore := !inPlace && len(dst.Projs) >= 1 && dst.Projs[len(dst.Projs)-1].Kind == flowir.ProjDeref
		if dst.Obj != nil {
			return bindObj(dst.Obj, dst.RootPos, !dst.IsBareVar(), inPlace, derefStore, rootSrcs, allSrcs, lvars)
		}
		if dst.Root == flowir.RootTransient && dst.Base != nil {
			changed := false
			walkTransientTargetValues(dst.Base, func(cur *flowir.Value) {
				if cur.Kind == flowir.ValPlace && cur.Place.Obj != nil {
					if bindObj(cur.Place.Obj, cur.Place.RootPos, true, !derefStore, derefStore, rootSrcs, allSrcs, lvars) {
						changed = true
					}
				} else if cur.Kind == flowir.ValAddrOf && cur.AddrPlace.Obj != nil {
					if bindObj(cur.AddrPlace.Obj, cur.AddrPlace.RootPos, true, !derefStore, derefStore, rootSrcs, allSrcs, lvars) {
						changed = true
					}
				}
			})
			return changed
		}
		return false
	}

	bindValTarget := func(target *flowir.Value, allSrcs, lvars []*types.Var) bool {
		if target == nil || (len(allSrcs) == 0 && len(lvars) == 0) {
			return false
		}
		if target.Kind == flowir.ValPlace {
			return bindPlace(target.Place, nil, allSrcs, lvars, true)
		}
		changed := false
		walkTransientTargetValues(target, func(cur *flowir.Value) {
			if cur.Kind == flowir.ValPlace && cur.Place.Obj != nil {
				if bindObj(cur.Place.Obj, cur.Place.RootPos, true, true, false, nil, allSrcs, lvars) {
					changed = true
				}
			} else if cur.Kind == flowir.ValAddrOf && cur.AddrPlace.Obj != nil {
				if bindObj(cur.AddrPlace.Obj, cur.AddrPlace.RootPos, true, true, false, nil, allSrcs, lvars) {
					changed = true
				}
			}
		})
		return changed
	}

	scanMethodValues := func(v *flowir.Value) {
		if cfg.onRHSMethodValue == nil || v == nil {
			return
		}
		var walk func(cur *flowir.Value)
		walk = func(cur *flowir.Value) {
			if cur == nil || cur.Kind == flowir.ValMakeClosure {
				return
			}
			if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallIIFE {
				for _, a := range cur.Args {
					walk(a)
				}
				forEachIIFEReturnValue(cur, walk)
				return
			}
			if cur.Kind == flowir.ValMethodVal {
				cfg.onRHSMethodValue(cur, aliased)
			}
			cur.ForEachChildValue(func(ch *flowir.Value) bool {
				walk(ch)
				return true
			})
		}
		walk(v)
	}

	for changed := true; changed; {
		changed = false
		var scanCallBinds func(v *flowir.Value)
		scanCallBinds = func(v *flowir.Value) {
			if v == nil || v.Kind == flowir.ValMakeClosure {
				return
			}
			if v.Kind == flowir.ValCall {
				switch v.CallKind {
				case flowir.CallBuiltin:
					switch {
					case v.BuiltinName == "copy" && len(v.Args) == 2:
						_, allSrcs := valSources(v.Args[1])
						lvars := valLinks(v.Args[1])
						if bindValTarget(v.Args[0], allSrcs, lvars) {
							changed = true
						}
					case v.BuiltinName == "append" && len(v.Args) >= 2:
						for _, elem := range v.Args[1:] {
							_, allSrcs := valSources(elem)
							lvars := valLinks(elem)
							if bindValTarget(v.Args[0], allSrcs, lvars) {
								changed = true
							}
						}
					}
				case flowir.CallPlain:
					if cfg.onPlainCall != nil && !v.IsMethodExprCall {
						cfg.onPlainCall(v, valSources, valLinks)
					}
				case flowir.CallIIFE:
					for _, a := range v.Args {
						scanCallBinds(a)
					}
					if v.IIFE != nil {
						v.ForEachArgParam(func(arg *flowir.Value, _ types.Type, _ int, paramIdx int, ok bool, packedVariadic bool) bool {
							if !ok || paramIdx < 0 || paramIdx >= len(v.IIFE.Params) || arg == nil {
								return true
							}
							pv := v.IIFE.Params[paramIdx]
							if pv == nil {
								return true
							}
							rootSrcs, allSrcs := valSources(arg)
							if packedVariadic {
								rootSrcs = nil
							}
							lvars := valLinks(arg)
							if bindObj(pv, pv.Pos(), packedVariadic, false, false, rootSrcs, allSrcs, lvars) {
								changed = true
							}
							return true
						})
					}
					return
				}
			}
			v.ForEachChildValue(func(ch *flowir.Value) bool {
				scanCallBinds(ch)
				return true
			})
		}
		visitOps(func(op *flowir.Op) {
			forEachOpTopValues(op, scanMethodValues)
			switch op.Kind {
			case flowir.OpAssign:
				op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
					rootSrcs, allSrcs := valSources(src)
					lvars := valLinks(src)
					if op.AssignKind == flowir.AssignRange {
						rootSrcs = allSrcs
					}
					if mapPlace, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil {
						_, keyAll := valSources(keyVal)
						keyLinks := valLinks(keyVal)
						mergedAll := append([]*types.Var(nil), allSrcs...)
						appendUniqueVars(&mergedAll, keyAll)
						mergedLinks := append([]*types.Var(nil), lvars...)
						appendUniqueVars(&mergedLinks, keyLinks)
						if bindPlace(mapPlace, nil, mergedAll, mergedLinks, true) {
							changed = true
						}
					} else if bindPlace(dst, rootSrcs, allSrcs, lvars, false) {
						changed = true
					}
					dst.ForEachChildValue(func(cv *flowir.Value) bool {
						scanCallBinds(cv)
						return true
					})
					return true
				})
				for _, src := range op.Srcs {
					scanCallBinds(src)
				}
			case flowir.OpTypeSwitchBind:
				if op.SwitchDst != nil && syntaxutil.IsLocalVar(op.SwitchDst) {
					rootSrcs, allSrcs := valSources(op.SwitchSrc)
					lvars := valLinks(op.SwitchSrc)
					var swPos token.Pos
					if op.SwitchAST != nil {
						swPos = op.SwitchAST.Pos()
					}
					if bindObj(op.SwitchDst, swPos, false, false, false, rootSrcs, allSrcs, lvars) {
						changed = true
					}
				}
				scanCallBinds(op.SwitchSrc)
			case flowir.OpChanSend:
				_, sendAll := valSources(op.SendVal)
				sendLinks := valLinks(op.SendVal)
				if bindPlace(op.ChanPlace, nil, sendAll, sendLinks, true) {
					changed = true
				}
				op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool {
					scanCallBinds(cv)
					return true
				})
				scanCallBinds(op.ChanVal)
				scanCallBinds(op.SendVal)
			case flowir.OpReturn:
				for _, r := range op.Results {
					scanCallBinds(r)
				}
			case flowir.OpDefer, flowir.OpGo:
				scanCallBinds(op.Call)
			case flowir.OpExpr:
				scanCallBinds(op.Expr)
			}
		})
	}
	return aliased, linkAliased
}
