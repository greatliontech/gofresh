package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func boundValueLeakFree(audited bool, p *packages.Package, roots map[types.Object]bool, body ast.Node) bool {
	return boundValueLeakFreeJudged(audited, p, roots, body, nil, nil, nil, nil, nil)
}

func boundValueLeakFreeDeferred(audited bool, p *packages.Package, roots map[types.Object]bool, body ast.Node, wants map[syntaxutil.ParamKey]bool) bool {
	return boundValueLeakFreeJudged(audited, p, roots, body, wants, nil, nil, nil, nil)
}

func boundValueLeakFreeJudged(
	audited bool,
	p *packages.Package,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	returns *bool,
	methodWants map[syntaxutil.FuncKey]bool,
	fieldWants map[syntaxutil.FieldPosKey]bool,
	elemWants map[syntaxutil.ElemParamUse]bool,
) bool {
	return boundValueJudged(audited, p, roots, body, wants, returns, methodWants, fieldWants, elemWants, false, false)
}

func boundValueClosureEnvLeakFreeJudged(
	audited bool,
	p *packages.Package,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
) bool {
	return boundValueJudged(audited, p, roots, body, wants, nil, methodWants, nil, nil, false, true)
}

func boundValueRetentionFreeJudged(
	audited bool,
	p *packages.Package,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	methodWants map[syntaxutil.FuncKey]bool,
) bool {
	return boundValueJudged(audited, p, roots, body, wants, nil, methodWants, nil, nil, true, false)
}

func boundValueJudged(
	audited bool,
	p *packages.Package,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[syntaxutil.ParamKey]bool,
	returns *bool,
	methodWants map[syntaxutil.FuncKey]bool,
	fieldWants map[syntaxutil.FieldPosKey]bool,
	elemWants map[syntaxutil.ElemParamUse]bool,
	tolerateRootedStores bool,
	allowCapturedClosure bool,
) bool {
	if p == nil || p.TypesInfo == nil || body == nil || len(roots) == 0 {
		return false
	}
	for r := range roots {
		if r == nil || refconfine.TypeReachesSyncNoCopyByValue(r.Type()) {
			return false
		}
	}
	lowered := flowir.LowerNode(p.TypesInfo, p.Types, body)
	if lowered == nil {
		return false
	}
	eng := &confinementEngine{
		audited:              audited,
		p:                    p,
		rootBody:             lowered,
		roots:                roots,
		tainted:              map[types.Object]bool{},
		tolerateRootedStores: tolerateRootedStores,
		allowCapturedClosure: allowCapturedClosure,
		wants:                wants,
		returns:              returns,
		methodWants:          methodWants,
		fieldWants:           fieldWants,
		elemWants:            elemWants,
	}
	return eng.run()
}

type valueEvalMode uint8

const (
	modeGeneral valueEvalMode = iota
	modeGovernedBindOrReturn
	modeBlankDiscard
)

type confinementEngine struct {
	audited              bool
	p                    *packages.Package
	rootBody             *flowir.Body
	roots                map[types.Object]bool
	tainted              map[types.Object]bool
	externalReaching     map[types.Object]bool
	tolerateRootedStores bool
	allowCapturedClosure bool

	// Bound-value deferral sinks.
	wants       map[syntaxutil.ParamKey]bool
	returns     *bool
	methodWants map[syntaxutil.FuncKey]bool
	fieldWants  map[syntaxutil.FieldPosKey]bool
	elemWants   map[syntaxutil.ElemParamUse]bool

	// Receiver read-only mode configuration.
	recvMode          bool
	recvObj           types.Object
	methods           map[string]methodBodyEntry
	declared          map[string]bool
	declaredByName    map[string][]string
	bodyless          map[string]bool
	closedFields      map[*types.Var][]string
	admittedOnceDo    map[*ast.CallExpr]bool
	recordMethodChain func(target string)
}

type methodBodyEntry struct {
	decl *ast.FuncDecl
	recv *ast.Ident
}

func (e *confinementEngine) run() bool {
	e.propagateTaint()
	if e.tolerateRootedStores {
		e.propagateExternalReaching()
	}
	return e.checkBody(e.rootBody, true, false)
}

func (e *confinementEngine) isRootOrTainted(obj types.Object) bool {
	return obj != nil && (e.roots[obj] || e.tainted[obj])
}

func (e *confinementEngine) placeIsRooted(pl flowir.Place) bool {
	if pl.Obj != nil {
		return e.isRootOrTainted(pl.Obj)
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil {
		return e.valueIsRooted(pl.Base) || (e.recvMode && e.isGovernableRecvCall(pl.Base))
	}
	return false
}

func (e *confinementEngine) valueIsRooted(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	switch v.Kind {
	case flowir.ValPlace:
		return e.placeIsRooted(v.Place)
	case flowir.ValAddrOf:
		return e.placeIsRooted(v.AddrPlace)
	case flowir.ValMethodVal:
		return e.valueIsRooted(v.Recv) || (v.HasRecvPlace && e.placeIsRooted(v.RecvPlace))
	case flowir.ValConvert:
		return e.valueIsRooted(v.Arg)
	case flowir.ValChanRecv:
		return e.valueIsRooted(v.Chan)
	default:
		return false
	}
}

func (e *confinementEngine) isMethodVal(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	if v.Kind == flowir.ValMethodVal {
		return true
	}
	if v.Kind == flowir.ValConvert {
		return e.isMethodVal(v.Arg)
	}
	return false
}

// isGovernableRecvCall reports whether v is a method call on a receiver-rooted
// expression targeting an in-package sibling, unexported interface method, or
// closed-world interface field on recvObj.
func (e *confinementEngine) isGovernableRecvCall(v *flowir.Value) bool {
	if !e.recvMode || v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallMethod || v.IsMethodExprCall {
		return false
	}
	if !e.valueIsRooted(v.Recv) || v.CalleeFunc == nil || v.Selection == nil || v.CallAST == nil {
		return false
	}
	if v.CalleeFunc.Pkg() != e.p.Types {
		return false
	}
	sel, ok := syntaxutil.UnwrapCallee(v.CallAST.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	target := syntaxutil.RecvTypeNameOf(e.p, sel) + "." + v.CalleeFunc.Name()
	if _, sibling := e.methods[target]; sibling {
		return true
	}
	if _, ok := unexportedDispatchTargets(e.p, v.Selection, v.CalleeFunc, e.declaredByName, e.bodyless); ok {
		return true
	}
	if !e.bodyless[v.CalleeFunc.Name()] {
		if _, ok := closedFieldDispatchTargets(e.p.TypesInfo, e.recvObj, sel, v.CalleeFunc.Name(), e.closedFields, e.declared); ok {
			return true
		}
	}
	return false
}

func (e *confinementEngine) isSyncOnceCall(v *flowir.Value) bool {
	if v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallMethod || v.IsMethodExprCall {
		return false
	}
	if len(v.Args) != 1 || v.Args[0] == nil || v.Args[0].Kind != flowir.ValMakeClosure || v.Args[0].Closure == nil {
		return false
	}
	if e.recvMode {
		return v.CallAST != nil && e.admittedOnceDo[v.CallAST]
	}
	if !refconfine.AuditedOnceDo(e.audited, v.CalleeFunc) {
		return false
	}
	if !v.HasRecvPlace || !refconfine.InPlaceSyncReceiver(e.p.TypesInfo, v.RecvPlace.Raw) {
		return false
	}
	if e.valueIsRooted(v.Recv) {
		return e.tolerateRootedStores
	}
	return true
}

func (e *confinementEngine) valueSuppliesRoot(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	if v.Type != nil &&
		!refconfine.TypeHandsOutMutableReach(v.Type) &&
		!refconfine.TypeCarriesSignature(v.Type) &&
		!refconfine.TypeReachesSyncNoCopyByValue(v.Type) {
		return false
	}
	if e.valueIsRooted(v) {
		return true
	}
	switch v.Kind {
	case flowir.ValInvalid:
		return true
	case flowir.ValPlace:
		if v.Place.Root == flowir.RootTransient {
			return e.valueSuppliesRoot(v.Place.Base)
		}
		return false
	case flowir.ValAddrOf:
		if v.AddrPlace.Root == flowir.RootTransient {
			return e.valueSuppliesRoot(v.AddrPlace.Base)
		}
		return false
	case flowir.ValMethodVal:
		return e.valueSuppliesRoot(v.Recv)
	case flowir.ValChanRecv:
		return e.valueSuppliesRoot(v.Chan)
	case flowir.ValConvert:
		return e.valueSuppliesRoot(v.Arg)
	case flowir.ValAllocFresh:
		switch v.AllocKind {
		case flowir.AllocMake, flowir.AllocBuiltinNewType:
			return false
		case flowir.AllocBuiltinNewExpr:
			return len(v.Args) > 0 && e.valueSuppliesRoot(v.Args[0])
		case flowir.AllocCompositeLit:
			for i := range v.CompositeElts {
				elt := &v.CompositeElts[i]
				if e.valueSuppliesRoot(elt.MapKey) || e.valueSuppliesRoot(elt.Value) {
					return true
				}
			}
			return false
		}
	case flowir.ValMakeClosure:
		if v.Closure != nil {
			for fv := range v.Closure.FreeVars {
				if e.isRootOrTainted(fv) {
					return true
				}
			}
		}
		return false
	case flowir.ValCall:
		if e.recvMode && e.isGovernableRecvCall(v) {
			return !refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type())
		}
		if v.CallKind == flowir.CallBuiltin && v.BuiltinName == "append" {
			for _, a := range v.Args {
				if e.valueSuppliesRoot(a) {
					return true
				}
			}
		}
		if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
			supplied := false
			v.IIFE.ForEachSyncOp(func(op *flowir.Op) bool {
				if op.Kind == flowir.OpReturn {
					for _, r := range op.Results {
						if e.valueSuppliesRoot(r) {
							supplied = true
							return false
						}
					}
				}
				return true
			})
			return supplied
		}
	case flowir.ValCompositeExpr:
		for _, a := range v.Args {
			if e.valueSuppliesRoot(a) {
				return true
			}
		}
	}
	return false
}

func (e *confinementEngine) propagateTaint() {
	eligible := func(v *types.Var) bool {
		return v != nil && !v.IsField() && !e.roots[v] && refconfine.CallResultHandsOut(v.Type())
	}
	markPlaceBase := func(pl flowir.Place) bool {
		if pl.Obj != nil && eligible(pl.Obj) && !e.tainted[pl.Obj] {
			e.tainted[pl.Obj] = true
			return true
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		var visitBody func(b *flowir.Body)
		var visitVal func(v *flowir.Value)
		visitVal = func(v *flowir.Value) {
			if v == nil {
				return
			}
			if v.Kind == flowir.ValCall {
				if v.CallKind == flowir.CallBuiltin && v.BuiltinName == "copy" && len(v.Args) == 2 {
					if e.valueSuppliesRoot(v.Args[1]) && v.Args[0] != nil && v.Args[0].Kind == flowir.ValPlace {
						if markPlaceBase(v.Args[0].Place) {
							changed = true
						}
					}
				}
				if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
					for i, arg := range v.Args {
						if pIdx, ok := v.ParamIndexForArg(i); ok && pIdx < len(v.IIFE.Params) {
							if pv := v.IIFE.Params[pIdx]; eligible(pv) && !e.tainted[pv] && e.valueSuppliesRoot(arg) {
								e.tainted[pv] = true
								changed = true
							}
						}
					}
					visitBody(v.IIFE)
				} else if e.isSyncOnceCall(v) {
					visitBody(v.Args[0].Closure)
				}
			}
			v.ForEachChildValue(func(child *flowir.Value) bool {
				visitVal(child)
				return true
			})
		}
		visitBody = func(b *flowir.Body) {
			if b == nil {
				return
			}
			b.ForEachSyncOp(func(op *flowir.Op) bool {
				switch op.Kind {
				case flowir.OpAssign:
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						if src != nil && e.valueSuppliesRoot(src) {
							if markPlaceBase(dst) {
								changed = true
							}
						}
						if mapPlace, keyVal, isMapWrite := dst.AsMapWrite(); isMapWrite && keyVal != nil && e.valueSuppliesRoot(keyVal) {
							if markPlaceBase(mapPlace) {
								changed = true
							}
						}
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							visitVal(cv)
							return true
						})
						return true
					})
					for _, src := range op.Srcs {
						visitVal(src)
					}
				case flowir.OpTypeSwitchBind:
					if eligible(op.SwitchDst) && !e.tainted[op.SwitchDst] && e.valueSuppliesRoot(op.SwitchSrc) {
						e.tainted[op.SwitchDst] = true
						changed = true
					}
					visitVal(op.SwitchSrc)
				case flowir.OpChanSend:
					if e.valueSuppliesRoot(op.SendVal) {
						if markPlaceBase(op.ChanPlace) {
							changed = true
						}
					}
					visitVal(op.ChanVal)
					visitVal(op.SendVal)
				case flowir.OpReturn:
					for _, r := range op.Results {
						visitVal(r)
					}
				case flowir.OpDefer:
					visitVal(op.Call)
				case flowir.OpExpr:
					visitVal(op.Expr)
				}
				return true
			})
		}
		visitBody(e.rootBody)
	}
}

func (e *confinementEngine) isExternalSeedVar(v *types.Var) bool {
	if v == nil || v.IsField() || e.roots[v] {
		return false
	}
	if e.externalReaching[v] {
		return true
	}
	isPkgGlobal := v.Pkg() != nil && v.Parent() == v.Pkg().Scope()
	isOuter := v.Pos() < e.rootBody.BodyStart || v.Pos() > e.rootBody.BodyEnd
	if !isPkgGlobal && !isOuter {
		return false
	}
	t := v.Type()
	return t == nil ||
		refconfine.TypeHandsOutMutableReach(t) ||
		refconfine.TypeMayCarryUnknownDynamic(e.audited, t) ||
		refconfine.TypeCarriesSignature(t)
}

func (e *confinementEngine) valueReachesExternal(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	found := false
	var walk func(cur *flowir.Value)
	walk = func(cur *flowir.Value) {
		if found || cur == nil {
			return
		}
		switch cur.Kind {
		case flowir.ValPlace:
			if cur.Place.Obj != nil && !e.roots[cur.Place.Obj] && e.isExternalSeedVar(cur.Place.Obj) {
				found = true
				return
			}
		case flowir.ValAddrOf:
			if vObj := cur.AddrPlace.Obj; vObj != nil && !e.roots[vObj] {
				if e.externalReaching[vObj] || vObj.Pos() < e.rootBody.BodyStart || vObj.Pos() > e.rootBody.BodyEnd ||
					(vObj.Pkg() != nil && vObj.Parent() == vObj.Pkg().Scope()) {
					found = true
					return
				}
			}
		case flowir.ValMethodVal:
			if cur.AutoAddr && cur.HasRecvPlace && cur.RecvPlace.Obj != nil && !e.roots[cur.RecvPlace.Obj] {
				vObj := cur.RecvPlace.Obj
				if e.externalReaching[vObj] || vObj.Pos() < e.rootBody.BodyStart || vObj.Pos() > e.rootBody.BodyEnd ||
					(vObj.Pkg() != nil && vObj.Parent() == vObj.Pkg().Scope()) {
					found = true
					return
				}
			}
		case flowir.ValChanRecv:
			found = true
			return
		case flowir.ValAllocFresh:
			if cur.AllocKind == flowir.AllocMake || cur.AllocKind == flowir.AllocBuiltinNewType {
				return
			}
		case flowir.ValMakeClosure:
			if cur.Closure != nil {
				for fv := range cur.Closure.FreeVars {
					if e.isExternalSeedVar(fv) {
						found = true
						return
					}
				}
			}
			return
		case flowir.ValCall:
			ct := cur.Type
			if ct == nil ||
				refconfine.TypeHandsOutMutableReach(ct) ||
				refconfine.TypeMayCarryUnknownDynamic(e.audited, ct) ||
				refconfine.TypeCarriesSignature(ct) {
				switch cur.CallKind {
				case flowir.CallBuiltin:
					switch cur.BuiltinName {
					case "make":
						return
					case "append":
						for _, a := range cur.Args {
							walk(a)
						}
						return
					default:
						found = true
						return
					}
				case flowir.CallPlain:
					fk := syntaxutil.FuncKey{Pkg: cur.CalleePkg, Name: ""}
					if cur.CalleeFunc != nil {
						fk.Name = cur.CalleeFunc.Name()
					}
					if !auditedValuePlane[fk] {
						found = true
						return
					}
				default:
					found = true
					return
				}
			}
		}
		cur.ForEachChildValue(func(child *flowir.Value) bool {
			walk(child)
			return !found
		})
	}
	walk(v)
	return found
}

func (e *confinementEngine) propagateExternalReaching() {
	e.externalReaching = map[types.Object]bool{}
	markVar := func(v *types.Var) bool {
		if v != nil && !v.IsField() && !e.roots[v] && !e.externalReaching[v] {
			e.externalReaching[v] = true
			return true
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		var visitBody func(b *flowir.Body)
		var visitVal func(v *flowir.Value)
		visitVal = func(v *flowir.Value) {
			if v == nil {
				return
			}
			if v.Kind == flowir.ValCall {
				if v.CallKind == flowir.CallBuiltin && v.BuiltinName == "copy" && len(v.Args) == 2 {
					if e.valueReachesExternal(v.Args[1]) && v.Args[0] != nil && v.Args[0].Kind == flowir.ValPlace {
						if markVar(v.Args[0].Place.Obj) {
							changed = true
						}
					}
				}
				if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
					for i, arg := range v.Args {
						if pIdx, ok := v.ParamIndexForArg(i); ok && pIdx < len(v.IIFE.Params) {
							if pv := v.IIFE.Params[pIdx]; pv != nil && e.valueReachesExternal(arg) && markVar(pv) {
								changed = true
							}
						}
					}
					visitBody(v.IIFE)
				} else if e.isSyncOnceCall(v) {
					visitBody(v.Args[0].Closure)
				}
			}
			v.ForEachChildValue(func(child *flowir.Value) bool {
				visitVal(child)
				return true
			})
		}
		visitBody = func(b *flowir.Body) {
			if b == nil {
				return
			}
			b.ForEachSyncOp(func(op *flowir.Op) bool {
				switch op.Kind {
				case flowir.OpAssign:
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						if src != nil && e.valueReachesExternal(src) && markVar(dst.Obj) {
							changed = true
						}
						if mapPlace, keyVal, isMapWrite := dst.AsMapWrite(); isMapWrite && keyVal != nil && e.valueReachesExternal(keyVal) {
							if markVar(mapPlace.Obj) {
								changed = true
							}
						}
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							visitVal(cv)
							return true
						})
						return true
					})
					for _, src := range op.Srcs {
						visitVal(src)
					}
				case flowir.OpTypeSwitchBind:
					if e.valueReachesExternal(op.SwitchSrc) && markVar(op.SwitchDst) {
						changed = true
					}
					visitVal(op.SwitchSrc)
				case flowir.OpChanSend:
					if e.valueReachesExternal(op.SendVal) && markVar(op.ChanPlace.Obj) {
						changed = true
					}
					visitVal(op.ChanVal)
					visitVal(op.SendVal)
				case flowir.OpReturn:
					for _, r := range op.Results {
						visitVal(r)
					}
				case flowir.OpDefer:
					visitVal(op.Call)
				case flowir.OpExpr:
					visitVal(op.Expr)
				}
				return true
			})
		}
		visitBody(e.rootBody)
	}
}

func (e *confinementEngine) valueTouchesAnyRoot(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	hit := false
	var walk func(cur *flowir.Value)
	walk = func(cur *flowir.Value) {
		if hit || cur == nil {
			return
		}
		switch cur.Kind {
		case flowir.ValPlace:
			if cur.Place.Obj != nil && e.isRootOrTainted(cur.Place.Obj) {
				hit = true
				return
			}
		case flowir.ValAddrOf:
			if cur.AddrPlace.Obj != nil && e.isRootOrTainted(cur.AddrPlace.Obj) {
				hit = true
				return
			}
		case flowir.ValMethodVal:
			if cur.HasRecvPlace && cur.RecvPlace.Obj != nil && e.isRootOrTainted(cur.RecvPlace.Obj) {
				hit = true
				return
			}
		case flowir.ValMakeClosure:
			if cur.Closure != nil {
				for fv := range cur.Closure.FreeVars {
					if e.isRootOrTainted(fv) {
						hit = true
						return
					}
				}
			}
		case flowir.ValCall:
			if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil {
				for fv := range cur.IIFE.FreeVars {
					if e.isRootOrTainted(fv) {
						hit = true
						return
					}
				}
			}
		}
		cur.ForEachChildValue(func(child *flowir.Value) bool {
			walk(child)
			return !hit
		})
	}
	walk(v)
	return hit
}

func (e *confinementEngine) bodyTouchesAnyRoot(b *flowir.Body) bool {
	if b == nil {
		return false
	}
	for fv := range b.FreeVars {
		if e.isRootOrTainted(fv) {
			return true
		}
	}
	hit := false
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		switch op.Kind {
		case flowir.OpAssign:
			for i := range op.Dsts {
				if op.Dsts[i].Obj != nil && e.isRootOrTainted(op.Dsts[i].Obj) {
					hit = true
					return false
				}
				op.Dsts[i].ForEachChildValue(func(cv *flowir.Value) bool {
					if e.valueTouchesAnyRoot(cv) {
						hit = true
						return false
					}
					return true
				})
				if hit {
					return false
				}
			}
			for _, s := range op.Srcs {
				if e.valueTouchesAnyRoot(s) {
					hit = true
					return false
				}
			}
		case flowir.OpTypeSwitchBind:
			if (op.SwitchDst != nil && e.isRootOrTainted(op.SwitchDst)) || e.valueTouchesAnyRoot(op.SwitchSrc) {
				hit = true
			}
		case flowir.OpChanSend:
			if (op.ChanPlace.Obj != nil && e.isRootOrTainted(op.ChanPlace.Obj)) ||
				e.valueTouchesAnyRoot(op.ChanVal) || e.valueTouchesAnyRoot(op.SendVal) {
				hit = true
			}
		case flowir.OpReturn:
			if op.IsNaked {
				for _, rv := range b.Results {
					if e.isRootOrTainted(rv) {
						hit = true
						break
					}
				}
			} else {
				for _, r := range op.Results {
					if e.valueTouchesAnyRoot(r) {
						hit = true
						break
					}
				}
			}
		case flowir.OpGo, flowir.OpDefer:
			if e.valueTouchesAnyRoot(op.Call) {
				hit = true
			}
		case flowir.OpExpr:
			if e.valueTouchesAnyRoot(op.Expr) {
				hit = true
			}
		}
		return !hit
	})
	return hit
}

func (e *confinementEngine) placeMapKeysSmuggle(pl flowir.Place, allowEmptyCarrier bool) bool {
	for i := range pl.Projs {
		pr := &pl.Projs[i]
		if pr.Kind != flowir.ProjIndex || pr.Key == nil || !syntaxutil.TypeMayBeMap(pr.BaseType) {
			continue
		}
		var slotT types.Type
		if mt, isMap := syntaxutil.UnderlyingType(pr.BaseType).(*types.Map); isMap {
			slotT = mt.Key()
		} else {
			// Type parameter constrained by ~map[K]V: use key's static type.
			slotT = pr.Key.Type
		}
		kt := pr.Key.Type
		if slotT == nil || kt == nil ||
			refconfine.TypeReachesSyncNoCopyByValue(slotT) || refconfine.TypeReachesSyncNoCopyByValue(kt) {
			return true
		}
		if (refconfine.TypeMayCarryUnknownDynamic(e.audited, slotT) || refconfine.TypeCarriesSignature(slotT) ||
			refconfine.TypeMayCarryUnknownDynamic(e.audited, kt) || refconfine.TypeCarriesSignature(kt)) &&
			(!allowEmptyCarrier || !isCarrierEmptySlotStore(e.audited, e.p.TypesInfo, slotT, pr.Key.Raw)) {
			return true
		}
		if (refconfine.TypeHandsOutMutableReach(slotT) || refconfine.TypeHandsOutMutableReach(kt)) &&
			(!e.tolerateRootedStores || e.valueReachesExternal(pr.Key)) {
			return true
		}
	}
	return false
}

func (e *confinementEngine) checkPlaceChildValues(pl flowir.Place) bool {
	ok := true
	if pl.Root == flowir.RootTransient && pl.Base != nil {
		if e.placeIsRooted(pl) {
			if !e.checkRootedReadOperand(pl.Base) {
				return false
			}
		} else if !e.checkValue(pl.Base, modeGeneral) {
			return false
		}
	}
	for i := range pl.Projs {
		pr := &pl.Projs[i]
		if pr.Key != nil && !e.checkValue(pr.Key, modeGeneral) {
			ok = false
			break
		}
		if pr.Low != nil && !e.checkValue(pr.Low, modeGeneral) {
			ok = false
			break
		}
		if pr.High != nil && !e.checkValue(pr.High, modeGeneral) {
			ok = false
			break
		}
		if pr.Max != nil && !e.checkValue(pr.Max, modeGeneral) {
			ok = false
			break
		}
	}
	return ok
}

func (e *confinementEngine) checkRootedReadOperand(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	switch v.Kind {
	case flowir.ValInvalid, flowir.ValMethodVal, flowir.ValAddrOf, flowir.ValChanRecv:
		return false
	case flowir.ValPlace:
		return e.checkPlaceChildValues(v.Place)
	case flowir.ValConvert:
		if v.Type == nil || v.Arg == nil || v.Arg.Type == nil ||
			syntaxutil.IsUnsafePointerType(v.Type) ||
			refconfine.TypeReachesSyncNoCopyByValue(v.Type) ||
			refconfine.TypeReachesSyncNoCopyByValue(v.Arg.Type) {
			return false
		}
		if v.IsTypeAssert && refconfine.TypeCarriesSignature(v.Type) && !refconfine.TypeCarriesSignature(v.Arg.Type) {
			return false
		}
		return e.checkRootedReadOperand(v.Arg)
	case flowir.ValCall:
		if e.recvMode && e.isGovernableRecvCall(v) {
			return e.checkCall(v, true)
		}
		return false
	default:
		return false
	}
}

func (e *confinementEngine) isEscapingGlobalType(t types.Type) bool {
	return t == nil ||
		refconfine.TypeHandsOutMutableReach(t) ||
		refconfine.TypeCarriesSignature(t) ||
		refconfine.TypeReachesSyncNoCopyByValue(t)
}

func (e *confinementEngine) checkRootedStoreAllowed(op *flowir.Op, dst flowir.Place, isDef bool, src *flowir.Value, inOnceDo bool) bool {
	if e.tolerateRootedStores {
		switch op.AssignKind {
		case flowir.AssignIncDec:
			return !e.placeMapKeysSmuggle(dst, true)
		case flowir.AssignRange:
			return !isDef &&
				dst.Type != nil &&
				!refconfine.TypeMayCarryUnknownDynamic(e.audited, dst.Type) &&
				!refconfine.CallResultHandsOut(dst.Type) &&
				!refconfine.TypeReachesSyncNoCopyByValue(dst.Type) &&
				!e.placeMapKeysSmuggle(dst, true)
		case flowir.AssignPlain:
			if dst.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(dst.Type) {
				return false
			}
			if refconfine.TypeMayCarryUnknownDynamic(e.audited, dst.Type) || refconfine.TypeCarriesSignature(dst.Type) {
				if src == nil || !isCarrierEmptySlotStore(e.audited, e.p.TypesInfo, dst.Type, src.Raw) {
					return false
				}
			}
			if refconfine.TypeHandsOutMutableReach(dst.Type) {
				if src == nil || e.valueReachesExternal(src) {
					return false
				}
			}
			return !e.placeMapKeysSmuggle(dst, true)
		default:
			return dst.Type != nil &&
				!refconfine.TypeMayCarryUnknownDynamic(e.audited, dst.Type) &&
				!refconfine.CallResultHandsOut(dst.Type) &&
				!refconfine.TypeReachesSyncNoCopyByValue(dst.Type) &&
				!e.placeMapKeysSmuggle(dst, true)
		}
	}
	if e.recvMode && inOnceDo && op.TopLevelInBody && op.AssignKind != flowir.AssignRange {
		if !refconfine.FillSelection(e.p.TypesInfo, dst.Raw) {
			return false
		}
		if dst.Type == nil ||
			refconfine.TypeMayCarryUnknownDynamic(e.audited, dst.Type) ||
			refconfine.CallResultHandsOut(dst.Type) ||
			refconfine.TypeReachesSyncNoCopyByValue(dst.Type) {
			return false
		}
		return !e.placeMapKeysSmuggle(dst, false)
	}
	return false
}

func (e *confinementEngine) checkBody(b *flowir.Body, isTopBody bool, inOnceDo bool) bool {
	if b == nil {
		return false
	}
	for i := range b.Ops {
		if !e.checkOp(&b.Ops[i], b, isTopBody, inOnceDo) {
			return false
		}
	}
	return true
}

func (e *confinementEngine) checkOp(op *flowir.Op, b *flowir.Body, isTopBody bool, inOnceDo bool) bool {
	switch op.Kind {
	case flowir.OpGo:
		if op.Call == nil || op.Call.Kind != flowir.ValCall || op.Call.CallKind == flowir.CallBuiltin {
			return !e.valueTouchesAnyRoot(op.Call)
		}
		if op.Call.CallKind == flowir.CallIIFE && (op.Call.IIFE == nil || e.bodyTouchesAnyRoot(op.Call.IIFE)) {
			return false
		}
		if (op.Call.Recv != nil && e.valueIsRooted(op.Call.Recv)) ||
			(op.Call.AutoAddrRecv && op.Call.HasRecvPlace && e.placeIsRooted(op.Call.RecvPlace)) ||
			(op.Call.Callee != nil && e.valueIsRooted(op.Call.Callee)) {
			return false
		}
		prevAllow := e.allowCapturedClosure
		e.allowCapturedClosure = false
		defer func() { e.allowCapturedClosure = prevAllow }()
		if op.Call.Recv != nil && !e.checkValue(op.Call.Recv, modeGeneral) {
			return false
		}
		if op.Call.Callee != nil && !e.checkValue(op.Call.Callee, modeGeneral) {
			return false
		}
		for _, arg := range op.Call.Args {
			if e.valueSuppliesRoot(arg) || !e.checkValue(arg, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.OpDefer:
		return e.checkValue(op.Call, modeGeneral)

	case flowir.OpBranch:
		return true

	case flowir.OpExpr:
		return e.checkValue(op.Expr, modeGeneral)

	case flowir.OpChanSend:
		if e.placeIsRooted(op.ChanPlace) || e.valueIsRooted(op.ChanVal) {
			return false
		}
		if !e.checkValue(op.ChanVal, modeGeneral) {
			return false
		}
		return e.checkValue(op.SendVal, modeGeneral)

	case flowir.OpTypeSwitchBind:
		if e.valueIsRooted(op.SwitchSrc) || (e.recvMode && e.isGovernableRecvCall(op.SwitchSrc)) {
			if e.isMethodVal(op.SwitchSrc) ||
				op.SwitchSrc.Type == nil ||
				refconfine.TypeReachesSyncNoCopyByValue(op.SwitchSrc.Type) ||
				(op.SwitchDst != nil && (op.SwitchDst.Type() == nil ||
					refconfine.TypeReachesSyncNoCopyByValue(op.SwitchDst.Type()) ||
					(refconfine.TypeCarriesSignature(op.SwitchDst.Type()) && !refconfine.TypeCarriesSignature(op.SwitchSrc.Type)))) {
				return false
			}
			return e.checkValue(op.SwitchSrc, modeGovernedBindOrReturn)
		}
		return e.checkValue(op.SwitchSrc, modeGeneral)

	case flowir.OpReturn:
		if op.IsNaked {
			for _, resVar := range b.Results {
				if resVar == nil || !e.isRootOrTainted(resVar) {
					continue
				}
				synth := &flowir.Value{
					Kind: flowir.ValPlace,
					Type: resVar.Type(),
					Place: flowir.Place{
						Root: flowir.RootResult,
						Obj:  resVar,
						Type: resVar.Type(),
					},
				}
				if !e.checkReturnResult(synth, isTopBody) {
					return false
				}
			}
			return true
		}
		for _, res := range op.Results {
			if !e.checkReturnResult(res, isTopBody) {
				return false
			}
		}
		return true

	case flowir.OpAssign:
		return e.checkAssignOp(op, isTopBody, inOnceDo)

	default:
		return false
	}
}

func (e *confinementEngine) checkReturnResult(res *flowir.Value, isTopBody bool) bool {
	if res == nil {
		return false
	}
	if e.valueIsRooted(res) || (e.recvMode && e.isGovernableRecvCall(res)) {
		if e.isMethodVal(res) || res.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(res.Type) {
			return false
		}
		if e.recvMode {
			if !isTopBody {
				return false
			}
			return e.checkValue(res, modeGovernedBindOrReturn)
		}
		if refconfine.TypeHandsOutMutableReach(res.Type) {
			if isTopBody && e.returns != nil {
				*e.returns = true
				return e.checkValue(res, modeGovernedBindOrReturn)
			}
			return false
		}
		if refconfine.TypeCarriesSignature(res.Type) {
			return false
		}
		return e.checkValue(res, modeGovernedBindOrReturn)
	}
	return e.checkValue(res, modeGeneral)
}

func (e *confinementEngine) dstAcceptsGovernedRoot(dst flowir.Place) bool {
	if dst.IsBlank() {
		return true
	}
	if !dst.IsBareVar() {
		return false
	}
	if dst.Root == flowir.RootPkgGlobal {
		return !e.isEscapingGlobalType(dst.Type)
	}
	return true
}

func (e *confinementEngine) checkAssignLHS(op *flowir.Op, dst flowir.Place, isDef bool, src *flowir.Value, inOnceDo bool) bool {
	if !e.checkPlaceChildValues(dst) {
		return false
	}
	if dst.IsBlank() {
		return true
	}
	if dst.IsBareVar() {
		if dst.Root == flowir.RootPkgGlobal {
			if src != nil && (e.valueIsRooted(src) || e.valueSuppliesRoot(src) || (e.recvMode && e.isGovernableRecvCall(src))) {
				if e.isEscapingGlobalType(dst.Type) {
					return false
				}
			}
			return true
		}
		if e.recvMode && dst.Obj == e.recvObj {
			return false
		}
		if e.isRootOrTainted(dst.Obj) {
			if dst.Obj.Pos() < e.rootBody.BodyStart || dst.Obj.Pos() > e.rootBody.BodyEnd {
				return false
			}
			if !e.recvMode && e.fieldWants != nil && refconfine.TypeCarriesSignature(dst.Obj.Type()) {
				originDefine := e.roots[dst.Obj] && isDef
				if (src == nil || !e.valueIsRooted(src)) && !originDefine {
					return false
				}
			}
		}
		return true
	}
	if e.placeIsRooted(dst) {
		return e.checkRootedStoreAllowed(op, dst, isDef, src, inOnceDo)
	}
	return true
}

func (e *confinementEngine) checkAssignOp(op *flowir.Op, isTopBody bool, inOnceDo bool) bool {
	if op.AssignKind == flowir.AssignRange {
		var rngSrc *flowir.Value
		if len(op.Srcs) == 1 {
			rngSrc = op.Srcs[0]
		}
		for i, dst := range op.Dsts {
			isDef := i < len(op.DstDefs) && op.DstDefs[i]
			if !e.checkAssignLHS(op, dst, isDef, rngSrc, inOnceDo) {
				return false
			}
		}
		if rngSrc != nil {
			if e.valueIsRooted(rngSrc) || (e.recvMode && e.isGovernableRecvCall(rngSrc)) {
				if rngSrc.Type == nil || e.isMethodVal(rngSrc) {
					return false
				}
				switch syntaxutil.UnderlyingType(rngSrc.Type).(type) {
				case *types.Chan, *types.Signature:
					return false
				}
				for _, dst := range op.Dsts {
					if !e.dstAcceptsGovernedRoot(dst) {
						return false
					}
					if !dst.IsBlank() && refconfine.TypeReachesSyncNoCopyByValue(dst.Type) {
						return false
					}
				}
				if !e.checkValue(rngSrc, modeGovernedBindOrReturn) {
					return false
				}
			} else if !e.checkValue(rngSrc, modeGeneral) {
				return false
			}
		}
		if op.RangeBody != nil {
			return e.checkBody(op.RangeBody, isTopBody, false)
		}
		return true
	}

	if op.AssignKind == flowir.AssignIncDec {
		if len(op.Dsts) != 1 {
			return false
		}
		return e.checkAssignLHS(op, op.Dsts[0], false, op.Srcs[0], inOnceDo)
	}

	if op.AssignKind == flowir.AssignCompound {
		if len(op.Dsts) != 1 || len(op.Srcs) != 1 {
			return false
		}
		dst := op.Dsts[0]
		var rhsOperand *flowir.Value
		if op.Srcs[0] != nil && op.Srcs[0].Kind == flowir.ValCompositeExpr && len(op.Srcs[0].Args) == 2 {
			rhsOperand = op.Srcs[0].Args[1]
		} else {
			rhsOperand = op.Srcs[0]
		}
		if !e.checkAssignLHS(op, dst, false, rhsOperand, inOnceDo) {
			return false
		}
		if !e.placeIsRooted(dst) && op.Srcs[0] != nil && op.Srcs[0].Kind == flowir.ValCompositeExpr && len(op.Srcs[0].Args) == 2 {
			if !e.checkValue(op.Srcs[0].Args[0], modeGeneral) {
				return false
			}
		}
		return rhsOperand == nil || e.checkValue(rhsOperand, modeGeneral)
	}

	if op.AssignKind == flowir.AssignZeroDecl {
		for i, dst := range op.Dsts {
			isDef := i < len(op.DstDefs) && op.DstDefs[i]
			if !e.checkAssignLHS(op, dst, isDef, nil, inOnceDo) {
				return false
			}
		}
		return true
	}

	if op.AssignKind == flowir.AssignMulti && len(op.Srcs) == 1 {
		src := op.Srcs[0]
		allGoverned := true
		for i, dst := range op.Dsts {
			isDef := i < len(op.DstDefs) && op.DstDefs[i]
			if !e.checkAssignLHS(op, dst, isDef, src, inOnceDo) {
				return false
			}
			if !e.dstAcceptsGovernedRoot(dst) || (!dst.IsBlank() && refconfine.TypeReachesSyncNoCopyByValue(dst.Type)) {
				allGoverned = false
			}
		}
		mode := modeGeneral
		if allGoverned {
			mode = modeGovernedBindOrReturn
			if len(op.Dsts) > 0 && op.Dsts[0].IsBlank() {
				blankPrimary := true
				for _, dst := range op.Dsts[1:] {
					if !dst.IsBlank() && (dst.Type == nil || refconfine.CallResultHandsOut(dst.Type) || refconfine.TypeReachesSyncNoCopyByValue(dst.Type)) {
						blankPrimary = false
						break
					}
				}
				if blankPrimary {
					mode = modeBlankDiscard
				}
			}
		}
		if (mode == modeGovernedBindOrReturn || mode == modeBlankDiscard) && e.valueIsRooted(src) {
			if e.isMethodVal(src) || refconfine.TypeReachesSyncNoCopyByValue(src.Type) {
				return false
			}
		}
		return e.checkValue(src, mode)
	}

	// AssignPlain (1:1 or N:N).
	ok := true
	op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
		if !e.checkAssignLHS(op, dst, isDef, src, inOnceDo) {
			ok = false
			return false
		}
		if src == nil {
			return true
		}
		mode := modeGeneral
		if dst.IsBlank() {
			mode = modeBlankDiscard
		} else if e.dstAcceptsGovernedRoot(dst) {
			mode = modeGovernedBindOrReturn
		}
		if (mode == modeGovernedBindOrReturn || mode == modeBlankDiscard) && e.valueIsRooted(src) {
			if e.isMethodVal(src) || refconfine.TypeReachesSyncNoCopyByValue(src.Type) ||
				(!dst.IsBlank() && refconfine.TypeReachesSyncNoCopyByValue(dst.Type)) {
				ok = false
				return false
			}
		}
		if !e.checkValue(src, mode) {
			ok = false
			return false
		}
		return true
	})
	return ok
}

func (e *confinementEngine) checkValue(v *flowir.Value, mode valueEvalMode) bool {
	if v == nil {
		return true
	}
	switch v.Kind {
	case flowir.ValInvalid:
		return false

	case flowir.ValScalarLitOrConst:
		return true

	case flowir.ValPlace:
		if e.placeIsRooted(v.Place) {
			if mode == modeGovernedBindOrReturn || mode == modeBlankDiscard {
				return e.checkRootedReadOperand(v)
			}
			if v.Type == nil || refconfine.CallResultHandsOut(v.Type) {
				return false
			}
			return e.checkRootedReadOperand(v)
		}
		return e.checkPlaceChildValues(v.Place)

	case flowir.ValAddrOf:
		if e.placeIsRooted(v.AddrPlace) {
			return false
		}
		if !e.checkPlaceChildValues(v.AddrPlace) {
			return false
		}
		if v.Low != nil && !e.checkValue(v.Low, modeGeneral) {
			return false
		}
		if v.High != nil && !e.checkValue(v.High, modeGeneral) {
			return false
		}
		if v.Max != nil && !e.checkValue(v.Max, modeGeneral) {
			return false
		}
		return true

	case flowir.ValMethodVal:
		if e.valueIsRooted(v.Recv) || (v.HasRecvPlace && e.placeIsRooted(v.RecvPlace)) {
			return false
		}
		return e.checkValue(v.Recv, modeGeneral)

	case flowir.ValChanRecv:
		if e.valueIsRooted(v.Chan) {
			return false
		}
		return e.checkValue(v.Chan, modeGeneral)

	case flowir.ValConvert:
		if e.valueIsRooted(v.Arg) || (e.recvMode && e.isGovernableRecvCall(v.Arg)) {
			if e.isMethodVal(v.Arg) || v.Arg == nil || v.Arg.Type == nil || v.Type == nil ||
				syntaxutil.IsUnsafePointerType(v.Type) ||
				refconfine.TypeReachesSyncNoCopyByValue(v.Arg.Type) ||
				refconfine.TypeReachesSyncNoCopyByValue(v.Type) {
				return false
			}
			if v.IsTypeAssert && mode != modeBlankDiscard &&
				refconfine.TypeCarriesSignature(v.Type) && !refconfine.TypeCarriesSignature(v.Arg.Type) {
				return false
			}
			if !refconfine.CallResultHandsOut(v.Type) {
				return e.checkRootedReadOperand(v.Arg)
			}
			if v.IsTypeAssert && (mode == modeGovernedBindOrReturn || mode == modeBlankDiscard) {
				return e.checkRootedReadOperand(v.Arg)
			}
			return false
		}
		return e.checkValue(v.Arg, mode)

	case flowir.ValCompare:
		for _, side := range []*flowir.Value{v.Left, v.Right} {
			if side == nil {
				continue
			}
			if e.valueIsRooted(side) {
				if e.isMethodVal(side) || side.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(side.Type) {
					return false
				}
				if !e.checkRootedReadOperand(side) {
					return false
				}
			} else if !e.checkValue(side, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.ValAllocFresh:
		for i := range v.CompositeElts {
			elt := &v.CompositeElts[i]
			if elt.MapKey != nil && !e.checkValue(elt.MapKey, modeGeneral) {
				return false
			}
			if elt.Index != nil && !e.checkValue(elt.Index, modeGeneral) {
				return false
			}
			if elt.Value != nil && !e.checkValue(elt.Value, modeGeneral) {
				return false
			}
		}
		for _, a := range v.Args {
			if !e.checkValue(a, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.ValMakeClosure:
		if v.Closure == nil {
			return false
		}
		captured := map[types.Object]bool{}
		for fv := range v.Closure.FreeVars {
			if e.isRootOrTainted(fv) {
				captured[fv] = true
			}
		}
		if len(captured) == 0 {
			return true
		}
		if !e.allowCapturedClosure {
			return false
		}
		subEng := &confinementEngine{
			audited:              e.audited,
			p:                    e.p,
			rootBody:             v.Closure,
			roots:                captured,
			tainted:              map[types.Object]bool{},
			tolerateRootedStores: e.tolerateRootedStores,
			allowCapturedClosure: true,
			wants:                e.wants,
			methodWants:          e.methodWants,
			fieldWants:           e.fieldWants,
			elemWants:            e.elemWants,
		}
		return subEng.run()

	case flowir.ValCall:
		return e.checkCall(v, mode == modeGovernedBindOrReturn || mode == modeBlankDiscard)

	case flowir.ValCompositeExpr:
		for _, a := range v.Args {
			if !e.checkValue(a, modeGeneral) {
				return false
			}
		}
		return true

	default:
		return false
	}
}

func (e *confinementEngine) checkCall(v *flowir.Value, governed bool) bool {
	switch v.CallKind {
	case flowir.CallBuiltin:
		if v.BuiltinName == "len" || v.BuiltinName == "cap" {
			for _, arg := range v.Args {
				if e.valueIsRooted(arg) {
					if e.isMethodVal(arg) || !e.checkRootedReadOperand(arg) {
						return false
					}
				} else if !e.checkValue(arg, modeGeneral) {
					return false
				}
			}
			return true
		}
		for _, arg := range v.Args {
			if !e.checkValue(arg, modeGeneral) {
				return false
			}
		}
		return true

	case flowir.CallIIFE:
		if v.IIFE == nil {
			return false
		}
		for i, arg := range v.Args {
			pIdx, ok := v.ParamIndexForArg(i)
			isPackedVariadic := v.CalleeSig != nil && v.CalleeSig.Variadic() && !v.Ellipsis && i >= v.CalleeSig.Params().Len()-1
			if ok && !isPackedVariadic && pIdx < len(v.IIFE.Params) {
				if e.valueIsRooted(arg) {
					if e.isMethodVal(arg) || arg.Type == nil || refconfine.TypeReachesSyncNoCopyByValue(arg.Type) {
						return false
					}
					if !e.checkValue(arg, modeGovernedBindOrReturn) {
						return false
					}
					continue
				}
			}
			if !e.checkValue(arg, modeGeneral) {
				return false
			}
		}
		return e.checkBody(v.IIFE, false, false)

	case flowir.CallMethod:
		if e.isSyncOnceCall(v) {
			if e.valueIsRooted(v.Recv) {
				if !e.checkRootedReadOperand(v.Recv) {
					return false
				}
			} else if !e.checkValue(v.Recv, modeGeneral) {
				return false
			}
			return e.checkBody(v.Args[0].Closure, false, e.recvMode)
		}
		if e.valueIsRooted(v.Recv) {
			if v.IsMethodExprCall || !e.checkRootedReadOperand(v.Recv) {
				return false
			}
			if refconfine.AuditedSynchronization(e.audited, v.CalleeFunc) {
				if !v.HasRecvPlace || !refconfine.InPlaceSyncReceiver(e.p.TypesInfo, v.RecvPlace.Raw) {
					return false
				}
				for _, arg := range v.Args {
					if !e.checkValue(arg, modeGeneral) {
						return false
					}
				}
				return true
			}
			if e.recvMode {
				if v.CalleeFunc == nil || v.CalleeFunc.Pkg() != e.p.Types || v.Selection == nil || v.CallAST == nil {
					return false
				}
				sel, ok := syntaxutil.UnwrapCallee(v.CallAST.Fun).(*ast.SelectorExpr)
				if !ok {
					return false
				}
				target := syntaxutil.RecvTypeNameOf(e.p, sel) + "." + v.CalleeFunc.Name()
				if _, sibling := e.methods[target]; sibling {
					if e.recordMethodChain != nil {
						e.recordMethodChain(target)
					}
					if !refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type()) && !governed {
						return false
					}
				} else {
					targets, ok := unexportedDispatchTargets(e.p, v.Selection, v.CalleeFunc, e.declaredByName, e.bodyless)
					if !ok && !e.bodyless[v.CalleeFunc.Name()] {
						targets, ok = closedFieldDispatchTargets(e.p.TypesInfo, e.recvObj, sel, v.CalleeFunc.Name(), e.closedFields, e.declared)
					}
					if !ok {
						return false
					}
					if e.recordMethodChain != nil {
						for _, t := range targets {
							e.recordMethodChain(t)
						}
					}
					if !refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type()) && !governed {
						return false
					}
				}
				for _, arg := range v.Args {
					if !e.checkValue(arg, modeGeneral) {
						return false
					}
				}
				return true
			}
			if e.methodWants == nil || v.CalleeFunc == nil || v.CalleeFunc.Pkg() == nil ||
				v.CalleeFunc.Pkg().Path() == "sync" || syntaxutil.InterfaceReceiver(v.CalleeFunc) ||
				v.Selection == nil || !refconfine.InstantiatedResultsHandOutNothing(e.audited, v.Selection.Type()) {
				return false
			}
			e.methodWants[syntaxutil.MethodFactKey(v.CalleeFunc)] = true
			return e.checkCallArgs(v)
		}
		if !e.checkValue(v.Recv, modeGeneral) {
			return false
		}
		return e.checkCallArgs(v)

	case flowir.CallPlain:
		return e.checkCallArgs(v)

	case flowir.CallIndirect:
		if e.valueIsRooted(v.Callee) {
			if e.recvMode || e.isMethodVal(v.Callee) || refconfine.CallResultHandsOut(v.Type) {
				return false
			}
			if !e.checkRootedReadOperand(v.Callee) {
				return false
			}
		} else if !e.checkValue(v.Callee, modeGeneral) {
			return false
		}
		return e.checkCallArgs(v)

	default:
		return false
	}
}

func (e *confinementEngine) checkCallArgs(v *flowir.Value) bool {
	for i, arg := range v.Args {
		if !e.valueIsRooted(arg) {
			if !e.checkValue(arg, modeGeneral) {
				return false
			}
			continue
		}
		if e.recvMode || arg.Type == nil || e.isMethodVal(arg) || refconfine.TypeReachesSyncNoCopyByValue(arg.Type) {
			return false
		}
		if !refconfine.TypeHandsOutMutableReach(arg.Type) && !refconfine.TypeCarriesSignature(arg.Type) {
			if !e.checkRootedReadOperand(arg) {
				return false
			}
			continue
		}
		deferred := false
		if v.CallKind == flowir.CallPlain && e.wants != nil && v.CalleeFunc != nil && v.CalleeSig != nil && v.CalleeSig.Recv() == nil {
			if pIdx, ok := v.ParamIndexForArg(i); ok {
				e.wants[syntaxutil.ParamKey{
					Func:  syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Name()},
					Index: pIdx,
				}] = true
				deferred = true
			}
		}
		if !deferred && v.CallKind == flowir.CallIndirect && e.fieldWants != nil &&
			v.Callee != nil && v.Callee.Kind == flowir.ValPlace && len(v.Callee.Place.Projs) > 0 {
			last := v.Callee.Place.Projs[len(v.Callee.Place.Projs)-1]
			prefix := v.Callee.Place
			prefix.Projs = v.Callee.Place.Projs[:len(v.Callee.Place.Projs)-1]
			if last.Kind == flowir.ProjField && last.Field != nil && e.placeIsRooted(prefix) {
				if pIdx, ok := v.ParamIndexForArg(i); ok {
					e.fieldWants[syntaxutil.FieldPosKey{Field: last.Field.Name(), Index: pIdx}] = true
					deferred = true
				}
			}
		}
		if !deferred && v.CallKind == flowir.CallIndirect && e.elemWants != nil &&
			v.Callee != nil && v.Callee.Kind == flowir.ValPlace &&
			v.Callee.Place.Root == flowir.RootPkgGlobal && v.Callee.Place.Obj != nil &&
			len(v.Callee.Place.Projs) == 1 && v.Callee.Place.Projs[0].Kind == flowir.ProjIndex &&
			refconfine.TypeMayCarryUnknownDynamic(e.audited, v.Callee.Place.Obj.Type()) {
			if pIdx, ok := v.ParamIndexForArg(i); ok {
				e.elemWants[syntaxutil.ElemParamUse{
					Owner: syntaxutil.DynamicVarKey(v.Callee.Place.Obj),
					Index: pIdx,
				}] = true
				deferred = true
			}
		}
		if !deferred || !e.checkRootedReadOperand(arg) {
			return false
		}
	}
	return true
}

func paramLeakFreeFunctions(
	audited bool,
	p *packages.Package,
	readOnlyLocal, retentionMethods map[string]bool,
) (
	map[syntaxutil.ParamKey]bool,
	map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool,
	map[syntaxutil.ParamKey]bool,
	map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool,
) {
	if p == nil || p.TypesInfo == nil {
		return nil, nil, nil, nil
	}
	proven := map[syntaxutil.ParamKey]bool{}
	allWants := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	retention := map[syntaxutil.ParamKey]bool{}
	allRetentionWants := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	retainOnly := func(obj types.Object, body ast.Node, key syntaxutil.ParamKey) {
		wants := map[syntaxutil.ParamKey]bool{}
		methodWants := map[syntaxutil.FuncKey]bool{}
		if !boundValueRetentionFreeJudged(audited, p, map[types.Object]bool{obj: true}, body, wants, methodWants) {
			return
		}
		for want := range methodWants {
			if want.Pkg != ownPath || !retentionMethods[want.Name] {
				return
			}
		}
		if len(wants) == 0 {
			retention[key] = true
			return
		}
		allRetentionWants[key] = wants
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Type.Params == nil {
				continue
			}
			ownFunc := syntaxutil.FuncKey{Pkg: ownPath, Name: fd.Name.Name}
			index := 0
			for _, field := range fd.Type.Params.List {
				names := field.Names
				if len(names) == 0 {
					names = []*ast.Ident{nil}
				}
				for _, name := range names {
					idx := index
					index++
					key := syntaxutil.ParamKey{Func: ownFunc, Index: idx}
					if name == nil || name.Name == "_" {
						proven[key] = true
						continue
					}
					obj := p.TypesInfo.Defs[name]
					if obj == nil {
						continue
					}
					if !refconfine.TypeHandsOutMutableReach(obj.Type()) {
						continue
					}
					wants := map[syntaxutil.ParamKey]bool{}
					methodWants := map[syntaxutil.FuncKey]bool{}
					if !boundValueLeakFreeJudged(audited, p, map[types.Object]bool{obj: true}, fd.Body, wants, nil, methodWants, nil, nil) {
						retainOnly(obj, fd.Body, key)
						continue
					}
					methodsProven := true
					for want := range methodWants {
						if want.Pkg != ownPath || !readOnlyLocal[want.Name] || !retentionMethods[want.Name] {
							methodsProven = false
							break
						}
					}
					if !methodsProven {
						retainOnly(obj, fd.Body, key)
						continue
					}
					if len(wants) == 0 {
						proven[key] = true
						continue
					}
					allWants[key] = wants
					retainOnly(obj, fd.Body, key)
				}
			}
		}
	}
	deps := resolveLocalParamDeps(ownPath, proven, allWants, func(need syntaxutil.ParamKey) bool {
		return proven[need]
	})
	retentionDeps := resolveLocalParamDeps(ownPath, retention, allRetentionWants, func(need syntaxutil.ParamKey) bool {
		return retention[need] || proven[need]
	})
	for key := range proven {
		delete(retentionDeps, key)
	}
	return proven, deps, retention, retentionDeps
}

func resolveLocalParamDeps(ownPath string, proven map[syntaxutil.ParamKey]bool, allWants map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool, satisfied func(syntaxutil.ParamKey) bool) map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool {
	conditional := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	deps := map[syntaxutil.ParamKey]map[syntaxutil.ParamKey]bool{}
	for key, wants := range allWants {
		crossPackage := false
		for want := range wants {
			if want.Func.Pkg != ownPath {
				crossPackage = true
				break
			}
		}
		if crossPackage {
			deps[key] = wants
		} else {
			conditional[key] = wants
		}
	}
	syntaxutil.SolveLeastFixedPoint(proven, conditional, satisfied)
	for key, needs := range conditional {
		if satisfied(key) {
			continue
		}
		edges := map[syntaxutil.ParamKey]bool{}
		for need := range needs {
			if !satisfied(need) {
				edges[need] = true
			}
		}
		if len(edges) > 0 {
			deps[key] = edges
		}
	}
	for key, wants := range deps {
		if satisfied(key) {
			delete(deps, key)
			continue
		}
		edges := map[syntaxutil.ParamKey]bool{}
		for need := range wants {
			if !satisfied(need) {
				edges[need] = true
			}
		}
		if len(edges) > 0 {
			deps[key] = edges
		} else {
			delete(deps, key)
		}
	}
	return deps
}

func receiverRetentionFreeMethods(audited bool, p *packages.Package, _ map[string]bool) map[string]bool {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	proven := map[string]bool{}
	pending := map[string]map[string]bool{}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name == nil || fd.Body == nil || len(fd.Recv.List) != 1 {
				continue
			}
			recvName := syntaxutil.RecvTypeName(fd)
			if recvName == "" {
				continue
			}
			key := recvName + "." + fd.Name.Name
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			if recvIdent == nil {
				if recvField := fd.Recv.List[0]; recvField != nil && refconfine.TypeReachesSyncNoCopyByValue(p.TypesInfo.TypeOf(recvField.Type)) {
					continue
				}
				proven[key] = true
				continue
			}
			recvObj := p.TypesInfo.Defs[recvIdent]
			if recvObj == nil {
				continue
			}
			wants := map[syntaxutil.ParamKey]bool{}
			methodWants := map[syntaxutil.FuncKey]bool{}
			if !boundValueRetentionFreeJudged(audited, p, map[types.Object]bool{recvObj: true}, fd.Body, wants, methodWants) {
				continue
			}
			if len(wants) != 0 {
				continue
			}
			needs := map[string]bool{}
			sound := true
			for want := range methodWants {
				if want.Pkg != ownPath {
					sound = false
					break
				}
				needs[want.Name] = true
			}
			if !sound {
				continue
			}
			if len(needs) == 0 {
				proven[key] = true
				continue
			}
			pending[key] = needs
		}
	}
	syntaxutil.SolveLeastFixedPoint(proven, pending, func(need string) bool {
		return proven[need]
	})
	return proven
}

// onceFieldOfDo resolves a call of the shape `x.field.Do(f)` — Do on a
// by-value sync.Once field selected from some value — to that field,
// or nil for every other shape.
func onceFieldOfDo(audited bool, info *types.Info, call *ast.CallExpr) *types.Var {
	if len(call.Args) != 1 {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.MethodVal {
		return nil
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok || !refconfine.AuditedOnceDo(audited, fn) {
		return nil
	}
	fieldSel, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	fieldSelection, ok := info.Selections[fieldSel]
	if !ok || fieldSelection.Kind() != types.FieldVal || len(fieldSelection.Index()) != 1 {
		return nil
	}
	field, ok := fieldSelection.Obj().(*types.Var)
	if !ok {
		return nil
	}
	named, ok := types.Unalias(field.Type()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Once" {
		return nil
	}
	return field
}

func closedInterfaceFields(p *packages.Package, callIdx *refconfine.CallSiteIndex) map[*types.Var][]string {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil
	}
	info := p.TypesInfo
	candidateField := func(field *types.Var) bool {
		if field == nil || !field.IsField() || field.Exported() || field.Pkg() != p.Types {
			return false
		}
		_, isIface := types.Unalias(field.Type()).Underlying().(*types.Interface)
		return isIface
	}
	any := false
	for _, name := range p.Types.Scope().Names() {
		typeName, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := typeName.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields() && !any; i++ {
			any = candidateField(st.Field(i))
		}
	}
	if !any {
		return nil
	}
	if callIdx == nil {
		callIdx = refconfine.BuildCallSiteIndex(p)
	}
	memberTypes := func(expr ast.Expr) ([]string, bool) {
		var members []string
		ok := callIdx.JudgeExpr(expr, func(t types.Type) (bool, bool) {
			if _, isIface := types.Unalias(t).Underlying().(*types.Interface); isIface {
				return false, false
			}
			concrete := types.Unalias(t)
			if ptr, ok := concrete.(*types.Pointer); ok {
				concrete = types.Unalias(ptr.Elem())
			}
			named, ok := concrete.(*types.Named)
			if !ok || named.Obj() == nil || named.Obj().Pkg() != p.Types {
				return true, false
			}
			members = append(members, named.Obj().Name())
			return true, true
		})
		return members, ok
	}
	fieldOf := func(structType types.Type, index int) *types.Var {
		if ptr, ok := types.Unalias(structType).(*types.Pointer); ok {
			structType = ptr.Elem()
		}
		st, ok := types.Unalias(structType).Underlying().(*types.Struct)
		if !ok || index < 0 || index >= st.NumFields() {
			return nil
		}
		if field := st.Field(index); candidateField(field) {
			return field
		}
		return nil
	}
	members := map[*types.Var][]string{}
	open := map[*types.Var]bool{}
	store := func(field *types.Var, value ast.Expr) {
		if !candidateField(field) || open[field] {
			return
		}
		more, ok := memberTypes(value)
		if !ok {
			open[field] = true
			delete(members, field)
			return
		}
		members[field] = append(members[field], more...)
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				t := info.TypeOf(n)
				if t == nil {
					return true
				}
				if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
					t = ptr.Elem()
				}
				for i, elt := range n.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if key, ok := ast.Unparen(kv.Key).(*ast.Ident); ok {
							if field, ok := info.Uses[key].(*types.Var); ok {
								store(field, kv.Value)
							}
						}
						continue
					}
					store(fieldOf(t, i), elt)
				}
			case *ast.AssignStmt:
				if len(n.Lhs) != len(n.Rhs) {
					for _, lhs := range n.Lhs {
						if sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr); ok {
							if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
								if field, ok := selection.Obj().(*types.Var); ok {
									open[field] = true
									delete(members, field)
								}
							}
						}
					}
					return true
				}
				for i, lhs := range n.Lhs {
					sel, ok := ast.Unparen(lhs).(*ast.SelectorExpr)
					if !ok {
						continue
					}
					selection, ok := info.Selections[sel]
					if !ok || selection.Kind() != types.FieldVal {
						continue
					}
					if field, ok := selection.Obj().(*types.Var); ok {
						store(field, n.Rhs[i])
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					if sel, ok := ast.Unparen(n.X).(*ast.SelectorExpr); ok {
						if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
							if field, ok := selection.Obj().(*types.Var); ok {
								open[field] = true
								delete(members, field)
							}
						}
					}
				}
			case *ast.CallExpr:
				tv, ok := info.Types[ast.Unparen(n.Fun)]
				if !ok || !tv.IsType() || len(n.Args) != 1 {
					return true
				}
				to := info.TypeOf(n)
				if to == nil {
					return true
				}
				if ptr, ok := types.Unalias(to).(*types.Pointer); ok {
					to = ptr.Elem()
				}
				st, ok := types.Unalias(to).Underlying().(*types.Struct)
				if !ok || types.Identical(info.TypeOf(n.Args[0]), to) {
					return true
				}
				for i := 0; i < st.NumFields(); i++ {
					if field := fieldOf(to, i); field != nil {
						open[field] = true
						delete(members, field)
					}
				}
			}
			return true
		})
	}
	closed := map[*types.Var][]string{}
	for field, names := range members {
		if open[field] || len(names) == 0 {
			continue
		}
		sort.Strings(names)
		closed[field] = slices.Compact(names)
	}
	return closed
}

func closedFieldDispatchTargets(info *types.Info, recvObj types.Object, sel *ast.SelectorExpr, name string, closed map[*types.Var][]string, declared map[string]bool) ([]string, bool) {
	fieldSel, ok := ast.Unparen(sel.X).(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	ident, ok := ast.Unparen(fieldSel.X).(*ast.Ident)
	if !ok || info.Uses[ident] != recvObj {
		return nil, false
	}
	selection, ok := info.Selections[fieldSel]
	if !ok || selection.Kind() != types.FieldVal || len(selection.Index()) != 1 {
		return nil, false
	}
	field, ok := selection.Obj().(*types.Var)
	if !ok {
		return nil, false
	}
	members, ok := closed[field]
	if !ok {
		return nil, false
	}
	targets := make([]string, 0, len(members))
	for _, member := range members {
		target := member + "." + name
		if !declared[target] {
			return nil, false
		}
		targets = append(targets, target)
	}
	return targets, true
}

func unexportedDispatchTargets(p *packages.Package, selection *types.Selection, fn *types.Func, declaredByName map[string][]string, bodyless map[string]bool) ([]string, bool) {
	if p.Types == nil || fn.Exported() || fn.Pkg() != p.Types || selection.Recv() == nil || bodyless[fn.Name()] {
		return nil, false
	}
	recv := types.Unalias(selection.Recv())
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = types.Unalias(ptr.Elem())
	}
	if _, ok := recv.Underlying().(*types.Interface); !ok {
		return nil, false
	}
	targets := append([]string(nil), declaredByName[fn.Name()]...)
	return targets, len(targets) > 0
}

func receiverReadOnlyMethods(audited bool, p *packages.Package, callIdx *refconfine.CallSiteIndex) map[string]bool {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	methods := map[string]methodBodyEntry{}
	bodyless := map[string]bool{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Recv != nil && fd.Name != nil && fd.Body == nil {
				bodyless[fd.Name.Name] = true
			}
			if !ok || fd.Recv == nil || fd.Name == nil || fd.Body == nil || len(fd.Recv.List) != 1 {
				continue
			}
			recvName := syntaxutil.RecvTypeName(fd)
			if recvName == "" {
				continue
			}
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			methods[recvName+"."+fd.Name.Name] = methodBodyEntry{decl: fd, recv: recvIdent}
		}
	}
	if len(methods) == 0 {
		return nil
	}
	onceSites, onceFieldRefs := collectPackageOnceFieldUsage(audited, p)
	declaredByName := map[string][]string{}
	declared := map[string]bool{}
	for key := range methods {
		declared[key] = true
		if dot := strings.LastIndex(key, "."); dot >= 0 {
			declaredByName[key[dot+1:]] = append(declaredByName[key[dot+1:]], key)
		}
	}
	closedFields := closedInterfaceFields(p, callIdx)
	for _, keys := range declaredByName {
		sort.Strings(keys)
	}
	disqualified := map[string]bool{}
	chains := map[string]map[string]bool{}
	for key, m := range methods {
		if m.recv == nil {
			if recvField := m.decl.Recv.List[0]; recvField != nil && refconfine.TypeReachesSyncNoCopyByValue(p.TypesInfo.TypeOf(recvField.Type)) {
				disqualified[key] = true
			}
			continue
		}
		recvObj := p.TypesInfo.Defs[m.recv]
		if recvObj == nil || refconfine.TypeReachesSyncNoCopyByValue(recvObj.Type()) {
			disqualified[key] = true
			continue
		}
		lowered := flowir.LowerFunc(p.TypesInfo, p.Types, m.decl)
		if lowered == nil {
			disqualified[key] = true
			continue
		}
		admittedOnceDo := findAdmittedReceiverOnceDo(audited, p, lowered, recvObj, onceSites, onceFieldRefs)
		eng := &confinementEngine{
			audited:        audited,
			p:              p,
			rootBody:       lowered,
			roots:          map[types.Object]bool{recvObj: true},
			tainted:        map[types.Object]bool{},
			recvMode:       true,
			recvObj:        recvObj,
			methods:        methods,
			declared:       declared,
			declaredByName: declaredByName,
			bodyless:       bodyless,
			closedFields:   closedFields,
			admittedOnceDo: admittedOnceDo,
			recordMethodChain: func(target string) {
				if chains[key] == nil {
					chains[key] = map[string]bool{}
				}
				chains[key][target] = true
			},
		}
		if !eng.run() {
			disqualified[key] = true
		}
	}
	syntaxutil.SolveReachFixedPoint(disqualified, chains, func(d string) bool { return disqualified[d] })
	readOnly := map[string]bool{}
	for key := range methods {
		if !disqualified[key] {
			readOnly[key] = true
		}
	}
	return readOnly
}

func collectPackageOnceFieldUsage(audited bool, p *packages.Package) (onceSites map[*types.Var]int, onceFieldRefs map[*types.Var]int) {
	onceSites = map[*types.Var]int{}
	onceFieldRefs = map[*types.Var]int{}
	zeroOnceKeyIdents := map[*ast.Ident]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if field := onceFieldOfDo(audited, p.TypesInfo, x); field != nil {
					onceSites[field]++
				}
				if tv, ok := p.TypesInfo.Types[ast.Unparen(x.Fun)]; ok && tv.IsType() && len(x.Args) == 1 {
					to := p.TypesInfo.TypeOf(x)
					from := p.TypesInfo.TypeOf(x.Args[0])
					if to != nil && from != nil && !types.Identical(from, to) {
						for _, convT := range []types.Type{to, from} {
							if ptr, isPtr := types.Unalias(convT).(*types.Pointer); isPtr {
								convT = ptr.Elem()
							}
							if st, isSt := types.Unalias(convT).Underlying().(*types.Struct); isSt {
								for i := 0; i < st.NumFields(); i++ {
									onceFieldRefs[st.Field(i)] += 2
								}
							}
						}
					}
				}
			case *ast.CompositeLit:
				ct := p.TypesInfo.TypeOf(x)
				if ct != nil {
					if ptr, isPtr := types.Unalias(ct).Underlying().(*types.Pointer); isPtr {
						ct = ptr.Elem()
					}
					if st, isSt := types.Unalias(ct).Underlying().(*types.Struct); isSt && len(x.Elts) > 0 {
						if _, keyed := x.Elts[0].(*ast.KeyValueExpr); keyed {
							for _, elt := range x.Elts {
								if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
									if keyID, isID := ast.Unparen(kv.Key).(*ast.Ident); isID && isZeroSyncOnceExpr(p.TypesInfo, kv.Value) {
										zeroOnceKeyIdents[keyID] = true
									}
								}
							}
						} else {
							for i, elt := range x.Elts {
								if i < st.NumFields() && refconfine.TypeReachesOnce(st.Field(i).Type()) && !isZeroSyncOnceExpr(p.TypesInfo, elt) {
									onceFieldRefs[st.Field(i)] += 2
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && !zeroOnceKeyIdents[id] {
				if fld, isVar := p.TypesInfo.Uses[id].(*types.Var); isVar && fld != nil && fld.IsField() {
					onceFieldRefs[fld]++
				}
			}
			return true
		})
	}
	return onceSites, onceFieldRefs
}

func findAdmittedReceiverOnceDo(
	audited bool,
	p *packages.Package,
	body *flowir.Body,
	recvObj types.Object,
	onceSites map[*types.Var]int,
	onceFieldRefs map[*types.Var]int,
) map[*ast.CallExpr]bool {
	if body == nil || recvObj == nil {
		return nil
	}
	if _, pointer := types.Unalias(recvObj.Type()).(*types.Pointer); !pointer {
		return nil
	}
	if refconfine.OnceFieldCount(recvObj.Type()) != 1 {
		return nil
	}
	for i := range body.Ops {
		op := &body.Ops[i]
		if !op.TopLevelInBody {
			return nil
		}
		if op.Kind == flowir.OpExpr && op.Expr != nil && op.Expr.Kind == flowir.ValCall && op.Expr.CallAST != nil {
			call := op.Expr.CallAST
			field := onceFieldOfDo(audited, p.TypesInfo, call)
			if field != nil && !field.Exported() && onceSites[field] == 1 && onceFieldRefs[field] == 1 {
				if ident, ok := call.Fun.(*ast.SelectorExpr).X.(*ast.SelectorExpr).X.(*ast.Ident); ok && p.TypesInfo.Uses[ident] == recvObj {
					if _, rawLit := call.Args[0].(*ast.FuncLit); rawLit && len(op.Expr.Args) == 1 &&
						op.Expr.Args[0] != nil && op.Expr.Args[0].Kind == flowir.ValMakeClosure && op.Expr.Args[0].Closure != nil {
						doBody := op.Expr.Args[0].Closure
						capturesOther := false
						for fv := range doBody.FreeVars {
							if fv != recvObj {
								capturesOther = true
								break
							}
						}
						if !capturesOther {
							return map[*ast.CallExpr]bool{call: true}
						}
					}
				}
			}
		}
		if !opCleanBeforeOnceDo(op, recvObj) {
			return nil
		}
	}
	return nil
}

func opCleanBeforeOnceDo(op *flowir.Op, recvObj types.Object) bool {
	if op == nil || !op.TopLevelInBody || op.Kind != flowir.OpAssign || op.AssignKind == flowir.AssignRange {
		return false
	}
	clean := true
	checkVal := func(v *flowir.Value) {
		if v == nil || !clean {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			switch cur.Kind {
			case flowir.ValInvalid, flowir.ValCall, flowir.ValChanRecv:
				clean = false
				return false
			case flowir.ValPlace:
				if cur.Place.Obj == recvObj || cur.Place.Root == flowir.RootPkgGlobal {
					clean = false
					return false
				}
			case flowir.ValAddrOf:
				if cur.AddrPlace.Obj == recvObj || cur.AddrPlace.Root == flowir.RootPkgGlobal {
					clean = false
					return false
				}
			case flowir.ValMethodVal:
				if cur.HasRecvPlace && (cur.RecvPlace.Obj == recvObj || cur.RecvPlace.Root == flowir.RootPkgGlobal) {
					clean = false
					return false
				}
			case flowir.ValMakeClosure:
				if rVar, ok := recvObj.(*types.Var); ok && cur.Closure != nil && cur.Closure.FreeVars[rVar] {
					clean = false
					return false
				}
			}
			return true
		})
	}
	op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
		if !dst.IsBareVar() || dst.Root != flowir.RootLocal {
			clean = false
			return false
		}
		checkVal(src)
		return clean
	})
	return clean
}

func isZeroSyncOnceExpr(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil {
		return false
	}
	cl, ok := ast.Unparen(expr).(*ast.CompositeLit)
	if !ok || len(cl.Elts) != 0 {
		return false
	}
	named, ok := types.Unalias(info.TypeOf(cl)).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "sync" && named.Obj().Name() == "Once"
}

func isNilInterfaceValueExpr(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil {
		return false
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		_, ok := info.Uses[e].(*types.Nil)
		return ok
	case *ast.CallExpr:
		tv := info.Types[ast.Unparen(e.Fun)]
		if tv.IsType() && types.IsInterface(tv.Type) && len(e.Args) == 1 && !e.Ellipsis.IsValid() {
			return isNilInterfaceValueExpr(info, e.Args[0])
		}
		return false
	default:
		return false
	}
}

func isTypedNilNonInterfaceExpr(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil {
		return false
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		_, ok := info.Uses[e].(*types.Nil)
		return ok
	case *ast.CallExpr:
		tv := info.Types[ast.Unparen(e.Fun)]
		if tv.IsType() && !types.IsInterface(tv.Type) && len(e.Args) == 1 && !e.Ellipsis.IsValid() {
			return isTypedNilNonInterfaceExpr(info, e.Args[0])
		}
		return false
	default:
		return false
	}
}

// isCarrierEmptySlotStore reports whether expr produces a value for slotType
// whose every dynamic-carrier or function-signature slot is provably nil/zero
// (and contains no sync.noCopy value).
func isCarrierEmptySlotStore(audited bool, info *types.Info, slotType types.Type, expr ast.Expr) bool {
	if info == nil || slotType == nil || expr == nil {
		return false
	}
	if refconfine.TypeReachesSyncNoCopyByValue(slotType) {
		return false
	}
	if !refconfine.TypeMayCarryUnknownDynamic(audited, slotType) && !refconfine.TypeCarriesSignature(slotType) {
		return true
	}
	if types.IsInterface(slotType) {
		return isNilInterfaceValueExpr(info, expr)
	}
	if isTypedNilNonInterfaceExpr(info, expr) {
		return true
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		b := syntaxutil.LookupBuiltin(info, ast.Unparen(e.Fun))
		if b == nil {
			return false
		}
		switch b.Name() {
		case "make":
			return len(e.Args) >= 1 && info.Types[ast.Unparen(e.Args[0])].IsType()
		case "new":
			return syntaxutil.IsBuiltinNewType(info, e)
		default:
			return false
		}
	case *ast.CompositeLit:
		switch u := types.Unalias(slotType).Underlying().(type) {
		case *types.Struct:
			if len(e.Elts) == 0 {
				return true
			}
			if _, keyed := e.Elts[0].(*ast.KeyValueExpr); keyed {
				for _, elt := range e.Elts {
					kv, ok := elt.(*ast.KeyValueExpr)
					if !ok {
						return false
					}
					keyID, ok := ast.Unparen(kv.Key).(*ast.Ident)
					if !ok {
						return false
					}
					fld, ok := info.Uses[keyID].(*types.Var)
					if !ok || fld == nil || !fld.IsField() {
						return false
					}
					if !isCarrierEmptySlotStore(audited, info, fld.Type(), kv.Value) {
						return false
					}
				}
				return true
			}
			if len(e.Elts) != u.NumFields() {
				return false
			}
			for i, elt := range e.Elts {
				if !isCarrierEmptySlotStore(audited, info, u.Field(i).Type(), elt) {
					return false
				}
			}
			return true
		case *types.Array, *types.Slice:
			elemT := u.(interface{ Elem() types.Type }).Elem()
			for _, elt := range e.Elts {
				val := elt
				if kv, ok := elt.(*ast.KeyValueExpr); ok {
					val = kv.Value
				}
				if !isCarrierEmptySlotStore(audited, info, elemT, val) {
					return false
				}
			}
			return true
		case *types.Map:
			for _, elt := range e.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					return false
				}
				if !isCarrierEmptySlotStore(audited, info, u.Key(), kv.Key) || !isCarrierEmptySlotStore(audited, info, u.Elem(), kv.Value) {
					return false
				}
			}
			return true
		default:
			return false
		}
	default:
		return false
	}
}
