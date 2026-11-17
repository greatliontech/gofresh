package dynstate

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

type varWriteInfo struct {
	defs              int
	initVal           *flowir.Value
	hasZeroDecl       bool
	hasNonPlainDef    bool
	hasPostDefWrite   bool
	hasChanSend       bool
	hasExplicitAddr   bool
	hasAutoAddrMethod bool
	hasBuiltinMut     bool
}

// pkgFlowCache caches lowered flowir.Body representations, lowered expression
// nodes, scoped local memory-alias graphs, and single-write variable summaries
// across all dynamic-state passes on a single package so each declaration in
// p.Syntax is lowered at most once.
type pkgFlowCache struct {
	audited bool
	base    *flowir.PkgCache

	localCarrierAliases map[*flowir.Body]map[types.Object]map[types.Object]bool
	interiorAliases     map[*flowir.Body]map[types.Object]map[types.Object]bool

	varWritesReady bool
	varWrites      map[*types.Var]*varWriteInfo

	declLowerCount int
	missCount      int
}

func newPkgFlowCache(audited bool, p *packages.Package) *pkgFlowCache {
	return newPkgFlowCacheWithIndex(audited, p, nil)
}

func newPkgFlowCacheWithIndex(audited bool, p *packages.Package, idx *refconfine.PkgIndex) *pkgFlowCache {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	var base *flowir.PkgCache
	if idx != nil {
		base = idx.FlowCache(p)
	} else {
		base = flowir.NewPkgCache(p.TypesInfo, p.Types, p.Syntax)
	}
	if base == nil {
		return nil
	}
	return &pkgFlowCache{
		audited:             audited,
		base:                base,
		localCarrierAliases: make(map[*flowir.Body]map[types.Object]map[types.Object]bool),
		interiorAliases:     make(map[*flowir.Body]map[types.Object]map[types.Object]bool),
		declLowerCount:      base.DeclLowerCount,
		missCount:           base.MissCount,
	}
}

func (fc *pkgFlowCache) attachToIndex(idx *refconfine.PkgIndex) {
	if fc != nil && fc.base != nil && idx != nil {
		idx.SetFlowCache(fc.base)
	}
}

func (fc *pkgFlowCache) syncStats() {
	if fc != nil && fc.base != nil {
		fc.declLowerCount = fc.base.DeclLowerCount
		fc.missCount = fc.base.MissCount
	}
}

func (fc *pkgFlowCache) scopeBody(p *packages.Package, enclosing ast.Node) *flowir.Body {
	switch n := enclosing.(type) {
	case nil:
		return nil
	case *ast.FuncDecl:
		return fc.funcBody(p, n)
	case *ast.FuncLit:
		return fc.litBody(p, n)
	default:
		return fc.body(p, n)
	}
}

func (fc *pkgFlowCache) body(p *packages.Package, node ast.Node) *flowir.Body {
	if node == nil {
		return nil
	}
	if fc != nil && fc.base != nil {
		b := fc.base.Body(node)
		fc.syncStats()
		return b
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	return flowir.LowerNode(p.TypesInfo, p.Types, node)
}

func (fc *pkgFlowCache) funcBody(p *packages.Package, fd *ast.FuncDecl) *flowir.Body {
	if fd == nil || fd.Body == nil {
		return nil
	}
	if fc != nil && fc.base != nil {
		b := fc.base.FuncBody(fd)
		fc.syncStats()
		return b
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	return flowir.LowerFunc(p.TypesInfo, p.Types, fd)
}

func (fc *pkgFlowCache) litBody(p *packages.Package, lit *ast.FuncLit) *flowir.Body {
	if lit == nil || lit.Body == nil {
		return nil
	}
	if fc != nil && fc.base != nil {
		b := fc.base.LitBody(lit)
		fc.syncStats()
		return b
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	return flowir.LowerFuncLit(p.TypesInfo, p.Types, lit)
}

func (fc *pkgFlowCache) exprValue(p *packages.Package, expr ast.Expr) *flowir.Value {
	if expr == nil {
		return nil
	}
	if fc != nil && fc.base != nil {
		return fc.base.ExprValue(expr)
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	b := flowir.LowerNode(p.TypesInfo, p.Types, expr)
	if b == nil || len(b.Ops) != 1 || b.Ops[0].Kind != flowir.OpExpr {
		return nil
	}
	return b.Ops[0].Expr
}

func (fc *pkgFlowCache) scopedLocalCarrierAliases(audited bool, b *flowir.Body, allowObj func(types.Object) bool) map[types.Object]map[types.Object]bool {
	if b == nil {
		return nil
	}
	shares := func(t types.Type) bool {
		return canAliasCarrierType(audited, t)
	}
	if allowObj != nil {
		return flowir.BuildScopedMemAliases(b, allowObj, shares)
	}
	if fc != nil && fc.audited == audited {
		if adj, ok := fc.localCarrierAliases[b]; ok {
			return adj
		}
	}
	adj := flowir.BuildScopedMemAliases(b, syntaxutil.IsLocalVar, shares)
	if fc != nil && fc.audited == audited {
		fc.localCarrierAliases[b] = adj
	}
	return adj
}

func (fc *pkgFlowCache) scopedBodyInteriorAliases(audited bool, b *flowir.Body, exclude map[types.Object]bool) map[types.Object]map[types.Object]bool {
	if b == nil {
		return nil
	}
	shares := sharesMemOrSigOrDynamic(audited)
	hasInteriorExclude := false
	for r := range exclude {
		if v, ok := r.(*types.Var); ok && v != nil && !v.IsField() && !isPkgOrOuterToBody(b, v) {
			hasInteriorExclude = true
			break
		}
	}
	if hasInteriorExclude {
		return flowir.BuildScopedMemAliases(
			b,
			func(obj types.Object) bool {
				v, ok := obj.(*types.Var)
				return ok && v != nil && !v.IsField() && !exclude[v] && !isPkgOrOuterToBody(b, v)
			},
			shares,
		)
	}
	if fc != nil && fc.audited == audited {
		if adj, ok := fc.interiorAliases[b]; ok {
			return adj
		}
	}
	adj := flowir.BuildScopedMemAliases(
		b,
		func(obj types.Object) bool {
			v, ok := obj.(*types.Var)
			return ok && v != nil && !v.IsField() && !isPkgOrOuterToBody(b, v)
		},
		shares,
	)
	if fc != nil && fc.audited == audited {
		fc.interiorAliases[b] = adj
	}
	return adj
}

func (fc *pkgFlowCache) ensureVarWriteInfos(p *packages.Package) map[*types.Var]*varWriteInfo {
	if fc == nil {
		if p == nil || p.TypesInfo == nil {
			return nil
		}
		fc = newPkgFlowCache(false, p)
		if fc == nil {
			return nil
		}
	}
	if fc.varWritesReady {
		return fc.varWrites
	}
	fc.varWritesReady = true
	fc.varWrites = make(map[*types.Var]*varWriteInfo)
	if fc.base == nil {
		return fc.varWrites
	}
	var pkgScope *types.Scope
	if fc.base.Pkg != nil {
		pkgScope = fc.base.Pkg.Scope()
	}
	entry := func(v *types.Var) *varWriteInfo {
		if v == nil || v.IsField() {
			return nil
		}
		st := fc.varWrites[v]
		if st == nil {
			st = &varWriteInfo{}
			fc.varWrites[v] = st
		}
		return st
	}

	markPlace := func(pl flowir.Place, fn func(*varWriteInfo)) {
		forEachPlaceRootVar(pl, func(rv *types.Var) {
			if st := entry(rv); st != nil {
				fn(st)
			}
		})
	}
	markValue := func(val *flowir.Value, fn func(*varWriteInfo)) {
		forEachValueRootVar(val, func(rv *types.Var) {
			if st := entry(rv); st != nil {
				fn(st)
			}
		})
	}

	var scanBody func(b *flowir.Body, topGenDecl bool)
	scanVal := func(v *flowir.Value) {
		if v == nil {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			switch cur.Kind {
			case flowir.ValAddrOf:
				markPlace(cur.AddrPlace, func(st *varWriteInfo) { st.hasExplicitAddr = true })
			case flowir.ValMethodVal:
				if cur.AutoAddr && cur.HasRecvPlace {
					markPlace(cur.RecvPlace, func(st *varWriteInfo) { st.hasAutoAddrMethod = true })
				}
			case flowir.ValCall:
				if cur.AutoAddrRecv && cur.HasRecvPlace {
					markPlace(cur.RecvPlace, func(st *varWriteInfo) { st.hasAutoAddrMethod = true })
				}
				if cur.CallKind == flowir.CallBuiltin && len(cur.Args) > 0 && cur.Args[0] != nil {
					switch cur.BuiltinName {
					case "delete", "clear", "copy", "append":
						markValue(cur.Args[0], func(st *varWriteInfo) { st.hasBuiltinMut = true })
					}
				}
				if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil {
					scanBody(cur.IIFE, false)
				}
			case flowir.ValMakeClosure:
				if cur.Closure != nil {
					scanBody(cur.Closure, false)
				}
			}
			return true
		})
	}

	scanBody = func(b *flowir.Body, topGenDecl bool) {
		if b == nil {
			return
		}
		for i := range b.Ops {
			op := &b.Ops[i]
			op.ForEachValue(func(v *flowir.Value) bool {
				scanVal(v)
				return true
			})
			switch op.Kind {
			case flowir.OpAssign:
				op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
					if dst.Obj == nil {
						markPlace(dst, func(st *varWriteInfo) { st.hasPostDefWrite = true })
						return true
					}
					st := entry(dst.Obj)
					if st == nil {
						return true
					}
					isOwnScopeDef := isDef && dst.IsBareVar() &&
						((topGenDecl && pkgScope != nil && dst.Obj.Parent() == pkgScope) ||
							(!topGenDecl && (pkgScope == nil || dst.Obj.Parent() != pkgScope)))
					if isOwnScopeDef {
						switch op.AssignKind {
						case flowir.AssignPlain:
							if src != nil {
								st.defs++
								st.initVal = src
							} else {
								st.hasPostDefWrite = true
							}
						case flowir.AssignZeroDecl:
							st.defs++
							st.hasZeroDecl = true
						case flowir.AssignMulti, flowir.AssignRange:
							st.defs++
							st.hasNonPlainDef = true
						default:
							st.hasPostDefWrite = true
						}
					} else {
						st.hasPostDefWrite = true
					}
					return true
				})
				if op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
					scanBody(op.RangeBody, false)
				}
			case flowir.OpTypeSwitchBind:
				if st := entry(op.SwitchDst); st != nil {
					st.defs++
					st.hasNonPlainDef = true
				}
			case flowir.OpChanSend:
				if op.ChanVal != nil {
					markValue(op.ChanVal, func(st *varWriteInfo) { st.hasChanSend = true })
				} else {
					markPlace(op.ChanPlace, func(st *varWriteInfo) { st.hasChanSend = true })
				}
			}
		}
	}

	for _, gd := range fc.base.GenDecls {
		scanBody(fc.base.Body(gd), true)
	}
	for _, fd := range fc.base.FuncDecls {
		scanBody(fc.base.FuncBody(fd), false)
	}
	// Also count package-scope const definitions so shadowed/ill-typed const+var collisions fail closed.
	if fc.base != nil && fc.base.Info != nil {
		for _, obj := range fc.base.Info.Defs {
			if v, ok := obj.(*types.Var); ok && v != nil && !v.IsField() {
				if st := fc.varWrites[v]; st == nil {
					fc.varWrites[v] = &varWriteInfo{}
				}
			}
		}
	}
	return fc.varWrites
}

// singleWritePkgGlobalInit returns (initVal, true) when gv is a package-scope
// variable defined by a single plain initializer in p with zero subsequent
// writes, interior projection writes, mutating container builtins, channel
// sends, or explicit/implicit address-takes anywhere in p.
func (fc *pkgFlowCache) singleWritePkgGlobalInit(p *packages.Package, gv *types.Var) (*flowir.Value, bool) {
	if gv == nil || p == nil || p.Types == nil || gv.Pkg() != p.Types || gv.Parent() != p.Types.Scope() {
		return nil, false
	}
	st := fc.ensureVarWriteInfos(p)[gv]
	if st == nil || st.defs != 1 || st.initVal == nil || st.hasZeroDecl || st.hasNonPlainDef ||
		st.hasPostDefWrite || st.hasChanSend || st.hasExplicitAddr || st.hasAutoAddrMethod || st.hasBuiltinMut {
		return nil, false
	}
	return st.initVal, true
}

// singleWriteLocalInit returns (initVal, true) when lv is a non-parameter,
// non-receiver, non-result local variable owned by fnBody and defined by a
// single plain initializer with zero subsequent writes, mutating container
// builtins, channel sends, or explicit/implicit address-takes.
func (fc *pkgFlowCache) singleWriteLocalInit(p *packages.Package, fnBody *flowir.Body, lv *types.Var) (*flowir.Value, bool) {
	if fnBody == nil || lv == nil || !fnBody.OwnsVar(lv) || lv == fnBody.Recv || fnBody.ResultSet[lv] {
		return nil, false
	}
	if _, isParam := fnBody.ParamIndex[lv]; isParam {
		return nil, false
	}
	st := fc.ensureVarWriteInfos(p)[lv]
	if st == nil || st.defs != 1 || st.initVal == nil || st.hasZeroDecl || st.hasNonPlainDef ||
		st.hasPostDefWrite || st.hasChanSend || st.hasExplicitAddr || st.hasAutoAddrMethod || st.hasBuiltinMut {
		return nil, false
	}
	return st.initVal, true
}

// varHasExplicitWriteOrAddr reports whether v (a package-scope or local
// variable) lacks a single plain/zero definition or undergoes any
// post-definition write, projection write, channel send, mutating container
// builtin (delete/clear/copy/append), or explicit/implicit address-take.
func (fc *pkgFlowCache) varHasExplicitWriteOrAddr(p *packages.Package, v *types.Var) bool {
	if v == nil {
		return true
	}
	st := fc.ensureVarWriteInfos(p)[v]
	if st == nil {
		return true
	}
	return st.defs != 1 || st.hasNonPlainDef || st.hasPostDefWrite || st.hasChanSend ||
		st.hasExplicitAddr || st.hasAutoAddrMethod || st.hasBuiltinMut
}

func forEachPlaceRootVar(pl flowir.Place, fn func(*types.Var)) {
	if pl.Obj != nil {
		fn(pl.Obj)
		return
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil {
		forEachValueRootVar(pl.Base, fn)
	}
}

func forEachValueRootVar(v *flowir.Value, fn func(*types.Var)) {
	for v != nil {
		switch v.Kind {
		case flowir.ValConvert:
			if !v.IsTypeAssert && v.Arg != nil && v.Arg.Type != nil {
				if b, ok := v.Arg.Type.Underlying().(*types.Basic); ok && b.Info()&types.IsString != 0 {
					return
				}
			}
			v = v.Arg
		case flowir.ValPlace:
			forEachPlaceRootVar(v.Place, fn)
			return
		case flowir.ValAddrOf:
			forEachPlaceRootVar(v.AddrPlace, fn)
			return
		default:
			return
		}
	}
}
