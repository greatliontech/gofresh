package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// IsEmptyMapInitValue reports whether val lowers an empty map allocation
// (make(map[K]V), make(map[K]V, cap), or map[K]V{}).
func IsEmptyMapInitValue(val *flowir.Value) bool {
	if val == nil || val.Type == nil {
		return false
	}
	if _, ok := types.Unalias(val.Type).Underlying().(*types.Map); !ok {
		return false
	}
	if val.Kind != flowir.ValAllocFresh {
		return false
	}
	switch val.AllocKind {
	case flowir.AllocMake:
		return true
	case flowir.AllocCompositeLit:
		return len(val.CompositeElts) == 0
	default:
		return false
	}
}

// MutexMapConfig configures VerifyMutexConfinedMap.
type MutexMapConfig struct {
	AllowNilLazyInit     bool
	AllowIntraPkgHelpers bool
	RequireEntryParamKey bool
	RequireAtLeastOneSet bool
	KeyPred              func(types.Type) bool
}

// VerifiedMutexMap describes a verified mutex-guarded package-scope map and its
// entry/helper function cone.
type VerifiedMutexMap struct {
	MutexVar      *types.Var
	IsRWMutex     bool
	EntryFunc     *types.Func
	EntryDecl     *ast.FuncDecl
	EntryBody     *flowir.Body
	EntryRegions  *BodyLockRegions
	ConeDecls     map[*ast.FuncDecl]bool
	ConeFuncs     map[*types.Func]bool
	StoredValues  []*flowir.Value
	LookedUpLocal map[*types.Var]bool
}

// VerifyMutexConfinedMap mechanically verifies over flowir that mapVar is an
// unexported single-definition package-scope map guarded exclusively by a
// dedicated unexported single-definition sync.Mutex or sync.RWMutex in a single
// entry function (and, when AllowIntraPkgHelpers is set, its write-locked
// exclusive intra-package helper cone).
func VerifyMutexConfinedMap(
	p *packages.Package,
	idx *PkgIndex,
	mapVar *types.Var,
	cfg MutexMapConfig,
) (*VerifiedMutexMap, bool) {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || mapVar == nil {
		return nil, false
	}
	if mapVar.Exported() || mapVar.IsField() || mapVar.Parent() != p.Types.Scope() || idx.DefCounts[mapVar] != 1 {
		return nil, false
	}
	mapT, isMap := types.Unalias(mapVar.Type()).Underlying().(*types.Map)
	if !isMap {
		return nil, false
	}
	if cfg.KeyPred != nil && !cfg.KeyPred(mapT.Key()) {
		return nil, false
	}
	if len(idx.UsesOf[mapVar]) == 0 {
		return nil, false
	}

	fc := idx.FlowCache(p)
	if fc == nil {
		return nil, false
	}

	vs := idx.VarSpecs[mapVar]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) > 1 {
		return nil, false
	}
	if len(vs.Values) == 0 {
		if !cfg.AllowNilLazyInit {
			return nil, false
		}
	} else {
		initVal := fc.ExprValue(vs.Values[0])
		if initVal == nil {
			return nil, false
		}
		if initVal.IsNil {
			if !cfg.AllowNilLazyInit {
				return nil, false
			}
		} else if !IsEmptyMapInitValue(initVal) {
			return nil, false
		}
	}

	// Collect candidate dedicated package-scope mutexes in p.Types.
	type muCandidate struct {
		v         *types.Var
		isRWMutex bool
		entryFD   *ast.FuncDecl
		entryFn   *types.Func
	}
	var muCands []muCandidate
	for _, name := range p.Types.Scope().Names() {
		v, ok := p.Types.Scope().Lookup(name).(*types.Var)
		if !ok || v == nil || v.Exported() || idx.DefCounts[v] != 1 {
			continue
		}
		rw := syntaxutil.IsNamedInPkg(v.Type(), "sync", "RWMutex")
		plain := syntaxutil.IsNamedInPkg(v.Type(), "sync", "Mutex")
		if !rw && !plain {
			continue
		}
		uses := idx.UsesOf[v]
		if len(uses) == 0 {
			continue
		}
		if mvs := idx.VarSpecs[v]; mvs != nil {
			if len(mvs.Names) != 1 || len(mvs.Values) > 1 {
				continue
			}
			if len(mvs.Values) == 1 {
				mvInit := fc.ExprValue(mvs.Values[0])
				if mvInit == nil || mvInit.Kind != flowir.ValAllocFresh || mvInit.AllocKind != flowir.AllocCompositeLit || len(mvInit.CompositeElts) != 0 {
					continue
				}
			}
		}
		var fd *ast.FuncDecl
		allSync := true
		for _, uid := range uses {
			encl := idx.SyncEnclFuncDecl(uid)
			if encl == nil || encl.Body == nil || (encl.Recv == nil && encl.Name != nil && encl.Name.Name == "init") {
				allSync = false
				break
			}
			if fd == nil {
				fd = encl
			} else if fd != encl {
				allSync = false
				break
			}
		}
		if !allSync || fd == nil || fd.Name == nil {
			continue
		}
		fnObj, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
		if fnObj == nil {
			continue
		}
		if sig, ok := fnObj.Type().(*types.Signature); !ok || sig.TypeParams().Len() > 0 {
			continue
		}
		muCands = append(muCands, muCandidate{v: v, isRWMutex: rw, entryFD: fd, entryFn: fnObj})
	}

	for _, cand := range muCands {
		entryBody := fc.FuncBody(cand.entryFD)
		if entryBody == nil {
			continue
		}
		regions, okReg := VerifyBodyLockRegions(p, idx, entryBody, LockTarget{
			Kind:      LockPkgGlobalVar,
			MutexVar:  cand.v,
			IsRWMutex: cand.isRWMutex,
		})
		if !okReg {
			continue
		}

		coneFDs := map[*ast.FuncDecl]bool{cand.entryFD: true}
		coneFns := map[*types.Func]bool{cand.entryFn: true}
		if cfg.AllowIntraPkgHelpers {
			helpers := ComputeExclusiveHelperCone(p, idx, cand.entryFn)
			for hf := range helpers {
				if hfd := idx.FuncDecls[hf]; hfd != nil && hfd.Body != nil {
					if sig, ok := hf.Type().(*types.Signature); !ok || sig.TypeParams().Len() > 0 {
						continue
					}
					coneFDs[hfd] = true
					coneFns[hf] = true
				}
			}
		}

		allMapUsesInCone := true
		for _, uid := range idx.UsesOf[mapVar] {
			encl := idx.SyncEnclFuncDecl(uid)
			if !coneFDs[encl] {
				allMapUsesInCone = false
				break
			}
		}
		if !allMapUsesInCone {
			continue
		}

		// Verify all calls from entryBody into helper coneFns happen synchronously
		// while holding a write lock, and no helper calls entryFn or uses goto.
		helpersOK := true
		if len(coneFns) > 1 {
			entryBody.ForEachSyncOp(func(op *flowir.Op) bool {
				mode, hasMode := regions.OpModes[op]
				if !hasMode {
					helpersOK = false
					return false
				}
				op.ForEachValue(func(v *flowir.Value) bool {
					if v == nil {
						return true
					}
					v.WalkValues(func(cur *flowir.Value) bool {
						switch cur.Kind {
						case flowir.ValMakeClosure:
							if bodyCallsAnyFunc(cur.Closure, coneFns) {
								helpersOK = false
								return false
							}
						case flowir.ValCall:
							if cur.CallKind == flowir.CallIIFE && bodyCallsAnyFunc(cur.IIFE, coneFns) {
								helpersOK = false
								return false
							}
							if cur.CalleeFunc != nil && cur.CalleeFunc != cand.entryFn && coneFns[cur.CalleeFunc] {
								if op.Kind == flowir.OpDefer || op.Kind == flowir.OpGo || !mode.IsWriteLocked() {
									helpersOK = false
									return false
								}
							}
						}
						return true
					})
					return helpersOK
				})
				return helpersOK
			})
			for hf := range coneFns {
				if hf == cand.entryFn {
					continue
				}
				hb := fc.FuncBody(idx.FuncDecls[hf])
				if hb == nil || bodyHasGotoOrCallsEntry(hb, cand.entryFn) {
					helpersOK = false
					break
				}
			}
		}
		if !helpersOK {
			continue
		}

		var entryKeyParam *types.Var
		if cfg.RequireEntryParamKey {
			sig, ok := cand.entryFn.Type().(*types.Signature)
			if !ok || sig.Recv() != nil || sig.Params().Len() != 1 {
				continue
			}
			entryKeyParam = sig.Params().At(0)
			if cfg.KeyPred != nil && !cfg.KeyPred(entryKeyParam.Type()) {
				continue
			}
			if bodyWritesOrAddrsVar(entryBody, entryKeyParam) {
				continue
			}
		}

		var storedVals []*flowir.Value
		lookedUpLocals := map[*types.Var]bool{}
		mapOpsOK := true
		for fd := range coneFDs {
			b := fc.FuncBody(fd)
			if b == nil {
				mapOpsOK = false
				break
			}
			if !verifyMapOpsInBody(b, fd == cand.entryFD, regions, mapVar, entryKeyParam, cfg, &storedVals, lookedUpLocals) {
				mapOpsOK = false
				break
			}
		}
		if !mapOpsOK {
			continue
		}
		if cfg.RequireAtLeastOneSet && len(storedVals) == 0 {
			continue
		}

		// Close lookedUpLocals transitively across mutable-ref local aliases/projections/conversions
		// across the cone and verify zero interior mutations, mutating builtins, address-takes,
		// or mutable-ref call escapes.
		for changed := true; changed; {
			changed = false
			for fd := range coneFDs {
				if closeLookedUpLocalAliases(fc.FuncBody(fd), lookedUpLocals) {
					changed = true
				}
			}
		}
		for fd := range coneFDs {
			if bodyMutatesInteriorOrAddrsVars(fc.FuncBody(fd), lookedUpLocals) {
				mapOpsOK = false
				break
			}
		}
		if !mapOpsOK {
			continue
		}

		return &VerifiedMutexMap{
			MutexVar:      cand.v,
			IsRWMutex:     cand.isRWMutex,
			EntryFunc:     cand.entryFn,
			EntryDecl:     cand.entryFD,
			EntryBody:     entryBody,
			EntryRegions:  regions,
			ConeDecls:     coneFDs,
			ConeFuncs:     coneFns,
			StoredValues:  storedVals,
			LookedUpLocal: lookedUpLocals,
		}, true
	}
	return nil, false
}

func verifyMapOpsInBody(
	b *flowir.Body,
	isEntry bool,
	regions *BodyLockRegions,
	mapVar *types.Var,
	entryKeyParam *types.Var,
	cfg MutexMapConfig,
	storedVals *[]*flowir.Value,
	lookedUpLocals map[*types.Var]bool,
) bool {
	totalMentions := countVarMentionsInBody(b, mapVar)
	if totalMentions == 0 {
		return true
	}

	validKeyVal := func(kv *flowir.Value) bool {
		if kv == nil || kv.Type == nil {
			return false
		}
		if cfg.RequireEntryParamKey {
			return isEntry && kv.Kind == flowir.ValPlace && kv.Place.IsBareVar() && kv.Place.Obj == entryKeyParam
		}
		return cfg.KeyPred == nil || cfg.KeyPred(kv.Type)
	}

	// Track verified nil-guard IfStmts (`if mapVar == nil { mapVar = make(...) }`) when AllowNilLazyInit is set.
	nilGuardBlocks := map[*ast.IfStmt]bool{}

	validMentions := 0
	opsOK := true
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		mode := LockWriteHeld
		if isEntry {
			var hasMode bool
			mode, hasMode = regions.OpModes[op]
			if !hasMode {
				opsOK = false
				return false
			}
		}

		switch op.Kind {
		case flowir.OpExpr:
			// Nil guard condition `if mapVar == nil { ... }`
			if cfg.AllowNilLazyInit && op.Expr != nil && op.Expr.Kind == flowir.ValCompare && op.Expr.CompareOp == token.EQL {
				if ifs, isIf := op.StmtAST.(*ast.IfStmt); isIf &&
					ifs.Init == nil && ifs.Else == nil && ifs.Body != nil && len(ifs.Body.List) == 1 &&
					op.Expr.Raw != nil && ifs.Cond != nil && ast.Unparen(op.Expr.Raw) == ast.Unparen(ifs.Cond) {
					if (isBareVarValue(op.Expr.Left, mapVar) && op.Expr.Right != nil && op.Expr.Right.IsNil) ||
						(isBareVarValue(op.Expr.Right, mapVar) && op.Expr.Left != nil && op.Expr.Left.IsNil) {
						if !mode.IsWriteLocked() {
							opsOK = false
							return false
						}
						nilGuardBlocks[ifs] = true
						validMentions++
						return true
					}
				}
			}

		case flowir.OpAssign:
			switch op.AssignKind {
			case flowir.AssignPlain:
				if len(op.Dsts) == 1 && len(op.Srcs) == 1 && op.Srcs[0] != nil {
					dst := op.Dsts[0]
					src := op.Srcs[0]
					// Case 1: Lazy init `mapVar = make(map[K]V)` inside `if mapVar == nil { ... }`
					if cfg.AllowNilLazyInit && dst.IsBareVar() && dst.Obj == mapVar {
						if mode.IsWriteLocked() && IsEmptyMapInitValue(src) && stmtInNilGuardIf(b.Block, nilGuardBlocks, op.StmtAST) {
							validMentions++
							return true
						}
						opsOK = false
						return false
					}
					// Case 2: Map store `mapVar[k] = val`
					if dst.Obj == mapVar && len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjIndex {
						if !mode.IsWriteLocked() || !validKeyVal(dst.Projs[0].Key) {
							opsOK = false
							return false
						}
						validMentions++
						*storedVals = append(*storedVals, src)
						return true
					}
					// Case 3: Single-value map lookup `v := mapVar[k]`
					if dst.IsBareVar() && dst.Root == flowir.RootLocal && dst.Obj != nil &&
						src.Kind == flowir.ValPlace && src.Place.Obj == mapVar &&
						len(src.Place.Projs) == 1 && src.Place.Projs[0].Kind == flowir.ProjIndex {
						if !mode.IsReadOrWriteLocked() || !validKeyVal(src.Place.Projs[0].Key) {
							opsOK = false
							return false
						}
						validMentions++
						lookedUpLocals[dst.Obj] = true
						return true
					}
				}

			case flowir.AssignMulti:
				// Case 4: Comma-ok map lookup `v, ok := mapVar[k]`
				if len(op.Dsts) == 2 && len(op.Srcs) == 1 && op.Srcs[0] != nil {
					dst0, dst1 := op.Dsts[0], op.Dsts[1]
					src := op.Srcs[0]
					if (dst0.IsBlank() || (dst0.IsBareVar() && dst0.Root == flowir.RootLocal)) &&
						(dst1.IsBlank() || (dst1.IsBareVar() && dst1.Root == flowir.RootLocal)) &&
						src.Kind == flowir.ValPlace && src.Place.Obj == mapVar &&
						len(src.Place.Projs) == 1 && src.Place.Projs[0].Kind == flowir.ProjIndex {
						if !mode.IsReadOrWriteLocked() || !validKeyVal(src.Place.Projs[0].Key) {
							opsOK = false
							return false
						}
						validMentions++
						if dst0.Obj != nil {
							lookedUpLocals[dst0.Obj] = true
						}
						return true
					}
				}
			}
		}
		return true
	})
	return opsOK && validMentions == totalMentions
}

func stmtInNilGuardIf(root *ast.BlockStmt, nilGuardIfs map[*ast.IfStmt]bool, target ast.Node) bool {
	if root == nil || target == nil || len(nilGuardIfs) == 0 {
		return false
	}
	for ifs := range nilGuardIfs {
		if len(ifs.Body.List) == 1 && ifs.Body.List[0] == target {
			return true
		}
	}
	return false
}

func isBareVarValue(v *flowir.Value, target *types.Var) bool {
	return v != nil && v.Kind == flowir.ValPlace && v.Place.IsBareVar() && v.Place.Obj == target
}

func countVarMentionsInBody(b *flowir.Body, target *types.Var) int {
	if b == nil || target == nil {
		return 0
	}
	n := 0
	var walkBody func(cur *flowir.Body)
	walkVal := func(v *flowir.Value) {
		if v == nil {
			return
		}
		v.WalkValues(func(cv *flowir.Value) bool {
			switch cv.Kind {
			case flowir.ValPlace:
				if cv.Place.Obj == target {
					n++
				}
			case flowir.ValAddrOf:
				if cv.AddrPlace.Obj == target {
					n++
				}
			case flowir.ValMethodVal:
				if cv.HasRecvPlace && cv.RecvPlace.Obj == target {
					n++
				}
			case flowir.ValCall:
				if cv.CallKind == flowir.CallIIFE && cv.IIFE != nil {
					walkBody(cv.IIFE)
				}
			case flowir.ValMakeClosure:
				if cv.Closure != nil {
					walkBody(cv.Closure)
				}
			}
			return true
		})
	}
	walkBody = func(cur *flowir.Body) {
		if cur == nil {
			return
		}
		for i := range cur.Ops {
			op := &cur.Ops[i]
			switch op.Kind {
			case flowir.OpAssign:
				for _, dst := range op.Dsts {
					if dst.Obj == target {
						n++
					}
				}
			case flowir.OpChanSend:
				if op.ChanPlace.Obj == target {
					n++
				}
			}
			op.ForEachValue(func(v *flowir.Value) bool {
				walkVal(v)
				return true
			})
			if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
				walkBody(op.RangeBody)
			}
		}
	}
	walkBody(b)
	return n
}

func bodyCallsAnyFunc(b *flowir.Body, targets map[*types.Func]bool) bool {
	if b == nil || len(targets) == 0 {
		return false
	}
	hit := false
	var walkBody func(cur *flowir.Body)
	walkVal := func(v *flowir.Value) {
		if v == nil || hit {
			return
		}
		v.WalkValues(func(cv *flowir.Value) bool {
			if hit {
				return false
			}
			switch cv.Kind {
			case flowir.ValCall:
				if cv.CalleeFunc != nil && targets[cv.CalleeFunc] {
					hit = true
					return false
				}
				if cv.CallKind == flowir.CallIIFE && cv.IIFE != nil {
					walkBody(cv.IIFE)
				}
			case flowir.ValMakeClosure:
				if cv.Closure != nil {
					walkBody(cv.Closure)
				}
			}
			return !hit
		})
	}
	walkBody = func(cur *flowir.Body) {
		if cur == nil || hit {
			return
		}
		for i := range cur.Ops {
			op := &cur.Ops[i]
			op.ForEachValue(func(v *flowir.Value) bool {
				walkVal(v)
				return !hit
			})
			if !hit && op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
				walkBody(op.RangeBody)
			}
		}
	}
	walkBody(b)
	return hit
}

func bodyHasGotoOrCallsEntry(b *flowir.Body, entryFn *types.Func) bool {
	if b == nil || b.HasGoto {
		return true
	}
	return entryFn != nil && bodyCallsAnyFunc(b, map[*types.Func]bool{entryFn: true})
}

func bodyWritesOrAddrsVar(b *flowir.Body, target *types.Var) bool {
	if b == nil || target == nil {
		return false
	}
	return bodyChecksVars(b, map[*types.Var]bool{target: true}, true)
}

func bodyMutatesInteriorOrAddrsVars(b *flowir.Body, targets map[*types.Var]bool) bool {
	if b == nil || len(targets) == 0 {
		return false
	}
	return bodyChecksVars(b, targets, false)
}

func placeRootTouchesTargets(pl flowir.Place, targets map[*types.Var]bool) bool {
	if pl.Obj != nil && targets[pl.Obj] {
		return true
	}
	if pl.Root == flowir.RootTransient && pl.Base != nil {
		return valueCarriesTargets(pl.Base, targets)
	}
	return false
}

func valueCarriesTargets(v *flowir.Value, targets map[*types.Var]bool) bool {
	if v == nil || len(targets) == 0 || !TypeCarriesMutableRef(v.Type) {
		return false
	}
	switch v.Kind {
	case flowir.ValPlace:
		return placeRootTouchesTargets(v.Place, targets)
	case flowir.ValConvert:
		return valueCarriesTargets(v.Arg, targets)
	case flowir.ValAddrOf:
		return placeRootTouchesTargets(v.AddrPlace, targets)
	case flowir.ValMethodVal:
		return v.HasRecvPlace && placeRootTouchesTargets(v.RecvPlace, targets)
	case flowir.ValAllocFresh:
		for i := range v.CompositeElts {
			if valueCarriesTargets(v.CompositeElts[i].MapKey, targets) || valueCarriesTargets(v.CompositeElts[i].Value, targets) {
				return true
			}
		}
		for _, a := range v.Args {
			if valueCarriesTargets(a, targets) {
				return true
			}
		}
	case flowir.ValCall:
		if v.CallKind == flowir.CallIIFE && v.IIFE != nil {
			hit := false
			v.IIFE.ForEachSyncOp(func(op *flowir.Op) bool {
				if op.Kind == flowir.OpReturn {
					for _, r := range op.Results {
						if valueCarriesTargets(r, targets) {
							hit = true
							return false
						}
					}
				}
				return true
			})
			if hit {
				return true
			}
		}
		if valueCarriesTargets(v.Recv, targets) {
			return true
		}
		for _, a := range v.Args {
			if valueCarriesTargets(a, targets) {
				return true
			}
		}
	case flowir.ValMakeClosure:
		if v.Closure != nil {
			for fv := range v.Closure.FreeVars {
				if targets[fv] {
					return true
				}
			}
		}
	}
	return false
}

func closeLookedUpLocalAliases(b *flowir.Body, targets map[*types.Var]bool) bool {
	if b == nil || len(targets) == 0 {
		return false
	}
	changed := false
	var walkBody func(cur *flowir.Body)
	walkBody = func(cur *flowir.Body) {
		if cur == nil {
			return
		}
		for i := range cur.Ops {
			op := &cur.Ops[i]
			switch op.Kind {
			case flowir.OpAssign:
				switch op.AssignKind {
				case flowir.AssignPlain, flowir.AssignMulti:
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						if dst.IsBareVar() && dst.Obj != nil && !targets[dst.Obj] &&
							TypeCarriesMutableRef(dst.Type) && valueCarriesTargets(src, targets) {
							targets[dst.Obj] = true
							changed = true
						}
						return true
					})
				case flowir.AssignRange:
					if len(op.Srcs) == 1 && valueCarriesTargets(op.Srcs[0], targets) {
						for _, dst := range op.Dsts {
							if dst.IsBareVar() && dst.Obj != nil && !targets[dst.Obj] && TypeCarriesMutableRef(dst.Type) {
								targets[dst.Obj] = true
								changed = true
							}
						}
					}
					if op.RangeBody != nil {
						walkBody(op.RangeBody)
					}
				}
			case flowir.OpTypeSwitchBind:
				if op.SwitchDst != nil && !targets[op.SwitchDst] &&
					TypeCarriesMutableRef(op.SwitchDst.Type()) && valueCarriesTargets(op.SwitchSrc, targets) {
					targets[op.SwitchDst] = true
					changed = true
				}
			}
			op.ForEachValue(func(v *flowir.Value) bool {
				if v != nil {
					v.WalkValues(func(cv *flowir.Value) bool {
						if cv.Kind == flowir.ValCall && cv.CallKind == flowir.CallIIFE && cv.IIFE != nil {
							walkBody(cv.IIFE)
						} else if cv.Kind == flowir.ValMakeClosure && cv.Closure != nil {
							walkBody(cv.Closure)
						}
						return true
					})
				}
				return true
			})
		}
	}
	walkBody(b)
	return changed
}

func placeCrossesRefOrPointer(pl flowir.Place) bool {
	if pl.Root == flowir.RootTransient {
		return true
	}
	for _, pr := range pl.Projs {
		switch pr.Kind {
		case flowir.ProjDeref:
			return true
		case flowir.ProjField:
			if pr.Indirect {
				return true
			}
			if pr.BaseType != nil {
				if _, isPtr := types.Unalias(pr.BaseType).Underlying().(*types.Pointer); isPtr {
					return true
				}
			}
		case flowir.ProjIndex:
			if pr.BaseType != nil {
				switch types.Unalias(pr.BaseType).Underlying().(type) {
				case *types.Slice, *types.Map, *types.Pointer:
					return true
				}
			}
		case flowir.ProjSlice:
			if pr.BaseType != nil {
				switch types.Unalias(pr.BaseType).Underlying().(type) {
				case *types.Slice, *types.Pointer:
					return true
				}
			}
		}
	}
	return false
}

func bodyChecksVars(b *flowir.Body, targets map[*types.Var]bool, forbidBareAssign bool) bool {
	hit := false
	var walkBody func(cur *flowir.Body)
	walkVal := func(v *flowir.Value) {
		if v == nil || hit {
			return
		}
		v.WalkValues(func(cv *flowir.Value) bool {
			if hit {
				return false
			}
			switch cv.Kind {
			case flowir.ValAddrOf:
				if placeRootTouchesTargets(cv.AddrPlace, targets) {
					hit = true
					return false
				}
			case flowir.ValMethodVal:
				if cv.HasRecvPlace && placeRootTouchesTargets(cv.RecvPlace, targets) &&
					(cv.AutoAddr || (!forbidBareAssign && TypeCarriesMutableRef(cv.RecvPlace.Type))) {
					hit = true
					return false
				}
			case flowir.ValConvert:
				if !forbidBareAssign && syntaxutil.IsUnsafePointerType(cv.Type) && valueCarriesTargets(cv.Arg, targets) {
					hit = true
					return false
				}
			case flowir.ValCall:
				if cv.AutoAddrRecv && cv.HasRecvPlace && placeRootTouchesTargets(cv.RecvPlace, targets) {
					hit = true
					return false
				}
				if cv.CallKind == flowir.CallBuiltin {
					switch cv.BuiltinName {
					case "len", "cap":
					case "delete", "clear", "copy", "append":
						if len(cv.Args) > 0 && cv.Args[0] != nil &&
							((cv.Args[0].Kind == flowir.ValPlace && placeRootTouchesTargets(cv.Args[0].Place, targets)) ||
								valueCarriesTargets(cv.Args[0], targets)) {
							hit = true
							return false
						}
					default:
						// unsafe.SliceData, unsafe.Slice, etc.
						if !forbidBareAssign {
							for _, a := range cv.Args {
								if valueCarriesTargets(a, targets) {
									hit = true
									return false
								}
							}
						}
					}
				} else if !forbidBareAssign {
					if cv.Recv != nil && valueCarriesTargets(cv.Recv, targets) {
						hit = true
						return false
					}
					for _, a := range cv.Args {
						if valueCarriesTargets(a, targets) {
							hit = true
							return false
						}
					}
				}
				if cv.CallKind == flowir.CallIIFE && cv.IIFE != nil {
					walkBody(cv.IIFE)
				}
			case flowir.ValMakeClosure:
				if cv.Closure != nil {
					walkBody(cv.Closure)
				}
			}
			return !hit
		})
	}
	walkBody = func(cur *flowir.Body) {
		if cur == nil || hit {
			return
		}
		for i := range cur.Ops {
			op := &cur.Ops[i]
			switch op.Kind {
			case flowir.OpAssign:
				for di, dst := range op.Dsts {
					if !placeRootTouchesTargets(dst, targets) {
						continue
					}
					isDef := di < len(op.DstDefs) && op.DstDefs[di] && dst.IsBareVar()
					if forbidBareAssign {
						if !dst.IsBareVar() || !isDef {
							hit = true
							return
						}
					} else if !dst.IsBareVar() && placeCrossesRefOrPointer(dst) {
						hit = true
						return
					}
				}
			case flowir.OpChanSend:
				if placeRootTouchesTargets(op.ChanPlace, targets) || (!forbidBareAssign && valueCarriesTargets(op.SendVal, targets)) {
					hit = true
					return
				}
			}
			op.ForEachValue(func(v *flowir.Value) bool {
				walkVal(v)
				return !hit
			})
			if !hit && op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
				walkBody(op.RangeBody)
			}
		}
	}
	walkBody(b)
	return hit
}
