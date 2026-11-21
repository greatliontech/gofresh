package dynstate

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// deriveMemoDischarges mechanically verifies mutex-guarded reflect.Type
// structural memoizers whose computed entries are content-invariant and
// confined to unexported package internals (REQ-closure-shared-dynamic-state-memo).
func deriveMemoDischarges(ctx context.Context, audited bool, p *packages.Package, fc *pkgFlowCache, idx *refconfine.PkgIndex) []string {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil
	}
	if idx == nil {
		idx = refconfine.BuildPkgIndex(p)
	}
	if fc == nil {
		fc = newPkgFlowCacheWithIndex(audited, p, idx)
	}
	target := dynstateTarget(p)
	var out []string
	for _, name := range p.Types.Scope().Names() {
		v, ok := p.Types.Scope().Lookup(name).(*types.Var)
		if !ok || !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			continue
		}
		varKey := syntaxutil.DynamicVarKey(v)
		okMemo, reason := verifyMemoVarWithReason(audited, p, fc, idx, v)
		if okMemo {
			out = append(out, varKey)
		} else if reason != "not map[reflect.Type]..." {
			emitDischargeRejectAt(ctx, p, target, "memo", varKey, reason, "", v.Pos())
		}
	}
	sort.Strings(out)
	return out
}

func verifyMemoVar(audited bool, p *packages.Package, fc *pkgFlowCache, idx *refconfine.PkgIndex, mapVar *types.Var) bool {
	ok, _ := verifyMemoVarWithReason(audited, p, fc, idx, mapVar)
	return ok
}

func verifyMemoVarWithReason(audited bool, p *packages.Package, fc *pkgFlowCache, idx *refconfine.PkgIndex, mapVar *types.Var) (bool, string) {
	if mapVar == nil {
		return false, "not map[reflect.Type]..."
	}
	mt, ok := types.Unalias(mapVar.Type()).Underlying().(*types.Map)
	if !ok || !syntaxutil.IsNamedInPkg(mt.Key(), "reflect", "Type") {
		return false, "not map[reflect.Type]..."
	}
	if mapVar.Exported() || idx.DefCounts[mapVar] != 1 {
		return false, "nil, exported, or multi-def mapVar"
	}
	if !syntaxutil.IsTrueStdlibInPkg(p, "reflect") || !syntaxutil.IsTrueStdlibInPkg(p, "sync") {
		return false, "non-std reflect or sync"
	}
	if refconfine.TypeMayCarryUnknownDynamic(audited, mt.Elem()) {
		return false, "map elem carries unknown dynamic"
	}
	ptr, ok := types.Unalias(mt.Elem()).(*types.Pointer)
	if !ok {
		return false, "map elem not pointer"
	}
	infoNamed, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || infoNamed.Obj() == nil || infoNamed.Obj().Pkg() != p.Types || infoNamed.Obj().Exported() {
		return false, "map elem not unexported local named struct"
	}
	if _, ok := infoNamed.Underlying().(*types.Struct); !ok {
		return false, "map elem underlying not struct"
	}

	protectedStructs := map[*types.Named]bool{}
	if !collectProtectedMemoStructs(p, infoNamed, protectedStructs) {
		return false, "collectProtectedMemoStructs failed"
	}

	verified, ok := refconfine.VerifyMutexConfinedMap(p, idx, mapVar, refconfine.MutexMapConfig{
		AllowNilLazyInit:     false,
		AllowIntraPkgHelpers: true,
		RequireEntryParamKey: true,
		RequireAtLeastOneSet: true,
		KeyPred:              syntaxutil.IsReflectType,
	})
	if !ok || verified == nil || verified.EntryFunc == nil || verified.EntryDecl == nil || verified.EntryBody == nil {
		return false, "VerifyMutexConfinedMap failed"
	}

	memoSig, ok := verified.EntryFunc.Type().(*types.Signature)
	if !ok || memoSig.Results().Len() == 0 {
		return false, "memoSig missing results"
	}
	needsErrorProof := false
	for ri := 0; ri < memoSig.Results().Len(); ri++ {
		rt := memoSig.Results().At(ri).Type()
		if isUniverseErrorType(rt) {
			needsErrorProof = true
			continue
		}
		if refconfine.TypeMayCarryUnknownDynamic(audited, rt) {
			return false, "memoSig result carries unknown dynamic"
		}
	}

	if okConf, r := verifyProtectedMemoStructConfinement(p, idx, verified.EntryDecl, protectedStructs); !okConf {
		return false, "confinement: " + r
	}

	allowedGlobals := map[*types.Var]bool{}
	checkedGlobals := map[*types.Var]bool{}
	allowGlobal := func(gv *types.Var) bool {
		if gv == nil || gv.Pkg() != p.Types || gv.IsField() || gv.Parent() != p.Types.Scope() {
			return false
		}
		if gv == mapVar || gv == verified.MutexVar {
			return true
		}
		if checkedGlobals[gv] {
			return allowedGlobals[gv]
		}
		checkedGlobals[gv] = true
		okG := isInitOnlyReflectTypeGlobal(p, fc, idx, gv) ||
			verifyReadOnlyCarrierFreeGlobalVar(audited, p, fc, idx, gv, nil, true)
		allowedGlobals[gv] = okG
		return okG
	}

	isMuCall := func(call *flowir.Value) bool {
		if call == nil || call.Kind != flowir.ValCall || call.CallKind != flowir.CallMethod ||
			call.IsMethodExprCall || len(call.Args) != 0 || call.Ellipsis ||
			call.CalleePkg != "sync" || call.CalleeFunc == nil ||
			!call.HasRecvPlace || !call.RecvPlace.IsBareVar() || call.RecvPlace.Obj != verified.MutexVar {
			return false
		}
		switch call.CalleeFunc.Name() {
		case "Lock", "Unlock", "RLock", "RUnlock":
			return true
		default:
			return false
		}
	}

	coneFuncs, localClosures, sawErrorSink, okCone := verifyDeterministicComputeCone(
		p,
		fc,
		idx,
		idx.FuncDecls,
		memoSig,
		verified.EntryBody,
		conePolicy{
			audited:                audited,
			allowMapRange:          false,
			allowReflectTypeValues: true,
			allowRecursiveSelf:     verified.EntryFunc,
			allowedGlobalRead:      allowGlobal,
			isExemptPkgGlobalWrite: func(_ *flowir.Op, dst flowir.Place) bool { return dst.Obj == mapVar },
			isExemptCall:           isMuCall,
		},
	)
	if !okCone {
		return false, "compute cone failed"
	}

	if needsErrorProof || sawErrorSink {
		if !verifyFlowIRErrorOrigins(
			p,
			fc,
			memoSig,
			verified.EntryBody,
			coneFuncs,
			localClosures,
			errorOriginConfig{
				trustedErrCallees:      map[*types.Func]bool{verified.EntryFunc: true},
				allowReflectTypeValues: true,
			},
		) {
			return false, "error origins failed"
		}
	}

	if okBody, r := verifyMemoProtectedAndPostStoreFlowIR(p, fc, memoSig, infoNamed, protectedStructs, mapVar, verified, coneFuncs, localClosures); !okBody {
		return false, "body: " + r
	}
	return true, ""
}

func verifyMemoProtectedAndPostStoreFlowIR(
	p *packages.Package,
	fc *pkgFlowCache,
	memoSig *types.Signature,
	infoNamed *types.Named,
	protected map[*types.Named]bool,
	mapVar *types.Var,
	verified *refconfine.VerifiedMutexMap,
	coneFuncs map[*types.Func]*ast.FuncDecl,
	localClosures map[*types.Var]*flowir.Body,
) (bool, string) {
	if okEq, r := verifyMemoGetOrComputeEquivalence(p, fc, memoSig, infoNamed, mapVar, verified, coneFuncs); !okEq {
		return false, r
	}

	// Check protected struct immutability & field confinement across entryBody, coneFuncs, and localClosures.
	bodies := make([]*flowir.Body, 0, 1+len(coneFuncs)+len(localClosures))
	bodies = append(bodies, verified.EntryBody)
	for _, fd := range coneFuncs {
		if b := fc.funcBody(p, fd); b != nil {
			bodies = append(bodies, b)
		}
	}
	for _, cb := range localClosures {
		if cb != nil {
			bodies = append(bodies, cb)
		}
	}
	for _, b := range bodies {
		if reason := checkMemoBodyProtectedSafetyFlowIR(b, protected); reason != "" {
			return false, reason
		}
	}
	return true, ""
}

func verifyHelperReturnsFreshNonNilInfo(
	p *packages.Package,
	fc *pkgFlowCache,
	infoNamed *types.Named,
	fd *ast.FuncDecl,
	isFreshOrigin func(*flowir.Value) bool,
) bool {
	if fd == nil || fd.Name == nil || p == nil || p.TypesInfo == nil {
		return false
	}
	fnObj, _ := p.TypesInfo.Defs[fd.Name].(*types.Func)
	if fnObj == nil {
		return false
	}
	sig, ok := fnObj.Type().(*types.Signature)
	if !ok || sig.Recv() != nil || (sig.Results().Len() != 1 && sig.Results().Len() != 2) {
		return false
	}
	if !syntaxutil.IsPtrToNamed(sig.Results().At(0).Type(), infoNamed) {
		return false
	}
	hasErr := sig.Results().Len() == 2
	if hasErr && !isUniverseErrorType(sig.Results().At(1).Type()) {
		return false
	}
	b := fc.funcBody(p, fd)
	if b == nil {
		return false
	}
	helperAddrTaken, helperClosureHazard := scanMemoBodyClosureAndAddrHazards(b, nil)
	if helperClosureHazard {
		return false
	}
	hasBadCtrl := b.HasDefer || b.HasGo || b.HasGoto
	freshLocals := map[*types.Var]bool{}
	badLocal := map[*types.Var]bool{}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if hasBadCtrl {
			return false
		}
		if op.Kind != flowir.OpAssign {
			return true
		}
		if op.AssignKind == flowir.AssignZeroDecl {
			for _, dst := range op.Dsts {
				if dst.Obj != nil {
					badLocal[dst.Obj] = true
				}
			}
			return true
		}
		for di, dst := range op.Dsts {
			if dst.Obj == nil {
				continue
			}
			if !dst.IsBareVar() || dst.Root != flowir.RootLocal || helperAddrTaken[dst.Obj] ||
				op.AssignKind != flowir.AssignPlain || di >= len(op.Srcs) || !isFreshOrigin(op.Srcs[di]) {
				badLocal[dst.Obj] = true
				delete(freshLocals, dst.Obj)
				continue
			}
			if !badLocal[dst.Obj] {
				freshLocals[dst.Obj] = true
			}
		}
		return true
	})

	sawFreshReturn := false
	returnsOK := true
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind != flowir.OpReturn {
			return true
		}
		if op.IsNaked || len(op.Results) != sig.Results().Len() {
			returnsOK = false
			return false
		}
		if hasErr && op.Results[1] != nil && !op.Results[1].IsNil {
			if op.Results[0] == nil || !op.Results[0].IsNil {
				returnsOK = false
				return false
			}
			return true
		}
		if hasErr && (op.Results[1] == nil || !op.Results[1].IsNil) {
			returnsOK = false
			return false
		}
		r0 := op.Results[0]
		if isFreshOrigin(r0) || (r0 != nil && r0.Kind == flowir.ValPlace && r0.Place.IsBareVar() && freshLocals[r0.Place.Obj] && !badLocal[r0.Place.Obj]) {
			sawFreshReturn = true
			return true
		}
		returnsOK = false
		return false
	})
	return !hasBadCtrl && returnsOK && sawFreshReturn
}

func scanMemoBodyClosureAndAddrHazards(rootBody *flowir.Body, mapVar *types.Var) (map[*types.Var]bool, bool) {
	addrTaken := map[*types.Var]bool{}
	hazard := false
	var walkBody func(b *flowir.Body, inClosure bool)
	walkBody = func(b *flowir.Body, inClosure bool) {
		if b == nil || hazard {
			return
		}
		b.ForEachSyncOp(func(op *flowir.Op) bool {
			if hazard {
				return false
			}
			if inClosure && (op.Kind == flowir.OpAssign || op.Kind == flowir.OpTypeSwitchBind) {
				for _, dst := range op.Dsts {
					if dst.Root == flowir.RootOuterVar || (mapVar != nil && dst.Obj == mapVar) {
						hazard = true
						return false
					}
				}
			}
			op.ForEachValue(func(val *flowir.Value) bool {
				if val == nil || hazard {
					return !hazard
				}
				val.WalkValues(func(cur *flowir.Value) bool {
					if hazard || cur == nil {
						return false
					}
					switch cur.Kind {
					case flowir.ValAddrOf:
						if !cur.IsArraySlice && len(cur.AddrPlace.Projs) == 0 && cur.AddrPlace.Obj != nil {
							if inClosure && cur.AddrPlace.Root == flowir.RootOuterVar {
								hazard = true
								return false
							}
							if !inClosure && cur.AddrPlace.Root == flowir.RootLocal {
								addrTaken[cur.AddrPlace.Obj] = true
							}
						}
					case flowir.ValMethodVal:
						if cur.AutoAddr && cur.HasRecvPlace && len(cur.RecvPlace.Projs) == 0 && cur.RecvPlace.Obj != nil {
							if inClosure && cur.RecvPlace.Root == flowir.RootOuterVar {
								hazard = true
								return false
							}
							if !inClosure && cur.RecvPlace.Root == flowir.RootLocal {
								addrTaken[cur.RecvPlace.Obj] = true
							}
						}
					case flowir.ValCall:
						if cur.AutoAddrRecv && cur.HasRecvPlace && len(cur.RecvPlace.Projs) == 0 && cur.RecvPlace.Obj != nil {
							if inClosure && cur.RecvPlace.Root == flowir.RootOuterVar {
								hazard = true
								return false
							}
							if !inClosure && cur.RecvPlace.Root == flowir.RootLocal {
								addrTaken[cur.RecvPlace.Obj] = true
							}
						}
						if cur.IIFE != nil {
							walkBody(cur.IIFE, true)
						}
					case flowir.ValMakeClosure:
						if cur.Closure != nil {
							walkBody(cur.Closure, true)
						}
					}
					return !hazard
				})
				return !hazard
			})
			return !hazard
		})
	}
	walkBody(rootBody, false)
	return addrTaken, hazard
}

func invalidateLoopWrittenFreshVars(p *packages.Package, loopNode ast.Node, cur *memoFlowState) {
	if p == nil || p.TypesInfo == nil || loopNode == nil || len(cur.freshVars) == 0 {
		return
	}
	dropExprRoot := func(e ast.Expr) {
		if e == nil {
			return
		}
		if id, ok := ast.Unparen(e).(*ast.Ident); ok {
			if v, okU := p.TypesInfo.Uses[id].(*types.Var); okU && v != nil {
				delete(cur.freshVars, v)
			}
			if v, okD := p.TypesInfo.Defs[id].(*types.Var); okD && v != nil {
				delete(cur.freshVars, v)
			}
		}
	}
	ast.Inspect(loopNode, func(n ast.Node) bool {
		if len(cur.freshVars) == 0 || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				dropExprRoot(lhs)
			}
		case *ast.IncDecStmt:
			dropExprRoot(x.X)
		case *ast.RangeStmt:
			dropExprRoot(x.Key)
			dropExprRoot(x.Value)
		case *ast.ValueSpec:
			for _, nm := range x.Names {
				if nm != nil {
					dropExprRoot(nm)
				}
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				dropExprRoot(x.X)
			}
		}
		return true
	})
}

func checkMemoBodyProtectedSafetyFlowIR(b *flowir.Body, protected map[*types.Named]bool) string {
	reason := ""
	checkVal := func(v *flowir.Value, allowDirectProtectedSliceRange bool) {
		if v == nil || reason != "" {
			return
		}
		consumedProtectedFieldVals := map[*flowir.Value]bool{}
		if allowDirectProtectedSliceRange && isProtectedPtrRefFieldPlace(v, protected, false) {
			consumedProtectedFieldVals[v] = true
		}

		v.WalkValues(func(cur *flowir.Value) bool {
			if reason != "" {
				return false
			}
			switch cur.Kind {
			case flowir.ValAddrOf:
				if placeTouchesProtectedStruct(cur.AddrPlace, protected) {
					reason = "addr of or inside protected"
					return false
				}
			case flowir.ValCall:
				if cur.CallKind == flowir.CallBuiltin && len(cur.Args) > 0 && cur.Args[0] != nil {
					switch cur.BuiltinName {
					case "len", "cap":
						if len(cur.Args) == 1 && !cur.Ellipsis && isProtectedPtrRefFieldPlace(cur.Args[0], protected, true) {
							consumedProtectedFieldVals[cur.Args[0]] = true
						}
					case "delete", "clear", "copy", "append":
						if valueHitsProtectedStruct(cur.Args[0], protected) {
							reason = "call mutates protected container"
							return false
						}
					}
				}
			case flowir.ValPlace:
				if !consumedProtectedFieldVals[cur] && placeReadsProtectedPtrRefField(cur.Place, protected) {
					reason = "ref field selector on protected ptr"
					return false
				}
			}
			return reason == ""
		})
	}

	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if reason != "" {
			return false
		}
		switch op.Kind {
		case flowir.OpAssign:
			for _, dst := range op.Dsts {
				if placeMutatesPublishedProtected(dst, protected) {
					reason = "assign mutates published protected"
					return false
				}
				dst.ForEachChildValue(func(cv *flowir.Value) bool {
					checkVal(cv, false)
					return reason == ""
				})
				if reason != "" {
					return false
				}
			}
			isRange := op.AssignKind == flowir.AssignRange
			for _, src := range op.Srcs {
				checkVal(src, isRange)
				if reason != "" {
					return false
				}
			}
		case flowir.OpReturn:
			for _, r := range op.Results {
				checkVal(r, false)
				if reason != "" {
					return false
				}
			}
		case flowir.OpTypeSwitchBind:
			checkVal(op.SwitchSrc, false)
		case flowir.OpExpr:
			checkVal(op.Expr, false)
		case flowir.OpDefer, flowir.OpGo:
			checkVal(op.Call, false)
		case flowir.OpChanSend:
			checkVal(op.ChanVal, false)
			checkVal(op.SendVal, false)
		}
		return reason == ""
	})
	return reason
}

func placeTouchesProtectedStruct(pl flowir.Place, protected map[*types.Named]bool) bool {
	if st := syntaxutil.DerefNamedStruct(pl.Type); st != nil && protected[st.Origin()] {
		return true
	}
	if pl.Obj != nil {
		if st := syntaxutil.DerefNamedStruct(pl.Obj.Type()); st != nil && protected[st.Origin()] {
			return true
		}
	}
	for _, pr := range pl.Projs {
		if st := syntaxutil.DerefNamedStruct(pr.BaseType); st != nil && protected[st.Origin()] {
			return true
		}
		if st := syntaxutil.DerefNamedStruct(pr.Type); st != nil && protected[st.Origin()] {
			return true
		}
	}
	return false
}

func valueHitsProtectedStruct(v *flowir.Value, protected map[*types.Named]bool) bool {
	if v == nil {
		return false
	}
	if st := syntaxutil.DerefNamedStruct(v.Type); st != nil && protected[st.Origin()] {
		return true
	}
	hit := false
	v.WalkValues(func(cur *flowir.Value) bool {
		if cur.Kind == flowir.ValPlace && placeTouchesProtectedStruct(cur.Place, protected) {
			hit = true
			return false
		}
		return true
	})
	return hit
}

func isProtectedPtrRefFieldPlace(v *flowir.Value, protected map[*types.Named]bool, allowMap bool) bool {
	if v == nil || v.Kind != flowir.ValPlace || len(v.Place.Projs) == 0 {
		return false
	}
	last := v.Place.Projs[len(v.Place.Projs)-1]
	if last.Kind != flowir.ProjField || last.Selection == nil || !isPtrToAnyProtected(last.Selection.Recv(), protected) {
		return false
	}
	// Ensure no earlier projection step also read an unconsumed *protected map/slice field.
	for i := 0; i < len(v.Place.Projs)-1; i++ {
		pr := v.Place.Projs[i]
		if pr.Kind == flowir.ProjField && pr.Selection != nil && isPtrToAnyProtected(pr.Selection.Recv(), protected) {
			switch types.Unalias(pr.Type).Underlying().(type) {
			case *types.Map, *types.Slice:
				return false
			}
		}
	}
	switch types.Unalias(last.Type).Underlying().(type) {
	case *types.Slice:
		return true
	case *types.Map:
		return allowMap
	default:
		return false
	}
}

func placeReadsProtectedPtrRefField(pl flowir.Place, protected map[*types.Named]bool) bool {
	for _, pr := range pl.Projs {
		if pr.Kind == flowir.ProjField && pr.Selection != nil && isPtrToAnyProtected(pr.Selection.Recv(), protected) {
			switch types.Unalias(pr.Type).Underlying().(type) {
			case *types.Map, *types.Slice:
				return true
			}
		}
	}
	return false
}

func placeMutatesPublishedProtected(dst flowir.Place, protected map[*types.Named]bool) bool {
	for _, pr := range dst.Projs {
		switch pr.Kind {
		case flowir.ProjDeref:
			if st := syntaxutil.DerefNamedStruct(pr.BaseType); st != nil && protected[st.Origin()] {
				return true
			}
		case flowir.ProjField:
			if pr.Selection != nil {
				if isPtrToAnyProtected(pr.Selection.Recv(), protected) || syntaxutil.SelectionCrossesEmbeddedPointer(pr.Selection) {
					return true
				}
			} else if isPtrToAnyProtected(pr.BaseType, protected) {
				return true
			}
		}
	}
	return false
}

func collectProtectedMemoStructs(p *packages.Package, root *types.Named, out map[*types.Named]bool) bool {
	seen := map[types.Type]bool{}
	ok := true
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || !ok {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if n, isNamed := t.(*types.Named); isNamed && n.Obj() != nil {
			if _, isSt := n.Underlying().(*types.Struct); isSt {
				if n.Obj().Pkg() != p.Types || n.Obj().Exported() {
					ok = false
					return
				}
				out[n] = true
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			elem := types.Unalias(u.Elem())
			elemNamed, isEN := elem.(*types.Named)
			if !isEN || elemNamed.Obj() == nil || elemNamed.Obj().Pkg() != p.Types || elemNamed.Obj().Exported() {
				ok = false
				return
			}
			if _, isSt := elemNamed.Underlying().(*types.Struct); !isSt {
				ok = false
				return
			}
			walk(elem)
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Struct:
			if _, isNamed := t.(*types.Named); !isNamed && u.NumFields() > 0 {
				ok = false
				return
			}
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Chan, *types.Interface, *types.Signature, *types.TypeParam:
			ok = false
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				ok = false
			}
		}
	}
	walk(root)
	return ok
}

func verifyProtectedMemoStructConfinement(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	memoFD *ast.FuncDecl,
	protected map[*types.Named]bool,
) (bool, string) {
	isProtectedPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		st, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && protected[st.Origin()]
	}
	return refconfine.VerifyProtectedStructOriginConfinement(p, idx, memoFD, protected, func(call *ast.CallExpr, argIdx int, arg ast.Expr) bool {
		if len(call.Args) != 1 || argIdx != 0 || call.Ellipsis.IsValid() {
			return false
		}
		sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSel || sel.Sel == nil {
			return false
		}
		fn, isFn := p.TypesInfo.Uses[sel.Sel].(*types.Func)
		if !isFn || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" {
			return false
		}
		if fn.Name() != "FieldByIndex" && fn.Name() != "FieldByIndexErr" {
			return false
		}
		sl, isSl := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(arg)).(*types.Slice)
		return isSl && !refconfine.TypeContainsRefOrPointerWith(sl.Elem(), isProtectedPtr)
	})
}

func isInitOnlyReflectTypeGlobal(p *packages.Package, fc *pkgFlowCache, idx *refconfine.PkgIndex, v *types.Var) bool {
	if v == nil || v.Exported() || idx.DefCounts[v] != 1 || !syntaxutil.IsNamedInPkg(v.Type(), "reflect", "Type") {
		return false
	}
	if vs := idx.VarSpecs[v]; vs != nil && len(vs.Values) > 0 {
		return false
	}
	st := fc.varWriteInfos(p)[v]
	if st == nil || st.Defs != 1 || !st.HasZeroDecl || st.HasNonPlainDef ||
		st.HasExplicitAddr || st.HasAutoAddrMethod || st.HasBuiltinMut || st.HasChanSend {
		return false
	}

	wroteInInit := false
	valid := true
	checkBody := func(b *flowir.Body, isTopInit bool) {
		if b == nil || !valid {
			return
		}
		var walk func(cur *flowir.Body, syncInit bool)
		walk = func(cur *flowir.Body, syncInit bool) {
			if cur == nil || !valid {
				return
			}
			for i := range cur.Ops {
				op := &cur.Ops[i]
				if op.Kind == flowir.OpAssign {
					for di, dst := range op.Dsts {
						touches := dst.Obj == v
						if !touches {
							flowir.ForEachPlaceRootVar(dst, func(rv *types.Var) {
								if rv == v {
									touches = true
								}
							})
						}
						if !touches {
							continue
						}
						if !syncInit || !dst.IsBareVar() || op.AssignKind != flowir.AssignPlain ||
							di >= len(op.Srcs) || !isPureReflectTypeDerivationFlowIR(p, op.Srcs[di]) {
							valid = false
							return
						}
						wroteInInit = true
					}
					if op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
						walk(op.RangeBody, syncInit)
					}
				}
				op.ForEachValue(func(val *flowir.Value) bool {
					if val == nil {
						return true
					}
					val.WalkValues(func(cv *flowir.Value) bool {
						if cv.Kind == flowir.ValMakeClosure && cv.Closure != nil {
							walk(cv.Closure, false)
						} else if cv.Kind == flowir.ValCall && cv.CallKind == flowir.CallIIFE && cv.IIFE != nil {
							walk(cv.IIFE, false)
						}
						return valid
					})
					return valid
				})
				if !valid {
					return
				}
			}
		}
		walk(b, isTopInit)
	}

	for _, gd := range fc.base.GenDecls {
		if b := fc.body(p, gd); b != nil {
			// Skip v's own zero declaration op; reject any write to v inside another package spec.
			for i := range b.Ops {
				op := &b.Ops[i]
				if op.Kind == flowir.OpAssign && op.AssignKind != flowir.AssignZeroDecl {
					for _, dst := range op.Dsts {
						if dst.Obj == v {
							return false
						}
					}
				}
			}
		}
	}
	for _, fd := range fc.base.FuncDecls {
		isInit := fd != nil && fd.Recv == nil && fd.Name != nil && fd.Name.Name == "init"
		checkBody(fc.funcBody(p, fd), isInit)
		if !valid {
			return false
		}
	}
	return valid && wroteInInit
}

func isPureReflectTypeDerivationFlowIR(p *packages.Package, val *flowir.Value) bool {
	if val == nil || val.Kind != flowir.ValCall {
		return false
	}
	valid := true
	sawReflectTypeQuery := false
	val.WalkValues(func(cur *flowir.Value) bool {
		if !valid {
			return false
		}
		switch cur.Kind {
		case flowir.ValInvalid, flowir.ValMakeClosure, flowir.ValChanRecv, flowir.ValMethodVal:
			valid = false
			return false
		case flowir.ValPlace:
			if cur.Place.Root == flowir.RootPkgGlobal {
				valid = false
				return false
			}
		case flowir.ValAddrOf:
			if placeTouchesPkgGlobal(p, cur.AddrPlace) {
				valid = false
				return false
			}
		case flowir.ValConvert:
			if cur.IsTypeAssert || syntaxutil.IsUnsafePointerType(cur.Type) {
				valid = false
				return false
			}
		case flowir.ValCall:
			if cur.CallKind == flowir.CallIIFE || cur.CallKind == flowir.CallIndirect || cur.IsMethodExprCall ||
				cur.CalleeFunc == nil || cur.CalleeFunc.Pkg() == nil || cur.CalleeFunc.Pkg().Path() != "reflect" ||
				!isTrueStdlibInPkg(p, "reflect") {
				valid = false
				return false
			}
			switch cur.CalleeFunc.Name() {
			case "TypeOf", "Type", "PtrTo", "PointerTo":
				sawReflectTypeQuery = true
			case "ValueOf", "Elem", "Zero":
			default:
				valid = false
				return false
			}
		}
		return valid
	})
	return valid && sawReflectTypeQuery
}

func isPtrToAnyProtected(t types.Type, protected map[*types.Named]bool) bool {
	if t == nil {
		return false
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	st := syntaxutil.DerefNamedStruct(ptr.Elem())
	return st != nil && protected[st.Origin()]
}
