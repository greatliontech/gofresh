package dynstate

import (
	"context"
	"go/ast"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// deriveMappingDischarges mechanically verifies package-level virtual-memory
// mapping bookkeeping structures (REQ-closure-shared-dynamic-state-mapping).
func deriveMappingDischarges(ctx context.Context, audited bool, p *packages.Package, fc *pkgFlowCache, idx *refconfine.PkgIndex) []string {
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
		okMap, reason := verifyMappingVarWithReason(audited, p, fc, idx, v)
		if okMap {
			out = append(out, varKey)
		} else if reason != "not_mapping_candidate" {
			emitDischargeRejectAt(ctx, p, target, "mapping", varKey, reason, "", v.Pos())
		}
	}
	sort.Strings(out)
	return out
}

func verifyMappingVar(audited bool, p *packages.Package, fc *pkgFlowCache, idx *refconfine.PkgIndex, v *types.Var) bool {
	ok, _ := verifyMappingVarWithReason(audited, p, fc, idx, v)
	return ok
}

func pkgImportsPath(p *packages.Package, path string) bool {
	if p == nil {
		return false
	}
	if p.Imports[path] != nil {
		return true
	}
	if p.Types != nil {
		for _, ip := range p.Types.Imports() {
			if ip != nil && ip.Path() == path {
				return true
			}
		}
	}
	return false
}

func verifyMappingVarWithReason(audited bool, p *packages.Package, fc *pkgFlowCache, idx *refconfine.PkgIndex, v *types.Var) (bool, string) {
	if v == nil || v.Exported() || idx.DefCounts[v] != 1 {
		return false, "not_mapping_candidate"
	}
	ptr, ok := types.Unalias(v.Type()).(*types.Pointer)
	if !ok {
		return false, "not_mapping_candidate"
	}
	outerNamed, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || outerNamed.Obj() == nil || outerNamed.Obj().Pkg() != p.Types || outerNamed.Obj().Exported() {
		return false, "not_mapping_candidate"
	}
	outerStruct, ok := outerNamed.Underlying().(*types.Struct)
	if !ok {
		return false, "not_mapping_candidate"
	}
	if !pkgImportsPath(p, "syscall") {
		return false, "not_mapping_candidate"
	}
	if !syntaxutil.IsTrueStdlibInPkg(p, "sync") || !syntaxutil.IsTrueStdlibInPkg(p, "syscall") {
		return false, "non_std_sync_or_syscall"
	}

	var baseNamed *types.Named
	var baseStruct *types.Struct
	var baseField *types.Var
	var mutexField *types.Var
	var activeField *types.Var
	callableFields := map[*types.Var]*types.Signature{}
	hasAddrCallable := false
	hasUnmapCallable := false

	scanStructFields := func(st *types.Struct, allowEmbeddedMapper bool) bool {
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f.Embedded() && syntaxutil.IsNamedInPkg(f.Type(), "sync", "Mutex") {
				if mutexField != nil {
					return false
				}
				mutexField = f
				continue
			}
			if f.Exported() {
				return false
			}
			if f.Embedded() {
				if !allowEmbeddedMapper || baseNamed != nil {
					return false
				}
				bn, ok := types.Unalias(f.Type()).(*types.Named)
				if !ok || bn.Obj() == nil || bn.Obj().Pkg() != p.Types || bn.Obj().Exported() {
					return false
				}
				bs, ok := bn.Underlying().(*types.Struct)
				if !ok {
					return false
				}
				baseNamed = bn
				baseStruct = bs
				baseField = f
				continue
			}
			if isBytePtrByteSliceMap(f.Type()) {
				if activeField != nil {
					return false
				}
				activeField = f
				continue
			}
			sig, ok := types.Unalias(f.Type()).(*types.Signature)
			if !ok {
				return false
			}
			isAddr, isUnmap, valid := classifyMapperCallableSig(audited, sig)
			if !valid {
				return false
			}
			if isAddr {
				hasAddrCallable = true
			}
			if isUnmap {
				hasUnmapCallable = true
			}
			callableFields[f] = sig
		}
		return true
	}

	if !scanStructFields(outerStruct, true) {
		return false, "invalid_mapper_struct_fields"
	}
	if baseStruct != nil && !scanStructFields(baseStruct, false) {
		return false, "invalid_mapper_struct_fields"
	}
	if mutexField == nil || activeField == nil || !hasAddrCallable || !hasUnmapCallable || len(callableFields) == 0 {
		return false, "missing_mutex_or_active_or_callables"
	}
	if len(idx.UsesOf[mutexField]) > 0 {
		return false, "direct_mutex_field_use"
	}

	// Verify single &S{...} composite literal initializer and bound syscall targets via flowir.
	initVal, ok := fc.singleWritePkgGlobalInit(p, v)
	if !ok || initVal == nil || !syntaxutil.IsPtrToNamed(initVal.Type, outerNamed) {
		return false, "non_single_composite_init"
	}
	initKeyIdents := map[*ast.Ident]bool{}
	boundTargets := map[*types.Var]*types.Func{}
	activeInitialized := false
	if !verifyMapperInitValueFlowIR(p, initVal, outerNamed, baseNamed, baseField, activeField, callableFields, initKeyIdents, boundTargets, &activeInitialized) {
		return false, "init_value_invalid"
	}
	if !activeInitialized || len(boundTargets) != len(callableFields) {
		return false, "uninitialized_active_or_callable"
	}
	if baseField != nil {
		for _, id := range idx.UsesOf[baseField] {
			if !initKeyIdents[id] {
				return false, "escaped_base_field"
			}
		}
	}
	for _, targetFn := range boundTargets {
		if !verifyMapperSyscallTargetFlowIR(p, fc, idx, targetFn) {
			return false, "syscall_target_invalid"
		}
	}

	// Reject any whole-struct dereference write *x = ... on outerNamed or baseNamed across flowir bodies.
	if pkgHasStructDerefWriteFlowIR(p, fc, outerNamed, baseNamed) {
		return false, "whole_struct_deref_write"
	}

	// Collect all methods declared on outerNamed and baseNamed.
	allowedMethods := map[*types.Func]*ast.FuncDecl{}
	for _, tn := range []*types.Named{outerNamed, baseNamed} {
		if tn == nil {
			continue
		}
		for i := 0; i < tn.NumMethods(); i++ {
			m := tn.Method(i)
			fd := idx.FuncDecls[m]
			if fd == nil || fd.Body == nil {
				return false, "bodyless_method"
			}
			if !verifyMapperMethodSignatureAndReturnsFlowIR(audited, p, fc, fd, m, callableFields) {
				return false, "method_signature_or_return_invalid"
			}
			allowedMethods[m] = fd
		}
	}

	// Verify every use of v: receiver of allowedMethods call or direct call of callableFields.
	for _, id := range idx.UsesOf[v] {
		sel, ok := idx.ParentUnparen(id).(*ast.SelectorExpr)
		if !ok || ast.Unparen(sel.X) != id {
			return false, "var_use_unconfined"
		}
		call, ok := idx.ParentUnparen(sel).(*ast.CallExpr)
		if !ok || ast.Unparen(call.Fun) != sel {
			return false, "var_use_unconfined"
		}
		selInfo := p.TypesInfo.Selections[sel]
		if selInfo == nil {
			return false, "var_use_unconfined"
		}
		switch selInfo.Kind() {
		case types.MethodVal:
			fn, ok := selInfo.Obj().(*types.Func)
			if !ok || allowedMethods[fn] == nil {
				return false, "var_use_unconfined"
			}
		case types.FieldVal:
			fld, ok := selInfo.Obj().(*types.Var)
			if !ok || callableFields[fld] == nil {
				return false, "var_use_unconfined"
			}
		default:
			return false, "var_use_unconfined"
		}
	}

	// Verify every use of callableFields across the entire package: only init key or direct call.
	for cf := range callableFields {
		for _, id := range idx.UsesOf[cf] {
			if initKeyIdents[id] {
				continue
			}
			sel, ok := idx.ParentUnparen(id).(*ast.SelectorExpr)
			if !ok || sel.Sel != id {
				return false, "callable_field_use_unconfined"
			}
			call, ok := idx.ParentUnparen(sel).(*ast.CallExpr)
			if !ok || ast.Unparen(call.Fun) != sel {
				return false, "callable_field_use_unconfined"
			}
		}
	}

	// Verify every use of activeField occurs inside a verified locked method of outerNamed/baseNamed.
	activeMethods := map[*ast.FuncDecl]bool{}
	for _, id := range idx.UsesOf[activeField] {
		if initKeyIdents[id] {
			continue
		}
		fd := idx.SyncEnclFuncDecl(id)
		if fd == nil {
			return false, "active_field_outside_allowed_method"
		}
		fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
		if !ok || allowedMethods[fn] == nil {
			return false, "active_field_outside_allowed_method"
		}
		activeMethods[fd] = true
	}
	for fd := range activeMethods {
		if !verifyMapperActiveMethodBodyFlowIR(p, fc, idx, fd, outerNamed, baseNamed, mutexField, activeField, callableFields) {
			return false, "active_method_body_invalid"
		}
	}
	return true, ""
}

func classifyMapperCallableSig(audited bool, sig *types.Signature) (isAddr, isUnmap, valid bool) {
	if sig == nil || sig.TypeParams().Len() > 0 {
		return false, false, false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if refconfine.TypeMayCarryUnknownDynamic(audited, sig.Params().At(i).Type()) {
			return false, false, false
		}
	}
	res := sig.Results()
	switch res.Len() {
	case 1:
		if isUniverseErrorType(res.At(0).Type()) {
			return false, true, true
		}
	case 2:
		b, ok := types.Unalias(res.At(0).Type()).Underlying().(*types.Basic)
		if ok && b.Kind() == types.Uintptr && isUniverseErrorType(res.At(1).Type()) {
			return true, false, true
		}
	}
	return false, false, false
}

func verifyMapperMethodSignatureAndReturnsFlowIR(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	fd *ast.FuncDecl,
	fn *types.Func,
	callableFields map[*types.Var]*types.Signature,
) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.TypeParams().Len() > 0 {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if refconfine.TypeMayCarryUnknownDynamic(audited, sig.Params().At(i).Type()) {
			return false
		}
	}
	errSlot := -1
	for i := 0; i < sig.Results().Len(); i++ {
		rt := sig.Results().At(i).Type()
		if isUniverseErrorType(rt) {
			if errSlot != -1 {
				return false
			}
			errSlot = i
			continue
		}
		if refconfine.TypeMayCarryUnknownDynamic(audited, rt) {
			return false
		}
	}
	if errSlot == -1 {
		return true
	}

	b := fc.funcBody(p, fd)
	if b == nil {
		return false
	}

	cleanErrVars := map[*types.Var]bool{}
	dirtyErrVars := map[*types.Var]bool{}
	isCallableFieldCall := func(val *flowir.Value) bool {
		if val == nil || val.Kind != flowir.ValCall || val.CallKind != flowir.CallIndirect || val.Callee == nil {
			return false
		}
		if val.Callee.Kind != flowir.ValPlace || len(val.Callee.Place.Projs) == 0 {
			return false
		}
		last := val.Callee.Place.Projs[len(val.Callee.Place.Projs)-1]
		return last.Kind == flowir.ProjField && last.Field != nil && callableFields[last.Field] != nil
	}
	isCleanErrVal := func(val *flowir.Value) bool {
		if val == nil {
			return false
		}
		if val.IsNil || val.IsConst || val.Kind == flowir.ValScalarLitOrConst {
			return true
		}
		if isCallableFieldCall(val) {
			return true
		}
		if val.Kind == flowir.ValPlace {
			if val.Place.Root == flowir.RootConstOrNil {
				return true
			}
			if val.Place.IsBareVar() && val.Place.Obj != nil {
				if val.Place.Root == flowir.RootPkgGlobal {
					return !refconfine.TypeMayCarryUnknownDynamic(audited, val.Place.Obj.Type())
				}
				return cleanErrVars[val.Place.Obj] && !dirtyErrVars[val.Place.Obj]
			}
		}
		return val.Type != nil && !refconfine.TypeMayCarryUnknownDynamic(audited, val.Type)
	}

	var namedErrVar *types.Var
	if resVar := sig.Results().At(errSlot); resVar.Name() != "" && resVar.Name() != "_" {
		namedErrVar = resVar
	}

	okReturns := true
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if !okReturns {
			return false
		}
		op.ForEachValue(func(v *flowir.Value) bool {
			if v == nil {
				return true
			}
			v.WalkValues(func(cur *flowir.Value) bool {
				if cur.Kind == flowir.ValMakeClosure || (cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallIIFE) {
					okReturns = false
					return false
				}
				return true
			})
			return okReturns
		})
		if !okReturns {
			return false
		}

		switch op.Kind {
		case flowir.OpAssign:
			switch op.AssignKind {
			case flowir.AssignZeroDecl:
			case flowir.AssignMulti:
				if len(op.Srcs) == 1 && isCallableFieldCall(op.Srcs[0]) {
					for _, dst := range op.Dsts {
						if dst.IsBareVar() && dst.Obj != nil && isUniverseErrorType(dst.Obj.Type()) {
							cleanErrVars[dst.Obj] = true
						}
					}
					return true
				}
				for _, dst := range op.Dsts {
					if dst.IsBareVar() && dst.Obj != nil && isUniverseErrorType(dst.Obj.Type()) {
						dirtyErrVars[dst.Obj] = true
					}
				}
			case flowir.AssignPlain:
				for i, dst := range op.Dsts {
					if !dst.IsBareVar() || dst.Obj == nil || !isUniverseErrorType(dst.Obj.Type()) {
						continue
					}
					if i < len(op.Srcs) && isCleanErrVal(op.Srcs[i]) {
						cleanErrVars[dst.Obj] = true
					} else {
						dirtyErrVars[dst.Obj] = true
					}
				}
			default:
				for _, dst := range op.Dsts {
					if dst.Obj != nil && isUniverseErrorType(dst.Obj.Type()) {
						dirtyErrVars[dst.Obj] = true
					}
				}
			}
		case flowir.OpReturn:
			if len(op.Results) == 0 {
				if namedErrVar == nil || dirtyErrVars[namedErrVar] {
					okReturns = false
				}
				return okReturns
			}
			if len(op.Results) == 1 && sig.Results().Len() > 1 {
				if !isCleanErrVal(op.Results[0]) {
					okReturns = false
				}
				return okReturns
			}
			if errSlot >= len(op.Results) || !isCleanErrVal(op.Results[errSlot]) {
				okReturns = false
			}
		}
		return okReturns
	})
	return okReturns
}

func verifyMapperActiveMethodBodyFlowIR(
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	fd *ast.FuncDecl,
	outerNamed, baseNamed *types.Named,
	mutexField, activeField *types.Var,
	callableFields map[*types.Var]*types.Signature,
) bool {
	b := fc.funcBody(p, fd)
	if b == nil || b.Recv == nil {
		return false
	}
	recvVar := b.Recv
	ptr, ok := types.Unalias(recvVar.Type()).(*types.Pointer)
	if !ok {
		return false
	}
	recvElem := types.Unalias(ptr.Elem())
	if !types.Identical(recvElem, outerNamed) && (baseNamed == nil || !types.Identical(recvElem, baseNamed)) {
		return false
	}
	// Reject reassigning recvVar or taking &recvVar anywhere in b.
	if mapperBodyReassignsOrAddrsRecv(b, recvVar) {
		return false
	}

	regions, ok := refconfine.VerifyBodyLockRegions(p, idx, b, refconfine.LockTarget{
		Kind:      refconfine.LockRecvField,
		RecvVar:   recvVar,
		LockField: mutexField,
		IsRWMutex: false,
	})
	if !ok || regions == nil || len(regions.IsLockTransitionOp) == 0 {
		return false
	}

	syscallAddrs := collectMapperSyscallAddrVarsFlowIR(b, recvVar, callableFields)
	mappedSlices, mappedKeys := collectMapperSliceAndKeyVarsFlowIR(b, syscallAddrs)

	// Verify zero closures/goroutines, at least one synchronous kernel-syscall
	// callableField invocation and activeField mutation, and that every activeField
	// mention occurs synchronously under WriteLocked dominance in one of the three
	// allowed map forms.
	totalActiveMentions := countFieldMentionsInBody(b, activeField)
	validActiveMentions := 0
	sawSyscallCall := false
	sawActiveMutation := false
	validBody := true

	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if !validBody {
			return false
		}
		mode, hasMode := regions.OpModes[op]
		if !hasMode {
			validBody = false
			return false
		}
		if op.Kind == flowir.OpGo {
			validBody = false
			return false
		}

		// Forbid closures, IIFEs, and &m.active[...] anywhere in b.
		op.ForEachValue(func(v *flowir.Value) bool {
			if v == nil {
				return true
			}
			v.WalkValues(func(cur *flowir.Value) bool {
				switch cur.Kind {
				case flowir.ValMakeClosure:
					validBody = false
					return false
				case flowir.ValCall:
					if cur.CallKind == flowir.CallIIFE {
						validBody = false
						return false
					}
					if op.Kind != flowir.OpDefer && cur.CallKind == flowir.CallIndirect &&
						cur.Callee != nil && cur.Callee.Kind == flowir.ValPlace &&
						cur.Callee.Place.Obj == recvVar && len(cur.Callee.Place.Projs) == 1 &&
						cur.Callee.Place.Projs[0].Kind == flowir.ProjField &&
						callableFields[cur.Callee.Place.Projs[0].Field] != nil {
						sawSyscallCall = true
					}
					// Builtin delete(m.active, keyVar)
					if cur.CallKind == flowir.CallBuiltin && cur.BuiltinName == "delete" &&
						len(cur.Args) == 2 && !cur.Ellipsis &&
						isRecvActiveFieldVal(cur.Args[0], recvVar, activeField) {
						if !mode.IsWriteLocked() || cur.Args[1] == nil || cur.Args[1].Kind != flowir.ValPlace ||
							!cur.Args[1].Place.IsBareVar() || mappedKeys[cur.Args[1].Place.Obj] == nil {
							validBody = false
							return false
						}
						sawActiveMutation = true
						validActiveMentions++
					}
				case flowir.ValAddrOf:
					if placeMentionsField(cur.AddrPlace, activeField) {
						validBody = false
						return false
					}
				case flowir.ValPlace:
					// Map index read: m.active[keyVar]
					if isRecvActiveIndexedPlace(cur.Place, recvVar, activeField, mappedKeys) {
						if !mode.IsWriteLocked() {
							validBody = false
							return false
						}
						validActiveMentions++
					}
				}
				return validBody
			})
			return validBody
		})
		if !validBody {
			return false
		}

		// Map store: m.active[keyVar] = valVar
		if op.Kind == flowir.OpAssign {
			for di, dst := range op.Dsts {
				if !placeMentionsField(dst, activeField) {
					continue
				}
				if op.AssignKind != flowir.AssignPlain || len(op.Dsts) != 1 || len(op.Srcs) != 1 || di != 0 ||
					!mode.IsWriteLocked() || !isRecvActiveIndexedPlace(dst, recvVar, activeField, mappedKeys) {
					validBody = false
					return false
				}
				keyVar := dst.Projs[len(dst.Projs)-1].Key.Place.Obj
				src := op.Srcs[0]
				if src == nil || src.Kind != flowir.ValPlace || !src.Place.IsBareVar() ||
					!mappedSlices[src.Place.Obj] || mappedKeys[keyVar] != src.Place.Obj {
					validBody = false
					return false
				}
				sawActiveMutation = true
				validActiveMentions++
			}
		}
		return validBody
	})

	return validBody && sawSyscallCall && sawActiveMutation && validActiveMentions == totalActiveMentions
}

func mapperBodyReassignsOrAddrsRecv(b *flowir.Body, recvVar *types.Var) bool {
	hit := false
	var walkBody func(cur *flowir.Body)
	walkBody = func(cur *flowir.Body) {
		if cur == nil || hit {
			return
		}
		for i := range cur.Ops {
			op := &cur.Ops[i]
			if op.Kind == flowir.OpAssign {
				for _, dst := range op.Dsts {
					if dst.IsBareVar() && dst.Obj == recvVar {
						hit = true
						return
					}
				}
			}
			op.ForEachValue(func(v *flowir.Value) bool {
				if v == nil {
					return true
				}
				v.WalkValues(func(cv *flowir.Value) bool {
					if cv.Kind == flowir.ValAddrOf && cv.AddrPlace.IsBareVar() && cv.AddrPlace.Obj == recvVar {
						hit = true
						return false
					}
					if cv.Kind == flowir.ValMakeClosure && cv.Closure != nil {
						walkBody(cv.Closure)
					} else if cv.Kind == flowir.ValCall && cv.CallKind == flowir.CallIIFE && cv.IIFE != nil {
						walkBody(cv.IIFE)
					}
					return !hit
				})
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

func isRecvActiveFieldPlace(pl flowir.Place, recvVar, activeField *types.Var) bool {
	return pl.Obj == recvVar && len(pl.Projs) == 1 &&
		pl.Projs[0].Kind == flowir.ProjField && pl.Projs[0].Field == activeField
}

func isRecvActiveFieldVal(v *flowir.Value, recvVar, activeField *types.Var) bool {
	return v != nil && v.Kind == flowir.ValPlace && isRecvActiveFieldPlace(v.Place, recvVar, activeField)
}

func isRecvActiveIndexedPlace(pl flowir.Place, recvVar, activeField *types.Var, mappedKeys map[*types.Var]*types.Var) bool {
	if pl.Obj != recvVar || len(pl.Projs) != 2 {
		return false
	}
	if pl.Projs[0].Kind != flowir.ProjField || pl.Projs[0].Field != activeField ||
		pl.Projs[1].Kind != flowir.ProjIndex || pl.Projs[1].Key == nil {
		return false
	}
	kv := pl.Projs[1].Key
	return kv.Kind == flowir.ValPlace && kv.Place.IsBareVar() && mappedKeys[kv.Place.Obj] != nil
}

func placeMentionsField(pl flowir.Place, target *types.Var) bool {
	for _, pr := range pl.Projs {
		if pr.Kind == flowir.ProjField && pr.Field == target {
			return true
		}
	}
	return false
}

func countFieldMentionsInBody(b *flowir.Body, target *types.Var) int {
	n := 0
	var walkBody func(cur *flowir.Body)
	walkVal := func(v *flowir.Value) {
		if v == nil {
			return
		}
		v.WalkValues(func(cv *flowir.Value) bool {
			switch cv.Kind {
			case flowir.ValPlace:
				for _, pr := range cv.Place.Projs {
					if pr.Kind == flowir.ProjField && pr.Field == target {
						n++
					}
				}
			case flowir.ValAddrOf:
				for _, pr := range cv.AddrPlace.Projs {
					if pr.Kind == flowir.ProjField && pr.Field == target {
						n++
					}
				}
			case flowir.ValMakeClosure:
				if cv.Closure != nil {
					walkBody(cv.Closure)
				}
			case flowir.ValCall:
				if cv.CallKind == flowir.CallIIFE && cv.IIFE != nil {
					walkBody(cv.IIFE)
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
			if op.Kind == flowir.OpAssign {
				for _, dst := range op.Dsts {
					for _, pr := range dst.Projs {
						if pr.Kind == flowir.ProjField && pr.Field == target {
							n++
						}
					}
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

func collectMapperSyscallAddrVarsFlowIR(
	b *flowir.Body,
	recvVar *types.Var,
	callableFields map[*types.Var]*types.Signature,
) map[*types.Var]bool {
	addrs := map[*types.Var]bool{}
	dirty := map[*types.Var]bool{}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind != flowir.OpAssign {
			return true
		}
		if op.AssignKind == flowir.AssignMulti && len(op.Dsts) == 2 && len(op.Srcs) == 1 && op.Srcs[0] != nil {
			call := op.Srcs[0]
			if call.Kind == flowir.ValCall && call.CallKind == flowir.CallIndirect &&
				call.Callee != nil && call.Callee.Kind == flowir.ValPlace &&
				call.Callee.Place.Obj == recvVar && len(call.Callee.Place.Projs) == 1 &&
				call.Callee.Place.Projs[0].Kind == flowir.ProjField &&
				callableFields[call.Callee.Place.Projs[0].Field] != nil {
				if op.Dsts[0].IsBareVar() && op.Dsts[0].Root == flowir.RootLocal && op.Dsts[0].Obj != nil {
					if addrs[op.Dsts[0].Obj] {
						dirty[op.Dsts[0].Obj] = true
					} else {
						addrs[op.Dsts[0].Obj] = true
					}
					if op.Dsts[1].IsBareVar() && op.Dsts[1].Obj != nil {
						dirty[op.Dsts[1].Obj] = true
					}
					return true
				}
			}
		}
		for _, dst := range op.Dsts {
			if dst.Obj != nil && op.AssignKind != flowir.AssignZeroDecl {
				dirty[dst.Obj] = true
			}
		}
		return true
	})
	for v := range dirty {
		delete(addrs, v)
	}
	return addrs
}

func collectMapperSliceAndKeyVarsFlowIR(b *flowir.Body, syscallAddrs map[*types.Var]bool) (map[*types.Var]bool, map[*types.Var]*types.Var) {
	slices := map[*types.Var]bool{}
	keys := map[*types.Var]*types.Var{}
	hdrAlias := map[*types.Var]*types.Var{}
	hdrDataCand := map[*types.Var]bool{}
	hdrDataWrites := map[*types.Var]int{}
	hdrBadFieldWrite := map[*types.Var]bool{}
	zeroDeclVars := map[*types.Var]bool{}
	writes := map[*types.Var]int{}

	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind != flowir.OpAssign {
			return true
		}
		if op.AssignKind == flowir.AssignZeroDecl {
			for _, dst := range op.Dsts {
				if dst.IsBareVar() && dst.Root == flowir.RootLocal && dst.Obj != nil {
					zeroDeclVars[dst.Obj] = true
				}
			}
			return true
		}
		for i, dst := range op.Dsts {
			if dst.IsBareVar() && dst.Obj != nil {
				writes[dst.Obj]++
				if op.AssignKind == flowir.AssignPlain && i < len(op.Srcs) && op.Srcs[i] != nil {
					rhs := op.Srcs[i]
					if isUnsafeSliceFromAddrFlowIR(rhs, syscallAddrs) {
						slices[dst.Obj] = true
					}
					if op.TopLevelInBody {
						if target := isUnsafeSliceHdrCastFlowIR(rhs); target != nil {
							hdrAlias[dst.Obj] = target
						}
					}
					if slVar := isByteSliceElemAddrFlowIR(rhs); slVar != nil {
						keys[dst.Obj] = slVar
					}
				}
			}
			// Legacy pre-unsafe.Slice pattern: var b []byte; hdr := (*SliceHeader)(unsafe.Pointer(&b)); hdr.Data = unsafe.Pointer(addr)
			if dst.Obj != nil && hdrAlias[dst.Obj] != nil && !dst.IsBareVar() {
				if op.AssignKind == flowir.AssignPlain && i < len(op.Srcs) && op.Srcs[i] != nil &&
					len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjField && dst.Projs[0].Field != nil {
					switch dst.Projs[0].Field.Name() {
					case "Data":
						hdrDataWrites[dst.Obj]++
						if op.TopLevelInBody && isUnsafePointerOfAddrFlowIR(op.Srcs[i], syscallAddrs) {
							hdrDataCand[dst.Obj] = true
						}
					case "Len", "Cap":
					default:
						hdrBadFieldWrite[dst.Obj] = true
					}
				} else {
					hdrBadFieldWrite[dst.Obj] = true
				}
			}
		}
		return true
	})
	for hdrVar, target := range hdrAlias {
		if hdrDataCand[hdrVar] && hdrDataWrites[hdrVar] == 1 && !hdrBadFieldWrite[hdrVar] &&
			writes[hdrVar] == 1 && zeroDeclVars[target] && writes[target] == 0 {
			slices[target] = true
		}
	}
	for v, c := range writes {
		if c > 1 {
			delete(slices, v)
			delete(keys, v)
		}
	}
	return slices, keys
}

func isUnsafeSliceFromAddrFlowIR(v *flowir.Value, syscallAddrs map[*types.Var]bool) bool {
	if v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallBuiltin ||
		v.BuiltinName != "Slice" || len(v.Args) != 2 || v.Ellipsis || v.Args[0] == nil {
		return false
	}
	arg0 := v.Args[0]
	if arg0.Kind != flowir.ValConvert || arg0.IsTypeAssert || arg0.Arg == nil {
		return false
	}
	return isUnsafePointerOfAddrFlowIR(arg0.Arg, syscallAddrs)
}

func isUnsafePointerOfAddrFlowIR(v *flowir.Value, syscallAddrs map[*types.Var]bool) bool {
	if v == nil || v.Kind != flowir.ValConvert || v.IsTypeAssert || !syntaxutil.IsUnsafePointerType(v.Type) || v.Arg == nil {
		return false
	}
	return v.Arg.Kind == flowir.ValPlace && v.Arg.Place.IsBareVar() && syscallAddrs[v.Arg.Place.Obj]
}

func isUnsafeSliceHdrCastFlowIR(v *flowir.Value) *types.Var {
	if v == nil || v.Kind != flowir.ValConvert || v.IsTypeAssert || v.Arg == nil {
		return nil
	}
	up := v.Arg
	if up.Kind != flowir.ValConvert || up.IsTypeAssert || !syntaxutil.IsUnsafePointerType(up.Type) || up.Arg == nil {
		return nil
	}
	addr := up.Arg
	if addr.Kind != flowir.ValAddrOf || addr.IsArraySlice || !addr.AddrPlace.IsBareVar() || !addr.AddrPlace.IsLocalRoot() {
		return nil
	}
	return addr.AddrPlace.Obj
}

func isByteSliceElemAddrFlowIR(v *flowir.Value) *types.Var {
	if v == nil || v.Kind != flowir.ValAddrOf || v.IsArraySlice || !v.AddrPlace.IsLocalRoot() ||
		v.AddrPlace.Obj == nil || len(v.AddrPlace.Projs) != 1 || v.AddrPlace.Projs[0].Kind != flowir.ProjIndex {
		return nil
	}
	return v.AddrPlace.Obj
}

func pkgHasStructDerefWriteFlowIR(p *packages.Package, fc *pkgFlowCache, targets ...*types.Named) bool {
	if fc == nil || fc.base == nil {
		return false
	}
	matchPtr := func(t types.Type) bool {
		st := syntaxutil.DerefNamedStruct(t)
		if st == nil {
			return false
		}
		for _, want := range targets {
			if want != nil && types.Identical(st, want) {
				return true
			}
		}
		return false
	}
	hit := false
	var scanBody func(b *flowir.Body)
	scanBody = func(b *flowir.Body) {
		if b == nil || hit {
			return
		}
		for i := range b.Ops {
			op := &b.Ops[i]
			if op.Kind == flowir.OpAssign {
				for _, dst := range op.Dsts {
					if len(dst.Projs) > 0 && dst.Projs[len(dst.Projs)-1].Kind == flowir.ProjDeref &&
						matchPtr(dst.Projs[len(dst.Projs)-1].BaseType) {
						hit = true
						return
					}
				}
				if op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
					scanBody(op.RangeBody)
				}
			}
			op.ForEachValue(func(v *flowir.Value) bool {
				if v == nil {
					return true
				}
				v.WalkValues(func(cv *flowir.Value) bool {
					if cv.Kind == flowir.ValMakeClosure && cv.Closure != nil {
						scanBody(cv.Closure)
					} else if cv.Kind == flowir.ValCall && cv.CallKind == flowir.CallIIFE && cv.IIFE != nil {
						scanBody(cv.IIFE)
					}
					return !hit
				})
				return !hit
			})
			if hit {
				return
			}
		}
	}
	for _, gd := range fc.base.GenDecls {
		scanBody(fc.body(p, gd))
	}
	for _, fd := range fc.base.FuncDecls {
		scanBody(fc.funcBody(p, fd))
	}
	return hit
}

func isBytePtrByteSliceMap(t types.Type) bool {
	m, ok := types.Unalias(t).Underlying().(*types.Map)
	if !ok {
		return false
	}
	kp, ok := types.Unalias(m.Key()).(*types.Pointer)
	if !ok {
		return false
	}
	kb, ok := types.Unalias(kp.Elem()).Underlying().(*types.Basic)
	if !ok || kb.Kind() != types.Byte {
		return false
	}
	vs, ok := types.Unalias(m.Elem()).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	vb, ok := types.Unalias(vs.Elem()).Underlying().(*types.Basic)
	return ok && vb.Kind() == types.Byte
}
