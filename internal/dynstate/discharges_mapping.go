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
		if syntaxutil.IsErrorType(res.At(0).Type()) {
			return false, true, true
		}
	case 2:
		b, ok := types.Unalias(res.At(0).Type()).Underlying().(*types.Basic)
		if ok && b.Kind() == types.Uintptr && syntaxutil.IsErrorType(res.At(1).Type()) {
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
		if syntaxutil.IsErrorType(rt) {
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
						if dst.IsBareVar() && dst.Obj != nil && syntaxutil.IsErrorType(dst.Obj.Type()) {
							cleanErrVars[dst.Obj] = true
						}
					}
					return true
				}
				for _, dst := range op.Dsts {
					if dst.IsBareVar() && dst.Obj != nil && syntaxutil.IsErrorType(dst.Obj.Type()) {
						dirtyErrVars[dst.Obj] = true
					}
				}
			case flowir.AssignPlain:
				for i, dst := range op.Dsts {
					if !dst.IsBareVar() || dst.Obj == nil || !syntaxutil.IsErrorType(dst.Obj.Type()) {
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
					if dst.Obj != nil && syntaxutil.IsErrorType(dst.Obj.Type()) {
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
