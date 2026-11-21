package freshstruct

import (
	"context"
	"go/ast"
	"go/types"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func pkgCanPassOrReturnExtractedObject(
	ctx context.Context,
	traceTarget string,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	isTrueStdPkg func(*types.Package) bool,
) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || len(p.Syntax) == 0 {
		return true
	}
	if len(p.OtherFiles) > 0 || (len(p.GoFiles) > 0 && len(p.CompiledGoFiles) > len(p.GoFiles)) {
		emitExtractEscape(ctx, p, traceTarget, "non_go_or_cgo_files", "", nil)
		return true
	}
	for _, file := range p.Syntax {
		for _, imp := range file.Imports {
			if imp != nil && imp.Path != nil {
				if uq, err := strconv.Unquote(imp.Path.Value); err == nil && (uq == "C" || uq == "unsafe") {
					emitExtractEscape(ctx, p, traceTarget, "imports_c_or_unsafe", uq, imp)
					return true
				}
			}
		}
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "go:linkname") {
					emitExtractEscape(ctx, p, traceTarget, "go_linkname", "", c)
					return true
				}
			}
		}
		for _, decl := range file.Decls {
			if fd, isFD := decl.(*ast.FuncDecl); isFD && fd.Body == nil {
				emitExtractEscape(ctx, p, traceTarget, "bodyless_func", fd.Name.Name, fd)
				return true
			}
		}
	}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		if v, isV := scope.Lookup(name).(*types.Var); isV && v != nil && typeCanCarryExtractedObject(v.Type()) {
			emitExtractEscape(ctx, p, traceTarget, "carrier_pkg_global", name, nil)
			return true
		}
	}
	checkExportedSig := func(sig *types.Signature) bool {
		if sig == nil {
			return false
		}
		for i := 0; i < sig.Results().Len(); i++ {
			if typeCanCarryExtractedObject(sig.Results().At(i).Type()) {
				return true
			}
		}
		for i := 0; i < sig.Params().Len(); i++ {
			pt := sig.Params().At(i).Type()
			if sig.Variadic() && i == sig.Params().Len()-1 {
				if sl, isSl := types.Unalias(pt).Underlying().(*types.Slice); isSl {
					pt = sl.Elem()
				}
			}
			if isRuntimeInterfaceType(pt) {
				continue
			}
			if _, isSig := types.Unalias(pt).Underlying().(*types.Signature); isSig {
				continue
			}
			if typeCanCarryExtractedObject(pt) {
				return true
			}
		}
		return false
	}
	if pkgExportedAPIReaches(p, typeCanCarryExtractedObject, nil, checkExportedSig) {
		emitExtractEscape(ctx, p, traceTarget, "exported_api_reaches_carrier", "", nil)
		return true
	}
	fc := idx.FlowCache(p)
	if fc == nil {
		return true
	}
	freshVars, freshFields, isFreshOwnedVal, isCallerSafeIfaceVal := computeFreshOwnedContainers(p, idx, fc, isTrueStdPkg)
	reflectCallsVerified := 0 // 0=unchecked, 1=ok, -1=failed

	isSafeStdIfaceRecv := func(pkgPath string, recvT types.Type) bool {
		if !isRuntimeInterfaceType(recvT) {
			return false
		}
		if isPureByteWriterIface(p, recvT) || pkgPath == "context" {
			return true
		}
		if pkgPath == "fmt" {
			if named, ok := types.Unalias(recvT).(*types.Named); ok && named.Obj() != nil {
				switch named.Obj().Name() {
				case "State", "Stringer", "GoStringer":
					return true
				}
			}
		}
		return false
	}
	isAllowedNonStdIfaceRecvCall := func(v *flowir.Value) bool {
		if v == nil || v.Recv == nil || !isRuntimeInterfaceType(v.Recv.Type) {
			return false
		}
		if isCallerSafeIfaceVal(v.Recv) {
			return true
		}
		return ifaceSealsOutStdlib(v.Recv.Type, isTrueStdPkg) &&
			v.CalleeSig != nil && v.CalleeSig.Results() != nil && v.CalleeSig.Results().Len() > 0
	}
	callNonRecvArgsCarry := func(v *flowir.Value) bool {
		if v == nil {
			return false
		}
		if v.IsMethodExprCall && len(v.Args) == 0 && v.Recv != nil && v.Recv.Type != nil {
			if tup, isTup := types.Unalias(v.Recv.Type).(*types.Tuple); isTup {
				for k := 1; k < tup.Len(); k++ {
					if tup.At(k) != nil && typeCanCarryExtractedObject(tup.At(k).Type()) {
						return true
					}
				}
				return false
			}
		}
		for _, a := range v.Args {
			if a != nil && !isFreshOwnedVal(a) && typeCanCarryExtractedObject(a.Type) {
				return true
			}
		}
		return false
	}
	isSafeReadOnlyStdCalleeCall := func(v *flowir.Value, callee *types.Func) (bool, string) {
		if v == nil || v.CallAST == nil || v.IsMethodExprCall || v.Recv != nil || callee == nil || callee.Pkg() == nil {
			return false, "readonly_std_bad_shape"
		}
		tupleFirst := hasTupleFirstArg(v)
		switch callee.Pkg().Path() {
		case "runtime":
			if callee.Name() == "KeepAlive" && !v.Ellipsis && len(v.Args) == 1 {
				return true, ""
			}
		case "reflect":
			if (callee.Name() == "TypeOf" || callee.Name() == "DeepEqual") && !v.Ellipsis {
				return true, ""
			}
		case "log":
			switch callee.Name() {
			case "Print", "Printf", "Println", "Fatal", "Fatalf", "Fatalln", "Panic", "Panicf", "Panicln":
				return true, ""
			}
		case "fmt":
			switch callee.Name() {
			case "Sprint", "Sprintf", "Sprintln", "Print", "Printf", "Println":
				return true, ""
			case "Errorf":
				wrapped := false
				v.ForEachArgParam(func(_ *flowir.Value, slotT types.Type, slotIdx int, _ int, _ bool, _ bool) bool {
					if callMayWrapErrorOperand(p, v.CallAST, callee, slotIdx, slotT) {
						wrapped = true
						return false
					}
					return true
				})
				if wrapped {
					return false, "fmt_errorf_wrap"
				}
				return true, ""
			case "Fprint", "Fprintf", "Fprintln":
				if !tupleFirst && len(v.Args) >= 1 && v.Args[0] != nil &&
					isPureByteWriterIface(p, v.Args[0].Type) && isCallerSafeIfaceVal(v.Args[0]) {
					return true, ""
				}
				return false, "fmt_fprint_unconfined_writer"
			case "Append", "Appendf", "Appendln":
				if !tupleFirst && len(v.Args) >= 1 && isFreshOwnedVal(v.Args[0]) {
					return true, ""
				}
				return false, "fmt_append_non_fresh_dst"
			case "FormatString":
				if !tupleFirst && len(v.Args) == 2 && isCallerSafeIfaceVal(v.Args[0]) &&
					v.Args[1] != nil && !typeCanCarryExtractedObject(v.Args[1].Type) {
					return true, ""
				}
				return false, "fmt_formatstring_unconfined_state"
			}
		}
		return false, "readonly_std_disallowed_callee"
	}

	return !forEachPkgFlowOp(p, fc, func(_ *types.Func, _ *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
		switch op.Kind {
		case flowir.OpAssign:
			if op.AssignKind != flowir.AssignZeroDecl {
				for _, dst := range op.Dsts {
					if dst.IsBlank() {
						continue
					}
					if !dst.IsLocalRoot() {
						emitExtractEscape(ctx, p, traceTarget, "assign_non_local_root", "", dst.Raw)
						return false
					}
					if len(dst.Projs) > 0 {
						if len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjField && freshFields[dst.Projs[0].Field] {
							continue
						}
						if len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjIndex && dst.Obj != nil && freshVars[dst.Obj] {
							continue
						}
						if typeCanCarryExtractedObject(dst.Type) || placeCrossesRefIndirection(dst) {
							emitExtractEscape(ctx, p, traceTarget, "assign_projected_or_indirect", "", dst.Raw)
							return false
						}
					}
				}
			}
		case flowir.OpChanSend:
			emitExtractEscape(ctx, p, traceTarget, "chan_send", "", op.StmtAST)
			return false
		case flowir.OpGo:
			emitExtractEscape(ctx, p, traceTarget, "spawn_go", "", op.StmtAST)
			return false
		}
		escaped := false
		op.ForEachValue(func(root *flowir.Value) bool {
			root.WalkValues(func(v *flowir.Value) bool {
				if escaped || v == nil {
					return false
				}
				switch v.Kind {
				case flowir.ValChanRecv:
					emitExtractEscape(ctx, p, traceTarget, "chan_recv", "", v.Raw)
					escaped = true
					return false
				case flowir.ValMethodVal:
					if v.Recv != nil && typeCanCarryExtractedObject(v.Recv.Type) {
						emitExtractEscape(ctx, p, traceTarget, "bound_method_val", "", v.Raw)
						escaped = true
						return false
					}
					return true
				case flowir.ValAllocFresh:
					switch v.AllocKind {
					case flowir.AllocBuiltinNewExpr:
						if len(v.Args) >= 1 && v.Args[0] != nil && !isFreshOwnedVal(v.Args[0]) &&
							typeCanCarryExtractedObject(v.Args[0].Type) && typeHasExternalMethod(p.Types, v.ElemType) {
							emitExtractEscape(ctx, p, traceTarget, "new_expr_ext_methods", "", v.Raw)
							escaped = true
							return false
						}
					case flowir.AllocCompositeLit:
						if typeHasExternalMethod(p.Types, v.ElemType) {
							for i := range v.CompositeElts {
								elt := &v.CompositeElts[i]
								if (elt.Value != nil && !isFreshOwnedVal(elt.Value) && typeCanCarryExtractedObject(elt.Value.Type)) ||
									(elt.MapKey != nil && !isFreshOwnedVal(elt.MapKey) && typeCanCarryExtractedObject(elt.MapKey.Type)) {
									emitExtractEscape(ctx, p, traceTarget, "composite_lit_ext_methods", "", v.Raw)
									escaped = true
									return false
								}
							}
						}
					}
					return true
				case flowir.ValConvert:
					if !v.IsTypeAssert && v.Type != nil && v.Arg != nil &&
						!isFreshOwnedVal(v.Arg) && typeCanCarryExtractedObject(v.Type) &&
						typeOrPtrHasMethods(v.Type) {
						emitExtractEscapeType(ctx, p, traceTarget, "convert_method_bearing_carrier", v.Type, v.Raw)
						escaped = true
						return false
					}
					return true
				}
				if v.Kind != flowir.ValCall {
					return true
				}
				if v.CallKind == flowir.CallBuiltin {
					switch v.BuiltinName {
					case "close":
						emitExtractEscape(ctx, p, traceTarget, "mutating_builtin", v.BuiltinName, v.Raw)
						escaped = true
						return false
					case "append", "copy", "clear", "delete":
						if hasTupleFirstArg(v) || len(v.Args) == 0 || !isFreshOwnedVal(v.Args[0]) {
							emitExtractEscape(ctx, p, traceTarget, "mutating_builtin", v.BuiltinName, v.Raw)
							escaped = true
							return false
						}
					}
					return true
				}
				callee := v.CalleeFunc
				if callee == nil {
					if (v.Recv != nil && typeCanCarryExtractedObject(v.Recv.Type)) || callNonRecvArgsCarry(v) {
						emitExtractEscape(ctx, p, traceTarget, "indirect_call_carries", "", v.Raw)
						escaped = true
						return false
					}
					return true
				}
				if callee.Pkg() == p.Types {
					if sig, okS := callee.Type().(*types.Signature); okS && sig.Recv() != nil && isRuntimeInterfaceType(sig.Recv().Type()) {
						if !isAllowedNonStdIfaceRecvCall(v) || callNonRecvArgsCarry(v) {
							emitExtractEscape(ctx, p, traceTarget, "intra_iface_call_carries", callee.Name(), v.Raw)
							escaped = true
							return false
						}
					}
					return true
				}
				if isTrueStdPkg(callee.Pkg()) {
					if v.Recv == nil && syntaxutil.IsReadOnlyEmptyInterfaceCallee(p, callee) {
						okStd, reason := isSafeReadOnlyStdCalleeCall(v, callee)
						if !okStd {
							emitExtractEscapeFunc(ctx, p, traceTarget, reason, callee, v.Raw)
							escaped = true
							return false
						}
						return true
					}
					if callee.Pkg().Path() == "reflect" {
						if callee.Name() == "Call" {
							if reflectCallsVerified == 0 {
								if pkgConfinesAllReflectValueCalls(ctx, traceTarget, p, idx, isTrueStdPkg) {
									reflectCallsVerified = 1
								} else {
									reflectCallsVerified = -1
								}
							}
							if reflectCallsVerified < 0 {
								emitExtractEscapeFunc(ctx, p, traceTarget, "reflect_value_call", callee, v.Raw)
								escaped = true
								return false
							}
						} else if callee.Name() == "CallSlice" {
							emitExtractEscapeFunc(ctx, p, traceTarget, "reflect_value_callslice", callee, v.Raw)
							escaped = true
							return false
						}
						return true
					}
					if callee.Pkg().Path() == "io" && callee.Name() == "WriteString" && !v.IsMethodExprCall && !hasTupleFirstArg(v) && len(v.Args) == 2 &&
						v.Args[0] != nil && isPureByteWriterIface(p, v.Args[0].Type) && isCallerSafeIfaceVal(v.Args[0]) &&
						v.Args[1] != nil && !typeCanCarryExtractedObject(v.Args[1].Type) {
						return true
					}
					if v.Recv != nil && !isFreshOwnedVal(v.Recv) && typeCanCarryExtractedObject(v.Recv.Type) &&
						!(isCallerSafeIfaceVal(v.Recv) && isSafeStdIfaceRecv(callee.Pkg().Path(), v.Recv.Type)) {
						emitExtractEscapeFunc(ctx, p, traceTarget, "std_concrete_or_mut_recv", callee, v.Raw)
						escaped = true
						return false
					}
					if callNonRecvArgsCarry(v) {
						emitExtractEscapeFunc(ctx, p, traceTarget, "std_call_args_carry", callee, v.Raw)
						escaped = true
						return false
					}
					return true
				}
				if v.Recv != nil && !isFreshOwnedVal(v.Recv) && typeCanCarryExtractedObject(v.Recv.Type) {
					if !isRuntimeInterfaceType(v.Recv.Type) {
						emitExtractEscapeFunc(ctx, p, traceTarget, "ext_concrete_recv_carries", callee, v.Raw)
						escaped = true
						return false
					}
					if !isAllowedNonStdIfaceRecvCall(v) {
						emitExtractEscapeFunc(ctx, p, traceTarget, "ext_unsealed_or_void_iface_recv", callee, v.Raw)
						escaped = true
						return false
					}
				}
				if callNonRecvArgsCarry(v) {
					emitExtractEscapeFunc(ctx, p, traceTarget, "ext_call_args_carry", callee, v.Raw)
					escaped = true
					return false
				}
				return true
			})
			return !escaped
		})
		return !escaped
	})
}
