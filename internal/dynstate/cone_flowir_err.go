package dynstate

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type errorOriginConfig struct {
	memoFields                     map[*types.Var]bool
	memoAssigns                    []*ast.AssignStmt
	trustedErrCallees              map[*types.Func]bool
	allowConfinedNonErrIfaceParams bool
	allowRootErrParams             bool
	allowReflectTypeValues         bool
}

func verifyFlowIRErrorOrigins(
	p *packages.Package,
	fc *pkgFlowCache,
	rootSig *types.Signature,
	rootBody *flowir.Body,
	coneFuncs map[*types.Func]*ast.FuncDecl,
	localClosures map[*types.Var]*flowir.Body,
	cfg errorOriginConfig,
) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || rootSig == nil || rootBody == nil {
		return false
	}
	if cfg.allowReflectTypeValues && !isTrueStdlibInPkg(p, "reflect") {
		cfg.allowReflectTypeValues = false
	}

	paramDisallowed := func(pt types.Type) bool {
		if typeReachesUniverseError(pt) {
			return true
		}
		if cfg.allowReflectTypeValues && syntaxutil.IsNamedInPkg(pt, "reflect", "Type") {
			return false
		}
		if cfg.allowConfinedNonErrIfaceParams && types.IsInterface(pt) {
			return false
		}
		return refconfine.TypeMayCarryUnknownDynamic(true, pt)
	}

	rootParams := make(map[*types.Var]bool, rootSig.Params().Len())
	for i := 0; i < rootSig.Params().Len(); i++ {
		pv := rootSig.Params().At(i)
		rootParams[pv] = true
		pt := pv.Type()
		if cfg.allowRootErrParams && isUniverseErrorType(pt) {
			continue
		}
		if paramDisallowed(pt) {
			return false
		}
	}

	scopes := make([]flowIRConeUnit, 0, 1+len(coneFuncs)+len(localClosures))
	scopes = append(scopes, flowIRConeUnit{sig: rootSig, body: rootBody})

	for fn, fd := range coneFuncs {
		sig, okSig := fn.Type().(*types.Signature)
		cbody := fc.funcBody(p, fd)
		if !okSig || cbody == nil {
			return false
		}
		if sig.Recv() != nil && refconfine.TypeMayCarryUnknownDynamic(true, sig.Recv().Type()) {
			return false
		}
		for i := 0; i < sig.Params().Len(); i++ {
			if paramDisallowed(sig.Params().At(i).Type()) {
				return false
			}
		}
		for i := 0; i < sig.Results().Len(); i++ {
			rt := sig.Results().At(i).Type()
			if refconfine.TypeMayCarryUnknownDynamic(true, rt) && !isUniverseErrorType(rt) {
				return false
			}
		}
		scopes = append(scopes, flowIRConeUnit{sig: sig, body: cbody})
	}

	for lv, closBody := range localClosures {
		sig, okSig := lv.Type().Underlying().(*types.Signature)
		if !okSig || closBody == nil {
			return false
		}
		for i := 0; i < sig.Params().Len(); i++ {
			if paramDisallowed(sig.Params().At(i).Type()) {
				return false
			}
		}
		for i := 0; i < sig.Results().Len(); i++ {
			rt := sig.Results().At(i).Type()
			if refconfine.TypeMayCarryUnknownDynamic(true, rt) && !isUniverseErrorType(rt) {
				return false
			}
		}
		scopes = append(scopes, flowIRConeUnit{sig: sig, body: closBody})
	}

	resolveVerifiedConeCallSig := func(call *flowir.Value) *types.Signature {
		if call == nil || call.Kind != flowir.ValCall || call.IsMethodExprCall {
			return nil
		}
		switch call.CallKind {
		case flowir.CallIndirect:
			if call.Callee != nil && call.Callee.Kind == flowir.ValPlace && call.Callee.Place.IsBareVar() &&
				localClosures[call.Callee.Place.Obj] != nil {
				sig, _ := call.Callee.Place.Obj.Type().Underlying().(*types.Signature)
				return sig
			}
		case flowir.CallPlain, flowir.CallMethod:
			if call.CallKind == flowir.CallMethod && call.Selection != nil && types.IsInterface(call.Selection.Recv()) {
				return nil
			}
			callee := call.CalleeFunc
			if callee != nil && (coneFuncs[callee] != nil || cfg.trustedErrCallees[callee]) {
				sig, _ := callee.Type().(*types.Signature)
				return sig
			}
		}
		return nil
	}

	var isPureErrorValue func(v *flowir.Value, depth int) bool
	isPureErrorValue = func(v *flowir.Value, depth int) bool {
		if v == nil || depth > 16 {
			return false
		}
		if v.IsNil || (v.Kind == flowir.ValPlace && v.Place.Root == flowir.RootConstOrNil) {
			return true
		}
		switch v.Kind {
		case flowir.ValPlace:
			if !v.Place.IsBareVar() || !v.Place.IsLocalRoot() || v.Place.Obj == nil {
				return false
			}
			lv := v.Place.Obj
			if !isUniverseErrorType(lv.Type()) {
				return false
			}
			if rootParams[lv] {
				return cfg.allowRootErrParams
			}
			return true

		case flowir.ValCall:
			if csig := resolveVerifiedConeCallSig(v); csig != nil {
				return csig.Results().Len() == 1 && isUniverseErrorType(csig.Results().At(0).Type())
			}
			if v.CallKind == flowir.CallPlain && !v.IsMethodExprCall && v.CalleeFunc != nil && v.CalleeFunc.Pkg() != nil {
				pkgPath := v.CalleeFunc.Pkg().Path()
				if !isTrueStdlibInPkg(p, pkgPath) {
					return false
				}
				if pkgPath == "errors" && v.CalleeFunc.Name() == "New" && len(v.Args) == 1 && !v.Ellipsis {
					return v.Args[0] != nil && isBasicStringType(v.Args[0].Type)
				}
				if pkgPath == "fmt" && v.CalleeFunc.Name() == "Errorf" && len(v.Args) >= 1 && !v.Ellipsis {
					return verifyPureFmtFormatArgsFlowIR(p, v.Args[0], v.Args[1:], true, cfg.allowReflectTypeValues, func(arg *flowir.Value) bool {
						return isPureErrorValue(arg, depth+1)
					})
				}
			}
		}
		return false
	}

	checkErrorSlot := func(lhsT types.Type, slotIdx int, rhs *flowir.Value, multiCall bool) bool {
		if !isUniverseErrorType(lhsT) {
			return true
		}
		if multiCall {
			csig := resolveVerifiedConeCallSig(rhs)
			return csig != nil && slotIdx >= 0 && slotIdx < csig.Results().Len() &&
				isUniverseErrorType(csig.Results().At(slotIdx).Type())
		}
		return isPureErrorValue(rhs, 0)
	}

	memoAssignNodes := map[ast.Node]bool{}
	for _, as := range cfg.memoAssigns {
		memoAssignNodes[as] = true
	}

	for _, sc := range scopes {
		okScope := true
		checkVal := func(v *flowir.Value) {
			if v == nil || !okScope {
				return
			}
			v.WalkValues(func(cur *flowir.Value) bool {
				if !okScope {
					return false
				}
				switch cur.Kind {
				case flowir.ValAddrOf:
					if isUniverseErrorType(cur.AddrPlace.Type) {
						okScope = false
						return false
					}
				case flowir.ValCall:
					if cur.CallKind == flowir.CallBuiltin && cur.BuiltinName == "panic" &&
						len(cur.Args) == 1 && cur.Args[0] != nil && isUniverseErrorType(cur.Args[0].Type) {
						if !isPureErrorValue(cur.Args[0], 0) {
							okScope = false
							return false
						}
						return true
					}
					if cur.CallKind == flowir.CallMethod && cur.Selection != nil && types.IsInterface(cur.Selection.Recv()) {
						if isUniverseErrorType(cur.Selection.Recv()) {
							if cur.CalleeFunc == nil || cur.CalleeFunc.Name() != "Error" ||
								len(cur.Args) != 0 || cur.Ellipsis || !isPureErrorValue(cur.Recv, 0) {
								okScope = false
								return false
							}
						}
						return true
					}
					if csig := resolveVerifiedConeCallSig(cur); csig != nil {
						nParams := csig.Params().Len()
						if len(cur.Args) == 1 && !cur.Ellipsis && cur.Args[0] != nil {
							if tup, isTuple := types.Unalias(cur.Args[0].Type).(*types.Tuple); isTuple && tup.Len() > 1 {
								if csig.Variadic() || tup.Len() != nParams {
									okScope = false
									return false
								}
								for pi := 0; pi < nParams; pi++ {
									if !checkErrorSlot(csig.Params().At(pi).Type(), pi, cur.Args[0], true) {
										okScope = false
										return false
									}
								}
								return true
							}
						}
						cur.ForEachArgParam(func(arg *flowir.Value, _ types.Type, _ int, paramIdx int, mapped bool, packedVariadic bool) bool {
							if !mapped || paramIdx < 0 || paramIdx >= nParams || arg == nil {
								okScope = false
								return false
							}
							pt := csig.Params().At(paramIdx).Type()
							if cur.Ellipsis && csig.Variadic() && paramIdx == nParams-1 {
								if typeReachesUniverseError(pt) && !arg.IsNil {
									okScope = false
									return false
								}
								return true
							}
							if packedVariadic {
								sl, okSL := types.Unalias(pt).Underlying().(*types.Slice)
								if !okSL {
									okScope = false
									return false
								}
								pt = sl.Elem()
							}
							if typeReachesUniverseError(pt) {
								if !isUniverseErrorType(pt) || !checkErrorSlot(pt, paramIdx, arg, false) {
									okScope = false
									return false
								}
							}
							return true
						})
						return okScope
					}
					if cur.CallKind == flowir.CallPlain && !cur.IsMethodExprCall && cur.CalleeFunc != nil &&
						cur.CalleeFunc.Pkg() != nil && cur.CalleeFunc.Pkg().Path() == "fmt" &&
						isTrueStdlibInPkg(p, "fmt") && cur.CalleeFunc.Name() == "Errorf" {
						if cur.Ellipsis || len(cur.Args) == 0 ||
							!verifyPureFmtFormatArgsFlowIR(p, cur.Args[0], cur.Args[1:], true, cfg.allowReflectTypeValues, func(arg *flowir.Value) bool {
								return isPureErrorValue(arg, 0)
							}) {
							okScope = false
							return false
						}
					}
				}
				return okScope
			})
		}

		sc.body.ForEachSyncOp(func(op *flowir.Op) bool {
			if !okScope {
				return false
			}
			switch op.Kind {
			case flowir.OpTypeSwitchBind:
				if op.SwitchDst != nil && isUniverseErrorType(op.SwitchDst.Type()) {
					okScope = false
					return false
				}
				checkVal(op.SwitchSrc)

			case flowir.OpAssign:
				for _, dst := range op.Dsts {
					dst.ForEachChildValue(func(cv *flowir.Value) bool {
						checkVal(cv)
						return okScope
					})
					if !okScope {
						return false
					}
				}
				for _, src := range op.Srcs {
					checkVal(src)
					if !okScope {
						return false
					}
				}

				if memoAssignNodes[op.StmtAST] {
					switch op.AssignKind {
					case flowir.AssignPlain:
						for i, dst := range op.Dsts {
							if len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjField && cfg.memoFields[dst.Projs[0].Field] {
								if i >= len(op.Srcs) || !checkErrorSlot(dst.Projs[0].Field.Type(), i, op.Srcs[i], false) {
									okScope = false
									return false
								}
							}
						}
					case flowir.AssignMulti:
						if len(op.Srcs) != 1 {
							okScope = false
							return false
						}
						for i, dst := range op.Dsts {
							if len(dst.Projs) == 1 && dst.Projs[0].Kind == flowir.ProjField && cfg.memoFields[dst.Projs[0].Field] {
								if !checkErrorSlot(dst.Projs[0].Field.Type(), i, op.Srcs[0], true) {
									okScope = false
									return false
								}
							}
						}
					default:
						okScope = false
						return false
					}
					return okScope
				}

				switch op.AssignKind {
				case flowir.AssignZeroDecl:
				case flowir.AssignRange:
					for _, dst := range op.Dsts {
						if isUniverseErrorType(dst.Type) {
							okScope = false
							return false
						}
					}
				case flowir.AssignPlain:
					for i, dst := range op.Dsts {
						if i >= len(op.Srcs) || !checkErrorSlot(dst.Type, i, op.Srcs[i], false) {
							okScope = false
							return false
						}
					}
				case flowir.AssignMulti:
					if len(op.Srcs) != 1 {
						for _, dst := range op.Dsts {
							if isUniverseErrorType(dst.Type) {
								okScope = false
								return false
							}
						}
						return true
					}
					for i, dst := range op.Dsts {
						if !checkErrorSlot(dst.Type, i, op.Srcs[0], true) {
							okScope = false
							return false
						}
					}
				default:
					for _, dst := range op.Dsts {
						if isUniverseErrorType(dst.Type) {
							okScope = false
							return false
						}
					}
				}

			case flowir.OpReturn:
				for _, r := range op.Results {
					checkVal(r)
					if !okScope {
						return false
					}
				}
				if len(op.Results) == 0 {
					return true
				}
				if len(op.Results) == 1 && sc.sig.Results().Len() > 1 {
					for ti := 0; ti < sc.sig.Results().Len(); ti++ {
						if !checkErrorSlot(sc.sig.Results().At(ti).Type(), ti, op.Results[0], true) {
							okScope = false
							return false
						}
					}
					return okScope
				}
				if len(op.Results) != sc.sig.Results().Len() {
					okScope = false
					return false
				}
				for ri, r := range op.Results {
					if !checkErrorSlot(sc.sig.Results().At(ri).Type(), ri, r, false) {
						okScope = false
						return false
					}
				}

			case flowir.OpExpr:
				checkVal(op.Expr)

			case flowir.OpDefer, flowir.OpGo:
				checkVal(op.Call)

			case flowir.OpChanSend:
				checkVal(op.ChanVal)
				checkVal(op.SendVal)
			}
			return okScope
		})
		if !okScope {
			return false
		}
	}
	return true
}
