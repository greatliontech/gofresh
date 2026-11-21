package dynstate

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type conePolicy struct {
	audited                bool
	allowMapRange          bool
	disallowedLitStructs   map[*types.Named]bool
	allowConfinedIfaceVars bool
	trustedPeerFuncs       map[*types.Func]bool
	allowReflectTypeValues bool
	allowRecursiveSelf     *types.Func
	allowedGlobalRead      func(*types.Var) bool
	isExemptPkgGlobalWrite func(op *flowir.Op, dst flowir.Place) bool
	isExemptCall           func(call *flowir.Value) bool
}

type flowIRConeUnit struct {
	sig  *types.Signature
	body *flowir.Body
}

func verifyDeterministicComputeCone(
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	funcDecls map[*types.Func]*ast.FuncDecl,
	rootSig *types.Signature,
	rootBody *flowir.Body,
	policy conePolicy,
) (coneFuncs map[*types.Func]*ast.FuncDecl, localClosures map[*types.Var]*flowir.Body, sawErrorSink bool, ok bool) {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || rootSig == nil || rootBody == nil {
		return nil, nil, false, false
	}
	if rootBody.HasGoto {
		return nil, nil, false, false
	}
	if policy.allowReflectTypeValues && !isTrueStdlibInPkg(p, "reflect") {
		policy.allowReflectTypeValues = false
	}
	for pi := 0; pi < rootSig.Params().Len(); pi++ {
		if typeReachesUniverseError(rootSig.Params().At(pi).Type()) {
			sawErrorSink = true
			break
		}
	}

	coneFuncs = map[*types.Func]*ast.FuncDecl{}
	localClosures = map[*types.Var]*flowir.Body{}
	queue := []flowIRConeUnit{{sig: rootSig, body: rootBody}}

	for len(queue) > 0 {
		unit := queue[0]
		queue = queue[1:]
		if unit.sig == nil || unit.body == nil || unit.body.HasGoto {
			return nil, nil, false, false
		}

		localClos, allowedClosureVals := collectConfinedLocalClosuresInBody(p, fc, idx, unit.body)
		for lv, closBody := range localClos {
			closSig, okSig := lv.Type().Underlying().(*types.Signature)
			if !okSig || closBody == nil || closBody.HasGoto {
				return nil, nil, false, false
			}
			if _, seen := localClosures[lv]; !seen {
				localClosures[lv] = closBody
				queue = append(queue, flowIRConeUnit{sig: closSig, body: closBody})
			}
		}

		var allowedIfaceVars map[*types.Var]bool
		if policy.allowConfinedIfaceVars {
			allowedIfaceVars = collectConfinedCallerInterfaceVarsFlowIR(p, idx, unit.sig, unit.body)
		}

		okUnit := true
		var checkBody func(b *flowir.Body)
		checkValue := func(v *flowir.Value) {
			if v == nil || !okUnit {
				return
			}
			v.WalkValues(func(cur *flowir.Value) bool {
				if !okUnit {
					return false
				}
				switch cur.Kind {
				case flowir.ValInvalid, flowir.ValChanRecv, flowir.ValMethodVal:
					okUnit = false
					return false

				case flowir.ValAddrOf:
					if placeTouchesPkgGlobal(p, cur.AddrPlace) {
						okUnit = false
						return false
					}

				case flowir.ValPlace:
					switch cur.Place.Root {
					case flowir.RootPkgGlobal:
						if cur.Place.Obj == nil || policy.allowedGlobalRead == nil || !policy.allowedGlobalRead(cur.Place.Obj) {
							okUnit = false
							return false
						}
					case flowir.RootFunc:
						if cur.Place.IsMethodExpr || cur.Place.Func == nil || cur.Place.Func.Origin() != cur.Place.Func || cur.Place.Func.Pkg() == nil {
							okUnit = false
							return false
						}
						fnObj := cur.Place.Func
						sig, okSig := fnObj.Type().(*types.Signature)
						if !okSig || sig.Recv() != nil {
							okUnit = false
							return false
						}
						if fnObj.Pkg() == p.Types {
							cfd := funcDecls[fnObj]
							cbody := fc.funcBody(p, cfd)
							if cfd == nil || cbody == nil || cbody.HasGoto {
								okUnit = false
								return false
							}
							if _, seen := coneFuncs[fnObj]; !seen {
								coneFuncs[fnObj] = cfd
								queue = append(queue, flowIRConeUnit{sig: sig, body: cbody})
							}
						} else if !isPureDeterministicConeStdlibFuncValue(p, fnObj, sig) {
							okUnit = false
							return false
						}
					}

				case flowir.ValAllocFresh:
					if cur.AllocKind == flowir.AllocCompositeLit && len(policy.disallowedLitStructs) > 0 && cur.ElemType != nil {
						if cn, isN := types.Unalias(cur.ElemType).(*types.Named); isN && policy.disallowedLitStructs[cn.Origin()] {
							okUnit = false
							return false
						}
					}

				case flowir.ValConvert:
					if syntaxutil.IsUnsafePointerType(cur.Type) {
						okUnit = false
						return false
					}

				case flowir.ValCompare:
					if (cur.CompareOp == token.EQL || cur.CompareOp == token.NEQ) &&
						isDisallowedConePointerComparison(cur, policy.allowReflectTypeValues) {
						okUnit = false
						return false
					}

				case flowir.ValMakeClosure:
					if !allowedClosureVals[cur] {
						okUnit = false
						return false
					}

				case flowir.ValCall:
					if policy.isExemptCall != nil && policy.isExemptCall(cur) {
						return true
					}
					if cur.IsMethodExprCall || cur.CallKind == flowir.CallIIFE {
						okUnit = false
						return false
					}
					switch cur.CallKind {
					case flowir.CallBuiltin:
						switch cur.BuiltinName {
						case "recover", "close", "println", "print", "Add", "Slice", "SliceData", "String", "StringData":
							okUnit = false
							return false
						case "delete", "clear", "copy", "append":
							if len(cur.Args) > 0 && valueTouchesPkgGlobal(p, cur.Args[0]) {
								okUnit = false
								return false
							}
						case "panic":
							if len(cur.Args) != 1 || cur.Ellipsis || cur.Args[0] == nil {
								okUnit = false
								return false
							}
							pt := cur.Args[0].Type
							if isUniverseErrorType(pt) {
								sawErrorSink = true
							} else if !isScalarBasicType(pt) {
								okUnit = false
								return false
							}
						case "len", "cap", "min", "max", "complex", "real", "imag", "Sizeof", "Alignof", "Offsetof":
						default:
							okUnit = false
							return false
						}

					case flowir.CallIndirect:
						if cur.Callee == nil || cur.Callee.Kind != flowir.ValPlace || !cur.Callee.Place.IsBareVar() || localClos[cur.Callee.Place.Obj] == nil {
							okUnit = false
							return false
						}
						if policy.allowConfinedIfaceVars {
							hasErr, argsOK := checkConeCallIfaceArgsFlowIR(policy.audited, cur, allowedIfaceVars)
							if !argsOK {
								okUnit = false
								return false
							}
							if hasErr {
								sawErrorSink = true
							}
						}

					case flowir.CallMethod, flowir.CallPlain:
						if cur.CallKind == flowir.CallMethod && cur.Selection != nil && types.IsInterface(cur.Selection.Recv()) {
							recvT := cur.Selection.Recv()
							if policy.allowReflectTypeValues && syntaxutil.IsNamedInPkg(recvT, "reflect", "Type") {
								if cur.CalleeFunc == nil || !isAllowedReflectTypeMethod(cur.CalleeFunc.Name()) {
									okUnit = false
									return false
								}
								return true
							}
							if policy.allowConfinedIfaceVars {
								if isUniverseErrorType(recvT) && cur.CalleeFunc != nil && cur.CalleeFunc.Name() == "Error" && len(cur.Args) == 0 && !cur.Ellipsis {
									sawErrorSink = true
									return true
								}
								if cur.Recv != nil && cur.Recv.Kind == flowir.ValPlace && cur.Recv.Place.IsBareVar() && allowedIfaceVars[cur.Recv.Place.Obj] {
									return true
								}
							}
							okUnit = false
							return false
						}

						callee := cur.CalleeFunc
						if callee == nil || callee.Origin() != callee || callee.Pkg() == nil {
							okUnit = false
							return false
						}
						if policy.allowRecursiveSelf != nil && callee == policy.allowRecursiveSelf {
							return true
						}
						if policy.trustedPeerFuncs[callee] {
							if policy.allowConfinedIfaceVars {
								hasErr, argsOK := checkConeCallIfaceArgsFlowIR(policy.audited, cur, allowedIfaceVars)
								if !argsOK {
									okUnit = false
									return false
								}
								if hasErr {
									sawErrorSink = true
								}
							}
							return true
						}
						if callee.Pkg() == p.Types {
							csig, okSig := callee.Type().(*types.Signature)
							cfd := funcDecls[callee]
							cbody := fc.funcBody(p, cfd)
							if !okSig || cfd == nil || cbody == nil || cbody.HasGoto {
								okUnit = false
								return false
							}
							if policy.allowConfinedIfaceVars {
								hasErr, argsOK := checkConeCallIfaceArgsFlowIR(policy.audited, cur, allowedIfaceVars)
								if !argsOK {
									okUnit = false
									return false
								}
								if hasErr {
									sawErrorSink = true
								}
							}
							if _, seen := coneFuncs[callee]; !seen {
								coneFuncs[callee] = cfd
								queue = append(queue, flowIRConeUnit{sig: csig, body: cbody})
							}
							return true
						}
						if !isPureDeterministicConeStdlibCallFlowIR(p, cur, policy.allowReflectTypeValues, &sawErrorSink) {
							okUnit = false
							return false
						}

					default:
						okUnit = false
						return false
					}
				}
				return okUnit
			})
		}

		checkBody = func(b *flowir.Body) {
			if b == nil || !okUnit {
				return
			}
			for i := range b.Ops {
				if !okUnit {
					return
				}
				op := &b.Ops[i]
				switch op.Kind {
				case flowir.OpGo, flowir.OpChanSend:
					okUnit = false
					return

				case flowir.OpDefer:
					if policy.isExemptCall == nil || op.Call == nil || !policy.isExemptCall(op.Call) {
						okUnit = false
						return
					}

				case flowir.OpAssign:
					if op.AssignKind == flowir.AssignRange {
						if len(op.Srcs) == 0 || op.Srcs[0] == nil || op.Srcs[0].Type == nil {
							okUnit = false
							return
						}
						switch syntaxutil.UnderlyingType(op.Srcs[0].Type).(type) {
						case *types.Chan, *types.Signature:
							okUnit = false
							return
						case *types.Map:
							if !policy.allowMapRange {
								okUnit = false
								return
							}
						}
					}
					for _, dst := range op.Dsts {
						if placeTouchesPkgGlobal(p, dst) &&
							(policy.isExemptPkgGlobalWrite == nil || !policy.isExemptPkgGlobalWrite(op, dst)) {
							okUnit = false
							return
						}
						dst.ForEachChildValue(func(cv *flowir.Value) bool {
							checkValue(cv)
							return okUnit
						})
						if !okUnit {
							return
						}
					}
					for _, src := range op.Srcs {
						checkValue(src)
						if !okUnit {
							return
						}
					}
					if op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
						checkBody(op.RangeBody)
					}

				case flowir.OpReturn:
					for _, r := range op.Results {
						checkValue(r)
						if !okUnit {
							return
						}
					}

				case flowir.OpTypeSwitchBind:
					checkValue(op.SwitchSrc)

				case flowir.OpExpr:
					if sw, isSw := op.StmtAST.(*ast.SwitchStmt); isSw && sw.Tag != nil {
						if isDisallowedConePointerSwitch(sw, p.TypesInfo, policy.allowReflectTypeValues) {
							okUnit = false
							return
						}
					}
					checkValue(op.Expr)
				}
			}
		}

		checkBody(unit.body)
		if !okUnit {
			return nil, nil, false, false
		}
	}

	return coneFuncs, localClosures, sawErrorSink, true
}

func collectConfinedLocalClosuresInBody(
	p *packages.Package,
	fc *pkgFlowCache,
	idx *refconfine.PkgIndex,
	b *flowir.Body,
) (map[*types.Var]*flowir.Body, map[*flowir.Value]bool) {
	res := map[*types.Var]*flowir.Body{}
	allowedVals := map[*flowir.Value]bool{}
	if b == nil {
		return res, allowedVals
	}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind != flowir.OpAssign || op.AssignKind != flowir.AssignPlain {
			return true
		}
		op.ForEachAssignPair(func(_ int, dst flowir.Place, isDef bool, src *flowir.Value) bool {
			if !isDef || !dst.IsBareVar() || dst.Root != flowir.RootLocal || dst.Obj == nil ||
				src == nil || src.Kind != flowir.ValMakeClosure || src.Closure == nil {
				return true
			}
			if isConfinedDirectCallClosureVar(p, fc, idx, dst.Obj) {
				res[dst.Obj] = src.Closure
				allowedVals[src] = true
			}
			return true
		})
		return true
	})
	return res, allowedVals
}

func placeTouchesPkgGlobal(p *packages.Package, pl flowir.Place) bool {
	if pl.Root == flowir.RootPkgGlobal {
		return true
	}
	hit := false
	flowir.ForEachPlaceRootVar(pl, func(rv *types.Var) {
		if rv != nil && !rv.IsField() && rv.Pkg() != nil && rv.Parent() == rv.Pkg().Scope() {
			hit = true
		}
	})
	if hit {
		return true
	}
	if p != nil && pl.Raw != nil && lookupRootPkgScopeVarAnyPkg(p, pl.Raw) != nil {
		return true
	}
	return false
}

func valueTouchesPkgGlobal(p *packages.Package, val *flowir.Value) bool {
	if val == nil {
		return false
	}
	hit := false
	flowir.ForEachValueRootVar(val, func(rv *types.Var) {
		if rv != nil && !rv.IsField() && rv.Pkg() != nil && rv.Parent() == rv.Pkg().Scope() {
			hit = true
		}
	})
	if hit {
		return true
	}
	return p != nil && val.Raw != nil && lookupRootPkgScopeVarAnyPkg(p, val.Raw) != nil
}

func typeExposesComparablePointerIdentity(t types.Type, allowReflectType bool) bool {
	if t == nil {
		return false
	}
	seen := map[types.Type]bool{}
	var walk func(cur types.Type) bool
	walk = func(cur types.Type) bool {
		if cur == nil {
			return false
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return false
		}
		seen[cur] = true
		if allowReflectType && syntaxutil.IsNamedInPkg(cur, "reflect", "Type") {
			return false
		}
		switch u := cur.Underlying().(type) {
		case *types.Pointer, *types.Interface, *types.Chan, *types.Signature:
			return true
		case *types.Array:
			return u.Len() > 0 && walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if f := u.Field(i); f.Name() != "_" && walk(f.Type()) {
					return true
				}
			}
		}
		return false
	}
	return walk(t)
}

func isDisallowedConePointerComparison(v *flowir.Value, allowReflectType bool) bool {
	if v == nil || v.Left == nil || v.Right == nil {
		return false
	}
	if v.Left.IsNil || v.Right.IsNil {
		return false
	}
	return typeExposesComparablePointerIdentity(v.Left.Type, allowReflectType) ||
		typeExposesComparablePointerIdentity(v.Right.Type, allowReflectType)
}

func isDisallowedConePointerSwitch(sw *ast.SwitchStmt, info *types.Info, allowReflectType bool) bool {
	if sw == nil || sw.Tag == nil || sw.Body == nil || info == nil {
		return false
	}
	tagT := info.TypeOf(sw.Tag)
	if !typeExposesComparablePointerIdentity(tagT, allowReflectType) {
		return false
	}
	for _, raw := range sw.Body.List {
		cc, ok := raw.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, ce := range cc.List {
			if !syntaxutil.IsNilIdent(info, ce) {
				return true
			}
		}
	}
	return false
}

func isAllowedReflectTypeMethod(name string) bool {
	switch name {
	case "Elem", "Field", "Key", "Kind", "Len", "Name", "NumField", "PkgPath",
		"Implements", "AssignableTo", "ConvertibleTo", "Comparable",
		"Bits", "Size", "Align", "FieldAlign", "String":
		return true
	default:
		return false
	}
}

func isPureDeterministicConeStdlibFuncValue(p *packages.Package, fn *types.Func, sig *types.Signature) bool {
	if fn == nil || fn.Pkg() == nil || sig == nil || sig.Recv() != nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	if !isTrueStdlibInPkg(p, pkgPath) {
		return false
	}
	traits := auditset.DeterministicStdCallTraits(pkgPath, fn.Name())
	if !traits.PureScalarOrValue || pkgPath == "errors" || pkgPath == "reflect" || pkgPath == "math" {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		pt := sig.Params().At(i).Type()
		if refconfine.TypeMayCarryUnknownDynamic(true, pt) || refconfine.TypeCarriesSignature(pt) || refconfine.TypeCarriesMutableRef(pt) {
			return false
		}
	}
	for i := 0; i < sig.Results().Len(); i++ {
		rt := sig.Results().At(i).Type()
		if refconfine.TypeMayCarryUnknownDynamic(true, rt) && !isUniverseErrorType(rt) {
			return false
		}
		if refconfine.TypeCarriesSignature(rt) {
			return false
		}
	}
	return true
}

func isTrueStdlibInPkg(p *packages.Package, pkgPath string) bool {
	return syntaxutil.IsTrueStdlibInPkg(p, pkgPath)
}

func isPureDeterministicConeStdlibCallFlowIR(
	p *packages.Package,
	call *flowir.Value,
	allowReflectType bool,
	sawErrorSink *bool,
) bool {
	if call == nil || call.CalleeFunc == nil || call.CalleeFunc.Pkg() == nil {
		return false
	}
	callee := call.CalleeFunc
	pkgPath := callee.Pkg().Path()
	name := callee.Name()
	if !isTrueStdlibInPkg(p, pkgPath) {
		return false
	}

	traits := auditset.DeterministicStdCallTraits(pkgPath, name)
	if traits.InPlaceContainerMutate {
		return len(call.Args) == 1 && !call.Ellipsis && !valueTouchesPkgGlobal(p, call.Args[0])
	}

	switch pkgPath {
	case "errors":
		return name == "New"

	case "fmt":
		switch name {
		case "Errorf":
			if call.Ellipsis || len(call.Args) == 0 {
				return false
			}
			ok := verifyPureFmtFormatArgsFlowIR(p, call.Args[0], call.Args[1:], true, allowReflectType, func(arg *flowir.Value) bool {
				return arg != nil && isUniverseErrorType(arg.Type)
			})
			if ok && sawErrorSink != nil {
				*sawErrorSink = true
			}
			return ok
		case "Sprintf":
			if call.Ellipsis || len(call.Args) == 0 {
				return false
			}
			return verifyPureFmtFormatArgsFlowIR(p, call.Args[0], call.Args[1:], false, allowReflectType, nil)
		case "Fprintf":
			if call.Ellipsis || len(call.Args) < 2 || !isLocalInMemoryWriterAddrFlowIR(p, call.Args[0]) {
				return false
			}
			return verifyPureFmtFormatArgsFlowIR(p, call.Args[1], call.Args[2:], false, allowReflectType, nil)
		case "Sprint", "Sprintln":
			for _, a := range call.Args {
				if a == nil || !isScalarBasicType(a.Type) {
					return false
				}
			}
			return true
		default:
			return false
		}

	case "reflect":
		if !allowReflectType {
			return false
		}
		if call.CallKind == flowir.CallMethod && call.Selection != nil {
			if syntaxutil.IsNamedInPkg(call.Selection.Recv(), "reflect", "StructTag") {
				return name == "Get" || name == "Lookup"
			}
			if syntaxutil.IsNamedInPkg(call.Selection.Recv(), "reflect", "Kind") {
				return name == "String"
			}
			return false
		}
		return traits.PureScalarOrValue

	case "strings", "bytes":
		sig, ok := callee.Type().(*types.Signature)
		if !ok {
			return false
		}
		for i := 0; i < sig.Params().Len(); i++ {
			if types.IsInterface(sig.Params().At(i).Type()) {
				return false
			}
		}
		for i := 0; i < sig.Results().Len(); i++ {
			if types.IsInterface(sig.Results().At(i).Type()) && !isUniverseErrorType(sig.Results().At(i).Type()) {
				return false
			}
		}
		return true

	case "slices":
		return traits.ReadOnlySliceCopy || traits.ReadOnlySliceInspect

	default:
		return traits.PureScalarOrValue && pkgPath != "math"
	}
}

func isLocalInMemoryWriterAddrFlowIR(p *packages.Package, v *flowir.Value) bool {
	if v == nil || v.Kind != flowir.ValAddrOf || v.IsArraySlice || !v.AddrPlace.IsBareVar() || v.AddrPlace.Root != flowir.RootLocal || v.AddrPlace.Obj == nil {
		return false
	}
	named, ok := types.Unalias(v.AddrPlace.Obj.Type()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	pkgPath := named.Obj().Pkg().Path()
	return isTrueStdlibInPkg(p, pkgPath) && auditset.InMemoryWriterPointerType(pkgPath, named.Obj().Name())
}

func verifyPureFmtFormatArgsFlowIR(
	p *packages.Package,
	fmtVal *flowir.Value,
	args []*flowir.Value,
	allowErrW bool,
	allowReflectType bool,
	isPureErr func(*flowir.Value) bool,
) bool {
	if p == nil || p.TypesInfo == nil || fmtVal == nil || fmtVal.Raw == nil {
		return false
	}
	tv := p.TypesInfo.Types[fmtVal.Raw]
	if tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	fmtStr := constant.StringVal(tv.Value)
	argIdx := 0
	ok := auditset.ScanFmtDirectives(fmtStr, func(d auditset.FmtDirective) bool {
		if d.HasArgIndex || d.DynamicWidth || d.DynamicPrec || d.Verb == '%' || d.ExposesPointerIdentity() {
			return false
		}
		if argIdx >= len(args) {
			return false
		}
		arg := args[argIdx]
		argIdx++
		if arg == nil {
			return false
		}
		if d.Verb == 'w' {
			return allowErrW && isPureErr != nil && isPureErr(arg)
		}
		if allowReflectType && isTrueStdlibInPkg(p, "reflect") && syntaxutil.IsNamedInPkg(arg.Type, "reflect", "Type") {
			return d.InvokesStringerOnly()
		}
		return isScalarBasicType(arg.Type)
	})
	return ok && argIdx == len(args)
}

func checkConeCallIfaceArgsFlowIR(
	audited bool,
	call *flowir.Value,
	allowedIfaceVars map[*types.Var]bool,
) (hasErrParam bool, ok bool) {
	if call == nil || call.CalleeSig == nil {
		return false, false
	}
	csig := call.CalleeSig
	nParams := csig.Params().Len()
	for pi := 0; pi < nParams; pi++ {
		if typeReachesUniverseError(csig.Params().At(pi).Type()) {
			hasErrParam = true
			break
		}
	}
	if len(call.Args) == 1 && !call.Ellipsis && call.Args[0] != nil {
		if tup, isTuple := types.Unalias(call.Args[0].Type).(*types.Tuple); isTuple && tup.Len() > 1 {
			if csig.Variadic() || tup.Len() != nParams {
				return hasErrParam, false
			}
			for pi := 0; pi < nParams; pi++ {
				pt := csig.Params().At(pi).Type()
				if !isUniverseErrorType(pt) && (types.IsInterface(pt) || refconfine.TypeMayCarryUnknownDynamic(audited, pt)) {
					return hasErrParam, false
				}
			}
			return hasErrParam, true
		}
	}

	argsOK := true
	call.ForEachArgParam(func(arg *flowir.Value, _ types.Type, _ int, paramIdx int, mapped bool, packedVariadic bool) bool {
		if !mapped || paramIdx < 0 || paramIdx >= nParams || arg == nil {
			argsOK = false
			return false
		}
		pt := csig.Params().At(paramIdx).Type()
		if call.Ellipsis && csig.Variadic() && paramIdx == nParams-1 {
			if !typeReachesUniverseError(pt) && refconfine.TypeMayCarryUnknownDynamic(audited, pt) && !arg.IsNil {
				argsOK = false
				return false
			}
			return true
		}
		if packedVariadic {
			sl, okSL := types.Unalias(pt).Underlying().(*types.Slice)
			if !okSL {
				argsOK = false
				return false
			}
			pt = sl.Elem()
		}
		if types.IsInterface(pt) {
			if isUniverseErrorType(pt) || arg.IsNil {
				return true
			}
			if arg.Kind == flowir.ValPlace && arg.Place.IsBareVar() && allowedIfaceVars[arg.Place.Obj] {
				return true
			}
			argsOK = false
			return false
		}
		if !typeReachesUniverseError(pt) && refconfine.TypeMayCarryUnknownDynamic(audited, pt) && !arg.IsNil {
			argsOK = false
			return false
		}
		return true
	})
	return hasErrParam, argsOK
}

func collectConfinedCallerInterfaceVarsFlowIR(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	sig *types.Signature,
	b *flowir.Body,
) map[*types.Var]bool {
	allowed := map[*types.Var]bool{}
	if sig == nil || b == nil {
		return allowed
	}
	candidates := map[*types.Var]bool{}
	for i := 0; i < sig.Params().Len(); i++ {
		pv := sig.Params().At(i)
		if types.IsInterface(pv.Type()) && !isUniverseErrorType(pv.Type()) {
			candidates[pv] = true
			allowed[pv] = true
		}
	}
	if len(candidates) == 0 {
		return allowed
	}

	type localDef struct {
		srcs  []*flowir.Value
		slots []int
		multi []bool
		bad   bool
	}
	localDefs := map[*types.Var]*localDef{}
	b.ForEachSyncOp(func(op *flowir.Op) bool {
		if op.Kind != flowir.OpAssign {
			return true
		}
		switch op.AssignKind {
		case flowir.AssignPlain:
			for i, dst := range op.Dsts {
				if !dst.IsBareVar() || dst.Obj == nil {
					continue
				}
				v := dst.Obj
				if candidates[v] {
					delete(allowed, v)
					continue
				}
				if !types.IsInterface(v.Type()) || isUniverseErrorType(v.Type()) {
					continue
				}
				d := localDefs[v]
				if d == nil {
					d = &localDef{}
					localDefs[v] = d
				}
				if i >= len(op.Srcs) || op.Srcs[i] == nil {
					d.bad = true
					continue
				}
				d.srcs = append(d.srcs, op.Srcs[i])
				d.slots = append(d.slots, i)
				d.multi = append(d.multi, false)
			}
		case flowir.AssignMulti:
			for i, dst := range op.Dsts {
				if !dst.IsBareVar() || dst.Obj == nil {
					continue
				}
				v := dst.Obj
				if candidates[v] {
					delete(allowed, v)
					continue
				}
				if !types.IsInterface(v.Type()) || isUniverseErrorType(v.Type()) {
					continue
				}
				d := localDefs[v]
				if d == nil {
					d = &localDef{}
					localDefs[v] = d
				}
				if len(op.Srcs) != 1 || op.Srcs[0] == nil {
					d.bad = true
					continue
				}
				d.srcs = append(d.srcs, op.Srcs[0])
				d.slots = append(d.slots, i)
				d.multi = append(d.multi, true)
			}
		default:
			for _, dst := range op.Dsts {
				if dst.Obj != nil {
					if candidates[dst.Obj] {
						delete(allowed, dst.Obj)
					} else if d := localDefs[dst.Obj]; d != nil {
						d.bad = true
					}
				}
			}
		}
		return true
	})

	for changed := true; changed; {
		changed = false
		for lv, d := range localDefs {
			if allowed[lv] || d.bad || len(d.srcs) == 0 {
				continue
			}
			allOK := true
			for k, src := range d.srcs {
				if src.Kind != flowir.ValCall || src.CallKind != flowir.CallMethod || src.IsMethodExprCall ||
					src.Selection == nil || !types.IsInterface(src.Selection.Recv()) ||
					src.Recv == nil || src.Recv.Kind != flowir.ValPlace || !src.Recv.Place.IsBareVar() ||
					!allowed[src.Recv.Place.Obj] {
					allOK = false
					break
				}
				if d.multi[k] {
					msig := src.CalleeSig
					if msig == nil || d.slots[k] >= msig.Results().Len() || !types.Identical(msig.Results().At(d.slots[k]).Type(), lv.Type()) {
						allOK = false
						break
					}
				}
			}
			if allOK {
				allowed[lv] = true
				changed = true
			}
		}
	}

	for v := range allowed {
		for _, uid := range idx.UsesOf[v] {
			par := idx.ParentUnparen(uid)
			switch x := par.(type) {
			case *ast.SelectorExpr:
				if ast.Unparen(x.X) != uid {
					delete(allowed, v)
				}
			case *ast.BinaryExpr:
				if (x.Op != token.EQL && x.Op != token.NEQ) || (!syntaxutil.IsNilIdent(p.TypesInfo, x.X) && !syntaxutil.IsNilIdent(p.TypesInfo, x.Y)) {
					delete(allowed, v)
				}
			case *ast.CallExpr:
				if ast.Unparen(x.Fun) == uid ||
					p.TypesInfo.Types[ast.Unparen(x.Fun)].IsType() ||
					syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(x.Fun)) != nil {
					delete(allowed, v)
				}
			default:
				delete(allowed, v)
			}
			if !allowed[v] {
				break
			}
		}
	}
	return allowed
}
