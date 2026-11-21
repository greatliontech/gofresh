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
	if !syntaxutil.IsTrueStdlibInPkg(p, pkgPath) {
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
				return arg != nil && syntaxutil.IsErrorType(arg.Type)
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
			if types.IsInterface(sig.Results().At(i).Type()) && !syntaxutil.IsErrorType(sig.Results().At(i).Type()) {
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
	return syntaxutil.IsTrueStdlibInPkg(p, pkgPath) && auditset.InMemoryWriterPointerType(pkgPath, named.Obj().Name())
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
		if allowReflectType && syntaxutil.IsTrueStdlibInPkg(p, "reflect") && syntaxutil.IsNamedInPkg(arg.Type, "reflect", "Type") {
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
				if !syntaxutil.IsErrorType(pt) && (types.IsInterface(pt) || refconfine.TypeMayCarryUnknownDynamic(audited, pt)) {
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
			if syntaxutil.IsErrorType(pt) || arg.IsNil {
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
		if types.IsInterface(pv.Type()) && !syntaxutil.IsErrorType(pv.Type()) {
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
				if !types.IsInterface(v.Type()) || syntaxutil.IsErrorType(v.Type()) {
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
				if !types.IsInterface(v.Type()) || syntaxutil.IsErrorType(v.Type()) {
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
