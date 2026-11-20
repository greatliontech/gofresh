package closure

import (
	"context"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/trace"
)

type streamKind uint8

const (
	streamKindWriter streamKind = iota
	streamKindReader
)

func (k streamKind) String() string {
	if k == streamKindReader {
		return "reader"
	}
	return "writer"
}

type wrapperKind uint8

const (
	wrapperNone wrapperKind = iota
	wrapperBufioWriter
	wrapperTabwriter
	wrapperBufioReader
)

type wrapperCallFrame struct {
	resultVal ssa.Value
	tupleIdx  int
}

func wrapperKindOfType(ct types.Type) wrapperKind {
	pkgPath, name, isPtr, matched := isNamedTypeOrPtr(ct)
	if !matched || !isPtr {
		return wrapperNone
	}
	switch {
	case pkgPath == "bufio" && name == "Writer":
		return wrapperBufioWriter
	case pkgPath == "text/tabwriter" && name == "Writer":
		return wrapperTabwriter
	case pkgPath == "bufio" && name == "Reader":
		return wrapperBufioReader
	default:
		return wrapperNone
	}
}

func emitStreamReject(ctx context.Context, site ssa.CallInstruction, kind streamKind, reason string, fp *freshParamAnalysis) {
	if !trace.AnyEnabled() {
		return
	}
	target := ""
	if fp != nil && fp.subjectRoot != nil {
		target = fp.subjectRoot.String()
	} else if site != nil && site.Parent() != nil {
		target = site.Parent().String()
	}
	if !trace.Enabled(ctx, trace.DomainClosure, target) {
		return
	}
	calleeStr, posStr := "", ""
	if site != nil {
		if site.Common() != nil && site.Common().StaticCallee() != nil {
			calleeStr = site.Common().StaticCallee().String()
		}
		if site.Parent() != nil && site.Parent().Prog != nil && site.Parent().Prog.Fset != nil && site.Pos().IsValid() {
			posStr = site.Parent().Prog.Fset.Position(site.Pos()).String()
		}
	}
	trace.Emit(ctx, trace.DomainClosure, "closure.stream.reject", target,
		trace.String("kind", kind.String()),
		trace.String("callee", calleeStr),
		trace.String("reason", reason),
		trace.String("pos", posStr),
	)
}

func inMemoryStreamOperand(ctx context.Context, site ssa.CallInstruction, val ssa.Value, kind streamKind, fp *freshParamAnalysis) bool {
	ok, reason := inMemoryStreamValue(val, kind, fp, 0, nil)
	if !ok {
		emitStreamReject(ctx, site, kind, reason, fp)
	}
	return ok
}

func isNamedTypeOrPtr(t types.Type) (pkgPath, typeName string, isPtr bool, ok bool) {
	if t == nil {
		return "", "", false, false
	}
	u := types.Unalias(t)
	if ptr, pOK := u.(*types.Pointer); pOK {
		isPtr = true
		u = types.Unalias(ptr.Elem())
	}
	named, nOK := u.(*types.Named)
	if !nOK || named.Obj() == nil || named.Obj().Pkg() == nil {
		return "", "", false, false
	}
	return named.Obj().Pkg().Path(), named.Obj().Name(), isPtr, true
}

func isAdmittedPureHashConcreteType(audited bool, ct types.Type) bool {
	if !audited || ct == nil || typeMayCarryDynamicTop(audited, ct) {
		return false
	}
	pkgPath, _, _, ok := isNamedTypeOrPtr(ct)
	if !ok {
		return false
	}
	if auditset.PureHashPackage(pkgPath) {
		return true
	}
	if after, okFIPS := strings.CutPrefix(pkgPath, "crypto/internal/fips140/"); okFIPS {
		return auditset.PureHashPackage("crypto/" + after)
	}
	return false
}

func isStatelessStreamConcreteType(audited bool, ct types.Type, kind streamKind) bool {
	pkgPath, name, isPtr, ok := isNamedTypeOrPtr(ct)
	if !ok {
		return false
	}
	if kind == streamKindWriter {
		if isPtr && auditset.InMemoryWriterPointerType(pkgPath, name) {
			return true
		}
		if pkgPath == "io" && name == "discard" {
			return true
		}
		return isAdmittedPureHashConcreteType(audited, ct)
	}
	return isPtr && (auditset.InMemoryReaderPointerType(pkgPath, name) || (pkgPath == "fmt" && name == "stringReader"))
}

func classifyStatefulStreamType(ct types.Type, kind streamKind) (isHMAC bool, wk wrapperKind, ok bool) {
	pkgPath, name, isPtr, matched := isNamedTypeOrPtr(ct)
	if !matched || !isPtr {
		return false, wrapperNone, false
	}
	if kind == streamKindWriter {
		switch {
		case (pkgPath == "crypto/internal/fips140/hmac" && name == "HMAC") || (pkgPath == "crypto/hmac" && name == "hmac"):
			return true, wrapperNone, true
		case pkgPath == "bufio" && name == "Writer":
			return false, wrapperBufioWriter, true
		case pkgPath == "text/tabwriter" && name == "Writer":
			return false, wrapperTabwriter, true
		}
		return false, wrapperNone, false
	}
	if pkgPath == "bufio" && name == "Reader" {
		return false, wrapperBufioReader, true
	}
	return false, wrapperNone, false
}

func inMemoryStreamValue(val ssa.Value, kind streamKind, fp *freshParamAnalysis, depth int, callStack map[*ssa.Function]wrapperCallFrame) (bool, string) {
	if fp == nil || !fp.selectionAudited {
		return false, "unaudited_or_nil_fp"
	}
	if val == nil || val.Type() == nil || depth > 16 {
		return false, "nil_or_depth_exceeded"
	}
	if cnst, isConst := val.(*ssa.Const); isConst && cnst.Value == nil {
		return false, "nil_const_stream"
	}
	for val != nil {
		switch u := val.(type) {
		case *ssa.MakeInterface:
			if u.X == nil || u.X.Type() == nil {
				return false, "nil_make_interface"
			}
			val = u.X
			continue
		case *ssa.ChangeInterface:
			if u.X == nil || u.X.Type() == nil {
				return false, "nil_change_interface"
			}
			val = u.X
			continue
		case *ssa.ChangeType:
			if isStatelessStreamConcreteType(fp.selectionAudited, u.Type(), kind) {
				return true, ""
			}
			if u.X == nil || u.X.Type() == nil {
				return false, "nil_change_type"
			}
			val = u.X
			continue
		}
		break
	}
	if cnst, isConst := val.(*ssa.Const); isConst && cnst.Value == nil {
		return false, "nil_const_stream"
	}
	audited := fp.selectionAudited
	if _, isIface := types.Unalias(val.Type()).Underlying().(*types.Interface); !isIface {
		ct := val.Type()
		if isStatelessStreamConcreteType(audited, ct, kind) {
			return true, ""
		}
		if _, _, ok := classifyStatefulStreamType(ct, kind); ok {
			return verifyStatefulStreamOrigin(val, kind, fp, depth, callStack)
		}
		return false, "unsupported_concrete_type:" + ct.String()
	}

	evalFP, collectFP, rootDone, propagate := newDispatchWalkStates(fp)
	if !walkDynamicValue(val, nil, make(map[ssa.Value]bool), rootDone, evalFP) {
		propagate()
		return false, "open_interface_stream"
	}
	concreteTypes := make(map[types.Type]bool)
	if !walkDynamicValue(val, &dynamicValueCollector{types: concreteTypes}, make(map[ssa.Value]bool), nil, collectFP) {
		propagate()
		return false, "open_interface_stream"
	}
	propagate()
	if len(concreteTypes) == 0 {
		return false, "empty_interface_stream"
	}
	needOriginProvenance := false
	for ct := range concreteTypes {
		if isStatelessStreamConcreteType(audited, ct, kind) {
			continue
		}
		if _, _, ok := classifyStatefulStreamType(ct, kind); ok {
			needOriginProvenance = true
			continue
		}
		return false, "unsupported_boxed_type:" + ct.String()
	}
	if !needOriginProvenance {
		return true, ""
	}
	return verifyStatefulStreamOrigin(val, kind, fp, depth, callStack)
}

func verifyStatefulStreamOrigin(val ssa.Value, kind streamKind, fp *freshParamAnalysis, depth int, callStack map[*ssa.Function]wrapperCallFrame) (bool, string) {
	type originVerdict struct {
		ok  bool
		why string
	}
	topMemo := map[ssa.Value]originVerdict{}
	inStack := map[ssa.Value]bool{}
	var walkOrigin func(cur ssa.Value, curFP *freshParamAnalysis, curDepth int, curStack map[*ssa.Function]wrapperCallFrame) (bool, string)
	walkOrigin = func(cur ssa.Value, curFP *freshParamAnalysis, curDepth int, curStack map[*ssa.Function]wrapperCallFrame) (bool, string) {
		if cur == nil || cur.Type() == nil {
			return false, "nil_origin"
		}
		if curDepth > 16 {
			return false, "nil_or_depth_exceeded"
		}
		if _, isIface := types.Unalias(cur.Type()).Underlying().(*types.Interface); !isIface {
			if isStatelessStreamConcreteType(curFP.selectionAudited, cur.Type(), kind) {
				return true, ""
			}
		}
		isTopFrame := len(curFP.callBindings) == 0 && len(curStack) == 0
		if isTopFrame {
			if cached, ok := topMemo[cur]; ok {
				return cached.ok, cached.why
			}
		}
		if inStack[cur] {
			return false, "cyclic_stream_origin"
		}
		inStack[cur] = true
		defer delete(inStack, cur)

		eval := func() (bool, string) {
			switch x := cur.(type) {
			case *ssa.MakeInterface:
				return walkOrigin(x.X, curFP, curDepth, curStack)
			case *ssa.ChangeInterface:
				return walkOrigin(x.X, curFP, curDepth, curStack)
			case *ssa.ChangeType:
				return walkOrigin(x.X, curFP, curDepth, curStack)
			case *ssa.Convert:
				return walkOrigin(x.X, curFP, curDepth, curStack)
			case *ssa.TypeAssert:
				if x.CommaOk {
					return false, "comma_ok_type_assert"
				}
				return walkOrigin(x.X, curFP, curDepth, curStack)
			case *ssa.Extract:
				if x.Index == 0 {
					if ta, ok := x.Tuple.(*ssa.TypeAssert); ok {
						return walkOrigin(ta.X, curFP, curDepth, curStack)
					}
				}
				if call, ok := x.Tuple.(*ssa.Call); ok {
					return walkCallOrigin(call, x, x.Index, curFP, curDepth, curStack, walkOrigin)
				}
				return false, "unsupported_extract"
			case *ssa.Phi:
				if len(x.Edges) == 0 {
					return false, "empty_phi"
				}
				for _, edge := range vEdges(x) {
					if ok, why := walkOrigin(edge, curFP, curDepth, curStack); !ok {
						return false, why
					}
				}
				return true, ""
			case *ssa.FreeVar:
				bindings, usedProg, ok := attributedFreeVarBindings(x, curFP)
				if !ok || len(bindings) == 0 {
					return false, "unattributed_freevar"
				}
				nextFP := curFP
				if usedProg {
					nextFP, _ = curFP.withProgramSites(nil)
				} else {
					nextFP = curFP.withoutCallee(x.Parent())
				}
				for _, b := range bindings {
					if okB, why := walkOrigin(b, nextFP, curDepth+1, curStack); !okB {
						return false, why
					}
				}
				return true, ""
			case *ssa.Parameter:
				if bound, ok := curFP.callBindings[x]; ok && bound != nil {
					return walkOrigin(bound, curFP.withoutCallee(x.Parent()), curDepth+1, curStack)
				}
				args, usedProg, ok := attributedParameterArgs(x, curFP)
				if !ok || len(args) == 0 {
					return false, "unattributed_param"
				}
				nextFP := curFP
				if usedProg {
					nextFP, _ = curFP.withProgramSites(nil)
				}
				for _, a := range args {
					if okA, why := walkOrigin(a, nextFP, curDepth+1, curStack); !okA {
						return false, why
					}
				}
				return true, ""
			case *ssa.UnOp:
				if x.Op != token.MUL {
					return false, "non_deref_unop"
				}
				if g, isGlob := x.X.(*ssa.Global); isGlob {
					if kind == streamKindWriter && isUnmutatedStandardSentinelGlobal(curFP.prog, g, "io", "Discard") {
						return true, ""
					}
					return false, "global_stateful_stream"
				}
				if cellOf(x.X, map[ssa.Value]bool{}) == nil {
					return false, "non_local_cell_load"
				}
				wrote := false
				failWhy := ""
				okCell := walkLoadCellReferrersWithFP(x.X, curFP, func(stored ssa.Value) bool {
					wrote = true
					okS, whyS := walkOrigin(stored, curFP, curDepth+1, curStack)
					if !okS {
						failWhy = whyS
					}
					return okS
				})
				if !okCell || !wrote {
					if failWhy != "" {
						return false, failWhy
					}
					return false, "escaped_or_empty_cell"
				}
				return true, ""
			case *ssa.Alloc:
				_, wk, okW := classifyStatefulStreamType(x.Type(), kind)
				if !okW || wk == wrapperNone {
					return false, "unsupported_alloc:" + x.Type().String()
				}
				return verifyWrapperRootConfined(x, wk, curFP, curDepth+1, curStack)
			case *ssa.Call:
				return walkCallOrigin(x, x, -1, curFP, curDepth, curStack, walkOrigin)
			default:
				return false, "unsupported_origin_ssa"
			}
		}

		okRes, whyRes := eval()
		if isTopFrame {
			topMemo[cur] = originVerdict{ok: okRes, why: whyRes}
		}
		return okRes, whyRes
	}
	return walkOrigin(val, fp, depth, callStack)
}

func vEdges(phi *ssa.Phi) []ssa.Value {
	return phi.Edges
}

func walkCallOrigin(call *ssa.Call, resultVal ssa.Value, tupleIdx int, curFP *freshParamAnalysis, curDepth int, curStack map[*ssa.Function]wrapperCallFrame, walkOrigin func(ssa.Value, *freshParamAnalysis, int, map[*ssa.Function]wrapperCallFrame) (bool, string)) (bool, string) {
	if call == nil || call.Common() == nil {
		return false, "nil_call"
	}
	if curDepth > 16 {
		return false, "nil_or_depth_exceeded"
	}
	c := call.Common()
	if callee := c.StaticCallee(); callee != nil && curFP.isStdFunc(callee) {
		pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
		switch {
		case pkgPath == "crypto/hmac" && name == "New" && tupleIdx < 0 && len(c.Args) == 2:
			return verifyHMACNewCall(c.Args[0], curFP, curDepth+1)
		case pkgPath == "bufio" && (name == "NewWriter" || name == "NewWriterSize") && tupleIdx < 0 && len(c.Args) >= 1:
			if okW, why := inMemoryStreamValue(c.Args[0], streamKindWriter, curFP, curDepth+1, curStack); !okW {
				return false, "bufio_writer_target:" + why
			}
			return verifyWrapperRootConfined(call, wrapperBufioWriter, curFP, curDepth+1, curStack)
		case pkgPath == "text/tabwriter" && name == "NewWriter" && tupleIdx < 0 && len(c.Args) == 6:
			if okW, why := inMemoryStreamValue(c.Args[0], streamKindWriter, curFP, curDepth+1, curStack); !okW {
				return false, "tabwriter_target:" + why
			}
			return verifyWrapperRootConfined(call, wrapperTabwriter, curFP, curDepth+1, curStack)
		case pkgPath == "text/tabwriter" && name == "Init" && tupleIdx < 0 && len(c.Args) == 7:
			return walkOrigin(c.Args[0], curFP, curDepth+1, curStack)
		case pkgPath == "bufio" && (name == "NewReader" || name == "NewReaderSize") && tupleIdx < 0 && len(c.Args) >= 1:
			if okR, why := inMemoryStreamValue(c.Args[0], streamKindReader, curFP, curDepth+1, curStack); !okR {
				return false, "bufio_reader_target:" + why
			}
			return verifyWrapperRootConfined(call, wrapperBufioReader, curFP, curDepth+1, curStack)
		case isAdmittedPureHashConcreteType(curFP.selectionAudited, resultVal.Type()):
			return true, ""
		case auditset.PureHashPackage(pkgPath) && tupleIdx < 0:
			return true, ""
		}
		return false, "unsupported_std_constructor:" + pkgPath + "." + name
	}

	var targets []*ssa.Function
	if sc := c.StaticCallee(); sc != nil {
		targets = []*ssa.Function{sc}
	} else if !c.IsInvoke() {
		resolved, ok := closedDynamicTargets(c.Value, resetWalkState(curFP))
		if !ok || len(resolved) == 0 {
			return false, "open_dynamic_helper"
		}
		for t := range resolved {
			targets = append(targets, t)
		}
	} else {
		return false, "invoke_helper"
	}

	for _, callee := range targets {
		if callee == nil || curFP.isStdFunc(callee) || len(callee.Blocks) == 0 || parameterizedBody(callee) || len(c.Args) != len(callee.Params) {
			return false, "ineligible_helper_callee"
		}
		if curFP.calleeSeen[callee] {
			return false, "recursive_stream_helper"
		}
		childFP := *curFP
		seenCopy := make(map[*ssa.Function]bool, len(curFP.calleeSeen)+1)
		for k, v := range curFP.calleeSeen {
			seenCopy[k] = v
		}
		seenCopy[callee] = true
		childFP.calleeSeen = seenCopy
		bindings := make(map[*ssa.Parameter]ssa.Value, len(curFP.callBindings)+len(callee.Params))
		for k, v := range curFP.callBindings {
			bindings[k] = v
		}
		for i, p := range callee.Params {
			bindings[p] = c.Args[i]
		}
		childFP.callBindings = bindings

		nextStack := make(map[*ssa.Function]wrapperCallFrame, len(curStack)+1)
		for k, v := range curStack {
			nextStack[k] = v
		}
		nextStack[callee] = wrapperCallFrame{resultVal: resultVal, tupleIdx: tupleIdx}

		sawRet := false
		for _, blk := range liveBlocks(callee, nil) {
			for _, instr := range blk.Instrs {
				ret, isRet := instr.(*ssa.Return)
				if !isRet {
					continue
				}
				var res ssa.Value
				if tupleIdx < 0 {
					if len(ret.Results) != 1 {
						return false, "helper_return_arity"
					}
					res = ret.Results[0]
				} else {
					if tupleIdx >= len(ret.Results) {
						return false, "helper_return_index"
					}
					res = ret.Results[tupleIdx]
				}
				if blk == callee.Recover && isSyntheticRecoverZeroConst(res) {
					continue
				}
				sawRet = true
				if okR, why := walkOrigin(res, &childFP, curDepth+1, nextStack); !okR {
					return false, why
				}
			}
		}
		if !sawRet {
			return false, "helper_no_return"
		}
	}
	return true, ""
}

func verifyHMACNewCall(factory ssa.Value, fp *freshParamAnalysis, depth int) (bool, string) {
	if factory == nil || fp == nil || !fp.selectionAudited {
		return false, "hmac_nil_factory"
	}
	if depth > 16 {
		return false, "nil_or_depth_exceeded"
	}
	targets, ok := closedDynamicTargets(factory, resetWalkState(fp))
	if !ok || len(targets) == 0 {
		return false, "hmac_open_factory"
	}
	for target := range targets {
		if target == nil || target.Signature == nil || target.Signature.Params().Len() != 0 || target.Signature.Results().Len() != 1 {
			return false, "hmac_bad_factory_sig"
		}
		pkgPath := funcPkgPath(target)
		if fp.isStdFunc(target) {
			if auditset.PureHashPackage(pkgPath) {
				continue
			}
			return false, "hmac_impure_std_factory:" + pkgPath + "." + functionSymbolName(target)
		}
		if (!fp.functions[target] && !fp.programFunctions[target]) || fp.verifiedHarnesses[pkgPath] != nil || len(target.Blocks) == 0 || parameterizedBody(target) {
			return false, "hmac_ineligible_factory"
		}
		if !fp.programFunctions[target] {
			fp.markSubjectUsed()
		}
		sawRet := false
		for _, blk := range liveBlocks(target, nil) {
			for _, instr := range blk.Instrs {
				ret, isRet := instr.(*ssa.Return)
				if !isRet {
					continue
				}
				if len(ret.Results) != 1 {
					return false, "hmac_factory_arity"
				}
				if blk == target.Recover && isSyntheticRecoverZeroConst(ret.Results[0]) {
					continue
				}
				sawRet = true
				if okH, why := inMemoryStreamValue(ret.Results[0], streamKindWriter, fp, depth+1, nil); !okH {
					return false, "hmac_factory_return:" + why
				}
			}
		}
		if !sawRet {
			return false, "hmac_factory_no_return"
		}
	}
	return true, ""
}

