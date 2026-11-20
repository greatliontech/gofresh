package closure

import (
	"context"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/trace"
)

const goParserTraceFlag = 8 // go/parser.Trace == 1 << 3

func emitParserReject(ctx context.Context, site ssa.CallInstruction, reason string, fp *freshParamAnalysis) {
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
	trace.Emit(ctx, trace.DomainClosure, "closure.parser.reject", target,
		trace.String("callee", calleeStr),
		trace.String("reason", reason),
		trace.String("pos", posStr),
	)
}

func parserModeTraceFree(v ssa.Value, fp *freshParamAnalysis) bool {
	return parserModeTraceFreeSeen(v, fp, map[ssa.Value]bool{})
}

func parserModeTraceFreeSeen(v ssa.Value, fp *freshParamAnalysis, seen map[ssa.Value]bool) bool {
	if v == nil || seen[v] {
		return false
	}
	seen[v] = true
	defer delete(seen, v)

	switch x := v.(type) {
	case *ssa.Const:
		if x.Value == nil || x.Value.Kind() != constant.Int {
			return false
		}
		u, ok := constant.Uint64Val(x.Value)
		return ok && (u&goParserTraceFlag) == 0
	case *ssa.ChangeType:
		return parserModeTraceFreeSeen(x.X, fp, seen)
	case *ssa.Convert:
		return parserModeTraceFreeSeen(x.X, fp, seen)
	case *ssa.Phi:
		if len(x.Edges) == 0 {
			return false
		}
		for _, edge := range x.Edges {
			if !parserModeTraceFreeSeen(edge, fp, seen) {
				return false
			}
		}
		return true
	case *ssa.BinOp:
		switch x.Op {
		case token.OR, token.XOR:
			return parserModeTraceFreeSeen(x.X, fp, seen) && parserModeTraceFreeSeen(x.Y, fp, seen)
		case token.AND:
			return parserModeTraceFreeSeen(x.X, fp, seen) || parserModeTraceFreeSeen(x.Y, fp, seen)
		case token.AND_NOT:
			if parserModeTraceFreeSeen(x.X, fp, seen) {
				return true
			}
			if c, isC := x.Y.(*ssa.Const); isC && c.Value != nil && c.Value.Kind() == constant.Int {
				if u, ok := constant.Uint64Val(c.Value); ok && (u&goParserTraceFlag) != 0 {
					return true
				}
			}
			return false
		}
	case *ssa.Parameter:
		if fp != nil {
			if bound, ok := fp.callBindings[x]; ok && bound != nil {
				return parserModeTraceFreeSeen(bound, fp.withoutCallee(x.Parent()), seen)
			}
		}
		args, usedProg, ok := attributedParameterArgs(x, fp)
		if !ok || len(args) == 0 {
			return false
		}
		nextFP := fp
		if usedProg {
			nextFP, _ = fp.withProgramSites(nil)
		}
		for _, a := range args {
			if !parserModeTraceFreeSeen(a, nextFP, seen) {
				return false
			}
		}
		return true
	case *ssa.FreeVar:
		bindings, usedProg, ok := attributedFreeVarBindings(x, fp)
		if !ok || len(bindings) == 0 {
			return false
		}
		nextFP := fp
		if usedProg {
			nextFP, _ = fp.withProgramSites(nil)
		} else if fp != nil {
			nextFP = fp.withoutCallee(x.Parent())
		}
		for _, b := range bindings {
			if !parserModeTraceFreeSeen(b, nextFP, seen) {
				return false
			}
		}
		return true
	}
	return false
}

func implementsIOReader(t types.Type) bool {
	if t == nil {
		return false
	}
	mset := types.NewMethodSet(t)
	for i := 0; i < mset.Len(); i++ {
		fn, ok := mset.At(i).Obj().(*types.Func)
		if !ok || fn.Name() != "Read" {
			continue
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Variadic() || sig.Params().Len() != 1 || sig.Results().Len() != 2 {
			continue
		}
		slice, ok := types.Unalias(sig.Params().At(0).Type()).(*types.Slice)
		if !ok {
			continue
		}
		b, ok := types.Unalias(slice.Elem()).(*types.Basic)
		if !ok || b.Kind() != types.Byte {
			continue
		}
		r0, ok := types.Unalias(sig.Results().At(0).Type()).(*types.Basic)
		if !ok || r0.Kind() != types.Int {
			continue
		}
		if sig.Results().At(1).Type().String() == "error" {
			return true
		}
	}
	return false
}

func admittedGoParserSourceCall(ctx context.Context, emitTrace bool, site ssa.CallInstruction, c *ssa.CallCommon, fp *freshParamAnalysis) bool {
	if fp == nil || !fp.selectionAudited || c == nil || len(c.Args) != 4 {
		return false
	}
	if !parserModeTraceFree(c.Args[3], fp) {
		if emitTrace {
			emitParserReject(ctx, site, "mode_may_enable_trace", fp)
		}
		return false
	}
	ok, why := parserSourceValue(c.Args[2], fp, map[ssa.Value]bool{})
	if !ok && emitTrace {
		emitParserReject(ctx, site, why, fp)
	}
	return ok
}

func parserSourceValue(src ssa.Value, fp *freshParamAnalysis, seen map[ssa.Value]bool) (bool, string) {
	if src == nil || fp == nil || !fp.selectionAudited {
		return false, "src_nil_or_unaudited"
	}
	if seen[src] {
		return false, "src_cycle"
	}
	seen[src] = true
	defer delete(seen, src)

	switch v := src.(type) {
	case *ssa.MakeInterface:
		if v.X == nil || v.X.Type() == nil {
			return false, "src_make_iface_nil"
		}
		if _, isIface := types.Unalias(v.X.Type()).Underlying().(*types.Interface); isIface {
			return false, "src_boxed_interface"
		}
		if !implementsIOReader(v.X.Type()) {
			return true, ""
		}
		okR, whyR := inMemoryStreamValue(v.X, streamKindReader, fp, 0, nil)
		if !okR {
			return false, "src_reader:" + whyR
		}
		return true, ""
	case *ssa.Phi:
		if len(v.Edges) == 0 {
			return false, "src_empty_phi"
		}
		for _, edge := range v.Edges {
			if okE, whyE := parserSourceValue(edge, fp, seen); !okE {
				return false, whyE
			}
		}
		return true, ""
	case *ssa.Parameter:
		if bound, ok := fp.callBindings[v]; ok && bound != nil {
			return parserSourceValue(bound, fp.withoutCallee(v.Parent()), seen)
		}
		args, usedProg, ok := attributedParameterArgs(v, fp)
		if !ok || len(args) == 0 {
			return false, "src_unattributed_param"
		}
		nextFP := fp
		if usedProg {
			nextFP, _ = fp.withProgramSites(nil)
		}
		for _, a := range args {
			if okA, whyA := parserSourceValue(a, nextFP, seen); !okA {
				return false, whyA
			}
		}
		return true, ""
	case *ssa.FreeVar:
		bindings, usedProg, ok := attributedFreeVarBindings(v, fp)
		if !ok || len(bindings) == 0 {
			return false, "src_unattributed_freevar"
		}
		nextFP := fp
		if usedProg {
			nextFP, _ = fp.withProgramSites(nil)
		} else {
			nextFP = fp.withoutCallee(v.Parent())
		}
		for _, b := range bindings {
			if okB, whyB := parserSourceValue(b, nextFP, seen); !okB {
				return false, whyB
			}
		}
		return true, ""
	case *ssa.Const:
		return false, "src_nil_const"
	case *ssa.ChangeInterface:
		return false, "src_nilable_change_interface"
	default:
		return false, "src_unproven_non_nil"
	}
}

func goParserCallReturnDynamicValue(
	callee *ssa.Function,
	pkgPath, symName string,
	tupleIndex int,
	collect *dynamicValueCollector,
	fp *freshParamAnalysis,
) (ok, handled bool) {
	if pkgPath != "go/parser" || callee == nil || callee.Pkg == nil || callee.Pkg.Prog == nil {
		return false, false
	}
	if symName != "ParseExpr" && !auditset.GoParserSourceFunc(symName) {
		return false, false
	}
	ssaProg := callee.Pkg.Prog
	if tupleIndex == 0 {
		if symName == "ParseFile" {
			if !collect.collecting() {
				markDynamicLeaf(fp)
				return true, true
			}
			if collect.types != nil {
				if astPkg := ssaProg.ImportedPackage("go/ast"); astPkg != nil && astPkg.Pkg != nil {
					if obj := astPkg.Pkg.Scope().Lookup("File"); obj != nil {
						collect.types[types.NewPointer(obj.Type())] = true
						return true, true
					}
				}
			}
			return collect.isSeeds(), true
		}
		// ParseExpr and ParseExprFrom return ast.Expr at tuple slot 0.
		if !collect.collecting() {
			markDynamicLeaf(fp)
			return true, true
		}
		if collect.types != nil {
			astPkg := ssaProg.ImportedPackage("go/ast")
			if astPkg == nil || astPkg.Pkg == nil || astPkg.Pkg.Scope() == nil {
				return collect.isSeeds(), true
			}
			exprObj := astPkg.Pkg.Scope().Lookup("Expr")
			if exprObj == nil {
				return collect.isSeeds(), true
			}
			exprIface, okIf := exprObj.Type().Underlying().(*types.Interface)
			if !okIf {
				return collect.isSeeds(), true
			}
			added := false
			for _, name := range astPkg.Pkg.Scope().Names() {
				tn, isTN := astPkg.Pkg.Scope().Lookup(name).(*types.TypeName)
				if !isTN || tn.IsAlias() {
					continue
				}
				if _, isIf := tn.Type().Underlying().(*types.Interface); isIf {
					continue
				}
				ptr := types.NewPointer(tn.Type())
				if types.Implements(ptr, exprIface) {
					if cm := ssaProg.LookupMethod(ptr, nil, "Pos"); cm != nil && len(cm.Blocks) > 0 {
						collect.types[ptr] = true
						added = true
					}
				}
			}
			return added || collect.isSeeds(), true
		}
		return collect.isSeeds(), true
	}
	if tupleIndex == 1 {
		if !collect.collecting() {
			markDynamicLeaf(fp)
			return true, true
		}
		if collect.types != nil {
			added := false
			addErrType := func(ct types.Type) {
				if ct == nil {
					return
				}
				if cm := ssaProg.LookupMethod(ct, nil, "Error"); cm != nil && len(cm.Blocks) > 0 {
					collect.types[ct] = true
					added = true
				}
			}
			if scanPkg := ssaProg.ImportedPackage("go/scanner"); scanPkg != nil && scanPkg.Pkg != nil && scanPkg.Pkg.Scope() != nil {
				if el := scanPkg.Pkg.Scope().Lookup("ErrorList"); el != nil {
					addErrType(el.Type())
				}
				if er := scanPkg.Pkg.Scope().Lookup("Error"); er != nil {
					addErrType(er.Type())
					addErrType(types.NewPointer(er.Type()))
				}
			}
			if errPkg := ssaProg.ImportedPackage("errors"); errPkg != nil && errPkg.Pkg != nil && errPkg.Pkg.Scope() != nil {
				if es := errPkg.Pkg.Scope().Lookup("errorString"); es != nil {
					addErrType(types.NewPointer(es.Type()))
				}
			}
			return added || collect.isSeeds(), true
		}
		return collect.isSeeds(), true
	}
	return false, false
}

func isGoASTNodeInterfaceType(t types.Type) (*types.Named, *types.Interface, bool) {
	if t == nil {
		return nil, nil, false
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "go/ast" {
		return nil, nil, false
	}
	if !auditset.GoASTNodeInterface(named.Obj().Name()) {
		return nil, nil, false
	}
	iface, ok := named.Underlying().(*types.Interface)
	if !ok || iface == nil {
		return nil, nil, false
	}
	return named, iface, true
}

func isGoASTTraversalInterfaceType(t types.Type) bool {
	if _, _, ok := isGoASTNodeInterfaceType(t); ok {
		return true
	}
	if t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "go/ast" {
		return false
	}
	_, isIface := named.Underlying().(*types.Interface)
	return isIface && named.Obj().Name() == "Visitor"
}

// checkMakeInterfaceStdHooks flags standard-library named types boxed or
// widened into a non-go/ast-traversal interface (directly or inside composite
// fields/elements) whose String methods or reflected Scope/CommentMap fields
// expose ASLR heap pointers or unsorted map iteration when formatted inside
// fmt (where callerStd is true).
func (a *tier2Analyzer) checkMakeInterfaceStdHooks(caller *ssa.Function, dstIface, srcType types.Type) {
	if a == nil || srcType == nil || isGoASTTraversalInterfaceType(dstIface) {
		return
	}
	seen := map[types.Type]bool{}
	var walkValueTypes func(types.Type) bool
	walkValueTypes = func(cur types.Type) bool {
		if cur == nil {
			return true
		}
		cur = types.Unalias(cur)
		if ssaOpaqueHandle(cur) || seen[cur] {
			return true
		}
		seen[cur] = true
		switch tt := cur.(type) {
		case *types.Named:
			if tt.Obj() != nil && tt.Obj().Pkg() != nil && tt.Obj().Pkg().Path() == "go/ast" {
				switch tt.Obj().Name() {
				case "Scope", "CommentMap", "Node", "Expr", "Stmt", "Decl", "Spec", "Visitor":
					if trace.AnyEnabled() && a.h != nil && a.h.ctx != nil {
						target := ""
						if a.fresh != nil && a.fresh.subjectRoot != nil {
							target = a.fresh.subjectRoot.String()
						} else if caller != nil {
							target = caller.String()
						}
						if trace.Enabled(a.h.ctx, trace.DomainClosure, target) {
							callerName, dstStr := "", ""
							if caller != nil {
								callerName = caller.String()
							}
							if dstIface != nil {
								dstStr = dstIface.String()
							}
							trace.Emit(a.h.ctx, trace.DomainClosure, "closure.std_hook.reject", target,
								trace.String("caller", callerName),
								trace.String("dst_iface", dstStr),
								trace.String("src_type", srcType.String()),
								trace.String("matched", tt.Obj().Name()),
							)
						}
					}
					a.recordExternalEffect(unauditedStandardEffect("go/ast", "String"))
					return false
				}
			}
			for i := 0; i < tt.TypeArgs().Len(); i++ {
				if !walkValueTypes(tt.TypeArgs().At(i)) {
					return false
				}
			}
			if _, isIf := tt.Underlying().(*types.Interface); isIf {
				return true
			}
			return walkValueTypes(tt.Underlying())
		case *types.Pointer:
			return walkValueTypes(tt.Elem())
		case *types.Slice:
			return walkValueTypes(tt.Elem())
		case *types.Array:
			return walkValueTypes(tt.Elem())
		case *types.Map:
			return walkValueTypes(tt.Key()) && walkValueTypes(tt.Elem())
		case *types.Chan:
			return walkValueTypes(tt.Elem())
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				if !walkValueTypes(tt.Field(i).Type()) {
					return false
				}
			}
		}
		return true
	}
	walkValueTypes(srcType)
}

func (a *tier2Analyzer) checkInstructionStdHooks(caller *ssa.Function, callerStd bool, instr ssa.Instruction) {
	if a == nil || callerStd || instr == nil {
		return
	}
	switch x := instr.(type) {
	case *ssa.MakeInterface:
		if x.X != nil {
			a.checkMakeInterfaceStdHooks(caller, x.Type(), x.X.Type())
		}
	case *ssa.ChangeInterface:
		if x.X != nil {
			a.checkMakeInterfaceStdHooks(caller, x.Type(), x.X.Type())
		}
	case *ssa.TypeAssert:
		if x.X != nil && x.AssertedType != nil {
			if _, isIf := types.Unalias(x.AssertedType).Underlying().(*types.Interface); isIf {
				a.checkMakeInterfaceStdHooks(caller, x.AssertedType, x.X.Type())
			}
		}
	}
}

func isStdGoASTConcreteType(ct types.Type, userPaths map[string]bool) bool {
	if ct == nil || userPaths["go/ast"] {
		return false
	}
	u := types.Unalias(ct)
	if ptr, ok := u.(*types.Pointer); ok {
		u = types.Unalias(ptr.Elem())
	}
	named, ok := u.(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "go/ast"
}

func isInvalidBasicOrInterfaceType(t types.Type) bool {
	if t == nil {
		return true
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Interface:
		return true
	case *types.Basic:
		return u.Kind() == types.Invalid
	}
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		if b, isBasic := types.Unalias(ptr.Elem()).Underlying().(*types.Basic); isBasic && b.Kind() == types.Invalid {
			return true
		}
	}
	return false
}

func (b *tier2Base) goASTIfaceSealed(ifaceNamed *types.Named, iface *types.Interface, userPaths map[string]bool) (bool, string) {
	if b == nil || b.prog == nil || b.prog.Prog == nil || ifaceNamed == nil || iface == nil || userPaths["go/ast"] {
		return false, "uninitialized_or_user_go_ast"
	}
	if b.goASTSealedMemo != nil {
		if sealed, ok := b.goASTSealedMemo[ifaceNamed]; ok {
			return sealed, b.goASTUnsealedReason[ifaceNamed]
		}
	}
	sealed := true
	unsealedReason := ""
	checkSingle := func(ct types.Type, source string) bool {
		if isInvalidBasicOrInterfaceType(ct) {
			return true
		}
		if types.Implements(ct, iface) && !isStdGoASTConcreteType(ct, userPaths) {
			unsealedReason = source + ":" + ct.String()
			return false
		}
		return true
	}
	seenGraph := map[types.Type]bool{}
	inspectTypeGraph := func(root types.Type, source string) bool {
		if root == nil || !sealed {
			return sealed
		}
		walkTypeGraph(root, true, seenGraph, func(cur types.Type) bool {
			if isInvalidBasicOrInterfaceType(cur) {
				return true
			}
			if !checkSingle(cur, source) {
				sealed = false
				return false
			}
			if _, isPtr := types.Unalias(cur).(*types.Pointer); !isPtr && !checkSingle(types.NewPointer(cur), source) {
				sealed = false
				return false
			}
			return true
		})
		return sealed
	}
	for _, rt := range b.prog.Prog.RuntimeTypes() {
		if !inspectTypeGraph(rt, "runtime_type") {
			sealed = false
			break
		}
	}
	if sealed {
		for _, pkg := range b.prog.Prog.AllPackages() {
			if pkg == nil || pkg.Pkg == nil || pkg.Pkg.Scope() == nil {
				continue
			}
			src := "pkg_scope:" + pkg.Pkg.Path()
			for _, name := range pkg.Pkg.Scope().Names() {
				tn, isTN := pkg.Pkg.Scope().Lookup(name).(*types.TypeName)
				if !isTN || tn.Type() == nil {
					continue
				}
				if !inspectTypeGraph(tn.Type(), src) {
					sealed = false
					break
				}
			}
			if !sealed {
				break
			}
		}
	}
	if sealed {
		var ops [16]*ssa.Value
		for _, fn := range progOrderedFunctions(b.prog) {
			if fn == nil {
				continue
			}
			src := "ssa_fn:" + fn.String()
			for _, blk := range fn.Blocks {
				for _, instr := range blk.Instrs {
					if v, isVal := instr.(ssa.Value); isVal && v.Type() != nil && !inspectTypeGraph(v.Type(), src) {
						sealed = false
						break
					}
					for _, op := range instr.Operands(ops[:0]) {
						if op != nil && *op != nil && (*op).Type() != nil && !inspectTypeGraph((*op).Type(), src) {
							sealed = false
							break
						}
					}
				}
				if !sealed {
					break
				}
			}
			if !sealed {
				break
			}
		}
	}
	if b.goASTSealedMemo == nil {
		b.goASTSealedMemo = make(map[*types.Named]bool, 5)
		b.goASTUnsealedReason = make(map[*types.Named]string, 5)
	}
	b.goASTSealedMemo[ifaceNamed] = sealed
	b.goASTUnsealedReason[ifaceNamed] = unsealedReason
	return sealed, unsealedReason
}

func (a *tier2Analyzer) closedGoASTNodeTargets(site ssa.CallInstruction, fromRTA bool) bool {
	if a == nil || a.h == nil || !a.h.SelectionAudited() || a.openWorld || a.base == nil || a.prog == nil || a.prog.Prog == nil {
		return false
	}
	c := site.Common()
	if c == nil || !c.IsInvoke() || c.Method == nil || c.Value == nil {
		return false
	}
	ifaceNamed, iface, ok := isGoASTNodeInterfaceType(c.Value.Type())
	if !ok {
		return false
	}
	var userPaths map[string]bool
	if a.fresh != nil {
		userPaths = a.fresh.userPkgPaths()
	}
	emitUnsealed := func(reason string) {
		if !trace.AnyEnabled() || a.h == nil || a.h.ctx == nil {
			return
		}
		target := ""
		if a.fresh != nil && a.fresh.subjectRoot != nil {
			target = a.fresh.subjectRoot.String()
		} else if site.Parent() != nil {
			target = site.Parent().String()
		}
		if trace.Enabled(a.h.ctx, trace.DomainClosure, target) {
			posStr := ""
			if a.prog.Prog.Fset != nil && site.Pos().IsValid() {
				posStr = a.prog.Prog.Fset.Position(site.Pos()).String()
			}
			trace.Emit(a.h.ctx, trace.DomainClosure, "closure.ast_sealed.reject", target,
				trace.String("iface", ifaceNamed.String()),
				trace.String("reason", reason),
				trace.String("pos", posStr),
			)
		}
	}
	if sealed, reason := a.base.goASTIfaceSealed(ifaceNamed, iface, userPaths); !sealed {
		emitUnsealed(reason)
		return false
	}
	seenExtra := map[types.Type]bool{}
	for _, extra := range [][]types.Type{a.enumeratedTypes, a.initBoxedTypes} {
		for _, ct := range extra {
			if ct == nil {
				continue
			}
			badReason := ""
			walkTypeGraph(ct, true, seenExtra, func(cur types.Type) bool {
				if isInvalidBasicOrInterfaceType(cur) {
					return true
				}
				if types.Implements(cur, iface) && !isStdGoASTConcreteType(cur, userPaths) {
					badReason = "extra_type:" + cur.String()
					return false
				}
				if _, isPtr := types.Unalias(cur).(*types.Pointer); !isPtr && types.Implements(types.NewPointer(cur), iface) && !isStdGoASTConcreteType(types.NewPointer(cur), userPaths) {
					badReason = "extra_ptr_type:" + types.NewPointer(cur).String()
					return false
				}
				return true
			})
			if badReason != "" {
				emitUnsealed(badReason)
				return false
			}
		}
	}
	astPkg := a.prog.Prog.ImportedPackage("go/ast")
	if astPkg == nil || astPkg.Pkg == nil || astPkg.Pkg.Scope() == nil {
		return false
	}
	held := make(map[*ssa.Function]bool)
	for _, name := range astPkg.Pkg.Scope().Names() {
		tn, isTN := astPkg.Pkg.Scope().Lookup(name).(*types.TypeName)
		if !isTN || tn.IsAlias() {
			continue
		}
		if _, isIf := tn.Type().Underlying().(*types.Interface); isIf {
			continue
		}
		for _, cand := range []types.Type{tn.Type(), types.NewPointer(tn.Type())} {
			if !types.Implements(cand, iface) {
				continue
			}
			sel := types.NewMethodSet(cand).Lookup(c.Method.Pkg(), c.Method.Name())
			if sel == nil {
				continue
			}
			fn := a.prog.Prog.MethodValue(sel)
			if fn == nil {
				return false
			}
			held[fn] = true
		}
	}
	if len(held) == 0 {
		return false
	}
	for fn := range held {
		if !auditedStandardCallee(true, "go/ast", functionSymbolName(fn), fn) {
			return false
		}
		if _, classB := classBEffectForFunction(fn); classB {
			return false
		}
	}
	for fn := range held {
		if fromRTA {
			a.rtaReach[fn] = true
		}
		a.addFunction(fn)
	}
	return true
}

func auditedIOWrapperTypeName(t types.Type) string {
	if t == nil {
		return ""
	}
	base := types.Unalias(t)
	if ptr, ok := base.(*types.Pointer); ok {
		base = types.Unalias(ptr.Elem())
	}
	named, ok := base.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "io" {
		return ""
	}
	switch name := named.Obj().Name(); name {
	case "nopCloser", "nopCloserWriterTo", "LimitedReader", "teeReader", "multiReader", "multiWriter", "eofReader":
		return name
	default:
		return ""
	}
}

func isAuditedStandardIOWrapperType(t types.Type) bool {
	return auditedIOWrapperTypeName(t) != ""
}

func auditedIOWrapperResultDynamicValue(callee *ssa.Function, tupleIndex int, collect *dynamicValueCollector, fp *freshParamAnalysis) (ok, skip bool) {
	if callee == nil || callee.Signature == nil || callee.Signature.Recv() == nil {
		return false, false
	}
	typeName := auditedIOWrapperTypeName(callee.Signature.Recv().Type())
	if typeName == "" {
		return false, false
	}
	var sentinelName string
	switch typeName {
	case "nopCloser":
		switch callee.Name() {
		case "Read", "Close":
		default:
			return false, false
		}
	case "nopCloserWriterTo":
		switch callee.Name() {
		case "Read", "Close", "WriteTo":
		default:
			return false, false
		}
	case "teeReader":
		if callee.Name() != "Read" {
			return false, false
		}
	case "LimitedReader", "multiReader", "eofReader":
		if callee.Name() != "Read" {
			return false, false
		}
		sentinelName = "EOF"
	case "multiWriter":
		switch callee.Name() {
		case "Write", "WriteString":
			sentinelName = "ErrShortWrite"
		default:
			return false, false
		}
	default:
		return false, false
	}
	if sentinelName != "" && tupleIndex != 0 {
		if callee.Pkg == nil || fp == nil {
			return collect.isSeeds(), true
		}
		g := callee.Pkg.Var(sentinelName)
		if g == nil || !isUnmutatedStandardSentinelGlobal(fp.prog, g, "io", sentinelName) {
			return collect.isSeeds(), true
		}
		if collect.collecting() && collect.types != nil {
			if !sentinelGlobalConcreteTypes(g, collect.types) && !collect.isSeeds() {
				return false, true
			}
		}
	}
	if !collect.collecting() {
		markDynamicLeaf(fp)
	}
	return true, true
}
