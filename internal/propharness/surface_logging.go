package propharness

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

func isBoolType(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Kind() == types.Bool
}

func isStringType(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && (b.Info()&types.IsString) != 0
}

func isStdLogLoggerPtr(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "log" && named.Obj().Name() == "Logger"
}

func isStdIOWriterType(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "io" && named.Obj().Name() == "Writer"
}

func isOSStdoutExpr(info *types.Info, e ast.Expr) bool {
	sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	v, _ := info.Uses[sel.Sel].(*types.Var)
	return v != nil && v.Pkg() != nil && v.Pkg().Path() == "os" && v.Name() == "Stdout"
}

func isLogNewStdoutCall(info *types.Info, e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 3 {
		return false
	}
	callee := resolveHarnessFuncExpr(info, call.Fun)
	if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "log" || callee.Name() != "New" {
		return false
	}
	return isOSStdoutExpr(info, call.Args[0])
}

func isFmtSprintCall(info *types.Info, call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	callee := resolveHarnessFuncExpr(info, call.Fun)
	if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "fmt" {
		return false
	}
	return callee.Name() == "Sprint" || callee.Name() == "Sprintf" || callee.Name() == "Sprintln"
}

func isNilIdent(info *types.Info, e ast.Expr) bool {
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok {
		return false
	}
	_, isNil := info.Uses[id].(*types.Nil)
	return isNil
}

func exprIsAddrTaken(idx *refconfine.PkgIndex, e ast.Expr) bool {
	if idx == nil || e == nil {
		return false
	}
	un, ok := idx.ParentUnparen(e).(*ast.UnaryExpr)
	return ok && un.Op == token.AND
}

func varNeverReassigned(idx *refconfine.PkgIndex, v *types.Var) bool {
	if v == nil || idx.DefCounts[v] > 1 {
		return false
	}
	for _, u := range idx.UsesOf[v] {
		if refconfine.IdentIsWrittenOrAddrTaken(idx, u) {
			return false
		}
	}
	return true
}

func nodeInsideForOrRange(idx *refconfine.PkgIndex, n ast.Node) bool {
	for cur := idx.ParentMap[n]; cur != nil; cur = idx.ParentMap[cur] {
		switch cur.(type) {
		case *ast.ForStmt, *ast.RangeStmt:
			return true
		case *ast.FuncDecl, *ast.FuncLit:
			return false
		}
	}
	return false
}

func collectEnclosingResultVars(info *types.Info, idx *refconfine.PkgIndex, n ast.Node) (resultVars map[*types.Var]bool, scopePos, scopeEnd token.Pos) {
	resultVars = map[*types.Var]bool{}
	addFieldList := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, fld := range fl.List {
			for _, nm := range fld.Names {
				if v, ok := info.Defs[nm].(*types.Var); ok && v != nil {
					resultVars[v] = true
				}
			}
		}
	}
	for cur := n; cur != nil; cur = idx.ParentMap[cur] {
		switch fn := cur.(type) {
		case *ast.FuncLit:
			if fn.Type != nil {
				addFieldList(fn.Type.Results)
			}
			if scopePos == token.NoPos {
				scopePos, scopeEnd = fn.Pos(), fn.End()
			}
		case *ast.FuncDecl:
			if fn.Type != nil {
				addFieldList(fn.Type.Results)
			}
			if scopePos == token.NoPos {
				scopePos, scopeEnd = fn.Pos(), fn.End()
			}
			return resultVars, scopePos, scopeEnd
		}
	}
	return resultVars, scopePos, scopeEnd
}

// isClosedPureLoggingExpr validates an expression against a strict closed
// allowlist of side-effect-free value forms (rejecting channel receives <-ch,
// address-taking &x, closures, composite literals, and disallowed calls).
func isClosedPureLoggingExpr(info *types.Info, expr ast.Expr, allowCall func(*ast.CallExpr) bool) bool {
	if expr == nil {
		return false
	}
	switch x := expr.(type) {
	case *ast.Ident, *ast.BasicLit:
		return true
	case *ast.ParenExpr:
		return isClosedPureLoggingExpr(info, x.X, allowCall)
	case *ast.SelectorExpr:
		return isClosedPureLoggingExpr(info, x.X, allowCall)
	case *ast.IndexExpr:
		return isClosedPureLoggingExpr(info, x.X, allowCall) &&
			isClosedPureLoggingExpr(info, x.Index, allowCall)
	case *ast.SliceExpr:
		if x.Low != nil && !isClosedPureLoggingExpr(info, x.Low, allowCall) {
			return false
		}
		if x.High != nil && !isClosedPureLoggingExpr(info, x.High, allowCall) {
			return false
		}
		if x.Max != nil && !isClosedPureLoggingExpr(info, x.Max, allowCall) {
			return false
		}
		return isClosedPureLoggingExpr(info, x.X, allowCall)
	case *ast.StarExpr:
		return isClosedPureLoggingExpr(info, x.X, allowCall)
	case *ast.UnaryExpr:
		switch x.Op {
		case token.NOT, token.ADD, token.SUB, token.XOR:
			return isClosedPureLoggingExpr(info, x.X, allowCall)
		default:
			return false
		}
	case *ast.BinaryExpr:
		return isClosedPureLoggingExpr(info, x.X, allowCall) &&
			isClosedPureLoggingExpr(info, x.Y, allowCall)
	case *ast.CallExpr:
		if syntaxutil.LookupBuiltin(info, syntaxutil.UnwrapCallee(x.Fun)) != nil {
			return false
		}
		if info.Types[syntaxutil.UnwrapCallee(x.Fun)].IsType() {
			return len(x.Args) == 1 && !x.Ellipsis.IsValid() &&
				isClosedPureLoggingExpr(info, x.Args[0], allowCall)
		}
		if allowCall == nil || !allowCall(x) {
			return false
		}
		for _, a := range x.Args {
			if !isClosedPureLoggingExpr(info, a, allowCall) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isClosedPureLoggingStmt(
	info *types.Info,
	stmt ast.Stmt,
	allowAssign func(*ast.AssignStmt) bool,
	allowIfInit func(ast.Stmt) bool,
	allowReturn bool,
	allowCall func(*ast.CallExpr) bool,
) bool {
	if stmt == nil {
		return false
	}
	switch x := stmt.(type) {
	case *ast.BlockStmt:
		for _, s := range x.List {
			if !isClosedPureLoggingStmt(info, s, allowAssign, allowIfInit, allowReturn, allowCall) {
				return false
			}
		}
		return true
	case *ast.EmptyStmt:
		return true
	case *ast.ExprStmt:
		call, isCall := ast.Unparen(x.X).(*ast.CallExpr)
		return isCall && !isFmtSprintCall(info, call) && isClosedPureLoggingExpr(info, call, allowCall)
	case *ast.AssignStmt:
		return allowAssign != nil && allowAssign(x)
	case *ast.IfStmt:
		if x.Init != nil && (allowIfInit == nil || !allowIfInit(x.Init)) {
			return false
		}
		if !isClosedPureLoggingExpr(info, x.Cond, allowCall) {
			return false
		}
		if !isClosedPureLoggingStmt(info, x.Body, allowAssign, allowIfInit, allowReturn, allowCall) {
			return false
		}
		if x.Else != nil && !isClosedPureLoggingStmt(info, x.Else, allowAssign, allowIfInit, allowReturn, allowCall) {
			return false
		}
		return true
	case *ast.ReturnStmt:
		if !allowReturn {
			return false
		}
		for _, r := range x.Results {
			if !isClosedPureLoggingExpr(info, r, allowCall) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// findPureLoggingBoolFlagReads identifies post-init reads of envFlagVars whose
// values are bool diagnostic-logging toggles (such as verbose/debug/raw-log
// flags) confined exclusively to gating diagnostic log emission on a sealed
// handle struct (*log.Logger or TB.Log*), never flowing into return values,
// PRNG bitstream state, iteration counts, or test failure decisions.
func findPureLoggingBoolFlagReads(g *harnessGraph, envFlagVars map[*types.Var]bool) map[*ast.Ident]bool {
	if g == nil || g.idx == nil || len(envFlagVars) == 0 {
		return nil
	}
	pureIntraPkgFns := computePureIntraPkgFuncs(g)

	info := g.info
	sc := g.screen
	idx := g.idx

	var knownHandleIfaceUnderlyings []*types.Interface
	for hi := range sc.handleIfaces {
		if ui, ok := hi.Underlying().(*types.Interface); ok {
			knownHandleIfaceUnderlyings = append(knownHandleIfaceUnderlyings, ui)
		}
	}
	for _, imp := range g.pkgTypes.Imports() {
		if imp != nil && imp.Path() == "testing" {
			if tbObj := imp.Scope().Lookup("TB"); tbObj != nil {
				if ui, ok := tbObj.Type().Underlying().(*types.Interface); ok {
					knownHandleIfaceUnderlyings = append(knownHandleIfaceUnderlyings, ui)
				}
			}
		}
	}

	isKnownHandleLoggerIface := func(t types.Type) bool {
		if t == nil || !types.IsInterface(t) {
			return false
		}
		ut := types.Unalias(t)
		if isTestingTBType(ut) {
			return true
		}
		if named, ok := ut.(*types.Named); ok && sc.handleIfaces[named.Origin()] {
			return true
		}
		ui, ok := ut.Underlying().(*types.Interface)
		if !ok {
			return false
		}
		for _, ki := range knownHandleIfaceUnderlyings {
			if types.Identical(ui, ki) {
				return true
			}
		}
		return false
	}

	loggerFields := map[*types.Var]bool{}
	candBoolFields := map[*types.Var]bool{}
	candIfaceFields := map[*types.Var]bool{}
	for hs := range sc.handleStructs {
		st, ok := hs.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f.Exported() {
				continue
			}
			if isStdLogLoggerPtr(f.Type()) {
				if verifyStdoutBackedLoggerField(g, f) {
					loggerFields[f] = true
				}
			} else if isBoolType(f.Type()) {
				candBoolFields[f] = true
			} else if isKnownHandleLoggerIface(f.Type()) {
				candIfaceFields[f] = true
			}
		}
	}

	handleIfaceFields, trustedIfaceParams := verifyTrustedLoggerIfaceFieldsAndParams(
		g,
		pureIntraPkgFns,
		candIfaceFields,
		isKnownHandleLoggerIface,
	)

	isTrustedHandlePtrVar := func(e ast.Expr) bool {
		id, ok := ast.Unparen(e).(*ast.Ident)
		if !ok {
			return false
		}
		v, _ := info.Uses[id].(*types.Var)
		return v != nil && sc.isHandleStructPtr(v.Type()) && varNeverReassigned(idx, v)
	}

	isTrustedLoggerFieldExpr := func(e ast.Expr) bool {
		sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
		if !ok {
			return false
		}
		fv, _ := info.Uses[sel.Sel].(*types.Var)
		return fv != nil && loggerFields[fv] && isTrustedHandlePtrVar(sel.X)
	}

	isTrustedLoggerIfaceRecv := func(e ast.Expr, enclFn *types.Func) bool {
		e = ast.Unparen(e)
		if isTrustedHandlePtrVar(e) {
			st, okSt := types.Unalias(info.TypeOf(e)).(*types.Pointer).Elem().Underlying().(*types.Struct)
			if !okSt {
				return false
			}
			for i := 0; i < st.NumFields(); i++ {
				if st.Field(i).Embedded() && isKnownHandleLoggerIface(st.Field(i).Type()) {
					return handleIfaceFields[st.Field(i)]
				}
			}
			return false
		}
		if sel, isSel := e.(*ast.SelectorExpr); isSel {
			fv, _ := info.Uses[sel.Sel].(*types.Var)
			return fv != nil && handleIfaceFields[fv] && isTrustedHandlePtrVar(sel.X)
		}
		id, isID := e.(*ast.Ident)
		if !isID || enclFn == nil || enclFn.Signature() == nil {
			return false
		}
		pv, _ := info.Uses[id].(*types.Var)
		if pv == nil {
			return false
		}
		params := enclFn.Signature().Params()
		for i := 0; i < params.Len(); i++ {
			if params.At(i) == pv {
				return trustedIfaceParams[loggingFuncParam{fn: enclFn, idx: i}]
			}
		}
		return false
	}

	isEnclosingVariadicForward := func(call *ast.CallExpr, enclFn *types.Func, argIdx int) bool {
		if !call.Ellipsis.IsValid() || argIdx != len(call.Args)-1 || enclFn == nil || enclFn.Signature() == nil || !enclFn.Signature().Variadic() {
			return false
		}
		aid, isID := ast.Unparen(call.Args[argIdx]).(*ast.Ident)
		if !isID {
			return false
		}
		pv, _ := info.Uses[aid].(*types.Var)
		params := enclFn.Signature().Params()
		return pv != nil && params.Len() > 0 && params.At(params.Len()-1) == pv && varNeverReassigned(idx, pv)
	}

	allLogCallArgsSafe := func(call *ast.CallExpr, enclFn *types.Func, allowScopedTypeParams bool, allowVariadicForward bool) bool {
		for i, a := range call.Args {
			if allowVariadicForward && isEnclosingVariadicForward(call, enclFn, i) {
				continue
			}
			if !isSafePureLogFormatArgType(g, pureIntraPkgFns, info.TypeOf(a), enclFn, allowScopedTypeParams, map[types.Type]bool{}) {
				return false
			}
		}
		return true
	}

	verifiedHandleLogMethods := map[*types.Func]bool{}
	makeAllowPureLogCall := func(enclFn *types.Func, allowName bool, inHandleLogMethod bool) func(*ast.CallExpr) bool {
		return func(call *ast.CallExpr) bool {
			callee := resolveHarnessFuncExpr(info, call.Fun)
			if callee == nil || callee.Pkg() == nil || callee.Signature() == nil {
				return false
			}
			csig := callee.Signature()
			callSel, _ := syntaxutil.UnwrapCallee(call.Fun).(*ast.SelectorExpr)
			switch callee.Pkg().Path() {
			case "log":
				if callee.Name() != "Print" && callee.Name() != "Printf" && callee.Name() != "Println" {
					return false
				}
				return callSel != nil && isTrustedLoggerFieldExpr(callSel.X) &&
					allLogCallArgsSafe(call, enclFn, true, inHandleLogMethod)
			case "fmt":
				if callee.Name() != "Sprint" && callee.Name() != "Sprintf" && callee.Name() != "Sprintln" {
					return false
				}
				return allLogCallArgsSafe(call, enclFn, false, false)
			default:
				if csig.Recv() == nil || callSel == nil {
					return false
				}
				if isKnownHandleLoggerIface(csig.Recv().Type()) {
					if !isTrustedLoggerIfaceRecv(callSel.X, enclFn) {
						return false
					}
					switch callee.Name() {
					case "Log", "Logf":
						return csig.Results().Len() == 0 &&
							allLogCallArgsSafe(call, enclFn, true, inHandleLogMethod)
					case "Helper":
						return csig.Results().Len() == 0 && len(call.Args) == 0
					case "Name":
						return allowName && csig.Params().Len() == 0 &&
							csig.Results().Len() == 1 && isStringType(csig.Results().At(0).Type())
					default:
						return false
					}
				}
				if sc.isHandleStructPtr(csig.Recv().Type()) {
					return isTrustedHandlePtrVar(callSel.X) && verifiedHandleLogMethods[callee.Origin()] &&
						allLogCallArgsSafe(call, enclFn, true, inHandleLogMethod)
				}
				return false
			}
		}
	}

	for fn, fd := range g.allDecls {
		sig := fn.Signature()
		if sig == nil || sig.Recv() == nil || !sc.isHandleStructPtr(sig.Recv().Type()) ||
			sig.Results().Len() != 0 || g.isFuncValueTaken(fn) || fd == nil || fd.Body == nil {
			continue
		}
		verifiedHandleLogMethods[fn] = true
	}
	variadicForwardSafeCallers := map[*types.Func]bool{}
	for fn, fd := range g.allDecls {
		sig := fn.Signature()
		if sig == nil || !sig.Variadic() || fd == nil || fd.Body == nil {
			continue
		}
		if fn.Exported() {
			if !sc.sealedHandleCallables[fn] {
				continue
			}
		} else if g.isFuncValueTaken(fn) {
			continue
		}
		variadicForwardSafeCallers[fn] = true
	}
	checkAllIntraPkgCallsSafe := func(fn *types.Func) bool {
		for _, uid := range idx.UsesOf[fn] {
			sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
			var call *ast.CallExpr
			if isSel && sel.Sel == uid {
				c, isC := idx.ParentUnparen(sel).(*ast.CallExpr)
				if !isC || ast.Unparen(c.Fun) != sel {
					return false
				}
				call = c
			} else {
				c, isC := idx.ParentUnparen(uid).(*ast.CallExpr)
				if !isC || syntaxutil.UnwrapCallee(c.Fun) != uid {
					return false
				}
				call = c
			}
			var callerFn *types.Func
			if enclFD := idx.EnclFunc[uid]; enclFD != nil && enclFD.Name != nil {
				if cfn, _ := info.Defs[enclFD.Name].(*types.Func); cfn != nil {
					callerFn = cfn.Origin()
				}
			}
			if callerFn == nil {
				return false
			}
			if funcReachesOnlyDriversOrWrappers(g, callerFn) {
				continue
			}
			if !allLogCallArgsSafe(call, callerFn, true, variadicForwardSafeCallers[callerFn]) {
				return false
			}
		}
		return true
	}
	for changed := true; changed; {
		changed = false
		for fn := range variadicForwardSafeCallers {
			if !checkAllIntraPkgCallsSafe(fn) {
				delete(variadicForwardSafeCallers, fn)
				changed = true
			}
		}
	}

	for changed := true; changed; {
		changed = false
		for fn := range verifiedHandleLogMethods {
			fd := g.allDecls[fn]
			if !isClosedPureLoggingStmt(info, fd.Body, nil, nil, false, makeAllowPureLogCall(fn, false, true)) ||
				!checkAllIntraPkgCallsSafe(fn) {
				delete(verifiedHandleLogMethods, fn)
				changed = true
			}
		}
	}

	verifiedHandleOutputMethods := map[*types.Func]bool{}
	for fn, fd := range g.allDecls {
		sig := fn.Signature()
		if sig == nil || sig.Recv() == nil || !sc.isHandleStructPtr(sig.Recv().Type()) ||
			sig.Params().Len() != 0 || sig.Results().Len() != 1 || !isStdIOWriterType(sig.Results().At(0).Type()) ||
			g.isFuncValueTaken(fn) || len(idx.UsesOf[fn]) != 0 || fd == nil || fd.Body == nil {
			continue
		}
		localOutVars := map[*types.Var]bool{}
		allowOutCall := func(call *ast.CallExpr) bool {
			callee := resolveHarnessFuncExpr(info, call.Fun)
			if callee == nil || callee.Pkg() == nil || callee.Signature() == nil {
				return false
			}
			csig := callee.Signature()
			callSel, _ := syntaxutil.UnwrapCallee(call.Fun).(*ast.SelectorExpr)
			switch callee.Pkg().Path() {
			case "log":
				return callee.Name() == "Writer" && csig.Params().Len() == 0 &&
					csig.Results().Len() == 1 && isStdIOWriterType(csig.Results().At(0).Type()) &&
					callSel != nil && isTrustedLoggerFieldExpr(callSel.X)
			case "fmt":
				if callee.Name() != "Sprint" && callee.Name() != "Sprintf" && callee.Name() != "Sprintln" {
					return false
				}
				return allLogCallArgsSafe(call, fn, false, false)
			default:
				if csig.Recv() == nil || callSel == nil {
					return false
				}
				if types.IsInterface(csig.Recv().Type()) {
					if callee.Name() == "Helper" && isKnownHandleLoggerIface(csig.Recv().Type()) && csig.Results().Len() == 0 && len(call.Args) == 0 {
						return isTrustedLoggerIfaceRecv(callSel.X, fn)
					}
					if callee.Name() == "Output" && csig.Params().Len() == 0 && csig.Results().Len() == 1 &&
						isStdIOWriterType(csig.Results().At(0).Type()) {
						rid, isID := ast.Unparen(callSel.X).(*ast.Ident)
						rv, _ := info.Uses[rid].(*types.Var)
						return isID && rv != nil && localOutVars[rv]
					}
					return false
				}
				if sc.isHandleStructPtr(csig.Recv().Type()) && isTrustedHandlePtrVar(callSel.X) && csig.Results().Len() == 0 &&
					allLogCallArgsSafe(call, fn, false, false) {
					return verifiedHandleLogMethods[callee.Origin()] ||
						callee.Name() == "Fatal" || callee.Name() == "Fatalf" || callee.Name() == "FailNow"
				}
				return false
			}
		}
		allowTypeAssertInit := func(s ast.Stmt) bool {
			as, isAs := s.(*ast.AssignStmt)
			if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
				return false
			}
			ta, isTA := ast.Unparen(as.Rhs[0]).(*ast.TypeAssertExpr)
			if !isTA || !isTrustedLoggerIfaceRecv(ta.X, fn) {
				return false
			}
			for _, lhs := range as.Lhs {
				lid, isID := ast.Unparen(lhs).(*ast.Ident)
				if !isID {
					return false
				}
				if lid.Name == "_" {
					continue
				}
				v, _ := info.Defs[lid].(*types.Var)
				if v == nil || v.IsField() {
					return false
				}
				localOutVars[v] = true
			}
			return true
		}
		if isClosedPureLoggingStmt(info, fd.Body, nil, allowTypeAssertInit, true, allowOutCall) {
			verifiedHandleOutputMethods[fn] = true
		}
	}

	isPureLoggingIfBody := func(blk *ast.BlockStmt) bool {
		if blk == nil {
			return false
		}
		enclFD := idx.EnclFunc[blk]
		var enclFn *types.Func
		if enclFD != nil && enclFD.Name != nil {
			if fn, _ := info.Defs[enclFD.Name].(*types.Func); fn != nil {
				enclFn = fn.Origin()
			}
		}
		resultVars, scopePos, scopeEnd := collectEnclosingResultVars(info, idx, blk)
		if scopePos == token.NoPos {
			return false
		}
		inLoop := nodeInsideForOrRange(idx, blk)
		localVars := map[*types.Var]bool{}
		ast.Inspect(blk, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				if v, isV := info.Defs[id].(*types.Var); isV && v != nil && !v.IsField() &&
					blk.Pos() <= v.Pos() && v.Pos() < blk.End() {
					localVars[v] = true
				}
			}
			return true
		})
		isConfinedLocalStringAssign := func(v *types.Var) bool {
			if v == nil || v.IsField() || resultVars[v] || v.Parent() == g.pkgTypes.Scope() || !isStringType(v.Type()) {
				return false
			}
			if localVars[v] {
				return true
			}
			if inLoop || v.Pos() < scopePos || v.Pos() >= scopeEnd {
				return false
			}
			for _, u := range idx.UsesOf[v] {
				if u.Pos() < blk.Pos() || u.Pos() >= blk.End() {
					return false
				}
			}
			return true
		}

		allowIfBodyCall := makeAllowPureLogCall(enclFn, true, false)
		allowIfBodyAssign := func(as *ast.AssignStmt) bool {
			if (as.Tok != token.ASSIGN && as.Tok != token.DEFINE) || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return false
			}
			lhs := ast.Unparen(as.Lhs[0])
			rhs := ast.Unparen(as.Rhs[0])
			if lid, isID := lhs.(*ast.Ident); isID {
				v, _ := info.Defs[lid].(*types.Var)
				if v == nil {
					v, _ = info.Uses[lid].(*types.Var)
				}
				return isConfinedLocalStringAssign(v) && isClosedPureLoggingExpr(info, rhs, allowIfBodyCall)
			}
			if as.Tok == token.ASSIGN && isTrustedLoggerFieldExpr(lhs) && isLogNewStdoutCall(info, rhs) {
				call := rhs.(*ast.CallExpr)
				return isClosedPureLoggingExpr(info, call.Args[1], allowIfBodyCall) &&
					isClosedPureLoggingExpr(info, call.Args[2], allowIfBodyCall)
			}
			return false
		}

		return isClosedPureLoggingStmt(info, blk, allowIfBodyAssign, nil, false, allowIfBodyCall)
	}

	loggingPredMethods := map[*types.Func]bool{}
	isInPureLoggingIfCond := func(node ast.Node) bool {
		allowCondCall := func(c *ast.CallExpr) bool {
			callSel, ok := syntaxutil.UnwrapCallee(c.Fun).(*ast.SelectorExpr)
			if !ok || !isTrustedHandlePtrVar(callSel.X) {
				return false
			}
			if c == node {
				return true
			}
			callee := resolveHarnessFuncExpr(info, c.Fun)
			return callee != nil && loggingPredMethods[callee.Origin()]
		}
		cur := node
		for cur != nil {
			par := idx.ParentMap[cur]
			switch p := par.(type) {
			case *ast.ParenExpr:
				cur = par
			case *ast.UnaryExpr:
				if p.Op != token.NOT {
					return false
				}
				cur = par
			case *ast.BinaryExpr:
				if p.Op != token.LAND && p.Op != token.LOR {
					return false
				}
				cur = par
			case *ast.IfStmt:
				return p.Init == nil && p.Else == nil && cur == p.Cond &&
					isClosedPureLoggingExpr(info, p.Cond, allowCondCall) && isPureLoggingIfBody(p.Body)
			default:
				return false
			}
		}
		return false
	}

	for fn, fd := range g.allDecls {
		sig := fn.Signature()
		if fn.Exported() || g.isFuncValueTaken(fn) || sig == nil || sig.Recv() == nil ||
			sig.Params().Len() != 0 || sig.Results().Len() != 1 || !isBoolType(sig.Results().At(0).Type()) {
			continue
		}
		if !sc.isHandleStructPtr(sig.Recv().Type()) || fd.Body == nil || len(fd.Body.List) != 1 {
			continue
		}
		ret, isRet := fd.Body.List[0].(*ast.ReturnStmt)
		if !isRet || len(ret.Results) != 1 || !isClosedPureLoggingExpr(info, ret.Results[0], nil) {
			continue
		}
		allCallsPureLog := len(idx.UsesOf[fn]) > 0
		for _, uid := range idx.UsesOf[fn] {
			sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
			if !isSel || sel.Sel != uid {
				allCallsPureLog = false
				break
			}
			call, isC := idx.ParentUnparen(sel).(*ast.CallExpr)
			if !isC || ast.Unparen(call.Fun) != sel {
				allCallsPureLog = false
				break
			}
			var callerFn *types.Func
			if enclFD := idx.EnclFunc[uid]; enclFD != nil && enclFD.Name != nil {
				if cfn, _ := info.Defs[enclFD.Name].(*types.Func); cfn != nil {
					callerFn = cfn.Origin()
				}
			}
			if callerFn != nil && funcReachesOnlyDriversOrWrappers(g, callerFn) {
				continue
			}
			if !isInPureLoggingIfCond(call) {
				allCallsPureLog = false
				break
			}
		}
		if allCallsPureLog {
			loggingPredMethods[fn] = true
		}
	}

	verifiedBoolFields := map[*types.Var]bool{}
	for bf := range candBoolFields {
		okField := true
		for _, uid := range idx.UsesOf[bf] {
			sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
			if !isSel || sel.Sel != uid {
				if kv, isKV := idx.ParentUnparen(uid).(*ast.KeyValueExpr); isKV && kv.Key == uid {
					continue
				}
				okField = false
				break
			}
			if exprIsAddrTaken(idx, sel) {
				okField = false
				break
			}
			if as, isAs := idx.ParentUnparen(sel).(*ast.AssignStmt); isAs && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
				if as.Tok == token.ASSIGN && ast.Unparen(as.Lhs[0]) == sel {
					continue
				}
				if as.Tok == token.DEFINE && ast.Unparen(as.Rhs[0]) == sel {
					resVars, _, _ := collectEnclosingResultVars(info, idx, as)
					if lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident); isID {
						if savV, _ := info.Defs[lid].(*types.Var); savV != nil && !resVars[savV] && !g.isReassignedParam(savV) {
							restoredOnly := len(idx.UsesOf[savV]) > 0
							for _, su := range idx.UsesOf[savV] {
								ras, isRAS := idx.ParentUnparen(su).(*ast.AssignStmt)
								if !isRAS || ras.Tok != token.ASSIGN || len(ras.Lhs) != 1 || len(ras.Rhs) != 1 || ast.Unparen(ras.Rhs[0]) != su {
									restoredOnly = false
									break
								}
								lsel, isLS := ast.Unparen(ras.Lhs[0]).(*ast.SelectorExpr)
								if !isLS || info.Uses[lsel.Sel] != bf {
									restoredOnly = false
									break
								}
							}
							if restoredOnly {
								continue
							}
						}
					}
				}
			}
			enclFD := idx.EnclFunc[uid]
			var enclFn *types.Func
			if enclFD != nil && enclFD.Name != nil {
				if fn, _ := info.Defs[enclFD.Name].(*types.Func); fn != nil {
					enclFn = fn.Origin()
				}
			}
			if enclFn != nil && (verifiedHandleLogMethods[enclFn] || verifiedHandleOutputMethods[enclFn] || loggingPredMethods[enclFn] || funcReachesOnlyDriversOrWrappers(g, enclFn)) {
				continue
			}
			if isInPureLoggingIfCond(sel) {
				continue
			}
			okField = false
			break
		}
		if okField {
			verifiedBoolFields[bf] = true
		}
	}

	loggingBoolParams := map[loggingFuncParam]bool{}
	for fn, fd := range g.declFuncs {
		if fn.Exported() || g.isFuncValueTaken(fn) || fd.Body == nil {
			continue
		}
		params := fn.Signature().Params()
		for pIdx := 0; pIdx < params.Len(); pIdx++ {
			pv := params.At(pIdx)
			if !isBoolType(pv.Type()) || g.isReassignedParam(pv) {
				continue
			}
			uses := idx.UsesOf[pv]
			if len(uses) == 0 {
				continue
			}
			allSafe := true
			for _, uid := range uses {
				par := idx.ParentUnparen(uid)
				if kv, isKV := par.(*ast.KeyValueExpr); isKV && ast.Unparen(kv.Value) == uid {
					if kid, isKID := kv.Key.(*ast.Ident); isKID {
						if fv, _ := info.Uses[kid].(*types.Var); fv != nil && verifiedBoolFields[fv] {
							continue
						}
					}
				}
				if as, isAs := par.(*ast.AssignStmt); isAs && as.Tok == token.ASSIGN && len(as.Lhs) == 1 && len(as.Rhs) == 1 && ast.Unparen(as.Rhs[0]) == uid {
					if lsel, isLS := ast.Unparen(as.Lhs[0]).(*ast.SelectorExpr); isLS {
						if fv, _ := info.Uses[lsel.Sel].(*types.Var); fv != nil && verifiedBoolFields[fv] {
							continue
						}
					}
				}
				if isInPureLoggingIfCond(uid) {
					continue
				}
				allSafe = false
				break
			}
			if allSafe {
				loggingBoolParams[loggingFuncParam{fn: fn, idx: pIdx}] = true
			}
		}
	}

	pureReads := map[*ast.Ident]bool{}
	for v := range envFlagVars {
		for id := range g.envFlagReadIdents[v] {
			var valExpr ast.Expr = id
			if !isBoolType(v.Type()) {
				sel, isSel := idx.ParentUnparen(id).(*ast.SelectorExpr)
				if !isSel || ast.Unparen(sel.X) != id || !isBoolType(info.TypeOf(sel)) {
					continue
				}
				valExpr = sel
			}
			par := idx.ParentUnparen(valExpr)
			if call, isC := par.(*ast.CallExpr); isC && !call.Ellipsis.IsValid() {
				callee := resolveHarnessFuncExpr(info, call.Fun)
				if callee != nil {
					callee = callee.Origin()
					argPos := -1
					for ai, a := range call.Args {
						if ast.Unparen(a) == valExpr {
							argPos = ai
							break
						}
					}
					if argPos >= 0 && loggingBoolParams[loggingFuncParam{fn: callee, idx: argPos}] {
						pureReads[id] = true
						continue
					}
				}
			}
			if isInPureLoggingIfCond(valExpr) {
				pureReads[id] = true
				continue
			}
			if g.domain != "" && g.pkg != nil && trace.Enabled(g.ctx, g.domain, g.pkg.PkgPath) {
				posStr := ""
				if g.pkg.Fset != nil && id.Pos().IsValid() {
					posStr = g.pkg.Fset.Position(id.Pos()).String()
				}
				trace.Emit(g.ctx, g.domain, "propharness.logging.reject", g.pkg.PkgPath,
					trace.String("var", v.Name()),
					trace.String("ident", id.Name),
					trace.String("pos", posStr),
				)
			}
		}
	}
	return pureReads
}
