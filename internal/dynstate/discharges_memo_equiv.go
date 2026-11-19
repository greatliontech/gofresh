package dynstate

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

type memoFlowState struct {
	cachePopulated bool
	fromHit        bool
	fromStore      bool
	entryHolders   map[*types.Var]bool
	freshVars      map[*types.Var]bool
	pendingVal     *types.Var
	pendingOk      *types.Var
}

func (s memoFlowState) clone() memoFlowState {
	out := s
	out.entryHolders = make(map[*types.Var]bool, len(s.entryHolders))
	for k, v := range s.entryHolders {
		if v {
			out.entryHolders[k] = true
		}
	}
	out.freshVars = make(map[*types.Var]bool, len(s.freshVars))
	for k, v := range s.freshVars {
		if v {
			out.freshVars[k] = true
		}
	}
	return out
}

func joinMemoFlowStates(a memoFlowState, termA bool, b memoFlowState, termB bool) (memoFlowState, bool, bool) {
	switch {
	case termA && termB:
		return memoFlowState{}, true, true
	case termA:
		return b.clone(), false, true
	case termB:
		return a.clone(), false, true
	default:
		if a.pendingVal != nil || b.pendingVal != nil || a.cachePopulated != b.cachePopulated {
			return memoFlowState{}, false, false
		}
		// Never join a store branch with an unpopulated branch.
		if !a.cachePopulated && (a.fromStore || b.fromStore || a.fromHit || b.fromHit) {
			return memoFlowState{}, false, false
		}
		out := memoFlowState{
			cachePopulated: a.cachePopulated,
			fromHit:        a.fromHit || b.fromHit,
			fromStore:      a.fromStore || b.fromStore,
			entryHolders:   map[*types.Var]bool{},
			freshVars:      map[*types.Var]bool{},
		}
		if out.cachePopulated {
			for k := range a.entryHolders {
				if b.entryHolders[k] {
					out.entryHolders[k] = true
				}
			}
		}
		for k := range a.freshVars {
			if b.freshVars[k] {
				out.freshVars[k] = true
			}
		}
		return out, false, true
	}
}

func verifyMemoGetOrComputeEquivalence(
	p *packages.Package,
	fc *pkgFlowCache,
	memoSig *types.Signature,
	infoNamed *types.Named,
	mapVar *types.Var,
	verified *refconfine.VerifiedMutexMap,
	coneFuncs map[*types.Func]*ast.FuncDecl,
) (bool, string) {
	entryBody := verified.EntryBody
	if entryBody == nil || entryBody.Block == nil || len(verified.StoredValues) != 1 {
		return false, "memo entry body requires single store and explicit returns"
	}

	helperFreshMemo := map[*types.Func]bool{}
	helperVisiting := map[*types.Func]bool{}
	var isFreshNonNilInfoOrigin func(v *flowir.Value) bool
	isFreshNonNilInfoOrigin = func(v *flowir.Value) bool {
		if v == nil || !syntaxutil.IsPtrToNamed(v.Type, infoNamed) {
			return false
		}
		if v.Kind == flowir.ValAllocFresh && v.AllocKind == flowir.AllocCompositeLit {
			return true
		}
		if v.Kind != flowir.ValCall || v.CalleeFunc == nil || v.CalleeFunc == verified.EntryFunc {
			return false
		}
		fd := coneFuncs[v.CalleeFunc]
		if fd == nil {
			return false
		}
		if res, done := helperFreshMemo[v.CalleeFunc]; done {
			return res
		}
		if helperVisiting[v.CalleeFunc] {
			return false
		}
		helperVisiting[v.CalleeFunc] = true
		okH := verifyHelperReturnsFreshNonNilInfo(p, fc, infoNamed, fd, isFreshNonNilInfoOrigin)
		delete(helperVisiting, v.CalleeFunc)
		helperFreshMemo[v.CalleeFunc] = okH
		return okH
	}

	opsByNode := map[ast.Node][]*flowir.Op{}
	rangeBodyByStmt := map[*ast.RangeStmt]*flowir.Body{}
	totalOps := 0
	badBranch := false
	addrTakenLocals, hasClosureHazard := scanMemoBodyClosureAndAddrHazards(entryBody, mapVar)
	if hasClosureHazard {
		return false, "memo entry closure or IIFE mutates or takes address of outer variable"
	}
	var indexOps func(b *flowir.Body)
	indexOps = func(b *flowir.Body) {
		if b == nil || badBranch {
			return
		}
		for i := range b.Ops {
			op := &b.Ops[i]
			totalOps++
			if op.StmtAST == nil {
				badBranch = true
				return
			}
			if op.Kind == flowir.OpBranch {
				bs, ok := op.StmtAST.(*ast.BranchStmt)
				if !ok || bs.Tok == token.GOTO || bs.Tok == token.FALLTHROUGH || bs.Label != nil {
					badBranch = true
					return
				}
			}
			opsByNode[op.StmtAST] = append(opsByNode[op.StmtAST], op)
			if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
				rs, ok := op.StmtAST.(*ast.RangeStmt)
				if !ok {
					badBranch = true
					return
				}
				rangeBodyByStmt[rs] = op.RangeBody
				indexOps(op.RangeBody)
			}
		}
	}
	indexOps(entryBody)
	if badBranch {
		return false, "unsupported branch in memo entry body"
	}

	errSlot := -1
	for ri := 0; ri < memoSig.Results().Len(); ri++ {
		if isUniverseErrorType(memoSig.Results().At(ri).Type()) {
			if errSlot != -1 {
				return false, "multiple error result slots"
			}
			errSlot = ri
		}
	}

	var canonicalProj [][]*types.Var
	hasCanonicalProj := false
	sawHitReturn := false
	sawStoreReturn := false
	storeOpCount := 0
	lookupOpCount := 0
	visitedOps := 0
	failReason := ""

	isZeroPreStoreVal := func(v *flowir.Value) bool {
		if v == nil {
			return false
		}
		if v.IsNil {
			return true
		}
		if !v.IsConst || v.Raw == nil || p.TypesInfo == nil {
			return false
		}
		tv := p.TypesInfo.Types[ast.Unparen(v.Raw)]
		if tv.Value == nil {
			return false
		}
		switch tv.Value.Kind() {
		case constant.Bool:
			return !constant.BoolVal(tv.Value)
		case constant.String:
			return constant.StringVal(tv.Value) == ""
		case constant.Int, constant.Float, constant.Complex:
			return constant.Sign(tv.Value) == 0
		default:
			return false
		}
	}

	checkReturnOp := func(op *flowir.Op, st memoFlowState) bool {
		if op.IsNaked || len(op.Results) != memoSig.Results().Len() || st.pendingVal != nil {
			failReason = "invalid return shape or unbranched map lookup"
			return false
		}
		if st.cachePopulated {
			proj := make([][]*types.Var, len(op.Results))
			for ri, r := range op.Results {
				if ri == errSlot {
					if r == nil || !r.IsNil {
						failReason = "populated memo return has non-nil error"
						return false
					}
					continue
				}
				if r == nil || r.Kind != flowir.ValPlace || r.Place.Root != flowir.RootLocal || !st.entryHolders[r.Place.Obj] {
					failReason = "populated memo return does not project cached entry"
					return false
				}
				fields := make([]*types.Var, 0, len(r.Place.Projs))
				for _, pr := range r.Place.Projs {
					if pr.Kind != flowir.ProjField || pr.Field == nil {
						failReason = "populated memo return uses non-field projection"
						return false
					}
					fields = append(fields, pr.Field)
				}
				proj[ri] = fields
			}
			if !hasCanonicalProj {
				canonicalProj = proj
				hasCanonicalProj = true
			} else {
				for ri := range proj {
					if !slices.Equal(canonicalProj[ri], proj[ri]) {
						failReason = "hit and miss return projections diverge"
						return false
					}
				}
			}
			if st.fromHit {
				sawHitReturn = true
			}
			if st.fromStore {
				sawStoreReturn = true
			}
			return true
		}
		// Unpopulated early return: allowed only before any hit/store when returning a non-nil error and zero values.
		if st.fromHit || st.fromStore || errSlot < 0 {
			failReason = "unpopulated non-error early return"
			return false
		}
		for ri, r := range op.Results {
			if ri == errSlot {
				if r == nil || r.IsNil {
					failReason = "unpopulated early return has nil error"
					return false
				}
				continue
			}
			if !isZeroPreStoreVal(r) {
				failReason = "unpopulated early return has non-zero value slot"
				return false
			}
		}
		return true
	}

	isMapLookupVal := func(v *flowir.Value) bool {
		return v != nil && v.Kind == flowir.ValPlace && v.Place.Obj == mapVar &&
			len(v.Place.Projs) == 1 && v.Place.Projs[0].Kind == flowir.ProjIndex
	}

	applyOp := func(op *flowir.Op, st memoFlowState, inLoop bool) (memoFlowState, bool, bool) {
		visitedOps++
		isLockTrans := verified.EntryRegions != nil && verified.EntryRegions.IsLockTransitionOp[op]
		if st.fromStore {
			if isLockTrans {
				return st, false, true
			}
			if op.Kind == flowir.OpReturn {
				if !checkReturnOp(op, st) {
					return memoFlowState{}, false, false
				}
				return st, true, true
			}
			failReason = "post-store non-return op"
			return memoFlowState{}, false, false
		}
		if st.pendingVal != nil && !isLockTrans {
			failReason = "statement intervenes between map lookup and hit guard"
			return memoFlowState{}, false, false
		}
		if isLockTrans {
			return st, false, true
		}

		switch op.Kind {
		case flowir.OpReturn:
			if !checkReturnOp(op, st) {
				return memoFlowState{}, false, false
			}
			return st, true, true

		case flowir.OpGo, flowir.OpDefer:
			// Lock defer (`defer mu.Unlock()`) is marked in IsLockTransitionOp and handled above.
			failReason = "non-lock defer or goroutine in memo entry"
			return memoFlowState{}, false, false

		case flowir.OpAssign:
			out := st.clone()
			switch op.AssignKind {
			case flowir.AssignZeroDecl:
				for _, dst := range op.Dsts {
					if dst.Obj != nil {
						delete(out.freshVars, dst.Obj)
						delete(out.entryHolders, dst.Obj)
					}
				}
				return out, false, true

			case flowir.AssignPlain:
				if len(op.Dsts) == 1 && len(op.Srcs) == 1 && op.Srcs[0] != nil && op.Dsts[0].Obj == mapVar {
					if inLoop || out.cachePopulated || out.fromStore || out.fromHit {
						failReason = "map store in loop or after hit/store"
						return memoFlowState{}, false, false
					}
					src := op.Srcs[0]
					if src.Kind != flowir.ValPlace || !src.Place.IsBareVar() || src.Place.Root != flowir.RootLocal || !out.freshVars[src.Place.Obj] {
						failReason = "stored value not local holding fresh non-nil *infoNamed"
						return memoFlowState{}, false, false
					}
					storeOpCount++
					out.cachePopulated = true
					out.fromStore = true
					out.entryHolders = map[*types.Var]bool{src.Place.Obj: true}
					return out, false, true
				}
				if len(op.Dsts) == 1 && len(op.Srcs) == 1 && isMapLookupVal(op.Srcs[0]) {
					dst := op.Dsts[0]
					if inLoop || out.cachePopulated || out.fromStore || out.fromHit ||
						dst.IsBlank() || !dst.IsBareVar() || dst.Root != flowir.RootLocal || dst.Obj == nil || addrTakenLocals[dst.Obj] {
						failReason = "invalid single-value map lookup"
						return memoFlowState{}, false, false
					}
					lookupOpCount++
					delete(out.freshVars, dst.Obj)
					delete(out.entryHolders, dst.Obj)
					out.pendingVal = dst.Obj
					out.pendingOk = nil
					return out, false, true
				}
				for di, dst := range op.Dsts {
					if dst.Obj == mapVar {
						failReason = "invalid map assignment"
						return memoFlowState{}, false, false
					}
					if dst.Obj != nil {
						wasFresh := out.freshVars[dst.Obj]
						wasHolder := out.entryHolders[dst.Obj]
						delete(out.freshVars, dst.Obj)
						delete(out.entryHolders, dst.Obj)
						if dst.IsBareVar() && dst.Root == flowir.RootLocal && !addrTakenLocals[dst.Obj] && di < len(op.Srcs) && op.Srcs[di] != nil {
							rhs := op.Srcs[di]
							if isFreshNonNilInfoOrigin(rhs) {
								out.freshVars[dst.Obj] = true
							} else if rhs.Kind == flowir.ValPlace && rhs.Place.IsBareVar() && rhs.Place.Obj != nil {
								if (rhs.Place.Obj == dst.Obj && wasFresh) || out.freshVars[rhs.Place.Obj] {
									out.freshVars[dst.Obj] = true
								}
								if (rhs.Place.Obj == dst.Obj && wasHolder) || out.entryHolders[rhs.Place.Obj] {
									out.entryHolders[dst.Obj] = true
								}
							}
						}
					}
				}
				return out, false, true

			case flowir.AssignMulti:
				if len(op.Srcs) == 1 && isMapLookupVal(op.Srcs[0]) {
					if inLoop || out.cachePopulated || out.fromStore || out.fromHit || len(op.Dsts) != 2 {
						failReason = "invalid comma-ok map lookup context"
						return memoFlowState{}, false, false
					}
					dst0, dst1 := op.Dsts[0], op.Dsts[1]
					if dst0.IsBlank() || !dst0.IsBareVar() || dst0.Root != flowir.RootLocal || dst0.Obj == nil || addrTakenLocals[dst0.Obj] ||
						dst1.IsBlank() || !dst1.IsBareVar() || dst1.Root != flowir.RootLocal || dst1.Obj == nil || addrTakenLocals[dst1.Obj] ||
						dst0.Obj == dst1.Obj {
						failReason = "comma-ok map lookup must bind distinct local value and ok vars"
						return memoFlowState{}, false, false
					}
					lookupOpCount++
					delete(out.freshVars, dst0.Obj)
					delete(out.freshVars, dst1.Obj)
					delete(out.entryHolders, dst0.Obj)
					delete(out.entryHolders, dst1.Obj)
					out.pendingVal = dst0.Obj
					out.pendingOk = dst1.Obj
					return out, false, true
				}
				for _, dst := range op.Dsts {
					if dst.Obj == mapVar {
						failReason = "invalid multi map assignment"
						return memoFlowState{}, false, false
					}
					if dst.Obj != nil {
						delete(out.freshVars, dst.Obj)
						delete(out.entryHolders, dst.Obj)
					}
				}
				return out, false, true

			default:
				for _, dst := range op.Dsts {
					if dst.Obj == mapVar {
						failReason = "invalid compound/range map assignment"
						return memoFlowState{}, false, false
					}
					if dst.Obj != nil {
						delete(out.freshVars, dst.Obj)
						delete(out.entryHolders, dst.Obj)
					}
				}
				return out, false, true
			}

		case flowir.OpTypeSwitchBind:
			out := st.clone()
			if op.SwitchDst != nil {
				delete(out.freshVars, op.SwitchDst)
				delete(out.entryHolders, op.SwitchDst)
			}
			return out, false, true

		case flowir.OpExpr:
			if op.Expr != nil && op.Expr.Kind == flowir.ValCall &&
				op.Expr.CallKind == flowir.CallBuiltin && op.Expr.BuiltinName == "panic" {
				failReason = "panic in memo entry"
				return memoFlowState{}, false, false
			}
			return st, false, true

		default:
			failReason = "unsupported op in memo entry"
			return memoFlowState{}, false, false
		}
	}

	applyNodeOps := func(n ast.Node, st memoFlowState, inLoop bool) (memoFlowState, bool, bool) {
		ops := opsByNode[n]
		if len(ops) == 0 {
			return memoFlowState{}, false, false
		}
		cur := st
		for _, op := range ops {
			var term, ok bool
			cur, term, ok = applyOp(op, cur, inLoop)
			if !ok {
				return memoFlowState{}, false, false
			}
			if term {
				return cur, true, true
			}
		}
		return cur, false, true
	}

	matchPendingCond := func(condVal *flowir.Value, valVar, okVar *types.Var) (hitOnTrue bool, ok bool) {
		if condVal == nil || valVar == nil {
			return false, false
		}
		isVar := func(v *flowir.Value, target *types.Var) bool {
			return v != nil && v.Kind == flowir.ValPlace && v.Place.IsBareVar() && v.Place.Obj == target
		}
		isBoolConst := func(v *flowir.Value) (val bool, isB bool) {
			if v == nil || !v.IsConst || v.Raw == nil || p.TypesInfo == nil {
				return false, false
			}
			tv := p.TypesInfo.Types[ast.Unparen(v.Raw)]
			if tv.Value == nil || tv.Value.Kind() != constant.Bool {
				return false, false
			}
			return constant.BoolVal(tv.Value), true
		}
		if okVar != nil {
			if isVar(condVal, okVar) {
				return true, true
			}
			if condVal.Kind == flowir.ValCompositeExpr && len(condVal.Args) == 1 && condVal.Raw != nil {
				if un, isUn := ast.Unparen(condVal.Raw).(*ast.UnaryExpr); isUn && un.Op == token.NOT && isVar(condVal.Args[0], okVar) {
					return false, true
				}
			}
			if condVal.Kind == flowir.ValCompare && (condVal.CompareOp == token.EQL || condVal.CompareOp == token.NEQ) {
				if b, isB := isBoolConst(condVal.Right); isB && isVar(condVal.Left, okVar) {
					if condVal.CompareOp == token.EQL {
						return b, true
					}
					return !b, true
				}
				if b, isB := isBoolConst(condVal.Left); isB && isVar(condVal.Right, okVar) {
					if condVal.CompareOp == token.EQL {
						return b, true
					}
					return !b, true
				}
			}
			return false, false
		}
		if condVal.Kind == flowir.ValCompare && (condVal.CompareOp == token.EQL || condVal.CompareOp == token.NEQ) {
			if (isVar(condVal.Left, valVar) && condVal.Right != nil && condVal.Right.IsNil) ||
				(isVar(condVal.Right, valVar) && condVal.Left != nil && condVal.Left.IsNil) {
				return condVal.CompareOp == token.NEQ, true
			}
		}
		return false, false
	}

	var switchBreakStack [][]memoFlowState
	var loopHasBreakStack []bool
	var walkStmt func(stmt ast.Stmt, cur memoFlowState, inLoop bool, inSwitch bool) (memoFlowState, bool, bool)
	walkStmtList := func(stmts []ast.Stmt, cur memoFlowState, inLoop bool, inSwitch bool) (memoFlowState, bool, bool) {
		for idxSt, st := range stmts {
			if st == nil {
				continue
			}
			if _, isEmpty := st.(*ast.EmptyStmt); isEmpty {
				continue
			}
			var term, ok bool
			cur, term, ok = walkStmt(st, cur, inLoop, inSwitch)
			if !ok {
				return memoFlowState{}, false, false
			}
			if term {
				for k := idxSt + 1; k < len(stmts); k++ {
					if stmts[k] != nil {
						if _, isE := stmts[k].(*ast.EmptyStmt); !isE {
							failReason = "unreachable trailing statement"
							return memoFlowState{}, false, false
						}
					}
				}
				return cur, true, true
			}
		}
		return cur, false, true
	}

	walkStmt = func(stmt ast.Stmt, cur memoFlowState, inLoop bool, inSwitch bool) (memoFlowState, bool, bool) {
		switch s := stmt.(type) {
		case nil, *ast.EmptyStmt:
			return cur, false, true

		case *ast.LabeledStmt:
			return walkStmt(s.Stmt, cur, inLoop, inSwitch)

		case *ast.BlockStmt:
			return walkStmtList(s.List, cur, inLoop, inSwitch)

		case *ast.DeclStmt:
			gd, ok := s.Decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
				return cur, false, true
			}
			for _, spec := range gd.Specs {
				vs, okVS := spec.(*ast.ValueSpec)
				if !okVS {
					continue
				}
				var term, okOp bool
				cur, term, okOp = applyNodeOps(vs, cur, inLoop)
				if !okOp || term {
					return cur, term, okOp
				}
			}
			return cur, false, true

		case *ast.ExprStmt, *ast.SendStmt, *ast.IncDecStmt, *ast.AssignStmt, *ast.GoStmt, *ast.DeferStmt, *ast.ReturnStmt:
			return applyNodeOps(s, cur, inLoop)

		case *ast.BranchStmt:
			if cur.pendingVal != nil || cur.fromStore || cur.cachePopulated {
				failReason = "branch statement after lookup/store"
				return memoFlowState{}, false, false
			}
			ops := opsByNode[s]
			if len(ops) != 1 {
				return memoFlowState{}, false, false
			}
			visitedOps++
			switch s.Tok {
			case token.CONTINUE:
				if !inLoop {
					return memoFlowState{}, false, false
				}
				return cur, true, true
			case token.BREAK:
				if inSwitch && len(switchBreakStack) > 0 {
					top := len(switchBreakStack) - 1
					switchBreakStack[top] = append(switchBreakStack[top], cur.clone())
					return cur, true, true
				}
				if inLoop && len(loopHasBreakStack) > 0 {
					loopHasBreakStack[len(loopHasBreakStack)-1] = true
					return cur, true, true
				}
				return memoFlowState{}, false, false
			default:
				return memoFlowState{}, false, false
			}

		case *ast.IfStmt:
			if s.Init != nil {
				var term, ok bool
				cur, term, ok = walkStmt(s.Init, cur, inLoop, inSwitch)
				if !ok || term {
					return memoFlowState{}, false, false
				}
			}
			if s.Cond == nil || s.Body == nil {
				return memoFlowState{}, false, false
			}
			condOps := opsByNode[s]
			if len(condOps) != 1 || condOps[0].Kind != flowir.OpExpr {
				return memoFlowState{}, false, false
			}
			if cur.fromStore {
				failReason = "if statement after map store"
				return memoFlowState{}, false, false
			}
			thenIn := cur.clone()
			elseIn := cur.clone()
			if cur.pendingVal != nil {
				hitOnTrue, okGuard := matchPendingCond(condOps[0].Expr, cur.pendingVal, cur.pendingOk)
				if !okGuard {
					failReason = "if condition does not check pending map lookup"
					return memoFlowState{}, false, false
				}
				visitedOps++
				valVar := cur.pendingVal
				thenIn.pendingVal, thenIn.pendingOk = nil, nil
				elseIn.pendingVal, elseIn.pendingOk = nil, nil
				if hitOnTrue {
					thenIn.cachePopulated = true
					thenIn.fromHit = true
					thenIn.entryHolders = map[*types.Var]bool{valVar: true}
				} else {
					elseIn.cachePopulated = true
					elseIn.fromHit = true
					elseIn.entryHolders = map[*types.Var]bool{valVar: true}
				}
			} else {
				var termCond, okCond bool
				cur, termCond, okCond = applyOp(condOps[0], cur, inLoop)
				if !okCond || termCond {
					return memoFlowState{}, false, false
				}
				thenIn = cur.clone()
				elseIn = cur.clone()
			}

			thenOut, thenTerm, okThen := walkStmtList(s.Body.List, thenIn, inLoop, inSwitch)
			if !okThen {
				return memoFlowState{}, false, false
			}
			elseOut, elseTerm := elseIn, false
			if s.Else != nil {
				var okElse bool
				elseOut, elseTerm, okElse = walkStmt(s.Else, elseIn, inLoop, inSwitch)
				if !okElse {
					return memoFlowState{}, false, false
				}
			}
			joined, jTerm, okJoin := joinMemoFlowStates(thenOut, thenTerm, elseOut, elseTerm)
			if !okJoin && failReason == "" {
				failReason = "incompatible memo states at if branch join"
			}
			return joined, jTerm, okJoin

		case *ast.SwitchStmt:
			if cur.pendingVal != nil || cur.fromStore || cur.cachePopulated {
				failReason = "switch statement with pending lookup or populated cache"
				return memoFlowState{}, false, false
			}
			if s.Init != nil {
				var term, ok bool
				cur, term, ok = walkStmt(s.Init, cur, inLoop, inSwitch)
				if !ok || term || cur.pendingVal != nil || cur.fromStore || cur.cachePopulated {
					return memoFlowState{}, false, false
				}
			}
			if s.Tag != nil {
				var term, ok bool
				cur, term, ok = applyNodeOps(s, cur, inLoop)
				if !ok || term {
					return memoFlowState{}, false, false
				}
			}
			if s.Body == nil {
				return memoFlowState{}, false, false
			}
			switchBreakStack = append(switchBreakStack, nil)
			var liveOut []memoFlowState
			hasDefault := false
			for _, raw := range s.Body.List {
				cc, okCC := raw.(*ast.CaseClause)
				if !okCC {
					switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
					return memoFlowState{}, false, false
				}
				if cc.List == nil {
					hasDefault = true
				}
				if len(opsByNode[cc]) > 0 {
					if _, termCond, okCond := applyNodeOps(cc, cur, inLoop); !okCond || termCond {
						switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
						return memoFlowState{}, false, false
					}
				}
				armOut, armTerm, okArm := walkStmtList(cc.Body, cur.clone(), inLoop, true)
				if !okArm {
					switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
					return memoFlowState{}, false, false
				}
				if !armTerm {
					liveOut = append(liveOut, armOut)
				}
			}
			breaks := switchBreakStack[len(switchBreakStack)-1]
			switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
			liveOut = append(liveOut, breaks...)
			if !hasDefault {
				liveOut = append(liveOut, cur.clone())
			}
			if len(liveOut) == 0 {
				return memoFlowState{}, true, true
			}
			acc := liveOut[0]
			for i := 1; i < len(liveOut); i++ {
				var okJ bool
				acc, _, okJ = joinMemoFlowStates(acc, false, liveOut[i], false)
				if !okJ {
					return memoFlowState{}, false, false
				}
			}
			return acc, false, true

		case *ast.TypeSwitchStmt:
			if cur.pendingVal != nil || cur.fromStore || cur.cachePopulated {
				failReason = "type switch with pending lookup or populated cache"
				return memoFlowState{}, false, false
			}
			if s.Init != nil {
				var term, ok bool
				cur, term, ok = walkStmt(s.Init, cur, inLoop, inSwitch)
				if !ok || term || cur.pendingVal != nil || cur.fromStore || cur.cachePopulated {
					return memoFlowState{}, false, false
				}
			}
			if _, termGuard, okGuard := applyNodeOps(s, cur, inLoop); !okGuard || termGuard {
				return memoFlowState{}, false, false
			}
			if s.Body == nil {
				return memoFlowState{}, false, false
			}
			switchBreakStack = append(switchBreakStack, nil)
			var liveOut []memoFlowState
			hasDefault := false
			for _, raw := range s.Body.List {
				cc, okCC := raw.(*ast.CaseClause)
				if !okCC {
					switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
					return memoFlowState{}, false, false
				}
				if cc.List == nil {
					hasDefault = true
				}
				armIn := cur.clone()
				if len(opsByNode[cc]) > 0 {
					var termCase, okCase bool
					armIn, termCase, okCase = applyNodeOps(cc, armIn, inLoop)
					if !okCase || termCase {
						switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
						return memoFlowState{}, false, false
					}
				}
				armOut, armTerm, okArm := walkStmtList(cc.Body, armIn, inLoop, true)
				if !okArm {
					switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
					return memoFlowState{}, false, false
				}
				if !armTerm {
					liveOut = append(liveOut, armOut)
				}
			}
			breaks := switchBreakStack[len(switchBreakStack)-1]
			switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
			liveOut = append(liveOut, breaks...)
			if !hasDefault {
				liveOut = append(liveOut, cur.clone())
			}
			if len(liveOut) == 0 {
				return memoFlowState{}, true, true
			}
			acc := liveOut[0]
			for i := 1; i < len(liveOut); i++ {
				var okJ bool
				acc, _, okJ = joinMemoFlowStates(acc, false, liveOut[i], false)
				if !okJ {
					return memoFlowState{}, false, false
				}
			}
			return acc, false, true

		case *ast.ForStmt:
			if cur.pendingVal != nil || cur.fromStore || cur.cachePopulated {
				failReason = "for loop with pending lookup or populated cache"
				return memoFlowState{}, false, false
			}
			if s.Init != nil {
				var term, ok bool
				cur, term, ok = walkStmt(s.Init, cur, true, false)
				if !ok || term || cur.pendingVal != nil || cur.fromStore || cur.cachePopulated {
					return memoFlowState{}, false, false
				}
			}
			if s.Cond != nil {
				var term, ok bool
				cur, term, ok = applyNodeOps(s, cur, true)
				if !ok || term {
					return memoFlowState{}, false, false
				}
			}
			if s.Post != nil {
				postOut, postTerm, okPost := walkStmt(s.Post, cur.clone(), true, false)
				if !okPost || postTerm || postOut.pendingVal != nil || postOut.fromStore || postOut.cachePopulated {
					return memoFlowState{}, false, false
				}
				for fv := range cur.freshVars {
					if !postOut.freshVars[fv] {
						delete(cur.freshVars, fv)
					}
				}
			}
			loopHasBreakStack = append(loopHasBreakStack, false)
			if s.Body != nil {
				bodyOut, bodyTerm, okBody := walkStmtList(s.Body.List, cur.clone(), true, false)
				if !okBody || (!bodyTerm && (bodyOut.pendingVal != nil || bodyOut.fromStore || bodyOut.cachePopulated)) {
					loopHasBreakStack = loopHasBreakStack[:len(loopHasBreakStack)-1]
					return memoFlowState{}, false, false
				}
				if !bodyTerm {
					for fv := range cur.freshVars {
						if !bodyOut.freshVars[fv] {
							delete(cur.freshVars, fv)
						}
					}
				}
			}
			sawBreak := loopHasBreakStack[len(loopHasBreakStack)-1]
			loopHasBreakStack = loopHasBreakStack[:len(loopHasBreakStack)-1]
			invalidateLoopWrittenFreshVars(p, s, &cur)
			if s.Cond == nil && !sawBreak {
				return cur, true, true
			}
			return cur, false, true

		case *ast.RangeStmt:
			if cur.pendingVal != nil || cur.fromStore || cur.cachePopulated {
				failReason = "range loop with pending lookup or populated cache"
				return memoFlowState{}, false, false
			}
			ops := opsByNode[s]
			if len(ops) != 1 {
				return memoFlowState{}, false, false
			}
			var termHdr, okHdr bool
			cur, termHdr, okHdr = applyOp(ops[0], cur, true)
			if !okHdr || termHdr {
				return memoFlowState{}, false, false
			}
			loopHasBreakStack = append(loopHasBreakStack, false)
			if rb := rangeBodyByStmt[s]; rb != nil && rb.Block != nil {
				bodyOut, bodyTerm, okBody := walkStmtList(rb.Block.List, cur.clone(), true, false)
				if !okBody || (!bodyTerm && (bodyOut.pendingVal != nil || bodyOut.fromStore || bodyOut.cachePopulated)) {
					loopHasBreakStack = loopHasBreakStack[:len(loopHasBreakStack)-1]
					return memoFlowState{}, false, false
				}
				if !bodyTerm {
					for fv := range cur.freshVars {
						if !bodyOut.freshVars[fv] {
							delete(cur.freshVars, fv)
						}
					}
				}
			}
			loopHasBreakStack = loopHasBreakStack[:len(loopHasBreakStack)-1]
			invalidateLoopWrittenFreshVars(p, s, &cur)
			return cur, false, true

		default:
			return memoFlowState{}, false, false
		}
	}

	initState := memoFlowState{
		entryHolders: map[*types.Var]bool{},
		freshVars:    map[*types.Var]bool{},
	}
	_, endTerm, okWalk := walkStmtList(entryBody.Block.List, initState, false, false)
	if !okWalk {
		if failReason != "" {
			return false, failReason
		}
		return false, "memo entry control-flow verification failed"
	}
	if !endTerm || visitedOps != totalOps {
		return false, "memo entry falls through or leaves unvisited ops"
	}
	if storeOpCount != 1 || lookupOpCount < 1 || !sawHitReturn || !sawStoreReturn || !hasCanonicalProj {
		return false, "memo entry lacks matched hit and store return paths"
	}
	return true, ""
}
