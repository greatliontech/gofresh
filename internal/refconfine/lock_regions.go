package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// LockTargetKind classifies the mutex root tracked by VerifyBodyLockRegions.
type LockTargetKind uint8

const (
	LockPkgGlobalVar LockTargetKind = iota + 1
	LockRecvField
)

// LockTarget identifies a dedicated synchronization mutex whose critical
// sections are verified over a flowir.Body.
type LockTarget struct {
	Kind      LockTargetKind
	MutexVar  *types.Var // LockPkgGlobalVar: unexported single-def sync.Mutex or sync.RWMutex
	RecvVar   *types.Var // LockRecvField: method pointer receiver *S
	LockField *types.Var // LockRecvField: embedded or named sync.Mutex / sync.RWMutex field
	IsRWMutex bool
}

// LockMode represents the abstract lock state along every control-flow path.
type LockMode uint8

const (
	LockInvalid LockMode = iota
	LockUnlocked
	LockReadHeld
	LockWriteHeld
	LockReadDeferred
	LockWriteDeferred
)

// IsReadOrWriteLocked reports whether m holds either a shared read lock or an
// exclusive write lock.
func (m LockMode) IsReadOrWriteLocked() bool {
	return m == LockReadHeld || m == LockReadDeferred || m == LockWriteHeld || m == LockWriteDeferred
}

// IsWriteLocked reports whether m holds an exclusive write lock.
func (m LockMode) IsWriteLocked() bool {
	return m == LockWriteHeld || m == LockWriteDeferred
}

// ValidExit reports whether returning or exiting the function in mode m leaves
// the mutex balanced (unlocked immediately or unlocked by a single registered
// defer).
func (m LockMode) ValidExit() bool {
	return m == LockUnlocked || m == LockReadDeferred || m == LockWriteDeferred
}

// BodyLockRegions records the verified pre-operation LockMode for every
// synchronous flowir.Op in a function body.
type BodyLockRegions struct {
	OpModes            map[*flowir.Op]LockMode
	IsLockTransitionOp map[*flowir.Op]bool
}

// VerifyBodyLockRegions performs structured control-flow region dominance over
// body (using its cached flowir.Ops), verifying within body that target is
// never copied by value, addressed, captured by closures/goroutines, or
// transitioned inside loops, that every return/fallthrough/panic path leaves
// target balanced, and that every join point agrees on a single LockMode.
// Callers enforce any cross-function or package-wide isolation of target.
func VerifyBodyLockRegions(
	p *packages.Package,
	_ *PkgIndex,
	body *flowir.Body,
	target LockTarget,
) (*BodyLockRegions, bool) {
	if p == nil || p.TypesInfo == nil || body == nil || body.Block == nil || !syntaxutil.IsTrueStdlibInPkg(p, "sync") {
		return nil, false
	}
	switch target.Kind {
	case LockPkgGlobalVar:
		if target.MutexVar == nil {
			return nil, false
		}
	case LockRecvField:
		if target.RecvVar == nil || target.LockField == nil {
			return nil, false
		}
	default:
		return nil, false
	}

	matchLockCall := func(v *flowir.Value) (string, bool) {
		if v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallMethod || v.IsMethodExprCall ||
			len(v.Args) != 0 || v.Ellipsis || v.CalleeFunc == nil || v.CalleePkg != "sync" || !v.HasRecvPlace {
			return "", false
		}
		mName := v.CalleeFunc.Name()
		switch mName {
		case "Lock", "Unlock":
		case "RLock", "RUnlock":
			if !target.IsRWMutex {
				return "", false
			}
		default:
			return "", false
		}
		switch target.Kind {
		case LockPkgGlobalVar:
			if !v.RecvPlace.IsBareVar() || v.RecvPlace.Obj != target.MutexVar {
				return "", false
			}
			return mName, true
		case LockRecvField:
			if v.RecvPlace.Obj != target.RecvVar {
				return "", false
			}
			if v.RecvPlace.IsBareVar() {
				if v.Selection == nil || !selectionReachesField(target.RecvVar.Type(), v.Selection, target.LockField) {
					return "", false
				}
				return mName, true
			}
			if len(v.RecvPlace.Projs) == 1 && v.RecvPlace.Projs[0].Kind == flowir.ProjField &&
				v.RecvPlace.Projs[0].Selection != nil && v.RecvPlace.Projs[0].Selection.Obj() == target.LockField {
				return mName, true
			}
			return "", false
		}
		return "", false
	}

	// Count total occurrences of the mutex target across all synchronous and
	// nested bodies, ensuring zero non-transition uses (no copies, &mu, closures,
	// goroutines, TryLock, or RLocker).
	totalMutexMentions := 0
	invalidMention := false
	var scanMentionsInBody func(b *flowir.Body, nested bool)
	scanMentionsInPlace := func(pl flowir.Place, nested bool) {
		switch target.Kind {
		case LockPkgGlobalVar:
			if pl.Obj == target.MutexVar {
				if nested {
					invalidMention = true
				}
				totalMutexMentions++
			}
		case LockRecvField:
			if pl.Obj == target.RecvVar {
				// Reject whole-struct dereference (*recv) which copies embedded sync.Mutex.
				if len(pl.Projs) == 1 && pl.Projs[0].Kind == flowir.ProjDeref {
					invalidMention = true
				}
				for _, pr := range pl.Projs {
					if pr.Kind == flowir.ProjField && pr.Selection != nil && pr.Selection.Obj() == target.LockField {
						if nested {
							invalidMention = true
						}
						totalMutexMentions++
					}
				}
			}
		}
	}
	scanMentionsInVal := func(v *flowir.Value, nested bool) {
		if v == nil || invalidMention {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			if invalidMention {
				return false
			}
			switch cur.Kind {
			case flowir.ValPlace:
				scanMentionsInPlace(cur.Place, nested)
			case flowir.ValAddrOf:
				scanMentionsInPlace(cur.AddrPlace, nested)
			case flowir.ValMethodVal:
				if cur.HasRecvPlace {
					scanMentionsInPlace(cur.RecvPlace, nested)
				}
				if target.Kind == LockRecvField && cur.HasRecvPlace && cur.RecvPlace.Obj == target.RecvVar &&
					cur.Method != nil && cur.Method.Pkg() != nil && cur.Method.Pkg().Path() == "sync" {
					invalidMention = true
					return false
				}
			case flowir.ValCall:
				if target.Kind == LockRecvField && cur.HasRecvPlace && cur.RecvPlace.Obj == target.RecvVar &&
					cur.CalleePkg == "sync" {
					if nested {
						invalidMention = true
						return false
					}
					if cur.RecvPlace.IsBareVar() {
						totalMutexMentions++
					}
				}
				if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil {
					scanMentionsInBody(cur.IIFE, true)
				}
			case flowir.ValMakeClosure:
				if cur.Closure != nil {
					scanMentionsInBody(cur.Closure, true)
				}
			}
			return true
		})
	}
	scanMentionsInBody = func(b *flowir.Body, nested bool) {
		if b == nil || invalidMention {
			return
		}
		for i := range b.Ops {
			op := &b.Ops[i]
			childNested := nested || op.Kind == flowir.OpGo
			switch op.Kind {
			case flowir.OpAssign:
				for _, dst := range op.Dsts {
					scanMentionsInPlace(dst, childNested)
				}
			case flowir.OpChanSend:
				scanMentionsInPlace(op.ChanPlace, childNested)
			}
			op.ForEachValue(func(v *flowir.Value) bool {
				scanMentionsInVal(v, childNested)
				return !invalidMention
			})
			if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
				scanMentionsInBody(op.RangeBody, childNested)
			}
		}
	}
	scanMentionsInBody(body, false)
	if invalidMention {
		return nil, false
	}

	opsByNode := map[ast.Node][]*flowir.Op{}
	rangeBodyByStmt := map[*ast.RangeStmt]*flowir.Body{}
	totalOps := 0
	hasBadBranch := false
	var indexOps func(b *flowir.Body)
	indexOps = func(b *flowir.Body) {
		if b == nil || hasBadBranch {
			return
		}
		if b.HasUnstructuredBranch() {
			hasBadBranch = true
			return
		}
		for i := range b.Ops {
			op := &b.Ops[i]
			totalOps++
			if op.StmtAST == nil {
				hasBadBranch = true
				return
			}
			opsByNode[op.StmtAST] = append(opsByNode[op.StmtAST], op)
			if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignRange {
				rs, ok := op.StmtAST.(*ast.RangeStmt)
				if !ok || (rs.Body != nil && op.RangeBody == nil) {
					hasBadBranch = true
					return
				}
				rangeBodyByStmt[rs] = op.RangeBody
				if op.RangeBody != nil {
					indexOps(op.RangeBody)
				}
			}
		}
	}
	indexOps(body)
	if hasBadBranch {
		return nil, false
	}

	res := &BodyLockRegions{
		OpModes:            make(map[*flowir.Op]LockMode, totalOps),
		IsLockTransitionOp: make(map[*flowir.Op]bool),
	}
	visitedOps := 0
	validLockMentions := 0

	applyLeafOp := func(op *flowir.Op, cur LockMode, inLoop bool) (LockMode, bool, bool) {
		if _, dup := res.OpModes[op]; dup {
			return LockInvalid, false, false
		}
		res.OpModes[op] = cur
		visitedOps++

		switch op.Kind {
		case flowir.OpExpr:
			if op.Expr != nil && op.Expr.Kind == flowir.ValInvalid {
				return LockInvalid, false, false
			}
			if mName, isLock := matchLockCall(op.Expr); isLock {
				if inLoop {
					return LockInvalid, false, false
				}
				res.IsLockTransitionOp[op] = true
				validLockMentions += lockCallMentionCount(op.Expr, target)
				switch mName {
				case "Lock":
					if cur != LockUnlocked {
						return LockInvalid, false, false
					}
					return LockWriteHeld, false, true
				case "RLock":
					if cur != LockUnlocked {
						return LockInvalid, false, false
					}
					return LockReadHeld, false, true
				case "Unlock":
					if cur != LockWriteHeld {
						return LockInvalid, false, false
					}
					return LockUnlocked, false, true
				case "RUnlock":
					if cur != LockReadHeld {
						return LockInvalid, false, false
					}
					return LockUnlocked, false, true
				}
				return LockInvalid, false, false
			}
			if valueCallsBuiltinPanic(op.Expr) {
				if !cur.ValidExit() {
					return LockInvalid, false, false
				}
				return cur, true, true
			}
			return cur, false, true

		case flowir.OpDefer:
			if mName, isLock := matchLockCall(op.Call); isLock {
				if inLoop {
					return LockInvalid, false, false
				}
				res.IsLockTransitionOp[op] = true
				validLockMentions += lockCallMentionCount(op.Call, target)
				switch mName {
				case "Unlock":
					if cur != LockWriteHeld {
						return LockInvalid, false, false
					}
					return LockWriteDeferred, false, true
				case "RUnlock":
					if cur != LockReadHeld {
						return LockInvalid, false, false
					}
					return LockReadDeferred, false, true
				default:
					return LockInvalid, false, false
				}
			}
			return cur, false, true

		case flowir.OpReturn:
			if !cur.ValidExit() {
				return LockInvalid, false, false
			}
			return cur, true, true

		default:
			return cur, false, true
		}
	}

	applyNodeOps := func(n ast.Node, cur LockMode, inLoop bool) (LockMode, bool, bool) {
		for _, op := range opsByNode[n] {
			var term, ok bool
			cur, term, ok = applyLeafOp(op, cur, inLoop)
			if !ok {
				return LockInvalid, false, false
			}
			if term {
				return cur, true, true
			}
		}
		return cur, false, true
	}

	var switchBreakStack [][]LockMode
	var loopHasBreakStack []bool

	var walkStmt func(stmt ast.Stmt, cur LockMode, inLoop bool, inSwitch bool) (LockMode, bool, bool)
	walkStmtList := func(stmts []ast.Stmt, cur LockMode, inLoop bool, inSwitch bool) (LockMode, bool, bool) {
		for _, st := range stmts {
			if st == nil {
				continue
			}
			if _, isEmpty := st.(*ast.EmptyStmt); isEmpty {
				continue
			}
			var term, ok bool
			cur, term, ok = walkStmt(st, cur, inLoop, inSwitch)
			if !ok {
				return LockInvalid, false, false
			}
			if term {
				// Reject trailing non-empty statements after an unconditional terminator so
				// every lowered Op in b.Ops has a reachable path state.
				idxSt := -1
				for k := range stmts {
					if stmts[k] == st {
						idxSt = k
						break
					}
				}
				for k := idxSt + 1; k < len(stmts); k++ {
					if stmts[k] != nil {
						if _, isE := stmts[k].(*ast.EmptyStmt); !isE {
							return LockInvalid, false, false
						}
					}
				}
				return cur, true, true
			}
		}
		return cur, false, true
	}

	walkStmt = func(stmt ast.Stmt, cur LockMode, inLoop bool, inSwitch bool) (LockMode, bool, bool) {
		switch s := stmt.(type) {
		case nil, *ast.EmptyStmt:
			return cur, false, true

		case *ast.LabeledStmt:
			// Unreferenced labels (zero goto/labeled-branch ops verified above) fall through.
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
			ops := opsByNode[s]
			if len(ops) != 1 {
				return LockInvalid, false, false
			}
			if _, dup := res.OpModes[ops[0]]; dup {
				return LockInvalid, false, false
			}
			res.OpModes[ops[0]] = cur
			visitedOps++
			switch s.Tok {
			case token.CONTINUE:
				if !inLoop {
					return LockInvalid, false, false
				}
				return cur, true, true
			case token.BREAK:
				if inSwitch && len(switchBreakStack) > 0 {
					top := len(switchBreakStack) - 1
					switchBreakStack[top] = append(switchBreakStack[top], cur)
					return cur, true, true
				}
				if inLoop && len(loopHasBreakStack) > 0 {
					loopHasBreakStack[len(loopHasBreakStack)-1] = true
					return cur, true, true
				}
				return LockInvalid, false, false
			default:
				return LockInvalid, false, false
			}

		case *ast.IfStmt:
			if s.Init != nil {
				var term, ok bool
				cur, term, ok = walkStmt(s.Init, cur, inLoop, inSwitch)
				if !ok || term {
					return LockInvalid, false, false
				}
			}
			if s.Cond != nil {
				var term, ok bool
				cur, term, ok = applyNodeOps(s, cur, inLoop)
				if !ok || term {
					return LockInvalid, false, false
				}
			}
			if s.Body == nil {
				return LockInvalid, false, false
			}
			thenMode, thenTerm, okThen := walkStmtList(s.Body.List, cur, inLoop, inSwitch)
			if !okThen {
				return LockInvalid, false, false
			}
			elseMode, elseTerm := cur, false
			if s.Else != nil {
				var okElse bool
				elseMode, elseTerm, okElse = walkStmt(s.Else, cur, inLoop, inSwitch)
				if !okElse {
					return LockInvalid, false, false
				}
			}
			return joinLockBranches(thenMode, thenTerm, elseMode, elseTerm)

		case *ast.SwitchStmt:
			if s.Init != nil {
				var term, ok bool
				cur, term, ok = walkStmt(s.Init, cur, inLoop, inSwitch)
				if !ok || term {
					return LockInvalid, false, false
				}
			}
			if s.Tag != nil {
				var term, ok bool
				cur, term, ok = applyNodeOps(s, cur, inLoop)
				if !ok || term {
					return LockInvalid, false, false
				}
			}
			if s.Body == nil {
				return LockInvalid, false, false
			}
			switchBreakStack = append(switchBreakStack, nil)
			var liveOut []LockMode
			hasDefault := false
			for _, raw := range s.Body.List {
				cc, okCC := raw.(*ast.CaseClause)
				if !okCC {
					switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
					return LockInvalid, false, false
				}
				if cc.List == nil {
					hasDefault = true
				}
				if _, termCond, okCond := applyNodeOps(cc, cur, inLoop); !okCond || termCond {
					switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
					return LockInvalid, false, false
				}
				armMode, armTerm, okArm := walkStmtList(cc.Body, cur, inLoop, true)
				if !okArm {
					switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
					return LockInvalid, false, false
				}
				if !armTerm {
					liveOut = append(liveOut, armMode)
				}
			}
			breaks := switchBreakStack[len(switchBreakStack)-1]
			switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
			liveOut = append(liveOut, breaks...)
			if !hasDefault {
				liveOut = append(liveOut, cur)
			}
			return joinLockModeSlice(liveOut)

		case *ast.TypeSwitchStmt:
			if s.Init != nil {
				var term, ok bool
				cur, term, ok = walkStmt(s.Init, cur, inLoop, inSwitch)
				if !ok || term {
					return LockInvalid, false, false
				}
			}
			if _, termGuard, okGuard := applyNodeOps(s, cur, inLoop); !okGuard || termGuard {
				return LockInvalid, false, false
			}
			if s.Body == nil {
				return LockInvalid, false, false
			}
			switchBreakStack = append(switchBreakStack, nil)
			var liveOut []LockMode
			hasDefault := false
			for _, raw := range s.Body.List {
				cc, okCC := raw.(*ast.CaseClause)
				if !okCC {
					switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
					return LockInvalid, false, false
				}
				if cc.List == nil {
					hasDefault = true
				}
				if _, termCase, okCase := applyNodeOps(cc, cur, inLoop); !okCase || termCase {
					switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
					return LockInvalid, false, false
				}
				armMode, armTerm, okArm := walkStmtList(cc.Body, cur, inLoop, true)
				if !okArm {
					switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
					return LockInvalid, false, false
				}
				if !armTerm {
					liveOut = append(liveOut, armMode)
				}
			}
			breaks := switchBreakStack[len(switchBreakStack)-1]
			switchBreakStack = switchBreakStack[:len(switchBreakStack)-1]
			liveOut = append(liveOut, breaks...)
			if !hasDefault {
				liveOut = append(liveOut, cur)
			}
			return joinLockModeSlice(liveOut)

		case *ast.ForStmt:
			if s.Init != nil {
				var term, ok bool
				cur, term, ok = walkStmt(s.Init, cur, true, false)
				if !ok || term {
					return LockInvalid, false, false
				}
			}
			if s.Cond != nil {
				var term, ok bool
				cur, term, ok = applyNodeOps(s, cur, true)
				if !ok || term {
					return LockInvalid, false, false
				}
			}
			if s.Post != nil {
				postMode, postTerm, okPost := walkStmt(s.Post, cur, true, false)
				if !okPost || postTerm || postMode != cur {
					return LockInvalid, false, false
				}
			}
			loopHasBreakStack = append(loopHasBreakStack, false)
			if s.Body != nil {
				bodyMode, bodyTerm, okBody := walkStmtList(s.Body.List, cur, true, false)
				if !okBody || (!bodyTerm && bodyMode != cur) {
					loopHasBreakStack = loopHasBreakStack[:len(loopHasBreakStack)-1]
					return LockInvalid, false, false
				}
			}
			sawBreak := loopHasBreakStack[len(loopHasBreakStack)-1]
			loopHasBreakStack = loopHasBreakStack[:len(loopHasBreakStack)-1]
			if s.Cond == nil && !sawBreak {
				return cur, true, true
			}
			return cur, false, true

		case *ast.RangeStmt:
			ops := opsByNode[s]
			if len(ops) != 1 {
				return LockInvalid, false, false
			}
			if _, dup := res.OpModes[ops[0]]; dup {
				return LockInvalid, false, false
			}
			res.OpModes[ops[0]] = cur
			visitedOps++
			loopHasBreakStack = append(loopHasBreakStack, false)
			if rb := rangeBodyByStmt[s]; rb != nil && rb.Block != nil {
				bodyMode, bodyTerm, okBody := walkStmtList(rb.Block.List, cur, true, false)
				if !okBody || (!bodyTerm && bodyMode != cur) {
					loopHasBreakStack = loopHasBreakStack[:len(loopHasBreakStack)-1]
					return LockInvalid, false, false
				}
			}
			loopHasBreakStack = loopHasBreakStack[:len(loopHasBreakStack)-1]
			return cur, false, true

		default:
			return LockInvalid, false, false
		}
	}

	endMode, endTerm, okWalk := walkStmtList(body.Block.List, LockUnlocked, false, false)
	if !okWalk || (!endTerm && !endMode.ValidExit()) {
		return nil, false
	}
	if visitedOps != totalOps || validLockMentions != totalMutexMentions {
		return nil, false
	}
	return res, true
}

func joinLockBranches(m1 LockMode, term1 bool, m2 LockMode, term2 bool) (LockMode, bool, bool) {
	switch {
	case term1 && term2:
		return LockUnlocked, true, true
	case term1:
		if m2 == LockInvalid {
			return LockInvalid, false, false
		}
		return m2, false, true
	case term2:
		if m1 == LockInvalid {
			return LockInvalid, false, false
		}
		return m1, false, true
	default:
		if m1 == LockInvalid || m1 != m2 {
			return LockInvalid, false, false
		}
		return m1, false, true
	}
}

func joinLockModeSlice(modes []LockMode) (LockMode, bool, bool) {
	if len(modes) == 0 {
		return LockUnlocked, true, true
	}
	first := modes[0]
	if first == LockInvalid {
		return LockInvalid, false, false
	}
	for _, m := range modes[1:] {
		if m != first {
			return LockInvalid, false, false
		}
	}
	return first, false, true
}

func selectionReachesField(recvType types.Type, sel *types.Selection, targetField *types.Var) bool {
	if recvType == nil || sel == nil || targetField == nil || len(sel.Index()) == 0 {
		return false
	}
	cur := types.Unalias(recvType)
	if ptr, ok := cur.(*types.Pointer); ok {
		cur = types.Unalias(ptr.Elem())
	}
	indices := sel.Index()
	// Walk embedded struct steps up to the mutex field (the final index is the method on sync.Mutex/RWMutex).
	for i := 0; i < len(indices)-1; i++ {
		st, ok := cur.Underlying().(*types.Struct)
		if !ok || indices[i] < 0 || indices[i] >= st.NumFields() {
			return false
		}
		fld := st.Field(indices[i])
		if fld == targetField || fld.Origin() == targetField.Origin() {
			return true
		}
		ft := types.Unalias(fld.Type())
		if ptr, ok := ft.(*types.Pointer); ok {
			ft = types.Unalias(ptr.Elem())
		}
		cur = ft
	}
	return false
}

func lockCallMentionCount(call *flowir.Value, target LockTarget) int {
	if call == nil {
		return 0
	}
	switch target.Kind {
	case LockPkgGlobalVar:
		// ValCall.Recv holds a ValPlace{Obj: MutexVar} (1 mention).
		return 1
	case LockRecvField:
		// Bare recv (m.Lock()) is counted once on ValCall; explicit m.mu.Lock()
		// has 1 ProjField on call.Recv.Place and 0 bare-recv count.
		return 1
	}
	return 0
}

func valueCallsBuiltinPanic(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	hit := false
	v.WalkValues(func(cur *flowir.Value) bool {
		if cur.Kind == flowir.ValCall && cur.CallKind == flowir.CallBuiltin && cur.BuiltinName == "panic" {
			hit = true
			return false
		}
		return true
	})
	return hit
}
