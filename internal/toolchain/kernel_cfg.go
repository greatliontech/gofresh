package toolchain

import (
	"go/ast"
	"go/token"
	"maps"
)

// stmtCFG models the intra-procedural control-flow graph of a pruned Go
// statement block without `go/types`, rejecting `goto`, labels, labeled
// branches, `fallthrough`, `recover()`, `go`, and channel sends.
type stmtCFG struct {
	Blocks []*cfgBlock
	Entry  int
	Exit   int // synthetic fallthrough exit block index
}

// cfgBlock is one basic block in a stmtCFG.
type cfgBlock struct {
	ID         int
	Stmts      []ast.Stmt
	BranchCond ast.Expr
	Succs      []int
	Returns    bool
	Aborts     bool // panic(...) or *.Exit(...)
}

// buildStmtCFG constructs an intra-procedural stmtCFG over stmts. It returns
// (_, false) if stmts contains unstructured control flow (`goto`, labels,
// labeled break/continue, `fallthrough`), `recover()`, `go`, or `SendStmt`.
func buildStmtCFG(stmts []ast.Stmt) (*stmtCFG, bool) {
	b := &cfgBuilder{}
	entry := b.newBlock()
	exit := b.newBlock()
	tail, ok := b.lowerStmts(entry, stmts, -1, -1)
	if !ok {
		return nil, false
	}
	if tail >= 0 {
		b.addEdge(tail, exit)
	}
	return &stmtCFG{
		Blocks: b.blocks,
		Entry:  entry,
		Exit:   exit,
	}, true
}

type cfgBuilder struct {
	blocks []*cfgBlock
}

func (b *cfgBuilder) newBlock() int {
	id := len(b.blocks)
	b.blocks = append(b.blocks, &cfgBlock{ID: id})
	return id
}

func (b *cfgBuilder) addEdge(from, to int) {
	if from < 0 || to < 0 {
		return
	}
	blk := b.blocks[from]
	if blk.Returns || blk.Aborts {
		return
	}
	for _, existing := range blk.Succs {
		if existing == to {
			return
		}
	}
	blk.Succs = append(blk.Succs, to)
}

func stmtHasForbiddenCFGConstruct(n ast.Node) bool {
	if n == nil {
		return false
	}
	bad := false
	ast.Inspect(n, func(ch ast.Node) bool {
		if bad || ch == nil {
			return false
		}
		switch x := ch.(type) {
		case *ast.FuncLit:
			return false
		case *ast.LabeledStmt, *ast.GoStmt, *ast.SendStmt:
			bad = true
			return false
		case *ast.BranchStmt:
			if x.Tok == token.GOTO || x.Tok == token.FALLTHROUGH || x.Label != nil {
				bad = true
				return false
			}
		case *ast.CallExpr:
			if id, ok := unwrapParens(x.Fun).(*ast.Ident); ok && id.Name == "recover" {
				bad = true
				return false
			}
		}
		return true
	})
	return bad
}

func isAbortExprStmt(s *ast.ExprStmt) bool {
	call, ok := unwrapParens(s.X).(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := unwrapParens(call.Fun).(*ast.Ident)
	return ok && id.Name == "panic"
}

func (b *cfgBuilder) lowerStmts(cur int, stmts []ast.Stmt, breakTarget, contTarget int) (int, bool) {
	for _, stmt := range stmts {
		if cur < 0 {
			// Unreachable statement after unconditional terminator in the same block.
			return -1, false
		}
		switch s := stmt.(type) {
		case *ast.EmptyStmt:
			continue
		case *ast.LabeledStmt, *ast.GoStmt, *ast.SendStmt, *ast.SelectStmt:
			return -1, false
		case *ast.BlockStmt:
			var ok bool
			cur, ok = b.lowerStmts(cur, s.List, breakTarget, contTarget)
			if !ok {
				return -1, false
			}
		case *ast.ReturnStmt:
			if stmtHasForbiddenCFGConstruct(s) {
				return -1, false
			}
			b.blocks[cur].Stmts = append(b.blocks[cur].Stmts, s)
			b.blocks[cur].Returns = true
			cur = -1
		case *ast.BranchStmt:
			if s.Label != nil {
				return -1, false
			}
			switch s.Tok {
			case token.BREAK:
				if breakTarget < 0 {
					return -1, false
				}
				b.addEdge(cur, breakTarget)
				cur = -1
			case token.CONTINUE:
				if contTarget < 0 {
					return -1, false
				}
				b.addEdge(cur, contTarget)
				cur = -1
			default:
				return -1, false
			}
		case *ast.IfStmt:
			if s.Init != nil {
				if stmtHasForbiddenCFGConstruct(s.Init) {
					return -1, false
				}
				b.blocks[cur].Stmts = append(b.blocks[cur].Stmts, s.Init)
			}
			if stmtHasForbiddenCFGConstruct(s.Cond) {
				return -1, false
			}
			b.blocks[cur].BranchCond = s.Cond
			thenBlk := b.newBlock()
			elseBlk := b.newBlock()
			joinBlk := b.newBlock()
			b.addEdge(cur, thenBlk)
			b.addEdge(cur, elseBlk)

			thenTail, okT := b.lowerStmts(thenBlk, s.Body.List, breakTarget, contTarget)
			if !okT {
				return -1, false
			}
			if thenTail >= 0 {
				b.addEdge(thenTail, joinBlk)
			}

			var elseTail int
			if s.Else == nil {
				elseTail = elseBlk
			} else {
				var okE bool
				switch el := s.Else.(type) {
				case *ast.BlockStmt:
					elseTail, okE = b.lowerStmts(elseBlk, el.List, breakTarget, contTarget)
				case *ast.IfStmt:
					elseTail, okE = b.lowerStmts(elseBlk, []ast.Stmt{el}, breakTarget, contTarget)
				default:
					return -1, false
				}
				if !okE {
					return -1, false
				}
			}
			if elseTail >= 0 {
				b.addEdge(elseTail, joinBlk)
			}
			if thenTail < 0 && elseTail < 0 {
				cur = -1
			} else {
				cur = joinBlk
			}
		case *ast.ForStmt:
			if s.Init != nil {
				if stmtHasForbiddenCFGConstruct(s.Init) {
					return -1, false
				}
				b.blocks[cur].Stmts = append(b.blocks[cur].Stmts, s.Init)
			}
			headBlk := b.newBlock()
			bodyBlk := b.newBlock()
			postBlk := headBlk
			if s.Post != nil {
				if stmtHasForbiddenCFGConstruct(s.Post) {
					return -1, false
				}
				postBlk = b.newBlock()
				b.blocks[postBlk].Stmts = append(b.blocks[postBlk].Stmts, s.Post)
				b.addEdge(postBlk, headBlk)
			}
			afterBlk := b.newBlock()
			b.addEdge(cur, headBlk)
			if s.Cond != nil {
				if stmtHasForbiddenCFGConstruct(s.Cond) {
					return -1, false
				}
				b.blocks[headBlk].BranchCond = s.Cond
				b.addEdge(headBlk, bodyBlk)
				b.addEdge(headBlk, afterBlk)
			} else {
				b.addEdge(headBlk, bodyBlk)
			}
			bodyTail, okB := b.lowerStmts(bodyBlk, s.Body.List, afterBlk, postBlk)
			if !okB {
				return -1, false
			}
			if bodyTail >= 0 {
				b.addEdge(bodyTail, postBlk)
			}
			// Check whether afterBlk has any incoming edge (from s.Cond != nil or a break).
			afterReachable := s.Cond != nil
			if !afterReachable {
				for _, blk := range b.blocks {
					for _, succ := range blk.Succs {
						if succ == afterBlk {
							afterReachable = true
							break
						}
					}
				}
			}
			if afterReachable {
				cur = afterBlk
			} else {
				cur = -1
			}
		case *ast.RangeStmt:
			if stmtHasForbiddenCFGConstruct(s.X) || stmtHasForbiddenCFGConstruct(s.Key) || stmtHasForbiddenCFGConstruct(s.Value) {
				return -1, false
			}
			headBlk := b.newBlock()
			bodyBlk := b.newBlock()
			afterBlk := b.newBlock()
			b.blocks[headBlk].Stmts = append(b.blocks[headBlk].Stmts, &ast.ExprStmt{X: s.X})
			b.addEdge(cur, headBlk)
			b.addEdge(headBlk, bodyBlk)
			b.addEdge(headBlk, afterBlk)
			bodyTail, okB := b.lowerStmts(bodyBlk, s.Body.List, afterBlk, headBlk)
			if !okB {
				return -1, false
			}
			if bodyTail >= 0 {
				b.addEdge(bodyTail, headBlk)
			}
			cur = afterBlk
		case *ast.SwitchStmt:
			if s.Init != nil {
				if stmtHasForbiddenCFGConstruct(s.Init) {
					return -1, false
				}
				b.blocks[cur].Stmts = append(b.blocks[cur].Stmts, s.Init)
			}
			if stmtHasForbiddenCFGConstruct(s.Tag) || s.Body == nil {
				return -1, false
			}
			afterBlk := b.newBlock()
			hasDefault := false
			anyReachesAfter := false
			for _, rawClause := range s.Body.List {
				cc, okCC := rawClause.(*ast.CaseClause)
				if !okCC {
					return -1, false
				}
				for _, ce := range cc.List {
					if stmtHasForbiddenCFGConstruct(ce) {
						return -1, false
					}
				}
				if cc.List == nil {
					hasDefault = true
				}
				caseBlk := b.newBlock()
				b.addEdge(cur, caseBlk)
				cTail, okC := b.lowerStmts(caseBlk, cc.Body, afterBlk, contTarget)
				if !okC {
					return -1, false
				}
				if cTail >= 0 {
					b.addEdge(cTail, afterBlk)
					anyReachesAfter = true
				}
			}
			if !hasDefault {
				b.addEdge(cur, afterBlk)
				anyReachesAfter = true
			}
			if !anyReachesAfter {
				for _, blk := range b.blocks {
					for _, succ := range blk.Succs {
						if succ == afterBlk {
							anyReachesAfter = true
							break
						}
					}
				}
			}
			if anyReachesAfter {
				cur = afterBlk
			} else {
				cur = -1
			}
		case *ast.ExprStmt:
			if stmtHasForbiddenCFGConstruct(s) {
				return -1, false
			}
			b.blocks[cur].Stmts = append(b.blocks[cur].Stmts, s)
			if isAbortExprStmt(s) {
				b.blocks[cur].Aborts = true
				cur = -1
			}
		case *ast.AssignStmt, *ast.DeclStmt, *ast.DeferStmt, *ast.IncDecStmt:
			if stmtHasForbiddenCFGConstruct(s) {
				return -1, false
			}
			b.blocks[cur].Stmts = append(b.blocks[cur].Stmts, s)
		default:
			return -1, false
		}
	}
	return cur, true
}

// reachableBlocks returns the boolean slice of blocks reachable from Entry.
func (cfg *stmtCFG) reachableBlocks() []bool {
	if cfg == nil || len(cfg.Blocks) == 0 {
		return nil
	}
	reach := make([]bool, len(cfg.Blocks))
	queue := []int{cfg.Entry}
	reach[cfg.Entry] = true
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, succ := range cfg.Blocks[id].Succs {
			if !reach[succ] {
				reach[succ] = true
				queue = append(queue, succ)
			}
		}
	}
	return reach
}

// everyPathReturns reports whether every reachable path from Entry reaches a
// ReturnStmt (without reaching Exit, Aborts, or getting trapped in a return-free
// infinite loop).
func (cfg *stmtCFG) everyPathReturns() bool {
	if cfg == nil || len(cfg.Blocks) == 0 {
		return false
	}
	reach := cfg.reachableBlocks()
	if reach[cfg.Exit] {
		return false
	}
	// Every reachable block must be able to reach at least one ReturnStmt block
	// (rules out `for { _ = x }` sinkless infinite loops!).
	canReachReturn := make([]bool, len(cfg.Blocks))
	preds := make([][]int, len(cfg.Blocks))
	var queue []int
	for id, blk := range cfg.Blocks {
		if !reach[id] {
			continue
		}
		if blk.Aborts {
			return false
		}
		if blk.Returns {
			canReachReturn[id] = true
			queue = append(queue, id)
		}
		for _, succ := range blk.Succs {
			if reach[succ] {
				preds[succ] = append(preds[succ], id)
			}
		}
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, p := range preds[id] {
			if !canReachReturn[p] {
				canReachReturn[p] = true
				queue = append(queue, p)
			}
		}
	}
	for id := range cfg.Blocks {
		if reach[id] && id != cfg.Exit && !canReachReturn[id] {
			return false
		}
	}
	return true
}

// pruneBlockStmts returns a shallowly pruned copy of stmts (preserving AST node
// pointers on surviving statements) where provably dead `if <false>` branches and
// `if <earlyFalse> { return }` hooks are elided and `if <true>` blocks are
// spliced, recording required runtime.* gates in reqGates and pruned statement
// subtrees in prunedNodes.
func (k *packageInactiveKernel) pruneBlockStmts(
	stmts []ast.Stmt,
	fn *ast.FuncDecl,
	pureVars map[string]bool,
	reqGates map[string]bool,
	prunedNodes *[]ast.Node,
) ([]ast.Stmt, bool) {
	if k == nil || k.hasDotImport || k.builtinsShadowed || len(stmts) == 0 {
		return stmts, false
	}
	var out []ast.Stmt
	modified := false
	localPure := maps.Clone(pureVars)
	if localPure == nil {
		localPure = map[string]bool{}
	}

	recordGates := func(gates []string) {
		if reqGates == nil {
			return
		}
		for _, g := range gates {
			if g != "" {
				reqGates[g] = true
			}
		}
	}
	recordPruned := func(n ast.Node) {
		if prunedNodes != nil && n != nil {
			*prunedNodes = append(*prunedNodes, n)
		}
	}

	pruneElseStmts := func(elStmt ast.Stmt) ([]ast.Stmt, bool) {
		switch el := elStmt.(type) {
		case *ast.BlockStmt:
			return k.pruneBlockStmts(el.List, fn, localPure, reqGates, prunedNodes)
		case *ast.IfStmt:
			return k.pruneBlockStmts([]ast.Stmt{el}, fn, localPure, reqGates, prunedNodes)
		default:
			return []ast.Stmt{elStmt}, false
		}
	}

	appendFoldedBranch := func(sub []ast.Stmt, lbrace, rbrace token.Pos, tail []ast.Stmt) bool {
		if sliceAlwaysTerminatesBlock(sub, fn, k) && !sliceHasControlFlowOrRecoverBypass(tail) {
			out = append(out, sub...)
			for _, rem := range tail {
				recordPruned(rem)
			}
			return true
		}
		if len(tail) > 0 && sliceDeclaresTopBlockIdent(sub) {
			out = append(out, &ast.BlockStmt{Lbrace: lbrace, List: sub, Rbrace: rbrace})
		} else {
			out = append(out, sub...)
		}
		return false
	}

	for i, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.IfStmt:
			if s.Init == nil && !stmtHasControlFlowOrRecoverBypass(s.Body) {
				if gates, okF := k.evalFalseExpr(s.Cond, fn, localPure); okF {
					if !modified {
						out = append(out, stmts[:i]...)
						modified = true
					}
					recordGates(gates)
					recordPruned(s.Cond)
					recordPruned(s.Body)
					if s.Else != nil {
						sub, _ := pruneElseStmts(s.Else)
						if appendFoldedBranch(sub, token.NoPos, token.NoPos, stmts[i+1:]) {
							return out, true
						}
					}
					continue
				}
				if s.Else == nil || !stmtHasControlFlowOrRecoverBypass(s.Else) {
					if gates, okT := k.evalTrueExpr(s.Cond, fn, localPure); okT {
						if !modified {
							out = append(out, stmts[:i]...)
							modified = true
						}
						recordGates(gates)
						recordPruned(s.Cond)
						if s.Else != nil {
							recordPruned(s.Else)
						}
						sub, _ := k.pruneBlockStmts(s.Body.List, fn, localPure, reqGates, prunedNodes)
						if appendFoldedBranch(sub, s.Body.Lbrace, s.Body.Rbrace, stmts[i+1:]) {
							return out, true
						}
						continue
					}
				}
			}
			bodySub, bodyMod := k.pruneBlockStmts(s.Body.List, fn, localPure, reqGates, prunedNodes)
			var elseStmt ast.Stmt = s.Else
			elseMod := false
			if s.Else != nil {
				if eSub, eMod := pruneElseStmts(s.Else); eMod {
					elseMod = true
					if _, wasIf := s.Else.(*ast.IfStmt); wasIf && len(eSub) == 1 {
						if subIf, okSub := eSub[0].(*ast.IfStmt); okSub {
							elseStmt = subIf
						} else {
							elseStmt = &ast.BlockStmt{List: eSub}
						}
					} else {
						elseStmt = &ast.BlockStmt{List: eSub}
					}
				}
			}
			if bodyMod || elseMod {
				if !modified {
					out = append(out, stmts[:i]...)
					modified = true
				}
				cp := *s
				if bodyMod {
					cp.Body = &ast.BlockStmt{Lbrace: s.Body.Lbrace, List: bodySub, Rbrace: s.Body.Rbrace}
				}
				if elseMod {
					cp.Else = elseStmt
				}
				out = append(out, &cp)
				continue
			}
		case *ast.BlockStmt:
			sub, subMod := k.pruneBlockStmts(s.List, fn, localPure, reqGates, prunedNodes)
			if subMod {
				if !modified {
					out = append(out, stmts[:i]...)
					modified = true
				}
				out = append(out, &ast.BlockStmt{Lbrace: s.Lbrace, List: sub, Rbrace: s.Rbrace})
				continue
			}
		case *ast.ForStmt:
			if s.Body != nil {
				sub, subMod := k.pruneBlockStmts(s.Body.List, fn, localPure, reqGates, prunedNodes)
				if subMod {
					if !modified {
						out = append(out, stmts[:i]...)
						modified = true
					}
					cp := *s
					cp.Body = &ast.BlockStmt{Lbrace: s.Body.Lbrace, List: sub, Rbrace: s.Body.Rbrace}
					out = append(out, &cp)
					continue
				}
			}
		case *ast.AssignStmt:
			// Conservative: if a local variable in localPure is reassigned to a non-pure expr, drop it from localPure.
			for _, lhs := range s.Lhs {
				if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
					delete(localPure, id.Name)
				}
			}
		case *ast.IncDecStmt:
			if id, okID := unwrapParens(s.X).(*ast.Ident); okID {
				delete(localPure, id.Name)
			}
		}
		if modified {
			out = append(out, stmt)
		}
	}
	if !modified {
		return stmts, false
	}
	return out, true
}

func sliceHasControlFlowOrRecoverBypass(stmts []ast.Stmt) bool {
	for _, st := range stmts {
		if stmtHasControlFlowOrRecoverBypass(st) {
			return true
		}
	}
	return false
}

func sliceDeclaresTopBlockIdent(stmts []ast.Stmt) bool {
	for _, st := range stmts {
		switch x := st.(type) {
		case *ast.AssignStmt:
			if x.Tok == token.DEFINE {
				return true
			}
		case *ast.DeclStmt:
			return true
		}
	}
	return false
}

func sliceAlwaysTerminatesBlock(stmts []ast.Stmt, fn *ast.FuncDecl, k *packageInactiveKernel) bool {
	if len(stmts) == 0 {
		return false
	}
	if blockAlwaysReturns(stmts) {
		return true
	}
	switch last := stmts[len(stmts)-1].(type) {
	case *ast.BranchStmt:
		return last.Label == nil && (last.Tok == token.BREAK || last.Tok == token.CONTINUE)
	case *ast.ExprStmt:
		return isAbortExprStmt(last) && (k == nil || !k.identShadowedInFunc(fn, "panic"))
	default:
		return false
	}
}
