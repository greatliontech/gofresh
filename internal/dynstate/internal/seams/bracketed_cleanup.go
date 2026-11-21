package seams

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type seamSaveRecord struct {
	idx      int
	localObj types.Object
}

type seamRestoreRecord struct {
	idx        int
	lhs        ast.Expr
	cbody      *ast.BlockStmt
	savedLocal types.Object
	zeroReset  bool
	viaCleanup bool
}

type grantedSeamExemption struct {
	fd         *ast.FuncDecl
	fn         *types.Func
	baseVar    *types.Var
	key        string
	writePos   token.Pos
	nodes      []ast.Node
	viaCleanup bool
	zeroReset  bool
}

func (a *bracketedSeamAnalyzer) candidateVar(obj types.Object) (*types.Var, bool) {
	v, ok := obj.(*types.Var)
	if !ok || v == nil || a.p.Types == nil || v.Pkg() != a.p.Types || v.Parent() != v.Pkg().Scope() || a.addrTaken[v] || a.ptrMethodOnVar[v] {
		return nil, false
	}
	if refconfine.TypeHandsOutDynamicAlias(a.audited, v.Type()) ||
		refconfine.TypeHandsOutMutableReach(v.Type()) {
		return nil, false
	}
	return v, true
}

func (a *bracketedSeamAnalyzer) seamTarget(expr ast.Expr, baseVarByKey map[string]*types.Var) (string, *types.Var, bool) {
	expr = ast.Unparen(expr)
	switch e := expr.(type) {
	case *ast.Ident:
		obj, ok := a.resolve(e)
		if !ok {
			return "", nil, false
		}
		v, ok := a.candidateVar(obj)
		if !ok {
			return "", nil, false
		}
		k := syntaxutil.DynamicVarKey(v)
		baseVarByKey[k] = v
		return k, v, true
	case *ast.SelectorExpr:
		baseID, ok := ast.Unparen(e.X).(*ast.Ident)
		if !ok {
			return "", nil, false
		}
		obj, ok := a.resolve(baseID)
		if !ok {
			return "", nil, false
		}
		v, ok := a.candidateVar(obj)
		if !ok {
			return "", nil, false
		}
		field, ok := a.p.TypesInfo.Uses[e.Sel].(*types.Var)
		if !ok || field == nil ||
			refconfine.TypeHandsOutDynamicAlias(a.audited, field.Type()) ||
			refconfine.TypeHandsOutMutableReach(field.Type()) {
			return "", nil, false
		}
		k := syntaxutil.DynamicVarKey(v) + "." + field.Name()
		baseVarByKey[k] = v
		return k, v, true
	default:
		return "", nil, false
	}
}

func (a *bracketedSeamAnalyzer) isZeroExpr(expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	switch e := expr.(type) {
	case *ast.Ident:
		switch a.p.TypesInfo.Uses[e].(type) {
		case *types.Nil:
			return true
		case *types.Const:
			return e.Name == "false"
		}
	case *ast.BasicLit:
		return e.Value == "0" || e.Value == `""` || e.Value == "``"
	case *ast.CompositeLit:
		return len(e.Elts) == 0
	}
	return false
}

func (a *bracketedSeamAnalyzer) analyzeLexicalSaveRestoreSeams() {
	p := a.p
	uninitVars := map[*types.Var]bool{}
	for v := range a.uninitDecls {
		if _, ok := a.candidateVar(v); ok {
			uninitVars[v] = true
		}
	}
	baseVarByKey := map[string]*types.Var{}
	var granted []grantedSeamExemption

	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil || a.isBlockedSeamDecl(fd) || fd.Name == nil || fd.Name.Name == "init" || fd.Name.Name == "_" || bodyHasGoOrParallel(p.TypesInfo, fd.Body) {
				continue
			}
			a.analyzeFuncSaveRestoreSeams(fd, uninitVars, baseVarByKey, &granted)
		}
	}

	if len(granted) > 0 {
		a.revokeAndRecordGrantedSeams(granted)
	}
}

func (a *bracketedSeamAnalyzer) analyzeFuncSaveRestoreSeams(
	fd *ast.FuncDecl,
	uninitVars map[*types.Var]bool,
	baseVarByKey map[string]*types.Var,
	granted *[]grantedSeamExemption,
) {
	p := a.p
	exempt := a.res.Exempt
	var declFn *types.Func
	if fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func); ok && fn != nil {
		declFn = fn.Origin()
	}
	localWrites := map[types.Object]int{}
	localAddr := map[types.Object]bool{}
	localFuncLits := map[types.Object]*ast.FuncLit{}
	recordTargetIdents := func(expr ast.Expr, target map[types.Object]int) {
		if expr == nil {
			return
		}
		ast.Inspect(expr, func(inner ast.Node) bool {
			if id, ok := inner.(*ast.Ident); ok {
				if obj, ok := a.resolve(id); ok {
					if v, ok := obj.(*types.Var); ok && v.Pkg() != nil && v.Parent() != v.Pkg().Scope() {
						target[obj]++
					}
				}
			}
			return true
		})
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range n.Lhs {
				recordTargetIdents(lhs, localWrites)
				if id, ok := ast.Unparen(lhs).(*ast.Ident); ok {
					if obj, ok := a.resolve(id); ok && i < len(n.Rhs) {
						if lit, ok := ast.Unparen(n.Rhs[i]).(*ast.FuncLit); ok {
							localFuncLits[obj] = lit
						}
					}
				}
			}
		case *ast.ValueSpec:
			for i, name := range n.Names {
				if obj := p.TypesInfo.Defs[name]; obj != nil {
					localWrites[obj]++
					if i < len(n.Values) {
						if lit, ok := ast.Unparen(n.Values[i]).(*ast.FuncLit); ok {
							localFuncLits[obj] = lit
						}
					}
				}
			}
		case *ast.IncDecStmt:
			recordTargetIdents(n.X, localWrites)
		case *ast.RangeStmt:
			recordTargetIdents(n.Key, localWrites)
			recordTargetIdents(n.Value, localWrites)
		case *ast.UnaryExpr:
			if n.Op == token.AND {
				ast.Inspect(n.X, func(inner ast.Node) bool {
					if id, ok := inner.(*ast.Ident); ok {
						if obj, ok := a.resolve(id); ok {
							localAddr[obj] = true
						}
					}
					return true
				})
			}
		}
		return true
	})
	immutableLocal := func(obj types.Object) bool {
		if obj == nil || localWrites[obj] != 1 || localAddr[obj] {
			return false
		}
		v, ok := obj.(*types.Var)
		return ok && v.Pkg() != nil && v.Parent() != v.Pkg().Scope()
	}
	namedResults := map[types.Object]bool{}
	if fd.Type != nil && fd.Type.Results != nil {
		for _, field := range fd.Type.Results.List {
			for _, name := range field.Names {
				if obj := p.TypesInfo.Defs[name]; obj != nil {
					namedResults[obj] = true
				}
			}
		}
	}
	returnedTargets := map[string]bool{}
	markLitTargets := func(lit *ast.FuncLit) {
		if lit == nil || lit.Body == nil {
			return
		}
		ast.Inspect(lit.Body, func(inner ast.Node) bool {
			if assign, ok := inner.(*ast.AssignStmt); ok {
				for _, lhs := range assign.Lhs {
					if key, _, ok := a.seamTarget(lhs, baseVarByKey); ok {
						returnedTargets[key] = true
					}
				}
			}
			return true
		})
	}
	markExprClosures := func(expr ast.Expr) {
		if expr == nil {
			return
		}
		ast.Inspect(expr, func(inner ast.Node) bool {
			switch inner := inner.(type) {
			case *ast.FuncLit:
				markLitTargets(inner)
				return false
			case *ast.Ident:
				if obj, ok := a.resolve(inner); ok && localFuncLits[obj] != nil {
					markLitTargets(localFuncLits[obj])
				}
			}
			return true
		})
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			if a.graph.NonSeqLits[n] {
				markLitTargets(n)
				return false
			}
		case *ast.ReturnStmt:
			for _, res := range n.Results {
				markExprClosures(res)
			}
		case *ast.AssignStmt:
			for i, lhs := range n.Lhs {
				if id, ok := ast.Unparen(lhs).(*ast.Ident); ok {
					if obj, ok := a.resolve(id); ok && namedResults[obj] && i < len(n.Rhs) {
						markExprClosures(n.Rhs[i])
					}
				}
			}
		}
		return true
	})

	wholeWrites := map[*types.Var]bool{}
	fieldWrites := map[*types.Var]bool{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assign.Lhs {
				if key, baseVar, ok := a.seamTarget(lhs, baseVarByKey); ok {
					if key == syntaxutil.DynamicVarKey(baseVar) {
						wholeWrites[baseVar] = true
					} else {
						fieldWrites[baseVar] = true
					}
				}
			}
		}
		return true
	})
	mixedBaseVar := func(v *types.Var) bool {
		return wholeWrites[v] && fieldWrites[v]
	}

	cleanupClosureBody := func(stmt ast.Stmt, block *ast.BlockStmt) (*ast.BlockStmt, bool) {
		switch s := stmt.(type) {
		case *ast.DeferStmt:
			if lit, ok := ast.Unparen(s.Call.Fun).(*ast.FuncLit); ok && len(s.Call.Args) == 0 && !a.graph.NonSeqLits[lit] {
				return lit.Body, false
			}
			if id, ok := ast.Unparen(s.Call.Fun).(*ast.Ident); ok && len(s.Call.Args) == 0 {
				if obj, ok := a.resolve(id); ok && immutableLocal(obj) && localFuncLits[obj] != nil && !a.graph.NonSeqLits[localFuncLits[obj]] {
					return localFuncLits[obj].Body, false
				}
			}
		case *ast.ExprStmt:
			if a.liveHandles == nil {
				return nil, false
			}
			call, ok := s.X.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 || testingSyncMethodName(p.TypesInfo, call) != "Cleanup" {
				return nil, false
			}
			sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok {
				return nil, false
			}
			recvID, ok := ast.Unparen(sel.X).(*ast.Ident)
			if !ok {
				return nil, false
			}
			recvVar, ok := p.TypesInfo.Uses[recvID].(*types.Var)
			if !ok || recvVar == nil || !a.liveHandles[block][recvVar] {
				return nil, false
			}
			if lit, ok := ast.Unparen(call.Args[0]).(*ast.FuncLit); ok && !a.graph.NonSeqLits[lit] {
				return lit.Body, true
			}
			if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); ok {
				if obj, ok := a.resolve(id); ok && immutableLocal(obj) && localFuncLits[obj] != nil && !a.graph.NonSeqLits[localFuncLits[obj]] {
					return localFuncLits[obj].Body, true
				}
			}
		}
		return nil, false
	}

	callableBodies := map[*ast.BlockStmt]bool{fd.Body: true}
	var blocks []*ast.BlockStmt
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			if a.graph.NonSeqLits[n] {
				return false
			}
			if n.Body != nil {
				callableBodies[n.Body] = true
			}
		case *ast.BlockStmt:
			blocks = append(blocks, n)
		}
		return true
	})

	type writeOccurrence struct {
		idx int
		lhs ast.Expr
	}
	for bi := len(blocks) - 1; bi >= 0; bi-- {
		block := blocks[bi]
		isCallableBody := callableBodies[block]
		saves := map[string][]seamSaveRecord{}
		deferRestores := map[string][]seamRestoreRecord{}
		validRestoreLHS := map[ast.Expr]bool{}
		for idx, stmt := range block.List {
			if assign, ok := stmt.(*ast.AssignStmt); ok && len(assign.Lhs) == len(assign.Rhs) {
				for i, lhs := range assign.Lhs {
					id, ok := ast.Unparen(lhs).(*ast.Ident)
					if !ok {
						continue
					}
					localObj, ok := a.resolve(id)
					if !ok || !immutableLocal(localObj) {
						continue
					}
					if key, baseVar, ok := a.seamTarget(assign.Rhs[i], baseVarByKey); ok && !returnedTargets[key] && !mixedBaseVar(baseVar) {
						saves[key] = append(saves[key], seamSaveRecord{idx: idx, localObj: localObj})
					}
				}
			} else if declStmt, ok := stmt.(*ast.DeclStmt); ok {
				if gd, ok := declStmt.Decl.(*ast.GenDecl); ok && gd.Tok == token.VAR {
					for _, spec := range gd.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok || len(vs.Names) != len(vs.Values) {
							continue
						}
						for i, name := range vs.Names {
							localObj := p.TypesInfo.Defs[name]
							if !immutableLocal(localObj) {
								continue
							}
							if key, baseVar, ok := a.seamTarget(vs.Values[i], baseVarByKey); ok && !returnedTargets[key] && !mixedBaseVar(baseVar) {
								saves[key] = append(saves[key], seamSaveRecord{idx: idx, localObj: localObj})
							}
						}
					}
				}
			}
			if isCallableBody {
				if cbody, viaCleanup := cleanupClosureBody(stmt, block); cbody != nil {
					for _, cstmt := range cbody.List {
						if a.stmtMayExitBeforeRestore(cstmt) {
							break
						}
						assign, ok := cstmt.(*ast.AssignStmt)
						if !ok || len(assign.Lhs) != len(assign.Rhs) {
							continue
						}
						for i, lhs := range assign.Lhs {
							key, baseVar, ok := a.seamTarget(lhs, baseVarByKey)
							if !ok || returnedTargets[key] || mixedBaseVar(baseVar) {
								continue
							}
							rhs := ast.Unparen(assign.Rhs[i])
							if id, ok := rhs.(*ast.Ident); ok {
								if obj, ok := a.resolve(id); ok {
									for _, s := range saves[key] {
										if s.localObj == obj && s.idx <= idx {
											deferRestores[key] = append(deferRestores[key], seamRestoreRecord{
												idx:        idx,
												lhs:        lhs,
												cbody:      cbody,
												savedLocal: obj,
												viaCleanup: viaCleanup,
											})
											validRestoreLHS[lhs] = true
										}
									}
								}
							}
							if uninitVars[baseVar] && a.isZeroExpr(rhs) {
								deferRestores[key] = append(deferRestores[key], seamRestoreRecord{
									idx:        idx,
									lhs:        lhs,
									cbody:      cbody,
									zeroReset:  true,
									viaCleanup: viaCleanup,
								})
								validRestoreLHS[lhs] = true
							}
						}
					}
				}
			}
		}

		poisonedKeys := map[string]bool{}
		for _, stmt := range block.List {
			ast.Inspect(stmt, func(n ast.Node) bool {
				if n == nil {
					return false
				}
				if assign, ok := n.(*ast.AssignStmt); ok {
					for _, lhs := range assign.Lhs {
						if exempt[lhs] {
							if key, _, ok := a.seamTarget(lhs, baseVarByKey); ok {
								poisonedKeys[key] = true
							}
						}
					}
				}
				switch n := n.(type) {
				case *ast.DeferStmt:
					ast.Inspect(n.Call, func(inner ast.Node) bool {
						if assign, ok := inner.(*ast.AssignStmt); ok {
							for _, lhs := range assign.Lhs {
								if !validRestoreLHS[lhs] {
									if key, _, ok := a.seamTarget(lhs, baseVarByKey); ok {
										poisonedKeys[key] = true
									}
								}
							}
						}
						return true
					})
					return false
				case *ast.FuncLit:
					ast.Inspect(n.Body, func(inner ast.Node) bool {
						if assign, ok := inner.(*ast.AssignStmt); ok {
							for _, lhs := range assign.Lhs {
								if !validRestoreLHS[lhs] {
									if key, _, ok := a.seamTarget(lhs, baseVarByKey); ok {
										poisonedKeys[key] = true
									}
								}
							}
						}
						return true
					})
					return false
				}
				return true
			})
		}

		writesByKey := map[string][]writeOccurrence{}
		for idx, stmt := range block.List {
			var cbody *ast.BlockStmt
			if isCallableBody {
				cbody, _ = cleanupClosureBody(stmt, block)
			}
			ast.Inspect(stmt, func(n ast.Node) bool {
				if n == nil || (cbody != nil && n == cbody) {
					return false
				}
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
				assign, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range assign.Lhs {
					if exempt[lhs] {
						continue
					}
					if key, _, ok := a.seamTarget(lhs, baseVarByKey); ok {
						writesByKey[key] = append(writesByKey[key], writeOccurrence{idx: idx, lhs: lhs})
					}
				}
				return true
			})
		}

		var deferKeys []string
		for key := range deferRestores {
			deferKeys = append(deferKeys, key)
		}
		sort.Strings(deferKeys)
		for _, key := range deferKeys {
			restores := deferRestores[key]
			if poisonedKeys[key] {
				continue
			}
			consistent := true
			firstR := restores[0]
			for _, r := range restores[1:] {
				if r.zeroReset != firstR.zeroReset || r.savedLocal != firstR.savedLocal || r.viaCleanup != firstR.viaCleanup {
					consistent = false
					break
				}
			}
			if !consistent {
				continue
			}
			writes := writesByKey[key]
			for _, r := range restores {
				valid := true
				if len(writes) > 0 {
					firstIdx := writes[0].idx
					if !r.zeroReset {
						hasMatchingSave := false
						for _, s := range saves[key] {
							if s.localObj == r.savedLocal && s.idx <= firstIdx && s.idx <= r.idx {
								hasMatchingSave = true
								break
							}
						}
						if !hasMatchingSave {
							valid = false
						}
					}
					if valid && firstIdx < r.idx {
						for m := firstIdx; m < r.idx; m++ {
							if a.stmtMayExitBeforeRestore(block.List[m]) {
								valid = false
								break
							}
						}
					}
				}
				if valid {
					var gNodes []ast.Node
					for _, rAll := range restores {
						exempt[rAll.lhs] = true
						gNodes = append(gNodes, rAll.lhs)
					}
					for _, w := range writes {
						exempt[w.lhs] = true
						gNodes = append(gNodes, w.lhs)
					}
					writePos := r.lhs.Pos()
					if len(writes) > 0 {
						writePos = writes[0].lhs.Pos()
					}
					*granted = append(*granted, grantedSeamExemption{
						fd:         fd,
						fn:         declFn,
						baseVar:    baseVarByKey[key],
						key:        key,
						writePos:   writePos,
						nodes:      gNodes,
						viaCleanup: r.viaCleanup,
						zeroReset:  r.zeroReset,
					})
					delete(writesByKey, key)
					break
				}
			}
		}

		var inlineKeys []string
		for key := range writesByKey {
			inlineKeys = append(inlineKeys, key)
		}
		sort.Strings(inlineKeys)
		for _, key := range inlineKeys {
			writes := writesByKey[key]
			if poisonedKeys[key] || len(deferRestores[key]) > 0 || len(saves[key]) == 0 || returnedTargets[key] {
				continue
			}
			for _, s := range saves[key] {
				restoreIdx := -1
				var restoreLHS ast.Expr
				for idx := s.idx + 1; idx < len(block.List); idx++ {
					assign, ok := block.List[idx].(*ast.AssignStmt)
					if !ok || len(assign.Lhs) != len(assign.Rhs) {
						continue
					}
					for i, lhs := range assign.Lhs {
						if k, _, ok := a.seamTarget(lhs, baseVarByKey); ok && k == key {
							if id, ok := ast.Unparen(assign.Rhs[i]).(*ast.Ident); ok {
								if obj, ok := a.resolve(id); ok && obj == s.localObj {
									restoreIdx = idx
									restoreLHS = lhs
									break
								}
							}
						}
					}
					if restoreIdx >= 0 {
						break
					}
				}
				if restoreIdx < 0 {
					continue
				}
				allInSpan := true
				firstIdx := restoreIdx
				for _, w := range writes {
					if w.lhs == restoreLHS {
						continue
					}
					if w.idx <= s.idx || w.idx >= restoreIdx {
						allInSpan = false
						break
					}
					if w.idx < firstIdx {
						firstIdx = w.idx
					}
				}
				if !allInSpan {
					continue
				}
				for m := firstIdx; m < restoreIdx; m++ {
					if a.stmtMayExitBeforeRestore(block.List[m]) {
						allInSpan = false
						break
					}
				}
				if allInSpan {
					gNodes := []ast.Node{restoreLHS}
					exempt[restoreLHS] = true
					for _, w := range writes {
						exempt[w.lhs] = true
						if w.lhs != restoreLHS {
							gNodes = append(gNodes, w.lhs)
						}
					}
					writePos := restoreLHS.Pos()
					for _, w := range writes {
						if w.lhs != restoreLHS {
							writePos = w.lhs.Pos()
							break
						}
					}
					*granted = append(*granted, grantedSeamExemption{
						fd:       fd,
						fn:       declFn,
						baseVar:  baseVarByKey[key],
						key:      key,
						writePos: writePos,
						nodes:    gNodes,
					})
					break
				}
			}
		}
	}
}

func (a *bracketedSeamAnalyzer) revokeAndRecordGrantedSeams(granted []grantedSeamExemption) {
	p := a.p
	exempt := a.res.Exempt
	reachMemo := map[*types.Func]map[*types.Func]bool{}
	canReachIntra := func(from, to *types.Func) bool {
		if from == nil || to == nil {
			return false
		}
		if from == to {
			return true
		}
		if m, ok := reachMemo[from]; ok {
			return m[to]
		}
		visited := map[*types.Func]bool{from: true}
		stack := []*types.Func{from}
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for next := range a.graph.IntraEdges[cur] {
				if !visited[next] {
					visited[next] = true
					stack = append(stack, next)
				}
			}
		}
		reachMemo[from] = visited
		return visited[to]
	}
	overlapsKey := func(g1, g2 grantedSeamExemption) bool {
		if g1.baseVar == nil || g1.baseVar != g2.baseVar {
			return false
		}
		if g1.key == g2.key {
			return true
		}
		whole := syntaxutil.DynamicVarKey(g1.baseVar)
		return g1.key == whole || g2.key == whole
	}

	revoked := make([]bool, len(granted))
	revokeIdx := func(i int) bool {
		if revoked[i] {
			return false
		}
		revoked[i] = true
		for _, n := range granted[i].nodes {
			delete(exempt, n)
		}
		return true
	}

	var toRevoke []int
	for i, g1 := range granted {
		if g1.viaCleanup {
			continue
		}
		for j, g2 := range granted {
			if !g2.viaCleanup || !overlapsKey(g1, g2) {
				continue
			}
			if canReachIntra(g1.fn, g2.fn) {
				toRevoke = append(toRevoke, i, j)
			}
		}
	}
	for _, idx := range toRevoke {
		revokeIdx(idx)
	}

	for changed := true; changed; {
		changed = false
		zeroResetVars := map[*types.Var]bool{}
		for i, g := range granted {
			if !revoked[i] && g.zeroReset && g.baseVar != nil {
				zeroResetVars[g.baseVar] = true
			}
		}
		if len(zeroResetVars) == 0 {
			break
		}
		dirtyZeroVars := map[*types.Var]bool{}
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if n == nil {
					return false
				}
				switch node := n.(type) {
				case *ast.ValueSpec:
					if len(node.Values) > 0 {
						for _, name := range node.Names {
							if v := extractTargetVar(p.TypesInfo, name); zeroResetVars[v] {
								dirtyZeroVars[v] = true
							}
						}
					}
				case *ast.AssignStmt:
					for _, lhs := range node.Lhs {
						if !exempt[lhs] {
							if v := extractTargetVar(p.TypesInfo, lhs); zeroResetVars[v] {
								dirtyZeroVars[v] = true
							}
						}
					}
				case *ast.IncDecStmt:
					if !exempt[node.X] {
						if v := extractTargetVar(p.TypesInfo, node.X); zeroResetVars[v] {
							dirtyZeroVars[v] = true
						}
					}
				case *ast.RangeStmt:
					for _, expr := range []ast.Expr{node.Key, node.Value} {
						if expr != nil && !exempt[expr] {
							if v := extractTargetVar(p.TypesInfo, expr); zeroResetVars[v] {
								dirtyZeroVars[v] = true
							}
						}
					}
				case *ast.SendStmt:
					if v := extractTargetVar(p.TypesInfo, node.Chan); zeroResetVars[v] {
						dirtyZeroVars[v] = true
					}
				}
				return true
			})
		}
		if len(dirtyZeroVars) > 0 {
			for i, g := range granted {
				if !revoked[i] && g.zeroReset && dirtyZeroVars[g.baseVar] {
					if revokeIdx(i) {
						changed = true
					}
				}
			}
		}
	}

	for i, g := range granted {
		if !revoked[i] {
			a.recordMutatingSeam(g.fd, g.baseVar, g.writePos, g.viaCleanup)
		}
	}
}
