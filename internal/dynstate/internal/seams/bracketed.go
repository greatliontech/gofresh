package seams

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// BracketedSeamNodes returns the AST nodes in p exempted as sequential
// bracketed seams (REQ-closure-shared-dynamic-state).
func BracketedSeamNodes(audited bool, p *packages.Package) map[ast.Node]bool {
	return AnalyzeBracketedSeams(audited, p, nil, nil).Exempt
}

// AnalyzeBracketedSeams identifies AST nodes in p that belong to lexically
// bracketed save-and-restore or zero-reset seams in sequential plain package
// functions (not methods, no go statement, no .Parallel reference, no escaping
// closure writing the seam, and neither escaping as a function value nor
// reachable in the package graph from init flow, a method, a go statement, or
// a .Parallel-bearing scope) or, under an audited toolchain, to an unexported
// uninitialized sync/atomic.Pointer[T] hook variable whose Store calls, if
// any, are serialized in such sequential plain functions under a single
// unexported package-level sync.Mutex with mu.Lock(), defer mu.Unlock(), and
// defer v.Store(nil) executed in that order before any non-nil Store or early
// exit, and summarizes exported mutating seams and cross-package function edges
// for Compose (REQ-closure-shared-dynamic-state).
func AnalyzeBracketedSeams(audited bool, p *packages.Package, idx *refconfine.PkgIndex, markHook ExportedSeamMarkHook) Result {
	var res Result
	if p == nil || p.TypesInfo == nil {
		return res
	}
	exempt := map[ast.Node]bool{}
	res.Exempt = exempt
	graph := AnalyzeCallGraph(p)
	res.NonSeqFuncUses = graph.NonSeqFuncUses
	res.SeqFuncEdges = graph.SeqFuncEdges
	res.ParallelFuncs = graph.ParallelFuncs
	res.ParallelEdges = graph.ParallelEdges
	liveHandles := computeLiveTestingHandles(p, graph)

	isBlockedSeamDecl := func(fd *ast.FuncDecl) bool {
		if fd == nil || fd.Name == nil || len(graph.Blocked) == 0 {
			return false
		}
		fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
		return ok && fn != nil && graph.Blocked[fn.Origin()]
	}
	var revIntra map[*types.Func][]*types.Func
	type exportedSeamKey struct {
		fn  syntaxutil.FuncKey
		key string
	}
	exportedSeamIdx := map[exportedSeamKey]int{}
	type exportedSeamMarkKey struct {
		fn  syntaxutil.FuncKey
		key string
		pos token.Pos
	}
	seenExportedMark := map[exportedSeamMarkKey]bool{}
	recordMutatingSeam := func(fd *ast.FuncDecl, baseVar *types.Var, writePos token.Pos, viaCleanup bool) {
		if fd == nil || fd.Name == nil || baseVar == nil || p.Types == nil || !refconfine.TypeMayCarryUnknownDynamic(audited, baseVar.Type()) {
			return
		}
		fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
		if !ok || fn == nil {
			return
		}
		fn = fn.Origin()
		if graph.Blocked[fn] {
			return
		}
		if revIntra == nil {
			revIntra = map[*types.Func][]*types.Func{}
			for caller, callees := range graph.IntraEdges {
				for callee := range callees {
					revIntra[callee] = append(revIntra[callee], caller)
				}
			}
		}
		var exportedCallers []*types.Func
		visited := map[*types.Func]bool{fn: true}
		stack := []*types.Func{fn}
		for len(stack) > 0 {
			cur := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if graph.Blocked[cur] {
				continue
			}
			if cur.Exported() || (p.Name == "main" && cur.Name() == "main") {
				exportedCallers = append(exportedCallers, cur)
			}
			for _, caller := range revIntra[cur] {
				if !visited[caller] {
					visited[caller] = true
					stack = append(stack, caller)
				}
			}
		}
		if len(exportedCallers) == 0 {
			return
		}
		slices.SortFunc(exportedCallers, func(a, b *types.Func) int {
			return strings.Compare(a.Name(), b.Name())
		})
		varKey := syntaxutil.DynamicVarKey(baseVar)
		for _, cur := range exportedCallers {
			expKey := syntaxutil.FuncKey{Pkg: p.Types.Path(), Name: cur.Name()}
			esk := exportedSeamKey{fn: expKey, key: varKey}
			if sIdx, exists := exportedSeamIdx[esk]; exists {
				if viaCleanup {
					res.ExportedSeams[sIdx].RunnerOnly = true
				}
			} else {
				exportedSeamIdx[esk] = len(res.ExportedSeams)
				res.ExportedSeams = append(res.ExportedSeams, syntaxutil.ExportedSeam{
					Func:       expKey,
					Key:        varKey,
					RunnerOnly: viaCleanup,
				})
			}
			mk := exportedSeamMarkKey{fn: expKey, key: varKey, pos: writePos}
			if !seenExportedMark[mk] {
				seenExportedMark[mk] = true
				if markHook != nil {
					markHook(p, expKey, varKey, writePos)
				}
			}
		}
	}
	resolve := func(ident *ast.Ident) (types.Object, bool) {
		if obj, ok := p.TypesInfo.Uses[ident]; ok && obj != nil {
			return obj, true
		}
		if obj, ok := p.TypesInfo.Defs[ident]; ok && obj != nil {
			return obj, true
		}
		return nil, false
	}

	addrTaken := map[*types.Var]bool{}
	ptrMethodOnVar := map[*types.Var]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					ast.Inspect(node.X, func(inner ast.Node) bool {
						if id, ok := inner.(*ast.Ident); ok {
							if obj, ok := resolve(id); ok {
								if v, ok := obj.(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
									addrTaken[v] = true
								}
							}
						}
						return true
					})
				}
			case *ast.SelectorExpr:
				if selInfo, ok := p.TypesInfo.Selections[node]; ok && selInfo != nil && selInfo.Kind() == types.MethodVal {
					if fn, ok := selInfo.Obj().(*types.Func); ok && fn != nil {
						if sig, ok := fn.Type().(*types.Signature); ok && sig != nil && sig.Recv() != nil {
							if _, isPtr := types.Unalias(sig.Recv().Type()).(*types.Pointer); isPtr {
								if v := extractTargetVar(p.TypesInfo, node.X); v != nil && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
									ptrMethodOnVar[v] = true
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	uninitDecls := map[*types.Var]bool{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Values) != 0 {
					continue
				}
				for _, name := range vs.Names {
					if v, ok := p.TypesInfo.Defs[name].(*types.Var); ok && v != nil && !v.Exported() && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && !addrTaken[v] {
						uninitDecls[v] = true
					}
				}
			}
		}
	}
	var initHelpers map[string]bool
	if idx != nil && idx.InitOnly != nil {
		initHelpers = idx.InitOnly
	} else {
		initHelpers = refconfine.BuildCallSiteIndex(p).InitOnlyHelpers()
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil {
				continue
			}
			if fd.Name.Name != "init" && !initHelpers[fd.Name.Name] {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range n.Lhs {
						ast.Inspect(lhs, func(inner ast.Node) bool {
							if id, ok := inner.(*ast.Ident); ok {
								if obj, ok := resolve(id); ok {
									if v, ok := obj.(*types.Var); ok {
										delete(uninitDecls, v)
									}
								}
							}
							return true
						})
					}
				case *ast.CallExpr:
					if sel, ok := ast.Unparen(n.Fun).(*ast.SelectorExpr); ok {
						if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
							if obj, ok := resolve(id); ok {
								if v, ok := obj.(*types.Var); ok {
									delete(uninitDecls, v)
								}
							}
						}
					}
				}
				return true
			})
		}
	}

	isAbortCall := func(call *ast.CallExpr) bool {
		switch fun := ast.Unparen(call.Fun).(type) {
		case *ast.Ident:
			if b, ok := p.TypesInfo.Uses[fun].(*types.Builtin); ok && b.Name() == "panic" {
				return true
			}
		case *ast.SelectorExpr:
			switch fun.Sel.Name {
			case "Fatal", "Fatalf", "Fatalln", "FailNow", "Skip", "Skipf", "SkipNow", "Panic", "Panicf", "Panicln", "Goexit", "Exit":
				return true
			}
		}
		return false
	}

	var iifeBodyMayAbort func(body *ast.BlockStmt) bool
	iifeBodyMayAbort = func(body *ast.BlockStmt) bool {
		if body == nil {
			return false
		}
		deferredOrGo := map[*ast.CallExpr]bool{}
		ast.Inspect(body, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.DeferStmt:
				if s.Call != nil {
					deferredOrGo[s.Call] = true
				}
			case *ast.GoStmt:
				if s.Call != nil {
					deferredOrGo[s.Call] = true
				}
			}
			return true
		})
		aborts := false
		ast.Inspect(body, func(n ast.Node) bool {
			if aborts || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.CallExpr:
				if isAbortCall(node) {
					aborts = true
					return false
				}
				if !deferredOrGo[node] {
					if lit, ok := ast.Unparen(node.Fun).(*ast.FuncLit); ok && iifeBodyMayAbort(lit.Body) {
						aborts = true
						return false
					}
				}
			}
			return true
		})
		return aborts
	}

	stmtMayExitBeforeRestore := func(stmt ast.Stmt) bool {
		if stmt == nil {
			return false
		}
		deferredOrGo := map[*ast.CallExpr]bool{}
		ast.Inspect(stmt, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.DeferStmt:
				if s.Call != nil {
					deferredOrGo[s.Call] = true
				}
			case *ast.GoStmt:
				if s.Call != nil {
					deferredOrGo[s.Call] = true
				}
			}
			return true
		})
		exits := false
		ast.Inspect(stmt, func(n ast.Node) bool {
			if exits || n == nil {
				return false
			}
			switch n := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ReturnStmt, *ast.BranchStmt:
				exits = true
				return false
			case *ast.CallExpr:
				if isAbortCall(n) {
					exits = true
					return false
				}
				if !deferredOrGo[n] {
					if lit, ok := ast.Unparen(n.Fun).(*ast.FuncLit); ok && iifeBodyMayAbort(lit.Body) {
						exits = true
						return false
					}
				}
			}
			return true
		})
		return exits
	}

	// 1. Mutex-bracketed unexported sync/atomic.Pointer[T] hook variables.
	isPkgNamedType := func(t types.Type, pkgPath, name string) bool {
		named, ok := types.Unalias(t).(*types.Named)
		return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
			named.Obj().Pkg().Path() == pkgPath && named.Obj().Name() == name
	}
	atomicPtrCandidates := map[*types.Var]bool{}
	mutexVars := map[*types.Var]bool{}
	if p.Types != nil {
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			v, ok := scope.Lookup(name).(*types.Var)
			if !ok || v.Exported() || !uninitDecls[v] {
				continue
			}
			if isPkgNamedType(v.Type(), "sync/atomic", "Pointer") {
				atomicPtrCandidates[v] = true
			} else if isPkgNamedType(v.Type(), "sync", "Mutex") {
				mutexVars[v] = true
			}
		}
	}
	if audited && len(atomicPtrCandidates) > 0 {
		validLoadStoreIdents := map[*ast.Ident]bool{}
		selsByVar := map[*types.Var][]*ast.SelectorExpr{}
		storesInFunc := map[*types.Var]map[*ast.FuncDecl]bool{}
		storePosInFunc := map[*types.Var]map[*ast.FuncDecl]token.Pos{}
		invalidAtomic := map[*types.Var]bool{}
		loadCalls := map[*types.Var]map[*ast.CallExpr]*ast.FuncDecl{}
		for _, file := range p.Syntax {
			for _, decl := range file.Decls {
				fd, isFD := decl.(*ast.FuncDecl)
				var walkDecl func(n ast.Node, inLitOrGo bool)
				walkDecl = func(n ast.Node, inLitOrGo bool) {
					if n == nil {
						return
					}
					switch node := n.(type) {
					case *ast.FuncLit, *ast.GoStmt:
						inLitOrGo = true
					case *ast.CallExpr:
						if sel, ok := ast.Unparen(node.Fun).(*ast.SelectorExpr); ok {
							if ident, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
								if v, ok := p.TypesInfo.Uses[ident].(*types.Var); ok && atomicPtrCandidates[v] {
									if sel.Sel.Name == "Load" && len(node.Args) == 0 && isFD && fd.Body != nil {
										validLoadStoreIdents[ident] = true
										selsByVar[v] = append(selsByVar[v], sel)
										if loadCalls[v] == nil {
											loadCalls[v] = map[*ast.CallExpr]*ast.FuncDecl{}
										}
										loadCalls[v][node] = fd
									} else if sel.Sel.Name == "Store" && len(node.Args) == 1 {
										validLoadStoreIdents[ident] = true
										selsByVar[v] = append(selsByVar[v], sel)
										if isFD && fd.Body != nil && !inLitOrGo {
											if storesInFunc[v] == nil {
												storesInFunc[v] = map[*ast.FuncDecl]bool{}
												storePosInFunc[v] = map[*ast.FuncDecl]token.Pos{}
											}
											storesInFunc[v][fd] = true
											if !storePosInFunc[v][fd].IsValid() {
												storePosInFunc[v][fd] = node.Pos()
											}
										} else {
											invalidAtomic[v] = true
										}
									}
								}
							}
						}
					}
					ast.Inspect(n, func(child ast.Node) bool {
						if child == nil || child == n {
							return true
						}
						walkDecl(child, inLitOrGo)
						return false
					})
				}
				walkDecl(decl, false)
			}
		}
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				ident, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				if v, ok := p.TypesInfo.Uses[ident].(*types.Var); ok && atomicPtrCandidates[v] && !validLoadStoreIdents[ident] {
					delete(atomicPtrCandidates, v)
				}
				return true
			})
		}
		loadResultSafe := func(v *types.Var) bool {
			for call, fd := range loadCalls[v] {
				allowedCallContext := false
				var boundLocal types.Object
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.BinaryExpr:
						if (n.Op == token.EQL || n.Op == token.NEQ) && (ast.Unparen(n.X) == call || ast.Unparen(n.Y) == call) {
							allowedCallContext = true
						}
					case *ast.SelectorExpr:
						if ast.Unparen(n.X) == call {
							allowedCallContext = true
						}
					case *ast.AssignStmt:
						if len(n.Lhs) == 1 && len(n.Rhs) == 1 && ast.Unparen(n.Rhs[0]) == call {
							if id, ok := ast.Unparen(n.Lhs[0]).(*ast.Ident); ok {
								if obj, ok := resolve(id); ok {
									if lv, ok := obj.(*types.Var); ok && lv.Pkg() != nil && lv.Parent() != lv.Pkg().Scope() {
										allowedCallContext = true
										boundLocal = obj
									}
								}
							}
						}
					}
					return true
				})
				if !allowedCallContext {
					return false
				}
				if boundLocal != nil {
					writes := 0
					validIdentUses := map[*ast.Ident]bool{}
					ast.Inspect(fd.Body, func(n ast.Node) bool {
						switch n := n.(type) {
						case *ast.AssignStmt:
							for _, lhs := range n.Lhs {
								ast.Inspect(lhs, func(inner ast.Node) bool {
									if id, ok := inner.(*ast.Ident); ok && p.TypesInfo.Defs[id] == boundLocal {
										writes++
										validIdentUses[id] = true
									} else if id, ok := inner.(*ast.Ident); ok && p.TypesInfo.Uses[id] == boundLocal {
										writes++
									}
									return true
								})
							}
						case *ast.BinaryExpr:
							if n.Op == token.EQL || n.Op == token.NEQ {
								for _, side := range []ast.Expr{n.X, n.Y} {
									if id, ok := ast.Unparen(side).(*ast.Ident); ok && p.TypesInfo.Uses[id] == boundLocal {
										validIdentUses[id] = true
									}
								}
							}
						case *ast.SelectorExpr:
							if id, ok := ast.Unparen(n.X).(*ast.Ident); ok && p.TypesInfo.Uses[id] == boundLocal {
								validIdentUses[id] = true
							}
						}
						return true
					})
					if writes != 1 {
						return false
					}
					allUsesValid := true
					ast.Inspect(fd.Body, func(n ast.Node) bool {
						if id, ok := n.(*ast.Ident); ok {
							if (p.TypesInfo.Uses[id] == boundLocal || p.TypesInfo.Defs[id] == boundLocal) && !validIdentUses[id] {
								allUsesValid = false
								return false
							}
						}
						return true
					})
					if !allUsesValid {
						return false
					}
				}
			}
			return true
		}
		funcBracketsAtomic := func(fd *ast.FuncDecl, v *types.Var) (*types.Var, bool) {
			if fd == nil || fd.Recv != nil || fd.Body == nil || isBlockedSeamDecl(fd) || fd.Name == nil || fd.Name.Name == "init" || fd.Name.Name == "_" || bodyHasGoOrParallel(p.TypesInfo, fd.Body) {
				return nil, false
			}
			lockIdx := -1
			unlockIdx := -1
			resetIdx := -1
			var lockedMu *types.Var
			validMutexCalls := map[*ast.CallExpr]bool{}
			var resetCall *ast.CallExpr
			for idx, stmt := range fd.Body.List {
				switch s := stmt.(type) {
				case *ast.ExprStmt:
					if call, ok := s.X.(*ast.CallExpr); ok && len(call.Args) == 0 {
						if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Lock" {
							if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
								if mu, ok := p.TypesInfo.Uses[id].(*types.Var); ok && mutexVars[mu] {
									if lockIdx >= 0 {
										return nil, false
									}
									lockIdx = idx
									lockedMu = mu
									validMutexCalls[call] = true
								}
							}
						}
					}
				case *ast.DeferStmt:
					if sel, ok := ast.Unparen(s.Call.Fun).(*ast.SelectorExpr); ok {
						if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
							if obj := p.TypesInfo.Uses[id]; obj != nil {
								if lockedMu != nil && obj == lockedMu && sel.Sel.Name == "Unlock" && len(s.Call.Args) == 0 {
									if unlockIdx >= 0 || idx <= lockIdx {
										return nil, false
									}
									unlockIdx = idx
									validMutexCalls[s.Call] = true
								} else if obj == v && sel.Sel.Name == "Store" && len(s.Call.Args) == 1 {
									argID, ok := ast.Unparen(s.Call.Args[0]).(*ast.Ident)
									if !ok {
										return nil, false
									}
									if _, isNil := p.TypesInfo.Uses[argID].(*types.Nil); !isNil {
										return nil, false
									}
									if resetIdx >= 0 || unlockIdx < 0 || idx <= unlockIdx {
										return nil, false
									}
									resetIdx = idx
									resetCall = s.Call
								}
							}
						}
					}
				}
			}
			if lockedMu == nil || lockIdx < 0 || unlockIdx <= lockIdx || resetIdx <= unlockIdx {
				return nil, false
			}
			for m := 0; m < resetIdx; m++ {
				if stmtMayExitBeforeRestore(fd.Body.List[m]) {
					return nil, false
				}
			}
			validBody := true
			for idx, stmt := range fd.Body.List {
				ast.Inspect(stmt, func(n ast.Node) bool {
					if !validBody || n == nil {
						return false
					}
					if d, ok := n.(*ast.DeferStmt); ok && d.Call != resetCall {
						ast.Inspect(d.Call, func(inner ast.Node) bool {
							if id, ok := inner.(*ast.Ident); ok && p.TypesInfo.Uses[id] == v {
								validBody = false
								return false
							}
							return true
						})
					}
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
					if !ok {
						return true
					}
					id, ok := ast.Unparen(sel.X).(*ast.Ident)
					if !ok {
						return true
					}
					obj := p.TypesInfo.Uses[id]
					if mu, ok := obj.(*types.Var); ok && mutexVars[mu] && !validMutexCalls[call] {
						validBody = false
						return false
					}
					if obj == v && sel.Sel.Name == "Store" && call != resetCall {
						if idx <= resetIdx {
							validBody = false
							return false
						}
					}
					return true
				})
			}
			if !validBody {
				return nil, false
			}
			return lockedMu, true
		}
		var sortedAtomicVars []*types.Var
		for v := range atomicPtrCandidates {
			sortedAtomicVars = append(sortedAtomicVars, v)
		}
		slices.SortFunc(sortedAtomicVars, func(a, b *types.Var) int {
			return strings.Compare(a.Name(), b.Name())
		})
		for _, v := range sortedAtomicVars {
			if invalidAtomic[v] || !loadResultSafe(v) {
				continue
			}
			if len(storesInFunc[v]) == 0 {
				for _, sel := range selsByVar[v] {
					exempt[sel] = true
				}
				continue
			}
			allBracketed := true
			var sharedMu *types.Var
			for fd := range storesInFunc[v] {
				mu, ok := funcBracketsAtomic(fd, v)
				if !ok || (sharedMu != nil && mu != sharedMu) {
					allBracketed = false
					break
				}
				sharedMu = mu
			}
			if allBracketed && sharedMu != nil {
				for _, sel := range selsByVar[v] {
					exempt[sel] = true
				}
				var storeDecls []*ast.FuncDecl
				for fd := range storesInFunc[v] {
					storeDecls = append(storeDecls, fd)
				}
				slices.SortFunc(storeDecls, func(a, b *ast.FuncDecl) int {
					if a.Pos() < b.Pos() {
						return -1
					}
					if a.Pos() > b.Pos() {
						return 1
					}
					return 0
				})
				for _, fd := range storeDecls {
					recordMutatingSeam(fd, v, storePosInFunc[v][fd], false)
				}
			}
		}
	}

	// 2. Lexically bracketed save-and-restore or zero-reset seams on
	// non-alias-handing, non-mutable-reach package variables (and their fields).
	candidateVar := func(obj types.Object) (*types.Var, bool) {
		v, ok := obj.(*types.Var)
		if !ok || v == nil || p.Types == nil || v.Pkg() != p.Types || v.Parent() != v.Pkg().Scope() || addrTaken[v] || ptrMethodOnVar[v] {
			return nil, false
		}
		if refconfine.TypeHandsOutDynamicAlias(audited, v.Type()) ||
			refconfine.TypeHandsOutMutableReach(v.Type()) {
			return nil, false
		}
		return v, true
	}
	uninitVars := map[*types.Var]bool{}
	for v := range uninitDecls {
		if _, ok := candidateVar(v); ok {
			uninitVars[v] = true
		}
	}
	baseVarByKey := map[string]*types.Var{}
	seamTarget := func(expr ast.Expr) (string, *types.Var, bool) {
		expr = ast.Unparen(expr)
		switch e := expr.(type) {
		case *ast.Ident:
			obj, ok := resolve(e)
			if !ok {
				return "", nil, false
			}
			v, ok := candidateVar(obj)
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
			obj, ok := resolve(baseID)
			if !ok {
				return "", nil, false
			}
			v, ok := candidateVar(obj)
			if !ok {
				return "", nil, false
			}
			field, ok := p.TypesInfo.Uses[e.Sel].(*types.Var)
			if !ok || field == nil ||
				refconfine.TypeHandsOutDynamicAlias(audited, field.Type()) ||
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
	isZeroExpr := func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		switch e := expr.(type) {
		case *ast.Ident:
			switch p.TypesInfo.Uses[e].(type) {
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

	type saveRecord struct {
		idx      int
		localObj types.Object
	}
	type restoreRecord struct {
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
	var granted []grantedSeamExemption

	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil || isBlockedSeamDecl(fd) || fd.Name == nil || fd.Name.Name == "init" || fd.Name.Name == "_" || bodyHasGoOrParallel(p.TypesInfo, fd.Body) {
				continue
			}
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
						if obj, ok := resolve(id); ok {
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
							if obj, ok := resolve(id); ok && i < len(n.Rhs) {
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
								if obj, ok := resolve(id); ok {
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
							if key, _, ok := seamTarget(lhs); ok {
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
						if obj, ok := resolve(inner); ok && localFuncLits[obj] != nil {
							markLitTargets(localFuncLits[obj])
						}
					}
					return true
				})
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit:
					if graph.NonSeqLits[n] {
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
							if obj, ok := resolve(id); ok && namedResults[obj] && i < len(n.Rhs) {
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
						if key, baseVar, ok := seamTarget(lhs); ok {
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
					if lit, ok := ast.Unparen(s.Call.Fun).(*ast.FuncLit); ok && len(s.Call.Args) == 0 && !graph.NonSeqLits[lit] {
						return lit.Body, false
					}
					if id, ok := ast.Unparen(s.Call.Fun).(*ast.Ident); ok && len(s.Call.Args) == 0 {
						if obj, ok := resolve(id); ok && immutableLocal(obj) && localFuncLits[obj] != nil && !graph.NonSeqLits[localFuncLits[obj]] {
							return localFuncLits[obj].Body, false
						}
					}
				case *ast.ExprStmt:
					if liveHandles == nil {
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
					if !ok || recvVar == nil || !liveHandles[block][recvVar] {
						return nil, false
					}
					if lit, ok := ast.Unparen(call.Args[0]).(*ast.FuncLit); ok && !graph.NonSeqLits[lit] {
						return lit.Body, true
					}
					if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); ok {
						if obj, ok := resolve(id); ok && immutableLocal(obj) && localFuncLits[obj] != nil && !graph.NonSeqLits[localFuncLits[obj]] {
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
					if graph.NonSeqLits[n] {
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
			for bi := len(blocks) - 1; bi >= 0; bi-- {
				block := blocks[bi]
				isCallableBody := callableBodies[block]
				saves := map[string][]saveRecord{}
				deferRestores := map[string][]restoreRecord{}
				validRestoreLHS := map[ast.Expr]bool{}
				for idx, stmt := range block.List {
					if assign, ok := stmt.(*ast.AssignStmt); ok && len(assign.Lhs) == len(assign.Rhs) {
						for i, lhs := range assign.Lhs {
							id, ok := ast.Unparen(lhs).(*ast.Ident)
							if !ok {
								continue
							}
							localObj, ok := resolve(id)
							if !ok || !immutableLocal(localObj) {
								continue
							}
							if key, baseVar, ok := seamTarget(assign.Rhs[i]); ok && !returnedTargets[key] && !mixedBaseVar(baseVar) {
								saves[key] = append(saves[key], saveRecord{idx: idx, localObj: localObj})
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
									if key, baseVar, ok := seamTarget(vs.Values[i]); ok && !returnedTargets[key] && !mixedBaseVar(baseVar) {
										saves[key] = append(saves[key], saveRecord{idx: idx, localObj: localObj})
									}
								}
							}
						}
					}
					if isCallableBody {
						if cbody, viaCleanup := cleanupClosureBody(stmt, block); cbody != nil {
							for _, cstmt := range cbody.List {
								if stmtMayExitBeforeRestore(cstmt) {
									break
								}
								assign, ok := cstmt.(*ast.AssignStmt)
								if !ok || len(assign.Lhs) != len(assign.Rhs) {
									continue
								}
								for i, lhs := range assign.Lhs {
									key, baseVar, ok := seamTarget(lhs)
									if !ok || returnedTargets[key] || mixedBaseVar(baseVar) {
										continue
									}
									rhs := ast.Unparen(assign.Rhs[i])
									if id, ok := rhs.(*ast.Ident); ok {
										if obj, ok := resolve(id); ok {
											for _, s := range saves[key] {
												if s.localObj == obj && s.idx <= idx {
													deferRestores[key] = append(deferRestores[key], restoreRecord{
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
									if uninitVars[baseVar] && isZeroExpr(rhs) {
										deferRestores[key] = append(deferRestores[key], restoreRecord{
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
									if key, _, ok := seamTarget(lhs); ok {
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
											if key, _, ok := seamTarget(lhs); ok {
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
											if key, _, ok := seamTarget(lhs); ok {
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

				type writeOccurrence struct {
					idx int
					lhs ast.Expr
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
							if key, _, ok := seamTarget(lhs); ok {
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
									if stmtMayExitBeforeRestore(block.List[m]) {
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
							granted = append(granted, grantedSeamExemption{
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
								if k, _, ok := seamTarget(lhs); ok && k == key {
									if id, ok := ast.Unparen(assign.Rhs[i]).(*ast.Ident); ok {
										if obj, ok := resolve(id); ok && obj == s.localObj {
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
							if stmtMayExitBeforeRestore(block.List[m]) {
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
							granted = append(granted, grantedSeamExemption{
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
	}

	if len(granted) > 0 {
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
				for next := range graph.IntraEdges[cur] {
					if !visited[next] {
						visited[next] = true
						stack = append(stack, next)
					}
				}
			}
			reachMemo[from] = visited
			return visited[to]
		}
		overlapsKey := func(a, b grantedSeamExemption) bool {
			if a.baseVar == nil || a.baseVar != b.baseVar {
				return false
			}
			if a.key == b.key {
				return true
			}
			whole := syntaxutil.DynamicVarKey(a.baseVar)
			return a.key == whole || b.key == whole
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

		// Revoke LIFO-conflicting defer/inline + Cleanup exemptions along 0+ intraEdges.
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

		// Monotonically revoke zeroReset exemptions on any variable that has a
		// non-exempt write anywhere in p.Syntax.
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
				recordMutatingSeam(g.fd, g.baseVar, g.writePos, g.viaCleanup)
			}
		}
	}

	slices.SortFunc(res.ExportedSeams, syntaxutil.ExportedSeam.Compare)
	return res
}
