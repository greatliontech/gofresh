package seams

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (a *bracketedSeamAnalyzer) analyzeMutexBracketedAtomicPtrs() {
	if !a.audited || a.p.Types == nil {
		return
	}
	p := a.p
	atomicPtrCandidates := map[*types.Var]bool{}
	mutexVars := map[*types.Var]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v.Exported() || !a.uninitDecls[v] {
			continue
		}
		if syntaxutil.IsNamedInPkg(v.Type(), "sync/atomic", "Pointer") {
			atomicPtrCandidates[v] = true
		} else if syntaxutil.IsNamedInPkg(v.Type(), "sync", "Mutex") {
			mutexVars[v] = true
		}
	}
	if len(atomicPtrCandidates) == 0 {
		return
	}

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

	var sortedAtomicVars []*types.Var
	for v := range atomicPtrCandidates {
		sortedAtomicVars = append(sortedAtomicVars, v)
	}
	slices.SortFunc(sortedAtomicVars, func(x, y *types.Var) int {
		return strings.Compare(x.Name(), y.Name())
	})
	for _, v := range sortedAtomicVars {
		if invalidAtomic[v] || !a.atomicLoadResultSafe(loadCalls[v]) {
			continue
		}
		if len(storesInFunc[v]) == 0 {
			for _, sel := range selsByVar[v] {
				a.res.Exempt[sel] = true
			}
			continue
		}
		allBracketed := true
		var sharedMu *types.Var
		for fd := range storesInFunc[v] {
			mu, ok := a.funcBracketsAtomic(fd, v, mutexVars)
			if !ok || (sharedMu != nil && mu != sharedMu) {
				allBracketed = false
				break
			}
			sharedMu = mu
		}
		if allBracketed && sharedMu != nil {
			for _, sel := range selsByVar[v] {
				a.res.Exempt[sel] = true
			}
			var storeDecls []*ast.FuncDecl
			for fd := range storesInFunc[v] {
				storeDecls = append(storeDecls, fd)
			}
			slices.SortFunc(storeDecls, func(x, y *ast.FuncDecl) int {
				if x.Pos() < y.Pos() {
					return -1
				}
				if x.Pos() > y.Pos() {
					return 1
				}
				return 0
			})
			for _, fd := range storeDecls {
				a.recordMutatingSeam(fd, v, storePosInFunc[v][fd], false)
			}
		}
	}
}

func (a *bracketedSeamAnalyzer) atomicLoadResultSafe(calls map[*ast.CallExpr]*ast.FuncDecl) bool {
	p := a.p
	for call, fd := range calls {
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
						if obj, ok := a.resolve(id); ok {
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

func (a *bracketedSeamAnalyzer) funcBracketsAtomic(fd *ast.FuncDecl, v *types.Var, mutexVars map[*types.Var]bool) (*types.Var, bool) {
	p := a.p
	if fd == nil || fd.Recv != nil || fd.Body == nil || a.isBlockedSeamDecl(fd) || fd.Name == nil || fd.Name.Name == "init" || fd.Name.Name == "_" || bodyHasGoOrParallel(p.TypesInfo, fd.Body) {
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
		if a.stmtMayExitBeforeRestore(fd.Body.List[m]) {
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
			if obj == v && sel.Sel.Name == "Store" && call != resetCall && idx <= resetIdx {
				validBody = false
				return false
			}
			return true
		})
	}
	if !validBody {
		return nil, false
	}
	return lockedMu, true
}
