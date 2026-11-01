package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
)

// unwrapCallee strips the spellings a direct call's callee can wear —
// parentheses and an explicit generic instantiation (index and
// index-list) — down to the expression naming it, the one ladder every
// callee-resolving walk shares.
func unwrapCallee(fun ast.Expr) ast.Expr {
	for {
		switch f := fun.(type) {
		case *ast.ParenExpr:
			fun = f.X
		case *ast.IndexExpr:
			fun = f.X
		case *ast.IndexListExpr:
			fun = f.X
		default:
			return fun
		}
	}
}

// plainCalleeFunc resolves a call's function expression to a plain named
// function and its declaring package path, unwrapping parenthesization
// and explicit generic instantiation; the generic origin carries the
// declared identity. Method values, builtins, and function-typed values
// resolve to nil - only a named function has a parameter fact to defer
// to (REQ-closure-shared-dynamic-state).
func plainCalleeFunc(p *packages.Package, fun ast.Expr) (*types.Func, string) {
	if p == nil || p.TypesInfo == nil {
		return nil, ""
	}
	fun = unwrapCallee(fun)
	var obj types.Object
	switch f := fun.(type) {
	case *ast.Ident:
		obj = p.TypesInfo.Uses[f]
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
				obj = p.TypesInfo.Uses[f.Sel]
			}
		}
	}
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return nil, ""
	}
	fn = fn.Origin()
	if sig, ok := fn.Type().(*types.Signature); !ok || sig.Recv() != nil {
		return nil, ""
	}
	return fn, fn.Pkg().Path()
}

func unparenExpr(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// eachLocalBinding visits each local binding pair (lhs, rhs) introduced by an
// assignment statement, value specification, range statement, or builtin
// copy(dst, src) call. It returns true when n is one of those four shapes.
func eachLocalBinding(info *types.Info, n ast.Node, visit func(lhs, rhs ast.Expr)) bool {
	switch n := n.(type) {
	case *ast.AssignStmt:
		if len(n.Lhs) == len(n.Rhs) {
			for i, lhs := range n.Lhs {
				visit(lhs, n.Rhs[i])
			}
		} else if len(n.Rhs) == 1 {
			for _, lhs := range n.Lhs {
				visit(lhs, n.Rhs[0])
			}
		}
		return true
	case *ast.ValueSpec:
		if len(n.Names) == len(n.Values) {
			for i, name := range n.Names {
				visit(name, n.Values[i])
			}
		} else if len(n.Values) == 1 {
			for _, name := range n.Names {
				visit(name, n.Values[0])
			}
		}
		return true
	case *ast.RangeStmt:
		for _, bind := range []ast.Expr{n.Key, n.Value} {
			if bind != nil {
				visit(bind, n.X)
			}
		}
		return true
	case *ast.CallExpr:
		if info != nil && len(n.Args) == 2 {
			if ident, ok := unparenExpr(n.Fun).(*ast.Ident); ok {
				if _, builtin := info.Uses[ident].(*types.Builtin); builtin && ident.Name == "copy" {
					visit(n.Args[0], n.Args[1])
					return true
				}
			}
		}
	}
	return false
}

// rootIdent unwraps selector, index, dereference, and parenthesized spine
// expressions down to the root identifier, or nil for any other shape.
func rootIdent(expr ast.Expr) *ast.Ident {
	for {
		switch e := expr.(type) {
		case *ast.Ident:
			return e
		case *ast.SelectorExpr:
			expr = e.X
		case *ast.IndexExpr:
			expr = e.X
		case *ast.IndexListExpr:
			expr = e.X
		case *ast.StarExpr:
			expr = e.X
		case *ast.ParenExpr:
			expr = e.X
		default:
			return nil
		}
	}
}

func identDefOrUse(info *types.Info, ident *ast.Ident) types.Object {
	if info == nil || ident == nil {
		return nil
	}
	if obj := info.Defs[ident]; obj != nil {
		return obj
	}
	return info.Uses[ident]
}

func isMethodValueBind(info *types.Info, expr ast.Expr) bool {
	sel, ok := unwrapCallee(expr).(*ast.SelectorExpr)
	if !ok || info == nil {
		return false
	}
	selection, ok := info.Selections[sel]
	return ok && selection.Kind() == types.MethodVal
}

// propagateLocalTaint computes the least fixed point of tainted local objects
// in body: any identifier bound by an assignment, value specification, or
// range statement whose source expression satisfies rhsTainted (or rangeTainted
// for a range operand) and whose object satisfies allow is added to tainted
// until convergence.
func propagateLocalTaint(
	info *types.Info,
	body ast.Node,
	tainted map[types.Object]bool,
	allow func(types.Object) bool,
	rhsTainted func(ast.Expr) bool,
	rangeTainted func(ast.Expr) bool,
) {
	for changed := true; changed; {
		changed = false
		taint := func(ident *ast.Ident) {
			obj := identDefOrUse(info, ident)
			if obj == nil || tainted[obj] || !allow(obj) {
				return
			}
			tainted[obj] = true
			changed = true
		}
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, rhs := range n.Rhs {
						if !rhsTainted(rhs) {
							continue
						}
						if ident, ok := n.Lhs[i].(*ast.Ident); ok {
							taint(ident)
						}
					}
				} else if len(n.Rhs) == 1 && rhsTainted(n.Rhs[0]) {
					for _, lhs := range n.Lhs {
						if ident, ok := lhs.(*ast.Ident); ok {
							taint(ident)
						}
					}
				}
			case *ast.RangeStmt:
				if rangeTainted != nil && rangeTainted(n.X) {
					for _, bind := range []ast.Expr{n.Key, n.Value} {
						if ident, ok := bind.(*ast.Ident); ok {
							taint(ident)
						}
					}
				}
			case *ast.ValueSpec:
				if len(n.Names) == len(n.Values) {
					for i, rhs := range n.Values {
						if rhs != nil && rhsTainted(rhs) {
							taint(n.Names[i])
						}
					}
				} else if len(n.Values) == 1 && n.Values[0] != nil && rhsTainted(n.Values[0]) {
					for _, name := range n.Names {
						taint(name)
					}
				}
			}
			return true
		})
	}
}

// pendingReturnDisposition is one conditionally discharged range whose
// enclosing function returned the binding: the fn's callers decide, and
// an uncontained handout restores the escape - to the attributed record
// when the range sat in an attributed body, to the immediate marks
// otherwise (REQ-closure-shared-dynamic-state).
type pendingReturnDisposition struct {
	fn     string
	keys   []string
	attrFn FuncKey
}

// bracketedSeamNodes identifies AST nodes in p that belong to lexically
// bracketed save-and-restore or zero-reset seams in sequential functions
// (no go statement, no .Parallel() call, and no escaping closure writing
// the seam) or to an unexported sync/atomic.Pointer[T] hook variable whose
// Store calls are serialized under a single unexported package-level
// sync.Mutex with mu.Lock(), defer mu.Unlock(), and defer v.Store(nil)
// executed in that order before any non-nil Store or early exit
// (REQ-closure-shared-dynamic-state).
func bracketedSeamNodes(audited bool, p *packages.Package) map[ast.Node]bool {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	exempt := map[ast.Node]bool{}
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
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.AND {
				ast.Inspect(u.X, func(inner ast.Node) bool {
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
					if v, ok := p.TypesInfo.Defs[name].(*types.Var); ok && v != nil && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && !addrTaken[v] {
						uninitDecls[v] = true
					}
				}
			}
		}
	}
	initHelpers := initOnlyReachableHelpers(p)
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
					if sel, ok := unparenExpr(n.Fun).(*ast.SelectorExpr); ok {
						if id, ok := unparenExpr(sel.X).(*ast.Ident); ok {
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

	stmtMayExitBeforeRestore := func(stmt ast.Stmt) bool {
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
				switch fun := unparenExpr(n.Fun).(type) {
				case *ast.Ident:
					if b, ok := p.TypesInfo.Uses[fun].(*types.Builtin); ok && b.Name() == "panic" {
						exits = true
						return false
					}
				case *ast.SelectorExpr:
					switch fun.Sel.Name {
					case "Fatal", "Fatalf", "Fatalln", "FailNow", "Skip", "Skipf", "SkipNow", "Panic", "Panicf", "Panicln", "Goexit", "Exit":
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
	if len(atomicPtrCandidates) > 0 && len(mutexVars) > 0 {
		validLoadStoreIdents := map[*ast.Ident]bool{}
		selsByVar := map[*types.Var][]*ast.SelectorExpr{}
		storesInFunc := map[*types.Var]map[*ast.FuncDecl]bool{}
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
						if sel, ok := unparenExpr(node.Fun).(*ast.SelectorExpr); ok {
							if ident, ok := unparenExpr(sel.X).(*ast.Ident); ok {
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
											}
											storesInFunc[v][fd] = true
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
						if (n.Op == token.EQL || n.Op == token.NEQ) && (unparenExpr(n.X) == call || unparenExpr(n.Y) == call) {
							allowedCallContext = true
						}
					case *ast.SelectorExpr:
						if unparenExpr(n.X) == call {
							allowedCallContext = true
						}
					case *ast.AssignStmt:
						if len(n.Lhs) == 1 && len(n.Rhs) == 1 && unparenExpr(n.Rhs[0]) == call {
							if id, ok := unparenExpr(n.Lhs[0]).(*ast.Ident); ok {
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
									if id, ok := unparenExpr(side).(*ast.Ident); ok && p.TypesInfo.Uses[id] == boundLocal {
										validIdentUses[id] = true
									}
								}
							}
						case *ast.SelectorExpr:
							if id, ok := unparenExpr(n.X).(*ast.Ident); ok && p.TypesInfo.Uses[id] == boundLocal {
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
			if fd == nil || fd.Body == nil || (fd.Recv == nil && fd.Name != nil && fd.Name.Name == "init") {
				return nil, false
			}
			nonSeq := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.GoStmt:
					nonSeq = true
					return false
				case *ast.CallExpr:
					if sel, ok := unparenExpr(n.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Parallel" && len(n.Args) == 0 {
						nonSeq = true
						return false
					}
				}
				return true
			})
			if nonSeq {
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
						if sel, ok := unparenExpr(call.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Lock" {
							if id, ok := unparenExpr(sel.X).(*ast.Ident); ok {
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
					if sel, ok := unparenExpr(s.Call.Fun).(*ast.SelectorExpr); ok {
						if id, ok := unparenExpr(sel.X).(*ast.Ident); ok {
							if obj := p.TypesInfo.Uses[id]; obj != nil {
								if lockedMu != nil && obj == lockedMu && sel.Sel.Name == "Unlock" && len(s.Call.Args) == 0 {
									if unlockIdx >= 0 || idx <= lockIdx {
										return nil, false
									}
									unlockIdx = idx
									validMutexCalls[s.Call] = true
								} else if obj == v && sel.Sel.Name == "Store" && len(s.Call.Args) == 1 {
									argID, ok := unparenExpr(s.Call.Args[0]).(*ast.Ident)
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
					sel, ok := unparenExpr(call.Fun).(*ast.SelectorExpr)
					if !ok {
						return true
					}
					id, ok := unparenExpr(sel.X).(*ast.Ident)
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
		for v := range atomicPtrCandidates {
			if invalidAtomic[v] || len(storesInFunc[v]) == 0 || !loadResultSafe(v) {
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
			}
		}
	}

	// 2. Lexically bracketed save-and-restore or zero-reset seams on
	// non-alias-handing, non-mutable-reach package variables (and their fields).
	candidateVar := func(obj types.Object) (*types.Var, bool) {
		v, ok := obj.(*types.Var)
		if !ok || v == nil || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() || addrTaken[v] {
			return nil, false
		}
		if TypeHandsOutDynamicAlias(audited, v.Type()) ||
			typeHandsOutMutableReach(v.Type()) {
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
	seamTarget := func(expr ast.Expr) (string, *types.Var, bool) {
		expr = unparenExpr(expr)
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
			return dynamicVarKey(v), v, true
		case *ast.SelectorExpr:
			baseID, ok := unparenExpr(e.X).(*ast.Ident)
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
				TypeHandsOutDynamicAlias(audited, field.Type()) ||
				typeHandsOutMutableReach(field.Type()) {
				return "", nil, false
			}
			return dynamicVarKey(v) + "." + field.Name(), v, true
		default:
			return "", nil, false
		}
	}
	isZeroExpr := func(expr ast.Expr) bool {
		expr = unparenExpr(expr)
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
	}

	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil || (fd.Recv == nil && fd.Name != nil && fd.Name.Name == "init") {
				continue
			}
			nonSequential := false
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
				if nonSequential || n == nil {
					return false
				}
				switch n := n.(type) {
				case *ast.GoStmt:
					nonSequential = true
					return false
				case *ast.CallExpr:
					if sel, ok := unparenExpr(n.Fun).(*ast.SelectorExpr); ok && sel.Sel.Name == "Parallel" && len(n.Args) == 0 {
						nonSequential = true
						return false
					}
				case *ast.AssignStmt:
					for i, lhs := range n.Lhs {
						recordTargetIdents(lhs, localWrites)
						if id, ok := unparenExpr(lhs).(*ast.Ident); ok {
							if obj, ok := resolve(id); ok && i < len(n.Rhs) {
								if lit, ok := unparenExpr(n.Rhs[i]).(*ast.FuncLit); ok {
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
								if lit, ok := unparenExpr(n.Values[i]).(*ast.FuncLit); ok {
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
			if nonSequential {
				continue
			}
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
				case *ast.ReturnStmt:
					for _, res := range n.Results {
						markExprClosures(res)
					}
				case *ast.AssignStmt:
					for i, lhs := range n.Lhs {
						if id, ok := unparenExpr(lhs).(*ast.Ident); ok {
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
							if key == dynamicVarKey(baseVar) {
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

			cleanupClosureBody := func(stmt ast.Stmt, allowCleanupCall bool) *ast.BlockStmt {
				switch s := stmt.(type) {
				case *ast.DeferStmt:
					if lit, ok := unparenExpr(s.Call.Fun).(*ast.FuncLit); ok && len(s.Call.Args) == 0 {
						return lit.Body
					}
					if id, ok := unparenExpr(s.Call.Fun).(*ast.Ident); ok && len(s.Call.Args) == 0 {
						if obj, ok := resolve(id); ok && immutableLocal(obj) && localFuncLits[obj] != nil {
							return localFuncLits[obj].Body
						}
					}
				case *ast.ExprStmt:
					if !allowCleanupCall {
						return nil
					}
					call, ok := s.X.(*ast.CallExpr)
					if !ok || len(call.Args) != 1 {
						return nil
					}
					sel, ok := unparenExpr(call.Fun).(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Cleanup" {
						return nil
					}
					if lit, ok := unparenExpr(call.Args[0]).(*ast.FuncLit); ok {
						return lit.Body
					}
					if id, ok := unparenExpr(call.Args[0]).(*ast.Ident); ok {
						if obj, ok := resolve(id); ok && immutableLocal(obj) && localFuncLits[obj] != nil {
							return localFuncLits[obj].Body
						}
					}
				}
				return nil
			}

			callableBodies := map[*ast.BlockStmt]bool{fd.Body: true}
			var blocks []*ast.BlockStmt
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit:
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
							id, ok := unparenExpr(lhs).(*ast.Ident)
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
						if cbody := cleanupClosureBody(stmt, block == fd.Body); cbody != nil {
							for _, cstmt := range cbody.List {
								assign, ok := cstmt.(*ast.AssignStmt)
								if !ok || len(assign.Lhs) != len(assign.Rhs) {
									continue
								}
								for i, lhs := range assign.Lhs {
									key, baseVar, ok := seamTarget(lhs)
									if !ok || returnedTargets[key] || mixedBaseVar(baseVar) {
										continue
									}
									rhs := unparenExpr(assign.Rhs[i])
									if id, ok := rhs.(*ast.Ident); ok {
										if obj, ok := resolve(id); ok {
											for _, s := range saves[key] {
												if s.localObj == obj && s.idx <= idx {
													deferRestores[key] = append(deferRestores[key], restoreRecord{
														idx:        idx,
														lhs:        lhs,
														cbody:      cbody,
														savedLocal: obj,
													})
													validRestoreLHS[lhs] = true
												}
											}
										}
									}
									if uninitVars[baseVar] && isZeroExpr(rhs) {
										deferRestores[key] = append(deferRestores[key], restoreRecord{
											idx:       idx,
											lhs:       lhs,
											cbody:     cbody,
											zeroReset: true,
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
					cbody := cleanupClosureBody(stmt, block == fd.Body)
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

				for key, restores := range deferRestores {
					if poisonedKeys[key] {
						continue
					}
					consistent := true
					firstR := restores[0]
					for _, r := range restores[1:] {
						if r.zeroReset != firstR.zeroReset || r.savedLocal != firstR.savedLocal {
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
							for _, rAll := range restores {
								exempt[rAll.lhs] = true
							}
							for _, w := range writes {
								exempt[w.lhs] = true
							}
							delete(writesByKey, key)
							break
						}
					}
				}

				for key, writes := range writesByKey {
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
									if id, ok := unparenExpr(assign.Rhs[i]).(*ast.Ident); ok {
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
							exempt[restoreLHS] = true
							for _, w := range writes {
								exempt[w.lhs] = true
							}
							break
						}
					}
				}
			}
		}
	}
	return exempt
}

// recordDynamicGlobalUses classifies every package-level dynamic-capable
// variable use in one package's syntax: mutated collects demonstrated
// mutations (writes, growth/deletion, sends, address captures,
// pointer-receiver method uses, rebindings), escaped collects
// alias-carrier values handed to code that may write them (call
// arguments, stores, returns, bindings, method calls, type
// assertions). Reads that provably cannot write — indexing, iteration,
// length/capacity, comparison — mark neither, and initOnly names the
// init-only-reachable helpers whose bodies are init flow
// (REQ-closure-shared-dynamic-state).
// singleSubject is the engine's caller-attested single-subject-process
// execution model: it arms the audited pooling set's discharge — off,
// every pool use keeps the fail-closed judgment
// (REQ-closure-shared-dynamic-state). poolDischarged, when non-nil,
// collects the pool variable keys whose admitted Get/Put calls the
// attestation discharged, for the subject-evidence audit record
// (REQ-vouch-recorded).
func recordDynamicGlobalUses(
	audited bool,
	p *packages.Package,
	mutated, escaped, initOnly map[string]bool,
	methodUses map[string]map[FuncKey]bool,
	paramUses, initParamUses map[string]map[ParamKey]bool,
	initMethodUses map[string]map[FuncKey]bool,
	fieldUses map[string]map[FieldPosKey]bool,
	elemUses map[string]map[ElemParamUse]bool,
	carrierLinks map[string]map[string]bool,
	attributed *[]AttributedUse,
	singleSubject bool,
	poolDischarged map[string]bool,
	hooks *ExplainHookSet,
) {
	if p == nil || p.TypesInfo == nil {
		return
	}
	dataMemos := dataMemoVars(audited, p)
	exemptSeamNodes := bracketedSeamNodes(audited, p)
	dynamicPackageVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		if !TypeMayCarryUnknownDynamic(audited, variable.Type()) {
			return nil, false
		}
		return variable, true
	}
	resolve := func(ident *ast.Ident) (types.Object, bool) {
		if obj, ok := p.TypesInfo.Uses[ident]; ok {
			return obj, true
		}
		if obj, ok := p.TypesInfo.Defs[ident]; ok && obj != nil {
			return obj, true
		}
		return nil, false
	}
	var aliasedLocals map[types.Object]map[string]bool
	var currentFn *ast.FuncDecl
	var currentAttrFn FuncKey
	var pendingReturns []pendingReturnDisposition
	markTargets := func(expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if obj, ok := resolve(ident); ok {
				if variable, ok := dynamicPackageVar(obj); ok {
					explainMark(hooks, p, "mutation", dynamicVarKey(variable), ident.Pos())
					mutated[dynamicVarKey(variable)] = true
				} else {
					for key := range aliasedLocals[obj] {
						explainMark(hooks, p, "mutation", key, ident.Pos())
						mutated[key] = true
					}
				}
			}
			return true
		})
	}
	initOnlyParams := directCallSites(p).funcParamsOf(initOnly)
	paramSeeds := map[types.Object]map[string]bool{}
	paramLinkSeeds := map[types.Object]map[string]bool{}
	paramSeedGrowth := false
	seedingPass := false
	initAliasedLocals := func(body ast.Node) map[types.Object]map[string]bool {
		aliased := map[types.Object]map[string]bool{}
		for obj, keys := range paramSeeds {
			set := map[string]bool{}
			for key := range keys {
				set[key] = true
			}
			aliased[obj] = set
		}
		linkAliased := map[types.Object]map[string]bool{}
		for obj, keys := range paramLinkSeeds {
			set := map[string]bool{}
			for key := range keys {
				set[key] = true
			}
			linkAliased[obj] = set
		}
		rhsKeys := func(expr ast.Expr) map[string]bool {
			keys := map[string]bool{}
			ast.Inspect(expr, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit:
					return false
				case *ast.Ident:
					if obj, ok := resolve(n); ok {
						if variable, ok := dynamicPackageVar(obj); ok {
							keys[dynamicVarKey(variable)] = true
						} else if source := aliased[obj]; source != nil {
							for key := range source {
								keys[key] = true
							}
						}
					}
				}
				return true
			})
			return keys
		}
		linkKeys := func(expr ast.Expr) map[string]bool {
			keys := map[string]bool{}
			ast.Inspect(expr, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit, *ast.CallExpr:
					return false
				case *ast.Ident:
					if obj, ok := resolve(n); ok {
						if variable, ok := dynamicPackageVar(obj); ok {
							keys[dynamicVarKey(variable)] = true
						} else if source := linkAliased[obj]; source != nil {
							for key := range source {
								keys[key] = true
							}
						}
					}
				}
				return true
			})
			return keys
		}
		storeLink := func(target ast.Expr, lkeys map[string]bool) {
			if len(lkeys) == 0 || carrierLinks == nil || seedingPass {
				return
			}
			base := target
			for {
				switch t := base.(type) {
				case *ast.IndexExpr:
					base = t.X
				case *ast.SelectorExpr:
					base = t.X
				case *ast.StarExpr:
					base = t.X
				case *ast.ParenExpr:
					base = t.X
				default:
					ident, identOK := base.(*ast.Ident)
					if !identOK {
						return
					}
					obj, objOK := resolve(ident)
					if !objOK {
						return
					}
					variable, varOK := dynamicPackageVar(obj)
					if !varOK {
						return
					}
					own := dynamicVarKey(variable)
					for key := range lkeys {
						if key == own {
							continue
						}
						if carrierLinks[own] == nil {
							carrierLinks[own] = map[string]bool{}
						}
						carrierLinks[own][key] = true
					}
					return
				}
			}
		}
		markRHSMethodValues := func(rhs ast.Expr) {
			if seedingPass {
				return
			}
			calledFuns := map[ast.Node]bool{}
			ast.Inspect(rhs, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					calledFuns[unparenExpr(call.Fun)] = true
				}
				return true
			})
			ast.Inspect(rhs, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || calledFuns[sel] {
					return true
				}
				if selection, selOK := p.TypesInfo.Selections[sel]; selOK && selection.Kind() == types.MethodVal {
					ast.Inspect(sel.X, func(inner ast.Node) bool {
						if ident, ok := inner.(*ast.Ident); ok {
							if obj, ok := resolve(ident); ok {
								if variable, ok := dynamicPackageVar(obj); ok {
									explainMark(hooks, p, "escape", dynamicVarKey(variable), ident.Pos())
									escaped[dynamicVarKey(variable)] = true
								} else {
									for key := range aliased[obj] {
										explainMark(hooks, p, "escape", key, ident.Pos())
										escaped[key] = true
									}
								}
							}
						}
						return true
					})
				}
				return true
			})
		}
		bind := func(target ast.Expr, keys, lkeys map[string]bool) bool {
			if len(keys) == 0 {
				return false
			}
			composite := false
		unwrap:
			for {
				switch t := target.(type) {
				case *ast.ParenExpr:
					target = t.X
				case *ast.SelectorExpr:
					target = t.X
					composite = true
				case *ast.IndexExpr:
					target = t.X
					composite = true
				case *ast.StarExpr:
					target = t.X
					composite = true
				default:
					break unwrap
				}
			}
			ident, ok := target.(*ast.Ident)
			if !ok {
				return false
			}
			obj, ok := resolve(ident)
			if !ok {
				return false
			}
			if _, isPkg := obj.(*types.PkgName); isPkg {
				return false
			}
			if variable, pkg := dynamicPackageVar(obj); pkg {
				if carrierLinks != nil && !seedingPass {
					own := dynamicVarKey(variable)
					for key := range lkeys {
						if key == own {
							continue
						}
						if carrierLinks[own] == nil {
							carrierLinks[own] = map[string]bool{}
						}
						carrierLinks[own][key] = true
					}
				}
				return false
			}
			if !composite && !TypeHandsOutDynamicAlias(audited, obj.Type()) {
				return false
			}
			changed := false
			if aliased[obj] == nil {
				aliased[obj] = map[string]bool{}
			}
			for key := range keys {
				if !aliased[obj][key] {
					aliased[obj][key] = true
					changed = true
				}
			}
			if len(lkeys) != 0 {
				if linkAliased[obj] == nil {
					linkAliased[obj] = map[string]bool{}
				}
				for key := range lkeys {
					if !linkAliased[obj][key] {
						linkAliased[obj][key] = true
						changed = true
					}
				}
			}
			return changed
		}
		for changed := true; changed; {
			changed = false
			ast.Inspect(body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncLit, *ast.GoStmt:
					return false
				case *ast.AssignStmt:
					if len(n.Lhs) == len(n.Rhs) {
						for i, rhs := range n.Rhs {
							markRHSMethodValues(rhs)
							lkeys := linkKeys(rhs)
							if bind(n.Lhs[i], rhsKeys(rhs), lkeys) {
								changed = true
							}
							storeLink(n.Lhs[i], lkeys)
						}
					} else if len(n.Rhs) == 1 {
						markRHSMethodValues(n.Rhs[0])
						keys := rhsKeys(n.Rhs[0])
						lkeys := linkKeys(n.Rhs[0])
						for _, lhs := range n.Lhs {
							if bind(lhs, keys, lkeys) {
								changed = true
							}
							storeLink(lhs, lkeys)
						}
					}
				case *ast.ValueSpec:
					if len(n.Names) == len(n.Values) {
						for i, name := range n.Names {
							markRHSMethodValues(n.Values[i])
							if bind(name, rhsKeys(n.Values[i]), linkKeys(n.Values[i])) {
								changed = true
							}
						}
					} else if len(n.Values) == 1 {
						markRHSMethodValues(n.Values[0])
						keys := rhsKeys(n.Values[0])
						lkeys := linkKeys(n.Values[0])
						for _, name := range n.Names {
							if bind(name, keys, lkeys) {
								changed = true
							}
						}
					}
				case *ast.RangeStmt:
					keys := rhsKeys(n.X)
					lkeys := linkKeys(n.X)
					for _, target := range []ast.Expr{n.Key, n.Value} {
						if target != nil && bind(target, keys, lkeys) {
							changed = true
						}
					}
				case *ast.CallExpr:
					if ident, ok := n.Fun.(*ast.Ident); ok && len(n.Args) == 2 {
						if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && ident.Name == "copy" {
							lkeys := linkKeys(n.Args[1])
							if bind(n.Args[0], rhsKeys(n.Args[1]), lkeys) {
								changed = true
							}
							storeLink(n.Args[0], lkeys)
						}
					}
					callee := unwrapCallee(n.Fun)
					if ident, ok := callee.(*ast.Ident); ok {
						if fn, ok := p.TypesInfo.Uses[ident].(*types.Func); ok {
							if params := initOnlyParams[fn]; len(params) != 0 {
								variadic := false
								if sig, ok := fn.Type().(*types.Signature); ok {
									variadic = sig.Variadic()
								}
								for i, arg := range n.Args {
									slot := min(i, len(params)-1)
									param := params[slot]
									if param == nil {
										continue
									}
									gateType := param.Type()
									if variadic && slot == len(params)-1 && n.Ellipsis == token.NoPos {
										if slice, ok := types.Unalias(gateType).(*types.Slice); ok {
											gateType = slice.Elem()
										}
									}
									if !TypeHandsOutDynamicAlias(audited, gateType) {
										continue
									}
									for key := range rhsKeys(arg) {
										if paramSeeds[param] == nil {
											paramSeeds[param] = map[string]bool{}
										}
										if !paramSeeds[param][key] {
											paramSeeds[param][key] = true
											paramSeedGrowth = true
										}
									}
									for key := range linkKeys(arg) {
										if paramLinkSeeds[param] == nil {
											paramLinkSeeds[param] = map[string]bool{}
										}
										if !paramLinkSeeds[param][key] {
											paramLinkSeeds[param][key] = true
											paramSeedGrowth = true
										}
									}
								}
							}
						}
					}
				}
				return true
			})
		}
		return aliased
	}
	carrierArgVar := func(arg ast.Expr) (*ast.Ident, *types.Var) {
		arg = unparenExpr(arg)
		var target *ast.Ident
		switch a := arg.(type) {
		case *ast.Ident:
			target = a
		case *ast.SelectorExpr:
			if x, ok := a.X.(*ast.Ident); ok {
				if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
					target = a.Sel
				}
			}
		}
		if target == nil {
			return nil, nil
		}
		obj, ok := resolve(target)
		if !ok {
			return nil, nil
		}
		variable, ok := dynamicPackageVar(obj)
		if !ok {
			return nil, nil
		}
		if !TypeHandsOutDynamicAlias(audited, variable.Type()) {
			return nil, nil
		}
		return target, variable
	}
	deferCarrierArgs := func(n *ast.CallExpr, sink map[string]map[ParamKey]bool, kind byte, onDeferred func(*ast.Ident)) {
		fn, pkgPath := plainCalleeFunc(p, n.Fun)
		if fn == nil {
			return
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil || sig.Params().Len() == 0 {
			return
		}
		for i, arg := range n.Args {
			target, variable := carrierArgVar(arg)
			if target == nil {
				continue
			}
			idx := i
			if sig.Variadic() && idx >= sig.Params().Len()-1 {
				idx = sig.Params().Len() - 1
			}
			key := dynamicVarKey(variable)
			if sink[key] == nil {
				sink[key] = map[ParamKey]bool{}
			}
			paramKey := ParamKey{Func: FuncKey{Pkg: pkgPath, Name: fn.Name()}, Index: idx}
			sink[key][paramKey] = true
			explainDeferralMark(hooks, p, kind, key, DeferralResolvent{Param: paramKey}, target.Pos())
			if onDeferred != nil {
				onDeferred(target)
			}
		}
	}
	poolCarrierIdent := func(recv ast.Expr) (*ast.Ident, *types.Var) {
		ident, isIdent := recv.(*ast.Ident)
		element := false
		if !isIdent {
			index, isIndex := recv.(*ast.IndexExpr)
			if !isIndex {
				return nil, nil
			}
			ident, isIdent = index.X.(*ast.Ident)
			if !isIdent {
				return nil, nil
			}
			element = true
		}
		obj, ok := resolve(ident)
		if !ok {
			return nil, nil
		}
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, nil
		}
		t := types.Unalias(variable.Type())
		if element {
			switch sequence := t.(type) {
			case *types.Array:
				t = types.Unalias(sequence.Elem())
			case *types.Slice:
				t = types.Unalias(sequence.Elem())
			default:
				return nil, nil
			}
		}
		named, ok := t.(*types.Named)
		if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
			return nil, nil
		}
		if named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Pool" {
			return nil, nil
		}
		return ident, variable
	}
	dischargePool := func(variable *types.Var) {
		if poolDischarged != nil {
			poolDischarged[dynamicVarKey(variable)] = true
		}
	}
	provenCalls := map[*ast.SelectorExpr]bool{}
	if !singleSubject {
		_, provenCalls = provenSharedPools(audited, p)
	}
	markExemptEscapes := func(arg ast.Expr) {
		ast.Inspect(arg, func(inner ast.Node) bool {
			if ident, ok := inner.(*ast.Ident); ok {
				if obj, ok := resolve(ident); ok {
					if variable, ok := dynamicPackageVar(obj); ok {
						if TypeHandsOutDynamicAlias(audited, variable.Type()) {
							explainMark(hooks, p, "escape", dynamicVarKey(variable), ident.Pos())
							escaped[dynamicVarKey(variable)] = true
						}
					} else {
						for key := range aliasedLocals[obj] {
							explainMark(hooks, p, "escape", key, ident.Pos())
							escaped[key] = true
						}
					}
				}
			}
			return true
		})
	}
	scanExemptCalls := func(body ast.Node) {
		if initParamUses == nil || body == nil {
			return
		}
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				return false
			case *ast.CallExpr:
				if ident, ok := n.Fun.(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						switch ident.Name {
						case "len", "cap", "delete", "clear", "append", "copy":
							return true
						}
					}
				}
				plain := false
				if fn, _ := plainCalleeFunc(p, n.Fun); fn != nil {
					plain = true
					deferCarrierArgs(n, initParamUses, 'q', nil)
				} else if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					if selection, selOK := p.TypesInfo.Selections[sel]; selOK && selection.Kind() == types.MethodVal {
						deferred := false
						var poolVar *types.Var
						if fn, fnOK := selection.Obj().(*types.Func); fnOK && (singleSubject || provenCalls[sel]) && AuditedPooling(audited, fn) {
							_, poolVar = poolCarrierIdent(sel.X)
						}
						if poolVar != nil {
							dischargePool(poolVar)
							if index, isIndex := sel.X.(*ast.IndexExpr); isIndex {
								markExemptEscapes(index.Index)
							}
							deferred = true
						} else if fn, fnOK := selection.Obj().(*types.Func); fnOK && !interfaceReceiver(fn) && instantiatedResultsHandOutNothing(audited, selection.Type()) {
							if ident, idOK := sel.X.(*ast.Ident); idOK {
								if obj, rOK := resolve(ident); rOK {
									if variable, vOK := dynamicPackageVar(obj); vOK {
										key := dynamicVarKey(variable)
										if initMethodUses[key] == nil {
											initMethodUses[key] = map[FuncKey]bool{}
										}
										factKey := methodFactKey(fn)
										initMethodUses[key][factKey] = true
										explainDeferralMark(hooks, p, 'n', key, DeferralResolvent{Method: factKey}, sel.Pos())
										deferred = true
									}
								}
							}
						}
						if !deferred {
							markExemptEscapes(sel.X)
						}
					}
				}
				for _, arg := range n.Args {
					if plain {
						if _, variable := carrierArgVar(arg); variable != nil {
							continue
						}
					}
					markExemptEscapes(arg)
				}
			}
			return true
		})
	}
	var skipInteriors map[ast.Node]bool
	walkBody := func(body ast.Node) {
		readContext := map[*ast.Ident]bool{}
		calledSelectors := map[*ast.SelectorExpr]bool{}
		goCalls := map[*ast.CallExpr]bool{}
		markRead := func(expr ast.Expr) {
			switch expr := expr.(type) {
			case *ast.Ident:
				readContext[expr] = true
			case *ast.SelectorExpr:
				readContext[expr.Sel] = true
			}
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if skipInteriors[n] {
				return false
			}
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if exemptSeamNodes[lhs] {
						markRead(lhs)
						if sel, ok := unparenExpr(lhs).(*ast.SelectorExpr); ok {
							markRead(sel.X)
						}
						continue
					}
					markTargets(lhs)
					if index, ok := lhs.(*ast.IndexExpr); ok {
						markRead(index.X)
					}
				}
				if len(n.Lhs) == 2 && len(n.Rhs) == 1 {
					if blank, ok := n.Lhs[0].(*ast.Ident); ok && blank.Name == "_" {
						if index, ok := unparenExpr(n.Rhs[0]).(*ast.IndexExpr); ok {
							markRead(unparenExpr(index.X))
						}
					}
				}
			case *ast.IncDecStmt:
				markTargets(n.X)
			case *ast.RangeStmt:
				if n.Key != nil {
					markTargets(n.Key)
				}
				if n.Value != nil {
					markTargets(n.Value)
				}
				if t := p.TypesInfo.TypeOf(n.X); t != nil {
					if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
						markTargets(n.X)
					} else if !rangeBindsAlias(t) {
						markRead(n.X)
					} else if n.Key == nil && n.Value == nil {
						markRead(n.X)
					} else if n.Tok == token.DEFINE && n.Body != nil {
						roots := map[types.Object]bool{}
						sound := true
						for _, bind := range []ast.Expr{n.Key, n.Value} {
							if bind == nil {
								continue
							}
							ident, ok := bind.(*ast.Ident)
							if !ok {
								sound = false
								break
							}
							if obj := p.TypesInfo.Defs[ident]; obj != nil && typeHandsOutMutableReach(obj.Type()) {
								roots[obj] = true
							}
						}
						var wants map[ParamKey]bool
						var methodWants map[FuncKey]bool
						var fieldWants map[FieldPosKey]bool
						var elemWants map[ElemParamUse]bool
						var returned bool
						var retPtr *bool
						if paramUses != nil {
							wants = map[ParamKey]bool{}
							if methodUses != nil {
								methodWants = map[FuncKey]bool{}
							}
							if fieldUses != nil {
								fieldWants = map[FieldPosKey]bool{}
							}
							if elemUses != nil {
								elemWants = map[ElemParamUse]bool{}
							}
							if currentFn != nil && currentFn.Recv == nil && currentFn.Name != nil && !currentFn.Name.IsExported() && currentFn.Name.Name != "init" {
								retPtr = &returned
							}
						}
						if sound && (len(roots) == 0 || boundValueLeakFreeJudged(audited, p, roots, n.Body, wants, retPtr, methodWants, fieldWants, elemWants)) {
							if len(wants) == 0 && len(methodWants) == 0 && len(fieldWants) == 0 && len(elemWants) == 0 && !returned {
								markRead(n.X)
							} else {
								var keys []string
								ast.Inspect(n.X, func(inner ast.Node) bool {
									if ident, ok := inner.(*ast.Ident); ok {
										if obj, ok := resolve(ident); ok {
											if variable, ok := dynamicPackageVar(obj); ok {
												keys = append(keys, dynamicVarKey(variable))
											} else {
												for key := range aliasedLocals[obj] {
													keys = append(keys, key)
												}
											}
										}
									}
									return true
								})
								if len(keys) > 0 {
									for _, key := range keys {
										if paramUses[key] == nil {
											paramUses[key] = map[ParamKey]bool{}
										}
										for want := range wants {
											paramUses[key][want] = true
											explainDeferralMark(hooks, p, 'p', key, DeferralResolvent{Param: want}, n.X.Pos())
										}
										if len(methodWants) > 0 && methodUses[key] == nil {
											methodUses[key] = map[FuncKey]bool{}
										}
										for want := range methodWants {
											methodUses[key][want] = true
											explainDeferralMark(hooks, p, 'm', key, DeferralResolvent{Method: want}, n.X.Pos())
										}
										if len(fieldWants) > 0 && fieldUses[key] == nil {
											fieldUses[key] = map[FieldPosKey]bool{}
										}
										for want := range fieldWants {
											pos := FieldPosKey{Owner: key, Field: want.Field, Index: want.Index}
											fieldUses[key][pos] = true
											explainDeferralMark(hooks, p, 'f', key, DeferralResolvent{FieldPos: pos}, n.X.Pos())
										}
										if len(elemWants) > 0 && elemUses[key] == nil {
											elemUses[key] = map[ElemParamUse]bool{}
										}
										for want := range elemWants {
											eu := ElemParamUse{Key: key, Owner: want.Owner, Index: want.Index}
											elemUses[key][eu] = true
											explainDeferralMark(hooks, p, 'e', key, DeferralResolvent{ElemUse: eu}, n.X.Pos())
										}
									}
									if returned {
										pendingReturns = append(pendingReturns, pendingReturnDisposition{
											fn:     currentFn.Name.Name,
											keys:   keys,
											attrFn: currentAttrFn,
										})
									}
									markRead(n.X)
								}
							}
						}
					}
				}
			case *ast.SendStmt:
				markTargets(n.Chan)
			case *ast.UnaryExpr:
				if n.Op == token.AND || n.Op == token.ARROW {
					if _, composite := unparenExpr(n.X).(*ast.CompositeLit); !composite || n.Op == token.ARROW {
						markTargets(n.X)
					}
				}
			case *ast.IndexExpr:
				if t := p.TypesInfo.TypeOf(n); t == nil || !typeHandsOutMutableReach(t) {
					markRead(n.X)
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL || n.Op == token.NEQ {
					markRead(n.X)
					markRead(n.Y)
				}
			case *ast.GoStmt:
				ast.Inspect(n, func(inner ast.Node) bool {
					if call, ok := inner.(*ast.CallExpr); ok {
						goCalls[call] = true
					}
					return true
				})
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					calledSelectors[sel] = true
				}
				if ident, ok := n.Fun.(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						switch ident.Name {
						case "len", "cap":
							for _, arg := range n.Args {
								markRead(arg)
							}
						case "delete", "clear":
							if len(n.Args) > 0 {
								markTargets(n.Args[0])
							}
						}
					}
				}
				if paramUses != nil && !goCalls[n] {
					deferCarrierArgs(n, paramUses, 'p', func(target *ast.Ident) {
						readContext[target] = true
					})
				}
				if elemUses != nil && !goCalls[n] {
					if index, ok := unparenExpr(n.Fun).(*ast.IndexExpr); ok {
						if base, ok := unparenExpr(index.X).(*ast.Ident); ok {
							if obj, ok := resolve(base); ok {
								if owner, ok := dynamicPackageVar(obj); ok {
									if sig, ok := types.Unalias(p.TypesInfo.TypeOf(n.Fun)).Underlying().(*types.Signature); ok {
										ownerKey := dynamicVarKey(owner)
										for i, arg := range n.Args {
											ident, ok := unparenExpr(arg).(*ast.Ident)
											if !ok {
												continue
											}
											aobj, ok := resolve(ident)
											if !ok {
												continue
											}
											variable, ok := dynamicPackageVar(aobj)
											if !ok || !TypeHandsOutDynamicAlias(audited, variable.Type()) {
												continue
											}
											idx := i
											if sig.Variadic() && idx >= sig.Params().Len()-1 {
												idx = sig.Params().Len() - 1
											}
											argKey := dynamicVarKey(variable)
											want := ElemParamUse{Key: argKey, Owner: ownerKey, Index: idx}
											if elemUses[argKey] == nil {
												elemUses[argKey] = map[ElemParamUse]bool{}
											}
											elemUses[argKey][want] = true
											explainDeferralMark(hooks, p, 'e', argKey, DeferralResolvent{ElemUse: want}, arg.Pos())
											readContext[ident] = true
										}
									}
								}
							}
						}
					}
				}
			case *ast.SelectorExpr:
				if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
					if fn, ok := selection.Obj().(*types.Func); ok {
						if (singleSubject || provenCalls[n]) && calledSelectors[n] && AuditedPooling(audited, fn) {
							if ident, variable := poolCarrierIdent(n.X); variable != nil {
								dischargePool(variable)
								readContext[ident] = true
								return true
							}
						}
						if calledSelectors[n] && dataMemoMethod(audited, fn) {
							if ident, ok := n.X.(*ast.Ident); ok {
								if obj, ok := resolve(ident); ok {
									if variable, ok := obj.(*types.Var); ok && dataMemos[variable] {
										readContext[ident] = true
										return true
									}
								}
							}
						}
						if calledSelectors[n] && exemptSeamNodes[n] {
							if ident, ok := unparenExpr(n.X).(*ast.Ident); ok {
								readContext[ident] = true
							}
							return true
						}
						if methodUses != nil && calledSelectors[n] && !interfaceReceiver(fn) && instantiatedResultsHandOutNothing(audited, selection.Type()) {
							if ident, ok := n.X.(*ast.Ident); ok {
								if obj, ok := resolve(ident); ok {
									if variable, ok := dynamicPackageVar(obj); ok {
										key := dynamicVarKey(variable)
										if methodUses[key] == nil {
											methodUses[key] = map[FuncKey]bool{}
										}
										factKey := methodFactKey(fn)
										methodUses[key][factKey] = true
										explainDeferralMark(hooks, p, 'm', key, DeferralResolvent{Method: factKey}, n.Pos())
										readContext[ident] = true
										return true
									}
								}
							}
						}
						if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
							if _, pointer := types.Unalias(sig.Recv().Type()).(*types.Pointer); pointer {
								markTargets(n.X)
							}
						}
					}
				}
			case *ast.Ident:
				if readContext[n] {
					return true
				}
				if obj, ok := resolve(n); ok {
					if variable, ok := dynamicPackageVar(obj); ok && TypeHandsOutDynamicAlias(audited, variable.Type()) {
						explainMark(hooks, p, "escape", dynamicVarKey(variable), n.Pos())
						escaped[dynamicVarKey(variable)] = true
					} else {
						for key := range aliasedLocals[obj] {
							explainMark(hooks, p, "escape", key, n.Pos())
							escaped[key] = true
						}
					}
				}
			}
			return true
		})
	}
	if len(initOnlyParams) != 0 {
		seedingPass = true
		for {
			paramSeedGrowth = false
			for _, file := range p.Syntax {
				for _, decl := range file.Decls {
					switch decl := decl.(type) {
					case *ast.FuncDecl:
						if decl.Recv == nil && decl.Name != nil && decl.Body != nil && (decl.Name.Name == "init" || initOnly[decl.Name.Name]) {
							initAliasedLocals(decl.Body)
						}
					case *ast.GenDecl:
						initAliasedLocals(decl)
					}
				}
			}
			if !paramSeedGrowth {
				break
			}
		}
		seedingPass = false
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				var methodKey FuncKey
				if decl.Recv != nil && decl.Name != nil && attributed != nil && decl.Body != nil && p.Types != nil {
					if fn, ok := p.TypesInfo.Defs[decl.Name].(*types.Func); ok && fn != nil {
						if key := methodFactKey(fn); key.Pkg != "" && !strings.HasPrefix(key.Name, ".") {
							methodKey = key
						}
					}
				}
				if methodKey.Valid() {
					fnKey := methodKey
					litMutated, litEscaped := map[string]bool{}, map[string]bool{}
					litMethods := map[string]map[FuncKey]bool{}
					interiors := map[ast.Node]bool{}
					saveLM, saveLE, saveLMU := mutated, escaped, methodUses
					mutated, escaped, methodUses = litMutated, litEscaped, litMethods
					ast.Inspect(decl.Body, func(n ast.Node) bool {
						switch n := n.(type) {
						case *ast.FuncLit:
							if n.Body != nil {
								walkBody(n.Body)
								interiors[n] = true
							}
							return false
						case *ast.GoStmt:
							walkBody(n)
							interiors[n] = true
							return false
						}
						return true
					})
					mutated, escaped, methodUses = saveLM, saveLE, saveLMU
					for key := range litMutated {
						*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key, Literal: true})
					}
					for key := range litEscaped {
						*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key, Escape: true, Literal: true})
					}
					for key, methods := range litMethods {
						for method := range methods {
							*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: method, Literal: true})
						}
					}
					localMutated, localEscaped := map[string]bool{}, map[string]bool{}
					localMethods := map[string]map[FuncKey]bool{}
					saveM, saveE, saveMU := mutated, escaped, methodUses
					mutated, escaped, methodUses = localMutated, localEscaped, localMethods
					skipInteriors = interiors
					walkBody(decl.Body)
					skipInteriors = nil
					mutated, escaped, methodUses = saveM, saveE, saveMU
					for key := range localMutated {
						*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key})
					}
					for key := range localEscaped {
						*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key, Escape: true})
					}
					for key, methods := range localMethods {
						for method := range methods {
							*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: method})
						}
					}
					continue
				}
				if decl.Recv == nil && decl.Name != nil && attributed != nil && !initOnly[decl.Name.Name] && decl.Name.Name != "init" && decl.Body != nil {
					var fnKey FuncKey
					if p.Types != nil {
						fnKey = FuncKey{Pkg: p.Types.Path(), Name: decl.Name.Name}
					}
					litMutated, litEscaped := map[string]bool{}, map[string]bool{}
					litMethods := map[string]map[FuncKey]bool{}
					interiors := map[ast.Node]bool{}
					saveLM, saveLE, saveLMU := mutated, escaped, methodUses
					mutated, escaped, methodUses = litMutated, litEscaped, litMethods
					ast.Inspect(decl.Body, func(n ast.Node) bool {
						switch n := n.(type) {
						case *ast.FuncLit:
							if n.Body != nil {
								walkBody(n.Body)
								interiors[n] = true
							}
							return false
						case *ast.GoStmt:
							walkBody(n)
							interiors[n] = true
							return false
						}
						return true
					})
					mutated, escaped, methodUses = saveLM, saveLE, saveLMU
					if fnKey.Valid() {
						for key := range litMutated {
							*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key, Literal: true})
						}
						for key := range litEscaped {
							*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key, Escape: true, Literal: true})
						}
						for key, methods := range litMethods {
							for method := range methods {
								*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: method, Literal: true})
							}
						}
					} else {
						for key := range litMutated {
							mutated[key] = true
						}
						for key := range litEscaped {
							escaped[key] = true
						}
						for key, methods := range litMethods {
							for method := range methods {
								if methodUses[key] == nil {
									methodUses[key] = map[FuncKey]bool{}
								}
								methodUses[key][method] = true
							}
						}
					}
					localMutated, localEscaped := map[string]bool{}, map[string]bool{}
					localMethods := map[string]map[FuncKey]bool{}
					saveM, saveE, saveMU := mutated, escaped, methodUses
					mutated, escaped, methodUses = localMutated, localEscaped, localMethods
					skipInteriors = interiors
					currentFn, currentAttrFn = decl, fnKey
					walkBody(decl.Body)
					currentFn, currentAttrFn = nil, FuncKey{}
					skipInteriors = nil
					mutated, escaped, methodUses = saveM, saveE, saveMU
					for key := range localMutated {
						*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key})
					}
					for key := range localEscaped {
						*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key, Escape: true})
					}
					for key, methods := range localMethods {
						for method := range methods {
							*attributed = append(*attributed, AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: method})
						}
					}
					continue
				}
				if decl.Recv == nil && decl.Name != nil && initOnly[decl.Name.Name] {
					if decl.Body != nil {
						aliasedLocals = initAliasedLocals(decl.Body)
						ast.Inspect(decl.Body, func(n ast.Node) bool {
							switch n := n.(type) {
							case *ast.FuncLit:
								if n.Body != nil {
									walkBody(n.Body)
								}
								return false
							case *ast.GoStmt:
								walkBody(n)
								return false
							}
							return true
						})
						scanExemptCalls(decl.Body)
						aliasedLocals = nil
					}
					continue
				}
				if decl.Recv == nil && decl.Name != nil && decl.Name.Name == "init" {
					if decl.Body != nil {
						aliasedLocals = initAliasedLocals(decl.Body)
						ast.Inspect(decl.Body, func(n ast.Node) bool {
							switch n := n.(type) {
							case *ast.FuncLit:
								if n.Body != nil {
									walkBody(n.Body)
								}
								return false
							case *ast.GoStmt:
								walkBody(n)
								return false
							}
							return true
						})
						scanExemptCalls(decl.Body)
						aliasedLocals = nil
					}
					continue
				}
				if decl.Body != nil {
					currentFn = decl
					walkBody(decl.Body)
					currentFn = nil
				}
			default:
				aliasedLocals = initAliasedLocals(decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					if lit, ok := n.(*ast.FuncLit); ok && lit.Body != nil {
						walkBody(lit.Body)
						return false
					}
					return true
				})
				scanExemptCalls(decl)
				aliasedLocals = nil
			}
		}
	}
	if len(pendingReturns) > 0 {
		returnerKeys := map[string]map[string]bool{}
		mergeKeys := func(fn string, keys map[string]bool) bool {
			if returnerKeys[fn] == nil {
				returnerKeys[fn] = map[string]bool{}
			}
			changed := false
			for key := range keys {
				if !returnerKeys[fn][key] {
					returnerKeys[fn][key] = true
					changed = true
				}
			}
			return changed
		}
		for _, pending := range pendingReturns {
			set := map[string]bool{}
			for _, key := range pending.keys {
				set[key] = true
			}
			mergeKeys(pending.fn, set)
		}
		bad := map[string]bool{}
		deps := map[string]map[string]bool{}
		scanned := map[string]bool{}
		for {
			var frontier []string
			for fn := range returnerKeys {
				if !scanned[fn] {
					frontier = append(frontier, fn)
					scanned[fn] = true
				}
			}
			if len(frontier) == 0 {
				break
			}
			returnerObjs := map[types.Object]string{}
			for _, file := range p.Syntax {
				for _, decl := range file.Decls {
					if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name != nil {
						if _, tracked := returnerKeys[fd.Name.Name]; tracked {
							if obj := p.TypesInfo.Defs[fd.Name]; obj != nil {
								returnerObjs[obj] = fd.Name.Name
							}
						}
					}
				}
			}
			frontierSet := map[string]bool{}
			for _, fn := range frontier {
				frontierSet[fn] = true
			}
			depend := func(from, to string) {
				if deps[from] == nil {
					deps[from] = map[string]bool{}
				}
				deps[from][to] = true
			}
			scanSites := func(body ast.Node, siteName string, siteEligible bool) {
				var stack []ast.Node
				ast.Inspect(body, func(n ast.Node) bool {
					if n == nil {
						stack = stack[:len(stack)-1]
						return true
					}
					defer func() { stack = append(stack, n) }()
					ident, ok := n.(*ast.Ident)
					if !ok {
						return true
					}
					obj := p.TypesInfo.Uses[ident]
					if obj == nil {
						return true
					}
					fnName, tracked := returnerObjs[obj]
					if !tracked || !frontierSet[fnName] {
						return true
					}
					if len(stack) == 0 {
						bad[fnName] = true
						return true
					}
					call, ok := stack[len(stack)-1].(*ast.CallExpr)
					if !ok || call.Fun != ast.Expr(ident) {
						bad[fnName] = true
						return true
					}
					var grand ast.Node
					if len(stack) >= 2 {
						grand = stack[len(stack)-2]
					}
					fnObj, isFunc := obj.(*types.Func)
					if !isFunc {
						bad[fnName] = true
						return true
					}
					sig, ok := fnObj.Type().(*types.Signature)
					if !ok {
						bad[fnName] = true
						return true
					}
					var targets []ast.Expr
					switch g := grand.(type) {
					case *ast.ExprStmt, *ast.GoStmt, *ast.DeferStmt:
						return true
					case *ast.ReturnStmt:
						inLit := false
						for _, frame := range stack {
							if _, isLit := frame.(*ast.FuncLit); isLit {
								inLit = true
								break
							}
						}
						if siteEligible && !inLit {
							if mergeKeys(siteName, returnerKeys[fnName]) {
								scanned[siteName] = false
							}
							depend(fnName, siteName)
						} else {
							bad[fnName] = true
						}
						return true
					case *ast.AssignStmt:
						if len(g.Rhs) != 1 || g.Rhs[0] != ast.Expr(call) {
							bad[fnName] = true
							return true
						}
						targets = g.Lhs
					case *ast.ValueSpec:
						if len(g.Values) != 1 || g.Values[0] != ast.Expr(call) {
							bad[fnName] = true
							return true
						}
						for _, name := range g.Names {
							targets = append(targets, name)
						}
					default:
						bad[fnName] = true
						return true
					}
					results := sig.Results()
					if results.Len() != len(targets) {
						bad[fnName] = true
						return true
					}
					roots := map[types.Object]bool{}
					for i, target := range targets {
						tIdent, ok := target.(*ast.Ident)
						if !ok {
							bad[fnName] = true
							return true
						}
						if !typeHandsOutMutableReach(results.At(i).Type()) {
							continue
						}
						if tObj := p.TypesInfo.Defs[tIdent]; tObj != nil {
							roots[tObj] = true
						} else if tObj := p.TypesInfo.Uses[tIdent]; tObj != nil {
							roots[tObj] = true
						}
					}
					if len(roots) == 0 {
						return true
					}
					siteWants := map[ParamKey]bool{}
					var siteMethodWants map[FuncKey]bool
					var siteFieldWants map[FieldPosKey]bool
					var siteElemWants map[ElemParamUse]bool
					if methodUses != nil {
						siteMethodWants = map[FuncKey]bool{}
					}
					if fieldUses != nil {
						siteFieldWants = map[FieldPosKey]bool{}
					}
					if elemUses != nil {
						siteElemWants = map[ElemParamUse]bool{}
					}
					var siteReturned bool
					var siteRet *bool
					if siteEligible {
						siteRet = &siteReturned
					}
					if !boundValueLeakFreeJudged(audited, p, roots, body, siteWants, siteRet, siteMethodWants, siteFieldWants, siteElemWants) {
						bad[fnName] = true
						return true
					}
					for want := range siteWants {
						for key := range returnerKeys[fnName] {
							if paramUses[key] == nil {
								paramUses[key] = map[ParamKey]bool{}
							}
							paramUses[key][want] = true
							explainDeferralMark(hooks, p, 'p', key, DeferralResolvent{Param: want}, call.Pos())
						}
					}
					for want := range siteMethodWants {
						for key := range returnerKeys[fnName] {
							if methodUses[key] == nil {
								methodUses[key] = map[FuncKey]bool{}
							}
							methodUses[key][want] = true
							explainDeferralMark(hooks, p, 'm', key, DeferralResolvent{Method: want}, call.Pos())
						}
					}
					for want := range siteFieldWants {
						for key := range returnerKeys[fnName] {
							if fieldUses[key] == nil {
								fieldUses[key] = map[FieldPosKey]bool{}
							}
							pos := FieldPosKey{Owner: key, Field: want.Field, Index: want.Index}
							fieldUses[key][pos] = true
							explainDeferralMark(hooks, p, 'f', key, DeferralResolvent{FieldPos: pos}, call.Pos())
						}
					}
					for want := range siteElemWants {
						for key := range returnerKeys[fnName] {
							if elemUses[key] == nil {
								elemUses[key] = map[ElemParamUse]bool{}
							}
							eu := ElemParamUse{Key: key, Owner: want.Owner, Index: want.Index}
							elemUses[key][eu] = true
							explainDeferralMark(hooks, p, 'e', key, DeferralResolvent{ElemUse: eu}, call.Pos())
						}
					}
					if siteReturned {
						if mergeKeys(siteName, returnerKeys[fnName]) {
							scanned[siteName] = false
						}
						depend(fnName, siteName)
					}
					return true
				})
			}
			for _, file := range p.Syntax {
				for _, decl := range file.Decls {
					switch decl := decl.(type) {
					case *ast.FuncDecl:
						if decl.Body == nil {
							continue
						}
						name := ""
						if decl.Name != nil {
							name = decl.Name.Name
						}
						eligible := decl.Recv == nil && decl.Name != nil && !decl.Name.IsExported() && name != "init"
						scanSites(decl.Body, name, eligible)
					case *ast.GenDecl:
						for _, spec := range decl.Specs {
							vs, ok := spec.(*ast.ValueSpec)
							if !ok {
								continue
							}
							for _, value := range vs.Values {
								ast.Inspect(value, func(n ast.Node) bool {
									if lit, ok := n.(*ast.FuncLit); ok {
										if lit.Body != nil {
											scanSites(lit.Body, "", false)
										}
										return false
									}
									if ident, ok := n.(*ast.Ident); ok {
										if obj := p.TypesInfo.Uses[ident]; obj != nil {
											if fnName, tracked := returnerObjs[obj]; tracked && frontierSet[fnName] {
												contained := false
												if call, isCall := value.(*ast.CallExpr); isCall && call.Fun == ast.Expr(ident) {
													if fnObj, isFunc := obj.(*types.Func); isFunc {
														if sig, isSig := fnObj.Type().(*types.Signature); isSig && sig.Results().Len() == len(vs.Names) {
															contained = true
															for i, nameIdent := range vs.Names {
																if nameIdent.Name != "_" && typeHandsOutMutableReach(sig.Results().At(i).Type()) {
																	contained = false
																	break
																}
															}
														}
													}
												}
												if !contained {
													bad[fnName] = true
												}
											}
										}
									}
									return true
								})
							}
						}
					}
				}
			}
		}
		solveReachFixedPoint(bad, deps, func(d string) bool { return bad[d] })
		type restoredKey struct {
			fn  FuncKey
			key string
		}
		restored := map[restoredKey]bool{}
		for _, pending := range pendingReturns {
			if !bad[pending.fn] {
				continue
			}
			for _, key := range pending.keys {
				if pending.attrFn.Valid() {
					rk := restoredKey{fn: pending.attrFn, key: key}
					if !restored[rk] {
						restored[rk] = true
						*attributed = append(*attributed, AttributedUse{Func: pending.attrFn, Key: key, Escape: true})
					}
				} else {
					explainMark(hooks, p, "escape", key, token.NoPos)
					escaped[key] = true
				}
			}
		}
	}
}

// environmentFreeFuncLit reports whether a function literal registered into
// a carrier is provably environment-free: every variable it references from
// an enclosing function scope proves leak-free under the use-shape engine.
func environmentFreeFuncLit(audited bool, p *packages.Package, lit *ast.FuncLit, enclosing ast.Node) bool {
	return environmentFreeFuncLitJudged(audited, p, lit, enclosing, nil, nil)
}

// environmentFreeFuncLitJudged additionally collects parameter and
// method wants when the caller supplies sinks, instead of refusing the
// deferrable shapes outright.
func environmentFreeFuncLitJudged(audited bool, p *packages.Package, lit *ast.FuncLit, enclosing ast.Node, wants map[ParamKey]bool, methodWants map[FuncKey]bool) bool {
	if p == nil || p.TypesInfo == nil || lit == nil || lit.Body == nil {
		return false
	}
	freeVars := func(body ast.Node, bound ast.Node) map[types.Object]bool {
		roots := map[types.Object]bool{}
		ast.Inspect(body, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			obj, ok := p.TypesInfo.Uses[ident]
			if !ok {
				return true
			}
			v, ok := obj.(*types.Var)
			if !ok || v.IsField() || v.Pkg() == nil {
				return true
			}
			if v.Parent() == v.Pkg().Scope() {
				return true
			}
			if v.Pos() >= bound.Pos() && v.Pos() <= bound.End() {
				return true
			}
			roots[v] = true
			return true
		})
		return roots
	}
	roots := freeVars(lit.Body, lit)
	if len(roots) == 0 {
		return true
	}
	if enclosing != nil {
		var edges [][2]types.Object
		aliasEdges := func(target ast.Expr, sources ast.Expr) {
			target = unparenExpr(target)
			ident, ok := target.(*ast.Ident)
			if !ok {
				return
			}
			obj := identDefOrUse(p.TypesInfo, ident)
			v, ok := obj.(*types.Var)
			if !ok || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() {
				return
			}
			if !typeHandsOutMutableReach(v.Type()) {
				return
			}
			ast.Inspect(sources, func(n ast.Node) bool {
				if src, ok := n.(*ast.Ident); ok {
					if o, ok := p.TypesInfo.Uses[src].(*types.Var); ok && o.Pkg() != nil && o.Parent() != o.Pkg().Scope() && !o.IsField() {
						if typeHandsOutMutableReach(o.Type()) {
							edges = append(edges, [2]types.Object{v, o})
						}
					}
				}
				return true
			})
		}
		ast.Inspect(enclosing, func(n ast.Node) bool {
			eachLocalBinding(p.TypesInfo, n, aliasEdges)
			return true
		})
		for changed := true; changed; {
			changed = false
			for _, e := range edges {
				if roots[e[0]] != roots[e[1]] {
					roots[e[0]], roots[e[1]] = true, true
					changed = true
				}
			}
		}
	}
	if !boundValueLeakFreeJudged(audited, p, roots, lit.Body, wants, nil, methodWants, nil, nil) {
		return false
	}
	if enclosing == nil {
		return true
	}
	sound := true
	ast.Inspect(enclosing, func(n ast.Node) bool {
		if !sound {
			return false
		}
		switch n := n.(type) {
		case *ast.FuncLit:
			if n == lit {
				return false
			}
			shared := false
			for v := range freeVars(n.Body, n) {
				if roots[v] {
					shared = true
					break
				}
			}
			if shared && !boundValueLeakFreeJudged(audited, p, roots, n.Body, wants, nil, methodWants, nil, nil) {
				sound = false
			}
			return false
		case *ast.GoStmt:
			ast.Inspect(n.Call, func(inner ast.Node) bool {
				if _, isLit := inner.(*ast.FuncLit); isLit {
					return false
				}
				if ident, ok := inner.(*ast.Ident); ok {
					if obj, ok := p.TypesInfo.Uses[ident]; ok && roots[obj] {
						sound = false
					}
				}
				return sound
			})
		}
		return sound
	})
	return sound
}

// fieldRegMark is one registered-population disposition for a
// func-signature struct field a carrier can hand out: class 'd' defers the
// field position to a parameter's leak-free fact, class 'p' poisons it. A
// poison with field "" covers the whole population, idx -1 every index.
type fieldRegMark struct {
	class byte
	field string
	idx   int
	param ParamKey
}

// classifyFieldRegistrants derives the registered-population marks of one
// admitted registration store.
func classifyFieldRegistrants(audited bool, p *packages.Package, lhs, rhs ast.Expr, emit func(fieldRegMark)) {
	if sel, ok := unparenExpr(lhs).(*ast.SelectorExpr); ok {
		if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.FieldVal {
			if _, isSig := types.Unalias(selection.Type()).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantValue(audited, p, sel.Sel.Name, rhs, emit)
				return
			}
		}
	}
	classifyRegistrantFlow(audited, p, rhs, emit)
}

func classifyRegistrantFlow(audited bool, p *packages.Package, expr ast.Expr, emit func(fieldRegMark)) {
	switch e := unparenExpr(expr).(type) {
	case *ast.CompositeLit:
		classifyRegistrantComposite(audited, p, e, emit)
		return
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			classifyRegistrantFlow(audited, p, e.X, emit)
			return
		}
	case *ast.FuncLit:
		classifyLiteralRegistrant(audited, p, ElemPositionField, e, emit)
		return
	case *ast.BasicLit:
		return
	case *ast.CallExpr:
		if ident, ok := unparenExpr(e.Fun).(*ast.Ident); ok {
			if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "make" || ident.Name == "new") {
				return
			}
		}
		for _, arg := range e.Args {
			classifyRegistrantFlow(audited, p, arg, emit)
		}
		return
	case *ast.Ident:
		if obj, ok := identUseOrDef(p, e); ok {
			switch obj.(type) {
			case *types.Func:
				classifyFieldRegistrantValue(audited, p, ElemPositionField, e, emit)
				return
			case *types.Nil:
				return
			}
		}
	case *ast.SelectorExpr:
		if obj, ok := p.TypesInfo.Uses[e.Sel]; ok {
			if _, isFunc := obj.(*types.Func); isFunc {
				classifyFieldRegistrantValue(audited, p, ElemPositionField, e, emit)
				return
			}
		}
	case *ast.IndexExpr, *ast.IndexListExpr:
		if fn, _ := plainCalleeFunc(p, e); fn != nil {
			classifyFieldRegistrantValue(audited, p, ElemPositionField, e, emit)
			return
		}
	}
	if typeCarriesSignature(p.TypesInfo.TypeOf(unparenExpr(expr))) {
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

func identUseOrDef(p *packages.Package, ident *ast.Ident) (types.Object, bool) {
	if obj, ok := p.TypesInfo.Uses[ident]; ok {
		return obj, true
	}
	if obj, ok := p.TypesInfo.Defs[ident]; ok && obj != nil {
		return obj, true
	}
	return nil, false
}

func classifyRegistrantComposite(audited bool, p *packages.Package, lit *ast.CompositeLit, emit func(fieldRegMark)) {
	t := p.TypesInfo.TypeOf(lit)
	if t == nil {
		emit(fieldRegMark{class: 'p', idx: -1})
		return
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Struct:
		for i, elt := range lit.Elts {
			var field *types.Var
			value := elt
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				value = kv.Value
				if key, ok := kv.Key.(*ast.Ident); ok {
					for j := 0; j < u.NumFields(); j++ {
						if u.Field(j).Name() == key.Name {
							field = u.Field(j)
							break
						}
					}
				}
			} else if i < u.NumFields() {
				field = u.Field(i)
			}
			if field == nil {
				emit(fieldRegMark{class: 'p', idx: -1})
				continue
			}
			if _, isSig := types.Unalias(field.Type()).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantValue(audited, p, field.Name(), value, emit)
				continue
			}
			classifyRegistrantFlow(audited, p, value, emit)
		}
	case *types.Map, *types.Slice, *types.Array:
		eachCompositeLitValue(lit, func(value ast.Expr) bool {
			classifyRegistrantFlow(audited, p, value, emit)
			return true
		})
	default:
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

func classifyFieldRegistrantValue(audited bool, p *packages.Package, field string, value ast.Expr, emit func(fieldRegMark)) {
	deferNamed := func(fn *types.Func) bool {
		if fn == nil || fn.Pkg() == nil {
			return false
		}
		fn = fn.Origin()
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil {
			return false
		}
		fk := FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}
		for idx := 0; idx < sig.Params().Len(); idx++ {
			emit(fieldRegMark{class: 'd', field: field, idx: idx, param: ParamKey{Func: fk, Index: idx}})
		}
		return true
	}
	switch v := unparenExpr(value).(type) {
	case *ast.FuncLit:
		classifyLiteralRegistrant(audited, p, field, v, emit)
		return
	case *ast.Ident:
		if obj, ok := identUseOrDef(p, v); ok {
			if _, isNil := obj.(*types.Nil); isNil {
				return
			}
			if fn, ok := obj.(*types.Func); ok && deferNamed(fn) {
				return
			}
		}
	case *ast.SelectorExpr:
		if _, isSelection := p.TypesInfo.Selections[v]; !isSelection {
			if x, ok := v.X.(*ast.Ident); ok {
				if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
					if fn, ok := p.TypesInfo.Uses[v.Sel].(*types.Func); ok && deferNamed(fn) {
						return
					}
				}
			}
		}
	case *ast.IndexExpr, *ast.IndexListExpr:
		if fn, _ := plainCalleeFunc(p, v); fn != nil && deferNamed(fn) {
			return
		}
	}
	emit(fieldRegMark{class: 'p', field: field, idx: -1})
}

func classifyLiteralRegistrant(audited bool, p *packages.Package, field string, lit *ast.FuncLit, emit func(fieldRegMark)) {
	if lit.Type == nil || lit.Body == nil {
		emit(fieldRegMark{class: 'p', field: field, idx: -1})
		return
	}
	idx := 0
	if lit.Type.Params != nil {
		for _, group := range lit.Type.Params.List {
			names := group.Names
			if len(names) == 0 {
				idx++
				continue
			}
			for _, name := range names {
				if name.Name == "_" {
					idx++
					continue
				}
				obj := p.TypesInfo.Defs[name]
				if obj == nil {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
					idx++
					continue
				}
				wants := map[ParamKey]bool{}
				if boundValueLeakFreeJudged(audited, p, map[types.Object]bool{obj: true}, lit.Body, wants, nil, nil, nil, nil) {
					for want := range wants {
						emit(fieldRegMark{class: 'd', field: field, idx: idx, param: want})
					}
				} else {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
				}
				idx++
			}
		}
	}
}

// recordEnvCarryingRegistrations records, per dynamic-capable package
// variable (own or foreign), whether this package's direct code stores a
// function-carrying value into it that is not provably environment-free.
func recordEnvCarryingRegistrations(
	audited bool,
	p *packages.Package,
	envCarrying map[string]bool,
	envCalls map[string]map[FuncKey]bool,
	fieldDefer map[FieldPosKey]map[ParamKey]bool,
	fieldPoison map[string]map[FieldParamPoison]bool,
	hooks *ExplainHookSet,
) {
	if p == nil || p.TypesInfo == nil {
		return
	}
	exemptSeamNodes := bracketedSeamNodes(audited, p)
	resolve := func(ident *ast.Ident) (types.Object, bool) {
		if obj, ok := p.TypesInfo.Uses[ident]; ok {
			return obj, true
		}
		if obj, ok := p.TypesInfo.Defs[ident]; ok && obj != nil {
			return obj, true
		}
		return nil, false
	}
	carrierVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		if !TypeMayCarryUnknownDynamic(audited, variable.Type()) {
			return nil, false
		}
		return variable, true
	}
	var localAliases map[types.Object][]*types.Var
	collectCarrierVars := func(expr ast.Expr, aliases map[types.Object][]*types.Var, skipFuncLit bool) []*types.Var {
		var vars []*types.Var
		ast.Inspect(expr, func(n ast.Node) bool {
			if skipFuncLit {
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
			}
			if ident, ok := n.(*ast.Ident); ok {
				if obj, ok := resolve(ident); ok {
					if variable, ok := carrierVar(obj); ok {
						vars = append(vars, variable)
					} else {
						vars = append(vars, aliases[obj]...)
					}
				}
			}
			return true
		})
		return vars
	}
	targetVars := func(expr ast.Expr) []*types.Var {
		return collectCarrierVars(expr, localAliases, false)
	}
	computeLocalAliases := func(body ast.Node) map[types.Object][]*types.Var {
		aliased := map[types.Object][]*types.Var{}
		sourceVars := func(expr ast.Expr) []*types.Var {
			return collectCarrierVars(expr, aliased, true)
		}
		bind := func(target ast.Expr, sources []*types.Var) bool {
			if len(sources) == 0 {
				return false
			}
			ident, ok := unparenExpr(target).(*ast.Ident)
			if !ok {
				return false
			}
			obj, ok := resolve(ident)
			if !ok {
				return false
			}
			if _, pkg := carrierVar(obj); pkg {
				return false
			}
			if !TypeHandsOutDynamicAlias(audited, obj.Type()) {
				return false
			}
			have := map[*types.Var]bool{}
			for _, v := range aliased[obj] {
				have[v] = true
			}
			changed := false
			for _, v := range sources {
				if !have[v] {
					aliased[obj] = append(aliased[obj], v)
					have[v] = true
					changed = true
				}
			}
			return changed
		}
		for changed := true; changed; {
			changed = false
			ast.Inspect(body, func(n ast.Node) bool {
				switch n.(type) {
				case *ast.FuncLit, *ast.GoStmt:
					return false
				}
				eachLocalBinding(p.TypesInfo, n, func(lhs, rhs ast.Expr) {
					if bind(lhs, sourceVars(rhs)) {
						changed = true
					}
				})
				return true
			})
		}
		return aliased
	}
	var enclosingBody ast.Node
	var pendingEnvCalls map[FuncKey]bool
	var carrying func(expr ast.Expr) bool
	carrying = func(expr ast.Expr) bool {
		switch e := unparenExpr(expr).(type) {
		case *ast.CompositeLit:
			return !eachCompositeLitValue(e, func(value ast.Expr) bool {
				return !carrying(value)
			})
		case *ast.UnaryExpr:
			if e.Op == token.AND {
				return carrying(e.X)
			}
		case *ast.FuncLit:
			return !environmentFreeFuncLit(audited, p, e, enclosingBody)
		case *ast.BasicLit:
			return false
		case *ast.CallExpr:
			if ident, ok := unparenExpr(e.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "make" || ident.Name == "new") {
					return false
				}
			}
			if pendingEnvCalls != nil && typeCarriesSignature(p.TypesInfo.TypeOf(unparenExpr(expr))) {
				if fn, pkgPath := plainCalleeFunc(p, e.Fun); fn != nil {
					for _, arg := range e.Args {
						if carrying(arg) {
							return true
						}
					}
					pendingEnvCalls[FuncKey{Pkg: pkgPath, Name: fn.Name()}] = true
					return false
				}
			}
		case *ast.Ident:
			if obj, ok := resolve(e); ok {
				switch obj.(type) {
				case *types.Func:
					return false
				case *types.Nil:
					return false
				}
			}
		case *ast.SelectorExpr:
			if selection, ok := p.TypesInfo.Selections[e]; ok {
				switch selection.Kind() {
				case types.MethodExpr:
					return false
				case types.MethodVal:
					return true
				}
				break
			}
			if obj, ok := p.TypesInfo.Uses[e.Sel]; ok {
				if _, isFunc := obj.(*types.Func); isFunc {
					return false
				}
			}
		case *ast.IndexExpr, *ast.IndexListExpr:
			if fn, _ := plainCalleeFunc(p, e); fn != nil {
				return false
			}
		}
		return typeCarriesSignature(p.TypesInfo.TypeOf(unparenExpr(expr)))
	}
	handleStore := func(lhs, rhs ast.Expr, rebindable bool) {
		if rebindable {
			if ident, ok := unparenExpr(lhs).(*ast.Ident); ok {
				if obj, ok := resolve(ident); ok {
					if _, isCarrier := carrierVar(obj); !isCarrier {
						return
					}
				}
			}
		}
		targets := targetVars(lhs)
		if len(targets) == 0 {
			return
		}
		flows := []ast.Expr{rhs}
		if call, ok := unparenExpr(rhs).(*ast.CallExpr); ok && len(call.Args) > 0 {
			if ident, ok := unparenExpr(call.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && ident.Name == "append" {
					var baseIdent *ast.Ident
					switch base := unparenExpr(call.Args[0]).(type) {
					case *ast.Ident:
						baseIdent = base
					case *ast.SelectorExpr:
						if x, ok := base.X.(*ast.Ident); ok {
							if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
								baseIdent = base.Sel
							}
						}
					}
					if baseIdent != nil {
						if obj, ok := resolve(baseIdent); ok {
							if variable, ok := carrierVar(obj); ok && len(targets) == 1 && variable == targets[0] {
								flows = call.Args[1:]
							}
						}
					}
				}
			}
		}
		poison := false
		pendingEnvCalls = map[FuncKey]bool{}
		var poisonAt token.Pos
		for _, flow := range flows {
			if carrying(flow) {
				poison = true
				poisonAt = flow.Pos()
				break
			}
		}
		if poison {
			for _, variable := range targets {
				explainStoreMark(hooks, p, dynamicVarKey(variable), poisonAt)
				envCarrying[dynamicVarKey(variable)] = true
			}
		} else if envCalls != nil {
			for callee := range pendingEnvCalls {
				for _, variable := range targets {
					key := dynamicVarKey(variable)
					if envCalls[key] == nil {
						envCalls[key] = map[FuncKey]bool{}
					}
					envCalls[key][callee] = true
				}
			}
			if fieldDefer != nil {
				var marks []fieldRegMark
				for _, flow := range flows {
					classifyFieldRegistrants(audited, p, lhs, flow, func(m fieldRegMark) {
						marks = append(marks, m)
					})
				}
				for _, variable := range targets {
					key := dynamicVarKey(variable)
					for _, m := range marks {
						switch m.class {
						case 'd':
							pos := FieldPosKey{Owner: key, Field: m.field, Index: m.idx}
							if fieldDefer[pos] == nil {
								fieldDefer[pos] = map[ParamKey]bool{}
							}
							fieldDefer[pos][m.param] = true
						case 'p':
							if fieldPoison[key] == nil {
								fieldPoison[key] = map[FieldParamPoison]bool{}
							}
							if m.field == "" {
								fieldPoison[key][FieldParamPoison{Owner: key}] = true
							} else {
								fieldPoison[key][FieldParamPoison{Owner: key, HasPos: true, Field: m.field, Index: m.idx}] = true
							}
						}
					}
				}
			}
		}
		pendingEnvCalls = nil
	}
	walkStores := func(body ast.Node) {
		localAliases = computeLocalAliases(body)
		defer func() { localAliases = nil }()
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit, *ast.GoStmt:
				return false
			case *ast.CallExpr:
				if ident, ok := unparenExpr(n.Fun).(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
						switch {
						case ident.Name == "copy" && len(n.Args) == 2:
							handleStore(n.Args[0], n.Args[1], false)
						case ident.Name == "append" && len(n.Args) > 1:
							for _, flow := range n.Args[1:] {
								handleStore(n.Args[0], flow, false)
							}
						}
					}
				}
			case *ast.AssignStmt:
				if len(n.Lhs) == len(n.Rhs) {
					for i, lhs := range n.Lhs {
						if exemptSeamNodes[lhs] {
							continue
						}
						handleStore(lhs, n.Rhs[i], true)
					}
				} else if len(n.Rhs) == 1 {
					for _, lhs := range n.Lhs {
						if exemptSeamNodes[lhs] {
							continue
						}
						handleStore(lhs, n.Rhs[0], true)
					}
				}
			case *ast.RangeStmt:
				for _, bind := range []ast.Expr{n.Key, n.Value} {
					if bind != nil && n.Tok == token.ASSIGN {
						handleStore(bind, n.X, true)
					}
				}
			case *ast.SendStmt:
				handleStore(n.Chan, n.Value, false)
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Body != nil {
					enclosingBody = decl.Body
					walkStores(decl.Body)
					enclosingBody = nil
				}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					if len(vs.Names) == len(vs.Values) {
						for i, name := range vs.Names {
							handleStore(name, vs.Values[i], true)
						}
					} else if len(vs.Values) == 1 {
						for _, name := range vs.Names {
							handleStore(name, vs.Values[0], true)
						}
					}
				}
			}
		}
	}
}

// auditedValuePlane names the standard value-plane helpers whose
// results carry exactly their arguments' values - clone and
// concatenation shapes with no environment of their own. A closed
// set: absence keeps the refusal.
var auditedValuePlane = map[FuncKey]bool{
	{Pkg: "slices", Name: "Clone"}:  true,
	{Pkg: "slices", Name: "Concat"}: true,
	{Pkg: "maps", Name: "Clone"}:    true,
}

// returnEnvFreeFunctions proves, per plain named function of the
// package, that every value its return expressions can carry into a
// carrier is environment-free provided the call's arguments are - the
// constructor-result admission of the environment-free registration
// audit.
func returnEnvFreeFunctions(
	audited bool,
	p *packages.Package,
	paramLeakFree map[ParamKey]bool,
	readOnly map[string]bool,
	hooks *ExplainHookSet,
) (
	map[string]bool,
	map[string]map[FuncKey]bool,
	map[string]map[ReturnFieldParamDefer]bool,
	map[string]map[ReturnFieldParamPoison]bool,
	map[ParamKey]bool,
	map[ParamKey]map[EnvAuditTarget]bool,
	map[string]map[EnvAuditTarget]bool,
) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil, nil, nil, nil, nil, nil, nil
	}
	ownPath := p.Types.Path()
	carries := func(t types.Type) bool {
		return typeCarriesSignature(t)
	}
	unparen := unparenExpr
	wantsResolve := func(wants map[ParamKey]bool, methodWants map[FuncKey]bool) bool {
		for want := range wants {
			if want.Func.Pkg != ownPath || !paramLeakFree[want] {
				return false
			}
		}
		for want := range methodWants {
			if want.Pkg != ownPath || !readOnly[want.Name] {
				return false
			}
		}
		return true
	}
	proven := map[string]bool{}
	deps := map[string]map[FuncKey]bool{}
	retDefer := map[string]map[ReturnFieldParamDefer]bool{}
	retPoison := map[string]map[ReturnFieldParamPoison]bool{}
	insFree := map[ParamKey]bool{}
	insDeps := map[ParamKey]map[EnvAuditTarget]bool{}
	callerInsDeps := map[string]map[EnvAuditTarget]bool{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Name.Name == "init" {
				continue
			}
			fnKey := fd.Name.Name
			ownFuncKey := FuncKey{Pkg: ownPath, Name: fnKey}
			params := map[types.Object]bool{}
			paramIndex := map[types.Object]int{}
			paramCount := 0
			if fd.Type.Params != nil {
				for _, field := range fd.Type.Params.List {
					if len(field.Names) == 0 {
						insFree[ParamKey{Func: ownFuncKey, Index: paramCount}] = true
						paramCount++
						continue
					}
					for _, name := range field.Names {
						if obj := p.TypesInfo.Defs[name]; obj != nil && name.Name != "_" {
							params[obj] = true
							paramIndex[obj] = paramCount
						} else {
							insFree[ParamKey{Func: ownFuncKey, Index: paramCount}] = true
						}
						paramCount++
					}
				}
			}
			localSources := map[types.Object][]ast.Expr{}
			writeSources := map[types.Object][]ast.Expr{}
			insertionWrites := map[types.Object][]ast.Expr{}
			localBroken := map[types.Object]bool{}
			captureBroken := map[types.Object]bool{}
			var aliasPairs [][2]types.Object
			var heldPairs [][2]types.Object
			stmtCallDeps := map[FuncKey]bool{}
			trackedVar := func(obj types.Object) (*types.Var, bool) {
				v, ok := obj.(*types.Var)
				if !ok || v.Pkg() == nil || v.Parent() == v.Pkg().Scope() || !carries(v.Type()) {
					return nil, false
				}
				return v, true
			}
			breakIdents := func(expr ast.Expr, capture bool, gate func(types.Object) bool) {
				ast.Inspect(expr, func(n ast.Node) bool {
					if ident, ok := n.(*ast.Ident); ok {
						obj := p.TypesInfo.Uses[ident]
						if obj == nil {
							obj = p.TypesInfo.Defs[ident]
						}
						if obj != nil {
							if _, ok := trackedVar(obj); (ok || params[obj]) && (gate == nil || gate(obj)) {
								localBroken[obj] = true
								if capture {
									captureBroken[obj] = true
								}
							}
						}
					}
					return true
				})
			}
			breakTargets := func(expr ast.Expr) {
				breakIdents(expr, true, nil)
			}
			chainRoot := func(target ast.Expr) ast.Expr {
				base := unparen(target)
				for {
					switch b := base.(type) {
					case *ast.SelectorExpr:
						base = unparen(b.X)
					case *ast.IndexExpr:
						base = unparen(b.X)
					case *ast.SliceExpr:
						base = unparen(b.X)
					case *ast.StarExpr:
						base = unparen(b.X)
					default:
						return base
					}
				}
			}
			breakBase := func(target ast.Expr) {
				breakTargets(chainRoot(target))
			}
			sharesHeader := func(t types.Type) bool {
				if t == nil {
					return true
				}
				switch types.Unalias(t).Underlying().(type) {
				case *types.Struct, *types.Array, *types.Basic:
					return false
				}
				return true
			}
			pairLink := func(obj, sobj types.Object, shares bool) {
				if v, ok := sobj.(*types.Var); ok && v.IsField() {
					return
				}
				_, tracked := trackedVar(sobj)
				if !tracked || !typeHandsOutMutableReach(sobj.Type()) {
					return
				}
				if shares {
					aliasPairs = append(aliasPairs, [2]types.Object{obj, sobj})
				} else {
					heldPairs = append(heldPairs, [2]types.Object{obj, sobj})
				}
			}
			var linkBacking func(obj types.Object, source ast.Expr)
			linkValue := func(obj types.Object, e ast.Expr, shares bool) {
				if ident, ok := chainRoot(e).(*ast.Ident); ok {
					sobj := p.TypesInfo.Uses[ident]
					if sobj == nil {
						sobj = p.TypesInfo.Defs[ident]
					}
					if sobj != nil {
						pairLink(obj, sobj, shares)
						return
					}
				}
				ast.Inspect(e, func(m ast.Node) bool {
					if id, ok := m.(*ast.Ident); ok {
						if sobj := p.TypesInfo.Uses[id]; sobj != nil {
							pairLink(obj, sobj, true)
						}
					}
					return true
				})
			}
			linkBacking = func(obj types.Object, source ast.Expr) {
				e := unparen(source)
				switch v := e.(type) {
				case *ast.Ident, *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr, *ast.SliceExpr:
					linkValue(obj, e, sharesHeader(p.TypesInfo.TypeOf(e)))
				case *ast.CompositeLit:
					eachCompositeLitValue(v, func(value ast.Expr) bool {
						linkBacking(obj, value)
						return true
					})
				case *ast.UnaryExpr:
					if v.Op == token.AND {
						linkBacking(obj, v.X)
						return
					}
					linkValue(obj, e, true)
				case *ast.CallExpr:
					if fnIdent, ok := unparen(v.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin {
							switch fnIdent.Name {
							case "make", "new":
								return
							case "append":
								if len(v.Args) > 0 {
									linkValue(obj, v.Args[0], true)
									for _, arg := range v.Args[1:] {
										linkBacking(obj, arg)
									}
								}
								return
							}
						}
					}
					if tv, ok := p.TypesInfo.Types[v.Fun]; ok && tv.IsType() && len(v.Args) == 1 {
						linkBacking(obj, v.Args[0])
						return
					}
					ast.Inspect(v.Fun, func(m ast.Node) bool {
						if id, ok := m.(*ast.Ident); ok {
							if sobj := p.TypesInfo.Uses[id]; sobj != nil {
								pairLink(obj, sobj, true)
							}
						}
						return true
					})
					for _, arg := range v.Args {
						linkBacking(obj, arg)
					}
				case *ast.BasicLit, *ast.FuncLit:
				default:
					linkValue(obj, e, true)
				}
			}
			type pendingStore struct {
				robj   types.Object
				root   *ast.Ident
				target ast.Expr
				source ast.Expr
			}
			var pendingStores []pendingStore
			type insertionUse struct {
				root        types.Object
				calleeParam ParamKey
				args        []ast.Expr
			}
			var pendingInsertionUses []insertionUse
			bindLocal := func(target ast.Expr, source ast.Expr, broken bool) {
				ident, ok := unparen(target).(*ast.Ident)
				if !ok {
					if source != nil && !broken {
						if rootIdent, ok := chainRoot(target).(*ast.Ident); ok {
							robj := p.TypesInfo.Uses[rootIdent]
							if robj == nil {
								robj = p.TypesInfo.Defs[rootIdent]
							}
							if robj != nil {
								if _, tracked := trackedVar(robj); tracked {
									pendingStores = append(pendingStores, pendingStore{robj, rootIdent, target, source})
									return
								}
							}
						}
					}
					breakBase(target)
					return
				}
				obj := p.TypesInfo.Defs[ident]
				if obj == nil {
					obj = p.TypesInfo.Uses[ident]
				}
				if obj != nil && params[obj] {
					localBroken[obj] = true
					return
				}
				if _, ok := trackedVar(obj); !ok {
					return
				}
				if broken || source == nil {
					localBroken[obj] = true
					return
				}
				if call, ok := unparen(source).(*ast.CallExpr); ok {
					if fnIdent, ok := unparen(call.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin && fnIdent.Name == "append" && len(call.Args) > 0 {
							if base, ok := unparen(call.Args[0]).(*ast.Ident); ok {
								if p.TypesInfo.Uses[base] == obj {
									linkBacking(obj, source)
									localSources[obj] = append(localSources[obj], call.Args[1:]...)
									return
								}
							}
						}
					}
				}
				linkBacking(obj, source)
				localSources[obj] = append(localSources[obj], source)
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.UnaryExpr:
					if n.Op == token.AND {
						switch root := chainRoot(n.X).(type) {
						case *ast.Ident:
							breakTargets(root)
						case *ast.CallExpr:
							breakTargets(n.X)
						}
					}
				case *ast.AssignStmt:
					if len(n.Lhs) == len(n.Rhs) {
						for i, lhs := range n.Lhs {
							bindLocal(lhs, n.Rhs[i], false)
						}
					} else if len(n.Rhs) == 1 {
						for _, lhs := range n.Lhs {
							bindLocal(lhs, n.Rhs[0], false)
						}
					} else {
						for _, lhs := range n.Lhs {
							bindLocal(lhs, nil, true)
						}
					}
				case *ast.ValueSpec:
					if len(n.Names) == len(n.Values) {
						for i, name := range n.Names {
							bindLocal(name, n.Values[i], false)
						}
					} else if len(n.Values) == 1 {
						for _, name := range n.Names {
							bindLocal(name, n.Values[0], false)
						}
					}
				case *ast.RangeStmt:
					container := false
					if t := p.TypesInfo.TypeOf(n.X); t != nil {
						switch u := types.Unalias(t).Underlying().(type) {
						case *types.Slice, *types.Array, *types.Map, *types.Basic:
							container = true
						case *types.Pointer:
							_, isArr := types.Unalias(u.Elem()).Underlying().(*types.Array)
							container = isArr
						}
					}
					for _, bind := range []ast.Expr{n.Key, n.Value} {
						if bind != nil {
							if container {
								bindLocal(bind, n.X, false)
							} else {
								bindLocal(bind, nil, true)
							}
						}
					}
				case *ast.SelectorExpr:
					if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
						if fn, ok := selection.Obj().(*types.Func); ok {
							if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
								_, ptr := types.Unalias(sig.Recv().Type()).(*types.Pointer)
								if ptr || sharesHeader(sig.Recv().Type()) || typeHandsOutMutableReach(sig.Recv().Type()) {
									mk := methodFactKey(fn)
									if mk.Pkg != ownPath || !readOnly[mk.Name] {
										breakBase(n.X)
									}
								}
							}
						}
					}
				case *ast.CallExpr:
					if ident, ok := unparen(n.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
							if ident.Name == "copy" && len(n.Args) == 2 {
								bindLocal(n.Args[0], nil, true)
							}
							return true
						}
					}
					if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
						return true
					}
					if fn, pkgPath := plainCalleeFunc(p, n.Fun); fn != nil {
						calleeFK := FuncKey{Pkg: pkgPath, Name: fn.Name()}
						if !auditedValuePlane[calleeFK] {
							reaches := typeCarriesSignature(p.TypesInfo.TypeOf(n))
							for _, arg := range n.Args {
								ast.Inspect(arg, func(inner ast.Node) bool {
									if ident, ok := inner.(*ast.Ident); ok {
										obj := p.TypesInfo.Uses[ident]
										if obj == nil {
											obj = p.TypesInfo.Defs[ident]
										}
										if obj != nil {
											if _, ok := trackedVar(obj); ok || params[obj] {
												reaches = true
											}
										}
									}
									return !reaches
								})
								if reaches {
									break
								}
							}
							if reaches {
								stmtCallDeps[calleeFK] = true
							}
							sig, _ := fn.Type().(*types.Signature)
							breakReachIn := func(e ast.Expr) {
								breakIdents(e, true, func(obj types.Object) bool {
									return typeHandsOutMutableReach(obj.Type())
								})
							}
							var classifyLit func(lit *ast.CompositeLit)
							classifyLit = func(lit *ast.CompositeLit) {
								eachCompositeLitValue(lit, func(value ast.Expr) bool {
									value = unparen(value)
									if t := p.TypesInfo.TypeOf(value); t != nil && !typeHandsOutMutableReach(t) {
										return true
									}
									switch v := value.(type) {
									case *ast.CompositeLit:
										classifyLit(v)
									case *ast.UnaryExpr:
										if v.Op == token.AND {
											if inner, ok := unparen(v.X).(*ast.CompositeLit); ok {
												classifyLit(inner)
												return true
											}
										}
										breakReachIn(value)
									case *ast.BasicLit, *ast.FuncLit:
									default:
										breakReachIn(value)
									}
									return true
								})
							}
							elemReach := func(t types.Type) bool {
								if t == nil {
									return true
								}
								switch u := types.Unalias(t).Underlying().(type) {
								case *types.Slice:
									return typeHandsOutMutableReach(u.Elem())
								case *types.Array:
									return typeHandsOutMutableReach(u.Elem())
								case *types.Map:
									return typeHandsOutMutableReach(u.Key()) || typeHandsOutMutableReach(u.Elem())
								}
								return true
							}
							var classifyArg func(e ast.Expr, calleeParam ParamKey, callArgs []ast.Expr)
							classifyArg = func(e ast.Expr, calleeParam ParamKey, callArgs []ast.Expr) {
								e = unparen(e)
								if t := p.TypesInfo.TypeOf(e); t != nil && !typeHandsOutMutableReach(t) {
									return
								}
								switch v := e.(type) {
								case *ast.Ident, *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr, *ast.SliceExpr:
									if ident, ok := chainRoot(e).(*ast.Ident); ok {
										obj := p.TypesInfo.Uses[ident]
										if obj == nil {
											obj = p.TypesInfo.Defs[ident]
										}
										if obj != nil {
											_, tracked := trackedVar(obj)
											if (tracked || params[obj]) && typeHandsOutMutableReach(obj.Type()) {
												pendingInsertionUses = append(pendingInsertionUses, insertionUse{root: obj, calleeParam: calleeParam, args: callArgs})
											}
										}
										return
									}
									breakReachIn(e)
								case *ast.CompositeLit:
									classifyLit(v)
								case *ast.UnaryExpr:
									if v.Op == token.AND {
										if lit, ok := unparen(v.X).(*ast.CompositeLit); ok {
											classifyLit(lit)
											return
										}
										return
									}
									breakReachIn(e)
								case *ast.BasicLit, *ast.FuncLit:
								case *ast.CallExpr:
									if fnIdent, ok := unparen(v.Fun).(*ast.Ident); ok {
										if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin {
											switch fnIdent.Name {
											case "make", "new":
												return
											case "append":
												for ai, a := range v.Args {
													if ai == len(v.Args)-1 && v.Ellipsis.IsValid() {
														if t := p.TypesInfo.TypeOf(a); t != nil {
															if sl, ok := types.Unalias(t).Underlying().(*types.Slice); ok && !typeHandsOutMutableReach(sl.Elem()) {
																continue
															}
														}
													}
													classifyArg(a, calleeParam, callArgs)
												}
												return
											}
											breakReachIn(e)
											return
										}
									}
									if tv, ok := p.TypesInfo.Types[v.Fun]; ok && tv.IsType() && len(v.Args) == 1 {
										classifyArg(v.Args[0], calleeParam, callArgs)
										return
									}
									if inner, innerPkg := plainCalleeFunc(p, v.Fun); inner != nil && auditedValuePlane[FuncKey{Pkg: innerPkg, Name: inner.Name()}] {
										if !elemReach(p.TypesInfo.TypeOf(e)) {
											return
										}
									}
									breakReachIn(e)
								default:
									breakReachIn(e)
								}
							}
							for j, arg := range n.Args {
								idx := j
								if sig != nil && sig.Variadic() && sig.Params().Len() > 0 && idx >= sig.Params().Len()-1 {
									idx = sig.Params().Len() - 1
								}
								classifyArg(arg, ParamKey{Func: calleeFK, Index: idx}, n.Args)
							}
						}
						return true
					}
					for _, arg := range n.Args {
						breakTargets(arg)
					}
					if sel, ok := unparen(n.Fun).(*ast.SelectorExpr); !ok || func() bool {
						selection, ok := p.TypesInfo.Selections[sel]
						return !ok || selection.Kind() != types.MethodVal
					}() {
						breakTargets(n.Fun)
					}
				}
				return true
			})
			freshObj := map[types.Object]bool{}
			var srcFresh func(e ast.Expr) bool
			srcFresh = func(e ast.Expr) bool {
				e = unparen(e)
				switch v := e.(type) {
				case *ast.CompositeLit:
					return true
				case *ast.UnaryExpr:
					return v.Op == token.AND && srcFresh(v.X)
				case *ast.CallExpr:
					if fnIdent, ok := unparen(v.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[fnIdent].(*types.Builtin); builtin {
							switch fnIdent.Name {
							case "make", "new":
								return true
							case "append":
								return len(v.Args) > 0 && srcFresh(v.Args[0])
							}
							return false
						}
					}
					if tv, ok := p.TypesInfo.Types[v.Fun]; ok && tv.IsType() && len(v.Args) == 1 {
						return srcFresh(v.Args[0])
					}
					return false
				case *ast.Ident, *ast.IndexExpr, *ast.SliceExpr, *ast.StarExpr, *ast.SelectorExpr:
					if ident, ok := chainRoot(e).(*ast.Ident); ok {
						obj := p.TypesInfo.Uses[ident]
						if obj == nil {
							obj = p.TypesInfo.Defs[ident]
						}
						return obj != nil && freshObj[obj]
					}
				}
				return false
			}
			for changed := true; changed; {
				changed = false
				for obj, srcs := range localSources {
					if freshObj[obj] || len(srcs) == 0 {
						continue
					}
					all := true
					for _, s := range srcs {
						if !srcFresh(s) {
							all = false
							break
						}
					}
					if all {
						freshObj[obj] = true
						changed = true
					}
				}
			}
			deepWrite := func(target ast.Expr, fresh bool) bool {
				var steps []ast.Expr
				e := unparen(target)
			flatten:
				for {
					switch s := e.(type) {
					case *ast.SelectorExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					case *ast.IndexExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					case *ast.SliceExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					case *ast.StarExpr:
						steps = append(steps, s)
						e = unparen(s.X)
					default:
						break flatten
					}
				}
				selectorSeen := false
				for i := len(steps) - 1; i >= 0; i-- {
					atRoot := i == len(steps)-1
					final := i == 0
					switch st := steps[i].(type) {
					case *ast.StarExpr:
						if !atRoot || !fresh {
							return true
						}
					case *ast.SelectorExpr:
						if t := p.TypesInfo.TypeOf(st.X); t != nil {
							if _, ptr := types.Unalias(t).Underlying().(*types.Pointer); ptr {
								if !atRoot || !fresh {
									return true
								}
							}
						}
						selectorSeen = true
					case *ast.IndexExpr:
						if !final || !fresh || selectorSeen {
							return true
						}
					case *ast.SliceExpr:
						if !fresh || selectorSeen {
							return true
						}
					}
				}
				return false
			}
			for _, ps := range pendingStores {
				if deepWrite(ps.target, freshObj[ps.robj]) {
					breakIdents(ps.root, false, nil)
					insertionWrites[ps.robj] = append(insertionWrites[ps.robj], ps.source)
					linkBacking(ps.robj, ps.source)
					continue
				}
				writeSources[ps.robj] = append(writeSources[ps.robj], ps.source)
				linkBacking(ps.robj, ps.source)
			}
			for changed := true; changed; {
				changed = false
				for _, pairs := range [][][2]types.Object{aliasPairs, heldPairs} {
					for _, pair := range pairs {
						if localBroken[pair[0]] != localBroken[pair[1]] {
							localBroken[pair[0]], localBroken[pair[1]] = true, true
							changed = true
						}
						if captureBroken[pair[0]] != captureBroken[pair[1]] {
							captureBroken[pair[0]], captureBroken[pair[1]] = true, true
							changed = true
						}
					}
				}
			}
			aliasRoot := map[types.Object]types.Object{}
			var aliasFind func(types.Object) types.Object
			aliasFind = func(x types.Object) types.Object {
				r, ok := aliasRoot[x]
				if !ok || r == x {
					return x
				}
				root := aliasFind(r)
				aliasRoot[x] = root
				return root
			}
			for _, pair := range aliasPairs {
				a, b := aliasFind(pair[0]), aliasFind(pair[1])
				if a != b {
					aliasRoot[a] = b
				}
			}
			sharedWrites := map[types.Object][]ast.Expr{}
			for obj, stores := range writeSources {
				root := aliasFind(obj)
				sharedWrites[root] = append(sharedWrites[root], stores...)
			}
			sharedInsertionWrites := map[types.Object][]ast.Expr{}
			for obj, stores := range insertionWrites {
				root := aliasFind(obj)
				sharedInsertionWrites[root] = append(sharedInsertionWrites[root], stores...)
			}
			resolvedUses := map[types.Object]map[EnvAuditTarget]bool{}
			usePoison := map[types.Object]bool{}
			componentMembers := map[types.Object][]types.Object{}
			memberSeen := map[types.Object]bool{}
			collectMember := func(o types.Object) {
				if !memberSeen[o] {
					memberSeen[o] = true
					componentMembers[aliasFind(o)] = append(componentMembers[aliasFind(o)], o)
				}
			}
			for _, pair := range aliasPairs {
				collectMember(pair[0])
				collectMember(pair[1])
			}
			for obj := range writeSources {
				collectMember(obj)
			}
			for obj := range params {
				collectMember(obj)
			}
			for root, ms := range componentMembers {
				if len(sharedWrites[root]) == 0 {
					continue
				}
				hasParam := false
				for _, m := range ms {
					if params[m] {
						hasParam = true
						break
					}
				}
				if hasParam {
					for _, m := range ms {
						localBroken[m] = true
					}
				}
			}
			fnDeps := map[FuncKey]bool{}
			for callee := range stmtCallDeps {
				fnDeps[callee] = true
			}
			insCallDeps := map[EnvAuditTarget]bool{}
			useFold := &insCallDeps
			recordFnDep := func(callee FuncKey) {
				fnDeps[callee] = true
			}
			var free func(expr ast.Expr) bool
			localFree := map[types.Object]int{} // 0 unknown, 1 proving, 2 free, 3 refused
			var judgeLocal func(obj types.Object) bool
			judgeLocal = func(obj types.Object) bool {
				if usePoison[aliasFind(obj)] {
					localFree[obj] = 3
					return false
				}
				for use := range resolvedUses[aliasFind(obj)] {
					(*useFold)[use] = true
				}
				switch localFree[obj] {
				case 2:
					return true
				case 3:
					return false
				case 1:
					return true
				}
				if localBroken[obj] {
					localFree[obj] = 3
					return false
				}
				localFree[obj] = 1
				for _, src := range localSources[obj] {
					if !free(src) {
						localFree[obj] = 3
						return false
					}
				}
				for _, stored := range sharedWrites[aliasFind(obj)] {
					if !free(stored) {
						localFree[obj] = 3
						return false
					}
				}
				localFree[obj] = 2
				return true
			}
			free = func(expr ast.Expr) bool {
				e := unparen(expr)
				if t := p.TypesInfo.TypeOf(e); t != nil && !carries(t) {
					return true
				}
				switch e := e.(type) {
				case *ast.BasicLit:
					return true
				case *ast.CompositeLit:
					return eachCompositeLitValue(e, free)
				case *ast.UnaryExpr:
					if e.Op == token.AND {
						return free(e.X)
					}
				case *ast.FuncLit:
					wants := map[ParamKey]bool{}
					methodWants := map[FuncKey]bool{}
					if !environmentFreeFuncLitJudged(audited, p, e, fd.Body, wants, methodWants) {
						return false
					}
					return wantsResolve(wants, methodWants)
				case *ast.Ident:
					obj := p.TypesInfo.Uses[e]
					switch obj := obj.(type) {
					case *types.Func:
						return true
					case *types.Nil:
						return true
					case *types.Var:
						if params[obj] {
							if localBroken[obj] {
								return false
							}
							if usePoison[aliasFind(obj)] {
								return false
							}
							for use := range resolvedUses[aliasFind(obj)] {
								(*useFold)[use] = true
							}
							return true
						}
						if obj.Parent() != nil && obj.Pkg() != nil && obj.Parent() != obj.Pkg().Scope() && !obj.IsField() {
							return judgeLocal(obj)
						}
					}
					return false
				case *ast.SelectorExpr:
					if selection, ok := p.TypesInfo.Selections[e]; ok {
						switch selection.Kind() {
						case types.MethodExpr:
							return true
						case types.MethodVal:
							return false
						}
						return free(e.X)
					}
					if obj, ok := p.TypesInfo.Uses[e.Sel]; ok {
						if _, isFunc := obj.(*types.Func); isFunc {
							return true
						}
					}
					return false
				case *ast.IndexExpr:
					switch x := unparen(e.X).(type) {
					case *ast.Ident:
						if _, isFunc := p.TypesInfo.Uses[x].(*types.Func); isFunc {
							return true
						}
					case *ast.SelectorExpr:
						if _, isFunc := p.TypesInfo.Uses[x.Sel].(*types.Func); isFunc {
							return true
						}
					}
					if t := p.TypesInfo.TypeOf(e.X); t != nil {
						switch u := types.Unalias(t).Underlying().(type) {
						case *types.Map, *types.Slice, *types.Array, *types.Basic:
							return free(e.X)
						case *types.Pointer:
							if _, isArr := types.Unalias(u.Elem()).Underlying().(*types.Array); isArr {
								return free(e.X)
							}
						}
					}
					return false
				case *ast.IndexListExpr:
					switch x := unparen(e.X).(type) {
					case *ast.Ident:
						if _, isFunc := p.TypesInfo.Uses[x].(*types.Func); isFunc {
							return true
						}
					case *ast.SelectorExpr:
						if _, isFunc := p.TypesInfo.Uses[x.Sel].(*types.Func); isFunc {
							return true
						}
					}
					return false
				case *ast.CallExpr:
					if ident, ok := unparen(e.Fun).(*ast.Ident); ok {
						if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
							switch ident.Name {
							case "make", "new":
								return true
							case "append":
								for _, arg := range e.Args {
									if !free(arg) {
										return false
									}
								}
								return true
							}
							return false
						}
					}
					if tv, ok := p.TypesInfo.Types[e.Fun]; ok && tv.IsType() {
						return len(e.Args) == 1 && free(e.Args[0])
					}
					if fn, pkgPath := plainCalleeFunc(p, e.Fun); fn != nil {
						for _, arg := range e.Args {
							if !free(arg) {
								return false
							}
						}
						calleeFK := FuncKey{Pkg: pkgPath, Name: fn.Name()}
						if auditedValuePlane[calleeFK] {
							return true
						}
						recordFnDep(calleeFK)
						return true
					}
					return false
				}
				return false
			}
			resolveUses := func(record bool) bool {
				changed := false
				for _, use := range pendingInsertionUses {
					root := aliasFind(use.root)
					if usePoison[root] {
						continue
					}
					allFree := true
					for _, a := range use.args {
						if !free(a) {
							allFree = false
							break
						}
					}
					if !allFree {
						usePoison[root] = true
						changed = true
						continue
					}
					if record {
						if resolvedUses[root] == nil {
							resolvedUses[root] = map[EnvAuditTarget]bool{}
						}
						resolvedUses[root][ParamAuditTarget(use.calleeParam)] = true
					}
				}
				return changed
			}
			propagateUses := func() bool {
				changed := false
				for _, pairs := range [][][2]types.Object{aliasPairs, heldPairs} {
					for _, pair := range pairs {
						a, b := aliasFind(pair[0]), aliasFind(pair[1])
						if a == b {
							continue
						}
						if usePoison[a] != usePoison[b] {
							usePoison[a], usePoison[b] = true, true
							changed = true
						}
						for use := range resolvedUses[a] {
							if !resolvedUses[b][use] {
								if resolvedUses[b] == nil {
									resolvedUses[b] = map[EnvAuditTarget]bool{}
								}
								resolvedUses[b][use] = true
								changed = true
							}
						}
						for use := range resolvedUses[b] {
							if !resolvedUses[a][use] {
								if resolvedUses[a] == nil {
									resolvedUses[a] = map[EnvAuditTarget]bool{}
								}
								resolvedUses[a][use] = true
								changed = true
							}
						}
					}
				}
				return changed
			}
			scratchFnDeps := map[FuncKey]bool{}
			scratchUseDeps := map[EnvAuditTarget]bool{}
			savedRecordFnDep, savedFold := recordFnDep, useFold
			recordFnDep = func(callee FuncKey) { scratchFnDeps[callee] = true }
			useFold = &scratchUseDeps
			for {
				changed := resolveUses(false)
				if propagateUses() {
					changed = true
				}
				if !changed {
					break
				}
				for k := range localFree {
					delete(localFree, k)
				}
			}
			recordFnDep, useFold = savedRecordFnDep, savedFold
			for k := range localFree {
				delete(localFree, k)
			}
			resolveUses(true)
			for propagateUses() {
			}
			for k := range localFree {
				delete(localFree, k)
			}
			for obj, idx := range paramIndex {
				key := ParamKey{Func: ownFuncKey, Index: idx}
				root := aliasFind(obj)
				if captureBroken[obj] || usePoison[root] {
					continue
				}
				collected := map[EnvAuditTarget]bool{}
				savedRec, savedFold := recordFnDep, useFold
				recordFnDep = func(callee FuncKey) { collected[FuncAuditTarget(callee)] = true }
				useFold = &collected
				okIns := true
				for _, stored := range append(append([]ast.Expr{}, sharedWrites[root]...), sharedInsertionWrites[root]...) {
					if ident, isIdent := unparen(stored).(*ast.Ident); isIdent {
						if sobj := p.TypesInfo.Uses[ident]; sobj != nil && params[sobj] &&
							!localBroken[sobj] && !captureBroken[sobj] {
							continue
						}
					}
					if !free(stored) {
						okIns = false
						break
					}
				}
				recordFnDep, useFold = savedRec, savedFold
				if !okIns {
					continue
				}
				for use := range resolvedUses[root] {
					collected[use] = true
				}
				insFree[key] = true
				if len(collected) > 0 {
					insDeps[key] = collected
				}
			}
			if hooks != nil && hooks.Refusal != nil {
				inner := free
				free = func(e ast.Expr) bool {
					r := inner(e)
					if !r {
						clause := "an unrecognized return shape"
						switch e := unparen(e).(type) {
						case *ast.Ident:
							obj := p.TypesInfo.Uses[e]
							if obj == nil {
								obj = p.TypesInfo.Defs[e]
							}
							switch {
							case obj != nil && localBroken[obj]:
								clause = "write or capture broke the binding"
							case obj != nil && usePoison[aliasFind(obj)]:
								clause = "an unjudgeable argument to a deferring call poisoned the storage"
							case obj != nil && len(sharedWrites[aliasFind(obj)]) > 0:
								clause = "a stored value refused"
							default:
								clause = "a binding source refused"
							}
						case *ast.CallExpr:
							clause = "callee outside the audited set and dependency channel"
						case *ast.CompositeLit:
							clause = "a literal element refused"
						case *ast.SelectorExpr, *ast.IndexExpr, *ast.SliceExpr:
							clause = "an unadmitted derivation shape"
						}
						explainRefusalMark(hooks, p, fd.Name.Name, e, clause)
					}
					return r
				}
			}
			ok = true
			results := 0
			if fd.Type.Results != nil {
				results = fd.Type.Results.NumFields()
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if !ok {
					return false
				}
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
				ret, isRet := n.(*ast.ReturnStmt)
				if !isRet {
					return true
				}
				if len(ret.Results) == 0 && results > 0 {
					ok = false
					return false
				}
				for _, result := range ret.Results {
					if !free(result) {
						ok = false
						return false
					}
				}
				return true
			})
			if !ok {
				continue
			}
			proven[fnKey] = true
			if len(fnDeps) > 0 {
				deps[fnKey] = fnDeps
			}
			if len(insCallDeps) > 0 {
				callerInsDeps[fnKey] = insCallDeps
			}
			recordReturnFieldRegistrants(audited, p, fnKey, fd.Body, retDefer, retPoison)
		}
	}
	return proven, deps, retDefer, retPoison, insFree, insDeps, callerInsDeps
}

func recordReturnFieldRegistrants(
	audited bool,
	p *packages.Package,
	fnKey string,
	body ast.Node,
	retDefer map[string]map[ReturnFieldParamDefer]bool,
	retPoison map[string]map[ReturnFieldParamPoison]bool,
) {
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	ownFuncKey := FuncKey{Pkg: ownPath, Name: fnKey}
	emit := func(m fieldRegMark) {
		switch m.class {
		case 'd':
			if retDefer[fnKey] == nil {
				retDefer[fnKey] = map[ReturnFieldParamDefer]bool{}
			}
			retDefer[fnKey][ReturnFieldParamDefer{
				Pos:   ReturnFieldPosKey{Func: ownFuncKey, Field: m.field, Index: m.idx},
				Param: m.param,
			}] = true
		case 'p':
			if retPoison[fnKey] == nil {
				retPoison[fnKey] = map[ReturnFieldParamPoison]bool{}
			}
			if m.field == "" {
				retPoison[fnKey][ReturnFieldParamPoison{Func: ownFuncKey}] = true
			} else {
				retPoison[fnKey][ReturnFieldParamPoison{Func: ownFuncKey, HasPos: true, Field: m.field, Index: m.idx}] = true
			}
		}
	}
	fieldWrite := func(lhs, rhs ast.Expr) {
		if sel, ok := unparenExpr(lhs).(*ast.SelectorExpr); ok {
			if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.FieldVal {
				if _, isSig := types.Unalias(selection.Type()).Underlying().(*types.Signature); isSig {
					classifyFieldRegistrantValue(audited, p, sel.Sel.Name, rhs, emit)
				}
			}
		}
	}
	funPositions := map[ast.Node]bool{}
	writePositions := map[ast.Node]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
		funLoop:
			for cur := unparenExpr(n.Fun); ; {
				funPositions[cur] = true
				switch x := cur.(type) {
				case *ast.IndexExpr:
					cur = unparenExpr(x.X)
				case *ast.IndexListExpr:
					cur = unparenExpr(x.X)
				case *ast.SelectorExpr:
					funPositions[x.Sel] = true
					break funLoop
				default:
					break funLoop
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				writePositions[unparenExpr(lhs)] = true
			}
		case *ast.IncDecStmt:
			writePositions[unparenExpr(n.X)] = true
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			classifyRegistrantComposite(audited, p, n, emit)
			return false
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, lhs := range n.Lhs {
					fieldWrite(lhs, n.Rhs[i])
				}
			} else if len(n.Rhs) == 1 {
				for _, lhs := range n.Lhs {
					fieldWrite(lhs, n.Rhs[0])
				}
			}
		case *ast.FuncLit:
			if !funPositions[n] {
				classifyLiteralRegistrant(audited, p, ElemPositionField, n, emit)
			}
		case *ast.CallExpr:
			if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
				break
			}
			if ident, ok := unparenExpr(n.Fun).(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin {
					break
				}
			}
			if fn, _ := plainCalleeFunc(p, n.Fun); fn != nil {
				break
			}
			if typeCarriesSignature(p.TypesInfo.TypeOf(n)) {
				emit(fieldRegMark{class: 'p', field: ElemPositionField, idx: -1})
			}
		case *ast.SelectorExpr:
			if funPositions[n] || writePositions[n] {
				break
			}
			if _, isFunc := p.TypesInfo.Uses[n.Sel].(*types.Func); isFunc {
				classifyFieldRegistrantValue(audited, p, ElemPositionField, n, emit)
				break
			}
			if typeCarriesSignature(p.TypesInfo.TypeOf(n)) {
				emit(fieldRegMark{class: 'p', field: ElemPositionField, idx: -1})
			}
		case *ast.IndexExpr, *ast.IndexListExpr:
			expr := n.(ast.Expr)
			if funPositions[n] || writePositions[n] {
				break
			}
			if fn, _ := plainCalleeFunc(p, expr); fn != nil {
				classifyFieldRegistrantValue(audited, p, ElemPositionField, expr, emit)
				break
			}
			if typeCarriesSignature(p.TypesInfo.TypeOf(expr)) {
				emit(fieldRegMark{class: 'p', field: ElemPositionField, idx: -1})
			}
		case *ast.Ident:
			if funPositions[n] {
				break
			}
			if _, isFunc := p.TypesInfo.Uses[n].(*types.Func); isFunc {
				classifyFieldRegistrantValue(audited, p, ElemPositionField, n, emit)
				break
			}
			if v, ok := p.TypesInfo.Uses[n].(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && typeCarriesSignature(v.Type()) {
				emit(fieldRegMark{class: 'p', idx: -1})
			}
		}
		return true
	})
}

func initOnlyReachableHelpers(p *packages.Package) map[string]bool {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil
	}
	return directCallSites(p).initOnlyHelpers()
}

func boundValueLeakFree(audited bool, p *packages.Package, roots map[types.Object]bool, body ast.Node) bool {
	return boundValueLeakFreeJudged(audited, p, roots, body, nil, nil, nil, nil, nil)
}

func boundValueLeakFreeDeferred(audited bool, p *packages.Package, roots map[types.Object]bool, body ast.Node, wants map[ParamKey]bool) bool {
	return boundValueLeakFreeJudged(audited, p, roots, body, wants, nil, nil, nil, nil)
}

func boundValueLeakFreeJudged(
	audited bool,
	p *packages.Package,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[ParamKey]bool,
	returns *bool,
	methodWants map[FuncKey]bool,
	fieldWants map[FieldPosKey]bool,
	elemWants map[ElemParamUse]bool,
) bool {
	return boundValueJudged(audited, p, roots, body, wants, returns, methodWants, fieldWants, elemWants, false)
}

func boundValueRetentionFreeJudged(
	audited bool,
	p *packages.Package,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[ParamKey]bool,
	methodWants map[FuncKey]bool,
) bool {
	return boundValueJudged(audited, p, roots, body, wants, nil, methodWants, nil, nil, true)
}

func boundValueJudged(
	audited bool,
	p *packages.Package,
	roots map[types.Object]bool,
	body ast.Node,
	wants map[ParamKey]bool,
	returns *bool,
	methodWants map[FuncKey]bool,
	fieldWants map[FieldPosKey]bool,
	elemWants map[ElemParamUse]bool,
	tolerateRootedStores bool,
) bool {
	if p == nil || p.TypesInfo == nil || body == nil || len(roots) == 0 {
		return false
	}
	goCalls := map[*ast.CallExpr]bool{}
	goIdents := map[ast.Node]bool{}
	litReturns := map[*ast.ReturnStmt]bool{}
	calleeReads := map[ast.Node]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			for cur := unparenExpr(call.Fun); ; {
				switch x := cur.(type) {
				case *ast.SelectorExpr, *ast.Ident:
					calleeReads[x] = true
					goto doneCallee
				case *ast.IndexExpr:
					calleeReads[x] = true
					cur = unparenExpr(x.X)
				case *ast.IndexListExpr:
					calleeReads[x] = true
					cur = unparenExpr(x.X)
				default:
					goto doneCallee
				}
			}
		doneCallee:
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.GoStmt:
			ast.Inspect(n, func(inner ast.Node) bool {
				if call, ok := inner.(*ast.CallExpr); ok {
					goCalls[call] = true
				}
				if lit, ok := inner.(*ast.FuncLit); ok {
					ast.Inspect(lit, func(deep ast.Node) bool {
						if call, ok := deep.(*ast.CallExpr); ok {
							goCalls[call] = true
						}
						if ident, ok := deep.(*ast.Ident); ok {
							goIdents[ident] = true
						}
						return true
					})
					return false
				}
				return true
			})
		case *ast.FuncLit:
			ast.Inspect(n, func(inner ast.Node) bool {
				if ret, ok := inner.(*ast.ReturnStmt); ok {
					litReturns[ret] = true
				}
				return true
			})
			return false
		}
		return true
	})
	carrierReaching := map[types.Object]bool{}
	carrierReach := func(expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		found := false
		ast.Inspect(expr, func(m ast.Node) bool {
			if found {
				return false
			}
			if ident, ok := m.(*ast.Ident); ok {
				if obj := p.TypesInfo.Uses[ident]; obj != nil {
					if carrierReaching[obj] {
						found = true
						return false
					}
					if variable, ok := obj.(*types.Var); ok && variable.Pkg() != nil &&
						variable.Parent() == variable.Pkg().Scope() &&
						TypeMayCarryUnknownDynamic(audited, variable.Type()) {
						found = true
					}
				}
			}
			return true
		})
		return found
	}
	if tolerateRootedStores {
		propagateLocalTaint(
			p.TypesInfo,
			body,
			carrierReaching,
			func(types.Object) bool { return true },
			carrierReach,
			nil,
		)
	}
	tainted := map[types.Object]bool{}
	isRoot := func(expr ast.Expr) bool {
		ident, ok := expr.(*ast.Ident)
		if !ok {
			return false
		}
		obj := p.TypesInfo.Uses[ident]
		if obj == nil {
			obj = p.TypesInfo.Defs[ident]
		}
		return obj != nil && (roots[obj] || tainted[obj])
	}
	rooted := func(expr ast.Expr) bool {
		ident := rootIdent(expr)
		return ident != nil && isRoot(ident)
	}
	propagateLocalTaint(
		p.TypesInfo,
		body,
		tainted,
		func(obj types.Object) bool {
			return !roots[obj] && (typeHandsOutMutableReach(obj.Type()) || typeCarriesSignature(obj.Type()))
		},
		rooted,
		rooted,
	)
	allowed := map[ast.Node]bool{}
	consume := func(expr ast.Expr) {
		if ident := rootIdent(expr); ident != nil {
			allowed[ident] = true
		}
	}
	methodValueBind := func(expr ast.Expr) bool {
		return isMethodValueBind(p.TypesInfo, expr)
	}
	leaky := false
	ast.Inspect(body, func(n ast.Node) bool {
		if leaky {
			return false
		}
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, rhs := range n.Rhs {
					if rooted(rhs) {
						if methodValueBind(rhs) {
							leaky = true
						} else if _, ok := n.Lhs[i].(*ast.Ident); ok {
							consume(rhs)
						}
					}
				}
			} else if len(n.Rhs) == 1 && rooted(n.Rhs[0]) {
				if methodValueBind(n.Rhs[0]) {
					leaky = true
				} else {
					allIdent := true
					for _, lhs := range n.Lhs {
						if _, ok := lhs.(*ast.Ident); !ok {
							allIdent = false
						}
					}
					if allIdent {
						consume(n.Rhs[0])
					}
				}
			}
			for i, lhs := range n.Lhs {
				if ident, ok := lhs.(*ast.Ident); ok {
					if obj := identDefOrUse(p.TypesInfo, ident); obj != nil && (roots[obj] || tainted[obj]) {
						if obj.Pos() < body.Pos() || obj.Pos() > body.End() {
							leaky = true
						}
						if fieldWants != nil && typeCarriesSignature(obj.Type()) {
							var rhs ast.Expr
							if len(n.Lhs) == len(n.Rhs) {
								rhs = n.Rhs[i]
							} else if len(n.Rhs) == 1 {
								rhs = n.Rhs[0]
							}
							originDefine := roots[obj] && p.TypesInfo.Defs[ident] != nil
							if (rhs == nil || !rooted(rhs)) && !originDefine {
								leaky = true
							}
						}
					}
					consume(ident)
					continue
				}
				if rooted(lhs) {
					var rhs ast.Expr
					if len(n.Lhs) == len(n.Rhs) {
						rhs = n.Rhs[i]
					} else if len(n.Rhs) == 1 {
						rhs = n.Rhs[0]
					}
					smuggles := false
					if rhs != nil {
						if t := p.TypesInfo.TypeOf(rhs); t == nil ||
							typeHandsOutMutableReach(t) ||
							typeCarriesSignature(t) {
							smuggles = carrierReach(rhs) || t == nil
						}
					}
					if tolerateRootedStores && !smuggles {
						consume(lhs)
					} else {
						leaky = true
					}
				}
			}
		case *ast.ValueSpec:
			if len(n.Names) == len(n.Values) {
				for i, rhs := range n.Values {
					if rooted(rhs) {
						if methodValueBind(rhs) {
							leaky = true
							continue
						}
						consume(rhs)
						allowed[n.Names[i]] = true
					}
				}
			} else if len(n.Values) == 1 && rooted(n.Values[0]) {
				if methodValueBind(n.Values[0]) {
					leaky = true
				} else {
					consume(n.Values[0])
					for _, name := range n.Names {
						allowed[name] = true
					}
				}
			}
		case *ast.IncDecStmt:
			if rooted(n.X) {
				if tolerateRootedStores {
					consume(n.X)
				} else {
					leaky = true
				}
			}
		case *ast.SendStmt:
			if rooted(n.Chan) {
				leaky = true
			}
		case *ast.UnaryExpr:
			if (n.Op == token.AND || n.Op == token.ARROW) && rooted(n.X) {
				leaky = true
			}
		case *ast.RangeStmt:
			if rooted(n.X) {
				if t := p.TypesInfo.TypeOf(n.X); t == nil {
					leaky = true
				} else if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
					leaky = true
				} else {
					for _, bind := range []ast.Expr{n.Key, n.Value} {
						if ident, ok := bind.(*ast.Ident); ok {
							consume(ident)
						} else if bind != nil {
							leaky = true
						}
					}
					consume(n.X)
				}
			}
		case *ast.ReturnStmt:
			for _, result := range n.Results {
				if rooted(result) {
					if t := p.TypesInfo.TypeOf(result); t == nil || typeHandsOutMutableReach(t) {
						if returns != nil && t != nil && !litReturns[n] && !methodValueBind(result) {
							*returns = true
							consume(result)
						} else {
							leaky = true
						}
					} else if methodValueBind(result) || typeCarriesSignature(p.TypesInfo.TypeOf(result)) {
						leaky = true
					} else {
						consume(result)
					}
				}
			}
		case *ast.CallExpr:
			if ident, ok := n.Fun.(*ast.Ident); ok {
				if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "len" || ident.Name == "cap") {
					for _, arg := range n.Args {
						if rooted(arg) {
							consume(arg)
						}
					}
					break
				}
			}
			if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
				if len(n.Args) == 1 && rooted(n.Args[0]) && !methodValueBind(n.Args[0]) {
					if t := p.TypesInfo.TypeOf(n); t != nil && !typeHandsOutMutableReach(t) && !typeCarriesSignature(t) {
						consume(n.Args[0])
					}
				}
				break
			}
			if sel, ok := unwrapCallee(n.Fun).(*ast.SelectorExpr); ok && rooted(sel.X) {
				selection, selOK := p.TypesInfo.Selections[sel]
				if selOK && selection.Kind() == types.MethodVal {
					fn, isFunc := selection.Obj().(*types.Func)
					if isFunc && AuditedSynchronization(audited, fn) {
						consume(sel.X)
						break
					}
					if isFunc && methodWants != nil && !goCalls[n] && fn.Pkg() != nil && !interfaceReceiver(fn) && instantiatedResultsHandOutNothing(audited, selection.Type()) {
						methodWants[methodFactKey(fn)] = true
						consume(sel.X)
					} else {
						leaky = true
					}
				} else if selOK && selection.Kind() == types.FieldVal {
				} else {
					leaky = true
				}
			}
			if fun := unparenExpr(n.Fun); rooted(fun) {
				if callResultHandsOut(p.TypesInfo.TypeOf(n)) {
					leaky = true
				}
			}
			for i, arg := range n.Args {
				if rooted(arg) {
					if t := p.TypesInfo.TypeOf(arg); t == nil || typeHandsOutMutableReach(t) || typeCarriesSignature(t) {
						deferred := false
						if wants != nil && !goCalls[n] {
							if fn, pkgPath := plainCalleeFunc(p, n.Fun); fn != nil {
								if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() == nil && sig.Params().Len() > 0 {
									idx := i
									if sig.Variadic() && idx >= sig.Params().Len()-1 {
										idx = sig.Params().Len() - 1
									}
									wants[ParamKey{Func: FuncKey{Pkg: pkgPath, Name: fn.Name()}, Index: idx}] = true
									consume(arg)
									deferred = true
								}
							}
						}
						if !deferred && fieldWants != nil && !goCalls[n] {
							if sel, ok := unwrapCallee(n.Fun).(*ast.SelectorExpr); ok && isRoot(sel.X) {
								if selection, selOK := p.TypesInfo.Selections[sel]; selOK && selection.Kind() == types.FieldVal {
									if sig, sigOK := types.Unalias(selection.Type()).Underlying().(*types.Signature); sigOK && sig.Params().Len() > 0 {
										idx := i
										if sig.Variadic() && idx >= sig.Params().Len()-1 {
											idx = sig.Params().Len() - 1
										}
										fieldWants[FieldPosKey{Field: sel.Sel.Name, Index: idx}] = true
										consume(arg)
										deferred = true
									}
								}
							}
						}
						if !deferred && elemWants != nil && !goCalls[n] {
							if index, ok := unparenExpr(n.Fun).(*ast.IndexExpr); ok {
								if base, ok := unparenExpr(index.X).(*ast.Ident); ok {
									obj := p.TypesInfo.Uses[base]
									if v, isVar := obj.(*types.Var); isVar && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && TypeMayCarryUnknownDynamic(audited, v.Type()) {
										if sig, sigOK := types.Unalias(p.TypesInfo.TypeOf(n.Fun)).Underlying().(*types.Signature); sigOK && sig.Params().Len() > 0 {
											idx := i
											if sig.Variadic() && idx >= sig.Params().Len()-1 {
												idx = sig.Params().Len() - 1
											}
											elemWants[ElemParamUse{Owner: dynamicVarKey(v), Index: idx}] = true
											consume(arg)
											deferred = true
										}
									}
								}
							}
						}
						if !deferred {
							leaky = true
						}
					} else if methodValueBind(arg) {
						leaky = true
					} else {
						consume(arg)
					}
				}
			}
		case *ast.IndexExpr:
			if rooted(n.X) && !allowed[rootIdent(n.X)] {
				if t := p.TypesInfo.TypeOf(n); t == nil || typeHandsOutMutableReach(t) || (!calleeReads[n] && typeCarriesSignature(t)) {
					leaky = true
				} else {
					consume(n.X)
				}
			}
		case *ast.SelectorExpr:
			if isRoot(n.X) && !allowed[rootIdent(n.X)] {
				if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
					break
				}
				if t := p.TypesInfo.TypeOf(n); t == nil || typeHandsOutMutableReach(t) || (!calleeReads[n] && typeCarriesSignature(t)) {
					leaky = true
				} else {
					consume(n.X)
				}
			}
		case *ast.BinaryExpr:
			if n.Op == token.EQL || n.Op == token.NEQ {
				if rooted(n.X) {
					consume(n.X)
				}
				if rooted(n.Y) {
					consume(n.Y)
				}
			}
		case *ast.Ident:
			if isRoot(n) && (goIdents[n] || (!allowed[n] && !calleeReads[n])) {
				leaky = true
			}
		}
		return true
	})
	return !leaky
}

func paramLeakFreeFunctions(
	audited bool,
	p *packages.Package,
	readOnlyLocal, retentionMethods map[string]bool,
) (
	map[ParamKey]bool,
	map[ParamKey]map[ParamKey]bool,
	map[ParamKey]bool,
	map[ParamKey]map[ParamKey]bool,
) {
	if p == nil || p.TypesInfo == nil {
		return nil, nil, nil, nil
	}
	proven := map[ParamKey]bool{}
	allWants := map[ParamKey]map[ParamKey]bool{}
	retention := map[ParamKey]bool{}
	allRetentionWants := map[ParamKey]map[ParamKey]bool{}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	retainOnly := func(obj types.Object, body ast.Node, key ParamKey) {
		wants := map[ParamKey]bool{}
		methodWants := map[FuncKey]bool{}
		if !boundValueRetentionFreeJudged(audited, p, map[types.Object]bool{obj: true}, body, wants, methodWants) {
			return
		}
		for want := range methodWants {
			if want.Pkg != ownPath || !retentionMethods[want.Name] {
				return
			}
		}
		if len(wants) == 0 {
			retention[key] = true
			return
		}
		allRetentionWants[key] = wants
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Body == nil || fd.Type.Params == nil {
				continue
			}
			ownFunc := FuncKey{Pkg: ownPath, Name: fd.Name.Name}
			index := 0
			for _, field := range fd.Type.Params.List {
				names := field.Names
				if len(names) == 0 {
					names = []*ast.Ident{nil}
				}
				for _, name := range names {
					idx := index
					index++
					key := ParamKey{Func: ownFunc, Index: idx}
					if name == nil || name.Name == "_" {
						proven[key] = true
						continue
					}
					obj := p.TypesInfo.Defs[name]
					if obj == nil {
						continue
					}
					if !typeHandsOutMutableReach(obj.Type()) {
						continue
					}
					wants := map[ParamKey]bool{}
					methodWants := map[FuncKey]bool{}
					if !boundValueLeakFreeJudged(audited, p, map[types.Object]bool{obj: true}, fd.Body, wants, nil, methodWants, nil, nil) {
						retainOnly(obj, fd.Body, key)
						continue
					}
					methodsProven := true
					for want := range methodWants {
						if want.Pkg != ownPath || !readOnlyLocal[want.Name] || !retentionMethods[want.Name] {
							methodsProven = false
							break
						}
					}
					if !methodsProven {
						continue
					}
					if len(wants) == 0 {
						proven[key] = true
						continue
					}
					allWants[key] = wants
				}
			}
		}
	}
	deps := resolveLocalParamDeps(ownPath, proven, allWants, func(need ParamKey) bool {
		return proven[need]
	})
	retentionDeps := resolveLocalParamDeps(ownPath, retention, allRetentionWants, func(need ParamKey) bool {
		return retention[need] || proven[need]
	})
	return proven, deps, retention, retentionDeps
}

func resolveLocalParamDeps(ownPath string, proven map[ParamKey]bool, allWants map[ParamKey]map[ParamKey]bool, satisfied func(ParamKey) bool) map[ParamKey]map[ParamKey]bool {
	conditional := map[ParamKey]map[ParamKey]bool{}
	deps := map[ParamKey]map[ParamKey]bool{}
	for key, wants := range allWants {
		crossPackage := false
		for want := range wants {
			if want.Func.Pkg != ownPath {
				crossPackage = true
				break
			}
		}
		if crossPackage {
			deps[key] = wants
		} else {
			conditional[key] = wants
		}
	}
	solveLeastFixedPoint(proven, conditional, satisfied)
	for key, needs := range conditional {
		if satisfied(key) {
			continue
		}
		edges := map[ParamKey]bool{}
		for need := range needs {
			if !satisfied(need) {
				edges[need] = true
			}
		}
		deps[key] = edges
	}
	return deps
}

func receiverRetentionFreeMethods(audited bool, p *packages.Package, readOnlyLocal map[string]bool) map[string]bool {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	proven := map[string]bool{}
	pending := map[string]map[string]bool{}
	ownPath := ""
	if p.Types != nil {
		ownPath = p.Types.Path()
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name == nil || fd.Body == nil || len(fd.Recv.List) != 1 {
				continue
			}
			recvName := RecvTypeName(fd)
			if recvName == "" {
				continue
			}
			key := recvName + "." + fd.Name.Name
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			if recvIdent == nil {
				proven[key] = true
				continue
			}
			recvObj := p.TypesInfo.Defs[recvIdent]
			if recvObj == nil {
				continue
			}
			wants := map[ParamKey]bool{}
			methodWants := map[FuncKey]bool{}
			if !boundValueRetentionFreeJudged(audited, p, map[types.Object]bool{recvObj: true}, fd.Body, wants, methodWants) {
				continue
			}
			if len(wants) != 0 {
				continue
			}
			needs := map[string]bool{}
			sound := true
			for want := range methodWants {
				if want.Pkg != ownPath {
					sound = false
					break
				}
				needs[want.Name] = true
			}
			if !sound {
				continue
			}
			if len(needs) == 0 {
				proven[key] = true
				continue
			}
			pending[key] = needs
		}
	}
	solveLeastFixedPoint(proven, pending, func(need string) bool {
		return proven[need]
	})
	return proven
}

// onceFieldOfDo resolves a call of the shape `x.field.Do(f)` — Do on a
// by-value sync.Once field selected from some value — to that field,
// or nil for every other shape.
func onceFieldOfDo(audited bool, info *types.Info, call *ast.CallExpr) *types.Var {
	if len(call.Args) != 1 {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	selection, ok := info.Selections[sel]
	if !ok || selection.Kind() != types.MethodVal {
		return nil
	}
	fn, ok := selection.Obj().(*types.Func)
	if !ok || !auditedOnceDo(audited, fn) {
		return nil
	}
	fieldSel, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	fieldSelection, ok := info.Selections[fieldSel]
	if !ok || fieldSelection.Kind() != types.FieldVal || len(fieldSelection.Index()) != 1 {
		return nil
	}
	field, ok := fieldSelection.Obj().(*types.Var)
	if !ok {
		return nil
	}
	named, ok := types.Unalias(field.Type()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Once" {
		return nil
	}
	return field
}

type callSiteIndex struct {
	info         *types.Info
	callable     map[string]bool
	funcParams   map[*types.Func][]types.Object
	params       map[*types.Var]callSiteParam
	written      map[*types.Var]bool
	escaped      map[*types.Func]bool
	calls        map[*types.Func][]*ast.CallExpr
	bareCallRefs map[string]map[string]bool
	bareEscaped  map[string]bool
}

type callSiteParam struct {
	fn       *types.Func
	index    int
	variadic bool
}

func directCallSites(p *packages.Package) *callSiteIndex {
	info := p.TypesInfo
	idx := &callSiteIndex{
		info:         info,
		callable:     map[string]bool{},
		funcParams:   map[*types.Func][]types.Object{},
		params:       map[*types.Var]callSiteParam{},
		written:      map[*types.Var]bool{},
		escaped:      map[*types.Func]bool{},
		calls:        map[*types.Func][]*ast.CallExpr{},
		bareCallRefs: map[string]map[string]bool{},
		bareEscaped:  map[string]bool{},
	}
	callable := map[*types.Func]bool{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil || fd.Name.Name == "init" || fd.Type == nil || fd.Type.Params == nil {
				continue
			}
			fn, ok := info.Defs[fd.Name].(*types.Func)
			if !ok || fn.Exported() {
				continue
			}
			callable[fn] = true
			idx.callable[fd.Name.Name] = true
			position := 0
			var paramObjs []types.Object
			for _, field := range fd.Type.Params.List {
				_, variadic := field.Type.(*ast.Ellipsis)
				for _, name := range field.Names {
					def := info.Defs[name]
					paramObjs = append(paramObjs, def)
					if v, ok := def.(*types.Var); ok {
						idx.params[v] = callSiteParam{fn: fn, index: position, variadic: variadic}
					}
					position++
				}
				if len(field.Names) == 0 {
					paramObjs = append(paramObjs, nil)
					position++
				}
			}
			idx.funcParams[fn] = paramObjs
			if fd.Body == nil {
				continue
			}
			markWritten := func(expr ast.Expr) {
				if ident, ok := expr.(*ast.Ident); ok {
					if v, ok := info.Uses[ident].(*types.Var); ok {
						if _, isParam := idx.params[v]; isParam {
							idx.written[v] = true
						}
					}
				}
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range n.Lhs {
						markWritten(lhs)
					}
				case *ast.IncDecStmt:
					markWritten(n.X)
				case *ast.UnaryExpr:
					if n.Op == token.AND {
						markWritten(n.X)
					}
				case *ast.RangeStmt:
					markWritten(n.Key)
					markWritten(n.Value)
				}
				return true
			})
		}
	}
	if len(callable) == 0 {
		return idx
	}
	callFun := map[*ast.Ident]bool{}
	bareCallFun := map[*ast.Ident]bool{}
	addBareRef := func(region, name string) {
		if idx.bareCallRefs[region] == nil {
			idx.bareCallRefs[region] = map[string]bool{}
		}
		idx.bareCallRefs[region][name] = true
	}
	var scanRegion func(region string, root ast.Node)
	scanRegion = func(region string, root ast.Node) {
		if root == nil {
			return
		}
		ast.Inspect(root, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				if n != root {
					if n.Type != nil {
						scanRegion("!", n.Type)
					}
					if n.Body != nil {
						scanRegion("!", n.Body)
					}
					return false
				}
			case *ast.GoStmt:
				if n.Call != nil {
					scanRegion("!", n.Call)
				}
				return false
			case *ast.CallExpr:
				fun := unwrapCallee(n.Fun)
				if ident, ok := fun.(*ast.Ident); ok {
					if fn, ok := info.Uses[ident].(*types.Func); ok && callable[fn] {
						idx.calls[fn] = append(idx.calls[fn], n)
						callFun[ident] = true
						if n.Fun == ident {
							bareCallFun[ident] = true
							addBareRef(region, fn.Name())
						}
					}
				}
			case *ast.Ident:
				if fn, ok := info.Uses[n].(*types.Func); ok && callable[fn] {
					if !callFun[n] {
						idx.escaped[fn] = true
					}
					if !bareCallFun[n] {
						idx.bareEscaped[fn.Name()] = true
					}
				}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Recv != nil {
					scanRegion("!", decl.Recv)
				}
				if decl.Type != nil {
					scanRegion("!", decl.Type)
				}
				if decl.Body != nil {
					switch {
					case decl.Recv == nil && decl.Name != nil && decl.Name.Name == "init":
						scanRegion("", decl.Body)
					case decl.Recv == nil && decl.Name != nil && idx.callable[decl.Name.Name]:
						scanRegion(decl.Name.Name, decl.Body)
					default:
						scanRegion("!", decl.Body)
					}
				}
			default:
				scanRegion("", decl)
			}
		}
	}
	return idx
}

func (idx *callSiteIndex) initOnlyHelpers() map[string]bool {
	if len(idx.callable) == 0 {
		return nil
	}
	disqualified := map[string]bool{}
	for name := range idx.bareEscaped {
		disqualified[name] = true
	}
	for name := range idx.bareCallRefs["!"] {
		disqualified[name] = true
	}
	for changed := true; changed; {
		changed = false
		for caller, refs := range idx.bareCallRefs {
			if caller == "" || caller == "!" || !disqualified[caller] {
				continue
			}
			for name := range refs {
				if !disqualified[name] {
					disqualified[name] = true
					changed = true
				}
			}
		}
	}
	qualified := map[string]bool{}
	for name := range idx.callable {
		if !disqualified[name] {
			qualified[name] = true
		}
	}
	reachable := map[string]bool{}
	var mark func(region string)
	mark = func(region string) {
		for name := range idx.bareCallRefs[region] {
			if qualified[name] && !reachable[name] {
				reachable[name] = true
				mark(name)
			}
		}
	}
	mark("")
	return reachable
}

func (idx *callSiteIndex) funcParamsOf(names map[string]bool) map[*types.Func][]types.Object {
	out := map[*types.Func][]types.Object{}
	for fn, params := range idx.funcParams {
		if names[fn.Name()] {
			out[fn] = params
		}
	}
	return out
}

func (idx *callSiteIndex) resolveParam(expr ast.Expr, seen map[*types.Var]bool, judge func(arg ast.Expr, seen map[*types.Var]bool) bool) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := idx.info.Uses[ident].(*types.Var)
	if !ok {
		return false
	}
	key, ok := idx.params[v]
	if !ok || key.variadic || idx.written[v] || idx.escaped[key.fn] || seen[v] {
		return false
	}
	sites := idx.calls[key.fn]
	if len(sites) == 0 {
		return false
	}
	seen[v] = true
	defer delete(seen, v)
	for _, site := range sites {
		if key.index >= len(site.Args) || !judge(site.Args[key.index], seen) {
			return false
		}
	}
	return true
}

func (idx *callSiteIndex) judgeExpr(expr ast.Expr, leaf func(types.Type) (decided, ok bool)) bool {
	var walk func(expr ast.Expr, seen map[*types.Var]bool) bool
	walk = func(expr ast.Expr, seen map[*types.Var]bool) bool {
		expr = unparenExpr(expr)
		t := idx.info.TypeOf(expr)
		if t == nil {
			return false
		}
		if decided, ok := leaf(t); decided {
			return ok
		}
		return idx.resolveParam(expr, seen, walk)
	}
	return walk(expr, map[*types.Var]bool{})
}

func walkSyncVarCalls(p *packages.Package, candidates map[*types.Var]bool, evictNonCallUses bool, judgeCall func(v *types.Var, sel *ast.SelectorExpr, call *ast.CallExpr) (admittedMethod, siteConforms bool)) map[*ast.SelectorExpr]bool {
	if len(candidates) == 0 {
		return nil
	}
	info := p.TypesInfo
	receiver := map[*ast.Ident]bool{}
	conformingBySelector := map[*ast.SelectorExpr]*types.Var{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			v, ok := info.Uses[ident].(*types.Var)
			if !ok || !candidates[v] {
				return true
			}
			admittedMethod, siteConforms := judgeCall(v, sel, call)
			if !admittedMethod {
				delete(candidates, v)
				return true
			}
			receiver[ident] = true
			if siteConforms {
				conformingBySelector[sel] = v
			} else if !evictNonCallUses {
				delete(candidates, v)
			}
			return true
		})
	}
	if evictNonCallUses {
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				ident, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				v, ok := info.Uses[ident].(*types.Var)
				if ok && candidates[v] && !receiver[ident] {
					delete(candidates, v)
				}
				return true
			})
		}
	}
	calls := map[*ast.SelectorExpr]bool{}
	for sel, v := range conformingBySelector {
		if candidates[v] {
			calls[sel] = true
		}
	}
	return calls
}

func dataMemoVars(audited bool, p *packages.Package) map[*types.Var]bool {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil
	}
	isSyncMap := func(t types.Type) bool {
		named, ok := types.Unalias(t).(*types.Named)
		return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "sync" && named.Obj().Name() == "Map"
	}
	candidates := map[*types.Var]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v.Exported() || !isSyncMap(v.Type()) {
			continue
		}
		candidates[v] = true
	}
	if len(candidates) == 0 {
		return nil
	}
	var index *callSiteIndex
	carrierFree := func(expr ast.Expr) bool {
		if index == nil {
			index = directCallSites(p)
		}
		return index.judgeExpr(expr, func(t types.Type) (bool, bool) {
			if !TypeMayCarryUnknownDynamic(audited, t) {
				return true, true
			}
			return false, false
		})
	}
	walkSyncVarCalls(p, candidates, false, func(_ *types.Var, sel *ast.SelectorExpr, call *ast.CallExpr) (bool, bool) {
		if !auditset.MemoMethod("Map", sel.Sel.Name) {
			return false, false
		}
		for _, arg := range call.Args {
			if !carrierFree(arg) {
				return true, false
			}
		}
		return true, true
	})
	return candidates
}

func closedInterfaceFields(p *packages.Package) map[*types.Var][]string {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return nil
	}
	info := p.TypesInfo
	candidateField := func(field *types.Var) bool {
		if field == nil || !field.IsField() || field.Exported() || field.Pkg() != p.Types {
			return false
		}
		_, isIface := types.Unalias(field.Type()).Underlying().(*types.Interface)
		return isIface
	}
	any := false
	for _, name := range p.Types.Scope().Names() {
		typeName, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := typeName.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields() && !any; i++ {
			any = candidateField(st.Field(i))
		}
	}
	if !any {
		return nil
	}
	index := directCallSites(p)
	memberTypes := func(expr ast.Expr) ([]string, bool) {
		var members []string
		ok := index.judgeExpr(expr, func(t types.Type) (bool, bool) {
			if _, isIface := types.Unalias(t).Underlying().(*types.Interface); isIface {
				return false, false
			}
			concrete := types.Unalias(t)
			if ptr, ok := concrete.(*types.Pointer); ok {
				concrete = types.Unalias(ptr.Elem())
			}
			named, ok := concrete.(*types.Named)
			if !ok || named.Obj() == nil || named.Obj().Pkg() != p.Types {
				return true, false
			}
			members = append(members, named.Obj().Name())
			return true, true
		})
		return members, ok
	}
	fieldOf := func(structType types.Type, index int) *types.Var {
		if ptr, ok := types.Unalias(structType).(*types.Pointer); ok {
			structType = ptr.Elem()
		}
		st, ok := types.Unalias(structType).Underlying().(*types.Struct)
		if !ok || index < 0 || index >= st.NumFields() {
			return nil
		}
		if field := st.Field(index); candidateField(field) {
			return field
		}
		return nil
	}
	members := map[*types.Var][]string{}
	open := map[*types.Var]bool{}
	store := func(field *types.Var, value ast.Expr) {
		if !candidateField(field) || open[field] {
			return
		}
		more, ok := memberTypes(value)
		if !ok {
			open[field] = true
			delete(members, field)
			return
		}
		members[field] = append(members[field], more...)
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				t := info.TypeOf(n)
				if t == nil {
					return true
				}
				if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
					t = ptr.Elem()
				}
				for i, elt := range n.Elts {
					if kv, ok := elt.(*ast.KeyValueExpr); ok {
						if key, ok := kv.Key.(*ast.Ident); ok {
							if field, ok := info.Uses[key].(*types.Var); ok {
								store(field, kv.Value)
							}
						}
						continue
					}
					store(fieldOf(t, i), elt)
				}
			case *ast.AssignStmt:
				if len(n.Lhs) != len(n.Rhs) {
					for _, lhs := range n.Lhs {
						if sel, ok := lhs.(*ast.SelectorExpr); ok {
							if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
								if field, ok := selection.Obj().(*types.Var); ok {
									open[field] = true
									delete(members, field)
								}
							}
						}
					}
					return true
				}
				for i, lhs := range n.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					selection, ok := info.Selections[sel]
					if !ok || selection.Kind() != types.FieldVal {
						continue
					}
					if field, ok := selection.Obj().(*types.Var); ok {
						store(field, n.Rhs[i])
					}
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					if sel, ok := n.X.(*ast.SelectorExpr); ok {
						if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
							if field, ok := selection.Obj().(*types.Var); ok {
								open[field] = true
								delete(members, field)
							}
						}
					}
				}
			case *ast.CallExpr:
				tv, ok := info.Types[n.Fun]
				if !ok || !tv.IsType() || len(n.Args) != 1 {
					return true
				}
				to := info.TypeOf(n)
				if to == nil {
					return true
				}
				if ptr, ok := types.Unalias(to).(*types.Pointer); ok {
					to = ptr.Elem()
				}
				st, ok := types.Unalias(to).Underlying().(*types.Struct)
				if !ok || types.Identical(info.TypeOf(n.Args[0]), to) {
					return true
				}
				for i := 0; i < st.NumFields(); i++ {
					if field := fieldOf(to, i); field != nil {
						open[field] = true
						delete(members, field)
					}
				}
			}
			return true
		})
	}
	closed := map[*types.Var][]string{}
	for field, names := range members {
		if open[field] || len(names) == 0 {
			continue
		}
		sort.Strings(names)
		closed[field] = slices.Compact(names)
	}
	return closed
}

func closedFieldDispatchTargets(info *types.Info, recvObj types.Object, sel *ast.SelectorExpr, name string, closed map[*types.Var][]string, declared map[string]bool) ([]string, bool) {
	fieldSel, ok := sel.X.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	ident, ok := fieldSel.X.(*ast.Ident)
	if !ok || info.Uses[ident] != recvObj {
		return nil, false
	}
	selection, ok := info.Selections[fieldSel]
	if !ok || selection.Kind() != types.FieldVal || len(selection.Index()) != 1 {
		return nil, false
	}
	field, ok := selection.Obj().(*types.Var)
	if !ok {
		return nil, false
	}
	members, ok := closed[field]
	if !ok {
		return nil, false
	}
	targets := make([]string, 0, len(members))
	for _, member := range members {
		target := member + "." + name
		if !declared[target] {
			return nil, false
		}
		targets = append(targets, target)
	}
	return targets, true
}

func unexportedDispatchTargets(p *packages.Package, selection *types.Selection, fn *types.Func, declaredByName map[string][]string, bodyless map[string]bool) ([]string, bool) {
	if p.Types == nil || fn.Exported() || fn.Pkg() != p.Types || selection.Recv() == nil || bodyless[fn.Name()] {
		return nil, false
	}
	recv := types.Unalias(selection.Recv())
	if ptr, ok := recv.(*types.Pointer); ok {
		recv = types.Unalias(ptr.Elem())
	}
	if _, ok := recv.Underlying().(*types.Interface); !ok {
		return nil, false
	}
	targets := append([]string(nil), declaredByName[fn.Name()]...)
	return targets, len(targets) > 0
}

func receiverReadOnlyMethods(audited bool, p *packages.Package) map[string]bool {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	type methodBody struct {
		decl *ast.FuncDecl
		recv *ast.Ident
	}
	methods := map[string]methodBody{}
	bodyless := map[string]bool{}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Recv != nil && fd.Name != nil && fd.Body == nil {
				bodyless[fd.Name.Name] = true
			}
			if !ok || fd.Recv == nil || fd.Name == nil || fd.Body == nil || len(fd.Recv.List) != 1 {
				continue
			}
			recvName := RecvTypeName(fd)
			if recvName == "" {
				continue
			}
			var recvIdent *ast.Ident
			if names := fd.Recv.List[0].Names; len(names) == 1 && names[0].Name != "_" {
				recvIdent = names[0]
			}
			methods[recvName+"."+fd.Name.Name] = methodBody{decl: fd, recv: recvIdent}
		}
	}
	if len(methods) == 0 {
		return nil
	}
	onceSites := map[*types.Var]int{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if field := onceFieldOfDo(audited, p.TypesInfo, call); field != nil {
				onceSites[field]++
			}
			return true
		})
	}
	declaredByName := map[string][]string{}
	declared := map[string]bool{}
	for key := range methods {
		declared[key] = true
		if dot := strings.LastIndex(key, "."); dot >= 0 {
			declaredByName[key[dot+1:]] = append(declaredByName[key[dot+1:]], key)
		}
	}
	closedFields := closedInterfaceFields(p)
	for _, keys := range declaredByName {
		sort.Strings(keys)
	}
	disqualified := map[string]bool{}
	chains := map[string]map[string]bool{}
	for key, m := range methods {
		if m.recv == nil {
			continue
		}
		recvObj := p.TypesInfo.Defs[m.recv]
		if recvObj == nil {
			disqualified[key] = true
			continue
		}
		tainted := map[types.Object]bool{}
		isRecv := func(expr ast.Expr) bool {
			ident, ok := expr.(*ast.Ident)
			if !ok {
				return false
			}
			obj := p.TypesInfo.Uses[ident]
			return obj == recvObj || (obj != nil && tainted[obj])
		}
		recvRooted := func(expr ast.Expr) bool {
			ident := rootIdent(expr)
			return ident != nil && isRecv(ident)
		}
		siblingLeaky := func(sel *ast.SelectorExpr) (bool, bool) {
			selection, ok := p.TypesInfo.Selections[sel]
			if !ok || selection.Kind() != types.MethodVal {
				return false, false
			}
			fn, ok := selection.Obj().(*types.Func)
			if !ok || fn.Pkg() != p.Types {
				return false, false
			}
			if _, sibling := methods[recvTypeNameOf(p, sel)+"."+fn.Name()]; !sibling {
				return false, false
			}
			return true, !instantiatedResultsHandOutNothing(audited, selection.Type())
		}
		rhsHandsReceiverValue := func(rhs ast.Expr) bool {
			if recvRooted(rhs) {
				return true
			}
			if call, ok := rhs.(*ast.CallExpr); ok {
				if sel, ok := unwrapCallee(call.Fun).(*ast.SelectorExpr); ok && recvRooted(sel.X) {
					if _, leaky := siblingLeaky(sel); leaky {
						return true
					}
				}
			}
			return false
		}
		propagateLocalTaint(
			p.TypesInfo,
			m.decl.Body,
			tainted,
			func(obj types.Object) bool {
				return obj != recvObj && typeHandsOutMutableReach(obj.Type())
			},
			rhsHandsReceiverValue,
			recvRooted,
		)
		allowed := map[ast.Node]bool{}
		governedCalls := map[*ast.CallExpr]bool{}
		consume := func(expr ast.Expr) {
			if ident := rootIdent(expr); ident != nil {
				allowed[ident] = true
			}
		}
		methodValueBind := func(expr ast.Expr) bool {
			return isMethodValueBind(p.TypesInfo, expr)
		}
		escapingSink := func(ident *ast.Ident) bool {
			if p.Types == nil {
				return true
			}
			obj := identDefOrUse(p.TypesInfo, ident)
			return obj != nil && obj.Pkg() != nil && obj.Parent() == obj.Pkg().Scope() && typeHandsOutMutableReach(obj.Type())
		}
		onceFill := map[ast.Node]bool{}
		ast.Inspect(m.decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			field := onceFieldOfDo(audited, p.TypesInfo, call)
			if field == nil || onceSites[field] != 1 || field.Exported() {
				return true
			}
			ident, ok := call.Fun.(*ast.SelectorExpr).X.(*ast.SelectorExpr).X.(*ast.Ident)
			if !ok || p.TypesInfo.Uses[ident] != recvObj || onceFieldCount(recvObj.Type()) != 1 {
				return true
			}
			if _, pointer := types.Unalias(recvObj.Type()).(*types.Pointer); !pointer {
				return true
			}
			lit, ok := call.Args[0].(*ast.FuncLit)
			if !ok {
				return true
			}
			for _, stmt := range lit.Body.List {
				switch stmt := stmt.(type) {
				case *ast.AssignStmt:
					fill := true
					for _, lhs := range stmt.Lhs {
						if recvRooted(lhs) && !fillSelection(p.TypesInfo, lhs) {
							fill = false
						}
					}
					if fill {
						onceFill[stmt] = true
					}
				case *ast.IncDecStmt:
					if fillSelection(p.TypesInfo, stmt.X) {
						onceFill[stmt] = true
					}
				}
			}
			return true
		})
		innerReturns := map[*ast.ReturnStmt]bool{}
		ast.Inspect(m.decl.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.FuncLit)
			if !ok {
				return true
			}
			ast.Inspect(lit.Body, func(inner ast.Node) bool {
				if r, ok := inner.(*ast.ReturnStmt); ok {
					innerReturns[r] = true
				}
				return true
			})
			return false
		})
		ast.Inspect(m.decl.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				governRHS := func(i int, rhs ast.Expr) {
					call, ok := rhs.(*ast.CallExpr)
					if !ok {
						return
					}
					sel, ok := unwrapCallee(call.Fun).(*ast.SelectorExpr)
					if !ok || !recvRooted(sel.X) {
						return
					}
					if sibling, _ := siblingLeaky(sel); !sibling {
						return
					}
					if i >= 0 {
						ident, ok := n.Lhs[i].(*ast.Ident)
						if !ok || escapingSink(ident) {
							return
						}
					} else {
						for _, lhs := range n.Lhs {
							ident, ok := lhs.(*ast.Ident)
							if !ok || escapingSink(ident) {
								return
							}
						}
					}
					governedCalls[call] = true
				}
				if len(n.Lhs) == len(n.Rhs) {
					for i, rhs := range n.Rhs {
						governRHS(i, rhs)
						if recvRooted(rhs) {
							if methodValueBind(rhs) {
								disqualified[key] = true
							} else if ident, ok := n.Lhs[i].(*ast.Ident); ok {
								if escapingSink(ident) {
									disqualified[key] = true
								} else {
									consume(rhs)
								}
							}
						}
					}
				} else if len(n.Rhs) == 1 {
					governRHS(-1, n.Rhs[0])
					if recvRooted(n.Rhs[0]) {
						if methodValueBind(n.Rhs[0]) {
							disqualified[key] = true
						}
						allIdent := true
						sink := false
						for _, lhs := range n.Lhs {
							ident, ok := lhs.(*ast.Ident)
							if !ok {
								allIdent = false
							} else if escapingSink(ident) {
								sink = true
							}
						}
						if allIdent && !methodValueBind(n.Rhs[0]) {
							if sink {
								disqualified[key] = true
							} else {
								consume(n.Rhs[0])
							}
						}
					}
				}
				for _, lhs := range n.Lhs {
					if ident, ok := lhs.(*ast.Ident); ok {
						if p.TypesInfo.Uses[ident] == recvObj || p.TypesInfo.Defs[ident] == recvObj {
							disqualified[key] = true
						}
						consume(ident)
						continue
					}
					if recvRooted(lhs) && !onceFill[n] {
						disqualified[key] = true
					}
				}

			case *ast.IncDecStmt:
				if recvRooted(n.X) && !onceFill[n] {
					disqualified[key] = true
				}
			case *ast.SendStmt:
				if recvRooted(n.Chan) {
					disqualified[key] = true
				}
			case *ast.UnaryExpr:
				if n.Op == token.AND && recvRooted(n.X) {
					disqualified[key] = true
				}
			case *ast.RangeStmt:
				if recvRooted(n.X) {
					t := p.TypesInfo.TypeOf(n.X)
					if t == nil {
						disqualified[key] = true
					} else if _, isChan := types.Unalias(t).Underlying().(*types.Chan); isChan {
						disqualified[key] = true
					} else {
						for _, bind := range []ast.Expr{n.Key, n.Value} {
							if ident, ok := bind.(*ast.Ident); ok && ident != nil {
								if escapingSink(ident) {
									disqualified[key] = true
									continue
								}
								if obj := p.TypesInfo.Defs[ident]; obj != nil {
									tainted[obj] = true
								}
								consume(ident)
							}
						}
						consume(n.X)
					}
				}
			case *ast.ReturnStmt:
				if innerReturns[n] {
					for _, result := range n.Results {
						if recvRooted(result) {
							disqualified[key] = true
						}
					}
					break
				}
				for _, result := range n.Results {
					if recvRooted(result) {
						if methodValueBind(result) {
							disqualified[key] = true
							continue
						}
						consume(result)
					}
					if call, ok := result.(*ast.CallExpr); ok {
						if sel, ok := unwrapCallee(call.Fun).(*ast.SelectorExpr); ok && recvRooted(sel.X) {
							if sibling, _ := siblingLeaky(sel); sibling {
								governedCalls[call] = true
							}
						}
					}
				}
			case *ast.CallExpr:
				if ident, ok := n.Fun.(*ast.Ident); ok {
					if _, builtin := p.TypesInfo.Uses[ident].(*types.Builtin); builtin && (ident.Name == "len" || ident.Name == "cap") {
						for _, arg := range n.Args {
							if recvRooted(arg) {
								consume(arg)
							}
						}
						break
					}
				}
				if tv, ok := p.TypesInfo.Types[n.Fun]; ok && tv.IsType() {
					if len(n.Args) == 1 && recvRooted(n.Args[0]) && !methodValueBind(n.Args[0]) {
						if !callResultHandsOut(p.TypesInfo.TypeOf(n)) {
							consume(n.Args[0])
						}
					}
					break
				}
				if sel, ok := unwrapCallee(n.Fun).(*ast.SelectorExpr); ok && recvRooted(sel.X) {
					if selection, ok := p.TypesInfo.Selections[sel]; ok && selection.Kind() == types.MethodVal {
						if fn, ok := selection.Obj().(*types.Func); ok && AuditedSynchronization(audited, fn) {
							consume(sel.X)
							break
						}
						if fn, ok := selection.Obj().(*types.Func); ok && fn.Pkg() == p.Types {
							target := recvTypeNameOf(p, sel) + "." + fn.Name()
							if _, sibling := methods[target]; sibling {
								if chains[key] == nil {
									chains[key] = map[string]bool{}
								}
								chains[key][target] = true
								consume(sel.X)
								if _, leaky := siblingLeaky(sel); leaky && !governedCalls[n] {
									disqualified[key] = true
								}
								break
							}
							targets, ok := unexportedDispatchTargets(p, selection, fn, declaredByName, bodyless)
							if !ok && !bodyless[fn.Name()] {
								targets, ok = closedFieldDispatchTargets(p.TypesInfo, recvObj, sel, fn.Name(), closedFields, declared)
							}
							if ok {
								if chains[key] == nil {
									chains[key] = map[string]bool{}
								}
								for _, target := range targets {
									chains[key][target] = true
								}
								consume(sel.X)
								if !instantiatedResultsHandOutNothing(audited, selection.Type()) && !governedCalls[n] {
									disqualified[key] = true
								}
								break
							}
						}
					}
					disqualified[key] = true
				}
			case *ast.IndexExpr:
				if recvRooted(n.X) && !allowed[rootIdent(n.X)] {
					if callResultHandsOut(p.TypesInfo.TypeOf(n)) {
						disqualified[key] = true
					} else {
						consume(n.X)
					}
				}
			case *ast.SelectorExpr:
				if recvRooted(n.X) && !allowed[rootIdent(n.X)] {
					if selection, ok := p.TypesInfo.Selections[n]; ok && selection.Kind() == types.MethodVal {
						disqualified[key] = true
						break
					}
					if callResultHandsOut(p.TypesInfo.TypeOf(n)) {
						disqualified[key] = true
					} else {
						consume(n.X)
					}
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL || n.Op == token.NEQ {
					if recvRooted(n.X) {
						consume(n.X)
					}
					if recvRooted(n.Y) {
						consume(n.Y)
					}
				}
			case *ast.Ident:
				if isRecv(n) && !allowed[n] {
					disqualified[key] = true
				}
			}
			return true
		})
	}
	solveReachFixedPoint(disqualified, chains, func(d string) bool { return disqualified[d] })
	readOnly := map[string]bool{}
	for key, m := range methods {
		if m.recv == nil || !disqualified[key] {
			readOnly[key] = true
		}
	}
	return readOnly
}

func provenSharedPools(audited bool, p *packages.Package) (proven map[*types.Var]types.Type, calls map[*ast.SelectorExpr]bool) {
	proven = map[*types.Var]types.Type{}
	calls = map[*ast.SelectorExpr]bool{}
	if p.TypesInfo == nil {
		return proven, calls
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
					continue
				}
				name := vs.Names[0]
				if name.IsExported() {
					continue
				}
				variable, ok := p.TypesInfo.Defs[name].(*types.Var)
				if !ok || variable.Pkg() == nil {
					continue
				}
				named, ok := types.Unalias(variable.Type()).(*types.Named)
				if !ok || named.Obj() == nil || named.Obj().Pkg() == nil ||
					named.Obj().Pkg().Path() != "sync" || named.Obj().Name() != "Pool" {
					continue
				}
				lit, ok := unparenExpr(vs.Values[0]).(*ast.CompositeLit)
				if !ok || len(lit.Elts) != 1 {
					continue
				}
				kv, ok := lit.Elts[0].(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "New" {
					continue
				}
				fnLit, ok := unparenExpr(kv.Value).(*ast.FuncLit)
				if !ok {
					continue
				}
				content := provenPoolContentType(audited, p, fnLit)
				if content == nil {
					continue
				}
				proven[variable] = content
			}
		}
	}
	if len(proven) == 0 {
		return proven, calls
	}
	candidates := make(map[*types.Var]bool, len(proven))
	for v := range proven {
		candidates[v] = true
	}
	calls = walkSyncVarCalls(p, candidates, true, func(v *types.Var, sel *ast.SelectorExpr, call *ast.CallExpr) (bool, bool) {
		selection, ok := p.TypesInfo.Selections[sel]
		if !ok || selection.Kind() != types.MethodVal {
			return false, false
		}
		fn, ok := selection.Obj().(*types.Func)
		if !ok || !AuditedPooling(audited, fn) {
			return false, false
		}
		return true, provenPoolCallConforms(p, fn, call, proven[v])
	})
	for v := range proven {
		if !candidates[v] {
			delete(proven, v)
		}
	}
	return proven, calls
}

func provenPoolContentType(audited bool, p *packages.Package, lit *ast.FuncLit) types.Type {
	if lit.Type == nil || lit.Type.Results == nil {
		return nil
	}
	for _, field := range lit.Type.Results.List {
		if len(field.Names) > 0 {
			return nil
		}
	}
	var content types.Type
	conforming := true
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if !conforming {
			return false
		}
		if _, nested := n.(*ast.FuncLit); nested {
			return false
		}
		if _, deferred := n.(*ast.DeferStmt); deferred {
			conforming = false
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		if len(ret.Results) != 1 {
			conforming = false
			return false
		}
		tv, ok := p.TypesInfo.Types[ret.Results[0]]
		if !ok || tv.Type == nil {
			conforming = false
			return false
		}
		t := tv.Type
		if basic, isBasic := types.Unalias(t).(*types.Basic); isBasic && basic.Info()&types.IsUntyped != 0 {
			conforming = false
			return false
		}
		if content == nil {
			content = t
		} else if !types.Identical(content, t) {
			conforming = false
			return false
		}
		return true
	})
	if !conforming || content == nil {
		return nil
	}
	if TypeMayCarryUnknownDynamic(audited, content) {
		return nil
	}
	return content
}

func provenPoolCallConforms(p *packages.Package, fn *types.Func, call *ast.CallExpr, content types.Type) bool {
	switch fn.Name() {
	case "Get":
		return len(call.Args) == 0
	case "Put":
		if len(call.Args) != 1 {
			return false
		}
		tv, ok := p.TypesInfo.Types[call.Args[0]]
		if !ok || tv.Type == nil {
			return false
		}
		return types.Identical(tv.Type, content)
	default:
		return false
	}
}

func recordFunctionReferenceRegions(p *packages.Package, initOnly map[string]bool, refs map[FuncKey]map[RefRegion]bool) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return
	}
	funcKeyOf := func(obj types.Object) (FuncKey, bool) {
		fn, ok := obj.(*types.Func)
		if !ok || fn.Pkg() == nil {
			return FuncKey{}, false
		}
		fn = fn.Origin()
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil {
			return FuncKey{}, false
		}
		return FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}, true
	}
	add := func(callee FuncKey, region RefRegion) {
		if refs[callee] == nil {
			refs[callee] = map[RefRegion]bool{}
		}
		refs[callee][region] = true
	}
	literalRegion := func(region RefRegion) RefRegion {
		switch region.Kind {
		case RegionLitFunc:
			return region
		case RegionFunc:
			return RefRegion{Kind: RegionLitFunc, Caller: region.Caller}
		default:
			return RefRegion{Kind: RegionProg}
		}
	}
	var scan func(region RefRegion, root ast.Node)
	scan = func(region RefRegion, root ast.Node) {
		calls := map[*ast.Ident]bool{}
		ast.Inspect(root, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				if n != root && n.Body != nil {
					scan(literalRegion(region), n.Body)
					return false
				}
			case *ast.GoStmt:
				scan(literalRegion(region), n.Call)
				return false
			case *ast.CallExpr:
				fun := unwrapCallee(n.Fun)
				if ident, ok := fun.(*ast.Ident); ok {
					if key, ok := funcKeyOf(p.TypesInfo.Uses[ident]); ok {
						calls[ident] = true
						add(key, region)
					}
				}
				if sel, ok := fun.(*ast.SelectorExpr); ok {
					if key, ok := funcKeyOf(p.TypesInfo.Uses[sel.Sel]); ok {
						calls[sel.Sel] = true
						add(key, region)
					}
				}
			case *ast.Ident:
				if calls[n] {
					return true
				}
				if key, ok := funcKeyOf(p.TypesInfo.Uses[n]); ok {
					add(key, literalRegion(region))
				}
			}
			return true
		})
	}
	initReg := RefRegion{Kind: RegionInit}
	progReg := RefRegion{Kind: RegionProg}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				switch {
				case decl.Recv != nil:
					if decl.Body != nil {
						scan(progReg, decl.Body)
					}
				case decl.Name != nil && decl.Name.Name == "init":
					if decl.Body != nil {
						scan(initReg, decl.Body)
					}
				case decl.Name != nil && initOnly[decl.Name.Name]:
					if decl.Body != nil {
						scan(initReg, decl.Body)
					}
				case decl.Name != nil:
					if decl.Body != nil && p.Types != nil {
						scan(RefRegion{Kind: RegionFunc, Caller: FuncKey{Pkg: p.Types.Path(), Name: decl.Name.Name}}, decl.Body)
					}
				}
			default:
				scan(initReg, decl)
			}
		}
	}
}

func recordOpaqueDynamicVars(p *packages.Package, opaque, breaks map[string]bool, deps map[string]map[string]bool) {
	if p == nil || p.TypesInfo == nil || p.Types == nil {
		return
	}
	interfacePackageVar := func(obj types.Object) (*types.Var, bool) {
		variable, ok := obj.(*types.Var)
		if !ok || variable.Pkg() == nil || variable.Parent() != variable.Pkg().Scope() {
			return nil, false
		}
		_, isInterface := types.Unalias(variable.Type()).Underlying().(*types.Interface)
		return variable, isInterface
	}
	var auditedImmutable func(expr ast.Expr, storeDeps map[string]bool) bool
	auditedArgument := func(expr ast.Expr, storeDeps map[string]bool) bool {
		if auditedImmutable(expr, storeDeps) {
			return true
		}
		if storeDeps != nil {
			var target *ast.Ident
			switch e := unparenExpr(expr).(type) {
			case *ast.Ident:
				target = e
			case *ast.SelectorExpr:
				if x, ok := e.X.(*ast.Ident); ok {
					if _, isPkg := p.TypesInfo.Uses[x].(*types.PkgName); isPkg {
						target = e.Sel
					}
				}
			}
			if target != nil {
				if obj, ok := p.TypesInfo.Uses[target]; ok {
					if variable, ok := interfacePackageVar(obj); ok {
						storeDeps[dynamicVarKey(variable)] = true
						return true
					}
				}
			}
		}
		return false
	}
	auditedImmutable = func(expr ast.Expr, storeDeps map[string]bool) bool {
		if tv, ok := p.TypesInfo.Types[expr]; ok && tv.Value != nil {
			return true
		}
		if t := p.TypesInfo.TypeOf(expr); t != nil && immutableRuntimeType(t) {
			return true
		}
		switch expr := expr.(type) {
		case *ast.Ident:
			return expr.Name == "nil" && p.TypesInfo.Uses[expr] == types.Universe.Lookup("nil")
		case *ast.CallExpr:
			sel, ok := expr.Fun.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
			if !ok || fn.Pkg() == nil {
				return false
			}
			if fn.Pkg().Path() == "errors" && fn.Name() == "New" {
				return true
			}
			if fn.Pkg().Path() == "fmt" && fn.Name() == "Errorf" {
				if sig, ok := fn.Type().(*types.Signature); !ok || sig.Recv() != nil {
					return false
				}
				for _, arg := range expr.Args {
					if !auditedArgument(arg, storeDeps) {
						return false
					}
				}
				return true
			}
			return false
		default:
			return false
		}
	}
	failed := map[string]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		if variable, ok := interfacePackageVar(scope.Lookup(name)); ok {
			opaque[dynamicVarKey(variable)] = true
		}
	}
	audit := func(target ast.Expr, value ast.Expr) {
		ident, ok := target.(*ast.Ident)
		if !ok {
			return
		}
		obj, ok := p.TypesInfo.Defs[ident]
		if !ok || obj == nil {
			if obj, ok = p.TypesInfo.Uses[ident]; !ok {
				return
			}
		}
		if variable, ok := interfacePackageVar(obj); ok {
			key := dynamicVarKey(variable)
			storeDeps := map[string]bool{}
			if value == nil || !auditedArgument(value, storeDeps) {
				failed[key] = true
				return
			}
			for dep := range storeDeps {
				if deps == nil {
					break
				}
				if deps[key] == nil {
					deps[key] = map[string]bool{}
				}
				deps[key][dep] = true
			}
		}
	}
	failSubtree := func(expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if obj, ok := p.TypesInfo.Uses[ident]; ok {
				if variable, ok := interfacePackageVar(obj); ok {
					failed[dynamicVarKey(variable)] = true
				}
			}
			return true
		})
	}
	failTargets := func(expr ast.Expr) {
		for {
			switch t := expr.(type) {
			case *ast.Ident:
				if obj, ok := p.TypesInfo.Uses[t]; ok {
					if variable, ok := interfacePackageVar(obj); ok {
						failed[dynamicVarKey(variable)] = true
					}
				}
				return
			case *ast.SelectorExpr:
				if obj, ok := p.TypesInfo.Uses[t.Sel]; ok {
					if variable, ok := interfacePackageVar(obj); ok {
						failed[dynamicVarKey(variable)] = true
						return
					}
				}
				expr = t.X
			case *ast.IndexExpr:
				expr = t.X
			case *ast.StarExpr:
				expr = t.X
			case *ast.ParenExpr:
				expr = t.X
			default:
				failSubtree(expr)
				return
			}
		}
	}
	failCaptures := func(expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.UnaryExpr:
				if n.Op == token.AND {
					if _, composite := unparenExpr(n.X).(*ast.CompositeLit); !composite {
						failTargets(n.X)
					}
				}
			}
			return true
		})
	}
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, ident := range vs.Names {
						var value ast.Expr
						if i < len(vs.Values) {
							value = vs.Values[i]
						}
						if len(vs.Values) == 0 {
							continue
						}
						audit(ident, value)
						if value != nil {
							failCaptures(value)
						}
					}
				}
			case *ast.FuncDecl:
				if decl.Recv != nil || decl.Name == nil || decl.Body == nil {
					continue
				}
				ast.Inspect(decl.Body, func(n ast.Node) bool {
					switch n := n.(type) {
					case *ast.FuncLit:
						return false
					case *ast.AssignStmt:
						for i, lhs := range n.Lhs {
							var value ast.Expr
							if i < len(n.Rhs) {
								value = n.Rhs[i]
							}
							switch target := lhs.(type) {
							case *ast.Ident:
								audit(target, value)
							case *ast.SelectorExpr:
								if base, ok := target.X.(*ast.Ident); ok {
									if _, isPkg := p.TypesInfo.Uses[base].(*types.PkgName); isPkg {
										audit(target.Sel, value)
										continue
									}
								}
								failTargets(lhs)
							default:
								failTargets(lhs)
							}
						}
					case *ast.UnaryExpr:
						if n.Op == token.AND {
							if _, composite := unparenExpr(n.X).(*ast.CompositeLit); !composite {
								failTargets(n.X)
							}
						}
					case *ast.RangeStmt:
						if n.Key != nil {
							failTargets(n.Key)
						}
						if n.Value != nil {
							failTargets(n.Value)
						}
					}
					return true
				})
			}
		}
	}
	for key := range failed {
		delete(opaque, key)
		breaks[key] = true
	}
}

func eachCompositeLitValue(lit *ast.CompositeLit, fn func(ast.Expr) bool) bool {
	for _, elt := range lit.Elts {
		value := elt
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			value = kv.Value
		}
		if !fn(value) {
			return false
		}
	}
	return true
}
