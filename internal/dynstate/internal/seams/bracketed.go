package seams

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type exportedSeamKey struct {
	fn  syntaxutil.FuncKey
	key string
}

type exportedSeamMarkKey struct {
	fn  syntaxutil.FuncKey
	key string
	pos token.Pos
}

type bracketedSeamAnalyzer struct {
	audited          bool
	p                *packages.Package
	idx              *refconfine.PkgIndex
	res              Result
	graph            callGraph
	liveHandles      map[*ast.BlockStmt]map[*types.Var]bool
	revIntra         map[*types.Func][]*types.Func
	exportedSeamIdx  map[exportedSeamKey]int
	seenExportedMark map[exportedSeamMarkKey]bool
	addrTaken        map[*types.Var]bool
	ptrMethodOnVar   map[*types.Var]bool
	uninitDecls      map[*types.Var]bool
}

// AnalyzeBracketedSeams identifies AST nodes in p that belong to lexically
// bracketed save-and-restore or zero-reset seams in sequential plain package
// functions or, under an audited toolchain, to an unexported uninitialized
// sync/atomic.Pointer[T] hook variable whose Store calls are serialized under a
// single unexported package-level sync.Mutex, and summarizes exported mutating
// seams, site positions, and cross-package function edges for Compose
// (REQ-closure-shared-dynamic-state).
func AnalyzeBracketedSeams(audited bool, p *packages.Package, idx *refconfine.PkgIndex) Result {
	if p == nil || p.TypesInfo == nil {
		return Result{}
	}
	graph := analyzeCallGraph(p)
	a := &bracketedSeamAnalyzer{
		audited: audited,
		p:       p,
		idx:     idx,
		res: Result{
			Exempt:         map[ast.Node]bool{},
			NonSeqFuncUses: graph.NonSeqFuncUses,
			SeqFuncEdges:   graph.SeqFuncEdges,
			ParallelFuncs:  graph.ParallelFuncs,
			ParallelEdges:  graph.ParallelEdges,
		},
		graph:            graph,
		liveHandles:      computeLiveTestingHandles(p, graph),
		exportedSeamIdx:  map[exportedSeamKey]int{},
		seenExportedMark: map[exportedSeamMarkKey]bool{},
		addrTaken:        map[*types.Var]bool{},
		ptrMethodOnVar:   map[*types.Var]bool{},
		uninitDecls:      map[*types.Var]bool{},
	}
	a.collectAddrTakenAndUninitDecls()
	a.analyzeMutexBracketedAtomicPtrs()
	a.analyzeLexicalSaveRestoreSeams()
	slices.SortFunc(a.res.ExportedSeams, syntaxutil.ExportedSeam.Compare)
	return a.res
}

func (a *bracketedSeamAnalyzer) resolve(ident *ast.Ident) (types.Object, bool) {
	if obj, ok := a.p.TypesInfo.Uses[ident]; ok && obj != nil {
		return obj, true
	}
	if obj, ok := a.p.TypesInfo.Defs[ident]; ok && obj != nil {
		return obj, true
	}
	return nil, false
}

func (a *bracketedSeamAnalyzer) isBlockedSeamDecl(fd *ast.FuncDecl) bool {
	if fd == nil || fd.Name == nil || len(a.graph.Blocked) == 0 {
		return false
	}
	fn, ok := a.p.TypesInfo.Defs[fd.Name].(*types.Func)
	return ok && fn != nil && a.graph.Blocked[fn.Origin()]
}

func (a *bracketedSeamAnalyzer) recordMutatingSeam(fd *ast.FuncDecl, baseVar *types.Var, writePos token.Pos, viaCleanup bool) {
	if fd == nil || fd.Name == nil || baseVar == nil || a.p.Types == nil || !refconfine.TypeMayCarryUnknownDynamic(a.audited, baseVar.Type()) {
		return
	}
	fn, ok := a.p.TypesInfo.Defs[fd.Name].(*types.Func)
	if !ok || fn == nil {
		return
	}
	fn = fn.Origin()
	if a.graph.Blocked[fn] {
		return
	}
	if a.revIntra == nil {
		a.revIntra = map[*types.Func][]*types.Func{}
		for caller, callees := range a.graph.IntraEdges {
			for callee := range callees {
				a.revIntra[callee] = append(a.revIntra[callee], caller)
			}
		}
	}
	var exportedCallers []*types.Func
	visited := map[*types.Func]bool{fn: true}
	stack := []*types.Func{fn}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if a.graph.Blocked[cur] {
			continue
		}
		if cur.Exported() || (a.p.Name == "main" && cur.Name() == "main") {
			exportedCallers = append(exportedCallers, cur)
		}
		for _, caller := range a.revIntra[cur] {
			if !visited[caller] {
				visited[caller] = true
				stack = append(stack, caller)
			}
		}
	}
	if len(exportedCallers) == 0 {
		return
	}
	slices.SortFunc(exportedCallers, func(x, y *types.Func) int {
		return strings.Compare(x.Name(), y.Name())
	})
	varKey := syntaxutil.DynamicVarKey(baseVar)
	for _, cur := range exportedCallers {
		expKey := syntaxutil.FuncKey{Pkg: a.p.Types.Path(), Name: cur.Name()}
		esk := exportedSeamKey{fn: expKey, key: varKey}
		if sIdx, exists := a.exportedSeamIdx[esk]; exists {
			if viaCleanup {
				a.res.ExportedSeams[sIdx].RunnerOnly = true
			}
		} else {
			a.exportedSeamIdx[esk] = len(a.res.ExportedSeams)
			a.res.ExportedSeams = append(a.res.ExportedSeams, syntaxutil.ExportedSeam{
				Func:       expKey,
				Key:        varKey,
				RunnerOnly: viaCleanup,
			})
		}
		mk := exportedSeamMarkKey{fn: expKey, key: varKey, pos: writePos}
		if !a.seenExportedMark[mk] {
			a.seenExportedMark[mk] = true
			a.res.ExportedSeamSites = append(a.res.ExportedSeamSites, ExportedSeamSite{
				Func: expKey,
				Key:  varKey,
				Pos:  writePos,
			})
		}
	}
}

func (a *bracketedSeamAnalyzer) collectAddrTakenAndUninitDecls() {
	p := a.p
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					ast.Inspect(node.X, func(inner ast.Node) bool {
						if id, ok := inner.(*ast.Ident); ok {
							if obj, ok := a.resolve(id); ok {
								if v, ok := obj.(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
									a.addrTaken[v] = true
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
									a.ptrMethodOnVar[v] = true
								}
							}
						}
					}
				}
			}
			return true
		})
	}
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
					if v, ok := p.TypesInfo.Defs[name].(*types.Var); ok && v != nil && !v.Exported() && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() && !a.addrTaken[v] {
						a.uninitDecls[v] = true
					}
				}
			}
		}
	}
	var initHelpers map[string]bool
	if a.idx != nil && a.idx.InitOnly != nil {
		initHelpers = a.idx.InitOnly
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
								if obj, ok := a.resolve(id); ok {
									if v, ok := obj.(*types.Var); ok {
										delete(a.uninitDecls, v)
									}
								}
							}
							return true
						})
					}
				case *ast.CallExpr:
					if sel, ok := ast.Unparen(n.Fun).(*ast.SelectorExpr); ok {
						if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
							if obj, ok := a.resolve(id); ok {
								if v, ok := obj.(*types.Var); ok {
									delete(a.uninitDecls, v)
								}
							}
						}
					}
				}
				return true
			})
		}
	}
}

func (a *bracketedSeamAnalyzer) isAbortCall(call *ast.CallExpr) bool {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		if b, ok := a.p.TypesInfo.Uses[fun].(*types.Builtin); ok && b.Name() == "panic" {
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

func (a *bracketedSeamAnalyzer) iifeBodyMayAbort(body *ast.BlockStmt) bool {
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
			if a.isAbortCall(node) {
				aborts = true
				return false
			}
			if !deferredOrGo[node] {
				if lit, ok := ast.Unparen(node.Fun).(*ast.FuncLit); ok && a.iifeBodyMayAbort(lit.Body) {
					aborts = true
					return false
				}
			}
		}
		return true
	})
	return aborts
}

func (a *bracketedSeamAnalyzer) stmtMayExitBeforeRestore(stmt ast.Stmt) bool {
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
			if a.isAbortCall(n) {
				exits = true
				return false
			}
			if !deferredOrGo[n] {
				if lit, ok := ast.Unparen(n.Fun).(*ast.FuncLit); ok && a.iifeBodyMayAbort(lit.Body) {
					exits = true
					return false
				}
			}
		}
		return true
	})
	return exits
}
