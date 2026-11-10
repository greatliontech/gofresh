// Package refconfine provides the unified package syntax and call-site index
// (PkgIndex, CallSiteIndex), dynamic-carrier and mutable-reference type
// classifiers, and the read-only reference confinement verifier
// (VerifyReadOnlyRefConfinement) shared by dynamic-state fact derivation,
// structural discharges, and protobuf/fresh-struct verifiers.
package refconfine

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// PkgIndex holds the precomputed AST, type-use, call-site, and confinement
// invariants of a type-checked package so intra-package dynamic-state and
// confinement passes do not repeatedly walk p.Syntax.
type PkgIndex struct {
	VarSpecs                 map[*types.Var]*ast.ValueSpec
	VarGenDecls              map[*types.Var]*ast.GenDecl
	DefCounts                map[types.Object]int
	UsesOf                   map[types.Object][]*ast.Ident
	ParentMap                map[ast.Node]ast.Node
	EnclFunc                 map[ast.Node]*ast.FuncDecl
	InFuncLit                map[ast.Node]bool
	InGoStmt                 map[ast.Node]bool
	FuncDecls                map[*types.Func]*ast.FuncDecl
	PlainByName              map[string][]*ast.FuncDecl
	InitBlocks               []*ast.BlockStmt
	FuncValueTaken           map[*types.Func]bool
	CalleeIdents             map[*ast.Ident]bool
	CalledMethodSels         map[*ast.SelectorExpr]bool
	DeclBodies               map[*types.Func]*ast.BlockStmt
	ReturnEnclFunc           map[*ast.ReturnStmt]*types.Func
	ResultVarFunc            map[*types.Var]*types.Func
	LitResultVars            map[*types.Var]bool
	FreshContainerCandidates map[*types.Var]bool
	CallSites                *CallSiteIndex
	InitOnly                 map[string]bool
	FreshLocalStructVars     map[*ast.FuncDecl]map[*types.Var]token.Pos
}

// CallSiteParam identifies a parameter slot of an unexported plain function.
type CallSiteParam struct {
	Fn       *types.Func
	Index    int
	Variadic bool
}

// CallSiteIndex indexes intra-package unexported plain functions, their
// parameter slots, and their direct call sites across p.Syntax.
type CallSiteIndex struct {
	Info         *types.Info
	Callable     map[string]bool
	FuncParams   map[*types.Func][]types.Object
	Params       map[*types.Var]CallSiteParam
	Written      map[*types.Var]bool
	Escaped      map[*types.Func]bool
	Calls        map[*types.Func][]*ast.CallExpr
	BareCallRefs map[string]map[string]bool
	BareEscaped  map[string]bool
}

// BuildPkgIndex constructs the unified package syntax, call-site, and
// confinement index in a single pass over p.TypesInfo and p.Syntax.
func BuildPkgIndex(p *packages.Package) *PkgIndex {
	if p == nil || p.Types == nil || p.TypesInfo == nil {
		return nil
	}
	info := p.TypesInfo
	idx := &PkgIndex{
		VarSpecs:                 map[*types.Var]*ast.ValueSpec{},
		VarGenDecls:              map[*types.Var]*ast.GenDecl{},
		DefCounts:                map[types.Object]int{},
		UsesOf:                   map[types.Object][]*ast.Ident{},
		ParentMap:                map[ast.Node]ast.Node{},
		EnclFunc:                 map[ast.Node]*ast.FuncDecl{},
		InFuncLit:                map[ast.Node]bool{},
		InGoStmt:                 map[ast.Node]bool{},
		FuncDecls:                map[*types.Func]*ast.FuncDecl{},
		PlainByName:              map[string][]*ast.FuncDecl{},
		FuncValueTaken:           map[*types.Func]bool{},
		CalleeIdents:             map[*ast.Ident]bool{},
		CalledMethodSels:         map[*ast.SelectorExpr]bool{},
		DeclBodies:               map[*types.Func]*ast.BlockStmt{},
		ReturnEnclFunc:           map[*ast.ReturnStmt]*types.Func{},
		ResultVarFunc:            map[*types.Var]*types.Func{},
		LitResultVars:            map[*types.Var]bool{},
		FreshContainerCandidates: map[*types.Var]bool{},
		FreshLocalStructVars:     map[*ast.FuncDecl]map[*types.Var]token.Pos{},
	}
	for id, obj := range info.Defs {
		if id != nil && obj != nil {
			idx.DefCounts[obj]++
		}
	}
	for id, obj := range info.Uses {
		if id != nil && obj != nil {
			idx.UsesOf[obj] = append(idx.UsesOf[obj], id)
		}
	}

	sigVars := map[*types.Var]bool{}
	recordFieldList := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, nm := range f.Names {
				if v, ok := info.Defs[nm].(*types.Var); ok && v != nil {
					sigVars[v] = true
				}
			}
		}
	}
	recordFuncResults := func(ft *ast.FuncType, fn *types.Func) {
		if ft == nil || ft.Results == nil {
			return
		}
		for _, field := range ft.Results.List {
			for _, nm := range field.Names {
				if v, ok := info.Defs[nm].(*types.Var); ok && v != nil {
					if fn != nil {
						idx.ResultVarFunc[v] = fn
					} else {
						idx.LitResultVars[v] = true
					}
				}
			}
		}
	}

	for _, file := range p.Syntax {
		var stack []ast.Node
		var curFD *ast.FuncDecl
		var curFnStack []*types.Func
		litDepth := 0
		goDepth := 0
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				curr := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				switch curr.(type) {
				case *ast.FuncLit:
					litDepth--
					curFnStack = curFnStack[:len(curFnStack)-1]
				case *ast.GoStmt:
					goDepth--
				case *ast.FuncDecl:
					curFD = nil
					curFnStack = curFnStack[:len(curFnStack)-1]
				}
				return false
			}
			if len(stack) > 0 {
				idx.ParentMap[n] = stack[len(stack)-1]
			}
			if curFD != nil {
				idx.EnclFunc[n] = curFD
			}
			if litDepth > 0 {
				idx.InFuncLit[n] = true
			}
			if goDepth > 0 {
				idx.InGoStmt[n] = true
			}
			var activeFn *types.Func
			if len(curFnStack) > 0 {
				activeFn = curFnStack[len(curFnStack)-1]
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				litDepth++
				idx.InFuncLit[x] = true
				curFnStack = append(curFnStack, nil)
				if x.Type != nil {
					recordFieldList(x.Type.Params)
					recordFieldList(x.Type.Results)
				}
				recordFuncResults(x.Type, nil)
			case *ast.GoStmt:
				goDepth++
				idx.InGoStmt[x] = true
			case *ast.FuncDecl:
				curFD = x
				idx.EnclFunc[x] = x
				var fn *types.Func
				if x.Name != nil {
					if defFn, ok := info.Defs[x.Name].(*types.Func); ok && defFn != nil {
						idx.FuncDecls[defFn] = x
						if !(x.Recv == nil && x.Name.Name == "init") {
							fn = defFn
							if x.Body != nil {
								idx.DeclBodies[fn] = x.Body
							}
						}
					}
				}
				curFnStack = append(curFnStack, fn)
				recordFieldList(x.Recv)
				if x.Type != nil {
					recordFieldList(x.Type.Params)
					recordFieldList(x.Type.Results)
				}
				recordFuncResults(x.Type, fn)
				if x.Recv == nil && x.Name != nil {
					idx.PlainByName[x.Name.Name] = append(idx.PlainByName[x.Name.Name], x)
					if x.Name.Name == "init" && x.Body != nil {
						idx.InitBlocks = append(idx.InitBlocks, x.Body)
					}
				}
			case *ast.ReturnStmt:
				idx.ReturnEnclFunc[x] = activeFn
			case *ast.CallExpr:
				if !info.Types[ast.Unparen(x.Fun)].IsType() {
					switch fun := ast.Unparen(x.Fun).(type) {
					case *ast.Ident:
						idx.CalleeIdents[fun] = true
					case *ast.SelectorExpr:
						selInfo := info.Selections[fun]
						if selInfo == nil || selInfo.Kind() != types.MethodExpr {
							if fun.Sel != nil {
								idx.CalleeIdents[fun.Sel] = true
							}
						}
						if selInfo != nil && selInfo.Kind() == types.MethodVal {
							idx.CalledMethodSels[fun] = true
						}
					}
				}
			}
			stack = append(stack, n)
			return true
		})

		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, nm := range vs.Names {
					if v, ok := info.Defs[nm].(*types.Var); ok && v != nil {
						idx.VarSpecs[v] = vs
						idx.VarGenDecls[v] = gd
					}
				}
			}
		}
	}

	for id, obj := range info.Uses {
		if id == nil || idx.CalleeIdents[id] {
			continue
		}
		if fn, ok := obj.(*types.Func); ok && fn != nil && fn.Pkg() == p.Types {
			idx.FuncValueTaken[fn.Origin()] = true
		}
	}

	populateFreshContainerCandidates(p, sigVars, idx.FreshContainerCandidates)
	idx.CallSites = BuildCallSiteIndex(p)
	idx.InitOnly = idx.CallSites.InitOnlyHelpers()
	return idx
}

func populateFreshContainerCandidates(p *packages.Package, sigVars map[*types.Var]bool, out map[*types.Var]bool) {
	info := p.TypesInfo
	candidates := map[*types.Var]bool{}
	disqualified := map[*types.Var]bool{}

	isFreshInit := func(v *types.Var, rhs ast.Expr) bool {
		rhs = ast.Unparen(rhs)
		if syntaxutil.IsNilIdent(info, rhs) {
			return true
		}
		switch e := rhs.(type) {
		case *ast.CompositeLit:
			if t := info.TypeOf(e); t != nil {
				switch types.Unalias(t).Underlying().(type) {
				case *types.Slice, *types.Array, *types.Map:
					return true
				}
			}
		case *ast.CallExpr:
			if id, isID := ast.Unparen(e.Fun).(*ast.Ident); isID {
				if b, isB := info.Uses[id].(*types.Builtin); isB {
					if b.Name() == "make" {
						return true
					}
					if b.Name() == "append" && len(e.Args) > 0 && syntaxutil.LookupIdentVar(info, e.Args[0]) == v {
						return true
					}
				}
			}
		}
		return false
	}

	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.ValueSpec:
				if len(s.Values) == 0 {
					for _, nm := range s.Names {
						if v, ok := info.Defs[nm].(*types.Var); ok && v != nil && v.Parent() != nil && v.Parent() != p.Types.Scope() && !sigVars[v] {
							candidates[v] = true
						}
					}
				} else if len(s.Names) == len(s.Values) {
					for i, nm := range s.Names {
						v, ok := info.Defs[nm].(*types.Var)
						if !ok || v == nil || v.Parent() == nil || v.Parent() == p.Types.Scope() || sigVars[v] {
							continue
						}
						candidates[v] = true
						if !isFreshInit(v, s.Values[i]) {
							disqualified[v] = true
						}
					}
				} else {
					for _, nm := range s.Names {
						if v, ok := info.Defs[nm].(*types.Var); ok && v != nil {
							disqualified[v] = true
						}
					}
				}

			case *ast.AssignStmt:
				if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
					for _, lhs := range s.Lhs {
						if v := syntaxutil.LookupIdentVar(info, lhs); v != nil {
							disqualified[v] = true
						}
					}
					return true
				}
				if len(s.Lhs) == len(s.Rhs) {
					for i, lhs := range s.Lhs {
						var v *types.Var
						if id, isID := ast.Unparen(lhs).(*ast.Ident); isID {
							if defV, ok := info.Defs[id].(*types.Var); ok && defV != nil {
								v = defV
							} else {
								v = syntaxutil.LookupIdentVar(info, id)
							}
						}
						if v == nil || v.Parent() == nil || v.Parent() == p.Types.Scope() || sigVars[v] {
							continue
						}
						candidates[v] = true
						if !isFreshInit(v, s.Rhs[i]) {
							disqualified[v] = true
						}
					}
				} else {
					for _, lhs := range s.Lhs {
						if id, isID := ast.Unparen(lhs).(*ast.Ident); isID {
							if defV, ok := info.Defs[id].(*types.Var); ok && defV != nil {
								disqualified[defV] = true
							} else if useV := syntaxutil.LookupIdentVar(info, id); useV != nil {
								disqualified[useV] = true
							}
						}
					}
				}

			case *ast.RangeStmt:
				for _, be := range []ast.Expr{s.Key, s.Value} {
					if id, isID := ast.Unparen(be).(*ast.Ident); isID {
						if defV, ok := info.Defs[id].(*types.Var); ok && defV != nil {
							disqualified[defV] = true
						} else if useV := syntaxutil.LookupIdentVar(info, id); useV != nil {
							disqualified[useV] = true
						}
					}
				}

			case *ast.UnaryExpr:
				if s.Op == token.AND {
					cur := ast.Unparen(s.X)
					for {
						switch inner := cur.(type) {
						case *ast.IndexExpr:
							cur = ast.Unparen(inner.X)
							continue
						case *ast.SliceExpr:
							cur = ast.Unparen(inner.X)
							continue
						case *ast.SelectorExpr:
							cur = ast.Unparen(inner.X)
							continue
						}
						break
					}
					if v := syntaxutil.LookupIdentVar(info, cur); v != nil {
						disqualified[v] = true
					}
				}
			}
			return true
		})
	}

	for v := range candidates {
		if !disqualified[v] {
			out[v] = true
		}
	}
}

// ParentUnparen returns the closest non-parenthesized ancestor of n in idx.ParentMap.
func (idx *PkgIndex) ParentUnparen(n ast.Node) ast.Node {
	cur := n
	for {
		par := idx.ParentMap[cur]
		if _, ok := par.(*ast.ParenExpr); ok {
			cur = par
			continue
		}
		return par
	}
}

// SyncEnclFuncDecl returns n's enclosing *ast.FuncDecl only when n executes
// synchronously inside that declaration without crossing a nested *ast.FuncLit
// or *ast.GoStmt boundary.
func (idx *PkgIndex) SyncEnclFuncDecl(n ast.Node) *ast.FuncDecl {
	if idx.InFuncLit[n] || idx.InGoStmt[n] {
		return nil
	}
	return idx.EnclFunc[n]
}

// IsSyncInFuncDecl reports whether n executes synchronously inside fd.
func (idx *PkgIndex) IsSyncInFuncDecl(n ast.Node, fd *ast.FuncDecl) bool {
	return fd != nil && idx.EnclFunc[n] == fd && !idx.InFuncLit[n] && !idx.InGoStmt[n]
}

// EnclosingTopStmt returns the top-level statement in body enclosing n, or nil.
func (idx *PkgIndex) EnclosingTopStmt(body *ast.BlockStmt, n ast.Node) ast.Stmt {
	cur := n
	for cur != nil && cur != body {
		par := idx.ParentMap[cur]
		if par == body {
			st, _ := cur.(ast.Stmt)
			return st
		}
		cur = par
	}
	return nil
}

// BuildCallSiteIndex constructs the intra-package direct call-site index for p.
func BuildCallSiteIndex(p *packages.Package) *CallSiteIndex {
	var info *types.Info
	if p != nil {
		info = p.TypesInfo
	}
	idx := &CallSiteIndex{
		Info:         info,
		Callable:     map[string]bool{},
		FuncParams:   map[*types.Func][]types.Object{},
		Params:       map[*types.Var]CallSiteParam{},
		Written:      map[*types.Var]bool{},
		Escaped:      map[*types.Func]bool{},
		Calls:        map[*types.Func][]*ast.CallExpr{},
		BareCallRefs: map[string]map[string]bool{},
		BareEscaped:  map[string]bool{},
	}
	if p == nil || info == nil {
		return idx
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
			idx.Callable[fd.Name.Name] = true
			position := 0
			var paramObjs []types.Object
			for _, field := range fd.Type.Params.List {
				_, variadic := field.Type.(*ast.Ellipsis)
				for _, name := range field.Names {
					def := info.Defs[name]
					paramObjs = append(paramObjs, def)
					if v, ok := def.(*types.Var); ok {
						idx.Params[v] = CallSiteParam{Fn: fn, Index: position, Variadic: variadic}
					}
					position++
				}
				if len(field.Names) == 0 {
					paramObjs = append(paramObjs, nil)
					position++
				}
			}
			idx.FuncParams[fn] = paramObjs
			if fd.Body == nil {
				continue
			}
			markWritten := func(expr ast.Expr) {
				if ident, ok := expr.(*ast.Ident); ok {
					if v, ok := info.Uses[ident].(*types.Var); ok {
						if _, isParam := idx.Params[v]; isParam {
							idx.Written[v] = true
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
		if idx.BareCallRefs[region] == nil {
			idx.BareCallRefs[region] = map[string]bool{}
		}
		idx.BareCallRefs[region][name] = true
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
				fun := syntaxutil.UnwrapCallee(n.Fun)
				if ident, ok := fun.(*ast.Ident); ok {
					if fn, ok := info.Uses[ident].(*types.Func); ok && callable[fn] {
						idx.Calls[fn] = append(idx.Calls[fn], n)
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
						idx.Escaped[fn] = true
					}
					if !bareCallFun[n] {
						idx.BareEscaped[fn.Name()] = true
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
					case decl.Recv == nil && decl.Name != nil && idx.Callable[decl.Name.Name]:
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

// InitOnlyHelpers returns the set of unexported plain helper function names
// reachable exclusively from package initialization flow.
func (idx *CallSiteIndex) InitOnlyHelpers() map[string]bool {
	if idx == nil || len(idx.Callable) == 0 {
		return nil
	}
	disqualified := map[string]bool{}
	for name := range idx.BareEscaped {
		disqualified[name] = true
	}
	for name := range idx.BareCallRefs["!"] {
		disqualified[name] = true
	}
	for changed := true; changed; {
		changed = false
		for caller, refs := range idx.BareCallRefs {
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
	for name := range idx.Callable {
		if !disqualified[name] {
			qualified[name] = true
		}
	}
	reachable := map[string]bool{}
	var mark func(region string)
	mark = func(region string) {
		for name := range idx.BareCallRefs[region] {
			if qualified[name] && !reachable[name] {
				reachable[name] = true
				mark(name)
			}
		}
	}
	mark("")
	return reachable
}

// FuncParamsOf returns the parameter object slices for functions in names.
func (idx *CallSiteIndex) FuncParamsOf(names map[string]bool) map[*types.Func][]types.Object {
	out := map[*types.Func][]types.Object{}
	if idx == nil {
		return out
	}
	for fn, params := range idx.FuncParams {
		if names[fn.Name()] {
			out[fn] = params
		}
	}
	return out
}

// ResolveParam checks whether expr is an unescaped, unwritten parameter whose
// every intra-package call site argument satisfies judge.
func (idx *CallSiteIndex) ResolveParam(expr ast.Expr, seen map[*types.Var]bool, judge func(arg ast.Expr, seen map[*types.Var]bool) bool) bool {
	if idx == nil || idx.Info == nil {
		return false
	}
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := idx.Info.Uses[ident].(*types.Var)
	if !ok {
		return false
	}
	key, ok := idx.Params[v]
	if !ok || key.Variadic || idx.Written[v] || idx.Escaped[key.Fn] || seen[v] {
		return false
	}
	sites := idx.Calls[key.Fn]
	if len(sites) == 0 {
		return false
	}
	seen[v] = true
	defer delete(seen, v)
	for _, site := range sites {
		if key.Index >= len(site.Args) || !judge(site.Args[key.Index], seen) {
			return false
		}
	}
	return true
}

// JudgeExpr evaluates leaf on expr's type, or recursively resolves intra-package
// parameter arguments when leaf returns decided=false.
func (idx *CallSiteIndex) JudgeExpr(expr ast.Expr, leaf func(types.Type) (decided, ok bool)) bool {
	if idx == nil || idx.Info == nil {
		return false
	}
	var walk func(expr ast.Expr, seen map[*types.Var]bool) bool
	walk = func(expr ast.Expr, seen map[*types.Var]bool) bool {
		expr = ast.Unparen(expr)
		t := idx.Info.TypeOf(expr)
		if t == nil {
			return false
		}
		if decided, ok := leaf(t); decided {
			return ok
		}
		return idx.ResolveParam(expr, seen, walk)
	}
	return walk(expr, map[*types.Var]bool{})
}
