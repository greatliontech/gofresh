package seams

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type parParamKey struct {
	fn  *types.Func
	idx int
}

type ifaceSlotKey struct {
	name string
	idx  int
}

type stdValueFunc struct {
	origSig *types.Signature
	instSig *types.Signature
}

type parGraph struct {
	p          *packages.Package
	stdPaths   map[string]bool
	allDecls   map[*types.Func]*ast.FuncDecl
	plainDecls map[*types.Func]*ast.FuncDecl

	adj        [][]int
	reachesPar []bool
	rootKeys   []syntaxutil.FuncKey
	adjLarge   map[int]map[int]bool

	directNamedMethodsCache map[*types.Named][]*types.Func
	typeMethodsCache        map[types.Type][]*types.Func
	mayCarryParCache        map[types.Type]bool
	typeParamsCache         map[types.Type][]*types.TypeParam
	mayCarryAliasCache      map[types.Type]bool
	stdParamWriteCache      map[types.Type]bool

	anyDirectCalleeIdent   map[*ast.Ident]bool
	directCallFuncLits     map[*ast.FuncLit]bool
	valueTakenDeclFuncs    map[*types.Func]bool
	valueTakenCrossSigs    map[syntaxutil.FuncKey]*types.Signature
	valueTakenStdFuncs     []stdValueFunc
	hasGenericRecvDeclFunc bool

	typeParamObjIDs         map[*types.TypeParam]int
	typeParamIDs            map[parParamKey]int
	recvTypeParamIDs        map[parParamKey]int
	execIDs                 map[*types.Func]int
	varIDs                  map[*types.Var]int
	varWriteThroughIDs      map[*types.Var]int
	returnIDs               map[*types.Func]int
	returnWriteIDs          map[*types.Func]int
	litReturnWriteIDs       map[*ast.FuncLit]int
	recvIDs                 map[*types.Func]int
	recvWriteIDs            map[*types.Func]int
	paramIDs                map[parParamKey]int
	paramWriteIDs           map[parParamKey]int
	crossIDs                map[syntaxutil.FuncKey]int
	unexpIfaceRecvHubs      map[string]int
	unexpIfaceRecvWriteHubs map[string]int
	unexpIfaceHubs          map[ifaceSlotKey]int
	unexpIfaceWriteHubs     map[ifaceSlotKey]int
	unexpIfaceRetWriteHubs  map[string]int
	typeHubs                map[types.Type]int
	subtreeIDs              map[ast.Node]int
	exprWTMemo              map[ast.Expr][]int
	addrTargetsMemo         map[ast.Node][]int
}

func newParGraph(p *packages.Package, stdPaths map[string]bool, allDecls, plainDecls map[*types.Func]*ast.FuncDecl) *parGraph {
	return &parGraph{
		p:                       p,
		stdPaths:                stdPaths,
		allDecls:                allDecls,
		plainDecls:              plainDecls,
		adjLarge:                map[int]map[int]bool{},
		directNamedMethodsCache: map[*types.Named][]*types.Func{},
		typeMethodsCache:        map[types.Type][]*types.Func{},
		mayCarryParCache:        map[types.Type]bool{},
		typeParamsCache:         map[types.Type][]*types.TypeParam{},
		mayCarryAliasCache:      map[types.Type]bool{},
		stdParamWriteCache:      map[types.Type]bool{},
		anyDirectCalleeIdent:    map[*ast.Ident]bool{},
		directCallFuncLits:      map[*ast.FuncLit]bool{},
		valueTakenDeclFuncs:     map[*types.Func]bool{},
		valueTakenCrossSigs:     map[syntaxutil.FuncKey]*types.Signature{},
		typeParamObjIDs:         map[*types.TypeParam]int{},
		typeParamIDs:            map[parParamKey]int{},
		recvTypeParamIDs:        map[parParamKey]int{},
		execIDs:                 map[*types.Func]int{},
		varIDs:                  map[*types.Var]int{},
		varWriteThroughIDs:      map[*types.Var]int{},
		returnIDs:               map[*types.Func]int{},
		returnWriteIDs:          map[*types.Func]int{},
		litReturnWriteIDs:       map[*ast.FuncLit]int{},
		recvIDs:                 map[*types.Func]int{},
		recvWriteIDs:            map[*types.Func]int{},
		paramIDs:                map[parParamKey]int{},
		paramWriteIDs:           map[parParamKey]int{},
		crossIDs:                map[syntaxutil.FuncKey]int{},
		unexpIfaceRecvHubs:      map[string]int{},
		unexpIfaceRecvWriteHubs: map[string]int{},
		unexpIfaceHubs:          map[ifaceSlotKey]int{},
		unexpIfaceWriteHubs:     map[ifaceSlotKey]int{},
		unexpIfaceRetWriteHubs:  map[string]int{},
		typeHubs:                map[types.Type]int{},
		subtreeIDs:              map[ast.Node]int{},
		exprWTMemo:              map[ast.Expr][]int{},
		addrTargetsMemo:         map[ast.Node][]int{},
	}
}

func (g *parGraph) isStdPkg(pkg *types.Package) bool {
	return pkg == nil || g.stdPaths[pkg.Path()]
}

func (g *parGraph) isStdCallee(callee *types.Func) bool {
	return callee == nil || g.isStdPkg(callee.Pkg())
}

func (g *parGraph) newNode() int {
	id := len(g.adj)
	g.adj = append(g.adj, nil)
	g.reachesPar = append(g.reachesPar, false)
	g.rootKeys = append(g.rootKeys, syntaxutil.FuncKey{})
	return id
}

func (g *parGraph) addParEdge(from, to int) {
	if from < 0 || to < 0 || from == to {
		return
	}
	row := g.adj[from]
	if large := g.adjLarge[from]; large != nil {
		if large[to] {
			return
		}
		large[to] = true
		g.adj[from] = append(row, to)
		return
	}
	for _, existing := range row {
		if existing == to {
			return
		}
	}
	if len(row) == 32 {
		m := make(map[int]bool, 64)
		for _, existing := range row {
			m[existing] = true
		}
		m[to] = true
		g.adjLarge[from] = m
	}
	g.adj[from] = append(row, to)
}

func (g *parGraph) directNamedMethods(named *types.Named) []*types.Func {
	if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil {
		return nil
	}
	if cached, ok := g.directNamedMethodsCache[named]; ok {
		return cached
	}
	switch named.Underlying().(type) {
	case *types.Interface, *types.TypeParam:
		g.directNamedMethodsCache[named] = nil
		return nil
	}
	seen := map[*types.Func]bool{}
	var methods []*types.Func
	addMethod := func(m *types.Func) {
		if m == nil || m.Pkg() == nil {
			return
		}
		m = m.Origin()
		if m.Name() == "Parallel" || seen[m] {
			return
		}
		if g.p.Types != nil && m.Pkg() != g.p.Types && !m.Exported() {
			return
		}
		seen[m] = true
		methods = append(methods, m)
	}
	for _, ms := range []*types.MethodSet{
		types.NewMethodSet(types.NewPointer(named)),
		types.NewMethodSet(named),
	} {
		for i := 0; i < ms.Len(); i++ {
			if m, ok := ms.At(i).Obj().(*types.Func); ok {
				addMethod(m)
			}
		}
	}
	for i := 0; i < named.NumMethods(); i++ {
		addMethod(named.Method(i))
	}
	g.directNamedMethodsCache[named] = methods
	return methods
}

func (g *parGraph) collectTypeMethods(root types.Type) []*types.Func {
	if root == nil {
		return nil
	}
	if _, isBasic := root.(*types.Basic); isBasic {
		return nil
	}
	if cached, ok := g.typeMethodsCache[root]; ok {
		return cached
	}
	visited := map[types.Type]bool{}
	seen := map[*types.Func]bool{}
	var methods []*types.Func
	addMethods := func(ms []*types.Func) {
		for _, m := range ms {
			if !seen[m] {
				seen[m] = true
				methods = append(methods, m)
			}
		}
	}
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || visited[t] {
			return
		}
		visited[t] = true
		switch u := t.(type) {
		case *types.Basic:
			return
		case *types.Alias:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					walk(targs.At(i))
				}
			}
			walk(types.Unalias(u))
		case *types.Named:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					walk(targs.At(i))
				}
			}
			if u.Obj() != nil && u.Obj().Pkg() != nil && u.Obj().Pkg() != g.p.Types && g.isStdPkg(u.Obj().Pkg()) {
				return
			}
			addMethods(g.directNamedMethods(u))
			walk(u.Underlying())
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				walk(u.At(i).Type())
			}
		case *types.Signature:
			if u.Recv() != nil {
				walk(u.Recv().Type())
			}
			walk(u.Params())
			walk(u.Results())
		case *types.Interface:
			for i := 0; i < u.NumExplicitMethods(); i++ {
				walk(u.ExplicitMethod(i).Type())
			}
			for i := 0; i < u.NumEmbeddeds(); i++ {
				walk(u.EmbeddedType(i))
			}
		case *types.TypeParam:
			walk(u.Constraint())
		case *types.Union:
			for i := 0; i < u.Len(); i++ {
				if term := u.Term(i); term != nil {
					walk(term.Type())
				}
			}
		}
	}
	walk(root)
	g.typeMethodsCache[root] = methods
	return methods
}

func (g *parGraph) typeMayCarryParallel(root types.Type) bool {
	if root == nil {
		return false
	}
	if b, isBasic := root.(*types.Basic); isBasic {
		return b.Kind() == types.UnsafePointer
	}
	if cached, ok := g.mayCarryParCache[root]; ok {
		return cached
	}
	if concreteTestingHandleKind(root) != "" {
		g.mayCarryParCache[root] = false
		return false
	}
	visited := map[types.Type]bool{}
	var walk func(t types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil || visited[t] {
			return false
		}
		if concreteTestingHandleKind(t) != "" {
			return false
		}
		visited[t] = true
		switch u := t.(type) {
		case *types.Basic:
			return u.Kind() == types.UnsafePointer
		case *types.Signature, *types.Interface, *types.TypeParam:
			return true
		case *types.Alias:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					if walk(targs.At(i)) {
						return true
					}
				}
			}
			return walk(types.Unalias(u))
		case *types.Named:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					if walk(targs.At(i)) {
						return true
					}
				}
			}
			return walk(u.Underlying())
		case *types.Pointer:
			return walk(u.Elem())
		case *types.Slice:
			return walk(u.Elem())
		case *types.Array:
			return walk(u.Elem())
		case *types.Chan:
			return walk(u.Elem())
		case *types.Map:
			return walk(u.Key()) || walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if walk(u.Field(i).Type()) {
					return true
				}
			}
			return false
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				if walk(u.At(i).Type()) {
					return true
				}
			}
			return false
		case *types.Union:
			for i := 0; i < u.Len(); i++ {
				if term := u.Term(i); term != nil && walk(term.Type()) {
					return true
				}
			}
			return false
		}
		return false
	}
	res := walk(root)
	g.mayCarryParCache[root] = res
	return res
}

func (g *parGraph) collectTypeParams(root types.Type) []*types.TypeParam {
	if root == nil {
		return nil
	}
	if _, isBasic := root.(*types.Basic); isBasic {
		return nil
	}
	if cached, ok := g.typeParamsCache[root]; ok {
		return cached
	}
	visited := map[types.Type]bool{}
	seen := map[*types.TypeParam]bool{}
	var tps []*types.TypeParam
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || visited[t] {
			return
		}
		visited[t] = true
		switch u := t.(type) {
		case *types.Basic:
			return
		case *types.TypeParam:
			if !seen[u] {
				seen[u] = true
				tps = append(tps, u)
			}
			walk(u.Constraint())
		case *types.Alias:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					walk(targs.At(i))
				}
			}
			walk(types.Unalias(u))
		case *types.Named:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					walk(targs.At(i))
				}
			}
			if u.Obj() != nil && u.Obj().Pkg() != nil && u.Obj().Pkg() != g.p.Types && g.isStdPkg(u.Obj().Pkg()) {
				return
			}
			walk(u.Underlying())
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Chan:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				walk(u.At(i).Type())
			}
		case *types.Signature:
			if u.Recv() != nil {
				walk(u.Recv().Type())
			}
			walk(u.Params())
			walk(u.Results())
		case *types.Interface:
			for i := 0; i < u.NumExplicitMethods(); i++ {
				walk(u.ExplicitMethod(i).Type())
			}
			for i := 0; i < u.NumEmbeddeds(); i++ {
				walk(u.EmbeddedType(i))
			}
		case *types.Union:
			for i := 0; i < u.Len(); i++ {
				if term := u.Term(i); term != nil {
					walk(term.Type())
				}
			}
		}
	}
	walk(root)
	g.typeParamsCache[root] = tps
	return tps
}

func forEachCallableSignature(root types.Type, visit func(*types.Signature)) {
	if root == nil {
		return
	}
	if sig, ok := types.Unalias(root).Underlying().(*types.Signature); ok {
		if sig != nil {
			visit(sig)
		}
		return
	}
	var visited map[types.Type]bool
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || visited[t] {
			return
		}
		switch u := t.(type) {
		case *types.Alias:
			if visited == nil {
				visited = map[types.Type]bool{}
			}
			visited[t] = true
			walk(types.Unalias(u))
		case *types.Named:
			if visited == nil {
				visited = map[types.Type]bool{}
			}
			visited[t] = true
			walk(u.Underlying())
		case *types.TypeParam:
			if visited == nil {
				visited = map[types.Type]bool{}
			}
			visited[t] = true
			walk(u.Constraint())
		case *types.Interface:
			if u.NumEmbeddeds() == 0 {
				return
			}
			if visited == nil {
				visited = map[types.Type]bool{}
			}
			visited[t] = true
			for i := 0; i < u.NumEmbeddeds(); i++ {
				walk(u.EmbeddedType(i))
			}
		case *types.Union:
			if visited == nil {
				visited = map[types.Type]bool{}
			}
			visited[t] = true
			for i := 0; i < u.Len(); i++ {
				if term := u.Term(i); term != nil {
					walk(term.Type())
				}
			}
		case *types.Signature:
			visit(u)
		}
	}
	walk(root)
}

func (g *parGraph) typeMayCarryMutableAlias(root types.Type) bool {
	if root == nil {
		return false
	}
	if b, isBasic := root.(*types.Basic); isBasic {
		return b.Kind() == types.UnsafePointer
	}
	if cached, ok := g.mayCarryAliasCache[root]; ok {
		return cached
	}
	if !g.typeMayCarryParallel(root) {
		g.mayCarryAliasCache[root] = false
		return false
	}
	visited := map[types.Type]bool{}
	var walk func(t types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil || visited[t] || concreteTestingHandleKind(t) != "" {
			return false
		}
		visited[t] = true
		switch u := t.(type) {
		case *types.Basic:
			return u.Kind() == types.UnsafePointer
		case *types.Signature:
			if u.Results() != nil {
				for i := 0; i < u.Results().Len(); i++ {
					if walk(u.Results().At(i).Type()) {
						return true
					}
				}
			}
			if u.Params() != nil {
				for i := 0; i < u.Params().Len(); i++ {
					matched := false
					forEachCallableSignature(u.Params().At(i).Type(), func(cbSig *types.Signature) {
						if matched || cbSig.Params() == nil {
							return
						}
						for j := 0; j < cbSig.Params().Len(); j++ {
							if walk(cbSig.Params().At(j).Type()) {
								matched = true
								return
							}
						}
					})
					if matched {
						return true
					}
				}
			}
			return false
		case *types.Pointer, *types.Map, *types.Slice, *types.Chan, *types.Interface, *types.TypeParam:
			return true
		case *types.Alias:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					if walk(targs.At(i)) {
						return true
					}
				}
			}
			return walk(types.Unalias(u))
		case *types.Named:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					if walk(targs.At(i)) {
						return true
					}
				}
			}
			return walk(u.Underlying())
		case *types.Array:
			return walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if walk(u.Field(i).Type()) {
					return true
				}
			}
			return false
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				if walk(u.At(i).Type()) {
					return true
				}
			}
			return false
		case *types.Union:
			for i := 0; i < u.Len(); i++ {
				if term := u.Term(i); term != nil && walk(term.Type()) {
					return true
				}
			}
			return false
		}
		return false
	}
	res := walk(root)
	g.mayCarryAliasCache[root] = res
	return res
}

func (g *parGraph) funcMayReturnMutableAlias(sig *types.Signature) bool {
	if sig == nil || sig.Results() == nil {
		return false
	}
	for i := 0; i < sig.Results().Len(); i++ {
		if g.typeMayCarryMutableAlias(sig.Results().At(i).Type()) {
			return true
		}
	}
	return false
}

func (g *parGraph) stdParamMayAcceptCarrierWrite(root types.Type) bool {
	if root == nil {
		return false
	}
	if b, isBasic := root.(*types.Basic); isBasic {
		return b.Kind() == types.UnsafePointer
	}
	if cached, ok := g.stdParamWriteCache[root]; ok {
		return cached
	}
	visited := map[types.Type]bool{}
	var walk func(t types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil || visited[t] || concreteTestingHandleKind(t) != "" {
			return false
		}
		visited[t] = true
		switch u := t.(type) {
		case *types.Basic:
			return u.Kind() == types.UnsafePointer
		case *types.Signature:
			if u.Results() != nil {
				for i := 0; i < u.Results().Len(); i++ {
					if walk(u.Results().At(i).Type()) {
						return true
					}
				}
			}
			if u.Params() != nil {
				for i := 0; i < u.Params().Len(); i++ {
					matched := false
					forEachCallableSignature(u.Params().At(i).Type(), func(cbSig *types.Signature) {
						if matched || cbSig.Params() == nil {
							return
						}
						for j := 0; j < cbSig.Params().Len(); j++ {
							if walk(cbSig.Params().At(j).Type()) {
								matched = true
								return
							}
						}
					})
					if matched {
						return true
					}
				}
			}
			return false
		case *types.Pointer, *types.Map, *types.Slice, *types.Chan:
			return true
		case *types.TypeParam:
			return walk(u.Constraint())
		case *types.Interface:
			for i := 0; i < u.NumEmbeddeds(); i++ {
				if walk(u.EmbeddedType(i)) {
					return true
				}
			}
			for i := 0; i < u.NumExplicitMethods(); i++ {
				if mSig, ok := u.ExplicitMethod(i).Type().(*types.Signature); ok && mSig != nil && mSig.Params() != nil {
					for j := 0; j < mSig.Params().Len(); j++ {
						if g.typeMayCarryParallel(mSig.Params().At(j).Type()) {
							return true
						}
					}
				}
			}
			return false
		case *types.Alias:
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					if walk(targs.At(i)) {
						return true
					}
				}
			}
			return walk(types.Unalias(u))
		case *types.Named:
			if obj := u.Obj(); obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "context" && obj.Name() == "Context" {
				return false
			}
			if targs := u.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					if walk(targs.At(i)) {
						return true
					}
				}
			}
			return walk(u.Underlying())
		case *types.Array:
			return walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if walk(u.Field(i).Type()) {
					return true
				}
			}
			return false
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				if walk(u.At(i).Type()) {
					return true
				}
			}
			return false
		case *types.Union:
			for i := 0; i < u.Len(); i++ {
				if term := u.Term(i); term != nil && walk(term.Type()) {
					return true
				}
			}
			return false
		}
		return false
	}
	res := walk(root)
	g.stdParamWriteCache[root] = res
	return res
}

func isInterfaceMethodSelection(selInfo *types.Selection, fn *types.Func) bool {
	if selInfo != nil && types.IsInterface(selInfo.Recv()) {
		return true
	}
	if fn != nil {
		if sig, ok := fn.Type().(*types.Signature); ok && sig != nil && sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) {
			return true
		}
	}
	return false
}

