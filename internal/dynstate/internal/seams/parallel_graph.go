package seams

import (
	"go/ast"
	"go/types"
	"strconv"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
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

func (g *parGraph) typeParamID(fn *types.Func, idx int) int {
	if fn == nil || idx < 0 {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.TypeParams() == nil || idx >= sig.TypeParams().Len() {
		return -1
	}
	pk := parParamKey{fn: fn, idx: idx}
	if id, ok := g.typeParamIDs[pk]; ok {
		return id
	}
	id := g.newNode()
	g.typeParamIDs[pk] = id
	g.typeParamObjIDs[sig.TypeParams().At(idx)] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#tp#" + strconv.Itoa(idx)}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) recvTypeParamID(fn *types.Func, idx int) int {
	if fn == nil || idx < 0 {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.RecvTypeParams() == nil || idx >= sig.RecvTypeParams().Len() {
		return -1
	}
	pk := parParamKey{fn: fn, idx: idx}
	if id, ok := g.recvTypeParamIDs[pk]; ok {
		return id
	}
	id := g.newNode()
	g.recvTypeParamIDs[pk] = id
	g.typeParamObjIDs[sig.RecvTypeParams().At(idx)] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#rtp#" + strconv.Itoa(idx)}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) wireTypeParamsOfType(ownerID int, t types.Type) {
	if ownerID < 0 || t == nil || len(g.typeParamObjIDs) == 0 {
		return
	}
	for _, tp := range g.collectTypeParams(t) {
		if tpID, ok := g.typeParamObjIDs[tp]; ok {
			g.addParEdge(ownerID, tpID)
		}
	}
}

func (g *parGraph) execFuncID(fn *types.Func) int {
	if fn == nil {
		return -1
	}
	fn = fn.Origin()
	if id, ok := g.execIDs[fn]; ok {
		return id
	}
	id := g.newNode()
	g.execIDs[fn] = id
	if fn.Exported() || (g.p.Name == "main" && g.plainDecls[fn] != nil && fn.Name() == "main") {
		if fk, ok := syntaxutil.CallableFactKey(fn); ok {
			g.rootKeys[id] = fk
		}
	}
	return id
}

func (g *parGraph) bindVarID(v *types.Var) int {
	if v == nil || !g.typeMayCarryParallel(v.Type()) {
		return -1
	}
	if id, ok := g.varIDs[v]; ok {
		return id
	}
	id := g.newNode()
	g.varIDs[v] = id
	g.wireTypeParamsOfType(id, v.Type())
	if g.p.Types != nil && v.Parent() == g.p.Types.Scope() && v.Exported() && v.Name() != "_" {
		fk := syntaxutil.FuncKey{Pkg: g.p.Types.Path(), Name: v.Name()}
		if fk.Valid() {
			g.rootKeys[id] = fk
		}
	}
	return id
}

func (g *parGraph) varWriteThroughID(v *types.Var) int {
	if v == nil || v.IsField() || v.Name() == "_" || g.p.Types == nil || v.Pkg() != g.p.Types || !g.typeMayCarryMutableAlias(v.Type()) {
		return -1
	}
	if id, ok := g.varWriteThroughIDs[v]; ok {
		return id
	}
	id := g.newNode()
	g.varWriteThroughIDs[v] = id
	g.addParEdge(g.bindVarID(v), id)
	if v.Parent() == g.p.Types.Scope() && v.Exported() {
		fk := syntaxutil.FuncKey{Pkg: g.p.Types.Path(), Name: v.Name() + "#w"}
		if fk.Valid() {
			g.rootKeys[id] = fk
		}
	}
	return id
}

func (g *parGraph) returnID(fn *types.Func) int {
	if fn == nil {
		return -1
	}
	fn = fn.Origin()
	if id, ok := g.returnIDs[fn]; ok {
		return id
	}
	id := g.newNode()
	g.returnIDs[fn] = id
	return id
}

func (g *parGraph) returnWriteID(fn *types.Func) int {
	if fn == nil {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || !g.funcMayReturnMutableAlias(sig) {
		return -1
	}
	if id, ok := g.returnWriteIDs[fn]; ok {
		return id
	}
	id := g.newNode()
	g.returnWriteIDs[fn] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#rw"}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) litReturnWriteID(lit *ast.FuncLit) int {
	if lit == nil {
		return -1
	}
	if id, ok := g.litReturnWriteIDs[lit]; ok {
		return id
	}
	tv, ok := g.p.TypesInfo.Types[lit]
	if !ok || tv.Type == nil {
		return -1
	}
	sig, ok := tv.Type.Underlying().(*types.Signature)
	if !ok || !g.funcMayReturnMutableAlias(sig) {
		return -1
	}
	id := g.newNode()
	g.litReturnWriteIDs[lit] = id
	return id
}

func (g *parGraph) recvID(fn *types.Func) int {
	if fn == nil {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.Recv() == nil || !g.typeMayCarryParallel(sig.Recv().Type()) {
		return -1
	}
	if id, ok := g.recvIDs[fn]; ok {
		return id
	}
	id := g.newNode()
	g.recvIDs[fn] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#recv"}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) recvWriteID(fn *types.Func) int {
	if fn == nil {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.Recv() == nil || !g.typeMayCarryMutableAlias(sig.Recv().Type()) {
		return -1
	}
	if id, ok := g.recvWriteIDs[fn]; ok {
		return id
	}
	id := g.newNode()
	g.recvWriteIDs[fn] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#wrecv"}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) paramID(fn *types.Func, idx int) int {
	if fn == nil || idx < 0 {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.Params() == nil || idx >= sig.Params().Len() || !g.typeMayCarryParallel(sig.Params().At(idx).Type()) {
		return -1
	}
	pk := parParamKey{fn: fn, idx: idx}
	if id, ok := g.paramIDs[pk]; ok {
		return id
	}
	id := g.newNode()
	g.paramIDs[pk] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#" + strconv.Itoa(idx)}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) paramWriteID(fn *types.Func, idx int) int {
	if fn == nil || idx < 0 {
		return -1
	}
	fn = fn.Origin()
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig == nil || sig.Params() == nil || idx >= sig.Params().Len() || !g.typeMayCarryMutableAlias(sig.Params().At(idx).Type()) {
		return -1
	}
	pk := parParamKey{fn: fn, idx: idx}
	if id, ok := g.paramWriteIDs[pk]; ok {
		return id
	}
	id := g.newNode()
	g.paramWriteIDs[pk] = id
	if fn.Exported() {
		if baseKey, ok := syntaxutil.CallableFactKey(fn); ok {
			fk := syntaxutil.FuncKey{Pkg: baseKey.Pkg, Name: baseKey.Name + "#w#" + strconv.Itoa(idx)}
			if fk.Valid() {
				g.rootKeys[id] = fk
			}
		}
	}
	return id
}

func (g *parGraph) crossID(fk syntaxutil.FuncKey) int {
	if !fk.Valid() {
		return -1
	}
	if id, ok := g.crossIDs[fk]; ok {
		return id
	}
	id := g.newNode()
	g.crossIDs[fk] = id
	g.rootKeys[id] = fk
	return id
}

func (g *parGraph) dynHubID(sig *types.Signature, idx int) int {
	if sig == nil || sig.Params() == nil || idx < 0 {
		return -1
	}
	nRes := 0
	if sig.Results() != nil {
		nRes = sig.Results().Len()
	}
	return g.crossID(syntaxutil.FuncKey{
		Pkg:  "*",
		Name: "#dyn#" + strconv.Itoa(sig.Params().Len()) + ":" + strconv.Itoa(nRes) + "#" + strconv.Itoa(idx),
	})
}

func (g *parGraph) dynHubWriteID(sig *types.Signature, idx int) int {
	if sig == nil || sig.Params() == nil || idx < 0 {
		return -1
	}
	nRes := 0
	if sig.Results() != nil {
		nRes = sig.Results().Len()
	}
	return g.crossID(syntaxutil.FuncKey{
		Pkg:  "*",
		Name: "#dynw#" + strconv.Itoa(sig.Params().Len()) + ":" + strconv.Itoa(nRes) + "#" + strconv.Itoa(idx),
	})
}

func (g *parGraph) dynReturnWriteID(sig *types.Signature) int {
	if !g.funcMayReturnMutableAlias(sig) {
		return -1
	}
	nParams := 0
	if sig.Params() != nil {
		nParams = sig.Params().Len()
	}
	return g.crossID(syntaxutil.FuncKey{
		Pkg:  "*",
		Name: "#dynrw#" + strconv.Itoa(nParams) + ":" + strconv.Itoa(sig.Results().Len()),
	})
}

func (g *parGraph) ifaceRecvID(methodName string) int {
	if methodName == "" {
		return -1
	}
	if ast.IsExported(methodName) {
		return g.crossID(syntaxutil.FuncKey{Pkg: "*", Name: methodName + "#recv"})
	}
	if id, ok := g.unexpIfaceRecvHubs[methodName]; ok {
		return id
	}
	id := g.newNode()
	g.unexpIfaceRecvHubs[methodName] = id
	return id
}

func (g *parGraph) ifaceRecvWriteID(methodName string) int {
	if methodName == "" {
		return -1
	}
	if ast.IsExported(methodName) {
		return g.crossID(syntaxutil.FuncKey{Pkg: "*", Name: methodName + "#wrecv"})
	}
	if id, ok := g.unexpIfaceRecvWriteHubs[methodName]; ok {
		return id
	}
	id := g.newNode()
	g.unexpIfaceRecvWriteHubs[methodName] = id
	return id
}

func (g *parGraph) ifaceHubID(methodName string, idx int) int {
	if methodName == "" || idx < 0 {
		return -1
	}
	if ast.IsExported(methodName) {
		return g.crossID(syntaxutil.FuncKey{Pkg: "*", Name: methodName + "#" + strconv.Itoa(idx)})
	}
	sk := ifaceSlotKey{name: methodName, idx: idx}
	if id, ok := g.unexpIfaceHubs[sk]; ok {
		return id
	}
	id := g.newNode()
	g.unexpIfaceHubs[sk] = id
	return id
}

func (g *parGraph) ifaceHubWriteID(methodName string, idx int) int {
	if methodName == "" || idx < 0 {
		return -1
	}
	if ast.IsExported(methodName) {
		return g.crossID(syntaxutil.FuncKey{Pkg: "*", Name: methodName + "#w#" + strconv.Itoa(idx)})
	}
	sk := ifaceSlotKey{name: methodName, idx: idx}
	if id, ok := g.unexpIfaceWriteHubs[sk]; ok {
		return id
	}
	id := g.newNode()
	g.unexpIfaceWriteHubs[sk] = id
	return id
}

func (g *parGraph) ifaceReturnWriteID(methodName string, sig *types.Signature) int {
	if methodName == "" || !g.funcMayReturnMutableAlias(sig) {
		return -1
	}
	if ast.IsExported(methodName) {
		return g.crossID(syntaxutil.FuncKey{Pkg: "*", Name: methodName + "#rw"})
	}
	if id, ok := g.unexpIfaceRetWriteHubs[methodName]; ok {
		return id
	}
	id := g.newNode()
	g.unexpIfaceRetWriteHubs[methodName] = id
	return id
}

func (g *parGraph) isSamePkgNonFieldVar(obj types.Object) (*types.Var, bool) {
	v, ok := obj.(*types.Var)
	if !ok || v == nil || v.IsField() || v.Name() == "_" || g.p.Types == nil || v.Pkg() != g.p.Types {
		return nil, false
	}
	return v, true
}

func (g *parGraph) targetVarID(v *types.Var) int {
	if v == nil || v.IsField() || v.Pkg() == nil || v.Name() == "_" || !g.typeMayCarryParallel(v.Type()) {
		return -1
	}
	if g.p.Types != nil && v.Pkg() == g.p.Types {
		return g.bindVarID(v)
	}
	if (g.p.Types == nil || v.Pkg() != g.p.Types) && v.Parent() == v.Pkg().Scope() && !g.isStdPkg(v.Pkg()) {
		return g.crossID(syntaxutil.FuncKey{Pkg: v.Pkg().Path(), Name: v.Name()})
	}
	return -1
}

func (g *parGraph) targetVarWriteThroughID(v *types.Var) int {
	if v == nil || v.IsField() || v.Pkg() == nil || v.Name() == "_" || !g.typeMayCarryMutableAlias(v.Type()) {
		return -1
	}
	if g.p.Types != nil && v.Pkg() == g.p.Types {
		return g.varWriteThroughID(v)
	}
	if (g.p.Types == nil || v.Pkg() != g.p.Types) && v.Parent() == v.Pkg().Scope() && !g.isStdPkg(v.Pkg()) {
		return g.crossID(syntaxutil.FuncKey{Pkg: v.Pkg().Path(), Name: v.Name() + "#w"})
	}
	return -1
}

func (g *parGraph) isBareVarExpr(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if e.Name == "_" {
			return true
		}
		v, ok := syntaxutil.IdentDefOrUse(g.p.TypesInfo, e).(*types.Var)
		return ok && v != nil && !v.IsField()
	case *ast.SelectorExpr:
		if g.p.TypesInfo.Selections[e] != nil {
			return false
		}
		v, ok := g.p.TypesInfo.Uses[e.Sel].(*types.Var)
		return ok && v != nil && !v.IsField()
	default:
		return false
	}
}

func (g *parGraph) recordMethodTarget(ownerID int, m *types.Func) {
	if ownerID < 0 || m == nil || m.Pkg() == nil {
		return
	}
	m = m.Origin()
	if g.allDecls[m] != nil {
		g.addParEdge(ownerID, g.execFuncID(m))
	} else if (g.p.Types == nil || m.Pkg() != g.p.Types) && !g.isStdCallee(m) {
		if fk, ok := syntaxutil.CallableFactKey(m); ok {
			g.addParEdge(ownerID, g.crossID(fk))
		}
	}
}

func (g *parGraph) typeHubID(t types.Type) int {
	if t == nil {
		return -1
	}
	if _, isBasic := t.(*types.Basic); isBasic {
		return -1
	}
	if h, ok := g.typeHubs[t]; ok {
		return h
	}
	ms := g.collectTypeMethods(t)
	if len(ms) == 0 {
		g.typeHubs[t] = -1
		return -1
	}
	h := g.newNode()
	g.typeHubs[t] = h
	for _, m := range ms {
		g.recordMethodTarget(h, m)
	}
	return h
}

func (g *parGraph) wireTypeArg(slotID int, targ types.Type) {
	if slotID < 0 || targ == nil {
		return
	}
	g.addParEdge(slotID, g.typeHubID(targ))
	g.wireTypeParamsOfType(slotID, targ)
}

func (g *parGraph) recordObjOnNode(ownerID int, obj types.Object, execOnlyPkgVars bool) {
	if ownerID < 0 || obj == nil {
		return
	}
	g.addParEdge(ownerID, g.typeHubID(obj.Type()))
	switch target := obj.(type) {
	case *types.Func:
		g.recordMethodTarget(ownerID, target)
	case *types.Var:
		if target.IsField() || target.Pkg() == nil || target.Name() == "_" {
			return
		}
		if _, ok := g.isSamePkgNonFieldVar(target); ok {
			if !execOnlyPkgVars || target.Parent() == g.p.Types.Scope() {
				g.addParEdge(ownerID, g.bindVarID(target))
			}
		} else if (g.p.Types == nil || target.Pkg() != g.p.Types) && target.Parent() == target.Pkg().Scope() && !g.isStdPkg(target.Pkg()) {
			g.addParEdge(ownerID, g.crossID(syntaxutil.FuncKey{Pkg: target.Pkg().Path(), Name: target.Name()}))
		}
	}
}

func (g *parGraph) resolveConcreteDeclCallee(call *ast.CallExpr) (*types.Func, *ast.Ident) {
	if tv, isType := g.p.TypesInfo.Types[call.Fun]; isType && tv.IsType() {
		return nil, nil
	}
	switch fun := syntaxutil.UnwrapCallee(call.Fun).(type) {
	case *ast.Ident:
		if fn, ok := g.p.TypesInfo.Uses[fun].(*types.Func); ok && fn != nil {
			fn = fn.Origin()
			if g.allDecls[fn] != nil {
				return fn, fun
			}
		}
	case *ast.SelectorExpr:
		if selInfo, isSel := g.p.TypesInfo.Selections[fun]; isSel && selInfo != nil {
			if selInfo.Kind() == types.MethodVal || selInfo.Kind() == types.MethodExpr {
				fn, _ := selInfo.Obj().(*types.Func)
				var origFn *types.Func
				if fn != nil {
					origFn = fn.Origin()
				}
				if origFn != nil && !isInterfaceMethodSelection(selInfo, origFn) && g.allDecls[origFn] != nil {
					return origFn, fun.Sel
				}
			}
		} else if fn, ok := g.p.TypesInfo.Uses[fun.Sel].(*types.Func); ok && fn != nil {
			fn = fn.Origin()
			if g.allDecls[fn] != nil {
				return fn, fun.Sel
			}
		}
	}
	return nil, nil
}
