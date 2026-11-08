package dynstate

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
)

// deriveMappingDischarges mechanically verifies package-level virtual-memory
// mapping bookkeeping structures (REQ-closure-shared-dynamic-state-mapping).
func deriveMappingDischarges(audited bool, p *packages.Package, idx *pkgSyntaxIndex) []string {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil
	}
	if idx == nil {
		idx = buildPkgSyntaxIndex(p)
	}
	var out []string
	for _, name := range p.Types.Scope().Names() {
		v, ok := p.Types.Scope().Lookup(name).(*types.Var)
		if !ok || !TypeMayCarryUnknownDynamic(audited, v.Type()) {
			continue
		}
		if verifyMappingVar(audited, p, idx, v) {
			out = append(out, dynamicVarKey(v))
		}
	}
	sort.Strings(out)
	return out
}

// deriveMemoDischarges mechanically verifies mutex-guarded reflect.Type
// structural memoizers whose computed entries are content-invariant and
// confined to unexported package internals (REQ-closure-shared-dynamic-state-memo).
func deriveMemoDischarges(audited bool, p *packages.Package, idx *pkgSyntaxIndex) []string {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil
	}
	if idx == nil {
		idx = buildPkgSyntaxIndex(p)
	}
	var out []string
	for _, name := range p.Types.Scope().Names() {
		v, ok := p.Types.Scope().Lookup(name).(*types.Var)
		if !ok || !TypeMayCarryUnknownDynamic(audited, v.Type()) {
			continue
		}
		if verifyMemoVar(audited, p, idx, v) {
			out = append(out, dynamicVarKey(v))
		}
	}
	sort.Strings(out)
	return out
}

type pkgSyntaxIndex struct {
	varSpecs   map[*types.Var]*ast.ValueSpec
	defCounts  map[types.Object]int
	usesOf     map[types.Object][]*ast.Ident
	parentMap  map[ast.Node]ast.Node
	enclFunc   map[ast.Node]*ast.FuncDecl
	inFuncLit  map[ast.Node]bool
	inGoStmt   map[ast.Node]bool
	funcDecls  map[*types.Func]*ast.FuncDecl
	plainByNm  map[string][]*ast.FuncDecl
	initBlocks []*ast.BlockStmt
}

func buildPkgSyntaxIndex(p *packages.Package) *pkgSyntaxIndex {
	idx := &pkgSyntaxIndex{
		varSpecs:  map[*types.Var]*ast.ValueSpec{},
		defCounts: map[types.Object]int{},
		usesOf:    map[types.Object][]*ast.Ident{},
		parentMap: map[ast.Node]ast.Node{},
		enclFunc:  map[ast.Node]*ast.FuncDecl{},
		inFuncLit: map[ast.Node]bool{},
		inGoStmt:  map[ast.Node]bool{},
		funcDecls: map[*types.Func]*ast.FuncDecl{},
		plainByNm: map[string][]*ast.FuncDecl{},
	}
	for id, obj := range p.TypesInfo.Defs {
		if id != nil && obj != nil {
			idx.defCounts[obj]++
		}
	}
	for id, obj := range p.TypesInfo.Uses {
		if id != nil && obj != nil {
			idx.usesOf[obj] = append(idx.usesOf[obj], id)
		}
	}
	for _, file := range p.Syntax {
		var stack []ast.Node
		var curFD *ast.FuncDecl
		litDepth := 0
		goDepth := 0
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				curr := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				if _, isLit := curr.(*ast.FuncLit); isLit {
					litDepth--
				}
				if _, isGo := curr.(*ast.GoStmt); isGo {
					goDepth--
				}
				if curr == curFD {
					curFD = nil
				}
				return false
			}
			if len(stack) > 0 {
				idx.parentMap[n] = stack[len(stack)-1]
			}
			if curFD != nil {
				idx.enclFunc[n] = curFD
			}
			if litDepth > 0 {
				idx.inFuncLit[n] = true
			}
			if goDepth > 0 {
				idx.inGoStmt[n] = true
			}
			switch x := n.(type) {
			case *ast.FuncLit:
				litDepth++
				idx.inFuncLit[x] = true
			case *ast.GoStmt:
				goDepth++
				idx.inGoStmt[x] = true
			case *ast.FuncDecl:
				curFD = x
				idx.enclFunc[x] = x
				if fn, ok := p.TypesInfo.Defs[x.Name].(*types.Func); ok && fn != nil {
					idx.funcDecls[fn] = x
				}
				if x.Recv == nil && x.Name != nil {
					idx.plainByNm[x.Name.Name] = append(idx.plainByNm[x.Name.Name], x)
					if x.Name.Name == "init" && x.Body != nil {
						idx.initBlocks = append(idx.initBlocks, x.Body)
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
					if v, ok := p.TypesInfo.Defs[nm].(*types.Var); ok && v != nil {
						idx.varSpecs[v] = vs
					}
				}
			}
		}
	}
	return idx
}

func (idx *pkgSyntaxIndex) parentUnparen(n ast.Node) ast.Node {
	cur := n
	for {
		par := idx.parentMap[cur]
		if _, ok := par.(*ast.ParenExpr); ok {
			cur = par
			continue
		}
		return par
	}
}

// syncEnclFuncDecl returns n's enclosing *ast.FuncDecl only when n executes
// synchronously inside that declaration without crossing a nested *ast.FuncLit
// or *ast.GoStmt boundary.
func (idx *pkgSyntaxIndex) syncEnclFuncDecl(n ast.Node) *ast.FuncDecl {
	if idx.inFuncLit[n] || idx.inGoStmt[n] {
		return nil
	}
	return idx.enclFunc[n]
}

func (idx *pkgSyntaxIndex) isSyncInFuncDecl(n ast.Node, fd *ast.FuncDecl) bool {
	return fd != nil && idx.enclFunc[n] == fd && !idx.inFuncLit[n] && !idx.inGoStmt[n]
}

// forEachSelectionHopStruct visits the receiver struct and every intermediate
// embedded struct traversed along selInfo.Index() before reaching the selected
// field or method.
func forEachSelectionHopStruct(selInfo *types.Selection, visit func(*types.Named)) {
	if selInfo == nil {
		return
	}
	cur := derefNamedStruct(selInfo.Recv())
	if cur == nil {
		return
	}
	visit(cur)
	indices := selInfo.Index()
	for i := 0; i+1 < len(indices); i++ {
		st, ok := cur.Underlying().(*types.Struct)
		if !ok || indices[i] < 0 || indices[i] >= st.NumFields() {
			return
		}
		cur = derefNamedStruct(st.Field(indices[i]).Type())
		if cur == nil {
			return
		}
		visit(cur)
	}
}

// selectionCrossesEmbeddedPointer reports whether any intermediate embedded
// field along selInfo.Index() before the final field is a pointer type.
func selectionCrossesEmbeddedPointer(selInfo *types.Selection) bool {
	if selInfo == nil || len(selInfo.Index()) <= 1 {
		return false
	}
	cur := derefNamedStruct(selInfo.Recv())
	if cur == nil {
		return false
	}
	indices := selInfo.Index()
	for i := 0; i+1 < len(indices); i++ {
		st, ok := cur.Underlying().(*types.Struct)
		if !ok || indices[i] < 0 || indices[i] >= st.NumFields() {
			return true
		}
		ft := types.Unalias(st.Field(indices[i]).Type())
		if _, isPtr := ft.(*types.Pointer); isPtr {
			return true
		}
		cur = derefNamedStruct(ft)
		if cur == nil {
			return false
		}
	}
	return false
}

// forEachValueContainedNamedStruct visits every named struct type stored by
// value inside root (recursing into value struct fields and arrays without
// crossing pointers, slices, maps, or channels).
func forEachValueContainedNamedStruct(root types.Type, visit func(*types.Named)) {
	seen := map[types.Type]bool{}
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if n, ok := t.(*types.Named); ok && n.Obj() != nil && n.Obj().Pkg() != nil {
			if _, isSt := n.Underlying().(*types.Struct); isSt {
				visit(n)
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Array:
			walk(u.Elem())
		}
	}
	walk(root)
}

func verifyMappingVar(audited bool, p *packages.Package, idx *pkgSyntaxIndex, v *types.Var) bool {
	if v == nil || v.Exported() || idx.defCounts[v] != 1 {
		return false
	}
	ptr, ok := types.Unalias(v.Type()).(*types.Pointer)
	if !ok {
		return false
	}
	outerNamed, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || outerNamed.Obj() == nil || outerNamed.Obj().Pkg() != p.Types || outerNamed.Obj().Exported() {
		return false
	}
	outerStruct, ok := outerNamed.Underlying().(*types.Struct)
	if !ok {
		return false
	}

	var baseNamed *types.Named
	var baseStruct *types.Struct
	var baseField *types.Var
	var mutexField *types.Var
	var activeField *types.Var
	callableFields := map[*types.Var]*types.Signature{}
	hasAddrCallable := false
	hasUnmapCallable := false

	scanStructFields := func(st *types.Struct, allowEmbeddedMapper bool) bool {
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f.Embedded() && isNamedInPkg(f.Type(), "sync", "Mutex") {
				if mutexField != nil {
					return false
				}
				mutexField = f
				continue
			}
			if f.Exported() {
				return false
			}
			if f.Embedded() {
				if !allowEmbeddedMapper || baseNamed != nil {
					return false
				}
				bn, ok := types.Unalias(f.Type()).(*types.Named)
				if !ok || bn.Obj() == nil || bn.Obj().Pkg() != p.Types || bn.Obj().Exported() {
					return false
				}
				bs, ok := bn.Underlying().(*types.Struct)
				if !ok {
					return false
				}
				baseNamed = bn
				baseStruct = bs
				baseField = f
				continue
			}
			if isBytePtrByteSliceMap(f.Type()) {
				if activeField != nil {
					return false
				}
				activeField = f
				continue
			}
			sig, ok := types.Unalias(f.Type()).(*types.Signature)
			if !ok {
				return false
			}
			isAddr, isUnmap, valid := classifyMapperCallableSig(audited, sig)
			if !valid {
				return false
			}
			if isAddr {
				hasAddrCallable = true
			}
			if isUnmap {
				hasUnmapCallable = true
			}
			callableFields[f] = sig
		}
		return true
	}

	if !scanStructFields(outerStruct, true) {
		return false
	}
	if baseStruct != nil && !scanStructFields(baseStruct, false) {
		return false
	}
	if mutexField == nil || activeField == nil || !hasAddrCallable || !hasUnmapCallable || len(callableFields) == 0 {
		return false
	}
	// Forbid any explicit reference to the embedded sync.Mutex field (m.Mutex = ..., &m.Mutex, etc.).
	if len(idx.usesOf[mutexField]) > 0 {
		return false
	}

	// Verify single &S{...} composite literal initializer and bound syscall targets.
	vs := idx.varSpecs[v]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
		return false
	}
	unary, ok := ast.Unparen(vs.Values[0]).(*ast.UnaryExpr)
	if !ok || unary.Op != token.AND {
		return false
	}
	comp, ok := ast.Unparen(unary.X).(*ast.CompositeLit)
	if !ok {
		return false
	}
	initKeyIdents := map[*ast.Ident]bool{}
	boundTargets := map[*types.Var]*types.Func{}
	activeInitialized := false
	if !verifyMapperCompositeLit(p, comp, outerNamed, baseNamed, activeField, callableFields, initKeyIdents, boundTargets, &activeInitialized) {
		return false
	}
	if !activeInitialized || len(boundTargets) != len(callableFields) {
		return false
	}
	if baseField != nil {
		for _, id := range idx.usesOf[baseField] {
			if !initKeyIdents[id] {
				return false
			}
		}
	}
	for _, targetFn := range boundTargets {
		if !verifyMapperSyscallTarget(p, idx, targetFn) {
			return false
		}
	}

	// Reject any whole-struct dereference write *x = ... on outerNamed or baseNamed.
	if pkgHasStructDerefWrite(p, outerNamed, baseNamed) {
		return false
	}

	// Collect all methods declared on outerNamed and baseNamed.
	allowedMethods := map[*types.Func]*ast.FuncDecl{}
	for _, tn := range []*types.Named{outerNamed, baseNamed} {
		if tn == nil {
			continue
		}
		for i := 0; i < tn.NumMethods(); i++ {
			m := tn.Method(i)
			fd := idx.funcDecls[m]
			if fd == nil || fd.Body == nil {
				return false
			}
			if !verifyMapperMethodSignatureAndReturns(audited, p, fd, m, callableFields) {
				return false
			}
			allowedMethods[m] = fd
		}
	}

	// Verify every use of v: receiver of allowedMethods call or direct call of callableFields.
	for _, id := range idx.usesOf[v] {
		sel, ok := idx.parentUnparen(id).(*ast.SelectorExpr)
		if !ok || ast.Unparen(sel.X) != id {
			return false
		}
		call, ok := idx.parentUnparen(sel).(*ast.CallExpr)
		if !ok || ast.Unparen(call.Fun) != sel {
			return false
		}
		selInfo := p.TypesInfo.Selections[sel]
		if selInfo == nil {
			return false
		}
		switch selInfo.Kind() {
		case types.MethodVal:
			fn, ok := selInfo.Obj().(*types.Func)
			if !ok || allowedMethods[fn] == nil {
				return false
			}
		case types.FieldVal:
			fld, ok := selInfo.Obj().(*types.Var)
			if !ok || callableFields[fld] == nil {
				return false
			}
		default:
			return false
		}
	}

	// Verify every use of callableFields across the entire package: only init key or direct call.
	for cf := range callableFields {
		for _, id := range idx.usesOf[cf] {
			if initKeyIdents[id] {
				continue
			}
			sel, ok := idx.parentUnparen(id).(*ast.SelectorExpr)
			if !ok || sel.Sel != id {
				return false
			}
			call, ok := idx.parentUnparen(sel).(*ast.CallExpr)
			if !ok || ast.Unparen(call.Fun) != sel {
				return false
			}
		}
	}

	// Verify every use of activeField occurs inside a verified locked method of outerNamed/baseNamed.
	activeMethods := map[*ast.FuncDecl]bool{}
	for _, id := range idx.usesOf[activeField] {
		if initKeyIdents[id] {
			continue
		}
		fd := idx.syncEnclFuncDecl(id)
		if fd == nil {
			return false
		}
		fn, ok := p.TypesInfo.Defs[fd.Name].(*types.Func)
		if !ok || allowedMethods[fn] == nil {
			return false
		}
		activeMethods[fd] = true
	}
	for fd := range activeMethods {
		if !verifyMapperActiveMethodBody(p, idx, fd, outerNamed, baseNamed, activeField, callableFields) {
			return false
		}
	}
	return true
}

func classifyMapperCallableSig(audited bool, sig *types.Signature) (isAddr, isUnmap, valid bool) {
	if sig == nil || sig.TypeParams().Len() > 0 {
		return false, false, false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if TypeMayCarryUnknownDynamic(audited, sig.Params().At(i).Type()) {
			return false, false, false
		}
	}
	preErr := types.Universe.Lookup("error").Type()
	res := sig.Results()
	switch res.Len() {
	case 1:
		if types.Identical(res.At(0).Type(), preErr) {
			return false, true, true
		}
	case 2:
		b, ok := types.Unalias(res.At(0).Type()).Underlying().(*types.Basic)
		if ok && b.Kind() == types.Uintptr && types.Identical(res.At(1).Type(), preErr) {
			return true, false, true
		}
	}
	return false, false, false
}

func verifyMapperCompositeLit(
	p *packages.Package,
	comp *ast.CompositeLit,
	outerNamed, baseNamed *types.Named,
	activeField *types.Var,
	callableFields map[*types.Var]*types.Signature,
	initKeyIdents map[*ast.Ident]bool,
	boundTargets map[*types.Var]*types.Func,
	activeInitialized *bool,
) bool {
	tv, ok := p.TypesInfo.Types[comp]
	if !ok {
		return false
	}
	compType := types.Unalias(tv.Type)
	if !types.Identical(compType, outerNamed) && (baseNamed == nil || !types.Identical(compType, baseNamed)) {
		return false
	}
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		keyID, ok := kv.Key.(*ast.Ident)
		if !ok {
			return false
		}
		fld, ok := p.TypesInfo.Uses[keyID].(*types.Var)
		if !ok {
			return false
		}
		initKeyIdents[keyID] = true
		val := ast.Unparen(kv.Value)
		if fld == activeField {
			if *activeInitialized || !isEmptyMapInitializer(p, val) {
				return false
			}
			*activeInitialized = true
			continue
		}
		if callableFields[fld] != nil {
			if boundTargets[fld] != nil {
				return false
			}
			valID, ok := val.(*ast.Ident)
			if !ok {
				return false
			}
			fn, ok := p.TypesInfo.Uses[valID].(*types.Func)
			if !ok || fn.Pkg() != p.Types || fn.Exported() {
				return false
			}
			if sig, ok := fn.Type().(*types.Signature); !ok || sig.Recv() != nil {
				return false
			}
			boundTargets[fld] = fn
			continue
		}
		if baseNamed != nil && fld.Embedded() && types.Identical(types.Unalias(fld.Type()), baseNamed) {
			subComp, ok := val.(*ast.CompositeLit)
			if !ok || !verifyMapperCompositeLit(p, subComp, outerNamed, baseNamed, activeField, callableFields, initKeyIdents, boundTargets, activeInitialized) {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func isEmptyMapInitializer(p *packages.Package, expr ast.Expr) bool {
	expr = ast.Unparen(expr)
	switch e := expr.(type) {
	case *ast.CompositeLit:
		_, ok := types.Unalias(p.TypesInfo.TypeOf(e)).Underlying().(*types.Map)
		return ok && len(e.Elts) == 0
	case *ast.CallExpr:
		id, ok := ast.Unparen(e.Fun).(*ast.Ident)
		if !ok {
			return false
		}
		b, ok := p.TypesInfo.Uses[id].(*types.Builtin)
		if !ok || b.Name() != "make" || len(e.Args) < 1 || len(e.Args) > 2 {
			return false
		}
		_, isMap := types.Unalias(p.TypesInfo.TypeOf(e)).Underlying().(*types.Map)
		return isMap
	}
	return false
}

func verifyMapperSyscallTarget(p *packages.Package, idx *pkgSyntaxIndex, root *types.Func) bool {
	if root == nil {
		return false
	}
	visited := map[*types.Func]bool{}
	checkedGlobals := map[*types.Var]bool{}
	reachesKernel := false
	invalid := false
	var walk func(fn *types.Func)
	walk = func(fn *types.Func) {
		if fn == nil || visited[fn] || invalid {
			return
		}
		visited[fn] = true
		fd := idx.funcDecls[fn]
		if fd == nil {
			invalid = true
			return
		}
		if hasKernelLinkageDirective(p, fd) || fd.Body == nil {
			reachesKernel = true
			if fd.Body == nil {
				return
			}
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if invalid || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.FuncLit, *ast.GoStmt, *ast.SendStmt:
				invalid = true
				return false
			case *ast.Ident:
				if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && !v.IsField() {
					if v.Pkg() != p.Types || v.Parent() == p.Types.Scope() {
						okGlobal, seen := checkedGlobals[v]
						if !seen {
							okGlobal = isMapperAllowedHelperGlobal(p, idx, v)
							checkedGlobals[v] = okGlobal
						}
						if !okGlobal {
							invalid = true
							return false
						}
					}
				}
			case *ast.CallExpr:
				fun := ast.Unparen(x.Fun)
				if tv, ok := p.TypesInfo.Types[fun]; ok && tv.IsType() {
					return true
				}
				if b := mapperCallBuiltinObj(p, fun); b != nil {
					switch b.Name() {
					case "len", "cap", "min", "max", "Pointer", "Sizeof", "Offsetof", "Alignof", "Add":
						return true
					default:
						invalid = true
						return false
					}
				}
				var callee *types.Func
				switch f := fun.(type) {
				case *ast.Ident:
					callee, _ = p.TypesInfo.Uses[f].(*types.Func)
				case *ast.SelectorExpr:
					if p.TypesInfo.Selections[f] == nil {
						callee, _ = p.TypesInfo.Uses[f.Sel].(*types.Func)
					}
				}
				if callee == nil {
					invalid = true
					return false
				}
				if isStdSyscallPrimitive(callee) {
					reachesKernel = true
					return true
				}
				if isAllowedSyscallBracket(callee) {
					return true
				}
				if callee.Pkg() == p.Types {
					walk(callee)
					return !invalid
				}
				invalid = true
				return false
			}
			return true
		})
	}
	walk(root)
	return reachesKernel && !invalid
}

func mapperCallBuiltinObj(p *packages.Package, fun ast.Expr) *types.Builtin {
	switch f := fun.(type) {
	case *ast.Ident:
		b, _ := p.TypesInfo.Uses[f].(*types.Builtin)
		return b
	case *ast.SelectorExpr:
		if p.TypesInfo.Selections[f] == nil {
			b, _ := p.TypesInfo.Uses[f.Sel].(*types.Builtin)
			return b
		}
	}
	return nil
}

func isAllowedSyscallBracket(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	switch fn.Pkg().Path() {
	case "runtime":
		switch fn.Name() {
		case "EnterSyscall", "ExitSyscall", "KeepAlive":
			return true
		}
	case "syscall":
		switch fn.Name() {
		case "Entersyscall", "Exitsyscall":
			return true
		}
	}
	return false
}

func isMapperAllowedHelperGlobal(p *packages.Package, idx *pkgSyntaxIndex, v *types.Var) bool {
	if v == nil || v.IsField() || v.Pkg() != p.Types || v.Parent() != p.Types.Scope() || v.Exported() {
		return false
	}
	isErr := types.Identical(v.Type(), types.Universe.Lookup("error").Type())
	isUintptr := false
	if b, ok := types.Unalias(v.Type()).Underlying().(*types.Basic); ok && b.Kind() == types.Uintptr {
		isUintptr = true
	}
	if !isErr && !isUintptr {
		return false
	}
	spec := idx.varSpecs[v]
	if spec == nil {
		return false
	}
	if isUintptr {
		if len(spec.Values) != 0 {
			return false
		}
	} else {
		if len(spec.Names) != len(spec.Values) {
			return false
		}
		matchedInit := false
		for i, nm := range spec.Names {
			if p.TypesInfo.Defs[nm] == v {
				matchedInit = true
				rhsType := p.TypesInfo.TypeOf(spec.Values[i])
				if rhsType == nil || TypeMayCarryUnknownDynamic(true, rhsType) {
					return false
				}
			}
		}
		if !matchedInit {
			return false
		}
	}
	for _, u := range idx.usesOf[v] {
		switch par := idx.parentMap[u].(type) {
		case *ast.AssignStmt:
			for _, l := range par.Lhs {
				if ast.Unparen(l) == u {
					return false
				}
			}
		case *ast.IncDecStmt:
			if ast.Unparen(par.X) == u {
				return false
			}
		case *ast.UnaryExpr:
			if isErr && par.Op == token.AND && ast.Unparen(par.X) == u {
				return false
			}
		}
	}
	return true
}

func hasKernelLinkageDirective(p *packages.Package, fd *ast.FuncDecl) bool {
	checkGroup := func(cg *ast.CommentGroup) bool {
		if cg == nil {
			return false
		}
		for _, c := range cg.List {
			if strings.HasPrefix(c.Text, "//go:linkname ") ||
				strings.HasPrefix(c.Text, "//go:linknamestd ") ||
				strings.HasPrefix(c.Text, "//go:cgo_import_dynamic ") {
				return true
			}
		}
		return false
	}
	if checkGroup(fd.Doc) {
		return true
	}
	for _, file := range p.Syntax {
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				for _, pfx := range []string{"//go:linkname ", "//go:linknamestd "} {
					if rest, ok := strings.CutPrefix(c.Text, pfx); ok {
						fields := strings.Fields(rest)
						if len(fields) >= 1 && fields[0] == fd.Name.Name {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func isStdSyscallPrimitive(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "syscall" {
		return false
	}
	switch fn.Name() {
	case "Syscall", "Syscall6", "Syscall9", "Syscall12", "Syscall15", "Syscall18",
		"RawSyscall", "RawSyscall6",
		"Mmap", "Munmap",
		"MapViewOfFile", "UnmapViewOfFile",
		"VirtualAlloc", "VirtualFree":
		return true
	}
	return false
}

func verifyMapperMethodSignatureAndReturns(audited bool, p *packages.Package, fd *ast.FuncDecl, fn *types.Func, callableFields map[*types.Var]*types.Signature) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.TypeParams().Len() > 0 {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if TypeMayCarryUnknownDynamic(audited, sig.Params().At(i).Type()) {
			return false
		}
	}
	preErr := types.Universe.Lookup("error").Type()
	errSlot := -1
	for i := 0; i < sig.Results().Len(); i++ {
		rt := sig.Results().At(i).Type()
		if types.Identical(rt, preErr) {
			if errSlot != -1 {
				return false
			}
			errSlot = i
			continue
		}
		if TypeMayCarryUnknownDynamic(audited, rt) {
			return false
		}
	}
	if errSlot == -1 {
		return true
	}
	// Collect local error variables assigned exclusively from callableFields, nil, or carrier-free sentinels.
	cleanErrVars := map[*types.Var]bool{}
	dirtyErrVars := map[*types.Var]bool{}
	isCleanErrExpr := func(expr ast.Expr) bool {
		expr = ast.Unparen(expr)
		if id, ok := expr.(*ast.Ident); ok {
			if p.TypesInfo.Uses[id] == types.Universe.Lookup("nil") {
				return true
			}
			if v, ok := p.TypesInfo.Uses[id].(*types.Var); ok {
				if v.Parent() == p.Types.Scope() {
					return !TypeMayCarryUnknownDynamic(audited, v.Type())
				}
				return cleanErrVars[v] && !dirtyErrVars[v]
			}
			if _, ok := p.TypesInfo.Uses[id].(*types.Const); ok {
				return true
			}
			return false
		}
		if call, ok := expr.(*ast.CallExpr); ok {
			if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
				if fld, ok := p.TypesInfo.Uses[sel.Sel].(*types.Var); ok && callableFields[fld] != nil {
					return true
				}
			}
		}
		tv, ok := p.TypesInfo.Types[expr]
		return ok && tv.Type != nil && !TypeMayCarryUnknownDynamic(audited, tv.Type)
	}

	var namedErrVar *types.Var
	if resVar := sig.Results().At(errSlot); resVar.Name() != "" && resVar.Name() != "_" {
		namedErrVar = resVar
	}

	okReturns := true
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if !okReturns {
			return false
		}
		switch s := n.(type) {
		case *ast.FuncLit:
			okReturns = false
			return false
		case *ast.AssignStmt:
			if len(s.Rhs) == 1 {
				if call, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr); ok {
					if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
						if fld, ok := p.TypesInfo.Uses[sel.Sel].(*types.Var); ok && callableFields[fld] != nil {
							for _, lhs := range s.Lhs {
								if id, ok := ast.Unparen(lhs).(*ast.Ident); ok {
									if v := lookupIdentVar(p, id); v != nil && types.Identical(v.Type(), preErr) {
										cleanErrVars[v] = true
									}
								}
							}
							return true
						}
					}
				}
			}
			for i, lhs := range s.Lhs {
				id, ok := ast.Unparen(lhs).(*ast.Ident)
				if !ok {
					continue
				}
				v := lookupIdentVar(p, id)
				if v == nil || !types.Identical(v.Type(), preErr) {
					continue
				}
				if i < len(s.Rhs) && isCleanErrExpr(s.Rhs[i]) {
					cleanErrVars[v] = true
				} else {
					dirtyErrVars[v] = true
				}
			}
		case *ast.ReturnStmt:
			if len(s.Results) == 0 {
				if namedErrVar == nil || dirtyErrVars[namedErrVar] {
					okReturns = false
				}
				return true
			}
			if len(s.Results) == 1 && sig.Results().Len() > 1 {
				if !isCleanErrExpr(s.Results[0]) {
					okReturns = false
				}
				return true
			}
			if errSlot >= len(s.Results) || !isCleanErrExpr(s.Results[errSlot]) {
				okReturns = false
			}
		}
		return true
	})
	return okReturns
}

func verifyMapperActiveMethodBody(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	fd *ast.FuncDecl,
	outerNamed, baseNamed *types.Named,
	activeField *types.Var,
	callableFields map[*types.Var]*types.Signature,
) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
		return false
	}
	recvID := fd.Recv.List[0].Names[0]
	recvVar, ok := p.TypesInfo.Defs[recvID].(*types.Var)
	if !ok || recvVar == nil {
		return false
	}
	ptr, ok := types.Unalias(recvVar.Type()).(*types.Pointer)
	if !ok {
		return false
	}
	recvElem := types.Unalias(ptr.Elem())
	if !types.Identical(recvElem, outerNamed) && (baseNamed == nil || !types.Identical(recvElem, baseNamed)) {
		return false
	}
	if varWrittenOrAddrTakenInBody(p, idx, fd.Body, recvVar) {
		return false
	}

	// Collect local uintptr variables returned from callableFields and local []byte slices built from them.
	syscallAddrs := collectMapperSyscallAddrVars(p, fd.Body, recvVar, callableFields)
	mappedSlices, mappedKeys := collectMapperSliceAndKeyVars(p, fd.Body, syscallAddrs)

	stmts := fd.Body.List
	lockIdx := -1
	deferUnlock := false
	unlockIdx := -1
	for i, st := range stmts {
		if isMutexMethodStmt(p, st, recvVar, "Lock") {
			if lockIdx != -1 {
				return false
			}
			lockIdx = i
			if i+1 < len(stmts) && isDeferMutexMethodStmt(p, stmts[i+1], recvVar, "Unlock") {
				deferUnlock = true
			}
			continue
		}
		if isMutexMethodStmt(p, st, recvVar, "Unlock") {
			if deferUnlock || lockIdx == -1 || unlockIdx != -1 {
				return false
			}
			unlockIdx = i
		}
	}
	if lockIdx == -1 || (!deferUnlock && unlockIdx == -1) {
		return false
	}
	startLocked := lockIdx + 1
	endLocked := len(stmts)
	if deferUnlock {
		startLocked = lockIdx + 2
	} else {
		endLocked = unlockIdx
		for i := startLocked; i < endLocked; i++ {
			if stmtContainsReturnOrBranch(stmts[i]) {
				return false
			}
		}
	}

	for i, st := range stmts {
		if i < startLocked || i >= endLocked {
			if subtreeMentionsObj(p, st, activeField) {
				return false
			}
			// Forbid any nested Lock/Unlock outside the exact top-level lock/unlock statements.
			if i != lockIdx && (deferUnlock || i != unlockIdx) && !(deferUnlock && i == lockIdx+1) {
				if stmtCallsRecvMutex(p, st, recvVar) {
					return false
				}
			}
		}
	}

	// Verify every activeField reference inside [startLocked, endLocked), and
	// forbid any nested Lock/Unlock inside the critical section.
	validActive := true
	for i := startLocked; i < endLocked; i++ {
		ast.Inspect(stmts[i], func(n ast.Node) bool {
			if !validActive {
				return false
			}
			switch x := n.(type) {
			case *ast.GoStmt, *ast.FuncLit:
				validActive = false
				return false
			case *ast.CallExpr:
				if isMutexMethodCall(p, x, recvVar, "Lock") || isMutexMethodCall(p, x, recvVar, "Unlock") {
					validActive = false
					return false
				}
			case *ast.Ident:
				if p.TypesInfo.Uses[x] != activeField {
					return true
				}
				sel, ok := idx.parentUnparen(x).(*ast.SelectorExpr)
				if !ok || sel.Sel != x || !isIdentUsingObj(p, sel.X, recvVar) {
					validActive = false
					return false
				}
				par := idx.parentUnparen(sel)
				switch pn := par.(type) {
				case *ast.IndexExpr:
					if ast.Unparen(pn.X) != sel {
						validActive = false
						return false
					}
					idxPar := idx.parentUnparen(pn)
					if un, ok := idxPar.(*ast.UnaryExpr); ok && un.Op == token.AND {
						validActive = false
						return false
					}
					keyVar := lookupIdentVar(p, pn.Index)
					if keyVar == nil || mappedKeys[keyVar] == nil {
						validActive = false
						return false
					}
					if as, ok := idxPar.(*ast.AssignStmt); ok {
						isLHS := false
						lhsPos := -1
						for li, l := range as.Lhs {
							if ast.Unparen(l) == pn {
								isLHS = true
								lhsPos = li
							}
						}
						if isLHS {
							if as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || lhsPos != 0 {
								validActive = false
								return false
							}
							valVar := lookupIdentVar(p, as.Rhs[0])
							if valVar == nil || !mappedSlices[valVar] || mappedKeys[keyVar] != valVar {
								validActive = false
								return false
							}
						}
					}
				case *ast.CallExpr:
					id, ok := ast.Unparen(pn.Fun).(*ast.Ident)
					if !ok {
						validActive = false
						return false
					}
					b, ok := p.TypesInfo.Uses[id].(*types.Builtin)
					if !ok || b.Name() != "delete" || len(pn.Args) != 2 || ast.Unparen(pn.Args[0]) != sel {
						validActive = false
						return false
					}
					delKey := lookupIdentVar(p, pn.Args[1])
					if delKey == nil || mappedKeys[delKey] == nil {
						validActive = false
						return false
					}
				default:
					validActive = false
					return false
				}
			}
			return true
		})
	}
	return validActive
}

func collectMapperSyscallAddrVars(
	p *packages.Package,
	body *ast.BlockStmt,
	recvVar *types.Var,
	callableFields map[*types.Var]*types.Signature,
) map[*types.Var]bool {
	addrs := map[*types.Var]bool{}
	dirty := map[*types.Var]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if len(as.Lhs) == 2 && len(as.Rhs) == 1 {
			if call, ok := ast.Unparen(as.Rhs[0]).(*ast.CallExpr); ok {
				if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && isIdentUsingObj(p, sel.X, recvVar) {
					if fld, ok := p.TypesInfo.Uses[sel.Sel].(*types.Var); ok && callableFields[fld] != nil {
						if v := lookupIdentVar(p, as.Lhs[0]); v != nil {
							addrs[v] = true
							return true
						}
					}
				}
			}
		}
		for _, l := range as.Lhs {
			if v := lookupIdentVar(p, l); v != nil {
				dirty[v] = true
			}
		}
		return true
	})
	for v := range dirty {
		delete(addrs, v)
	}
	return addrs
}

func collectMapperSliceAndKeyVars(p *packages.Package, body *ast.BlockStmt, syscallAddrs map[*types.Var]bool) (map[*types.Var]bool, map[*types.Var]*types.Var) {
	slices := map[*types.Var]bool{}
	keys := map[*types.Var]*types.Var{}
	hdrAlias := map[*types.Var]*types.Var{}
	sliceWrites := map[*types.Var]int{}
	keyWrites := map[*types.Var]int{}

	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for i, l := range s.Lhs {
				if v := lookupIdentVar(p, l); v != nil {
					sliceWrites[v]++
					keyWrites[v]++
					if i < len(s.Rhs) {
						rhs := ast.Unparen(s.Rhs[i])
						if isUnsafeSliceFromAddr(p, rhs, syscallAddrs) {
							slices[v] = true
						}
						if target := isUnsafeSliceHdrCast(p, rhs); target != nil {
							hdrAlias[v] = target
						}
						if slVar := isByteSliceElemAddr(p, rhs); slVar != nil {
							keys[v] = slVar
						}
					}
				}
				// Legacy pre-unsafe.Slice pattern: hdr.Data = unsafe.Pointer(addr)
				if sel, ok := ast.Unparen(l).(*ast.SelectorExpr); ok && sel.Sel.Name == "Data" && i < len(s.Rhs) {
					if hdrVar := lookupIdentVar(p, sel.X); hdrVar != nil && hdrAlias[hdrVar] != nil {
						if isUnsafePointerOfAddr(p, s.Rhs[i], syscallAddrs) {
							slices[hdrAlias[hdrVar]] = true
						}
					}
				}
			}
		}
		return true
	})
	for v, c := range sliceWrites {
		if c > 1 {
			delete(slices, v)
		}
	}
	for v, c := range keyWrites {
		if c > 1 {
			delete(keys, v)
		}
	}
	return slices, keys
}

func isUnsafeSliceFromAddr(p *packages.Package, expr ast.Expr, syscallAddrs map[*types.Var]bool) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 2 {
		return false
	}
	var b *types.Builtin
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		b, _ = p.TypesInfo.Uses[fun.Sel].(*types.Builtin)
	case *ast.Ident:
		b, _ = p.TypesInfo.Uses[fun].(*types.Builtin)
	}
	if b == nil || b.Name() != "Slice" {
		return false
	}
	// Expect (*byte)(unsafe.Pointer(addr))
	arg0, ok := ast.Unparen(call.Args[0]).(*ast.CallExpr)
	if !ok || len(arg0.Args) != 1 || !p.TypesInfo.Types[arg0.Fun].IsType() {
		return false
	}
	return isUnsafePointerOfAddr(p, arg0.Args[0], syscallAddrs)
}

func isUnsafePointerOfAddr(p *packages.Package, expr ast.Expr, syscallAddrs map[*types.Var]bool) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !p.TypesInfo.Types[call.Fun].IsType() {
		return false
	}
	basic, ok := types.Unalias(p.TypesInfo.TypeOf(call)).Underlying().(*types.Basic)
	if !ok || basic.Kind() != types.UnsafePointer {
		return false
	}
	v := lookupIdentVar(p, call.Args[0])
	return v != nil && syscallAddrs[v]
}

func isUnsafeSliceHdrCast(p *packages.Package, expr ast.Expr) *types.Var {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !p.TypesInfo.Types[call.Fun].IsType() {
		return nil
	}
	up, ok := ast.Unparen(call.Args[0]).(*ast.CallExpr)
	if !ok || len(up.Args) != 1 || !p.TypesInfo.Types[up.Fun].IsType() {
		return nil
	}
	un, ok := ast.Unparen(up.Args[0]).(*ast.UnaryExpr)
	if !ok || un.Op != token.AND {
		return nil
	}
	v := lookupIdentVar(p, un.X)
	if v == nil || v.Parent() == p.Types.Scope() {
		return nil
	}
	return v
}

func isByteSliceElemAddr(p *packages.Package, expr ast.Expr) *types.Var {
	un, ok := ast.Unparen(expr).(*ast.UnaryExpr)
	if !ok || un.Op != token.AND {
		return nil
	}
	ie, ok := ast.Unparen(un.X).(*ast.IndexExpr)
	if !ok {
		return nil
	}
	return lookupIdentVar(p, ie.X)
}

func verifyMemoVar(audited bool, p *packages.Package, idx *pkgSyntaxIndex, mapVar *types.Var) bool {
	ok, _ := verifyMemoVarWithReason(audited, p, idx, mapVar)
	return ok
}

func verifyMemoVarWithReason(audited bool, p *packages.Package, idx *pkgSyntaxIndex, mapVar *types.Var) (bool, string) {
	if mapVar == nil || mapVar.Exported() || idx.defCounts[mapVar] != 1 {
		return false, "nil, exported, or multi-def mapVar"
	}
	mt, ok := types.Unalias(mapVar.Type()).Underlying().(*types.Map)
	if !ok || !isNamedInPkg(mt.Key(), "reflect", "Type") {
		return false, "not map[reflect.Type]..."
	}
	if TypeMayCarryUnknownDynamic(audited, mt.Elem()) {
		return false, "map elem carries unknown dynamic"
	}
	ptr, ok := types.Unalias(mt.Elem()).(*types.Pointer)
	if !ok {
		return false, "map elem not pointer"
	}
	infoNamed, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || infoNamed.Obj() == nil || infoNamed.Obj().Pkg() != p.Types || infoNamed.Obj().Exported() {
		return false, "map elem not unexported local named struct"
	}
	if _, ok := infoNamed.Underlying().(*types.Struct); !ok {
		return false, "map elem underlying not struct"
	}

	vs := idx.varSpecs[mapVar]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 || !isEmptyMapInitializer(p, vs.Values[0]) {
		return false, "varSpec not single empty map initializer"
	}

	// All references to mapVar must lie synchronously inside a single top-level plain function memoFn.
	uses := idx.usesOf[mapVar]
	if len(uses) == 0 {
		return false, "zero uses of mapVar"
	}
	var memoFD *ast.FuncDecl
	for _, id := range uses {
		fd := idx.syncEnclFuncDecl(id)
		if fd == nil || fd.Recv != nil || fd.Body == nil || fd.Name.Name == "init" {
			return false, "mapVar use outside plain non-init top-level func"
		}
		if memoFD == nil {
			memoFD = fd
		} else if memoFD != fd {
			return false, "mapVar used across multiple functions"
		}
	}
	memoFnObj, ok := p.TypesInfo.Defs[memoFD.Name].(*types.Func)
	if !ok || memoFnObj == nil {
		return false, "memoFnObj missing"
	}
	memoSig, ok := memoFnObj.Type().(*types.Signature)
	if !ok || memoSig.TypeParams().Len() > 0 || memoSig.Params().Len() != 1 {
		return false, "memoSig not 1-param non-generic"
	}
	paramVar := memoSig.Params().At(0)
	if !isNamedInPkg(paramVar.Type(), "reflect", "Type") {
		return false, "paramVar not reflect.Type"
	}
	if varWrittenOrAddrTakenInBody(p, idx, memoFD.Body, paramVar) {
		return false, "paramVar written or addr-taken"
	}

	// Collect infoNamed and all nested package-local named struct types inside it.
	protectedStructs := map[*types.Named]bool{}
	if !collectProtectedMemoStructs(p, infoNamed, protectedStructs) {
		return false, "collectProtectedMemoStructs failed"
	}

	// Ensure protectedStructs never appear on exported package surface or interface conversions,
	// never undergo pointer-identity comparison, and are never mutated outside memoFD.Body.
	if ok, r := verifyProtectedMemoStructConfinement(p, idx, memoFD, protectedStructs); !ok {
		return false, "confinement: " + r
	}

	// Verify lock, map lookup/store, and pure deterministic computation inside memoFD.Body.
	if ok, r := verifyMemoFunctionBody(p, idx, memoFD, memoFnObj, paramVar, mapVar, infoNamed, protectedStructs); !ok {
		return false, "body: " + r
	}
	return true, ""
}

func collectProtectedMemoStructs(p *packages.Package, root *types.Named, out map[*types.Named]bool) bool {
	seen := map[types.Type]bool{}
	ok := true
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || !ok {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if n, isNamed := t.(*types.Named); isNamed && n.Obj() != nil {
			if _, isSt := n.Underlying().(*types.Struct); isSt {
				if n.Obj().Pkg() != p.Types || n.Obj().Exported() {
					ok = false
					return
				}
				out[n] = true
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Pointer:
			elem := types.Unalias(u.Elem())
			elemNamed, isEN := elem.(*types.Named)
			if !isEN || elemNamed.Obj() == nil || elemNamed.Obj().Pkg() != p.Types || elemNamed.Obj().Exported() {
				ok = false
				return
			}
			if _, isSt := elemNamed.Underlying().(*types.Struct); !isSt {
				ok = false
				return
			}
			walk(elem)
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Struct:
			if _, isNamed := t.(*types.Named); !isNamed && u.NumFields() > 0 {
				ok = false
				return
			}
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		case *types.Chan, *types.Interface, *types.Signature, *types.TypeParam:
			ok = false
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				ok = false
			}
		}
	}
	walk(root)
	return ok
}

func verifyProtectedMemoStructConfinement(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	memoFD *ast.FuncDecl,
	protected map[*types.Named]bool,
) (bool, string) {
	typeContainsPtrToProtected := func(root types.Type) bool {
		seen := map[types.Type]bool{}
		hit := false
		var walk func(t types.Type)
		walk = func(t types.Type) {
			if t == nil || hit {
				return
			}
			t = types.Unalias(t)
			if seen[t] {
				return
			}
			seen[t] = true
			if isPtrToAnyProtected(t, protected) {
				hit = true
				return
			}
			switch u := t.Underlying().(type) {
			case *types.Array:
				walk(u.Elem())
			case *types.Struct:
				for i := 0; i < u.NumFields(); i++ {
					walk(u.Field(i).Type())
				}
			}
		}
		walk(root)
		return hit
	}
	mentionsProtected := func(root types.Type) bool {
		seen := map[types.Type]bool{}
		hit := false
		var walk func(t types.Type)
		walk = func(t types.Type) {
			if t == nil || hit {
				return
			}
			t = types.Unalias(t)
			if seen[t] {
				return
			}
			seen[t] = true
			if n, ok := t.(*types.Named); ok && protected[n] {
				hit = true
				return
			}
			switch u := t.Underlying().(type) {
			case *types.Pointer:
				walk(u.Elem())
			case *types.Slice:
				walk(u.Elem())
			case *types.Array:
				walk(u.Elem())
			case *types.Map:
				walk(u.Key())
				walk(u.Elem())
			case *types.Chan:
				walk(u.Elem())
			case *types.Struct:
				for i := 0; i < u.NumFields(); i++ {
					if u.Field(i).Exported() {
						walk(u.Field(i).Type())
					}
				}
			case *types.Signature:
				for i := 0; i < u.Params().Len(); i++ {
					walk(u.Params().At(i).Type())
				}
				for i := 0; i < u.Results().Len(); i++ {
					walk(u.Results().At(i).Type())
				}
			}
		}
		walk(root)
		return hit
	}

	for _, name := range p.Types.Scope().Names() {
		obj := p.Types.Scope().Lookup(name)
		if obj == nil || !obj.Exported() {
			continue
		}
		if mentionsProtected(obj.Type()) {
			return false, "exported mentions protected: " + name
		}
		if tn, ok := obj.(*types.TypeName); ok {
			if named, ok := types.Unalias(tn.Type()).(*types.Named); ok {
				pset := types.NewMethodSet(types.NewPointer(named))
				for i := 0; i < pset.Len(); i++ {
					if m := pset.At(i).Obj(); m != nil && m.Exported() && mentionsProtected(m.Type()) {
						return false, "exported method mentions protected: " + name + "." + m.Name()
					}
				}
			}
		}
	}

	clean := true
	confReason := ""
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !clean || n == nil {
				return false
			}
			inSyncMemo := idx.isSyncInFuncDecl(n, memoFD)
			switch x := n.(type) {
			case *ast.BinaryExpr:
				if x.Op == token.EQL || x.Op == token.NEQ {
					lt := p.TypesInfo.TypeOf(x.X)
					rt := p.TypesInfo.TypeOf(x.Y)
					if (isPtrToAnyProtected(lt, protected) && !isNilIdent(p, x.Y)) ||
						(isPtrToAnyProtected(rt, protected) && !isNilIdent(p, x.X)) {
						clean = false
						confReason = "ptr identity compare"
						return false
					}
				}
			case *ast.SwitchStmt:
				if x.Tag != nil && isPtrToAnyProtected(p.TypesInfo.TypeOf(x.Tag), protected) && x.Body != nil {
					for _, st := range x.Body.List {
						if cc, ok := st.(*ast.CaseClause); ok {
							for _, ce := range cc.List {
								if !isNilIdent(p, ce) {
									clean = false
									confReason = "switch ptr compare"
									return false
								}
							}
						}
					}
				}
			case *ast.CaseClause:
				for _, ce := range x.List {
					if !isNilIdent(p, ce) && isPtrToAnyProtected(p.TypesInfo.TypeOf(ce), protected) {
						clean = false
						confReason = "case ptr compare"
						return false
					}
				}
			case *ast.MapType:
				if typeContainsPtrToProtected(p.TypesInfo.TypeOf(x.Key)) {
					clean = false
					confReason = "map key ptr"
					return false
				}
			case *ast.AssignStmt:
				if !inSyncMemo {
					for _, lhs := range x.Lhs {
						if exprMutatesProtectedStruct(p, lhs, protected) {
							clean = false
							confReason = "assign outside memo"
							return false
						}
					}
				}
				if len(x.Rhs) == 1 && len(x.Lhs) > 1 {
					rhsT := p.TypesInfo.TypeOf(x.Rhs[0])
					if tup, isTup := rhsT.(*types.Tuple); isTup {
						for i, lhs := range x.Lhs {
							if i < tup.Len() && assignErasesProtected(tup.At(i).Type(), p.TypesInfo.TypeOf(lhs), protected) {
								clean = false
								confReason = "tuple assign boxes into interface"
								return false
							}
						}
					} else if assignErasesProtected(rhsT, p.TypesInfo.TypeOf(x.Lhs[0]), protected) {
						clean = false
						confReason = "comma-ok assign boxes into interface"
						return false
					}
				} else {
					for i, lhs := range x.Lhs {
						if i < len(x.Rhs) && assignErasesProtected(p.TypesInfo.TypeOf(x.Rhs[i]), p.TypesInfo.TypeOf(lhs), protected) {
							clean = false
							confReason = "assign boxes into interface"
							return false
						}
					}
				}
			case *ast.ValueSpec:
				if len(x.Values) == 1 && len(x.Names) > 1 {
					rhsT := p.TypesInfo.TypeOf(x.Values[0])
					if tup, isTup := rhsT.(*types.Tuple); isTup {
						for i, nm := range x.Names {
							if v := p.TypesInfo.Defs[nm]; v != nil && i < tup.Len() && assignErasesProtected(tup.At(i).Type(), v.Type(), protected) {
								clean = false
								confReason = "tuple varspec boxes into interface"
								return false
							}
						}
					} else if v := p.TypesInfo.Defs[x.Names[0]]; v != nil && assignErasesProtected(rhsT, v.Type(), protected) {
						clean = false
						confReason = "comma-ok varspec boxes into interface"
						return false
					}
				} else {
					for i, nm := range x.Names {
						if i < len(x.Values) {
							if v := p.TypesInfo.Defs[nm]; v != nil && assignErasesProtected(p.TypesInfo.TypeOf(x.Values[i]), v.Type(), protected) {
								clean = false
								confReason = "varspec boxes into interface"
								return false
							}
						}
					}
				}
			case *ast.CompositeLit:
				litType := p.TypesInfo.TypeOf(x)
				if litType != nil {
					if ptr, isPtr := types.Unalias(litType).Underlying().(*types.Pointer); isPtr {
						litType = ptr.Elem()
					}
					switch u := types.Unalias(litType).Underlying().(type) {
					case *types.Slice:
						for _, elt := range x.Elts {
							val := elt
							if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
								val = kv.Value
							}
							if assignErasesProtected(p.TypesInfo.TypeOf(val), u.Elem(), protected) {
								clean = false
								confReason = "slice complit boxes into interface"
								return false
							}
						}
					case *types.Array:
						for _, elt := range x.Elts {
							val := elt
							if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
								val = kv.Value
							}
							if assignErasesProtected(p.TypesInfo.TypeOf(val), u.Elem(), protected) {
								clean = false
								confReason = "array complit boxes into interface"
								return false
							}
						}
					case *types.Map:
						for _, elt := range x.Elts {
							if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
								if assignErasesProtected(p.TypesInfo.TypeOf(kv.Key), u.Key(), protected) ||
									assignErasesProtected(p.TypesInfo.TypeOf(kv.Value), u.Elem(), protected) {
									clean = false
									confReason = "map complit boxes into interface"
									return false
								}
							}
						}
					case *types.Struct:
						for ei, elt := range x.Elts {
							if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
								var fieldType types.Type
								if fid, okID := kv.Key.(*ast.Ident); okID {
									if fObj := p.TypesInfo.Uses[fid]; fObj != nil {
										fieldType = fObj.Type()
									}
								}
								if fieldType == nil || assignErasesProtected(p.TypesInfo.TypeOf(kv.Value), fieldType, protected) {
									clean = false
									confReason = "struct complit boxes into interface"
									return false
								}
							} else if ei < u.NumFields() && assignErasesProtected(p.TypesInfo.TypeOf(elt), u.Field(ei).Type(), protected) {
								clean = false
								confReason = "pos struct complit boxes into interface"
								return false
							}
						}
					default:
						for _, elt := range x.Elts {
							val := elt
							if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
								val = kv.Value
							}
							if typeMentionsProtectedStruct(p.TypesInfo.TypeOf(val), protected) {
								clean = false
								confReason = "complit boxes into interface"
								return false
							}
						}
					}
				}
			case *ast.SendStmt:
				if chT := p.TypesInfo.TypeOf(x.Chan); chT != nil {
					if ch, okCh := types.Unalias(chT).Underlying().(*types.Chan); okCh {
						if assignErasesProtected(p.TypesInfo.TypeOf(x.Value), ch.Elem(), protected) {
							clean = false
							confReason = "send boxes into interface"
							return false
						}
					} else if typeMentionsProtectedStruct(p.TypesInfo.TypeOf(x.Value), protected) {
						clean = false
						confReason = "send unknown chan boxes into interface"
						return false
					}
				}
			case *ast.ReturnStmt:
				var retSrcs []types.Type
				if len(x.Results) == 1 {
					if tup, isTup := p.TypesInfo.TypeOf(x.Results[0]).(*types.Tuple); isTup {
						for ti := 0; ti < tup.Len(); ti++ {
							retSrcs = append(retSrcs, tup.At(ti).Type())
						}
					}
				}
				if retSrcs == nil {
					for _, r := range x.Results {
						retSrcs = append(retSrcs, p.TypesInfo.TypeOf(r))
					}
				}
				for ri, rT := range retSrcs {
					if typeMentionsProtectedStruct(rT, protected) {
						if enclFD := idx.enclFunc[x]; enclFD != nil && !idx.inFuncLit[x] {
							if fnObj, ok := p.TypesInfo.Defs[enclFD.Name].(*types.Func); ok && fnObj != nil {
								if sig, okSig := fnObj.Type().(*types.Signature); okSig && sig.Results() != nil && ri < sig.Results().Len() {
									if assignErasesProtected(rT, sig.Results().At(ri).Type(), protected) {
										clean = false
										confReason = "return boxes into interface"
										return false
									}
									continue
								}
							}
						}
						clean = false
						confReason = "closure or unmatched return mentions protected"
						return false
					}
				}
			case *ast.IncDecStmt:
				if !inSyncMemo && exprMutatesProtectedStruct(p, x.X, protected) {
					clean = false
					confReason = "incdec outside memo"
					return false
				}
			case *ast.RangeStmt:
				if !inSyncMemo && x.Tok == token.ASSIGN {
					if (x.Key != nil && exprMutatesProtectedStruct(p, x.Key, protected)) ||
						(x.Value != nil && exprMutatesProtectedStruct(p, x.Value, protected)) {
						clean = false
						confReason = "range outside memo"
						return false
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && !inSyncMemo && exprTakesAddrInsideProtected(p, x.X, protected) {
					clean = false
					confReason = "addr outside memo"
					return false
				}
			case *ast.CallExpr:
				// Forbid converting protected struct / pointer to interface (e.g. any(sinfo)) or builtin delete/clear/copy/append on its fields.
				if !inSyncMemo && callMutatesProtectedContainer(p, x, protected) {
					clean = false
					confReason = "call mutates outside memo"
					return false
				}
				if callBoxesProtectedIntoInterface(p, x, protected) {
					clean = false
					confReason = "boxes into interface"
					return false
				}
			}
			return true
		})
	}
	if !clean {
		return false, confReason
	}
	for _, inst := range p.TypesInfo.Instances {
		if inst.TypeArgs != nil {
			for i := 0; i < inst.TypeArgs.Len(); i++ {
				if typeMentionsProtectedStruct(inst.TypeArgs.At(i), protected) {
					return false, "generic instance mentions protected"
				}
			}
		}
	}
	if !verifyNoAliasedProtectedContainerMutation(p, protected) {
		return false, "aliased container mutation"
	}
	return true, ""
}

// verifyNoAliasedProtectedContainerMutation tracks local/parameter slice and map variables
// across the entire package (including memoFD) that may alias a container stored inside a
// protected memo struct (via assignment, range-value binding, or intra-package parameter passing)
// and rejects any element mutation, element address-taking, container builtin write,
// composite-literal/struct-field/global escape, or cross-package/interface call.
func verifyNoAliasedProtectedContainerMutation(
	p *packages.Package,
	protected map[*types.Named]bool,
) bool {
	isProtectedPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		st, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && protected[st.Origin()]
	}
	return VerifyReadOnlyRefConfinement(p, RefConfineConfig{
		IsImmutablePtr:                  isProtectedPtr,
		SeedStructOrigin:                func(st *types.Named) bool { return protected[st] },
		AllowCompositeLitIntoSeedStruct: true,
		AllowCallArg: func(call *ast.CallExpr, argIdx int, arg ast.Expr) bool {
			if len(call.Args) != 1 || argIdx != 0 || call.Ellipsis.IsValid() {
				return false
			}
			sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !isSel || sel.Sel == nil {
				return false
			}
			fn, isFn := p.TypesInfo.Uses[sel.Sel].(*types.Func)
			if !isFn || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" {
				return false
			}
			if fn.Name() != "FieldByIndex" && fn.Name() != "FieldByIndexErr" {
				return false
			}
			sl, isSl := types.Unalias(p.TypesInfo.TypeOf(arg)).Underlying().(*types.Slice)
			return isSl && !typeContainsRefOrPointerWith(sl.Elem(), isProtectedPtr)
		},
	})
}

func verifyMemoFunctionBody(
	p *packages.Package,
	idx *pkgSyntaxIndex,
	memoFD *ast.FuncDecl,
	memoFnObj *types.Func,
	paramVar *types.Var,
	mapVar *types.Var,
	infoNamed *types.Named,
	protected map[*types.Named]bool,
) (bool, string) {
	// Identify dedicated package-scope mutex mu referenced exclusively inside memoFD.
	var muVar *types.Var
	isRWMutex := false
	for _, name := range p.Types.Scope().Names() {
		v, ok := p.Types.Scope().Lookup(name).(*types.Var)
		if !ok || v.Exported() {
			continue
		}
		rw := isNamedInPkg(v.Type(), "sync", "RWMutex")
		plain := isNamedInPkg(v.Type(), "sync", "Mutex")
		if !rw && !plain {
			continue
		}
		uses := idx.usesOf[v]
		if len(uses) == 0 {
			continue
		}
		allInMemo := true
		for _, id := range uses {
			if !idx.isSyncInFuncDecl(id, memoFD) {
				allInMemo = false
				break
			}
		}
		if allInMemo {
			if vs := idx.varSpecs[v]; vs != nil && len(vs.Values) > 0 {
				if len(vs.Values) != 1 {
					return false, "mu multi-value spec"
				}
				cl, ok := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
				if !ok || len(cl.Elts) != 0 {
					return false, "mu non-empty initializer"
				}
			}
			if idx.defCounts[v] != 1 {
				return false, "mu multi-def"
			}
			muVar = v
			isRWMutex = rw
			break
		}
	}
	if muVar == nil {
		return false, "muVar not found"
	}

	// Verify top-level read-lock lookup + immediate return-if-found + write-lock store in memoFD.Body.List.
	stmts := memoFD.Body.List
	if len(stmts) < 7 {
		return false, "fewer than 7 stmts"
	}
	rLockMethod := "Lock"
	if isRWMutex {
		rLockMethod = "RLock"
	}
	if !isMutexMethodStmt(p, stmts[0], muVar, rLockMethod) && !isMutexMethodStmt(p, stmts[0], muVar, "Lock") {
		return false, "stmt[0] not lock"
	}
	wantRUnlock := "Unlock"
	if isMutexMethodStmt(p, stmts[0], muVar, "RLock") {
		wantRUnlock = "RUnlock"
	}
	lookupAssign, ok := stmts[1].(*ast.AssignStmt)
	if !ok || (len(lookupAssign.Lhs) != 1 && len(lookupAssign.Lhs) != 2) || len(lookupAssign.Rhs) != 1 {
		return false, "stmt[1] not lookup assign"
	}
	lookupIdx, ok := ast.Unparen(lookupAssign.Rhs[0]).(*ast.IndexExpr)
	if !ok || !isIdentUsingObj(p, lookupIdx.X, mapVar) || !isIdentUsingObj(p, lookupIdx.Index, paramVar) {
		return false, "stmt[1] not M[param]"
	}
	lookedUpVar := lookupIdentVar(p, lookupAssign.Lhs[0])
	if lookedUpVar == nil {
		return false, "lookedUpVar nil"
	}
	var foundVar *types.Var
	if len(lookupAssign.Lhs) == 2 {
		foundVar = lookupIdentVar(p, lookupAssign.Lhs[1])
		if foundVar == nil {
			return false, "foundVar nil"
		}
	}
	if !isMutexMethodStmt(p, stmts[2], muVar, wantRUnlock) {
		return false, "stmt[2] not unlock"
	}
	ifFound, ok := stmts[3].(*ast.IfStmt)
	if !ok || ifFound.Init != nil || ifFound.Else != nil {
		return false, "stmt[3] not plain if"
	}
	if foundVar != nil {
		if !isIdentUsingObj(p, ifFound.Cond, foundVar) {
			return false, "stmt[3] cond not foundVar"
		}
	} else {
		be, isBin := ast.Unparen(ifFound.Cond).(*ast.BinaryExpr)
		if !isBin || be.Op != token.NEQ || !(isIdentUsingObj(p, be.X, lookedUpVar) && isNilIdent(p, be.Y) || isIdentUsingObj(p, be.Y, lookedUpVar) && isNilIdent(p, be.X)) {
			return false, "stmt[3] cond not != nil"
		}
	}
	if len(ifFound.Body.List) != 1 {
		return false, "stmt[3] body len != 1"
	}
	if _, ok := ifFound.Body.List[0].(*ast.ReturnStmt); !ok {
		return false, "stmt[3] body not return"
	}

	// Locate write-lock + M[param] = val + write-unlock near the end of stmts.
	wLockIdx := -1
	for i := 4; i < len(stmts); i++ {
		if isMutexMethodStmt(p, stmts[i], muVar, "Lock") {
			wLockIdx = i
			break
		}
	}
	if wLockIdx == -1 || wLockIdx+2 >= len(stmts) {
		return false, "wLockIdx missing"
	}
	storeStmtIdx := wLockIdx + 1
	afterStoreIdx := wLockIdx + 3
	if isDeferMutexMethodStmt(p, stmts[wLockIdx+1], muVar, "Unlock") {
		if wLockIdx+2 >= len(stmts) {
			return false, "defer unlock missing store"
		}
		storeStmtIdx = wLockIdx + 2
		afterStoreIdx = wLockIdx + 3
	} else if !isMutexMethodStmt(p, stmts[wLockIdx+2], muVar, "Unlock") {
		return false, "wUnlock missing"
	}
	storeAssign, ok := stmts[storeStmtIdx].(*ast.AssignStmt)
	if !ok || storeAssign.Tok != token.ASSIGN || len(storeAssign.Lhs) != 1 || len(storeAssign.Rhs) != 1 {
		return false, "storeAssign invalid"
	}
	storeIdx, ok := ast.Unparen(storeAssign.Lhs[0]).(*ast.IndexExpr)
	if !ok || !isIdentUsingObj(p, storeIdx.X, mapVar) || !isIdentUsingObj(p, storeIdx.Index, paramVar) {
		return false, "storeIdx not M[param]"
	}

	// Ensure mapVar and muVar are NEVER referenced outside their exact verified statement positions!
	allowedMapIdents := map[*ast.Ident]bool{
		ast.Unparen(lookupIdx.X).(*ast.Ident): true,
		ast.Unparen(storeIdx.X).(*ast.Ident):  true,
	}
	for _, id := range idx.usesOf[mapVar] {
		if !allowedMapIdents[id] {
			return false, "mapVar extra ref"
		}
	}
	allowedMuStmts := map[ast.Stmt]bool{
		stmts[0]:          true,
		stmts[2]:          true,
		stmts[wLockIdx]:   true,
		stmts[wLockIdx+1]: storeStmtIdx == wLockIdx+2,
		stmts[wLockIdx+2]: storeStmtIdx == wLockIdx+1,
	}
	for _, id := range idx.usesOf[muVar] {
		topSt := enclosingTopStmt(memoFD.Body, idx, id)
		if !allowedMuStmts[topSt] {
			return false, "muVar extra ref"
		}
	}

	// After storeStmtIdx, allow ONLY return statements returning side-effect-free
	// local variables, FieldVal selector chains on local variables, nil, or
	// compile-time constants (forbidding any post-publish assignment, builtin
	// copy/clear/delete/append, or helper call).
	for i := afterStoreIdx; i < len(stmts); i++ {
		ret, ok := stmts[i].(*ast.ReturnStmt)
		if !ok {
			return false, "post-store non-return"
		}
		for _, r := range ret.Results {
			if !isPurePostStoreReturnExpr(p, r) {
				return false, "post-store impure return expr"
			}
		}
	}

	// Verify deterministic pure body across stmts[4:wLockIdx] and return statements:
	// - Zero GoStmt, FuncLit, SendStmt, unary ARROW, or map/chan/func RangeStmt.
	// - Only allowed package-scope vars (mapVar, muVar, or init-only reflect.Type sentinels).
	// - Only pure deterministic calls.
	// - Zero mutations on pointers to any protected struct or through index/slice chains on protected structs.
	pureBody := true
	bodyReason := ""
	_ = infoNamed
	ast.Inspect(memoFD.Body, func(n ast.Node) bool {
		if !pureBody || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.GoStmt, *ast.FuncLit, *ast.SendStmt:
			pureBody = false
			bodyReason = "go/funclit/send"
			return false
		case *ast.UnaryExpr:
			if x.Op == token.ARROW {
				pureBody = false
				bodyReason = "chan arrow"
				return false
			}
			if x.Op == token.AND {
				if exprTakesAddrInsideProtected(p, x.X, protected) {
					pureBody = false
					bodyReason = "addr inside protected"
					return false
				}
				// Also forbid &localInfo on local value structs in protected (allowing fresh &structInfo{...} composite literals) so no pointer alias to a stack fieldInfo exists.
				if _, isComp := ast.Unparen(x.X).(*ast.CompositeLit); !isComp {
					if st := derefNamedStruct(p.TypesInfo.TypeOf(x.X)); st != nil && protected[st] {
						pureBody = false
						bodyReason = "addr of local protected"
						return false
					}
				}
			}
		case *ast.RangeStmt:
			rt := types.Unalias(p.TypesInfo.TypeOf(x.X)).Underlying()
			switch rt.(type) {
			case *types.Slice, *types.Array:
			case *types.Basic:
			default:
				pureBody = false
				bodyReason = "non-slice range"
				return false
			}
			if x.Tok == token.ASSIGN {
				if (x.Key != nil && exprChainMutatesPublishedProtected(p, x.Key, protected)) ||
					(x.Value != nil && exprChainMutatesPublishedProtected(p, x.Value, protected)) {
					pureBody = false
					bodyReason = "range mutates published"
					return false
				}
			}
		case *ast.IncDecStmt:
			if exprChainMutatesPublishedProtected(p, x.X, protected) {
				pureBody = false
				bodyReason = "incdec mutates published"
				return false
			}
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if exprChainMutatesPublishedProtected(p, lhs, protected) {
					pureBody = false
					bodyReason = "assign mutates published"
					return false
				}
			}
		case *ast.SelectorExpr:
			// Reference-typed (map/slice) fields of any pointer-to-protected struct may only be ranged over or measured via len/cap,
			// never aliased into local variables unless read-only confinement holds.
			if selInfo := p.TypesInfo.Selections[x]; selInfo != nil && selInfo.Kind() == types.FieldVal && isPtrToAnyProtected(selInfo.Recv(), protected) {
				switch types.Unalias(selInfo.Type()).Underlying().(type) {
				case *types.Map, *types.Slice:
					par := idx.parentUnparen(x)
					allowed := false
					if rng, ok := par.(*ast.RangeStmt); ok && ast.Unparen(rng.X) == x {
						allowed = true
					} else if call, ok := par.(*ast.CallExpr); ok && len(call.Args) == 1 && ast.Unparen(call.Args[0]) == x {
						if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
							if b, ok := p.TypesInfo.Uses[id].(*types.Builtin); ok && (b.Name() == "len" || b.Name() == "cap") {
								allowed = true
							}
						}
					}
					if !allowed {
						pureBody = false
						bodyReason = "ref field selector: " + x.Sel.Name
						return false
					}
				}
			}
		case *ast.Ident:
			if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && v.Pkg() == p.Types && !v.IsField() && v.Parent() == p.Types.Scope() {
				if v != mapVar && v != muVar && !isInitOnlyReflectTypeGlobal(p, idx, v) {
					pureBody = false
					bodyReason = "disallowed pkg var: " + v.Name()
					return false
				}
			}
		case *ast.CallExpr:
			if callMutatesProtectedContainer(p, x, protected) {
				pureBody = false
				bodyReason = "call mutates protected container"
				return false
			}
			if !isPureMemoCall(p, x, memoFnObj, muVar) {
				pureBody = false
				bodyReason = "impure call"
				return false
			}
		}
		return true
	})
	return pureBody, bodyReason
}

func isInitOnlyReflectTypeGlobal(p *packages.Package, idx *pkgSyntaxIndex, v *types.Var) bool {
	if v == nil || v.Exported() || idx.defCounts[v] != 1 || !isNamedInPkg(v.Type(), "reflect", "Type") {
		return false
	}
	if vs := idx.varSpecs[v]; vs != nil && len(vs.Values) > 0 {
		return false
	}
	wroteInInit := false
	for _, id := range idx.usesOf[v] {
		par := idx.parentUnparen(id)
		if un, ok := par.(*ast.UnaryExpr); ok && un.Op == token.AND {
			return false
		}
		if as, ok := par.(*ast.AssignStmt); ok {
			isLHS := false
			for li, l := range as.Lhs {
				if ast.Unparen(l) == id {
					isLHS = true
					fd := idx.syncEnclFuncDecl(id)
					if fd == nil || fd.Recv != nil || fd.Name.Name != "init" || as.Tok != token.ASSIGN || li >= len(as.Rhs) {
						return false
					}
					if !isPureReflectTypeDerivation(p, as.Rhs[li]) {
						return false
					}
					wroteInInit = true
				}
			}
			if isLHS {
				continue
			}
		}
		if inc, ok := par.(*ast.IncDecStmt); ok && ast.Unparen(inc.X) == id {
			return false
		}
	}
	return wroteInInit
}

func isPureReflectTypeDerivation(p *packages.Package, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	// Require every call inside expr to be either a Go type conversion or a pure
	// reflect type/zero-value query, and forbid reading any package-scope variable.
	valid := true
	sawReflectTypeQuery := false
	ast.Inspect(call, func(n ast.Node) bool {
		if !valid || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.FuncLit, *ast.GoStmt:
			valid = false
			return false
		case *ast.Ident:
			if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && v.Pkg() == p.Types && !v.IsField() && v.Parent() == p.Types.Scope() {
				valid = false
				return false
			}
		case *ast.CallExpr:
			fun := ast.Unparen(x.Fun)
			if p.TypesInfo.Types[fun].IsType() {
				return true
			}
			sel, isSel := fun.(*ast.SelectorExpr)
			if !isSel {
				valid = false
				return false
			}
			fn, isFn := p.TypesInfo.Uses[sel.Sel].(*types.Func)
			if !isFn || fn.Pkg() == nil || fn.Pkg().Path() != "reflect" {
				valid = false
				return false
			}
			switch fn.Name() {
			case "TypeOf", "Type", "PtrTo", "PointerTo":
				sawReflectTypeQuery = true
			case "ValueOf", "Elem", "Zero":
			default:
				valid = false
				return false
			}
		}
		return true
	})
	return valid && sawReflectTypeQuery
}

func isPureMemoCall(p *packages.Package, call *ast.CallExpr, memoFn *types.Func, muVar *types.Var) bool {
	fun := ast.Unparen(call.Fun)
	if tv := p.TypesInfo.Types[fun]; tv.IsType() {
		basic, isBasic := types.Unalias(tv.Type).Underlying().(*types.Basic)
		return !isBasic || basic.Kind() != types.UnsafePointer
	}
	if id, ok := fun.(*ast.Ident); ok {
		switch obj := p.TypesInfo.Uses[id].(type) {
		case *types.Builtin:
			switch obj.Name() {
			case "len", "cap", "make", "append", "copy", "new":
				return true
			}
			return false
		case *types.Func:
			return obj == memoFn
		}
		return false
	}
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if isIdentUsingObj(p, sel.X, muVar) {
		switch sel.Sel.Name {
		case "RLock", "RUnlock", "Lock", "Unlock":
			return len(call.Args) == 0
		}
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	name := fn.Name()
	if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil {
		if isNamedInPkg(selInfo.Recv(), "reflect", "Type") {
			switch name {
			case "Elem", "Field", "Key", "Kind", "Len", "Name", "NumField", "PkgPath",
				"Implements", "AssignableTo", "ConvertibleTo", "Comparable",
				"Bits", "Size", "Align", "FieldAlign", "String":
				return true
			}
			return false
		}
		if isNamedInPkg(selInfo.Recv(), "reflect", "StructTag") {
			return name == "Get" || name == "Lookup"
		}
		if isNamedInPkg(selInfo.Recv(), "reflect", "Kind") {
			return name == "String"
		}
		return false
	}
	switch pkgPath {
	case "reflect":
		return name == "TypeOf" || name == "PtrTo" || name == "PointerTo"
	case "errors":
		return name == "New"
	case "fmt":
		if (name == "Sprintf" || name == "Errorf") && len(call.Args) >= 1 {
			tv, ok := p.TypesInfo.Types[call.Args[0]]
			if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
				return false
			}
			fmtStr := constant.StringVal(tv.Value)
			if formatStringExposesPointerIdentity(fmtStr) {
				return false
			}
			for _, arg := range call.Args[1:] {
				at := p.TypesInfo.TypeOf(arg)
				if at == nil {
					return false
				}
				if _, isBasic := types.Unalias(at).Underlying().(*types.Basic); isBasic {
					continue
				}
				if isNamedInPkg(at, "reflect", "Type") || isNamedInPkg(at, "reflect", "Kind") || isNamedInPkg(at, "reflect", "StructTag") {
					continue
				}
				return false
			}
			return true
		}
		return false
	case "strings":
		switch name {
		case "Split", "SplitN", "Index", "IndexByte", "LastIndex",
			"ToLower", "ToUpper", "TrimSpace", "Trim", "TrimPrefix", "TrimSuffix",
			"HasPrefix", "HasSuffix", "Contains", "Cut", "Join", "Replace", "ReplaceAll", "EqualFold":
			return true
		}
	case "strconv":
		switch name {
		case "Itoa", "Atoi", "ParseInt", "ParseUint", "ParseBool", "FormatInt", "FormatUint", "Quote":
			return true
		}
	}
	return false
}

func formatStringExposesPointerIdentity(fmtStr string) bool {
	for i := 0; i < len(fmtStr); {
		if fmtStr[i] != '%' {
			i++
			continue
		}
		i++
		if i >= len(fmtStr) {
			return true
		}
		if fmtStr[i] == '%' {
			i++
			continue
		}
		hasSharp := false
		for i < len(fmtStr) {
			c := fmtStr[i]
			switch {
			case c == '#':
				hasSharp = true
				i++
			case c == '+' || c == '-' || c == ' ' || c == '0' || c == '.' || c == '*' || (c >= '1' && c <= '9'):
				i++
			case c == '[':
				i++
				for i < len(fmtStr) && fmtStr[i] != ']' {
					i++
				}
				if i >= len(fmtStr) {
					return true
				}
				i++
			default:
				goto checkVerb
			}
		}
	checkVerb:
		if i >= len(fmtStr) {
			return true
		}
		verb := fmtStr[i]
		if verb == 'p' || (verb == 'v' && hasSharp) {
			return true
		}
		i++
	}
	return false
}

func isPtrToAnyProtected(t types.Type, protected map[*types.Named]bool) bool {
	if t == nil {
		return false
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	st := derefNamedStruct(ptr.Elem())
	return st != nil && protected[st]
}

// exprChainMutatesPublishedProtected reports whether writing to lhs inside memoFD
// could mutate an already-published protected struct entry (via a pointer to any
// protected struct, a dereference, or an index/slice chain on a protected struct),
// while permitting direct field writes on unaliased stack-allocated value structs.
func exprChainMutatesPublishedProtected(p *packages.Package, lhs ast.Expr, protected map[*types.Named]bool) bool {
	lhs = ast.Unparen(lhs)
	switch e := lhs.(type) {
	case *ast.StarExpr:
		if st := derefNamedStruct(p.TypesInfo.TypeOf(e.X)); st != nil && protected[st] {
			return true
		}
		return exprChainMutatesPublishedProtected(p, e.X, protected)
	case *ast.IndexExpr:
		return exprChainMutatesPublishedProtected(p, e.X, protected)
	case *ast.SliceExpr:
		return exprChainMutatesPublishedProtected(p, e.X, protected)
	case *ast.SelectorExpr:
		if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
			if isPtrToAnyProtected(selInfo.Recv(), protected) || selectionCrossesEmbeddedPointer(selInfo) {
				return true
			}
			return exprChainMutatesPublishedProtected(p, e.X, protected)
		}
	}
	return false
}

func exprMutatesProtectedStruct(p *packages.Package, lhs ast.Expr, protected map[*types.Named]bool) bool {
	lhs = ast.Unparen(lhs)
	switch e := lhs.(type) {
	case *ast.SelectorExpr:
		if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
			hit := false
			forEachSelectionHopStruct(selInfo, func(st *types.Named) {
				if protected[st] {
					hit = true
				}
			})
			if hit {
				return true
			}
			return exprMutatesProtectedStruct(p, e.X, protected)
		}
	case *ast.StarExpr:
		if st := derefNamedStruct(p.TypesInfo.TypeOf(e.X)); st != nil && protected[st] {
			return true
		}
		return exprMutatesProtectedStruct(p, e.X, protected)
	case *ast.IndexExpr:
		if st := derefNamedStruct(p.TypesInfo.TypeOf(e)); st != nil && protected[st] {
			return true
		}
		return exprMutatesProtectedStruct(p, e.X, protected)
	case *ast.SliceExpr:
		return exprMutatesProtectedStruct(p, e.X, protected)
	}
	return false
}

func exprTakesAddrInsideProtected(p *packages.Package, inner ast.Expr, protected map[*types.Named]bool) bool {
	inner = ast.Unparen(inner)
	switch e := inner.(type) {
	case *ast.SelectorExpr:
		if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
			hit := false
			forEachSelectionHopStruct(selInfo, func(st *types.Named) {
				if protected[st] {
					hit = true
				}
			})
			if hit {
				return true
			}
			return exprTakesAddrInsideProtected(p, e.X, protected)
		}
	case *ast.IndexExpr:
		if st := derefNamedStruct(p.TypesInfo.TypeOf(e)); st != nil && protected[st] {
			return true
		}
		return exprTakesAddrInsideProtected(p, e.X, protected)
	case *ast.SliceExpr:
		return exprTakesAddrInsideProtected(p, e.X, protected)
	}
	return false
}

func callMutatesProtectedContainer(p *packages.Package, call *ast.CallExpr, protected map[*types.Named]bool) bool {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return false
	}
	b, ok := p.TypesInfo.Uses[id].(*types.Builtin)
	if !ok {
		return false
	}
	switch b.Name() {
	case "delete", "clear", "copy", "append":
		if len(call.Args) > 0 && exprMutatesProtectedStruct(p, call.Args[0], protected) {
			return true
		}
	}
	return false
}

func callBoxesProtectedIntoInterface(p *packages.Package, call *ast.CallExpr, protected map[*types.Named]bool) bool {
	fun := ast.Unparen(call.Fun)
	if id, isID := fun.(*ast.Ident); isID {
		if b, isB := p.TypesInfo.Uses[id].(*types.Builtin); isB {
			if b.Name() == "append" && len(call.Args) >= 2 {
				dstSlice := p.TypesInfo.TypeOf(call.Args[0])
				if dstSlice != nil {
					if sl, okSl := types.Unalias(dstSlice).Underlying().(*types.Slice); okSl {
						if call.Ellipsis.IsValid() {
							return assignErasesProtected(p.TypesInfo.TypeOf(call.Args[1]), dstSlice, protected)
						}
						for _, arg := range call.Args[1:] {
							if assignErasesProtected(p.TypesInfo.TypeOf(arg), sl.Elem(), protected) {
								return true
							}
						}
					}
				}
			}
			return false
		}
	}
	if tv := p.TypesInfo.Types[fun]; tv.IsType() {
		if len(call.Args) == 1 {
			argType := p.TypesInfo.TypeOf(call.Args[0])
			if typeMentionsProtectedStruct(argType, protected) {
				dst := types.Unalias(tv.Type)
				if b, isB := dst.Underlying().(*types.Basic); isB && b.Kind() == types.UnsafePointer {
					return true
				}
				if assignErasesProtected(argType, dst, protected) || !types.Identical(dst, types.Unalias(argType)) {
					return true
				}
			}
		}
		return false
	}
	sig, ok := types.Unalias(p.TypesInfo.TypeOf(fun)).Underlying().(*types.Signature)
	if !ok {
		return false
	}
	var argTypes []types.Type
	if len(call.Args) == 1 {
		if tup, isTup := p.TypesInfo.TypeOf(call.Args[0]).(*types.Tuple); isTup {
			for ti := 0; ti < tup.Len(); ti++ {
				argTypes = append(argTypes, tup.At(ti).Type())
			}
		}
	}
	if argTypes == nil {
		for _, arg := range call.Args {
			argTypes = append(argTypes, p.TypesInfo.TypeOf(arg))
		}
	}
	for i, argType := range argTypes {
		if !typeMentionsProtectedStruct(argType, protected) {
			continue
		}
		var formal types.Type
		if sig.Variadic() && i >= sig.Params().Len()-1 {
			if sl, ok := types.Unalias(sig.Params().At(sig.Params().Len() - 1).Type()).Underlying().(*types.Slice); ok && !call.Ellipsis.IsValid() {
				formal = sl.Elem()
			} else {
				formal = sig.Params().At(sig.Params().Len() - 1).Type()
			}
		} else if i < sig.Params().Len() {
			formal = sig.Params().At(i).Type()
		}
		if formal != nil && assignErasesProtected(argType, formal, protected) {
			return true
		}
	}
	return false
}

func assignErasesProtected(src, dst types.Type, protected map[*types.Named]bool) bool {
	if src == nil || dst == nil || len(protected) == 0 {
		return false
	}
	type pair struct {
		s, d types.Type
	}
	seen := map[pair]bool{}
	var walk func(s, d types.Type) bool
	walk = func(s, d types.Type) bool {
		if s == nil || d == nil || !typeMentionsProtectedStruct(s, protected) {
			return false
		}
		s = types.Unalias(s)
		d = types.Unalias(d)
		if types.Identical(s, d) {
			return false
		}
		k := pair{s: s, d: d}
		if seen[k] {
			return false
		}
		seen[k] = true
		if _, isIf := d.Underlying().(*types.Interface); isIf {
			return true
		}
		switch su := s.Underlying().(type) {
		case *types.Pointer:
			if du, ok := d.Underlying().(*types.Pointer); ok {
				return walk(su.Elem(), du.Elem())
			}
		case *types.Slice:
			if du, ok := d.Underlying().(*types.Slice); ok {
				return walk(su.Elem(), du.Elem())
			}
		case *types.Array:
			if du, ok := d.Underlying().(*types.Array); ok && su.Len() == du.Len() {
				return walk(su.Elem(), du.Elem())
			}
		case *types.Chan:
			if du, ok := d.Underlying().(*types.Chan); ok {
				return walk(su.Elem(), du.Elem())
			}
		case *types.Map:
			if du, ok := d.Underlying().(*types.Map); ok {
				return walk(su.Key(), du.Key()) || walk(su.Elem(), du.Elem())
			}
		case *types.Struct:
			if du, ok := d.Underlying().(*types.Struct); ok && su.NumFields() == du.NumFields() {
				for i := 0; i < su.NumFields(); i++ {
					if walk(su.Field(i).Type(), du.Field(i).Type()) {
						return true
					}
				}
				return false
			}
		case *types.Signature:
			if du, ok := d.Underlying().(*types.Signature); ok {
				sp, dp := su.Params(), du.Params()
				sr, dr := su.Results(), du.Results()
				if (sp == nil) != (dp == nil) || (sr == nil) != (dr == nil) {
					return true
				}
				if sp != nil && sp.Len() != dp.Len() {
					return true
				}
				if sr != nil && sr.Len() != dr.Len() {
					return true
				}
				for i := 0; sp != nil && i < sp.Len(); i++ {
					if walk(sp.At(i).Type(), dp.At(i).Type()) {
						return true
					}
				}
				for i := 0; sr != nil && i < sr.Len(); i++ {
					if walk(sr.At(i).Type(), dr.At(i).Type()) {
						return true
					}
				}
				return false
			}
		}
		return true
	}
	return walk(src, dst)
}

func typeMentionsProtectedStruct(root types.Type, protected map[*types.Named]bool) bool {
	if root == nil || len(protected) == 0 {
		return false
	}
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		if alias, isAlias := t.(*types.Alias); isAlias {
			if targs := alias.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					walk(targs.At(i))
				}
			}
			t = types.Unalias(t)
		}
		if seen[t] {
			return
		}
		seen[t] = true
		if named, isNamed := t.(*types.Named); isNamed {
			if protected[named] {
				hit = true
				return
			}
			if targs := named.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					walk(targs.At(i))
				}
			}
		}
		switch u := t.Underlying().(type) {
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
			walk(u.Params())
			walk(u.Results())
		case *types.Interface:
			for i := 0; i < u.NumEmbeddeds(); i++ {
				walk(u.EmbeddedType(i))
			}
			for i := 0; i < u.NumExplicitMethods(); i++ {
				walk(u.ExplicitMethod(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func pkgHasStructDerefWrite(p *packages.Package, targets ...*types.Named) bool {
	hit := false
	match := func(t types.Type) bool {
		st := derefNamedStruct(t)
		if st == nil {
			return false
		}
		for _, want := range targets {
			if want != nil && types.Identical(st, want) {
				return true
			}
		}
		return false
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if hit {
				return false
			}
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range as.Lhs {
				if star, ok := ast.Unparen(lhs).(*ast.StarExpr); ok && match(p.TypesInfo.TypeOf(star.X)) {
					hit = true
					return false
				}
			}
			return true
		})
	}
	return hit
}

func varWrittenOrAddrTakenInBody(p *packages.Package, idx *pkgSyntaxIndex, body *ast.BlockStmt, v *types.Var) bool {
	bad := false
	ast.Inspect(body, func(n ast.Node) bool {
		if bad || n == nil {
			return false
		}
		switch s := n.(type) {
		case *ast.AssignStmt:
			for _, l := range s.Lhs {
				if isIdentUsingObj(p, l, v) {
					bad = true
					return false
				}
			}
		case *ast.IncDecStmt:
			if isIdentUsingObj(p, s.X, v) {
				bad = true
				return false
			}
		case *ast.UnaryExpr:
			if s.Op == token.AND && isIdentUsingObj(p, s.X, v) {
				bad = true
				return false
			}
		}
		return true
	})
	_ = idx
	return bad
}

func enclosingTopStmt(body *ast.BlockStmt, idx *pkgSyntaxIndex, n ast.Node) ast.Stmt {
	cur := n
	for cur != nil && cur != body {
		par := idx.parentMap[cur]
		if par == body {
			st, _ := cur.(ast.Stmt)
			return st
		}
		cur = par
	}
	return nil
}

func isMutexMethodStmt(p *packages.Package, st ast.Stmt, muVar *types.Var, method string) bool {
	es, ok := st.(*ast.ExprStmt)
	if !ok {
		return false
	}
	return isMutexMethodCall(p, es.X, muVar, method)
}

func isDeferMutexMethodStmt(p *packages.Package, st ast.Stmt, muVar *types.Var, method string) bool {
	ds, ok := st.(*ast.DeferStmt)
	if !ok {
		return false
	}
	return isMutexMethodCall(p, ds.Call, muVar, method)
}

func isMutexMethodCall(p *packages.Package, expr ast.Expr, muVar *types.Var, method string) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method || !isIdentUsingObj(p, sel.X, muVar) {
		return false
	}
	fn, ok := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == "sync"
}

func stmtCallsRecvMutex(p *packages.Package, st ast.Stmt, recvVar *types.Var) bool {
	hit := false
	ast.Inspect(st, func(n ast.Node) bool {
		if hit || n == nil {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if isMutexMethodCall(p, call, recvVar, "Lock") || isMutexMethodCall(p, call, recvVar, "Unlock") {
				hit = true
				return false
			}
		}
		return true
	})
	return hit
}

func stmtContainsReturnOrBranch(st ast.Stmt) bool {
	hit := false
	ast.Inspect(st, func(n ast.Node) bool {
		if hit {
			return false
		}
		switch n.(type) {
		case *ast.ReturnStmt, *ast.BranchStmt, *ast.DeferStmt, *ast.GoStmt:
			hit = true
			return false
		}
		return true
	})
	return hit
}

func subtreeMentionsObj(p *packages.Package, root ast.Node, obj types.Object) bool {
	hit := false
	ast.Inspect(root, func(n ast.Node) bool {
		if hit {
			return false
		}
		if id, ok := n.(*ast.Ident); ok && p.TypesInfo.Uses[id] == obj {
			hit = true
			return false
		}
		return true
	})
	return hit
}

func lookupIdentVar(p *packages.Package, expr ast.Expr) *types.Var {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil
	}
	if v, ok := p.TypesInfo.Uses[id].(*types.Var); ok {
		return v
	}
	if v, ok := p.TypesInfo.Defs[id].(*types.Var); ok {
		return v
	}
	return nil
}

func isIdentUsingObj(p *packages.Package, expr ast.Expr, want types.Object) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && p.TypesInfo.Uses[id] == want
}

func isNilIdent(p *packages.Package, expr ast.Expr) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	return ok && p.TypesInfo.Uses[id] == types.Universe.Lookup("nil")
}

func isNamedInPkg(t types.Type, pkgPath, name string) bool {
	if t == nil {
		return false
	}
	n, ok := types.Unalias(t).(*types.Named)
	return ok && n.Obj() != nil && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == pkgPath && n.Obj().Name() == name
}

func isPtrToNamed(t types.Type, want *types.Named) bool {
	if t == nil || want == nil {
		return false
	}
	ptr, ok := types.Unalias(t).(*types.Pointer)
	return ok && types.Identical(types.Unalias(ptr.Elem()), want)
}

func derefNamedStruct(t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj() == nil || n.Obj().Pkg() == nil {
		return nil
	}
	if _, isSt := n.Underlying().(*types.Struct); !isSt {
		return nil
	}
	return n
}

func isBytePtrByteSliceMap(t types.Type) bool {
	m, ok := types.Unalias(t).Underlying().(*types.Map)
	if !ok {
		return false
	}
	kp, ok := types.Unalias(m.Key()).(*types.Pointer)
	if !ok {
		return false
	}
	kb, ok := types.Unalias(kp.Elem()).Underlying().(*types.Basic)
	if !ok || kb.Kind() != types.Byte {
		return false
	}
	vs, ok := types.Unalias(m.Elem()).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	vb, ok := types.Unalias(vs.Elem()).Underlying().(*types.Basic)
	return ok && vb.Kind() == types.Byte
}

func isPurePostStoreReturnExpr(p *packages.Package, r ast.Expr) bool {
	for {
		r = ast.Unparen(r)
		if isNilIdent(p, r) {
			return true
		}
		if tv := p.TypesInfo.Types[r]; tv.Value != nil {
			return true
		}
		if v := lookupIdentVar(p, r); v != nil && v.Parent() != p.Types.Scope() {
			return true
		}
		sel, ok := r.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		selInfo := p.TypesInfo.Selections[sel]
		if selInfo == nil || selInfo.Kind() != types.FieldVal {
			return false
		}
		r = sel.X
	}
}
