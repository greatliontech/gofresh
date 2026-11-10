package dynstate

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// deriveMappingDischarges mechanically verifies package-level virtual-memory
// mapping bookkeeping structures (REQ-closure-shared-dynamic-state-mapping).
func deriveMappingDischarges(audited bool, p *packages.Package, idx *refconfine.PkgIndex) []string {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil
	}
	if idx == nil {
		idx = refconfine.BuildPkgIndex(p)
	}
	var out []string
	for _, name := range p.Types.Scope().Names() {
		v, ok := p.Types.Scope().Lookup(name).(*types.Var)
		if !ok || !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			continue
		}
		if verifyMappingVar(audited, p, idx, v) {
			out = append(out, syntaxutil.DynamicVarKey(v))
		}
	}
	sort.Strings(out)
	return out
}

// deriveMemoDischarges mechanically verifies mutex-guarded reflect.Type
// structural memoizers whose computed entries are content-invariant and
// confined to unexported package internals (REQ-closure-shared-dynamic-state-memo).
func deriveMemoDischarges(audited bool, p *packages.Package, idx *refconfine.PkgIndex) []string {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil
	}
	if idx == nil {
		idx = refconfine.BuildPkgIndex(p)
	}
	var out []string
	for _, name := range p.Types.Scope().Names() {
		v, ok := p.Types.Scope().Lookup(name).(*types.Var)
		if !ok || !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			continue
		}
		if verifyMemoVar(audited, p, idx, v) {
			out = append(out, syntaxutil.DynamicVarKey(v))
		}
	}
	sort.Strings(out)
	return out
}

func verifyMappingVar(audited bool, p *packages.Package, idx *refconfine.PkgIndex, v *types.Var) bool {
	if v == nil || v.Exported() || idx.DefCounts[v] != 1 {
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
			if f.Embedded() && syntaxutil.IsNamedInPkg(f.Type(), "sync", "Mutex") {
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
	if len(idx.UsesOf[mutexField]) > 0 {
		return false
	}

	// Verify single &S{...} composite literal initializer and bound syscall targets.
	vs := idx.VarSpecs[v]
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
		for _, id := range idx.UsesOf[baseField] {
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
			fd := idx.FuncDecls[m]
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
	for _, id := range idx.UsesOf[v] {
		sel, ok := idx.ParentUnparen(id).(*ast.SelectorExpr)
		if !ok || ast.Unparen(sel.X) != id {
			return false
		}
		call, ok := idx.ParentUnparen(sel).(*ast.CallExpr)
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
		for _, id := range idx.UsesOf[cf] {
			if initKeyIdents[id] {
				continue
			}
			sel, ok := idx.ParentUnparen(id).(*ast.SelectorExpr)
			if !ok || sel.Sel != id {
				return false
			}
			call, ok := idx.ParentUnparen(sel).(*ast.CallExpr)
			if !ok || ast.Unparen(call.Fun) != sel {
				return false
			}
		}
	}

	// Verify every use of activeField occurs inside a verified locked method of outerNamed/baseNamed.
	activeMethods := map[*ast.FuncDecl]bool{}
	for _, id := range idx.UsesOf[activeField] {
		if initKeyIdents[id] {
			continue
		}
		fd := idx.SyncEnclFuncDecl(id)
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
		if refconfine.TypeMayCarryUnknownDynamic(audited, sig.Params().At(i).Type()) {
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
		_, ok := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(e)).(*types.Map)
		return ok && len(e.Elts) == 0
	case *ast.CallExpr:
		b := syntaxutil.LookupBuiltin(p.TypesInfo, e.Fun)
		if b == nil || b.Name() != "make" || len(e.Args) < 1 || len(e.Args) > 2 {
			return false
		}
		_, isMap := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(e)).(*types.Map)
		return isMap
	}
	return false
}

func verifyMapperSyscallTarget(p *packages.Package, idx *refconfine.PkgIndex, root *types.Func) bool {
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
		fd := idx.FuncDecls[fn]
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
				if b := syntaxutil.LookupBuiltin(p.TypesInfo, fun); b != nil {
					switch b.Name() {
					case "len", "cap", "min", "max", "Pointer", "Sizeof", "Offsetof", "Alignof", "Add":
						return true
					default:
						invalid = true
						return false
					}
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, fun)
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

func isMapperAllowedHelperGlobal(p *packages.Package, idx *refconfine.PkgIndex, v *types.Var) bool {
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
	spec := idx.VarSpecs[v]
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
				if rhsType == nil || refconfine.TypeMayCarryUnknownDynamic(true, rhsType) {
					return false
				}
			}
		}
		if !matchedInit {
			return false
		}
	}
	for _, u := range idx.UsesOf[v] {
		switch par := idx.ParentMap[u].(type) {
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
		if refconfine.TypeMayCarryUnknownDynamic(audited, sig.Params().At(i).Type()) {
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
		if refconfine.TypeMayCarryUnknownDynamic(audited, rt) {
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
					return !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type())
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
		return ok && tv.Type != nil && !refconfine.TypeMayCarryUnknownDynamic(audited, tv.Type)
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
									if v := syntaxutil.LookupIdentVar(p.TypesInfo, id); v != nil && types.Identical(v.Type(), preErr) {
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
				v := syntaxutil.LookupIdentVar(p.TypesInfo, id)
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
	idx *refconfine.PkgIndex,
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
	if syntaxutil.VarWrittenOrAddrTakenInBody(p.TypesInfo, fd.Body, recvVar) {
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
		if syntaxutil.IsMutexMethodStmt(p.TypesInfo, st, recvVar, "Lock") {
			if lockIdx != -1 {
				return false
			}
			lockIdx = i
			if i+1 < len(stmts) && syntaxutil.IsDeferMutexMethodStmt(p.TypesInfo, stmts[i+1], recvVar, "Unlock") {
				deferUnlock = true
			}
			continue
		}
		if syntaxutil.IsMutexMethodStmt(p.TypesInfo, st, recvVar, "Unlock") {
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
			if syntaxutil.SubtreeMentionsObj(p.TypesInfo, st, activeField) {
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
				if syntaxutil.IsMutexMethodCall(p.TypesInfo, x, recvVar, "Lock") || syntaxutil.IsMutexMethodCall(p.TypesInfo, x, recvVar, "Unlock") {
					validActive = false
					return false
				}
			case *ast.Ident:
				if p.TypesInfo.Uses[x] != activeField {
					return true
				}
				sel, ok := idx.ParentUnparen(x).(*ast.SelectorExpr)
				if !ok || sel.Sel != x || !syntaxutil.IsIdentUsingObj(p.TypesInfo, sel.X, recvVar) {
					validActive = false
					return false
				}
				par := idx.ParentUnparen(sel)
				switch pn := par.(type) {
				case *ast.IndexExpr:
					if ast.Unparen(pn.X) != sel {
						validActive = false
						return false
					}
					idxPar := idx.ParentUnparen(pn)
					if un, ok := idxPar.(*ast.UnaryExpr); ok && un.Op == token.AND {
						validActive = false
						return false
					}
					keyVar := syntaxutil.LookupIdentVar(p.TypesInfo, pn.Index)
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
							valVar := syntaxutil.LookupIdentVar(p.TypesInfo, as.Rhs[0])
							if valVar == nil || !mappedSlices[valVar] || mappedKeys[keyVar] != valVar {
								validActive = false
								return false
							}
						}
					}
				case *ast.CallExpr:
					b := syntaxutil.LookupBuiltin(p.TypesInfo, pn.Fun)
					if b == nil || b.Name() != "delete" || len(pn.Args) != 2 || ast.Unparen(pn.Args[0]) != sel {
						validActive = false
						return false
					}
					delKey := syntaxutil.LookupIdentVar(p.TypesInfo, pn.Args[1])
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
				if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && syntaxutil.IsIdentUsingObj(p.TypesInfo, sel.X, recvVar) {
					if fld, ok := p.TypesInfo.Uses[sel.Sel].(*types.Var); ok && callableFields[fld] != nil {
						if v := syntaxutil.LookupIdentVar(p.TypesInfo, as.Lhs[0]); v != nil {
							addrs[v] = true
							return true
						}
					}
				}
			}
		}
		for _, l := range as.Lhs {
			if v := syntaxutil.LookupIdentVar(p.TypesInfo, l); v != nil {
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
				if v := syntaxutil.LookupIdentVar(p.TypesInfo, l); v != nil {
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
					if hdrVar := syntaxutil.LookupIdentVar(p.TypesInfo, sel.X); hdrVar != nil && hdrAlias[hdrVar] != nil {
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
	b := syntaxutil.LookupBuiltin(p.TypesInfo, call.Fun)
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
	if !syntaxutil.IsUnsafePointerType(p.TypesInfo.TypeOf(call)) {
		return false
	}
	v := syntaxutil.LookupIdentVar(p.TypesInfo, call.Args[0])
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
	v := syntaxutil.LookupIdentVar(p.TypesInfo, un.X)
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
	return syntaxutil.LookupIdentVar(p.TypesInfo, ie.X)
}

func verifyMemoVar(audited bool, p *packages.Package, idx *refconfine.PkgIndex, mapVar *types.Var) bool {
	ok, _ := verifyMemoVarWithReason(audited, p, idx, mapVar)
	return ok
}

func verifyMemoVarWithReason(audited bool, p *packages.Package, idx *refconfine.PkgIndex, mapVar *types.Var) (bool, string) {
	if mapVar == nil || mapVar.Exported() || idx.DefCounts[mapVar] != 1 {
		return false, "nil, exported, or multi-def mapVar"
	}
	mt, ok := types.Unalias(mapVar.Type()).Underlying().(*types.Map)
	if !ok || !syntaxutil.IsNamedInPkg(mt.Key(), "reflect", "Type") {
		return false, "not map[reflect.Type]..."
	}
	if refconfine.TypeMayCarryUnknownDynamic(audited, mt.Elem()) {
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

	vs := idx.VarSpecs[mapVar]
	if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 || !isEmptyMapInitializer(p, vs.Values[0]) {
		return false, "varSpec not single empty map initializer"
	}

	// All references to mapVar must lie synchronously inside a single top-level plain function memoFn.
	uses := idx.UsesOf[mapVar]
	if len(uses) == 0 {
		return false, "zero uses of mapVar"
	}
	var memoFD *ast.FuncDecl
	for _, id := range uses {
		fd := idx.SyncEnclFuncDecl(id)
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
	if !syntaxutil.IsNamedInPkg(paramVar.Type(), "reflect", "Type") {
		return false, "paramVar not reflect.Type"
	}
	if syntaxutil.VarWrittenOrAddrTakenInBody(p.TypesInfo, memoFD.Body, paramVar) {
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
	idx *refconfine.PkgIndex,
	memoFD *ast.FuncDecl,
	protected map[*types.Named]bool,
) (bool, string) {
	isProtectedPtr := func(t types.Type) bool {
		ptr, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return false
		}
		st, ok := types.Unalias(ptr.Elem()).(*types.Named)
		return ok && protected[st.Origin()]
	}
	return refconfine.VerifyProtectedStructOriginConfinement(p, idx, memoFD, protected, func(call *ast.CallExpr, argIdx int, arg ast.Expr) bool {
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
		sl, isSl := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(arg)).(*types.Slice)
		return isSl && !refconfine.TypeContainsRefOrPointerWith(sl.Elem(), isProtectedPtr)
	})
}

func verifyMemoFunctionBody(
	p *packages.Package,
	idx *refconfine.PkgIndex,
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
		rw := syntaxutil.IsNamedInPkg(v.Type(), "sync", "RWMutex")
		plain := syntaxutil.IsNamedInPkg(v.Type(), "sync", "Mutex")
		if !rw && !plain {
			continue
		}
		uses := idx.UsesOf[v]
		if len(uses) == 0 {
			continue
		}
		allInMemo := true
		for _, id := range uses {
			if !idx.IsSyncInFuncDecl(id, memoFD) {
				allInMemo = false
				break
			}
		}
		if allInMemo {
			if vs := idx.VarSpecs[v]; vs != nil && len(vs.Values) > 0 {
				if len(vs.Values) != 1 {
					return false, "mu multi-value spec"
				}
				cl, ok := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
				if !ok || len(cl.Elts) != 0 {
					return false, "mu non-empty initializer"
				}
			}
			if idx.DefCounts[v] != 1 {
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
	if !syntaxutil.IsMutexMethodStmt(p.TypesInfo, stmts[0], muVar, rLockMethod) && !syntaxutil.IsMutexMethodStmt(p.TypesInfo, stmts[0], muVar, "Lock") {
		return false, "stmt[0] not lock"
	}
	wantRUnlock := "Unlock"
	if syntaxutil.IsMutexMethodStmt(p.TypesInfo, stmts[0], muVar, "RLock") {
		wantRUnlock = "RUnlock"
	}
	lookupAssign, ok := stmts[1].(*ast.AssignStmt)
	if !ok || (len(lookupAssign.Lhs) != 1 && len(lookupAssign.Lhs) != 2) || len(lookupAssign.Rhs) != 1 {
		return false, "stmt[1] not lookup assign"
	}
	lookupIdx, ok := ast.Unparen(lookupAssign.Rhs[0]).(*ast.IndexExpr)
	if !ok || !syntaxutil.IsIdentUsingObj(p.TypesInfo, lookupIdx.X, mapVar) || !syntaxutil.IsIdentUsingObj(p.TypesInfo, lookupIdx.Index, paramVar) {
		return false, "stmt[1] not M[param]"
	}
	lookedUpVar := syntaxutil.LookupIdentVar(p.TypesInfo, lookupAssign.Lhs[0])
	if lookedUpVar == nil {
		return false, "lookedUpVar nil"
	}
	var foundVar *types.Var
	if len(lookupAssign.Lhs) == 2 {
		foundVar = syntaxutil.LookupIdentVar(p.TypesInfo, lookupAssign.Lhs[1])
		if foundVar == nil {
			return false, "foundVar nil"
		}
	}
	if !syntaxutil.IsMutexMethodStmt(p.TypesInfo, stmts[2], muVar, wantRUnlock) {
		return false, "stmt[2] not unlock"
	}
	ifFound, ok := stmts[3].(*ast.IfStmt)
	if !ok || ifFound.Init != nil || ifFound.Else != nil {
		return false, "stmt[3] not plain if"
	}
	if foundVar != nil {
		if !syntaxutil.IsIdentUsingObj(p.TypesInfo, ifFound.Cond, foundVar) {
			return false, "stmt[3] cond not foundVar"
		}
	} else {
		be, isBin := ast.Unparen(ifFound.Cond).(*ast.BinaryExpr)
		if !isBin || be.Op != token.NEQ || !(syntaxutil.IsIdentUsingObj(p.TypesInfo, be.X, lookedUpVar) && syntaxutil.IsNilIdent(p.TypesInfo, be.Y) || syntaxutil.IsIdentUsingObj(p.TypesInfo, be.Y, lookedUpVar) && syntaxutil.IsNilIdent(p.TypesInfo, be.X)) {
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
		if syntaxutil.IsMutexMethodStmt(p.TypesInfo, stmts[i], muVar, "Lock") {
			wLockIdx = i
			break
		}
	}
	if wLockIdx == -1 || wLockIdx+2 >= len(stmts) {
		return false, "wLockIdx missing"
	}
	storeStmtIdx := wLockIdx + 1
	afterStoreIdx := wLockIdx + 3
	if syntaxutil.IsDeferMutexMethodStmt(p.TypesInfo, stmts[wLockIdx+1], muVar, "Unlock") {
		if wLockIdx+2 >= len(stmts) {
			return false, "defer unlock missing store"
		}
		storeStmtIdx = wLockIdx + 2
		afterStoreIdx = wLockIdx + 3
	} else if !syntaxutil.IsMutexMethodStmt(p.TypesInfo, stmts[wLockIdx+2], muVar, "Unlock") {
		return false, "wUnlock missing"
	}
	storeAssign, ok := stmts[storeStmtIdx].(*ast.AssignStmt)
	if !ok || storeAssign.Tok != token.ASSIGN || len(storeAssign.Lhs) != 1 || len(storeAssign.Rhs) != 1 {
		return false, "storeAssign invalid"
	}
	storeIdx, ok := ast.Unparen(storeAssign.Lhs[0]).(*ast.IndexExpr)
	if !ok || !syntaxutil.IsIdentUsingObj(p.TypesInfo, storeIdx.X, mapVar) || !syntaxutil.IsIdentUsingObj(p.TypesInfo, storeIdx.Index, paramVar) {
		return false, "storeIdx not M[param]"
	}

	// Ensure mapVar and muVar are NEVER referenced outside their exact verified statement positions!
	allowedMapIdents := map[*ast.Ident]bool{
		ast.Unparen(lookupIdx.X).(*ast.Ident): true,
		ast.Unparen(storeIdx.X).(*ast.Ident):  true,
	}
	for _, id := range idx.UsesOf[mapVar] {
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
	for _, id := range idx.UsesOf[muVar] {
		topSt := enclosingTopStmt(memoFD.Body, idx, id)
		if !allowedMuStmts[topSt] {
			return false, "muVar extra ref"
		}
	}

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
				if refconfine.TouchesAnyNamedStruct(p, x.X, protected) {
					pureBody = false
					bodyReason = "addr inside protected"
					return false
				}
				if _, isComp := ast.Unparen(x.X).(*ast.CompositeLit); !isComp {
					if st := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x.X)); st != nil && protected[st] {
						pureBody = false
						bodyReason = "addr of local protected"
						return false
					}
				}
			}
		case *ast.RangeStmt:
			rt := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(x.X))
			switch rt.(type) {
			case *types.Slice, *types.Array, *types.Basic:
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
			if selInfo := p.TypesInfo.Selections[x]; selInfo != nil && selInfo.Kind() == types.FieldVal && isPtrToAnyProtected(selInfo.Recv(), protected) {
				switch types.Unalias(selInfo.Type()).Underlying().(type) {
				case *types.Map, *types.Slice:
					par := idx.ParentUnparen(x)
					allowed := false
					if rng, ok := par.(*ast.RangeStmt); ok && ast.Unparen(rng.X) == x {
						allowed = true
					} else if call, ok := par.(*ast.CallExpr); ok && len(call.Args) == 1 && ast.Unparen(call.Args[0]) == x {
						if b := syntaxutil.LookupBuiltin(p.TypesInfo, call.Fun); b != nil && (b.Name() == "len" || b.Name() == "cap") {
							allowed = true
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

func isInitOnlyReflectTypeGlobal(p *packages.Package, idx *refconfine.PkgIndex, v *types.Var) bool {
	if v == nil || v.Exported() || idx.DefCounts[v] != 1 || !syntaxutil.IsNamedInPkg(v.Type(), "reflect", "Type") {
		return false
	}
	if vs := idx.VarSpecs[v]; vs != nil && len(vs.Values) > 0 {
		return false
	}
	wroteInInit := false
	for _, id := range idx.UsesOf[v] {
		par := idx.ParentUnparen(id)
		if un, ok := par.(*ast.UnaryExpr); ok && un.Op == token.AND {
			return false
		}
		if as, ok := par.(*ast.AssignStmt); ok {
			isLHS := false
			for li, l := range as.Lhs {
				if ast.Unparen(l) == id {
					isLHS = true
					fd := idx.SyncEnclFuncDecl(id)
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
		return !syntaxutil.IsUnsafePointerType(tv.Type)
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
	if syntaxutil.IsIdentUsingObj(p.TypesInfo, sel.X, muVar) {
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
		if syntaxutil.IsNamedInPkg(selInfo.Recv(), "reflect", "Type") {
			switch name {
			case "Elem", "Field", "Key", "Kind", "Len", "Name", "NumField", "PkgPath",
				"Implements", "AssignableTo", "ConvertibleTo", "Comparable",
				"Bits", "Size", "Align", "FieldAlign", "String":
				return true
			}
			return false
		}
		if syntaxutil.IsNamedInPkg(selInfo.Recv(), "reflect", "StructTag") {
			return name == "Get" || name == "Lookup"
		}
		if syntaxutil.IsNamedInPkg(selInfo.Recv(), "reflect", "Kind") {
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
				if syntaxutil.IsNamedInPkg(at, "reflect", "Type") || syntaxutil.IsNamedInPkg(at, "reflect", "Kind") || syntaxutil.IsNamedInPkg(at, "reflect", "StructTag") {
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
	st := syntaxutil.DerefNamedStruct(ptr.Elem())
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
		if st := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(e.X)); st != nil && protected[st] {
			return true
		}
		return exprChainMutatesPublishedProtected(p, e.X, protected)
	case *ast.IndexExpr:
		return exprChainMutatesPublishedProtected(p, e.X, protected)
	case *ast.SliceExpr:
		return exprChainMutatesPublishedProtected(p, e.X, protected)
	case *ast.SelectorExpr:
		if selInfo := p.TypesInfo.Selections[e]; selInfo != nil && selInfo.Kind() == types.FieldVal {
			if isPtrToAnyProtected(selInfo.Recv(), protected) || syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
				return true
			}
			return exprChainMutatesPublishedProtected(p, e.X, protected)
		}
	}
	return false
}

func callMutatesProtectedContainer(p *packages.Package, call *ast.CallExpr, protected map[*types.Named]bool) bool {
	b := syntaxutil.LookupBuiltin(p.TypesInfo, call.Fun)
	if b == nil {
		return false
	}
	switch b.Name() {
	case "delete", "clear", "copy", "append":
		if len(call.Args) > 0 && refconfine.TouchesAnyNamedStruct(p, call.Args[0], protected) {
			return true
		}
	}
	return false
}

func pkgHasStructDerefWrite(p *packages.Package, targets ...*types.Named) bool {
	hit := false
	match := func(t types.Type) bool {
		st := syntaxutil.DerefNamedStruct(t)
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

func enclosingTopStmt(body *ast.BlockStmt, idx *refconfine.PkgIndex, n ast.Node) ast.Stmt {
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

func stmtCallsRecvMutex(p *packages.Package, st ast.Stmt, recvVar *types.Var) bool {
	hit := false
	ast.Inspect(st, func(n ast.Node) bool {
		if hit || n == nil {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok {
			if syntaxutil.IsMutexMethodCall(p.TypesInfo, call, recvVar, "Lock") || syntaxutil.IsMutexMethodCall(p.TypesInfo, call, recvVar, "Unlock") {
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
		if syntaxutil.IsNilIdent(p.TypesInfo, r) {
			return true
		}
		if tv := p.TypesInfo.Types[r]; tv.Value != nil {
			return true
		}
		if v := syntaxutil.LookupIdentVar(p.TypesInfo, r); v != nil && v.Parent() != p.Types.Scope() {
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
