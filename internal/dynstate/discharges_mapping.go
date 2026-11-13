package dynstate

import (
	"go/ast"
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
