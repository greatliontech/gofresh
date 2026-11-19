package dynstate

import (
	"go/ast"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
)

func verifyMapperInitValueFlowIR(
	p *packages.Package,
	val *flowir.Value,
	outerNamed, baseNamed *types.Named,
	baseField, activeField *types.Var,
	callableFields map[*types.Var]*types.Signature,
	initKeyIdents map[*ast.Ident]bool,
	boundTargets map[*types.Var]*types.Func,
	activeInitialized *bool,
) bool {
	if val == nil || val.Kind != flowir.ValAllocFresh || val.AllocKind != flowir.AllocCompositeLit || val.ElemType == nil {
		return false
	}
	elemT := types.Unalias(val.ElemType)
	if !types.Identical(elemT, outerNamed) && (baseNamed == nil || !types.Identical(elemT, baseNamed)) {
		return false
	}
	// Require keyed composite literals and record key idents for field-use confinement.
	if rawExpr := ast.Unparen(val.Raw); rawExpr != nil {
		if un, isUn := rawExpr.(*ast.UnaryExpr); isUn {
			rawExpr = ast.Unparen(un.X)
		}
		cl, ok := rawExpr.(*ast.CompositeLit)
		if !ok || len(cl.Elts) != len(val.CompositeElts) {
			return false
		}
		for _, rawElt := range cl.Elts {
			kv, isKV := rawElt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			kid, isID := kv.Key.(*ast.Ident)
			if !isID {
				return false
			}
			initKeyIdents[kid] = true
		}
	} else {
		return false
	}

	for _, elt := range val.CompositeElts {
		fld := elt.Field
		if fld == nil || elt.Value == nil {
			return false
		}
		if fld == activeField {
			if *activeInitialized || !refconfine.IsEmptyMapInitValue(elt.Value) {
				return false
			}
			*activeInitialized = true
			continue
		}
		if callableFields[fld] != nil {
			if boundTargets[fld] != nil || elt.Value.Kind != flowir.ValPlace ||
				elt.Value.Place.Root != flowir.RootFunc || elt.Value.Place.IsMethodExpr {
				return false
			}
			fn := elt.Value.Place.Func
			if fn == nil || fn.Pkg() != p.Types || fn.Exported() {
				return false
			}
			if sig, ok := fn.Type().(*types.Signature); !ok || sig.Recv() != nil {
				return false
			}
			boundTargets[fld] = fn
			continue
		}
		if baseNamed != nil && fld == baseField && fld.Embedded() && types.Identical(types.Unalias(fld.Type()), baseNamed) {
			if !verifyMapperInitValueFlowIR(p, elt.Value, outerNamed, baseNamed, baseField, activeField, callableFields, initKeyIdents, boundTargets, activeInitialized) {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func verifyMapperSyscallTargetFlowIR(p *packages.Package, fc *pkgFlowCache, idx *refconfine.PkgIndex, root *types.Func) bool {
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
		b := fc.funcBody(p, fd)
		if b == nil {
			invalid = true
			return
		}
		checkGlobal := func(gv *types.Var) bool {
			if gv == nil || gv.IsField() {
				return true
			}
			if gv.Pkg() != p.Types || gv.Parent() == p.Types.Scope() {
				okG, seen := checkedGlobals[gv]
				if !seen {
					okG = isMapperAllowedHelperGlobalFlowIR(p, fc, idx, gv)
					checkedGlobals[gv] = okG
				}
				return okG
			}
			return true
		}

		checkVal := func(v *flowir.Value) {
			if v == nil || invalid {
				return
			}
			v.WalkValues(func(cur *flowir.Value) bool {
				if invalid {
					return false
				}
				switch cur.Kind {
				case flowir.ValInvalid, flowir.ValMakeClosure, flowir.ValChanRecv, flowir.ValMethodVal:
					invalid = true
					return false
				case flowir.ValPlace:
					if cur.Place.Root == flowir.RootPkgGlobal && !checkGlobal(cur.Place.Obj) {
						invalid = true
						return false
					}
				case flowir.ValAddrOf:
					if cur.AddrPlace.Root == flowir.RootPkgGlobal && !checkGlobal(cur.AddrPlace.Obj) {
						invalid = true
						return false
					}
				case flowir.ValCall:
					switch cur.CallKind {
					case flowir.CallIIFE, flowir.CallIndirect:
						invalid = true
						return false
					case flowir.CallBuiltin:
						switch cur.BuiltinName {
						case "len", "cap", "min", "max", "Pointer", "Sizeof", "Offsetof", "Alignof", "Add":
							return true
						default:
							invalid = true
							return false
						}
					case flowir.CallPlain, flowir.CallMethod:
						if cur.IsMethodExprCall || cur.CalleeFunc == nil {
							invalid = true
							return false
						}
						callee := cur.CalleeFunc
						if isStdSyscallPrimitive(p, callee) {
							reachesKernel = true
							return true
						}
						if isAllowedSyscallBracket(p, callee) {
							return true
						}
						if callee.Pkg() == p.Types {
							walk(callee)
							return !invalid
						}
						invalid = true
						return false
					default:
						invalid = true
						return false
					}
				}
				return !invalid
			})
		}

		b.ForEachSyncOp(func(op *flowir.Op) bool {
			if invalid {
				return false
			}
			switch op.Kind {
			case flowir.OpGo, flowir.OpChanSend:
				invalid = true
				return false
			case flowir.OpAssign:
				for _, dst := range op.Dsts {
					if dst.Root == flowir.RootPkgGlobal && !checkGlobal(dst.Obj) {
						invalid = true
						return false
					}
				}
			}
			op.ForEachValue(func(v *flowir.Value) bool {
				checkVal(v)
				return !invalid
			})
			return !invalid
		})
	}
	walk(root)
	return reachesKernel && !invalid
}

func isAllowedSyscallBracket(p *packages.Package, fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil || !isTrueStdlibInPkg(p, fn.Pkg().Path()) {
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

func isMapperAllowedHelperGlobalFlowIR(p *packages.Package, fc *pkgFlowCache, idx *refconfine.PkgIndex, v *types.Var) bool {
	if v == nil || v.IsField() || v.Pkg() != p.Types || v.Parent() != p.Types.Scope() || v.Exported() {
		return false
	}
	isErr := isUniverseErrorType(v.Type())
	isUintptr := false
	if b, ok := types.Unalias(v.Type()).Underlying().(*types.Basic); ok && b.Kind() == types.Uintptr {
		isUintptr = true
	}
	if !isErr && !isUintptr {
		return false
	}
	st := fc.ensureVarWriteInfos(p)[v]
	if st == nil || st.defs != 1 || st.hasNonPlainDef || st.hasPostDefWrite || st.hasBuiltinMut || st.hasChanSend {
		return false
	}
	if isUintptr {
		return st.hasZeroDecl && st.initVal == nil
	}
	if st.hasExplicitAddr || st.hasZeroDecl || st.initVal == nil || st.initVal.Type == nil {
		return false
	}
	return !refconfine.TypeMayCarryUnknownDynamic(true, st.initVal.Type)
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

func isStdSyscallPrimitive(p *packages.Package, fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "syscall" || !isTrueStdlibInPkg(p, "syscall") {
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
