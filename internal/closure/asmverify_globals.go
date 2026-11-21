package closure

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/refconfine"
)

const (
	nonReadOnlyGlobalsSummaryKey = "gofresh/non-readonly-globals@1"
	asmExternalGlobalsSummaryKey = "gofresh/asm-external-globals@1"
)

type asmExternalGlobalVerdict struct {
	vars []*types.Var
	ok   bool
}

// progAsmTextLinkageClean verifies that neither fnName nor any intra-package
// Go-named TEXT callee in goCallees carries a go:linkname binding across the
// loaded program, and that no intra-package Go-named TEXT callee resolves to a
// Go-bodied function across any AST or SSA compartment of pkgPath.
func progAsmTextLinkageClean(haz *nonSSAGlobalHazardSummary, p *program, pkgPath, fnName string, goCallees []string) bool {
	if haz == nil || haz.hasMalformedLinkname || p == nil || pkgPath == "" {
		return false
	}
	if fnName != "" && haz.linknamedVars[pkgVarKey{pkgPath: pkgPath, name: fnName}] {
		return false
	}
	for _, calleeName := range goCallees {
		if calleeName == "" || haz.linknamedVars[pkgVarKey{pkgPath: pkgPath, name: calleeName}] {
			return false
		}
		for _, apkg := range haz.allPkgsByPath[pkgPath] {
			if apkg == nil {
				continue
			}
			for _, af := range apkg.Syntax {
				if af == nil {
					continue
				}
				for _, decl := range af.Decls {
					if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name != nil && fd.Name.Name == calleeName && fd.Body != nil {
						return false
					}
				}
			}
		}
		if p.Prog != nil {
			for _, sp := range p.Prog.AllPackages() {
				if sp != nil && sp.Pkg != nil && sp.Pkg.Path() == pkgPath {
					if ssaFn := sp.Func(calleeName); ssaFn != nil && len(ssaFn.Blocks) > 0 {
						return false
					}
				}
			}
		}
	}
	return true
}

func (b *tier2Base) isAsmTextLinkageClean(pkg *listPkg, fnName string, goCallees []string) bool {
	if b == nil || b.prog == nil || pkg == nil {
		return false
	}
	srcPath := pkg.SourcePath()
	haz := nonSSAGlobalHazardsSummary(true, b.prog)
	if !progAsmTextLinkageClean(haz, b.prog, srcPath, fnName, goCallees) {
		return false
	}
	if pkg.ImportPath != "" && pkg.ImportPath != srcPath {
		if fnName != "" && haz.linknamedVars[pkgVarKey{pkgPath: pkg.ImportPath, name: fnName}] {
			return false
		}
		for _, calleeName := range goCallees {
			if haz.linknamedVars[pkgVarKey{pkgPath: pkg.ImportPath, name: calleeName}] {
				return false
			}
		}
	}
	checkNoBaseLinkname := func(sym string) bool {
		if sym == "" {
			return true
		}
		if len(b.objsByLinkTarget[srcPath+"."+sym]) > 0 {
			return false
		}
		if pkg.ImportPath != "" && len(b.objsByLinkTarget[pkg.ImportPath+"."+sym]) > 0 {
			return false
		}
		for _, idx := range b.idxByTypes {
			if idx == nil || (idx.path != srcPath && idx.path != pkg.ImportPath && (idx.meta == nil || idx.meta.Dir != pkg.Dir)) {
				continue
			}
			if idx.linknameByName[sym] != "" {
				return false
			}
			if idx.pkg != nil && idx.pkg.Types != nil && idx.pkg.Types.Scope() != nil {
				if obj := idx.pkg.Types.Scope().Lookup(sym); obj != nil && idx.linknames[obj] != "" {
					return false
				}
			}
		}
		return true
	}
	if !checkNoBaseLinkname(fnName) {
		return false
	}
	for _, calleeName := range goCallees {
		if !checkNoBaseLinkname(calleeName) {
			return false
		}
	}
	return true
}

// astPackageVarReadOnly verifies across every syntax tree of pkg (including
// uninstantiated generic functions that SSA may not materialize) that v is
// never assigned, incremented/decremented, bound in a range clause, or
// address-taken, and (when allowDeclInit is false) carries no ValueSpec
// initializer.
func astPackageVarReadOnly(pkg *packages.Package, v *types.Var, allowDeclInit bool) bool {
	return verifyPackageVarASTConfinement(pkg, v, allowDeclInit, nil)
}

func isAsmLookupTableValueType(t types.Type) bool {
	return isAsmLookupTableValueTypeSeen(t, map[types.Type]bool{})
}

func isAsmLookupTableValueTypeSeen(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return true
	}
	seen[t] = true
	switch u := t.Underlying().(type) {
	case *types.Basic:
		const allowedScalarInfo = types.IsBoolean | types.IsInteger | types.IsFloat | types.IsComplex
		return (u.Info()&allowedScalarInfo) != 0 && (u.Info()&types.IsUntyped) == 0 && u.Kind() != types.Uintptr
	case *types.Array:
		return u.Len() >= 0 && isAsmLookupTableValueTypeSeen(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if !isAsmLookupTableValueTypeSeen(u.Field(i).Type(), seen) {
				return false
			}
		}
		return true
	default:
		// Slices, pointers, maps, channels, funcs, interfaces, and type parameters are rejected.
		return false
	}
}

func (b *tier2Base) classifyAsmExternalGlobal(ref asmverify.ExternalSBRef) ([]*types.Var, bool) {
	if b == nil || b.h == nil || !b.h.SelectionAudited() || b.prog == nil {
		return nil, false
	}
	if ref.PkgPath == "internal/cpu" && ref.Name == "HWCap" {
		isNonStd := false
		for _, idx := range b.idxByTypes {
			if idx != nil && idx.path == "internal/cpu" && !idx.std {
				isNonStd = true
				break
			}
		}
		if !isNonStd {
			return classifyAsmExternalGlobalInProg(true, b.prog, ref)
		}
	}
	b.ensureBinaryUnsafeEvaluated()
	if len(b.objsByLinkTarget[ref.PkgPath+"."+ref.Name]) > 0 || b.pkgUnsafeHazard[ref.PkgPath] {
		return nil, false
	}
	hasNonStdIdx := false
	for _, idx := range b.idxByTypes {
		if idx == nil || idx.path != ref.PkgPath {
			continue
		}
		if idx.std {
			return nil, false
		}
		hasNonStdIdx = true
		if !b.pkgFreeOfUnverifiedNativeWriteHazard(idx) || idx.linknameByName[ref.Name] != "" {
			return nil, false
		}
		if idx.ssa != nil {
			if g := idx.ssa.Var(ref.Name); g != nil && b.flagBacked[g] {
				return nil, false
			}
		}
		if idx.pkg != nil && idx.pkg.Types != nil && idx.pkg.Types.Scope() != nil {
			if obj := idx.pkg.Types.Scope().Lookup(ref.Name); obj != nil && idx.linknames[obj] != "" {
				return nil, false
			}
		}
	}
	if !hasNonStdIdx {
		return nil, false
	}
	return classifyAsmExternalGlobalInProg(true, b.prog, ref)
}

func classifyAsmExternalGlobalInProg(audited bool, p *program, ref asmverify.ExternalSBRef) ([]*types.Var, bool) {
	if !audited || p == nil || p.Prog == nil || ref.PkgPath == "" || ref.Name == "" {
		return nil, false
	}
	if p.Summaries != nil {
		if memo, ok := p.Summaries[asmExternalGlobalsSummaryKey].(map[asmverify.ExternalSBRef]asmExternalGlobalVerdict); ok {
			if cached, found := memo[ref]; found {
				return cached.vars, cached.ok
			}
		}
	}
	save := func(vars []*types.Var, ok bool) ([]*types.Var, bool) {
		if p.Summaries == nil {
			p.Summaries = make(map[string]any, 4)
		}
		memo, _ := p.Summaries[asmExternalGlobalsSummaryKey].(map[asmverify.ExternalSBRef]asmExternalGlobalVerdict)
		if memo == nil {
			memo = make(map[asmverify.ExternalSBRef]asmExternalGlobalVerdict, 4)
			p.Summaries[asmExternalGlobalsSummaryKey] = memo
		}
		memo[ref] = asmExternalGlobalVerdict{vars: vars, ok: ok}
		return vars, ok
	}

	haz := nonSSAGlobalHazardsSummary(audited, p)
	if haz == nil || haz.hasMalformedLinkname {
		return save(nil, false)
	}

	loadedByTypes := make(map[*types.Package]*packages.Package, len(haz.allPkgs))
	for _, lp := range haz.allPkgs {
		if lp != nil && lp.Types != nil {
			loadedByTypes[lp.Types] = lp
		}
	}
	var defaultSizes types.Sizes
	if p.GOARCH != "" {
		defaultSizes = types.SizesFor("gc", p.GOARCH)
	}

	if ref.PkgPath == "internal/cpu" && ref.Name == "HWCap" && len(haz.allPkgsByPath["internal/cpu"]) == 0 {
		wantKind, okTarget := auditset.AuditedReadOnlyVarLinknameTarget("internal/cpu.HWCap")
		if !okTarget {
			return save(nil, false)
		}
		for _, lk := range haz.linknamesByTarget["internal/cpu.HWCap"] {
			if haz.blockedPkgs[lk.pkgPath] {
				return save(nil, false)
			}
			variants := haz.allPkgsByPath[lk.pkgPath]
			if len(variants) == 0 {
				return save(nil, false)
			}
			for _, pkg := range variants {
				if pkg == nil || pkg.Types == nil || pkg.Types.Scope() == nil {
					return save(nil, false)
				}
				if isStdImportPath(pkg.PkgPath) && pkg.Module == nil {
					continue
				}
				pkgSizes := defaultSizes
				if pkgSizes == nil {
					pkgSizes = pkg.TypesSizes
				}
				if refconfine.PackageHasUnconfinedUnsafeMemoryHazard(pkg, pkgSizes, loadedByTypes) {
					return save(nil, false)
				}
				v, okV := pkg.Types.Scope().Lookup(lk.name).(*types.Var)
				if !okV || v.IsField() {
					return save(nil, false)
				}
				basic, okB := v.Type().Underlying().(*types.Basic)
				if !okB || basic.Kind() != wantKind || !astPackageVarReadOnly(pkg, v, false) {
					return save(nil, false)
				}
				ssaMatched := false
				for _, sp := range p.Prog.AllPackages() {
					if sp != nil && sp.Pkg == pkg.Types {
						if g := sp.Var(v.Name()); g != nil && ssaGlobalStrictlyReadOnly(p, g) {
							ssaMatched = true
						}
					}
				}
				if !ssaMatched {
					return save(nil, false)
				}
				if v.Exported() {
					for _, other := range haz.allPkgs {
						if other != nil && other != pkg && !astPackageVarReadOnly(other, v, false) {
							return save(nil, false)
						}
					}
				}
			}
		}
		return save(nil, true)
	}

	variants := haz.allPkgsByPath[ref.PkgPath]
	if len(variants) == 0 || haz.blockedPkgs[ref.PkgPath] || haz.linknamedVars[pkgVarKey{pkgPath: ref.PkgPath, name: ref.Name}] {
		return save(nil, false)
	}

	// Collect SSA packages and their synchronous init helper sets for ref.PkgPath.
	var ssaTargets []*ssa.Package
	for _, sp := range p.Prog.AllPackages() {
		if sp != nil && sp.Pkg != nil && sp.Pkg.Path() == ref.PkgPath {
			ssaTargets = append(ssaTargets, sp)
		}
	}
	if len(ssaTargets) == 0 {
		return save(nil, false)
	}

	syncInitFuncs := map[*ssa.Function]bool{}
	syncInitHelperNames := map[string]bool{}
	allFns := progOrderedFunctions(p)
	for _, sp := range ssaTargets {
		helpers := computePackageSyncInitSet(sp, allFns)
		for fn := range helpers {
			syncInitFuncs[fn] = true
			if fn.Name() != "init" && !strings.HasPrefix(fn.Name(), "init#") {
				syncInitHelperNames[fn.Name()] = true
			}
		}
	}

	syncInitHelperNames = filterASTStrictlyInitOnlyHelpers(variants, syncInitHelperNames)
	for fn := range syncInitFuncs {
		if fn.Name() != "init" && !strings.HasPrefix(fn.Name(), "init#") && !syncInitHelperNames[fn.Name()] {
			delete(syncInitFuncs, fn)
		}
	}

	var vars []*types.Var
	for _, pkg := range variants {
		if pkg == nil || pkg.Types == nil || pkg.Types.Scope() == nil || pkg.TypesInfo == nil {
			return save(nil, false)
		}
		pkgSizes := defaultSizes
		if pkgSizes == nil {
			pkgSizes = pkg.TypesSizes
		}
		if refconfine.PackageHasUnconfinedUnsafeMemoryHazard(pkg, pkgSizes, loadedByTypes) {
			return save(nil, false)
		}
		v, okV := pkg.Types.Scope().Lookup(ref.Name).(*types.Var)
		if !okV || v.IsField() || v.Parent() != pkg.Types.Scope() || !isAsmLookupTableValueType(v.Type()) {
			return save(nil, false)
		}
		if !verifyPackageVarASTConfinement(pkg, v, true, syncInitHelperNames) {
			return save(nil, false)
		}
		if v.Exported() {
			for _, other := range haz.allPkgs {
				if other != nil && other.PkgPath != ref.PkgPath {
					if !verifyPackageVarASTConfinement(other, v, false, nil) {
						return save(nil, false)
					}
				}
			}
		}
		vars = append(vars, v)
	}

	for _, sp := range ssaTargets {
		g := sp.Var(ref.Name)
		if g == nil || !verifySSAGlobalInitSettledAndUnescaped(allFns, g, syncInitFuncs) {
			return save(nil, false)
		}
	}

	return save(vars, true)
}

func computePackageSyncInitSet(sp *ssa.Package, allFns []*ssa.Function) map[*ssa.Function]bool {
	out := map[*ssa.Function]bool{}
	if sp == nil {
		return out
	}
	initFn := sp.Func("init")
	if initFn == nil {
		return out
	}
	// Candidate helpers: unexported top-level functions in sp whose sole SSA
	// references across the entire program are direct static Call/Defer instructions
	// from functions inside out (never GoStmt, never address-taken/value-escaped).
	callersOf := map[*ssa.Function][]*ssa.Function{}
	disqualified := map[*ssa.Function]bool{}
	var ops [16]*ssa.Value
	for _, fn := range allFns {
		if fn == nil {
			continue
		}
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				if _, isDbg := instr.(*ssa.DebugRef); isDbg {
					continue
				}
				if _, isGo := instr.(*ssa.Go); isGo {
					for _, op := range instr.Operands(ops[:0]) {
						if op != nil && *op != nil {
							if c, ok := (*op).(*ssa.Function); ok {
								disqualified[c] = true
							}
						}
					}
					continue
				}
				site, isCall := instr.(ssa.CallInstruction)
				for _, op := range instr.Operands(ops[:0]) {
					if op == nil || *op == nil {
						continue
					}
					c, ok := (*op).(*ssa.Function)
					if !ok || c.Pkg != sp {
						continue
					}
					if isCall && site.Common() != nil && !site.Common().IsInvoke() && site.Common().Value == c {
						isArg := false
						for _, a := range site.Common().Args {
							if a == c {
								isArg = true
								break
							}
						}
						if !isArg {
							callersOf[c] = append(callersOf[c], fn)
							continue
						}
					}
					disqualified[c] = true
				}
			}
		}
	}

	out[initFn] = true
	queue := []*ssa.Function{initFn}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, blk := range cur.Blocks {
			for _, instr := range blk.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				if _, isGo := instr.(*ssa.Go); isGo {
					continue
				}
				callee := site.Common().StaticCallee()
				if callee == nil || callee.Pkg != sp || out[callee] || disqualified[callee] ||
					ast.IsExported(callee.Name()) || len(callee.Blocks) == 0 ||
					callee.TypeParams().Len() > 0 || callee.TypeArgs() != nil {
					continue
				}
				out[callee] = true
				queue = append(queue, callee)
			}
		}
	}
	// Evict any helper that has a caller outside out.
	for {
		evicted := false
		for fn := range out {
			if fn == initFn {
				continue
			}
			for _, caller := range callersOf[fn] {
				if !out[caller] {
					delete(out, fn)
					evicted = true
					break
				}
			}
		}
		if !evicted {
			break
		}
	}
	return out
}

func verifySSAGlobalInitSettledAndUnescaped(allFns []*ssa.Function, g *ssa.Global, syncInitFuncs map[*ssa.Function]bool) bool {
	var ops [16]*ssa.Value
	var checkDerivedPtr func(v ssa.Value, allowWrite bool, depth int) bool
	checkDerivedPtr = func(v ssa.Value, allowWrite bool, depth int) bool {
		if v == nil || depth > 16 {
			return false
		}
		if v.Referrers() == nil {
			return true
		}
		for _, ref := range *v.Referrers() {
			switch r := ref.(type) {
			case *ssa.DebugRef:
				continue
			case *ssa.UnOp:
				if r.Op != token.MUL || r.X != v {
					return false
				}
			case *ssa.Store:
				if !allowWrite || r.Addr != v || r.Val == v || r.Val == g {
					return false
				}
			case *ssa.IndexAddr:
				if r.X != v || !checkDerivedPtr(r, allowWrite, depth+1) {
					return false
				}
			case *ssa.FieldAddr:
				if r.X != v || !checkDerivedPtr(r, allowWrite, depth+1) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}

	for _, fn := range allFns {
		if fn == nil {
			continue
		}
		inSyncInit := syncInitFuncs[fn]
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				if _, isDbg := instr.(*ssa.DebugRef); isDbg {
					continue
				}
				mentionsG := false
				for _, op := range instr.Operands(ops[:0]) {
					if op != nil && *op == g {
						mentionsG = true
						break
					}
				}
				if !mentionsG {
					continue
				}
				switch x := instr.(type) {
				case *ssa.UnOp:
					if x.Op != token.MUL || x.X != g {
						return false
					}
				case *ssa.Store:
					if !inSyncInit || x.Addr != g || x.Val == g {
						return false
					}
				case *ssa.IndexAddr:
					if x.X != g || !checkDerivedPtr(x, inSyncInit, 1) {
						return false
					}
				case *ssa.FieldAddr:
					if x.X != g || !checkDerivedPtr(x, inSyncInit, 1) {
						return false
					}
				default:
					return false
				}
			}
		}
	}
	return true
}

func filterASTStrictlyInitOnlyHelpers(variants []*packages.Package, cand map[string]bool) map[string]bool {
	if len(cand) == 0 {
		return nil
	}
	active := make(map[string]bool, len(cand))
	for k := range cand {
		active[k] = true
	}
	for {
		evicted := false
		for _, pkg := range variants {
			if pkg == nil || pkg.TypesInfo == nil || pkg.Types == nil {
				return nil
			}
			for _, file := range pkg.Syntax {
				if file == nil {
					continue
				}
				for _, decl := range file.Decls {
					inInitOrHelper := false
					if fd, isFD := decl.(*ast.FuncDecl); isFD && fd.Recv == nil && fd.Name != nil {
						if fd.Name.Name == "init" || active[fd.Name.Name] {
							inInitOrHelper = true
						}
					}
					if inInitOrHelper {
						continue
					}
					ast.Inspect(decl, func(n ast.Node) bool {
						id, okID := n.(*ast.Ident)
						if !okID {
							return true
						}
						if fnObj, okFn := pkg.TypesInfo.Uses[id].(*types.Func); okFn && fnObj.Pkg() == pkg.Types && active[fnObj.Name()] {
							delete(active, fnObj.Name())
							evicted = true
						}
						return true
					})
				}
			}
		}
		if !evicted {
			break
		}
	}
	return active
}

func verifyPackageVarASTConfinement(pkg *packages.Package, v *types.Var, allowInitWrites bool, allowedInitHelpers map[string]bool) bool {
	if pkg == nil || v == nil || pkg.TypesInfo == nil {
		return false
	}
	var placeReachesVar func(e ast.Expr) bool
	placeReachesVar = func(e ast.Expr) bool {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			return pkg.TypesInfo.Uses[x] == v || pkg.TypesInfo.Defs[x] == v
		case *ast.SelectorExpr:
			if x.Sel != nil && pkg.TypesInfo.Uses[x.Sel] == v {
				return true
			}
			return placeReachesVar(x.X)
		case *ast.IndexExpr:
			return placeReachesVar(x.X)
		case *ast.StarExpr:
			return placeReachesVar(x.X)
		}
		return false
	}

	ok := true
	for _, file := range pkg.Syntax {
		if file == nil || !ok {
			continue
		}
		for _, decl := range file.Decls {
			if !ok {
				break
			}
			inAllowedInitFunc := false
			if fd, isFD := decl.(*ast.FuncDecl); isFD && fd.Recv == nil && fd.Name != nil && allowInitWrites {
				if fd.Name.Name == "init" || allowedInitHelpers[fd.Name.Name] {
					inAllowedInitFunc = true
				}
			}
			var inspectSubtree func(n ast.Node, inAsyncOrLit bool)
			inspectSubtree = func(n ast.Node, inAsyncOrLit bool) {
				if !ok || n == nil {
					return
				}
				switch x := n.(type) {
				case *ast.GoStmt:
					ast.Inspect(x, func(ch ast.Node) bool {
						if ch == x {
							return true
						}
						inspectSubtree(ch, true)
						return false
					})
					return
				case *ast.FuncLit:
					ast.Inspect(x, func(ch ast.Node) bool {
						if ch == x {
							return true
						}
						inspectSubtree(ch, true)
						return false
					})
					return
				case *ast.ValueSpec:
					for i, id := range x.Names {
						if pkg.TypesInfo.Defs[id] == v {
							if !allowInitWrites && (len(x.Values) > i || len(x.Values) > 0) {
								ok = false
								return
							}
						}
					}
				case *ast.AssignStmt:
					for _, lhs := range x.Lhs {
						if placeReachesVar(lhs) {
							if x.Tok == token.DEFINE || !inAllowedInitFunc || inAsyncOrLit {
								ok = false
								return
							}
						}
					}
				case *ast.IncDecStmt:
					if placeReachesVar(x.X) {
						if !inAllowedInitFunc || inAsyncOrLit {
							ok = false
							return
						}
					}
				case *ast.RangeStmt:
					if (x.Key != nil && placeReachesVar(x.Key)) || (x.Value != nil && placeReachesVar(x.Value)) {
						if x.Tok == token.DEFINE || !inAllowedInitFunc || inAsyncOrLit {
							ok = false
							return
						}
					}
				case *ast.UnaryExpr:
					if x.Op == token.AND && placeReachesVar(x.X) {
						ok = false
						return
					}
				case *ast.SelectorExpr:
					if selInfo := pkg.TypesInfo.Selections[x]; selInfo != nil && selInfo.Kind() == types.MethodVal &&
						refconfine.SelectionHasPointerReceiver(selInfo) && placeReachesVar(x.X) {
						ok = false
						return
					}
				case *ast.SliceExpr:
					if placeReachesVar(x.X) {
						ok = false
						return
					}
				}
				ast.Inspect(n, func(ch ast.Node) bool {
					if ch == n {
						return true
					}
					inspectSubtree(ch, inAsyncOrLit)
					return false
				})
			}
			inspectSubtree(decl, false)
		}
	}
	return ok
}
