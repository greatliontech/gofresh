package capsule

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

type intraCandCall struct {
	callee             *types.Func
	hasLocalScalarRecv bool
}

// DeriveNonMutatingMethods mechanically identifies exported methods in p.Types
// that perform zero non-local mutations and call only pure or transitively
// non-mutating intra-package helpers.
func DeriveNonMutatingMethods(audited bool, p *packages.Package, idx *refconfine.PkgIndex) []syntaxutil.FuncKey {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return nil
	}
	isScalarPtrRecv := func(fn *types.Func) *types.Var {
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() == nil {
			return nil
		}
		ptr, isP := types.Unalias(sig.Recv().Type()).(*types.Pointer)
		if !isP || refconfine.TypeContainsRefOrPointer(ptr.Elem()) {
			return nil
		}
		return sig.Recv()
	}

	cands := map[*types.Func]*ast.FuncDecl{}
	scalarPtrHelpers := map[*types.Func]bool{}
	intraCallsByCand := map[*types.Func][]intraCandCall{}

	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || fn.Pkg() != p.Types {
			continue
		}
		scalarRecv := isScalarPtrRecv(fn)
		localVars := map[*types.Var]bool{}
		localScalarVars := map[*types.Var]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if id, isID := n.(*ast.Ident); isID {
				if dv, ok := p.TypesInfo.Defs[id].(*types.Var); ok && dv != nil && !dv.IsField() && dv.Parent() != p.Types.Scope() {
					localVars[dv] = true
					if !refconfine.TypeContainsRefOrPointer(dv.Type()) {
						localScalarVars[dv] = true
					}
				}
			}
			return true
		})
		if fd.Type != nil && fd.Type.Results != nil {
			for _, field := range fd.Type.Results.List {
				for _, nm := range field.Names {
					if dv, ok := p.TypesInfo.Defs[nm].(*types.Var); ok && dv != nil {
						localVars[dv] = true
					}
				}
			}
		}
		usedScalarRecvWrite := false
		isPureLocalLHS := func(expr ast.Expr) bool {
			expr = ast.Unparen(expr)
			if id, isID := expr.(*ast.Ident); isID {
				if id.Name == "_" {
					return true
				}
				if dv, ok := p.TypesInfo.Defs[id].(*types.Var); ok && dv != nil {
					return localVars[dv]
				}
				if uv, ok := p.TypesInfo.Uses[id].(*types.Var); ok && uv != nil {
					return localVars[uv]
				}
				return false
			}
			if scalarRecv != nil {
				if star, isStar := expr.(*ast.StarExpr); isStar {
					if rid, isID := ast.Unparen(star.X).(*ast.Ident); isID && p.TypesInfo.Uses[rid] == scalarRecv {
						usedScalarRecvWrite = true
						return true
					}
				}
			}
			return false
		}
		okLocal := true
		var intraCalls []intraCandCall
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !okLocal || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.GoStmt, *ast.SendStmt:
				okLocal = false
				return false
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if !isPureLocalLHS(lhs) {
						okLocal = false
						return false
					}
				}
			case *ast.IncDecStmt:
				if !isPureLocalLHS(x.X) {
					okLocal = false
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && !isPureLocalLHS(x.Key)) || (x.Value != nil && !isPureLocalLHS(x.Value)) {
						okLocal = false
						return false
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if id, isID := ast.Unparen(x.X).(*ast.Ident); isID {
						uv, _ := p.TypesInfo.Uses[id].(*types.Var)
						if uv != nil && localVars[uv] && !refconfine.TypeContainsRefOrPointer(uv.Type()) {
							return true
						}
					}
					okLocal = false
					return false
				}
			case *ast.CallExpr:
				if tv, okTV := p.TypesInfo.Types[x.Fun]; okTV && tv.IsType() {
					return true
				}
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "len", "cap", "min", "max", "panic", "recover", "new", "make":
							return true
						}
						okLocal = false
						return false
					}
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun)
				if callee == nil {
					okLocal = false
					return false
				}
				callee = callee.Origin()
				if sig, okSig := callee.Type().(*types.Signature); okSig && sig.Recv() != nil && types.IsInterface(sig.Recv().Type()) {
					rt := types.Unalias(sig.Recv().Type())
					named, isNamed := rt.(*types.Named)
					if !isNamed || named.Obj() == nil || named.Obj().Pkg() == nil {
						okLocal = false
						return false
					}
					ifacePkg, ifaceName := named.Obj().Pkg().Path(), named.Obj().Name()
					immutableIface := (ifacePkg == "reflect" && auditset.ReflectImmutable(ifaceName)) ||
						(ifacePkg == "go/constant" && auditset.ConstantImmutable(ifaceName))
					if !immutableIface {
						okLocal = false
						return false
					}
					for _, arg := range x.Args {
						if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(arg)) {
							okLocal = false
							return false
						}
					}
					return true
				}
				if auditset.NonMutatingStdCallee(callee) {
					return true
				}
				if callee.Pkg() == p.Types {
					hasScalarRecv := false
					if sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr); isSel {
						if lv := syntaxutil.LookupIdentVar(p.TypesInfo, sel.X); lv != nil && localScalarVars[lv] {
							hasScalarRecv = true
						}
					}
					intraCalls = append(intraCalls, intraCandCall{
						callee:             callee,
						hasLocalScalarRecv: hasScalarRecv,
					})
					return true
				}
				okLocal = false
				return false
			}
			return true
		})
		if okLocal {
			cands[fn] = fd
			if len(intraCalls) > 0 {
				intraCallsByCand[fn] = intraCalls
			}
			if usedScalarRecvWrite {
				scalarPtrHelpers[fn] = true
			}
		}
	}

	for {
		changed := false
		for fn := range cands {
			callsOK := true
			for _, ic := range intraCallsByCand[fn] {
				if cands[ic.callee] == nil || (scalarPtrHelpers[ic.callee] && !ic.hasLocalScalarRecv) {
					callsOK = false
					break
				}
			}
			if !callsOK {
				delete(cands, fn)
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	pkgPath := p.Types.Path()
	var out []syntaxutil.FuncKey
	for fn, fd := range cands {
		if scalarPtrHelpers[fn] || !fn.Exported() || fd.Recv == nil {
			continue
		}
		recvName := syntaxutil.RecvTypeName(fd)
		if recvName == "" {
			continue
		}
		fk := syntaxutil.FuncKey{Pkg: pkgPath, Name: recvName + "." + fn.Name()}
		if fk.Valid() {
			out = append(out, fk)
		}
	}
	slices.SortFunc(out, syntaxutil.FuncKey.Compare)
	return out
}

func containsSyncOrAtomicCarrier(root types.Type) bool {
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
		if named, isN := t.(*types.Named); isN && named.Obj() != nil && named.Obj().Pkg() != nil {
			pkgPath := named.Obj().Pkg().Path()
			name := named.Obj().Name()
			if (pkgPath == "sync" && (name == "Map" || name == "Pool")) ||
				(pkgPath == "sync/atomic" && (name == "Value" || name == "Pointer" || name == "Uintptr")) {
				hit = true
				return
			}
		}
		switch u := t.Underlying().(type) {
		case *types.Chan:
			hit = true
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
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

func isUnsafePtrOrUintptrScalar(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && (b.Kind() == types.UnsafePointer || b.Kind() == types.Uintptr)
}

func sigAcceptsCarrier(t types.Type) bool {
	sig, ok := types.Unalias(t).Underlying().(*types.Signature)
	if !ok {
		return false
	}
	if sig.Recv() != nil {
		rt := sig.Recv().Type()
		if refconfine.TypeContainsRefOrPointer(rt) || syntaxutil.ContainsUintptr(rt) {
			return true
		}
	}
	for i := 0; i < sig.Params().Len(); i++ {
		pt := sig.Params().At(i).Type()
		if refconfine.TypeContainsRefOrPointer(pt) || syntaxutil.ContainsUintptr(pt) {
			return true
		}
	}
	return false
}

func structFreeOfCarrierHandles(t types.Type) bool {
	seen := map[types.Type]bool{}
	ok := true
	var walk func(cur types.Type)
	walk = func(cur types.Type) {
		if cur == nil || !ok {
			return
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return
		}
		seen[cur] = true
		switch u := cur.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer || u.Kind() == types.Uintptr {
				ok = false
			}
		case *types.Interface, *types.Signature, *types.Chan, *types.TypeParam:
			ok = false
		case *types.Pointer:
			ok = false
		case *types.Map:
			ok = false
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(t)
	return ok
}

// DeriveNoPostInitCarrierWrites mechanically checks whether package p cannot
// write or retain any pointer, slice, map, channel, function, interface, or
// uintptr carrier in package-scope state after init, returning any non-stdlib
// cross-package callees to which p forwards carrier-bearing arguments outside init.
func DeriveNoPostInitCarrierWrites(
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	initOnly map[string]bool,
	directVarWrites []string,
) (bool, []string) {
	if !audited || p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return false, nil
	}
	if len(p.OtherFiles) > 0 || (len(p.GoFiles) > 0 && len(p.CompiledGoFiles) > len(p.GoFiles)) || len(directVarWrites) > 0 {
		return false, nil
	}
	if idx == nil {
		idx = refconfine.BuildPkgIndex(p)
	}
	if initOnly == nil {
		initOnly = idx.InitOnly
	}
	initConeFDs := map[*ast.FuncDecl]bool{}
	for _, file := range p.Syntax {
		for _, imp := range file.Imports {
			if imp != nil && imp.Path != nil {
				if uq, err := strconv.Unquote(imp.Path.Value); err == nil && uq == "C" {
					return false, nil
				}
			}
		}
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, "go:linkname") {
					return false, nil
				}
			}
		}
		for _, decl := range file.Decls {
			fd, isFD := decl.(*ast.FuncDecl)
			if !isFD {
				continue
			}
			if fd.Body == nil {
				return false, nil
			}
			if fd.Recv == nil && (fd.Name.Name == "init" || initOnly[fd.Name.Name]) {
				initConeFDs[fd] = true
			}
		}
	}
	isPostInitNode := func(n ast.Node) bool {
		if idx.InGoStmt[n] {
			return true
		}
		if idx.InFuncLit[n] {
			cur := idx.ParentMap[n]
			for cur != nil {
				if lit, isLit := cur.(*ast.FuncLit); isLit {
					call, isCall := idx.ParentUnparen(lit).(*ast.CallExpr)
					if !isCall || ast.Unparen(call.Fun) != lit {
						return true
					}
				}
				if fd, isFD := cur.(*ast.FuncDecl); isFD {
					return !initConeFDs[fd]
				}
				cur = idx.ParentMap[cur]
			}
			return false
		}
		fd := idx.SyncEnclFuncDecl(n)
		if fd == nil {
			return false
		}
		return !initConeFDs[fd]
	}

	mutableRefPkgUses := map[*ast.Ident]bool{}
	validatedPoolVars := map[*types.Var]bool{}
	scope := p.Types.Scope()
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok || v == nil {
			continue
		}
		vt := v.Type()
		if !refconfine.TypeContainsRefOrPointer(vt) && !syntaxutil.ContainsUintptr(vt) {
			continue
		}
		if !v.Exported() && syntaxutil.IsNamedInPkg(vt, "sync", "Pool") {
			for _, uid := range idx.UsesOf[v] {
				if !isPostInitNode(uid) {
					continue
				}
				sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
				if !isSel || ast.Unparen(sel.X) != uid {
					return false, nil
				}
				call, isCall := idx.ParentUnparen(sel).(*ast.CallExpr)
				if !isCall || ast.Unparen(call.Fun) != sel || call.Ellipsis.IsValid() {
					return false, nil
				}
				switch sel.Sel.Name {
				case "Get":
					if len(call.Args) != 0 {
						return false, nil
					}
				case "Put":
					if len(call.Args) != 1 {
						return false, nil
					}
					ptr, isPtr := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(call.Args[0])).(*types.Pointer)
					if !isPtr || !structFreeOfCarrierHandles(ptr.Elem()) {
						return false, nil
					}
				default:
					return false, nil
				}
			}
			validatedPoolVars[v] = true
			continue
		}
		if containsSyncOrAtomicCarrier(vt) {
			return false, nil
		}
		if v.Exported() && (refconfine.TypeCarriesMutableRef(vt) || syntaxutil.ContainsUintptr(vt)) {
			return false, nil
		}
		rawPtrScalar := isUnsafePtrOrUintptrScalar(vt)
		carriesMutRef := !rawPtrScalar && refconfine.TypeCarriesMutableRef(vt)
		for _, uid := range idx.UsesOf[v] {
			if !isPostInitNode(uid) {
				continue
			}
			if refconfine.IdentOrExprIsWritten(idx, uid) || freshstruct.IdentReachesMutatedOrAddrPrefix(p, idx, uid) {
				return false, nil
			}
			if rawPtrScalar {
				par := idx.ParentUnparen(uid)
				switch pn := par.(type) {
				case *ast.CaseClause:
				case *ast.BinaryExpr:
					if pn.Op != token.EQL && pn.Op != token.NEQ {
						return false, nil
					}
				case *ast.KeyValueExpr:
					if ast.Unparen(pn.Value) != uid {
						return false, nil
					}
				default:
					return false, nil
				}
				continue
			}
			if call, isCall := idx.ParentUnparen(uid).(*ast.CallExpr); isCall && len(call.Args) > 0 && ast.Unparen(call.Args[0]) == uid {
				if cid, isID := ast.Unparen(call.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							return false, nil
						}
					}
				}
			}
			if carriesMutRef {
				mutableRefPkgUses[uid] = true
			}
		}
	}
	if len(mutableRefPkgUses) > 0 {
		if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
			Index: idx,
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				id, isID := expr.(*ast.Ident)
				if !isID || !mutableRefPkgUses[id] {
					return false, false
				}
				t := p.TypesInfo.TypeOf(id)
				return refconfine.IsDirectMutableRef(t), refconfine.TypeCarriesMutableRef(t)
			},
		}) {
			return false, nil
		}
	}

	depSet := map[string]bool{}
	directCalleeIdents := map[*ast.Ident]bool{}
	recordDepCallee := func(orig *types.Func) bool {
		depPkg := orig.Pkg().Path()
		if depPkg == "C" {
			return false
		}
		if syntaxutil.IsStandardLibraryPkgPath(depPkg) {
			return auditset.NonRetainingStdCallee(orig)
		}
		depSet[depPkg] = true
		return true
	}
	okCalls := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !okCalls || n == nil {
				return false
			}
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			curFun := ast.Unparen(call.Fun)
			switch e := curFun.(type) {
			case *ast.IndexExpr:
				curFun = ast.Unparen(e.X)
			case *ast.IndexListExpr:
				curFun = ast.Unparen(e.X)
			}
			switch fn := curFun.(type) {
			case *ast.Ident:
				directCalleeIdents[fn] = true
			case *ast.SelectorExpr:
				directCalleeIdents[fn.Sel] = true
			}
			if !isPostInitNode(call) {
				return true
			}
			if p.TypesInfo.Types[call.Fun].IsType() {
				return true
			}
			if cid, isID := ast.Unparen(call.Fun).(*ast.Ident); isID {
				if _, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
					return true
				}
			} else if sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr); isSel {
				if _, isB := p.TypesInfo.Uses[sel.Sel].(*types.Builtin); isB {
					return true
				}
				if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && types.IsInterface(selInfo.Recv()) {
					return true
				}
			}
			callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
			if callee == nil {
				return true
			}
			orig := callee.Origin()
			if orig.Pkg() == nil || orig.Pkg() == p.Types {
				return true
			}
			if sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr); isSel {
				if rid, isID := ast.Unparen(sel.X).(*ast.Ident); isID {
					if uv, ok := p.TypesInfo.Uses[rid].(*types.Var); ok && validatedPoolVars[uv] {
						return true
					}
				}
			}
			passesCarrier := false
			if sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr); isSel {
				if selInfo := p.TypesInfo.Selections[sel]; selInfo != nil && selInfo.Kind() == types.MethodVal {
					rt := p.TypesInfo.TypeOf(sel.X)
					if refconfine.TypeContainsRefOrPointer(rt) || syntaxutil.ContainsUintptr(rt) {
						passesCarrier = true
					}
				}
			}
			if !passesCarrier {
				for _, arg := range call.Args {
					at := p.TypesInfo.TypeOf(arg)
					if refconfine.TypeContainsRefOrPointer(at) || syntaxutil.ContainsUintptr(at) {
						passesCarrier = true
						break
					}
				}
			}
			if !passesCarrier {
				return true
			}
			if !recordDepCallee(orig) {
				okCalls = false
				return false
			}
			return true
		})
		if !okCalls {
			return false, nil
		}
	}
	for id, obj := range p.TypesInfo.Uses {
		if directCalleeIdents[id] {
			continue
		}
		fn, isFn := obj.(*types.Func)
		if !isFn {
			continue
		}
		orig := fn.Origin()
		if orig.Pkg() == nil || orig.Pkg() == p.Types || !sigAcceptsCarrier(orig.Type()) {
			continue
		}
		if !recordDepCallee(orig) {
			return false, nil
		}
	}

	if len(depSet) == 0 {
		return true, nil
	}
	deps := make([]string, 0, len(depSet))
	for dep := range depSet {
		deps = append(deps, dep)
	}
	sort.Strings(deps)
	return true, deps
}

func addExemptStructInFunc(m map[*ast.FuncDecl]map[*types.Named]bool, fd *ast.FuncDecl, st *types.Named) {
	if fd == nil || st == nil {
		return
	}
	sub := m[fd]
	if sub == nil {
		sub = map[*types.Named]bool{}
		m[fd] = sub
	}
	sub[st] = true
}

// CollectDirectCrossPkgVarWrites scans p.Syntax for direct writes, container-mutating
// builtins, or escaping address-takes targeting imported dynamic package-scope variables.
func CollectDirectCrossPkgVarWrites(audited bool, p *packages.Package, idx *refconfine.PkgIndex) []string {
	if p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil
	}
	if idx == nil {
		idx = refconfine.BuildPkgIndex(p)
	}
	lookupImportedVar := func(expr ast.Expr) *types.Var {
		switch e := ast.Unparen(expr).(type) {
		case *ast.SelectorExpr:
			if p.TypesInfo.Selections[e] != nil {
				return nil
			}
			if v, ok := p.TypesInfo.Uses[e.Sel].(*types.Var); ok && v != nil && !v.IsField() &&
				v.Pkg() != nil && v.Pkg() != p.Types && v.Parent() == v.Pkg().Scope() {
				return v
			}
		case *ast.Ident:
			if v, ok := p.TypesInfo.Uses[e].(*types.Var); ok && v != nil && !v.IsField() &&
				v.Pkg() != nil && v.Pkg() != p.Types && v.Parent() == v.Pkg().Scope() {
				return v
			}
		}
		return nil
	}
	rootImportedVar := func(expr ast.Expr) (*types.Var, bool) {
		cur := ast.Unparen(expr)
		direct := true
		for {
			if v := lookupImportedVar(cur); v != nil {
				return v, direct
			}
			switch e := cur.(type) {
			case *ast.SelectorExpr:
				if p.TypesInfo.Selections[e] == nil {
					return nil, false
				}
				cur = ast.Unparen(e.X)
				direct = false
			case *ast.IndexExpr:
				cur = ast.Unparen(e.X)
				direct = false
			case *ast.SliceExpr:
				cur = ast.Unparen(e.X)
				direct = false
			case *ast.StarExpr:
				cur = ast.Unparen(e.X)
				direct = false
			default:
				return nil, false
			}
		}
	}

	seen := map[string]bool{}
	recordVar := func(v *types.Var) {
		if v != nil && refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			seen[syntaxutil.DynamicVarKey(v)] = true
		}
	}

	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if v, _ := rootImportedVar(lhs); v != nil {
						recordVar(v)
					}
				}
			case *ast.IncDecStmt:
				if v, _ := rootImportedVar(x.X); v != nil {
					recordVar(v)
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if x.Key != nil {
						if v, _ := rootImportedVar(x.Key); v != nil {
							recordVar(v)
						}
					}
					if x.Value != nil {
						if v, _ := rootImportedVar(x.Value); v != nil {
							recordVar(v)
						}
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND {
					if v, direct := rootImportedVar(x.X); v != nil {
						isByValueStruct := false
						if direct {
							if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr && syntaxutil.DerefNamedStruct(v.Type()) != nil {
								isByValueStruct = true
							}
						}
						if !isByValueStruct {
							recordVar(v)
						}
					}
				}
			case *ast.CallExpr:
				if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(x.Fun)); b != nil {
					switch b.Name() {
					case "delete", "clear", "copy", "append":
						if len(x.Args) > 0 {
							if v, _ := rootImportedVar(x.Args[0]); v != nil {
								recordVar(v)
							}
						}
					}
				}
			}
			return true
		})
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CollectNonMethodCrossPkgVarUses returns the sorted qualified variable keys of
// every cross-package dynamic-capable package variable referenced in p.Syntax
// in any position other than the direct receiver X of a non-promoted method
// call X.Method(...) or an exempted direct-methods-only alias initializer.
func CollectNonMethodCrossPkgVarUses(audited bool, p *packages.Package, idx *refconfine.PkgIndex, exemptUseIdents map[*ast.Ident]bool) []string {
	if p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return nil
	}
	if idx == nil {
		idx = refconfine.BuildPkgIndex(p)
	}
	seen := map[string]bool{}
	isDirectMethodCallRecv := func(varExpr ast.Expr) bool {
		mSel, ok := idx.ParentUnparen(varExpr).(*ast.SelectorExpr)
		if !ok || ast.Unparen(mSel.X) != varExpr {
			return false
		}
		selInfo := p.TypesInfo.Selections[mSel]
		if selInfo == nil || selInfo.Kind() != types.MethodVal || len(selInfo.Index()) != 1 {
			return false
		}
		call, ok := idx.ParentUnparen(mSel).(*ast.CallExpr)
		return ok && ast.Unparen(call.Fun) == mSel
	}
	for ident, obj := range p.TypesInfo.Uses {
		if exemptUseIdents[ident] {
			continue
		}
		v, ok := obj.(*types.Var)
		if !ok || v == nil || v.IsField() || v.Pkg() == nil || v.Pkg() == p.Types || v.Parent() != v.Pkg().Scope() {
			continue
		}
		if !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) {
			continue
		}
		var varExpr ast.Expr = ident
		if parSel, isSel := idx.ParentMap[ident].(*ast.SelectorExpr); isSel && parSel.Sel == ident && p.TypesInfo.Selections[parSel] == nil {
			varExpr = parSel
		}
		if !isDirectMethodCallRecv(varExpr) {
			seen[syntaxutil.DynamicVarKey(v)] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
