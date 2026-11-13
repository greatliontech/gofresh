package dynstate

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

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
	if ok, r := verifyMemoFunctionBody(p, idx, memoFD, memoFnObj, paramVar, mapVar, protectedStructs); !ok {
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
			if refconfine.CallMutatesNamedStructContainer(p, x, protected) {
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
