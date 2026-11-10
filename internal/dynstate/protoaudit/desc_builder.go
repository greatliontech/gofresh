package protoaudit

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func verifyProtoDescBuilderType(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
	exemptReadFields map[*types.Var]bool,
) (map[ast.Node]bool, map[*ast.FuncDecl]map[*types.Named]bool, []syntaxutil.TypeRef, bool) {
	if named.Obj() == nil || !named.Obj().Exported() || named.TypeParams().Len() > 0 {
		return nil, nil, nil, false
	}
	hasRawDesc := false
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Name() == "GoTypes" {
			return nil, nil, nil, false
		}
		if f.Name() == "RawDescriptor" && f.Exported() && syntaxutil.IsByteSliceType(f.Type()) {
			hasRawDesc = true
		}
	}
	if !hasRawDesc {
		return nil, nil, nil, false
	}

	var buildFn *types.Func
	psetBuilder := types.NewMethodSet(types.NewPointer(named))
	for i := 0; i < psetBuilder.Len(); i++ {
		m, okM := psetBuilder.At(i).Obj().(*types.Func)
		if !okM || m.Pkg() != p.Types {
			return nil, nil, nil, false
		}
		if !m.Exported() {
			continue
		}
		if m.Name() != "Build" || buildFn != nil {
			return nil, nil, nil, false
		}
		buildFn = m
	}
	if buildFn == nil {
		return nil, nil, nil, false
	}
	sig, ok := buildFn.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return nil, nil, nil, false
	}
	outType := types.Unalias(sig.Results().At(0).Type())
	outNamed, _ := outType.(*types.Named)
	outSt, ok := outType.Underlying().(*types.Struct)
	if !ok || !syntaxutil.StructHasExportedIfaceField(outSt, "File") {
		return nil, nil, nil, false
	}
	buildFD := idx.FuncDecls[buildFn]
	if buildFD == nil || buildFD.Body == nil {
		return nil, nil, nil, false
	}

	descFamily := map[*types.Named]bool{}
	for i := 0; i < outSt.NumFields(); i++ {
		f := outSt.Field(i)
		if f.Exported() {
			if _, elemNamed, okElem := syntaxutil.SliceElemNamedStruct(f.Type()); okElem && elemNamed.Obj() != nil && elemNamed.Obj().Pkg() == p.Types {
				descFamily[elemNamed] = true
			}
		}
	}
	if len(descFamily) == 0 {
		return nil, nil, nil, false
	}

	buildReach := map[*types.Func]bool{buildFn: true}
	bQueue := []*types.Func{buildFn}
	for len(bQueue) > 0 {
		cur := bQueue[0]
		bQueue = bQueue[1:]
		cfd := idx.FuncDecls[cur]
		if cfd == nil || cfd.Body == nil {
			return nil, nil, nil, false
		}
		ast.Inspect(cfd.Body, func(n ast.Node) bool {
			if call, isCall := n.(*ast.CallExpr); isCall {
				if callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun); callee != nil {
					callee = callee.Origin()
					if sigC, okSig := callee.Type().(*types.Signature); okSig && sigC.Recv() != nil && types.IsInterface(sigC.Recv().Type()) {
						return true
					}
					if callee.Pkg() == p.Types && !buildReach[callee] {
						buildReach[callee] = true
						bQueue = append(bQueue, callee)
					}
				}
			}
			return true
		})
	}

	fileRootStructs := map[*types.Named]bool{}
	outFileValid := true
	for fn := range buildReach {
		cfd := idx.FuncDecls[fn]
		ast.Inspect(cfd.Body, func(n ast.Node) bool {
			if !outFileValid || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.CompositeLit:
				if syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x)) == outNamed && outNamed != nil {
					for _, elt := range x.Elts {
						kv, isKV := elt.(*ast.KeyValueExpr)
						if !isKV {
							outFileValid = false
							return false
						}
						kid, isID := kv.Key.(*ast.Ident)
						if isID && kid.Name == "File" {
							fs := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(kv.Value))
							if fs == nil || fs.Obj() == nil || fs.Obj().Pkg() != p.Types {
								outFileValid = false
								return false
							}
							fileRootStructs[fs] = true
							descFamily[fs] = true
						}
					}
				}
			case *ast.AssignStmt:
				for li, lhs := range x.Lhs {
					sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
					if !isSel || sel.Sel.Name != "File" {
						continue
					}
					if syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(sel.X)) == outNamed && outNamed != nil {
						if li >= len(x.Rhs) {
							outFileValid = false
							return false
						}
						fs := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x.Rhs[li]))
						if fs == nil || fs.Obj() == nil || fs.Obj().Pkg() != p.Types {
							outFileValid = false
							return false
						}
						fileRootStructs[fs] = true
						descFamily[fs] = true
					}
				}
			}
			return true
		})
	}
	if !outFileValid || len(fileRootStructs) != 1 {
		return nil, nil, nil, false
	}
	var fileNamed *types.Named
	for fn := range fileRootStructs {
		fileNamed = fn
	}

	extraGuards := map[syntaxutil.TypeRef]bool{}
	immutableSlicePtrTypes := map[*types.Named]bool{}
	seenWalk := map[types.Type]bool{}
	fieldsValid := true
	var walkType func(owner *types.Named, t types.Type)
	walkType = func(owner *types.Named, t types.Type) {
		if t == nil || !fieldsValid {
			return
		}
		t = types.Unalias(t)
		if syntaxutil.IsNamedInPkg(t, "sync", "Mutex") {
			if owner != fileNamed {
				fieldsValid = false
			}
			return
		}
		if syntaxutil.IsNamedInPkg(t, "sync", "Once") {
			return
		}
		if n, isN := t.(*types.Named); isN {
			if n == named || n == outNamed {
				return
			}
			if n.Obj() != nil && n.Obj().Pkg() == p.Types {
				if _, isSt := n.Underlying().(*types.Struct); isSt {
					if n.TypeParams().Len() > 0 {
						fieldsValid = false
						return
					}
					if !descFamily[n] {
						descFamily[n] = true
						if stN, okS := n.Underlying().(*types.Struct); okS {
							for i := 0; i < stN.NumFields(); i++ {
								walkType(n, stN.Field(i).Type())
							}
						}
					}
					return
				}
				if _, isSl := n.Underlying().(*types.Slice); isSl {
					immutableSlicePtrTypes[n] = true
				}
			} else if ref, _, subSt, okRef := syntaxutil.TypeRefOfStructFull(n); okRef && subSt.NumFields() > 0 && ref.Valid() {
				extraGuards[ref] = true
				return
			}
		}
		if seenWalk[t] {
			return
		}
		seenWalk[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				fieldsValid = false
			}
		case *types.Chan, *types.TypeParam:
			fieldsValid = false
		case *types.Interface, *types.Signature:
			return
		case *types.Pointer:
			elem := types.Unalias(u.Elem())
			en, isEN := elem.(*types.Named)
			if !isEN || en.Obj() == nil || en.Obj().Pkg() != p.Types {
				fieldsValid = false
				return
			}
			if _, isSt := en.Underlying().(*types.Struct); !isSt {
				fieldsValid = false
				return
			}
			walkType(owner, elem)
		case *types.Slice:
			walkType(owner, u.Elem())
		case *types.Array:
			walkType(owner, u.Elem())
		case *types.Map:
			walkType(owner, u.Key())
			walkType(owner, u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walkType(owner, u.Field(i).Type())
			}
		}
	}
	initialFamily := make([]*types.Named, 0, len(descFamily))
	for fn := range descFamily {
		initialFamily = append(initialFamily, fn)
	}
	for _, fn := range initialFamily {
		if stN, okS := fn.Underlying().(*types.Struct); okS {
			for i := 0; i < stN.NumFields(); i++ {
				walkType(fn, stN.Field(i).Type())
			}
		}
	}
	if !fieldsValid {
		return nil, nil, nil, false
	}

	for slNamed := range immutableSlicePtrTypes {
		psetSl := types.NewMethodSet(types.NewPointer(slNamed))
		for i := 0; i < psetSl.Len(); i++ {
			mfn, okM := psetSl.At(i).Obj().(*types.Func)
			if !okM || mfn.Pkg() != p.Types {
				return nil, nil, nil, false
			}
			mfd := idx.FuncDecls[mfn]
			if mfd == nil || mfd.Body == nil || bodyHasAnyAssignment(p, mfd.Body) {
				return nil, nil, nil, false
			}
		}
	}

	fileSt, ok := fileNamed.Underlying().(*types.Struct)
	if !ok {
		return nil, nil, nil, false
	}
	var fileMuField, fileOnceField *types.Var
	for famNamed := range descFamily {
		if famNamed == fileNamed || structEmbedsUnexported(fileSt, famNamed) {
			if fst, okS := famNamed.Underlying().(*types.Struct); okS {
				mu, done := findUnexportedMutexAndUint32(fst)
				if mu != nil {
					fileMuField = mu
				}
				if done != nil {
					fileOnceField = done
				}
			}
		}
	}
	if fileMuField == nil || fileOnceField == nil {
		return nil, nil, nil, false
	}
	var fileOnceFn *types.Func
	psetFile := types.NewMethodSet(types.NewPointer(fileNamed))
	for i := 0; i < psetFile.Len(); i++ {
		m, okM := psetFile.At(i).Obj().(*types.Func)
		if !okM || m.Pkg() != p.Types || m.Exported() {
			continue
		}
		mfd := idx.FuncDecls[m]
		if mfd != nil && mfd.Body != nil && isLockedOnceInitMethodAllowTailUnlock(p, mfd, fileNamed, fileMuField, fileOnceField) {
			if fileOnceFn != nil {
				return nil, nil, nil, false
			}
			fileOnceFn = m
		}
	}
	if fileOnceFn == nil {
		return nil, nil, nil, false
	}

	receiverOnceDoBlocks := map[*ast.BlockStmt]*types.Named{}
	memoOnceDoBlocks := map[*ast.BlockStmt]bool{}
	allowedBuildLitBlocks := map[*ast.BlockStmt]bool{}
	for _, file := range p.Syntax {
		litOK := true
		ast.Inspect(file, func(n ast.Node) bool {
			if !litOK || n == nil {
				return false
			}
			if _, isGo := n.(*ast.GoStmt); isGo {
				litOK = false
				return false
			}
			lit, isLit := n.(*ast.FuncLit)
			if !isLit {
				return true
			}
			if memoOnceDoBlocks[lit.Body] {
				return true
			}
			if recvStruct, okDo := classifyOnceDoCallback(p, idx, lit, descFamily); okDo {
				if recvStruct != nil {
					receiverOnceDoBlocks[lit.Body] = recvStruct
				}
				return true
			}
			if innerBody, okMemo := isMemoizedOnceGetterClosure(p, idx, lit); okMemo {
				memoOnceDoBlocks[innerBody] = true
				allowedBuildLitBlocks[lit.Body] = true
				allowedBuildLitBlocks[innerBody] = true
				return true
			}
			if isPureSortSliceComparator(p, idx, lit) || isSyncPoolNewConstructor(p, idx, lit) {
				return true
			}
			litOK = false
			return false
		})
		if !litOK {
			return nil, nil, nil, false
		}
	}

	var initFDs []*ast.FuncDecl
	for _, file := range p.Syntax {
		for _, decl := range file.Decls {
			if fd, isFD := decl.(*ast.FuncDecl); isFD && fd.Recv == nil && fd.Name.Name == "init" && fd.Body != nil {
				initFDs = append(initFDs, fd)
			}
		}
	}
	initConeFDs := refconfine.ComputeExclusiveConeFromRoots(p, idx, initFDs, nil, nil)
	rootFuncs := map[*types.Func]bool{buildFn: true, fileOnceFn: true}
	initAndBuildConeFDs := refconfine.ComputeExclusiveConeFromRoots(p, idx, initFDs, rootFuncs, allowedBuildLitBlocks)

	initOnlyRefGlobals := map[*types.Var]bool{}
	for _, name := range p.Types.Scope().Names() {
		v, isVar := p.Types.Scope().Lookup(name).(*types.Var)
		if !isVar || v == nil {
			continue
		}
		if syntaxutil.IsNamedInPkg(v.Type(), "sync", "Pool") {
			if v.Exported() || !verifySyncPoolGlobalUses(p, idx, v) {
				return nil, nil, nil, false
			}
			continue
		}
		for _, uid := range idx.UsesOf[v] {
			enclFD := idx.SyncEnclFuncDecl(uid)
			if initConeFDs[enclFD] {
				continue
			}
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				return nil, nil, nil, false
			}
			par := idx.ParentUnparen(uid)
			if ix, isIx := par.(*ast.IndexExpr); isIx && ast.Unparen(ix.X) == uid && refconfine.IdentOrExprIsWritten(idx, ix) {
				return nil, nil, nil, false
			}
			if cid, isCall := par.(*ast.CallExpr); isCall && len(cid.Args) > 0 && ast.Unparen(cid.Args[0]) == uid {
				if fnID, isID := ast.Unparen(cid.Fun).(*ast.Ident); isID {
					if b, isB := p.TypesInfo.Uses[fnID].(*types.Builtin); isB && (b.Name() == "delete" || b.Name() == "clear" || b.Name() == "copy" || b.Name() == "append") {
						return nil, nil, nil, false
					}
				}
			}
		}
		if refconfine.TypeCarriesMutableRef(v.Type()) {
			initOnlyRefGlobals[v] = true
		}
	}
	for _, file := range p.Syntax {
		extOK := true
		ast.Inspect(file, func(n ast.Node) bool {
			if !extOK || n == nil {
				return false
			}
			id, isID := n.(*ast.Ident)
			if !isID {
				return true
			}
			v, isVar := p.TypesInfo.Uses[id].(*types.Var)
			if !isVar || v == nil || v.IsField() || v.Pkg() == nil || v.Pkg() == p.Types || v.Parent() != v.Pkg().Scope() {
				return true
			}
			sel, isSel := idx.ParentUnparen(id).(*ast.SelectorExpr)
			if !isSel || sel.Sel != id {
				return true
			}
			if refconfine.IdentOrExprIsWritten(idx, sel) {
				extOK = false
				return false
			}
			if un, isUn := idx.ParentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
				if !isReadOnlyPtrCallArg(p, idx, un) {
					extOK = false
					return false
				}
			}
			return true
		})
		if !extOK {
			return nil, nil, nil, false
		}
	}

	fileOnceFD := idx.FuncDecls[fileOnceFn]
	exempt := map[ast.Node]bool{}
	exemptByFunc := map[*ast.FuncDecl]map[*types.Named]bool{}
	for _, uid := range idx.UsesOf[fileMuField] {
		if !idx.IsSyncInFuncDecl(uid, fileOnceFD) {
			return nil, nil, nil, false
		}
	}
	for _, uid := range idx.UsesOf[fileOnceField] {
		sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
		if !isSel || sel.Sel != uid {
			return nil, nil, nil, false
		}
		if idx.IsSyncInFuncDecl(uid, fileOnceFD) {
			if un, isUn := idx.ParentUnparen(sel).(*ast.UnaryExpr); isUn && un.Op == token.AND {
				exempt[un] = true
			}
			continue
		}
		un, isUn := idx.ParentUnparen(sel).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND || !refconfine.IsPureAtomicLoadArg(p, idx, un) {
			return nil, nil, nil, false
		}
		exempt[un] = true
	}

	unexportedScalarSetterFDs := map[*ast.FuncDecl]*types.Named{}
	for famSt := range descFamily {
		if famSt.Obj().Exported() {
			continue
		}
		pset := types.NewMethodSet(types.NewPointer(famSt))
		for i := 0; i < pset.Len(); i++ {
			mfn, okM := pset.At(i).Obj().(*types.Func)
			if !okM || mfn.Pkg() != p.Types || !mfn.Exported() {
				continue
			}
			mfd := idx.FuncDecls[mfn]
			if mfd == nil || mfd.Body == nil {
				continue
			}
			if isPureReceiverScalarSetter(p, idx, mfd, famSt) {
				allCallsInBuild := true
				for _, cid := range idx.UsesOf[mfn] {
					encl := idx.SyncEnclFuncDecl(cid)
					if !initAndBuildConeFDs[encl] {
						allCallsInBuild = false
						break
					}
				}
				if allCallsInBuild {
					unexportedScalarSetterFDs[mfd] = famSt
				}
			}
		}
	}

	for fd := range initAndBuildConeFDs {
		if fd != nil && fd.Body != nil && bodyMutatesAnyNonInitGlobal(p, fd.Body, initConeFDs[fd], mutatedVars) {
			return nil, nil, nil, false
		}
		for famSt := range descFamily {
			addExemptStructInFunc(exemptByFunc, fd, famSt)
		}
	}
	for fd, famSt := range unexportedScalarSetterFDs {
		addExemptStructInFunc(exemptByFunc, fd, famSt)
	}

	enclosingOnceBlock := func(n ast.Node) (*ast.BlockStmt, *types.Named, bool) {
		cur := n
		for cur != nil {
			if blk, isBlk := cur.(*ast.BlockStmt); isBlk {
				if recvSt, okR := receiverOnceDoBlocks[blk]; okR {
					return blk, recvSt, false
				}
				if memoOnceDoBlocks[blk] {
					c2 := idx.ParentMap[blk]
					for c2 != nil {
						if fd, isFD := c2.(*ast.FuncDecl); isFD {
							return blk, nil, initAndBuildConeFDs[fd]
						}
						c2 = idx.ParentMap[c2]
					}
					return nil, nil, false
				}
			}
			if _, isLit := cur.(*ast.FuncLit); isLit {
				return nil, nil, false
			}
			cur = idx.ParentMap[cur]
		}
		return nil, nil, false
	}

	isAllowedDescAddrTake := func(un *ast.UnaryExpr) bool {
		if exempt[un] {
			return true
		}
		inner := ast.Unparen(un.X)
		switch in := inner.(type) {
		case *ast.CompositeLit:
			if litSt := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(in)); litSt != nil && descFamily[litSt] {
				return true
			}
		case *ast.SelectorExpr:
			selInfo := p.TypesInfo.Selections[in]
			if selInfo == nil || selInfo.Kind() != types.FieldVal {
				return false
			}
			ft := types.Unalias(selInfo.Type())
			if fn, isN := ft.(*types.Named); isN && (descFamily[fn] || immutableSlicePtrTypes[fn]) {
				return true
			}
		case *ast.IndexExpr:
			if elemN := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(in)); elemN != nil && descFamily[elemN] {
				return true
			}
		}
		return false
	}

	pf := freshstruct.ComputePackageFreshConstructors(p, idx, nil)

	checkDescMutExpr := func(stmtNode ast.Node, expr ast.Expr) bool {
		if !refconfine.TouchesAnyNamedStruct(p, expr, descFamily) {
			return true
		}
		syncFD := idx.SyncEnclFuncDecl(stmtNode)
		if syncFD != nil {
			if initAndBuildConeFDs[syncFD] {
				exempt[stmtNode] = true
				return true
			}
			if setterSt, okS := unexportedScalarSetterFDs[syncFD]; okS && refconfine.TouchesAnyNamedStruct(p, expr, map[*types.Named]bool{setterSt: true}) {
				exempt[stmtNode] = true
				return true
			}
			if pf.IsFreshMutationTarget(syncFD, expr) {
				exempt[stmtNode] = true
				return true
			}
		}
		_, recvSt, isMemoBuild := enclosingOnceBlock(stmtNode)
		if isMemoBuild {
			exempt[stmtNode] = true
			return true
		}
		if recvSt != nil {
			if refconfine.TouchesAnyNamedStruct(p, expr, map[*types.Named]bool{recvSt: true}) {
				exempt[stmtNode] = true
				return true
			}
		}
		return false
	}

	for _, file := range p.Syntax {
		mutOK := true
		ast.Inspect(file, func(n ast.Node) bool {
			if !mutOK || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if !checkDescMutExpr(x, lhs) {
						mutOK = false
						return false
					}
				}
			case *ast.IncDecStmt:
				if !checkDescMutExpr(x, x.X) {
					mutOK = false
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if (x.Key != nil && !checkDescMutExpr(x, x.Key)) || (x.Value != nil && !checkDescMutExpr(x, x.Value)) {
						mutOK = false
						return false
					}
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && refconfine.TouchesAnyNamedStruct(p, x.X, descFamily) {
					syncFD := idx.SyncEnclFuncDecl(x)
					if syncFD != nil {
						if initAndBuildConeFDs[syncFD] {
							exempt[x] = true
							return true
						}
						if pf.IsFreshAddrOrValue(syncFD, x.X) {
							exempt[x] = true
							return true
						}
					}
					_, recvSt, isMemoBuild := enclosingOnceBlock(x)
					if isMemoBuild || recvSt != nil {
						exempt[x] = true
						return true
					}
					if isAllowedDescAddrTake(x) {
						exempt[x] = true
						return true
					}
					mutOK = false
					return false
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if !checkDescMutExpr(x, x.Args[0]) {
								mutOK = false
								return false
							}
						}
					}
				}
			}
			return true
		})
		if !mutOK {
			return nil, nil, nil, false
		}
	}

	snapshotGuardedFields := collectSnapshotGuardedValueFields(p, idx, descFamily, extraGuards, initAndBuildConeFDs, pf)

	nonSnapshotExtraGuards := map[syntaxutil.TypeRef]bool{}
	seenNonSnap := map[types.Type]bool{}
	nonSnapValid := true
	var walkNonSnapshotType func(t types.Type)
	walkNonSnapshotType = func(t types.Type) {
		if t == nil || !nonSnapValid {
			return
		}
		t = types.Unalias(t)
		if syntaxutil.IsNamedInPkg(t, "sync", "Mutex") || syntaxutil.IsNamedInPkg(t, "sync", "Once") {
			return
		}
		if n, isN := t.(*types.Named); isN {
			if n == named || n == outNamed || descFamily[n] || immutableSlicePtrTypes[n] {
				return
			}
			if n.Obj() != nil && n.Obj().Pkg() != nil && n.Obj().Pkg() != p.Types {
				switch subU := n.Underlying().(type) {
				case *types.Struct:
					if subU.NumFields() > 0 {
						ref := syntaxutil.TypeRef{Pkg: n.Obj().Pkg().Path(), Name: n.Obj().Name()}
						if !ref.Valid() {
							nonSnapValid = false
							return
						}
						nonSnapshotExtraGuards[ref] = true
					}
				case *types.Slice, *types.Map:
					ref := syntaxutil.TypeRef{Pkg: n.Obj().Pkg().Path(), Name: n.Obj().Name()}
					if !ref.Valid() {
						nonSnapValid = false
						return
					}
					nonSnapshotExtraGuards[ref] = true
				}
			}
		}
		if seenNonSnap[t] {
			return
		}
		seenNonSnap[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				nonSnapValid = false
			}
		case *types.Chan, *types.TypeParam:
			nonSnapValid = false
		case *types.Interface, *types.Signature:
			return
		case *types.Pointer:
			en, isEN := types.Unalias(u.Elem()).(*types.Named)
			if !isEN || (!descFamily[en] && !immutableSlicePtrTypes[en]) {
				nonSnapValid = false
				return
			}
		case *types.Slice:
			walkNonSnapshotType(u.Elem())
		case *types.Array:
			walkNonSnapshotType(u.Elem())
		case *types.Map:
			walkNonSnapshotType(u.Key())
			walkNonSnapshotType(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walkNonSnapshotType(u.Field(i).Type())
			}
		}
	}
	for famSt := range descFamily {
		if stN, okS := famSt.Underlying().(*types.Struct); okS {
			for i := 0; i < stN.NumFields(); i++ {
				f := stN.Field(i)
				if snapshotGuardedFields[f] {
					continue
				}
				walkNonSnapshotType(f.Type())
			}
		}
	}
	if !nonSnapValid {
		return nil, nil, nil, false
	}

	isImmPtr := func(t types.Type) bool {
		ptr, okP := types.Unalias(t).(*types.Pointer)
		if !okP {
			return false
		}
		en, okN := types.Unalias(ptr.Elem()).(*types.Named)
		return okN && (descFamily[en] || immutableSlicePtrTypes[en])
	}
	immutableIfaceFields := collectImmutableIfaceFields(p, idx, descFamily, isImmPtr)
	if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
		Index:                         idx,
		IsImmutablePtr:                isImmPtr,
		AllowReturnFromUnexportedFunc: true,
		AllowImmutableInterfaceElem: func(containerExpr ast.Expr) bool {
			sel, isSel := ast.Unparen(containerExpr).(*ast.SelectorExpr)
			if !isSel {
				return false
			}
			fv, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
			return fv != nil && immutableIfaceFields[fv]
		},
		AllowMethodRecv: func(call *ast.CallExpr, callee *types.Func, _ ast.Expr) bool {
			if callee == nil || call.Ellipsis.IsValid() {
				return false
			}
			orig := callee.Origin()
			sig, okSig := orig.Type().(*types.Signature)
			if !okSig || sig.Recv() == nil {
				return false
			}
			recvT := types.Unalias(sig.Recv().Type())
			if _, isPtr := recvT.(*types.Pointer); isPtr {
				return false
			}
			rn, isRN := recvT.(*types.Named)
			if !isRN || rn.Obj() == nil || rn.Obj().Pkg() == nil {
				return false
			}
			if _, isSl := rn.Underlying().(*types.Slice); !isSl {
				return false
			}
			sliceRef := syntaxutil.TypeRef{Pkg: rn.Obj().Pkg().Path(), Name: rn.Obj().Name()}
			if !nonSnapshotExtraGuards[sliceRef] {
				return false
			}
			for _, a := range call.Args {
				if refconfine.TypeContainsRefOrPointer(p.TypesInfo.TypeOf(a)) {
					return false
				}
			}
			for ri := 0; ri < sig.Results().Len(); ri++ {
				if refconfine.TypeContainsRefOrPointer(sig.Results().At(ri).Type()) {
					return false
				}
			}
			return true
		},
		SeedExpr: func(expr ast.Expr) (bool, bool) {
			if id, isID := ast.Unparen(expr).(*ast.Ident); isID {
				if v, isV := p.TypesInfo.Uses[id].(*types.Var); isV && initOnlyRefGlobals[v] {
					if initConeFDs[idx.SyncEnclFuncDecl(id)] {
						return false, false
					}
					ft := v.Type()
					if refconfine.IsDirectMutableRefWith(ft, isImmPtr) {
						return true, true
					}
					if refconfine.TypeCarriesMutableRefWith(ft, isImmPtr) {
						return false, true
					}
				}
				return false, false
			}
			sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
			if !isSel {
				return false, false
			}
			selInfo := p.TypesInfo.Selections[sel]
			if selInfo == nil || selInfo.Kind() != types.FieldVal || selInfo.Obj() == nil || selInfo.Obj().Exported() {
				return false, false
			}
			if fv, isFV := selInfo.Obj().(*types.Var); isFV && snapshotGuardedFields[fv] {
				return false, false
			}
			if refconfine.IsInsideExemptWriteOrAddr(idx, sel, exempt) {
				return false, false
			}
			syncFD := idx.SyncEnclFuncDecl(sel)
			if syncFD != nil && (initAndBuildConeFDs[syncFD] || unexportedScalarSetterFDs[syncFD] != nil || pf.IsFreshAddrOrValue(syncFD, sel) || pf.IsFreshMutationTarget(syncFD, sel)) {
				return false, false
			}
			if _, recvSt, isMemoBuild := enclosingOnceBlock(sel); isMemoBuild || recvSt != nil {
				return false, false
			}
			hit := false
			syntaxutil.ForEachSelectionHopStruct(selInfo, func(hop *types.Named) {
				if descFamily[hop] {
					hit = true
				}
			})
			if !hit {
				return false, false
			}
			ft := selInfo.Type()
			if refconfine.IsDirectMutableRefWith(ft, isImmPtr) {
				return true, true
			}
			if refconfine.TypeCarriesMutableRefWith(ft, isImmPtr) {
				return false, true
			}
			return false, false
		},
		AllowCallArg: func(call *ast.CallExpr, _ int, _ ast.Expr) bool {
			callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
			return callee != nil && callee.Pkg() != nil && callee.Pkg().Path() == "bytes" && callee.Name() == "Equal"
		},
	}) {
		return nil, nil, nil, false
	}

	guardMap := map[syntaxutil.TypeRef]bool{}
	for famSt := range descFamily {
		ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: famSt.Obj().Name()}
		if !ref.Valid() {
			return nil, nil, nil, false
		}
		guardMap[ref] = true
	}
	for g := range nonSnapshotExtraGuards {
		guardMap[g] = true
	}
	guardTypes := make([]syntaxutil.TypeRef, 0, len(guardMap))
	for g := range guardMap {
		guardTypes = append(guardTypes, g)
	}
	sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].Key() < guardTypes[j].Key() })
	if exemptReadFields != nil {
		memo := map[*types.Named]bool{}
		visiting := map[*types.Named]bool{}
		for famSt := range descFamily {
			st, okS := famSt.Underlying().(*types.Struct)
			if !okS {
				continue
			}
			for i := 0; i < st.NumFields(); i++ {
				f := st.Field(i)
				if f.Exported() && isDescFamilyReadConfinedType(f.Type(), descFamily, memo, visiting) {
					exemptReadFields[f] = true
				}
			}
		}
	}
	return exempt, exemptByFunc, guardTypes, true
}

func isDescFamilyReadConfinedType(
	t types.Type,
	descFamily map[*types.Named]bool,
	memo map[*types.Named]bool,
	visiting map[*types.Named]bool,
) bool {
	if t == nil {
		return false
	}
	named, isN := types.Unalias(t).(*types.Named)
	if !isN || !descFamily[named] || named.Obj() == nil {
		return false
	}
	if res, ok := memo[named]; ok {
		return res
	}
	if visiting[named] {
		return false
	}
	st, isSt := named.Underlying().(*types.Struct)
	if !isSt || st.NumFields() == 0 {
		memo[named] = false
		return false
	}
	visiting[named] = true
	defer delete(visiting, named)
	for i := 0; i < st.NumFields(); i++ {
		sf := st.Field(i)
		if !refconfine.TypeCarriesMutableRef(sf.Type()) {
			continue
		}
		if !sf.Exported() && !sf.Embedded() {
			continue
		}
		if !isDescFamilyReadConfinedType(sf.Type(), descFamily, memo, visiting) {
			memo[named] = false
			return false
		}
	}
	memo[named] = true
	return true
}

func isZeroSizedStatelessField(f *types.Var) bool {
	if f == nil {
		return false
	}
	t := f.Type()
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Struct:
		if u.NumFields() != 0 {
			return false
		}
	case *types.Array:
		if u.Len() != 0 {
			return false
		}
	default:
		return false
	}
	return types.NewMethodSet(types.NewPointer(t)).Len() == 0
}

func collectImmutableIfaceFields(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	descFamily map[*types.Named]bool,
	isImmPtr func(types.Type) bool,
) map[*types.Var]bool {
	cand := map[*types.Var]bool{}
	fieldOwner := map[*types.Var]*types.Named{}
	for ownerNamed := range descFamily {
		st, ok := ownerNamed.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			var elemT types.Type
			switch u := types.Unalias(f.Type()).Underlying().(type) {
			case *types.Slice:
				elemT = u.Elem()
			case *types.Map:
				elemT = u.Elem()
			}
			if elemT == nil {
				continue
			}
			if iface, okI := types.Unalias(elemT).Underlying().(*types.Interface); okI && iface.NumMethods() > 0 {
				cand[f] = true
				fieldOwner[f] = ownerNamed
			}
		}
	}
	if len(cand) == 0 {
		return nil
	}

	unkeyedOwners := map[*types.Named]bool{}
	rangeValField := map[*types.Var]*types.Var{}
	writtenVars := map[*types.Var]bool{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.CompositeLit:
				if len(s.Elts) > 0 {
					if named, isN := types.Unalias(p.TypesInfo.TypeOf(s)).(*types.Named); isN && descFamily[named] {
						for _, elt := range s.Elts {
							if _, isKV := elt.(*ast.KeyValueExpr); !isKV {
								unkeyedOwners[named] = true
								break
							}
						}
					}
				}
			case *ast.AssignStmt:
				if s.Tok != token.DEFINE {
					for _, lhs := range s.Lhs {
						if id, isID := ast.Unparen(lhs).(*ast.Ident); isID {
							if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
								writtenVars[v] = true
							}
						}
					}
				}
			case *ast.UnaryExpr:
				if s.Op == token.AND {
					if id, isID := ast.Unparen(s.X).(*ast.Ident); isID {
						if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
							writtenVars[v] = true
						}
					}
				}
			case *ast.RangeStmt:
				if s.Tok == token.DEFINE && s.Value != nil {
					if vid, isID := ast.Unparen(s.Value).(*ast.Ident); isID {
						if vv, _ := p.TypesInfo.Defs[vid].(*types.Var); vv != nil && idx.DefCounts[vv] == 1 {
							if xSel, isSel := ast.Unparen(s.X).(*ast.SelectorExpr); isSel {
								if sf, _ := p.TypesInfo.Uses[xSel.Sel].(*types.Var); sf != nil && cand[sf] {
									rangeValField[vv] = sf
								}
							}
						}
					}
				} else if s.Tok == token.ASSIGN {
					for _, e := range []ast.Expr{s.Key, s.Value} {
						if id, isID := ast.Unparen(e).(*ast.Ident); isID && id != nil {
							if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
								writtenVars[v] = true
							}
						}
					}
				}
			}
			return true
		})
	}
	for v := range writtenVars {
		delete(rangeValField, v)
	}
	for f, owner := range fieldOwner {
		if unkeyedOwners[owner] {
			delete(cand, f)
		}
	}

	isMakeCall := func(e ast.Expr) bool {
		c, isC := ast.Unparen(e).(*ast.CallExpr)
		if !isC || len(c.Args) == 0 {
			return false
		}
		id, isID := ast.Unparen(c.Fun).(*ast.Ident)
		if !isID {
			return false
		}
		b, isB := p.TypesInfo.Uses[id].(*types.Builtin)
		return isB && b.Name() == "make"
	}
	validElem := func(e ast.Expr) bool {
		e = ast.Unparen(e)
		if e == nil {
			return false
		}
		if isImmPtr(p.TypesInfo.TypeOf(e)) {
			return true
		}
		if id, isID := e.(*ast.Ident); isID {
			if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil {
				if srcF := rangeValField[v]; srcF != nil && cand[srcF] {
					return true
				}
			}
		}
		return false
	}

	changed := true
	for changed {
		changed = false
		for f := range cand {
			okField := true
			for _, uid := range idx.UsesOf[f] {
				if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
					rhs := ast.Unparen(kv.Value)
					if syntaxutil.IsNilIdent(p.TypesInfo, rhs) || isMakeCall(rhs) {
						continue
					}
					if cl, isCL := rhs.(*ast.CompositeLit); isCL {
						for _, elt := range cl.Elts {
							val := elt
							if ekv, isEKV := elt.(*ast.KeyValueExpr); isEKV {
								val = ekv.Value
							}
							if !validElem(val) {
								okField = false
								break
							}
						}
						if okField {
							continue
						}
					}
					okField = false
					break
				}
				sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
				if !isSel || sel.Sel != uid {
					okField = false
					break
				}
				par := idx.ParentUnparen(sel)
				if un, isUn := par.(*ast.UnaryExpr); isUn && un.Op == token.AND {
					okField = false
					break
				}
				if _, isSl := par.(*ast.SliceExpr); isSl {
					okField = false
					break
				}
				if call, isCall := par.(*ast.CallExpr); isCall && len(call.Args) >= 1 && ast.Unparen(call.Args[0]) == sel {
					if cid, isID := ast.Unparen(call.Fun).(*ast.Ident); isID {
						if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && (b.Name() == "copy" || b.Name() == "delete" || b.Name() == "clear") {
							okField = false
							break
						}
					}
				}
				if refconfine.IdentOrExprIsWritten(idx, sel) {
					as, isAs := par.(*ast.AssignStmt)
					if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Lhs[0]) != sel {
						okField = false
						break
					}
					rhs := ast.Unparen(as.Rhs[0])
					if syntaxutil.IsNilIdent(p.TypesInfo, rhs) || isMakeCall(rhs) {
						continue
					}
					apCall, isAC := rhs.(*ast.CallExpr)
					if !isAC || len(apCall.Args) < 2 || apCall.Ellipsis.IsValid() {
						okField = false
						break
					}
					apID, isID := ast.Unparen(apCall.Fun).(*ast.Ident)
					if !isID {
						okField = false
						break
					}
					if b, isB := p.TypesInfo.Uses[apID].(*types.Builtin); !isB || b.Name() != "append" || !syntaxutil.SameFieldTargetExpr(p, sel, apCall.Args[0]) {
						okField = false
						break
					}
					for _, arg := range apCall.Args[1:] {
						if !validElem(arg) {
							okField = false
							break
						}
					}
					if !okField {
						break
					}
					continue
				}
				if ix, isIx := par.(*ast.IndexExpr); isIx && ast.Unparen(ix.X) == sel {
					ixPar := idx.ParentUnparen(ix)
					if un, isUn := ixPar.(*ast.UnaryExpr); isUn && un.Op == token.AND {
						okField = false
						break
					}
					if refconfine.IdentOrExprIsWritten(idx, ix) {
						as, isAs := ixPar.(*ast.AssignStmt)
						if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Lhs[0]) != ix || !validElem(as.Rhs[0]) {
							okField = false
							break
						}
					}
					continue
				}
			}
			if !okField {
				delete(cand, f)
				changed = true
			}
		}
	}
	return cand
}

func structEmbedsUnexported(st *types.Struct, target *types.Named) bool {
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f.Embedded() && !f.Exported() && types.Unalias(f.Type()) == target {
			return true
		}
	}
	return false
}

func isLockedOnceInitMethodAllowTailUnlock(
	p *packages.Package,
	fd *ast.FuncDecl,
	named *types.Named,
	muField, doneField *types.Var,
) bool {
	if isLockedOnceInitMethod(p, fd, named, muField, doneField) {
		return true
	}
	stmts := fd.Body.List
	if len(stmts) < 3 || fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 {
		return false
	}
	recvVar, ok := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if !ok || recvVar == nil || !syntaxutil.IsPtrToNamed(recvVar.Type(), named) {
		return false
	}
	if !isFieldMutexCallStmt(p, stmts[0], recvVar, muField, "Lock", false) || !isFieldMutexCallStmt(p, stmts[len(stmts)-1], recvVar, muField, "Unlock", false) {
		return false
	}
	for _, mid := range stmts[1 : len(stmts)-1] {
		bad := false
		ast.Inspect(mid, func(n ast.Node) bool {
			if bad || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.ReturnStmt, *ast.BranchStmt, *ast.GoStmt, *ast.DeferStmt:
				bad = true
				return false
			case *ast.ExprStmt:
				if isFieldMutexCallStmt(p, x, recvVar, muField, "Unlock", false) || isFieldMutexCallStmt(p, x, recvVar, muField, "Lock", false) {
					bad = true
					return false
				}
			}
			return true
		})
		if bad {
			return false
		}
	}
	sawAtomicStore := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if sawAtomicStore || n == nil {
			return false
		}
		call, okC := n.(*ast.CallExpr)
		if !okC || len(call.Args) != 2 {
			return true
		}
		if isAtomicUint32Call(p, call, "StoreUint32") && isAddrOfRecvField(p, call.Args[0], recvVar, doneField) {
			if tv := p.TypesInfo.Types[call.Args[1]]; tv.Value != nil {
				if v, okI := constant.Uint64Val(tv.Value); okI && v > 0 {
					sawAtomicStore = true
					return false
				}
			}
		}
		return true
	})
	return sawAtomicStore
}

func classifyOnceDoCallback(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	lit *ast.FuncLit,
	descFamily map[*types.Named]bool,
) (*types.Named, bool) {
	call, isCall := idx.ParentUnparen(lit).(*ast.CallExpr)
	if !isCall || len(call.Args) != 1 || ast.Unparen(call.Args[0]) != lit {
		return nil, false
	}
	sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isSel || sel.Sel.Name != "Do" {
		return nil, false
	}
	fn, isFn := p.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !isFn || fn.Pkg() == nil || fn.Pkg().Path() != "sync" || fn.Name() != "Do" {
		return nil, false
	}
	onceSel, isOS := ast.Unparen(sel.X).(*ast.SelectorExpr)
	if !isOS || !syntaxutil.IsNamedInPkg(p.TypesInfo.TypeOf(onceSel), "sync", "Once") {
		return nil, false
	}
	rid, isRID := ast.Unparen(onceSel.X).(*ast.Ident)
	if !isRID {
		return nil, false
	}
	rv, _ := p.TypesInfo.Uses[rid].(*types.Var)
	if rv == nil {
		return nil, false
	}
	recvSt := syntaxutil.DerefNamedStruct(rv.Type())
	if recvSt == nil || !descFamily[recvSt] {
		return nil, false
	}
	var enclFD *ast.FuncDecl
	for cur := idx.ParentMap[call]; cur != nil; cur = idx.ParentMap[cur] {
		if _, isInnerLit := cur.(*ast.FuncLit); isInnerLit {
			return nil, false
		}
		if fd, isFD := cur.(*ast.FuncDecl); isFD {
			enclFD = fd
			break
		}
	}
	if enclFD == nil || enclFD.Recv == nil || len(enclFD.Recv.List) != 1 || len(enclFD.Recv.List[0].Names) != 1 {
		return nil, false
	}
	if p.TypesInfo.Defs[enclFD.Recv.List[0].Names[0]] != rv {
		return nil, false
	}
	if bodyMutatesAnyPackageGlobal(p, lit.Body, nil) {
		return nil, false
	}
	return recvSt, true
}

func isPureSortSliceComparator(p *packages.Package, idx *refconfine.PkgIndex, lit *ast.FuncLit) bool {
	call, isCall := idx.ParentUnparen(lit).(*ast.CallExpr)
	if !isCall || len(call.Args) != 2 || ast.Unparen(call.Args[1]) != lit {
		return false
	}
	callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
	if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "sort" || callee.Name() != "Slice" {
		return false
	}
	return lit.Body != nil && !bodyHasAnyAssignment(p, lit.Body)
}

func isSyncPoolNewConstructor(p *packages.Package, idx *refconfine.PkgIndex, lit *ast.FuncLit) bool {
	kv, isKV := idx.ParentUnparen(lit).(*ast.KeyValueExpr)
	if !isKV || ast.Unparen(kv.Value) != lit {
		return false
	}
	kid, isID := kv.Key.(*ast.Ident)
	if !isID || kid.Name != "New" {
		return false
	}
	cl, isCL := idx.ParentUnparen(kv).(*ast.CompositeLit)
	if !isCL || !syntaxutil.IsNamedInPkg(p.TypesInfo.TypeOf(cl), "sync", "Pool") {
		return false
	}
	if lit.Body == nil || len(lit.Body.List) != 1 {
		return false
	}
	ret, isRet := lit.Body.List[0].(*ast.ReturnStmt)
	if !isRet || len(ret.Results) != 1 {
		return false
	}
	nc, isNC := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
	if !isNC || len(nc.Args) != 1 {
		return false
	}
	nid, isNID := ast.Unparen(nc.Fun).(*ast.Ident)
	if !isNID {
		return false
	}
	b, isB := p.TypesInfo.Uses[nid].(*types.Builtin)
	return isB && b.Name() == "new"
}

func bodyHasAnyAssignment(p *packages.Package, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt, *ast.IncDecStmt, *ast.SendStmt, *ast.GoStmt, *ast.DeferStmt:
			found = true
			return false
		case *ast.RangeStmt:
			if x.Tok == token.ASSIGN {
				found = true
				return false
			}
		case *ast.CallExpr:
			if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID {
				if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
					switch b.Name() {
					case "delete", "clear", "copy", "append":
						found = true
						return false
					}
				}
			}
		}
		return true
	})
	return found
}

func verifySyncPoolGlobalUses(_ *packages.Package, idx *refconfine.PkgIndex, v *types.Var) bool {
	for _, uid := range idx.UsesOf[v] {
		sel, isSel := idx.ParentUnparen(uid).(*ast.SelectorExpr)
		if !isSel || ast.Unparen(sel.X) != uid || (sel.Sel.Name != "Get" && sel.Sel.Name != "Put") {
			return false
		}
		call, isCall := idx.ParentUnparen(sel).(*ast.CallExpr)
		if !isCall || ast.Unparen(call.Fun) != sel {
			return false
		}
	}
	return true
}

func isReadOnlyPtrCallArg(p *packages.Package, idx *refconfine.PkgIndex, un *ast.UnaryExpr) bool {
	call, isCall := idx.ParentUnparen(un).(*ast.CallExpr)
	if !isCall {
		return false
	}
	argIdx := -1
	for i, a := range call.Args {
		if ast.Unparen(a) == un {
			argIdx = i
			break
		}
	}
	if argIdx < 0 {
		return false
	}
	callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
	if callee == nil || callee.Pkg() != p.Types {
		return false
	}
	fd := idx.FuncDecls[callee.Origin()]
	sig, okSig := callee.Origin().Type().(*types.Signature)
	if fd == nil || fd.Body == nil || !okSig || sig.Variadic() || argIdx >= sig.Params().Len() {
		return false
	}
	pv := sig.Params().At(argIdx)
	for _, uid := range idx.UsesOf[pv] {
		if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
			return false
		}
		par := idx.ParentUnparen(uid)
		if star, isStar := par.(*ast.StarExpr); isStar && ast.Unparen(star.X) == uid {
			if refconfine.IdentOrExprIsWritten(idx, star) {
				return false
			}
		}
	}
	return true
}

func isPureReceiverScalarSetter(p *packages.Package, _ *refconfine.PkgIndex, fd *ast.FuncDecl, recvStruct *types.Named) bool {
	if fd.Recv == nil || len(fd.Recv.List) != 1 || len(fd.Recv.List[0].Names) != 1 || fd.Body == nil {
		return false
	}
	rv, _ := p.TypesInfo.Defs[fd.Recv.List[0].Names[0]].(*types.Var)
	if rv == nil || !syntaxutil.IsPtrToNamed(rv.Type(), recvStruct) {
		return false
	}
	for _, stmt := range fd.Body.List {
		as, isAs := stmt.(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != len(as.Rhs) {
			return false
		}
		for i, lhs := range as.Lhs {
			sel, isSel := ast.Unparen(lhs).(*ast.SelectorExpr)
			if !isSel {
				return false
			}
			rid, isID := ast.Unparen(sel.X).(*ast.Ident)
			if !isID || p.TypesInfo.Uses[rid] != rv {
				return false
			}
			lt := p.TypesInfo.TypeOf(sel)
			if lt == nil || refconfine.TypeContainsRefOrPointer(lt) {
				return false
			}
			rhs := ast.Unparen(as.Rhs[i])
			if p.TypesInfo.Types[rhs].Value != nil {
				continue
			}
			if pid, isPID := rhs.(*ast.Ident); isPID {
				if pv, isV := p.TypesInfo.Uses[pid].(*types.Var); isV && pv != nil && !pv.IsField() && pv.Parent() != p.Types.Scope() && !refconfine.TypeContainsRefOrPointer(pv.Type()) {
					continue
				}
			}
			return false
		}
	}
	return len(fd.Body.List) > 0
}

func bodyMutatesAnyNonInitGlobal(p *packages.Package, body *ast.BlockStmt, inInit bool, mutatedVars map[string]bool) bool {
	if inInit {
		return false
	}
	return bodyMutatesAnyPackageGlobal(p, body, mutatedVars)
}
