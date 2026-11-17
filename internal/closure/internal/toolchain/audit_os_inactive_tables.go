package toolchain

import (
	"go/ast"
	"go/token"
	"maps"
)

type osFalseHelperKey struct {
	name    string
	arity   int
	boolIdx int
}

var osAllowedPureIntConversions = kernelPureIntConvNames

type osInactiveTableStruct struct {
	name           string
	spineField     string
	nonSpineFields map[string]bool
	methods        map[string]*ast.FuncDecl
	readNilMethods map[string]bool
	mutatorMethods map[string]bool
	valid          bool
}

type osInactiveTableVar struct {
	name       string
	structName string
	declIdent  *ast.Ident
}

type osTableMutSite struct {
	fn   *ast.FuncDecl
	call *ast.CallExpr
}

var osAllowedBasicTableFields = map[string]bool{
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
	"bool": true, "string": true, "byte": true,
}

func discoverOSStateTables(
	k *PackageInactiveKernel,
	idx *PackageASTIndex,
	files []*ast.File,
	anyLinknameLocals map[string]bool,
) (
	tableStructs map[string]*osInactiveTableStruct,
	activeTables map[string]osInactiveTableVar,
	mutSitesByTable map[string][]osTableMutSite,
) {
	tableStructs = map[string]*osInactiveTableStruct{}
	activeTables = map[string]osInactiveTableVar{}
	mutSitesByTable = map[string][]osTableMutSite{}
	if k == nil || idx == nil || k.hasDotImport || k.builtinsShadowed {
		return tableStructs, activeTables, mutSitesByTable
	}

	isSafeNonSpineFieldType := func(sFile *ast.File, expr ast.Expr) bool {
		switch t := unwrapParens(expr).(type) {
		case *ast.ArrayType, *ast.MapType:
			return true
		case *ast.Ident:
			return osAllowedBasicTableFields[t.Name] && idx.pkgDeclCounts[t.Name] == 0 && !k.fileImportNames[sFile][t.Name]
		case *ast.SelectorExpr:
			pkgID, okID := unwrapParens(t.X).(*ast.Ident)
			if !okID {
				return false
			}
			switch k.FileImportPath(sFile, pkgID.Name) {
			case "sync":
				return t.Sel.Name == "Mutex" || t.Sel.Name == "RWMutex"
			case "internal/sync":
				return t.Sel.Name == "Mutex" || t.Sel.Name == "RWMutex" || t.Sel.Name == "KernelMutex"
			}
		}
		return false
	}

	for sName, sp := range idx.nonAliasStructSpec {
		if ast.IsExported(sName) {
			continue
		}
		sFile := idx.typeSpecFile[sp]
		if idx.pkgDeclCounts[sName] != 1 || k.FileImportPath(sFile, "atomic") != "sync/atomic" {
			continue
		}
		stType, okST := unwrapParens(sp.Type).(*ast.StructType)
		if !okST || stType.Fields == nil {
			continue
		}
		var spineField string
		nonSpineFields := map[string]bool{}
		badStructField := false
		for _, fld := range stType.Fields.List {
			if len(fld.Names) == 0 {
				badStructField = true
				break
			}
			for _, id := range fld.Names {
				if id.Name == "" || id.Name == "_" || ast.IsExported(id.Name) {
					badStructField = true
					break
				}
			}
			if badStructField {
				break
			}
			isSpineType := false
			if idxExpr, okIdx := unwrapParens(fld.Type).(*ast.IndexExpr); okIdx {
				_, isSpineType = isSelectorBaseField(idxExpr.X, "atomic", "Pointer")
			}
			if isSpineType {
				if len(fld.Names) != 1 || spineField != "" {
					badStructField = true
					break
				}
				spineField = fld.Names[0].Name
			} else {
				if !isSafeNonSpineFieldType(sFile, fld.Type) {
					badStructField = true
					break
				}
				for _, id := range fld.Names {
					nonSpineFields[id.Name] = true
				}
			}
		}
		if badStructField || spineField == "" {
			continue
		}
		cand := &osInactiveTableStruct{
			name:           sName,
			spineField:     spineField,
			nonSpineFields: nonSpineFields,
			methods:        map[string]*ast.FuncDecl{},
			readNilMethods: map[string]bool{},
			mutatorMethods: map[string]bool{},
			valid:          true,
		}
		for _, f := range files {
			for _, decl := range f.Decls {
				fn, okF := decl.(*ast.FuncDecl)
				if !okF || fn.Recv == nil || len(fn.Recv.List) != 1 || RecvBaseTypeName(fn.Recv.List[0].Type) != sName {
					continue
				}
				if k.fileImportNames[f][sName] {
					cand.valid = false
					break
				}
				_, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr)
				if !isPtr || fn.Body == nil || fn.Name == nil || anyLinknameLocals[fn.Name.Name] || cand.nonSpineFields[fn.Name.Name] || fn.Name.Name == spineField {
					cand.valid = false
					break
				}
				if _, dup := cand.methods[fn.Name.Name]; dup {
					cand.valid = false
					break
				}
				cand.methods[fn.Name.Name] = fn
			}
			if !cand.valid {
				break
			}
		}
		if !cand.valid || len(cand.methods) == 0 {
			continue
		}

		allowedSpineSels := map[*ast.SelectorExpr]bool{}
		methodCalleeMap := map[string]map[string]bool{}
		for mName, mFn := range cand.methods {
			mRecv := recvVarName(mFn)
			if mRecv == "" || k.IdentShadowedInFunc(mFn, "nil") || funcDeclaresAnyParamOrResult(mFn, map[string]bool{}) || bodyDeclaresAnyIdent(mFn.Body, map[string]bool{mRecv: true}) {
				cand.valid = false
				break
			}
			if mFn.Type != nil {
				for _, fl := range []*ast.FieldList{mFn.Type.TypeParams, mFn.Type.Params, mFn.Type.Results} {
					if fl == nil {
						continue
					}
					for _, fld := range fl.List {
						for _, id := range fld.Names {
							if id.Name == mRecv {
								cand.valid = false
							}
						}
					}
				}
			}
			if !cand.valid {
				break
			}
			allowedRecvIdents := map[*ast.Ident]bool{}
			methodCalleeMap[mName] = map[string]bool{}
			var mutatesSpine, badSpineUse bool
			ast.Inspect(mFn.Body, func(n ast.Node) bool {
				if badSpineUse || n == nil {
					return false
				}
				if u, okU := n.(*ast.UnaryExpr); okU && u.Op == token.AND {
					ast.Inspect(u.X, func(un ast.Node) bool {
						if id, okID := un.(*ast.Ident); okID && id.Name == mRecv {
							badSpineUse = true
							return false
						}
						return !badSpineUse
					})
					if badSpineUse {
						return false
					}
				}
				if sel, okS := n.(*ast.SelectorExpr); okS && cand.nonSpineFields[sel.Sel.Name] {
					if rID, okR := isIdentNamed(sel.X, mRecv); okR {
						allowedRecvIdents[rID] = true
					}
				}
				call, okC := n.(*ast.CallExpr)
				if !okC || call.Ellipsis.IsValid() {
					return true
				}
				opSel, okOS := unwrapParens(call.Fun).(*ast.SelectorExpr)
				if !okOS {
					return true
				}
				if rID, okRM := isIdentNamed(opSel.X, mRecv); okRM && cand.methods[opSel.Sel.Name] != nil {
					allowedRecvIdents[rID] = true
					methodCalleeMap[mName][opSel.Sel.Name] = true
					return true
				}
				spSel, okSS := unwrapParens(opSel.X).(*ast.SelectorExpr)
				if !okSS || spSel.Sel.Name != spineField {
					return true
				}
				rID, okR := isIdentNamed(spSel.X, mRecv)
				if !okR {
					badSpineUse = true
					return false
				}
				switch opSel.Sel.Name {
				case "Load":
					if len(call.Args) != 0 {
						badSpineUse = true
						return false
					}
					allowedSpineSels[spSel], allowedRecvIdents[rID] = true, true
				case "Store", "Swap":
					if len(call.Args) != 1 {
						badSpineUse = true
						return false
					}
					allowedSpineSels[spSel], allowedRecvIdents[rID], mutatesSpine = true, true, true
				case "CompareAndSwap":
					if len(call.Args) != 2 {
						badSpineUse = true
						return false
					}
					allowedSpineSels[spSel], allowedRecvIdents[rID], mutatesSpine = true, true, true
				default:
					badSpineUse = true
					return false
				}
				return true
			})
			if !badSpineUse {
				walkNonSelectorPropIdents(mFn.Body, func(id *ast.Ident) {
					if id.Name == mRecv && !allowedRecvIdents[id] {
						badSpineUse = true
					}
				})
			}
			if badSpineUse {
				cand.valid = false
				break
			}
			if mutatesSpine {
				cand.mutatorMethods[mName] = true
				continue
			}
			if funcHasUnnamedResults(mFn.Type, 1) && !bodyHasControlFlowOrRecoverBypass(mFn.Body) && len(mFn.Body.List) >= 2 {
				as0, okA := mFn.Body.List[0].(*ast.AssignStmt)
				ifs1, okI := mFn.Body.List[1].(*ast.IfStmt)
				if okA && as0.Tok == token.DEFINE && len(as0.Lhs) == 1 && len(as0.Rhs) == 1 && okI && ifs1.Init == nil && ifs1.Else == nil && len(ifs1.Body.List) == 1 {
					if vID, okV := unwrapParens(as0.Lhs[0]).(*ast.Ident); okV && vID.Name != "" && vID.Name != "_" {
						if _, okSP := isZeroArgMethodCallOnSelector(as0.Rhs[0], mRecv, spineField, "Load"); okSP {
							leftCond := ifs1.Cond
							for {
								orBin, okOr := unwrapParens(leftCond).(*ast.BinaryExpr)
								if !okOr || orBin.Op != token.LOR {
									break
								}
								leftCond = orBin.X
							}
							if condChecksEqErr(leftCond, vID.Name) {
								if rNil, okRN := ifs1.Body.List[0].(*ast.ReturnStmt); okRN && len(rNil.Results) == 1 {
									if _, okNil := isIdentNamed(rNil.Results[0], "nil"); okNil {
										cand.readNilMethods[mName] = true
									}
								}
							}
						}
					}
				}
			}
		}
		if !cand.valid {
			continue
		}
		for {
			mProp := false
			for mName, callees := range methodCalleeMap {
				if cand.mutatorMethods[mName] {
					continue
				}
				for callee := range callees {
					if cand.mutatorMethods[callee] {
						cand.mutatorMethods[mName] = true
						delete(cand.readNilMethods, mName)
						mProp = true
						break
					}
				}
			}
			if !mProp {
				break
			}
		}
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				if !cand.valid || n == nil {
					return false
				}
				if sel, okS := n.(*ast.SelectorExpr); okS && sel.Sel.Name == spineField && !allowedSpineSels[sel] {
					cand.valid = false
					return false
				}
				return true
			})
		}
		if cand.valid {
			tableStructs[sName] = cand
		}
	}

	varCands := map[string]osInactiveTableVar{}
	for vName, sp := range idx.zeroInitPkgVars {
		vFile := idx.pkgVarFiles[vName]
		if ast.IsExported(vName) || len(sp.Names) != 1 || sp.Type == nil {
			continue
		}
		if sName := baseTypeIdentName(sp.Type); sName != "" && !ast.IsExported(sName) && !k.fileImportNames[vFile][sName] {
			varCands[vName] = osInactiveTableVar{name: vName, structName: sName, declIdent: sp.Names[0]}
		}
	}

	candAllowedByName := map[string]map[*ast.Ident]bool{}
	candSitesByTable := map[string][]osTableMutSite{}
	for vName, vc := range varCands {
		ts := tableStructs[vc.structName]
		if ts == nil || idx.pkgDeclCounts[vName] != 1 || anyLinknameLocals[vName] {
			continue
		}
		allowedIdents := map[*ast.Ident]bool{vc.declIdent: true}
		var sites []osTableMutSite
		badUse := false
		for _, f := range files {
			if k.fileImportNames[f][vName] {
				badUse = true
				break
			}
			for _, decl := range f.Decls {
				fn, okF := decl.(*ast.FuncDecl)
				if !okF || fn.Body == nil {
					continue
				}
				if funcShadowsAnyIdent(fn, map[string]bool{vName: true}) {
					badUse = true
					break
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if badUse || n == nil {
						return false
					}
					if u, okU := n.(*ast.UnaryExpr); okU && u.Op == token.AND {
						ast.Inspect(u.X, func(un ast.Node) bool {
							if id, okID := un.(*ast.Ident); okID && id.Name == vName {
								badUse = true
								return false
							}
							return !badUse
						})
						if badUse {
							return false
						}
					}
					if sel, okS := n.(*ast.SelectorExpr); okS && ts.nonSpineFields[sel.Sel.Name] {
						if bID, okID := unwrapParens(sel.X).(*ast.Ident); okID && bID.Name == vName {
							allowedIdents[bID] = true
						}
					}
					call, okC := n.(*ast.CallExpr)
					if !okC || call.Ellipsis.IsValid() {
						return true
					}
					sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr)
					if !okS {
						return true
					}
					bID, okID := unwrapParens(sel.X).(*ast.Ident)
					if !okID || bID.Name != vName {
						return true
					}
					if ts.methods[sel.Sel.Name] == nil {
						badUse = true
						return false
					}
					if ts.mutatorMethods[sel.Sel.Name] {
						if fn.Recv == nil && fn.Name != nil && fn.Name.Name == "init" {
							badUse = true
							return false
						}
						sites = append(sites, osTableMutSite{fn: fn, call: call})
					}
					allowedIdents[bID] = true
					return true
				})
				if badUse {
					break
				}
			}
			if badUse {
				break
			}
		}
		if !badUse {
			candAllowedByName[vName] = allowedIdents
			candSitesByTable[vName] = sites
		}
	}
	leakedTableNames := filterNonSelPropIdentsInSet(files, candAllowedByName)
	for vName := range candAllowedByName {
		if !leakedTableNames[vName] {
			activeTables[vName] = varCands[vName]
			mutSitesByTable[vName] = candSitesByTable[vName]
		}
	}
	return tableStructs, activeTables, mutSitesByTable
}

func discoverOSPureIndexHelpers(k *PackageInactiveKernel, idx *PackageASTIndex, files []*ast.File, anyLinknameLocals map[string]bool) map[string]bool {
	pureIndexHelpers := map[string]bool{}
	if k == nil || idx == nil || k.hasDotImport || k.builtinsShadowed {
		return pureIndexHelpers
	}
	constDeclNames := map[string]bool{}
	for _, f := range files {
		for _, decl := range f.Decls {
			if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.CONST {
				for _, spec := range gd.Specs {
					if vs, okV := spec.(*ast.ValueSpec); okV {
						for _, id := range vs.Names {
							if id.Name != "_" {
								constDeclNames[id.Name] = true
							}
						}
					}
				}
			}
		}
	}

	for hName, fn := range idx.topFuncs {
		if ast.IsExported(hName) || idx.pkgDeclCounts[hName] != 1 || anyLinknameLocals[hName] || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			continue
		}
		if !funcHasUnnamedResults(fn.Type, 2) || len(fn.Type.Results.List) != 2 {
			continue
		}
		r0ID, okR0 := unwrapParens(fn.Type.Results.List[0].Type).(*ast.Ident)
		_, okR1 := isIdentNamed(fn.Type.Results.List[1].Type, "bool")
		if !okR0 || !okR1 || !osAllowedPureIntConversions[r0ID.Name] || idx.pkgDeclCounts[r0ID.Name] != 0 || k.IdentShadowedInFunc(fn, r0ID.Name) || k.IdentShadowedInFunc(fn, "bool") {
			continue
		}
		hParams := paramNamesFlat(fn.Type.Params)
		if len(hParams) != 1 || hParams[0] == "" || hParams[0] == "_" {
			continue
		}
		hFile := idx.funcFile[fn]

		var isPureIdxExpr func(expr ast.Expr, scope map[string]bool) bool
		isPureIdxExpr = func(expr ast.Expr, scope map[string]bool) bool {
			if expr == nil {
				return false
			}
			switch x := unwrapParens(expr).(type) {
			case *ast.BasicLit:
				return true
			case *ast.Ident:
				if x.Name == hParams[0] || scope[x.Name] {
					return true
				}
				if x.Name == "true" || x.Name == "false" || x.Name == "nil" {
					return idx.pkgDeclCounts[x.Name] == 0 && !k.IdentShadowedInFunc(fn, x.Name)
				}
				return constDeclNames[x.Name] && idx.pkgDeclCounts[x.Name] == 1 && !anyLinknameLocals[x.Name] && !k.IdentShadowedInFunc(fn, x.Name)
			case *ast.SelectorExpr:
				return k.isPureParamFieldChain(hParams[0], x)
			case *ast.UnaryExpr:
				switch x.Op {
				case token.ADD, token.SUB, token.NOT, token.XOR:
					return isPureIdxExpr(x.X, scope)
				}
			case *ast.BinaryExpr:
				switch x.Op {
				case token.ADD, token.SUB, token.MUL, token.QUO, token.REM,
					token.AND, token.OR, token.XOR, token.AND_NOT, token.SHL, token.SHR,
					token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ,
					token.LAND, token.LOR:
					return isPureIdxExpr(x.X, scope) && isPureIdxExpr(x.Y, scope)
				}
			case *ast.CallExpr:
				if x.Ellipsis.IsValid() || len(x.Args) != 1 || !isPureIdxExpr(x.Args[0], scope) {
					return false
				}
				if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
					return osAllowedPureIntConversions[cID.Name] && idx.pkgDeclCounts[cID.Name] == 0 && !k.IdentShadowedInFunc(fn, cID.Name) && !scope[cID.Name] && cID.Name != hParams[0]
				}
				if cSel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
					uID, okU := unwrapParens(cSel.X).(*ast.Ident)
					if !okU || (cSel.Sel.Name != "Pointer" && cSel.Sel.Name != "Sizeof" && cSel.Sel.Name != "Alignof") {
						return false
					}
					return k.FileImportPath(hFile, uID.Name) == "unsafe" && !funcShadowsAnyIdent(fn, map[string]bool{uID.Name: true}) && !scope[uID.Name] && hParams[0] != uID.Name
				}
			}
			return false
		}

		isPureIdxAssign := func(as *ast.AssignStmt, scope map[string]bool) bool {
			if as == nil || len(as.Lhs) == 0 || len(as.Lhs) != len(as.Rhs) {
				return false
			}
			for _, rhs := range as.Rhs {
				if !isPureIdxExpr(rhs, scope) {
					return false
				}
			}
			switch as.Tok {
			case token.DEFINE:
				added := map[string]bool{}
				for _, lhs := range as.Lhs {
					id, okID := unwrapParens(lhs).(*ast.Ident)
					if !okID || id.Name == "" || id.Name == hParams[0] {
						return false
					}
					if id.Name == "_" {
						continue
					}
					if scope[id.Name] || added[id.Name] {
						return false
					}
					added[id.Name] = true
				}
				maps.Copy(scope, added)
				return true
			case token.ASSIGN, token.ADD_ASSIGN, token.SUB_ASSIGN, token.MUL_ASSIGN, token.QUO_ASSIGN, token.REM_ASSIGN,
				token.AND_ASSIGN, token.OR_ASSIGN, token.XOR_ASSIGN, token.SHL_ASSIGN, token.SHR_ASSIGN, token.AND_NOT_ASSIGN:
				for _, lhs := range as.Lhs {
					id, okID := unwrapParens(lhs).(*ast.Ident)
					if !okID || id.Name == "" || id.Name == hParams[0] || (id.Name != "_" && !scope[id.Name]) {
						return false
					}
				}
				return true
			}
			return false
		}

		var isPureIdxBlock func(stmts []ast.Stmt, parentScope map[string]bool) bool
		isPureIdxBlock = func(stmts []ast.Stmt, parentScope map[string]bool) bool {
			scope := maps.Clone(parentScope)
			for _, stmt := range stmts {
				switch s := stmt.(type) {
				case *ast.BlockStmt:
					if !isPureIdxBlock(s.List, scope) {
						return false
					}
				case *ast.ReturnStmt:
					if len(s.Results) != 2 || !isPureIdxExpr(s.Results[0], scope) || !isPureIdxExpr(s.Results[1], scope) {
						return false
					}
				case *ast.IfStmt:
					ifScope := maps.Clone(scope)
					if s.Init != nil {
						initAs, okA := s.Init.(*ast.AssignStmt)
						if !okA || initAs.Tok != token.DEFINE || !isPureIdxAssign(initAs, ifScope) {
							return false
						}
					}
					if !isPureIdxExpr(s.Cond, ifScope) || !isPureIdxBlock(s.Body.List, ifScope) {
						return false
					}
					if s.Else != nil {
						switch el := s.Else.(type) {
						case *ast.BlockStmt:
							if !isPureIdxBlock(el.List, ifScope) {
								return false
							}
						case *ast.IfStmt:
							if !isPureIdxBlock([]ast.Stmt{el}, ifScope) {
								return false
							}
						default:
							return false
						}
					}
				case *ast.DeclStmt:
					gd, okG := s.Decl.(*ast.GenDecl)
					if !okG || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
						return false
					}
					for _, spec := range gd.Specs {
						vs, okV := spec.(*ast.ValueSpec)
						if !okV || len(vs.Names) == 0 || (len(vs.Values) != 0 && len(vs.Values) != len(vs.Names)) || (gd.Tok == token.CONST && len(vs.Values) != len(vs.Names)) {
							return false
						}
						if vs.Type != nil {
							tID, okT := unwrapParens(vs.Type).(*ast.Ident)
							if !okT || (!osAllowedPureIntConversions[tID.Name] && tID.Name != "bool") || idx.pkgDeclCounts[tID.Name] != 0 || k.IdentShadowedInFunc(fn, tID.Name) || scope[tID.Name] || tID.Name == hParams[0] {
								return false
							}
						}
						for _, val := range vs.Values {
							if !isPureIdxExpr(val, scope) {
								return false
							}
						}
						added := map[string]bool{}
						for _, id := range vs.Names {
							if id.Name == "" || id.Name == hParams[0] {
								return false
							}
							if id.Name == "_" {
								continue
							}
							if scope[id.Name] || added[id.Name] {
								return false
							}
							added[id.Name] = true
						}
						maps.Copy(scope, added)
					}
				case *ast.AssignStmt:
					if !isPureIdxAssign(s, scope) {
						return false
					}
				default:
					return false
				}
			}
			return true
		}

		if isPureIdxBlock(fn.Body.List, map[string]bool{}) {
			pureIndexHelpers[hName] = true
		}
	}
	return pureIndexHelpers
}
