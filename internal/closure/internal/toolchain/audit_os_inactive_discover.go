package toolchain

import (
	"go/ast"
	"go/token"
	"maps"
	"strconv"
	"strings"
)

type osFalseHelperKey struct {
	name    string
	arity   int
	boolIdx int
}

var osAllowedPureIntConversions = map[string]bool{
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
}

type osInactiveState struct {
	pkgDeclCounts       map[string]int
	funcFile            map[*ast.FuncDecl]*ast.File
	fileImportNames     map[*ast.File]map[string]bool
	falseConsts         map[string]bool
	trueConsts          map[string]bool
	osGateFuncs         map[string]string
	nilAccessors        map[string][]string
	falsePreds          map[string][]string
	falseHandledHelpers map[osFalseHelperKey][]string
}

func (s *osInactiveState) identShadowedInFunc(fn *ast.FuncDecl, name string) bool {
	if s == nil {
		return true
	}
	if funcShadowsAnyIdent(fn, map[string]bool{name: true}) {
		return true
	}
	if fn != nil && s.fileImportNames[s.funcFile[fn]][name] {
		return true
	}
	return false
}

type osFalseEvalEnv[D any] struct {
	st          *osInactiveState
	zeroDep     func() D
	gateDep     func(rtGate string) D
	falsePred   func(name string) (D, bool)
	nilAccessor func(name string) (D, bool)
	merge       func(a, b D) D
}

func evalOSFalseExpr[D any](env osFalseEvalEnv[D], expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) (D, bool) {
	var zero D
	if env.st == nil {
		return zero, false
	}
	expr = unwrapParens(expr)
	if id, okID := expr.(*ast.Ident); okID {
		if id.Name == "false" && env.st.pkgDeclCounts["false"] == 0 && !env.st.identShadowedInFunc(fn, "false") {
			return env.zeroDep(), true
		}
		if env.st.falseConsts[id.Name] && !env.st.identShadowedInFunc(fn, id.Name) {
			return env.zeroDep(), true
		}
		return zero, false
	}
	if call, okC := expr.(*ast.CallExpr); okC && !call.Ellipsis.IsValid() {
		if cID, okID := unwrapParens(call.Fun).(*ast.Ident); okID && !env.st.identShadowedInFunc(fn, cID.Name) {
			if len(call.Args) == 0 {
				if rtGate, okG := env.st.osGateFuncs[cID.Name]; okG {
					return env.gateDep(rtGate), true
				}
			}
			if len(call.Args) == 1 && env.st.isPureChain(call.Args[0], fn, params) {
				if d, okFP := env.falsePred(cID.Name); okFP {
					return d, true
				}
			}
		}
	}
	if bin, okB := expr.(*ast.BinaryExpr); okB {
		switch bin.Op {
		case token.NEQ:
			checkNilAccCall := func(callSide, nilSide ast.Expr) (D, bool) {
				if _, okNil := isIdentNamed(nilSide, "nil"); !okNil || env.st.pkgDeclCounts["nil"] != 0 || env.st.identShadowedInFunc(fn, "nil") {
					return zero, false
				}
				c, okC := unwrapParens(callSide).(*ast.CallExpr)
				if !okC || c.Ellipsis.IsValid() || len(c.Args) != 1 || !env.st.isPureChain(c.Args[0], fn, params) {
					return zero, false
				}
				cID, okID := unwrapParens(c.Fun).(*ast.Ident)
				if !okID || env.st.identShadowedInFunc(fn, cID.Name) {
					return zero, false
				}
				return env.nilAccessor(cID.Name)
			}
			if d, okL := checkNilAccCall(bin.X, bin.Y); okL {
				return d, true
			}
			if d, okR := checkNilAccCall(bin.Y, bin.X); okR {
				return d, true
			}
		case token.LAND:
			if dL, okL := evalOSFalseExpr(env, bin.X, fn, params); okL {
				return dL, true
			}
			if env.st.isPureGuardExpr(bin.X, fn, params) {
				return evalOSFalseExpr(env, bin.Y, fn, params)
			}
		case token.LOR:
			dL, okL := evalOSFalseExpr(env, bin.X, fn, params)
			if !okL {
				return zero, false
			}
			dR, okR := evalOSFalseExpr(env, bin.Y, fn, params)
			if !okR {
				return zero, false
			}
			return env.merge(dL, dR), true
		}
	}
	return zero, false
}

func discoverOSInactiveState(idx *PackageASTIndex, files []*ast.File, osRuntimePullMap map[string]string, osAnyLinknameLocals map[string]bool) *osInactiveState {
	var pkgDeclCounts map[string]int
	var funcFile map[*ast.FuncDecl]*ast.File
	var fileImportNames map[*ast.File]map[string]bool
	var topFuncs map[string]*ast.FuncDecl
	haveIdx := idx != nil
	if haveIdx {
		pkgDeclCounts = idx.pkgDeclCounts
		funcFile = idx.funcFile
		fileImportNames = idx.fileImportNames
		topFuncs = idx.topFuncs
	} else {
		pkgDeclCounts = map[string]int{}
		funcFile = map[*ast.FuncDecl]*ast.File{}
		fileImportNames = map[*ast.File]map[string]bool{}
		topFuncs = map[string]*ast.FuncDecl{}
	}
	st := &osInactiveState{
		pkgDeclCounts:       pkgDeclCounts,
		funcFile:            funcFile,
		fileImportNames:     fileImportNames,
		falseConsts:         map[string]bool{},
		trueConsts:          map[string]bool{},
		osGateFuncs:         map[string]string{},
		nilAccessors:        map[string][]string{},
		falsePreds:          map[string][]string{},
		falseHandledHelpers: map[osFalseHelperKey][]string{},
	}

	constDeclNames := map[string]bool{}
	falseConstCand := map[string]bool{}
	trueConstCand := map[string]bool{}
	badBoolConst := map[string]bool{}
	fileImportsAtomic := map[*ast.File]bool{}
	fileImportsSync := map[*ast.File]bool{}
	fileImportsRuntime := map[*ast.File]bool{}
	fileImportsUnsafe := map[*ast.File]bool{}
	badSpecialImport := map[*ast.File]map[string]bool{}

	type tableStructCand struct {
		name           string
		spineField     string
		nonSpineFields map[string]bool
		methods        map[string]*ast.FuncDecl
		readNilMethods map[string]bool
		mutatorMethods map[string]bool
		valid          bool
	}
	structSpecs := map[string]*ast.TypeSpec{}
	structFiles := map[string]*ast.File{}
	if haveIdx {
		for sName, sp := range idx.nonAliasStructSpec {
			if !ast.IsExported(sName) {
				structSpecs[sName] = sp
				structFiles[sName] = idx.typeSpecFile[sp]
			}
		}
	}

	type tableVarCand struct {
		name       string
		structName string
		declIdent  *ast.Ident
	}
	varCands := map[string]tableVarCand{}

	for _, f := range files {
		if !haveIdx {
			fileImportNames[f] = map[string]bool{}
		}
		badSpecialImport[f] = map[string]bool{}
		for _, imp := range f.Imports {
			if imp.Name != nil && imp.Name.Name == "." {
				return st
			}
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return st
			}
			if imp.Name != nil {
				if imp.Name.Name != "_" {
					if !haveIdx {
						fileImportNames[f][imp.Name.Name] = true
					}
					badSpecialImport[f][imp.Name.Name] = true
				}
				continue
			}
			base := p
			if slash := strings.LastIndexByte(p, '/'); slash >= 0 {
				base = p[slash+1:]
			}
			if !haveIdx {
				fileImportNames[f][base] = true
			}
			switch p {
			case "sync/atomic":
				fileImportsAtomic[f] = true
			case "sync":
				fileImportsSync[f] = true
			case "runtime":
				fileImportsRuntime[f] = true
			case "unsafe":
				fileImportsUnsafe[f] = true
			default:
				if base == "atomic" || base == "sync" || base == "runtime" || base == "unsafe" {
					badSpecialImport[f][base] = true
				}
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for idxSpec, id := range sp.Names {
							if id.Name == "_" {
								continue
							}
							if !haveIdx {
								pkgDeclCounts[id.Name]++
							}
							if d.Tok == token.CONST {
								constDeclNames[id.Name] = true
								if sp.Type == nil && idxSpec < len(sp.Values) {
									if vID, okID := unwrapParens(sp.Values[idxSpec]).(*ast.Ident); okID {
										switch vID.Name {
										case "false":
											if !fileImportNames[f]["false"] {
												falseConstCand[id.Name] = true
											} else {
												badBoolConst[id.Name] = true
											}
										case "true":
											if !fileImportNames[f]["true"] {
												trueConstCand[id.Name] = true
											} else {
												badBoolConst[id.Name] = true
											}
										default:
											badBoolConst[id.Name] = true
										}
									} else {
										badBoolConst[id.Name] = true
									}
								} else {
									badBoolConst[id.Name] = true
								}
							}
							if d.Tok == token.VAR && !ast.IsExported(id.Name) && len(sp.Names) == 1 && len(sp.Values) == 0 && sp.Type != nil {
								if sName := baseTypeIdentName(sp.Type); sName != "" && !ast.IsExported(sName) && !fileImportNames[f][sName] {
									varCands[id.Name] = tableVarCand{name: id.Name, structName: sName, declIdent: id}
								}
							}
						}
					case *ast.TypeSpec:
						if !haveIdx && sp.Name != nil && sp.Name.Name != "_" {
							pkgDeclCounts[sp.Name.Name]++
							if !ast.IsExported(sp.Name.Name) && !sp.Assign.IsValid() {
								if _, okST := unwrapParens(sp.Type).(*ast.StructType); okST {
									structSpecs[sp.Name.Name] = sp
									structFiles[sp.Name.Name] = f
								}
							}
						}
					}
				}
			case *ast.FuncDecl:
				if !haveIdx {
					funcFile[d] = f
					if d.Recv == nil && d.Name != nil && d.Name.Name != "init" && d.Name.Name != "_" {
						pkgDeclCounts[d.Name.Name]++
						topFuncs[d.Name.Name] = d
					}
				}
			}
		}
	}

	if pkgDeclCounts["false"] == 0 && pkgDeclCounts["true"] == 0 && pkgDeclCounts["bool"] == 0 {
		for name := range falseConstCand {
			if !badBoolConst[name] && !trueConstCand[name] && pkgDeclCounts[name] == 1 && !osAnyLinknameLocals[name] {
				st.falseConsts[name] = true
			}
		}
		for name := range trueConstCand {
			if !badBoolConst[name] && !falseConstCand[name] && pkgDeclCounts[name] == 1 && !osAnyLinknameLocals[name] {
				st.trueConsts[name] = true
			}
		}
	}

	for gName, fn := range topFuncs {
		if ast.IsExported(gName) || pkgDeclCounts[gName] != 1 || fn.Type == nil || fn.Type.TypeParams != nil {
			continue
		}
		if fn.Type.Params != nil && fn.Type.Params.NumFields() != 0 {
			continue
		}
		if !funcHasUnnamedResults(fn.Type, 1) || len(fn.Type.Results.List) != 1 {
			continue
		}
		if _, okBool := isIdentNamed(fn.Type.Results.List[0].Type, "bool"); !okBool || pkgDeclCounts["bool"] != 0 || st.identShadowedInFunc(fn, "bool") {
			continue
		}
		if fn.Body == nil {
			if rtTarget := osRuntimePullMap[gName]; strings.HasPrefix(rtTarget, "runtime.") {
				st.osGateFuncs[gName] = rtTarget
			}
			continue
		}
		if osAnyLinknameLocals[gName] || st.identShadowedInFunc(fn, "false") || bodyHasControlFlowOrRecoverBypass(fn.Body) || len(fn.Body.List) != 1 {
			continue
		}
		if ret, okR := fn.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
			if rID, okID := unwrapParens(ret.Results[0]).(*ast.Ident); okID {
				if (rID.Name == "false" && pkgDeclCounts["false"] == 0) || (st.falseConsts[rID.Name] && !st.identShadowedInFunc(fn, rID.Name)) {
					st.osGateFuncs[gName] = ""
				}
			}
		}
	}

	// Discover generic/concrete atomic-spine state tables (e.g. struct holding an unexported atomic.Pointer[...] spine).
	allowedBasicFieldTypes := map[string]bool{
		"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
		"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
		"bool": true, "string": true, "byte": true,
	}
	isSafeNonSpineFieldType := func(sFile *ast.File, expr ast.Expr) bool {
		switch t := unwrapParens(expr).(type) {
		case *ast.ArrayType, *ast.MapType:
			return true
		case *ast.Ident:
			return allowedBasicFieldTypes[t.Name] && pkgDeclCounts[t.Name] == 0 && !fileImportNames[sFile][t.Name]
		case *ast.SelectorExpr:
			if t.Sel.Name != "Mutex" && t.Sel.Name != "RWMutex" {
				return false
			}
			_, okSync := isIdentNamed(t.X, "sync")
			return okSync && fileImportsSync[sFile] && !badSpecialImport[sFile]["sync"] && pkgDeclCounts["sync"] == 0
		default:
			return false
		}
	}
	tableStructs := map[string]*tableStructCand{}
	for sName, sp := range structSpecs {
		sFile := structFiles[sName]
		if pkgDeclCounts[sName] != 1 || pkgDeclCounts["atomic"] != 0 || !fileImportsAtomic[sFile] || badSpecialImport[sFile]["atomic"] {
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
		cand := &tableStructCand{
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
				if !okF || fn.Recv == nil || len(fn.Recv.List) != 1 {
					continue
				}
				if RecvBaseTypeName(fn.Recv.List[0].Type) != sName {
					continue
				}
				if fileImportNames[f][sName] {
					cand.valid = false
					break
				}
				_, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr)
				if !isPtr || fn.Body == nil || fn.Name == nil || osAnyLinknameLocals[fn.Name.Name] || cand.nonSpineFields[fn.Name.Name] || fn.Name.Name == spineField {
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
		// Ensure spineField is accessed exclusively via pointer-receiver methods on sName using atomic Pointer methods,
		// and receiver pointers never escape or take field addresses.
		allowedSpineSels := map[*ast.SelectorExpr]bool{}
		methodCalleeMap := map[string]map[string]bool{}
		for mName, mFn := range cand.methods {
			mRecv := recvVarName(mFn)
			if mRecv == "" || pkgDeclCounts["nil"] != 0 || st.identShadowedInFunc(mFn, "nil") || bodyDeclaresAnyIdent(mFn.Body, map[string]bool{mRecv: true}) {
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
					allowedSpineSels[spSel] = true
					allowedRecvIdents[rID] = true
				case "Store", "Swap":
					if len(call.Args) != 1 {
						badSpineUse = true
						return false
					}
					allowedSpineSels[spSel] = true
					allowedRecvIdents[rID] = true
					mutatesSpine = true
				case "CompareAndSwap":
					if len(call.Args) != 2 {
						badSpineUse = true
						return false
					}
					allowedSpineSels[spSel] = true
					allowedRecvIdents[rID] = true
					mutatesSpine = true
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
			// Check whether read-only method returns nil immediately when spine.Load() == nil.
			if funcHasUnnamedResults(mFn.Type, 1) && !bodyHasControlFlowOrRecoverBypass(mFn.Body) && len(mFn.Body.List) >= 2 {
				as0, okA := mFn.Body.List[0].(*ast.AssignStmt)
				ifs1, okI := mFn.Body.List[1].(*ast.IfStmt)
				if okA && as0.Tok == token.DEFINE && len(as0.Lhs) == 1 && len(as0.Rhs) == 1 && okI && ifs1.Init == nil && ifs1.Else == nil && len(ifs1.Body.List) == 1 {
					vID, okV := unwrapParens(as0.Lhs[0]).(*ast.Ident)
					if okV && vID.Name != "" && vID.Name != "_" {
						if lCall, okLC := unwrapParens(as0.Rhs[0]).(*ast.CallExpr); okLC && !lCall.Ellipsis.IsValid() && len(lCall.Args) == 0 {
							if lSel, okLS := unwrapParens(lCall.Fun).(*ast.SelectorExpr); okLS && lSel.Sel.Name == "Load" {
								if _, okSP := isSelectorBaseField(lSel.X, mRecv, spineField); okSP {
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

	type mutCallSite struct {
		fn   *ast.FuncDecl
		call *ast.CallExpr
	}
	activeTables := map[string]tableVarCand{}
	mutSitesByTable := map[string][]mutCallSite{}
	candAllowedByName := map[string]map[*ast.Ident]bool{}
	candSitesByTable := map[string][]mutCallSite{}
	for vName, vc := range varCands {
		ts := tableStructs[vc.structName]
		if ts == nil || pkgDeclCounts[vName] != 1 || osAnyLinknameLocals[vName] {
			continue
		}
		allowedIdents := map[*ast.Ident]bool{vc.declIdent: true}
		var sites []mutCallSite
		badUse := false
		for _, f := range files {
			if fileImportNames[f][vName] {
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
						sites = append(sites, mutCallSite{fn: fn, call: call})
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

	pureIndexHelpers := map[string]bool{}
	for hName, fn := range topFuncs {
		if ast.IsExported(hName) || pkgDeclCounts[hName] != 1 || osAnyLinknameLocals[hName] || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			continue
		}
		if !funcHasUnnamedResults(fn.Type, 2) || len(fn.Type.Results.List) != 2 {
			continue
		}
		r0ID, okR0 := unwrapParens(fn.Type.Results.List[0].Type).(*ast.Ident)
		_, okR1 := isIdentNamed(fn.Type.Results.List[1].Type, "bool")
		if !okR0 || !okR1 || !osAllowedPureIntConversions[r0ID.Name] || pkgDeclCounts[r0ID.Name] != 0 || st.identShadowedInFunc(fn, r0ID.Name) || pkgDeclCounts["bool"] != 0 || st.identShadowedInFunc(fn, "bool") {
			continue
		}
		hParams := paramNamesFlat(fn.Type.Params)
		if len(hParams) != 1 || hParams[0] == "" || hParams[0] == "_" {
			continue
		}
		hFile := funcFile[fn]

		var isParamFieldChain func(expr ast.Expr) bool
		isParamFieldChain = func(expr ast.Expr) bool {
			switch e := unwrapParens(expr).(type) {
			case *ast.Ident:
				return e.Name == hParams[0]
			case *ast.SelectorExpr:
				return isParamFieldChain(e.X)
			default:
				return false
			}
		}

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
					return pkgDeclCounts[x.Name] == 0 && !st.identShadowedInFunc(fn, x.Name)
				}
				if constDeclNames[x.Name] && pkgDeclCounts[x.Name] == 1 && !osAnyLinknameLocals[x.Name] && !st.identShadowedInFunc(fn, x.Name) {
					return true
				}
				return false
			case *ast.SelectorExpr:
				return isParamFieldChain(x)
			case *ast.UnaryExpr:
				switch x.Op {
				case token.ADD, token.SUB, token.NOT, token.XOR:
					return isPureIdxExpr(x.X, scope)
				default:
					return false
				}
			case *ast.BinaryExpr:
				switch x.Op {
				case token.ADD, token.SUB, token.MUL, token.QUO, token.REM,
					token.AND, token.OR, token.XOR, token.AND_NOT, token.SHL, token.SHR,
					token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ,
					token.LAND, token.LOR:
					return isPureIdxExpr(x.X, scope) && isPureIdxExpr(x.Y, scope)
				default:
					return false
				}
			case *ast.CallExpr:
				if x.Ellipsis.IsValid() || len(x.Args) != 1 || !isPureIdxExpr(x.Args[0], scope) {
					return false
				}
				if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
					return osAllowedPureIntConversions[cID.Name] && pkgDeclCounts[cID.Name] == 0 && !st.identShadowedInFunc(fn, cID.Name) && !scope[cID.Name] && cID.Name != hParams[0]
				}
				if cSel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
					_, okU := isIdentNamed(cSel.X, "unsafe")
					if !okU || (cSel.Sel.Name != "Pointer" && cSel.Sel.Name != "Sizeof" && cSel.Sel.Name != "Alignof") {
						return false
					}
					return fileImportsUnsafe[hFile] && !badSpecialImport[hFile]["unsafe"] && pkgDeclCounts["unsafe"] == 0 && !funcShadowsAnyIdent(fn, map[string]bool{"unsafe": true}) && !scope["unsafe"] && hParams[0] != "unsafe"
				}
				return false
			default:
				return false
			}
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
				for name := range added {
					scope[name] = true
				}
				return true
			case token.ASSIGN, token.ADD_ASSIGN, token.SUB_ASSIGN, token.MUL_ASSIGN, token.QUO_ASSIGN, token.REM_ASSIGN,
				token.AND_ASSIGN, token.OR_ASSIGN, token.XOR_ASSIGN, token.SHL_ASSIGN, token.SHR_ASSIGN, token.AND_NOT_ASSIGN:
				for _, lhs := range as.Lhs {
					id, okID := unwrapParens(lhs).(*ast.Ident)
					if !okID || id.Name == "" || id.Name == hParams[0] {
						return false
					}
					if id.Name != "_" && !scope[id.Name] {
						return false
					}
				}
				return true
			default:
				return false
			}
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
						if !okV || len(vs.Names) == 0 || (len(vs.Values) != 0 && len(vs.Values) != len(vs.Names)) {
							return false
						}
						if gd.Tok == token.CONST && len(vs.Values) != len(vs.Names) {
							return false
						}
						if vs.Type != nil {
							tID, okT := unwrapParens(vs.Type).(*ast.Ident)
							if !okT || (!osAllowedPureIntConversions[tID.Name] && tID.Name != "bool") || pkgDeclCounts[tID.Name] != 0 || st.identShadowedInFunc(fn, tID.Name) || scope[tID.Name] || tID.Name == hParams[0] {
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
						for name := range added {
							scope[name] = true
						}
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

	type depPair struct {
		gates map[string]bool
		tabs  map[string]bool
	}
	cloneDep := func(d depPair) depPair {
		out := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
		for g := range d.gates {
			if g != "" {
				out.gates[g] = true
			}
		}
		for t := range d.tabs {
			out.tabs[t] = true
		}
		return out
	}
	mergeDep := func(dst *depPair, src depPair) bool {
		changed := false
		for g := range src.gates {
			if g != "" && !dst.gates[g] {
				dst.gates[g] = true
				changed = true
			}
		}
		for t := range src.tabs {
			if !dst.tabs[t] {
				dst.tabs[t] = true
				changed = true
			}
		}
		return changed
	}

	funcParamSet := func(fn *ast.FuncDecl) map[string]bool {
		out := map[string]bool{}
		if fn == nil {
			return out
		}
		if r := recvVarName(fn); r != "" {
			out[r] = true
		}
		for _, p := range paramNamesFlat(fn.Type.Params) {
			if p != "" && p != "_" {
				out[p] = true
			}
		}
		return out
	}

	type rule3CallSite struct {
		caller *ast.FuncDecl
		call   *ast.CallExpr
	}
	rule3CandFuncs := map[string]*ast.FuncDecl{}
	for fnName, fn := range topFuncs {
		if ast.IsExported(fnName) || pkgDeclCounts[fnName] != 1 || osAnyLinknameLocals[fnName] || fn.Body == nil {
			continue
		}
		shadowedByImport := false
		for _, f := range files {
			if fileImportNames[f][fnName] {
				shadowedByImport = true
				break
			}
		}
		if !shadowedByImport {
			rule3CandFuncs[fnName] = fn
		}
	}
	rule3CallSites := map[string][]rule3CallSite{}
	rule3AllowedIdents := map[string]map[*ast.Ident]bool{}
	for fnName, fn := range rule3CandFuncs {
		rule3AllowedIdents[fnName] = map[*ast.Ident]bool{fn.Name: true}
	}
	if len(rule3CandFuncs) > 0 {
		for _, f := range files {
			for _, decl := range f.Decls {
				caller, okF := decl.(*ast.FuncDecl)
				if !okF || caller.Body == nil {
					continue
				}
				ast.Inspect(caller.Body, func(n ast.Node) bool {
					call, okC := n.(*ast.CallExpr)
					if !okC {
						return true
					}
					cID, okID := unwrapParens(call.Fun).(*ast.Ident)
					if !okID || rule3CandFuncs[cID.Name] == nil {
						return true
					}
					rule3CallSites[cID.Name] = append(rule3CallSites[cID.Name], rule3CallSite{caller: caller, call: call})
					rule3AllowedIdents[cID.Name][cID] = true
					return true
				})
			}
		}
		leakedRule3 := filterNonSelPropIdentsInSet(files, rule3AllowedIdents)
		for fnName := range leakedRule3 {
			delete(rule3CandFuncs, fnName)
			delete(rule3CallSites, fnName)
		}
	}

	// Greatest fixpoint over activeTables: keep only tables whose mutator call sites are all gated/unreachable.
	var finalNilAcc, finalFalsePreds map[string]depPair
	var finalTableGates map[string]map[string]bool
	for {
		nilAcc := map[string]depPair{}
		falsePreds := map[string]depPair{}

		evalEnv := osFalseEvalEnv[depPair]{
			st: st,
			zeroDep: func() depPair {
				return depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
			},
			gateDep: func(rtGate string) depPair {
				d := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				if rtGate != "" {
					d.gates[rtGate] = true
				}
				return d
			},
			falsePred: func(name string) (depPair, bool) {
				fp, okFP := falsePreds[name]
				if !okFP {
					return depPair{}, false
				}
				return cloneDep(fp), true
			},
			nilAccessor: func(name string) (depPair, bool) {
				na, okNA := nilAcc[name]
				if !okNA {
					return depPair{}, false
				}
				return cloneDep(na), true
			},
			merge: func(a, b depPair) depPair {
				out := cloneDep(a)
				mergeDep(&out, b)
				return out
			},
		}
		evalFalse := func(expr ast.Expr, fn *ast.FuncDecl, params map[string]bool) (depPair, bool) {
			return evalOSFalseExpr(evalEnv, expr, fn, params)
		}

		// Inner least fixpoint for nilAcc & falsePreds under current activeTables.
		for {
			innerChanged := false
			for fnName, fn := range topFuncs {
				if ast.IsExported(fnName) || pkgDeclCounts[fnName] != 1 || osAnyLinknameLocals[fnName] || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
					continue
				}
				pNames := paramNamesFlat(fn.Type.Params)
				if len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" || !funcHasUnnamedResults(fn.Type, 1) || len(fn.Type.Results.List) != 1 {
					continue
				}
				pSet := map[string]bool{pNames[0]: true}
				if _, isBoolRes := isIdentNamed(fn.Type.Results.List[0].Type, "bool"); isBoolRes {
					if pkgDeclCounts["bool"] != 0 || st.identShadowedInFunc(fn, "bool") {
						continue
					}
					if _, already := falsePreds[fnName]; already || len(fn.Body.List) != 1 || st.identShadowedInFunc(fn, "nil") || st.identShadowedInFunc(fn, "false") || st.identShadowedInFunc(fn, "true") {
						continue
					}
					if ret, okR := fn.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
						if d, okF := evalFalse(ret.Results[0], fn, pSet); okF {
							falsePreds[fnName] = d
							innerChanged = true
						}
					}
					continue
				}
				if _, already := nilAcc[fnName]; already || pkgDeclCounts["nil"] != 0 || st.identShadowedInFunc(fn, "nil") || st.identShadowedInFunc(fn, "false") || st.identShadowedInFunc(fn, "true") {
					continue
				}
				fnFile := funcFile[fn]
				var proveBlockReturnsNil func(stmts []ast.Stmt, knownNil map[string]bool, declaredLocals map[string]bool, acc *depPair) bool
				proveBlockReturnsNil = func(stmts []ast.Stmt, knownNil map[string]bool, declaredLocals map[string]bool, acc *depPair) bool {
					for i := 0; i < len(stmts); i++ {
						switch s := stmts[i].(type) {
						case *ast.ReturnStmt:
							if len(s.Results) != 1 {
								return false
							}
							rID, okID := unwrapParens(s.Results[0]).(*ast.Ident)
							return okID && (rID.Name == "nil" || knownNil[rID.Name])
						case *ast.ExprStmt:
							kc, okKC := unwrapParens(s.X).(*ast.CallExpr)
							if !okKC || kc.Ellipsis.IsValid() || len(kc.Args) != 1 || !st.isPureChain(kc.Args[0], fn, pSet) {
								return false
							}
							if _, okKA := isSelectorBaseField(kc.Fun, "runtime", "KeepAlive"); !okKA {
								return false
							}
							if !fileImportsRuntime[fnFile] || badSpecialImport[fnFile]["runtime"] || pkgDeclCounts["runtime"] != 0 || funcShadowsAnyIdent(fn, map[string]bool{"runtime": true}) || declaredLocals["runtime"] {
								return false
							}
						case *ast.AssignStmt:
							if s.Tok == token.DEFINE && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
								vID, okV := unwrapParens(s.Lhs[0]).(*ast.Ident)
								c, okC := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
								if !okV || !okC || vID.Name == "" || vID.Name == "_" || declaredLocals[vID.Name] || c.Ellipsis.IsValid() || len(c.Args) != 1 {
									return false
								}
								if cID, okCID := unwrapParens(c.Fun).(*ast.Ident); okCID && !st.identShadowedInFunc(fn, cID.Name) && !declaredLocals[cID.Name] && st.isPureChain(c.Args[0], fn, pSet) {
									na, okNA := nilAcc[cID.Name]
									if !okNA {
										return false
									}
									mergeDep(acc, na)
									declaredLocals[vID.Name] = true
									knownNil[vID.Name] = true
									continue
								}
							}
							if s.Tok == token.DEFINE && len(s.Lhs) == 2 && len(s.Rhs) == 1 && i+2 < len(stmts) {
								idxID, okI0 := unwrapParens(s.Lhs[0]).(*ast.Ident)
								okVarID, okI1 := unwrapParens(s.Lhs[1]).(*ast.Ident)
								ic, okIC := unwrapParens(s.Rhs[0]).(*ast.CallExpr)
								if !okI0 || !okI1 || !okIC || idxID.Name == "" || idxID.Name == "_" || okVarID.Name == "" || okVarID.Name == "_" || idxID.Name == okVarID.Name || declaredLocals[idxID.Name] || declaredLocals[okVarID.Name] || ic.Ellipsis.IsValid() || len(ic.Args) != 1 || !st.isPureChain(ic.Args[0], fn, pSet) {
									return false
								}
								ihID, okIH := unwrapParens(ic.Fun).(*ast.Ident)
								if !okIH || !pureIndexHelpers[ihID.Name] || st.identShadowedInFunc(fn, ihID.Name) || declaredLocals[ihID.Name] {
									return false
								}
								guardIf, okGI := stmts[i+1].(*ast.IfStmt)
								getAs, okGA := stmts[i+2].(*ast.AssignStmt)
								if !okGI || guardIf.Init != nil || guardIf.Else != nil || len(guardIf.Body.List) != 1 || !okGA || getAs.Tok != token.DEFINE || len(getAs.Lhs) != 1 || len(getAs.Rhs) != 1 {
									return false
								}
								uNot, okUN := unwrapParens(guardIf.Cond).(*ast.UnaryExpr)
								gRet, okGR := guardIf.Body.List[0].(*ast.ReturnStmt)
								if !okUN || uNot.Op != token.NOT || !okGR || len(gRet.Results) != 1 {
									return false
								}
								_, okVarMatch := isIdentNamed(uNot.X, okVarID.Name)
								_, okRetNil := isIdentNamed(gRet.Results[0], "nil")
								if !okVarMatch || !okRetNil {
									return false
								}
								declaredLocals[idxID.Name] = true
								declaredLocals[okVarID.Name] = true
								sVarID, okSV := unwrapParens(getAs.Lhs[0]).(*ast.Ident)
								getCall, okGC := unwrapParens(getAs.Rhs[0]).(*ast.CallExpr)
								if !okSV || sVarID.Name == "" || sVarID.Name == "_" || declaredLocals[sVarID.Name] || !okGC || getCall.Ellipsis.IsValid() || len(getCall.Args) != 1 {
									return false
								}
								_, okIdxArg := isIdentNamed(getCall.Args[0], idxID.Name)
								getSel, okGS := unwrapParens(getCall.Fun).(*ast.SelectorExpr)
								if !okIdxArg || !okGS {
									return false
								}
								tabID, okTID := unwrapParens(getSel.X).(*ast.Ident)
								if !okTID || st.identShadowedInFunc(fn, tabID.Name) || declaredLocals[tabID.Name] {
									return false
								}
								vc, okTab := activeTables[tabID.Name]
								if !okTab || !tableStructs[vc.structName].readNilMethods[getSel.Sel.Name] {
									return false
								}
								acc.tabs[tabID.Name] = true
								declaredLocals[sVarID.Name] = true
								knownNil[sVarID.Name] = true
								i += 2
								continue
							}
							return false
						case *ast.IfStmt:
							if s.Else != nil {
								return false
							}
							if s.Init == nil {
								if d, okF := evalFalse(s.Cond, fn, pSet); okF {
									mergeDep(acc, d)
									continue
								}
								if nzVar := condChecksNonZeroErr(s.Cond); nzVar != "" && knownNil[nzVar] {
									continue
								}
								if condChecksEqErr(s.Cond, pNames[0]) && len(s.Body.List) == 1 {
									if r0, okR0 := s.Body.List[0].(*ast.ReturnStmt); okR0 && len(r0.Results) == 1 {
										if _, okN := isIdentNamed(r0.Results[0], "nil"); okN {
											continue
										}
									}
								}
								for kn := range knownNil {
									if condChecksEqErr(s.Cond, kn) {
										if proveBlockReturnsNil(s.Body.List, maps.Clone(knownNil), maps.Clone(declaredLocals), acc) {
											return true
										}
									}
								}
								return false
							}
							if initAs, okA := s.Init.(*ast.AssignStmt); okA && initAs.Tok == token.DEFINE && len(initAs.Lhs) == 1 && len(initAs.Rhs) == 1 {
								vID, okV := unwrapParens(initAs.Lhs[0]).(*ast.Ident)
								c, okC := unwrapParens(initAs.Rhs[0]).(*ast.CallExpr)
								if okV && okC && vID.Name != "" && vID.Name != "_" && vID.Name != "nil" && condChecksNonZeroErr(s.Cond) == vID.Name && !c.Ellipsis.IsValid() && len(c.Args) == 1 && st.isPureChain(c.Args[0], fn, pSet) {
									if cID, okCID := unwrapParens(c.Fun).(*ast.Ident); okCID && !st.identShadowedInFunc(fn, cID.Name) && !declaredLocals[cID.Name] {
										if na, okNA := nilAcc[cID.Name]; okNA {
											mergeDep(acc, na)
											continue
										}
									}
								}
							}
							return false
						default:
							return false
						}
					}
					return false
				}
				acc := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				if proveBlockReturnsNil(fn.Body.List, map[string]bool{}, map[string]bool{pNames[0]: true}, &acc) {
					nilAcc[fnName] = acc
					innerChanged = true
				}
			}
			if !innerChanged {
				break
			}
		}

		// Compute dead IfStmt branches & unreachableFuncs across files under (nilAcc, falsePreds).
		deadIfDeps := map[*ast.IfStmt]depPair{}
		for _, f := range files {
			for _, decl := range f.Decls {
				fn, okF := decl.(*ast.FuncDecl)
				if !okF || fn.Body == nil {
					continue
				}
				pSet := funcParamSet(fn)
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					ifs, okI := n.(*ast.IfStmt)
					if !okI {
						return true
					}
					if ifs.Init == nil && ifs.Else == nil && !bodyHasControlFlowOrRecoverBypass(ifs.Body) {
						if d, okF := evalFalse(ifs.Cond, fn, pSet); okF {
							deadIfDeps[ifs] = d
							return false
						}
					}
					return true
				})
			}
		}

		nodeDeadDep := func(fn *ast.FuncDecl, target ast.Node) (depPair, bool) {
			var found bool
			var out depPair
			var walk func(n ast.Node, cur *depPair)
			walk = func(n ast.Node, cur *depPair) {
				if found || n == nil {
					return
				}
				if n == target {
					if cur != nil {
						out = cloneDep(*cur)
						found = true
					}
					return
				}
				if ifs, okI := n.(*ast.IfStmt); okI {
					if d, okD := deadIfDeps[ifs]; okD {
						next := cloneDep(d)
						if cur != nil {
							mergeDep(&next, *cur)
						}
						for _, bs := range ifs.Body.List {
							walk(bs, &next)
						}
						return
					}
				}
				ast.Inspect(n, func(ch ast.Node) bool {
					if ch == n {
						return true
					}
					walk(ch, cur)
					return false
				})
			}
			walk(fn.Body, nil)
			return out, found
		}

		nodeContainsCall := func(root *ast.IfStmt, target *ast.CallExpr) bool {
			if root == nil || target == nil {
				return false
			}
			hit := false
			ast.Inspect(root, func(n ast.Node) bool {
				if n == target {
					hit = true
					return false
				}
				return !hit
			})
			return hit
		}

		unreachableFuncs := map[string]depPair{}
		seedRule1Head := map[string]*ast.IfStmt{}
		// Seed Rule 1: top-level concrete funcs whose first statement is `if !<falseCond> [|| ...] { return ... }`.
		for fnName, fn := range topFuncs {
			if pkgDeclCounts[fnName] != 1 || fn.Body == nil || len(fn.Body.List) == 0 {
				continue
			}
			ifs, okI := fn.Body.List[0].(*ast.IfStmt)
			if !okI || ifs.Init != nil || ifs.Else != nil || len(ifs.Body.List) != 1 || bodyHasControlFlowOrRecoverBypass(ifs.Body) {
				continue
			}
			if _, okRet := ifs.Body.List[0].(*ast.ReturnStmt); !okRet {
				continue
			}
			negTarget := ifs.Cond
			for {
				orBin, okOr := unwrapParens(negTarget).(*ast.BinaryExpr)
				if !okOr || orBin.Op != token.LOR {
					break
				}
				negTarget = orBin.X
			}
			if uNot, okU := unwrapParens(negTarget).(*ast.UnaryExpr); okU && uNot.Op == token.NOT {
				if d, okF := evalFalse(uNot.X, fn, nil); okF {
					unreachableFuncs[fnName] = d
					seedRule1Head[fnName] = ifs
				}
			}
		}

		// Seed/iterate Rule 3: unexported non-linknamed top-level funcs called exclusively from deadIfDeps or unreachableFuncs.
		for {
			uChanged := false
			for fnName := range rule3CandFuncs {
				if _, already := unreachableFuncs[fnName]; already {
					continue
				}
				agg := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
				allCovered := true
				for _, site := range rule3CallSites[fnName] {
					caller := site.caller
					if caller.Recv == nil {
						if callerUnreach, isCallerUnreach := unreachableFuncs[caller.Name.Name]; isCallerUnreach && !nodeContainsCall(seedRule1Head[caller.Name.Name], site.call) {
							mergeDep(&agg, callerUnreach)
							continue
						}
					}
					if dDead, okD := nodeDeadDep(caller, site.call); okD {
						mergeDep(&agg, dDead)
						continue
					}
					allCovered = false
					break
				}
				if allCovered {
					unreachableFuncs[fnName] = agg
					uChanged = true
				}
			}
			if !uChanged {
				break
			}
		}

		evicted := false
		curTableDeps := map[string]depPair{}
		for vName := range activeTables {
			agg := depPair{gates: map[string]bool{}, tabs: map[string]bool{}}
			covered := true
			for _, site := range mutSitesByTable[vName] {
				if site.fn.Recv == nil {
					if uDep, okU := unreachableFuncs[site.fn.Name.Name]; okU && !nodeContainsCall(seedRule1Head[site.fn.Name.Name], site.call) {
						mergeDep(&agg, uDep)
						continue
					}
				}
				if dDead, okD := nodeDeadDep(site.fn, site.call); okD {
					mergeDep(&agg, dDead)
					continue
				}
				covered = false
				break
			}
			if !covered {
				delete(activeTables, vName)
				evicted = true
				continue
			}
			curTableDeps[vName] = agg
		}
		if evicted {
			continue
		}

		// Propagate table-to-table dependencies to fixpoint and finalize gate sets.
		for {
			tChanged := false
			for vName, dp := range curTableDeps {
				for depTab := range dp.tabs {
					if other, okO := curTableDeps[depTab]; okO {
						for g := range other.gates {
							if !dp.gates[g] {
								dp.gates[g] = true
								tChanged = true
							}
						}
					}
				}
				curTableDeps[vName] = dp
			}
			if !tChanged {
				break
			}
		}
		finalTableGates = map[string]map[string]bool{}
		for vName, dp := range curTableDeps {
			finalTableGates[vName] = dp.gates
		}
		finalNilAcc = nilAcc
		finalFalsePreds = falsePreds
		break
	}

	resolveDepGates := func(dp depPair) []string {
		merged := map[string]bool{}
		for g := range dp.gates {
			if g != "" {
				merged[g] = true
			}
		}
		for t := range dp.tabs {
			for g := range finalTableGates[t] {
				if g != "" {
					merged[g] = true
				}
			}
		}
		out := sortedKeys(merged)
		if out == nil {
			out = make([]string, 0)
		}
		return out
	}

	for name, dp := range finalNilAcc {
		st.nilAccessors[name] = resolveDepGates(dp)
	}
	for name, dp := range finalFalsePreds {
		st.falsePreds[name] = resolveDepGates(dp)
	}

	// Discover unexported false-handled tuple helpers (e.g. `if ..., handled, ... := h(...); handled`).
	identShadowedAtHead := func(fn *ast.FuncDecl, name string) bool {
		return funcDeclaresParamOrResult(fn, name) || fileImportNames[funcFile[fn]][name]
	}
	isPureZeroResult := func(fn *ast.FuncDecl, expr ast.Expr) bool {
		expr = unwrapParens(expr)
		if id, okID := expr.(*ast.Ident); okID {
			if (id.Name == "nil" || id.Name == "false") && pkgDeclCounts[id.Name] == 0 && !identShadowedAtHead(fn, id.Name) {
				return true
			}
			if st.falseConsts[id.Name] && !identShadowedAtHead(fn, id.Name) {
				return true
			}
			return false
		}
		if isZeroIntLit(expr) {
			return true
		}
		if lit, okL := expr.(*ast.BasicLit); okL && lit.Kind == token.STRING && lit.Value == `""` {
			return true
		}
		return false
	}
	for hName, fn := range topFuncs {
		if ast.IsExported(hName) || pkgDeclCounts[hName] != 1 || osAnyLinknameLocals[hName] || fn.Body == nil || len(fn.Body.List) == 0 || fn.Type == nil || fn.Type.TypeParams != nil || fn.Type.Results == nil {
			continue
		}
		numRes := fn.Type.Results.NumFields()
		if numRes < 2 || pkgDeclCounts["false"] != 0 || pkgDeclCounts["bool"] != 0 || identShadowedAtHead(fn, "false") || identShadowedAtHead(fn, "nil") || identShadowedAtHead(fn, "bool") {
			continue
		}
		checkRetTuple := func(ret *ast.ReturnStmt, gates []string) {
			if len(ret.Results) != numRes {
				return
			}
			for idx, r := range ret.Results {
				rID, okID := unwrapParens(r).(*ast.Ident)
				if !okID || (rID.Name != "false" && (!st.falseConsts[rID.Name] || identShadowedAtHead(fn, rID.Name))) {
					continue
				}
				if _, okBool := isIdentNamed(funcResultFieldTypeAt(fn.Type.Results, idx), "bool"); !okBool {
					continue
				}
				othersZero := true
				for j, other := range ret.Results {
					if j != idx && !isPureZeroResult(fn, other) {
						othersZero = false
						break
					}
				}
				if othersZero {
					st.falseHandledHelpers[osFalseHelperKey{name: hName, arity: len(ret.Results), boolIdx: idx}] = gates
				}
			}
		}
		switch s0 := fn.Body.List[0].(type) {
		case *ast.ReturnStmt:
			checkRetTuple(s0, make([]string, 0))
		case *ast.IfStmt:
			if s0.Init == nil && s0.Else == nil && len(s0.Body.List) == 1 && !bodyHasControlFlowOrRecoverBypass(s0.Body) {
				if ret, okR := s0.Body.List[0].(*ast.ReturnStmt); okR {
					if uNot, okU := unwrapParens(s0.Cond).(*ast.UnaryExpr); okU && uNot.Op == token.NOT {
						if gates, okG := st.evalFalseCond(uNot.X, fn, nil); okG {
							checkRetTuple(ret, gates)
						}
					}
				}
			}
		}
	}

	return st
}
