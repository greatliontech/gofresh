package toolchain

import (
	"fmt"
	"go/ast"
	"go/token"
	"maps"
)

func verifyOSNologStatHelpers(
	allTopFuncs, allFileMethods, allRawFileMethods, allFileStatMethods map[string]*ast.FuncDecl,
	pkgDeclCounts, fileMethodCounts, rawFileMethodCounts, fileStatMethodCounts map[string]int,
	funcFile map[*ast.FuncDecl]*ast.File,
	fileImportsSyscall map[*ast.File]bool,
	osInactive *osInactiveState,
	osNoFileReserved, osAnyLinknameLocals map[string]bool,
	disjointAltStruct string,
	usedSameFile, usedFstatNolog, usedFileStatInGetwd bool,
	skipInactiveHookIf func(ast.Stmt, *ast.FuncDecl) bool,
) error {
	returnsFileInfoOrStat := func(fn *ast.FuncDecl) bool {
		if fn == nil || fn.Type == nil || fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
			return false
		}
		t0 := unwrapParens(fn.Type.Results.List[0].Type)
		if _, okFI := isIdentNamed(t0, "FileInfo"); okFI {
			return true
		}
		if star, okS := t0.(*ast.StarExpr); okS {
			if _, okFS := isIdentNamed(star.X, "fileStat"); okFS {
				return true
			}
		}
		return false
	}

	type statWorkItem struct {
		kind string // "top", "file", "raw", "filestat"
		name string
	}
	type statRootSpec struct {
		item       statWorkItem
		needKernel bool
		isFdStat   bool
	}
	roots := []statRootSpec{
		{item: statWorkItem{kind: "top", name: "statNolog"}, needKernel: true},
		{item: statWorkItem{kind: "top", name: "lstatNolog"}, needKernel: true},
	}
	if usedFstatNolog {
		roots = append(roots, statRootSpec{item: statWorkItem{kind: "top", name: "fstatNolog"}, needKernel: true, isFdStat: true})
	}
	if usedFileStatInGetwd {
		roots = append(roots, statRootSpec{item: statWorkItem{kind: "file", name: "Stat"}, needKernel: true, isFdStat: true})
	}
	if usedSameFile && allFileStatMethods["loadFileId"] != nil {
		roots = append(roots, statRootSpec{item: statWorkItem{kind: "filestat", name: "loadFileId"}, needKernel: false})
	}

	lookupStatCallable := func(it statWorkItem) (*ast.FuncDecl, bool) {
		switch it.kind {
		case "top":
			fn := allTopFuncs[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || pkgDeclCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			return fn, true
		case "file":
			fn := allFileMethods[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || fileMethodCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			if _, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr); !isPtr {
				return nil, false
			}
			return fn, true
		case "raw":
			fn := allRawFileMethods[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || rawFileMethodCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			if _, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr); !isPtr {
				return nil, false
			}
			return fn, true
		case "filestat":
			fn := allFileStatMethods[it.name]
			if fn == nil || fn.Body == nil || fn.Type == nil || fn.Recv == nil || len(fn.Recv.List) != 1 || fileStatMethodCounts[it.name] != 1 || osAnyLinknameLocals[it.name] {
				return nil, false
			}
			if _, isPtr := unwrapParens(fn.Recv.List[0].Type).(*ast.StarExpr); !isPtr {
				return nil, false
			}
			return fn, true
		default:
			return nil, false
		}
	}

	usedIgnoringEINTR := false
	for _, rootSpec := range roots {
		rootLabel := rootSpec.item.name
		if rootSpec.item.kind != "top" {
			rootLabel = rootSpec.item.kind + ":" + rootSpec.item.name
		}
		if _, okRoot := lookupStatCallable(rootSpec.item); !okRoot {
			return fmt.Errorf("os: missing or invalid %s helper", rootLabel)
		}
		visited := map[statWorkItem]bool{}
		queue := []statWorkItem{rootSpec.item}
		sawKernelStat := false

		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			if visited[cur] {
				continue
			}
			visited[cur] = true
			curLabel := cur.name
			if cur.kind != "top" {
				curLabel = cur.kind + ":" + cur.name
			}
			fn, okFn := lookupStatCallable(cur)
			if !okFn || funcShadowsAnyIdent(fn, map[string]bool{"testlog": true, "syscall": true, "nil": true, "fileStat": true}) {
				return fmt.Errorf("os: invalid %s stat helper %s", rootLabel, curLabel)
			}
			hPos := 0
			for hPos < len(fn.Body.List) && skipInactiveHookIf(fn.Body.List[hPos], fn) {
				hPos++
			}
			stmts := fn.Body.List[hPos:]
			if len(stmts) == 0 {
				return fmt.Errorf("os: %s helper %s has empty body", rootLabel, curLabel)
			}

			type statLocalBinding struct {
				isZeroFileStat bool
				sawFresh       bool
				bad            bool
			}
			identBinding := map[*ast.Ident]*statLocalBinding{}
			topScope := map[string]*statLocalBinding{}
			topSame := map[string]*statLocalBinding{}
			if r := recvVarName(fn); r != "" && r != "_" {
				b := &statLocalBinding{bad: true}
				topScope[r] = b
				topSame[r] = b
			}
			for _, p := range paramNamesFlat(fn.Type.Params) {
				if p != "" && p != "_" {
					b := &statLocalBinding{bad: true}
					topScope[p] = b
					topSame[p] = b
				}
			}
			if fn.Type.Results != nil {
				for _, fld := range fn.Type.Results.List {
					for _, id := range fld.Names {
						if id.Name != "" && id.Name != "_" {
							b := &statLocalBinding{sawFresh: true}
							topScope[id.Name] = b
							topSame[id.Name] = b
							identBinding[id] = b
						}
					}
				}
			}

			fileImports := map[string]bool(nil)
			if osInactive != nil {
				fileImports = osInactive.fileImportNames[funcFile[fn]]
			}

			var helperErr error
			var bindStatExpr func(e ast.Expr, scope map[string]*statLocalBinding)
			var bindStatStmt func(s ast.Stmt, scope, sameBlock map[string]*statLocalBinding)

			bindStatExpr = func(e ast.Expr, scope map[string]*statLocalBinding) {
				if helperErr != nil || e == nil {
					return
				}
				switch x := e.(type) {
				case *ast.Ident:
					if b := scope[x.Name]; b != nil {
						identBinding[x] = b
					}
					return
				case *ast.SelectorExpr:
					bindStatExpr(x.X, scope)
					return
				case *ast.UnaryExpr:
					bindStatExpr(x.X, scope)
					if helperErr == nil && x.Op == token.AND {
						curExpr := unwrapParens(x.X)
						for {
							sel, okS := curExpr.(*ast.SelectorExpr)
							if !okS {
								break
							}
							curExpr = unwrapParens(sel.X)
						}
						if bID, okB := curExpr.(*ast.Ident); okB && identBinding[bID] == nil && pkgDeclCounts[bID.Name] > 0 {
							helperErr = fmt.Errorf("os: %s helper %s takes address of package declaration %s", rootLabel, curLabel, bID.Name)
						}
					}
					return
				case *ast.FuncLit:
					litScope := maps.Clone(scope)
					litSame := map[string]*statLocalBinding{}
					if x.Type != nil {
						if x.Type.Params != nil {
							for _, fld := range x.Type.Params.List {
								bindStatExpr(fld.Type, scope)
							}
						}
						if x.Type.Results != nil {
							for _, fld := range x.Type.Results.List {
								bindStatExpr(fld.Type, scope)
							}
						}
						for _, p := range paramNamesFlat(x.Type.Params) {
							if p != "" && p != "_" {
								b := &statLocalBinding{bad: true}
								litScope[p] = b
								litSame[p] = b
							}
						}
						if x.Type.Results != nil {
							for _, fld := range x.Type.Results.List {
								for _, id := range fld.Names {
									if id.Name != "" && id.Name != "_" {
										b := &statLocalBinding{bad: true}
										litScope[id.Name] = b
										litSame[id.Name] = b
										identBinding[id] = b
									}
								}
							}
						}
					}
					if x.Body != nil {
						for _, st := range x.Body.List {
							bindStatStmt(st, litScope, litSame)
						}
					}
					return
				}
				ast.Inspect(e, func(ch ast.Node) bool {
					if helperErr != nil || ch == nil {
						return false
					}
					if ch == e {
						return true
					}
					if subE, okE := ch.(ast.Expr); okE {
						bindStatExpr(subE, scope)
						return false
					}
					if subS, okS := ch.(ast.Stmt); okS {
						bindStatStmt(subS, scope, map[string]*statLocalBinding{})
						return false
					}
					return true
				})
			}

			bindStatStmt = func(s ast.Stmt, scope, sameBlock map[string]*statLocalBinding) {
				if helperErr != nil || s == nil {
					return
				}
				switch x := s.(type) {
				case *ast.BlockStmt:
					blkScope := maps.Clone(scope)
					blkSame := map[string]*statLocalBinding{}
					for _, st := range x.List {
						bindStatStmt(st, blkScope, blkSame)
					}
				case *ast.LabeledStmt:
					bindStatStmt(x.Stmt, scope, sameBlock)
				case *ast.BranchStmt, *ast.EmptyStmt:
				case *ast.DeclStmt:
					gd, okGD := x.Decl.(*ast.GenDecl)
					if !okGD {
						helperErr = fmt.Errorf("os: %s helper %s has unexpected declaration %T", rootLabel, curLabel, x.Decl)
						return
					}
					for _, spec := range gd.Specs {
						switch sp := spec.(type) {
						case *ast.TypeSpec:
							helperErr = fmt.Errorf("os: %s helper %s declares local type", rootLabel, curLabel)
							return
						case *ast.ValueSpec:
							if sp.Type != nil {
								bindStatExpr(sp.Type, scope)
							}
							for _, val := range sp.Values {
								bindStatExpr(val, scope)
							}
							isFSVal := gd.Tok == token.VAR && sp.Type != nil && len(sp.Values) == 0 && !fileImports["fileStat"]
							if isFSVal {
								_, isFSVal = isIdentNamed(sp.Type, "fileStat")
							}
							for _, id := range sp.Names {
								if id.Name == "" || id.Name == "_" {
									continue
								}
								b := &statLocalBinding{isZeroFileStat: isFSVal}
								identBinding[id] = b
								scope[id.Name] = b
								sameBlock[id.Name] = b
							}
						}
					}
				case *ast.AssignStmt:
					if x.Tok == token.DEFINE {
						for _, rhs := range x.Rhs {
							bindStatExpr(rhs, scope)
						}
						for _, lhs := range x.Lhs {
							if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
								if id.Name == "" || id.Name == "_" {
									continue
								}
								if existing := sameBlock[id.Name]; existing != nil {
									identBinding[id] = existing
								} else {
									b := &statLocalBinding{}
									scope[id.Name] = b
									sameBlock[id.Name] = b
									identBinding[id] = b
								}
							} else {
								bindStatExpr(lhs, scope)
							}
						}
					} else {
						for _, lhs := range x.Lhs {
							bindStatExpr(lhs, scope)
						}
						for _, rhs := range x.Rhs {
							bindStatExpr(rhs, scope)
						}
					}
				case *ast.IfStmt:
					if skipInactiveHookIf(x, fn) {
						return
					}
					ifScope := maps.Clone(scope)
					ifSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, ifScope, ifSame)
					}
					bindStatExpr(x.Cond, ifScope)
					if x.Body != nil {
						bindStatStmt(x.Body, ifScope, ifSame)
					}
					if x.Else != nil {
						bindStatStmt(x.Else, maps.Clone(ifScope), map[string]*statLocalBinding{})
					}
				case *ast.ForStmt:
					forScope := maps.Clone(scope)
					forSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, forScope, forSame)
					}
					if x.Cond != nil {
						bindStatExpr(x.Cond, forScope)
					}
					if x.Post != nil {
						bindStatStmt(x.Post, forScope, forSame)
					}
					if x.Body != nil {
						bindStatStmt(x.Body, forScope, forSame)
					}
				case *ast.RangeStmt:
					bindStatExpr(x.X, scope)
					rngScope := maps.Clone(scope)
					rngSame := map[string]*statLocalBinding{}
					if x.Tok == token.DEFINE {
						for _, expr := range []ast.Expr{x.Key, x.Value} {
							if expr == nil {
								continue
							}
							if id, okID := unwrapParens(expr).(*ast.Ident); okID {
								if id.Name != "" && id.Name != "_" {
									b := &statLocalBinding{bad: true}
									rngScope[id.Name] = b
									rngSame[id.Name] = b
									identBinding[id] = b
								}
							} else {
								bindStatExpr(expr, rngScope)
							}
						}
					} else {
						if x.Key != nil {
							bindStatExpr(x.Key, rngScope)
						}
						if x.Value != nil {
							bindStatExpr(x.Value, rngScope)
						}
					}
					if x.Body != nil {
						bindStatStmt(x.Body, rngScope, rngSame)
					}
				case *ast.SwitchStmt:
					swScope := maps.Clone(scope)
					swSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, swScope, swSame)
					}
					if x.Tag != nil {
						bindStatExpr(x.Tag, swScope)
					}
					if x.Body != nil {
						for _, cs := range x.Body.List {
							if cc, okCC := cs.(*ast.CaseClause); okCC {
								for _, ce := range cc.List {
									bindStatExpr(ce, swScope)
								}
								ccScope := maps.Clone(swScope)
								ccSame := map[string]*statLocalBinding{}
								for _, bodySt := range cc.Body {
									bindStatStmt(bodySt, ccScope, ccSame)
								}
							}
						}
					}
				case *ast.TypeSwitchStmt:
					tsScope := maps.Clone(scope)
					tsSame := map[string]*statLocalBinding{}
					if x.Init != nil {
						bindStatStmt(x.Init, tsScope, tsSame)
					}
					var boundID *ast.Ident
					if as, okA := x.Assign.(*ast.AssignStmt); okA && as.Tok == token.DEFINE && len(as.Lhs) == 1 && len(as.Rhs) == 1 {
						bindStatExpr(as.Rhs[0], tsScope)
						if id, okID := unwrapParens(as.Lhs[0]).(*ast.Ident); okID && id.Name != "" && id.Name != "_" {
							boundID = id
							identBinding[id] = &statLocalBinding{bad: true}
						}
					} else if x.Assign != nil {
						bindStatStmt(x.Assign, tsScope, tsSame)
					}
					if x.Body != nil {
						for _, cs := range x.Body.List {
							if cc, okCC := cs.(*ast.CaseClause); okCC {
								for _, ce := range cc.List {
									bindStatExpr(ce, tsScope)
								}
								ccScope := maps.Clone(tsScope)
								ccSame := map[string]*statLocalBinding{}
								if boundID != nil {
									b := &statLocalBinding{bad: true}
									ccScope[boundID.Name] = b
									ccSame[boundID.Name] = b
								}
								for _, bodySt := range cc.Body {
									bindStatStmt(bodySt, ccScope, ccSame)
								}
							}
						}
					}
				case *ast.SelectStmt:
					if x.Body != nil {
						for _, cs := range x.Body.List {
							if cm, okCM := cs.(*ast.CommClause); okCM {
								cmScope := maps.Clone(scope)
								cmSame := map[string]*statLocalBinding{}
								if cm.Comm != nil {
									bindStatStmt(cm.Comm, cmScope, cmSame)
								}
								for _, bodySt := range cm.Body {
									bindStatStmt(bodySt, cmScope, cmSame)
								}
							}
						}
					}
				case *ast.ReturnStmt:
					for _, r := range x.Results {
						bindStatExpr(r, scope)
					}
				case *ast.ExprStmt:
					bindStatExpr(x.X, scope)
				case *ast.SendStmt:
					bindStatExpr(x.Chan, scope)
					bindStatExpr(x.Value, scope)
				case *ast.IncDecStmt:
					bindStatExpr(x.X, scope)
				case *ast.GoStmt:
					bindStatExpr(x.Call, scope)
				case *ast.DeferStmt:
					bindStatExpr(x.Call, scope)
				default:
					helperErr = fmt.Errorf("os: %s helper %s has unsupported statement %T", rootLabel, curLabel, s)
				}
			}

			for _, st := range stmts {
				bindStatStmt(st, topScope, topSame)
				if helperErr != nil {
					return helperErr
				}
			}

			// Pass 2a: mark any address-taken non-fileStat local, any whole-value mutation of a zero-init
			// fileStat local, and any inc/dec/range/type-switch assignment target on its lexical binding
			// before evaluating isFreshStatExpr.
			for _, st := range stmts {
				ast.Inspect(st, func(n ast.Node) bool {
					if helperErr != nil || n == nil {
						return false
					}
					if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, fn) {
						return false
					}
					switch x := n.(type) {
					case *ast.UnaryExpr:
						if x.Op == token.AND {
							if directID, okD := unwrapParens(x.X).(*ast.Ident); okD {
								if b := identBinding[directID]; b != nil && !b.isZeroFileStat {
									b.bad = true
								}
							}
						}
					case *ast.AssignStmt:
						for _, lhs := range x.Lhs {
							if _, okStar := unwrapParens(lhs).(*ast.StarExpr); okStar {
								helperErr = fmt.Errorf("os: %s helper %s dereference-assigns pointer target", rootLabel, curLabel)
								return false
							}
							if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
								if b := identBinding[lID]; b != nil && b.isZeroFileStat {
									b.bad = true
								}
							}
						}
					case *ast.IncDecStmt:
						if _, okStar := unwrapParens(x.X).(*ast.StarExpr); okStar {
							helperErr = fmt.Errorf("os: %s helper %s dereference-mutates pointer target", rootLabel, curLabel)
							return false
						}
						if lID, okID := unwrapParens(x.X).(*ast.Ident); okID {
							if b := identBinding[lID]; b != nil {
								b.bad = true
							}
						}
					case *ast.RangeStmt:
						for _, expr := range []ast.Expr{x.Key, x.Value} {
							if expr != nil {
								if _, okStar := unwrapParens(expr).(*ast.StarExpr); okStar {
									helperErr = fmt.Errorf("os: %s helper %s dereference-assigns pointer target in range", rootLabel, curLabel)
									return false
								}
								if id, okID := unwrapParens(expr).(*ast.Ident); okID {
									if b := identBinding[id]; b != nil {
										b.bad = true
									}
								}
							}
						}
					case *ast.TypeSwitchStmt:
						if as, okA := x.Assign.(*ast.AssignStmt); okA {
							for _, lhs := range as.Lhs {
								if id, okID := unwrapParens(lhs).(*ast.Ident); okID {
									if b := identBinding[id]; b != nil {
										b.bad = true
									}
								}
							}
						}
					}
					return true
				})
				if helperErr != nil {
					return helperErr
				}
			}

			isFreshStatExpr := func(expr ast.Expr) bool {
				expr = unwrapParens(expr)
				if _, okNil := isIdentNamed(expr, "nil"); okNil && !fileImports["nil"] {
					return true
				}
				if u, okU := expr.(*ast.UnaryExpr); okU && u.Op == token.AND {
					if _, tName := compositeWriterLit(expr); tName == "fileStat" && !fileImports["fileStat"] {
						return true
					}
					if vID, okV := unwrapParens(u.X).(*ast.Ident); okV {
						b := identBinding[vID]
						return b != nil && b.isZeroFileStat && !b.bad
					}
					return false
				}
				if c, okC := expr.(*ast.CallExpr); okC && !c.Ellipsis.IsValid() {
					if cID, okID := unwrapParens(c.Fun).(*ast.Ident); okID && !fileImports[cID.Name] && allTopFuncs[cID.Name] != nil && pkgDeclCounts[cID.Name] == 1 && !osAnyLinknameLocals[cID.Name] && returnsFileInfoOrStat(allTopFuncs[cID.Name]) {
						return true
					}
				}
				return false
			}

			enqueueIfNew := func(it statWorkItem) {
				if !visited[it] {
					queue = append(queue, it)
				}
			}

			recordBindFreshness := func(id *ast.Ident, fresh bool) {
				if id == nil || id.Name == "" || id.Name == "_" {
					return
				}
				if b := identBinding[id]; b != nil {
					if fresh {
						b.sawFresh = true
					} else {
						b.bad = true
					}
				}
			}

			// Pass 2b: evaluate all variable initializers/assignments against finalized zero-fileStat
			// bindings, and audit calls and identifier references.
			checkReturns := returnsFileInfoOrStat(fn)
			for _, st := range stmts {
				ast.Inspect(st, func(n ast.Node) bool {
					if helperErr != nil || n == nil {
						return false
					}
					if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, fn) {
						return false
					}
					switch x := n.(type) {
					case *ast.GenDecl:
						for _, spec := range x.Specs {
							vs, okVS := spec.(*ast.ValueSpec)
							if !okVS {
								continue
							}
							if len(vs.Names) == 1 {
								if b := identBinding[vs.Names[0]]; b != nil && b.isZeroFileStat {
									continue
								}
							}
							allZeroFS := len(vs.Names) > 0
							for _, id := range vs.Names {
								if id.Name == "" || id.Name == "_" {
									continue
								}
								if b := identBinding[id]; b == nil || !b.isZeroFileStat {
									allZeroFS = false
									break
								}
							}
							if allZeroFS {
								continue
							}
							if len(vs.Values) == 0 {
								for _, id := range vs.Names {
									recordBindFreshness(id, x.Tok == token.VAR)
								}
							} else if len(vs.Values) == len(vs.Names) {
								for i, id := range vs.Names {
									recordBindFreshness(id, isFreshStatExpr(vs.Values[i]))
								}
							} else if len(vs.Values) == 1 && len(vs.Names) == 2 {
								recordBindFreshness(vs.Names[0], isFreshStatExpr(vs.Values[0]))
								recordBindFreshness(vs.Names[1], false)
							} else {
								for _, id := range vs.Names {
									recordBindFreshness(id, false)
								}
							}
						}
					case *ast.AssignStmt:
						if x.Tok != token.ASSIGN && x.Tok != token.DEFINE {
							for _, lhs := range x.Lhs {
								if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
									recordBindFreshness(lID, false)
								}
							}
						} else if len(x.Rhs) == 1 && len(x.Lhs) == 2 {
							if l0, ok0 := unwrapParens(x.Lhs[0]).(*ast.Ident); ok0 {
								recordBindFreshness(l0, isFreshStatExpr(x.Rhs[0]))
							}
							if l1, ok1 := unwrapParens(x.Lhs[1]).(*ast.Ident); ok1 {
								recordBindFreshness(l1, false)
							}
						} else if len(x.Lhs) == len(x.Rhs) {
							for i, lhs := range x.Lhs {
								if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
									recordBindFreshness(lID, isFreshStatExpr(x.Rhs[i]))
								}
							}
						} else {
							for _, lhs := range x.Lhs {
								if lID, okID := unwrapParens(lhs).(*ast.Ident); okID {
									recordBindFreshness(lID, false)
								}
							}
						}
					case *ast.Ident:
						if x.Name == "testlog" {
							helperErr = fmt.Errorf("os: %s helper %s references testlog", rootLabel, curLabel)
							return false
						}
						if disjointAltStruct != "" && x.Name == disjointAltStruct {
							helperErr = fmt.Errorf("os: %s helper %s references alternate FileInfo struct %s", rootLabel, curLabel, disjointAltStruct)
							return false
						}
					case *ast.CallExpr:
						if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID {
							if identBinding[cID] != nil {
								helperErr = fmt.Errorf("os: %s helper %s calls local variable %s", rootLabel, curLabel, cID.Name)
								return false
							}
							if osAnyLinknameLocals[cID.Name] {
								helperErr = fmt.Errorf("os: %s helper %s calls linknamed %s", rootLabel, curLabel, cID.Name)
								return false
							}
							if cID.Name == "ignoringEINTR" {
								usedIgnoringEINTR = true
							} else if allTopFuncs[cID.Name] != nil {
								enqueueIfNew(statWorkItem{kind: "top", name: cID.Name})
							}
						} else if sel, okS := unwrapParens(x.Fun).(*ast.SelectorExpr); okS {
							if _, okSys := isIdentNamed(sel.X, "syscall"); okSys {
								if rootSpec.isFdStat {
									if sel.Sel.Name == "Fstat" || sel.Sel.Name == "GetFileInformationByHandle" {
										sawKernelStat = true
									}
								} else {
									if sel.Sel.Name == "Stat" || sel.Sel.Name == "Lstat" || sel.Sel.Name == "GetFileAttributesEx" || sel.Sel.Name == "CreateFile" || sel.Sel.Name == "GetFileInformationByHandle" {
										sawKernelStat = true
									}
								}
							} else if rootSpec.isFdStat && sel.Sel.Name == "Fstat" {
								sawKernelStat = true
							}
							isNonImportRecv := false
							if bID, okB := unwrapParens(sel.X).(*ast.Ident); okB && !fileImports[bID.Name] {
								isNonImportRecv = true
							} else if _, okTA := unwrapParens(sel.X).(*ast.TypeAssertExpr); okTA {
								isNonImportRecv = true
							}
							if isNonImportRecv {
								if allFileStatMethods[sel.Sel.Name] != nil {
									enqueueIfNew(statWorkItem{kind: "filestat", name: sel.Sel.Name})
								} else if sel.Sel.Name != "Close" && allFileMethods[sel.Sel.Name] != nil {
									enqueueIfNew(statWorkItem{kind: "file", name: sel.Sel.Name})
								} else if sel.Sel.Name != "close" && allRawFileMethods[sel.Sel.Name] != nil {
									enqueueIfNew(statWorkItem{kind: "raw", name: sel.Sel.Name})
								}
							}
						}
					case *ast.FuncLit:
						// Only permitted as the callback argument of ignoringEINTR(...).
					}
					return true
				})
				if helperErr != nil {
					return helperErr
				}
			}

			if checkReturns {
				for _, st := range stmts {
					ast.Inspect(st, func(n ast.Node) bool {
						if helperErr != nil || n == nil {
							return false
						}
						if _, okFL := n.(*ast.FuncLit); okFL {
							return false
						}
						if ifs, okI := n.(*ast.IfStmt); okI && skipInactiveHookIf(ifs, fn) {
							return false
						}
						ret, okR := n.(*ast.ReturnStmt)
						if !okR {
							return true
						}
						if len(ret.Results) == 0 {
							helperErr = fmt.Errorf("os: %s helper %s has bare return", rootLabel, curLabel)
							return false
						}
						r0 := unwrapParens(ret.Results[0])
						if isFreshStatExpr(r0) {
							return true
						}
						if vID, okV := r0.(*ast.Ident); okV {
							if b := identBinding[vID]; b != nil && b.sawFresh && !b.bad {
								return true
							}
						}
						helperErr = fmt.Errorf("os: %s helper %s returns unverified FileInfo expression", rootLabel, curLabel)
						return false
					})
					if helperErr != nil {
						return helperErr
					}
				}
			}
		}

		if rootSpec.needKernel && !sawKernelStat {
			return fmt.Errorf("os: %s does not reach kernel stat operation", rootLabel)
		}
	}
	if usedIgnoringEINTR && !verifyOSIgnoringEINTR(allTopFuncs["ignoringEINTR"], funcFile, fileImportsSyscall, osNoFileReserved, osAnyLinknameLocals) {
		return fmt.Errorf("os: invalid ignoringEINTR helper used by statNolog")
	}
	return nil
}
