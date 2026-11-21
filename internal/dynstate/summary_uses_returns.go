package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func (s *globalUseScanner) flushScopeUses(fnKey syntaxutil.FuncKey, literal bool, sc useSinkScope) {
	for key := range sc.mutated {
		*s.attributed = append(*s.attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Literal: literal})
	}
	for key := range sc.escaped {
		*s.attributed = append(*s.attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Escape: true, Literal: literal})
	}
	for key, methods := range sc.methodUses {
		for m := range methods {
			*s.attributed = append(*s.attributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: m, Literal: literal})
		}
	}
	if s.attributedParams != nil {
		for key, params := range sc.paramUses {
			for pk := range params {
				*s.attributedParams = append(*s.attributedParams, syntaxutil.VarParamUse{Key: key, Param: pk, Func: fnKey, Literal: literal})
			}
		}
	} else if s.sink.paramUses != nil {
		for key, params := range sc.paramUses {
			if s.sink.paramUses[key] == nil {
				s.sink.paramUses[key] = map[syntaxutil.ParamKey]bool{}
			}
			for pk := range params {
				s.sink.paramUses[key][pk] = true
			}
		}
	}
	if s.poolAttributed != nil {
		for key := range sc.poolMutated {
			*s.poolAttributed = append(*s.poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Literal: literal})
		}
		for key := range sc.poolEscaped {
			*s.poolAttributed = append(*s.poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, Escape: true, Literal: literal})
		}
		for key, methods := range sc.poolMethods {
			for m := range methods {
				*s.poolAttributed = append(*s.poolAttributed, syntaxutil.AttributedUse{Func: fnKey, Key: key, HasMethod: true, Method: m, Literal: literal})
			}
		}
	} else {
		if s.sink.poolMutated != nil {
			for key := range sc.poolMutated {
				s.sink.poolMutated[key] = true
			}
			for key := range sc.poolMethods {
				s.sink.poolMutated[key] = true
			}
		}
		if s.sink.poolEscaped != nil {
			for key := range sc.poolEscaped {
				s.sink.poolEscaped[key] = true
			}
		}
	}
}

func (s *globalUseScanner) runScopedPass(fnKey syntaxutil.FuncKey, literal bool, exec func()) {
	savedSink := s.sink
	savedDeferFn, savedDeferLit := s.currentDeferFn, s.currentDeferLit
	sc := useSinkScope{
		mutated:     map[string]bool{},
		escaped:     map[string]bool{},
		methodUses:  map[string]map[syntaxutil.FuncKey]bool{},
		poolMutated: map[string]bool{},
		poolEscaped: map[string]bool{},
		poolMethods: map[string]map[syntaxutil.FuncKey]bool{},
	}
	if savedSink.paramUses != nil {
		sc.paramUses = map[string]map[syntaxutil.ParamKey]bool{}
	}
	s.sink = sc
	if fnKey.Valid() {
		s.currentDeferFn, s.currentDeferLit = fnKey, literal
	}
	exec()
	s.currentDeferFn, s.currentDeferLit = savedDeferFn, savedDeferLit
	s.sink = savedSink
	s.flushScopeUses(fnKey, literal, sc)
}

func (s *globalUseScanner) walkAttributedDecl(decl *ast.FuncDecl, fnKey syntaxutil.FuncKey, setCurrentFn bool) {
	b := s.fc.funcBody(s.p, decl)
	if b == nil {
		return
	}
	declAliases, _ := computeBodyCarrierAliases(s.audited, s.fc, b, carrierAliasConfig{
		parentAliases:       s.aliasedLocals,
		carrierVar:          s.dynamicPackageVar,
		skipMethodRecv:      s.isExemptMethodRecvCall,
		skipNonBuiltinCalls: true,
		descendNested:       true,
	})
	prevAliases := s.aliasedLocals
	prevPrecomp := s.precomputedDeclAliases
	s.aliasedLocals = declAliases
	s.precomputedDeclAliases = true
	defer func() {
		s.aliasedLocals = prevAliases
		s.precomputedDeclAliases = prevPrecomp
	}()

	// Pass 1: nested closures (ValMakeClosure / CallIIFE) and OpGo statements -> Literal: true.
	s.runScopedPass(fnKey, true, func() {
		forEachNestedLiteralAndGo(b, func(litBody *flowir.Body) {
			s.walkBody(litBody, true)
		}, func(goOp *flowir.Op) {
			goBody := &flowir.Body{AST: goOp.StmtAST, Ops: []flowir.Op{*goOp}}
			s.walkBody(goBody, true)
		})
	})

	// Pass 2: synchronous operations in decl.Body only -> Literal: false.
	s.runScopedPass(fnKey, false, func() {
		if setCurrentFn {
			s.currentFn = decl
			s.currentAttrFn = fnKey
		}
		s.walkBody(b, false)
		if setCurrentFn {
			s.currentFn = nil
			s.currentAttrFn = syntaxutil.FuncKey{}
		}
	})
}

func (s *globalUseScanner) scanDecls() {
	for _, file := range s.p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				var methodKey syntaxutil.FuncKey
				if decl.Recv != nil && decl.Name != nil && s.attributed != nil && decl.Body != nil && s.p.Types != nil {
					if fn, ok := s.p.TypesInfo.Defs[decl.Name].(*types.Func); ok && fn != nil {
						if key := syntaxutil.MethodFactKey(fn); key.Pkg != "" && !strings.HasPrefix(key.Name, ".") {
							methodKey = key
						}
					}
				}
				if methodKey.Valid() {
					s.walkAttributedDecl(decl, methodKey, false)
					continue
				}
				if decl.Recv == nil && decl.Name != nil && s.attributed != nil && !s.initOnly[decl.Name.Name] &&
					decl.Name.Name != "init" && decl.Name.Name != "_" && decl.Body != nil && s.p.Types != nil {
					fnKey := syntaxutil.FuncKey{Pkg: s.p.Types.Path(), Name: decl.Name.Name}
					s.walkAttributedDecl(decl, fnKey, true)
					continue
				}
				if decl.Recv == nil && decl.Name != nil && (decl.Name.Name == "init" || s.initOnly[decl.Name.Name]) {
					if decl.Body != nil {
						b := s.fc.funcBody(s.p, decl)
						s.aliasedLocals = s.initAliasedLocals(b)
						forEachNestedLiteralAndGo(b, func(litBody *flowir.Body) {
							s.walkBody(litBody, true)
						}, func(goOp *flowir.Op) {
							goBody := &flowir.Body{AST: goOp.StmtAST, Ops: []flowir.Op{*goOp}}
							s.walkBody(goBody, true)
						})
						s.scanExemptCalls(b)
						s.aliasedLocals = nil
					}
					continue
				}
				if decl.Body != nil {
					b := s.fc.funcBody(s.p, decl)
					declAliases, _ := computeBodyCarrierAliases(s.audited, s.fc, b, carrierAliasConfig{
						parentAliases:       s.aliasedLocals,
						carrierVar:          s.dynamicPackageVar,
						skipMethodRecv:      s.isExemptMethodRecvCall,
						skipNonBuiltinCalls: true,
						descendNested:       true,
					})
					prevAliases := s.aliasedLocals
					prevPrecomp := s.precomputedDeclAliases
					s.aliasedLocals = declAliases
					s.precomputedDeclAliases = true
					s.currentFn = decl
					s.walkBody(b, true)
					s.currentFn = nil
					s.aliasedLocals = prevAliases
					s.precomputedDeclAliases = prevPrecomp
				}
			case *ast.GenDecl:
				if decl.Tok == token.VAR || decl.Tok == token.CONST {
					b := s.fc.body(s.p, decl)
					s.aliasedLocals = s.initAliasedLocals(b)
					forEachNestedLiteralAndGo(b, func(litBody *flowir.Body) {
						s.walkBody(litBody, true)
					}, nil)
					s.scanExemptCalls(b)
					s.aliasedLocals = nil
				} else {
					// Fail closed on any alias-handing dynamic package global referenced inside a type declaration.
					ast.Inspect(decl, func(n ast.Node) bool {
						if id, ok := n.(*ast.Ident); ok {
							if obj, uOK := s.p.TypesInfo.Uses[id]; uOK {
								if variable, dOK := s.dynamicPackageVar(obj); dOK && refconfine.TypeHandsOutDynamicAlias(s.audited, variable.Type()) {
									s.markEscapedVars([]*types.Var{variable}, id.Pos())
								}
							}
						}
						return true
					})
				}
			}
		}
	}
}

func (s *globalUseScanner) resolvePendingReturns() {
	if len(s.pendingReturns) == 0 {
		return
	}
	returnerKeys := map[string]map[string]bool{}
	mergeKeys := func(fn string, keys map[string]bool) bool {
		if returnerKeys[fn] == nil {
			returnerKeys[fn] = map[string]bool{}
		}
		changed := false
		for key := range keys {
			if !returnerKeys[fn][key] {
				returnerKeys[fn][key] = true
				changed = true
			}
		}
		return changed
	}
	for _, pending := range s.pendingReturns {
		set := map[string]bool{}
		for _, key := range pending.keys {
			set[key] = true
		}
		mergeKeys(pending.fn, set)
	}
	plainFuncObjs := map[string]types.Object{}
	for _, file := range s.p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name != nil {
				if obj := s.p.TypesInfo.Defs[fd.Name]; obj != nil {
					plainFuncObjs[fd.Name.Name] = obj
				}
			}
		}
	}
	bad := map[string]bool{}
	deps := map[string]map[string]bool{}
	scanned := map[string]bool{}
	for {
		var frontier []string
		for fn := range returnerKeys {
			if !scanned[fn] {
				frontier = append(frontier, fn)
				scanned[fn] = true
			}
		}
		if len(frontier) == 0 {
			break
		}
		returnerObjs := map[types.Object]string{}
		for fn := range returnerKeys {
			if obj := plainFuncObjs[fn]; obj != nil {
				returnerObjs[obj] = fn
			}
		}
		frontierSet := map[string]bool{}
		for _, fn := range frontier {
			frontierSet[fn] = true
		}
		depend := func(from, to string) {
			if deps[from] == nil {
				deps[from] = map[string]bool{}
			}
			deps[from][to] = true
		}

		checkTrackedCall := func(v *flowir.Value) (string, *types.Signature, bool) {
			if v == nil || v.Kind != flowir.ValCall || v.CallKind != flowir.CallPlain || v.IsMethodExprCall || v.CalleeFunc == nil {
				return "", nil, false
			}
			orig := v.CalleeFunc.Origin()
			fnName, tracked := returnerObjs[orig]
			if !tracked || !frontierSet[fnName] {
				return "", nil, false
			}
			sig, ok := orig.Type().(*types.Signature)
			if !ok {
				bad[fnName] = true
				return "", nil, false
			}
			return fnName, sig, true
		}

		var scanSites func(rootNode ast.Node, rootBody *flowir.Body, siteName string, siteEligible, topGenDecl bool)
		scanSites = func(rootNode ast.Node, rootBody *flowir.Body, siteName string, siteEligible, topGenDecl bool) {
			if rootBody == nil {
				return
			}
			var walkScope func(b *flowir.Body, inLit bool)
			var scanExpr func(v *flowir.Value, inLit bool)
			scanExpr = func(v *flowir.Value, inLit bool) {
				if v == nil {
					return
				}
				switch v.Kind {
				case flowir.ValMakeClosure:
					if v.Closure != nil {
						if topGenDecl && v.Lit != nil && v.Lit.Body != nil {
							scanSites(v.Lit.Body, v.Closure, "", false, false)
						} else {
							walkScope(v.Closure, true)
						}
					}
					return
				case flowir.ValCall:
					if v.CallKind == flowir.CallIIFE {
						for _, a := range v.Args {
							scanExpr(a, inLit)
						}
						if v.IIFE != nil {
							if topGenDecl && v.IIFE.Block != nil {
								scanSites(v.IIFE.Block, v.IIFE, "", false, false)
							} else {
								walkScope(v.IIFE, true)
							}
						}
						return
					}
					if fnName, _, ok := checkTrackedCall(v); ok {
						bad[fnName] = true
						for _, a := range v.Args {
							scanExpr(a, inLit)
						}
						return
					}
				case flowir.ValPlace:
					if v.Place.Root == flowir.RootFunc && v.Place.Func != nil {
						if fnName, tracked := returnerObjs[v.Place.Func.Origin()]; tracked && frontierSet[fnName] {
							bad[fnName] = true
						}
					}
				}
				v.ForEachChildValue(func(ch *flowir.Value) bool {
					scanExpr(ch, inLit)
					return true
				})
			}

			handleAssignCall := func(op *flowir.Op, callVal *flowir.Value, fnName string, sig *types.Signature, inLit bool) {
				for _, dst := range op.Dsts {
					dst.ForEachChildValue(func(cv *flowir.Value) bool {
						scanExpr(cv, inLit)
						return true
					})
				}
				for _, a := range callVal.Args {
					scanExpr(a, inLit)
				}
				results := sig.Results()
				if results == nil || results.Len() != len(op.Dsts) {
					bad[fnName] = true
					return
				}
				roots := map[types.Object]bool{}
				for i, dst := range op.Dsts {
					if dst.IsBlank() {
						continue
					}
					if !dst.IsBareVar() || dst.Obj == nil {
						bad[fnName] = true
						return
					}
					if refconfine.TypeHandsOutMutableReach(results.At(i).Type()) || syntaxutil.ContainsUintptr(results.At(i).Type()) {
						roots[dst.Obj] = true
					}
				}
				if len(roots) == 0 {
					return
				}
				if topGenDecl || rootNode == nil {
					bad[fnName] = true
					return
				}
				siteWants := map[syntaxutil.ParamKey]bool{}
				var siteMethodWants map[syntaxutil.FuncKey]bool
				var siteFieldWants map[syntaxutil.FieldPosKey]bool
				var siteElemWants map[syntaxutil.ElemParamUse]bool
				if s.sink.methodUses != nil {
					siteMethodWants = map[syntaxutil.FuncKey]bool{}
				}
				if s.fieldUses != nil {
					siteFieldWants = map[syntaxutil.FieldPosKey]bool{}
				}
				if s.elemUses != nil {
					siteElemWants = map[syntaxutil.ElemParamUse]bool{}
				}
				var siteReturned bool
				var siteRet *bool
				if siteEligible {
					siteRet = &siteReturned
				}
				if !boundValueLeakFreeJudged(s.audited, s.p, s.fc, roots, rootNode, siteWants, siteRet, siteMethodWants, siteFieldWants, siteElemWants) {
					bad[fnName] = true
					return
				}
				var callPos token.Pos
				if callVal.CallAST != nil {
					callPos = callVal.CallAST.Pos()
				}
				for key := range returnerKeys[fnName] {
					s.recordConfinementSinkUses(key, siteWants, siteMethodWants, siteFieldWants, siteElemWants, syntaxutil.FuncKey{}, false, callPos)
				}
				if siteReturned {
					if mergeKeys(siteName, returnerKeys[fnName]) {
						scanned[siteName] = false
					}
					depend(fnName, siteName)
				}
			}

			walkScope = func(b *flowir.Body, inLit bool) {
				if b == nil {
					return
				}
				b.ForEachSyncOp(func(op *flowir.Op) bool {
					switch op.Kind {
					case flowir.OpExpr:
						if !topGenDecl {
							if _, _, ok := checkTrackedCall(op.Expr); ok {
								for _, a := range op.Expr.Args {
									scanExpr(a, inLit)
								}
								return true
							}
						}
						scanExpr(op.Expr, inLit)
					case flowir.OpDefer, flowir.OpGo:
						if !topGenDecl {
							if _, _, ok := checkTrackedCall(op.Call); ok {
								for _, a := range op.Call.Args {
									scanExpr(a, inLit)
								}
								return true
							}
						}
						scanExpr(op.Call, inLit)
					case flowir.OpReturn:
						for _, res := range op.Results {
							if fnName, _, ok := checkTrackedCall(res); ok {
								if !topGenDecl && siteEligible && !inLit {
									if mergeKeys(siteName, returnerKeys[fnName]) {
										scanned[siteName] = false
									}
									depend(fnName, siteName)
								} else {
									bad[fnName] = true
								}
								for _, a := range res.Args {
									scanExpr(a, inLit)
								}
							} else {
								scanExpr(res, inLit)
							}
						}
					case flowir.OpAssign:
						if (op.AssignKind == flowir.AssignPlain || op.AssignKind == flowir.AssignMulti) && len(op.Srcs) == 1 {
							if fnName, sig, ok := checkTrackedCall(op.Srcs[0]); ok {
								handleAssignCall(op, op.Srcs[0], fnName, sig, inLit)
								return true
							}
						}
						forEachOpTopValues(op, func(v *flowir.Value) {
							scanExpr(v, inLit)
						})
					default:
						forEachOpTopValues(op, func(v *flowir.Value) {
							scanExpr(v, inLit)
						})
					}
					return true
				})
			}

			walkScope(rootBody, false)
		}

		var frontierFuncDecls map[*ast.FuncDecl]bool
		hasTopLevelValueUse := s.idx == nil
		if s.idx != nil {
			frontierFuncDecls = map[*ast.FuncDecl]bool{}
			for _, fn := range frontier {
				if obj := plainFuncObjs[fn]; obj != nil {
					for _, id := range s.idx.UsesOf[obj] {
						if fd := s.idx.EnclFunc[id]; fd != nil {
							frontierFuncDecls[fd] = true
						} else {
							hasTopLevelValueUse = true
						}
					}
				}
			}
		}
		for _, file := range s.p.Syntax {
			if file == nil {
				continue
			}
			for _, decl := range file.Decls {
				switch decl := decl.(type) {
				case *ast.FuncDecl:
					if decl.Body == nil || (s.idx != nil && !frontierFuncDecls[decl]) {
						continue
					}
					name := ""
					if decl.Name != nil {
						name = decl.Name.Name
					}
					eligible := decl.Recv == nil && decl.Name != nil && !decl.Name.IsExported() && name != "init" && name != "_"
					scanSites(decl.Body, s.fc.funcBody(s.p, decl), name, eligible, false)
				case *ast.GenDecl:
					if !hasTopLevelValueUse {
						continue
					}
					if decl.Tok == token.VAR || decl.Tok == token.CONST {
						scanSites(nil, s.fc.body(s.p, decl), "", false, true)
					} else {
						ast.Inspect(decl, func(n ast.Node) bool {
							if id, ok := n.(*ast.Ident); ok {
								if obj := s.p.TypesInfo.Uses[id]; obj != nil {
									if fnName, tracked := returnerObjs[obj]; tracked && frontierSet[fnName] {
										bad[fnName] = true
									}
								}
							}
							return true
						})
					}
				}
			}
		}
	}
	syntaxutil.SolveReachFixedPoint(bad, deps, func(d string) bool { return bad[d] })
	type restoredKey struct {
		fn  syntaxutil.FuncKey
		key string
	}
	restored := map[restoredKey]bool{}
	for _, pending := range s.pendingReturns {
		if !bad[pending.fn] {
			continue
		}
		for _, key := range pending.keys {
			if pending.attrFn.Valid() {
				rk := restoredKey{fn: pending.attrFn, key: key}
				if !restored[rk] {
					restored[rk] = true
					syntaxutil.ExplainAttributedMark(s.hooks, s.p, "escape", key, pending.attrFn, false, pending.pos)
					*s.attributed = append(*s.attributed, syntaxutil.AttributedUse{Func: pending.attrFn, Key: key, Escape: true})
				}
			} else {
				syntaxutil.ExplainMark(s.hooks, s.p, "escape", key, pending.pos)
				s.sink.escaped[key] = true
			}
		}
	}
}
