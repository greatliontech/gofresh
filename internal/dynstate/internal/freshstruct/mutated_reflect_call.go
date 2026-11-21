package freshstruct

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"maps"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

func pkgConfinesAllReflectValueCalls(
	ctx context.Context,
	traceTarget string,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	isTrueStdPkg func(*types.Package) bool,
) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return false
	}
	fc := idx.FlowCache(p)
	if fc == nil {
		return false
	}

	isReflectValCallObj := func(fn *types.Func) bool {
		if fn == nil || !isTrueStdPkg(fn.Pkg()) || fn.Pkg().Path() != "reflect" || fn.Name() != "Call" {
			return false
		}
		sig, okS := fn.Type().(*types.Signature)
		return okS && sig.Recv() != nil && syntaxutil.IsNamedInPkg(sig.Recv().Type(), "reflect", "Value")
	}

	var callSites []*ast.CallExpr
	syntaxOK := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !syntaxOK || n == nil || isUnreachableConstIfBranch(p, idx, n) {
				return false
			}
			call, isC := n.(*ast.CallExpr)
			if !isC {
				return true
			}
			callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
			if !isReflectValCallObj(callee) {
				return true
			}
			if call.Ellipsis.IsValid() || len(call.Args) != 1 {
				emitExtractEscape(ctx, p, traceTarget, "reflect_call_bad_arity", "", call)
				syntaxOK = false
				return false
			}
			sel, isS := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !isS {
				emitExtractEscape(ctx, p, traceTarget, "reflect_call_non_selector", "", call)
				syntaxOK = false
				return false
			}
			sInfo := p.TypesInfo.Selections[sel]
			if sInfo == nil || sInfo.Kind() != types.MethodVal ||
				!isSafeScalarReflectValueCallArg(p, call.Args[0], isTrueStdPkg) {
				emitExtractEscape(ctx, p, traceTarget, "reflect_call_bad_args", "", call)
				syntaxOK = false
				return false
			}
			callSites = append(callSites, call)
			return true
		})
		if !syntaxOK {
			return false
		}
	}
	if len(callSites) == 0 {
		return true
	}
	if pkgHasReflectCallFileHazard(p) {
		emitExtractEscape(ctx, p, traceTarget, "reflect_call_file_hazard", "", nil)
		return false
	}

	addrOrOuterVars := map[*types.Var]bool{}
	addrFields := map[*types.Var]bool{}
	convertedStructs := map[*types.Named]bool{}
	recordAddr := func(pl flowir.Place) {
		if pl.Obj != nil {
			addrOrOuterVars[pl.Obj] = true
		}
		if len(pl.Projs) > 0 {
			last := pl.Projs[len(pl.Projs)-1]
			if last.Kind == flowir.ProjField && last.Field != nil {
				addrFields[last.Field] = true
			}
		}
	}

	callInBadScope := false
	forEachPkgFlowOp(p, fc, func(enclFn *types.Func, enclLit *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
		if op.Kind == flowir.OpTypeSwitchBind && op.SwitchDst != nil {
			addrOrOuterVars[op.SwitchDst] = true
		}
		for _, dst := range op.Dsts {
			if dst.Root == flowir.RootOuterVar && dst.Obj != nil {
				addrOrOuterVars[dst.Obj] = true
			}
		}
		op.ForEachValue(func(root *flowir.Value) bool {
			root.WalkValues(func(v *flowir.Value) bool {
				if v == nil {
					return false
				}
				switch v.Kind {
				case flowir.ValPlace:
					if v.Place.Root == flowir.RootOuterVar && v.Place.Obj != nil {
						addrOrOuterVars[v.Place.Obj] = true
					}
				case flowir.ValAddrOf:
					recordAddr(v.AddrPlace)
				case flowir.ValMethodVal:
					if v.AutoAddr && v.HasRecvPlace {
						recordAddr(v.RecvPlace)
					}
				case flowir.ValCall:
					if v.AutoAddrRecv && v.HasRecvPlace {
						recordAddr(v.RecvPlace)
					}
					if v.CallKind == flowir.CallBuiltin && v.BuiltinName == "recover" {
						callInBadScope = true
						return false
					}
					if isReflectValCallObj(v.CalleeFunc) && (enclFn == nil || enclLit != nil) {
						callInBadScope = true
						return false
					}
				case flowir.ValConvert:
					if !v.IsTypeAssert && v.Type != nil && v.Arg != nil && v.Arg.Type != nil &&
						!types.Identical(v.Type, v.Arg.Type) {
						seen := map[types.Type]bool{}
						recordNamedStructsInto(v.Type, convertedStructs, seen)
						recordNamedStructsInto(v.Arg.Type, convertedStructs, seen)
					}
				}
				return !callInBadScope
			})
			return !callInBadScope
		})
		return !callInBadScope
	})
	if callInBadScope {
		emitExtractEscape(ctx, p, traceTarget, "reflect_call_closure_or_recover", "", nil)
		return false
	}
	for _, call := range callSites {
		if !callReturnIsUnconditionallyIndexed(p, idx, call, addrOrOuterVars) {
			emitExtractEscape(ctx, p, traceTarget, "reflect_call_return_unindexed", "", call)
			return false
		}
	}

	escapedFuncs := collectEscapedIntraPkgFuncs(p, idx)
	ifaceMethodNames := collectPkgInterfaceMethodNames(p)
	strictConcreteStructs := collectStrictConcreteUnexportedStructs(p, fc, convertedStructs)
	excludedVars := map[*types.Var]bool{}
	candRVParamFuncs := map[*types.Func]bool{}
	excludeInto := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, fld := range fl.List {
			for _, nm := range fld.Names {
				if v, ok := p.TypesInfo.Defs[nm].(*types.Var); ok && v != nil {
					excludedVars[v] = true
				}
			}
		}
	}
	funcDeclHasCall := map[*ast.FuncDecl]bool{}
	for _, fd := range fc.FuncDecls {
		if fd == nil {
			continue
		}
		excludeInto(fd.Recv)
		if fd.Type != nil {
			excludeInto(fd.Type.Results)
			var fnObj *types.Func
			if fd.Name != nil {
				fnObj, _ = p.TypesInfo.Defs[fd.Name].(*types.Func)
			}
			canTrack := (fd.Type.TypeParams == nil || len(fd.Type.TypeParams.List) == 0) &&
				fnObj != nil && fd.Body != nil && !escapedFuncs[fnObj.Origin()]
			if canTrack {
				sig, okS := fnObj.Type().(*types.Signature)
				if !okS || sig.TypeParams().Len() > 0 || sig.RecvTypeParams().Len() > 0 {
					canTrack = false
				} else if fd.Recv == nil {
					canTrack = !fnObj.Exported()
				} else {
					recvNamed := syntaxutil.DerefNamedStruct(sig.Recv().Type())
					canTrack = recvNamed != nil && recvNamed.Obj() != nil && recvNamed.Obj().Pkg() == p.Types &&
						!recvNamed.Obj().Exported() && !ifaceMethodNames[fnObj.Name()] &&
						(!fnObj.Exported() || strictConcreteStructs[recvNamed.Origin()])
				}
			}
			if canTrack {
				candRVParamFuncs[fnObj.Origin()] = true
			} else {
				excludeInto(fd.Type.Params)
			}
		}
		if fd.Body != nil {
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if call, isC := n.(*ast.CallExpr); isC && !isUnreachableConstIfBranch(p, idx, call) {
					if isReflectValCallObj(syntaxutil.ResolveCalledFuncObj(p, call.Fun)) {
						funcDeclHasCall[fd] = true
					}
				}
				return true
			})
			if funcDeclHasCall[fd] && fc.FuncBody(fd).HasGotoLabelOrFallthrough() {
				emitExtractEscape(ctx, p, traceTarget, "reflect_call_unstructured_cf", "", fd)
				return false
			}
		}
	}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if lit, isLit := n.(*ast.FuncLit); isLit && lit.Type != nil {
				excludeInto(lit.Type.Params)
				excludeInto(lit.Type.Results)
			}
			return true
		})
	}

	isRVType := func(t types.Type) bool {
		return syntaxutil.IsNamedInPkg(t, "reflect", "Value")
	}
	paramVarSet := collectFuncParamVars(p)
	eligibleLocalRV := map[*types.Var]bool{}
	sealedParamLevel := map[*types.Var]uint8{}
	callableVarLevel := map[*types.Var]uint8{}
	for _, obj := range p.TypesInfo.Defs {
		lv, ok := obj.(*types.Var)
		if !ok || lv == nil || lv.IsField() || lv.Pkg() != p.Types || lv.Parent() == p.Types.Scope() ||
			excludedVars[lv] || addrOrOuterVars[lv] || !isRVType(lv.Type()) {
			continue
		}
		callableVarLevel[lv] = 2
		if paramVarSet[lv] {
			sealedParamLevel[lv] = 2
		} else {
			eligibleLocalRV[lv] = true
		}
	}

	candCallableFields := collectUnexportedStructCandFields(p, addrFields, convertedStructs, isRVType)
	callableFieldLevel := make(map[*types.Var]uint8, len(candCallableFields))
	for fld := range candCallableFields {
		callableFieldLevel[fld] = 2
	}

	var sealedObjLevel func(val *flowir.Value, curSealed map[*types.Var]uint8) uint8
	var callableMethodLevel func(val *flowir.Value, curSealed map[*types.Var]uint8) uint8

	sealedObjLevel = func(val *flowir.Value, curSealed map[*types.Var]uint8) uint8 {
		if val == nil || !isRVType(val.Type) {
			return 0
		}
		switch val.Kind {
		case flowir.ValPlace:
			pl := val.Place
			if pl.IsBareVar() {
				return curSealed[pl.Obj]
			}
			if pl.Root == flowir.RootTransient && pl.Base != nil && len(pl.Projs) == 1 && pl.Projs[0].Kind == flowir.ProjIndex {
				bc := pl.Base
				if bc.Kind == flowir.ValCall && !bc.IsMethodExprCall && !bc.Ellipsis && len(bc.Args) == 1 &&
					isReflectValCallObj(bc.CalleeFunc) && bc.CallAST != nil &&
					isSafeScalarReflectValueCallArg(p, bc.CallAST.Args[0], isTrueStdPkg) &&
					callableMethodLevel(bc.Recv, curSealed) >= 2 {
					return 1
				}
			}
		case flowir.ValCall:
			if val.CalleeFunc == nil || !isTrueStdPkg(val.CalleeFunc.Pkg()) || val.CalleeFunc.Pkg().Path() != "reflect" ||
				val.IsMethodExprCall || val.Ellipsis || hasTupleFirstArg(val) {
				return 0
			}
			switch val.CalleeFunc.Name() {
			case "ValueOf":
				if val.Recv == nil && len(val.Args) == 1 && val.Args[0] != nil {
					return classifyReflectCallRootSealLevel(val.Args[0].Type, isTrueStdPkg)
				}
			case "Field", "FieldByName", "FieldByIndex":
				if val.Recv != nil && len(val.Args) == 1 && val.Args[0] != nil && !typeCanCarryExtractedObject(val.Args[0].Type) {
					return sealedObjLevel(val.Recv, curSealed)
				}
			}
		}
		return 0
	}

	callableMethodLevel = func(val *flowir.Value, curSealed map[*types.Var]uint8) uint8 {
		if val == nil || !isRVType(val.Type) {
			return 0
		}
		switch val.Kind {
		case flowir.ValPlace:
			pl := val.Place
			if pl.IsBareVar() {
				return callableVarLevel[pl.Obj]
			}
			if len(pl.Projs) == 1 && pl.Projs[0].Kind == flowir.ProjField && pl.Projs[0].Field != nil {
				return callableFieldLevel[pl.Projs[0].Field]
			}
		case flowir.ValCall:
			if val.CalleeFunc != nil && isTrueStdPkg(val.CalleeFunc.Pkg()) && val.CalleeFunc.Pkg().Path() == "reflect" &&
				!val.IsMethodExprCall && !val.Ellipsis && !hasTupleFirstArg(val) && val.Recv != nil &&
				len(val.Args) == 1 && val.Args[0] != nil && !typeCanCarryExtractedObject(val.Args[0].Type) {
				switch val.CalleeFunc.Name() {
				case "Method", "MethodByName":
					return sealedObjLevel(val.Recv, curSealed)
				}
			}
		}
		return 0
	}

	type indexedFunc struct {
		fd              *ast.FuncDecl
		fn              *types.Func
		body            *flowir.Body
		opsByNode       map[ast.Node][]*flowir.Op
		rangeBodyByStmt map[*ast.RangeStmt]*flowir.Body
		structuredOK    bool
	}
	indexedFuncs := make([]indexedFunc, 0, len(fc.FuncDecls))
	for _, fd := range fc.FuncDecls {
		if fd == nil || fd.Body == nil {
			continue
		}
		var fn *types.Func
		if fd.Name != nil {
			fn, _ = p.TypesInfo.Defs[fd.Name].(*types.Func)
		}
		b := fc.FuncBody(fd)
		if b == nil {
			if funcDeclHasCall[fd] {
				return false
			}
			continue
		}
		opsByNode := map[ast.Node][]*flowir.Op{}
		rangeBodyByStmt := map[*ast.RangeStmt]*flowir.Body{}
		structuredOK := !b.HasGotoLabelOrFallthrough()
		var idxBody func(curB *flowir.Body)
		idxBody = func(curB *flowir.Body) {
			if curB == nil {
				return
			}
			for i := range curB.Ops {
				op := &curB.Ops[i]
				if op.StmtAST != nil {
					opsByNode[op.StmtAST] = append(opsByNode[op.StmtAST], op)
				} else {
					structuredOK = false
				}
				if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignRange {
					if rs, okR := op.StmtAST.(*ast.RangeStmt); okR {
						rangeBodyByStmt[rs] = op.RangeBody
					}
					if op.RangeBody != nil {
						idxBody(op.RangeBody)
					}
				}
			}
		}
		idxBody(b)
		if funcDeclHasCall[fd] && !structuredOK {
			return false
		}
		indexedFuncs = append(indexedFuncs, indexedFunc{
			fd:              fd,
			fn:              fn,
			body:            b,
			opsByNode:       opsByNode,
			rangeBodyByStmt: rangeBodyByStmt,
			structuredOK:    structuredOK,
		})
	}

	intersectLevels := func(states []map[*types.Var]uint8) map[*types.Var]uint8 {
		if len(states) == 0 {
			return map[*types.Var]uint8{}
		}
		out := maps.Clone(states[0])
		for i := 1; i < len(states); i++ {
			for v, prev := range out {
				next := states[i][v]
				if next == 0 {
					delete(out, v)
				} else if next < prev {
					out[v] = next
				}
			}
		}
		return out
	}

	evictLoopBodyAndPostReassignedVars := func(loopBody *ast.BlockStmt, loopPost ast.Stmt, cur map[*types.Var]uint8) {
		declaredInBody := map[*types.Var]bool{}
		if loopBody != nil {
			ast.Inspect(loopBody, func(n ast.Node) bool {
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
				switch s := n.(type) {
				case *ast.ValueSpec:
					for _, nm := range s.Names {
						if v, ok := p.TypesInfo.Defs[nm].(*types.Var); ok && v != nil {
							declaredInBody[v] = true
						}
					}
				case *ast.AssignStmt:
					if s.Tok == token.DEFINE {
						for _, lhs := range s.Lhs {
							if id, ok := ast.Unparen(lhs).(*ast.Ident); ok {
								if v, okV := p.TypesInfo.Defs[id].(*types.Var); okV && v != nil {
									declaredInBody[v] = true
								}
							}
						}
					}
				case *ast.RangeStmt:
					if s.Tok == token.DEFINE {
						for _, e := range []ast.Expr{s.Key, s.Value} {
							if id, ok := ast.Unparen(e).(*ast.Ident); ok && id != nil {
								if v, okV := p.TypesInfo.Defs[id].(*types.Var); okV && v != nil {
									declaredInBody[v] = true
								}
							}
						}
					}
				}
				return true
			})
		}
		evictAssigned := func(root ast.Node) {
			if root == nil {
				return
			}
			ast.Inspect(root, func(n ast.Node) bool {
				if _, isLit := n.(*ast.FuncLit); isLit {
					return false
				}
				switch s := n.(type) {
				case *ast.AssignStmt:
					for _, lhs := range s.Lhs {
						if id, ok := ast.Unparen(lhs).(*ast.Ident); ok {
							if v, okV := p.TypesInfo.Uses[id].(*types.Var); okV && v != nil && !declaredInBody[v] {
								delete(cur, v)
							}
						}
					}
				case *ast.RangeStmt:
					if s.Tok == token.ASSIGN {
						for _, e := range []ast.Expr{s.Key, s.Value} {
							if id, ok := ast.Unparen(e).(*ast.Ident); ok && id != nil {
								if v, okV := p.TypesInfo.Uses[id].(*types.Var); okV && v != nil && !declaredInBody[v] {
									delete(cur, v)
								}
							}
						}
					}
				}
				return true
			})
		}
		evictAssigned(loopBody)
		evictAssigned(loopPost)
	}

	lowerTo := func(m map[*types.Var]uint8, k *types.Var, lv uint8, changed *bool) {
		if prev := m[k]; prev > lv {
			if lv == 0 {
				delete(m, k)
			} else {
				m[k] = lv
			}
			*changed = true
		}
	}

	var opPreSealed map[*flowir.Op]map[*types.Var]uint8
	for changed := true; changed; {
		changed = false
		opPreSealed = map[*flowir.Op]map[*types.Var]uint8{}

		applyOp := func(op *flowir.Op, cur map[*types.Var]uint8) (map[*types.Var]uint8, bool) {
			opPreSealed[op] = maps.Clone(cur)
			op.ForEachValue(func(root *flowir.Value) bool {
				root.WalkValues(func(v *flowir.Value) bool {
					if v == nil {
						return false
					}
					if v.Kind == flowir.ValAllocFresh && v.AllocKind == flowir.AllocCompositeLit {
						for i := range v.CompositeElts {
							elt := &v.CompositeElts[i]
							if elt.Field != nil && callableFieldLevel[elt.Field] > 0 {
								lowerTo(callableFieldLevel, elt.Field, callableMethodLevel(elt.Value, cur), &changed)
							}
						}
					}
					if v.Kind == flowir.ValCall && v.CalleeFunc != nil && candRVParamFuncs[v.CalleeFunc.Origin()] {
						fnOrig := v.CalleeFunc.Origin()
						if sig, okS := fnOrig.Type().(*types.Signature); okS && sig.Params() != nil {
							tupleCall := hasTupleFirstArg(v)
							for pi := 0; pi < sig.Params().Len(); pi++ {
								pv := sig.Params().At(pi)
								if sealedParamLevel[pv] > 0 {
									if v.IsMethodExprCall || tupleCall || (sig.Variadic() && pi == sig.Params().Len()-1) || pi >= len(v.Args) {
										lowerTo(sealedParamLevel, pv, 0, &changed)
									} else {
										lowerTo(sealedParamLevel, pv, sealedObjLevel(v.Args[pi], cur), &changed)
									}
								}
								if callableVarLevel[pv] > 0 {
									if v.IsMethodExprCall || tupleCall || (sig.Variadic() && pi == sig.Params().Len()-1) || pi >= len(v.Args) {
										lowerTo(callableVarLevel, pv, 0, &changed)
									} else {
										lowerTo(callableVarLevel, pv, callableMethodLevel(v.Args[pi], cur), &changed)
									}
								}
							}
						}
					}
					return true
				})
				return true
			})

			switch op.Kind {
			case flowir.OpReturn:
				return cur, true
			case flowir.OpExpr:
				if op.Expr != nil && op.Expr.Kind == flowir.ValCall && op.Expr.CallKind == flowir.CallBuiltin && op.Expr.BuiltinName == "panic" {
					return cur, true
				}
			case flowir.OpAssign:
				switch op.AssignKind {
				case flowir.AssignZeroDecl:
					for _, dst := range op.Dsts {
						if dst.IsBareVar() && eligibleLocalRV[dst.Obj] {
							cur[dst.Obj] = 2
						}
					}
				case flowir.AssignPlain:
					if len(op.Dsts) == len(op.Srcs) {
						rhsSealed := make([]uint8, len(op.Srcs))
						rhsCallable := make([]uint8, len(op.Srcs))
						for i := range op.Srcs {
							rhsSealed[i] = sealedObjLevel(op.Srcs[i], cur)
							rhsCallable[i] = callableMethodLevel(op.Srcs[i], cur)
						}
						for i, dst := range op.Dsts {
							if dst.Obj != nil {
								if dst.IsBareVar() && (eligibleLocalRV[dst.Obj] || sealedParamLevel[dst.Obj] > 0) && rhsSealed[i] > 0 {
									cur[dst.Obj] = rhsSealed[i]
								} else {
									delete(cur, dst.Obj)
								}
								if callableVarLevel[dst.Obj] > 0 {
									if dst.IsBareVar() {
										lowerTo(callableVarLevel, dst.Obj, rhsCallable[i], &changed)
									} else {
										lowerTo(callableVarLevel, dst.Obj, 0, &changed)
									}
								}
							}
							if len(dst.Projs) > 0 {
								last := dst.Projs[len(dst.Projs)-1]
								if last.Kind == flowir.ProjField && last.Field != nil && callableFieldLevel[last.Field] > 0 {
									if len(dst.Projs) == 1 {
										lowerTo(callableFieldLevel, last.Field, rhsCallable[i], &changed)
									} else {
										lowerTo(callableFieldLevel, last.Field, 0, &changed)
									}
								}
							}
						}
						break
					}
					fallthrough
				default:
					for _, dst := range op.Dsts {
						if dst.Obj != nil {
							delete(cur, dst.Obj)
							lowerTo(callableVarLevel, dst.Obj, 0, &changed)
						}
						if len(dst.Projs) > 0 {
							last := dst.Projs[len(dst.Projs)-1]
							if last.Kind == flowir.ProjField && last.Field != nil {
								lowerTo(callableFieldLevel, last.Field, 0, &changed)
							}
						}
					}
				}
			}
			return cur, false
		}

		for fi := range indexedFuncs {
			fnInfo := &indexedFuncs[fi]
			entry := map[*types.Var]uint8{}
			if fnInfo.fn != nil {
				if sig, okS := fnInfo.fn.Type().(*types.Signature); okS && sig.Params() != nil {
					for pi := 0; pi < sig.Params().Len(); pi++ {
						pv := sig.Params().At(pi)
						if lv := sealedParamLevel[pv]; lv > 0 {
							entry[pv] = lv
						}
					}
				}
			}
			if !fnInfo.structuredOK {
				empty := map[*types.Var]uint8{}
				forEachBodyAndClosureOp(fnInfo.fn, nil, fnInfo.body, fnInfo.body, func(_ *types.Func, _ *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
					_, _ = applyOp(op, maps.Clone(empty))
					return true
				})
				continue
			}

			const (
				termNone = iota
				termDeadEnd
			)
			var switchBreaks [][]map[*types.Var]uint8

			applyNode := func(n ast.Node, cur map[*types.Var]uint8) (map[*types.Var]uint8, int) {
				for _, op := range fnInfo.opsByNode[n] {
					var dead bool
					cur, dead = applyOp(op, cur)
					if dead {
						return cur, termDeadEnd
					}
				}
				return cur, termNone
			}

			var walkStmt func(st ast.Stmt, cur map[*types.Var]uint8, inSwitch bool) (map[*types.Var]uint8, int)
			walkList := func(list []ast.Stmt, cur map[*types.Var]uint8, inSwitch bool) (map[*types.Var]uint8, int) {
				for _, s := range list {
					if s == nil {
						continue
					}
					var tk int
					cur, tk = walkStmt(s, cur, inSwitch)
					if tk != termNone {
						return cur, tk
					}
				}
				return cur, termNone
			}

			walkStmt = func(st ast.Stmt, cur map[*types.Var]uint8, inSwitch bool) (map[*types.Var]uint8, int) {
				switch s := st.(type) {
				case nil, *ast.EmptyStmt:
					return cur, termNone
				case *ast.BlockStmt:
					return walkList(s.List, cur, inSwitch)
				case *ast.DeclStmt:
					if gd, okG := s.Decl.(*ast.GenDecl); okG && (gd.Tok == token.VAR || gd.Tok == token.CONST) {
						for _, spec := range gd.Specs {
							if vs, okV := spec.(*ast.ValueSpec); okV {
								var tk int
								cur, tk = applyNode(vs, cur)
								if tk != termNone {
									return cur, tk
								}
							}
						}
					}
					return cur, termNone
				case *ast.ExprStmt, *ast.SendStmt, *ast.IncDecStmt, *ast.AssignStmt, *ast.GoStmt, *ast.DeferStmt, *ast.ReturnStmt:
					return applyNode(s, cur)
				case *ast.BranchStmt:
					_, _ = applyNode(s, cur)
					if s.Tok == token.BREAK && inSwitch && len(switchBreaks) > 0 {
						top := len(switchBreaks) - 1
						switchBreaks[top] = append(switchBreaks[top], maps.Clone(cur))
					}
					return cur, termDeadEnd
				case *ast.IfStmt:
					if s.Init != nil {
						var tk int
						cur, tk = walkStmt(s.Init, cur, inSwitch)
						if tk != termNone {
							return cur, tk
						}
					}
					if s.Cond != nil {
						var tk int
						cur, tk = applyNode(s, cur)
						if tk != termNone {
							return cur, tk
						}
					}
					thenIn := maps.Clone(cur)
					if narVar, narLv := extractReflectInterfaceTypeAssertNarrowing(p, s, eligibleLocalRV, sealedParamLevel, addrOrOuterVars, isTrueStdPkg); narVar != nil && narLv > thenIn[narVar] {
						thenIn[narVar] = narLv
					}
					thenSt, thenTK := walkList(s.Body.List, thenIn, inSwitch)
					elseSt, elseTK := maps.Clone(cur), termNone
					if s.Else != nil {
						elseSt, elseTK = walkStmt(s.Else, maps.Clone(cur), inSwitch)
					}
					if thenTK != termNone && elseTK != termNone {
						return map[*types.Var]uint8{}, termDeadEnd
					}
					if thenTK != termNone {
						return elseSt, termNone
					}
					if elseTK != termNone {
						return thenSt, termNone
					}
					return intersectLevels([]map[*types.Var]uint8{thenSt, elseSt}), termNone
				case *ast.SwitchStmt, *ast.TypeSwitchStmt:
					var bodyBlk *ast.BlockStmt
					if sw, isSw := s.(*ast.SwitchStmt); isSw {
						bodyBlk = sw.Body
						if sw.Init != nil {
							var tk int
							cur, tk = walkStmt(sw.Init, cur, inSwitch)
							if tk != termNone {
								return cur, tk
							}
						}
						if sw.Tag != nil {
							_, _ = applyNode(sw, cur)
						}
					} else if tsw, isTSw := s.(*ast.TypeSwitchStmt); isTSw {
						bodyBlk = tsw.Body
						if tsw.Init != nil {
							var tk int
							cur, tk = walkStmt(tsw.Init, cur, inSwitch)
							if tk != termNone {
								return cur, tk
							}
						}
						_, _ = applyNode(tsw, cur)
					}
					switchBreaks = append(switchBreaks, nil)
					var outs []map[*types.Var]uint8
					hasDefault := false
					if bodyBlk != nil {
						for _, raw := range bodyBlk.List {
							if cc, okC := raw.(*ast.CaseClause); okC {
								if cc.List == nil {
									hasDefault = true
								}
								cCur := maps.Clone(cur)
								_, _ = applyNode(cc, cCur)
								outSt, tk := walkList(cc.Body, cCur, true)
								if tk == termNone {
									outs = append(outs, outSt)
								}
							}
						}
					}
					outs = append(outs, switchBreaks[len(switchBreaks)-1]...)
					switchBreaks = switchBreaks[:len(switchBreaks)-1]
					if !hasDefault {
						outs = append(outs, maps.Clone(cur))
					}
					if len(outs) == 0 {
						return map[*types.Var]uint8{}, termDeadEnd
					}
					return intersectLevels(outs), termNone
				case *ast.ForStmt:
					if s.Init != nil {
						var tk int
						cur, tk = walkStmt(s.Init, cur, false)
						if tk != termNone {
							return cur, tk
						}
					}
					evictLoopBodyAndPostReassignedVars(s.Body, s.Post, cur)
					if s.Cond != nil {
						_, _ = applyNode(s, cur)
					}
					if s.Body != nil {
						_, _ = walkList(s.Body.List, maps.Clone(cur), false)
					}
					if s.Post != nil {
						_, _ = walkStmt(s.Post, maps.Clone(cur), false)
					}
					return cur, termNone
				case *ast.RangeStmt:
					evictLoopBodyAndPostReassignedVars(s.Body, nil, cur)
					_, _ = applyNode(s, cur)
					if rb := fnInfo.rangeBodyByStmt[s]; rb != nil && rb.Block != nil {
						_, _ = walkList(rb.Block.List, maps.Clone(cur), false)
					}
					return cur, termNone
				default:
					empty := map[*types.Var]uint8{}
					ast.Inspect(s, func(n ast.Node) bool {
						for _, op := range fnInfo.opsByNode[n] {
							_, _ = applyOp(op, maps.Clone(empty))
						}
						return true
					})
					return empty, termNone
				}
			}

			_, _ = walkList(fnInfo.fd.Body.List, entry, false)
			forEachBodyAndClosureOp(fnInfo.fn, nil, fnInfo.body, fnInfo.body, func(_ *types.Func, enclLit *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
				if enclLit != nil {
					_, _ = applyOp(op, map[*types.Var]uint8{})
				}
				return true
			})
		}

		for _, gd := range fc.GenDecls {
			if gd == nil {
				continue
			}
			b := fc.Body(gd)
			forEachBodyAndClosureOp(nil, nil, b, b, func(_ *types.Func, _ *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
				_, _ = applyOp(op, map[*types.Var]uint8{})
				return true
			})
		}
	}

	allVerified := true
	forEachPkgFlowOp(p, fc, func(_ *types.Func, _ *ast.FuncLit, _ *flowir.Body, op *flowir.Op) bool {
		op.ForEachValue(func(root *flowir.Value) bool {
			root.WalkValues(func(v *flowir.Value) bool {
				if !allVerified || v == nil {
					return false
				}
				if v.Kind == flowir.ValCall && isReflectValCallObj(v.CalleeFunc) {
					pre := opPreSealed[op]
					if v.IsMethodExprCall || v.Ellipsis || len(v.Args) != 1 || v.CallAST == nil ||
						!isSafeScalarReflectValueCallArg(p, v.CallAST.Args[0], isTrueStdPkg) ||
						callableMethodLevel(v.Recv, pre) == 0 {
						emitExtractEscape(ctx, p, traceTarget, "reflect_call_unsealed_recv", "", v.Raw)
						allVerified = false
						return false
					}
				}
				return true
			})
			return allVerified
		})
		return allVerified
	})
	return allVerified
}
