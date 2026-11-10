package seams

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func pkgMutatesTestingStruct(p *packages.Package) bool {
	if p == nil || p.TypesInfo == nil {
		return false
	}
	checkLHS := func(expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		switch e := ast.Unparen(expr).(type) {
		case *ast.StarExpr:
			if tv, ok := p.TypesInfo.Types[e.X]; ok && concreteTestingHandleKind(tv.Type) != "" {
				return true
			}
		case *ast.SelectorExpr:
			if tv, ok := p.TypesInfo.Types[e.X]; ok && tv.Type != nil {
				if concreteTestingHandleKind(tv.Type) != "" || concreteTestingHandleKind(types.NewPointer(tv.Type)) != "" {
					return true
				}
			}
		}
		return false
	}
	for _, file := range p.Syntax {
		mutated := false
		ast.Inspect(file, func(n ast.Node) bool {
			if mutated || n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range node.Lhs {
					if checkLHS(lhs) {
						mutated = true
						return false
					}
				}
			case *ast.IncDecStmt:
				if checkLHS(node.X) {
					mutated = true
					return false
				}
			case *ast.RangeStmt:
				if checkLHS(node.Key) || checkLHS(node.Value) {
					mutated = true
					return false
				}
			}
			return true
		})
		if mutated {
			return true
		}
	}
	return false
}

// computeLiveTestingHandles computes, for each callable block (fd.Body or
// sequential FuncLit.Body) in *_test.go files of p, the set of own concrete
// *testing.T/*testing.B/*testing.F parameter variables proven to originate
// solely from uncalled Go test/benchmark/fuzz runner entries.
func computeLiveTestingHandles(p *packages.Package, graph CallGraph) map[*ast.BlockStmt]map[*types.Var]bool {
	if p == nil || p.TypesInfo == nil || p.Fset == nil || pkgMutatesTestingStruct(p) {
		return nil
	}
	useCount := map[*types.Func]int{}
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				if fn, ok := p.TypesInfo.Uses[id].(*types.Func); ok && fn != nil {
					useCount[fn.Origin()]++
				}
			}
			return true
		})
	}

	isTestFileDecl := func(fd *ast.FuncDecl) bool {
		if fd == nil || !fd.Pos().IsValid() {
			return false
		}
		return strings.HasSuffix(p.Fset.Position(fd.Pos()).Filename, "_test.go")
	}

	type helperCallSite struct {
		callerBody *ast.BlockStmt
		call       *ast.CallExpr
	}
	type subRunnerEdge struct {
		parentBody *ast.BlockStmt
		recvID     *ast.Ident
		lit        *ast.FuncLit
		param0     *types.Var
	}
	type localCallEdge struct {
		lit        *ast.FuncLit
		params     []*types.Var
		callerBody []*ast.BlockStmt
		calls      []*ast.CallExpr
	}

	liveInBody := map[*ast.BlockStmt]map[*types.Var]bool{}
	markLive := func(body *ast.BlockStmt, v *types.Var) bool {
		if body == nil || v == nil {
			return false
		}
		if liveInBody[body] == nil {
			liveInBody[body] = map[*types.Var]bool{}
		}
		if liveInBody[body][v] {
			return false
		}
		liveInBody[body][v] = true
		return true
	}

	fnParams := map[*types.Func][]*types.Var{}
	fnBody := map[*types.Func]*ast.BlockStmt{}
	mutatedOrAddrVar := map[*types.Var]bool{}
	helperSites := map[*types.Func][]helperCallSite{}
	var subEdges []subRunnerEdge
	var localEdges []localCallEdge

	extractFieldListParamVars := func(fl *ast.FieldList) []*types.Var {
		if fl == nil {
			return nil
		}
		var out []*types.Var
		for _, field := range fl.List {
			if len(field.Names) == 0 {
				out = append(out, nil)
				continue
			}
			for _, name := range field.Names {
				v, _ := p.TypesInfo.Defs[name].(*types.Var)
				out = append(out, v)
			}
		}
		return out
	}

	for fn, fd := range graph.DeclPlainFuncs {
		if !isTestFileDecl(fd) || graph.Blocked[fn] || fd.Body == nil || bodyHasGoOrParallel(p.TypesInfo, fd.Body) {
			continue
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig == nil {
			continue
		}
		params := extractFieldListParamVars(fd.Type.Params)
		fnParams[fn] = params
		fnBody[fn] = fd.Body

		// Record writes and address-takes of local/parameter variables inside fd.Body.
		localWrites := map[types.Object]int{}
		localFuncLit := map[types.Object]*ast.FuncLit{}
		localReadCalls := map[types.Object][]*ast.CallExpr{}
		localReadBodies := map[types.Object][]*ast.BlockStmt{}
		localReadCount := map[types.Object]int{}
		validWriteIdent := map[*ast.Ident]bool{}

		recordVarWrite := func(expr ast.Expr) {
			if expr == nil {
				return
			}
			ast.Inspect(expr, func(inner ast.Node) bool {
				if id, ok := inner.(*ast.Ident); ok {
					if obj := syntaxutil.IdentDefOrUse(p.TypesInfo, id); obj != nil {
						localWrites[obj]++
						if v, ok := obj.(*types.Var); ok && v != nil {
							mutatedOrAddrVar[v] = true
						}
					}
				}
				return true
			})
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			switch node := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					recordVarWrite(lhs)
					if id, ok := ast.Unparen(lhs).(*ast.Ident); ok && i < len(node.Rhs) {
						if obj := syntaxutil.IdentDefOrUse(p.TypesInfo, id); obj != nil {
							if lit, ok := ast.Unparen(node.Rhs[i]).(*ast.FuncLit); ok && !graph.NonSeqLits[lit] {
								validWriteIdent[id] = true
								localFuncLit[obj] = lit
							}
						}
					}
				}
			case *ast.ValueSpec:
				for i, name := range node.Names {
					if obj := p.TypesInfo.Defs[name]; obj != nil {
						localWrites[obj]++
						if v, ok := obj.(*types.Var); ok && v != nil {
							mutatedOrAddrVar[v] = true
						}
						if i < len(node.Values) {
							if lit, ok := ast.Unparen(node.Values[i]).(*ast.FuncLit); ok && !graph.NonSeqLits[lit] {
								validWriteIdent[name] = true
								localFuncLit[obj] = lit
							}
						}
					}
				}
			case *ast.IncDecStmt:
				recordVarWrite(node.X)
			case *ast.RangeStmt:
				recordVarWrite(node.Key)
				recordVarWrite(node.Value)
			case *ast.UnaryExpr:
				if node.Op == token.AND {
					ast.Inspect(node.X, func(inner ast.Node) bool {
						if id, ok := inner.(*ast.Ident); ok {
							if v, ok := syntaxutil.IdentDefOrUse(p.TypesInfo, id).(*types.Var); ok && v != nil {
								mutatedOrAddrVar[v] = true
							}
						}
						return true
					})
				}
			}
			return true
		})

		immutableLitForObj := func(obj types.Object) *ast.FuncLit {
			v, ok := obj.(*types.Var)
			if !ok || v == nil || localWrites[obj] != 1 {
				return nil
			}
			// Must not have &v taken; note mutatedOrAddrVar[v] is set on the single write,
			// so check explicit address-takes separately below.
			return localFuncLit[obj]
		}
		addrTakenLocal := map[types.Object]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.AND {
				ast.Inspect(u.X, func(inner ast.Node) bool {
					if id, ok := inner.(*ast.Ident); ok {
						if obj := syntaxutil.IdentDefOrUse(p.TypesInfo, id); obj != nil {
							addrTakenLocal[obj] = true
						}
					}
					return true
				})
			}
			return true
		})

		subCallbackArgIdent := map[*ast.Ident]bool{}
		directLocalCallIdent := map[*ast.Ident]bool{}
		var walkSeq func(n ast.Node, curBody *ast.BlockStmt)
		walkSeq = func(n ast.Node, curBody *ast.BlockStmt) {
			if n == nil {
				return
			}
			switch node := n.(type) {
			case *ast.GoStmt:
				return
			case *ast.FuncLit:
				if graph.NonSeqLits[node] {
					return
				}
				if node.Body != nil {
					walkSeq(node.Body, node.Body)
				}
				return
			case *ast.CallExpr:
				if !node.Ellipsis.IsValid() {
					// 1. Direct plain package helper call.
					if callee, _ := syntaxutil.PlainCalleeFunc(p, node.Fun); callee != nil && graph.DeclPlainFuncs[callee] != nil && !callee.Exported() {
						helperSites[callee] = append(helperSites[callee], helperCallSite{
							callerBody: curBody,
							call:       node,
						})
					}
					// 2. Synchronous t.Run / b.Run / f.Fuzz sub-runner call.
					syncName := testingSyncMethodName(p.TypesInfo, node)
					if (syncName == "Run" && len(node.Args) == 2) || (syncName == "Fuzz" && len(node.Args) == 1) {
						cbIdx := 0
						if syncName == "Run" {
							cbIdx = 1
						}
						if sel, ok := ast.Unparen(node.Fun).(*ast.SelectorExpr); ok {
							if recvID, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
								var cbLit *ast.FuncLit
								switch cb := ast.Unparen(node.Args[cbIdx]).(type) {
								case *ast.FuncLit:
									if !graph.NonSeqLits[cb] {
										cbLit = cb
									}
								case *ast.Ident:
									if obj := p.TypesInfo.Uses[cb]; obj != nil && !addrTakenLocal[obj] {
										if lit := immutableLitForObj(obj); lit != nil {
											cbLit = lit
											subCallbackArgIdent[cb] = true
										}
									}
								}
								if cbLit != nil && cbLit.Type != nil && cbLit.Body != nil {
									litParams := extractFieldListParamVars(cbLit.Type.Params)
									if len(litParams) >= 1 && litParams[0] != nil {
										subEdges = append(subEdges, subRunnerEdge{
											parentBody: curBody,
											recvID:     recvID,
											lit:        cbLit,
											param0:     litParams[0],
										})
									}
								}
							}
						}
					}
					// 3. Direct IIFE or local FuncLit variable call.
					switch fun := ast.Unparen(node.Fun).(type) {
					case *ast.FuncLit:
						if !graph.NonSeqLits[fun] && fun.Type != nil && fun.Body != nil {
							localEdges = append(localEdges, localCallEdge{
								lit:        fun,
								params:     extractFieldListParamVars(fun.Type.Params),
								callerBody: []*ast.BlockStmt{curBody},
								calls:      []*ast.CallExpr{node},
							})
						}
					case *ast.Ident:
						if obj := p.TypesInfo.Uses[fun]; obj != nil && !addrTakenLocal[obj] && immutableLitForObj(obj) != nil {
							directLocalCallIdent[fun] = true
							localReadCalls[obj] = append(localReadCalls[obj], node)
							localReadBodies[obj] = append(localReadBodies[obj], curBody)
						}
					}
				}
			case *ast.Ident:
				if !validWriteIdent[node] {
					if obj := p.TypesInfo.Uses[node]; obj != nil && localFuncLit[obj] != nil {
						localReadCount[obj]++
					}
				}
			}
			ast.Inspect(n, func(child ast.Node) bool {
				if child == nil || child == n {
					return true
				}
				walkSeq(child, curBody)
				return false
			})
		}
		walkSeq(fd.Body, fd.Body)

		// Filter subEdges whose bound local had any extra read beyond the sub-runner arg.
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || validWriteIdent[id] {
				return true
			}
			if obj := p.TypesInfo.Uses[id]; obj != nil && localFuncLit[obj] != nil {
				if subCallbackArgIdent[id] && localReadCount[obj] != 1 {
					// Invalidate any subEdge using this lit.
					badLit := localFuncLit[obj]
					for i := range subEdges {
						if subEdges[i].lit == badLit {
							subEdges[i].param0 = nil
						}
					}
				}
			}
			return true
		})

		for obj, lit := range localFuncLit {
			if addrTakenLocal[obj] || localWrites[obj] != 1 || lit == nil || lit.Type == nil || lit.Body == nil {
				continue
			}
			calls := localReadCalls[obj]
			if len(calls) == 0 || len(calls) != localReadCount[obj] {
				continue
			}
			localEdges = append(localEdges, localCallEdge{
				lit:        lit,
				params:     extractFieldListParamVars(lit.Type.Params),
				callerBody: localReadBodies[obj],
				calls:      calls,
			})
		}

		// Base case: uncalled Go test / benchmark / fuzz runner root in *_test.go.
		if useCount[fn] == 0 && !sig.Variadic() && sig.Params().Len() == 1 && sig.Results().Len() == 0 && len(params) == 1 && params[0] != nil && !mutatedOrAddrVar[params[0]] {
			kind := concreteTestingHandleKind(params[0].Type())
			name := fn.Name()
			isRunner := (name != "TestMain" && isGoTestRunnerName(name, "Test") && kind == "T") ||
				(isGoTestRunnerName(name, "Benchmark") && kind == "B") ||
				(isGoTestRunnerName(name, "Fuzz") && kind == "F")
			if isRunner {
				markLive(fd.Body, params[0])
			}
		}
	}

	argIsLiveInBody := func(body *ast.BlockStmt, expr ast.Expr) bool {
		if body == nil || expr == nil {
			return false
		}
		id, ok := ast.Unparen(expr).(*ast.Ident)
		if !ok {
			return false
		}
		v, ok := p.TypesInfo.Uses[id].(*types.Var)
		return ok && v != nil && liveInBody[body][v]
	}

	for changed := true; changed; {
		changed = false
		// 1. Synchronous sub-runner callbacks (t.Run / b.Run / f.Fuzz).
		for _, se := range subEdges {
			if se.param0 == nil || mutatedOrAddrVar[se.param0] || concreteTestingHandleKind(se.param0.Type()) == "" {
				continue
			}
			if argIsLiveInBody(se.parentBody, se.recvID) {
				if markLive(se.lit.Body, se.param0) {
					changed = true
				}
			}
		}
		// 2. Direct local closure helpers / IIFEs.
		for _, le := range localEdges {
			if le.lit == nil || le.lit.Body == nil || len(le.calls) == 0 {
				continue
			}
			tv, ok := p.TypesInfo.Types[le.lit]
			if !ok || tv.Type == nil {
				continue
			}
			sig, ok := tv.Type.Underlying().(*types.Signature)
			if !ok || sig == nil || sig.Variadic() {
				continue
			}
			for pIdx, pv := range le.params {
				if pv == nil || mutatedOrAddrVar[pv] || concreteTestingHandleKind(pv.Type()) == "" {
					continue
				}
				allLive := true
				for ci, call := range le.calls {
					if len(call.Args) != sig.Params().Len() || pIdx >= len(call.Args) || !argIsLiveInBody(le.callerBody[ci], call.Args[pIdx]) {
						allLive = false
						break
					}
				}
				if allLive && markLive(le.lit.Body, pv) {
					changed = true
				}
			}
		}
		// 3. Unexported sequential *_test.go helper functions whose every intra-package
		// reference is a direct sequential call passing a live handle.
		for callee, sites := range helperSites {
			if len(sites) == 0 || len(sites) != useCount[callee] {
				continue
			}
			sig, ok := callee.Type().(*types.Signature)
			if !ok || sig == nil || sig.Variadic() {
				continue
			}
			body := fnBody[callee]
			params := fnParams[callee]
			if body == nil {
				continue
			}
			for pIdx, pv := range params {
				if pv == nil || mutatedOrAddrVar[pv] || concreteTestingHandleKind(pv.Type()) == "" {
					continue
				}
				allLive := true
				for _, site := range sites {
					if len(site.call.Args) != sig.Params().Len() || pIdx >= len(site.call.Args) || !argIsLiveInBody(site.callerBody, site.call.Args[pIdx]) {
						allLive = false
						break
					}
				}
				if allLive && markLive(body, pv) {
					changed = true
				}
			}
		}
	}
	return liveInBody
}
