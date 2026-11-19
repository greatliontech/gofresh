package propharness

import (
	"go/ast"
	"go/token"
	"go/types"
)

// collectEnvFlagCategoryAVars computes via inter-procedural fixed point over
// package-level var initializers, init() bodies, and init-only helpers the
// subset of categoryA package variables whose settled state may depend on
// command-line flags or environment lookups (propagating control-dependent
// helper calls, tainted parameters/results, and local slice/map/pointer aliases
// of categoryA globals).
func collectEnvFlagCategoryAVars(g *harnessGraph, categoryA map[*types.Var]bool) map[*types.Var]bool {
	if len(categoryA) == 0 {
		return nil
	}
	info := g.info
	envReadingInit := map[*types.Func]bool{}
	for fn := range g.initOnly {
		fd := g.declFuncs[fn]
		if fd == nil || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && osEnvLookupIdent(info, id) != nil {
				envReadingInit[fn] = true
				return false
			}
			return true
		})
	}
	for changed := true; changed; {
		changed = false
		for fn := range g.initOnly {
			if envReadingInit[fn] {
				continue
			}
			fd := g.declFuncs[fn]
			if fd == nil || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if callee := resolveHarnessFuncExpr(info, call.Fun); callee != nil && envReadingInit[callee.Origin()] {
						envReadingInit[fn] = true
						changed = true
						return false
					}
				}
				return true
			})
		}
	}

	envFlagVars := map[*types.Var]bool{}
	condEnvInitFuncs := map[*types.Func]bool{}
	taintedInitParams := map[harnessParamKey]bool{}
	envResultInitFuncs := map[*types.Func]bool{}
	paramAliases := map[harnessParamKey]map[*types.Var]bool{}
	returnAliases := map[*types.Func]map[*types.Var]bool{}

	exprTouchesEnv := func(root ast.Node, envLocals map[*types.Var]bool) bool {
		hit := false
		ast.Inspect(root, func(n ast.Node) bool {
			if hit || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.Ident:
				if osEnvLookupIdent(info, x) != nil {
					hit = true
					return false
				}
				if v, ok := info.Uses[x].(*types.Var); ok && (envLocals[v] || envFlagVars[v]) {
					hit = true
					return false
				}
			case *ast.CallExpr:
				if callee := resolveHarnessFuncExpr(info, x.Fun); callee != nil {
					orig := callee.Origin()
					if envReadingInit[orig] || envResultInitFuncs[orig] {
						hit = true
						return false
					}
				}
			}
			return true
		})
		return hit
	}

	rootLocalVar := func(e ast.Expr) *types.Var {
		pkgScope := g.pkgTypes.Scope()
		for e != nil {
			switch x := ast.Unparen(e).(type) {
			case *ast.Ident:
				if v := lookupLocalVar(info, pkgScope, x); v != nil {
					return v
				}
				return nil
			case *ast.SelectorExpr:
				if sel := info.Selections[x]; sel != nil && sel.Kind() == types.FieldVal {
					e = x.X
					continue
				}
				return nil
			case *ast.IndexExpr:
				e = x.X
			case *ast.SliceExpr:
				e = x.X
			case *ast.StarExpr:
				e = x.X
			default:
				return nil
			}
		}
		return nil
	}

	addAliasSet := func(dst map[*types.Var]map[*types.Var]bool, lv *types.Var, src map[*types.Var]bool) bool {
		if lv == nil || len(src) == 0 {
			return false
		}
		added := false
		for gv := range src {
			if dst[lv] == nil {
				dst[lv] = map[*types.Var]bool{}
			}
			if !dst[lv][gv] {
				dst[lv][gv] = true
				added = true
			}
		}
		return added
	}

	for _, entry := range g.pkgVars {
		if categoryA[entry.v] && entry.val != nil && exprTouchesEnv(entry.val, nil) {
			envFlagVars[entry.v] = true
		}
	}

	scanInitBody := func(body *ast.BlockStmt, curFn *types.Func) bool {
		if body == nil {
			return false
		}
		envLocals := map[*types.Var]bool{}
		localAliases := map[*types.Var]map[*types.Var]bool{}
		startCondEnv := false
		if curFn != nil {
			startCondEnv = condEnvInitFuncs[curFn]
			sig := curFn.Signature()
			if sig != nil {
				for pi := 0; pi < sig.Params().Len(); pi++ {
					pv := sig.Params().At(pi)
					pk := harnessParamKey{fn: curFn, idx: pi}
					if taintedInitParams[pk] {
						envLocals[pv] = true
					}
					addAliasSet(localAliases, pv, paramAliases[pk])
				}
			}
		}
		collectAliasVars := func(root ast.Node) map[*types.Var]bool {
			var out map[*types.Var]bool
			add := func(gv *types.Var) {
				if gv != nil && categoryA[gv] {
					if out == nil {
						out = map[*types.Var]bool{}
					}
					out[gv] = true
				}
			}
			ast.Inspect(root, func(n ast.Node) bool {
				if n == nil {
					return false
				}
				switch x := n.(type) {
				case *ast.Ident:
					if v, ok := info.Uses[x].(*types.Var); ok && v != nil {
						if categoryA[v] {
							add(v)
						}
						for gv := range localAliases[v] {
							add(gv)
						}
					}
				case *ast.CallExpr:
					if callee := resolveHarnessFuncExpr(info, x.Fun); callee != nil {
						for gv := range returnAliases[callee.Origin()] {
							add(gv)
						}
					}
				}
				return true
			})
			return out
		}

		progressedSummary := false
		for changed := true; changed; {
			changed = false
			markTarget := func(target ast.Expr, forceAliasWrite bool) {
				if target == nil {
					return
				}
				if rv := rootPkgVar(info, target, g.pkgVarSet); rv != nil && categoryA[rv] && !envFlagVars[rv] {
					envFlagVars[rv] = true
					changed = true
					progressedSummary = true
				}
				if lv := rootLocalVar(target); lv != nil {
					if !envLocals[lv] {
						envLocals[lv] = true
						changed = true
					}
					_, isBareID := ast.Unparen(target).(*ast.Ident)
					if forceAliasWrite || !isBareID {
						for gv := range localAliases[lv] {
							if categoryA[gv] && !envFlagVars[gv] {
								envFlagVars[gv] = true
								changed = true
								progressedSummary = true
							}
						}
					}
				}
			}

			var walk func(n ast.Node, condEnv bool)
			walk = func(n ast.Node, condEnv bool) {
				if n == nil {
					return
				}
				switch x := n.(type) {
				case *ast.IfStmt:
					nextEnv := condEnv || (x.Init != nil && exprTouchesEnv(x.Init, envLocals)) || exprTouchesEnv(x.Cond, envLocals)
					if x.Init != nil {
						walk(x.Init, nextEnv)
					}
					if x.Cond != nil {
						walk(x.Cond, nextEnv)
					}
					walk(x.Body, nextEnv)
					if x.Else != nil {
						walk(x.Else, nextEnv)
					}
					return
				case *ast.SwitchStmt:
					nextEnv := condEnv || (x.Init != nil && exprTouchesEnv(x.Init, envLocals)) || (x.Tag != nil && exprTouchesEnv(x.Tag, envLocals))
					if x.Init != nil {
						walk(x.Init, nextEnv)
					}
					if x.Tag != nil {
						walk(x.Tag, nextEnv)
					}
					walk(x.Body, nextEnv)
					return
				case *ast.TypeSwitchStmt:
					nextEnv := condEnv || (x.Init != nil && exprTouchesEnv(x.Init, envLocals)) || exprTouchesEnv(x.Assign, envLocals)
					if x.Init != nil {
						walk(x.Init, nextEnv)
					}
					walk(x.Assign, nextEnv)
					walk(x.Body, nextEnv)
					return
				case *ast.SelectStmt:
					nextEnv := condEnv || exprTouchesEnv(x.Body, envLocals)
					walk(x.Body, nextEnv)
					return
				case *ast.ForStmt:
					nextEnv := condEnv ||
						(x.Init != nil && exprTouchesEnv(x.Init, envLocals)) ||
						(x.Cond != nil && exprTouchesEnv(x.Cond, envLocals)) ||
						(x.Post != nil && exprTouchesEnv(x.Post, envLocals))
					if x.Init != nil {
						walk(x.Init, nextEnv)
					}
					if x.Cond != nil {
						walk(x.Cond, nextEnv)
					}
					if x.Post != nil {
						walk(x.Post, nextEnv)
					}
					walk(x.Body, nextEnv)
					return
				case *ast.RangeStmt:
					rngAliases := collectAliasVars(x.X)
					if kv := rootLocalVar(x.Key); addAliasSet(localAliases, kv, rngAliases) {
						changed = true
					}
					if vv := rootLocalVar(x.Value); addAliasSet(localAliases, vv, rngAliases) {
						changed = true
					}
					nextEnv := condEnv || exprTouchesEnv(x.X, envLocals)
					if x.X != nil {
						walk(x.X, nextEnv)
					}
					if nextEnv {
						markTarget(x.Key, false)
						markTarget(x.Value, false)
					}
					walk(x.Body, nextEnv)
					return
				case *ast.ValueSpec:
					for i, nm := range x.Names {
						var rhsNode ast.Node
						if i < len(x.Values) {
							rhsNode = x.Values[i]
						} else if len(x.Values) == 1 && len(x.Names) > 1 {
							rhsNode = x.Values[0]
						}
						if rhsNode != nil {
							if lv := rootLocalVar(nm); addAliasSet(localAliases, lv, collectAliasVars(rhsNode)) {
								changed = true
							}
						}
						rhsEnv := condEnv || (rhsNode != nil && exprTouchesEnv(rhsNode, envLocals))
						if rhsEnv {
							markTarget(nm, false)
						}
					}
				case *ast.AssignStmt:
					var rhsAliases map[*types.Var]bool
					rhsEnv := condEnv
					for _, rhs := range x.Rhs {
						if exprTouchesEnv(rhs, envLocals) {
							rhsEnv = true
						}
						for gv := range collectAliasVars(rhs) {
							if rhsAliases == nil {
								rhsAliases = map[*types.Var]bool{}
							}
							rhsAliases[gv] = true
						}
					}
					for _, lhs := range x.Lhs {
						if _, isBareID := ast.Unparen(lhs).(*ast.Ident); isBareID {
							if lv := rootLocalVar(lhs); addAliasSet(localAliases, lv, rhsAliases) {
								changed = true
							}
						}
						if rhsEnv {
							markTarget(lhs, false)
						}
					}
				case *ast.IncDecStmt:
					if condEnv || exprTouchesEnv(x.X, envLocals) {
						markTarget(x.X, false)
					}
				case *ast.SendStmt:
					if condEnv || exprTouchesEnv(x.Value, envLocals) {
						markTarget(x.Chan, true)
					}
				case *ast.ReturnStmt:
					if curFn != nil {
						retEnv := condEnv
						if len(x.Results) == 0 && curFn.Signature() != nil && curFn.Signature().Results() != nil {
							resTuple := curFn.Signature().Results()
							for ri := 0; ri < resTuple.Len(); ri++ {
								rv := resTuple.At(ri)
								if envLocals[rv] {
									retEnv = true
								}
								for gv := range localAliases[rv] {
									if returnAliases[curFn] == nil {
										returnAliases[curFn] = map[*types.Var]bool{}
									}
									if !returnAliases[curFn][gv] {
										returnAliases[curFn][gv] = true
										changed = true
										progressedSummary = true
									}
								}
							}
						}
						for _, res := range x.Results {
							if exprTouchesEnv(res, envLocals) {
								retEnv = true
							}
							for gv := range collectAliasVars(res) {
								if returnAliases[curFn] == nil {
									returnAliases[curFn] = map[*types.Var]bool{}
								}
								if !returnAliases[curFn][gv] {
									returnAliases[curFn][gv] = true
									changed = true
									progressedSummary = true
								}
							}
						}
						if retEnv && !envResultInitFuncs[curFn] {
							envResultInitFuncs[curFn] = true
							changed = true
							progressedSummary = true
						}
					}
				case *ast.CallExpr:
					callee := resolveHarnessFuncExpr(info, x.Fun)
					if callee != nil && callee.Pkg() != nil && callee.Pkg().Path() == "flag" && len(x.Args) > 0 {
						if un, ok := ast.Unparen(x.Args[0]).(*ast.UnaryExpr); ok && un.Op == token.AND {
							markTarget(un.X, true)
						}
					}
					if callee != nil && g.initOnly[callee.Origin()] {
						orig := callee.Origin()
						if condEnv && !condEnvInitFuncs[orig] {
							condEnvInitFuncs[orig] = true
							progressedSummary = true
						}
						csig := orig.Signature()
						if csig != nil && csig.Params().Len() > 0 {
							for ai, a := range x.Args {
								pIdx := ai
								if pIdx >= csig.Params().Len() {
									pIdx = csig.Params().Len() - 1
								}
								pk := harnessParamKey{fn: orig, idx: pIdx}
								if exprTouchesEnv(a, envLocals) && !taintedInitParams[pk] {
									taintedInitParams[pk] = true
									progressedSummary = true
								}
								for gv := range collectAliasVars(a) {
									if paramAliases[pk] == nil {
										paramAliases[pk] = map[*types.Var]bool{}
									}
									if !paramAliases[pk][gv] {
										paramAliases[pk][gv] = true
										progressedSummary = true
									}
								}
							}
						}
					}
					if arg0, ok := mutatingBuiltinFirstArg(info, x); ok {
						callEnv := condEnv
						for _, a := range x.Args {
							if exprTouchesEnv(a, envLocals) {
								callEnv = true
								break
							}
						}
						if callEnv {
							markTarget(arg0, true)
						}
					}
					anyArgEnv := condEnv
					for _, a := range x.Args {
						if exprTouchesEnv(a, envLocals) {
							anyArgEnv = true
							break
						}
					}
					if anyArgEnv {
						for _, a := range x.Args {
							if un, ok := ast.Unparen(a).(*ast.UnaryExpr); ok && un.Op == token.AND {
								markTarget(un.X, true)
							}
						}
					}
				}
				ast.Inspect(n, func(child ast.Node) bool {
					if child == nil || child == n {
						return true
					}
					walk(child, condEnv)
					return false
				})
			}
			walk(body, startCondEnv)
		}
		return progressedSummary
	}

	for progressed := true; progressed; {
		progressed = false
		for _, entry := range g.pkgVars {
			if categoryA[entry.v] && !envFlagVars[entry.v] && entry.val != nil && exprTouchesEnv(entry.val, nil) {
				envFlagVars[entry.v] = true
				progressed = true
			}
		}
		for _, af := range g.pkg.Syntax {
			for _, decl := range af.Decls {
				if d, ok := decl.(*ast.FuncDecl); ok && d.Recv == nil {
					if d.Name.Name == "init" {
						if scanInitBody(d.Body, nil) {
							progressed = true
						}
					} else if fn, ok := info.Defs[d.Name].(*types.Func); ok && fn != nil && g.initOnly[fn.Origin()] {
						if scanInitBody(d.Body, fn.Origin()) {
							progressed = true
						}
					}
				}
			}
		}
	}
	return envFlagVars
}
