package toolchain

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"slices"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
	"github.com/greatliontech/gofresh/internal/trace"
)

// VerifyToolchainAssemblyFile verifies a standard-library or runtime assembly/header
// file using cprep.VerifyAssemblyFile and emits a cprep.verify.done trace event.
func VerifyToolchainAssemblyFile(ctx context.Context, pkgPath, name, src string, selectedHeaders map[string]bool) error {
	err := cprep.VerifyAssemblyFile(pkgPath, name, src, selectedHeaders)
	if trace.AnyEnabled() {
		target := name
		if pkgPath != "" {
			target = pkgPath + "/" + name
		}
		if trace.Enabled(ctx, trace.DomainClosure, target) {
			trace.Emit(ctx, trace.DomainClosure, "cprep.verify.done", target,
				trace.Bool("ok", err == nil),
				trace.Err(err),
			)
		}
	}
	return err
}

// CollectStrippedAsmRuntimeIdents strips comments from src and records all
// referenced runtime identifiers and Mach-O symbol names into out.
func CollectStrippedAsmRuntimeIdents(src string, out map[string]bool) {
	var prevStripped string
	for passIdx, joinSpace := range []bool{false, true} {
		stripped := cprep.StripAssemblyComments(src, true, joinSpace)
		if passIdx > 0 && stripped == prevStripped {
			continue
		}
		prevStripped = stripped
		cprep.CollectRuntimeIdentsAndMachOString(stripped, out)
		if collapsed := cprep.CollapseTokenPasteOps(cprep.NormalizeCStringLiterals(stripped, true)); collapsed != stripped {
			cprep.CollectRuntimeIdentsAndMachOString(collapsed, out)
		}
	}
}

// DiscoverRuntimeInactiveGates discovers unexported runtime gate functions that
// provably return false unless an unexported atomic state variable is mutated.
func DiscoverRuntimeInactiveGates(files []*ast.File, goSrcs []string, nonGoIdents map[string]bool) map[string][]string {
	anyLinknameLocal := map[string]bool{}
	twoArgTargets := map[string][]string{}
	aliasedRuntimeSym := map[string]bool{}
	for _, src := range goSrcs {
		err := scanGoDirectiveComments(src, func(line string) error {
			if !strings.HasPrefix(line, "//go:linkname") {
				return nil
			}
			_, plain := auditset.BoundedToken(line, "//go:linkname", " \t")
			_, std := auditset.BoundedToken(line, "//go:linknamestd", " \t")
			fields := strings.Fields(line)
			if (!plain && !std) || (len(fields) != 2 && len(fields) != 3) {
				return fmt.Errorf("malformed linkname %q", line)
			}
			anyLinknameLocal[fields[1]] = true
			if len(fields) == 3 {
				twoArgTargets[fields[1]] = append(twoArgTargets[fields[1]], fields[2])
				if strings.HasPrefix(fields[2], "runtime.") {
					rem := strings.TrimPrefix(fields[2], "runtime.")
					if rem != fields[1] {
						aliasedRuntimeSym[rem] = true
					}
				}
			}
			return nil
		})
		if err != nil {
			return nil
		}
	}

	fileImportsAtomic := map[*ast.File]bool{}
	pkgDeclCounts := map[string]int{}
	falseConstCand := map[string]bool{}
	trueConstCand := map[string]bool{}
	badBoolConst := map[string]bool{}
	type atomicStateCand struct {
		declIdent *ast.Ident
		isBool    bool
	}
	stateCands := map[string]atomicStateCand{}
	topFuncs := map[string]*ast.FuncDecl{}

	for _, f := range files {
		hasDotImport := false
		hasAtomic := false
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return nil
			}
			if imp.Name != nil && imp.Name.Name == "." {
				hasDotImport = true
			}
			if (p == "internal/runtime/atomic" || p == "sync/atomic") && imp.Name == nil {
				hasAtomic = true
			}
		}
		if hasAtomic && !hasDotImport {
			fileImportsAtomic[f] = true
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						for idx, id := range sp.Names {
							if id.Name != "_" {
								pkgDeclCounts[id.Name]++
							}
							if d.Tok == token.CONST && id.Name != "_" {
								typeOK := sp.Type == nil
								if !typeOK {
									_, typeOK = isIdentNamed(sp.Type, "bool")
								}
								if typeOK && len(sp.Values) == len(sp.Names) {
									if _, okF := isIdentNamed(sp.Values[idx], "false"); okF {
										falseConstCand[id.Name] = true
									} else if _, okT := isIdentNamed(sp.Values[idx], "true"); okT {
										trueConstCand[id.Name] = true
									} else {
										badBoolConst[id.Name] = true
									}
								} else {
									badBoolConst[id.Name] = true
								}
							}
							if d.Tok == token.VAR && id.Name != "_" && !ast.IsExported(id.Name) && len(sp.Values) == 0 && fileImportsAtomic[f] && sp.Type != nil {
								if sel, okS := unwrapParens(sp.Type).(*ast.SelectorExpr); okS {
									if _, okA := isIdentNamed(sel.X, "atomic"); okA {
										switch sel.Sel.Name {
										case "Uint64", "Uint32", "Int64", "Int32":
											stateCands[id.Name] = atomicStateCand{declIdent: id, isBool: false}
										case "Bool":
											stateCands[id.Name] = atomicStateCand{declIdent: id, isBool: true}
										}
									}
								}
							}
						}
					case *ast.TypeSpec:
						if sp.Name != nil && sp.Name.Name != "_" {
							pkgDeclCounts[sp.Name.Name]++
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name != nil && d.Name.Name != "init" && d.Name.Name != "_" {
					pkgDeclCounts[d.Name.Name]++
					if d.Body != nil {
						topFuncs[d.Name.Name] = d
					}
				}
			}
		}
	}
	if pkgDeclCounts["false"] > 0 || pkgDeclCounts["true"] > 0 || pkgDeclCounts["bool"] > 0 || pkgDeclCounts["atomic"] > 0 {
		return nil
	}
	falseConsts := map[string]bool{}
	for name := range falseConstCand {
		if !badBoolConst[name] && !trueConstCand[name] && pkgDeclCounts[name] == 1 && !anyLinknameLocal[name] && !aliasedRuntimeSym[name] {
			falseConsts[name] = true
		}
	}
	trueConsts := map[string]bool{}
	for name := range trueConstCand {
		if !badBoolConst[name] && !falseConstCand[name] && pkgDeclCounts[name] == 1 && !anyLinknameLocal[name] && !aliasedRuntimeSym[name] {
			trueConsts[name] = true
		}
	}

	activeStateCands := map[string]atomicStateCand{}
	allowedIdentsByState := map[string]map[*ast.Ident]bool{}
	mutatorSetByState := map[string]map[string]bool{}
	for sName, cand := range stateCands {
		if pkgDeclCounts[sName] != 1 || anyLinknameLocal[sName] || aliasedRuntimeSym[sName] || nonGoIdents[sName] {
			continue
		}
		activeStateCands[sName] = cand
		allowedIdentsByState[sName] = map[*ast.Ident]bool{cand.declIdent: true}
		mutatorSetByState[sName] = map[string]bool{}
	}

	verifiedStateMutators := map[string][]string{}
	verifiedStateIsBool := map[string]bool{}
	if len(activeStateCands) > 0 {
		for _, f := range files {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				var shadowedCache map[string]bool
				shadows := func(name string) bool {
					if shadowedCache == nil {
						shadowedCache = map[string]bool{}
					}
					if res, ok := shadowedCache[name]; ok {
						return res
					}
					res := funcShadowsAnyIdent(fn, map[string]bool{name: true})
					shadowedCache[name] = res
					return res
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, isCall := n.(*ast.CallExpr)
					if !isCall || call.Ellipsis.IsValid() {
						return true
					}
					sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr)
					if !okS {
						return true
					}
					baseID, okID := unwrapParens(sel.X).(*ast.Ident)
					if !okID {
						return true
					}
					cand, isCand := activeStateCands[baseID.Name]
					if !isCand || shadows(baseID.Name) || shadows("false") {
						return true
					}
					switch {
					case sel.Sel.Name == "Load" && len(call.Args) == 0:
						allowedIdentsByState[baseID.Name][baseID] = true
					case sel.Sel.Name == "Store" && len(call.Args) == 1:
						isZero := (!cand.isBool && isZeroIntLit(call.Args[0]))
						if cand.isBool {
							_, isZero = isIdentNamed(call.Args[0], "false")
						}
						if isZero {
							allowedIdentsByState[baseID.Name][baseID] = true
						} else if fn.Recv == nil && fn.Name != nil && !ast.IsExported(fn.Name.Name) && fn.Name.Name != "init" {
							allowedIdentsByState[baseID.Name][baseID] = true
							mutatorSetByState[baseID.Name][fn.Name.Name] = true
						}
					}
					return true
				})
			}
		}

		allowedMutators := map[string]map[*ast.Ident]bool{}
		for sName, cand := range activeStateCands {
			_ = cand
			allowedMutators[sName] = allowedIdentsByState[sName]
			for mName := range mutatorSetByState[sName] {
				if mFn := topFuncs[mName]; mFn != nil && allowedMutators[mName] == nil {
					allowedMutators[mName] = map[*ast.Ident]bool{mFn.Name: true}
				}
			}
		}
		leaked := filterNonSelPropIdentsInSet(files, allowedMutators)

		for sName, cand := range activeStateCands {
			if leaked[sName] {
				continue
			}
			mutatorSet := mutatorSetByState[sName]
			mutatorsValid := true
			mutTargets := make([]string, 0, len(mutatorSet)+1)
			mutTargets = append(mutTargets, "runtime."+sName)
			for mName := range mutatorSet {
				mFn := topFuncs[mName]
				if mFn == nil || pkgDeclCounts[mName] != 1 || ast.IsExported(mName) || aliasedRuntimeSym[mName] || nonGoIdents[mName] {
					mutatorsValid = false
					break
				}
				for _, t := range twoArgTargets[mName] {
					if t != "runtime."+mName {
						mutatorsValid = false
						break
					}
				}
				if !mutatorsValid || leaked[mName] {
					mutatorsValid = false
					break
				}
				mutTargets = append(mutTargets, "runtime."+mName)
			}
			if !mutatorsValid {
				continue
			}
			slices.Sort(mutTargets)
			verifiedStateMutators[sName] = mutTargets
			verifiedStateIsBool[sName] = cand.isBool
		}
	}

	provenGates := map[string][]string{}
	var evalFalseExpr func(expr ast.Expr, fn *ast.FuncDecl) ([]string, bool)
	evalFalseExpr = func(expr ast.Expr, fn *ast.FuncDecl) ([]string, bool) {
		expr = unwrapParens(expr)
		if id, ok := expr.(*ast.Ident); ok {
			if id.Name == "false" || (falseConsts[id.Name] && !funcShadowsAnyIdent(fn, map[string]bool{id.Name: true})) {
				return make([]string, 0), true
			}
			return nil, false
		}
		if call, ok := expr.(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 0 {
			if gID, okG := unwrapParens(call.Fun).(*ast.Ident); okG && !funcShadowsAnyIdent(fn, map[string]bool{gID.Name: true}) {
				if deps, okP := provenGates["runtime."+gID.Name]; okP {
					return slices.Clone(deps), true
				}
			}
			if sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Load" {
				if sID, okID := unwrapParens(sel.X).(*ast.Ident); okID && verifiedStateIsBool[sID.Name] && !funcShadowsAnyIdent(fn, map[string]bool{sID.Name: true}) {
					if deps, okM := verifiedStateMutators[sID.Name]; okM {
						return slices.Clone(deps), true
					}
				}
			}
		}
		if bin, ok := expr.(*ast.BinaryExpr); ok {
			switch bin.Op {
			case token.NEQ:
				checkLoadZero := func(loadExpr, zeroExpr ast.Expr) ([]string, bool) {
					if !isZeroIntLit(zeroExpr) {
						return nil, false
					}
					c, okC := unwrapParens(loadExpr).(*ast.CallExpr)
					if !okC || c.Ellipsis.IsValid() || len(c.Args) != 0 {
						return nil, false
					}
					sel, okS := unwrapParens(c.Fun).(*ast.SelectorExpr)
					if !okS || sel.Sel.Name != "Load" {
						return nil, false
					}
					sID, okID := unwrapParens(sel.X).(*ast.Ident)
					if !okID || verifiedStateIsBool[sID.Name] || funcShadowsAnyIdent(fn, map[string]bool{sID.Name: true}) {
						return nil, false
					}
					deps, okM := verifiedStateMutators[sID.Name]
					if !okM {
						return nil, false
					}
					return slices.Clone(deps), true
				}
				if deps, okL := checkLoadZero(bin.X, bin.Y); okL {
					return deps, true
				}
				if deps, okR := checkLoadZero(bin.Y, bin.X); okR {
					return deps, true
				}
			case token.LAND:
				if deps, okL := evalFalseExpr(bin.X, fn); okL {
					return deps, true
				}
				if id, okID := unwrapParens(bin.X).(*ast.Ident); okID && (id.Name == "true" || (trueConsts[id.Name] && !funcShadowsAnyIdent(fn, map[string]bool{id.Name: true}))) {
					return evalFalseExpr(bin.Y, fn)
				}
			case token.LOR:
				depsL, okL := evalFalseExpr(bin.X, fn)
				if !okL {
					return nil, false
				}
				depsR, okR := evalFalseExpr(bin.Y, fn)
				if !okR {
					return nil, false
				}
				merged := map[string]bool{}
				for _, d := range depsL {
					merged[d] = true
				}
				for _, d := range depsR {
					merged[d] = true
				}
				out := sortedKeys(merged)
				if out == nil {
					out = make([]string, 0)
				}
				return out, true
			}
		}
		return nil, false
	}

	gateReserved := map[string]bool{"false": true, "true": true, "bool": true}
	for {
		changed := false
		for gName, fn := range topFuncs {
			key := "runtime." + gName
			if _, already := provenGates[key]; already {
				continue
			}
			if ast.IsExported(gName) || pkgDeclCounts[gName] != 1 || aliasedRuntimeSym[gName] || fn.Type == nil {
				continue
			}
			badTarget := false
			for _, t := range twoArgTargets[gName] {
				if t != key {
					badTarget = true
					break
				}
			}
			if badTarget {
				continue
			}
			if fn.Type.Params != nil && fn.Type.Params.NumFields() != 0 {
				continue
			}
			if fn.Type.Results == nil || fn.Type.Results.NumFields() != 1 || len(fn.Type.Results.List) != 1 {
				continue
			}
			if _, okBool := isIdentNamed(fn.Type.Results.List[0].Type, "bool"); !okBool {
				continue
			}
			if len(fn.Body.List) == 0 || funcShadowsAnyIdent(fn, gateReserved) || bodyHasControlFlowOrRecoverBypass(fn.Body) {
				continue
			}
			switch s0 := fn.Body.List[0].(type) {
			case *ast.ReturnStmt:
				if len(s0.Results) == 1 {
					if deps, ok := evalFalseExpr(s0.Results[0], fn); ok {
						provenGates[key] = deps
						changed = true
					}
				}
			case *ast.IfStmt:
				if s0.Init == nil && s0.Else == nil && len(s0.Body.List) == 1 {
					if ret, okR := s0.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
						if _, okFalse := isIdentNamed(ret.Results[0], "false"); okFalse {
							if u, okU := unwrapParens(s0.Cond).(*ast.UnaryExpr); okU && u.Op == token.NOT {
								if deps, ok := evalFalseExpr(u.X, fn); ok {
									provenGates[key] = deps
									changed = true
								}
							}
						}
					}
				}
			}
		}
		if !changed {
			break
		}
	}
	if len(provenGates) == 0 {
		return nil
	}
	return provenGates
}
