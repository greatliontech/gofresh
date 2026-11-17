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

func pureLocalSelectorChainPath(expr ast.Expr, allowedRoots map[string]bool) (string, bool) {
	switch e := unwrapParens(expr).(type) {
	case *ast.Ident:
		if allowedRoots[e.Name] {
			return e.Name, true
		}
	case *ast.SelectorExpr:
		if base, ok := pureLocalSelectorChainPath(e.X, allowedRoots); ok && e.Sel != nil && e.Sel.Name != "" {
			return base + "." + e.Sel.Name, true
		}
	}
	return "", false
}

// DiscoverRuntimeInactiveGates discovers unexported runtime gate functions that
// provably return false unless an unexported atomic or zero-initialized pointer
// state variable is mutated.
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
	ptrStateCands := map[string]*ast.Ident{}
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
		if hasDotImport {
			return nil
		}
		if hasAtomic {
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
							if d.Tok == token.VAR && id.Name != "_" && !ast.IsExported(id.Name) && len(sp.Values) == 0 && sp.Type != nil {
								if fileImportsAtomic[f] {
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
								if _, okStar := unwrapParens(sp.Type).(*ast.StarExpr); okStar {
									ptrStateCands[id.Name] = id
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
	if pkgDeclCounts["false"] > 0 || pkgDeclCounts["true"] > 0 || pkgDeclCounts["bool"] > 0 || pkgDeclCounts["atomic"] > 0 || pkgDeclCounts["nil"] > 0 {
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

	type runtimeDirectCallSite struct {
		caller *ast.FuncDecl
		call   *ast.CallExpr
		ident  *ast.Ident
	}
	mutatorDirectCallSites := map[string][]runtimeDirectCallSite{}
	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, okC := n.(*ast.CallExpr)
				if !okC {
					return true
				}
				if cID, okID := unwrapParens(call.Fun).(*ast.Ident); okID && topFuncs[cID.Name] != nil && !funcShadowsAnyIdent(fn, map[string]bool{cID.Name: true}) {
					mutatorDirectCallSites[cID.Name] = append(mutatorDirectCallSites[cID.Name], runtimeDirectCallSite{
						caller: fn,
						call:   call,
						ident:  cID,
					})
				}
				return true
			})
		}
	}

	funcImportNames := make(map[*ast.FuncDecl]map[string]bool, len(topFuncs)+4)
	for _, f := range files {
		impSet := map[string]bool{}
		for _, imp := range f.Imports {
			if imp.Name != nil {
				if imp.Name.Name != "_" && imp.Name.Name != "." && imp.Name.Name != "" {
					impSet[imp.Name.Name] = true
				}
				continue
			}
			if imp.Path != nil {
				if p, err := strconv.Unquote(imp.Path.Value); err == nil {
					if slash := strings.LastIndexByte(p, '/'); slash >= 0 {
						p = p[slash+1:]
					}
					if p != "" && p != "_" && p != "." {
						impSet[p] = true
					}
				}
			}
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				funcImportNames[fn] = impSet
			}
		}
	}
	identUnshadowedInFunc := func(fn *ast.FuncDecl, name string) bool {
		return !funcImportNames[fn][name] && !funcShadowsAnyIdent(fn, map[string]bool{name: true})
	}

	isValidUnexportedMutatorDecl := func(mName string) bool {
		if mName == "main" {
			return false
		}
		mFn := topFuncs[mName]
		if mFn == nil || mFn.Recv != nil || pkgDeclCounts[mName] != 1 || ast.IsExported(mName) || aliasedRuntimeSym[mName] || nonGoIdents[mName] {
			return false
		}
		for _, t := range twoArgTargets[mName] {
			if t != "runtime."+mName {
				return false
			}
		}
		allowed := map[*ast.Ident]bool{mFn.Name: true}
		for _, cs := range mutatorDirectCallSites[mName] {
			allowed[cs.ident] = true
		}
		return allNonSelPropIdentsIn(files, mName, allowed)
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

	unleakedStateCands := map[string]atomicStateCand{}
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
						} else if fn.Recv == nil && fn.Name != nil && !ast.IsExported(fn.Name.Name) && fn.Name.Name != "init" && fn.Name.Name != "main" {
							allowedIdentsByState[baseID.Name][baseID] = true
							mutatorSetByState[baseID.Name][fn.Name.Name] = true
						}
					}
					return true
				})
			}
		}

		leaked := filterNonSelPropIdentsInSet(files, allowedIdentsByState)
		for sName, cand := range activeStateCands {
			if !leaked[sName] {
				unleakedStateCands[sName] = cand
			}
		}
	}

	verifiedStateMutators := map[string][]string{}
	verifiedStateIsBool := map[string]bool{}

	// Collect candidate unexported zero-init pointer globals (`var p *T`) that are
	// never address-taken (`&p`) and never mutated in `init()`.
	type ptrWriteSite struct {
		fn     *ast.FuncDecl
		assign *ast.AssignStmt
	}
	activePtrCands := map[string][]ptrWriteSite{}
	for pName := range ptrStateCands {
		if pkgDeclCounts[pName] == 1 && !anyLinknameLocal[pName] && !aliasedRuntimeSym[pName] && !nonGoIdents[pName] {
			activePtrCands[pName] = nil
		}
	}
	if len(activePtrCands) > 0 {
		badPtr := map[string]bool{}
		for _, f := range files {
			for _, decl := range f.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					ast.Inspect(d, func(n ast.Node) bool {
						if id, okID := n.(*ast.Ident); okID {
							if declID, isCand := ptrStateCands[id.Name]; isCand && id != declID {
								badPtr[id.Name] = true
							}
						}
						return true
					})
				case *ast.FuncDecl:
					fn := d
					if fn.Body == nil {
						continue
					}
					isInit := fn.Recv == nil && fn.Name != nil && fn.Name.Name == "init"
					ast.Inspect(fn.Body, func(n ast.Node) bool {
						if n == nil {
							return false
						}
						switch x := n.(type) {
						case *ast.UnaryExpr:
							if x.Op == token.AND {
								ast.Inspect(x.X, func(un ast.Node) bool {
									if id, okID := un.(*ast.Ident); okID {
										if _, isCand := activePtrCands[id.Name]; isCand {
											badPtr[id.Name] = true
										}
									}
									return true
								})
							}
						case *ast.RangeStmt:
							for _, e := range []ast.Expr{x.Key, x.Value} {
								if id, okID := unwrapParens(e).(*ast.Ident); okID {
									if _, isCand := activePtrCands[id.Name]; isCand {
										badPtr[id.Name] = true
									}
								}
							}
						case *ast.IncDecStmt:
							if id, okID := unwrapParens(x.X).(*ast.Ident); okID {
								if _, isCand := activePtrCands[id.Name]; isCand {
									badPtr[id.Name] = true
								}
							}
						case *ast.AssignStmt:
							for _, lhs := range x.Lhs {
								id, okID := unwrapParens(lhs).(*ast.Ident)
								if !okID {
									continue
								}
								if _, isCand := activePtrCands[id.Name]; !isCand {
									continue
								}
								if !identUnshadowedInFunc(fn, id.Name) || isInit || x.Tok != token.ASSIGN || len(x.Lhs) != 1 || len(x.Rhs) != 1 {
									badPtr[id.Name] = true
									continue
								}
								if _, okNil := isIdentNamed(x.Rhs[0], "nil"); okNil && identUnshadowedInFunc(fn, "nil") {
									continue
								}
								activePtrCands[id.Name] = append(activePtrCands[id.Name], ptrWriteSite{fn: fn, assign: x})
							}
						}
						return true
					})
				}
			}
		}
		for pName := range badPtr {
			delete(activePtrCands, pName)
		}
	}

	provenGates := map[string][]string{}
	verifiedNilPtrMutators := map[string][]string{}

	var evalFalseExpr func(expr ast.Expr, fn *ast.FuncDecl, localGetgVars map[string]bool) ([]string, bool)
	evalFalseExpr = func(expr ast.Expr, fn *ast.FuncDecl, localGetgVars map[string]bool) ([]string, bool) {
		expr = unwrapParens(expr)
		if id, ok := expr.(*ast.Ident); ok {
			if (id.Name == "false" || falseConsts[id.Name]) && identUnshadowedInFunc(fn, id.Name) {
				return make([]string, 0), true
			}
			return nil, false
		}
		if call, ok := expr.(*ast.CallExpr); ok && !call.Ellipsis.IsValid() && len(call.Args) == 0 {
			if gID, okG := unwrapParens(call.Fun).(*ast.Ident); okG && identUnshadowedInFunc(fn, gID.Name) {
				if deps, okP := provenGates["runtime."+gID.Name]; okP {
					return slices.Clone(deps), true
				}
			}
			if sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr); okS && sel.Sel.Name == "Load" {
				if sID, okID := unwrapParens(sel.X).(*ast.Ident); okID && verifiedStateIsBool[sID.Name] && identUnshadowedInFunc(fn, sID.Name) {
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
					if !okID || verifiedStateIsBool[sID.Name] || !identUnshadowedInFunc(fn, sID.Name) {
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
				checkNilPtrNeq := func(ptrSide, nilSide ast.Expr) ([]string, bool) {
					if _, okN := isIdentNamed(nilSide, "nil"); !okN || !identUnshadowedInFunc(fn, "nil") {
						return nil, false
					}
					pID, okP := unwrapParens(ptrSide).(*ast.Ident)
					if !okP || !identUnshadowedInFunc(fn, pID.Name) {
						return nil, false
					}
					deps, okM := verifiedNilPtrMutators[pID.Name]
					if !okM {
						return nil, false
					}
					return slices.Clone(deps), true
				}
				if deps, okL := checkNilPtrNeq(bin.X, bin.Y); okL {
					return deps, true
				}
				if deps, okR := checkNilPtrNeq(bin.Y, bin.X); okR {
					return deps, true
				}
			case token.LAND:
				if deps, okL := evalFalseExpr(bin.X, fn, localGetgVars); okL {
					return deps, true
				}
				if id, okID := unwrapParens(bin.X).(*ast.Ident); okID && (id.Name == "true" || trueConsts[id.Name]) && identUnshadowedInFunc(fn, id.Name) {
					return evalFalseExpr(bin.Y, fn, localGetgVars)
				}
				// Prove `X != nil && X == <nilPtrGlobal>` (or symmetric) is false when <nilPtrGlobal> == nil.
				if len(localGetgVars) > 0 && identUnshadowedInFunc(fn, "nil") {
					extractNeqNil := func(e ast.Expr) (string, bool) {
						b, okB := unwrapParens(e).(*ast.BinaryExpr)
						if !okB || b.Op != token.NEQ {
							return "", false
						}
						if _, okN := isIdentNamed(b.Y, "nil"); okN {
							return pureLocalSelectorChainPath(b.X, localGetgVars)
						}
						if _, okN := isIdentNamed(b.X, "nil"); okN {
							return pureLocalSelectorChainPath(b.Y, localGetgVars)
						}
						return "", false
					}
					extractEqNilPtr := func(e ast.Expr) (string, []string, bool) {
						b, okB := unwrapParens(e).(*ast.BinaryExpr)
						if !okB || b.Op != token.EQL {
							return "", nil, false
						}
						checkSides := func(chainSide, ptrSide ast.Expr) (string, []string, bool) {
							pID, okP := unwrapParens(ptrSide).(*ast.Ident)
							if !okP || funcShadowsAnyIdent(fn, map[string]bool{pID.Name: true}) {
								return "", nil, false
							}
							deps, okM := verifiedNilPtrMutators[pID.Name]
							if !okM {
								return "", nil, false
							}
							path, okPath := pureLocalSelectorChainPath(chainSide, localGetgVars)
							if !okPath {
								return "", nil, false
							}
							return path, slices.Clone(deps), true
						}
						if path, deps, ok1 := checkSides(b.X, b.Y); ok1 {
							return path, deps, true
						}
						return checkSides(b.Y, b.X)
					}
					if p1, ok1 := extractNeqNil(bin.X); ok1 {
						if p2, deps, ok2 := extractEqNilPtr(bin.Y); ok2 && p1 == p2 {
							return deps, true
						}
					}
					if p1, ok1 := extractNeqNil(bin.Y); ok1 {
						if p2, deps, ok2 := extractEqNilPtr(bin.X); ok2 && p1 == p2 {
							return deps, true
						}
					}
				}
			case token.LOR:
				depsL, okL := evalFalseExpr(bin.X, fn, localGetgVars)
				if !okL {
					return nil, false
				}
				depsR, okR := evalFalseExpr(bin.Y, fn, localGetgVars)
				if !okR {
					return nil, false
				}
				return mergeGateLists(depsL, depsR), true
			}
		}
		return nil, false
	}

	nodeGuardedByProvenFalseIf := func(fn *ast.FuncDecl, target ast.Node) ([]string, bool) {
		if fn == nil || fn.Body == nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			return nil, false
		}
		var out []string
		found := false
		var walk func(n ast.Node, curDeps []string, guarded bool)
		walk = func(n ast.Node, curDeps []string, guarded bool) {
			if found || n == nil {
				return
			}
			if n == target {
				if guarded {
					out = curDeps
					found = true
				}
				return
			}
			if ifs, okI := n.(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil {
				if d, okF := evalFalseExpr(ifs.Cond, fn, nil); okF {
					merged := mergeGateLists(curDeps, d)
					for _, bs := range ifs.Body.List {
						walk(bs, merged, true)
					}
					return
				}
			}
			ast.Inspect(n, func(ch ast.Node) bool {
				if ch == n {
					return true
				}
				walk(ch, curDeps, guarded)
				return false
			})
		}
		walk(fn.Body, nil, false)
		return out, found
	}

	var resolveMutatorTargets func(mName string, visiting map[string]bool) ([]string, bool)
	resolveMutatorTargets = func(mName string, visiting map[string]bool) ([]string, bool) {
		if visiting[mName] || !isValidUnexportedMutatorDecl(mName) {
			return nil, false
		}
		nextVis := make(map[string]bool, len(visiting)+1)
		for k, v := range visiting {
			nextVis[k] = v
		}
		nextVis[mName] = true
		deps := map[string]bool{"runtime." + mName: true}
		for _, cs := range mutatorDirectCallSites[mName] {
			if gDeps, okG := nodeGuardedByProvenFalseIf(cs.caller, cs.call); okG {
				for _, d := range gDeps {
					deps[d] = true
				}
				continue
			}
			if cs.caller == nil || cs.caller.Recv != nil || cs.caller.Name == nil {
				return nil, false
			}
			cDeps, okC := resolveMutatorTargets(cs.caller.Name.Name, nextVis)
			if !okC {
				return nil, false
			}
			for _, d := range cDeps {
				deps[d] = true
			}
		}
		return sortedKeys(deps), true
	}

	gateReserved := map[string]bool{"false": true, "true": true, "bool": true, "nil": true, "getg": true}
	for {
		changed := false
		for sName, cand := range unleakedStateCands {
			depSet := map[string]bool{"runtime." + sName: true}
			mutatorsValid := true
			for mName := range mutatorSetByState[sName] {
				mDeps, okM := resolveMutatorTargets(mName, nil)
				if !okM {
					mutatorsValid = false
					break
				}
				for _, d := range mDeps {
					depSet[d] = true
				}
			}
			if !mutatorsValid {
				continue
			}
			sorted := sortedKeys(depSet)
			if prev, exists := verifiedStateMutators[sName]; !exists || !slices.Equal(prev, sorted) {
				verifiedStateMutators[sName] = sorted
				verifiedStateIsBool[sName] = cand.isBool
				changed = true
			}
		}

		for pName, sites := range activePtrCands {
			depSet := map[string]bool{"runtime." + pName: true}
			allOK := true
			for _, site := range sites {
				if gDeps, okG := nodeGuardedByProvenFalseIf(site.fn, site.assign); okG {
					for _, d := range gDeps {
						depSet[d] = true
					}
					continue
				}
				if site.fn.Recv == nil && site.fn.Name != nil {
					if mDeps, okM := resolveMutatorTargets(site.fn.Name.Name, nil); okM {
						for _, d := range mDeps {
							depSet[d] = true
						}
						continue
					}
				}
				allOK = false
				break
			}
			if allOK {
				sorted := sortedKeys(depSet)
				if prev, exists := verifiedNilPtrMutators[pName]; !exists || !slices.Equal(prev, sorted) {
					verifiedNilPtrMutators[pName] = sorted
					changed = true
				}
			}
		}

		for gName, fn := range topFuncs {
			key := "runtime." + gName
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
			stmts := fn.Body.List
			var localGetgVars map[string]bool
			if len(stmts) == 2 {
				if as0, okA := stmts[0].(*ast.AssignStmt); okA && as0.Tok == token.DEFINE && len(as0.Lhs) == 1 && len(as0.Rhs) == 1 {
					if gVarID, okV := unwrapParens(as0.Lhs[0]).(*ast.Ident); okV && gVarID.Name != "" && gVarID.Name != "_" {
						if gCall, okC := unwrapParens(as0.Rhs[0]).(*ast.CallExpr); okC && !gCall.Ellipsis.IsValid() && len(gCall.Args) == 0 {
							if _, okGetg := isIdentNamed(gCall.Fun, "getg"); okGetg && pkgDeclCounts["getg"] <= 1 {
								restBlk := &ast.BlockStmt{List: stmts[1:]}
								if !bodyMutatesOrTakesAddrOfAny(restBlk, map[string]bool{gVarID.Name: true}) && !bodyDeclaresAnyIdent(restBlk, map[string]bool{gVarID.Name: true}) {
									localGetgVars = map[string]bool{gVarID.Name: true}
									stmts = stmts[1:]
								}
							}
						}
					}
				}
			}
			switch s0 := stmts[0].(type) {
			case *ast.ReturnStmt:
				if len(s0.Results) == 1 {
					if deps, ok := evalFalseExpr(s0.Results[0], fn, localGetgVars); ok {
						if prev, exists := provenGates[key]; !exists || !slices.Equal(prev, deps) {
							provenGates[key] = deps
							changed = true
						}
					}
				}
			case *ast.IfStmt:
				if s0.Init == nil && s0.Else == nil && len(s0.Body.List) == 1 {
					if ret, okR := s0.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
						if _, okFalse := isIdentNamed(ret.Results[0], "false"); okFalse {
							if u, okU := unwrapParens(s0.Cond).(*ast.UnaryExpr); okU && u.Op == token.NOT {
								if deps, ok := evalFalseExpr(u.X, fn, localGetgVars); ok {
									if prev, exists := provenGates[key]; !exists || !slices.Equal(prev, deps) {
										provenGates[key] = deps
										changed = true
									}
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
