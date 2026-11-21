package toolchain

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

// packageInactiveKernel indexes package-generic compile-time boolean constants,
// inactive runtime linkname gates, unmutated function-variable gate aliases,
// and provably inactive helper/stub functions across a standard-library package's
// selected Go files.
type packageInactiveKernel struct {
	idx               *packageASTIndex
	files             []*ast.File
	fileImportPkg     map[*ast.File]map[string]string
	fileImportNames   map[*ast.File]map[string]bool
	hasDotImport      bool
	builtinsShadowed  bool
	FalseConsts       map[string]bool
	TrueConsts        map[string]bool
	FalseGates        map[string]string
	FalseFuncVars     map[string]string
	EarlyFalseFuncs   map[string][]string
	NoopVoidFuncs     map[string][]string
	NilErrFuncs       map[string][]string
	PureIntReadFuncs  map[string]bool
	anyLinknameLocals map[string]bool
}

var kernelPureIntConvNames = map[string]bool{
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true, "uintptr": true,
}

var kernelAtomicIntLoadNames = map[string]bool{
	"Loaduintptr": true, "Loadint32": true, "Loadint64": true,
	"Loaduint32": true, "Loaduint64": true, "Loadint": true, "Loaduint": true,
}

// newPackageInactiveKernel constructs a packageInactiveKernel over idx and files.
func newPackageInactiveKernel(idx *packageASTIndex, files []*ast.File, runtimePullMap map[string]string, anyLinknameLocals map[string]bool) *packageInactiveKernel {
	k := &packageInactiveKernel{
		idx:               idx,
		files:             files,
		fileImportPkg:     make(map[*ast.File]map[string]string, len(files)),
		fileImportNames:   make(map[*ast.File]map[string]bool, len(files)),
		FalseConsts:       map[string]bool{},
		TrueConsts:        map[string]bool{},
		FalseGates:        map[string]string{},
		FalseFuncVars:     map[string]string{},
		EarlyFalseFuncs:   map[string][]string{},
		NoopVoidFuncs:     map[string][]string{},
		NilErrFuncs:       map[string][]string{},
		PureIntReadFuncs:  map[string]bool{},
		anyLinknameLocals: anyLinknameLocals,
	}
	if idx == nil {
		var err error
		idx, err = indexPackageAST("", files, nil, nil)
		if err != nil {
			k.builtinsShadowed = true
			return k
		}
		k.idx = idx
	}
	if idx.pkgDeclCounts["true"] > 0 || idx.pkgDeclCounts["false"] > 0 || idx.pkgDeclCounts["bool"] > 0 || idx.pkgDeclCounts["nil"] > 0 {
		k.builtinsShadowed = true
		return k
	}

	falseConstCand := map[string]ast.Expr{}
	trueConstCand := map[string]ast.Expr{}
	constExprCand := map[string]ast.Expr{}
	constFile := map[string]*ast.File{}
	badBoolConst := map[string]bool{}

	for _, f := range files {
		k.fileImportPkg[f] = map[string]string{}
		k.fileImportNames[f] = map[string]bool{}
		for _, imp := range f.Imports {
			if imp.Path == nil {
				continue
			}
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				k.hasDotImport = true
				return k
			}
			if imp.Name != nil {
				if imp.Name.Name == "." {
					k.hasDotImport = true
					return k
				}
				if imp.Name.Name != "_" && imp.Name.Name != "" {
					if _, dup := k.fileImportPkg[f][imp.Name.Name]; dup {
						k.fileImportPkg[f][imp.Name.Name] = ""
					} else {
						k.fileImportPkg[f][imp.Name.Name] = p
					}
					k.fileImportNames[f][imp.Name.Name] = true
				}
				continue
			}
			base := p
			if slash := strings.LastIndexByte(p, '/'); slash >= 0 {
				base = p[slash+1:]
			}
			if base != "" && base != "_" && base != "." {
				if _, dup := k.fileImportPkg[f][base]; dup {
					k.fileImportPkg[f][base] = ""
				} else {
					k.fileImportPkg[f][base] = p
				}
				k.fileImportNames[f][base] = true
			}
		}

		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				typeOK := vs.Type == nil
				if !typeOK {
					_, typeOK = isIdentNamed(vs.Type, "bool")
				}
				for i, id := range vs.Names {
					if id.Name == "" || id.Name == "_" {
						continue
					}
					if !typeOK || len(vs.Values) != len(vs.Names) || k.fileImportNames[f]["true"] || k.fileImportNames[f]["false"] || k.fileImportNames[f]["bool"] {
						badBoolConst[id.Name] = true
						continue
					}
					val := unwrapParens(vs.Values[i])
					if vID, okID := val.(*ast.Ident); okID && (vID.Name == "false" || vID.Name == "true") {
						if vID.Name == "false" {
							falseConstCand[id.Name] = val
						} else {
							trueConstCand[id.Name] = val
						}
						constFile[id.Name] = f
						continue
					}
					constExprCand[id.Name] = val
					constFile[id.Name] = f
				}
			}
		}
	}

	for name := range falseConstCand {
		if !badBoolConst[name] && trueConstCand[name] == nil && constExprCand[name] == nil && idx.pkgDeclCounts[name] == 1 && !anyLinknameLocals[name] {
			k.FalseConsts[name] = true
		}
	}
	for name := range trueConstCand {
		if !badBoolConst[name] && falseConstCand[name] == nil && constExprCand[name] == nil && idx.pkgDeclCounts[name] == 1 && !anyLinknameLocals[name] {
			k.TrueConsts[name] = true
		}
	}
	// Resolve composite boolean constant expressions (`!c`, `c1 && c2`, `c1 || c2`).
	for {
		changed := false
		for name, expr := range constExprCand {
			if k.FalseConsts[name] || k.TrueConsts[name] || badBoolConst[name] || idx.pkgDeclCounts[name] != 1 || anyLinknameLocals[name] {
				continue
			}
			f := constFile[name]
			val, ok := k.evalConstBoolExpr(f, expr)
			if !ok {
				continue
			}
			if val {
				k.TrueConsts[name] = true
			} else {
				k.FalseConsts[name] = true
			}
			changed = true
		}
		if !changed {
			break
		}
	}

	// Discover 0-arg bool-returning false gate functions (bodyless runtime pulls + constant-false stubs).
	for gName, fn := range idx.topFuncs {
		if ast.IsExported(gName) || idx.pkgDeclCounts[gName] != 1 || fn.Type == nil || fn.Type.TypeParams != nil {
			continue
		}
		if fn.Type.Params != nil && fn.Type.Params.NumFields() != 0 {
			continue
		}
		if !funcHasUnnamedResults(fn.Type, 1) || len(fn.Type.Results.List) != 1 {
			continue
		}
		if _, okBool := isIdentNamed(fn.Type.Results.List[0].Type, "bool"); !okBool || k.identShadowedInFunc(fn, "bool") {
			continue
		}
		if fn.Body == nil {
			if rtTarget := runtimePullMap[gName]; strings.HasPrefix(rtTarget, "runtime.") {
				k.FalseGates[gName] = rtTarget
			}
			continue
		}
		if anyLinknameLocals[gName] || bodyHasControlFlowOrRecoverBypass(fn.Body) || len(fn.Body.List) != 1 {
			continue
		}
		if ret, okR := fn.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
			if gates, okF := k.evalFalseExpr(ret.Results[0], fn, nil); okF && len(gates) == 0 {
				k.FalseGates[gName] = ""
			}
		}
	}

	// Discover unmutated package-level function variables initialized to a FalseGate (`var fnAlias = gateFn`).
	k.discoverUnmutatedFalseFuncVars()

	// Discover pure 1-arg integer field/atomic-uintptr read helpers (`func h(x *T) int { return int(rtatomic.Loaduintptr((*uintptr)(unsafe.Pointer(&x.f)))) }`).
	k.discoverPureIntReadFuncs()

	// Discover unexported early-false, no-op void, and nil-error helper functions.
	k.discoverHelperStubs()
	return k
}

func (k *packageInactiveKernel) evalConstBoolExpr(f *ast.File, expr ast.Expr) (bool, bool) {
	switch e := unwrapParens(expr).(type) {
	case *ast.Ident:
		if k.fileImportNames[f][e.Name] {
			return false, false
		}
		switch {
		case e.Name == "true" || k.TrueConsts[e.Name]:
			return true, true
		case e.Name == "false" || k.FalseConsts[e.Name]:
			return false, true
		}
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			v, ok := k.evalConstBoolExpr(f, e.X)
			return !v, ok
		}
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND:
			l, okL := k.evalConstBoolExpr(f, e.X)
			r, okR := k.evalConstBoolExpr(f, e.Y)
			if okL && !l {
				return false, true
			}
			if okL && okR {
				return l && r, true
			}
		case token.LOR:
			l, okL := k.evalConstBoolExpr(f, e.X)
			r, okR := k.evalConstBoolExpr(f, e.Y)
			if okL && l {
				return true, true
			}
			if okL && okR {
				return l || r, true
			}
		}
	}
	return false, false
}

// fileImportPath returns the resolved import path for localAlias in file f,
// or "" if localAlias is not a unique import identifier in f.
func (k *packageInactiveKernel) fileImportPath(f *ast.File, localAlias string) string {
	if k == nil || f == nil || localAlias == "" || k.idx.pkgDeclCounts[localAlias] > 0 {
		return ""
	}
	return k.fileImportPkg[f][localAlias]
}

// identShadowedInFunc reports whether name is shadowed by an import in fn's file
// or by a parameter, result, or local declaration inside fn.
func (k *packageInactiveKernel) identShadowedInFunc(fn *ast.FuncDecl, name string) bool {
	if k == nil || k.hasDotImport || k.builtinsShadowed {
		return true
	}
	if funcShadowsAnyIdent(fn, map[string]bool{name: true}) {
		return true
	}
	if fn != nil && k.fileImportNames[k.idx.funcFile[fn]][name] {
		return true
	}
	return false
}

func (k *packageInactiveKernel) discoverUnmutatedFalseFuncVars() {
	if len(k.FalseGates) == 0 {
		return
	}
	cands := map[string]string{}
	allowedDeclIdents := map[string]map[*ast.Ident]bool{}
	for vName, initExpr := range k.idx.initPkgVars {
		if ast.IsExported(vName) || k.idx.pkgVarCounts[vName] != 1 || k.idx.pkgDeclCounts[vName] != 1 || k.anyLinknameLocals[vName] {
			continue
		}
		vFile := k.idx.initPkgVarFile[vName]
		if k.fileImportNames[vFile][vName] {
			continue
		}
		rhsID, okID := unwrapParens(initExpr).(*ast.Ident)
		if !okID || k.fileImportNames[vFile][rhsID.Name] {
			continue
		}
		rtGate, isGate := k.FalseGates[rhsID.Name]
		if !isGate {
			continue
		}
		vs := k.idx.pkgVarSpecs[vName]
		if vs != nil && vs.Type != nil {
			ft, okFT := unwrapParens(vs.Type).(*ast.FuncType)
			if !okFT || ft.TypeParams != nil || (ft.Params != nil && ft.Params.NumFields() != 0) || !funcHasUnnamedResults(ft, 1) {
				continue
			}
			if _, okBool := isIdentNamed(ft.Results.List[0].Type, "bool"); !okBool {
				continue
			}
		}
		cands[vName] = rtGate
		allowed := map[*ast.Ident]bool{}
		for id := range k.idx.varDeclIdents[vName] {
			allowed[id] = true
		}
		allowedDeclIdents[vName] = allowed
	}
	if len(cands) == 0 {
		return
	}
	for _, f := range k.files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, okC := n.(*ast.CallExpr)
				if !okC || call.Ellipsis.IsValid() || len(call.Args) != 0 {
					return true
				}
				cID, okID := unwrapParens(call.Fun).(*ast.Ident)
				if !okID {
					return true
				}
				if _, isCand := cands[cID.Name]; isCand && !k.identShadowedInFunc(fn, cID.Name) {
					allowedDeclIdents[cID.Name][cID] = true
				}
				return true
			})
		}
	}
	leaked := filterNonSelPropIdentsInSet(k.files, allowedDeclIdents)
	for vName, rtGate := range cands {
		if !leaked[vName] {
			k.FalseFuncVars[vName] = rtGate
		}
	}
}

func (k *packageInactiveKernel) discoverPureIntReadFuncs() {
	for hName, fn := range k.idx.topFuncs {
		if ast.IsExported(hName) || k.idx.pkgDeclCounts[hName] != 1 || k.anyLinknameLocals[hName] || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
			continue
		}
		if !funcHasUnnamedResults(fn.Type, 1) || len(fn.Type.Results.List) != 1 || len(fn.Body.List) != 1 {
			continue
		}
		resID, okRes := unwrapParens(fn.Type.Results.List[0].Type).(*ast.Ident)
		if !okRes || !kernelPureIntConvNames[resID.Name] || k.idx.pkgDeclCounts[resID.Name] != 0 || k.identShadowedInFunc(fn, resID.Name) {
			continue
		}
		pNames := paramNamesFlat(fn.Type.Params)
		if len(pNames) != 1 || pNames[0] == "" || pNames[0] == "_" {
			continue
		}
		ret, okRet := fn.Body.List[0].(*ast.ReturnStmt)
		if !okRet || len(ret.Results) != 1 {
			continue
		}
		if k.isPureParamIntReadExpr(k.idx.funcFile[fn], fn, pNames[0], ret.Results[0]) {
			k.PureIntReadFuncs[hName] = true
		}
	}
}

func (k *packageInactiveKernel) isPureParamFieldChain(param string, expr ast.Expr) bool {
	switch e := unwrapParens(expr).(type) {
	case *ast.Ident:
		return e.Name == param
	case *ast.SelectorExpr:
		return k.isPureParamFieldChain(param, e.X)
	default:
		return false
	}
}

func (k *packageInactiveKernel) isPureParamIntReadExpr(f *ast.File, fn *ast.FuncDecl, param string, expr ast.Expr) bool {
	expr = unwrapParens(expr)
	if k.isPureParamFieldChain(param, expr) {
		return true
	}
	call, okC := expr.(*ast.CallExpr)
	if !okC || call.Ellipsis.IsValid() || len(call.Args) != 1 {
		return false
	}
	if cID, okID := unwrapParens(call.Fun).(*ast.Ident); okID {
		if !kernelPureIntConvNames[cID.Name] || k.idx.pkgDeclCounts[cID.Name] != 0 || k.identShadowedInFunc(fn, cID.Name) || cID.Name == param {
			return false
		}
		return k.isPureParamIntReadExpr(f, fn, param, call.Args[0])
	}
	// Allow `<atomicPkg>.Loaduintptr((*uintptr)(unsafe.Pointer(&<param.field...>)))`.
	sel, okS := unwrapParens(call.Fun).(*ast.SelectorExpr)
	if !okS || !kernelAtomicIntLoadNames[sel.Sel.Name] {
		return false
	}
	pkgID, okPkg := unwrapParens(sel.X).(*ast.Ident)
	if !okPkg || pkgID.Name == param || funcShadowsAnyIdent(fn, map[string]bool{pkgID.Name: true}) {
		return false
	}
	impPath := k.fileImportPath(f, pkgID.Name)
	if impPath != "internal/runtime/atomic" && impPath != "sync/atomic" {
		return false
	}
	ptrCast, okPC := unwrapParens(call.Args[0]).(*ast.CallExpr)
	if !okPC || ptrCast.Ellipsis.IsValid() || len(ptrCast.Args) != 1 {
		return false
	}
	starType, okST := unwrapParens(ptrCast.Fun).(*ast.StarExpr)
	if !okST {
		return false
	}
	tID, okTID := unwrapParens(starType.X).(*ast.Ident)
	if !okTID || !kernelPureIntConvNames[tID.Name] || k.idx.pkgDeclCounts[tID.Name] != 0 || k.identShadowedInFunc(fn, tID.Name) || tID.Name == param {
		return false
	}
	uCall, okUC := unwrapParens(ptrCast.Args[0]).(*ast.CallExpr)
	if !okUC || uCall.Ellipsis.IsValid() || len(uCall.Args) != 1 {
		return false
	}
	uSel, okUS := unwrapParens(uCall.Fun).(*ast.SelectorExpr)
	if !okUS || uSel.Sel.Name != "Pointer" {
		return false
	}
	uPkgID, okUP := unwrapParens(uSel.X).(*ast.Ident)
	if !okUP || uPkgID.Name == param || funcShadowsAnyIdent(fn, map[string]bool{uPkgID.Name: true}) || k.fileImportPath(f, uPkgID.Name) != "unsafe" {
		return false
	}
	amp, okAmp := unwrapParens(uCall.Args[0]).(*ast.UnaryExpr)
	if !okAmp || amp.Op != token.AND {
		return false
	}
	selTarget, okSel := unwrapParens(amp.X).(*ast.SelectorExpr)
	return okSel && k.isPureParamFieldChain(param, selTarget)
}

// isPureChain reports whether expr is a side-effect-free read chain over pureVars,
// field selections, `&`, integer conversions, and verified 1-arg pure integer read helpers.
func (k *packageInactiveKernel) isPureChain(expr ast.Expr, fn *ast.FuncDecl, pureVars map[string]bool) bool {
	if k == nil || k.hasDotImport || k.builtinsShadowed {
		return false
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.Ident:
		return pureVars[x.Name]
	case *ast.SelectorExpr:
		return k.isPureChain(x.X, fn, pureVars)
	case *ast.UnaryExpr:
		return x.Op == token.AND && k.isPureChain(x.X, fn, pureVars)
	case *ast.CallExpr:
		if x.Ellipsis.IsValid() || len(x.Args) != 1 {
			return false
		}
		cID, okID := unwrapParens(x.Fun).(*ast.Ident)
		if !okID || k.identShadowedInFunc(fn, cID.Name) {
			return false
		}
		if kernelPureIntConvNames[cID.Name] && k.idx.pkgDeclCounts[cID.Name] == 0 {
			return k.isPureChain(x.Args[0], fn, pureVars)
		}
		if k.PureIntReadFuncs[cID.Name] {
			return k.isPureChain(x.Args[0], fn, pureVars)
		}
		return false
	default:
		return false
	}
}

// isPureGuardExpr reports whether expr is a side-effect-free boolean/scalar guard
// expression over pureVars, literals, and package boolean constants.
func (k *packageInactiveKernel) isPureGuardExpr(expr ast.Expr, fn *ast.FuncDecl, pureVars map[string]bool) bool {
	if k == nil || k.hasDotImport || k.builtinsShadowed {
		return false
	}
	if k.isPureChain(expr, fn, pureVars) {
		return true
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		if x.Name == "nil" || x.Name == "true" || x.Name == "false" {
			return k.idx.pkgDeclCounts[x.Name] == 0 && !k.identShadowedInFunc(fn, x.Name)
		}
		if k.TrueConsts[x.Name] || k.FalseConsts[x.Name] {
			return !k.identShadowedInFunc(fn, x.Name)
		}
	case *ast.UnaryExpr:
		return x.Op == token.NOT && k.isPureGuardExpr(x.X, fn, pureVars)
	case *ast.BinaryExpr:
		switch x.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ, token.LAND, token.LOR:
			return k.isPureGuardExpr(x.X, fn, pureVars) && k.isPureGuardExpr(x.Y, fn, pureVars)
		}
	}
	return false
}

func mergeGateLists(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return make([]string, 0)
	}
	set := make(map[string]bool, len(a)+len(b))
	for _, g := range a {
		if g != "" {
			set[g] = true
		}
	}
	for _, g := range b {
		if g != "" {
			set[g] = true
		}
	}
	out := sortedKeys(set)
	if out == nil {
		return make([]string, 0)
	}
	return out
}

// evalFalseExpr proves that expr evaluates to false without side effects,
// returning any runtime.* inactive gates required for the proof.
func (k *packageInactiveKernel) evalFalseExpr(expr ast.Expr, fn *ast.FuncDecl, pureVars map[string]bool) ([]string, bool) {
	if k == nil || k.hasDotImport || k.builtinsShadowed {
		return nil, false
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.Ident:
		if (x.Name == "false" || k.FalseConsts[x.Name]) && !k.identShadowedInFunc(fn, x.Name) {
			return make([]string, 0), true
		}
	case *ast.UnaryExpr:
		if x.Op == token.NOT {
			return k.evalTrueExpr(x.X, fn, pureVars)
		}
	case *ast.CallExpr:
		if !x.Ellipsis.IsValid() {
			if cID, okID := unwrapParens(x.Fun).(*ast.Ident); okID && !k.identShadowedInFunc(fn, cID.Name) {
				if len(x.Args) == 0 {
					if rtGate, okG := k.FalseGates[cID.Name]; okG {
						if rtGate == "" {
							return make([]string, 0), true
						}
						return []string{rtGate}, true
					}
					if rtGate, okFV := k.FalseFuncVars[cID.Name]; okFV {
						if rtGate == "" {
							return make([]string, 0), true
						}
						return []string{rtGate}, true
					}
				}
				if gates, okEF := k.EarlyFalseFuncs[cID.Name]; okEF {
					allPure := true
					for _, arg := range x.Args {
						if !k.isPureGuardExpr(arg, fn, pureVars) {
							allPure = false
							break
						}
					}
					if allPure {
						return mergeGateLists(gates, nil), true
					}
				}
			}
		}
	case *ast.BinaryExpr:
		switch x.Op {
		case token.LAND:
			if gL, okL := k.evalFalseExpr(x.X, fn, pureVars); okL {
				return gL, true
			}
			if k.isPureGuardExpr(x.X, fn, pureVars) {
				return k.evalFalseExpr(x.Y, fn, pureVars)
			}
			if gT, okT := k.evalTrueExpr(x.X, fn, pureVars); okT {
				if gR, okR := k.evalFalseExpr(x.Y, fn, pureVars); okR {
					return mergeGateLists(gT, gR), true
				}
			}
		case token.LOR:
			gL, okL := k.evalFalseExpr(x.X, fn, pureVars)
			if !okL {
				return nil, false
			}
			gR, okR := k.evalFalseExpr(x.Y, fn, pureVars)
			if !okR {
				return nil, false
			}
			return mergeGateLists(gL, gR), true
		}
	}
	return nil, false
}

// evalTrueExpr proves that expr evaluates to true without side effects,
// returning any runtime.* inactive gates required for the proof.
func (k *packageInactiveKernel) evalTrueExpr(expr ast.Expr, fn *ast.FuncDecl, pureVars map[string]bool) ([]string, bool) {
	if k == nil || k.hasDotImport || k.builtinsShadowed {
		return nil, false
	}
	switch x := unwrapParens(expr).(type) {
	case *ast.Ident:
		if (x.Name == "true" || k.TrueConsts[x.Name]) && !k.identShadowedInFunc(fn, x.Name) {
			return make([]string, 0), true
		}
	case *ast.UnaryExpr:
		if x.Op == token.NOT {
			return k.evalFalseExpr(x.X, fn, pureVars)
		}
	case *ast.BinaryExpr:
		switch x.Op {
		case token.LOR:
			if gL, okL := k.evalTrueExpr(x.X, fn, pureVars); okL {
				return gL, true
			}
			if k.isPureGuardExpr(x.X, fn, pureVars) {
				return k.evalTrueExpr(x.Y, fn, pureVars)
			}
			if gF, okF := k.evalFalseExpr(x.X, fn, pureVars); okF {
				if gR, okR := k.evalTrueExpr(x.Y, fn, pureVars); okR {
					return mergeGateLists(gF, gR), true
				}
			}
		case token.LAND:
			gL, okL := k.evalTrueExpr(x.X, fn, pureVars)
			if !okL {
				return nil, false
			}
			gR, okR := k.evalTrueExpr(x.Y, fn, pureVars)
			if !okR {
				return nil, false
			}
			return mergeGateLists(gL, gR), true
		}
	}
	return nil, false
}

func (k *packageInactiveKernel) discoverHelperStubs() {
	for {
		changed := false
		for hName, fn := range k.idx.topFuncs {
			if ast.IsExported(hName) || k.idx.pkgDeclCounts[hName] != 1 || k.anyLinknameLocals[hName] || fn.Body == nil || fn.Type == nil || fn.Type.TypeParams != nil || bodyHasControlFlowOrRecoverBypass(fn.Body) {
				continue
			}
			pureParams := map[string]bool{}
			for _, p := range paramNamesFlat(fn.Type.Params) {
				if p != "" && p != "_" {
					pureParams[p] = true
				}
			}
			req := map[string]bool{}
			pruned, _ := k.pruneBlockStmts(fn.Body.List, fn, pureParams, req, nil)
			numRes := 0
			if fn.Type.Results != nil {
				numRes = fn.Type.Results.NumFields()
			}
			switch numRes {
			case 0:
				if _, exists := k.NoopVoidFuncs[hName]; !exists && len(pruned) == 0 {
					k.NoopVoidFuncs[hName] = sortedKeys(req)
					changed = true
				}
			case 1:
				if funcHasUnnamedResults(fn.Type, 1) {
					resType := fn.Type.Results.List[0].Type
					if _, isBool := isIdentNamed(resType, "bool"); isBool && !k.identShadowedInFunc(fn, "bool") {
						if _, exists := k.EarlyFalseFuncs[hName]; !exists && len(pruned) > 0 {
							if ret, okR := pruned[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
								if g, okF := k.evalFalseExpr(ret.Results[0], fn, pureParams); okF {
									for _, r := range g {
										req[r] = true
									}
									k.EarlyFalseFuncs[hName] = sortedKeys(req)
									changed = true
								}
							} else if ifs, okI := pruned[0].(*ast.IfStmt); okI && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 {
								if ret, okR := ifs.Body.List[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
									if gCond, okT := k.evalTrueExpr(ifs.Cond, fn, pureParams); okT {
										if gRet, okF := k.evalFalseExpr(ret.Results[0], fn, pureParams); okF {
											for _, r := range gCond {
												req[r] = true
											}
											for _, r := range gRet {
												req[r] = true
											}
											k.EarlyFalseFuncs[hName] = sortedKeys(req)
											changed = true
										}
									}
								}
							}
						}
					} else if _, isErr := isIdentNamed(resType, "error"); isErr && !k.identShadowedInFunc(fn, "error") {
						if _, exists := k.NilErrFuncs[hName]; !exists && len(pruned) == 1 {
							if ret, okR := pruned[0].(*ast.ReturnStmt); okR && len(ret.Results) == 1 {
								if _, okNil := isIdentNamed(ret.Results[0], "nil"); okNil && !k.identShadowedInFunc(fn, "nil") {
									k.NilErrFuncs[hName] = sortedKeys(req)
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
}
