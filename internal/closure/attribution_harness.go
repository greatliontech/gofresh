package closure

import (
	"sort"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/closure/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/closure/internal/rta"
	"github.com/greatliontech/gofresh/internal/propharness"
)

func isGeneratedTestMainPackage(prog *program, pkg *ssa.Package) bool {
	return prog != nil && pkg != nil && pkg.Pkg != nil && pkg.Pkg.Name() == "main" && pkg.Pkg.Path() == prog.PkgPath+".test"
}

func isPotentialHarnessCallbackSite(site ssa.CallInstruction) bool {
	if site == nil || site.Common() == nil {
		return false
	}
	c := site.Common()
	if len(c.Args) == 0 {
		return false
	}
	if c.IsInvoke() {
		return c.Method != nil && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" && (c.Method.Name() == "Cleanup" || c.Method.Name() == "Fuzz")
	}
	if callee := c.StaticCallee(); callee != nil {
		if funcPkgPath(callee) != "testing" {
			return false
		}
		base := baseFunctionSymbolName(callee)
		return base == "Cleanup" || base == "Fuzz"
	}
	return true
}

func collectTestingHarnessCallbacks(audited bool, verifiedHarnesses map[string]*propharness.VerifiedPackage, pureDelegates map[string]bool, userPaths map[string]bool, summary *callerReferenceSummary, subjectRoot *ssa.Function, enumerated bool, enc enumerationClosure, prov map[*ssa.Function]bool, mask uint64, res *rta.Result) (cleanupOut []*ssa.Function, unclosedCleanup bool, fuzzOut []*ssa.Function, unclosedFuzz bool) {
	seenCleanup := make(map[*ssa.Function]bool)
	seenFuzz := make(map[*ssa.Function]bool)
	var lazyFP *freshParamAnalysis
	getFP := func() *freshParamAnalysis {
		if lazyFP != nil {
			return lazyFP
		}
		functions := make(map[*ssa.Function]bool, len(prov))
		dynamicTargets := make(map[ssa.CallInstruction]map[*ssa.Function]bool)
		if res != nil {
			for fn, m := range res.Reachable {
				if m&mask != 0 {
					functions[fn] = true
				}
			}
			for site, targets := range res.Targets {
				if !functions[site.Parent()] {
					continue
				}
				for t, m := range targets {
					if m&mask != 0 && functions[t] {
						proj := dynamicTargets[site]
						if proj == nil {
							proj = make(map[*ssa.Function]bool)
							dynamicTargets[site] = proj
						}
						proj[t] = true
					}
				}
			}
		} else {
			for fn := range prov {
				functions[fn] = true
			}
		}
		var reach attributedReachability
		reach.functions = functions
		reach.dynamicTargets = dynamicTargets
		reach.subjectRoot = subjectRoot
		reach.enumeratedRoot = enumerated
		reach.enumeratedRootSites = enc.sites
		reach.enumeratedFieldStores = enc.fieldStores
		reach.verifiedHarnesses = verifiedHarnesses
		reach.userPaths = userPaths
		if summary != nil {
			reach.prog = summary.prog
			reach.summary = summary
			reach.structFieldStores = summary.structFieldStores
			reach.structWholeStores = summary.structWholeStores
			reach.structPoisoned = summary.structPoisoned
			reach.structReferencedByType = summary.structReferencedByType
			reach.programSites = summary.sites
			reach.programValueRef = summary.valueRef
			reach.programFunctions = summary.allFunctions
		}
		lazyFP = newFreshParamAnalysis(audited, pureDelegates, reach, func(fn *ssa.Function) bool {
			return isStdPkgPath(userPaths, funcPkgPath(fn))
		})
		return lazyFP
	}
	checkFuzzSig := func(fb *ssa.Function) bool {
		if fb == nil {
			return false
		}
		for idx, p := range fb.Params {
			if p == nil {
				continue
			}
			if idx == 0 && isHarnessPointerType(p.Type()) {
				continue
			}
			if typeMayCarryDynamicTop(audited, p.Type()) {
				return false
			}
		}
		return true
	}
	markUnclosed := func(kind string) {
		if kind == "Fuzz" {
			unclosedFuzz = true
		} else {
			unclosedCleanup = true
		}
	}
	addCallback := func(kind string, cb *ssa.Function) {
		if cb == nil {
			return
		}
		if cb.Parent() == nil && verifiedHarnesses[funcPkgPath(cb)] != nil {
			markUnclosed(kind)
			return
		}
		if kind == "Fuzz" {
			if !checkFuzzSig(cb) {
				unclosedFuzz = true
				return
			}
			if !seenFuzz[cb] {
				seenFuzz[cb] = true
				fuzzOut = append(fuzzOut, cb)
			}
			return
		}
		if !seenCleanup[cb] {
			seenCleanup[cb] = true
			cleanupOut = append(cleanupOut, cb)
		}
	}
	unwrapIface := func(v ssa.Value) ssa.Value {
		for v != nil {
			switch u := v.(type) {
			case *ssa.MakeInterface:
				v = u.X
			case *ssa.ChangeInterface:
				v = u.X
			default:
				return v
			}
		}
		return nil
	}
	handleSite := func(site ssa.CallInstruction) {
		rawArg, kind := testingHarnessCallArg(site, mask, res)
		if kind == "" {
			return
		}
		arg := unwrapIface(rawArg)
		if arg == nil {
			markUnclosed(kind)
			return
		}
		switch x := arg.(type) {
		case *ssa.Function:
			addCallback(kind, x)
		case *ssa.MakeClosure:
			cb, ok := x.Fn.(*ssa.Function)
			if !ok || cb == nil {
				markUnclosed(kind)
				return
			}
			if isBoundMethodWrapper(cb) && len(x.Bindings) > 0 && typeMayCarryDynamicTop(audited, x.Bindings[0].Type()) {
				if !subjectClosedDynamicValue(x.Bindings[0], make(map[ssa.Value]bool), getFP()) {
					markUnclosed(kind)
					return
				}
			}
			addCallback(kind, cb)
		default:
			targets, closed := closedDynamicTargets(rawArg, getFP())
			if !closed || len(targets) == 0 {
				markUnclosed(kind)
				return
			}
			for cb := range targets {
				addCallback(kind, cb)
			}
		}
	}
	if summary != nil && summary.harnessCallbackSites != nil {
		var ordered []*ssa.Function
		for fn := range prov {
			if fn != nil && len(summary.harnessCallbackSites[fn]) > 0 {
				ordered = append(ordered, fn)
			}
		}
		if len(ordered) == 0 {
			return nil, false, nil, false
		}
		sort.Slice(ordered, func(i, j int) bool { return lessSSAFunctionOrder(ordered[i], ordered[j]) })
		for _, fn := range ordered {
			for _, site := range summary.harnessCallbackSites[fn] {
				handleSite(site)
			}
		}
	} else {
		ordered := make([]*ssa.Function, 0, len(prov))
		for fn := range prov {
			if fn != nil {
				ordered = append(ordered, fn)
			}
		}
		sort.Slice(ordered, func(i, j int) bool { return lessSSAFunctionOrder(ordered[i], ordered[j]) })
		for _, fn := range ordered {
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					if site, ok := instr.(ssa.CallInstruction); ok {
						handleSite(site)
					}
				}
			}
		}
	}
	sort.Slice(cleanupOut, func(i, j int) bool { return cleanupOut[i].String() < cleanupOut[j].String() })
	sort.Slice(fuzzOut, func(i, j int) bool { return fuzzOut[i].String() < fuzzOut[j].String() })
	return cleanupOut, unclosedCleanup, fuzzOut, unclosedFuzz
}

func testingHarnessCallArg(site ssa.CallInstruction, mask uint64, res *rta.Result) (ssa.Value, string) {
	if site == nil || site.Common() == nil {
		return nil, ""
	}
	c := site.Common()
	if len(c.Args) == 0 {
		return nil, ""
	}
	matchTarget := func(fn *ssa.Function) string {
		if fn == nil || funcPkgPath(fn) != "testing" {
			return ""
		}
		base := baseFunctionSymbolName(fn)
		if base == "Cleanup" || base == "Fuzz" {
			return base
		}
		return ""
	}
	if c.IsInvoke() && c.Method != nil && c.Method.Pkg() != nil && c.Method.Pkg().Path() == "testing" {
		if c.Method.Name() == "Cleanup" || c.Method.Name() == "Fuzz" {
			return c.Args[len(c.Args)-1], c.Method.Name()
		}
	}
	if callee := c.StaticCallee(); callee != nil {
		if kind := matchTarget(callee); kind != "" {
			return c.Args[len(c.Args)-1], kind
		}
		return nil, ""
	}
	if res == nil {
		return nil, ""
	}
	for target, tmask := range res.Targets[site] {
		if tmask&mask != 0 {
			if kind := matchTarget(target); kind != "" {
				return c.Args[len(c.Args)-1], kind
			}
		}
	}
	return nil, ""
}

func isVerifiedPureRootedAsmStub(audited bool, prog *program, fn *ssa.Function) bool {
	if !audited || prog == nil || fn == nil || len(fn.Blocks) != 0 || fn.Synthetic != "" || parameterizedBody(fn) {
		return false
	}
	if fn.Signature == nil || fn.Signature.Recv() != nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	if !asmverify.SignatureCarrierFree(fn.Signature) {
		return false
	}
	pkgPath := fn.Pkg.Pkg.Path()
	hazards := nonSSAGlobalHazardsSummary(audited, prog)
	if hazards == nil || hazards.linknamedVars[pkgVarKey{pkgPath: pkgPath, name: fn.Name()}] {
		return false
	}
	vp := hazards.verifiedAsm[pkgPath]
	if vp == nil || !vp.PackageSafe {
		return false
	}
	sum, ok := vp.Funcs[fn.Name()]
	if !ok || !sum.Verified || sum.ImpureKind != "" || !progAsmTextLinkageClean(hazards, prog, pkgPath, fn.Name(), sum.GoCallees) {
		return false
	}
	if sum.CPUIDArgs > 0 && !asmverify.IsCanonicalCPUIDSignature(fn.Signature, sum.CPUIDArgs) {
		return false
	}
	for _, ref := range sum.ExternalSBRefs {
		if _, refOK := classifyAsmExternalGlobalInProg(audited, prog, ref); !refOK {
			return false
		}
	}
	return true
}

func rootedProvenanceIncomplete(audited bool, verifiedHarnesses map[string]*propharness.VerifiedPackage, prog *program, userPaths map[string]bool, sets ...map[*ssa.Function]bool) bool {
	var space [16]*ssa.Value
	for _, set := range sets {
		for fn := range set {
			if fn == nil {
				continue
			}
			pkgPath := funcPkgPath(fn)
			if isStdPkgPath(userPaths, pkgPath) {
				continue
			}
			if len(fn.Blocks) == 0 {
				if fn.Synthetic == "" && !parameterizedBody(fn) && !isVerifiedPureRootedAsmStub(audited, prog, fn) {
					return true
				}
				continue
			}
			for _, p := range fn.Params {
				if p != nil && nonStdTypeUsesUnsafePointer(audited, verifiedHarnesses, userPaths, p.Type()) {
					return true
				}
			}
			for _, b := range fn.Blocks {
				for _, instr := range b.Instrs {
					if v, ok := instr.(ssa.Value); ok && nonStdTypeUsesUnsafePointer(audited, verifiedHarnesses, userPaths, v.Type()) {
						return true
					}
					for _, op := range instr.Operands(space[:0]) {
						if op == nil || *op == nil {
							continue
						}
						if nonStdTypeUsesUnsafePointer(audited, verifiedHarnesses, userPaths, (*op).Type()) {
							return true
						}
						if g, ok := (*op).(*ssa.Function); ok {
							if isUnattributableRootedStdSymbol(funcPkgPath(g), baseFunctionSymbolName(g)) {
								return true
							}
						}
					}
					site, ok := instr.(ssa.CallInstruction)
					if !ok || site.Common() == nil {
						continue
					}
					c := site.Common()
					if c.IsInvoke() {
						if c.Method != nil && c.Method.Pkg() != nil && isUnattributableRootedStdSymbol(c.Method.Pkg().Path(), c.Method.Name()) {
							return true
						}
						continue
					}
					if b, ok := c.Value.(*ssa.Builtin); ok {
						switch b.Name() {
						case "Add", "Slice", "SliceData", "String", "StringData":
							return true
						}
						continue
					}
					if callee := c.StaticCallee(); callee != nil {
						cPkg := funcPkgPath(callee)
						if isUnattributableRootedStdSymbol(cPkg, baseFunctionSymbolName(callee)) {
							return true
						}
						if (userPaths[cPkg] || !isStdImportPath(cPkg)) && len(callee.Blocks) == 0 && callee.Synthetic == "" && !parameterizedBody(callee) && !isVerifiedPureRootedAsmStub(audited, prog, callee) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func isTestingCleanupCallback(fn *ssa.Function) bool {
	if fn == nil || fn.Parent() == nil {
		return false
	}
	for _, b := range fn.Parent().Blocks {
		for _, instr := range b.Instrs {
			switch x := instr.(type) {
			case *ssa.MakeClosure:
				if x.Fn == fn && x.Referrers() != nil {
					for _, ref := range *x.Referrers() {
						if site, ok := ref.(ssa.CallInstruction); ok && isTestingCleanupCall(site, x) {
							return true
						}
					}
				}
			case ssa.CallInstruction:
				if isTestingCleanupCall(x, fn) {
					return true
				}
			}
		}
	}
	return false
}

func isTestingCleanupCall(site ssa.CallInstruction, arg ssa.Value) bool {
	if site == nil || site.Common() == nil {
		return false
	}
	c := site.Common()
	hasArg := false
	for _, a := range c.Args {
		if a == arg {
			hasArg = true
			break
		}
	}
	if !hasArg {
		return false
	}
	if c.IsInvoke() {
		return c.Method != nil && c.Method.Name() == "Cleanup"
	}
	callee := c.StaticCallee()
	return callee != nil && funcPkgPath(callee) == "testing" && functionSymbolName(callee) == "Cleanup"
}
