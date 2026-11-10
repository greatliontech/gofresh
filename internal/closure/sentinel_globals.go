package closure

import (
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/internal/auditset"
)

const verifiedUserSentinelGlobalsSummaryKey = "gofresh/user-sentinel-globals@1"

func verifiedUserSentinelGlobals(audited bool, p *program) map[*ssa.Global]bool {
	if !audited || p == nil || p.Prog == nil {
		return nil
	}
	if p.Summaries != nil {
		if cached, ok := p.Summaries[verifiedUserSentinelGlobalsSummaryKey].(map[*ssa.Global]bool); ok {
			return cached
		}
	}
	blockedPkgs, linknamedVars := nonSSAGlobalHazards(audited, p)
	if summary := lookupSummaryForProg(p, audited); summary != nil && summary.errorNewSentinelGlobals != nil {
		verified := make(map[*ssa.Global]bool, len(summary.errorNewSentinelGlobals))
		for g := range summary.errorNewSentinelGlobals {
			if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil {
				continue
			}
			pkgPath := g.Pkg.Pkg.Path()
			if blockedPkgs[pkgPath] || linknamedVars[pkgVarKey{pkgPath: pkgPath, name: g.Name()}] {
				continue
			}
			verified[g] = true
		}
		if p.Summaries == nil {
			p.Summaries = make(map[string]any, 2)
		}
		p.Summaries[verifiedUserSentinelGlobalsSummaryKey] = verified
		return verified
	}
	errType := types.Universe.Lookup("error").Type()
	poisoned := make(map[*ssa.Global]bool)
	initStores := make(map[*ssa.Global]int)
	var space [16]*ssa.Value
	for _, fn := range progOrderedFunctions(p) {
		if fn == nil {
			continue
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				for _, op := range instr.Operands(space[:0]) {
					if op == nil {
						continue
					}
					g, ok := (*op).(*ssa.Global)
					if !ok || g == nil || poisoned[g] || g.Pkg == nil || g.Pkg.Pkg == nil {
						continue
					}
					ptr, ok := types.Unalias(g.Type()).(*types.Pointer)
					if !ok || !types.Identical(ptr.Elem(), errType) {
						continue
					}
					pkgPath := g.Pkg.Pkg.Path()
					if blockedPkgs[pkgPath] || linknamedVars[pkgVarKey{pkgPath: pkgPath, name: g.Name()}] {
						poisoned[g] = true
						continue
					}
					switch r := instr.(type) {
					case *ssa.DebugRef:
					case *ssa.UnOp:
						if r.Op != token.MUL || r.X != g {
							poisoned[g] = true
						}
					case *ssa.Store:
						if r.Addr != g || r.Val == g || fn != g.Pkg.Func("init") {
							poisoned[g] = true
							continue
						}
						call, ok := r.Val.(*ssa.Call)
						if !ok || call.Common() == nil {
							poisoned[g] = true
							continue
						}
						callee := call.Common().StaticCallee()
						if callee == nil || funcPkgPath(callee) != "errors" || callee.Name() != "New" {
							poisoned[g] = true
							continue
						}
						initStores[g]++
						if initStores[g] > 1 {
							poisoned[g] = true
						}
					default:
						poisoned[g] = true
					}
				}
			}
		}
	}
	verified := make(map[*ssa.Global]bool, len(initStores))
	for g, count := range initStores {
		if count == 1 && !poisoned[g] {
			verified[g] = true
		}
	}
	if p.Summaries == nil {
		p.Summaries = make(map[string]any, 2)
	}
	p.Summaries[verifiedUserSentinelGlobalsSummaryKey] = verified
	return verified
}

func isUnmutatedSentinelGlobal(audited bool, p *program, userPaths map[string]bool, g *ssa.Global) bool {
	if !audited || p == nil || g == nil || g.Pkg == nil || g.Pkg.Pkg == nil || g.Pkg.Prog != p.Prog {
		return false
	}
	pkgPath := g.Pkg.Pkg.Path()
	if isStdPkgPath(userPaths, pkgPath) && !isInternalStdPackagePath(pkgPath) {
		return false
	}
	return verifiedUserSentinelGlobals(audited, p)[g]
}

func isUnmutatedStandardSentinelGlobalAny(p *program, g *ssa.Global) bool {
	if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil {
		return false
	}
	pkgPath := g.Pkg.Pkg.Path()
	if !auditset.StandardSentinelGlobal(pkgPath, g.Name()) {
		return false
	}
	return isUnmutatedStandardSentinelGlobal(p, g, pkgPath, g.Name())
}

func computeMutatedGlobals(all map[*ssa.Function]bool) map[*ssa.Global]bool {
	mutated := make(map[*ssa.Global]bool)
	var space [16]*ssa.Value
	for fn := range all {
		if fn == nil {
			continue
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				for _, op := range instr.Operands(space[:0]) {
					if op == nil {
						continue
					}
					g, ok := (*op).(*ssa.Global)
					if !ok || g == nil || mutated[g] {
						continue
					}
					switch r := instr.(type) {
					case *ssa.DebugRef:
					case *ssa.UnOp:
						if r.Op != token.MUL || r.X != g {
							mutated[g] = true
						}
					case *ssa.Store:
						if r.Addr != g || fn.Pkg != g.Pkg || !initFlowFrame(fn) {
							mutated[g] = true
						}
					default:
						mutated[g] = true
					}
				}
			}
		}
	}
	return mutated
}

func mutatedGlobalsForProgram(p *program, ssaProg *ssa.Program) map[*ssa.Global]bool {
	if p != nil && p.Prog == ssaProg {
		if p.MutatedGlobals != nil {
			return p.MutatedGlobals
		}
		if summary := lookupSummaryForProg(p, true); summary == nil {
			summary = lookupSummaryForProg(p, false)
		} else if summary.mutatedGlobals != nil {
			p.MutatedGlobals = summary.mutatedGlobals
			return p.MutatedGlobals
		}
		if summary := lookupSummaryForProg(p, false); summary != nil && summary.mutatedGlobals != nil {
			p.MutatedGlobals = summary.mutatedGlobals
			return p.MutatedGlobals
		}
		p.MutatedGlobals = computeMutatedGlobals(progAllFunctions(p))
		return p.MutatedGlobals
	}
	if ssaProg == nil {
		return nil
	}
	return computeMutatedGlobals(ssautil.AllFunctions(ssaProg))
}

func isUnmutatedStandardSentinelGlobal(p *program, g *ssa.Global, wantPkg, wantName string) bool {
	if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil || g.Pkg.Prog == nil || g.Pkg.Pkg.Path() != wantPkg || g.Name() != wantName {
		return false
	}
	return !mutatedGlobalsForProgram(p, g.Pkg.Prog)[g]
}

func sentinelGlobalConcreteTypes(g *ssa.Global, out map[types.Type]bool) bool {
	if g == nil || g.Pkg == nil {
		return false
	}
	if ptr, ok := types.Unalias(g.Type()).(*types.Pointer); ok {
		if _, isIface := ptr.Elem().Underlying().(*types.Interface); !isIface {
			out[ptr.Elem()] = true
			return true
		}
	}
	initFn := g.Pkg.Func("init")
	if initFn == nil {
		return false
	}
	found := false
	for _, b := range initFn.Blocks {
		for _, instr := range b.Instrs {
			store, ok := instr.(*ssa.Store)
			if !ok || store.Addr != g {
				continue
			}
			if mi, ok := store.Val.(*ssa.MakeInterface); ok && mi.X != nil {
				out[mi.X.Type()] = true
				found = true
			} else if call, ok := store.Val.(*ssa.Call); ok && call.Common() != nil {
				if callee := call.Common().StaticCallee(); callee != nil {
					for _, cb := range callee.Blocks {
						for _, cinstr := range cb.Instrs {
							if ret, ok := cinstr.(*ssa.Return); ok && len(ret.Results) == 1 {
								if mi, ok := ret.Results[0].(*ssa.MakeInterface); ok && mi.X != nil {
									out[mi.X.Type()] = true
									found = true
								}
							}
						}
					}
				}
			}
		}
	}
	return found
}

func (fp *freshParamAnalysis) stdTypeMayDelegateDynamic(t types.Type) bool {
	if t == nil {
		return true
	}
	audited := fp != nil && fp.selectionAudited
	base := types.Unalias(t)
	if ptr, ok := base.(*types.Pointer); ok {
		base = types.Unalias(ptr.Elem())
	}
	named, ok := base.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return true
	}
	if _, ok := auditedAtomicPointerElem(audited, named); ok {
		return true
	}
	if _, isStruct := named.Underlying().(*types.Struct); !isStruct {
		return true
	}
	pkgPath := named.Obj().Pkg().Path()
	if !isStdPkgPath(fp.userPkgPaths(), pkgPath) {
		return true
	}
	if fp.isAuditedStandardOrDelegate(pkgPath) {
		return true
	}
	switch pkgPath {
	case "context", "math/rand", "net/url", "sync":
		return true
	default:
		return false
	}
}
