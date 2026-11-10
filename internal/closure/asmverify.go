package closure

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/asmverify"
	"github.com/greatliontech/gofresh/internal/trace"
)

const verifiedNonStdAsmMemoSummaryKey = "gofresh/verified-nonstd-asm@4"

func sortedCleanBasenamesKey(files []string) string {
	if len(files) == 0 {
		return ""
	}
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = filepath.Base(filepath.Clean(f))
	}
	slices.Sort(names)
	return strings.Join(names, "\x00")
}

func verifyNonStdAssemblyMemo(p *program, goarch, pkgPath, dir string, sFiles, hFiles []string, typeScopes []*types.Package, read func(string) ([]byte, error)) (*asmverify.VerifiedPackage, bool) {
	memoKey := goarch + "\x00" + pkgPath + "\x00" + filepath.Clean(dir) + "\x00" + sortedCleanBasenamesKey(sFiles) + "\x00|\x00" + sortedCleanBasenamesKey(hFiles)
	if p != nil && p.Summaries != nil {
		if memoMap, ok := p.Summaries[verifiedNonStdAsmMemoSummaryKey].(map[string]*asmverify.VerifiedPackage); ok {
			if cached, found := memoMap[memoKey]; found && cached != nil {
				if !cached.OK || !asmverify.CheckVerifiedTypeScopes(cached, typeScopes) {
					return &asmverify.VerifiedPackage{OK: false}, false
				}
				return cached, true
			}
		}
	}
	vp, ok := asmverify.VerifyNonStdFiles(goarch, pkgPath, dir, sFiles, hFiles, typeScopes, read)
	if !ok || vp == nil {
		vp = &asmverify.VerifiedPackage{OK: false}
	}
	if p != nil {
		if p.Summaries == nil {
			p.Summaries = make(map[string]any, 4)
		}
		memoMap, _ := p.Summaries[verifiedNonStdAsmMemoSummaryKey].(map[string]*asmverify.VerifiedPackage)
		if memoMap == nil {
			memoMap = make(map[string]*asmverify.VerifiedPackage, 4)
			p.Summaries[verifiedNonStdAsmMemoSummaryKey] = memoMap
		}
		memoMap[memoKey] = vp
	}
	if !vp.OK || !asmverify.CheckVerifiedTypeScopes(vp, typeScopes) {
		return &asmverify.VerifiedPackage{OK: false}, false
	}
	return vp, true
}

func (b *tier2Base) verifiedPackageAssembly(pkg *listPkg) (*asmverify.VerifiedPackage, bool) {
	if b == nil || b.h == nil || !b.h.SelectionAudited() || pkg == nil || len(pkg.SFiles) == 0 {
		return nil, false
	}
	if hasExternalCgoMeta(pkg) || len(pkg.SysoFiles) != 0 || hasNonHeaderNativeSource(pkg) {
		return nil, false
	}
	key := pkg.ImportPath + "\x00" + filepath.Clean(pkg.Dir)
	if b.verifiedAsm != nil {
		if cached, ok := b.verifiedAsm[key]; ok {
			return cached, cached.OK
		}
	}
	var typeScopes []*types.Package
	srcPath := pkg.SourcePath()
	for tp, idx := range b.idxByTypes {
		if tp != nil && idx != nil && (idx.path == srcPath || idx.path == pkg.ImportPath || (idx.meta != nil && idx.meta.Dir == pkg.Dir)) {
			typeScopes = append(typeScopes, tp)
		}
	}
	if len(pkg.GoFiles) > 0 && len(typeScopes) == 0 {
		if b.verifiedAsm == nil {
			b.verifiedAsm = make(map[string]*asmverify.VerifiedPackage, 4)
		}
		res := &asmverify.VerifiedPackage{OK: false}
		b.verifiedAsm[key] = res
		return res, false
	}
	readFn := func(fullPath string) ([]byte, error) {
		if b.h.underCache(pkg.Dir) {
			return os.ReadFile(fullPath)
		}
		fb, err := b.h.readFile(fullPath)
		if err != nil {
			return nil, err
		}
		return fb.content, nil
	}
	var start time.Time
	tracing := trace.Enabled(context.Background(), trace.DomainClosure, srcPath)
	if tracing {
		start = time.Now()
	}
	res, ok := verifyNonStdAssemblyMemo(b.prog, b.h.effectiveGOARCH(), srcPath, pkg.Dir, pkg.SFiles, pkg.HFiles, typeScopes, readFn)
	if !ok {
		res = &asmverify.VerifiedPackage{OK: false}
	}
	if tracing {
		trace.Emit(context.Background(), trace.DomainClosure, "asmverify.package.done", srcPath,
			trace.Bool("ok", res.OK),
			trace.Int("sfiles", len(pkg.SFiles)),
			trace.Int("hfiles", len(pkg.HFiles)),
			trace.Int("funcs", len(res.Funcs)),
			trace.Int64("duration_ns", time.Since(start).Nanoseconds()),
		)
	}
	if b.verifiedAsm == nil {
		b.verifiedAsm = make(map[string]*asmverify.VerifiedPackage, 4)
	}
	b.verifiedAsm[key] = res
	return res, res.OK
}

func (b *tier2Base) verifiedPackageAssemblyMaximalPure(pkg *listPkg) bool {
	vp, ok := b.verifiedPackageAssembly(pkg)
	if !ok || vp == nil {
		return false
	}
	for _, sum := range vp.Funcs {
		if sum.ImpureKind != "" || sum.CPUIDArgs > 0 {
			return false
		}
	}
	matchedIdx := false
	srcPath := pkg.SourcePath()
	for _, idx := range b.idxByTypes {
		if idx == nil || (idx.path != srcPath && idx.path != pkg.ImportPath && (idx.meta == nil || idx.meta.Dir != pkg.Dir)) {
			continue
		}
		matchedIdx = true
		for obj, node := range idx.decls {
			fnObj, isFn := obj.(*types.Func)
			fd, isFD := node.(*ast.FuncDecl)
			if !isFn || !isFD || fd.Body != nil {
				continue
			}
			sig, isSig := fnObj.Type().(*types.Signature)
			if !isSig || sig.Recv() != nil || sig.TypeParams().Len() > 0 || !asmverify.SignatureCarrierFree(sig) {
				return false
			}
			if _, found := vp.Funcs[fnObj.Name()]; !found {
				return false
			}
		}
	}
	return matchedIdx
}

func (a *tier2Analyzer) verifiedPackageAssembly(pkg *listPkg) bool {
	if a == nil || a.base == nil {
		return false
	}
	_, ok := a.base.verifiedPackageAssembly(pkg)
	return ok
}

func (a *tier2Analyzer) verifiedPackageAssemblyFunc(pkg *listPkg, fn *ssa.Function) (asmverify.TextSummary, bool) {
	if a == nil || a.base == nil || fn == nil || fn.Signature == nil || fn.Signature.Recv() != nil || fn.TypeParams().Len() > 0 {
		return asmverify.TextSummary{}, false
	}
	if !asmverify.SignatureCarrierFree(fn.Signature) {
		return asmverify.TextSummary{}, false
	}
	vp, ok := a.base.verifiedPackageAssembly(pkg)
	if !ok || vp == nil {
		return asmverify.TextSummary{}, false
	}
	sum, found := vp.Funcs[fn.Name()]
	if !found {
		return asmverify.TextSummary{}, false
	}
	if sum.CPUIDArgs > 0 && !asmverify.IsCanonicalCPUIDSignature(fn.Signature, sum.CPUIDArgs) {
		sum.CPUIDArgs = 0
		if sum.ImpureKind == "" {
			sum.ImpureKind = "per-core CPUID register"
		}
	}
	return sum, true
}

func (a *tier2Analyzer) scanVerifiedAsmBodylessFunction(fn *ssa.Function, idx *pkgIndex, isRoot bool) {
	if a == nil || fn == nil || idx == nil || idx.std || idx.meta == nil || len(idx.meta.SFiles) == 0 || len(fn.Blocks) != 0 {
		return
	}
	sum, ok := a.verifiedPackageAssemblyFunc(idx.meta, fn)
	if !ok {
		a.recordExternalEffect(opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly"))
		a.requestWiden("non-toolchain assembly in " + idx.id)
		return
	}
	fnName := functionSymbolName(fn)
	if sum.ImpureKind != "" {
		a.recordExternalEffect(symbolExternalEffect(externalEffectNative, idx.path, fnName, "reaches "+idx.path+"."+fnName+" ("+sum.ImpureKind+")"))
		return
	}
	if sum.CPUIDArgs > 0 && isRoot {
		a.recordExternalEffect(symbolExternalEffect(externalEffectNative, idx.path, fnName, "reaches "+idx.path+"."+fnName+" (per-core CPUID register)"))
	}
}

func (a *tier2Analyzer) classifyVerifiedAsmCallee(callee *ssa.Function, calleeIdx *pkgIndex, c *ssa.CallCommon, site ssa.CallInstruction) (externalEffect, bool) {
	if callee == nil || calleeIdx == nil || calleeIdx.meta == nil || len(calleeIdx.meta.SFiles) == 0 {
		return externalEffect{}, false
	}
	sum, ok := a.verifiedPackageAssemblyFunc(calleeIdx.meta, callee)
	if !ok {
		a.requestWiden("non-toolchain assembly in " + calleeIdx.id)
		return opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly"), true
	}
	fnName := functionSymbolName(callee)
	if sum.ImpureKind != "" {
		return symbolExternalEffect(externalEffectNative, calleeIdx.path, fnName, "reaches "+calleeIdx.path+"."+fnName+" ("+sum.ImpureKind+")"), true
	}
	if sum.CPUIDArgs > 0 && asmverify.CPUIDCallReadsPerCoreState(c, site) {
		return symbolExternalEffect(externalEffectNative, calleeIdx.path, fnName, "reaches "+calleeIdx.path+"."+fnName+" (per-core CPUID register)"), true
	}
	return externalEffect{}, false
}

func (b *tier2Base) isVerifiedReadOnlyLinknameVar(idx *pkgIndex, obj types.Object, target string) bool {
	if b == nil || b.h == nil || !b.h.SelectionAudited() || idx == nil || obj == nil {
		return false
	}
	wantKind, ok := auditset.AuditedReadOnlyVarLinknameTarget(target)
	if !ok {
		return false
	}
	checkOne := func(pIdx *pkgIndex, pObj types.Object) bool {
		if pIdx == nil || pObj == nil || pIdx.ssa == nil {
			return false
		}
		v, ok := pObj.(*types.Var)
		if !ok || v.IsField() || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
			return false
		}
		basic, ok := v.Type().Underlying().(*types.Basic)
		if !ok || basic.Kind() != wantKind {
			return false
		}
		if !b.pkgFreeOfUnverifiedNativeWriteHazard(pIdx) {
			return false
		}
		if g := pIdx.ssa.Var(v.Name()); g == nil || !ssaGlobalStrictlyReadOnly(b.prog, g) {
			return false
		}
		if pIdx.pkg != nil && !astPackageVarReadOnly(pIdx.pkg, v, false) {
			return false
		}
		if v.Exported() {
			for _, otherIdx := range b.idxByTypes {
				if otherIdx != nil && otherIdx != pIdx && otherIdx.pkg != nil && !astPackageVarReadOnly(otherIdx.pkg, v, false) {
					return false
				}
			}
		}
		return true
	}
	if !checkOne(idx, obj) {
		return false
	}
	for _, peer := range b.objsByLinkTarget[target] {
		if peer == obj {
			continue
		}
		if peer == nil || peer.Pkg() == nil {
			return false
		}
		peerIdx := b.idxByTypes[peer.Pkg()]
		if peerIdx != nil && peerIdx.std {
			continue
		}
		if !checkOne(peerIdx, peer) {
			return false
		}
	}
	return true
}

func (b *tier2Base) verifiedReadOnlyLinknameLocals(pkgPath string) map[string]bool {
	if b == nil || b.h == nil || !b.h.SelectionAudited() || pkgPath == "" {
		return nil
	}
	var out map[string]bool
	for _, idx := range b.idxByTypes {
		if idx == nil || idx.path != pkgPath {
			continue
		}
		for obj, target := range idx.linknames {
			if b.isVerifiedReadOnlyLinknameVar(idx, obj, target) {
				if out == nil {
					out = make(map[string]bool, 2)
				}
				out[obj.Name()] = true
			}
		}
		if idx.pkg != nil && idx.pkg.Types != nil && idx.pkg.Types.Scope() != nil {
			for name, target := range idx.linknameByName {
				obj := idx.pkg.Types.Scope().Lookup(name)
				if obj == nil {
					continue
				}
				if docTarget := idx.linknames[obj]; docTarget != "" && docTarget != target {
					delete(out, name)
					continue
				}
				if b.isVerifiedReadOnlyLinknameVar(idx, obj, target) {
					if out == nil {
						out = make(map[string]bool, 2)
					}
					out[name] = true
				}
			}
		}
	}
	return out
}

const nonReadOnlyGlobalsSummaryKey = "gofresh/non-readonly-globals@1"

func nonReadOnlySSAGlobals(p *program) map[*ssa.Global]bool {
	if p == nil || p.Prog == nil {
		return nil
	}
	if p.Summaries != nil {
		if cached, ok := p.Summaries[nonReadOnlyGlobalsSummaryKey].(map[*ssa.Global]bool); ok {
			return cached
		}
	}
	nonRO := map[*ssa.Global]bool{}
	var ops [16]*ssa.Value
	for _, fn := range progOrderedFunctions(p) {
		if fn == nil {
			continue
		}
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				if _, ok := instr.(*ssa.DebugRef); ok {
					continue
				}
				for _, op := range instr.Operands(ops[:0]) {
					if op == nil || *op == nil {
						continue
					}
					g, ok := (*op).(*ssa.Global)
					if !ok {
						continue
					}
					un, isUn := instr.(*ssa.UnOp)
					if !isUn || un.Op != token.MUL || un.X != g {
						nonRO[g] = true
					}
				}
			}
		}
	}
	if p.Summaries == nil {
		p.Summaries = make(map[string]any, 2)
	}
	p.Summaries[nonReadOnlyGlobalsSummaryKey] = nonRO
	return nonRO
}

func ssaGlobalStrictlyReadOnly(p *program, g *ssa.Global) bool {
	if p == nil || g == nil || g.Pkg == nil {
		return false
	}
	return !nonReadOnlySSAGlobals(p)[g]
}

// astPackageVarReadOnly verifies across every syntax tree of pkg (including
// uninstantiated generic functions that SSA may not materialize) that v is
// never assigned, incremented/decremented, bound in a range clause, or
// address-taken, and (when allowDeclInit is false) carries no ValueSpec
// initializer.
func astPackageVarReadOnly(pkg *packages.Package, v *types.Var, allowDeclInit bool) bool {
	if pkg == nil || v == nil || pkg.TypesInfo == nil {
		return false
	}
	usesVar := func(e ast.Expr) bool {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			return pkg.TypesInfo.Uses[x] == v || pkg.TypesInfo.Defs[x] == v
		case *ast.SelectorExpr:
			return x.Sel != nil && pkg.TypesInfo.Uses[x.Sel] == v
		}
		return false
	}
	ok := true
	for _, file := range pkg.Syntax {
		if file == nil || !ok {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if !ok || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.ValueSpec:
				for i, id := range x.Names {
					if pkg.TypesInfo.Defs[id] == v {
						if !allowDeclInit && (len(x.Values) > i || len(x.Values) > 0) {
							ok = false
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if usesVar(lhs) {
						ok = false
						return false
					}
				}
			case *ast.IncDecStmt:
				if usesVar(x.X) {
					ok = false
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN && (usesVar(x.Key) || usesVar(x.Value)) {
					ok = false
					return false
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && usesVar(x.X) {
					ok = false
					return false
				}
			}
			return true
		})
	}
	return ok
}
