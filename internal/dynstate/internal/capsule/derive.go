// Package capsule mechanically derives lazy once-initialized capsule types,
// raw and sample-aligned immutable builder types, and idempotent init-settled
// builder clusters across a package's syntax.
package capsule

import (
	"context"
	"go/ast"
	"go/types"
	"slices"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshalloc"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

func pkgTraceTarget(p *packages.Package) string {
	if p == nil {
		return ""
	}
	if p.PkgPath != "" {
		return p.PkgPath
	}
	if p.Types != nil {
		return p.Types.Path()
	}
	return ""
}

// EmitCapsuleReject emits a dynstate.capsule.reject trace event when
// trace.DomainDynstate is enabled for p.
func EmitCapsuleReject(ctx context.Context, p *packages.Package, symbol, reason string, at ast.Node) {
	target := pkgTraceTarget(p)
	if !trace.Enabled(ctx, trace.DomainDynstate, target) {
		return
	}
	pos := ""
	if p != nil && p.Fset != nil && at != nil && at.Pos().IsValid() {
		pos = p.Fset.Position(at.Pos()).String()
	}
	trace.Emit(ctx, trace.DomainDynstate, "dynstate.capsule.reject", target,
		trace.String("struct", symbol),
		trace.String("reason", reason),
		trace.String("pos", pos),
	)
}

func emitCapsuleReject(ctx context.Context, p *packages.Package, symbol, reason string, at ast.Node) {
	EmitCapsuleReject(ctx, p, symbol, reason, at)
}

// PackageFacts holds the capsule, builder, and init-settled cluster facts and
// mutation exemptions derived for a single package. Higher-layer passes treat
// its maps and slices as read-only inputs.
type PackageFacts struct {
	Clusters                []syntaxutil.InitSettledClusterFact
	Builders                []syntaxutil.InitBuilderFact
	Capsules                []syntaxutil.LazyOnceCapsuleType
	CondMutations           []syntaxutil.ConditionalStructMutation
	ClaimedVars             map[*types.Var]bool
	ExemptNodes             map[ast.Node]bool
	ExemptFamilyByFunc      map[*ast.FuncDecl]map[*types.Named]bool
	ExemptReadFields        map[*types.Var]bool
	ForeignReflectFields    map[*types.Var]bool
	ClusterCapsuleElemTypes map[*types.Var][]*types.Named
}

// DerivePackageFacts derives init-settled builder clusters, builder facts, lazy
// once-capsule facts, and capsule-scoped mutation exemptions across p.Syntax.
func DerivePackageFacts(
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshalloc.FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	initOnly map[string]bool,
	mutatedVars map[string]bool,
	extraExemptNodes map[ast.Node]bool,
) *PackageFacts {
	return DerivePackageFactsCtx(nil, audited, p, idx, freshCache, confinedCacheMaps, initOnly, mutatedVars, extraExemptNodes)
}

// DerivePackageFactsCtx derives init-settled clusters, builders, lazy
// once-capsules, and capsule-scoped mutation exemptions with ctx-scoped
// trace.DomainDynstate provenance emission.
func DerivePackageFactsCtx(
	ctx context.Context,
	audited bool,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshalloc.FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	initOnly map[string]bool,
	mutatedVars map[string]bool,
	extraExemptNodes map[ast.Node]bool,
) *PackageFacts {
	if p == nil || p.Types == nil || p.TypesInfo == nil || len(p.Syntax) == 0 {
		return &PackageFacts{}
	}
	if idx == nil {
		idx = refconfine.BuildPkgIndex(p)
	}
	if initOnly == nil {
		initOnly = idx.InitOnly
	}
	if freshCache == nil {
		freshCache = freshalloc.NewFreshLocalsCache(p, idx)
	}
	if confinedCacheMaps == nil {
		confinedCacheMaps = freshalloc.FindMutexConfinedConstructorCaches(p, idx)
	}
	exempted := make(map[ast.Node]bool, len(extraExemptNodes))
	for n, v := range extraExemptNodes {
		if v {
			exempted[n] = true
		}
	}
	out := &PackageFacts{
		ExemptNodes:          exempted,
		ExemptFamilyByFunc:   map[*ast.FuncDecl]map[*types.Named]bool{},
		ExemptReadFields:     map[*types.Var]bool{},
		ForeignReflectFields: map[*types.Var]bool{},
	}
	if audited {
		out.Clusters, out.ClaimedVars, out.ClusterCapsuleElemTypes = deriveInitSettledClusters(ctx, audited, p, idx, initOnly, out.ExemptNodes)
		out.Builders, out.Capsules, out.CondMutations = deriveBuildersAndCapsules(
			ctx, p, idx, freshCache, confinedCacheMaps, mutatedVars,
			out.ExemptNodes, out.ExemptFamilyByFunc, out.ExemptReadFields, out.ForeignReflectFields,
		)
	}
	return out
}

func addExemptStructInFunc(m map[*ast.FuncDecl]map[*types.Named]bool, fd *ast.FuncDecl, st *types.Named) {
	if fd == nil || st == nil {
		return
	}
	sub := m[fd]
	if sub == nil {
		sub = map[*types.Named]bool{}
		m[fd] = sub
	}
	sub[st] = true
}

func deriveBuildersAndCapsules(
	ctx context.Context,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshalloc.FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	mutatedVars map[string]bool,
	exempted map[ast.Node]bool,
	exemptFamilyByFunc map[*ast.FuncDecl]map[*types.Named]bool,
	exemptReadFields map[*types.Var]bool,
	foreignReflectFields map[*types.Var]bool,
) ([]syntaxutil.InitBuilderFact, []syntaxutil.LazyOnceCapsuleType, []syntaxutil.ConditionalStructMutation) {
	type candidate struct {
		ref   syntaxutil.TypeRef
		named *types.Named
		st    *types.Struct
	}
	var candidates []candidate
	for _, name := range p.Types.Scope().Names() {
		tn, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok || tn == nil || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok || named == nil {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: tn.Name()}
		if !ref.Valid() {
			continue
		}
		candidates = append(candidates, candidate{ref: ref, named: named, st: st})
	}

	var builders []syntaxutil.InitBuilderFact
	var capsules []syntaxutil.LazyOnceCapsuleType
	var conds []syntaxutil.ConditionalStructMutation
	builderExempt := map[ast.Node]bool{}
	builderHelperIdents := map[*ast.Ident]bool{}
	if confinedCacheMaps == nil {
		confinedCacheMaps = freshalloc.FindMutexConfinedConstructorCaches(p, idx)
	}

	for _, c := range candidates {
		if bf, dbNodes, dbByFunc, rawConds, okRaw := verifyRawCapsuleBuilderType(ctx, p, idx, c.ref, c.named, c.st, mutatedVars, exemptReadFields); okRaw {
			for n := range dbNodes {
				exempted[n] = true
			}
			for fd, fam := range dbByFunc {
				for st := range fam {
					addExemptStructInFunc(exemptFamilyByFunc, fd, st)
				}
			}
			conds = append(conds, rawConds...)
			builders = append(builders, bf)
		}
	}

	for _, c := range candidates {
		if bf, bNodes, helperIdents, okB := verifySampleCapsuleBuilderType(ctx, p, idx, c.ref, c.named, c.st, mutatedVars); okB {
			for n := range bNodes {
				exempted[n] = true
				builderExempt[n] = true
			}
			for id := range helperIdents {
				builderHelperIdents[id] = true
			}
			builders = append(builders, bf)
		}
	}

	verifiedLockedRoots := map[*types.Named]bool{}
	for progress := true; progress; {
		progress = false
		for _, c := range candidates {
			if verifiedLockedRoots[c.named] {
				continue
			}
			capFact, cNodes, cByFunc, cConds, okCap := verifyLockedOnceCapsuleType(
				nil, p, idx, freshCache, c.ref, c.named, c.st, mutatedVars, builderExempt, builderHelperIdents, verifiedLockedRoots, confinedCacheMaps,
			)
			if !okCap {
				continue
			}
			verifiedLockedRoots[c.named] = true
			progress = true
			for n := range cNodes {
				exempted[n] = true
			}
			for fd, fam := range cByFunc {
				for st := range fam {
					addExemptStructInFunc(exemptFamilyByFunc, fd, st)
				}
			}
			conds = append(conds, cConds...)
			capsules = append(capsules, capFact)
		}
	}
	if trace.Enabled(ctx, trace.DomainDynstate, pkgTraceTarget(p)) {
		for _, c := range candidates {
			if !verifiedLockedRoots[c.named] {
				_, _, _, _, _ = verifyLockedOnceCapsuleType(
					ctx, p, idx, freshCache, c.ref, c.named, c.st, mutatedVars, builderExempt, builderHelperIdents, verifiedLockedRoots, confinedCacheMaps,
				)
			}
		}
	}

	for _, c := range candidates {
		if verifiedLockedRoots[c.named] {
			continue
		}
		if verifyReadOnlyCapsuleType(p, idx, c.named, c.st, builderExempt, verifiedLockedRoots) {
			capsules = append(capsules, syntaxutil.LazyOnceCapsuleType{
				Type:                   c.ref,
				HasExportedReflectType: syntaxutil.StructHasExportedReflectTypeField(c.st),
			})
		}
	}

	capsuleReflectSafe := false
	if len(verifiedLockedRoots) > 0 {
		rejectReason := ""
		if freshalloc.PkgCanStepUnexportedReflectField(p, idx) {
			rejectReason = "step_unexported_reflect_field"
		} else if pkgTakesUnsafeAddrOfMatchingIface(p, idx, verifiedLockedRoots, nil) {
			rejectReason = "unsafe_addr_matching_iface"
		} else if !pkgConfinesMatchingIfaceValueOf(p, idx, verifiedLockedRoots, nil) {
			rejectReason = "unconfined_matching_iface_valueof"
		} else {
			capsuleReflectSafe = true
		}
		if rejectReason != "" {
			for root := range verifiedLockedRoots {
				ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: root.Obj().Name()}
				emitCapsuleReject(ctx, p, ref.Key(), rejectReason, nil)
			}
		}
	}
	if capsuleReflectSafe {
		for i := range capsules {
			if tn, okTN := p.Types.Scope().Lookup(capsules[i].Type.Name).(*types.TypeName); okTN && tn != nil {
				if capNamed, okCN := types.Unalias(tn.Type()).(*types.Named); okCN && verifiedLockedRoots[capNamed] {
					capsules[i].CapsuleReflectSafe = true
				}
			}
		}
	}
	if foreignReflectFields != nil && capsuleReflectSafe {
		for _, c := range candidates {
			if c.named == nil || c.named.Obj() == nil || c.named.Obj().Exported() || c.named.TypeParams() != nil {
				continue
			}
			if pkgReifiesStructReflectType(p, c.named) || pkgTakesUnsafeAddrOfMatchingIface(p, idx, verifiedLockedRoots, c.named) || !pkgConfinesMatchingIfaceValueOf(p, idx, verifiedLockedRoots, c.named) {
				continue
			}
			for i := 0; i < c.st.NumFields(); i++ {
				f := c.st.Field(i)
				if f.Exported() || f.Embedded() {
					continue
				}
				ptr, isP := types.Unalias(f.Type()).(*types.Pointer)
				if !isP {
					continue
				}
				elem, isN := types.Unalias(ptr.Elem()).(*types.Named)
				if isN && verifiedLockedRoots[elem] {
					foreignReflectFields[f] = true
				}
			}
		}
		atomicCopyFuncs := collectSafeAtomicPtrCopyFuncs(p, idx)
		for i := range capsules {
			if !capsules[i].CapsuleReflectSafe {
				continue
			}
			if tn, okTN := p.Types.Scope().Lookup(capsules[i].Type.Name).(*types.TypeName); okTN && tn != nil {
				if capNamed, okCN := types.Unalias(tn.Type()).(*types.Named); okCN {
					capsules[i].SafePtrWrapperParams = collectSafePtrWrapperParams(p, idx, capNamed, foreignReflectFields)
				}
			}
			capsules[i].SafeAtomicPtrCopyFuncs = atomicCopyFuncs
		}
	}

	slices.SortFunc(builders, syntaxutil.InitBuilderFact.Compare)
	slices.SortFunc(capsules, syntaxutil.LazyOnceCapsuleType.Compare)
	return builders, capsules, conds
}
