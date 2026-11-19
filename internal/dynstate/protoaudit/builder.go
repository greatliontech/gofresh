package protoaudit

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"slices"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
	"github.com/greatliontech/gofresh/internal/trace"
)

func deriveProtoRuntimeTypes(
	ctx context.Context,
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshstruct.FreshLocalsCache,
	confinedCacheMaps map[*types.Var]map[*ast.FuncDecl]bool,
	mutatedVars map[string]bool,
	exempted map[ast.Node]bool,
	exemptFamilyByFunc map[*ast.FuncDecl]map[*types.Named]bool,
	exemptReadFields map[*types.Var]bool,
	foreignReflectFields map[*types.Var]bool,
) ([]ProtoRuntimeTypeFact, []syntaxutil.ConditionalStructMutation) {
	type candidate struct {
		ref   syntaxutil.TypeRef
		named *types.Named
		st    *types.Struct
	}
	var candidates []candidate
	for _, name := range p.Types.Scope().Names() {
		tn, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok || tn.IsAlias() {
			continue
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
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

	var out []ProtoRuntimeTypeFact
	var conds []syntaxutil.ConditionalStructMutation
	builderExempt := map[ast.Node]bool{}
	builderHelperIdents := map[*ast.Ident]bool{}
	if confinedCacheMaps == nil {
		confinedCacheMaps = freshstruct.FindMutexConfinedConstructorCaches(p, idx)
	}

	for _, c := range candidates {
		if dbNodes, dbByFunc, dbGuards, okDB := verifyProtoDescBuilderType(p, idx, c.named, c.st, mutatedVars, exemptReadFields); okDB {
			for n := range dbNodes {
				exempted[n] = true
			}
			for fd, fam := range dbByFunc {
				for st := range fam {
					addExemptStructInFunc(exemptFamilyByFunc, fd, st)
				}
			}
			out = append(out, ProtoRuntimeTypeFact{
				Type:       c.ref,
				Role:       ProtoRoleDescBuilder,
				GuardTypes: dbGuards,
			})
		}
	}

	for _, c := range candidates {
		if bNodes, helperIdents, subBuilder, allowedHelpers, bGuards, okB := verifyProtoBuilderType(p, idx, c.named, c.st, mutatedVars); okB {
			for n := range bNodes {
				exempted[n] = true
				builderExempt[n] = true
			}
			for id := range helperIdents {
				builderHelperIdents[id] = true
			}
			out = append(out, ProtoRuntimeTypeFact{
				Type:           c.ref,
				Role:           ProtoRoleBuilder,
				SubBuilder:     subBuilder,
				AllowedHelpers: allowedHelpers,
				GuardTypes:     bGuards,
			})
		}
	}

	verifiedMsgRoots := map[*types.Named]bool{}
	verifiedCapsuleRoots := map[*types.Named]bool{}
	for _, c := range candidates {
		if mNodes, mByFunc, mGuards, mConds, okM := verifyProtoMessageType(p, idx, freshCache, c.named, c.st, mutatedVars, builderExempt, verifiedMsgRoots, confinedCacheMaps); okM {
			verifiedMsgRoots[c.named] = true
			verifiedCapsuleRoots[c.named] = true
			for n := range mNodes {
				exempted[n] = true
			}
			for fd, fam := range mByFunc {
				for st := range fam {
					addExemptStructInFunc(exemptFamilyByFunc, fd, st)
				}
			}
			conds = append(conds, mConds...)
			out = append(out, ProtoRuntimeTypeFact{
				Type:       c.ref,
				Role:       ProtoRoleMessage,
				GuardTypes: mGuards,
			})
		}
	}
	for _, c := range candidates {
		if eNodes, eByFunc, initHelper, eGuards, eConds, okE := verifyProtoExtensionType(p, idx, freshCache, c.named, c.st, mutatedVars, builderExempt, builderHelperIdents, verifiedMsgRoots, confinedCacheMaps); okE {
			verifiedCapsuleRoots[c.named] = true
			for n := range eNodes {
				exempted[n] = true
			}
			for fd, fam := range eByFunc {
				for st := range fam {
					addExemptStructInFunc(exemptFamilyByFunc, fd, st)
				}
			}
			conds = append(conds, eConds...)
			out = append(out, ProtoRuntimeTypeFact{
				Type:       c.ref,
				Role:       ProtoRoleExtension,
				InitHelper: initHelper,
				GuardTypes: eGuards,
			})
		}
	}
	for _, c := range candidates {
		if verifyProtoEnumType(p, idx, c.named, c.st, builderExempt, verifiedMsgRoots) {
			out = append(out, ProtoRuntimeTypeFact{Type: c.ref, Role: ProtoRoleEnum})
		}
	}
	capsuleReflectSafe := false
	if len(verifiedCapsuleRoots) > 0 {
		target := p.PkgPath
		if target == "" {
			target = p.Types.Path()
		}
		rejectReason := ""
		if freshstruct.PkgCanStepUnexportedReflectField(p, idx) {
			rejectReason = "step_unexported_reflect_field"
		} else if pkgTakesUnsafeAddrOfMatchingIface(p, idx, verifiedCapsuleRoots, nil) {
			rejectReason = "unsafe_addr_matching_iface"
		} else if !pkgConfinesMatchingIfaceValueOf(p, idx, verifiedCapsuleRoots, nil) {
			rejectReason = "unconfined_matching_iface_valueof"
		} else {
			capsuleReflectSafe = true
		}
		if rejectReason != "" && trace.Enabled(ctx, trace.DomainDynstate, target) {
			for i := range out {
				if out[i].Role == ProtoRoleMessage || out[i].Role == ProtoRoleExtension {
					trace.Emit(ctx, trace.DomainDynstate, "dynstate.capsule.reject", target,
						trace.String("struct", out[i].Type.Key()),
						trace.String("role", out[i].Role),
						trace.String("reason", rejectReason),
					)
				}
			}
		}
	}
	if capsuleReflectSafe {
		for i := range out {
			if out[i].Role == ProtoRoleMessage || out[i].Role == ProtoRoleExtension {
				out[i].CapsuleReflectSafe = true
			}
		}
	}
	if foreignReflectFields != nil && capsuleReflectSafe {
		for _, c := range candidates {
			if c.named == nil || c.named.Obj() == nil || c.named.Obj().Exported() || c.named.TypeParams() != nil {
				continue
			}
			if pkgReifiesStructReflectType(p, c.named) || pkgTakesUnsafeAddrOfMatchingIface(p, idx, verifiedCapsuleRoots, c.named) || !pkgConfinesMatchingIfaceValueOf(p, idx, verifiedCapsuleRoots, c.named) {
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
				if isN && verifiedCapsuleRoots[elem] {
					foreignReflectFields[f] = true
				}
			}
		}
		atomicCopyFuncs := collectSafeAtomicPtrCopyFuncs(p, idx)
		for i := range out {
			if !out[i].CapsuleReflectSafe {
				continue
			}
			if tn, okTN := p.Types.Scope().Lookup(out[i].Type.Name).(*types.TypeName); okTN && tn != nil {
				if capNamed, okCN := types.Unalias(tn.Type()).(*types.Named); okCN {
					out[i].SafePtrWrapperParams = collectSafePtrWrapperParams(p, idx, capNamed, foreignReflectFields)
				}
			}
			out[i].SafeAtomicPtrCopyFuncs = atomicCopyFuncs
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type.Key() != out[j].Type.Key() {
			return out[i].Type.Key() < out[j].Type.Key()
		}
		return out[i].Role < out[j].Role
	})
	return out, conds
}

func pkgReifiesStructReflectType(p *packages.Package, target *types.Named) bool {
	if p == nil || p.TypesInfo == nil || target == nil {
		return false
	}
	mentionsTarget := func(root types.Type) bool {
		seen := map[types.Type]bool{}
		hit := false
		var walk func(t types.Type)
		walk = func(t types.Type) {
			if t == nil || hit {
				return
			}
			t = types.Unalias(t)
			if t == target {
				hit = true
				return
			}
			if seen[t] {
				return
			}
			seen[t] = true
			switch u := t.Underlying().(type) {
			case *types.Pointer:
				walk(u.Elem())
			case *types.Slice:
				walk(u.Elem())
			case *types.Array:
				walk(u.Elem())
			case *types.Map:
				walk(u.Key())
				walk(u.Elem())
			case *types.Chan:
				walk(u.Elem())
			case *types.Struct:
				for i := 0; i < u.NumFields(); i++ {
					walk(u.Field(i).Type())
				}
			}
		}
		walk(root)
		return hit
	}
	reified := false
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if reified || n == nil {
				return false
			}
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
			if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "reflect" || !syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
				return true
			}
			switch callee.Name() {
			case "TypeOf", "ValueOf":
				if len(call.Args) == 1 && mentionsTarget(p.TypesInfo.TypeOf(call.Args[0])) {
					reified = true
					return false
				}
			case "TypeFor":
				if sig, okS := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(call.Fun)).(*types.Signature); okS && sig.Results().Len() == 1 {
					for id, inst := range p.TypesInfo.Instances {
						if id.Pos() >= call.Fun.Pos() && id.End() <= call.Fun.End() && inst.TypeArgs != nil {
							for ti := 0; ti < inst.TypeArgs.Len(); ti++ {
								if mentionsTarget(inst.TypeArgs.At(ti)) {
									reified = true
									return false
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	return reified
}

func isSealedStdlibIface(p *packages.Package, iface *types.Interface) bool {
	if p == nil || iface == nil {
		return false
	}
	for i := 0; i < iface.NumMethods(); i++ {
		m := iface.Method(i)
		if !m.Exported() && m.Pkg() != nil && m.Pkg() != p.Types && syntaxutil.IsTrueStdlibInPkg(p, m.Pkg().Path()) {
			return true
		}
	}
	return false
}

func typeMentionsMatchingNonEmptyIface(p *packages.Package, root types.Type, stopRoots map[*types.Named]bool, target *types.Named) bool {
	var ptrTarget *types.Pointer
	if target != nil {
		ptrTarget = types.NewPointer(target)
	}
	seen := map[types.Type]bool{}
	hit := false
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || hit {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		if n, isN := t.(*types.Named); isN && stopRoots[n] {
			return
		}
		switch u := t.Underlying().(type) {
		case *types.Interface:
			if u.NumMethods() > 0 && !isSealedStdlibIface(p, u) &&
				(target == nil || types.Implements(target, u) || types.Implements(ptrTarget, u)) {
				hit = true
				return
			}
		case *types.Pointer:
			walk(u.Elem())
		case *types.Slice:
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Map:
			walk(u.Key())
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(root)
	return hit
}

func pkgTakesUnsafeAddrOfMatchingIface(p *packages.Package, idx *refconfine.PkgIndex, stopRoots map[*types.Named]bool, target *types.Named) bool {
	if p == nil || p.TypesInfo == nil || idx == nil {
		return false
	}
	hit := false
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if hit || n == nil {
				return false
			}
			call, isCall := n.(*ast.CallExpr)
			if !isCall || len(call.Args) == 0 {
				return true
			}
			if tv := p.TypesInfo.Types[call.Fun]; tv.IsType() && len(call.Args) == 1 && syntaxutil.IsUnsafePointerType(types.Unalias(tv.Type)) {
				if refconfine.IsPureAtomicLoadInnerConv(p, idx, call) ||
					refconfine.IsAtomicPointerSlotTargetInnerConv(p, idx, call) ||
					refconfine.IsSafeAtomicPointerValueArg(p, idx, call) {
					return true
				}
				if ptr, isP := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(call.Args[0])).(*types.Pointer); isP && typeMentionsMatchingNonEmptyIface(p, ptr.Elem(), stopRoots, target) {
					hit = true
					return false
				}
				return true
			}
			if b := syntaxutil.LookupBuiltin(p.TypesInfo, ast.Unparen(call.Fun)); b != nil {
				switch b.Name() {
				case "SliceData":
					if sl, isSl := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(call.Args[0])).(*types.Slice); isSl && typeMentionsMatchingNonEmptyIface(p, sl.Elem(), stopRoots, target) {
						hit = true
						return false
					}
				case "Slice":
					if ptr, isP := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(call.Args[0])).(*types.Pointer); isP && typeMentionsMatchingNonEmptyIface(p, ptr.Elem(), stopRoots, target) {
						hit = true
						return false
					}
				}
			}
			return true
		})
	}
	return hit
}

func pkgConfinesMatchingIfaceValueOf(p *packages.Package, idx *refconfine.PkgIndex, stopRoots map[*types.Named]bool, target *types.Named) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil {
		return false
	}
	var ptrTarget *types.Pointer
	if target != nil {
		ptrTarget = types.NewPointer(target)
	}
	stmtAlwaysPanics := func(stmt ast.Stmt) bool {
		blk, isB := stmt.(*ast.BlockStmt)
		if !isB || len(blk.List) == 0 {
			return false
		}
		es, isE := blk.List[len(blk.List)-1].(*ast.ExprStmt)
		if !isE {
			return false
		}
		c, isC := ast.Unparen(es.X).(*ast.CallExpr)
		if !isC {
			return false
		}
		cid, isID := ast.Unparen(c.Fun).(*ast.Ident)
		if !isID {
			return false
		}
		b, isBuilt := p.TypesInfo.Uses[cid].(*types.Builtin)
		return isBuilt && b.Name() == "panic"
	}
	isRVTypeCall := func(expr ast.Expr, rv *types.Var) bool {
		c, isC := ast.Unparen(expr).(*ast.CallExpr)
		if !isC || len(c.Args) != 0 || c.Ellipsis.IsValid() {
			return false
		}
		sel, isS := ast.Unparen(c.Fun).(*ast.SelectorExpr)
		if !isS || sel.Sel == nil || sel.Sel.Name != "Type" {
			return false
		}
		id, isID := ast.Unparen(sel.X).(*ast.Ident)
		if !isID || p.TypesInfo.Uses[id] != rv {
			return false
		}
		fn := syntaxutil.ResolveCalledFuncObj(p, c.Fun)
		return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "reflect" && fn.Name() == "Type"
	}
	ok := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !ok || n == nil {
				return false
			}
			call, isCall := n.(*ast.CallExpr)
			if !isCall || len(call.Args) != 1 || call.Ellipsis.IsValid() || !syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
				return true
			}
			callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
			if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "reflect" || callee.Name() != "ValueOf" {
				return true
			}
			argT := p.TypesInfo.TypeOf(call.Args[0])
			if argT == nil {
				return true
			}
			iface, isIf := types.Unalias(argT).Underlying().(*types.Interface)
			if !isIf {
				if typeMentionsMatchingNonEmptyIface(p, argT, stopRoots, target) {
					ok = false
					return false
				}
				return true
			}
			if iface.NumMethods() == 0 || isSealedStdlibIface(p, iface) {
				return true
			}
			if target != nil && !types.Implements(target, iface) && !types.Implements(ptrTarget, iface) {
				return true
			}
			if sel, isSel := idx.ParentUnparen(call).(*ast.SelectorExpr); isSel && ast.Unparen(sel.X) == call && sel.Sel != nil {
				if oc, isOC := idx.ParentUnparen(sel).(*ast.CallExpr); isOC && ast.Unparen(oc.Fun) == sel {
					switch sel.Sel.Name {
					case "Type", "Kind", "IsNil", "IsValid", "IsZero", "Len", "Cap", "NumField", "NumMethod":
						return true
					}
				}
			}
			as, isAS := idx.ParentUnparen(call).(*ast.AssignStmt)
			if !isAS || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != call {
				ok = false
				return false
			}
			lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
			if !isID {
				ok = false
				return false
			}
			rv, _ := p.TypesInfo.Uses[lid].(*types.Var)
			if rv == nil {
				rv, _ = p.TypesInfo.Defs[lid].(*types.Var)
			}
			enclFD := idx.SyncEnclFuncDecl(call)
			if rv == nil || enclFD == nil || idx.EnclFunc[call] != enclFD || enclFD.Body == nil || rv.Parent() == p.Types.Scope() ||
				rv.Pos() <= enclFD.Body.Pos() || rv.Pos() >= enclFD.Body.End() {
				ok = false
				return false
			}
			sawReturn := false
			for _, uid := range idx.UsesOf[rv] {
				if idx.EnclFunc[uid] != enclFD {
					ok = false
					return false
				}
				if uid == lid {
					continue
				}
				par := idx.ParentUnparen(uid)
				switch pn := par.(type) {
				case *ast.AssignStmt:
					if len(pn.Lhs) != 1 || len(pn.Rhs) != 1 || ast.Unparen(pn.Lhs[0]) != uid {
						ok = false
						return false
					}
					rc, isRC := ast.Unparen(pn.Rhs[0]).(*ast.CallExpr)
					if !isRC {
						ok = false
						return false
					}
					rfn := syntaxutil.ResolveCalledFuncObj(p, rc.Fun)
					if rfn == nil || rfn.Pkg() == nil || rfn.Pkg().Path() != "reflect" {
						ok = false
						return false
					}
					switch rfn.Name() {
					case "ValueOf", "Zero", "Elem":
					default:
						ok = false
						return false
					}
				case *ast.SelectorExpr:
					if ast.Unparen(pn.X) != uid || pn.Sel == nil {
						ok = false
						return false
					}
					oc, isOC := idx.ParentUnparen(pn).(*ast.CallExpr)
					if !isOC || ast.Unparen(oc.Fun) != pn {
						ok = false
						return false
					}
					switch pn.Sel.Name {
					case "Type", "Kind", "IsNil", "IsValid", "IsZero", "Len", "Cap", "NumField", "NumMethod":
					case "Elem":
						ras, isRAS := idx.ParentUnparen(oc).(*ast.AssignStmt)
						if !isRAS || len(ras.Lhs) != 1 || len(ras.Rhs) != 1 || ast.Unparen(ras.Rhs[0]) != oc {
							ok = false
							return false
						}
						rlid, isRID := ast.Unparen(ras.Lhs[0]).(*ast.Ident)
						if !isRID || p.TypesInfo.Uses[rlid] != rv {
							ok = false
							return false
						}
					default:
						ok = false
						return false
					}
				case *ast.ReturnStmt:
					sawReturn = true
				default:
					ok = false
					return false
				}
			}
			if sawReturn {
				var earliestRetPos token.Pos
				hasGoto := false
				var assignAfter func(afterPos token.Pos) bool
				ast.Inspect(enclFD.Body, func(bn ast.Node) bool {
					if bn == nil {
						return false
					}
					if br, isBr := bn.(*ast.BranchStmt); isBr && br.Tok == token.GOTO {
						hasGoto = true
					}
					if retS, isRet := bn.(*ast.ReturnStmt); isRet && retS.Pos() >= call.Pos() {
						if !earliestRetPos.IsValid() || retS.Pos() < earliestRetPos {
							earliestRetPos = retS.Pos()
						}
					}
					return true
				})
				assignAfter = func(afterPos token.Pos) bool {
					reassigned := false
					ast.Inspect(enclFD.Body, func(bn ast.Node) bool {
						if reassigned || bn == nil {
							return false
						}
						if as, isAS := bn.(*ast.AssignStmt); isAS && as.Pos() >= afterPos {
							for _, lhs := range as.Lhs {
								if id, isID := ast.Unparen(lhs).(*ast.Ident); isID && p.TypesInfo.Uses[id] == rv {
									reassigned = true
									return false
								}
							}
						}
						return true
					})
					return reassigned
				}
				if hasGoto || !earliestRetPos.IsValid() {
					ok = false
					return false
				}
				var enclRecvVar *types.Var
				if enclFD.Recv != nil && len(enclFD.Recv.List) == 1 && len(enclFD.Recv.List[0].Names) == 1 {
					rvObj, _ := p.TypesInfo.Defs[enclFD.Recv.List[0].Names[0]].(*types.Var)
					if rvObj != nil && idx.DefCounts[rvObj] == 1 {
						recvClean := true
						for _, ruid := range idx.UsesOf[rvObj] {
							if refconfine.IdentIsWrittenOrAddrTaken(idx, ruid) {
								recvClean = false
								break
							}
						}
						if recvClean {
							enclRecvVar = rvObj
						}
					}
				}
				isRecvUnexportedField := func(expr ast.Expr) bool {
					if enclRecvVar == nil {
						return false
					}
					sel, isS := ast.Unparen(expr).(*ast.SelectorExpr)
					if !isS || !syntaxutil.IsIdentUsingObj(p.TypesInfo, sel.X, enclRecvVar) {
						return false
					}
					selInfo := p.TypesInfo.Selections[sel]
					if selInfo == nil || selInfo.Kind() != types.FieldVal || selInfo.Obj() == nil || selInfo.Obj().Exported() {
						return false
					}
					fld, _ := selInfo.Obj().(*types.Var)
					return isSafeConverterGoTypeField(p, idx, fld, stopRoots)
				}
				hasTypeGuard := false
				for _, stmt := range enclFD.Body.List {
					if stmt.Pos() >= earliestRetPos {
						break
					}
					ifs, isIfS := stmt.(*ast.IfStmt)
					if !isIfS || ifs.Init != nil || ifs.Pos() <= call.End() || ifs.End() > earliestRetPos || ifs.Else != nil || !stmtAlwaysPanics(ifs.Body) {
						continue
					}
					bin, isBin := ast.Unparen(ifs.Cond).(*ast.BinaryExpr)
					if !isBin || bin.Op != token.NEQ {
						continue
					}
					xIsRV := isRVTypeCall(bin.X, rv)
					yIsRV := isRVTypeCall(bin.Y, rv)
					otherSide := bin.Y
					if yIsRV {
						otherSide = bin.X
					}
					if xIsRV != yIsRV && isRecvUnexportedField(otherSide) && !assignAfter(ifs.Pos()) {
						hasTypeGuard = true
						break
					}
				}
				if !hasTypeGuard {
					ok = false
					return false
				}
			}
			return true
		})
	}
	return ok
}

func isZeroSizedStructOrArray(root types.Type) bool {
	seen := map[types.Type]bool{}
	var check func(t types.Type) bool
	check = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if seen[t] {
			return false
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Array:
			return u.Len() == 0
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if !check(u.Field(i).Type()) {
					return false
				}
			}
			return true
		}
		return false
	}
	return check(root)
}

func isSafeConverterGoTypeField(p *packages.Package, idx *refconfine.PkgIndex, fld *types.Var, verifiedCapsuleRoots map[*types.Named]bool) bool {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || fld == nil || !fld.IsField() || fld.Exported() || fld.Pkg() != p.Types {
		return false
	}
	pkgPath := p.Types.Path()
	isInternalPkg := pkgPath == "internal" || strings.HasPrefix(pkgPath, "internal/") ||
		strings.HasSuffix(pkgPath, "/internal") || strings.Contains(pkgPath, "/internal/")
	ownerNamed := (*types.Named)(nil)
	for _, name := range p.Types.Scope().Names() {
		tn, okTN := p.Types.Scope().Lookup(name).(*types.TypeName)
		if !okTN || tn == nil || tn.IsAlias() {
			continue
		}
		n, okN := tn.Type().(*types.Named)
		if !okN || n == nil {
			continue
		}
		st, okSt := n.Underlying().(*types.Struct)
		if !okSt {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			if st.Field(i) == fld {
				if n.Obj().Exported() || ownerNamed != nil {
					return false
				}
				ownerNamed = n
			}
		}
	}
	if ownerNamed == nil {
		return false
	}
	ownerSt := ownerNamed.Underlying().(*types.Struct)
	fldIdx := -1
	for i := 0; i < ownerSt.NumFields(); i++ {
		if ownerSt.Field(i) == fld {
			fldIdx = i
			break
		}
	}
	if fldIdx < 0 {
		return false
	}
	for _, uid := range idx.UsesOf[fld] {
		if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && ast.Unparen(kv.Key) == uid {
			continue
		}
		if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
			return false
		}
	}
	hasStructRebindOrUnsafeAddr := func(target *types.Named) bool {
		if target == nil {
			return true
		}
		targetSt, okSt := target.Underlying().(*types.Struct)
		if !okSt {
			return true
		}
		matchesTarget := func(t types.Type) bool {
			if t == nil {
				return false
			}
			t = types.Unalias(t)
			if ptr, isP := t.(*types.Pointer); isP {
				t = types.Unalias(ptr.Elem())
			}
			return t == target || types.IdenticalIgnoreTags(t.Underlying(), targetSt)
		}
		hit := false
		for _, file := range p.Syntax {
			ast.Inspect(file, func(n ast.Node) bool {
				if hit || n == nil {
					return false
				}
				call, isC := n.(*ast.CallExpr)
				if !isC || len(call.Args) != 1 || call.Ellipsis.IsValid() {
					return true
				}
				tv := p.TypesInfo.Types[ast.Unparen(call.Fun)]
				if !tv.IsType() || tv.Type == nil || syntaxutil.IsNilIdent(p.TypesInfo, call.Args[0]) {
					return true
				}
				dstT := types.Unalias(tv.Type)
				srcT := p.TypesInfo.TypeOf(call.Args[0])
				if srcT == nil {
					return true
				}
				srcT = types.Unalias(srcT)
				if syntaxutil.IsUnsafePointerType(dstT) && matchesTarget(srcT) {
					hit = true
					return false
				}
				_, dstSt := syntaxutil.DerefAnyStructType(dstT)
				_, srcSt := syntaxutil.DerefAnyStructType(srcT)
				if dstSt != nil && srcSt != nil &&
					(matchesTarget(dstT) || matchesTarget(srcT)) && !types.Identical(dstT, srcT) {
					hit = true
					return false
				}
				return true
			})
		}
		return hit
	}
	if hasStructRebindOrUnsafeAddr(ownerNamed) {
		return false
	}
	visitedVars := map[*types.Var]bool{}
	var isSafeTypeOrigin func(expr ast.Expr) bool
	isSafeTypeOrigin = func(expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		expr = ast.Unparen(expr)
		switch e := expr.(type) {
		case *ast.Ident:
			v, _ := p.TypesInfo.Uses[e].(*types.Var)
			if v == nil || v.Pkg() != p.Types {
				return false
			}
			if visitedVars[v] {
				return true
			}
			for _, uid := range idx.UsesOf[v] {
				if u, isU := idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND && ast.Unparen(u.X) == uid {
					return false
				}
			}
			for fn, fd := range idx.FuncDecls {
				if fn == nil || fd == nil {
					continue
				}
				sig, okS := fn.Type().(*types.Signature)
				if !okS {
					continue
				}
				for pi := 0; pi < sig.Params().Len(); pi++ {
					if sig.Params().At(pi) == v {
						if sig.Recv() != nil {
							return false
						}
						if fn.Exported() && (!isInternalPkg || len(idx.UsesOf[fn]) == 0) {
							return false
						}
						visitedVars[v] = true
						for _, cuid := range idx.UsesOf[fn] {
							cc := refconfine.EnclosingCallOfCalleeIdent(idx, cuid)
							if cc == nil || cc.Ellipsis.IsValid() || pi >= len(cc.Args) {
								return false
							}
							if !isSafeTypeOrigin(cc.Args[pi]) {
								return false
							}
						}
						return true
					}
				}
			}
			if v.Parent() == p.Types.Scope() {
				if idx.DefCounts[v] != 1 {
					return false
				}
				for _, uid := range idx.UsesOf[v] {
					if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
						return false
					}
				}
				vs := idx.VarSpecs[v]
				if vs == nil || len(vs.Names) != len(vs.Values) {
					return false
				}
				visitedVars[v] = true
				for i, nm := range vs.Names {
					if p.TypesInfo.Defs[nm] == v {
						return isSafeTypeOrigin(vs.Values[i])
					}
				}
				return false
			}
			enclFD := idx.EnclFunc[e]
			if enclFD == nil || enclFD.Body == nil {
				return false
			}
			visitedVars[v] = true
			sawWrite := false
			localOK := true
			ast.Inspect(enclFD.Body, func(bn ast.Node) bool {
				if !localOK || bn == nil {
					return false
				}
				switch x := bn.(type) {
				case *ast.ValueSpec:
					for i, nm := range x.Names {
						if p.TypesInfo.Defs[nm] == v {
							if i >= len(x.Values) || !isSafeTypeOrigin(x.Values[i]) {
								localOK = false
								return false
							}
							sawWrite = true
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range x.Lhs {
						lid, isID := ast.Unparen(lhs).(*ast.Ident)
						if !isID {
							continue
						}
						if p.TypesInfo.Defs[lid] == v || p.TypesInfo.Uses[lid] == v {
							if len(x.Lhs) != len(x.Rhs) || i >= len(x.Rhs) || !isSafeTypeOrigin(x.Rhs[i]) {
								localOK = false
								return false
							}
							sawWrite = true
						}
					}
				case *ast.RangeStmt:
					for _, re := range []ast.Expr{x.Key, x.Value} {
						if rid, isID := ast.Unparen(re).(*ast.Ident); isID && (p.TypesInfo.Defs[rid] == v || p.TypesInfo.Uses[rid] == v) {
							localOK = false
							return false
						}
					}
				}
				return true
			})
			return sawWrite && localOK
		case *ast.SelectorExpr:
			selInfo := p.TypesInfo.Selections[e]
			if selInfo == nil || selInfo.Kind() != types.FieldVal {
				return false
			}
			if syntaxutil.IsNamedInPkg(selInfo.Recv(), "reflect", "StructField") && e.Sel != nil && e.Sel.Name == "Type" {
				return true
			}
			recvNamed := syntaxutil.DerefNamedStruct(selInfo.Recv())
			if recvNamed == nil {
				return false
			}
			if verifiedCapsuleRoots[recvNamed] {
				return true
			}
			sfld, _ := selInfo.Obj().(*types.Var)
			if sfld == nil || !sfld.IsField() || sfld.Exported() || sfld.Pkg() != p.Types ||
				recvNamed.Obj() == nil || recvNamed.Obj().Pkg() != p.Types || recvNamed.Obj().Exported() ||
				hasStructRebindOrUnsafeAddr(recvNamed) {
				return false
			}
			if visitedVars[sfld] {
				return true
			}
			for _, uid := range idx.UsesOf[sfld] {
				if u, isU := idx.ParentUnparen(uid).(*ast.UnaryExpr); isU && u.Op == token.AND {
					return false
				}
			}
			sSt, okSt := recvNamed.Underlying().(*types.Struct)
			if !okSt {
				return false
			}
			sIdx := -1
			for si := 0; si < sSt.NumFields(); si++ {
				if sSt.Field(si) == sfld {
					sIdx = si
					break
				}
			}
			if sIdx < 0 {
				return false
			}
			visitedVars[sfld] = true
			sawFldWrite := false
			fldOK := true
			for _, sfile := range p.Syntax {
				ast.Inspect(sfile, func(sn ast.Node) bool {
					if !fldOK || sn == nil {
						return false
					}
					switch sx := sn.(type) {
					case *ast.CompositeLit:
						if syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(sx)) != recvNamed || len(sx.Elts) == 0 {
							return true
						}
						if _, isKV0 := sx.Elts[0].(*ast.KeyValueExpr); isKV0 {
							for _, elt := range sx.Elts {
								kv, isKV := elt.(*ast.KeyValueExpr)
								if !isKV {
									fldOK = false
									return false
								}
								kid, isID := ast.Unparen(kv.Key).(*ast.Ident)
								if isID && p.TypesInfo.Uses[kid] == sfld {
									if !isSafeTypeOrigin(kv.Value) {
										fldOK = false
										return false
									}
									sawFldWrite = true
								}
							}
						} else if sIdx < len(sx.Elts) {
							if !isSafeTypeOrigin(sx.Elts[sIdx]) {
								fldOK = false
								return false
							}
							sawFldWrite = true
						}
					case *ast.AssignStmt:
						for i, lhs := range sx.Lhs {
							lsel, isS := ast.Unparen(lhs).(*ast.SelectorExpr)
							if !isS || lsel.Sel == nil || p.TypesInfo.Uses[lsel.Sel] != sfld {
								continue
							}
							if len(sx.Lhs) != len(sx.Rhs) || i >= len(sx.Rhs) || !isSafeTypeOrigin(sx.Rhs[i]) {
								fldOK = false
								return false
							}
							sawFldWrite = true
						}
					}
					return true
				})
			}
			return sawFldWrite && fldOK
		case *ast.CallExpr:
			callee := syntaxutil.ResolveCalledFuncObj(p, e.Fun)
			if callee == nil || callee.Pkg() == nil || callee.Pkg().Path() != "reflect" || !syntaxutil.IsTrueStdlibInPkg(p, "reflect") {
				return false
			}
			switch callee.Name() {
			case "Elem", "Key":
				if sel, isS := ast.Unparen(e.Fun).(*ast.SelectorExpr); isS && len(e.Args) == 0 {
					return isSafeTypeOrigin(sel.X)
				}
			case "PtrTo", "PointerTo", "SliceOf":
				return len(e.Args) == 1 && isSafeTypeOrigin(e.Args[0])
			case "TypeOf":
				if len(e.Args) != 1 || e.Ellipsis.IsValid() {
					return false
				}
				return isCarrierFreeSafeTypeOfArg(p, p.TypesInfo.TypeOf(e.Args[0]))
			}
		}
		return false
	}
	sawInit := false
	allInitsOK := true
	for _, file := range p.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if !allInitsOK || n == nil {
				return false
			}
			cl, isCL := n.(*ast.CompositeLit)
			if !isCL || syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(cl)) != ownerNamed || len(cl.Elts) == 0 {
				return true
			}
			sawInit = true
			if _, isKV0 := cl.Elts[0].(*ast.KeyValueExpr); isKV0 {
				for _, elt := range cl.Elts {
					kv, isKV := elt.(*ast.KeyValueExpr)
					if !isKV {
						allInitsOK = false
						return false
					}
					kid, isID := ast.Unparen(kv.Key).(*ast.Ident)
					if isID && p.TypesInfo.Uses[kid] == fld {
						if !isSafeTypeOrigin(kv.Value) {
							allInitsOK = false
							return false
						}
					}
				}
			} else if fldIdx < len(cl.Elts) {
				if !isSafeTypeOrigin(cl.Elts[fldIdx]) {
					allInitsOK = false
					return false
				}
			}
			return true
		})
	}
	return sawInit && allInitsOK
}

func isCarrierFreeSafeTypeOfArg(p *packages.Package, root types.Type) bool {
	if p == nil || p.Types == nil || root == nil {
		return false
	}
	seen := map[types.Type]bool{}
	ok := true
	var walk func(t types.Type, allowPtr bool)
	walk = func(t types.Type, allowPtr bool) {
		if t == nil || !ok {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.Invalid || u.Kind() == types.UnsafePointer || u.Kind() == types.Uintptr {
				ok = false
			}
		case *types.Pointer:
			if !allowPtr {
				ok = false
				return
			}
			walk(u.Elem(), true)
		case *types.Slice:
			walk(u.Elem(), false)
		case *types.Array:
			walk(u.Elem(), false)
		case *types.Struct:
			named, isN := t.(*types.Named)
			if !isN || named.Obj() == nil || named.Obj().Pkg() != p.Types {
				ok = false
				return
			}
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type(), false)
			}
		default:
			ok = false
		}
	}
	walk(root, true)
	return ok
}

func collectSafePtrWrapperParams(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	capNamed *types.Named,
	foreignReflectFields map[*types.Var]bool,
) []syntaxutil.ParamKey {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || capNamed == nil {
		return nil
	}
	wantCapPtr := types.NewPointer(capNamed)
	isMatchingCapsuleWrapper := func(t types.Type) bool {
		wNamed, isN := types.Unalias(t).(*types.Named)
		if !isN || wNamed.Obj() == nil || wNamed.Obj().Pkg() != p.Types || wNamed.Obj().Exported() || wNamed.TypeParams() != nil {
			return false
		}
		st, isSt := wNamed.Underlying().(*types.Struct)
		if !isSt || st.NumFields() == 0 {
			return false
		}
		sawTarget := false
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if isZeroSizedStructOrArray(f.Type()) {
				if sawTarget {
					return false
				}
				continue
			}
			if sawTarget || !foreignReflectFields[f] || !types.Identical(types.Unalias(f.Type()), wantCapPtr) {
				return false
			}
			sawTarget = true
		}
		return sawTarget
	}
	var out []syntaxutil.ParamKey
	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || !fn.Exported() || fn.Pkg() != p.Types {
			continue
		}
		sig, okS := fn.Type().(*types.Signature)
		if !okS || sig.TypeParams().Len() > 0 || sig.RecvTypeParams().Len() > 0 || sig.Params().Len() != 1 || sig.Results().Len() != 1 {
			continue
		}
		if sig.Recv() != nil && !isZeroSizedStructOrArray(sig.Recv().Type()) {
			continue
		}
		pv := sig.Params().At(0)
		if !syntaxutil.IsUnsafePointerType(pv.Type()) {
			continue
		}
		retPtr, isRP := types.Unalias(sig.Results().At(0).Type()).(*types.Pointer)
		if !isRP || !isMatchingCapsuleWrapper(retPtr.Elem()) {
			continue
		}
		if len(fd.Body.List) != 1 {
			continue
		}
		ret, isRet := fd.Body.List[0].(*ast.ReturnStmt)
		if !isRet || len(ret.Results) != 1 {
			continue
		}
		castCall, isCC := ast.Unparen(ret.Results[0]).(*ast.CallExpr)
		if !isCC || len(castCall.Args) != 1 || castCall.Ellipsis.IsValid() {
			continue
		}
		castTV := p.TypesInfo.Types[ast.Unparen(castCall.Fun)]
		if !castTV.IsType() || !types.Identical(types.Unalias(castTV.Type), types.Unalias(sig.Results().At(0).Type())) {
			continue
		}
		arg := ast.Unparen(castCall.Args[0])
		if innerConv, isIC := arg.(*ast.CallExpr); isIC && len(innerConv.Args) == 1 && !innerConv.Ellipsis.IsValid() {
			itv := p.TypesInfo.Types[ast.Unparen(innerConv.Fun)]
			if itv.IsType() && syntaxutil.IsUnsafePointerType(itv.Type) {
				arg = ast.Unparen(innerConv.Args[0])
			}
		}
		if !syntaxutil.IsIdentUsingObj(p.TypesInfo, arg, pv) {
			continue
		}
		if fk, okFK := syntaxutil.CallableFactKey(fn); okFK {
			out = append(out, syntaxutil.ParamKey{Func: fk, Index: 0})
		}
	}
	slices.SortFunc(out, syntaxutil.ParamKey.Compare)
	return out
}

func collectSafeAtomicPtrCopyFuncs(p *packages.Package, idx *refconfine.PkgIndex) []syntaxutil.FuncKey {
	if p == nil || p.Types == nil || p.TypesInfo == nil || idx == nil || !syntaxutil.IsTrueStdlibInPkg(p, "sync/atomic") {
		return nil
	}
	isUnsafePtrSlotCast := func(expr ast.Expr, wantParam *types.Var) bool {
		c, isC := ast.Unparen(expr).(*ast.CallExpr)
		if !isC || len(c.Args) != 1 || c.Ellipsis.IsValid() {
			return false
		}
		tv := p.TypesInfo.Types[ast.Unparen(c.Fun)]
		if !tv.IsType() || tv.Type == nil {
			return false
		}
		ptr, isP := types.Unalias(tv.Type).(*types.Pointer)
		if !isP || !syntaxutil.IsUnsafePointerType(ptr.Elem()) {
			return false
		}
		arg := ast.Unparen(c.Args[0])
		if ic, isIC := arg.(*ast.CallExpr); isIC && len(ic.Args) == 1 && !ic.Ellipsis.IsValid() {
			itv := p.TypesInfo.Types[ast.Unparen(ic.Fun)]
			if itv.IsType() && syntaxutil.IsUnsafePointerType(itv.Type) {
				arg = ast.Unparen(ic.Args[0])
			}
		}
		return syntaxutil.IsIdentUsingObj(p.TypesInfo, arg, wantParam)
	}
	isCopyAssignStmt := func(stmt ast.Stmt, srcP, dstP *types.Var) bool {
		as, isAS := stmt.(*ast.AssignStmt)
		if !isAS || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return false
		}
		st, isSt := ast.Unparen(as.Lhs[0]).(*ast.StarExpr)
		if !isSt || !isUnsafePtrSlotCast(st.X, dstP) {
			return false
		}
		rc, isRC := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
		if !isRC || len(rc.Args) != 1 || rc.Ellipsis.IsValid() {
			return false
		}
		fn := syntaxutil.ResolveCalledFuncObj(p, rc.Fun)
		return fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "sync/atomic" && fn.Name() == "LoadPointer" &&
			isUnsafePtrSlotCast(rc.Args[0], srcP)
	}
	var out []syntaxutil.FuncKey
	for fn, fd := range idx.FuncDecls {
		if fn == nil || fd == nil || fd.Body == nil || !fn.Exported() || fn.Pkg() != p.Types {
			continue
		}
		sig, okS := fn.Type().(*types.Signature)
		if !okS || sig.TypeParams().Len() > 0 || sig.RecvTypeParams().Len() > 0 || sig.Params().Len() != 2 || sig.Results().Len() != 0 {
			continue
		}
		if sig.Recv() != nil && !isZeroSizedStructOrArray(sig.Recv().Type()) {
			continue
		}
		p0, p1 := sig.Params().At(0), sig.Params().At(1)
		if !syntaxutil.IsUnsafePointerType(p0.Type()) || !syntaxutil.IsUnsafePointerType(p1.Type()) {
			continue
		}
		okBody := false
		if len(fd.Body.List) == 1 {
			if isCopyAssignStmt(fd.Body.List[0], p0, p1) {
				okBody = true
			} else if ifs, isIf := fd.Body.List[0].(*ast.IfStmt); isIf && ifs.Init == nil && ifs.Else == nil && len(ifs.Body.List) == 1 && isCopyAssignStmt(ifs.Body.List[0], p0, p1) {
				un, isUn := ast.Unparen(ifs.Cond).(*ast.UnaryExpr)
				if isUn && un.Op == token.NOT {
					cc, isCC := ast.Unparen(un.X).(*ast.CallExpr)
					if isCC && len(cc.Args) == 3 && !cc.Ellipsis.IsValid() {
						cfn := syntaxutil.ResolveCalledFuncObj(p, cc.Fun)
						isNilSecondArg := syntaxutil.IsNilIdent(p.TypesInfo, cc.Args[1])
						if !isNilSecondArg {
							if nc, isNC := ast.Unparen(cc.Args[1]).(*ast.CallExpr); isNC && len(nc.Args) == 1 && !nc.Ellipsis.IsValid() {
								ntv := p.TypesInfo.Types[ast.Unparen(nc.Fun)]
								isNilSecondArg = ntv.IsType() && syntaxutil.IsUnsafePointerType(ntv.Type) && syntaxutil.IsNilIdent(p.TypesInfo, nc.Args[0])
							}
						}
						if cfn != nil && cfn.Pkg() != nil && cfn.Pkg().Path() == "sync/atomic" && cfn.Name() == "CompareAndSwapPointer" &&
							isUnsafePtrSlotCast(cc.Args[0], p0) && isNilSecondArg {
							if derefDst, isDD := ast.Unparen(cc.Args[2]).(*ast.StarExpr); isDD && isUnsafePtrSlotCast(derefDst.X, p1) {
								okBody = true
							}
						}
					}
				}
			}
		}
		if okBody {
			if fk, okFK := syntaxutil.CallableFactKey(fn); okFK {
				out = append(out, fk)
			}
		}
	}
	slices.SortFunc(out, syntaxutil.FuncKey.Compare)
	return out
}

func verifyProtoBuilderType(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	named *types.Named,
	st *types.Struct,
	mutatedVars map[string]bool,
) (map[ast.Node]bool, map[*ast.Ident]bool, syntaxutil.TypeRef, []syntaxutil.FuncKey, []syntaxutil.TypeRef, bool) {
	if named.Obj() == nil || !named.Obj().Exported() || named.TypeParams().Len() > 0 {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	hasGoTypes := false
	infoElemStructs := map[*types.Named]bool{}
	builderExportedStructFields := map[*types.Var]*types.Named{}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		switch f.Name() {
		case "GoTypes":
			if !f.Exported() || !syntaxutil.IsAnySliceType(f.Type()) {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			hasGoTypes = true
		case "EnumInfos", "MessageInfos", "ExtensionInfos":
			if !f.Exported() {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			_, elemNamed, okElem := syntaxutil.SliceElemNamedStruct(f.Type())
			if !okElem {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			infoElemStructs[elemNamed] = true
		default:
			if f.Exported() {
				if fnamed, isN := types.Unalias(f.Type()).(*types.Named); isN {
					if _, isSt := fnamed.Underlying().(*types.Struct); isSt {
						builderExportedStructFields[f] = fnamed
					}
				}
			}
		}
	}
	if !hasGoTypes || len(infoElemStructs) == 0 || named.NumMethods() != 1 {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	buildFn := named.Method(0)
	if buildFn.Name() != "Build" {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	sig, ok := buildFn.Type().(*types.Signature)
	if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	outType := types.Unalias(sig.Results().At(0).Type())
	outNamed, _ := outType.(*types.Named)
	outSt, ok := outType.Underlying().(*types.Struct)
	if !ok || !syntaxutil.StructHasExportedIfaceField(outSt, "File") {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	buildFD := idx.FuncDecls[buildFn]
	if buildFD == nil || buildFD.Body == nil || sig.Recv() == nil {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}
	recvVar := sig.Recv()
	var namedResultOutVar *types.Var
	if sig.Results().At(0).Name() != "" {
		namedResultOutVar = sig.Results().At(0)
	}

	var subBuilderRef syntaxutil.TypeRef
	var fbOutVar *types.Var
	fbOutSliceFields := map[*types.Var]bool{}
	subCallBad := false
	ast.Inspect(buildFD.Body, func(n ast.Node) bool {
		if subCallBad || n == nil {
			return false
		}
		call, isCall := n.(*ast.CallExpr)
		if !isCall || len(call.Args) != 0 {
			return true
		}
		sel, isSel := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "Build" {
			return true
		}
		subSel, isSubSel := ast.Unparen(sel.X).(*ast.SelectorExpr)
		if !isSubSel {
			return true
		}
		rid, isID := ast.Unparen(subSel.X).(*ast.Ident)
		if !isID || p.TypesInfo.Uses[rid] != recvVar {
			return true
		}
		subFieldObj, _ := p.TypesInfo.Uses[subSel.Sel].(*types.Var)
		subNamed := builderExportedStructFields[subFieldObj]
		if subNamed == nil || subNamed.Obj() == nil || subNamed.Obj().Pkg() == nil {
			subCallBad = true
			return false
		}
		ref := syntaxutil.TypeRef{Pkg: subNamed.Obj().Pkg().Path(), Name: subNamed.Obj().Name()}
		if !ref.Valid() || fbOutVar != nil {
			subCallBad = true
			return false
		}
		as, isAs := idx.ParentUnparen(call).(*ast.AssignStmt)
		if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			subCallBad = true
			return false
		}
		lid, isLID := ast.Unparen(as.Lhs[0]).(*ast.Ident)
		if !isLID {
			subCallBad = true
			return false
		}
		lv, _ := p.TypesInfo.Defs[lid].(*types.Var)
		if lv == nil || idx.DefCounts[lv] != 1 {
			subCallBad = true
			return false
		}
		fbSt, isSt := types.Unalias(lv.Type()).Underlying().(*types.Struct)
		if !isSt || !syntaxutil.StructHasExportedIfaceField(fbSt, "File") {
			subCallBad = true
			return false
		}
		for i := 0; i < fbSt.NumFields(); i++ {
			ff := fbSt.Field(i)
			if ff.Exported() {
				if _, _, okElem := syntaxutil.SliceElemNamedStruct(ff.Type()); okElem {
					fbOutSliceFields[ff] = true
				}
			}
		}
		if len(fbOutSliceFields) == 0 {
			subCallBad = true
			return false
		}
		for _, uid := range idx.UsesOf[lv] {
			if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
				subCallBad = true
				return false
			}
		}
		subBuilderRef = ref
		fbOutVar = lv
		return true
	})
	if subCallBad {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}

	isSubBuilderSliceElemAddr := func(expr ast.Expr) bool {
		if fbOutVar == nil {
			return false
		}
		un, isUn := ast.Unparen(expr).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return false
		}
		ix, isIx := ast.Unparen(un.X).(*ast.IndexExpr)
		if !isIx {
			return false
		}
		sel, isSel := ast.Unparen(ix.X).(*ast.SelectorExpr)
		if !isSel {
			return false
		}
		id, isID := ast.Unparen(sel.X).(*ast.Ident)
		if !isID || p.TypesInfo.Uses[id] != fbOutVar {
			return false
		}
		fObj, _ := p.TypesInfo.Uses[sel.Sel].(*types.Var)
		return fbOutSliceFields[fObj]
	}

	isSubBuilderFileExpr := func(expr ast.Expr) bool {
		if fbOutVar == nil {
			return false
		}
		sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "File" {
			return false
		}
		id, isID := ast.Unparen(sel.X).(*ast.Ident)
		return isID && p.TypesInfo.Uses[id] == fbOutVar
	}

	directDescStructs := map[*types.Named]bool{}
	isVerifiedDirectDescAlloc := func(expr ast.Expr) bool {
		if fbOutVar != nil {
			return false
		}
		un, isUn := ast.Unparen(expr).(*ast.UnaryExpr)
		if !isUn || un.Op != token.AND {
			return false
		}
		cl, isCL := ast.Unparen(un.X).(*ast.CompositeLit)
		if !isCL {
			return false
		}
		stNamed := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(cl))
		if stNamed == nil || stNamed.Obj() == nil || stNamed.Obj().Pkg() != p.Types || stNamed.Obj().Exported() || stNamed.TypeParams().Len() > 0 {
			return false
		}
		for _, elt := range cl.Elts {
			val := elt
			if kv, isKV := elt.(*ast.KeyValueExpr); isKV {
				val = kv.Value
			}
			vt := p.TypesInfo.TypeOf(val)
			if vt == nil {
				return false
			}
			if !refconfine.TypeContainsRefOrPointer(vt) || syntaxutil.IsByteSliceType(vt) {
				continue
			}
			return false
		}
		directDescStructs[stNamed] = true
		return true
	}

	checkDescValue := func(expr ast.Expr) bool {
		if fbOutVar != nil {
			return isSubBuilderSliceElemAddr(expr)
		}
		vt := p.TypesInfo.TypeOf(expr)
		if vt != nil && !refconfine.TypeContainsRefOrPointer(vt) {
			return true
		}
		return isVerifiedDirectDescAlloc(expr)
	}

	checkOutFileValue := func(expr ast.Expr) bool {
		if fbOutVar != nil {
			return isSubBuilderFileExpr(expr)
		}
		return isVerifiedDirectDescAlloc(expr)
	}

	goTypesDerivedVars := map[*types.Var]bool{}
	isGoTypesExpr := func(expr ast.Expr) bool {
		cur := ast.Unparen(expr)
		for {
			if se, isSE := cur.(*ast.SliceExpr); isSE {
				cur = ast.Unparen(se.X)
				continue
			}
			break
		}
		if sel, isSel := cur.(*ast.SelectorExpr); isSel && sel.Sel.Name == "GoTypes" {
			if id, isID := ast.Unparen(sel.X).(*ast.Ident); isID && p.TypesInfo.Uses[id] == recvVar {
				return true
			}
		}
		if id, isID := cur.(*ast.Ident); isID {
			if v, _ := p.TypesInfo.Uses[id].(*types.Var); v != nil && goTypesDerivedVars[v] {
				return true
			}
		}
		return false
	}
	ast.Inspect(buildFD.Body, func(n ast.Node) bool {
		as, isAs := n.(*ast.AssignStmt)
		if !isAs || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		if lid, isID := ast.Unparen(as.Lhs[0]).(*ast.Ident); isID {
			if lv, _ := p.TypesInfo.Defs[lid].(*types.Var); lv != nil && idx.DefCounts[lv] == 1 && isGoTypesExpr(as.Rhs[0]) {
				reassigned := false
				for _, uid := range idx.UsesOf[lv] {
					if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
						reassigned = true
						break
					}
				}
				if !reassigned {
					goTypesDerivedVars[lv] = true
				}
			}
		}
		return true
	})

	isNilDefaultRecvIfaceAssign := func(sel *ast.SelectorExpr) bool {
		as, isAs := idx.ParentUnparen(sel).(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Rhs[0]) != sel {
			return false
		}
		lhs := ast.Unparen(as.Lhs[0])
		if !types.IsInterface(p.TypesInfo.TypeOf(lhs)) {
			return false
		}
		cur := lhs
		for {
			s, okS := cur.(*ast.SelectorExpr)
			if !okS {
				return false
			}
			if id, isID := ast.Unparen(s.X).(*ast.Ident); isID {
				if p.TypesInfo.Uses[id] != recvVar {
					return false
				}
				break
			}
			cur = ast.Unparen(s.X)
		}
		blk, isBlk := idx.ParentMap[as].(*ast.BlockStmt)
		if !isBlk || len(blk.List) != 1 {
			return false
		}
		ifStmt, isIf := idx.ParentMap[blk].(*ast.IfStmt)
		if !isIf || ifStmt.Body != blk || ifStmt.Else != nil {
			return false
		}
		bin, isBin := ast.Unparen(ifStmt.Cond).(*ast.BinaryExpr)
		if !isBin || bin.Op != token.EQL {
			return false
		}
		return syntaxutil.IsNilIdent(p.TypesInfo, bin.Y) || syntaxutil.IsNilIdent(p.TypesInfo, bin.X)
	}

	isDescoptsGoTypeAssign := func(sel *ast.SelectorExpr) bool {
		as, isAs := idx.ParentUnparen(sel).(*ast.AssignStmt)
		if !isAs || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 || ast.Unparen(as.Lhs[0]) != sel {
			return false
		}
		ta, isTA := ast.Unparen(as.Rhs[0]).(*ast.TypeAssertExpr)
		if !isTA || ta.Type == nil || !types.IsInterface(p.TypesInfo.TypeOf(ta)) {
			return false
		}
		ix, isIx := ast.Unparen(ta.X).(*ast.IndexExpr)
		return isIx && isGoTypesExpr(ix.X)
	}

	sawOutFileInit := false
	outValid := true
	checkOutCompositeLit := func(cl *ast.CompositeLit) bool {
		for _, elt := range cl.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			kid, isID := kv.Key.(*ast.Ident)
			if !isID || kid.Name != "File" || !checkOutFileValue(kv.Value) {
				return false
			}
			sawOutFileInit = true
		}
		return true
	}
	if namedResultOutVar != nil {
		for _, uid := range idx.UsesOf[namedResultOutVar] {
			par := idx.ParentUnparen(uid)
			if sel, isSel := par.(*ast.SelectorExpr); isSel && ast.Unparen(sel.X) == uid {
				if as, isAs := idx.ParentUnparen(sel).(*ast.AssignStmt); isAs {
					onLHS := false
					for li, l := range as.Lhs {
						if ast.Unparen(l) == sel {
							onLHS = true
							if sel.Sel.Name != "File" || li >= len(as.Rhs) || !checkOutFileValue(as.Rhs[li]) {
								outValid = false
							} else {
								sawOutFileInit = true
							}
						}
					}
					if onLHS {
						continue
					}
				}
				continue
			}
			if _, isRet := par.(*ast.ReturnStmt); isRet {
				continue
			}
			outValid = false
		}
	}
	ast.Inspect(buildFD.Body, func(n ast.Node) bool {
		if !outValid || n == nil {
			return false
		}
		ret, isRet := n.(*ast.ReturnStmt)
		if !isRet {
			return true
		}
		if len(ret.Results) == 0 {
			if namedResultOutVar == nil {
				outValid = false
				return false
			}
			return true
		}
		if len(ret.Results) != 1 {
			outValid = false
			return false
		}
		res := ast.Unparen(ret.Results[0])
		if rid, isID := res.(*ast.Ident); isID {
			if namedResultOutVar == nil || p.TypesInfo.Uses[rid] != namedResultOutVar {
				outValid = false
				return false
			}
			return true
		}
		cl, isCL := res.(*ast.CompositeLit)
		if !isCL || len(cl.Elts) == 0 || !checkOutCompositeLit(cl) {
			outValid = false
			return false
		}
		return true
	})
	if !outValid || !sawOutFileInit {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}

	buildCone := map[*types.Func]bool{buildFn: true}
	constructedStructs := map[*types.Named]bool{}
	coneQueue := []*types.Func{buildFn}
	validBuild := true
	enqueueConstructedStruct := func(stNamed *types.Named) {
		if stNamed == nil || stNamed == named || stNamed == outNamed || infoElemStructs[stNamed] || stNamed.Obj() == nil || stNamed.Obj().Pkg() != p.Types || constructedStructs[stNamed] {
			return
		}
		constructedStructs[stNamed] = true
		pset := types.NewMethodSet(types.NewPointer(stNamed))
		for mi := 0; mi < pset.Len(); mi++ {
			mfn, okM := pset.At(mi).Obj().(*types.Func)
			if !okM || mfn == nil {
				validBuild = false
				return
			}
			msig, okSig := mfn.Type().(*types.Signature)
			if !okSig || msig.Recv() == nil {
				validBuild = false
				return
			}
			if types.IsInterface(msig.Recv().Type()) {
				continue
			}
			mfn = mfn.Origin()
			if mfn.Pkg() != p.Types {
				validBuild = false
				return
			}
			if !buildCone[mfn] {
				buildCone[mfn] = true
				coneQueue = append(coneQueue, mfn)
			}
		}
	}
	for k := range directDescStructs {
		enqueueConstructedStruct(k)
	}
	for len(coneQueue) > 0 && validBuild {
		curFn := coneQueue[0]
		coneQueue = coneQueue[1:]
		fd := idx.FuncDecls[curFn]
		if fd == nil || fd.Body == nil {
			validBuild = false
			break
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !validBuild || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.GoStmt, *ast.FuncLit:
				validBuild = false
				return false
			case *ast.CompositeLit:
				enqueueConstructedStruct(syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x)))
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) == 1 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && b.Name() == "new" {
						enqueueConstructedStruct(syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(x)))
					}
				}
				if callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun); callee != nil {
					callee = callee.Origin()
					if csig, okSig := callee.Type().(*types.Signature); okSig && csig.Recv() != nil && types.IsInterface(csig.Recv().Type()) {
					} else if callee.Pkg() == p.Types && !buildCone[callee] {
						buildCone[callee] = true
						coneQueue = append(coneQueue, callee)
					}
				}
			}
			return true
		})
	}
	if !validBuild {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}

	exempt := map[ast.Node]bool{}
	helperCandidates := map[*types.Func]bool{}
	validHelperCallIdents := map[*ast.Ident]bool{}
	for fn := range buildCone {
		fd := idx.FuncDecls[fn]
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if !validBuild || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.Ident:
				if v, ok := p.TypesInfo.Uses[x].(*types.Var); ok && !v.IsField() && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
					if v.Pkg() == p.Types {
						if v.Exported() || mutatedVars[syntaxutil.DynamicVarKey(v)] || !isDeterministicImmutableBuilderGlobal(p, idx, v) {
							validBuild = false
							return false
						}
					} else {
						sel, isSel := idx.ParentUnparen(x).(*ast.SelectorExpr)
						if !isSel || sel.Sel != x || fn != buildFn || (!isNilDefaultRecvIfaceAssign(sel) && !isDescoptsGoTypeAssign(sel)) {
							validBuild = false
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for li, lhs := range x.Lhs {
					if !refconfine.TouchesAnyNamedStruct(p, lhs, infoElemStructs) {
						continue
					}
					if fn != buildFn || li >= len(x.Rhs) || !isSafeBuilderInfoAssignment(p, lhs, x.Rhs[li], infoElemStructs, checkDescValue) {
						validBuild = false
						return false
					}
					exempt[x] = true
					if comp, okComp := ast.Unparen(x.Rhs[li]).(*ast.CompositeLit); okComp {
						exempt[comp] = true
					}
				}
			case *ast.IncDecStmt:
				if refconfine.TouchesAnyNamedStruct(p, x.X, infoElemStructs) {
					validBuild = false
					return false
				}
			case *ast.CallExpr:
				if fn == buildFn && len(x.Args) >= 2 && !x.Ellipsis.IsValid() {
					var calleeID *ast.Ident
					switch fun := ast.Unparen(x.Fun).(type) {
					case *ast.SelectorExpr:
						calleeID = fun.Sel
					case *ast.Ident:
						calleeID = fun
					}
					if calleeID != nil {
						if selFn, isFn := p.TypesInfo.Uses[calleeID].(*types.Func); isFn && selFn != nil {
							selFn = selFn.Origin()
							if selFn.Exported() && selFn.Pkg() != nil {
								if fnSig, okSig := selFn.Type().(*types.Signature); okSig && fnSig.Recv() == nil {
									if un, isUn := ast.Unparen(x.Args[0]).(*ast.UnaryExpr); isUn && un.Op == token.AND && refconfine.TouchesAnyNamedStruct(p, un.X, infoElemStructs) {
										if !checkDescValue(x.Args[1]) {
											validBuild = false
											return false
										}
										for _, extra := range x.Args[2:] {
											et := p.TypesInfo.TypeOf(extra)
											if et == nil || (!syntaxutil.IsReflectType(et) && refconfine.TypeContainsRefOrPointer(et)) {
												validBuild = false
												return false
											}
										}
										helperCandidates[selFn] = true
										validHelperCallIdents[calleeID] = true
										exempt[un] = true
									}
								}
							}
						}
					}
				}
			}
			return true
		})
	}
	if !validBuild {
		return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
	}

	guardSet := map[syntaxutil.TypeRef]bool{}
	if len(constructedStructs) > 0 {
		for cs := range constructedStructs {
			if cs.Obj() == nil || cs.Obj().Pkg() != p.Types || cs.Obj().Exported() || cs.TypeParams().Len() > 0 {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			if !builderHelperStructFieldsSafe(cs, fbOutVar != nil) {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			ref := syntaxutil.TypeRef{Pkg: p.Types.Path(), Name: cs.Obj().Name()}
			if !ref.Valid() {
				return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
			}
			guardSet[ref] = true
		}
		if refconfine.PkgHasAnyMutationOnStructs(p, constructedStructs, nil) {
			return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
		}
		infoElemPkgs := map[*types.Package]bool{}
		for infoSt := range infoElemStructs {
			if infoSt.Obj() != nil && infoSt.Obj().Pkg() != nil {
				infoElemPkgs[infoSt.Obj().Pkg()] = true
			}
		}
		goTypesCarrierFields := map[*types.Var]bool{}
		for cs := range constructedStructs {
			if cst, okS := cs.Underlying().(*types.Struct); okS {
				for i := 0; i < cst.NumFields(); i++ {
					f := cst.Field(i)
					if !f.Exported() && syntaxutil.IsAnySliceType(f.Type()) {
						onlyGoTypes := false
						validUses := true
						for _, uid := range idx.UsesOf[f] {
							if kv, isKV := idx.ParentMap[uid].(*ast.KeyValueExpr); isKV && kv.Key == uid {
								gsel, isGS := ast.Unparen(kv.Value).(*ast.SelectorExpr)
								if !isGS || gsel.Sel.Name != "GoTypes" {
									validUses = false
									break
								}
								if rid, isID := ast.Unparen(gsel.X).(*ast.Ident); !isID || p.TypesInfo.Uses[rid] != recvVar {
									validUses = false
									break
								}
								onlyGoTypes = true
							}
						}
						if validUses && onlyGoTypes {
							goTypesCarrierFields[f] = true
						}
					}
				}
			}
		}
		if !refconfine.VerifyReadOnlyRefConfinement(p, refconfine.Config{
			Index:                         idx,
			AllowReturnFromUnexportedFunc: true,
			SeedExpr: func(expr ast.Expr) (bool, bool) {
				sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
				if !isSel {
					return false, false
				}
				selInfo := p.TypesInfo.Selections[sel]
				if selInfo == nil || selInfo.Kind() != types.FieldVal {
					return false, false
				}
				hit := false
				syntaxutil.ForEachSelectionHopStruct(selInfo, func(hop *types.Named) {
					if constructedStructs[hop] {
						hit = true
					}
				})
				if !hit {
					return false, false
				}
				ft := selInfo.Type()
				if refconfine.IsDirectMutableRef(ft) {
					return true, true
				}
				if refconfine.TypeCarriesMutableRef(ft) {
					return false, true
				}
				return false, false
			},
			AllowCallArg: func(call *ast.CallExpr, argIdx int, arg ast.Expr) bool {
				if argIdx != 0 || len(call.Args) != 1 || call.Ellipsis.IsValid() {
					return false
				}
				if syntaxutil.IsReflectTypeOfCall(p, call) {
					return true
				}
				ix, isIx := ast.Unparen(arg).(*ast.IndexExpr)
				if !isIx {
					return false
				}
				xsel, isXS := ast.Unparen(ix.X).(*ast.SelectorExpr)
				if !isXS {
					return false
				}
				fv, _ := p.TypesInfo.Uses[xsel.Sel].(*types.Var)
				if fv == nil || !goTypesCarrierFields[fv] {
					return false
				}
				callee := syntaxutil.ResolveCalledFuncObj(p, call.Fun)
				if callee == nil || !infoElemPkgs[callee.Pkg()] {
					return false
				}
				csig, okSig := callee.Type().(*types.Signature)
				if !okSig || csig.Recv() == nil || csig.Results().Len() != 1 || !types.IsInterface(csig.Results().At(0).Type()) {
					return false
				}
				recvSt, okSt := types.Unalias(csig.Recv().Type()).Underlying().(*types.Struct)
				return okSt && recvSt.NumFields() == 0
			},
		}) {
			return nil, nil, syntaxutil.TypeRef{}, nil, nil, false
		}
	}

	var guardTypes []syntaxutil.TypeRef
	if len(guardSet) > 0 {
		guardTypes = make([]syntaxutil.TypeRef, 0, len(guardSet))
		for g := range guardSet {
			guardTypes = append(guardTypes, g)
		}
		sort.Slice(guardTypes, func(i, j int) bool { return guardTypes[i].Key() < guardTypes[j].Key() })
	}

	var allowedHelpers []syntaxutil.FuncKey
	for selFn := range helperCandidates {
		allInBuild := true
		for _, id := range idx.UsesOf[selFn] {
			if !validHelperCallIdents[id] {
				allInBuild = false
				break
			}
		}
		if allInBuild {
			for _, id := range idx.UsesOf[selFn] {
				exempt[id] = true
			}
			allowedHelpers = append(allowedHelpers, syntaxutil.FuncKey{Pkg: selFn.Pkg().Path(), Name: selFn.Name()})
		}
	}
	slices.SortFunc(allowedHelpers, syntaxutil.FuncKey.Compare)
	return exempt, validHelperCallIdents, subBuilderRef, allowedHelpers, guardTypes, true
}

func isSafeBuilderInfoAssignment(
	p *packages.Package,
	lhs, rhs ast.Expr,
	infoElemStructs map[*types.Named]bool,
	checkDesc func(ast.Expr) bool,
) bool {
	lhs = ast.Unparen(lhs)
	rhs = ast.Unparen(rhs)
	switch l := lhs.(type) {
	case *ast.SelectorExpr:
		if l.Sel.Name == "GoReflectType" {
			return syntaxutil.IsReflectTypeOfCall(p, rhs)
		}
		if l.Sel.Name == "Desc" {
			return !syntaxutil.ExprIsFuncLit(rhs) && checkDesc(rhs)
		}
		return false
	case *ast.IndexExpr:
		comp, ok := rhs.(*ast.CompositeLit)
		if !ok {
			return false
		}
		st := syntaxutil.DerefNamedStruct(p.TypesInfo.TypeOf(comp))
		if st == nil || !infoElemStructs[st] {
			return false
		}
		for _, elt := range comp.Elts {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				return false
			}
			kID, isID := kv.Key.(*ast.Ident)
			if !isID {
				return false
			}
			switch kID.Name {
			case "GoReflectType":
				if !syntaxutil.IsReflectTypeOfCall(p, kv.Value) {
					return false
				}
			case "Desc":
				if syntaxutil.ExprIsFuncLit(kv.Value) || !checkDesc(kv.Value) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	return false
}

func builderHelperStructFieldsSafe(named *types.Named, allowResolverFields bool) bool {
	seen := map[types.Type]bool{}
	ok := true
	var walk func(t types.Type)
	walk = func(t types.Type) {
		if t == nil || !ok {
			return
		}
		t = types.Unalias(t)
		if seen[t] {
			return
		}
		seen[t] = true
		switch u := t.Underlying().(type) {
		case *types.Basic:
			if u.Kind() == types.UnsafePointer {
				ok = false
			}
		case *types.Signature, *types.Chan, *types.Map, *types.Pointer, *types.TypeParam:
			ok = false
		case *types.Interface:
			if !allowResolverFields {
				ok = false
			}
		case *types.Slice:
			if syntaxutil.IsAnySliceType(t) {
				if !allowResolverFields {
					ok = false
				}
				return
			}
			walk(u.Elem())
		case *types.Array:
			walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				walk(u.Field(i).Type())
			}
		}
	}
	walk(named)
	return ok
}

func isDeterministicImmutableBuilderGlobal(p *packages.Package, idx *refconfine.PkgIndex, v *types.Var) bool {
	if idx.DefCounts[v] != 1 {
		return false
	}
	for _, uid := range idx.UsesOf[v] {
		if refconfine.IdentIsWrittenOrAddrTaken(idx, uid) {
			return false
		}
		par := idx.ParentUnparen(uid)
		if ix, isIx := par.(*ast.IndexExpr); isIx && ast.Unparen(ix.X) == uid {
			if refconfine.IdentOrExprIsWritten(idx, ix) {
				return false
			}
			continue
		}
		if !refconfine.TypeContainsRefOrPointer(v.Type()) {
			continue
		}
		return false
	}
	if !refconfine.TypeContainsRefOrPointer(v.Type()) {
		return true
	}
	mp, isMap := types.Unalias(v.Type()).Underlying().(*types.Map)
	if !isMap || refconfine.TypeContainsRefOrPointer(mp.Key()) || !syntaxutil.IsReflectType(mp.Elem()) {
		return false
	}
	vs := idx.VarSpecs[v]
	if vs == nil {
		return false
	}
	valIdx := -1
	for i, nm := range vs.Names {
		if p.TypesInfo.Defs[nm] == v {
			valIdx = i
			break
		}
	}
	if valIdx < 0 || valIdx >= len(vs.Values) {
		return false
	}
	cl, isCL := ast.Unparen(vs.Values[valIdx]).(*ast.CompositeLit)
	if !isCL {
		return false
	}
	for _, elt := range cl.Elts {
		kv, isKV := elt.(*ast.KeyValueExpr)
		if !isKV || p.TypesInfo.Types[kv.Key].Value == nil || !syntaxutil.IsReflectTypeOfCall(p, kv.Value) {
			return false
		}
		rc := ast.Unparen(kv.Value).(*ast.CallExpr)
		if len(rc.Args) != 1 || !isSafeExtTypeExpr(p, rc.Args[0]) {
			return false
		}
	}
	return true
}
