package capsule

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/internal/freshstruct"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func isNilComparableType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch syntaxutil.UnderlyingType(t).(type) {
	case *types.Interface, *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Signature:
		return true
	}
	return false
}

// deriveOnceExportedWriteGuardFields checks every non-fresh write to an exported
// field of family inside onceCone. If zero such writes exist, it returns
// (nil, nil, nil, true). Otherwise, only direct scalar/interface field
// assignments `recv.<Field> = rhs` (never sub-slice/map element writes, inc/dec,
// range writes, or mutating builtins) are eligible, and every direct exported
// field write or transitive call to an exported-writing helper inside onceFn
// must execute strictly inside the true branch of an `if recv.<GuardField> == nil`
// guard on an exported nil-comparable field of rootNamed that is never written
// prior to that check, returning the sorted guard field names and the exact set
// of verified guarded LHS selector expressions.
func deriveOnceExportedWriteGuardFields(
	p *packages.Package,
	idx *refconfine.PkgIndex,
	freshCache *freshstruct.FreshLocalsCache,
	rootNamed *types.Named,
	family map[*types.Named]bool,
	onceFn *types.Func,
	onceCone map[*types.Func]bool,
	builderExempt map[ast.Node]bool,
) ([]string, map[ast.Expr]bool, ast.Node, bool) {
	isNonFreshExportedFamilyWrite := func(fd *ast.FuncDecl, expr ast.Expr) bool {
		if expr == nil {
			return false
		}
		freshVars, freshEsc := freshCache.Get(fd)
		if freshstruct.IsRootedAtFreshLocal(p, expr, freshVars, freshEsc) {
			return false
		}
		hitSt, fld := lhsRootFamilyField(p, expr, family)
		return hitSt != nil && fld != nil && fld.Exported()
	}
	isDirectExportedFamilyFieldSel := func(expr ast.Expr) bool {
		sel, isSel := ast.Unparen(expr).(*ast.SelectorExpr)
		if !isSel {
			return false
		}
		selInfo := p.TypesInfo.Selections[sel]
		if selInfo == nil || selInfo.Kind() != types.FieldVal {
			return false
		}
		fld, _ := selInfo.Obj().(*types.Var)
		if fld == nil || !fld.Exported() {
			return false
		}
		matched := false
		syntaxutil.ForEachSelectionHopStruct(selInfo, func(st *types.Named) {
			if family[st] {
				matched = true
			}
		})
		return matched
	}

	directExpWriters := map[*types.Func]bool{}
	guardedLHS := map[ast.Expr]bool{}
	var firstExpWriteNode ast.Node
	var badSubWriteNode ast.Node
	intraConeCalls := map[*types.Func][]*types.Func{}
	for fn := range onceCone {
		fd := idx.FuncDecls[fn]
		if fd == nil || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if badSubWriteNode != nil || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.AssignStmt:
				if builderExempt[x] {
					return true
				}
				for _, lhs := range x.Lhs {
					if isNonFreshExportedFamilyWrite(fd, lhs) {
						if x.Tok != token.ASSIGN || !isDirectExportedFamilyFieldSel(lhs) {
							badSubWriteNode = x
							return false
						}
						guardedLHS[ast.Unparen(lhs)] = true
						directExpWriters[fn] = true
						if firstExpWriteNode == nil {
							firstExpWriteNode = x
						}
					}
				}
			case *ast.IncDecStmt:
				if isNonFreshExportedFamilyWrite(fd, x.X) {
					badSubWriteNode = x
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN {
					if isNonFreshExportedFamilyWrite(fd, x.Key) || isNonFreshExportedFamilyWrite(fd, x.Value) {
						badSubWriteNode = x
						return false
					}
				}
			case *ast.CallExpr:
				if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
					if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
						switch b.Name() {
						case "delete", "clear", "copy", "append":
							if isNonFreshExportedFamilyWrite(fd, x.Args[0]) {
								badSubWriteNode = x
								return false
							}
						}
					}
				}
				if callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun); callee != nil {
					callee = callee.Origin()
					if onceCone[callee] {
						intraConeCalls[fn] = append(intraConeCalls[fn], callee)
					}
				}
			}
			return true
		})
		if badSubWriteNode != nil {
			return nil, nil, badSubWriteNode, false
		}
	}
	if len(directExpWriters) == 0 {
		return nil, nil, nil, true
	}

	transExpWriters := make(map[*types.Func]bool, len(directExpWriters))
	for fn := range directExpWriters {
		transExpWriters[fn] = true
	}
	for changed := true; changed; {
		changed = false
		for fn, callees := range intraConeCalls {
			if transExpWriters[fn] {
				continue
			}
			for _, c := range callees {
				if transExpWriters[c] {
					transExpWriters[fn] = true
					changed = true
					break
				}
			}
		}
	}

	onceFD := idx.FuncDecls[onceFn]
	if onceFD == nil || onceFD.Body == nil || onceFD.Recv == nil || len(onceFD.Recv.List) != 1 || len(onceFD.Recv.List[0].Names) != 1 || freshstruct.FuncBodyHasGoto(onceFD.Body) {
		return nil, nil, firstExpWriteNode, false
	}
	onceRecv, _ := p.TypesInfo.Defs[onceFD.Recv.List[0].Names[0]].(*types.Var)
	if onceRecv == nil || !syntaxutil.IsPtrToNamed(onceRecv.Type(), rootNamed) {
		return nil, nil, firstExpWriteNode, false
	}

	reassignedRecv := false
	var expSites []ast.Node
	ast.Inspect(onceFD.Body, func(n ast.Node) bool {
		if reassignedRecv || n == nil {
			return false
		}
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if lid, isID := ast.Unparen(lhs).(*ast.Ident); isID {
					if (x.Tok == token.ASSIGN && p.TypesInfo.Uses[lid] == onceRecv) ||
						(x.Tok == token.DEFINE && p.TypesInfo.Defs[lid] == onceRecv) {
						reassignedRecv = true
						return false
					}
				}
				if !builderExempt[x] && isNonFreshExportedFamilyWrite(onceFD, lhs) {
					expSites = append(expSites, x)
				}
			}
		case *ast.IncDecStmt:
			if syntaxutil.IsIdentUsingObj(p.TypesInfo, x.X, onceRecv) {
				reassignedRecv = true
				return false
			}
			if isNonFreshExportedFamilyWrite(onceFD, x.X) {
				expSites = append(expSites, x)
			}
		case *ast.RangeStmt:
			if x.Tok == token.ASSIGN {
				if (x.Key != nil && syntaxutil.IsIdentUsingObj(p.TypesInfo, x.Key, onceRecv)) ||
					(x.Value != nil && syntaxutil.IsIdentUsingObj(p.TypesInfo, x.Value, onceRecv)) {
					reassignedRecv = true
					return false
				}
				if isNonFreshExportedFamilyWrite(onceFD, x.Key) || isNonFreshExportedFamilyWrite(onceFD, x.Value) {
					expSites = append(expSites, x)
				}
			}
		case *ast.CallExpr:
			if cid, isID := ast.Unparen(x.Fun).(*ast.Ident); isID && len(x.Args) > 0 {
				if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB {
					switch b.Name() {
					case "delete", "clear", "copy", "append":
						if isNonFreshExportedFamilyWrite(onceFD, x.Args[0]) {
							expSites = append(expSites, x)
						}
					}
				}
			}
			if callee := syntaxutil.ResolveCalledFuncObj(p, x.Fun); callee != nil {
				callee = callee.Origin()
				if callee != onceFn && transExpWriters[callee] {
					sel, isSel := ast.Unparen(x.Fun).(*ast.SelectorExpr)
					if !isSel || !syntaxutil.IsIdentUsingObj(p.TypesInfo, sel.X, onceRecv) {
						reassignedRecv = true
						return false
					}
					expSites = append(expSites, x)
				}
			}
		}
		return true
	})
	if reassignedRecv || len(expSites) == 0 {
		return nil, nil, firstExpWriteNode, false
	}

	matchNilGuardField := func(cond ast.Expr) *types.Var {
		bin, isBin := ast.Unparen(cond).(*ast.BinaryExpr)
		if !isBin || bin.Op != token.EQL {
			return nil
		}
		var fieldExpr ast.Expr
		if syntaxutil.IsNilIdent(p.TypesInfo, bin.Y) {
			fieldExpr = bin.X
		} else if syntaxutil.IsNilIdent(p.TypesInfo, bin.X) {
			fieldExpr = bin.Y
		} else {
			return nil
		}
		sel, isSel := ast.Unparen(fieldExpr).(*ast.SelectorExpr)
		if !isSel || !syntaxutil.IsIdentUsingObj(p.TypesInfo, sel.X, onceRecv) {
			return nil
		}
		selInfo := p.TypesInfo.Selections[sel]
		if selInfo == nil || selInfo.Kind() != types.FieldVal || syntaxutil.SelectionCrossesEmbeddedPointer(selInfo) {
			return nil
		}
		if syntaxutil.DerefNamedStruct(selInfo.Recv()) != rootNamed {
			return nil
		}
		fld, _ := selInfo.Obj().(*types.Var)
		if fld == nil || !fld.Exported() || !isNilComparableType(fld.Type()) {
			return nil
		}
		return fld
	}

	guardMinIfPos := map[*types.Var]token.Pos{}
	for _, site := range expSites {
		if idx.InFuncLit[site] || idx.InGoStmt[site] {
			return nil, nil, site, false
		}
		var matchedGuard *types.Var
		var matchedIfPos token.Pos
		for cur := idx.ParentMap[site]; cur != nil && cur != onceFD.Body; cur = idx.ParentMap[cur] {
			ifs, isIf := cur.(*ast.IfStmt)
			if !isIf || ifs.Init != nil || ifs.Body == nil {
				continue
			}
			if site.Pos() < ifs.Body.Pos() || site.Pos() >= ifs.Body.End() {
				continue
			}
			if gf := matchNilGuardField(ifs.Cond); gf != nil {
				matchedGuard = gf
				matchedIfPos = ifs.Pos()
				break
			}
		}
		if matchedGuard == nil {
			return nil, nil, site, false
		}
		if prev, ok := guardMinIfPos[matchedGuard]; !ok || matchedIfPos < prev {
			guardMinIfPos[matchedGuard] = matchedIfPos
		}
	}

	for _, minIfPos := range guardMinIfPos {
		for _, site := range expSites {
			if site.Pos() < minIfPos {
				return nil, nil, site, false
			}
		}
	}

	out := make([]string, 0, len(guardMinIfPos))
	for gf := range guardMinIfPos {
		out = append(out, gf.Name())
	}
	sort.Strings(out)
	return out, guardedLHS, nil, true
}
