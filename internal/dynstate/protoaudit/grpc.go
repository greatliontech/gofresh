package protoaudit

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

func deriveGrpcServiceVars(audited bool, p *packages.Package, idx *refconfine.PkgIndex) []GrpcServiceVarFact {
	var out []GrpcServiceVarFact
	for _, name := range p.Types.Scope().Names() {
		v, ok := p.Types.Scope().Lookup(name).(*types.Var)
		if !ok || !refconfine.TypeMayCarryUnknownDynamic(audited, v.Type()) || idx.DefCounts[v] != 1 {
			continue
		}
		svcRef, svcNamed, okRef := syntaxutil.TypeRefOfNamedStruct(v.Type())
		if !okRef {
			continue
		}
		if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); isPtr {
			continue
		}
		methodRef, streamRef, okShape := verifyGrpcServiceStructShape(svcNamed)
		if !okShape {
			continue
		}
		vs := idx.VarSpecs[v]
		if vs == nil || len(vs.Names) != 1 || len(vs.Values) != 1 {
			continue
		}
		comp, ok := ast.Unparen(vs.Values[0]).(*ast.CompositeLit)
		if !ok || !types.Identical(types.Unalias(p.TypesInfo.TypeOf(comp)), svcNamed) {
			continue
		}
		if !verifyGrpcServiceCompositeLit(p, comp) {
			continue
		}
		if !verifyGrpcServiceVarUses(p, idx, v) {
			continue
		}
		out = append(out, GrpcServiceVarFact{
			Key:        syntaxutil.DynamicVarKey(v),
			SvcDesc:    svcRef,
			MethodDesc: methodRef,
			StreamDesc: streamRef,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func verifyGrpcServiceStructShape(svcNamed *types.Named) (methodRef, streamRef syntaxutil.TypeRef, ok bool) {
	st, isSt := svcNamed.Underlying().(*types.Struct)
	if !isSt {
		return syntaxutil.TypeRef{}, syntaxutil.TypeRef{}, false
	}
	hasServiceName := false
	hasHandlerType := false
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if !f.Exported() {
			return syntaxutil.TypeRef{}, syntaxutil.TypeRef{}, false
		}
		switch f.Name() {
		case "ServiceName":
			b, isB := types.Unalias(f.Type()).Underlying().(*types.Basic)
			if !isB || b.Kind() != types.String {
				return syntaxutil.TypeRef{}, syntaxutil.TypeRef{}, false
			}
			hasServiceName = true
		case "HandlerType":
			if !types.IsInterface(f.Type()) {
				return syntaxutil.TypeRef{}, syntaxutil.TypeRef{}, false
			}
			hasHandlerType = true
		case "Methods":
			mRef, okM := syntaxutil.SliceElemStructRef(f.Type())
			if !okM {
				return syntaxutil.TypeRef{}, syntaxutil.TypeRef{}, false
			}
			methodRef = mRef
		case "Streams":
			sRef, okS := syntaxutil.SliceElemStructRef(f.Type())
			if !okS {
				return syntaxutil.TypeRef{}, syntaxutil.TypeRef{}, false
			}
			streamRef = sRef
		case "Metadata":
		default:
			return syntaxutil.TypeRef{}, syntaxutil.TypeRef{}, false
		}
	}
	if !hasServiceName || !hasHandlerType || (methodRef.IsZero() && streamRef.IsZero()) {
		return syntaxutil.TypeRef{}, syntaxutil.TypeRef{}, false
	}
	return methodRef, streamRef, true
}

func verifyGrpcServiceCompositeLit(p *packages.Package, comp *ast.CompositeLit) bool {
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		kID, ok := kv.Key.(*ast.Ident)
		if !ok {
			return false
		}
		val := ast.Unparen(kv.Value)
		switch kID.Name {
		case "ServiceName":
			if tv := p.TypesInfo.Types[val]; tv.Value == nil || tv.Value.Kind() != constant.String {
				return false
			}
		case "Metadata":
			if !syntaxutil.IsNilIdent(p.TypesInfo, val) {
				if tv := p.TypesInfo.Types[val]; tv.Value == nil {
					return false
				}
			}
		case "HandlerType":
			call, isCall := val.(*ast.CallExpr)
			if !isCall || len(call.Args) != 1 || !p.TypesInfo.Types[call.Fun].IsType() || !syntaxutil.IsNilIdent(p.TypesInfo, call.Args[0]) {
				return false
			}
			ptr, isPtr := types.Unalias(p.TypesInfo.Types[call.Fun].Type).(*types.Pointer)
			if !isPtr || !types.IsInterface(ptr.Elem()) {
				return false
			}
		case "Methods", "Streams":
			slComp, isComp := val.(*ast.CompositeLit)
			if !isComp {
				return false
			}
			for _, item := range slComp.Elts {
				itemComp, isIC := ast.Unparen(item).(*ast.CompositeLit)
				if !isIC || !verifyGrpcEntryCompositeLit(p, itemComp) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func verifyGrpcEntryCompositeLit(p *packages.Package, comp *ast.CompositeLit) bool {
	for _, elt := range comp.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		kID, ok := kv.Key.(*ast.Ident)
		if !ok {
			return false
		}
		val := ast.Unparen(kv.Value)
		switch kID.Name {
		case "MethodName", "StreamName", "ServerStreams", "ClientStreams":
			if tv := p.TypesInfo.Types[val]; tv.Value == nil {
				return false
			}
		case "Handler":
			id, isID := val.(*ast.Ident)
			if !isID {
				return false
			}
			fn, isFn := p.TypesInfo.Uses[id].(*types.Func)
			if !isFn || fn.Pkg() != p.Types {
				return false
			}
			if sig, okSig := fn.Type().(*types.Signature); !okSig || sig.Recv() != nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func verifyGrpcServiceVarUses(p *packages.Package, idx *refconfine.PkgIndex, v *types.Var) bool {
	for _, id := range idx.UsesOf[v] {
		par := idx.ParentUnparen(id)
		if as, isAs := par.(*ast.AssignStmt); isAs {
			for _, lhs := range as.Lhs {
				if ast.Unparen(lhs) == id {
					return false
				}
			}
		}
		if inc, isInc := par.(*ast.IncDecStmt); isInc && ast.Unparen(inc.X) == id {
			return false
		}
		if rng, isRng := par.(*ast.RangeStmt); isRng && rng.Tok == token.ASSIGN &&
			((rng.Key != nil && ast.Unparen(rng.Key) == id) || (rng.Value != nil && ast.Unparen(rng.Value) == id)) {
			return false
		}
		cur := ast.Node(id)
		for {
			next := idx.ParentUnparen(cur)
			switch nx := next.(type) {
			case *ast.SelectorExpr:
				if ast.Unparen(nx.X) == cur {
					cur = nx
					continue
				}
			case *ast.IndexExpr:
				if ast.Unparen(nx.X) == cur {
					cur = nx
					continue
				}
			case *ast.SliceExpr:
				if ast.Unparen(nx.X) == cur {
					return false
				}
			case *ast.UnaryExpr:
				if nx.Op == token.AND && cur != id && ast.Unparen(nx.X) == cur {
					curExpr, isExpr := cur.(ast.Expr)
					if !isExpr {
						return false
					}
					curType := types.Unalias(p.TypesInfo.TypeOf(curExpr))
					if _, isPtr := curType.(*types.Pointer); isPtr || syntaxutil.DerefNamedStruct(curType) == nil {
						return false
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range nx.Lhs {
					if ast.Unparen(lhs) == cur && cur != id {
						return false
					}
				}
			case *ast.IncDecStmt:
				if ast.Unparen(nx.X) == cur {
					return false
				}
			case *ast.RangeStmt:
				if nx.Tok == token.ASSIGN &&
					((nx.Key != nil && ast.Unparen(nx.Key) == cur) || (nx.Value != nil && ast.Unparen(nx.Value) == cur)) {
					return false
				}
			case *ast.CallExpr:
				isArg := false
				for _, arg := range nx.Args {
					if ast.Unparen(arg) == cur {
						isArg = true
						break
					}
				}
				if isArg {
					if cid, isID := ast.Unparen(nx.Fun).(*ast.Ident); isID {
						if b, isB := p.TypesInfo.Uses[cid].(*types.Builtin); isB && (b.Name() == "len" || b.Name() == "cap") {
							break
						}
					}
					curExpr, isExpr := cur.(ast.Expr)
					if !isExpr {
						return false
					}
					if b, isBasic := syntaxutil.UnderlyingType(p.TypesInfo.TypeOf(curExpr)).(*types.Basic); !isBasic || b.Kind() == types.UnsafePointer {
						return false
					}
				}
			}
			break
		}
	}
	return true
}
