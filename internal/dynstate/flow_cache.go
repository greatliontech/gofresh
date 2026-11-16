package dynstate

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/flowir"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/dynstate/syntaxutil"
)

// pkgFlowCache caches lowered flowir.Body representations, lowered expression
// nodes, and scoped local memory-alias graphs across all dynamic-state passes
// on a single package so each declaration in p.Syntax is lowered at most once.
type pkgFlowCache struct {
	audited bool
	info    *types.Info
	pkg     *types.Package

	bodies              map[ast.Node]*flowir.Body
	values              map[ast.Expr]*flowir.Value
	localCarrierAliases map[*flowir.Body]map[types.Object]map[types.Object]bool
	interiorAliases     map[*flowir.Body]map[types.Object]map[types.Object]bool
	interiorStrAliases  map[*flowir.Body]map[types.Object]map[types.Object]bool

	stdPkgPaths              map[string]bool
	pkgHasStringHeaderUnsafe bool
	pkgWritesForeignStrGlob  bool
	exposedStringGlobals     map[*types.Var]bool
	pkgDirectStringUnsafe    map[*types.Func]bool
	stringHazardFuncs        map[*types.Func]bool

	declLowerCount int
	missCount      int
}

func newPkgFlowCache(audited bool, p *packages.Package) *pkgFlowCache {
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	fc := &pkgFlowCache{
		audited:                audited,
		info:                   p.TypesInfo,
		pkg:                    p.Types,
		bodies:              make(map[ast.Node]*flowir.Body, len(p.Syntax)*8),
		values:              make(map[ast.Expr]*flowir.Value, len(p.Syntax)*32),
		localCarrierAliases: make(map[*flowir.Body]map[types.Object]map[types.Object]bool),
		interiorAliases:     make(map[*flowir.Body]map[types.Object]map[types.Object]bool),
		interiorStrAliases:  make(map[*flowir.Body]map[types.Object]map[types.Object]bool),
		stdPkgPaths:            collectImportedStdPkgPaths(audited, p),
		exposedStringGlobals:   make(map[*types.Var]bool),
		pkgDirectStringUnsafe:  make(map[*types.Func]bool),
		stringHazardFuncs:      make(map[*types.Func]bool),
	}
	for _, file := range p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				b := flowir.LowerFunc(p.TypesInfo, p.Types, d)
				fc.declLowerCount++
				if b != nil {
					fc.bodies[d] = b
					fc.bodies[d.Body] = b
					fc.indexNestedBodies(b)
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR && d.Tok != token.CONST {
					continue
				}
				b := flowir.LowerNode(p.TypesInfo, p.Types, d)
				fc.declLowerCount++
				if b != nil {
					fc.bodies[d] = b
					fc.indexGenDeclSpecs(d, b)
					fc.indexNestedBodies(b)
				}
			}
		}
	}
	fc.precomputeStringHeaderHazards(p)
	return fc
}

func (fc *pkgFlowCache) indexGenDeclSpecs(gd *ast.GenDecl, b *flowir.Body) {
	if gd == nil || b == nil {
		return
	}
	specOps := map[*ast.ValueSpec][]flowir.Op{}
	for _, op := range b.Ops {
		if vs, ok := op.StmtAST.(*ast.ValueSpec); ok && vs != nil {
			specOps[vs] = append(specOps[vs], op)
		}
	}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || vs == nil {
			continue
		}
		ops := specOps[vs]
		vsBody := &flowir.Body{
			AST:        vs,
			ScopeStart: vs.Pos(),
			ScopeEnd:   vs.End(),
			BodyStart:  vs.Pos(),
			BodyEnd:    vs.End(),
			Ops:        ops,
		}
		fc.bodies[vs] = vsBody
		if gd.Tok == token.VAR && len(ops) == 1 && ops[0].Kind == flowir.OpAssign && len(ops[0].Srcs) == len(vs.Values) {
			for i, valExpr := range vs.Values {
				if valExpr == nil || ops[0].Srcs[i] == nil {
					continue
				}
				fc.bodies[valExpr] = &flowir.Body{
					AST:        valExpr,
					ScopeStart: valExpr.Pos(),
					ScopeEnd:   valExpr.End(),
					BodyStart:  valExpr.Pos(),
					BodyEnd:    valExpr.End(),
					Ops: []flowir.Op{{
						Kind:    flowir.OpExpr,
						StmtAST: valExpr,
						Expr:    ops[0].Srcs[i],
					}},
				}
			}
		} else if gd.Tok == token.CONST && len(ops) == len(vs.Values) {
			for i, valExpr := range vs.Values {
				if valExpr == nil || ops[i].Kind != flowir.OpExpr || ops[i].Expr == nil {
					continue
				}
				fc.bodies[valExpr] = &flowir.Body{
					AST:        valExpr,
					ScopeStart: valExpr.Pos(),
					ScopeEnd:   valExpr.End(),
					BodyStart:  valExpr.Pos(),
					BodyEnd:    valExpr.End(),
					Ops:        []flowir.Op{ops[i]},
				}
			}
		}
	}
}

func (fc *pkgFlowCache) indexNestedBodies(b *flowir.Body) {
	if fc == nil || b == nil {
		return
	}
	indexVal := func(v *flowir.Value) {
		if v == nil {
			return
		}
		v.WalkValues(func(cur *flowir.Value) bool {
			for raw := cur.Raw; raw != nil; {
				if _, exists := fc.values[raw]; !exists || raw == cur.Raw {
					fc.values[raw] = cur
				}
				pe, ok := raw.(*ast.ParenExpr)
				if !ok {
					break
				}
				raw = pe.X
			}
			switch cur.Kind {
			case flowir.ValMakeClosure:
				if cur.Closure != nil {
					if cur.Lit != nil {
						fc.bodies[cur.Lit] = cur.Closure
						if cur.Lit.Body != nil {
							fc.bodies[cur.Lit.Body] = cur.Closure
						}
					}
					fc.indexNestedBodies(cur.Closure)
				}
			case flowir.ValCall:
				if cur.CallKind == flowir.CallIIFE && cur.IIFE != nil {
					if cur.CallAST != nil {
						if lit, ok := syntaxutil.UnparenExpr(cur.CallAST.Fun).(*ast.FuncLit); ok && lit != nil {
							fc.bodies[lit] = cur.IIFE
							if lit.Body != nil {
								fc.bodies[lit.Body] = cur.IIFE
							}
						}
					}
					fc.indexNestedBodies(cur.IIFE)
				}
			}
			return true
		})
	}
	for i := range b.Ops {
		op := &b.Ops[i]
		switch op.Kind {
		case flowir.OpAssign:
			for _, dst := range op.Dsts {
				dst.ForEachChildValue(func(cv *flowir.Value) bool { indexVal(cv); return true })
			}
			for _, src := range op.Srcs {
				indexVal(src)
			}
			if op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
				if op.RangeBody.Block != nil {
					fc.bodies[op.RangeBody.Block] = op.RangeBody
				}
				fc.indexNestedBodies(op.RangeBody)
			}
		case flowir.OpTypeSwitchBind:
			indexVal(op.SwitchSrc)
		case flowir.OpChanSend:
			op.ChanPlace.ForEachChildValue(func(cv *flowir.Value) bool { indexVal(cv); return true })
			indexVal(op.ChanVal)
			indexVal(op.SendVal)
		case flowir.OpReturn:
			for _, r := range op.Results {
				indexVal(r)
			}
		case flowir.OpDefer:
			indexVal(op.Call)
		case flowir.OpGo:
			if op.StmtAST != nil {
				fc.bodies[op.StmtAST] = &flowir.Body{
					AST:        op.StmtAST,
					ScopeStart: op.StmtAST.Pos(),
					ScopeEnd:   op.StmtAST.End(),
					BodyStart:  op.StmtAST.Pos(),
					BodyEnd:    op.StmtAST.End(),
					Ops: []flowir.Op{{
						Kind:    flowir.OpGo,
						StmtAST: op.StmtAST,
						Call:    op.Call,
					}},
				}
			}
			indexVal(op.Call)
		case flowir.OpExpr:
			indexVal(op.Expr)
		}
	}
}

func (fc *pkgFlowCache) scopeBody(p *packages.Package, enclosing ast.Node) *flowir.Body {
	switch n := enclosing.(type) {
	case nil:
		return nil
	case *ast.FuncDecl:
		return fc.funcBody(p, n)
	case *ast.FuncLit:
		return fc.litBody(p, n)
	default:
		return fc.body(p, n)
	}
}

func (fc *pkgFlowCache) body(p *packages.Package, node ast.Node) *flowir.Body {
	if node == nil {
		return nil
	}
	if fc != nil {
		if b, ok := fc.bodies[node]; ok {
			return b
		}
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	b := flowir.LowerNode(p.TypesInfo, p.Types, node)
	if fc != nil && b != nil {
		fc.missCount++
		fc.bodies[node] = b
		fc.indexNestedBodies(b)
	}
	return b
}

func (fc *pkgFlowCache) funcBody(p *packages.Package, fd *ast.FuncDecl) *flowir.Body {
	if fd == nil || fd.Body == nil {
		return nil
	}
	if fc != nil {
		if b, ok := fc.bodies[fd]; ok {
			return b
		}
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	b := flowir.LowerFunc(p.TypesInfo, p.Types, fd)
	if fc != nil && b != nil {
		fc.missCount++
		fc.bodies[fd] = b
		fc.bodies[fd.Body] = b
		fc.indexNestedBodies(b)
	}
	return b
}

func (fc *pkgFlowCache) litBody(p *packages.Package, lit *ast.FuncLit) *flowir.Body {
	if lit == nil || lit.Body == nil {
		return nil
	}
	if fc != nil {
		if b, ok := fc.bodies[lit]; ok {
			return b
		}
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	b := flowir.LowerFuncLit(p.TypesInfo, p.Types, lit)
	if fc != nil && b != nil {
		fc.missCount++
		fc.bodies[lit] = b
		fc.bodies[lit.Body] = b
		fc.indexNestedBodies(b)
	}
	return b
}

// exprValue returns the lowered *flowir.Value for expr, hitting the pre-indexed
// value map for all expressions inside package function and var/const
// declarations and falling back to expression lowering only for standalone
// expressions (such as inside type declarations or nil caches).
func (fc *pkgFlowCache) exprValue(p *packages.Package, expr ast.Expr) *flowir.Value {
	if expr == nil {
		return nil
	}
	if fc != nil {
		if v, ok := fc.values[expr]; ok {
			return v
		}
		if b, ok := fc.bodies[expr]; ok && len(b.Ops) == 1 && b.Ops[0].Kind == flowir.OpExpr {
			return b.Ops[0].Expr
		}
	}
	if p == nil || p.TypesInfo == nil {
		return nil
	}
	b := flowir.LowerNode(p.TypesInfo, p.Types, expr)
	if b == nil || len(b.Ops) != 1 || b.Ops[0].Kind != flowir.OpExpr {
		return nil
	}
	v := b.Ops[0].Expr
	if fc != nil && v != nil {
		fc.values[expr] = v
		fc.indexNestedBodies(b)
	}
	return v
}

func collectImportedStdPkgPaths(audited bool, p *packages.Package) map[string]bool {
	if !audited || p == nil || len(p.Imports) == 0 {
		return nil
	}
	out := make(map[string]bool)
	visited := make(map[*packages.Package]bool)
	var walk func(m map[string]*packages.Package)
	walk = func(m map[string]*packages.Package) {
		for _, imp := range m {
			if imp == nil || visited[imp] {
				continue
			}
			visited[imp] = true
			if imp.Module == nil && imp.PkgPath != "" && imp.PkgPath != "unsafe" && imp.PkgPath != "C" &&
				syntaxutil.IsStandardLibraryPkgPath(imp.PkgPath) {
				out[imp.PkgPath] = true
			}
			if len(imp.Imports) > 0 {
				walk(imp.Imports)
			}
		}
	}
	walk(p.Imports)
	return out
}

// isConfinedReadOnlyStringDataCall reports whether callVal (`unsafe.StringData(s)`)
// is bound once to a local *byte variable within topBody whose only uses are
// pointer-equality comparisons (`fp == sp`, `fp != nil`) or 1-hop byte reads
// (`*fp`), with zero dereference writes, address-takings, conversions, slices,
// or call/return/global escapes.
func isConfinedReadOnlyStringDataCall(topBody *flowir.Body, callVal *flowir.Value) bool {
	if topBody == nil || callVal == nil || callVal.Kind != flowir.ValCall ||
		callVal.CallKind != flowir.CallBuiltin || callVal.BuiltinName != "StringData" {
		return false
	}
	var target *types.Var
	var defOp *flowir.Op
	forEachBodyOpAndTopVal(topBody, func(op *flowir.Op) {
		if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignPlain &&
			len(op.Dsts) == 1 && len(op.Srcs) == 1 && op.Srcs[0] == callVal {
			dst := op.Dsts[0]
			if dst.IsBareVar() && dst.Root == flowir.RootLocal && dst.Obj != nil &&
				syntaxutil.IsLocalVar(dst.Obj) && !typeMayHoldErasedString(dst.Type) {
				if defOp == nil {
					target = dst.Obj
					defOp = op
				} else {
					target = nil
				}
			}
		}
	}, nil)
	if target == nil || defOp == nil {
		return false
	}
	allowedPlaces := map[*flowir.Value]bool{}
	forEachBodyOpAndTopVal(topBody, nil, func(v *flowir.Value) {
		if v == nil {
			return
		}
		if v.Kind == flowir.ValCompare {
			for _, side := range []*flowir.Value{v.Left, v.Right} {
				if side != nil && side.Kind == flowir.ValPlace && side.Place.IsBareVar() && side.Place.Obj == target {
					allowedPlaces[side] = true
				}
			}
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin &&
			(v.BuiltinName == "Sizeof" || v.BuiltinName == "Alignof") {
			for _, a := range v.Args {
				if a != nil && a.Kind == flowir.ValPlace && a.Place.IsBareVar() && a.Place.Obj == target {
					allowedPlaces[a] = true
				}
			}
		}
		if v.Kind == flowir.ValPlace && v.Place.Obj == target &&
			len(v.Place.Projs) == 1 && v.Place.Projs[0].Kind == flowir.ProjDeref {
			allowedPlaces[v] = true
		}
	})
	ok := true
	forEachBodyOpAndTopVal(topBody, func(op *flowir.Op) {
		if !ok {
			return
		}
		switch op.Kind {
		case flowir.OpAssign:
			for _, dst := range op.Dsts {
				if dst.Obj == target && op != defOp {
					ok = false
					return
				}
			}
		case flowir.OpTypeSwitchBind:
			if op.SwitchDst == target {
				ok = false
			}
		case flowir.OpChanSend:
			if op.ChanPlace.Obj == target {
				ok = false
			}
		}
	}, func(v *flowir.Value) {
		if !ok || v == nil {
			return
		}
		switch v.Kind {
		case flowir.ValPlace:
			if v.Place.Obj == target && !allowedPlaces[v] {
				ok = false
			}
		case flowir.ValAddrOf:
			if v.AddrPlace.Obj == target {
				ok = false
			}
		case flowir.ValMethodVal:
			if v.HasRecvPlace && v.RecvPlace.Obj == target {
				ok = false
			}
		case flowir.ValCall:
			if v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj == target {
				ok = false
			}
		}
	})
	return ok
}

func valueNodeIsDirectStringHeaderUnsafe(topBody *flowir.Body, cur *flowir.Value) bool {
	if cur == nil {
		return false
	}
	switch cur.Kind {
	case flowir.ValCall:
		if cur.CallKind == flowir.CallBuiltin {
			if cur.BuiltinName == "StringData" {
				return !isConfinedReadOnlyStringDataCall(topBody, cur)
			}
			return false
		}
		if syntaxutil.ContainsUnsafePointer(cur.Type) {
			return true
		}
	case flowir.ValConvert:
		if syntaxutil.IsUnsafePointerType(cur.Type) &&
			(cur.Arg == nil || syntaxutil.ContainsUintptr(cur.Arg.Type) || syntaxutil.PointerMayReachString(cur.Arg.Type)) {
			return true
		}
	}
	return false
}

func valueHasDirectStringHeaderUnsafe(topBody *flowir.Body, v *flowir.Value) bool {
	if v == nil {
		return false
	}
	hit := false
	v.WalkValues(func(cur *flowir.Value) bool {
		if hit {
			return false
		}
		if valueNodeIsDirectStringHeaderUnsafe(topBody, cur) {
			hit = true
			return false
		}
		return true
	})
	return hit
}

func forEachBodyOpAndTopVal(b *flowir.Body, onOp func(*flowir.Op), onTopVal func(*flowir.Value)) {
	if b == nil {
		return
	}
	var scanVal func(v *flowir.Value)
	scanVal = func(v *flowir.Value) {
		if v == nil {
			return
		}
		if onTopVal != nil {
			onTopVal(v)
		}
		if v.Kind == flowir.ValMakeClosure && v.Closure != nil {
			forEachBodyOpAndTopVal(v.Closure, onOp, onTopVal)
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallIIFE && v.IIFE != nil {
			forEachBodyOpAndTopVal(v.IIFE, onOp, onTopVal)
		}
		v.ForEachChildValue(func(ch *flowir.Value) bool {
			scanVal(ch)
			return true
		})
	}
	for i := range b.Ops {
		op := &b.Ops[i]
		if onOp != nil {
			onOp(op)
		}
		forEachOpTopValues(op, scanVal)
		if op.Kind == flowir.OpAssign && op.AssignKind == flowir.AssignRange && op.RangeBody != nil {
			forEachBodyOpAndTopVal(op.RangeBody, onOp, onTopVal)
		}
	}
}

func isLocalOnlyClosureCall(b *flowir.Body, callVal *flowir.Value) bool {
	if b == nil || callVal == nil || callVal.CallKind != flowir.CallIndirect ||
		callVal.Callee == nil || callVal.Callee.Kind != flowir.ValPlace || !callVal.Callee.Place.IsBareVar() {
		return false
	}
	v := callVal.Callee.Place.Obj
	if v == nil || !b.OwnsVar(v) || v == b.Recv || b.ResultSet[v] {
		return false
	}
	if _, isParam := b.ParamIndex[v]; isParam {
		return false
	}
	okLocal := true
	sawClosure := false
	forEachBodyOpAndTopVal(b, func(op *flowir.Op) {
		if !okLocal {
			return
		}
		switch op.Kind {
		case flowir.OpAssign:
			if op.AssignKind == flowir.AssignZeroDecl {
				return
			}
			if op.AssignKind == flowir.AssignCompound || op.AssignKind == flowir.AssignIncDec || op.AssignKind == flowir.AssignRange {
				for _, dst := range op.Dsts {
					if dst.Obj == v {
						okLocal = false
						return
					}
				}
				return
			}
			op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
				if dst.Obj != v {
					return true
				}
				if !dst.IsBareVar() || src == nil || (src.Kind != flowir.ValMakeClosure && !(src.Kind == flowir.ValScalarLitOrConst && src.IsNil)) {
					okLocal = false
					return false
				}
				if src.Kind == flowir.ValMakeClosure {
					sawClosure = true
				}
				return true
			})
		case flowir.OpTypeSwitchBind:
			if op.SwitchDst == v {
				okLocal = false
			}
		case flowir.OpChanSend:
			if op.ChanPlace.Obj == v {
				okLocal = false
			}
		}
	}, func(val *flowir.Value) {
		if okLocal && val.Kind == flowir.ValAddrOf && val.AddrPlace.Obj == v {
			okLocal = false
		}
	})
	return okLocal && sawClosure
}

func typeMayHoldErasedString(t types.Type) bool {
	return t != nil && refconfine.TypeMayCarryUnknownDynamic(false, t)
}

func erasesStringIntoType(srcType, dstType types.Type) bool {
	return srcType != nil && dstType != nil &&
		syntaxutil.TypeReachesString(srcType) &&
		!syntaxutil.TypeReachesString(dstType) &&
		!syntaxutil.IsFreshStringSliceCopy(srcType, dstType) &&
		typeMayHoldErasedString(dstType)
}

func callPassesStringValue(v *flowir.Value) bool {
	if v == nil || v.Kind != flowir.ValCall {
		return false
	}
	if v.Recv != nil && syntaxutil.TypeReachesString(v.Recv.Type) {
		return true
	}
	for _, a := range v.Args {
		if a != nil && syntaxutil.TypeReachesString(a.Type) {
			return true
		}
	}
	return false
}

func (fc *pkgFlowCache) precomputeStringHeaderHazards(p *packages.Package) {
	if fc == nil || p == nil || p.TypesInfo == nil {
		return
	}
	isAuditedStdPkg := fc.audited && p.Module == nil && p.PkgPath != "" &&
		p.PkgPath != "unsafe" && p.PkgPath != "C" && syntaxutil.IsStandardLibraryPkgPath(p.PkgPath)
	funcBodies := make(map[*types.Func]*flowir.Body)
	var allTopBodies []*flowir.Body
	for _, file := range p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				var fn *types.Func
				if d.Name != nil {
					if fObj, ok := p.TypesInfo.Defs[d.Name].(*types.Func); ok && fObj != nil {
						fn = fObj.Origin()
					}
				}
				if d.Body == nil {
					if fn != nil && (syntaxutil.TypeReachesString(fn.Type()) || typeMayHoldErasedString(fn.Type())) {
						fc.stringHazardFuncs[fn] = true
						if !isAuditedStdPkg {
							fc.pkgHasStringHeaderUnsafe = true
							fc.pkgDirectStringUnsafe[fn] = true
						}
					}
					continue
				}
				b := fc.bodies[d]
				if b == nil {
					continue
				}
				allTopBodies = append(allTopBodies, b)
				if fn != nil {
					funcBodies[fn] = b
				}
				hasDirect := false
				forEachBodyOpAndTopVal(b, nil, func(v *flowir.Value) {
					if !hasDirect && valueNodeIsDirectStringHeaderUnsafe(b, v) {
						hasDirect = true
					}
				})
				if hasDirect {
					fc.pkgHasStringHeaderUnsafe = true
					if fn != nil {
						fc.pkgDirectStringUnsafe[fn] = true
						fc.stringHazardFuncs[fn] = true
					}
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR && d.Tok != token.CONST {
					continue
				}
				b := fc.bodies[d]
				if b == nil {
					continue
				}
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok && vs != nil {
						if vsb := fc.bodies[vs]; vsb != nil {
							allTopBodies = append(allTopBodies, vsb)
						}
					}
				}
				forEachBodyOpAndTopVal(b, nil, func(v *flowir.Value) {
					if !fc.pkgHasStringHeaderUnsafe && valueNodeIsDirectStringHeaderUnsafe(b, v) {
						fc.pkgHasStringHeaderUnsafe = true
					}
				})
			}
		}
	}

	var pkgStrGlobals []*types.Var
	if p.Types != nil && p.Types.Scope() != nil {
		sc := p.Types.Scope()
		for _, name := range sc.Names() {
			if gv, ok := sc.Lookup(name).(*types.Var); ok && gv != nil && syntaxutil.TypeReachesString(gv.Type()) {
				pkgStrGlobals = append(pkgStrGlobals, gv)
				if fc.pkgHasStringHeaderUnsafe || gv.Exported() {
					fc.exposedStringGlobals[gv] = true
				}
			}
		}
	}
	for _, b := range allTopBodies {
		forEachBodyOpAndTopVal(b, func(op *flowir.Op) {
			if fc.pkgWritesForeignStrGlob || op.Kind != flowir.OpAssign {
				return
			}
			op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
				if dst.Root == flowir.RootPkgGlobal && dst.Obj != nil &&
					fc.pkg != nil && dst.Obj.Pkg() != fc.pkg &&
					(syntaxutil.TypeReachesString(dst.Type) || (src != nil && syntaxutil.TypeReachesString(src.Type) && refconfine.CallResultHandsOut(dst.Type))) {
					fc.pkgWritesForeignStrGlob = true
					return false
				}
				return true
			})
		}, func(v *flowir.Value) {
			if !fc.pkgWritesForeignStrGlob && v != nil && v.Kind == flowir.ValCall &&
				v.CallKind == flowir.CallBuiltin && v.BuiltinName == "copy" &&
				len(v.Args) == 2 && v.Args[0] != nil && syntaxutil.TypeReachesString(v.Args[0].Type) {
				v.Args[0].WalkValues(func(cur *flowir.Value) bool {
					if cur.Kind == flowir.ValPlace && cur.Place.Root == flowir.RootPkgGlobal &&
						cur.Place.Obj != nil && fc.pkg != nil && cur.Place.Obj.Pkg() != fc.pkg {
						fc.pkgWritesForeignStrGlob = true
						return false
					}
					return true
				})
			}
		})
	}

	if fc.pkgHasStringHeaderUnsafe {
		for changed := true; changed; {
			changed = false
			for fn, b := range funcBodies {
				if fc.pkgDirectStringUnsafe[fn] {
					continue
				}
				reaches := false
				forEachBodyOpAndTopVal(b, nil, func(v *flowir.Value) {
					if reaches || v.Kind != flowir.ValCall {
						return
					}
					switch v.CallKind {
					case flowir.CallPlain:
						if v.IsMethodExprCall || v.CalleeFunc == nil {
							reaches = true
						} else if fc.pkgDirectStringUnsafe[v.CalleeFunc.Origin()] {
							reaches = true
						}
					case flowir.CallMethod:
						if v.IsMethodExprCall || v.CalleeFunc == nil || syntaxutil.InterfaceReceiver(v.CalleeFunc) {
							reaches = true
						} else if fc.pkgDirectStringUnsafe[v.CalleeFunc.Origin()] {
							reaches = true
						}
					case flowir.CallIndirect:
						reaches = true
					}
				})
				if reaches {
					fc.pkgDirectStringUnsafe[fn] = true
					fc.stringHazardFuncs[fn] = true
					changed = true
				}
			}
		}
	}

	bodyExposesReadGlobal := func(b *flowir.Body) bool {
		if b == nil {
			return false
		}
		for _, rt := range b.ResultTypes {
			if rt != nil && (syntaxutil.TypeReachesString(rt) || refconfine.CallResultHandsOut(rt)) {
				return true
			}
		}
		for _, rv := range b.Results {
			if rv != nil && (syntaxutil.TypeReachesString(rv.Type()) || refconfine.CallResultHandsOut(rv.Type())) {
				return true
			}
		}
		if fc.bodyMayPassStringToUnsafe(b) {
			return true
		}
		hit := false
		forEachBodyOpAndTopVal(b, func(op *flowir.Op) {
			if hit {
				return
			}
			switch op.Kind {
			case flowir.OpReturn:
				for i, r := range op.Results {
					if r == nil {
						continue
					}
					if syntaxutil.TypeReachesString(r.Type) || refconfine.CallResultHandsOut(r.Type) ||
						(i < len(b.ResultTypes) && b.ResultTypes[i] != nil && refconfine.CallResultHandsOut(b.ResultTypes[i])) {
						hit = true
						return
					}
				}
			case flowir.OpChanSend:
				if op.SendVal != nil && (syntaxutil.TypeReachesString(op.SendVal.Type) || refconfine.CallResultHandsOut(op.SendVal.Type)) {
					hit = true
				}
			case flowir.OpAssign:
				for _, dst := range op.Dsts {
					if dst.IsBlank() || (!syntaxutil.TypeReachesString(dst.Type) && !refconfine.CallResultHandsOut(dst.Type)) {
						continue
					}
					if dst.Root == flowir.RootPkgGlobal {
						if fc.isExposedStringGlobal(dst.Obj) || refconfine.CallResultHandsOut(dst.Type) {
							hit = true
							return
						}
					} else if dst.Root == flowir.RootResult || (!dst.IsBareVar() && dst.Root != flowir.RootLocal) {
						hit = true
						return
					}
				}
			}
		}, func(v *flowir.Value) {
			if !hit && v != nil && v.Kind == flowir.ValCall &&
				v.CallKind == flowir.CallBuiltin && v.BuiltinName == "copy" &&
				len(v.Args) == 2 && v.Args[0] != nil && syntaxutil.TypeReachesString(v.Args[0].Type) {
				hit = true
			}
		})
		return hit
	}

	for changed := true; changed; {
		changed = false
		for fn, b := range funcBodies {
			if fc.stringHazardFuncs[fn] {
				continue
			}
			if fc.bodyMayPassStringToUnsafe(b) {
				fc.stringHazardFuncs[fn] = true
				changed = true
			}
		}
		for _, gv := range pkgStrGlobals {
			if fc.exposedStringGlobals[gv] {
				continue
			}
			for _, b := range allTopBodies {
				if bodyReadsVar(b, gv) && bodyExposesReadGlobal(b) {
					fc.exposedStringGlobals[gv] = true
					changed = true
					break
				}
			}
		}
	}
}

func bodyReadsVar(b *flowir.Body, target *types.Var) bool {
	if b == nil || target == nil {
		return false
	}
	hit := false
	forEachBodyOpAndTopVal(b, func(op *flowir.Op) {
		if hit || op.Kind != flowir.OpAssign {
			return
		}
		if op.AssignKind == flowir.AssignIncDec {
			for _, dst := range op.Dsts {
				if dst.Obj == target {
					hit = true
					return
				}
			}
		}
		for _, dst := range op.Dsts {
			if len(dst.Projs) > 0 && dst.Obj == target {
				hit = true
				return
			}
		}
	}, func(v *flowir.Value) {
		if hit {
			return
		}
		switch v.Kind {
		case flowir.ValPlace:
			if v.Place.Obj == target {
				hit = true
			}
		case flowir.ValAddrOf:
			if v.AddrPlace.Obj == target {
				hit = true
			}
		case flowir.ValMethodVal:
			if v.HasRecvPlace && v.RecvPlace.Obj == target {
				hit = true
			}
		case flowir.ValCall:
			if v.AutoAddrRecv && v.HasRecvPlace && v.RecvPlace.Obj == target {
				hit = true
			}
		}
	})
	return hit
}

func (fc *pkgFlowCache) isExposedStringGlobal(v *types.Var) bool {
	if v == nil || !syntaxutil.TypeReachesString(v.Type()) {
		return false
	}
	if fc != nil && fc.pkg != nil && v.Pkg() == fc.pkg {
		return fc.exposedStringGlobals[v]
	}
	return true
}

func (fc *pkgFlowCache) callMayReachStringHeaderUnsafe(audited bool, v *flowir.Value) bool {
	if v == nil || v.Kind != flowir.ValCall {
		return true
	}
	var stdPkgPaths map[string]bool
	if fc != nil {
		stdPkgPaths = fc.stdPkgPaths
	}
	switch v.CallKind {
	case flowir.CallBuiltin:
		return v.BuiltinName == "StringData"
	case flowir.CallPlain:
		if v.IsMethodExprCall || v.CalleeFunc == nil {
			return true
		}
		fn := v.CalleeFunc.Origin()
		fk := syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: fn.Name()}
		if auditedValuePlane[fk] {
			return false
		}
		if fc != nil && fc.pkg != nil && fn.Pkg() == fc.pkg {
			return fc.stringHazardFuncs[fn]
		}
		return !(audited && stdPkgPaths[v.CalleePkg])
	case flowir.CallMethod:
		if v.IsMethodExprCall || v.CalleeFunc == nil || syntaxutil.InterfaceReceiver(v.CalleeFunc) {
			return true
		}
		fn := v.CalleeFunc.Origin()
		if fc != nil && fc.pkg != nil && fn.Pkg() == fc.pkg {
			return fc.stringHazardFuncs[fn]
		}
		return !(audited && stdPkgPaths[v.CalleePkg])
	case flowir.CallIIFE:
		return fc.bodyMayPassStringToUnsafe(v.IIFE)
	default:
		return true
	}
}

func valueWrapsStringInCarrier(v *flowir.Value) bool {
	if v == nil {
		return false
	}
	hit := false
	v.WalkValues(func(cur *flowir.Value) bool {
		if hit {
			return false
		}
		switch cur.Kind {
		case flowir.ValAllocFresh:
			if cur.AllocKind == flowir.AllocBuiltinNewExpr &&
				len(cur.Args) > 0 && cur.Args[0] != nil && erasesStringIntoType(cur.Args[0].Type, cur.Type) {
				hit = true
				return false
			}
			if cur.AllocKind == flowir.AllocCompositeLit && typeMayHoldErasedString(cur.Type) {
				for i := range cur.CompositeElts {
					elt := &cur.CompositeElts[i]
					if (elt.MapKey != nil && erasesStringIntoType(elt.MapKey.Type, cur.Type)) ||
						(elt.Value != nil && erasesStringIntoType(elt.Value.Type, cur.Type)) {
						hit = true
						return false
					}
				}
			}
		case flowir.ValAddrOf:
			if erasesStringIntoType(cur.AddrPlace.Type, cur.Type) ||
				(cur.AddrPlace.Obj != nil && erasesStringIntoType(cur.AddrPlace.Obj.Type(), cur.Type)) {
				hit = true
				return false
			}
			if cur.AddrPlace.Root == flowir.RootTransient && cur.AddrPlace.Base != nil &&
				cur.AddrPlace.Base.Kind == flowir.ValAllocFresh && cur.AddrPlace.Base.AllocKind == flowir.AllocCompositeLit &&
				typeMayHoldErasedString(cur.Type) {
				for i := range cur.AddrPlace.Base.CompositeElts {
					elt := &cur.AddrPlace.Base.CompositeElts[i]
					if (elt.MapKey != nil && erasesStringIntoType(elt.MapKey.Type, cur.Type)) ||
						(elt.Value != nil && erasesStringIntoType(elt.Value.Type, cur.Type)) {
						hit = true
						return false
					}
				}
			}
		case flowir.ValMethodVal:
			if cur.Recv != nil && syntaxutil.TypeReachesString(cur.Recv.Type) {
				hit = true
				return false
			}
		case flowir.ValMakeClosure:
			if cur.Closure != nil {
				for fv := range cur.Closure.FreeVars {
					if fv != nil && syntaxutil.TypeReachesString(fv.Type()) {
						hit = true
						return false
					}
				}
			}
		case flowir.ValConvert:
			if !cur.IsTypeAssert && cur.Arg != nil && erasesStringIntoType(cur.Arg.Type, cur.Type) {
				hit = true
				return false
			}
		case flowir.ValCall:
			if cur.CallKind == flowir.CallBuiltin && cur.BuiltinName == "append" &&
				len(cur.Args) > 0 && cur.Args[0] != nil && typeMayHoldErasedString(cur.Args[0].Type) {
				for _, a := range cur.Args[1:] {
					if a != nil && erasesStringIntoType(a.Type, cur.Args[0].Type) {
						hit = true
						return false
					}
				}
			}
		}
		return true
	})
	return hit
}

func callPassesCarrierValue(v *flowir.Value) bool {
	if v == nil || v.Kind != flowir.ValCall {
		return false
	}
	if v.Recv != nil && typeMayHoldErasedString(v.Recv.Type) {
		return true
	}
	for _, a := range v.Args {
		if a != nil && typeMayHoldErasedString(a.Type) {
			return true
		}
	}
	return false
}

func (fc *pkgFlowCache) bodyMayPassStringToUnsafe(b *flowir.Body) bool {
	if b == nil {
		return false
	}
	audited := fc != nil && fc.audited
	hit := false
	wrapsStr := false
	hasCarrierSink := false
	for _, rt := range b.ResultTypes {
		if rt != nil && typeMayHoldErasedString(rt) {
			hasCarrierSink = true
			break
		}
	}
	if !hasCarrierSink {
		for _, rv := range b.Results {
			if rv != nil && typeMayHoldErasedString(rv.Type()) {
				hasCarrierSink = true
				break
			}
		}
	}
	forEachBodyOpAndTopVal(b, func(op *flowir.Op) {
		if hit {
			return
		}
		switch op.Kind {
		case flowir.OpReturn:
			for i, r := range op.Results {
				if r == nil {
					continue
				}
				var slotT types.Type
				if i < len(b.ResultTypes) {
					slotT = b.ResultTypes[i]
				}
				if typeMayHoldErasedString(r.Type) || typeMayHoldErasedString(slotT) {
					hasCarrierSink = true
				}
				if erasesStringIntoType(r.Type, slotT) {
					wrapsStr = true
					hasCarrierSink = true
				}
			}
		case flowir.OpAssign:
			if op.AssignKind != flowir.AssignZeroDecl && op.AssignKind != flowir.AssignIncDec {
				op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
					if !dst.IsBlank() && src != nil && erasesStringIntoType(src.Type, dst.Type) {
						wrapsStr = true
					}
					return true
				})
			}
			for _, dst := range op.Dsts {
				if dst.IsBlank() {
					continue
				}
				if !dst.IsBareVar() {
					if dst.Obj != nil && erasesStringIntoType(dst.Type, dst.Obj.Type()) {
						wrapsStr = true
					}
					if mapPl, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil &&
						mapPl.Obj != nil && erasesStringIntoType(keyVal.Type, mapPl.Obj.Type()) {
						wrapsStr = true
					}
				}
				switch dst.Root {
				case flowir.RootPkgGlobal:
					if fc.isExposedStringGlobal(dst.Obj) {
						hit = true
						return
					}
					if typeMayHoldErasedString(dst.Type) || (dst.Obj != nil && typeMayHoldErasedString(dst.Obj.Type())) {
						hasCarrierSink = true
					}
				case flowir.RootOuterVar:
					if syntaxutil.TypeReachesString(dst.Type) &&
						(dst.Obj == nil || dst.Obj.Pos() < b.BodyStart || dst.Obj.Pos() > b.BodyEnd) {
						hit = true
						return
					}
					if typeMayHoldErasedString(dst.Type) {
						hasCarrierSink = true
					}
				case flowir.RootResult:
					if typeMayHoldErasedString(dst.Type) {
						hasCarrierSink = true
					}
				default:
					if !dst.IsBareVar() && dst.Root != flowir.RootLocal {
						if syntaxutil.TypeReachesString(dst.Type) {
							hit = true
							return
						}
						if _, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil && syntaxutil.TypeReachesString(keyVal.Type) {
							hit = true
							return
						}
						if typeMayHoldErasedString(dst.Type) {
							hasCarrierSink = true
						}
					}
				}
			}
		case flowir.OpChanSend:
			if op.SendVal != nil {
				if syntaxutil.TypeReachesString(op.SendVal.Type) {
					hit = true
				} else if typeMayHoldErasedString(op.SendVal.Type) {
					hasCarrierSink = true
				}
			}
		}
	}, func(v *flowir.Value) {
		if hit {
			return
		}
		if valueNodeIsDirectStringHeaderUnsafe(b, v) {
			hit = true
			return
		}
		if v.Kind == flowir.ValMethodVal && v.Recv != nil && syntaxutil.TypeReachesString(v.Recv.Type) {
			hit = true
			return
		}
		if !wrapsStr && valueWrapsStringInCarrier(v) {
			wrapsStr = true
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin && v.BuiltinName == "copy" &&
			len(v.Args) == 2 && v.Args[0] != nil && syntaxutil.TypeReachesString(v.Args[0].Type) {
			hit = true
			return
		}
		if v.Kind == flowir.ValCall && v.CallKind != flowir.CallIIFE && !isLocalOnlyClosureCall(b, v) {
			isValPlane := v.CallKind == flowir.CallBuiltin ||
				(v.CallKind == flowir.CallPlain && !v.IsMethodExprCall && v.CalleeFunc != nil &&
					auditedValuePlane[syntaxutil.FuncKey{Pkg: v.CalleePkg, Name: v.CalleeFunc.Origin().Name()}])
			if !isValPlane {
				v.ForEachArgParam(func(a *flowir.Value, slotType types.Type, _ int, pIdx int, pOK bool, packedVariadic bool) bool {
					if a == nil {
						return true
					}
					paramType := slotType
					if pOK {
						if pt := v.FormalParamSlotType(pIdx, packedVariadic); pt != nil {
							paramType = pt
						}
					}
					if erasesStringIntoType(a.Type, slotType) || erasesStringIntoType(slotType, paramType) {
						wrapsStr = true
						hasCarrierSink = true
					}
					return true
				})
				if callPassesCarrierValue(v) {
					hasCarrierSink = true
				}
			}
			if fc.callMayReachStringHeaderUnsafe(audited, v) && callPassesStringValue(v) {
				hit = true
				return
			}
		}
		if wrapsStr && hasCarrierSink {
			hit = true
		}
	})
	return hit || (wrapsStr && hasCarrierSink)
}

// bodyReturnsOrExposesString reports whether b returns a string-reaching value
// or may pass/expose a string value outside local pure reads.
func (fc *pkgFlowCache) bodyReturnsOrExposesString(b *flowir.Body) bool {
	if b == nil {
		return false
	}
	for _, rt := range b.ResultTypes {
		if rt != nil && (syntaxutil.TypeReachesString(rt) || typeMayHoldErasedString(rt)) {
			return true
		}
	}
	for _, rv := range b.Results {
		if rv != nil && (syntaxutil.TypeReachesString(rv.Type()) || typeMayHoldErasedString(rv.Type())) {
			return true
		}
	}
	if fc.bodyMayPassStringToUnsafe(b) {
		return true
	}
	hit := false
	forEachBodyOpAndTopVal(b, func(op *flowir.Op) {
		if hit {
			return
		}
		switch op.Kind {
		case flowir.OpReturn:
			for _, r := range op.Results {
				if r != nil && (syntaxutil.TypeReachesString(r.Type) || typeMayHoldErasedString(r.Type)) {
					hit = true
					return
				}
			}
		case flowir.OpAssign:
			for _, dst := range op.Dsts {
				if dst.IsBlank() || (!syntaxutil.TypeReachesString(dst.Type) && !typeMayHoldErasedString(dst.Type)) {
					continue
				}
				if dst.Root == flowir.RootPkgGlobal || dst.Root == flowir.RootOuterVar || dst.Root == flowir.RootResult ||
					(!dst.IsBareVar() && dst.Root != flowir.RootLocal) {
					hit = true
					return
				}
			}
		case flowir.OpChanSend:
			if op.SendVal != nil && (syntaxutil.TypeReachesString(op.SendVal.Type) || typeMayHoldErasedString(op.SendVal.Type)) {
				hit = true
			}
		}
	}, func(v *flowir.Value) {
		if hit {
			return
		}
		if valueNodeIsDirectStringHeaderUnsafe(b, v) {
			hit = true
			return
		}
		if v.Kind == flowir.ValMethodVal && v.Recv != nil && syntaxutil.TypeReachesString(v.Recv.Type) {
			hit = true
			return
		}
		if v.Kind == flowir.ValCall && v.CallKind == flowir.CallBuiltin && v.BuiltinName == "copy" &&
			len(v.Args) == 2 && v.Args[0] != nil && syntaxutil.TypeReachesString(v.Args[0].Type) {
			hit = true
			return
		}
		if v.Kind == flowir.ValCall && v.CallKind != flowir.CallIIFE && v.CallKind != flowir.CallBuiltin {
			switch v.CallKind {
			case flowir.CallPlain:
				if v.IsMethodExprCall || v.CalleeFunc == nil || fc.pkgDirectStringUnsafe[v.CalleeFunc.Origin()] ||
					(callPassesStringValue(v) && fc.callMayReachStringHeaderUnsafe(fc.audited, v)) {
					hit = true
				}
			case flowir.CallMethod:
				if v.IsMethodExprCall || v.CalleeFunc == nil || syntaxutil.InterfaceReceiver(v.CalleeFunc) ||
					fc.pkgDirectStringUnsafe[v.CalleeFunc.Origin()] ||
					(callPassesStringValue(v) && fc.callMayReachStringHeaderUnsafe(fc.audited, v)) {
					hit = true
				}
			default:
				hit = true
			}
		}
	})
	return hit
}

// bodyExposesStringToPkgUnsafe reports whether b (inside a package containing
// direct string-header unsafe operations) may expose a string value read in b
// to string-header unsafe mutation directly, via a package call, via return,
// or via store to non-local storage.
func (fc *pkgFlowCache) bodyExposesStringToPkgUnsafe(b *flowir.Body) bool {
	return fc != nil && fc.pkgHasStringHeaderUnsafe && fc.bodyReturnsOrExposesString(b)
}

func (fc *pkgFlowCache) scopedLocalCarrierAliases(audited bool, b *flowir.Body, allowObj func(types.Object) bool) map[types.Object]map[types.Object]bool {
	if b == nil {
		return nil
	}
	shares := func(t types.Type) bool {
		return canAliasCarrierType(audited, false, t)
	}
	if allowObj != nil {
		return flowir.BuildScopedMemAliases(b, allowObj, shares)
	}
	if fc != nil && fc.audited == audited {
		if adj, ok := fc.localCarrierAliases[b]; ok {
			return adj
		}
	}
	adj := flowir.BuildScopedMemAliases(b, syntaxutil.IsLocalVar, shares)
	if fc != nil && fc.audited == audited {
		fc.localCarrierAliases[b] = adj
	}
	return adj
}

func (fc *pkgFlowCache) scopedBodyInteriorAliases(audited, includeStrings bool, b *flowir.Body, exclude map[types.Object]bool) map[types.Object]map[types.Object]bool {
	if b == nil {
		return nil
	}
	baseShares := sharesMemOrSigOrDynamic(audited)
	shares := func(t types.Type) bool {
		return baseShares(t) || (includeStrings && syntaxutil.TypeReachesString(t))
	}
	hasInteriorExclude := false
	for r := range exclude {
		if v, ok := r.(*types.Var); ok && v != nil && !v.IsField() && !isPkgOrOuterToBody(b, v) {
			hasInteriorExclude = true
			break
		}
	}
	if hasInteriorExclude {
		return flowir.BuildScopedMemAliases(
			b,
			func(obj types.Object) bool {
				v, ok := obj.(*types.Var)
				return ok && v != nil && !v.IsField() && !exclude[v] && !isPkgOrOuterToBody(b, v)
			},
			shares,
		)
	}
	if fc != nil && fc.audited == audited {
		cache := fc.interiorAliases
		if includeStrings {
			cache = fc.interiorStrAliases
		}
		if adj, ok := cache[b]; ok {
			return adj
		}
	}
	adj := flowir.BuildScopedMemAliases(
		b,
		func(obj types.Object) bool {
			v, ok := obj.(*types.Var)
			return ok && v != nil && !v.IsField() && !isPkgOrOuterToBody(b, v)
		},
		shares,
	)
	if fc != nil && fc.audited == audited {
		if includeStrings {
			fc.interiorStrAliases[b] = adj
		} else {
			fc.interiorAliases[b] = adj
		}
	}
	return adj
}

func typeReachesNamedWithMethods(t types.Type) bool {
	if t == nil {
		return false
	}
	return typeReachesNamedWithMethodsSeen(t, make(map[types.Type]bool))
}

func typeReachesNamedWithMethodsSeen(t types.Type, seen map[types.Type]bool) bool {
	return refconfine.WalkTypeStructure(t, seen, false, func(u types.Type) (bool, bool) {
		switch u := u.(type) {
		case *types.Named:
			if _, isIface := u.Underlying().(*types.Interface); isIface {
				return true, true
			}
			msetType := types.Type(u)
			if _, isPtr := u.Underlying().(*types.Pointer); !isPtr {
				msetType = types.NewPointer(u)
			}
			if types.NewMethodSet(msetType).Len() > 0 {
				return true, true
			}
			return false, false
		case *types.Basic, *types.Signature:
			return false, true
		case *types.Interface, *types.TypeParam:
			return true, true
		case *types.Pointer:
			return typeReachesNamedWithMethodsSeen(u.Elem(), seen), true
		case *types.Slice:
			return typeReachesNamedWithMethodsSeen(u.Elem(), seen), true
		case *types.Chan:
			return typeReachesNamedWithMethodsSeen(u.Elem(), seen), true
		case *types.Map:
			return typeReachesNamedWithMethodsSeen(u.Key(), seen) || typeReachesNamedWithMethodsSeen(u.Elem(), seen), true
		case *types.Struct, *types.Array, *types.Tuple:
			return false, false
		default:
			return true, true
		}
	})
}

func typeMayCarryCallback(audited bool, t types.Type) bool {
	if t == nil {
		return false
	}
	return refconfine.TypeCarriesSignature(t) ||
		refconfine.TypeHandsOutDynamicAlias(audited, t) ||
		typeReachesNamedWithMethods(t)
}

func typeMayWriteBackStringToOrigin(audited bool, t types.Type) bool {
	if t == nil {
		return true
	}
	strOrErased := func(x types.Type) bool {
		return x != nil && (syntaxutil.TypeReachesString(x) || typeMayHoldErasedString(x))
	}
	seen := map[types.Type]bool{}
	var walk func(cur types.Type) bool
	walk = func(cur types.Type) bool {
		if cur == nil {
			return true
		}
		u0 := types.Unalias(cur)
		if tup, isTup := u0.(*types.Tuple); isTup {
			for i := 0; i < tup.Len(); i++ {
				if walk(tup.At(i).Type()) {
					return true
				}
			}
			return false
		}
		if _, isTP := u0.(*types.TypeParam); isTP {
			return true
		}
		if seen[u0] {
			return false
		}
		seen[u0] = true
		if named, isNamed := u0.(*types.Named); isNamed {
			if elem, ok := refconfine.AuditedAtomicPointerElem(audited, named); ok {
				return elem == nil || strOrErased(elem) || typeMayCarryCallback(audited, elem) || walk(elem)
			}
		}
		if typeReachesNamedWithMethods(u0) {
			return true
		}
		switch u := u0.Underlying().(type) {
		case *types.Basic:
			return u.Kind() == types.UnsafePointer || u.Kind() == types.Uintptr
		case *types.Interface:
			return true
		case *types.Signature:
			if params := u.Params(); params != nil {
				for i := 0; i < params.Len(); i++ {
					pt := params.At(i).Type()
					if strOrErased(pt) || typeMayCarryCallback(audited, pt) {
						return true
					}
				}
			}
			if results := u.Results(); results != nil {
				for i := 0; i < results.Len(); i++ {
					if walk(results.At(i).Type()) {
						return true
					}
				}
			}
			return false
		case *types.Pointer:
			return strOrErased(u.Elem()) || typeMayCarryCallback(audited, u.Elem()) || walk(u.Elem())
		case *types.Slice:
			return strOrErased(u.Elem()) || typeMayCarryCallback(audited, u.Elem()) || walk(u.Elem())
		case *types.Map:
			return strOrErased(u.Key()) || strOrErased(u.Elem()) ||
				typeMayCarryCallback(audited, u.Key()) || typeMayCarryCallback(audited, u.Elem()) ||
				walk(u.Key()) || walk(u.Elem())
		case *types.Chan:
			return walk(u.Elem()) ||
				(u.Dir() != types.RecvOnly && (strOrErased(u.Elem()) || typeMayCarryCallback(audited, u.Elem())))
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if walk(u.Field(i).Type()) {
					return true
				}
			}
			return false
		case *types.Array:
			return walk(u.Elem())
		}
		return false
	}
	return walk(t)
}

func typeMayWriteBackCallbackToOrigin(audited bool, t types.Type) bool {
	if t == nil {
		return true
	}
	seen := map[types.Type]bool{}
	var walk func(cur types.Type) bool
	sigPlants := func(sig *types.Signature) bool {
		if sig == nil {
			return false
		}
		if params := sig.Params(); params != nil {
			for i := 0; i < params.Len(); i++ {
				if typeMayCarryCallback(audited, params.At(i).Type()) {
					return true
				}
			}
		}
		if results := sig.Results(); results != nil {
			for i := 0; i < results.Len(); i++ {
				if walk(results.At(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	walk = func(cur types.Type) bool {
		if cur == nil {
			return true
		}
		u0 := types.Unalias(cur)
		if tup, isTup := u0.(*types.Tuple); isTup {
			for i := 0; i < tup.Len(); i++ {
				if walk(tup.At(i).Type()) {
					return true
				}
			}
			return false
		}
		if _, isTP := u0.(*types.TypeParam); isTP {
			return true
		}
		if seen[u0] {
			return false
		}
		seen[u0] = true
		if named, isNamed := u0.(*types.Named); isNamed {
			if elem, ok := refconfine.AuditedAtomicPointerElem(audited, named); ok {
				return elem == nil || typeMayCarryCallback(audited, elem) || walk(elem)
			}
			msetType := types.Type(named)
			if _, isIface := u0.Underlying().(*types.Interface); !isIface {
				if _, isPtr := u0.Underlying().(*types.Pointer); !isPtr {
					msetType = types.NewPointer(named)
				}
			}
			mset := types.NewMethodSet(msetType)
			for i := 0; i < mset.Len(); i++ {
				if sig, ok := mset.At(i).Type().(*types.Signature); ok && sigPlants(sig) {
					return true
				}
			}
		}
		switch u := u0.Underlying().(type) {
		case *types.Basic:
			return u.Kind() == types.UnsafePointer || u.Kind() == types.Uintptr
		case *types.Interface:
			return true
		case *types.Signature:
			return sigPlants(u)
		case *types.Pointer:
			return typeMayCarryCallback(audited, u.Elem()) || walk(u.Elem())
		case *types.Slice:
			return typeMayCarryCallback(audited, u.Elem()) || walk(u.Elem())
		case *types.Map:
			return typeMayCarryCallback(audited, u.Key()) || typeMayCarryCallback(audited, u.Elem()) ||
				walk(u.Key()) || walk(u.Elem())
		case *types.Chan:
			return walk(u.Elem()) || (u.Dir() != types.RecvOnly && typeMayCarryCallback(audited, u.Elem()))
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if walk(u.Field(i).Type()) {
					return true
				}
			}
			return false
		case *types.Array:
			return walk(u.Elem())
		}
		return false
	}
	return walk(t)
}

func collectForeignStringAndCallbackEdges(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	sinkPkgs map[string]bool,
	sinkParams map[syntaxutil.ParamKey]bool,
	sinkMethods map[syntaxutil.FuncKey]bool,
	callbackTargets map[string]bool,
) {
	if p == nil || p.Types == nil || fc == nil {
		return
	}
	selfPkg := p.Types.Path()
	eligibleForeign := func(pkgPath string) bool {
		return pkgPath != "" && pkgPath != selfPkg && !(audited && fc.stdPkgPaths[pkgPath])
	}
	strOrErased := func(t types.Type) bool {
		return t != nil && (syntaxutil.TypeReachesString(t) || typeMayHoldErasedString(t))
	}
	noteForeignValueFrom := func(q string, t types.Type) {
		if !eligibleForeign(q) {
			return
		}
		if typeMayWriteBackStringToOrigin(audited, t) {
			sinkPkgs[q] = true
		}
		if typeMayWriteBackCallbackToOrigin(audited, t) {
			callbackTargets[q] = true
		}
	}
	seenNamedCapTypes := map[types.Type]bool{}
	var noteForeignNamedMethodCapabilities func(t types.Type)
	noteForeignNamedMethodCapabilities = func(t types.Type) {
		if t == nil {
			return
		}
		u0 := types.Unalias(t)
		if tup, isTup := u0.(*types.Tuple); isTup {
			for i := 0; i < tup.Len(); i++ {
				noteForeignNamedMethodCapabilities(tup.At(i).Type())
			}
			return
		}
		if seenNamedCapTypes[u0] {
			return
		}
		seenNamedCapTypes[u0] = true
		if named, isNamed := u0.(*types.Named); isNamed {
			if targs := named.TypeArgs(); targs != nil {
				for i := 0; i < targs.Len(); i++ {
					noteForeignNamedMethodCapabilities(targs.At(i))
				}
			}
			if _, isIface := u0.Underlying().(*types.Interface); !isIface && named.Obj() != nil && named.Obj().Pkg() != nil {
				q := named.Obj().Pkg().Path()
				if eligibleForeign(q) {
					msetType := types.Type(named)
					if _, isPtr := u0.Underlying().(*types.Pointer); !isPtr {
						msetType = types.NewPointer(named)
					}
					mset := types.NewMethodSet(msetType)
					if mset.Len() > 0 {
						under := u0.Underlying()
						carriesDyn := refconfine.TypeCarriesSignature(under) || refconfine.TypeHandsOutDynamicAlias(audited, under)
						if strOrErased(under) || carriesDyn {
							sinkPkgs[q] = true
						} else {
							for i := 0; i < mset.Len(); i++ {
								sig, ok := mset.At(i).Type().(*types.Signature)
								if !ok || sig == nil {
									continue
								}
								hit := false
								if params := sig.Params(); params != nil {
									for j := 0; j < params.Len(); j++ {
										pt := params.At(j).Type()
										if strOrErased(pt) || typeMayCarryCallback(audited, pt) {
											hit = true
											break
										}
									}
								}
								if !hit {
									if results := sig.Results(); results != nil {
										for j := 0; j < results.Len(); j++ {
											if typeMayWriteBackStringToOrigin(audited, results.At(j).Type()) {
												hit = true
												break
											}
										}
									}
								}
								if hit {
									sinkPkgs[q] = true
									break
								}
							}
						}
						if carriesDyn || typeMayWriteBackCallbackToOrigin(audited, named) {
							callbackTargets[q] = true
						}
					}
				}
			}
		}
		switch u := u0.Underlying().(type) {
		case *types.Pointer:
			noteForeignNamedMethodCapabilities(u.Elem())
		case *types.Slice:
			noteForeignNamedMethodCapabilities(u.Elem())
		case *types.Array:
			noteForeignNamedMethodCapabilities(u.Elem())
		case *types.Chan:
			noteForeignNamedMethodCapabilities(u.Elem())
		case *types.Map:
			noteForeignNamedMethodCapabilities(u.Key())
			noteForeignNamedMethodCapabilities(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				noteForeignNamedMethodCapabilities(u.Field(i).Type())
			}
		case *types.Signature:
			if params := u.Params(); params != nil {
				for i := 0; i < params.Len(); i++ {
					noteForeignNamedMethodCapabilities(params.At(i).Type())
				}
			}
			if results := u.Results(); results != nil {
				for i := 0; i < results.Len(); i++ {
					noteForeignNamedMethodCapabilities(results.At(i).Type())
				}
			}
		}
	}

	var walkBody func(b *flowir.Body, inGo bool)
	var walkVal func(v *flowir.Value, inGo bool)

	walkVal = func(v *flowir.Value, inGo bool) {
		if v == nil {
			return
		}
		noteForeignNamedMethodCapabilities(v.Type)
		if v.Kind == flowir.ValAllocFresh {
			noteForeignNamedMethodCapabilities(v.ElemType)
		}
		switch v.Kind {
		case flowir.ValMakeClosure:
			if v.Closure != nil {
				walkBody(v.Closure, inGo)
			}
			return

		case flowir.ValPlace:
			if v.Place.Root == flowir.RootFunc && eligibleForeign(v.Place.FuncPkg) {
				sinkPkgs[v.Place.FuncPkg] = true
				if typeMayWriteBackCallbackToOrigin(audited, v.Type) {
					callbackTargets[v.Place.FuncPkg] = true
				}
			} else if v.Place.Root == flowir.RootPkgGlobal && v.Place.Obj != nil && v.Place.Obj.Pkg() != nil {
				q := v.Place.Obj.Pkg().Path()
				noteForeignValueFrom(q, v.Place.Obj.Type())
				noteForeignValueFrom(q, v.Type)
			}

		case flowir.ValAddrOf:
			if v.AddrPlace.Root == flowir.RootPkgGlobal && v.AddrPlace.Obj != nil && v.AddrPlace.Obj.Pkg() != nil {
				q := v.AddrPlace.Obj.Pkg().Path()
				noteForeignValueFrom(q, v.Type)
				if eligibleForeign(q) {
					if strOrErased(v.AddrPlace.Obj.Type()) {
						sinkPkgs[q] = true
					}
					if typeMayCarryCallback(audited, v.AddrPlace.Obj.Type()) {
						callbackTargets[q] = true
					}
				}
			}

		case flowir.ValMethodVal:
			if eligibleForeign(v.CalleePkg) {
				sinkPkgs[v.CalleePkg] = true
				if (v.Recv != nil && typeMayCarryCallback(audited, v.Recv.Type)) ||
					typeMayWriteBackCallbackToOrigin(audited, v.Type) {
					callbackTargets[v.CalleePkg] = true
				}
			}

		case flowir.ValCall:
			if v.CallKind == flowir.CallIIFE {
				for _, a := range v.Args {
					walkVal(a, inGo)
				}
				if v.IIFE != nil {
					walkBody(v.IIFE, inGo)
				}
				return
			}
			if v.CallKind == flowir.CallBuiltin {
				if (v.BuiltinName == "copy" || v.BuiltinName == "append") && len(v.Args) >= 2 && v.Args[0] != nil {
					v.Args[0].WalkValues(func(cur *flowir.Value) bool {
						if cur.Kind == flowir.ValPlace && cur.Place.Root == flowir.RootPkgGlobal &&
							cur.Place.Obj != nil && cur.Place.Obj.Pkg() != nil {
							q := cur.Place.Obj.Pkg().Path()
							if eligibleForeign(q) {
								if strOrErased(v.Args[0].Type) {
									sinkPkgs[q] = true
								}
								if typeMayCarryCallback(audited, v.Args[0].Type) {
									callbackTargets[q] = true
								}
							}
						}
						return true
					})
				}
				for _, a := range v.Args {
					walkVal(a, inGo)
				}
				return
			}

			q := v.CalleePkg
			if eligibleForeign(q) {
				if v.Type != nil && typeMayCarryCallback(audited, v.Type) {
					sinkPkgs[q] = true
				}
				noteForeignValueFrom(q, v.Type)
				if v.Recv != nil && typeMayCarryCallback(audited, v.Recv.Type) {
					callbackTargets[q] = true
				}
				for _, a := range v.Args {
					if a != nil && typeMayCarryCallback(audited, a.Type) {
						callbackTargets[q] = true
					}
				}
				if v.CallKind == flowir.CallPlain && !v.IsMethodExprCall && v.CalleeFunc != nil && !inGo {
					fk := syntaxutil.FuncKey{Pkg: q, Name: v.CalleeFunc.Origin().Name()}
					if !auditedValuePlane[fk] {
						v.ForEachArgParam(func(a *flowir.Value, slotType types.Type, _ int, pIdx int, pOK bool, packedVariadic bool) bool {
							if a == nil {
								return true
							}
							paramType := slotType
							if pOK {
								if pt := v.FormalParamSlotType(pIdx, packedVariadic); pt != nil {
									paramType = pt
								}
							}
							if paramType != nil && typeMayCarryCallback(audited, paramType) {
								callbackTargets[q] = true
							}
							if isPureFreshDataValueWith(a, nil) {
								return true
							}
							argAlreadyErased := erasesStringIntoType(a.Type, slotType) ||
								(!syntaxutil.TypeReachesString(a.Type) && typeMayHoldErasedString(a.Type))
							strPass := syntaxutil.TypeReachesString(a.Type) ||
								(slotType != nil && syntaxutil.TypeReachesString(slotType)) ||
								(paramType != nil && syntaxutil.TypeReachesString(paramType)) ||
								erasesStringIntoType(slotType, paramType)
							if argAlreadyErased || (!pOK && strPass) {
								sinkPkgs[q] = true
							} else if pOK && strPass {
								sinkParams[syntaxutil.ParamKey{Func: fk, Index: pIdx}] = true
							}
							return true
						})
					}
				} else if v.CallKind == flowir.CallMethod && !v.IsMethodExprCall &&
					v.CalleeFunc != nil && !syntaxutil.InterfaceReceiver(v.CalleeFunc) && !inGo {
					mk := syntaxutil.MethodFactKey(v.CalleeFunc.Origin())
					v.ForEachArgParam(func(a *flowir.Value, slotType types.Type, _ int, pIdx int, pOK bool, packedVariadic bool) bool {
						if a == nil {
							return true
						}
						paramType := slotType
						if pOK {
							if pt := v.FormalParamSlotType(pIdx, packedVariadic); pt != nil {
								paramType = pt
							}
						}
						if paramType != nil && typeMayCarryCallback(audited, paramType) {
							callbackTargets[q] = true
						}
						if !isPureFreshDataValueWith(a, nil) && (strOrErased(a.Type) || strOrErased(slotType) || strOrErased(paramType)) {
							sinkPkgs[q] = true
						}
						return true
					})
					if v.Recv != nil && !isPureFreshDataValueWith(v.Recv, nil) {
						if (!syntaxutil.TypeReachesString(v.Recv.Type) && typeMayHoldErasedString(v.Recv.Type)) || !mk.Valid() {
							sinkPkgs[q] = true
						} else if syntaxutil.TypeReachesString(v.Recv.Type) {
							sinkMethods[mk] = true
						}
					}
				} else {
					if v.Recv != nil && !isPureFreshDataValueWith(v.Recv, nil) && strOrErased(v.Recv.Type) {
						sinkPkgs[q] = true
					}
					for _, a := range v.Args {
						if a != nil && !isPureFreshDataValueWith(a, nil) && strOrErased(a.Type) {
							sinkPkgs[q] = true
						}
					}
				}
			}

			if v.Recv != nil {
				walkVal(v.Recv, inGo)
			}
			if v.Callee != nil && !(v.CallKind == flowir.CallPlain && !v.IsMethodExprCall) {
				walkVal(v.Callee, inGo)
			}
			for _, a := range v.Args {
				walkVal(a, inGo)
			}
			return
		}

		v.ForEachChildValue(func(ch *flowir.Value) bool {
			walkVal(ch, inGo)
			return true
		})
	}

	walkBody = func(b *flowir.Body, inGo bool) {
		if b == nil {
			return
		}
		if b.Recv != nil {
			noteForeignNamedMethodCapabilities(b.Recv.Type())
		}
		for _, pv := range b.Params {
			if pv != nil {
				noteForeignNamedMethodCapabilities(pv.Type())
			}
		}
		for _, rt := range b.ResultTypes {
			noteForeignNamedMethodCapabilities(rt)
		}
		b.ForEachSyncOp(func(op *flowir.Op) bool {
			switch op.Kind {
			case flowir.OpGo:
				walkVal(op.Call, true)
				return true
			case flowir.OpAssign:
				for _, dst := range op.Dsts {
					noteForeignNamedMethodCapabilities(dst.Type)
					if dst.Obj != nil {
						noteForeignNamedMethodCapabilities(dst.Obj.Type())
					}
				}
				if op.AssignKind != flowir.AssignZeroDecl && op.AssignKind != flowir.AssignIncDec {
					op.ForEachAssignPair(func(_ int, dst flowir.Place, _ bool, src *flowir.Value) bool {
						if dst.Root == flowir.RootPkgGlobal && dst.Obj != nil && dst.Obj.Pkg() != nil {
							q := dst.Obj.Pkg().Path()
							if eligibleForeign(q) {
								if strOrErased(dst.Type) || (src != nil && strOrErased(src.Type)) {
									sinkPkgs[q] = true
								}
								if typeMayCarryCallback(audited, dst.Type) || (src != nil && typeMayCarryCallback(audited, src.Type)) {
									callbackTargets[q] = true
								}
								if _, keyVal, isMapW := dst.AsMapWrite(); isMapW && keyVal != nil {
									if strOrErased(keyVal.Type) {
										sinkPkgs[q] = true
									}
									if typeMayCarryCallback(audited, keyVal.Type) {
										callbackTargets[q] = true
									}
								}
							}
						}
						return true
					})
				}
			case flowir.OpChanSend:
				if op.ChanPlace.Root == flowir.RootPkgGlobal && op.ChanPlace.Obj != nil && op.ChanPlace.Obj.Pkg() != nil {
					q := op.ChanPlace.Obj.Pkg().Path()
					if eligibleForeign(q) && op.SendVal != nil {
						if strOrErased(op.SendVal.Type) {
							sinkPkgs[q] = true
						}
						if typeMayCarryCallback(audited, op.SendVal.Type) {
							callbackTargets[q] = true
						}
					}
				}
			}
			forEachOpTopValues(op, func(tv *flowir.Value) {
				walkVal(tv, inGo)
			})
			return true
		})
	}

	if p.Types != nil && p.Types.Scope() != nil {
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			switch obj := scope.Lookup(name).(type) {
			case *types.Var, *types.TypeName:
				noteForeignNamedMethodCapabilities(obj.Type())
			}
		}
	}
	if p.TypesInfo != nil {
		if p.TypesInfo.Instances != nil {
			for _, inst := range p.TypesInfo.Instances {
				if inst.TypeArgs != nil {
					for i := 0; i < inst.TypeArgs.Len(); i++ {
						noteForeignNamedMethodCapabilities(inst.TypeArgs.At(i))
					}
				}
			}
		} else {
			for _, tv := range p.TypesInfo.Types {
				if tv.IsType() {
					noteForeignNamedMethodCapabilities(tv.Type)
				}
			}
		}
	}

	for _, file := range p.Syntax {
		if file == nil {
			continue
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body != nil {
					walkBody(fc.funcBody(p, d), false)
				}
			case *ast.GenDecl:
				if d.Tok == token.VAR || d.Tok == token.CONST {
					walkBody(fc.body(p, d), false)
				}
			}
		}
	}
}
