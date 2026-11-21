package flowir

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// PlaceEntersInterior reports whether accessing or writing through p (with
// writeContainer true for container-mutating operations such as delete, clear,
// channel send, or channel receive) crosses beyond p.Obj's own single-hop
// reference header into interior reach.
func PlaceEntersInterior(p Place, writeContainer bool) bool {
	if p.Obj == nil || p.Obj.Type() == nil || isTypeParam(p.Obj.Type()) {
		return true
	}
	usedHeader := !syntaxutil.IsRefHeaderType(p.Obj.Type())
	crossHop := func() bool {
		if usedHeader {
			return true
		}
		usedHeader = true
		return false
	}
	for _, proj := range p.Projs {
		if proj.BaseType == nil || isTypeParam(proj.BaseType) {
			return true
		}
		baseU := types.Unalias(proj.BaseType).Underlying()
		switch proj.Kind {
		case ProjDeref:
			if crossHop() {
				return true
			}
		case ProjIndex:
			switch baseU.(type) {
			case *types.Array:
				// Inline array element: no pointer/header indirection.
			case *types.Pointer, *types.Slice, *types.Map:
				if crossHop() {
					return true
				}
			default:
				return true
			}
		case ProjSlice:
			switch baseU.(type) {
			case *types.Slice, *types.Array:
				// Re-slicing a slice or inline array yields a slice view without an extra hop.
			case *types.Pointer:
				if crossHop() {
					return true
				}
			default:
				return true
			}
		case ProjField:
			cur := baseU
			if ptr, isPtr := cur.(*types.Pointer); isPtr {
				if crossHop() {
					return true
				}
				cur = types.Unalias(ptr.Elem()).Underlying()
			}
			if proj.Selection == nil {
				return true
			}
			idx := proj.Selection.Index()
			for _, fi := range idx[:len(idx)-1] {
				st, ok := cur.(*types.Struct)
				if !ok || fi < 0 || fi >= st.NumFields() {
					return true
				}
				ft := st.Field(fi).Type()
				if isTypeParam(ft) {
					return true
				}
				fu := types.Unalias(ft).Underlying()
				if ptr, isPtr := fu.(*types.Pointer); isPtr {
					if crossHop() {
						return true
					}
					cur = types.Unalias(ptr.Elem()).Underlying()
				} else {
					cur = fu
				}
			}
		default:
			return true
		}
	}
	if writeContainer {
		if crossHop() {
			return true
		}
	}
	return false
}

func isTypeParam(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := types.Unalias(t).(*types.TypeParam)
	return ok
}

// VisitAllOps visits every operation in b (including OpGo and RangeBody) and
// recursively descends into nested ValMakeClosure and CallIIFE bodies.
func VisitAllOps(b *Body, fn func(*Op)) {
	if b == nil || fn == nil {
		return
	}
	var scanVal func(v *Value)
	scanVal = func(v *Value) {
		if v == nil {
			return
		}
		if v.Kind == ValMakeClosure && v.Closure != nil {
			VisitAllOps(v.Closure, fn)
		}
		if v.Kind == ValCall && v.CallKind == CallIIFE && v.IIFE != nil {
			VisitAllOps(v.IIFE, fn)
		}
		v.ForEachChildValue(func(ch *Value) bool {
			scanVal(ch)
			return true
		})
	}
	b.ForEachSyncOp(func(op *Op) bool {
		fn(op)
		op.ForEachValue(func(v *Value) bool {
			scanVal(v)
			return true
		})
		return true
	})
}

// VisitSyncAndIIFEOps visits every synchronous non-OpGo operation in b and
// recursively descends into synchronous CallIIFE bodies without entering
// uncalled ValMakeClosure bodies or spawned goroutines.
func VisitSyncAndIIFEOps(b *Body, fn func(*Op)) {
	if b == nil || fn == nil {
		return
	}
	var scanVal func(v *Value)
	scanVal = func(v *Value) {
		if v == nil || v.Kind == ValMakeClosure {
			return
		}
		if v.Kind == ValCall && v.CallKind == CallIIFE {
			for _, a := range v.Args {
				scanVal(a)
			}
			if v.IIFE != nil {
				VisitSyncAndIIFEOps(v.IIFE, fn)
			}
			return
		}
		v.ForEachChildValue(func(ch *Value) bool {
			scanVal(ch)
			return true
		})
	}
	b.ForEachSyncOp(func(op *Op) bool {
		if op.Kind == OpGo {
			return true
		}
		fn(op)
		op.ForEachValue(func(v *Value) bool {
			scanVal(v)
			return true
		})
		return true
	})
}

// ForEachIIFEReturnValue invokes fn on each named result place and synchronous
// return expression of an IIFE call value v.
func ForEachIIFEReturnValue(v *Value, fn func(*Value)) {
	if v == nil || v.Kind != ValCall || v.CallKind != CallIIFE || v.IIFE == nil || fn == nil {
		return
	}
	for _, rv := range v.IIFE.Results {
		if rv == nil {
			continue
		}
		fn(&Value{
			Kind: ValPlace,
			Type: rv.Type(),
			Place: Place{
				Root:    RootResult,
				RootPos: rv.Pos(),
				Obj:     rv,
				Type:    rv.Type(),
			},
		})
	}
	v.IIFE.ForEachSyncOp(func(op *Op) bool {
		if op.Kind != OpReturn {
			return true
		}
		for _, res := range op.Results {
			if res != nil {
				fn(res)
			}
		}
		return true
	})
}

func fieldMatches(f *types.Var, match func(*types.Var) bool) bool {
	if f == nil {
		return false
	}
	return match(f) || (f.Origin() != f && match(f.Origin()))
}

func placeMentionsDirectVar(p Place, match func(*types.Var) bool) bool {
	if p.Obj != nil && match(p.Obj) {
		return true
	}
	for i := range p.Projs {
		if fieldMatches(p.Projs[i].Field, match) {
			return true
		}
	}
	return false
}

func valueMentionsMatch(v *Value, match func(*types.Var) bool) bool {
	if v == nil || match == nil {
		return false
	}
	hit := false
	v.WalkValues(func(cur *Value) bool {
		if hit {
			return false
		}
		switch cur.Kind {
		case ValPlace:
			if placeMentionsDirectVar(cur.Place, match) {
				hit = true
				return false
			}
		case ValAddrOf:
			if placeMentionsDirectVar(cur.AddrPlace, match) {
				hit = true
				return false
			}
		case ValMethodVal:
			if cur.HasRecvPlace && placeMentionsDirectVar(cur.RecvPlace, match) {
				hit = true
				return false
			}
		case ValAllocFresh:
			for i := range cur.CompositeElts {
				if fieldMatches(cur.CompositeElts[i].Field, match) {
					hit = true
					return false
				}
			}
		case ValCall:
			if cur.HasRecvPlace && placeMentionsDirectVar(cur.RecvPlace, match) {
				hit = true
				return false
			}
			if cur.CallKind == CallIIFE && cur.IIFE != nil && bodyMentionsMatch(cur.IIFE, match) {
				hit = true
				return false
			}
		case ValMakeClosure:
			if cur.Closure != nil && bodyMentionsMatch(cur.Closure, match) {
				hit = true
				return false
			}
		}
		return true
	})
	return hit
}

func opMentionsMatch(op *Op, match func(*types.Var) bool) bool {
	if op == nil || match == nil {
		return false
	}
	switch op.Kind {
	case OpAssign:
		for _, dst := range op.Dsts {
			if placeMentionsDirectVar(dst, match) {
				return true
			}
		}
		if op.RangeBody != nil && bodyMentionsMatch(op.RangeBody, match) {
			return true
		}
	case OpTypeSwitchBind:
		if op.SwitchDst != nil && match(op.SwitchDst) {
			return true
		}
	case OpChanSend:
		if placeMentionsDirectVar(op.ChanPlace, match) {
			return true
		}
	}
	hit := false
	op.ForEachValue(func(v *Value) bool {
		if valueMentionsMatch(v, match) {
			hit = true
			return false
		}
		return true
	})
	return hit
}

func bodyMentionsMatch(b *Body, match func(*types.Var) bool) bool {
	if b == nil || match == nil {
		return false
	}
	for i := range b.Ops {
		if opMentionsMatch(&b.Ops[i], match) {
			return true
		}
	}
	return false
}

// ValueMentionsVar reports whether v (including any nested ValMakeClosure or
// CallIIFE body) references target as a variable or struct field.
func ValueMentionsVar(v *Value, target *types.Var) bool {
	if v == nil || target == nil {
		return false
	}
	return valueMentionsMatch(v, func(cand *types.Var) bool { return cand == target })
}

// ValueMentionsVars reports whether v (including any nested ValMakeClosure or
// CallIIFE body) references any variable or struct field in targets.
func ValueMentionsVars(v *Value, targets map[*types.Var]bool) bool {
	if v == nil || len(targets) == 0 {
		return false
	}
	return valueMentionsMatch(v, func(cand *types.Var) bool { return targets[cand] })
}

// OpMentionsVars reports whether op (including any RangeBody or nested closure/IIFE)
// references or defines any variable or struct field in targets.
func OpMentionsVars(op *Op, targets map[*types.Var]bool) bool {
	if op == nil || len(targets) == 0 {
		return false
	}
	return opMentionsMatch(op, func(cand *types.Var) bool { return targets[cand] })
}

// BodyMentionsVars reports whether any operation in b (including nested
// RangeBody, ValMakeClosure, and CallIIFE bodies) references or defines any
// variable or struct field in targets.
func BodyMentionsVars(b *Body, targets map[*types.Var]bool) bool {
	if b == nil || len(targets) == 0 {
		return false
	}
	return bodyMentionsMatch(b, func(cand *types.Var) bool { return targets[cand] })
}

// BodyMentionsVar reports whether any operation in b references or defines target.
func BodyMentionsVar(b *Body, target *types.Var) bool {
	if b == nil || target == nil {
		return false
	}
	return bodyMentionsMatch(b, func(cand *types.Var) bool { return cand == target })
}

// ForEachNestedOp visits every operation in curBody and recursively descends
// into nested ValMakeClosure, CallIIFE, and RangeBody bodies, passing the
// enclosing *types.Func (for top-level FuncDecls), *ast.FuncLit (for closures
// and IIFEs), and enclosing declaration/closure *Body, stopping early when
// visit returns false.
func ForEachNestedOp(
	fn *types.Func,
	fl *ast.FuncLit,
	declBody *Body,
	curBody *Body,
	visit func(enclFn *types.Func, enclLit *ast.FuncLit, enclDeclBody *Body, op *Op) bool,
) bool {
	if curBody == nil || visit == nil {
		return true
	}
	if declBody == nil {
		declBody = curBody
	}
	for i := range curBody.Ops {
		op := &curBody.Ops[i]
		if !visit(fn, fl, declBody, op) {
			return false
		}
		stop := false
		op.ForEachValue(func(root *Value) bool {
			root.WalkValues(func(v *Value) bool {
				if stop || v == nil {
					return false
				}
				switch v.Kind {
				case ValMakeClosure:
					if v.Closure != nil && !ForEachNestedOp(nil, v.Lit, v.Closure, v.Closure, visit) {
						stop = true
						return false
					}
				case ValCall:
					if v.CallKind == CallIIFE && v.IIFE != nil {
						var iifeLit *ast.FuncLit
						if v.CallAST != nil {
							iifeLit, _ = syntaxutil.UnparenExpr(v.CallAST.Fun).(*ast.FuncLit)
						}
						if !ForEachNestedOp(nil, iifeLit, v.IIFE, v.IIFE, visit) {
							stop = true
							return false
						}
					}
				}
				return true
			})
			return !stop
		})
		if stop {
			return false
		}
		if op.Kind == OpAssign && op.AssignKind == AssignRange && op.RangeBody != nil {
			if !ForEachNestedOp(fn, fl, declBody, op.RangeBody, visit) {
				return false
			}
		}
	}
	return true
}

// ForEachOp visits every operation across all lowered FuncDecls and GenDecls in
// c (descending into closures, IIFEs, and range loops via ForEachNestedOp),
// stopping early when visit returns false.
func (c *PkgCache) ForEachOp(
	visit func(enclFn *types.Func, enclLit *ast.FuncLit, enclDeclBody *Body, op *Op) bool,
) bool {
	if c == nil || c.Info == nil || visit == nil {
		return true
	}
	for _, fd := range c.FuncDecls {
		if fd == nil || fd.Body == nil {
			continue
		}
		var fn *types.Func
		if fd.Name != nil {
			fn, _ = c.Info.Defs[fd.Name].(*types.Func)
		}
		b := c.FuncBody(fd)
		if !ForEachNestedOp(fn, nil, b, b, visit) {
			return false
		}
	}
	for _, gd := range c.GenDecls {
		if gd == nil {
			continue
		}
		b := c.Body(gd)
		if !ForEachNestedOp(nil, nil, b, b, visit) {
			return false
		}
	}
	return true
}
