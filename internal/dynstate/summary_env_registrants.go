package dynstate

import (
	"go/ast"
	"go/types"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/flowir"
	"github.com/greatliontech/gofresh/internal/refconfine"
	"github.com/greatliontech/gofresh/internal/syntaxutil"
)

// fieldRegMark is one registered-population disposition for a func-signature
// struct field a carrier can hand out: class 'd' defers the field position to a
// parameter's leak-free fact, class 'p' poisons it. A poison with field ""
// covers the whole population, idx -1 every index.
type fieldRegMark struct {
	class byte
	field string
	idx   int
	param syntaxutil.ParamKey
}

// classifyFieldRegistrantsValue derives the registered-population marks of one
// admitted registration store over lowered flowir places and values.
func classifyFieldRegistrantsValue(
	audited bool,
	p *packages.Package,
	fc *pkgFlowCache,
	dst flowir.Place,
	hasDst bool,
	rhs *flowir.Value,
	emit func(fieldRegMark),
) {
	if hasDst && len(dst.Projs) > 0 {
		last := dst.Projs[len(dst.Projs)-1]
		if last.Kind == flowir.ProjField && last.Field != nil && last.Selection != nil && last.Type != nil {
			if _, isSig := types.Unalias(last.Type).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantFlowValue(audited, p, fc, last.Field.Name(), rhs, emit)
				return
			}
		}
	}
	classifyRegistrantFlowValue(audited, p, fc, rhs, emit)
}

func classifyRegistrantFlowValue(audited bool, p *packages.Package, fc *pkgFlowCache, v *flowir.Value, emit func(fieldRegMark)) {
	if v == nil || v.IsTypeExpr {
		return
	}
	switch v.Kind {
	case flowir.ValScalarLitOrConst:
		return
	case flowir.ValAllocFresh:
		switch v.AllocKind {
		case flowir.AllocCompositeLit:
			classifyRegistrantCompositeValue(audited, p, fc, v, emit)
			return
		case flowir.AllocMake, flowir.AllocBuiltinNewType:
			return
		case flowir.AllocBuiltinNewExpr:
			for _, arg := range v.Args {
				classifyRegistrantFlowValue(audited, p, fc, arg, emit)
			}
			return
		}
	case flowir.ValMakeClosure:
		classifyLiteralRegistrant(audited, p, fc, syntaxutil.ElemPositionField, v.Lit, emit)
		return
	case flowir.ValConvert:
		if !v.IsTypeAssert && v.Arg != nil && !syntaxutil.IsUnsafePointerType(v.Arg.Type) {
			classifyRegistrantFlowValue(audited, p, fc, v.Arg, emit)
			return
		}
	case flowir.ValCall:
		if v.IsMethodExprCall && v.Recv != nil {
			classifyRegistrantFlowValue(audited, p, fc, v.Recv, emit)
		}
		for _, arg := range v.Args {
			classifyRegistrantFlowValue(audited, p, fc, arg, emit)
		}
		return
	case flowir.ValPlace:
		if v.IsNil || v.IsConst || v.Place.Root == flowir.RootConstOrNil {
			return
		}
		if v.Place.Root == flowir.RootFunc && !v.Place.IsMethodExpr && len(v.Place.Projs) == 0 && v.Place.Func != nil {
			classifyFieldRegistrantFlowValue(audited, p, fc, syntaxutil.ElemPositionField, v, emit)
			return
		}
	}
	if refconfine.TypeCarriesSignature(v.Type) {
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

func classifyRegistrantCompositeValue(audited bool, p *packages.Package, fc *pkgFlowCache, litVal *flowir.Value, emit func(fieldRegMark)) {
	if litVal == nil || litVal.ElemType == nil {
		emit(fieldRegMark{class: 'p', idx: -1})
		return
	}
	switch syntaxutil.UnderlyingType(litVal.ElemType).(type) {
	case *types.Struct:
		for i := range litVal.CompositeElts {
			elt := &litVal.CompositeElts[i]
			if elt.Field == nil {
				emit(fieldRegMark{class: 'p', idx: -1})
				continue
			}
			if _, isSig := types.Unalias(elt.Field.Type()).Underlying().(*types.Signature); isSig {
				classifyFieldRegistrantFlowValue(audited, p, fc, elt.Field.Name(), elt.Value, emit)
				continue
			}
			classifyRegistrantFlowValue(audited, p, fc, elt.Value, emit)
		}
	case *types.Map:
		for i := range litVal.CompositeElts {
			elt := &litVal.CompositeElts[i]
			if elt.MapKey != nil {
				classifyRegistrantFlowValue(audited, p, fc, elt.MapKey, emit)
			}
			if elt.Value != nil {
				classifyRegistrantFlowValue(audited, p, fc, elt.Value, emit)
			}
		}
	case *types.Slice, *types.Array:
		for i := range litVal.CompositeElts {
			elt := &litVal.CompositeElts[i]
			if elt.Value != nil {
				classifyRegistrantFlowValue(audited, p, fc, elt.Value, emit)
			}
		}
	default:
		emit(fieldRegMark{class: 'p', idx: -1})
	}
}

func classifyFieldRegistrantFlowValue(audited bool, p *packages.Package, fc *pkgFlowCache, field string, v *flowir.Value, emit func(fieldRegMark)) {
	deferNamed := func(fn *types.Func) bool {
		if fn == nil || fn.Pkg() == nil {
			return false
		}
		fn = fn.Origin()
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Recv() != nil {
			return false
		}
		fk := syntaxutil.FuncKey{Pkg: fn.Pkg().Path(), Name: fn.Name()}
		for idx := 0; idx < sig.Params().Len(); idx++ {
			emit(fieldRegMark{class: 'd', field: field, idx: idx, param: syntaxutil.ParamKey{Func: fk, Index: idx}})
		}
		return true
	}
	if v != nil && !v.IsTypeExpr {
		switch v.Kind {
		case flowir.ValScalarLitOrConst:
			if v.IsNil {
				return
			}
		case flowir.ValMakeClosure:
			classifyLiteralRegistrant(audited, p, fc, field, v.Lit, emit)
			return
		case flowir.ValPlace:
			if v.IsNil {
				return
			}
			if v.Place.Root == flowir.RootFunc && !v.Place.IsMethodExpr && len(v.Place.Projs) == 0 && v.Place.Func != nil && deferNamed(v.Place.Func) {
				return
			}
		}
	}
	emit(fieldRegMark{class: 'p', field: field, idx: -1})
}

func classifyLiteralRegistrant(audited bool, p *packages.Package, fc *pkgFlowCache, field string, lit *ast.FuncLit, emit func(fieldRegMark)) {
	if lit == nil || lit.Type == nil || lit.Body == nil {
		emit(fieldRegMark{class: 'p', field: field, idx: -1})
		return
	}
	idx := 0
	if lit.Type.Params != nil {
		for _, group := range lit.Type.Params.List {
			names := group.Names
			if len(names) == 0 {
				idx++
				continue
			}
			for _, name := range names {
				if name.Name == "_" {
					idx++
					continue
				}
				obj := p.TypesInfo.Defs[name]
				if obj == nil {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
					idx++
					continue
				}
				wants := map[syntaxutil.ParamKey]bool{}
				if boundValueLeakFreeJudged(audited, p, fc, map[types.Object]bool{obj: true}, lit.Body, wants, nil, nil, nil, nil) {
					for want := range wants {
						emit(fieldRegMark{class: 'd', field: field, idx: idx, param: want})
					}
				} else {
					emit(fieldRegMark{class: 'p', field: field, idx: idx})
				}
				idx++
			}
		}
	}
}
