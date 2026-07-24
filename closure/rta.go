// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is adapted from golang.org/x/tools/go/callgraph/rta v0.46.0.
// It preserves RTA's reachability semantics while attributing every fact to
// the subjects that discovered it. Call graphs are intentionally omitted.
package closure

import (
	"context"
	"fmt"
	"go/types"
	"hash/crc32"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/types/typeutil"
)

type attributedRTAResult struct {
	Reachable map[*ssa.Function]uint64
	Resolved  map[ssa.CallInstruction]uint64
	Targets   map[ssa.CallInstruction]map[*ssa.Function]uint64
}

// attributedRTA is the working state of RTA. Every mask is bounded to one
// batch of at most 64 subjects, so the state can be discarded between batches.
type attributedRTA struct {
	result *attributedRTAResult
	prog   *ssa.Program

	reflectValueCall *ssa.Function

	worklist []*ssa.Function
	pending  map[*ssa.Function]uint64
	queued   map[*ssa.Function]bool

	// Signature -> map[function]subject mask.
	addrTakenFuncsBySig typeutil.Map
	// Signature -> map[dynamic call site]subject mask.
	dynCallSites typeutil.Map
	// Interface -> map[invoke site]subject mask.
	invokeSites typeutil.Map

	concreteTypes  typeutil.Map
	interfaceTypes typeutil.Map
	runtimeTypes   typeutil.Map // type -> subject mask
}

func (r *attributedRTA) addResolvedTarget(site ssa.CallInstruction, target *ssa.Function, masks uint64) {
	if site == nil || target == nil || masks == 0 {
		return
	}
	r.result.Resolved[site] |= masks
	targets := r.result.Targets[site]
	if targets == nil {
		targets = make(map[*ssa.Function]uint64)
		r.result.Targets[site] = targets
	}
	targets[target] |= masks
}

type attributedConcreteTypeInfo struct {
	C          types.Type
	fprint     uint64
	masks      uint64
	implements []*types.Interface
}

type attributedInterfaceTypeInfo struct {
	I               *types.Interface
	fprint          uint64
	implementations []types.Type
}

func (r *attributedRTA) addReachable(f *ssa.Function, masks uint64) {
	delta := masks &^ r.result.Reachable[f]
	if delta == 0 {
		return
	}
	r.result.Reachable[f] |= delta
	r.pending[f] |= delta
	if !r.queued[f] {
		r.queued[f] = true
		r.worklist = append(r.worklist, f)
	}
}

// visitAddrTakenFunc records each subject that reaches an address-taking use.
func (r *attributedRTA) visitAddrTakenFunc(f *ssa.Function, masks uint64) {
	S := f.Signature
	funcs, _ := r.addrTakenFuncsBySig.At(S).(map[*ssa.Function]uint64)
	if funcs == nil {
		funcs = make(map[*ssa.Function]uint64)
		r.addrTakenFuncsBySig.Set(S, funcs)
	}
	delta := masks &^ funcs[f]
	if delta == 0 {
		return
	}
	funcs[f] |= delta

	// A dynamic edge belongs only to subjects that reach both the function
	// value and the matching call site. Unioning either side would contaminate
	// independent analyses in the same batch.
	sites, _ := r.dynCallSites.At(S).(map[ssa.CallInstruction]uint64)
	for site, siteMasks := range sites {
		matched := delta & siteMasks
		r.addReachable(f, matched)
		if matched != 0 {
			r.addResolvedTarget(site, f, matched)
		}
	}

	// Upstream RTA treats the presence of reflect.Value.Call in the program as
	// sufficient to make every address-taken function reachable by reflection.
	if r.reflectValueCall != nil {
		r.addReachable(f, delta)
	}
}

func (r *attributedRTA) visitDynCall(site ssa.CallInstruction, masks uint64) {
	S := site.Common().Signature()
	sites, _ := r.dynCallSites.At(S).(map[ssa.CallInstruction]uint64)
	if sites == nil {
		sites = make(map[ssa.CallInstruction]uint64)
		r.dynCallSites.Set(S, sites)
	}
	delta := masks &^ sites[site]
	if delta == 0 {
		return
	}
	sites[site] |= delta

	funcs, _ := r.addrTakenFuncsBySig.At(S).(map[*ssa.Function]uint64)
	for f, functionMasks := range funcs {
		matched := delta & functionMasks
		r.addReachable(f, matched)
		if matched != 0 {
			r.addResolvedTarget(site, f, matched)
		}
	}
}

func (r *attributedRTA) addInvokeEdge(site ssa.CallInstruction, C types.Type, masks uint64) {
	if masks == 0 {
		return
	}
	imethod := site.Common().Method
	cmethod := r.prog.LookupMethod(C, imethod.Pkg(), imethod.Name())
	r.addReachable(cmethod, masks)
	if cmethod != nil {
		r.addResolvedTarget(site, cmethod, masks)
	}
}

func (r *attributedRTA) visitInvoke(site ssa.CallInstruction, masks uint64) {
	I := site.Common().Value.Type().Underlying().(*types.Interface)
	sites, _ := r.invokeSites.At(I).(map[ssa.CallInstruction]uint64)
	if sites == nil {
		sites = make(map[ssa.CallInstruction]uint64)
		r.invokeSites.Set(I, sites)
	}
	delta := masks &^ sites[site]
	if delta == 0 {
		return
	}
	sites[site] |= delta

	for _, C := range r.implementations(I) {
		cinfo := r.concreteTypes.At(C).(*attributedConcreteTypeInfo)
		// As with function calls, an invoke edge exists only in analyses that
		// reach both the concrete runtime type and this invoke site.
		r.addInvokeEdge(site, C, delta&cinfo.masks)
	}
}

func (r *attributedRTA) visitFunc(f *ssa.Function, masks uint64) {
	var space [32]*ssa.Value
	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			rands := instr.Operands(space[:0])
			switch instr := instr.(type) {
			case ssa.CallInstruction:
				call := instr.Common()
				if call.IsInvoke() {
					r.visitInvoke(instr, masks)
				} else if g := call.StaticCallee(); g != nil {
					// Static edges inherit exactly the caller's newly reached subjects.
					r.addReachable(g, masks)
				} else if _, ok := call.Value.(*ssa.Builtin); !ok {
					r.visitDynCall(instr, masks)
				}
				rands = rands[1:]
			case *ssa.MakeInterface:
				r.addRuntimeType(instr.X.Type(), masks, false)
			}
			for _, op := range rands {
				if g, ok := (*op).(*ssa.Function); ok {
					r.visitAddrTakenFunc(g, masks)
				}
			}
		}
	}
}

// analyzeAttributed performs RTA for up to 64 subjects at once. roots maps each
// root function to the subjects for which it is an independent-analysis root.
// The walk mirrors upstream RTA, whose internal assertions panic on shapes it
// cannot classify; the boundary converts any such panic into an error so an
// unsupported shape degrades to per-subject unavailable evidence in the
// embedding process — fail-closed, never a crash. The breadth is deliberate:
// a genuine regression panicking here degrades instead of crashing, and its
// detection signal is corpus-level "unsupported analysis shape" counts.
func analyzeAttributed(ctx context.Context, roots map[*ssa.Function]uint64) (result *attributedRTAResult, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result, err = nil, fmt.Errorf("closure: attributed reachability: unsupported analysis shape: %v", recovered)
		}
	}()
	if ctx == nil {
		return nil, fmt.Errorf("closure: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	if len(roots) == 0 {
		return nil, nil
	}
	var prog *ssa.Program
	for root := range roots {
		prog = root.Prog
		break
	}
	r := &attributedRTA{
		result: &attributedRTAResult{
			Reachable: make(map[*ssa.Function]uint64),
			Resolved:  make(map[ssa.CallInstruction]uint64),
			Targets:   make(map[ssa.CallInstruction]map[*ssa.Function]uint64),
		},
		prog:    prog,
		pending: make(map[*ssa.Function]uint64),
		queued:  make(map[*ssa.Function]bool),
	}

	if reflectPkg := prog.ImportedPackage("reflect"); reflectPkg != nil {
		reflectValue := reflectPkg.Members["Value"].(*ssa.Type)
		r.reflectValueCall = prog.LookupMethod(reflectValue.Object().Type(), reflectPkg.Pkg, "Call")
	}

	hasher := typeutil.MakeHasher()
	r.addrTakenFuncsBySig.SetHasher(hasher)
	r.dynCallSites.SetHasher(hasher)
	r.invokeSites.SetHasher(hasher)
	r.concreteTypes.SetHasher(hasher)
	r.interfaceTypes.SetHasher(hasher)
	r.runtimeTypes.SetHasher(hasher)

	for root, masks := range roots {
		r.addReachable(root, masks)
	}
	for len(r.worklist) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		var shadow []*ssa.Function
		shadow, r.worklist = r.worklist, shadow
		for _, f := range shadow {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
			}
			r.queued[f] = false
			masks := r.pending[f]
			delete(r.pending, f)
			r.visitFunc(f, masks)
		}
	}
	return r.result, nil
}

func (r *attributedRTA) interfaces(C types.Type) []*types.Interface {
	var cinfo *attributedConcreteTypeInfo
	if v := r.concreteTypes.At(C); v != nil {
		cinfo = v.(*attributedConcreteTypeInfo)
	} else {
		cinfo = &attributedConcreteTypeInfo{C: C, fprint: attributedFingerprint(r.prog.MethodSets.MethodSet(C))}
		r.concreteTypes.Set(C, cinfo)
		r.interfaceTypes.Iterate(func(I types.Type, v any) {
			iinfo := v.(*attributedInterfaceTypeInfo)
			if I := types.Unalias(I).(*types.Interface); attributedImplements(cinfo, iinfo) {
				iinfo.implementations = append(iinfo.implementations, C)
				cinfo.implements = append(cinfo.implements, I)
			}
		})
	}
	return cinfo.implements
}

func (r *attributedRTA) implementations(I *types.Interface) []types.Type {
	var iinfo *attributedInterfaceTypeInfo
	if v := r.interfaceTypes.At(I); v != nil {
		iinfo = v.(*attributedInterfaceTypeInfo)
	} else {
		iinfo = &attributedInterfaceTypeInfo{I: I, fprint: attributedFingerprint(r.prog.MethodSets.MethodSet(I))}
		r.interfaceTypes.Set(I, iinfo)
		r.concreteTypes.Iterate(func(C types.Type, v any) {
			cinfo := v.(*attributedConcreteTypeInfo)
			if attributedImplements(cinfo, iinfo) {
				cinfo.implements = append(cinfo.implements, I)
				iinfo.implementations = append(iinfo.implementations, C)
			}
		})
	}
	return iinfo.implementations
}

// addRuntimeType is adapted from needMethods in go/ssa/builder.go, matching
// upstream RTA's exported-method and recursive runtime-type behavior.
func (r *attributedRTA) addRuntimeType(T types.Type, masks uint64, skip bool) {
	T = types.Unalias(T)
	previous, _ := r.runtimeTypes.At(T).(uint64)
	delta := masks &^ previous
	if delta == 0 {
		return
	}
	r.runtimeTypes.Set(T, previous|delta)

	mset := r.prog.MethodSets.MethodSet(T)
	if _, ok := T.Underlying().(*types.Interface); !ok {
		for i, n := 0, mset.Len(); i < n; i++ {
			sel := mset.At(i)
			if sel.Obj().Exported() {
				r.addReachable(r.prog.MethodValue(sel), delta)
			}
		}

		r.interfaces(T)
		cinfo := r.concreteTypes.At(T).(*attributedConcreteTypeInfo)
		cinfo.masks |= delta
		for _, I := range cinfo.implements {
			sites, _ := r.invokeSites.At(I).(map[ssa.CallInstruction]uint64)
			for site, siteMasks := range sites {
				r.addInvokeEdge(site, T, delta&siteMasks)
			}
		}
	}

	var n *types.Named
	switch T := types.Unalias(T).(type) {
	case *types.Named:
		n = T
	case *types.Pointer:
		n, _ = types.Unalias(T.Elem()).(*types.Named)
	}
	if n != nil && n.Obj().Pkg() == nil {
		return
	}

	for method := range mset.Methods() {
		if method.Obj().Exported() {
			sig := method.Type().(*types.Signature)
			r.addRuntimeType(sig.Params(), delta, true)
			r.addRuntimeType(sig.Results(), delta, true)
		}
	}

	switch t := T.(type) {
	case *types.Alias:
		panic("unreachable")
	case *types.Basic, *types.Interface:
	case *types.Pointer:
		r.addRuntimeType(t.Elem(), delta, false)
	case *types.Slice:
		r.addRuntimeType(t.Elem(), delta, false)
	case *types.Chan:
		r.addRuntimeType(t.Elem(), delta, false)
	case *types.Map:
		r.addRuntimeType(t.Key(), delta, false)
		r.addRuntimeType(t.Elem(), delta, false)
	case *types.Signature:
		if t.Recv() != nil {
			panic(fmt.Sprintf("Signature %s has Recv %s", t, t.Recv()))
		}
		r.addRuntimeType(t.Params(), delta, true)
		r.addRuntimeType(t.Results(), delta, true)
	case *types.Named:
		r.addRuntimeType(types.NewPointer(T), delta, false)
		r.addRuntimeType(t.Underlying(), delta, true)
	case *types.Array:
		r.addRuntimeType(t.Elem(), delta, false)
	case *types.Struct:
		for i, n := 0, t.NumFields(); i < n; i++ {
			r.addRuntimeType(t.Field(i).Type(), delta, false)
		}
	case *types.Tuple:
		for i, n := 0, t.Len(); i < n; i++ {
			r.addRuntimeType(t.At(i).Type(), delta, false)
		}
	default:
		panic(T)
	}
	_ = skip // retained to mirror upstream's recursive accessibility traversal
}

func attributedFingerprint(mset *types.MethodSet) uint64 {
	var space [64]byte
	var mask uint64
	for method := range mset.Methods() {
		method := method.Obj()
		sig := method.Type().(*types.Signature)
		if sig.TypeParams() != nil {
			continue
		}
		sum := crc32.ChecksumIEEE(fmt.Appendf(space[:], "%s/%d/%d", method.Id(), sig.Params().Len(), sig.Results().Len()))
		mask |= 1 << (sum % 64)
	}
	return mask
}

func attributedImplements(cinfo *attributedConcreteTypeInfo, iinfo *attributedInterfaceTypeInfo) bool {
	return iinfo.fprint & ^cinfo.fprint == 0 && types.Implements(cinfo.C, iinfo.I)
}
