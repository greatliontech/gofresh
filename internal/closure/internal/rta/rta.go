// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is adapted from golang.org/x/tools/go/callgraph/rta v0.46.0,
// with the v0.50 runtime-type signature traversal and alias normalization.
// It preserves RTA's reachability semantics while attributing every fact to
// the subjects that discovered it. Call graphs are intentionally omitted.
package rta

import (
	"context"
	"fmt"
	"go/types"
	"hash/crc32"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/types/typeutil"
)

type Result struct {
	Reachable           map[*ssa.Function]uint64
	Resolved            map[ssa.CallInstruction]uint64
	Targets             map[ssa.CallInstruction]map[*ssa.Function]uint64
	HarnessStdReachable map[*ssa.Function]uint64
	HarnessStdTargets   map[ssa.CallInstruction]map[*ssa.Function]uint64
}

type reflectWriteKind uint8

const (
	reflectWriteSet reflectWriteKind = iota
	reflectWriteMap
	reflectWriteSlice
	reflectWriteChan
	numReflectWriteKinds
)

type closedMethodCallInfo struct {
	sigs []*types.Signature
	ok   bool
}

// attributedRTA is the working state of RTA. Every mask is bounded to one
// batch of at most 64 subjects, so the state can be discarded between batches.
type attributedRTA struct {
	result             *Result
	prog               *ssa.Program
	harnessPkg         string
	harnessOnlyTesting bool
	userPkgs           map[string]bool

	reflectValueCall         *ssa.Function
	reflectValueCallSlice    *ssa.Function
	reflectMethodFuncs       map[*ssa.Function]bool
	reflectSingleMethodFuncs map[*ssa.Function]bool
	reflectWriteFuncs        map[*ssa.Function]reflectWriteKind
	reflectMethodMasks       uint64
	reflectWriteMasks        [numReflectWriteKinds]uint64
	trampolineAsserts        map[*ssa.TypeAssert]bool
	closedMethodCalls        map[*ssa.Call]closedMethodCallInfo
	// current is the function whose body the walk is visiting - the
	// recover boundary's provenance for unsupported-shape panics.
	current *ssa.Function

	worklist []*ssa.Function
	pending  map[*ssa.Function]uint64
	queued   map[*ssa.Function]bool

	harnessWorklist []*ssa.Function
	harnessPending  map[*ssa.Function]uint64
	harnessQueued   map[*ssa.Function]bool

	// Signature -> map[function]subject mask.
	addrTakenFuncsBySig        typeutil.Map
	harnessAddrTakenFuncsBySig typeutil.Map
	// Signature -> map[dynamic call site]subject mask.
	dynCallSites        typeutil.Map
	harnessDynCallSites typeutil.Map
	// Interface -> map[invoke site]subject mask.
	invokeSites        typeutil.Map
	harnessInvokeSites typeutil.Map
	// Receiverless signature -> subject mask of closed v.Method(i).Interface().(S) assertions.
	directReflectMethodSigs typeutil.Map
	// Receiverless signature -> subject mask of type-asserted function signatures.
	reflectAssertSigs typeutil.Map
	// Per-kind receiverless signature -> subject mask of reflect-writable container function slots.
	reflectWriteSigs [numReflectWriteKinds]typeutil.Map
	// Receiverless signature -> map[method function]subject mask of runtime-type methods.
	runtimeMethodFuncs typeutil.Map

	concreteTypes         typeutil.Map
	interfaceTypes        typeutil.Map
	runtimeTypes          typeutil.Map // accessible runtime type -> subject mask
	traversedTypes        typeutil.Map // structurally descended type -> subject mask
	harnessRuntimeTypes   typeutil.Map // harness-internal stdlib runtime type -> subject mask
	harnessTraversedTypes typeutil.Map // harness-internal stdlib descended type -> subject mask
	writableTypes         typeutil.Map // reflect-writable container traversal -> subject mask
	embedROTypes          typeutil.Map // embedded-unexported-field traversal -> subject mask
	typeParamSeen         map[types.Type]bool
}

func isStdImportPathShape(path string) bool {
	if path == "" || path == "C" {
		return false
	}
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	return !strings.Contains(first, ".")
}

func (r *attributedRTA) isHarnessInternalStdPkg(pkgPath string) bool {
	return r.harnessPkg != "" &&
		pkgPath != "" &&
		pkgPath != r.harnessPkg &&
		(pkgPath != "testing" || r.harnessOnlyTesting) &&
		pkgPath != "context" &&
		!r.userPkgs[pkgPath] &&
		isStdImportPathShape(pkgPath)
}

func (r *attributedRTA) isPureHarnessInternalStdType(t types.Type) bool {
	if r.harnessPkg == "" || t == nil {
		return false
	}
	top := types.Unalias(t)
	for {
		ptr, ok := top.(*types.Pointer)
		if !ok {
			break
		}
		top = types.Unalias(ptr.Elem())
	}
	if topNamed, ok := top.(*types.Named); ok {
		if obj := topNamed.Obj(); obj != nil && obj.Pkg() != nil {
			p := obj.Pkg().Path()
			if p == "context" || p == "errors" || (p == "os" && obj.Name() == "File") || (p == "io" && obj.Name() == "discard") {
				return false
			}
		}
	}
	seen := make(map[types.Type]bool)
	sawHarnessStdNamed := false
	var walk func(types.Type) bool
	walk = func(cur types.Type) bool {
		if cur == nil {
			return true
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return true
		}
		seen[cur] = true
		switch tt := cur.(type) {
		case *types.Named:
			if obj := tt.Obj(); obj != nil && obj.Pkg() != nil {
				p := obj.Pkg().Path()
				if !isStdImportPathShape(p) || r.userPkgs[p] || p == r.harnessPkg || p == "testing" {
					return false
				}
				if r.isHarnessInternalStdPkg(p) {
					sawHarnessStdNamed = true
				}
			}
			if args := tt.TypeArgs(); args != nil {
				for i, n := 0, args.Len(); i < n; i++ {
					if !walk(args.At(i)) {
						return false
					}
				}
			}
			return walk(tt.Underlying())
		case *types.Pointer:
			return walk(tt.Elem())
		case *types.Slice:
			return walk(tt.Elem())
		case *types.Array:
			return walk(tt.Elem())
		case *types.Map:
			return walk(tt.Key()) && walk(tt.Elem())
		case *types.Chan:
			return walk(tt.Elem())
		case *types.Struct:
			for i, n := 0, tt.NumFields(); i < n; i++ {
				if !walk(tt.Field(i).Type()) {
					return false
				}
			}
			return true
		case *types.Tuple:
			for i, n := 0, tt.Len(); i < n; i++ {
				if !walk(tt.At(i).Type()) {
					return false
				}
			}
			return true
		case *types.Signature:
			return walk(tt.Params()) && walk(tt.Results())
		case *types.Interface:
			for i, n := 0, tt.NumMethods(); i < n; i++ {
				if !walk(tt.Method(i).Type()) {
					return false
				}
			}
			return true
		default:
			return true
		}
	}
	return walk(t) && sawHarnessStdNamed
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

func (r *attributedRTA) addHarnessStdResolvedTarget(site ssa.CallInstruction, target *ssa.Function, masks uint64, markResolved bool) {
	if site == nil || target == nil || masks == 0 {
		return
	}
	if markResolved {
		r.result.Resolved[site] |= masks
	}
	targets := r.result.HarnessStdTargets[site]
	if targets == nil {
		targets = make(map[*ssa.Function]uint64)
		r.result.HarnessStdTargets[site] = targets
	}
	targets[target] |= masks
}

type attributedConcreteTypeInfo struct {
	C               types.Type
	fprint          uint64
	masks           uint64
	harnessStdMasks uint64
	implements      []*types.Interface
}

type attributedInterfaceTypeInfo struct {
	I               *types.Interface
	fprint          uint64
	implementations []types.Type
}

func (r *attributedRTA) addReachable(f *ssa.Function, masks uint64) {
	if f == nil {
		// MethodValue returns nil for interface and parameterized
		// receivers and LookupMethod can miss: a nil enqueued here
		// crashes the walk into an unsupported-shape refusal - the
		// class this chunk removes (the chunk-132 review's H2).
		return
	}
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

func (r *attributedRTA) addHarnessStdReachable(f *ssa.Function, masks uint64) {
	if f == nil || masks == 0 {
		return
	}
	if !r.isHarnessInternalStdPkg(ssaFuncPkgPath(f)) {
		r.addReachable(f, masks)
		return
	}
	delta := masks &^ r.result.HarnessStdReachable[f]
	if delta == 0 {
		return
	}
	r.result.HarnessStdReachable[f] |= delta
	r.harnessPending[f] |= delta
	if !r.harnessQueued[f] {
		r.harnessQueued[f] = true
		r.harnessWorklist = append(r.harnessWorklist, f)
	}
}

// visitAddrTakenFunc records each subject that reaches an address-taking use.
func (r *attributedRTA) visitAddrTakenFunc(f *ssa.Function, masks uint64) {
	r.visitAddrTakenFuncWithSig(f, f.Signature, masks)
}

func (r *attributedRTA) visitAddrTakenFuncWithSig(f *ssa.Function, S *types.Signature, masks uint64) {
	if f == nil || S == nil || masks == 0 {
		return
	}
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
			callerPkg := ssaFuncPkgPath(site.Parent())
			if callerPkg != "reflect" && callerPkg != "testing" {
				r.noteReflectCalleeUse(f, matched)
			}
		}
	}
	if r.harnessPkg != "" {
		hSites, _ := r.harnessDynCallSites.At(S).(map[ssa.CallInstruction]uint64)
		for site, siteMasks := range hSites {
			matched := delta & siteMasks
			if matched != 0 {
				r.addHarnessStdReachable(f, matched)
				r.addHarnessStdResolvedTarget(site, f, matched, false)
			}
		}
	}

	// Upstream RTA treats the presence of reflect.Value.Call or CallSlice in
	// the program as sufficient to make every address-taken function reachable
	// by reflection.
	if r.reflectValueCall != nil || r.reflectValueCallSlice != nil {
		r.addReachable(f, delta)
	}
}

func (r *attributedRTA) visitHarnessStdAddrTakenFunc(f *ssa.Function, masks uint64) {
	if f == nil || f.Signature == nil || masks == 0 {
		return
	}
	if !r.isHarnessInternalStdPkg(ssaFuncPkgPath(f)) {
		r.visitAddrTakenFunc(f, masks)
		return
	}
	S := f.Signature
	funcs, _ := r.harnessAddrTakenFuncsBySig.At(S).(map[*ssa.Function]uint64)
	if funcs == nil {
		funcs = make(map[*ssa.Function]uint64)
		r.harnessAddrTakenFuncsBySig.Set(S, funcs)
	}
	delta := masks &^ funcs[f]
	if delta == 0 {
		return
	}
	funcs[f] |= delta

	hSites, _ := r.harnessDynCallSites.At(S).(map[ssa.CallInstruction]uint64)
	for site, siteMasks := range hSites {
		if matched := delta & siteMasks; matched != 0 {
			r.addHarnessStdReachable(f, matched)
			r.addHarnessStdResolvedTarget(site, f, matched, false)
		}
	}
	sites, _ := r.dynCallSites.At(S).(map[ssa.CallInstruction]uint64)
	for site, siteMasks := range sites {
		if ssaFuncPkgPath(site.Parent()) != r.harnessPkg {
			continue
		}
		if matched := delta & siteMasks; matched != 0 {
			r.addHarnessStdReachable(f, matched)
			r.addHarnessStdResolvedTarget(site, f, matched, true)
		}
	}
	if r.reflectValueCall != nil || r.reflectValueCallSlice != nil {
		r.addHarnessStdReachable(f, delta)
	}
}

func (r *attributedRTA) activeReflectSigMask(S *types.Signature) uint64 {
	direct, _ := r.directReflectMethodSigs.At(S).(uint64)
	if r.reflectMethodMasks == 0 {
		return direct
	}
	unboxOrWrite, _ := r.reflectAssertSigs.At(S).(uint64)
	for k := range numReflectWriteKinds {
		if m := r.reflectWriteMasks[k]; m != 0 {
			sigMasks, _ := r.reflectWriteSigs[k].At(S).(uint64)
			unboxOrWrite |= m & sigMasks
		}
	}
	return direct | (r.reflectMethodMasks & unboxOrWrite)
}

func (r *attributedRTA) flushReflectMethodsForSig(S *types.Signature) {
	active := r.activeReflectSigMask(S)
	if active == 0 {
		return
	}
	methods, _ := r.runtimeMethodFuncs.At(S).(map[*ssa.Function]uint64)
	for fn, fnMasks := range methods {
		if matched := active & fnMasks; matched != 0 {
			r.visitAddrTakenFuncWithSig(fn, S, matched)
		}
	}
}

func (r *attributedRTA) addReflectMethodMasks(masks uint64) {
	delta := masks &^ r.reflectMethodMasks
	if delta == 0 {
		return
	}
	r.reflectMethodMasks |= delta
	r.runtimeMethodFuncs.Iterate(func(key types.Type, _ any) {
		r.flushReflectMethodsForSig(key.(*types.Signature))
	})
}

func (r *attributedRTA) addDirectReflectMethodSig(S *types.Signature, masks uint64) {
	if S == nil || S.Recv() != nil || S.TypeParams() != nil || masks == 0 {
		return
	}
	clear(r.typeParamSeen)
	if ContainsTypeParam(S, r.typeParamSeen) {
		return
	}
	prev, _ := r.directReflectMethodSigs.At(S).(uint64)
	delta := masks &^ prev
	if delta == 0 {
		return
	}
	r.directReflectMethodSigs.Set(S, prev|delta)
	r.flushReflectMethodsForSig(S)
}

func (r *attributedRTA) addReflectWriteMasks(kind reflectWriteKind, masks uint64) {
	delta := masks &^ r.reflectWriteMasks[kind]
	if delta == 0 {
		return
	}
	r.reflectWriteMasks[kind] |= delta
	if r.reflectMethodMasks == 0 {
		return
	}
	r.reflectWriteSigs[kind].Iterate(func(key types.Type, _ any) {
		r.flushReflectMethodsForSig(key.(*types.Signature))
	})
}

func (r *attributedRTA) addReflectAssertSig(S *types.Signature, masks uint64) {
	if S == nil || S.Recv() != nil || S.TypeParams() != nil || masks == 0 {
		return
	}
	clear(r.typeParamSeen)
	if ContainsTypeParam(S, r.typeParamSeen) {
		return
	}
	prev, _ := r.reflectAssertSigs.At(S).(uint64)
	delta := masks &^ prev
	if delta == 0 {
		return
	}
	r.reflectAssertSigs.Set(S, prev|delta)
	r.flushReflectMethodsForSig(S)
}

func (r *attributedRTA) addReflectWriteSig(kind reflectWriteKind, S *types.Signature, masks uint64) {
	if S == nil || S.Recv() != nil || S.TypeParams() != nil || masks == 0 {
		return
	}
	clear(r.typeParamSeen)
	if ContainsTypeParam(S, r.typeParamSeen) {
		return
	}
	prev, _ := r.reflectWriteSigs[kind].At(S).(uint64)
	delta := masks &^ prev
	if delta == 0 {
		return
	}
	r.reflectWriteSigs[kind].Set(S, prev|delta)
	r.flushReflectMethodsForSig(S)
}

func (r *attributedRTA) addRuntimeMethodFunc(f *ssa.Function, masks uint64) {
	if f == nil || f.Signature == nil || masks == 0 {
		return
	}
	S := types.NewSignatureType(nil, nil, nil, f.Signature.Params(), f.Signature.Results(), f.Signature.Variadic())
	methods, _ := r.runtimeMethodFuncs.At(S).(map[*ssa.Function]uint64)
	if methods == nil {
		methods = make(map[*ssa.Function]uint64)
		r.runtimeMethodFuncs.Set(S, methods)
	}
	delta := masks &^ methods[f]
	if delta == 0 {
		return
	}
	fnMasks := methods[f] | delta
	methods[f] = fnMasks
	if matched := r.activeReflectSigMask(S) & fnMasks; matched != 0 {
		r.visitAddrTakenFuncWithSig(f, S, matched)
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

	callerPkg := ssaFuncPkgPath(site.Parent())
	noteCaller := callerPkg != "reflect" && callerPkg != "testing"
	funcs, _ := r.addrTakenFuncsBySig.At(S).(map[*ssa.Function]uint64)
	for f, functionMasks := range funcs {
		matched := delta & functionMasks
		r.addReachable(f, matched)
		if matched != 0 {
			r.addResolvedTarget(site, f, matched)
			if noteCaller {
				r.noteReflectCalleeUse(f, matched)
			}
		}
	}
	if r.harnessPkg != "" && callerPkg == r.harnessPkg {
		hFuncs, _ := r.harnessAddrTakenFuncsBySig.At(S).(map[*ssa.Function]uint64)
		for f, functionMasks := range hFuncs {
			if matched := delta & functionMasks; matched != 0 {
				r.addHarnessStdReachable(f, matched)
				r.addHarnessStdResolvedTarget(site, f, matched, true)
			}
		}
	}
}

func (r *attributedRTA) visitHarnessStdDynCall(site ssa.CallInstruction, masks uint64) {
	S := site.Common().Signature()
	sites, _ := r.harnessDynCallSites.At(S).(map[ssa.CallInstruction]uint64)
	if sites == nil {
		sites = make(map[ssa.CallInstruction]uint64)
		r.harnessDynCallSites.Set(S, sites)
	}
	delta := masks &^ sites[site]
	if delta == 0 {
		return
	}
	sites[site] |= delta

	for _, table := range []*typeutil.Map{&r.addrTakenFuncsBySig, &r.harnessAddrTakenFuncsBySig} {
		funcs, _ := table.At(S).(map[*ssa.Function]uint64)
		for f, functionMasks := range funcs {
			if matched := delta & functionMasks; matched != 0 {
				r.addHarnessStdReachable(f, matched)
				r.addHarnessStdResolvedTarget(site, f, matched, false)
			}
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
		callerPkg := ssaFuncPkgPath(site.Parent())
		if callerPkg != "reflect" && callerPkg != "testing" {
			r.noteReflectCalleeUse(cmethod, masks)
		}
	}
}

func (r *attributedRTA) addHarnessStdInvokeEdge(site ssa.CallInstruction, C types.Type, masks uint64, markResolved bool) {
	if masks == 0 {
		return
	}
	imethod := site.Common().Method
	cmethod := r.prog.LookupMethod(C, imethod.Pkg(), imethod.Name())
	r.addHarnessStdReachable(cmethod, masks)
	if cmethod != nil {
		r.addHarnessStdResolvedTarget(site, cmethod, masks, markResolved)
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

	callerIsHarness := r.harnessPkg != "" && ssaFuncPkgPath(site.Parent()) == r.harnessPkg
	for _, C := range r.implementations(I) {
		cinfo := r.concreteTypes.At(C).(*attributedConcreteTypeInfo)
		// As with function calls, an invoke edge exists only in analyses that
		// reach both the concrete runtime type and this invoke site.
		outerMatch := delta & cinfo.masks
		r.addInvokeEdge(site, C, outerMatch)
		if callerIsHarness {
			r.addHarnessStdInvokeEdge(site, C, (delta&cinfo.harnessStdMasks)&^outerMatch, true)
		}
	}
}

func (r *attributedRTA) visitHarnessStdInvoke(site ssa.CallInstruction, masks uint64) {
	I := site.Common().Value.Type().Underlying().(*types.Interface)
	sites, _ := r.harnessInvokeSites.At(I).(map[ssa.CallInstruction]uint64)
	if sites == nil {
		sites = make(map[ssa.CallInstruction]uint64)
		r.harnessInvokeSites.Set(I, sites)
	}
	delta := masks &^ sites[site]
	if delta == 0 {
		return
	}
	sites[site] |= delta

	for _, C := range r.implementations(I) {
		cinfo := r.concreteTypes.At(C).(*attributedConcreteTypeInfo)
		r.addHarnessStdInvokeEdge(site, C, delta&(cinfo.masks|cinfo.harnessStdMasks), false)
	}
}

func ssaFuncPkgPath(fn *ssa.Function) string {
	for depth := 0; fn != nil && depth < 8; depth++ {
		for p := fn; p != nil; p = p.Parent() {
			if p.Pkg != nil && p.Pkg.Pkg != nil {
				return p.Pkg.Pkg.Path()
			}
			if obj := p.Object(); obj != nil && obj.Pkg() != nil {
				return obj.Pkg().Path()
			}
			if orig := p.Origin(); orig != nil {
				if orig.Pkg != nil && orig.Pkg.Pkg != nil {
					return orig.Pkg.Pkg.Path()
				}
				if obj := orig.Object(); obj != nil && obj.Pkg() != nil {
					return obj.Pkg().Path()
				}
			}
			if p.Signature != nil && p.Signature.Recv() != nil {
				rt := types.Unalias(p.Signature.Recv().Type())
				if ptr, ok := rt.(*types.Pointer); ok {
					rt = types.Unalias(ptr.Elem())
				}
				if named, ok := rt.(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil {
					return named.Obj().Pkg().Path()
				}
			}
		}
		if !strings.HasPrefix(fn.Synthetic, "bound ") && !strings.HasPrefix(fn.Synthetic, "thunk ") && !strings.HasPrefix(fn.Synthetic, "wrapper ") {
			return ""
		}
		var next *ssa.Function
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if call, ok := instr.(ssa.CallInstruction); ok {
					if call.Common().IsInvoke() {
						if m := call.Common().Method; m != nil && m.Pkg() != nil {
							return m.Pkg().Path()
						}
						return ""
					}
					if callee := call.Common().StaticCallee(); callee != nil && callee != fn {
						next = callee
						break
					}
				}
			}
			if next != nil {
				break
			}
		}
		fn = next
	}
	return ""
}

func unwrapWrapperCallee(f *ssa.Function) *ssa.Function {
	for range 4 {
		if f == nil || (!strings.HasPrefix(f.Synthetic, "bound ") && !strings.HasPrefix(f.Synthetic, "thunk ") && !strings.HasPrefix(f.Synthetic, "wrapper ")) {
			return f
		}
		var next *ssa.Function
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				if call, ok := instr.(ssa.CallInstruction); ok {
					if callee := call.Common().StaticCallee(); callee != nil {
						next = callee
						break
					}
				}
			}
			if next != nil {
				break
			}
		}
		if next == nil || next == f {
			return f
		}
		f = next
	}
	return f
}

func (r *attributedRTA) noteReflectCalleeUse(g *ssa.Function, masks uint64) {
	base := unwrapWrapperCallee(g)
	if base == nil {
		return
	}
	if r.reflectMethodFuncs[base] {
		r.addReflectMethodMasks(masks)
	}
	if kind, ok := r.reflectWriteFuncs[base]; ok {
		r.addReflectWriteMasks(kind, masks)
	}
	if orig := base.Origin(); orig != nil && orig.Name() == "TypeAssert" && ssaFuncPkgPath(orig) == "reflect" && len(base.TypeArgs()) == 1 {
		targ := base.TypeArgs()[0]
		if sig, ok := types.Unalias(targ).Underlying().(*types.Signature); ok {
			r.addReflectAssertSig(sig, masks)
		} else if !types.IsInterface(types.Unalias(targ).Underlying()) {
			r.addWritableRuntimeType(targ, masks, false)
		}
	}
}

func (r *attributedRTA) noteReflectCallSite(callIns ssa.CallInstruction, g *ssa.Function, masks uint64) {
	if sc, isCall := callIns.(*ssa.Call); isCall {
		base := unwrapWrapperCallee(g)
		if base != nil && r.reflectSingleMethodFuncs[base] {
			if sigs, ok := r.closedMethodValueSigs(sc); ok {
				for _, sig := range sigs {
					r.addDirectReflectMethodSig(sig, masks)
				}
				return
			}
		}
	}
	r.noteReflectCalleeUse(g, masks)
}

// closedMethodValueSigs inspects the SSA referrer cone of a direct
// (reflect.Value).Method or MethodByName call. When the returned reflect.Value
// never escapes to containers, memory stores, returns, or unanalyzed calls —
// staying strictly inside consumer-only reflect.Value methods (such as IsValid,
// Type, or Call), intra-package non-variadic helpers, and direct Interface() /
// TypeAssert unboxings — it returns ok=true with the exact receiverless
// function signatures asserted from that call.
func (r *attributedRTA) closedMethodValueSigs(sc *ssa.Call) ([]*types.Signature, bool) {
	if sc == nil || sc.Parent() == nil {
		return nil, false
	}
	if cached, found := r.closedMethodCalls[sc]; found {
		return cached.sigs, cached.ok
	}
	sigs, ok := computeClosedMethodValueSigs(sc)
	if r.closedMethodCalls == nil {
		r.closedMethodCalls = make(map[*ssa.Call]closedMethodCallInfo, 4)
	}
	r.closedMethodCalls[sc] = closedMethodCallInfo{sigs: sigs, ok: ok}
	return sigs, ok
}

func computeClosedMethodValueSigs(sc *ssa.Call) ([]*types.Signature, bool) {
	type qItem struct {
		val     ssa.Value
		isIface bool
	}
	visited := map[qItem]bool{{val: sc, isIface: false}: true}
	queue := []qItem{{val: sc, isIface: false}}
	enqueue := func(it qItem) {
		if !visited[it] {
			visited[it] = true
			queue = append(queue, it)
		}
	}
	var sigs []*types.Signature
	const maxSteps = 64
	steps := 0
	for len(queue) > 0 {
		steps++
		if steps > maxSteps {
			return nil, false
		}
		cur := queue[0]
		queue = queue[1:]
		refs := cur.val.Referrers()
		if refs == nil {
			return nil, false
		}
		for _, ref := range *refs {
			if cur.isIface {
				switch ins := ref.(type) {
				case *ssa.DebugRef:
				case *ssa.Phi:
					enqueue(qItem{val: ins, isIface: true})
				case *ssa.TypeAssert:
					if ins.X != cur.val {
						return nil, false
					}
					at := types.Unalias(ins.AssertedType)
					if types.IsInterface(at.Underlying()) {
						return nil, false
					}
					if sig, isSig := at.Underlying().(*types.Signature); isSig {
						sigs = append(sigs, sig)
					}
				default:
					return nil, false
				}
				continue
			}
			switch ins := ref.(type) {
			case *ssa.DebugRef:
			case *ssa.Phi:
				enqueue(qItem{val: ins, isIface: false})
			case ssa.CallInstruction:
				c := ins.Common()
				if c == nil || c.IsInvoke() || c.Value == cur.val {
					return nil, false
				}
				callee := c.StaticCallee()
				if callee == nil {
					return nil, false
				}
				base := unwrapWrapperCallee(callee)
				if base == nil {
					return nil, false
				}
				if orig := base.Origin(); orig != nil && orig.Name() == "TypeAssert" && ssaFuncPkgPath(orig) == "reflect" && len(base.TypeArgs()) == 1 {
					if len(c.Args) != 1 || c.Args[0] != cur.val {
						return nil, false
					}
					targ := types.Unalias(base.TypeArgs()[0])
					if types.IsInterface(targ.Underlying()) {
						return nil, false
					}
					if sig, isSig := targ.Underlying().(*types.Signature); isSig {
						sigs = append(sigs, sig)
					}
					continue
				}
				if ssaFuncPkgPath(base) == "reflect" {
					if base.Signature == nil || base.Signature.Recv() == nil || len(c.Args) == 0 || c.Args[0] != cur.val {
						return nil, false
					}
					for _, a := range c.Args[1:] {
						if a == cur.val {
							return nil, false
						}
					}
					switch base.Name() {
					case "Interface":
						if ic, isCall := ins.(*ssa.Call); isCall {
							enqueue(qItem{val: ic, isIface: true})
						}
					case "IsValid", "Kind", "Type", "IsNil", "IsZero", "CanInterface", "CanAddr", "CanSet", "NumMethod", "String", "Call", "CallSlice":
					default:
						return nil, false
					}
					continue
				}
				if callee == base && callee.Synthetic == "" && len(callee.Blocks) > 0 &&
					callee.Pkg != nil && sc.Parent().Pkg != nil && callee.Pkg == sc.Parent().Pkg &&
					(callee.Signature == nil || !callee.Signature.Variadic()) {
					for i, a := range c.Args {
						if a == cur.val {
							if i >= len(callee.Params) {
								return nil, false
							}
							enqueue(qItem{val: callee.Params[i], isIface: false})
						}
					}
					continue
				}
				return nil, false
			default:
				return nil, false
			}
		}
	}
	return sigs, true
}

func (r *attributedRTA) isTypedCallbackTrampolineAssert(f *ssa.Function, instr *ssa.TypeAssert) bool {
	if f == nil || instr == nil {
		return false
	}
	if cached, ok := r.trampolineAsserts[instr]; ok {
		return cached
	}
	res := checkTypedCallbackTrampolineAssert(f, instr)
	if r.trampolineAsserts == nil {
		r.trampolineAsserts = make(map[*ssa.TypeAssert]bool, 4)
	}
	r.trampolineAsserts[instr] = res
	return res
}

// checkTypedCallbackTrampolineAssert reports whether instr asserts a parameter
// of an unexported package-level helper f whose sole intra-package references
// pass f alongside a statically typed function MakeInterface into an unexported
// bodyless runtime trampoline (such as time.AfterFunc -> newTimer -> goFunc).
// Such an assertion can never unbox a caller-supplied untyped reflect.Value.Interface()
// unless the caller already type-asserted that signature before calling into the package.
func checkTypedCallbackTrampolineAssert(f *ssa.Function, instr *ssa.TypeAssert) bool {
	param, ok := instr.X.(*ssa.Parameter)
	if !ok || f.Pkg == nil || f.Signature == nil || f.Signature.Recv() != nil || f.Object() == nil || f.Object().Exported() {
		return false
	}
	paramIdx := -1
	for i, p := range f.Params {
		if p == param {
			paramIdx = i
			break
		}
	}
	if paramIdx < 0 {
		return false
	}
	var pkgFuncs []*ssa.Function
	var addFn func(*ssa.Function)
	addFn = func(fn *ssa.Function) {
		if fn == nil {
			return
		}
		pkgFuncs = append(pkgFuncs, fn)
		for _, anon := range fn.AnonFuncs {
			addFn(anon)
		}
	}
	for _, mem := range f.Pkg.Members {
		switch m := mem.(type) {
		case *ssa.Function:
			addFn(m)
		case *ssa.Type:
			mset := f.Prog.MethodSets.MethodSet(types.NewPointer(m.Type()))
			for i, n := 0, mset.Len(); i < n; i++ {
				if fn := f.Prog.MethodValue(mset.At(i)); fn != nil && fn.Pkg == f.Pkg {
					addFn(fn)
				}
			}
		}
	}
	trampolines := map[*ssa.Function]bool{}
	sawRef := false
	var ops [16]*ssa.Value
	for _, fn := range pkgFuncs {
		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				rands := ins.Operands(ops[:0])
				mentionsF := false
				for _, op := range rands {
					if op != nil && *op == f {
						mentionsF = true
						break
					}
				}
				if !mentionsF {
					continue
				}
				sawRef = true
				callIns, isCall := ins.(ssa.CallInstruction)
				if !isCall {
					return false
				}
				c := callIns.Common()
				if c == nil || c.IsInvoke() {
					return false
				}
				callee := c.StaticCallee()
				if callee == nil {
					return false
				}
				if callee == f {
					for _, arg := range c.Args {
						if arg == f {
							return false
						}
					}
					if paramIdx >= len(c.Args) || !isMakeInterfaceOfSignature(c.Args[paramIdx]) {
						return false
					}
					continue
				}
				if callee.Pkg != f.Pkg || len(callee.Blocks) != 0 || callee.Object() == nil || callee.Object().Exported() {
					return false
				}
				sawTypedSig := false
				for _, arg := range c.Args {
					if arg == nil || arg == f || !types.IsInterface(types.Unalias(arg.Type()).Underlying()) {
						continue
					}
					if cnst, isConst := arg.(*ssa.Const); isConst && cnst.IsNil() {
						continue
					}
					if !isMakeInterfaceOfSignature(arg) {
						return false
					}
					sawTypedSig = true
				}
				if !sawTypedSig {
					return false
				}
				trampolines[callee] = true
			}
		}
	}
	if !sawRef {
		return false
	}
	for _, fn := range pkgFuncs {
		for _, b := range fn.Blocks {
			for _, ins := range b.Instrs {
				rands := ins.Operands(ops[:0])
				if callIns, isCall := ins.(ssa.CallInstruction); isCall && !callIns.Common().IsInvoke() && len(rands) > 0 {
					rands = rands[1:]
				}
				for _, op := range rands {
					if op != nil {
						if g, ok := (*op).(*ssa.Function); ok && trampolines[g] {
							return false
						}
					}
				}
			}
		}
	}
	return true
}

func isMakeInterfaceOfSignature(v ssa.Value) bool {
	mk, ok := v.(*ssa.MakeInterface)
	if !ok || mk == nil || mk.X == nil || mk.X.Type() == nil {
		return false
	}
	_, isSig := types.Unalias(mk.X.Type()).Underlying().(*types.Signature)
	return isSig
}

func (r *attributedRTA) visitFunc(f *ssa.Function, masks uint64, harnessStdPlane bool) {
	r.current = f
	// addRuntimeType(reflect.Value) marks reflect.Value's own method set
	// (including anonymous iterator closures in Methods/Seq/Seq2) reachable
	// whenever a reflect.Value is formatted or boxed, and package "testing"
	// invokes reflect.Value.Call internally in testing/fuzz.go on (*testing.F).Fuzz
	// targets that attribution roots explicitly. Only uses originating outside
	// "reflect" and "testing" activate reflective method-value or container-write
	// propagation.
	callerPkg := ssaFuncPkgPath(f)
	callerIsHarness := !harnessStdPlane && r.harnessPkg != "" && callerPkg == r.harnessPkg
	ignoreReflectCallee := harnessStdPlane || callerPkg == "reflect" || callerPkg == "testing" || strings.HasPrefix(f.Synthetic, "wrapper ")
	var space [32]*ssa.Value
	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			rands := instr.Operands(space[:0])
			switch instr := instr.(type) {
			case ssa.CallInstruction:
				call := instr.Common()
				if call.IsInvoke() {
					if harnessStdPlane {
						r.visitHarnessStdInvoke(instr, masks)
					} else {
						r.visitInvoke(instr, masks)
					}
				} else if g := call.StaticCallee(); g != nil {
					if harnessStdPlane || (callerIsHarness && r.isHarnessInternalStdPkg(ssaFuncPkgPath(g))) {
						r.addHarnessStdReachable(g, masks)
					} else {
						// Static edges inherit exactly the caller's newly reached subjects.
						r.addReachable(g, masks)
					}
					if !ignoreReflectCallee {
						r.noteReflectCallSite(instr, g, masks)
					}
				} else if _, ok := call.Value.(*ssa.Builtin); !ok {
					if harnessStdPlane {
						r.visitHarnessStdDynCall(instr, masks)
					} else {
						r.visitDynCall(instr, masks)
					}
				}
				rands = rands[1:]
			case *ssa.MakeInterface:
				if (harnessStdPlane || callerIsHarness) && r.isPureHarnessInternalStdType(instr.X.Type()) {
					r.addHarnessStdRuntimeType(instr.X.Type(), masks, false)
				} else {
					r.addRuntimeType(instr.X.Type(), masks, false)
					if !harnessStdPlane {
						r.addWritableRuntimeType(instr.X.Type(), masks, false)
					}
				}
			case *ssa.TypeAssert:
				if !harnessStdPlane {
					if sig, ok := types.Unalias(instr.AssertedType).Underlying().(*types.Signature); ok {
						if !r.isTypedCallbackTrampolineAssert(f, instr) {
							r.addReflectAssertSig(sig, masks)
						}
					} else if !types.IsInterface(types.Unalias(instr.AssertedType).Underlying()) {
						r.addWritableRuntimeType(instr.AssertedType, masks, false)
					}
				}
			case *ssa.MakeClosure:
				if onlyDirectCallCallee(instr) {
					rands = rands[1:]
				}
			}
			for _, op := range rands {
				if g, ok := (*op).(*ssa.Function); ok {
					if harnessStdPlane {
						r.visitHarnessStdAddrTakenFunc(g, masks)
					} else {
						r.visitAddrTakenFunc(g, masks)
						if !ignoreReflectCallee {
							r.noteReflectCalleeUse(g, masks)
						}
					}
				}
			}
		}
	}
}

// onlyDirectCallCallee reports whether a closure creation is used exclusively
// as the callee operand of direct call/go/defer instructions (where
// StaticCallee resolves it directly) and never escapes as a first-class value.
func onlyDirectCallCallee(mk *ssa.MakeClosure) bool {
	if mk == nil {
		return false
	}
	refs := mk.Referrers()
	if refs == nil || len(*refs) == 0 {
		return false
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case ssa.CallInstruction:
			c := r.Common()
			if c == nil || c.IsInvoke() || c.Value != mk {
				return false
			}
			for _, arg := range c.Args {
				if arg == mk {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// Seeds carries per-subject facts established outside the walk — the
// caller-enumeration closure of a dynamic-carrying subject hands the
// walk exactly what enumerable callers can pass: function values become
// dispatch candidates (address-taken under the subject's mask, so the
// subject's own dynamic sites resolve to them and their bodies join the
// subject's reachability only if actually dispatched), and materialized
// concrete types enter the runtime-type walk (so interface dispatch on
// a parameter enumerates them and their exported method sets stay
// visible). Seeding never forces reachability by itself: an undispatched
// candidate contributes nothing, mirroring RTA's own address-taken
// semantics.
type Seeds struct {
	AddrTaken    map[*ssa.Function]uint64
	RuntimeTypes []TypeSeed
	// HarnessPkg, when non-empty, names a mechanically verified
	// property-testing harness package whose internal standard-library call
	// graph executes on an isolated runtime-type plane so harness-internal
	// standard-library error/template/codec types never pollute non-harness
	// interface invoke sites, while non-stdlib callbacks and methods
	// dispatched through those standard-library helpers promote back to
	// Reachable.
	HarnessPkg      string
	UserPkgs        map[string]bool
	HarnessStdRoots map[*ssa.Function]uint64
}

// TypeSeed is one concrete type materialized at an enumerated caller
// site, entering the runtime-type walk under the subjects of Masks.
type TypeSeed struct {
	Type  types.Type
	Masks uint64
}

func checkNonParameterizedRoots(roots map[*ssa.Function]uint64) error {
	for root := range roots {
		if root == nil {
			continue
		}
		// An instance carries its origin's TypeParams; what makes a
		// root parameterized is an EMPTY argument list (an origin) or
		// an argument still mentioning a type parameter (a
		// parameterized instance) - a fully concrete instance roots
		// like any plain function.
		generic := root.TypeParams().Len() > 0 || (root.Signature != nil && root.Signature.RecvTypeParams() != nil)
		if !generic {
			continue
		}
		args := root.TypeArgs()
		parameterized := len(args) == 0
		for _, arg := range args {
			if ContainsTypeParam(arg, make(map[types.Type]bool)) {
				parameterized = true
				break
			}
		}
		if parameterized {
			return fmt.Errorf("closure: attributed reachability: parameterized root %s", root.String())
		}
	}
	return nil
}

// analyzeAttributed performs RTA for up to 64 subjects at once. roots maps each
// root function to the subjects for which it is an independent-analysis root.
// The walk mirrors upstream RTA, whose internal assertions panic on shapes it
// cannot classify; the boundary converts any such panic into an error so an
// unsupported shape degrades to per-subject unavailable evidence in the
// embedding process — fail-closed, never a crash. The breadth is deliberate:
// a genuine regression panicking here degrades instead of crashing, and its
// detection signal is corpus-level "unsupported analysis shape" counts.
// Analyze runs attributed RTA over the masked roots and seeds.
func Analyze(ctx context.Context, roots map[*ssa.Function]uint64, seeds *Seeds) (result *Result, err error) {
	var r *attributedRTA
	defer func() {
		if recovered := recover(); recovered != nil {
			// The visiting-function provenance makes the next field
			// occurrence self-attributing: the shape's entry path was
			// undiagnosable from a bare panic value once.
			site := ""
			if r != nil && r.current != nil {
				site = " (visiting " + r.current.String() + ")"
			}
			result, err = nil, fmt.Errorf("closure: attributed reachability: unsupported analysis shape: %v%s", recovered, site)
		}
	}()
	if ctx == nil {
		return nil, fmt.Errorf("closure: nil analysis context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
	}
	if len(roots) == 0 && (seeds == nil || len(seeds.HarnessStdRoots) == 0) {
		return nil, nil
	}
	// Rooting a parameterized body is a caller-contract violation, not
	// a stray shape: attribution's own arm roots concrete
	// instantiations and never origins, so an origin root fails loudly
	// here instead of silently walking a body whose dispatch surface
	// was never analyzable - the flattering direction the type-param
	// SHAPE skip below must not extend to.
	if err := checkNonParameterizedRoots(roots); err != nil {
		return nil, err
	}
	if seeds != nil {
		if err := checkNonParameterizedRoots(seeds.HarnessStdRoots); err != nil {
			return nil, err
		}
	}
	var prog *ssa.Program
	for root := range roots {
		if root != nil {
			prog = root.Prog
			break
		}
	}
	if prog == nil && seeds != nil {
		for root := range seeds.HarnessStdRoots {
			if root != nil {
				prog = root.Prog
				break
			}
		}
	}
	if prog == nil {
		return nil, nil
	}
	r = &attributedRTA{
		result: &Result{
			Reachable: make(map[*ssa.Function]uint64),
			Resolved:  make(map[ssa.CallInstruction]uint64),
			Targets:   make(map[ssa.CallInstruction]map[*ssa.Function]uint64),
		},
		prog:          prog,
		pending:       make(map[*ssa.Function]uint64),
		queued:        make(map[*ssa.Function]bool),
		typeParamSeen: make(map[types.Type]bool),
	}
	if seeds != nil && seeds.HarnessPkg != "" {
		r.harnessPkg = seeds.HarnessPkg
		r.userPkgs = seeds.UserPkgs
		for root, m := range seeds.HarnessStdRoots {
			if m != 0 && ssaFuncPkgPath(root) == "testing" {
				r.harnessOnlyTesting = true
				break
			}
		}
		r.result.HarnessStdReachable = make(map[*ssa.Function]uint64)
		r.result.HarnessStdTargets = make(map[ssa.CallInstruction]map[*ssa.Function]uint64)
		r.harnessPending = make(map[*ssa.Function]uint64)
		r.harnessQueued = make(map[*ssa.Function]bool)
	}

	if reflectPkg := prog.ImportedPackage("reflect"); reflectPkg != nil {
		r.reflectMethodFuncs = make(map[*ssa.Function]bool, 3)
		r.reflectSingleMethodFuncs = make(map[*ssa.Function]bool, 2)
		r.reflectWriteFuncs = make(map[*ssa.Function]reflectWriteKind, 11)
		if reflectValue, ok := reflectPkg.Members["Value"].(*ssa.Type); ok && reflectValue != nil {
			valType := types.Unalias(reflectValue.Object().Type())
			r.reflectValueCall = prog.LookupMethod(valType, reflectPkg.Pkg, "Call")
			r.reflectValueCallSlice = prog.LookupMethod(valType, reflectPkg.Pkg, "CallSlice")
			for _, mName := range []string{"Method", "MethodByName", "Methods"} {
				if fn := prog.LookupMethod(valType, reflectPkg.Pkg, mName); fn != nil {
					r.reflectMethodFuncs[fn] = true
					if mName != "Methods" {
						r.reflectSingleMethodFuncs[fn] = true
					}
				}
			}
			for _, spec := range []struct {
				name string
				kind reflectWriteKind
			}{
				{"Set", reflectWriteSet},
				{"SetIterKey", reflectWriteSet},
				{"SetIterValue", reflectWriteSet},
				{"SetPointer", reflectWriteSet},
				{"SetMapIndex", reflectWriteMap},
				{"Send", reflectWriteChan},
				{"TrySend", reflectWriteChan},
			} {
				if fn := prog.LookupMethod(valType, reflectPkg.Pkg, spec.name); fn != nil {
					r.reflectWriteFuncs[fn] = spec.kind
				}
			}
		}
		for _, spec := range []struct {
			name string
			kind reflectWriteKind
		}{
			{"Append", reflectWriteSlice},
			{"AppendSlice", reflectWriteSlice},
			{"Copy", reflectWriteSlice},
			{"Select", reflectWriteChan},
		} {
			if fn := reflectPkg.Func(spec.name); fn != nil {
				r.reflectWriteFuncs[fn] = spec.kind
			}
		}
	}

	hasher := typeutil.MakeHasher()
	r.addrTakenFuncsBySig.SetHasher(hasher)
	r.dynCallSites.SetHasher(hasher)
	r.invokeSites.SetHasher(hasher)
	if r.harnessPkg != "" {
		r.harnessAddrTakenFuncsBySig.SetHasher(hasher)
		r.harnessDynCallSites.SetHasher(hasher)
		r.harnessInvokeSites.SetHasher(hasher)
		r.harnessRuntimeTypes.SetHasher(hasher)
		r.harnessTraversedTypes.SetHasher(hasher)
	}
	r.directReflectMethodSigs.SetHasher(hasher)
	r.reflectAssertSigs.SetHasher(hasher)
	for k := range numReflectWriteKinds {
		r.reflectWriteSigs[k].SetHasher(hasher)
	}
	r.runtimeMethodFuncs.SetHasher(hasher)
	r.concreteTypes.SetHasher(hasher)
	r.interfaceTypes.SetHasher(hasher)
	r.runtimeTypes.SetHasher(hasher)
	r.traversedTypes.SetHasher(hasher)
	r.writableTypes.SetHasher(hasher)
	r.embedROTypes.SetHasher(hasher)

	// Seeds precede root processing so a subject's first-visited dynamic
	// site already sees its enumerated candidates and types; the visit
	// maps are delta-driven, so order affects nothing but avoids a
	// re-walk.
	if seeds != nil {
		for f, masks := range seeds.AddrTaken {
			if f != nil && masks != 0 {
				r.visitAddrTakenFunc(f, masks)
			}
		}
		for _, seed := range seeds.RuntimeTypes {
			if seed.Type != nil && seed.Masks != 0 {
				r.addRuntimeType(seed.Type, seed.Masks, false)
				r.addWritableRuntimeType(seed.Type, seed.Masks, false)
			}
		}
		for root, masks := range seeds.HarnessStdRoots {
			r.addHarnessStdReachable(root, masks)
		}
	}
	for root, masks := range roots {
		r.addReachable(root, masks)
	}
	for len(r.worklist) > 0 || len(r.harnessWorklist) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
		}
		if len(r.worklist) > 0 {
			var shadow []*ssa.Function
			shadow, r.worklist = r.worklist, shadow
			for _, f := range shadow {
				if err := ctx.Err(); err != nil {
					return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
				}
				r.queued[f] = false
				masks := r.pending[f]
				delete(r.pending, f)
				r.visitFunc(f, masks, false)
			}
		}
		if len(r.harnessWorklist) > 0 {
			var hShadow []*ssa.Function
			hShadow, r.harnessWorklist = r.harnessWorklist, hShadow
			for _, f := range hShadow {
				if err := ctx.Err(); err != nil {
					return nil, fmt.Errorf("closure: analysis cancelled: %w", err)
				}
				r.harnessQueued[f] = false
				masks := r.harnessPending[f]
				delete(r.harnessPending, f)
				r.visitFunc(f, masks, true)
			}
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

// containsTypeParam reports whether the type mentions a type parameter
// anywhere in its structure. Such a type denotes no runtime type - only
// fully concrete instantiations exist at runtime, and they enter the
// walk through their own MakeInterface and instantiation sites - so the
// runtime-type walk skips it wholesale instead of panicking in the
// shape switch (the bldc field campaign's "unsupported analysis
// shape: T", one generic-shaped symbol darkening whole packages
// through the batch). The seen map breaks reference cycles.
func ContainsTypeParam(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	unaliased := types.Unalias(t)
	switch unaliased.(type) {
	case *types.TypeParam, *types.Union:
		return true
	case *types.Basic:
		return false
	}
	if seen[t] {
		return false
	}
	seen[t] = true
	switch t := unaliased.(type) {
	case *types.Pointer:
		return ContainsTypeParam(t.Elem(), seen)
	case *types.Slice:
		return ContainsTypeParam(t.Elem(), seen)
	case *types.Array:
		return ContainsTypeParam(t.Elem(), seen)
	case *types.Chan:
		return ContainsTypeParam(t.Elem(), seen)
	case *types.Map:
		return ContainsTypeParam(t.Key(), seen) || ContainsTypeParam(t.Elem(), seen)
	case *types.Signature:
		if t.TypeParams() != nil || t.RecvTypeParams() != nil {
			return true
		}
		return ContainsTypeParam(t.Params(), seen) || ContainsTypeParam(t.Results(), seen)
	case *types.Tuple:
		for i, n := 0, t.Len(); i < n; i++ {
			if ContainsTypeParam(t.At(i).Type(), seen) {
				return true
			}
		}
		return false
	case *types.Struct:
		for i, n := 0, t.NumFields(); i < n; i++ {
			if ContainsTypeParam(t.Field(i).Type(), seen) {
				return true
			}
		}
		return false
	case *types.Named:
		if t.TypeParams() != nil && t.TypeArgs() == nil {
			// A generic origin type is never a runtime type.
			return true
		}
		if args := t.TypeArgs(); args != nil {
			for i, n := 0, args.Len(); i < n; i++ {
				if ContainsTypeParam(args.At(i), seen) {
					return true
				}
			}
		}
		// A type declared INSIDE a generic body mentions the enclosing
		// type parameters only through its underlying - x/tools' own
		// free-variable walker ends its Named case the same way
		// ("recurse for types local to parameterized functions"), and
		// missing it let Inner[local] defeat the guard, the rooting
		// filter, and the loud arm at once (the chunk-132 review's
		// H1). The seen map breaks reference cycles.
		return ContainsTypeParam(t.Underlying(), seen)
	case *types.Interface:
		for i, n := 0, t.NumEmbeddeds(); i < n; i++ {
			if ContainsTypeParam(t.EmbeddedType(i), seen) {
				return true
			}
		}
		for i, n := 0, t.NumExplicitMethods(); i < n; i++ {
			if ContainsTypeParam(t.ExplicitMethod(i).Type(), seen) {
				return true
			}
		}
		return false
	}
	// Unknown kinds keep the shape switch's fail-closed panic path.
	return false
}

// addRuntimeType is adapted from needMethods in go/ssa/builder.go, matching
// upstream RTA's exported-method and recursive runtime-type behavior.
// Intermediate tuple types and underlying types of named types pass skip=true:
// reflection can reach their element and field types, never the tuple or
// unnamed underlying type itself unless materialized independently.
func (r *attributedRTA) addRuntimeType(T types.Type, masks uint64, skip bool) {
	if masks == 0 {
		return
	}
	T = types.Unalias(T)
	var prevAccess, accessDelta uint64
	if !skip {
		prevAccess, _ = r.runtimeTypes.At(T).(uint64)
		accessDelta = masks &^ prevAccess
	}
	prevTraversed, _ := r.traversedTypes.At(T).(uint64)
	traverseDelta := masks &^ prevTraversed
	if accessDelta == 0 && traverseDelta == 0 {
		return
	}
	if prevTraversed == 0 {
		clear(r.typeParamSeen)
		if ContainsTypeParam(T, r.typeParamSeen) {
			return
		}
	}
	if accessDelta != 0 {
		r.runtimeTypes.Set(T, prevAccess|accessDelta)
		if _, ok := T.Underlying().(*types.Interface); !ok {
			mset := r.prog.MethodSets.MethodSet(T)
			for i, n := 0, mset.Len(); i < n; i++ {
				sel := mset.At(i)
				if sel.Obj().Exported() && sel.Obj().Type().(*types.Signature).TypeParams() == nil {
					mv := r.prog.MethodValue(sel)
					r.addReachable(mv, accessDelta)
					r.addRuntimeMethodFunc(mv, accessDelta)
				}
			}

			r.interfaces(T)
			cinfo := r.concreteTypes.At(T).(*attributedConcreteTypeInfo)
			cinfo.masks |= accessDelta
			for _, I := range cinfo.implements {
				sites, _ := r.invokeSites.At(I).(map[ssa.CallInstruction]uint64)
				for site, siteMasks := range sites {
					r.addInvokeEdge(site, T, accessDelta&siteMasks)
				}
				if r.harnessPkg != "" {
					hSites, _ := r.harnessInvokeSites.At(I).(map[ssa.CallInstruction]uint64)
					for site, siteMasks := range hSites {
						r.addHarnessStdInvokeEdge(site, T, accessDelta&siteMasks, false)
					}
				}
			}
		}
	}
	if traverseDelta == 0 {
		return
	}
	r.traversedTypes.Set(T, prevTraversed|traverseDelta)

	mset := r.prog.MethodSets.MethodSet(T)
	for i, n := 0, mset.Len(); i < n; i++ {
		method := mset.At(i)
		sig := method.Type().(*types.Signature)
		if sig.TypeParams() == nil {
			r.addRuntimeType(sig.Params(), traverseDelta, true)
			r.addRuntimeType(sig.Results(), traverseDelta, true)
		}
	}

	switch t := T.(type) {
	case *types.Alias:
		panic("unreachable")
	case *types.Basic, *types.Interface:
	case *types.Pointer:
		r.addRuntimeType(t.Elem(), traverseDelta, false)
	case *types.Slice:
		r.addRuntimeType(t.Elem(), traverseDelta, false)
	case *types.Chan:
		r.addRuntimeType(t.Elem(), traverseDelta, false)
	case *types.Map:
		r.addRuntimeType(t.Key(), traverseDelta, false)
		r.addRuntimeType(t.Elem(), traverseDelta, false)
	case *types.Signature:
		if t.Recv() != nil {
			panic(fmt.Sprintf("Signature %s has Recv %s", t, t.Recv()))
		}
		r.addRuntimeType(t.Params(), traverseDelta, true)
		r.addRuntimeType(t.Results(), traverseDelta, true)
	case *types.Named:
		r.addRuntimeType(types.NewPointer(T), traverseDelta, false)
		r.addRuntimeType(t.Underlying(), traverseDelta, true)
	case *types.Array:
		r.addRuntimeType(t.Elem(), traverseDelta, false)
	case *types.Struct:
		for i, n := 0, t.NumFields(); i < n; i++ {
			r.addRuntimeType(t.Field(i).Type(), traverseDelta, false)
		}
	case *types.Tuple:
		for i, n := 0, t.Len(); i < n; i++ {
			r.addRuntimeType(t.At(i).Type(), traverseDelta, false)
		}
	default:
		panic(T)
	}
}

func (r *attributedRTA) addHarnessStdRuntimeType(T types.Type, masks uint64, skip bool) {
	if masks == 0 {
		return
	}
	T = types.Unalias(T)
	if !r.isPureHarnessInternalStdType(T) {
		r.addRuntimeType(T, masks, skip)
		return
	}
	var prevAccess, accessDelta uint64
	if !skip {
		prevAccess, _ = r.harnessRuntimeTypes.At(T).(uint64)
		accessDelta = masks &^ prevAccess
	}
	prevTraversed, _ := r.harnessTraversedTypes.At(T).(uint64)
	traverseDelta := masks &^ prevTraversed
	if accessDelta == 0 && traverseDelta == 0 {
		return
	}
	if prevTraversed == 0 {
		clear(r.typeParamSeen)
		if ContainsTypeParam(T, r.typeParamSeen) {
			return
		}
	}
	if accessDelta != 0 {
		r.harnessRuntimeTypes.Set(T, prevAccess|accessDelta)
		if _, ok := T.Underlying().(*types.Interface); !ok {
			mset := r.prog.MethodSets.MethodSet(T)
			for i, n := 0, mset.Len(); i < n; i++ {
				sel := mset.At(i)
				if sel.Obj().Exported() && sel.Obj().Type().(*types.Signature).TypeParams() == nil {
					mv := r.prog.MethodValue(sel)
					r.addHarnessStdReachable(mv, accessDelta)
				}
			}

			r.interfaces(T)
			cinfo := r.concreteTypes.At(T).(*attributedConcreteTypeInfo)
			cinfo.harnessStdMasks |= accessDelta
			for _, I := range cinfo.implements {
				hSites, _ := r.harnessInvokeSites.At(I).(map[ssa.CallInstruction]uint64)
				for site, siteMasks := range hSites {
					r.addHarnessStdInvokeEdge(site, T, accessDelta&siteMasks, false)
				}
				sites, _ := r.invokeSites.At(I).(map[ssa.CallInstruction]uint64)
				for site, siteMasks := range sites {
					if ssaFuncPkgPath(site.Parent()) == r.harnessPkg {
						r.addHarnessStdInvokeEdge(site, T, (accessDelta&siteMasks)&^cinfo.masks, true)
					}
				}
			}
		}
	}
	if traverseDelta == 0 {
		return
	}
	r.harnessTraversedTypes.Set(T, prevTraversed|traverseDelta)

	mset := r.prog.MethodSets.MethodSet(T)
	for i, n := 0, mset.Len(); i < n; i++ {
		method := mset.At(i)
		sig := method.Type().(*types.Signature)
		if sig.TypeParams() == nil {
			r.addHarnessStdRuntimeType(sig.Params(), traverseDelta, true)
			r.addHarnessStdRuntimeType(sig.Results(), traverseDelta, true)
		}
	}

	switch t := T.(type) {
	case *types.Alias:
		panic("unreachable")
	case *types.Basic, *types.Interface:
	case *types.Pointer:
		r.addHarnessStdRuntimeType(t.Elem(), traverseDelta, false)
	case *types.Slice:
		r.addHarnessStdRuntimeType(t.Elem(), traverseDelta, false)
	case *types.Chan:
		r.addHarnessStdRuntimeType(t.Elem(), traverseDelta, false)
	case *types.Map:
		r.addHarnessStdRuntimeType(t.Key(), traverseDelta, false)
		r.addHarnessStdRuntimeType(t.Elem(), traverseDelta, false)
	case *types.Signature:
		if t.Recv() != nil {
			panic(fmt.Sprintf("Signature %s has Recv %s", t, t.Recv()))
		}
		r.addHarnessStdRuntimeType(t.Params(), traverseDelta, true)
		r.addHarnessStdRuntimeType(t.Results(), traverseDelta, true)
	case *types.Named:
		r.addHarnessStdRuntimeType(types.NewPointer(T), traverseDelta, false)
		r.addHarnessStdRuntimeType(t.Underlying(), traverseDelta, true)
	case *types.Array:
		r.addHarnessStdRuntimeType(t.Elem(), traverseDelta, false)
	case *types.Struct:
		for i, n := 0, t.NumFields(); i < n; i++ {
			r.addHarnessStdRuntimeType(t.Field(i).Type(), traverseDelta, false)
		}
	case *types.Tuple:
		for i, n := 0, t.Len(); i < n; i++ {
			r.addHarnessStdRuntimeType(t.At(i).Type(), traverseDelta, false)
		}
	default:
		panic(T)
	}
}

// addWritableRuntimeType traverses runtime types whose composite elements or
// exported struct fields can receive values through reflective container writes
// (such as Value.Set, SetMapIndex, Send, Append, Copy, or Select), recording
// any receiverless function slot signature in reflectWritableSigs.
//
// In Go's reflect package, accessing a non-embedded unexported struct field
// sets flagStickyRO permanently, whereas accessing an unexported embedded
// struct field sets flagEmbedRO (embedRO=true), blocking direct writes to the
// embedded value itself while still permitting writes to promoted exported
// fields inside it. Method sets are not traversed here because method parameter
// and result signatures are never writable container slots.
func (r *attributedRTA) addWritableRuntimeType(T types.Type, masks uint64, embedRO bool) {
	if T == nil || masks == 0 {
		return
	}
	T = types.Unalias(T)
	table := &r.writableTypes
	if embedRO {
		table = &r.embedROTypes
	}
	prev, _ := table.At(T).(uint64)
	delta := masks &^ prev
	if delta == 0 {
		return
	}
	if prev == 0 {
		clear(r.typeParamSeen)
		if ContainsTypeParam(T, r.typeParamSeen) {
			return
		}
	}
	table.Set(T, prev|delta)

	switch t := T.(type) {
	case *types.Alias:
		panic("unreachable")
	case *types.Basic, *types.Interface:
	case *types.Pointer:
		r.addWritableRuntimeType(t.Elem(), delta, embedRO)
	case *types.Slice:
		if !embedRO {
			if sig, ok := types.Unalias(t.Elem()).Underlying().(*types.Signature); ok {
				r.addReflectWriteSig(reflectWriteSlice, sig, delta)
			}
			r.addWritableRuntimeType(t.Elem(), delta, false)
		}
	case *types.Array:
		if !embedRO {
			if sig, ok := types.Unalias(t.Elem()).Underlying().(*types.Signature); ok {
				r.addReflectWriteSig(reflectWriteSlice, sig, delta)
			}
			r.addWritableRuntimeType(t.Elem(), delta, false)
		}
	case *types.Chan:
		if !embedRO {
			if sig, ok := types.Unalias(t.Elem()).Underlying().(*types.Signature); ok {
				r.addReflectWriteSig(reflectWriteChan, sig, delta)
			} else {
				r.addWritableRuntimeType(t.Elem(), delta, false)
			}
		}
	case *types.Map:
		if !embedRO {
			if sig, ok := types.Unalias(t.Elem()).Underlying().(*types.Signature); ok {
				r.addReflectWriteSig(reflectWriteMap, sig, delta)
			} else {
				r.addWritableRuntimeType(t.Elem(), delta, false)
			}
			if _, isSig := types.Unalias(t.Key()).Underlying().(*types.Signature); !isSig {
				r.addWritableRuntimeType(t.Key(), delta, false)
			}
		}
	case *types.Signature:
		if !embedRO && t.Recv() == nil {
			r.addReflectWriteSig(reflectWriteSet, t, delta)
		}
	case *types.Named:
		r.addWritableRuntimeType(t.Underlying(), delta, embedRO)
	case *types.Struct:
		for i, n := 0, t.NumFields(); i < n; i++ {
			f := t.Field(i)
			if f.Exported() {
				r.addWritableRuntimeType(f.Type(), delta, false)
			} else if f.Embedded() {
				r.addWritableRuntimeType(f.Type(), delta, true)
			}
		}
	case *types.Tuple:
		for i, n := 0, t.Len(); i < n; i++ {
			r.addWritableRuntimeType(t.At(i).Type(), delta, embedRO)
		}
	default:
		panic(T)
	}
}

func attributedFingerprint(mset *types.MethodSet) uint64 {
	var space [64]byte
	var mask uint64
	for i, n := 0, mset.Len(); i < n; i++ {
		method := mset.At(i).Obj()
		sig := method.Type().(*types.Signature)
		if sig.TypeParams() != nil {
			continue
		}
		sum := crc32.ChecksumIEEE(fmt.Appendf(space[:0], "%s/%d/%d", method.Id(), sig.Params().Len(), sig.Results().Len()))
		mask |= 1 << (sum % 64)
	}
	return mask
}

func attributedImplements(cinfo *attributedConcreteTypeInfo, iinfo *attributedInterfaceTypeInfo) bool {
	return iinfo.fprint & ^cinfo.fprint == 0 && types.Implements(cinfo.C, iinfo.I)
}
