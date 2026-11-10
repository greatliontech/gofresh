package rta

import (
	"go/types"
	"hash/crc32"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/types/typeutil"
)

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

// seedAddrTakenFunc registers a caller-enumerated candidate function value
// from Seeds.AddrTaken under its signature so dynamic call sites with matching
// signature resolve to it without forcing the candidate's body reachable when
// it is never dispatched.
func (r *attributedRTA) seedAddrTakenFunc(f *ssa.Function, masks uint64) {
	if f == nil {
		return
	}
	r.visitAddrTakenFuncWithSig(f, f.Signature, masks, false)
}

// visitAddrTakenFunc records each subject that reaches an in-body address-taking use.
func (r *attributedRTA) visitAddrTakenFunc(f *ssa.Function, masks uint64) {
	if f == nil {
		return
	}
	r.visitAddrTakenFuncWithSig(f, f.Signature, masks, true)
}

func (r *attributedRTA) visitAddrTakenFuncWithSig(f *ssa.Function, S *types.Signature, masks uint64, inBody bool) {
	if f == nil || S == nil || masks == 0 {
		return
	}
	// Upstream RTA treats the presence of reflect.Value.Call or CallSlice in
	// the program as sufficient to make every in-body address-taken function
	// reachable by reflection. Caller-enumerated candidate seeds (inBody=false)
	// join reachability only when dispatched at a matching dynamic call site.
	if inBody && (r.reflectValueCall != nil || r.reflectValueCallSlice != nil) {
		r.addReachable(f, masks)
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
			callerPkg := r.funcPkgPath(site.Parent())
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
}

func (r *attributedRTA) visitHarnessStdAddrTakenFunc(f *ssa.Function, masks uint64) {
	if f == nil || f.Signature == nil || masks == 0 {
		return
	}
	if !r.isHarnessInternalStdPkg(r.funcPkgPath(f)) {
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
		if r.funcPkgPath(site.Parent()) != r.harnessPkg {
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

	callerPkg := r.funcPkgPath(site.Parent())
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
		callerPkg := r.funcPkgPath(site.Parent())
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

	callerIsHarness := r.harnessPkg != "" && r.funcPkgPath(site.Parent()) == r.harnessPkg
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

func (r *attributedRTA) concreteInfo(C types.Type, mset *types.MethodSet) *attributedConcreteTypeInfo {
	if v := r.concreteTypes.At(C); v != nil {
		return v.(*attributedConcreteTypeInfo)
	}
	if mset == nil {
		mset = r.prog.MethodSets.MethodSet(C)
	}
	cinfo := &attributedConcreteTypeInfo{C: C, fprint: attributedFingerprint(mset)}
	r.concreteTypes.Set(C, cinfo)
	r.interfaceTypes.Iterate(func(I types.Type, v any) {
		iinfo := v.(*attributedInterfaceTypeInfo)
		if iface := types.Unalias(I).(*types.Interface); attributedImplements(cinfo, iinfo) {
			iinfo.implementations = append(iinfo.implementations, C)
			cinfo.implements = append(cinfo.implements, iface)
		}
	})
	return cinfo
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

func attributedFingerprint(mset *types.MethodSet) uint64 {
	var space [256]byte
	var mask uint64
	for i, n := 0, mset.Len(); i < n; i++ {
		method := mset.At(i).Obj()
		sig := method.Type().(*types.Signature)
		if sig.TypeParams() != nil {
			continue
		}
		b := space[:0]
		name := method.Name()
		if !method.Exported() {
			path := "_"
			if pkg := method.Pkg(); pkg != nil && pkg.Path() != "" {
				path = pkg.Path()
			}
			b = append(b, path...)
			b = append(b, '.')
		}
		b = append(b, name...)
		b = append(b, '/')
		b = strconv.AppendInt(b, int64(sig.Params().Len()), 10)
		b = append(b, '/')
		b = strconv.AppendInt(b, int64(sig.Results().Len()), 10)
		sum := crc32.ChecksumIEEE(b)
		mask |= 1 << (sum % 64)
	}
	return mask
}

func attributedImplements(cinfo *attributedConcreteTypeInfo, iinfo *attributedInterfaceTypeInfo) bool {
	return iinfo.fprint & ^cinfo.fprint == 0 && types.Implements(cinfo.C, iinfo.I)
}

func (r *attributedRTA) funcPkgPath(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		return fn.Pkg.Pkg.Path()
	}
	if r != nil {
		if cached, ok := r.pkgPaths[fn]; ok {
			return cached
		}
	}
	res := ssaFuncPkgPath(fn)
	if r != nil {
		if r.pkgPaths == nil {
			r.pkgPaths = make(map[*ssa.Function]string, 16)
		}
		r.pkgPaths[fn] = res
	}
	return res
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

func (r *attributedRTA) unwrapWrapper(f *ssa.Function) *ssa.Function {
	if f == nil || f.Synthetic == "" {
		return f
	}
	if r != nil {
		if cached, ok := r.unwrappedCallees[f]; ok {
			return cached
		}
	}
	res := unwrapWrapperCallee(f)
	if r != nil {
		if r.unwrappedCallees == nil {
			r.unwrappedCallees = make(map[*ssa.Function]*ssa.Function, 16)
		}
		r.unwrappedCallees[f] = res
	}
	return res
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
