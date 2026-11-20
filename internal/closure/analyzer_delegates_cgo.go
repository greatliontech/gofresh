package closure

import (
	"fmt"
	"go/constant"
	"go/types"
	"os"
	"sort"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/propharness"
)

func (a *tier2Analyzer) admitPropertyHarnessInvokeTarget(reachable attributedReachability, site ssa.CallInstruction, target *ssa.Function) bool {
	if a == nil || site == nil || site.Common() == nil || !site.Common().IsInvoke() || target == nil || target.Signature == nil || target.Signature.Recv() == nil {
		return false
	}
	recvNamed := namedOriginDeref(target.Signature.Recv().Type())
	if recvNamed == nil || recvNamed.Obj() == nil || recvNamed.Obj().Pkg() == nil {
		return false
	}
	vp := a.verifiedHarness(recvNamed.Obj().Pkg().Path())
	if vp == nil {
		return false
	}
	if _, isSample := propertyHarnessSeededSampleCallee(vp, target); isSample {
		return false
	}
	if !propertyHarnessClosedArgsForTarget(site.Common(), target, a.fresh) {
		return false
	}
	return a.propertyHarnessReceiverBoxesClosed(reachable, recvNamed)
}

func (a *tier2Analyzer) propertyHarnessReceiverBoxesClosed(reachable attributedReachability, recvOrigin *types.Named) bool {
	if recvOrigin == nil {
		return false
	}
	if a.harnessRecvBoxClosed != nil {
		if ok, cached := a.harnessRecvBoxClosed[recvOrigin]; cached {
			return ok
		}
	} else {
		a.harnessRecvBoxClosed = make(map[*types.Named]bool, 4)
	}
	for _, t := range reachable.enumeratedTypes {
		if typeContainsNamedOrigin(t, recvOrigin) {
			a.harnessRecvBoxClosed[recvOrigin] = false
			return false
		}
	}
	rtaFns := reachable.rtaFunctions
	if rtaFns == nil {
		rtaFns = reachable.functions
	}
	for fn := range rtaFns {
		if fn == nil || len(fn.Blocks) == 0 {
			continue
		}
		if a.propertyHarnessAudited(ssaFuncOriginPkgPath(fn)) {
			continue
		}
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				mi, ok := instr.(*ssa.MakeInterface)
				if !ok || mi.X == nil || !typeContainsNamedOrigin(mi.X.Type(), recvOrigin) {
					continue
				}
				if !reachable.functions[fn] {
					a.harnessRecvBoxClosed[recvOrigin] = false
					return false
				}
				xt := types.Unalias(mi.X.Type())
				if namedOriginDeref(xt) == recvOrigin {
					if !propertyHarnessClosedValue(mi.X, a.fresh) {
						a.harnessRecvBoxClosed[recvOrigin] = false
						return false
					}
					continue
				}
				if sl, isSlice := xt.(*types.Slice); isSlice && namedOriginDeref(sl.Elem()) == recvOrigin {
					if !harnessVariadicClosed(mi.X, a.fresh) {
						a.harnessRecvBoxClosed[recvOrigin] = false
						return false
					}
					continue
				}
				a.harnessRecvBoxClosed[recvOrigin] = false
				return false
			}
		}
	}
	a.harnessRecvBoxClosed[recvOrigin] = true
	return true
}

func namedOriginDeref(t types.Type) *types.Named {
	if t == nil {
		return nil
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	if named, ok := t.(*types.Named); ok && named != nil {
		return named.Origin()
	}
	return nil
}

func typeContainsNamedOrigin(t types.Type, origin *types.Named) bool {
	if t == nil || origin == nil {
		return false
	}
	seen := make(map[types.Type]bool)
	var walk func(types.Type) bool
	walk = func(cur types.Type) bool {
		if cur == nil {
			return false
		}
		cur = types.Unalias(cur)
		if seen[cur] {
			return false
		}
		seen[cur] = true
		switch tt := cur.(type) {
		case *types.Named:
			if tt.Origin() == origin {
				return true
			}
			for i := 0; i < tt.TypeArgs().Len(); i++ {
				if walk(tt.TypeArgs().At(i)) {
					return true
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
			return walk(tt.Key()) || walk(tt.Elem())
		case *types.Chan:
			return walk(tt.Elem())
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				if walk(tt.Field(i).Type()) {
					return true
				}
			}
		case *types.Signature:
			for _, tuple := range []*types.Tuple{tt.Params(), tt.Results()} {
				for i := 0; tuple != nil && i < tuple.Len(); i++ {
					if walk(tuple.At(i).Type()) {
						return true
					}
				}
			}
		case *types.Interface:
			for i := 0; i < tt.NumMethods(); i++ {
				if walk(tt.Method(i).Type()) {
					return true
				}
			}
		case *types.Tuple:
			for i := 0; i < tt.Len(); i++ {
				if walk(tt.At(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	return walk(t)
}

func (a *tier2Analyzer) addHarnessArgMethodSets(t types.Type) {
	isStdOrHarnessPkg := func(pkg *types.Package) bool {
		if pkg == nil {
			return false
		}
		if idx := a.idxByTypes[pkg]; idx != nil {
			return idx.std || a.propertyHarnessAudited(idx.path)
		}
		return isStdImportPath(pkg.Path()) || a.propertyHarnessAudited(pkg.Path())
	}
	enqueueNamedMethods := func(named *types.Named) {
		if named == nil || named.Obj() == nil || named.Obj().Pkg() == nil || isStdOrHarnessPkg(named.Obj().Pkg()) {
			return
		}
		for _, mt := range []types.Type{named, types.NewPointer(named)} {
			set := types.NewMethodSet(mt)
			for i := 0; i < set.Len(); i++ {
				if fn, ok := set.At(i).Obj().(*types.Func); ok {
					a.enqueueObject(fn)
				}
			}
		}
	}
	var ifaces []*types.Interface
	seenArg := map[types.Type]bool{}
	var collectArgTypes func(types.Type)
	collectArgTypes = func(cur types.Type) {
		if cur == nil {
			return
		}
		cur = types.Unalias(cur)
		if ssaOpaqueHandle(cur) || seenArg[cur] {
			return
		}
		seenArg[cur] = true
		switch tt := cur.(type) {
		case *types.Named:
			for i := 0; i < tt.TypeArgs().Len(); i++ {
				collectArgTypes(tt.TypeArgs().At(i))
			}
			if iface, isIf := tt.Underlying().(*types.Interface); isIf {
				ifaces = append(ifaces, iface)
				return
			}
			if tt.Obj() != nil && isStdOrHarnessPkg(tt.Obj().Pkg()) {
				return
			}
			enqueueNamedMethods(tt)
			collectArgTypes(tt.Underlying())
		case *types.Interface:
			ifaces = append(ifaces, tt)
		case *types.Pointer:
			collectArgTypes(tt.Elem())
		case *types.Slice:
			collectArgTypes(tt.Elem())
		case *types.Array:
			collectArgTypes(tt.Elem())
		case *types.Chan:
			collectArgTypes(tt.Elem())
		case *types.Map:
			collectArgTypes(tt.Key())
			collectArgTypes(tt.Elem())
		case *types.Signature:
			for _, tuple := range []*types.Tuple{tt.Params(), tt.Results()} {
				for i := 0; tuple != nil && i < tuple.Len(); i++ {
					collectArgTypes(tuple.At(i).Type())
				}
			}
		case *types.Struct:
			for i := 0; i < tt.NumFields(); i++ {
				collectArgTypes(tt.Field(i).Type())
			}
		case *types.Tuple:
			for i := 0; i < tt.Len(); i++ {
				collectArgTypes(tt.At(i).Type())
			}
		}
	}
	collectArgTypes(t)
	if len(ifaces) == 0 || (len(a.enumeratedTypes) == 0 && len(a.initBoxedTypes) == 0) {
		return
	}
	seenCand := map[types.Type]bool{}
	walkCandidates := func(cands []types.Type) {
		for _, ct := range cands {
			walkTypeGraph(ct, true, seenCand, func(cur types.Type) bool {
				named, ok := cur.(*types.Named)
				if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
					return true
				}
				if _, isIf := named.Underlying().(*types.Interface); isIf {
					return true
				}
				ptrType := types.NewPointer(named)
				for _, iface := range ifaces {
					if types.Implements(named, iface) || types.Implements(ptrType, iface) {
						enqueueNamedMethods(named)
						break
					}
				}
				return true
			})
		}
	}
	walkCandidates(a.enumeratedTypes)
	walkCandidates(a.initBoxedTypes)
}

func (a *tier2Analyzer) isOpaquePropertyHarnessStruct(n *types.Named) bool {
	if a == nil || n == nil || n.Obj() == nil || n.Obj().Pkg() == nil {
		return false
	}
	if !a.propertyHarnessAudited(n.Obj().Pkg().Path()) {
		return false
	}
	st, ok := n.Underlying().(*types.Struct)
	return ok && propharness.StructHasNoExportedFields(st)
}

func (a *tier2Analyzer) scanBodylessNonStdFunction(fn *ssa.Function, idx *pkgIndex, isSubjectRoot bool) {
	if a == nil || fn == nil || len(fn.Blocks) != 0 || idx == nil || idx.std {
		return
	}
	a.markFilePackage(idx)
	hasLinkname := false
	if obj := fn.Object(); obj != nil {
		if target := a.linknameTarget(idx, obj); target != "" {
			hasLinkname = true
			if !(a.base != nil && a.base.isVerifiedReadOnlyLinknameVar(idx, obj, target)) {
				a.addLinknameTarget(target)
			}
		}
	}
	if idx.meta != nil && len(idx.meta.SFiles) > 0 {
		a.scanVerifiedAsmBodylessFunction(fn, idx, isSubjectRoot)
	} else if !hasLinkname {
		a.requestWiden("bodyless non-standard function in " + idx.id)
	}
}

func (a *tier2Analyzer) linknameTarget(idx *pkgIndex, obj types.Object) string {
	if idx == nil || obj == nil {
		return ""
	}
	docTarget := idx.linknames[obj]
	fileTarget := idx.linknameByName[obj.Name()]
	if docTarget != "" && fileTarget != "" && docTarget != fileTarget {
		return "<conflict>"
	}
	if docTarget != "" {
		return docTarget
	}
	return fileTarget
}

func (a *tier2Analyzer) addLinknameTarget(target string) {
	lastDot := strings.LastIndexByte(target, '.')
	if lastDot < 0 {
		a.requestWiden("unresolved go:linkname target " + target)
		return
	}
	pkgPath, name := target[:lastDot], target[lastDot+1:]
	obj := a.objByName[pkgPath+"."+name]
	isStd := isStdImportPath(pkgPath)
	if obj != nil && obj.Pkg() != nil {
		if idx := a.idxByTypes[obj.Pkg()]; idx != nil {
			isStd = idx.std
		}
	} else if m, ok := a.metaByPath[pkgPath]; ok {
		isStd = m.Standard
	}
	var effect externalEffect
	var classified bool
	if isStd || !isStdImportPath(pkgPath) {
		effect, classified = classBEffect(pkgPath, name)
	}
	if !classified && isStd {
		effect = symbolExternalEffect(externalEffectLinkage, pkgPath, name, "reaches standard linkname target "+target)
		classified = true
	}
	if classified {
		a.recordExternalEffect(effect)
	}
	if obj == nil {
		a.requestWiden("unresolved go:linkname target " + target)
		return
	}
	a.enqueueObject(obj)
}

func (a *tier2Analyzer) addReachedPackageFiles() error {
	pkgs := make([]*pkgIndex, 0, len(a.filePkgs))
	for idx := range a.filePkgs {
		pkgs = append(pkgs, idx)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].id < pkgs[j].id })
	for _, idx := range pkgs {
		if err := a.contextErr(); err != nil {
			return err
		}
		if idx.meta == nil {
			a.requestWiden("missing file metadata for " + idx.id)
			continue
		}
		if idx.wasmImport {
			effect := opaqueExternalEffect(externalEffectLinkage, "reaches go:wasmimport")
			effect.unrefinable = true
			a.recordExternalEffect(effect)
		}
		if hasExternalCgoMeta(idx.meta) {
			effect := opaqueExternalEffect(externalEffectNative, "reaches cgo external library")
			effect.unrefinable = true
			a.recordExternalEffect(effect)
		}
		if idx.mutable {
			if hasCgoCallbackBlindspot(idx.meta) && !a.verifiedPackageAssemblySafe(idx.meta) {
				modCache := ""
				if a.h != nil {
					modCache = a.h.modCache
				}
				if root := cgoIncludeRootOutsideDir(idx.meta, modCache); root != "" {
					return fmt.Errorf("closure: cgo include root outside package dir: %s", root)
				}
				all, err := allPackageFiles(a.contextErr, idx.meta.Dir)
				if err != nil {
					return err
				}
				if include, err := cgoEscapingInclude(idx.meta, all); err != nil {
					return err
				} else if include != "" {
					return fmt.Errorf("closure: cgo include escapes package dir: %s", include)
				}
				a.requestWiden("cgo callback source in " + idx.id)
			}
		}
		if len(idx.meta.SFiles) == 0 || a.verifiedPackageAssemblySafe(idx.meta) {
			continue
		}
		a.recordExternalEffect(opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly"))
		a.requestWiden("non-toolchain assembly in " + idx.id)
	}
	return nil
}

func (a *tier2Analyzer) requestWiden(reason string) {
	if !a.widen || reason < a.widenReason {
		a.widen = true
		a.widenReason = reason
	}
}

func (a *tier2Analyzer) recordExternalEffect(effect externalEffect) {
	a.collectExternalEffect(effect)
	if !a.unverifiable || preferEffectReason(effect, a.selected) {
		a.selected = effect
	}
	a.unverifiable = true
}

func (a *tier2Analyzer) collectExternalEffect(effect externalEffect) bool {
	before := len(a.effects)
	a.effects = appendExternalEffect(a.effects, effect)
	return len(a.effects) != before
}

func effectCauseRank(effect externalEffect) int {
	if effect.kind == externalEffectTestRuntime && effect.observable {
		return -1
	}
	if effect.packagePath == "" && effect.kind == externalEffectTestRuntime {
		return 4
	}
	switch effect.kind {
	case externalEffectUnauditedStandard, externalEffectTestRuntime:
		return 0
	case externalEffectFormattedOutput, externalEffectEnvironment:
		return 1
	case externalEffectFileIO:
		return 3
	default:
		return 4
	}
}

func isStandardFallbackExempt(audited bool, pkgPath string) bool {
	return pkgPath == "testing" || isSourceOnlyStandardPackage(audited, pkgPath)
}

func (a *tier2Analyzer) result() tier2Result {
	effects := append([]externalEffect(nil), a.effects...)
	sort.Slice(effects, func(i, j int) bool { return effectLess(effects[i], effects[j]) })
	return tier2Result{effects: effects, widen: a.widen, widenReason: a.widenReason, unverifiable: a.unverifiable, reason: a.selected.reason}
}

func effectLess(a, b externalEffect) bool {
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	if a.packagePath != b.packagePath {
		return a.packagePath < b.packagePath
	}
	if a.symbol != b.symbol {
		return a.symbol < b.symbol
	}
	if a.detail != b.detail {
		return a.detail < b.detail
	}
	if a.reason != b.reason {
		return a.reason < b.reason
	}
	if a.unrefinable != b.unrefinable {
		return b.unrefinable
	}
	return !a.observable && b.observable
}

func classBEffectForFunction(fn *ssa.Function) (externalEffect, bool) {
	if fn == nil {
		return externalEffect{}, false
	}
	return classBEffect(funcPkgPath(fn), functionSymbolName(fn))
}

func classBReasonForFunction(fn *ssa.Function) string {
	effect, ok := classBEffectForFunction(fn)
	if !ok {
		return ""
	}
	return effect.reason
}

func osOpenFileMayMutate(callee *ssa.Function, pkgPath, name string, c *ssa.CallCommon) bool {
	if pkgPath != "os" || name != "OpenFile" {
		return false
	}
	flags, known := openFileFlagsForCallee(callee, c)
	return !known || openFileFlagsMutate(flags)
}

func openFileFlags(c *ssa.CallCommon) (int64, bool) {
	if c == nil {
		return 0, false
	}
	return openFileFlagsForCallee(c.StaticCallee(), c)
}

func openFileFlagsForCallee(callee *ssa.Function, c *ssa.CallCommon) (int64, bool) {
	flagArg := 1
	if callee != nil && callee.Signature != nil && callee.Signature.Recv() != nil {
		flagArg = 2
	}
	if c == nil || len(c.Args) <= flagArg {
		return 0, false
	}
	return constInt(c.Args[flagArg])
}

func openFileFlagsMutate(flags int64) bool {
	const mutatingFlags = int64(os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREATE | os.O_TRUNC)
	return flags&mutatingFlags != 0
}

func ordinaryOpenFileFlagsObservable(flags int64) bool {
	return flags == 0
}

func recognizedOpenFileFlags(callee *ssa.Function, flags int64) bool {
	if callee == nil || callee.Object() == nil || callee.Object().Pkg() == nil {
		return false
	}
	scope := callee.Object().Pkg().Scope()
	var mask int64
	var writeOnly, readWrite int64
	for _, name := range []string{"O_WRONLY", "O_RDWR", "O_APPEND", "O_CREATE", "O_EXCL", "O_SYNC", "O_TRUNC"} {
		object, ok := scope.Lookup(name).(*types.Const)
		if !ok {
			return false
		}
		value, ok := constant.Int64Val(object.Val())
		if !ok {
			return false
		}
		mask |= value
		if name == "O_WRONLY" {
			writeOnly = value
		}
		if name == "O_RDWR" {
			readWrite = value
		}
	}
	access := flags & (writeOnly | readWrite)
	return flags&^mask == 0 && (access == 0 || access == writeOnly || access == readWrite)
}

func syscallOpenMayCreate(pkgPath, name string, c *ssa.CallCommon) bool {
	if pkgPath != "syscall" && pkgPath != "golang.org/x/sys/unix" {
		return false
	}
	flagArg := -1
	switch name {
	case "Open":
		flagArg = 1
	case "Openat":
		flagArg = 2
	default:
		return false
	}
	if c == nil || flagArg >= len(c.Args) {
		return true
	}
	v, ok := c.Args[flagArg].(*ssa.Const)
	if !ok {
		return true
	}
	flags, ok := constant.Int64Val(v.Value)
	if !ok {
		return true
	}
	return flags&int64(os.O_CREATE) != 0
}
