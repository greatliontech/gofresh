package closure

import (
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/go-x-tools/go/ssa/ssautil"
	"github.com/greatliontech/gofresh/internal/auditset"
)

func observableCallEffect(audited bool, effect externalEffect, call *ssa.CallCommon, site ssa.CallInstruction, fp *freshParamAnalysis) bool {
	if call == nil {
		return false
	}
	// Every observation admission below is a toolchain-source claim
	// about the wrapper bodies the producing binary compiles — the
	// admitted os read set's "internal steps solely realize the logged
	// effect", the guard-pinned accessor, the fresh-path helpers — and
	// the producing build shares the analysis' selection
	// (WithBuildFlags is the producing go command's flags). Under an
	// unwalked selection those bodies are unaudited source: no
	// observation admission fires, and every effect keeps its ordinary
	// fail-closed refusal (REQ-closure-observability-toolchain-key). The verdict arrives explicitly — it is
	// a property of the analysis, never of the optional fresh-param
	// value, whose nil keeps meaning exactly "parameter crossing
	// refused" as the crossing helpers state.
	if !audited {
		return false
	}
	// The toolchain accessor is guard-pinned: its value is fixed by the
	// toolchain guard the fingerprint already carries, so branching on
	// it observes nothing the record does not pin. The audited carve-out
	// is this exact symbol — never the runtime package, whose other
	// surfaces stay unaudited; the enforcing precision gate is the
	// maximal tier's exact-GOROOT exemption (the AST scan covers the
	// whole source closure, so any other runtime selector blocks there
	// regardless of this condition — which is why widening this exact
	// match alone is not test-distinguishable).
	if effect.packagePath == "runtime" && effect.symbol == "GOROOT" {
		return true
	}
	if effect.packagePath == "testing" && effect.symbol == "TempDir" {
		return observableFreshPathResult(site, fp)
	}
	if effect.packagePath == "path/filepath" && effect.symbol == "Join" {
		return observableFreshPathResult(site, fp) || observablePinnedPathResult(site)
	}
	if effect.packagePath != "os" {
		return false
	}
	switch effect.symbol {
	case "Getenv", "LookupEnv":
		return observableIdentityArgument(effect, call)
	case "Open":
		return (observableIdentityArgument(effect, call) || guardPinnedPathArgument(call)) && observableOpenResult(site)
	case "OpenFile":
		flags, known := openFileFlags(call)
		if !known || !recognizedOpenFileFlags(call.StaticCallee(), flags) {
			return false
		}
		pathFresh := len(call.Args) != 0 && freshPathValue(call.Args[0], make(map[ssa.Value]bool), fp, nil)
		if !pathFresh && (!ordinaryOpenFileFlagsObservable(flags) || !observableIdentityArgument(effect, call)) {
			return false
		}
		if pathFresh && !freshOpenFileTargetObservable(flags, call.Args[0], site) {
			return false
		}
		return observableOpenResult(site) && observableTupleError(site)
	case "ReadFile":
		return observableIdentityArgument(effect, call) || guardPinnedPathArgument(call) || len(call.Args) != 0 && freshPathValue(call.Args[0], make(map[ssa.Value]bool), fp, nil) && freshReadableTargetObservable(call.Args[0], site)
	case "ReadDir":
		return (observableIdentityArgument(effect, call) || guardPinnedPathArgument(call)) && observableReadDirResult(site)
	case "WriteFile":
		return len(call.Args) >= 2 && freshPathValue(call.Args[0], make(map[ssa.Value]bool), fp, nil) && guardedWriteBytes(call.Args[1], make(map[ssa.Value]bool)) && observableErrorResult(site)
	case "Remove", "RemoveAll":
		return len(call.Args) != 0 && freshPathValue(call.Args[0], make(map[ssa.Value]bool), fp, nil) && freshTargetCreatedBefore(call.Args[0], site) && observableErrorResult(site)
	default:
		return false
	}
}

func observableIdentityArgument(effect externalEffect, call *ssa.CallCommon) bool {
	if call == nil || len(call.Args) == 0 {
		return false
	}
	value, ok := call.Args[0].(*ssa.Const)
	if !ok || value.Value == nil || value.Value.Kind() != constant.String {
		return false
	}
	identity := constant.StringVal(value.Value)
	// The admission proves testlog representability alone: non-empty,
	// valid UTF-8, newline-free. Resolvability — a ".."-carrying identity
	// included — is the runtime observation's obligation: ingest either
	// discharges the traversal's congruence and records the resolved
	// identity, or seals the observation fail-closed
	// (REQ-inputs-path-congruence), so no admitted effect's identity can
	// serve unresolved.
	return identity != "" && utf8.ValidString(identity) && !strings.ContainsAny(identity, "\x00\r\n")
}

func observableFreshPathResult(site ssa.CallInstruction, fp *freshParamAnalysis) bool {
	value, ok := site.(ssa.Value)
	return ok && !blockInCycle(site.Block()) && freshPathValue(value, make(map[ssa.Value]bool), fp, nil) && observableFreshPathUses(value, make(map[ssa.Value]bool), fp, nil)
}

// guardPinnedPathArgument reports whether the call's path argument is a
// guard-pinned toolchain path: the value the read observes is fixed by
// the toolchain guard the fingerprint carries, so the read is inside
// the admitted observation set for READ positions only — mutation
// admissions never accept pinned paths (freshness licenses mutation;
// pinning never does), so a write through such a path blocks on its own
// effect.
func guardPinnedPathArgument(call *ssa.CallCommon) bool {
	return call != nil && len(call.Args) != 0 && guardPinnedPathValue(call.Args[0], make(map[ssa.Value]bool))
}

// guardPinnedPathValue admits exactly the toolchain accessor's result
// and filepath.Join chains rooted at it with safe constant components —
// the same grammar as freshPathValue with the pinned accessor as the
// one root. Any other shape, including a component that is not a safe
// constant, refuses.
func guardPinnedPathValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	call, ok := value.(*ssa.Call)
	if !ok {
		return false
	}
	callee := call.Common().StaticCallee()
	if callee == nil {
		return false
	}
	pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
	if pkgPath == "runtime" && name == "GOROOT" {
		return true
	}
	if pkgPath != "path/filepath" || name != "Join" {
		return false
	}
	args, ok := fixedVariadicArgs(call)
	if !ok || len(args) < 2 || !guardPinnedPathValue(args[0], seen) {
		return false
	}
	for _, arg := range args[1:] {
		if !safeFreshPathComponent(arg) {
			return false
		}
	}
	return true
}

// observablePinnedPathResult admits a filepath.Join whose result is a
// guard-pinned path. Unlike fresh paths, no consumer walk is needed:
// every consumer site classifies its own effect independently, and no
// mutation admission accepts a pinned path, so an escaping write blocks
// there.
func observablePinnedPathResult(site ssa.CallInstruction) bool {
	value, ok := site.(ssa.Value)
	return ok && guardPinnedPathValue(value, make(map[ssa.Value]bool))
}

func freshPathValue(value ssa.Value, seen map[ssa.Value]bool, fp *freshParamAnalysis, inProgress map[freshParamKey]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	if inProgress == nil {
		inProgress = map[freshParamKey]bool{}
	}
	switch value := value.(type) {
	case *ssa.Parameter:
		// A parameter holds a fresh capability when every attributed
		// call site of its function passes one at this position
		// (REQ-inputs-fresh-mutation's boundary extension); its own
		// uses are audited from each origin's uses walk.
		if fp == nil {
			return false
		}
		fn := value.Parent()
		for i, param := range fn.Params {
			if param == value {
				return fp.paramArgFreshMemo(freshParamKey{fn: fn, idx: i}, inProgress)
			}
		}
		return false
	case *ssa.Call:
		callee := value.Common().StaticCallee()
		if callee == nil {
			return false
		}
		pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
		if pkgPath == "testing" && name == "TempDir" {
			return true
		}
		if pkgPath != "path/filepath" || name != "Join" {
			return false
		}
		args, ok := fixedVariadicArgs(value)
		if !ok || len(args) < 2 || !freshPathValue(args[0], seen, fp, inProgress) {
			return false
		}
		for _, arg := range args[1:] {
			if !safeFreshPathComponent(arg) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func observableFreshPathUses(value ssa.Value, seen map[ssa.Value]bool, fp *freshParamAnalysis, inProgress map[freshParamKey]bool) bool {
	if value == nil || seen[value] || value.Referrers() == nil {
		return value != nil
	}
	seen[value] = true
	joinStores := 0
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			joinStores++
			if joinStores > 1 {
				return false
			}
			if ref.Val != value || !freshPathStoreFeedsJoin(ref, value, seen, fp, inProgress) {
				return false
			}
		case ssa.CallInstruction:
			if !observableFreshPathConsumer(ref, value, fp, inProgress) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func observableFreshPathConsumer(site ssa.CallInstruction, pathValue ssa.Value, fp *freshParamAnalysis, inProgress map[freshParamKey]bool) bool {
	if site == nil || site.Common() == nil || site.Common().StaticCallee() == nil {
		return false
	}
	if _, concurrent := site.(*ssa.Go); concurrent {
		return false
	}
	if blockInCycle(site.Block()) {
		return false
	}
	call := site.Common()
	callee := call.StaticCallee()
	pkgPath, name := funcPkgPath(callee), functionSymbolName(callee)
	// Crossing into a static user function is admitted when every
	// attributed call site of the callee passes fresh at the value's
	// positions and the parameter's uses stay within the graph
	// (REQ-inputs-fresh-mutation's boundary extension).
	if fp.boundaryCrossingObservable(site, pathValue, inProgress) {
		return true
	}
	if pkgPath != "os" || len(call.Args) == 0 || call.Args[0] != pathValue {
		return false
	}
	switch name {
	case "ReadFile":
		return freshReadableTargetObservable(pathValue, site)
	case "WriteFile":
		return len(call.Args) >= 2 && guardedWriteBytes(call.Args[1], make(map[ssa.Value]bool)) && observableErrorResult(site)
	case "Remove", "RemoveAll":
		return observableErrorResult(site)
	case "OpenFile":
		flags, known := openFileFlags(call)
		return known && recognizedOpenFileFlags(call.StaticCallee(), flags) && freshOpenFileTargetObservable(flags, pathValue, site) && observableOpenResult(site) && observableTupleError(site)
	default:
		return false
	}
}

func freshPathStoreFeedsJoin(store *ssa.Store, pathValue ssa.Value, seen map[ssa.Value]bool, fp *freshParamAnalysis, inProgress map[freshParamKey]bool) bool {
	address, ok := store.Addr.(*ssa.IndexAddr)
	if !ok {
		return false
	}
	alloc, ok := address.X.(*ssa.Alloc)
	if !ok || alloc.Referrers() == nil {
		return false
	}
	for _, allocRef := range *alloc.Referrers() {
		slice, ok := allocRef.(*ssa.Slice)
		if !ok || slice.Referrers() == nil {
			continue
		}
		for _, sliceRef := range *slice.Referrers() {
			call, ok := sliceRef.(*ssa.Call)
			if !ok || call.Common().StaticCallee() == nil || funcPkgPath(call.Common().StaticCallee()) != "path/filepath" || call.Common().StaticCallee().Name() != "Join" {
				continue
			}
			args, exact := fixedVariadicArgs(call)
			if !exact || len(args) < 2 || args[0] != pathValue {
				continue
			}
			valid := true
			for _, arg := range args[1:] {
				valid = valid && safeFreshPathComponent(arg)
			}
			if valid && observableFreshPathUses(call, seen, fp, inProgress) {
				return true
			}
		}
	}
	return false
}

func fixedVariadicArgs(site *ssa.Call) ([]ssa.Value, bool) {
	if site == nil || site.Common() == nil || len(site.Common().Args) != 1 {
		return nil, false
	}
	slice, ok := site.Common().Args[0].(*ssa.Slice)
	if !ok || slice.X == nil {
		return nil, false
	}
	alloc, ok := slice.X.(*ssa.Alloc)
	if !ok || alloc.Referrers() == nil {
		return nil, false
	}
	pointer, ok := alloc.Type().Underlying().(*types.Pointer)
	if !ok {
		return nil, false
	}
	array, ok := pointer.Elem().Underlying().(*types.Array)
	if !ok || array.Len() < 1 || array.Len() > 64 {
		return nil, false
	}
	args := make([]ssa.Value, int(array.Len()))
	for _, ref := range *alloc.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Slice:
			if ref != slice {
				return nil, false
			}
		case *ssa.IndexAddr:
			index, ok := constInt(ref.Index)
			if !ok || index < 0 || index >= int64(len(args)) || args[index] != nil || ref.Referrers() == nil {
				return nil, false
			}
			var stored ssa.Value
			for _, addressRef := range *ref.Referrers() {
				switch addressRef := addressRef.(type) {
				case *ssa.DebugRef:
				case *ssa.Store:
					if stored != nil || addressRef.Addr != ref {
						return nil, false
					}
					stored = addressRef.Val
				default:
					return nil, false
				}
			}
			if stored == nil {
				return nil, false
			}
			args[index] = stored
		default:
			return nil, false
		}
	}
	for _, arg := range args {
		if arg == nil {
			return nil, false
		}
	}
	if slice.Referrers() == nil {
		return nil, false
	}
	for _, ref := range *slice.Referrers() {
		if call, ok := ref.(*ssa.Call); !ok || call != site {
			if _, debug := ref.(*ssa.DebugRef); !debug {
				return nil, false
			}
		}
	}
	return args, true
}

func safeFreshPathComponent(value ssa.Value) bool {
	constantValue, ok := value.(*ssa.Const)
	if !ok || constantValue.Value == nil || constantValue.Value.Kind() != constant.String {
		return false
	}
	component := constant.StringVal(constantValue.Value)
	if component == "" || component == "." || component == ".." || !utf8.ValidString(component) || strings.TrimRight(component, " .") != component || strings.ContainsAny(component, "\x00\r\n/\\<>:\"|?*") || filepath.VolumeName(component) != "" {
		return false
	}
	for _, r := range component {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	device := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
	switch device {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return false
	}
	return !(len(device) == 4 && (strings.HasPrefix(device, "COM") || strings.HasPrefix(device, "LPT")) && device[3] >= '1' && device[3] <= '9')
}

func freshTargetCreatedBefore(pathValue ssa.Value, site ssa.CallInstruction) bool {
	if freshRootPathValue(pathValue, make(map[ssa.Value]bool)) {
		return true
	}
	return guardedWriteCreatedBefore(pathValue, site)
}

func guardedWriteCreatedBefore(pathValue ssa.Value, site ssa.CallInstruction) bool {
	if pathValue == nil || pathValue.Referrers() == nil || site == nil {
		return false
	}
	for _, ref := range *pathValue.Referrers() {
		call, ok := ref.(*ssa.Call)
		if !ok || call == site || call.Common().StaticCallee() == nil || funcPkgPath(call.Common().StaticCallee()) != "os" || call.Common().StaticCallee().Name() != "WriteFile" {
			continue
		}
		if len(call.Common().Args) >= 2 && call.Common().Args[0] == pathValue && guardedWriteBytes(call.Common().Args[1], make(map[ssa.Value]bool)) && successfulErrorResultDominates(call, site) && noMutationBeforeFreshUse(pathValue, call, site) {
			return true
		}
	}
	return false
}

func freshOpenFileTargetObservable(_ int64, pathValue ssa.Value, site ssa.CallInstruction) bool {
	return guardedWriteCreatedBefore(pathValue, site)
}

func freshReadableTargetObservable(pathValue ssa.Value, site ssa.CallInstruction) bool {
	return guardedWriteCreatedBefore(pathValue, site)
}

func noMutationBeforeFreshUse(pathValue ssa.Value, creator *ssa.Call, use ssa.CallInstruction) bool {
	if pathValue == nil || pathValue.Referrers() == nil || creator == nil || use == nil {
		return false
	}
	values := append([]ssa.Value{pathValue}, freshPathAncestors(pathValue)...)
	for _, value := range values {
		if value == nil || value.Referrers() == nil {
			return false
		}
		for _, ref := range *value.Referrers() {
			call, ok := ref.(ssa.CallInstruction)
			if !ok || call == creator || call == use || !freshPathMutationCall(call) {
				continue
			}
			if !instructionDominates(use, call) {
				return false
			}
		}
	}
	return true
}

func freshPathAncestors(value ssa.Value) []ssa.Value {
	call, ok := value.(*ssa.Call)
	if !ok || call.Common().StaticCallee() == nil || funcPkgPath(call.Common().StaticCallee()) != "path/filepath" || call.Common().StaticCallee().Name() != "Join" {
		return nil
	}
	args, ok := fixedVariadicArgs(call)
	if !ok || len(args) < 2 {
		return nil
	}
	return append([]ssa.Value{args[0]}, freshPathAncestors(args[0])...)
}

func freshPathMutationCall(site ssa.CallInstruction) bool {
	if site == nil || site.Common() == nil || site.Common().StaticCallee() == nil || funcPkgPath(site.Common().StaticCallee()) != "os" {
		return false
	}
	switch site.Common().StaticCallee().Name() {
	case "WriteFile", "Remove", "RemoveAll":
		return true
	case "OpenFile":
		flags, known := openFileFlags(site.Common())
		return !known || flags != 0
	default:
		return false
	}
}

func instructionDominates(before, after ssa.Instruction) bool {
	if before == nil || after == nil || before.Block() == nil || after.Block() == nil {
		return false
	}
	if before.Block() != after.Block() {
		return before.Block().Dominates(after.Block())
	}
	for _, instruction := range before.Block().Instrs {
		if instruction == before {
			return true
		}
		if instruction == after {
			return false
		}
	}
	return false
}

func freshRootPathValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Call:
		callee := value.Common().StaticCallee()
		if callee == nil {
			return false
		}
		return funcPkgPath(callee) == "testing" && functionSymbolName(callee) == "TempDir"
	default:
		return false
	}
}

func blockInCycle(block *ssa.BasicBlock) bool {
	if block == nil {
		return true
	}
	seen := make(map[*ssa.BasicBlock]bool)
	queue := append([]*ssa.BasicBlock(nil), block.Succs...)
	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		if current == block {
			return true
		}
		if current == nil || seen[current] {
			continue
		}
		seen[current] = true
		queue = append(queue, current.Succs...)
	}
	return false
}

func successfulErrorResultDominates(value ssa.Value, use ssa.Instruction) bool {
	if value == nil || value.Referrers() == nil || use == nil || use.Block() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		comparison, ok := ref.(*ssa.BinOp)
		if !ok || (comparison.Op != token.EQL && comparison.Op != token.NEQ) || !isNilComparison(comparison, value) || comparison.Referrers() == nil {
			continue
		}
		for _, comparisonRef := range *comparison.Referrers() {
			branch, ok := comparisonRef.(*ssa.If)
			if !ok || len(branch.Block().Succs) != 2 {
				continue
			}
			success := branch.Block().Succs[0]
			if comparison.Op == token.NEQ {
				success = branch.Block().Succs[1]
			}
			if success == use.Block() || success.Dominates(use.Block()) {
				return true
			}
		}
	}
	return false
}

func guardedWriteBytes(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Convert:
		constantValue, ok := value.X.(*ssa.Const)
		return ok && constantValue.Value != nil && constantValue.Value.Kind() == constant.String
	case *ssa.Slice:
		return guardedWriteBytes(value.X, seen)
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !guardedWriteBytes(edge, cloneValueSet(seen)) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func observableErrorResult(site ssa.CallInstruction) bool {
	value, ok := site.(ssa.Value)
	return ok && boundedErrorValue(value)
}

func observableTupleError(site ssa.CallInstruction) bool {
	value, ok := site.(ssa.Value)
	if !ok || value.Referrers() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		extract, ok := ref.(*ssa.Extract)
		if !ok {
			if _, debug := ref.(*ssa.DebugRef); !debug {
				return false
			}
			continue
		}
		if extract.Index == 1 && !boundedErrorValue(extract) {
			return false
		}
	}
	return true
}

func boundedErrorValue(value ssa.Value) bool {
	if value == nil || value.Referrers() == nil {
		return value != nil
	}
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.BinOp:
			if ref.Op != token.EQL && ref.Op != token.NEQ || !isNilComparison(ref, value) || !boundedBoolValue(ref) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func boundedBoolValue(value ssa.Value) bool {
	if value == nil || value.Referrers() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		switch ref.(type) {
		case *ssa.DebugRef, *ssa.If:
		default:
			return false
		}
	}
	return true
}

func isNilComparison(operation *ssa.BinOp, value ssa.Value) bool {
	if operation == nil {
		return false
	}
	other := operation.X
	if other == value {
		other = operation.Y
	} else if operation.Y != value {
		return false
	}
	constantValue, ok := other.(*ssa.Const)
	return ok && constantValue.IsNil()
}

func constInt(value ssa.Value) (int64, bool) {
	constantValue, ok := value.(*ssa.Const)
	if !ok || constantValue.Value == nil || constantValue.Value.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(constantValue.Value)
}

func cloneValueSet(values map[ssa.Value]bool) map[ssa.Value]bool {
	clone := make(map[ssa.Value]bool, len(values))
	for value := range values {
		clone[value] = true
	}
	return clone
}

func fileValueFromAdmittedOpen(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Extract:
		if value.Index != 0 {
			return false
		}
		call, ok := value.Tuple.(ssa.CallInstruction)
		if !ok || call.Common() == nil || call.Common().StaticCallee() == nil {
			return false
		}
		effect, classified := classBEffect(funcPkgPath(call.Common().StaticCallee()), call.Common().StaticCallee().Name())
		if !classified || effect.packagePath != "os" {
			return false
		}
		switch effect.symbol {
		case "Open":
			return observableIdentityArgument(effect, call.Common()) || guardPinnedPathArgument(call.Common())
		case "OpenFile":
			flags, known := openFileFlags(call.Common())
			if !known || !recognizedOpenFileFlags(call.Common().StaticCallee(), flags) || len(call.Common().Args) == 0 {
				return false
			}
			pathFresh := freshPathValue(call.Common().Args[0], make(map[ssa.Value]bool), nil, nil)
			return pathFresh && freshOpenFileTargetObservable(flags, call.Common().Args[0], call) || ordinaryOpenFileFlagsObservable(flags) && observableIdentityArgument(effect, call.Common())
		default:
			return false
		}
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !fileValueFromAdmittedOpen(edge, seen) {
				return false
			}
		}
		return true
	case *ssa.ChangeType:
		return fileValueFromAdmittedOpen(value.X, seen)
	case *ssa.Convert:
		return fileValueFromAdmittedOpen(value.X, seen)
	default:
		return false
	}
}

func observableOpenResult(site ssa.CallInstruction) bool {
	value, ok := site.(ssa.Value)
	if !ok || value.Referrers() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		extract, ok := ref.(*ssa.Extract)
		if !ok {
			if _, debug := ref.(*ssa.DebugRef); !debug {
				return false
			}
			continue
		}
		if extract.Index == 0 && !observableFileValue(extract, make(map[ssa.Value]bool)) {
			return false
		}
	}
	return true
}

func observableReadDirResult(site ssa.CallInstruction) bool {
	value, ok := site.(ssa.Value)
	if !ok || value.Referrers() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		extract, ok := ref.(*ssa.Extract)
		if !ok {
			if _, debug := ref.(*ssa.DebugRef); !debug {
				return false
			}
			continue
		}
		if extract.Index == 0 && !observableDirEntriesValue(extract, make(map[ssa.Value]bool)) {
			return false
		}
	}
	return true
}

func observableDirEntriesValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] || value.Referrers() == nil {
		return value != nil
	}
	seen[value] = true
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Index:
			if !observableDirEntryValue(ref, make(map[ssa.Value]bool)) {
				return false
			}
		case *ssa.IndexAddr:
			if !observableDirEntryAddress(ref) {
				return false
			}
		case *ssa.Slice:
			if !observableDirEntriesValue(ref, seen) {
				return false
			}
		case *ssa.Phi:
			if !observableDirEntriesValue(ref, seen) {
				return false
			}
		case ssa.CallInstruction:
			if _, concurrent := ref.(*ssa.Go); concurrent {
				return false
			}
			common := ref.Common()
			if common == nil {
				return false
			}
			builtin, ok := common.Value.(*ssa.Builtin)
			if !ok || builtin.Name() != "len" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func observableDirEntryAddress(value ssa.Value) bool {
	if value == nil || value.Referrers() == nil {
		return false
	}
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.UnOp:
			if ref.Op != token.MUL || !observableDirEntryValue(ref, make(map[ssa.Value]bool)) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func observableDirEntryValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] || value.Referrers() == nil {
		return value != nil
	}
	seen[value] = true
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.MakeInterface:
			if !observableDirEntryValue(ref, seen) {
				return false
			}
		case *ssa.ChangeInterface:
			if !observableDirEntryValue(ref, seen) {
				return false
			}
		case *ssa.Phi:
			if !observableDirEntryValue(ref, seen) {
				return false
			}
		case ssa.CallInstruction:
			if !observableDirEntryCall(ref) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func observableDirEntryCall(site ssa.CallInstruction) bool {
	if site == nil || site.Common() == nil || !site.Common().IsInvoke() || site.Common().Method == nil {
		return false
	}
	switch site.Common().Method.Name() {
	case "Name", "IsDir", "Type":
		return dirEntryValueFromAdmittedReadDir(site.Common().Value, make(map[ssa.Value]bool))
	default:
		return false
	}
}

func dirEntryValueFromAdmittedReadDir(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.MakeInterface:
		return dirEntryValueFromAdmittedReadDir(value.X, seen)
	case *ssa.ChangeInterface:
		return dirEntryValueFromAdmittedReadDir(value.X, seen)
	case *ssa.Index:
		return dirEntriesValueFromAdmittedReadDir(value.X, seen)
	case *ssa.UnOp:
		if value.Op != token.MUL {
			return false
		}
		address, ok := value.X.(*ssa.IndexAddr)
		return ok && dirEntriesValueFromAdmittedReadDir(address.X, seen)
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !dirEntryValueFromAdmittedReadDir(edge, seen) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func dirEntriesValueFromAdmittedReadDir(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Extract:
		if value.Index != 0 {
			return false
		}
		call, ok := value.Tuple.(ssa.CallInstruction)
		if !ok || call.Common() == nil || call.Common().StaticCallee() == nil {
			return false
		}
		effect, classified := classBEffect(funcPkgPath(call.Common().StaticCallee()), call.Common().StaticCallee().Name())
		if !classified || effect.packagePath != "os" || effect.symbol != "ReadDir" {
			return false
		}
		return observableIdentityArgument(effect, call.Common()) || guardPinnedPathArgument(call.Common())
	case *ssa.Slice:
		return dirEntriesValueFromAdmittedReadDir(value.X, seen)
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !dirEntriesValueFromAdmittedReadDir(edge, seen) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func observableFileValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] || value.Referrers() == nil {
		return value != nil
	}
	seen[value] = true
	for _, ref := range *value.Referrers() {
		switch ref := ref.(type) {
		case *ssa.DebugRef:
			continue
		case *ssa.Phi:
			if !observableFileValue(ref, seen) {
				return false
			}
		case *ssa.BinOp:
			if (ref.Op != token.EQL && ref.Op != token.NEQ) || !isNilComparison(ref, value) || !boundedBoolValue(ref) {
				return false
			}
		case ssa.CallInstruction:
			if _, concurrent := ref.(*ssa.Go); concurrent {
				return false
			}
			common := ref.Common()
			if common == nil || len(common.Args) == 0 || common.Args[0] != value || !observableFileMethod(common.StaticCallee()) {
				return false
			}
			if common.StaticCallee().Name() == "Name" && fileValueFromFreshOpenFile(value, make(map[ssa.Value]bool)) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func fileValueFromFreshOpenFile(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Extract:
		if value.Index != 0 {
			return false
		}
		call, ok := value.Tuple.(ssa.CallInstruction)
		if !ok || call.Common() == nil || call.Common().StaticCallee() == nil || funcPkgPath(call.Common().StaticCallee()) != "os" || call.Common().StaticCallee().Name() != "OpenFile" || len(call.Common().Args) == 0 {
			return false
		}
		return freshPathValue(call.Common().Args[0], make(map[ssa.Value]bool), nil, nil)
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !fileValueFromFreshOpenFile(edge, cloneValueSet(seen)) {
				return false
			}
		}
		return true
	case *ssa.ChangeType:
		return fileValueFromFreshOpenFile(value.X, seen)
	case *ssa.Convert:
		return fileValueFromFreshOpenFile(value.X, seen)
	default:
		return false
	}
}

func observableFileMethod(fn *ssa.Function) bool {
	if fn == nil || funcPkgPath(fn) != "os" || fn.Signature == nil || fn.Signature.Recv() == nil {
		return false
	}
	receiver := types.TypeString(fn.Signature.Recv().Type(), nil)
	if !strings.Contains(receiver, "os.File") {
		return false
	}
	switch fn.Name() {
	case "Close", "Name", "Read", "ReadAt", "Seek":
		return true
	default:
		return false
	}
}

// locallyClosedDynamicValue is the intraprocedural projection of
// subjectClosedDynamicValue: with no caller-edge analysis, the
// parameter arm fails closed, so only locally constructed values close.
func locallyClosedDynamicValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	return subjectClosedDynamicValue(value, seen, nil)
}

// subjectClosedDynamicValue extends locallyClosedDynamicValue across
// exactly one boundary kind: a parameter is subject-closed when every
// subject-attributed call site of its function passes a subject-closed
// value at its position, so the operand's dynamic types are fully
// determined by the subject's own flow. A load from a global or field
// refuses: analysis is subject-scoped but the process heap is shared,
// so a sibling subject's runtime flow can plant an implementation the
// subject's attributed enumeration cannot see
// (REQ-closure-observability-dispatch
// admission).
func inActiveCallee(fn *ssa.Function, calleeSeen map[*ssa.Function]bool) bool {
	if len(calleeSeen) == 0 {
		return false
	}
	for fn != nil {
		if calleeSeen[fn] {
			return true
		}
		fn = fn.Parent()
	}
	return false
}

func resetWalkState(fp *freshParamAnalysis) *freshParamAnalysis {
	if fp == nil || (fp.stackDepth == nil && fp.rootSeen == nil) {
		return fp
	}
	copied := *fp
	copied.stackDepth = nil
	copied.lowlink = nil
	copied.hasLeaf = nil
	copied.usedSubject = nil
	copied.rootDone = nil
	copied.rootLowlink = nil
	copied.rootHasLeaf = nil
	copied.rootUsedSubject = nil
	copied.rootSeen = nil
	return &copied
}

func subjectClosedDynamicValue(value ssa.Value, seen map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	return closedDynamicValue(value, seen, map[ssa.Value]bool{}, resetWalkState(fp))
}

// closedDynamicValue walks with a gray set (cycle guard — one value
// legitimately feeds several call sites of one parameter, so a
// completed evaluation must not poison the next) and a done memo (a
// completed result is reused, bounding the walk linearly where DAG
// revisits would otherwise re-evaluate exponentially). A refusal forced
// by a gray ancestor memoizes conservatively: deterministic under SSA
// operand order, fail-closed, never a wrong acceptance — gray only ever
// forces false and every combinator is conjunctive.
func closedDynamicValue(value ssa.Value, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	return walkDynamicValue(value, nil, seen, done, fp)
}

type dynamicValueCollector struct {
	funcs          map[*ssa.Function]bool
	types          map[types.Type]bool
	seeds          bool
	visitedStructs map[*types.Named]bool
}

func (c *dynamicValueCollector) collecting() bool {
	return c != nil
}

func (c *dynamicValueCollector) isSeeds() bool {
	return c != nil && c.seeds
}

// walkDynamicValue is the single SSA shape ladder serving the
// closed-value judgment (collect == nil, with a gray seen set and done memo),
// the function-target collector (collect.funcs != nil), the concrete
// interface-type collector (collect.types != nil), and the combined RTA
// seed collector (collect.seeds == true).
func walkDynamicValue(value ssa.Value, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if value == nil {
		return false
	}
	if collect.isSeeds() {
		if value.Type() != nil && !typeMayCarryDynamicTop(fp != nil && fp.selectionAudited, value.Type()) {
			return true
		}
		if fp == nil {
			if seen[value] {
				return true
			}
			seen[value] = true
			walkDynamicValueUncached(value, collect, seen, done, nil)
			return true
		}
		if fp.usedSubject != nil && value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot) {
			*fp.usedSubject = true
		}
		outsideCallee := !inActiveCallee(value.Parent(), fp.calleeSeen)
		inProgScope := outsideCallee && !fp.ignoreContextValuePayload && fp.enumRecvNamed == nil && value.Parent() != fp.enumRoot && value.Parent() != fp.subjectRoot
		if outsideCallee {
			if inProgScope && fp.summary != nil {
				if entry, ok := fp.summary.enumSeedsMemo[value]; ok {
					for _, t := range entry.types {
						collect.types[t] = true
					}
					for _, fn := range entry.funcs {
						collect.funcs[fn] = true
					}
					return true
				}
			}
			if fp.rootSeen != nil {
				if fp.rootSeen[value] {
					return true
				}
				fp.rootSeen[value] = true
				walkDynamicValueUncached(value, collect, seen, done, fp)
				return true
			}
			if seen != nil && seen[value] {
				return true
			}
			topSeedWalk := len(collect.visitedStructs) == 0
			usedSubject := value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot)
			rootFP := *fp
			rootFP.rootSeen = map[ssa.Value]bool{value: true}
			rootFP.usedSubject = &usedSubject
			var subVisited map[*types.Named]bool
			subSeen := seen
			if topSeedWalk {
				subSeen = map[ssa.Value]bool{}
			} else {
				subVisited = collect.visitedStructs
			}
			subCollect := dynamicValueCollector{
				types:          map[types.Type]bool{},
				funcs:          map[*ssa.Function]bool{},
				seeds:          true,
				visitedStructs: subVisited,
			}
			walkDynamicValueUncached(value, &subCollect, subSeen, done, &rootFP)
			if seen != nil {
				seen[value] = true
			}
			if fp.usedSubject != nil && usedSubject {
				*fp.usedSubject = true
			}
			for t := range subCollect.types {
				collect.types[t] = true
			}
			for fn := range subCollect.funcs {
				collect.funcs[fn] = true
			}
			if topSeedWalk && len(subCollect.visitedStructs) > 0 {
				if collect.visitedStructs == nil {
					collect.visitedStructs = map[*types.Named]bool{}
				}
				for s := range subCollect.visitedStructs {
					collect.visitedStructs[s] = true
				}
			}
			if topSeedWalk && inProgScope && fp.summary != nil && !usedSubject && len(fp.calleeSeen) == 0 && len(fp.invokeSeen) == 0 {
				var dedupTypes []types.Type
				if len(subCollect.types) > 0 {
					dedupTypes = make([]types.Type, 0, len(subCollect.types))
					for t := range subCollect.types {
						dedupTypes = append(dedupTypes, t)
					}
				}
				var funcs []*ssa.Function
				if len(subCollect.funcs) > 0 {
					funcs = make([]*ssa.Function, 0, len(subCollect.funcs))
					for fn := range subCollect.funcs {
						funcs = append(funcs, fn)
					}
				}
				fp.summary.enumSeedsMemo[value] = dynamicSeedEntry{
					types: dedupTypes,
					funcs: funcs,
				}
			}
			return true
		}
		if seen[value] {
			return true
		}
		seen[value] = true
		walkDynamicValueUncached(value, collect, seen, done, fp)
		return true
	}
	collecting := collect.collecting()
	if fp == nil {
		if collecting {
			if seen[value] {
				return true
			}
			seen[value] = true
			return walkDynamicValueUncached(value, collect, seen, done, nil)
		}
		if r, ok := done[value]; ok {
			return r
		}
		if seen[value] {
			return false
		}
		seen[value] = true
		defer delete(seen, value)
		r := walkDynamicValueUncached(value, nil, seen, done, nil)
		if done != nil {
			done[value] = r
		}
		return r
	}
	if fp.usedSubject != nil && value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot) {
		*fp.usedSubject = true
	}
	outsideCallee := !inActiveCallee(value.Parent(), fp.calleeSeen)
	inProgScope := outsideCallee && !fp.ignoreContextValuePayload && fp.enumRecvNamed == nil && (fp.enumOnly || fp.enumRoot == nil) && (fp.inProgramSites || fp.inFieldStore || fp.enumOnly) && value.Parent() != fp.enumRoot && value.Parent() != fp.subjectRoot
	if collecting {
		if outsideCallee {
			if inProgScope && fp.summary != nil {
				if collect.types != nil && collect.funcs == nil {
					tMemo, tFail := fp.summary.progTypesMemo, fp.summary.progTypesFailed
					if fp.enumOnly {
						tMemo, tFail = fp.summary.enumTypesMemo, fp.summary.enumTypesFailed
					}
					if tFail[value] {
						return false
					}
					if ts, ok := tMemo[value]; ok {
						for _, t := range ts {
							collect.types[t] = true
						}
						return true
					}
				} else if collect.funcs != nil && collect.types == nil && !fp.enumOnly {
					if fp.summary.progFuncsFailed[value] {
						return false
					}
					if fs, ok := fp.summary.progFuncsMemo[value]; ok {
						for _, fn := range fs {
							collect.funcs[fn] = true
						}
						return true
					}
				}
			}
			if collect.types != nil && collect.funcs == nil {
				if fp.typesFailed != nil && fp.typesFailed[value] {
					return false
				}
				if fp.typesMemo != nil {
					if ts, ok := fp.typesMemo[value]; ok {
						for _, t := range ts {
							collect.types[t] = true
						}
						return true
					}
				}
			} else if collect.funcs != nil && collect.types == nil {
				if fp.funcsFailed != nil && fp.funcsFailed[value] {
					return false
				}
				if fp.funcsMemo != nil {
					if fs, ok := fp.funcsMemo[value]; ok {
						for _, fn := range fs {
							collect.funcs[fn] = true
						}
						return true
					}
				}
			}
			if fp.rootSeen != nil {
				if fp.rootSeen[value] {
					return true
				}
				fp.rootSeen[value] = true
				return walkDynamicValueUncached(value, collect, seen, done, fp)
			}
			usedSubject := value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot)
			rootFP := *fp
			rootFP.rootSeen = map[ssa.Value]bool{value: true}
			rootFP.usedSubject = &usedSubject
			var subCollect dynamicValueCollector
			if collect.types != nil {
				subCollect.types = map[types.Type]bool{}
			}
			if collect.funcs != nil {
				subCollect.funcs = map[*ssa.Function]bool{}
			}
			r := walkDynamicValueUncached(value, &subCollect, seen, done, &rootFP)
			if fp.usedSubject != nil && usedSubject {
				*fp.usedSubject = true
			}
			if r {
				for t := range subCollect.types {
					collect.types[t] = true
				}
				for fn := range subCollect.funcs {
					collect.funcs[fn] = true
				}
			}
			if len(fp.calleeSeen) == 0 && len(fp.invokeSeen) == 0 && len(fp.enumStructVisiting) == 0 {
				if collect.types != nil && collect.funcs == nil {
					if r {
						ts := make([]types.Type, 0, len(subCollect.types))
						for t := range subCollect.types {
							ts = append(ts, t)
						}
						if fp.typesMemo != nil {
							fp.typesMemo[value] = ts
						}
						if inProgScope && fp.summary != nil && !usedSubject {
							tMemo := fp.summary.progTypesMemo
							if fp.enumOnly {
								tMemo = fp.summary.enumTypesMemo
							}
							tMemo[value] = ts
						}
					} else {
						if fp.typesFailed != nil {
							fp.typesFailed[value] = true
						}
						if inProgScope && fp.summary != nil && !usedSubject {
							tFail := fp.summary.progTypesFailed
							if fp.enumOnly {
								tFail = fp.summary.enumTypesFailed
							}
							tFail[value] = true
						}
					}
				} else if collect.funcs != nil && collect.types == nil {
					if r {
						fs := make([]*ssa.Function, 0, len(subCollect.funcs))
						for fn := range subCollect.funcs {
							fs = append(fs, fn)
						}
						if fp.funcsMemo != nil {
							fp.funcsMemo[value] = fs
						}
						if inProgScope && !fp.enumOnly && fp.summary != nil && !usedSubject {
							fp.summary.progFuncsMemo[value] = fs
						}
					} else {
						if fp.funcsFailed != nil {
							fp.funcsFailed[value] = true
						}
						if inProgScope && !fp.enumOnly && fp.summary != nil && !usedSubject {
							fp.summary.progFuncsFailed[value] = true
						}
					}
				}
			}
			return r
		}
		if seen[value] {
			return true
		}
		seen[value] = true
		return walkDynamicValueUncached(value, collect, seen, done, fp)
	}
	if fp.stackDepth == nil {
		var lowlink int
		var hasLeaf, usedSubject bool
		if done == nil {
			done = map[ssa.Value]bool{}
		}
		if seen == nil {
			seen = map[ssa.Value]bool{}
		}
		rootFP := *fp
		rootFP.stackDepth = map[ssa.Value]int{}
		rootFP.lowlink = &lowlink
		rootFP.hasLeaf = &hasLeaf
		rootFP.usedSubject = &usedSubject
		rootFP.rootDone = done
		rootFP.rootLowlink = map[ssa.Value]int{}
		rootFP.rootHasLeaf = map[ssa.Value]bool{}
		rootFP.rootUsedSubject = map[ssa.Value]bool{}
		fp = &rootFP
	}
	if outsideCallee {
		if inProgScope && fp.summary != nil {
			progMemo := fp.summary.progClosedDone
			if fp.enumOnly {
				progMemo = fp.summary.enumClosedDone
			}
			if r, ok := progMemo[value]; ok {
				if r {
					markDynamicLeaf(fp)
				}
				return r
			}
		}
		if fp.closedDone != nil {
			if r, ok := fp.closedDone[value]; ok {
				if r {
					markDynamicLeaf(fp)
				}
				return r
			}
		}
	} else if done != nil {
		if r, ok := done[value]; ok {
			if r {
				markDynamicLeaf(fp)
			}
			return r
		}
	}
	if d, onStack := fp.stackDepth[value]; onStack {
		if fp.selectionAudited && !isTestingTBInterface(value.Type()) {
			if *fp.lowlink == 0 || d < *fp.lowlink {
				*fp.lowlink = d
			}
			return true
		}
		return false
	}
	if outsideCallee && fp.rootDone != nil {
		if r, ok := fp.rootDone[value]; ok {
			if ll := fp.rootLowlink[value]; ll != 0 && (*fp.lowlink == 0 || ll < *fp.lowlink) {
				*fp.lowlink = ll
			}
			if r && fp.rootHasLeaf[value] {
				markDynamicLeaf(fp)
			}
			if fp.rootUsedSubject[value] && fp.usedSubject != nil {
				*fp.usedSubject = true
			}
			return r
		}
	}
	myDepth := fp.baseDepth + len(fp.stackDepth) + 1
	fp.stackDepth[value] = myDepth
	outerLowlink := *fp.lowlink
	*fp.lowlink = 0
	outerHasLeaf := *fp.hasLeaf
	*fp.hasLeaf = false
	outerUsedSubject := *fp.usedSubject
	*fp.usedSubject = value.Parent() != nil && (value.Parent() == fp.enumRoot || value.Parent() == fp.subjectRoot)

	r := walkDynamicValueUncached(value, nil, seen, done, fp)

	delete(fp.stackDepth, value)
	myLowlink := *fp.lowlink
	myHasLeaf := *fp.hasLeaf
	myUsedSubject := *fp.usedSubject
	if myLowlink != 0 && myLowlink >= myDepth {
		if r && !myHasLeaf {
			if fp.selectionAudited && inProgScope && !myUsedSubject {
				myHasLeaf = true
				myUsedSubject = true
			} else {
				r = false
			}
		}
		myLowlink = 0
		if outsideCallee {
			for k, ll := range fp.rootLowlink {
				if ll >= myDepth {
					delete(fp.rootDone, k)
					delete(fp.rootLowlink, k)
					delete(fp.rootHasLeaf, k)
					delete(fp.rootUsedSubject, k)
				}
			}
		}
	}
	*fp.lowlink = outerLowlink
	if myLowlink != 0 && (*fp.lowlink == 0 || myLowlink < *fp.lowlink) {
		*fp.lowlink = myLowlink
	}
	*fp.hasLeaf = outerHasLeaf || (r && myHasLeaf)
	*fp.usedSubject = outerUsedSubject || myUsedSubject

	if myLowlink == 0 {
		if outsideCallee {
			if fp.closedDone != nil && len(fp.enumStructVisiting) == 0 {
				fp.closedDone[value] = r
			}
			if inProgScope && fp.summary != nil && !myUsedSubject && len(fp.enumStructVisiting) == 0 {
				progMemo := fp.summary.progClosedDone
				if fp.enumOnly {
					progMemo = fp.summary.enumClosedDone
				}
				progMemo[value] = r
			}
		} else if done != nil && len(fp.enumStructVisiting) == 0 {
			done[value] = r
		}
	} else if outsideCallee && fp.rootDone != nil {
		fp.rootDone[value] = r
		fp.rootLowlink[value] = myLowlink
		fp.rootHasLeaf[value] = r && myHasLeaf
		fp.rootUsedSubject[value] = myUsedSubject
	}
	return r
}

func markDynamicLeaf(fp *freshParamAnalysis) {
	if fp != nil && fp.hasLeaf != nil {
		*fp.hasLeaf = true
	}
}

func enumUserStructClosed(named *types.Named, fp *freshParamAnalysis) bool {
	if fp == nil || !fp.selectionAudited || named == nil {
		return false
	}
	if fp.enumRecvNamed != nil {
		copied := *fp
		copied.enumRecvNamed = nil
		fp = &copied
	}
	if fp.structPoisoned[structFieldKey{named: named, field: -1}] || !fp.structReferencedByType[named] {
		return false
	}
	if fp.summary != nil && !fp.ignoreContextValuePayload {
		if r, ok := fp.summary.enumStructClosed[named]; ok {
			return r
		}
	}
	if fp.enumStructVisiting[named] {
		return true
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	topLevel := len(fp.enumStructVisiting) == 0
	visiting := make(map[*types.Named]bool, len(fp.enumStructVisiting)+1)
	for k, v := range fp.enumStructVisiting {
		visiting[k] = v
	}
	visiting[named] = true
	usedSubject := false
	for _, wv := range fp.structWholeStores[named] {
		var lowlink int
		var hasLeaf, storeUsedSubject bool
		wholeFP := *resetWalkState(fp)
		wholeFP.inProgramSites = true
		wholeFP.inFieldStore = false
		wholeFP.callBindings = nil
		wholeFP.calleeSeen = nil
		wholeFP.calleeDepth = nil
		wholeFP.invokeSeen = nil
		wholeFP.invokeDepth = nil
		wholeFP.baseDepth = 0
		wholeFP.enumStructVisiting = visiting
		wholeFP.stackDepth = map[ssa.Value]int{}
		wholeFP.lowlink = &lowlink
		wholeFP.hasLeaf = &hasLeaf
		wholeFP.usedSubject = &storeUsedSubject
		wholeFP.rootDone = map[ssa.Value]bool{}
		wholeFP.rootLowlink = map[ssa.Value]int{}
		wholeFP.rootHasLeaf = map[ssa.Value]bool{}
		wholeFP.rootUsedSubject = map[ssa.Value]bool{}
		wholeFP.closedDone = map[ssa.Value]bool{}
		wholeFP.typesMemo = map[ssa.Value][]types.Type{}
		wholeFP.typesFailed = map[ssa.Value]bool{}
		wholeFP.funcsMemo = map[ssa.Value][]*ssa.Function{}
		wholeFP.funcsFailed = map[ssa.Value]bool{}
		wholeFP.invokeTargets = map[ssa.CallInstruction]map[*ssa.Function]bool{}
		wholeFP.invokeFailed = map[ssa.CallInstruction]bool{}
		ok := walkDynamicValue(wv, nil, map[ssa.Value]bool{}, wholeFP.rootDone, &wholeFP)
		if storeUsedSubject {
			usedSubject = true
		}
		if !ok {
			if usedSubject && fp.usedSubject != nil {
				*fp.usedSubject = true
			}
			if topLevel && !usedSubject && fp.summary != nil && !fp.ignoreContextValuePayload {
				fp.summary.enumStructClosed[named] = false
			}
			return false
		}
	}
	for f := 0; f < st.NumFields(); f++ {
		fType := st.Field(f).Type()
		if !typeMayCarryDynamicTop(fp.selectionAudited, fType) {
			continue
		}
		key := structFieldKey{named: named, field: f}
		if fp.structPoisoned[key] {
			if topLevel && fp.summary != nil && !fp.ignoreContextValuePayload {
				fp.summary.enumStructClosed[named] = false
			}
			return false
		}
		if _, isPtr := types.Unalias(fType).(*types.Pointer); !isPtr {
			if innerNamed := derefNamedStruct(fp.userPkgPaths(), fType); innerNamed != nil {
				innerFP := *fp
				innerFP.enumStructVisiting = visiting
				innerUsedSubject := false
				innerFP.usedSubject = &innerUsedSubject
				ok := enumUserStructClosed(innerNamed, &innerFP)
				if innerUsedSubject {
					usedSubject = true
				}
				if !ok {
					if usedSubject && fp.usedSubject != nil {
						*fp.usedSubject = true
					}
					if topLevel && !usedSubject && fp.summary != nil && !fp.ignoreContextValuePayload {
						fp.summary.enumStructClosed[named] = false
					}
					return false
				}
			}
		}
		for _, sv := range fp.structFieldStores[key] {
			var lowlink int
			var hasLeaf, storeUsedSubject bool
			fieldFP := *resetWalkState(fp)
			fieldFP.inFieldStore = true
			fieldFP.callBindings = nil
			fieldFP.calleeSeen = nil
			fieldFP.calleeDepth = nil
			fieldFP.invokeSeen = nil
			fieldFP.invokeDepth = nil
			fieldFP.baseDepth = 0
			fieldFP.enumStructVisiting = visiting
			fieldFP.stackDepth = map[ssa.Value]int{}
			fieldFP.lowlink = &lowlink
			fieldFP.hasLeaf = &hasLeaf
			fieldFP.usedSubject = &storeUsedSubject
			fieldFP.rootDone = map[ssa.Value]bool{}
			fieldFP.rootLowlink = map[ssa.Value]int{}
			fieldFP.rootHasLeaf = map[ssa.Value]bool{}
			fieldFP.rootUsedSubject = map[ssa.Value]bool{}
			fieldFP.closedDone = map[ssa.Value]bool{}
			fieldFP.typesMemo = map[ssa.Value][]types.Type{}
			fieldFP.typesFailed = map[ssa.Value]bool{}
			fieldFP.funcsMemo = map[ssa.Value][]*ssa.Function{}
			fieldFP.funcsFailed = map[ssa.Value]bool{}
			fieldFP.invokeTargets = map[ssa.CallInstruction]map[*ssa.Function]bool{}
			fieldFP.invokeFailed = map[ssa.CallInstruction]bool{}
			ok := walkDynamicValue(sv, nil, map[ssa.Value]bool{}, fieldFP.rootDone, &fieldFP)
			if storeUsedSubject {
				usedSubject = true
			}
			if !ok {
				if usedSubject && fp.usedSubject != nil {
					*fp.usedSubject = true
				}
				if topLevel && !usedSubject && fp.summary != nil && !fp.ignoreContextValuePayload {
					fp.summary.enumStructClosed[named] = false
				}
				return false
			}
		}
	}
	if usedSubject && fp.usedSubject != nil {
		*fp.usedSubject = true
	}
	if topLevel && !usedSubject && fp.summary != nil && !fp.ignoreContextValuePayload {
		fp.summary.enumStructClosed[named] = true
	}
	return true
}

func collectUserStructSeeds(named *types.Named, collect *dynamicValueCollector, fp *freshParamAnalysis) {
	if !collect.isSeeds() || fp == nil || !fp.selectionAudited || named == nil {
		return
	}
	if collect.visitedStructs != nil && collect.visitedStructs[named] {
		return
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return
	}
	if collect.visitedStructs == nil {
		collect.visitedStructs = map[*types.Named]bool{}
	}
	collect.visitedStructs[named] = true
	wholeFP := *fp
	wholeFP.inProgramSites = true
	wholeFP.inFieldStore = false
	wholeFP.callBindings = nil
	wholeFP.calleeSeen = nil
	wholeFP.calleeDepth = nil
	wholeFP.invokeSeen = nil
	wholeFP.invokeDepth = nil
	wholeFP.baseDepth = 0
	for _, wv := range fp.structWholeStores[named] {
		walkDynamicValue(wv, collect, map[ssa.Value]bool{}, nil, &wholeFP)
	}
	fieldFP := *fp
	fieldFP.inFieldStore = true
	fieldFP.callBindings = nil
	fieldFP.calleeSeen = nil
	fieldFP.calleeDepth = nil
	fieldFP.invokeSeen = nil
	fieldFP.invokeDepth = nil
	fieldFP.baseDepth = 0
	for f := 0; f < st.NumFields(); f++ {
		fType := st.Field(f).Type()
		if !typeMayCarryDynamicTop(fp.selectionAudited, fType) {
			continue
		}
		if _, isPtr := types.Unalias(fType).(*types.Pointer); !isPtr {
			if innerNamed := derefNamedStruct(fp.userPkgPaths(), fType); innerNamed != nil {
				collectUserStructSeeds(innerNamed, collect, fp)
			}
		}
		key := structFieldKey{named: named, field: f}
		for _, sv := range fp.structFieldStores[key] {
			walkDynamicValue(sv, collect, map[ssa.Value]bool{}, nil, &fieldFP)
		}
	}
}

func userStructWholeStoresClosed(named *types.Named, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if fp == nil || named == nil {
		return collect.isSeeds()
	}
	if !collect.isSeeds() && fp.structPoisoned[structFieldKey{named: named, field: -1}] {
		return false
	}
	wholeStores := fp.structWholeStores[named]
	if len(wholeStores) == 0 {
		return true
	}
	wholeFP := *fp
	wholeFP.inProgramSites = true
	wholeFP.inFieldStore = false
	wholeFP.callBindings = nil
	wholeFP.calleeSeen = nil
	wholeFP.calleeDepth = nil
	wholeDone := done
	if fp.rootDone != nil {
		wholeDone = fp.rootDone
	}
	if !collect.collecting() {
		savedLeaf := false
		if fp.hasLeaf != nil {
			savedLeaf = *fp.hasLeaf
		}
		for _, wv := range wholeStores {
			if !walkDynamicValue(wv, nil, seen, wholeDone, &wholeFP) {
				return false
			}
		}
		if fp.hasLeaf != nil {
			*fp.hasLeaf = savedLeaf
		}
		return true
	}
	if collect.isSeeds() {
		for _, wv := range wholeStores {
			walkDynamicValue(wv, collect, seen, wholeDone, &wholeFP)
		}
	}
	return true
}

func isTestingTBInterface(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "testing" && named.Obj().Name() == "TB"
}

func isHarnessPointerType(t types.Type) bool {
	ptr, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "testing" {
		return false
	}
	switch named.Obj().Name() {
	case "T", "B", "F", "M":
		return true
	default:
		return false
	}
}

func walkDynamicValueUncached(value ssa.Value, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	collecting := collect.collecting()
	if value != nil && value.Type() != nil {
		audited := fp != nil && fp.selectionAudited
		if !typeMayCarryDynamicTop(audited, value.Type()) {
			if !collecting {
				markDynamicLeaf(fp)
			}
			return true
		}
		if audited && isHarnessPointerType(value.Type()) {
			if !collecting {
				markDynamicLeaf(fp)
				return true
			}
			if collect.types != nil {
				collect.types[value.Type()] = true
				return true
			}
			return false
		}
	}
	recurse := func(next ssa.Value) bool {
		return walkDynamicValue(next, collect, seen, done, fp)
	}
	switch v := value.(type) {
	case *ssa.Builtin:
		if !collecting {
			markDynamicLeaf(fp)
		}
		return !collecting || collect.isSeeds()
	case *ssa.Const:
		if !collecting || v.Value == nil {
			markDynamicLeaf(fp)
			return true
		}
		return collect.isSeeds()
	case *ssa.MakeSlice:
		if collect.isSeeds() {
			if fp != nil && fp.selectionAudited {
				walkMakeSliceIndexedStoresWithFP(v, map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
					recurse(val)
					return true
				})
			}
			return true
		}
		wrote := false
		if !walkMakeSliceIndexedStoresWithFP(v, map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
			wrote = true
			if fp == nil || !fp.selectionAudited {
				return false
			}
			return recurse(val)
		}) {
			return false
		}
		if !wrote {
			if !collecting {
				markDynamicLeaf(fp)
			}
			return !collecting
		}
		return true
	case *ssa.MakeMap:
		if fp == nil || !fp.selectionAudited {
			return collect.isSeeds()
		}
		if !walkMakeMapValuesWithFP(v, map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
			return recurse(val) || collect.isSeeds()
		}) && !collect.isSeeds() {
			return false
		}
		if !collecting {
			markDynamicLeaf(fp)
		}
		return true
	case *ssa.Lookup:
		if fp == nil || !fp.selectionAudited || v.X == nil {
			return collect.isSeeds()
		}
		return recurse(v.X)
	case *ssa.MakeInterface:
		// An interface value pins its dynamic type at this instruction —
		// closed for dispatch enumeration. A FUNCTION laundered through an
		// interface is different: an interface is never invoked as a
		// function (its contents must be asserted back out first), so the
		// walk here is judging the function value's provenance, and the
		// interface hop must not wash the wrapper obligation — recurse.
		if v.X == nil || v.X.Type() == nil {
			return collect.isSeeds()
		}
		if _, isIface := types.Unalias(v.X.Type()).Underlying().(*types.Interface); isIface {
			return collect.isSeeds()
		}
		_, isFunc := types.Unalias(v.X.Type()).Underlying().(*types.Signature)
		audited := fp != nil && fp.selectionAudited
		carriesInner := !isFunc && audited && typeMayCarryDynamicTop(audited, v.X.Type()) && !isHarnessPointerType(v.X.Type()) && !(v.X.Parent() != nil && fp.isStdFunc(v.X.Parent())) && (fp.enumOnly || collect.isSeeds() || stdTypeMayDelegateDynamic(audited, fp.userPkgPaths(), v.X.Type()))
		if collect != nil && collect.types != nil {
			collect.types[v.X.Type()] = true
			if (isFunc && collect.funcs != nil) || (carriesInner && collect.isSeeds()) {
				return recurse(v.X)
			}
			return true
		}
		if isFunc || (collect != nil && collect.funcs != nil) {
			return recurse(v.X)
		}
		if carriesInner && !collecting && fp != nil {
			return recurse(v.X)
		}
		markDynamicLeaf(fp)
		return true
	case *ssa.Function:
		// A synthetic interface-method thunk as a VALUE is never closed:
		// its receiver arrives at call sites the value walk cannot see.
		// Direct static calls to a thunk judge the receiver argument at
		// the site instead and never consult the value walk for it.
		if !collect.isSeeds() && syntheticInterfaceMethodWrapper(v) && len(v.FreeVars) == 0 {
			return false
		}
		if collect != nil {
			if collect.funcs == nil {
				return false
			}
			collect.funcs[v] = true
		}
		markDynamicLeaf(fp)
		return true
	case *ssa.MakeClosure:
		// A synthetic interface-method bound wrapper performs the real
		// dispatch on its captured receiver inside a body no walk scans:
		// the closure value is closed only through its bindings, whatever
		// later carries it to a call site.
		fn, ok := v.Fn.(*ssa.Function)
		wrapFP := fp
		if ok && syntheticInterfaceMethodWrapper(fn) {
			if mObj, mOK := fn.Object().(*types.Func); mOK && isContextCancelMethod(mObj) {
				wrapFP = withIgnoreContextValuePayload(fp)
			}
		}
		if !collecting {
			if ok && syntheticInterfaceMethodWrapper(fn) {
				for _, binding := range v.Bindings {
					if !walkDynamicValue(binding, nil, seen, done, wrapFP) {
						return false
					}
				}
			}
			markDynamicLeaf(fp)
			return true
		}
		if !ok || collect.funcs == nil {
			return collect.isSeeds()
		}
		if syntheticInterfaceMethodWrapper(fn) && wrapFP != nil && wrapFP.selectionAudited {
			if collect.isSeeds() && len(v.Bindings) == 1 {
				walkDynamicValue(v.Bindings[0], collect, seen, done, wrapFP)
			}
			if len(v.Bindings) != 1 || v.Parent() == nil || v.Parent().Prog == nil {
				if collect.isSeeds() {
					collect.funcs[fn] = true
					return true
				}
				return false
			}
			method, ok := fn.Object().(*types.Func)
			if !ok || method == nil {
				if collect.isSeeds() {
					collect.funcs[fn] = true
					return true
				}
				return false
			}
			cts := map[types.Type]bool{}
			subFP := *wrapFP
			subFP.rootSeen = nil
			if !walkDynamicValue(v.Bindings[0], &dynamicValueCollector{types: cts}, map[ssa.Value]bool{}, nil, &subFP) {
				if collect.isSeeds() {
					collect.funcs[fn] = true
					return true
				}
				return false
			}
			targets, ok := resolveConcreteMethodTargets(v.Parent().Prog, v.Bindings[0].Type(), method, cts, wrapFP)
			if !ok {
				if collect.isSeeds() {
					collect.funcs[fn] = true
					return true
				}
				return false
			}
			for t := range targets {
				collect.funcs[t] = true
			}
			return true
		}
		collect.funcs[fn] = true
		return true
	case *ssa.ChangeInterface:
		return recurse(v.X)
	case *ssa.TypeAssert:
		if !collect.isSeeds() && collect != nil && collect.types != nil && fp != nil && fp.selectionAudited && v.AssertedType != nil {
			subTypes := map[types.Type]bool{}
			subCollect := *collect
			subCollect.types = subTypes
			if !walkDynamicValue(v.X, &subCollect, seen, done, fp) {
				return false
			}
			assertedIface, isIface := types.Unalias(v.AssertedType).Underlying().(*types.Interface)
			for ct := range subTypes {
				if isIface {
					if types.Implements(ct, assertedIface) {
						collect.types[ct] = true
					}
				} else if types.AssignableTo(ct, v.AssertedType) || types.Identical(ct, v.AssertedType) {
					collect.types[ct] = true
				}
			}
			return true
		}
		return recurse(v.X)
	case *ssa.ChangeType:
		return recurse(v.X)
	case *ssa.Convert:
		return recurse(v.X)
	case *ssa.Slice:
		if v.X != nil {
			if _, isSlice := types.Unalias(v.X.Type()).Underlying().(*types.Slice); isSlice {
				return recurse(v.X)
			}
			if alloc, ok := v.X.(*ssa.Alloc); ok {
				if cell := cellOf(alloc, map[ssa.Value]bool{}); cell != nil {
					if !collecting {
						if fp != nil && fp.stackDepth != nil {
							if d, onStack := fp.stackDepth[cell]; onStack {
								if fp.selectionAudited {
									if *fp.lowlink == 0 || d < *fp.lowlink {
										*fp.lowlink = d
									}
									return true
								}
								return false
							}
							fp.stackDepth[cell] = fp.stackDepth[value]
							defer delete(fp.stackDepth, cell)
						} else {
							if seen[cell] {
								return false
							}
							seen[cell] = true
							defer delete(seen, cell)
						}
					}
					if !walkLoadCellReferrersWithFP(alloc, fp, recurse) && !collect.isSeeds() {
						return false
					}
					if !collecting {
						markDynamicLeaf(fp)
					}
					return true
				}
			}
		}
		return collect.isSeeds()
	case *ssa.Alloc:
		if fp != nil && fp.selectionAudited && v.Type() != nil {
			stdAlloc := v.Parent() != nil && fp.isStdFunc(v.Parent())
			var userNamed *types.Named
			if !stdAlloc {
				userNamed = derefNamedStruct(fp.userPkgPaths(), v.Type())
			}
			if stdAlloc || (userNamed != nil && !fp.structPoisoned[structFieldKey{named: userNamed, field: -1}]) {
				if !collecting {
					if userNamed != nil && fp.enumOnly && typeMayCarryDynamicTop(fp.selectionAudited, userNamed) {
						if userNamed == fp.enumRecvNamed {
							if fp.usedSubject != nil {
								*fp.usedSubject = true
							}
						} else if !enumUserStructClosed(userNamed, fp) {
							return false
						}
					}
					markDynamicLeaf(fp)
					return true
				}
				if collect.types != nil {
					collect.types[v.Type()] = true
					if userNamed != nil && collect.isSeeds() && typeMayCarryDynamicTop(fp.selectionAudited, userNamed) {
						collectUserStructSeeds(userNamed, collect, fp)
					}
					return true
				}
			}
		}
		return collect.isSeeds()
	case *ssa.Field:
		if fp != nil && (fp.selectionAudited || collect.isSeeds()) && v.X != nil {
			if named := derefNamedStruct(fp.userPkgPaths(), v.X.Type()); named != nil {
				fieldFP := *fp
				fieldFP.inFieldStore = true
				fieldFP.callBindings = nil
				fieldFP.calleeSeen = nil
				fieldFP.calleeDepth = nil
				fieldDone := done
				if fp.rootDone != nil {
					fieldDone = fp.rootDone
				}
				if fp.enumRoot != nil && len(fp.enumRoot.Params) > 0 && v.X == fp.enumRoot.Params[0] && len(fp.enumFieldStores) > 0 {
					if !userStructWholeStoresClosed(named, collect, seen, fieldDone, &fieldFP) && !collect.isSeeds() {
						return false
					}
					stores, ok := fp.enumFieldStores[v.Field]
					if ok && len(stores) == 0 {
						if !collecting {
							markDynamicLeaf(fp)
						}
						return true
					}
					for _, sv := range stores {
						if !walkDynamicValue(sv, collect, seen, fieldDone, &fieldFP) && !collect.isSeeds() {
							return false
						}
					}
					return true
				}
				key := structFieldKey{named: named, field: v.Field}
				if !collect.isSeeds() && (fp.structPoisoned[key] || !fp.structReferencedByType[named]) {
					return false
				}
				if !collecting {
					savedLeaf := false
					if fp.hasLeaf != nil {
						savedLeaf = *fp.hasLeaf
					}
					if !walkDynamicValue(v.X, nil, seen, done, fp) {
						return false
					}
					if fp.hasLeaf != nil {
						*fp.hasLeaf = savedLeaf
					}
				} else if collect.isSeeds() {
					recurse(v.X)
				}
				if !userStructWholeStoresClosed(named, collect, seen, fieldDone, &fieldFP) && !collect.isSeeds() {
					return false
				}
				stores := fp.structFieldStores[key]
				if len(stores) == 0 {
					if !collecting {
						markDynamicLeaf(fp)
					}
					return true
				}
				for _, sv := range stores {
					if !walkDynamicValue(sv, collect, seen, fieldDone, &fieldFP) && !collect.isSeeds() {
						return false
					}
				}
				return true
			}
		}
		return collect.isSeeds()
	case *ssa.Call:
		if b, ok := v.Common().Value.(*ssa.Builtin); ok && b.Name() == "append" {
			for _, arg := range v.Common().Args {
				if !recurse(arg) && !collect.isSeeds() {
					return false
				}
			}
			return walkMakeSliceIndexedStoresWithFP(v, map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
				return fp != nil && fp.selectionAudited && (recurse(val) || collect.isSeeds())
			}) || collect.isSeeds()
		}
		if (collect.isSeeds() || (fp != nil && fp.selectionAudited)) && !v.Common().IsInvoke() && len(v.Common().Args) == 1 {
			if callee := v.Common().StaticCallee(); callee != nil && funcPkgPath(callee) == "slices" && functionSymbolName(callee) == "Clone" {
				if !recurse(v.Common().Args[0]) && !collect.isSeeds() {
					return false
				}
				if fp != nil && fp.selectionAudited {
					return walkMakeSliceIndexedStoresWithFP(v, map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
						return recurse(val) || collect.isSeeds()
					}) || collect.isSeeds()
				}
				return collect.isSeeds()
			}
		}
		if isHarnessContextCall(v, seen, done, fp) {
			if !collecting {
				markDynamicLeaf(fp)
				return true
			}
			if collect != nil && collect.types != nil {
				if ct := harnessCancelCtxType(v); ct != nil {
					collect.types[ct] = true
					return true
				}
			}
			return collect.isSeeds()
		}
		// A gate-passing static call into the property harness yields a
		// closed value: the harness wraps exactly the closed callables
		// the boundary gate judged (rapid.MakeCheck's returned callback
		// feeding the subtest driver is the driving shape).
		if !collecting && propertyHarnessClosedResult(v, fp) {
			markDynamicLeaf(fp)
			return true
		}
		return staticCallResultDynamicValue(v, -1, collect, seen, done, fp) || collect.isSeeds()
	case *ssa.Phi:
		if len(v.Edges) == 0 {
			return collect.isSeeds()
		}
		for _, edge := range v.Edges {
			if !recurse(edge) && !collect.isSeeds() {
				return false
			}
		}
		return true
	case *ssa.Extract:
		if call, ok := v.Tuple.(*ssa.Call); ok {
			if !collecting && propertyHarnessClosedResult(call, fp) {
				markDynamicLeaf(fp)
				return true
			}
			return staticCallResultDynamicValue(call, v.Index, collect, seen, done, fp) || collect.isSeeds()
		}
		return recurse(v.Tuple)
	case *ssa.Parameter:
		if fp != nil {
			if bound, ok := fp.callBindings[v]; ok && bound != nil {
				boundFP := fp
				fn := v.Parent()
				if fn != nil && fp.calleeSeen[fn] {
					copied := *fp
					calleeSeen := make(map[*ssa.Function]bool, len(fp.calleeSeen))
					for k, val := range fp.calleeSeen {
						if k != fn {
							calleeSeen[k] = val
						}
					}
					copied.calleeSeen = calleeSeen
					calleeDepth := make(map[*ssa.Function]int, len(fp.calleeDepth))
					for k, val := range fp.calleeDepth {
						if k != fn {
							calleeDepth[k] = val
						}
					}
					copied.calleeDepth = calleeDepth
					bindings := make(map[*ssa.Parameter]ssa.Value, len(fp.callBindings))
					for k, val := range fp.callBindings {
						if k.Parent() != fn {
							bindings[k] = val
						}
					}
					copied.callBindings = bindings
					boundFP = &copied
				}
				return walkDynamicValue(bound, collect, seen, done, boundFP)
			}
			if fp.enumRecvNamed != nil && fp.enumRoot != nil && len(fp.enumRoot.Params) > 0 && v == fp.enumRoot.Params[0] {
				if !collecting {
					markDynamicLeaf(fp)
					return true
				}
				if collect.types != nil {
					collect.types[v.Type()] = true
					return true
				}
				return collect.isSeeds()
			}
		}
		args, usedProgramSites, ok := attributedParameterArgs(v, fp)
		if !ok {
			if fp != nil && fp.selectionAudited && !fp.enumOnly && fp.enumRoot == nil && (fp.inProgramSites || fp.inFieldStore) {
				fn := v.Parent()
				if fn != nil && fn != fp.enumRoot && fn != fp.subjectRoot && !fp.functions[fn] && !fp.dynamic[fn] && len(fp.callers[fn]) == 0 && !fp.programValueRef[fn] && len(fp.programSites[fn]) == 0 && !initFlowFrame(fn) {
					if fp.usedSubject != nil {
						*fp.usedSubject = true
					}
					markDynamicLeaf(fp)
					return true
				}
			}
			return collect.isSeeds()
		}
		argFP := fp
		argDone := done
		if usedProgramSites && fp != nil {
			if !fp.inProgramSites || len(fp.callBindings) > 0 {
				copied := *fp
				copied.inProgramSites = true
				copied.callBindings = nil
				copied.calleeSeen = nil
				copied.calleeDepth = nil
				argFP = &copied
			}
			if fp.rootDone != nil {
				argDone = fp.rootDone
			}
		}
		for _, arg := range args {
			if !walkDynamicValue(arg, collect, seen, argDone, argFP) && !collect.isSeeds() {
				return false
			}
		}
		return true
	case *ssa.FreeVar:
		bindings, usedProgramSites, ok := attributedFreeVarBindings(v, fp)
		if !ok {
			return collect.isSeeds()
		}
		bindFP := fp
		bindDone := done
		fn := v.Parent()
		if usedProgramSites && fp != nil {
			if !fp.inProgramSites || len(fp.callBindings) > 0 {
				copied := *fp
				copied.inProgramSites = true
				copied.callBindings = nil
				copied.calleeSeen = nil
				copied.calleeDepth = nil
				bindFP = &copied
			}
			if fp.rootDone != nil {
				bindDone = fp.rootDone
			}
		} else if fp != nil && fn != nil && fp.calleeSeen[fn] {
			copied := *fp
			calleeSeen := make(map[*ssa.Function]bool, len(fp.calleeSeen))
			for k, val := range fp.calleeSeen {
				if k != fn {
					calleeSeen[k] = val
				}
			}
			copied.calleeSeen = calleeSeen
			calleeDepth := make(map[*ssa.Function]int, len(fp.calleeDepth))
			for k, val := range fp.calleeDepth {
				if k != fn {
					calleeDepth[k] = val
				}
			}
			copied.calleeDepth = calleeDepth
			cb := make(map[*ssa.Parameter]ssa.Value, len(fp.callBindings))
			for k, val := range fp.callBindings {
				if k.Parent() != fn {
					cb[k] = val
				}
			}
			copied.callBindings = cb
			bindFP = &copied
		}
		for _, b := range bindings {
			if !walkDynamicValue(b, collect, seen, bindDone, bindFP) && !collect.isSeeds() {
				return false
			}
		}
		return true
	case *ssa.UnOp:
		// A load from a closed cell: the recursive local closure's
		// idiom (`var visit func(); visit = func() { visit() }`) calls
		// through the cell the closure captured.
		if v.Op != token.MUL {
			return collect.isSeeds()
		}
		if g, ok := v.X.(*ssa.Global); ok && fp != nil && fp.selectionAudited && (isUnmutatedStandardSentinelGlobalAny(g) || isUnmutatedSentinelGlobal(fp.userPkgPaths(), g)) {
			if !collecting {
				markDynamicLeaf(fp)
				return true
			}
			if collect.types != nil {
				return sentinelGlobalConcreteTypes(g, collect.types) || collect.isSeeds()
			}
			return collect.isSeeds()
		}
		if fa, ok := v.X.(*ssa.FieldAddr); ok && fp != nil {
			fieldFP := *fp
			fieldFP.inFieldStore = true
			fieldFP.callBindings = nil
			fieldFP.calleeSeen = nil
			fieldFP.calleeDepth = nil
			fieldDone := done
			if fp.rootDone != nil {
				fieldDone = fp.rootDone
			}
			if fp.enumRoot != nil && len(fp.enumRoot.Params) > 0 && fa.X == fp.enumRoot.Params[0] && len(fp.enumFieldStores) > 0 {
				if named := derefNamedStruct(fp.userPkgPaths(), fa.X.Type()); named != nil && !userStructWholeStoresClosed(named, collect, seen, fieldDone, &fieldFP) && !collect.isSeeds() {
					return false
				}
				stores, ok := fp.enumFieldStores[fa.Field]
				if ok && len(stores) == 0 {
					if !collecting {
						markDynamicLeaf(fp)
					}
					return true
				}
				for _, sv := range stores {
					if !walkDynamicValue(sv, collect, seen, fieldDone, &fieldFP) && !collect.isSeeds() {
						return false
					}
				}
				return true
			}
			if (fp.selectionAudited || collect.isSeeds()) && fa.X != nil {
				if named := derefNamedStruct(fp.userPkgPaths(), fa.X.Type()); named != nil {
					key := structFieldKey{named: named, field: fa.Field}
					if !collect.isSeeds() && (fp.structPoisoned[key] || !fp.structReferencedByType[named]) {
						return false
					}
					if !collecting {
						savedLeaf := false
						if fp.hasLeaf != nil {
							savedLeaf = *fp.hasLeaf
						}
						if !walkDynamicValue(fa.X, nil, seen, done, fp) {
							return false
						}
						if fp.hasLeaf != nil {
							*fp.hasLeaf = savedLeaf
						}
					} else if collect.isSeeds() {
						recurse(fa.X)
					}
					if !userStructWholeStoresClosed(named, collect, seen, fieldDone, &fieldFP) && !collect.isSeeds() {
						return false
					}
					stores := fp.structFieldStores[key]
					if len(stores) == 0 {
						if !collecting {
							markDynamicLeaf(fp)
						}
						return true
					}
					for _, sv := range stores {
						if !walkDynamicValue(sv, collect, seen, fieldDone, &fieldFP) && !collect.isSeeds() {
							return false
						}
					}
					return true
				}
			}
		}
		if ia, ok := v.X.(*ssa.IndexAddr); ok && ia.X != nil {
			if _, isSlice := types.Unalias(ia.X.Type()).Underlying().(*types.Slice); isSlice {
				return recurse(ia.X)
			}
		}
		if fp != nil && (fp.selectionAudited || collect.isSeeds()) && v.Type() != nil {
			if _, isPtr := types.Unalias(v.Type()).(*types.Pointer); !isPtr {
				if userNamed := derefNamedStruct(fp.userPkgPaths(), v.Type()); userNamed != nil {
					if !collect.isSeeds() && fp.structPoisoned[structFieldKey{named: userNamed, field: -1}] {
						return false
					}
					if !collecting {
						if !recurse(v.X) {
							return false
						}
						if fp.enumOnly && typeMayCarryDynamicTop(fp.selectionAudited, userNamed) {
							if userNamed == fp.enumRecvNamed {
								if fp.usedSubject != nil {
									*fp.usedSubject = true
								}
							} else if !enumUserStructClosed(userNamed, fp) {
								return false
							}
						}
						markDynamicLeaf(fp)
						return true
					}
					if collect.isSeeds() {
						recurse(v.X)
						if typeMayCarryDynamicTop(fp.selectionAudited, userNamed) {
							collectUserStructSeeds(userNamed, collect, fp)
						}
						return true
					}
				}
			}
		}
		cell := cellOf(v.X, map[ssa.Value]bool{})
		if cell == nil {
			return collect.isSeeds()
		}
		if !collecting {
			if fp != nil && fp.stackDepth != nil {
				if d, onStack := fp.stackDepth[cell]; onStack {
					if fp.selectionAudited {
						if *fp.lowlink == 0 || d < *fp.lowlink {
							*fp.lowlink = d
						}
						return true
					}
					return false
				}
				fp.stackDepth[cell] = fp.stackDepth[value]
				defer delete(fp.stackDepth, cell)
			} else {
				if seen[cell] {
					return false
				}
				seen[cell] = true
				defer delete(seen, cell)
			}
		}
		return walkLoadCellReferrersWithFP(v.X, fp, func(val ssa.Value) bool {
			return recurse(val) || collect.isSeeds()
		}) || collect.isSeeds()
	default:
		return collect.isSeeds()
	}
}

func isUnmutatedSentinelGlobal(userPaths map[string]bool, g *ssa.Global) bool {
	if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil || isStdPkgPath(userPaths, g.Pkg.Pkg.Path()) {
		return false
	}
	ptr, ok := types.Unalias(g.Type()).(*types.Pointer)
	if !ok || !types.Identical(ptr.Elem(), types.Universe.Lookup("error").Type()) {
		return false
	}
	initFn := g.Pkg.Func("init")
	if initFn == nil {
		return false
	}
	hasErrorsNew := false
	for _, b := range initFn.Blocks {
		for _, instr := range b.Instrs {
			store, ok := instr.(*ssa.Store)
			if !ok || store.Addr != g {
				continue
			}
			call, ok := store.Val.(*ssa.Call)
			if !ok || call.Common() == nil {
				return false
			}
			callee := call.Common().StaticCallee()
			if callee == nil || funcPkgPath(callee) != "errors" || callee.Name() != "New" {
				return false
			}
			hasErrorsNew = true
		}
	}
	if !hasErrorsNew {
		return false
	}
	return isUnmutatedStandardSentinelGlobal(g, g.Pkg.Pkg.Path(), g.Name())
}

func isUnmutatedStandardSentinelGlobalAny(g *ssa.Global) bool {
	if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil {
		return false
	}
	pkgPath := g.Pkg.Pkg.Path()
	if !auditset.StandardSentinelGlobal(pkgPath, g.Name()) {
		return false
	}
	return isUnmutatedStandardSentinelGlobal(g, pkgPath, g.Name())
}

var (
	mutatedGlobalsMu    sync.Mutex
	mutatedGlobalsCache map[*ssa.Program]map[*ssa.Global]bool
)

func evictMutatedGlobalsCache(prog *ssa.Program) {
	if prog == nil {
		return
	}
	mutatedGlobalsMu.Lock()
	delete(mutatedGlobalsCache, prog)
	mutatedGlobalsMu.Unlock()
}

func mutatedGlobalsCacheLen() int {
	mutatedGlobalsMu.Lock()
	defer mutatedGlobalsMu.Unlock()
	return len(mutatedGlobalsCache)
}

func programMutatedGlobals(prog *ssa.Program) map[*ssa.Global]bool {
	if prog == nil {
		return nil
	}
	mutatedGlobalsMu.Lock()
	if m, ok := mutatedGlobalsCache[prog]; ok {
		mutatedGlobalsMu.Unlock()
		return m
	}
	mutatedGlobalsMu.Unlock()

	mutated := make(map[*ssa.Global]bool)
	var space [16]*ssa.Value
	for fn := range ssautil.AllFunctions(prog) {
		if fn == nil {
			continue
		}
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				for _, op := range instr.Operands(space[:0]) {
					if op == nil {
						continue
					}
					g, ok := (*op).(*ssa.Global)
					if !ok || g == nil || mutated[g] {
						continue
					}
					switch r := instr.(type) {
					case *ssa.DebugRef:
					case *ssa.UnOp:
						if r.Op != token.MUL || r.X != g {
							mutated[g] = true
						}
					case *ssa.Store:
						if r.Addr != g || fn.Pkg != g.Pkg || !initFlowFrame(fn) {
							mutated[g] = true
						}
					default:
						mutated[g] = true
					}
				}
			}
		}
	}

	mutatedGlobalsMu.Lock()
	if mutatedGlobalsCache == nil || len(mutatedGlobalsCache) >= 8 {
		mutatedGlobalsCache = make(map[*ssa.Program]map[*ssa.Global]bool, 8)
	}
	mutatedGlobalsCache[prog] = mutated
	mutatedGlobalsMu.Unlock()
	return mutated
}

func isUnmutatedStandardSentinelGlobal(g *ssa.Global, wantPkg, wantName string) bool {
	if g == nil || g.Pkg == nil || g.Pkg.Pkg == nil || g.Pkg.Prog == nil || g.Pkg.Pkg.Path() != wantPkg || g.Name() != wantName {
		return false
	}
	return !programMutatedGlobals(g.Pkg.Prog)[g]
}

func sentinelGlobalConcreteTypes(g *ssa.Global, out map[types.Type]bool) bool {
	if g == nil || g.Pkg == nil {
		return false
	}
	if ptr, ok := types.Unalias(g.Type()).(*types.Pointer); ok {
		if _, isIface := ptr.Elem().Underlying().(*types.Interface); !isIface {
			out[ptr.Elem()] = true
			return true
		}
	}
	initFn := g.Pkg.Func("init")
	if initFn == nil {
		return false
	}
	found := false
	for _, b := range initFn.Blocks {
		for _, instr := range b.Instrs {
			store, ok := instr.(*ssa.Store)
			if !ok || store.Addr != g {
				continue
			}
			if mi, ok := store.Val.(*ssa.MakeInterface); ok && mi.X != nil {
				out[mi.X.Type()] = true
				found = true
			} else if call, ok := store.Val.(*ssa.Call); ok && call.Common() != nil {
				if callee := call.Common().StaticCallee(); callee != nil {
					for _, cb := range callee.Blocks {
						for _, cinstr := range cb.Instrs {
							if ret, ok := cinstr.(*ssa.Return); ok && len(ret.Results) == 1 {
								if mi, ok := ret.Results[0].(*ssa.MakeInterface); ok && mi.X != nil {
									out[mi.X.Type()] = true
									found = true
								}
							}
						}
					}
				}
			}
		}
	}
	return found
}

func isAuditedStandardOrDelegatePackage(audited bool, pkgPath string) bool {
	return isSourceOnlyStandardPackage(audited, pkgPath) || (audited && pureDelegatePackages[pkgPath])
}

func stdTypeMayDelegateDynamic(audited bool, userPaths map[string]bool, t types.Type) bool {
	if t == nil {
		return true
	}
	base := types.Unalias(t)
	if ptr, ok := base.(*types.Pointer); ok {
		base = types.Unalias(ptr.Elem())
	}
	named, ok := base.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return true
	}
	if _, ok := AuditedAtomicPointerElem(audited, named); ok {
		return true
	}
	if _, isStruct := named.Underlying().(*types.Struct); !isStruct {
		return true
	}
	pkgPath := named.Obj().Pkg().Path()
	if !isStdPkgPath(userPaths, pkgPath) {
		return true
	}
	if isAuditedStandardOrDelegatePackage(audited, pkgPath) {
		return true
	}
	switch pkgPath {
	case "context", "math/rand", "net/url", "sync":
		return true
	default:
		return false
	}
}

func liveCalleeBlocks(fn *ssa.Function) []*ssa.BasicBlock {
	if fn == nil || len(fn.Blocks) == 0 {
		return nil
	}
	seen := make(map[*ssa.BasicBlock]bool, len(fn.Blocks))
	queue := []*ssa.BasicBlock{fn.Blocks[0]}
	seen[fn.Blocks[0]] = true
	for i := 0; i < len(queue); i++ {
		b := queue[i]
		if len(b.Instrs) > 0 {
			if ifInstr, ok := b.Instrs[len(b.Instrs)-1].(*ssa.If); ok && len(b.Succs) == 2 {
				if c, ok := ifInstr.Cond.(*ssa.Const); ok && c.Value != nil && c.Value.Kind() == constant.Bool {
					succ := b.Succs[1]
					if constant.BoolVal(c.Value) {
						succ = b.Succs[0]
					}
					if !seen[succ] {
						seen[succ] = true
						queue = append(queue, succ)
					}
					continue
				}
			}
		}
		for _, succ := range b.Succs {
			if !seen[succ] {
				seen[succ] = true
				queue = append(queue, succ)
			}
		}
	}
	if fn.Recover != nil && !seen[fn.Recover] {
		queue = append(queue, fn.Recover)
	}
	return queue
}

// staticCallResultDynamicValue steps through a static call's returned SSA
// expressions when the callee belongs to the audited standard-library
// surface or is a reached in-module function whose body is already scanned
// in the subject's reachability cone, and every dynamic-carrying argument is
// itself closed under the walk. This closes standard iterator constructors
// (strings.SplitSeq), pure constructors returning interfaces (crypto/sha256.New,
// strings.NewReader, bytes.NewReader), timerless context constructors
// (context.Background, context.WithCancel, context.WithValue,
// context.WithoutCancel), and reached in-module iterator/constructor helpers
// (REQ-closure-observability-dispatch).
func staticCallResultDynamicValue(call *ssa.Call, tupleIndex int, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if fp == nil || !fp.selectionAudited || call == nil || call.Common() == nil {
		return false
	}
	fp = contextCancelMethodFP(call, fp)
	if call.Common().IsInvoke() {
		if fp.invokeSeen[call] {
			if fp.lowlink != nil {
				if d := fp.invokeDepth[call]; d > 0 && (*fp.lowlink == 0 || d < *fp.lowlink) {
					*fp.lowlink = d
				}
			}
			return fp.selectionAudited
		}
		invokeFP := *fp
		invokeSeen := make(map[ssa.CallInstruction]bool, len(fp.invokeSeen)+1)
		for k, v := range fp.invokeSeen {
			invokeSeen[k] = v
		}
		invokeSeen[call] = true
		invokeFP.invokeSeen = invokeSeen
		invokeDepth := make(map[ssa.CallInstruction]int, len(fp.invokeDepth)+1)
		for k, v := range fp.invokeDepth {
			invokeDepth[k] = v
		}
		depth := fp.baseDepth + len(fp.stackDepth) + 1
		invokeDepth[call] = depth
		invokeFP.invokeDepth = invokeDepth
		invokeFP.baseDepth = depth
		targets, ok := closedInvokeTargets(call, &invokeFP)
		if !ok || (len(targets) == 0 && !fp.selectionAudited) {
			return false
		}
		if len(targets) == 0 {
			if !collect.collecting() {
				markDynamicLeaf(fp)
			}
			return !collect.isSeeds()
		}
		if collect.isSeeds() {
			for _, arg := range call.Common().Args {
				if arg == nil {
					return false
				}
				walkDynamicValue(arg, collect, seen, done, &invokeFP)
			}
		}
		var ordered []*ssa.Function
		for callee := range targets {
			ordered = append(ordered, callee)
		}
		slices.SortFunc(ordered, func(a, b *ssa.Function) int { return strings.Compare(a.String(), b.String()) })
		for _, callee := range ordered {
			callArgs := append([]ssa.Value{call.Common().Value}, call.Common().Args...)
			if !calleeResultDynamicValue(call, callee, callArgs, tupleIndex, collect, seen, done, &invokeFP) && !collect.isSeeds() {
				return false
			}
		}
		return true
	}
	callee := call.Common().StaticCallee()
	if tupleIndex == 1 && callee != nil && funcPkgPath(callee) == "context" && (callee.Name() == "WithCancel" || callee.Name() == "WithCancelCause") {
		fp = withIgnoreContextValuePayload(fp)
	}
	return calleeResultDynamicValue(call, callee, call.Common().Args, tupleIndex, collect, seen, done, fp)
}

func calleeResultDynamicValue(call *ssa.Call, callee *ssa.Function, callArgs []ssa.Value, tupleIndex int, collect *dynamicValueCollector, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if callee == nil || (callee.Synthetic != "" && callee.Origin() == nil && !isPromotedWrapper(callee) && !strings.HasPrefix(callee.Synthetic, "wrapper ")) || len(callee.Blocks) == 0 || !calleeFreeVarsClosed(callee, fp) {
		return false
	}
	if fp.calleeSeen[callee] {
		if fp.lowlink != nil {
			if d := fp.calleeDepth[callee]; d > 0 && (*fp.lowlink == 0 || d < *fp.lowlink) {
				*fp.lowlink = d
			}
		}
		return fp.selectionAudited
	}
	if callee == fp.enumRoot || callee == fp.subjectRoot {
		if fp.usedSubject != nil {
			*fp.usedSubject = true
		}
	}
	pkgPath := funcPkgPath(callee)
	if fp.isStdFunc(callee) {
		if (!collect.isSeeds() && pkgPath == "math/rand") || (!isAuditedStandardOrDelegatePackage(fp.selectionAudited, pkgPath) && !auditedStandardCallee(fp.selectionAudited, pkgPath, functionSymbolName(callee), callee)) {
			return false
		}
	} else {
		if (!fp.functions[callee] && !fp.programFunctions[callee]) || callee == fp.enumRoot || (callee.Signature.Variadic() && !fp.selectionAudited && !fp.inFieldStore && !fp.inProgramSites) || propertyHarnessPath(pkgPath) {
			return false
		}
		if fp.enumOnly && !collect.isSeeds() {
			var retType types.Type = call.Type()
			if tupleIndex >= 0 {
				if tup, ok := call.Type().(*types.Tuple); ok && tupleIndex < tup.Len() {
					retType = tup.At(tupleIndex).Type()
				}
			}
			if retType != nil {
				if _, isSig := types.Unalias(retType).Underlying().(*types.Signature); isSig {
					return false
				}
			}
		}
	}
	if len(callArgs) != len(callee.Params) {
		return false
	}
	for i, arg := range callArgs {
		if arg == nil {
			return false
		}
		if call.Common().IsInvoke() && i == 0 && !collect.isSeeds() {
			continue
		}
		if fp != nil && fp.ignoreContextValuePayload && !fp.enumOnly && !collect.isSeeds() && !calleeParamMayAffectResult(fp, callee, i) {
			continue
		}
		if !fp.isStdFunc(callee) {
			if named := derefNamedStruct(fp.userPkgPaths(), arg.Type()); named != nil {
				paramSupplies := len(callee.Blocks) == 0 || callee.Synthetic != "" || parameterizedBody(callee) || paramMaySupplyDynamicSeen(fp.selectionAudited, fp.userPkgPaths(), callee.Params[i], nil, make(map[*ssa.Parameter]bool))
				if !collect.collecting() && paramSupplies && typeMayCarryDynamicTop(fp.selectionAudited, named) {
					savedLeaf := false
					if fp.hasLeaf != nil {
						savedLeaf = *fp.hasLeaf
					}
					if !walkDynamicValue(arg, nil, seen, done, fp) {
						return false
					}
					if fp.hasLeaf != nil {
						*fp.hasLeaf = savedLeaf
					}
					if fp.enumOnly {
						if named == fp.enumRecvNamed {
							if fp.usedSubject != nil {
								*fp.usedSubject = true
							}
						} else if !enumUserStructClosed(named, fp) {
							return false
						}
					}
				}
				if collect.isSeeds() && typeMayCarryDynamicTop(fp.selectionAudited, named) {
					walkDynamicValue(arg, collect, seen, done, fp)
					collectUserStructSeeds(named, collect, fp)
				}
				continue
			}
		}
		if !collect.collecting() && typeMayCarryDynamicTop(fp.selectionAudited, arg.Type()) {
			savedLeaf := false
			if fp.hasLeaf != nil {
				savedLeaf = *fp.hasLeaf
			}
			if !walkDynamicValue(arg, nil, seen, done, fp) {
				return false
			}
			if fp.hasLeaf != nil {
				*fp.hasLeaf = savedLeaf
			}
		} else if collect.isSeeds() {
			walkDynamicValue(arg, collect, seen, done, fp)
		} else if collect.collecting() && ((i == 0 && funcPkgPath(callee) == "context" && callee.Name() == "WithValue") || isAuditedIOWrapperArg(callee, i)) {
			if !walkDynamicValue(arg, collect, seen, done, fp) {
				return false
			}
		}
	}
	calleeFP := *fp
	calleeSeen := make(map[*ssa.Function]bool, len(fp.calleeSeen)+1)
	for k, v := range fp.calleeSeen {
		calleeSeen[k] = v
	}
	calleeSeen[callee] = true
	calleeFP.calleeSeen = calleeSeen
	calleeDepth := make(map[*ssa.Function]int, len(fp.calleeDepth)+1)
	for k, v := range fp.calleeDepth {
		calleeDepth[k] = v
	}
	depth := fp.baseDepth + len(fp.stackDepth) + 1
	calleeDepth[callee] = depth
	calleeFP.calleeDepth = calleeDepth
	calleeFP.baseDepth = depth
	bindings := make(map[*ssa.Parameter]ssa.Value, len(fp.callBindings)+len(callee.Params))
	for k, v := range fp.callBindings {
		bindings[k] = v
	}
	for i, p := range callee.Params {
		bindings[p] = callArgs[i]
	}
	calleeFP.callBindings = bindings
	var calleeDone, calleeSeenMap map[ssa.Value]bool
	if !collect.collecting() {
		calleeDone = map[ssa.Value]bool{}
		calleeSeenMap = seen
	} else {
		calleeSeenMap = make(map[ssa.Value]bool, len(seen))
		for k, v := range seen {
			if v && k != nil && k.Parent() != callee {
				calleeSeenMap[k] = true
			}
		}
	}
	hasReturn := false
	for _, block := range liveCalleeBlocks(callee) {
		for _, instr := range block.Instrs {
			ret, ok := instr.(*ssa.Return)
			if !ok {
				continue
			}
			var res ssa.Value
			if tupleIndex < 0 {
				if len(ret.Results) != 1 {
					if collect.isSeeds() {
						continue
					}
					return false
				}
				res = ret.Results[0]
			} else {
				if tupleIndex < 0 || tupleIndex >= len(ret.Results) {
					if collect.isSeeds() {
						continue
					}
					return false
				}
				res = ret.Results[tupleIndex]
			}
			if block == callee.Recover && isSyntheticRecoverZeroConst(res) {
				continue
			}
			hasReturn = true
			if !walkDynamicValue(res, collect, calleeSeenMap, calleeDone, &calleeFP) && !collect.isSeeds() {
				return false
			}
			if res != nil && res.Type() != nil {
				if _, isSlice := types.Unalias(res.Type()).Underlying().(*types.Slice); isSlice {
					retIdx := tupleIndex
					if retIdx < 0 {
						retIdx = 0
					}
					if !walkCallResultSliceStoresWithFP(call, retIdx, len(ret.Results), map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
						return fp != nil && fp.selectionAudited && (walkDynamicValue(val, collect, seen, done, fp) || collect.isSeeds())
					}) && !collect.isSeeds() {
						return false
					}
				} else if _, isMap := types.Unalias(res.Type()).Underlying().(*types.Map); isMap {
					retIdx := tupleIndex
					if retIdx < 0 {
						retIdx = 0
					}
					if !walkCallResultMapValuesWithFP(call, retIdx, len(ret.Results), map[ssa.Value]bool{}, fp, func(val ssa.Value) bool {
						return fp != nil && fp.selectionAudited && (walkDynamicValue(val, collect, seen, done, fp) || collect.isSeeds())
					}) && !collect.isSeeds() {
						return false
					}
				}
			}
		}
	}
	return hasReturn || collect.isSeeds()
}

func walkCallResultSliceStoresWithFP(site ssa.CallInstruction, retIdx, numResults int, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	callVal, ok := site.(ssa.Value)
	if !ok || callVal == nil {
		return true
	}
	if numResults <= 1 {
		return walkMakeSliceIndexedStoresWithFP(callVal, visited, fp, walkVal)
	}
	if callVal.Referrers() == nil {
		return true
	}
	for _, ref := range *callVal.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Extract:
			if r.Tuple != callVal {
				return false
			}
			if r.Index == retIdx && !walkMakeSliceIndexedStoresWithFP(r, visited, fp, walkVal) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func walkCallResultMapValuesWithFP(site ssa.CallInstruction, retIdx, numResults int, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	callVal, ok := site.(ssa.Value)
	if !ok || callVal == nil {
		return true
	}
	if numResults <= 1 {
		return walkMakeMapValuesWithFP(callVal, visited, fp, walkVal)
	}
	if callVal.Referrers() == nil {
		return true
	}
	for _, ref := range *callVal.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Extract:
			if r.Tuple != callVal {
				return false
			}
			if r.Index == retIdx && !walkMakeMapValuesWithFP(r, visited, fp, walkVal) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func calleeFreeVarsClosed(callee *ssa.Function, fp *freshParamAnalysis) bool {
	if callee == nil {
		return false
	}
	if len(callee.FreeVars) == 0 {
		return true
	}
	if fp == nil || !fp.selectionAudited {
		return false
	}
	for _, fv := range callee.FreeVars {
		if cellOf(fv, map[ssa.Value]bool{}) != nil {
			continue
		}
		if _, _, ok := attributedFreeVarBindings(fv, fp); !ok {
			return false
		}
	}
	return true
}

func isSyntheticRecoverZeroConst(res ssa.Value) bool {
	c, ok := res.(*ssa.Const)
	return ok && c.Value == nil
}

func isAuditedIOWrapperArg(callee *ssa.Function, argIdx int) bool {
	if callee == nil || funcPkgPath(callee) != "io" {
		return false
	}
	switch callee.Name() {
	case "NopCloser", "LimitReader", "MultiReader", "MultiWriter":
		return argIdx == 0
	case "TeeReader":
		return argIdx == 0 || argIdx == 1
	default:
		return false
	}
}

func calleeParamMayAffectResult(fp *freshParamAnalysis, callee *ssa.Function, idx int) bool {
	audited := fp != nil && fp.selectionAudited
	if !audited || callee == nil || idx < 0 || idx >= len(callee.Params) {
		return true
	}
	if funcPkgPath(callee) == "context" && callee.Name() == "WithValue" {
		return idx == 0
	}
	if !fp.isStdFunc(callee) {
		if len(callee.Blocks) == 0 || callee.Synthetic != "" || parameterizedBody(callee) {
			return true
		}
		return paramFlowsOutsideContextValuePayload(fp, callee.Params[idx], make(map[ssa.Value]bool))
	}
	return true
}

func paramFlowsOutsideContextValuePayload(fp *freshParamAnalysis, val ssa.Value, seen map[ssa.Value]bool) bool {
	audited := fp != nil && fp.selectionAudited
	if val == nil {
		return true
	}
	if seen[val] {
		return false
	}
	seen[val] = true
	refs := val.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return true
			}
		case *ssa.Field:
			if r.X != val {
				return true
			}
			if carrierFreeValueUses(audited, r, nil) {
				continue
			}
			if paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.FieldAddr:
			if r.X != val {
				return true
			}
			if carrierFreeFieldAddr(audited, r, nil) {
				continue
			}
			if paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.Store:
			if r.Val != val || r.Addr == val {
				return true
			}
			var alloc *ssa.Alloc
			switch a := r.Addr.(type) {
			case *ssa.Alloc:
				alloc = a
			case *ssa.FieldAddr:
				alloc, _ = a.X.(*ssa.Alloc)
			}
			if alloc == nil || allocFlowsOutsideContextValuePayload(fp, alloc, seen) {
				return true
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != val || paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.MakeInterface:
			if r.X != val || paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.ChangeInterface:
			if r.X != val || paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.Phi:
			if paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case ssa.CallInstruction:
			if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil || r.Common().IsInvoke() {
				return true
			}
			subCallee := r.Common().StaticCallee()
			if subCallee == nil || len(r.Common().Args) != len(subCallee.Params) {
				return true
			}
			for i, arg := range r.Common().Args {
				if arg == val && calleeParamMayAffectResult(fp, subCallee, i) {
					return true
				}
			}
		default:
			return true
		}
	}
	return false
}

func allocFlowsOutsideContextValuePayload(fp *freshParamAnalysis, alloc *ssa.Alloc, seen map[ssa.Value]bool) bool {
	if alloc == nil {
		return true
	}
	if seen[alloc] {
		return false
	}
	seen[alloc] = true
	refs := alloc.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Addr != alloc {
				return true
			}
		case *ssa.FieldAddr:
			if r.X != alloc || r.Referrers() == nil {
				return true
			}
			for _, fref := range *r.Referrers() {
				switch fr := fref.(type) {
				case *ssa.DebugRef:
				case *ssa.Store:
					if fr.Addr != r {
						return true
					}
				case *ssa.UnOp:
					if fr.Op != token.MUL || fr.X != r || paramFlowsOutsideContextValuePayload(fp, fr, seen) {
						return true
					}
				default:
					return true
				}
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != alloc || paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		case *ssa.MakeInterface:
			if r.X != alloc || paramFlowsOutsideContextValuePayload(fp, r, seen) {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// cellOf resolves a load's address to the local allocation it names —
// the allocation itself, or a free variable bound to it by every
// closure creation of its function (a free variable bound to different
// cells across creations names none). Nothing else is a cell.
func cellOf(addr ssa.Value, seen map[ssa.Value]bool) *ssa.Alloc {
	switch a := addr.(type) {
	case *ssa.Alloc:
		return a
	case *ssa.FieldAddr:
		return cellOf(a.X, seen)
	case *ssa.IndexAddr:
		return cellOf(a.X, seen)
	case *ssa.FreeVar:
		if seen[a] {
			return nil
		}
		seen[a] = true
		var cell *ssa.Alloc
		index := slices.Index(a.Parent().FreeVars, a)
		if index < 0 {
			return nil
		}
		for _, mk := range closureCreations(a.Parent()) {
			// A creation binding this free variable to a different cell
			// than another creation did names none: one closure body,
			// two cells — the fail-closed backstop no fixture
			// constructs.
			if index >= len(mk.Bindings) {
				return nil
			}
			bound := cellOf(mk.Bindings[index], seen)
			if bound == nil || (cell != nil && bound != cell) {
				return nil
			}
			cell = bound
		}
		return cell
	}
	return nil
}

// closureCreations lists the MakeClosure instructions creating fn.
func closureCreations(fn *ssa.Function) []*ssa.MakeClosure {
	var creations []*ssa.MakeClosure
	if fn == nil || fn.Parent() == nil {
		return nil
	}
	for _, block := range fn.Parent().Blocks {
		for _, instr := range block.Instrs {
			if mk, ok := instr.(*ssa.MakeClosure); ok && mk.Fn == fn {
				creations = append(creations, mk)
			}
		}
	}
	return creations
}

// walkLoadCellReferrers walks every referrer of the local cell backing loadAddr,
// failing closed on any address escape or non-zero whole-struct overwrite when
// loadAddr selects a specific field, and applying walkVal only to stores that
// can populate loadAddr.
func walkLoadCellReferrers(loadAddr ssa.Value, walkVal func(ssa.Value) bool) bool {
	return walkLoadCellReferrersWithFP(loadAddr, nil, walkVal)
}

func walkLoadCellReferrersWithFP(loadAddr ssa.Value, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	cell := cellOf(loadAddr, map[ssa.Value]bool{})
	if cell == nil {
		return false
	}
	if fa, ok := loadAddr.(*ssa.FieldAddr); ok {
		if _, isFV := fa.X.(*ssa.FreeVar); fa.X == cell || isFV {
			return walkCellFieldReferrersWithFP(cell, fa.Field, map[ssa.Value]bool{}, fp, walkVal)
		}
	}
	return walkCellReferrersWithFP(cell, map[ssa.Value]bool{}, fp, walkVal)
}

func walkCellFieldReferrersWithFP(cell *ssa.Alloc, fieldIdx int, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if visited[cell] {
		return true
	}
	visited[cell] = true
	refs := cell.Referrers()
	if refs == nil {
		return true
	}
	noEscapeOnly := func(ssa.Value) bool { return true }
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Addr != cell {
				return false
			}
			c, isZero := r.Val.(*ssa.Const)
			if !isZero || c.Value != nil {
				return false
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != cell {
				return false
			}
		case *ssa.FieldAddr:
			if r.X != cell {
				return false
			}
			cb := noEscapeOnly
			if r.Field == fieldIdx {
				cb = walkVal
			}
			if !walkCellReferrersWithFP(r, visited, fp, cb) {
				return false
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok {
				return false
			}
			for i, b := range r.Bindings {
				if b == cell {
					if i >= len(fn.FreeVars) || !walkFreeVarFieldReferrersWithFP(fn.FreeVars[i], fieldIdx, visited, fp, walkVal) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func walkFreeVarFieldReferrersWithFP(fv *ssa.FreeVar, fieldIdx int, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if visited[fv] {
		return true
	}
	visited[fv] = true
	refs := fv.Referrers()
	if refs == nil {
		return true
	}
	noEscapeOnly := func(ssa.Value) bool { return true }
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Addr != fv {
				return false
			}
			c, isZero := r.Val.(*ssa.Const)
			if !isZero || c.Value != nil {
				return false
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != fv {
				return false
			}
		case *ssa.FieldAddr:
			if r.X != fv {
				return false
			}
			cb := noEscapeOnly
			if r.Field == fieldIdx {
				cb = walkVal
			}
			if !walkCellReferrersWithFP(r, visited, fp, cb) {
				return false
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok {
				return false
			}
			for i, b := range r.Bindings {
				if b == fv {
					if i >= len(fn.FreeVars) || !walkFreeVarFieldReferrersWithFP(fn.FreeVars[i], fieldIdx, visited, fp, walkVal) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

// walkCellReferrersWithFP walks every referrer of a local cell (and of every free
// variable a closure binds to it, recursively), applying walkVal to each
// stored value and failing closed on any address escape.
func walkCellReferrersWithFP(alias ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if visited[alias] {
		return true
	}
	visited[alias] = true
	refs := alias.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Addr != alias {
				return false
			}
			if u, ok := r.Val.(*ssa.UnOp); ok && u.Op == token.MUL && cellOf(u.X, map[ssa.Value]bool{}) == cellOf(alias, map[ssa.Value]bool{}) {
				return false
			}
			if appendElem := selfCellAppendElem(alias, r.Val); appendElem != nil {
				if !walkVal(appendElem) {
					return false
				}
				continue
			}
			if !walkVal(r.Val) {
				return false
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != alias {
				return false
			}
			if r.Type() != nil {
				if _, isSlice := types.Unalias(r.Type()).Underlying().(*types.Slice); isSlice {
					elemWalk := walkVal
					if fp == nil || !fp.selectionAudited {
						elemWalk = func(ssa.Value) bool { return false }
					}
					if !walkMakeSliceIndexedStoresWithFP(r, visited, fp, elemWalk) {
						return false
					}
				}
			}
		case *ssa.Slice:
			if r.X != alias || !walkMakeSliceIndexedStoresWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.FieldAddr:
			if r.X != alias || !walkCellReferrersWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.IndexAddr:
			if r.X != alias || !walkCellReferrersWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok {
				return false
			}
			for i, binding := range r.Bindings {
				if binding == alias {
					if i >= len(fn.FreeVars) || !walkCellReferrersWithFP(fn.FreeVars[i], visited, fp, walkVal) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func selfCellAppendElem(alias, val ssa.Value) ssa.Value {
	call, ok := val.(*ssa.Call)
	if !ok || call.Common() == nil {
		return nil
	}
	b, ok := call.Common().Value.(*ssa.Builtin)
	if !ok || b.Name() != "append" || len(call.Common().Args) != 2 {
		return nil
	}
	load, ok := call.Common().Args[0].(*ssa.UnOp)
	if !ok || load.Op != token.MUL || load.X != alias {
		return nil
	}
	return call.Common().Args[1]
}

func walkMakeSliceIndexedStoresWithFP(s ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if s == nil {
		return false
	}
	if visited[s] {
		return true
	}
	visited[s] = true
	refs := s.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.BinOp:
			if r.Op != token.EQL && r.Op != token.NEQ {
				return false
			}
		case *ssa.IndexAddr:
			if r.X != s || !walkCellReferrersWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.Slice:
			if r.X != s || !walkMakeSliceIndexedStoresWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.Phi:
			if !walkMakeSliceIndexedStoresWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.Return:
			if fp == nil || !fp.selectionAudited || r.Parent() == nil {
				return false
			}
			fn := r.Parent()
			if !fp.calleeSeen[fn] {
				if fp.programValueRef[fn] || len(fp.programSites[fn]) == 0 {
					return false
				}
				for retIdx, res := range r.Results {
					if res != s {
						continue
					}
					for _, site := range fp.programSites[fn] {
						if !walkCallResultSliceStoresWithFP(site, retIdx, len(r.Results), visited, fp, walkVal) {
							return false
						}
					}
				}
			}
		case *ssa.MapUpdate:
			if r.Value != s || r.Map == s || fp == nil || !fp.selectionAudited || !walkMapSliceReadsWithFP(r.Map, visited, fp, walkVal) {
				return false
			}
		case *ssa.Store:
			if r.Val != s || r.Addr == s || fp == nil || !fp.selectionAudited {
				return false
			}
			switch addr := r.Addr.(type) {
			case *ssa.Alloc, *ssa.FreeVar:
				cell := cellOf(addr, map[ssa.Value]bool{})
				if cell == nil || !walkSliceCellLoadsWithFP(cell, visited, fp, walkVal) {
					return false
				}
			case *ssa.FieldAddr:
				if addr.X == nil || fp.summary == nil {
					return false
				}
				named := derefNamedStruct(fp.userPkgPaths(), addr.X.Type())
				if named == nil {
					return false
				}
				key := structFieldKey{named: named, field: addr.Field}
				if fp.structPoisoned[key] || !fp.structReferencedByType[named] {
					return false
				}
				for _, rd := range fp.summary.structFieldReads[key] {
					if !walkMakeSliceIndexedStoresWithFP(rd, visited, fp, walkVal) {
						return false
					}
				}
			default:
				return false
			}
		case *ssa.MakeInterface:
			if r.X != s || fp == nil || !fp.selectionAudited || !makeInterfaceOnlyVarargsLogged(r, fp.selectionAudited) {
				return false
			}
		case ssa.CallInstruction:
			if r.Common() == nil {
				return false
			}
			if b, ok := r.Common().Value.(*ssa.Builtin); ok {
				if b.Name() == "len" || b.Name() == "cap" {
					continue
				}
				if b.Name() == "copy" && len(r.Common().Args) == 2 {
					if r.Common().Args[0] == s && !walkVal(r.Common().Args[1]) {
						return false
					}
					continue
				}
				if b.Name() == "append" && len(r.Common().Args) == 2 {
					if r.Common().Args[0] == s {
						if !walkVal(r.Common().Args[1]) {
							return false
						}
						if rVal, ok := r.(ssa.Value); !ok || !walkMakeSliceIndexedStoresWithFP(rVal, visited, fp, walkVal) {
							return false
						}
					}
					continue
				}
				return false
			}
			if _, isGo := r.(*ssa.Go); isGo {
				return false
			}
			if r.Common().IsInvoke() {
				if fp == nil || !fp.selectionAudited || r.Common().Value == s {
					return false
				}
				targets, ok := closedInvokeTargets(r, fp)
				if !ok {
					return false
				}
				for callee := range targets {
					if callee == nil || len(callee.Blocks) == 0 || len(r.Common().Args)+1 != len(callee.Params) {
						return false
					}
					for i, arg := range r.Common().Args {
						if arg == s && !walkMakeSliceIndexedStoresWithFP(callee.Params[i+1], visited, fp, walkVal) {
							return false
						}
					}
				}
				continue
			}
			callee := r.Common().StaticCallee()
			if fp != nil && fp.selectionAudited && callee != nil && funcPkgPath(callee) == "slices" {
				if admitted, aliasesReturn := isAuditedSlicesCallForSlice(functionSymbolName(callee), r.Common().Args, s); admitted {
					if aliasesReturn {
						if rVal, ok := r.(ssa.Value); ok && !walkMakeSliceIndexedStoresWithFP(rVal, visited, fp, walkVal) {
							return false
						}
					}
					continue
				}
			}
			if callee == nil || len(callee.Blocks) == 0 || len(r.Common().Args) != len(callee.Params) {
				return false
			}
			for i, arg := range r.Common().Args {
				if arg == s && !walkMakeSliceIndexedStoresWithFP(callee.Params[i], visited, fp, walkVal) {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func isAuditedSlicesCallForSlice(name string, args []ssa.Value, s ssa.Value) (admitted, aliasesReturn bool) {
	maxArgIdx := 0
	switch name {
	case "Compact", "CompactFunc":
		aliasesReturn = true
	case "Equal", "EqualFunc", "Compare", "CompareFunc":
		maxArgIdx = 1
	case "Clone", "Sort", "SortFunc", "SortStableFunc", "Reverse",
		"IsSorted", "IsSortedFunc", "BinarySearch", "BinarySearchFunc",
		"Index", "IndexFunc", "Contains", "ContainsFunc",
		"Min", "MinFunc", "Max", "MaxFunc":
	default:
		return false, false
	}
	found := false
	for i, arg := range args {
		if arg == s {
			if i > maxArgIdx {
				return false, false
			}
			found = true
		}
	}
	if !found {
		return false, false
	}
	return true, aliasesReturn
}

func walkSliceCellLoadsWithFP(alias ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if alias == nil {
		return false
	}
	if visited[alias] {
		return true
	}
	visited[alias] = true
	refs := alias.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Addr != alias {
				return false
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != alias || !walkMakeSliceIndexedStoresWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok {
				return false
			}
			for i, binding := range r.Bindings {
				if binding == alias {
					if i >= len(fn.FreeVars) || !walkSliceCellLoadsWithFP(fn.FreeVars[i], visited, fp, walkVal) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func makeInterfaceOnlyVarargsLogged(mi *ssa.MakeInterface, audited bool) bool {
	if mi == nil || mi.Referrers() == nil {
		return false
	}
	for _, ref := range *mi.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Val != mi || r.Addr == mi {
				return false
			}
			ia, ok := r.Addr.(*ssa.IndexAddr)
			if !ok {
				return false
			}
			alloc, ok := ia.X.(*ssa.Alloc)
			if !ok || alloc.Referrers() == nil {
				return false
			}
			for _, aref := range *alloc.Referrers() {
				switch ar := aref.(type) {
				case *ssa.DebugRef, *ssa.IndexAddr:
				case *ssa.Slice:
					if ar.X != alloc || ar.Referrers() == nil {
						return false
					}
					for _, sref := range *ar.Referrers() {
						switch sr := sref.(type) {
						case *ssa.DebugRef:
						case ssa.CallInstruction:
							if _, isGo := sr.(*ssa.Go); isGo || sr.Common() == nil || sr.Common().IsInvoke() {
								return false
							}
							callee := sr.Common().StaticCallee()
							if callee == nil {
								return false
							}
							if funcPkgPath(callee) == "fmt" {
								continue
							}
							if _, ok := harnessCalleeEffect(audited, callee, false); ok {
								continue
							}
							return false
						default:
							return false
						}
					}
				default:
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

func walkMakeMapValues(m ssa.Value, visited map[ssa.Value]bool, walkVal func(ssa.Value) bool) bool {
	return walkMakeMapValuesWithFP(m, visited, nil, walkVal)
}

func walkMakeMapValuesWithFP(m ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if m == nil {
		return false
	}
	if visited[m] {
		return true
	}
	visited[m] = true
	refs := m.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Lookup:
			if r.X != m {
				return false
			}
		case *ssa.Range:
			if r.X != m {
				return false
			}
		case *ssa.Phi:
			if !walkMakeMapValuesWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.Return:
			if fp == nil || !fp.selectionAudited || r.Parent() == nil {
				return false
			}
			fn := r.Parent()
			if !fp.calleeSeen[fn] {
				if fp.programValueRef[fn] || len(fp.programSites[fn]) == 0 {
					return false
				}
				for retIdx, res := range r.Results {
					if res != m {
						continue
					}
					for _, site := range fp.programSites[fn] {
						if !walkCallResultMapValuesWithFP(site, retIdx, len(r.Results), visited, fp, walkVal) {
							return false
						}
					}
				}
			}
		case *ssa.Store:
			if r.Val != m || r.Addr == m || fp == nil || !fp.selectionAudited {
				return false
			}
			switch addr := r.Addr.(type) {
			case *ssa.Alloc, *ssa.FreeVar:
				cell := cellOf(addr, map[ssa.Value]bool{})
				if cell == nil || !walkMapCellLoadsWithFP(cell, visited, fp, walkVal) {
					return false
				}
			case *ssa.FieldAddr:
				if addr.X == nil || fp.summary == nil {
					return false
				}
				named := derefNamedStruct(fp.userPkgPaths(), addr.X.Type())
				if named == nil {
					return false
				}
				key := structFieldKey{named: named, field: addr.Field}
				if fp.structPoisoned[key] || !fp.structReferencedByType[named] {
					return false
				}
				for _, rd := range fp.summary.structFieldReads[key] {
					if !walkMakeMapValuesWithFP(rd, visited, fp, walkVal) {
						return false
					}
				}
			default:
				return false
			}
		case *ssa.MapUpdate:
			if r.Map != m || !walkVal(r.Value) {
				return false
			}
		case ssa.CallInstruction:
			if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil {
				return false
			}
			if b, ok := r.Common().Value.(*ssa.Builtin); ok {
				if b.Name() != "len" && b.Name() != "delete" && b.Name() != "clear" {
					return false
				}
				continue
			}
			callee := r.Common().StaticCallee()
			if r.Common().IsInvoke() || callee == nil || len(callee.Blocks) == 0 || len(r.Common().Args) != len(callee.Params) {
				return false
			}
			for i, arg := range r.Common().Args {
				if arg == m && !walkMakeMapValuesWithFP(callee.Params[i], visited, fp, walkVal) {
					return false
				}
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok {
				return false
			}
			for i, binding := range r.Bindings {
				if binding == m {
					if i >= len(fn.FreeVars) || !walkMakeMapValuesWithFP(fn.FreeVars[i], visited, fp, walkVal) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func walkMapCellLoadsWithFP(alias ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if alias == nil {
		return false
	}
	if visited[alias] {
		return true
	}
	visited[alias] = true
	refs := alias.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Addr != alias {
				return false
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != alias || !walkMakeMapValuesWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok {
				return false
			}
			for i, binding := range r.Bindings {
				if binding == alias {
					if i >= len(fn.FreeVars) || !walkMapCellLoadsWithFP(fn.FreeVars[i], visited, fp, walkVal) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func walkMapSliceReadsWithFP(m ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if m == nil {
		return false
	}
	if visited[m] {
		return true
	}
	visited[m] = true
	refs := m.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.MapUpdate:
			if r.Map != m {
				return false
			}
		case *ssa.Lookup:
			if r.X != m {
				return false
			}
			if !r.CommaOk {
				if !walkMakeSliceIndexedStoresWithFP(r, visited, fp, walkVal) {
					return false
				}
				continue
			}
			if r.Referrers() != nil {
				for _, lref := range *r.Referrers() {
					switch lr := lref.(type) {
					case *ssa.DebugRef:
					case *ssa.Extract:
						if lr.Tuple != r {
							return false
						}
						if lr.Index == 0 && !walkMakeSliceIndexedStoresWithFP(lr, visited, fp, walkVal) {
							return false
						}
					default:
						return false
					}
				}
			}
		case *ssa.Range:
			if r.X != m {
				return false
			}
			if r.Referrers() != nil {
				for _, rref := range *r.Referrers() {
					switch rr := rref.(type) {
					case *ssa.DebugRef:
					case *ssa.Next:
						if rr.Iter != r {
							return false
						}
						if rr.Referrers() != nil {
							for _, nref := range *rr.Referrers() {
								switch nr := nref.(type) {
								case *ssa.DebugRef:
								case *ssa.Extract:
									if nr.Tuple != rr {
										return false
									}
									if nr.Index == 2 && !walkMakeSliceIndexedStoresWithFP(nr, visited, fp, walkVal) {
										return false
									}
								default:
									return false
								}
							}
						}
					default:
						return false
					}
				}
			}
		case *ssa.Phi:
			if !walkMapSliceReadsWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.Store:
			if r.Val != m || r.Addr == m || fp == nil || !fp.selectionAudited {
				return false
			}
			switch addr := r.Addr.(type) {
			case *ssa.Alloc, *ssa.FreeVar:
				cell := cellOf(addr, map[ssa.Value]bool{})
				if cell == nil || !walkMapSliceCellLoadsWithFP(cell, visited, fp, walkVal) {
					return false
				}
			case *ssa.FieldAddr:
				if addr.X == nil || fp.summary == nil {
					return false
				}
				named := derefNamedStruct(fp.userPkgPaths(), addr.X.Type())
				if named == nil {
					return false
				}
				key := structFieldKey{named: named, field: addr.Field}
				if fp.structPoisoned[key] || !fp.structReferencedByType[named] {
					return false
				}
				for _, rd := range fp.summary.structFieldReads[key] {
					if !walkMapSliceReadsWithFP(rd, visited, fp, walkVal) {
						return false
					}
				}
			default:
				return false
			}
		case ssa.CallInstruction:
			if _, isGo := r.(*ssa.Go); isGo || r.Common() == nil {
				return false
			}
			if b, ok := r.Common().Value.(*ssa.Builtin); ok {
				if b.Name() != "len" && b.Name() != "delete" && b.Name() != "clear" {
					return false
				}
				continue
			}
			callee := r.Common().StaticCallee()
			if r.Common().IsInvoke() || callee == nil || len(callee.Blocks) == 0 || len(r.Common().Args) != len(callee.Params) {
				return false
			}
			for i, arg := range r.Common().Args {
				if arg == m && !walkMapSliceReadsWithFP(callee.Params[i], visited, fp, walkVal) {
					return false
				}
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok {
				return false
			}
			for i, binding := range r.Bindings {
				if binding == m {
					if i >= len(fn.FreeVars) || !walkMapSliceReadsWithFP(fn.FreeVars[i], visited, fp, walkVal) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

func walkMapSliceCellLoadsWithFP(alias ssa.Value, visited map[ssa.Value]bool, fp *freshParamAnalysis, walkVal func(ssa.Value) bool) bool {
	if alias == nil {
		return false
	}
	if visited[alias] {
		return true
	}
	visited[alias] = true
	refs := alias.Referrers()
	if refs == nil {
		return true
	}
	for _, ref := range *refs {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Store:
			if r.Addr != alias {
				return false
			}
		case *ssa.UnOp:
			if r.Op != token.MUL || r.X != alias || !walkMapSliceReadsWithFP(r, visited, fp, walkVal) {
				return false
			}
		case *ssa.MakeClosure:
			fn, ok := r.Fn.(*ssa.Function)
			if !ok {
				return false
			}
			for i, binding := range r.Bindings {
				if binding == alias {
					if i >= len(fn.FreeVars) || !walkMapSliceCellLoadsWithFP(fn.FreeVars[i], visited, fp, walkVal) {
						return false
					}
				}
			}
		default:
			return false
		}
	}
	return true
}

// closedDynamicTargets collects the functions a computed call's operand
// can hold when the closed-value walk closes it through shapes whose
// leaves are function values — function constants and closure
// creations, through phis, tuple extractions, type changes, closed
// cells, and the subject-attributed parameter crossing. A leaf the
// walk closes without naming a function (a gate-passing harness call
// result) or any open shape yields no set, and the enumeration's own
// targets stand. The set bounds the operand exactly: every function
// value that can reach the load or the parameter is one of the leaves
// (REQ-closure-observability-dispatch).
func closedDynamicTargets(value ssa.Value, fp *freshParamAnalysis) (map[*ssa.Function]bool, bool) {
	if !subjectClosedDynamicValue(value, make(map[ssa.Value]bool), fp) {
		return nil, false
	}
	targets := map[*ssa.Function]bool{}
	if !walkDynamicValue(value, &dynamicValueCollector{funcs: targets}, map[ssa.Value]bool{}, nil, resetWalkState(fp)) {
		return nil, false
	}
	return targets, true
}

// closedInvokeTargets resolves the methods of the invoked name on the concrete
// types an interface operand can hold, through the program's method sets.
// An operand the walk cannot close, a closed operand naming no concrete type,
// or a method the concrete type promotes from an unscanned body returns false
// so the enumeration's projection stays whole (REQ-closure-observability-dispatch).
func closedInvokeTargets(site ssa.CallInstruction, fp *freshParamAnalysis) (map[*ssa.Function]bool, bool) {
	if site == nil || site.Parent() == nil || site.Parent().Prog == nil {
		return nil, false
	}
	c := site.Common()
	if c == nil || !c.IsInvoke() || c.Method == nil {
		return nil, false
	}
	fp = contextCancelMethodFP(site, fp)
	outsideCallee := fp != nil && (c.Value == nil || !inActiveCallee(c.Value.Parent(), fp.calleeSeen))
	inProgScope := outsideCallee && !fp.ignoreContextValuePayload && fp.enumRecvNamed == nil && (fp.enumOnly || fp.enumRoot == nil) && (fp.inProgramSites || fp.inFieldStore || fp.enumOnly) && site.Parent() != fp.enumRoot && site.Parent() != fp.subjectRoot
	if inProgScope && fp.summary != nil {
		pTargets, pFailed := fp.summary.progInvokeTargets, fp.summary.progInvokeFailed
		if fp.enumOnly {
			pTargets, pFailed = fp.summary.enumInvokeTargets, fp.summary.enumInvokeFailed
		}
		if pFailed[site] {
			return nil, false
		}
		if cached, ok := pTargets[site]; ok {
			return cached, true
		}
	}
	cacheable := outsideCallee && fp.invokeTargets != nil && fp.invokeFailed != nil
	if cacheable {
		if fp.invokeFailed[site] {
			return nil, false
		}
		if cached, ok := fp.invokeTargets[site]; ok {
			return cached, true
		}
	}
	var lowlink1, lowlink2 int
	var hasLeaf1, usedSubject1, usedSubject2 bool
	var evalFP, collectFP *freshParamAnalysis
	if fp != nil {
		e := *fp
		if fp.stackDepth != nil {
			e.stackDepth = fp.stackDepth
			e.rootDone = fp.rootDone
			e.rootLowlink = fp.rootLowlink
			e.rootHasLeaf = fp.rootHasLeaf
			e.rootUsedSubject = fp.rootUsedSubject
		} else {
			e.stackDepth = map[ssa.Value]int{}
			e.rootDone = map[ssa.Value]bool{}
			e.rootLowlink = map[ssa.Value]int{}
			e.rootHasLeaf = map[ssa.Value]bool{}
			e.rootUsedSubject = map[ssa.Value]bool{}
		}
		e.lowlink = &lowlink1
		e.hasLeaf = &hasLeaf1
		e.usedSubject = &usedSubject1
		e.rootSeen = nil
		evalFP = &e

		col := *fp
		col.stackDepth = nil
		col.lowlink = &lowlink2
		col.hasLeaf = nil
		col.usedSubject = &usedSubject2
		col.rootDone = nil
		col.rootLowlink = nil
		col.rootHasLeaf = nil
		col.rootUsedSubject = nil
		col.rootSeen = nil
		collectFP = &col
	}
	propagateWalkFlags := func() (bool, bool) {
		noEscape := lowlink1 == 0 && lowlink2 == 0 && (fp == nil || len(fp.enumStructVisiting) == 0)
		usedSubj := usedSubject1 || usedSubject2
		if fp != nil {
			if fp.lowlink != nil {
				if lowlink1 != 0 && (*fp.lowlink == 0 || lowlink1 < *fp.lowlink) {
					*fp.lowlink = lowlink1
				}
				if lowlink2 != 0 && (*fp.lowlink == 0 || lowlink2 < *fp.lowlink) {
					*fp.lowlink = lowlink2
				}
			}
			if fp.hasLeaf != nil && hasLeaf1 {
				*fp.hasLeaf = true
			}
			if fp.usedSubject != nil && usedSubj {
				*fp.usedSubject = true
			}
		}
		return noEscape, usedSubj
	}
	fail := func() (map[*ssa.Function]bool, bool) {
		noEscape, usedSubj := propagateWalkFlags()
		if noEscape {
			if cacheable {
				fp.invokeFailed[site] = true
			}
			if inProgScope && fp.summary != nil && !usedSubj {
				pFailed := fp.summary.progInvokeFailed
				if fp.enumOnly {
					pFailed = fp.summary.enumInvokeFailed
				}
				pFailed[site] = true
			}
		}
		return nil, false
	}
	if !walkDynamicValue(c.Value, nil, make(map[ssa.Value]bool), nil, evalFP) {
		return fail()
	}
	concreteTypes := map[types.Type]bool{}
	allowEmptyConcrete := fp != nil && fp.selectionAudited && !isDirectNilOnlyParam(c.Value, fp)
	if !walkDynamicValue(c.Value, &dynamicValueCollector{types: concreteTypes}, map[ssa.Value]bool{}, nil, collectFP) || (len(concreteTypes) == 0 && !allowEmptyConcrete) {
		return fail()
	}
	targets, ok := resolveConcreteMethodTargets(site.Parent().Prog, c.Value.Type(), c.Method, concreteTypes, collectFP)
	if !ok {
		return fail()
	}
	noEscape, usedSubj := propagateWalkFlags()
	if noEscape {
		if cacheable {
			fp.invokeTargets[site] = targets
		}
		if inProgScope && fp.summary != nil && !usedSubj {
			pTargets := fp.summary.progInvokeTargets
			if fp.enumOnly {
				pTargets = fp.summary.enumInvokeTargets
			}
			pTargets[site] = targets
		}
	}
	return targets, true
}

func isDirectNilOnlyParam(v ssa.Value, fp *freshParamAnalysis) bool {
	if fp == nil || fp.inProgramSites || fp.inFieldStore || fp.enumOnly || len(fp.invokeSeen) > 0 {
		return false
	}
	p, ok := v.(*ssa.Parameter)
	if !ok {
		return false
	}
	args, usedProg, ok := attributedParameterArgs(p, fp)
	if !ok || usedProg || len(args) == 0 {
		return false
	}
	for _, arg := range args {
		c, isConst := arg.(*ssa.Const)
		if !isConst || c.Value != nil {
			return false
		}
	}
	return true
}

func resolveConcreteMethodTargets(prog *ssa.Program, recvType types.Type, method *types.Func, concreteTypes map[types.Type]bool, fp *freshParamAnalysis) (map[*ssa.Function]bool, bool) {
	return resolveConcreteMethodTargetsSeen(prog, recvType, method, concreteTypes, fp, map[types.Type]bool{})
}

func resolveConcreteMethodTargetsSeen(prog *ssa.Program, recvType types.Type, method *types.Func, concreteTypes map[types.Type]bool, fp *freshParamAnalysis, seenTypes map[types.Type]bool) (map[*ssa.Function]bool, bool) {
	if prog == nil || method == nil {
		return nil, false
	}
	audited := fp != nil && fp.selectionAudited
	hasIOWrapper, hasTeeReader, hasNonWrapperConcrete := false, false, false
	if audited {
		for ct := range concreteTypes {
			if isAuditedStandardIOWrapperType(ct) {
				hasIOWrapper = true
				if isAuditedTeeReaderType(ct) {
					hasTeeReader = true
				}
			} else {
				hasNonWrapperConcrete = true
			}
		}
		if hasIOWrapper && method.Name() != "Close" && !hasNonWrapperConcrete {
			return nil, false
		}
	}
	iface, _ := types.Unalias(recvType).Underlying().(*types.Interface)
	targets := make(map[*ssa.Function]bool, len(concreteTypes))
	resolveOne := func(ct types.Type, mPkg *types.Package, mName string, mFunc *types.Func) bool {
		if seenTypes[ct] {
			return true
		}
		if mFunc != nil && isAuditedStandardContextInvoke(audited, ct, mFunc) {
			cmethod := prog.LookupMethod(ct, mPkg, mName)
			if cmethod == nil || len(cmethod.Blocks) == 0 {
				return false
			}
			targets[cmethod] = true
			return true
		}
		sel := prog.MethodSets.MethodSet(ct).Lookup(mPkg, mName)
		if sel == nil {
			return false
		}
		fnObj, ok := sel.Obj().(*types.Func)
		if !ok || fnObj == nil {
			return false
		}
		declFn := prog.FuncValue(fnObj)
		if declFn == nil {
			if !audited || fp == nil || len(sel.Index()) < 2 {
				return false
			}
			fieldPath := sel.Index()[:len(sel.Index())-1]
			sig, ok := fnObj.Type().(*types.Signature)
			if !ok || sig.Recv() == nil {
				return false
			}
			if _, isIface := types.Unalias(sig.Recv().Type()).Underlying().(*types.Interface); !isIface {
				return false
			}
			if fnObj.Pkg() != nil && propertyHarnessPath(fnObj.Pkg().Path()) {
				return false
			}
			named := derefNamedStruct(fp.userPkgPaths(), ct)
			if named == nil {
				return false
			}
			curNamed := named
			var stores []ssa.Value
			for i, fIdx := range fieldPath {
				key := structFieldKey{named: curNamed, field: fIdx}
				if fp.structPoisoned[key] || !fp.structReferencedByType[curNamed] || !userStructWholeStoresClosed(curNamed, nil, map[ssa.Value]bool{}, nil, resetWalkState(fp)) {
					return false
				}
				if i == len(fieldPath)-1 {
					stores = fp.structFieldStores[key]
				} else {
					st, ok := curNamed.Underlying().(*types.Struct)
					if !ok || fIdx < 0 || fIdx >= st.NumFields() {
						return false
					}
					curNamed = derefNamedStruct(fp.userPkgPaths(), st.Field(fIdx).Type())
					if curNamed == nil {
						return false
					}
				}
			}
			if len(stores) == 0 {
				return false
			}
			seenTypes[ct] = true
			fieldFP := *fp
			fieldFP.inFieldStore = true
			fieldFP.callBindings = nil
			fieldFP.calleeSeen = nil
			fieldFP.calleeDepth = nil
			embeddedTypes := map[types.Type]bool{}
			for _, sv := range stores {
				if !subjectClosedDynamicValue(sv, map[ssa.Value]bool{}, resetWalkState(&fieldFP)) || !walkDynamicValue(sv, &dynamicValueCollector{types: embeddedTypes}, map[ssa.Value]bool{}, nil, resetWalkState(&fieldFP)) {
					return false
				}
			}
			if len(embeddedTypes) == 0 {
				return true
			}
			embeddedTargets, ok := resolveConcreteMethodTargetsSeen(prog, sig.Recv().Type(), fnObj, embeddedTypes, &fieldFP, seenTypes)
			if !ok {
				return false
			}
			for t := range embeddedTargets {
				targets[t] = true
			}
			return true
		} else {
			if len(declFn.Blocks) == 0 || propertyHarnessPath(funcPkgPath(declFn)) {
				return false
			}
			if fp.isStdFunc(declFn) {
				if mFunc == nil || !isAuditedStandardContextInvoke(audited, ct, mFunc) {
					if typeMayCarryDynamicTop(audited, ct) && (len(declFn.Params) == 0 || paramMaySupplyDynamicSeen(audited, fp.userPkgPaths(), declFn.Params[0], nil, make(map[*ssa.Parameter]bool))) {
						return false
					}
					declPkg := funcPkgPath(declFn)
					if !isAuditedStandardOrDelegatePackage(audited, declPkg) && !auditedStandardCallee(audited, declPkg, functionSymbolName(declFn), declFn) {
						return false
					}
				}
			}
		}
		cmethod := prog.LookupMethod(ct, mPkg, mName)
		if cmethod == nil || len(cmethod.Blocks) == 0 {
			return false
		}
		targets[cmethod] = true
		return true
	}
	for ct := range concreteTypes {
		if audited && isAuditedStandardIOWrapperType(ct) {
			if iface != nil && !types.Implements(ct, iface) {
				continue
			}
			cmethod := prog.LookupMethod(ct, method.Pkg(), method.Name())
			if cmethod == nil || len(cmethod.Blocks) == 0 {
				return nil, false
			}
			targets[cmethod] = true
			continue
		}
		if hasTeeReader && method.Name() == "Read" && prog.MethodSets.MethodSet(ct).Lookup(nil, "Write") != nil {
			if !resolveOne(ct, nil, "Write", nil) {
				return nil, false
			}
		}
		if iface != nil && !types.Implements(ct, iface) {
			if !hasIOWrapper || prog.MethodSets.MethodSet(ct).Lookup(method.Pkg(), method.Name()) == nil {
				continue
			}
		}
		if !resolveOne(ct, method.Pkg(), method.Name(), method) {
			return nil, false
		}
	}
	return targets, true
}

func isAuditedStandardIOWrapperType(t types.Type) bool {
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "io" {
		return false
	}
	switch named.Obj().Name() {
	case "nopCloser", "nopCloserWriterTo", "LimitedReader", "teeReader", "multiReader", "multiWriter", "eofReader":
		return true
	default:
		return false
	}
}

func isAuditedTeeReaderType(t types.Type) bool {
	if ptr, ok := types.Unalias(t).(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "io" && named.Obj().Name() == "teeReader"
}

// narrowedTargets returns a dynamic call's or interface invoke's targets
// narrowed to the functions or concrete-type methods its operand can hold,
// within the enumeration's own set; a static call or an operand yielding no
// set keeps the enumeration's targets whole (REQ-closure-observability-dispatch).
func narrowedTargets(site ssa.CallInstruction, targets map[*ssa.Function]bool, fp *freshParamAnalysis) map[*ssa.Function]bool {
	c := site.Common()
	if c == nil || c.StaticCallee() != nil || len(targets) == 0 {
		return targets
	}
	var held map[*ssa.Function]bool
	var ok bool
	if c.IsInvoke() {
		held, ok = closedInvokeTargets(site, fp)
	} else {
		held, ok = closedDynamicTargets(c.Value, fp)
	}
	if !ok {
		return targets
	}
	narrowed := make(map[*ssa.Function]bool, len(held))
	anyInTargets := false
	for fn := range held {
		if targets[fn] {
			anyInTargets = true
		}
		narrowed[fn] = true
	}
	// A held function the enumeration does not list is a vocabulary
	// mismatch between the collector and RTA (a bound-method wrapper
	// against its method, say) — a fail-closed backstop no fixture
	// constructs, never a demonstrated bug: the enumeration's targets
	// stand rather than an empty set admitting the site. An empty held
	// set (a nil function value) is the one legitimate empty result.
	if !anyInTargets && len(held) > 0 {
		return targets
	}
	return narrowed
}

// attributedParameterArgs returns the value passed at param's position by
// every subject-attributed call site of its function, or ok=false when
// the crossing is unavailable — the function is dynamically targeted,
// closes over state, is variadic, or has no attributed caller (absence
// of provenance is refused, never a vacuous pass). It is the one
// caller-boundary discipline shared by every value walk that crosses a
// parameter. (The subject root's own harness parameter never reaches the
// dispatch walk's crossing: it is concrete *testing.T/B/F, and every
// concrete-to-interface boundary materializes a MakeInterface the walk
// closes on.)
func attributedParameterArgs(param *ssa.Parameter, fp *freshParamAnalysis) ([]ssa.Value, bool, bool) {
	if fp != nil {
		if bound, ok := fp.callBindings[param]; ok && bound != nil {
			return []ssa.Value{bound}, false, true
		}
	}
	fn := param.Parent()
	if !fp.paramCrossingEligible(fn) {
		return nil, false, false
	}
	idx := -1
	for i, p := range fn.Params {
		if p == param {
			idx = i
		}
	}
	if idx < 0 {
		return nil, false, false
	}
	sites := fp.callers[fn]
	usedProgramSites := false
	if fn == fp.enumRoot {
		// The subject root's own parameters cross to its whole-view
		// caller enumeration; any subject-internal recursion sites join
		// the conjunction rather than replacing it.
		sites = append(append([]ssa.CallInstruction(nil), sites...), fp.enumSites...)
		if len(fp.enumSites) > 0 {
			usedProgramSites = true
		}
	}
	needRecvProgram := fn != fp.enumRoot && (fp.dynamic[fn] || fp.inProgramSites || fp.inFieldStore || fp.enumOnly || len(sites) == 0 || len(fn.FreeVars) != 0)
	if idx == 0 && fn.Signature != nil && fn.Signature.Recv() != nil && fp != nil && fp.selectionAudited && fp.summary != nil && needRecvProgram {
		if namedSig := derefNamedSignature(fp.userPkgPaths(), param.Type()); namedSig != nil {
			if _, isPtr := types.Unalias(param.Type()).(*types.Pointer); isPtr || fp.programValueRef[fn] || fp.summary.namedSigPoisoned[namedSig] {
				return nil, false, false
			}
			sources := fp.summary.namedSigSources[namedSig]
			progSites := fp.programSites[fn]
			combined := make([]ssa.Value, 0, len(progSites)+len(sources))
			for _, site := range progSites {
				if site.Common().IsInvoke() {
					continue
				}
				if len(site.Common().Args) > 0 {
					combined = append(combined, site.Common().Args[0])
				} else {
					return nil, false, false
				}
			}
			combined = append(combined, sources...)
			if len(combined) == 0 {
				return nil, false, false
			}
			return combined, true, true
		}
		if named := derefNamedStruct(fp.userPkgPaths(), param.Type()); named != nil {
			if fp.programValueRef[fn] || fp.structPoisoned[structFieldKey{named: named, field: -1}] {
				return nil, false, false
			}
			boxed := fp.summary.structBoxedValues[named]
			if len(boxed) > 0 {
				combined := make([]ssa.Value, 0, len(fp.programSites[fn])+len(boxed))
				for _, site := range fp.programSites[fn] {
					if site.Common().IsInvoke() {
						continue
					}
					if len(site.Common().Args) > 0 {
						combined = append(combined, site.Common().Args[0])
					} else {
						return nil, false, false
					}
				}
				combined = append(combined, boxed...)
				return combined, true, true
			}
		}
	}
	isSigParam := false
	if param.Type() != nil {
		_, isSigParam = types.Unalias(param.Type()).Underlying().(*types.Signature)
	}
	if isSigParam && !fp.inFieldStore && !fp.inProgramSites {
		if (!fp.functions[fn] && (!fp.selectionAudited || fp.enumOnly || fp.programValueRef[fn] || len(fp.programSites[fn]) == 0)) || fp.dynamic[fn] || len(fn.FreeVars) != 0 || fn.Signature.Variadic() {
			return nil, false, false
		}
	}
	isEnumSigParam := fp.enumOnly && !fp.inFieldStore && isSigParam
	perSubjectSigParam := isSigParam && !fp.inFieldStore && !fp.inProgramSites && !fp.enumOnly && fp.functions[fn] && (len(sites) > 0 || !fp.selectionAudited)
	needProgramSites := (len(sites) == 0 || len(fn.FreeVars) != 0 || (fn != fp.enumRoot && (fp.dynamic[fn] || fp.inProgramSites || fp.inFieldStore || fp.enumOnly))) && !isEnumSigParam && !perSubjectSigParam
	if needProgramSites {
		if fp.programSites == nil || fp.programValueRef[fn] || (len(fn.FreeVars) != 0 && !fp.selectionAudited) {
			return nil, false, false
		}
		sites = fp.programSites[fn]
		usedProgramSites = true
	}
	if len(sites) == 0 {
		// Absence of provenance refuses, never a vacuous pass. A
		// subject-reachable, statically called function always has an
		// attributed caller, so this arm is the clause's fail-closed
		// backstop rather than a reachable state.
		return nil, false, false
	}
	args := make([]ssa.Value, 0, len(sites))
	for _, site := range sites {
		if site.Common().IsInvoke() {
			if fn.Signature == nil || fn.Signature.Recv() == nil {
				return nil, false, false
			}
			if idx == 0 {
				args = append(args, site.Common().Value)
				continue
			}
			siteArgs := site.Common().Args
			if idx-1 >= len(siteArgs) {
				return nil, false, false
			}
			args = append(args, siteArgs[idx-1])
			continue
		}
		siteArgs := site.Common().Args
		if idx >= len(siteArgs) {
			return nil, false, false
		}
		args = append(args, siteArgs[idx])
	}
	return args, usedProgramSites, true
}

func attributedFreeVarBindings(fv *ssa.FreeVar, fp *freshParamAnalysis) ([]ssa.Value, bool, bool) {
	if fv == nil || fp == nil || !fp.selectionAudited {
		return nil, false, false
	}
	fn := fv.Parent()
	if fn == nil {
		return nil, false, false
	}
	idx := slices.Index(fn.FreeVars, fv)
	if idx < 0 {
		return nil, false, false
	}
	if fn.Parent() != nil && inActiveCallee(fn.Parent(), fp.calleeSeen) {
		mcs := closureCreations(fn)
		if len(mcs) == 0 {
			return nil, false, false
		}
		bindings := make([]ssa.Value, 0, len(mcs))
		for _, mc := range mcs {
			if mc == nil || idx >= len(mc.Bindings) || mc.Bindings[idx] == nil {
				return nil, false, false
			}
			bindings = append(bindings, mc.Bindings[idx])
		}
		return bindings, false, true
	}
	var mcs []*ssa.MakeClosure
	if fp.summary != nil {
		if fp.summary.nonClosureRef[fn] {
			return nil, false, false
		}
		mcs = fp.summary.closureRefs[fn]
	} else if fn.Parent() != nil {
		mcs = closureCreations(fn)
	}
	if len(mcs) == 0 {
		return nil, false, false
	}
	usedProgramSites := fn.Parent() == nil
	bindings := make([]ssa.Value, 0, len(mcs))
	for _, mc := range mcs {
		if mc == nil || idx >= len(mc.Bindings) || mc.Bindings[idx] == nil {
			return nil, false, false
		}
		if !usedProgramSites && (len(fp.functions) == 0 || !fp.functions[mc.Parent()]) {
			usedProgramSites = true
		}
		bindings = append(bindings, mc.Bindings[idx])
	}
	return bindings, usedProgramSites, true
}

// inMemoryFormattedSink reports whether a fmt writer operand provably
// pins every dynamic type it can carry to an audited in-memory sink —
// *bytes.Buffer or *strings.Builder — so the formatted bytes never leave
// process memory and the call is Sprint-equivalent value computation
// (REQ-closure-observability-writer-sink). The
// concrete type at each pinning MakeInterface decides alone: which
// buffer instance receives the bytes never changes which Write runs, and
// mutation of shared memory is the shared-dynamic-state rules' domain,
// not an ambient effect — the same footing as a direct Write on that
// buffer. Everything unpinned — loads, call results, globals, function
// values — fails closed, and a parameter crosses only through the
// attributed-caller discipline the dispatch walks share.
func inMemoryFormattedSink(value ssa.Value, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if value == nil {
		return false
	}
	if r, ok := done[value]; ok {
		return r
	}
	if seen[value] {
		return false
	}
	seen[value] = true
	defer delete(seen, value)
	r := inMemoryFormattedSinkUncached(value, seen, done, fp)
	done[value] = r
	return r
}

func inMemoryFormattedSinkUncached(value ssa.Value, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	switch v := value.(type) {
	case *ssa.MakeInterface:
		return auditedInMemorySinkType(v.X.Type())
	case *ssa.ChangeInterface:
		return inMemoryFormattedSink(v.X, seen, done, fp)
	case *ssa.TypeAssert:
		return inMemoryFormattedSink(v.X, seen, done, fp)
	case *ssa.ChangeType:
		return inMemoryFormattedSink(v.X, seen, done, fp)
	case *ssa.Convert:
		return inMemoryFormattedSink(v.X, seen, done, fp)
	case *ssa.Phi:
		if len(v.Edges) == 0 {
			return false
		}
		for _, edge := range v.Edges {
			if !inMemoryFormattedSink(edge, seen, done, fp) {
				return false
			}
		}
		return true
	case *ssa.Extract:
		return inMemoryFormattedSink(v.Tuple, seen, done, fp)
	case *ssa.Parameter:
		args, usedProgramSites, ok := attributedParameterArgs(v, fp)
		if !ok {
			return false
		}
		argFP := fp
		if usedProgramSites && fp != nil && !fp.inProgramSites {
			copied := *fp
			copied.inProgramSites = true
			argFP = &copied
		}
		for _, arg := range args {
			if !inMemoryFormattedSink(arg, seen, done, argFP) {
				return false
			}
		}
		return true
	case *ssa.UnOp:
		if v.Op != token.MUL {
			return false
		}
		if g, ok := v.X.(*ssa.Global); ok && fp != nil && fp.selectionAudited && isUnmutatedStandardSentinelGlobal(g, "io", "Discard") {
			return true
		}
		if cellOf(v.X, map[ssa.Value]bool{}) == nil {
			return false
		}
		wrote := false
		ok := walkLoadCellReferrers(v.X, func(val ssa.Value) bool {
			wrote = true
			return inMemoryFormattedSink(val, seen, done, fp)
		})
		return ok && wrote
	default:
		return false
	}
}

// auditedInMemorySinkType admits exactly the two standard sinks whose
// Write appends to process memory and acquires nothing ambient. Both
// implement io.Writer on the pointer receiver only, so the pointer form
// is the whole surface.
func auditedInMemorySinkType(t types.Type) bool {
	pointer, ok := types.Unalias(t).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(pointer.Elem()).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	switch named.Obj().Pkg().Path() + "." + named.Obj().Name() {
	case "bytes.Buffer", "strings.Builder":
		return true
	}
	return false
}

// syntheticInterfaceMethodWrapper reports whether fn is a compiler
// synthetic (bound wrapper or thunk) over an interface method: the one
// wrapper family whose std-attributed body performs a real dynamic
// dispatch the walks never scan, so the dispatch provenance must be
// read at the wrapper's call site instead.
func syntheticInterfaceMethodWrapper(fn *ssa.Function) bool {
	if fn == nil || fn.Synthetic == "" {
		return false
	}
	obj, ok := fn.Object().(*types.Func)
	if !ok || obj == nil {
		return false
	}
	sig, ok := obj.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	_, isInterface := types.Unalias(sig.Recv().Type()).Underlying().(*types.Interface)
	return isInterface
}

// wrapperReceiver returns the value carrying a static wrapper call's
// dispatch provenance: a thunk's receiver argument (thunks close over
// nothing and take the receiver first), or the operand itself for a
// bound wrapper — whose bindings the closed-value walk already gates.
func wrapperReceiver(c *ssa.CallCommon, callee *ssa.Function) ssa.Value {
	if len(callee.FreeVars) == 0 {
		if len(c.Args) == 0 {
			return nil
		}
		return c.Args[0]
	}
	return c.Value
}

func isHarnessContextCall(call *ssa.Call, seen, done map[ssa.Value]bool, fp *freshParamAnalysis) bool {
	if fp == nil || !fp.selectionAudited || call == nil || call.Common() == nil || call.Parent() == nil || call.Parent().Prog == nil {
		return false
	}
	c := call.Common()
	if c.IsInvoke() {
		if c.Method == nil || c.Method.Name() != "Context" || c.Method.Pkg() == nil || c.Method.Pkg().Path() != "testing" {
			return false
		}
		return closedHarnessContextReceiver(c.Value, call.Parent().Prog, fp)
	}
	callee := c.StaticCallee()
	if callee == nil || funcPkgPath(callee) != "testing" || callee.Name() != "Context" {
		return false
	}
	if syntheticInterfaceMethodWrapper(callee) {
		recv := wrapperReceiver(c, callee)
		return closedHarnessContextReceiver(recv, call.Parent().Prog, fp)
	}
	_, ok := harnessCalleeEffect(fp.selectionAudited, callee, false)
	return ok
}

func closedHarnessContextReceiver(recv ssa.Value, prog *ssa.Program, fp *freshParamAnalysis) bool {
	if recv == nil || prog == nil || fp == nil || !fp.selectionAudited {
		return false
	}
	if !subjectClosedDynamicValue(recv, map[ssa.Value]bool{}, fp) {
		return false
	}
	cts := map[types.Type]bool{}
	if !walkDynamicValue(recv, &dynamicValueCollector{types: cts}, map[ssa.Value]bool{}, nil, resetWalkState(fp)) || len(cts) == 0 {
		return false
	}
	for ct := range cts {
		cmethod := prog.LookupMethod(ct, nil, "Context")
		if !harnessInvokeAdmitted(fp.selectionAudited, cmethod) {
			return false
		}
	}
	return true
}

func harnessCancelCtxType(call *ssa.Call) types.Type {
	if call == nil || call.Parent() == nil || call.Parent().Prog == nil {
		return nil
	}
	return programCancelCtxType(call.Parent().Prog)
}

func programCancelCtxType(prog *ssa.Program) types.Type {
	if prog == nil {
		return nil
	}
	for _, pkg := range prog.AllPackages() {
		if pkg == nil || pkg.Pkg == nil || pkg.Pkg.Path() != "context" {
			continue
		}
		if obj := pkg.Pkg.Scope().Lookup("cancelCtx"); obj != nil {
			return types.NewPointer(obj.Type())
		}
	}
	return nil
}

func isAuditedStandardContextInvoke(audited bool, ct types.Type, method *types.Func) bool {
	if !audited || ct == nil || method == nil || method.Pkg() == nil || method.Pkg().Path() != "context" {
		return false
	}
	switch method.Name() {
	case "Deadline", "Done", "Err", "Value":
	default:
		return false
	}
	return isAuditedStandardContextRecvType(ct)
}

func isContextCancelMethod(method *types.Func) bool {
	if method == nil || method.Pkg() == nil || method.Pkg().Path() != "context" {
		return false
	}
	switch method.Name() {
	case "Deadline", "Done", "Err":
	default:
		return false
	}
	sig, ok := method.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	recvType := sig.Recv().Type()
	if named, ok := types.Unalias(recvType).(*types.Named); ok && named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "context" && named.Obj().Name() == "Context" {
		return true
	}
	return isAuditedStandardContextRecvType(recvType)
}

func isContextCancelSite(site ssa.CallInstruction) bool {
	if site == nil || site.Common() == nil {
		return false
	}
	c := site.Common()
	if c.IsInvoke() {
		return isContextCancelMethod(c.Method)
	}
	callee := c.StaticCallee()
	if callee == nil {
		return false
	}
	if mObj, ok := callee.Object().(*types.Func); ok && isContextCancelMethod(mObj) {
		return true
	}
	return false
}

func withIgnoreContextValuePayload(fp *freshParamAnalysis) *freshParamAnalysis {
	if fp == nil || !fp.selectionAudited || fp.ignoreContextValuePayload {
		return fp
	}
	copied := *fp
	copied.ignoreContextValuePayload = true
	copied.closedDone = map[ssa.Value]bool{}
	copied.typesMemo = map[ssa.Value][]types.Type{}
	copied.typesFailed = map[ssa.Value]bool{}
	copied.funcsMemo = map[ssa.Value][]*ssa.Function{}
	copied.funcsFailed = map[ssa.Value]bool{}
	copied.invokeTargets = map[ssa.CallInstruction]map[*ssa.Function]bool{}
	copied.invokeFailed = map[ssa.CallInstruction]bool{}
	if fp.rootDone != nil {
		copied.rootDone = map[ssa.Value]bool{}
		copied.rootLowlink = map[ssa.Value]int{}
		copied.rootHasLeaf = map[ssa.Value]bool{}
		copied.rootUsedSubject = map[ssa.Value]bool{}
	}
	return &copied
}

func contextCancelMethodFP(site ssa.CallInstruction, fp *freshParamAnalysis) *freshParamAnalysis {
	if fp == nil || !fp.selectionAudited || fp.ignoreContextValuePayload || !isContextCancelSite(site) {
		return fp
	}
	return withIgnoreContextValuePayload(fp)
}

func isAuditedStandardContextRecvType(ct types.Type) bool {
	if ct == nil {
		return false
	}
	base := ct
	if ptr, ok := types.Unalias(ct).(*types.Pointer); ok {
		base = ptr.Elem()
	}
	named, ok := types.Unalias(base).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "context" {
		return false
	}
	switch named.Obj().Name() {
	case "cancelCtx", "withoutCancelCtx", "valueCtx", "backgroundCtx", "todoCtx", "emptyCtx":
		return true
	default:
		return false
	}
}
