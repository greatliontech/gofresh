package closure

import (
	"go/constant"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/tools/go/ssa"
)

func observableCallEffect(effect externalEffect, call *ssa.CallCommon, site ssa.CallInstruction, fp *freshParamAnalysis) bool {
	if call == nil {
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
	pkgPath, name := funcPkgPath(callee), callee.Name()
	if object := callee.Object(); object != nil {
		name = object.Name()
	}
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
		pkgPath, name := funcPkgPath(callee), callee.Name()
		if object := callee.Object(); object != nil {
			name = object.Name()
		}
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
	pkgPath, name := funcPkgPath(callee), callee.Name()
	if object := callee.Object(); object != nil {
		name = object.Name()
	}
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
		name := callee.Name()
		if object := callee.Object(); object != nil {
			name = object.Name()
		}
		return funcPkgPath(callee) == "testing" && name == "TempDir"
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

func locallyClosedDynamicValue(value ssa.Value, seen map[ssa.Value]bool) bool {
	if value == nil || seen[value] {
		return false
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Function, *ssa.Builtin, *ssa.Const, *ssa.MakeClosure:
		return true
	case *ssa.MakeInterface:
		return true
	case *ssa.ChangeInterface:
		return locallyClosedDynamicValue(value.X, seen)
	case *ssa.TypeAssert:
		// Asserting narrows the dynamic-type set of X, never widens it:
		// the asserted value is closed exactly when its operand is.
		return locallyClosedDynamicValue(value.X, seen)
	case *ssa.ChangeType:
		return locallyClosedDynamicValue(value.X, seen)
	case *ssa.Convert:
		return locallyClosedDynamicValue(value.X, seen)
	case *ssa.Phi:
		if len(value.Edges) == 0 {
			return false
		}
		for _, edge := range value.Edges {
			if !locallyClosedDynamicValue(edge, seen) {
				return false
			}
		}
		return true
	case *ssa.Extract:
		return locallyClosedDynamicValue(value.Tuple, seen)
	default:
		return false
	}
}
