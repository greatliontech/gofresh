package observability

import (
	"context"
	"go/types"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure"
)

// auditedStandardMethod is the receiver-qualified arm of the walk
// tiers' standard-symbol ladder: a standard method admitted where its
// receiver distinguishes it from an ambient declaration sharing its
// bare name — time's pure Time methods behind the fold-excluded shared
// names, and reflect's (Type).Key behind the iteration read sharing
// it (REQ-closure-observability-audited-set).
func auditedStandardMethod(audited bool, fn *ssa.Function) bool {
	if !audited || fn == nil {
		return false
	}
	f, ok := fn.Object().(*types.Func)
	if !ok {
		return false
	}
	return auditset.ReceiverMethod(f, "time", auditset.TimeMethod) || auditset.ReceiverMethod(f, "reflect", auditset.ReflectMethod) || auditset.ReceiverMethod(f, "math/rand", auditset.RandMethod) || auditset.ReceiverMethod(f, "sync/atomic", auditset.AtomicMethod) || auditset.ReceiverMethod(f, "runtime/debug", auditset.RuntimeDebugMethod) || auditset.ReceiverMethod(f, "go/ast", auditset.GoASTMethod)
}

// auditedStandardCallee is the walk tiers' whole standard admission
// for one callee — the bare-name ladder, the receiver-qualified arm,
// or an anonymous closure parented under an audited standard symbol
// (such as context.WithCancel's returned CancelFunc).
func auditedStandardCallee(audited bool, pkgPath, name string, fn *ssa.Function) bool {
	if auditedStandardSymbol(audited, pkgPath, name) || auditedStandardMethod(audited, fn) {
		return true
	}
	if audited && pkgPath == "context" && fn != nil && fn.Signature != nil && fn.Signature.Recv() != nil {
		switch fn.Name() {
		case "Deadline", "Done", "Err", "Value":
			if isAuditedStandardContextRecvType(fn.Signature.Recv().Type()) {
				return true
			}
		}
	}
	if audited && pkgPath == "fmt" && fn != nil && fn.Name() == "Error" && fn.Signature != nil && fn.Signature.Recv() != nil {
		if isAuditedStandardFmtErrorRecvType(fn.Signature.Recv().Type()) {
			return true
		}
	}
	if fn != nil && fn.Object() == nil && fn.Parent() != nil {
		top := fn.Parent()
		for top.Parent() != nil {
			top = top.Parent()
		}
		topName := functionSymbolName(top)
		return auditedStandardSymbol(audited, pkgPath, topName) || auditedStandardMethod(audited, top) || (audited && pkgPath == "context" && topName == "propagateCancel")
	}
	return false
}

type harnessFamily uint8

const (
	harnessFamilyNone harnessFamily = iota
	harnessFamilyLogging
	harnessFamilyPacing
	harnessFamilySubtestDriver
	harnessFamilyFuzzDriver
	harnessFamilyLifecycle
)

type harnessAdmission struct {
	family         harnessFamily
	receivers      []string
	reasonSuffix   string
	dynamicTarget  bool
	invokeAdmitted bool
}

// harnessAdmissions is the one table classifying the testing-harness
// families across static calls, enumerated dynamic targets, invoke admission,
// body-scan cutting, and immutable-environment outcome eligibility
// (REQ-closure-observability-analysis).
var harnessAdmissions = func() map[string]harnessAdmission {
	out := map[string]harnessAdmission{
		"Run": {
			family:       harnessFamilySubtestDriver,
			receivers:    []string{"T", "B"},
			reasonSuffix: " (test harness subtest execution)",
		},
		"Fuzz": {
			family:    harnessFamilyFuzzDriver,
			receivers: []string{"F"},
		},
		"Context": {
			family:         harnessFamilyLifecycle,
			receivers:      []string{"T", "B", "F", "common"},
			reasonSuffix:   " (test harness context)",
			dynamicTarget:  true,
			invokeAdmitted: true,
		},
	}
	for _, name := range []string{"Fatal", "Fatalf", "Error", "Errorf", "Log", "Logf", "Skip", "Skipf", "SkipNow", "Fail", "FailNow"} {
		out[name] = harnessAdmission{
			family:         harnessFamilyLogging,
			reasonSuffix:   " (test harness logging)",
			dynamicTarget:  true,
			invokeAdmitted: true,
		}
	}
	for _, name := range []string{"N", "Loop", "ResetTimer", "StartTimer", "StopTimer"} {
		out[name] = harnessAdmission{
			family:        harnessFamilyPacing,
			reasonSuffix:  " (benchmark pacing)",
			dynamicTarget: true,
		}
	}
	return out
}()

func harnessReceiverMatches(fn *ssa.Function, receivers []string) bool {
	if len(receivers) == 0 {
		return true
	}
	if fn == nil || fn.Signature == nil || fn.Signature.Recv() == nil {
		return false
	}
	recv := fn.Signature.Recv().Type()
	if ptr, ok := types.Unalias(recv).(*types.Pointer); ok {
		recv = ptr.Elem()
	}
	named, ok := types.Unalias(recv).(*types.Named)
	if !ok || named.Obj() == nil {
		return false
	}
	name := named.Obj().Name()
	for _, want := range receivers {
		if name == want {
			return true
		}
	}
	return false
}

func harnessClassifiedEffect(name, suffix string) externalEffect {
	effect := symbolExternalEffect(externalEffectTestRuntime, "testing", name, "reaches testing."+name+suffix)
	effect.Observable = true
	return effect
}

// harnessCalleeEffect classifies a static or dynamic testing-harness callee
// through the single harnessAdmissions table.
func harnessCalleeEffect(audited bool, fn *ssa.Function, dynamic bool) (externalEffect, bool) {
	if !audited || fn == nil || funcPkgPath(fn) != "testing" {
		return externalEffect{}, false
	}
	name := functionSymbolName(fn)
	entry, ok := harnessAdmissions[name]
	if !ok || entry.reasonSuffix == "" || (dynamic && !entry.dynamicTarget) || !harnessReceiverMatches(fn, entry.receivers) {
		return externalEffect{}, false
	}
	return harnessClassifiedEffect(name, entry.reasonSuffix), true
}

// harnessBodyCut reports whether a testing-harness function's body is cut from
// the walk (logging, pacing, subtest driver when audited; fuzz driver always).
func harnessBodyCut(audited bool, fn *ssa.Function) bool {
	if fn == nil || funcPkgPath(fn) != "testing" {
		return false
	}
	entry, ok := harnessAdmissions[functionSymbolName(fn)]
	if !ok || !harnessReceiverMatches(fn, entry.receivers) {
		return false
	}
	return entry.family == harnessFamilyFuzzDriver || audited
}

// harnessOutcomeAdmitted reports whether an observable testing-runtime effect
// belongs to the admitted harness families (logging, pacing including B.N,
// or subtest driver) that do not veto immutable-environment outcomes.
func harnessOutcomeAdmitted(effect externalEffect) bool {
	if !effect.Observable || effect.Kind != externalEffectTestRuntime || effect.PackagePath != "testing" {
		return false
	}
	if effect.Symbol == "B.N" {
		return true
	}
	entry, ok := harnessAdmissions[effect.Symbol]
	return ok && entry.reasonSuffix != ""
}

// harnessInvokeAdmitted reports whether a testing-harness method is admitted as
// an RTA-enumerated interface-invoke target on testing.TB.
func harnessInvokeAdmitted(audited bool, fn *ssa.Function) bool {
	if !audited || fn == nil || funcPkgPath(fn) != "testing" {
		return false
	}
	entry, ok := harnessAdmissions[functionSymbolName(fn)]
	return ok && entry.invokeAdmitted && harnessReceiverMatches(fn, entry.receivers)
}

func auditedHarnessLogging(audited bool, pkgPath, name string) bool {
	return audited && pkgPath == "testing" && harnessAdmissions[name].family == harnessFamilyLogging
}

func harnessLoggingEffect(name string) externalEffect {
	return harnessClassifiedEffect(name, harnessAdmissions["Log"].reasonSuffix)
}

func auditedHarnessPacing(audited bool, pkgPath, name string) bool {
	return audited && pkgPath == "testing" && harnessAdmissions[name].family == harnessFamilyPacing
}

func harnessPacingEffect(name string) externalEffect {
	return harnessClassifiedEffect(name, harnessAdmissions["Loop"].reasonSuffix)
}

func harnessSubtestDriverEffect() externalEffect {
	return harnessClassifiedEffect("Run", harnessAdmissions["Run"].reasonSuffix)
}

func isAdmittedOSGetwdErrorType(audited bool, ct types.Type, fp *freshParamAnalysis) bool {
	if !audited || ct == nil || fp == nil || fp.summary == nil || fp.summary.userMutatesOSWrapperError {
		return false
	}
	u := types.Unalias(ct)
	if ptr, ok := u.(*types.Pointer); ok {
		named, ok := types.Unalias(ptr.Elem()).(*types.Named)
		if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
			return false
		}
		pkgPath, name := named.Obj().Pkg().Path(), named.Obj().Name()
		return (pkgPath == "os" && name == "SyscallError") || ((pkgPath == "io/fs" || pkgPath == "os") && name == "PathError") || (pkgPath == "syscall" && name == "Errno")
	}
	named, ok := u.(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == "syscall" && named.Obj().Name() == "Errno"
}

func isAdmittedOSGetwdErrorMethod(audited bool, callee *ssa.Function, fp *freshParamAnalysis) bool {
	if !audited || callee == nil || callee.Name() != "Error" || callee.Signature == nil || callee.Signature.Recv() == nil {
		return false
	}
	return isAdmittedOSGetwdErrorType(audited, callee.Signature.Recv().Type(), fp)
}

func isAdmittedPureMathSymbol(audited bool, pureDelegates map[string]bool, pkgPath string, callee *ssa.Function) bool {
	if !audited || pkgPath != "math" || callee == nil || (callee.Signature != nil && callee.Signature.Recv() != nil) {
		return false
	}
	return pureDelegates["math:"+functionSymbolName(callee)]
}

func admitPureDelegateCall(audited bool, pureDelegates map[string]bool, pkgPath string, callee *ssa.Function, site ssa.CallInstruction, callerStd bool, fp *freshParamAnalysis) bool {
	if !audited || pkgPath == "" {
		return false
	}
	if isSourceOnlyStandardPackage(true, pkgPath) {
		return true
	}
	if isAdmittedPureMathSymbol(audited, pureDelegates, pkgPath, callee) {
		if callerStd || site == nil {
			return true
		}
		c := site.Common()
		if c == nil || c.IsInvoke() {
			return false
		}
		if sc := c.StaticCallee(); sc != nil {
			return sc == callee
		}
		if fp == nil {
			return false
		}
		siteFP := contextCancelMethodFP(site, fp)
		if !subjectClosedDynamicValue(c.Value, make(map[ssa.Value]bool), siteFP) {
			return false
		}
		held, ok := closedDynamicTargets(c.Value, siteFP)
		return ok && held[callee]
	}
	if !pureDelegates[pkgPath] {
		if site == nil || site.Common() == nil || !site.Common().IsInvoke() || !isAdmittedOSGetwdErrorMethod(audited, callee, fp) {
			return false
		}
		siteFP := contextCancelMethodFP(site, fp)
		if !subjectClosedDynamicValue(site.Common().Value, make(map[ssa.Value]bool), siteFP) {
			return false
		}
		held, ok := closedInvokeTargets(site, siteFP)
		return ok && held[callee]
	}
	if callerStd || isInternalStdPackagePath(pkgPath) {
		return true
	}
	if site == nil || callee == nil {
		return false
	}
	c := site.Common()
	if c == nil {
		return false
	}
	if c.IsInvoke() {
		if fp == nil {
			return false
		}
		siteFP := contextCancelMethodFP(site, fp)
		if !subjectClosedDynamicValue(c.Value, make(map[ssa.Value]bool), siteFP) {
			return false
		}
		held, ok := closedInvokeTargets(site, siteFP)
		return ok && held[callee]
	}
	if sc := c.StaticCallee(); sc != nil {
		if sc != callee {
			return false
		}
		if strings.HasPrefix(callee.Synthetic, "bound ") {
			mc, ok := c.Value.(*ssa.MakeClosure)
			return ok && len(mc.Bindings) > 0 && isAuditedStdAliasValue(audited, mc.Bindings[0])
		}
		if len(c.Args) > 0 && ((callee.Signature != nil && callee.Signature.Recv() != nil) || strings.HasPrefix(callee.Synthetic, "thunk ")) {
			return isAuditedStdAliasValue(audited, c.Args[0])
		}
		return false
	}
	if fp == nil {
		return false
	}
	siteFP := contextCancelMethodFP(site, fp)
	if !subjectClosedDynamicValue(c.Value, make(map[ssa.Value]bool), siteFP) {
		return false
	}
	held, ok := closedDynamicTargets(c.Value, siteFP)
	return ok && held[callee]
}

// admittedGatedStandardSymbol evaluates call-site or build-flag gated standard
// operations (writer-first sinks, fmt.Fscan* readers, go/parser source calls,
// and -buildvcs + go.mod-gated runtime/debug.ReadBuildInfo).
func admittedGatedStandardSymbol(
	audited bool,
	emitTrace bool,
	h *closure.Hasher,
	targetPkgPath string,
	callee *ssa.Function,
	pkgPath, name string,
	c *ssa.CallCommon,
	site ssa.CallInstruction,
	fp *freshParamAnalysis,
) bool {
	if !audited || callee == nil {
		return false
	}
	if pkgPath == "runtime/debug" && name == "ReadBuildInfo" && (callee.Signature == nil || callee.Signature.Recv() == nil) {
		if c != nil && c.IsInvoke() {
			return false
		}
		return h != nil && h.AdmitsTier2ReadBuildInfo(targetPkgPath)
	}
	if c == nil || c.StaticCallee() != callee {
		return false
	}
	var ctx context.Context
	if h != nil {
		ctx = h.Context()
	} else if fp != nil {
		ctx = fp.traceCtx
	}
	if auditset.WriterFirstStdFunc(pkgPath, name) {
		if len(c.Args) == 0 {
			return false
		}
		if emitTrace {
			return inMemoryStreamOperand(ctx, site, c.Args[0], streamKindWriter, fp)
		}
		ok, _ := inMemoryStreamValue(c.Args[0], streamKindWriter, fp, 0, nil)
		return ok
	}
	if fmtFscanFamily(true, pkgPath, name) {
		if len(c.Args) == 0 {
			return false
		}
		if emitTrace {
			return inMemoryStreamOperand(ctx, site, c.Args[0], streamKindReader, fp)
		}
		ok, _ := inMemoryStreamValue(c.Args[0], streamKindReader, fp, 0, nil)
		return ok
	}
	if pkgPath == "go/parser" && auditset.GoParserSourceFunc(name) {
		return len(c.Args) == 4 && admittedGoParserSourceCall(ctx, emitTrace, site, c, fp)
	}
	return false
}

// admittedResolvedStandardOrDelegateCallee evaluates standard/delegate callee
// admission for an already-resolved invoke or dynamic function target without
// re-entering closedInvokeTargets or closedDynamicTargets.
func admittedResolvedStandardOrDelegateCallee(
	audited bool,
	pureDelegates map[string]bool,
	h *closure.Hasher,
	targetPkgPath, pkgPath string,
	callee *ssa.Function,
	isInvoke bool,
	fp *freshParamAnalysis,
) bool {
	if !audited || callee == nil || pkgPath == "" {
		return false
	}
	name := functionSymbolName(callee)
	if isSourceOnlyStandardPackage(true, pkgPath) || auditedStandardCallee(true, pkgPath, name, callee) {
		return true
	}
	if !isInvoke && isAdmittedPureMathSymbol(true, pureDelegates, pkgPath, callee) {
		return true
	}
	if pureDelegates[pkgPath] {
		return true
	}
	if isInvoke && isAdmittedOSGetwdErrorMethod(true, callee, fp) {
		return true
	}
	if isInvoke && callee.Signature != nil && callee.Signature.Recv() != nil {
		rt := callee.Signature.Recv().Type()
		if isAdmittedPureHashConcreteType(true, rt) {
			return true
		}
		if isHMAC, _, okH := classifyStatefulStreamType(rt, streamKindWriter); okH && isHMAC {
			return true
		}
	}
	if !isInvoke && pkgPath == "runtime/debug" && name == "ReadBuildInfo" && (callee.Signature == nil || callee.Signature.Recv() == nil) {
		return h != nil && h.AdmitsTier2ReadBuildInfo(targetPkgPath)
	}
	return false
}

// admittedPureStandardOrDelegateCallee is the unified SSA standard/delegate
// callee admission ladder shared by static calls and RTA dynamic targets.
func admittedPureStandardOrDelegateCallee(
	audited bool,
	pureDelegates map[string]bool,
	emitTrace bool,
	h *closure.Hasher,
	targetPkgPath, pkgPath string,
	callee *ssa.Function,
	site ssa.CallInstruction,
	callerStd bool,
	fp *freshParamAnalysis,
) bool {
	if !audited || callee == nil || pkgPath == "" {
		return false
	}
	name := functionSymbolName(callee)
	var c *ssa.CallCommon
	if site != nil {
		c = site.Common()
	}
	if admittedGatedStandardSymbol(audited, emitTrace, h, targetPkgPath, callee, pkgPath, name, c, site, fp) {
		return true
	}
	if isSourceOnlyStandardPackage(true, pkgPath) || auditedStandardCallee(true, pkgPath, name, callee) {
		return true
	}
	return admitPureDelegateCall(true, pureDelegates, pkgPath, callee, site, callerStd, fp)
}
