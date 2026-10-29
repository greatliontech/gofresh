package closure

import (
	"go/types"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
)

type externalEffectKind uint8

// The enum ORDER is the effect projection's primary sort key; the proof's
// refusal names the highest-ranked blocking effect under effectCauseRank
// with this order as the tie-break — so inserting or reordering members,
// and any rank-table edit that can move a RECORDED reason text, owe an
// ObservationRTA bump (the recorded-evidence versioning clause) — and,
// because the persisted effect and testing scans store the kind as its
// number, an effectScanStrategy and a testingScanStrategy bump too; a
// re-stratification provably touching no recorded class states that
// exemption in its commit message instead.
const (
	externalEffectOpaque externalEffectKind = iota
	externalEffectStandardInput
	externalEffectFormattedOutput
	externalEffectEnvironment
	externalEffectFileIO
	externalEffectFilesystemMutation
	externalEffectPathMutation
	externalEffectTestRuntime
	externalEffectNetwork
	externalEffectPlugin
	externalEffectNative
	externalEffectLinkage
	externalEffectUnauditedStandard
)

// externalEffect retains the complete machine-readable fact independently of the
// single legacy diagnostic projected through Closure.Reason.
type externalEffect struct {
	kind        externalEffectKind
	packagePath string
	symbol      string
	detail      string
	reason      string
	unrefinable bool
	observable  bool
}

type maximalEffectScan struct {
	effects []externalEffect
	// importCandidates are diagnostic-only candidates: a plain
	// always-external import names its package as a preferred-reason
	// candidate at its rank without contributing a verdict-bearing
	// effect - an unused import blocks nothing
	// (REQ-closure-observability-cause-order).
	importCandidates []externalEffect
	preferred        string
}

func (s *maximalEffectScan) add(effect externalEffect) {
	s.effects = appendExternalEffect(s.effects, effect)
}

func opaqueExternalEffect(kind externalEffectKind, reason string) externalEffect {
	return externalEffect{kind: kind, detail: reason, reason: reason + ambientDischargeChannel(kind)}
}

func symbolExternalEffect(kind externalEffectKind, pkgPath, name, reason string) externalEffect {
	return externalEffect{kind: kind, packagePath: pkgPath, symbol: name, reason: reason + ambientDischargeChannel(kind)}
}

// auditedStandardMethod is the receiver-qualified arm of the walk
// tiers' standard-symbol ladder: a standard method admitted where its
// receiver distinguishes it from an ambient declaration sharing its
// bare name — time's pure Time methods behind the fold-excluded shared
// names, and reflect's (Type).Key behind the iteration read sharing
// it. The fold sees no method call and has no such arm, so the
// bare-name exclusions keep the variables and functions refused there.
// A bound method value's wrapper declares the method it delegates to,
// so the enumerated-target arm judges it as that method through this
// ladder; the wrapper's own body is never walked
// (REQ-closure-observability-audited-set).
func auditedStandardMethod(audited bool, fn *ssa.Function) bool {
	if !audited || fn == nil {
		return false
	}
	f, ok := fn.Object().(*types.Func)
	if !ok {
		return false
	}
	return auditset.ReceiverMethod(f, "time", auditset.TimeMethod) || auditset.ReceiverMethod(f, "reflect", auditset.ReflectMethod) || auditset.ReceiverMethod(f, "math/rand", auditset.RandMethod) || auditset.ReceiverMethod(f, "sync/atomic", auditset.AtomicMethod)
}

// auditedStandardCallee is the walk tiers' whole standard admission
// for one callee — the bare-name ladder, the receiver-qualified arm,
// or an anonymous closure parented under an audited standard symbol
// (such as context.WithCancel's returned CancelFunc) — so no walk site
// can take one arm without the other.
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

// unauditedStandardEffect is the one spelling of the fallback every
// tier reaches for a standard symbol outside the audited sets — the
// fold's selector scan, the walk's enumerated dynamic target, and the
// walk's static callee.
func unauditedStandardEffect(pkgPath, name string) externalEffect {
	return symbolExternalEffect(externalEffectUnauditedStandard, pkgPath, name, "reaches unaudited standard operation "+pkgPath+"."+name)
}

// ambientDischargeChannel names the lift an ambient effect's boundary
// affords, composed by the constructors so every reason of the kind
// carries it (REQ-closure-refusal-channels). A network, plugin, or
// native reach is analyzed by no finer tier, and the closure walk
// honors no directive below the subject, so the channel is the
// subject's own: restructuring it away from the reach, or the
// subject-level purity responsibility — the //gofresh:pure directive on
// its declaration or the caller's purity assertion
// (REQ-purity-directive, REQ-purity-responsibility). Every other kind
// carries its lift elsewhere: an observable effect proceeds to the
// observation bracket, an unaudited standard reach names the toolchain
// audit through the selection notice.
func ambientDischargeChannel(kind externalEffectKind) string {
	switch kind {
	case externalEffectNetwork, externalEffectPlugin, externalEffectNative:
		return " (dischargeable by restructuring the subject away from the reach, or by " + PurityResponsibility + ")"
	default:
		return ""
	}
}

// PurityResponsibility is the one spelling of the subject-level purity
// channel every refusal that affords it names: the author's durable
// directive or the caller's recorded assertion (REQ-purity-directive,
// REQ-purity-responsibility; REQ-closure-refusal-channels).
const PurityResponsibility = "the //gofresh:pure directive on the subject's declaration or the caller's purity assertion"

func appendExternalEffect(effects []externalEffect, effect externalEffect) []externalEffect {
	if effect.reason == "" {
		return effects
	}
	for _, existing := range effects {
		if existing == effect {
			return effects
		}
	}
	return append(effects, effect)
}

type classBEntry struct {
	kind   externalEffectKind
	suffix string
}

// classBTable is the one declarative classification table for effect-bearing
// packages, and classBPackages is derived from its keys so the classifier
// and the maximal tier's dot-import backstop (packageHasClassifiedExternalAPI)
// can never disagree (REQ-closure-observability-audited-set).
var classBTable, classBPackages = func() (map[string]map[string]classBEntry, map[string]bool) {
	arms := []struct {
		pkgs   []string
		kind   externalEffectKind
		suffix string
		names  []string
	}{
		{
			pkgs:   []string{"fmt"},
			kind:   externalEffectStandardInput,
			suffix: " (standard input)",
			names:  []string{"Scan", "Scanf", "Scanln", "Fscan", "Fscanf", "Fscanln"},
		},
		{
			pkgs:   []string{"fmt"},
			kind:   externalEffectFormattedOutput,
			suffix: " (formatted output)",
			names:  []string{"Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln"},
		},
		{
			pkgs:   []string{"os"},
			kind:   externalEffectEnvironment,
			suffix: " (environment input)",
			names:  []string{"Getenv", "LookupEnv", "Environ", "ExpandEnv"},
		},
		{
			pkgs:   []string{"os"},
			kind:   externalEffectFileIO,
			suffix: " (file I/O)",
			names:  []string{"Open", "OpenFile", "ReadFile", "ReadDir", "Stat", "Lstat"},
		},
		{
			pkgs:   []string{"os"},
			kind:   externalEffectFilesystemMutation,
			suffix: " (filesystem mutation)",
			names:  []string{"Create", "CreateTemp", "WriteFile"},
		},
		{
			pkgs:   []string{"os"},
			kind:   externalEffectPathMutation,
			suffix: " (path mutation)",
			names:  []string{"CopyFS", "Link", "Mkdir", "MkdirAll", "MkdirTemp", "Remove", "RemoveAll", "Rename", "Symlink"},
		},
		{
			pkgs:   []string{"syscall", "golang.org/x/sys/unix"},
			kind:   externalEffectFilesystemMutation,
			suffix: " (filesystem mutation)",
			names:  []string{"Creat"},
		},
		{
			pkgs:   []string{"syscall", "golang.org/x/sys/unix"},
			kind:   externalEffectPathMutation,
			suffix: " (path mutation)",
			names:  []string{"Link", "Linkat", "Mkdir", "Mkdirat", "Rename", "Renameat", "Renameat2", "Rmdir", "Symlink", "Symlinkat", "Unlink", "Unlinkat"},
		},
		{
			// crypto/rand's operation surface is the entropy class: Read, Text,
			// Prime, and Int are classified as external system calls rather than
			// left to the unaudited fallback (REQ-closure-observability-entropy).
			pkgs:   []string{"crypto/rand"},
			kind:   externalEffectNative,
			suffix: " (entropy)",
			names:  []string{"Read", "Text", "Int", "Prime"},
		},
		{
			pkgs:   []string{"testing"},
			kind:   externalEffectPathMutation,
			suffix: " (process or path mutation)",
			names:  []string{"TempDir", "Chdir", "Setenv"},
		},
		{
			pkgs:   []string{"testing"},
			kind:   externalEffectTestRuntime,
			suffix: " (test runtime configuration)",
			names:  []string{"Short", "Verbose", "Testing", "CoverMode", "Coverage", "Deadline", "Parallel", "ArtifactDir"},
		},
		{
			pkgs:   []string{"testing"},
			kind:   externalEffectTestRuntime,
			suffix: " (test runtime execution)",
			names:  []string{"Run", "Fuzz", "RunParallel", "Elapsed", "Result", "AllocsPerRun", "Benchmark", "RunBenchmarks", "RunExamples", "RunTests", "Main", "MainStart"},
		},
		{
			pkgs:   []string{"net"},
			kind:   externalEffectNetwork,
			suffix: " (network I/O)",
			names:  []string{"Dial", "DialContext", "DialTCP", "DialUDP", "DialIP", "Listen", "ListenTCP", "ListenUDP", "ListenIP", "ListenPacket"},
		},
		{
			pkgs:   []string{"net/http"},
			kind:   externalEffectNetwork,
			suffix: " (network I/O)",
			names:  []string{"Get", "Head", "Post", "PostForm", "Do", "ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS"},
		},
		{
			pkgs:   []string{"html/template", "text/template"},
			kind:   externalEffectFileIO,
			suffix: " (file I/O)",
			names:  []string{"ParseFiles", "ParseGlob"},
		},
		{
			pkgs:   []string{"plugin"},
			kind:   externalEffectPlugin,
			suffix: "",
			names:  []string{"Open", "Lookup"},
		},
	}
	table := make(map[string]map[string]classBEntry)
	pkgs := make(map[string]bool)
	for _, arm := range arms {
		for _, pkg := range arm.pkgs {
			pkgs[pkg] = true
			byName := table[pkg]
			if byName == nil {
				byName = make(map[string]classBEntry, len(arm.names))
				table[pkg] = byName
			}
			for _, name := range arm.names {
				byName[name] = classBEntry{kind: arm.kind, suffix: arm.suffix}
			}
		}
	}
	return table, pkgs
}()

func classBEffect(pkgPath, name string) (externalEffect, bool) {
	entry, ok := classBTable[pkgPath][name]
	if !ok {
		return externalEffect{}, false
	}
	return symbolExternalEffect(entry.kind, pkgPath, name, "reaches "+pkgPath+"."+name+entry.suffix), true
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
	effect.observable = true
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
	if !effect.observable || effect.kind != externalEffectTestRuntime || effect.packagePath != "testing" {
		return false
	}
	if effect.symbol == "B.N" {
		return true
	}
	entry, ok := harnessAdmissions[effect.symbol]
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

// auditedHarnessLogging reports whether a testing-package symbol is the
// harness's failure/logging channel (REQ-closure-observability-harness-logging).
func auditedHarnessLogging(audited bool, pkgPath, name string) bool {
	return audited && pkgPath == "testing" && harnessAdmissions[name].family == harnessFamilyLogging
}

// harnessLoggingEffect is the admitted harness fact the walk records in
// place of descending into harness internals.
func harnessLoggingEffect(name string) externalEffect {
	return harnessClassifiedEffect(name, harnessAdmissions["Log"].reasonSuffix)
}

// auditedHarnessPacing reports whether a testing-package symbol is the
// benchmark harness's pacing protocol (REQ-closure-observability-benchmark-pacing).
func auditedHarnessPacing(audited bool, pkgPath, name string) bool {
	return audited && pkgPath == "testing" && harnessAdmissions[name].family == harnessFamilyPacing
}

// harnessPacingEffect is the admitted harness fact the walk records for
// a pacing call or the B.N field read.
func harnessPacingEffect(name string) externalEffect {
	return harnessClassifiedEffect(name, harnessAdmissions["Loop"].reasonSuffix)
}

// harnessSubtestDriverEffect is the admitted harness fact recorded for a
// reached subtest driver ((*T).Run, (*B).Run).
func harnessSubtestDriverEffect() externalEffect {
	return harnessClassifiedEffect("Run", harnessAdmissions["Run"].reasonSuffix)
}

// classBPureStandard audits specific operations of effect-bearing
// standard packages as pure: value-to-value computation with no ambient
// acquisition, no testlog-invisible channel, and no machine-variant
// results — every per-package surface one table in internal/auditset
// (fmt, reflect, time, net/url, path/filepath, flag). fmt's Sprint
// family qualifies (arguments' methods stay visible to reachability);
// its Print family is classified output and its Scan family classified
// input, so only the pure remainder lands there. reflect's runtime-type
// set and descriptor-view surface read sealed descriptors and invoke
// nothing, its dispatch channel refused by name. time's fixed-argument
// construction and value computation —
// Date and the calendar, clock-field, zone-accessor, formatting,
// comparison, and duration operations over Time, Duration, Month, and
// Weekday values, FixedZone included — read neither the clock, nor
// the local zone, nor the exported time.UTC variable: the ambient
// channels enter only through Now/Since/Until and the timers (the
// clock), Local, the Unix constructors, and the loading constructors
// (the local zone and the zone database), Parse (which consults Local
// for zone abbreviations), and (Time).Location (the time.UTC variable's
// value, a pointer into the package's own state), all of which stay
// refused. The set is a table in internal/auditset because this
// match is by BARE NAME: a name shared by a pure declaration and an
// ambient one (After, Local, UTC, Unix, UnixMilli, UnixMicro,
// Location, AddDate) is excluded from it whole, the pure method forms
// living in the receiver-qualified table auditedStandardCallee
// consults where the walk knows the callee — so this table names only
// the collision-free surface. Execution-free
// references — an audited type or constant name (fmt.Stringer,
// time.Time, time.Month and its constants, time.Duration and its
// constants, time.Weekday and its constants, the layout constants) —
// declare
// or denote and execute nothing, and every dispatch through a value
// of such a type classifies at its own site. math/big is admitted
// whole as a member of the audited-pure package set
// (isSourceOnlyStandardPackage), not operation by operation here.
// Grows only by source audit (REQ-closure-observability-audited-set).
func classBPureStandard(audited bool, pkgPath, name string) bool {
	// Every per-package audited surface is one table in internal/auditset.
	return audited && auditset.Symbol(pkgPath, name)
}

// auditedStandardSymbol is the one ladder every tier consults for a
// standard package's symbol-level admissions — the class-B pure
// operations (every per-package symbol table, reflect's included) and
// the audited sync surface (synchronization, pooling, and memo sets) —
// so a further table can never be added at two consulting sites and
// missed at the third.
func auditedStandardSymbol(audited bool, pkgPath, name string) bool {
	return classBPureStandard(audited, pkgPath, name) || (audited && pkgPath == "sync" && auditset.SyncSurfaceName(name))
}

// fmtFprintFamily names fmt's writer-first print operations — the one
// classified family whose effect is decided by an operand: the writer
// receives every formatted byte, so a writer proven to be an audited
// in-memory sink makes the call Sprint-equivalent value computation,
// while Print (implicit stdout) and the Scan families carry their
// channel in the symbol itself
// (REQ-closure-observability-writer-sink).
func fmtFprintFamily(audited bool, pkgPath, name string) bool {
	if !audited || pkgPath != "fmt" {
		return false
	}
	switch name {
	case "Fprint", "Fprintf", "Fprintln":
		return true
	}
	return false
}

func classBReason(pkgPath, name string) string {
	effect, ok := classBEffect(pkgPath, name)
	if !ok {
		return ""
	}
	return effect.reason
}
