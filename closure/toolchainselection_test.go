package closure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// Every selection the structural content verifier admits or refuses on the
// running toolchain: the default, race, tag, cross-platform, and cgo-off
// selections admit by structural AST verification without hardcoded per-release
// digest tables; an unclassifiable flag set refuses
// (REQ-closure-observability-toolchain-key).
func TestSelectionsAdmitByContent(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library under several selections")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	hasher := func(flags ...string) *Hasher {
		t.Helper()
		h, err := newAt(dir, flags...)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	if h := hasher(); !h.SelectionAudited() {
		t.Fatalf("running toolchain failed structural verification: %s", h.SelectionNotice())
	}
	cgo := cgoEnabled(t)
	for _, tc := range []struct {
		name  string
		flags []string
		cgo   bool
	}{
		{"race selection", []string{"-race"}, true},
		{"a tag no audited file is constrained on", []string{"-tags=dup"}, false},
		{"race with such a tag", []string{"-race", "-tags=dup"}, true},
	} {
		if tc.cgo && !cgo {
			t.Logf("%s: skipped, cgo disabled", tc.name)
			continue
		}
		if h := hasher(tc.flags...); !h.SelectionAudited() {
			t.Errorf("%s: refused — %s", tc.name, h.SelectionNotice())
		}
	}
	// A flag set the go command refuses lists nothing: refused as an
	// unreadable surface naming the go command's own statement — an
	// unclassifiable selection is never admitted.
	if h := hasher("-tags"); h.SelectionAudited() || !strings.Contains(h.SelectionAttribution(), "could not be read") {
		t.Errorf("unclassifiable flags: audited=%v attribution %q", h.SelectionAudited(), h.SelectionAttribution())
	}
	// A tag that selects netgo resolver override files refuses naming net.
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if h := hasher("-tags=netgo"); h.SelectionAudited() || !strings.Contains(h.SelectionAttribution(), "the audited surface of "+snapshot.Value("GOVERSION")+" moved in 1 keys: net") {
		t.Errorf("netgo selection: audited=%v attribution %q, want net named as moved", h.SelectionAudited(), h.SelectionAttribution())
	}
	if h, err := newAtEnv(context.Background(), dir, environmentWith("GOFLAGS=-tags=netgo"), "-tags=dup"); err != nil {
		t.Fatal(err)
	} else if !h.SelectionAudited() {
		t.Errorf("an explicit -tags=dup under GOFLAGS=-tags=netgo refused: %s", h.SelectionNotice())
	}
	if h := hasher("-tags=dup,netgo"); h.SelectionAudited() || !strings.HasSuffix(h.SelectionAttribution(), ": net") {
		t.Errorf("the explicit union served the override's record: audited=%v attribution %q", h.SelectionAudited(), h.SelectionAttribution())
	}
	// Cross-platform and cgo-off selections admit structurally without needing
	// per-platform digest rows.
	for _, env := range [][]string{
		environmentWith("GOOS=plan9", "GOARCH=amd64"),
		environmentWith("CGO_ENABLED=0"),
		environmentWith("GOOS=windows", "GOARCH=arm64"),
	} {
		if h, err := newAtEnv(context.Background(), dir, env); err != nil {
			t.Fatal(err)
		} else if !h.SelectionAudited() {
			t.Errorf("selection %v refused: %s", env, h.SelectionNotice())
		}
	}
}

// The degradation over explicit inputs: an unclassifiable flag set, an
// unreadable surface, packages failing structural verification named and
// bounded, and the audited verdict; the notice is axis + consequence + remedy,
// and the attribution the bare axis (REQ-closure-refusal-channels).
func TestToolchainSourceDegradationNamesEveryAxis(t *testing.T) {
	base := sourceDigests{
		Packages:  map[string]string{},
		inventory: map[string]listedPackage{},
	}
	for _, root := range auditedSurfaceTables() {
		first, _, _ := strings.Cut(root, "/")
		if strings.Contains(first, ".") {
			continue
		}
		digest := "digest-" + root
		base.Packages[root] = digest
		base.inventory[root] = listedPackage{ImportPath: root, Audited: true, digest: digest}
		memoKey := verifiedPackageMemoKey(root, digest)
		verifiedPackageMemo.Store(memoKey, true)
		t.Cleanup(func() { verifiedPackageMemo.Delete(memoKey) })
	}
	if d := toolchainSourceDegradation("go1.99.0", base, nil); !d.audited() || d.notice() != "" || d.axis != "" {
		t.Fatalf("every package verified, yet %+v", d)
	}

	unverifiedBytes := sourceDigests{
		Packages:  map[string]string{},
		inventory: map[string]listedPackage{},
	}
	for k, v := range base.Packages {
		unverifiedBytes.Packages[k] = v
		unverifiedBytes.inventory[k] = base.inventory[k]
	}
	unverifiedBytes.Packages["bytes"] = "corrupt-digest"

	for _, tc := range []struct {
		name    string
		d       sourceDigests
		listErr error
		axis    string
		remedy  string
	}{
		{"unreadable surface (an unclassifiable flag set included)", sourceDigests{}, errors.New("listing the standard library: boom"), "could not be read: listing the standard library: boom", "listed and readable"},
		{"one package failed verification", unverifiedBytes, nil, "moved in 1 keys: bytes", "structural source contracts"},
	} {
		d := toolchainSourceDegradation("go1.99.0", tc.d, tc.listErr)
		if d.audited() || !strings.Contains(d.axis, tc.axis) || !strings.Contains(d.remedy, tc.remedy) {
			t.Errorf("%s: degradation %+v, want axis %q and remedy %q", tc.name, d, tc.axis, tc.remedy)
		}
		if notice := d.notice(); !strings.HasPrefix(notice, "toolchain-selection audit: "+d.axis+" — ") || !strings.HasSuffix(notice, d.remedy) {
			t.Errorf("%s: notice %q is not axis+consequence+remedy", tc.name, notice)
		}
		requireBareAxis(t, tc.name, d.notice(), d.axis)
	}
	// Many failed keys: bounded to 8 and the rest counted.
	many := sourceDigests{
		Packages:  map[string]string{},
		inventory: map[string]listedPackage{},
	}
	for _, p := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"} {
		many.Packages[p] = "x"
	}
	d := toolchainSourceDegradation("go1.99.0", many, nil)
	if !strings.Contains(d.axis, "moved in ") || !strings.Contains(d.axis, "a, b, c, d, e, f, g, h (+") {
		t.Fatalf("bounded naming: %q", d.axis)
	}
}

// Equal admission Booleans cannot alias different source or policy inputs, and
// an unaudited selection never shares an effectScanScope or AnalysisScope with
// an audited selection over identical content and policy.
func TestEffectScanScopeDiscriminatesContentAndPolicy(t *testing.T) {
	h := Hasher{selectionResolved: true, source: sourceDigests{Content: "content-a", Policy: "policy-a"}}
	base := h.effectScanScope()
	if base != effectScanStrategy+" "+runtime.Version()+"|content-a|policy-a" {
		t.Fatalf("effect scope lost a dependency: %q", base)
	}
	unaudited := Hasher{selectionResolved: true, selection: selectionDegradation{axis: "moved"}, source: sourceDigests{Content: "content-a", Policy: "policy-a"}}
	if unaudited.effectScanScope() == base {
		t.Fatal("unaudited selection shared effectScanScope with audited selection")
	}
	caller := AnalysisScope{ProofStrategy: "proof", FactStrategy: "facts", Toolchain: "tc", BuildConfig: "bc"}
	if auditedScope, unauditedScope := h.SetAnalysisScope(caller), unaudited.SetAnalysisScope(caller); auditedScope.Proofs() == unauditedScope.Proofs() || auditedScope.Facts() == unauditedScope.Facts() {
		t.Fatal("unaudited selection shared AnalysisScope with audited selection")
	}
	for _, source := range []sourceDigests{
		{Content: "content-b", Policy: "policy-a"},
		{Content: "content-a", Policy: "policy-b"},
	} {
		h.source = source
		if h.effectScanScope() == base {
			t.Fatal("different dependencies share a scope")
		}
	}
	for _, source := range []sourceDigests{{Content: "content-a"}, {Policy: "policy-a"}, {}} {
		h.source = source
		if h.effectScanScope() != "" {
			t.Fatal("incomplete dependencies armed the memo")
		}
	}
}

// An unaudited selection degrades every stdlib admission to the
// ordinary fail-closed classification — the same posture as an
// unlisted toolchain — at the admission functions themselves.
func TestUnauditedSelectionDisablesAdmissions(t *testing.T) {
	if auditedStandardSymbol(true, "sync", "Lock") == auditedStandardSymbol(false, "sync", "Lock") {
		t.Error("sync admission ignores the selection verdict")
	}
	if classBPureStandard(true, "fmt", "Sprintf") == classBPureStandard(false, "fmt", "Sprintf") {
		t.Error("class-B admission ignores the selection verdict")
	}
	if isSourceOnlyStandardPackage(true, "bytes") == isSourceOnlyStandardPackage(false, "bytes") {
		t.Error("source-only set ignores the selection verdict")
	}
	if auditedHarnessLogging(true, "testing", "Fatal") == auditedHarnessLogging(false, "testing", "Fatal") {
		t.Error("harness-logging admission ignores the selection verdict")
	}
}

// The end-to-end refusal: a Hasher constructed over an unlisted
// surface — the listing emptied under the test — degrades stdlib
// admissions for real analyses: a subject observable under the listed
// toolchain refuses, with the ordinary fail-closed classification
// carrying the reason (the verdict threads from construction to the
// admission sites, not merely honored as a parameter).
func TestUnlistedSurfaceRefusesObservability(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over the fixture corpus")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	fixture, err := filepath.Abs("fixtures/observable")
	if err != nil {
		t.Fatal(err)
	}
	listed, err := newAt(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !listed.SelectionAudited() {
		t.Skipf("running toolchain unlisted (the canary covers it): %s", listed.SelectionNotice())
	}
	subject := Subject{Package: "github.com/greatliontech/gofresh/closure/fixtures/observable", Symbol: "TestReadFile"}
	listedObs, err := listed.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if o := listedObs[subject]; !o.Observable {
		t.Fatalf("fixture assumption moved: TestReadFile not observable under the listed toolchain: %+v", o)
	}
	memoKey := verifiedPackageMemoKey("strings", listed.source.Packages["strings"])
	verifiedPackageMemo.Store(memoKey, false)
	t.Cleanup(func() { verifiedPackageMemo.Delete(memoKey) })
	unlisted, err := newAt(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if unlisted.SelectionAudited() || !strings.Contains(unlisted.SelectionAttribution(), "moved in") {
		t.Fatalf("an unverified surface admitted: %v %q", unlisted.SelectionAudited(), unlisted.SelectionAttribution())
	}
	unlistedObs, err := unlisted.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if o := unlistedObs[subject]; o.Observable {
		t.Fatalf("the unlisted analysis kept the observability proof — the verdict never reached the admission sites: %+v", o)
	}
}

// The resolving notice entry reads the effective GOFLAGS from the
// caller's environment — go-env read and snapshot-fed alike — and
// cannot silently lose the notice: this is the entry a consumer without
// a Hasher calls, so its resolution path is the serving surface. A
// GOFLAGS the classification cannot read refuses through it; a clean
// default selection on a listed toolchain resolves no notice.
func TestToolchainSelectionNoticeResolvedContextReadsTheEnvironment(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	// The ambient environment carries GOENV, as a witness runner's does:
	// the settings below are replaced, never appended, or the
	// environment normalizer refuses the doubled key.
	t.Setenv("GOENV", "warm")
	dir := t.TempDir()
	env := environmentWith("GOENV=off", "GOFLAGS=-tags", "GOEXPERIMENT=")
	notice, err := ToolchainSelectionNoticeResolved(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, env), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(notice, "could not be read") || !strings.Contains(notice, "-tags (from $GOFLAGS)") {
		t.Fatalf("go-env-resolved notice lost the GOFLAGS selection: %q", notice)
	}
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	notice, err = ToolchainSelectionNoticeResolved(context.Background(), gotool.PrimedEnvReader(gotool.Runner{}, dir, env, snapshot), nil)
	if err != nil || !strings.Contains(notice, "-tags (from $GOFLAGS)") {
		t.Fatalf("snapshot-resolved notice lost the GOFLAGS selection: %v %q", err, notice)
	}
	clean, err := ToolchainSelectionNoticeResolved(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, environmentWith("GOENV=off", "GOFLAGS=", "GOEXPERIMENT=")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := newAtEnv(context.Background(), dir, environmentWith("GOENV=off", "GOFLAGS=", "GOEXPERIMENT=")); err != nil {
		t.Fatal(err)
	} else if (clean == "") != h.SelectionAudited() || clean != h.SelectionNotice() {
		t.Fatalf("the resolved notice %q disagrees with the constructed verdict (audited=%v, notice %q)", clean, h.SelectionAudited(), h.SelectionNotice())
	}
}

// The audit ladder survives the zero value: a Hasher built without
// construction refuses every admission AND explains itself — the
// verdict/text biconditional holds in the unresolved world too.
func TestZeroHasherRefusesSelectionAudit(t *testing.T) {
	var h Hasher
	if h.SelectionAudited() {
		t.Fatal("zero-value Hasher reports an audited selection — fail-open by omission")
	}
	if notice := h.SelectionNotice(); notice == "" || !strings.Contains(notice, "unresolved") {
		t.Fatalf("unresolved verdict has no explaining notice: %q", notice)
	}
	// The third reading refuses with the same verdict: a refusal
	// composed under the zero value names the unresolved axis, never
	// an empty attribution beside a refused audit
	// (REQ-closure-refusal-channels).
	if attribution := h.SelectionAttribution(); attribution == "" || !strings.Contains(attribution, "unresolved") {
		t.Fatalf("unresolved verdict's attribution %q does not name the unresolved axis", attribution)
	}
	requireBareAxis(t, "unresolved", h.SelectionNotice(), h.SelectionAttribution())
}

// requireBareAxis is the one spelling of the axis-only rule over both
// worlds: the attribution is the notice's axis and carries neither the
// consequence nor the remedy (REQ-closure-refusal-channels).
func requireBareAxis(t *testing.T, name, notice, attribution string) {
	t.Helper()
	if !strings.HasPrefix(notice, "toolchain-selection audit: "+attribution+" — ") {
		t.Errorf("%s: attribution %q is not the notice's axis (%q)", name, attribution, notice)
	}
	for _, forbidden := range []string{"admission", "walked against", "never admitted", "listed and readable", "—"} {
		if strings.Contains(attribution, forbidden) {
			t.Errorf("%s: attribution %q carries %q — consequence or remedy text", name, attribution, forbidden)
		}
	}
}

// environmentWith is the ambient environment with the given settings
// replacing any ambient value of the same key.
func environmentWith(settings ...string) []string {
	override := map[string]bool{}
	for _, setting := range settings {
		key, _, _ := strings.Cut(setting, "=")
		override[key] = true
	}
	var env []string
	for _, entry := range os.Environ() {
		if key, _, _ := strings.Cut(entry, "="); !override[key] {
			env = append(env, entry)
		}
	}
	return append(env, settings...)
}
