package closure

import (
	"path/filepath"
	"runtime"
	"testing"
)

// The selection axis of the toolchain-audit key: build flags
// canonicalize to a sorted tag-set key, the sanitizer flags implying
// their tags, and an unclassifiable flag set never admits
// (REQ-closure-observability-analysis's exact-version keying clause).
func TestSelectionAuditKeyCanonicalizesBuildFlags(t *testing.T) {
	cases := []struct {
		name  string
		flags []string
		key   string
		ok    bool
	}{
		{"no flags is the default selection", nil, "", true},
		{"selection-neutral flags stay default", []string{"-pgo=auto", "-trimpath"}, "", true},
		{"tags equals form", []string{"-tags=dst"}, "dst", true},
		{"tags two-argument form", []string{"-tags", "dst"}, "dst", true},
		{"tag sets sort and dedup", []string{"-tags=b,a", "-tags=a"}, "a,b", true},
		{"race implies its tag", []string{"-race"}, "race", true},
		{"race unions declared tags", []string{"-race", "-tags=dst"}, "dst,race", true},
		{"msan and asan imply their tags", []string{"-msan", "-asan"}, "asan,msan", true},
		{"bare -tags is unclassifiable", []string{"-tags"}, "", false},
	}
	for _, tc := range cases {
		key, ok := selectionAuditKey(tc.flags)
		if key != tc.key || ok != tc.ok {
			t.Errorf("%s: selectionAuditKey(%v) = %q,%v want %q,%v", tc.name, tc.flags, key, ok, tc.key, tc.ok)
		}
	}
}

// The two-axis verdict: on a listed release the default and race
// selections are audited (the race walk landed with the axis: the
// audited surface's selected non-test source is byte-identical under
// plain -race), a dst-tagged selection refuses until its own walk
// lists it, and an unclassifiable flag set refuses.
func TestAuditedToolchainSelectionAxes(t *testing.T) {
	if !auditedToolchainSource() {
		t.Skip("running toolchain not in the audited-release list; the version canary covers this")
	}
	cases := []struct {
		name    string
		flags   []string
		audited bool
	}{
		{"default selection audited", nil, true},
		{"race selection audited by the race walk", []string{"-race"}, true},
		{"dst selection refuses until walked", []string{"-tags=dst"}, false},
		{"dst-race refuses until walked", []string{"-race", "-tags=dst"}, false},
		{"unknown tag refuses", []string{"-tags=mysterytag"}, false},
		{"unclassifiable flags refuse", []string{"-tags"}, false},
	}
	for _, tc := range cases {
		if got := AuditedToolchainSelection(tc.flags, "", ""); got != tc.audited {
			t.Errorf("%s: AuditedToolchainSelection(%v) = %v want %v", tc.name, tc.flags, got, tc.audited)
		}
	}
}

// Every release in the version listing carries a selections entry and
// vice versa — the two axes never drift apart.
func TestAuditedSelectionsCoverEveryListedRelease(t *testing.T) {
	for release := range auditedToolchainReleases {
		sels, ok := auditedToolchainSelections[release]
		if !ok || !sels[""] {
			t.Errorf("release %s listed without a default-selection audit entry", release)
		}
	}
	for release := range auditedToolchainSelections {
		if !auditedToolchainReleases[release] {
			t.Errorf("selections list release %s absent from the version listing", release)
		}
	}
}

// An unaudited selection degrades every stdlib admission to the
// ordinary fail-closed classification — the same posture as an
// unlisted release — at the admission functions themselves.
func TestUnauditedSelectionDisablesAdmissions(t *testing.T) {
	if auditedSyncSymbol(true, "sync", "Lock") == auditedSyncSymbol(false, "sync", "Lock") {
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

// The environment axes: GOFLAGS joins the effective selection, and a
// GOEXPERIMENT or GOOS/GOARCH differing from this binary's own is a
// selection no walk covered — each refuses, fail-closed, exactly as
// an unwalked tag set does (the env channel that would otherwise
// bypass the flag-derived key).
func TestAuditedToolchainSelectionEnvAxes(t *testing.T) {
	if !auditedToolchainSource() {
		t.Skip("running toolchain not in the audited-release list; the version canary covers this")
	}
	if !AuditedToolchainSelection(nil, "", "") {
		t.Fatal("default selection with default env refused")
	}
	if AuditedToolchainSelection(nil, "-tags=dst", "") {
		t.Error("GOFLAGS-carried dst tag bypassed the selection axis")
	}
	if !AuditedToolchainSelection(nil, "-race", "") {
		t.Error("GOFLAGS-carried -race refused despite the race listing")
	}
	if AuditedToolchainSelection(nil, "", "somefutureexp") {
		t.Error("an environment GOEXPERIMENT differing from the binary's admitted")
	}
	if !AuditedToolchainSelection(nil, "", binaryExperiment()) {
		t.Error("the binary's own experiment refused")
	}
	// GOOS/GOARCH need no axis: the delta walks read the audited
	// packages' platform-split files whole, so cross-platform
	// selections of the audited packages ride the walked source (the
	// pre-existing cross-GOOS analysis capability stays —
	// TestOpenFileFlagsUseSelectedGOOS pins it end to end).
}

// Sanitizer value forms classify or refuse — never silently default
// (the -msan=true hole): an explicit true selects the tag, false
// stays default, and an unparsable value never admits.
func TestSelectionAuditKeySanitizerValueForms(t *testing.T) {
	cases := []struct {
		flags []string
		key   string
		ok    bool
	}{
		{[]string{"-race=true"}, "race", true},
		{[]string{"-race=false"}, "", true},
		{[]string{"-msan=true"}, "msan", true},
		{[]string{"-asan=1"}, "asan", true},
		{[]string{"-race=weird"}, "", false},
	}
	for _, tc := range cases {
		key, ok := selectionAuditKey(tc.flags)
		if key != tc.key || ok != tc.ok {
			t.Errorf("selectionAuditKey(%v) = %q,%v want %q,%v", tc.flags, key, ok, tc.key, tc.ok)
		}
	}
}

// The effect-scan memo scope discriminates on the selection verdict:
// an unaudited selection's scans key apart from the default's, so
// neither ever serves the other (REQ-closure-effect-scan-memo's
// selection dimension); the default scope stays byte-identical to the
// pre-selection era's so existing memos keep serving.
func TestEffectScanScopeDiscriminatesSelectionVerdict(t *testing.T) {
	audited := (&Hasher{selectionAudited: true}).effectScanScope()
	unaudited := (&Hasher{selectionAudited: false}).effectScanScope()
	if audited == unaudited {
		t.Fatal("effect-scan memo scope ignores the selection verdict — unaudited scans could serve audited consumers")
	}
	if audited != effectScanStrategy+" "+runtime.Version() {
		t.Fatalf("audited scope moved from the pre-selection format: %q", audited)
	}
}

// The end-to-end refusal: a Hasher constructed with an unwalked tag
// selection degrades stdlib admissions for real analyses — a subject
// observable under the default selection refuses under -tags=dst,
// with the ordinary fail-closed classification carrying the reason
// (the verdict threads from construction to the admission sites, not
// merely honored as a parameter).
func TestUnwalkedTagSelectionRefusesObservability(t *testing.T) {
	if !auditedToolchainSource() {
		t.Skip("running toolchain not in the audited-release list")
	}
	fixture, err := filepath.Abs("fixtures/observable")
	if err != nil {
		t.Fatal(err)
	}
	def, err := NewAt(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !def.SelectionAudited() {
		t.Fatal("default-selection hasher reports unaudited")
	}
	tagged, err := NewAt(fixture, "-tags=dst")
	if err != nil {
		t.Fatal(err)
	}
	if tagged.SelectionAudited() {
		t.Fatal("dst-tagged hasher reports audited — the unwalked selection inherited the default audit")
	}
	// The verdict reaches the analysis itself: a subject observable
	// under the default selection refuses under the unwalked tag —
	// the end-to-end arm the per-function refusal pins cannot carry.
	subject := Subject{Package: "github.com/greatliontech/gofresh/closure/fixtures/observable", Symbol: "TestReadFile"}
	defObs, err := def.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if o := defObs[subject]; !o.Observable {
		t.Fatalf("fixture assumption moved: TestReadFile not observable under the default selection: %+v", o)
	}
	taggedObs, err := tagged.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if o := taggedObs[subject]; o.Observable {
		t.Fatalf("dst-tagged analysis kept the observability proof — the selection verdict never reached the admission sites: %+v", o)
	}
}
