package closure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

// Every selection the content key admits or refuses, on the running
// toolchain (the canary pins that it is listed): the default and race
// selections admit — the race selection selects the same audited files
// (the recorded fact, now enforced by equality); a tag no audited file
// is constrained on selects the same files and admits BY CONTENT (the
// selection axis dissolved); an unclassifiable flag set refuses; and a
// tag that selects different audited bytes — the dst hook tag on a
// godst toolchain, whose dst-tagged files sit in the surface — refuses
// naming the packages that moved
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
		t.Skipf("running toolchain unlisted (the canary covers it): %s", h.SelectionNotice())
	}
	// The race arms need cgo: the go command refuses a race listing
	// without it.
	cgo := cgoEnabled(t)
	for _, tc := range []struct {
		name  string
		flags []string
		cgo   bool
	}{
		{"race selects the same audited files", []string{"-race"}, true},
		{"a tag no audited file is constrained on selects the same files", []string{"-tags=dup"}, false},
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
	// A tag that selects audited bytes refuses naming the package: netgo
	// selects net's netgo-constrained files on every listed toolchain;
	// the refusal labels the surface by the go command's own version
	// (the pass snapshot's), never the analyzing process's.
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if h := hasher("-tags=netgo"); h.SelectionAudited() || !strings.Contains(h.SelectionAttribution(), "the audited surface of "+snapshot.Value("GOVERSION")+" moved in 1 keys off") || !strings.HasSuffix(h.SelectionAttribution(), ": net") {
		t.Errorf("netgo selection: audited=%v attribution %q, want net named as moved off the snapshot's version", h.SelectionAudited(), h.SelectionAttribution())
	}
	// An explicit flag overrides GOFLAGS, as the go command merges them:
	// `-tags=dup` under GOFLAGS=-tags=netgo selects no netgo file and
	// admits, and the union spelled explicitly — refused — shares no
	// memo record with it (the scope is the snapshot's identity).
	if h, err := newAtEnv(context.Background(), dir, environmentWith("GOFLAGS=-tags=netgo"), "-tags=dup"); err != nil {
		t.Fatal(err)
	} else if !h.SelectionAudited() {
		t.Errorf("an explicit -tags=dup under GOFLAGS=-tags=netgo refused: %s", h.SelectionNotice())
	}
	if h := hasher("-tags=dup,netgo"); h.SelectionAudited() || !strings.HasSuffix(h.SelectionAttribution(), ": net") {
		t.Errorf("the explicit union served the override's record: audited=%v attribution %q", h.SelectionAudited(), h.SelectionAttribution())
	}
	// Another platform's analysis selects other bytes — its split
	// files: a listed platform row (plan9/amd64, listed from this host
	// over its default row) admits by content; a platform no row covers
	// refuses until a host lists it.
	if h, err := newAtEnv(context.Background(), dir, environmentWith("GOOS=plan9", "GOARCH=amd64")); err != nil {
		t.Fatal(err)
	} else if !h.SelectionAudited() {
		t.Errorf("the listed plan9/amd64 selection refused: %s", h.SelectionNotice())
	}
	// cgo off — every host without a C compiler — is listed from this
	// host as the same kind of delta row.
	if h, err := newAtEnv(context.Background(), dir, environmentWith("CGO_ENABLED=0")); err != nil {
		t.Fatal(err)
	} else if !h.SelectionAudited() {
		t.Errorf("the listed cgo-off selection refused: %s", h.SelectionNotice())
	}
	if h, err := newAtEnv(context.Background(), dir, environmentWith("GOOS=windows", "GOARCH=arm64")); err != nil {
		t.Fatal(err)
	} else if h.SelectionAudited() || !strings.Contains(h.SelectionAttribution(), "moved in") {
		t.Errorf("an unlisted platform: audited=%v attribution %q, want the moved keys named", h.SelectionAudited(), h.SelectionAttribution())
	}
	// A tag that selects different audited bytes refuses: the godst
	// hook tag where the running GOROOT carries dst-tagged files in an
	// audited package (time's dst_tz.go); elsewhere the arm is
	// unreachable and skipped — the planted-listing pin below carries
	// the refusal's shape on every host.
	if _, err := os.Stat(filepath.Join(snapshot.Value("GOROOT"), "src", "time", "dst_tz.go")); err != nil {
		t.Skip("no dst-tagged audited file in the running GOROOT; the dst arm needs a godst toolchain")
	}
	h := hasher("-tags=dst")
	if h.SelectionAudited() || !strings.Contains(h.SelectionAttribution(), "moved in") || !strings.Contains(h.SelectionAttribution(), "time") {
		t.Errorf("dst selection: audited=%v attribution %q, want the moved packages named with time among them", h.SelectionAudited(), h.SelectionAttribution())
	}
}

// The degradation over explicit inputs — the unlisted world a listed
// toolchain cannot reach: an unclassifiable flag set, an unreadable
// surface, moved keys named and bounded with the lacking ones, and the
// audited verdict; the notice is axis + consequence + remedy, and the
// attribution the bare axis (REQ-closure-refusal-channels).
func TestToolchainSourceDegradationNamesEveryAxis(t *testing.T) {
	prior := auditedToolchainSources
	t.Cleanup(func() { auditedToolchainSources = prior })
	auditedToolchainSources = []toolchainSourceRow{{Label: "go1.99.0", Packages: map[string]string{"strings": "a", "bytes": "b", "runtime": "s"}}}
	same := sourceDigests{Packages: map[string]string{"strings": "a", "bytes": "b", "runtime": "s"}}
	if d := toolchainSourceDegradation("go1.99.0", same, nil); !d.audited() || d.notice() != "" || d.axis != "" {
		t.Fatalf("every digest listed, yet %+v", d)
	}
	for _, tc := range []struct {
		name    string
		d       sourceDigests
		listErr error
		axis    string
		remedy  string
	}{
		{"unreadable surface (an unclassifiable flag set included)", sourceDigests{}, errors.New("listing the standard library: boom"), "could not be read: listing the standard library: boom", "listed and readable"},
		{"one package moved", sourceDigests{Packages: map[string]string{"strings": "a", "bytes": "moved", "runtime": "s"}}, nil, "moved in 1 keys off go1.99.0: bytes", "walked against the admissions"},
		{"the runtime moved", sourceDigests{Packages: map[string]string{"strings": "a", "bytes": "b", "runtime": "moved"}}, nil, "moved in 1 keys off go1.99.0: runtime", "digests listed"},
		{"a key the row lacks", sourceDigests{Packages: map[string]string{"strings": "a", "bytes": "b", "runtime": "s", "unique": "u"}}, nil, "moved in 1 keys off go1.99.0: unique", "listed"},
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
	// Many moved keys: packages first, then symbols, bounded and the
	// rest counted.
	many := sourceDigests{Packages: map[string]string{}}
	for _, p := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"} {
		many.Packages[p] = "x"
	}
	d := toolchainSourceDegradation("go1.99.0", many, nil)
	if want := "moved in 11 keys off go1.99.0: a, b, c, d, e, f, g, h (+3 more)"; !strings.Contains(d.axis, want) {
		t.Fatalf("bounded naming: %q, want %q", d.axis, want)
	}
	// No row listed at all: every key moved, off no row.
	auditedToolchainSources = nil
	if d := toolchainSourceDegradation("go1.99.0", same, nil); !strings.Contains(d.axis, "moved in 3 keys (no row listed): bytes, runtime, strings") {
		t.Fatalf("no rows: %q", d.axis)
	}
}

// The effect-scan memo scope discriminates on the selection verdict:
// an unaudited selection's scans key apart from the default's, so
// neither ever serves the other (REQ-closure-effect-scan-memo's
// selection dimension); the default scope stays byte-identical to the
// pre-selection era's so existing memos keep serving.
func TestEffectScanScopeDiscriminatesSelectionVerdict(t *testing.T) {
	audited := (&Hasher{selectionResolved: true}).effectScanScope()
	unaudited := (&Hasher{selectionResolved: true, selection: selectionDegradation{axis: "unwalked"}}).effectScanScope()
	if audited == unaudited {
		t.Fatal("effect-scan memo scope ignores the selection verdict — unaudited scans could serve audited consumers")
	}
	if audited != effectScanStrategy+" "+runtime.Version() {
		t.Fatalf("audited scope moved from the pre-selection format: %q", audited)
	}
}

// An unaudited selection degrades every stdlib admission to the
// ordinary fail-closed classification — the same posture as an
// unlisted toolchain — at the admission functions themselves.
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
	prior := auditedToolchainSources
	t.Cleanup(func() { auditedToolchainSources = prior })
	auditedToolchainSources = nil
	unlisted, err := newAt(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if unlisted.SelectionAudited() || !strings.Contains(unlisted.SelectionAttribution(), "moved in") {
		t.Fatalf("an emptied listing admitted: %v %q", unlisted.SelectionAudited(), unlisted.SelectionAttribution())
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

// The listing hosts list the stated selection set — the host default,
// the race seams, the platforms the fleet analyzes for from another
// host, and cgo off — exactly: a selection struck from the set would
// leave the canary silent about a row the fleet relies on.
func TestListedSelectionsAreTheStatedSet(t *testing.T) {
	want := []listedSelection{
		{},
		{Suffix: " race", Flags: []string{"-race"}},
		{Suffix: " plan9/amd64", Env: []string{"GOOS=plan9", "GOARCH=amd64"}},
		{Suffix: " cgo0", Env: []string{"CGO_ENABLED=0"}},
	}
	if !reflect.DeepEqual(listedSelections, want) {
		t.Fatalf("listedSelections = %+v, want the stated set %+v", listedSelections, want)
	}
}
