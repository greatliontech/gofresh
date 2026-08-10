package gofresh

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// writePinnedDepModule writes a module depending on golang.org/x/sync at the
// parent module's own pinned version — present in any module cache able to
// build gofresh itself — and returns its directory.
func writePinnedDepModule(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}", "golang.org/x/sync").Output()
	if err != nil {
		t.Fatalf("resolve parent x/sync version: %v", err)
	}
	version := strings.TrimSpace(string(out))
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":      "module example.com/pinned\n\ngo 1.26\n\nrequire golang.org/x/sync " + version + "\n",
		"lib.go":      "package pinned\n\nimport \"golang.org/x/sync/errgroup\"\n\nfunc Run() error {\n\tvar g errgroup.Group\n\tg.Go(func() error { return nil })\n\treturn g.Wait()\n}\n",
		"lib_test.go": "package pinned\n\nimport \"testing\"\n\nfunc TestRun(t *testing.T) {\n\tif Run() != nil {\n\t\tt.Fatal(\"run\")\n\t}\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	tidy.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off")
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	return dir
}

type scanResult struct {
	known, openWorld, external map[Subject]bool
	pure                       map[Subject]bool
	downgradeReason            map[Subject]string
	vouchDischarges            map[Subject]string
}

func runScan(t *testing.T, scope, dir string, pkgPaths ...string) scanResult {
	t.Helper()
	return runScanVouched(t, scope, dir, nil, pkgPaths...)
}

func runScanVouched(t *testing.T, scope, dir string, vouches map[string]bool, pkgPaths ...string) scanResult {
	t.Helper()
	hasher, err := closure.NewAtContextEnv(context.Background(), dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	scan, _, err := scanViewSubjects(context.Background(), hasher, scope, dir, os.Environ(), nil, nil, vouches, pkgPaths...)
	if err != nil {
		t.Fatal(err)
	}
	result := scanResult{known: scan.known, openWorld: scan.openWorld, external: scan.external, pure: map[Subject]bool{}, downgradeReason: scan.downgradeReason, vouchDischarges: scan.vouchDischarges}
	for subject := range scan.known {
		if scan.directivePure(subject) {
			result.pure[subject] = true
		}
	}
	return result
}

// Version-pinned package facts load once, then serve from the in-process
// cache, then from the persistent memo across cache resets, with
// fact-equivalent scan results throughout; a scope change recomputes
// (REQ-closure-dynamic-state-memo).
func TestDynamicStateFactsServePinnedPackagesWithoutLoading(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"

	var missLoads [][]string
	viewTestHooks.dynamicStateMissLoad = func(patterns []string) {
		missLoads = append(missLoads, append([]string(nil), patterns...))
	}
	defer func() { viewTestHooks.dynamicStateMissLoad = nil }()
	processFactCache = sync.Map{}

	const scope = DynamicStateStrategy + "|test-toolchain|test-buildconfig"
	first := runScan(t, scope, dir, pkg)
	if len(missLoads) != 1 {
		t.Fatalf("cold scan performed %d pinned fact loads, want exactly 1", len(missLoads))
	}
	if !strings.Contains(strings.Join(missLoads[0], " "), "golang.org/x/sync/errgroup") {
		t.Fatalf("pinned fact load did not cover errgroup: %v", missLoads[0])
	}
	if !first.known[Subject{Package: pkg, Symbol: "Run"}] {
		t.Fatal("scan lost the subject")
	}

	second := runScan(t, scope, dir, pkg)
	if len(missLoads) != 1 {
		t.Fatalf("in-process warm scan re-loaded pinned facts: %d loads", len(missLoads))
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("in-process fact serve is not scan-equivalent:\n first %+v\n second %+v", first, second)
	}

	processFactCache = sync.Map{}
	third := runScan(t, scope, dir, pkg)
	if len(missLoads) != 1 {
		t.Fatalf("persistent warm scan re-loaded pinned facts: %d loads", len(missLoads))
	}
	if !reflect.DeepEqual(first, third) {
		t.Fatalf("persistent fact serve is not scan-equivalent:\n first %+v\n third %+v", first, third)
	}

	processFactCache = sync.Map{}
	moved := runScan(t, DynamicStateStrategy+"|other-toolchain|test-buildconfig", dir, pkg)
	if len(missLoads) != 2 {
		t.Fatalf("scope change served stale facts: %d loads, want 2", len(missLoads))
	}
	if !reflect.DeepEqual(first, moved) {
		t.Fatalf("recomputation under a moved scope is not scan-equivalent:\n first %+v\n moved %+v", first, moved)
	}
}

// A fact survives serialization with its mutation, declaration, and
// method-directive content intact, and the promoted-method lookup resolves
// directives from the deserialized fact (REQ-closure-dynamic-state-memo,
// REQ-purity-directive, REQ-external-directive).
func TestDynamicStateFactRoundTripCarriesMutationsAndMethodDirectives(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/factsrc\n\ngo 1.26\n",
		"lib.go": `package factsrc

import "errors"

var Hook func()

var ErrSentinel = errors.New("sentinel")

var Hooks = map[string]func(){}

var Bound []func() int

func seed() {
	c := new(int)
	Bound = []func() int{func() int { (*c)++; return *c }}
}

var _ = boot()

func boot() bool {
	seed()
	return true
}

func take(map[string]func()) {}

func Escape() { take(Hooks) }

func Pass() map[string]func() { return Hooks }

func Rebind() { Hook = nil }

type Widget int

//gofresh:pure
func (Widget) Pure() int { return 1 }

//gofresh:external
func (Widget) External() int { return 2 }
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	load, err := closure.LoadViewPackagesEnv(context.Background(), dir, os.Environ(), nil, "example.com/factsrc")
	if err != nil {
		t.Fatal(err)
	}
	var plain *types.Package
	var fact dynamicStateFact
	for _, p := range load.Packages() {
		if p.PkgPath == "example.com/factsrc" && p.ForTest == "" {
			fact = dynamicStateFactOf(p)
			plain = p.Types
		}
	}
	if plain == nil {
		t.Fatal("fixture package not loaded")
	}
	raw, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	var restored dynamicStateFact
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fact, restored) {
		t.Fatalf("fact did not round-trip:\n before %+v\n after  %+v", fact, restored)
	}
	wantKey := "example.com/factsrc.Hook"
	if !contains(restored.Declares, wantKey) {
		t.Fatalf("fact lost declaration content: %+v", restored)
	}
	if !contains(restored.AttributedUses, "example.com/factsrc\x00Rebind\x00example.com/factsrc.Hook\x00m") {
		t.Fatalf("fact lost the attributed mutation - a dropped attribution silently discharges a runtime rebind: %+v", restored)
	}
	if !contains(restored.FuncRefs, "example.com/factsrc\x00take\x01example.com/factsrc\x00Escape") {
		t.Fatalf("fact lost the reference-region edge - a dropped edge starves the fixed point: %+v", restored.FuncRefs)
	}
	if !contains(restored.AttributedUses, "example.com/factsrc\x00Pass\x00example.com/factsrc.Hooks\x00e") {
		t.Fatalf("fact lost the attributed escape - a dropped attribution silently closes an open package: %+v", restored)
	}
	if !contains(restored.ParamUses, "example.com/factsrc.Hooks\x00example.com/factsrc\x00take\x000") {
		t.Fatalf("fact lost the deferred call-argument mark - a dropped deferral silently closes an open package: %+v", restored.ParamUses)
	}
	if !contains(restored.ParamLeakFree, "example.com/factsrc\x00take\x000") {
		t.Fatalf("fact lost the leak-free parameter proof - a dropped proof refuses every deferred argument: %+v", restored.ParamLeakFree)
	}
	if !contains(restored.Opaque, "example.com/factsrc.ErrSentinel") {
		t.Fatalf("fact lost opacity content: %+v", restored)
	}
	if !contains(restored.EnvCarrying, "example.com/factsrc.Bound") {
		t.Fatalf("fact lost the environment-audit mark - a dropped mark keeps a capturing registration settled: %+v", restored.EnvCarrying)
	}
	if restored.PureMethods["Widget.Pure"] == "" || restored.ExternalMethods["Widget.External"] == "" {
		t.Fatalf("fact lost method directives: %+v", restored)
	}

	state := &viewDynamicState{facts: map[string][]dynamicStateFact{"example.com/factsrc": {restored}}}
	widget, ok := plain.Scope().Lookup("Widget").(*types.TypeName)
	if !ok {
		t.Fatal("Widget type missing")
	}
	methods := types.NewMethodSet(widget.Type())
	var pureKey, externalKey string
	for i := 0; i < methods.Len(); i++ {
		method := methods.At(i).Obj().(*types.Func)
		p, x := state.methodDirectives(method)
		if method.Name() == "Pure" {
			pureKey = p
		}
		if method.Name() == "External" {
			externalKey = x
		}
	}
	if pureKey == "" || externalKey == "" {
		t.Fatalf("promoted-method directive lookup failed: pure=%q external=%q", pureKey, externalKey)
	}
}

// A caller vouch discharges a would-be culprit in a version-pinned
// dependency: the downgrade lifts and the discharge is recorded on
// every subject reaching the owning package, while a vouch naming a
// different variable confers nothing (REQ-vouch-discharge,
// REQ-vouch-recorded).
func TestVouchDischargesPinnedCulprit(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"
	const ghost = "golang.org/x/sync/errgroup.Ghost"
	subject := Subject{Package: pkg, Symbol: "Run"}
	processFactCache = sync.Map{}
	const scope = DynamicStateStrategy + "|vouch-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}
	var hit bool
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, ghost)
			fact.Mutates = append(fact.Mutates, ghost)
			processFactCache.Store(k, fact)
			hit = true
		}
		return true
	})
	if !hit {
		t.Fatal("no errgroup fact in the process cache")
	}

	poisoned := runScan(t, scope, dir, pkg)
	if reason := poisoned.downgradeReason[subject]; !strings.Contains(reason, ghost+" is mutated") {
		t.Fatalf("poisoned downgrade = %q, want the culprit named", reason)
	}
	if discharges := poisoned.vouchDischarges[subject]; discharges != "" {
		t.Fatalf("unvouched scan recorded a discharge: %q", discharges)
	}

	vouched := runScanVouched(t, scope, dir, map[string]bool{ghost: true}, pkg)
	if reason := vouched.downgradeReason[subject]; reason != "" {
		t.Fatalf("vouched culprit still downgrades: %q", reason)
	}
	if discharges := vouched.vouchDischarges[subject]; discharges != ghost {
		t.Fatalf("discharge record = %q, want %q", discharges, ghost)
	}

	other := runScanVouched(t, scope, dir, map[string]bool{"golang.org/x/sync/errgroup.Other": true}, pkg)
	if reason := other.downgradeReason[subject]; !strings.Contains(reason, ghost+" is mutated") {
		t.Fatalf("a vouch for a different variable lifted the downgrade: %q", reason)
	}
	if discharges := other.vouchDischarges[subject]; discharges != "" {
		t.Fatalf("an inert vouch recorded a discharge: %q", discharges)
	}

	// All three culprit ranks discharge - the escape and env-carrying
	// families (the field report's registration shape) exactly like the
	// mutation rank - and the record carries every load-bearing vouch,
	// sorted.
	const shade = "golang.org/x/sync/errgroup.Shade"
	const wraith = "golang.org/x/sync/errgroup.Wraith"
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, shade, wraith)
			fact.Escapes = append(fact.Escapes, shade)
			fact.EnvCarrying = append(fact.EnvCarrying, wraith)
			processFactCache.Store(k, fact)
		}
		return true
	})
	all := map[string]bool{ghost: true, shade: true, wraith: true}
	lifted := runScanVouched(t, scope, dir, all, pkg)
	if reason := lifted.downgradeReason[subject]; reason != "" {
		t.Fatalf("three-rank vouch left a downgrade: %q", reason)
	}
	if discharges := lifted.vouchDischarges[subject]; discharges != ghost+","+shade+","+wraith {
		t.Fatalf("three-rank discharge record = %q", discharges)
	}

	// A vouch names exactly one variable: a bare package identity
	// confers nothing.
	bare := runScanVouched(t, scope, dir, map[string]bool{"golang.org/x/sync/errgroup": true}, pkg)
	if reason := bare.downgradeReason[subject]; !strings.Contains(reason, ghost) {
		t.Fatalf("bare-package vouch lifted the downgrade: %q", reason)
	}
	if discharges := bare.vouchDischarges[subject]; discharges != "" {
		t.Fatalf("bare-package vouch recorded a discharge: %q", discharges)
	}

	// A vouched and an unvouched culprit sharing the package: the
	// unvouched one opens it whatever the declaration order, and the
	// discharge record still names every load-bearing vouch — the
	// vouched key declared AFTER the opener included.
	const alpha = "golang.org/x/sync/errgroup.Alpha"
	const zeta = "golang.org/x/sync/errgroup.Zeta"
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, alpha, zeta)
			fact.Mutates = append(fact.Mutates, alpha, zeta)
			processFactCache.Store(k, fact)
		}
		return true
	})
	withZeta := map[string]bool{ghost: true, shade: true, wraith: true, zeta: true}
	mixed := runScanVouched(t, scope, dir, withZeta, pkg)
	if reason := mixed.downgradeReason[subject]; !strings.Contains(reason, alpha+" is mutated") {
		t.Fatalf("mixed-package downgrade = %q, want the unvouched culprit named", reason)
	}
	if discharges := mixed.vouchDischarges[subject]; discharges != ghost+","+shade+","+wraith+","+zeta {
		t.Fatalf("mixed-package discharge record = %q", discharges)
	}
}

// The engine option threads the vouch to capture: a vouched pinned
// culprit's subject records the discharge on its fingerprint, its
// verdict is no longer downgraded, and without the vouch the same
// poisoned graph refuses naming the culprit (REQ-vouch-input,
// REQ-vouch-recorded).
func TestVouchedFingerprintRecordsDischarge(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const ghost = "golang.org/x/sync/errgroup.Ghost"
	subject := Subject{Package: "example.com/pinned", Symbol: "Run"}
	processFactCache = sync.Map{}
	ctx := context.Background()

	warm, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := warm.NewView(ctx, []Subject{subject}, dir); err != nil {
		t.Fatal(err)
	}
	var hit bool
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, ghost)
			fact.Mutates = append(fact.Mutates, ghost)
			processFactCache.Store(k, fact)
			hit = true
		}
		return true
	})
	if !hit {
		t.Fatal("no errgroup fact in the process cache")
	}

	control, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	controlView, err := control.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	controlFP, err := controlView.Capture(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	controlVerdict, err := controlView.Check(ctx, controlFP, subject)
	if err != nil {
		t.Fatal(err)
	}
	if controlVerdict.Status != Unverifiable || !strings.Contains(controlVerdict.Reason, ghost) {
		t.Fatalf("poisoned control verdict = %+v, want the downgrade naming %s", controlVerdict, ghost)
	}

	vouched, err := New(WithDir(dir), WithDynamicStateVouches(ghost))
	if err != nil {
		t.Fatal(err)
	}
	view, err := vouched.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.DynamicStateVouches != ghost {
		t.Fatalf("fingerprint discharge = %q, want %q", fingerprint.DynamicStateVouches, ghost)
	}
	verdict, err := view.Check(ctx, fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(verdict.Reason, "shares mutated dynamic state") {
		t.Fatalf("vouched verdict still downgraded: %+v", verdict)
	}
}

// writeSemverDepModule mirrors writePinnedDepModule over
// golang.org/x/mod/semver: a pinned dependency whose real source is
// benign enough to pass the observability scan, so observed-surface
// tests exercise the completed-observation path rather than refusing
// at the proof.
func writeSemverDepModule(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}", "golang.org/x/mod").Output()
	if err != nil {
		t.Fatalf("resolve parent x/mod version: %v", err)
	}
	version := strings.TrimSpace(string(out))
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":      "module example.com/semverdep\n\ngo 1.26\n\nrequire golang.org/x/mod " + version + "\n",
		"lib.go":      "package semverdep\n\nimport \"golang.org/x/mod/semver\"\n\nfunc Valid(v string) bool {\n\treturn semver.IsValid(v)\n}\n",
		"lib_test.go": "package semverdep\n\nimport \"testing\"\n\nfunc TestValid(t *testing.T) {\n\tif !Valid(\"v1.2.3\") {\n\t\tt.Fatal(\"valid\")\n\t}\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	tidy.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off")
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	return dir
}

// A completed observation never substitutes for the shared-dynamic-state
// downgrade: process-shared state sits outside every observation
// bracket, so an OBSERVABLE downgraded subject still refuses on the
// observed check surface - unvouched on the current tree, and equally
// for a record captured vouched-valid once the vouch is withdrawn
// (REQ-purity-observation-separation, REQ-closure-shared-dynamic-state,
// REQ-vouch-recorded).
func TestObservedEvidenceNeverSuppressesSharedDynamicState(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeSemverDepModule(t)
	const ghost = "golang.org/x/mod/semver.Ghost"
	subject := Subject{Package: "example.com/semverdep", Symbol: "TestValid"}
	processFactCache = sync.Map{}
	ctx := context.Background()

	warm, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := warm.NewView(ctx, []Subject{subject}, dir); err != nil {
		t.Fatal(err)
	}
	var hit bool
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/mod/semver") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, ghost)
			fact.Mutates = append(fact.Mutates, ghost)
			processFactCache.Store(k, fact)
			hit = true
		}
		return true
	})
	if !hit {
		t.Fatal("no semver fact in the process cache")
	}

	observe := func(e *Engine) (*View, Fingerprint) {
		t.Helper()
		producer, err := e.NewView(ctx, []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := producer.CaptureObserved(ctx, subject)
		if err != nil {
			t.Fatal(err)
		}
		// The fixture must be genuinely observable, or the test refuses
		// through the ordinary path and never exercises the bypass.
		if !fingerprint.ObservationProof.Observable {
			t.Fatalf("fixture not observable: %+v", fingerprint.ObservationProof)
		}
		observation, err := runtimeinput.FromTestLog(nil, dir, dir, runtimeinput.WithCompletedProcess("semver test"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
		if err != nil {
			t.Fatal(err)
		}
		return producer, fingerprint
	}

	// Unvouched: the downgraded subject refuses on the observed surface
	// of the same tree that captured it.
	plain, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	plainView, plainFP := observe(plain)
	verdict, err := plainView.CheckObserved(ctx, plainFP, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, ghost) {
		t.Fatalf("unvouched observed verdict = %+v, want unverifiable naming %s", verdict, ghost)
	}

	// Vouched capture serves observed; the withdrawn vouch resurfaces
	// the culprit on the observed surface too.
	vouched, err := New(WithDir(dir), WithDynamicStateVouches(ghost))
	if err != nil {
		t.Fatal(err)
	}
	vouchedView, fingerprint := observe(vouched)
	if fingerprint.DynamicStateVouches != ghost {
		t.Fatalf("observed fingerprint discharge = %q, want %q", fingerprint.DynamicStateVouches, ghost)
	}
	served, err := vouchedView.CheckObserved(ctx, fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if served.Status != Valid {
		t.Fatalf("vouched observed verdict = %+v, want valid", served)
	}
	withdrawn, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	current, err := withdrawn.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err = current.CheckObserved(ctx, fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, ghost) {
		t.Fatalf("withdrawn-vouch observed verdict = %+v, want unverifiable naming %s", verdict, ghost)
	}
}

// Two pinned packages whose facts declare the same vouched key (the
// persisted-fact channel) each record their own discharge: a subject
// reaching only the later-walked package still carries the acceptance
// (REQ-vouch-recorded).
func TestVouchDischargeRecordsPerOwningPackage(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}", "golang.org/x/mod").Output()
	if err != nil {
		t.Fatal(err)
	}
	modVersion := strings.TrimSpace(string(out))
	out, err = exec.Command("go", "list", "-m", "-f", "{{.Version}}", "golang.org/x/sync").Output()
	if err != nil {
		t.Fatal(err)
	}
	syncVersion := strings.TrimSpace(string(out))
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":      "module example.com/twodeps\n\ngo 1.26\n\nrequire (\n\tgolang.org/x/mod " + modVersion + "\n\tgolang.org/x/sync " + syncVersion + "\n)\n",
		"a/a.go":      "package a\n\nimport \"golang.org/x/mod/semver\"\n\nfunc Valid(v string) bool { return semver.IsValid(v) }\n",
		"a/a_test.go": "package a\n\nimport \"testing\"\n\nfunc TestValid(t *testing.T) { if !Valid(\"v1.0.0\") { t.Fatal(\"valid\") } }\n",
		"b/b.go":      "package b\n\nimport \"golang.org/x/sync/errgroup\"\n\nfunc Run() error {\n\tvar g errgroup.Group\n\tg.Go(func() error { return nil })\n\treturn g.Wait()\n}\n",
		"b/b_test.go": "package b\n\nimport \"testing\"\n\nfunc TestRun(t *testing.T) { if Run() != nil { t.Fatal(\"run\") } }\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	tidy.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off")
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	const shared = "example.com/shared.Ghost"
	processFactCache = sync.Map{}
	const scope = DynamicStateStrategy + "|two-deps-toolchain|cfg"
	pkgs := []string{"example.com/twodeps/a", "example.com/twodeps/b"}
	subjectA := Subject{Package: pkgs[0], Symbol: "Valid"}
	subjectB := Subject{Package: pkgs[1], Symbol: "Run"}

	clean := runScan(t, scope, dir, pkgs...)
	if r := clean.downgradeReason[subjectA] + clean.downgradeReason[subjectB]; r != "" {
		t.Fatalf("baseline downgraded: %q", r)
	}
	var poisoned int
	processFactCache.Range(func(k, v any) bool {
		key := k.(string)
		if strings.HasSuffix(key, "\x00golang.org/x/mod/semver") || strings.HasSuffix(key, "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, shared)
			fact.Mutates = append(fact.Mutates, shared)
			processFactCache.Store(k, fact)
			poisoned++
		}
		return true
	})
	if poisoned != 2 {
		t.Fatalf("poisoned %d facts, want both deps", poisoned)
	}
	vouchedScan := runScanVouched(t, scope, dir, map[string]bool{shared: true}, pkgs...)
	if r := vouchedScan.downgradeReason[subjectA] + vouchedScan.downgradeReason[subjectB]; r != "" {
		t.Fatalf("vouched culprits still downgrade: %q", r)
	}
	if a, b := vouchedScan.vouchDischarges[subjectA], vouchedScan.vouchDischarges[subjectB]; a != shared || b != shared {
		t.Fatalf("per-package discharge records = a:%q b:%q, want both %q", a, b, shared)
	}
}

// A record captured vouched-valid refuses once the vouch is withdrawn,
// here on an UNOBSERVABLE subject (errgroup's real source trips the
// observability scan), so the refusal runs the ordinary closure path;
// the observed capture still records the discharge like the plain one
// (REQ-vouch-recorded).
func TestVouchWithdrawalRefusesObservedServe(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const ghost = "golang.org/x/sync/errgroup.Ghost"
	subject := Subject{Package: "example.com/pinned", Symbol: "TestRun"}
	processFactCache = sync.Map{}
	ctx := context.Background()

	warm, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := warm.NewView(ctx, []Subject{subject}, dir); err != nil {
		t.Fatal(err)
	}
	var hit bool
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, ghost)
			fact.Mutates = append(fact.Mutates, ghost)
			processFactCache.Store(k, fact)
			hit = true
		}
		return true
	})
	if !hit {
		t.Fatal("no errgroup fact in the process cache")
	}

	vouched, err := New(WithDir(dir), WithDynamicStateVouches(ghost))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := vouched.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.CaptureObserved(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtimeinput.FromTestLog(nil, dir, dir, runtimeinput.WithCompletedProcess("pinned test"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.DynamicStateVouches != ghost {
		t.Fatalf("observed fingerprint discharge = %q, want %q", fingerprint.DynamicStateVouches, ghost)
	}

	withdrawn, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	current, err := withdrawn.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := current.CheckObserved(ctx, fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, ghost) {
		t.Fatalf("withdrawn-vouch observed verdict = %+v, want unverifiable naming %s", verdict, ghost)
	}
}

// A persisted fact carrying an attribution the consumer cannot parse is
// not trusted: every key the fact declares marks mutated — fail-closed
// like every malformed-fact arm — and the downgrade names the declared
// key (REQ-closure-shared-dynamic-state).
func TestMalformedAttributedUseMarksEveryDeclaredKey(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"
	subject := Subject{Package: pkg, Symbol: "Run"}
	processFactCache = sync.Map{}
	const scope = DynamicStateStrategy + "|malformed-attribution-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	poison := func(mutate func(*dynamicStateFact)) {
		var hit bool
		processFactCache.Range(func(k, v any) bool {
			if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
				fact := v.(dynamicStateFact)
				mutate(&fact)
				processFactCache.Store(k, fact)
				hit = true
			}
			return true
		})
		if !hit {
			t.Fatal("no errgroup fact in the process cache")
		}
	}

	// Control: a crafted declaration alone must not downgrade anything.
	poison(func(fact *dynamicStateFact) {
		fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
	})
	control := runScan(t, scope, dir, pkg)
	if reason := control.downgradeReason[subject]; reason != "" {
		t.Fatalf("declaration alone downgraded the subject: %q", reason)
	}

	// A 3-part attribution — its function key missing the NUL-joined
	// name — cannot be judged and must not be dropped.
	poison(func(fact *dynamicStateFact) {
		fact.AttributedUses = append(fact.AttributedUses, "golang.org/x/sync/errgroup\x00Ghost\x00m")
	})
	poisoned := runScan(t, scope, dir, pkg)
	if reason := poisoned.downgradeReason[subject]; !strings.Contains(reason, "golang.org/x/sync/errgroup.Ghost is mutated") {
		t.Fatalf("downgrade reason %q does not mark the declared key - a malformed attribution slipped through", reason)
	}
}

// A persisted deferred call-argument mark the consumer cannot parse is
// not trusted: every key the fact declares marks mutated — fail-closed
// like every malformed-fact arm (REQ-closure-shared-dynamic-state).
func TestMalformedParamUseMarksEveryDeclaredKey(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"
	subject := Subject{Package: pkg, Symbol: "Run"}
	processFactCache = sync.Map{}
	const scope = DynamicStateStrategy + "|malformed-param-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	var hit bool
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
			// One NUL only - the callee parameter key lost its frame.
			fact.ParamUses = append(fact.ParamUses, "golang.org/x/sync/errgroup.Ghost\x00bad")
			processFactCache.Store(k, fact)
			hit = true
		}
		return true
	})
	if !hit {
		t.Fatal("no errgroup fact in the process cache")
	}
	poisoned := runScan(t, scope, dir, pkg)
	if reason := poisoned.downgradeReason[subject]; !strings.Contains(reason, "golang.org/x/sync/errgroup.Ghost is mutated") {
		t.Fatalf("downgrade reason %q does not mark the declared key - a malformed deferral slipped through", reason)
	}
}

// A persisted deferred field-position mark the consumer cannot parse is
// not trusted: every key the fact declares marks mutated — fail-closed
// like every malformed-fact arm (REQ-closure-shared-dynamic-state).
func TestMalformedFieldParamUseMarksEveryDeclaredKey(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"
	subject := Subject{Package: pkg, Symbol: "Run"}
	processFactCache = sync.Map{}
	const scope = DynamicStateStrategy + "|malformed-fieldparam-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	var hit bool
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
			// The position part lost its index NUL - unparseable.
			fact.FieldParamUses = append(fact.FieldParamUses, "golang.org/x/sync/errgroup.Ghost\x01bad")
			processFactCache.Store(k, fact)
			hit = true
		}
		return true
	})
	if !hit {
		t.Fatal("no errgroup fact in the process cache")
	}
	poisoned := runScan(t, scope, dir, pkg)
	if reason := poisoned.downgradeReason[subject]; !strings.Contains(reason, "golang.org/x/sync/errgroup.Ghost is mutated") {
		t.Fatalf("downgrade reason %q does not mark the declared key - a malformed field deferral slipped through", reason)
	}
}

// Every persisted registered-population record shares the malformed-fact
// discipline: an entry the consumer cannot parse marks every key the
// carrying fact declares mutated — fail-closed
// (REQ-closure-shared-dynamic-state).
func TestMalformedFieldPopulationRecordsMarkEveryDeclaredKey(t *testing.T) {
	cases := []struct {
		name   string
		poison func(fact *dynamicStateFact)
	}{
		{"fieldParamDefer", func(fact *dynamicStateFact) {
			// Deferral with a negative index - outside the record domain.
			fact.FieldParamDefer = append(fact.FieldParamDefer, "golang.org/x/sync/errgroup.Ghost\x01Build\x00-1\x01p\x00f\x000")
		}},
		{"fieldParamPoison", func(fact *dynamicStateFact) {
			// Position part lost its index NUL.
			fact.FieldParamPoison = append(fact.FieldParamPoison, "golang.org/x/sync/errgroup.Ghost\x01bad")
		}},
		{"returnFieldParamDefer", func(fact *dynamicStateFact) {
			// Function key lost its NUL frame.
			fact.ReturnFieldParamDefer = append(fact.ReturnFieldParamDefer, "badfn\x01Build\x000\x01p\x00f\x000")
		}},
		{"returnFieldParamPoison", func(fact *dynamicStateFact) {
			fact.ReturnFieldParamPoison = append(fact.ReturnFieldParamPoison, "badfn\x01Build\x000")
		}},
		{"elemParamUses", func(fact *dynamicStateFact) {
			// Two parts only - the owner key lost its frame.
			fact.ElemParamUses = append(fact.ElemParamUses, "golang.org/x/sync/errgroup.Ghost\x01bad")
		}},
		{"elemNonCanonicalIndex", func(fact *dynamicStateFact) {
			fact.ElemParamUses = append(fact.ElemParamUses, "golang.org/x/sync/errgroup.Ghost\x01owner.Key\x0100")
		}},
		{"nonCanonicalIndex", func(fact *dynamicStateFact) {
			// "00" spells a position no recorded mark can match - it
			// must be malformed, never a silently empty population.
			fact.FieldParamDefer = append(fact.FieldParamDefer, "golang.org/x/sync/errgroup.Ghost\x01Build\x0000\x01p\x00f\x000")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			dir := writePinnedDepModule(t)
			const pkg = "example.com/pinned"
			subject := Subject{Package: pkg, Symbol: "Run"}
			processFactCache = sync.Map{}
			scope := DynamicStateStrategy + "|malformed-fieldpop-" + tc.name + "|cfg"

			clean := runScan(t, scope, dir, pkg)
			if reason := clean.downgradeReason[subject]; reason != "" {
				t.Fatalf("baseline already downgraded: %q", reason)
			}

			var hit bool
			processFactCache.Range(func(k, v any) bool {
				if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
					fact := v.(dynamicStateFact)
					fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
					tc.poison(&fact)
					processFactCache.Store(k, fact)
					hit = true
				}
				return true
			})
			if !hit {
				t.Fatal("no errgroup fact in the process cache")
			}
			poisoned := runScan(t, scope, dir, pkg)
			if reason := poisoned.downgradeReason[subject]; !strings.Contains(reason, "golang.org/x/sync/errgroup.Ghost is mutated") {
				t.Fatalf("downgrade reason %q does not mark the declared key - a malformed population record slipped through", reason)
			}
		})
	}
}

// A pinned module's bucket moves when any pinned module reachable from it
// changes version — the import-cone version signature completing the fact's
// input identity (REQ-closure-dynamic-state-memo): a dependency bump that
// could reshape a carrier type must move the key.
func TestPinnedBucketsMoveWithImportConeVersions(t *testing.T) {
	meta := func(depPin string) []closure.GraphPackage {
		return []closure.GraphPackage{
			{ImportPath: "example.com/a", PkgPath: "example.com/a", Class: closure.PinnedPackage, Pin: "example.com/a@v1.0.0", Imports: []string{"example.com/b"}},
			{ImportPath: "example.com/b", PkgPath: "example.com/b", Class: closure.PinnedPackage, Pin: depPin},
		}
	}
	before, _ := pinnedBuckets(meta("example.com/b@v2.0.0"))
	same, _ := pinnedBuckets(meta("example.com/b@v2.0.0"))
	after, _ := pinnedBuckets(meta("example.com/b@v3.0.0"))
	if before["example.com/a@v1.0.0"] != same["example.com/a@v1.0.0"] {
		t.Fatal("bucket derivation is not deterministic")
	}
	if before["example.com/a@v1.0.0"] == after["example.com/a@v1.0.0"] {
		t.Fatal("a reachable dependency version bump did not move the importing module's bucket")
	}
}

// A pinned module reaching a mutable-local node through its import cone is
// unkeyable: no bucket exists for it, so no cache layer can hold its facts
// (REQ-closure-dynamic-state-memo) — part of its type environment carries no
// version signal.
func TestPinnedBucketsExcludeModulesReachingMutableLocalSource(t *testing.T) {
	meta := []closure.GraphPackage{
		{ImportPath: "example.com/x", PkgPath: "example.com/x", Class: closure.PinnedPackage, Pin: "example.com/x@v1.0.0", Imports: []string{"example.com/y"}},
		{ImportPath: "example.com/y", PkgPath: "example.com/y", Class: closure.MutableLocalPackage},
		{ImportPath: "example.com/z", PkgPath: "example.com/z", Class: closure.PinnedPackage, Pin: "example.com/z@v1.0.0"},
	}
	buckets, unkeyable := pinnedBuckets(meta)
	if !unkeyable["example.com/x@v1.0.0"] {
		t.Fatal("a pinned module importing mutable-local source was not marked unkeyable")
	}
	if _, ok := buckets["example.com/x@v1.0.0"]; ok {
		t.Fatal("an unkeyable module received a bucket")
	}
	if unkeyable["example.com/z@v1.0.0"] {
		t.Fatal("a pinned module with a pure pinned cone was wrongly unkeyable")
	}
	if _, ok := buckets["example.com/z@v1.0.0"]; !ok {
		t.Fatal("a keyable pinned module lost its bucket")
	}
}

// Mutable-local facts derive fresh on every scan: an edit introducing a
// post-init mutation of a dependency's dynamic-capable global downgrades the
// subject on the very next scan in the same process — no cache layer may hold
// a mutable-local derivation (REQ-closure-mutable-local,
// REQ-closure-dynamic-state-memo).
func TestDynamicStateLocalFactsDeriveFreshEachScan(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	depSource := "package dep\n\nvar Hook func()\n"
	for name, content := range map[string]string{
		"go.mod":     "module example.com/freshlocal\n\ngo 1.26\n",
		"lib.go":     "package freshlocal\n\nimport \"example.com/freshlocal/dep\"\n\nfunc Use() { _ = dep.Hook }\n",
		"dep/dep.go": depSource,
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const pkg = "example.com/freshlocal"
	const scope = DynamicStateStrategy + "|fresh-local|cfg"
	subject := Subject{Package: pkg, Symbol: "Use"}

	before := runScan(t, scope, dir, pkg)
	if before.downgradeReason[subject] != "" {
		t.Fatal("unmutated hook already downgraded the subject")
	}
	mutated := depSource + "\nfunc Rebind() { Hook = nil }\n"
	if err := os.WriteFile(filepath.Join(dir, "dep", "dep.go"), []byte(mutated), 0o644); err != nil {
		t.Fatal(err)
	}
	after := runScan(t, scope, dir, pkg)
	if after.downgradeReason[subject] == "" {
		t.Fatal("a fresh local mutation did not downgrade the subject on the next scan - a cache layer held a mutable-local fact")
	}
}

// writeFileProxyModule publishes a module version into a file:// GOPROXY
// layout so a test can fabricate a genuinely module-cache-resident (pinned)
// dependency without touching the network or the real cache.
func writeFileProxyModule(t *testing.T, proxyDir, modPath, version string, files map[string]string) {
	t.Helper()
	base := filepath.Join(proxyDir, filepath.FromSlash(modPath), "@v")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"list":            version + "\n",
		version + ".info": `{"Version":"` + version + `"}`,
		version + ".mod":  files["go.mod"],
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(modPath + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, version+".zip"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A pinned module whose type environment reaches mutable-local source (a
// local replace in its import cone) is unkeyable: its facts derive fresh
// every pass, so an edit to the local dependency changes the downgrade on the
// very next scan — no cache layer may launder local state through a pinned
// key (REQ-closure-dynamic-state-memo; the H-shaped violation of the fact
// invariant).
func TestPinnedFactsWithMutableLocalTypeEnvironmentDeriveFreshEachPass(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	modCache, err := os.MkdirTemp("", "gofresh-modcache-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOMODCACHE", modCache)
	t.Cleanup(func() {
		// The go tool writes the module cache read-only; clean restores
		// write permission before removal.
		clean := exec.Command("go", "clean", "-modcache")
		clean.Env = append(os.Environ(), "GOMODCACHE="+modCache)
		_ = clean.Run()
		os.RemoveAll(modCache)
	})
	proxy := t.TempDir()
	writeFileProxyModule(t, proxy, "example.com/x", "v1.0.0", map[string]string{
		"go.mod": "module example.com/x\n\ngo 1.26\n\nrequire example.com/y v1.0.0\n",
		"x.go":   "package x\n\nimport \"example.com/y\"\n\nvar Hook y.T\n\nfunc Rebind() {\n\tvar zero y.T\n\tHook = zero\n}\n",
	})
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")

	dir := t.TempDir()
	ySource := "package y\n\ntype T int\n"
	for name, content := range map[string]string{
		"go.mod":   "module example.com/hostmod\n\ngo 1.26\n\nrequire example.com/x v1.0.0\n\nreplace example.com/y => ./y\n",
		"lib.go":   "package hostmod\n\nimport \"example.com/x\"\n\nfunc Use() { x.Rebind() }\n",
		"y/go.mod": "module example.com/y\n\ngo 1.26\n",
		"y/y.go":   ySource,
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	tidy.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}

	const pkg = "example.com/hostmod"
	const scope = DynamicStateStrategy + "|proxy-host|cfg"
	subject := Subject{Package: pkg, Symbol: "Use"}
	processFactCache = sync.Map{}

	before := runScan(t, scope, dir, pkg)
	if before.downgradeReason[subject] != "" {
		t.Fatal("an int-typed hook already downgraded the subject")
	}
	if err := os.WriteFile(filepath.Join(dir, "y", "y.go"), []byte("package y\n\ntype T func()\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := runScan(t, scope, dir, pkg)
	if after.downgradeReason[subject] == "" {
		t.Fatal("a mutable-local type edit did not move the pinned dependency's fact - a cache layer laundered local state through a pinned key")
	}
}

// A test-cycle intermediate recompilation ("r [a.test]") is scanned from its
// own compilation: its mutation facts downgrade the tested package's
// subjects, and the scan succeeds even when the intermediate's plain form
// does not compile because it references test-added declarations
// (REQ-closure-dynamic-state-memo, REQ-closure-shared-dynamic-state).
func TestIntermediateRecompilationsScanFromTheirOwnCompilation(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":               "module example.com/cycle\n\ngo 1.26\n",
		"a/a.go":               "package a\n\nfunc A() int { return 1 }\n",
		"a/helper_test.go":     "package a\n\nconst FromTest = 1\n",
		"a/a_external_test.go": "package a_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/cycle/r\"\n)\n\nfunc TestA(t *testing.T) {\n\tr.Touch()\n}\n",
		"r/r.go":               "package r\n\nimport \"example.com/cycle/a\"\n\nvar Hook func()\n\nfunc Touch() {\n\t_ = a.FromTest\n\tHook = nil\n}\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const pkg = "example.com/cycle/a"
	result := runScan(t, DynamicStateStrategy+"|cycle|cfg", dir, pkg)
	subject := Subject{Package: pkg, Symbol: "A"}
	if !result.known[subject] {
		t.Fatal("scan lost the subject")
	}
	if result.downgradeReason[subject] == "" {
		t.Fatal("the intermediate recompilation's mutation did not downgrade the tested package's subjects")
	}
}

func contains(list []string, want string) bool {
	for _, have := range list {
		if have == want {
			return true
		}
	}
	return false
}
