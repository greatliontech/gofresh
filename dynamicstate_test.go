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
	"golang.org/x/tools/go/packages"
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
	scan, _, err := scanViewSubjects(context.Background(), hasher, scope, dir, os.Environ(), nil, nil, vouches, false, pkgPaths...)
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

import (
	"errors"
	"sync"
)

var pool sync.Pool

func Recycle() {
	v := pool.Get()
	pool.Put(v)
}

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
			fact = dynamicStateFactOf(p, false)
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

	// The pooling-discharge audit record: absent from an unattested
	// fact, present in an attested one, and surviving serialization —
	// a dropped record silently hides the load-bearing attestation
	// (REQ-vouch-recorded, REQ-closure-shared-dynamic-state).
	if len(restored.PoolDischarges) != 0 {
		t.Fatalf("unattested fact carries pool discharges: %+v", restored.PoolDischarges)
	}
	var attested dynamicStateFact
	for _, p := range load.Packages() {
		if p.PkgPath == "example.com/factsrc" && p.ForTest == "" {
			attested = dynamicStateFactOf(p, true)
		}
	}
	rawAttested, err := json.Marshal(attested)
	if err != nil {
		t.Fatal(err)
	}
	var restoredAttested dynamicStateFact
	if err := json.Unmarshal(rawAttested, &restoredAttested); err != nil {
		t.Fatal(err)
	}
	if !contains(restoredAttested.PoolDischarges, "example.com/factsrc.pool") {
		t.Fatalf("attested fact lost the pooling-discharge record: %+v", restoredAttested.PoolDischarges)
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

// writeMappedDepModule writes a module depending on golang.org/x/sys at
// the parent module's own pinned version, whose one function round-trips
// an anonymous mapping through unix.Mmap/Munmap — the shape whose only
// shared-dynamic-state culprit is the mapper bookkeeping.
func writeMappedDepModule(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}", "golang.org/x/sys").Output()
	if err != nil {
		t.Fatalf("resolve parent x/sys version: %v", err)
	}
	version := strings.TrimSpace(string(out))
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/mapped\n\ngo 1.26\n\nrequire golang.org/x/sys " + version + "\n",
		"lib.go": "package mapped\n\nimport \"golang.org/x/sys/unix\"\n\nfunc Roundtrip() error {\n\tb, err := unix.Mmap(-1, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)\n\tif err != nil {\n\t\treturn err\n\t}\n\treturn unix.Munmap(b)\n}\n",
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

// The audited mapping set: under the single-subject attestation the
// mapper bookkeeping's marks discharge for the version-pinned module and
// the discharge rides the subject's evidence; without the attestation
// the downgrade stands naming mapper; and a different variable of the
// same module keeps its own judgment even attested — the discharge
// covers exactly the audited name (REQ-closure-shared-dynamic-state,
// REQ-vouch-recorded).
func TestAuditedMappingDischargeRequiresAttestation(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeMappedDepModule(t)
	const mapper = "golang.org/x/sys/unix.mapper"
	subject := Subject{Package: "example.com/mapped", Symbol: "Roundtrip"}
	processFactCache = sync.Map{}
	ctx := context.Background()

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
	if controlVerdict.Status != Unverifiable || !strings.Contains(controlVerdict.Reason, mapper+" is mutated") {
		t.Fatalf("unattested verdict = %+v, want the downgrade naming %s", controlVerdict, mapper)
	}
	if controlFP.SingleSubjectDischarges != "" {
		t.Fatalf("unattested evidence recorded %q, want nothing", controlFP.SingleSubjectDischarges)
	}

	attested, err := New(WithDir(dir), WithSingleSubjectExecution())
	if err != nil {
		t.Fatal(err)
	}
	view, err := attested.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.SingleSubjectDischarges != mapper {
		t.Fatalf("attested evidence = %q, want %q", fingerprint.SingleSubjectDischarges, mapper)
	}
	verdict, err := view.Check(ctx, fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(verdict.Reason, "shares mutated dynamic state") {
		t.Fatalf("attested verdict still downgraded: %+v", verdict)
	}

	// A ghost variable of the same module stays refused under the
	// attestation: the discharge names exactly the audited variable.
	const ghost = "golang.org/x/sys/unix.Ghost"
	var hit bool
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sys/unix") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, ghost)
			fact.Mutates = append(fact.Mutates, ghost)
			processFactCache.Store(k, fact)
			hit = true
		}
		return true
	})
	if !hit {
		t.Fatal("no unix fact in the process cache")
	}
	poisonedEngine, err := New(WithDir(dir), WithSingleSubjectExecution())
	if err != nil {
		t.Fatal(err)
	}
	poisonedView, err := poisonedEngine.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	poisonedFP, err := poisonedView.Capture(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	poisonedVerdict, err := poisonedView.Check(ctx, poisonedFP, subject)
	if err != nil {
		t.Fatal(err)
	}
	if poisonedVerdict.Status != Unverifiable || !strings.Contains(poisonedVerdict.Reason, ghost+" is mutated") {
		t.Fatalf("attested ghost verdict = %+v, want the downgrade naming %s - the discharge covers exactly the audited variable", poisonedVerdict, ghost)
	}
}

// The audited mapping set confers nothing on a mutable-local checkout:
// the discharge crosses exactly the version-pinned dependency line, so
// a replace-directed golang.org/x/sys keeps the mapper downgrade under
// the attestation and records no discharge — code the caller can edit
// is fixed, not audited (REQ-closure-shared-dynamic-state, the
// vouch-dependency-boundary discipline). The local stub carries the
// audited shape (a bookkeeping map plus function fields, written
// through a pointer-receiver mapping call) at the audited import path.
func TestAuditedMappingConfersNothingOnMutableLocalCheckout(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":                 "module example.com/mapped\n\ngo 1.26\n\nrequire golang.org/x/sys v0.0.0\n\nreplace golang.org/x/sys => ./local-sys\n",
		"lib.go":                 "package mapped\n\nimport \"golang.org/x/sys/unix\"\n\nfunc Roundtrip() error {\n\tb, err := unix.Mmap(4096)\n\tif err != nil {\n\t\treturn err\n\t}\n\treturn unix.Munmap(b)\n}\n",
		"local-sys/go.mod":       "module golang.org/x/sys\n\ngo 1.26\n",
		"local-sys/unix/mmap.go": "package unix\n\nimport \"errors\"\n\ntype mmapper struct {\n\tactive map[*byte][]byte\n\tmmap   func(length int) ([]byte, error)\n\tmunmap func(b []byte) error\n}\n\nvar mapper = &mmapper{\n\tactive: map[*byte][]byte{},\n\tmmap:   rawMmap,\n\tmunmap: rawMunmap,\n}\n\nfunc rawMmap(length int) ([]byte, error) { return make([]byte, length), nil }\n\nfunc rawMunmap(b []byte) error { return nil }\n\nfunc (m *mmapper) Mmap(length int) ([]byte, error) {\n\tb, err := m.mmap(length)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tm.active[&b[0]] = b\n\treturn b, nil\n}\n\nfunc (m *mmapper) Munmap(b []byte) error {\n\tif len(b) == 0 {\n\t\treturn errors.New(\"empty\")\n\t}\n\tdelete(m.active, &b[0])\n\treturn m.munmap(b)\n}\n\nfunc Mmap(length int) ([]byte, error) { return mapper.Mmap(length) }\n\nfunc Munmap(b []byte) error { return mapper.Munmap(b) }\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	processFactCache = sync.Map{}
	ctx := context.Background()
	subject := Subject{Package: "example.com/mapped", Symbol: "Roundtrip"}
	engine, err := New(WithDir(dir), WithSingleSubjectExecution())
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(ctx, fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "golang.org/x/sys/unix.mapper is mutated") {
		t.Fatalf("mutable-local checkout verdict = %+v, want the downgrade naming the mapper - the discharge crosses only the version-pinned line", verdict)
	}
	if fingerprint.SingleSubjectDischarges != "" {
		t.Fatalf("mutable-local checkout recorded a discharge: %q", fingerprint.SingleSubjectDischarges)
	}
}

// The audited memoization set: the structMap-shaped cache of the
// version-pinned gopkg.in/yaml.v3 discharges WITHOUT any execution
// attestation (content-invariant derivation — its values are never
// subject-planted), while a ghost variable of the same module keeps its
// own judgment — the discharge covers exactly the audited variable
// (REQ-closure-shared-dynamic-state).
func TestAuditedMemoizationDischargeIsAttestationFree(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	modCache, err := os.MkdirTemp("", "gofresh-modcache-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOMODCACHE", modCache)
	t.Cleanup(func() {
		clean := exec.Command("go", "clean", "-modcache")
		clean.Env = append(os.Environ(), "GOMODCACHE="+modCache)
		_ = clean.Run()
		os.RemoveAll(modCache)
	})
	proxy := t.TempDir()
	memoSource := "package yaml\n\nimport (\n\t\"reflect\"\n\t\"sync\"\n)\n\ntype structInfo struct{ n int }\n\nvar structMap = make(map[reflect.Type]*structInfo)\nvar fieldMapMutex sync.RWMutex\n\nfunc FieldCount(st reflect.Type) int {\n\tfieldMapMutex.RLock()\n\tsinfo, found := structMap[st]\n\tfieldMapMutex.RUnlock()\n\tif found {\n\t\treturn sinfo.n\n\t}\n\tsinfo = &structInfo{n: st.NumField()}\n\tfieldMapMutex.Lock()\n\tstructMap[st] = sinfo\n\tfieldMapMutex.Unlock()\n\treturn sinfo.n\n}\n"
	writeFileProxyModule(t, proxy, "gopkg.in/yaml.v3", "v3.0.1", map[string]string{
		"go.mod":  "module gopkg.in/yaml.v3\n\ngo 1.26\n",
		"yaml.go": memoSource,
	})
	writeFileProxyModule(t, proxy, "gopkg.in/yaml.v3", "v3.0.2", map[string]string{
		"go.mod":  "module gopkg.in/yaml.v3\n\ngo 1.26\n",
		"yaml.go": memoSource + "\nvar Ghost = map[string]func(){}\n\nfunc ArmGhost() { Ghost[\"k\"] = func() {} }\n",
	})
	writeFileProxyModule(t, proxy, "gopkg.in/yaml.v3", "v3.0.3", map[string]string{
		"go.mod":  "module gopkg.in/yaml.v3\n\ngo 1.26\n",
		"yaml.go": memoSource,
	})
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")

	host := func(t *testing.T, version string) string {
		t.Helper()
		dir := t.TempDir()
		for name, content := range map[string]string{
			"go.mod": "module example.com/memohost\n\ngo 1.26\n\nrequire gopkg.in/yaml.v3 " + version + "\n",
			"lib.go": "package memohost\n\nimport (\n\t\"reflect\"\n\n\tyaml \"gopkg.in/yaml.v3\"\n)\n\ntype rec struct{ A, B int }\n\nfunc Use() int { return yaml.FieldCount(reflect.TypeOf(rec{})) }\n",
		} {
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
		return dir
	}
	subject := Subject{Package: "example.com/memohost", Symbol: "Use"}

	processFactCache = sync.Map{}
	clean := runScan(t, DynamicStateStrategy+"|memo-clean|cfg", host(t, "v3.0.1"), "example.com/memohost")
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("unattested structMap-shaped cache downgraded the subject: %q - the memoization discharge needs no attestation", reason)
	}

	processFactCache = sync.Map{}
	ghosted := runScan(t, DynamicStateStrategy+"|memo-ghost|cfg", host(t, "v3.0.2"), "example.com/memohost")
	if reason := ghosted.downgradeReason[subject]; !strings.Contains(reason, "gopkg.in/yaml.v3.Ghost is mutated") {
		t.Fatalf("ghost verdict reason = %q, want the downgrade naming Ghost - the discharge covers exactly the audited variable", reason)
	}

	// The audit is a property of the audited versions' source: an
	// unaudited version with the identical shape refuses fail-closed
	// until its source is audited.
	processFactCache = sync.Map{}
	unaudited := runScan(t, DynamicStateStrategy+"|memo-unaudited|cfg", host(t, "v3.0.3"), "example.com/memohost")
	if reason := unaudited.downgradeReason[subject]; !strings.Contains(reason, "gopkg.in/yaml.v3.structMap is mutated") {
		t.Fatalf("unaudited-version reason = %q, want the downgrade naming structMap - no version inherits the audit", reason)
	}
}

// The audited memoization set confers nothing on a mutable-local
// checkout: the audit holds for the version-pinned source alone, so a
// replace-directed gopkg.in/yaml.v3 keeps the structMap downgrade —
// code the caller can edit is fixed, not audited
// (REQ-closure-shared-dynamic-state).
func TestAuditedMemoizationConfersNothingOnMutableLocalCheckout(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":             "module example.com/memohost\n\ngo 1.26\n\nrequire gopkg.in/yaml.v3 v3.0.0\n\nreplace gopkg.in/yaml.v3 => ./local-yaml\n",
		"lib.go":             "package memohost\n\nimport (\n\t\"reflect\"\n\n\tyaml \"gopkg.in/yaml.v3\"\n)\n\ntype rec struct{ A, B int }\n\nfunc Use() int { return yaml.FieldCount(reflect.TypeOf(rec{})) }\n",
		"local-yaml/go.mod":  "module gopkg.in/yaml.v3\n\ngo 1.26\n",
		"local-yaml/yaml.go": "package yaml\n\nimport (\n\t\"reflect\"\n\t\"sync\"\n)\n\ntype structInfo struct{ n int }\n\nvar structMap = make(map[reflect.Type]*structInfo)\nvar fieldMapMutex sync.RWMutex\n\nfunc FieldCount(st reflect.Type) int {\n\tfieldMapMutex.RLock()\n\tsinfo, found := structMap[st]\n\tfieldMapMutex.RUnlock()\n\tif found {\n\t\treturn sinfo.n\n\t}\n\tsinfo = &structInfo{n: st.NumField()}\n\tfieldMapMutex.Lock()\n\tstructMap[st] = sinfo\n\tfieldMapMutex.Unlock()\n\treturn sinfo.n\n}\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	processFactCache = sync.Map{}
	scan := runScan(t, DynamicStateStrategy+"|memo-local|cfg", dir, "example.com/memohost")
	subject := Subject{Package: "example.com/memohost", Symbol: "Use"}
	if reason := scan.downgradeReason[subject]; !strings.Contains(reason, "gopkg.in/yaml.v3.structMap is mutated") {
		t.Fatalf("mutable-local checkout reason = %q, want the downgrade naming structMap - the audit covers only the version-pinned line", reason)
	}
}

// The //gofresh:single-subject directive confers nothing on a
// dependency's variable even under the attestation: the directive
// covers exactly the code its author edits and reviews — the inverse of
// the vouch boundary (REQ-closure-shared-dynamic-state).
func TestSingleSubjectDirectiveConfersNothingOnDependency(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	modCache, err := os.MkdirTemp("", "gofresh-modcache-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOMODCACHE", modCache)
	t.Cleanup(func() {
		clean := exec.Command("go", "clean", "-modcache")
		clean.Env = append(os.Environ(), "GOMODCACHE="+modCache)
		_ = clean.Run()
		os.RemoveAll(modCache)
	})
	proxy := t.TempDir()
	writeFileProxyModule(t, proxy, "example.com/depdir", "v1.0.0", map[string]string{
		"go.mod": "module example.com/depdir\n\ngo 1.26\n",
		"x.go":   "package depdir\n\n//gofresh:single-subject\nvar Hook func()\n\nfunc Rebind() { Hook = nil }\n",
	})
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")

	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/dirhost\n\ngo 1.26\n\nrequire example.com/depdir v1.0.0\n",
		"lib.go": "package dirhost\n\nimport \"example.com/depdir\"\n\nfunc Use() { depdir.Rebind() }\n",
	} {
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

	processFactCache = sync.Map{}
	hasher, err := closure.NewAtContextEnv(context.Background(), dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	scan, _, err := scanViewSubjects(context.Background(), hasher, DynamicStateStrategy+"|dep-directive|cfg", dir, os.Environ(), nil, nil, nil, true, "example.com/dirhost")
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/dirhost", Symbol: "Use"}
	if reason := scan.downgradeReason[subject]; !strings.Contains(reason, "example.com/depdir.Hook is mutated") {
		t.Fatalf("attested dep-directive reason = %q, want the downgrade naming Hook - a dependency's directive confers nothing", reason)
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

// An init-flow bind of one carrier from another records the storage
// link in the declaring package's fact
// (REQ-closure-shared-dynamic-state).
func TestCarrierAliasLinkRecorded(t *testing.T) {
	files := map[string]string{
		"go.mod":     "module example.com/xesc\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\nfunc one() int { return 1 }\n\nvar Hooks = map[string]func() int{\"a\": one}\n\nvar Alias = Hooks\n\nfunc Count() int { return len(Hooks) }\n",
	}
	dir := writeModuleTree(t, files)
	cfg := &packages.Config{Mode: packages.LoadAllSyntax, Dir: dir}
	pkgs, err := packages.Load(cfg, "example.com/xesc/reg")
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("load: %v (%d packages)", err, len(pkgs))
	}
	fact := dynamicStateFactOf(pkgs[0], false)
	want := "example.com/xesc/reg.Alias\x01example.com/xesc/reg.Hooks"
	found := false
	for _, link := range fact.CarrierLinks {
		if link == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("CarrierLinks = %q, want the Alias-to-Hooks storage link recorded", fact.CarrierLinks)
	}
}

// An init-flow element store whose target is a carrier links the two
// backings exactly as a whole-name bind does, while a call-result bind
// records no link - the callee's value is not the argument's backing
// (REQ-closure-shared-dynamic-state).
func TestCarrierStoreLinkRecordedAndCallResultsUnlinked(t *testing.T) {
	files := map[string]string{
		"go.mod":     "module example.com/xesc\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\nfunc one() int { return 1 }\n\nvar Inner = []func() int{one}\n\nvar Hooks = map[string][]func() int{}\n\nfunc pick(m map[string][]func() int) map[string][]func() int { return m }\n\nvar Picked = pick(Hooks)\n\nfunc init() {\n\tHooks[\"a\"] = Inner\n}\n\nfunc Count() int { return len(Hooks) }\n",
	}
	dir := writeModuleTree(t, files)
	cfg := &packages.Config{Mode: packages.LoadAllSyntax, Dir: dir}
	pkgs, err := packages.Load(cfg, "example.com/xesc/reg")
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("load: %v (%d packages)", err, len(pkgs))
	}
	fact := dynamicStateFactOf(pkgs[0], false)
	wantStore := "example.com/xesc/reg.Hooks\x01example.com/xesc/reg.Inner"
	foundStore := false
	for _, link := range fact.CarrierLinks {
		if link == wantStore {
			foundStore = true
		}
		if strings.Contains(link, "Picked") {
			t.Fatalf("CarrierLinks = %q, want no link through a call result", fact.CarrierLinks)
		}
	}
	if !foundStore {
		t.Fatalf("CarrierLinks = %q, want the element-store link recorded", fact.CarrierLinks)
	}
}

// A cross-carrier storage link crosses mutation marks symmetrically: a
// mutation recorded against an aliasing key refuses the linked origin
// key too - one backing under every name it carries
// (REQ-closure-shared-dynamic-state).
func TestCarrierLinkCrossesMutationMarks(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"
	subject := Subject{Package: pkg, Symbol: "Run"}
	processFactCache = sync.Map{}
	const scope = DynamicStateStrategy + "|carrier-link-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	var hit bool
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			// The origin is declared; the mutation lands on an
			// undeclared aliasing key - without the link no culprit
			// exists, with it the mark crosses to the origin.
			fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
			fact.Mutates = append(fact.Mutates, "golang.org/x/sync/errgroup.ghostAlias")
			fact.CarrierLinks = append(fact.CarrierLinks, "golang.org/x/sync/errgroup.ghostAlias\x01golang.org/x/sync/errgroup.Ghost")
			processFactCache.Store(k, fact)
			hit = true
		}
		return true
	})
	if !hit {
		t.Fatal("no errgroup fact in the process cache")
	}
	linked := runScan(t, scope, dir, pkg)
	if reason := linked.downgradeReason[subject]; !strings.Contains(reason, "golang.org/x/sync/errgroup.Ghost is mutated") {
		t.Fatalf("downgrade reason %q does not cross the link - the shared backing split across keys", reason)
	}
}

// The link crosses escape marks identically: an escape recorded against
// an aliasing key refuses the linked origin
// (REQ-closure-shared-dynamic-state).
func TestCarrierLinkCrossesEscapeMarks(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"
	subject := Subject{Package: pkg, Symbol: "Run"}
	processFactCache = sync.Map{}
	const scope = DynamicStateStrategy + "|carrier-link-escape-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	var hit bool
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
			fact.Escapes = append(fact.Escapes, "golang.org/x/sync/errgroup.ghostAlias")
			fact.CarrierLinks = append(fact.CarrierLinks, "golang.org/x/sync/errgroup.ghostAlias\x01golang.org/x/sync/errgroup.Ghost")
			processFactCache.Store(k, fact)
			hit = true
		}
		return true
	})
	if !hit {
		t.Fatal("no errgroup fact in the process cache")
	}
	linked := runScan(t, scope, dir, pkg)
	if reason := linked.downgradeReason[subject]; !strings.Contains(reason, "golang.org/x/sync/errgroup.Ghost escapes writable") {
		t.Fatalf("downgrade reason %q does not cross the escape link - the shared backing split across keys", reason)
	}
}

// A persisted cross-carrier link the consumer cannot parse is not
// trusted: every key the fact declares marks mutated — fail-closed like
// every malformed-fact arm (REQ-closure-shared-dynamic-state).
func TestMalformedCarrierLinkMarksEveryDeclaredKey(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"
	subject := Subject{Package: pkg, Symbol: "Run"}
	processFactCache = sync.Map{}
	const scope = DynamicStateStrategy + "|malformed-link-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	var hit bool
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
			// No separator - the link lost one of its keys.
			fact.CarrierLinks = append(fact.CarrierLinks, "golang.org/x/sync/errgroup.Ghost")
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
		t.Fatalf("downgrade reason %q does not mark the declared key - a malformed link slipped through", reason)
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
		{"paramLeakFreeDeps", func(fact *dynamicStateFact) {
			// Dependency key lost a NUL frame.
			fact.ParamLeakFreeDeps = append(fact.ParamLeakFreeDeps, "golang.org/x/sync/errgroup\x00Go\x000\x01bad")
		}},
		{"paramRetentionFreeDeps", func(fact *dynamicStateFact) {
			// The retention grade's edges validate identically.
			fact.ParamRetentionFreeDeps = append(fact.ParamRetentionFreeDeps, "golang.org/x/sync/errgroup\x00Go\x000\x01bad")
		}},
		{"initParamUses", func(fact *dynamicStateFact) {
			// One NUL only - the callee parameter key lost its frame.
			fact.InitParamUses = append(fact.InitParamUses, "golang.org/x/sync/errgroup.Ghost\x00bad")
		}},
		{"initMethodUses", func(fact *dynamicStateFact) {
			// No separator - the method key is missing.
			fact.InitMethodUses = append(fact.InitMethodUses, "golang.org/x/sync/errgroup.Ghost")
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
