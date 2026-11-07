package gofresh

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A replaced local dependency is IN the loaded scope: its syntax loads
// and the refusal lands inside it with a position — pinning that the
// edge-termination clause's "outside the loaded scope" never silently
// widens to swallow loadable dependencies. (The genuinely-outside
// shape — an export-data-only module-cache dependency — is not
// fixturable hermetically: a replaced dep loads with syntax and a
// parse-broken dep refuses the whole view.)
func TestExplainChainReplacedDepIsInScope(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	files := map[string]string{
		"go.mod":         "module example.com/explain\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./depstub\n",
		"depstub/go.mod": "module example.com/dep\n\ngo 1.26\n",
		"depstub/dep.go": "package dep\n\ntype Handler func(n int) int\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\nfunc Make() []Handler {\n\tc := &counter{}\n\treturn []Handler{c.Next}\n}\n",
		"reg/reg.go":     "package reg\n\nimport \"example.com/dep\"\n\nfunc gen() []dep.Handler { return dep.Make() }\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
	}
	dir := writeModuleTree(t, files)
	chain := explainView(t, dir, "example.com/explain/reg", "Registry")
	if chain.Arm != "environment-audit" {
		t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
	}
	sawDepEdge, sawDepRefusal := false, false
	for _, l := range chain.Links {
		if l.Kind == "edge" && strings.Contains(l.Callee, "example.com/dep") {
			sawDepEdge = true
		}
		if l.Kind == "refusal" && strings.Contains(l.Package, "example.com/dep") {
			sawDepRefusal = true
			if !strings.Contains(l.Pos, "dep.go:") {
				t.Fatalf("in-scope dependency refusal lacks its position: %+v", l)
			}
		}
	}
	if !sawDepEdge || !sawDepRefusal {
		t.Fatalf("replaced dependency not treated as in-scope: %+v", chain)
	}
}

// Under an unaudited toolchain selection every tier refusal carries the
// selection's owned attribution — the degraded axis, appended at the
// tier's own composition: the closure tier, signature dynamism, and
// shared dynamic state here (the observability tier is pinned in the
// closure package) — while the declaration-borne refusals, the external
// directive and an ambiguous identity, carry none, and an audited
// selection attributes nothing (REQ-closure-refusal-channels).
func TestUnauditedSelectionAttributesTierRefusals(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over fixtures")
	}
	isolateProofCache(t)
	badEnv := unauditedTagEnv(t)
	axis := " (judged under an unaudited toolchain selection: the audited surface of " + runtime.Version() + " moved in 1 keys: strings)"
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":           "module example.com/view\n\ngo 1.26\n",
		"view.go":          "package view\n\nimport \"net\"\n\nfunc Open(f func()) { f() }\n\nfunc Dial() error { _, err := net.Dial(\"tcp\", \"\"); return err }\n\n//gofresh:external\nfunc Declared() int { return 1 }\n\nfunc Twice() int { return 1 }\n",
		"view_test.go":     "package view_test\n\nfunc Twice() int { return 2 }\n",
		"shared/shared.go": "package shared\n\nvar Hook = func() {}\n\nfunc Rebind() { Hook = func() {} }\n\nfunc Shared() { Hook() }\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The shared-dynamic-state downgrade is package-wide, so its
	// fixture is its own package beside the others.
	shared := Subject{Package: "example.com/view/shared", Symbol: "Shared"}
	subjects := func(names ...string) []Subject {
		out := []Subject{shared}
		for _, name := range names {
			out = append(out, Subject{Package: "example.com/view", Symbol: name})
		}
		return out
	}
	engine, err := newEngine(withDir(dir), withEnv(badEnv...), withBuildFlags("-tags=badstd"))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), subjects("Open", "Dial", "Declared", "Twice"), dir)
	if err != nil {
		t.Fatal(err)
	}
	reason := func(symbol string) string {
		subject := Subject{Package: "example.com/view", Symbol: symbol}
		if symbol == shared.Symbol {
			subject = shared
		}
		facts, ok := view.facts.maximal[subject]
		cl := facts.closure()
		if !ok || !cl.Unverifiable {
			t.Fatalf("%s = %+v, want an unverifiable maximal closure", symbol, cl)
		}
		return cl.Reason
	}
	if got := reason("Open"); got != "subject accepts caller-supplied dynamic behavior through its parameter f func() (dischargeable by bounding that type away from dynamic carriers, or by "+closure.PurityResponsibility+")"+axis {
		t.Fatalf("signature-dynamism refusal = %q, want the term, the channel, and the axis", got)
	}
	if got := reason("Dial"); !strings.HasPrefix(got, "reaches net") || !strings.HasSuffix(got, axis) || strings.Count(got, "judged under") != 1 {
		t.Fatalf("closure-tier refusal = %q, want the reach with the axis appended once", got)
	}
	if got := reason("Shared"); !strings.Contains(got, "example.com/view/shared.Hook is mutated") || !strings.HasSuffix(got, axis) || strings.Count(got, "judged under") != 1 {
		t.Fatalf("shared-dynamic-state refusal = %q, want the culprit with the axis appended", got)
	}
	if got := reason("Declared"); got != "external directive" {
		t.Fatalf("external declaration = %q, want no attribution", got)
	}
	if got := reason("Twice"); !strings.HasPrefix(got, "ambiguous subject identity: ") || strings.Contains(got, "judged under") {
		t.Fatalf("ambiguous identity = %q, want no attribution", got)
	}
	for _, symbol := range []string{"Declared", "Twice", "Open"} {
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: symbol}, withEnv(badEnv...), withBuildFlags("-tags=badstd"))
		if verdict.Status != Unverifiable || (symbol == "Declared" && verdict.Reason != "external directive") || (symbol == "Open" && !strings.HasSuffix(verdict.Reason, axis)) {
			t.Fatalf("%s verdict = %+v", symbol, verdict)
		}
	}
	audited, err := newEngine(withDir(dir), withEnv(badEnv...))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := audited.newView(context.Background(), subjects("Open", "Dial"), dir)
	if err != nil {
		t.Fatal(err)
	}
	for symbol, facts := range plain.facts.maximal {
		cl := facts.closure()
		if strings.Contains(cl.Reason, "judged under") {
			t.Fatalf("audited selection attributed %s: %q", symbol.Symbol, cl.Reason)
		}
	}
}

func TestUnscopedFactsNeverUseTheProcessCache(t *testing.T) {
	if testing.Short() {
		t.Skip("loads pinned facts under complete and absent scopes")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	processFactCache.Reset()
	t.Cleanup(func() { processFactCache.Reset() })
	loads := 0
	const pkg = "example.com/pinned"
	withViewTestHooks(viewTestHookSet{
		dynamicStateMissLoad: func([]string) { loads++ },
	}, func() {
		clean := runScan(t, "complete", dir, pkg)
		if loads != 1 {
			t.Fatalf("cold loads=%d", loads)
		}
		if warm := runScan(t, "complete", dir, pkg); loads != 1 || !reflect.DeepEqual(warm, clean) {
			t.Fatal("complete scope did not serve")
		}
		var key string
		var poison dynamicStateFact
		processFactCache.Range(func(k string, fact dynamicStateFact) bool {
			if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
				key = k[strings.IndexByte(k, 0):]
				poison = fact
				poison.Declares = append(poison.Declares, "golang.org/x/sync/errgroup.Ghost")
				poison.Mutates = append(poison.Mutates, "golang.org/x/sync/errgroup.Ghost")
			}
			return true
		})
		if key == "" {
			t.Fatal("no pinned fact control")
		}
		processFactCache.Reset()
		processFactCache.Store(key, poison)
		for i := 0; i < 2; i++ {
			got := runScan(t, "", dir, pkg)
			if loads != 2+i || !reflect.DeepEqual(got, clean) {
				t.Errorf("unscoped scan served cached facts: loads=%d result=%+v", loads, got)
			}
			stored, ok := processFactCache.Load(key)
			if !ok || !reflect.DeepEqual(stored, poison) {
				t.Error("unscoped scan wrote process facts")
			}
		}
	})
}

// Version-pinned package facts load once, then serve from the in-process
// cache, then from the persistent memo across cache resets, with
// fact-equivalent scan results throughout; a scope change recomputes
// (REQ-closure-dynamic-state-memo).
func TestDynamicStateFactsServePinnedPackagesWithoutLoading(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"

	var missLoads [][]string
	processFactCache.Reset()
	withViewTestHooks(viewTestHookSet{
		dynamicStateMissLoad: func(patterns []string) {
			missLoads = append(missLoads, append([]string(nil), patterns...))
		},
	}, func() {
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

		processFactCache.Reset()
		third := runScan(t, scope, dir, pkg)
		if len(missLoads) != 1 {
			t.Fatalf("persistent warm scan re-loaded pinned facts: %d loads", len(missLoads))
		}
		if !reflect.DeepEqual(first, third) {
			t.Fatalf("persistent fact serve is not scan-equivalent:\n first %+v\n third %+v", first, third)
		}

		processFactCache.Reset()
		moved := runScan(t, DynamicStateStrategy+"|other-toolchain|test-buildconfig", dir, pkg)
		if len(missLoads) != 2 {
			t.Fatalf("scope change served stale facts: %d loads, want 2", len(missLoads))
		}
		if !reflect.DeepEqual(first, moved) {
			t.Fatalf("recomputation under a moved scope is not scan-equivalent:\n first %+v\n moved %+v", first, moved)
		}
	})
}

// The engine option threads the vouch to capture: a vouched pinned
// culprit's subject records the discharge on its fingerprint, its
// verdict is no longer downgraded, and without the vouch the same
// poisoned graph refuses naming the culprit (REQ-vouch-input,
// REQ-vouch-recorded).
func TestVouchedFingerprintRecordsDischarge(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const ghost = "golang.org/x/sync/errgroup.Ghost"
	subject := Subject{Package: "example.com/pinned", Symbol: "Run"}
	processFactCache.Reset()
	ctx := context.Background()

	// Poisons the in-process fact cache between two views: the scan memo
	// would serve the first view's outputs whole (a production key never
	// holds a moved fact), so the derivation is exercised directly.
	withViewTestHooks(viewTestHookSet{scanMemoOff: true}, func() {
		warm, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := warm.newView(ctx, []Subject{subject}, dir); err != nil {
			t.Fatal(err)
		}
		var hit bool
		processFactCache.Range(func(k string, fact dynamicStateFact) bool {
			if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
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

		control, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		controlView, err := control.newView(ctx, []Subject{subject}, dir)
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

		vouched, err := newEngine(withDir(dir), withDynamicStateVouches(ghost))
		if err != nil {
			t.Fatal(err)
		}
		view, err := vouched.newView(ctx, []Subject{subject}, dir)
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
	})
}

// The audited mapping set discharges WITHOUT any execution attestation
// (the deepened audit: init-only callable fields, address-keyed
// data-only bookkeeping): the unattested verdict stands with no
// evidence record — the engine's own verdict, the memoization set's
// class — the attested session records nothing for it either, and a
// ghost variable of the same module keeps its own judgment — the
// discharge covers exactly the audited name
// (REQ-closure-shared-dynamic-state).
func TestAuditedMappingDischargeIsAttestationFree(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeMappedDepModule(t)
	const mapper = "golang.org/x/sys/unix.mapper"
	subject := Subject{Package: "example.com/mapped", Symbol: "Roundtrip"}
	processFactCache.Reset()
	ctx := context.Background()

	// Poisons the in-process fact cache between two views: the scan memo
	// would serve the first view's outputs whole (a production key never
	// holds a moved fact), so the derivation is exercised directly.
	withViewTestHooks(viewTestHookSet{scanMemoOff: true}, func() {
		control, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		controlView, err := control.newView(ctx, []Subject{subject}, dir)
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
		// The fixture's closure still reaches the mapping syscalls' external
		// effects (their observability classification is untouched by the
		// discharge), so the ONLY residual is that class — pinned by
		// equality so a second downgrade can never hide behind it.
		if controlVerdict.Status != Unverifiable || controlVerdict.Reason != "reaches golang.org/x/sys/unix (external system call) (dischargeable by restructuring the subject away from the reach, or by the //gofresh:pure directive on the subject's declaration or the caller's purity assertion)" {
			t.Fatalf("unattested verdict = %+v, want exactly the untouched observability class - the mapping discharge needs no attestation; a mapper-naming reason likely means the parent go.mod pins an x/sys version outside the audited set: audit the new source and extend auditedMappingOut's switch", controlVerdict)
		}
		if controlFP.SingleSubjectDischarges != "" {
			t.Fatalf("unattested evidence recorded %q, want nothing - the discharge is the engine's own verdict", controlFP.SingleSubjectDischarges)
		}

		attested, err := newEngine(withDir(dir), withSingleSubjectExecution())
		if err != nil {
			t.Fatal(err)
		}
		view, err := attested.newView(ctx, []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := view.Capture(ctx, subject)
		if err != nil {
			t.Fatal(err)
		}
		if fingerprint.SingleSubjectDischarges != "" {
			t.Fatalf("attested evidence recorded %q, want nothing - the mapping discharge is not an attestation", fingerprint.SingleSubjectDischarges)
		}
		verdict, err := view.Check(ctx, fingerprint, subject)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(verdict.Reason, "shares mutated dynamic state") {
			t.Fatalf("attested verdict downgraded: %+v", verdict)
		}

		// A ghost variable of the same module keeps its own judgment in the
		// unattested mode: the discharge names exactly the audited variable.
		const ghost = "golang.org/x/sys/unix.Ghost"
		var hit bool
		processFactCache.Range(func(k string, fact dynamicStateFact) bool {
			if strings.HasSuffix(k, "\x00golang.org/x/sys/unix") {
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
		poisonedEngine, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		poisonedView, err := poisonedEngine.newView(ctx, []Subject{subject}, dir)
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
			t.Fatalf("ghost verdict = %+v, want the downgrade naming %s - the discharge covers exactly the audited variable", poisonedVerdict, ghost)
		}
		attestedGhostEngine, err := newEngine(withDir(dir), withSingleSubjectExecution())
		if err != nil {
			t.Fatal(err)
		}
		attestedGhostView, err := attestedGhostEngine.newView(ctx, []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		attestedGhostFP, err := attestedGhostView.Capture(ctx, subject)
		if err != nil {
			t.Fatal(err)
		}
		attestedGhostVerdict, err := attestedGhostView.Check(ctx, attestedGhostFP, subject)
		if err != nil {
			t.Fatal(err)
		}
		if attestedGhostVerdict.Status != Unverifiable || !strings.Contains(attestedGhostVerdict.Reason, ghost+" is mutated") {
			t.Fatalf("attested ghost verdict = %+v, want the downgrade naming %s - the attestation arms no ghost discharge", attestedGhostVerdict, ghost)
		}
	})
}

// The mapping audit is a property of the audited versions' source: an
// unaudited pinned version carrying the identical mapper shape refuses
// fail-closed until its source is audited — exactly the memoization
// set's rule (REQ-closure-shared-dynamic-state).
func TestAuditedMappingUnauditedVersionRefuses(t *testing.T) {
	if testing.Short() {
		t.Skip("populates a module cache and runs the engine over a temporary module")
	}
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
	mapperSource := "package unix\n\ntype mmapper struct {\n\tactive map[*byte][]byte\n\tmmap   func(length int) ([]byte, error)\n\tmunmap func(b []byte) error\n}\n\nvar mapper = &mmapper{\n\tactive: map[*byte][]byte{},\n\tmmap:   func(length int) ([]byte, error) { return make([]byte, length), nil },\n\tmunmap: func(b []byte) error { return nil },\n}\n\nfunc (m *mmapper) Mmap(length int) ([]byte, error) {\n\tb, err := m.mmap(length)\n\tif err != nil {\n\t\treturn nil, err\n\t}\n\tm.active[&b[0]] = b\n\treturn b, nil\n}\n\nfunc (m *mmapper) Munmap(b []byte) error {\n\tdelete(m.active, &b[0])\n\treturn m.munmap(b)\n}\n\nfunc Mmap(length int) ([]byte, error) { return mapper.Mmap(length) }\n\nfunc Munmap(b []byte) error { return mapper.Munmap(b) }\n"
	writeFileProxyModule(t, proxy, "golang.org/x/sys", "v0.999.0", map[string]string{
		"go.mod":       "module golang.org/x/sys\n\ngo 1.26\n",
		"unix/mmap.go": mapperSource,
	})
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/mapped\n\ngo 1.26\n\nrequire golang.org/x/sys v0.999.0\n",
		"lib.go": "package mapped\n\nimport \"golang.org/x/sys/unix\"\n\nfunc Roundtrip() error {\n\tb, err := unix.Mmap(4096)\n\tif err != nil {\n\t\treturn err\n\t}\n\treturn unix.Munmap(b)\n}\n",
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
	processFactCache.Reset()
	ctx := context.Background()
	subject := Subject{Package: "example.com/mapped", Symbol: "Roundtrip"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(ctx, []Subject{subject}, dir)
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
		t.Fatalf("unaudited-version verdict = %+v, want the downgrade naming the mapper - no version inherits the audit", verdict)
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
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	processFactCache.Reset()
	ctx := context.Background()
	subject := Subject{Package: "example.com/mapped", Symbol: "Roundtrip"}
	engine, err := newEngine(withDir(dir), withSingleSubjectExecution())
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(ctx, []Subject{subject}, dir)
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
	if testing.Short() {
		t.Skip("populates a module cache and runs the engine over a temporary module")
	}
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

	processFactCache.Reset()
	clean := runScan(t, DynamicStateStrategy+"|memo-clean|cfg", host(t, "v3.0.1"), "example.com/memohost")
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("unattested structMap-shaped cache downgraded the subject: %q - the memoization discharge needs no attestation", reason)
	}

	processFactCache.Reset()
	ghosted := runScan(t, DynamicStateStrategy+"|memo-ghost|cfg", host(t, "v3.0.2"), "example.com/memohost")
	if reason := ghosted.downgradeReason[subject]; !strings.Contains(reason, "gopkg.in/yaml.v3.Ghost is mutated") {
		t.Fatalf("ghost verdict reason = %q, want the downgrade naming Ghost - the discharge covers exactly the audited variable", reason)
	}

	// The audit is a property of the audited versions' source: an
	// unaudited version with the identical shape refuses fail-closed
	// until its source is audited.
	processFactCache.Reset()
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
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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
	processFactCache.Reset()
	scan := runScan(t, DynamicStateStrategy+"|memo-local|cfg", dir, "example.com/memohost")
	subject := Subject{Package: "example.com/memohost", Symbol: "Use"}
	if reason := scan.downgradeReason[subject]; !strings.Contains(reason, "gopkg.in/yaml.v3.structMap is mutated") {
		t.Fatalf("mutable-local checkout reason = %q, want the downgrade naming structMap - the audit covers only the version-pinned line", reason)
	}
	// The reason contract at the boundary's other side: a
	// mutable-local culprit names the restructure and the
	// single-subject directive — and NEVER the vouch, whose boundary
	// is exactly the inverse (code the caller can edit is fixed, not
	// vouched) (REQ-closure-shared-dynamic-state-reason).
	if reason := scan.downgradeReason[subject]; !strings.Contains(reason, "//gofresh:single-subject") ||
		!strings.Contains(reason, "restructuring") || strings.Contains(reason, "caller vouch") {
		t.Fatalf("mutable-local checkout reason = %q, want the directive-and-restructure channel and no vouch spelling", reason)
	}
}

// The //gofresh:single-subject directive confers nothing on a
// dependency's variable even under the attestation: the directive
// covers exactly the code its author edits and reviews — the inverse of
// the vouch boundary (REQ-closure-shared-dynamic-state).
func TestSingleSubjectDirectiveConfersNothingOnDependency(t *testing.T) {
	if testing.Short() {
		t.Skip("populates a module cache and runs the engine over a temporary module")
	}
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

	processFactCache.Reset()
	hasher, err := closureNewAtEnv(context.Background(), dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	scan, _, _, err := scanViewSubjects(context.Background(), hasher, attestedScope(DynamicStateStrategy+"|dep-directive|cfg"), nil, 0, "example.com/dirhost")
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/dirhost", Symbol: "Use"}
	if reason := scan.downgradeReason[subject]; !strings.Contains(reason, "example.com/depdir.Hook is mutated") {
		t.Fatalf("attested dep-directive reason = %q, want the downgrade naming Hook - a dependency's directive confers nothing", reason)
	}
}

// A completed observation never substitutes for the shared-dynamic-state
// downgrade: process-shared state sits outside every observation
// bracket, so an OBSERVABLE downgraded subject still refuses on the
// observed check surface - unvouched on the current tree, and equally
// for a record captured vouched-valid once the vouch is withdrawn
// (REQ-purity-observation-separation, REQ-closure-shared-dynamic-state,
// REQ-vouch-recorded).
func TestObservedEvidenceNeverSuppressesSharedDynamicState(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	// Poisons the in-process fact cache between two views: the scan memo
	// would serve the first view's outputs whole (a production key never
	// holds a moved fact), so the derivation is exercised directly.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeSemverDepModule(t)
	const ghost = "golang.org/x/mod/semver.Ghost"
	subject := Subject{Package: "example.com/semverdep", Symbol: "TestValid"}
	processFactCache.Reset()
	ctx := context.Background()

	withViewTestHooks(viewTestHookSet{scanMemoOff: true}, func() {
		warm, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := warm.newView(ctx, []Subject{subject}, dir); err != nil {
			t.Fatal(err)
		}
		var hit bool
		processFactCache.Range(func(k string, fact dynamicStateFact) bool {
			if strings.HasSuffix(k, "\x00golang.org/x/mod/semver") {
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

		observe := func(e *engine) (*Snapshot, Fingerprint) {
			t.Helper()
			producer, err := e.newView(ctx, []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint, err := producer.captureObserved(ctx, subject)
			if err != nil {
				t.Fatal(err)
			}
			// The fixture must be genuinely observable, or the test refuses
			// through the ordinary path and never exercises the bypass.
			if !fingerprint.ObservationProof.Observable {
				t.Fatalf("fixture not observable: %+v", fingerprint.ObservationProof)
			}
			observation, err := riFromTestLog(nil, dir, dir, runtimeinput.WithCompletedProcess("semver test"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
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
		plain, err := newEngine(withDir(dir))
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
		vouched, err := newEngine(withDir(dir), withDynamicStateVouches(ghost))
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
		withdrawn, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		current, err := withdrawn.newView(ctx, []Subject{subject}, dir)
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
	})
}

// Two pinned packages whose facts declare the same vouched key (the
// persisted-fact channel) each record their own discharge: a subject
// reaching only the later-walked package still carries the acceptance
// (REQ-vouch-recorded).
func TestVouchDischargeRecordsPerOwningPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("populates a module cache and runs the engine over a temporary module")
	}
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
	processFactCache.Reset()
	const scope = DynamicStateStrategy + "|two-deps-toolchain|cfg"
	pkgs := []string{"example.com/twodeps/a", "example.com/twodeps/b"}
	subjectA := Subject{Package: pkgs[0], Symbol: "Valid"}
	subjectB := Subject{Package: pkgs[1], Symbol: "Run"}

	clean := runScan(t, scope, dir, pkgs...)
	if r := clean.downgradeReason[subjectA] + clean.downgradeReason[subjectB]; r != "" {
		t.Fatalf("baseline downgraded: %q", r)
	}
	var poisoned int
	processFactCache.Range(func(key string, fact dynamicStateFact) bool {
		if strings.HasSuffix(key, "\x00golang.org/x/mod/semver") || strings.HasSuffix(key, "\x00golang.org/x/sync/errgroup") {
			fact.Declares = append(fact.Declares, shared)
			fact.Mutates = append(fact.Mutates, shared)
			processFactCache.Store(key, fact)
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
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	// Poisons the in-process fact cache between two views: the scan memo
	// would serve the first view's outputs whole (a production key never
	// holds a moved fact), so the derivation is exercised directly.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const ghost = "golang.org/x/sync/errgroup.Ghost"
	subject := Subject{Package: "example.com/pinned", Symbol: "TestRun"}
	processFactCache.Reset()
	ctx := context.Background()

	withViewTestHooks(viewTestHookSet{scanMemoOff: true}, func() {
		warm, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := warm.newView(ctx, []Subject{subject}, dir); err != nil {
			t.Fatal(err)
		}
		var hit bool
		processFactCache.Range(func(k string, fact dynamicStateFact) bool {
			if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
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

		vouched, err := newEngine(withDir(dir), withDynamicStateVouches(ghost))
		if err != nil {
			t.Fatal(err)
		}
		producer, err := vouched.newView(ctx, []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := producer.captureObserved(ctx, subject)
		if err != nil {
			t.Fatal(err)
		}
		observation, err := riFromTestLog(nil, dir, dir, runtimeinput.WithCompletedProcess("pinned test"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
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

		withdrawn, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		current, err := withdrawn.newView(ctx, []Subject{subject}, dir)
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
	})
}

// Mutable-local facts derive fresh on every scan: an edit introducing a
// post-init mutation of a dependency's dynamic-capable global downgrades the
// subject on the very next scan in the same process — no cache layer may hold
// a mutable-local derivation (REQ-closure-mutable-local,
// REQ-closure-dynamic-state-memo).
func TestDynamicStateLocalFactsDeriveFreshEachScan(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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

//gofresh:pure
func TestChainHooksArmOnlyDuringExplain(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	// The normal analysis path constructs no chains: a view derivation
	// over a refusing culprit leaves the explain hooks unarmed, and the
	// on-demand re-derivation disarms them on return
	// (REQ-explain-passive).
	files := map[string]string{
		"go.mod":     "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc gen() map[string]handler {\n\tc := &counter{}\n\treturn map[string]handler{\"k\": c.Next}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
	}
	dir := writeModuleTree(t, files)
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{{Package: "example.com/explain/reg", Symbol: "Count"}}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Normal view derivation computes dynamic-state facts via FactOf (nil hooks),
	// recording only the refusal summary without constructing a Chain.
	cl := view.facts.closure(Subject{Package: "example.com/explain/reg", Symbol: "Count"})
	if !cl.Unverifiable || cl.Culprit.Package != "example.com/explain/reg" || cl.Culprit.Symbol != "Registry" {
		t.Fatalf("unexpected closure fact from normal view derivation: %+v", cl)
	}
	chain, err := view.ExplainDynamicState(context.Background(), "example.com/explain/reg", "Registry")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.Links) == 0 {
		t.Fatal("on-demand ExplainDynamicState returned empty chain for refusing culprit")
	}
}

// A chain is the current derivation: explain re-loads at the ask and
// runs no drift check, so a chain asked after an edit describes the
// edited tree, with no refusal, even though the verdict it explains was
// captured before the edit (REQ-explain-passive).
//
//gofresh:pure
func TestExplainStraddlesALaterEdit(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	before := "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc gen() map[string]handler {\n\tc := &counter{}\n\treturn map[string]handler{\"k\": c.Next}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n"
	dir := writeModuleTree(t, map[string]string{
		"go.mod":     "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": before,
	})
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{{Package: "example.com/explain/reg", Symbol: "Count"}}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Before the edit the registry is a culprit with a chain.
	if chain, err := view.ExplainDynamicState(context.Background(), "example.com/explain/reg", "Registry"); err != nil || len(chain.Links) == 0 {
		t.Fatalf("chain before the edit = %+v, %v; want the culprit's chain", chain, err)
	}
	// The edit after the verdict: the registry becomes an inert map
	// literal, so the culprit's chain over the edited tree is empty.
	after := strings.Replace(before, "var Registry = gen()", "var Registry = map[string]handler{}", 1)
	if after == before {
		t.Fatal("fixture edit did not apply")
	}
	if err := os.WriteFile(filepath.Join(dir, "reg", "reg.go"), []byte(after), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after the edit = %v, want ErrViewChanged (the edit is real drift)", err)
	}
	chain, err := view.ExplainDynamicState(context.Background(), "example.com/explain/reg", "Registry")
	if err != nil {
		t.Fatalf("explain after the edit = %v, want a chain over the edited tree with no refusal", err)
	}
	if len(chain.Links) != 0 || chain.Arm != "" {
		t.Fatalf("chain after the edit = %+v, want the edited tree's empty chain, not the captured verdict's", chain)
	}
}

// The view tier gives the same openness answer as the closure tier
// (REQ-closure-analysis's parameterized-subject arm): a constraint-
// bounded generic analyzes closed — it produces a usable observed
// disposition — while an unbounded zero-parameter generic reads open on
// the type-parameter list itself, which a params-only walk misses, and
// refuses open-world.
func TestViewTierGenericOpennessMatchesConstraints(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeBoundedViewFixture(t)
	const pkg = "example.com/boundedview"
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	bounded := Subject{Package: pkg, Symbol: "Sum"}
	unbounded := Subject{Package: pkg, Symbol: "Value"}
	view, err := engine.newView(context.Background(), []Subject{bounded, unbounded}, dir)
	if err != nil {
		t.Fatal(err)
	}
	boundedPrint, err := view.captureObserved(context.Background(), bounded)
	if err != nil {
		t.Fatal(err)
	}
	if !boundedPrint.ObservationProof.Observable || strings.Contains(boundedPrint.ObservationProof.Reason, "caller-supplied dynamic") {
		t.Fatalf("bounded generic read open at the view tier: %+v", boundedPrint.ObservationProof)
	}
	verdict, err := view.CheckObserved(context.Background(), boundedPrint, bounded)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("bounded generic verdict = %+v, want valid", verdict)
	}
	unboundedPrint, err := view.captureObserved(context.Background(), unbounded)
	if err != nil {
		t.Fatal(err)
	}
	unboundedVerdict, err := view.CheckObserved(context.Background(), unboundedPrint, unbounded)
	if err != nil {
		t.Fatal(err)
	}
	if unboundedVerdict.Status != Unverifiable {
		t.Fatalf("zero-parameter any-generic verdict = %+v, want unverifiable (open on the type-parameter list)", unboundedVerdict)
	}
}

// Init functions are unaddressable by name, so subjects carry the
// declaration ledger's positional identity: init#<file>#<ordinal>,
// 0-based within the file in declaration order. Each init declaration
// is its own subject - capture works, the fingerprint moves when
// anything in the subject's closure moves, and a change outside every
// init's reach and outside the subject's own reach leaves it valid.
func TestInitSubjectsCapturePositionally(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	writeInitFixture(t, dir, map[string]string{
		"go.mod": "module example.com/initfix\n\ngo 1.26\n",
		"a.go": `package initfix

var registry []string

func wireA() { registry = append(registry, "a") }

func init() { wireA() }

func init() { registry = append(registry, "second") }
`,
		"other/other.go": `package other

func Unwired(x int) int {
	if x > 10 {
		return x - 1
	}
	return x
}
`,
		"a_test.go": `package initfix

import "testing"

func TestRegistry(t *testing.T) {
	if len(registry) == 0 {
		t.Fatal("registry empty")
	}
}
`,
	})
	ctx := context.Background()
	first, second := Subject{Package: "example.com/initfix", Symbol: "init#a.go#0"}, Subject{Package: "example.com/initfix", Symbol: "init#a.go#1"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(ctx, []Subject{first, second}, dir)
	if err != nil {
		t.Fatal(err)
	}
	firstPrint, err := view.Capture(ctx, first)
	if err != nil {
		t.Fatalf("first init capture: %v", err)
	}
	secondPrint, err := view.Capture(ctx, second)
	if err != nil {
		t.Fatalf("second init capture: %v", err)
	}
	if firstPrint.MaximalClosure == "" || secondPrint.MaximalClosure == "" {
		t.Fatalf("init closures empty: %q %q", firstPrint.MaximalClosure, secondPrint.MaximalClosure)
	}

	// A change outside the subjects' closure entirely - an unimported
	// sibling package. (The home package's core is package-granular, so
	// the outside edit must live outside the package.) The init subject
	// stays put.
	writeInitFixture(t, dir, map[string]string{"other/other.go": `package other

func Unwired(x int) int {
	if x > 10 {
		return x - 2
	}
	return x
}
`})
	engine2, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view2, err := engine2.newView(ctx, []Subject{first, second}, dir)
	if err != nil {
		t.Fatal(err)
	}
	firstAfterUnrelated, err := view2.Capture(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if firstAfterUnrelated.MaximalClosure != firstPrint.MaximalClosure {
		t.Fatalf("init closure moved on an unreachable edit: %q -> %q", firstPrint.MaximalClosure, firstAfterUnrelated.MaximalClosure)
	}

	// A change inside the first init's transitive reach moves it.
	writeInitFixture(t, dir, map[string]string{"a.go": `package initfix

var registry []string

func wireA() { registry = append(registry, "a", "wired") }

func init() { wireA() }

func init() { registry = append(registry, "second") }
`})
	engine3, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view3, err := engine3.newView(ctx, []Subject{first, second}, dir)
	if err != nil {
		t.Fatal(err)
	}
	firstAfterWireEdit, err := view3.Capture(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if firstAfterWireEdit.MaximalClosure == firstPrint.MaximalClosure {
		t.Fatal("init closure did not move when its wiring changed")
	}
}

// A positional init subject that names no declaration - ordinal past
// the file's inits, or a file with none - refuses at view construction
// with the named subject, exactly like any unknown symbol.
func TestInitSubjectUnknownOrdinalRefuses(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	writeInitFixture(t, dir, map[string]string{
		"go.mod": "module example.com/initmiss\n\ngo 1.26\n",
		"a.go":   "package initmiss\n\nfunc init() {}\n",
		"a_test.go": `package initmiss

import "testing"

func TestNothing(t *testing.T) {}
`,
	})
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	missing := Subject{Package: "example.com/initmiss", Symbol: "init#a.go#1"}
	if _, err := engine.newView(context.Background(), []Subject{missing}, dir); err == nil || !strings.Contains(err.Error(), "init#a.go#1") {
		t.Fatalf("unknown init ordinal view = %v, want a refusal naming the subject", err)
	}
}

// The positional identity is file-scoped: an init added in another
// file neither shifts an existing subject's identity nor makes it
// unresolvable. (Its closure moves - package initialization is in
// every subject's closure - but the key still names the same
// declaration and re-capture succeeds.)
func TestInitSubjectIdentityStableAcrossOtherFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.com/initstable\n\ngo 1.26\n",
		"a.go":   "package initstable\n\nvar n int\n\nfunc init() { n++ }\n",
		"a_test.go": `package initstable

import "testing"

func TestN(t *testing.T) {
	if n == 0 {
		t.Fatal("n zero")
	}
}
`,
	}
	writeInitFixture(t, dir, files)
	ctx := context.Background()
	subject := Subject{Package: "example.com/initstable", Symbol: "init#a.go#0"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.Capture(ctx, subject); err != nil {
		t.Fatal(err)
	}
	writeInitFixture(t, dir, map[string]string{"aa.go": "package initstable\n\nfunc init() { n += 2 }\n"})
	engine2, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	// The new file's own init starts at ordinal 0 - the counter is
	// per-file, never package-wide.
	added := Subject{Package: "example.com/initstable", Symbol: "init#aa.go#0"}
	view2, err := engine2.newView(ctx, []Subject{subject, added}, dir)
	if err != nil {
		t.Fatalf("init subjects unresolvable after another file gained an init: %v", err)
	}
	if _, err := view2.Capture(ctx, subject); err != nil {
		t.Fatalf("existing init subject failed capture after another file gained an init: %v", err)
	}
	if _, err := view2.Capture(ctx, added); err != nil {
		t.Fatalf("added file's first init failed capture under its own 0-based ordinal: %v", err)
	}
}

// A method named init under a receiver the naming grammar cannot reduce
// (the parenthesized form) is still a method, never an init
// declaration: it must not skew a sibling init's ordinal. The real
// init keeps ordinal 0; the ordinal the skew would have produced does
// not exist.
func TestInitOrdinalIgnoresUnnameableReceiverMethod(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	writeInitFixture(t, dir, map[string]string{
		"go.mod": "module example.com/initrecv\n\ngo 1.26\n",
		"a.go": `package initrecv

type T struct{}

var n int

func ((T)) init() {}

func init() { n++ }
`,
		"a_test.go": `package initrecv

import "testing"

func TestN(t *testing.T) {
	if n == 0 {
		t.Fatal("n zero")
	}
}
`,
	})
	ctx := context.Background()
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	real := Subject{Package: "example.com/initrecv", Symbol: "init#a.go#0"}
	view, err := engine.newView(ctx, []Subject{real}, dir)
	if err != nil {
		t.Fatalf("real init not addressable at ordinal 0: %v", err)
	}
	if _, err := view.Capture(ctx, real); err != nil {
		t.Fatal(err)
	}
	skewed := Subject{Package: "example.com/initrecv", Symbol: "init#a.go#1"}
	if _, err := engine.newView(ctx, []Subject{skewed}, dir); err == nil {
		t.Fatal("ordinal 1 resolved: the method skewed the init count")
	}
}

func TestViewBaseFactsKeepMaskedEffects(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over a fixture with independent simultaneous blockers")
	}
	dir := writeModuleTree(t, map[string]string{
		"go.mod": "module example.com/base\n\ngo 1.26\n",
		"base.go": `package base
import ("os"; "net")
var Hook = func() {}
func Rebind() { Hook = func() {} }
//gofresh:external
func F(callback func()) { callback(); Hook(); _ = os.Getenv("INPUT"); _, _ = net.Dial("tcp", "") }
`,
	})
	e, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	s := Subject{Package: "example.com/base", Symbol: "F"}
	v, err := e.newView(t.Context(), []Subject{s}, dir)
	if err != nil {
		t.Fatal(err)
	}
	f := v.facts.maximal[s]
	if !f.external || f.openWorld == nil || f.sharedState == nil {
		t.Fatalf("consumer-tier obligations were overwritten: %+v", f)
	}
	env, network := false, false
	for _, effect := range f.source.Effects {
		env = env || effect.Package == "os" && effect.Symbol == "Getenv"
		network = network || effect.Package == "net" && effect.Symbol == "Dial"
	}
	if !env || !network {
		t.Fatalf("masked source obligations lost: %+v", f.source.Effects)
	}
	fp, err := v.Capture(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := v.Check(t.Context(), fp, s)
	if err != nil || verdict.Status != Unverifiable || verdict.Ground.Cause.Kind != ExternalDirectiveCause {
		t.Fatalf("ordinary external projection changed: %+v, %v", verdict, err)
	}
	if err := v.Validate(t.Context()); err != nil {
		t.Fatalf("unchanged complete base did not close: %v", err)
	}
}

// The //gofresh:single-subject variable directive discharges a
// subject-own variable's marks only with both legs present — the
// author's in-source directive and the caller's single-subject
// attestation — and records the load-bearing discharge on the
// subject's evidence; either leg alone confers nothing
// (REQ-closure-shared-dynamic-state, REQ-vouch-recorded).
func TestSingleSubjectDirectiveDischarges(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	// The memo-served arm below reads this test's own cache home,
	// never the user's store.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	// The arming call is rooted in the subject: the directive's
	// remaining role after the reachability scoping is exactly
	// rooted-but-subject-own state (an unrooted armer discharges by
	// reachability with no directive at all).
	directed := "package view\n\n//gofresh:single-subject\nvar frameAccounting func(int)\n\nfunc Arm(f func(int)) { frameAccounting = f }\n\nfunc F() bool {\n\tArm(func(int) {})\n\treturn frameAccounting == nil\n}\n"
	undirected := "package view\n\nvar frameAccounting func(int)\n\nfunc Arm(f func(int)) { frameAccounting = f }\n\nfunc F() bool {\n\tArm(func(int) {})\n\treturn frameAccounting == nil\n}\n"
	blockDirected := "package view\n\nvar (\n\t//gofresh:single-subject\n\tframeAccounting func(int)\n)\n\nfunc Arm(f func(int)) { frameAccounting = f }\n\nfunc F() bool {\n\tArm(func(int) {})\n\treturn frameAccounting == nil\n}\n"
	ctx := context.Background()
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	capture := func(t *testing.T, source string, opts ...option) (Fingerprint, Verdict) {
		t.Helper()
		dir := writeViewModule(t, source)
		engine, err := newEngine(append([]option{withDir(dir)}, opts...)...)
		if err != nil {
			t.Fatal(err)
		}
		view, err := engine.newView(ctx, []Subject{subject}, dir)
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
		return fingerprint, verdict
	}

	fingerprint, verdict := capture(t, directed, withSingleSubjectExecution())
	if verdict.Status != Valid {
		t.Fatalf("directed attested verdict = %+v, want Valid", verdict)
	}
	if fingerprint.SingleSubjectDischarges != "example.com/view.frameAccounting" {
		t.Fatalf("directed attested evidence = %q, want the discharged variable named canonically", fingerprint.SingleSubjectDischarges)
	}

	blockFP, blockVerdict := capture(t, blockDirected, withSingleSubjectExecution())
	if blockVerdict.Status != Valid || blockFP.SingleSubjectDischarges != "example.com/view.frameAccounting" {
		t.Fatalf("block-form directive: verdict = %+v evidence = %q, want Valid with the discharge recorded", blockVerdict, blockFP.SingleSubjectDischarges)
	}

	bare, bareVerdict := capture(t, undirected, withSingleSubjectExecution())
	if bareVerdict.Status != Unverifiable || !strings.Contains(bareVerdict.Reason, "example.com/view.frameAccounting is mutated") {
		t.Fatalf("attestation-only verdict = %+v, want the downgrade - the attestation alone confers nothing", bareVerdict)
	}
	if bare.SingleSubjectDischarges != "" {
		t.Fatalf("attestation-only evidence recorded %q, want nothing", bare.SingleSubjectDischarges)
	}

	unattested, unattestedVerdict := capture(t, directed)
	if unattestedVerdict.Status != Unverifiable || !strings.Contains(unattestedVerdict.Reason, "example.com/view.frameAccounting is mutated") {
		t.Fatalf("directive-only verdict = %+v, want the downgrade - the directive alone confers nothing", unattestedVerdict)
	}
	if unattested.SingleSubjectDischarges != "" {
		t.Fatalf("directive-only evidence recorded %q, want nothing", unattested.SingleSubjectDischarges)
	}
	// The directive-only reason still names the attestation: an
	// unattested consumer's own half is exactly that.
	if !strings.Contains(unattestedVerdict.Reason, "or by the //gofresh:single-subject directive on the declaration under the caller's single-subject attestation") {
		t.Fatalf("directive-only reason = %q, want the two-leg channel", unattestedVerdict.Reason)
	}
	// The directive met under the package-process attestation, which
	// does not back it, is named as present and unbacked, the
	// restructure the one remedy left — never the single-subject
	// attestation that model forbids
	// (REQ-closure-shared-dynamic-state-reason).
	fp, verdict := capture(t, directed, withPackageProcessExecution())
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.frameAccounting is mutated") {
		t.Fatalf("package-process directed verdict = %+v, want the downgrade", verdict)
	}
	if !strings.Contains(verdict.Reason, "//gofresh:single-subject directive is backed by no single-subject attestation here; dischargeable by restructuring the state") || strings.Contains(verdict.Reason, "under the caller's single-subject attestation") {
		t.Fatalf("package-process directed reason = %q, want the directive named unbacked with the restructure alone", verdict.Reason)
	}
	if fp.SingleSubjectDischarges != "" || fp.PackageProcessDischarges != "" {
		t.Fatalf("package-process directed evidence recorded %q/%q, want nothing", fp.SingleSubjectDischarges, fp.PackageProcessDischarges)
	}
	// An undirected variable under the package-process model is pointed
	// at the restructure alone, the directive named as single-subject-
	// only — never a remedy that would only move it to the unbacked
	// text.
	_, bareVerdict = capture(t, undirected, withPackageProcessExecution())
	if !strings.Contains(bareVerdict.Reason, "dischargeable by restructuring the state; the //gofresh:single-subject directive discharges only under the caller's single-subject attestation, which the package-process model does not give") || strings.Contains(bareVerdict.Reason, "or by the //gofresh:single-subject directive") {
		t.Fatalf("package-process undirected reason = %q, want the restructure alone with the directive named single-subject-only", bareVerdict.Reason)
	}
	// Both attestations set: the single-subject judgment takes
	// precedence and the directive discharges — no unbacked text is
	// composed, the discharge is recorded.
	bothFP, bothVerdict := capture(t, directed, withSingleSubjectExecution(), withPackageProcessExecution())
	if bothVerdict.Status != Valid || bothFP.SingleSubjectDischarges != "example.com/view.frameAccounting" {
		t.Fatalf("both attestations: verdict = %+v evidence = %q, want Valid with the single-subject discharge recorded", bothVerdict, bothFP.SingleSubjectDischarges)
	}
	// The text is scan output served from the memo: a second capture
	// under the same cache home serves the scan entry — counted through
	// the progress face — and carries the same text (the entry's
	// version keys it).
	servedScans := 0
	_, served := capture(t, directed, withPackageProcessExecution(), withProgress(func(p Progress) {
		if p.Phase == "served" && p.Served == "scan" {
			servedScans += p.Index
		}
	}))
	if servedScans == 0 {
		t.Fatal("the second capture served no scan entry from the memo")
	}
	if served.Reason != verdict.Reason {
		t.Fatalf("memo-served reason = %q, want the computed %q", served.Reason, verdict.Reason)
	}
}

// The generated-proto descriptor cluster: variables declared in a
// protoc-gen-go generated file discharge under the single-subject
// attestation with the audited pinned protobuf runtime (header +
// attestation, the directive's two-leg model), the discharge on
// evidence; without the attestation, with an unaudited runtime
// version, under a sibling generator's header (protoc-gen-gogo — an
// unaudited runtime), and for hand-written sibling variables, every
// mark stands (REQ-closure-shared-dynamic-state, REQ-vouch-recorded).
func TestGeneratedProtoClusterDischarges(t *testing.T) {
	if testing.Short() {
		t.Skip("populates a module cache and runs the engine over a temporary module")
	}
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
	stub := map[string]string{
		"go.mod":                    "module google.golang.org/protobuf\n\ngo 1.26\n",
		"runtime/protoimpl/impl.go": "package protoimpl\n\ntype TypeBuilder struct{ N int }\n",
	}
	writeFileProxyModule(t, proxy, "google.golang.org/protobuf", "v1.36.11", stub)
	writeFileProxyModule(t, proxy, "google.golang.org/protobuf", "v1.36.12", stub)
	writeFileProxyModule(t, proxy, "google.golang.org/grpc", "v1.82.1", map[string]string{
		"go.mod":         "module google.golang.org/grpc\n\ngo 1.26\n",
		"codes/codes.go": "package codes\n\ntype Code uint32\n",
	})
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")

	genFile := func(header string) string {
		return header + "\n// versions:\n// \tprotoc-gen-go v1.36.11\n\npackage view\n\nimport _ \"google.golang.org/protobuf/runtime/protoimpl\"\n\nvar File_x_proto any\n\nvar file_x_proto_msgTypes = []func(){func() {}}\n\nfunc file_x_proto_init() {\n\tif File_x_proto != nil {\n\t\treturn\n\t}\n\tFile_x_proto = struct{}{}\n}\n\nfunc init() { file_x_proto_init() }\n"
	}
	ctx := context.Background()
	capture := func(t *testing.T, version, header, symbol string, opts ...option) (Fingerprint, Verdict) {
		t.Helper()
		dir := writeModuleTree(t, map[string]string{
			"go.mod":    "module example.com/view\n\ngo 1.26\n\nrequire google.golang.org/protobuf " + version + "\n",
			"gen.pb.go": genFile(header),
			"view.go":   "package view\n\nfunc F() *func() { return &file_x_proto_msgTypes[0] }\n\nvar handHooks = map[string]func(){}\n\nfunc F2() int {\n\thandHooks[\"k\"] = func() {}\n\treturn len(handHooks)\n}\n",
		})
		tidy := exec.Command("go", "mod", "tidy")
		tidy.Dir = dir
		tidy.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
		if out, err := tidy.CombinedOutput(); err != nil {
			t.Fatalf("go mod tidy: %v\n%s", err, out)
		}
		processFactCache.Reset()
		subject := Subject{Package: "example.com/view", Symbol: symbol}
		engine, err := newEngine(append([]option{withDir(dir)}, opts...)...)
		if err != nil {
			t.Fatal(err)
		}
		view, err := engine.newView(ctx, []Subject{subject}, dir)
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
		return fingerprint, verdict
	}
	const goHeader = "// Code generated by protoc-gen-go. DO NOT EDIT."

	fingerprint, verdict := capture(t, "v1.36.11", goHeader, "F", withSingleSubjectExecution())
	if verdict.Status != Valid {
		t.Fatalf("attested verdict = %+v, want Valid - the generated cluster discharges under the audited runtime", verdict)
	}
	if !strings.Contains(fingerprint.SingleSubjectDischarges, "example.com/view.file_x_proto_msgTypes") {
		t.Fatalf("evidence = %q, want the discharged generated variable recorded", fingerprint.SingleSubjectDischarges)
	}

	_, unattested := capture(t, "v1.36.11", goHeader, "F")
	if unattested.Status != Unverifiable || !strings.Contains(unattested.Reason, "example.com/view.file_x_proto_msgTypes is mutated") {
		t.Fatalf("unattested verdict = %+v, want the downgrade - the header alone confers nothing", unattested)
	}

	_, unaudited := capture(t, "v1.36.12", goHeader, "F", withSingleSubjectExecution())
	if unaudited.Status != Unverifiable || !strings.Contains(unaudited.Reason, "example.com/view.file_x_proto_msgTypes is mutated") {
		t.Fatalf("unaudited-runtime verdict = %+v, want the downgrade - no version inherits the audit", unaudited)
	}

	_, gogo := capture(t, "v1.36.11", "// Code generated by protoc-gen-gogo. DO NOT EDIT.", "F", withSingleSubjectExecution())
	if gogo.Status != Unverifiable || !strings.Contains(gogo.Reason, "example.com/view.file_x_proto_msgTypes is mutated") {
		t.Fatalf("gogo-header verdict = %+v, want the downgrade - a sibling generator's header never matches", gogo)
	}

	// The second audited generator: a protoc-gen-go-grpc header
	// discharges under the audited pinned grpc runtime.
	grpcDir := writeModuleTree(t, map[string]string{
		"go.mod":         "module example.com/view\n\ngo 1.26\n\nrequire google.golang.org/grpc v1.82.1\n",
		"gen_grpc.pb.go": "// Code generated by protoc-gen-go-grpc. DO NOT EDIT.\n\npackage view\n\nimport _ \"google.golang.org/grpc/codes\"\n\nvar Svc_ServiceDesc = []func(){func() {}}\n",
		"view.go":        "package view\n\nfunc F() *func() { return &Svc_ServiceDesc[0] }\n",
	})
	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = grpcDir
	tidy.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Fatalf("go mod tidy: %v\n%s", err, out)
	}
	processFactCache.Reset()
	grpcSubject := Subject{Package: "example.com/view", Symbol: "F"}
	grpcEngine, err := newEngine(withDir(grpcDir), withSingleSubjectExecution())
	if err != nil {
		t.Fatal(err)
	}
	grpcView, err := grpcEngine.newView(ctx, []Subject{grpcSubject}, grpcDir)
	if err != nil {
		t.Fatal(err)
	}
	grpcFP, err := grpcView.Capture(ctx, grpcSubject)
	if err != nil {
		t.Fatal(err)
	}
	grpcVerdict, err := grpcView.Check(ctx, grpcFP, grpcSubject)
	if err != nil {
		t.Fatal(err)
	}
	if grpcVerdict.Status != Valid || !strings.Contains(grpcFP.SingleSubjectDischarges, "example.com/view.Svc_ServiceDesc") {
		t.Fatalf("go-grpc verdict = %+v evidence = %q, want Valid with the discharge recorded", grpcVerdict, grpcFP.SingleSubjectDischarges)
	}

	_, hand := capture(t, "v1.36.11", goHeader, "F2", withSingleSubjectExecution())
	if hand.Status != Unverifiable || !strings.Contains(hand.Reason, "example.com/view.handHooks is mutated") {
		t.Fatalf("hand-written verdict = %+v, want the downgrade - the discharge covers generated files only", hand)
	}
}

// A package with assembly sources stays downgraded through the closure
// tier's native-code and linkage dispositions - the mutation analysis
// needs no foreign-code rule of its own
// (REQ-closure-shared-dynamic-state).
func TestForeignCodePackageKeepsTypeLevelDowngrade(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nvar Hook = func() {}\n\nfunc F() { Hook() }\n")
	if err := os.WriteFile(filepath.Join(dir, "empty_amd64.s"), []byte("// nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("verdict = %+v, want the foreign-code downgrade", verdict)
	}
}

func TestWithEnvSelectsWorkspaceSource(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	fixture := writeWorkspaceEnvironmentFixture(t)
	t.Setenv("GOWORK", fixture.goWork)

	standalone, err := newEngine(withDir(fixture.consumer), withEnv(environmentWith(map[string]string{"GOWORK": "off"})...))
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := newEngine(withDir(fixture.consumer), withEnv(environmentWith(map[string]string{"GOWORK": fixture.goWork})...))
	if err != nil {
		t.Fatal(err)
	}
	viewUsesSource(t, standalone, fixture, fixture.standaloneFile, fixture.workspaceFile)
	viewUsesSource(t, workspace, fixture, fixture.workspaceFile, fixture.standaloneFile)
}

func TestEnginesWithDifferentEnvironmentsConstructViewsConcurrently(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	fixture := writeWorkspaceEnvironmentFixture(t)
	standalone, err := newEngine(withDir(fixture.consumer), withEnv(environmentWith(map[string]string{"GOWORK": "off"})...))
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := newEngine(withDir(fixture.consumer), withEnv(environmentWith(map[string]string{"GOWORK": fixture.goWork})...))
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		files []string
		err   error
	}
	results := make([]result, 2)
	engines := []*engine{standalone, workspace}
	var wait sync.WaitGroup
	for i, engine := range engines {
		wait.Add(1)
		go func() {
			defer wait.Done()
			view, err := engine.newView(context.Background(), []Subject{fixture.subject}, fixture.consumer)
			results[i].err = err
			if err == nil {
				results[i].files = view.SourceFiles()
			}
		}()
	}
	wait.Wait()
	for _, result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
	}
	if !slices.Contains(results[0].files, fixture.standaloneFile) || slices.Contains(results[0].files, fixture.workspaceFile) {
		t.Fatalf("standalone Engine files = %v", results[0].files)
	}
	if !slices.Contains(results[1].files, fixture.workspaceFile) || slices.Contains(results[1].files, fixture.standaloneFile) {
		t.Fatalf("workspace Engine files = %v", results[1].files)
	}
}

func TestWithEnvCopiesNormalizesAndRejectsAmbiguity(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	fixture := writeWorkspaceEnvironmentFixture(t)
	env := environmentWith(map[string]string{"GOWORK": "off"})
	option := withEnv(env...)
	for i := range env {
		if strings.HasPrefix(env[i], "GOWORK=") {
			env[i] = "GOWORK=" + fixture.goWork
		}
	}
	engine, err := newEngine(withDir(fixture.consumer), option)
	if err != nil {
		t.Fatal(err)
	}
	viewUsesSource(t, engine, fixture, fixture.standaloneFile, fixture.workspaceFile)

	reversed := environmentWith(map[string]string{"GOWORK": "off"})
	slices.Reverse(reversed)
	other, err := newEngine(withDir(fixture.consumer), withEnv(reversed...))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(engine.env, other.env) {
		t.Fatal("equivalent environments did not normalize deterministically")
	}

	for _, test := range []struct {
		name string
		env  []string
		want string
	}{
		{name: "missing equals", env: []string{"BROKEN"}, want: "malformed"},
		{name: "empty key", env: []string{"=value"}, want: "malformed"},
		{name: "NUL", env: []string{"KEY=value\x00tail"}, want: "NUL"},
		{name: "duplicate", env: []string{"KEY=first", "KEY=second"}, want: "duplicate key"},
		{name: "external package driver", env: environmentWith(map[string]string{"GOPACKAGESDRIVER": "custom-driver"}), want: "GOPACKAGESDRIVER"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newEngine(withEnv(test.env...)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("newEngine(withEnv(%q)) = %v, want %q error", test.env, err, test.want)
			}
		})
	}

}

func TestDefaultEnvironmentIsCapturedAtNew(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	fixture := writeWorkspaceEnvironmentFixture(t)
	t.Setenv("GOWORK", "off")
	standalone, err := newEngine(withDir(fixture.consumer))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", fixture.goWork)
	workspace, err := newEngine(withDir(fixture.consumer))
	if err != nil {
		t.Fatal(err)
	}
	viewUsesSource(t, standalone, fixture, fixture.standaloneFile, fixture.workspaceFile)
	viewUsesSource(t, workspace, fixture, fixture.workspaceFile, fixture.standaloneFile)
}

func TestWithEnvDoesNotSelectGoLauncherFromSuppliedPath(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	fixture := writeWorkspaceEnvironmentFixture(t)
	env := environmentWith(map[string]string{"GOWORK": "off", "PATH": filepath.Join(t.TempDir(), "missing")})
	engine, err := newEngine(withDir(fixture.consumer), withEnv(env...))
	if err != nil {
		t.Fatalf("host go launcher was not used: %v", err)
	}
	if _, err := engine.newView(context.Background(), []Subject{fixture.subject}, fixture.consumer); err != nil {
		t.Fatalf("view did not retain host go launcher: %v", err)
	}
}

func TestPackageDriverSafetyPinDoesNotChangeRuntimeEnvironment(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/driverenv\n\ngo 1.26.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package driverenv\n\nfunc F() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GOPACKAGESDRIVER=") {
			env = append(env, entry)
		}
	}
	engine, err := newEngine(withDir(dir), withEnv(env...))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/driverenv", Symbol: "F"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.FromTestLog([]byte("getenv GOPACKAGESDRIVER\n"), dir, dir, env, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("package-driver safety pin changed runtime environment: %+v", verdict)
	}
}

func TestPurityScanUsesSuppliedEnvironment(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/envpurity\n\ngo 1.26.4\n")
	write("default.go", "//go:build !special\n\npackage envpurity\n\nfunc F() {}\n")
	write("special.go", "//go:build special\n\npackage envpurity\n\n//gofresh:pure\nfunc F() {}\n")
	env := environmentWith(map[string]string{"GOFLAGS": "-tags=special", "GOWORK": "off"})
	scan, err := scanSubjectsInWithBuildFlagsEnv(context.Background(), dir, env, nil, "example.com/envpurity")
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/envpurity", Symbol: "F"}
	if !scan.known[subject] || !scan.directivePure(subject) {
		t.Fatalf("supplied GOFLAGS did not select pure declaration: known=%v pure=%v", scan.known[subject], scan.directivePure(subject))
	}
}

// writeSharedHelperFixture is the field shape: one directory whose
// in-package test file (package amb) and external test package (package
// amb_test) both declare mustHelper — legal Go, two distinct packages in
// one test binary sharing a top-level name.
func writeSharedHelperFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/amb\n\ngo 1.26\n",
		"lib.go": "package amb\n\nfunc Compute(x int) int { return x * 2 }\n",
		"internal_test.go": `package amb

import "testing"

func mustHelper(t *testing.T) int {
	t.Helper()
	return 21
}

func TestInternal(t *testing.T) {
	if Compute(mustHelper(t)) != 42 {
		t.Fatal("broken")
	}
}
`,
		"external_test.go": `package amb_test

import (
	"testing"

	"example.com/amb"
)

func mustHelper(t *testing.T) int {
	t.Helper()
	return 5
}

func TestExternal(t *testing.T) {
	if amb.Compute(mustHelper(t)) != 10 {
		t.Fatal("broken")
	}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A name duplicated between a package and its external test package is a
// subject-local collapse, not a package-wide refusal: the view builds,
// every unambiguous subject captures sound evidence untouched by the
// collision, and only a request for the collapsed name itself answers
// with refused capture — unverifiable evidence naming both declarations
// (REQ-purity-directive's refusal, scoped to the subject it is about).
func TestSharedTestHelperNameKeepsPackageMeasurable(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeSharedHelperFixture(t)
	const pkg = "example.com/amb"
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: pkg, Symbol: "Compute"},
		{Package: pkg, Symbol: "TestInternal"},
		{Package: pkg, Symbol: "TestExternal"},
	}
	view, err := engine.newView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatalf("shared helper name made the package unmeasurable: %v", err)
	}
	for _, subject := range subjects {
		fingerprint, err := view.captureObserved(context.Background(), subject)
		if err != nil {
			t.Fatalf("capture %s: %v", subject.Symbol, err)
		}
		if strings.Contains(fingerprint.ObservationProof.Reason, "ambiguous") {
			t.Fatalf("unambiguous subject %s degraded by a sibling collision: %+v", subject.Symbol, fingerprint.ObservationProof)
		}
	}
}

// Requesting the collapsed name itself is refused capture for exactly
// that subject: the view still builds, the evidence is unverifiable, and
// the reason names both declarations so the repair (rename one) is
// actionable without spelunking.
func TestAmbiguousSubjectItselfIsRefusedCaptureAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeSharedHelperFixture(t)
	const pkg = "example.com/amb"
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := Subject{Package: pkg, Symbol: "mustHelper"}
	view, err := engine.newView(context.Background(), []Subject{ambiguous, {Package: pkg, Symbol: "Compute"}}, dir)
	if err != nil {
		t.Fatalf("ambiguous subject request failed view construction: %v", err)
	}
	fingerprint, err := view.captureObserved(context.Background(), ambiguous)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if fingerprint.ObservationProof.Observable {
		t.Fatalf("collapsed identity captured usable evidence: %+v", fingerprint.ObservationProof)
	}
	// The degraded proof names the collision so the repair is actionable.
	reason := fingerprint.ObservationProof.Reason
	if !strings.Contains(reason, "ambiguous") {
		t.Fatalf("refused capture does not name the collision: %q", reason)
	}
	verdict, err := view.CheckObserved(context.Background(), fingerprint, ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "declared at both") ||
		!strings.Contains(verdict.Reason, "internal_test.go") || !strings.Contains(verdict.Reason, "external_test.go") {
		t.Fatalf("verdict does not name both declarations: %+v", verdict)
	}
	if verdict.Ground.Cause.Kind != AmbiguousSubjectCause {
		t.Fatalf("ambiguous identity origin was lost: %+v", verdict.Ground)
	}
	if fingerprint.PurityAssertion != "" {
		t.Fatalf("collapsed identity carries a purity attribution: %q", fingerprint.PurityAssertion)
	}
	sibling, err := view.captureObserved(context.Background(), Subject{Package: pkg, Symbol: "Compute"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sibling.ObservationProof.Reason, "ambiguous") {
		t.Fatalf("sibling subject degraded by the collision: %+v", sibling.ObservationProof)
	}
}

// A caller assertion confers nothing on a collapsed identity either:
// the assertion names one declarer taking responsibility, and the
// identity has two (REQ-purity-directive, REQ-purity-responsibility).
func TestAmbiguousSubjectCallerAssertionConfersNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeSharedHelperFixture(t)
	const pkg = "example.com/amb"
	engine, err := newEngine(withDir(dir), withAssumePure(func(Subject) bool { return true }))
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := Subject{Package: pkg, Symbol: "mustHelper"}
	view, err := engine.newView(context.Background(), []Subject{ambiguous}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.PurityAssertion != "" {
		t.Fatalf("caller assertion attributed purity to a collapsed identity: %q", fingerprint.PurityAssertion)
	}
}

// A directive on either colliding declaration confers nothing: purity for
// a collapsed identity would let one declaration vouch for the other
// (REQ-purity-directive, REQ-purity-responsibility).
func TestAmbiguousSubjectDirectiveConfersNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeSharedHelperFixture(t)
	internal := filepath.Join(dir, "internal_test.go")
	content, err := os.ReadFile(internal)
	if err != nil {
		t.Fatal(err)
	}
	directive := strings.Replace(string(content), "func mustHelper(t *testing.T) int {", "//gofresh:pure\nfunc mustHelper(t *testing.T) int {", 1)
	if err := os.WriteFile(internal, []byte(directive), 0o644); err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/amb"
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := Subject{Package: pkg, Symbol: "mustHelper"}
	view, err := engine.newView(context.Background(), []Subject{ambiguous}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.PurityAssertion != "" {
		t.Fatalf("directive on one colliding declaration attributed purity to the collapsed identity: %q", fingerprint.PurityAssertion)
	}

	// The public directive scan refuses the same attribution: the pure
	// predicate must never claim a collapsed identity.
	pred, err := scanPureDirectivesIn(dir, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if pred(ambiguous) {
		t.Fatal("public directive scan claimed purity for a collapsed identity")
	}
}

// An external directive on a colliding declaration is refused the same
// way: the collapsed identity's evidence names the ambiguity, never one
// declaration's externality (REQ-purity-directive's refusal scope).
func TestAmbiguousSubjectExternalDirectiveConfersNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeSharedHelperFixture(t)
	external := filepath.Join(dir, "external_test.go")
	content, err := os.ReadFile(external)
	if err != nil {
		t.Fatal(err)
	}
	directive := strings.Replace(string(content), "func mustHelper(t *testing.T) int {", "//gofresh:external\nfunc mustHelper(t *testing.T) int {", 1)
	if err := os.WriteFile(external, []byte(directive), 0o644); err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/amb"
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := Subject{Package: pkg, Symbol: "mustHelper"}
	view, err := engine.newView(context.Background(), []Subject{ambiguous}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), mustCapture(t, view, ambiguous), ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "ambiguous") {
		t.Fatalf("collapsed identity with an external twin = %+v, want the ambiguity named, not the directive", verdict)
	}
}

func mustCapture(t *testing.T, view *Snapshot, subject Subject) Fingerprint {
	t.Helper()
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

// A cut belongs to the immutable observation, including when a subset becomes
// an independently closing producer (REQ-fresh-producer-view, REQ-fresh-context).
func TestSiblingPreservesBudgetCutProvenance(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and cuts one reachability pass")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	const source = "package view\n\nimport \"example.com/cut/gen\"\n\nfunc F() int { return gen.Size() }\n\nfunc Property() { gen.Compile(\"k\") }\n"
	dir := writeModuleTree(t, map[string]string{
		"go.mod":       "module example.com/cut\n\ngo 1.26\n",
		"gen/gen.go":   "package gen\n\nvar memo = map[string]func(){}\n\nfunc Compile(name string) { memo[name] = func() {} }\n\nfunc Size() int { return len(memo) }\n",
		"view.go":      source,
		"pure/pure.go": "package pure\n\nfunc F() int { return 7 }\n",
		"fixture":      "stable",
	})
	const budget = 10 * time.Second
	passes := 0
	injected, discharged := 0, 0
	pending := false
	withViewTestHooks(viewTestHookSet{
		observe: func() { passes++ },
		analysisBound: func(ctx context.Context, requested time.Duration) (context.Context, context.CancelFunc) {
			if requested != budget {
				t.Fatalf("analysis budget = %s, want %s", requested, budget)
			}
			if passes == 1 && injected == 0 {
				injected++
				pending = true
				return context.WithDeadline(ctx, time.Now().Add(-time.Second))
			}
			return context.WithTimeout(ctx, requested)
		},
		beforeDischarge: func() {
			if pending {
				if passes != 1 {
					t.Fatalf("expired construction reached discharge in pass %d", passes)
				}
				discharged++
				pending = false
			}
		},
	}, func() {
		engine, err := newEngine(withDir(dir), withSingleSubjectExecution(), withAnalysisBudget(budget))
		if err != nil {
			t.Fatal(err)
		}
		cut := Subject{Package: "example.com/cut", Symbol: "F"}
		pure := Subject{Package: "example.com/cut/pure", Symbol: "F"}
		parent, err := engine.newView(context.Background(), []Subject{cut, pure}, dir)
		if err != nil {
			t.Fatal(err)
		}
		if passes != 2 || !parent.facts.cut[cut] || parent.facts.cut[pure] {
			t.Fatalf("construction premise: passes=%d cut=%v", passes, parent.facts.cut)
		}
		if err := parent.Validate(context.Background()); !errors.Is(err, ErrAnalysisUnavailable) || errors.Is(err, ErrViewChanged) {
			t.Fatalf("parent on unchanged tree: %v, want cut unavailability", err)
		}
		sibling := func(t *testing.T, from *Snapshot, subjects ...Subject) *Snapshot {
			t.Helper()
			before := passes
			v, err := from.Sibling(subjects)
			if err != nil {
				t.Fatal(err)
			}
			if passes != before {
				t.Fatal("subset selection performed an observation")
			}
			return v
		}
		assertCut := func(t *testing.T, v *Snapshot) {
			t.Helper()
			if err := v.Validate(context.Background()); !errors.Is(err, ErrAnalysisUnavailable) || errors.Is(err, ErrViewChanged) {
				t.Fatalf("sibling on unchanged tree: %v, want cut unavailability", err)
			}
		}
		attach := func(t *testing.T, v *Snapshot, fp Fingerprint) {
			t.Helper()
			observation, err := riFromTestLog([]byte("open fixture\n"), dir, dir,
				runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := v.AttachObservation(cut, fp, observation); err != nil {
				t.Fatal(err)
			}
		}
		t.Run("maximal and nested", func(t *testing.T) {
			first := sibling(t, parent, cut)
			if cl := first.facts.closure(cut); cl.Culprit != (closure.Subject{}) {
				t.Fatalf("cut closure retained unjudged culprit: %+v", cl.Culprit)
			}
			fp, err := first.Capture(t.Context(), cut)
			if err != nil {
				t.Fatal(err)
			}
			verdict, err := first.Check(t.Context(), fp, cut)
			if err != nil || verdict.Status != Unverifiable || verdict.Ground.Cause != (Cause{Kind: SharedDynamicStateCause, Condition: Unavailable}) {
				t.Fatalf("cut was reported as established dependence: %+v %v", verdict, err)
			}
			assertCut(t, first)
			assertCut(t, sibling(t, first, cut))
		})
		t.Run("unaffected subset", func(t *testing.T) {
			if err := sibling(t, parent, pure).Validate(context.Background()); err != nil {
				t.Fatalf("uncut subject borrowed another subject's cut: %v", err)
			}
		})
		for _, inherited := range []bool{false, true} {
			t.Run(fmt.Sprintf("observed inherited=%t", inherited), func(t *testing.T) {
				v := sibling(t, parent, cut)
				fp, err := v.captureObserved(context.Background(), cut)
				if err != nil {
					t.Fatal(err)
				}
				if fp.SingleSubjectDischarges != "" {
					t.Fatal("cut capture gained a discharge")
				}
				if inherited {
					v = sibling(t, v, cut)
				}
				attach(t, v, fp)
				assertCut(t, v)
			})
		}
		t.Run("cancellation", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := sibling(t, parent, cut).Validate(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled sibling: %v", err)
			}
		})
		t.Run("runtime movement", func(t *testing.T) {
			v := sibling(t, parent, cut)
			fp, err := v.captureObserved(context.Background(), cut)
			if err != nil {
				t.Fatal(err)
			}
			attach(t, v, fp)
			if err := os.WriteFile(filepath.Join(dir, "fixture"), []byte("moved"), 0o644); err != nil {
				t.Fatal(err)
			}
			err = v.Validate(context.Background())
			if !errors.Is(err, ErrViewChanged) || !strings.Contains(err.Error(), "runtime inputs") || errors.Is(err, ErrAnalysisUnavailable) {
				t.Fatalf("runtime drift behind a cut: %v", err)
			}
		})
		t.Run("source movement", func(t *testing.T) {
			v := sibling(t, parent, cut)
			if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte(strings.Replace(source, "return gen.Size()", "return gen.Size() + 1", 1)), 0o644); err != nil {
				t.Fatal(err)
			}
			err := v.Validate(context.Background())
			if !errors.Is(err, ErrViewChanged) || errors.Is(err, ErrAnalysisUnavailable) {
				t.Fatalf("source drift behind a cut: %v", err)
			}
		})
	})
	if injected != 1 || discharged != 1 {
		t.Errorf("construction cut: injected=%d discharged=%d, want one each", injected, discharged)
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
	if testing.Short() {
		t.Skip("populates a module cache and runs the engine over a temporary module")
	}
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
	processFactCache.Reset()

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
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
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

// Every capture path stamps the closure identity's derivation beside
// the hash, so a consumer keying a judgment to the identity can compare
// two records within one derivation (REQ-closure-identity-strategy).
func TestEveryCaptureStampsTheClosureStrategy(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := scanMemoModule(t)
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), scanMemoSubjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := view.Capture(context.Background(), scanMemoSubjects[0])
	if err != nil {
		t.Fatal(err)
	}
	if plain.ClosureStrategy != ClosureStrategy {
		t.Fatalf("Capture stamped closure strategy %q, want %q", plain.ClosureStrategy, ClosureStrategy)
	}
	batch, err := view.CaptureBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	observed, err := view.CaptureObservedBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for name, fps := range map[string]map[Subject]Fingerprint{"CaptureBatch": batch, "CaptureObservedBatch": observed} {
		if len(fps) != len(scanMemoSubjects) {
			t.Fatalf("%s returned %d fingerprints for %d subjects", name, len(fps), len(scanMemoSubjects))
		}
		for subject, fp := range fps {
			if fp.ClosureStrategy != ClosureStrategy {
				t.Fatalf("%s: %s stamped closure strategy %q, want %q", subject.Symbol, name, fp.ClosureStrategy, ClosureStrategy)
			}
		}
	}
}

const methodPkg = "github.com/greatliontech/gofresh/internal/closure/testdata/methodsubject"

// TestCaptureCheckRoundTrip pins the happy path end to end: a fingerprint captured
// for a pure subject is Valid when checked against the same tree, and the same
// fingerprint checked against a different subject's closure is stale. The subject is
// pure (reaches no external dependence) so the clean verdict is Valid, not
// Unverifiable.
func TestCaptureCheckRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	e, err := newEngine()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	subj := Subject{Package: methodPkg, Symbol: "Adder.Value"}
	fp, err := e.capture(context.Background(), subj, ".")
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	v, err := e.check(context.Background(), fp, subj, ".")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v.Status != Valid {
		t.Errorf("round-trip: got %s (%s), want valid", v.Status, v.Reason)
	}
	// The same recorded fingerprint checked against a different subject (Adder.Ptr
	// has a different closure) is stale on the closure guard.
	other := Subject{Package: methodPkg, Symbol: "Adder.Ptr"}
	v2, err := e.check(context.Background(), fp, other, ".")
	if err != nil {
		t.Fatalf("Check other: %v", err)
	}
	if v2.Status != Stale || v2.Reason != "closure" {
		t.Errorf("cross-subject: got {%s %q}, want {stale closure}", v2.Status, v2.Reason)
	}
	// A recorded manifest that cannot be re-evaluated is an unevaluable applicable
	// guard — Stale, never an error and never valid (REQ-guard-completeness).
	bad := fp
	bad.RuntimeInputs = "not a manifest"
	bad.RuntimeDigest = "D"
	v3, err := e.check(context.Background(), bad, subj, ".")
	if err != nil {
		t.Fatalf("Check malformed manifest: %v", err)
	}
	if v3.Status != Stale || v3.Reason != "runtimeinputs" {
		t.Errorf("malformed manifest: got {%s %q}, want {stale runtimeinputs}", v3.Status, v3.Reason)
	}
}

// TestBuildFlagsAffectVerdict pins that withBuildFlags threads into the buildconfig
// guard end to end: a fingerprint captured with no build flags is stale on
// buildconfig when checked by an engine that used one, so a build-invocation change
// is caught.
func TestBuildFlagsAffectVerdict(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	subj := Subject{Package: methodPkg, Symbol: "Adder.Value"}
	plain, err := newEngine()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fp, err := plain.capture(context.Background(), subj, ".") // captured with no build inputs
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	tagged, err := newEngine(withBuildFlags("-tags=integration"))
	if err != nil {
		t.Fatalf("New tagged: %v", err)
	}
	v, err := tagged.check(context.Background(), fp, subj, ".")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v.Status != Stale || v.Reason != "buildconfig" {
		t.Errorf("build-input change: got {%s %q}, want {stale buildconfig}", v.Status, v.Reason)
	}
}

// TestBuildFlagsSelectSourceAndPurity pins build-selection coherence across the
// closure and purity surfaces. The same tag that produced the result selects every
// analyzed declaration; an unselected file cannot contribute code or confer purity.
func TestBuildFlagsSelectSourceAndPurity(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	tmp := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/tagged\n\ngo 1.26\n")
	write("selected_default.go", "//go:build !special\n\npackage tagged\n\n//gofresh:pure\nfunc Selected() int { return 1 }\n")
	write("selected_special.go", "//go:build special\n\npackage tagged\n\nfunc Selected() int { return 2 }\n")

	const pkg = "example.com/tagged"
	flags := []string{"-tags=special"}
	defaultPure, err := scanPureDirectivesIn(tmp, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !defaultPure(Subject{Package: pkg, Symbol: "Selected"}) {
		t.Fatal("default build did not find its purity directive")
	}
	specialPure, err := scanPureDirectivesAt(tmp, os.Environ(), flags, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if specialPure(Subject{Package: pkg, Symbol: "Selected"}) {
		t.Fatal("unselected default file conferred purity on the special build")
	}

	recorded, err := newEngine(withDir(tmp), withBuildFlags(flags...))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: pkg, Symbol: "Selected"}
	fp, err := recorded.capture(context.Background(), subject, tmp)
	if err != nil {
		t.Fatal(err)
	}
	write("selected_special.go", "//go:build special\n\npackage tagged\n\nfunc Selected() int { return 3 }\n")
	current, err := newEngine(withDir(tmp), withBuildFlags(flags...))
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := current.check(context.Background(), fp, subject, tmp)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" {
		t.Fatalf("selected source edit = {%s %q}, want {stale closure}", verdict.Status, verdict.Reason)
	}
}

// TestAssumePureOverride pins REQ-purity-override end to end: a subject whose closure
// reaches an unverifiable dependence is Unverifiable by default, and Valid when the
// engine is given a purity predicate that asserts it.
func TestAssumePureOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over the fixture corpus")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	subj := Subject{Package: "github.com/greatliontech/gofresh/internal/closure/testdata/harnessroot", Symbol: "BenchmarkProd"}

	e, err := newEngine()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fp, err := e.captureFor(context.Background(), subj, ".", Measurement)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if v, err := e.check(context.Background(), fp, subj, "."); err != nil {
		t.Fatalf("Check: %v", err)
	} else if v.Status != Unverifiable {
		t.Errorf("default: got %s, want unverifiable (closure reaches file I/O)", v.Status)
	}

	pure, err := newEngine(withAssumePure(func(s Subject) bool { return s == subj }))
	if err != nil {
		t.Fatalf("New pure: %v", err)
	}
	pureFP, err := pure.captureFor(context.Background(), subj, ".", Measurement)
	if err != nil {
		t.Fatalf("Capture pure: %v", err)
	}
	if pureFP.PurityAssertion != "caller assertion" {
		t.Fatalf("purity assertion = %q, want attributable caller assertion", pureFP.PurityAssertion)
	}
	if v, err := pure.check(context.Background(), fp, subj, "."); err != nil {
		t.Fatalf("Check unrecorded pure: %v", err)
	} else if v.Status != Unverifiable {
		t.Errorf("unrecorded assume-pure: got %s, want unverifiable", v.Status)
	}
	if v, err := pure.check(context.Background(), pureFP, subj, "."); err != nil {
		t.Fatalf("Check pure: %v", err)
	} else if v.Status != Valid {
		t.Errorf("assume-pure: got %s (%s), want valid", v.Status, v.Reason)
	}
}

// TestWithDirOutOfTree pins the explicit tree root: an engine rooted at a
// directory the process does not run inside fingerprints that tree's
// subjects — the analyzed tree is an input, never a cwd coupling.
func TestWithDirOutOfTree(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	tmp := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/tiny\n\ngo 1.26\n")
	write("tiny.go", "package tiny\n\n//gofresh:pure\nfunc Add(a, b int) int { return a + b }\n")
	write("tiny_test.go", "package tiny\n\nimport \"testing\"\n\n//gofresh:pure\nfunc TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"sum\")\n\t}\n}\n")

	e, err := newEngine(withDir(tmp))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	subj := Subject{Package: "example.com/tiny", Symbol: "TestAdd"}
	fp, err := e.capture(context.Background(), subj, tmp)
	if err != nil {
		t.Fatalf("Capture out of tree: %v", err)
	}
	v, err := e.check(context.Background(), fp, subj, tmp)
	if err != nil || v.Status != Valid {
		t.Fatalf("round trip = %+v, %v", v, err)
	}
	// The directive scanner honors the same root.
	pred, err := scanPureDirectivesIn(tmp, "example.com/tiny")
	if err != nil {
		t.Fatalf("ScanPureDirectives: %v", err)
	}
	if !pred(Subject{Package: "example.com/tiny", Symbol: "Add"}) {
		t.Fatal("out-of-tree directive not honored")
	}
}

// TestExternalDirectiveWithholdsReuse pins REQ-external-directive and
// REQ-external-precedence end to end: a subject carrying //gofresh:external is
// unverifiable "external directive" whenever its guards hold, a caller purity
// assertion confers nothing (and records no attribution), and a real source
// change still reports stale — externality never masks guard information.
func TestExternalDirectiveWithholdsReuse(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	tmp := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/ext\n\ngo 1.26\n")
	write("ext.go", "package ext\n\n//gofresh:external\nfunc Reads() int { return 1 }\n")

	const pkg = "example.com/ext"
	subj := Subject{Package: pkg, Symbol: "Reads"}
	e, err := newEngine(withDir(tmp), withAssumePure(func(Subject) bool { return true }))
	if err != nil {
		t.Fatal(err)
	}
	fp, err := e.capture(context.Background(), subj, tmp)
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if fp.PurityAssertion != "" {
		t.Fatalf("purity assertion on an external subject = %q, want none (REQ-external-precedence)", fp.PurityAssertion)
	}
	if v, err := e.check(context.Background(), fp, subj, tmp); err != nil {
		t.Fatalf("Check: %v", err)
	} else if v.Status != Unverifiable || v.Reason != "external directive" {
		t.Fatalf("verdict = {%s %q}, want {unverifiable external directive}", v.Status, v.Reason)
	}

	// A source change stales — externality withholds reuse, never guard info.
	write("ext.go", "package ext\n\n//gofresh:external\nfunc Reads() int { return 2 }\n")
	changed, err := newEngine(withDir(tmp))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := changed.check(context.Background(), fp, subj, tmp); err != nil {
		t.Fatalf("Check changed: %v", err)
	} else if v.Status != Stale || v.Reason != "closure" {
		t.Fatalf("changed-source verdict = {%s %q}, want {stale closure}", v.Status, v.Reason)
	}
}

// TestExternalDirectiveConflictRefused pins the contradiction refusal
// (REQ-external-precedence): one declaration carrying both //gofresh:pure and
// //gofresh:external fails observation rather than picking a winner.
func TestExternalDirectiveConflictRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module example.com/conflict\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "c.go"), []byte("package conflict\n\n//gofresh:pure\n//gofresh:external\nfunc Torn() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := newEngine(withDir(tmp))
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.capture(context.Background(), Subject{Package: "example.com/conflict", Symbol: "Torn"}, tmp)
	if err == nil || !strings.Contains(err.Error(), "gofresh:pure and //gofresh:external") {
		t.Fatalf("Capture = %v, want the contradiction refusal", err)
	}
}

// TestExternalDirectiveFixtureScan pins the scanner surface over the committed
// fixture package: exact-form directives on functions and methods mark their
// subjects, near-miss forms do not.
func TestExternalDirectiveFixtureScan(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	const pkg = "github.com/greatliontech/gofresh/testdata/externaldirective"
	e, err := newEngine()
	if err != nil {
		t.Fatal(err)
	}
	for symbol, wantExternal := range map[string]bool{
		"Declared":        true,
		"T.Declared":      true,
		"NotDeclared":     false,
		"SpacedDirective": false,
		"T.NotDeclared":   false,
	} {
		subj := Subject{Package: pkg, Symbol: symbol}
		fp, err := e.capture(context.Background(), subj, ".")
		if err != nil {
			t.Fatalf("Capture %s: %v", symbol, err)
		}
		v, err := e.check(context.Background(), fp, subj, ".")
		if err != nil {
			t.Fatalf("Check %s: %v", symbol, err)
		}
		if wantExternal && (v.Status != Unverifiable || v.Reason != "external directive") {
			t.Errorf("%s = {%s %q}, want {unverifiable external directive}", symbol, v.Status, v.Reason)
		}
		if !wantExternal && v.Reason == "external directive" {
			t.Errorf("%s marked external without the directive", symbol)
		}
	}
}

// TestExternalDirectiveConflictScopedToScanSubjects pins the refusal scope
// (REQ-external-precedence): a contradiction in a dependency that yields no
// subject of the scan does not brick its dependents; scanning the conflicted
// package itself refuses.
func TestExternalDirectiveConflictScopedToScanSubjects(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	tmp := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(tmp, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/scoped\n\ngo 1.26\n")
	write("dep/dep.go", "package dep\n\n//gofresh:pure\n//gofresh:external\nfunc Torn() int { return 1 }\n")
	write("top.go", "package scoped\n\nimport \"example.com/scoped/dep\"\n\nfunc Uses() int { return dep.Torn() }\n")

	e, err := newEngine(withDir(tmp))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.capture(context.Background(), Subject{Package: "example.com/scoped", Symbol: "Uses"}, tmp); err != nil {
		t.Fatalf("dependent capture refused by a dependency's conflict: %v", err)
	}
	_, err = e.capture(context.Background(), Subject{Package: "example.com/scoped/dep", Symbol: "Torn"}, tmp)
	if err == nil || !strings.Contains(err.Error(), "gofresh:pure and //gofresh:external") {
		t.Fatalf("conflicted package's own capture = %v, want the contradiction refusal", err)
	}

	// A conflicted METHOD promoting into a requested subject refuses too —
	// including one declared in another package and promoted through
	// embedding, which only the method-set path can sight.
	write("meth/meth.go", "package meth\n\ntype T struct{}\n\n//gofresh:pure\n//gofresh:external\nfunc (T) Torn() int { return 1 }\n")
	_, err = e.capture(context.Background(), Subject{Package: "example.com/scoped/meth", Symbol: "T.Torn"}, tmp)
	if err == nil || !strings.Contains(err.Error(), "gofresh:pure and //gofresh:external") {
		t.Fatalf("conflicted method capture = %v, want the contradiction refusal", err)
	}
	write("embed/embed.go", "package embed\n\nimport \"example.com/scoped/meth\"\n\ntype W struct{ meth.T }\n")
	_, err = e.capture(context.Background(), Subject{Package: "example.com/scoped/embed", Symbol: "W.Torn"}, tmp)
	if err == nil || !strings.Contains(err.Error(), "gofresh:pure and //gofresh:external") {
		t.Fatalf("promoted conflicted method capture = %v, want the contradiction refusal", err)
	}
}

const preparationSource = "package view\n\nfunc F() int { return 1 }\n\nfunc G() int { return 2 }\n"

// A subject the scan does not know refuses before the maximal fold reads
// and hashes a single contributing file: the answer is the scan's, and the
// fold cannot change it (preparation before measurement).
func TestUnknownSubjectRefusesBeforeTheMaximalFold(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	isolateProofCache(t)
	dir := writeViewModule(t, preparationSource)
	folded := false
	withViewTestHooks(viewTestHookSet{
		maximalBatch: func() { folded = true },
	}, func() {
		engine, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		_, err = engine.newView(context.Background(), []Subject{{Package: "example.com/view", Symbol: "NoSuch"}}, dir)
		if err == nil || err.Error() != "gofresh: subject example.com/view.NoSuch not found in selected source" {
			t.Fatalf("unknown subject = %v, want the not-found refusal in its one-subject wording", err)
		}
		if folded {
			t.Fatal("the maximal fold ran before the unknown subject refused")
		}
		// The refusal names every unknown subject of the batch at once, each
		// once in request order, beside the known ones it does not name —
		// one narrowing step for the caller.
		_, err = engine.newView(context.Background(), []Subject{
			{Package: "example.com/view", Symbol: "NoSuch"},
			{Package: "example.com/view", Symbol: "F"},
			{Package: "example.com/view", Symbol: "NoSuchEither"},
			{Package: "example.com/view", Symbol: "NoSuch"},
		}, dir)
		var unknown *UnknownSubjectsError
		if !errors.As(err, &unknown) {
			t.Fatalf("batch with two unknown subjects = %v, want the typed refusal", err)
		}
		want := []Subject{{Package: "example.com/view", Symbol: "NoSuch"}, {Package: "example.com/view", Symbol: "NoSuchEither"}}
		if !reflect.DeepEqual(unknown.Subjects, want) {
			t.Fatalf("unknown subjects = %v, want %v", unknown.Subjects, want)
		}
		if !strings.Contains(err.Error(), "NoSuch, ") || !strings.Contains(err.Error(), "NoSuchEither") {
			t.Fatalf("refusal %q does not name every unknown subject", err)
		}
		if folded {
			t.Fatal("the maximal fold ran before the unknown subjects refused")
		}
	})
}

// A view package that resolves into the module cache refuses from the
// listing, before the typed load the scan would otherwise pay.
func TestModuleCacheViewPackageRefusesBeforeTheTypedLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("populates a module cache and runs the engine over a temporary module")
	}
	dir := writePinnedDepModule(t)
	loaded := false
	withViewTestHooks(viewTestHookSet{
		typedLoad: func() { loaded = true },
	}, func() {
		engine, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		_, err = engine.newView(context.Background(), []Subject{{Package: "golang.org/x/sync/errgroup", Symbol: "Group.Go"}}, dir)
		if err == nil || !strings.Contains(err.Error(), "resolves into the module cache") {
			t.Fatalf("module-cache view package = %v, want the module-cache refusal", err)
		}
		if loaded {
			t.Fatal("the typed load ran before the module-cache refusal")
		}
	})
}

// A batch with one malformed record refuses whole before any verdict is
// decided or any runtime-input window is opened, on both check surfaces.
func TestMalformedRecordRefusesTheBatchBeforeAnyWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	isolateProofCache(t)
	dir := writeViewModule(t, preparationSource)
	f, g := Subject{Package: "example.com/view", Symbol: "F"}, Subject{Package: "example.com/view", Symbol: "G"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	good, err := view.Capture(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.ResultKind = Kind(99)
	opened := 0
	withViewTestHooks(viewTestHookSet{
		runtimeWindow: func() { opened++ },
	}, func() {
		for name, check := range map[string]func(map[Subject]Fingerprint) (map[Subject]Verdict, error){
			"CheckBatch": func(r map[Subject]Fingerprint) (map[Subject]Verdict, error) {
				return view.CheckBatch(context.Background(), r)
			},
			"CheckObservedBatch": func(r map[Subject]Fingerprint) (map[Subject]Verdict, error) {
				return view.CheckObservedBatch(context.Background(), r)
			},
		} {
			verdicts, err := check(map[Subject]Fingerprint{f: good, g: bad})
			if err == nil || !strings.Contains(err.Error(), "invalid recorded result kind") {
				t.Fatalf("%s with a malformed record = %v %v, want the kind refusal", name, verdicts, err)
			}
			if verdicts != nil {
				t.Fatalf("%s decided verdicts beside the refusal: %v", name, verdicts)
			}
		}
	})
	if opened != 0 {
		t.Fatalf("%d runtime-input windows opened for refused batches", opened)
	}
}

// A sealed view whose captured proof has no completed observation
// attached refuses before the validation re-observes the tree.
func TestMissingAttachmentRefusesBeforeTheValidationObservation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.captureObserved(context.Background(), subject); err != nil {
		t.Fatal(err)
	}
	observed := 0
	withViewTestHooks(viewTestHookSet{
		observe: func() { observed++ },
	}, func() {
		err = view.Validate(context.Background())
	})
	if err == nil || !strings.Contains(err.Error(), "no attached completed observation") {
		t.Fatalf("validation without an attachment = %v, want the attachment refusal", err)
	}
	if observed != 0 {
		t.Fatalf("validation observed the tree %d times before refusing on the missing attachment", observed)
	}
	_ = closure.Observability{}
}

// The toolchain-selection notice is announced at view construction —
// where the Hasher resolved it, one go env read the engine's own
// construction never pays — before any load, not first on the
// precise-analysis path. The selection activates a tag-gated stdlib file
// that violates structural verification (whereas a tag constraining no
// unverified std file selects verified bytes and emits no notice).
func TestToolchainSelectionNoticeAnnouncedAtViewConstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	isolateProofCache(t)
	dir := writeViewModule(t, preparationSource)
	badEnv := unauditedTagEnv(t)
	var events []Progress
	engine, err := newEngine(withDir(dir), withEnv(badEnv...), withProgress(func(p Progress) { events = append(events, p) }), withBuildFlags("-tags=badstd"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.newView(context.Background(), []Subject{{Package: "example.com/view", Symbol: "F"}}, dir); err != nil {
		t.Fatal(err)
	}
	notices, firstNotice, firstWork := 0, -1, -1
	for i, e := range events {
		switch e.Phase {
		case "toolchain-unaudited":
			notices++
			if firstNotice < 0 {
				firstNotice = i
			}
			if e.Detail == "" {
				t.Fatal("notice carries no detail")
			}
		case "list", "typecheck", "hash", "load", "prove":
			if firstWork < 0 {
				firstWork = i
			}
		}
	}
	if notices != 1 {
		t.Fatalf("toolchain-unaudited notices at construction = %d, want exactly one (once per engine)", notices)
	}
	// Announced before any paid step, never first on a path reached
	// after one.
	if firstWork >= 0 && firstNotice > firstWork {
		t.Fatalf("the notice (event %d) followed the first paid step (event %d): %+v", firstNotice, firstWork, events)
	}
}

func writePartitionModule(t *testing.T, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const partitionProduction = "package partition\n\nfunc F() int { return 1 }\n"

const partitionTest = "package partition\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"

// A sibling test added to the subject's package stales the recording with the
// stable discriminating reason "test variants" on both check surfaces: the
// core is unmoved, only the compartment drifted, and the consumer — not
// gofresh — decides what that means (REQ-closure-test-variant-identity).
func TestSiblingTestAdditionStalesAsTestVariants(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writePartitionModule(t, map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      partitionProduction,
		"partition_test.go": partitionTest,
	})
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := engine.capture(context.Background(), subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.TestVariantClosure == "" || fingerprint.TestVariantClosure == testvariant.EmptyTestVariantClosure {
		t.Fatalf("captured compartment = %q, want a non-empty test-file identity", fingerprint.TestVariantClosure)
	}
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(partitionTest+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdict, err := engine.check(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "test variants" {
		t.Fatalf("sibling test addition = %+v, want {stale \"test variants\"}", verdict)
	}
	observed, err := engine.checkObserved(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Stale || observed.Reason != "test variants" {
		t.Fatalf("observed-policy check = %+v, want {stale \"test variants\"}", observed)
	}
}

// A subject declared in a test file has its own body in the compartment:
// editing the recorded test itself moves the compartment, not the core, and
// the verdict says so (REQ-closure-test-variant-identity).
func TestTestFileSubjectBodyLivesInCompartment(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writePartitionModule(t, map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      partitionProduction,
		"partition_test.go": partitionTest,
	})
	subject := Subject{Package: "example.com/partition", Symbol: "TestF"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := engine.capture(context.Background(), subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte("package partition\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"edited body\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdict, err := engine.check(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "test variants" {
		t.Fatalf("edited recorded test = %+v, want {stale \"test variants\"}", verdict)
	}
}

// A recording that predates the partition carries no compartment: it fails
// closed to stale even when the core still matches — the one shape where a
// pre-partition core CAN match is a package with no test files
// (REQ-closure-test-variant-identity).
func TestPrePartitionRecordingFailsClosedAsTestVariants(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writePartitionModule(t, map[string]string{
		"go.mod":  "module example.com/notest\n\ngo 1.26\n",
		"main.go": "package notest\n\nfunc F() int { return 1 }\n",
	})
	subject := Subject{Package: "example.com/notest", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := engine.capture(context.Background(), subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.TestVariantClosure != testvariant.EmptyTestVariantClosure {
		t.Fatalf("no-test capture compartment = %q, want the defined empty identity", fingerprint.TestVariantClosure)
	}
	prePartition := fingerprint
	prePartition.TestVariantClosure = ""
	verdict, err := engine.check(context.Background(), prePartition, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "test variants" {
		t.Fatalf("pre-partition recording = %+v, want fail-closed {stale \"test variants\"}", verdict)
	}
	// Both check surfaces share one evidence ladder: the observed surface
	// fails a pre-partition recording closed identically.
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := view.CheckObserved(context.Background(), prePartition, subject)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Stale || observed.Reason != "test variants" {
		t.Fatalf("observed pre-partition recording = %+v, want fail-closed {stale \"test variants\"}", observed)
	}
	current, err := engine.check(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if current.Status != Valid {
		t.Fatalf("post-partition recording = %+v, want valid", current)
	}
}

// Compartment drift is decided from recorded evidence alone: with the core
// equal, a drifted compartment is stale "test variants" on both check
// surfaces and no precise analysis runs; with both equal, the verdict is
// valid, equally without analysis (REQ-closure-test-variant-identity,
// REQ-fresh-hierarchical-check).
func TestCompartmentDriftStalesWithoutPreciseAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writePartitionModule(t, map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      partitionProduction,
		"partition_test.go": partitionTest,
	})
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}

	// Both equal: the verdict is served with no precise analysis.
	unchanged, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses := 0
	unchanged.beforePreciseAnalysis = func() { analyses++ }
	verdict, err := unchanged.Check(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid || analyses != 0 {
		t.Fatalf("no-drift check = %+v with %d analyses, want valid without analysis", verdict, analyses)
	}

	// Compartment drift: stale "test variants", no analysis consulted.
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(partitionTest+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drifted, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses = 0
	drifted.beforePreciseAnalysis = func() { analyses++ }
	verdict, err = drifted.Check(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "test variants" || analyses != 0 {
		t.Fatalf("compartment-drift check = %+v with %d analyses, want {stale \"test variants\"} without analysis", verdict, analyses)
	}
	observed, err := drifted.CheckObserved(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Stale || observed.Reason != "test variants" || analyses != 0 {
		t.Fatalf("compartment-drift observed check = %+v with %d analyses, want {stale \"test variants\"} without analysis", observed, analyses)
	}
}

// Core drift takes the ladder's first tier even when the compartment also
// drifted: strictly more drift never improves a verdict, and the reason names
// the core ("closure"), the compartment being compared only under an equal
// core (REQ-closure-test-variant-identity, REQ-fresh-hierarchical-check).
func TestMixedCoreAndCompartmentDriftStalesOnClosure(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writePartitionModule(t, map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      partitionProduction,
		"sibling.go":        "package partition\n\nfunc Sibling() int { return 1 }\n",
		"partition_test.go": partitionTest,
	})
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}

	// A production sibling edit AND a sibling-test edit drift both tiers.
	if err := os.WriteFile(filepath.Join(dir, "sibling.go"), []byte("package partition\n\nfunc Sibling() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(partitionTest+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drifted, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := drifted.Check(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" {
		t.Fatalf("mixed-drift check = %+v, want {stale \"closure\"}", verdict)
	}
	observed, err := drifted.CheckObserved(context.Background(), recorded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Stale || observed.Reason != "closure" {
		t.Fatalf("mixed-drift observed check = %+v, want {stale \"closure\"}", observed)
	}
}

// The view serves the compartment ledger from its construction-time snapshot:
// the same bytes the recorded compartment hash folded, unchanged by later
// on-disk edits, so capture-time persistence and check-time diffing read
// coherent data (REQ-closure-test-variant-ledger,
// REQ-fresh-coherent-view).
func TestViewServesTestVariantLedgerFromItsSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writePartitionModule(t, map[string]string{
		"go.mod":            "module example.com/partition\n\ngo 1.26\n",
		"partition.go":      partitionProduction,
		"partition_test.go": partitionTest,
	})
	subject := Subject{Package: "example.com/partition", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := view.TestVariantLedger(subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(captured.Declarations) != 1 || captured.Declarations[0].Name != "TestF" || captured.Declarations[0].Kind != "func" {
		t.Fatalf("captured ledger = %+v, want the one recorded test", captured.Declarations)
	}
	// Caller-owned all the way down: mutating a served reference list never
	// surfaces through the view's internal ledger or later callers.
	if len(captured.Declarations[0].References) == 0 {
		t.Fatalf("captured declaration carries no references: %+v", captured.Declarations[0])
	}
	original := captured.Declarations[0].References[0]
	captured.Declarations[0].References[0] = "mutated"
	refetched, err := view.TestVariantLedger(subject)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(refetched.Declarations[0].References, "mutated") {
		t.Fatalf("view ledger shares reference backing arrays with callers: %v", refetched.Declarations[0].References)
	}
	captured.Declarations[0].References[0] = original
	// The compartment's bytes are among the view's exposed source identities,
	// so a producer's provenance covers them like any core member
	// (REQ-fresh-view-source-identities).
	sources, err := view.SourceFilesFor(subject)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(sources, filepath.Join(dir, "partition_test.go")) {
		t.Fatalf("view source identities omit the compartment file: %v", sources)
	}
	if _, err := view.TestVariantLedger(Subject{Package: "example.com/partition", Symbol: "Missing"}); err == nil {
		t.Fatal("ledger served for a subject outside the view")
	}
	if err := os.WriteFile(filepath.Join(dir, "partition_test.go"), []byte(partitionTest+"\nfunc TestSibling(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err := view.TestVariantLedger(subject)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(captured, snapshot) {
		t.Fatalf("view ledger moved with a post-construction edit:\n%+v\n%+v", captured, snapshot)
	}
	fresh, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	current, err := fresh.TestVariantLedger(subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Declarations) != 2 {
		t.Fatalf("current ledger = %+v, want the added sibling visible to a fresh view", current.Declarations)
	}
}

// A reported version is unchanged while real selected stdlib behavior moves.
// Both stored proof reuse and ordinary explicit-purity reuse need the content
// dependency; the latter reaches a package outside the admission surface.
func TestToolchainContentBindsRecordedApplicability(t *testing.T) {
	if testing.Short() {
		t.Skip("clones a toolchain and checks real source changes")
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux outcome support and reflink fixture")
	}
	for _, tc := range []struct {
		name, source, file, old, replacement, after string
		observed                                    bool
	}{
		{"observed", "package stdlibdep\nimport \"strings\"\nfunc Value() int { return strings.Compare(\"a\", \"a\") }\n", "strings/compare.go", "return bytealg.CompareString(a, b)", "return bytealg.CompareString(a, b) + 3", "3", true},
		{"asserted-pure", "package stdlibdep\nimport \"image/color\"\n//gofresh:pure\nfunc Value() int { y, _, _ := color.RGBToYCbCr(0, 0, 0); return int(y) }\n", "image/color/ycbcr.go", "r1 := int32(r)", "r1 := int32(r) + 255", "76", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			cache := t.TempDir()
			t.Setenv("XDG_CACHE_HOME", cache)
			root := testenv.OverlayGOROOT(t, os.Environ(), nil)
			t.Setenv("GOROOT", root)
			t.Setenv("GOTOOLCHAIN", "local")
			t.Setenv("GOENV", "off")
			t.Setenv("GOFLAGS", "")
			t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
			dir := t.TempDir()
			for name, text := range map[string]string{
				"go.mod":        "module example.com/stdlibdep\n\ngo 1.27\n",
				"value.go":      tc.source,
				"value_test.go": "package stdlibdep\nimport \"testing\"\nfunc TestValue(t *testing.T) { Value() }\n",
				"cmd/main.go":   "package main\nimport (\"fmt\"; p \"example.com/stdlibdep\")\nfunc main() { fmt.Print(p.Value()) }\n",
			} {
				path := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			subject := Subject{Package: "example.com/stdlibdep", Symbol: "Value"}
			newView := func() *Snapshot {
				t.Helper()
				e, err := newEngine(withDir(dir))
				if err != nil {
					t.Fatal(err)
				}
				v, err := e.newView(ctx, []Subject{subject}, dir)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			runValue := func(want string) {
				t.Helper()
				cmd := exec.CommandContext(ctx, "go", "run", "./cmd")
				cmd.Dir = dir
				out, err := cmd.CombinedOutput()
				if err != nil || string(out) != want {
					t.Fatalf("actual value=%q want=%q error=%v", out, want, err)
				}
			}
			capture := func(v *Snapshot) (Fingerprint, error) {
				if tc.observed {
					return v.captureObserved(ctx, subject)
				}
				return v.Capture(ctx, subject)
			}
			check := func(v *Snapshot, f Fingerprint) (Verdict, error) {
				if tc.observed {
					return v.CheckObserved(ctx, f, subject)
				}
				return v.Check(ctx, f, subject)
			}
			producer := newView()
			record, err := capture(producer)
			if err != nil {
				t.Fatal(err)
			}
			if tc.observed {
				if !record.ObservationProof.Observable {
					t.Fatalf("initial proof: %+v", record.ObservationProof)
				}
				record, err = producer.AttachObservation(subject, record, supportedObservation(t, producer, dir, dir, "execution", ""))
				if err != nil {
					t.Fatal(err)
				}
			} else if record.PurityAssertion == "" {
				t.Fatal("missing explicit-purity control")
			}
			if err := producer.Validate(ctx); err != nil {
				t.Fatal(err)
			}
			if verdict, err := check(newView(), record); err != nil || verdict.Status != Valid {
				t.Fatalf("unchanged control: %+v %v", verdict, err)
			}
			runValue("0")
			pending := newView()
			pendingRecord, err := capture(pending)
			if err != nil {
				t.Fatal(err)
			}
			if tc.observed {
				_, err = pending.AttachObservation(subject, pendingRecord, supportedObservation(t, pending, dir, dir, "pending", ""))
				if err != nil {
					t.Fatal(err)
				}
			}
			file := filepath.Join(root, "src", tc.file)
			source, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(string(source), tc.old, tc.replacement, 1)
			if changed == string(source) {
				t.Fatal("source anchor absent")
			}
			if err := os.Remove(file); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte(changed), 0o644); err != nil {
				t.Fatal(err)
			}
			runValue(tc.after)
			if err := pending.Validate(ctx); !errors.Is(err, ErrViewChanged) {
				t.Fatalf("closing accepted changed selected source: %v", err)
			}
			if !tc.observed {
				sel, err := ResolveToolchainSelection(ctx, BuildDescription{Directory: dir, Environment: os.Environ()})
				if err != nil || sel.SelectionNotice != "" {
					t.Fatalf("outside-audit control changed admission: %s %v", sel.SelectionNotice, err)
				}
			}
			var warm Fingerprint
			for _, state := range []string{"warm", "discarded-cache"} {
				if state == "discarded-cache" {
					if err := os.RemoveAll(filepath.Join(cache, "gofresh")); err != nil {
						t.Fatal(err)
					}
				}
				view := newView()
				current, err := capture(view)
				if err != nil {
					t.Fatal(err)
				}
				if current.Guards.Toolchain != record.Guards.Toolchain || current.MaximalClosure != record.MaximalClosure {
					t.Fatal("fixture changed the reported version or module-source hash")
				}
				if current.ToolchainContent == "" || current.ToolchainContent == record.ToolchainContent {
					t.Fatal("selected stdlib content did not move")
				}
				if current.AdmissionPolicy != record.AdmissionPolicy {
					t.Fatal("a source edit moved the policy identity")
				}
				if tc.observed && !current.ObservationProof.Observable {
					t.Fatalf("structurally valid source change lost observability: %+v", current.ObservationProof)
				}
				if state == "warm" {
					warm = current
				} else if current.ObservationProof != warm.ObservationProof || current.ToolchainContent != warm.ToolchainContent {
					t.Fatal("warm and discarded-cache derivations disagree")
				}
				if verdict, err := check(view, record); err != nil || verdict.Status != Stale || verdict.Reason != "toolchain content" {
					t.Fatalf("%s old record: %+v %v", state, verdict, err)
				}
				legacy := record
				legacy.ToolchainContent = ""
				if verdict, err := check(view, legacy); err != nil || verdict.Status != Unverifiable {
					t.Fatalf("missing historical content: %+v %v", verdict, err)
				}
			}
		})
	}
}

// A historical checker fixture can carry a different producing policy while
// its source, proof disposition and runtime inputs otherwise agree. The live
// checker must judge policy compatibility, not just that fixture's integrity.
func TestPolicyMismatchCannotLiftClosureRefusal(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs an outcome-supported historical fixture")
	}
	dir := writeSupportedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(t.Context(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	control, err := producer.captureObserved(t.Context(), subject)
	if err != nil || !control.ObservationProof.Observable {
		t.Fatalf("control: %+v %v", control, err)
	}
	// Model the stored policy of an older build after establishing the shared
	// disposition. This is not a claim of production under that live policy.
	cl := producer.facts.closure(subject)
	if cl.AdmissionPolicy == "" {
		t.Fatal("current policy missing")
	}
	cl.AdmissionPolicy = "historical-" + cl.AdmissionPolicy
	producer.facts.maximal[subject] = testSubjectFacts(cl)
	recorded, err := producer.captureObserved(t.Context(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation := supportedObservation(t, producer, dir, dir, "historical", "getenv OUTCOME_VALUE\n")
	recorded, err = producer.AttachObservation(subject, recorded, observation)
	if err != nil {
		t.Fatal(err)
	}
	if !compatibleObservationProof(recorded, subject) || !runtimeinput.HasOutcomeSupport(recorded.RuntimeInputs, outcomeSubject(recorded, subject)) {
		t.Fatal("historical checker fixture lacks internally bound support")
	}
	current, err := engine.newView(t.Context(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict, err := current.CheckObserved(t.Context(), recorded, subject); err != nil || verdict.Status != Unverifiable {
		t.Fatalf("policy mismatch lifted the closure refusal: %+v %v", verdict, err)
	}
}

type cancelAfterChecks struct {
	context.Context
	after, checks int
}

func (c *cancelAfterChecks) Err() error {
	c.checks++
	if c.checks > c.after {
		return context.Canceled
	}
	return nil
}

// testObservationBracket captures an observation bracket over roots — the
// whole module by default — for completed-observation construction in tests.
func testObservationBracket(t *testing.T, moduleDir string, roots ...string) runtimeinput.Bracket {
	t.Helper()
	if len(roots) == 0 {
		roots = []string{"."}
	}
	bracket, err := riCaptureBracket(moduleDir, roots)
	if err != nil {
		t.Fatal(err)
	}
	return bracket
}

func TestUnavailableObservationAnalysisIsUnverifiable(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":      "module example.com/external\n\ngo 1.26\n",
		"external.go": "package external\n\nimport \"os\"\n\nfunc Ok() bool { return os.Getenv(\"OK\") == \"\" }\n",
		"external_test.go": `package external_test

import (
	"testing"

	"example.com/external"
)

func TestExternal(t *testing.T) {
	if !external.Ok() {
		t.Fatal("not ok")
	}
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	subject := Subject{Package: "example.com/external", Symbol: "Ok"}
	oracle := Subject{Package: "example.com/external", Symbol: "TestExternal"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject, oracle}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("observation proof = %+v, want unavailable disposition", fingerprint.ObservationProof)
	}
	oracleFingerprint, err := producer.captureObserved(context.Background(), oracle)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(oracleFingerprint.ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("oracle observation proof = %+v, want isolated analyzed disposition", oracleFingerprint.ObservationProof)
	}
	observation, err := riFromTestLog(nil, dir, dir, runtimeinput.WithCompletedProcess("external test"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.AttachObservation(oracle, oracleFingerprint, observation); err != nil {
		t.Fatal(err)
	}
	if err := producer.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, err := engine.newView(context.Background(), []Subject{subject, oracle}, dir)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := current.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("verdict = %+v, want unverifiable", verdict)
	}
	// One batched capture over both subjects preserves the same isolation: the
	// unrootable subject degrades alone while its package sibling analyzes.
	batchProducer, err := engine.newView(context.Background(), []Subject{subject, oracle}, dir)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := batchProducer.CaptureObservedBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(batch[subject].ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("batched unrootable proof = %+v, want unavailable disposition", batch[subject].ObservationProof)
	}
	if strings.Contains(batch[oracle].ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("batched oracle proof = %+v, want isolated analyzed disposition", batch[oracle].ObservationProof)
	}
}

func TestObservedRecordingStalesOnMaximalDrift(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.ObservationProof.Observable {
		t.Fatalf("observed fingerprint = %+v", fingerprint)
	}
	observation, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	// A fingerprint that is not byte-identical to the captured proof —
	// here a tampered purity assertion — must refuse attachment: runtime
	// evidence binds only to the exact captured record.
	tampered := fingerprint
	tampered.PurityAssertion = "caller assertion"
	if _, err := producer.AttachObservation(subject, tampered, observation); err == nil {
		t.Fatal("tampered fingerprint accepted a runtime observation attachment")
	}
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.AttachObservation(subject, producer.observedFingerprintLocked(subject), observation); err == nil {
		t.Fatal("second runtime observation attachment was accepted")
	}
	// One Validate: the view revalidates whatever it captured with no
	// routing sentinel for the caller to interpret.
	if err := producer.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(dir, "observed.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte(strings.Replace(string(source), "return 1", "return 2", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Core drift stales the recording on the closure even under the
	// observed policy: the observation lift rescues unverifiability, never
	// a drifted core.
	verdict, err := current.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" {
		t.Fatalf("observed check after maximal drift = %+v, want {stale \"closure\"}", verdict)
	}
}

// Cancellation surfacing mid-check returns the context error and a zero
// verdict, never a partial answer — even when the record's evidence alone
// already decided staleness.
func TestCheckObservedPropagatesCancellationMidCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(dir, "observed.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte(strings.Replace(string(source), "return 1", "return 2", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &cancelAfterChecks{Context: context.Background(), after: 1}
	if verdict, err := current.CheckObserved(ctx, fingerprint, subject); !errors.Is(err, context.Canceled) || verdict != (Verdict{}) {
		t.Fatalf("CheckObserved cancellation = %+v, %v; want zero verdict and context.Canceled", verdict, err)
	}
}

// TestObservedProofAdmitsParentTraversalIdentity pins the effects
// admission's testlog-representability bar: a constant read identity
// carrying ".." is admitted — resolvability is the runtime observation's
// obligation under REQ-inputs-path-congruence, discharged or sealed at
// ingest — so the repo-root read idiom no longer blocks the proof, and
// with it the plain tier's file-I/O rescue.
func TestObservedProofAdmitsParentTraversalIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":       "module example.com/traversal\n\ngo 1.26\n",
		"data/fixture": "one",
		"pkg/pkg.go":   "package pkg\n\nfunc Sibling() int { return 1 }\n",
		"pkg/pkg_test.go": "package pkg\n\nimport (\"os\"; \"testing\")\n\n" +
			"func TestReadsAbove(*testing.T) { _, _ = os.ReadFile(\"../data/fixture\") }\n",
	} {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	subject := Subject{Package: "example.com/traversal/pkg", Symbol: "TestReadsAbove"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.ObservationProof.Observable {
		t.Fatalf("traversal read identity blocked the proof: %+v", fingerprint.ObservationProof)
	}
}

func TestObservedFingerprintLiftsOnlyExplicitCompletedEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeSupportedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.ObservationProof.Observable || !compatibleObservationProof(fingerprint, subject) {
		t.Fatalf("captured proof = %+v", fingerprint.ObservationProof)
	}
	withoutManifest, err := producer.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if withoutManifest.Status != Unverifiable {
		t.Fatalf("proof without completed manifest = %+v, want unverifiable", withoutManifest)
	}
	observation := supportedObservation(t, producer, dir, dir, "worker", "getenv OUTCOME_VALUE\n")
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	if err := producer.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	current, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses := 0
	current.beforePreciseAnalysis = func() { analyses++ }
	ordinary, err := current.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.Status != Unverifiable {
		t.Fatalf("ordinary check inferred observation policy: %+v", ordinary)
	}
	observed, err := current.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != Valid {
		t.Fatalf("observed check = %+v, want valid", observed)
	}
	if analyses != 0 {
		t.Fatalf("unchanged-maximal observed check invoked precise analysis %d times, want 0", analyses)
	}
	tampered := fingerprint
	tampered.ObservationProof.Evidence = "tampered"
	verdict, err := current.CheckObserved(context.Background(), tampered, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("tampered proof = %+v, want unverifiable", verdict)
	}
	malformed := supportedObservation(t, current, dir, dir, "worker-malformed", "\ngetenv OUTCOME_VALUE\n")
	malformedState, err := runtimeinput.CompletedState(malformed)
	if err != nil {
		t.Fatal(err)
	}
	malformedFingerprint := fingerprint
	malformedFingerprint.RuntimeInputs = malformedState.Manifest
	malformedFingerprint.RuntimeDigest = malformedState.Digest
	verdict, err = current.CheckObserved(context.Background(), malformedFingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable {
		t.Fatalf("manifest unverifiability was suppressed: %+v", verdict)
	}
	// Unsupported file outcomes still retain their input guard: a proven
	// input change must stale even a recording whose observation cannot lift.
	fileObservation, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("file-identity"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fileGuarded := fingerprint
	fileGuarded.RuntimeInputs, fileGuarded.RuntimeDigest = fileObservation.Manifest, fileObservation.Digest
	if err := os.WriteFile(filepath.Join(dir, "fixture"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	verdict, err = current.CheckObserved(context.Background(), fileGuarded, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || !strings.HasPrefix(verdict.Reason, "runtimeinputs") || !strings.Contains(verdict.Reason, "moved: path fixture") {
		t.Fatalf("changed observed input = %+v, want stale runtimeinputs naming the mover", verdict)
	}
}

func TestValidateBracketsProofAnalysisWithRuntimeObservation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	producer.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
		calls++
		if calls == 1 {
			return state, nil
		}
		moved := state
		moved.Digest = "moved"
		return moved, nil
	}
	if err := producer.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate across runtime drift = %v, want ErrViewChanged", err)
	}
	if calls != 2 {
		t.Fatalf("runtime observations = %d, want 2", calls)
	}
}

func TestViewSourceFilesReturnsMaximalMutableInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{{Package: "example.com/view", Symbol: "F"}}, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "view.go")
	files := view.SourceFiles()
	if len(files) == 0 || !slices.Contains(files, want) {
		t.Fatalf("SourceFiles = %v, want %s", files, want)
	}
	files[0] = "changed"
	if slices.Contains(view.SourceFiles(), "changed") {
		t.Fatal("SourceFiles returned mutable view storage")
	}
}

func TestBatchedViewPreservesSubjectFingerprintsAndSourceFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"go.mod":  "module example.com/view\n\ngo 1.26\n",
		"root.go": "package view\n\nfunc F() {}\nfunc H() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "sub.go"), []byte("package sub\n\nfunc G() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: "example.com/view", Symbol: "F"},
		{Package: "example.com/view", Symbol: "H"},
		{Package: "example.com/view/sub", Symbol: "G"},
	}
	wantByPackage := map[string][]string{
		"example.com/view":     {filepath.Join(dir, "root.go")},
		"example.com/view/sub": {filepath.Join(dir, "sub", "sub.go")},
	}
	batch, err := engine.newView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	var wantUnion []string
	for _, subject := range subjects {
		singleton, err := engine.newView(context.Background(), []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		batchedFingerprint, err := batch.Capture(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		singletonFingerprint, err := singleton.Capture(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		if batchedFingerprint != singletonFingerprint {
			t.Fatalf("%+v batched fingerprint = %+v, singleton = %+v", subject, batchedFingerprint, singletonFingerprint)
		}
		batchedFiles, err := batch.SourceFilesFor(subject)
		if err != nil {
			t.Fatal(err)
		}
		singletonFiles := singleton.SourceFiles()
		if want := wantByPackage[subject.Package]; !slices.Equal(singletonFiles, want) {
			t.Fatalf("%+v singleton files = %v, want exact source identities %v", subject, singletonFiles, want)
		}
		if !slices.Equal(batchedFiles, singletonFiles) {
			t.Fatalf("%+v batched files = %v, singleton = %v", subject, batchedFiles, singletonFiles)
		}
		wantUnion = append(wantUnion, singletonFiles...)
		batchedFiles[0] = "changed"
		current, err := batch.SourceFilesFor(subject)
		if err != nil || slices.Contains(current, "changed") {
			t.Fatalf("SourceFilesFor returned mutable storage: %v, %v", current, err)
		}
	}
	slices.Sort(wantUnion)
	wantUnion = slices.Compact(wantUnion)
	if got := batch.SourceFiles(); !slices.Equal(got, wantUnion) {
		t.Fatalf("batched source-file union = %v, want %v", got, wantUnion)
	}
	if _, err := batch.SourceFilesFor(Subject{Package: "example.com/view", Symbol: "Missing"}); err == nil {
		t.Fatal("SourceFilesFor accepted a subject outside the view")
	}
}

func TestEngineCheckUsesFreshView(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	t.Setenv("GOGC", "100")
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := engine.captureFor(context.Background(), subject, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("GOGC", "off"); err != nil {
		t.Fatal(err)
	}
	verdict, err := engine.check(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("same Engine after ambient drift = {%s %q}, want valid", verdict.Status, verdict.Reason)
	}
	current, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	verdict, err = current.check(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "runtimeconfig" {
		t.Fatalf("new Engine after runtime-config drift = {%s %q}, want {stale runtimeconfig}", verdict.Status, verdict.Reason)
	}
}

func TestCodeViewOmitsMeasurementGuards(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.Guards.Toolchain == "" || fingerprint.Guards.BuildConfig == "" {
		t.Fatalf("code guards missing: %+v", fingerprint.Guards)
	}
	if fingerprint.Guards.Machine != "" || fingerprint.Guards.RuntimeConfig != "" {
		t.Fatalf("code view captured measurement guards: %+v", fingerprint.Guards)
	}
	if _, err := engine.newViewFor(context.Background(), []Subject{subject}, dir, Kind(99)); err == nil {
		t.Fatal("invalid result kind accepted")
	}
}

func TestResultKindIsBoundToFingerprint(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	measurement, err := engine.newViewFor(context.Background(), []Subject{subject}, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := measurement.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ResultKind != Measurement {
		t.Fatalf("captured result kind = %d, want measurement", fingerprint.ResultKind)
	}
	code, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := code.Check(context.Background(), fingerprint, subject); err == nil {
		t.Fatal("measurement fingerprint accepted by code-result view")
	}
	if _, err := code.CheckBatch(context.Background(), map[Subject]Fingerprint{subject: fingerprint}); err == nil {
		t.Fatal("measurement fingerprint accepted by code-result batch")
	}
	reclassified := fingerprint
	reclassified.ResultKind = CodeResult
	if _, err := engine.check(context.Background(), reclassified, subject, dir); err == nil {
		t.Fatal("measurement guards accepted after result-kind reclassification")
	}
	fingerprint.ResultKind = 0
	if _, err := engine.check(context.Background(), fingerprint, subject, dir); err == nil {
		t.Fatal("fingerprint with missing result kind accepted")
	}
}

func TestProducerViewValidatesAfterSourceChange(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The producer view remains the immutable pre-run observation.
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("frozen producer view = {%s %q}, want valid", verdict.Status, verdict.Reason)
	}
	if err := view.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after source edit = %v, want ErrViewChanged", err)
	} else if !strings.Contains(err.Error(), "changed ") || !strings.Contains(err.Error(), "view.go") {
		t.Fatalf("drift refusal does not name the moved file: %v", err)
	}
	verdict, err = engine.check(context.Background(), fingerprint, subject, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" {
		t.Fatalf("fresh current view = {%s %q}, want {stale closure}", verdict.Status, verdict.Reason)
	}
}

func TestProducerViewRejectsSourceIdentityChangeWithEqualBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for _, dep := range []string{"dep-a", "dep-b"} {
		depDir := filepath.Join(dir, dep)
		if err := os.Mkdir(depDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(depDir, "go.mod"), []byte("module example.com/dep\n\ngo 1.26\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(depDir, "dep.go"), []byte("package dep\n\nfunc F() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	goMod := func(dep string) []byte {
		return []byte("module example.com/view\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\nreplace example.com/dep => ./" + dep + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), goMod("dep-a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nimport \"example.com/dep\"\n\nfunc F() { dep.F() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{{Package: "example.com/view", Symbol: "F"}}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), goMod("dep-b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after source identity change = %v, want ErrViewChanged", err)
	} else if !strings.Contains(err.Error(), "moved: ") ||
		!strings.Contains(err.Error(), "dep-a") || !strings.Contains(err.Error(), "dep-b") {
		t.Fatalf("identity-change refusal does not name the swapped identities: %v", err)
	}
}

func TestNewViewRejectsSourceChangeDuringConstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	var change sync.Once
	engine, err := newEngine(
		withDir(dir),
		withAssumePure(func(Subject) bool {
			change.Do(func() {
				if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
					t.Error(err)
				}
			})
			return false
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.newView(context.Background(), []Subject{subject}, dir); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("NewView during source change = %v, want ErrViewChanged", err)
	}
}

// TestConstructionDriftNamesTheChangedFile pins content-change attribution:
// a mid-construction edit that keeps the source membership identical is
// named through the per-file digests the closure's own reads produced —
// "changed <path>", never a bare refusal.
func TestConstructionDriftNamesTheChangedFile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	var change sync.Once
	engine, err := newEngine(
		withDir(dir),
		withAssumePure(func(Subject) bool {
			change.Do(func() {
				if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
					t.Error(err)
				}
			})
			return false
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.newView(context.Background(), []Subject{subject}, dir)
	if !errors.Is(err, ErrViewChanged) {
		t.Fatalf("NewView during source change = %v, want ErrViewChanged", err)
	}
	if !strings.Contains(err.Error(), "changed ") || !strings.Contains(err.Error(), "view.go") {
		t.Fatalf("construction drift does not name the changed file: %v", err)
	}
}

// TestConstructionDriftNamesTheChangedCompartmentFile pins content-change
// attribution over the test-variant compartment: a mid-construction edit of
// a test-only file is named through the digests the compartment computation
// itself produced, exactly like a core member.
func TestConstructionDriftNamesTheChangedCompartmentFile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	if err := os.WriteFile(filepath.Join(dir, "extra_test.go"), []byte("package view\n\nimport \"testing\"\n\nfunc TestExtra(t *testing.T) { _ = F() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	var change sync.Once
	engine, err := newEngine(
		withDir(dir),
		withAssumePure(func(Subject) bool {
			change.Do(func() {
				if err := os.WriteFile(filepath.Join(dir, "extra_test.go"), []byte("package view\n\nimport \"testing\"\n\nfunc TestExtra(t *testing.T) { _ = F() + 1 }\n"), 0o644); err != nil {
					t.Error(err)
				}
			})
			return false
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.newView(context.Background(), []Subject{subject}, dir)
	if !errors.Is(err, ErrViewChanged) {
		t.Fatalf("NewView during compartment change = %v, want ErrViewChanged", err)
	}
	if !strings.Contains(err.Error(), "changed ") || !strings.Contains(err.Error(), "extra_test.go") {
		t.Fatalf("compartment drift does not name the changed file: %v", err)
	}
}

func TestViewDetectsAddedInitializer(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nvar Value int\nfunc F() int { return Value }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "init.go"), []byte("package view\n\nfunc init() { Value = 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after adding initializer = %v, want ErrViewChanged", err)
	}
}

func TestViewFreezesRelativeModuleDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	original, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})
	engine, err := newEngine()
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.newView(context.Background(), []Subject{subject}, ".")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	canonical, err := gotool.CanonicalDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if view.moduleDir != canonical {
		t.Fatalf("view module dir after chdir = %q, want frozen %q", view.moduleDir, canonical)
	}
}

// Runtime-input revalidation re-hashes relative identities under the
// root the producer anchored the observation at when the caller declared
// one (withEvidenceRoot): a workspace member's engine reads a manifest
// framed at the workspace root — a root-module fixture the member's
// oracle read, recorded as one tree-relative identity — valid while the
// fixture holds and stale when it moves, while an engine without the
// declaration resolves the same identity under the member and reads it
// stale; a root that does not contain the module directory is refused
// at construction (REQ-inputs-evidence-root).
func TestRuntimeRevalidationUsesEvidenceRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a workspace fixture and runs the engine over it")
	}
	root := t.TempDir()
	member := filepath.Join(root, "member")
	if err := os.MkdirAll(member, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"go.work":          "go 1.26\n\nuse ./member\n",
		"member/go.mod":    "module example.com/member\n\ngo 1.26\n",
		"member/member.go": "package member\n\nfunc F() {}\n",
		"shared/fixture":   "before",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The producer frames at the workspace root: the member's process
	// reads the root fixture cwd-relatively, recorded tree-relative.
	state, err := riFromTestLog([]byte("open ../shared/fixture\n"), root, member, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, root, "member", "shared/fixture")))
	if err != nil {
		t.Fatal(err)
	}
	paths, err := runtimeinput.Paths(state.Manifest, root)
	if err != nil || len(paths) != 1 || paths[0] != filepath.Join(root, "shared", "fixture") {
		t.Fatalf("recorded identities = %v, %v; want the fixture tree-relative under the root", paths, err)
	}
	current := func(opts ...option) runtimeinput.State {
		t.Helper()
		e, err := newEngine(append([]option{withDir(member), withEnv(os.Environ()...)}, opts...)...)
		if err != nil {
			t.Fatal(err)
		}
		view := &Snapshot{moduleDir: member, session: e}
		st, err := view.currentRuntimeContext(context.Background(), Fingerprint{RuntimeInputs: state.Manifest}, map[string]runtimeinput.State{})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if got := current(withEvidenceRoot(root)); !got.OK || got.Digest != state.Digest {
		t.Fatalf("evidence-root recompute = %+v, want the recorded digest %s", got, state.Digest)
	}
	if got := current(); got.Digest == state.Digest {
		t.Fatalf("member-rooted recompute reproduced the digest %s; the identity should have resolved under the member and missed", got.Digest)
	}
	if err := os.WriteFile(filepath.Join(root, "shared", "fixture"), []byte("after"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := current(withEvidenceRoot(root)); got.Digest == state.Digest {
		t.Fatalf("a moved root fixture kept the recorded digest under the evidence root")
	}
	if _, err := newEngine(withDir(member), withEnv(os.Environ()...), withEvidenceRoot(t.TempDir())); err == nil || !strings.Contains(err.Error(), "does not contain the module directory") {
		t.Fatalf("an evidence root outside the module = %v; want the containment refusal", err)
	}
	// Loads, closure analysis, and guard observation stay at the module
	// directory: every guard observation an evidence-rooted engine
	// performs captures in the member, and its fingerprint is the
	// module-rooted engine's, field for field.
	subject := Subject{Package: "example.com/member", Symbol: "F"}
	var guardDirs []string
	capture := func(opts ...option) Fingerprint {
		t.Helper()
		e, err := newEngine(append([]option{withDir(member), withEnv(os.Environ()...)}, opts...)...)
		if err != nil {
			t.Fatal(err)
		}
		fp, err := e.captureFor(context.Background(), subject, member, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}
	var plain, rooted Fingerprint
	withViewTestHooks(viewTestHookSet{
		guardDir: func(dir string) { guardDirs = append(guardDirs, dir) },
	}, func() {
		plain = capture()
		guardDirs = nil
		rooted = capture(withEvidenceRoot(root))
	})
	if plain != rooted {
		t.Fatalf("the evidence root moved the captured fingerprint:\n plain  %+v\n rooted %+v", plain, rooted)
	}
	resolvedMember, err := filepath.EvalSymlinks(member)
	if err != nil {
		t.Fatal(err)
	}
	if len(guardDirs) == 0 {
		t.Fatal("no guard observation recorded under the evidence root")
	}
	for _, dir := range guardDirs {
		if dir != resolvedMember {
			t.Fatalf("a guard observation under the evidence root captured in %s, want the module directory %s", dir, resolvedMember)
		}
	}
}

// Runtime-input revalidation computes environment values from the
// producer processes' environment when the caller declared one
// (the session's runtime description): a record digested under the env the producing
// process actually saw stays valid though the analysis env differs,
// while an engine without the declaration - the analysis-env stand-in -
// reads the same record stale. The runtime-inputs contract's
// same-environment-as-the-producing-process rule, made declarable.
func TestRuntimeRevalidationUsesProducerEnv(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	producerEnv := append(append([]string(nil), os.Environ()...), "GOFRESH_TEST_WIDTH=2")
	state, err := runtimeinput.FromTestLog([]byte("getenv GOFRESH_TEST_WIDTH\n"), dir, dir, producerEnv, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	current := func(runtimeEnv []string) runtimeinput.State {
		t.Helper()
		session, err := NewSession(context.Background(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		snapshot := &Snapshot{session: session, kind: CodeResult}
		binding := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: runtimeEnv})
		view := &Snapshot{moduleDir: dir, session: session, runtime: &binding.runtime}
		st, err := view.currentRuntimeContext(context.Background(), Fingerprint{RuntimeInputs: state.Manifest}, map[string]runtimeinput.State{})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if got := current(producerEnv); !got.OK || got.Digest != state.Digest {
		t.Fatalf("producer-env recompute = %+v, want the recorded digest %s", got, state.Digest)
	}
	if got := current(nil); got.Digest == state.Digest {
		t.Fatal("analysis-env stand-in reproduced the producer-env digest; the env divergence is invisible")
	}

	// The observed-producer validation path revalidates attached
	// manifests under the same rule: an env-reading observation recorded
	// under the producer env validates only when the engine knows that
	// env.
	obsDir := writeObservedViewModule(t)
	sub := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	obsProducerEnv := append(append([]string(nil), os.Environ()...), "GOFRESH_TEST_WIDTH=2")
	validate := func(runtimeEnv []string) error {
		t.Helper()
		session, err := NewSession(context.Background(), BuildDescription{Directory: obsDir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := session.Snapshot(context.Background(), []Subject{sub}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		v, err := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: runtimeEnv}).newView([]Subject{sub})
		if err != nil {
			t.Fatal(err)
		}
		fp, err := v.captureObserved(context.Background(), sub)
		if err != nil {
			t.Fatal(err)
		}
		obs, err := runtimeinput.FromTestLog([]byte("getenv GOFRESH_TEST_WIDTH\n"), obsDir, obsDir, obsProducerEnv, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, obsDir)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.AttachObservation(sub, fp, obs); err != nil {
			t.Fatal(err)
		}
		return v.Validate(context.Background())
	}
	if err := validate(obsProducerEnv); err != nil {
		t.Fatalf("producer-env observed validation = %v, want valid", err)
	}
	if err := validate(nil); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("analysis-env stand-in = %v, want the view-changed manifest refusal", err)
	}
}

// The measurement guard's runtime-config digest describes the
// environment the measured processes actually run under: a producer
// env moving its GOMAXPROCS stales every fingerprint captured under
// the prior width - the runtime reads the key before execution, so
// scheduling behavior moves with no other guard moving - while an
// equal producer env checks valid (the session's runtime description).
func TestRuntimeConfigGuardTracksProducerEnv(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	base := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GOMAXPROCS=") {
			base = append(base, entry)
		}
	}
	view := func(width string) *Snapshot {
		t.Helper()
		session, err := NewSession(context.Background(), BuildDescription{Directory: dir, Environment: base, Inputs: []string{}}, SessionPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := session.Snapshot(context.Background(), []Subject{subject}, Measurement)
		if err != nil {
			t.Fatal(err)
		}
		v, err := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: append(append([]string(nil), base...), "GOMAXPROCS="+width)}).newView([]Subject{subject})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	fingerprint, err := view("2").Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view("4").Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "runtimeconfig" {
		t.Fatalf("moved producer width = %+v, want stale runtimeconfig", verdict)
	}
	verdict, err = view("2").Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("equal producer width = %+v, want valid", verdict)
	}
}

func TestRuntimeInputCheckReobservesBaseView(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	state, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := view.Check(context.Background(), fingerprint, subject); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("runtime-input check after base drift = %v, want ErrViewChanged", err)
	}
}

func TestRuntimeInputCheckDetectsMovementBetweenSnapshots(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = "manifest"
	fingerprint.RuntimeDigest = "recorded"
	calls := 0
	view.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
		calls++
		digest := "recorded"
		if calls > 1 {
			digest = "moved"
		}
		return runtimeinput.State{Digest: digest, OK: true}, nil
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "runtimeinputs" || calls != 2 {
		t.Fatalf("moving runtime input verdict = %+v calls=%d, want stale after two observations", verdict, calls)
	}
}

func TestCancelledContextAbortsUnchangedRuntimeCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	state, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	current, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := current.Check(ctx, fingerprint, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("Check under cancelled context = %v, want context.Canceled", err)
	}
	verdict, err := current.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("unchanged runtime check = %+v, want valid", verdict)
	}
}

// A deferred-close engine's checks skip the per-check closing base
// observation and return provisional verdicts; the view's validation is
// the one close (REQ-fresh-coherent-view's deferred close). The default
// engine pays each check's own close and refuses an edit itself; the
// deferred engine's check serves the provisional verdict and the same
// edit refuses at validation, discarding it.
func TestDeferredCheckCloseCollapsesBaseObservationsIntoValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\nfunc G() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := Subject{Package: "example.com/view", Symbol: "F"}
	g := Subject{Package: "example.com/view", Symbol: "G"}
	producerEngine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := producerEngine.newView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[Subject]Fingerprint{}
	for _, subject := range []Subject{f, g} {
		fingerprint, err := producer.Capture(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint.RuntimeInputs = state.Manifest
		fingerprint.RuntimeDigest = state.Digest
		recorded[subject] = fingerprint
	}

	deferredEngine, err := newEngine(withDir(dir), withDeferredCheckClose())
	if err != nil {
		t.Fatal(err)
	}
	deferredView, err := deferredEngine.newView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	defaultView, err := producerEngine.newView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}

	// On a quiescent tree, the default check pays exactly its one closing
	// base observation and the deferred check pays none; both serve the
	// same valid verdicts.
	observations := 0
	var defaultVerdicts, deferredVerdicts map[Subject]Verdict
	var defaultPasses, deferredPasses int
	withViewTestHooks(viewTestHookSet{
		observe: func() { observations++ },
	}, func() {
		defaultVerdicts, err = defaultView.CheckBatch(context.Background(), recorded)
		if err != nil {
			t.Fatal(err)
		}
		defaultPasses = observations
		observations = 0
		deferredVerdicts, err = deferredView.CheckBatch(context.Background(), recorded)
		if err != nil {
			t.Fatal(err)
		}
		deferredPasses = observations
	})
	if defaultPasses != 1 || deferredPasses != 0 {
		t.Fatalf("closing base observations: default = %d, deferred = %d; want 1 and 0", defaultPasses, deferredPasses)
	}
	for _, subject := range []Subject{f, g} {
		if defaultVerdicts[subject].Status != Valid || deferredVerdicts[subject].Status != Valid {
			t.Fatalf("quiescent verdicts: default %+v, deferred %+v, want both valid", defaultVerdicts[subject], deferredVerdicts[subject])
		}
	}
	// The observed check path defers identically: an observed-class
	// recording's check pays the one closing base observation by default
	// and none under the deferred engine.
	obsProducer, err := producerEngine.newView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	observedRecorded := map[Subject]Fingerprint{}
	for _, subject := range []Subject{f, g} {
		fingerprint, err := obsProducer.captureObserved(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint.RuntimeInputs = state.Manifest
		fingerprint.RuntimeDigest = state.Digest
		observedRecorded[subject] = fingerprint
	}
	var defaultObservedPasses, deferredObservedPasses int
	withViewTestHooks(viewTestHookSet{
		observe: func() { observations++ },
	}, func() {
		observations = 0
		if _, err := defaultView.CheckObservedBatch(context.Background(), observedRecorded); err != nil {
			t.Fatal(err)
		}
		defaultObservedPasses = observations
		observations = 0
		if _, err := deferredView.CheckObservedBatch(context.Background(), observedRecorded); err != nil {
			t.Fatal(err)
		}
		deferredObservedPasses = observations
	})
	if defaultObservedPasses != 1 || deferredObservedPasses != 0 {
		t.Fatalf("observed closing base observations: default = %d, deferred = %d; want 1 and 0", defaultObservedPasses, deferredObservedPasses)
	}

	// The deferred view's one close: validation on the unchanged tree
	// succeeds with a single comparison observation, so the provisional
	// verdicts of both check classes stand at the cost of one pass.
	observations = 0
	withViewTestHooks(viewTestHookSet{
		observe: func() { observations++ },
	}, func() {
		if err := deferredView.Validate(context.Background()); err != nil {
			t.Fatalf("deferred close on an unchanged tree: %v", err)
		}
	})
	if observations != 1 {
		t.Fatalf("the deferred close cost %d observations, want 1 — validation's one comparison observation closes every deferred interval", observations)
	}

	// An edit after construction: the default check's own close refuses;
	// the deferred check serves provisionally and the refusal lands at
	// validation, discarding the verdicts with it.
	editedDeferred, err := deferredEngine.newView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	editedDefault, err := producerEngine.newView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 1 }\nfunc G() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := editedDefault.CheckBatch(context.Background(), recorded); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("default check across an edit = %v, want ErrViewChanged at the check's own close", err)
	}
	provisional, err := editedDeferred.CheckBatch(context.Background(), recorded)
	if err != nil {
		t.Fatalf("deferred check across an edit = %v, want provisional verdicts", err)
	}
	if provisional[f].Status != Valid {
		t.Fatalf("provisional verdict = %+v, want valid pending the deferred close", provisional[f])
	}
	if err := editedDeferred.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("deferred close across an edit = %v, want ErrViewChanged discarding the provisional verdicts", err)
	}
}

func TestCheckBatchHonorsCancellationDuringRuntimeObservation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\nfunc G() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	f := Subject{Package: "example.com/view", Symbol: "F"}
	g := Subject{Package: "example.com/view", Symbol: "G"}
	producer, err := engine.newView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[Subject]Fingerprint{}
	state, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []Subject{f, g} {
		fingerprint, err := producer.Capture(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint.RuntimeInputs = state.Manifest
		fingerprint.RuntimeDigest = state.Digest
		recorded[subject] = fingerprint
	}
	current, err := engine.newView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel from inside the first runtime-input observation: the batch must
	// stop between observations with the context error — never observe the
	// second record or finish under a private uncancelled context.
	observations := 0
	current.runtimeCurrent = func(hookCtx context.Context, encoded, moduleDir string) (runtimeinput.State, error) {
		observations++
		cancel()
		return riCurrentCtx(hookCtx, encoded, moduleDir)
	}
	if _, err := current.CheckBatch(ctx, recorded); !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckBatch cancelled during runtime observation = %v, want context.Canceled", err)
	}
	if observations != 1 {
		t.Fatalf("runtime observations after mid-observation cancel = %d, want 1", observations)
	}
}

func TestCaptureObservedBatchReturnsContextErrorAtAnalysisBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Cancellation injected exactly when the proof analysis begins must
	// surface as the context error, never as fingerprints from a partially
	// cancelled analysis.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	view.beforePreciseAnalysis = cancel
	if _, err := view.CaptureObservedBatch(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("CaptureObservedBatch cancelled at the analysis boundary = %v, want context.Canceled", err)
	}
}

// Check decides from recorded evidence alone — no check surface runs precise
// analysis. Unchanged evidence answers valid, a failing known guard reports
// its own staleness, and any maximal drift is stale "closure" unconditionally:
// there is no precise-analysis rescue of a drifted core
// (REQ-fresh-hierarchical-check).
func TestCheckDecidesFromRecordedEvidenceWithoutPreciseAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\nfunc G() int { return 2 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}

	unchanged, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses := 0
	unchanged.beforePreciseAnalysis = func() { analyses++ }
	verdict, err := unchanged.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid || analyses != 0 {
		t.Fatalf("unchanged check = %+v with %d analyses, want valid without analysis", verdict, analyses)
	}
	guardDrift := fingerprint
	guardDrift.Guards.BuildConfig = "different"
	verdict, err = unchanged.Check(context.Background(), guardDrift, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "buildconfig" || analyses != 0 {
		t.Fatalf("failed known guard = %+v with %d analyses, want stale buildconfig without analysis", verdict, analyses)
	}

	// A sibling edit that does not touch F's body still moves the maximal
	// closure: stale "closure", with no analysis attempting a rescue.
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 1 }\nfunc G() int { return 3 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	analyses = 0
	current.beforePreciseAnalysis = func() { analyses++ }
	verdict, err = current.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Stale || verdict.Reason != "closure" || analyses != 0 {
		t.Fatalf("drifted check = %+v with %d analyses, want stale closure without analysis", verdict, analyses)
	}
}

// A cancelled caller context refuses an observed capture before any work.
func TestObservedCaptureHonorsCancelledContext(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := view.captureObserved(ctx, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("CaptureObserved under cancelled context = %v, want context.Canceled", err)
	}
}

func TestContextAwareViewConstructionHonorsCancellation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	_, err = engine.newView(ctx, []Subject{subject}, dir)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled view construction = %v, want context.Canceled", err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.Check(ctx, fingerprint, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled view check = %v, want context.Canceled", err)
	}
	stale := fingerprint
	stale.MaximalClosure = "moved"
	publicationCtx := &cancelAfterChecks{Context: context.Background(), after: 1}
	if _, err := view.Check(publicationCtx, stale, subject); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled verdict publication = %v, want context.Canceled", err)
	}
	current, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	comparisonCtx := &cancelAfterChecks{Context: context.Background(), after: 2}
	if err := view.compareObservationContext(comparisonCtx, *current.facts); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled base comparison = %v, want context.Canceled", err)
	}
	runtimeFingerprint := fingerprint
	runtimeFingerprint.RuntimeInputs = "manifest"
	runtimeFingerprint.RuntimeDigest = "digest"
	runtimeCtx, runtimeCancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	view.runtimeCurrent = func(ctx context.Context, _, _ string) (runtimeinput.State, error) {
		close(started)
		<-ctx.Done()
		return runtimeinput.State{}, ctx.Err()
	}
	done := make(chan error, 1)
	go func() {
		_, err := view.Check(runtimeCtx, runtimeFingerprint, subject)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(30 * time.Second):
		t.Fatal("runtime-input check did not start")
	}
	runtimeCancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runtime-input cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime-input check ignored cancellation")
	}
	if err := view.Validate(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled view validation = %v, want context.Canceled", err)
	}
	if _, err := view.Capture(context.Background(), subject); !errors.Is(err, errViewSealed) {
		t.Fatalf("capture after cancelled validation = %v, want ErrViewSealed", err)
	}
}

func TestObservedCaptureRejectsDriftSinceViewConstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := view.captureObserved(context.Background(), subject); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("CaptureObserved after drift = %v, want ErrViewChanged", err)
	}
}

func TestObservedCaptureRejectsGuardDriftSinceViewConstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	goenv := filepath.Join(t.TempDir(), "goenv")
	if err := os.WriteFile(goenv, []byte("GOFLAGS=-tags=first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", goenv)
	t.Setenv("GOFLAGS", "")
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newViewFor(context.Background(), []Subject{subject}, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goenv, []byte("GOFLAGS=-tags=second\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := view.captureObserved(context.Background(), subject); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("CaptureObserved after guard drift = %v, want ErrViewChanged", err)
	}
}

func TestCancelledObservedCaptureDoesNotWaitForViewLock(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	view.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := view.captureObserved(ctx, subject)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled observed capture error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		view.mu.Unlock()
		t.Fatal("cancelled observed capture waited for the view lock")
	}
	view.mu.Unlock()
}

func TestObservedCaptureDoesNotPublishAfterCancellationWhileWaitingForLock(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// Warm the proof analysis so the second capture reaches the lock wait.
	if _, err := view.captureObserved(context.Background(), subject); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	view.mu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := view.captureObserved(ctx, subject)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	view.mu.Unlock()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("capture after lock-wait cancellation = %v, want context.Canceled", err)
	}
}

func TestValidateReobservesPurityAfterAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	// The purity assertion flips during Validate's final re-observation
	// and nowhere earlier. Observation count to that point: view
	// construction pair 2, observed capture bracket close 1, validation's
	// seeded read 1 - so the flip lands on observation 5, the validation
	// analysis bracket's closing observation.
	calls := 0
	engine, err := newEngine(
		withDir(dir),
		withAssumePure(func(Subject) bool {
			calls++
			return calls > 4
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := riFromTestLog(nil, dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.AttachObservation(subject, fingerprint, observation); err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after purity drift = %v, want ErrViewChanged", err)
	}
}

func TestValidationSealsViewAgainstLaterCapture(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := view.Capture(context.Background(), subject); !errors.Is(err, errViewSealed) {
		t.Fatalf("capture after validation = %v, want ErrViewSealed", err)
	}
	observedView, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := observedView.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := observedView.captureObserved(context.Background(), subject); !errors.Is(err, errViewSealed) {
		t.Fatalf("observed capture after validation = %v, want ErrViewSealed", err)
	}
}

// A capture whose proof analysis is already in flight when validation seals
// the view must refuse at its publication boundary, never publish into a
// sealed view.
func TestValidationSealsConcurrentObservedPublication(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	view.beforePreciseAnalysis = func() {
		close(ready)
		<-release
	}
	go func() {
		_, err := view.captureObserved(context.Background(), subject)
		done <- err
	}()
	select {
	case <-ready:
	case <-time.After(30 * time.Second):
		t.Fatal("observed capture did not reach the analysis boundary")
	}
	if err := view.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, errViewSealed) {
		t.Fatalf("concurrent capture after validation = %v, want ErrViewSealed", err)
	}
}

func TestObservedCaptureIsConcurrentSafe(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan Fingerprint, 2)
	errs := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			fingerprint, err := view.captureObserved(context.Background(), subject)
			results <- fingerprint
			errs <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var first Fingerprint
	for fingerprint := range results {
		if first.MaximalClosure == "" {
			first = fingerprint
			continue
		}
		if fingerprint != first {
			t.Fatalf("concurrent captures differ: %+v != %+v", fingerprint, first)
		}
	}
}

// An observation proof is bound to the subject it was computed for: a record
// carrying a sibling's proof — even with internally consistent evidence — is
// never served through the observation lift.
func TestObservationProofBindsSubjectIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeSupportedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation := supportedObservation(t, producer, dir, dir, "worker", "getenv OUTCOME_VALUE\n")
	fingerprint, err = producer.AttachObservation(subject, fingerprint, observation)
	if err != nil {
		t.Fatal(err)
	}
	current, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	intact, err := current.CheckObserved(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if intact.Status != Valid {
		t.Fatalf("intact observed record = %+v, want valid through the lift", intact)
	}
	// Rebind the proof to a sibling identity and re-derive its evidence so
	// only the subject binding — not the evidence hash — discriminates.
	spliced := fingerprint
	spliced.ObservationProof.Subject = Subject{Package: "example.com/observed", Symbol: "Sibling"}
	spliced.ObservationProof.Evidence = observationProofEvidence(spliced)
	verdict, err := current.CheckObserved(context.Background(), spliced, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status == Valid {
		t.Fatalf("record carrying a sibling's proof = %+v, want the lift denied", verdict)
	}
}

func TestCheckObservedBatchMatchesSingleChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":             "module example.com/batch\n\ngo 1.26\n",
		"a/a.go":             "package a\n\nfunc F() int { return 1 }\n",
		"b/b.go":             "package b\n\nfunc H() int { return 2 }\n",
		"b/observed_test.go": "package b\n\nimport (\"os\"; \"testing\")\n\nfunc TestRead(*testing.T) { _ = os.Getenv(\"OUTCOME_VALUE\") }\n",
		"b/fixture":          "one",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	aF := Subject{Package: "example.com/batch/a", Symbol: "F"}
	bRead := Subject{Package: "example.com/batch/b", Symbol: "TestRead"}
	bH := Subject{Package: "example.com/batch/b", Symbol: "H"}
	subjects := []Subject{aF, bRead, bH}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	captured := map[Subject]Fingerprint{}
	for _, subject := range subjects {
		fingerprint, err := producer.captureObserved(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		captured[subject] = fingerprint
	}
	processView, err := producer.Sibling([]Subject{bRead})
	if err != nil {
		t.Fatal(err)
	}
	state := supportedObservation(t, processView, dir, filepath.Join(dir, "b"), "b test", "getenv OUTCOME_VALUE\n")
	withRuntime := captured[bRead]
	withRuntime.RuntimeInputs = state.Manifest
	withRuntime.RuntimeDigest = state.Digest
	captured[bRead] = withRuntime

	// The batch mixes disposition classes: a verifiable subject in a pure
	// package, an unverifiable subject served through its observation lift,
	// and an unverifiable sibling with no lift evidence.
	singleView, err := engine.newView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	batchView, err := engine.newView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	rounds := []map[Subject]Fingerprint{
		{aF: captured[aF], bRead: captured[bRead], bH: captured[bH]},
	}
	// Tampering the lift-bearing record pins proof denial changing a verdict:
	// intact evidence serves this subject valid through its observation lift.
	tampered := captured[bRead]
	tampered.ObservationProof.Evidence = "tampered"
	guardDrift := captured[aF]
	guardDrift.Guards.BuildConfig = "different"
	maximalOnly := captured[bH]
	maximalOnly.ObservationAssertion = ""
	maximalOnly.ObservationProof = ObservationProof{}
	rounds = append(rounds, map[Subject]Fingerprint{aF: guardDrift, bRead: tampered, bH: maximalOnly})

	observations := 0
	withViewTestHooks(viewTestHookSet{
		observe: func() { observations++ },
	}, func() {
		for i, recorded := range rounds {
			singles := map[Subject]Verdict{}
			for subject, fingerprint := range recorded {
				verdict, err := singleView.CheckObserved(context.Background(), fingerprint, subject)
				if err != nil {
					t.Fatal(err)
				}
				singles[subject] = verdict
			}
			observations = 0
			batch, err := batchView.CheckObservedBatch(context.Background(), recorded)
			if err != nil {
				t.Fatal(err)
			}
			for subject := range recorded {
				if batch[subject] != singles[subject] {
					t.Fatalf("round %d: batch verdict for %s.%s = %+v, single = %+v", i, subject.Package, subject.Symbol, batch[subject], singles[subject])
				}
			}
			if i == 0 {
				// The first round genuinely exercises every disposition class:
				// the verifiable subject answers valid, the unverifiable subject
				// is served valid through its observation lift, and the sibling
				// without lift evidence answers unverifiable.
				if singles[aF].Status != Valid {
					t.Fatalf("verifiable subject = %+v, want valid", singles[aF])
				}
				if singles[bRead].Status != Valid {
					t.Fatalf("lift-served observed subject = %+v, want valid", singles[bRead])
				}
				if singles[bH].Status != Unverifiable {
					t.Fatalf("liftless unverifiable subject = %+v, want unverifiable", singles[bH])
				}
				if observations != 1 {
					t.Fatalf("batched observed check performed %d observations, want 1", observations)
				}
			}
			if i == 1 {
				if singles[bRead].Status != Unverifiable {
					t.Fatalf("tampered lift-bearing record = %+v, want unverifiable", singles[bRead])
				}
				if singles[aF].Status != Stale || singles[aF].Reason != "buildconfig" {
					t.Fatalf("guard-drifted record = %+v, want stale buildconfig", singles[aF])
				}
			}
		}
	})

	// An all-unchanged manifest-less batch answers without observations or
	// precise analysis, and a cancelled caller context aborts the batch.
	quietView, err := engine.newView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	observations = 0
	analyses := 0
	withViewTestHooks(viewTestHookSet{
		observe: func() { observations++ },
	}, func() {
		quietView.beforePreciseAnalysis = func() { analyses++ }
		quiet, err := quietView.CheckObservedBatch(context.Background(), map[Subject]Fingerprint{aF: captured[aF]})
		if err != nil {
			t.Fatal(err)
		}
		if quiet[aF].Status != Valid || observations != 0 || analyses != 0 {
			t.Fatalf("all-unchanged batch = %+v with %d observations and %d analyses, want valid with none", quiet[aF], observations, analyses)
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := quietView.CheckObservedBatch(cancelled, map[Subject]Fingerprint{aF: captured[aF]}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled observed batch = %v, want context.Canceled", err)
		}
		// Evidence-only staleness — even with a runtime manifest attached — is
		// decided without opening the observation window.
		earlyStale := captured[bRead]
		earlyStale.MaximalClosure = ""
		earlyStale.RuntimeInputs = state.Manifest
		earlyStale.RuntimeDigest = state.Digest
		observations = 0
		early, err := quietView.CheckObservedBatch(context.Background(), map[Subject]Fingerprint{bRead: earlyStale})
		if err != nil {
			t.Fatal(err)
		}
		if got := early[bRead]; got.Status != Stale || got.Reason != "closure" || observations != 0 {
			t.Fatalf("early-stale record = %+v with %d observations, want stale closure with none", got, observations)
		}
	})
}

func TestCheckObservedBatchMarksMovingRuntimeInputStale(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	// The undrifted finish must re-observe the runtime window and stale a
	// record whose runtime input moved mid-check even when the before state
	// agreed with the recording. The drifted case pins evidence-only
	// staleness deciding before the window: a drifted core is stale
	// "closure" regardless of window movement. The guard-drift case
	// additionally pins one window semantics across the single and batch
	// forms: an already-stale verdict is not overridden by window movement,
	// in either form.
	for _, scenario := range []string{"unchanged", "drifted", "guard drift"} {
		t.Run(scenario, func(t *testing.T) {
			drift := scenario == "drifted"
			dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
			fixture := filepath.Join(dir, "fixture")
			if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
				t.Fatal(err)
			}
			engine, err := newEngine(withDir(dir))
			if err != nil {
				t.Fatal(err)
			}
			subject := Subject{Package: "example.com/view", Symbol: "F"}
			producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint, err := producer.captureObserved(context.Background(), subject)
			if err != nil {
				t.Fatal(err)
			}
			state, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
			if err != nil {
				t.Fatal(err)
			}
			fingerprint.RuntimeInputs = state.Manifest
			fingerprint.RuntimeDigest = state.Digest
			if drift {
				if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc F() {}\nfunc G() {}\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want := Verdict{Status: Stale, Reason: "runtimeinputs", Ground: JudgmentGround{Cause: Cause{Kind: RuntimeInputsCause, Condition: Unavailable}, Scope: JudgmentScope{Subject: subject, ResultKind: CodeResult}}}
			if drift {
				want.Reason = "closure"
				want.Ground.Cause = Cause{Kind: ClosureCause, Condition: Changed}
			}
			if scenario == "guard drift" {
				fingerprint.Guards.BuildConfig = "different"
				want.Reason = "buildconfig"
				want.Ground.Cause = Cause{Kind: BuildConfigCause, Condition: Changed}
			}
			movingRuntime := func(v *Snapshot) {
				calls := 0
				v.runtimeCurrent = func(ctx context.Context, encoded, moduleDir string) (runtimeinput.State, error) {
					calls++
					if calls == 1 {
						return riCurrentCtx(ctx, encoded, moduleDir)
					}
					return runtimeinput.State{}, nil
				}
			}
			current, err := engine.newView(context.Background(), []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			movingRuntime(current)
			verdicts, err := current.CheckObservedBatch(context.Background(), map[Subject]Fingerprint{subject: fingerprint})
			if err != nil {
				t.Fatal(err)
			}
			if verdicts[subject] != want {
				t.Fatalf("moving runtime input in observed batch = %+v, want %+v", verdicts[subject], want)
			}
			singleView, err := engine.newView(context.Background(), []Subject{subject}, dir)
			if err != nil {
				t.Fatal(err)
			}
			movingRuntime(singleView)
			single, err := singleView.CheckObserved(context.Background(), fingerprint, subject)
			if err != nil {
				t.Fatal(err)
			}
			if single != verdicts[subject] {
				t.Fatalf("single verdict %+v diverges from batch %+v under a moving window", single, verdicts[subject])
			}
		})
	}
}

func TestAnalysisBudgetExhaustionYieldsUnavailableEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n\nfunc G() {}\n")
	subjects := []Subject{{Package: "example.com/view", Symbol: "F"}, {Package: "example.com/view", Symbol: "G"}}
	var mu sync.Mutex
	var cuts []Progress
	budgeted, err := newEngine(withDir(dir), withAnalysisBudget(time.Nanosecond), withProgress(func(p Progress) {
		if p.Phase == "budget-exhausted" {
			mu.Lock()
			defer mu.Unlock()
			cuts = append(cuts, p)
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	// Capture under an exhausted budget still lands a fingerprint carrying an
	// unavailable proof — never an operation error while the caller's context
	// is live, and never observable evidence. The reason names the budget:
	// the record is read long after the pass, and a bare deadline error would
	// not say whose deadline cut it.
	captureView, err := budgeted.newView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprints, err := captureView.CaptureObservedBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		fingerprint := fingerprints[subject]
		if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "observation analysis unavailable: analysis budget 1ns exhausted: ") {
			t.Fatalf("budget-exhausted capture proof for %s = %+v, want an unavailable disposition naming the budget", subject.Symbol, fingerprint.ObservationProof)
		}
	}
	// A second pass over one subject: the cut is reported for a single
	// unproven subject too — the count is the fact, not a threshold.
	single, err := budgeted.newView(context.Background(), subjects[:1], dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := single.captureObserved(context.Background(), subjects[0]); err != nil {
		t.Fatal(err)
	}
	// Each pass reports its cut once, with the count it left unproven —
	// never one event per subject.
	mu.Lock()
	defer mu.Unlock()
	var details []string
	for _, cut := range cuts {
		if cut.Package != "" {
			t.Fatalf("budget-exhausted event names a package: %+v", cut)
		}
		details = append(details, cut.Detail)
	}
	want := []string{"analysis budget 1ns exhausted: 2 subjects unproven", "analysis budget 1ns exhausted: 1 subject unproven"}
	if !slices.Equal(details, want) {
		t.Fatalf("budget-exhausted events = %q, want %q (one per pass, naming the budget and the count)", details, want)
	}
}

// TestValidationReportsUnavailabilityAfterTheClosingCompare pins
// ErrAnalysisUnavailable's contract: a validation whose proof pass the
// budget cut still runs its closing runtime-input comparison, so a
// runtime input moved during the pass is reported as the move, never
// masked by the unavailability a caller would record as unverifiable
// evidence.
func TestValidationReportsUnavailabilityAfterTheClosingCompare(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	engine, producer, fixture, fingerprint := attachedProducer(t)
	if strings.Contains(fingerprint.ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("unbudgeted capture proof = %+v, want an analyzed disposition", fingerprint.ObservationProof)
	}
	// The validation's own proof pass runs under an exhausted budget —
	// set on the engine after the capture, the one way to budget the
	// validation alone (an option budgets every pass of the engine):
	// with nothing moved, the unavailability is the verdict.
	engine.analysisBudget = time.Nanosecond
	if err := producer.Validate(context.Background()); !errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("validation under a cut proof pass = %v, want ErrAnalysisUnavailable", err)
	}
	// The fixture moves once the proof pass has begun — after the opening
	// runtime-input comparison passed, before the closing one runs.
	var err error
	withViewTestHooks(viewTestHookSet{
		beforeAnalysis: func() {
			if err := os.WriteFile(fixture, []byte("moved"), 0o644); err != nil {
				t.Error(err)
			}
		},
	}, func() {
		err = producer.Validate(context.Background())
	})
	if err == nil || errors.Is(err, ErrAnalysisUnavailable) {
		t.Fatalf("validation with a moved runtime input under a cut proof pass = %v, want the move reported, never the unavailability", err)
	}
}

func TestBudgetedProducerValidatesUnavailableProof(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	_, producer, _, fingerprint := attachedProducer(t, withAnalysisBudget(time.Nanosecond))
	if !strings.Contains(fingerprint.ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("budgeted capture proof = %+v, want unavailable disposition", fingerprint.ObservationProof)
	}
	// The captured proof is unavailable, so validation re-establishes it by
	// class regardless of where the fresh budget expires — never a spurious
	// view-changed error from mismatched error text.
	if err := producer.Validate(context.Background()); err != nil {
		t.Fatalf("budgeted validation of an unavailable proof = %v, want success", err)
	}
}

// attachedProducer builds a one-subject module with a fixture file, an
// engine over it with the given options, a producer view with the
// subject's observed proof captured, and a completed observation of the
// fixture attached: the shape every producer-validation test starts from.
func attachedProducer(t *testing.T, opts ...option) (eng *engine, producer *Snapshot, fixture string, fingerprint Fingerprint) {
	t.Helper()
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	fixture = filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := newEngine(append([]option{withDir(dir)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	producer, err = eng.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err = producer.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer.AttachObservation(subject, fingerprint, observation); err != nil {
		t.Fatal(err)
	}
	return eng, producer, fixture, fingerprint
}

// TestLiveBudgetNamesNoBudgetOnAnOwnCauseRefusal pins the discriminator's
// negative arm through the isolation retry: a batch that fails for its
// own cause — a test-only dependency that does not compile, so the
// subject's test-binary program never loads — refuses the subject under a
// budget that has not expired with no budget in its reason, and the pass
// reports no exhaustion.
func TestLiveBudgetNamesNoBudgetOnAnOwnCauseRefusal(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "helper"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"go.mod":           "module example.com/ext\n\ngo 1.26\n",
		"ext.go":           "package ext\n\nfunc Ok() bool { return true }\n",
		"ext_test.go":      "package ext_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/ext/helper\"\n)\n\nfunc TestOk(t *testing.T) { helper.H() }\n",
		"helper/helper.go": "package helper\n\nfunc H() { undefinedSymbol() }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	subject := Subject{Package: "example.com/ext", Symbol: "Ok"}
	var mu sync.Mutex
	var cuts []Progress
	engine, err := newEngine(withDir(dir), withAnalysisBudget(time.Hour), withProgress(func(p Progress) {
		if p.Phase == "budget-exhausted" {
			mu.Lock()
			defer mu.Unlock()
			cuts = append(cuts, p)
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := producer.CaptureObservedBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The closure's own load-failure prefix is the coupling the pin
	// wants: it is what makes this refusal an own-cause one.
	reason := batch[subject].ObservationProof.Reason
	if !strings.HasPrefix(reason, "observation analysis unavailable: closure: load ") || strings.Contains(reason, "analysis budget") {
		t.Fatalf("own-cause refusal under a live budget = %q; want the load failure without a budget named", reason)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(cuts) != 0 {
		t.Fatalf("budget-exhausted events under a live budget = %+v, want none", cuts)
	}
}

func TestProgressReportsAnalysisPhases(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	// A fresh cache: the observability memo legitimately swallows the
	// prove phase on a hit, and this test pins the fresh-analysis
	// sequence.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	var events []Progress
	engine, err := newEngine(withDir(dir), withProgress(func(p Progress) { events = append(events, p) }))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	events = nil
	recorded, err := producer.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	phases := map[string]int{}
	for _, event := range events {
		phases[event.Phase]++
		switch event.Phase {
		case "load", "prove":
			if event.Package != subject.Package {
				t.Fatalf("per-package %s event names %q, want %q", event.Phase, event.Package, subject.Package)
			}
		case "observe", "runtime":
			if event.Package != "" {
				t.Fatalf("%s event names a package: %+v", event.Phase, event)
			}
		case "analysis-unavailable", "toolchain-unaudited":
			// Diagnostic phases carry their payload in Detail; both
			// fire only under their conditions (an isolated analysis
			// failure; an unlisted toolchain surface), so their absence here is
			// as legal as their presence on the next-rc leg.
			if event.Detail == "" {
				t.Fatalf("diagnostic phase %q carries no detail", event.Phase)
			}
		case "list", "hash", "typecheck", "served", "cancelled":
			// Per-unit and served/kept reporting rides beside the
			// step phases; pinned by TestProgressReportsUnitsServedAndKept.
		default:
			t.Fatalf("unknown progress phase %q", event.Phase)
		}
	}
	// A cold observed capture observes once - the analysis bracket opens on
	// the view's agreed facts and reads only at close - opens no runtime
	// window, loads the package program once, and proves once.
	if phases["observe"] != 1 || phases["runtime"] != 0 || phases["load"] != 1 || phases["prove"] != 1 {
		t.Fatalf("progress phases = %v, want observe:1 load:1 prove:1", phases)
	}

	// A manifest-carrying record's window reads once, at close.
	state, err := riFromTestLog(nil, dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	withRuntime := recorded
	withRuntime.RuntimeInputs = state.Manifest
	withRuntime.RuntimeDigest = state.Digest
	runtimeView, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	events = nil
	if _, err := runtimeView.CheckObserved(context.Background(), withRuntime, subject); err != nil {
		t.Fatal(err)
	}
	runtimeEvents := 0
	for _, event := range events {
		if event.Phase == "runtime" {
			runtimeEvents++
		}
	}
	if runtimeEvents != 2 {
		t.Fatalf("runtime-window events = %d, want 2", runtimeEvents)
	}
}

func TestDriftBracketsObserveOncePerSide(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	fixture := filepath.Join(dir, "fixture")
	if err := os.WriteFile(fixture, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := producer.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	state, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	current, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// A runtime-input check's window opens on the view's agreed facts and
	// reads only at close: one fresh observation, with drift across the
	// window still refusing there.
	observations := 0
	withViewTestHooks(viewTestHookSet{
		observe: func() { observations++ },
	}, func() {
		if _, err := current.Check(context.Background(), fingerprint, subject); err != nil {
			t.Fatal(err)
		}
		if observations != 1 {
			t.Fatalf("runtime-input check performed %d observations, want 1", observations)
		}
		// The observability analysis uses one close-only bracket: it opens on
		// the view's agreed facts and reads exactly once, at close.
		observations = 0
		if err := current.ensureObservable(context.Background(), []Subject{subject}); err != nil {
			t.Fatal(err)
		}
		if observations != 1 {
			t.Fatalf("proof analysis performed %d observations, want 1", observations)
		}
		// An already-computed proof re-observes nothing.
		observations = 0
		if err := current.ensureObservable(context.Background(), []Subject{subject}); err != nil {
			t.Fatal(err)
		}
		if observations != 0 {
			t.Fatalf("cached proof analysis performed %d observations, want 0", observations)
		}
	})
}

// One knob redirects every persistent memo class, and no knob position
// changes a verdict - the store is a cache, never a record
// (REQ-closure-observability-memo, REQ-closure-dynamic-state-memo).
func TestMemoStoreKnobIsVerdictInvariant(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	source := "package view\n\nvar Hooks = map[string]func(){\"k\": func() {}}\n\nfunc F() int { return len(Hooks) }\n"
	verdictUnder := func(t *testing.T, configure func(t *testing.T)) Status {
		t.Helper()
		configure(t)
		dir := writeViewModule(t, source)
		engine, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		subject := Subject{Package: "example.com/view", Symbol: "F"}
		view, err := engine.newView(context.Background(), []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := view.Capture(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		verdict, err := view.Check(context.Background(), fingerprint, subject)
		if err != nil {
			t.Fatal(err)
		}
		return verdict.Status
	}
	restore := func(t *testing.T) {
		t.Cleanup(func() { setMemoRoot("") })
	}
	base := verdictUnder(t, func(t *testing.T) { restore(t) })

	redirected := t.TempDir()
	got := verdictUnder(t, func(t *testing.T) {
		restore(t)
		setMemoRoot(redirected)
	})
	if got != base {
		t.Fatalf("redirected store changed the verdict: %v vs %v", got, base)
	}
}

// The redirect contains every persistent write - a pinned-dep fact scan
// lands under the redirected root, never the user cache
// (REQ-closure-dynamic-state-memo).
func TestMemoStoreKnobContainsPersistentWrites(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	forbidden := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", forbidden)
	t.Cleanup(func() { setMemoRoot("") })
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"
	const scope = DynamicStateStrategy + "|knob-containment|cfg"

	redirected := t.TempDir()
	setMemoRoot(redirected)
	processFactCache.Reset()
	first := runScan(t, scope, dir, pkg)
	if !first.known[Subject{Package: pkg, Symbol: "Run"}] {
		t.Fatal("scan lost the subject")
	}
	if entries, err := os.ReadDir(filepath.Join(redirected, "gofresh")); err != nil || len(entries) == 0 {
		t.Fatalf("redirected store received no memo writes: %v %v", entries, err)
	}
	if entries, err := os.ReadDir(filepath.Join(forbidden, "gofresh")); err == nil && len(entries) > 0 {
		t.Fatalf("redirect leaked %d entries into the user cache", len(entries))
	}
}

// A maximal-only producer validation compares one fresh observation against
// the captured facts instead of paying a construction pair: the compared
// read is never recorded, so a torn read can only refuse
// (REQ-fresh-coherent-view's record/compare asymmetry). Drift detection is
// intact: an edit between capture and validation still refuses.
func TestValidateMaximalReadsOnceAndStillRefusesDrift(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc Sum(a, b int) int { return a + b }\n")
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newViewFor(context.Background(), []Subject{{Package: "example.com/view", Symbol: "Sum"}}, dir, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.Capture(context.Background(), Subject{Package: "example.com/view", Symbol: "Sum"}); err != nil {
		t.Fatal(err)
	}
	observations := 0
	withViewTestHooks(viewTestHookSet{
		observe: func() { observations++ },
	}, func() {
		if err := view.Validate(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	if observations != 1 {
		t.Fatalf("maximal validation performed %d observation passes, want exactly 1", observations)
	}

	edited, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view2, err := edited.newViewFor(context.Background(), []Subject{{Package: "example.com/view", Symbol: "Sum"}}, dir, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view2.Capture(context.Background(), Subject{Package: "example.com/view", Symbol: "Sum"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte("package view\n\nfunc Sum(a, b int) int { return a + b + 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := view2.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("single-read validation missed the drift: %v", err)
	}
}

// An observed producer lifecycle pays five observation passes: the
// construction pair (facts become the record), the capture bracket's one
// closing observation, the validation view's one seeded read, and the
// validation analysis bracket's one close - comparison-only reads are
// single (REQ-fresh-coherent-view's record/compare asymmetry). Drift
// between capture and validation still refuses through the seeded read.
func TestObservedProducerLifecyclePassEconomy(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	observations := 0
	withViewTestHooks(viewTestHookSet{
		observe: func() { observations++ },
	}, func() {
		producer, err := engine.newView(context.Background(), []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := producer.captureObserved(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		observation, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("observed test"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := producer.AttachObservation(subject, fingerprint, observation); err != nil {
			t.Fatal(err)
		}
		if err := producer.Validate(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	if observations != 5 {
		t.Fatalf("observed producer lifecycle performed %d observation passes, want 5 (2 construction + 1 capture bracket + 1 seeded read + 1 validation bracket)", observations)
	}

	// Same lifecycle with an edit after capture: the seeded read refuses.
	producer2, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint2, err := producer2.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation2, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("observed test 2"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := producer2.AttachObservation(subject, fingerprint2, observation2); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "observed.go"), []byte("package observed\n\nfunc Sibling() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	observations = 0
	withViewTestHooks(viewTestHookSet{
		observe: func() { observations++ },
	}, func() {
		if err := producer2.Validate(context.Background()); !errors.Is(err, ErrViewChanged) {
			t.Fatalf("seeded validation missed capture-to-validate drift: %v", err)
		}
	})
	// The seeded read itself refuses - one observation, no analysis
	// bracket: the seed comparison is what makes the seeded facts
	// record-grade before any validation-time analysis spends work on
	// them (the bracket close would still refuse, one analysis later).
	if observations != 1 {
		t.Fatalf("capture-to-validate drift refused after %d observations, want 1 (the seeded read)", observations)
	}
}

// A sibling view shares the parent's single observation — identical
// fingerprints, zero additional observation passes — while carrying its
// own producer transaction: the parent's validation seal never blocks a
// sibling's attach/validate cycle, and one subject attaches its own
// runtime evidence once per sibling (the per-target transaction shape a
// mutation campaign runs). REQ-fresh-coherent-view: nothing the sibling
// serves is re-read.
func TestSiblingSharesObservationAndIsolatesTransactions(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/sibling\n\ngo 1.26\n",
		"a/a.go": "package a\n\nfunc F() int { return 1 }\n",
		"b/b.go": "package b\n\nfunc G() int { return 2 }\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	aF := Subject{Package: "example.com/sibling/a", Symbol: "F"}
	bG := Subject{Package: "example.com/sibling/b", Symbol: "G"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := engine.newView(context.Background(), []Subject{aF, bG}, dir)
	if err != nil {
		t.Fatal(err)
	}
	parentF, err := parent.Capture(context.Background(), aF)
	if err != nil {
		t.Fatal(err)
	}

	observations := 0
	var siblingOne, siblingTwo *Snapshot
	withViewTestHooks(viewTestHookSet{
		observe: func() { observations++ },
	}, func() {
		siblingOne, err = parent.Sibling([]Subject{aF})
		if err != nil {
			t.Fatal(err)
		}
		siblingTwo, err = parent.Sibling([]Subject{aF, bG})
		if err != nil {
			t.Fatal(err)
		}
		if observations != 0 {
			t.Fatalf("sibling derivation performed %d observations, want 0 — every served fact must be the parent's", observations)
		}
		if _, err := parent.Sibling([]Subject{{Package: "example.com/sibling/a", Symbol: "Absent"}}); err == nil {
			t.Fatal("sibling over a subject outside the parent view derived, want refusal")
		}
		oneF, err := siblingOne.Capture(context.Background(), aF)
		if err != nil {
			t.Fatal(err)
		}
		if oneF != parentF {
			t.Fatalf("sibling fingerprint = %+v, parent = %+v — shared observation must serve identical evidence", oneF, parentF)
		}

		// The parent's validation seals only the parent's transaction.
		if err := parent.Validate(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := parent.Capture(context.Background(), aF); err == nil {
			t.Fatal("parent capture after validation succeeded, want the seal")
		}
		if _, err := siblingOne.Capture(context.Background(), aF); err != nil {
			t.Fatalf("sibling capture after the parent's validation: %v", err)
		}
		if err := siblingOne.Validate(context.Background()); err != nil {
			t.Fatalf("sibling validation after the parent's: %v", err)
		}
		// A sealed parent still derives: the facts are construction-time and
		// the sibling's own validation is its drift gate. This parent never
		// captured an observed proof, so the derived sibling's observed
		// capture computes one fresh rather than serving an absent
		// inherited proof.
		sealedSibling, err := parent.Sibling([]Subject{aF})
		if err != nil {
			t.Fatalf("sibling derivation from a sealed parent: %v", err)
		}
		observations = 0
		if _, err := sealedSibling.captureObserved(context.Background(), aF); err != nil {
			t.Fatalf("observed capture over a subject the parent never captured: %v", err)
		}
		if observations == 0 {
			t.Fatal("proof-less observed capture completed without observing, want a fresh proof computation")
		}
	})
	// A sibling sealed by its own validation never seals the family, and
	// a single-subject sibling's validation compares against the SUBSET's
	// source union — the parent's wider union would refuse an unchanged
	// tree.
	if _, err := siblingTwo.Capture(context.Background(), bG); err != nil {
		t.Fatalf("second sibling capture after first sibling's validation: %v", err)
	}
	if err := siblingTwo.Validate(context.Background()); err != nil {
		t.Fatalf("second sibling validation: %v", err)
	}

	// Runtime-evidence attachment is per sibling: two siblings attach the
	// same subject's evidence independently, and one sibling attaches a
	// subject once.
	attachParent, err := engine.newView(context.Background(), []Subject{aF, bG}, dir)
	if err != nil {
		t.Fatal(err)
	}
	observedFPs, err := attachParent.CaptureObservedBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	attachOne, err := attachParent.Sibling([]Subject{aF})
	if err != nil {
		t.Fatal(err)
	}
	attachTwo, err := attachParent.Sibling([]Subject{aF, bG})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runtimeinput.Incomplete(dir, "probe", "probe reason", os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attachOne.AttachObservation(aF, observedFPs[aF], observation); err != nil {
		t.Fatalf("first sibling attach: %v", err)
	}
	if _, err := attachTwo.AttachObservation(aF, observedFPs[aF], observation); err != nil {
		t.Fatalf("second sibling attach of the same subject: %v", err)
	}
	if _, err := attachOne.AttachObservation(aF, observedFPs[aF], observation); err == nil {
		t.Fatal("re-attachment on one sibling succeeded, want the once-per-transaction refusal")
	}
	// The campaign's endgame: a sibling of an observed parent attaches
	// its target's runtime evidence and validates through the observed
	// arm on an unchanged tree.
	if _, err := attachTwo.AttachObservation(bG, observedFPs[bG], observation); err != nil {
		t.Fatal(err)
	}
	if err := attachTwo.Validate(context.Background()); err != nil {
		t.Fatalf("observed-arm sibling validation on an unchanged tree: %v", err)
	}
	// Subject order never shapes the narrowed union: a reversed-order
	// sibling over both packages still validates the unchanged tree (the
	// union recipe sorts; an order-carrying union would falsely refuse).
	reversed, err := attachParent.Sibling([]Subject{bG, aF})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reversed.AttachObservation(aF, observedFPs[aF], observation); err != nil {
		t.Fatal(err)
	}
	if _, err := reversed.AttachObservation(bG, observedFPs[bG], observation); err != nil {
		t.Fatal(err)
	}
	if err := reversed.Validate(context.Background()); err != nil {
		t.Fatalf("reversed-order sibling validation on an unchanged tree: %v", err)
	}
}

// A drifted tree refuses a sibling's validation exactly as any view's:
// sharing the parent's recorded facts never weakens the compare side.
func TestSiblingValidationRefusesDrift(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/siblingdrift\n\ngo 1.26\n",
		"a/a.go": "package a\n\nfunc F() int { return 1 }\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	aF := Subject{Package: "example.com/siblingdrift/a", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := engine.newView(context.Background(), []Subject{aF}, dir)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := parent.Sibling([]Subject{aF})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "a.go"), []byte("package a\n\nfunc F() int { return 3 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sibling.Validate(context.Background()); err == nil {
		t.Fatal("sibling validated a drifted tree, want refusal")
	}
}

// A sibling whose one subject's closure spans two in-module packages
// derives a narrowed union that still covers the full cross-package
// closure and compares equal to a fresh subset observation on an
// unchanged tree. This leg pins the cross-package narrowing only;
// order canonicalization is TestSortedUniqueUnionCanonicalizes' pin —
// every production feeder arrives pre-sorted, so no integration path
// can discriminate the recipe's own sort.
func TestSiblingCrossPackageClosureValidatesUnchangedTree(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/siblingdeps\n\ngo 1.26\n",
		"a/a.go": "package a\n\nimport \"example.com/siblingdeps/b\"\n\nfunc F() int { return b.G() }\n",
		"b/b.go": "package b\n\nfunc G() int { return 2 }\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	aF := Subject{Package: "example.com/siblingdeps/a", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	parent, err := engine.newView(context.Background(), []Subject{aF}, dir)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := parent.Sibling([]Subject{aF})
	if err != nil {
		t.Fatal(err)
	}
	// Guard against vacuity: the one subject's union must really span
	// both packages, or the cross-package claim above tests nothing.
	var hasA, hasB bool
	for _, f := range sibling.SourceFiles() {
		if strings.HasSuffix(f, filepath.Join("a", "a.go")) {
			hasA = true
		}
		if strings.HasSuffix(f, filepath.Join("b", "b.go")) {
			hasB = true
		}
	}
	if !hasA || !hasB {
		t.Fatalf("cross-package closure union = %v, want both packages' sources", sibling.SourceFiles())
	}
	if err := sibling.Validate(context.Background()); err != nil {
		t.Fatalf("cross-package-closure sibling validation on an unchanged tree: %v", err)
	}
}

// Within one endpoint phase, records carrying the identical encoded
// manifest evaluate once; the closing endpoint is a fresh instant, so
// movement across the window stays detected
// (REQ-inputs-guard's per-record evaluation collapsed per phase).
func TestRuntimeInputManifestEvaluationSharedPerPhase(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n\nfunc G() int { return 2 }\n")
	f := Subject{Package: "example.com/view", Symbol: "F"}
	g := Subject{Package: "example.com/view", Symbol: "G"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fps, err := view.CaptureBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[Subject]Fingerprint{}
	for s, fp := range fps {
		fp.RuntimeInputs = "shared-manifest"
		fp.RuntimeDigest = "recorded"
		recorded[s] = fp
	}
	calls := 0
	view.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
		calls++
		return runtimeinput.State{Digest: "recorded", OK: true}, nil
	}
	verdicts, err := view.CheckBatch(context.Background(), recorded)
	if err != nil {
		t.Fatal(err)
	}
	// Both records traverse the runtime window - the sharing claim is
	// vacuous if either stales out of it beforehand.
	for s, v := range verdicts {
		if v.Status != Valid {
			t.Fatalf("record %v did not traverse the runtime window: %+v", s, v)
		}
	}
	// Two records, one manifest, two endpoint phases: exactly two
	// evaluations - one per phase, shared across the records.
	if calls != 2 {
		t.Fatalf("shared manifest evaluated %d times across two records and two phases, want 2", calls)
	}
}

// A module legally named without a dot keeps its startup refusals: the
// standard-library cut consults the listed package metadata, never the
// import path's shape - the path heuristic classified every dotless
// module standard and silently disabled the whole startup walk for it.
func TestDotlessModuleKeepsStartupRefusals(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module probe\n\ngo 1.26\n",
		"view.go": "package probe\n\nimport \"os\"\n\nvar boot = load()\n\nfunc load() int {\n\tdata, _ := os.ReadFile(\"boot.txt\")\n\treturn len(data)\n}\n\nfunc F() int { return boot }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "probe", Symbol: "F"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ObservationProof.Observable {
		t.Fatal("dotless module's startup effect earned a proof - the startup walk was filtered out")
	}
	if !strings.Contains(fingerprint.ObservationProof.Reason, "startup effect") {
		t.Fatalf("dotless refusal = %q, want the startup effect named", fingerprint.ObservationProof.Reason)
	}
}

// The dotless-module soundness family's other two arms: package-level
// flag registrations in a dotless module are judged (a subject reading
// the registered storage refuses), and a dotless user callback
// dispatched from a harness frame stays in the test-main walk (its
// blocking effect refuses).
func TestDotlessModuleFlagAndTestMainSoundness(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Run("flag registration judged", func(t *testing.T) {
		dir := t.TempDir()
		for name, content := range map[string]string{
			"go.mod":  "module probe\n\ngo 1.26\n",
			"view.go": "package probe\n\nimport \"flag\"\n\nvar verbose = flag.Bool(\"probe-verbose\", false, \"\")\n\nfunc F() bool { return *verbose }\n",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		engine, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		subject := Subject{Package: "probe", Symbol: "F"}
		view, err := engine.newView(context.Background(), []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := view.captureObserved(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		if fingerprint.ObservationProof.Observable {
			t.Fatal("dotless module's flag-backed read earned a proof - the registration was never judged")
		}
		if !strings.Contains(fingerprint.ObservationProof.Reason, "flag-registered") {
			t.Fatalf("dotless flag refusal = %q, want the flag-registered state named", fingerprint.ObservationProof.Reason)
		}
	})
	t.Run("test-main harness callback walked", func(t *testing.T) {
		dir := t.TempDir()
		for name, content := range map[string]string{
			"go.mod":  "module probe\n\ngo 1.26\n",
			"view.go": "package probe\n\nfunc F() int { return 1 }\n",
			// The external test package is the one unfallbacked
			// module-facts population: its TestMain here pins that
			// go/packages carries Module for probe_test too.
			"main_test.go": "package probe_test\n\nimport (\n\t\"os\"\n\t\"testing\"\n\n\t\"probe\"\n)\n\nfunc TestMain(m *testing.M) {\n\ttesting.Benchmark(func(b *testing.B) {\n\t\t_ = os.WriteFile(\"probe.txt\", []byte(\"x\"), 0o600)\n\t})\n\tos.Exit(m.Run())\n}\n\nfunc TestF(t *testing.T) {\n\tif probe.F() != 1 {\n\t\tt.Fatal(\"wrong\")\n\t}\n}\n",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		engine, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		subject := Subject{Package: "probe", Symbol: "TestF"}
		view, err := engine.newView(context.Background(), []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := view.captureObserved(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		if fingerprint.ObservationProof.Observable {
			t.Fatal("dotless test-main callback's write earned a proof - the callback vanished from the walk")
		}
		// Tier-discriminating: the test-main WALK classified the
		// callback's write with the write's own reason (neither the
		// package-scan backstop's "package scan:" wording nor a leaked
		// initializer "startup effect:" may stand in for it).
		if reason := fingerprint.ObservationProof.Reason; !strings.Contains(reason, "os.WriteFile") || strings.Contains(reason, "package scan:") || strings.Contains(reason, "startup effect:") {
			t.Fatalf("refusal = %q, want the walk-tier classification of the callback's write", reason)
		}
	})
}

// Producer validation evaluates each distinct attached manifest once
// per pass: subjects sharing one encoded manifest cost one evaluation
// before and one after the re-analysis, never one per subject - the
// check window's amplification collapse on the producer path.
func TestValidateSharesManifestEvaluationAcrossSubjects(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":           "module example.com/observed\n\ngo 1.26\n",
		"observed.go":      "package observed\n\nfunc Sibling() int { return 1 }\n",
		"observed_test.go": "package observed\n\nimport (\"os\"; \"testing\")\n\nfunc TestReadA(*testing.T) { _, _ = os.ReadFile(\"fixture\") }\n\nfunc TestReadB(*testing.T) { _, _ = os.ReadFile(\"fixture\") }\n",
		"fixture":          "one",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subjects := []Subject{
		{Package: "example.com/observed", Symbol: "TestReadA"},
		{Package: "example.com/observed", Symbol: "TestReadB"},
	}
	producer, err := engine.newView(context.Background(), subjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.CompletedState(observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range subjects {
		fingerprint, err := producer.captureObserved(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := producer.AttachObservation(subject, fingerprint, observation); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	producer.runtimeCurrent = func(context.Context, string, string) (runtimeinput.State, error) {
		calls++
		return state, nil
	}
	if err := producer.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("manifest evaluations = %d, want one per validation pass", calls)
	}
}

// The execution-model attestations are part of the persisted fact
// identity: each option stamps its marker into the derived fact scope,
// so option-on and option-off sessions can never serve each other's
// facts (REQ-closure-dynamic-state-memo,
// REQ-closure-shared-dynamic-state).
func TestExecutionModelMarkersSplitTheFactScope(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	capture := func(opts ...option) string {
		t.Helper()
		var scope string
		withViewTestHooks(viewTestHookSet{
			factScope: func(s string) { scope = s },
		}, func() {
			engine, err := newEngine(append([]option{withDir(dir)}, opts...)...)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := engine.newView(context.Background(), []Subject{subject}, dir); err != nil {
				t.Fatal(err)
			}
		})
		if scope == "" {
			t.Fatal("the view derived no fact scope")
		}
		return scope
	}
	plain := capture()
	single := capture(withSingleSubjectExecution())
	pkgproc := capture(withPackageProcessExecution())
	if !strings.Contains(single, "|single-subject-execution") || plain == single {
		t.Fatalf("single-subject marker missing: plain=%q single=%q", plain, single)
	}
	if !strings.Contains(pkgproc, "|package-process-execution") || plain == pkgproc || single == pkgproc {
		t.Fatalf("package-process marker missing: plain=%q pkgproc=%q", plain, pkgproc)
	}
	both := capture(withSingleSubjectExecution(), withPackageProcessExecution())
	reverseBoth := capture(withPackageProcessExecution(), withSingleSubjectExecution())
	if both != single || reverseBoth != single {
		t.Fatalf("both-options scope did not resolve to single-subject precedence: both=%q reverse=%q single=%q", both, reverseBoth, single)
	}
}

// A sibling narrowing shares the union's facts — the package-process
// discharges included: a consumer that captures from the union and
// attaches through the sibling must see identical fingerprints
// (REQ-closure-shared-dynamic-state-reachability).
func TestSiblingCarriesPackageProcessDischarges(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	const quiet = "package app\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif !F() && F() {\n\t\tt.Fail()\n\t}\n}\n"
	dir := writeModuleTree(t, map[string]string{
		"go.mod":          "module example.com/view\n\ngo 1.26\n",
		"wire/wire.go":    "package wire\n\nvar reg func() int\n\nfunc Arm() func() {\n\treg = func() int { return 1 }\n\treturn func() { reg = nil }\n}\n\nfunc Armed() bool { return reg != nil }\n",
		"app/app.go":      "package app\n\nimport \"example.com/view/wire\"\n\nfunc F() bool { return wire.Armed() }\n",
		"app/app_test.go": quiet,
	})
	subject := Subject{Package: "example.com/view/app", Symbol: "F"}
	engine, err := newEngine(withDir(dir), withPackageProcessExecution())
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.PackageProcessDischarges == "" {
		t.Fatal("setup: the union capture carries no discharge to test the carry")
	}
	sibling, err := view.Sibling([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	siblingFP, err := sibling.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if siblingFP != fingerprint {
		t.Fatalf("sibling fingerprint diverged from the union's:\n  union   %+v\n  sibling %+v", fingerprint, siblingFP)
	}
}

// A recorded fingerprint computed under another dynamic-state strategy
// — or predating the field — re-measures rather than serving verdicts
// under semantics it was not computed by: the structural twin of the
// observation-strategy refusal
// (REQ-closure-dynamic-state-memo's serving arm).
func TestDynamicStateStrategyMoveRefusesAtCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() int { return 1 }\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.DynamicStateStrategy != DynamicStateStrategy {
		t.Fatalf("capture recorded strategy %q, want the engine's own", fingerprint.DynamicStateStrategy)
	}
	for name, recorded := range map[string]string{"moved": "gofresh/dynamic-state@1", "predates the field": ""} {
		stale := fingerprint
		stale.DynamicStateStrategy = recorded
		verdict, err := view.Check(context.Background(), stale, subject)
		if err != nil {
			t.Fatal(err)
		}
		if verdict.Status != Stale || verdict.Reason != "dynamic-state strategy" {
			t.Fatalf("%s: verdict = %+v, want the strategy refusal", name, verdict)
		}
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("current-strategy verdict = %+v, want Valid", verdict)
	}
}

// The analysis budget bounds the dynamic-state discharges' reachability
// analysis exactly as it bounds the observability proof: a pass the
// budget cuts leaves the culprit STANDING — the subject keeps its
// refusal, nothing is discharged, never validity — reports the
// exhaustion once with the count of subjects left undischarged, and
// persists no scan facts, so the next unbounded pass derives cold and
// discharges; a cut in one pass of a comparing pair is the pass's fact,
// never drift (REQ-fresh-context,
// REQ-closure-shared-dynamic-state-reachability).
func TestAnalysisBudgetCutLeavesTheCulpritStanding(t *testing.T) {
	if testing.Short() {
		t.Skip("builds module fixtures and runs the engine over them")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	capture := func(t *testing.T, dir string, subject Subject, opts ...option) (Fingerprint, Verdict, []string) {
		t.Helper()
		var mu sync.Mutex
		var cuts []string
		opts = append([]option{withDir(dir), withProgress(func(p Progress) {
			if p.Phase == "budget-exhausted" {
				mu.Lock()
				defer mu.Unlock()
				cuts = append(cuts, p.Detail)
			}
		})}, opts...)
		engine, err := newEngine(opts...)
		if err != nil {
			t.Fatal(err)
		}
		view, err := engine.newView(context.Background(), []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := view.Capture(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		verdict, err := view.Check(context.Background(), fingerprint, subject)
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		return fingerprint, verdict, cuts
	}
	t.Run("single-subject discharge", func(t *testing.T) {
		loads := 0
		withViewTestHooks(viewTestHookSet{
			typedLoad: func() { loads++ },
		}, func() {
			dir := writeModuleTree(t, map[string]string{
				"go.mod":     "module example.com/view\n\ngo 1.26\n",
				"gen/gen.go": "package gen\n\nvar memo = map[string]func(){}\n\nfunc Compile(name string) { memo[name] = func() {} }\n\nfunc Size() int { return len(memo) }\n",
				"view.go":    "package view\n\nimport \"example.com/view/gen\"\n\nfunc F() int { return gen.Size() }\n\nfunc Property() { gen.Compile(\"k\") }\n",
			})
			subject := Subject{Package: "example.com/view", Symbol: "F"}
			fingerprint, verdict, cuts := capture(t, dir, subject, withSingleSubjectExecution(), withAnalysisBudget(time.Nanosecond))
			if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/gen.memo is mutated") || !strings.Contains(verdict.Reason, "(reachability unjudged: analysis budget 1ns exhausted)") {
				t.Fatalf("verdict under a cut budget = %+v, want the downgrade naming gen.memo AND the budget — a cut discharges nothing and the record says why", verdict)
			}
			if fingerprint.SingleSubjectDischarges != "" {
				t.Fatalf("a cut pass recorded a discharge: %q", fingerprint.SingleSubjectDischarges)
			}
			// The pass judges every downgraded subject of the scanned
			// package (F and Property both carry gen.memo), and the view's
			// construction pair is two observation passes — one event
			// each, never one per subject.
			if want := []string{"analysis budget 1ns exhausted: 2 subjects undischarged", "analysis budget 1ns exhausted: 2 subjects undischarged"}; !slices.Equal(cuts, want) {
				t.Fatalf("budget-exhausted events = %q, want %q (once per pass, with the pass's count)", cuts, want)
			}
			// The cut persisted no scan facts: the unbounded pass pays its
			// typed load and discharges; the pass after it is served.
			loads = 0
			fingerprint, verdict, cuts = capture(t, dir, subject, withSingleSubjectExecution())
			if verdict.Status != Valid || fingerprint.SingleSubjectDischarges != "example.com/view/gen.memo" || len(cuts) != 0 {
				t.Fatalf("the unbounded pass after a cut = %+v / %q / %q, want the discharge", verdict, fingerprint.SingleSubjectDischarges, cuts)
			}
			if loads == 0 {
				t.Fatal("the unbounded pass paid no typed load — the cut pass persisted its undischarged scan")
			}
			loads = 0
			capture(t, dir, subject, withSingleSubjectExecution())
			if loads != 0 {
				t.Fatalf("the pass after a complete derivation paid %d typed loads — the derivation did not persist", loads)
			}
		})
	})
	t.Run("an operation cancelled at the discharge is never a budget cut", func(t *testing.T) {
		dir := writeModuleTree(t, map[string]string{
			"go.mod":     "module example.com/view\n\ngo 1.26\n",
			"gen/gen.go": "package gen\n\nvar memo = map[string]func(){}\n\nfunc Compile(name string) { memo[name] = func() {} }\n\nfunc Size() int { return len(memo) }\n",
			"view.go":    "package view\n\nimport \"example.com/view/gen\"\n\nfunc F() int { return gen.Size() }\n\nfunc Property() { gen.Compile(\"k\") }\n",
		})
		// A cache home of its own: the first arm persisted this
		// content's discharged scan, which would serve the pass whole
		// before any discharge ran.
		t.Setenv("XDG_CACHE_HOME", t.TempDir())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var mu sync.Mutex
		var cuts []string
		withViewTestHooks(viewTestHookSet{
			beforeDischarge: cancel,
		}, func() {
			engine, err := newEngine(withDir(dir), withSingleSubjectExecution(), withAnalysisBudget(time.Minute), withProgress(func(p Progress) {
				if p.Phase == "budget-exhausted" {
					mu.Lock()
					defer mu.Unlock()
					cuts = append(cuts, p.Detail)
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := engine.newView(ctx, []Subject{{Package: "example.com/view", Symbol: "F"}}, dir); !errors.Is(err, context.Canceled) {
				t.Fatalf("a view construction cancelled at the discharge = %v, want the operation's cancellation", err)
			}
		})
		mu.Lock()
		defer mu.Unlock()
		if len(cuts) != 0 {
			t.Fatalf("the operation's cancellation was reported as a budget cut: %q", cuts)
		}
	})
	// A cut in ONE pass of a comparing pair is the pass's fact, never the
	// tree's: the construction pair builds the view when its first or
	// its second pass alone is cut (taking the cut pass's fail-closed
	// shape), and a validation whose re-observation alone is cut reports
	// the analysis's unavailability, never drift. The deadline factory
	// expires exactly one pass. A pass after a completed one is
	// served by the scan memo before any discharge runs, so the cut pass
	// is given a fresh cache home at its observation — the cache-loss
	// shape, the one route to a cut re-observation of an unchanged tree.
	const straddleBudget = 10 * time.Second
	withStraddle := func(t *testing.T, cutPass int, fn func(Fingerprint, Verdict, []string, *Snapshot)) {
		t.Helper()
		t.Setenv("XDG_CACHE_HOME", t.TempDir())
		observations := 0
		dir := writeModuleTree(t, map[string]string{
			"go.mod":     "module example.com/view\n\ngo 1.26\n",
			"gen/gen.go": "package gen\n\nvar memo = map[string]func(){}\n\nfunc Compile(name string) { memo[name] = func() {} }\n\nfunc Size() int { return len(memo) }\n",
			"view.go":    "package view\n\nimport \"example.com/view/gen\"\n\nfunc F() int { return gen.Size() }\n\nfunc Property() { gen.Compile(\"k\") }\n",
		})
		// Keyed on the observation count, not on boundary calls: a memo
		// hit runs no discharge, and the proof has its own analysis boundary.
		injected, discharged := 0, 0
		pending := false
		withViewTestHooks(viewTestHookSet{
			observe: func() {
				observations++
				if observations == cutPass && cutPass > 1 {
					t.Setenv("XDG_CACHE_HOME", t.TempDir())
				}
			},
			analysisBound: func(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
				if budget != straddleBudget {
					t.Fatalf("analysis budget = %s, want %s", budget, straddleBudget)
				}
				if observations == cutPass && injected == 0 {
					injected++
					pending = true
					return context.WithDeadline(ctx, time.Now().Add(-time.Second))
				}
				return context.WithTimeout(ctx, budget)
			},
			beforeDischarge: func() {
				if pending {
					if observations != cutPass {
						t.Fatalf("expired pass %d reached discharge in pass %d", cutPass, observations)
					}
					discharged++
					pending = false
				}
			},
		}, func() {
			var mu sync.Mutex
			var cuts []string
			engine, err := newEngine(withDir(dir), withSingleSubjectExecution(), withAnalysisBudget(straddleBudget), withProgress(func(p Progress) {
				if p.Phase == "budget-exhausted" {
					mu.Lock()
					defer mu.Unlock()
					cuts = append(cuts, p.Detail)
				}
			}))
			if err != nil {
				t.Fatal(err)
			}
			subject := Subject{Package: "example.com/view", Symbol: "F"}
			view, err := engine.newView(context.Background(), []Subject{subject}, dir)
			if err != nil {
				t.Fatalf("a construction pair with pass %d cut refused: %v — a cut is the pass's fact, never the tree's", cutPass, err)
			}
			fingerprint, err := view.Capture(context.Background(), subject)
			if err != nil {
				t.Fatal(err)
			}
			verdict, err := view.Check(context.Background(), fingerprint, subject)
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			copiedCuts := append([]string(nil), cuts...)
			mu.Unlock()
			fn(fingerprint, verdict, copiedCuts, view)
		})
		if injected != 1 || discharged != 1 {
			t.Errorf("target pass %d: injected=%d discharged=%d, want one each", cutPass, injected, discharged)
		}
	}
	for _, cutPass := range []int{1, 2} {
		t.Run(fmt.Sprintf("construction pair with pass %d cut builds fail-closed", cutPass), func(t *testing.T) {
			withStraddle(t, cutPass, func(fingerprint Fingerprint, verdict Verdict, cuts []string, _ *Snapshot) {
				if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "gen.memo is mutated") || !strings.Contains(verdict.Reason, "(reachability unjudged: analysis budget 10s exhausted)") || fingerprint.SingleSubjectDischarges != "" {
					t.Fatalf("pass %d cut: verdict %+v, discharges %q — want the cut pass's fail-closed shape naming the budget", cutPass, verdict, fingerprint.SingleSubjectDischarges)
				}
				if want := []string{"analysis budget 10s exhausted: 2 subjects undischarged"}; !slices.Equal(cuts, want) {
					t.Fatalf("pass %d cut: events %q, want %q (the cut pass alone reports)", cutPass, cuts, want)
				}
			})
		})
	}
	t.Run("a capture after a cut construction keeps the fail-closed facts; its validation reports the cut last", func(t *testing.T) {
		// Pass 1 cut, pass 2 served from nothing (the cut persisted no
		// facts) and discharged: the view is fail-closed. The capture's
		// closing pass is served discharged — a difference the cut alone
		// explains — and the capture SUCCEEDS; the observed validation
		// then reports that unavailability after every other check.
		withStraddle(t, 1, func(_ Fingerprint, _ Verdict, _ []string, view *Snapshot) {
			subject := Subject{Package: "example.com/view", Symbol: "F"}
			fingerprint, err := view.captureObserved(context.Background(), subject)
			if err != nil {
				t.Fatalf("CaptureObserved after a cut construction = %v, want the capture to keep the view's fail-closed facts", err)
			}
			if verdict, err := view.Check(context.Background(), fingerprint, subject); err != nil || verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "(reachability unjudged: analysis budget 10s exhausted)") {
				t.Fatalf("the captured record's verdict = %+v (%v), want the cut's fail-closed refusal naming the budget", verdict, err)
			}
			// A stable attached observation: the observed validation runs
			// every other check (all holding) and then reports the cut.
			dir := view.moduleDir
			if err := os.WriteFile(filepath.Join(dir, "fixture"), []byte("stable"), 0o644); err != nil {
				t.Fatal(err)
			}
			observation, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := view.AttachObservation(subject, fingerprint, observation); err != nil {
				t.Fatal(err)
			}
			if err := view.Validate(context.Background()); !errors.Is(err, ErrAnalysisUnavailable) {
				t.Fatalf("validation after a cut construction = %v, want ErrAnalysisUnavailable (held, reported last)", err)
			}
		})
	})
	t.Run("a moved runtime input outranks a cut re-observation", func(t *testing.T) {
		// Passes 1 and 2 build the view uncut, the capture's closing pass
		// is observation 3; the attached observation's fixture moves; the
		// validation's re-observation (observation 4) is cut. The moved
		// input is drift and is reported — the cut's unavailability waits
		// behind every other check.
		withStraddle(t, 4, func(_ Fingerprint, _ Verdict, _ []string, view *Snapshot) {
			subject := Subject{Package: "example.com/view", Symbol: "F"}
			fingerprint, err := view.captureObserved(context.Background(), subject)
			if err != nil {
				t.Fatal(err)
			}
			dir := view.moduleDir
			fixture := filepath.Join(dir, "fixture")
			if err := os.WriteFile(fixture, []byte("before"), 0o644); err != nil {
				t.Fatal(err)
			}
			observation, err := riFromTestLog([]byte("open fixture\n"), dir, dir, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := view.AttachObservation(subject, fingerprint, observation); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fixture, []byte("after"), 0o644); err != nil {
				t.Fatal(err)
			}
			err = view.Validate(context.Background())
			if !errors.Is(err, ErrViewChanged) || errors.Is(err, ErrAnalysisUnavailable) {
				t.Fatalf("validation with a moved input and a cut re-observation = %v, want the moved input reported as drift, the cut held behind it", err)
			}
		})
	})
	t.Run("a validation cut alone reports unavailability, never drift", func(t *testing.T) {
		// Passes 1 and 2 build the view uncut (discharged); the third
		// pass — the validation's re-observation — is cut.
		withStraddle(t, 3, func(_ Fingerprint, _ Verdict, _ []string, view *Snapshot) {
			err := view.Validate(context.Background())
			if !errors.Is(err, ErrAnalysisUnavailable) || !strings.Contains(err.Error(), "example.com/view.F") {
				t.Fatalf("validation under a cut re-observation = %v, want ErrAnalysisUnavailable naming the subject", err)
			}
		})
	})
	t.Run("package-process discharge", func(t *testing.T) {
		dir := writeModuleTree(t, map[string]string{
			"go.mod":          "module example.com/view\n\ngo 1.26\n",
			"wire/wire.go":    "package wire\n\nvar reg func() int\n\nfunc Arm() func() {\n\treg = func() int { return 1 }\n\treturn func() { reg = nil }\n}\n\nfunc Armed() bool { return reg != nil }\n",
			"app/app.go":      "package app\n\nimport \"example.com/view/wire\"\n\nfunc F() bool { return wire.Armed() }\n",
			"app/app_test.go": "package app\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif !F() && F() {\n\t\tt.Fail()\n\t}\n}\n",
		})
		subject := Subject{Package: "example.com/view/app", Symbol: "F"}
		fingerprint, verdict, cuts := capture(t, dir, subject, withPackageProcessExecution(), withAnalysisBudget(time.Nanosecond))
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/wire.reg is mutated") || fingerprint.PackageProcessDischarges != "" {
			t.Fatalf("verdict under a cut budget = %+v / %q, want the downgrade naming wire.reg and no discharge", verdict, fingerprint.PackageProcessDischarges)
		}
		// F and TestF both carry wire.reg; two passes, one event each.
		if want := []string{"analysis budget 1ns exhausted: 2 subjects undischarged", "analysis budget 1ns exhausted: 2 subjects undischarged"}; !slices.Equal(cuts, want) {
			t.Fatalf("budget-exhausted events = %q, want %q", cuts, want)
		}
		if _, verdict, _ := capture(t, dir, subject, withPackageProcessExecution()); verdict.Status != Valid {
			t.Fatalf("the unbounded pass after a cut = %+v, want the binary-scoped discharge", verdict)
		}
	})
}

// One observation pass performs at most one typed package load — the subject
// scan and the closure tier's testing-type effect scan share it — and a
// pass whose package scan the store already holds under the pass's own
// recomputed key performs none (REQ-closure-scan-memo): over a cold store
// view construction's paired observations load exactly once, the second
// pass serving the first's scan, and a warm store serves both
// (REQ-fresh-coherent-view: no same-pass mixture; the key re-derived from
// the bytes each pass keeps the passes independent witnesses).
// The count is taken at the go-command boundary: every typed load drives
// exactly one `go list … -json=<fields> …` invocation. That one-call-per-Load
// shape is github.com/greatliontech/go-x-tools/go/packages driver behavior,
// not a gofresh property — if a go-x-tools upgrade changes how many list calls
// one Load issues, this count moves without any sharing regression; recalibrate
// the expected count against a single packages.Load before suspecting the code.
func TestViewObservationPassPerformsOneTypedLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shimDir := t.TempDir()
	logPath := filepath.Join(shimDir, "typed-loads.log")
	script := "#!/bin/sh\nfor arg in \"$@\"; do\n\tcase \"$arg\" in\n\t-json=*) echo typed-load >> " + logPath + " ;;\n\tesac\ndone\nexec " + realGo + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shimDir, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":      "module example.com/oneload\n\ngo 1.26\n",
		"lib.go":      "package oneload\n\nfunc F() int { return 1 }\n",
		"lib_test.go": "package oneload\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.newViewFor(context.Background(), []Subject{{Package: "example.com/oneload", Symbol: "F"}}, dir, CodeResult); err != nil {
		t.Fatal(err)
	}

	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("no typed loads logged at all: %v", err)
	}
	if got := strings.Count(string(logged), "typed-load"); got != 1 {
		t.Fatalf("cold view construction drove %d typed package loads, want exactly 1 (the first pass; the second serves its scan)", got)
	}
	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.newViewFor(context.Background(), []Subject{{Package: "example.com/oneload", Symbol: "F"}}, dir, CodeResult); err != nil {
		t.Fatal(err)
	}
	if logged, err := os.ReadFile(logPath); !os.IsNotExist(err) {
		t.Fatalf("warm view construction drove %d typed package loads (read error %v), want none", strings.Count(string(logged), "typed-load"), err)
	}
}

// One observation pass performs one `go env -json` read (the snapshot) and
// derives GOFLAGS validation, GOMODCACHE, and the toolchain guard from it
// (REQ-guard-toolchain: GOVERSION with the host platform — no live `go
// version` probe). Construction's pair therefore shows exactly two env
// reads, zero version probes, and zero single-key env execs (the
// batched-probe contract). The env-json
// matcher is x/tools-version-coupled: some driver versions issue key-scoped
// `go env -json GOMOD` calls that would match the same arm - if this count
// moves on an x/tools upgrade, recalibrate against a single packages.Load
// before suspecting the batching.
func TestViewObservationPassBatchesToolchainProbes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	realGo, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shimDir := t.TempDir()
	logPath := filepath.Join(shimDir, "probes.log")
	script := "#!/bin/sh\ncase \"$1 $2\" in\n\"env -json\") echo env-json >> " + logPath + " ;;\n\"env GOFLAGS\") echo env-goflags >> " + logPath + " ;;\n\"env GOMODCACHE\") echo env-gomodcache >> " + logPath + " ;;\n\"version \") echo version >> " + logPath + " ;;\nesac\nexec " + realGo + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(shimDir, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":      "module example.com/probes\n\ngo 1.26\n",
		"lib.go":      "package probes\n\nfunc F() int { return 1 }\n",
		"lib_test.go": "package probes\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	// Engine construction performs its own one-time validation probe; the
	// batched-probe contract is per observation pass, so the count window
	// opens here.
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.newViewFor(context.Background(), []Subject{{Package: "example.com/probes", Symbol: "F"}}, dir, CodeResult); err != nil {
		t.Fatal(err)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("no probes logged: %v", err)
	}
	counts := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(logged)), "\n") {
		counts[line]++
	}
	if counts["env-json"] != 2 || counts["version"] != 0 || counts["env-goflags"] != 0 || counts["env-gomodcache"] != 0 {
		t.Fatalf("construction probe counts = %v, want env-json:2, no version probe, and no single-key env execs", counts)
	}
}

// A second view over an unchanged tree serves every view package's scan
// from the memo — no typed load — with outputs identical to the cold
// view's (REQ-closure-scan-memo).
func TestScanMemoServesTheWholeScanWithoutATypedLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := scanMemoModule(t)
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	cold, err := engine.newView(context.Background(), scanMemoSubjects, dir)
	if err != nil {
		t.Fatal(err)
	}
	want := scanOutputs(t, cold, scanMemoSubjects)
	if cold.facts.source == nil {
		t.Fatal("cold construction discarded its shared typed inputs")
	}
	loads := 0
	var events []Progress
	var warm *Snapshot
	withViewTestHooks(viewTestHookSet{
		typedLoad: func() { loads++ },
	}, func() {
		warmEngine, err := newEngine(withDir(dir), withProgress(func(p Progress) { events = append(events, p) }))
		if err != nil {
			t.Fatal(err)
		}
		warm, err = warmEngine.newView(context.Background(), scanMemoSubjects, dir)
		if err != nil {
			t.Fatal(err)
		}
	})
	if loads != 0 {
		t.Fatalf("the warm view paid %d typed loads", loads)
	}
	if warm.facts.source != nil {
		t.Fatal("warm memo invented a typed source generation")
	}
	for _, subject := range scanMemoSubjects {
		if !cold.facts.maximal[subject].equal(warm.facts.maximal[subject], false) {
			t.Fatalf("complete base facts differ across cold/warm paths for %v", subject)
		}
	}
	served, testingServed, typechecks := 0, 0, 0
	for _, e := range events {
		switch {
		case e.Phase == "served" && e.Served == "scan" && e.Index == 1:
			served++
		case e.Phase == "served" && e.Served == "testing scan" && e.Index == 1:
			testingServed++
		case e.Phase == "typecheck":
			typechecks++
		}
	}
	if served != 1 {
		t.Fatalf("scan served summaries = %d, want one for the view package: %+v", served, events)
	}
	// The pass's memo scope arms the testing-effect scan memo too: the
	// warm fold serves it and performs no typed load of its own.
	if testingServed != 1 || typechecks != 0 {
		t.Fatalf("testing-scan served summaries = %d, typecheck events = %d; want 1 and 0: %+v", testingServed, typechecks, events)
	}
	if got := scanOutputs(t, warm, scanMemoSubjects); !reflect.DeepEqual(got, want) {
		t.Fatalf("served scan differs from the cold one:\n got %v\nwant %v", got, want)
	}
	// The outputs themselves carry the marks the memo must reproduce.
	if !strings.Contains(want[scanMemoSubjects[1]], "unverifiable") || !strings.Contains(want[scanMemoSubjects[2]], "external directive") {
		t.Fatalf("fixture no longer exercises the dynamic and external marks: %v", want)
	}
}

// A vouch is load-bearing for the discharges an entry records, so a
// changed vouch set misses; a corrupt entry recomputes.
func TestScanMemoMissesOnVouchChangeAndCorruption(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	dir := scanMemoModule(t)
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.newView(context.Background(), scanMemoSubjects, dir); err != nil {
		t.Fatal(err)
	}
	loads := 0
	withViewTestHooks(viewTestHookSet{
		typedLoad: func() { loads++ },
	}, func() {
		// The option takes the canonical dotted identity (REQ-vouch-input);
		// the file below spells the same vouch in its own grammar.
		vouched, err := newEngine(withDir(dir), withDynamicStateVouches("example.com/scanmemo/dep.Hooks"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := vouched.newView(context.Background(), scanMemoSubjects, dir); err != nil {
			t.Fatal(err)
		}
		if loads == 0 {
			t.Fatal("a changed vouch set served the unvouched scan")
		}
		// An engine with the same vouch set serves the vouched scan, and a
		// changed vouch set misses — a persisted entry never serves a discharge
		// under another set.
		loads = 0
		sameVouch, err := newEngine(withDir(dir), withDynamicStateVouches("example.com/scanmemo/dep.Hooks"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sameVouch.newView(context.Background(), scanMemoSubjects, dir); err != nil {
			t.Fatal(err)
		}
		if loads != 0 {
			t.Fatalf("an equal vouch set recomputed (%d loads), want served", loads)
		}
		changed, err := newEngine(withDir(dir), withDynamicStateVouches("example.com/scanmemo/dep.Hooks", "example.com/scanmemo/dep.Other"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := changed.newView(context.Background(), scanMemoSubjects, dir); err != nil {
			t.Fatal(err)
		}
		if loads == 0 {
			t.Fatal("a changed vouch set served the prior scan")
		}
		// Corrupt every scan entry: the next view recomputes silently.
		entries, _ := filepath.Glob(filepath.Join(cache, "gofresh", "scanfacts", "*.json"))
		if len(entries) == 0 {
			t.Fatal("no scan entries persisted")
		}
		for _, e := range entries {
			if err := os.WriteFile(e, []byte("{not json"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		loads = 0
		if _, err := engine.newView(context.Background(), scanMemoSubjects, dir); err != nil {
			t.Fatal(err)
		}
		if loads == 0 {
			t.Fatal("a corrupt entry served")
		}
	})
}

// The key moves under any source edit inside the view package's
// test-binary graph and holds under an edit outside it, so a served
// scan never describes a program other than the current one
// (REQ-closure-scan-memo). A comment-only edit preserves public source
// equivalence under REQ-closure-canonical-member, but invalidates the private
// raw-source key that protects position-bearing scan payloads.
func TestScanMemoKeyTracksTheTestBinaryGraph(t *testing.T) {
	if testing.Short() {
		t.Skip("builds module fixtures and runs the engine over them")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := scanMemoModule(t)
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.newView(context.Background(), scanMemoSubjects, dir); err != nil {
		t.Fatal(err)
	}
	loads := 0
	withViewTestHooks(viewTestHookSet{
		typedLoad: func() { loads++ },
	}, func() {
		for _, tc := range []struct {
			path   string
			inside bool
		}{
			{"dep/dep.go", true}, {"view/view.go", true}, {"view/view_test.go", true}, {"other/other.go", false},
		} {
			for _, name := range []string{"a", "second"} {
				full := filepath.Join(dir, filepath.FromSlash(tc.path))
				original, err := os.ReadFile(full)
				if err != nil {
					t.Fatal(err)
				}
				// A source edit: a new declaration, never a comment.
				if err := os.WriteFile(full, append(append([]byte(nil), original...), []byte("\nvar _ = \""+name+"\"\n")...), 0o644); err != nil {
					t.Fatal(err)
				}
				loads = 0
				_, err = engine.newView(context.Background(), scanMemoSubjects, dir)
				if restoreErr := os.WriteFile(full, original, 0o644); restoreErr != nil {
					t.Fatal(restoreErr)
				}
				if err != nil {
					t.Fatal(err)
				}
				if tc.inside && loads == 0 {
					t.Fatalf("an edit to %s (inside the graph) served the stale scan", tc.path)
				}
				if !tc.inside && loads != 0 {
					t.Fatalf("an edit to %s (outside the graph) missed the scan memo", tc.path)
				}
			}
			// Core equivalence ignores ordinary comments, but position-bearing
			// scan payloads have an additional raw-source dependency.
			if !tc.inside || strings.HasSuffix(tc.path, "_test.go") {
				continue
			}
			full := filepath.Join(dir, filepath.FromSlash(tc.path))
			original, err := os.ReadFile(full)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, append(append([]byte(nil), original...), []byte("\n// a comment\n")...), 0o644); err != nil {
				t.Fatal(err)
			}
			loads = 0
			changedView, viewErr := engine.newView(context.Background(), scanMemoSubjects, dir)
			if restoreErr := os.WriteFile(full, original, 0o644); restoreErr != nil {
				t.Fatal(restoreErr)
			}
			if viewErr != nil {
				t.Fatal(viewErr)
			}
			if loads == 0 {
				t.Fatalf("a comment-only edit to %s served a spelling-sensitive scan", tc.path)
			}
			restoredView, err := engine.newView(context.Background(), scanMemoSubjects, dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, subject := range scanMemoSubjects {
				if changedView.facts.closure(subject).Hash != restoredView.facts.closure(subject).Hash {
					t.Fatal("comment edit moved public core equivalence")
				}
			}
		}
	})
}

// The shared-dynamic-state judgment is per package graph: a view batching
// several packages yields for each exactly what its solitary view yields,
// a mutation linked only by a sibling's binary never opens a package, and
// a pass mixing served and derived packages reproduces the cold outputs
// (REQ-closure-shared-dynamic-state, REQ-closure-scan-memo).
func TestScanMemoComposesEachPackageOverItsOwnGraph(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := leakModule(t)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	batch := scanOutputs(t, newLeakView(t, dir, leakSubjects), leakSubjects)
	if !strings.Contains(batch[leakA], "|verifiable|") {
		t.Fatalf("a mutation linked only by b's binary opened a: %s", batch[leakA])
	}
	if !strings.Contains(batch[leakB], "example.com/leak/d.Callback") {
		t.Fatalf("b's own graph links the mutation yet b is not downgraded on it: %s", batch[leakB])
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	soloA := scanOutputs(t, newLeakView(t, dir, leakSubjects[:1]), leakSubjects[:1])
	soloB := scanOutputs(t, newLeakView(t, dir, leakSubjects[1:]), leakSubjects[1:])
	if soloA[leakA] != batch[leakA] || soloB[leakB] != batch[leakB] {
		t.Fatalf("batched view differs from the solitary views:\nbatch %v\nsolo  %v %v", batch, soloA, soloB)
	}
	// A cache warmed by a's solitary view serves a into the batched pass
	// while b derives — the served half and the derived half agree with
	// the cold batch.
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	newLeakView(t, dir, leakSubjects[:1])
	loads := 0
	var events []Progress
	var mixed *Snapshot
	withViewTestHooks(viewTestHookSet{
		typedLoad: func() { loads++ },
	}, func() {
		mixed = newLeakView(t, dir, leakSubjects, withProgress(func(p Progress) { events = append(events, p) }))
	})
	// One typed load: b derives in the first pass beside the served a;
	// the agreement pass then serves both from the store.
	if loads != 1 {
		t.Fatalf("typed loads = %d, want one for b", loads)
	}
	servedScans := 0
	for _, e := range events {
		if e.Phase == "served" && e.Served == "scan" {
			servedScans += e.Index
		}
	}
	if servedScans != 2 {
		t.Fatalf("scan packages served = %d, want both by the operation's end", servedScans)
	}
	if got := scanOutputs(t, mixed, leakSubjects); !reflect.DeepEqual(got, batch) {
		t.Fatalf("mixed served/derived pass differs from the cold batch:\n got %v\nwant %v", got, batch)
	}
}

// An entry of another shape — a version the reader does not speak —
// recomputes rather than serving (REQ-closure-scan-memo).
func TestScanMemoRefusesAnEntryOfAnotherShape(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	dir := scanMemoModule(t)
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.newView(context.Background(), scanMemoSubjects, dir); err != nil {
		t.Fatal(err)
	}
	entries, _ := filepath.Glob(filepath.Join(cache, "gofresh", "scanfacts", "*.json"))
	if len(entries) == 0 {
		t.Fatal("no scan entries persisted")
	}
	for _, e := range entries {
		raw, err := os.ReadFile(e)
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Scope   string          `json:"scope"`
			Key     string          `json:"key"`
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		if string(payload["version"]) != strconv.Itoa(scanEntryVersion) {
			t.Fatalf("entry %s carries version %s, want %d", e, payload["version"], scanEntryVersion)
		}
		payload["version"] = json.RawMessage("0")
		envelope.Payload, _ = json.Marshal(payload)
		rewritten, _ := json.Marshal(envelope)
		if err := os.WriteFile(e, rewritten, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	loads := 0
	withViewTestHooks(viewTestHookSet{
		typedLoad: func() { loads++ },
	}, func() {
		if _, err := engine.newView(context.Background(), scanMemoSubjects, dir); err != nil {
			t.Fatal(err)
		}
	})
	if loads == 0 {
		t.Fatal("an entry of another version served")
	}
}

// An entry is stored after the attestation-scoped discharges finished
// shaping the scan, so a served scan carries the discharge and its
// record exactly as the cold derivation did (REQ-closure-scan-memo).
func TestScanMemoServesTheDischargedScan(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	for path, content := range map[string]string{
		"go.mod":     "module example.com/view\n\ngo 1.26\n",
		"gen/gen.go": "package gen\n\nvar memo = map[string]func(){}\n\nfunc Compile(name string) { memo[name] = func() {} }\n\nfunc Size() int { return len(memo) }\n",
		"view.go":    "package view\n\nimport \"example.com/view/gen\"\n\nfunc F() int { return gen.Size() }\n\nfunc Property() { gen.Compile(\"k\") }\n",
	} {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	subjects := []Subject{{Package: "example.com/view", Symbol: "F"}, {Package: "example.com/view", Symbol: "Property"}}
	cold := scanOutputs(t, newLeakView(t, dir, subjects, withSingleSubjectExecution()), subjects)
	if !strings.Contains(cold[subjects[0]], "|verifiable|") || !strings.HasSuffix(cold[subjects[0]], "|example.com/view/gen.memo") {
		t.Fatalf("the attestation did not discharge F's culprit on record: %s", cold[subjects[0]])
	}
	loads := 0
	var warm map[Subject]string
	withViewTestHooks(viewTestHookSet{
		typedLoad: func() { loads++ },
	}, func() {
		warm = scanOutputs(t, newLeakView(t, dir, subjects, withSingleSubjectExecution()), subjects)
	})
	if loads != 0 {
		t.Fatalf("the warm view paid %d typed loads", loads)
	}
	if !reflect.DeepEqual(warm, cold) {
		t.Fatalf("served discharged scan differs from the cold one:\n got %v\nwant %v", warm, cold)
	}
}

// TestObservedCaptureReusesConstructionSnapshot pins that the
// precise-analysis bracket derives its env-derived configuration from the
// view's construction snapshot: the process environment is immutable
// analysis configuration, so re-reading go env would cost two process
// executions per capture batch and could only agree.
func TestObservedCaptureReusesConstructionSnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	var seen *gotool.EnvSnapshot
	withViewTestHooks(viewTestHookSet{
		snapshot: func(s *gotool.EnvSnapshot) { seen = s },
	}, func() {
		view, err := engine.newView(context.Background(), []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		if view.facts.snapshot == nil {
			t.Fatal("view retained no construction snapshot")
		}
		if _, err := view.captureObserved(context.Background(), subject); err != nil {
			t.Fatal(err)
		}
		if seen != view.facts.snapshot {
			t.Fatalf("bracket snapshot = %p, want the construction snapshot %p", seen, view.facts.snapshot)
		}
	})
}

// TestObservedCaptureRefusesMidWindowOverlayBeforeAnyLoad pins the
// bracket's live build-flag revalidation: an overlay written to the go env
// file after view construction refuses before any load whose derivations
// could persist to the observability memo — no load or prove phase runs.
// GOENV redirects the go command's env file to a sandbox path, so the
// user's real configuration is never touched.
func TestObservedCaptureRefusesMidWindowOverlayBeforeAnyLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	goenv := filepath.Join(t.TempDir(), "goenv")
	if err := os.WriteFile(goenv, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var phases []string
	var mu sync.Mutex
	// Replace, never append: the ambient environment may itself carry
	// GOENV (a stipulator witness run does), and the engine rejects
	// duplicate keys by design.
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GOENV=") {
			env = append(env, kv)
		}
	}
	env = append(env, "GOENV="+goenv)
	engine, err := newEngine(
		withDir(dir),
		withEnv(env...),
		withProgress(func(p Progress) {
			mu.Lock()
			phases = append(phases, p.Phase)
			mu.Unlock()
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	phases = nil
	mu.Unlock()
	if err := os.WriteFile(goenv, []byte("GOFLAGS=-overlay=/absent.json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = view.captureObserved(context.Background(), subject)
	if err == nil || !strings.Contains(err.Error(), "overlay") {
		t.Fatalf("mid-window overlay capture = %v, want the build-flag overlay refusal", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, phase := range phases {
		if phase == "load" || phase == "prove" {
			t.Fatalf("phase %q ran after the overlay was written; refusal must precede any load (phases: %v)", phase, phases)
		}
	}
}

// An external-test twin's directive must never confer purity on the
// production declaration it collides with: the collapsed identity refuses
// capture — unverifiable evidence naming both declarations, no purity
// attribution — while the view itself builds (the refusal is scoped to
// the subject, REQ-purity-directive).
func TestExternalTestSubjectCollisionRefusesCaptureSubjectLocally(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\nfunc F() { _, _ = os.ReadFile(\"fixture\") }\n")
	if err := os.WriteFile(filepath.Join(dir, "external_test.go"), []byte("package view_test\n\n//gofresh:pure\nfunc F() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatalf("subject-local collision failed the whole view: %v", err)
	}
	fingerprint, err := view.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.PurityAssertion != "" {
		t.Fatalf("external twin's directive conferred purity on the collapsed identity: %q", fingerprint.PurityAssertion)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "ambiguous") {
		t.Fatalf("collapsed identity verdict = %+v, want unverifiable naming the collision", verdict)
	}
}

// A standard-interface call devirtualized onto its resolved concrete target
// is classified by that target, not widened: the observation proof names the
// resolved testing.TempDir effect.
func TestResolvedStandardInterfaceTargetIsClassified(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n")
	source := "package view\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { var value interface{ TempDir() string } = t; _ = value.TempDir() }\n"
	if err := os.WriteFile(filepath.Join(dir, "interface_test.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "TestF"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "testing.TempDir") {
		t.Fatalf("resolved standard interface target = %+v, want testing.TempDir named", fingerprint.ObservationProof)
	}
}

func TestUnauditedStandardOperationIsUnverifiable(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nimport \"time\"\n\nfunc F() int64 { return time.Now().UnixNano() }\n")
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "time") {
		t.Fatalf("time.Now verdict = %+v, want unverifiable naming time", verdict)
	}
	// The precise classification lives in the observation proof.
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "unaudited standard operation time.Now") {
		t.Fatalf("time.Now proof = %+v, want unaudited-standard classification", fingerprint.ObservationProof)
	}
}

// A callback handed to a standard-library operation is classified by its
// resolved target — the observation proof names os.Getenv — never widened
// into a blanket refusal.
func TestExternalCallbackFromStandardLibraryIsClassified(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nimport (\"os\"; \"regexp\")\n\nfunc F() string { return regexp.MustCompile(\".\").ReplaceAllStringFunc(\"X\", os.Getenv) }\n")
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "os.Getenv") {
		t.Fatalf("standard-library external callback = %+v, want os.Getenv named", fingerprint.ObservationProof)
	}
}

func TestStandardGlobalStateIsUnverifiable(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nimport \"os\"\n\nfunc F() int { return len(os.Args) }\n")
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "os") {
		t.Fatalf("os.Args verdict = %+v, want unverifiable naming os", verdict)
	}
	// The precise classification lives in the observation proof.
	if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "unaudited standard operation os.Args") {
		t.Fatalf("os.Args proof = %+v, want os.Args classification", fingerprint.ObservationProof)
	}
}

// The benchmark's iteration count is harness pacing: a measurement-kind
// view proves the b.N reader observable and its verdict valid
// (REQ-closure-observability-benchmark-pacing).
func TestBenchmarkIterationCountIsHarnessPacing(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n")
	if err := os.WriteFile(filepath.Join(dir, "benchmark_test.go"), []byte("package view\n\nimport \"testing\"\n\nfunc BenchmarkF(b *testing.B) { _ = b.N }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "BenchmarkF"}
	view, err := engine.newViewFor(context.Background(), []Subject{subject}, dir, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("benchmark iteration verdict = %+v, want valid — the count is harness pacing", verdict)
	}
	if !fingerprint.ObservationProof.Observable || fingerprint.ObservationProof.Reason != "" {
		t.Fatalf("benchmark iteration proof = %+v, want observable", fingerprint.ObservationProof)
	}
}

// Impure or unverified non-standard assembly blocks the observation proof:
// a leaf body executing a hardware counter (`RDTSC`) refuses with the symbol's
// decoded native effect on supported ISAs (or the conservative non-toolchain
// assembly floor elsewhere), while a non-leaf `CALL`-bearing `.s` file widens
// and refuses naming the non-toolchain assembly.
func TestNonStandardAssemblyBlocksObservationProof(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	t.Run("impure-leaf", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nfunc F()\n")
		assembly := "#include \"textflag.h\"\nTEXT ·F(SB), NOSPLIT, $0-0\n\tRDTSC\n\tRET\n"
		if err := os.WriteFile(filepath.Join(dir, "view.s"), []byte(assembly), 0o644); err != nil {
			t.Fatal(err)
		}
		engine, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		subject := Subject{Package: "example.com/view", Symbol: "F"}
		view, err := engine.newView(context.Background(), []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := view.captureObserved(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		wantSubstr := "non-toolchain assembly"
		if runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" {
			wantSubstr = "reaches example.com/view.F (hardware counter, entropy, or system assembly instruction)"
		}
		if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, wantSubstr) {
			t.Fatalf("impure leaf assembly proof = %+v, want refused containing %q", fingerprint.ObservationProof, wantSubstr)
		}
	})
	t.Run("unverified-call", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nfunc Helper()\nfunc F()\n")
		assembly := "#include \"textflag.h\"\nTEXT ·Helper(SB), NOSPLIT, $0-0\n\tRET\nTEXT ·F(SB), NOSPLIT, $0-0\n\tCALL ·Helper(SB)\n\tRET\n"
		if err := os.WriteFile(filepath.Join(dir, "view.s"), []byte(assembly), 0o644); err != nil {
			t.Fatal(err)
		}
		engine, err := newEngine(withDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		subject := Subject{Package: "example.com/view", Symbol: "F"}
		view, err := engine.newView(context.Background(), []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := view.captureObserved(context.Background(), subject)
		if err != nil {
			t.Fatal(err)
		}
		if fingerprint.ObservationProof.Observable || !strings.Contains(fingerprint.ObservationProof.Reason, "non-toolchain assembly") {
			t.Fatalf("unverified call assembly proof = %+v, want refused naming the non-toolchain assembly", fingerprint.ObservationProof)
		}
	})
}

// An opaque system object is permanently unauditable: the subject
// checks unverifiable with a native cause named - the lexicographic
// least of the package's native findings under the shared
// cause-preference order.
func TestSystemObjectRemainsOpaque(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc F() {}\n")
	if err := os.WriteFile(filepath.Join(dir, "view.syso"), []byte("opaque system object"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "cgo or native source") {
		t.Fatalf("system-object verdict = %+v, want unverifiable naming the native cause", verdict)
	}
	if fingerprint.ObservationProof.Observable {
		t.Fatalf("system-object proof = %+v, want refused", fingerprint.ObservationProof)
	}
}

func TestExternalStandardLinknameTargetBlocksObservationProof(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nimport _ \"unsafe\"\n\n//go:linkname nanotime runtime.nanotime\nfunc nanotime() int64\n\nfunc F() int64 { return nanotime() }\n")
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.ObservationProof.Observable {
		t.Fatalf("standard linkname proof = %+v, want refused", fingerprint.ObservationProof)
	}
}

// A production function named TestMain is an ordinary subject: the
// observability analysis roots it instead of refusing it as harness setup.
func TestProductionFunctionNamedTestMainIsAnalyzable(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nfunc TestMain() {}\n")
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "TestMain"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatalf("production TestMain was not analyzable: %v", err)
	}
	if strings.Contains(fingerprint.ObservationProof.Reason, "observation analysis unavailable") {
		t.Fatalf("production TestMain was not rootable: %+v", fingerprint.ObservationProof)
	}
}

func TestProductionTestMainSignatureIsNotHarnessSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, "package view\n\nimport (\"os\"; \"testing\")\n\nfunc TestMain(m *testing.M) { _, _ = os.ReadFile(\"fixture\") }\n")
	if err := os.WriteFile(filepath.Join(dir, "view_test.go"), []byte("package view\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/view", Symbol: "TestF"}
	view, err := engine.newView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.captureObserved(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if !fingerprint.ObservationProof.Observable {
		t.Fatalf("production TestMain contaminated test subject: %+v", fingerprint.ObservationProof)
	}
}

func TestViewMembershipRefusalsRetainSelectionScope(t *testing.T) {
	if testing.Short() {
		t.Skip("loads a real declared-but-unselected subject")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod": "module example.com/members\n\ngo 1.27.0\n",
		"p.go":   "package members\nfunc F() int { return 1 }\nfunc G() int { return 2 }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	f, g := Subject{Package: "example.com/members", Symbol: "F"}, Subject{Package: "example.com/members", Symbol: "G"}
	all, err := session.Snapshot(t.Context(), []Subject{f, g}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	if declared, err := bindTestRuntime(t, all, RuntimeDescription{}).CurrentFacts(t.Context(), g); err != nil || declared.MaximalClosure == "" {
		t.Fatalf("the excluded subject is not a real declaration: %v", err)
	}
	selected, err := all.Sibling([]Subject{f})
	if err != nil {
		t.Fatal(err)
	}
	view := selected
	bound := bindTestRuntime(t, selected, RuntimeDescription{})
	view.beforePreciseAnalysis = func() { t.Fatal("membership refusal started proof work") }
	observation, err := runtimeinput.Incomplete(dir, "unrelated-process", "no completion", os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"capture":          func() error { _, err := view.Capture(t.Context(), g); return err },
		"observed capture": func() error { _, err := view.captureObserved(t.Context(), g); return err },
		"source files":     func() error { _, err := view.SourceFilesFor(g); return err },
		"ledger":           func() error { _, err := view.TestVariantLedger(g); return err },
		"attachment":       func() error { _, err := view.AttachObservation(g, Fingerprint{}, observation); return err },
		"binding facts":    func() error { _, err := bound.CurrentFacts(t.Context(), g); return err },
		"snapshot sources": func() error { _, err := selected.SourceFilesFor(g); return err },
		"snapshot ledger":  func() error { _, err := selected.TestVariantLedger(g); return err },
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			var refusal *UnknownSubjectsError
			if !errors.As(err, &refusal) || refusal.Scope != SelectedView || !slices.Equal(refusal.Subjects, []Subject{g}) {
				t.Fatalf("selected-view refusal lost its typed scope: %T %v", err, err)
			}
		})
	}
	if _, err := bound.CurrentFacts(t.Context(), f); err != nil {
		t.Fatalf("refused projection sealed a valid sibling: %v", err)
	}
}

// TestStaleRuntimeInputsNamesTheMover pins the attribution surface end to end
// (REQ-inputs-path-identities): a recording staled by a moved runtime input
// reports which input moved, not one opaque word.
func TestStaleRuntimeInputsNamesTheMover(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	tmp := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(tmp, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/mover\n\ngo 1.26\n")
	write("m.go", "package mover\n\nfunc F() int { return 1 }\n")
	write("data/fixture.txt", "v1")

	subj := Subject{Package: "example.com/mover", Symbol: "F"}
	e, err := newEngine(withDir(tmp))
	if err != nil {
		t.Fatal(err)
	}
	fp, err := e.capture(context.Background(), subj, tmp)
	if err != nil {
		t.Fatal(err)
	}
	bracket, err := riCaptureBracket(tmp, []string{"data"})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := riFromTestLog([]byte("open data/fixture.txt\n"), tmp, tmp,
		runtimeinput.WithCompletedProcess("package-test-binary:mover"), runtimeinput.WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	st, err := runtimeinput.CompletedState(obs)
	if err != nil {
		t.Fatal(err)
	}
	fp.RuntimeInputs = st.Manifest
	fp.RuntimeDigest = st.Digest

	if v, err := e.check(context.Background(), fp, subj, tmp); err != nil {
		t.Fatal(err)
	} else if v.Status != Valid {
		t.Fatalf("unmoved input verdict = {%s %q}, want valid", v.Status, v.Reason)
	}

	write("data/fixture.txt", "v2")
	v, err := e.check(context.Background(), fp, subj, tmp)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != Stale || !strings.Contains(v.Reason, "moved: path data/fixture.txt") {
		t.Fatalf("moved-input verdict = {%s %q}, want stale naming the mover", v.Status, v.Reason)
	}
	if v.Ground.Cause != (Cause{Kind: RuntimeInputsCause, Condition: Changed}) {
		t.Fatalf("mover lost its semantic cause: %+v", v.Ground)
	}
	view := &Snapshot{session: e, moduleDir: tmp}
	v.Reason = "different diagnostic wording"
	decorated := view.withMovedInputs(t.Context(), v, fp)
	if decorated.Ground != v.Ground || !strings.Contains(decorated.Reason, "moved: path data/fixture.txt") {
		t.Fatalf("wording selected decoration or changed authority: %+v", decorated)
	}
	spoof := Verdict{Status: Stale, Reason: "runtimeinputs", Ground: JudgmentGround{Cause: Cause{Kind: ClosureCause, Condition: Changed}}}
	if got := view.withMovedInputs(t.Context(), spoof, fp); got != spoof {
		t.Fatalf("runtime diagnostic spoof selected attribution: %+v", got)
	}
}

func TestResolveToolchainSelection(t *testing.T) {
	dir := t.TempDir()
	build := BuildDescription{Directory: dir, Environment: os.Environ()}
	if _, err := ResolveToolchainSelection(nil, build); err == nil {
		t.Fatal("nil context accepted by ResolveToolchainSelection")
	}
	if _, err := ResolveToolchainSelection(context.Background(), BuildDescription{Environment: os.Environ()}); err == nil {
		t.Fatal("empty directory accepted by ResolveToolchainSelection")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ResolveToolchainSelection(cancelled, build); err == nil {
		t.Fatal("cancelled context accepted by ResolveToolchainSelection")
	}
	var nilSession *Session
	if _, err := nilSession.ToolchainSelection(context.Background()); err == nil {
		t.Fatal("nil session accepted by ToolchainSelection")
	}
	degradedEnv := environmentWith(map[string]string{"GOENV": "off", "GOFLAGS": "-tags"})
	degraded, err := ResolveToolchainSelection(context.Background(), BuildDescription{Directory: dir, Environment: degradedEnv})
	if err != nil {
		t.Fatalf("ResolveToolchainSelection degraded GOFLAGS: %v", err)
	}
	if degraded.ToolchainContent != "" || degraded.AdmissionPolicy == "" || !strings.Contains(degraded.SelectionNotice, "-tags (from $GOFLAGS)") {
		t.Fatalf("ResolveToolchainSelection degraded GOFLAGS = %+v", degraded)
	}
	if testing.Short() {
		t.Skip("audits the host toolchain selection via go list")
	}
	sel, err := ResolveToolchainSelection(context.Background(), build)
	if err != nil {
		t.Fatalf("ResolveToolchainSelection: %v", err)
	}
	if sel.ToolchainContent == "" || sel.AdmissionPolicy == "" {
		t.Fatalf("ResolveToolchainSelection returned empty digests: %+v", sel)
	}
}

func TestRuntimeBindingRefusesDelimiterCollision(t *testing.T) {
	if testing.Short() {
		t.Skip("observes source and measurement guard generations")
	}
	if runtime.GOOS != "linux" {
		t.Skip("measurement support requires Linux")
	}
	dir := writeViewModule(t, "package view\nfunc F() {}\n")
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	session, err := NewSession(t.Context(), BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := session.Snapshot(t.Context(), []Subject{subject}, Measurement)
	if err != nil {
		t.Fatal(err)
	}
	first := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: []string{"GOGC=200\nGODEBUG=x", "GODEBUG=y"}})
	second := bindTestRuntime(t, snapshot, RuntimeDescription{Environment: []string{"GOGC=200", "GODEBUG=x\nGODEBUG=y"}})
	recorded, err := first.CurrentFacts(t.Context(), subject)
	if err != nil {
		t.Fatal(err)
	}
	current, err := second.CurrentFacts(t.Context(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if recorded.Guards.BuildConfig != current.Guards.BuildConfig || recorded.Guards.Machine != current.Guards.Machine {
		t.Fatal("runtime-only control changed compilation or machine identity")
	}
	if verdict, err := first.Check(t.Context(), subject, recorded); err != nil || verdict.Status != Valid {
		t.Fatalf("same runtime configuration did not pass: %+v %v", verdict, err)
	}
	if verdict, err := second.Check(t.Context(), subject, recorded); err != nil || verdict.Status != Stale || verdict.Reason != "runtimeconfig" {
		t.Fatalf("distinct runtime configuration was not refused: %+v %v", verdict, err)
	}
}

// TestScanPureDirectives pins REQ-purity-directive: the scanner marks exactly the
// symbols carrying //gofresh:pure — a function and a method (named "Type.Method") —
// and leaves their directive-less neighbours unmarked.
func TestScanPureDirectives(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	const pkg = "github.com/greatliontech/gofresh/testdata/puredirective"
	pred, err := scanPureDirectives(pkg)
	if err != nil {
		t.Fatalf("ScanPureDirectives: %v", err)
	}
	cases := []struct {
		symbol string
		want   bool
	}{
		{"Asserted", true},
		{"NotAsserted", false},
		{"SpacedDirective", false},
		{"T.Asserted", true},
		{"T.NotAsserted", false},
		// Declared in the external test package ("pkg_test"): the directive must
		// key under the package under test's import path, the path the engine
		// roots the subject under (REQ-purity-directive).
		{"BenchmarkXAsserted", true},
		{"BenchmarkXNotAsserted", false},
	}
	for _, tc := range cases {
		if got := pred(Subject{Package: pkg, Symbol: tc.symbol}); got != tc.want {
			t.Errorf("%s: pure=%v, want %v", tc.symbol, got, tc.want)
		}
	}
}

// TestScanAcceptsUniverseMethodAcrossTestVariants pins the refusal boundary of
// REQ-purity-directive: the ambiguous-subject refusal is for distinct
// declarations collapsing onto one subject identity, never for one declaration
// sighted through two build variants of the same source package. A top-level
// type whose method set holds a position-less universe method — error's Error,
// promoted through interface or struct embedding — is scanned by both the
// production package and its in-package test variant (the scan loads with
// Tests: true); both sightings resolve to the single universe declaration, so
// the scan must succeed rather than manufacture an ambiguity from
// variant-dependent keys.
func TestScanAcceptsUniverseMethodAcrossTestVariants(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/universe\n\ngo 1.26\n",
		"universe.go": "package universe\n\n" +
			"type E = interface{ error }\n\n" +
			"type T struct{ error }\n\n" +
			"//gofresh:pure\nfunc F() {}\n",
		"universe_test.go": "package universe\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) { F() }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pred, err := scanPureDirectivesIn(dir, "example.com/universe")
	if err != nil {
		t.Fatalf("ScanPureDirectives: %v", err)
	}
	if !pred(Subject{Package: "example.com/universe", Symbol: "F"}) {
		t.Errorf("F: pure=false, want true")
	}
}

// TestScanKeepsRecompiledDependencySubjectsUnderOwnPackage pins the subject
// attribution boundary of the scan (REQ-purity-directive with the subject
// identity of the overview spec): `go list -test` marks every package
// recompiled into a test binary with ForTest — including intermediate
// dependencies — but only the package under test's own variants declare
// subjects of the package under test. A dependency recompiled for the test
// binary (external test of a imports r, r imports a — so r is rebuilt against
// a's test variant) keeps its declarations under its own import path: they
// never appear as subjects of the tested package, and a top-level symbol name
// shared between the two packages is two distinct subjects, not an ambiguity.
func TestScanKeepsRecompiledDependencySubjectsUnderOwnPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.26\n",
		"a/a.go": "package a\n\n//gofresh:pure\nfunc G() {}\n",
		// The in-package test file makes "a [a.test]" a distinct variant, so r —
		// importing a, imported by a's external test — is recompiled against it
		// as "r [a.test]" with ForTest set.
		"a/in_test.go":  "package a\n\nimport \"testing\"\n\nfunc TestInternal(t *testing.T) { G() }\n",
		"a/ext_test.go": "package a_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/m/r\"\n)\n\nfunc TestG(t *testing.T) { r.Use() }\n",
		"r/r.go":        "package r\n\nimport \"example.com/m/a\"\n\nfunc Use() { a.G() }\n\nfunc G() {}\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The attribution assertions below hold vacuously if the recompiled
	// dependency variant ("r [a.test]") stops materializing, so its presence is
	// load-bearing.
	cfg := &packages.Config{
		Mode:  packages.NeedName | packages.NeedForTest | packages.NeedImports | packages.NeedDeps,
		Tests: true,
		Dir:   dir,
	}
	loaded, err := packages.Load(cfg, "example.com/m/a")
	if err != nil {
		t.Fatalf("variant guard load: %v", err)
	}
	variant := false
	packages.Visit(loaded, nil, func(p *packages.Package) {
		if p.PkgPath == "example.com/m/r" && p.ForTest == "example.com/m/a" {
			variant = true
		}
	})
	if !variant {
		t.Fatal("fixture no longer yields the recompiled dependency variant r [a.test]; the attribution assertions below would hold vacuously")
	}
	scan, err := scanSubjectsInWithBuildFlagsEnv(context.Background(), dir, os.Environ(), nil, "example.com/m/a", "example.com/m/r")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	pred, known := scan.directivePure, scan.known
	for subject, want := range map[Subject]bool{
		{Package: "example.com/m/a", Symbol: "G"}:   true,
		{Package: "example.com/m/r", Symbol: "G"}:   true,
		{Package: "example.com/m/r", Symbol: "Use"}: true,
		// r's declaration, recompiled as "r [a.test]", is never a subject of a.
		{Package: "example.com/m/a", Symbol: "Use"}: false,
	} {
		if known[subject] != want {
			t.Errorf("known[%s.%s]=%v, want %v", subject.Package, subject.Symbol, known[subject], want)
		}
	}
	if !pred(Subject{Package: "example.com/m/a", Symbol: "G"}) {
		t.Errorf("a.G: pure=false, want true (directive on a's own declaration)")
	}
	if pred(Subject{Package: "example.com/m/r", Symbol: "G"}) {
		t.Errorf("r.G: pure=true, want false (a's directive must not leak to r's same-named symbol)")
	}
}
