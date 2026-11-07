package gofresh

import (
	"context"
	"errors"
	"fmt"
	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/dynstate"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A data memo — an unexported by-value sync.Map whose every use is a Load,
// Store, or LoadOrStore with carrier-free key and value static types — holds
// no dynamic carrier and marks nothing; an interface-typed key parameter
// resolves through its direct call sites. Any other use, a carrier stored, an
// exported or pointer variable keeps the mark
// (REQ-closure-shared-dynamic-state-memo).
func TestDataMemoMarksNothing(t *testing.T) {
	const head = "package view\n\nimport \"sync\"\n\nvar memo sync.Map\n\n"
	cases := []struct {
		name, rest string
		valid      bool
	}{
		{"load and store of data", "func expand(key string) []rune {\n\tif v, ok := memo.Load(key); ok {\n\t\treturn v.([]rune)\n\t}\n\tr := []rune(key)\n\tmemo.Store(key, r)\n\treturn r\n}\n\nfunc F() int { return len(expand(\"ab\")) }\n", true},
		{"load or store of data", "func name(key int) string {\n\tv, _ := memo.LoadOrStore(key, \"n\")\n\treturn v.(string)\n}\n\nfunc F() string { return name(1) }\n", true},
		{"interface-typed key parameter resolved through its call sites", "func expand(key any) []rune {\n\tif v, ok := memo.Load(key); ok {\n\t\treturn v.([]rune)\n\t}\n\tr := []rune(\"x\")\n\tmemo.Store(key, r)\n\treturn r\n}\n\nfunc F() int { return len(expand(\"ab\")) + len(expand(7)) }\n", true},
		{"a carrier value stored", "func hook(key string) func() {\n\tif v, ok := memo.Load(key); ok {\n\t\treturn v.(func())\n\t}\n\tf := func() {}\n\tmemo.Store(key, f)\n\treturn f\n}\n\nfunc F() int {\n\thook(\"k\")\n\treturn 1\n}\n", false},
		{"a carrier key parameter fed a carrier", "func expand(key any) int {\n\tmemo.Store(key, 1)\n\treturn 1\n}\n\nfunc F() int { return expand(func() {}) }\n", false},
		{"range use", "func F() int {\n\tn := 0\n\tmemo.Range(func(k, v any) bool {\n\t\tn++\n\t\treturn true\n\t})\n\treturn n\n}\n", false},
		{"delete use", "func F() int {\n\tmemo.Store(\"k\", 1)\n\tmemo.Delete(\"k\")\n\treturn 1\n}\n", false},
		{"variable passed to a helper", "func use(m *sync.Map) {}\n\nfunc F() int {\n\tuse(&memo)\n\tmemo.Store(\"k\", 1)\n\treturn 1\n}\n", false},
		{"variadic value parameter", "func h() int { return 1 }\n\nfunc fill(key string, vals ...any) { memo.Store(key, vals) }\n\nfunc F() int {\n\tfill(\"k\", \"a\", h)\n\treturn 1\n}\n", false},
		{"parenthesized receiver", "func h() int { return 1 }\n\nfunc F() int {\n\t(memo).Store(\"k\", h)\n\treturn 1\n}\n", false},
		{"init-flow alias fill", "func h() int { return 1 }\n\nfunc register(m *sync.Map) { m.Store(\"k\", h) }\n\nfunc init() { register(&memo) }\n\nfunc F() int {\n\tv, _ := memo.Load(\"k\")\n\tif v == nil {\n\t\treturn 0\n\t}\n\treturn 1\n}\n", false},
		{"fixed parameter of a variadic function", "func fill(key any, rest ...int) int {\n\tmemo.Store(key, len(rest))\n\treturn 1\n}\n\nfunc F() int { return fill(\"k\", 1, 2) }\n", true},
		{"key parameter reassigned", "func expand(key any) int {\n\tkey = func() {}\n\tmemo.Store(key, 1)\n\treturn 1\n}\n\nfunc F() int { return expand(\"k\") }\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeViewModule(t, head+tc.rest)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if tc.valid && verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid — a data memo marked", verdict)
			}
			if !tc.valid && (verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.memo")) {
				t.Fatalf("verdict = %+v, want the refusal naming memo — an open sync.Map was judged a data memo", verdict)
			}
		})
	}
	for name, source := range map[string]string{
		"exported variable": "package view\n\nimport \"sync\"\n\nvar Memo sync.Map\n\nfunc F() int {\n\tMemo.Store(\"k\", 1)\n\treturn 1\n}\n",
		"pointer variable":  "package view\n\nimport \"sync\"\n\nvar memo = &sync.Map{}\n\nfunc F() int {\n\tmemo.Store(\"k\", 1)\n\treturn 1\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.") {
				t.Fatalf("verdict = %+v, want a refusal — a reachable or shared sync.Map was judged a data memo", verdict)
			}
		})
	}
}

// writePinnedDepModule writes a module depending on golang.org/x/sync at the
// parent module's own pinned version — present in any module cache able to
// build gofresh itself — and returns its directory.
func writePinnedDepModule(t *testing.T) string {
	t.Helper()
	tmpl := getPinnedDepTemplate(t)
	dir := t.TempDir()
	for name, content := range tmpl.files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	markPinnedTemplateDir(dir)
	return dir
}

type scanResult struct {
	known, external map[Subject]bool
	openWorld       map[Subject]string
	pure            map[Subject]bool
	downgradeReason map[Subject]string
	vouchDischarges map[Subject]string
}

// testScope carries one test's opaque scope string as the fact-strategy
// axis: the persisted keys it renders are identities the tests compare,
// never parse.
func testScope(scope string) closure.AnalysisScope {
	if scope == "" {
		return closure.AnalysisScope{}
	}
	return closure.AnalysisScope{FactStrategy: scope, Toolchain: "test-toolchain", BuildConfig: "test-build"}
}

// attestedScope is testScope under the single-subject attestation.
func attestedScope(scope string) closure.AnalysisScope {
	s := testScope(scope)
	s.SingleSubject = true
	return s
}

func runScan(t *testing.T, scope, dir string, pkgPaths ...string) scanResult {
	t.Helper()
	return runScanVouched(t, scope, dir, nil, pkgPaths...)
}

func runScanVouched(t *testing.T, scope, dir string, vouches map[string]bool, pkgPaths ...string) scanResult {
	t.Helper()
	if scan, _, ok := inMemoryRunScanVouched(scope, dir, vouches, pkgPaths...); ok {
		result := scanResult{known: scan.known, openWorld: scan.openWorld, external: scan.external, pure: map[Subject]bool{}, downgradeReason: scan.downgradeReason, vouchDischarges: scan.vouchDischarges}
		for subject := range scan.known {
			if scan.directivePure(subject) {
				result.pure[subject] = true
			}
		}
		return result
	}
	// These scans pin the derivation over a poisoned in-process fact
	// cache; the scan memo would serve the first scan's outputs whole.
	hasher, err := closureNewAtEnv(context.Background(), dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	analysis := testScope(scope)
	for v := range vouches {
		analysis.Vouches = append(analysis.Vouches, v)
	}
	analysis = hasher.SetAnalysisScope(analysis)
	scan, _, _, err := scanViewSubjectsWithMemo(context.Background(), hasher, analysis, nil, 0, false, pkgPaths...)
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
	processFactCache.Reset()
	const scope = DynamicStateStrategy + "|vouch-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
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

	poisoned := runScan(t, scope, dir, pkg)
	if reason := poisoned.downgradeReason[subject]; !strings.Contains(reason, ghost+" is mutated") {
		t.Fatalf("poisoned downgrade = %q, want the culprit named", reason)
	}
	// The reason contract: a version-pinned dependency culprit names
	// its discharge channel — the vouch spelling with the audit
	// obligation — so the refusal is never a dead end
	// (REQ-closure-shared-dynamic-state-reason).
	if reason := poisoned.downgradeReason[subject]; !strings.Contains(reason, "dischargeable by a caller vouch for golang.org/x/sync/errgroup.Ghost") ||
		!strings.Contains(reason, "--vouch golang.org/x/sync/errgroup:Ghost") ||
		!strings.Contains(reason, "initialized once and never written") {
		t.Fatalf("poisoned downgrade = %q, want the vouch channel named with its audit obligation", reason)
	}
	// The mutated ghost is NOT a function-value carrier: its stated
	// obligation must stop at init-only — the env clause on a plain
	// variable would demand an audit with no subject.
	if reason := poisoned.downgradeReason[subject]; strings.Contains(reason, "environment-free") {
		t.Fatalf("poisoned downgrade = %q; a non-carrier's obligation must not demand the environment audit", reason)
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
	const spectre = "golang.org/x/sync/errgroup.Spectre"
	processFactCache.Range(func(k string, fact dynamicStateFact) bool {
		if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
			fact.Declares = append(fact.Declares, shade, wraith, spectre)
			fact.Escapes = append(fact.Escapes, shade, spectre)
			fact.EnvCarrying = append(fact.EnvCarrying, wraith, spectre)
			processFactCache.Store(k, fact)
		}
		return true
	})
	// The env-carrying culprit's obligation names the environment
	// audit (REQ-closure-shared-dynamic-state-reason): wraith survives
	// a vouch set covering the others and renders the env verb with
	// the full checklist.
	wraithScan := runScanVouched(t, scope, dir, map[string]bool{ghost: true, shade: true, spectre: true}, pkg)
	if reason := wraithScan.downgradeReason[subject]; !strings.Contains(reason, wraith+" registers function values outside the environment-free audit") ||
		!strings.Contains(reason, "registering only environment-free function values") {
		t.Fatalf("wraith downgrade = %q, want the env verb with the environment-audit obligation", reason)
	}
	// The escaped+env-carrying spectre: the escape verb wins the
	// per-variable rank, and the obligation STILL audits the
	// registered values' environments — the carrier chooses the
	// audit, never the verb (the vouch lifts the environment-audit
	// mark too, so a verb-scoped checklist would hand out an
	// unearned lift).
	spectreScan := runScanVouched(t, scope, dir, map[string]bool{ghost: true, shade: true, wraith: true}, pkg)
	if reason := spectreScan.downgradeReason[subject]; !strings.Contains(reason, spectre+" escapes writable") ||
		!strings.Contains(reason, "registering only environment-free function values") {
		t.Fatalf("spectre downgrade = %q, want the escape verb carrying the environment-audit obligation", reason)
	}
	all := map[string]bool{ghost: true, shade: true, wraith: true, spectre: true}
	lifted := runScanVouched(t, scope, dir, all, pkg)
	if reason := lifted.downgradeReason[subject]; reason != "" {
		t.Fatalf("three-rank vouch left a downgrade: %q", reason)
	}
	if discharges := lifted.vouchDischarges[subject]; discharges != ghost+","+shade+","+spectre+","+wraith {
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
	processFactCache.Range(func(k string, fact dynamicStateFact) bool {
		if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
			fact.Declares = append(fact.Declares, alpha, zeta)
			fact.Mutates = append(fact.Mutates, alpha, zeta)
			processFactCache.Store(k, fact)
		}
		return true
	})
	withZeta := map[string]bool{ghost: true, shade: true, wraith: true, spectre: true, zeta: true}
	mixed := runScanVouched(t, scope, dir, withZeta, pkg)
	if reason := mixed.downgradeReason[subject]; !strings.Contains(reason, alpha+" is mutated") {
		t.Fatalf("mixed-package downgrade = %q, want the unvouched culprit named", reason)
	}
	if discharges := mixed.vouchDischarges[subject]; discharges != ghost+","+shade+","+spectre+","+wraith+","+zeta {
		t.Fatalf("mixed-package discharge record = %q", discharges)
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

// The audited atomic transparency: a sync/atomic.Pointer[T] whose
// pointee is data-only is no culprit — the carrier walk sees *T, and a
// mutable data-only variable is out of the invariant's scope — so a
// subject mutating through it stays verifiable with no attestation and
// no discharge record (REQ-closure-shared-dynamic-state).
func TestAtomicPointerDataOnlyPointeeNeverACulprit(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeModuleTree(t, map[string]string{
		"go.mod":     "module example.com/acct\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\nimport \"sync/atomic\"\n\ntype registry struct {\n\tlive map[string]bool\n}\n\nvar acct atomic.Pointer[registry]\n\nfunc Track(k string) {\n\tif r := acct.Load(); r != nil {\n\t\tr.live[k] = true\n\t}\n}\n\nfunc Enable() func() {\n\tacct.Store(&registry{live: map[string]bool{}})\n\treturn func() { acct.Store(nil) }\n}\n",
	})
	processFactCache.Reset()
	scan := runScan(t, "", dir, "example.com/acct/reg")
	subject := Subject{Package: "example.com/acct/reg", Symbol: "Track"}
	if reason := scan.downgradeReason[subject]; reason != "" {
		t.Fatalf("data-only atomic.Pointer pointee downgraded the subject: %q", reason)
	}
}

// The transparency's fail-closed half: a sync/atomic.Pointer[T] whose
// pointee carries dynamic behavior triggers exactly as *T would — the
// walk substitutes the semantic type, it never exempts the variable
// (REQ-closure-shared-dynamic-state).
func TestAtomicPointerDynamicPointeeKeepsEveryMark(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeModuleTree(t, map[string]string{
		"go.mod":     "module example.com/hooks\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\nimport \"sync/atomic\"\n\ntype hookSet struct {\n\tfire func()\n}\n\nvar hooks atomic.Pointer[hookSet]\n\nfunc Fire() {\n\tif h := hooks.Load(); h != nil {\n\t\th.fire()\n\t}\n}\n\nfunc Arm(f func()) {\n\thooks.Store(&hookSet{fire: f})\n}\n",
	})
	processFactCache.Reset()
	scan := runScan(t, "", dir, "example.com/hooks/reg")
	subject := Subject{Package: "example.com/hooks/reg", Symbol: "Fire"}
	if reason := scan.downgradeReason[subject]; !strings.Contains(reason, "example.com/hooks/reg.hooks is mutated") {
		t.Fatalf("dynamic-pointee reason = %q, want the downgrade naming hooks - the transparency substitutes the type, never exempts it", reason)
	}
}

// The transparency applies through an alias spelling — types.Unalias
// resolves `type P = atomic.Pointer[T]` to the toolchain instantiation
// before the walk judges it. The dynamic-pointee alias is the leg with
// teeth: an unresolved alias would match no case and read as no
// carrier at all, silently serving a func-carrying culprit as fresh —
// so the culprit MUST still be seen through the alias
// (REQ-closure-shared-dynamic-state).
func TestAtomicTransparencyThroughAlias(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeModuleTree(t, map[string]string{
		"go.mod":     "module example.com/aliased\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\nimport \"sync/atomic\"\n\ntype registry struct {\n\tlive map[string]bool\n}\n\ntype P = atomic.Pointer[registry]\n\nvar acct P\n\nfunc Track(k string) {\n\tif r := acct.Load(); r != nil {\n\t\tr.live[k] = true\n\t}\n}\n\nfunc Enable() {\n\tacct.Store(&registry{live: map[string]bool{}})\n}\n",
		"dyn/dyn.go": "package dyn\n\nimport \"sync/atomic\"\n\ntype hookSet struct {\n\tfire func()\n}\n\ntype Q = atomic.Pointer[hookSet]\n\nvar hooks Q\n\nfunc Fire() {\n\tif h := hooks.Load(); h != nil {\n\t\th.fire()\n\t}\n}\n\nfunc Arm(f func()) {\n\thooks.Store(&hookSet{fire: f})\n}\n",
	})
	processFactCache.Reset()
	scan := runScan(t, "", dir, "example.com/aliased/reg", "example.com/aliased/dyn")
	subject := Subject{Package: "example.com/aliased/reg", Symbol: "Track"}
	if reason := scan.downgradeReason[subject]; reason != "" {
		t.Fatalf("aliased data-only atomic.Pointer downgraded the subject: %q", reason)
	}
	dynSubject := Subject{Package: "example.com/aliased/dyn", Symbol: "Fire"}
	if reason := scan.downgradeReason[dynSubject]; !strings.Contains(reason, "example.com/aliased/dyn.hooks is mutated") {
		t.Fatalf("aliased dynamic-pointee reason = %q, want the downgrade naming hooks - an unresolved alias would silently serve the culprit as fresh", reason)
	}
}

// A defined wrapper (`type P atomic.Pointer[T]`) inherits no methods
// and its cell is reached only through an address conversion the
// escape rules mark, so it keeps the fail-closed judgment — the
// transparency never crosses a definition boundary
// (REQ-closure-shared-dynamic-state-atomic).
func TestAtomicTransparencyStopsAtDefinedWrappers(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeModuleTree(t, map[string]string{
		"go.mod":     "module example.com/wrapped\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\nimport \"sync/atomic\"\n\ntype registry struct {\n\tlive map[string]bool\n}\n\ntype P atomic.Pointer[registry]\n\nvar acct P\n\nfunc Cell() *P {\n\treturn &acct\n}\n",
	})
	processFactCache.Reset()
	scan := runScan(t, "", dir, "example.com/wrapped/reg")
	subject := Subject{Package: "example.com/wrapped/reg", Symbol: "Cell"}
	if reason := scan.downgradeReason[subject]; !strings.Contains(reason, "example.com/wrapped/reg.acct") {
		t.Fatalf("defined-wrapper reason = %q, want the fail-closed downgrade naming acct", reason)
	}
}

// One carrier rule at every tier (REQ-closure-analysis): a parameter
// of the toolchain's atomic pointer type opens its subject exactly
// when *T would — a data-only pointee leaves the subject closed, a
// dynamic-carrying pointee opens it.
func TestAtomicPointerParameterOpennessFollowsPointee(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeModuleTree(t, map[string]string{
		"go.mod":     "module example.com/params\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\nimport \"sync/atomic\"\n\ntype registry struct {\n\tlive map[string]bool\n}\n\ntype hooks struct {\n\tfire func()\n}\n\nfunc Data(p *atomic.Pointer[registry]) int {\n\tif p.Load() != nil {\n\t\treturn 1\n\t}\n\treturn 0\n}\n\nfunc Bounded[T interface{ atomic.Pointer[registry] }](p *T) int {\n\tif p != nil {\n\t\treturn 1\n\t}\n\treturn 0\n}\n\nfunc Dyn(p *atomic.Pointer[hooks]) int {\n\tif p.Load() != nil {\n\t\treturn 1\n\t}\n\treturn 0\n}\n",
	})
	processFactCache.Reset()
	scan := runScan(t, "", dir, "example.com/params/reg")
	if term := scan.openWorld[Subject{Package: "example.com/params/reg", Symbol: "Data"}]; term != "" {
		t.Fatalf("a data-only atomic.Pointer parameter opened the subject through %q", term)
	}
	if term := scan.openWorld[Subject{Package: "example.com/params/reg", Symbol: "Bounded"}]; term != "" {
		t.Fatalf("a constraint term of the toolchain atomic type opened the subject through %q - the term walk must see the same transparency the parameter walk does", term)
	}
	if term := scan.openWorld[Subject{Package: "example.com/params/reg", Symbol: "Dyn"}]; term == "" {
		t.Fatal("a dynamic-pointee atomic.Pointer parameter left the subject closed")
	}
}

// The alias-handing read judgment sees the atomic field as *T: a
// data-only atomic pointer beside a hook field leaves the struct a
// by-value carrier whose reads copy — no escape-class downgrade
// (REQ-closure-shared-dynamic-state).
func TestAtomicFieldBesideHookStaysByValue(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeModuleTree(t, map[string]string{
		"go.mod":     "module example.com/beside\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\nimport \"sync/atomic\"\n\ntype config struct {\n\tn int\n}\n\ntype box struct {\n\tcfg  atomic.Pointer[config]\n\thook func()\n}\n\nvar state box\n\nfunc Read() {\n\tif f := state.hook; f != nil {\n\t\tf()\n\t}\n}\n",
	})
	processFactCache.Reset()
	scan := runScan(t, "", dir, "example.com/beside/reg")
	subject := Subject{Package: "example.com/beside/reg", Symbol: "Read"}
	if reason := scan.downgradeReason[subject]; reason != "" {
		t.Fatalf("data-only atomic field beside a hook downgraded the read: %q", reason)
	}
}

// The transparency covers exactly the toolchain's sync/atomic.Pointer:
// a user-defined generic Pointer carrying an unsafe cell keeps the
// fail-closed trigger whatever its type argument — the audit is of the
// toolchain's source, and no name-shaped sibling inherits it
// (REQ-closure-shared-dynamic-state-atomic).
func TestAtomicTransparencyCoversOnlyTheToolchainPointer(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writeModuleTree(t, map[string]string{
		"go.mod":     "module example.com/homebrew\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\nimport \"unsafe\"\n\ntype Pointer[T any] struct {\n\tp unsafe.Pointer\n}\n\ntype registry struct {\n\tlive map[string]bool\n}\n\nvar acct Pointer[registry]\n\nfunc Track() {\n\tacct.p = nil\n}\n",
	})
	processFactCache.Reset()
	scan := runScan(t, "", dir, "example.com/homebrew/reg")
	subject := Subject{Package: "example.com/homebrew/reg", Symbol: "Track"}
	if reason := scan.downgradeReason[subject]; !strings.Contains(reason, "example.com/homebrew/reg.acct is mutated") {
		t.Fatalf("homebrew Pointer reason = %q, want the fail-closed downgrade naming acct - the audit never leaves the toolchain", reason)
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

// A persisted fact carrying an attribution the consumer cannot parse is
// not trusted: every key the fact declares marks mutated — fail-closed
// like every malformed-fact arm — and the downgrade names the declared
// key (REQ-closure-shared-dynamic-state).
func TestMalformedAttributedUseMarksEveryDeclaredKey(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"
	subject := Subject{Package: pkg, Symbol: "Run"}
	processFactCache.Reset()
	const scope = DynamicStateStrategy + "|malformed-attribution-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	poison := func(mutate func(*dynamicStateFact)) {
		var hit bool
		processFactCache.Range(func(k string, fact dynamicStateFact) bool {
			if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
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

	// An invalid attribution — its function key missing the name —
	// cannot be judged and must not be dropped.
	poison(func(fact *dynamicStateFact) {
		fact.AttributedUses = append(fact.AttributedUses, dynstate.AttributedUse{Func: dynstate.FuncKey{Pkg: "golang.org/x/sync/errgroup"}, Key: "golang.org/x/sync/errgroup.Ghost"})
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
	pkgs := parseAndTypecheckDAG(t, "", map[string]map[string]string{
		"example.com/xesc/reg": {"reg.go": "package reg\n\nfunc one() int { return 1 }\n\nvar Hooks = map[string]func() int{\"a\": one}\n\nvar Alias = Hooks\n\nfunc Count() int { return len(Hooks) }\n"},
	})
	fact := dynamicStateFactOf(true, pkgs[0], false)
	want := dynstate.CarrierLink{From: "example.com/xesc/reg.Alias", To: "example.com/xesc/reg.Hooks"}
	found := false
	for _, link := range fact.CarrierLinks {
		if link == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("CarrierLinks = %+v, want the Alias-to-Hooks storage link recorded", fact.CarrierLinks)
	}
}

// An init-flow element store whose target is a carrier links the two
// backings exactly as a whole-name bind does, while a call-result bind
// records no link - the callee's value is not the argument's backing
// (REQ-closure-shared-dynamic-state).
func TestCarrierStoreLinkRecordedAndCallResultsUnlinked(t *testing.T) {
	pkgs := parseAndTypecheckDAG(t, "", map[string]map[string]string{
		"example.com/xesc/reg": {"reg.go": "package reg\n\nfunc one() int { return 1 }\n\nvar Inner = []func() int{one}\n\nvar Hooks = map[string][]func() int{}\n\nfunc pick(m map[string][]func() int) map[string][]func() int { return m }\n\nvar Picked = pick(Hooks)\n\nfunc init() {\n\tHooks[\"a\"] = Inner\n}\n\nfunc Count() int { return len(Hooks) }\n"},
	})
	fact := dynamicStateFactOf(true, pkgs[0], false)
	wantStore := dynstate.CarrierLink{From: "example.com/xesc/reg.Hooks", To: "example.com/xesc/reg.Inner"}
	foundStore := false
	for _, link := range fact.CarrierLinks {
		if link == wantStore {
			foundStore = true
		}
		if strings.Contains(link.From, "Picked") || strings.Contains(link.To, "Picked") {
			t.Fatalf("CarrierLinks = %+v, want no link through a call result", fact.CarrierLinks)
		}
	}
	if !foundStore {
		t.Fatalf("CarrierLinks = %+v, want the element-store link recorded", fact.CarrierLinks)
	}
}

// A cross-carrier storage link crosses mutation marks symmetrically: a
// mutation recorded against an aliasing key refuses the linked origin
// key too - one backing under every name it carries
// (REQ-closure-shared-dynamic-state-init-aliasing).
func TestCarrierLinkCrossesMutationMarks(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const pkg = "example.com/pinned"
	subject := Subject{Package: pkg, Symbol: "Run"}
	processFactCache.Reset()
	const scope = DynamicStateStrategy + "|carrier-link-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	var hit bool
	processFactCache.Range(func(k string, fact dynamicStateFact) bool {
		if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
			// The origin is declared; the mutation lands on an
			// undeclared aliasing key - without the link no culprit
			// exists, with it the mark crosses to the origin.
			fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
			fact.Mutates = append(fact.Mutates, "golang.org/x/sync/errgroup.ghostAlias")
			fact.CarrierLinks = append(fact.CarrierLinks, dynstate.CarrierLink{From: "golang.org/x/sync/errgroup.ghostAlias", To: "golang.org/x/sync/errgroup.Ghost"})
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
	processFactCache.Reset()
	const scope = DynamicStateStrategy + "|carrier-link-escape-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	var hit bool
	processFactCache.Range(func(k string, fact dynamicStateFact) bool {
		if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
			fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
			fact.Escapes = append(fact.Escapes, "golang.org/x/sync/errgroup.ghostAlias")
			fact.CarrierLinks = append(fact.CarrierLinks, dynstate.CarrierLink{From: "golang.org/x/sync/errgroup.ghostAlias", To: "golang.org/x/sync/errgroup.Ghost"})
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
	processFactCache.Reset()
	const scope = DynamicStateStrategy + "|malformed-link-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	var hit bool
	processFactCache.Range(func(k string, fact dynamicStateFact) bool {
		if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
			fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
			// Missing To key - the link lost one of its keys.
			fact.CarrierLinks = append(fact.CarrierLinks, dynstate.CarrierLink{From: "golang.org/x/sync/errgroup.Ghost"})
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
	processFactCache.Reset()
	const scope = DynamicStateStrategy + "|malformed-param-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	var hit bool
	processFactCache.Range(func(k string, fact dynamicStateFact) bool {
		if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
			fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
			// Callee parameter key missing function name.
			fact.ParamUses = append(fact.ParamUses, dynstate.VarParamUse{Key: "golang.org/x/sync/errgroup.Ghost", Param: dynstate.ParamKey{Func: dynstate.FuncKey{Pkg: "bad"}}})
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
	processFactCache.Reset()
	const scope = DynamicStateStrategy + "|malformed-fieldparam-toolchain|cfg"

	clean := runScan(t, scope, dir, pkg)
	if reason := clean.downgradeReason[subject]; reason != "" {
		t.Fatalf("baseline already downgraded: %q", reason)
	}

	var hit bool
	processFactCache.Range(func(k string, fact dynamicStateFact) bool {
		if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
			fact.Declares = append(fact.Declares, "golang.org/x/sync/errgroup.Ghost")
			// Invalid negative index in FieldParamUses.
			fact.FieldParamUses = append(fact.FieldParamUses, dynstate.FieldPosKey{Owner: "golang.org/x/sync/errgroup.Ghost", Field: "bad", Index: -1})
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
			fact.FieldParamDefer = append(fact.FieldParamDefer, dynstate.FieldParamDefer{
				Pos:   dynstate.FieldPosKey{Owner: "golang.org/x/sync/errgroup.Ghost", Field: "Build", Index: -1},
				Param: dynstate.ParamKey{Func: dynstate.FuncKey{Pkg: "p", Name: "f"}, Index: 0},
			})
		}},
		{"fieldParamPoison", func(fact *dynamicStateFact) {
			// HasPos=true with missing Field name.
			fact.FieldParamPoison = append(fact.FieldParamPoison, dynstate.FieldParamPoison{Owner: "golang.org/x/sync/errgroup.Ghost", HasPos: true})
		}},
		{"returnFieldParamDefer", func(fact *dynamicStateFact) {
			// Function key missing Name.
			fact.ReturnFieldParamDefer = append(fact.ReturnFieldParamDefer, dynstate.ReturnFieldParamDefer{
				Pos:   dynstate.ReturnFieldPosKey{Func: dynstate.FuncKey{Pkg: "badfn"}, Field: "Build", Index: 0},
				Param: dynstate.ParamKey{Func: dynstate.FuncKey{Pkg: "p", Name: "f"}, Index: 0},
			})
		}},
		{"returnFieldParamPoison", func(fact *dynamicStateFact) {
			fact.ReturnFieldParamPoison = append(fact.ReturnFieldParamPoison, dynstate.ReturnFieldParamPoison{
				Func:   dynstate.FuncKey{Pkg: "badfn"},
				HasPos: true,
				Field:  "Build",
				Index:  0,
			})
		}},
		{"elemParamUses", func(fact *dynamicStateFact) {
			// Missing Owner key.
			fact.ElemParamUses = append(fact.ElemParamUses, dynstate.ElemParamUse{Key: "golang.org/x/sync/errgroup.Ghost"})
		}},
		{"paramLeakFreeDeps", func(fact *dynamicStateFact) {
			// Dependency key missing Name.
			fact.ParamLeakFreeDeps = append(fact.ParamLeakFreeDeps, dynstate.ParamDepEdge{
				Own: dynstate.ParamKey{Func: dynstate.FuncKey{Pkg: "golang.org/x/sync/errgroup", Name: "Go"}, Index: 0},
				Dep: dynstate.ParamKey{Func: dynstate.FuncKey{Pkg: "bad"}},
			})
		}},
		{"paramRetentionFreeDeps", func(fact *dynamicStateFact) {
			// The retention grade's edges validate identically.
			fact.ParamRetentionFreeDeps = append(fact.ParamRetentionFreeDeps, dynstate.ParamDepEdge{
				Own: dynstate.ParamKey{Func: dynstate.FuncKey{Pkg: "golang.org/x/sync/errgroup", Name: "Go"}, Index: 0},
				Dep: dynstate.ParamKey{Func: dynstate.FuncKey{Pkg: "bad"}},
			})
		}},
		{"initParamUses", func(fact *dynamicStateFact) {
			// Callee parameter key missing Name.
			fact.InitParamUses = append(fact.InitParamUses, dynstate.VarParamUse{
				Key:   "golang.org/x/sync/errgroup.Ghost",
				Param: dynstate.ParamKey{Func: dynstate.FuncKey{Pkg: "bad"}},
			})
		}},
		{"initMethodUses", func(fact *dynamicStateFact) {
			// Method key is missing.
			fact.InitMethodUses = append(fact.InitMethodUses, dynstate.VarMethodUse{Key: "golang.org/x/sync/errgroup.Ghost"})
		}},
		{"elemNegativeIndex", func(fact *dynamicStateFact) {
			fact.ElemParamUses = append(fact.ElemParamUses, dynstate.ElemParamUse{Key: "golang.org/x/sync/errgroup.Ghost", Owner: "owner.Key", Index: -1})
		}},
		{"negativeParamIndex", func(fact *dynamicStateFact) {
			fact.FieldParamDefer = append(fact.FieldParamDefer, dynstate.FieldParamDefer{
				Pos:   dynstate.FieldPosKey{Owner: "golang.org/x/sync/errgroup.Ghost", Field: "Build", Index: 0},
				Param: dynstate.ParamKey{Func: dynstate.FuncKey{Pkg: "p", Name: "f"}, Index: -1},
			})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CACHE_HOME", t.TempDir())
			dir := writePinnedDepModule(t)
			const pkg = "example.com/pinned"
			subject := Subject{Package: pkg, Symbol: "Run"}
			processFactCache.Reset()
			scope := DynamicStateStrategy + "|malformed-fieldpop-" + tc.name + "|cfg"

			clean := runScan(t, scope, dir, pkg)
			if reason := clean.downgradeReason[subject]; reason != "" {
				t.Fatalf("baseline already downgraded: %q", reason)
			}

			var hit bool
			processFactCache.Range(func(k string, fact dynamicStateFact) bool {
				if strings.HasSuffix(k, "\x00golang.org/x/sync/errgroup") {
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

func TestBracketedSeamNodes(t *testing.T) {
	deriveFactFile := func(t *testing.T, audited bool, filename, src string) dynamicStateFact {
		t.Helper()
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filename, src, 0)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		info := &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Instances:  map[*ast.Ident]types.Instance{},
			Defs:       map[*ast.Ident]types.Object{},
			Uses:       map[*ast.Ident]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
		}
		typesPkg, err := (&types.Config{Importer: importer.Default()}).Check("example.com/p", fset, []*ast.File{file}, info)
		if err != nil {
			t.Fatalf("typecheck: %v", err)
		}
		pkg := &packages.Package{
			ID:        "example.com/p",
			Name:      "p",
			PkgPath:   "example.com/p",
			Fset:      fset,
			Syntax:    []*ast.File{file},
			Types:     typesPkg,
			TypesInfo: info,
			Module:    &packages.Module{Path: "example.com/p"},
		}
		return dynamicStateFactOf(audited, pkg, false)
	}
	deriveFactWithAudit := func(t *testing.T, audited bool, src string) dynamicStateFact {
		t.Helper()
		return deriveFactFile(t, audited, "p_test.go", src)
	}
	deriveFact := func(t *testing.T, src string) dynamicStateFact {
		t.Helper()
		return deriveFactWithAudit(t, true, src)
	}

	positiveCases := []struct {
		name string
		src  string
	}{
		{
			name: "saved and restored via defer",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise() int {
	calls := 0
	orig := probe
	probe = func() int { calls++; return 2 }
	defer func() { probe = orig }()
	return probe() + calls
}`,
		},
		{
			name: "saved and restored via Cleanup with loop writes",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func TestSeam(t *testing.T) {
	orig := probe
	t.Cleanup(func() { probe = orig })
	for i := 0; i < 3; i++ {
		probe = func() int { return i }
	}
}`,
		},
		{
			name: "saved and restored inline without early exit",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise() int {
	orig := probe
	probe = func() int { return 2 }
	got := probe()
	probe = orig
	return got
}`,
		},
		{
			name: "uninitialized struct hook reset to nil in defer and Cleanup",
			src: `package p
import "testing"
var hooks struct {
	before func()
	after  func()
}
func TestHooks(t *testing.T) {
	seen := 0
	hooks.before = func() { seen++ }
	defer func() { hooks.before = nil }()
	hooks.after = func() { seen++ }
	t.Cleanup(func() { hooks.after = nil })
}`,
		},
		{
			name: "mutex-bracketed atomic.Pointer hook",
			src: `package p
import (
	"sync"
	"sync/atomic"
)
type hookSet struct{ onEvent func() }
var (
	hookMu  sync.Mutex
	hookPtr atomic.Pointer[hookSet]
)
func Emit() {
	if h := hookPtr.Load(); h != nil && h.onEvent != nil {
		h.onEvent()
	}
}
func RunWithHooks() {
	hookMu.Lock()
	defer hookMu.Unlock()
	defer hookPtr.Store(nil)
	hookPtr.Store(&hookSet{onEvent: func() {}})
	Emit()
	hookPtr.Store(nil)
}`,
		},
		{
			name: "pure-load uninitialized atomic.Pointer hook without in-package Store",
			src: `package p
import "sync/atomic"
type hookSet struct{ onEvent func() }
var hookPtr atomic.Pointer[hookSet]
func Emit() {
	if h := hookPtr.Load(); h != nil && h.onEvent != nil {
		h.onEvent()
	}
}`,
		},
		{
			name: "unexported test helper and t.Run subtest Cleanup on live testing.T",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func swapProbe(t *testing.T, fn func() int) {
	orig := probe
	probe = fn
	t.Cleanup(func() { probe = orig })
}
func TestCaller(t *testing.T) {
	swapProbe(t, func() int { return 2 })
	t.Run("sub", func(subT *testing.T) {
		swapProbe(subT, func() int { return 3 })
		orig := probe
		probe = func() int { return 4 }
		subT.Cleanup(func() { probe = orig })
	})
	localSwap := func(ht *testing.T) {
		orig := probe
		probe = func() int { return 5 }
		ht.Cleanup(func() { probe = orig })
	}
	localSwap(t)
}`,
		},
		{
			name: "fault-injection closure containing panic assigned before defer restore",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise() {
	orig := probe
	probe = func() int { panic("injected fault") }
	defer func() { probe = orig }()
}`,
		},
	}
	for _, tc := range positiveCases {
		t.Run("positive/"+tc.name, func(t *testing.T) {
			fact := deriveFact(t, tc.src)
			if len(fact.Mutates) != 0 || len(fact.Escapes) != 0 || len(fact.EnvCarrying) != 0 || len(fact.AttributedUses) != 0 {
				t.Fatalf("bracketed seam marked dynamic state: Mutates=%v Escapes=%v EnvCarrying=%v AttributedUses=%v",
					fact.Mutates, fact.Escapes, fact.EnvCarrying, fact.AttributedUses)
			}
		})
	}

	negativeCases := []struct {
		name string
		src  string
	}{
		{
			name: "unbracketed write",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise() {
	probe = func() int { return 2 }
}`,
		},
		{
			name: "write before save",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise() {
	probe = func() int { return 2 }
	orig := probe
	defer func() { probe = orig }()
}`,
		},
		{
			name: "early exit between write and defer",
			src: `package p
type T struct{}
func (*T) Fatal(...any) {}
func defaultProbe() int { return 1 }
var probe = defaultProbe
func TestSeam(t *T, bad bool) {
	orig := probe
	probe = func() int { return 2 }
	if bad {
		t.Fatal("abort before defer")
	}
	defer func() { probe = orig }()
}`,
		},
		{
			name: "mutated saved local",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise() {
	orig := probe
	orig = func() int { return 3 }
	probe = func() int { return 2 }
	defer func() { probe = orig }()
}`,
		},
		{
			name: "nil reset on initialized variable",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise() {
	probe = func() int { return 2 }
	defer func() { probe = nil }()
}`,
		},
		{
			name: "parallel test function",
			src: `package p
type T struct{}
func (*T) Parallel() {}
func defaultProbe() int { return 1 }
var probe = defaultProbe
func TestParallel(t *T) {
	t.Parallel()
	orig := probe
	probe = func() int { return 2 }
	defer func() { probe = orig }()
}`,
		},
		{
			name: "goroutine spawn in function",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise() {
	orig := probe
	probe = func() int { return 2 }
	defer func() { probe = orig }()
	go func() { _ = probe() }()
}`,
		},
		{
			name: "returned closure writes seam",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func MakeWriter() func() {
	orig := probe
	defer func() { probe = orig }()
	return func() { probe = func() int { return 2 } }
}`,
		},
		{
			name: "atomic pointer without defer nil store",
			src: `package p
import (
	"sync"
	"sync/atomic"
)
type hookSet struct{ onEvent func() }
var (
	hookMu  sync.Mutex
	hookPtr atomic.Pointer[hookSet]
)
func RunWithHooks() {
	hookMu.Lock()
	defer hookMu.Unlock()
	hookPtr.Store(&hookSet{onEvent: func() {}})
}`,
		},
		{
			name: "nested closure called after inline restore",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise() {
	orig := probe
	cl := func() { probe = func() int { return 2 } }
	probe = orig
	cl()
}`,
		},
		{
			name: "closure escaping via named return",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func MakeWriter() (fn func()) {
	orig := probe
	defer func() { probe = orig }()
	fn = func() { probe = func() int { return 2 } }
	return
}`,
		},
		{
			name: "closure escaping via composite return",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func MakeWriters() []func() {
	orig := probe
	defer func() { probe = orig }()
	return []func(){func() { probe = func() int { return 2 } }}
}`,
		},
		{
			name: "LIFO defer inversion with conflicting second defer",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise() {
	orig := probe
	defer func() { probe = func() int { return 9 } }()
	defer func() { probe = orig }()
	probe = func() int { return 2 }
}`,
		},
		{
			name: "nested block defer with outer inline restore",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise(cond bool) {
	orig := probe
	if cond {
		defer func() { probe = func() int { return 9 } }()
	}
	probe = orig
}`,
		},
		{
			name: "composite saved local field mutated before restore",
			src: `package p
func defaultProbe() int { return 1 }
type cfg struct{ fn func() int }
var state = cfg{fn: defaultProbe}
func Exercise() {
	orig := state
	orig.fn = func() int { return 99 }
	state = cfg{fn: func() int { return 2 }}
	defer func() { state = orig }()
}`,
		},
		{
			name: "atomic pointer defer store before defer unlock",
			src: `package p
import (
	"sync"
	"sync/atomic"
)
type hookSet struct{ onEvent func() }
var (
	hookMu  sync.Mutex
	hookPtr atomic.Pointer[hookSet]
)
func RunWithHooks() {
	hookMu.Lock()
	defer hookPtr.Store(nil)
	defer hookMu.Unlock()
	hookPtr.Store(&hookSet{onEvent: func() {}})
}`,
		},
		{
			name: "atomic pointer non-nil store before defer nil store",
			src: `package p
import (
	"sync"
	"sync/atomic"
)
type hookSet struct{ onEvent func() }
var (
	hookMu  sync.Mutex
	hookPtr atomic.Pointer[hookSet]
)
func RunWithHooks() {
	hookMu.Lock()
	defer hookMu.Unlock()
	hookPtr.Store(&hookSet{onEvent: func() {}})
	defer hookPtr.Store(nil)
}`,
		},
		{
			name: "atomic pointer stored under different mutexes",
			src: `package p
import (
	"sync"
	"sync/atomic"
)
type hookSet struct{ onEvent func() }
var (
	hookMuA sync.Mutex
	hookMuB sync.Mutex
	hookPtr atomic.Pointer[hookSet]
)
func RunA() {
	hookMuA.Lock()
	defer hookMuA.Unlock()
	defer hookPtr.Store(nil)
	hookPtr.Store(&hookSet{onEvent: func() {}})
}
func RunB() {
	hookMuB.Lock()
	defer hookMuB.Unlock()
	defer hookPtr.Store(nil)
	hookPtr.Store(&hookSet{onEvent: func() {}})
}`,
		},
		{
			name: "atomic pointer store inside nested closure",
			src: `package p
import (
	"sync"
	"sync/atomic"
)
type hookSet struct{ onEvent func() }
var (
	hookMu  sync.Mutex
	hookPtr atomic.Pointer[hookSet]
)
func MakeSetter() func() {
	hookMu.Lock()
	defer hookMu.Unlock()
	defer hookPtr.Store(nil)
	return func() {
		hookPtr.Store(&hookSet{onEvent: func() {}})
	}
}`,
		},
		{
			name: "inner Cleanup inside nested closure overwrites outer restore",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func TestInnerCleanupOverwritesOuterRestore(t *testing.T) {
	orig1 := probe
	probe = func() int { return 2 }
	func() {
		orig2 := probe
		t.Cleanup(func() { probe = orig2 })
		probe = func() int { return 3 }
	}()
	probe = orig1
}`,
		},
		{
			name: "non-testing Cleanup method does not discharge write",
			src: `package p
type fakeCleaner struct{}
func (*fakeCleaner) Cleanup(func()) {}
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise(c *fakeCleaner) {
	orig := probe
	c.Cleanup(func() { probe = orig })
	probe = func() int { return 2 }
}`,
		},
		{
			name: "locally bracketed write inside testing.B.RunParallel closure",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func BenchmarkRace(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			orig := probe
			defer func() { probe = orig }()
			probe = func() int { return 2 }
		}
	})
}`,
		},
		{
			name: "locally bracketed inline write inside time.AfterFunc closure",
			src: `package p
import "time"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Schedule() {
	time.AfterFunc(time.Millisecond, func() {
		orig := probe
		probe = func() int { return 2 }
		probe = orig
	})
}`,
		},
		{
			name: "pure-load atomic.Pointer hook with escaping Load result",
			src: `package p
import "sync/atomic"
type hookSet struct{ onEvent func() }
var hookPtr atomic.Pointer[hookSet]
func Leak() *hookSet {
	return hookPtr.Load()
}`,
		},
		{
			name: "pure-load atomic.Pointer hook populated in init",
			src: `package p
import "sync/atomic"
type hookSet struct{ onEvent func() }
var hookPtr atomic.Pointer[hookSet]
func init() {
	hookPtr.Store(&hookSet{onEvent: func() {}})
}
func Emit() {
	if h := hookPtr.Load(); h != nil && h.onEvent != nil {
		h.onEvent()
	}
}`,
		},
		{
			name: "pure-load exported atomic.Pointer hook",
			src: `package p
import "sync/atomic"
type HookSet struct{ OnEvent func() }
var HookPtr atomic.Pointer[HookSet]
func Emit() {
	if h := HookPtr.Load(); h != nil && h.OnEvent != nil {
		h.OnEvent()
	}
}`,
		},
		{
			name: "throwaway zero-value testing.T Cleanup never executes",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Mutate() {
	var fake testing.T
	orig := probe
	probe = func() int { return 2 }
	fake.Cleanup(func() { probe = orig })
}`,
		},
		{
			name: "inline composite literal testing.T Cleanup never executes",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Mutate() {
	orig := probe
	probe = func() int { return 2 }
	(&testing.T{}).Cleanup(func() { probe = orig })
}`,
		},
		{
			name: "testing.TB interface parameter admits custom noop implementation",
			src: `package p
import "testing"
type noopTB struct{ testing.TB }
func (noopTB) Cleanup(func()) {}
func defaultProbe() int { return 1 }
var probe = defaultProbe
func swapTB(tb testing.TB) {
	orig := probe
	probe = func() int { return 2 }
	tb.Cleanup(func() { probe = orig })
}
func TestNoopTB(t *testing.T) {
	_ = t
	swapTB(noopTB{})
}`,
		},
		{
			name: "exported non-runner function taking testing.T rejected",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func ExportedSwap(t *testing.T) {
	orig := probe
	probe = func() int { return 2 }
	t.Cleanup(func() { probe = orig })
}`,
		},
		{
			name: "uncalled helper taking testing.T rejected",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func unusedSwap(t *testing.T) {
	orig := probe
	probe = func() int { return 2 }
	t.Cleanup(func() { probe = orig })
}`,
		},
		{
			name: "Test function invoked directly with synthetic testing.T rejected",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func TestSeam(t *testing.T) {
	orig := probe
	probe = func() int { return 2 }
	t.Cleanup(func() { probe = orig })
}
func TestCaller(t *testing.T) {
	_ = t
	TestSeam(&testing.T{})
}`,
		},
		{
			name: "dereference overwrite of testing.T invalidates Cleanup provenance",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func TestClobberT(t *testing.T) {
	orig := probe
	probe = func() int { return 2 }
	t.Cleanup(func() { probe = orig })
	*t = testing.T{}
}`,
		},
		{
			name: "outer testing.T captured inside nested IIFE Cleanup",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func TestOuterCapture(t *testing.T) {
	func() {
		orig := probe
		probe = func() int { return 2 }
		t.Cleanup(func() { probe = orig })
	}()
}`,
		},
		{
			name: "outer testing.T passed to helper inside t.Run subtest",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func swapProbe(t *testing.T, fn func() int) {
	orig := probe
	probe = fn
	t.Cleanup(func() { probe = orig })
}
func TestSubMismatch(t *testing.T) {
	t.Run("sub", func(subT *testing.T) {
		_ = subT
		swapProbe(t, func() int { return 2 })
	})
}`,
		},
		{
			name: "LIFO conflict between defer restore and helper Cleanup restore",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func swapProbe(t *testing.T, fn func() int) {
	orig := probe
	probe = fn
	t.Cleanup(func() { probe = orig })
}
func TestMixedLIFO(t *testing.T) {
	orig := probe
	probe = func() int { return 2 }
	defer func() { probe = orig }()
	swapProbe(t, func() int { return 3 })
}`,
		},
		{
			name: "LIFO conflict between zero-reset defer and helper Cleanup restore",
			src: `package p
import "testing"
var probe func() int
func swapProbe(t *testing.T, fn func() int) {
	orig := probe
	probe = fn
	t.Cleanup(func() { probe = orig })
}
func TestMixedZeroResetLIFO(t *testing.T) {
	probe = func() int { return 2 }
	defer func() { probe = nil }()
	swapProbe(t, func() int { return 3 })
}`,
		},
		{
			name: "LIFO conflict between inline restore and helper Cleanup restore",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func swapProbe(t *testing.T, fn func() int) {
	orig := probe
	probe = fn
	t.Cleanup(func() { probe = orig })
}
func TestInlinePlusCleanup(t *testing.T) {
	orig := probe
	probe = func() int { return 2 }
	swapProbe(t, func() int { return 3 })
	probe = orig
}`,
		},
		{
			name: "exported uninitialized variable cannot use zero-reset",
			src: `package p
var Probe func() int
func Exercise() {
	Probe = func() int { return 2 }
	defer func() { Probe = nil }()
}`,
		},
		{
			name: "blank-identifier package initializer writing var invalidates zero-reset",
			src: `package p
var hook func() int
var _ = func() int {
	hook = func() int { return 1 }
	return 0
}()
func Exercise() {
	hook = func() int { return 2 }
	defer func() { hook = nil }()
}`,
		},
		{
			name: "non-exempt helper write invalidates zero-reset",
			src: `package p
var hook func() int
func SetupDefault() {
	hook = func() int { return 1 }
}
func Exercise() {
	hook = func() int { return 2 }
	defer func() { hook = nil }()
}`,
		},
		{
			name: "implicit pointer-receiver method call on scalar struct seam",
			src: `package p
type holder struct{ fn func() int }
func (h *holder) Clear() { h.fn = nil }
var state holder
func Exercise() {
	orig := state
	state = holder{fn: func() int { return 2 }}
	defer func() { state = orig }()
	state.Clear()
}`,
		},
		{
			name: "early return inside defer closure before restore assignment",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise(skip bool) {
	orig := probe
	probe = func() int { return 2 }
	defer func() {
		if skip {
			return
		}
		probe = orig
	}()
}`,
		},
		{
			name: "early return inside Cleanup closure before restore assignment",
			src: `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func TestEarlyReturnCleanup(t *testing.T) {
	skip := true
	orig := probe
	probe = func() int { return 2 }
	t.Cleanup(func() {
		if skip {
			return
		}
		probe = orig
	})
}`,
		},
		{
			name: "synchronous IIFE panic inside defer closure before restore assignment",
			src: `package p
func defaultProbe() int { return 1 }
var probe = defaultProbe
func Exercise() {
	orig := probe
	probe = func() int { return 2 }
	defer func() {
		func() { panic("abort before restore") }()
		probe = orig
	}()
}`,
		},
	}
	for _, tc := range negativeCases {
		t.Run("negative/"+tc.name, func(t *testing.T) {
			fact := deriveFact(t, tc.src)
			if len(fact.Mutates) == 0 && len(fact.Escapes) == 0 && len(fact.EnvCarrying) == 0 && len(fact.AttributedUses) == 0 {
				t.Fatalf("unbracketed/unsound seam was exempted: %+v", fact)
			}
		})
	}

	// Unaudited sync/atomic must fail closed even when syntax matches the
	// mutex-bracketed or pure-Load seam shape (REQ-closure-shared-dynamic-state-atomic).
	for _, name := range []string{
		"mutex-bracketed atomic.Pointer hook",
		"pure-load uninitialized atomic.Pointer hook without in-package Store",
	} {
		var src string
		for _, tc := range positiveCases {
			if tc.name == name {
				src = tc.src
				break
			}
		}
		t.Run("unaudited/"+name, func(t *testing.T) {
			fact := deriveFactWithAudit(t, false, src)
			if len(fact.Mutates) == 0 && len(fact.Escapes) == 0 && len(fact.EnvCarrying) == 0 && len(fact.AttributedUses) == 0 {
				t.Fatalf("unaudited atomic.Pointer seam was exempted despite audited=false: %+v", fact)
			}
		})
	}

	t.Run("non_test_file/TestSeam in production file rejected", func(t *testing.T) {
		fact := deriveFactFile(t, true, "p.go", `package p
import "testing"
func defaultProbe() int { return 1 }
var probe = defaultProbe
func TestSeam(t *testing.T) {
	orig := probe
	t.Cleanup(func() { probe = orig })
	probe = func() int { return 2 }
}`)
		if len(fact.Mutates) == 0 && len(fact.Escapes) == 0 && len(fact.EnvCarrying) == 0 && len(fact.AttributedUses) == 0 {
			t.Fatalf("TestSeam Cleanup in non-_test.go file was exempted: %+v", fact)
		}
	})
}

// explainView builds a view over the module tree and returns the
// chain for the named culprit.
func explainView(t *testing.T, dir, pkgPath, varName string) Chain {
	t.Helper()
	return explainViewForSubject(t, dir, Subject{Package: pkgPath, Symbol: "Count"}, pkgPath, varName)
}

func explainViewForSubject(t *testing.T, dir string, s Subject, pkgPath, varName string) Chain {
	t.Helper()
	if chain, ok := inMemoryExplainViewForSubject(t, dir, s, pkgPath, varName); ok {
		return chain
	}
	engine, err := newEngine(withDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(context.Background(), []Subject{s}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := view.Capture(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(context.Background(), fp, s)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Ground.Cause.Kind == SharedDynamicStateCause {
		parsed, ok := CulpritFromReason(verdict.Reason)
		if !ok || verdict.Ground.Cause.Culprit != parsed {
			t.Fatalf("Verdict.Ground.Cause.Culprit = %+v, CulpritFromReason(%q) = (%+v, %v)", verdict.Ground.Cause.Culprit, verdict.Reason, parsed, ok)
		}
	} else if verdict.Ground.Cause.Culprit != (Subject{}) {
		t.Fatalf("non-shared-state verdict carried culprit: %+v", verdict.Ground.Cause)
	}
	chain, err := view.ExplainDynamicState(context.Background(), pkgPath, varName)
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

//gofresh:pure
func TestExplainChains(t *testing.T) {
	goMod := "module example.com/explain\n\ngo 1.26\n"

	t.Run("environment-audit chain reaches the refusing expression", func(t *testing.T) {
		// The registration stores an unjudged method value through a
		// constructor: the chain must carry the store, the dependency
		// edge into the constructor, and the innermost refusal with
		// its position.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc gen() map[string]handler {\n\tc := &counter{}\n\treturn map[string]handler{\"k\": c.Next}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "environment-audit" {
			t.Fatalf("arm = %q, want environment-audit; chain %+v", chain.Arm, chain)
		}
		var haveEdge, haveRefusal bool
		for _, l := range chain.Links {
			if l.Kind == "edge" && strings.Contains(l.Callee, "gen") {
				haveEdge = true
			}
			if l.Kind == "refusal" && l.Symbol == "gen" {
				haveRefusal = true
				if !strings.Contains(l.Pos, "reg.go:") {
					t.Fatalf("refusal position missing: %+v", l)
				}
				if l.Clause == "" {
					t.Fatalf("refusal clause empty: %+v", l)
				}
			}
		}
		if !haveEdge || !haveRefusal {
			t.Fatalf("chain lacks edge or refusal: %+v", chain)
		}
	})
	t.Run("cross-package edge chain names the foreign refusal", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"law/law.go": "package law\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype Handler func(n int) int\n\nfunc Build() []Handler {\n\tc := &counter{}\n\treturn []Handler{c.Next}\n}\n",
			"reg/reg.go": "package reg\n\nimport \"example.com/explain/law\"\n\nfunc gen() []law.Handler { return law.Build() }\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "environment-audit" {
			t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
		}
		var crossEdge, foreignRefusal bool
		for _, l := range chain.Links {
			if l.Kind == "edge" && strings.Contains(l.Callee, "law.Build") {
				crossEdge = true
			}
			if l.Kind == "refusal" && l.Symbol == "Build" && strings.Contains(l.Package, "law") {
				foreignRefusal = true
			}
		}
		if !crossEdge || !foreignRefusal {
			t.Fatalf("cross-package chain incomplete: %+v", chain)
		}
	})
	t.Run("direct registration store carries the store link", func(t *testing.T) {
		// A carrying value stored at the registration itself (no
		// constructor in between): the chain's store link names the
		// site.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nvar shared = &counter{}\n\nvar Registry = map[string]handler{\"k\": shared.Next}\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "environment-audit" {
			t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
		}
		var haveStore bool
		for _, l := range chain.Links {
			if l.Kind == "store" && strings.Contains(l.Pos, "reg.go:") {
				haveStore = true
			}
		}
		if !haveStore {
			t.Fatalf("chain lacks a positioned store link: %+v", chain)
		}
	})
	t.Run("mutation chain names the deciding site", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry = map[string]handler{\"d\": double}\n\nfunc Add(h handler) { Registry[\"x\"] = h }\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "mutation" {
			t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
		}
		if len(chain.Links) == 0 || !strings.Contains(chain.Links[0].Pos, "reg.go:") {
			t.Fatalf("mutation chain lacks a positioned site: %+v", chain)
		}
	})
	t.Run("a proven constructor yields an empty chain", func(t *testing.T) {
		// The registration's every dependency edge resolves: no chain,
		// even though a dependency edge exists.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen() map[string]handler {\n\treturn map[string]handler{\"d\": double}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "" || len(chain.Links) != 0 {
			t.Fatalf("expected empty chain for a proven constructor, got %+v", chain)
		}
	})
	t.Run("a test-file culprit chains from the test variant", func(t *testing.T) {
		// The verdict's scope includes test variants; explain must see
		// the same declarations.
		files := map[string]string{
			"go.mod":          goMod,
			"reg/reg.go":      "package reg\n\nfunc Count() int { return 0 }\n",
			"reg/reg_test.go": "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Hooks = map[string]handler{\"d\": double}\n\nfunc install(h handler) { Hooks[\"x\"] = h }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Hooks")
		if chain.Arm != "mutation" || len(chain.Links) == 0 {
			t.Fatalf("test-file culprit not chained: %+v", chain)
		}
		if !strings.Contains(chain.Links[0].Pos, "reg_test.go:") {
			t.Fatalf("mutation site not in the test file: %+v", chain.Links[0])
		}
	})
	t.Run("an importer's mutation chains against the owning package", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry = map[string]Handler{\"d\": double}\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/explain/reg\"\n\nfunc Install(h reg.Handler) { reg.Registry[\"x\"] = h }\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainViewForSubject(t, dir, Subject{Package: "example.com/explain/user", Symbol: "F"}, "example.com/explain/reg", "Registry")
		if chain.Arm != "mutation" || len(chain.Links) == 0 {
			t.Fatalf("importer mutation not chained: %+v", chain)
		}
		if !strings.Contains(chain.Links[0].Pos, "user.go:") {
			t.Fatalf("mutation site not in the importing package: %+v", chain.Links[0])
		}
	})
	t.Run("refusal clauses stay in the spec vocabulary", func(t *testing.T) {
		// REQ-explain-vocabulary: every emitted clause is one of the
		// spec's enumerated families.
		allowed := map[string]bool{
			"write or capture broke the binding":                    true,
			"a binding source refused":                              true,
			"a stored value refused":                                true,
			"callee outside the audited set and dependency channel": true,
			"a literal element refused":                             true,
			"an unadmitted derivation shape":                        true,
			"an unrecognized return shape":                          true,
		}
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc gen() map[string]handler {\n\tc := &counter{}\n\treturn map[string]handler{\"k\": c.Next}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		var sawRefusal bool
		for _, l := range chain.Links {
			if l.Kind != "refusal" {
				continue
			}
			sawRefusal = true
			if !allowed[l.Clause] {
				t.Fatalf("clause %q outside the spec vocabulary", l.Clause)
			}
		}
		if !sawRefusal {
			t.Fatalf("no refusal link to check: %+v", chain)
		}
	})
	t.Run("a foreign direct registration chains with its store", func(t *testing.T) {
		// An importing package's init stores a method value straight
		// into the culprit: the store link lands from the foreign
		// package's analysis.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry = map[string]Handler{\"d\": double}\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/explain/reg\"\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\nfunc init() {\n\tc := &counter{}\n\treg.Registry[\"k\"] = c.Next\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainViewForSubject(t, dir, Subject{Package: "example.com/explain/user", Symbol: "F"}, "example.com/explain/reg", "Registry")
		if chain.Arm != "environment-audit" || len(chain.Links) == 0 {
			t.Fatalf("foreign registration not chained: %+v", chain)
		}
		var haveForeign bool
		for _, l := range chain.Links {
			if l.Kind == "store" && strings.Contains(l.Package, "user") && strings.Contains(l.Pos, "user.go:") {
				haveForeign = true
			}
		}
		if !haveForeign {
			t.Fatalf("foreign store link missing: %+v", chain)
		}
	})
	t.Run("a foreign constructor registration chains its edge", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry = map[string]Handler{\"d\": double}\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/explain/reg\"\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\nfunc mk() reg.Handler {\n\tc := &counter{}\n\treturn c.Next\n}\n\nfunc init() {\n\treg.Registry[\"k\"] = mk()\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainViewForSubject(t, dir, Subject{Package: "example.com/explain/user", Symbol: "F"}, "example.com/explain/reg", "Registry")
		var haveEdge, haveRefusal bool
		for _, l := range chain.Links {
			if l.Kind == "edge" && strings.Contains(l.Package, "user") && strings.Contains(l.Callee, "mk") {
				haveEdge = true
			}
			if l.Kind == "refusal" && l.Symbol == "mk" {
				haveRefusal = true
			}
		}
		if !haveEdge || !haveRefusal {
			t.Fatalf("foreign constructor chain incomplete: %+v", chain)
		}
	})
	t.Run("a test-file constructor refusal keeps its link", func(t *testing.T) {
		// The refused function exists only in the test variant; the
		// refusal re-derivation must run that variant.
		files := map[string]string{
			"go.mod":          goMod,
			"reg/reg.go":      "package reg\n\nfunc Count() int { return 0 }\n",
			"reg/reg_test.go": "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc mk() map[string]handler {\n\tc := &counter{}\n\treturn map[string]handler{\"k\": c.Next}\n}\n\nvar Hooks = mk()\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Hooks")
		if chain.Arm != "environment-audit" {
			t.Fatalf("arm = %q; chain %+v", chain.Arm, chain)
		}
		var haveRefusal bool
		for _, l := range chain.Links {
			if l.Kind == "refusal" && l.Symbol == "mk" && strings.Contains(l.Pos, "reg_test.go:") {
				haveRefusal = true
			}
		}
		if !haveRefusal {
			t.Fatalf("test-variant refusal link missing: %+v", chain)
		}
	})
	t.Run("a non-culprit yields an empty chain", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry = map[string]handler{\"d\": double}\n\nfunc Count() int { return len(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "" || len(chain.Links) != 0 {
			t.Fatalf("expected empty chain for a non-culprit, got %+v", chain)
		}
	})
}

//gofresh:pure
func TestExplainDeferralChains(t *testing.T) {
	goMod := "module example.com/explain\n\ngo 1.26\n"

	t.Run("unproven argument deferral names the callee parameter", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar sink []entry\n\nfunc grab(es []entry) int {\n\tsink = es\n\treturn len(es)\n}\n\nfunc Count() int { return grab(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "escape" || len(chain.Links) == 0 {
			t.Fatalf("chain = %+v, want an escape deferral chain", chain)
		}
		link := chain.Links[0]
		if link.Clause != "a deferred argument's parameter unproven" {
			t.Fatalf("clause = %q - the deferral family is missing", link.Clause)
		}
		if !strings.Contains(link.Callee, "example.com/explain/reg.grab parameter 0") {
			t.Fatalf("callee = %q, want the unproven parameter named", link.Callee)
		}
		if link.Pos == "" || !strings.Contains(link.Pos, "reg.go") {
			t.Fatalf("pos = %q, want the deferring use site", link.Pos)
		}
	})
	t.Run("unproven method deferral is a mutation chain", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct {\n\tn     int\n\thooks []func()\n}\n\nfunc (c *counter) Bump() int {\n\tc.n++\n\treturn c.n\n}\n\nvar Registry = &counter{}\n\nfunc Count() int { return Registry.Bump() }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "mutation" || len(chain.Links) == 0 {
			t.Fatalf("chain = %+v, want a mutation deferral chain", chain)
		}
		link := chain.Links[0]
		if link.Clause != "a deferred method use unproven" {
			t.Fatalf("clause = %q - the deferral family is missing", link.Clause)
		}
		if !strings.Contains(link.Callee, "counter.Bump") {
			t.Fatalf("callee = %q, want the unproven method named", link.Callee)
		}
	})
	t.Run("unproven init receiver deferral is an escape chain", func(t *testing.T) {
		// The retention grade decides an init-flow receiver deferral -
		// a read-only-but-retaining method must still derive a chain
		// naming itself, never an empty derivation.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype box struct{ fns []func() int }\n\nfunc (b *box) Keep() {\n\tgo func() { _ = b.fns }()\n}\n\nfunc (b *box) Tally() int { return len(b.fns) }\n\nfunc one() int { return 1 }\n\nvar Registry = &box{fns: []func() int{one}}\n\nfunc init() {\n\tRegistry.Keep()\n}\n\nfunc Count() int { return Registry.Tally() }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "escape" || len(chain.Links) == 0 {
			t.Fatalf("chain = %+v, want an escape deferral chain for the retained receiver", chain)
		}
		link := chain.Links[0]
		if link.Clause != "an init-flow receiver's method unproven" {
			t.Fatalf("clause = %q - the init receiver deferral family is missing", link.Clause)
		}
		if !strings.Contains(link.Callee, "box.Keep") {
			t.Fatalf("callee = %q, want the unproven method named", link.Callee)
		}
	})
	t.Run("refused field position names the failing registrant", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar Registry []entry\n\nvar sink []string\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: grab}}\n}\n\nfunc Count() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "escape" || len(chain.Links) == 0 {
			t.Fatalf("chain = %+v, want an escape deferral chain", chain)
		}
		link := chain.Links[0]
		if link.Clause != "the registered population refused the field position" {
			t.Fatalf("clause = %q - the field deferral family is missing", link.Clause)
		}
		if !strings.Contains(link.Callee, "Build parameter 0") || !strings.Contains(link.Callee, "example.com/explain/reg.grab parameter 0") {
			t.Fatalf("callee = %q, want the field position and failing registrant named", link.Callee)
		}
	})
	t.Run("object-closed sentinel yields no chain despite unproven deferrals", func(t *testing.T) {
		// The verdict discharges escapes of an opaque interface variable
		// (audited immutable construction); the chain must apply the
		// same proof state - a Valid verdict has no chain.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"boom\")\n\nvar sink error\n\nfunc grab(e error) error {\n\tsink = e\n\treturn e\n}\n\nfunc Count() int {\n\tif grab(ErrX) != nil {\n\t\treturn 1\n\t}\n\treturn 0\n}\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "ErrX")
		if chain.Arm != "" || len(chain.Links) != 0 {
			t.Fatalf("chain = %+v, want empty - an opacity-discharged sentinel earned a chain", chain)
		}
	})
	t.Run("opacity discharge covers direct escape sites", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"boom\")\n\nvar sink []error\n\nfunc Count() int {\n\tsink = append(sink, ErrX)\n\treturn len(sink)\n}\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "ErrX")
		if chain.Arm != "" || len(chain.Links) != 0 {
			t.Fatalf("chain = %+v, want empty - an opacity-discharged direct escape earned a chain", chain)
		}
	})
	t.Run("mixed unproven deferrals rank mutation first", func(t *testing.T) {
		// A carrier with both an unproven argument deferral and an
		// unproven method deferral chains as mutation - the arm the
		// verdict ranking would name.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct {\n\tn     int\n\thooks []func()\n}\n\nfunc (c *counter) Bump() int {\n\tc.n++\n\treturn c.n\n}\n\nvar Registry = &counter{}\n\nvar sink *counter\n\nfunc grab(c *counter) int {\n\tsink = c\n\treturn c.n\n}\n\nfunc Count() int { return Registry.Bump() + grab(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "mutation" || len(chain.Links) == 0 {
			t.Fatalf("chain = %+v, want a mutation chain for mixed deferrals", chain)
		}
	})
	t.Run("direct escape with unproven method deferral ranks mutation", func(t *testing.T) {
		// The verdict reason would say "is mutated" - mutation outranks
		// escape - so the chain's arm must match, the method deferral
		// leading the links.
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype counter struct {\n\tn     int\n\thooks []func()\n}\n\nfunc (c *counter) Bump() int {\n\tc.n++\n\treturn c.n\n}\n\nvar Registry = &counter{}\n\nvar sink []*counter\n\nfunc Count() int {\n\tsink = append(sink, Registry)\n\treturn Registry.Bump()\n}\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "mutation" || len(chain.Links) < 2 {
			t.Fatalf("chain = %+v, want a mutation-armed chain carrying both the deferral and the escape site", chain)
		}
		if chain.Links[0].Clause != "a deferred method use unproven" {
			t.Fatalf("links[0] = %+v, want the mutation-kind deferral leading", chain.Links[0])
		}
	})
	t.Run("refused element position names the owner and registrant", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nvar Legs = map[string]func(v *inv) int{\"w\": grab}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Count() int {\n\treturn Legs[\"w\"](Shared)\n}\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Shared")
		if chain.Arm != "escape" || len(chain.Links) == 0 {
			t.Fatalf("chain = %+v, want an escape deferral chain", chain)
		}
		link := chain.Links[0]
		if link.Clause != "the element population refused the position" {
			t.Fatalf("clause = %q - the element deferral family is missing", link.Clause)
		}
		if !strings.Contains(link.Callee, "example.com/explain/reg.Legs element parameter 0") || !strings.Contains(link.Callee, "example.com/explain/reg.grab parameter 0") {
			t.Fatalf("callee = %q, want the owner and failing registrant named", link.Callee)
		}
	})
	t.Run("resolved deferral contributes no chain", func(t *testing.T) {
		files := map[string]string{
			"go.mod":     goMod,
			"reg/reg.go": "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc width(es []entry) int { return len(es) }\n\nfunc Count() int { return width(Registry) }\n",
		}
		dir := writeModuleTree(t, files)
		chain := explainView(t, dir, "example.com/explain/reg", "Registry")
		if chain.Arm != "" || len(chain.Links) != 0 {
			t.Fatalf("chain = %+v, want empty - a proven deferral earned a chain", chain)
		}
	})
}

//gofresh:pure
func TestExplainChainBound(t *testing.T) {
	// The production shape: stores and edges first, refusals appended
	// innermost-first, the protected index at the first refusal.
	long := Chain{Arm: "environment-audit"}
	for i := 0; i < chainLinkCap+6; i++ {
		long.Links = append(long.Links, ChainLink{Kind: "edge", Symbol: "fn"})
	}
	protect := len(long.Links)
	long.Links = append(long.Links,
		ChainLink{Kind: "refusal", Symbol: "innermost"},
		ChainLink{Kind: "refusal", Symbol: "outer"},
	)
	got := boundChain(long, protect)
	if len(got.Links) != chainLinkCap {
		t.Fatalf("bound kept %d links, want %d", len(got.Links), chainLinkCap)
	}
	if got.Omitted != len(long.Links)-chainLinkCap {
		t.Fatalf("omitted = %d, want %d", got.Omitted, len(long.Links)-chainLinkCap)
	}
	if got.Links[len(got.Links)-1].Symbol != "innermost" {
		t.Fatalf("the innermost refusal was dropped: %+v", got.Links[len(got.Links)-1])
	}
	// A protected link already inside the kept head keeps the chain's
	// tail instead.
	short := Chain{Arm: "mutation"}
	for i := 0; i < chainLinkCap+3; i++ {
		short.Links = append(short.Links, ChainLink{Kind: "culprit", Symbol: "s"})
	}
	short.Links[len(short.Links)-1].Symbol = "tail"
	got = boundChain(short, 0)
	if got.Links[len(got.Links)-1].Symbol != "tail" {
		t.Fatalf("head-protected bound dropped the tail: %+v", got.Links[len(got.Links)-1])
	}
}

//gofresh:pure
func TestExplainChainBoundsSurfaceDerivation(t *testing.T) {
	// A derivation whose environment-audit path is deeper than the
	// link cap bounds end-to-end: the omitted remainder is counted and
	// the innermost refusal survives the bound (REQ-explain-bounded).
	var reg strings.Builder
	reg.WriteString("package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\n")
	const depth = chainLinkCap + 6
	for i := 0; i < depth; i++ {
		if i == depth-1 {
			fmt.Fprintf(&reg, "func gen%d() map[string]handler {\n\tc := &counter{}\n\treturn map[string]handler{\"k\": c.Next}\n}\n\n", i)
			continue
		}
		fmt.Fprintf(&reg, "func gen%d() map[string]handler { return gen%d() }\n\n", i, i+1)
	}
	reg.WriteString("var Registry = gen0()\n\nfunc Count() int { return len(Registry) }\n")
	files := map[string]string{
		"go.mod":     "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": reg.String(),
	}
	dir := writeModuleTree(t, files)
	chain := explainView(t, dir, "example.com/explain/reg", "Registry")
	if chain.Arm != "environment-audit" {
		t.Fatalf("arm = %q, want environment-audit; chain %+v", chain.Arm, chain)
	}
	if chain.Omitted == 0 {
		t.Fatalf("deep chain reported no omitted links: %d links, omitted %d", len(chain.Links), chain.Omitted)
	}
	if len(chain.Links) != chainLinkCap {
		t.Fatalf("bound kept %d links, want %d", len(chain.Links), chainLinkCap)
	}
	last := chain.Links[len(chain.Links)-1]
	if last.Kind != "refusal" {
		t.Fatalf("the innermost refusal did not survive the bound: %+v", last)
	}
}

func TestExplainCarrierLinkedCulpritAndCallResultNonLink(t *testing.T) {
	const src = `package p

type Info struct{ Fn func() }
type Desc interface{ Name() string }
type Out struct{ File Desc }
type Builder struct{ Table []Info }

func (b Builder) Build() Out {
	return Out{}
}

var (
	backing  = []Info{{}}
	Aliased  []Info
	msgTypes = []Info{{}}
	FileDesc Desc
)

func init() {
	initHelper()
}

func initHelper() {
	Aliased = backing
	out := Builder{Table: msgTypes}.Build()
	FileDesc = out.File
}

func Mutate() {
	backing[0] = Info{}
	msgTypes[0] = Info{}
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "p.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	typesPkg, err := (&types.Config{}).Check("example.com/p", fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatal(err)
	}
	pkg := &packages.Package{
		ID:        "example.com/p",
		Name:      "p",
		PkgPath:   "example.com/p",
		Fset:      fset,
		Syntax:    []*ast.File{file},
		Types:     typesPkg,
		TypesInfo: info,
	}
	fact := dynamicStateFactOf(true, pkg, false)
	for _, link := range fact.CarrierLinks {
		if (strings.Contains(link.From, "FileDesc") || strings.Contains(link.To, "FileDesc")) &&
			(strings.Contains(link.From, "msgTypes") || strings.Contains(link.To, "msgTypes")) {
			t.Fatalf("call result out := Builder{Table: msgTypes}.Build() falsely linked FileDesc to msgTypes: %+v", link)
		}
	}
	sawAliasLink := false
	for _, link := range fact.CarrierLinks {
		if (strings.Contains(link.From, "Aliased") && strings.Contains(link.To, "backing")) ||
			(strings.Contains(link.From, "backing") && strings.Contains(link.To, "Aliased")) {
			sawAliasLink = true
		}
	}
	if !sawAliasLink {
		t.Fatalf("direct carrier assignment Aliased = backing missing from CarrierLinks: %v", fact.CarrierLinks)
	}

	// Verify envAuditTrail follows linkedKeys across CarrierLinks.
	linkedFacts := map[string][]dynamicStateFact{
		"example.com/p": {{
			CarrierLinks: []dynstate.CarrierLink{{From: "example.com/p.Aliased", To: "example.com/p.backing"}},
			EnvCarrying:  []string{"example.com/p.backing"},
			EnvCallUses:  []dynstate.EnvCallUse{{Key: "example.com/p.backing", Callee: dynstate.FuncKey{Pkg: "example.com/dep", Name: "Make"}}},
		}},
	}
	edges, refusedFn, refusedPath := envAuditTrail(
		map[string][]*packages.Package{"example.com/dep": {{}}},
		linkedFacts,
		map[string]bool{"example.com/p.Aliased": true, "example.com/p.backing": true},
		"Aliased",
	)
	if len(edges) == 0 || refusedFn != "Make" || refusedPath != "example.com/dep" {
		t.Fatalf("carrier-linked envAuditTrail = (%+v, %q, %q), want edge to example.com/dep.Make", edges, refusedFn, refusedPath)
	}

	dir := writeModuleTree(t, map[string]string{
		"go.mod":     "module example.com/explain\n\ngo 1.26\n",
		"reg/reg.go": "package reg\n\ntype Info struct{ Fn func() }\n\nvar (\n\tbacking = []Info{{}}\n\tAliased []Info\n)\n\nfunc init() {\n\tAliased = backing\n}\n\nfunc Mutate() {\n\tbacking[0] = Info{}\n}\n\nfunc Count() int { return len(Aliased) }\n",
	})
	chain := explainView(t, dir, "example.com/explain/reg", "Aliased")
	if chain.Arm != "mutation" || len(chain.Links) == 0 {
		t.Fatalf("explainView(Aliased) = %+v, want mutation chain derived via CarrierLinks from backing", chain)
	}
}

func TestCulpritFromReason(t *testing.T) {
	for _, tc := range []struct {
		reason string
		want   Subject
		ok     bool
	}{
		{
			reason: "package graph shares mutated dynamic state: example.com/pkg/sub: example.com/pkg/sub.Hooks is mutated",
			want:   Subject{Package: "example.com/pkg/sub", Symbol: "Hooks"},
			ok:     true,
		},
		{
			reason: "gopkg.in/yaml.v3: gopkg.in/yaml.v3.structMap escapes writable",
			want:   Subject{Package: "gopkg.in/yaml.v3", Symbol: "structMap"},
			ok:     true,
		},
		{
			reason: "post-run freshness check: package graph shares mutated dynamic state: github.com/x/b: github.com/x/b.thresholds registers function values outside the environment-free audit",
			want:   Subject{Package: "github.com/x/b", Symbol: "thresholds"},
			ok:     true,
		},
		{
			reason: "os.Getenv (environment variable read)",
			ok:     false,
		},
		{
			reason: "example.com/a: example.com/b.Hooks is mutated",
			ok:     false,
		},
		{
			reason: ": .NoPkg is mutated",
			ok:     false,
		},
		{
			reason: "example.com/pkg: example.com/pkg.123bad is mutated",
			ok:     false,
		},
		{
			reason: "package graph shares mutated dynamic state: example.com/pkg: example.com/pkg.Hooks is mutated (reachability unjudged: analysis budget 1ms exhausted)",
			ok:     false,
		},
	} {
		got, ok := CulpritFromReason(tc.reason)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("CulpritFromReason(%q) = (%+v, %v), want (%+v, %v)", tc.reason, got, ok, tc.want, tc.ok)
		}
	}
}

// A dispatch of an exported method through the receiver's own closed
// interface field chains into every member's declaration: the field
// is closed when every store in the package carries a concrete
// in-package type, a constructor's parameter resolving through its
// direct call sites. Any store of another shape, an escape of the
// field's address, a variadic or escaped or exported constructor, or a
// member promoting the method leaves the dispatch an escape
// (REQ-closure-shared-dynamic-state-receiver-proof).
func TestClosedInterfaceFieldDispatchChains(t *testing.T) {
	const head = "package view\n\ntype impl interface{ String() string }\n\ntype lit string\n\nfunc (l lit) String() string { return string(l) }\n\ntype gen struct {\n\timpl impl\n\tcb   func()\n}\n\nfunc (g *gen) String() string { return g.impl.String() }\n\n"
	cases := []struct {
		name, rest string
		valid      bool
	}{
		{"literal store of a concrete type", "var G = &gen{impl: lit(\"x\")}\n\nfunc F() string { return G.String() }\n", true},
		{"positional literal store", "var G = &gen{lit(\"x\"), nil}\n\nfunc F() string { return G.String() }\n", true},
		{"constructor parameter resolved through its call sites", "func newGen(i impl) *gen { return &gen{impl: i} }\n\nvar G = newGen(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", true},
		{"generic constructor", "type box[T any] struct{ v T }\n\nfunc (b box[T]) String() string { return \"box\" }\n\nfunc newGen2[T any](i impl, _ T) *gen { return &gen{impl: i} }\n\nvar G = newGen2[int](box[int]{}, 1)\n\nfunc F() string { return G.String() }\n", true},
		{"assignment store in init", "var G = &gen{impl: lit(\"x\")}\n\nfunc init() { G.impl = lit(\"y\") }\n\nfunc F() string { return G.String() }\n", true},
		{"a member writing a carrier", "type bad struct{ cb func() }\n\nfunc (b *bad) String() string {\n\tb.cb = nil\n\treturn \"bad\"\n}\n\nvar G = &gen{impl: lit(\"x\")}\n\nvar H = &gen{impl: &bad{}}\n\nfunc F() string { return G.String() }\n", false},
		{"store of an interface-typed call result", "func pick() impl { return lit(\"p\") }\n\nvar G = &gen{impl: pick()}\n\nfunc F() string { return G.String() }\n", false},
		{"constructor parameter fed an interface value", "func newGen(i impl) *gen { return &gen{impl: i} }\n\nfunc pick() impl { return lit(\"p\") }\n\nvar G = newGen(pick())\n\nfunc F() string { return G.String() }\n", false},
		{"variadic constructor", "func newGen(is ...impl) *gen { return &gen{impl: is[0]} }\n\nvar G = newGen(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", false},
		{"exported constructor", "func NewGen(i impl) *gen { return &gen{impl: i} }\n\nvar G = NewGen(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", false},
		{"escaped constructor value", "func newGen(i impl) *gen { return &gen{impl: i} }\n\nvar mk = newGen\n\nvar G = newGen(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", false},
		{"field address taken", "var G = &gen{impl: lit(\"x\")}\n\nvar p = &G.impl\n\nfunc F() string { return G.String() }\n", false},
		{"member promoting the method", "type base struct{}\n\nfunc (base) String() string { return \"b\" }\n\ntype promoted struct{ base }\n\nvar G = &gen{impl: promoted{}}\n\nfunc F() string { return G.String() }\n", false},
		{"conversion from an identical struct type", "type other struct {\n\timpl impl\n\tcb   func()\n}\n\nfunc pick() impl { return lit(\"p\") }\n\nvar G = &gen{impl: lit(\"x\")}\n\nfunc init() { *G = gen(other{impl: pick()}) }\n\nfunc F() string { return G.String() }\n", false},
		{"store through an embedded promotion", "type outer struct{ gen }\n\nfunc pick() impl { return lit(\"p\") }\n\nvar O = &outer{gen: gen{impl: lit(\"x\")}}\n\nfunc init() { O.impl = pick() }\n\nvar G = &gen{impl: lit(\"x\")}\n\nfunc F() string { return G.String() }\n", false},
		{"parameter reassigned in its body", "func pick() impl { return lit(\"p\") }\n\nfunc newGen(i impl) *gen {\n\tif i == nil {\n\t\ti = pick()\n\t}\n\treturn &gen{impl: i}\n}\n\nvar G = newGen(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", false},
		{"fixed parameter of a variadic constructor", "func newGen(i impl, rest ...int) *gen { return &gen{impl: i} }\n\nvar G = newGen(lit(\"x\"), 1, 2)\n\nfunc F() string { return G.String() }\n", true},
		{"constructor never called", "func unused(i impl) *gen { return &gen{impl: i} }\n\nvar G = &gen{impl: lit(\"x\")}\n\nfunc F() string { return G.String() }\n", false},
		{"promoted store of a concrete type", "type outer struct{ gen }\n\nvar O = &outer{gen: gen{impl: lit(\"x\")}}\n\nfunc init() { O.impl = lit(\"y\") }\n\nvar G = &gen{impl: lit(\"x\")}\n\nfunc F() string { return G.String() }\n", true},
		{"field read into a local", "var G = &gen{impl: lit(\"x\")}\n\nfunc (g *gen) Via() string {\n\tv := g.impl\n\treturn v.String()\n}\n\nfunc F() string { return G.Via() }\n", false},
		{"method parameter store", "type factory struct{}\n\nfunc (factory) make(i impl) *gen { return &gen{impl: i} }\n\nvar G = factory{}.make(lit(\"x\"))\n\nfunc F() string { return G.String() }\n", false},
	}
	t.Run("a foreign concrete member opens the field", func(t *testing.T) {
		t.Parallel()
		source := "package view\n\nimport \"time\"\n\ntype impl interface{ String() string }\n\ntype lit string\n\nfunc (l lit) String() string { return string(l) }\n\ntype gen struct {\n\timpl impl\n\tcb   func()\n}\n\nfunc (g *gen) String() string { return g.impl.String() }\n\nvar G = &gen{impl: lit(\"x\")}\n\nvar H = &gen{impl: time.Month(1)}\n\nfunc F() string { return G.String() }\n"
		dir := writeViewModule(t, source)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G") {
			t.Fatalf("verdict = %+v, want the refusal naming G — a foreign member's method was chained", verdict)
		}
	})
	t.Run("an exported field is never closed", func(t *testing.T) {
		t.Parallel()
		source := "package view\n\ntype impl interface{ String() string }\n\ntype lit string\n\nfunc (l lit) String() string { return string(l) }\n\ntype gen struct {\n\tImpl impl\n\tcb   func()\n}\n\nfunc (g *gen) String() string { return g.Impl.String() }\n\nvar G = &gen{Impl: lit(\"x\")}\n\nfunc F() string { return G.String() }\n"
		dir := writeViewModule(t, source)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G") {
			t.Fatalf("verdict = %+v, want the refusal naming G — an exported field, writable from any importer, was closed", verdict)
		}
	})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := writeViewModule(t, head+tc.rest)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if tc.valid && verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid — a closed field's exported dispatch broke the proof", verdict)
			}
			if !tc.valid && (verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G")) {
				t.Fatalf("verdict = %+v, want the refusal naming G — an open field's dispatch was chained", verdict)
			}
		})
	}
}

func writeBoundedViewFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/boundedview\n\ngo 1.26\n",
		"lib.go": `package boundedview

type Number interface{ ~int | ~float64 }

func Sum[T Number](a, b T) T { return a + b }

func Value[T any]() int { return 1 }

func UseBoth() int {
	Value[int]()
	return int(Sum(1, 2))
}
`,
		"lib_test.go": "package boundedview\n\nimport \"testing\"\n\nfunc TestUse(t *testing.T) {\n\tif UseBoth() != 3 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func writeInitFixture(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The once-filled memo keeps the receiver-effect proof: a data-plane
// field written directly in the literal a receiver-rooted sync.Once's
// Do runs fills once per receiver, so a call on the package-level
// carrier marks nothing. Every other receiver write — a counter, a
// data slice element, a fill through a bound method or a local Once, a
// carrier field inside the Do — keeps the mark. A dispatch of an
// unexported interface method chains into every in-package declaration
// of that name; an exported method's dispatch chains through the
// receiver's closed interface field (REQ-closure-shared-dynamic-state-receiver-proof).
func TestOnceFilledMemoKeepsTheProof(t *testing.T) {
	const gen = "package view\n\nimport \"sync\"\n\ntype impl interface {\n\tString() string\n\tvalue() int\n\tslice() []int\n}\n\ntype lit string\n\nfunc (l lit) String() string { return string(l) }\n\nfunc (l lit) value() int { return len(l) }\n\nfunc (l lit) slice() []int { return nil }\n\ntype gen struct {\n\timpl  impl\n\tonce  sync.Once\n\tstr   string\n\tn     int\n\tnames []string\n\tfns   []func() int\n\tcb    func()\n\tm     map[string]int\n\thooks map[string]func()\n}\n\n"
	cases := []struct {
		name, methods, subject string
		valid                  bool
	}{
		{"once-filled data field", "func (g *gen) Value() int {\n\tg.once.Do(func() { g.n = g.impl.value() })\n\treturn g.n\n}\n", "func F() int { return G.Value() }\n", true},
		// The exported dispatch chains through the closed field: the
		// fixture stores one concrete type into impl.
		{"exported dispatch through the closed field", "func (g *gen) String() string { return g.impl.String() }\n", "func F() string { return G.String() }\n", true},
		{"once-filled counter", "func (g *gen) Count() int {\n\tg.once.Do(func() { g.n++ })\n\treturn g.n\n}\n", "func F() int { return G.Count() }\n", true},
		{"once-filled data slice element", "func (g *gen) Name() string {\n\tg.once.Do(func() { g.names[0] = \"x\" })\n\treturn g.names[0]\n}\n", "func F() string { return G.Name() }\n", true},
		{"counter outside the once", "func (g *gen) Next() int {\n\tg.n++\n\treturn g.n\n}\n", "func F() int { return G.Next() }\n", false},
		{"data slice element outside the once", "func (g *gen) Set() string {\n\tg.names[0] = \"x\"\n\treturn g.names[0]\n}\n", "func F() string { return G.Set() }\n", false},
		{"once-filled carrier field", "func (g *gen) Swap() int {\n\tg.once.Do(func() { g.impl = lit(\"y\") })\n\treturn 1\n}\n", "func F() int { return G.Swap() }\n", false},
		{"once fill through a bound method", "func (g *gen) fill() { g.str = \"f\" }\n\nfunc (g *gen) Bound() string {\n\tg.once.Do(g.fill)\n\treturn g.str\n}\n", "func F() string { return G.Bound() }\n", false},
		{"fill under a local once", "func (g *gen) Local() string {\n\tvar once sync.Once\n\tonce.Do(func() { g.str = \"l\" })\n\treturn g.str\n}\n", "func F() string { return G.Local() }\n", false},
		{"nested fill inside the once", "func (g *gen) Nested() string {\n\tg.once.Do(func() {\n\t\tif g.str == \"\" {\n\t\t\tg.str = \"n\"\n\t\t}\n\t})\n\treturn g.str\n}\n", "func F() string { return G.Nested() }\n", false},
		{"unexported dispatch", "func (g *gen) Value() int { return g.impl.value() }\n", "func F() int { return G.Value() }\n", true},
		// The result of an unexported dispatch handing out mutable
		// reach escapes outside a governed bind, as a sibling call's does.
		{"unexported dispatch result escapes", "func (g *gen) Slice() int {\n\tg.impl.slice()\n\treturn 1\n}\n", "func F() int { return G.Slice() }\n", false},
		{"interface field write", "func (g *gen) Reset() int {\n\tg.impl = lit(\"y\")\n\treturn 1\n}\n", "func F() int { return G.Reset() }\n", false},
		{"func field write", "func (g *gen) Hook() int {\n\tg.cb = func() {}\n\treturn 1\n}\n", "func F() int { return G.Hook() }\n", false},
		{"func slice element write", "func (g *gen) Slot() int {\n\tg.fns[0] = nil\n\treturn 1\n}\n", "func F() int { return G.Slot() }\n", false},
		{"whole receiver write", "func (g *gen) Zero() int {\n\t*g = gen{}\n\treturn 1\n}\n", "func F() int { return G.Zero() }\n", false},
		// A consuming read allows only its own node: the carrier
		// write after it is refused at its own.
		{"carrier write after a consuming read", "func (g *gen) Both() int {\n\tn := len(g.names)\n\tg.impl = lit(\"y\")\n\treturn n\n}\n", "func F() int { return G.Both() }\n", false},
		// A fill through a tainted alias is judged by the element it
		// writes: data admits, a carrier refuses — the alias's read was
		// consumed, so the element type is the fill's only guard.
		{"once fill through a data alias", "func (g *gen) Alias() int {\n\tg.once.Do(func() {\n\t\tm := g.m\n\t\tm[\"k\"] = 1\n\t})\n\treturn len(g.m)\n}\n", "func F() int { return G.Alias() }\n", true},
		{"once fill through a carrier alias", "func (g *gen) Hooks() int {\n\tg.once.Do(func() {\n\t\th := g.hooks\n\t\th[\"k\"] = func() {}\n\t})\n\treturn len(g.hooks)\n}\n", "func F() int { return G.Hooks() }\n", false},
		// One Once, two literals: the field holds whichever a subject's
		// order fired first — no fill for that Once anywhere.
		{"two Do sites on one once", "func (g *gen) First() string {\n\tg.once.Do(func() { g.str = \"a\" })\n\treturn g.str\n}\n\nfunc (g *gen) Second() string {\n\tg.once.Do(func() { g.str = \"b\" })\n\treturn g.str\n}\n", "func F() string { return G.First() }\n", false},
		// A plain function can fire the Once too: a second site.
		{"Do site outside any method", "func (g *gen) Fill() string {\n\tg.once.Do(func() { g.str = \"a\" })\n\treturn g.str\n}\n\nfunc prime() { G.once.Do(func() {}) }\n", "func F() string {\n\tprime()\n\treturn G.Fill()\n}\n", false},
		// A fill that rewrites the Once re-arms it: refused.
		{"fill re-arming the once", "func (g *gen) Rearm() string {\n\tg.once.Do(func() {\n\t\tg.str = \"r\"\n\t\tg.once = sync.Once{}\n\t})\n\treturn g.str\n}\n", "func F() string { return G.Rearm() }\n", false},
		// A parenthesized target is no selection: refused even in the once.
		{"parenthesized once fill", "func (g *gen) Paren() string {\n\tg.once.Do(func() { (g.str) = \"p\" })\n\treturn g.str\n}\n", "func F() string { return G.Paren() }\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := writeViewModule(t, gen+tc.methods+"\nvar G = &gen{impl: lit(\"x\"), names: []string{\"a\"}, fns: []func() int{nil}, m: map[string]int{}, hooks: map[string]func(){}}\n\n"+tc.subject)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if tc.valid && verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid — a once-filled memo or an unexported dispatch broke the proof", verdict)
			}
			if !tc.valid && (verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G")) {
				t.Fatalf("verdict = %+v, want the refusal naming G — a receiver write outside the once-filled memo was proven read-only", verdict)
			}
		})
	}
	t.Run("composite implementer's carrier-writing declaration is chained", func(t *testing.T) {
		t.Parallel()
		// An unnamed composite promotes the unexported method from an
		// in-package declaration: that declaration is a chain target
		// whatever type promotes it.
		source := "package view\n\ntype impl interface {\n\tString() string\n\tvalue() int\n}\n\ntype a struct{ cb func() }\n\nfunc (x *a) value() int {\n\tx.cb = nil\n\treturn 1\n}\n\ntype b struct{}\n\nfunc (b) String() string { return \"b\" }\n\ntype gen struct{ impl impl }\n\nfunc (g *gen) Value() int { return g.impl.value() }\n\nvar G = &gen{impl: struct {\n\t*a\n\tb\n}{a: &a{}}}\n\nfunc F() int { return G.Value() }\n"
		dir := writeViewModule(t, source)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G") {
			t.Fatalf("verdict = %+v, want the refusal naming G — a composite's promoted carrier write was not chained", verdict)
		}
	})
	t.Run("promoted implementer's clean declaration is chained", func(t *testing.T) {
		t.Parallel()
		source := "package view\n\ntype impl interface {\n\tString() string\n\tvalue() int\n}\n\ntype base struct{}\n\nfunc (base) String() string { return \"b\" }\n\nfunc (base) value() int { return 1 }\n\ntype promoted struct{ base }\n\ntype gen struct{ impl impl }\n\nfunc (g *gen) Value() int { return g.impl.value() }\n\nvar G = &gen{impl: promoted{}}\n\nfunc F() int { return G.Value() }\n"
		dir := writeViewModule(t, source)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid — the promoted declaration is base's own, proven", verdict)
		}
	})
	t.Run("a shared, reachable, or copied once hosts no fill", func(t *testing.T) {
		t.Parallel()
		for name, source := range map[string]string{
			"pointer once":               "package view\n\nimport \"sync\"\n\ntype gen struct {\n\tonce *sync.Once\n\tcb   func()\n\tstr  string\n}\n\nfunc (g *gen) Fill() string {\n\tg.once.Do(func() { g.str = \"p\" })\n\treturn g.str\n}\n\nvar G = &gen{once: new(sync.Once)}\n\nfunc F() string { return G.Fill() }\n",
			"exported once":              "package view\n\nimport \"sync\"\n\ntype gen struct {\n\tOnce sync.Once\n\tcb   func()\n\tstr  string\n}\n\nfunc (g *gen) Fill() string {\n\tg.Once.Do(func() { g.str = \"e\" })\n\treturn g.str\n}\n\nvar G = &gen{}\n\nfunc F() string { return G.Fill() }\n",
			"once behind a pointer step": "package view\n\nimport \"sync\"\n\ntype inner struct{ once sync.Once }\n\ntype gen struct {\n\tp   *inner\n\tcb  func()\n\tstr string\n}\n\nfunc (g *gen) Fill() string {\n\tg.p.once.Do(func() { g.str = \"s\" })\n\treturn g.str\n}\n\nvar shared = &inner{}\n\nvar G = &gen{p: shared}\n\nvar H = &gen{p: shared}\n\nfunc F() string { return G.Fill() + H.Fill() }\n",
			"two onces on one receiver":  "package view\n\nimport \"sync\"\n\ntype gen struct {\n\tonceA, onceB sync.Once\n\tcb           func()\n\ta, b         int\n}\n\nfunc (g *gen) A() int {\n\tg.onceA.Do(func() { g.a = 1 })\n\treturn g.a\n}\n\nfunc (g *gen) B() int {\n\tg.onceB.Do(func() { g.b = g.a })\n\treturn g.b\n}\n\nvar G = &gen{}\n\nfunc F() int { return G.B() }\n",
			"value receiver":             "package view\n\nimport \"sync\"\n\ntype gen struct {\n\tonce sync.Once\n\tcb   func()\n\tm    map[string]int\n}\n\nfunc (g gen) Fill() int {\n\tg.once.Do(func() { g.m[\"k\"] = len(g.m) })\n\treturn g.m[\"k\"]\n}\n\nvar G = &gen{m: map[string]int{}}\n\nfunc F() int { return G.Fill() }\n",
			"embedded once":              "package view\n\nimport \"sync\"\n\ntype gen struct {\n\tsync.Once\n\tcb  func()\n\tstr string\n}\n\nfunc (g *gen) Fill() string {\n\tg.Do(func() { g.str = \"m\" })\n\treturn g.str\n}\n\nvar G = &gen{}\n\nfunc F() string { return G.Fill() }\n",
		} {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				dir := writeViewModule(t, source)
				verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
				if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G") {
					t.Fatalf("verdict = %+v, want the refusal naming G — a shared or reachable Once hosted a fill", verdict)
				}
			})
		}
	})
	t.Run("a test-file declaration installed at init is chained", func(t *testing.T) {
		t.Parallel()
		// The proof is enumerated over the variant's own declarations,
		// and the view's cone takes the test variant alone when one
		// exists: the plain compilation's proof, blind to the test-file
		// fake, is never served for the test binary that links it.
		files := map[string]string{
			"go.mod":            "module example.com/xesc\n\ngo 1.26\n",
			"view/view.go":      "package view\n\ntype impl interface{ value() int }\n\ntype lit struct{}\n\nfunc (lit) value() int { return 1 }\n\ntype gen struct{ impl impl }\n\nfunc (g *gen) Value() int { return g.impl.value() }\n\nvar G = &gen{impl: lit{}}\n\nfunc F() int { return G.Value() }\n",
			"view/view_test.go": "package view\n\ntype fake struct{ cb func() }\n\nfunc (f *fake) value() int {\n\tf.cb = nil\n\treturn 2\n}\n\nfunc init() { G.impl = &fake{} }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/xesc/view.G") {
			t.Fatalf("verdict = %+v, want the refusal naming G — the plain compilation's proof served for the test binary", verdict)
		}
	})
	t.Run("unexported method nobody declares keeps the escape", func(t *testing.T) {
		t.Parallel()
		source := "package view\n\ntype impl interface{ other() int }\n\ntype gen struct{ impl impl }\n\nfunc (g *gen) Other() int {\n\tif g.impl == nil {\n\t\treturn 0\n\t}\n\treturn g.impl.other()\n}\n\nvar G = &gen{}\n\nfunc F() int { return G.Other() }\n"
		dir := writeViewModule(t, source)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.G") {
			t.Fatalf("verdict = %+v, want the refusal naming G — a dispatch with no declaration was chained into nothing", verdict)
		}
	})
}

// The receiver-naming grammar reduces every legal receiver form,
// the parenthesized ones included — a method is never minted as a
// plain-function subject because its receiver wore parentheses.
// The convention shared across the tools is AST-side DECLARATION
// naming: the declarer's name, all three reducers unwrapping the
// same grammar. Subject and binding naming are wider — this
// package's types-side walk and stipulator's lookup both admit
// promoted methods, in agreement.
func TestRecvTypeNameReducesEveryReceiverForm(t *testing.T) {
	cases := []struct {
		recv string
		want string
	}{
		{"T", "T"},
		{"*T", "T"},
		{"(T)", "T"},
		{"(*T)", "T"},
		{"((*T))", "T"},
		{"(((T)))", "T"},
		{"(P[X])", "P"},
		{"((*P[X, Y]))", "P"},
		{"pkg.T", ""}, // a selector receiver is a type error the grammar refuses
		{"[]T", ""},   // as is any non-name form
	}
	for _, tc := range cases {
		src := "package p\ntype T struct{}\nfunc (r " + tc.recv + ") M() {}\n"
		f, err := parser.ParseFile(token.NewFileSet(), "p.go", src, 0)
		if err != nil {
			t.Fatalf("%s: %v", tc.recv, err)
		}
		var fd *ast.FuncDecl
		for _, d := range f.Decls {
			if x, ok := d.(*ast.FuncDecl); ok && x.Recv != nil {
				fd = x
			}
		}
		if got := recvTypeName(fd); got != tc.want {
			t.Errorf("recvTypeName(recv %s) = %q, want %q", tc.recv, got, tc.want)
		}
	}
	// The entry guard's second operand is reachable only from a
	// hand-constructed AST — the parser never yields a receiver-bearing
	// declaration with an empty field list — so construct it directly:
	// the pinned outcome is the guard's "" refusal, not an index panic.
	if got := recvTypeName(&ast.FuncDecl{Name: ast.NewIdent("M"), Recv: &ast.FieldList{}}); got != "" {
		t.Errorf(`recvTypeName(empty receiver list) = %q, want ""`, got)
	}
}

// The mint site honors the grammar's refusal: a receiver-bearing
// declaration whose receiver the grammar cannot name (a type error
// the parser tolerates) yields NO subject — never a plain-function
// phantom under the bare method name. The reducer returning "" is
// necessary but not sufficient for that; this pins the skip itself.
func TestUnnameableReceiverNeverMintsPlainFunctionSubject(t *testing.T) {
	scanFor := func(t *testing.T, src string) *subjectScan {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "q.go", src, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		// The loader's error-package shape: Types allocated before
		// type-checking, info empty — so BOTH minting walks run (the
		// AST walk and the package-scope method-set walk).
		pkg := &packages.Package{
			ID:        "example.com/q",
			PkgPath:   "example.com/q",
			Fset:      fset,
			Syntax:    []*ast.File{f},
			Types:     types.NewPackage("example.com/q", "q"),
			TypesInfo: &types.Info{},
		}
		scan, err := scanSubjectsFromLoaded(true, []*packages.Package{pkg}, &viewDynamicState{}, "example.com/q")
		if err != nil {
			t.Fatal(err)
		}
		return scan
	}
	subject := Subject{Package: "example.com/q", Symbol: "Foo"}
	t.Run("no phantom without a real twin", func(t *testing.T) {
		scan := scanFor(t, "package q\n\n//gofresh:pure\nfunc (r pkg.T) Foo() {}\n")
		// No subject AT ALL — not merely none named Foo: a mint under
		// any residual name (the bare method's, "") is the same
		// phantom class.
		if len(scan.known) != 0 {
			t.Errorf("the skipped declaration minted subjects: %v", scan.known)
		}
		if scan.pure[subject] {
			t.Error("the skipped declaration's //gofresh:pure marked a phantom subject")
		}
	})
	t.Run("a real twin stays clean", func(t *testing.T) {
		scan := scanFor(t, "package q\n\n//gofresh:pure\nfunc (r pkg.T) Foo() {}\n\nfunc Foo() {}\n")
		if !scan.known[subject] {
			t.Fatal("the plain function Foo was not recorded")
		}
		if len(scan.known) != 1 {
			t.Errorf("the skipped declaration minted a subject beside the plain Foo: %v", scan.known)
		}
		if len(scan.ambiguous) != 0 {
			t.Errorf("the skipped method collided with its plain twin: %v", scan.ambiguous)
		}
		if scan.pure[subject] {
			t.Error("the skipped declaration's //gofresh:pure leaked onto the plain function")
		}
	})
}

// testSubjectFacts builds synthetic base observations for verdict-ladder tests.
// Production acquires these inputs from ComputeMaximalFactsBatch and the scan;
// no reverse projection can reconstruct a real complete blocker inventory.
func testSubjectFacts(c closure.Closure) subjectFacts {
	f := subjectFacts{
		source: closure.MaximalFacts{
			Identity: closure.MaximalIdentity{Hash: c.Hash, TestVariants: c.TestVariants,
				ToolchainContent: c.ToolchainContent, AdmissionPolicy: c.AdmissionPolicy},
			Diagnostic: c.Reason,
		},
		external: c.External,
	}
	if c.Unverifiable {
		r := &subjectRefusal{
			reason:  c.Reason,
			culprit: Subject{Package: c.Culprit.Package, Symbol: c.Culprit.Symbol},
		}
		switch c.Refusal {
		case closure.OpenWorldRefusal:
			f.openWorld = r
		case closure.SharedDynamicStateRefusal:
			f.sharedState = r
		case closure.AmbiguousSubjectRefusal:
			f.ambiguous = r
		default:
			f.source.Effects = []closure.Blocker{{Reason: c.Reason}}
		}
	}
	return f
}

func TestSubjectFactsHiddenObligations(t *testing.T) {
	s := Subject{Package: "example.com/base", Symbol: "F"}
	base := testSubjectFacts(closure.Closure{Hash: "source", Unverifiable: true, Reason: "effect"})
	base.source.Effects = append(base.source.Effects, closure.Blocker{Kind: closure.BlockerEnvironment, Package: "os", Symbol: "Getenv"})
	base.openWorld = &subjectRefusal{reason: "open"}
	base.sharedState = &subjectRefusal{reason: "shared"}
	base.ambiguous = &subjectRefusal{reason: "ambiguous"}
	base.external = true
	view := &Snapshot{subjects: []Subject{s}, facts: &observationFacts{maximal: map[Subject]subjectFacts{s: base}}}
	for _, tc := range []struct {
		name   string
		change func(*subjectFacts)
	}{
		{"source effect", func(f *subjectFacts) { f.source.Effects = f.source.Effects[1:] }},
		{"open world", func(f *subjectFacts) { f.openWorld = nil }},
		{"shared state", func(f *subjectFacts) { f.sharedState = nil }},
		{"ambiguous", func(f *subjectFacts) { f.ambiguous = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			tc.change(&changed)
			// Externality still decides both projections. Comparing only that
			// projection would miss the changed underlying obligation.
			if changed.closure().Reason != base.closure().Reason {
				t.Fatal("test did not hide the changed obligation")
			}
			current := observationFacts{maximal: map[Subject]subjectFacts{s: changed}}
			if err := view.compareObservationContext(t.Context(), current); !errors.Is(err, ErrViewChanged) {
				t.Fatalf("hidden obligation change: %v", err)
			}
			current.cut = map[Subject]bool{s: true}
			want := ErrViewChanged
			if tc.name == "shared state" {
				want = ErrAnalysisUnavailable
			}
			if err := view.compareObservationContext(t.Context(), current); !errors.Is(err, want) {
				t.Fatalf("cut comparison: %v, want %v", err, want)
			}
		})
	}
	for _, tc := range []struct {
		name string
		set  func(*subjectFacts, *subjectRefusal)
		kind closure.RefusalKind
	}{
		{"open", func(f *subjectFacts, r *subjectRefusal) { f.openWorld = r }, closure.OpenWorldRefusal},
		{"shared", func(f *subjectFacts, r *subjectRefusal) { f.sharedState = r }, closure.SharedDynamicStateRefusal},
		{"ambiguous", func(f *subjectFacts, r *subjectRefusal) { f.ambiguous = r }, closure.AmbiguousSubjectRefusal},
	} {
		t.Run("empty diagnostic/"+tc.name, func(t *testing.T) {
			f := testSubjectFacts(closure.Closure{Hash: "source"})
			tc.set(&f, &subjectRefusal{})
			if c := f.closure(); !c.Unverifiable || c.Refusal != tc.kind {
				t.Fatalf("empty diagnostic erased obligation: %+v", c)
			}
		})
	}
}

func TestSubjectFactsProjectionAndSiblingIsolation(t *testing.T) {
	s := Subject{Package: "example.com/base", Symbol: "F"}
	base := testSubjectFacts(closure.Closure{Hash: "source", Unverifiable: true, Reason: "effect"})
	base.openWorld = &subjectRefusal{reason: "open"}
	base.sharedState = &subjectRefusal{reason: "shared"}
	load := &closure.ViewLoad{}
	parent := &Snapshot{subjects: []Subject{s}, facts: &observationFacts{
		maximal: map[Subject]subjectFacts{s: base}, source: load,
	}}
	child, err := parent.Sibling([]Subject{s})
	if err != nil {
		t.Fatal(err)
	}
	if child.facts.source != load || !child.facts.maximal[s].equal(base, false) {
		t.Fatal("sibling lost its generation or an underlying obligation")
	}
	projection := child.facts.closure(s)
	projection.Hash, projection.Unverifiable, projection.Reason = "foreign", false, ""
	if !child.facts.maximal[s].equal(base, false) || !parent.facts.maximal[s].equal(base, false) {
		t.Fatal("local projection changed shared facts")
	}
	// Taking a cut may select the unavailable shared-state analysis, but
	// never replaces the first observation's selected-source inputs.
	other := observationFacts{maximal: map[Subject]subjectFacts{s: base}}
	b := other.maximal[s]
	b.sharedState = &subjectRefusal{reason: "cut"}
	b.openWorld = nil // deliberately different; takeCut has no authority over it
	other.maximal[s] = b
	child.facts.takeCut(other, s)
	if child.facts.source != load || child.facts.maximal[s].openWorld != base.openWorld || child.facts.maximal[s].sharedState.reason != "cut" {
		t.Fatal("cut replaced non-discharge inputs")
	}
	if !parent.facts.maximal[s].equal(base, false) {
		t.Fatal("sibling cut mutated parent facts")
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := parent.compareObservationContext(cancelled, *parent.facts); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled comparison: %v", err)
	}
}

// A carrier escape discharges only by proof, never by init flow - an
// alias outlives initialization in a proven function exactly as in an
// init body. The two proofs: a leak-free callee parameter (deferred to
// composition, cross-package included), and a leak-free range binding
// over the loop body (REQ-closure-shared-dynamic-state).
// Each child owns its module tree, Engine and View and reads an unchanged
// process environment. Keep this parent nonparallel: its grouped children
// must finish before any root test can change environment or observation hooks.
func TestCarrierEscapeDischarges(t *testing.T) {
	goMod := "module example.com/xesc\n\ngo 1.26\n"
	t.Run("escape through a proven function stays escaped", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nvar stash map[string]func()\n\nfunc Keep(m map[string]func()) { stash = m }\n\nfunc Seed() { Keep(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade - a retaining callee reached through a proven init-only chain aliased the registry into runtime-writable state", verdict)
		}
	})
	t.Run("return escape through a proven function stays escaped", func(t *testing.T) {
		t.Parallel()
		// The carrier is returned, not argument-passed: no parameter
		// proof applies, and the alias lands in the caller's package
		// state - init flow must not launder it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc Grab() map[string]func() { return Hooks }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar G = reg.Grab()\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		// The subject sits in the declaring package: the caller package's
		// own binding additionally fails the environment audit (a call
		// result is an opaque source), and its culprit would front-run
		// the escape this leg pins.
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade - a returned alias discharged with its proven function", verdict)
		}
	})
	t.Run("leak-free consumer discharges the argument escape", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc check(m map[string]func()) {\n\tfor k := range m {\n\t\t_ = k\n\t}\n}\n\nfunc Seed() { check(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a provably leak-free consumer refused the discharge", verdict)
		}
	})
	t.Run("func-typed hook argument stays valid", func(t *testing.T) {
		t.Parallel()
		// A non-alias-handing carrier cannot be rebound through an
		// argument - it must not enter the parameter deferral, whose
		// facts deliberately omit no-reach parameters and would refuse
		// the ubiquitous callback-passing shape.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hook = func() {}\n\nfunc use(f func()) {}\n\nfunc F() { use(Hook) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc G() { reg.F() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "G"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a func-typed hook argument entered the unresolvable deferral", verdict)
		}
	})
	t.Run("bare range over a carrier discharges", func(t *testing.T) {
		t.Parallel()
		// A binding-free range aliases nothing.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Count() int {\n\tn := 0\n\tfor range Registry {\n\t\tn++\n\t}\n\treturn n\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a binding-free range refused", verdict)
		}
	})
	t.Run("declared local alias read discharges", func(t *testing.T) {
		t.Parallel()
		// var-declared bindings track exactly like := bindings.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc peek(m map[string]func()) int {\n\tvar x = m\n\treturn len(x)\n}\n\nfunc Seed() { _ = peek(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a var-declared tracked binding refused the proof", verdict)
		}
	})
	t.Run("declared local alias write refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc poke(m map[string]func()) {\n\tvar x = m\n\tx[\"k\"] = func() {}\n}\n\nfunc Seed() { poke(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want the downgrade - a write through a var-declared binding passed the proof", verdict)
		}
	})
	t.Run("deferred call argument earns the discharge", func(t *testing.T) {
		t.Parallel()
		// A deferred call is synchronous at function exit - the
		// parameter proof bounds the alias exactly as a plain call's.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc check(m map[string]func()) {\n\tfor k := range m {\n\t\t_ = k\n\t}\n}\n\nfunc Seed() { defer check(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a deferred call's argument lost the parameter deferral", verdict)
		}
	})
	t.Run("aliased local read discharges", func(t *testing.T) {
		t.Parallel()
		// The consumer binds the parameter to a local and reads through
		// it - the tracked binding keeps every arm, so the proof holds.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc peek(m map[string]func()) int {\n\tx := m\n\treturn len(x)\n}\n\nfunc Seed() { _ = peek(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a tracked local binding refused the proof it stays inside", verdict)
		}
	})
	t.Run("literal reading an init-local alias discharges", func(t *testing.T) {
		t.Parallel()
		// The nested literal only length-reads the aliased local - the
		// read shapes apply to the alias exactly as to the carrier.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nvar Size func() int\n\nfunc init() {\n\tm := Hooks\n\tSize = func() int { return len(m) }\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a length-read through the init-local alias refused", verdict)
		}
	})
	t.Run("go statement argument keeps the escape", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc check(m map[string]func()) {\n\tfor k := range m {\n\t\t_ = k\n\t}\n}\n\nfunc Seed() { go check(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want the downgrade - a goroutine's argument earned the synchronous deferral", verdict)
		}
	})
	t.Run("unrecognized consumer use refuses", func(t *testing.T) {
		t.Parallel()
		// The parameter appears only inside a composite literal - a shape
		// no enumerated arm classifies; the engine's catch-all ident
		// visit must refuse it, fail-closed.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc hold(m map[string]func()) {\n\tpair := []any{m}\n\t_ = pair\n}\n\nfunc Seed() { hold(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade - an unclassified parameter use passed the leak-free proof", verdict)
		}
	})
	t.Run("cross-package retaining callee refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nvar held map[string]func()\n\nfunc Register(m map[string]func()) { held = m }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Hooks = map[string]func(){}\n\nfunc Seed() { val.Register(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade - a foreign retaining parameter discharged", verdict)
		}
	})
	t.Run("cross-package leak-free callee discharges", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nfunc Check(m map[string]func()) int { return len(m) }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Hooks = map[string]func(){}\n\nfunc Seed() { val.Check(Hooks) }\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nvar _ = boot()\n\nfunc boot() bool {\n\treg.Seed()\n\treturn true\n}\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a foreign leak-free parameter refused the discharge", verdict)
		}
	})
	t.Run("leak-free range binding discharges the iteration", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Labels() []string {\n\tout := []string{}\n\tfor _, e := range Registry {\n\t\tout = append(out, e.Label)\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return len(reg.Labels()) }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a leak-free alias-handing range binding refused the discharge", verdict)
		}
	})
	t.Run("range binding retained beyond the loop refuses", func(t *testing.T) {
		t.Parallel()
		// The binding is copied into a local declared OUTSIDE the loop
		// body - the alias survives where the loop-body arms cannot see
		// its uses, so the proof must refuse.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Last() []string {\n\tvar save entry\n\tfor _, e := range Registry {\n\t\tsave = e\n\t}\n\treturn save.Cols\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return len(reg.Last()) }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - an outside-body retention passed the loop proof", verdict)
		}
	})
	t.Run("leaking range binding keeps the escape", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Columns() []string {\n\tout := []string{}\n\tfor _, e := range Registry {\n\t\tout = append(out, e.Cols...)\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return len(reg.Columns()) }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - an alias-handing field flowed out of the loop unrefused", verdict)
		}
	})
	t.Run("func-field call through the binding discharges", func(t *testing.T) {
		t.Parallel()
		// The registry-of-builders shape: the loop invokes a func-typed
		// field of the binding - the callee receives only its arguments,
		// so the binding proof holds and the pure builder composes.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc double(n int) int { return n * 2 }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: double}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(1)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a func-field call through the binding refused the discharge", verdict)
		}
	})
	t.Run("func-field argument discharges through the registered population", func(t *testing.T) {
		t.Parallel()
		// An argument handing the callee an alias into carrier state
		// defers to the field position's registered population: the only
		// registrant is a named function whose parameter proves
		// leak-free, so the binding proof composes.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar Registry []entry\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: width}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a leak-free registered population refused the field-position discharge", verdict)
		}
	})
	t.Run("func-field argument refuses when a registrant retains the alias", func(t *testing.T) {
		t.Parallel()
		// The same shape with a registrant that stores its parameter
		// into package state: the population cannot prove the position
		// leak-free, so the escape stays.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar Registry []entry\n\nvar sink []string\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: grab}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - an alias-retaining registrant passed the population proof", verdict)
		}
	})
	t.Run("func-field argument discharges through a judged literal registrant", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: func(cols []string) int { return len(cols) }}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a leak-free literal registrant refused the field-position discharge", verdict)
		}
	})
	t.Run("func-field argument refuses on a leaking literal registrant", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar Registry []entry\n\nvar sink []string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: func(cols []string) int {\n\t\tsink = cols\n\t\treturn len(cols)\n\t}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a leaking literal registrant passed the population proof", verdict)
		}
	})
	t.Run("func-field argument discharges through a constructor registrant", func(t *testing.T) {
		t.Parallel()
		// The registry is built by a proven return-environment-free
		// constructor: its field marks join the population through the
		// carrier's constructor-registration pair.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc build() []entry {\n\treturn []entry{{Cols: []string{\"a\"}, Build: width}}\n}\n\nvar Registry = build()\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a constructor-supplied leak-free population refused the discharge", verdict)
		}
	})
	t.Run("func-field argument refuses on a constructor's leaking registrant", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar sink []string\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nfunc build() []entry {\n\treturn []entry{{Cols: []string{\"a\"}, Build: grab}}\n}\n\nvar Registry = build()\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a constructor's alias-retaining registrant passed the population proof", verdict)
		}
	})
	t.Run("func-field argument refuses on a method-expression registrant", func(t *testing.T) {
		t.Parallel()
		// A method expression carries a receiver frame no leak-free fact
		// covers - the classification poisons the field position.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ cols []string }\n\nfunc (c *counter) grab(cols []string) int {\n\tc.cols = cols\n\treturn len(cols)\n}\n\ntype entry struct {\n\tCols  []string\n\tBuild func(c *counter, cols []string) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: (*counter).grab}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tc := &counter{}\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(c, e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a method-expression registrant passed the population proof", verdict)
		}
	})
	t.Run("constructor-argument registrants join the population", func(t *testing.T) {
		t.Parallel()
		// A passthrough constructor's parameters carry the store site's
		// values into the carrier - the arguments are classified at the
		// store site, so the leaking registrant inside one refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar sink []string\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nfunc pass(es []entry) []entry { return es }\n\nvar Registry = pass([]entry{{Cols: []string{\"a\"}, Build: grab}})\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a constructor argument's registrant escaped the population", verdict)
		}
	})
	t.Run("constructor-argument leak-free registrants discharge", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc pass(es []entry) []entry { return es }\n\nvar Registry = pass([]entry{{Cols: []string{\"a\"}, Build: width}})\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a passthrough constructor's leak-free argument registrant refused the discharge", verdict)
		}
	})
	t.Run("rebound binding detaches from the population and refuses", func(t *testing.T) {
		t.Parallel()
		// Rebinding the tracked local from a value the population never
		// registered would resolve its field calls against the wrong
		// registrants - the proof refuses the rebinding.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inner struct {\n\tFn  func(cols []string) int\n\tPad []string\n}\n\ntype entry struct {\n\tCols []string\n\tSub  inner\n}\n\nvar Registry []entry\n\nvar sink []string\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Sub: inner{Fn: width}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ts := e.Sub\n\t\ts = inner{Fn: grab}\n\t\ttotal += s.Fn(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a rebound binding resolved against the carrier's population", verdict)
		}
	})
	t.Run("foreign-valued declaration of a tracked binding refuses", func(t *testing.T) {
		t.Parallel()
		// The declaration twin of the rebinding refusal: the name is
		// tracked by a later carrier assignment, but its initial value
		// is one the population never registered - the declaration
		// ident stays unconsumed and the tracked-ident catch-all
		// refuses, no dedicated arm needed.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inner struct {\n\tFn  func(cols []string) int\n\tPad []string\n}\n\ntype entry struct {\n\tCols []string\n\tSub  inner\n}\n\nvar Registry []entry\n\nvar sink []string\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Sub: inner{Fn: width}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\tvar s inner = inner{Fn: grab}\n\t\ts = e.Sub\n\t\ttotal += s.Fn(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a foreign-valued declaration resolved against the carrier's population", verdict)
		}
	})
	t.Run("delegating constructor joins its dependency's population", func(t *testing.T) {
		t.Parallel()
		// The proven constructor returns another constructor's result -
		// the dependency's field marks decide, joined over the proof's
		// dependency edges.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar sink []string\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nfunc part() []entry {\n\treturn []entry{{Cols: []string{\"a\"}, Build: grab}}\n}\n\nfunc build() []entry { return part() }\n\nvar Registry = build()\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a delegated constructor's registrant escaped the transitive join", verdict)
		}
	})
	t.Run("delegating constructor's leak-free dependency discharges", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc part() []entry {\n\treturn []entry{{Cols: []string{\"a\"}, Build: width}}\n}\n\nfunc build() []entry { return part() }\n\nvar Registry = build()\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a delegating constructor's leak-free dependency refused the transitive discharge", verdict)
		}
	})
	t.Run("literal registrant's own deferral resolves at composition", func(t *testing.T) {
		t.Parallel()
		// The judged literal hands its parameter to a named function -
		// the deferral rides the population marks and resolves against
		// the leak-free union.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: func(cols []string) int { return width(cols) }}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a literal registrant's carried deferral refused the discharge", verdict)
		}
	})
	t.Run("literal registrant's unproven deferral refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar sink []string\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: func(cols []string) int { return grab(cols) }}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a literal's unproven deferral passed the population proof", verdict)
		}
	})
	t.Run("func-field argument through an unrelated value keeps the escape", func(t *testing.T) {
		t.Parallel()
		// The invoked field belongs to a local that is not the judged
		// binding - its callee is outside the carrier's registered
		// population, so the want must not be recorded against it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar Registry []entry\n\nvar sink []string\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: width}}\n}\n\nfunc Total() int {\n\thelper := entry{Build: grab}\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += helper.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - an unrelated value's field call earned the carrier's deferral", verdict)
		}
	})
	t.Run("constructor reading a func-carrying package variable poisons its population", func(t *testing.T) {
		t.Parallel()
		// The proof's derivation channel could hand the read variable's
		// unclassified interior into the result - whole-population
		// poison, whatever the constructor's literals prove.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar hidden []entry\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc build() []entry {\n\t_ = len(hidden)\n\treturn []entry{{Cols: []string{\"a\"}, Build: width}}\n}\n\nvar Registry = build()\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a constructor's package-variable read left its population unpoisoned", verdict)
		}
	})
	t.Run("nested registrant pools into the population by field name", func(t *testing.T) {
		t.Parallel()
		// A nested struct's func field can become a judged binding
		// through the taint chain - its registrants share the field-name
		// namespace, so the nested leaking registrant must refuse.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inner struct {\n\tFn  func(cols []string) int\n\tPad []string\n}\n\ntype entry struct {\n\tCols []string\n\tSub  inner\n}\n\nvar Registry []entry\n\nvar sink []string\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Sub: inner{Fn: grab}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ts := e.Sub\n\t\ttotal += s.Fn(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a nested leaking registrant escaped the pooled population", verdict)
		}
	})
	t.Run("non-signature rebind of a carrier-derived local stays discharged", func(t *testing.T) {
		t.Parallel()
		// A rebound []string local can never be a func-field base - the
		// rebinding refusal is scoped to signature-carrying bindings,
		// so the default-fallback pattern keeps its discharge.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar fallback = []string{\"z\"}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\tc := e.Cols\n\t\tif len(c) == 0 {\n\t\t\tc = fallback\n\t\t}\n\t\ttotal += len(c)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a non-signature fallback rebind lost its discharge", verdict)
		}
	})
	t.Run("make-constructed registry discharges", func(t *testing.T) {
		t.Parallel()
		// make's type argument is not a value - the population stays
		// exactly the appended registrants'.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nvar Registry = make([]entry, 0)\n\nfunc init() {\n\tRegistry = append(Registry, entry{Cols: []string{\"a\"}, Build: width})\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - make's type argument poisoned the population", verdict)
		}
	})
	t.Run("named func-typed field earns the discharge", func(t *testing.T) {
		t.Parallel()
		// The http.HandlerFunc idiom: the field's type is a named func
		// type, unwrapped to its signature on both sides.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Builder func(cols []string) int\n\ntype entry struct {\n\tCols  []string\n\tBuild Builder\n}\n\nvar Registry []entry\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: width}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a named func-typed field refused the discharge", verdict)
		}
	})
	t.Run("nested leak-free registrant discharges through the pooled population", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inner struct {\n\tFn  func(cols []string) int\n\tPad []string\n}\n\ntype entry struct {\n\tCols []string\n\tSub  inner\n}\n\nvar Registry []entry\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Sub: inner{Fn: width}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ts := e.Sub\n\t\ttotal += s.Fn(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a nested leak-free registrant refused the pooled discharge", verdict)
		}
	})
	t.Run("go-statement func-field argument keeps the escape", func(t *testing.T) {
		t.Parallel()
		// The goroutine runs concurrently with the loop - the field call's
		// argument never defers, whatever the population proves.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar Registry []entry\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: width}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\tgo e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a concurrent field call's argument earned the deferral", verdict)
		}
	})
	t.Run("func-field argument refuses on a direct field-write registrant", func(t *testing.T) {
		t.Parallel()
		// Re-registration through the carrier's own storage joins the
		// population exactly as the initial store did.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar Registry []entry\n\nvar sink []string\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: width}}\n\tRegistry[0].Build = grab\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a field-write registrant escaped the population", verdict)
		}
	})
	t.Run("comma-ok existence read discharges on any carrier", func(t *testing.T) {
		t.Parallel()
		// The blank target produces no value to hand out - writeless
		// whatever the element type.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Table = map[string]entry{\"a\": {Cols: []string{\"x\"}}}\n\nfunc Has(token string) bool {\n\t_, ok := Table[token]\n\treturn ok\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool { return reg.Has(\"a\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a blank existence read refused", verdict)
		}
	})
	t.Run("comma-ok binding that writes through refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Table = map[string]entry{\"a\": {Cols: []string{\"x\"}}}\n\nfunc Poke(token string) bool {\n\tv, ok := Table[token]\n\tif ok {\n\t\tv.Cols[0] = \"z\"\n\t}\n\treturn ok\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool { return reg.Poke(\"a\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Table") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Table - a written-through comma-ok binding passed", verdict)
		}
	})
	t.Run("dispatch-table carrier argument discharges through the element population", func(t *testing.T) {
		t.Parallel()
		// legs[token](shared): the callee is unknowable statically, so
		// the argument defers to the dispatch carrier's element
		// population - every registered value must prove the position.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nvar Legs = map[string]func(v *inv) int{\"w\": width}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a leak-free element population refused the dispatch argument", verdict)
		}
	})
	t.Run("dispatch-table argument refuses when an element retains it", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nvar Legs = map[string]func(v *inv) int{\"w\": grab}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a retaining element passed the population proof", verdict)
		}
	})
	t.Run("dispatch-table literal element judges at registration", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar Legs = map[string]func(v *inv) int{\"w\": func(v *inv) int { return len(v.Cols) }}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a leak-free literal element refused the dispatch argument", verdict)
		}
	})
	t.Run("dispatch-table leaking literal element refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nvar Legs = map[string]func(v *inv) int{\"w\": func(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a leaking literal element passed", verdict)
		}
	})
	t.Run("dispatch element from a constructor-returned bare function refuses", func(t *testing.T) {
		t.Parallel()
		// The registrant reaches the element through a proven
		// constructor's returned bare function - its disposition rides
		// the return-environment-free channel.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc pick() func(v *inv) int { return grab }\n\nvar Legs = map[string]func(v *inv) int{\"w\": pick()}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a constructor-returned retaining element passed", verdict)
		}
	})
	t.Run("dispatch element from a constructor-returned leak-free function discharges", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nfunc pick() func(v *inv) int { return width }\n\nvar Legs = map[string]func(v *inv) int{\"w\": pick()}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a constructor-returned leak-free element refused the dispatch argument", verdict)
		}
	})
	t.Run("dispatch element through a constructor local passthrough refuses", func(t *testing.T) {
		t.Parallel()
		// The proof admits the local; the value-position sweep pools
		// its source - the retaining registrant must surface.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc pick() func(v *inv) int {\n\tf := grab\n\treturn f\n}\n\nvar Legs = map[string]func(v *inv) int{\"w\": pick()}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a local-passthrough registrant escaped the population", verdict)
		}
	})
	t.Run("dispatch element written into a constructor local refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc pick() map[string]func(v *inv) int {\n\tr := map[string]func(v *inv) int{}\n\tr[\"w\"] = grab\n\treturn r\n}\n\nvar Legs = pick()\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - an index-written registrant escaped the population", verdict)
		}
	})
	t.Run("dispatch element behind a conversion refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\ntype Leg func(v *inv) int\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc pick() Leg { return Leg(grab) }\n\nvar Legs = map[string]Leg{\"w\": pick()}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a converted registrant escaped the population", verdict)
		}
	})
	t.Run("dispatch element appended in a constructor refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc pick() []func(v *inv) int {\n\treturn append([]func(v *inv) int{}, grab)\n}\n\nvar Legs = pick()\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[0](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - an appended registrant escaped the population", verdict)
		}
	})
	t.Run("dispatch element written into a constructor local discharges when leak-free", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar kept []string\n\nfunc keep(s []string) { kept = s }\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nfunc pick() map[string]func(v *inv) int {\n\tkeep(nil)\n\tr := map[string]func(v *inv) int{}\n\tr[\"w\"] = width\n\treturn r\n}\n\nvar Legs = pick()\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a leak-free index-written registrant refused the discharge", verdict)
		}
	})
	t.Run("callee-mutated constructor local refuses the dispatch discharge", func(t *testing.T) {
		t.Parallel()
		// A callee handed the local can insert a registrant after the
		// recorded population - the local breaks at the call, keeping
		// the proof and the discharge fail-closed.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nfunc hookf(m map[string]func(v *inv) int) {\n\tm[\"w\"] = grab\n}\n\nfunc pick() map[string]func(v *inv) int {\n\tr := map[string]func(v *inv) int{}\n\tr[\"w\"] = width\n\thookf(r)\n\treturn r\n}\n\nvar Legs = pick()\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a callee-inserted registrant escaped the population", verdict)
		}
	})
	t.Run("signature-var callee handed the constructor local refuses", func(t *testing.T) {
		t.Parallel()
		// The callee is a func-valued package variable - unattributable,
		// so the handed local breaks and the proof refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nvar hook = func(m map[string]func(v *inv) int) int {\n\tm[\"w\"] = grab\n\treturn 0\n}\n\nfunc pick() map[string]func(v *inv) int {\n\tr := map[string]func(v *inv) int{}\n\tr[\"w\"] = width\n\t_ = hook(r)\n\treturn r\n}\n\nvar Legs = pick()\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a signature-var callee's insertion escaped the population", verdict)
		}
	})
	t.Run("closure-mutated constructor local refuses the dispatch discharge", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\ntype config struct {\n\tFn func(v *inv) int\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nfunc pick(cfg config) map[string]func(v *inv) int {\n\tr := map[string]func(v *inv) int{}\n\tr[\"w\"] = width\n\tswap := func() { r[\"w\"] = cfg.Fn }\n\tswap()\n\treturn r\n}\n\nvar Legs = pick(config{Fn: grab})\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a closure-inserted registrant escaped the population", verdict)
		}
	})
	t.Run("param-field insertion into the constructor local refuses", func(t *testing.T) {
		t.Parallel()
		// cfg.Fn is priced under its field name at the store site - an
		// element-position insertion is a different position, so the
		// sweep's fail-closed default poisons it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\ntype config struct {\n\tFn func(v *inv) int\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nfunc pick(cfg config) map[string]func(v *inv) int {\n\tr := map[string]func(v *inv) int{}\n\tr[\"w\"] = cfg.Fn\n\treturn r\n}\n\nvar Legs = pick(config{Fn: grab})\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a param-field insertion escaped the population", verdict)
		}
	})
	t.Run("void-callee param-field insertion refuses through the edge", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\ntype config struct {\n\tFn func(v *inv) int\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nfunc hookf(m map[string]func(v *inv) int, cfg config) {\n\tm[\"w\"] = cfg.Fn\n}\n\nfunc pick(cfg config) map[string]func(v *inv) int {\n\tr := map[string]func(v *inv) int{}\n\tr[\"w\"] = width\n\thookf(r, cfg)\n\treturn r\n}\n\nvar Legs = pick(config{Fn: grab})\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a void callee's param-field insertion escaped", verdict)
		}
	})
	t.Run("value-receiver method insertion refuses", func(t *testing.T) {
		t.Parallel()
		// A value receiver over a map-underlying type writes through -
		// the receiver breaks exactly like a handed argument.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\ntype legmap map[string]func(v *inv) int\n\nfunc (m legmap) swap() int {\n\tm[\"w\"] = grab\n\treturn 0\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nfunc pick() map[string]func(v *inv) int {\n\tr := legmap{}\n\tr[\"w\"] = width\n\t_ = r.swap()\n\treturn r\n}\n\nvar Legs = pick()\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a value-receiver insertion escaped", verdict)
		}
	})
	t.Run("void-callee call-result insertion refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nfunc mk() func(v *inv) int { return grab }\n\nfunc hookf(m map[string]func(v *inv) int) {\n\tm[\"w\"] = mk()\n}\n\nfunc pick() map[string]func(v *inv) int {\n\tr := map[string]func(v *inv) int{}\n\tr[\"w\"] = width\n\thookf(r)\n\treturn r\n}\n\nvar Legs = pick()\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a void callee's call-result insertion escaped", verdict)
		}
	})
	t.Run("struct-receiver interior insertion refuses", func(t *testing.T) {
		t.Parallel()
		// The receiver copies by value but its interior map shares
		// backing - the break covers any receiver whose interior hands
		// out mutable reach.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\ntype holder struct {\n\tf map[string]func(v *inv) int\n}\n\nfunc (h holder) swap() int {\n\th.f[\"w\"] = grab\n\treturn 0\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nfunc pick() map[string]func(v *inv) int {\n\tr := map[string]func(v *inv) int{}\n\tr[\"w\"] = width\n\tvar h holder\n\th.f = r\n\t_ = h.swap()\n\treturn r\n}\n\nvar Legs = pick()\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a struct-receiver interior insertion escaped", verdict)
		}
	})
	t.Run("void-callee signature-var call-result insertion refuses", func(t *testing.T) {
		t.Parallel()
		// The producing callee is a func-valued variable - its result
		// is unattributable, so the sweep's fail-closed default poisons
		// the element position.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc grab(v *inv) int {\n\tsink = v.Cols\n\treturn len(v.Cols)\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nvar maker = func() func(v *inv) int { return grab }\n\nfunc hookf(m map[string]func(v *inv) int) {\n\tm[\"w\"] = maker()\n}\n\nfunc pick() map[string]func(v *inv) int {\n\tr := map[string]func(v *inv) int{}\n\tr[\"w\"] = width\n\thookf(r)\n\treturn r\n}\n\nvar Legs = pick()\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a signature-var call result escaped the population", verdict)
		}
	})
	t.Run("callee-inserted leak-free element discharges", func(t *testing.T) {
		t.Parallel()
		// The edge's precision pin: the callee's swept marks join the
		// population, and a leak-free insertion discharges.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nvar sink []string\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nfunc hookf(m map[string]func(v *inv) int) {\n\tm[\"x\"] = width\n}\n\nfunc pick() map[string]func(v *inv) int {\n\tr := map[string]func(v *inv) int{}\n\tr[\"w\"] = width\n\thookf(r)\n\treturn r\n}\n\nvar Legs = pick()\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\treturn Legs[token](Shared)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a leak-free callee insertion refused the edge-joined discharge", verdict)
		}
	})
	t.Run("init-body dispatch argument keeps the escape", func(t *testing.T) {
		t.Parallel()
		// Init flow is program code for deferrals - the alias outlives
		// initialization, so the dispatch admission never applies there.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nvar Legs = map[string]func(v *inv) int{\"w\": width}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nvar total int\n\nfunc init() {\n\ttotal = Legs[\"w\"](Shared)\n}\n\nfunc Total() int { return total }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - an init-body dispatch argument earned the deferral", verdict)
		}
	})
	t.Run("go-statement dispatch argument keeps the escape", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inv struct {\n\tCols []string\n\tHook func()\n}\n\nfunc width(v *inv) int { return len(v.Cols) }\n\nvar Legs = map[string]func(v *inv) int{\"w\": width}\n\nvar Shared = &inv{Cols: []string{\"a\"}}\n\nfunc Total(token string) int {\n\tgo Legs[token](Shared)\n\treturn 0\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Shared") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Shared - a concurrent dispatch argument earned the deferral", verdict)
		}
	})
	t.Run("range-binding dispatch argument defers through the element population", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc width(cols []string) int { return len(cols) }\n\nvar Legs = map[string]func(cols []string) int{\"w\": width}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total(token string) int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += Legs[token](e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a range-binding dispatch argument refused the element discharge", verdict)
		}
	})
	t.Run("range-binding dispatch argument refuses on a retaining element", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar sink []string\n\nfunc grab(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n\nvar Legs = map[string]func(cols []string) int{\"w\": grab}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total(token string) int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += Legs[token](e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total(\"w\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a retaining element passed the range-binding dispatch", verdict)
		}
	})
	t.Run("cross-package parameter forwarding resolves the chain", func(t *testing.T) {
		t.Parallel()
		// The helper forwards its parameter to a foreign leak-free
		// parameter - the conditional edge resolves at composition.
		files := map[string]string{
			"go.mod":       goMod,
			"prop/prop.go": "package prop\n\nfunc Sum(cols []string) int { return len(cols) }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/prop\"\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc helper(cols []string) int { return prop.Sum(cols) }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += helper(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a cross-package forwarding chain refused the discharge", verdict)
		}
	})
	t.Run("cross-package forwarding to a retaining parameter refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"prop/prop.go": "package prop\n\nvar sink []string\n\nfunc Sum(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/prop\"\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc helper(cols []string) int { return prop.Sum(cols) }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += helper(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a retaining foreign parameter resolved", verdict)
		}
	})
	t.Run("three-hop forwarding chain resolves transitively", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"prop/prop.go": "package prop\n\nfunc Sum(cols []string) int { return len(cols) }\n",
			"mid/mid.go":   "package mid\n\nimport \"example.com/xesc/prop\"\n\nfunc Pass(cols []string) int { return prop.Sum(cols) }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/mid\"\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc helper(cols []string) int { return mid.Pass(cols) }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += helper(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a three-hop forwarding chain refused the discharge", verdict)
		}
	})
	t.Run("forwarding through a local intermediary resolves the foreign hop", func(t *testing.T) {
		t.Parallel()
		// The chain's first hop is same-package; the foreign hop sits
		// behind it - the promoted edges resolve the whole chain.
		files := map[string]string{
			"go.mod":       goMod,
			"prop/prop.go": "package prop\n\nfunc Sum(cols []string) int { return len(cols) }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/prop\"\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc local2(cols []string) int { return prop.Sum(cols) }\n\nfunc helper(cols []string) int { return local2(cols) }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += helper(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a local intermediary blocked the foreign resolution", verdict)
		}
	})
	t.Run("mutual recursion with a foreign hop refuses as a cycle", func(t *testing.T) {
		t.Parallel()
		// Both members route to the edge channel; their mutual edges
		// cycle and the composition fixed point refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"prop/prop.go": "package prop\n\nfunc Sum(cols []string) int { return len(cols) }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/prop\"\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc helper(cols []string) int {\n\tif len(cols) == 0 {\n\t\treturn prop.Sum(cols)\n\t}\n\treturn other(cols)\n}\n\nfunc other(cols []string) int {\n\tif len(cols) == 1 {\n\t\treturn prop.Sum(cols)\n\t}\n\treturn helper(cols)\n}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += helper(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a mutual edge cycle resolved", verdict)
		}
	})
	t.Run("field registrant defers to a conditionally proven parameter", func(t *testing.T) {
		t.Parallel()
		// The registrant's own parameter proof rides the edge channel -
		// the 'd' mark resolves against the composed fixed point.
		files := map[string]string{
			"go.mod":       goMod,
			"prop/prop.go": "package prop\n\nfunc Sum(cols []string) int { return len(cols) }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/prop\"\n\ntype entry struct {\n\tCols  []string\n\tBuild func(cols []string) int\n}\n\nvar Registry []entry\n\nfunc relay(cols []string) int { return prop.Sum(cols) }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: relay}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a conditionally proven registrant parameter refused the field discharge", verdict)
		}
	})
	t.Run("registered literal handing out a captured field closure refuses", func(t *testing.T) {
		t.Parallel()
		// The wrapper literal returns w.handler - a signature-carrying
		// read of its capture. The value IS its environment (the shared
		// closure over n); the value-plane refusal keeps the escape.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype widget struct {\n\thandler func() int\n}\n\nvar Registry = map[string]func() func() int{}\n\nfunc init() {\n\tn := 0\n\tw := widget{handler: func() int {\n\t\tn++\n\t\treturn n\n\t}}\n\tRegistry[\"h\"] = func() func() int { return w.handler }\n}\n\nfunc Run() int {\n\tf := Registry[\"h\"]()\n\treturn f() + f()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a captured field closure handed out env-free", verdict)
		}
	})
	t.Run("constructor handing out a captured field closure refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype widget struct {\n\thandler func() int\n}\n\nfunc mk() map[string]func() func() int {\n\tn := 0\n\tw := widget{handler: func() int {\n\t\tn++\n\t\treturn n\n\t}}\n\treturn map[string]func() func() int{\"h\": func() func() int { return w.handler }}\n}\n\nvar Registry = mk()\n\nfunc Run() int {\n\tf := Registry[\"h\"]()\n\treturn f() + f()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a constructor handed out a captured closure env-free", verdict)
		}
	})
	t.Run("registered literal handing out a captured method value refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Tick() int {\n\tc.n++\n\treturn c.n\n}\n\ntype widget struct {\n\thandler func() int\n}\n\nvar Registry = map[string]func() func() int{}\n\nfunc init() {\n\tc := &counter{}\n\tw := widget{handler: c.Tick}\n\tRegistry[\"h\"] = func() func() int { return w.handler }\n}\n\nfunc Run() int {\n\tf := Registry[\"h\"]()\n\treturn f() + f()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a captured method value handed out env-free", verdict)
		}
	})
	t.Run("rooted map-field dispatch with scalar arguments discharges", func(t *testing.T) {
		t.Parallel()
		// The callee read is an invocation, not a handout - the
		// value-plane refusal skips call positions.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols     []string\n\tHandlers map[string]func(n int) int\n}\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Handlers: map[string]func(n int) int{\"x\": double}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Handlers[\"x\"](1)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a rooted map-field invocation refused on the value plane", verdict)
		}
	})
	t.Run("locally bound handout refuses on the value plane", func(t *testing.T) {
		t.Parallel()
		// The bind tracks - the signature-carrying value carries its
		// environment through the local exactly as through the read.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype widget struct {\n\thandler func() int\n}\n\nvar Registry = map[string]func() func() int{}\n\nfunc init() {\n\tn := 0\n\tw := widget{handler: func() int {\n\t\tn++\n\t\treturn n\n\t}}\n\tRegistry[\"h\"] = func() func() int {\n\t\tx := w.handler\n\t\treturn x\n\t}\n}\n\nfunc Run() int {\n\tf := Registry[\"h\"]()\n\treturn f() + f()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a locally bound handout escaped the value plane", verdict)
		}
	})
	t.Run("range-bound handout refuses on the value plane", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype widget struct {\n\tlist []func() int\n}\n\nvar Registry = map[string]func() func() int{}\n\nfunc init() {\n\tn := 0\n\tw := widget{list: []func() int{func() int {\n\t\tn++\n\t\treturn n\n\t}}}\n\tRegistry[\"h\"] = func() func() int {\n\t\tfor _, f := range w.list {\n\t\t\treturn f\n\t\t}\n\t\treturn nil\n\t}\n}\n\nfunc Run() int {\n\tf := Registry[\"h\"]()\n\treturn f() + f()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a range-bound handout escaped the value plane", verdict)
		}
	})
	t.Run("struct-copy bound handout refuses on the value plane", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype widget struct {\n\thandler func() int\n}\n\nvar Registry = map[string]func() func() int{}\n\nfunc init() {\n\tn := 0\n\tw := widget{handler: func() int {\n\t\tn++\n\t\treturn n\n\t}}\n\tRegistry[\"h\"] = func() func() int {\n\t\tx := w\n\t\treturn x.handler\n\t}\n}\n\nfunc Run() int {\n\tf := Registry[\"h\"]()\n\treturn f() + f()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a struct-copy handout escaped the value plane", verdict)
		}
	})
	t.Run("method-result handout refuses through the constructor door", func(t *testing.T) {
		t.Parallel()
		// The read-only method returns a signature-carrying value - the
		// deferral's result gate refuses on the value plane.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype widget struct {\n\thandler func() int\n}\n\nfunc (w widget) Get() func() int { return w.handler }\n\nfunc mk() map[string]func() func() int {\n\tn := 0\n\tw := widget{handler: func() int {\n\t\tn++\n\t\treturn n\n\t}}\n\treturn map[string]func() func() int{\"h\": func() func() int { return w.Get() }}\n}\n\nvar Registry = mk()\n\nfunc Run() int {\n\tf := Registry[\"h\"]()\n\treturn f() + f()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a method-result handout escaped the deferral gate", verdict)
		}
	})
	t.Run("package-var getter returning a callback refuses", func(t *testing.T) {
		t.Parallel()
		// The method call itself is the tolerated position, but its
		// signature-carrying result denies the read-only deferral: the
		// receiver stays fail-closed.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype R struct {\n\thook func() int\n}\n\nvar V = &R{hook: func() int { return 1 }}\n\nfunc (r *R) Get() func() int { return r.hook }\n\nfunc Run() int {\n\tf := V.Get()\n\treturn f()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.V") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.V - a callback-returning getter must not earn the read-only deferral", verdict)
		}
	})
	t.Run("field-callee call result handout refuses", func(t *testing.T) {
		t.Parallel()
		// return w.get() - the callee read is tolerated, but its
		// signature-carrying result is a value-plane handout.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype widget struct {\n\tget func() func() int\n}\n\nvar Registry = map[string]func() func() int{}\n\nfunc init() {\n\tn := 0\n\thandler := func() int {\n\t\tn++\n\t\treturn n\n\t}\n\tw := widget{get: func() func() int { return handler }}\n\tRegistry[\"h\"] = func() func() int { return w.get() }\n}\n\nfunc Run() int {\n\tf := Registry[\"h\"]()\n\treturn f() + f()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a field-callee result handout escaped", verdict)
		}
	})
	t.Run("bound-callee call result handout refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype widget struct {\n\tget func() func() int\n}\n\nvar Registry = map[string]func() func() int{}\n\nfunc init() {\n\tn := 0\n\thandler := func() int {\n\t\tn++\n\t\treturn n\n\t}\n\tw := widget{get: func() func() int { return handler }}\n\tRegistry[\"h\"] = func() func() int {\n\t\tfn := w.get\n\t\treturn fn()\n\t}\n}\n\nfunc Run() int {\n\tf := Registry[\"h\"]()\n\treturn f() + f()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a bound-callee result handout escaped", verdict)
		}
	})
	t.Run("void method call on a rooted element stays valid", func(t *testing.T) {
		t.Parallel()
		// A void call hands out nothing - the read-only method deferral
		// resolves it; the result gate must not misread the empty result
		// tuple as a handout.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Ping() {}\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: double}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\te.Ping()\n\t\ttotal += e.Build(1)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a void method call hands out nothing", verdict)
		}
	})
	t.Run("two-result dispatch on a rooted element stays valid", func(t *testing.T) {
		t.Parallel()
		// Every element of the result tuple is a copied scalar - the
		// multi-result shape alone is not a handout.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols   []string\n\tLookup func(s string) (int, bool)\n}\n\nfunc look(s string) (int, bool) { return len(s), true }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Lookup: look}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\tif v, ok := e.Lookup(\"ab\"); ok {\n\t\t\ttotal += v\n\t\t}\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an all-scalar result tuple hands out nothing", verdict)
		}
	})
	t.Run("map-returning field callee refuses", func(t *testing.T) {
		t.Parallel()
		// The call is tolerated but its result hands the caller shared
		// mutable reach - a mutation-equivalent escape.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype widget struct {\n\tget func() map[string]int\n}\n\nvar Registry = map[string]func() map[string]int{}\n\nfunc init() {\n\tm := map[string]int{\"a\": 1}\n\tw := widget{get: func() map[string]int { return m }}\n\tRegistry[\"h\"] = func() map[string]int { return w.get() }\n}\n\nfunc Run() int {\n\td := Registry[\"h\"]()\n\treturn d[\"a\"]\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a map-returning callee handed out shared reach", verdict)
		}
	})
	t.Run("two-result handout with a signature element refuses", func(t *testing.T) {
		t.Parallel()
		// One tuple element is a signature - the comma-discarded shape
		// must not launder it past the result gate.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype widget struct {\n\tboth func() (func() int, bool)\n}\n\nvar Registry = map[string]func() int{}\n\nfunc init() {\n\tn := 0\n\thandler := func() int {\n\t\tn++\n\t\treturn n\n\t}\n\tw := widget{both: func() (func() int, bool) { return handler, true }}\n\tRegistry[\"h\"] = func() int {\n\t\tf, _ := w.both()\n\t\treturn f()\n\t}\n}\n\nfunc Run() int {\n\treturn Registry[\"h\"]() + Registry[\"h\"]()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a signature element rode a result tuple out", verdict)
		}
	})
	t.Run("two-result handout with a map element refuses", func(t *testing.T) {
		t.Parallel()
		// The shared-reach element rides the tuple beside a scalar.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype widget struct {\n\tboth func() (map[string]int, bool)\n}\n\nvar Registry = map[string]func() int{}\n\nfunc init() {\n\tm := map[string]int{\"a\": 1}\n\tw := widget{both: func() (map[string]int, bool) { return m, true }}\n\tRegistry[\"h\"] = func() int {\n\t\td, _ := w.both()\n\t\treturn d[\"a\"]\n\t}\n}\n\nfunc Run() int {\n\treturn Registry[\"h\"]()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a map element rode a result tuple out", verdict)
		}
	})
	t.Run("bound field callee invocation stays valid", func(t *testing.T) {
		t.Parallel()
		// The bind-then-call idiom: the tracked local is only ever
		// invoked - a call position, never a handout.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nfunc double(n int) int { return 2 * n }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: double}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\tfn := e.Build\n\t\ttotal += fn(1)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the bind-then-call idiom refused", verdict)
		}
	})
	t.Run("stateless handout through a registered literal stays valid", func(t *testing.T) {
		t.Parallel()
		// The benign twin: the returned literal captures nothing - the
		// value-plane refusal must not reach it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Registry = map[string]func() func() int{}\n\nfunc init() {\n\tRegistry[\"h\"] = func() func() int {\n\t\treturn func() int { return 7 }\n\t}\n}\n\nfunc Run() int {\n\tf := Registry[\"h\"]()\n\treturn f() + f()\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a stateless handout refused on the value plane", verdict)
		}
	})
	t.Run("plain-data builder effects stay per-process", func(t *testing.T) {
		t.Parallel()
		// A registered named builder mutating a plain package variable is
		// per-process-deterministic content the whole-graph hash already
		// covers - the discharge composes Valid exactly as the identical
		// static call chain does.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar count int\n\nfunc bump(n int) int {\n\tcount += n\n\treturn count\n}\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: bump}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(1)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a named builder's plain-data write refused the discharge", verdict)
		}
	})
	t.Run("interface-dispatched method call through the binding refuses", func(t *testing.T) {
		t.Parallel()
		// The statically-typed read-only twin now defers (the method-use
		// marks); interface dispatch stays refused - the callee set is
		// unknowable to the receiver fact.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Sizer interface{ Width() int }\n\ntype fixed struct{ n int }\n\nfunc (f fixed) Width() int { return f.n }\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n\tSizer\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Sizer: fixed{n: 1}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Width()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - an interface-dispatched method call earned the deferral", verdict)
		}
	})
	t.Run("capture-free literal registration discharges", func(t *testing.T) {
		t.Parallel()
		// The literal references a package-level variable: not a capture -
		// its uses attribute at this site like any program code.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar scale = 2\n\nfunc init() {\n\tRegistry = append(Registry, entry{Cols: []string{\"a\"}, Build: func(n int) int { return n * scale }})\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += e.Build(1)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a capture-free literal appended in init refused the audit", verdict)
		}
	})
	t.Run("sibling writer poisons a reader-only carrier", func(t *testing.T) {
		t.Parallel()
		// The reader literal is leak-free over its own body, but a sibling
		// literal registered into a different carrier writes the shared
		// environment - one object however many carriers reach it, so the
		// reader's carrier refuses too.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar ReadHooks []func() string\n\nvar WriteHooks []func()\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tReadHooks = []func() string{func() string { return state[0] }}\n\tWriteHooks = []func(){func() { state[0] = \"b\" }}\n}\n\nfunc Read() string {\n\tout := \"\"\n\tfor _, f := range ReadHooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Read() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.ReadHooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.ReadHooks - a sibling writer left the reader's carrier settled", verdict)
		}
	})
	t.Run("aliased environment poisons through the alias set", func(t *testing.T) {
		t.Parallel()
		// A one-line alias of the captured slice hands the goroutine the
		// same backing under another name - the audit closes the alias
		// set over the enclosing body before judging.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc churn(s []string) {\n\tfor i := range s {\n\t\ts[i] = s[i] + \"!\"\n\t}\n}\n\nfunc init() {\n\tstate := []string{\"a\"}\n\talias := state\n\tgo churn(alias)\n\tHooks = []func() string{func() string { return state[0] }}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - an alias of the captured environment slipped the audit", verdict)
		}
	})
	t.Run("builtin copy registration is a judged store", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []func() int{nil}\n\nfunc init() {\n\tcounter := 0\n\tcopy(Hooks, []func() int{func() int { counter++; return counter }})\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\tif f != nil {\n\t\t\ttotal += f()\n\t\t}\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a builtin copy smuggled a capturing closure past the audit", verdict)
		}
	})
	t.Run("init-body carrier argument earns the deferral", func(t *testing.T) {
		t.Parallel()
		// The call sits directly in an init body - the exempt region -
		// and defers to the foreign parameter's leak-free fact exactly as
		// program code does.
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nfunc Check(m map[string]func()) int { return len(m) }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Hooks = map[string]func(){}\n\nvar sink int\n\nfunc init() {\n\tsink = val.Check(Hooks)\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an init-body argument to a leak-free foreign parameter refused the deferral", verdict)
		}
	})
	t.Run("init-body carrier argument to a retaining callee escapes", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nvar held map[string]func()\n\nfunc Keep(m map[string]func()) { held = m }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Hooks = map[string]func(){}\n\nfunc init() {\n\tval.Keep(Hooks)\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Hooks - an init-body handout to a retaining callee stayed exempt", verdict)
		}
	})
	t.Run("init-body carrier argument to a method escapes", func(t *testing.T) {
		t.Parallel()
		// No leak-free fact exists for a method callee - the exempt
		// region's handout keeps the fail-closed escape.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype sink struct{ m map[string]func() }\n\nfunc (s *sink) Keep(m map[string]func()) { s.m = m }\n\nvar keeper sink\n\nvar Hooks = map[string]func(){}\n\nfunc init() {\n\tkeeper.Keep(Hooks)\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Hooks - an init-body handout to a method stayed exempt", verdict)
		}
	})
	t.Run("init-body fill through a writing parameter discharges", func(t *testing.T) {
		t.Parallel()
		// The callee writes a data field through its parameter but
		// retains nothing - in init flow the write is the region's own
		// exempt store, so the retention grade discharges the deferral.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tN     int\n\tBuild func() int\n}\n\nfunc one() int { return 1 }\n\nvar Registry = map[string]*entry{\"a\": {N: 1, Build: one}}\n\nfunc touch(m map[string]*entry) {\n\tm[\"a\"].N++\n\tm[\"a\"].N = 2\n}\n\nfunc init() {\n\ttouch(Registry)\n}\n\nfunc Run() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an init-flow fill through a retention-free parameter kept the escape", verdict)
		}
	})
	t.Run("program-code fill through a writing parameter refuses", func(t *testing.T) {
		t.Parallel()
		// The same callee reached from program code: the write is a
		// post-initialization mutation channel, the strict leak-free
		// grade governs and refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tN     int\n\tBuild func() int\n}\n\nfunc one() int { return 1 }\n\nvar Registry = map[string]*entry{\"a\": {N: 1, Build: one}}\n\nfunc touch(m map[string]*entry) {\n\tm[\"a\"].N++\n\tm[\"a\"].N = 2\n}\n\nfunc Run() int {\n\ttouch(Registry)\n\treturn len(Registry)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a program-code fill slipped the strict grade", verdict)
		}
	})
	t.Run("init-flow fill chaining a retaining method refuses", func(t *testing.T) {
		t.Parallel()
		// The helper writes (retention tolerates that) but then calls a
		// method whose goroutine retains the receiver - the retention
		// grade's method chain must demand retention, never read-only.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype box struct {\n\tn   int\n\tfns []func() int\n}\n\nfunc (b *box) Keep() {\n\tgo func() { _ = b.fns }()\n}\n\nfunc (b *box) Count() int { return len(b.fns) }\n\nfunc one() int { return 1 }\n\nvar Registry = &box{fns: []func() int{one}}\n\nfunc hand(b *box) {\n\tb.n = 1\n\tb.Keep()\n}\n\nfunc init() {\n\thand(Registry)\n}\n\nfunc Run() int { return Registry.Count() }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a retaining method rode a writing helper through init", verdict)
		}
	})
	t.Run("foreign carrier stored through an init fill refuses", func(t *testing.T) {
		t.Parallel()
		// The stored value reaches another carrier: tolerating the store
		// would silently alias two backings through the parameter.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nfunc one() int { return 1 }\n\nvar Inner = []func() int{one}\n\nvar Hooks = map[string][]func() int{}\n\nfunc fill(m map[string][]func() int) {\n\tm[\"a\"] = Inner\n}\n\nfunc init() {\n\tfill(Hooks)\n}\n\nfunc Run() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Hooks - a foreign carrier rode a tolerated store", verdict)
		}
	})
	t.Run("eager goroutine argument keeps the discharge", func(t *testing.T) {
		t.Parallel()
		// A go statement's direct arguments are evaluated at the
		// statement and retain nothing - only the goroutine's own
		// literal captures refuse.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nfunc one() int { return 1 }\n\nvar Hooks = map[string][]func() int{\"a\": {one}}\n\nfunc emit(int) {}\n\nfunc note(m map[string][]func() int) {\n\tgo emit(len(m))\n}\n\nfunc init() {\n\tnote(Hooks)\n}\n\nfunc Run() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an eager goroutine argument refused the retention grade", verdict)
		}
	})
	t.Run("init fill laundering a carrier through a local hop refuses", func(t *testing.T) {
		t.Parallel()
		// A local bound from the foreign carrier is that carrier's
		// backing - the store tolerance must see through the hop.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nfunc one() int { return 1 }\n\nvar Inner = []func() int{one}\n\nvar Hooks = map[string][]func() int{}\n\nfunc fill(m map[string][]func() int) {\n\tx := Inner\n\tm[\"a\"] = x\n}\n\nfunc init() {\n\tfill(Hooks)\n}\n\nfunc Run() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Hooks - a local hop laundered the foreign carrier", verdict)
		}
	})
	t.Run("leak-free proof survives a converting read-only method", func(t *testing.T) {
		t.Parallel()
		// The conversion of a tracked read to a reach-free result is a
		// fresh copy - the retention grade must not refuse it, or every
		// leak-free proof chaining through the method breaks.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype box struct {\n\traw []byte\n\tfns []func() int\n}\n\nfunc (b *box) Dump() string { return string(b.raw) }\n\nfunc one() int { return 1 }\n\nvar Registry = &box{raw: []byte(\"x\"), fns: []func() int{one}}\n\nfunc use(b *box) int {\n\treturn len(b.Dump())\n}\n\nfunc Run() int { return use(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a converting read-only method broke the leak-free chain", verdict)
		}
	})
	t.Run("init-bound method result stays valid", func(t *testing.T) {
		t.Parallel()
		// A called method's receiver is priced by the call's own
		// deferral - binding the RESULT retains nothing of the receiver.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype box struct{ fns []func() int }\n\nfunc (b *box) Count() int { return len(b.fns) }\n\nfunc one() int { return 1 }\n\nvar Registry = &box{fns: []func() int{one}}\n\nvar total int\n\nfunc init() {\n\tt := Registry.Count()\n\ttotal = t\n}\n\nfunc Run() int { return total }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a bound method result escaped its receiver", verdict)
		}
	})
	t.Run("bound carrier method value in init flow escapes", func(t *testing.T) {
		t.Parallel()
		// The bound value retains its receiver past initialization -
		// fail-closed exactly as the call spelling's unproven receiver.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype box struct{ fns []func() int }\n\nfunc (b *box) Keep() {\n\tgo func() { _ = b.fns }()\n}\n\nfunc (b *box) Count() int { return len(b.fns) }\n\nfunc one() int { return 1 }\n\nvar Registry = &box{fns: []func() int{one}}\n\nfunc init() {\n\tf := Registry.Keep\n\tf()\n}\n\nfunc Run() int { return Registry.Count() }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a bound method value slipped the exempt region", verdict)
		}
	})
	t.Run("init-body writing method fill on a carrier receiver discharges", func(t *testing.T) {
		t.Parallel()
		// The method writes receiver state but retains nothing - in init
		// flow the write is the region's own exempt store, so the
		// receiver retention grade discharges the deferral.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype box struct {\n\tn   int\n\tfns []func() int\n}\n\nfunc (b *box) Fill() {\n\tb.n = 2\n}\n\nfunc (b *box) Count() int { return len(b.fns) + b.n }\n\nfunc one() int { return 1 }\n\nvar Registry = &box{fns: []func() int{one}}\n\nfunc init() {\n\tRegistry.Fill()\n}\n\nfunc Run() int { return Registry.Count() }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an init-flow method fill through a retention-free receiver kept the escape", verdict)
		}
	})
	t.Run("init-body method call on a carrier receiver escapes", func(t *testing.T) {
		t.Parallel()
		// The receiver is handed to the callee exactly as an argument
		// is - a retaining method (the goroutine outlives initialization)
		// must not slip through the exempt region unmarked.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype box struct{ fns []func() int }\n\nfunc (b *box) Keep() {\n\tgo func() { _ = b.fns }()\n}\n\nfunc (b *box) Count() int { return len(b.fns) }\n\nvar Registry = &box{fns: []func() int{func() int { return 1 }}}\n\nfunc init() {\n\tRegistry.Keep()\n}\n\nfunc Run() int { return Registry.Count() }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - an init-body carrier receiver stayed exempt", verdict)
		}
	})
	t.Run("foreign self-append of a judged element discharges", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc init() {\n\treg.Hooks = append(reg.Hooks, func() string { return \"x\" })\n}\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a qualified self-append of a capture-free literal refused the audit", verdict)
		}
	})
	t.Run("foreign-carrier registration is audited by the storing package", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc init() {\n\tstate := []string{\"a\"}\n\treg.Hooks = []func() string{func() string { state[0] = \"b\"; return state[0] }}\n}\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a foreign capturing registration passed the audit", verdict)
		}
	})
	t.Run("method expression and nil registrations stay environment-free", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype calc struct{}\n\nfunc (calc) Double(n int) int { return n * 2 }\n\ntype entry struct {\n\tCols  []string\n\tBuild func(c calc, n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{\n\t\t{Cols: []string{\"a\"}, Build: calc.Double},\n\t\t{Cols: []string{\"b\"}, Build: nil},\n\t}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\tif e.Build != nil {\n\t\t\ttotal += e.Build(calc{}, 1)\n\t\t}\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a method expression or nil registration refused the audit", verdict)
		}
	})
	t.Run("mutation culprit outranks the environment culprit", func(t *testing.T) {
		t.Parallel()
		// One package, two refusals: a registered literal stores into a
		// second carrier (program code - the mutation mark), and the
		// first carrier's registration is itself environment-carrying.
		// The culprit names the mutation.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Extra []func() int\n\nvar Hooks []func() int\n\nfunc init() {\n\tcounter := 0\n\tHooks = []func() int{func() int {\n\t\tcounter++\n\t\tExtra = append(Extra, nil)\n\t\treturn counter\n\t}}\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "is mutated") {
			t.Fatalf("verdict = %+v, want the mutation culprit - the environment culprit outranked a demonstrated mutation", verdict)
		}
	})
	t.Run("param-sourced fill in exempt init flow poisons", func(t *testing.T) {
		t.Parallel()
		// The store sits in an init-only helper - the exempt region, so
		// no escape attribution fires - and the parameter RHS is an
		// opaque source the audit alone refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() int\n\nfunc install(fs []func() int) { Hooks = fs }\n\nfunc init() {\n\tinstall([]func() int{func() int { return 1 }})\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a parameter-sourced fill in exempt init flow passed the audit", verdict)
		}
	})
	t.Run("aliased-local handout to a method in an init body escapes", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype sink struct{ m map[string]func() }\n\nfunc (s *sink) Keep(m map[string]func()) { s.m = m }\n\nvar keeper sink\n\nvar Hooks = map[string]func(){}\n\nfunc init() {\n\tm := Hooks\n\tkeeper.Keep(m)\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Hooks - an aliased init-local handout to a method stayed exempt", verdict)
		}
	})
	t.Run("wrapped carrier argument in an init body escapes", func(t *testing.T) {
		t.Parallel()
		// The carrier rides inside a composite argument - no deferral
		// can resolve it, and the exempt region's fail-closed arm must
		// still see it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype wrap struct{ m map[string]func() }\n\nfunc churn(m map[string]func()) {\n\tfor k := range m {\n\t\tdelete(m, k)\n\t}\n}\n\nfunc hold(w wrap) { go churn(w.m) }\n\nvar Hooks = map[string]func(){}\n\nfunc init() {\n\thold(wrap{m: Hooks})\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Hooks - a wrapped carrier argument slipped the exempt region", verdict)
		}
	})
	t.Run("copied-out carrier alias escapes through its handout", func(t *testing.T) {
		t.Parallel()
		// A builtin copy binds the destination local to the carrier's
		// backing; handing the destination out afterwards is handing the
		// carrier out.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []map[string]func() int{{\"a\": one}}\n\nfunc one() int { return 1 }\n\nfunc two() int { return 2 }\n\nfunc churn(d []map[string]func() int) {\n\tfor _, m := range d {\n\t\tm[\"a\"] = two\n\t}\n}\n\nfunc init() {\n\tdst := make([]map[string]func() int, 1)\n\tcopy(dst, Hooks)\n\tgo churn(dst)\n}\n\nfunc Read() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Read() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Read"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want a downgrade naming reg.Hooks - a copied-out alias handed to a goroutine stayed settled", verdict)
		}
	})
	t.Run("declared alias joins the alias set", func(t *testing.T) {
		t.Parallel()
		// The var-declaration form of the one-line alias - a declaration
		// binding aliases exactly as an assignment binding does.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc churn(s []string) {\n\tfor i := range s {\n\t\ts[i] = s[i] + \"!\"\n\t}\n}\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tvar alias = state\n\tgo churn(alias)\n\tHooks = []func() string{func() string { return state[0] }}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a declared alias slipped the closure", verdict)
		}
	})
	t.Run("declared init-local alias is the carrier inside a stored literal", func(t *testing.T) {
		t.Parallel()
		// The var-declaration form of the init-local alias: a stored
		// literal writing through it writes the carrier.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nvar Add func()\n\nfunc init() {\n\tvar m = Hooks\n\tAdd = func() { m[\"k\"] = func() {} }\n}\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want a downgrade naming reg.Hooks - a declared alias write inside a stored literal stayed unattributed", verdict)
		}
	})
	t.Run("store through a pointer alias is audited", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tp := &Hooks\n\t*p = []func() string{func() string { state[0] = \"b\"; return state[0] }}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a pointer-alias store slipped the audit", verdict)
		}
	})
	t.Run("parenthesized copy destination stays bound", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []map[string]func() int{{\"a\": one}}\n\nfunc one() int { return 1 }\n\nfunc two() int { return 2 }\n\nfunc churn(d []map[string]func() int) {\n\tfor _, m := range d {\n\t\tm[\"a\"] = two\n\t}\n}\n\nfunc init() {\n\tdst := make([]map[string]func() int, 1)\n\tcopy((dst), Hooks)\n\tgo churn(dst)\n}\n\nfunc Read() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Read() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Read"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want a downgrade naming reg.Hooks - a parenthesized copy destination escaped the binding", verdict)
		}
	})
	t.Run("append through a resliced alias is audited", func(t *testing.T) {
		t.Parallel()
		// The append rebinds the local AND writes the new element into
		// the shared backing whenever capacity allows - a store through
		// the alias, never exempt as a rebinding.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []func(){func() {}}\n\nfunc init() {\n\tstate := 0\n\tm := Hooks[:0]\n\tm = append(m, func() { state++ })\n}\n\nfunc Run() { Hooks[0]() }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() { reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - an append through a resliced alias passed as a rebinding", verdict)
		}
	})
	t.Run("copy into an aliased local is audited", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []func() int{nil}\n\nfunc init() {\n\tstate := 0\n\tm := Hooks\n\tcopy(m, []func() int{func() int { state++; return state }})\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\tif f != nil {\n\t\t\ttotal += f()\n\t\t}\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a copy into an aliased local passed as a rebinding", verdict)
		}
	})
	t.Run("store through a paren-copied alias is audited", func(t *testing.T) {
		t.Parallel()
		// The destination arrives parenthesized and the capturing store
		// goes through it - the audit's alias resolution must see both.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks = []map[string]func() int{{}}\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tdst := make([]map[string]func() int, 1)\n\tcopy((dst), Hooks)\n\tdst[0][\"k\"] = func() int { state[0] = \"b\"; return len(state) }\n}\n\nfunc Read() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Read() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Read"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a capturing store through a paren-copied alias slipped the audit", verdict)
		}
	})
	t.Run("multi-source binding joins every backing to the alias set", func(t *testing.T) {
		t.Parallel()
		// One binding, two sources: the combined slice shares the
		// captured state's backing through the appended elements, and
		// the goroutine writes it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc churn(s [][]string) {\n\tfor _, row := range s {\n\t\trow[0] = row[0] + \"!\"\n\t}\n}\n\nfunc init() {\n\tstate := [][]string{{\"a\"}}\n\tfresh := [][]string{}\n\tcombo := append(fresh, state...)\n\tgo churn(combo)\n\tHooks = []func() string{func() string { return state[0][0] }}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a multi-source alias binding slipped the closure", verdict)
		}
	})
	t.Run("go-statement argument poisons the captured environment", func(t *testing.T) {
		t.Parallel()
		// The goroutine outlives initialization holding the environment
		// the registered reader captures - fail-closed without judging
		// what the goroutine's callee does with it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc churn(s []string) {\n\tfor i := range s {\n\t\ts[i] = s[i] + \"!\"\n\t}\n}\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tgo churn(state)\n\tHooks = []func() string{func() string { return state[0] }}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a goroutine holding the captured environment left it settled", verdict)
		}
	})
	t.Run("capturing literal registration refuses every reader", func(t *testing.T) {
		t.Parallel()
		// The environment hole: registered closures share an init-local
		// slice, one writing it, one reading it - subjects in one binary
		// observe order-dependent state under what would otherwise be a
		// closed verdict. The audit refuses the carrier itself, so even a
		// proof-free read path (a func-element range binds nothing of
		// mutable reach) downgrades.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() string\n\nfunc init() {\n\tstate := []string{\"a\"}\n\tHooks = []func() string{\n\t\tfunc() string { state[0] = state[0] + \"!\"; return \"\" },\n\t\tfunc() string { return state[0] },\n\t}\n}\n\nfunc Run() string {\n\tout := \"\"\n\tfor _, f := range Hooks {\n\t\tout += f()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a capturing registered closure kept the carrier settled", verdict)
		}
	})
	t.Run("written captured scalar refuses like captured reach", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() int\n\nfunc init() {\n\tcounter := 0\n\tHooks = []func() int{func() int { counter++; return counter }}\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a written captured scalar kept the carrier settled", verdict)
		}
	})
	t.Run("read-only captured scalar stays environment-free", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar Hooks []func() int\n\nfunc init() {\n\tbase := 10\n\tHooks = []func() int{func() int { return base }}\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a read-only captured scalar is settled after initialization", verdict)
		}
	})
	t.Run("constructor-result registration audits the returns", func(t *testing.T) {
		t.Parallel()
		// The generated-registry shape: a carrier initialized from a
		// plain named in-package constructor defers to the
		// constructor's return-environment-free proof instead of
		// poisoning as an opaque call result.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc triple(n int) int { return 3 * n }\n\nfunc generated() []handler {\n\treturn []handler{double, triple}\n}\n\nvar Registry = generated()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a constructor returning named functions poisoned the registry", verdict)
		}
	})
	t.Run("foreign constructor chain resolves at composition", func(t *testing.T) {
		t.Parallel()
		// The generated-thresholds shape: the in-package constructor
		// returns a foreign constructor's result over foreign
		// call-result arguments - each proof persists per package and
		// the chain resolves at composition.
		files := map[string]string{
			"go.mod":       goMod,
			"lib/lib.go":   "package lib\n\ntype Rule func(n int) bool\n\ntype Row struct {\n\tName string\n\tR    Rule\n}\n\nfunc Cite(name string) string { return name + \"!\" }\n\nfunc Must(rows ...Row) []Row {\n\treturn rows\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/lib\"\n\nfunc positive(n int) bool { return n > 0 }\n\nfunc generated() []lib.Row {\n\treturn lib.Must(lib.Row{Name: lib.Cite(\"a\"), R: positive})\n}\n\nvar Registry = generated()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a foreign constructor chain refused the composed proofs", verdict)
		}
	})
	t.Run("returned closure over a parameter admits with judged arguments", func(t *testing.T) {
		t.Parallel()
		// The near-policy shape: the constructor returns a literal
		// capturing only its own parameter, whose in-literal use
		// chains through a same-package leak-free parameter; the
		// caller judges the argument.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nfunc matchCols(got, want []string) bool {\n\treturn len(got) == len(want)\n}\n\nfunc nearPolicy(legacy []string) func(got []string) bool {\n\treturn func(got []string) bool { return matchCols(got, legacy) }\n}\n\nvar defaultCols = []string{\"a\"}\n\ntype class struct {\n\tMatch func(got []string) bool\n\tCols  []string\n}\n\nvar Registry = []class{{Match: nearPolicy(defaultCols), Cols: defaultCols}}\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a parameter-capturing returned closure refused the audit", verdict)
		}
	})
	t.Run("constructor returning a bound method value keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc generated() []handler {\n\tc := &counter{}\n\treturn []handler{c.Next}\n}\n\nvar Registry = generated()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a constructor-returned method value proved environment-free", verdict)
		}
	})
	t.Run("constructor closure leaking its capture keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The returned literal's body hands its captured environment
		// to a package variable - the use-shape judgment over the
		// literal refuses, so the constructor never proves.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar stash []int\n\ntype handler func(n int) int\n\nfunc generated() []handler {\n\tshared := []int{0}\n\treturn []handler{func(n int) int {\n\t\tstash = shared\n\t\treturn shared[0] + n\n\t}}\n}\n\nvar Registry = generated()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a capture-leaking literal proved environment-free", verdict)
		}
	})
	t.Run("non-environment-free constructor argument keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc wrap(h handler) []handler { return []handler{h} }\n\nvar seed = &counter{}\n\nvar Registry = wrap(seed.Next)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a method-value argument rode a proven constructor", verdict)
		}
	})
	t.Run("constructor cycle keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc genA() []handler { return genB() }\n\nfunc genB() []handler { return genA() }\n\nvar Registry = genA()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a constructor cycle resolved environment-free", verdict)
		}
	})
	t.Run("element write into a returned local keeps the poison", func(t *testing.T) {
		t.Parallel()
		// A write through an index reaches the local's storage without
		// a whole-identifier bind - the binding breaks, however the
		// composite it started from judged.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc generated() []handler {\n\ths := []handler{double}\n\tc := &counter{}\n\ths[0] = c.Next\n\treturn hs\n}\n\nvar Registry = generated()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an element write into a returned local proved environment-free", verdict)
		}
	})
	t.Run("field write into a returned local keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype row struct{ H handler }\n\nfunc generated() []row {\n\tr := row{H: double}\n\tc := &counter{}\n\tr.H = c.Next\n\treturn []row{r}\n}\n\nvar Registry = generated()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a field write into a returned local proved environment-free", verdict)
		}
	})
	t.Run("address-captured returned local keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The address opens a deref write path the binding walk cannot
		// see - the capture breaks the binding.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc generated() []handler {\n\tvar h handler = double\n\tp := &h\n\tc := &counter{}\n\t*p = c.Next\n\treturn []handler{h}\n}\n\nvar Registry = generated()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an address-captured local proved environment-free", verdict)
		}
	})
	t.Run("reassigned parameter keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The caller judged the entry value; the body swapped in a
		// bound method value the caller never saw.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc generated(h handler) []handler {\n\tc := &counter{}\n\th = c.Next\n\treturn []handler{h}\n}\n\nvar Registry = generated(nil)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a reassigned parameter kept the caller's assumption", verdict)
		}
	})
	t.Run("building constructor derives from its parameter", func(t *testing.T) {
		t.Parallel()
		// The validate-loop-and-build shape: range over the variadic
		// parameter, field reads off the bound row, append
		// accumulation onto the local, an index write whose operand
		// only reads the row, a multi-value bind from a judged call,
		// and a converted result.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype row struct {\n\tName string\n\tH    handler\n}\n\ntype rows2 []row\n\nfunc validate(in []row) ([]row, error) {\n\treturn in, nil\n}\n\nfunc gen(rows ...row) rows2 {\n\tout := make([]row, 0, len(rows))\n\tseen := map[string]int{}\n\tfor i, r := range rows {\n\t\tseen[r.Name] = i\n\t\th := r.H\n\t\t_ = h\n\t\tout = append(out, row{Name: r.Name, H: r.H})\n\t}\n\tbuilt, err := validate(out)\n\tif err != nil {\n\t\tpanic(err)\n\t}\n\treturn rows2(built)\n}\n\nvar Registry = gen(row{Name: \"a\", H: double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a building constructor refused the caller-judged derivations", verdict)
		}
	})
	t.Run("explicit generic constructor instantiation resolves", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"lib/lib.go":   "package lib\n\nfunc Must[T any](rows ...T) []T {\n\tout := make([]T, 0, len(rows))\n\tfor _, r := range rows {\n\t\tout = append(out, r)\n\t}\n\treturn out\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/lib\"\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype row struct {\n\tName string\n\tH    handler\n}\n\nvar Registry = lib.Must[row](row{Name: \"a\", H: double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an explicit generic instantiation refused the constructor deferral", verdict)
		}
	})
	t.Run("returned append of judged elements derives", func(t *testing.T) {
		t.Parallel()
		// The append arm in return position: judged elements onto the
		// caller-judged variadic base, no local in between.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(rows ...handler) []handler {\n\treturn append(rows, double)\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a returned append of judged elements refused the derivation", verdict)
		}
	})
	t.Run("pointer-receiver method write on a range binding keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The method call addresses its receiver with no & in the
		// syntax - the auto-address is the same write path the
		// explicit capture arm breaks on.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype row struct {\n\tName string\n\tH    handler\n}\n\nfunc (r *row) poison(c *counter) { r.H = c.Next }\n\nfunc gen(rows ...row) []row {\n\tout := make([]row, 0, len(rows))\n\tc := &counter{}\n\tfor _, r := range rows {\n\t\tr.poison(c)\n\t\tout = append(out, r)\n\t}\n\treturn out\n}\n\nvar Registry = gen(row{Name: \"a\", H: double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an auto-addressed method write stayed judged", verdict)
		}
	})
	t.Run("self-capturing field bind breaks the read-only proof", func(t *testing.T) {
		t.Parallel()
		// A constructor-installed closure capturing the receiver is the
		// receiver-stored launder: the holding field reads reach-free
		// under the carrier rules, yet calling it writes receiver state.
		// A signature-carrying receiver-rooted read therefore refuses -
		// the read-only proof fails, the auto-address break stays
		// judged, and the verdict refuses instead of serving a proof
		// that assumed the receiver stable
		// (REQ-closure-shared-dynamic-state).
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\ntype row struct {\n\tName string\n\tH    handler\n}\n\nfunc mk() row {\n\tvar r row\n\tr.H = func(n int) int {\n\t\tr.Name = \"written\"\n\t\treturn n\n\t}\n\treturn r\n}\n\nfunc (r *row) title() string {\n\th := r.H\n\t_ = h(1)\n\treturn r.Name\n}\n\nfunc gen(rows ...row) []row {\n\tout := make([]row, 0, len(rows))\n\tfor _, r := range rows {\n\t\t_ = r.title()\n\t\tout = append(out, r)\n\t}\n\treturn out\n}\n\nvar Registry = gen(mk())\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status == Valid {
			t.Fatalf("verdict = %+v, want a refusal - the self-capturing field bind was proven receiver-read-only", verdict)
		}
		t.Logf("reason: %q", verdict.Reason)
	})
	t.Run("read-only method call on a judged binding stays judged", func(t *testing.T) {
		t.Parallel()
		// The in-package receiver-read-only proof exempts the
		// auto-address break - the precision the exemption exists for.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype row struct {\n\tName string\n\tH    handler\n}\n\nfunc (r *row) title() string { return r.Name }\n\nfunc gen(rows ...row) []row {\n\tout := make([]row, 0, len(rows))\n\tfor _, r := range rows {\n\t\t_ = r.title()\n\t\tout = append(out, r)\n\t}\n\treturn out\n}\n\nvar Registry = gen(row{Name: \"a\", H: double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a proven read-only method call broke the binding", verdict)
		}
	})
	t.Run("channel range keeps the poison", func(t *testing.T) {
		t.Parallel()
		// A channel's elements are sender-supplied - never part of the
		// judged operand.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc gen() []handler {\n\tch := make(chan handler, 1)\n\tc := &counter{}\n\tch <- c.Next\n\tclose(ch)\n\tout := make([]handler, 0, 1)\n\tfor f := range ch {\n\t\tout = append(out, f)\n\t}\n\treturn out\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - channel elements rode the range derivation", verdict)
		}
	})
	t.Run("function range keeps the poison", func(t *testing.T) {
		t.Parallel()
		// An iterator's elements are yield-supplied - the function
		// value's own environment-freedom says nothing about them.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc iter(yield func(handler) bool) {\n\tc := &counter{}\n\tyield(c.Next)\n}\n\nfunc gen() []handler {\n\tout := make([]handler, 0, 1)\n\tfor f := range iter {\n\t\tout = append(out, f)\n\t}\n\treturn out\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - yield-supplied elements rode the range derivation", verdict)
		}
	})
	t.Run("aliased map write keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The break follows the storage, not the name: a write through
		// either alias breaks both.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen() map[string]handler {\n\tm := map[string]handler{\"d\": double}\n\tm2 := m\n\tc := &counter{}\n\tm2[\"k\"] = c.Next\n\treturn m\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - the alias write left the returned name judged", verdict)
		}
	})
	t.Run("append through a fresh base of an unjudged element keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The free-arm append judgment (not the self-append bind arm):
		// the element must judge wherever the append lands.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen() []handler {\n\tother := []handler{double}\n\tc := &counter{}\n\tout := append(other, c.Next)\n\treturn out\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an unjudged element rode a fresh-base append", verdict)
		}
	})
	t.Run("shared-backing append write keeps the poison", func(t *testing.T) {
		t.Parallel()
		// A fresh-base append with spare capacity shares the base's
		// backing: the write through the new name lands in the
		// returned one.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen() []handler {\n\tother := append(make([]handler, 0, 2), double)\n\tout := append(other, double)\n\tc := &counter{}\n\tout[0] = c.Next\n\treturn other\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a shared-backing append write left the base judged", verdict)
		}
	})
	t.Run("nested append chain write keeps the poison", func(t *testing.T) {
		t.Parallel()
		// Every level of an append chain may share the innermost
		// base's backing: the alias link descends to it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen() []handler {\n\tbase := append(make([]handler, 0, 3), double)\n\tout := append(append(base, double), double)\n\tc := &counter{}\n\tout[0] = c.Next\n\treturn base\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a nested append chain write left the innermost base judged", verdict)
		}
	})
	t.Run("sliced-base append write keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The base hunt stops at the slice expression; the tracked
		// name inside it still owns the backing the target shares.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen() []handler {\n\tbase := append(make([]handler, 0, 3), double)\n\tout := append(base[:1], double)\n\tc := &counter{}\n\tout[0] = c.Next\n\treturn base\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a sliced-base append write left the base judged", verdict)
		}
	})
	t.Run("sliced nested append chain write keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The chain's slice step hides the base from the descend;
		// the walk of the terminal expression still links it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen() []handler {\n\tbase := append(make([]handler, 0, 3), double)\n\tout := append(append(base, double)[:1], double)\n\tc := &counter{}\n\tout[0] = c.Next\n\treturn base\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a sliced nested append chain write left the base judged", verdict)
		}
	})
	t.Run("element write of a judged value derives", func(t *testing.T) {
		t.Parallel()
		// A store of a caller-judged value into a fresh map is a
		// store, not a break: the base holds only judged values.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) map[string]handler {\n\tm := map[string]handler{}\n\tm[\"d\"] = h\n\treturn m\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an element write of a judged value refused the derivation", verdict)
		}
	})
	t.Run("field write of a judged value derives", func(t *testing.T) {
		t.Parallel()
		// The building-constructor shape: a fresh struct filled field
		// by field with caller-judged values.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype catalog struct{ current handler }\n\nfunc gen(h handler) map[string]handler {\n\tc := catalog{}\n\tc.current = h\n\treturn map[string]handler{\"d\": c.current}\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a field write of a judged value refused the derivation", verdict)
		}
	})
	t.Run("dereference write of a judged value derives", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype catalog struct{ current handler }\n\nfunc gen(h handler) map[string]handler {\n\tp := new(catalog)\n\t*p = catalog{current: h}\n\treturn map[string]handler{\"d\": p.current}\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a dereference write of a judged value refused the derivation", verdict)
		}
	})
	t.Run("element write of an unjudged value keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) map[string]handler {\n\tm := map[string]handler{}\n\tm[\"d\"] = h\n\tc := &counter{}\n\tm[\"k\"] = c.Next\n\treturn m\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an unjudged element store left the base judged", verdict)
		}
	})
	t.Run("field write of an unjudged value keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\ntype catalog struct{ current handler }\n\nfunc gen() map[string]handler {\n\tc := catalog{}\n\tk := &counter{}\n\tc.current = k.Next\n\treturn map[string]handler{\"d\": c.current}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an unjudged field store left the base judged", verdict)
		}
	})
	t.Run("aliased element write of a judged value stays judged", func(t *testing.T) {
		t.Parallel()
		// The store lands through the alias; the component's store
		// set answers for both names.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) map[string]handler {\n\tm := map[string]handler{\"d\": h}\n\tm2 := m\n\tm2[\"k\"] = h\n\treturn m\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a judged store through an alias refused the base", verdict)
		}
	})
	t.Run("element write into a parameter keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The caller's storage mutates under the caller's judgment;
		// the write breaks the assumption even when the value judges.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(rows []handler, h handler) []handler {\n\trows[0] = h\n\treturn rows\n}\n\nvar Registry = gen([]handler{double}, double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a parameter-element write left the assumption standing", verdict)
		}
	})
	t.Run("element write through a parameter alias keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The store reaches the caller's storage through the local
		// alias; the parameter's component breaks outright.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(rows []handler, h handler) []handler {\n\tr2 := rows\n\tc := &counter{}\n\tr2[0] = c.Next\n\treturn rows\n}\n\nvar Registry = gen([]handler{double}, double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a parameter-alias store left the assumption standing", verdict)
		}
	})
	t.Run("judged element write through a parameter alias keeps the poison", func(t *testing.T) {
		t.Parallel()
		// Even a judged store mutates the caller's storage under the
		// caller's judgment - the break is unconditional.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(rows []handler, h handler) []handler {\n\tr2 := rows\n\tr2[0] = h\n\treturn rows\n}\n\nvar Registry = gen([]handler{double}, double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a judged parameter-alias store left the assumption standing", verdict)
		}
	})
	t.Run("dereference write of an unjudged value keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\ntype catalog struct{ current handler }\n\nfunc gen() map[string]handler {\n\tp := new(catalog)\n\tk := &counter{}\n\t*p = catalog{current: k.Next}\n\treturn map[string]handler{\"d\": p.current}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an unjudged dereference store left the base judged", verdict)
		}
	})
	t.Run("pointer-carrier field store of a judged value derives", func(t *testing.T) {
		t.Parallel()
		// The constructor returns the pointer itself; the audit judges
		// the package state without the accessor reading through it (a
		// field read through a pointer-typed package carrier refuses
		// at the escapes culprit instead).
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype catalog struct{ current handler }\n\nfunc gen(h handler) *catalog {\n\tc := &catalog{}\n\tc.current = h\n\treturn c\n}\n\nvar registry = gen(double)\n\nfunc Count() int { return 1 }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a pointer-carrier field store of a judged value refused the derivation", verdict)
		}
	})
	t.Run("copy into a constructor local keeps the poison", func(t *testing.T) {
		t.Parallel()
		// A valueless write breaks outright - copy's stored values are
		// invisible to the binding walk.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) []handler {\n\tdst := make([]handler, 1)\n\tcopy(dst, []handler{h})\n\treturn dst\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a copy target stayed judged", verdict)
		}
	})
	t.Run("write through an element-read binding keeps the poison", func(t *testing.T) {
		t.Parallel()
		// x aliases s[0]'s pointee; the write through x lands in the
		// returned slice's element.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype catalog struct{ current handler }\n\nfunc gen(h handler) []*catalog {\n\ts := []*catalog{{current: h}}\n\tx := s[0]\n\tc := &counter{}\n\tx.current = c.Next\n\treturn s\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an element-read alias write left the container judged", verdict)
		}
	})
	t.Run("write through a map-element-read binding keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) map[string][]handler {\n\tm := map[string][]handler{\"a\": {h}}\n\tx := m[\"a\"]\n\tc := &counter{}\n\tx[0] = c.Next\n\treturn m\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a map-element alias write left the container judged", verdict)
		}
	})
	t.Run("write through a conversion binding keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype table map[string]handler\n\nfunc gen(h handler) map[string]handler {\n\tm := map[string]handler{\"d\": h}\n\tm2 := table(m)\n\tc := &counter{}\n\tm2[\"k\"] = c.Next\n\treturn m\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a conversion alias write left the original judged", verdict)
		}
	})
	t.Run("write through a literal-embedded parameter keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The composite literal embeds the parameter's backing; the
		// store through the literal's field reaches the caller's
		// storage.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype holder struct{ rows []handler }\n\nfunc gen(rows []handler) []handler {\n\th := holder{rows: rows}\n\tc := &counter{}\n\th.rows[0] = c.Next\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a literal-embedded parameter store left the assumption standing", verdict)
		}
	})
	t.Run("write through an argument-returning callee result keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc id(s []handler) []handler { return s }\n\nfunc gen(h handler) []handler {\n\tbase := []handler{h}\n\tout := id(base)\n\tc := &counter{}\n\tout[0] = c.Next\n\treturn base\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a callee-result alias write left the argument judged", verdict)
		}
	})
	t.Run("self-append accumulation stays judged", func(t *testing.T) {
		t.Parallel()
		// The accumulation-loop core: appends onto the binding itself
		// flow only the new elements, never the self-reference.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(hs ...handler) []handler {\n\tvar out []handler\n\tfor _, h := range hs {\n\t\tout = append(out, h)\n\t}\n\treturn out\n}\n\nvar Registry = gen(double, double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the self-append accumulation refused", verdict)
		}
	})
	t.Run("judged store through a conversion binding stays judged", func(t *testing.T) {
		t.Parallel()
		// The link feeds the store union, not a hard break: the
		// conversion alias with a judged store keeps both names valid.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype table map[string]handler\n\nfunc gen(h handler) map[string]handler {\n\tm := map[string]handler{\"d\": h}\n\tm2 := table(m)\n\tm2[\"k\"] = h\n\treturn m\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a judged store through a conversion alias refused the original", verdict)
		}
	})
	t.Run("struct value copy stays independent storage", func(t *testing.T) {
		t.Parallel()
		// A struct value bind copies its scalar fields; the copy's
		// unjudged store must not poison the original.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype catalog struct{ current handler }\n\nfunc gen(h handler) map[string]handler {\n\tc := catalog{current: h}\n\td := c\n\tk := &counter{}\n\td.current = k.Next\n\treturn map[string]handler{\"d\": c.current}\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the copy's store poisoned the independent original", verdict)
		}
	})
	t.Run("keyed literals of one struct type stay independent", func(t *testing.T) {
		t.Parallel()
		// A field name denotes no runtime value: two locals built
		// from keyed literals of the same struct type must not share
		// a component through the field object.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype holder struct{ rows []handler }\n\nfunc gen(h handler) []handler {\n\ta := holder{rows: []handler{h}}\n\tb := holder{rows: []handler{h}}\n\tk := &counter{}\n\tb.rows[0] = k.Next\n\treturn a.rows\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the sibling literal's store poisoned an independent local through the field object", verdict)
		}
	})
	t.Run("write through a stored value's container keeps the poison", func(t *testing.T) {
		t.Parallel()
		// Storing base into m makes m's storage reach base's backing;
		// the write through m's element lands in base.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) []handler {\n\tbase := []handler{h}\n\tm := map[string][]handler{}\n\tm[\"a\"] = base\n\tc := &counter{}\n\tm[\"a\"][0] = c.Next\n\treturn base\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a store never linked the container to the stored value", verdict)
		}
	})
	t.Run("write through a self-appended element keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The appended element's backing joins the accumulating
		// binding; a write through the binding's element lands in the
		// element's original container.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype catalog struct{ current handler }\n\nfunc gen(h handler) []*catalog {\n\ts := []*catalog{{current: h}}\n\tvar out []*catalog\n\tout = append(out, s[0])\n\tc := &counter{}\n\tout[0].current = c.Next\n\treturn s\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a self-appended element's aliasing was dropped", verdict)
		}
	})
	t.Run("slice-step write keeps the poison", func(t *testing.T) {
		t.Parallel()
		// s[0:1][0] writes s's backing through a slice step.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) []handler {\n\ts := []handler{h}\n\tc := &counter{}\n\ts[0:1][0] = c.Next\n\treturn s\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a slice-step write was invisible to the chain walk", verdict)
		}
	})
	t.Run("address capture of a conversion alias keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The break through the alias propagates across the new link
		// shapes exactly as across whole-identifier pairs.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype table map[string]handler\n\nfunc gen(h handler) map[string]handler {\n\tm := map[string]handler{\"d\": h}\n\tm2 := table(m)\n\tq := &m2\n\t_ = q\n\treturn m\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - the address-capture break failed to cross the conversion link", verdict)
		}
	})
	t.Run("write through a call-rooted chain keeps the poison", func(t *testing.T) {
		t.Parallel()
		// id(s)[0] writes s's backing through the call result; the
		// non-ident root breaks every tracked name it reaches.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc id(s []handler) []handler { return s }\n\nfunc gen(h handler) []handler {\n\ts := []handler{h}\n\tc := &counter{}\n\tid(s)[0] = c.Next\n\treturn s\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a call-rooted write chain was invisible", verdict)
		}
	})
	t.Run("argument-position call-rooted address capture keeps the poison", func(t *testing.T) {
		t.Parallel()
		// sink(&id(s)[0]) hands the callee a pointer into s's backing
		// through the call result; the call-rooted capture breaks every
		// tracked name the operand reaches, fail-closed.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc id(s []handler) []handler { return s }\n\nfunc sink(p *handler) {\n\tc := &counter{}\n\t*p = c.Next\n}\n\nfunc gen(h handler) []handler {\n\ts := []handler{h}\n\tsink(&id(s)[0])\n\treturn s\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an argument-position call-rooted capture was invisible", verdict)
		}
	})
	t.Run("argument-position literal capture hands out embedded reach", func(t *testing.T) {
		t.Parallel()
		// sink(&holder{rows: rows}) lets the callee write p.rows[0] -
		// the literal is fresh storage, but its embedded tracked names
		// travel with the pointer; the literal exemption is sound only
		// where the bind link or the returned-literal audit carries the
		// reach.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype holder struct{ rows []handler }\n\nfunc sink(p *holder) {\n\tc := &counter{}\n\tp.rows[0] = c.Next\n}\n\nfunc gen(rows []handler) []handler {\n\tsink(&holder{rows: rows})\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an argument-position literal capture handed out reach invisibly", verdict)
		}
	})
	t.Run("returned literal constructor stays admissible", func(t *testing.T) {
		t.Parallel()
		// return &T{field: param} is the constructor idiom the
		// returned-literal audit owns: the literal addresses fresh
		// storage and the parameter's reach rides the audit, never a
		// break - the fail-closed capture extension must not refuse it.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype holder struct{ rows []handler }\n\nfunc build(rows []handler) *holder {\n\treturn &holder{rows: rows}\n}\n\nfunc gen(h handler) []handler {\n\tb := build([]handler{h})\n\treturn b.rows\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the return-position literal capture was spuriously broken", verdict)
		}
	})
	t.Run("bind-position literal capture links without breaking", func(t *testing.T) {
		t.Parallel()
		// p := &holder{rows: rows} rides the bind link: reach is
		// carried, nothing breaks, and absent writes the registration
		// composes Valid.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype holder struct{ rows []handler }\n\nfunc gen(rows []handler) []handler {\n\tp := &holder{rows: rows}\n\t_ = p\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a bind-position literal capture broke instead of linking", verdict)
		}
	})
	t.Run("bind-then-pass capture defers to the callee's argument insertions", func(t *testing.T) {
		t.Parallel()
		// p := &holder{rows: rows}; sink(p) hands the callee a write
		// path into rows' backing through the bind link; sink's
		// p.rows[0] = c.Next inserts a method value the audit refuses —
		// the callee's argument-storage insertions must join the
		// carrier's population over the dependency edge, not vanish
		// behind a return-position-only proof (a no-return callee
		// resolves vacuously).
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype holder struct{ rows []handler }\n\nfunc sink(p *holder) {\n\tc := &counter{}\n\tp.rows[0] = c.Next\n}\n\nfunc gen(rows []handler) []handler {\n\tp := &holder{rows: rows}\n\tsink(p)\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a bind-then-pass callee's argument insertion was invisible", verdict)
		}
	})
	t.Run("no-address tracked argument defers to the callee's argument insertions", func(t *testing.T) {
		t.Parallel()
		// sink2(s) passes the slice header itself - same backing, no &
		// anywhere; sink2's q[0] = c.Next is the same unaudited
		// insertion through argument storage.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc sink2(q []handler) {\n\tc := &counter{}\n\tq[0] = c.Next\n}\n\nfunc gen(s []handler) []handler {\n\tsink2(s)\n\treturn s\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a no-address tracked argument's callee insertion was invisible", verdict)
		}
	})
	t.Run("elided address-of in pointer-element composite literal breaks embedded reach", func(t *testing.T) {
		t.Parallel()
		// sink([]*holder{{rows: rows}}) - Go elides the & on the inner
		// literal (no UnaryExpr), but the slice element is *holder and
		// the callee writes ps[0].rows[0]; the argument-literal walk
		// must see the elided spelling.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype holder struct{ rows []handler }\n\nfunc sink(ps []*holder) {\n\tc := &counter{}\n\tps[0].rows[0] = c.Next\n}\n\nfunc gen(rows []handler) []handler {\n\tsink([]*holder{{rows: rows}})\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - the elided address-of hid the literal's embedded reach", verdict)
		}
	})
	t.Run("non-inserting callee keeps the tracked argument admissible", func(t *testing.T) {
		t.Parallel()
		// probe(rows) reads len(q) only - a callee with no argument
		// insertions must not poison the store; the admission leg pins
		// that the new edge is precise, never a blanket break.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar total int\n\nfunc probe(q []handler) {\n\ttotal += len(q)\n}\n\nfunc gen(rows []handler) []handler {\n\tprobe(rows)\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a non-inserting callee poisoned its tracked argument", verdict)
		}
	})
	t.Run("plain-named-function insertion through argument storage stays admissible", func(t *testing.T) {
		t.Parallel()
		// fill(q) writes q[0] = double - an insertion the audit admits
		// (a plain named function carries no environment); the edge must
		// carry the insertion into the population, where it composes.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc fill(q []handler) {\n\tq[0] = double\n}\n\nfunc gen(rows []handler) []handler {\n\tfill(rows)\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an admissible plain-named insertion refused the store", verdict)
		}
	})
	t.Run("init-flow carrier argument refuses on the writable escape", func(t *testing.T) {
		t.Parallel()
		// var A = ...; var Registry = gen2(A) - gen2 inserts a method
		// value into A's backing at init. An observer of A refuses
		// TODAY on the writable-escape arm (A handed to a call is
		// mutation-equivalent), which outranks the env-audit culprit;
		// this anchor pins that init-flow carrier arguments never need
		// the callee-insertion mechanism to refuse.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen2(q []handler) []handler {\n\tc := &counter{}\n\tq[0] = c.Next\n\treturn q\n}\n\nvar A = []handler{double}\n\nvar Registry = gen2(A)\n\nfunc CountA() int { return len(A) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.CountA() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "CountA"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.A escapes writable") {
			t.Fatalf("verdict = %+v, want the writable-escape refusal covering init-flow carrier arguments", verdict)
		}
	})
	t.Run("rebound parameter insertion keeps the poison", func(t *testing.T) {
		t.Parallel()
		// sink rebinds h before storing it: the stored value is no
		// longer the caller's judged argument, so the bare-parameter
		// skip must not fire (H1 of the chunk-83 review).
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc sink(q []handler, h handler) {\n\tc := &counter{}\n\th = c.Next\n\tq[0] = h\n}\n\nfunc gen(rows []handler) []handler {\n\tsink(rows, double)\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade - a rebound parameter's insertion was skipped as the caller's value", verdict)
		}
	})
	t.Run("environment-carrying argument to a deferring call keeps the poison", func(t *testing.T) {
		t.Parallel()
		// gen passes c.Next as sink's second argument; sink stores it
		// into the first. The caller's obligation is discharged by
		// judging EVERY argument of a deferring call at the call site
		// (H2 of the chunk-83 review) - a method value refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc sink(q []handler, h handler) {\n\tq[0] = h\n}\n\nfunc gen(rows []handler) []handler {\n\tc := &counter{}\n\tsink(rows, c.Next)\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade - an environment-carrying argument slipped past the deferring call", verdict)
		}
	})
	t.Run("call-rooted tracked argument keeps the poison", func(t *testing.T) {
		t.Parallel()
		// sink(id(s)) hands the callee s's backing through a call
		// result: the per-parameter fact cannot attribute the value's
		// provenance, so the tracked names break fail-closed - the
		// demonstrated fault licensing the call-rooted break.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc id(s []handler) []handler { return s }\n\nfunc sink(q []handler) {\n\tc := &counter{}\n\tq[0] = c.Next\n}\n\nfunc gen(s []handler) []handler {\n\tsink(id(s))\n\treturn s\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade - a call-rooted tracked argument was invisible", verdict)
		}
	})
	t.Run("reach-free derived arguments stay admissible", func(t *testing.T) {
		t.Parallel()
		// append onto a fresh base, an audited clone, and a literal of
		// copied function values each hand the callee fresh backing
		// whose elements copy - no write path into rows exists, and
		// the classification gates on the value's own type, never the
		// chain root's alone (M3 of the chunk-83 review).
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nimport \"slices\"\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar total int\n\nfunc probe(q []handler) {\n\ttotal += len(q)\n}\n\nfunc genAppend(rows []handler) []handler {\n\tprobe(append([]handler{}, rows...))\n\treturn rows\n}\n\nfunc genClone(rows []handler) []handler {\n\tprobe(slices.Clone(rows))\n\treturn rows\n}\n\nfunc genLit(rows []handler) []handler {\n\tprobe([]handler{rows[0]})\n\treturn rows\n}\n\nvar A = genAppend([]handler{double})\n\nvar B = genClone([]handler{double})\n\nvar C = genLit([]handler{double})\n\nfunc Count() int { return len(A) + len(B) + len(C) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a reach-free derived argument was broken on its chain root", verdict)
		}
	})
	t.Run("relayed parameter chains through the callee's insertion fact", func(t *testing.T) {
		t.Parallel()
		// relay hands its own parameter onward: relay's insertion fact
		// chains through sink2's, and sink2's poison reaches gen over
		// two conditional edges.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc sink2(q []handler) {\n\tc := &counter{}\n\tq[0] = c.Next\n}\n\nfunc relay(q []handler) {\n\tsink2(q)\n}\n\nfunc gen(s []handler) []handler {\n\trelay(s)\n\treturn s\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade - the relayed insertion chain was invisible", verdict)
		}
	})
	t.Run("variadic trailing arguments key the final parameter", func(t *testing.T) {
		t.Parallel()
		// vsink's variadic parameter receives rows through the
		// ellipsis; its insertion poisons, keyed at the final declared
		// index whatever the call-site arity.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc vsink(tag int, qs ...[]handler) {\n\tc := &counter{}\n\tqs[1][0] = c.Next\n}\n\nfunc gen(rows []handler) []handler {\n\tvsink(1, []handler{double}, rows)\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade - the variadic insertion was invisible", verdict)
		}
	})
	t.Run("local-rooted deferral edge survives the judgment memo", func(t *testing.T) {
		t.Parallel()
		// loc is a LOCAL handed to the inserting callee: the deferral
		// edge must fold whether or not the local's freedom was
		// memoized during use resolution (round-2 H1 - the memo
		// short-circuit dropped local-rooted edges).
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc b(q []handler) {\n\tc := &counter{}\n\tq[0] = c.Next\n}\n\nfunc gen() []handler {\n\tloc := []handler{double}\n\tb(loc)\n\treturn loc\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade - a local-rooted deferral edge was dropped by the memo", verdict)
		}
	})
	t.Run("param-sourced local carries the deferral to the return", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc b(q []handler) {\n\tc := &counter{}\n\tq[0] = c.Next\n}\n\nfunc gen(rows []handler) []handler {\n\tloc := rows\n\tb(loc)\n\treturn loc\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade - a param-sourced local dropped the deferral", verdict)
		}
	})
	t.Run("held copy carries the deferral to its origin", func(t *testing.T) {
		t.Parallel()
		// x copies the header struct, but x.rows shares rows' backing:
		// the callee's insertion through the copy lands in the origin
		// (round-2 H2 - the use maps crossed alias pairs only).
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype holder struct{ rows []handler }\n\nfunc mut(x holder) {\n\tc := &counter{}\n\tx.rows[0] = c.Next\n}\n\nfunc gen(rows []handler) []handler {\n\thh := holder{rows: rows}\n\tx := hh\n\tmut(x)\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade - a held copy hid the insertion from its origin", verdict)
		}
	})
	t.Run("held copy carries the poison to its origin", func(t *testing.T) {
		t.Parallel()
		// The same shape through the poison route: an unjudgeable
		// argument beside the copy poisons the origin's storage too.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype holder struct{ rows []handler }\n\nfunc put(x holder, h handler) {\n\tx.rows[0] = h\n}\n\nfunc gen(rows []handler) []handler {\n\thh := holder{rows: rows}\n\tx := hh\n\tc := &counter{}\n\tput(x, c.Next)\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade - a held copy hid the poison from its origin", verdict)
		}
	})
	t.Run("element read of a judged map derives", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) map[string]handler {\n\tm := map[string]handler{\"a\": h}\n\tv := m[\"a\"]\n\treturn map[string]handler{\"d\": v}\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an element read of a judged map refused the derivation", verdict)
		}
	})
	t.Run("index read of a judged slice derives in return position", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) map[string]handler {\n\ts := []handler{h}\n\treturn map[string]handler{\"d\": s[0]}\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a return-position slice read refused the derivation", verdict)
		}
	})
	t.Run("comma-ok map read derives", func(t *testing.T) {
		t.Parallel()
		// The registry-constructor group shape: comma-ok read of a
		// pointer element, zero-miss fill, field write, field read.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype box struct{ f handler }\n\nfunc gen(h handler) map[string]handler {\n\tm := map[string]*box{}\n\tb, ok := m[\"k\"]\n\tif !ok {\n\t\tb = &box{}\n\t\tm[\"k\"] = b\n\t}\n\tb.f = h\n\treturn map[string]handler{\"d\": b.f}\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the comma-ok read chain refused the derivation", verdict)
		}
	})
	t.Run("index read of a judged array derives", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) map[string]handler {\n\ta := [1]handler{h}\n\treturn map[string]handler{\"d\": a[0]}\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an array index read refused the derivation", verdict)
		}
	})
	t.Run("index read through a judged array pointer derives", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) map[string]handler {\n\ta := &[1]handler{h}\n\treturn map[string]handler{\"d\": a[0]}\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an array-pointer index read refused the derivation", verdict)
		}
	})
	t.Run("poisoned store into a cyclic chain keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The cycle admits only recirculation; the external poison
		// entering through the store refuses every member.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype box struct{ f handler }\n\nfunc gen(h handler) map[string]handler {\n\tm := map[string]*box{}\n\tb, ok := m[\"k\"]\n\tif !ok {\n\t\tb = &box{}\n\t\tm[\"k\"] = b\n\t}\n\tc := &counter{}\n\tb.f = c.Next\n\treturn map[string]handler{\"d\": b.f}\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - the cycle admitted an external poison", verdict)
		}
	})
	t.Run("element read of an unjudged container keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) map[string]handler {\n\tc := &counter{}\n\tm := map[string]handler{\"a\": c.Next}\n\tv := m[\"a\"]\n\treturn map[string]handler{\"d\": v}\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an unjudged container's element read judged", verdict)
		}
	})
	t.Run("cloned judged rows derive", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nimport \"slices\"\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) []handler {\n\treturn slices.Clone([]handler{h})\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - slices.Clone of judged rows refused", verdict)
		}
	})
	t.Run("cloned judged map derives", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nimport \"maps\"\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) map[string]handler {\n\treturn maps.Clone(map[string]handler{\"d\": h})\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - maps.Clone of a judged map refused", verdict)
		}
	})
	t.Run("concatenated judged slices derive", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nimport \"slices\"\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) []handler {\n\treturn slices.Concat([]handler{h}, []handler{h})\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - slices.Concat of judged slices refused", verdict)
		}
	})
	t.Run("explicitly instantiated clone derives", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nimport \"slices\"\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) []handler {\n\treturn slices.Clone[[]handler]([]handler{h})\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the instantiated clone spelling refused", verdict)
		}
	})
	t.Run("dot-imported clone derives", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nimport . \"slices\"\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) []handler {\n\treturn Clone([]handler{h})\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the dot-imported clone spelling refused", verdict)
		}
	})
	t.Run("clone of an unjudged slice keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nimport \"slices\"\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) []handler {\n\tc := &counter{}\n\treturn slices.Clone([]handler{c.Next})\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a clone of unjudged rows judged", verdict)
		}
	})
	t.Run("unaudited standard callee keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The audited set is closed: a value-plane-pure helper
		// outside it still refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nimport \"slices\"\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(h handler) []handler {\n\treturn slices.Insert([]handler{h}, 0, h)\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an unaudited standard callee judged", verdict)
		}
	})
	t.Run("write through a cloned slice keeps the poison", func(t *testing.T) {
		t.Parallel()
		// Clone copies the elements; reach-bearing elements still
		// alias, and the bind link carries the store back.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nimport \"slices\"\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype catalog struct{ current handler }\n\nfunc gen(h handler) []*catalog {\n\ts := []*catalog{{current: h}}\n\tx := slices.Clone(s)\n\tc := &counter{}\n\tx[0].current = c.Next\n\treturn s\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a cloned slice's element aliasing was dropped", verdict)
		}
	})
	t.Run("registry accumulation constructor derives", func(t *testing.T) {
		t.Parallel()
		// The field's registry shape end-to-end: range over param
		// rows, comma-ok group fill, append into a fresh pointee's
		// field, slot stores into fresh maps, returned aggregate.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype payload struct{ hs []handler }\n\ntype row struct {\n\tkey string\n\tp   payload\n}\n\ntype group struct{ pays []payload }\n\nfunc gen(rows ...row) map[string][]handler {\n\tgroups := map[string]*group{}\n\tvar order []string\n\tfor _, r := range rows {\n\t\tg, ok := groups[r.key]\n\t\tif !ok {\n\t\t\tg = &group{}\n\t\t\tgroups[r.key] = g\n\t\t\torder = append(order, r.key)\n\t\t}\n\t\tg.pays = append(g.pays, r.p)\n\t}\n\tout := map[string][]handler{}\n\tfor _, k := range order {\n\t\tg := groups[k]\n\t\tfor _, pl := range g.pays {\n\t\t\tout[k] = pl.hs\n\t\t}\n\t}\n\treturn out\n}\n\nvar Registry = gen(row{key: \"d\", p: payload{hs: []handler{double}}})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the registry accumulation constructor refused", verdict)
		}
	})
	t.Run("registry accumulation of an unjudged element keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype group struct{ fns []handler }\n\nfunc gen(h handler) map[string][]handler {\n\tgroups := map[string]*group{}\n\tg := &group{}\n\tgroups[\"d\"] = g\n\tc := &counter{}\n\tg.fns = append(g.fns, c.Next)\n\tout := map[string][]handler{}\n\tout[\"d\"] = g.fns\n\treturn out\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an unjudged accumulation element judged", verdict)
		}
	})
	t.Run("held-copy slot store stays local to the holder", func(t *testing.T) {
		t.Parallel()
		// A struct copy read out of a parameter takes slot writes
		// without breaking the caller's assumption.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype row struct {\n\tkey string\n\tfn  handler\n}\n\nfunc gen(rows []row, h handler) map[string]handler {\n\tr := rows[0]\n\tr.fn = h\n\treturn map[string]handler{r.key: r.fn}\n}\n\nvar Registry = gen([]row{{key: \"d\", fn: double}}, double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a slot store into a held copy fired the caller break", verdict)
		}
	})
	t.Run("dereference crossing below a held copy keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The copy's interior pointer reaches the caller's backing; a
		// write crossing it is a write into the caller's storage.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype cell struct{ fn handler }\n\ntype row struct {\n\tkey  string\n\tcell *cell\n}\n\nfunc gen(rows []row, h handler) map[string]handler {\n\tr := rows[0]\n\tr.cell.fn = h\n\treturn map[string]handler{r.key: rows[0].cell.fn}\n}\n\nvar Registry = gen([]row{{key: \"d\", cell: &cell{fn: double}}}, double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a dereference crossing below a held copy stayed judged", verdict)
		}
	})
	t.Run("non-final index write keeps the poison", func(t *testing.T) {
		t.Parallel()
		// m[k][i] writes through the slot's stored header - the write
		// lands in foreign backing even on a fresh root.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(rows []handler, h handler) []handler {\n\tm := map[string][]handler{}\n\tm[\"a\"] = rows\n\tm[\"a\"][0] = h\n\treturn rows\n}\n\nvar Registry = gen([]handler{double}, double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a non-final index write through a stored parameter header stayed judged", verdict)
		}
	})
	t.Run("store through a returned pointer keeps the poison", func(t *testing.T) {
		t.Parallel()
		// Callee-returned storage is not provably body-owned; a write
		// through it may land anywhere - fail-closed break.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype box struct{ f handler }\n\nfunc fresh() *box { return &box{} }\n\nfunc gen(h handler) map[string]handler {\n\tq := fresh()\n\tq.f = h\n\treturn map[string]handler{\"d\": q.f}\n}\n\nvar Registry = gen(double)\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a store through callee-returned storage stayed judged", verdict)
		}
	})
	t.Run("held copy embedded in a fresh literal keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The literal is body-owned but the embedded copy's interior
		// headers are not: the index write must route deep.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype row struct {\n\tkey string\n\ths  []handler\n}\n\ntype wrap struct{ inner row }\n\nfunc gen(rows []row) []row {\n\tr := rows[0]\n\tw := wrap{inner: r}\n\tc := &counter{}\n\tw.inner.hs[0] = c.Next\n\treturn rows\n}\n\nvar Registry = gen([]row{{key: \"d\", hs: []handler{double}}})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a fresh literal laundered a held copy's backing", verdict)
		}
	})
	t.Run("held copy installed by slot store keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype row struct {\n\tkey string\n\ths  []handler\n}\n\ntype box struct{ r row }\n\nfunc gen(rows []row) []row {\n\tb := box{}\n\tb.r = rows[0]\n\tc := &counter{}\n\tb.r.hs[0] = c.Next\n\treturn rows\n}\n\nvar Registry = gen([]row{{key: \"d\", hs: []handler{double}}})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a slot-installed held copy laundered its backing", verdict)
		}
	})
	t.Run("write through a closure-returned carrier keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The callee expression's captures carry backing into the
		// result - the func literal's captured slice links as sharing.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen(rows []handler) []handler {\n\ts := func() []handler { return rows }()\n\tc := &counter{}\n\ts[0] = c.Next\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a closure-returned carrier's write went unlinked", verdict)
		}
	})
	t.Run("write through a value-receiver method result keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype wrap struct{ hs []handler }\n\nfunc (w wrap) get() []handler { return w.hs }\n\nfunc gen(rows []handler) []handler {\n\tw := wrap{hs: rows}\n\ts := w.get()\n\tc := &counter{}\n\ts[0] = c.Next\n\treturn rows\n}\n\nvar Registry = gen([]handler{double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a value-receiver result's write went unlinked", verdict)
		}
	})
	t.Run("converted method value in return keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc gen() []handler {\n\tc := &counter{}\n\treturn []handler{handler(c.Next)}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a converted method value rode the conversion derivation", verdict)
		}
	})
	t.Run("instantiated function reference derives", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nfunc ident[T any](v T) T { return v }\n\nfunc gen() []func(int) int {\n\treturn []func(int) int{ident[int]}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an instantiated named-function reference refused the derivation", verdict)
		}
	})
	t.Run("element read of a package carrier in return keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar pool = []handler{double}\n\nfunc gen() []handler {\n\treturn []handler{pool[0]}\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - an element read of a package carrier rode the derivation", verdict)
		}
	})
	t.Run("declared multi-value bind from a judged call derives", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc validate(in []handler) ([]handler, error) {\n\treturn in, nil\n}\n\nfunc gen() []handler {\n\tvar built, initErr = validate([]handler{double})\n\tif initErr != nil {\n\t\tpanic(initErr)\n\t}\n\treturn built\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a declared multi-value bind refused the shared judged source", verdict)
		}
	})
	t.Run("written range binding keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The derivation dies at the first write through the binding:
		// the swapped-in method value never rides the proof.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\ntype row struct {\n\tName string\n\tH    handler\n}\n\nfunc gen(rows ...row) []row {\n\tout := make([]row, 0, len(rows))\n\tc := &counter{}\n\tfor _, r := range rows {\n\t\tr.H = c.Next\n\t\tout = append(out, r)\n\t}\n\treturn out\n}\n\nvar Registry = gen(row{Name: \"a\", H: double})\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a written range binding stayed judged", verdict)
		}
	})
	t.Run("append of an unjudged element keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next(n int) int {\n\tc.n += n\n\treturn c.n\n}\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc gen() []handler {\n\tout := []handler{double}\n\tc := &counter{}\n\tout = append(out, c.Next)\n\treturn out\n}\n\nvar Registry = gen()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - an unjudged appended element stayed judged", verdict)
		}
	})
	t.Run("naked-return constructor keeps the poison", func(t *testing.T) {
		t.Parallel()
		// Named results assigned across the body escape the
		// return-expression judgment - a naked return refuses the
		// proof.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc generated() (out []handler) {\n\tout = []handler{double}\n\treturn\n}\n\nvar Registry = generated()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a naked-return constructor proved environment-free", verdict)
		}
	})
	t.Run("returned closure handing its capture to a retaining function keeps the poison", func(t *testing.T) {
		t.Parallel()
		// The literal's parameter want resolves against the declaring
		// package's facts - a callee that retains its parameter never
		// proves leak-free, so the constructor refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar kept [][]string\n\nfunc keep(s []string) bool {\n\tkept = append(kept, s)\n\treturn true\n}\n\nfunc nearPolicy(legacy []string) func(got []string) bool {\n\treturn func(got []string) bool { return keep(legacy) }\n}\n\nvar defaultCols = []string{\"a\"}\n\ntype class struct {\n\tMatch func(got []string) bool\n\tCols  []string\n}\n\nvar Registry = []class{{Match: nearPolicy(defaultCols), Cols: defaultCols}}\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a retained capture proved leak-free", verdict)
		}
	})
	t.Run("constructor forwarding a function-variable call keeps the poison", func(t *testing.T) {
		t.Parallel()
		// A multi-value forward of a non-plain call must not slip the
		// judgment through its tuple type - the callee is unknown, so
		// the proof refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nvar mk = func() ([]handler, error) {\n\treturn []handler{double}, nil\n}\n\nfunc generated() ([]handler, error) {\n\treturn mk()\n}\n\nvar Registry, initErr = generated()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a tuple forward of an unknown callee proved environment-free", verdict)
		}
	})
	t.Run("tuple argument from a function-variable call keeps the poison", func(t *testing.T) {
		t.Parallel()
		// A multi-value spread argument rides a tuple type the
		// signature walk never descends - the judgment must fall to
		// the call arm, whose unknown callee refuses, and never admit
		// the tuple by type.
		files := map[string]string{
			"go.mod":       goMod,
			"lib/lib.go":   "package lib\n\ntype Rule func(n int) bool\n\ntype Row struct {\n\tName string\n\tR    Rule\n}\n\nfunc Take(r Row, err error) []Row {\n\treturn []Row{r}\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/lib\"\n\nfunc positive(n int) bool { return n > 0 }\n\nvar mk = func() (lib.Row, error) {\n\treturn lib.Row{Name: \"a\", R: positive}, nil\n}\n\nfunc generated() []lib.Row {\n\treturn lib.Take(mk())\n}\n\nvar Registry = generated()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a tuple spread from an unknown callee proved environment-free", verdict)
		}
	})
	t.Run("constructor called through a function variable keeps the poison", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype handler func(n int) int\n\nfunc double(n int) int { return 2 * n }\n\nfunc generated() []handler { return []handler{double} }\n\nvar mk = generated\n\nvar Registry = mk()\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Count"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Registry - a function-variable call earned the constructor deferral", verdict)
		}
	})
	t.Run("bound method value registration refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype counter struct{ n int }\n\nfunc (c *counter) Next() int {\n\tc.n++\n\treturn c.n\n}\n\nvar Hooks []func() int\n\nfunc init() {\n\tc := &counter{}\n\tHooks = []func() int{c.Next}\n}\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks registers function values outside the environment-free audit") {
			t.Fatalf("verdict = %+v, want the environment-audit downgrade naming reg.Hooks - a bound method value carries its receiver as environment", verdict)
		}
	})
	t.Run("method-call-result registration refuses as an opaque source", func(t *testing.T) {
		t.Parallel()
		// The values arrive through a method result the audit cannot
		// see into - only plain named callees earn the
		// return-environment-free deferral, every other call shape
		// stays fail-closed.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype builder struct{ n int }\n\nfunc (b builder) Build() []func() int {\n\treturn []func() int{func() int { return 1 }}\n}\n\nvar seed builder\n\nvar Hooks = seed.Build()\n\nfunc Run() int {\n\ttotal := 0\n\tfor _, f := range Hooks {\n\t\ttotal += f()\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Hooks - a method-call-result registration passed the audit", verdict)
		}
	})
	t.Run("binding argument to a leak-free sibling discharges", func(t *testing.T) {
		t.Parallel()
		// The classifier shape: the loop hands a binding's field to a
		// plain named in-package function; the binding proof defers to
		// that parameter's leak-free fact through the carrier's deferred
		// marks.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc double() int { return 2 }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Build: double}}\n}\n\nfunc equalCols(a, b []string) bool {\n\tif len(a) != len(b) {\n\t\treturn false\n\t}\n\tfor i := range a {\n\t\tif a[i] != b[i] {\n\t\t\treturn false\n\t\t}\n\t}\n\treturn true\n}\n\nfunc Match(header []string) bool {\n\tfor _, e := range Registry {\n\t\tif equalCols(header, e.Cols) {\n\t\t\treturn true\n\t\t}\n\t}\n\treturn false\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool { return reg.Match([]string{\"a\"}) }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a binding argument to a leak-free sibling refused the deferral", verdict)
		}
	})
	t.Run("binding argument to a retaining sibling refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nvar stash [][]string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc keep(cols []string) bool {\n\tstash = append(stash, cols)\n\treturn true\n}\n\nfunc Match() bool {\n\tfor _, e := range Registry {\n\t\tif keep(e.Cols) {\n\t\t\treturn true\n\t\t}\n\t}\n\treturn false\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool { return reg.Match() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a retaining sibling resolved the deferral", verdict)
		}
	})
	t.Run("binding argument to a foreign leak-free parameter discharges", func(t *testing.T) {
		t.Parallel()
		// The deferred marks resolve cross-package at composition.
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nfunc Width(cols []string) int { return len(cols) }\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += val.Width(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a foreign leak-free parameter refused the cross-package deferral", verdict)
		}
	})
	t.Run("binding argument to a foreign retaining parameter refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nvar held [][]string\n\nfunc Keep(cols []string) int {\n\theld = append(held, cols)\n\treturn len(held)\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += val.Keep(e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a foreign retaining parameter resolved the deferral", verdict)
		}
	})
	t.Run("parameter proof chains through a same-package sibling", func(t *testing.T) {
		t.Parallel()
		// The fact-side fixed point: Sum's parameter proves leak-free
		// because its rooted argument goes to width, itself proven - so
		// a carrier passed cross-package into Sum discharges.
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\ntype Entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc Sum(entries []Entry) int {\n\ttotal := 0\n\tfor _, e := range entries {\n\t\ttotal += width(e.Cols)\n\t}\n\treturn total\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []val.Entry\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int { return val.Sum(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the intra-package parameter chain refused the fixed point", verdict)
		}
	})
	t.Run("mutually recursive parameter chain refuses", func(t *testing.T) {
		t.Parallel()
		// Neither parameter proves first - the fixed point is
		// deliberately conservative, and the carrier keeps its escape.
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\ntype Entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nfunc SumA(entries []Entry) int {\n\tif len(entries) == 0 {\n\t\treturn 0\n\t}\n\treturn SumB(entries)\n}\n\nfunc SumB(entries []Entry) int {\n\treturn SumA(entries)\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []val.Entry\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int { return val.SumA(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a mutually recursive chain proved itself", verdict)
		}
	})
	t.Run("cross-package parameter chain resolves past a same-named sibling", func(t *testing.T) {
		t.Parallel()
		// Sum's parameter proof depends on lib.Width's - the
		// conditional edge resolves at composition, and the same-named
		// local sibling never stands in for the foreign key.
		files := map[string]string{
			"go.mod":       goMod,
			"lib/lib.go":   "package lib\n\nfunc Width(cols []string) int { return len(cols) }\n",
			"val/val.go":   "package val\n\nimport \"example.com/xesc/lib\"\n\ntype Entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nfunc Width(cols []string) int { return len(cols) }\n\nfunc Sum(entries []Entry) int {\n\ttotal := 0\n\tfor _, e := range entries {\n\t\ttotal += lib.Width(e.Cols)\n\t}\n\treturn total\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []val.Entry\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int { return val.Sum(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a resolvable cross-package chain kept its escape", verdict)
		}
	})
	t.Run("same-named sibling never stands in for a retaining foreign parameter", func(t *testing.T) {
		t.Parallel()
		// The foreign target retains; the leak-free local decoy shares
		// its name - key discrimination must keep the refusal.
		files := map[string]string{
			"go.mod":       goMod,
			"lib/lib.go":   "package lib\n\nvar sink []string\n\nfunc Width(cols []string) int {\n\tsink = cols\n\treturn len(cols)\n}\n",
			"val/val.go":   "package val\n\nimport \"example.com/xesc/lib\"\n\ntype Entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nfunc Width(cols []string) int { return len(cols) }\n\nfunc Sum(entries []Entry) int {\n\ttotal := 0\n\tfor _, e := range entries {\n\t\ttotal += lib.Width(e.Cols)\n\t}\n\treturn total\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []val.Entry\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Total() int { return val.Sum(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a same-named sibling stood in for the retaining foreign key", verdict)
		}
	})
	t.Run("wrapped goroutine call never defers", func(t *testing.T) {
		t.Parallel()
		// The literal wrap is the same concurrent execution as the
		// direct go statement - both spellings refuse identically.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc Total() int {\n\tfor _, e := range Registry {\n\t\tgo func() { width(e.Cols) }()\n\t}\n\treturn 0\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a goroutine-wrapped call earned the deferral", verdict)
		}
	})
	t.Run("variadic binding arguments clamp to the final parameter", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc joins(sets ...[]string) int {\n\ttotal := 0\n\tfor _, s := range sets {\n\t\ttotal += len(s)\n\t}\n\treturn total\n}\n\nfunc Total() int {\n\ttotal := 0\n\tfor _, e := range Registry {\n\t\ttotal += joins(e.Cols, e.Cols)\n\t}\n\treturn total\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a variadic binding argument missed the parameter clamp", verdict)
		}
	})
	t.Run("go-statement binding argument never defers", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func() int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc Total() int {\n\tfor _, e := range Registry {\n\t\tgo width(e.Cols)\n\t}\n\treturn 0\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a goroutine's binding argument earned the deferral", verdict)
		}
	})
	t.Run("method value bound from the binding refuses", func(t *testing.T) {
		t.Parallel()
		// Binding a method value captures the receiver inside a func
		// value the reach classification cannot see - calling it later
		// writes the shared backing under a would-be-closed verdict.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Scribble() { e.Cols[0] = \"w\" }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Touch() int {\n\tfor _, e := range Registry {\n\t\tf := e.Scribble\n\t\tf()\n\t}\n\treturn len(Registry)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Touch() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Touch"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a bound method value slipped the reach classification", verdict)
		}
	})
	t.Run("receiver fact refuses a method-value self-capture", func(t *testing.T) {
		t.Parallel()
		// The deferred fact itself must refuse: a method binding its own
		// receiver's writing method is not read-only however reach-free
		// the func value looks.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Scribble() { e.Cols[0] = \"w\" }\n\nfunc (e entry) Spelling() string {\n\tf := e.Scribble\n\tf()\n\treturn e.Label\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Spellings() string {\n\tout := \"\"\n\tfor _, e := range Registry {\n\t\tout += e.Spelling()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Spellings() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Spellings"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a self-capturing method proved read-only", verdict)
		}
	})
	t.Run("returned method value refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Scribble() { e.Cols[0] = \"w\" }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc grab() func() {\n\tfor _, e := range Registry {\n\t\treturn e.Scribble\n\t}\n\treturn nil\n}\n\nfunc Run() int {\n\tif f := grab(); f != nil {\n\t\tf()\n\t}\n\treturn len(Registry)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Run"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a returned method value slipped the disposition", verdict)
		}
	})
	t.Run("method value argument refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Scribble() { e.Cols[0] = \"w\" }\n\nfunc invoke(f func()) { f() }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Touch() int {\n\tfor _, e := range Registry {\n\t\tinvoke(e.Scribble)\n\t}\n\treturn len(Registry)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Touch() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Touch"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a method-value argument slipped the consume", verdict)
		}
	})
	t.Run("method value returned by a sibling method refuses", func(t *testing.T) {
		t.Parallel()
		// Give hands its receiver out inside a func value the caller's
		// result check cannot see - the receiver fact must refuse Give,
		// so the binding call's deferral fails.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Scribble() { e.Cols[0] = \"w\" }\n\nfunc (e entry) Give() func() { return e.Scribble }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Touch() int {\n\tfor _, e := range Registry {\n\t\tf := e.Give()\n\t\tf()\n\t}\n\treturn len(Registry)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Touch() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Touch"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a method-value return proved read-only", verdict)
		}
	})
	t.Run("sibling chain into a method-value return refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Scribble() { e.Cols[0] = \"w\" }\n\nfunc (e entry) Give() func() { return e.Scribble }\n\nfunc (e entry) Do() string {\n\tf := e.Give()\n\tf()\n\treturn e.Label\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Names() string {\n\tout := \"\"\n\tfor _, e := range Registry {\n\t\tout += e.Do()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Names() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Names"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a sibling chain laundered a method-value return", verdict)
		}
	})
	t.Run("promoted method through concrete embedding defers", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype base struct{ Label string }\n\nfunc (b base) Spelling() string { return b.Label }\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n\tbase\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, base: base{Label: \"x\"}}}\n}\n\nfunc Spellings() string {\n\tout := \"\"\n\tfor _, e := range Registry {\n\t\tout += e.Spelling()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Spellings() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a promoted read-only method refused through the embedded type's key", verdict)
		}
	})
	t.Run("read-only method call through the binding defers", func(t *testing.T) {
		t.Parallel()
		// The admissionSpelling shape: a value-receiver method reading
		// string fields, proven receiver-read-only by its declaring
		// package - the binding proof defers through the method-use
		// marks.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tAlt   string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Spelling() string {\n\tif e.Alt != \"\" {\n\t\treturn e.Alt\n\t}\n\treturn e.Label\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Spellings() string {\n\tout := \"\"\n\tfor _, e := range Registry {\n\t\tout += e.Spelling()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Spellings() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a proven read-only method call refused the binding proof", verdict)
		}
	})
	t.Run("composite-literal return through a reach-bearing step defers", func(t *testing.T) {
		t.Parallel()
		// The threshold Rule() shape: the returned literal wraps a
		// string read whose intermediate field type carries a pointer -
		// the read produces only the leaf copy, so the receiver proof
		// holds and the method use defers.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype id struct{ v string }\n\ntype inner struct {\n\trule string\n\tp    *int\n}\n\ntype entry struct {\n\tCols  []string\n\tIn    inner\n\tBuild func(n int) int\n}\n\nfunc (e entry) Rule() id { return id{v: e.In.rule} }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, In: inner{rule: \"r\"}}}\n}\n\nfunc Rules() string {\n\tout := \"\"\n\tfor _, e := range Registry {\n\t\tout += e.Rule().v\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Rules() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a composite-literal return over a reach-bearing step refused the receiver proof", verdict)
		}
	})
	t.Run("chain method call converting its receiver defers", func(t *testing.T) {
		t.Parallel()
		// The proposition String() shape: a defined-string field's
		// method converts its whole receiver to a reach-free type - a
		// value copy that cannot write back.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype name string\n\nfunc (n name) Spelling() string { return string(n) }\n\ntype entry struct {\n\tCols  []string\n\tN     name\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, N: \"x\"}}\n}\n\nfunc Spellings() string {\n\tout := \"\"\n\tfor _, e := range Registry {\n\t\tout += e.N.Spelling()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Spellings() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a reach-free receiver conversion refused the receiver proof", verdict)
		}
	})
	t.Run("aliasing conversion of receiver state keeps the refusal", func(t *testing.T) {
		t.Parallel()
		// The conversion admission is result-type-judged: converting a
		// receiver slice to a named slice type aliases the backing, so
		// the method never proves and the want refuses fail-closed.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype colsT []string\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nfunc (e entry) AliasConvert() int {\n\tc := colsT(e.Cols)\n\treturn len(c)\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Convert() int {\n\tn := 0\n\tfor _, e := range Registry {\n\t\tn += e.AliasConvert()\n\t}\n\treturn n\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Convert() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Convert"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry is mutated") {
			t.Fatalf("verdict = %+v, want the mutation downgrade naming reg.Registry - an aliasing conversion proved read-only", verdict)
		}
	})
	t.Run("method value conversion keeps the refusal", func(t *testing.T) {
		t.Parallel()
		// A bound method value converted to a func type has a
		// reach-free result type yet carries the captured receiver -
		// invoking it executes receiver writes. The conversion
		// admission must gate on the operand shape, not the result
		// type alone.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype fn func()\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Mut() { e.Build = nil }\n\nfunc (e entry) Sneak() int {\n\tf := fn(e.Mut)\n\tf()\n\treturn len(e.Cols)\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Sneaks() int {\n\tn := 0\n\tfor _, e := range Registry {\n\t\tn += e.Sneak()\n\t}\n\treturn n\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Sneaks() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Sneaks"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry is mutated") {
			t.Fatalf("verdict = %+v, want the mutation downgrade naming reg.Registry - a converted method value proved read-only", verdict)
		}
	})
	t.Run("returned method value conversion keeps the refusal", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype fn func()\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Mut() { e.Cols[0] = \"x\" }\n\nfunc (e entry) Handout() fn { return fn(e.Mut) }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Sneaks() int {\n\tfor _, e := range Registry {\n\t\te.Handout()()\n\t}\n\treturn len(Registry)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Sneaks() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Sneaks"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a returned converted method value proved read-only", verdict)
		}
	})
	t.Run("chain method value argument keeps the refusal", func(t *testing.T) {
		t.Parallel()
		// A method value on a chain step must refuse at the selector
		// arm itself: with the reach-free inner step consumed first,
		// the ident backstop never fires, so a deferred refusal would
		// launder the capture.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype name string\n\nfunc (n name) Spelling() string { return string(n) }\n\ntype entry struct {\n\tCols  []string\n\tN     name\n\tBuild func(n int) int\n}\n\nfunc sink(f func() string) string { return f() }\n\nfunc (e entry) Hand() string { return sink(e.N.Spelling) }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, N: \"x\"}}\n}\n\nfunc Hands() string {\n\tout := \"\"\n\tfor _, e := range Registry {\n\t\tout += e.Hand()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Hands() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Hands"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry is mutated") {
			t.Fatalf("verdict = %+v, want the mutation downgrade naming reg.Registry - a chain method value argument proved read-only", verdict)
		}
	})
	t.Run("package-level alias sink keeps the refusal", func(t *testing.T) {
		t.Parallel()
		// The tracked-binding discipline covers only sinks that die
		// with the body: a reach-bearing bind to a package variable
		// outlives the proof, and the sink variable itself may fall
		// outside the priced carrier universe - the alias write then
		// mutates the carrier's backing unpriced.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar stash []string\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Alias() int {\n\tstash = e.Cols\n\treturn len(e.Cols)\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Reads() string {\n\ts := \"\"\n\tfor _, e := range Registry {\n\t\t_ = e.Alias()\n\t\ts += e.Cols[0]\n\t}\n\treturn s\n}\n\nfunc Write() { stash[0] = \"w\" }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Reads() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry is mutated") {
			t.Fatalf("verdict = %+v, want the mutation downgrade naming reg.Registry - a package-level alias sink proved read-only", verdict)
		}
	})
	t.Run("range-assigned package variable sink keeps the refusal", func(t *testing.T) {
		t.Parallel()
		// The assign-form range bind is the same outliving sink as an
		// assignment: the bound element aliases receiver state past
		// the body when the target is a reach-bearing package
		// variable.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar row []string\n\ntype entry struct {\n\tRows  [][]string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Scan() int {\n\tn := 0\n\tfor _, row = range e.Rows {\n\t\tn += len(row)\n\t}\n\treturn n\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Rows: [][]string{{\"a\"}}}}\n}\n\nfunc Scans() int {\n\tn := 0\n\tfor _, e := range Registry {\n\t\tn += e.Scan()\n\t}\n\treturn n\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Scans() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Scans"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry is mutated") {
			t.Fatalf("verdict = %+v, want the mutation downgrade naming reg.Registry - a range-assigned package sink proved read-only", verdict)
		}
	})
	t.Run("sibling-fed package sink keeps the refusal", func(t *testing.T) {
		t.Parallel()
		// A leaky sibling call bound to an outliving target must not
		// be governed into a consume: the alias arrives through the
		// sibling's results and outlives the body all the same.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar stash []string\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Sib() []string { return e.Cols }\n\nfunc (e entry) Alias() int {\n\tstash = e.Sib()\n\treturn len(e.Cols)\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Reads() string {\n\ts := \"\"\n\tfor _, e := range Registry {\n\t\t_ = e.Alias()\n\t\ts += e.Cols[0]\n\t}\n\treturn s\n}\n\nfunc Write() { stash[0] = \"w\" }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Reads() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry is mutated") {
			t.Fatalf("verdict = %+v, want the mutation downgrade naming reg.Registry - a sibling-fed package sink proved read-only", verdict)
		}
	})
	t.Run("dot-imported package sink keeps the refusal", func(t *testing.T) {
		t.Parallel()
		// A dot-imported variable is the same outliving sink under a
		// bare name; the scope test must follow the object's own
		// package.
		files := map[string]string{
			"go.mod":       goMod,
			"hold/hold.go": "package hold\n\nvar Stash []string\n",
			"reg/reg.go":   "package reg\n\nimport . \"example.com/xesc/hold\"\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Alias() int {\n\tStash = e.Cols\n\treturn len(e.Cols)\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Reads() string {\n\ts := \"\"\n\tfor _, e := range Registry {\n\t\t_ = e.Alias()\n\t\ts += e.Cols[0]\n\t}\n\treturn s\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Reads() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry is mutated") {
			t.Fatalf("verdict = %+v, want the mutation downgrade naming reg.Registry - a dot-imported sink proved read-only", verdict)
		}
	})
	t.Run("closure handout of a tainted local keeps the refusal", func(t *testing.T) {
		t.Parallel()
		// A return inside a nested literal is an escape position: the
		// literal outlives the body carrying the captured alias, and
		// the caller's result judgment sees only a signature.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Handout() func() []string {\n\ts := e.Cols\n\treturn func() []string { return s }\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}}}\n}\n\nfunc Hands() int {\n\tn := 0\n\tfor _, e := range Registry {\n\t\tn += len(e.Handout()())\n\t}\n\treturn n\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Hands() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Hands"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a closure handout of a tainted local slipped every gate", verdict)
		}
	})
	t.Run("reach-free store to a package variable stays proven", func(t *testing.T) {
		t.Parallel()
		// The outliving-sink refusal is reach-judged: a string copy
		// stored to a package variable cannot write back into the
		// receiver, so the proof holds.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\nvar seen string\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Note() int {\n\tseen = e.Label\n\treturn len(e.Label)\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Notes() int {\n\tn := 0\n\tfor _, e := range Registry {\n\t\tn += e.Note()\n\t}\n\treturn n\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Notes() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a reach-free store to a package variable refused the receiver proof", verdict)
		}
	})
	t.Run("reach-bearing chain leaf keeps the refusal", func(t *testing.T) {
		t.Parallel()
		// The outermost-node judgment still refuses when the produced
		// value itself hands out reach: a pointer leaf handed to a
		// callee is an escape however deep the chain.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype inner struct {\n\trule string\n\tp    *int\n}\n\ntype entry struct {\n\tCols  []string\n\tIn    inner\n\tBuild func(n int) int\n}\n\nfunc sink(p *int) int { return *p }\n\nfunc (e entry) Leaf() int { return sink(e.In.p) }\n\nvar Registry []entry\n\nfunc init() {\n\tn := 1\n\tRegistry = []entry{{Cols: []string{\"a\"}, In: inner{rule: \"r\", p: &n}}}\n}\n\nfunc Leaves() int {\n\tn := 0\n\tfor _, e := range Registry {\n\t\tn += e.Leaf()\n\t}\n\treturn n\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Leaves() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Leaves"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry is mutated") {
			t.Fatalf("verdict = %+v, want the mutation downgrade naming reg.Registry - a reach-bearing chain leaf proved read-only", verdict)
		}
	})
	t.Run("writing method call through the binding refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e *entry) Bump() {\n\te.Cols = append(e.Cols, \"y\")\n}\n\nvar Registry []*entry\n\nfunc init() {\n\tRegistry = []*entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Grow() int {\n\tfor _, e := range Registry {\n\t\te.Bump()\n\t}\n\treturn len(Registry)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Grow() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Grow"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry is mutated") {
			t.Fatalf("verdict = %+v, want the mutation downgrade naming reg.Registry - a writing method resolved the deferral", verdict)
		}
	})
	t.Run("alias-handing method results refuse the deferral", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Columns() []string { return e.Cols }\n\nvar Registry []entry\n\nvar stash []string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Leak() {\n\tfor _, e := range Registry {\n\t\tstash = e.Columns()\n\t}\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() { reg.Leak() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Leak"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - alias-handing method results earned the deferral", verdict)
		}
	})
	t.Run("cross-package read-only method resolves at composition", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\ntype Entry struct {\n\tCols  []string\n\tLabel string\n\tAlt   string\n\tBuild func(n int) int\n}\n\nfunc (e Entry) Spelling() string {\n\tif e.Alt != \"\" {\n\t\treturn e.Alt\n\t}\n\treturn e.Label\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []val.Entry\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Spellings() string {\n\tout := \"\"\n\tfor _, e := range Registry {\n\t\tout += e.Spelling()\n\t}\n\treturn out\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() string { return reg.Spellings() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a foreign read-only method refused the cross-package method marks", verdict)
		}
	})
	t.Run("fact-time parameter proof chains through a local read-only method", func(t *testing.T) {
		t.Parallel()
		// Sum's parameter proof needs entry.Spelling read-only - the
		// same-package receiver fixed point supplies it, so a carrier
		// passed cross-package into Sum discharges.
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\ntype Entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e Entry) Spelling() string { return e.Label }\n\nfunc Sum(entries []Entry) int {\n\ttotal := 0\n\tfor _, e := range entries {\n\t\ttotal += len(e.Spelling())\n\t}\n\treturn total\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []val.Entry\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Total() int { return val.Sum(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the fact-time method chain refused the fixed point", verdict)
		}
	})
	t.Run("parameter chain through a writing method refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\ntype Entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e *Entry) Bump() { e.Cols = append(e.Cols, \"y\") }\n\nfunc Sum(entries []*Entry) int {\n\tfor _, e := range entries {\n\t\te.Bump()\n\t}\n\treturn len(entries)\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []*val.Entry\n\nfunc init() {\n\tRegistry = []*val.Entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Total() int { return val.Sum(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a writing method proved the parameter chain", verdict)
		}
	})
	t.Run("cross-package method want stays unproven at fact time", func(t *testing.T) {
		t.Parallel()
		// Sum's parameter proof would need a foreign method - a
		// same-named local read-only method must never satisfy it.
		files := map[string]string{
			"go.mod":       goMod,
			"lib/lib.go":   "package lib\n\ntype Meta struct {\n\tCols []string\n\tName string\n}\n\nfunc (m *Meta) Spelling() string {\n\tm.Cols = append(m.Cols, \"seen\")\n\treturn m.Name\n}\n",
			"val/val.go":   "package val\n\nimport \"example.com/xesc/lib\"\n\ntype Entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n\tRef   *lib.Meta\n}\n\ntype Meta struct{ n string }\n\nfunc (m Meta) Spelling() string { return m.n }\n\nfunc Sum(entries []Entry) int {\n\ttotal := 0\n\tfor _, e := range entries {\n\t\ttotal += len(e.Ref.Spelling())\n\t}\n\treturn total\n}\n",
			"reg/reg.go":   "package reg\n\nimport (\n\t\"example.com/xesc/lib\"\n\t\"example.com/xesc/val\"\n)\n\nvar Registry []val.Entry\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}, Label: \"x\", Ref: &lib.Meta{Name: \"m\"}}}\n}\n\nfunc Total() int { return val.Sum(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a foreign method want resolved against a local namesake", verdict)
		}
	})
	t.Run("go-wrapped method call never defers", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nfunc (e entry) Spelling() string { return e.Label }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Spellings() int {\n\tfor _, e := range Registry {\n\t\tgo func() { _ = e.Spelling() }()\n\t}\n\treturn 0\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Spellings() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Spellings"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a goroutine-wrapped method call earned the deferral", verdict)
		}
	})
	t.Run("returned binding discharges when every caller contains it", func(t *testing.T) {
		t.Parallel()
		// The lookup shape: an unexported function ranges the registry
		// and returns the matching entry; the caller binds it, reads a
		// no-reach field, and calls the func field - all contained.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc double(n int) int { return n * 2 }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\", Build: double}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Describe(label string) int {\n\tclass, ok := lookup(label)\n\tif !ok {\n\t\treturn 0\n\t}\n\treturn class.Build(len(class.Label))\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Describe(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a contained returned binding refused the disposition", verdict)
		}
	})
	t.Run("returned binding retained by a caller refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar stash []string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Keep(label string) {\n\tclass, _ := lookup(label)\n\tstash = class.Cols\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() { reg.Keep(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a retained returned binding passed the disposition", verdict)
		}
	})
	t.Run("exported returner refuses the disposition", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []Entry\n\nfunc init() {\n\tRegistry = []Entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc Lookup(label string) (Entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn Entry{}, false\n}\n\nfunc Count() int { return len(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - an exported returner earned the package-local disposition", verdict)
		}
	})
	t.Run("value reference of the returner refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Finder() func(string) (entry, bool) {\n\treturn lookup\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool {\n\t_, ok := reg.Finder()(\"x\")\n\treturn ok\n}\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a value reference of the returner passed the disposition", verdict)
		}
	})
	t.Run("argument-position returner result refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\nfunc Note(v any) {}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc first() entry {\n\tfor _, e := range Registry {\n\t\treturn e\n\t}\n\treturn entry{}\n}\n\nfunc Report() { val.Note(first()) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() { reg.Report() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - an argument-position result passed the disposition", verdict)
		}
	})
	t.Run("returned binding propagates through a contained chain", func(t *testing.T) {
		t.Parallel()
		// find re-returns lookup's binding; find's own caller contains -
		// the disposition chains through the package-local fixed point.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc double(n int) int { return n * 2 }\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\", Build: double}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc find(label string) (entry, bool) {\n\tclass, ok := lookup(label)\n\treturn class, ok\n}\n\nfunc Describe(label string) int {\n\tclass, ok := find(label)\n\tif !ok {\n\t\treturn 0\n\t}\n\treturn class.Build(1)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Describe(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a contained propagation chain refused the disposition", verdict)
		}
	})
	t.Run("propagation through an exported function refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype Entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []Entry\n\nfunc init() {\n\tRegistry = []Entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (Entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn Entry{}, false\n}\n\nfunc Find(label string) (Entry, bool) {\n\tclass, ok := lookup(label)\n\treturn class, ok\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool {\n\t_, ok := reg.Find(\"x\")\n\treturn ok\n}\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - propagation through an exported function passed", verdict)
		}
	})
	t.Run("package-level literal caller is a use site", func(t *testing.T) {
		t.Parallel()
		// The containment scan covers literals stored at package level -
		// a writing use inside one refuses exactly as a function body's
		// would.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nvar Grab = func() {\n\tclass, _ := lookup(\"x\")\n\tclass.Cols[0] = \"z\"\n}\n\nfunc Describe(label string) int {\n\tclass, ok := lookup(label)\n\tif !ok {\n\t\treturn 0\n\t}\n\treturn len(class.Cols)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int {\n\treg.Grab()\n\treturn reg.Describe(\"x\")\n}\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a package-level literal's writing use escaped the containment scan", verdict)
		}
	})
	t.Run("initializer-position returner binding refuses", func(t *testing.T) {
		t.Parallel()
		// A direct initializer-position call binds package variables -
		// an alias-handing result landing anywhere but a blank refuses.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc firstCols() ([]string, bool) {\n\tfor _, e := range Registry {\n\t\treturn e.Cols, true\n\t}\n\treturn nil, false\n}\n\nvar cached, _ = firstCols()\n\nfunc Look() int {\n\tcols, _ := firstCols()\n\treturn len(cols)\n}\n\nfunc Cached() int { return len(cached) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Cached() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Cached"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - an initializer-position alias binding passed containment", verdict)
		}
	})
	t.Run("discarded returner result is contained", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Touch(label string) int {\n\tlookup(label)\n\treturn len(Registry)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Touch(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a discarded returner result refused containment", verdict)
		}
	})
	t.Run("caller-site literal re-return refuses", func(t *testing.T) {
		t.Parallel()
		// The re-return sits inside a nested literal at the caller site:
		// it chains to the literal's unknowable caller, never to the
		// enclosing function's disposition - and the retained reach
		// through the untracked literal binding must keep the escape.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar stash []string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc middle() {\n\tget := func() (entry, bool) { return lookup(\"x\") }\n\tclass, _ := get()\n\tstash = class.Cols\n}\n\nfunc Run() { middle() }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() { reg.Run() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a literal's re-return chained the disposition to the wrong caller", verdict)
		}
	})
	t.Run("method re-return refuses the disposition", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\ntype finder struct{ prefix string }\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc (f finder) find(label string) (entry, bool) {\n\treturn lookup(f.prefix + label)\n}\n\nfunc Probe(label string) bool {\n\t_, ok := finder{}.find(label)\n\treturn ok\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() bool { return reg.Probe(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Probe"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a method's re-return earned the disposition", verdict)
		}
	})
	t.Run("bad containment propagates back through the chain", func(t *testing.T) {
		t.Parallel()
		// find re-returns lookup's binding and find's own caller
		// retains - the failure walks back through the dependency edge
		// and lookup's discharge retracts.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar stash []string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc find(label string) (entry, bool) {\n\tclass, ok := lookup(label)\n\treturn class, ok\n}\n\nfunc Keep(label string) {\n\tclass, _ := find(label)\n\tstash = class.Cols\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() { reg.Keep(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a bad second hop left the first discharged", verdict)
		}
	})
	t.Run("literal return inside the loop never joins the disposition", func(t *testing.T) {
		t.Parallel()
		// An immediately invoked literal returning the binding exits the
		// literal, not the function - its handout is an unknown caller's
		// and the range keeps the strict refusal.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc sneak() []string {\n\tfor _, e := range Registry {\n\t\tgot := func() entry { return e }()\n\t\treturn got.Cols\n\t}\n\treturn nil\n}\n\nfunc Sneak() int {\n\tcols := sneak()\n\treturn len(cols)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return len(reg.Sneak()) }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/reg", Symbol: "Sneak"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Registry - a literal's return joined the disposition", verdict)
		}
	})
	t.Run("returned binding argument defers through the caller", func(t *testing.T) {
		t.Parallel()
		// The caller hands the returned binding's field to a leak-free
		// named function - the caller-site judgment carries the want to
		// the carrier exactly as a range binding's would.
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc width(cols []string) int { return len(cols) }\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Measure(label string) int {\n\tclass, ok := lookup(label)\n\tif !ok {\n\t\treturn 0\n\t}\n\treturn width(class.Cols)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Measure(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a deferred caller-site argument refused the disposition", verdict)
		}
	})
	t.Run("returned binding argument to a retaining callee refuses", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{
			"go.mod":       goMod,
			"reg/reg.go":   "package reg\n\ntype entry struct {\n\tCols  []string\n\tLabel string\n\tBuild func(n int) int\n}\n\nvar Registry []entry\n\nvar held [][]string\n\nfunc init() {\n\tRegistry = []entry{{Cols: []string{\"a\"}, Label: \"x\"}}\n}\n\nfunc keep(cols []string) int {\n\theld = append(held, cols)\n\treturn len(held)\n}\n\nfunc lookup(label string) (entry, bool) {\n\tfor _, e := range Registry {\n\t\tif e.Label == label {\n\t\t\treturn e, true\n\t\t}\n\t}\n\treturn entry{}, false\n}\n\nfunc Measure(label string) int {\n\tclass, ok := lookup(label)\n\tif !ok {\n\t\treturn 0\n\t}\n\treturn keep(class.Cols)\n}\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Measure(\"x\") }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Registry escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Registry - a retaining callee resolved the caller-site deferral", verdict)
		}
	})
	t.Run("cross-package func-field caller proves leak-free", func(t *testing.T) {
		t.Parallel()
		// The fact side of the same arm: a foreign function ranging its
		// parameter and invoking a func field of each binding records the
		// parameter leak-free, so passing a carrier to it discharges.
		files := map[string]string{
			"go.mod":       goMod,
			"val/val.go":   "package val\n\ntype Entry struct {\n\tCols  []string\n\tBuild func(n int) int\n}\n\nfunc Sum(entries []Entry) int {\n\ttotal := 0\n\tfor _, e := range entries {\n\t\ttotal += e.Build(1)\n\t}\n\treturn total\n}\n",
			"reg/reg.go":   "package reg\n\nimport \"example.com/xesc/val\"\n\nvar Registry []val.Entry\n\nfunc double(n int) int { return n * 2 }\n\nfunc init() {\n\tRegistry = []val.Entry{{Cols: []string{\"a\"}, Build: double}}\n}\n\nfunc Total() int { return val.Sum(Registry) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xesc/reg\"\n\nfunc F() int { return reg.Total() }\n",
		}
		dir := writeModuleTree(t, files)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/xesc/user", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a foreign func-field caller refused the leak-free proof", verdict)
		}
	})
}

// A store the composition discharges as init flow must first pass the
// object-closure audit, whichever package's function performs it: a
// graph-proven function rebinding an interface variable to a non-audited
// mutable construction breaks the closure (the discharge of the mutation
// is correct - the ESCAPE must not also discharge), while an audited
// construction through the same shape keeps it
// (REQ-closure-shared-dynamic-state-escape-narrowings).
func TestProvenInitFlowStoresAuditedForObjectClosure(t *testing.T) {
	t.Run("non-audited store through a proven function breaks the closure", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       "module example.com/xop\n\ngo 1.26\n",
			"reg/reg.go":   "package reg\n\nvar Err error\n\nfunc SetErr(e error) { Err = e }\n\nfunc Get() error { return Err }\n",
			"user/user.go": "package user\n\nimport \"example.com/xop/reg\"\n\ntype impl struct{ N int }\n\nfunc (i *impl) Error() string { return \"boom\" }\n\nvar _ = seed()\n\nfunc seed() bool {\n\treg.SetErr(&impl{})\n\treturn true\n}\n\nfunc F() bool { return reg.Get() == nil }\n",
		}
		dir := writeModuleTree(t, files)
		subject := Subject{Package: "example.com/xop/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Err escapes writable") {
			t.Fatalf("verdict = %+v, want the escape downgrade naming reg.Err - a non-audited store through a proven function kept the variable object-closed", verdict)
		}
	})
	t.Run("audited construction through a proven function keeps the closure", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       "module example.com/xop\n\ngo 1.26\n",
			"reg/reg.go":   "package reg\n\nimport \"errors\"\n\nvar Err error\n\nfunc Boot() { Err = errors.New(\"boot\") }\n\nfunc Get() error { return Err }\n",
			"user/user.go": "package user\n\nimport \"example.com/xop/reg\"\n\nvar _ = seed()\n\nfunc seed() bool {\n\treg.Boot()\n\treturn true\n}\n\nfunc F() bool { return reg.Get() == nil }\n",
		}
		dir := writeModuleTree(t, files)
		subject := Subject{Package: "example.com/xop/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - an audited construction through a proven function broke the closure", verdict)
		}
	})
	t.Run("initializer-expression address capture breaks the closure", func(t *testing.T) {
		// The receiving-carrier channel is deliberately absent (the
		// address is discarded): only the capture arm over initializer
		// expressions sees this shape, so the row pins that arm alone -
		// the audit cannot attribute what happens to a captured
		// address, and the spec breaks the closure fail-closed.
		files := map[string]string{
			"go.mod":       "module example.com/xop\n\ngo 1.26\n",
			"reg/reg.go":   "package reg\n\nvar Err error\n\nfunc Get() error { return Err }\n",
			"user/user.go": "package user\n\nimport \"example.com/xop/reg\"\n\nvar _ = &reg.Err\n\nfunc F() bool { return reg.Get() == nil }\n",
		}
		dir := writeModuleTree(t, files)
		subject := Subject{Package: "example.com/xop/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Err") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Err - an initializer-expression capture kept the variable object-closed", verdict)
		}
	})
	t.Run("capture stored through a pointer refuses on the pointer carrier", func(t *testing.T) {
		// The issue's original reproducer: the receiving pointer's own
		// escape channel now refuses it independently of the capture
		// arm - the verdict must stay Unverifiable whichever culprit
		// the composition names.
		files := map[string]string{
			"go.mod":       "module example.com/xop\n\ngo 1.26\n",
			"reg/reg.go":   "package reg\n\nvar Err error\n\nfunc Get() error { return Err }\n",
			"user/user.go": "package user\n\nimport \"example.com/xop/reg\"\n\ntype impl struct{ N int }\n\nfunc (i *impl) Error() string { return \"boom\" }\n\nvar p = &reg.Err\n\nfunc init() { *p = &impl{} }\n\nfunc F() bool { return reg.Get() == nil }\n",
		}
		dir := writeModuleTree(t, files)
		subject := Subject{Package: "example.com/xop/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable {
			t.Fatalf("verdict = %+v, want Unverifiable - a mutable pointer laundered an object-closed sentinel", verdict)
		}
	})
	t.Run("qualified store of an audited construction keeps the closure", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       "module example.com/xop\n\ngo 1.26\n",
			"reg/reg.go":   "package reg\n\nvar Err error\n\nfunc Get() error { return Err }\n",
			"user/user.go": "package user\n\nimport (\n\t\"errors\"\n\n\t\"example.com/xop/reg\"\n)\n\nfunc init() { reg.Err = errors.New(\"configured\") }\n\nfunc F() bool { return reg.Get() == nil }\n",
		}
		dir := writeModuleTree(t, files)
		subject := Subject{Package: "example.com/xop/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a qualified store of an audited construction broke the closure", verdict)
		}
	})
	t.Run("qualified composite store aliases no package name", func(t *testing.T) {
		// reg.Hooks = My unwraps to the reg package name: binding it as
		// a local would make every later reg.X mention in the body a
		// spurious carrier touch - the qualified-store class owns the
		// shape instead.
		files := map[string]string{
			"go.mod":       "module example.com/xop\n\ngo 1.26\n",
			"reg/reg.go":   "package reg\n\nvar Slots []map[string]int\n\nvar Err error\n\nfunc Get() error { return Err }\n",
			"user/user.go": "package user\n\nimport \"example.com/xop/reg\"\n\nvar My = []map[string]int{{\"k\": 1}}\n\nvar probe func() error\n\nfunc init() {\n\treg.Slots = My\n\tprobe = func() error { return reg.Err }\n}\n\nfunc F() bool { return reg.Get() == nil }\n",
		}
		dir := writeModuleTree(t, files)
		subject := Subject{Package: "example.com/xop/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a qualified composite store aliased the package name", verdict)
		}
	})
	t.Run("qualified store of a non-audited value breaks the closure", func(t *testing.T) {
		files := map[string]string{
			"go.mod":       "module example.com/xop\n\ngo 1.26\n",
			"reg/reg.go":   "package reg\n\nvar Err error\n\nfunc Get() error { return Err }\n",
			"user/user.go": "package user\n\nimport \"example.com/xop/reg\"\n\ntype impl struct{ N int }\n\nfunc (i *impl) Error() string { return \"boom\" }\n\nfunc init() { reg.Err = &impl{} }\n\nfunc F() bool { return reg.Get() == nil }\n",
		}
		dir := writeModuleTree(t, files)
		subject := Subject{Package: "example.com/xop/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Err") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Err - a qualified non-audited store kept the variable object-closed", verdict)
		}
	})
}

// The three fail-closed mutation shapes the carrier rules must catch
// (REQ-closure-shared-dynamic-state-mutation-shape): a package-level
// function-literal mutator, a pointer-receiver method VALUE bind, and
// read-aliasing of a map-carried hook set.
func TestSharedDynamicStateFailClosedShapes(t *testing.T) {
	for name, source := range map[string]string{
		"package-level funclit mutator":      "package view\n\nvar Hook = func() {}\n\nvar Rebind = func() { Hook = func() {} }\n\nfunc F() { Rebind() }\n",
		"pointer-receiver method value bind": "package view\n\ntype Registry struct{ hook func() }\n\nfunc (r *Registry) Set(f func()) { r.hook = f }\n\nvar Reg Registry\n\nfunc F() { set := Reg.Set; set(func() {}) }\n",
		"map read-alias":                     "package view\n\nvar Hooks = map[string]func(){}\n\nfunc F() { m := Hooks; m[\"k\"] = func() {} }\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") {
				t.Fatalf("verdict = %+v, want the shared-dynamic-state downgrade", verdict)
			}
		})
	}
}

// Writeless reads of alias carriers and object-closed sentinels are not
// mutation: indexing, iteration, length, and comparison discharge, and
// an errors.New sentinel stays closed through an escape
// (REQ-closure-shared-dynamic-state-mutation-shape).
func TestSharedDynamicStateWritelessReadsDoNotDowngrade(t *testing.T) {
	for name, source := range map[string]string{
		"sentinel escape into errors.Is":              "package view\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"x\")\n\nfunc F() bool { return errors.Is(nil, ErrX) }\n",
		"sentinel comparison":                         "package view\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"x\")\nvar ErrY = errors.New(\"y\")\n\nfunc F() bool { return ErrX == ErrY }\n",
		"registry map read shapes":                    "package view\n\nvar Hooks = map[string]func(){\"k\": func() {}}\n\nfunc F() int {\n\tif len(Hooks) > 0 {\n\t\tHooks[\"k\"]()\n\t}\n\tn := 0\n\tfor range Hooks {\n\t\tn++\n\t}\n\treturn n\n}\n",
		"non-opaque sentinel comparison":              "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error = &impl{}\n\nfunc F() bool { return ErrX == nil }\n",
		"constant-boxed sentinel escape discharges":   "package view\n\ntype code int\n\nfunc (c code) Error() string { return \"code\" }\n\nconst c0 code = 1\n\nvar ErrX error = c0\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(ErrX) != nil }\n",
		"exported initializer-only helper discharges": "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = Declare(\"k\")\n\nfunc Declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
		"slice capacity read":                         "package view\n\nvar Hooks = make([]func(), 0, 4)\n\nfunc F() int { return cap(Hooks) }\n",
		"read-only method call discharges":            "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int { return r.n }\n\nfunc F() int { return R.Count() }\n",
		"rwmutex rlock read discharges":               "package view\n\nimport \"sync\"\n\ntype reg struct {\n\tmu sync.RWMutex\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int {\n\tr.mu.RLock()\n\tdefer r.mu.RUnlock()\n\treturn r.n\n}\n\nfunc F() int { return R.Count() }\n",
		"aliased sync import discharges":              "package view\n\nimport s \"sync\"\n\ntype reg struct {\n\tmu s.Mutex\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int {\n\tr.mu.Lock()\n\tdefer r.mu.Unlock()\n\treturn r.n\n}\n\nfunc F() int { return R.Count() }\n",
		"mutex-guarded read discharges":               "package view\n\nimport \"sync\"\n\ntype reg struct {\n\tmu sync.Mutex\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int {\n\tr.mu.Lock()\n\tdefer r.mu.Unlock()\n\treturn r.n\n}\n\nfunc F() int { return R.Count() }\n",
		"read-only chain discharges":                  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int { return r.raw() }\n\nfunc (r *reg) raw() int { return r.n }\n\nfunc F() int { return R.Count() }\n",
		"generic instantiated result discharges":      "package view\n\ntype reg[A comparable] struct {\n\tfn func()\n\tv  A\n}\n\nvar R = &reg[string]{}\n\nfunc (r *reg[A]) Value() A { return r.v }\n\nfunc F() string { return R.Value() }\n",
		"reflect-type result discharges":              "package view\n\nimport \"reflect\"\n\ntype reg struct {\n\tfn func()\n\tt  reflect.Type\n}\n\nvar R = &reg{t: reflect.TypeOf(0)}\n\nfunc (r *reg) Kind() reflect.Type { return r.t }\n\nfunc F() bool { return R.Kind() != nil }\n",
		"value-typed binding stays untainted":         "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{\"k\": 1}}\n\nfunc (r *reg) Pick() int {\n\tx := r.n\n\tif x > 0 {\n\t\treturn x\n\t}\n\tv, ok := r.m[\"k\"]\n\tif ok {\n\t\treturn v\n\t}\n\treturn 0\n}\n\nfunc F() int { return R.Pick() }\n",
		"pairing discriminates positions":             "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc localMap() map[string]int { return map[string]int{} }\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Sum() int {\n\tm2, m := localMap(), r.inner()\n\tm2[\"k\"] = 1\n\treturn len(m) + len(m2)\n}\n\nfunc F() int { return R.Sum() }\n",
		"governed sibling binding discharges":         "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Sum() int {\n\tm := r.inner()\n\treturn len(m)\n}\n\nfunc F() int { return R.Sum() }\n",
		"registry lookup shape discharges":            "package view\n\nimport (\n\t\"reflect\"\n\t\"sync\"\n)\n\ntype entry struct {\n\tattr struct{}\n\ttyp  reflect.Type\n}\n\ntype reg struct {\n\tmu sync.Mutex\n\tfn func()\n\tm  map[string]entry\n}\n\nvar R = &reg{m: map[string]entry{}}\n\nfunc (r *reg) Lookup(name string) (struct{}, reflect.Type, bool) {\n\tr.mu.Lock()\n\tdefer r.mu.Unlock()\n\te, ok := r.m[name]\n\treturn e.attr, e.typ, ok\n}\n\nfunc F() bool {\n\t_, _, ok := R.Lookup(\"k\")\n\treturn ok\n}\n",
		"generic receiver read discharges":            "package view\n\ntype reg[A comparable] struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg[string]{}\n\nfunc (r *reg[A]) Count() int { return r.n }\n\nfunc F() int { return R.Count() }\n",
		"init-only helper registration":               "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = declare(\"k\")\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
		"helper chain registration":                   "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = declare(\"k\")\n\nfunc declare(name string) bool { return install(name) }\n\nfunc install(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
		"sentinel map-key registration":               "package view\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"x\")\n\nvar index = map[error]string{}\n\nfunc init() { index[ErrX] = \"x\" }\n\nfunc F() error { return ErrX }\n",
		"deferred init registration stays init flow":  "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = boot()\n\nfunc boot() bool {\n\tdefer register()\n\treturn true\n}\n\nfunc register() {\n\tHooks[\"k\"] = func() {}\n}\n\nfunc F() int { return len(Hooks) }\n",
		"by-value carrier argument seeds nothing":     "package view\n\nvar Count = func() {}\n\nvar Rebind func()\n\nfunc setup(f func()) {\n\tRebind = func() { f() }\n}\n\nfunc init() { setup(Count) }\n\nfunc F() bool { return Count != nil }\n",
		"non-spread variadic copies the carrier":      "package view\n\nvar OnBoot = func() {}\n\nvar Rebind func()\n\nfunc register(hooks ...func()) {\n\tRebind = func() { hooks[0]() }\n}\n\nfunc init() { register(OnBoot) }\n\nfunc F() bool { return OnBoot != nil }\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := writeViewModule(t, source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid - a writeless read downgraded", verdict)
			}
		})
	}
}

// Escapes of writable carriers and sentinel rebinds stay mutation
// (REQ-closure-shared-dynamic-state), and the refusal names the owning
// package and variable (REQ-closure-shared-dynamic-state-reason).
func TestSharedDynamicStateEscapesAndRebindsDowngradeWithCulprit(t *testing.T) {
	for name, tc := range map[string]struct{ source, culprit string }{
		"sentinel rebind": {
			source:  "package view\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"x\")\n\nfunc F() { ErrX = errors.New(\"y\") }\n",
			culprit: "example.com/view.ErrX is mutated",
		},
		"mutable-object sentinel escape": {
			source:  "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error = &impl{}\n\nfunc use(err error) error { return err }\n\nfunc F() { _ = use(ErrX) }\n",
			culprit: "example.com/view.ErrX escapes writable",
		},
		"registry map escape": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nfunc take(m map[string]func()) map[string]func() { return m }\n\nfunc F() { _ = take(Hooks) }\n",
			culprit: "example.com/view.Hooks escapes writable",
		},
		"channel range receives": {
			source:  "package view\n\nvar Ch = make(chan func(), 1)\n\nfunc F() { for f := range Ch { f() } }\n",
			culprit: "example.com/view.Ch is mutated",
		},
		"indexed-out alias escapes": {
			source:  "package view\n\nvar Registry = []map[string]func(){{}}\n\nfunc take(m map[string]func()) {}\n\nfunc F() { take(Registry[0]) }\n",
			culprit: "example.com/view.Registry escapes writable",
		},
		"init-nested literal rebind": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar f func()\n\nfunc init() { f = func() { Hooks[\"k\"] = nil } }\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"goroutine-in-init sentinel rebind": {
			source:  "package view\n\nimport \"errors\"\n\nvar ErrX = errors.New(\"x\")\n\nfunc use(err error) {}\n\nfunc init() { go func() { ErrX = errors.New(\"later\") }() }\n\nfunc F() { use(ErrX) }\n",
			culprit: "example.com/view.ErrX is mutated",
		},
		"helper parameter bound at the init call site": {
			// The helper declares BEFORE the init that calls it: the
			// seed must cross bodies through the package-level
			// fixpoint, not ride declaration order.
			source:  "package view\n\nvar Hooks = []func(){func() {}}\n\nvar Rebind func()\n\nfunc setup(hs []func()) {\n\tRebind = func() { hs[0] = func() {} }\n}\n\nfunc init() { setup(Hooks) }\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"composite-target binding carries the alias": {
			source:  "package view\n\ntype holder struct{ m []func() }\n\nvar Hooks = []func(){func() {}}\n\nvar Rebind func()\n\nfunc init() {\n\tvar s holder\n\ts.m = Hooks\n\tRebind = func() { s.m[0] = func() {} }\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper also called from program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = declare(\"k\")\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc Register(name string) { declare(name) }\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper referenced as a value": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = declare(\"k\")\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nvar Declare = declare\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper stores non-audited sentinel": {
			source:  "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error\n\nvar _ = setup()\n\nfunc setup() bool {\n\tErrX = &impl{}\n\treturn true\n}\n\nfunc use(err error) error { return err }\n\nfunc F() { _ = use(ErrX) }\n",
			culprit: "example.com/view.ErrX escapes writable",
		},
		"initializer-literal reference is program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar F2 = func() { declare(\"x\") }\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"init-body-literal reference is program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Run func()\n\nfunc init() { Run = func() { declare(\"k\") } }\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper-body-literal reference is program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Run func()\n\nvar _ = declare()\n\nfunc declare() bool {\n\tRun = func() { install(\"k\") }\n\treturn true\n}\n\nfunc install(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper go-statement argument escapes": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = setup()\n\nfunc setup() bool { go mutate(Hooks); return true }\n\nfunc mutate(m map[string]func()) { m[\"k\"] = func() {} }\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks escapes writable",
		},
		"init go-statement argument escapes": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nfunc mutate(m map[string]func()) { m[\"k\"] = func() {} }\n\nfunc init() { go mutate(Hooks) }\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks escapes writable",
		},
		"go literal-call argument escapes": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = setup()\n\nfunc setup() bool {\n\tgo func(m map[string]func()) { m[\"k\"] = func() {} }(Hooks)\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks escapes writable",
		},
		"go-statement callee races program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nfunc init() { go declare(\"k\") }\n\nfunc declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"slice-receiver range binding marks": {
			source:  "package view\n\ntype entry struct {\n\tfn func()\n\tn  *int\n}\n\ntype reg []entry\n\nvar R = reg{{fn: func() {}, n: new(int)}}\n\nfunc (r reg) First() *int {\n\tfor _, e := range r {\n\t\treturn e.n\n\t}\n\treturn nil\n}\n\nfunc F() {\n\tp := R.First()\n\t*p = 1\n}\n",
			culprit: "example.com/view.R escapes writable",
		},
		"direct field-store RHS keeps the mark": {
			source:  "package view\n\ntype box struct{ f map[string]int }\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) Outer() int {\n\tvar s box\n\ts.f = r.m\n\ts.f[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"shadowed len keeps the mark": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc len(m map[string]int) int { return 0 }\n\nfunc (r *reg) Size() int { return len(r.m) }\n\nfunc F() int { return R.Size() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"mixed parallel assign keeps the mark": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Outer() int {\n\tm, x := r.inner(), 5\n\tm[\"k\"] = x\n\treturn 0\n}\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"clean-plus-leaky parallel assign keeps the mark": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n\tn  int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) count() int { return r.n }\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Outer() int {\n\tn, m := r.count(), r.inner()\n\tm[\"k\"] = n\n\treturn 0\n}\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"field-store binding keeps the mark": {
			source:  "package view\n\ntype box struct{ f map[string]int }\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Outer() int {\n\tvar s box\n\ts.f = r.inner()\n\ts.f[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"leaky sibling call in arg position marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc probe(m map[string]int) int { return len(m) }\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Outer() int { return probe(r.inner()) }\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"sibling leaky return launders nothing": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) inner() map[string]int { return r.m }\n\nfunc (r *reg) Outer() int {\n\tm := r.inner()\n\tm[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Outer() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"loop-carried taint marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) Set() int {\n\tvar v map[string]int\n\tfor i := 0; i < 2; i++ {\n\t\tif v != nil {\n\t\t\tv[\"k\"] = 1\n\t\t}\n\t\tv = r.m\n\t}\n\treturn 0\n}\n\nfunc F() int { return R.Set() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"assign-form range binding taints": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\ts  []map[string]int\n}\n\nvar R = &reg{s: []map[string]int{{}}}\n\nfunc (r *reg) Set() int {\n\tvar v map[string]int\n\tfor _, v = range r.s {\n\t\t_ = v\n\t}\n\tv[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Set() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"tainted local write marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) Set() int {\n\te := r.m\n\te[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Set() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"tainted arg escape marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc probe(m map[string]int) int { return len(m) }\n\nfunc (r *reg) Peek() int {\n\tv := r.m\n\treturn probe(v)\n}\n\nfunc F() int { return R.Peek() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"local-alias write through method marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tm  map[string]int\n}\n\nvar R = &reg{m: map[string]int{}}\n\nfunc (r *reg) Set() int {\n\tv := r.m\n\tv[\"k\"] = 1\n\treturn 0\n}\n\nfunc F() int { return R.Set() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"returned mutable pointer marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\ts  []*int\n}\n\nvar R = &reg{s: []*int{new(int)}}\n\nfunc (r *reg) Get() *int { return r.s[0] }\n\nfunc F() { p := R.Get(); *p = 1 }\n",
			culprit: "example.com/view.R is mutated",
		},
		"interface-dispatched call keeps the mark": {
			source:  "package view\n\ntype counter interface{ Count() int }\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nfunc (r *reg) Count() int { return r.n }\n\nvar R counter = &reg{}\n\nfunc F() int { return R.Count() }\n",
			culprit: "example.com/view.R escapes writable",
		},
		"chain into writer sibling marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int { return r.bump() }\n\nfunc (r *reg) bump() int {\n\tr.n++\n\treturn r.n\n}\n\nfunc F() int { return R.Count() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"non-mutex sync field use marks": {
			source:  "package view\n\nimport \"sync\"\n\ntype reg struct {\n\twg sync.WaitGroup\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int {\n\tr.wg.Wait()\n\treturn r.n\n}\n\nfunc F() int { return R.Count() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"assignment writer method call marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Set(v int) { r.n = v }\n\nfunc F() { R.Set(3) }\n",
			culprit: "example.com/view.R is mutated",
		},
		"writer method call marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Bump() { r.n++ }\n\nfunc F() { R.Bump() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"method value bind keeps the mark": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc (r *reg) Count() int { return r.n }\n\nfunc F() int {\n\tg := R.Count\n\treturn g()\n}\n",
			culprit: "example.com/view.R is mutated",
		},
		"alias-returning method call marks": {
			source:  "package view\n\ntype reg struct {\n\thooks map[string]func()\n}\n\nvar R = &reg{hooks: map[string]func(){}}\n\nfunc (r *reg) Hooks() map[string]func() { return r.hooks }\n\nfunc F() int { return len(R.Hooks()) }\n",
			culprit: "example.com/view.R is mutated",
		},
		"receiver-escaping method call marks": {
			source:  "package view\n\ntype reg struct {\n\tfn func()\n\tn  int\n}\n\nvar R = &reg{}\n\nfunc probe(v any) int { return 0 }\n\nfunc (r *reg) Count() int { return probe(r) }\n\nfunc F() int { return R.Count() }\n",
			culprit: "example.com/view.R is mutated",
		},
		"method helper never qualifies": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\ntype reg struct{}\n\nvar _ = reg{}.declare(\"k\")\n\nfunc (reg) declare(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper nested literal mutates as program code": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Run func()\n\nvar _ = declare()\n\nfunc declare() bool {\n\tRun = func() { Hooks[\"k\"] = nil }\n\treturn true\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"helper reached through disqualified caller": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar _ = inner(\"k\")\n\nfunc inner(name string) bool {\n\tHooks[name] = func() {}\n\treturn true\n}\n\nfunc outer(name string) { inner(name) }\n\nfunc Register(name string) { outer(name) }\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"range-bound init store breaks opacity": {
			source:  "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error\n\nvar errs = []error{&impl{}}\n\nfunc init() { for _, ErrX = range errs {} }\n\nfunc use(err error) error { return err }\n\nfunc F() { _ = use(ErrX) }\n",
			culprit: "example.com/view.ErrX escapes writable",
		},
		"init-local alias captured by a literal marks the carrier": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Mut func()\n\nfunc init() {\n\tm := Hooks\n\tMut = func() { m[\"x\"] = func() {} }\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"init-local alias handed out by a literal escapes the carrier": {
			// The argument is a local, so the parameter deferral never
			// applies - the alias-carrier ident arm must mark the
			// carrier the local aliases.
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Mut func()\n\nfunc keep(m map[string]func()) {}\n\nfunc init() {\n\tm := Hooks\n\tMut = func() { keep(m) }\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks escapes writable",
		},
		"chained init-local alias marks the carrier": {
			source:  "package view\n\nvar Hooks = map[string]func(){}\n\nvar Mut func()\n\nfunc init() {\n\ta := Hooks\n\tb := a\n\tMut = func() { b[\"x\"] = func() {} }\n}\n\nfunc F() int { return len(Hooks) }\n",
			culprit: "example.com/view.Hooks is mutated",
		},
		"indirect init store breaks opacity": {
			// The consumer retains its parameter, so the escape stands
			// and the verdict turns on the opacity the indirect store
			// broke; an empty consumer would discharge the escape by the
			// leak-free parameter proof and never reach opacity at all.
			source:  "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error\n\nfunc init() { p := &ErrX; *p = &impl{} }\n\nfunc use(err error) error { return err }\n\nfunc F() { _ = use(ErrX) }\n",
			culprit: "example.com/view.ErrX escapes writable",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := writeViewModule(t, tc.source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") || !strings.Contains(verdict.Reason, tc.culprit) {
				t.Fatalf("verdict = %+v, want the downgrade naming %q", verdict, tc.culprit)
			}
		})
	}
}

// Sibling subjects sharing one process communicate through pool
// contents — a subject unreachable from F can Put a value F's Get
// dispatches on — so the audited pooling set's shared-dynamic-state
// discharge holds only under the caller's single-subject-process
// attestation: option on, the canonical idiom is Valid; option off,
// the pool keeps the fail-closed judgment
// (REQ-closure-shared-dynamic-state,
// REQ-closure-shared-dynamic-state-reason).
func TestPoolingDischargeRequiresSingleSubjectAttestation(t *testing.T) {
	source := "package view\n\nimport \"sync\"\n\nvar pool sync.Pool\n\ntype fast struct{}\n\nfunc (fast) Work() int { return 1 }\n\ntype slow struct{}\n\nfunc (slow) Work() int { return 2 }\n\nfunc Plant() { pool.Put(slow{}) }\n\nfunc F() int {\n\tpool.Put(fast{})\n\tif w, ok := pool.Get().(interface{ Work() int }); ok {\n\t\treturn w.Work()\n\t}\n\treturn 0\n}\n"
	dir := writeViewModule(t, source)
	attested := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
	if attested.Status != Valid {
		t.Fatalf("attested verdict = %+v, want Valid - the single-subject model roots every Put in the subject's own flow", attested)
	}
	unattested := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	if unattested.Status != Unverifiable || !strings.Contains(unattested.Reason, "shares mutated dynamic state") || !strings.Contains(unattested.Reason, "example.com/view.pool is mutated") {
		t.Fatalf("unattested verdict = %+v, want the fail-closed downgrade naming the pool - sibling subjects communicate through pool contents", unattested)
	}
}

// The content-proven discharge admits the canonical pooling idiom in
// any execution model — no attestation: an unexported package-level
// sync.Pool declared with a New function literal returning one
// identical concrete dynamic-carrier-free type, every appearance a
// Get or Put receiver, every Put argument statically that type. Pool
// contents are then non-nil T under every schedule, so no dispatch
// outcome can distinguish subject orders
// (REQ-closure-shared-dynamic-state).
func TestContentProvenPoolDischargesWithoutAttestation(t *testing.T) {
	for name, source := range map[string]string{
		"get and put":         "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() any { b := make([]byte, 0, 64); return &b }}\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\t*b = (*b)[:0]\n\tn := cap(*b)\n\tbufs.Put(b)\n\treturn n\n}\n",
		"deferred put":        "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() any { b := make([]byte, 0, 64); return &b }}\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
		"uses across helpers": "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() any { b := make([]byte, 0, 64); return &b }}\n\nfunc borrow() *[]byte { return bufs.Get().(*[]byte) }\n\nfunc give(b *[]byte) { bufs.Put(b) }\n\nfunc F() int {\n\tb := borrow()\n\tdefer give(b)\n\treturn cap(*b)\n}\n",
		"struct content":      "package view\n\nimport \"sync\"\n\ntype scratch struct{ n int }\n\nvar scratches = sync.Pool{New: func() any { return new(scratch) }}\n\nfunc F() int {\n\ts := scratches.Get().(*scratch)\n\ts.n++\n\tn := s.n\n\tscratches.Put(s)\n\treturn n\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid - a content-proven pool downgraded without the attestation", verdict)
			}
		})
	}
}

// Every shape the content proof cannot see keeps the attestation
// requirement, fail-closed: the declaration must be the only content
// source (a conforming New function literal), the content type one
// identical concrete dynamic-carrier-free type, every appearance a
// Get or Put receiver — an initializer-flow write or address capture
// included, since init regions exempt writes from the mutation marks
// the proof would otherwise lean on — and every Put argument
// statically exactly T (REQ-closure-shared-dynamic-state,
// REQ-closure-shared-dynamic-state-reason).
func TestContentProvenPoolNonConformingShapesKeepAttestationRequirement(t *testing.T) {
	conformingDecl := "var bufs = sync.Pool{New: func() any { b := make([]byte, 0, 64); return &b }}\n"
	for name, tc := range map[string]struct{ source, culprit string }{
		"exported pool": {
			source:  "package view\n\nimport \"sync\"\n\nvar Bufs = sync.Pool{New: func() any { b := make([]byte, 0, 64); return &b }}\n\nfunc F() int {\n\tb := Bufs.Get().(*[]byte)\n\tdefer Bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.Bufs is mutated",
		},
		"no New field": {
			source:  "package view\n\nimport \"sync\"\n\nvar bufs sync.Pool\n\nfunc F() int {\n\tb, ok := bufs.Get().(*[]byte)\n\tif !ok {\n\t\tn := make([]byte, 0, 64)\n\t\tb = &n\n\t}\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"named-function New": {
			source:  "package view\n\nimport \"sync\"\n\nfunc newBuf() any { b := make([]byte, 0, 64); return &b }\n\nvar bufs = sync.Pool{New: newBuf}\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"named-result New with deferred rewrite": {
			// The deferred closure retypes the named result after the
			// return expression the derivation reads — the content is
			// *int at runtime while the returns say *[]byte. Both the
			// named-result rule and the defer rule refuse this shape.
			source:  "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() (v any) {\n\tdefer func() { v = new(int) }()\n\tb := make([]byte, 0, 64)\n\treturn &b\n}}\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"named result without defer": {
			// Sound in fact, refused by the signature rule alone — the
			// case that isolates the named-results check from the defer
			// check.
			source:  "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() (v any) {\n\tb := make([]byte, 0, 64)\n\treturn &b\n}}\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"recovering New": {
			// A recovered panic returns the zero value of the unnamed
			// any result — a nil interface — so Get yields nil exactly
			// when no sibling planted first: nil-vs-T is type-plane and
			// subject-order-steered. The defer rule refuses the shape.
			source:  "package view\n\nimport \"sync\"\n\nvar cold = true\n\nvar bufs = sync.Pool{New: func() any {\n\tdefer func() { _ = recover() }()\n\tif cold {\n\t\tpanic(\"cold\")\n\t}\n\tb := make([]byte, 0, 64)\n\treturn &b\n}}\n\nfunc F() int {\n\tv := bufs.Get()\n\tif v == nil {\n\t\treturn 0\n\t}\n\tb := v.(*[]byte)\n\tbufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"deferred side effect in New": {
			// A plain defer with no recover is sound today, but the
			// bound is the statement shape, fail-closed — post-return
			// channels are closed wholesale, not judged by what the
			// deferred call happens to do.
			source:  "package view\n\nimport \"sync\"\n\nfunc noop() {}\n\nvar bufs = sync.Pool{New: func() any {\n\tdefer noop()\n\tb := make([]byte, 0, 64)\n\treturn &b\n}}\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"multi-name declaration": {
			source:  "package view\n\nimport \"sync\"\n\nvar bufs, spare = sync.Pool{New: func() any { b := make([]byte, 0, 64); return &b }}, 0\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b) + spare\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"empty composite literal": {
			source:  "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{}\n\nfunc F() int {\n\tb, ok := bufs.Get().(*[]byte)\n\tif !ok {\n\t\tn := make([]byte, 0, 64)\n\t\tb = &n\n\t}\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"interface-typed New return": {
			source:  "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() any { var v any = new(int); return v }}\n\nfunc F() int {\n\tp := bufs.Get().(*int)\n\tdefer bufs.Put(p)\n\treturn *p\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"two content types": {
			source:  "package view\n\nimport \"sync\"\n\nvar cold bool\n\nvar bufs = sync.Pool{New: func() any {\n\tif cold {\n\t\treturn new(int)\n\t}\n\tb := make([]byte, 0, 64)\n\treturn &b\n}}\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"untyped nil New return": {
			// The Put is nil too, so every site would conform to an
			// untyped content type — the untyped rejection alone is
			// what keeps this pool unproven.
			source:  "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() any { return nil }}\n\nfunc F() int {\n\tv := bufs.Get()\n\tbufs.Put(nil)\n\tif v == nil {\n\t\treturn 0\n\t}\n\treturn 1\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"dispatch-carrying content": {
			source:  "package view\n\nimport \"sync\"\n\nvar hooks = sync.Pool{New: func() any { return func() int { return 1 } }}\n\nfunc F() int {\n\th := hooks.Get().(func() int)\n\tdefer hooks.Put(h)\n\treturn h()\n}\n",
			culprit: "example.com/view.hooks is mutated",
		},
		"put of the any-typed Get result": {
			source:  "package view\n\nimport \"sync\"\n\n" + conformingDecl + "\nfunc F() int {\n\tv := bufs.Get()\n\tdefer bufs.Put(v)\n\treturn 0\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"put of a different concrete type": {
			source:  "package view\n\nimport \"sync\"\n\n" + conformingDecl + "\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\t_ = b\n\tbufs.Put(new(int))\n\treturn 0\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"New-field store elsewhere evicts wholesale": {
			source:  "package view\n\nimport \"sync\"\n\n" + conformingDecl + "\nfunc rearm() { bufs.New = func() any { return new(int) } }\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"initializer-flow rebind evicts": {
			source:  "package view\n\nimport \"sync\"\n\n" + conformingDecl + "\nfunc init() {\n\tbufs = sync.Pool{New: func() any { return new(int) }}\n}\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"initializer-flow address capture evicts": {
			source:  "package view\n\nimport \"sync\"\n\n" + conformingDecl + "\nfunc warm(p *sync.Pool) {}\n\nfunc init() { warm(&bufs) }\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"method-value bind evicts": {
			source:  "package view\n\nimport \"sync\"\n\n" + conformingDecl + "\nfunc F() int {\n\tget := bufs.Get\n\tb := get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"array element carrier stays attestation-gated": {
			source:  "package view\n\nimport \"sync\"\n\nvar pools [4]sync.Pool\n\nfunc F() int {\n\ti := 1\n\tv := pools[i].Get()\n\tpools[i].Put(v)\n\treturn i\n}\n",
			culprit: "example.com/view.pools is mutated",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := writeViewModule(t, tc.source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") || !strings.Contains(verdict.Reason, tc.culprit) {
				t.Fatalf("verdict = %+v, want the fail-closed downgrade naming %q", verdict, tc.culprit)
			}
		})
	}
}

// A load-bearing single-subject attestation rides the subject's
// evidence exactly as a vouch discharge does: option on with a fired
// pool discharge, the fingerprint names the discharged pool
// canonically; option on with no pool reachable, the record is empty —
// an inert attestation records nothing; option off, a content-proven
// pool stands with nothing recorded (the engine's own verdict) and an
// unproven pool keeps the downgrade (REQ-vouch-recorded,
// REQ-closure-shared-dynamic-state).
func TestSingleSubjectAttestationRecordedOnEvidence(t *testing.T) {
	subject := Subject{Package: "example.com/view", Symbol: "F"}
	pooled := "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() any { b := make([]byte, 0, 64); return &b }}\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n"
	capture := func(t *testing.T, source string, opts ...option) (Fingerprint, Verdict) {
		t.Helper()
		dir := writeViewModule(t, source)
		return captureCheckFP(t, dir, subject, opts...)
	}

	loadBearing, verdict := capture(t, pooled, withSingleSubjectExecution())
	if verdict.Status != Valid {
		t.Fatalf("attested pooled verdict = %+v, want Valid", verdict)
	}
	if loadBearing.SingleSubjectDischarges != "example.com/view.bufs" {
		t.Fatalf("attested pooled evidence = %q, want the discharged pool named canonically", loadBearing.SingleSubjectDischarges)
	}

	inert, inertVerdict := capture(t, "package view\n\nfunc F() int { return 1 }\n", withSingleSubjectExecution())
	if inertVerdict.Status != Valid {
		t.Fatalf("attested pool-free verdict = %+v, want Valid", inertVerdict)
	}
	if inert.SingleSubjectDischarges != "" {
		t.Fatalf("inert attestation recorded %q, want nothing - no pool discharge is reachable from the subject", inert.SingleSubjectDischarges)
	}

	// The conforming pool is content-proven, so the unattested leg
	// pins the proven discharge's recording discipline instead: the
	// verdict stands without the attestation and the discharge rides
	// no evidence record — the engine's own verdict, not a caller
	// assertion (REQ-closure-shared-dynamic-state).
	unattested, offVerdict := capture(t, pooled)
	if offVerdict.Status != Valid {
		t.Fatalf("unattested content-proven pooled verdict = %+v, want Valid", offVerdict)
	}
	if unattested.SingleSubjectDischarges != "" {
		t.Fatalf("unattested evidence recorded %q, want nothing - the content-proven discharge is not an attestation", unattested.SingleSubjectDischarges)
	}

	// A pool the content proof does not cover — contents typed by a
	// planted struct, no New — keeps the downgrade and records nothing.
	unproven := "package view\n\nimport \"sync\"\n\nvar pool sync.Pool\n\ntype item struct{}\n\nfunc F() int {\n\tpool.Put(item{})\n\tif _, ok := pool.Get().(item); ok {\n\t\treturn 1\n\t}\n\treturn 0\n}\n"
	offEvidence, offUnproven := capture(t, unproven)
	if offUnproven.Status != Unverifiable || !strings.Contains(offUnproven.Reason, "example.com/view.pool is mutated") {
		t.Fatalf("unattested unproven pooled verdict = %+v, want the fail-closed downgrade naming the pool", offUnproven)
	}
	if offEvidence.SingleSubjectDischarges != "" {
		t.Fatalf("unattested evidence recorded %q, want nothing", offEvidence.SingleSubjectDischarges)
	}
}

// The audited pooling set under the single-subject-process attestation:
// a Get or Put CALL on a package-level sync.Pool carrier — the pool
// variable itself, or an element of a package-level array or slice of
// sync.Pool — is not mutation of the pool variable, so the canonical
// pooling idiom leaves the package closed and the subject verifiable
// (REQ-closure-shared-dynamic-state).
func TestAuditedPoolingGetPutDoesNotDowngrade(t *testing.T) {
	for name, source := range map[string]string{
		"pool var get and put":           "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() any { b := make([]byte, 0, 64); return &b }}\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\t*b = (*b)[:0]\n\tn := cap(*b)\n\tbufs.Put(b)\n\treturn n\n}\n",
		"deferred put":                   "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() any { b := make([]byte, 0, 64); return &b }}\n\nfunc F() int {\n\tb := bufs.Get().(*[]byte)\n\tdefer bufs.Put(b)\n\treturn cap(*b)\n}\n",
		"pool array element get and put": "package view\n\nimport \"sync\"\n\nvar pools [4]sync.Pool\n\nfunc F() int {\n\ti := 1\n\tv := pools[i].Get()\n\tpools[i].Put(v)\n\treturn i\n}\n",
		"pool slice element get and put": "package view\n\nimport \"sync\"\n\nvar pools = make([]sync.Pool, 4)\n\nfunc F() int {\n\ti := 1\n\tv := pools[i].Get()\n\tpools[i].Put(v)\n\treturn i\n}\n",
		"init-flow warm-up put":          "package view\n\nimport \"sync\"\n\nvar bufs sync.Pool\n\nfunc init() {\n\tb := make([]byte, 0, 64)\n\tbufs.Put(&b)\n}\n\nfunc F() bool { return bufs.Get() != nil }\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
			if verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid - an audited pooling call downgraded", verdict)
			}
		})
	}
}

// The pooling admission covers exactly the Get and Put CALL on the
// package-level carrier, even with the single-subject attestation
// armed: a rebinding, an address capture, a method-value bind, and a
// New-field store stay mutation; an unaudited function value
// registered as New keeps the environment-audit refusal, and a New
// closure's body stays program code, so its writes to dynamic package
// state mark the written carrier; a package-level value handed to Put
// keeps its own escape — the admission never leaks into argument
// pricing (REQ-closure-shared-dynamic-state,
// REQ-closure-shared-dynamic-state-reason).
func TestAuditedPoolingEveryOtherUseKeepsFailClosed(t *testing.T) {
	for name, tc := range map[string]struct{ source, culprit string }{
		"pool rebinding": {
			source:  "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() any { return new(int) }}\n\nfunc F() { bufs = sync.Pool{} }\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"pool address capture": {
			source:  "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() any { return new(int) }}\n\nfunc take(p *sync.Pool) {}\n\nfunc F() { take(&bufs) }\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"method value bind": {
			source:  "package view\n\nimport \"sync\"\n\nvar bufs = sync.Pool{New: func() any { return new(int) }}\n\nfunc F() any {\n\tget := bufs.Get\n\treturn get()\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"embedded pool keeps the mark": {
			// The admitted carrier is exactly a sync.Pool variable or an
			// element of an array or slice of sync.Pool: a struct
			// embedding a pool can carry sibling dynamic state, so its
			// implicit Get promotion keeps the pointer-receiver capture.
			source:  "package view\n\nimport \"sync\"\n\ntype holder struct {\n\tsync.Pool\n\thooks []func()\n}\n\nvar bufs holder\n\nfunc F() any {\n\tv := bufs.Get()\n\tbufs.Put(v)\n\treturn nil\n}\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"new-field store outside init flow": {
			source:  "package view\n\nimport \"sync\"\n\nvar bufs sync.Pool\n\nfunc F() { bufs.New = func() any { return new(int) } }\n",
			culprit: "example.com/view.bufs is mutated",
		},
		"unaudited new value registration": {
			source:  "package view\n\nimport \"sync\"\n\nvar newFn func() any\n\nvar bufs = sync.Pool{New: newFn}\n\nfunc F() any {\n\tv := bufs.Get()\n\tbufs.Put(v)\n\treturn nil\n}\n",
			culprit: "example.com/view.bufs registers function values outside the environment-free audit",
		},
		"new closure mutating dynamic package state": {
			source:  "package view\n\nimport \"sync\"\n\nvar seen = map[string]func(){}\n\nvar bufs = sync.Pool{New: func() any { seen[\"boot\"] = func() {}; return new(int) }}\n\nfunc F() any {\n\tv := bufs.Get()\n\tbufs.Put(v)\n\treturn v\n}\n",
			culprit: "example.com/view.seen is mutated",
		},
		"pooled package-level value keeps its own escape": {
			source:  "package view\n\nimport \"sync\"\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error = &impl{}\n\nvar bufs sync.Pool\n\nfunc F() { bufs.Put(ErrX) }\n",
			culprit: "example.com/view.ErrX escapes writable",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, tc.source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
			if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") || !strings.Contains(verdict.Reason, tc.culprit) {
				t.Fatalf("verdict = %+v, want the downgrade naming %q", verdict, tc.culprit)
			}
		})
	}
}

// A value of static type reflect.Type is an audited construction for
// the object-closed narrowing whatever expression produced it — a
// direct reflect.TypeOf call or a chained view method alike — because
// the interface is sealed by unexported methods and every referent is
// the runtime's canonical, immutable type descriptor: the type-cache
// idiom leaves the package closed and its escapes are not mutation
// (REQ-closure-shared-dynamic-state).
func TestAuditedTypeOfConstructionKeepsObjectClosed(t *testing.T) {
	for name, source := range map[string]string{
		"type-cache var escape discharges": "package view\n\nimport \"reflect\"\n\nvar bytesType = reflect.TypeOf([]byte{})\n\nfunc use(t reflect.Type) reflect.Type { return t }\n\nfunc F() bool { return use(bytesType) != nil }\n",
		"chained view method discharges":   "package view\n\nimport \"reflect\"\n\nvar elemType = reflect.TypeOf([]byte{}).Elem()\n\nfunc use(t reflect.Type) reflect.Type { return t }\n\nfunc F() bool { return use(elemType) != nil }\n",
		"yaml decoder shape discharges":    "package view\n\nimport \"reflect\"\n\nvar (\n\tstringMapType  = reflect.TypeOf(map[string]any{})\n\tgeneralMapType = reflect.TypeOf(map[any]any{})\n\tifaceType      = generalMapType.Elem()\n)\n\ntype decoder struct{ stringMapType, generalMapType reflect.Type }\n\nfunc F() *decoder {\n\tif ifaceType.String() == \"\" {\n\t\treturn nil\n\t}\n\treturn &decoder{stringMapType: stringMapType, generalMapType: generalMapType}\n}\n",
		"type-cache block discharges":      "package view\n\nimport \"reflect\"\n\nvar (\n\tbytesType  = reflect.TypeOf([]byte{})\n\tintType    = reflect.TypeOf(int(1))\n\tstringType = reflect.TypeOf(\"\")\n\tstructType = reflect.TypeOf(struct{ n int }{})\n)\n\nfunc use(t reflect.Type) reflect.Type { return t }\n\nfunc F() bool {\n\treturn use(bytesType) != use(intType) && stringType != nil && structType != nil\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid - an audited reflect.TypeOf construction downgraded", verdict)
			}
		})
	}
}

// The reflect.Type admissions keep their bounds: rebinding the
// variable remains mutation everywhere, and a construction's argument
// keeps its own pricing — a package-level carrier handed to TypeOf
// still refuses (REQ-closure-shared-dynamic-state,
// REQ-closure-shared-dynamic-state-reason).
func TestAuditedTypeOfConstructionBounds(t *testing.T) {
	for name, tc := range map[string]struct{ source, culprit string }{
		"rebinding stays mutation": {
			source:  "package view\n\nimport \"reflect\"\n\nvar bytesType = reflect.TypeOf([]byte{})\n\nfunc F() { bytesType = reflect.TypeOf(\"\") }\n",
			culprit: "example.com/view.bytesType is mutated",
		},
		"carrier argument keeps its own pricing": {
			source:  "package view\n\nimport \"reflect\"\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error = &impl{}\n\nvar errType = reflect.TypeOf(ErrX)\n\nfunc use(t reflect.Type) reflect.Type { return t }\n\nfunc F() bool { return use(errType) != nil }\n",
			culprit: "example.com/view.ErrX escapes writable",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, tc.source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") || !strings.Contains(verdict.Reason, tc.culprit) {
				t.Fatalf("verdict = %+v, want the downgrade naming %q", verdict, tc.culprit)
			}
		})
	}
}

// A direct fmt.Errorf call chained through audited arguments is an
// audited construction: the result retains at most its argument
// objects, so the canonical wrapped-sentinel idiom stays object-closed
// when every argument is a constant, a nested audited construction, or
// a sibling object-closed variable — whatever the declaration order
// (REQ-closure-shared-dynamic-state-escape-narrowings).
func TestAuditedErrorfConstructionKeepsObjectClosed(t *testing.T) {
	for name, source := range map[string]string{
		"wrapped sentinel discharges": "package view\n\nimport (\n\t\"errors\"\n\t\"fmt\"\n)\n\nvar Base = errors.New(\"base\")\n\nvar Wrapped = fmt.Errorf(\"%w: bound\", Base)\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(Wrapped) != nil }\n",
		"sentinel family discharges":  "package view\n\nimport (\n\t\"errors\"\n\t\"fmt\"\n)\n\nvar ErrProposalDropped = errors.New(\"raft proposal dropped\")\n\nvar ErrProposalDroppedLogBound = fmt.Errorf(\"%w: log bound\", ErrProposalDropped)\n\nvar ErrProposalDroppedQuorumGate = fmt.Errorf(\"%w: quorum gate\", ErrProposalDropped)\n\nfunc use(err error) error { return err }\n\nfunc F() bool {\n\treturn use(ErrProposalDroppedLogBound) != use(ErrProposalDroppedQuorumGate)\n}\n",
		"chained wrap discharges":     "package view\n\nimport (\n\t\"errors\"\n\t\"fmt\"\n)\n\nvar Base = errors.New(\"base\")\n\nvar Mid = fmt.Errorf(\"%w: mid\", Base)\n\nvar Top = fmt.Errorf(\"%w: top\", Mid)\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(Top) != nil }\n",
		"reversed declaration order":  "package view\n\nimport (\n\t\"errors\"\n\t\"fmt\"\n)\n\nvar Wrapped = fmt.Errorf(\"%w: bound\", Base)\n\nvar Base = errors.New(\"base\")\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(Wrapped) != nil }\n",
		"constant-only errorf":        "package view\n\nimport \"fmt\"\n\nvar Sentinel = fmt.Errorf(\"code %d: %s\", 7, \"gate\")\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(Sentinel) != nil }\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid - an audited fmt.Errorf construction downgraded", verdict)
			}
		})
	}
}

// The fmt.Errorf admission covers exactly the direct call over audited
// arguments: a local-variable argument refuses, a wrap over a
// non-closed sibling falls with the sibling at composition (the
// chained judgment, not the declaration order), and rebinding a
// wrapped variable remains mutation everywhere
// (REQ-closure-shared-dynamic-state,
// REQ-closure-shared-dynamic-state-reason).
func TestAuditedErrorfConstructionBounds(t *testing.T) {
	for name, tc := range map[string]struct{ source, culprit string }{
		"local argument refuses": {
			source:  "package view\n\nimport (\n\t\"errors\"\n\t\"fmt\"\n)\n\nvar Wrapped error\n\nfunc init() {\n\te := errors.New(\"base\")\n\tWrapped = fmt.Errorf(\"%w: bound\", e)\n}\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(Wrapped) != nil }\n",
			culprit: "example.com/view.Wrapped escapes writable",
		},
		"non-closed sibling fells the wrap": {
			// Alpha sorts before Zeta: the culprit naming Alpha pins that
			// the wrap itself fell through the dependency edge — with the
			// chain ignored, Alpha would stay opaque and only Zeta could
			// be named.
			source:  "package view\n\nimport \"fmt\"\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar Alpha = fmt.Errorf(\"%w: bound\", Zeta)\n\nvar Zeta error = &impl{}\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(Alpha) != nil }\n",
			culprit: "example.com/view.Alpha escapes writable",
		},
		"rebinding a wrapped var stays mutation": {
			source:  "package view\n\nimport (\n\t\"errors\"\n\t\"fmt\"\n)\n\nvar Base = errors.New(\"base\")\n\nvar Wrapped = fmt.Errorf(\"%w: bound\", Base)\n\nfunc F() { Wrapped = fmt.Errorf(\"%w: again\", Base) }\n",
			culprit: "example.com/view.Wrapped is mutated",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, tc.source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "shares mutated dynamic state") || !strings.Contains(verdict.Reason, tc.culprit) {
				t.Fatalf("verdict = %+v, want the downgrade naming %q", verdict, tc.culprit)
			}
		})
	}
}

// Taking the address of a composite literal captures the fresh object
// alone: an object-closed element reference discharges as an escape, a
// non-closed element keeps the escape refusal (never a spurious
// mutation), and a capture nested inside the literal still marks
// (REQ-closure-shared-dynamic-state,
// REQ-closure-shared-dynamic-state-reason).
func TestCompositeAddressCapturesFreshObjectOnly(t *testing.T) {
	t.Run("closed element discharges", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nimport \"errors\"\n\nvar E = errors.New(\"x\")\n\ntype box struct{ err error }\n\nfunc F() *box { return &box{err: E} }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the composite's address is the fresh object's", verdict)
		}
	})
	t.Run("non-closed element keeps the escape refusal", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error = &impl{}\n\ntype box struct{ err error }\n\nfunc F() *box { return &box{err: ErrX} }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.ErrX escapes writable") {
			t.Fatalf("verdict = %+v, want the escape refusal naming ErrX - an element reference is an escape, never a capture", verdict)
		}
	})
	t.Run("nested capture still marks", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nimport \"errors\"\n\nvar E = errors.New(\"x\")\n\ntype box struct{ p *error }\n\nfunc F() *box { return &box{p: &E} }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.E is mutated") {
			t.Fatalf("verdict = %+v, want the capture refusal naming E - a nested address capture reaches the variable's cell", verdict)
		}
	})
}

// The object-closed discharge extends to method calls and method-value
// binds through the variable: every admissible referent's method set is
// read-only over immutable data by the same source audit, so the
// canonical sentinel uses stay verifiable, while a non-closed variable's
// method call keeps the fail-closed escape
// (REQ-closure-shared-dynamic-state-escape-narrowings).
func TestObjectClosedMethodCallDischarges(t *testing.T) {
	for name, source := range map[string]string{
		"errors.New var method call":   "package view\n\nimport \"errors\"\n\nvar E = errors.New(\"x\")\n\nfunc F() string { return E.Error() }\n",
		"wrapped var method call":      "package view\n\nimport (\n\t\"errors\"\n\t\"fmt\"\n)\n\nvar Base = errors.New(\"x\")\n\nvar Wrapped = fmt.Errorf(\"%w: y\", Base)\n\nfunc F() string { return Wrapped.Error() }\n",
		"constant-boxed method call":   "package view\n\ntype code int\n\nfunc (c code) Error() string { return \"code\" }\n\nconst c0 code = 1\n\nvar ErrX error = c0\n\nfunc F() string { return ErrX.Error() }\n",
		"method value bind discharges": "package view\n\nimport \"errors\"\n\nvar E = errors.New(\"x\")\n\nfunc F() func() string { return E.Error }\n",
		"nil referent discharges":      "package view\n\nvar E error = nil\n\nfunc F() string { return E.Error() }\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeViewModule(t, source)
			verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
			if verdict.Status != Valid {
				t.Fatalf("verdict = %+v, want Valid - a read-only method use of a closed referent downgraded", verdict)
			}
		})
	}
	t.Run("non-closed var method call keeps the mark", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error = &impl{}\n\nfunc F() string { return ErrX.Error() }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.ErrX escapes writable") {
			t.Fatalf("verdict = %+v, want the fail-closed refusal naming ErrX", verdict)
		}
	})
	t.Run("non-closed var method value bind keeps the mark", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrX error = &impl{}\n\nfunc F() func() string { return ErrX.Error }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.ErrX escapes writable") {
			t.Fatalf("verdict = %+v, want the fail-closed refusal naming ErrX - the bound value retains the writable receiver", verdict)
		}
	})
}

// A re-export — a package-level interface variable bound from an
// imported package's variable — chains the object-closed judgment
// across packages: closed origin, closed re-export; a non-closed or
// mutated origin fells the re-export; and a referent no fact declares
// (a standard-library variable) refuses fail-closed
// (REQ-closure-shared-dynamic-state,
// REQ-closure-shared-dynamic-state-reason).
func TestObjectClosedReExportCrossesPackages(t *testing.T) {
	check := func(t *testing.T, files map[string]string) Verdict {
		t.Helper()
		dir := writeModuleTree(t, files)
		return captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
	}
	t.Run("closed origin closes the re-export", func(t *testing.T) {
		verdict := check(t, map[string]string{
			"go.mod":     "module example.com/view\n\ngo 1.26\n",
			"wal/wal.go": "package wal\n\nimport \"errors\"\n\nvar ErrSealed = errors.New(\"wal: sealed\")\n",
			"view.go":    "package view\n\nimport \"example.com/view/wal\"\n\nvar ErrSealed = wal.ErrSealed\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(ErrSealed) != nil }\n",
		})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the re-export chains the closed origin", verdict)
		}
	})
	t.Run("transitive re-export chains the closed origin", func(t *testing.T) {
		verdict := check(t, map[string]string{
			"go.mod":     "module example.com/view\n\ngo 1.26\n",
			"wal/wal.go": "package wal\n\nimport \"errors\"\n\nvar ErrSealed = errors.New(\"wal: sealed\")\n",
			"mid/mid.go": "package mid\n\nimport \"example.com/view/wal\"\n\nvar ErrSealed = wal.ErrSealed\n",
			"view.go":    "package view\n\nimport \"example.com/view/mid\"\n\nvar ErrSealed = mid.ErrSealed\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(ErrSealed) != nil }\n",
		})
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the chain closes transitively", verdict)
		}
	})
	t.Run("felled origin reaches the transitive re-export", func(t *testing.T) {
		verdict := check(t, map[string]string{
			"go.mod":     "module example.com/view\n\ngo 1.26\n",
			"wal/wal.go": "package wal\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrSealed error = &impl{}\n",
			"mid/mid.go": "package mid\n\nimport \"example.com/view/wal\"\n\nvar ErrSealed = wal.ErrSealed\n",
			"view.go":    "package view\n\nimport \"example.com/view/mid\"\n\nvar ErrSealed = mid.ErrSealed\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(ErrSealed) != nil }\n",
		})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.ErrSealed escapes writable") {
			t.Fatalf("verdict = %+v, want the refusal naming the outermost re-export - the break propagates the whole chain", verdict)
		}
	})
	t.Run("non-closed origin fells the re-export", func(t *testing.T) {
		verdict := check(t, map[string]string{
			"go.mod":     "module example.com/view\n\ngo 1.26\n",
			"wal/wal.go": "package wal\n\ntype impl struct{ n int }\n\nfunc (i *impl) Error() string { return \"\" }\n\nvar ErrSealed error = &impl{}\n",
			"view.go":    "package view\n\nimport \"example.com/view/wal\"\n\nvar ErrSealed = wal.ErrSealed\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(ErrSealed) != nil }\n",
		})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.ErrSealed escapes writable") {
			t.Fatalf("verdict = %+v, want the refusal naming the re-export - the cross-package edge fell with the origin", verdict)
		}
	})
	t.Run("mutated origin fells the re-export", func(t *testing.T) {
		verdict := check(t, map[string]string{
			"go.mod":     "module example.com/view\n\ngo 1.26\n",
			"wal/wal.go": "package wal\n\nimport \"errors\"\n\nvar ErrSealed = errors.New(\"wal: sealed\")\n\nfunc Reseal() { ErrSealed = errors.New(\"resealed\") }\n",
			"view.go":    "package view\n\nimport \"example.com/view/wal\"\n\nvar ErrSealed = wal.ErrSealed\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(ErrSealed) != nil }\n",
		})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "is mutated") {
			t.Fatalf("verdict = %+v, want the mutation refusal - marks cross the linked pair", verdict)
		}
	})
	t.Run("undeclared referent refuses", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nimport \"io\"\n\nvar E = io.EOF\n\nfunc use(err error) error { return err }\n\nfunc F() bool { return use(E) != nil }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.E escapes writable") {
			t.Fatalf("verdict = %+v, want the fail-closed refusal - a module-less referent has no audited closure", verdict)
		}
	})
}

// Under the single-subject attestation the shared-dynamic-state
// judgment scopes per subject: a culprit whose every marking site is
// provably outside the subject's rooted flow is init-determined state
// and discharges; a rooted site, a closure-carried (unattributed)
// mark, and a TestMain-armed oracle keep the downgrade; and without
// the attestation nothing changes
// (REQ-closure-shared-dynamic-state,
// REQ-closure-shared-dynamic-state-reason).
func TestReachabilityScopedDischarge(t *testing.T) {
	memoTree := map[string]string{
		"go.mod":     "module example.com/view\n\ngo 1.26\n",
		"gen/gen.go": "package gen\n\nvar memo = map[string]func(){}\n\nfunc Compile(name string) { memo[name] = func() {} }\n\nfunc Size() int { return len(memo) }\n",
		"view.go":    "package view\n\nimport \"example.com/view/gen\"\n\nfunc F() int { return gen.Size() }\n\nfunc Property() { gen.Compile(\"k\") }\n",
	}
	captureFP := captureCheckFP
	t.Run("sibling-only mutator discharges attested", func(t *testing.T) {
		dir := writeModuleTree(t, memoTree)
		fingerprint, verdict := captureFP(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - no marking site of gen.memo is in F's rooted flow", verdict)
		}
		if fingerprint.SingleSubjectDischarges != "example.com/view/gen.memo" {
			t.Fatalf("evidence = %q, want the scoped-out culprit recorded - a load-bearing scoping is never silent", fingerprint.SingleSubjectDischarges)
		}
	})
	t.Run("unattested keeps the downgrade", func(t *testing.T) {
		dir := writeModuleTree(t, memoTree)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/gen.memo is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming gen.memo - the scoping is attestation-gated", verdict)
		}
	})
	t.Run("rooted mutator keeps the downgrade attested", func(t *testing.T) {
		dir := writeModuleTree(t, memoTree)
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "Property"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/gen.memo is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - the subject's own flow reaches the mutator", verdict)
		}
		// The re-judgment's surviving culprit carries the reason
		// contract too (REQ-closure-shared-dynamic-state-reason): this
		// leg publishes the per-subject culprit list's text, and a
		// mutable-local culprit names the directive-and-restructure
		// channel there exactly as the whole-package naming walk does.
		if !strings.Contains(verdict.Reason, "//gofresh:single-subject") || !strings.Contains(verdict.Reason, "restructuring") {
			t.Fatalf("verdict reason = %q, want the mutable-local discharge channel on the re-judged culprit", verdict.Reason)
		}
	})
	t.Run("stored-literal mark discharges through its unreached encloser", func(t *testing.T) {
		// The literal's marks are literal-borne sites of Register: the
		// value cannot exist unless Register runs, Register is neither
		// init-reachable nor in F's rooted flow, so under the
		// attestation neither the literal nor the stash assignment can
		// have executed. The foreclosures that keep the stored-value
		// hazard closed — an init-reachable or program-code-referenced
		// encloser, a top-level literal — are pinned by
		// TestLiteralBorneSiteForeclosures.
		dir := writeViewModule(t, "package view\n\nvar hooks = map[string]func(){}\n\nvar stash func()\n\nfunc Register() { stash = func() { hooks[\"k\"] = nil } }\n\nfunc F() int { return len(hooks) }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid under the amended literal-borne siting", verdict)
		}
	})
	t.Run("method-site mutator discharges attested", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nvar memo = map[string]func(){}\n\ntype filler struct{ n int }\n\nfunc (f *filler) Fill() { memo[\"k\"] = func() {} }\n\nfunc Property() {\n\tvar f filler\n\tf.Fill()\n}\n\nfunc F() int { return len(memo) }\n")
		fingerprint, verdict := captureFP(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the method-attributed site is outside F's rooted flow", verdict)
		}
		if fingerprint.SingleSubjectDischarges != "example.com/view.memo" {
			t.Fatalf("evidence = %q, want the scoped-out culprit recorded", fingerprint.SingleSubjectDischarges)
		}
	})
	t.Run("rooted method site keeps the downgrade attested", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nvar memo = map[string]func(){}\n\ntype filler struct{ n int }\n\nfunc (f *filler) Fill() { memo[\"k\"] = func() {} }\n\nfunc F() int {\n\tvar f filler\n\tf.Fill()\n\treturn len(memo)\n}\n")
		fingerprint, verdict := captureFP(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.memo is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - the subject's flow executes the method site", verdict)
		}
		if fingerprint.SingleSubjectDischarges != "" {
			t.Fatalf("evidence = %q, want nothing - no culprit was scoped out", fingerprint.SingleSubjectDischarges)
		}
	})
	t.Run("alias-receiver rooted method site keeps the downgrade", func(t *testing.T) {
		// The site key derives from the semantic unaliased receiver on
		// both sides: an alias-spelled receiver must not slip the
		// rooted-set match and discharge a site the subject executes.
		dir := writeViewModule(t, "package view\n\nvar memo = map[string]func(){}\n\ntype impl struct{ n int }\n\ntype alias = impl\n\nfunc (a *alias) Fill() { memo[\"k\"] = func() {} }\n\nfunc F() int {\n\tvar a alias\n\ta.Fill()\n\treturn len(memo)\n}\n")
		_, verdict := captureFP(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.memo is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - the alias-spelled site is the subject's own", verdict)
		}
	})
	t.Run("callable env-carrying var never discharges", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nvar hook func()\n\nfunc Register() {\n\tn := 0\n\thook = func() { n++ }\n}\n\nfunc F() bool { return hook == nil }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		// The inventory is per-variable and class-blind: the callable
		// env hazard forecloses every discharge for hook, so the
		// first-rank culprit text (the mutation's) survives.
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.hook is mutated") {
			t.Fatalf("verdict = %+v, want the refusal naming hook - a callable variable has a markless execution channel", verdict)
		}
	})
	t.Run("non-callable env-carrying discharges with its use sites", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\ntype holder struct{ fn func() }\n\nvar reg = &holder{}\n\nfunc Register() {\n\tn := 0\n\treg.fn = func() { n++ }\n}\n\nfunc F() int { return 1 }\n")
		fingerprint, verdict := captureFP(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the hazard executes only through marked sites, all outside F's rooted flow", verdict)
		}
		if fingerprint.SingleSubjectDischarges != "example.com/view.reg" {
			t.Fatalf("evidence = %q, want the scoped-out culprit recorded", fingerprint.SingleSubjectDischarges)
		}
	})
	t.Run("TestMain-armed oracle keeps the downgrade", func(t *testing.T) {
		dir := writeModuleTree(t, map[string]string{
			"go.mod":       "module example.com/view\n\ngo 1.26\n",
			"view.go":      "package view\n\nvar oracle func()\n\nfunc Touch() bool { return oracle == nil }\n",
			"view_test.go": "package view\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestMain(m *testing.M) {\n\toracle = func() {}\n\tos.Exit(m.Run())\n}\n\nfunc BenchmarkTouch(b *testing.B) {\n\tfor i := 0; i < b.N; i++ {\n\t\tTouch()\n\t}\n}\n",
		})
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "BenchmarkTouch"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.oracle is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming oracle - TestMain runs in the subject's process", verdict)
		}
	})
}

// The audited linkname-target floor names the true reason: a file
// whose every linkname names an audited target no longer masks the
// closure's remaining effects behind the opaque-linkage rank, while an
// unaudited linkname keeps the opaque floor
// (REQ-closure-blindspot).
func TestAuditedLinknameFloorNamesTrueReason(t *testing.T) {
	t.Run("audited linkname unmasks the remaining effects", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nimport \"unsafe\"\n\n//go:linkname runtimeGetAuxv runtime.getAuxv\nfunc runtimeGetAuxv() []uintptr\n\nfunc F() int {\n\tp := unsafe.Pointer(&struct{}{})\n\t_ = p\n\treturn len(runtimeGetAuxv())\n}\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || strings.Contains(verdict.Reason, "go:linkname") {
			t.Fatalf("verdict = %+v, want the remaining effects named without the opaque-linkage mask", verdict)
		}
	})
	t.Run("unaudited linkname keeps the opaque floor", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nimport _ \"unsafe\"\n\n//go:linkname runtimeRand runtime.rand\nfunc runtimeRand() uint64\n\nfunc F() uint64 { return runtimeRand() }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"})
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reaches go:linkname (opaque linkage)") {
			t.Fatalf("verdict = %+v, want the opaque-linkage floor", verdict)
		}
	})
}

// generatedProtoHeader is token-bound over the generator name: the
// canonical protoc-gen-go marker matches with a period or whitespace
// after the token, and every prefix-sharing sibling generator refuses
// (REQ-closure-shared-dynamic-state).
func TestGeneratedProtoHeaderTokenBound(t *testing.T) {
	for text, want := range map[string]string{
		"// Code generated by protoc-gen-go. DO NOT EDIT.":             "protoc-gen-go",
		"// Code generated by protoc-gen-go v1.34.1. DO NOT EDIT.":     "protoc-gen-go",
		"// Code generated by protoc-gen-go-grpc. DO NOT EDIT.":        "protoc-gen-go-grpc",
		"// Code generated by protoc-gen-go-grpc v1.5.1. DO NOT EDIT.": "protoc-gen-go-grpc",
		"// Code generated by protoc-gen-gogo. DO NOT EDIT.":           "",
		"// Code generated by protoc-gen-govalidators. DO NOT EDIT.":   "",
		"// Code generated by protoc-gen-go. KEEP EDITING.":            "",
		"// Code generated by protoc-gen-go":                           "",
	} {
		if got := generatedProtoHeader(text); got != want {
			t.Errorf("generatedProtoHeader(%q) = %q, want %q", text, got, want)
		}
	}
}

// The unattested execution model's binary-scoped reachability judgment
// (REQ-closure-shared-dynamic-state-reachability): sibling subjects in a shared
// process are themselves harness roots of the analyzed test binary, so
// a culprit no harness root's post-init flow reaches is
// init-determined for every subject of the binary — no attestation
// needed. Fail-closed on a rooted arming site, a benchmark root
// included, and on an ambiguous harness-named root.
func TestBinaryScopedReachabilityDischarge(t *testing.T) {
	wireTree := func(appTest string) map[string]string {
		tree := map[string]string{
			"go.mod":       "module example.com/view\n\ngo 1.26\n",
			"wire/wire.go": "package wire\n\nvar reg func() int\n\nfunc Arm() func() {\n\treg = func() int { return 1 }\n\treturn func() { reg = nil }\n}\n\nfunc Armed() bool { return reg != nil }\n",
			"app/app.go":   "package app\n\nimport \"example.com/view/wire\"\n\nfunc F() bool { return wire.Armed() }\n",
		}
		if appTest != "" {
			tree["app/app_test.go"] = appTest
		}
		return tree
	}
	const quietAppTest = "package app\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif !F() && F() {\n\t\tt.Fail()\n\t}\n}\n"
	subject := Subject{Package: "example.com/view/app", Symbol: "F"}
	t.Run("unrooted armer discharges under the attestation", func(t *testing.T) {
		t.Parallel()
		dir := writeModuleTree(t, wireTree(quietAppTest))
		fingerprint, verdict := captureCheckFP(t, dir, subject, withPackageProcessExecution())
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - no harness root of app's binary reaches wire.Arm, its literal disarm included", verdict)
		}
		if fingerprint.PackageProcessDischarges != "example.com/view/wire.reg" {
			t.Fatalf("evidence = %q, want the discharged culprit recorded - a load-bearing judgment is never silent", fingerprint.PackageProcessDischarges)
		}
	})
	t.Run("no attestation keeps the downgrade", func(t *testing.T) {
		t.Parallel()
		dir := writeModuleTree(t, wireTree(quietAppTest))
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/wire.reg is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - the binary-scoped judgment is attestation-gated: an unattested consumer may run the subject through any binary", verdict)
		}
	})
	t.Run("test-rooted armer keeps the downgrade", func(t *testing.T) {
		t.Parallel()
		dir := writeModuleTree(t, wireTree("package app\n\nimport (\n\t\"testing\"\n\n\t\"example.com/view/wire\"\n)\n\nfunc TestF(t *testing.T) {\n\tdisarm := wire.Arm()\n\tdefer disarm()\n\tif !F() {\n\t\tt.Fail()\n\t}\n}\n"))
		verdict := captureCheck(t, dir, subject, withPackageProcessExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/wire.reg is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming wire.reg - a harness root reaches the armer", verdict)
		}
	})
	t.Run("benchmark-rooted armer keeps the downgrade", func(t *testing.T) {
		t.Parallel()
		dir := writeModuleTree(t, wireTree("package app\n\nimport (\n\t\"testing\"\n\n\t\"example.com/view/wire\"\n)\n\nfunc BenchmarkF(b *testing.B) {\n\twire.Arm()\n\tfor i := 0; i < b.N; i++ {\n\t\tF()\n\t}\n}\n"))
		verdict := captureCheck(t, dir, subject, withPackageProcessExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/wire.reg is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a benchmark is a harness root exactly as a test is", verdict)
		}
	})
	t.Run("ambiguous harness root grants nothing", func(t *testing.T) {
		t.Parallel()
		tree := wireTree("package app\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tif !F() && F() {\n\t\tt.Fail()\n\t}\n}\n")
		tree["app/ext_test.go"] = "package app_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/view/app\"\n)\n\nfunc TestF(t *testing.T) {\n\t_ = app.F()\n}\n"
		dir := writeModuleTree(t, tree)
		verdict := captureCheck(t, dir, subject, withPackageProcessExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/wire.reg is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a tombstoned harness name leaves the binary's inventory incomplete", verdict)
		}
	})
	t.Run("harness-library literal armer discharges when its runner is unrooted", func(t *testing.T) {
		t.Parallel()
		// The conformance-library shape: a shared test-harness package
		// arms the oracle inside a subtest literal of a named runner.
		// A binary that links the library without any root calling the
		// runner cannot execute the literal — the reference records as
		// a lit-region bounded by the runner, never bare "prog", so
		// the armer stays un-init-reachable and the disarm literal's
		// marks site on it.
		tree := wireTree("package app\n\nimport (\n\t\"testing\"\n\n\t\"example.com/view/kit\"\n)\n\nfunc TestF(t *testing.T) {\n\tif kit.Helper() != 1 {\n\t\tt.Fail()\n\t}\n\t_ = F()\n}\n")
		tree["kit/kit.go"] = "package kit\n\nimport \"example.com/view/wire\"\n\nfunc Helper() int { return 1 }\n\nfunc run(f func()) { f() }\n\nfunc Conformance() {\n\trun(func() {\n\t\tdisarm := wire.Arm()\n\t\tdisarm()\n\t})\n}\n"
		dir := writeModuleTree(t, tree)
		verdict := captureCheck(t, dir, subject, withPackageProcessExecution())
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - no root reaches the library's runner, so neither the subtest literal nor the armer can run", verdict)
		}
	})
	t.Run("harness-library runner rooted keeps the downgrade", func(t *testing.T) {
		t.Parallel()
		tree := wireTree("package app\n\nimport (\n\t\"testing\"\n\n\t\"example.com/view/kit\"\n)\n\nfunc TestF(t *testing.T) {\n\tkit.Conformance()\n\t_ = F()\n}\n")
		tree["kit/kit.go"] = "package kit\n\nimport \"example.com/view/wire\"\n\nfunc Helper() int { return 1 }\n\nfunc run(f func()) { f() }\n\nfunc Conformance() {\n\trun(func() {\n\t\tdisarm := wire.Arm()\n\t\tdisarm()\n\t})\n}\n"
		dir := writeModuleTree(t, tree)
		verdict := captureCheck(t, dir, subject, withPackageProcessExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/wire.reg is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a root runs the conformance runner, whose literal arms", verdict)
		}
	})
	t.Run("fuzz-rooted armer keeps the downgrade", func(t *testing.T) {
		t.Parallel()
		tree := wireTree("package app\n\nimport (\n\t\"testing\"\n\n\t\"example.com/view/wire\"\n)\n\nfunc FuzzF(f *testing.F) {\n\tdisarm := wire.Arm()\n\tdisarm()\n\t_ = F()\n}\n")
		dir := writeModuleTree(t, tree)
		verdict := captureCheck(t, dir, subject, withPackageProcessExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/wire.reg is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a fuzz target is a harness root and its literal arms", verdict)
		}
	})
	t.Run("testmain-flow armer keeps the downgrade", func(t *testing.T) {
		t.Parallel()
		tree := wireTree("package app\n\nimport (\n\t\"os\"\n\t\"testing\"\n\n\t\"example.com/view/wire\"\n)\n\nfunc TestMain(m *testing.M) {\n\twire.Arm()\n\tos.Exit(m.Run())\n}\n\nfunc TestF(t *testing.T) {\n\tif !F() {\n\t\tt.Fail()\n\t}\n}\n")
		dir := writeModuleTree(t, tree)
		verdict := captureCheck(t, dir, subject, withPackageProcessExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/wire.reg is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - every root rides the user TestMain flow, which arms", verdict)
		}
	})
	t.Run("open-world harness-named root leaves the inventory incomplete", func(t *testing.T) {
		t.Parallel()
		// The harness filter is name-only, so a PRODUCTION-file
		// generic with a harness name joins the root set (test files
		// cannot declare one — the go tool refuses); unbounded and
		// dynamic-receiving, it reads open-world and the whole
		// binary's inventory grants nothing.
		tree := wireTree(quietAppTest)
		tree["app/generic.go"] = "package app\n\nfunc TestGadget[T any](v T) any {\n\tvar out any = v\n\treturn out\n}\n"
		dir := writeModuleTree(t, tree)
		verdict := captureCheck(t, dir, subject, withPackageProcessExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view/wire.reg is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - an open-world harness-named root grants nothing", verdict)
		}
	})
	t.Run("no harness roots discharges vacuously", func(t *testing.T) {
		t.Parallel()
		dir := writeModuleTree(t, wireTree(""))
		verdict := captureCheck(t, dir, subject, withPackageProcessExecution())
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - a binary with no harness roots executes nothing past initialization", verdict)
		}
	})
}

// Literal-borne sites attribute to their enclosing named declaration
// for the reachability scopings, with the two foreclosures that keep
// the stored-value hazard closed: an encloser the init flow reaches
// (an init-created literal outlives initialization through a store)
// and an encloser referenced from program code — another literal — no
// named caller carries (REQ-closure-shared-dynamic-state).
func TestLiteralBorneSiteForeclosures(t *testing.T) {
	t.Run("init-reachable encloser forecloses", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nvar hooks = map[string]func(){}\n\nvar stash func()\n\nvar _ = arm()\n\nfunc arm() int {\n\tstash = func() { hooks[\"k\"] = nil }\n\treturn 0\n}\n\nfunc F() int { return len(hooks) }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming hooks - the init flow created the literal, and a stored literal outlives initialization", verdict)
		}
	})
	t.Run("literal-context reference resolves through its own encloser", func(t *testing.T) {
		// arm is referenced only from a literal inside Wire: the
		// lit-region bounds the reference by Wire, and with neither
		// Wire nor arm in F's rooted flow the whole chain is dead —
		// relay can never hold the value, so the stored literal can
		// never run.
		dir := writeViewModule(t, "package view\n\nvar hooks = map[string]func(){}\n\nvar stash func()\n\nvar relay func()\n\nfunc arm() { stash = func() { hooks[\"k\"] = nil } }\n\nfunc Wire() { relay = func() { arm() } }\n\nfunc F() int { return len(hooks) }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the literal-context reference is bounded by its unreached encloser", verdict)
		}
	})
	t.Run("method-context reference stays prog and forecloses", func(t *testing.T) {
		// A method body is outside the named-function fixed point:
		// a reference from it records bare "prog", the armer reads
		// init-reachable, and the literal's marks foreclose.
		dir := writeViewModule(t, "package view\n\nvar hooks = map[string]func(){}\n\nvar stash func()\n\ntype wirer struct{ n int }\n\nfunc (w *wirer) Wire() { arm() }\n\nfunc arm() { stash = func() { hooks[\"k\"] = nil } }\n\nfunc F() int { return len(hooks) }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a method-context reference gives the regions no bound", verdict)
		}
	})
	t.Run("init-called method's literal forecloses", func(t *testing.T) {
		// The reference regions cannot see method calls, so a method
		// encloser's init reach is unknowable — and this one IS
		// init-called: its stored literal outlives initialization.
		dir := writeViewModule(t, "package view\n\nvar hooks = map[string]func(){}\n\nvar stash func()\n\ntype armer struct{ n int }\n\nfunc (armer) arm() { stash = func() { hooks[\"k\"] = nil } }\n\nfunc init() { armer{}.arm() }\n\nfunc F() int { return len(hooks) }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - an init-created method literal escapes no foreclosure", verdict)
		}
	})
	t.Run("method-encloser literal forecloses even unrooted", func(t *testing.T) {
		// Fail-closed uniformly: methods are outside the
		// reference-region graph, so even an apparently-unreached
		// method encloser gives its literal marks no bound.
		dir := writeViewModule(t, "package view\n\nvar hooks = map[string]func(){}\n\nvar stash func()\n\ntype armer struct{ n int }\n\nfunc (armer) arm() { stash = func() { hooks[\"k\"] = nil } }\n\nfunc F() int { return len(hooks) }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a method encloser's init reach is unknowable", verdict)
		}
	})
	t.Run("carrier method use inside a literal sites on the encloser", func(t *testing.T) {
		// The frameAccounting shape reduced: the carrier is written
		// only through an unproven method, called from a literal
		// nested in an unreached plain function.
		dir := writeViewModule(t, "package view\n\ntype reg struct{ m map[string]func() }\n\nfunc (r *reg) Add(k string) { r.m[k] = func() {} }\n\nvar acct = reg{m: map[string]func(){}}\n\nfunc Arm() func() {\n\treturn func() { acct.Add(\"k\") }\n}\n\nfunc F() int { return 1 }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the literal's carrier method use sites on unreached Arm", verdict)
		}
	})
	t.Run("carrier method use in an init-only encloser's literal forecloses", func(t *testing.T) {
		// The literal-borne method-use class must never ride the
		// init-only discharge: the encloser ran at init, but the
		// stored literal outlives it.
		dir := writeViewModule(t, "package view\n\ntype reg struct{ m map[string]func() }\n\nfunc (r *reg) Add(k string) { r.m[k] = func() {} }\n\nvar acct = reg{m: map[string]func(){}}\n\nvar stash func()\n\nvar _ = arm()\n\nfunc arm() int {\n\tstash = func() { acct.Add(\"k\") }\n\treturn 0\n}\n\nfunc F() int { return 1 }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.acct is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - the init-created literal's method use outlives initialization", verdict)
		}
	})
	t.Run("carrier method use in a method-encloser literal forecloses", func(t *testing.T) {
		// The dl class composes with the same method-encloser
		// foreclosure as plain literal marks: the wrapper method's
		// init reach is unknowable, so its literal's carrier method
		// use keeps the downgrade even though nothing visibly calls
		// the wrapper.
		dir := writeViewModule(t, "package view\n\ntype reg struct{ m map[string]func() }\n\nfunc (r *reg) Add(k string) { r.m[k] = func() {} }\n\nvar acct = reg{m: map[string]func(){}}\n\ntype wrapper struct{ n int }\n\nfunc (wrapper) Arm() func() {\n\treturn func() { acct.Add(\"k\") }\n}\n\nfunc F() int { return 1 }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.acct is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a method encloser bounds nothing", verdict)
		}
	})
	t.Run("top-level literal keeps foreclosing", func(t *testing.T) {
		dir := writeViewModule(t, "package view\n\nvar hooks = map[string]func(){}\n\nvar stash = func() { hooks[\"k\"] = nil }\n\nfunc F() int { return len(hooks) }\n")
		verdict := captureCheck(t, dir, Subject{Package: "example.com/view", Symbol: "F"}, withSingleSubjectExecution())
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/view.hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a package-level literal has no named encloser and its marks stay unattributed", verdict)
		}
	})
}

// An exported registration constructor called only from package-level
// initializers - its own package's and a sibling's - proves init-only
// across the graph, and the registry mutation inside it is startup
// flow; one program-code caller anywhere poisons the proof
// (REQ-closure-shared-dynamic-state-init-flow).
func TestCrossPackageInitOnlyRegistration(t *testing.T) {
	files := map[string]string{
		"go.mod":       "module example.com/xreg\n\ngo 1.26\n",
		"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc NewKey(name string) string {\n\tHooks[name] = func() {}\n\treturn name\n}\n\nvar _ = NewKey(\"own\")\n\nfunc Count() int { return len(Hooks) }\n",
		"user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.NewKey(\"sibling\")\n\nfunc F() int { return reg.Count() }\n",
	}
	t.Run("initializer-only callers discharge", func(t *testing.T) {
		dir := writeModuleTree(t, files)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - initializer-only registration downgraded", verdict)
		}
	})
	t.Run("explicit generic instantiation discharges", func(t *testing.T) {
		generic := map[string]string{
			"go.mod":       files["go.mod"],
			"reg/reg.go":   "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc NewKey[T any](name string) string {\n\tHooks[name] = func() {}\n\treturn name\n}\n\nvar _ = NewKey[int](\"own\")\n\nfunc Count() int { return len(Hooks) }\n",
			"user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.NewKey[string](\"sibling\")\n\nfunc F() int { return reg.Count() }\n",
		}
		dir := writeModuleTree(t, generic)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - explicit instantiation read as a value reference", verdict)
		}
	})
	t.Run("nested literal in attributed function stays program code", func(t *testing.T) {
		lit := map[string]string{"go.mod": files["go.mod"], "reg/reg.go": "package reg\n\nvar Hooks = map[string]func(){}\n\nvar Run func()\n\nfunc Setup(name string) string {\n\tRun = func() { Hooks[name] = func() {} }\n\treturn name\n}\n\nfunc Count() int { return len(Hooks) }\n", "user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.Setup(\"sibling\")\n\nfunc Late() { reg.Run() }\n\nfunc F() int { return reg.Count() }\n"}
		dir := writeModuleTree(t, lit)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a runtime-callable literal discharged with its function", verdict)
		}
	})
	t.Run("go statement in attributed function stays program code", func(t *testing.T) {
		gost := map[string]string{"go.mod": files["go.mod"], "reg/reg.go": "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc Setup(name string) string {\n\tgo func() { Hooks[name] = func() {} }()\n\treturn name\n}\n\nfunc Count() int { return len(Hooks) }\n", "user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.Setup(\"sibling\")\n\nfunc F() int { return reg.Count() }\n"}
		dir := writeModuleTree(t, gost)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - a goroutine discharged with its function", verdict)
		}
	})
	t.Run("go statement call argument stays program code", func(t *testing.T) {
		// The carrier use sits in the go statement's ARGUMENT list, not
		// nested in a function literal: only the go-statement half of the
		// interiors walk keeps it program code. The goroutine outlives
		// initialization and writes Hooks at runtime, so discharging the
		// escape with the proven function would be unsound.
		goarg := map[string]string{"go.mod": files["go.mod"], "reg/reg.go": "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc spill(m map[string]func()) { m[\"late\"] = func() {} }\n\nfunc Setup(name string) string {\n\tgo spill(Hooks)\n\treturn name\n}\n\nfunc Count() int { return len(Hooks) }\n", "user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.Setup(\"sibling\")\n\nfunc F() int { return reg.Count() }\n"}
		dir := writeModuleTree(t, goarg)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Hooks - a go-statement call argument discharged with its attributed function", verdict)
		}
	})
	t.Run("transitive chain discharges", func(t *testing.T) {
		chain := map[string]string{"go.mod": files["go.mod"], "reg/reg.go": "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc Outer(name string) string { return inner(name) }\n\nfunc inner(name string) string {\n\tHooks[name] = func() {}\n\treturn name\n}\n\nfunc Count() int { return len(Hooks) }\n", "user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.Outer(\"sibling\")\n\nfunc F() int { return reg.Count() }\n"}
		dir := writeModuleTree(t, chain)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Valid {
			t.Fatalf("verdict = %+v, want Valid - the chain did not resolve", verdict)
		}
	})
	t.Run("unproven attributed caller poisons", func(t *testing.T) {
		unproven := map[string]string{"go.mod": files["go.mod"], "reg/reg.go": "package reg\n\nvar Hooks = map[string]func(){}\n\nfunc Outer(name string) string { return inner(name) }\n\nfunc inner(name string) string {\n\tHooks[name] = func() {}\n\treturn name\n}\n\nfunc Count() int { return len(Hooks) }\n", "user/user.go": "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.Outer(\"sibling\")\n\nfunc Caller() string { return reg.Outer(\"late\") }\n\nfunc F() int { return reg.Count() }\n"}
		dir := writeModuleTree(t, unproven)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade - an unproven caller resolved", verdict)
		}
	})
	t.Run("program-code caller poisons", func(t *testing.T) {
		poisoned := map[string]string{}
		for k, v := range files {
			poisoned[k] = v
		}
		poisoned["user/user.go"] = "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.NewKey(\"sibling\")\n\nfunc Late() string { return reg.NewKey(\"late\") }\n\nfunc F() int { return reg.Count() }\n"
		dir := writeModuleTree(t, poisoned)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Hooks", verdict)
		}
	})
	t.Run("value reference poisons", func(t *testing.T) {
		poisoned := map[string]string{}
		for k, v := range files {
			poisoned[k] = v
		}
		poisoned["user/user.go"] = "package user\n\nimport \"example.com/xreg/reg\"\n\nvar K = reg.NewKey(\"sibling\")\n\nvar Ctor = reg.NewKey\n\nfunc F() int { return reg.Count() }\n"
		dir := writeModuleTree(t, poisoned)
		subject := Subject{Package: "example.com/xreg/user", Symbol: "F"}
		verdict := captureCheck(t, dir, subject)
		if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "reg.Hooks is mutated") {
			t.Fatalf("verdict = %+v, want the downgrade naming reg.Hooks", verdict)
		}
	})
}

func TestExplainBlockedExportedSeamCrossPackageCaller(t *testing.T) {
	t.Parallel()
	baseTree := func(callerTestSrc string) map[string]string {
		return map[string]string{
			"go.mod": "module example.com/xseam\n\ngo 1.26\n",
			"seam/seam.go": `package seam

var probe func() int

func WithProbe(fn func() int, body func()) {
	orig := probe
	defer func() { probe = orig }()
	probe = fn
	body()
}

func Value() int {
	if probe != nil {
		return probe()
	}
	return 1
}
`,
			"app/app.go":      "package app\n\nimport \"example.com/xseam/seam\"\n\nfunc Run() int { return seam.Value() }\n",
			"app/app_test.go": callerTestSrc,
		}
	}

	seqDir := writeModuleTree(t, baseTree(`package app_test

import (
	"testing"
	"example.com/xseam/app"
	"example.com/xseam/seam"
)

func TestClean(t *testing.T) {
	if got := app.Run(); got != 1 {
		t.Fatalf("got %d", got)
	}
}

func TestSequentialSeam(t *testing.T) {
	seam.WithProbe(func() int { return 9 }, func() {
		_ = app.Run()
	})
}
`))
	if verdict := captureCheck(t, seqDir, Subject{Package: "example.com/xseam/app", Symbol: "TestClean"}, withPackageProcessExecution()); verdict.Status != Valid {
		t.Fatalf("sequential cross-package seam verdict = %+v, want Valid", verdict)
	}

	parDir := writeModuleTree(t, baseTree(`package app_test

import (
	"testing"
	"example.com/xseam/app"
	"example.com/xseam/seam"
)

func TestClean(t *testing.T) {
	if got := app.Run(); got != 1 {
		t.Fatalf("got %d", got)
	}
}

func TestParallelSeam(t *testing.T) {
	t.Parallel()
	seam.WithProbe(func() int { return 9 }, func() {
		_ = app.Run()
	})
}
`))
	verdict := captureCheck(t, parDir, Subject{Package: "example.com/xseam/app", Symbol: "TestClean"}, withPackageProcessExecution())
	if verdict.Status != Unverifiable || !strings.Contains(verdict.Reason, "example.com/xseam/seam.probe is mutated") {
		t.Fatalf("parallel cross-package seam verdict = %+v, want downgrade naming example.com/xseam/seam.probe", verdict)
	}
	chain := explainViewForSubject(t, parDir, Subject{Package: "example.com/xseam/app", Symbol: "TestClean"}, "example.com/xseam/seam", "probe")
	if chain.Arm != "mutation" || len(chain.Links) == 0 {
		t.Fatalf("ExplainDynamicState(seam.probe) = %+v, want non-empty mutation chain", chain)
	}

	// Cross-package .Parallel() helper (testutil.EnterParallel) tainting both an exported seam
	// and an unexported intra-package seam under PackageExecution + ExplainDynamicState.
	helperTree := baseTree(`package app_test

import (
	"testing"
	"example.com/xseam/app"
	"example.com/xseam/seam"
	"example.com/xseam/testutil"
)

func TestClean(t *testing.T) {
	if got := app.Run(); got != 1 {
		t.Fatalf("got %d", got)
	}
}

func TestViaCrossPkgParallelHelper(t *testing.T) {
	testutil.EnterParallel(t)
	seam.WithProbe(func() int { return 9 }, func() {
		_ = app.Run()
	})
}
`)
	helperTree["testutil/testutil.go"] = "package testutil\n\nimport \"testing\"\n\nfunc EnterParallel(t *testing.T) { t.Parallel() }\n"
	helperTree["app/internal_seam_test.go"] = `package app

import (
	"testing"
	"example.com/xseam/testutil"
)

var localHook func() int

func withLocalHook(fn func() int, body func()) {
	orig := localHook
	defer func() { localHook = orig }()
	localHook = fn
	body()
}

func TestUnexportedViaCrossPkgParallel(t *testing.T) {
	testutil.EnterParallel(t)
	withLocalHook(func() int { return 4 }, func() {})
}
`
	helperDir := writeModuleTree(t, helperTree)
	helperVerdict := captureCheck(t, helperDir, Subject{Package: "example.com/xseam/app", Symbol: "TestClean"}, withPackageProcessExecution())
	if helperVerdict.Status != Unverifiable {
		t.Fatalf("cross-package .Parallel helper verdict = %+v, want Unverifiable", helperVerdict)
	}
	for _, wantSym := range []struct {
		pkg string
		sym string
	}{
		{pkg: "example.com/xseam/seam", sym: "probe"},
		{pkg: "example.com/xseam/app", sym: "localHook"},
	} {
		c := explainViewForSubject(t, helperDir, Subject{Package: "example.com/xseam/app", Symbol: "TestClean"}, wantSym.pkg, wantSym.sym)
		if c.Arm != "mutation" || len(c.Links) == 0 {
			t.Fatalf("ExplainDynamicState(%s.%s) = %+v, want non-empty mutation chain", wantSym.pkg, wantSym.sym, c)
		}
	}

	// Stdlib maps.Copy populating a package-level map with a .Parallel() helper
	// taints callers reading that map under real go/packages stdlib loading.
	mapsCopyTree := baseTree(`package app_test

import (
	"maps"
	"testing"
	"example.com/xseam/app"
	"example.com/xseam/seam"
	"example.com/xseam/testutil"
)

func init() {
	cp := maps.Copy[map[string]func(*testing.T), map[string]func(*testing.T)]
	cp(testutil.HookMap, map[string]func(*testing.T){"k": testutil.EnterParallel})
}

func TestClean(t *testing.T) {
	if got := app.Run(); got != 1 {
		t.Fatalf("got %d", got)
	}
}

func TestViaStdlibMapsCopy(t *testing.T) {
	testutil.RunHookMap(t)
	seam.WithProbe(func() int { return 9 }, func() {
		_ = app.Run()
	})
}
`)
	mapsCopyTree["testutil/testutil.go"] = "package testutil\n\nimport \"testing\"\n\nvar enterMap = map[string]func(*testing.T){}\nvar HookMap = enterMap\n\nfunc EnterParallel(t *testing.T) { t.Parallel() }\nfunc RunHookMap(t *testing.T) { enterMap[\"k\"](t) }\n"
	mapsCopyDir := writeModuleTree(t, mapsCopyTree)
	mapsCopyVerdict := captureCheck(t, mapsCopyDir, Subject{Package: "example.com/xseam/app", Symbol: "TestClean"}, withPackageProcessExecution())
	if mapsCopyVerdict.Status != Unverifiable || !strings.Contains(mapsCopyVerdict.Reason, "example.com/xseam/seam.probe is mutated") {
		t.Fatalf("stdlib maps.Copy .Parallel verdict = %+v, want Unverifiable naming example.com/xseam/seam.probe", mapsCopyVerdict)
	}
}
