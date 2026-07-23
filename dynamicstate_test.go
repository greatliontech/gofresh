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
}

func runScan(t *testing.T, scope, dir string, pkgPaths ...string) scanResult {
	t.Helper()
	hasher, err := closure.NewAtContextEnv(context.Background(), dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	pure, known, openWorld, external, _, err := scanViewSubjects(context.Background(), hasher, scope, dir, os.Environ(), nil, pkgPaths...)
	if err != nil {
		t.Fatal(err)
	}
	result := scanResult{known: known, openWorld: openWorld, external: external, pure: map[Subject]bool{}}
	for subject := range known {
		if pure(subject) {
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
	dynamicStateMissLoadHook = func(patterns []string) {
		missLoads = append(missLoads, append([]string(nil), patterns...))
	}
	defer func() { dynamicStateMissLoadHook = nil }()
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

var Hook func()

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
	if !contains(restored.Mutates, wantKey) || !contains(restored.Declares, wantKey) {
		t.Fatalf("fact lost mutation content: %+v", restored)
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
	if before.openWorld[subject] {
		t.Fatal("unmutated hook already downgraded the subject")
	}
	mutated := depSource + "\nfunc Rebind() { Hook = nil }\n"
	if err := os.WriteFile(filepath.Join(dir, "dep", "dep.go"), []byte(mutated), 0o644); err != nil {
		t.Fatal(err)
	}
	after := runScan(t, scope, dir, pkg)
	if !after.openWorld[subject] {
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
	if before.openWorld[subject] {
		t.Fatal("an int-typed hook already downgraded the subject")
	}
	if err := os.WriteFile(filepath.Join(dir, "y", "y.go"), []byte("package y\n\ntype T func()\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := runScan(t, scope, dir, pkg)
	if !after.openWorld[subject] {
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
	if !result.openWorld[subject] {
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
