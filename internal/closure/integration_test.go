package closure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/cachefile"
	progpkg "github.com/greatliontech/gofresh/internal/closure/internal/program"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"go/types"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/pprof"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// The fold's unnamed-import binding is pinned against the toolchain's
// own package names: for every importable standard package the derived
// identifier is the declared one, so a release adding a path whose
// declared name the rule cannot derive fails here instead of opening a
// silent fold hole (REQ-closure-observability-declaration-bindings).
func TestImplicitImportNameMatchesTheToolchain(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	out, err := exec.Command("go", "list", "-f", "{{.ImportPath}} {{.Name}}", "std").Output()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] == "main" || strings.HasPrefix(fields[0], "internal/") || strings.Contains(fields[0], "/internal/") || strings.HasPrefix(fields[0], "vendor/") {
			continue
		}
		checked++
		if got := implicitImportName(fields[0]); got != fields[1] {
			t.Errorf("implicitImportName(%q) = %q, the toolchain declares %q", fields[0], got, fields[1])
		}
	}
	if checked < 100 {
		t.Fatalf("checked %d importable standard packages, want the whole library", checked)
	}
}

// TestMaximalHashReal exercises the Tier-1 maximal pipeline against a real
// package (store, which pulls in the benchfmt cache dep), validating determinism
// and cross-module classification (a src: contribution for the main module,
// cache: for benchfmt). maximalHash is the A′ widening target (REQ-closure-blindspot).
func TestMaximalHashReal(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/gotool"
	a, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatalf("maximalHash: %v", err)
	}
	if len(a) != 32 {
		t.Errorf("hash len: got %d (%q)", len(a), a)
	}
	if b, _ := h.maximalHash(pkg); b != a {
		t.Errorf("hash not deterministic: %q vs %q", a, b)
	}
}

// TestListMemoizes pins the per-package listing cache: two calls for the same
// package path return the identical backing slice (proving the second reused the
// memo rather than re-running the `go list` subprocess), and the content is the
// same. The efficiency claim is that N benchmarks in a package pay one listing;
// the observable proxy is memo identity.
func TestListMemoizes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	h, err := newAt("")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/gotool"
	first, err := h.list(pkg)
	if err != nil {
		t.Fatalf("list (first): %v", err)
	}
	if len(first) == 0 {
		t.Fatal("list returned no packages")
	}
	second, err := h.list(pkg)
	if err != nil {
		t.Fatalf("list (second): %v", err)
	}
	if len(second) != len(first) {
		t.Fatalf("second listing len %d != first %d", len(second), len(first))
	}
	// Same backing array ⇒ the second call hit the memo, not a fresh subprocess.
	if &first[0] != &second[0] {
		t.Error("list did not memoize: second call returned a distinct slice")
	}
}

func TestListUsesBuildFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/tagged\n\ngo 1.26\n")
	writeFile(t, dir, "selected_default.go", "//go:build !special\n\npackage tagged\n\nfunc Selected() int { return 1 }\n")
	writeFile(t, dir, "selected_special.go", "//go:build special\n\npackage tagged\n\nfunc Selected() int { return 2 }\n")

	h, err := newAt(dir, "-tags=special")
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := h.list("example.com/tagged")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if p.ImportPath != "example.com/tagged" {
			continue
		}
		if !stringSliceContains(p.GoFiles, "selected_special.go") || stringSliceContains(p.GoFiles, "selected_default.go") {
			t.Fatalf("selected Go files = %v, want only special variant", p.GoFiles)
		}
		return
	}
	t.Fatal("go list omitted the tagged package")
}

// TestRecompiledDependencyStaysOutOfSubjectRoots pins subject rooting
// (REQ-closure-analysis): the reachability walk roots at the subject, so the
// candidate-root index for a package must come only from that package's own
// variants. `go list` marks every package recompiled into the test binary with
// ForTest — including an intermediate dependency (a's external test imports r,
// r imports a → "r [a.test]") — but the dependency's top-level functions are
// not subjects of the tested package: a name shared with the tested package
// must not read as an ambiguous root, and a name the tested package never
// declares must be refused, never silently resolved to the dependency's
// closure.
func TestRecompiledDependencyStaysOutOfSubjectRoots(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	writeTriangle := func(t *testing.T, aSource, rSource string) string {
		t.Helper()
		dir := t.TempDir()
		for name, content := range map[string]string{
			"go.mod": "module example.com/triangle\n\ngo 1.26\n",
			"a/a.go": aSource,
			// The in-package test file makes "a [a.test]" a distinct variant, so
			// r — importing a, imported by a's external test — is recompiled
			// against it as "r [a.test]" with ForTest set.
			"a/in_test.go":  "package a\n\nimport \"testing\"\n\nfunc TestInternal(t *testing.T) {}\n",
			"a/ext_test.go": "package a_test\n\nimport (\n\t\"testing\"\n\n\t\"example.com/triangle/r\"\n)\n\nfunc TestExternal(t *testing.T) { r.Use() }\n",
			"r/r.go":        rSource,
		} {
			path := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		// The assertions below hold vacuously if the recompiled dependency
		// variant stops materializing, so its presence is load-bearing.
		cfg := &packages.Config{
			Mode:  packages.NeedName | packages.NeedForTest | packages.NeedImports | packages.NeedDeps,
			Tests: true,
			Dir:   dir,
		}
		loaded, err := packages.Load(cfg, "example.com/triangle/a")
		if err != nil {
			t.Fatalf("variant guard load: %v", err)
		}
		variant := false
		packages.Visit(loaded, nil, func(p *packages.Package) {
			if p.PkgPath == "example.com/triangle/r" && p.ForTest == "example.com/triangle/a" {
				variant = true
			}
		})
		if !variant {
			t.Fatal("fixture no longer yields the recompiled dependency variant r [a.test]; the assertions below would hold vacuously")
		}
		return dir
	}

	t.Run("shared name is no root collision", func(t *testing.T) {
		dir := writeTriangle(t,
			"package a\n\nfunc G() {}\n",
			"package r\n\nimport \"example.com/triangle/a\"\n\nfunc Use() { a.G() }\n\nfunc G() {}\n",
		)
		h, err := NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()))
		if err != nil {
			t.Fatalf("NewAt: %v", err)
		}
		_, reach, err := computeTier2ResultAndReach(h, "example.com/triangle/a", "G")
		if err != nil {
			t.Fatalf("analysis of a.G with a same-named dependency symbol: %v", err)
		}
		if len(reach) == 0 {
			t.Fatal("empty reachability for a's own G")
		}
	})

	t.Run("dependency symbol is not rootable under the tested package", func(t *testing.T) {
		dir := writeTriangle(t,
			"package a\n\nfunc A() {}\n",
			"package r\n\nimport \"example.com/triangle/a\"\n\nfunc Use() { a.A() }\n",
		)
		h, err := NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()))
		if err != nil {
			t.Fatalf("NewAt: %v", err)
		}
		fixtures := newFixturePrograms(t, h)
		fixtures.supply(t, "example.com/triangle/a")
		if _, reach, err := computeTier2ResultAndReach(h, "example.com/triangle/a", "A"); err != nil || len(reach) == 0 {
			t.Fatalf("analysis of a.A: reach %v, %v; want a's own subject to resolve", reach, err)
		}
		fixtures.supply(t, "example.com/triangle/a")
		if _, err := computeTier2Result(h, "example.com/triangle/a", "Use"); err == nil {
			t.Fatal("analysis of a.Use: want an error (a never declares Use), got the recompiled dependency's closure")
		}
	})
}

func TestOpenFileFlagsUseSelectedGOOS(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over the fixture corpus")
	}
	env := append([]string(nil), os.Environ()...)
	found := false
	for i, entry := range env {
		if strings.HasPrefix(entry, "GOOS=") {
			env[i] = "GOOS=plan9"
			found = true
		}
	}
	if !found {
		env = append(env, "GOOS=plan9")
	}
	h, err := newAtEnv(context.Background(), "", env)
	if err != nil {
		t.Fatal(err)
	}
	const pkg = "github.com/greatliontech/gofresh/internal/closure/testdata/observablefresh"
	subjects := []Subject{
		{Package: pkg, Symbol: "TestTempDirOpenFile"},
		{Package: pkg, Symbol: "TestOpenFileUnknownFlags"},
	}
	results, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if !results[subjects[0]].Observable {
		t.Fatalf("Plan 9 recognized flags = %+v, want observable", results[subjects[0]])
	}
	if results[subjects[1]].Observable {
		t.Fatalf("Plan 9 unknown flags = %+v, want blocked", results[subjects[1]])
	}
}

// The toolchain-audit canary: the running toolchain's audited standard-library
// surface satisfies the structural AST and directive contracts across standard
// build selections.
func TestAuditedToolchainCoversRunningToolchain(t *testing.T) {
	if testing.Short() {
		t.Skip("toolchain integration test")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	for _, sel := range []struct {
		suffix string
		env    []string
		flags  []string
	}{
		{"", nil, nil},
		{" race", nil, []string{"-race"}},
		{" plan9/amd64", []string{"GOOS=plan9", "GOARCH=amd64"}, nil},
		{" cgo0", []string{"CGO_ENABLED=0"}, nil},
	} {
		h, err := newAtEnv(context.Background(), ".", environmentWith(sel.env...), sel.flags...)
		if err != nil {
			t.Fatal(err)
		}
		if !h.SelectionAudited() {
			t.Fatalf("inspected toolchain under %v %v failed structural verification — %s", sel.env, sel.flags, h.SelectionNotice())
		}
	}
}

func TestPGOBuildCopiesRetainImportBindings(t *testing.T) {
	if testing.Short() {
		t.Skip("lists and builds a main-package test binary with a real PGO profile")
	}
	const pkg = "example.com/pgobindings"
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":            "module " + pkg + "\n\ngo 1.27.0\n",
		"main.go":           "package main\nimport \"example.com/pgobindings/dependency\"\nfunc main() { declared.Value() }\n",
		"main_test.go":      "package main\nimport (\"testing\"; \"example.com/pgobindings/dependency\")\nfunc TestValue(t *testing.T) { if declared.Value() != 1 { t.Fatal(\"wrong value\") } }\n",
		"dependency/dep.go": "package declared\nfunc Value() int { return 1 }\n",
	})
	var profile bytes.Buffer
	if err := pprof.StartCPUProfile(&profile); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Millisecond)
	for time.Now().Before(deadline) {
	}
	pprof.StopCPUProfile()
	if err := os.WriteFile(filepath.Join(dir, "default.pgo"), profile.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	hCtrl, err := NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()), "-pgo=off")
	if err != nil {
		t.Fatal(err)
	}
	control, err := hCtrl.TestVariantLedger(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !testvariant.DiffTestVariantLedgers(control, control).Inert() {
		t.Fatal("ordinary ledger control has incomplete binding evidence")
	}
	for _, flags := range [][]string{nil, {"-pgo=auto"}, {"-pgo=" + filepath.Join(dir, "default.pgo")}} {
		h, err := NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()), flags...)
		if err != nil {
			t.Fatal(err)
		}
		listed, err := h.list(pkg)
		if err != nil {
			t.Fatal(err)
		}
		decorated := false
		for _, p := range listed {
			if p.SourcePath() == "testing" && p.ImportPath != p.SourcePath() {
				decorated = true
			}
		}
		if !decorated && len(flags) == 0 {
			t.Fatal("default-PGO fixture did not produce the decorated dependency")
		}
		ledger, err := h.TestVariantLedger(pkg)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(ledger, control) {
			t.Fatalf("PGO changed source-name binding evidence under %v:\n got %+v\nwant %+v", flags, ledger, control)
		}
		if !testvariant.DiffTestVariantLedgers(ledger, ledger).Inert() {
			t.Fatalf("PGO ledger refused its unchanged source under %v", flags)
		}
		// Pin the declared name, not a coincidentally correct path basename.
		if got := ledger.BaseFiles[0].Bindings.Imports; !reflect.DeepEqual(got, []testvariant.TestVariantImport{{Name: "declared", Path: pkg + "/dependency"}}) {
			t.Fatalf("base-file import = %+v", got)
		}
		args := append([]string{"test", "-count=1"}, flags...)
		args = append(args, ".")
		if output, err := (gotool.Runner{}).Run(t.Context(), dir, os.Environ(), args...); err != nil {
			t.Fatalf("the listed PGO test binary does not execute: %v\n%s", err, output)
		}
	}
}

func TestListingMemoRejectsRetypedSource(t *testing.T) {
	if testing.Short() {
		t.Skip("lists a module across an entry retype")
	}
	isolateProofCache(t)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":    "module example.com/retype\n\ngo 1.27\n",
		"p.go":      "package retype\nvar N = 7\nfunc F() int { return N }\n",
		"extra.go/": "",
	})
	env := listingEnv("", "off")
	snapshot := snapshotFor(t, dir, env)
	const pkg = "example.com/retype"
	first, n, h, err := listFrom(t, dir, pkg, env, snapshot)
	if err != nil || n != 1 {
		t.Fatalf("cold: %d %v", n, err)
	}
	original, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatal(err)
	}
	control, n, _, err := listFrom(t, dir, pkg, env, snapshot)
	if err != nil || n != 0 || !reflect.DeepEqual(first, control) {
		t.Fatalf("warm control: %d %v", n, err)
	}
	if err := os.Remove(filepath.Join(dir, "extra.go")); err != nil {
		t.Fatal(err)
	}
	writeTree(t, dir, map[string]string{"extra.go": "package retype\nfunc init() { N = 17 }\n"})
	warm, n, h, err := listFrom(t, dir, pkg, env, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	warmHash, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatal(err)
	}
	path, err := cachefile.Path(listingDirName, h.listingScope(), pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	cold, coldN, h, err := listFrom(t, dir, pkg, env, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	coldHash, err := h.maximalHash(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || coldN != 1 || !reflect.DeepEqual(warm, cold) || warmHash != coldHash || original == coldHash {
		t.Fatalf("retype: warm spawns=%d cold spawns=%d old=%s warm=%s cold=%s", n, coldN, original, warmHash, coldHash)
	}
}

func TestToolchainMemoRejectsIncompleteInventory(t *testing.T) {
	if testing.Short() {
		t.Skip("reads and corrupts a private standard-library memo")
	}
	if !stampsTrusted {
		t.Skip("this platform never serves the listing memo")
	}
	isolateProofCache(t)
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/surface\n\ngo 1.27\n"})
	env := listingEnv("", "off")
	snapshot := snapshotFor(t, dir, env)
	flags := []string{"-tags=dup"}
	listings := 0
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 1 && cmd.Args[1] == "list" {
			listings++
		}
	}}
	read := func() sourceDigests {
		t.Helper()
		d, err := toolchainSourceDigests(t.Context(), runner, dir, env, snapshot, flags)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	original := read()
	stringsMemoKey := verifiedPackageMemoKey("strings", original.Packages["strings"])
	withClosureTestHooks(analysisTestHookSet{
		packageVerdictOverride: func(memoKey string) (verifiedPackageVerdict, bool) {
			if memoKey == stringsMemoKey {
				return verifiedPackageVerdict{OK: false}, true
			}
			return verifiedPackageVerdict{}, false
		},
	}, func() {
		if toolchainSourceDegradation(snapshot.Value("GOVERSION"), original, nil).audited() {
			t.Fatal("unverified strings control unexpectedly admitted")
		}
		if again := read(); listings != 1 || !reflect.DeepEqual(again, original) {
			t.Fatal("valid unchanged memo did not serve")
		}
		scope := toolchainSourceScope(snapshot, flags, surfaceSeeds())
		path, err := cachefile.Path(sourceDigestsDirName, scope, "listing")
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for name, corrupt := range map[string]func(*surfaceListing){
			"empty":              func(l *surfaceListing) { l.Packages = nil },
			"missing package":    func(l *surfaceListing) { l.Packages = l.Packages[1:] },
			"missing files":      func(l *surfaceListing) { l.Packages[0].Files = nil },
			"missing stamps":     func(l *surfaceListing) { l.Discovery[0].Entries = nil },
			"missing discovery":  func(l *surfaceListing) { l.Discovery = nil },
			"missing commitment": func(l *surfaceListing) { l.Integrity = "" },
			"admission label":    func(l *surfaceListing) { l.Packages[0].Audited = !l.Packages[0].Audited },
		} {
			t.Run(name, func(t *testing.T) {
				var envelope cachefile.Envelope
				if err := json.Unmarshal(data, &envelope); err != nil {
					t.Fatal(err)
				}
				var listing surfaceListing
				if err := json.Unmarshal(envelope.Payload, &listing); err != nil {
					t.Fatal(err)
				}
				corrupt(&listing)
				envelope.Payload, err = json.Marshal(listing)
				if err != nil {
					t.Fatal(err)
				}
				broken, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, broken, 0o600); err != nil {
					t.Fatal(err)
				}
				before := listings
				got := read()
				if listings != before+1 || !reflect.DeepEqual(got, original) || toolchainSourceDegradation(snapshot.Value("GOVERSION"), got, nil).audited() {
					t.Fatal("incomplete inventory served or changed admission")
				}
			})
		}
	})
}

// Every selection the structural content verifier admits or refuses on the
// running toolchain: the default, race, tag, cross-platform, and cgo-off
// selections admit by structural AST verification without hardcoded per-release
// digest tables; an unclassifiable flag set refuses
// (REQ-closure-observability-toolchain-key).
func TestSelectionsAdmitByContent(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library under several selections")
	}
	isolateProofCache(t)
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
		{"netgo tag selection", []string{"-tags=netgo"}, false},
		{"netcgo tag selection", []string{"-tags=netcgo"}, true},
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
	// A tag that selects a standard-library file violating structural contracts
	// refuses naming the affected package, while an explicit -tags flag
	// overrides GOFLAGS as the go command does.
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	badRoot := unauditedTagGOROOT(t)
	badEnv := func(extra ...string) []string {
		args := append([]string{"GOROOT=" + badRoot, "GOTOOLCHAIN=local"}, extra...)
		return environmentWith(args...)
	}
	if h, err := newAtEnv(context.Background(), dir, badEnv()); err != nil {
		t.Fatal(err)
	} else if !h.SelectionAudited() {
		t.Errorf("untouched GOROOT without badstd tag refused: %s", h.SelectionNotice())
	}
	if h, err := newAtEnv(context.Background(), dir, badEnv(), "-tags=badstd"); err != nil {
		t.Fatal(err)
	} else if h.SelectionAudited() || !strings.Contains(h.SelectionAttribution(), "the audited surface of "+snapshot.Value("GOVERSION")+" moved in 1 keys: strings") {
		t.Errorf("badstd selection: audited=%v attribution %q, want strings named as moved", h.SelectionAudited(), h.SelectionAttribution())
	}
	if h, err := newAtEnv(context.Background(), dir, badEnv("GOFLAGS=-tags=badstd"), "-tags=dup"); err != nil {
		t.Fatal(err)
	} else if !h.SelectionAudited() {
		t.Errorf("an explicit -tags=dup under GOFLAGS=-tags=badstd refused: %s", h.SelectionNotice())
	}
	if h, err := newAtEnv(context.Background(), dir, badEnv(), "-tags=dup,badstd"); err != nil {
		t.Fatal(err)
	} else if h.SelectionAudited() || !strings.HasSuffix(h.SelectionAttribution(), ": strings") {
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
	isolateProofCache(t)
	// The ambient environment carries GOENV, as a witness runner's does:
	// the settings below are replaced, never appended, or the
	// environment normalizer refuses the doubled key.
	t.Setenv("GOENV", "warm")
	dir := t.TempDir()
	env := environmentWith("GOENV=off", "GOFLAGS=-tags", "GOEXPERIMENT=")
	_, _, notice, err := ResolveToolchainSelection(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, env), nil)
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
	_, _, notice, err = ResolveToolchainSelection(context.Background(), gotool.PrimedEnvReader(gotool.Runner{}, dir, env, snapshot), nil)
	if err != nil || !strings.Contains(notice, "-tags (from $GOFLAGS)") {
		t.Fatalf("snapshot-resolved notice lost the GOFLAGS selection: %v %q", err, notice)
	}
	_, _, clean, err := ResolveToolchainSelection(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, environmentWith("GOENV=off", "GOFLAGS=", "GOEXPERIMENT=")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := newAtEnv(context.Background(), dir, environmentWith("GOENV=off", "GOFLAGS=", "GOEXPERIMENT=")); err != nil {
		t.Fatal(err)
	} else if (clean == "") != h.SelectionAudited() || clean != h.SelectionNotice() {
		t.Fatalf("the resolved notice %q disagrees with the constructed verdict (audited=%v, notice %q)", clean, h.SelectionAudited(), h.SelectionNotice())
	}
}

// TestDigestTraversalEndsAtTheNextFileBoundary pins the digest
// traversal's check point (REQ-closure-observability-toolchain-key: the
// digests are read on every construction and the traversal checks its
// context before every file read): a context cancelled while the
// audited surface is being digested ends the traversal at the next file
// boundary — the file the cancellation lands on is the last one read
// and the construction answers the cancellation — and the listing
// record the memo stored before the digests were read, the completed
// listing's own, stands under the live seeds' scope.
func TestDigestTraversalEndsAtTheNextFileBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const stopAt = 3
	reads := 0
	var err error
	withClosureTestHooks(analysisTestHookSet{
		digestRead: func(name string) {
			reads++
			if reads == stopAt {
				cancel()
			}
		},
	}, func() {
		_, err = newAtEnv(ctx, ".", environmentWith())
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a construction cancelled mid-digest answered %v, want the cancellation", err)
	}
	if reads != stopAt {
		t.Fatalf("the traversal read %d files with the cancellation at read %d, want exactly that many: the next boundary ends it", reads, stopAt)
	}
	snapshot, err := gotool.NewEnvReader(gotool.Runner{}, ".", os.Environ()).Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("the completed listing's record does not stand after the cancelled digest traversal: %v", err)
	}
}

func TestFinalDigestReadCannotCompleteACancelledConstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("counts the selected standard-library reads")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	env := environmentWith()
	reads := 0
	withClosureTestHooks(analysisTestHookSet{
		digestRead: func(string) { reads++ },
	}, func() {
		if _, err := newAtEnv(t.Context(), ".", env); err != nil {
			t.Fatal(err)
		}
	})
	last := reads
	if last == 0 {
		t.Fatal("no selected file was read")
	}
	for _, notice := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		reads = 0
		var err error
		withClosureTestHooks(analysisTestHookSet{
			digestRead: func(string) {
				reads++
				if reads == last {
					cancel()
				}
			},
		}, func() {
			if notice {
				_, _, _, err = ResolveToolchainSelection(ctx, gotool.NewEnvReader(gotool.Runner{}, ".", env), nil)
			} else {
				_, err = newAtEnv(ctx, ".", env)
			}
		})
		cancel()
		if reads != last || !errors.Is(err, context.Canceled) {
			t.Fatalf("notice=%t final-read cancellation: reads=%d/%d error=%v", notice, reads, last, err)
		}
	}
}

// TestDstSelectionIsJudgedByContentNeverByTag pins structural content
// verification over `-tags dst` without any fork-specific or tag-specific
// hardcoding (REQ-closure-observability-toolchain-key): on both stock and
// custom dst-capable toolchains the running selection passes structural
// verification unconditionally, and injecting an unapproved dst-tagged file into
// an overlaid GOROOT refuses `-tags dst` while leaving the plain selection
// admitted.
func TestDstSelectionIsJudgedByContentNeverByTag(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	isolateProofCache(t)
	ctx := context.Background()
	base, err := newAtEnv(ctx, ".", environmentWith())
	if err != nil {
		t.Fatal(err)
	}
	if !base.SelectionAudited() {
		t.Fatalf("the running toolchain failed structural verification under its default selection: %s", base.SelectionNotice())
	}
	cgo := cgoEnabled(t)
	for _, sel := range []struct {
		suffix string
		flags  []string
		cgo    bool
	}{
		{" dst", []string{"-tags", "dst"}, false},
		{" dst race", []string{"-tags", "dst", "-race"}, true},
	} {
		if sel.cgo && !cgo {
			continue
		}
		h, err := newAtEnv(ctx, ".", environmentWith(), sel.flags...)
		if err != nil {
			t.Fatal(err)
		}
		if !h.SelectionAudited() {
			t.Fatalf("the %q selection on the running toolchain refused: %s", sel.suffix, h.SelectionNotice())
		}
	}

	snap, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, ".", environmentWith())
	if err != nil {
		t.Fatal(err)
	}
	goroot := snap.Value("GOROOT")
	origGetwd, err := os.ReadFile(filepath.Join(goroot, "src/os/getwd.go"))
	if err != nil {
		t.Fatal(err)
	}
	origFilePosix, err := os.ReadFile(filepath.Join(goroot, "src/os/file_posix.go"))
	if err != nil {
		t.Fatal(err)
	}
	hookedGetwd := strings.Replace(
		string(origGetwd),
		"func Getwd() (dir string, err error) {\n",
		"func Getwd() (dir string, err error) {\n\tif gofreshSimOverlay {\n\t\tif wd, handled, werr := gofreshTryGetwd(); handled {\n\t\t\treturn wd, werr\n\t\t}\n\t}\n",
		1,
	)
	hookedFilePosix := strings.Replace(
		string(origFilePosix),
		"func (f *File) Close() error {\n\tif f == nil {\n\t\treturn ErrInvalid\n\t}\n",
		"func (f *File) Close() error {\n\tif f == nil {\n\t\treturn ErrInvalid\n\t}\n\tif gofreshSimOverlay {\n\t\tif s := gofreshStateOf(f.file); s != nil {\n\t\t\treturn nil\n\t\t}\n\t}\n",
		1,
	)
	if hookedGetwd == string(origGetwd) || hookedFilePosix == string(origFilePosix) {
		t.Fatal("failed to locate hook insertion anchors in GOROOT src/os")
	}

	const simRuntimeClean = `//go:build simoverlay

package runtime

import "internal/runtime/atomic"

var gofreshSimFlag atomic.Uint32

func gofreshSimEnable() {
	gofreshSimFlag.Store(1)
}

func gofreshSimGate() bool {
	return gofreshSimFlag.Load() != 0
}
`
	const simOSOff = `//go:build !simoverlay

package os

const gofreshSimOverlay = false

func gofreshTryGetwd() (string, bool, error) { return "", false, nil }
func gofreshStateOf(_ *file) *int            { return nil }
`
	const simOSOn = `//go:build simoverlay

package os

import (
	"runtime"
	"sync/atomic"
	"unsafe"
)

const gofreshSimOverlay = true

//go:linkname gofreshOSGate runtime.gofreshSimGate
func gofreshOSGate() bool

type gofreshSimTable[T any, S any] struct {
	spine atomic.Pointer[S]
	count int
}

func (t *gofreshSimTable[T, S]) get(idx int) *S {
	sp := t.spine.Load()
	if sp == nil || idx < 0 || idx > t.count {
		return nil
	}
	return sp
}

func (t *gofreshSimTable[T, S]) register(s *S) {
	t.count++
	t.spine.Store(s)
}

var gofreshSimStates gofreshSimTable[file, int]

func gofreshSimStats() int {
	return gofreshSimStates.count
}

func gofreshSimIdx(f *file) (int, bool) {
	return int(uintptr(unsafe.Pointer(f))), true
}

func gofreshStateOf(f *file) *int {
	idx, ok := gofreshSimIdx(f)
	if !ok {
		return nil
	}
	s := gofreshSimStates.get(idx)
	runtime.KeepAlive(f)
	return s
}

func gofreshRegisterSim(_ *file) {
	if !gofreshOSGate() {
		return
	}
	v := 1
	gofreshSimStates.register(&v)
}

func gofreshTryGetwd() (string, bool, error) {
	if !gofreshOSGate() {
		return "", false, nil
	}
	gofreshRegisterSim(nil)
	return "/sim", true, nil
}
`
	simGOROOT, simValidEnv := testenv.OverlayGOROOTEnv(t, environmentWith(), map[string]string{
		"src/strings/gofresh_dst_unapproved.go": "//go:build dst\n\npackage strings\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshDstUnapproved\nfunc gofreshDstUnapproved() {}\n",
		"src/runtime/gofresh_sim_overlay.go":    simRuntimeClean,
		"src/os/gofresh_sim_off.go":             simOSOff,
		"src/os/gofresh_sim_on.go":              simOSOn,
		"src/os/getwd.go":                       hookedGetwd,
		"src/os/file_posix.go":                  hookedFilePosix,
		"src/image/color/gofresh_sim_trigger.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPullEnable runtime.gofreshSimEnable\nfunc gofreshPullEnable()\n\nfunc ActivateSim() { gofreshPullEnable() }\n",
	})
	withSimFiles := func(extra map[string]string, fn func([]string)) {
		t.Helper()
		type savedEntry struct {
			path string
			data []byte
		}
		var saved []savedEntry
		var created []string
		for rel, content := range extra {
			target := filepath.Join(simGOROOT, filepath.FromSlash(rel))
			if prev, err := os.ReadFile(target); err == nil {
				saved = append(saved, savedEntry{path: target, data: prev})
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
			} else {
				created = append(created, target)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		defer func() {
			for _, target := range created {
				_ = os.Remove(target)
			}
			for _, s := range saved {
				_ = os.Remove(s.path)
				if err := os.WriteFile(s.path, s.data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}()
		fn(simValidEnv)
	}
	simPlain, err := newAtEnv(ctx, ".", simValidEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !simPlain.SelectionAudited() {
		t.Fatalf("plain selection over overlaid GOROOT refused: %s", simPlain.SelectionNotice())
	}
	dstOverlay, err := newAtEnv(ctx, ".", simValidEnv, "-tags", "dst")
	if err != nil {
		t.Fatal(err)
	}
	if dstOverlay.SelectionAudited() || !strings.Contains(dstOverlay.SelectionAttribution(), "moved in 1 keys: strings") {
		t.Fatalf("dst selection with unapproved strings file: audited=%v attribution=%q", dstOverlay.SelectionAudited(), dstOverlay.SelectionAttribution())
	}
	simActive, err := newAtEnv(ctx, ".", simValidEnv, "-tags", "simoverlay")
	if err != nil {
		t.Fatal(err)
	}
	if !simActive.SelectionAudited() {
		t.Fatalf("simoverlay selection with verified inactive runtime gate and state table refused: %s", simActive.SelectionNotice())
	}

	// Off-surface non-startup exported function pulling runtime.gofreshSimEnable via //go:linkname:
	// the toolchain selection remains audited because startup cannot flip the gate, a sibling subject
	// in the same test binary linking image/color remains observable (including over os.Getenv),
	// and any subject calling that off-surface function is refused at both tiers.
	modDir := t.TempDir()
	writeTree(t, modDir, map[string]string{
		"go.mod": "module example.com/offsurface\n\ngo 1.24\n",
		"sub_test.go": `package offsurface

import (
	"image/color"
	"os"
	"strings"
	"testing"
)

func TestCallsOffSurfaceTrigger(t *testing.T) {
	color.ActivateSim()
}

func TestCleanOffSurfaceSibling(t *testing.T) {
	_ = os.Getenv("GOFRESH_OFFSURFACE_CLEAN")
	if strings.TrimSpace(" ok ") != "ok" {
		t.Fatal("unexpected trim result")
	}
}
`,
	})
	modView, err := newAtEnv(ctx, modDir, simValidEnv, "-tags", "simoverlay")
	if err != nil {
		t.Fatal(err)
	}
	if !modView.SelectionAudited() {
		t.Fatalf("off-surface non-startup trigger unexpectedly invalidated selection: %s", modView.SelectionNotice())
	}
	trigSubj := Subject{Package: "example.com/offsurface", Symbol: "TestCallsOffSurfaceTrigger"}
	cleanSubj := Subject{Package: "example.com/offsurface", Symbol: "TestCleanOffSurfaceSibling"}
	obs, err := modView.ComputeObservabilityBatch([]Subject{trigSubj, cleanSubj})
	if err != nil {
		t.Fatal(err)
	}
	if obs[trigSubj].Observable {
		t.Fatalf("subject calling off-surface gate activator admitted as observable: %+v", obs[trigSubj])
	}
	t2Trig, _, err := computeTier2ResultAndReach(modView, trigSubj.Package, trigSubj.Symbol)
	if err != nil {
		t.Fatal(err)
	}
	if !t2Trig.unverifiable {
		t.Fatalf("tier2 admitted subject calling off-surface gate activator: %+v", t2Trig)
	}
	if !obs[cleanSubj].Observable {
		t.Fatalf("clean sibling subject in off-surface test refused: %+v", obs[cleanSubj])
	}

	goversion := snap.Value("GOVERSION")
	evalSimNegative := func(name string, extra map[string]string) selectionDegradation {
		t.Helper()
		var deg selectionDegradation
		withSimFiles(extra, func(_ []string) {
			d := sourceDigests{
				Content:   simActive.source.Content,
				Policy:    simActive.source.Policy,
				Packages:  maps.Clone(simActive.source.Packages),
				inventory: maps.Clone(simActive.source.inventory),
			}
			touchedPkgs := map[string]bool{}
			for rel := range extra {
				clean := filepath.ToSlash(filepath.Clean(rel))
				switch {
				case strings.HasPrefix(clean, "pkg/include/"):
					touchedPkgs["runtime"] = true
				case strings.HasPrefix(clean, "src/"):
					pkgPath := path.Dir(strings.TrimPrefix(clean, "src/"))
					touchedPkgs[pkgPath] = true
				}
			}
			buf := make([]byte, 32*1024)
			for pkgPath := range touchedPkgs {
				lp, ok := d.inventory[pkgPath]
				if !ok {
					t.Fatalf("%s: package %s not in std inventory", name, pkgPath)
				}
				files := slices.Clone(lp.Files)
				for rel := range extra {
					clean := filepath.ToSlash(filepath.Clean(rel))
					if strings.HasPrefix(clean, "src/"+pkgPath+"/") {
						base := path.Base(clean)
						if !strings.Contains( clean[len("src/"+pkgPath+"/"):], "/") && !slices.Contains(files, base) {
							files = append(files, base)
						}
					}
				}
				slices.Sort(files)
				lp.Files = files
				digest, err := digestListedPackageBuffered(ctx, lp, buf)
				if err != nil {
					t.Fatalf("%s: digest %s: %v", name, pkgPath, err)
				}
				lp.digest = digest
				d.inventory[pkgPath] = lp
				if lp.Audited {
					d.Packages[pkgPath] = digest
				}
			}
			var err error
			deg, err = toolchainSourceDegradationContext(ctx, goversion, d, nil)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		})
		return deg
	}

	// Negative 1: runtime calls the gate mutator directly.
	if deg := evalSimNegative("called runtime mutator", map[string]string{
		"src/runtime/gofresh_sim_overlay.go": simRuntimeClean + "\nfunc gofreshBootActivate() { gofreshSimEnable() }\n",
	}); deg.audited() || !strings.Contains(deg.axis, "os") {
		t.Fatalf("simoverlay with called runtime mutator: audited=%v attribution=%q", deg.audited(), deg.axis)
	}

	// Negative 2: another audited surface package pulls the runtime gate mutator via //go:linkname.
	if deg := evalSimNegative("linkname-pulled runtime mutator", map[string]string{
		"src/testing/gofresh_pull_mutator.go": "//go:build simoverlay\n\npackage testing\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPullEnable runtime.gofreshSimEnable\nfunc gofreshPullEnable()\n",
	}); deg.audited() || !strings.Contains(deg.axis, "os") {
		t.Fatalf("simoverlay with linkname-pulled runtime mutator: audited=%v attribution=%q", deg.audited(), deg.axis)
	}

	// Negative 3: state-table register is reachable without the inactive runtime gate.
	simUngatedTable := strings.Replace(simOSOn, "\tif !gofreshOSGate() {\n\t\treturn\n\t}\n", "", 1) + "\nfunc GofreshReachableRegister() { gofreshRegisterSim(nil) }\n"
	if deg := evalSimNegative("ungated state-table register", map[string]string{
		"src/os/gofresh_sim_on.go": simUngatedTable,
	}); deg.audited() || !strings.Contains(deg.axis, "os") {
		t.Fatalf("simoverlay with ungated state-table register: audited=%v attribution=%q", deg.audited(), deg.axis)
	}

	// Negative 4: genuinely off-surface std package (image/color) activates runtime gate at startup,
	// via push-linkname, or via assembly/header symbol references (including macro expansion,
	// pkg/include headers, middle-dot whitespace/comments, token pasting, or direct flag writes).
	if slices.Contains(auditedSurfaceTables(), "image/color") {
		t.Fatal("image/color unexpectedly joined auditedSurfaceTables; test requires an off-surface std package")
	}
	// Positive controls for Negative 4: benign runtime assembly and benign off-surface cgo C file
	// must keep the selection audited so the negative cases below cannot pass from go list errors.
	benignFiles := map[string]string{
		"pkg/include/gofresh_bridge.h":             "#define NOOP_ASM RET\n",
		"src/runtime/gofresh_bridge_benign.s":      "//go:build simoverlay\n\n#include \"gofresh_bridge.h\"\nTEXT ·gofreshRuntimeAsmNoop(SB),$0-0\n\tNOOP_ASM\n",
		"src/image/color/gofresh_bridge_enable.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname simEnable runtime.gofreshSimEnable\nfunc simEnable()\n\nfunc gofreshBridgeEnable() { simEnable() }\n",
	}
	if cgo {
		benignFiles["src/image/color/gofresh_sim_cgo.go"] = "//go:build simoverlay\n\npackage color\n\nimport \"C\"\n"
		benignFiles["src/image/color/gofresh_sim_ext.c"] = "//go:build simoverlay\n\nvoid gofreshBenignC(void) {}\n"
		benignFiles["src/runtime/cgo/gofresh_bridge.h"] = "#define BENIGN_STR(x) #x\n"
		benignFiles["src/runtime/cgo/gofresh_bridge_ok.c"] = "//go:build simoverlay\n\n#include \"gofresh_bridge.h\"\nconst char *gofreshBenignRuntimeCgo(void) { return BENIGN_STR(ok); }\n"
	}
	withSimFiles(benignFiles, func(benignEnv []string) {
		benignH, err := newAtEnv(ctx, ".", benignEnv, "-tags", "simoverlay")
		if err != nil {
			t.Fatal(err)
		}
		if !benignH.SelectionAudited() {
			t.Fatalf("benign runtime assembly / off-surface cgo C file refused: %s", benignH.SelectionNotice())
		}
	})

	for _, tc := range []struct {
		name    string
		cgoOnly bool
		files   map[string]string
	}{
		{
			name: "off-surface startup init pull-linkname",
			files: map[string]string{
				"src/image/color/gofresh_sim_boot.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPullEnable runtime.gofreshSimEnable\nfunc gofreshPullEnable()\n\nfunc init() { gofreshPullEnable() }\n",
			},
		},
		{
			name: "off-surface startup var initializer pull-linkname",
			files: map[string]string{
				"src/image/color/gofresh_sim_boot.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPullEnable runtime.gofreshSimEnable\nfunc gofreshPullEnable()\n\nfunc bootHelper() int { gofreshPullEnable(); return 1 }\n\nvar _ = bootHelper()\n",
			},
		},
		{
			name: "off-surface push-linkname overriding runtime mutator",
			files: map[string]string{
				"src/image/color/gofresh_sim_push.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname gofreshPushEnable runtime.gofreshSimEnable\nfunc gofreshPushEnable() {}\n",
			},
		},
		{
			name: "off-surface assembly middle-dot whitespace",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALL runtime · gofreshSimEnable(SB)\n\tRET\n",
			},
		},
		{
			name: "off-surface assembly middle-dot block comment",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALL runtime/*c*/·gofreshSimEnable(SB)\n\tRET\n",
			},
		},
		{
			name: "off-surface local header macro runtime prefix",
			files: map[string]string{
				"src/image/color/gofresh_local.h":   "#define R runtime\n",
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\n#include \"gofresh_local.h\"\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALL R·gofreshSimEnable(SB)\n\tRET\n",
			},
		},
		{
			name: "off-surface pkg/include header macro runtime prefix",
			files: map[string]string{
				"pkg/include/gofresh_inc.h":         "#define RINC runtime\n",
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\n#include \"gofresh_inc.h\"\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALL RINC·gofreshSimEnable(SB)\n\tRET\n",
			},
		},
		{
			name: "off-surface parameterized macro runtime call",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\n#define CALLRT(s) CALL runtime·s(SB)\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALLRT(gofreshSimEnable)\n\tRET\n",
			},
		},
		{
			name: "off-surface token-paste macro runtime call",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\n#define PASTE(a,b) a##b\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALL PASTE(run,time)·gofreshSimEnable(SB)\n\tRET\n",
			},
		},
		{
			name: "off-surface assembly direct gate flag write",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tMOVL $1, runtime·gofreshSimFlag(SB)\n\tRET\n",
			},
		},
		{
			name:    "off-surface c adjacent string literal runtime pull",
			cgoOnly: true,
			files: map[string]string{
				"src/image/color/gofresh_sim_cgo.go": "//go:build simoverlay\n\npackage color\n\nimport \"C\"\n",
				"src/image/color/gofresh_sim_ext.c":  "//go:build simoverlay\n\nextern void gofreshEnableC(void) __asm__(\"runtime.\" \"gofreshSimEnable\");\nvoid gofreshBootC(void) { gofreshEnableC(); }\n",
			},
		},
		{
			name:    "off-surface c hex escape runtime pull",
			cgoOnly: true,
			files: map[string]string{
				"src/image/color/gofresh_sim_cgo.go": "//go:build simoverlay\n\npackage color\n\nimport \"C\"\n",
				"src/image/color/gofresh_sim_ext.c":  "//go:build simoverlay\n\nextern void gofreshEnableC(void) __asm__(\"runtime.\\x67ofreshSimEnable\");\nvoid gofreshBootC(void) { gofreshEnableC(); }\n",
			},
		},
		{
			name:    "off-surface c stringize macro runtime pull",
			cgoOnly: true,
			files: map[string]string{
				"src/image/color/gofresh_sim_cgo.go": "//go:build simoverlay\n\npackage color\n\nimport \"C\"\n",
				"src/image/color/gofresh_sim_ext.c":  "//go:build simoverlay\n\n#define RTSYM(x) extern void gofreshEnableC(void) __asm__(\"runtime.\" #x);\nRTSYM(gofreshSimEnable)\nvoid gofreshBootC(void) { gofreshEnableC(); }\n",
			},
		},
		{
			name: "off-surface multiline parameterized macro runtime call",
			files: map[string]string{
				"src/image/color/gofresh_sim_asm.s": "//go:build simoverlay\n\n#define CALLRT(s) CALL runtime·s(SB)\nTEXT ·gofreshAsmBoot(SB),$0-0\n\tCALLRT(\n\t\tgofreshSimEnable\n\t)\n\tRET\n",
			},
		},
		{
			name: "off-surface runtime header assembly external pull",
			files: map[string]string{
				"pkg/include/gofresh_bridge.h":             "#define EXT_PKG image/color\n",
				"src/runtime/gofresh_bridge.s":             "//go:build simoverlay\n\n#include \"gofresh_bridge.h\"\nTEXT ·gofreshRuntimeAsmNoop(SB),$0-0\n\tCALL EXT_PKG·gofreshBridgeEnable(SB)\n\tRET\n",
				"src/image/color/gofresh_bridge_enable.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname simEnable runtime.gofreshSimEnable\nfunc simEnable()\n\nfunc gofreshBridgeEnable() { simEnable() }\n",
			},
		},
		{
			name:    "off-surface runtime/cgo header stringize external pull",
			cgoOnly: true,
			files: map[string]string{
				"src/runtime/cgo/gofresh_bridge.h":         "#define EXT_CALL(pkg, fn) extern void gofreshBridge(void) __asm__(#pkg \".\" #fn);\n",
				"src/runtime/cgo/gofresh_bridge.c":         "//go:build simoverlay\n\n#include \"gofresh_bridge.h\"\nEXT_CALL(image/color, gofreshBridgeEnable)\nvoid gofreshRuntimeNoop(void) { gofreshBridge(); }\n",
				"src/image/color/gofresh_bridge_enable.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname simEnable runtime.gofreshSimEnable\nfunc simEnable()\n\nfunc gofreshBridgeEnable() { simEnable() }\n",
			},
		},
		{
			name: "off-surface runtime method linkname external pull",
			files: map[string]string{
				"src/runtime/gofresh_bridge_method.go":     "//go:build simoverlay\n\npackage runtime\n\nimport _ \"unsafe\"\n\n//go:linkname rtBridgeMethod image/color.(*Palette).gofreshBridgeMethod\nfunc rtBridgeMethod(*struct{})\n",
				"src/image/color/gofresh_bridge_enable.go": "//go:build simoverlay\n\npackage color\n\nimport _ \"unsafe\"\n\n//go:linkname simEnable runtime.gofreshSimEnable\nfunc simEnable()\n\nfunc (p *Palette) gofreshBridgeMethod() { simEnable() }\n",
			},
		},
	} {
		if tc.cgoOnly && !cgo {
			continue
		}
		deg := evalSimNegative(tc.name, tc.files)
		if deg.audited() || !strings.Contains(deg.axis, "os") {
			t.Fatalf("%s: audited=%v attribution=%q", tc.name, deg.audited(), deg.axis)
		}
	}
}

// TestListingMemoRecordLandsUnderTheLiveSeedsScope pins the memo's
// wiring (REQ-closure-observability-toolchain-key's listing memo): a
// listing is stored under the scope the live surface seeds make and
// under no other seed list's, so a record of another surface rule is
// never the one a construction finds.
func TestListingMemoRecordLandsUnderTheLiveSeedsScope(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	isolateProofCache(t)
	ctx := context.Background()
	dir := t.TempDir()
	runner := gotool.Runner{}
	snapshot, err := gotool.NewEnvReader(runner, dir, os.Environ()).Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil); err != nil {
		t.Fatal(err)
	}
	live, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("no listing record under the live seeds' scope: %v", err)
	}
	other, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, []string{"runtime", "sync/atomic", "testing"}), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(other); err == nil {
		t.Fatalf("a listing record under another seed list's scope: %s", other)
	}
}

// The running toolchain's surface digests under the default selection:
// every surface package present with a digest (the runtime and the
// reached delegates included), the race selection moving exactly the
// race seams, and the listing memo serving the second read without a
// listing while the tree stands (REQ-closure-observability-toolchain-key).
func TestToolchainSourceDigestsReadTheRunningToolchain(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	isolateProofCache(t)
	ctx := context.Background()
	dir := t.TempDir()
	listings := 0
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 1 && cmd.Args[1] == "list" {
			listings++
		}
	}}
	reader := gotool.NewEnvReader(runner, dir, os.Environ())
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	d, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range auditedSurfaceTables() {
		if p == "golang.org/x/sys/unix" {
			continue // a module package, never the toolchain's
		}
		if d.Packages[p] == "" {
			t.Errorf("no digest for the surface package %s", p)
		}
	}
	for _, p := range []string{"crypto/internal/fips140", "vendor/golang.org/x/net/http2/hpack", "internal/godebug", "runtime", "internal/runtime/atomic", "unsafe", "runtime/cgo", "runtime/race"} {
		if d.Packages[p] == "" {
			t.Errorf("no digest for the reached package %s", p)
		}
	}
	if listings != 1 {
		t.Fatalf("the first read listed %d times, want once", listings)
	}
	again, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil)
	if err != nil || !reflect.DeepEqual(again, d) {
		t.Fatalf("the memo-served digests differ: %v %+v", err, again)
	}
	if listings != 1 {
		t.Fatalf("the second read listed again (%d listings); the memo serves it", listings)
	}
	race, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, []string{"-race"})
	if err != nil {
		t.Fatal(err)
	}
	// The race selection differs from the default in exactly the race
	// seams the listing's race rows carry as their delta: internal/race
	// selects race.go for norace.go (sync's delegate, the real instrumentation
	// behind the race.Enabled guards), sync/atomic selects race.s for
	// asm.s (the atomics routed through the runtime's instrumented
	// forms), the runtime and its sys delegate select their race files,
	// and the detector's runtime (runtime/race, a link-time seed) its
	// race-tagged files — all judged inert for every admission under
	// either selection; every other surface package selects the same
	// files.
	var differs []string
	for k, v := range race.Packages {
		if d.Packages[k] != v {
			differs = append(differs, k)
		}
	}
	sort.Strings(differs)
	if !reflect.DeepEqual(differs, []string{"internal/race", "internal/runtime/sys", "runtime", "runtime/race", "sync/atomic"}) {
		t.Fatalf("the race selection differs from the default in %v, want the race seams alone", differs)
	}
}

// A package the go command could not load refuses the listing by name
// through the parser — the shim's listing carries an Error entry — and
// a package the selection gives no file (a platform none of its files
// build on) is the empty selection, digested as the empty sequence.
func TestListingErrorsRefuseByNameAndTheEmptySelectionDigests(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns the go command")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the listing shim is a shell script")
	}
	isolateProofCache(t)
	ctx := context.Background()
	root := t.TempDir()
	empty := filepath.Join(root, "src", "plugin")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	listingJSON := filepath.Join(root, "listing.json")
	shim := filepath.Join(root, "golist.sh")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexec cat "+listingJSON+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 1 && cmd.Args[1] == "list" {
			cmd.Path = shim
		}
	}}
	dir := t.TempDir()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(listingJSON, []byte(`{"ImportPath":"strings","Standard":true,"Dir":"`+root+`","GoFiles":["a.go"],"Error":{"Err":"import cycle not allowed"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil); err == nil || !strings.Contains(err.Error(), "package strings failed to load: import cycle not allowed") {
		t.Fatalf("a listing error digested instead of refusing by name: %v", err)
	}
	if err := os.WriteFile(listingJSON, []byte(`{"ImportPath":"plugin","Standard":true,"Dir":"`+empty+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := digestFiles(ctx, empty, nil); d.Packages["plugin"] != want {
		t.Fatalf("the empty selection digests %q, want the empty sequence %q", d.Packages["plugin"], want)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// The memo scope is the explicit build flags verbatim and the pass
// snapshot's identity — every setting the go command reports: GOFLAGS
// (the go command merges and overrides it itself, so the scope never
// re-derives the merge), the platform, cgo, the experiment and FIPS
// module sets, the root and version — one value for one environment,
// so a record never serves a listing it was not taken under.
func TestToolchainSourceScopeDiscriminatesEveryAxis(t *testing.T) {
	if testing.Short() {
		t.Skip("toolchain integration test")
	}
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	snapshot := func(settings ...string) *gotool.EnvSnapshot {
		t.Helper()
		given := map[string]bool{}
		for _, setting := range settings {
			key, _, _ := strings.Cut(setting, "=")
			given[key] = true
		}
		for _, setting := range []string{"GOENV=off", "GOEXPERIMENT=", "GOFLAGS=", "GOFIPS140=off"} {
			if key, _, _ := strings.Cut(setting, "="); !given[key] {
				settings = append(settings, setting)
			}
		}
		s, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, dir, environmentWith(settings...))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	base := snapshot()
	if got, want := toolchainSourceScope(base, nil, surfaceSeeds()), toolchainSourceScope(snapshot(), nil, surfaceSeeds()); got != want {
		t.Errorf("one environment, two scopes: %q vs %q", got, want)
	}
	if got, same := toolchainSourceScope(base, []string{"-tags=netgo"}, surfaceSeeds()), toolchainSourceScope(base, nil, surfaceSeeds()); got == same {
		t.Errorf("the explicit flags do not key the scope: %q", got)
	}
	for _, axis := range []string{"GOFLAGS=-tags=netgo", "GOEXPERIMENT=fieldtrack", "GOOS=plan9", "GOARCH=arm64", "CGO_ENABLED=0", "GOFIPS140=latest"} {
		if got, same := toolchainSourceScope(snapshot(axis), nil, surfaceSeeds()), toolchainSourceScope(base, nil, surfaceSeeds()); got == same {
			t.Errorf("%s does not key the scope: %q", axis, got)
		}
	}
	if got := toolchainSourceScope(base, nil, surfaceSeeds()); !strings.Contains(got, "GOVERSION="+base.Value("GOVERSION")) || !strings.Contains(got, "GOROOT="+base.Value("GOROOT")) {
		t.Errorf("the scope names neither the version nor the GOROOT: %q", got)
	}
	// An explicit flag over GOFLAGS is the go command's merge, not the
	// scope's: the two shapes are two scopes whatever they select.
	if a, b := toolchainSourceScope(snapshot("GOFLAGS=-tags=netgo"), []string{"-tags=dup"}, surfaceSeeds()), toolchainSourceScope(base, []string{"-tags=dup,netgo"}, surfaceSeeds()); a == b {
		t.Error("an explicit flag over GOFLAGS shares a scope with their union")
	}
}

// The memo serves a listing only over the tree it was taken over, end
// to end: a standard library planted in a temporary tree (the go
// command's listing answered by a shim) lists once, serves the second
// read without a listing, and after one planted file is edited in
// place re-lists on the third read with the package's digest moved —
// the listing never decides which bytes are compiled from a tree that
// moved, and the digests are always the files' own.
func TestToolchainSourceMemoRelistsAMovedTree(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns the go command")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the listing shim is a shell script")
	}
	isolateProofCache(t)
	ctx := context.Background()
	root := t.TempDir()
	pkgDir := filepath.Join(root, "src", "strings")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("strings.go", "package strings\n")
	write("other.go", "//go:build never\n\npackage strings\n")
	listingJSON := filepath.Join(root, "listing.json")
	if err := os.WriteFile(listingJSON, []byte(`{"ImportPath":"strings","Standard":true,"Dir":"`+pkgDir+`","GoFiles":["strings.go"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(root, "golist.sh")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nexec cat "+listingJSON+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	listings := 0
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 1 && cmd.Args[1] == "list" {
			listings++
			cmd.Path = shim
		}
	}}
	dir := t.TempDir()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	read := func() sourceDigests {
		t.Helper()
		d, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	first := read()
	if want, _ := digestFiles(ctx, pkgDir, []string{"strings.go"}); first.Packages["strings"] != want || listings != 1 {
		t.Fatalf("first read: digest %q (want %q), %d listings", first.Packages["strings"], want, listings)
	}
	wantListings := 1
	if !stampsTrusted {
		wantListings = 2 // no change time here: every read lists
	}
	if again := read(); again.Packages["strings"] != first.Packages["strings"] || listings != wantListings {
		t.Fatalf("second read: %d listings over an unchanged tree, want %d", listings, wantListings)
	}
	// The tree moves under the same scope: the unselected file's
	// constraint edited in place (its selection may now differ) —
	// re-listed; the shim now selects it, and the digest moves.
	write("other.go", "package strings\n\nfunc Other() {}\n")
	if err := os.WriteFile(listingJSON, []byte(`{"ImportPath":"strings","Standard":true,"Dir":"`+pkgDir+`","GoFiles":["other.go","strings.go"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	third := read()
	if listings != wantListings+1 {
		t.Fatalf("a moved tree served the stale listing (%d listings)", listings)
	}
	if want, _ := digestFiles(ctx, pkgDir, []string{"other.go", "strings.go"}); third.Packages["strings"] != want || third.Packages["strings"] == first.Packages["strings"] {
		t.Fatalf("the digest did not follow the moved tree: %q, want %q", third.Packages["strings"], want)
	}
	// A selected file edited in place: its stamp re-lists (the same
	// files selected) and the digest follows the new bytes.
	write("strings.go", "package strings\n\nfunc Edited() {}\n")
	fourth := read()
	if want, _ := digestFiles(ctx, pkgDir, []string{"other.go", "strings.go"}); fourth.Packages["strings"] != want || fourth.Packages["strings"] == third.Packages["strings"] {
		t.Fatalf("an edited selected file left the digest: %q, want %q", fourth.Packages["strings"], want)
	}
}

func TestToolchainSourceScopeIgnoresModulePathsAndServesDigestMemo(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns the go command")
	}
	isolateProofCache(t)
	ctx := context.Background()
	modA := t.TempDir()
	modB := t.TempDir()
	writeTree(t, modA, map[string]string{"go.mod": "module example.com/moda\n\ngo 1.26\n"})
	writeTree(t, modB, map[string]string{"go.mod": "module example.com/modb\n\ngo 1.26\n"})
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	snapA, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, modA, env)
	if err != nil {
		t.Fatal(err)
	}
	snapB, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, modB, env)
	if err != nil {
		t.Fatal(err)
	}
	scopeA := toolchainSourceScope(snapA, nil, surfaceSeeds())
	scopeB := toolchainSourceScope(snapB, nil, surfaceSeeds())
	if scopeA != scopeB {
		t.Fatalf("distinct modules under same toolchain produced different scopes:\nA: %s\nB: %s", scopeA, scopeB)
	}
	listings := 0
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		if len(cmd.Args) > 1 && cmd.Args[1] == "list" {
			listings++
		}
	}}
	first, err := toolchainSourceDigests(ctx, runner, modA, env, snapA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if listings != 1 {
		t.Fatalf("cold listings = %d, want 1", listings)
	}
	second, err := toolchainSourceDigests(ctx, runner, modB, env, snapB, nil)
	if err != nil {
		t.Fatal(err)
	}
	if listings != 1 {
		t.Fatalf("warm cross-module listings = %d, want 1", listings)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("warm cross-module digests differed from cold digests")
	}
	// An empty package digest in the memoized map is rejected by sourceDigestsFromMemo.
	l := surfaceListing{
		Version:  sourceDigestsVersion,
		Packages: []listedPackage{{ImportPath: "strings", Audited: true}, {ImportPath: "archive/tar", Audited: false}},
	}
	if _, ok := sourceDigestsFromMemo(l, map[string]string{"strings": "", "archive/tar": "abc"}); ok {
		t.Fatal("sourceDigestsFromMemo accepted empty digest for audited package")
	}
	if _, ok := sourceDigestsFromMemo(l, map[string]string{"strings": "abc", "archive/tar": ""}); ok {
		t.Fatal("sourceDigestsFromMemo accepted empty digest for non-audited package")
	}
}

func TestNonInternalDelegatesAdmittedOnlyThroughAuditedStdCallers(t *testing.T) {
	if testing.Short() {
		t.Skip("builds whole-program SSA over a temporary module")
	}
	isolateProofCache(t)
	dir := t.TempDir()
	const pkg = "example.com/noninternal"
	writeTree(t, dir, map[string]string{
		"go.mod": "module " + pkg + "\n\ngo 1.26\n",
		"p_test.go": `package noninternal

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/json"
	"hash"
	"io"
	"testing"
)

func TestAdmittedSHA256AndJSON(t *testing.T) {
	var h hash.Hash = sha256.New()
	_, _ = h.Write([]byte("ok"))
	_ = h.Sum(nil)
	m := json.RawMessage(` + "`" + `{"a":1}` + "`" + `)
	_, _ = m.MarshalJSON()
	var marshaler json.Marshaler = m
	if _, err := marshaler.MarshalJSON(); err != nil {
		_ = err.Error()
	}
}

func TestDirectSHA3Static(t *testing.T) {
	h := sha3.New256()
	_, _ = h.Write([]byte("x"))
}

func TestDirectSHA3FuncValue(t *testing.T) {
	fn := sha3.New256
	_ = fn()
}

func TestDirectSHA3Invoke(t *testing.T) {
	var d sha3.SHA3
	var w io.Writer = &d
	_, _ = w.Write([]byte("x"))
}

func TestCryptoRegisterHash(t *testing.T) {
	crypto.RegisterHash(crypto.SHA256, sha256.New)
}
`,
		"jsonv2_direct_test.go": `//go:build goexperiment.jsonv2

package noninternal

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"testing"
)

func TestDirectJSONTextStatic(t *testing.T) {
	_ = jsontext.Value("{}").IsValid()
}

func TestDirectJSONTextFuncValue(t *testing.T) {
	fn := jsontext.Value.IsValid
	_ = fn(jsontext.Value("{}"))
}

func TestDirectJSONTextInvoke(t *testing.T) {
	var m json.Marshaler = jsontext.Value("{}")
	_, err := m.MarshalJSON()
	if err != nil {
		_ = err.Error()
	}
}

func TestDirectJSONV2Static(t *testing.T) {
	_, _ = jsonv2.Marshal(1)
}

func TestDirectJSONV2FuncValue(t *testing.T) {
	fn := jsonv2.Marshal
	_, _ = fn(1)
}

func TestDirectJSONV2Invoke(t *testing.T) {
	var err error = &jsonv2.SemanticError{}
	_ = err.Error()
}
`,
	})
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !h.SelectionAudited() {
		t.Fatalf("running toolchain not audited: %s", h.SelectionNotice())
	}
	subjects := []Subject{
		{Package: pkg, Symbol: "TestAdmittedSHA256AndJSON"},
		{Package: pkg, Symbol: "TestDirectSHA3Static"},
		{Package: pkg, Symbol: "TestDirectSHA3FuncValue"},
		{Package: pkg, Symbol: "TestDirectSHA3Invoke"},
		{Package: pkg, Symbol: "TestCryptoRegisterHash"},
	}
	batched, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	if obs := batched[subjects[0]]; !obs.Observable {
		t.Fatalf("TestAdmittedSHA256AndJSON refused: %+v", obs)
	}
	for _, s := range subjects[1:] {
		if obs := batched[s]; obs.Observable {
			t.Fatalf("%s admitted despite direct reference to unaudited public package: %+v", s.Symbol, obs)
		}
		soloH, err := newAt(dir)
		if err != nil {
			t.Fatal(err)
		}
		solo, err := soloH.ComputeObservabilityBatch([]Subject{s})
		if err != nil {
			t.Fatal(err)
		}
		if batched[s] != solo[s] {
			t.Fatalf("%s batch (%+v) != solo (%+v)", s.Symbol, batched[s], solo[s])
		}
	}

	// Under GOEXPERIMENT=jsonv2, json.RawMessage is a type alias for
	// encoding/json/jsontext.Value: user code importing only "encoding/json"
	// remains admitted, while direct user references to non-internal pure
	// delegates remain refused.
	jsonV2Hasher, err := newAtEnv(context.Background(), dir, environmentWith("GOEXPERIMENT=jsonv2"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonV2Hasher.SelectionAudited() {
		t.Fatalf("GOEXPERIMENT=jsonv2 selection not audited: %s", jsonV2Hasher.SelectionNotice())
	}
	jsonV2Subjects := []Subject{
		subjects[0],
		{Package: pkg, Symbol: "TestDirectJSONTextStatic"},
		{Package: pkg, Symbol: "TestDirectJSONTextFuncValue"},
		{Package: pkg, Symbol: "TestDirectJSONTextInvoke"},
		{Package: pkg, Symbol: "TestDirectJSONV2Static"},
		{Package: pkg, Symbol: "TestDirectJSONV2FuncValue"},
		{Package: pkg, Symbol: "TestDirectJSONV2Invoke"},
	}
	jsonV2Obs, err := jsonV2Hasher.ComputeObservabilityBatch(jsonV2Subjects)
	if err != nil {
		t.Fatal(err)
	}
	if obs := jsonV2Obs[jsonV2Subjects[0]]; !obs.Observable {
		t.Fatalf("TestAdmittedSHA256AndJSON refused under GOEXPERIMENT=jsonv2: %+v", obs)
	}
	for _, s := range jsonV2Subjects[1:] {
		if obs := jsonV2Obs[s]; obs.Observable {
			t.Fatalf("%s admitted under GOEXPERIMENT=jsonv2 despite direct user reference: %+v", s.Symbol, obs)
		}
	}
	if got := jsonV2Obs[Subject{Package: pkg, Symbol: "TestDirectJSONTextInvoke"}].Reason; !strings.HasPrefix(got, "subject reachability is not closed:") {
		t.Fatalf("TestDirectJSONTextInvoke reason = %q, want closed-invoke provenance refusal", got)
	}
	if t2Admitted, _, err := computeTier2ResultAndReach(jsonV2Hasher, pkg, "TestAdmittedSHA256AndJSON"); err != nil {
		t.Fatal(err)
	} else if t2Admitted.unverifiable || t2Admitted.widen {
		t.Fatalf("TestAdmittedSHA256AndJSON tier2 refused under GOEXPERIMENT=jsonv2: %+v", t2Admitted)
	}
	for _, sym := range []string{"TestDirectJSONTextStatic", "TestDirectJSONTextFuncValue"} {
		t2, _, err := computeTier2ResultAndReach(jsonV2Hasher, pkg, sym)
		if err != nil {
			t.Fatal(err)
		}
		if !t2.unverifiable || !strings.Contains(t2.reason, "encoding/json/jsontext") {
			t.Fatalf("%s tier2 = %+v, want unaudited encoding/json/jsontext refusal", sym, t2)
		}
	}
	if t2Inv, _, err := computeTier2ResultAndReach(jsonV2Hasher, pkg, "TestDirectJSONTextInvoke"); err != nil {
		t.Fatal(err)
	} else if !t2Inv.widen {
		t.Fatalf("TestDirectJSONTextInvoke tier2 = %+v, want widen=true", t2Inv)
	}
	reversed := slices.Clone(jsonV2Subjects)
	slices.Reverse(reversed)
	jsonV2HasherRev, err := newAtEnv(context.Background(), dir, environmentWith("GOEXPERIMENT=jsonv2"))
	if err != nil {
		t.Fatal(err)
	}
	jsonV2ObsRev, err := jsonV2HasherRev.ComputeObservabilityBatch(reversed)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range jsonV2Subjects {
		if jsonV2Obs[s] != jsonV2ObsRev[s] {
			t.Fatalf("%s order-dependent observability under GOEXPERIMENT=jsonv2: forward=%+v reverse=%+v", s.Symbol, jsonV2Obs[s], jsonV2ObsRev[s])
		}
	}
}

func TestNonInternalDelegateCrossPackageAndSiblingIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns go list and loads standard library")
	}
	isolateProofCache(t)

	dir := t.TempDir()
	const mod = "example.com/mod"
	writeTree(t, dir, map[string]string{
		"go.mod": "module " + mod + "\n\ngo 1.26\n",
		"pkga/a.go": `package pkga

import "crypto/sha3"

type SHA3Holder struct {
	D sha3.SHA3
}

type SHA3Alias = sha3.SHA3
`,
		"pkga/a_jsonv2.go": `//go:build goexperiment.jsonv2

package pkga

import "encoding/json/jsontext"

type JSONHolder struct {
	V jsontext.Value
}

type ValAlias = jsontext.Value
`,
		"pkgb/b_test.go": `package pkgb

import (
	"encoding/json"
	"io"
	"testing"

	"` + "example.com/mod/pkga" + `"
)

//go:noinline
func callWriter(w io.Writer) error {
	_, err := w.Write([]byte("x"))
	return err
}

func TestCrossPkgSHA3FieldStatic(t *testing.T) {
	var h pkga.SHA3Holder
	_, _ = h.D.Write([]byte("x"))
}

func TestCrossPkgSHA3FieldInvoke(t *testing.T) {
	var h pkga.SHA3Holder
	if err := callWriter(&h.D); err != nil {
		_ = err.Error()
	}
}

func TestCrossPkgSHA3AliasFuncValue(t *testing.T) {
	var d pkga.SHA3Alias
	fn := d.Write
	_, _ = fn([]byte("x"))
}

func TestCleanRawMessageCrossPkg(t *testing.T) {
	m := json.RawMessage("{}")
	_, _ = m.MarshalJSON()
}
`,
		"pkgb/b_jsonv2_test.go": `//go:build goexperiment.jsonv2

package pkgb

import (
	"encoding/json"
	"testing"

	"` + "example.com/mod/pkga" + `"
)

//go:noinline
func callMarshaler(m json.Marshaler) ([]byte, error) {
	return m.MarshalJSON()
}

func TestCrossPkgJSONFieldStatic(t *testing.T) {
	h := pkga.JSONHolder{V: pkga.ValAlias("{}")}
	_ = h.V.IsValid()
}

func TestCrossPkgJSONAliasFuncValue(t *testing.T) {
	fn := pkga.ValAlias.IsValid
	_ = fn(pkga.ValAlias("{}"))
}

func TestCrossPkgJSONFieldInvoke(t *testing.T) {
	h := pkga.JSONHolder{V: pkga.ValAlias("{}")}
	if _, err := callMarshaler(h.V); err != nil {
		_ = err.Error()
	}
}

func TestCrossPkgJSONAliasInvoke(t *testing.T) {
	var v pkga.ValAlias = pkga.ValAlias("{}")
	if _, err := callMarshaler(v); err != nil {
		_ = err.Error()
	}
}
`,
		"isolated/clean_test.go": `package isolated

import (
	"encoding/json"
	"testing"
)

//go:noinline
func callIsolatedMarshaler(m json.Marshaler) ([]byte, error) {
	return m.MarshalJSON()
}

func TestCleanRawMessageSibling(t *testing.T) {
	raw := json.RawMessage(` + "`" + `{"k":1}` + "`" + `)
	if _, err := callIsolatedMarshaler(raw); err != nil {
		_ = err.Error()
	}
}
`,
		"isolated/dirty_jsonv2_test.go": `//go:build goexperiment.jsonv2

package isolated

import (
	"encoding/json/jsontext"
	"testing"
)

func TestDirtyDirectJSONTextSibling(t *testing.T) {
	if _, err := callIsolatedMarshaler(jsontext.Value("{}")); err != nil {
		_ = err.Error()
	}
}
`,
	})

	pkgB := mod + "/pkgb"
	pkgIso := mod + "/isolated"

	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	sha3Subjects := []Subject{
		{Package: pkgB, Symbol: "TestCleanRawMessageCrossPkg"},
		{Package: pkgB, Symbol: "TestCrossPkgSHA3FieldStatic"},
		{Package: pkgB, Symbol: "TestCrossPkgSHA3FieldInvoke"},
		{Package: pkgB, Symbol: "TestCrossPkgSHA3AliasFuncValue"},
	}
	sha3Obs, err := h.ComputeObservabilityBatch(sha3Subjects)
	if err != nil {
		t.Fatal(err)
	}
	if !sha3Obs[sha3Subjects[0]].Observable {
		t.Fatalf("TestCleanRawMessageCrossPkg refused: %+v", sha3Obs[sha3Subjects[0]])
	}
	for _, s := range sha3Subjects[1:] {
		if sha3Obs[s].Observable {
			t.Fatalf("%s admitted despite cross-package crypto/sha3 exposure: %+v", s.Symbol, sha3Obs[s])
		}
		t2, _, err := computeTier2ResultAndReach(h, s.Package, s.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		if !t2.unverifiable && !t2.widen {
			t.Fatalf("%s tier2 admitted cross-package crypto/sha3 exposure: %+v", s.Symbol, t2)
		}
	}

	jsonV2Env := environmentWith("GOEXPERIMENT=jsonv2")
	jh, err := newAtEnv(t.Context(), dir, jsonV2Env)
	if err != nil {
		t.Fatal(err)
	}
	if !jh.SelectionAudited() {
		t.Fatalf("GOEXPERIMENT=jsonv2 selection not audited: %s", jh.SelectionNotice())
	}
	crossJSONSubjects := []Subject{
		{Package: pkgB, Symbol: "TestCleanRawMessageCrossPkg"},
		{Package: pkgB, Symbol: "TestCrossPkgJSONFieldStatic"},
		{Package: pkgB, Symbol: "TestCrossPkgJSONAliasFuncValue"},
		{Package: pkgB, Symbol: "TestCrossPkgJSONFieldInvoke"},
		{Package: pkgB, Symbol: "TestCrossPkgJSONAliasInvoke"},
	}
	crossObs, err := jh.ComputeObservabilityBatch(crossJSONSubjects)
	if err != nil {
		t.Fatal(err)
	}
	if !crossObs[crossJSONSubjects[0]].Observable {
		t.Fatalf("TestCleanRawMessageCrossPkg refused under jsonv2: %+v", crossObs[crossJSONSubjects[0]])
	}
	for _, s := range crossJSONSubjects[1:] {
		if crossObs[s].Observable {
			t.Fatalf("%s admitted despite cross-package jsontext exposure: %+v", s.Symbol, crossObs[s])
		}
		t2, _, err := computeTier2ResultAndReach(jh, s.Package, s.Symbol)
		if err != nil {
			t.Fatal(err)
		}
		if !t2.unverifiable && !t2.widen {
			t.Fatalf("%s tier2 admitted cross-package jsontext exposure: %+v", s.Symbol, t2)
		}
	}

	// Sibling-test batch equivalence: importing encoding/json/jsontext in
	// dirty_jsonv2_test.go must not poison TestCleanRawMessageSibling in
	// clean_test.go, regardless of batch order or solo execution.
	cleanSubj := Subject{Package: pkgIso, Symbol: "TestCleanRawMessageSibling"}
	dirtySubj := Subject{Package: pkgIso, Symbol: "TestDirtyDirectJSONTextSibling"}

	jhIso1, err := newAtEnv(t.Context(), dir, jsonV2Env)
	if err != nil {
		t.Fatal(err)
	}
	batch1, err := jhIso1.ComputeObservabilityBatch([]Subject{cleanSubj, dirtySubj})
	if err != nil {
		t.Fatal(err)
	}
	jhIso2, err := newAtEnv(t.Context(), dir, jsonV2Env)
	if err != nil {
		t.Fatal(err)
	}
	batch2, err := jhIso2.ComputeObservabilityBatch([]Subject{dirtySubj, cleanSubj})
	if err != nil {
		t.Fatal(err)
	}
	jhSoloClean, err := newAtEnv(t.Context(), dir, jsonV2Env)
	if err != nil {
		t.Fatal(err)
	}
	soloClean, err := jhSoloClean.ComputeObservabilityBatch([]Subject{cleanSubj})
	if err != nil {
		t.Fatal(err)
	}
	if !batch1[cleanSubj].Observable || !batch1[cleanSubj].EffectFree {
		t.Fatalf("clean sibling refused when batched with jsontext sibling: %+v", batch1[cleanSubj])
	}
	if batch1[dirtySubj].Observable {
		t.Fatalf("dirty jsontext sibling admitted: %+v", batch1[dirtySubj])
	}
	if batch1[cleanSubj] != batch2[cleanSubj] || batch1[cleanSubj] != soloClean[cleanSubj] {
		t.Fatalf("batch equivalence violated for clean sibling: b1=%+v b2=%+v solo=%+v", batch1[cleanSubj], batch2[cleanSubj], soloClean[cleanSubj])
	}
	if t2Clean, _, err := computeTier2ResultAndReach(jhIso1, pkgIso, cleanSubj.Symbol); err != nil {
		t.Fatal(err)
	} else if t2Clean.unverifiable || t2Clean.widen {
		t.Fatalf("clean sibling tier2 poisoned by jsontext sibling: %+v", t2Clean)
	}
}

func TestPkgIncludeHeaderMutationInvalidatesWarmCacheAndRefusesAudit(t *testing.T) {
	if testing.Short() {
		t.Skip("copies GOROOT/src and lists standard library")
	}
	isolateProofCache(t)

	hostGOROOT := runtime.GOROOT()
	fakeGOROOT, env := testenv.OverlayGOROOTEnv(t, os.Environ(), nil)
	workDir := t.TempDir()

	textflagPath := filepath.Join(fakeGOROOT, "pkg", "include", "textflag.h")
	hostTextflagPath := filepath.Join(hostGOROOT, "pkg", "include", "textflag.h")
	hostInfo, err := os.Stat(hostTextflagPath)
	if err != nil {
		t.Fatal(err)
	}
	fakeInfo, err := os.Stat(textflagPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(hostInfo, fakeInfo) {
		t.Fatal("overlay pkg/include/textflag.h shares host GOROOT inode")
	}

	cold, err := newAtEnv(t.Context(), workDir, env)
	if err != nil {
		t.Fatal(err)
	}
	if !cold.SelectionAudited() {
		t.Fatalf("clean overlay GOROOT refused: %s", cold.SelectionNotice())
	}
	origContent := cold.ToolchainContent()
	if origContent == "" {
		t.Fatal("empty ToolchainContent on clean overlay GOROOT")
	}

	origTextflag, err := os.ReadFile(textflagPath)
	if err != nil {
		t.Fatal(err)
	}
	overwriteTextflag := func(content []byte) {
		t.Helper()
		if err := os.Remove(textflagPath); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.WriteFile(textflagPath, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Mutate GOROOT/pkg/include/textflag.h against the warm XDG_CACHE_HOME,
	// exercising both SYSCALL traps and runtime·walltime / lowercase macro aliasing.
	for _, injection := range []string{
		"\n#define EVIL_TRAP SYSCALL\n",
		"\n#define READ_WALL CALL runtime·walltime(SB)\n",
		"\n#define strings runtime\n",
	} {
		overwriteTextflag(append(slices.Clone(origTextflag), []byte(injection)...))
		afterEdit, err := newAtEnv(t.Context(), workDir, env)
		if err != nil {
			t.Fatal(err)
		}
		if afterEdit.ToolchainContent() == origContent {
			t.Fatalf("ToolchainContent() unchanged (%s) after injecting %q into pkg/include/textflag.h", origContent, injection)
		}
		if afterEdit.SelectionAudited() {
			t.Fatalf("SelectionAudited() = true after injecting %q into pkg/include/textflag.h", injection)
		}
		if !strings.Contains(afterEdit.SelectionNotice(), "runtime") {
			t.Fatalf("SelectionNotice() = %q, want runtime failure attribution", afterEdit.SelectionNotice())
		}
	}

	// Restore textflag.h and add a brand-new header file in pkg/include to verify
	// directory-stamp and full-directory verification coverage.
	overwriteTextflag(origTextflag)
	extraHdr := filepath.Join(fakeGOROOT, "pkg", "include", "injected_trap.h")
	if err := os.WriteFile(extraHdr, []byte("#define EXTRA_TRAP SYSENTER\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	afterAdd, err := newAtEnv(t.Context(), workDir, env)
	if err != nil {
		t.Fatal(err)
	}
	if afterAdd.ToolchainContent() == origContent {
		t.Fatalf("ToolchainContent() unchanged (%s) after adding pkg/include/injected_trap.h", origContent)
	}
	if afterAdd.SelectionAudited() {
		t.Fatal("SelectionAudited() = true after adding SYSENTER macro header to pkg/include")
	}
}

func TestToolchainSurfaceAdmitsCrossTargetSelections(t *testing.T) {
	if testing.Short() {
		t.Skip("lists cross-target standard libraries")
	}
	isolateProofCache(t)
	ctx := t.Context()
	dir := t.TempDir()
	for _, tc := range []struct {
		name     string
		settings []string
	}{
		{"linux_amd64", []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"}},
		{"windows_amd64", []string{"GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0"}},
		{"plan9_amd64", []string{"GOOS=plan9", "GOARCH=amd64", "CGO_ENABLED=0"}},
		{"darwin_arm64", []string{"GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0"}},
		{"wasip1_wasm", []string{"GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0"}},
		{"js_wasm", []string{"GOOS=js", "GOARCH=wasm", "CGO_ENABLED=0"}},
	} {
		env, err := gotool.NormalizeEnv(environmentWith(tc.settings...))
		if err != nil {
			t.Fatalf("%s NormalizeEnv: %v", tc.name, err)
		}
		reader := gotool.NewEnvReader(gotool.Runner{}, dir, env)
		snapshot, err := reader.Snapshot(ctx)
		if err != nil {
			t.Fatalf("%s Snapshot: %v", tc.name, err)
		}
		d, err := toolchainSourceDigests(ctx, gotool.Runner{}, dir, env, snapshot, nil)
		if err != nil {
			t.Fatalf("%s toolchainSourceDigests: %v", tc.name, err)
		}
		if failed := verifyToolchainSurface(d); len(failed) != 0 {
			var details []string
			for _, pkg := range failed {
				details = append(details, pkg+": "+fmtSprintErr(verifyListedPackage(d.inventory[pkg])))
			}
			t.Fatalf("%s surface verification failed on %v (%v)", tc.name, failed, details)
		}
	}
}

func fmtSprintErr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// listingMemoModule writes a module whose view package imports a sibling
// carrying an embed tree (with an empty subdirectory), leaves a third
// package unimported, and carries an empty non-package directory the
// tests use as a working directory below the module root.
func listingMemoModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":           "module example.com/lm\n\ngo 1.26\n",
		"a/a.go":           "package a\n\nimport \"example.com/lm/b\"\n\nfunc F() int { return b.G() }\n",
		"b/b.go":           "package b\n\nimport \"embed\"\n\n//go:embed assets\nvar assets embed.FS\n\nfunc G() int {\n\tentries, _ := assets.ReadDir(\"assets\")\n\treturn len(entries)\n}\n",
		"b/assets/one.txt": "one\n",
		"b/assets/empty/":  "",
		"b/NOTES.md":       "notes\n",
		"c/c.go":           "package c\n\nfunc Unrelated() int { return 3 }\n",
		"deep/":            "",
	})
	return dir
}

const listingMemoPkg = "example.com/lm/a"

// listFrom builds a Hasher over dir from snapshot and lists pkg,
// returning the listing, the number of toolchain spawns it paid, the
// Hasher, and the listing error if any.
func listFrom(t *testing.T, dir, pkg string, env []string, snapshot *gotool.EnvSnapshot, flags ...string) ([]listPkg, int, *Hasher, error) {
	t.Helper()
	h, err := NewAt(context.Background(), gotool.PrimedEnvReader(gotool.Runner{}, dir, env, snapshot), flags...)
	if err != nil {
		t.Fatal(err)
	}
	spawns := 0
	h.OnProgress(func(phase, _ string) {
		if phase == "list" {
			spawns++
		}
	})
	// This helper measures the declaration-listing cache, independently of
	// admission to an analysis (including a module-less stdlib test listing).
	pkgs, err := h.listUnvalidated(pkg)
	return pkgs, spawns, h, err
}

func listOnce(t *testing.T, dir string, env []string, snapshot *gotool.EnvSnapshot, flags ...string) ([]listPkg, int, *Hasher) {
	t.Helper()
	pkgs, spawns, h, err := listFrom(t, dir, listingMemoPkg, env, snapshot, flags...)
	if err != nil {
		t.Fatal(err)
	}
	return pkgs, spawns, h
}

func snapshotFor(t *testing.T, dir string, env []string) *gotool.EnvSnapshot {
	t.Helper()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// A second Hasher over an unchanged tree serves the listing from the memo
// without a spawn, identical to the spawned one (REQ-closure-listing-memo).
func TestListingMemoServesTheListingWithoutASpawn(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the toolchain over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := listingMemoModule(t)
	env := listingEnv("", "")
	cold, spawns, _ := listOnce(t, dir, env, snapshotFor(t, dir, env))
	if spawns != 1 {
		t.Fatalf("cold listing paid %d spawns, want 1", spawns)
	}
	// A fresh snapshot, as every process takes its own: the scope must
	// render identically for one environment.
	warm, spawns, h := listOnce(t, dir, env, snapshotFor(t, dir, env))
	if spawns != 0 {
		t.Fatalf("warm listing paid %d spawns", spawns)
	}
	if !h.ServedSummary()["listing"][listingMemoPkg] {
		t.Fatalf("served summary lacks the listing: %v", h.ServedSummary())
	}
	if !reflect.DeepEqual(warm, cold) {
		t.Fatalf("served listing differs from the spawned one:\n got %+v\nwant %+v", warm, cold)
	}
	if len(h.fileDigests) == 0 {
		t.Fatal("verification recorded no file digests for the fold")
	}
	// Every Hasher holds its pass's snapshot — a reader takes one when
	// none is handed on — so a fresh pass over the same environment
	// serves the listing too: the snapshot-less, unscoped state is
	// unrepresentable.
	if _, spawns, _ := listOnce(t, dir, env, nil); spawns != 0 {
		t.Fatalf("a fresh pass's listing paid %d spawns, want 0 (served under the pass's own snapshot)", spawns)
	}
}

// Every recorded input moves the memo: an edit or a new file in a listed
// package directory, a new file anywhere under an embed tree (an empty
// subdirectory included), a module-file edit, go.sum or a vendor
// manifest appearing, a workspace file appearing on the ancestor chain,
// a module file appearing between the working directory and the module
// root, and a changed flag set all refuse to serve; an edit outside the
// graph serves, and so does an edit to a non-source file in a listed
// directory (the listing reads its name, never its bytes); a flag naming a module file leaves the memo inert; a
// corrupt entry recomputes (REQ-closure-listing-memo).
func TestListingMemoKeyTracksEveryConsultedInput(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the toolchain over it")
	}
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	dir := listingMemoModule(t)
	// The working directory sits below the module root so the absence
	// of a module file between them is a recorded input.
	work := filepath.Join(dir, "deep")
	env := listingEnv("", "")
	snapshot := snapshotFor(t, work, env)
	listOnce(t, work, env, snapshot)
	appendTo := func(rel, text string) func() {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		original, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, append(append([]byte(nil), original...), []byte(text)...), 0o644); err != nil {
			t.Fatal(err)
		}
		return func() { os.WriteFile(full, original, 0o644) }
	}
	create := func(rel, text string) func() {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return func() { os.Remove(full) }
	}
	cases := []struct {
		name   string
		mutate func() func()
		serves bool
	}{
		{"edit inside a listed package", func() func() { return appendTo("b/b.go", "\n// edit\n") }, false},
		{"new file in a listed package", func() func() { return create("b/extra.go", "package b\n") }, false},
		{"new file under the embed tree", func() func() { return create("b/assets/two.txt", "two\n") }, false},
		{"new file in an empty embed subdirectory", func() func() { return create("b/assets/empty/new.txt", "new\n") }, false},
		{"module file edit", func() func() { return appendTo("go.mod", "\n// edit\n") }, false},
		{"go.sum appearing", func() func() { return create("go.sum", "") }, false},
		{"vendor manifest appearing", func() func() { return create("vendor/modules.txt", "") }, false},
		{"workspace file appearing", func() func() { return create("go.work", "go 1.26\n\nuse .\n") }, false},
		{"module file appearing below the root", func() func() { return create("deep/go.mod", "module example.com/deep\n\ngo 1.26\n") }, false},
		{"non-source file edit in a listed package", func() func() { return appendTo("b/NOTES.md", "more\n") }, true},
		{"edit outside the graph", func() func() { return appendTo("c/c.go", "\n// edit\n") }, true},
		{"new file outside the graph", func() func() { return create("c/extra.go", "package c\n") }, true},
	}
	for _, tc := range cases {
		restore := tc.mutate()
		_, spawns, _, err := listFrom(t, work, listingMemoPkg, env, snapshot)
		restore()
		served := err == nil && spawns == 0
		if served != tc.serves {
			t.Fatalf("%s: served=%t (spawns %d, err %v), want served=%t", tc.name, served, spawns, err, tc.serves)
		}
		// Re-store the pristine tree's listing for the next case.
		listOnce(t, work, env, snapshot)
	}
	if _, spawns, _ := listOnce(t, work, env, snapshot, "-tags=x"); spawns != 1 {
		t.Fatalf("a changed flag set paid %d spawns, want 1", spawns)
	}
	modfileEnv := listingEnv("-modfile=go.mod", "")
	modfileSnapshot := snapshotFor(t, dir, modfileEnv)
	listOnce(t, dir, modfileEnv, modfileSnapshot)
	if _, spawns, _ := listOnce(t, dir, modfileEnv, modfileSnapshot); spawns != 1 {
		t.Fatalf("a modfile flag left the memo active: %d spawns", spawns)
	}
	entries, _ := filepath.Glob(filepath.Join(cache, "gofresh", listingDirName, "*.json"))
	if len(entries) == 0 {
		t.Fatal("no listing entries persisted")
	}
	for _, e := range entries {
		if err := os.WriteFile(e, []byte("{not json"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, spawns, _ := listOnce(t, work, env, snapshot); spawns != 1 {
		t.Fatalf("a corrupt entry served: %d spawns", spawns)
	}
}

// The module graph's files are inputs whether or not their module
// contributes a package: a workspace's every used module's go.mod, the
// workspace file itself, and the target of a local replacement the main
// module names all refuse to serve when edited (REQ-closure-listing-memo).
func TestListingMemoRecordsTheModuleGraphsFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("builds module fixtures and runs the toolchain over them")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"go.work":     "go 1.26\n\nuse (\n\t./a\n\t./b\n)\n",
		"a/go.mod":    "module example.com/wa\n\ngo 1.26\n",
		"a/a.go":      "package wa\n\nfunc F() int { return 1 }\n",
		"b/go.mod":    "module example.com/wb\n\ngo 1.26\n",
		"b/b.go":      "package wb\n\nfunc G() int { return 2 }\n",
		"rep/go.mod":  "module example.com/rep\n\ngo 1.26\n",
		"rep/r.go":    "package rep\n\nfunc R() int { return 3 }\n",
		"rep2/go.mod": "module example.com/rep2\n\ngo 1.26\n",
		"rep2/r.go":   "package rep2\n\nfunc R() int { return 4 }\n",
	})
	// The replacement is named by a's go.mod but no package of a imports
	// it: its module file is still a graph input.
	// a also replaces the used module b (the standalone-and-workspace
	// pattern), so b's module file is first recorded as a's replacement
	// target; b's own replacement of rep2 must still be scanned.
	if err := os.WriteFile(filepath.Join(root, "a", "go.mod"), []byte("module example.com/wa\n\ngo 1.26\n\nrequire (\n\texample.com/rep v0.0.0\n\texample.com/wb v0.0.0\n)\n\nreplace (\n\texample.com/rep => ../rep\n\texample.com/wb => ../b\n)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b", "go.mod"), []byte("module example.com/wb\n\ngo 1.26\n\nrequire example.com/rep2 v0.0.0\n\nreplace example.com/rep2 => ../rep2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "a")
	env := listingEnv("", "")
	snapshot := snapshotFor(t, work, env)
	if got := snapshot.Value("GOWORK"); got != filepath.Join(root, "go.work") {
		t.Fatalf("GOWORK = %q, want the fixture's workspace file", got)
	}
	list := func() (int, error) {
		_, spawns, _, err := listFrom(t, work, "example.com/wa", env, snapshot)
		return spawns, err
	}
	if spawns, err := list(); err != nil || spawns != 1 {
		t.Fatalf("cold listing: spawns %d, err %v", spawns, err)
	}
	if spawns, err := list(); err != nil || spawns != 0 {
		t.Fatalf("warm listing: spawns %d, err %v", spawns, err)
	}
	for _, rel := range []string{"b/go.mod", "go.work", "rep/go.mod", "rep2/go.mod"} {
		full := filepath.Join(root, filepath.FromSlash(rel))
		original, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, append(append([]byte(nil), original...), []byte("\n// edit\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
		spawns, err := list()
		if err := os.WriteFile(full, original, 0o644); err != nil {
			t.Fatal(err)
		}
		if err == nil && spawns == 0 {
			t.Fatalf("an edit to %s served the stale listing", rel)
		}
		list()
	}
	// A vendor manifest at the workspace root — where `go work vendor`
	// writes it — is a graph input too.
	if err := os.WriteFile(filepath.Join(root, "vendor", "modules.txt"), []byte(""), 0o644); err != nil {
		if err := os.MkdirAll(filepath.Join(root, "vendor"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "vendor", "modules.txt"), []byte(""), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if spawns, err := list(); err == nil && spawns == 0 {
		t.Fatal("a workspace vendor manifest appearing served the stale listing")
	}
}

// A main package whose module path ends in ".test" is a package like
// any other: its own directory is recorded, so a new file there refuses
// to serve — only the requested package's generated test main is
// scaffolding outside the model (REQ-closure-listing-memo).
func TestListingMemoRecordsADotTestModulesOwnDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the toolchain over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":     "module example.test\n\ngo 1.26\n",
		"main.go":    "package main\n\nimport \"example.test/lib\"\n\nfunc main() { _ = lib.L() }\n",
		"lib/lib.go": "package lib\n\nfunc L() int { return 1 }\n",
	})
	env := listingEnv("", "off")
	snapshot := snapshotFor(t, dir, env)
	if _, spawns, _, err := listFrom(t, dir, "example.test", env, snapshot); err != nil || spawns != 1 {
		t.Fatalf("cold: spawns %d, err %v", spawns, err)
	}
	if _, spawns, _, err := listFrom(t, dir, "example.test", env, snapshot); err != nil || spawns != 0 {
		t.Fatalf("warm: spawns %d, err %v", spawns, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "extra.go"), []byte("package main\n\nimport _ \"net/http\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, spawns, _, err := listFrom(t, dir, "example.test", env, snapshot); err == nil && spawns == 0 {
		t.Fatal("a new file in the subject's own directory served the stale listing")
	}
}

// A vendored dependency carries no module directory: its tree is
// recorded as mutable-local source under the main module, every path in
// the record is absolute, and the listing serves from any process
// working directory (REQ-closure-listing-memo).
func TestListingMemoServesVendoredTreesFromAnyWorkingDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the toolchain over it")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":                        "module example.com/vm\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\n",
		"v.go":                          "package vm\n\nimport \"example.com/dep\"\n\nfunc V() int { return dep.D() }\n",
		"vendor/modules.txt":            "# example.com/dep v0.0.0\n## explicit; go 1.26\nexample.com/dep\n",
		"vendor/example.com/dep/dep.go": "package dep\n\nfunc D() int { return 1 }\n",
	})
	env := listingEnv("", "off")
	snapshot := snapshotFor(t, dir, env)
	if _, spawns, _, err := listFrom(t, dir, "example.com/vm", env, snapshot); err != nil || spawns != 1 {
		t.Fatalf("cold: spawns %d, err %v", spawns, err)
	}
	// The module root holds a go.mod: a working-directory-relative record
	// would resolve differently here and refuse.
	t.Chdir(dir)
	if _, spawns, _, err := listFrom(t, dir, "example.com/vm", env, snapshot); err != nil || spawns != 0 {
		t.Fatalf("warm from another working directory: spawns %d, err %v", spawns, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vendor", "example.com", "dep", "dep.go"), []byte("package dep\n\nfunc D() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, spawns, _, err := listFrom(t, dir, "example.com/vm", env, snapshot); err == nil && spawns == 0 {
		t.Fatal("an edit inside the vendor tree served the stale listing")
	}
}

// A listing whose inputs cannot be modelled — no main module contains
// the working directory — is never stored: every pass spawns
// (REQ-closure-listing-memo).
func TestListingMemoStoresNothingWithoutAMainModule(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the toolchain over a module-less directory")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	env := listingEnv("", "off")
	snapshot := snapshotFor(t, dir, env)
	for i := 0; i < 2; i++ {
		_, spawns, _, err := listFrom(t, dir, "fmt", env, snapshot)
		if err != nil || spawns != 1 {
			t.Fatalf("pass %d: spawns %d, err %v — a module-less listing was stored", i, spawns, err)
		}
	}
}

// The record's Go shape is part of the scope: a Hasher whose record type
// differs — as an older binary's would — never decodes this binary's
// entries, and the shape identity is a function of the type alone.
func TestListingScopeCarriesTheRecordShape(t *testing.T) {
	if testing.Short() {
		t.Skip("toolchain integration test")
	}
	if listingShape != typeShape(reflect.TypeOf(listingRecord{})) {
		t.Fatal("shape identity is not a function of the record type")
	}
	type other struct {
		Version  int
		Files    map[string]string
		Dirs     map[string][]string
		Absent   []string
		Packages []listPkg
		Extra    string
	}
	if typeShape(reflect.TypeOf(other{})) == listingShape {
		t.Fatal("a record type with an extra field has the same shape identity")
	}
	h := &Hasher{snapshot: &gotool.EnvSnapshot{}, dir: "/x", source: sourceDigests{Content: "content", Policy: "policy"}}
	if !strings.Contains(h.listingScope(), "|"+listingShape+"|") {
		t.Fatalf("scope %q does not carry the shape", h.listingScope())
	}

	// Quoted GOFLAGS containing "-modfile=..." as a substring of another flag's
	// value must not disable listingScope, whereas a quoted "-modfile=..." flag
	// or malformed quote in GOFLAGS must disable it.
	dir := t.TempDir()
	snapNonModfile := snapshotFor(t, dir, gotool.SetEnv(os.Environ(), "GOFLAGS", `"-ldflags=-X main.v=-modfile=alt.mod"`))
	hNonModfile := &Hasher{snapshot: snapNonModfile, dir: "/x", source: sourceDigests{Content: "content", Policy: "policy"}}
	if hNonModfile.listingScope() == "" {
		t.Fatal("listingScope disabled by non-modfile quoted GOFLAGS")
	}
	snapQuotedModfile := snapshotFor(t, dir, gotool.SetEnv(os.Environ(), "GOFLAGS", `"-modfile=/tmp/with space/go.mod"`))
	hQuotedModfile := &Hasher{snapshot: snapQuotedModfile, dir: "/x", source: sourceDigests{Content: "content", Policy: "policy"}}
	if got := hQuotedModfile.listingScope(); got != "" {
		t.Fatalf("listingScope under quoted -modfile = %q, want empty", got)
	}

	shimDir := t.TempDir()
	shimPath := filepath.Join(shimDir, "go")
	if err := os.WriteFile(shimPath, []byte("#!/bin/sh\nprintf '{\"GOVERSION\":\"go1.26.0\",\"GOFLAGS\":\"'\"'\"'-tags=unterminated\"}\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir)
	snapMalformed := snapshotFor(t, dir, gotool.SetEnv(os.Environ(), "PATH", shimDir))
	hMalformed := &Hasher{snapshot: snapMalformed, dir: "/x", source: sourceDigests{Content: "content", Policy: "policy"}}
	if got := hMalformed.listingScope(); got != "" {
		t.Fatalf("listingScope under malformed GOFLAGS = %q, want empty", got)
	}
}

// fixtureEvidence projects identities rather than pointers or raw token.Pos:
// independent loads own different type universes and file-set base offsets.
type fixtureEvidence struct {
	Proof                                                 Observability
	All, Subject, Startup, Harness                        []string
	Resolved                                              []string
	Targets                                               map[string][]string
	Whole, SubjectEffects, StartupEffects, HarnessEffects tier2Result
}

func fixtureProgramEvidence(t *testing.T, dir string, p *program, symbol string) fixtureEvidence {
	t.Helper()
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: p.PkgPath, Symbol: symbol}
	rows, err := attributedReachableSets(h.ctx, h.SelectionAudited(), h.source.pureDelegates, p, []Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	r := rows[0]
	ids := map[*types.Package]string{}
	for _, pkg := range p.Pkgs {
		ids[pkg.Types] = pkg.ID
	}
	fnKey := func(fn *ssa.Function) string {
		if fn == nil {
			return "<nil>"
		}
		id := ""
		if fn.Pkg != nil {
			id = ids[fn.Pkg.Pkg]
		}
		pos := p.Prog.Fset.PositionFor(fn.Pos(), false)
		return fmt.Sprintf("%s|%s|%s:%d|%s", id, fn.String(), pos.Filename, pos.Offset, fn.Synthetic)
	}
	set := func(m map[*ssa.Function]bool) []string {
		var out []string
		for fn, present := range m {
			if present {
				out = append(out, fnKey(fn))
			}
		}
		slices.Sort(out)
		return out
	}
	siteKey := func(site ssa.CallInstruction) string {
		pos := p.Prog.Fset.PositionFor(site.Pos(), false)
		return fmt.Sprintf("%s|%s:%d|%s", fnKey(site.Parent()), pos.Filename, pos.Offset, site.String())
	}
	e := fixtureEvidence{All: set(r.functions), Subject: set(r.subjectFunctions), Startup: set(r.startupFunctions), Harness: set(r.testMainFunctions), Targets: map[string][]string{}}
	for site, yes := range r.resolved {
		if yes {
			e.Resolved = append(e.Resolved, siteKey(site))
		}
	}
	slices.Sort(e.Resolved)
	for site, targets := range r.dynamicTargets {
		e.Targets[siteKey(site)] = set(targets)
	}
	metas, err := h.list(p.PkgPath)
	if err != nil {
		t.Fatal(err)
	}
	base := newTier2Base(h, p, metas)
	e.Whole, err = h.tier2Reachable(base, r)
	if err != nil {
		t.Fatal(err)
	}
	subjectReach := r
	subjectReach.functions = r.subjectFunctions
	e.SubjectEffects, err = h.tier2Reachable(base, subjectReach)
	if err != nil {
		t.Fatal(err)
	}
	startupReach := r
	startupReach.functions = nonStandardFunctions(base, r.startupFunctions)
	e.StartupEffects = directExternalEffects(base, startupReach)
	harnessReach := r
	harnessReach.functions = nonStandardFunctions(base, r.testMainFunctions)
	e.HarnessEffects = testMainObservedEffects(base, harnessReach)
	for _, result := range []*tier2Result{&e.Whole, &e.SubjectEffects, &e.StartupEffects, &e.HarnessEffects} {
		slices.SortFunc(result.effects, func(a, b externalEffect) int { return strings.Compare(fmt.Sprintf("%+v", a), fmt.Sprintf("%+v", b)) })
	}
	// Exercise the public singleton pipeline too: the raw projection above
	// cannot stand in for its full disposition, diagnostics and outcome method.
	p.PkgScopeProbe = nil
	h.progs[p.PkgPath] = p
	proofs, err := h.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	e.Proof = proofs[subject]
	return e
}

func assertFixtureEvidence(t *testing.T, got, want fixtureEvidence) {
	t.Helper()
	g, w := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := 0; i < g.NumField(); i++ {
		if !reflect.DeepEqual(g.Field(i).Interface(), w.Field(i).Interface()) {
			t.Errorf("prepared/independent evidence differs in %s", g.Type().Field(i).Name)
		}
	}
}

func TestFixturePreparationPreservesIndependentEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("compares independent whole-program analyses")
	}
	const base = "github.com/greatliontech/gofresh/internal/closure/testdata/"
	cases := []struct {
		path, symbol string
		observable   bool
	}{
		{base + "observable", "TestReadFile", true},
		{base + "initfile", "TestInitFile", false},
		{base + "observablemutation", "TestRemove", false},
		{base + "harnessroot", "BenchmarkProd", true},
	}
	h, err := newAt("")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, tc := range cases {
		paths = append(paths, tc.path)
	}
	prepared, err := progpkg.Prepare(h.ctx, h.dir, h.packageEnv, h.buildFlags, paths...)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.symbol, func(t *testing.T) {
			p, err := prepared.Build(t.Context(), tc.path)
			if err != nil {
				t.Fatal(err)
			}
			got := fixtureProgramEvidence(t, h.dir, p, tc.symbol)
			p, err = progpkg.Load(t.Context(), h.dir, h.packageEnv, h.buildFlags, tc.path)
			if err != nil {
				t.Fatal(err)
			}
			want := fixtureProgramEvidence(t, h.dir, p, tc.symbol)
			assertFixtureEvidence(t, got, want)
			if got.Proof.Observable != tc.observable {
				t.Fatalf("positive/negative control: %+v", got.Proof)
			}
		})
	}
}

func TestFixturePreparationExcludesForeignInitializersAndCallers(t *testing.T) {
	if testing.Short() {
		t.Skip("compares independent whole-program analyses")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":      "module example.com/isolation\n\ngo 1.27\n",
		"p/p.go":      "package p\nfunc Run(check func() bool) bool { return check() }\nfunc Local() bool { return Run(func() bool { return true }) }\n",
		"caller/p.go": "package caller\nimport (\"os\"; \"example.com/isolation/p\")\nfunc Foreign() bool { return p.Run(func() bool { return os.WriteFile(\"foreign\", nil, 0600) == nil }) }\n",
		"poison/p.go": "package poison\nimport \"os\"\nfunc init() { _ = os.WriteFile(\"poison\", nil, 0600) }\n",
	}
	for name, text := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, name, text)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	const target = "example.com/isolation/p"
	// First isolate caller enumeration, then add unrelated startup poison.
	for _, paths := range [][]string{{target, "example.com/isolation/caller"}, {target, "example.com/isolation/caller", "example.com/isolation/poison"}} {
		prepared, err := progpkg.Prepare(h.ctx, dir, h.packageEnv, nil, paths...)
		if err != nil {
			t.Fatal(err)
		}
		p, err := prepared.Build(t.Context(), target)
		if err != nil {
			t.Fatal(err)
		}
		got := fixtureProgramEvidence(t, dir, p, "Run")
		p, err = progpkg.Load(t.Context(), dir, h.packageEnv, nil, target)
		if err != nil {
			t.Fatal(err)
		}
		want := fixtureProgramEvidence(t, dir, p, "Run")
		assertFixtureEvidence(t, got, want)
		if !got.Proof.Observable {
			t.Fatalf("foreign fixture contaminated closed subject: %+v", got.Proof)
		}
	}
}

// BenchmarkFixturePreparation compares identical source-loading/SSA workloads.
// Each iteration owns a new generation, each target a fresh SSA program. Neither
// arm computes or serves proof memos. Typed-graph retention lasts one iteration;
// allocation totals are not a measurement of its live or peak resident memory.
//
//gofresh:pure
func BenchmarkFixturePreparation(b *testing.B) {
	const base = "github.com/greatliontech/gofresh/internal/closure/testdata/"
	paths := []string{base + "observable", base + "external", base + "initfile", base + "rootcollision/bench"}
	h, err := newAt("")
	if err != nil {
		b.Fatal(err)
	}
	b.Run("independent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, path := range paths {
				if _, err := progpkg.Load(b.Context(), h.dir, h.packageEnv, h.buildFlags, path); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("prepared", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			prepared, err := progpkg.Prepare(b.Context(), h.dir, h.packageEnv, h.buildFlags, paths...)
			if err != nil {
				b.Fatal(err)
			}
			for _, path := range paths {
				if _, err := prepared.Build(b.Context(), path); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}

// BenchmarkComputeObservabilityBatch measures the proof analyzer end to end
// over a mixed fixture set — the per-target cost a consumer's capture batch
// pays. Allocations are the tracked axis; the memo is disabled (no scope)
// so the analysis itself is measured.
//
//gofresh:pure
func BenchmarkComputeObservabilityBatch(b *testing.B) {
	const base = "github.com/greatliontech/gofresh/internal/closure/testdata/"
	subjects := []Subject{
		{Package: base + "observable", Symbol: "TestReadFile"},
		{Package: base + "observable", Symbol: "TestGetenv"},
		{Package: base + "observablebad", Symbol: "TestOpenStat"},
		{Package: base + "observablefresh", Symbol: "TestFreshFileNameEscape"},
		{Package: base + "observablemutation", Symbol: "TestRemove"},
	}
	b.ReportAllocs()
	for b.Loop() {
		h, err := newAt("")
		if err != nil {
			b.Fatal(err)
		}
		if _, err := h.ComputeObservabilityBatch(subjects); err != nil {
			b.Fatal(err)
		}
	}
}

// A shared view load must fully substitute for the testing-type effect scan's
// private load — same effects, no second typed load inside the pass
// (REQ-fresh-coherent-view: one load per observation pass).
func TestViewLoadSubstitutesForTestingTypeScanLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/viewload\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib.go"), []byte("package viewload\n\nfunc F() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib_test.go"), []byte("package viewload\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tt.TempDir()\n\tif F() != 1 {\n\t\tt.Fatal(\"broken\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/viewload"
	subjects := []Subject{{Package: pkg, Symbol: "TestF"}}

	unshared, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	want, _, err := unshared.ComputeMaximalBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}

	load, err := loadViewPackagesEnv(context.Background(), dir, os.Environ(), nil, pkg)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	shared.UseViewLoad(load)
	var privateLoads []string
	var got map[Subject]Closure
	withClosureTestHooks(analysisTestHookSet{
		testingTypeOwnLoad: func(pkgPath string) { privateLoads = append(privateLoads, pkgPath) },
	}, func() {
		got, _, err = shared.ComputeMaximalBatch(subjects)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(privateLoads) != 0 {
		t.Fatalf("testing-type scan performed private loads despite a covering view load: %v", privateLoads)
	}
	for _, subject := range subjects {
		if got[subject] != want[subject] {
			t.Fatalf("shared view load changed the closure for %s:\n  unshared %+v\n  shared   %+v", subject.Symbol, want[subject], got[subject])
		}
	}
	if !got[subjects[0]].Unverifiable {
		t.Fatal("fixture should be unverifiable through its testing-runtime effect (t.TempDir); the testing-type scan did not run")
	}
}

// A view load that does not cover the requested package falls back to the
// private load with identical semantics rather than failing or silently
// skipping the scan.
func TestViewLoadMissFallsBackToPrivateTestingTypeLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/viewloadmiss\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib.go"), []byte("package viewloadmiss\n\nfunc F() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lib_test.go"), []byte("package viewloadmiss\n\nimport \"testing\"\n\nfunc TestF(t *testing.T) {\n\tt.TempDir()\n\t_ = F()\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "other.go"), []byte("package other\n\nfunc G() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const pkg = "example.com/viewloadmiss"
	subjects := []Subject{{Package: pkg, Symbol: "TestF"}}

	load, err := loadViewPackagesEnv(context.Background(), dir, os.Environ(), nil, "example.com/viewloadmiss/other")
	if err != nil {
		t.Fatal(err)
	}
	h, err := newAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.UseViewLoad(load)
	var privateLoads []string
	// The private load is a typed load like any other: it reports a
	// typecheck unit naming the package, so an operator sees the cost.
	var units []string
	h.OnUnit(func(phase, pkgPath string, index, total int) {
		if phase == "typecheck" {
			units = append(units, fmt.Sprintf("%s:%d/%d", pkgPath, index, total))
		}
	})
	var got map[Subject]Closure
	withClosureTestHooks(analysisTestHookSet{
		testingTypeOwnLoad: func(pkgPath string) { privateLoads = append(privateLoads, pkgPath) },
	}, func() {
		got, _, err = h.ComputeMaximalBatch(subjects)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(privateLoads) != 1 || privateLoads[0] != pkg {
		t.Fatalf("expected exactly one private fallback load of %s, got %v", pkg, privateLoads)
	}
	if want := []string{pkg + ":0/1"}; !slices.Equal(units, want) {
		t.Fatalf("typecheck units = %v, want %v", units, want)
	}
	if !got[subjects[0]].Unverifiable {
		t.Fatal("fallback path lost the testing-runtime effect")
	}
}

func TestTestVariantInertnessRejectsRebinding(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over a fixture")
	}
	t.Setenv("GOFRESH_BINDING_A", "true")
	t.Setenv("GOFRESH_BINDING_B", "false")
	for _, tc := range []struct{ name, production, test, after string }{
		{"benchmark environment with file-reading sibling", "package p\n", "package p\nimport (\"testing\"; \"fmt\"; \"os\")\nfunc BenchmarkEnv(b *testing.B) { if true { fmt.Println(\"VALUE\", os.Getenv(\"GOFRESH_BINDING_A\")) } else { fmt.Println(\"VALUE\", os.Getenv(\"GOFRESH_BINDING_B\")) } }\nfunc TestValue(t *testing.T) { BenchmarkEnv(nil) }\nfunc TestReadsFile(t *testing.T) { _, _ = os.ReadFile(\"fixture\") }\n", "\nconst true = false\n"},
		{"test universe", "package p\n", "package p\nimport (\"testing\"; \"fmt\")\nfunc TestValue(t *testing.T) { fmt.Println(\"VALUE\", true) }\n", "\nconst true = false\n"},
		{"production universe", "package p\nfunc Value() bool { return true }\n", "package p\nimport (\"testing\"; \"fmt\")\nfunc TestValue(t *testing.T) { fmt.Println(\"VALUE\", Value()) }\n", "\nconst true = false\n"},
		{"import alias", "package p\n", "package p\nimport (\"testing\"; \"fmt\"; x \"example.com/binding/a\"; _ \"example.com/binding/b\")\nfunc TestValue(t *testing.T) { fmt.Println(\"VALUE\", x.Value) }\n", "swap"},
		{"declared import name", "package p\n", "package p\nimport (\"testing\"; \"fmt\"; \"example.com/binding/a\"; _ \"example.com/binding/b\")\nfunc TestValue(t *testing.T) { fmt.Println(\"VALUE\", a.Value) }\n", "swap-default"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTestVariantModule(t, map[string]string{
				"go.mod": "module example.com/binding\n\ngo 1.26\n",
				"p.go":   tc.production, "p_test.go": tc.test,
				"a/a.go": "package a\nconst Value = true\n", "b/b.go": "package a\nconst Value = false\n",
			})
			run := func(want string) {
				t.Helper()
				out, err := (gotool.Runner{}).Run(context.Background(), dir, os.Environ(), "test", "-count=1", "-v", "-run=^TestValue$", ".")
				if err != nil || !strings.Contains(string(out), "VALUE "+want) {
					t.Fatalf("runtime: want %s, got %s, %v", want, out, err)
				}
			}
			subject := Subject{Package: "example.com/binding", Symbol: "TestValue"}
			if tc.name == "benchmark environment with file-reading sibling" {
				subject.Symbol = "BenchmarkEnv"
			}
			beforeCore := computeAt(t, dir, subject)[subject]
			if subject.Symbol == "BenchmarkEnv" && !beforeCore.Unverifiable {
				t.Fatal("file-reading sibling did not preserve the conservative external-input floor")
			}
			before := ledgerAt(t, dir, subject.Package)
			run("true")
			afterSource := tc.test + tc.after
			if tc.after == "swap" {
				afterSource = strings.ReplaceAll(strings.ReplaceAll(tc.test, `x "example.com/binding/a"`, `_ "example.com/binding/a"`), `_ "example.com/binding/b"`, `x "example.com/binding/b"`)
			}
			if tc.after == "swap-default" {
				afterSource = strings.ReplaceAll(strings.ReplaceAll(tc.test, `; "example.com/binding/a"`, `; _ "example.com/binding/a"`), `_ "example.com/binding/b"`, `"example.com/binding/b"`)
			}
			if err := os.WriteFile(filepath.Join(dir, "p_test.go"), []byte(afterSource), 0o644); err != nil {
				t.Fatal(err)
			}
			run("false")
			afterCore := computeAt(t, dir, subject)[subject]
			if beforeCore.Hash != afterCore.Hash {
				t.Fatal("fixture moved core")
			}
			delta := testvariant.DiffTestVariantLedgers(before, ledgerAt(t, dir, subject.Package))
			if len(delta.Changed)+len(delta.Removed) != 0 {
				t.Fatalf("fixture changed declaration bytes: %+v", delta)
			}
			if delta.Inert() {
				t.Fatalf("behavior changed under unchanged core and declarations, but delta is inert: %+v", delta)
			}
		})
	}
}

func TestTestVariantBindingGuardAllowsUnrelatedGrowth(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the engine over a fixture")
	}
	const beforeSource = "package p\nimport (\"testing\"; _ \"fmt\")\nfunc TestValue(t *testing.T) {}\n"
	dir := writeTestVariantModule(t, map[string]string{
		"go.mod":    "module example.com/binding\n\ngo 1.26\n",
		"p.go":      "package p\nfunc Value() int { return 1 }\n",
		"p_test.go": beforeSource,
	})
	subject := Subject{Package: "example.com/binding", Symbol: "TestValue"}
	core := computeAt(t, dir, subject)[subject].Hash
	before := ledgerAt(t, dir, subject.Package)
	afterSource := strings.Replace(beforeSource, `_ "fmt"`, `"fmt"`, 1) + "\n// harmless header comment\nfunc Helper() string { return fmt.Sprint(Extra) }\nconst Extra = 2\ntype Other struct{}\nfunc TestSibling(t *testing.T) { if Helper() != \"2\" { t.Fatal(Helper()) } }\n"
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("// harmless base comment\npackage p\nfunc Value() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p_test.go"), []byte(afterSource), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (gotool.Runner{}).Run(context.Background(), dir, os.Environ(), "test", "-count=1", "."); err != nil {
		t.Fatal(err)
	}
	if computeAt(t, dir, subject)[subject].Hash != core {
		t.Fatal("unrelated growth changed dependency core")
	}
	if delta := testvariant.DiffTestVariantLedgers(before, ledgerAt(t, dir, subject.Package)); !delta.Inert() {
		t.Fatalf("unrelated declarations and new-code import refused: %+v", delta)
	}
}

// The package listing reads the runner's List: a go whose listing
// exits cleanly while a descendant holds the pipe past the wait delay
// is refused as a LISTING (gotool.ErrListingRefused, never the served
// salvage's form) — the bare Run route would have refused too, by
// discarding the salvaged output on any error, but with exec's
// wait-delay error, which the salvage guard reads as served — while
// the same shim's environment document, whole by its own test, still
// serves the reader (REQ-fresh-go-command-policy).
func TestListingRefusesTheSalvagedAnswer(t *testing.T) {
	if testing.Short() {
		t.Skip("toolchain integration test")
	}
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	shim := t.TempDir()
	// Every go command answers through the real go and then forks a
	// holder of the pipe: the structured readers salvage their whole
	// documents, the listing refuses.
	script := "#!/bin/sh\n\"" + goBinary + "\" \"$@\"\nstatus=$?\nsleep 2 &\nexit $status\n"
	if err := os.WriteFile(filepath.Join(shim, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := listingMemoModule(t)
	runner := gotool.Runner{Prepare: func(c *exec.Cmd) { c.WaitDelay = 300 * time.Millisecond }}
	h, err := NewAt(context.Background(), gotool.NewEnvReader(runner, dir, os.Environ()))
	if err != nil {
		t.Fatalf("the reader's whole document did not serve: %v", err)
	}
	_, err = h.list(listingMemoPkg)
	if !errors.Is(err, gotool.ErrListingRefused) {
		t.Fatalf("the held listing was not refused as a listing: %v", err)
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("the refused listing reads as a served salvage: %v", err)
	}
}

func isolatedToolchainSource(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "go")
	cmd := exec.CommandContext(t.Context(), "cp", "-a", "--reflink=auto", runtime.GOROOT(), root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("copy: %s %v", out, err)
	}
	t.Setenv("GOROOT", root)
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	return root
}

func TestToolchainListingTracksFIPSAliasSelection(t *testing.T) {
	if testing.Short() {
		t.Skip("clones and retargets a supported FIPS source selection")
	}
	for _, linked := range []bool{false, true} {
		t.Run(map[bool]string{false: "directory", true: "symlink-root"}[linked], func(t *testing.T) {
			testFIPSAliasSelection(t, linked)
		})
	}
}

func testFIPSAliasSelection(t *testing.T, linked bool) {
	t.Helper()
	root := isolatedToolchainSource(t)
	if linked {
		path := filepath.Join(root, "lib", "fips140")
		outside := filepath.Join(t.TempDir(), "fips140")
		if err := os.Rename(path, outside); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOFIPS140", "inprocess")
	cache := t.TempDir()
	t.Setenv("GOMODCACHE", cache)
	t.Cleanup(func() {
		// Go normally makes extracted module directories read-only. They are
		// this fixture's private cache, so restore traversal/removal permissions.
		_ = filepath.WalkDir(cache, func(path string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				return os.Chmod(path, 0o700)
			}
			return err
		})
	})
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/fipsdep\n\ngo 1.27\n"})
	env := listingEnv("-modcacherw", "off")
	snapshot := snapshotFor(t, dir, env)
	read := func() sourceDigests {
		t.Helper()
		d, err := toolchainSourceDigests(t.Context(), gotool.Runner{}, dir, env, snapshot, nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	before := read()
	if again := read(); again.Content != before.Content {
		t.Fatal("unchanged FIPS selection moved")
	}
	alias := filepath.Join(root, "lib", "fips140", "inprocess.txt")
	if err := os.WriteFile(alias, []byte("v1.0.0-c2097c7c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	warm := read()
	path, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil && !(linked && os.IsNotExist(err)) {
		t.Fatal(err)
	}
	cold := read()
	if before.Content == cold.Content || warm.Content != cold.Content {
		t.Fatalf("FIPS retarget: before=%s warm=%s cold=%s", before.Content, warm.Content, cold.Content)
	}
}

func TestSubjectListingRefusesUninventoriedStandardPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs an explicitly importable symlinked standard package")
	}
	root := isolatedToolchainSource(t)
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"p.go": "package exclusive\nfunc Value() int { return 7 }\n"})
	if err := os.Symlink(outside, filepath.Join(root, "src", "exclusive")); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"go.mod": "module example.com/symlinkstd\n\ngo 1.27\n", "p.go": "package p\nimport \"exclusive\"\nfunc F() int { return exclusive.Value() }\n"})
	env := listingEnv("", "off")
	h, err := newAtEnv(t.Context(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := h.source.inventory["exclusive"]; found {
		t.Fatal("wildcard unexpectedly inventoried the symlink package")
	}
	if _, err := h.list("example.com/symlinkstd"); err == nil || !strings.Contains(err.Error(), "standard package exclusive is not covered") {
		t.Fatalf("missing source coverage: %v", err)
	}
	// A normal in-module target remains analyzable under the same inventory.
	writeTree(t, dir, map[string]string{"p.go": "package p\nfunc F() int { return 7 }\n"})
	h, err = newAtEnv(t.Context(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.list("example.com/symlinkstd"); err != nil {
		t.Fatal(err)
	}
}

func TestToolchainAdmissionNeedsEveryAuditedRoot(t *testing.T) {
	if testing.Short() {
		t.Skip("omits a required root from wildcard discovery")
	}
	root := isolatedToolchainSource(t)
	outside := filepath.Join(t.TempDir(), "ring")
	path := filepath.Join(root, "src", "container", "ring")
	if err := os.Rename(path, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	h, err := newAtEnv(t.Context(), t.TempDir(), listingEnv("", "off"))
	if err != nil {
		t.Fatal(err)
	}
	if _, found := h.source.inventory["container/ring"]; found {
		t.Fatal("fixture root was still reached by dependency enumeration")
	}
	if h.SelectionAudited() || h.ToolchainContent() != "" || !strings.Contains(h.SelectionNotice(), "required audited standard package container/ring") {
		t.Fatalf("missing audit root admitted: %s", h.SelectionNotice())
	}
}

func TestToolchainListingDoesNotCacheSymlinkSelectionInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("changes followed source and embed selection inputs")
	}
	for _, directoryLink := range []bool{false, true} {
		t.Run(map[bool]string{false: "excluded-file", true: "embedded-directory"}[directoryLink], func(t *testing.T) {
			root := isolatedToolchainSource(t)
			outside := t.TempDir()
			if directoryLink {
				writeTree(t, outside, map[string]string{
					"p.go":           "package stdembed\nimport \"embed\"\n//go:embed assets\nvar Files embed.FS\n",
					"assets/one.txt": "one", "assets/deep/empty/": "",
				})
				if err := os.Symlink(outside, filepath.Join(root, "src", "stdembed")); err != nil {
					t.Fatal(err)
				}
				writeTree(t, root, map[string]string{"src/anchor/p.go": "package anchor\nimport _ \"stdembed\"\n"})
			} else {
				writeTree(t, outside, map[string]string{"extra.go": "//go:build never\n\npackage strings\n"})
				if err := os.Symlink(filepath.Join(outside, "extra.go"), filepath.Join(root, "src", "strings", "extra.go")); err != nil {
					t.Fatal(err)
				}
			}
			dir := t.TempDir()
			writeTree(t, dir, map[string]string{"go.mod": "module example.com/linkselection\n\ngo 1.27\n", "main.go": "package main\nimport (\"fmt\"; \"strings\")\nfunc main() { fmt.Print(strings.Compare(\"a\", \"a\")) }\n"})
			env := listingEnv("", "off")
			snapshot := snapshotFor(t, dir, env)
			listings := 0
			runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
				if cmd.Args[1] == "list" {
					listings++
				}
			}}
			read := func() sourceDigests {
				t.Helper()
				d, err := toolchainSourceDigests(t.Context(), runner, dir, env, snapshot, nil)
				if err != nil {
					t.Fatal(err)
				}
				return d
			}
			before := read()
			if again := read(); again.Content != before.Content {
				t.Fatal("unchanged symlink-bearing selection moved")
			}
			priorListings := listings
			if directoryLink {
				if _, present := before.inventory["stdembed"]; !present {
					t.Fatal("selected symlink package was absent")
				}
				writeTree(t, outside, map[string]string{"assets/deep/empty/new.txt": "new"})
			} else {
				writeTree(t, outside, map[string]string{"extra.go": "package strings\nfunc init() { panic(\"new selected initializer\") }\n"})
				cmd := exec.CommandContext(t.Context(), "go", "run", ".")
				cmd.Dir, cmd.Env = dir, env
				if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "new selected initializer") {
					t.Fatalf("fresh program missed selected initializer: %s %v", out, err)
				}
			}
			after := read()
			if after.Content == before.Content || listings != priorListings+1 {
				t.Fatal("changed symlink target did not move selection")
			}
			if priorListings != 2 {
				t.Fatal("symlink-bearing discovery served an unsupported memo")
			}
			path, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("unsupported discovery persisted: %v", err)
			}
		})
	}
}

func TestAuditedExperimentRejectsUnverifiedSourceChanges(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	isolateProofCache(t)
	ctx := context.Background()
	dir := t.TempDir()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	d, err := toolchainSourceDigests(ctx, gotool.Runner{}, dir, env, snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	if deg := toolchainSourceDegradation("rebuilt-toolchain", d, nil); !deg.audited() {
		t.Fatalf("verified content rejected under a different label: %s", deg.notice())
	}
	for _, key := range []string{"internal/goexperiment", "runtime", "strings"} {
		changed := d
		changed.Packages = maps.Clone(d.Packages)
		changed.Packages[key] = "unverified-source-change"
		deg := toolchainSourceDegradation("rebuilt-toolchain", changed, nil)
		if deg.audited() || !strings.Contains(deg.notice(), key) {
			t.Fatalf("changed %s admitted or not named: %s", key, deg.notice())
		}
	}
}

// A bracket's live snapshot is its own pass: taken fresh over the
// construction reader's runner, directory, and environment, so the
// memo scopes by the environment the bracket's loads run in, while the
// classification keeps the construction snapshot's module cache. A
// module cache moved between construction and the bracket shows in the
// live snapshot and not in the classification.
func TestBracketLiveSnapshotIsItsOwnPass(t *testing.T) {
	if testing.Short() {
		t.Skip("toolchain integration test")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	construction, err := (gotool.Runner{}).TakeEnvSnapshot(ctx, dir, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	moved := gotool.SetEnv(os.Environ(), "GOMODCACHE", filepath.Join(t.TempDir(), "modcache"))
	h, err := NewBracketAt(ctx, gotool.PrimedEnvReader(gotool.Runner{}, dir, moved, construction))
	if err != nil {
		t.Fatal(err)
	}
	live := h.snapshot.Value("GOMODCACHE")
	if live == construction.Value("GOMODCACHE") {
		t.Fatalf("the bracket's snapshot is the construction's (%q): no fresh pass was taken", live)
	}
	if want, _ := gotool.LookupEnv(moved, "GOMODCACHE"); live != want {
		t.Fatalf("live GOMODCACHE = %q, want the moved %q", live, want)
	}
	if h.modCache != filepath.Clean(construction.Value("GOMODCACHE")) {
		t.Fatalf("classification module cache = %q, want the construction snapshot's %q", h.modCache, construction.Value("GOMODCACHE"))
	}
}

func TestFixturePreparationLifetimeAndFailureIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("toolchain integration test")
	}
	dir := t.TempDir()
	writeFile(t, dir, "go.mod", "module example.com/fixtureowner\n\ngo 1.27\n")
	for name, source := range map[string]string{"a": "func A() {}", "b": "func B() {}", "bad": "var Broken int = \"wrong\""} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, filepath.Join(name, "p.go"), "package fixture\n"+source+"\n")
	}
	const a, b, bad = "example.com/fixtureowner/a", "example.com/fixtureowner/b", "example.com/fixtureowner/bad"
	newOwner := func(t *testing.T) *fixturePrograms {
		t.Helper()
		h, err := NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()))
		if err != nil {
			t.Fatal(err)
		}
		return newFixturePrograms(t, h, a, b, bad)
	}
	t.Run("lazy and bounded", func(t *testing.T) {
		owner := newOwner(t)
		if owner.prepared != nil || owner.attempted || owner.typedLoads != 0 {
			t.Fatal("constructor prepared filtered-out cases")
		}
		owner.supply(t, a)
		first := owner.loaded
		prep := owner.prepared
		first.PkgScopeProbe = map[bool]error{true: errors.New("old analysis")}
		owner.supply(t, a)
		if first.PkgScopeProbe != nil {
			t.Fatal("case inherited the package-scope probe")
		}
		owner.supply(t, b)
		if owner.h.progs[a] != nil || len(owner.h.progs) != 1 || owner.prepared != prep {
			t.Fatal("replacement retained prior SSA or dropped preparation")
		}
		owner.supply(t, a)
		if owner.loaded == first || owner.loaded.Prog == first.Prog {
			t.Fatal("A-B-A reused prior SSA")
		}
		owner.checkPreparationCounts(t, 3)
		owner.release()
		if owner.loaded != nil || owner.prepared != nil || owner.roster != nil || len(owner.h.progs) != 0 {
			t.Fatal("cleanup retained fixture references")
		}
	})
	t.Run("per-root failure", func(t *testing.T) {
		owner := newOwner(t)
		owner.supply(t, a)
		if err := owner.acquire(bad); err == nil {
			t.Fatal("bad fixture accepted")
		}
		if owner.loaded != nil || len(owner.h.progs) != 0 {
			t.Fatal("failed replacement left stale program key")
		}
		owner.supply(t, b)
		if owner.typedLoads != 1 || owner.prepareErr != nil {
			t.Fatal("per-root failure triggered independent fallback")
		}
		if err := owner.acquire("example.com/fixtureowner/unregistered"); err == nil || owner.loaded != nil {
			t.Fatal("unregistered fixture accepted or retained previous SSA")
		}
	})
	t.Run("global operational fallback", func(t *testing.T) {
		owner := newOwner(t)
		owner.prepare = func(context.Context, string, []string, []string, ...string) (*progpkg.Prepared, error) {
			return nil, errors.New("loader-wide operational failure")
		}
		if err := owner.acquire(bad); err == nil {
			t.Fatal("bad independent fixture accepted")
		}
		owner.supply(t, a)
		owner.supply(t, b)
		if owner.typedLoads != 4 || owner.ssaBuilds != 3 || owner.prepared != nil {
			t.Fatalf("fallback attempts: %+v", owner)
		}
	})
	t.Run("cancelled preparation never falls back", func(t *testing.T) {
		owner := newOwner(t)
		owner.prepare = func(context.Context, string, []string, []string, ...string) (*progpkg.Prepared, error) {
			return nil, context.Canceled
		}
		for _, path := range []string{a, b} {
			if err := owner.acquire(path); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation: %v", err)
			}
		}
		if owner.typedLoads != 1 || owner.ssaBuilds != 0 || owner.loaded != nil {
			t.Fatal("cancelled preparation attempted fallback")
		}
	})
	t.Run("cancelled owner drops cached SSA", func(t *testing.T) {
		owner := newOwner(t)
		owner.supply(t, a)
		ctx, cancel := context.WithCancel(owner.h.ctx)
		cancel()
		owner.h.ctx = ctx
		if err := owner.acquire(a); !errors.Is(err, context.Canceled) || owner.loaded != nil || len(owner.h.progs) != 0 {
			t.Fatalf("cancelled cached supply: %v", err)
		}
	})
}
