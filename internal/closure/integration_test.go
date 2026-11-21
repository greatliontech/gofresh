package closure

import (
	"bytes"
	"context"

	"errors"
	"fmt"

	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/toolchain"
	"os"
	"os/exec"

	"path/filepath"
	"reflect"
	"runtime"
	"runtime/pprof"
	"slices"

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
	_, _, notice, err := toolchain.ResolveToolchainSelection(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, env), nil)
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
	_, _, notice, err = toolchain.ResolveToolchainSelection(context.Background(), gotool.PrimedEnvReader(gotool.Runner{}, dir, env, snapshot), nil)
	if err != nil || !strings.Contains(notice, "-tags (from $GOFLAGS)") {
		t.Fatalf("snapshot-resolved notice lost the GOFLAGS selection: %v %q", err, notice)
	}
	_, _, clean, err := toolchain.ResolveToolchainSelection(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, environmentWith("GOENV=off", "GOFLAGS=", "GOEXPERIMENT=")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := newAtEnv(context.Background(), dir, environmentWith("GOENV=off", "GOFLAGS=", "GOEXPERIMENT=")); err != nil {
		t.Fatal(err)
	} else if (clean == "") != h.SelectionAudited() || clean != h.SelectionNotice() {
		t.Fatalf("the resolved notice %q disagrees with the constructed verdict (audited=%v, notice %q)", clean, h.SelectionAudited(), h.SelectionNotice())
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
	h := &Hasher{snapshot: &gotool.EnvSnapshot{}, dir: "/x", selection: toolchain.SelectionForTest(true, "", "", "content", "policy", nil, nil)}
	if !strings.Contains(h.listingScope(), "|"+listingShape+"|") {
		t.Fatalf("scope %q does not carry the shape", h.listingScope())
	}

	// Quoted GOFLAGS containing "-modfile=..." as a substring of another flag's
	// value must not disable listingScope, whereas a quoted "-modfile=..." flag
	// or malformed quote in GOFLAGS must disable it.
	dir := t.TempDir()
	snapNonModfile := snapshotFor(t, dir, gotool.SetEnv(os.Environ(), "GOFLAGS", `"-ldflags=-X main.v=-modfile=alt.mod"`))
	hNonModfile := &Hasher{snapshot: snapNonModfile, dir: "/x", selection: toolchain.SelectionForTest(true, "", "", "content", "policy", nil, nil)}
	if hNonModfile.listingScope() == "" {
		t.Fatal("listingScope disabled by non-modfile quoted GOFLAGS")
	}
	snapQuotedModfile := snapshotFor(t, dir, gotool.SetEnv(os.Environ(), "GOFLAGS", `"-modfile=/tmp/with space/go.mod"`))
	hQuotedModfile := &Hasher{snapshot: snapQuotedModfile, dir: "/x", selection: toolchain.SelectionForTest(true, "", "", "content", "policy", nil, nil)}
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
	hMalformed := &Hasher{snapshot: snapMalformed, dir: "/x", selection: toolchain.SelectionForTest(true, "", "", "content", "policy", nil, nil)}
	if got := hMalformed.listingScope(); got != "" {
		t.Fatalf("listingScope under malformed GOFLAGS = %q, want empty", got)
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
	if _, _, found := h.Selection().StandardPackageMeta("exclusive"); found {
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
	if _, _, found := h.Selection().StandardPackageMeta("container/ring"); found {
		t.Fatal("fixture root was still reached by dependency enumeration")
	}
	if h.SelectionAudited() || h.ToolchainContent() != "" || !strings.Contains(h.SelectionNotice(), "required audited standard package container/ring") {
		t.Fatalf("missing audit root admitted: %s", h.SelectionNotice())
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

func TestListingMemoServesNestedWorkspaceModulesAndTransitiveReplaces(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns the go command over nested workspace and transitive replace fixtures")
	}
	isolateProofCache(t)
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"go.work":          "go 1.26\n\nuse (\n\t.\n\t./sub\n\t./sub/leaf\n)\n\nreplace example.com/wrep1 => ./wrep1\n",
		"go.mod":           "module example.com/wsroot\n\ngo 1.26\n\nrequire example.com/rep1 v0.0.0\n\nreplace example.com/rep1 => ./rep1\n",
		"root.go":          "package wsroot\n\nfunc Root() int { return 1 }\n",
		"sub/go.mod":       "module example.com/wsroot/sub\n\ngo 1.26\n",
		"sub/sub.go":       "package sub\n\nfunc Sub() int { return 2 }\n",
		"sub/leaf/go.mod":  "module example.com/wsroot/sub/leaf\n\ngo 1.26\n",
		"sub/leaf/leaf.go": "package leaf\n\nfunc Leaf() int { return 3 }\n",
		"rep1/go.mod":      "module example.com/rep1\n\ngo 1.26\n\nrequire example.com/rep2 v0.0.0\n\nreplace example.com/rep2 => ../rep2\n",
		"rep1/r1.go":       "package rep1\n\nfunc R1() int { return 4 }\n",
		"rep2/go.mod":      "module example.com/rep2\n\ngo 1.26\n",
		"rep2/r2.go":       "package rep2\n\nfunc R2() int { return 5 }\n",
		"wrep1/go.mod":     "module example.com/wrep1\n\ngo 1.26\n\nrequire example.com/wrep2 v0.0.0\n\nreplace example.com/wrep2 => ../wrep2\n",
		"wrep1/w1.go":      "package wrep1\n\nfunc W1() int { return 6 }\n",
		"wrep2/go.mod":     "module example.com/wrep2\n\ngo 1.26\n",
		"wrep2/w2.go":      "package wrep2\n\nfunc W2() int { return 7 }\n",
	})
	leafDir := filepath.Join(root, "sub", "leaf")
	env := listingEnv("", "")
	snapshot := snapshotFor(t, leafDir, env)
	if got := snapshot.Value("GOWORK"); got != filepath.Join(root, "go.work") {
		t.Fatalf("GOWORK = %q, want %q", got, filepath.Join(root, "go.work"))
	}

	// Cold pass from nested submodule leafDir listing ancestor module example.com/wsroot.
	_, spawns, h, err := listFrom(t, leafDir, "example.com/wsroot", env, snapshot)
	if err != nil || spawns != 1 {
		t.Fatalf("cold nested workspace list: spawns=%d err=%v", spawns, err)
	}
	// Warm pass must hit the listing memo (spawns == 0) because intermediate sub/go.mod
	// and sub/leaf/go.mod are recorded in rec.Files rather than rec.Absent.
	_, spawns, _, err = listFrom(t, leafDir, "example.com/wsroot", env, snapshot)
	if err != nil || spawns != 0 {
		t.Fatalf("warm nested workspace list missed memo: spawns=%d err=%v", spawns, err)
	}

	var stored listingRecord
	if !cachefile.Load(listingDirName, h.listingScope(), "example.com/wsroot", &stored) {
		t.Fatal("expected persisted listingRecord")
	}
	for _, rel := range []string{"sub/go.mod", "sub/leaf/go.mod", "rep2/go.mod", "wrep2/go.mod"} {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if stored.Files[full] == "" || slices.Contains(stored.Absent, full) {
			t.Fatalf("%s missing from Files or present in Absent: files=%v absent=%v", rel, stored.Files, stored.Absent)
		}
	}

	// Edits to nested submodule go.mod and transitive local replace targets must invalidate the memo.
	for _, rel := range []string{"sub/go.mod", "sub/leaf/go.mod", "rep2/go.mod", "wrep2/go.mod"} {
		full := filepath.Join(root, filepath.FromSlash(rel))
		orig, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, append(slices.Clone(orig), []byte("\n// edited\n")...), 0o644); err != nil {
			t.Fatal(err)
		}
		_, spawns, _, err = listFrom(t, leafDir, "example.com/wsroot", env, snapshot)
		if restoreErr := os.WriteFile(full, orig, 0o644); restoreErr != nil {
			t.Fatal(restoreErr)
		}
		if err != nil || spawns != 1 {
			t.Fatalf("edit to %s did not invalidate listing memo: spawns=%d err=%v", rel, spawns, err)
		}
		if _, spawns, _, err = listFrom(t, leafDir, "example.com/wsroot", env, snapshot); err != nil || spawns != 1 {
			t.Fatalf("re-prime after restoring %s: spawns=%d err=%v", rel, spawns, err)
		}
	}
}
