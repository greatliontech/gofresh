package closure

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/closure/internal/compartment"
	"github.com/greatliontech/gofresh/internal/closure/internal/listing"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestNewAtRejectsExternalPackageDriver(t *testing.T) {
	env := environmentWith("GOPACKAGESDRIVER=custom")
	if _, err := newAtEnv(context.Background(), t.TempDir(), env); err == nil || !strings.Contains(err.Error(), "GOPACKAGESDRIVER") {
		t.Fatalf("external package driver accepted: %v", err)
	}
}

func TestSyntheticTestPackageCannotReplaceAnImportBinding(t *testing.T) {
	const pkg = "example.com/bindings"
	dir := writeTestVariantModule(t, map[string]string{
		"p.go":        "package p\n",
		"ext_test.go": "package p_test\nimport \"example.com/bindings_test\"\nfunc Example() { declared.Value() }\n",
	})
	module := &listMod{Path: pkg, Main: true, Dir: dir}
	real := listPkg{ImportPath: pkg + "_test", Name: "declared", Dir: filepath.Join(dir, "dependency")}
	synthetic := listPkg{ImportPath: pkg + "_test [" + pkg + ".test]", ForTest: pkg, Name: "p_test", Dir: dir, Module: module, GoFiles: []string{"ext_test.go"}}
	for _, copies := range [][]listPkg{{real, synthetic, real}, {synthetic, real, synthetic}} {
		h := &Hasher{lists: map[string][]listPkg{pkg: append([]listPkg{
			{ImportPath: pkg, Name: "p", Dir: dir, Module: module, GoFiles: []string{"p.go"}},
		}, copies...)}, testVariants: map[string]compartment.Identity{}}
		ledger, err := h.TestVariantLedger(pkg)
		if err != nil {
			t.Fatal(err)
		}
		if len(ledger.FileHeaders) != 1 || len(ledger.FileHeaders[0].Bindings.Imports) != 1 {
			t.Fatalf("missing external-test binding evidence: %+v", ledger)
		}
		if got := ledger.FileHeaders[0].Bindings.Imports[0]; got.Path != pkg+"_test" || got.Name != "" {
			t.Fatalf("conflicting declaration was resolved by listing order: %+v", got)
		}
		if testvariant.DiffTestVariantLedgers(ledger, ledger).Inert() {
			t.Fatal("conflicting import-name evidence authorized inertness")
		}
	}
}

func TestToolchainListingTracksPreviouslyEmptyEmbedDirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	isolateProofCache(t)
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"src/strings/p.go":                  "package strings\nimport \"embed\"\n//go:embed testdata\nvar files embed.FS\n",
		"src/strings/testdata/one.txt":      "one",
		"src/strings/testdata/deep/empty/":  "",
		"src/unused/testdata/deep/data.txt": "unselected",
		"src/cmd/tool/p.go":                 "package main\n",
	})
	envFile, listingFile := filepath.Join(root, "env.json"), filepath.Join(root, "listing.json")
	writeJSON := func(path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(envFile, map[string]string{"GOROOT": root, "GOVERSION": "go1.27.2"})
	pkg := listPkg{ImportPath: "strings", Standard: true, Dir: filepath.Join(root, "src", "strings"), GoFiles: []string{"p.go"}, EmbedFiles: []string{"testdata/one.txt"}, EmbedPatterns: []string{"testdata"}}
	writeJSON(listingFile, pkg)
	listings := 0
	runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		file := envFile
		if cmd.Args[1] == "list" {
			listings++
			file = listingFile
		}
		cmd.Path = "/bin/sh"
		cmd.Args = []string{"sh", "-c", "cat \"$1\"", "fixture", file}
	}}
	snapshot, err := runner.TakeEnvSnapshot(t.Context(), root, os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	read := func() sourceDigests {
		t.Helper()
		d, err := toolchainSourceDigests(t.Context(), runner, root, os.Environ(), snapshot, nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	before := read()
	warm := read()
	if !reflect.DeepEqual(before, warm) {
		t.Fatal("unchanged selection moved")
	}
	if stampsTrusted && listings != 1 {
		t.Fatal("unchanged inventory failed to serve")
	}
	// These bytes are neither package discovery nor a selected embed input.
	writeTree(t, root, map[string]string{"src/unused/testdata/deep/data.txt": "changed", "src/cmd/tool/p.go": "package main\n// changed\n"})
	if again := read(); again.Content != before.Content || stampsTrusted && listings != 1 {
		t.Fatal("irrelevant test/tool bytes moved the selection memo")
	}
	writeTree(t, root, map[string]string{"src/strings/testdata/deep/empty/new.txt": "new"})
	pkg.EmbedFiles = append(pkg.EmbedFiles, "testdata/deep/empty/new.txt")
	writeJSON(listingFile, pkg)
	count := listings
	after := read()
	if listings != count+1 || after.Content == before.Content || after.Packages["strings"] == before.Packages["strings"] {
		t.Fatal("previously empty embed branch stayed invisible")
	}
}

func TestListingEntriesTrackSymlinkTargetKinds(t *testing.T) {
	dir, target := t.TempDir(), filepath.Join(t.TempDir(), "target")
	if err := os.Symlink(target, filepath.Join(dir, "input.go")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	read := func() listingEntry {
		t.Helper()
		entries, err := listingEntries(dir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("entries: %+v %v", entries, err)
		}
		return entries[0]
	}
	missing := read()
	if !missing.Dangling || missing.regular() {
		t.Fatalf("dangling: %+v", missing)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := read()
	if directory == missing || directory.Dangling || directory.regular() || directory.TargetType != os.ModeDir {
		t.Fatalf("directory: %+v", directory)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("package p\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	regular := read()
	if regular == directory || regular == missing || !regular.regular() {
		t.Fatalf("regular: %+v", regular)
	}
	if again := read(); again != regular {
		t.Fatal("unchanged entry moved")
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
		verifiedPackageMemo.Store(memoKey, verifiedPackageVerdict{OK: true})
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
	isolateProofCache(t)
	listed := newInMemoryHasher(t)
	if !listed.SelectionAudited() {
		t.Skipf("running toolchain unlisted (the canary covers it): %s", listed.SelectionNotice())
	}
	subject := Subject{Package: "github.com/greatliontech/gofresh/internal/closure/testdata/observable", Symbol: "TestReadFile"}
	supplyRegisteredFixtures(t, listed, subject.Package)
	listedObs, err := listed.ComputeObservabilityBatch([]Subject{subject})
	if err != nil {
		t.Fatal(err)
	}
	if o := listedObs[subject]; !o.Observable {
		t.Fatalf("fixture assumption moved: TestReadFile not observable under the listed toolchain: %+v", o)
	}
	memoKey := verifiedPackageMemoKey("strings", listed.source.Packages["strings"])
	verifiedPackageMemo.Store(memoKey, verifiedPackageVerdict{OK: false})
	t.Cleanup(func() { verifiedPackageMemo.Delete(memoKey) })
	unlisted := newInMemoryHasher(t)
	supplyRegisteredFixtures(t, unlisted, subject.Package)
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

// TestPackageFileWalkEndsAtTheNextEntry pins the package-file walk's
// check point (REQ-closure-observability-toolchain-key: the walk checks
// the package's cancellation check at every entry): over a planted tree
// a context cancelled at the walk's second entry ends it at the third —
// the entries seen are exactly the two before the cancellation's check
// fired — answering the cancellation with nothing listed; a context
// cancelled before the walk ends it at the root entry; the live walk
// lists the three files.
func TestPackageFileWalkEndsAtTheNextEntry(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go", "c.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("package p\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := &Hasher{ctx: ctx}
	const stopAt = 2
	seen := 0
	prior := walkEntryForTest
	walkEntryForTest = func(path string) {
		seen++
		if seen == stopAt {
			cancel()
		}
	}
	t.Cleanup(func() { walkEntryForTest = prior })
	files, err := allPackageFiles(h.contextErr, dir)
	if !errors.Is(err, context.Canceled) || len(files) != 0 {
		t.Fatalf("a walk cancelled at entry %d answered %v with %d files, want the cancellation and nothing listed", stopAt, err, len(files))
	}
	if seen != stopAt {
		t.Fatalf("the walk visited %d entries with the cancellation at entry %d, want exactly that many: the next entry's check ends it", seen, stopAt)
	}
	walkEntryForTest = prior
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if files, err := allPackageFiles((&Hasher{ctx: cancelled}).contextErr, dir); !errors.Is(err, context.Canceled) || len(files) != 0 {
		t.Fatalf("a pre-cancelled walk answered %v with %d files, want the cancellation at the root entry", err, len(files))
	}
	live, err := allPackageFiles((&Hasher{ctx: context.Background()}).contextErr, dir)
	if err != nil || len(live) != 3 {
		t.Fatalf("the live walk answered %v with %d files, want the three", err, len(live))
	}
}

func TestHarnessPremisePackagesAreSurfaceSeedsAndVerified(t *testing.T) {
	for _, p := range []string{"internal/testlog", "testing", "testing/internal/testdeps"} {
		if !slices.Contains(auditedSurfaceTables(), p) || !slices.Contains(harnessPremisePackages, p) {
			t.Errorf("the harness premise package %s is not a surface seed", p)
		}
	}
	for _, version := range []string{"go1.27.1-dst.13", "go1.27.2-dst.15", "go1.28.0-dst.99"} {
		d := sourceDigests{Packages: map[string]string{"testing": "unlisted-content"}}
		if toolchainSourceDegradation(version, d, nil).audited() {
			t.Fatalf("version %q admitted unverified harness content", version)
		}
	}
}

// TestListingScopeFollowsTheSurfaceRule pins the listing memo's scope
// against the surface rule (REQ-closure-observability-toolchain-key's
// listing memo): the scope carries the surface seeds' digest, so two
// seed lists — the rule before and after a seed joins — make two scopes
// and a warm record of the old surface is never served to the new
// rule; the same list makes the same scope.
func TestListingScopeFollowsTheSurfaceRule(t *testing.T) {
	snapshot, err := cachedHostSnapshotOnce()
	if err != nil {
		t.Fatal(err)
	}
	before := []string{"runtime", "sync/atomic", "testing"}
	after := []string{"runtime", "sync/atomic", "testing", "testing/internal/testdeps"}
	if a, b := toolchainSourceScope(snapshot, nil, before), toolchainSourceScope(snapshot, nil, after); a == b {
		t.Fatalf("a seed joining the surface kept the listing scope %q", a)
	}
	if a, b := toolchainSourceScope(snapshot, nil, after), toolchainSourceScope(snapshot, nil, slices.Clone(after)); a != b {
		t.Fatalf("the same seeds made two scopes: %q vs %q", a, b)
	}
	if a, b := toolchainSourceScope(snapshot, nil, surfaceSeeds()), toolchainSourceScope(snapshot, nil, before); a == b {
		t.Fatalf("the live seeds scope as a three-seed rule: %q", a)
	}
}

// The digest is a function of the files' names, order-independent
// content, and set: a renamed, reordered, re-split, or edited file
// moves it, an identical set read in any order does not, and an
// unreadable file is an error — never a reading short one file
// (REQ-closure-observability-toolchain-key).
func TestDigestFilesFollowsNamesAndBytes(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package p\n")
	write("b.go", "package p\n\nfunc B() {}\n")
	write("c.s", "TEXT ·x(SB),0,$0\n")
	base, err := digestFiles(context.Background(), dir, []string{"a.go", "b.go", "c.s"})
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := digestFiles(context.Background(), dir, []string{"a.go", "b.go", "c.s"}); again != base {
		t.Fatal("the digest is not a function of the files")
	}
	if reordered, _ := digestFiles(context.Background(), dir, []string{"c.s", "a.go", "b.go"}); reordered == base {
		t.Fatal("file order is part of the digest; the caller sorts, so a reordering must move it")
	}
	if fewer, _ := digestFiles(context.Background(), dir, []string{"a.go", "b.go"}); fewer == base {
		t.Fatal("dropping a file left the digest unchanged")
	}
	write("b.go", "package p\n\nfunc B() int { return 1 }\n")
	if edited, _ := digestFiles(context.Background(), dir, []string{"a.go", "b.go", "c.s"}); edited == base {
		t.Fatal("editing a file left the digest unchanged")
	}
	if _, err := digestFiles(context.Background(), dir, []string{"a.go", "missing.go"}); err == nil {
		t.Fatal("an unreadable file digested instead of refusing")
	}
	// The name is part of the content: a file renamed with the same
	// bytes moves the digest (the walk reads names).
	write("d.go", "package p\n")
	one, _ := digestFiles(context.Background(), dir, []string{"a.go"})
	other, _ := digestFiles(context.Background(), dir, []string{"d.go"})
	if one == other {
		t.Fatal("two files of identical bytes under different names digest alike")
	}
}

func TestDigestFilesFramesBinaryContentsUnambiguously(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"assets/a": "x\x00assets/b\x00y"})
	one, err := digestFiles(t.Context(), dir, []string{"assets/a"})
	if err != nil {
		t.Fatal(err)
	}
	writeTree(t, dir, map[string]string{"assets/a": "x", "assets/b": "y"})
	two, err := digestFiles(t.Context(), dir, []string{"assets/a", "assets/b"})
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("different file inventories have the same framing")
	}
}

// Every non-test file class the build selects joins the digest, sorted
// and deduplicated (test files are never listed in these classes).
func TestSelectedFilesCoversEveryBuildClass(t *testing.T) {
	p := listing.Package{
		GoFiles: []string{"z.go", "a.go"}, CgoFiles: []string{"c.go"}, CFiles: []string{"x.c"}, CXXFiles: []string{"y.cc"},
		MFiles: []string{"m.m"}, HFiles: []string{"h.h"}, FFiles: []string{"f.f"}, SFiles: []string{"s.s"},
		SwigFiles: []string{"w.swig"}, SwigCXXFiles: []string{"w.swigcxx"}, SysoFiles: []string{"o.syso"}, EmbedFiles: []string{"e.txt", "a.go"},
	}
	want := []string{"a.go", "c.go", "e.txt", "f.f", "h.h", "m.m", "o.syso", "s.s", "w.swig", "w.swigcxx", "x.c", "y.cc", "z.go"}
	if got := selectedFiles(p); !reflect.DeepEqual(got, want) {
		t.Fatalf("selectedFiles = %v, want %v", got, want)
	}
}

// The surface derives mechanically: every admission table's listed
// package (the linkname floor's runtime and syscall among them) and
// the link-time packages, plus every standard package they reach
// through the listing's dependencies and imports at any depth, the
// runtime included — never a non-standard import, never an unreached
// package — so a delegate's delegate, a dependency the pseudo-import C
// pulls, and the runtime a vendor fork hooks are keyed.
func TestAuditedSurfaceDerivesTheDelegates(t *testing.T) {
	tables := auditedSurfaceTables()
	for _, must := range []string{"strings", "fmt", "sync", "sync/atomic", "testing", "reflect", "time", "math/rand", "net/url", "path/filepath", "flag", "os", "syscall", "encoding/json", "runtime"} {
		if !contains(tables, must) {
			t.Errorf("the tables' surface lacks %s", must)
		}
	}
	for _, p := range auditset.PurePackages() {
		if !contains(tables, p) {
			t.Errorf("the tables' surface lacks the pure package %s", p)
		}
	}
	if !contains(tables, "golang.org/x/sys/unix") {
		t.Error("the class-B table names golang.org/x/sys/unix; the listing keeps it off the toolchain's surface")
	}
	std := []listing.Package{
		{ImportPath: "strings", Standard: true, Imports: []string{"internal/bytealg", "unsafe", "runtime", "internal/abi", "unicode/utf8", "example.com/notstd"}},
		{ImportPath: "internal/bytealg", Standard: true, Imports: []string{"internal/cpu", "internal/secondlevel"}},
		{ImportPath: "internal/secondlevel", Standard: true, Imports: []string{"internal/thirdlevel", "internal/runtime/atomic"}},
		{ImportPath: "internal/thirdlevel", Standard: true, Imports: []string{"strings"}},
		{ImportPath: "internal/unreached", Standard: true},
		{ImportPath: "unicode/utf8", Standard: true},
		{ImportPath: "runtime", Standard: true, Imports: []string{"internal/runtime/sys"}}, {ImportPath: "internal/runtime/sys", Standard: true},
		{ImportPath: "unsafe", Standard: true}, {ImportPath: "internal/abi", Standard: true}, {ImportPath: "internal/cpu", Standard: true},
		{ImportPath: "internal/runtime/atomic", Standard: true},
		// A cgo package imports "C", never runtime/cgo; the go command
		// records the bridge in Deps alone — the walk follows Deps;
		// the detectors' runtimes, in no Deps at all, seed the surface.
		{ImportPath: "net", Standard: true, Imports: []string{"C", "strings"}, Deps: []string{"runtime/cgo", "internal/viadeps", "strings"}},
		{ImportPath: "runtime/cgo", Standard: true}, {ImportPath: "internal/viadeps", Standard: true},
		{ImportPath: "runtime/race", Standard: true}, {ImportPath: "runtime/msan", Standard: true},
	}
	surface := auditedSurface(std)
	for _, in := range []string{"strings", "internal/bytealg", "internal/secondlevel", "internal/thirdlevel", "unicode/utf8", "runtime", "internal/runtime/sys", "unsafe", "internal/abi", "internal/cpu", "internal/runtime/atomic", "net", "runtime/cgo", "internal/viadeps", "runtime/race", "runtime/msan"} {
		if !contains(surface, in) {
			t.Errorf("%s is not in the surface: every reached standard package is", in)
		}
	}
	for _, out := range []string{"example.com/notstd", "internal/unreached", "golang.org/x/sys/unix", "C", "runtime/asan"} {
		if contains(surface, out) {
			t.Errorf("%s joined the surface: non-standard or unreached packages never do", out)
		}
	}
}

// A listing serves only over the directory contents it was taken over:
// an entry edited (its change time moved even with the modification
// time restored), added, removed, or renamed in any stamped directory
// — the package's and every subdirectory an embedded file lives in —
// or a directory gone unreadable, stales the record — so the memo
// never decides which bytes the build selects from a tree that moved.
func TestSurfaceListingServesOnlyOverItsStamps(t *testing.T) {
	if !stampsTrusted {
		t.Skip("this platform's stat carries no change time: the memo never serves")
	}
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package p\n")
	write("b.go", "//go:build never\n\npackage p\n")
	write("data/x.txt", "x\n")
	files := []string{"a.go", "data/x.txt"}
	stamp := func() []dirStamp {
		t.Helper()
		stamps, err := stampDirs(dir, files)
		if err != nil {
			t.Fatal(err)
		}
		return stamps
	}
	l := surfaceListing{Version: sourceDigestsVersion, Packages: []listedPackage{{ImportPath: "p", Dir: dir, Files: files}}, Discovery: stamp()}
	if !stampsCurrent(l) {
		t.Fatal("an unchanged directory reads as stale")
	}
	stamps := l.Discovery
	if len(stamps) != 2 || stamps[0].Path != dir || stamps[1].Path != filepath.Join(dir, "data") || len(stamps[0].Entries) != 3 || stamps[0].Entries[1].Name != "b.go" || stamps[0].Entries[1].Size != int64(len("//go:build never\n\npackage p\n")) {
		t.Fatalf("stamps = %+v", stamps)
	}
	// A constraint edit on an unselected file — the selection may now
	// differ — moves its stamp (size and times).
	before := stamps[0].Entries[1]
	write("b.go", "//go:build linux\n\npackage p\n")
	if stampsCurrent(l) {
		t.Fatal("an edited entry served the stale listing")
	}
	// The modification time restored: the change time still moved.
	if err := os.Chtimes(filepath.Join(dir, "b.go"), time.Unix(0, before.ModTime), time.Unix(0, before.ModTime)); err != nil {
		t.Fatal(err)
	}
	if now, _ := stampEntries(dir); now[1].ModTime != before.ModTime {
		t.Fatal("Chtimes did not restore the modification time")
	} else if now[1].ChangeTime == before.ChangeTime && now[1].Size == before.Size {
		t.Fatal("an edit with the modification time restored left the stamp unchanged")
	}
	write("b.go", "//go:build never\n\npackage p\n")
	l.Discovery = stamp()
	if !stampsCurrent(l) {
		t.Fatal("a re-stamped listing reads as stale")
	}
	write("c.go", "package p\n")
	if stampsCurrent(l) {
		t.Fatal("an added entry served the stale listing")
	}
	if err := os.Remove(filepath.Join(dir, "c.go")); err != nil {
		t.Fatal(err)
	}
	l.Discovery = stamp()
	write("data/y.txt", "y\n")
	if stampsCurrent(l) {
		t.Fatal("an entry added under an embedded file's directory served the stale listing")
	}
	if err := os.Remove(filepath.Join(dir, "data", "y.txt")); err != nil {
		t.Fatal(err)
	}
	l.Discovery = stamp()
	if err := os.Rename(filepath.Join(dir, "b.go"), filepath.Join(dir, "bb.go")); err != nil {
		t.Fatal(err)
	}
	if stampsCurrent(l) {
		t.Fatal("a renamed entry served the stale listing")
	}
	if err := os.Rename(filepath.Join(dir, "bb.go"), filepath.Join(dir, "b.go")); err != nil {
		t.Fatal(err)
	}
	l.Discovery = stamp()
	if err := os.Remove(filepath.Join(dir, "a.go")); err != nil {
		t.Fatal(err)
	}
	if stampsCurrent(l) {
		t.Fatal("a removed entry served the stale listing")
	}
	l.Discovery = append(l.Discovery, dirStamp{Path: filepath.Join(dir, "gone")})
	if stampsCurrent(l) {
		t.Fatal("an unreadable directory served the stale listing")
	}
}

// verifyToolchainSurface and verifyListedPackage enforce the structural AST and
// directive contracts over standard-library packages without hardcoded release
// digest tables.
func TestVerifyToolchainSurfaceEnforcesStructuralContracts(t *testing.T) {
	t.Parallel()
	writePkg := func(importPath string, files map[string]string) listedPackage {
		t.Helper()
		dir := t.TempDir()
		var names []string
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
		}
		slices.Sort(names)
		digest, err := digestFiles(context.Background(), dir, names)
		if err != nil {
			t.Fatal(err)
		}
		return listedPackage{
			ImportPath: importPath,
			Dir:        dir,
			Files:      names,
			Audited:    true,
			digest:     digest,
		}
	}

	validPure := writePkg("strings", map[string]string{
		"strings.go": "package strings\nimport _ \"unsafe\"\n// prose comment mentioning //go:linkname foo bar mid-line is ignored\n//go:linkname divideError runtime.divideError\nfunc Compare(a, b string) int { return 0 }\n",
	})
	if err := verifyListedPackage(validPure); err != nil {
		t.Fatalf("valid pure package refused: %v", err)
	}

	badImportPure := writePkg("strings", map[string]string{
		"strings.go": "package strings\nimport \"os\"\nvar _ = os.Args\n",
	})
	if err := verifyListedPackage(badImportPure); err == nil {
		t.Fatal("pure package importing os admitted")
	}

	digestLP := func(lp listedPackage) listedPackage {
		d, err := digestFiles(t.Context(), lp.Dir, lp.Files)
		if err != nil {
			t.Fatal(err)
		}
		lp.digest = d
		lp.Audited = true
		return lp
	}
	seedPreverifiedSurface := func(overrides ...listedPackage) sourceDigests {
		sd := sourceDigests{
			Packages:  map[string]string{},
			inventory: map[string]listedPackage{},
		}
		for _, root := range auditedSurfaceTables() {
			first, _, _ := strings.Cut(root, "/")
			if strings.Contains(first, ".") {
				continue
			}
			d := "seed-ok-" + root
			sd.Packages[root] = d
			sd.inventory[root] = listedPackage{ImportPath: root, Audited: true, digest: d}
			mk := verifiedPackageMemoKey(root, d)
			verifiedPackageMemo.Store(mk, verifiedPackageVerdict{OK: true})
			t.Cleanup(func() { verifiedPackageMemo.Delete(mk) })
		}
		for _, ov := range overrides {
			sd.inventory[ov.ImportPath] = ov
			if ov.Audited {
				sd.Packages[ov.ImportPath] = ov.digest
			}
		}
		return sd
	}

	stringsImpPoll := digestLP(writePkg("strings", map[string]string{
		"strings.go": "package strings\nimport \"internal/poll\"\nvar _ = poll.ErrNetClosing\n",
	}))
	if failed := verifyToolchainSurface(seedPreverifiedSurface(stringsImpPoll)); !slices.Contains(failed, "strings") {
		t.Fatalf("pure package importing uninventoried internal/poll: failed=%v, want strings", failed)
	}
	pollWithSyscall := digestLP(writePkg("internal/poll", map[string]string{
		"poll.go": "package poll\nimport \"syscall\"\nvar ErrNetClosing = syscall.EINVAL\n",
	}))
	if failed := verifyToolchainSurface(seedPreverifiedSurface(stringsImpPoll, pollWithSyscall)); !slices.Contains(failed, "internal/poll") {
		t.Fatalf("pure package importing syscall-backed internal/poll: failed=%v, want internal/poll", failed)
	}

	customLeafPure := digestLP(writePkg("internal/customleaf", map[string]string{
		"leaf.go":  "package customleaf\nfunc Add(a, b int) int { return a + b }\n",
		"leaf_s.s": "// SYSCALL in comment only\nTEXT ·AddAsm(SB),$0-24\n\tRET\n",
	}))
	customMidPure := digestLP(writePkg("internal/custommid", map[string]string{
		"mid.go": "package custommid\nimport \"internal/customleaf\"\nfunc Twice(x int) int { return customleaf.Add(x, x) }\n",
	}))
	stringsImpCustom := digestLP(writePkg("strings", map[string]string{
		"strings.go": "package strings\nimport \"internal/custommid\"\nfunc Double(x int) int { return custommid.Twice(x) }\n",
	}))
	_, pureDelSet, ioErr, ctxErr := verifyToolchainSurfaceAndDelegatesWithIO(t.Context(), seedPreverifiedSurface(stringsImpCustom, customMidPure, customLeafPure))
	if ioErr != nil || ctxErr != nil || !pureDelSet["internal/custommid"] || !pureDelSet["internal/customleaf"] {
		t.Fatalf("transitive pure delegates refused or incomplete: delegates=%v ioErr=%v ctxErr=%v", pureDelSet, ioErr, ctxErr)
	}

	customLeafRawSyscall := digestLP(writePkg("internal/customleaf", map[string]string{
		"leaf.go":  "package customleaf\nfunc Trap()\n",
		"leaf_s.s": "TEXT ·Trap(SB),$0-0\n\tSYSCALL\n\tRET\n",
	}))
	if failed := verifyToolchainSurface(seedPreverifiedSurface(stringsImpCustom, customMidPure, customLeafRawSyscall)); !slices.Contains(failed, "internal/customleaf") {
		t.Fatalf("transitive delegate with raw SYSCALL assembly admitted: failed=%v", failed)
	}

	customLeafInt80 := writePkg("internal/customleaf", map[string]string{
		"leaf.go":  "package customleaf\nfunc Trap386()\n",
		"leaf_s.s": "#define INVOKE INT $0x80\nTEXT ·Trap386(SB),$0-0\n\tINVOKE\n\tRET\n",
	})
	if err := verifyListedPurePackage(customLeafInt80); err == nil {
		t.Fatal("delegate assembly with INT $0x80 admitted")
	}

	badDelegateImport := writePkg("internal/bytealg", map[string]string{
		"bytealg.go": "package bytealg\nimport \"os\"\nvar _ = os.Getenv\n",
	})
	if err := verifyListedPurePackage(badDelegateImport); err == nil {
		t.Fatal("pure-delegate package importing os admitted")
	}

	validTimePure := writePkg("encoding/asn1", map[string]string{
		"asn1.go": "package asn1\nimport \"time\"\nvar _ = time.UTC\n",
	})
	if err := verifyListedPackage(validTimePure); err != nil {
		t.Fatalf("pure package using pure time selector refused: %v", err)
	}

	badTimeNowPure := writePkg("encoding/asn1", map[string]string{
		"asn1.go": "package asn1\nimport \"time\"\nvar _ = time.Now()\n",
	})
	if err := verifyListedPackage(badTimeNowPure); err == nil {
		t.Fatal("pure package calling time.Now() admitted")
	}

	badTimeAliasPure := writePkg("encoding/asn1", map[string]string{
		"asn1.go": "package asn1\nimport t \"time\"\nvar _ = t.Now()\n",
	})
	if err := verifyListedPackage(badTimeAliasPure); err == nil {
		t.Fatal("pure package aliasing time import admitted")
	}

	validMathBigRand := writePkg("math/big", map[string]string{
		"nat.go": "package big\nimport \"math/rand\"\ntype r = *rand.Rand\n",
	})
	if err := verifyListedPackage(validMathBigRand); err != nil {
		t.Fatalf("valid math/big rand.Rand reference refused: %v", err)
	}

	badMathBigRand := writePkg("math/big", map[string]string{
		"nat.go": "package big\nimport \"math/rand\"\nvar _ = rand.Int()\n",
	})
	if err := verifyListedPackage(badMathBigRand); err == nil {
		t.Fatal("math/big calling global rand.Int() admitted")
	}

	badRuntimePure := writePkg("strings", map[string]string{
		"strings.go": "package strings\nimport \"runtime\"\nvar _ = runtime.NumCPU()\n",
	})
	if err := verifyListedPackage(badRuntimePure); err == nil {
		t.Fatal("pure package calling runtime.NumCPU() admitted")
	}

	validScanner := writePkg("text/scanner", map[string]string{
		"scanner.go": "package scanner\nimport \"os\"\nvar _ = os.Stderr\n",
	})
	if err := verifyListedPackage(validScanner); err != nil {
		t.Fatalf("valid text/scanner os.Stderr reference refused: %v", err)
	}

	for name, src := range map[string]string{
		"Getenv":       "package scanner\nimport \"os\"\nvar _ = os.Getenv(\"X\")\n",
		"StderrWrite":  "package scanner\nimport \"os\"\nfunc f() { _, _ = os.Stderr.Write(nil) }\n",
		"StderrAssign": "package scanner\nimport \"os\"\nfunc f() { os.Stderr = nil }\n",
		"StderrAddr":   "package scanner\nimport \"os\"\nvar _ = &os.Stderr\n",
		"AliasedOS":    "package scanner\nimport myos \"os\"\nvar _ = myos.Getenv(\"X\")\n",
	} {
		badScanner := writePkg("text/scanner", map[string]string{"scanner.go": src})
		if err := verifyListedPackage(badScanner); err == nil {
			t.Fatalf("text/scanner violation %s admitted", name)
		}
	}

	for name, src := range map[string]string{
		"two-arg unapproved":      "package strings\nimport _ \"unsafe\"\n//go:linkname secret runtime.getAuxv\nfunc secret() uintptr\n",
		"one-arg unapproved":      "package strings\nimport _ \"unsafe\"\n//go:linkname ExportedSecret\nfunc ExportedSecret() {}\n",
		"indented linkname":       "package strings\nimport _ \"unsafe\"\n\t//go:linkname secret runtime.getAuxv\nfunc secret() uintptr\n",
		"CR mid-comment linkname": "package strings\nimport _ \"unsafe\"\n//go:linkname divideError runtime.divideError\r//go:linkname secret runtime.getAuxv\nfunc secret() uintptr\n",
		"BOM linkname":            "\uFEFF//go:linkname secret runtime.getAuxv\npackage strings\nimport _ \"unsafe\"\nfunc secret() uintptr\n",
		"block go:linkname":       "package strings\n/*go:linkname secret runtime.getAuxv*/\n",
		"wasmimport":              "package strings\n//go:wasmimport env clock\nfunc clock() int64\n",
		"wasmexport":              "package strings\n//go:wasmexport Exported\nfunc Exported() {}\n",
		"cgo directive":           "package strings\n//go:cgo_import_dynamic libc_open open \"libc.so\"\n",
		"fmt Println":             "package strings\nimport \"fmt\"\nfunc f() { fmt.Println(\"leak\") }\n",
		"fmt aliased":             "package strings\nimport f \"fmt\"\nvar _ = f.Sprintf(\"x\")\n",
	} {
		badDirPure := writePkg("strings", map[string]string{"strings.go": src})
		if err := verifyListedPackage(badDirPure); err == nil {
			t.Fatalf("pure package directive/selector violation %s admitted", name)
		}
	}

	for name, pkg := range map[string]listedPackage{
		"delegate os import": writePkg("crypto/internal/fips140/sha256", map[string]string{
			"sha256.go": "package sha256\nimport \"os\"\nvar _ = os.Getenv(\"X\")\n",
		}),
		"delegate unapproved 1-arg linkname": writePkg("internal/bytealg", map[string]string{
			"bytealg.go": "package bytealg\nimport _ \"unsafe\"\n//go:linkname unapprovedHook\nfunc unapprovedHook()\n",
		}),
		"filepathlite bad syscall": writePkg("internal/filepathlite", map[string]string{
			"path.go": "package filepathlite\nimport \"syscall\"\nvar _, _ = syscall.Getenv(\"X\")\n",
		}),
		"filepathlite bad windows": writePkg("internal/filepathlite", map[string]string{
			"path.go": "package filepathlite\nimport \"internal/syscall/windows\"\nvar _ = windows.GetStdHandle(0)\n",
		}),
		"jsonv2 bare time.Unix": writePkg("encoding/json/v2", map[string]string{
			"time.go": "package json\nimport \"time\"\nvar _ = time.Unix(0, 0)\n",
		}),
	} {
		if err := verifyListedPurePackage(pkg); err == nil {
			t.Fatalf("delegate package violation %s admitted", name)
		}
	}

	validJsonV2TimeUnixUTC := writePkg("encoding/json/v2", map[string]string{
		"time.go": "package json\nimport \"time\"\nvar _ = time.Unix(0, 0).UTC()\n",
	})
	if err := verifyListedPurePackage(validJsonV2TimeUnixUTC); err != nil {
		t.Fatalf("encoding/json/v2 time.Unix(0, 0).UTC() refused: %v", err)
	}

	nativeFilePure := writePkg("strings", map[string]string{
		"strings.go": "package strings\n",
		"native.c":   "int x = 0;\n",
	})
	if err := verifyListedPackage(nativeFilePure); err == nil {
		t.Fatal("pure package selecting native C file admitted")
	}

	validOS := writePkg("os", map[string]string{
		"os.go":       syntheticOSSrc,
		"tempfile.go": "package os\nimport _ \"unsafe\"\n//go:linkname runtime_rand runtime.rand\nfunc runtime_rand() uint64\n",
	})
	if err := verifyListedPackage(validOS); err != nil {
		t.Fatalf("valid os package refused: %v", err)
	}

	if err := verifyListedPackage(writePkg("os", map[string]string{
		"os.go":    syntheticOSSrc,
		"native.s": "TEXT ·f(SB),$0-0\n\tRET\n",
	})); err == nil {
		t.Fatal("os package selecting assembly file admitted")
	}

	gatedOS := mustMutateFixture(t, syntheticOSSrc, "func Getwd() (string, error) {\n", "const simEnabled = true\nfunc trySimGetwd() (string, bool, error) {\n\tif !simGate() {\n\t\treturn \"\", false, nil\n\t}\n\treturn \"/sim\", true, nil\n}\nfunc Getwd() (string, error) {\n\tif simEnabled {\n\t\tif wd, ok, err := trySimGetwd(); ok {\n\t\t\treturn wd, err\n\t\t}\n\t}\n")
	if err := verifyListedPackage(writePkg("os", map[string]string{
		"os.go":  gatedOS,
		"sim.go": "package os\nimport _ \"unsafe\"\n//go:linkname simGate runtime.simGate\nfunc simGate() bool\n",
	})); err == nil {
		t.Fatal("standalone os package requiring unverified runtime gate admitted")
	}

	simTabBase := mustMutateFixture(t, syntheticOSSrc, "import (\n", "import (\n\t\"sync/atomic\"\n")
	simTabBase = mustMutateFixture(t, simTabBase,
		"func (f *File) Close() error {\n\tif f == nil {\n\t\treturn ErrInvalid\n\t}\n\treturn f.file.close()\n}",
		"const simOff = false\nconst simEnabled = true\ntype simTab struct { spine atomic.Pointer[int]; count int }\nfunc (t *simTab) get(idx int) *int { sp := t.spine.Load(); if sp == nil || idx < 0 || idx > t.count { return nil }; return sp }\nfunc (t *simTab) set(v *int) { t.count++; t.spine.Store(v) }\nvar simStates simTab\nfunc simCount() int { return simStates.count }\nfunc simIdx(f *file) (int, bool) { return 0, f != nil }\nfunc stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s := simStates.get(idx); return s }\nfunc (f *File) Close() error {\n\tif f == nil {\n\t\treturn ErrInvalid\n\t}\n\tif simOff {\n\t\treturn nil\n\t}\n\tif simEnabled {\n\t\tif s := stateOf(f.file); s != nil {\n\t\t\treturn nil\n\t\t}\n\t}\n\treturn f.file.close()\n}",
	)
	if err := verifyListedPackage(writePkg("os", map[string]string{"os.go": simTabBase})); err != nil {
		t.Fatalf("valid standalone os state-table fixture refused: %v", err)
	}
	simTabTimeIdx := mustMutateFixture(t, simTabBase,
		"func simIdx(f *file) (int, bool) { return 0, f != nil }\nfunc stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s := simStates.get(idx); return s }\n",
		"func time(f *file) (int, bool) { return 0, f != nil }\n",
	)
	if err := verifyListedPackage(writePkg("os", map[string]string{
		"os.go":     simTabTimeIdx,
		"shadow.go": "package os\nimport \"time\"\nvar _ = time.UTC\nfunc stateOf(f *file) *int { idx, ok := time(f); if !ok { return nil }; s := simStates.get(idx); return s }\n",
	})); err == nil {
		t.Fatal("os state-table nilAcc import-shadowing pureIndexHelper admitted")
	}

	plan9OpenBase := mustMutateFixture(t, syntheticOSSrc,
		"func openFileNolog(name string, flag int, perm uint32) (*File, error) {\n\tr, err := syscall.Open(name, flag, perm)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"open\", Path: name, Err: err}\n\t}\n\treturn newFile(r, name), nil\n}",
		"func ignoringEINTR(fn func() error) error { return fn() }\nfunc open(path string, flag int, perm uint32) (int, pollFD, error) {\n\tr, err := syscall.Open(path, flag, perm)\n\treturn r, pollFD{}, err\n}\nfunc openFileNolog(name string, flag int, perm uint32) (*File, error) {\n\tvar r int\n\tvar s pollFD\n\tvar e error\n\tignoringEINTR(func() error {\n\t\tr, s, e = open(name, flag, perm)\n\t\treturn e\n\t})\n\tif e != nil {\n\t\treturn nil, &PathError{Op: \"open\", Path: name, Err: e}\n\t}\n\t_ = s\n\treturn newFile(r, name), nil\n}",
	)
	if err := verifyListedPackage(writePkg("os", map[string]string{"os.go": plan9OpenBase})); err != nil {
		t.Fatalf("valid standalone Plan 9 openFileNolog fixture refused: %v", err)
	}

	posixGetwdBase := mustMutateFixture(t, syntheticOSSrc,
		"func Getwd() (string, error) {\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}",
		"func ignoringEINTR2[T any](fn func() (T, error)) (T, error) {\n\tfor {\n\t\tv, err := fn()\n\t\tif err != syscall.EINTR {\n\t\t\treturn v, err\n\t\t}\n\t}\n}\nfunc Getwd() (string, error) {\n\tdir, err := ignoringEINTR2(syscall.Getwd)\n\treturn dir, err\n}",
	)
	if err := verifyListedPackage(writePkg("os", map[string]string{"os.go": posixGetwdBase})); err != nil {
		t.Fatalf("valid standalone POSIX Getwd ignoringEINTR2 fixture refused: %v", err)
	}

	const climbHelpersCommon = `import (
	"errors"
	"internal/testlog"
	"io"
	"sync"
	"syscall"
)`
	const climbGetwdBodyPrefix = `type FileInfo interface {
	Name() string
}
type fileStat struct {
	name string
	dev  uint64
	ino  uint64
}
func (fs *fileStat) Name() string { return fs.name }
type SyscallError struct {
	Syscall string
	Err     error
}
func (e *SyscallError) Error() string { return e.Syscall }
func NewSyscallError(callName string, err error) error {
	if err == nil {
		return nil
	}
	return &SyscallError{callName, err}
}
const errENOSYS = syscall.ENOSYS
var getwdCache struct {
	sync.Mutex
	dir string
}
func SameFile(fi1, fi2 FileInfo) bool {
	fs1, ok1 := fi1.(*fileStat)
	fs2, ok2 := fi2.(*fileStat)
	if !ok1 || !ok2 {
		return false
	}
	return sameFile(fs1, fs2)
}
func sameFile(fs1, fs2 *fileStat) bool {
	return fs1.dev == fs2.dev && fs1.ino == fs2.ino
}
func statNolog(name string) (FileInfo, error) {
	var fs fileStat
	err := syscall.Stat(name, nil)
	if err != nil {
		return nil, &PathError{Op: "stat", Path: name, Err: err}
	}
	return &fs, nil
}
func lstatNolog(name string) (FileInfo, error) {
	var fs fileStat
	err := syscall.Lstat(name, nil)
	if err != nil {
		return nil, &PathError{Op: "lstat", Path: name, Err: err}
	}
	return &fs, nil
}
func openDirNolog(name string) (*File, error) {
	return openFileNolog(name, 0, 0)
}
func (f *File) Readdirnames(n int) ([]string, error) {
	return nil, io.EOF
}
`
	const climbGetwdFuncFstat = `func fstatNolog(f *File) (FileInfo, error) {
	var fs fileStat
	err := f.pfd.Fstat(nil)
	if err != nil {
		return nil, f.wrapErr("stat", err)
	}
	return &fs, nil
}
func Getwd() (dir string, err error) {
	var dot FileInfo
	dir = Getenv("PWD")
	if len(dir) > 0 && dir[0] == '/' {
		dot, err = statNolog(".")
		if err != nil {
			return "", err
		}
		d, err := statNolog(dir)
		if err == nil && SameFile(dot, d) {
			return dir, nil
		}
	}
	if syscall.ImplementsGetwd {
		dir, err = syscall.Getwd()
		if err != syscall.ENAMETOOLONG {
			return dir, NewSyscallError("getwd", err)
		}
	}
	if dot == nil {
		dot, err = statNolog(".")
		if err != nil {
			return "", err
		}
	}
	getwdCache.Lock()
	dir = getwdCache.dir
	getwdCache.Unlock()
	if len(dir) > 0 {
		d, err := statNolog(dir)
		if err == nil && SameFile(dot, d) {
			return dir, nil
		}
	}
	root, err := statNolog("/")
	if err != nil {
		return "", err
	}
	if SameFile(root, dot) {
		return "/", nil
	}
	dir = ""
	for parent := ".."; ; parent = "../" + parent {
		if len(parent) >= 1024 {
			return "", NewSyscallError("getwd", syscall.ENAMETOOLONG)
		}
		fd, err := openDirNolog(parent)
		if err != nil {
			return "", err
		}
		for {
			names, err := fd.Readdirnames(100)
			if err != nil {
				fd.Close()
				return "", NewSyscallError("getwd", errENOSYS)
			}
			for _, name := range names {
				d, _ := lstatNolog(parent + "/" + name)
				if SameFile(d, dot) {
					dir = "/" + name + dir
					goto Found
				}
			}
		}
	Found:
		pd, err := fstatNolog(fd)
		fd.Close()
		if err != nil {
			return "", err
		}
		if SameFile(pd, root) {
			break
		}
		dot = pd
	}
	getwdCache.Lock()
	getwdCache.dir = dir
	getwdCache.Unlock()
	return dir, nil
}`

	climbFstatGetwdBase := mustMutateFixture(t, syntheticOSSrc,
		"import (\n\t\"errors\"\n\t\"internal/testlog\"\n\t\"io\"\n\t\"syscall\"\n)",
		climbHelpersCommon,
	)
	climbFstatGetwdBase = mustMutateFixture(t, climbFstatGetwdBase,
		"func (fd *pollFD) Close() error                { return nil }",
		"func (fd *pollFD) Close() error                { return nil }\nfunc (fd *pollFD) Fstat(_ any) error           { return nil }",
	)
	climbFstatGetwdBase = mustMutateFixture(t, climbFstatGetwdBase,
		"func Getwd() (string, error) {\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}",
		climbGetwdBodyPrefix+climbGetwdFuncFstat,
	)
	if err := verifyListedPackage(writePkg("os", map[string]string{"os.go": climbFstatGetwdBase})); err != nil {
		t.Fatalf("valid standalone climbing Getwd (fstatNolog) fixture refused: %v", err)
	}

	climbFileStatGetwdBase := mustMutateFixture(t, climbFstatGetwdBase,
		"func fstatNolog(f *File) (FileInfo, error) {",
		"func (f *File) Stat() (FileInfo, error) {\n\tif f == nil {\n\t\treturn nil, ErrInvalid\n\t}\n\tvar fs fileStat\n\terr := f.pfd.Fstat(nil)\n\tif err != nil {\n\t\treturn nil, f.wrapErr(\"stat\", err)\n\t}\n\treturn &fs, nil\n}\nfunc fstatNologUnused(f *File) (FileInfo, error) {",
	)
	climbFileStatGetwdBase = mustMutateFixture(t, climbFileStatGetwdBase,
		"pd, err := fstatNolog(fd)",
		"pd, err := fd.Stat()",
	)
	if err := verifyListedPackage(writePkg("os", map[string]string{"os.go": climbFileStatGetwdBase})); err != nil {
		t.Fatalf("valid standalone climbing Getwd (fd.Stat) fixture refused: %v", err)
	}

	climbDisjointAltBase := mustMutateFixture(t, climbFstatGetwdBase,
		"func SameFile(fi1, fi2 FileInfo) bool {\n",
		"type altStat struct{ id int }\nfunc (a *altStat) Name() string { return \"\" }\nfunc sameAlt(a, b FileInfo) (bool, bool) {\n\td1, ok1 := a.(*altStat)\n\td2, ok2 := b.(*altStat)\n\tif !ok1 && !ok2 {\n\t\treturn false, false\n\t}\n\tif !ok1 || !ok2 {\n\t\treturn false, true\n\t}\n\treturn d1.id == d2.id, true\n}\nfunc SameFile(fi1, fi2 FileInfo) bool {\n\tif same, handled := sameAlt(fi1, fi2); handled {\n\t\treturn same\n\t}\n",
	)
	if err := verifyListedPackage(writePkg("os", map[string]string{"os.go": climbDisjointAltBase})); err != nil {
		t.Fatalf("valid standalone climbing Getwd (disjoint SameFile alt struct) fixture refused: %v", err)
	}

	for name, mut := range map[string][2]string{
		"missing LookupEnv":                                               {"func LookupEnv(key string) (string, bool) {\n\ttestlog.Getenv(key)\n\treturn \"\", false\n}\n", ""},
		"Chdir missing testlog.Open":                                      {"\t\ttestlog.Open(dir)\n", ""},
		"Chdir returning nil on syscall error":                            {"return &PathError{Op: \"chdir\", Path: dir, Err: e}", "return nil"},
		"ReadFile bypassing Open":                                         {"f, err := Open(name)", "var f *File; var err error"},
		"aliased testlog":                                                 {"\"internal/testlog\"", "tl \"internal/testlog\""},
		"shadowed testlog":                                                {"testlog.Getenv(key)", "testlog := struct{ Getenv func(string) }{func(string) {}}; testlog.Getenv(key)"},
		"ErrInvalid nil initializer":                                      {"errors.New(\"invalid argument\")", "error(nil)"},
		"ErrInvalid mutated in init":                                      {"var ErrClosed =", "func init() { ErrInvalid = nil }\nvar ErrClosed ="},
		"shadowed errors package var":                                     {"var errors = struct{ New func(string) error }{func(string) error { return nil }}\nvar ErrInvalid =", ""},
		"OpenFile hook inside if false":                                   {"testlog.Open(name)", "if false { testlog.Open(name) }"},
		"Stat hook guarded by true const":                                 {"func Stat(name string)", "const alwaysTrue = true\nfunc Stat(name string)"},
		"OpenFile hook preceded by var skip guard":                        {"testlog.Open(name)", "if skipHook { return nil, nil }\n\ttestlog.Open(name)"},
		"OpenFile dropping name arg":                                      {"testlog.Open(name)", "testlog.Open(\"\")"},
		"File.Write dropping ErrShortWrite":                               {"\tif n != len(b) {\n\t\terr = io.ErrShortWrite\n\t}\n", ""},
		"File.Write dropping wrapErr":                                     {"\tif e != nil {\n\t\terr = f.wrapErr(\"write\", e)\n\t}\n", ""},
		"File.WriteString bypassing Write":                                {"return f.Write([]byte(s))", "return len(s), nil"},
		"File.Close bypassing file.close":                                 {"return f.file.close()", "return nil"},
		"file.close ignoring pfd.Close error":                             {"if e := file.pfd.Close(); e != nil {\n\t\terr = &PathError{Op: \"close\", Path: file.name, Err: e}\n\t}", "_ = file.pfd.Close()"},
		"os linkname overriding Open":                                     {"func Open(", "//go:linkname Open runtime.evilOpen\nfunc Open("},
		"os linkname overriding close":                                    {"func (file *file) close()", "//go:linkname close runtime.evilClose\nfunc (file *file) close()"},
		"os linkname overriding destroy":                                  {"package os\n", "package os\nimport _ \"unsafe\"\n//go:linkname destroy runtime.evilDestroy\nfunc destroy()\n"},
		"os aliased unsafe import":                                        {"import (\n", "import (\n\tu \"unsafe\"\n"},
		"file.close receiver shadowing ErrInvalid":                        {"func (file *file) close() error {\n\tif file == nil {\n\t\treturn syscall.EINVAL\n\t}\n\tvar err error\n\tif e := file.pfd.Close(); e != nil {\n\t\terr = &PathError{Op: \"close\", Path: file.name, Err: e}\n\t}\n\treturn err\n}", "func (*file) Error() string { return \"\" }\nfunc (ErrInvalid *file) close() error {\n\tif ErrInvalid == nil {\n\t\treturn ErrInvalid\n\t}\n\tvar err error\n\tif e := ErrInvalid.pfd.Close(); e != nil {\n\t\terr = &PathError{Op: \"close\", Path: ErrInvalid.name, Err: e}\n\t}\n\treturn err\n}"},
		"os wasmimport directive":                                         {"package os\n", "package os\n//go:wasmimport env hostRead\nfunc hostRead()\n"},
		"os cgo_import_dynamic directive":                                 {"package os\n", "package os\n//go:cgo_import_dynamic libc_open open \"libc.so\"\n"},
		"OpenFile synthesizing fake descriptor":                           {"r, err := syscall.Open(name, flag, perm)", "r, err := 99, error(nil)"},
		"OpenFile mutating descriptor":                                    {"return newFile(r, name), nil", "r = 0\n\treturn newFile(r, name), nil"},
		"ReadFile helper calling testlog.Stat":                            {"func statOrZero(f *File) int64 {\n\treturn 0\n}", "func statOrZero(f *File) int64 {\n\ttestlog.Stat(f.name)\n\treturn 0\n}"},
		"File.Fd returning synthetic zero":                                {"return uintptr(f.pfd.Sysfd)", "return uintptr(0)"},
		"Exit omitting PanicOnExit0 guard":                                {"\tif code == 0 && testlog.PanicOnExit0() {\n\t\tpanic(\"os.Exit(0)\")\n\t}\n", ""},
		"file.close calling syscall.Exit":                                 {"\treturn err\n}", "\tsyscall.Exit(0)\n\treturn err\n}"},
		"Getwd returning constant slash":                                  {"dir, err := syscall.Getwd()\n\treturn dir, err", "return \"/\", nil"},
		"Getwd returning concatenated string literal":                     {"dir, err := syscall.Getwd()\n\treturn dir, err", "return \"/tmp\" + \"/spoof\", nil"},
		"Getwd returning package const string":                            {"func Getwd() (string, error) {\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}", "const fakeWD = \"/fake\"\nfunc Getwd() (string, error) {\n\treturn fakeWD, nil\n}"},
		"Getwd returning constant error under non-error guard":            {"func Getwd() (string, error) {\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}", "func Getwd() (string, error) {\n\tif true {\n\t\treturn \"\", ErrInvalid\n\t}\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}"},
		"Getwd swallowing syscall.Getwd error":                            {"dir, err := syscall.Getwd()\n\treturn dir, err", "dir, _ := syscall.Getwd()\n\treturn dir, nil"},
		"Getwd ignoringEINTR2 spoofing return":                            {"return v, err", "_, _ = v, err\n\t\t\treturn *new(T), nil"},
		"Getwd ignoringEINTR2 inverted EINTR check":                       {"err != syscall.EINTR", "err == syscall.EINTR"},
		"openFileNolog ignoringEINTR spoofing nil":                        {"return fn()", "for {\n\t\terr := fn()\n\t\t_ = err\n\t\tif err != syscall.EINTR {\n\t\t\treturn nil\n\t\t}\n\t}"},
		"openFileNolog ignoringEINTR inverted EINTR check":                {"return fn()", "for {\n\t\terr := fn()\n\t\tif err == syscall.EINTR {\n\t\t\treturn err\n\t\t}\n\t}"},
		"open helper early return with valid fd":                          {"\tr, err := syscall.Open(path, flag, perm)", "\tif path == \"x\" {\n\t\treturn 3, pollFD{}, nil\n\t}\n\tr, err := syscall.Open(path, flag, perm)"},
		"state table non-spine field address-taken":                       {"func simCount() int { return simStates.count }", "func simCount() *int { return &simStates.count }"},
		"state table whole-struct overwrite":                              {"func simCount() int { return simStates.count }", "func simCount() int { simStates = simTab{}; return 0 }"},
		"state table indirect mutator method called":                      {"func simCount() int { return simStates.count }", "func (t *simTab) wrapSet(v *int) { t.set(v) }\nfunc ExportedWrapTrigger() { var x int; simStates.wrapSet(&x) }\nfunc simCount() int { return simStates.count }"},
		"state table custom struct non-spine field":                       {"type simTab struct { spine atomic.Pointer[int]; count int }", "type subBox struct{ v int }\ntype simTab struct { spine atomic.Pointer[int]; count int; sub subBox }"},
		"state table receiver escaping":                                   {"func simCount() int { return simStates.count }", "func (t *simTab) leak() any { return t }\nfunc simCount() int { return simStates.count }"},
		"state table non-nil short-circuit condition":                     {"sp == nil || idx < 0", "idx < 0 || sp == nil"},
		"state table nilAcc parameter shadowing callee":                   {"func stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s := simStates.get(idx); return s }", "func stateOf(simIdx func(any) (int, bool)) *int { idx, ok := simIdx(simIdx); if !ok { return nil }; s := simStates.get(idx); return s }"},
		"state table nilAcc 2-LHS := redeclaring prior local on 1st LHS":  {"func stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s := simStates.get(idx); return s }", "func stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s1 := simStates.get(idx); if s1 == nil { s1, ok2 := simIdx(f); if !ok2 { return nil }; s2 := simStates.get(s1); return s2 }; return nil }"},
		"state table nilAcc 2-LHS := redeclaring prior local on 2nd LHS":  {"func stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s := simStates.get(idx); return s }", "func stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s1 := simStates.get(idx); if s1 == nil { idx2, ok := simIdx(f); if !ok { return nil }; s2 := simStates.get(idx2); return s2 }; return nil }"},
		"state table pureIndexHelper reading package global var":          {"func simIdx(f *file) (int, bool) { return 0, f != nil }", "var globalIdxBias int\nfunc simIdx(f *file) (int, bool) { return globalIdxBias, f != nil }"},
		"state table pureIndexHelper writing package global var":          {"func simIdx(f *file) (int, bool) { return 0, f != nil }", "var globalIdxSink int\nfunc simIdx(f *file) (int, bool) { globalIdxSink = 1; return 0, f != nil }"},
		"state table pureIndexHelper channel send":                        {"func simIdx(f *file) (int, bool) { return 0, f != nil }", "func simIdx(f *file) (int, bool) { var ch chan int; ch <- 1; return 0, f != nil }"},
		"Chdir invoking helper before Logger.Chdir":                       {"\tif log := testlog.Logger(); log != nil {", "\t_, _ = Getwd()\n\tif log := testlog.Logger(); log != nil {"},
		"Getwd climb returning nil-initialized package error":             {"const errENOSYS = syscall.ENOSYS", "var errENOSYS error = nil"},
		"Getwd climb returning PWD hint without slash guard":              {"if len(dir) > 0 && dir[0] == '/' {", "if len(dir) > 0 {"},
		"Getwd climb mutating dir outside SameFile(d, dot)":               {"\t\t\t\tif SameFile(d, dot) {", "\t\t\t\tdir = \"/spoof\"\n\t\t\t\tif SameFile(d, dot) {"},
		"Getwd climb breaking outer loop without SameFile":                {"\t\tif SameFile(pd, root) {\n\t\t\tbreak\n\t\t}", "\t\tif pd != nil {\n\t\t\tbreak\n\t\t}"},
		"statNolog returning address of package-level fileStat":           {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "var sharedFS fileStat\nfunc statNolog(name string) (FileInfo, error) {\n\t_ = &sharedFS; return &sharedFS, nil; var fs fileStat"},
		"statNolog returning package-level *fileStat var":                 {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "var sharedStatPtr *fileStat\nfunc statNolog(name string) (FileInfo, error) {\n\treturn sharedStatPtr, nil; var fs fileStat"},
		"statNolog calling testlog.Stat":                                  {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "func statNolog(name string) (FileInfo, error) {\n\ttestlog.Stat(name)\n\tvar fs fileStat"},
		"openDirNolog calling testlog.Open":                               {"func openDirNolog(name string) (*File, error) {\n\treturn openFileNolog(name, 0, 0)\n}", "func openDirNolog(name string) (*File, error) {\n\ttestlog.Open(name)\n\treturn openFileNolog(name, 0, 0)\n}"},
		"SameFile returning true unconditionally":                         {"return sameFile(fs1, fs2)", "return true"},
		"sameFile comparing single argument to itself":                    {"return fs1.dev == fs2.dev && fs1.ino == fs2.ino", "return fs1.dev == fs1.dev && fs1.ino == fs1.ino"},
		"File.Stat calling testlog.Stat when used by Getwd":               {"func (f *File) Stat() (FileInfo, error) {\n\tif f == nil {", "func (f *File) Stat() (FileInfo, error) {\n\ttestlog.Stat(f.name)\n\tif f == nil {"},
		"statNolog overwriting fresh FileInfo via addr-of local":          {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "func clobberInfo(dst *FileInfo) { *dst = nil }\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\tvar out FileInfo = &fs\n\tclobberInfo(&out)\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn out, nil\n}"},
		"statNolog overwriting local fileStat from package var":           {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)", "var sharedFS fileStat\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tfs = sharedFS"},
		"statNolog overwriting local fileStat after taking addr":          {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "var sharedFS fileStat\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\tp := &fs\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\tfs = sharedFS\n\treturn p, nil\n}"},
		"statNolog overwriting fresh FileInfo via 2nd 2-LHS":              {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "func bogusPair() (int, FileInfo) { return 0, nil }\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\tvar p FileInfo = &fs\n\t_, p = bogusPair()\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn p, nil\n}"},
		"statNolog taking pkg var addr after sibling block local":         {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "var sharedFS fileStat\nfunc statNolog(name string) (FileInfo, error) {\n\t{ var sharedFS int; _ = sharedFS }\n\t_ = &sharedFS\n\tvar fs fileStat"},
		"statNolog returning pkg var laundered by inner block local":      {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "var sharedFS FileInfo = &fileStat{}\nfunc statNolog(name string) (FileInfo, error) {\n\tif false { var sharedFS FileInfo = &fileStat{}; _ = sharedFS }\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\t_ = &fs\n\treturn sharedFS, nil\n}"},
		"statNolog returning pkg var before post-return local":            {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "var sharedFS FileInfo = &fileStat{}\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\tif true { return sharedFS, nil }\n\tvar sharedFS FileInfo = &fs\n\treturn sharedFS, nil\n}"},
		"statNolog calling local function variable shadowing top helper":  {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "var sharedFS FileInfo = &fileStat{}\nfunc newFreshFS() (FileInfo, error) { return &fileStat{}, nil }\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\t_ = &fs\n\tnewFreshFS := func() (FileInfo, error) { return sharedFS, nil }\n\treturn newFreshFS()\n}"},
		"statNolog calling local function variable in statement position": {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "var extraHook func()\nfunc statNolog(name string) (FileInfo, error) {\n\tfn := extraHook\n\tfn()\n\tvar fs fileStat"},
		"statNolog helper dereference-assigning fileStat pointer":         {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "var sharedFS fileStat\nfunc clobberFS(dst *fileStat) { *dst = sharedFS }\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\tclobberFS(&fs)"},
		"Getwd returning sentinel error without call provenance":          {"func Getwd() (string, error) {\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}", "func Getwd() (string, error) {\n\terr := ErrInvalid\n\tif err != nil {\n\t\treturn \"\", err\n\t}\n\tdir, err2 := syscall.Getwd()\n\treturn dir, err2\n}"},
		"Getwd returning const error under unverified err guard":          {"func Getwd() (string, error) {\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}", "func Getwd() (string, error) {\n\terr := ErrInvalid\n\tif err != nil {\n\t\treturn \"\", syscall.ENOSYS\n\t}\n\tdir, err2 := syscall.Getwd()\n\treturn dir, err2\n}"},
		"Getwd jumping via goto into post-call error guard":               {"\t\tfd, err := openDirNolog(parent)\n\t\tif err != nil {\n\t\t\treturn \"\", err\n\t\t}", "\t\tif len(parent) > 0 {\n\t\t\terr = ErrInvalid\n\t\t\tgoto Bail\n\t\t}\n\t\tfd, err := openDirNolog(parent)\n\tBail:\n\t\tif err != nil {\n\t\t\treturn \"\", err\n\t\t}"},
		"Getwd returning error from else branch of error guard":           {"\tgetwdCache.Lock()\n\tdir = getwdCache.dir", "\ttmp, lerr := lstatNolog(\".\")\n\t_ = tmp\n\tif lerr != nil {\n\t\treturn \"\", lerr\n\t} else {\n\t\treturn \"\", syscall.ENOSYS\n\t}\n\tgetwdCache.Lock()\n\tdir = getwdCache.dir"},
		"Getwd mutating error inside compound branch":                     {"\tgetwdCache.Lock()\n\tdir = getwdCache.dir", "\ttmp, lerr := lstatNolog(\".\")\n\t_ = tmp\n\tif dot == nil {\n\t\tlerr = ErrInvalid\n\t}\n\tif lerr != nil {\n\t\treturn \"\", lerr\n\t}\n\tgetwdCache.Lock()\n\tdir = getwdCache.dir"},
		"Getwd poisoning getwdCache.dir in package helper":                {"var getwdCache struct {", "func poisonGetwdCache() { getwdCache.dir = \".\" }\nvar getwdCache struct {"},
		"Getwd mutating parent loop step":                                 {"for parent := \"..\"; ; parent = \"../\" + parent {", "for parent := \"..\"; ; parent = \"/tmp\" {"},
		"Getwd reassigning parent inside climb loop":                      {"\t\tfd, err := openDirNolog(parent)", "\t\tparent = \"/tmp\"\n\t\tfd, err := openDirNolog(parent)"},
		"statNolog referencing disjoint SameFile alt struct":              {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "func statNolog(name string) (FileInfo, error) {\n\tvar _ *altStat\n\tvar fs fileStat"},
	} {
		base := syntheticOSSrc
		switch name {
		case "shadowed errors package var":
			base = mustMutateFixture(t, base, "var ErrInvalid =", "var errors = struct{ New func(string) error }{func(string) error { return nil }}\nvar ErrInvalid =")
			mut = [2]string{"var ErrClosed =", "var ErrClosed ="}
		case "Stat hook guarded by true const":
			base = mustMutateFixture(t, base, "testlog.Stat(name)\n\treturn nil, nil\n}", "if alwaysTrue {}\n\ttestlog.Stat(name)\n\treturn nil, nil\n}")
		case "OpenFile hook preceded by var skip guard":
			base = mustMutateFixture(t, base, "var ErrInvalid =", "var skipHook bool\nvar ErrInvalid =")
		case "os linkname overriding Open", "os linkname overriding close":
			base = mustMutateFixture(t, base, "import (\n", "import (\n\t_ \"unsafe\"\n")
		case "Getwd ignoringEINTR2 spoofing return", "Getwd ignoringEINTR2 inverted EINTR check":
			base = posixGetwdBase
		case "openFileNolog ignoringEINTR spoofing nil", "openFileNolog ignoringEINTR inverted EINTR check", "open helper early return with valid fd":
			base = plan9OpenBase
		case "state table nilAcc parameter shadowing callee":
			base = mustMutateFixture(t, simTabBase, "type file struct {\n\tpfd  pollFD\n\tname string\n}", "type file struct {\n\tpfd   pollFD\n\tname  string\n\tbadFn func(any) (int, bool)\n}")
			base = mustMutateFixture(t, base, "if s := stateOf(f.file); s != nil {", "if s := stateOf(f.file.badFn); s != nil {")
		case "state table non-spine field address-taken",
			"state table whole-struct overwrite",
			"state table indirect mutator method called",
			"state table custom struct non-spine field",
			"state table receiver escaping",
			"state table non-nil short-circuit condition",
			"state table nilAcc 2-LHS := redeclaring prior local on 1st LHS",
			"state table nilAcc 2-LHS := redeclaring prior local on 2nd LHS",
			"state table pureIndexHelper reading package global var",
			"state table pureIndexHelper writing package global var",
			"state table pureIndexHelper channel send":
			base = simTabBase
		case "Getwd climb returning nil-initialized package error",
			"Getwd climb returning PWD hint without slash guard",
			"Getwd climb mutating dir outside SameFile(d, dot)",
			"Getwd climb breaking outer loop without SameFile",
			"statNolog returning address of package-level fileStat",
			"statNolog returning package-level *fileStat var",
			"statNolog calling testlog.Stat",
			"openDirNolog calling testlog.Open",
			"SameFile returning true unconditionally",
			"sameFile comparing single argument to itself",
			"statNolog overwriting fresh FileInfo via addr-of local",
			"statNolog overwriting local fileStat from package var",
			"statNolog overwriting local fileStat after taking addr",
			"statNolog overwriting fresh FileInfo via 2nd 2-LHS",
			"statNolog taking pkg var addr after sibling block local",
			"statNolog returning pkg var laundered by inner block local",
			"statNolog returning pkg var before post-return local",
			"statNolog calling local function variable shadowing top helper",
			"statNolog calling local function variable in statement position",
			"statNolog helper dereference-assigning fileStat pointer",
			"Getwd jumping via goto into post-call error guard",
			"Getwd returning error from else branch of error guard",
			"Getwd mutating error inside compound branch",
			"Getwd poisoning getwdCache.dir in package helper",
			"Getwd mutating parent loop step",
			"Getwd reassigning parent inside climb loop":
			base = climbFstatGetwdBase
		case "File.Stat calling testlog.Stat when used by Getwd":
			base = climbFileStatGetwdBase
		case "statNolog referencing disjoint SameFile alt struct":
			base = climbDisjointAltBase
		}
		src := mustMutateFixture(t, base, mut[0], mut[1])
		if err := verifyListedPackage(writePkg("os", map[string]string{"os.go": src})); err == nil {
			t.Fatalf("os package violation %q admitted", name)
		}
	}

	validInternalTestlog := writePkg("internal/testlog", map[string]string{
		"log.go": syntheticInternalTestlogSrc,
	})
	if err := verifyListedPackage(validInternalTestlog); err != nil {
		t.Fatalf("valid internal/testlog package refused: %v", err)
	}
	for name, mut := range map[string][2]string{
		"SetLogger false condition":  {"!logger.CompareAndSwap(nil, &impl)", "false"},
		"SetLogger Store overwrite":  {"if !logger.CompareAndSwap(nil, &impl) {\n\t\tpanic(\"testlog: SetLogger must be called only once\")\n\t}", "logger.Store(&impl)"},
		"Logger returning nil":       {"return *impl", "return nil"},
		"Getenv dropping arg":        {"log.Getenv(name)", "log.Getenv(\"\")"},
		"Open bypassing Logger":      {"if log := Logger(); log != nil {\n\t\tlog.Open(name)\n\t}", "if false {}"},
		"Stat wrong method":          {"log.Stat(name)", "log.Open(name)"},
		"extra Reset clearing state": {"func Chdir(name string)", "func Reset() { logger.Store(nil) }\nfunc Chdir(name string)"},
	} {
		src := mustMutateFixture(t, syntheticInternalTestlogSrc, mut[0], mut[1])
		if err := verifyListedPackage(writePkg("internal/testlog", map[string]string{"log.go": src})); err == nil {
			t.Fatalf("internal/testlog violation %q admitted", name)
		}
	}

	validBufio := writePkg("bufio", map[string]string{
		"bufio.go": syntheticBufioSrc,
	})
	if err := verifyListedPurePackage(validBufio); err != nil {
		t.Fatalf("valid bufio package refused: %v", err)
	}
	for name, mut := range map[string][2]string{
		"Flush dropping ErrShortWrite":       {"err = io.ErrShortWrite", "err = nil"},
		"Flush returning nil on write error": {"b.err = err\n\t\treturn err", "b.err = err\n\t\treturn nil"},
		"NewWriterSize missing <= 0 clamp":   {"if size <= 0 {", "if size < 0 {"},
		"WriteByte skipping Flush on 0":      {"b.Available() <= 0 && b.Flush() != nil", "b.Available() < 0 && b.Flush() != nil"},
		"WriteString advancing by len(s)":    {"s = s[n:]", "s = s[len(s):]"},
		"WriteString swallowing sticky err":  {"return nn, b.err", "return nn, nil"},
		"Flush empty buffer non-nil error":   {"if b.n == 0 {\n\t\treturn nil\n\t}", "if b.n == 0 {\n\t\treturn io.EOF\n\t}"},
		"WriteString trivial probe if true":  {"if b.Buffered() == 0 && sw == nil && tryStringWriter {", "if true {"},
	} {
		src := mustMutateFixture(t, syntheticBufioSrc, mut[0], mut[1])
		if err := verifyListedPurePackage(writePkg("bufio", map[string]string{"bufio.go": src})); err == nil {
			t.Fatalf("bufio violation %q admitted", name)
		}
	}

	validTestdeps := writePkg("testing/internal/testdeps", map[string]string{
		"deps.go": syntheticTestdepsSrc,
	})
	if err := verifyListedPackage(validTestdeps); err != nil {
		t.Fatalf("valid testdeps package refused: %v", err)
	}
	for name, mut := range map[string][2]string{
		"StartTestLog SetLogger nil":       {"testlog.SetLogger(&log)", "testlog.SetLogger(nil)"},
		"StartTestLog ignoring w":          {"log.w = bufio.NewWriter(w)", "log.w = bufio.NewWriter(io.Discard)"},
		"StartTestLog nil writer":          {"log.w = bufio.NewWriter(w)", "log.w = bufio.NewWriter(nil)"},
		"StopTestLog dropping Flush":       {"err := log.w.Flush()\n\tlog.w = nil\n\treturn err", "log.w.Flush()\n\tlog.w = nil\n\treturn nil"},
		"StopTestLog blanking Flush":       {"err := log.w.Flush()\n\tlog.w = nil\n\treturn err", "_ = log.w.Flush()\n\tlog.w = nil\n\treturn nil"},
		"StopTestLog clearing w pre-Flush": {"err := log.w.Flush()\n\tlog.w = nil", "log.w = nil\n\terr := log.w.Flush()"},
		"StopTestLog omitting w = nil":     {"\tlog.w = nil\n", ""},
		"StopTestLog nil-guarding w":       {"err := log.w.Flush()\n\tlog.w = nil\n\treturn err", "if log.w == nil { return nil }\n\terr := log.w.Flush()\n\tlog.w = nil\n\treturn err"},
		"add dropping newline check":       {"strings.Contains(name, \"\\n\")", "strings.Contains(name, \"\\r\")"},
		"add wrong separator byte":         {"l.w.WriteByte(' ')", "l.w.WriteByte('\\t')"},
		"Getenv wrong verb":                {"l.add(\"getenv\", key)", "l.add(\"open\", key)"},
		"add calling Reset":                {"l.w.WriteString(op)", "l.w.Reset(io.Discard)\n\tl.w.WriteString(op)"},
	} {
		src := mustMutateFixture(t, syntheticTestdepsSrc, mut[0], mut[1])
		if err := verifyListedPackage(writePkg("testing/internal/testdeps", map[string]string{"deps.go": src})); err == nil {
			t.Fatalf("testdeps violation %q admitted", name)
		}
	}

	validTestingStock := writePkg("testing", map[string]string{
		"testing.go": syntheticTestingInlineSrc,
	})
	if err := verifyListedPackage(validTestingStock); err != nil {
		t.Fatalf("valid inline testing package refused: %v", err)
	}
	validTestingSplit := writePkg("testing", map[string]string{
		"testing.go": syntheticTestingSplitSrc,
	})
	if err := verifyListedPackage(validTestingSplit); err != nil {
		t.Fatalf("valid split testing package refused: %v", err)
	}

	for name, mut := range map[string][2]string{
		"blanked StopTestLog":                     {"if err := m.deps.StopTestLog(); err != nil {\n\t\t\tpanic(err)\n\t\t}", "_ = m.deps.StopTestLog()"},
		"unchecked err StopTestLog":               {"if err := m.deps.StopTestLog(); err != nil {\n\t\t\tpanic(err)\n\t\t}", "err2 := m.deps.StopTestLog(); _ = err2"},
		"empty handler StopTestLog":               {"panic(err)", ""},
		"fmt-only handler StopTestLog":            {"import (\n", "import (\n\t\"fmt\"\n"},
		"exit-zero handler StopTestLog":           {"panic(err)", "os.Exit(0)"},
		"return-only handler StopTestLog":         {"panic(err)", "return 1"},
		"recover-swallowed StopTestLog":           {"flag.Parse()", "defer func() { _ = recover() }()\n\tflag.Parse()"},
		"dead-branch if false StopTestLog":        {"if err := m.deps.StopTestLog(); err != nil {\n\t\t\tpanic(err)\n\t\t}", "if false { if err := m.deps.StopTestLog(); err != nil { os.Exit(2) } }"},
		"unguarded flag StopTestLog":              {"var testlog = flag.String(\"test.testlogfile\", \"\", \"\")", "var otherFlag bool\nvar testlog = flag.String(\"test.testlogfile\", \"\", \"\")"},
		"goto bypassing StopTestLog":              {"if err := m.deps.StopTestLog(); err != nil {\n\t\t\tpanic(err)\n\t\t}", "goto done; if err := m.deps.StopTestLog(); err != nil { os.Exit(2) }; done: ;"},
		"hardcoded os.Create path":                {"os.Create(*testlog)", "os.Create(\"log\")"},
		"missing f.Close after Stop":              {"if err := f.Close(); err != nil {\n\t\t\tos.Exit(2)\n\t\t}", "_ = f"},
		"unchecked f.Close after Stop":            {"if err := f.Close(); err != nil {\n\t\t\tos.Exit(2)\n\t\t}", "_ = f.Close()"},
		"flag dereference clobber":                {"flag.Parse()", "flag.Parse()\n\t*testlog = \"\""},
		"flag dereference address-taken":          {"flag.Parse()", "flag.Parse()\n\t_ = &*testlog"},
		"non-empty flag default":                  {"flag.String(\"test.testlogfile\", \"\", \"\")", "flag.String(\"test.testlogfile\", \"x\", \"\")"},
		"missing flag.Parse in Run":               {"\tflag.Parse()\n", ""},
		"runner call before StartTestLog":         {"m.deps.StartTestLog(f)", "_ = runTests(m.tests)\n\t\tm.deps.StartTestLog(f)"},
		"runner call after StopTestLog":           {"\t\treturn 0\n", "\t\t_ = runTests(m.tests)\n\t\treturn 0\n"},
		"fallthrough to runner after StopTestLog": {"\t\treturn 0\n", ""},
		"os.Exit(1) before StopTestLog":           {"_ = runTests(m.tests)", "if !runTests(m.tests) { os.Exit(1) }"},
		"missing Context method":                  {"func (c *common) Context() context.Context { c.checkFuzzFn(\"Context\"); return c.ctx }", ""},
		"flag pointer alias clobber":              {"flag.Parse()", "flag.Parse()\n\talias := testlog; *alias = \"\""},
		"flag pointer map key escape":             {"flag.Parse()", "flag.Parse()\n\t_ = map[any]int{testlog: 1}"},
		"flag.Set clobber":                        {"flag.Parse()", "flag.Parse()\n\t_ = flag.Set(\"test.testlogfile\", \"\")"},
		"flag.CommandLine.Set clobber":            {"flag.Parse()", "flag.Parse()\n\t_ = flag.CommandLine.Set(\"test.testlogfile\", \"\")"},
		"duplicate test.testlogfile flag":         {"var testlog = flag.String(\"test.testlogfile\", \"\", \"\")", "var testlog = flag.String(\"test.testlogfile\", \"\", \"\")\nvar testlog2 = flag.String(\"test.testlogfile\", \"\", \"\")"},
		"runTests mimicking runExample os.Exit":   {"\treturn true\n}", "\tif _, err := os.OpenFile(\"x\", 0, 0); err != nil {\n\t\tos.Exit(1)\n\t}\n\treturn true\n}"},
		"tRunner calling os.Exit(1)":              {"func runTests(", "func tRunner() { os.Exit(1) }\nfunc runTests("},
		"B.Loop calling os.Exit(1)":               {"func runTests(", "type B struct{}\nfunc (b *B) Loop() bool { os.Exit(1); return false }\nfunc runTests("},
		"B.loopSlow calling os.Exit(1)":           {"func runTests(", "type B struct{}\nfunc (b *B) loopSlow() bool { os.Exit(1); return false }\nfunc runTests("},
		"init calling os.Exit(1)":                 {"func MainStart(", "func init() { os.Exit(1) }\nfunc MainStart("},
		"extra &M{} outside MainStart":            {"func MainStart(", "func rogueM(d testDeps) *M { return &M{deps: d} }\nfunc MainStart("},
		"new(M) allocation":                       {"func MainStart(", "func allocM() *M { return new(M) }\nfunc MainStart("},
		"mutating *m inside M method":             {"flag.Parse()", "*m = M{}\n\tflag.Parse()"},
		"M receiver map key escape":               {"flag.Parse()", "_ = map[any]int{m: 1}\n\tflag.Parse()"},
		"indented //go:linkname bypass":           {"package testing\n", "package testing\nimport _ \"unsafe\"\n\t//go:linkname MainStart runtime.evilMainStart\n"},
		"CR-embedded //go:linkname bypass":        {"package testing\n", "package testing\nimport _ \"unsafe\"\n//go:linkname f runtime.f\r//go:linkname MainStart runtime.evil\nfunc f()\n"},
		"BOM-prefixed //go:linkname bypass":       {"package testing\n", "\uFEFF//go:linkname MainStart runtime.evilMainStart\npackage testing\nimport _ \"unsafe\"\n"},
		"block /*go:linkname*/ directive":         {"package testing\n", "package testing\n/*go:linkname MainStart runtime.evil*/\n"},
		"wasmexport directive in testing":         {"package testing\n", "package testing\n//go:wasmexport EvilExport\nfunc EvilExport() {}\n"},
	} {
		base := syntheticTestingInlineSrc
		if name == "fmt-only handler StopTestLog" {
			base = mustMutateFixture(t, base, "panic(err)", "fmt.Fprintf(os.Stderr, \"%v\\n\", err)")
		}
		if name == "unguarded flag StopTestLog" {
			base = mustMutateFixture(t, base, "if err := m.deps.StopTestLog(); err != nil {\n\t\t\tpanic(err)\n\t\t}", "if otherFlag { if err := m.deps.StopTestLog(); err != nil { os.Exit(2) } }")
		}
		src := mustMutateFixture(t, base, mut[0], mut[1])
		if err := verifyListedPackage(writePkg("testing", map[string]string{"testing.go": src})); err == nil {
			t.Fatalf("testing inline violation %q admitted", name)
		}
	}

	// Verify renamed file (bench.go instead of benchmark.go) cannot bypass (*common).Context verification.
	brokenContextBench := mustMutateFixture(t, syntheticTestingInlineSrc, "c.checkFuzzFn(\"Context\"); return c.ctx", "return context.Background()")
	if err := verifyListedPackage(writePkg("testing", map[string]string{"bench.go": brokenContextBench})); err == nil {
		t.Fatal("broken (*common).Context in renamed bench.go admitted")
	}

	// Split-mode M.Run / Init / before / after / afterOnce / writeProfiles / syscall exit negative cases.
	for name, mut := range map[string][2]string{
		"MainStart omitting Init()":                         {"\tInit()\n", ""},
		"flag.Parse after m.before()":                       {"\tif !flag.Parsed() {\n\t\tflag.Parse()\n\t}\n", ""},
		"pre-before zero return outside matchList":          {"if *matchList != \"\" {", "if m.numRun > 99 {"},
		"pre-before return 2 clobbered by defer":            {"m.exitCode = 0\n\t\treturn", "return"},
		"go runTests outliving defer m.after()":             {"if !runTests(m.tests) {", "go runTests(m.tests)\n\tif false {"},
		"unconditional err return in before":                {"if *cpuProfile != \"\" {", "if err := io.EOF; err != nil {\n\t\treturn\n\t}\n\tif *cpuProfile != \"\" {"},
		"shadowed local testlogFile := f":                   {"testlogFile = f", "testlogFile := f; _ = testlogFile"},
		"StopTestLog not first in writeProfiles":            {"func (m *M) writeProfiles() {\n", "func (m *M) writeProfiles() {\n\tif m.numRun < 0 { return }\n"},
		"burned m.afterOnce before after":                   {"m.before()", "m.afterOnce.Do(func() {})\n\tm.before()"},
		"exported After method":                             {"after()", "After()"},
		"direct call to m.after() outside alarm":            {"m.startAlarm()", "m.after()\n\tm.startAlarm()"},
		"os.Exit(2) in M.Run skipping defer after":          {"m.exitCode = 1\n\t\treturn", "os.Exit(2)"},
		"alarm FuncLit without panic":                       {"\t\tpanic(\"test timed out\")\n", ""},
		"syscall.Exit(0) bypass":                            {"\"time\"", "\"syscall\"\n\t\"time\""},
		"syscall.RawSyscall SYS_EXIT bypass":                {"m.numRun++", "m.numRun++"},
		"post-before helper calling os.Exit(1)":             {"m.startAlarm()", "helperExit()\n\tm.startAlarm()"},
		"post-before helper calling os.Exit via func value": {"m.startAlarm()", "fn := helperExit; fn()\n\tm.startAlarm()"},
		"after helper calling os.Exit(1)":                   {"m.writeProfiles()", "helperExit()\n\t\tm.writeProfiles()"},
		"testlogFile map key escape":                        {"testlogFile = f", "testlogFile = f\n\t\t_ = map[any]int{testlogFile: 1}"},
	} {
		base := syntheticTestingSplitSrc
		switch name {
		case "flag.Parse after m.before()":
			base = mustMutateFixture(t, base, "m.before()", "m.before()\n\tflag.Parse()")
		case "pre-before return 2 clobbered by defer":
			base = mustMutateFixture(t, base, "if *matchList != \"\" {", "if m.numRun < 0 {")
		case "syscall.Exit(0) bypass":
			base = mustMutateFixture(t, base, "m.startAlarm()", "syscall.Exit(0)\n\tm.startAlarm()")
		case "syscall.RawSyscall SYS_EXIT bypass":
			base = mustMutateFixture(t, base, "\"time\"", "\"syscall\"\n\t\"time\"")
			base = mustMutateFixture(t, base, "m.startAlarm()", "syscall.RawSyscall(syscall.SYS_EXIT, 0, 0, 0)\n\tm.startAlarm()")
		case "post-before helper calling os.Exit(1)", "post-before helper calling os.Exit via func value", "after helper calling os.Exit(1)":
			base += "\nfunc helperExit() { os.Exit(1) }\n"
		}
		src := mustMutateFixture(t, base, mut[0], mut[1])
		if err := verifyListedPackage(writePkg("testing", map[string]string{"testing.go": src})); err == nil {
			t.Fatalf("testing split violation %q admitted", name)
		}
	}

	validTestingPassthroughWrap := writePkg("testing", map[string]string{
		"testing.go": mustMutateFixture(t, syntheticTestingInlineSrc, "m.deps.StartTestLog(f)", "m.deps.StartTestLog(wrapLog(f))") +
			"\nfunc wrapLog(f *os.File) io.Writer { return f }\n",
	})
	if err := verifyListedPackage(validTestingPassthroughWrap); err != nil {
		t.Fatalf("valid pass-through StartTestLog wrapper refused: %v", err)
	}

	validTestingCustomWriter := writePkg("testing", map[string]string{
		"testing.go": mustMutateFixture(t, syntheticTestingInlineSrc, "m.deps.StartTestLog(f)", "m.deps.StartTestLog(wrapLog(f))") +
			"\nfunc wrapLog(f *os.File) io.Writer { return &customLogWriter{f: f, fd: int(f.Fd())} }\n",
		"writer.go": "package testing\nimport (\"os\"; \"syscall\"; \"unsafe\")\ntype customLogWriter struct { f *os.File; fd int }\nfunc (w *customLogWriter) Write(p []byte) (int, error) {\n\tif useDirect {\n\t\treturn w.writeDirect(p)\n\t}\n\treturn w.f.Write(p)\n}\nfunc (w *customLogWriter) writeDirect(p []byte) (int, error) {\n\tn, err := rawStreamWrite(w.fd, p)\n\tif err != nil {\n\t\terr = &os.PathError{Op: \"write\", Path: w.f.Name(), Err: err}\n\t}\n\treturn n, err\n}\nfunc rawStreamWrite(fd int, payload []byte) (written int, err error) {\n\twriteAll := func(b []byte) error {\n\t\tfor len(b) > 0 {\n\t\t\tr1, _, errno := syscall.RawSyscall(syscall.SYS_WRITE, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))\n\t\t\tif errno == syscall.EINTR || errno == syscall.EAGAIN {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tif errno != 0 {\n\t\t\t\treturn errno\n\t\t\t}\n\t\t\tb = b[int(r1):]\n\t\t}\n\t\treturn nil\n\t}\n\tfor {\n\t\tchunkErr := writeAll(payload)\n\t\tif chunkErr == nil && err == nil {\n\t\t\twritten += len(payload)\n\t\t} else if chunkErr != nil && err == nil {\n\t\t\terr = chunkErr\n\t\t}\n\t\tpayload = payload[len(payload):]\n\t\tif len(payload) == 0 {\n\t\t\treturn written, err\n\t\t}\n\t}\n}\n",
	})
	if err := verifyListedPackage(validTestingCustomWriter); err != nil {
		t.Fatalf("valid custom StartTestLog writer refused: %v", err)
	}

	makeTestingWithWrap := func(extraImports, extraDecls, startExpr string) map[string]string {
		src := syntheticTestingInlineSrc
		if extraImports != "" {
			src = mustMutateFixture(t, src, "import (\n", "import (\n"+extraImports)
		}
		src = mustMutateFixture(t, src, "m.deps.StartTestLog(f)", startExpr)
		return map[string]string{"testing.go": src + "\n" + extraDecls + "\n"}
	}
	for name, files := range map[string]map[string]string{
		"nil StartTestLog": {
			"testing.go": mustMutateFixture(t, syntheticTestingInlineSrc, "m.deps.StartTestLog(f)", "_ = f; m.deps.StartTestLog(nil)"),
		},
		"io.Discard StartTestLog": {
			"testing.go": mustMutateFixture(t, syntheticTestingInlineSrc, "m.deps.StartTestLog(f)", "_ = f; m.deps.StartTestLog(io.Discard)"),
		},
		"parameter StartTestLog without os.Create": {
			"testing.go": mustMutateFixture(t,
				mustMutateFixture(t, syntheticTestingInlineSrc, "f, err := os.Create(*testlog)\n\t\tif err != nil {\n\t\t\tos.Exit(2)\n\t\t}", ""),
				"type M struct {", "var f *os.File\ntype M struct {"),
		},
		"uninitialized local *os.File StartTestLog": {
			"testing.go": mustMutateFixture(t, syntheticTestingInlineSrc, "f, err := os.Create(*testlog)\n\t\tif err != nil {\n\t\t\tos.Exit(2)\n\t\t}", "var f *os.File"),
		},
		"bytes.Buffer StartTestLog": {
			"testing.go": mustMutateFixture(t,
				mustMutateFixture(t, syntheticTestingInlineSrc, "import (\n", "import (\n\t\"bytes\"\n"),
				"m.deps.StartTestLog(f)", "_ = f; buf := new(bytes.Buffer); m.deps.StartTestLog(buf)"),
		},
		"read-only os.Open StartTestLog": {
			"testing.go": mustMutateFixture(t, syntheticTestingInlineSrc, "os.Create(*testlog)", "os.Open(*testlog)"),
		},
		"O_CREATE without O_WRONLY/O_RDWR StartTestLog": {
			"testing.go": mustMutateFixture(t, syntheticTestingInlineSrc, "os.Create(*testlog)", "os.OpenFile(*testlog, os.O_CREATE, 0o644)"),
		},
		"unchecked os.Create error StartTestLog": {
			"testing.go": mustMutateFixture(t, syntheticTestingInlineSrc, "f, err := os.Create(*testlog)\n\t\tif err != nil {\n\t\t\tos.Exit(2)\n\t\t}", "f, _ := os.Create(*testlog)"),
		},
		"missing wrapper function": makeTestingWithWrap("", "", "m.deps.StartTestLog(missingWrap(f))"),
		"wrapper ignoring file parameter": makeTestingWithWrap("",
			"type sinkWriter struct{ other *os.File }\nfunc (w *sinkWriter) Write(p []byte) (int, error) { return w.other.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &sinkWriter{} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"composite binding one field but writing unbound field": makeTestingWithWrap("",
			"type sinkWriter struct{ f, other *os.File }\nfunc (w *sinkWriter) Write(p []byte) (int, error) { return w.other.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &sinkWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"post-init bound field mutation": makeTestingWithWrap("",
			"type sinkWriter struct{ f *os.File }\nfunc (w *sinkWriter) Write(p []byte) (int, error) { return w.f.Write(p) }\nfunc (w *sinkWriter) Reset() { w.f = nil }\nfunc wrapLog(f *os.File) io.Writer { return &sinkWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"writer swallowing error": makeTestingWithWrap("",
			"type badWriter struct{ f *os.File }\nfunc (w *badWriter) Write(p []byte) (int, error) { _, _ = w.f.Write(p); return len(p), nil }\nfunc wrapLog(f *os.File) io.Writer { return &badWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"writer swallowing error on if err != nil branch": makeTestingWithWrap("",
			"type badBranchWriter struct{ f *os.File }\nfunc (w *badBranchWriter) Write(p []byte) (int, error) { n, err := w.f.Write(p); if err != nil { return len(p), nil }; return n, err }\nfunc wrapLog(f *os.File) io.Writer { return &badBranchWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"1-result helper swallowing error on if err != nil branch": makeTestingWithWrap("",
			"type badHelperWriter struct{ f *os.File }\nfunc writeHelper(f *os.File, p []byte) error { _, err := f.Write(p); if err != nil { return nil }; return err }\nfunc (w *badHelperWriter) Write(p []byte) (int, error) { if err := writeHelper(w.f, p); err != nil { return 0, err }; return len(p), nil }\nfunc wrapLog(f *os.File) io.Writer { return &badHelperWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"writer overwriting err via non-sink call": makeTestingWithWrap("",
			"func clearErr() (int, error) { return 0, nil }\ntype overwriteWriter struct{ f *os.File }\nfunc (w *overwriteWriter) Write(p []byte) (int, error) { n, err := w.f.Write(p); n, err = clearErr(); return n, err }\nfunc wrapLog(f *os.File) io.Writer { return &overwriteWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"writer overwriting err via nil variable": makeTestingWithWrap("",
			"var noErr error\ntype overwriteVarWriter struct{ f *os.File }\nfunc (w *overwriteVarWriter) Write(p []byte) (int, error) { n, err := w.f.Write(p); err = noErr; return n, err }\nfunc wrapLog(f *os.File) io.Writer { return &overwriteVarWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"writer clearing named err in defer": makeTestingWithWrap("",
			"type deferClearWriter struct{ f *os.File }\nfunc (w *deferClearWriter) Write(p []byte) (n int, err error) { defer func() { err = nil }(); n, err = w.f.Write(p); return n, err }\nfunc wrapLog(f *os.File) io.Writer { return &deferClearWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"monotonic latch with tautological first arm": makeTestingWithWrap("",
			"type badLatchWriter struct{ f *os.File }\nfunc (w *badLatchWriter) Write(p []byte) (written int, err error) { for { _, chunkErr := w.f.Write(p); if true { written += len(p) } else if chunkErr != nil && err == nil { err = chunkErr }; return written, err } }\nfunc wrapLog(f *os.File) io.Writer { return &badLatchWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"writer discarding RawSyscall errno": makeTestingWithWrap("\t\"syscall\"\n",
			"type badRawWriter struct{ f *os.File; fd int }\nfunc (w *badRawWriter) Write(p []byte) (int, error) { _, _, _ = syscall.RawSyscall(syscall.SYS_WRITE, uintptr(w.fd), 0, uintptr(len(p))); return 0, nil }\nfunc wrapLog(f *os.File) io.Writer { return &badRawWriter{f: f, fd: 1} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"writer tainting err with nil": makeTestingWithWrap("",
			"type taintedWriter struct{ f *os.File }\nfunc (w *taintedWriter) Write(p []byte) (int, error) { n, err := w.f.Write(p); err = nil; return n, err }\nfunc wrapLog(f *os.File) io.Writer { return &taintedWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"writer skipping sink via early return nil": makeTestingWithWrap("",
			"var skipLog bool\ntype skipWriter struct{ f *os.File }\nfunc (w *skipWriter) Write(p []byte) (int, error) { if skipLog { return len(p), nil }; return w.f.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &skipWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"vacuous writer returning 0 nil": makeTestingWithWrap("",
			"type vacuousWriter struct{ f *os.File }\nfunc (w *vacuousWriter) Write(p []byte) (int, error) { return 0, nil }\nfunc wrapLog(f *os.File) io.Writer { return &vacuousWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
		"recursive writer": makeTestingWithWrap("",
			"type recWriter struct{ f *os.File }\nfunc (w *recWriter) Write(p []byte) (int, error) { return w.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &recWriter{f: f} }",
			"m.deps.StartTestLog(wrapLog(f))"),
	} {
		if err := verifyListedPackage(writePkg("testing", files)); err == nil {
			t.Fatalf("invalid testing StartTestLog case %s admitted", name)
		}
	}

	// Closed support-import selector allowlists and assembly header/directive/symbol checks.
	for name, pkg := range map[string]listedPackage{
		"fips140only drbg.Read": writePkg("crypto/internal/fips140only", map[string]string{
			"fips.go": "package fips140only\nimport \"crypto/internal/fips140/drbg\"\nfunc f(b []byte) { drbg.Read(b) }\n",
		}),
		"math.Sin": writePkg("strings", map[string]string{
			"strings.go": "package strings\nimport \"math\"\nvar _ = math.Sin(1)\n",
		}),
		"reflect.MakeFunc": writePkg("strings", map[string]string{
			"strings.go": "package strings\nimport \"reflect\"\nvar _ = reflect.MakeFunc\n",
		}),
		"reflect Value.Call": writePkg("strings", map[string]string{
			"strings.go": "package strings\nimport \"reflect\"\nfunc f(v reflect.Value) { v.Call(nil) }\n",
		}),
		"exported sync.Map global": writePkg("strings", map[string]string{
			"strings.go": "package strings\nimport \"sync\"\nvar GlobalRegistry sync.Map\n",
		}),
		"atomic.Value": writePkg("strings", map[string]string{
			"strings.go": "package strings\nimport \"sync/atomic\"\nvar v atomic.Value\n",
		}),
		"sha256 unapproved godebug": writePkg("crypto/internal/fips140/sha256", map[string]string{
			"sha256.go": "package sha256\nimport \"crypto/internal/fips140deps/godebug\"\nvar _ = godebug.Value(\"http2client\")\n",
		}),
		"asm header #define SYSCALL": writePkg("internal/bytealg", map[string]string{
			"bytealg.go": "package bytealg\nfunc f()\n",
			"defs.h":     "#define DO_TRAP SYSCALL\n",
			"asm.s":      "#include \"defs.h\"\nTEXT ·f(SB),$0-0\n\tDO_TRAP\n\tRET\n",
		}),
		"asm char quote before SYSCALL": writePkg("internal/bytealg", map[string]string{
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tMOVB $'\"', AX; SYSCALL; MOVB $'\"', BX\n\tRET\n",
		}),
		"asm system #include": writePkg("internal/bytealg", map[string]string{
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#include <stdlib.h>\nTEXT ·f(SB),$0-0\n\tRET\n",
		}),
		"asm parent path #include": writePkg("internal/bytealg", map[string]string{
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#include \"../secret.h\"\nTEXT ·f(SB),$0-0\n\tRET\n",
		}),
		"asm unapproved cross-package call": writePkg("internal/bytealg", map[string]string{
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tCALL syscall·Syscall(SB)\n\tRET\n",
		}),
	} {
		if err := verifyListedPurePackage(pkg); err == nil {
			t.Fatalf("pure/delegate violation %s admitted", name)
		}
	}

	cctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := verifyToolchainSurfaceContext(cctx, seedPreverifiedSurface(validPure)); err == nil {
		t.Fatal("verifyToolchainSurfaceContext ignored cancelled context")
	}

	if got := namedMoved([]string{"a", "b"}); got != "a, b" {
		t.Fatalf("namedMoved = %q", got)
	}

	// A package whose on-disk bytes drift from lp.digest during verification
	// reports a read degradation rather than "moved in N keys" and never caches
	// the stale verdict under lp.digest (both pure and non-pure verifier paths).
	for _, tc := range []struct {
		importPath string
		file       string
		origSrc    string
		driftedSrc string
	}{
		{
			importPath: "strings",
			file:       "strings.go",
			origSrc:    "package strings\nfunc Clone(s string) string { return s }\n",
			driftedSrc: "package strings\nimport \"os\"\nvar _ = os.Getenv(\"X\")\n",
		},
		{
			importPath: "internal/testlog",
			file:       "testlog.go",
			origSrc:    "package testlog\n",
			driftedSrc: "package testlog\nvar _ = 1\n",
		},
	} {
		toctouPkg := writePkg(tc.importPath, map[string]string{
			tc.file: tc.origSrc,
		})
		origDigest, err := digestFiles(t.Context(), toctouPkg.Dir, toctouPkg.Files)
		if err != nil {
			t.Fatal(err)
		}
		toctouPkg.digest = origDigest
		if err := os.WriteFile(filepath.Join(toctouPkg.Dir, tc.file), []byte(tc.driftedSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		toctouSurface := sourceDigests{
			Packages:  map[string]string{tc.importPath: origDigest},
			inventory: map[string]listedPackage{tc.importPath: toctouPkg},
		}
		deg := toolchainSourceDegradation("go1.test", toctouSurface, nil)
		if deg.audited() || !strings.Contains(deg.axis, "could not be read") {
			t.Fatalf("%s TOCTOU degradation = %+v, want could not be read", tc.importPath, deg)
		}
		if _, cached := verifiedPackageMemo.Load(verifiedPackageMemoKey(tc.importPath, origDigest)); cached {
			t.Fatalf("%s TOCTOU verification failure poisoned verifiedPackageMemo", tc.importPath)
		}
	}
}

func FuzzClosureCoverageAndMutableLocalIdentity(f *testing.F) {
	f.Add("pkg/a", "v1.2.3", "func F() int { return 1 }", "// normal comment", true, false)
	f.Add("pkg/b", "v0.1.0", "func G() string { return \"x\" }", "//go:noinline", false, true)
	f.Add("pkg/c", "v2.0.0", "var X = 42", "// Code generated by tool; DO NOT EDIT.", false, false)

	f.Fuzz(func(t *testing.T, subPkg, ver, decl, comment string, inModCache, isMain bool) {
		cleanSub := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}
			return 'a'
		}, subPkg)
		if cleanSub == "" {
			cleanSub = "p"
		}
		cleanVer := "v1.0.0"
		if strings.HasPrefix(ver, "v") && len(ver) < 16 && !strings.ContainsAny(ver, "/\\ \t\n") {
			cleanVer = ver
		}

		// 1. Canonical member digest & strategy coupling (REQ-closure-identity-strategy).
		if !strings.Contains(IdentityStrategy, canonicalStrategy) || !strings.Contains(IdentityStrategy, variantParseStrategy) {
			t.Fatalf("IdentityStrategy %q does not compose %q and %q", IdentityStrategy, canonicalStrategy, variantParseStrategy)
		}
		srcBase := "package p\n\n" + decl + "\n"
		d1, ok1 := canonicalDigest([]byte(srcBase))
		if ok1 {
			// Non-retained comment and whitespace changes leave the canonical digest invariant,
			// whereas directive or generated-marker comments move it when retained.
			withSpace := "package p\n\n\t\n" + decl + "\n"
			if d2, ok2 := canonicalDigest([]byte(withSpace)); !ok2 || d1 != d2 {
				t.Fatalf("whitespace moved canonical digest: %q vs %q", d1, d2)
			}
			singleLine := strings.ReplaceAll(strings.ReplaceAll(comment, "\n", " "), "\r", " ")
			if !strings.HasPrefix(singleLine, "//") {
				singleLine = "// " + singleLine
			}
			withComment := "package p\n" + singleLine + "\n" + decl + "\n"
			dComment, okC := canonicalDigest([]byte(withComment))
			if okC {
				if !retainedComment(singleLine) && dComment != d1 {
					t.Fatalf("non-retained comment %q moved canonical digest", singleLine)
				}
				if retainedComment(singleLine) && dComment == d1 {
					t.Fatalf("retained directive/generated comment %q did not move canonical digest", singleLine)
				}
			}
			withDirective := "package p\n//go:noinline\n" + decl + "\n"
			if dDir, okDir := canonicalDigest([]byte(withDirective)); !okDir || dDir == d1 {
				t.Fatalf("retained //go:noinline directive did not move canonical digest: %q", dDir)
			}
		}

		// 2. Blindspot resolved vs downgraded linkname floor (REQ-closure-blindspot).
		auditedLinkSrc := "package p\n//go:linkname a runtime.getAuxv\n"
		unauditedLinkSrc := "package p\n//go:linkname a runtime.unapproved\n"
		if scanAud, err := maximalFileEffectsContent(true, "link.go", []byte(auditedLinkSrc)); err != nil || len(scanAud.effects) != 0 {
			t.Fatalf("audited linkname target did not drop opaque-linkage floor: %+v, err=%v", scanAud.effects, err)
		}
		if scanDowngraded, err := maximalFileEffectsContent(false, "link.go", []byte(auditedLinkSrc)); err != nil || !strings.Contains(scanDowngraded.preferred, "go:linkname") {
			t.Fatalf("downgraded toolchain did not restore opaque-linkage floor on audited linkname: %+v, err=%v", scanDowngraded, err)
		}
		if scanUnaud, err := maximalFileEffectsContent(true, "link.go", []byte(unauditedLinkSrc)); err != nil || !strings.Contains(scanUnaud.preferred, "go:linkname") {
			t.Fatalf("unaudited linkname target did not keep opaque-linkage floor: %+v, err=%v", scanUnaud, err)
		}

		// 3. Coverage, mutable-local vs module-cache classification, test-variant compartment,
		// and per-subject vs view-wide source files (REQ-closure-coverage, REQ-closure-mutable-local,
		// REQ-closure-view-maximal).
		root := t.TempDir()
		modCache := filepath.Join(root, "modcache")
		workDir := filepath.Join(root, "work")
		pkgDir := filepath.Join(workDir, cleanSub)
		modDir := workDir
		if inModCache {
			modDir = filepath.Join(modCache, "example.com", "dep@"+cleanVer)
			pkgDir = filepath.Join(modDir, cleanSub)
		}
		if err := os.MkdirAll(pkgDir, 0o755); err != nil {
			t.Fatal(err)
		}
		goFile := "member.go"
		testFile := "member_test.go"
		embedFile := "data.txt"
		if err := os.WriteFile(filepath.Join(pkgDir, goFile), []byte("package p\nfunc M() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, testFile), []byte("package p\nimport \"testing\"\nfunc TestM(t *testing.T) {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, embedFile), []byte("payload\n"), 0o644); err != nil {
			t.Fatal(err)
		}

		h := &Hasher{
			ctx:      context.Background(),
			modCache: modCache,
			contribs: map[string]depContribution{},
			contents: map[string]fileBytes{},
		}
		lp := listPkg{
			ImportPath: "example.com/dep/" + cleanSub,
			Dir:        pkgDir,
			GoFiles:    []string{goFile},
			EmbedFiles: []string{embedFile},
			Module: &listMod{
				Path:    "example.com/dep",
				Version: cleanVer,
				Dir:     modDir,
				Main:    isMain,
			},
		}
		compiled, embedded, canonical := memberKinds(lp)
		if !compiled[goFile] || !canonical[goFile] || !embedded[embedFile] || canonical[embedFile] {
			t.Fatalf("memberKinds misclassified compiled/embedded/canonical: %v %v %v", compiled, embedded, canonical)
		}
		emptyComp, err := compartment.ComputeIdentity(pkgDir, nil, nil, nil, nil, h, nil)
		if err != nil || emptyComp.Hash == "" {
			t.Fatalf("empty compartment.ComputeIdentity = (%+v, %v)", emptyComp, err)
		}
		compId, err := compartment.ComputeIdentity(pkgDir, []string{testFile}, map[string]bool{testFile: true}, nil, map[string]string{}, h, nil)
		if err != nil || compId.Hash == "" || compId.Hash == emptyComp.Hash || !slices.Equal(compId.Files, []string{testFile}) {
			t.Fatalf("compartment.ComputeIdentity = (%+v, %v), want non-empty test-variant hash over [%s]", compId, err, testFile)
		}

		isPinned := h.pinnedPackage(&lp)
		wantPinned := inModCache && !isMain
		if isPinned != wantPinned {
			t.Fatalf("pinnedPackage = %v, want %v (inModCache=%v, isMain=%v)", isPinned, wantPinned, inModCache, isMain)
		}

		contrib1, files1, err := h.contributionAndFilesFor("example.com/subj", lp)
		if err != nil {
			t.Fatalf("contributionAndFilesFor: %v", err)
		}
		if isPinned {
			if !strings.HasPrefix(contrib1, "cache:") || len(files1) != 0 {
				t.Fatalf("pinned package contribution = %q (files=%v), want cache: prefix and no source files", contrib1, files1)
			}
		} else {
			if !strings.HasPrefix(contrib1, "src:") || len(files1) != 2 {
				t.Fatalf("mutable-local package contribution = %q (files=%v), want src: prefix and 2 source files", contrib1, files1)
			}
			// Editing the test-only compartment file leaves the core contribution hash unchanged,
			// while moving the test-variant compartment hash.
			if err := os.WriteFile(filepath.Join(pkgDir, testFile), []byte("package p\nimport \"testing\"\nfunc TestM(t *testing.T) { t.Log(1) }\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			h.resetCallScope()
			contribAfterTestEdit, _, err := h.contributionAndFilesFor("example.com/subj", lp)
			if err != nil || contribAfterTestEdit != contrib1 {
				t.Fatalf("test-variant edit moved core contribution: %q vs %q (err=%v)", contribAfterTestEdit, contrib1, err)
			}
			compId2, err := compartment.ComputeIdentity(pkgDir, []string{testFile}, map[string]bool{testFile: true}, nil, map[string]string{}, h, nil)
			if err != nil || compId2.Hash == compId.Hash {
				t.Fatalf("test-variant edit did not move compartment hash: %q", compId.Hash)
			}

			// Silent edit in mutable-local core source file moves its contribution hash.
			h.resetCallScope()
			if err := os.WriteFile(filepath.Join(pkgDir, goFile), []byte("package p\nfunc M() { println(1) }\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			contrib2, _, err := h.contributionAndFilesFor("example.com/subj", lp)
			if err != nil {
				t.Fatal(err)
			}
			if contrib2 == contrib1 {
				t.Fatalf("editing mutable-local source file did not move contribution: %q", contrib1)
			}
		}

		// Standard library and generated testmain packages are excluded from non-stdlib fold.
		stdPkg := lp
		stdPkg.Standard = true
		if c, _, err := h.contributionAndFilesFor("example.com/subj", stdPkg); err != nil || c != "" {
			t.Fatalf("stdlib package was not excluded: %q, %v", c, err)
		}
	})
}

func FuzzToolchainKeyObligations(f *testing.F) {
	f.Add("strings", "package strings\nfunc Clone(s string) string { return s }\n", "strings.go", true)
	f.Add("bytes", "package bytes\nfunc Equal(a, b []byte) bool { return true }\n", "bytes.go", false)
	f.Add("0", "package strings\n0", "0", true)

	basePackages := map[string]string{}
	baseInventory := map[string]listedPackage{}
	for _, root := range auditedSurfaceTables() {
		first, _, _ := strings.Cut(root, "/")
		if strings.Contains(first, ".") {
			continue
		}
		d := "preverified-" + root
		basePackages[root] = d
		baseInventory[root] = listedPackage{ImportPath: root, Audited: true, digest: d}
		verifiedPackageMemo.Store(verifiedPackageMemoKey(root, d), verifiedPackageVerdict{OK: true})
	}

	f.Fuzz(func(t *testing.T, pkgChoice, body, extraName string, cancelCtx bool) {
		pkgName := "strings"
		if pkgChoice == "bytes" {
			pkgName = "bytes"
		}
		cleanExtra := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}
			return 'x'
		}, extraName)
		if cleanExtra == "" {
			cleanExtra = "extra"
		}
		dir := t.TempDir()
		mainFile := pkgName + ".go"
		src := "package " + pkgName + "\nfunc Helper() {}\n"
		if strings.HasPrefix(body, "package "+pkgName+"\n") {
			_, parseErr := parser.ParseFile(token.NewFileSet(), mainFile, body+"\nvar _ = 1\n", 0)
			dirErr := verifyFileLinknameDirectives(pkgName, body+"\nvar _ = 1\n")
			if parseErr == nil && dirErr == nil && !strings.Contains(body, "import") && !strings.Contains(body, "//") {
				src = body
			} else if parseErr != nil || dirErr != nil {
				badDir := filepath.Join(dir, "malformed")
				if err := os.MkdirAll(badDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(badDir, mainFile), []byte(body+"\nvar _ = 1\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := verifyListedPackage(listedPackage{ImportPath: pkgName, Dir: badDir, Files: []string{mainFile}, Audited: true}); err == nil {
					t.Fatalf("malformed or directive-violating %s source admitted", pkgName)
				}
			}
		}
		if err := os.WriteFile(filepath.Join(dir, mainFile), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}

		// 1. Selected inventory & content identity (REQ-closure-observability-toolchain-key:
		// content-identity, selected-inventory).
		lp := listPkg{
			ImportPath: pkgName,
			Standard:   true,
			Dir:        dir,
			GoFiles:    []string{mainFile, mainFile},
			SFiles:     []string{"asm.s"},
		}
		if err := os.WriteFile(filepath.Join(dir, "asm.s"), []byte("TEXT ·f(SB),0,$0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		sel := selectedFiles(lp)
		if !slices.Equal(sel, []string{"asm.s", mainFile}) {
			t.Fatalf("selectedFiles = %v, want sorted non-test [asm.s %s]", sel, mainFile)
		}

		ctx := context.Background()
		if cancelCtx {
			cctx, cancel := context.WithCancel(ctx)
			cancel()
			if _, err := digestFiles(cctx, dir, sel); err == nil {
				t.Fatal("digestFiles ignored cancelled context")
			}
		}

		d1, err := digestFiles(ctx, dir, sel)
		if err != nil {
			t.Fatalf("digestFiles: %v", err)
		}

		// 2. Effective selection scope, inventory memo stamps, and semantic authority
		// (REQ-closure-observability-toolchain-key: effective-selection, inventory-memo,
		// semantic-authority).
		scopeNoFlags := toolchainSourceScope(nil, nil, surfaceSeeds())
		scopeWithFlag := toolchainSourceScope(nil, []string{"-tags=" + cleanExtra}, surfaceSeeds())
		if scopeNoFlags == scopeWithFlag {
			t.Fatalf("build flag did not key toolchainSourceScope: %q", scopeNoFlags)
		}
		stamps, err := stampDirs(dir, sel)
		if err != nil {
			t.Fatalf("stampDirs: %v", err)
		}
		listingRec := surfaceListing{
			Version: sourceDigestsVersion,
			Packages: []listedPackage{
				{ImportPath: pkgName, Dir: dir, Files: sel, Audited: true},
				{ImportPath: "archive/tar", Dir: dir, Files: sel, Audited: false},
			},
			Discovery: stamps,
		}
		if !stampsCurrent(listingRec) || !cacheableDiscovery(listingRec) {
			t.Fatal("unchanged directory stamps reported stale or uncacheable")
		}
		if listingIntegrity(scopeNoFlags, listingRec) == listingIntegrity(scopeWithFlag, listingRec) {
			t.Fatal("listingIntegrity did not commit to scope")
		}
		extraPath := filepath.Join(dir, "added_"+cleanExtra+".go")
		if err := os.WriteFile(extraPath, []byte("package "+pkgName+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if stampsCurrent(listingRec) {
			t.Fatal("added directory entry did not invalidate stampsCurrent")
		}
		if err := os.Remove(extraPath); err != nil {
			t.Fatal(err)
		}
		if !stampsCurrent(listingRec) {
			t.Fatal("removing added file did not restore stampsCurrent")
		}
		memoA, okA := sourceDigestsFromMemo(listingRec, map[string]string{pkgName: d1, "archive/tar": "tar-v1"})
		memoB, okB := sourceDigestsFromMemo(listingRec, map[string]string{pkgName: d1, "archive/tar": "tar-v2"})
		if !okA || !okB || memoA.Content == memoB.Content || !reflect.DeepEqual(memoA.Packages, memoB.Packages) {
			t.Fatalf("unaudited stdlib drift did not move Content while preserving audited Packages: %+v vs %+v", memoA, memoB)
		}

		// Editing selected file moves content digest.
		if err := os.WriteFile(filepath.Join(dir, mainFile), []byte(src+"\nvar _ = 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		d2, err := digestFiles(ctx, dir, sel)
		if err != nil {
			t.Fatalf("digestFiles after edit: %v", err)
		}
		if d1 == d2 {
			t.Fatal("selected file edit did not move digestFiles")
		}

		// 3. Transitive implementation dependencies, observation premises, & claim rechecking on drift
		// (REQ-closure-observability-toolchain-key: semantic-authority, selected-inventory,
		// implementation-dependencies, observation-premises, claim-rechecking).
		stdList := []listPkg{
			{
				ImportPath: pkgName,
				Standard:   true,
				Dir:        dir,
				GoFiles:    []string{mainFile},
				Deps:       []string{"internal/bytealg"},
			},
			{
				ImportPath: "internal/bytealg",
				Standard:   true,
				Dir:        dir,
				GoFiles:    []string{mainFile},
			},
			{
				ImportPath: "runtime/race",
				Standard:   true,
				Dir:        dir,
				GoFiles:    []string{mainFile},
			},
		}
		aud := auditedSurface(stdList)
		if !slices.Contains(aud, pkgName) || !slices.Contains(aud, "internal/bytealg") || !slices.Contains(aud, "runtime/race") {
			t.Fatalf("auditedSurface did not close over transitive dependency and implicit link package: %v", aud)
		}

		// Exercise observation-premises and bufio writer verification directly
		// (internal/testlog, bufio, os, testing, testing/internal/testdeps) without
		// pre-verified memo short-circuiting.
		testlogDir := filepath.Join(dir, "testlog")
		bufioDir := filepath.Join(dir, "bufio")
		osDir := filepath.Join(dir, "os")
		testingDir := filepath.Join(dir, "testing")
		testdepsDir := filepath.Join(dir, "testdeps")
		for _, sub := range []string{testlogDir, bufioDir, osDir, testingDir, testdepsDir} {
			if err := os.MkdirAll(sub, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		osSrc := syntheticOSSrc
		if err := os.WriteFile(filepath.Join(testlogDir, "testlog.go"), []byte(syntheticInternalTestlogSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bufioDir, "bufio.go"), []byte(syntheticBufioSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(osDir, "os.go"), []byte(osSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(testingDir, "testing.go"), []byte(syntheticTestingInlineSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(testdepsDir, "testdeps.go"), []byte(syntheticTestdepsSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		testlogDigest, err := digestFiles(ctx, testlogDir, []string{"testlog.go"})
		if err != nil {
			t.Fatal(err)
		}
		bufioDigest, err := digestFiles(ctx, bufioDir, []string{"bufio.go"})
		if err != nil {
			t.Fatal(err)
		}
		osDigest, err := digestFiles(ctx, osDir, []string{"os.go"})
		if err != nil {
			t.Fatal(err)
		}
		testingDigest, err := digestFiles(ctx, testingDir, []string{"testing.go"})
		if err != nil {
			t.Fatal(err)
		}
		testdepsDigest, err := digestFiles(ctx, testdepsDir, []string{"testdeps.go"})
		if err != nil {
			t.Fatal(err)
		}
		verifiedPackageMemo.Delete(verifiedPackageMemoKey("internal/testlog", testlogDigest))
		verifiedPackageMemo.Delete(verifiedPackageMemoKey("bufio", bufioDigest))
		verifiedPackageMemo.Delete(verifiedPackageMemoKey("os", osDigest))
		verifiedPackageMemo.Delete(verifiedPackageMemoKey("testing", testingDigest))
		verifiedPackageMemo.Delete(verifiedPackageMemoKey("testing/internal/testdeps", testdepsDigest))

		pkgs := make(map[string]string, len(basePackages))
		inv := make(map[string]listedPackage, len(baseInventory))
		for k, v := range basePackages {
			pkgs[k] = v
		}
		for k, v := range baseInventory {
			inv[k] = v
		}
		// Intact surface (including live-verified internal/testlog, bufio, os, testing, and testing/internal/testdeps) passes verification.
		pkgs[pkgName] = d2
		inv[pkgName] = listedPackage{ImportPath: pkgName, Dir: dir, Files: sel, Audited: true, digest: d2}
		t.Cleanup(func() {
			verifiedPackageMemo.Delete(verifiedPackageMemoKey(pkgName, d2))
		})
		pkgs["internal/testlog"] = testlogDigest
		inv["internal/testlog"] = listedPackage{ImportPath: "internal/testlog", Dir: testlogDir, Files: []string{"testlog.go"}, Audited: true, digest: testlogDigest}
		pkgs["bufio"] = bufioDigest
		inv["bufio"] = listedPackage{ImportPath: "bufio", Dir: bufioDir, Files: []string{"bufio.go"}, Audited: true, digest: bufioDigest}
		pkgs["os"] = osDigest
		inv["os"] = listedPackage{ImportPath: "os", Dir: osDir, Files: []string{"os.go"}, Audited: true, digest: osDigest}
		pkgs["testing"] = testingDigest
		inv["testing"] = listedPackage{ImportPath: "testing", Dir: testingDir, Files: []string{"testing.go"}, Audited: true, digest: testingDigest}
		pkgs["testing/internal/testdeps"] = testdepsDigest
		inv["testing/internal/testdeps"] = listedPackage{ImportPath: "testing/internal/testdeps", Dir: testdepsDir, Files: []string{"testdeps.go"}, Audited: true, digest: testdepsDigest}
		intactSD := sourceDigests{Packages: pkgs, inventory: inv, Policy: admissionPolicy()}
		if deg := toolchainSourceDegradation("go1.test", intactSD, nil); !deg.audited() {
			t.Fatalf("intact audited surface degraded: %+v", deg)
		}
		// Breaking (*common).Context in testing triggers degradation.
		brokenTestingSrc := mustMutateFixture(t, syntheticTestingInlineSrc, "c.checkFuzzFn(\"Context\"); return c.ctx", "return context.Background()")
		if err := os.WriteFile(filepath.Join(testingDir, "testing.go"), []byte(brokenTestingSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		brokenTestingDigest, err := digestFiles(ctx, testingDir, []string{"testing.go"})
		if err != nil {
			t.Fatal(err)
		}
		verifiedPackageMemo.Delete(verifiedPackageMemoKey("testing", brokenTestingDigest))
		pkgs["testing"] = brokenTestingDigest
		inv["testing"] = listedPackage{ImportPath: "testing", Dir: testingDir, Files: []string{"testing.go"}, Audited: true, digest: brokenTestingDigest}
		brokenTestingSD := sourceDigests{Packages: pkgs, inventory: inv, Policy: admissionPolicy()}
		if deg := toolchainSourceDegradation("go1.test", brokenTestingSD, nil); deg.audited() || !strings.Contains(deg.axis, "testing") {
			t.Fatalf("broken (*common).Context in testing did not trigger degradation: %+v", deg)
		}
		if err := os.WriteFile(filepath.Join(testingDir, "testing.go"), []byte(syntheticTestingInlineSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		pkgs["testing"] = testingDigest
		inv["testing"] = listedPackage{ImportPath: "testing", Dir: testingDir, Files: []string{"testing.go"}, Audited: true, digest: testingDigest}

		// Breaking a harness observation premise in testing/internal/testdeps triggers degradation.
		brokenTestdepsSrc := mustMutateFixture(t, syntheticTestdepsSrc, "err := log.w.Flush()\n\tlog.w = nil\n\treturn err", "log.w = nil\n\treturn nil")
		if err := os.WriteFile(filepath.Join(testdepsDir, "testdeps.go"), []byte(brokenTestdepsSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		brokenTestdepsDigest, err := digestFiles(ctx, testdepsDir, []string{"testdeps.go"})
		if err != nil {
			t.Fatal(err)
		}
		verifiedPackageMemo.Delete(verifiedPackageMemoKey("testing/internal/testdeps", brokenTestdepsDigest))
		pkgs["testing/internal/testdeps"] = brokenTestdepsDigest
		inv["testing/internal/testdeps"] = listedPackage{ImportPath: "testing/internal/testdeps", Dir: testdepsDir, Files: []string{"testdeps.go"}, Audited: true, digest: brokenTestdepsDigest}
		brokenPremiseSD := sourceDigests{Packages: pkgs, inventory: inv, Policy: admissionPolicy()}
		if deg := toolchainSourceDegradation("go1.test", brokenPremiseSD, nil); deg.audited() || !strings.Contains(deg.axis, "testing/internal/testdeps") {
			t.Fatalf("broken observation premise in testing/internal/testdeps did not trigger degradation: %+v", deg)
		}
		// Restore intact testing/internal/testdeps and verify drifted digest in pkgName triggers degradation.
		pkgs["testing/internal/testdeps"] = testdepsDigest
		inv["testing/internal/testdeps"] = listedPackage{ImportPath: "testing/internal/testdeps", Dir: testdepsDir, Files: []string{"testdeps.go"}, Audited: true, digest: testdepsDigest}
		pkgs[pkgName] = d1
		driftedSD := sourceDigests{Packages: pkgs, inventory: inv, Policy: admissionPolicy()}
		if deg := toolchainSourceDegradation("go1.test", driftedSD, nil); deg.audited() || !strings.Contains(deg.axis, pkgName) {
			t.Fatalf("moved audited package digest did not trigger degradation naming %s: %+v", pkgName, deg)
		}
	})
}

func TestTestingAndTestdepsVerifierPayloadCountAndBindingContracts(t *testing.T) {
	root := t.TempDir()
	writePkg := func(importPath string, files map[string]string) listedPackage {
		t.Helper()
		dir := filepath.Join(root, strings.ReplaceAll(importPath, "/", "_"), t.Name(), strings.ReplaceAll(filepath.Base(t.TempDir()), "/", "_"))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		var names []string
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			names = append(names, name)
		}
		sort.Strings(names)
		return listedPackage{ImportPath: importPath, Dir: dir, Files: names, Audited: true}
	}

	makeWrappedTesting := func(extraImports, extraDecls string) map[string]string {
		src := syntheticTestingInlineSrc
		if extraImports != "" {
			src = mustMutateFixture(t, src, "import (\n", "import (\n"+extraImports)
		}
		src = mustMutateFixture(t, src, "m.deps.StartTestLog(f)", "m.deps.StartTestLog(wrapLog(f))")
		return map[string]string{"testing.go": src + "\n" + extraDecls + "\n"}
	}

	// Unrelated struct field mutation in package testing must not reject a
	// scoped unexported custom testlog writer whose own bound field is immutable.
	admittedScopedField := writePkg("testing", makeWrappedTesting("",
		"type otherHolder struct{ w io.Writer }\nfunc resetOther(o *otherHolder) { o.w = nil }\ntype scopedLogWriter struct{ w *os.File }\nfunc (s *scopedLogWriter) Write(p []byte) (int, error) { return s.w.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &scopedLogWriter{w: f} }"))
	if err := verifyListedPackage(admittedScopedField); err != nil {
		t.Fatalf("scoped custom testlog writer alongside unrelated field mutation refused: %v", err)
	}

	framedChunkHelper := "func framedChunkWrite(f *os.File, prefix []byte, payload []byte) (written int, err error) {\n\twriteAll := func(b []byte) error {\n\t\t_, werr := f.Write(b)\n\t\treturn werr\n\t}\n\tfor {\n\t\tbuf := make([]byte, 0, len(payload))\n\t\tbuf = append(buf, prefix...)\n\t\tbuf = append(buf, payload...)\n\t\tchunkErr := writeAll(buf)\n\t\tif chunkErr == nil && err == nil {\n\t\t\twritten += len(payload)\n\t\t} else if chunkErr != nil && err == nil {\n\t\t\terr = chunkErr\n\t\t}\n\t\tpayload = payload[len(payload):]\n\t\tif len(payload) == 0 {\n\t\t\treturn written, err\n\t\t}\n\t}\n}\n"

	// Provably empty prefix (`[]byte("")`) in chunking-loop append preserves payload stream verbatim.
	admittedEmptyAppendPrefix := writePkg("testing", makeWrappedTesting("",
		framedChunkHelper+"type framedWriter struct{ f *os.File }\nfunc (w *framedWriter) Write(p []byte) (int, error) { return framedChunkWrite(w.f, []byte(\"\"), p) }\nfunc wrapLog(f *os.File) io.Writer { return &framedWriter{f: f} }"))
	if err := verifyListedPackage(admittedEmptyAppendPrefix); err != nil {
		t.Fatalf("empty-prefix append custom testlog writer refused: %v", err)
	}

	for name, files := range map[string]map[string]string{
		"sink called with nil payload": makeWrappedTesting("",
			"type wNil struct{ f *os.File }\nfunc (w *wNil) Write(p []byte) (int, error) { return w.f.Write(nil) }\nfunc wrapLog(f *os.File) io.Writer { return &wNil{f: f} }"),
		"blanked write count returning len(p)": makeWrappedTesting("",
			"type wBlankN struct{ f *os.File }\nfunc (w *wBlankN) Write(p []byte) (int, error) { _, err := w.f.Write(p); return len(p), err }\nfunc wrapLog(f *os.File) io.Writer { return &wBlankN{f: f} }"),
		"bound write count ignored returning len(p)": makeWrappedTesting("",
			"type wFakeN struct{ f *os.File }\nfunc (w *wFakeN) Write(p []byte) (int, error) { n, err := w.f.Write(p); _ = n; return len(p), err }\nfunc wrapLog(f *os.File) io.Writer { return &wFakeN{f: f} }"),
		"unlooped tail syscall.Write": makeWrappedTesting("\t\"syscall\"\n",
			"type wUnlooped struct{ fd int }\nfunc (w *wUnlooped) Write(p []byte) (int, error) { return syscall.Write(w.fd, p) }\nfunc wrapLog(f *os.File) io.Writer { return &wUnlooped{fd: int(f.Fd())} }"),
		"unlooped assigned syscall.Write": makeWrappedTesting("\t\"syscall\"\n",
			"type wUnlooped2 struct{ fd int }\nfunc (w *wUnlooped2) Write(p []byte) (int, error) { n, err := syscall.Write(w.fd, p); return n, err }\nfunc wrapLog(f *os.File) io.Writer { return &wUnlooped2{fd: int(f.Fd())} }"),
		"loop advancing slice by len(p) instead of n": makeWrappedTesting("\t\"syscall\"\n",
			"type wSkipTail struct{ fd int }\nfunc writeBad(fd int, p []byte) error { for len(p) > 0 { n, err := syscall.Write(fd, p); _ = n; if err != nil { return err }; p = p[len(p):] }; return nil }\nfunc (w *wSkipTail) Write(p []byte) (int, error) { err := writeBad(w.fd, p); if err != nil { return 0, err }; return len(p), nil }\nfunc wrapLog(f *os.File) io.Writer { return &wSkipTail{fd: int(f.Fd())} }"),
		"corrupting payload byte before write": makeWrappedTesting("",
			"type wCorrupt struct{ f *os.File }\nfunc (w *wCorrupt) Write(p []byte) (int, error) { p[0] = 0; return w.f.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &wCorrupt{f: f} }"),
		"incrementing payload byte before write": makeWrappedTesting("",
			"type wInc struct{ f *os.File }\nfunc (w *wInc) Write(p []byte) (int, error) { p[0]++; return w.f.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &wInc{f: f} }"),
		"corrupting payload via local slice alias": makeWrappedTesting("",
			"type wAlias struct{ f *os.File }\nfunc (w *wAlias) Write(p []byte) (int, error) { alias := p; alias[0] = 0; return w.f.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &wAlias{f: f} }"),
		"passing payload to unverified helper": makeWrappedTesting("",
			"func scramble(b []byte) { if len(b) > 0 { b[0] = 'x' } }\ntype wHelper struct{ f *os.File }\nfunc (w *wHelper) Write(p []byte) (int, error) { scramble(p); return w.f.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &wHelper{f: f} }"),
		"non-empty header prefix in append": makeWrappedTesting("",
			framedChunkHelper+"type wPrefix struct{ f *os.File }\nfunc (w *wPrefix) Write(p []byte) (int, error) { return framedChunkWrite(w.f, []byte(\"x\"), p) }\nfunc wrapLog(f *os.File) io.Writer { return &wPrefix{f: f} }"),
		"appending trailing byte per Write call": makeWrappedTesting("",
			"type wTrail struct{ f *os.File }\nfunc (w *wTrail) Write(p []byte) (int, error) { out := append(make([]byte, 0, len(p)+1), p...); out = append(out, '\\n'); return w.f.Write(out) }\nfunc wrapLog(f *os.File) io.Writer { return &wTrail{f: f} }"),
		"custom writer declaring WriteString bypassing Write": makeWrappedTesting("",
			"type wBypassSW struct{ f *os.File }\nfunc (w *wBypassSW) Write(p []byte) (int, error) { return w.f.Write(p) }\nfunc (w *wBypassSW) WriteString(s string) (int, error) { return len(s), nil }\nfunc wrapLog(f *os.File) io.Writer { return &wBypassSW{f: f} }"),
		"custom writer declaring ReadFrom": makeWrappedTesting("",
			"type wReadFrom struct{ f *os.File }\nfunc (w *wReadFrom) Write(p []byte) (int, error) { return w.f.Write(p) }\nfunc (w *wReadFrom) ReadFrom(r io.Reader) (int64, error) { return 0, nil }\nfunc wrapLog(f *os.File) io.Writer { return &wReadFrom{f: f} }"),
		"clearing payload before write": makeWrappedTesting("",
			"type wClear struct{ f *os.File }\nfunc (w *wClear) Write(p []byte) (int, error) { clear(p); return w.f.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &wClear{f: f} }"),
		"mutating own bound field w inside Write": makeWrappedTesting("",
			"type wMut struct{ w *os.File }\nfunc (s *wMut) Write(p []byte) (int, error) { s.w = nil; return s.w.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &wMut{w: f} }"),
		"escaping receiver from method": makeWrappedTesting("",
			"var globalSink any\ntype wEsc struct{ w *os.File }\nfunc (s *wEsc) Write(p []byte) (int, error) { globalSink = s; return s.w.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &wEsc{w: f} }"),
		"exported custom writer struct": makeWrappedTesting("",
			"type ExportedWriter struct{ w *os.File }\nfunc (s *ExportedWriter) Write(p []byte) (int, error) { return s.w.Write(p) }\nfunc wrapLog(f *os.File) io.Writer { return &ExportedWriter{w: f} }"),
		"second StartTestLog overwriting valid StartTestLog with Discard": {
			"testing.go": mustMutateFixture(t, syntheticTestingInlineSrc, "m.deps.StartTestLog(f)", "m.deps.StartTestLog(f); m.deps.StartTestLog(io.Discard)"),
		},
		"M.Run reaching StartTestLog without reaching StopTestLog": {
			"testing.go": mustMutateFixture(t, syntheticTestingSplitSrc, "\tdefer m.after()\n", ""),
		},
		"M.Run reaching StopTestLog without reaching StartTestLog": {
			"testing.go": mustMutateFixture(t, syntheticTestingSplitSrc, "\tm.before()\n", ""),
		},
		"startAlarm calling helper with os.Exit(2)": {
			"testing.go": mustMutateFixture(t, syntheticTestingSplitSrc, "func (m *M) startAlarm() {\n", "func abortTwo() { os.Exit(2) }\nfunc (m *M) startAlarm() {\n\tabortTwo()\n"),
		},
		"dead if false branch discharging sink": makeWrappedTesting("",
			"func writeAll(f *os.File, p []byte) error { _, err := f.Write(p); return err }\ntype wDeadBranch struct{ f *os.File }\nfunc (w *wDeadBranch) Write(p []byte) (int, error) { if false { err := writeAll(w.f, p); if err != nil { return 0, err }; return len(p), nil }; return len(p), nil }\nfunc wrapLog(f *os.File) io.Writer { return &wDeadBranch{f: f} }"),
		"switch goto label bypassing sink": makeWrappedTesting("",
			"func writeAll(f *os.File, p []byte) error { _, err := f.Write(p); return err }\ntype wGoto struct{ f *os.File }\nfunc (w *wGoto) Write(p []byte) (int, error) { switch { default: goto skip }; if err := writeAll(w.f, p); err != nil { return 0, err }; skip: ; return len(p), nil }\nfunc wrapLog(f *os.File) io.Writer { return &wGoto{f: f} }"),
		"infinite for init loop without sink": makeWrappedTesting("",
			"type wInf struct{ f *os.File }\nfunc (w *wInf) Write(p []byte) (int, error) { _ = w.f; for x := 0; ; { _ = x } }\nfunc wrapLog(f *os.File) io.Writer { return &wInf{f: f} }"),
		"reassigning verified sink closure variable": makeWrappedTesting("\t\"syscall\"\n\t\"unsafe\"\n",
			"type wRebind struct{ f *os.File; fd int }\nfunc rawWriteBad(fd int, payload []byte) (written int, err error) {\n\twriteAll := func(b []byte) error {\n\t\tfor len(b) > 0 {\n\t\t\tr1, _, errno := syscall.RawSyscall(syscall.SYS_WRITE, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))\n\t\t\tif errno != 0 { return errno }\n\t\t\tb = b[int(r1):]\n\t\t}\n\t\treturn nil\n\t}\n\twriteAll = func([]byte) error { return nil }\n\tfor {\n\t\tchunkErr := writeAll(payload)\n\t\tif chunkErr == nil && err == nil { written += len(payload) } else if chunkErr != nil && err == nil { err = chunkErr }\n\t\tpayload = payload[len(payload):]\n\t\tif len(payload) == 0 { return written, err }\n\t}\n}\nfunc (w *wRebind) Write(p []byte) (int, error) { return rawWriteBad(w.fd, p) }\nfunc wrapLog(f *os.File) io.Writer { return &wRebind{f: f, fd: int(f.Fd())} }"),
	} {
		if err := verifyListedPackage(writePkg("testing", files)); err == nil {
			t.Fatalf("testing writer violation %q admitted", name)
		}
	}

	for name, mut := range map[string][2]string{
		"StopTestLog clearing flushErr via &err":         {"return err", "clearErr(&err)\n\treturn err"},
		"StopTestLog defer referencing flushErr":         {"return err", "defer func() { _ = err }()\n\treturn err"},
		"StopTestLog unconditional early return nil":     {"err := log.w.Flush()", "return nil\n\terr := log.w.Flush()"},
		"StopTestLog dead branch setting flushErr":       {"err := log.w.Flush()", "var err error\n\tif false { err = log.w.Flush() }"},
		"StopTestLog switch goto bypassing Flush":        {"err := log.w.Flush()", "var err error\n\tswitch { default: goto skip }\n\terr = log.w.Flush()\n\tskip: ;"},
		"StartTestLog dead local alias with Discard":     {"log.w = bufio.NewWriter(w)", "unused := w; _ = unused; log.w = bufio.NewWriter(io.Discard)"},
		"StartTestLog unused helper call taking w":       {"log.w = bufio.NewWriter(w)", "dropW(w); log.w = bufio.NewWriter(w)"},
		"StartTestLog mismatched logger base":            {"var log testLog", "var log, other testLog"},
		"StartTestLog dead code after early return":      {"log.mu.Lock()", "return\n\tlog.mu.Lock()"},
		"StartTestLog overwriting bound writer with nil": {"log.w = bufio.NewWriter(w)", "log.w = bufio.NewWriter(w)\n\tlog.w = nil"},
	} {
		base := syntheticTestdepsSrc
		switch name {
		case "StopTestLog clearing flushErr via &err":
			base += "\nfunc clearErr(p *error) { *p = nil }\n"
		case "StartTestLog unused helper call taking w":
			base += "\nfunc dropW(io.Writer) {}\n"
		case "StartTestLog mismatched logger base":
			base = mustMutateFixture(t, base, "log.w = bufio.NewWriter(w)", "other.w = bufio.NewWriter(w)")
		}
		src := mustMutateFixture(t, base, mut[0], mut[1])
		if err := verifyListedPackage(writePkg("testing/internal/testdeps", map[string]string{"deps.go": src})); err == nil {
			t.Fatalf("testdeps violation %q admitted", name)
		}
	}
}

func TestAssemblyVerifierPreprocessorAndContinuationRejections(t *testing.T) {
	root := t.TempDir()
	writeAsmPkg := func(name, importPath string, files map[string]string) listedPackage {
		t.Helper()
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		var names []string
		for fn, content := range files {
			if err := os.WriteFile(filepath.Join(dir, fn), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			names = append(names, fn)
		}
		sort.Strings(names)
		return listedPackage{ImportPath: importPath, Dir: dir, Files: names, Audited: true}
	}

	validCDeclHeader := writeAsmPkg("valid_c_int_header", "internal/bytealg", map[string]string{
		"bytealg.go": "package bytealg\nfunc f()\n",
		"defs.h":     "// Header with lowercase C int token, empty feature flag, and parameterized macro\n#define CONST_VAL 1\n#define hasAVX\n#define get_tls(r) MOVQ TLS, r\n/* int in comment */\ntypedef int word_t;\n",
		"asm.s":      "#include \"defs.h\"\n#define ROL16(R, T) PSHUFB ·rol16<>(SB), R\nTEXT ·f(SB),$0-0\n\tVSETVLI X5, X6, E8, M1, TA, MA\n\tROL16(X0, X1)\n\tRET\n",
	})
	if err := verifyListedPurePackage(validCDeclHeader); err != nil {
		t.Fatalf("valid assembly package with lowercase C int, local-symbol macro, and RISC-V VSETVLI TA refused: %v", err)
	}

	for name, files := range map[string]map[string]string{
		"macro-aliased INT $0x80": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"defs.h":     "#define DO_TRAP INT\n",
			"asm.s":      "#include \"defs.h\"\nTEXT ·f(SB),$0-0\n\tDO_TRAP $0x80\n\tRET\n",
		},
		"macro-expanded #include": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#define INC #include \"evil.h\"\nINC\nTEXT ·f(SB),$0-0\n\tRET\n",
		},
		"SYSENTER trap instruction": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tSYSENTER\n\tRET\n",
		},
		"SPARC TA software trap": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tTA $0x10\n\tRET\n",
		},
		"RDTSC clock read": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tRDTSC\n\tRET\n",
		},
		"RDRAND entropy read": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tRDRAND AX\n\tRET\n",
		},
		"ARM64 CNTVCT_EL0 counter read": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tMRS CNTVCT_EL0, R0\n\tRET\n",
		},
		"whitespace-split runtime · walltime": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tCALL runtime · walltime(SB)\n\tRET\n",
		},
		"block-comment-split runtime/*c*/·walltime": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tCALL runtime/*c*/·walltime(SB)\n\tRET\n",
		},
		"slash-split internal / poll · Write": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tCALL internal / poll · Write(SB)\n\tRET\n",
		},
		"slash-split masking via self package suffix": {
			"strings.go": "package strings\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tCALL foo / strings·Index(SB)\n\tRET\n",
		},
		"object-like macro ending with lowercase package prefix": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#define M CALL time\nTEXT ·f(SB),$0-0\n\tM ·now(SB)\n\tRET\n",
		},
		"parameterized macro splitting package prefix before middle dot": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#define DOIT(P) CALL P ·now(SB)\nTEXT ·f(SB),$0-0\n\tDOIT(time)\n\tRET\n",
		},
		"macro invocation preceding middle dot": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#define ID(X) X\nTEXT ·f(SB),$0-0\n\tCALL ID(time) ·now(SB)\n\tRET\n",
		},
		"#define shadowing self package name": {
			"strings.go": "package strings\nfunc f()\n",
			"asm.s":      "#define strings runtime\nTEXT ·f(SB),$0-0\n\tCALL strings·walltime(SB)\n\tRET\n",
		},
		"header #define shadowing lowercase package name": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"defs.h":     "#define bytes time\n",
			"asm.s":      "#include \"defs.h\"\nTEXT ·f(SB),$0-0\n\tCALL bytes·Compare(SB)\n\tRET\n",
		},
		"macro body starting with middle-dot symbol": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#define DOT ·now(SB)\nTEXT ·f(SB),$0-0\n\tCALL time DOT\n\tRET\n",
		},
		"macro parameter inside slash-qualified package segment": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#define GET(cpu) MOVB internal∕cpu·X86(SB), AX\nTEXT ·f(SB),$0-0\n\tGET(syscall)\n\tRET\n",
		},
		"backslash-continued #include keyword": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#inc\\\nlude \"evil.h\"\nTEXT ·f(SB),$0-0\n\tRET\n",
		},
		"multiline block comment inside #include": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#/*\n*/include \"evil.h\"\nTEXT ·f(SB),$0-0\n\tRET\n",
		},
		"backslash-continued SYSCALL token": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tSYS\\\nCALL\n\tRET\n",
		},
		"line comment ending with backslash before SYSCALL": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\t// comment \\\n\tSYSCALL\n\tRET\n",
		},
		"backslash-continued #define SYSCALL without space": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#define M\\\nSYSCALL\nTEXT ·f(SB),$0-0\n\tM\n\tRET\n",
		},
		"backslash followed by block comment splitting SYSCALL": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "TEXT ·f(SB),$0-0\n\tSYS\\/* comment */\nCALL\n\tRET\n",
		},
		"CRLF string literal continuation before SYSCALL": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "DATA x<>+0(SB)/8, $\"a\\\r\n\"; SYSCALL\r\nTEXT ·f(SB),$0-0\n\tRET\n",
		},
		"multi-ifdef macro expansion budget overflow": {
			"bytealg.go": "package bytealg\nfunc f()\n",
			"asm.s":      "#define B0 a\n#define B0 b\n#define B1 a\n#define B1 b\n#define B2 a\n#define B2 b\n#define B3 a\n#define B3 b\n#define B4 a\n#define B4 b\n#define B5 a\n#define B5 b\n#define B6 a\n#define B6 b\n#define B7 a\n#define B7 b\n#define B8 a\n#define B8 b\nTEXT ·f(SB),$0-0\n\tNOP B0 B1 B2 B3 B4 B5 B6 B7 B8\n\tRET\n",
		},
	} {
		pkgPath := "internal/bytealg"
		if _, hasStrings := files["strings.go"]; hasStrings {
			pkgPath = "strings"
		}
		if err := verifyListedPurePackage(writeAsmPkg(strings.ReplaceAll(name, " ", "_"), pkgPath, files)); err == nil {
			t.Fatalf("assembly violation %q admitted", name)
		}
	}

	// Direct non-Go preprocessor and C string-literal normalization checks (platform/cgo-independent).
	benignOff, err := verifyOffSurfacePackageWithIO(t.Context(), writeAsmPkg("benign_off_c", "image/color", map[string]string{
		"color.go": "package color\n",
		"ext.c":    "void benignC(void) {}\n",
	}), "")
	if err != nil || len(benignOff.DirectRuntimePulls) != 0 {
		t.Fatalf("benign off-surface C package: pulls=%v err=%v", benignOff.DirectRuntimePulls, err)
	}
	longPadding := strings.Repeat("int pad_var = 0; ", 1200) // > 19 KiB on a single physical line
	for name, files := range map[string]map[string]string{
		"adjacent C string literals": {
			"color.go": "package color\n",
			"ext.c":    "extern void f(void) __asm__(\"runtime.\" \"gofreshSimEnable\");\n",
		},
		"C hex escape in string literal": {
			"color.go": "package color\n",
			"ext.c":    "extern void f(void) __asm__(\"runtime.\\x67ofreshSimEnable\");\n",
		},
		"C octal escape in string literal": {
			"color.go": "package color\n",
			"ext.c":    "extern void f(void) __asm__(\"runtime.\\147ofreshSimEnable\");\n",
		},
		"C unicode escape in string literal": {
			"color.go": "package color\n",
			"ext.c":    "extern void f(void) __asm__(\"runtime.\\u0067ofreshSimEnable\");\n",
		},
		"C stringize macro operator": {
			"color.go": "package color\n",
			"ext.c":    "#define RTSYM(x) extern void f(void) __asm__(\"runtime.\" #x);\nRTSYM(gofreshSimEnable)\n",
		},
		"multiline object-like macro string concatenation": {
			"color.go": "package color\n",
			"ext.c":    "#define PFX \"runtime.\"\n#define SFX \"gofreshSimEnable\"\nextern void f(void) __asm__(\nPFX\nSFX\n);\n",
		},
		"multiline parameterized assembly macro": {
			"color.go": "package color\n",
			"asm.s":    "#define CALLRT(s) CALL runtime·s(SB)\nTEXT ·f(SB),$0-0\n\tCALLRT(\n\t\tgofreshSimEnable\n\t)\n\tRET\n",
		},
		"companion ifdef macros with two-level token paste": {
			"color.go": "package color\n",
			"asm.s":    "#ifdef ALT\n#define PKG other\n#define SYM benign\n#else\n#define PKG runtime\n#define SYM gofreshSimEnable\n#endif\n#define PASTE2(a, b) a##·##b\n#define PASTE(a, b) PASTE2(a, b)\nTEXT ·f(SB),$0-0\n\tCALL PASTE(PKG, SYM)(SB)\n\tRET\n",
		},
		"chained ifdef macros": {
			"color.go": "package color\n",
			"asm.s":    "#ifdef ALT\n#define INNER() RET\n#else\n#define INNER() CALL runtime·gofreshSimEnable(SB)\n#endif\n#define OUTER() INNER()\nTEXT ·f(SB),$0-0\n\tOUTER()\n\tRET\n",
		},
		"long single-line C declaration exceeding 16KiB": {
			"color.go": "package color\n",
			"ext.c":    longPadding + "extern void f(void) __asm__(\"runtime.gofreshSimEnable\");\n",
		},
		"CRLF string continuation before C asm label": {
			"color.go": "package color\n",
			"ext.c":    "const char *s = \"abc\\\r\n\\\"/*comment*/\";\r\nextern void f(void) __asm__(\"runtime.gofreshSimEnable\");\r\n",
		},
		"ungrouped import C preamble": {
			"color.go": "package color\n/*\nextern void f(void) __asm__(\"runtime.gofreshSimEnable\");\n*/\nimport \"C\"\n",
		},
	} {
		v, err := verifyOffSurfacePackageWithIO(t.Context(), writeAsmPkg("off_"+strings.ReplaceAll(name, " ", "_"), "image/color", files), "")
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if !slices.Contains(v.DirectRuntimePulls, "runtime.gofreshSimEnable") {
			t.Fatalf("%s: DirectRuntimePulls=%v, want runtime.gofreshSimEnable", name, v.DirectRuntimePulls)
		}
	}

	overflowOff, err := verifyOffSurfacePackageWithIO(t.Context(), writeAsmPkg("off_macro_overflow", "image/color", map[string]string{
		"color.go": "package color\n",
		"ext.c":    "#define B0 1\n#define B0 2\n#define B1 1\n#define B1 2\n#define B2 1\n#define B2 2\n#define B3 1\n#define B3 2\n#define B4 1\n#define B4 2\n#define B5 1\n#define B5 2\n#define B6 1\n#define B6 2\n#define B7 1\n#define B7 2\n#define B8 1\n#define B8 2\nint x = B0 + B1 + B2 + B3 + B4 + B5 + B6 + B7 + B8;\n",
	}), "")
	if err != nil || !slices.Contains(overflowOff.DirectRuntimePulls, "runtime.*") {
		t.Fatalf("off-surface macro overflow: pulls=%v err=%v, want runtime.*", overflowOff.DirectRuntimePulls, err)
	}

	fakeGoroot := filepath.Join(root, "fake_goroot")
	if err := os.MkdirAll(filepath.Join(fakeGoroot, "pkg", "include"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(fakeGoroot, "src", "runtime"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeGoroot, "pkg", "include", "bridge.h"), []byte("#define EXT_PKG image/color\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeGoroot, "src", "runtime", "runtime.go"), []byte("package runtime\nimport \"internal/runtime/atomic\"\nvar gofreshSimState atomic.Bool\nvar gofreshSimStateAsm atomic.Bool\nfunc gofreshSimEnable() { gofreshSimState.Store(true) }\nfunc gofreshSimEnableAsm() { gofreshSimStateAsm.Store(true) }\nfunc gofreshSimActive() bool { return gofreshSimState.Load() }\nfunc gofreshSimActiveAsm() bool { return gofreshSimStateAsm.Load() }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeGoroot, "src", "runtime", "bridge_c.h"), []byte("#define EXT_CALL(pkg, fn) extern void b(void) __asm__(#pkg \".\" #fn);\n#define PASTE2(a, b) a##b\n#define PASTE(a, b) PASTE2(a, b)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeGoroot, "src", "runtime", "bridge.s"), []byte("#include \"bridge.h\"\n#define CALL_LOCAL(a, b) CALL ·a##b(SB)\nTEXT ·f(SB),$0-0\n\tCALL EXT_PKG·gofreshBridgeEnable(SB)\n\tCALL foo·(*bar(SB); CALL image/color·(*Palette)·gofreshBridgeAsmMethod(SB)\n\tCALL_LOCAL(gofreshSim, EnableAsm)\n\tRET\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeGoroot, "src", "runtime", "bridge.c"), []byte("#include \"bridge_c.h\"\nEXT_CALL(image/color, gofreshBridgeEnableC)\nextern void bMachO(void) __asm__(\"_image/color.gofreshBridgeMachO\");\nextern void bPct(void) __asm__(\"image%2fcolor.gofreshBridgePct\");\nextern void bMethod(void) __asm__(\"image/color.(*Palette).gofreshBridgeMethod\");\nextern int PASTE(gofreshSim, State);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rtVerdict, vErr, iErr := verifyListedPackageWithIOAndSalt(t.Context(), listedPackage{
		ImportPath: "runtime",
		Dir:        filepath.Join(fakeGoroot, "src", "runtime"),
		Files:      []string{"bridge.c", "bridge.s", "bridge_c.h", "runtime.go"},
		Audited:    true,
	}, "salt")
	if vErr != nil || iErr != nil {
		t.Fatalf("synthetic runtime header macro/stringize check failed: vErr=%v iErr=%v", vErr, iErr)
	}
	for _, want := range []string{
		"image/color.gofreshBridgeEnable",
		"image/color.gofreshBridgeEnableC",
		"image/color.gofreshBridgeMachO",
		"image/color.gofreshBridgePct",
		"image/color.Palette.gofreshBridgeMethod",
		"image/color.Palette.gofreshBridgeAsmMethod",
	} {
		if !slices.Contains(rtVerdict.ExternalLinknamePulls, want) {
			t.Fatalf("runtime ExternalLinknamePulls=%v, missing %s", rtVerdict.ExternalLinknamePulls, want)
		}
	}
	if _, ok := rtVerdict.InactiveRuntimeGates["runtime.gofreshSimActive"]; ok {
		t.Fatalf("runtime.gofreshSimActive remained proven inactive despite C macro-pasted reference to gofreshSimState: %v", rtVerdict.InactiveRuntimeGates)
	}
	if _, ok := rtVerdict.InactiveRuntimeGates["runtime.gofreshSimActiveAsm"]; ok {
		t.Fatalf("runtime.gofreshSimActiveAsm remained proven inactive despite asm ·a##b local macro call to gofreshSimEnableAsm: %v", rtVerdict.InactiveRuntimeGates)
	}
}
