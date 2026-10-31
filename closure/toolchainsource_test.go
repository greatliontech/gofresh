package closure

import (
	"context"
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

	"github.com/greatliontech/gofresh/closure/internal/compartment"
	"github.com/greatliontech/gofresh/closure/internal/listing"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/testenv"
)

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
		"missing LookupEnv":                        {"func LookupEnv(key string) (string, bool) {\n\ttestlog.Getenv(key)\n\treturn \"\", false\n}\n", ""},
		"Chdir missing testlog.Open":               {"\t\ttestlog.Open(dir)\n", ""},
		"Chdir returning nil on syscall error":     {"return &PathError{Op: \"chdir\", Path: dir, Err: e}", "return nil"},
		"ReadFile bypassing Open":                  {"f, err := Open(name)", "var f *File; var err error"},
		"aliased testlog":                          {"\"internal/testlog\"", "tl \"internal/testlog\""},
		"shadowed testlog":                         {"testlog.Getenv(key)", "testlog := struct{ Getenv func(string) }{func(string) {}}; testlog.Getenv(key)"},
		"ErrInvalid nil initializer":               {"errors.New(\"invalid argument\")", "error(nil)"},
		"ErrInvalid mutated in init":               {"var ErrClosed =", "func init() { ErrInvalid = nil }\nvar ErrClosed ="},
		"shadowed errors package var":              {"var errors = struct{ New func(string) error }{func(string) error { return nil }}\nvar ErrInvalid =", ""},
		"OpenFile hook inside if false":            {"testlog.Open(name)", "if false { testlog.Open(name) }"},
		"Stat hook guarded by true const":          {"func Stat(name string)", "const alwaysTrue = true\nfunc Stat(name string)"},
		"OpenFile hook preceded by var skip guard": {"testlog.Open(name)", "if skipHook { return nil, nil }\n\ttestlog.Open(name)"},
		"OpenFile dropping name arg":               {"testlog.Open(name)", "testlog.Open(\"\")"},
		"File.Write dropping ErrShortWrite":        {"\tif n != len(b) {\n\t\terr = io.ErrShortWrite\n\t}\n", ""},
		"File.Write dropping wrapErr":              {"\tif e != nil {\n\t\terr = f.wrapErr(\"write\", e)\n\t}\n", ""},
		"File.WriteString bypassing Write":         {"return f.Write([]byte(s))", "return len(s), nil"},
		"File.Close bypassing file.close":          {"return f.file.close()", "return nil"},
		"file.close ignoring pfd.Close error":      {"if e := file.pfd.Close(); e != nil {\n\t\terr = &PathError{Op: \"close\", Path: file.name, Err: e}\n\t}", "_ = file.pfd.Close()"},
		"os linkname overriding Open":              {"func Open(", "//go:linkname Open runtime.evilOpen\nfunc Open("},
		"os linkname overriding close":             {"func (file *file) close()", "//go:linkname close runtime.evilClose\nfunc (file *file) close()"},
		"os linkname overriding destroy":           {"package os\n", "package os\nimport _ \"unsafe\"\n//go:linkname destroy runtime.evilDestroy\nfunc destroy()\n"},
		"os aliased unsafe import":                 {"import (\n", "import (\n\tu \"unsafe\"\n"},
		"file.close receiver shadowing ErrInvalid": {"func (file *file) close() error {\n\tif file == nil {\n\t\treturn syscall.EINVAL\n\t}\n\tvar err error\n\tif e := file.pfd.Close(); e != nil {\n\t\terr = &PathError{Op: \"close\", Path: file.name, Err: e}\n\t}\n\treturn err\n}", "func (*file) Error() string { return \"\" }\nfunc (ErrInvalid *file) close() error {\n\tif ErrInvalid == nil {\n\t\treturn ErrInvalid\n\t}\n\tvar err error\n\tif e := ErrInvalid.pfd.Close(); e != nil {\n\t\terr = &PathError{Op: \"close\", Path: ErrInvalid.name, Err: e}\n\t}\n\treturn err\n}"},
		"os wasmimport directive":                                {"package os\n", "package os\n//go:wasmimport env hostRead\nfunc hostRead()\n"},
		"os cgo_import_dynamic directive":                        {"package os\n", "package os\n//go:cgo_import_dynamic libc_open open \"libc.so\"\n"},
		"OpenFile synthesizing fake descriptor":                  {"r, err := syscall.Open(name, flag, perm)", "r, err := 99, error(nil)"},
		"OpenFile mutating descriptor":                           {"return newFile(r, name), nil", "r = 0\n\treturn newFile(r, name), nil"},
		"ReadFile helper calling testlog.Stat":                   {"func statOrZero(f *File) int64 {\n\treturn 0\n}", "func statOrZero(f *File) int64 {\n\ttestlog.Stat(f.name)\n\treturn 0\n}"},
		"File.Fd returning synthetic zero":                       {"return uintptr(f.pfd.Sysfd)", "return uintptr(0)"},
		"Exit omitting PanicOnExit0 guard":                       {"\tif code == 0 && testlog.PanicOnExit0() {\n\t\tpanic(\"os.Exit(0)\")\n\t}\n", ""},
		"file.close calling syscall.Exit":                        {"\treturn err\n}", "\tsyscall.Exit(0)\n\treturn err\n}"},
		"Getwd returning constant slash":                         {"dir, err := syscall.Getwd()\n\treturn dir, err", "return \"/\", nil"},
		"Getwd returning concatenated string literal":            {"dir, err := syscall.Getwd()\n\treturn dir, err", "return \"/tmp\" + \"/spoof\", nil"},
		"Getwd returning package const string":                   {"func Getwd() (string, error) {\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}", "const fakeWD = \"/fake\"\nfunc Getwd() (string, error) {\n\treturn fakeWD, nil\n}"},
		"Getwd returning constant error under non-error guard":   {"func Getwd() (string, error) {\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}", "func Getwd() (string, error) {\n\tif true {\n\t\treturn \"\", ErrInvalid\n\t}\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}"},
		"Getwd swallowing syscall.Getwd error":                   {"dir, err := syscall.Getwd()\n\treturn dir, err", "dir, _ := syscall.Getwd()\n\treturn dir, nil"},
		"Getwd ignoringEINTR2 spoofing return":                   {"return v, err", "_, _ = v, err\n\t\t\treturn *new(T), nil"},
		"Getwd ignoringEINTR2 inverted EINTR check":              {"err != syscall.EINTR", "err == syscall.EINTR"},
		"openFileNolog ignoringEINTR spoofing nil":               {"return fn()", "for {\n\t\terr := fn()\n\t\t_ = err\n\t\tif err != syscall.EINTR {\n\t\t\treturn nil\n\t\t}\n\t}"},
		"openFileNolog ignoringEINTR inverted EINTR check":       {"return fn()", "for {\n\t\terr := fn()\n\t\tif err == syscall.EINTR {\n\t\t\treturn err\n\t\t}\n\t}"},
		"open helper early return with valid fd":                 {"\tr, err := syscall.Open(path, flag, perm)", "\tif path == \"x\" {\n\t\treturn 3, pollFD{}, nil\n\t}\n\tr, err := syscall.Open(path, flag, perm)"},
		"state table non-spine field address-taken":              {"func simCount() int { return simStates.count }", "func simCount() *int { return &simStates.count }"},
		"state table whole-struct overwrite":                     {"func simCount() int { return simStates.count }", "func simCount() int { simStates = simTab{}; return 0 }"},
		"state table indirect mutator method called":             {"func simCount() int { return simStates.count }", "func (t *simTab) wrapSet(v *int) { t.set(v) }\nfunc ExportedWrapTrigger() { var x int; simStates.wrapSet(&x) }\nfunc simCount() int { return simStates.count }"},
		"state table custom struct non-spine field":              {"type simTab struct { spine atomic.Pointer[int]; count int }", "type subBox struct{ v int }\ntype simTab struct { spine atomic.Pointer[int]; count int; sub subBox }"},
		"state table receiver escaping":                          {"func simCount() int { return simStates.count }", "func (t *simTab) leak() any { return t }\nfunc simCount() int { return simStates.count }"},
		"state table non-nil short-circuit condition":            {"sp == nil || idx < 0", "idx < 0 || sp == nil"},
		"state table nilAcc parameter shadowing callee":                  {"func stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s := simStates.get(idx); return s }", "func stateOf(simIdx func(any) (int, bool)) *int { idx, ok := simIdx(simIdx); if !ok { return nil }; s := simStates.get(idx); return s }"},
		"state table nilAcc 2-LHS := redeclaring prior local on 1st LHS": {"func stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s := simStates.get(idx); return s }", "func stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s1 := simStates.get(idx); if s1 == nil { s1, ok2 := simIdx(f); if !ok2 { return nil }; s2 := simStates.get(s1); return s2 }; return nil }"},
		"state table nilAcc 2-LHS := redeclaring prior local on 2nd LHS": {"func stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s := simStates.get(idx); return s }", "func stateOf(f *file) *int { idx, ok := simIdx(f); if !ok { return nil }; s1 := simStates.get(idx); if s1 == nil { idx2, ok := simIdx(f); if !ok { return nil }; s2 := simStates.get(idx2); return s2 }; return nil }"},
		"state table pureIndexHelper reading package global var":         {"func simIdx(f *file) (int, bool) { return 0, f != nil }", "var globalIdxBias int\nfunc simIdx(f *file) (int, bool) { return globalIdxBias, f != nil }"},
		"state table pureIndexHelper writing package global var": {"func simIdx(f *file) (int, bool) { return 0, f != nil }", "var globalIdxSink int\nfunc simIdx(f *file) (int, bool) { globalIdxSink = 1; return 0, f != nil }"},
		"state table pureIndexHelper channel send":               {"func simIdx(f *file) (int, bool) { return 0, f != nil }", "func simIdx(f *file) (int, bool) { var ch chan int; ch <- 1; return 0, f != nil }"},
		"Chdir invoking helper before Logger.Chdir":              {"\tif log := testlog.Logger(); log != nil {", "\t_, _ = Getwd()\n\tif log := testlog.Logger(); log != nil {"},
		"Getwd climb returning nil-initialized package error":    {"const errENOSYS = syscall.ENOSYS", "var errENOSYS error = nil"},
		"Getwd climb returning PWD hint without slash guard":     {"if len(dir) > 0 && dir[0] == '/' {", "if len(dir) > 0 {"},
		"Getwd climb mutating dir outside SameFile(d, dot)":      {"\t\t\t\tif SameFile(d, dot) {", "\t\t\t\tdir = \"/spoof\"\n\t\t\t\tif SameFile(d, dot) {"},
		"Getwd climb breaking outer loop without SameFile":       {"\t\tif SameFile(pd, root) {\n\t\t\tbreak\n\t\t}", "\t\tif pd != nil {\n\t\t\tbreak\n\t\t}"},
		"statNolog returning address of package-level fileStat":  {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "var sharedFS fileStat\nfunc statNolog(name string) (FileInfo, error) {\n\t_ = &sharedFS; return &sharedFS, nil; var fs fileStat"},
		"statNolog returning package-level *fileStat var":        {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "var sharedStatPtr *fileStat\nfunc statNolog(name string) (FileInfo, error) {\n\treturn sharedStatPtr, nil; var fs fileStat"},
		"statNolog calling testlog.Stat":                         {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "func statNolog(name string) (FileInfo, error) {\n\ttestlog.Stat(name)\n\tvar fs fileStat"},
		"openDirNolog calling testlog.Open":                      {"func openDirNolog(name string) (*File, error) {\n\treturn openFileNolog(name, 0, 0)\n}", "func openDirNolog(name string) (*File, error) {\n\ttestlog.Open(name)\n\treturn openFileNolog(name, 0, 0)\n}"},
		"SameFile returning true unconditionally":                {"return sameFile(fs1, fs2)", "return true"},
		"sameFile comparing single argument to itself":           {"return fs1.dev == fs2.dev && fs1.ino == fs2.ino", "return fs1.dev == fs1.dev && fs1.ino == fs1.ino"},
		"File.Stat calling testlog.Stat when used by Getwd":      {"func (f *File) Stat() (FileInfo, error) {\n\tif f == nil {", "func (f *File) Stat() (FileInfo, error) {\n\ttestlog.Stat(f.name)\n\tif f == nil {"},
		"statNolog overwriting fresh FileInfo via addr-of local":  {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "func clobberInfo(dst *FileInfo) { *dst = nil }\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\tvar out FileInfo = &fs\n\tclobberInfo(&out)\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn out, nil\n}"},
		"statNolog overwriting local fileStat from package var":   {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)", "var sharedFS fileStat\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tfs = sharedFS"},
		"statNolog overwriting local fileStat after taking addr":  {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "var sharedFS fileStat\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\tp := &fs\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\tfs = sharedFS\n\treturn p, nil\n}"},
		"statNolog overwriting fresh FileInfo via 2nd 2-LHS":      {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "func bogusPair() (int, FileInfo) { return 0, nil }\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\tvar p FileInfo = &fs\n\t_, p = bogusPair()\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn p, nil\n}"},
		"statNolog taking pkg var addr after sibling block local": {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "var sharedFS fileStat\nfunc statNolog(name string) (FileInfo, error) {\n\t{ var sharedFS int; _ = sharedFS }\n\t_ = &sharedFS\n\tvar fs fileStat"},
		"statNolog returning pkg var laundered by inner block local": {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "var sharedFS FileInfo = &fileStat{}\nfunc statNolog(name string) (FileInfo, error) {\n\tif false { var sharedFS FileInfo = &fileStat{}; _ = sharedFS }\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\t_ = &fs\n\treturn sharedFS, nil\n}"},
		"statNolog returning pkg var before post-return local": {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "var sharedFS FileInfo = &fileStat{}\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\tif true { return sharedFS, nil }\n\tvar sharedFS FileInfo = &fs\n\treturn sharedFS, nil\n}"},
		"statNolog calling local function variable shadowing top helper": {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\treturn &fs, nil\n}", "var sharedFS FileInfo = &fileStat{}\nfunc newFreshFS() (FileInfo, error) { return &fileStat{}, nil }\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\terr := syscall.Stat(name, nil)\n\tif err != nil {\n\t\treturn nil, &PathError{Op: \"stat\", Path: name, Err: err}\n\t}\n\t_ = &fs\n\tnewFreshFS := func() (FileInfo, error) { return sharedFS, nil }\n\treturn newFreshFS()\n}"},
		"statNolog calling local function variable in statement position": {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "var extraHook func()\nfunc statNolog(name string) (FileInfo, error) {\n\tfn := extraHook\n\tfn()\n\tvar fs fileStat"},
		"statNolog helper dereference-assigning fileStat pointer": {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "var sharedFS fileStat\nfunc clobberFS(dst *fileStat) { *dst = sharedFS }\nfunc statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat\n\tclobberFS(&fs)"},
		"Getwd returning sentinel error without call provenance":  {"func Getwd() (string, error) {\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}", "func Getwd() (string, error) {\n\terr := ErrInvalid\n\tif err != nil {\n\t\treturn \"\", err\n\t}\n\tdir, err2 := syscall.Getwd()\n\treturn dir, err2\n}"},
		"Getwd returning const error under unverified err guard":  {"func Getwd() (string, error) {\n\tdir, err := syscall.Getwd()\n\treturn dir, err\n}", "func Getwd() (string, error) {\n\terr := ErrInvalid\n\tif err != nil {\n\t\treturn \"\", syscall.ENOSYS\n\t}\n\tdir, err2 := syscall.Getwd()\n\treturn dir, err2\n}"},
		"Getwd jumping via goto into post-call error guard":       {"\t\tfd, err := openDirNolog(parent)\n\t\tif err != nil {\n\t\t\treturn \"\", err\n\t\t}", "\t\tif len(parent) > 0 {\n\t\t\terr = ErrInvalid\n\t\t\tgoto Bail\n\t\t}\n\t\tfd, err := openDirNolog(parent)\n\tBail:\n\t\tif err != nil {\n\t\t\treturn \"\", err\n\t\t}"},
		"Getwd returning error from else branch of error guard":   {"\tgetwdCache.Lock()\n\tdir = getwdCache.dir", "\ttmp, lerr := lstatNolog(\".\")\n\t_ = tmp\n\tif lerr != nil {\n\t\treturn \"\", lerr\n\t} else {\n\t\treturn \"\", syscall.ENOSYS\n\t}\n\tgetwdCache.Lock()\n\tdir = getwdCache.dir"},
		"Getwd mutating error inside compound branch":             {"\tgetwdCache.Lock()\n\tdir = getwdCache.dir", "\ttmp, lerr := lstatNolog(\".\")\n\t_ = tmp\n\tif dot == nil {\n\t\tlerr = ErrInvalid\n\t}\n\tif lerr != nil {\n\t\treturn \"\", lerr\n\t}\n\tgetwdCache.Lock()\n\tdir = getwdCache.dir"},
		"Getwd poisoning getwdCache.dir in package helper":        {"var getwdCache struct {", "func poisonGetwdCache() { getwdCache.dir = \".\" }\nvar getwdCache struct {"},
		"Getwd mutating parent loop step":                         {"for parent := \"..\"; ; parent = \"../\" + parent {", "for parent := \"..\"; ; parent = \"/tmp\" {"},
		"Getwd reassigning parent inside climb loop":              {"\t\tfd, err := openDirNolog(parent)", "\t\tparent = \"/tmp\"\n\t\tfd, err := openDirNolog(parent)"},
		"statNolog referencing disjoint SameFile alt struct":      {"func statNolog(name string) (FileInfo, error) {\n\tvar fs fileStat", "func statNolog(name string) (FileInfo, error) {\n\tvar _ *altStat\n\tvar fs fileStat"},
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
		"blanked StopTestLog":              {"if err := m.deps.StopTestLog(); err != nil {\n\t\t\tpanic(err)\n\t\t}", "_ = m.deps.StopTestLog()"},
		"unchecked err StopTestLog":        {"if err := m.deps.StopTestLog(); err != nil {\n\t\t\tpanic(err)\n\t\t}", "err2 := m.deps.StopTestLog(); _ = err2"},
		"empty handler StopTestLog":        {"panic(err)", ""},
		"fmt-only handler StopTestLog":     {"import (\n", "import (\n\t\"fmt\"\n"},
		"exit-zero handler StopTestLog":    {"panic(err)", "os.Exit(0)"},
		"return-only handler StopTestLog":  {"panic(err)", "return 1"},
		"recover-swallowed StopTestLog":    {"flag.Parse()", "defer func() { _ = recover() }()\n\tflag.Parse()"},
		"dead-branch if false StopTestLog": {"if err := m.deps.StopTestLog(); err != nil {\n\t\t\tpanic(err)\n\t\t}", "if false { if err := m.deps.StopTestLog(); err != nil { os.Exit(2) } }"},
		"unguarded flag StopTestLog":       {"var testlog = flag.String(\"test.testlogfile\", \"\", \"\")", "var otherFlag bool\nvar testlog = flag.String(\"test.testlogfile\", \"\", \"\")"},
		"goto bypassing StopTestLog":       {"if err := m.deps.StopTestLog(); err != nil {\n\t\t\tpanic(err)\n\t\t}", "goto done; if err := m.deps.StopTestLog(); err != nil { os.Exit(2) }; done: ;"},
		"hardcoded os.Create path":         {"os.Create(*testlog)", "os.Create(\"log\")"},
		"missing f.Close after Stop":       {"if err := f.Close(); err != nil {\n\t\t\tos.Exit(2)\n\t\t}", "_ = f"},
		"unchecked f.Close after Stop":     {"if err := f.Close(); err != nil {\n\t\t\tos.Exit(2)\n\t\t}", "_ = f.Close()"},
		"flag dereference clobber":         {"flag.Parse()", "flag.Parse()\n\t*testlog = \"\""},
		"flag dereference address-taken":   {"flag.Parse()", "flag.Parse()\n\t_ = &*testlog"},
		"non-empty flag default":           {"flag.String(\"test.testlogfile\", \"\", \"\")", "flag.String(\"test.testlogfile\", \"x\", \"\")"},
		"missing flag.Parse in Run":        {"\tflag.Parse()\n", ""},
		"runner call before StartTestLog":       {"m.deps.StartTestLog(f)", "_ = runTests(m.tests)\n\t\tm.deps.StartTestLog(f)"},
		"runner call after StopTestLog":         {"\t\treturn 0\n", "\t\t_ = runTests(m.tests)\n\t\treturn 0\n"},
		"fallthrough to runner after StopTestLog": {"\t\treturn 0\n", ""},
		"os.Exit(1) before StopTestLog":              {"_ = runTests(m.tests)", "if !runTests(m.tests) { os.Exit(1) }"},
		"missing Context method":                {"func (c *common) Context() context.Context { c.checkFuzzFn(\"Context\"); return c.ctx }", ""},
		"flag pointer alias clobber":            {"flag.Parse()", "flag.Parse()\n\talias := testlog; *alias = \"\""},
		"flag pointer map key escape":           {"flag.Parse()", "flag.Parse()\n\t_ = map[any]int{testlog: 1}"},
		"flag.Set clobber":                      {"flag.Parse()", "flag.Parse()\n\t_ = flag.Set(\"test.testlogfile\", \"\")"},
		"flag.CommandLine.Set clobber":          {"flag.Parse()", "flag.Parse()\n\t_ = flag.CommandLine.Set(\"test.testlogfile\", \"\")"},
		"duplicate test.testlogfile flag":       {"var testlog = flag.String(\"test.testlogfile\", \"\", \"\")", "var testlog = flag.String(\"test.testlogfile\", \"\", \"\")\nvar testlog2 = flag.String(\"test.testlogfile\", \"\", \"\")"},
		"runTests mimicking runExample os.Exit": {"\treturn true\n}", "\tif _, err := os.OpenFile(\"x\", 0, 0); err != nil {\n\t\tos.Exit(1)\n\t}\n\treturn true\n}"},
		"tRunner calling os.Exit(1)":            {"func runTests(", "func tRunner() { os.Exit(1) }\nfunc runTests("},
		"init calling os.Exit(1)":               {"func MainStart(", "func init() { os.Exit(1) }\nfunc MainStart("},
		"extra &M{} outside MainStart":          {"func MainStart(", "func rogueM(d testDeps) *M { return &M{deps: d} }\nfunc MainStart("},
		"new(M) allocation":                     {"func MainStart(", "func allocM() *M { return new(M) }\nfunc MainStart("},
		"mutating *m inside M method":           {"flag.Parse()", "*m = M{}\n\tflag.Parse()"},
		"M receiver map key escape":             {"flag.Parse()", "_ = map[any]int{m: 1}\n\tflag.Parse()"},
		"indented //go:linkname bypass":         {"package testing\n", "package testing\nimport _ \"unsafe\"\n\t//go:linkname MainStart runtime.evilMainStart\n"},
		"CR-embedded //go:linkname bypass":      {"package testing\n", "package testing\nimport _ \"unsafe\"\n//go:linkname f runtime.f\r//go:linkname MainStart runtime.evil\nfunc f()\n"},
		"BOM-prefixed //go:linkname bypass":     {"package testing\n", "\uFEFF//go:linkname MainStart runtime.evilMainStart\npackage testing\nimport _ \"unsafe\"\n"},
		"block /*go:linkname*/ directive":       {"package testing\n", "package testing\n/*go:linkname MainStart runtime.evil*/\n"},
		"wasmexport directive in testing":       {"package testing\n", "package testing\n//go:wasmexport EvilExport\nfunc EvilExport() {}\n"},
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
		"MainStart omitting Init()":                {"\tInit()\n", ""},
		"flag.Parse after m.before()":              {"\tif !flag.Parsed() {\n\t\tflag.Parse()\n\t}\n", ""},
		"pre-before zero return outside matchList": {"if *matchList != \"\" {", "if m.numRun > 99 {"},
		"pre-before return 2 clobbered by defer":   {"m.exitCode = 0\n\t\treturn", "return"},
		"go runTests outliving defer m.after()":    {"if !runTests(m.tests) {", "go runTests(m.tests)\n\tif false {"},
		"unconditional err return in before":       {"if *cpuProfile != \"\" {", "if err := io.EOF; err != nil {\n\t\treturn\n\t}\n\tif *cpuProfile != \"\" {"},
		"shadowed local testlogFile := f":          {"testlogFile = f", "testlogFile := f; _ = testlogFile"},
		"StopTestLog not first in writeProfiles":   {"func (m *M) writeProfiles() {\n", "func (m *M) writeProfiles() {\n\tif m.numRun < 0 { return }\n"},
		"burned m.afterOnce before after":          {"m.before()", "m.afterOnce.Do(func() {})\n\tm.before()"},
		"exported After method":                    {"after()", "After()"},
		"direct call to m.after() outside alarm":   {"m.startAlarm()", "m.after()\n\tm.startAlarm()"},
		"os.Exit(2) in M.Run skipping defer after": {"m.exitCode = 1\n\t\treturn", "os.Exit(2)"},
		"alarm FuncLit without panic":              {"\t\tpanic(\"test timed out\")\n", ""},
		"syscall.Exit(0) bypass":                             {"\"time\"", "\"syscall\"\n\t\"time\""},
		"syscall.RawSyscall SYS_EXIT bypass":                 {"m.numRun++", "m.numRun++"},
		"post-before helper calling os.Exit(1)":              {"m.startAlarm()", "helperExit()\n\tm.startAlarm()"},
		"post-before helper calling os.Exit via func value":  {"m.startAlarm()", "fn := helperExit; fn()\n\tm.startAlarm()"},
		"after helper calling os.Exit(1)":                    {"m.writeProfiles()", "helperExit()\n\t\tm.writeProfiles()"},
		"testlogFile map key escape":                         {"testlogFile = f", "testlogFile = f\n\t\t_ = map[any]int{testlogFile: 1}"},
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
	// the stale verdict under lp.digest.
	toctouPkg := writePkg("strings", map[string]string{
		"strings.go": "package strings\nfunc Clone(s string) string { return s }\n",
	})
	origDigest, err := digestFiles(t.Context(), toctouPkg.Dir, toctouPkg.Files)
	if err != nil {
		t.Fatal(err)
	}
	toctouPkg.digest = origDigest
	if err := os.WriteFile(filepath.Join(toctouPkg.Dir, "strings.go"), []byte("package strings\nimport \"os\"\nvar _ = os.Getenv(\"X\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	toctouSurface := sourceDigests{
		Packages:  map[string]string{"strings": origDigest},
		inventory: map[string]listedPackage{"strings": toctouPkg},
	}
	deg := toolchainSourceDegradation("go1.test", toctouSurface, nil)
	if deg.audited() || !strings.Contains(deg.axis, "could not be read") {
		t.Fatalf("TOCTOU degradation = %+v, want could not be read", deg)
	}
	if _, cached := verifiedPackageMemo.Load(verifiedPackageMemoKey("strings", origDigest)); cached {
		t.Fatal("TOCTOU verification failure poisoned verifiedPackageMemo")
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

func mustMutateFixture(t *testing.T, base, old, repl string) string {
	t.Helper()
	if !strings.Contains(base, old) {
		t.Fatalf("mustMutateFixture: substring %q not found in baseline fixture", old)
	}
	return strings.Replace(base, old, repl, 1)
}

const syntheticInternalTestlogSrc = `package testlog
import "sync/atomic"
type Interface interface {
	Getenv(string)
	Stat(string)
	Open(string)
	Chdir(string)
}
var logger atomic.Pointer[Interface]
func SetLogger(impl Interface) {
	if !logger.CompareAndSwap(nil, &impl) {
		panic("testlog: SetLogger must be called only once")
	}
}
func Logger() Interface {
	impl := logger.Load()
	if impl == nil {
		return nil
	}
	return *impl
}
func Getenv(name string) {
	if log := Logger(); log != nil {
		log.Getenv(name)
	}
}
func Open(name string) {
	if log := Logger(); log != nil {
		log.Open(name)
	}
}
func Stat(name string) {
	if log := Logger(); log != nil {
		log.Stat(name)
	}
}
func Chdir(name string) {
	if log := Logger(); log != nil {
		log.Chdir(name)
	}
}
`

const syntheticOSSrc = `package os
import (
	"errors"
	"internal/testlog"
	"io"
	"syscall"
)
var ErrInvalid = errors.New("invalid argument")
var ErrClosed = errors.New("file already closed")
type PathError struct {
	Op   string
	Path string
	Err  error
}
func (e *PathError) Error() string { return e.Op }
type pollFD struct {
	Sysfd int
}
func (fd *pollFD) Read(p []byte) (int, error)  { return 0, io.EOF }
func (fd *pollFD) Write(p []byte) (int, error) { return len(p), nil }
func (fd *pollFD) Close() error                { return nil }
type file struct {
	pfd  pollFD
	name string
}
type File struct {
	*file
}
func newFile(fd int, name string) *File {
	return &File{&file{pfd: pollFD{Sysfd: fd}, name: name}}
}
func Exit(code int) {
	if code == 0 && testlog.PanicOnExit0() {
		panic("os.Exit(0)")
	}
	syscall.Exit(code)
}
func Getenv(key string) string {
	testlog.Getenv(key)
	return ""
}
func LookupEnv(key string) (string, bool) {
	testlog.Getenv(key)
	return "", false
}
func Open(name string) (*File, error) {
	return OpenFile(name, 0, 0)
}
func Create(name string) (*File, error) {
	return OpenFile(name, 1, 0o666)
}
func OpenFile(name string, flag int, perm uint32) (*File, error) {
	testlog.Open(name)
	return openFileNolog(name, flag, perm)
}
func openFileNolog(name string, flag int, perm uint32) (*File, error) {
	r, err := syscall.Open(name, flag, perm)
	if err != nil {
		return nil, &PathError{Op: "open", Path: name, Err: err}
	}
	return newFile(r, name), nil
}
func openDir(name string) (*File, error) {
	testlog.Open(name)
	return &File{&file{name: name}}, nil
}
func statOrZero(f *File) int64 {
	return 0
}
func readFileContents(statSize int64, read func([]byte) (int, error)) ([]byte, error) {
	var buf [1]byte
	_, err := read(buf[:])
	if err == io.EOF {
		return nil, nil
	}
	return nil, err
}
func (f *File) Read(b []byte) (int, error) {
	if err := f.checkValid("read"); err != nil {
		return 0, err
	}
	return f.pfd.Read(b)
}
func ReadFile(name string) ([]byte, error) {
	f, err := Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readFileContents(statOrZero(f), f.Read)
}
func ReadDir(name string) ([]any, error) {
	f, err := openDir(name)
	_ = f
	return nil, err
}
func Stat(name string) (any, error) {
	testlog.Stat(name)
	return nil, nil
}
func Lstat(name string) (any, error) {
	testlog.Stat(name)
	return nil, nil
}
func Getwd() (string, error) {
	dir, err := syscall.Getwd()
	return dir, err
}
func Chdir(dir string) error {
	if e := syscall.Chdir(dir); e != nil {
		testlog.Open(dir)
		return &PathError{Op: "chdir", Path: dir, Err: e}
	}
	if log := testlog.Logger(); log != nil {
		wd, err := Getwd()
		if err == nil {
			log.Chdir(wd)
		}
	}
	return nil
}
func (f *File) checkValid(op string) error {
	if f == nil {
		return ErrInvalid
	}
	return nil
}
func (f *File) wrapErr(op string, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	return &PathError{Op: op, Path: f.name, Err: err}
}
func (f *File) Write(b []byte) (n int, err error) {
	if err := f.checkValid("write"); err != nil {
		return 0, err
	}
	n, e := f.write(b)
	if n < 0 {
		n = 0
	}
	if n != len(b) {
		err = io.ErrShortWrite
	}
	if e != nil {
		err = f.wrapErr("write", e)
	}
	return n, err
}
func (f *File) WriteString(s string) (n int, err error) {
	return f.Write([]byte(s))
}
func (f *File) write(b []byte) (n int, err error) {
	n, err = f.pfd.Write(b)
	return n, err
}
func (f *File) Fd() uintptr {
	return f.fd()
}
func (f *File) fd() uintptr {
	if f == nil {
		return ^(uintptr(0))
	}
	return uintptr(f.pfd.Sysfd)
}
func (f *File) Close() error {
	if f == nil {
		return ErrInvalid
	}
	return f.file.close()
}
func (file *file) close() error {
	if file == nil {
		return syscall.EINVAL
	}
	var err error
	if e := file.pfd.Close(); e != nil {
		err = &PathError{Op: "close", Path: file.name, Err: e}
	}
	return err
}
`

const syntheticBufioSrc = `package bufio
import "io"
const defaultBufSize = 4096
type Writer struct {
	err error
	buf []byte
	n   int
	wr  io.Writer
}
func NewWriterSize(w io.Writer, size int) *Writer {
	b, ok := w.(*Writer)
	if ok && len(b.buf) >= size {
		return b
	}
	if size <= 0 {
		size = defaultBufSize
	}
	return &Writer{
		buf: make([]byte, size),
		wr:  w,
	}
}
func NewWriter(w io.Writer) *Writer {
	return NewWriterSize(w, defaultBufSize)
}
func (b *Writer) Available() int { return len(b.buf) - b.n }
func (b *Writer) Buffered() int  { return b.n }
func (b *Writer) Flush() error {
	if b.err != nil {
		return b.err
	}
	if b.n == 0 {
		return nil
	}
	n, err := b.wr.Write(b.buf[0:b.n])
	if n < b.n && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		if n > 0 && n < b.n {
			copy(b.buf[0:b.n-n], b.buf[n:b.n])
		}
		b.n -= n
		b.err = err
		return err
	}
	b.n = 0
	return nil
}
func (b *Writer) WriteByte(c byte) error {
	if b.err != nil {
		return b.err
	}
	if b.Available() <= 0 && b.Flush() != nil {
		return b.err
	}
	b.buf[b.n] = c
	b.n++
	return nil
}
func (b *Writer) WriteString(s string) (int, error) {
	var sw io.StringWriter
	tryStringWriter := true
	nn := 0
	for len(s) > b.Available() && b.err == nil {
		var n int
		if b.Buffered() == 0 && sw == nil && tryStringWriter {
			sw, tryStringWriter = b.wr.(io.StringWriter)
		}
		if b.Buffered() == 0 && tryStringWriter {
			n, b.err = sw.WriteString(s)
		} else {
			n = copy(b.buf[b.n:], s)
			b.n += n
			b.Flush()
		}
		nn += n
		s = s[n:]
	}
	if b.err != nil {
		return nn, b.err
	}
	n := copy(b.buf[b.n:], s)
	b.n += n
	nn += n
	return nn, nil
}
`

const syntheticTestdepsSrc = `package testdeps
import (
	"bufio"
	"internal/testlog"
	"io"
	"strings"
	"sync"
)
type TestDeps struct{}
type testLog struct {
	mu  sync.Mutex
	w   *bufio.Writer
	set bool
}
func (l *testLog) Getenv(key string) { l.add("getenv", key) }
func (l *testLog) Open(name string)  { l.add("open", name) }
func (l *testLog) Stat(name string)  { l.add("stat", name) }
func (l *testLog) Chdir(name string) { l.add("chdir", name) }
func (l *testLog) add(op, name string) {
	if strings.Contains(name, "\n") || name == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w == nil {
		return
	}
	l.w.WriteString(op)
	l.w.WriteByte(' ')
	l.w.WriteString(name)
	l.w.WriteByte('\n')
}
var log testLog
func (TestDeps) StartTestLog(w io.Writer) {
	log.mu.Lock()
	log.w = bufio.NewWriter(w)
	if !log.set {
		log.set = true
		testlog.SetLogger(&log)
		log.w.WriteString("# test log\n")
	}
	log.mu.Unlock()
}
func (TestDeps) StopTestLog() error {
	log.mu.Lock()
	defer log.mu.Unlock()
	err := log.w.Flush()
	log.w = nil
	return err
}
`

const syntheticTestingInlineSrc = `package testing
import (
	"context"
	"flag"
	"io"
	"os"
)
var testlog = flag.String("test.testlogfile", "", "")
type common struct{ ctx context.Context }
func (c *common) checkFuzzFn(string) {}
func (c *common) Context() context.Context { c.checkFuzzFn("Context"); return c.ctx }
type testDeps interface {
	StartTestLog(io.Writer)
	StopTestLog() error
}
type M struct {
	deps  testDeps
	tests []InternalTest
}
type InternalTest struct {
	Name string
	F    func(*T)
}
type T struct{ common }
func MainStart(d testDeps) *M { return &M{deps: d} }
func runTests(tests []InternalTest) bool {
	for _, it := range tests {
		it.F(&T{})
	}
	return true
}
func (m *M) Run() int {
	flag.Parse()
	if *testlog != "" {
		f, err := os.Create(*testlog)
		if err != nil {
			os.Exit(2)
		}
		m.deps.StartTestLog(f)
		_ = runTests(m.tests)
		if err := m.deps.StopTestLog(); err != nil {
			panic(err)
		}
		if err := f.Close(); err != nil {
			os.Exit(2)
		}
		return 0
	}
	_ = runTests(m.tests)
	return 0
}
`

const syntheticTestingSplitSrc = `package testing
import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)
var (
	initRan     bool
	testlog     *string
	matchList   *string
	cpuProfile  *string
	testlogFile *os.File
)
func Init() {
	if initRan {
		return
	}
	initRan = true
	testlog = flag.String("test.testlogfile", "", "")
	matchList = flag.String("test.list", "", "")
	cpuProfile = flag.String("test.cpuprofile", "", "")
}
type common struct{ ctx context.Context }
func (c *common) checkFuzzFn(string) {}
func (c *common) Context() context.Context { c.checkFuzzFn("Context"); return c.ctx }
type testDeps interface {
	StartTestLog(io.Writer)
	StopTestLog() error
}
type M struct {
	deps      testDeps
	tests     []InternalTest
	afterOnce sync.Once
	exitCode  int
	numRun    int
}
type InternalTest struct {
	Name string
	F    func(*T)
}
type T struct{ common }
func MainStart(d testDeps, tests []InternalTest) *M {
	Init()
	return &M{deps: d, tests: tests}
}
func runTests(tests []InternalTest) bool {
	for _, it := range tests {
		it.F(&T{})
	}
	return true
}
func (m *M) Run() (code int) {
	defer func() {
		code = m.exitCode
	}()
	m.numRun++
	if !flag.Parsed() {
		flag.Parse()
	}
	if *matchList != "" {
		m.exitCode = 0
		return
	}
	m.before()
	defer m.after()
	m.startAlarm()
	if !runTests(m.tests) {
		m.exitCode = 1
		return
	}
	m.exitCode = 0
	return
}
func (m *M) before() {
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return
		}
		_ = f.Close()
	}
	if *testlog != "" {
		f, err := os.Create(*testlog)
		if err != nil {
			os.Exit(2)
		}
		m.deps.StartTestLog(f)
		testlogFile = f
	}
}
func (m *M) after() {
	m.afterOnce.Do(func() {
		m.writeProfiles()
	})
}
func (m *M) writeProfiles() {
	if *testlog != "" {
		if err := m.deps.StopTestLog(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
		if err := testlogFile.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(2)
		}
	}
	if *cpuProfile != "" {
		coverReport()
	}
}
func coverReport() {
	if _, err := os.Create("cov"); err != nil {
		os.Exit(2)
	}
}
func (m *M) startAlarm() {
	_ = time.AfterFunc(time.Minute, func() {
		m.after()
		panic("test timed out")
	})
}
`

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
			"asm.s": "#define B0 a\n#define B0 b\n#define B1 a\n#define B1 b\n#define B2 a\n#define B2 b\n#define B3 a\n#define B3 b\n#define B4 a\n#define B4 b\n#define B5 a\n#define B5 b\n#define B6 a\n#define B6 b\n#define B7 a\n#define B7 b\n#define B8 a\n#define B8 b\nTEXT ·f(SB),$0-0\n\tNOP B0 B1 B2 B3 B4 B5 B6 B7 B8\n\tRET\n",
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




