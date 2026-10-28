package closure

import (
	"context"
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
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
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
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
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

	unlistedInternalPure := writePkg("strings", map[string]string{
		"strings.go": "package strings\nimport \"internal/poll\"\nvar _ = poll.ErrNetClosing\n",
	})
	if err := verifyListedPackage(unlistedInternalPure); err == nil {
		t.Fatal("pure package importing unlisted internal/poll admitted")
	}

	badDelegateImport := writePkg("internal/bytealg", map[string]string{
		"bytealg.go": "package bytealg\nimport \"os\"\nvar _ = os.Getenv\n",
	})
	if err := verifyListedPackage(badDelegateImport); err == nil {
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
		"two-arg unapproved": "package strings\nimport _ \"unsafe\"\n//go:linkname secret runtime.getAuxv\nfunc secret() uintptr\n",
		"one-arg unapproved": "package strings\nimport _ \"unsafe\"\n//go:linkname ExportedSecret\nfunc ExportedSecret() {}\n",
		"wasmimport":         "package strings\n//go:wasmimport env clock\nfunc clock() int64\n",
		"cgo directive":      "package strings\n//go:cgo_import_dynamic libc_open open \"libc.so\"\n",
		"fmt Println":        "package strings\nimport \"fmt\"\nfunc f() { fmt.Println(\"leak\") }\n",
		"fmt aliased":        "package strings\nimport f \"fmt\"\nvar _ = f.Sprintf(\"x\")\n",
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
		if err := verifyListedPackage(pkg); err == nil {
			t.Fatalf("delegate package violation %s admitted", name)
		}
	}

	validJsonV2TimeUnixUTC := writePkg("encoding/json/v2", map[string]string{
		"time.go": "package json\nimport \"time\"\nvar _ = time.Unix(0, 0).UTC()\n",
	})
	if err := verifyListedPackage(validJsonV2TimeUnixUTC); err != nil {
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
		"os.go": "package os\nimport \"internal/testlog\"\nfunc Getenv(k string) string { testlog.Getenv(k); return \"\" }\nfunc LookupEnv(k string) (string, bool) { testlog.Getenv(k); return \"\", false }\nfunc OpenFile(n string) { testlog.Open(n) }\nfunc openDir(n string) { testlog.Open(n) }\nfunc Stat(n string) { testlog.Stat(n) }\nfunc Lstat(n string) { testlog.Stat(n) }\nfunc Chdir(d string) error { testlog.Open(d); testlog.Logger().Chdir(d); return nil }\n",
	})
	if err := verifyListedPackage(validOS); err != nil {
		t.Fatalf("valid os package refused: %v", err)
	}

	badOSMissingLookupEnv := writePkg("os", map[string]string{
		"os.go": "package os\nimport \"internal/testlog\"\nfunc Getenv(k string) string { testlog.Getenv(k); return \"\" }\nfunc OpenFile(n string) { testlog.Open(n) }\nfunc openDir(n string) { testlog.Open(n) }\nfunc Stat(n string) { testlog.Stat(n) }\nfunc Lstat(n string) { testlog.Stat(n) }\nfunc Chdir(d string) error { testlog.Open(d); testlog.Logger().Chdir(d); return nil }\n",
	})
	if err := verifyListedPackage(badOSMissingLookupEnv); err == nil {
		t.Fatal("os package missing LookupEnv admitted")
	}

	badOSChdirMissingOpen := writePkg("os", map[string]string{
		"os.go": "package os\nimport \"internal/testlog\"\nfunc Getenv(k string) string { testlog.Getenv(k); return \"\" }\nfunc LookupEnv(k string) (string, bool) { testlog.Getenv(k); return \"\", false }\nfunc OpenFile(n string) { testlog.Open(n) }\nfunc openDir(n string) { testlog.Open(n) }\nfunc Stat(n string) { testlog.Stat(n) }\nfunc Lstat(n string) { testlog.Stat(n) }\nfunc Chdir(d string) error { testlog.Logger().Chdir(d); return nil }\n",
	})
	if err := verifyListedPackage(badOSChdirMissingOpen); err == nil {
		t.Fatal("os package Chdir missing testlog.Open admitted")
	}

	badOSMissingHook := writePkg("os", map[string]string{
		"os.go": "package os\nimport \"internal/testlog\"\nfunc hooks() { testlog.Open(\"a\") }\n",
	})
	if err := verifyListedPackage(badOSMissingHook); err == nil {
		t.Fatal("os package missing testlog hooks admitted")
	}

	badOSSyscallChdirOnly := writePkg("os", map[string]string{
		"os.go": "package os\nimport (\"internal/testlog\"; \"syscall\")\nfunc hooks() { testlog.Open(\"a\"); testlog.Stat(\"b\"); testlog.Getenv(\"c\"); _ = testlog.Logger(); _ = syscall.Chdir(\"d\") }\n",
	})
	if err := verifyListedPackage(badOSSyscallChdirOnly); err == nil {
		t.Fatal("os package with only syscall.Chdir and no testlog Chdir hook admitted")
	}

	badOSUnhookedGetenv := writePkg("os", map[string]string{
		"os.go": "package os\nimport \"internal/testlog\"\nfunc Getenv(k string) string { return \"\" }\nfunc other() { testlog.Open(\"a\"); testlog.Stat(\"b\"); testlog.Getenv(\"c\"); testlog.Logger().Chdir(\"d\") }\n",
	})
	if err := verifyListedPackage(badOSUnhookedGetenv); err == nil {
		t.Fatal("os package with unhooked Getenv function admitted")
	}

	validTestdeps := writePkg("testing/internal/testdeps", map[string]string{
		"deps.go": "package testdeps\nimport \"internal/testlog\"\nfunc StartTestLog() { testlog.SetLogger(nil) }\nfunc StopTestLog() error { w.Flush(); return nil }\n",
	})
	if err := verifyListedPackage(validTestdeps); err != nil {
		t.Fatalf("valid testdeps package refused: %v", err)
	}

	validTestingStock := writePkg("testing", map[string]string{
		"testing.go": "package testing\nfunc run() { deps.StartTestLog(nil); if err := deps.StopTestLog(); err != nil { panic(err) } }\n",
	})
	if err := verifyListedPackage(validTestingStock); err != nil {
		t.Fatalf("valid stock testing package refused: %v", err)
	}

	discardedStopTesting := writePkg("testing", map[string]string{
		"testing.go": "package testing\nfunc run() { deps.StartTestLog(nil); _ = deps.StopTestLog() }\n",
	})
	if err := verifyListedPackage(discardedStopTesting); err == nil {
		t.Fatal("testing package discarding StopTestLog error admitted")
	}

	validTestingDst := writePkg("testing", map[string]string{
		"testing.go":    "package testing\nfunc run() { deps.StartTestLog(dstWrapTestlogWriter(nil)); if err := deps.StopTestLog(); err != nil { panic(err) } }\n",
		"dst_hostio.go": "package testing\nfunc dstHostStreamWrite(fd int, header, payload []byte) (int, error) { return 0, nil }\nfunc (w *dstTestlogWriter) writeFromBubble(p []byte) (int, error) { n, err := dstHostStreamWrite(0, nil, p); return n, err }\n",
	})
	if err := verifyListedPackage(validTestingDst); err != nil {
		t.Fatalf("valid repaired godst testing package refused: %v", err)
	}

	unwrappedTestingDst := writePkg("testing", map[string]string{
		"testing.go":    "package testing\nfunc run() { deps.StartTestLog(nil); if err := deps.StopTestLog(); err != nil { panic(err) } }\n",
		"dst_hostio.go": "package testing\nfunc dstHostStreamWrite(fd int, header, payload []byte) (int, error) { return 0, nil }\nfunc (w *dstTestlogWriter) writeFromBubble(p []byte) (int, error) { n, err := dstHostStreamWrite(0, nil, p); return n, err }\n",
	})
	if err := verifyListedPackage(unwrappedTestingDst); err == nil {
		t.Fatal("godst testing package without dstWrapTestlogWriter admitted")
	}

	brokenTestingDst := writePkg("testing", map[string]string{
		"testing.go":    "package testing\nfunc run() { deps.StartTestLog(dstWrapTestlogWriter(nil)); if err := deps.StopTestLog(); err != nil { panic(err) } }\n",
		"dst_hostio.go": "package testing\nfunc dstHostStreamWrite(fd int, header, payload []byte) {}\nfunc (w *dstTestlogWriter) writeFromBubble(p []byte) (int, error) { return 0, nil }\n",
	})
	if err := verifyListedPackage(brokenTestingDst); err == nil {
		t.Fatal("broken godst testing package dropping write errors admitted")
	}

	missingFnTestingDst := writePkg("testing", map[string]string{
		"testing.go":    "package testing\nfunc run() { deps.StartTestLog(dstWrapTestlogWriter(nil)); if err := deps.StopTestLog(); err != nil { panic(err) } }\n",
		"dst_hostio.go": "package testing\nfunc otherHelper() {}\n",
	})
	if err := verifyListedPackage(missingFnTestingDst); err == nil {
		t.Fatal("testing package with dst_hostio.go missing dstHostStreamWrite admitted")
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
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
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
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
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
		verifiedPackageMemo.Store(verifiedPackageMemoKey(root, d), true)
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
		if strings.HasPrefix(body, "package "+pkgName+"\n") && !strings.Contains(body, "import") && !strings.Contains(body, "//") {
			src = body
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

		// Exercise observation-premises verification directly (os, testing, testing/internal/testdeps)
		// without pre-verified memo short-circuiting.
		osDir := filepath.Join(dir, "os")
		testingDir := filepath.Join(dir, "testing")
		testdepsDir := filepath.Join(dir, "testdeps")
		for _, sub := range []string{osDir, testingDir, testdepsDir} {
			if err := os.MkdirAll(sub, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		osSrc := "package os\nimport \"internal/testlog\"\nfunc Getenv(k string) string { testlog.Getenv(k); return \"\" }\nfunc LookupEnv(k string) (string, bool) { testlog.Getenv(k); return \"\", false }\nfunc OpenFile(n string) { testlog.Open(n) }\nfunc openDir(n string) { testlog.Open(n) }\nfunc Stat(n string) { testlog.Stat(n) }\nfunc Lstat(n string) { testlog.Stat(n) }\nfunc Chdir(n string) { testlog.Logger(); testlog.Open(n); testlog.Chdir(n) }\n"
		testingSrc := "package testing\ntype M struct{ d interface{ StartTestLog(any); StopTestLog() error } }\nfunc (m *M) Run() int { m.d.StartTestLog(nil); err := m.d.StopTestLog(); if err != nil { return 1 }; return 0 }\n"
		testdepsSrc := "package testdeps\nimport \"internal/testlog\"\nfunc StartTestLog(w any) { testlog.SetLogger(nil) }\nfunc StopTestLog() error { var w interface{ Flush() error }; return w.Flush() }\n"
		if err := os.WriteFile(filepath.Join(osDir, "os.go"), []byte(osSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(testingDir, "testing.go"), []byte(testingSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(testdepsDir, "testdeps.go"), []byte(testdepsSrc), 0o644); err != nil {
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
		// Intact surface (including live-verified os, testing, and testing/internal/testdeps) passes verification.
		pkgs[pkgName] = d2
		inv[pkgName] = listedPackage{ImportPath: pkgName, Dir: dir, Files: sel, Audited: true, digest: d2}
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
		// Breaking a harness observation premise in testing/internal/testdeps triggers degradation.
		brokenTestdepsSrc := "package testdeps\nimport \"internal/testlog\"\nfunc StartTestLog(w any) { testlog.SetLogger(nil) }\nfunc StopTestLog() {}\n"
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

