package closure

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

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
	base, err := digestFiles(dir, []string{"a.go", "b.go", "c.s"})
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := digestFiles(dir, []string{"a.go", "b.go", "c.s"}); again != base {
		t.Fatal("the digest is not a function of the files")
	}
	if reordered, _ := digestFiles(dir, []string{"c.s", "a.go", "b.go"}); reordered == base {
		t.Fatal("file order is part of the digest; the caller sorts, so a reordering must move it")
	}
	if fewer, _ := digestFiles(dir, []string{"a.go", "b.go"}); fewer == base {
		t.Fatal("dropping a file left the digest unchanged")
	}
	write("b.go", "package p\n\nfunc B() int { return 1 }\n")
	if edited, _ := digestFiles(dir, []string{"a.go", "b.go", "c.s"}); edited == base {
		t.Fatal("editing a file left the digest unchanged")
	}
	if _, err := digestFiles(dir, []string{"a.go", "missing.go"}); err == nil {
		t.Fatal("an unreadable file digested instead of refusing")
	}
	// The name is part of the content: a file renamed with the same
	// bytes moves the digest (the walk reads names).
	write("d.go", "package p\n")
	one, _ := digestFiles(dir, []string{"a.go"})
	other, _ := digestFiles(dir, []string{"d.go"})
	if one == other {
		t.Fatal("two files of identical bytes under different names digest alike")
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
	for _, must := range []string{"strings", "fmt", "sync", "sync/atomic", "testing", "reflect", "time", "net/url", "path/filepath", "flag", "os", "syscall", "encoding/json", "runtime"} {
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
	l := surfaceListing{Version: sourceDigestsVersion, Packages: []listedPackage{{ImportPath: "p", Dir: dir, Files: files, Dirs: stamp()}}}
	if !stampsCurrent(l) {
		t.Fatal("an unchanged directory reads as stale")
	}
	stamps := l.Packages[0].Dirs
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
	l.Packages[0].Dirs = stamp()
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
	l.Packages[0].Dirs = stamp()
	write("data/y.txt", "y\n")
	if stampsCurrent(l) {
		t.Fatal("an entry added under an embedded file's directory served the stale listing")
	}
	if err := os.Remove(filepath.Join(dir, "data", "y.txt")); err != nil {
		t.Fatal(err)
	}
	l.Packages[0].Dirs = stamp()
	if err := os.Rename(filepath.Join(dir, "b.go"), filepath.Join(dir, "bb.go")); err != nil {
		t.Fatal(err)
	}
	if stampsCurrent(l) {
		t.Fatal("a renamed entry served the stale listing")
	}
	if err := os.Rename(filepath.Join(dir, "bb.go"), filepath.Join(dir, "b.go")); err != nil {
		t.Fatal(err)
	}
	l.Packages[0].Dirs = stamp()
	if err := os.Remove(filepath.Join(dir, "a.go")); err != nil {
		t.Fatal(err)
	}
	if stampsCurrent(l) {
		t.Fatal("a removed entry served the stale listing")
	}
	l.Packages = append(l.Packages, listedPackage{ImportPath: "q", Dir: filepath.Join(dir, "gone"), Dirs: []dirStamp{{Path: filepath.Join(dir, "gone")}}})
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
	if want, _ := digestFiles(empty, nil); d.Packages["plugin"] != want {
		t.Fatalf("the empty selection digests %q, want the empty sequence %q", d.Packages["plugin"], want)
	}
}

// movedKeys judges per row chain: a row's chain (its own keys over its
// base's) must list EVERY key — a toolchain mixing two listed releases'
// packages is no listed toolchain, one release's race runtime over the
// other's files included: a selection's row is a delta over its own
// toolchain's row and admits nothing over another's; the closest
// chain names the refusal, sorted; with no row listed every key is
// moved.
func TestMovedKeysJudgePerRowChain(t *testing.T) {
	rows := []toolchainSourceRow{
		{Label: "go1.99.0", Packages: map[string]string{"a": "1", "b": "1", "c": "1", "runtime": "1"}},
		{Label: "go1.99.1", Base: "go1.99.0", Packages: map[string]string{"a": "2", "runtime": "2"}},
		{Label: "go1.99.0 race", Base: "go1.99.0", Packages: map[string]string{"c": "race", "runtime": "1r"}},
		{Label: "go1.99.1 race", Base: "go1.99.1", Packages: map[string]string{"c": "race", "runtime": "2r"}},
	}
	digests := func(a, b, c, r string) sourceDigests {
		return sourceDigests{Packages: map[string]string{"a": a, "b": b, "c": c, "runtime": r}}
	}
	for _, tc := range []struct {
		name    string
		d       sourceDigests
		moved   []string
		closest string
	}{
		{"the root row", digests("1", "1", "1", "1"), nil, "go1.99.0"},
		{"the delta row over its base", digests("2", "1", "1", "2"), nil, "go1.99.1"},
		{"each toolchain's race row over its own chain", digests("2", "1", "race", "2r"), nil, "go1.99.1 race"},
		{"the other toolchain's race row", digests("1", "1", "race", "1r"), nil, "go1.99.0 race"},
		{"one release's race runtime over the other's files refuses (a tie, the first race row named)", digests("2", "1", "race", "1r"), []string{"a"}, "go1.99.0 race"},
		{"a mix of two releases refuses (a tie names the first row)", digests("2", "1", "1", "1"), []string{"a"}, "go1.99.0"},
		{"a mix the other way", digests("1", "1", "1", "2"), []string{"runtime"}, "go1.99.0"},
		{"a mix closer to the delta row", digests("2", "9", "1", "2"), []string{"b"}, "go1.99.1"},
		{"the race seam under the default runtime", digests("1", "1", "race", "1"), []string{"c"}, "go1.99.0"},
		{"the closest row names the fewest moved, sorted", digests("3", "9", "1", "3"), []string{"a", "b", "runtime"}, "go1.99.0"},
	} {
		moved, closest := movedKeys(tc.d, rows)
		if !reflect.DeepEqual(moved, tc.moved) || closest != tc.closest {
			t.Errorf("%s: moved %v off %q, want %v off %q", tc.name, moved, closest, tc.moved, tc.closest)
		}
	}
	if moved, closest := movedKeys(digests("1", "1", "1", "1"), nil); !reflect.DeepEqual(moved, []string{"a", "b", "c", "runtime"}) || closest != "" {
		t.Fatalf("no rows: moved %v off %q", moved, closest)
	}
	if got := namedMoved([]string{"a", "b"}); got != "a, b" {
		t.Fatalf("namedMoved = %q", got)
	}
	packages := rowChain(rows, "go1.99.1")
	if packages["a"] != "2" || packages["b"] != "1" || packages["runtime"] != "2" {
		t.Fatalf("the chain resolves %v", packages)
	}
	if packages := rowChain(rows, "go1.99.1 race"); packages["a"] != "2" || packages["b"] != "1" || packages["c"] != "race" || packages["runtime"] != "2r" {
		t.Fatalf("the race row's chain resolves %v, want its seams over its toolchain's chain", packages)
	}
}

// validChains judges a listing's shape: labels unique, every Base
// naming a row, no chain cycling, every row listing at least one key
// (a root row's completeness is the canary's judgment over the running
// toolchain — no other host can judge it).
func validChains(rows []toolchainSourceRow) error {
	byLabel := map[string]toolchainSourceRow{}
	for _, row := range rows {
		if _, dup := byLabel[row.Label]; dup {
			return fmt.Errorf("label %q listed twice", row.Label)
		}
		if len(row.Packages) == 0 {
			return fmt.Errorf("row %q lists no key", row.Label)
		}
		byLabel[row.Label] = row
	}
	for _, row := range rows {
		seen := map[string]bool{}
		for label := row.Label; label != ""; label = byLabel[label].Base {
			if seen[label] {
				return fmt.Errorf("row %q: chain cycles at %q", row.Label, label)
			}
			seen[label] = true
			if _, ok := byLabel[label]; !ok {
				return fmt.Errorf("row %q: base %q names no row", row.Label, label)
			}
		}
	}
	return nil
}

// The listing's shape is the one rowChain relies on (validChains): a
// misspelled base would otherwise resolve to the delta row alone,
// refusing with a misleading closest row on the one host that could
// notice; the judgment is pinned over planted shapes and applied to
// the real listing (a source literal, so the pin judges every edit of
// it on every tier).
func TestToolchainSourceRowsFormValidChains(t *testing.T) {
	if err := validChains(auditedToolchainSources); err != nil {
		t.Fatalf("auditedToolchainSources: %v", err)
	}
	complete := toolchainSourceRow{Label: "go1.99.0", Packages: map[string]string{"a": "1"}}
	if err := validChains([]toolchainSourceRow{complete, {Label: "go1.99.1", Base: "go1.99.0", Packages: map[string]string{"a": "2"}}, {Label: "go1.99.1 race", Base: "go1.99.1", Packages: map[string]string{"a": "r"}}}); err != nil {
		t.Fatalf("a valid listing refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		rows []toolchainSourceRow
	}{
		{"a duplicated label", []toolchainSourceRow{complete, {Label: "go1.99.0", Packages: map[string]string{"a": "2"}}}},
		{"a misspelled base", []toolchainSourceRow{complete, {Label: "go1.99.1", Base: "go1.99.0 ", Packages: map[string]string{"a": "2"}}}},
		{"a cycle", []toolchainSourceRow{{Label: "x", Base: "y", Packages: map[string]string{"a": "1"}}, {Label: "y", Base: "x", Packages: map[string]string{"a": "2"}}}},
		{"a self-based row", []toolchainSourceRow{{Label: "x", Base: "x", Packages: map[string]string{"a": "1"}}}},
		{"an empty row", []toolchainSourceRow{complete, {Label: "go1.99.1", Base: "go1.99.0", Packages: map[string]string{}}}},
	} {
		if validChains(tc.rows) == nil {
			t.Errorf("%s admitted", tc.name)
		}
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
	if want, _ := digestFiles(pkgDir, []string{"strings.go"}); first.Packages["strings"] != want || listings != 1 {
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
	if want, _ := digestFiles(pkgDir, []string{"other.go", "strings.go"}); third.Packages["strings"] != want || third.Packages["strings"] == first.Packages["strings"] {
		t.Fatalf("the digest did not follow the moved tree: %q, want %q", third.Packages["strings"], want)
	}
	// A selected file edited in place: its stamp re-lists (the same
	// files selected) and the digest follows the new bytes.
	write("strings.go", "package strings\n\nfunc Edited() {}\n")
	fourth := read()
	if want, _ := digestFiles(pkgDir, []string{"other.go", "strings.go"}); fourth.Packages["strings"] != want || fourth.Packages["strings"] == third.Packages["strings"] {
		t.Fatalf("an edited selected file left the digest: %q, want %q", fourth.Packages["strings"], want)
	}
}
