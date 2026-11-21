package closure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/trace"
)

// The toolchain-source audit is keyed by CONTENT: each audited surface
// package's source, as the build selects it under the analysis'
// effective selection from the GOROOT in use, is digested and verified
// structurally against gofresh's boundary contracts
// (REQ-closure-observability-toolchain-key). The version string is diagnostic
// context, never the key: a rebuild of identical source (an experiment
// selecting no different file, a vendor flavor whose patches are tag-gated, a
// distro build, a point release off the audited surface) shares the same
// content digest, and a patched surface file moves its package's digest and
// re-runs structural verification whatever the version says.

// auditedSurfaceTables is the audited surface's own members: the union
// of every toolchain-source admission table's packages — the
// audited-pure set, the per-package symbol tables, the receiver tables
// (sync, reflect, time), the class-B operations' packages, the atomic
// transparency, the harness channels, and the linkname-target floor's
// packages (runtime, syscall) — so a table can never be added without
// its package joining the key — and the harness premise's own
// implementation (harnessPremisePackages: a listing asserts every
// test-log write the harness attempts lands or fails the binary, and
// the buffered writes with StopTestLog's flush error live in
// testing/internal/testdeps, which only the generated test main imports,
// so no table's dependencies reach it). Sorted, deduplicated.
func auditedSurfaceTables() []string {
	set := map[string]bool{"sync/atomic": true}
	for _, p := range harnessPremisePackages {
		set[p] = true
	}
	for _, p := range auditset.PurePackages() {
		set[p] = true
	}
	for _, p := range auditset.SymbolPackages() {
		set[p] = true
	}
	for _, p := range auditset.ReceiverPackages() {
		set[p] = true
	}
	for _, p := range auditset.ClassBPackages() {
		set[p] = true
	}
	for _, target := range auditset.AuditedLinknameTargets() {
		if i := strings.LastIndexByte(target, '.'); i > 0 {
			set[target[:i]] = true
		}
	}
	for target := range auditset.AuditedReadOnlyVarLinknameTargets() {
		if i := strings.LastIndexByte(target, '.'); i > 0 {
			set[target[:i]] = true
		}
	}
	return sortedKeys(set)
}

// implicitLinkPackages are the standard packages the go command links
// into a build without any dependency naming them — the detectors'
// runtimes under their sanitizer flags (the cgo bridge behind every
// cgo file's pseudo-import is different: the listing's Deps carry it
// wherever it is linked) — so they appear in no listing's dependency
// walk; they seed the surface whenever the listing carries them,
// under every selection (an over-wide surface only refuses more).
var implicitLinkPackages = []string{"runtime/race", "runtime/msan", "runtime/asan"}

// auditedSurface derives the audited surface over a standard-library
// listing: the tables' listed packages (a table may name a
// version-pinned module package — golang.org/x/sys/unix's class-B
// effects — whose source the module audits key, never the toolchain's;
// `go list std` never lists it), the link-time packages, and every
// standard package they reach — the listing's transitive dependencies
// (Deps, which carry what the pseudo-import C pulls) and imports, with
// no exclusion.
func auditedSurface(std []gotool.ListedPackage) []string {
	byPath := make(map[string]gotool.ListedPackage, len(std))
	for _, p := range std {
		byPath[p.ImportPath] = p
	}
	set := map[string]bool{}
	var queue []string
	for _, p := range surfaceSeeds() {
		if _, ok := byPath[p]; ok && !set[p] {
			set[p] = true
			queue = append(queue, p)
		}
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, dep := range append(append([]string(nil), byPath[p].Deps...), byPath[p].Imports...) {
			if _, ok := byPath[dep]; ok && !set[dep] {
				set[dep] = true
				queue = append(queue, dep)
			}
		}
	}
	return sortedKeys(set)
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sourceDigests separates the audited projection from the complete selected
// standard-library content and the admission policy governing this pass.
type sourceDigests struct {
	Packages      map[string]string
	Content       string
	Policy        string
	inventory     map[string]listedPackage
	pureDelegates map[string]bool
}

// surfaceListing is the memoized standard-library listing under one scope.
type surfaceListing struct {
	Version   int             `json:"version"`
	Packages  []listedPackage `json:"packages"`
	Discovery []dirStamp      `json:"discovery"`
	Integrity string          `json:"integrity"`
	plan      *discoveryPlan
}

type listedPackage struct {
	ImportPath string   `json:"importPath"`
	Dir        string   `json:"dir"`
	Files      []string `json:"files"`
	EmbedRoots []string `json:"embedRoots"`
	Audited    bool     `json:"audited"`
	digest     string
}

// dirStamp is one directory's entries at listing time: the package
// directory and every subdirectory a selected (embedded) file lives in.
type dirStamp struct {
	Path    string       `json:"path"`
	Entries []entryStamp `json:"entries"`
}

// entryStamp is one directory entry's identity at listing time: its
// name, kind, size, modification time and change time (nanoseconds).
type entryStamp struct {
	Name       string      `json:"name"`
	Type       os.FileMode `json:"type"`
	Size       int64       `json:"size"`
	ModTime    int64       `json:"modTime"`
	ChangeTime int64       `json:"changeTime"`
}

// sourceDigestsVersion versions the memoized listing record's shape and derivation.
const sourceDigestsVersion = 5

// surfaceSeeds are the audited surface's roots — every admission table's
// packages (auditedSurfaceTables) and the link-time packages.
func surfaceSeeds() []string {
	return append(auditedSurfaceTables(), implicitLinkPackages...)
}

const sourceDigestsDirName = "toolchain-source"

// harnessPremisePackages hold the testing harness's test-log pipeline.
var harnessPremisePackages = []string{"internal/testlog", "testing", "testing/internal/testdeps"}

// toolchainVerifierVersion versions the structural stdlib boundary verifier.
// Bumping this invalidates cached package verification verdicts and moves
// AdmissionPolicy.
const toolchainVerifierVersion = "gofresh/toolchain-verifier@22"

// selectedFiles are the non-test files the build selects for a package
// under the listing's selection, sorted by name; test files never.
func selectedFiles(p gotool.ListedPackage) []string {
	var files []string
	for _, class := range [][]string{p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles, p.SFiles, p.SwigFiles, p.SwigCXXFiles, p.SysoFiles, p.EmbedFiles} {
		files = append(files, class...)
	}
	sort.Strings(files)
	return slices.Compact(files)
}

// stampEntries stamps every entry of dir in name order, using an open
// directory handle so Unix platforms stat entries via fstatat on the open
// descriptor instead of re-walking the directory path per entry.
func stampEntries(dir string) ([]entryStamp, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	infos, err := f.Readdir(-1)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(infos, func(a, b os.FileInfo) int {
		return strings.Compare(a.Name(), b.Name())
	})
	stamps := make([]entryStamp, len(infos))
	for i, info := range infos {
		stamps[i] = entryStamp{
			Name:       info.Name(),
			Type:       info.Mode().Type(),
			Size:       info.Size(),
			ModTime:    info.ModTime().UnixNano(),
			ChangeTime: changeTime(info),
		}
	}
	return stamps, nil
}

func dirEntriesMatch(dir string, recorded []entryStamp) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()
	if len(recorded) == 0 {
		names, err := f.Readdirnames(1)
		if errors.Is(err, io.EOF) {
			return len(names) == 0, nil
		}
		if err != nil {
			return false, err
		}
		return false, nil
	}
	infos, err := f.Readdir(-1)
	if err != nil {
		return false, err
	}
	if len(infos) != len(recorded) {
		return false, nil
	}
	slices.SortFunc(infos, func(a, b os.FileInfo) int {
		return strings.Compare(a.Name(), b.Name())
	})
	for i, info := range infos {
		rec := recorded[i]
		if info.Name() != rec.Name || info.Mode().Type() != rec.Type || info.Size() != rec.Size || info.ModTime().UnixNano() != rec.ModTime || changeTime(info) != rec.ChangeTime {
			return false, nil
		}
	}
	return true, nil
}

// stampDirs stamps the package directory and every subdirectory a selected file lives in.
func stampDirs(dir string, files []string) ([]dirStamp, error) {
	set := map[string]bool{dir: true}
	for _, file := range files {
		set[filepath.Join(dir, filepath.Dir(file))] = true
	}
	var stamps []dirStamp
	for _, path := range sortedKeys(set) {
		entries, err := stampEntries(path)
		if err != nil {
			return nil, err
		}
		stamps = append(stamps, dirStamp{Path: path, Entries: entries})
	}
	return stamps, nil
}

func stdPackageGOROOT(dir, importPath string) (string, bool) {
	if dir == "" || importPath == "" {
		return "", false
	}
	cleanDir := filepath.Clean(dir)
	suffix := string(filepath.Separator) + filepath.Join("src", filepath.FromSlash(importPath))
	if !strings.HasSuffix(cleanDir, suffix) {
		return "", false
	}
	goroot := strings.TrimSuffix(cleanDir, suffix)
	if goroot == "" {
		goroot = string(filepath.Separator)
	}
	return goroot, true
}

func pkgIncludeRelativeFiles(ctx context.Context, pkgIncludeDir string) ([]string, error) {
	var out []string
	var walk func(absDir, relPrefix string) error
	walk = func(absDir, relPrefix string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, err := os.ReadDir(absDir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := entry.Name()
			if entry.IsDir() {
				if err := walk(filepath.Join(absDir, name), relPrefix+name+"/"); err != nil {
					return err
				}
				continue
			}
			out = append(out, relPrefix+name)
		}
		return nil
	}
	if err := walk(pkgIncludeDir, ""); err != nil {
		return nil, err
	}
	return out, nil
}

func resolvePkgIncludeDirAndFiles(ctx context.Context, goroot string) (pkgIncludeDir string, rels []string, notDir bool, ioErr error) {
	if goroot == "" {
		return "", nil, false, nil
	}
	pkgIncludeDir = filepath.Join(goroot, "pkg", "include")
	info, err := os.Stat(pkgIncludeDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, false, nil
		}
		return "", nil, false, err
	}
	if !info.IsDir() {
		return pkgIncludeDir, nil, true, nil
	}
	rels, err = pkgIncludeRelativeFiles(ctx, pkgIncludeDir)
	if err != nil {
		return "", nil, false, err
	}
	return pkgIncludeDir, rels, false, nil
}

// stampsCurrent reports whether every listed package's directories still carry
// exactly the entries they were listed over, each with its recorded stamp.
func stampsCurrent(l surfaceListing) bool {
	return stampsCurrentContext(context.Background(), l)
}

func hasNonSymlinkDirEntry(entries []entryStamp, name string) bool {
	i, found := slices.BinarySearchFunc(entries, name, func(e entryStamp, target string) int {
		return strings.Compare(e.Name, target)
	})
	return found && entries[i].Type.IsDir() && entries[i].Type&os.ModeSymlink == 0
}

type discoveryRootCheck struct {
	idx   int
	clean string
}

type discoveryPlan struct {
	hasSymlinkEntry    bool
	rootChecks         []discoveryRootCheck
	pending            []int
	hasPkgInclude      bool
	pkgInclude         string
	pkgIncludeRecorded bool
}

func buildDiscoveryPlan(l surfaceListing) *discoveryPlan {
	p := &discoveryPlan{}
	for _, d := range l.Discovery {
		for _, entry := range d.Entries {
			if entry.Type&os.ModeSymlink != 0 {
				p.hasSymlinkEntry = true
				return p
			}
		}
	}
	recorded := make(map[string][]entryStamp, len(l.Discovery))
	for i, d := range l.Discovery {
		clean := filepath.Clean(d.Path)
		parent := filepath.Dir(clean)
		if parentEntries, ok := recorded[parent]; ok && parent != clean && hasNonSymlinkDirEntry(parentEntries, filepath.Base(clean)) {
			recorded[clean] = d.Entries
			p.pending = append(p.pending, i)
			continue
		}
		p.rootChecks = append(p.rootChecks, discoveryRootCheck{idx: i, clean: clean})
		recorded[clean] = d.Entries
	}
	for _, pkg := range l.Packages {
		if goroot, ok := stdPackageGOROOT(pkg.Dir, pkg.ImportPath); ok {
			p.hasPkgInclude = true
			p.pkgInclude = filepath.Join(goroot, "pkg", "include")
			_, p.pkgIncludeRecorded = recorded[filepath.Clean(p.pkgInclude)]
			break
		}
	}
	return p
}

func stampsCurrentContext(ctx context.Context, l surfaceListing) bool {
	if !stampsTrusted {
		trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", "",
			trace.String("reason", "stamps_untrusted"),
		)
		return false
	}
	plan := l.plan
	if plan == nil {
		plan = buildDiscoveryPlan(l)
	}
	if plan.hasSymlinkEntry {
		trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", "",
			trace.String("reason", "uncacheable_discovery"),
		)
		return false
	}
	for _, rc := range plan.rootChecks {
		d := l.Discovery[rc.idx]
		resolved, err := filepath.EvalSymlinks(d.Path)
		if err != nil || resolved != rc.clean {
			trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", "",
				trace.String("reason", "uncacheable_discovery"),
			)
			return false
		}
		matched, err := dirEntriesMatch(d.Path, d.Entries)
		if err != nil {
			trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", d.Path,
				trace.String("reason", "read_error"),
				trace.Err(err),
			)
			return false
		}
		if !matched {
			if trace.Enabled(ctx, trace.DomainToolchain, d.Path) {
				if stamps, sErr := stampEntries(d.Path); sErr == nil {
					emitEntryStampMismatch(ctx, d.Path, d.Entries, stamps)
				}
			}
			return false
		}
	}
	pending := plan.pending
	workers := min(8, runtime.GOMAXPROCS(0), len(pending))
	if len(pending) <= 4 || workers <= 1 {
		for _, idx := range pending {
			d := l.Discovery[idx]
			matched, err := dirEntriesMatch(d.Path, d.Entries)
			if err != nil {
				trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", d.Path,
					trace.String("reason", "read_error"),
					trace.Err(err),
				)
				return false
			}
			if !matched {
				if trace.Enabled(ctx, trace.DomainToolchain, d.Path) {
					if stamps, sErr := stampEntries(d.Path); sErr == nil {
						emitEntryStampMismatch(ctx, d.Path, d.Entries, stamps)
					}
				}
				return false
			}
		}
	} else {
		type matchOutcome struct {
			done    bool
			matched bool
			err     error
		}
		outcomes := make([]matchOutcome, len(pending))
		var cursor atomic.Int64
		var stopAt atomic.Int64
		stopAt.Store(int64(len(pending)))
		var wg sync.WaitGroup
		wg.Add(workers)
		for range workers {
			go func() {
				defer wg.Done()
				for {
					pos := cursor.Add(1) - 1
					if pos >= stopAt.Load() {
						return
					}
					d := l.Discovery[pending[pos]]
					matched, err := dirEntriesMatch(d.Path, d.Entries)
					outcomes[pos] = matchOutcome{done: true, matched: matched, err: err}
					if err != nil || !matched {
						for {
							cur := stopAt.Load()
							if pos >= cur || stopAt.CompareAndSwap(cur, pos) {
								break
							}
						}
					}
				}
			}()
		}
		wg.Wait()
		for pos, idx := range pending {
			out := outcomes[pos]
			if !out.done {
				d := l.Discovery[idx]
				matched, err := dirEntriesMatch(d.Path, d.Entries)
				out = matchOutcome{done: true, matched: matched, err: err}
			}
			if out.err != nil {
				d := l.Discovery[idx]
				trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", d.Path,
					trace.String("reason", "read_error"),
					trace.Err(out.err),
				)
				return false
			}
			if !out.matched {
				d := l.Discovery[idx]
				if trace.Enabled(ctx, trace.DomainToolchain, d.Path) {
					if stamps, sErr := stampEntries(d.Path); sErr == nil {
						emitEntryStampMismatch(ctx, d.Path, d.Entries, stamps)
					}
				}
				return false
			}
		}
	}
	if plan.hasPkgInclude {
		pkgInclude := plan.pkgInclude
		if _, err := os.Lstat(pkgInclude); err == nil {
			if !plan.pkgIncludeRecorded {
				trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", pkgInclude,
					trace.String("reason", "missing_pkg_include_stamp"),
				)
				return false
			}
		} else if !os.IsNotExist(err) {
			trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", pkgInclude,
				trace.String("reason", "pkg_include_stat_error"),
				trace.Err(err),
			)
			return false
		}
	}
	return true
}

func emitEntryStampMismatch(ctx context.Context, dirPath string, recorded, current []entryStamp) {
	n := min(len(recorded), len(current))
	for i := range n {
		if recorded[i] == current[i] {
			continue
		}
		if recorded[i].Name == current[i].Name {
			trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", dirPath,
				trace.String("entry", recorded[i].Name),
				trace.String("reason", "entry_stamp_changed"),
				trace.Int64("recorded_size", recorded[i].Size),
				trace.Int64("current_size", current[i].Size),
				trace.Int64("recorded_mtime", recorded[i].ModTime),
				trace.Int64("current_mtime", current[i].ModTime),
				trace.Int64("recorded_ctime", recorded[i].ChangeTime),
				trace.Int64("current_ctime", current[i].ChangeTime),
				trace.Uint32("recorded_mode", uint32(recorded[i].Type)),
				trace.Uint32("current_mode", uint32(current[i].Type)),
			)
			return
		}
		trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", dirPath,
			trace.String("entry", recorded[i].Name),
			trace.String("current_entry", current[i].Name),
			trace.String("reason", "entry_set_changed"),
		)
		return
	}
	trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", dirPath,
		trace.String("reason", "entry_count_changed"),
		trace.Int("recorded_count", len(recorded)),
		trace.Int("current_count", len(current)),
	)
}

func cacheableDiscovery(l surfaceListing) bool {
	canonicalDirs := make(map[string]bool, len(l.Discovery))
	for _, d := range l.Discovery {
		for _, entry := range d.Entries {
			if entry.Type&os.ModeSymlink != 0 {
				return false
			}
		}
		clean := filepath.Clean(d.Path)
		parent := filepath.Dir(clean)
		if parent != clean && canonicalDirs[parent] {
			info, err := os.Lstat(clean)
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return false
			}
			canonicalDirs[clean] = true
			continue
		}
		resolved, err := filepath.EvalSymlinks(d.Path)
		if err != nil || resolved != clean {
			return false
		}
		canonicalDirs[clean] = true
	}
	return true
}

func listingIntegrity(scope string, l surfaceListing) string {
	l.Integrity = ""
	data, _ := json.Marshal(struct {
		Scope   string
		Listing surfaceListing
	}{scope, l})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func stampDiscovery(ctx context.Context, root string) ([]dirStamp, error) {
	return stampDiscoveryTree(ctx, root, false)
}

func stampDiscoveryTree(ctx context.Context, root string, packagesOnly bool) ([]dirStamp, error) {
	return stampDiscoveryTreeWithExisting(ctx, root, packagesOnly, nil)
}

func stampDiscoveryTreeWithExisting(ctx context.Context, root string, packagesOnly bool, existing map[string]dirStamp) ([]dirStamp, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var rootStamp dirStamp
	if d, ok := existing[root]; ok {
		rootStamp = d
	} else {
		entries, err := stampEntries(root)
		if err != nil {
			return nil, err
		}
		rootStamp = dirStamp{Path: root, Entries: entries}
	}
	dirs := []dirStamp{rootStamp}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if packagesOnly && entry.IsDir() {
			rel, _ := filepath.Rel(root, path)
			if excludedStandardDirectory(rel) {
				return filepath.SkipDir
			}
		}
		if !entry.IsDir() {
			return nil
		}
		if d, ok := existing[path]; ok {
			dirs = append(dirs, d)
			return nil
		}
		entries, err := stampEntries(path)
		if err != nil {
			return err
		}
		dirs = append(dirs, dirStamp{Path: path, Entries: entries})
		return nil
	})
	return dirs, err
}

func excludedStandardDirectory(relative string) bool {
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if parts[0] == "cmd" || strings.Contains(parts[0], ".") {
		return true
	}
	for _, part := range parts {
		if part == "testdata" || strings.HasPrefix(part, ".") || strings.HasPrefix(part, "_") {
			return true
		}
	}
	return false
}
