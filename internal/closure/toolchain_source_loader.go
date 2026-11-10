package closure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure/internal/listing"
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
// no exclusion: the implementation packages an audited body's
// behaviour rests on at any depth (encoding/json's v2 engine,
// crypto/sha256's fips140 core and the indicator it records to,
// net/http's vendored hpack) and the runtime itself, which every
// admission compiles against and where a vendor fork's hooks live. The
// derivation is mechanical so a delegate is never forgotten; an
// over-wide surface only refuses more, never admits more.
func auditedSurface(std []listing.Package) []string {
	byPath := make(map[string]listing.Package, len(std))
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

// surfaceListing is the memoized standard-library listing under one
// scope: per standard package its directory, the files the build
// selects for it, and the stamp of every
// entry of every directory a selected file lives in. A record serves
// only while every stamp holds (stampsCurrent): a file edited, added,
// removed, or renamed in any stamped directory — a patched GOROOT in
// place, a distro rebuild, a developer's tree — re-lists, so the memo
// never decides which bytes are compiled from a stale selection. While
// the listing's integrity and stamps hold, its selected-file digests may
// also be served from the companion digest memo keyed by the listing's
// integrity commitment.
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
// name, kind, size, modification time and change time (nanoseconds). The
// change time is the kernel's — an in-place edit, a rename over the
// entry, or a permission change moves it even when the modification
// time is restored — so a listing serves only over the directory
// contents it was taken over; a platform whose stat carries no change
// time never serves the memo (stampsTrusted).
type entryStamp struct {
	Name       string      `json:"name"`
	Type       os.FileMode `json:"type"`
	Size       int64       `json:"size"`
	ModTime    int64       `json:"modTime"`
	ChangeTime int64       `json:"changeTime"`
}

// sourceDigestsVersion versions the memoized listing record's shape
// and derivation: the walk over the seeds (auditedSurface's edge rule
// — which listing edges it follows, how a seed missing from std is
// treated), the file classes (selectedFiles), the stamp. An edit to
// any of those bumps it, or a warm record derived by the old rule is
// served until its stamps move. The surface rule's SEEDS ride the
// record's scope instead (toolchainSourceScope), so a seed edit keys
// its own records with no bump.
const sourceDigestsVersion = 5

// surfaceSeeds are the audited surface's roots — every admission
// table's packages (auditedSurfaceTables) and the link-time packages
// — the listing's dependency walk closes over; the listing memo's
// scope carries their digest.
func surfaceSeeds() []string {
	return append(auditedSurfaceTables(), implicitLinkPackages...)
}

const sourceDigestsDirName = "toolchain-source"

// selectedFiles are the non-test files the build selects for a package
// under the listing's selection, every class the compile or link reads
// — Go, cgo, C/C++/Objective-C/Fortran, headers, assembly, SWIG, object
// files, embedded files — sorted by name; test files never (a test file
// is no admission's source).
func selectedFiles(p listing.Package) []string {
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

// stampDirs stamps the package directory and every subdirectory a
// selected file lives in (an embedded file's), each once, in path
// order.
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

// stampsCurrent reports whether every listed package's directories
// still carry exactly the entries they were listed over, each with its
// recorded stamp; any difference, an unreadable directory included, is
// stale, and a platform whose stamps carry no change time is never
// current.
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
			// Parent directory's recorded entries include filepath.Base(clean) as a
			// non-symlink directory; once parent's live entries match, this child
			// path is inductively non-symlink as well.
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

// A symlink can select source through an unstamped target without changing
// the link itself. These trees still analyze, but re-list on every construction
// until their followed-target dependency model is represented explicitly.
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

// listingIntegrity detects incomplete private-cache payloads, including a
// missing delegate whose other entries still match the filesystem. It is not
// authentication of a coherently replaced payload and commitment.
func listingIntegrity(scope string, l surfaceListing) string {
	l.Integrity = ""
	data, _ := json.Marshal(struct {
		Scope   string
		Listing surfaceListing
	}{scope, l})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// stampDiscovery covers source-package discovery and embed membership,
// including currently empty directories that a selected file did not name.
func stampDiscovery(ctx context.Context, root string) ([]dirStamp, error) {
	return stampDiscoveryTree(ctx, root, false)
}

// Package discovery follows cmd/go's std-pattern directory exclusions.
// Explicitly selected package and embed roots are observed separately.
func stampDiscoveryTree(ctx context.Context, root string, packagesOnly bool) ([]dirStamp, error) {
	return stampDiscoveryTreeWithExisting(ctx, root, packagesOnly, nil)
}

func stampDiscoveryTreeWithExisting(ctx context.Context, root string, packagesOnly bool, existing map[string]dirStamp) ([]dirStamp, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// WalkDir does not descend into a root symlink. Retain that root's
	// observation anyway so cache eligibility can reject its indirection.
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

// digestFiles digests the named files of dir in name order: each
// contributes an unsigned big-endian 64-bit name length, the name bytes,
// an unsigned big-endian 64-bit content length, and the content bytes — so
// binary contents cannot disguise file boundaries. A renamed, reordered,
// or re-split file moves the digest as a changed one does. An
// unreadable file is an error, never a skipped one: a reading short one
// file would admit source the walk never read. The context is checked
// before every file read (a read in progress is never interrupted —
// the bound is one file), so a cancelled construction ends at the next
// file boundary answering the cancellation.
func digestFiles(ctx context.Context, dir string, files []string) (string, error) {
	return digestFilesBuffered(ctx, dir, files, make([]byte, 32*1024))
}

func digestFilesBuffered(ctx context.Context, dir string, files []string, buffer []byte) (string, error) {
	return digestFilesWithExtraBuffered(ctx, dir, files, "", nil, buffer)
}

func digestListedPackageBuffered(ctx context.Context, p listedPackage, buffer []byte) (string, error) {
	if p.ImportPath == "runtime" {
		if goroot, ok := stdPackageGOROOT(p.Dir, p.ImportPath); ok {
			pkgIncludeDir := filepath.Join(goroot, "pkg", "include")
			info, err := os.Stat(pkgIncludeDir)
			if err != nil && !os.IsNotExist(err) {
				return "", err
			}
			if err == nil {
				if !info.IsDir() {
					return "", fmt.Errorf("pkg/include: not a directory")
				}
				extra, err := pkgIncludeRelativeFiles(ctx, pkgIncludeDir)
				if err != nil {
					return "", err
				}
				return digestFilesWithExtraBuffered(ctx, p.Dir, p.Files, pkgIncludeDir, extra, buffer)
			}
		}
	}
	return digestFilesBuffered(ctx, p.Dir, p.Files, buffer)
}

func writeFramedFileDigestEntry(h io.Writer, framedName string, sizeBytes uint64, content io.Reader, buffer []byte) (int64, error) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(framedName)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(framedName))
	binary.BigEndian.PutUint64(size[:], sizeBytes)
	_, _ = h.Write(size[:])
	return io.CopyBuffer(h, struct{ io.Reader }{content}, buffer)
}

func writeFramedFileBytesEntry(h io.Writer, framedName string, data []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(framedName)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(framedName))
	binary.BigEndian.PutUint64(size[:], uint64(len(data)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(data)
}

func digestFilesWithExtraBuffered(ctx context.Context, dir string, files []string, extraDir string, extraRelSlash []string, buffer []byte) (string, error) {
	h := sha256.New()
	hashEntry := func(framedName, fullPath string) error {
		// The check point: a cancelled traversal exits at the next file
		// boundary, reading no further file.
		if err := ctx.Err(); err != nil {
			return err
		}
		emitDigestReadHook(framedName)
		file, err := os.Open(fullPath)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return err
		}
		// Reader-only wrapping keeps io.CopyBuffer on the pass-owned buffer
		// instead of a per-file WriterTo allocation. Check the framed length.
		written, readErr := writeFramedFileDigestEntry(h, framedName, uint64(info.Size()), file, buffer)
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if written != info.Size() {
			return fmt.Errorf("source size moved while reading %s", framedName)
		}
		return nil
	}
	for _, name := range files {
		if err := hashEntry(name, filepath.Join(dir, name)); err != nil {
			return "", err
		}
	}
	for _, rel := range extraRelSlash {
		if err := hashEntry("../../pkg/include/"+rel, filepath.Join(extraDir, filepath.FromSlash(rel))); err != nil {
			return "", err
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// trackedFileRead records a file read performed during structural package
// verification so verifyReadPackageDigest can confirm post-parse metadata and
// hash the already-read bytes without reading the file from disk a second time.
type trackedFileRead struct {
	fullPath string
	preStamp entryStamp
	hasStamp bool
	data     []byte
}

func readFileTracked(fullPath, framedName string, cache map[string]trackedFileRead) ([]byte, error) {
	var preStamp entryStamp
	var hasStamp bool
	if cache != nil && stampsTrusted {
		if info, err := os.Lstat(fullPath); err == nil && info.Mode().IsRegular() {
			preStamp = entryStamp{
				Name:       info.Name(),
				Type:       info.Mode().Type(),
				Size:       info.Size(),
				ModTime:    info.ModTime().UnixNano(),
				ChangeTime: changeTime(info),
			}
			hasStamp = true
		}
	}
	raw, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}
	if cache != nil {
		cache[framedName] = trackedFileRead{
			fullPath: fullPath,
			preStamp: preStamp,
			hasStamp: hasStamp && int64(len(raw)) == preStamp.Size,
			data:     raw,
		}
	}
	return raw, nil
}

func readPackageFileTracked(dir, name string, cache map[string]trackedFileRead) ([]byte, error) {
	return readFileTracked(filepath.Join(dir, name), name, cache)
}

func verifyReadPackageDigest(ctx context.Context, p listedPackage, cache map[string]trackedFileRead) (string, error) {
	var pkgIncludeDir string
	var extraRels []string
	if p.ImportPath == "runtime" {
		if goroot, ok := stdPackageGOROOT(p.Dir, p.ImportPath); ok {
			pkgIncludeDir = filepath.Join(goroot, "pkg", "include")
			info, err := os.Stat(pkgIncludeDir)
			if err != nil && !os.IsNotExist(err) {
				return "", err
			}
			if err == nil {
				if !info.IsDir() {
					return "", fmt.Errorf("pkg/include: not a directory")
				}
				rels, err := pkgIncludeRelativeFiles(ctx, pkgIncludeDir)
				if err != nil {
					return "", err
				}
				extraRels = rels
			}
		}
	}
	h := sha256.New()
	var fallbackBuf []byte
	checkAndWrite := func(framedName, fullPath string) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if rf, ok := cache[framedName]; ok {
			stampMatches := false
			if stampsTrusted && rf.hasStamp {
				info, err := os.Lstat(rf.fullPath)
				if err != nil {
					return false, err
				}
				postStamp := entryStamp{
					Name:       info.Name(),
					Type:       info.Mode().Type(),
					Size:       info.Size(),
					ModTime:    info.ModTime().UnixNano(),
					ChangeTime: changeTime(info),
				}
				stampMatches = postStamp == rf.preStamp
			}
			if !stampMatches {
				currentBytes, err := os.ReadFile(rf.fullPath)
				if err != nil {
					trace.Emit(ctx, trace.DomainToolchain, "stamp_fallback", p.ImportPath,
						trace.String("file", framedName),
						trace.Bool("content_equal", false),
						trace.Err(err),
					)
					return false, err
				}
				eq := bytes.Equal(currentBytes, rf.data)
				trace.Emit(ctx, trace.DomainToolchain, "stamp_fallback", p.ImportPath,
					trace.String("file", framedName),
					trace.Bool("content_equal", eq),
				)
				if !eq {
					return false, nil
				}
			}
			writeFramedFileBytesEntry(h, framedName, rf.data)
			return true, nil
		}
		if fallbackBuf == nil {
			fallbackBuf = make([]byte, 32*1024)
		}
		file, err := os.Open(fullPath)
		if err != nil {
			return false, err
		}
		info, err := file.Stat()
		if err != nil {
			file.Close()
			return false, err
		}
		written, readErr := writeFramedFileDigestEntry(h, framedName, uint64(info.Size()), file, fallbackBuf)
		closeErr := file.Close()
		if readErr != nil {
			return false, readErr
		}
		if closeErr != nil {
			return false, closeErr
		}
		if written != info.Size() {
			return false, nil
		}
		return true, nil
	}
	for _, name := range p.Files {
		ok, err := checkAndWrite(name, filepath.Join(p.Dir, name))
		if err != nil {
			return "", err
		}
		if !ok {
			return "", nil
		}
	}
	for _, rel := range extraRels {
		ok, err := checkAndWrite("../../pkg/include/"+rel, filepath.Join(pkgIncludeDir, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		if !ok {
			return "", nil
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// listSurface derives the complete listing and its audited projection from
// a standard-library listing under the analysis' selection: every package's
// selected files and its directories' stamps (a package the selection
// gives no file — a platform none of its files build on — is the
// empty selection, digested as such; a package the go command could
// not load never reaches here: the listing parser refuses it by name).
func listSurface(std []listing.Package) (surfaceListing, error) {
	byPath := make(map[string]listing.Package, len(std))
	for _, p := range std {
		byPath[p.ImportPath] = p
	}
	l := surfaceListing{Version: sourceDigestsVersion}
	directories := map[string]dirStamp{}
	audited := map[string]bool{}
	for _, path := range auditedSurface(std) {
		audited[path] = true
	}
	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, pkgPath := range paths {
		p := byPath[pkgPath]
		files := selectedFiles(p)
		lp := listedPackage{ImportPath: pkgPath, Dir: p.Dir, Files: files, EmbedRoots: embedRoots(p.Dir, p.EmbedPatterns), Audited: audited[pkgPath]}
		stamps, err := stampDirs(p.Dir, files)
		if err != nil {
			return surfaceListing{}, fmt.Errorf("%s: %w", pkgPath, err)
		}
		for _, d := range stamps {
			directories[d.Path] = d
		}
		l.Packages = append(l.Packages, lp)
	}
	l.Discovery = orderedStamps(directories)
	return l, nil
}

func orderedStamps(dirs map[string]dirStamp) []dirStamp {
	paths := make([]string, 0, len(dirs))
	for path := range dirs {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	result := make([]dirStamp, 0, len(paths))
	for _, path := range paths {
		result = append(result, dirs[path])
	}
	return result
}

// listingDiscoveryRoots are the directories whose membership or metadata
// can change source selection. Snapshot-mode FIPS also reads alias, archive
// and checksum inputs outside src. Selected external package directories
// cover their embed-discovery trees as well.
func listingDiscoveryRoots(snapshot *gotool.EnvSnapshot, l surfaceListing) ([]string, error) {
	goroot := snapshot.Value("GOROOT")
	src := filepath.Join(goroot, "src")
	set := map[string]bool{}
	if goroot != "" {
		pkgInclude := filepath.Join(goroot, "pkg", "include")
		if _, err := os.Lstat(pkgInclude); err == nil {
			set[pkgInclude] = true
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if fips := snapshot.Value("GOFIPS140"); fips != "" && fips != "off" && fips != "latest" {
		set[filepath.Join(goroot, "lib", "fips140")] = true
	}
	for _, p := range l.Packages {
		rel, err := filepath.Rel(src, p.Dir)
		outsideDiscovery := err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
		outsideDiscovery = outsideDiscovery || excludedStandardDirectory(rel)
		if outsideDiscovery {
			set[p.Dir] = true
		}
		for _, root := range p.EmbedRoots {
			info, err := os.Stat(root)
			if err != nil {
				return nil, err
			}
			if info.IsDir() {
				set[root] = true
			}
		}
	}
	return sortedKeys(set), nil
}

// digestListing reads and digests every listed package's selected
// files; an unreadable file refuses naming the package.
func digestListing(ctx context.Context, l surfaceListing) (sourceDigests, error) {
	d := sourceDigests{Packages: map[string]string{}, inventory: map[string]listedPackage{}}
	all := map[string]string{}
	buffer := make([]byte, 32*1024)
	for _, p := range l.Packages {
		digest, err := digestListedPackageBuffered(ctx, p, buffer)
		if err != nil {
			return sourceDigests{}, fmt.Errorf("%s: %w", p.ImportPath, err)
		}
		p.digest = digest
		all[p.ImportPath] = digest
		d.inventory[p.ImportPath] = p
		if p.Audited {
			d.Packages[p.ImportPath] = digest
		}
	}
	if len(all) == 0 || len(d.Packages) == 0 {
		return sourceDigests{}, errors.New("incomplete standard-library inventory")
	}
	data, _ := json.Marshal(all)
	sum := sha256.Sum256(append([]byte("gofresh/toolchain-content@1\x00"), data...))
	d.Content = hex.EncodeToString(sum[:])
	return d, nil
}

type persistedSourceDigests struct {
	All map[string]string `json:"all"`
}

var (
	toolchainListingMemo cachefile.SyncMemo[memoizedListing]
	toolchainDigestsMemo cachefile.SyncMemo[memoizedDigests]
)

type memoizedListing struct {
	rawSum  [32]byte
	listing surfaceListing
}

type memoizedDigests struct {
	rawSum  [32]byte
	all     map[string]string
	content string
}

func loadToolchainListing(scope string) (surfaceListing, bool) {
	listingPath, err := cachefile.Path(sourceDigestsDirName, scope, "listing")
	var rawSum [32]byte
	haveRaw := false
	if err == nil {
		if raw, readErr := os.ReadFile(listingPath); readErr == nil {
			rawSum = sha256.Sum256(raw)
			haveRaw = true
			if entry, ok := toolchainListingMemo.Load(listingPath); ok {
				if entry.rawSum == rawSum {
					return entry.listing, true
				}
			}
		}
	}
	var l surfaceListing
	if !cachefile.Load(sourceDigestsDirName, scope, "listing", &l) {
		return surfaceListing{}, false
	}
	if l.Version != sourceDigestsVersion || len(l.Packages) == 0 || len(l.Discovery) == 0 || l.Integrity != listingIntegrity(scope, l) {
		return surfaceListing{}, false
	}
	l.plan = buildDiscoveryPlan(l)
	if haveRaw {
		toolchainListingMemo.Store(listingPath, memoizedListing{
			rawSum:  rawSum,
			listing: l,
		})
	}
	return l, true
}

func sourceDigestsFromMemo(l surfaceListing, all map[string]string) (sourceDigests, bool) {
	return sourceDigestsFromMemoWithContent(l, all, "")
}

func sourceDigestsFromMemoWithContent(l surfaceListing, all map[string]string, precomputedContent string) (sourceDigests, bool) {
	if len(all) == 0 || len(all) != len(l.Packages) {
		return sourceDigests{}, false
	}
	d := sourceDigests{
		Packages:  make(map[string]string),
		inventory: make(map[string]listedPackage, len(l.Packages)),
	}
	for _, p := range l.Packages {
		digest, ok := all[p.ImportPath]
		if !ok || digest == "" {
			return sourceDigests{}, false
		}
		p.digest = digest
		d.inventory[p.ImportPath] = p
		if p.Audited {
			d.Packages[p.ImportPath] = digest
		}
	}
	if len(d.Packages) == 0 {
		return sourceDigests{}, false
	}
	if precomputedContent != "" {
		d.Content = precomputedContent
		return d, true
	}
	data, _ := json.Marshal(all)
	sum := sha256.Sum256(append([]byte("gofresh/toolchain-content@1\x00"), data...))
	d.Content = hex.EncodeToString(sum[:])
	return d, true
}

func loadToolchainDigests(scope string, l surfaceListing) (sourceDigests, bool) {
	if l.Integrity == "" {
		return sourceDigests{}, false
	}
	key := "digests-" + l.Integrity
	recordPath, err := cachefile.Path(sourceDigestsDirName, scope, key)
	var rawSum [32]byte
	haveRaw := false
	if err == nil {
		if raw, readErr := os.ReadFile(recordPath); readErr == nil {
			rawSum = sha256.Sum256(raw)
			haveRaw = true
			if entry, ok := toolchainDigestsMemo.Load(recordPath); ok {
				if entry.rawSum == rawSum {
					if d, ok := sourceDigestsFromMemoWithContent(l, entry.all, entry.content); ok {
						return d, true
					}
				}
			}
		}
	}
	var cached persistedSourceDigests
	if !cachefile.Load(sourceDigestsDirName, scope, key, &cached) {
		return sourceDigests{}, false
	}
	d, ok := sourceDigestsFromMemo(l, cached.All)
	if !ok {
		return sourceDigests{}, false
	}
	if haveRaw {
		toolchainDigestsMemo.Store(recordPath, memoizedDigests{
			rawSum:  rawSum,
			all:     cached.All,
			content: d.Content,
		})
	}
	return d, true
}

func storeToolchainDigests(scope string, l surfaceListing, d sourceDigests) {
	if l.Integrity == "" || len(d.inventory) == 0 {
		return
	}
	all := make(map[string]string, len(d.inventory))
	for pkg, lp := range d.inventory {
		all[pkg] = lp.digest
	}
	key := "digests-" + l.Integrity
	cachefile.Store(sourceDigestsDirName, scope, key, persistedSourceDigests{All: all})
	if recordPath, err := cachefile.Path(sourceDigestsDirName, scope, key); err == nil {
		if raw, readErr := os.ReadFile(recordPath); readErr == nil {
			toolchainDigestsMemo.Store(recordPath, memoizedDigests{
				rawSum:  sha256.Sum256(raw),
				all:     all,
				content: d.Content,
			})
		}
	}
}

func toolchainSnapshotIdentity(snapshot *gotool.EnvSnapshot) string {
	var b strings.Builder
	for _, line := range strings.Split(snapshot.Identity(), "\n") {
		if line == "" || strings.HasPrefix(line, "GOMOD=") || strings.HasPrefix(line, "GOWORK=") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// toolchainSourceScope keys the listing memo: the record version, the
// explicit build flags verbatim, and the pass snapshot's toolchain
// identity — every `go env` setting (GOROOT, GOVERSION, GOFLAGS, GOOS,
// GOARCH, CGO_ENABLED, GOEXPERIMENT, GOFIPS140, …) as the go command
// reports it, excluding module-local GOMOD and GOWORK paths — so two
// listings share a record exactly when the go command would select the
// same files from the same tree; the go command's own flag semantics
// (an explicit flag over GOFLAGS) are never re-derived here. The tree's
// contents are the record's stamps, not the scope's. The surface seeds'
// digest is the scope's last limb: the record lists the packages the
// rule derived when it was written, so a rule whose seeds moved must
// miss it.
func toolchainSourceScope(snapshot *gotool.EnvSnapshot, buildFlags []string, seeds []string) string {
	seedDigest := sha256.Sum256([]byte(strings.Join(seeds, "\n")))
	return fmt.Sprintf("%d|%s|%s|%x", sourceDigestsVersion, strings.Join(buildFlags, "\x00"), toolchainSnapshotIdentity(snapshot), seedDigest[:8])
}

// toolchainSourceDigests lists the standard library under the effective
// selection through the pass's runner (`go list -json -e -deps std` in the
// analysis' environment, the build flags applied; a package the go
// command could not load is refused by the parser, named) — served
// from the persistent listing memo under the selection's scope while
// its stamps hold — and digests the complete inventory from the files
// themselves (or serves the companion digest memo while every stamp
// holds), retaining the audited subset as a separate projection. A
// listing failure or an unreadable file is an error: the
// admission then refuses, naming it.
func toolchainSourceDigests(ctx context.Context, runner gotool.Runner, dir string, env []string, snapshot *gotool.EnvSnapshot, buildFlags []string) (sourceDigests, error) {
	scope := toolchainSourceScope(snapshot, buildFlags, surfaceSeeds())
	l, loadedListing := loadToolchainListing(scope)
	warmListing := loadedListing && stampsCurrentContext(ctx, l)
	if trace.AnyEnabled() {
		goroot := snapshot.Value("GOROOT")
		if trace.Enabled(ctx, trace.DomainToolchain, goroot) {
			trace.Emit(ctx, trace.DomainToolchain, "scope_resolved", goroot,
				trace.String("goversion", snapshot.Value("GOVERSION")),
				trace.Strings("build_flags", buildFlags),
				trace.String("scope", scope),
				trace.Bool("warm_listing", warmListing),
			)
		}
	}
	cacheable := warmListing
	if !warmListing {
		args := append([]string{"-json", "-e", "-deps"}, buildFlags...)
		args = append(args, "std")
		out, err := runner.List(ctx, dir, env, args...)
		if err != nil {
			return sourceDigests{}, fmt.Errorf("listing the standard library: %w", err)
		}
		std, err := listing.Parse(bytes.NewReader(out))
		if err != nil {
			return sourceDigests{}, fmt.Errorf("listing the standard library: %w", err)
		}
		if len(std) == 0 {
			return sourceDigests{}, errors.New("listing the standard library: no package listed")
		}
		if l, err = listSurface(std); err != nil {
			return sourceDigests{}, err
		}
		directories := map[string]dirStamp{}
		for _, d := range l.Discovery {
			directories[d.Path] = d
		}
		stamps, err := stampDiscoveryTreeWithExisting(ctx, filepath.Join(snapshot.Value("GOROOT"), "src"), true, directories)
		if err != nil {
			return sourceDigests{}, err
		}
		for _, d := range stamps {
			directories[d.Path] = d
		}
		roots, err := listingDiscoveryRoots(snapshot, l)
		if err != nil {
			return sourceDigests{}, err
		}
		for _, root := range roots {
			stamps, err := stampDiscoveryTreeWithExisting(ctx, root, false, directories)
			if err != nil {
				return sourceDigests{}, err
			}
			for _, d := range stamps {
				directories[d.Path] = d
			}
		}
		l.Discovery = orderedStamps(directories)
		l.Integrity = listingIntegrity(scope, l)
		l.plan = buildDiscoveryPlan(l)
		cacheable = cacheableDiscovery(l)
		if cacheable {
			cachefile.Store(sourceDigestsDirName, scope, "listing", l)
			if listingPath, err := cachefile.Path(sourceDigestsDirName, scope, "listing"); err == nil {
				if raw, readErr := os.ReadFile(listingPath); readErr == nil {
					toolchainListingMemo.Store(listingPath, memoizedListing{
						rawSum:  sha256.Sum256(raw),
						listing: l,
					})
				}
			}
		}
	} else if !hasDigestReadTestHook() {
		if err := ctx.Err(); err != nil {
			return sourceDigests{}, err
		}
		if d, ok := loadToolchainDigests(scope, l); ok {
			return d, nil
		}
	}
	d, err := digestListing(ctx, l)
	if err != nil {
		return sourceDigests{}, err
	}
	if cacheable {
		storeToolchainDigests(scope, l, d)
	}
	return d, nil
}

func boolKeys(m map[string]string) map[string]bool {
	set := make(map[string]bool, len(m))
	for k := range m {
		set[k] = true
	}
	return set
}

// movedKeysBound bounds the keys a refusal names; the rest are counted.
const movedKeysBound = 8

// namedMoved renders failed/moved keys for a refusal: up to the bound named,
// the remainder counted.
func namedMoved(moved []string) string {
	shown := moved
	if len(shown) > movedKeysBound {
		shown = shown[:movedKeysBound]
	}
	text := strings.Join(shown, ", ")
	if rest := len(moved) - len(shown); rest > 0 {
		text += fmt.Sprintf(" (+%d more)", rest)
	}
	return text
}

// harnessPremisePackages hold the testing harness's test-log pipeline —
// internal/testlog stores and dispatches the process logger, testing wraps
// the file the harness writes, and testing/internal/testdeps buffers the
// records and returns StopTestLog's flush error, which fails the binary.
// All three are surface seeds.
var harnessPremisePackages = []string{"internal/testlog", "testing", "testing/internal/testdeps"}

// toolchainVerifierVersion versions the structural stdlib boundary verifier.
// Bumping this invalidates cached package verification verdicts and moves
// AdmissionPolicy.
const toolchainVerifierVersion = "gofresh/toolchain-verifier@18"
