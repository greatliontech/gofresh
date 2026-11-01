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
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/greatliontech/gofresh/internal/closure/internal/listing"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/internal/auditset"
	"github.com/greatliontech/gofresh/internal/cachefile"
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
	for p := range classBPackages {
		set[p] = true
	}
	for target := range auditedLinknameTargets {
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

// stampEntries stamps every entry of dir in name order.
func stampEntries(dir string) ([]entryStamp, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	stamps := make([]entryStamp, 0, len(entries))
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		stamps = append(stamps, entryStamp{Name: entry.Name(), Type: info.Mode().Type(), Size: info.Size(), ModTime: info.ModTime().UnixNano(), ChangeTime: changeTime(info)})
	}
	return stamps, nil
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
	if !stampsTrusted || !cacheableDiscovery(l) {
		return false
	}
	recorded := make(map[string]bool, len(l.Discovery))
	for _, d := range l.Discovery {
		stamps, err := stampEntries(d.Path)
		if err != nil || !slices.Equal(stamps, d.Entries) {
			return false
		}
		recorded[filepath.Clean(d.Path)] = true
	}
	for _, p := range l.Packages {
		if goroot, ok := stdPackageGOROOT(p.Dir, p.ImportPath); ok {
			pkgInclude := filepath.Join(goroot, "pkg", "include")
			if _, err := os.Lstat(pkgInclude); err == nil {
				if !recorded[filepath.Clean(pkgInclude)] {
					return false
				}
			} else if !os.IsNotExist(err) {
				return false
			}
			break
		}
	}
	return true
}

// A symlink can select source through an unstamped target without changing
// the link itself. These trees still analyze, but re-list on every construction
// until their followed-target dependency model is represented explicitly.
func cacheableDiscovery(l surfaceListing) bool {
	for _, d := range l.Discovery {
		resolved, err := filepath.EvalSymlinks(d.Path)
		if err != nil || resolved != filepath.Clean(d.Path) {
			return false
		}
		for _, entry := range d.Entries {
			if entry.Type&os.ModeSymlink != 0 {
				return false
			}
		}
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// WalkDir does not descend into a root symlink. Retain that root's
	// observation anyway so cache eligibility can reject its indirection.
	entries, err := stampEntries(root)
	if err != nil {
		return nil, err
	}
	dirs := []dirStamp{{Path: root, Entries: entries}}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
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

// digestReadForTest, when set, sees every file the digest traversal is
// about to read — the seam a cancellation pin cancels from.
var digestReadForTest func(name string)

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
		if digestReadForTest != nil {
			digestReadForTest(framedName)
		}
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
			if stampsTrusted {
				if !rf.hasStamp {
					return false, nil
				}
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
				if postStamp != rf.preStamp {
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

var toolchainDigestsMemo sync.Map

func sourceDigestsFromMemo(l surfaceListing, all map[string]string) (sourceDigests, bool) {
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
	if err == nil {
		if v, ok := toolchainDigestsMemo.Load(recordPath); ok {
			if _, statErr := os.Stat(recordPath); statErr == nil {
				if d, ok := sourceDigestsFromMemo(l, v.(map[string]string)); ok {
					return d, true
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
	if err == nil {
		toolchainDigestsMemo.Store(recordPath, cached.All)
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
		toolchainDigestsMemo.Store(recordPath, all)
	}
}

func toolchainSnapshotIdentity(snapshot *gotool.EnvSnapshot) string {
	var b strings.Builder
	for line := range strings.SplitSeq(snapshot.Identity(), "\n") {
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
	var l surfaceListing
	warmListing := cachefile.Load(sourceDigestsDirName, scope, "listing", &l) && l.Version == sourceDigestsVersion && len(l.Packages) != 0 && len(l.Discovery) != 0 && l.Integrity == listingIntegrity(scope, l) && stampsCurrent(l)
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
		stamps, err := stampDiscoveryTree(ctx, filepath.Join(snapshot.Value("GOROOT"), "src"), true)
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
			stamps, err := stampDiscovery(ctx, root)
			if err != nil {
				return sourceDigests{}, err
			}
			for _, d := range stamps {
				directories[d.Path] = d
			}
		}
		l.Discovery = orderedStamps(directories)
		l.Integrity = listingIntegrity(scope, l)
		if cacheableDiscovery(l) {
			cachefile.Store(sourceDigestsDirName, scope, "listing", l)
		}
	} else if digestReadForTest == nil {
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
	if cacheableDiscovery(l) {
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
const toolchainVerifierVersion = "gofresh/toolchain-verifier@17"

type verifiedPackageVerdict struct {
	OK                           bool                `json:"ok"`
	Delegates                    []string            `json:"delegates,omitempty"`
	InactiveRuntimeGates         map[string][]string `json:"inactiveRuntimeGates,omitempty"`
	RuntimeLinknamePulls         []string            `json:"runtimeLinknamePulls,omitempty"`
	ExternalLinknamePulls        []string            `json:"externalLinknamePulls,omitempty"`
	RequiredInactiveRuntimeGates []string            `json:"requiredInactiveRuntimeGates,omitempty"`
}

type offSurfaceCrossEdge struct {
	Pkg string `json:"pkg"`
	Sym string `json:"sym"`
}

type offSurfaceUnaliasedSel struct {
	Ident      string   `json:"ident"`
	Sel        string   `json:"sel"`
	Candidates []string `json:"candidates"`
}

type offSurfaceVerdict struct {
	PackageName        string                              `json:"packageName,omitempty"`
	DirectRuntimePulls []string                            `json:"directRuntimePulls,omitempty"`
	RuntimePullByDecl  map[string]string                   `json:"runtimePullByDecl,omitempty"`
	LocalEdges         map[string][]string                 `json:"localEdges,omitempty"`
	LocalSels          map[string][]string                 `json:"localSels,omitempty"`
	MethodsByType      map[string][]string                 `json:"methodsByType,omitempty"`
	CrossEdges         map[string][]offSurfaceCrossEdge    `json:"crossEdges,omitempty"`
	UnaliasedSels      map[string][]offSurfaceUnaliasedSel `json:"unaliasedSels,omitempty"`
	DotImports         []string                            `json:"dotImports,omitempty"`
	DotImportIdents    map[string][]string                 `json:"dotImportIdents,omitempty"`
	SeedDecls          []string                            `json:"seedDecls,omitempty"`
	SeedSels           []string                            `json:"seedSels,omitempty"`
	SeedCrossEdges     []offSurfaceCrossEdge               `json:"seedCrossEdges,omitempty"`
	SeedUnaliasedSels  []offSurfaceUnaliasedSel            `json:"seedUnaliasedSels,omitempty"`
	SeedDotIdents      []string                            `json:"seedDotIdents,omitempty"`
	DeclaredNames      []string                            `json:"declaredNames,omitempty"`
}

// verifiedPackageMemo caches structural verification verdicts per
// verifiedPackageMemoKey in memory.
var verifiedPackageMemo sync.Map

// verifiedPureDelegateMemo caches pure-delegate verification verdicts per
// verifiedPureDelegateMemoKeyWithPolicy in memory.
var verifiedPureDelegateMemo sync.Map

// verifiedOffSurfaceMemo caches off-surface runtime-pull/startup graphs per
// verifiedOffSurfaceMemoKeyWithPolicy in memory.
var verifiedOffSurfaceMemo sync.Map

// pkgIncludeHeaderCache caches GOROOT/pkg/include header contents keyed by
// goroot+"|"+pkgIncludeSalt when pkgIncludeSalt is non-empty.
var pkgIncludeHeaderCache sync.Map

func listedPackageNeedsPkgIncludeSalt(lp listedPackage) bool {
	if lp.ImportPath == "runtime" {
		return false
	}
	for _, name := range lp.Files {
		switch strings.ToLower(filepath.Ext(name)) {
		case ".s", ".h", ".c", ".cc", ".cpp", ".cxx", ".m":
			return true
		}
	}
	return false
}

func verifiedPackageMemoKey(importPath, digest string) string {
	return verifiedPackageMemoKeyWithPolicy("", importPath, digest, "")
}

func verifiedPackageMemoKeyWithPolicy(policy, importPath, digest, pkgIncludeSalt string) string {
	if policy == "" {
		policy = admissionPolicy()
	}
	key := toolchainVerifierVersion + "|" + policy + "|" + importPath + "|" + digest
	if pkgIncludeSalt != "" {
		key += "|inc:" + pkgIncludeSalt
	}
	return key
}

func verifiedPureDelegateMemoKeyWithPolicy(policy, importPath, digest, pkgIncludeSalt string) string {
	if policy == "" {
		policy = admissionPolicy()
	}
	key := toolchainVerifierVersion + "|delegate|" + policy + "|" + importPath + "|" + digest
	if pkgIncludeSalt != "" {
		key += "|inc:" + pkgIncludeSalt
	}
	return key
}

func verifiedOffSurfaceMemoKeyWithPolicy(policy, importPath, digest, pkgIncludeSalt string) string {
	if policy == "" {
		policy = admissionPolicy()
	}
	key := toolchainVerifierVersion + "|offsurface|" + policy + "|" + importPath + "|" + digest
	if pkgIncludeSalt != "" {
		key += "|inc:" + pkgIncludeSalt
	}
	return key
}

func packageGOROOTForInclude(dir, importPath string) (string, bool) {
	if goroot, ok := stdPackageGOROOT(dir, importPath); ok {
		return goroot, true
	}
	if dir == "" {
		return "", false
	}
	cleanDir := filepath.Clean(dir)
	marker := string(filepath.Separator) + filepath.Join("lib", "fips140") + string(filepath.Separator)
	if idx := strings.Index(cleanDir, marker); idx > 0 {
		return cleanDir[:idx], true
	}
	return "", false
}

func loadPkgIncludeHeadersForPackage(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (headers []string, verdictErr error, ioErr error) {
	goroot, ok := packageGOROOTForInclude(lp.Dir, lp.ImportPath)
	if !ok {
		return nil, nil, nil
	}
	cacheKey := ""
	if pkgIncludeSalt != "" {
		cacheKey = goroot + "|" + pkgIncludeSalt
		if v, okC := pkgIncludeHeaderCache.Load(cacheKey); okC {
			return v.([]string), nil, nil
		}
	}
	pkgIncludeDir := filepath.Join(goroot, "pkg", "include")
	info, err := os.Stat(pkgIncludeDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("pkg/include: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("pkg/include: not a directory"), nil
	}
	rels, err := pkgIncludeRelativeFiles(ctx, pkgIncludeDir)
	if err != nil {
		return nil, nil, fmt.Errorf("pkg/include: %w", err)
	}
	headers = make([]string, 0, len(rels))
	for _, rel := range rels {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		fullPath := filepath.Join(pkgIncludeDir, filepath.FromSlash(rel))
		finfo, err := os.Lstat(fullPath)
		if err != nil {
			return nil, nil, fmt.Errorf("pkg/include/%s: %w", rel, err)
		}
		if !finfo.Mode().IsRegular() {
			return nil, fmt.Errorf("pkg/include/%s: non-regular entry", rel), nil
		}
		raw, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, nil, fmt.Errorf("pkg/include/%s: %w", rel, err)
		}
		headers = append(headers, string(raw))
	}
	if cacheKey != "" {
		pkgIncludeHeaderCache.Store(cacheKey, headers)
	}
	return headers, nil, nil
}

// verifyToolchainSurface checks every audited standard-library package in d
// against gofresh's structural boundary contracts. It returns the sorted list
// of package paths that failed verification (empty when the entire surface is
// verified).
func verifyToolchainSurface(d sourceDigests) []string {
	failed, _, ioErr, _ := verifyToolchainSurfaceAndDelegatesWithIO(context.Background(), d)
	if ioErr != nil {
		return sortedKeys(boolKeys(d.Packages))
	}
	return failed
}

func verifyToolchainSurfaceContext(ctx context.Context, d sourceDigests) ([]string, error) {
	failed, _, ioErr, ctxErr := verifyToolchainSurfaceAndDelegatesWithIO(ctx, d)
	if ctxErr != nil {
		return nil, ctxErr
	}
	if ioErr != nil {
		return nil, ioErr
	}
	return failed, nil
}

func verifyToolchainSurfaceWithIO(ctx context.Context, d sourceDigests) (failed []string, ioErr error, ctxErr error) {
	failed, _, ioErr, ctxErr = verifyToolchainSurfaceAndDelegatesWithIO(ctx, d)
	return failed, ioErr, ctxErr
}

func verifyToolchainSurfaceAndDelegatesWithIO(ctx context.Context, d sourceDigests) (failed []string, pureDelegates map[string]bool, ioErr error, ctxErr error) {
	if len(d.Packages) == 0 {
		var missing []string
		for _, root := range auditedSurfaceTables() {
			first, _, _ := strings.Cut(root, "/")
			if !strings.Contains(first, ".") {
				missing = append(missing, root)
			}
		}
		return missing, nil, nil, nil
	}
	keys := sortedKeys(boolKeys(d.Packages))
	if len(d.inventory) == 0 {
		return keys, nil, nil, nil
	}
	failedSet := map[string]bool{}
	for _, root := range auditedSurfaceTables() {
		first, _, _ := strings.Cut(root, "/")
		if strings.Contains(first, ".") {
			continue
		}
		if d.Packages[root] == "" {
			failedSet[root] = true
		}
	}
	policy := d.Policy
	if policy == "" {
		policy = admissionPolicy()
	}
	pkgIncludeSalt := ""
	if rtLP, ok := d.inventory["runtime"]; ok {
		pkgIncludeSalt = rtLP.digest
	}
	rootDelegates := map[string][]string{}
	surfaceVerdicts := map[string]verifiedPackageVerdict{}
	for _, pkg := range keys {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		wantDigest := d.Packages[pkg]
		lp, ok := d.inventory[pkg]
		if !ok || wantDigest == "" || lp.digest == "" || lp.digest != wantDigest {
			failedSet[pkg] = true
			continue
		}
		verdict, err := verifyListedPackageMemoized(ctx, lp, policy, pkgIncludeSalt)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, nil, ctxErr
			}
			return nil, nil, err, nil
		}
		if !verdict.OK {
			failedSet[pkg] = true
			continue
		}
		surfaceVerdicts[pkg] = verdict
		if (auditset.PurePackage(pkg) || pkg == "path/filepath") && len(verdict.Delegates) > 0 {
			rootDelegates[pkg] = verdict.Delegates
		}
	}

	const (
		delUnseen uint8 = iota
		delVisiting
		delValid
		delFailedInSurface
		delFailedOffSurface
	)
	state := map[string]uint8{}
	pureDelegates = map[string]bool{}
	delegateVerdicts := map[string]verifiedPackageVerdict{}
	var walkDelegate func(pkg string) (uint8, error, error)
	walkDelegate = func(pkg string) (uint8, error, error) {
		switch s := state[pkg]; s {
		case delValid, delFailedInSurface, delFailedOffSurface:
			return s, nil, nil
		case delVisiting:
			if d.Packages[pkg] != "" {
				failedSet[pkg] = true
				state[pkg] = delFailedInSurface
				return delFailedInSurface, nil, nil
			}
			state[pkg] = delFailedOffSurface
			return delFailedOffSurface, nil, nil
		}
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
		state[pkg] = delVisiting
		lp, ok := d.inventory[pkg]
		wantDigest := d.Packages[pkg]
		if !ok || lp.digest == "" || (wantDigest != "" && lp.digest != wantDigest) {
			if wantDigest != "" {
				failedSet[pkg] = true
				state[pkg] = delFailedInSurface
				return delFailedInSurface, nil, nil
			}
			state[pkg] = delFailedOffSurface
			return delFailedOffSurface, nil, nil
		}
		verdict, err := verifyPureDelegateMemoized(ctx, lp, policy, pkgIncludeSalt)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return 0, nil, ctxErr
			}
			return 0, err, nil
		}
		if !verdict.OK {
			if wantDigest != "" {
				failedSet[pkg] = true
				state[pkg] = delFailedInSurface
				return delFailedInSurface, nil, nil
			}
			state[pkg] = delFailedOffSurface
			return delFailedOffSurface, nil, nil
		}
		var subStatus uint8 = delValid
		for _, sub := range verdict.Delegates {
			st, ioE, ctxE := walkDelegate(sub)
			if ioE != nil || ctxE != nil {
				return 0, ioE, ctxE
			}
			if st == delFailedOffSurface {
				subStatus = delFailedOffSurface
			} else if st == delFailedInSurface && subStatus == delValid {
				subStatus = delFailedInSurface
			}
		}
		if subStatus == delValid {
			pureDelegates[pkg] = true
			delegateVerdicts[pkg] = verdict
		}
		state[pkg] = subStatus
		return subStatus, nil, nil
	}

	rootKeys := make([]string, 0, len(rootDelegates))
	for k := range rootDelegates {
		rootKeys = append(rootKeys, k)
	}
	slices.Sort(rootKeys)
	for _, rootPkg := range rootKeys {
		for _, del := range rootDelegates[rootPkg] {
			st, ioE, ctxE := walkDelegate(del)
			if ioE != nil || ctxE != nil {
				return nil, nil, ioE, ctxE
			}
			if st == delFailedOffSurface {
				failedSet[rootPkg] = true
			}
		}
	}

	pulledRuntimeTargets := map[string]bool{}
	externalLinknameSeeds := []offSurfaceCrossEdge{}
	needsInactiveGateCheck := false
	for _, pkg := range keys {
		if len(surfaceVerdicts[pkg].RequiredInactiveRuntimeGates) > 0 {
			needsInactiveGateCheck = true
		}
		if pkg != "runtime" {
			for _, sym := range surfaceVerdicts[pkg].RuntimeLinknamePulls {
				pulledRuntimeTargets[sym] = true
			}
		}
		for _, ext := range surfaceVerdicts[pkg].ExternalLinknamePulls {
			if tPkg, tSym, ok := splitLinknameTarget(ext); ok {
				externalLinknameSeeds = append(externalLinknameSeeds, offSurfaceCrossEdge{Pkg: tPkg, Sym: tSym})
			}
		}
	}
	for delPkg := range pureDelegates {
		for _, sym := range delegateVerdicts[delPkg].RuntimeLinknamePulls {
			pulledRuntimeTargets[sym] = true
		}
		for _, ext := range delegateVerdicts[delPkg].ExternalLinknamePulls {
			if tPkg, tSym, ok := splitLinknameTarget(ext); ok {
				externalLinknameSeeds = append(externalLinknameSeeds, offSurfaceCrossEdge{Pkg: tPkg, Sym: tSym})
			}
		}
	}
	rtVerdict, hasVerifiedRuntime := surfaceVerdicts["runtime"]
	if failedSet["runtime"] {
		hasVerifiedRuntime = false
	}
	if needsInactiveGateCheck && hasVerifiedRuntime && !pulledRuntimeTargets["runtime.*"] {
		if ioE, ctxE := collectOffSurfaceStartupRuntimePulls(ctx, d, policy, pkgIncludeSalt, pureDelegates, externalLinknameSeeds, pulledRuntimeTargets); ioE != nil || ctxE != nil {
			return nil, nil, ioE, ctxE
		}
	}
	for _, pkg := range keys {
		reqGates := surfaceVerdicts[pkg].RequiredInactiveRuntimeGates
		if len(reqGates) == 0 {
			continue
		}
		if !hasVerifiedRuntime || pulledRuntimeTargets["runtime.*"] {
			failedSet[pkg] = true
			continue
		}
		for _, gate := range reqGates {
			mutators, ok := rtVerdict.InactiveRuntimeGates[gate]
			if !ok {
				failedSet[pkg] = true
				break
			}
			mutatorPulled := false
			for _, mut := range mutators {
				if pulledRuntimeTargets[mut] {
					mutatorPulled = true
					break
				}
			}
			if mutatorPulled {
				failedSet[pkg] = true
				break
			}
		}
	}

	if len(failedSet) == 0 {
		return nil, pureDelegates, nil, nil
	}
	return sortedKeys(failedSet), nil, nil, nil
}

func memoizePackageVerdict[V any](
	ctx context.Context,
	lp listedPackage,
	policy, pkgIncludeSalt string,
	scopePrefix string,
	memoKeyFn func(policy, importPath, digest, salt string) string,
	memMap *sync.Map,
	compute func(context.Context, listedPackage, string) (V, error),
) (V, error) {
	var zero V
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if policy == "" {
		policy = admissionPolicy()
	}
	needsIncSalt := listedPackageNeedsPkgIncludeSalt(lp)
	canMemo := !needsIncSalt || pkgIncludeSalt != ""
	salt := ""
	if needsIncSalt {
		salt = pkgIncludeSalt
	}
	memoKey := memoKeyFn(policy, lp.ImportPath, lp.digest, salt)
	cacheKey := lp.ImportPath + "|" + lp.digest
	if salt != "" {
		cacheKey += "|inc:" + salt
	}
	scope := scopePrefix + "|" + toolchainVerifierVersion + "|" + policy
	if canMemo {
		if v, ok := memMap.Load(memoKey); ok {
			return v.(V), nil
		}
		var cached V
		if cachefile.Load(sourceDigestsDirName, scope, cacheKey, &cached) {
			memMap.Store(memoKey, cached)
			return cached, nil
		}
	}
	verdict, ioErr := compute(ctx, lp, pkgIncludeSalt)
	if ioErr != nil {
		return zero, ioErr
	}
	if canMemo {
		memMap.Store(memoKey, verdict)
		if lp.digest != "" {
			cachefile.Store(sourceDigestsDirName, scope, cacheKey, verdict)
		}
	}
	return verdict, nil
}

func verifyListedPackageMemoized(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (verifiedPackageVerdict, error) {
	return memoizePackageVerdict(
		ctx, lp, policy, pkgIncludeSalt,
		"verified-package",
		verifiedPackageMemoKeyWithPolicy,
		&verifiedPackageMemo,
		func(ctx context.Context, lp listedPackage, salt string) (verifiedPackageVerdict, error) {
			verdict, verdictErr, ioErr := verifyListedPackageWithIOAndSalt(ctx, lp, salt)
			if ioErr != nil {
				return verifiedPackageVerdict{}, ioErr
			}
			if verdictErr != nil {
				return verifiedPackageVerdict{OK: false}, nil
			}
			verdict.OK = true
			return verdict, nil
		},
	)
}

func verifyPureDelegateMemoized(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (verifiedPackageVerdict, error) {
	return memoizePackageVerdict(
		ctx, lp, policy, pkgIncludeSalt,
		"verified-pure-delegate",
		verifiedPureDelegateMemoKeyWithPolicy,
		&verifiedPureDelegateMemo,
		func(ctx context.Context, lp listedPackage, salt string) (verifiedPackageVerdict, error) {
			verdict, verdictErr, ioErr := verifyPureCandidateWithIOAndSalt(ctx, lp, salt)
			if ioErr != nil {
				return verifiedPackageVerdict{}, ioErr
			}
			if verdictErr != nil {
				return verifiedPackageVerdict{OK: false}, nil
			}
			verdict.OK = true
			return verdict, nil
		},
	)
}

func verifyOffSurfacePackageMemoized(ctx context.Context, lp listedPackage, policy, pkgIncludeSalt string) (offSurfaceVerdict, error) {
	return memoizePackageVerdict(
		ctx, lp, policy, pkgIncludeSalt,
		"verified-offsurface",
		verifiedOffSurfaceMemoKeyWithPolicy,
		&verifiedOffSurfaceMemo,
		verifyOffSurfacePackageWithIO,
	)
}

func resolveStdInventoryImport(inventory map[string]listedPackage, importPath string) (string, bool) {
	if _, ok := inventory[importPath]; ok {
		return importPath, true
	}
	if !strings.HasPrefix(importPath, "vendor/") {
		vend := "vendor/" + importPath
		if _, ok := inventory[vend]; ok {
			return vend, true
		}
	}
	return "", false
}

// verifyListedPackage checks the structural AST and directive contracts for one
// standard-library package's selected files.
func verifyListedPackage(lp listedPackage) error {
	verdict, verdictErr, ioErr := verifyListedPackageWithIO(context.Background(), lp)
	if ioErr != nil {
		return ioErr
	}
	if verdictErr != nil {
		return verdictErr
	}
	if len(verdict.RequiredInactiveRuntimeGates) > 0 {
		return fmt.Errorf("%s: requires cross-package runtime gate verification %v", lp.ImportPath, verdict.RequiredInactiveRuntimeGates)
	}
	return nil
}

// verifyListedPurePackage checks the pure/delegate AST, assembly, native-file,
// and directive contracts for one standard-library package's selected files.
func verifyListedPurePackage(lp listedPackage) error {
	_, verdictErr, ioErr := verifyPureCandidateWithIO(context.Background(), lp)
	if ioErr != nil {
		return ioErr
	}
	return verdictErr
}

func verifyPureCandidateWithIO(ctx context.Context, lp listedPackage) (verdict verifiedPackageVerdict, verdictErr error, ioErr error) {
	return verifyPureCandidateWithIOAndSalt(ctx, lp, "")
}

func verifyPureCandidateWithIOAndSalt(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (verdict verifiedPackageVerdict, verdictErr error, ioErr error) {
	if err := ctx.Err(); err != nil {
		return verifiedPackageVerdict{}, nil, err
	}
	if lp.Dir == "" {
		return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: empty directory", lp.ImportPath)
	}
	var goFiles, asmFiles, headerFiles []string
	selectedHeaders := map[string]bool{}
	for _, name := range lp.Files {
		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".c", ".cc", ".cpp", ".cxx", ".f", ".m", ".swig", ".swigcxx", ".syso":
			return verifiedPackageVerdict{}, fmt.Errorf("%s: pure package selects native file %s", lp.ImportPath, name), nil
		case ".s":
			asmFiles = append(asmFiles, name)
		case ".h":
			headerFiles = append(headerFiles, name)
			selectedHeaders[name] = true
		case ".go":
			goFiles = append(goFiles, name)
		}
	}
	if len(goFiles) == 0 {
		return verifiedPackageVerdict{}, fmt.Errorf("%s: no selected Go files", lp.ImportPath), nil
	}
	var readCache map[string]trackedFileRead
	if lp.digest != "" {
		readCache = make(map[string]trackedFileRead, len(lp.Files))
	}
	runtimePullTargets := map[string]bool{}
	externalPullTargets := map[string]bool{}
	var nonGoTexts []string
	for _, name := range append(slices.Clone(asmFiles), headerFiles...) {
		if err := ctx.Err(); err != nil {
			return verifiedPackageVerdict{}, nil, err
		}
		src, err := readPackageFileTracked(lp.Dir, name, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		if len(asmFiles) > 0 {
			if err := verifyAssemblyFile(lp.ImportPath, name, string(src), selectedHeaders); err != nil {
				return verifiedPackageVerdict{}, err, nil
			}
		}
		if lp.ImportPath != "runtime" {
			nonGoTexts = append(nonGoTexts, string(src))
		}
	}
	if len(nonGoTexts) > 0 && lp.ImportPath != "runtime" {
		incHdrs, vErr, iErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
		if iErr != nil {
			return verifiedPackageVerdict{}, nil, iErr
		}
		if vErr != nil {
			return verifiedPackageVerdict{}, vErr, nil
		}
		if scanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, runtimePullTargets, externalPullTargets, nil) {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
		}
	}

	fset := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(goFiles))
	for _, name := range goFiles {
		if err := ctx.Err(); err != nil {
			return verifiedPackageVerdict{}, nil, err
		}
		src, err := readPackageFileTracked(lp.Dir, name, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		if err := verifyFileLinknameDirectives(lp.ImportPath, text); err != nil {
			return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
		}
		if lp.ImportPath != "runtime" {
			collectGoLinknameTargets(lp.ImportPath, text, runtimePullTargets, externalPullTargets)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
		}
		parsed = append(parsed, file)
	}
	if lp.digest != "" {
		curDigest, err := verifyReadPackageDigest(ctx, lp, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: %w", lp.ImportPath, err)
		}
		if curDigest != lp.digest {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: source moved during verification", lp.ImportPath)
		}
	}
	if err := verifyPurePackageAST(lp.ImportPath, parsed); err != nil {
		return verifiedPackageVerdict{}, err, nil
	}
	if lp.ImportPath == "bufio" {
		if err := verifyBufioWriterAST(parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	}
	delegateSet := map[string]bool{}
	for _, f := range parsed {
		for _, imp := range f.Imports {
			importPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return verifiedPackageVerdict{}, err, nil
			}
			if !isPureSupportImport(lp.ImportPath, importPath) && !auditset.PurePackage(importPath) {
				delegateSet[importPath] = true
			}
		}
	}
	if len(delegateSet) > 0 {
		verdict.Delegates = sortedKeys(delegateSet)
	}
	if len(runtimePullTargets) > 0 {
		verdict.RuntimeLinknamePulls = sortedKeys(runtimePullTargets)
	}
	if len(externalPullTargets) > 0 {
		verdict.ExternalLinknamePulls = sortedKeys(externalPullTargets)
	}
	return verdict, nil, nil
}

func verifyListedPackageWithIO(ctx context.Context, lp listedPackage) (verdict verifiedPackageVerdict, verdictErr error, ioErr error) {
	return verifyListedPackageWithIOAndSalt(ctx, lp, "")
}

func verifyListedPackageWithIOAndSalt(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (verdict verifiedPackageVerdict, verdictErr error, ioErr error) {
	if err := ctx.Err(); err != nil {
		return verifiedPackageVerdict{}, nil, err
	}
	if lp.Dir == "" {
		return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: empty directory", lp.ImportPath)
	}
	if auditset.PurePackage(lp.ImportPath) {
		return verifyPureCandidateWithIOAndSalt(ctx, lp, pkgIncludeSalt)
	}
	var goFiles, runtimeAsmHeaders, nonGoFiles []string
	for _, name := range lp.Files {
		if strings.EqualFold(filepath.Ext(name), ".go") {
			goFiles = append(goFiles, name)
		} else if lp.ImportPath == "runtime" && allowedPureAsmStandardHeaders[name] {
			runtimeAsmHeaders = append(runtimeAsmHeaders, name)
		} else if lp.ImportPath == "os" || lp.ImportPath == "internal/testlog" || lp.ImportPath == "testing/internal/testdeps" || lp.ImportPath == "testing" {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: unexpected non-Go file %s", lp.ImportPath, name), nil
		} else {
			nonGoFiles = append(nonGoFiles, name)
		}
	}
	var readCache map[string]trackedFileRead
	if lp.digest != "" {
		readCache = make(map[string]trackedFileRead, len(lp.Files)+8)
	}
	runtimePullTargets := map[string]bool{}
	externalPullTargets := map[string]bool{}
	runtimeNonGoIdents := map[string]bool{}
	var nonGoTexts []string
	var runtimeIncludeHdrs []string
	var runtimeNonGoTexts []string
	for _, name := range nonGoFiles {
		ext := strings.ToLower(filepath.Ext(name))
		switch ext {
		case ".s", ".h", ".c", ".cc", ".cpp", ".cxx", ".m", ".syso":
			if err := ctx.Err(); err != nil {
				return verifiedPackageVerdict{}, nil, err
			}
			raw, err := readPackageFileTracked(lp.Dir, name, readCache)
			if err != nil {
				return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
			}
			if lp.ImportPath == "runtime" {
				if ext == ".syso" {
					collectRuntimeIdentsAndMachO(raw, runtimeNonGoIdents)
				} else {
					for _, joinSpace := range []bool{false, true} {
						stripped := stripAssemblyComments(string(raw), true, joinSpace)
						collectRuntimeIdentsAndMachO([]byte(stripped), runtimeNonGoIdents)
						collectRuntimeIdentsAndMachO([]byte(collapseTokenPasteOps(normalizeCStringLiterals(stripped, true))), runtimeNonGoIdents)
					}
					if ext == ".h" {
						runtimeIncludeHdrs = append(runtimeIncludeHdrs, string(raw))
					}
					runtimeNonGoTexts = append(runtimeNonGoTexts, string(raw))
				}
			} else {
				if ext == ".syso" {
					collectRawBytesRuntimeSymbolRefs(raw, runtimePullTargets)
				} else {
					nonGoTexts = append(nonGoTexts, string(raw))
				}
			}
		}
	}
	if len(goFiles) == 0 {
		if lp.ImportPath == "os" || lp.ImportPath == "internal/testlog" || lp.ImportPath == "testing" || lp.ImportPath == "testing/internal/testdeps" || lp.ImportPath == "runtime" || lp.ImportPath == "sync" || lp.ImportPath == "reflect" || lp.ImportPath == "time" || lp.ImportPath == "math" || lp.ImportPath == "math/rand" || lp.ImportPath == "context" || lp.ImportPath == "crypto/fips140" || lp.ImportPath == "path/filepath" {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: no selected Go files", lp.ImportPath), nil
		}
		if len(nonGoTexts) > 0 && lp.ImportPath != "runtime" {
			incHdrs, vErr, iErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
			if iErr != nil {
				return verifiedPackageVerdict{}, nil, iErr
			}
			if vErr != nil {
				return verifiedPackageVerdict{}, vErr, nil
			}
			if scanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, runtimePullTargets, externalPullTargets, nil) {
				return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
			}
		}
		if lp.digest != "" && len(nonGoFiles) > 0 {
			curDigest, err := verifyReadPackageDigest(ctx, lp, readCache)
			if err != nil {
				return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: %w", lp.ImportPath, err)
			}
			if curDigest != lp.digest {
				return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: source moved during verification", lp.ImportPath)
			}
		}
		if len(runtimePullTargets) > 0 {
			verdict.RuntimeLinknamePulls = sortedKeys(runtimePullTargets)
		}
		if len(externalPullTargets) > 0 {
			verdict.ExternalLinknamePulls = sortedKeys(externalPullTargets)
		}
		return verdict, nil, nil
	}

	for _, name := range runtimeAsmHeaders {
		if err := ctx.Err(); err != nil {
			return verifiedPackageVerdict{}, nil, err
		}
		src, err := readPackageFileTracked(lp.Dir, name, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		if err := verifyAssemblyFile("", lp.ImportPath+"/"+name, string(src), nil); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
		for _, joinSpace := range []bool{false, true} {
			stripped := stripAssemblyComments(string(src), true, joinSpace)
			collectRuntimeIdentsAndMachO([]byte(stripped), runtimeNonGoIdents)
			collectRuntimeIdentsAndMachO([]byte(collapseTokenPasteOps(normalizeCStringLiterals(stripped, true))), runtimeNonGoIdents)
		}
		if lp.ImportPath == "runtime" {
			runtimeIncludeHdrs = append(runtimeIncludeHdrs, string(src))
		}
	}
	if lp.ImportPath == "runtime" {
		if goroot, ok := stdPackageGOROOT(lp.Dir, lp.ImportPath); ok {
			pkgIncludeDir := filepath.Join(goroot, "pkg", "include")
			info, err := os.Stat(pkgIncludeDir)
			if err != nil && !os.IsNotExist(err) {
				return verifiedPackageVerdict{}, nil, fmt.Errorf("pkg/include: %w", err)
			}
			if err == nil {
				if !info.IsDir() {
					return verifiedPackageVerdict{}, fmt.Errorf("pkg/include: not a directory"), nil
				}
				hdrs, err := pkgIncludeRelativeFiles(ctx, pkgIncludeDir)
				if err != nil {
					return verifiedPackageVerdict{}, nil, fmt.Errorf("pkg/include: %w", err)
				}
				for _, rel := range hdrs {
					if err := ctx.Err(); err != nil {
						return verifiedPackageVerdict{}, nil, err
					}
					fullPath := filepath.Join(pkgIncludeDir, filepath.FromSlash(rel))
					finfo, err := os.Lstat(fullPath)
					if err != nil {
						return verifiedPackageVerdict{}, nil, fmt.Errorf("pkg/include/%s: %w", rel, err)
					}
					if !finfo.Mode().IsRegular() {
						return verifiedPackageVerdict{}, fmt.Errorf("pkg/include/%s: non-regular entry", rel), nil
					}
					src, err := readFileTracked(fullPath, "../../pkg/include/"+rel, readCache)
					if err != nil {
						return verifiedPackageVerdict{}, nil, fmt.Errorf("pkg/include/%s: %w", rel, err)
					}
					if err := verifyAssemblyFile("", "pkg/include/"+rel, string(src), nil); err != nil {
						return verifiedPackageVerdict{}, err, nil
					}
					for _, joinSpace := range []bool{false, true} {
						stripped := stripAssemblyComments(string(src), true, joinSpace)
						collectRuntimeIdentsAndMachO([]byte(stripped), runtimeNonGoIdents)
						collectRuntimeIdentsAndMachO([]byte(collapseTokenPasteOps(normalizeCStringLiterals(stripped, true))), runtimeNonGoIdents)
					}
					runtimeIncludeHdrs = append(runtimeIncludeHdrs, string(src))
				}
			}
		}
	}

	fset := token.NewFileSet()
	parsed := make([]*ast.File, 0, len(goFiles))
	var runtimeGoSrcs []string
	runtimePullLinknames := map[string]bool{}
	osRuntimePullMap := map[string]string{}
	osAnyLinknameLocals := map[string]bool{}
	selfPushLinknames := map[string]bool{}
	isHarnessPkg := lp.ImportPath == "os" || lp.ImportPath == "internal/testlog" || lp.ImportPath == "testing/internal/testdeps" || lp.ImportPath == "testing"
	for _, name := range goFiles {
		if err := ctx.Err(); err != nil {
			return verifiedPackageVerdict{}, nil, err
		}
		src, err := readPackageFileTracked(lp.Dir, name, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err)
		}
		text := string(src)
		if lp.ImportPath == "runtime" {
			runtimeGoSrcs = append(runtimeGoSrcs, text)
			collectGoLinknameTargets(lp.ImportPath, text, nil, externalPullTargets)
		} else {
			collectGoLinknameTargets(lp.ImportPath, text, runtimePullTargets, externalPullTargets)
		}
		if isHarnessPkg {
			if err := verifyHarnessFileDirectives(lp.ImportPath, text, runtimePullLinknames, selfPushLinknames, osRuntimePullMap, osAnyLinknameLocals); err != nil {
				return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
			}
		}
		mode := parser.Mode(0)
		if strings.Contains(text, `"C"`) {
			mode = parser.ParseComments
		}
		file, err := parser.ParseFile(fset, name, src, mode)
		if err != nil {
			return verifiedPackageVerdict{}, fmt.Errorf("%s/%s: %w", lp.ImportPath, name, err), nil
		}
		if mode == parser.ParseComments {
			preambles := extractFileCgoPreambles(file)
			if lp.ImportPath == "runtime" {
				runtimeNonGoTexts = append(runtimeNonGoTexts, preambles...)
			} else {
				nonGoTexts = append(nonGoTexts, preambles...)
			}
		}
		parsed = append(parsed, file)
	}
	if lp.ImportPath == "runtime" && len(runtimeNonGoTexts) > 0 {
		if scanPreprocessedNonGoSymbolRefs(lp.ImportPath, runtimeIncludeHdrs, runtimeNonGoTexts, nil, externalPullTargets, runtimeNonGoIdents) {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
		}
	} else if len(nonGoTexts) > 0 && lp.ImportPath != "runtime" {
		incHdrs, vErr, iErr := loadPkgIncludeHeadersForPackage(ctx, lp, pkgIncludeSalt)
		if iErr != nil {
			return verifiedPackageVerdict{}, nil, iErr
		}
		if vErr != nil {
			return verifiedPackageVerdict{}, vErr, nil
		}
		if scanPreprocessedNonGoSymbolRefs(lp.ImportPath, incHdrs, nonGoTexts, runtimePullTargets, externalPullTargets, nil) {
			return verifiedPackageVerdict{}, fmt.Errorf("%s: non-Go macro expansion budget exceeded", lp.ImportPath), nil
		}
	}
	if lp.digest != "" {
		curDigest, err := verifyReadPackageDigest(ctx, lp, readCache)
		if err != nil {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: %w", lp.ImportPath, err)
		}
		if curDigest != lp.digest {
			return verifiedPackageVerdict{}, nil, fmt.Errorf("%s: source moved during verification", lp.ImportPath)
		}
	}

	switch lp.ImportPath {
	case "runtime":
		verdict.InactiveRuntimeGates = discoverRuntimeInactiveGates(parsed, runtimeGoSrcs, runtimeNonGoIdents)
	case "os":
		reqGates, err := verifyOSPackageAST(parsed, osRuntimePullMap, osAnyLinknameLocals)
		if err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
		verdict.RequiredInactiveRuntimeGates = reqGates
	case "internal/testlog":
		if err := verifyInternalTestlogPackageAST(parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "testing/internal/testdeps":
		if err := verifyTestdepsPackageAST(parsed); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "testing":
		if err := verifyTestingPackageAST(parsed, runtimePullLinknames, selfPushLinknames); err != nil {
			return verifiedPackageVerdict{}, err, nil
		}
	case "path/filepath":
		delegateSet := map[string]bool{}
		for _, f := range parsed {
			for _, imp := range f.Imports {
				importPath, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					return verifiedPackageVerdict{}, err, nil
				}
				if strings.HasPrefix(importPath, "internal/") && !forbiddenPureImport(lp.ImportPath, importPath) && !isPureSupportImport(lp.ImportPath, importPath) && !auditset.PurePackage(importPath) {
					delegateSet[importPath] = true
				}
			}
		}
		if len(delegateSet) > 0 {
			verdict.Delegates = sortedKeys(delegateSet)
		}
	}
	if len(runtimePullTargets) > 0 {
		verdict.RuntimeLinknamePulls = sortedKeys(runtimePullTargets)
	}
	if len(externalPullTargets) > 0 {
		verdict.ExternalLinknamePulls = sortedKeys(externalPullTargets)
	}
	return verdict, nil, nil
}

// selectionDegradation is one toolchain-source audit verdict: the axis
// that refused (empty when audited) and the remedy clause the notice
// appends.
type selectionDegradation struct {
	axis, remedy string
}

// unresolvedSelection is the verdict of a Hasher built without
// construction (the zero value): refused, never admitted by default.
var unresolvedSelection = selectionDegradation{
	axis:   "verdict unresolved: this Hasher was built without construction (NewAt or NewBracketAt)",
	remedy: "; a resolved verdict needs the constructor's selection and toolchain reads",
}

func (d selectionDegradation) audited() bool { return d.axis == "" }

// notice renders the verdict as the one owned notice consumers serve:
// empty exactly when audited, else the axis, the consequence, and the
// remedy — text and verdict can never disagree.
func (d selectionDegradation) notice() string {
	const consequence = " — standard-library observation admissions are disabled (observation proofs strip and serving degrades to execution)"
	if d.axis == "" {
		return ""
	}
	return "toolchain-selection audit: " + d.axis + consequence + d.remedy
}

// toolchainSourceDegradation derives the verdict over the running
// toolchain's surface digests and inventory: a surface that could not be
// listed or read refuses naming the fault; a surface where any audited
// package fails structural verification refuses naming the failed packages;
// otherwise the selection is audited.
func toolchainSourceDegradation(version string, d sourceDigests, listErr error) selectionDegradation {
	deg, _ := toolchainSourceDegradationContext(context.Background(), version, d, listErr)
	return deg
}

func toolchainSourceDegradationContext(ctx context.Context, version string, d sourceDigests, listErr error) (selectionDegradation, error) {
	deg, _, err := toolchainSourceDegradationAndDelegatesContext(ctx, version, d, listErr)
	return deg, err
}

func toolchainSourceDegradationAndDelegatesContext(ctx context.Context, version string, d sourceDigests, listErr error) (selectionDegradation, map[string]bool, error) {
	if listErr != nil {
		return selectionDegradation{
			fmt.Sprintf("the audited surface of %s could not be read: %v", version, listErr),
			"; the admission needs the toolchain's standard-library source listed and readable",
		}, nil, nil
	}
	failed, pureDelegates, ioErr, ctxErr := verifyToolchainSurfaceAndDelegatesWithIO(ctx, d)
	if ctxErr != nil {
		return selectionDegradation{}, nil, ctxErr
	}
	if ioErr != nil {
		return selectionDegradation{
			fmt.Sprintf("the audited surface of %s could not be read: %v", version, ioErr),
			"; the admission needs the toolchain's standard-library source listed and readable",
		}, nil, nil
	}
	if len(failed) == 0 {
		return selectionDegradation{}, pureDelegates, nil
	}
	return selectionDegradation{
		fmt.Sprintf("the audited surface of %s moved in %d keys: %s", version, len(failed), namedMoved(failed)),
		"; the admission needs every audited standard-library package to satisfy the structural source contracts",
	}, nil, nil
}

// resolveSelection derives a pass's toolchain-source verdict through
// its environment reader: the audited surface's digests under the
// explicit build flags in the environment the reader resolves (the go
// command merges GOFLAGS itself), read from the GOROOT the snapshot
// names, the listing memoized per selection scope.
func resolveSelection(ctx context.Context, reader *gotool.EnvReader, buildFlags []string) (selectionDegradation, sourceDigests, error) {
	snapshot, err := reader.Snapshot(ctx)
	if err != nil {
		return selectionDegradation{}, sourceDigests{}, err
	}
	normalized, err := gotool.NormalizeEnv(reader.Env)
	if err != nil {
		return selectionDegradation{}, sourceDigests{}, err
	}
	d, listErr := toolchainSourceDigests(ctx, reader.Runner, reader.Dir, normalized, snapshot, buildFlags)
	d.Policy = admissionPolicy()
	if listErr == nil {
		for _, root := range auditedSurfaceTables() {
			first, _, _ := strings.Cut(root, "/")
			if strings.Contains(first, ".") {
				continue
			} // module-version audits
			if _, ok := d.inventory[root]; !ok {
				listErr = fmt.Errorf("required audited standard package %s was not inventoried", root)
				d.Content = ""
				break
			}
		}
	}
	if ctx.Err() != nil {
		return selectionDegradation{}, sourceDigests{}, ctx.Err()
	}
	deg, pureDelegates, err := toolchainSourceDegradationAndDelegatesContext(ctx, snapshot.Value("GOVERSION"), d, listErr)
	if err != nil {
		return selectionDegradation{}, sourceDigests{}, err
	}
	if deg.audited() {
		d.pureDelegates = pureDelegates
	}
	return deg, d, nil
}

func isInternalStdPackagePath(pkgPath string) bool {
	return pkgPath == "internal" || strings.HasPrefix(pkgPath, "internal/") || strings.HasSuffix(pkgPath, "/internal") || strings.Contains(pkgPath, "/internal/")
}

// ResolveToolchainSelection resolves the toolchain content digest, admission
// policy digest, and toolchain-source audit notice for reader and buildFlags.
func ResolveToolchainSelection(ctx context.Context, reader *gotool.EnvReader, buildFlags []string) (content, policy, notice string, err error) {
	if reader == nil {
		return "", "", "", fmt.Errorf("closure: nil environment reader")
	}
	verdict, source, err := resolveSelection(ctx, reader, buildFlags)
	if err != nil {
		return "", "", "", err
	}
	return source.Content, source.Policy, verdict.notice(), nil
}

// SelectionAudited reports this Hasher's toolchain-source audit verdict
// — a constructor-resolved verdict with an empty notice, one derivation
// with the rendering: the consumer-tier scans (purity, dynamic state)
// and the view surfaces answer their audited-set consultations from the
// same verdict the closure tiers thread internally. An unresolved
// (zero-value) Hasher refuses.
func (h *Hasher) SelectionAudited() bool {
	return h.verdict().audited()
}

func (h *Hasher) verdict() selectionDegradation {
	if !h.selectionResolved {
		return unresolvedSelection
	}
	return h.selection
}

// SelectionNotice renders this Hasher's verdict as the owned notice:
// empty when audited.
func (h *Hasher) SelectionNotice() string {
	return h.verdict().notice()
}

// SelectionAttribution is the verdict's axis — the text a tier refusal
// composed under an unaudited selection carries as its attribution
// (REQ-closure-refusal-channels); empty when audited.
func (h *Hasher) SelectionAttribution() string {
	return h.verdict().axis
}

// AttributeSelection appends the selection's attribution to a tier
// refusal's reason: a refusal judged under an unaudited selection names
// it, so a consumer sees that the selection, not the subject, may be
// the cause; an audited selection or an empty reason is unchanged.
func AttributeSelection(reason, axis string) string {
	if axis == "" || reason == "" {
		return reason
	}
	return reason + " (judged under an unaudited toolchain selection: " + axis + ")"
}
