package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/cachefile"
)

// The listing memo serves a package's `go list -json -deps -test` output
// when every input the listing consulted is byte-identical to the one
// the stored listing was derived from. go list is a deterministic
// function of the toolchain and environment (the pass's env snapshot),
// the build flags, the working directory, the module graph's files, and
// the contents of every mutable-local directory it reads — entry names/kinds,
// and the bytes of every source-kind file, whose build constraints and
// import lines shape the graph — plus the trees under embed patterns,
// whose membership the listing resolves; version-pinned modules are
// immutable under their pin, which go.sum carries. The entry records
// those inputs beside the listing and a hit re-verifies every one of
// them against the file system, so a served listing is the listing the
// spawn would produce (REQ-closure-listing-memo). The memo is a cache,
// never a record: any mismatch, corruption, or unreadable input
// recomputes silently.

// listingDirName is the listing memo's store directory.
const listingDirName = "listing"

// listingRecordVersion moves whenever the input model changes; the
// record's Go shape rides the scope on its own (listingShape), so a
// field added to the listing's package type retires older entries
// without a version bump.
const listingRecordVersion = 4

// listingRecord is one persisted listing with the inputs it was derived
// from: file digests by absolute path, effective entry classifications by
// absolute directory, and paths that must not exist.
type listingRecord struct {
	Version  int                       `json:"version"`
	Files    map[string]string         `json:"files"`
	Dirs     map[string][]listingEntry `json:"dirs"`
	Absent   []string                  `json:"absent"`
	Packages []listPkg                 `json:"packages"`
}

// listingEntry keeps both the entry's kind and a symlink's effective kind.
// A dangling link can become source without its own name or kind changing.
type listingEntry struct {
	Name       string      `json:"name"`
	Type       os.FileMode `json:"type"`
	TargetType os.FileMode `json:"targetType"`
	Dangling   bool        `json:"dangling"`
}

func (e listingEntry) regular() bool {
	return e.Type == 0 || e.Type == os.ModeSymlink && !e.Dangling && e.TargetType == 0
}

// listingShape is the record type's structural identity — every field
// name and type, recursively — so an entry written by a binary with
// another record shape lives under another scope and never decodes
// with zero-valued fields.
var listingShape = typeShape(reflect.TypeOf(listingRecord{}))

func typeShape(t reflect.Type) string {
	var b strings.Builder
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		switch t.Kind() {
		case reflect.Struct:
			if seen[t] {
				b.WriteString("recursive")
				return
			}
			seen[t] = true
			b.WriteString("{")
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				b.WriteString(f.Name + ":")
				walk(f.Type)
				b.WriteString(";")
			}
			b.WriteString("}")
			delete(seen, t)
		case reflect.Pointer, reflect.Slice, reflect.Array:
			b.WriteString(t.Kind().String() + " ")
			walk(t.Elem())
		case reflect.Map:
			b.WriteString("map[")
			walk(t.Key())
			b.WriteString("]")
			walk(t.Elem())
		default:
			b.WriteString(t.Kind().String())
		}
	}
	walk(t)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// listingSourceExts are the file kinds go list reads to classify a
// package's files; every other entry contributes its name only.
var listingSourceExts = map[string]bool{
	".go": true, ".c": true, ".cc": true, ".cxx": true, ".cpp": true, ".m": true,
	".h": true, ".hh": true, ".hpp": true, ".hxx": true,
	".s": true, ".S": true, ".sx": true, ".swig": true, ".swigcxx": true, ".syso": true,
	".f": true, ".F": true, ".for": true, ".f90": true,
}

// listingScope is the memo scope: the record version and shape, the
// pass snapshot's identity (every Hasher holds its pass's), the working
// directory, and the build flags. Empty — the memo inert — when a flag
// names a module file outside the recorded input model.
func (h *Hasher) listingScope() string {
	if h.ToolchainContent() == "" {
		return ""
	}
	if hasExplicitModfileFlag(h.snapshot.Value("GOFLAGS"), h.buildFlags) {
		return ""
	}
	sum := sha256.Sum256([]byte(h.snapshot.Identity()))
	return "listing|" + strconv.Itoa(listingRecordVersion) + "|" + listingShape + "|" + hex.EncodeToString(sum[:16]) + "|" + h.ToolchainContent() + "|" + h.dir + "|" + strings.Join(h.buildFlags, "\x00")
}

// loadListing serves pkgPath's listing when the persisted record exists
// and every recorded input verifies against the file system; the
// verified file digests ride to the Hasher's per-file memo so a naming
// consumer never re-reads a byte the verification already digested.
func (h *Hasher) loadListing(pkgPath string) ([]listPkg, bool) {
	scope := h.listingScope()
	if scope == "" || h.contextErr() != nil {
		return nil, false
	}
	var rec listingRecord
	if !cachefile.Load(listingDirName, scope, pkgPath, &rec) || rec.Version != listingRecordVersion {
		return nil, false
	}
	for dir, want := range rec.Dirs {
		got, err := listingEntries(dir)
		if err != nil || !slices.Equal(got, want) {
			return nil, false
		}
	}
	for _, path := range rec.Absent {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return nil, false
		}
	}
	digests := make(map[string]string, len(rec.Files))
	for path, want := range rec.Files {
		fb, err := h.readFile(path)
		if err != nil {
			return nil, false
		}
		got := fb.digest()
		if got != want {
			return nil, false
		}
		digests[path] = got
	}
	for path, d := range digests {
		h.fileDigests[path] = d
	}
	return rec.Packages, true
}

// storeListing persists pkgPath's freshly spawned listing with its
// derived inputs; a listing whose inputs cannot be modelled is not
// stored.
func (h *Hasher) storeListing(pkgPath string, pkgs []listPkg) {
	scope := h.listingScope()
	if scope == "" {
		return
	}
	rec, ok := h.listingInputs(pkgPath, pkgs)
	if !ok {
		return
	}
	rec.Packages = pkgs
	cachefile.Store(listingDirName, scope, pkgPath, rec)
}

// listingInputs derives the input record of pkgPath's listing: every
// mutable-local package directory's entry names and source-kind file
// bytes, the trees under its embed patterns, and every module/workspace
// file and absent sentinel collected by collectModuleInputs. False when
// no main module contains the working directory, or a module or
// workspace file cannot be parsed or safely modelled.
func (h *Hasher) listingInputs(pkgPath string, pkgs []listPkg) (*listingRecord, bool) {
	modFiles, absentPaths, ok := h.collectModuleInputs(moduleInputOptions{
		requireMainModule:  true,
		emitUnmodelledDiag: true,
		diagPkgPath:        pkgPath,
		pkgPaths:           []string{pkgPath},
	}, [][]listPkg{pkgs})
	if !ok {
		return nil, false
	}
	rec := &listingRecord{
		Version: listingRecordVersion,
		Files:   modFiles,
		Dirs:    map[string][]listingEntry{},
		Absent:  absentPaths,
	}
	addSourceFile := func(path string) bool {
		path = filepath.Clean(path)
		if _, done := rec.Files[path]; done {
			return true
		}
		fb, err := h.readFile(path)
		if err != nil {
			return false
		}
		rec.Files[path] = fb.digest()
		return true
	}
	for _, p := range pkgs {
		if p.Standard || p.Module == nil || h.pinnedPackage(&p) || p.IsGeneratedTestMainFor(pkgPath) {
			continue
		}
		if !recordPackageDirInputs(p.Dir, &p, rec.Dirs, addSourceFile) {
			return nil, false
		}
	}
	return rec, true
}

// recordPackageDirInputs records dir's entry listing, every regular source-ext
// file in dir (compiled and build-tag-excluded alike), and every directory
// consulted by p's //go:embed patterns into dirs.
func recordPackageDirInputs(dir string, p *listPkg, dirs map[string][]listingEntry, addSourceFile func(string) bool) bool {
	addDir := func(d string) bool {
		d = filepath.Clean(d)
		if _, done := dirs[d]; done {
			return true
		}
		names, err := listingEntries(d)
		if err != nil {
			return false
		}
		dirs[d] = names
		return true
	}
	addTree := func(root string) bool {
		return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && !addDir(path) {
				return os.ErrInvalid
			}
			return nil
		}) == nil
	}
	dir = filepath.Clean(dir)
	if !addDir(dir) {
		return false
	}
	for _, entry := range dirs[dir] {
		if !listingSourceExts[filepath.Ext(entry.Name)] || !entry.regular() {
			continue
		}
		if !addSourceFile(filepath.Join(dir, entry.Name)) {
			return false
		}
	}
	for _, root := range embedRoots(dir, p.EmbedPatterns, p.TestEmbedPatterns, p.XTestEmbedPatterns) {
		info, err := os.Stat(root)
		switch {
		case err != nil:
			if !os.IsNotExist(err) {
				return false
			}
			if !addDir(filepath.Dir(root)) {
				return false
			}
		case info.IsDir():
			if !addTree(root) {
				return false
			}
		default:
			if !addDir(filepath.Dir(root)) {
				return false
			}
		}
	}
	return true
}

// embedRoots resolves the directory or file each embed pattern is
// anchored at — the pattern's longest metacharacter-free prefix,
// relative to the package directory — so the trees whose membership the
// listing resolves are recorded whole.
func embedRoots(dir string, patternSets ...[]string) []string {
	seen := map[string]bool{}
	var roots []string
	for _, patterns := range patternSets {
		for _, pattern := range patterns {
			pattern = strings.TrimPrefix(pattern, "all:")
			root := ""
			for _, segment := range strings.Split(pattern, "/") {
				if strings.ContainsAny(segment, `*?[\`) {
					break
				}
				root = filepath.Join(root, segment)
			}
			full := filepath.Join(dir, root)
			if !seen[full] {
				seen[full] = true
				roots = append(roots, full)
			}
		}
	}
	return roots
}

// listingEntries returns the names and effective classifications the listing
// can observe. Permissions and timestamps are not membership identity.
func listingEntries(dir string) ([]listingEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]listingEntry, 0, len(entries))
	for _, e := range entries {
		entry := listingEntry{Name: e.Name(), Type: e.Type()}
		if entry.Type == os.ModeSymlink {
			info, err := os.Stat(filepath.Join(dir, e.Name()))
			if os.IsNotExist(err) {
				entry.Dangling = true
			} else if err != nil {
				return nil, err
			} else {
				entry.TargetType = info.Mode().Type()
			}
		}
		names = append(names, entry)
	}
	return names, nil
}
