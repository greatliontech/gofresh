package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/closure/internal/digest"
)

// The listing memo serves a package's `go list -json -deps -test` output
// when every input the listing consulted is byte-identical to the one
// the stored listing was derived from. go list is a deterministic
// function of the toolchain and environment (the pass's env snapshot),
// the build flags, the working directory, the module graph's files, and
// the contents of every mutable-local directory it reads — file names,
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
const listingRecordVersion = 2

// listingRecord is one persisted listing with the inputs it was derived
// from: file digests by absolute path, directory entry names by absolute
// directory, and paths that must not exist.
type listingRecord struct {
	Version  int                 `json:"version"`
	Files    map[string]string   `json:"files"`
	Dirs     map[string][]string `json:"dirs"`
	Absent   []string            `json:"absent"`
	Packages []listPkg           `json:"packages"`
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

// listingScope is the memo scope: the record version and shape, the env
// snapshot's identity, the working directory, and the build flags.
// Empty — the memo inert — when the Hasher was built without a
// snapshot, or when a flag names a module file outside the recorded
// input model.
func (h *Hasher) listingScope() string {
	if h.snapshot == nil {
		return ""
	}
	for _, flag := range append(strings.Fields(h.snapshot.Value("GOFLAGS")), h.buildFlags...) {
		name := strings.TrimLeft(strings.Trim(flag, `"'`), "-")
		if name == "modfile" || strings.HasPrefix(name, "modfile=") {
			return ""
		}
	}
	sum := sha256.Sum256([]byte(h.snapshot.Identity()))
	return "listing|" + strconv.Itoa(listingRecordVersion) + "|" + listingShape + "|" + hex.EncodeToString(sum[:16]) + "|" + h.dir + "|" + strings.Join(h.buildFlags, "\x00")
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
		got, err := dirEntryNames(dir)
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
// bytes, the trees under its embed patterns, the module files of every
// module the module graph reads — each module contributing a package
// (vendored nodes carry no module directory and ride the vendor tree),
// every module the workspace uses, and the target of every local
// replacement those files name — the vendor manifest of the main module
// and of the workspace root, the workspace file the snapshot resolved
// (or its absence along the ancestor chain), and the absence of a
// module file between the working directory and the main module root. False when no main module
// contains the working directory, or a module or workspace file
// carries a directive this build cannot parse (reported as a
// diagnostic on every pass the condition holds): the pass stays
// unmodelled and spawns.
func (h *Hasher) listingInputs(pkgPath string, pkgs []listPkg) (*listingRecord, bool) {
	rec := &listingRecord{Version: listingRecordVersion, Files: map[string]string{}, Dirs: map[string][]string{}}
	absent := map[string]bool{}
	addFile := func(path string) ([]byte, bool) {
		if _, done := rec.Files[path]; done || absent[path] {
			return nil, true
		}
		content, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				absent[path] = true
				return nil, true
			}
			return nil, false
		}
		rec.Files[path] = digest.Content(content)
		return content, true
	}
	addDir := func(dir string) bool {
		if _, done := rec.Dirs[dir]; done {
			return true
		}
		names, err := dirEntryNames(dir)
		if err != nil {
			return false
		}
		rec.Dirs[dir] = names
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
	// addModule records a module directory's go.mod and go.sum and, from
	// the go.mod, the module file of every local replacement target —
	// requirements the graph reads without any package of the target
	// entering this listing.
	modules := map[string]bool{}
	addModule := func(dir string) bool {
		dir = filepath.Clean(dir)
		if modules[dir] {
			return true
		}
		modules[dir] = true
		// The module file is read here regardless of whether an earlier
		// record (a replacement target's) already digested it: the
		// replace scan below must run once per module, not once per
		// first sighting of its file.
		goMod := filepath.Join(dir, "go.mod")
		if _, ok := addFile(goMod); !ok {
			return false
		}
		if _, ok := addFile(filepath.Join(dir, "go.sum")); !ok {
			return false
		}
		content, err := os.ReadFile(goMod)
		if err != nil {
			return os.IsNotExist(err)
		}
		f, err := modfile.Parse(goMod, content, nil)
		if err != nil {
			h.emitDiagnostic("listing-unmodelled", pkgPath, goMod+": "+err.Error()+"; the listing is spawned every pass")
			return false
		}
		for _, r := range f.Replace {
			if r.New.Version != "" {
				continue
			}
			target := r.New.Path
			if !filepath.IsAbs(target) {
				target = filepath.Join(dir, target)
			}
			if _, ok := addFile(filepath.Join(target, "go.mod")); !ok {
				return false
			}
		}
		return true
	}
	var mainDirs []string
	for _, p := range pkgs {
		if p.Standard || p.Module == nil || h.pinnedPackage(&p) || p.IsGeneratedTestMainFor(pkgPath) {
			continue
		}
		if p.Module.Dir != "" {
			if p.Module.Main && !modules[filepath.Clean(p.Module.Dir)] {
				mainDirs = append(mainDirs, filepath.Clean(p.Module.Dir))
			}
			if !addModule(p.Module.Dir) {
				return nil, false
			}
		}
		dir := filepath.Clean(p.Dir)
		if !addDir(dir) {
			return nil, false
		}
		for _, name := range rec.Dirs[dir] {
			if !listingSourceExts[filepath.Ext(name)] {
				continue
			}
			path := filepath.Join(dir, name)
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() {
				// A dangling link or a non-regular entry is a name the
				// listing sees and no byte it reads.
				continue
			}
			if _, ok := addFile(path); !ok {
				return nil, false
			}
		}
		for _, root := range embedRoots(dir, p.EmbedPatterns, p.TestEmbedPatterns, p.XTestEmbedPatterns) {
			info, err := os.Stat(root)
			switch {
			case err != nil:
				if !os.IsNotExist(err) {
					return nil, false
				}
				if !addDir(filepath.Dir(root)) {
					return nil, false
				}
			case info.IsDir():
				if !addTree(root) {
					return nil, false
				}
			default:
				if !addDir(filepath.Dir(root)) {
					return nil, false
				}
			}
		}
	}
	dir := filepath.Clean(h.dir)
	if !filepath.IsAbs(dir) {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, false
		}
		dir = abs
	}
	mainDir := ""
	for _, candidate := range mainDirs {
		if (dir == candidate || strings.HasPrefix(dir, candidate+string(filepath.Separator))) && len(candidate) > len(mainDir) {
			mainDir = candidate
		}
	}
	if mainDir == "" {
		return nil, false
	}
	for d := dir; d != mainDir; d = filepath.Dir(d) {
		absent[filepath.Join(d, "go.mod")] = true
	}
	if _, ok := addFile(filepath.Join(mainDir, "vendor", "modules.txt")); !ok {
		return nil, false
	}
	switch work := h.snapshot.Value("GOWORK"); work {
	case "off":
	case "":
		for d := dir; ; d = filepath.Dir(d) {
			absent[filepath.Join(d, "go.work")] = true
			if filepath.Dir(d) == d {
				break
			}
		}
	default:
		content, ok := addFile(work)
		if !ok {
			return nil, false
		}
		if content == nil {
			h.emitDiagnostic("listing-unmodelled", pkgPath, work+": the workspace file the environment resolved is absent; the listing is spawned every pass")
			return nil, false
		}
		if _, ok := addFile(strings.TrimSuffix(work, ".work") + ".work.sum"); !ok {
			return nil, false
		}
		wf, err := modfile.ParseWork(work, content, nil)
		if err != nil {
			h.emitDiagnostic("listing-unmodelled", pkgPath, work+": "+err.Error()+"; the listing is spawned every pass")
			return nil, false
		}
		workDir := filepath.Dir(work)
		// `go work vendor` writes the manifest at the workspace root,
		// which is never a module directory.
		if _, ok := addFile(filepath.Join(workDir, "vendor", "modules.txt")); !ok {
			return nil, false
		}
		for _, use := range wf.Use {
			target := use.Path
			if !filepath.IsAbs(target) {
				target = filepath.Join(workDir, target)
			}
			if !addModule(target) {
				return nil, false
			}
		}
		for _, r := range wf.Replace {
			if r.New.Version != "" {
				continue
			}
			target := r.New.Path
			if !filepath.IsAbs(target) {
				target = filepath.Join(workDir, target)
			}
			if _, ok := addFile(filepath.Join(target, "go.mod")); !ok {
				return nil, false
			}
		}
	}
	for path := range absent {
		rec.Absent = append(rec.Absent, path)
	}
	sort.Strings(rec.Absent)
	return rec, true
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

// dirEntryNames returns a directory's entry names, sorted.
func dirEntryNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}
