package closure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/greatliontech/gofresh/internal/buildflags"
	"github.com/greatliontech/gofresh/internal/dynstate"
)

// PackageClass is the mutability class of one graph package's source, the
// same discrimination the closure hash applies to its contributions:
// standard-library source rides the toolchain guard, module-cache source is
// pinned by its version, and everything else — main module, local replace,
// workspace sibling, vendored copy — is mutable-local and must be observed by
// content on every pass (REQ-closure-mutable-local, REQ-closure-pinned-dep).
type PackageClass = dynstate.PackageClass

const (
	MutableLocalPackage = dynstate.MutableLocalPackage
	StandardPackage     = dynstate.StandardPackage
	PinnedPackage       = dynstate.PinnedPackage
)

// GraphPackage is one node of a view's test-binary package graph as the
// metadata listing names it: enough identity to classify, key, and walk the
// graph without loading any syntax.
type GraphPackage = dynstate.GraphPackage

// GraphMetadata returns the deduplicated test-binary package graphs of
// pkgPaths from the metadata listing — the same listing the closure hash
// walks, so classification here and classification there cannot disagree.
func (h *Hasher) GraphMetadata(pkgPaths ...string) ([]GraphPackage, error) {
	var nodes []GraphPackage
	seen := map[string]bool{}
	for _, pkgPath := range pkgPaths {
		pkgs, err := h.list(pkgPath)
		if err != nil {
			return nil, err
		}
		for _, p := range pkgs {
			if err := h.contextErr(); err != nil {
				return nil, err
			}
			if seen[p.ImportPath] {
				continue
			}
			seen[p.ImportPath] = true
			node := GraphPackage{
				ImportPath: p.ImportPath,
				PkgPath:    p.SourcePath(),
				ForTest:    p.ForTest,
				Imports:    append([]string(nil), p.Imports...),
			}
			if p.Name == "main" && strings.HasSuffix(p.ImportPath, ".test") {
				node.TestMain = true
			}
			switch {
			case p.Standard || p.Module == nil:
				node.Class = StandardPackage
			case h.pinnedPackage(&p):
				node.Class = PinnedPackage
				node.Pin = h.modulePin(p.Module)
			default:
				node.Class = MutableLocalPackage
			}
			nodes = append(nodes, node)
		}
	}
	return nodes, nil
}

func (h *Hasher) moduleGraphInputs(freshDisk bool, listed [][]listPkg) (map[string]string, []string, bool) {
	if h == nil || h.snapshot == nil {
		return nil, nil, false
	}
	goFlags, err := buildflags.Fields(h.snapshot.Value("GOFLAGS"))
	if err != nil {
		return nil, nil, false
	}
	for _, flag := range append(goFlags, h.buildFlags...) {
		name := strings.TrimLeft(flag, "-")
		if name == "modfile" || strings.HasPrefix(name, "modfile=") {
			return nil, nil, false
		}
	}
	readOne := h.readFile
	if freshDisk {
		readOne = readBytes
	}
	modFiles := map[string]string{}
	modContents := map[string][]byte{}
	absentFiles := map[string]bool{}
	recordFile := func(path string) ([]byte, bool) {
		path = filepath.Clean(path)
		if absentFiles[path] {
			return nil, true
		}
		if content, ok := modContents[path]; ok {
			return content, true
		}
		fb, err := readOne(path)
		if err != nil {
			if os.IsNotExist(err) {
				absentFiles[path] = true
				return nil, true
			}
			return nil, false
		}
		modFiles[path] = fb.digest()
		modContents[path] = fb.content
		return fb.content, true
	}
	seenModules := map[string]bool{}
	var recordModule func(dir string) bool
	recordModule = func(dir string) bool {
		dir = filepath.Clean(dir)
		if dir == "" || seenModules[dir] {
			return true
		}
		seenModules[dir] = true
		goMod := filepath.Join(dir, "go.mod")
		content, ok := recordFile(goMod)
		if !ok {
			return false
		}
		if _, ok := recordFile(filepath.Join(dir, "go.sum")); !ok {
			return false
		}
		if _, ok := recordFile(filepath.Join(dir, "vendor", "modules.txt")); !ok {
			return false
		}
		if content == nil {
			return true
		}
		f, err := modfile.Parse(goMod, content, nil)
		if err != nil {
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
			if !recordModule(target) {
				return false
			}
		}
		return true
	}
	var mainDirs []string
	for _, pkgs := range listed {
		for _, p := range pkgs {
			if p.Standard || p.Module == nil || h.pinnedPackage(&p) || (p.Name == "main" && strings.HasSuffix(p.ImportPath, ".test")) {
				continue
			}
			if p.Module.Dir != "" {
				cleanModDir := filepath.Clean(p.Module.Dir)
				if p.Module.Main {
					mainDirs = append(mainDirs, cleanModDir)
				}
				if !recordModule(cleanModDir) {
					return nil, nil, false
				}
			}
		}
	}
	if gomod := h.snapshot.Value("GOMOD"); gomod != "" && gomod != os.DevNull {
		if !recordModule(filepath.Dir(gomod)) {
			return nil, nil, false
		}
	}
	dir := filepath.Clean(h.dir)
	if !filepath.IsAbs(dir) {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, nil, false
		}
		dir = abs
	}
	mainDir := ""
	for _, candidate := range mainDirs {
		if (dir == candidate || strings.HasPrefix(dir, candidate+string(filepath.Separator))) && len(candidate) > len(mainDir) {
			mainDir = candidate
		}
	}
	if mainDir != "" {
		for d := dir; d != mainDir; d = filepath.Dir(d) {
			if _, ok := recordFile(filepath.Join(d, "go.mod")); !ok {
				return nil, nil, false
			}
			if filepath.Dir(d) == d {
				break
			}
		}
	}
	switch work := h.snapshot.Value("GOWORK"); work {
	case "off":
	case "":
		for d := dir; ; d = filepath.Dir(d) {
			if _, ok := recordFile(filepath.Join(d, "go.work")); !ok {
				return nil, nil, false
			}
			if filepath.Dir(d) == d {
				break
			}
		}
	default:
		content, ok := recordFile(work)
		if !ok || content == nil {
			return nil, nil, false
		}
		if _, ok := recordFile(strings.TrimSuffix(work, ".work") + ".work.sum"); !ok {
			return nil, nil, false
		}
		workDir := filepath.Dir(work)
		if _, ok := recordFile(filepath.Join(workDir, "vendor", "modules.txt")); !ok {
			return nil, nil, false
		}
		wf, err := modfile.ParseWork(work, content, nil)
		if err != nil {
			return nil, nil, false
		}
		for _, use := range wf.Use {
			target := use.Path
			if !filepath.IsAbs(target) {
				target = filepath.Join(workDir, target)
			}
			if !recordModule(target) {
				return nil, nil, false
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
			if !recordModule(target) {
				return nil, nil, false
			}
		}
	}
	absentPaths := make([]string, 0, len(absentFiles))
	for path := range absentFiles {
		absentPaths = append(absentPaths, path)
	}
	sort.Strings(absentPaths)
	return modFiles, absentPaths, true
}

func (h *Hasher) moduleGraphDigest(freshDisk bool, listed [][]listPkg) (string, bool) {
	modFiles, absentPaths, ok := h.moduleGraphInputs(freshDisk, listed)
	if !ok {
		return "", false
	}
	presentPaths := make([]string, 0, len(modFiles))
	for path := range modFiles {
		presentPaths = append(presentPaths, path)
	}
	sort.Strings(presentPaths)
	sum := sha256.New()
	fmt.Fprintf(sum, "present:%d\x00", len(presentPaths))
	for _, path := range presentPaths {
		fmt.Fprintf(sum, "%d:%s\x00%s\n", len(path), path, modFiles[path])
	}
	fmt.Fprintf(sum, "absent:%d\x00", len(absentPaths))
	for _, path := range absentPaths {
		fmt.Fprintf(sum, "%d:%s\n", len(path), path)
	}
	return hex.EncodeToString(sum.Sum(nil)), true
}

// TreeDigestSnapshot captures the file byte digests, absent module-graph
// sentinels, and mutable-local package directory entry listings observed
// before a typed load so callers can verify no input to PackageScanKey moved
// before persisting scan outputs. The zero value fails closed.
type TreeDigestSnapshot struct {
	valid      bool
	files      map[string]string
	absent     []string
	pkgDirs    map[string][]listingEntry
	wholeTrees []string
}

// SnapshotScanInputs captures the pre-load filesystem state covering pkgPaths'
// mutable-local packages and module/workspace resolution files.
func (h *Hasher) SnapshotScanInputs(pkgPaths ...string) TreeDigestSnapshot {
	if h == nil || len(pkgPaths) == 0 {
		return TreeDigestSnapshot{}
	}
	listed := make([][]listPkg, 0, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		pkgs, err := h.list(pkgPath)
		if err != nil {
			return TreeDigestSnapshot{}
		}
		listed = append(listed, pkgs)
	}
	modFiles, absentPaths, ok := h.moduleGraphInputs(false, listed)
	if !ok {
		return TreeDigestSnapshot{}
	}
	files := make(map[string]string, len(h.fileDigests)+len(modFiles))
	for path, d := range h.fileDigests {
		files[filepath.Clean(path)] = d
	}
	for path, d := range modFiles {
		files[filepath.Clean(path)] = d
	}
	pkgDirs := map[string][]listingEntry{}
	seenWholeTree := map[string]bool{}
	var wholeTrees []string
	recordFile := func(full string) bool {
		full = filepath.Clean(full)
		if _, recorded := files[full]; recorded {
			return true
		}
		fb, err := h.readFile(full)
		if err != nil {
			return false
		}
		files[full] = fb.digest()
		return true
	}
	for _, pkgs := range listed {
		for _, p := range pkgs {
			if p.Standard || p.Module == nil || h.pinnedPackage(&p) || (p.Name == "main" && strings.HasSuffix(p.ImportPath, ".test")) {
				continue
			}
			cleanDir := filepath.Clean(p.Dir)
			if !recordPackageDirInputs(cleanDir, &p, pkgDirs, recordFile) {
				return TreeDigestSnapshot{}
			}
			srcFiles := p.SourceFiles()
			if hasCgoCallbackBlindspot(&p) || len(p.SFiles) > 0 {
				var err error
				srcFiles, err = allPackageFiles(h.contextErr, p.Dir)
				if err != nil {
					return TreeDigestSnapshot{}
				}
				if !seenWholeTree[cleanDir] {
					seenWholeTree[cleanDir] = true
					wholeTrees = append(wholeTrees, cleanDir)
				}
			}
			for _, name := range srcFiles {
				if !recordFile(filepath.Join(p.Dir, name)) {
					return TreeDigestSnapshot{}
				}
			}
		}
	}
	return TreeDigestSnapshot{
		valid:      true,
		files:      files,
		absent:     absentPaths,
		pkgDirs:    pkgDirs,
		wholeTrees: wholeTrees,
	}
}

// MatchesDisk reports whether s was validly captured and every recorded file
// digest, absent sentinel, and mutable-local package directory listing still
// matches disk.
func (s TreeDigestSnapshot) MatchesDisk() bool {
	if !s.valid {
		return false
	}
	for path, want := range s.files {
		cur, err := readBytes(path)
		if err != nil || cur.digest() != want {
			return false
		}
	}
	for _, path := range s.absent {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return false
		}
	}
	for dir, want := range s.pkgDirs {
		got, err := listingEntries(dir)
		if err != nil || !slices.Equal(got, want) {
			return false
		}
	}
	for _, treeDir := range s.wholeTrees {
		rels, err := allPackageFiles(func() error { return nil }, treeDir)
		if err != nil {
			return false
		}
		for _, rel := range rels {
			if _, ok := s.files[filepath.Clean(filepath.Join(treeDir, rel))]; !ok {
				return false
			}
		}
	}
	return true
}

// MutableFactKeys derives per-listing content-and-pin keys and expected source
// file sets for every MutableLocalPackage node in meta from the current tree's
// source bytes, module/workspace resolution files, and reachable version pins
// (REQ-closure-dynamic-state-memo).
// When freshDisk is true, file bytes are re-read directly from disk rather than
// h's pass cache so callers can bracket a typed load against mid-load edits.
// Cgo packages and any node whose transitive import cone or module graph fails
// to read, digest, or pin omit their key so the caller derives fresh.
func (h *Hasher) MutableFactKeys(factScope string, meta []GraphPackage, freshDisk bool, pkgPaths ...string) (map[string]string, map[string]map[string]bool) {
	if factScope == "" || len(meta) == 0 || len(pkgPaths) == 0 {
		return nil, nil
	}
	listed := make([][]listPkg, 0, len(pkgPaths))
	localPkgDigest := map[string]string{}
	filesByListing := map[string]map[string]bool{}
	fileDigests := map[string]string{}
	fileFailed := map[string]bool{}
	for _, pkgPath := range pkgPaths {
		pkgs, err := h.list(pkgPath)
		if err != nil {
			return nil, nil
		}
		listed = append(listed, pkgs)
		for _, p := range pkgs {
			if err := h.contextErr(); err != nil {
				return nil, nil
			}
			if p.Standard || p.Module == nil || h.pinnedPackage(&p) || (p.Name == "main" && strings.HasSuffix(p.ImportPath, ".test")) {
				continue
			}
			if _, recorded := localPkgDigest[p.ImportPath]; recorded {
				continue
			}
			if len(p.CgoFiles) > 0 {
				localPkgDigest[p.ImportPath] = ""
				continue
			}
			srcFiles := p.SourceFiles()
			paths := make([]string, 0, len(srcFiles))
			seenPath := make(map[string]bool, len(srcFiles))
			for _, name := range srcFiles {
				full := filepath.Clean(filepath.Join(p.Dir, name))
				if !seenPath[full] {
					seenPath[full] = true
					paths = append(paths, full)
				}
			}
			sort.Strings(paths)
			sum := sha256.New()
			fmt.Fprintf(sum, "import:%d:%s\x00pkg:%d:%s\x00fortest:%d:%s\x00files:%d\x00",
				len(p.ImportPath), p.ImportPath, len(p.SourcePath()), p.SourcePath(), len(p.ForTest), p.ForTest, len(paths))
			ok := true
			for _, full := range paths {
				if fileFailed[full] {
					ok = false
					break
				}
				d, have := fileDigests[full]
				if !have {
					var fb fileBytes
					var readErr error
					if freshDisk {
						fb, readErr = readBytes(full)
					} else {
						fb, readErr = h.readFile(full)
					}
					if readErr != nil {
						fileFailed[full] = true
						ok = false
						break
					}
					d = fb.digest()
					fileDigests[full] = d
				}
				fmt.Fprintf(sum, "%d:%s\x00%s\n", len(full), full, d)
			}
			if !ok {
				localPkgDigest[p.ImportPath] = ""
				continue
			}
			localPkgDigest[p.ImportPath] = hex.EncodeToString(sum.Sum(nil))
			filesByListing[p.ImportPath] = seenPath
		}
	}

	modDigest, ok := h.moduleGraphDigest(freshDisk, listed)
	if !ok {
		return nil, nil
	}

	imports := make(map[string][]string, len(meta))
	pins := make(map[string]string, len(meta))
	unpinnedDep := make(map[string]bool)
	local := make(map[string]bool, len(meta))
	knownNode := make(map[string]bool, len(meta)+1)
	knownNode["unsafe"] = true
	for _, node := range meta {
		imports[node.ImportPath] = node.Imports
		if !node.TestMain {
			knownNode[node.ImportPath] = true
		}
		if node.Class == PinnedPackage {
			if node.Pin == "" {
				unpinnedDep[node.ImportPath] = true
			} else {
				pins[node.ImportPath] = node.Pin
			}
		}
		if node.Class == MutableLocalPackage && !node.TestMain {
			local[node.ImportPath] = true
		}
	}

	keys := map[string]string{}
	for _, node := range meta {
		if node.Class != MutableLocalPackage || node.TestMain {
			continue
		}
		pinSet := map[string]bool{}
		var localEntries []string
		seen := map[string]bool{}
		ok := true
		var walk func(string)
		walk = func(listing string) {
			if !ok || seen[listing] {
				return
			}
			seen[listing] = true
			if !knownNode[listing] || unpinnedDep[listing] {
				ok = false
				return
			}
			if pin := pins[listing]; pin != "" {
				pinSet[pin] = true
			}
			if local[listing] {
				d := localPkgDigest[listing]
				if d == "" {
					ok = false
					return
				}
				localEntries = append(localEntries, listing+"="+d)
			}
			for _, imp := range imports[listing] {
				walk(imp)
			}
		}
		walk(node.ImportPath)
		if !ok {
			continue
		}
		pinList := make([]string, 0, len(pinSet))
		for pin := range pinSet {
			pinList = append(pinList, pin)
		}
		sort.Strings(pinList)
		sort.Strings(localEntries)
		sum := sha256.New()
		fmt.Fprintf(sum, "scope:%d:%s\x00modgraph:%s\x00listing:%d:%s\x00pins:%d\x00",
			len(factScope), factScope, modDigest, len(node.ImportPath), node.ImportPath, len(pinList))
		for _, pin := range pinList {
			fmt.Fprintf(sum, "%d:%s\n", len(pin), pin)
		}
		fmt.Fprintf(sum, "locals:%d\x00", len(localEntries))
		for _, entry := range localEntries {
			fmt.Fprintf(sum, "%d:%s\n", len(entry), entry)
		}
		keys[node.ImportPath] = hex.EncodeToString(sum.Sum(nil))
	}
	return keys, filesByListing
}
