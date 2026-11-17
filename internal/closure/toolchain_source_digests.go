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
	"sort"
	"strings"

	"github.com/greatliontech/gofresh/internal/cachefile"
	"github.com/greatliontech/gofresh/internal/closure/internal/listing"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/trace"
)

// pkgIncludeHeaderCache caches GOROOT/pkg/include header contents keyed by
// goroot+"|"+pkgIncludeSalt when pkgIncludeSalt is non-empty.
var pkgIncludeHeaderCache cachefile.SyncMemo[[]string]

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

// loadPkgIncludeHeaders loads all regular files under GOROOT/pkg/include in
// deterministic relative-path order, populating readCache when non-nil and
// consulting pkgIncludeHeaderCache when readCache is nil and pkgIncludeSalt is non-empty.
func loadPkgIncludeHeaders(ctx context.Context, lp listedPackage, pkgIncludeSalt string, readCache map[string]trackedFileRead) (rels []string, headers []string, verdictErr error, ioErr error) {
	goroot, ok := packageGOROOTForInclude(lp.Dir, lp.ImportPath)
	if !ok {
		return nil, nil, nil, nil
	}
	cacheKey := ""
	if readCache == nil && pkgIncludeSalt != "" {
		cacheKey = goroot + "|" + pkgIncludeSalt
		if v, okC := pkgIncludeHeaderCache.Load(cacheKey); okC {
			return nil, v, nil, nil
		}
	}
	pkgIncludeDir, rels, notDir, err := resolvePkgIncludeDirAndFiles(ctx, goroot)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("pkg/include: %w", err)
	}
	if notDir {
		return nil, nil, fmt.Errorf("pkg/include: not a directory"), nil
	}
	if pkgIncludeDir == "" {
		return nil, nil, nil, nil
	}
	headers = make([]string, 0, len(rels))
	for _, rel := range rels {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		fullPath := filepath.Join(pkgIncludeDir, filepath.FromSlash(rel))
		finfo, err := os.Lstat(fullPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("pkg/include/%s: %w", rel, err)
		}
		if !finfo.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("pkg/include/%s: non-regular entry", rel), nil
		}
		raw, err := readFileTracked(fullPath, "../../pkg/include/"+rel, readCache)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("pkg/include/%s: %w", rel, err)
		}
		headers = append(headers, string(raw))
	}
	if cacheKey != "" {
		pkgIncludeHeaderCache.Store(cacheKey, headers)
	}
	return rels, headers, nil, nil
}

func loadPkgIncludeHeadersForPackage(ctx context.Context, lp listedPackage, pkgIncludeSalt string) (headers []string, verdictErr error, ioErr error) {
	_, headers, verdictErr, ioErr = loadPkgIncludeHeaders(ctx, lp, pkgIncludeSalt, nil)
	return headers, verdictErr, ioErr
}

func digestFiles(ctx context.Context, dir string, files []string) (string, error) {
	return digestFilesBuffered(ctx, dir, files, make([]byte, 32*1024))
}

func digestFilesBuffered(ctx context.Context, dir string, files []string, buffer []byte) (string, error) {
	return digestFilesWithExtraBuffered(ctx, dir, files, "", nil, buffer)
}

func digestListedPackageBuffered(ctx context.Context, p listedPackage, buffer []byte) (string, error) {
	if p.ImportPath == "runtime" {
		if goroot, ok := stdPackageGOROOT(p.Dir, p.ImportPath); ok {
			pkgIncludeDir, extra, notDir, err := resolvePkgIncludeDirAndFiles(ctx, goroot)
			if err != nil {
				return "", err
			}
			if notDir {
				return "", fmt.Errorf("pkg/include: not a directory")
			}
			if pkgIncludeDir != "" {
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
			dir, rels, notDir, err := resolvePkgIncludeDirAndFiles(ctx, goroot)
			if err != nil {
				return "", err
			}
			if notDir {
				return "", fmt.Errorf("pkg/include: not a directory")
			}
			pkgIncludeDir = dir
			extraRels = rels
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

func toolchainSourceScope(snapshot *gotool.EnvSnapshot, buildFlags []string, seeds []string) string {
	seedDigest := sha256.Sum256([]byte(strings.Join(seeds, "\n")))
	return fmt.Sprintf("%d|%s|%s|%x", sourceDigestsVersion, strings.Join(buildFlags, "\x00"), toolchainSnapshotIdentity(snapshot), seedDigest[:8])
}

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

const movedKeysBound = 8

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
