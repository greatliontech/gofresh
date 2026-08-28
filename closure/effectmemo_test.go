package closure

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
)

func pinnedFixture(t *testing.T, h *Hasher) (listPkg, string) {
	t.Helper()
	moduleDir := filepath.Join(h.modCache, "example.com", "pinned@v1.2.3")
	pkgDir := filepath.Join(moduleDir, "eff")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The directives populate the wire shape's detail and unrefinable
	// fields, so the serve test's DeepEqual pins the full round trip.
	source := "package eff\n\nimport \"os\"\n\n//go:wasmimport host log\n//go:linkname E\nfunc E() { _, _ = os.ReadFile(\"x\") }\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "eff.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := listPkg{
		ImportPath: "example.com/pinned/eff",
		Dir:        pkgDir,
		GoFiles:    []string{"eff.go"},
		Module:     &listMod{Path: "example.com/pinned", Version: "v1.2.3", Dir: moduleDir, Main: false},
	}
	return pkg, pkgDir
}

// TestEffectScanMemoServesPinnedPackagesWithoutReads pins the memo's core
// property (REQ-closure-effect-scan-memo): a pinned package's scan derived
// once serves from the persistent memo with no file reads — proven by
// deleting the files and serving the identical scan from a fresh Hasher.
func TestEffectScanMemoServesPinnedPackagesWithoutReads(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/host\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Steer the fake module cache under the temp tree.
	h.modCache = filepath.Join(dir, "modcache")
	pkg, pkgDir := pinnedFixture(t, h)

	derived, handled, err := h.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("derivation = handled %v, err %v", handled, err)
	}
	if derived.preferred == "" || len(derived.effects) == 0 {
		t.Fatalf("derived scan carries no facts: %+v", derived)
	}
	// Every guard leg runs while the fixture's files are still readable,
	// so a weakened guard genuinely derives and serves rather than
	// escaping through a read error. A module reporting no version takes
	// the read path even when its files sit inside the module cache: its
	// pin would carry no signal. (Reachable listings report no version
	// only for the main and workspace modules; the leg is witnessed here
	// in its own right.)
	unversioned := pkg
	unversioned.Module = &listMod{Path: "example.com/pinned", Dir: filepath.Dir(pkgDir), Main: false}
	if _, handled, err := h.pinnedEffectScan(unversioned); err != nil || handled {
		t.Fatalf("unversioned in-cache package = handled %v, err %v; want unhandled, nil", handled, err)
	}
	// A version-labeled module living outside the module cache (a local
	// replace) and a module without a content dir likewise read.
	dirless := pkg
	dirless.Module = &listMod{Path: "example.com/pinned", Version: "v1.2.3", Main: false}
	if _, handled, err := h.pinnedEffectScan(dirless); err != nil || handled {
		t.Fatalf("dirless module = handled %v, err %v; want unhandled, nil", handled, err)
	}
	if err := os.RemoveAll(pkgDir); err != nil {
		t.Fatal(err)
	}
	h2, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2.modCache = h.modCache
	served, handled, err := h2.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("serve = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(served, derived) {
		t.Fatalf("served scan diverged:\n got %+v\nwant %+v", served, derived)
	}
	// A mutable-local package never enters this memo — with a real,
	// readable file, so a weakened guard would genuinely derive and
	// serve rather than escape through a read error.
	localDir := filepath.Join(dir, "local")
	if err := os.MkdirAll(localDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "eff.go"), []byte("package eff\n\nimport \"os\"\n\nfunc E() { _, _ = os.ReadFile(\"x\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	local := pkg
	local.Module = &listMod{Main: true, Dir: dir}
	local.Dir = localDir
	if _, handled, err := h2.pinnedEffectScan(local); err != nil || handled {
		t.Fatalf("mutable-local package = handled %v, err %v; want unhandled, nil", handled, err)
	}
	// A synthetic version label on a module outside the cache still reads:
	// the cache-membership leg holds on its own.
	replaced := pkg
	replaced.Module = &listMod{Path: "example.com/pinned", Version: "v1.2.3", Dir: localDir, Main: false}
	replaced.Dir = localDir
	if _, handled, err := h2.pinnedEffectScan(replaced); err != nil || handled {
		t.Fatalf("local-replace package = handled %v, err %v; want unhandled, nil", handled, err)
	}
	// Package-level facts ride the live listing, never the memo: the same
	// key serves a different composite when the build configuration moves
	// a metadata fact (an assembly file selected only under some tags),
	// still with no file reads.
	asm := pkg
	asm.SFiles = []string{"impl_asm.s"}
	withAsm, handled, err := h2.pinnedEffectScan(asm)
	if err != nil || !handled {
		t.Fatalf("assembly-carrying serve = handled %v, err %v", handled, err)
	}
	if !hasEffectReason(withAsm.effects, "reaches non-standard assembly") {
		t.Fatalf("assembly fact missing from the served composite: %+v", withAsm)
	}
	if hasEffectReason(served.effects, "reaches non-standard assembly") {
		t.Fatalf("assembly fact leaked into the assembly-free composite: %+v", served)
	}
}

func hasEffectReason(effects []externalEffect, reason string) bool {
	for _, effect := range effects {
		if effect.reason == reason {
			return true
		}
	}
	return false
}

// TestEffectScanMemoFoldMatchesInlineFold pins the byte-equivalence clause
// (REQ-closure-effect-scan-memo) against the inline loop's flat fold on a
// fixture that discriminates: a duplicate effect across two files, competing
// preferred diagnostics, and a package-level fact folding in first. Both the
// miss-path derivation and the memo hit must equal the flat per-item fold.
func TestEffectScanMemoFoldMatchesInlineFold(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/host\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.modCache = filepath.Join(dir, "modcache")
	pkg, pkgDir := pinnedFixture(t, h)
	if err := os.WriteFile(filepath.Join(pkgDir, "more.go"), []byte("package eff\n\nimport \"os\"\n\nfunc F() { _, _ = os.Open(\"y\"); _, _ = os.ReadFile(\"x\") }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "netimp.go"), []byte("package eff\n\nimport \"net\"\n\nfunc G() { _ = net.Dial }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg.GoFiles = append(pkg.GoFiles, "more.go", "netimp.go")
	pkg.SFiles = []string{"impl_asm.s"}

	flat := maximalPackageExternalEffects(&pkg)
	pkgFactCount := len(flat.effects)
	var rawEffects int
	var preferreds []string
	for _, name := range pkg.GoFiles {
		scan, err := maximalFileEffects(true, filepath.Join(pkgDir, name))
		if err != nil {
			t.Fatal(err)
		}
		rawEffects += len(scan.effects)
		preferreds = append(preferreds, scan.preferred)
		for _, effect := range scan.effects {
			flat.effects = appendExternalEffect(flat.effects, effect)
		}
		for _, candidate := range scan.importCandidates {
			flat.importCandidates = appendExternalEffect(flat.importCandidates, candidate)
		}
		if len(scan.effects) == 0 && len(scan.importCandidates) == 0 && scan.preferred != "" && (flat.preferred == "" || scan.preferred < flat.preferred) {
			flat.preferred = scan.preferred
		}
	}
	if selected := preferredEffectReason(append(append([]externalEffect(nil), flat.effects...), flat.importCandidates...)); selected != "" {
		flat.preferred = selected
	}
	if rawEffects <= len(flat.effects)-pkgFactCount {
		t.Fatalf("fixture does not discriminate dedup: %d raw file effects, %d folded", rawEffects, len(flat.effects)-pkgFactCount)
	}
	if len(preferreds) != 3 || preferreds[0] == preferreds[1] || preferreds[1] == preferreds[2] || preferreds[0] == preferreds[2] {
		t.Fatalf("fixture does not discriminate the preferred fold: %v", preferreds)
	}

	derived, handled, err := h.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("derivation = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(derived, flat) {
		t.Fatalf("miss-path composite diverged from the flat fold:\n got %+v\nwant %+v", derived, flat)
	}
	h2, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h2.modCache = h.modCache
	served, handled, err := h2.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("serve = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(served, flat) {
		t.Fatalf("memo hit diverged from the flat fold:\n got %+v\nwant %+v", served, flat)
	}
	// The stored fold carries no package-level facts: deriving under a
	// configuration that selects the assembly file and then serving under
	// one that does not must drop the assembly fact, not replay it.
	var flatNoAsm maximalEffectScan
	for _, name := range pkg.GoFiles {
		scan, err := maximalFileEffects(true, filepath.Join(pkgDir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, effect := range scan.effects {
			flatNoAsm.effects = appendExternalEffect(flatNoAsm.effects, effect)
		}
		for _, candidate := range scan.importCandidates {
			flatNoAsm.importCandidates = appendExternalEffect(flatNoAsm.importCandidates, candidate)
		}
		if len(scan.effects) == 0 && len(scan.importCandidates) == 0 && scan.preferred != "" && (flatNoAsm.preferred == "" || scan.preferred < flatNoAsm.preferred) {
			flatNoAsm.preferred = scan.preferred
		}
	}
	if selected := preferredEffectReason(append(append([]externalEffect(nil), flatNoAsm.effects...), flatNoAsm.importCandidates...)); selected != "" {
		flatNoAsm.preferred = selected
	}
	noAsm := pkg
	noAsm.SFiles = nil
	servedNoAsm, handled, err := h2.pinnedEffectScan(noAsm)
	if err != nil || !handled {
		t.Fatalf("assembly-free serve = handled %v, err %v", handled, err)
	}
	if !reflect.DeepEqual(servedNoAsm, flatNoAsm) {
		t.Fatalf("assembly-free memo hit diverged from the flat file fold:\n got %+v\nwant %+v", servedNoAsm, flatNoAsm)
	}
}

// TestEffectScanMemoMissesOnScopeAndFileSetChange pins the key's
// completeness: a strategy-scope change, the toolchain identity, a file-set
// change, and the Go/cgo partition each miss, and a corrupt entry
// recomputes silently.
func TestEffectScanMemoMissesOnScopeAndFileSetChange(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	scan := maximalEffectScan{
		preferred:        "reaches net (network I/O)",
		effects:          []externalEffect{{kind: externalEffectFileIO, reason: "reaches os.ReadFile (file I/O)"}},
		importCandidates: []externalEffect{{kind: externalEffectNetwork, packagePath: "net", reason: "reaches net (network I/O)"}},
	}
	key := effectScanKey("example.com/pinned@v1.2.3", "example.com/pinned/eff", []string{"eff.go"}, nil)
	storeEffectScan(effectScanDirName, (&Hasher{selectionAudited: true}).effectScanScope(), key, scan)
	if got, ok := loadEffectScan(effectScanDirName, (&Hasher{selectionAudited: true}).effectScanScope(), key); !ok || !reflect.DeepEqual(got, scan) {
		t.Fatalf("round trip = %+v ok=%v", got, ok)
	}
	if _, ok := loadEffectScan(effectScanDirName, (&Hasher{selectionAudited: true}).effectScanScope()+"-bumped", key); ok {
		t.Fatal("a bumped scan strategy served a prior generation's scan")
	}
	if _, ok := loadEffectScan(effectScanDirName, effectScanStrategy, key); ok {
		t.Fatal("the bare strategy without the toolchain identity served")
	}
	if _, ok := loadEffectScan(testingScanDirName, (&Hasher{selectionAudited: true}).effectScanScope(), key); ok {
		t.Fatal("the sibling testing-scan directory served the effect-scan entry")
	}
	otherFiles := effectScanKey("example.com/pinned@v1.2.3", "example.com/pinned/eff", []string{"eff.go", "extra.go"}, nil)
	if _, ok := loadEffectScan(effectScanDirName, (&Hasher{selectionAudited: true}).effectScanScope(), otherFiles); ok {
		t.Fatal("a changed file set served the prior set's scan")
	}
	migrated := effectScanKey("example.com/pinned@v1.2.3", "example.com/pinned/eff", nil, []string{"eff.go"})
	if _, ok := loadEffectScan(effectScanDirName, (&Hasher{selectionAudited: true}).effectScanScope(), migrated); ok {
		t.Fatal("a file migrating between the Go and cgo lists served the prior partition's scan")
	}
	path, err := cachefile.Path(effectScanDirName, (&Hasher{selectionAudited: true}).effectScanScope(), key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadEffectScan(effectScanDirName, (&Hasher{selectionAudited: true}).effectScanScope(), key); ok {
		t.Fatal("a corrupt entry served")
	}
}

// A package whose files carry only potential-external fallbacks - no
// effects, no plain always-external candidates - selects the
// lexicographically least fallback, package-wide
// (REQ-closure-observability-analysis's cause-preference order).
func TestPinnedFallbackSelectsLexicographicLeast(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/host\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := NewAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.modCache = filepath.Join(dir, "modcache")
	pkg, pkgDir := pinnedFixture(t, h)
	for name, source := range map[string]string{
		"only_time.go": "package eff\n\nvar _ = timeJan\n",
		"only_fmt.go":  "package eff\n\nimport \"fmt\"\n\nfunc S(v int) string { return fmt.Sprintf(\"%d\", v) }\n",
		"decl_time.go": "package eff\n\nimport \"time\"\n\nvar timeJan = time.January\n",
	} {
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg.GoFiles = []string{"decl_time.go", "only_fmt.go", "only_time.go"}
	composite, handled, err := h.pinnedEffectScan(pkg)
	if err != nil || !handled {
		t.Fatalf("derivation = handled %v, err %v", handled, err)
	}
	if len(composite.effects) != 0 || len(composite.importCandidates) != 0 {
		t.Fatalf("fallback fixture grew effects or candidates: %+v", composite)
	}
	if composite.preferred != "reaches fmt (potential external dependence)" {
		t.Fatalf("fallback selection = %q, want the lexicographic least", composite.preferred)
	}
}
