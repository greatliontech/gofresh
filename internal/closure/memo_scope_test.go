package closure

import (
	"context"

	"os"
	"path/filepath"
	"slices"

	"strings"
	"testing"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/toolchain"
)

func TestAnalysisScopeScanIncludesRootedStrategyUnderExecutionAttestations(t *testing.T) {
	base := AnalysisScope{
		FactStrategy:     "gofresh/dynamic-state@test",
		Toolchain:        "tc",
		BuildConfig:      "bc",
		toolchainContent: "tcc",
		admissionPolicy:  "ap",
	}
	if base.Facts() == "" {
		t.Fatal("plain Facts() is empty")
	}
	if base.Scan() == "" || strings.Contains(base.Scan(), rootedFunctionsStrategy) {
		t.Fatalf("plain Scan() = %q, want non-empty without %q", base.Scan(), rootedFunctionsStrategy)
	}
	pkgExec := base
	pkgExec.PackageProcess = true
	if pkgExec.Facts() != base.Facts() {
		t.Fatalf("PackageProcess Facts() = %q, want identical to base %q", pkgExec.Facts(), base.Facts())
	}
	if !strings.Contains(pkgExec.Scan(), "|package-process-execution|"+rootedFunctionsStrategy) {
		t.Fatalf("PackageProcess Scan() = %q, want package-process marker and %q", pkgExec.Scan(), rootedFunctionsStrategy)
	}
	singleExec := base
	singleExec.SingleSubject = true
	if singleExec.Facts() != base.Facts() {
		t.Fatalf("SingleSubject Facts() = %q, want identical to base %q", singleExec.Facts(), base.Facts())
	}
	if !strings.Contains(singleExec.Scan(), "|single-subject-execution|"+rootedFunctionsStrategy) {
		t.Fatalf("SingleSubject Scan() = %q, want single-subject marker and %q", singleExec.Scan(), rootedFunctionsStrategy)
	}
	bothExec := base
	bothExec.SingleSubject = true
	bothExec.PackageProcess = true
	if bothExec.Facts() != base.Facts() || !strings.Contains(bothExec.Scan(), "|single-subject-execution|package-process-execution|"+rootedFunctionsStrategy) {
		t.Fatalf("both attestations: Facts=%q Scan=%q, want Facts=%q and both execution markers with %q", bothExec.Facts(), bothExec.Scan(), base.Facts(), rootedFunctionsStrategy)
	}
}

func TestMutableFactKeysTracksModuleGraphAndRejectsModfileFlag(t *testing.T) {
	root := t.TempDir()
	dep1 := filepath.Join(root, "dep1")
	dep2 := filepath.Join(root, "dep2")
	app := filepath.Join(root, "app")
	writeFile(t, dep1, "go.mod", "module example.com/dep\n\ngo 1.26\n")
	writeFile(t, dep1, "dep.go", "package dep\n\nfunc V() int { return 1 }\n")
	writeFile(t, dep2, "go.mod", "module example.com/dep\n\ngo 1.26\n")
	writeFile(t, dep2, "dep.go", "package dep\n\nfunc V() int { return 2 }\n")
	writeFile(t, app, "go.mod", "module example.com/app\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\nreplace example.com/dep => ../dep1\n")
	writeFile(t, app, "app.go", "package app\n\nimport (\n\t_ \"embed\"\n\t\"example.com/dep\"\n)\n\n//go:embed assets/*\nvar _ string\n\nfunc F() int { return dep.V() }\n")
	writeFile(t, app, "excluded.go", "//go:build ignore\n\npackage app\n\nvar IgnoredHook func()\n")
	writeFile(t, filepath.Join(app, "assets"), "one.txt", "one\n")

	h, err := newAt(app)
	if err != nil {
		t.Fatal(err)
	}
	pkgPath := "example.com/app"
	meta, err := h.GraphMetadata(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	preKeys, expectedFiles := h.MutableFactKeys("facts@1", meta, false, pkgPath)
	if preKeys[pkgPath] == "" || !expectedFiles[pkgPath][filepath.Clean(filepath.Join(app, "app.go"))] {
		t.Fatalf("initial MutableFactKeys = (%v, %v), want non-empty key and app.go", preKeys, expectedFiles)
	}
	sameKeys, _ := h.MutableFactKeys("facts@1", meta, true, pkgPath)
	if sameKeys[pkgPath] != preKeys[pkgPath] {
		t.Fatalf("freshDisk MutableFactKeys on unchanged tree = %q, want %q", sameKeys[pkgPath], preKeys[pkgPath])
	}

	// Rewriting go.mod's replace target on disk without reloading metadata must
	// move the freshDisk key immediately.
	writeFile(t, app, "go.mod", "module example.com/app\n\ngo 1.26\n\nrequire example.com/dep v0.0.0\nreplace example.com/dep => ../dep2\n")
	driftedKeys, _ := h.MutableFactKeys("facts@1", meta, true, pkgPath)
	if driftedKeys[pkgPath] == "" || driftedKeys[pkgPath] == preKeys[pkgPath] {
		t.Fatalf("freshDisk MutableFactKeys after go.mod replace edit = %q, want distinct non-empty key from %q", driftedKeys[pkgPath], preKeys[pkgPath])
	}

	// SnapshotScanInputs fails closed on zero value and -modfile, and captures
	// non-empty file digests, absent sentinels, and mutable-local directory entries.
	if (TreeDigestSnapshot{}).MatchesDisk() {
		t.Fatal("zero TreeDigestSnapshot unexpectedly matched disk")
	}
	snap := h.SnapshotScanInputs(pkgPath)
	if !snap.valid || len(snap.files) == 0 || len(snap.absent) == 0 || len(snap.pkgDirs) == 0 {
		t.Fatalf("SnapshotScanInputs = %+v, want valid non-empty files/absent/pkgDirs", snap)
	}
	if !snap.MatchesDisk() {
		t.Fatal("fresh SnapshotScanInputs did not match unchanged disk")
	}
	// Editing a tracked file invalidates MatchesDisk.
	writeFile(t, app, "app.go", "package app\n\nimport (\n\t_ \"embed\"\n\t\"example.com/dep\"\n)\n\n//go:embed assets/*\nvar _ string\n\nfunc F() int { return dep.V() + 1 }\n")
	if snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs matched after app.go content edit")
	}
	writeFile(t, app, "app.go", "package app\n\nimport (\n\t_ \"embed\"\n\t\"example.com/dep\"\n)\n\n//go:embed assets/*\nvar _ string\n\nfunc F() int { return dep.V() }\n")
	if !snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs did not match after restoring app.go")
	}
	// Editing a build-tag-excluded file in place (dropping //go:build ignore)
	// invalidates MatchesDisk via source-ext byte digests.
	writeFile(t, app, "excluded.go", "package app\n\nvar IgnoredHook func()\n")
	if snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs matched after in-place edit of build-tag-excluded excluded.go")
	}
	writeFile(t, app, "excluded.go", "//go:build ignore\n\npackage app\n\nvar IgnoredHook func()\n")
	if !snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs did not match after restoring excluded.go")
	}
	// Adding a file inside an //go:embed directory invalidates MatchesDisk via embedRoots pkgDirs.
	extraAsset := filepath.Join(app, "assets", "two.txt")
	writeFile(t, filepath.Join(app, "assets"), "two.txt", "two\n")
	if snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs matched after adding file under //go:embed directory")
	}
	if err := os.Remove(extraAsset); err != nil {
		t.Fatal(err)
	}
	if !snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs did not match after removing extra embedded file")
	}
	// Adding an untracked *_test.go file in app invalidates MatchesDisk via pkgDirs.
	testPath := filepath.Join(app, "app_test.go")
	writeFile(t, app, "app_test.go", "package app\n")
	if snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs matched after adding app_test.go")
	}
	if err := os.Remove(testPath); err != nil {
		t.Fatal(err)
	}
	// Materializing a previously-absent go.sum invalidates MatchesDisk via absent sentinels.
	goSumPath := filepath.Join(app, "go.sum")
	writeFile(t, app, "go.sum", "")
	if snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs matched after previously-absent go.sum appeared")
	}
	if err := os.Remove(goSumPath); err != nil {
		t.Fatal(err)
	}
	if !snap.MatchesDisk() {
		t.Fatal("SnapshotScanInputs did not match after removing go.sum")
	}

	// Passing -modfile disables MutableFactKeys and SnapshotScanInputs so callers fail closed.
	hModfile, err := newAt(app, "-modfile="+filepath.Join(app, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	modfileKeys, modfileFiles := hModfile.MutableFactKeys("facts@1", meta, false, pkgPath)
	if len(modfileKeys) != 0 || len(modfileFiles) != 0 {
		t.Fatalf("MutableFactKeys with -modfile = (%v, %v), want empty", modfileKeys, modfileFiles)
	}
	if hModfile.SnapshotScanInputs(pkgPath).MatchesDisk() {
		t.Fatal("SnapshotScanInputs with -modfile unexpectedly matched disk")
	}

	// Hasher constructed with reader.Dir == "" (current working directory) in a
	// subdirectory of a module inside a go.work workspace must still track both
	// go.work replace edits and intermediate go.mod sentinels.
	sub := filepath.Join(app, "sub")
	writeFile(t, sub, "sub.go", "package sub\n\nimport \"example.com/dep\"\n\nfunc S() int { return dep.V() }\n")
	writeFile(t, root, "go.work", "go 1.26\n\nuse ./app\nreplace example.com/dep => ./dep1\n")
	t.Setenv("GOWORK", "")
	t.Chdir(sub)
	cwdHasher, err := NewAt(context.Background(), &gotool.EnvReader{Dir: "", Env: os.Environ()})
	if err != nil {
		t.Fatal(err)
	}
	subPkg := "example.com/app/sub"
	subMeta, err := cwdHasher.GraphMetadata(subPkg)
	if err != nil {
		t.Fatal(err)
	}
	cwdKeys0, _ := cwdHasher.MutableFactKeys("facts@1", subMeta, false, subPkg)
	if cwdKeys0[subPkg] == "" {
		t.Fatalf("Dir==\"\" MutableFactKeys = %v, want non-empty key", cwdKeys0)
	}
	writeFile(t, root, "go.work", "go 1.26\n\nuse ./app\nreplace example.com/dep => ./dep2\n")
	cwdKeysWorkEdited, _ := cwdHasher.MutableFactKeys("facts@1", subMeta, true, subPkg)
	if cwdKeysWorkEdited[subPkg] == "" || cwdKeysWorkEdited[subPkg] == cwdKeys0[subPkg] {
		t.Fatalf("Dir==\"\" MutableFactKeys after go.work replace edit = %q, want distinct from %q", cwdKeysWorkEdited[subPkg], cwdKeys0[subPkg])
	}
	writeFile(t, root, "go.work", "go 1.26\n\nuse ./app\nreplace example.com/dep => ./dep1\n")
	writeFile(t, sub, "go.mod", "module example.com/app/sub\n\ngo 1.26\n")
	cwdKeysNestedMod, _ := cwdHasher.MutableFactKeys("facts@1", subMeta, true, subPkg)
	if cwdKeysNestedMod[subPkg] == "" || cwdKeysNestedMod[subPkg] == cwdKeys0[subPkg] {
		t.Fatalf("Dir==\"\" MutableFactKeys after nested sub/go.mod appeared = %q, want distinct from %q", cwdKeysNestedMod[subPkg], cwdKeys0[subPkg])
	}
}

func TestViewLoadClassifiersAndTestMainPredicates(t *testing.T) {
	if pkgDir, modDir := LoadedPackageDirs(nil); pkgDir != "" || modDir != "" {
		t.Fatalf("LoadedPackageDirs(nil) = (%q, %q), want empty", pkgDir, modDir)
	}
	if class, pin := ClassifyLoadedPackage(nil, "/cache"); class != StandardPackage || pin != "" {
		t.Fatalf("ClassifyLoadedPackage(nil) = (%v, %q), want StandardPackage", class, pin)
	}

	modCache := filepath.FromSlash("/cache/mod")
	pinnedModDir := filepath.Join(modCache, "example.com", "dep@v1.2.3")
	pinnedPkg := &packages.Package{
		ID:         "example.com/dep/sub",
		PkgPath:    "example.com/dep/sub",
		OtherFiles: []string{filepath.Join(pinnedModDir, "sub", "asm.s")},
		Module:     &packages.Module{Path: "example.com/dep", Version: "v1.2.3", Dir: pinnedModDir},
	}
	if pkgDir, modDir := LoadedPackageDirs(pinnedPkg); pkgDir != filepath.Join(pinnedModDir, "sub") || modDir != pinnedModDir {
		t.Fatalf("LoadedPackageDirs(pinnedPkg) = (%q, %q)", pkgDir, modDir)
	}
	h := &Hasher{modCache: modCache}
	if class, pin := h.ClassifyLoadedPackage(pinnedPkg); class != PinnedPackage || pin != "example.com/dep@v1.2.3" {
		t.Fatalf("ClassifyLoadedPackage(pinnedPkg) = (%v, %q), want (PinnedPackage, example.com/dep@v1.2.3)", class, pin)
	}

	syntheticPinned := &packages.Package{
		PkgPath: "example.com/synth",
		Module:  &packages.Module{Path: "example.com/synth", Version: "v1.0.0"},
	}
	if class, pin := ClassifyLoadedPackage(syntheticPinned, ""); class != PinnedPackage || pin != "" {
		t.Fatalf("ClassifyLoadedPackage(syntheticPinned, \"\") = (%v, %q), want (PinnedPackage, \"\")", class, pin)
	}
	if class, _ := ClassifyLoadedPackage(syntheticPinned, modCache); class != MutableLocalPackage {
		t.Fatalf("ClassifyLoadedPackage(syntheticPinned, modCache) = %v, want MutableLocalPackage when pkgDir is empty", class)
	}

	replacedPkg := &packages.Package{
		PkgPath:    "example.com/rep",
		EmbedFiles: []string{"/local/rep/data.txt"},
		Module: &packages.Module{
			Path:    "example.com/rep",
			Dir:     pinnedModDir,
			Replace: &packages.Module{Path: "../rep", Dir: "/local/rep"},
		},
	}
	if class, _ := h.ClassifyLoadedPackage(replacedPkg); class != MutableLocalPackage {
		t.Fatalf("ClassifyLoadedPackage(replacedPkg) = %v, want MutableLocalPackage", class)
	}

	variantPkg := &packages.Package{PkgPath: "example.com/p", ForTest: "example.com/p"}
	if got := gotool.LoadedListingID(variantPkg); got != "example.com/p [example.com/p.test]" {
		t.Fatalf("LoadedListingID(variantPkg) = %q", got)
	}

	genMain := &packages.Package{
		ID:      "example.test.test",
		PkgPath: "example.test.test",
		Name:    "main",
		GoFiles: []string{"/tmp/go-build/_testmain.go"},
		Imports: map[string]*packages.Package{
			"example.test [example.test.test]": {PkgPath: "example.test", ForTest: "example.test"},
		},
	}
	if !gotool.IsGeneratedTestMainPackage(genMain) || !gotool.IsGeneratedTestMainPackageFor(genMain, "example.test") || gotool.IsGeneratedTestMainPackageFor(genMain, "other") {
		t.Fatal("generated test main misclassified")
	}

	userDotTestMain := &packages.Package{
		ID:      "example.test",
		PkgPath: "example.test",
		Name:    "main",
		Dir:     "/work/example.test",
		GoFiles: []string{"/work/example.test/main.go"},
		Imports: map[string]*packages.Package{
			"example.test/lib": {ID: "example.test/lib", PkgPath: "example.test/lib"},
		},
	}
	if gotool.IsGeneratedTestMainPackage(userDotTestMain) || gotool.IsGeneratedTestMainPackageFor(userDotTestMain, "example.test") || gotool.IsGeneratedTestMainPackageFor(userDotTestMain, "example") {
		t.Fatal("user-authored module example.test package main misclassified as generated test main")
	}
}

func TestCollectModuleInputsNestedWorkspaceTransitiveReplacesAndDanglingSymlink(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	leaf := filepath.Join(sub, "leaf")
	rep1 := filepath.Join(root, "rep1")
	rep2 := filepath.Join(root, "rep2")
	wrep1 := filepath.Join(root, "wrep1")
	wrep2 := filepath.Join(root, "wrep2")
	for _, d := range []string{root, sub, leaf, rep1, rep2, wrep1, wrep2} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, root, "go.work", "go 1.26\n\nuse (\n\t.\n\t./sub\n\t./sub/leaf\n)\n\nreplace example.com/wrep1 => ./wrep1\n")
	writeFile(t, root, "go.mod", "module example.com/root\n\ngo 1.26\n\nrequire example.com/rep1 v0.0.0\n\nreplace example.com/rep1 => ./rep1\n")
	writeFile(t, root, "root.go", "package root\nfunc R() int { return 1 }\n")
	writeFile(t, sub, "go.mod", "module example.com/root/sub\n\ngo 1.26\n")
	writeFile(t, sub, "sub.go", "package sub\nfunc S() int { return 2 }\n")
	writeFile(t, leaf, "go.mod", "module example.com/root/sub/leaf\n\ngo 1.26\n")
	writeFile(t, leaf, "leaf.go", "package leaf\nfunc L() int { return 3 }\n")
	writeFile(t, rep1, "go.mod", "module example.com/rep1\n\ngo 1.26\n\nrequire example.com/rep2 v0.0.0\n\nreplace example.com/rep2 => ../rep2\n")
	writeFile(t, rep2, "go.mod", "module example.com/rep2\n\ngo 1.26\n")
	writeFile(t, rep2, "go.sum", "example.com/x v1.0.0 h1:abc=\n")
	writeFile(t, wrep1, "go.mod", "module example.com/wrep1\n\ngo 1.26\n\nrequire example.com/wrep2 v0.0.0\n\nreplace example.com/wrep2 => ../wrep2\n")
	writeFile(t, wrep2, "go.mod", "module example.com/wrep2\n\ngo 1.26\n")

	withGoWork := func(val string) []string {
		base := slices.DeleteFunc(os.Environ(), func(kv string) bool {
			return strings.HasPrefix(kv, "GOWORK=")
		})
		return append(base, "GOWORK="+val)
	}
	env := withGoWork(filepath.Join(root, "go.work"))
	snap, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), leaf, env)
	if err != nil {
		t.Fatal(err)
	}
	h := &Hasher{
		ctx:         context.Background(),
		dir:         leaf,
		snapshot:    snap,
		fileDigests: map[string]string{},
		selection:   toolchain.SelectionForTest(true, "", "", "tc-content", "", nil, nil),
	}
	pkgs := []listPkg{{
		ImportPath: "example.com/root",
		Name:       "root",
		Dir:        root,
		GoFiles:    []string{"root.go"},
		Module:     &listMod{Path: "example.com/root", Dir: root, GoMod: filepath.Join(root, "go.mod"), Main: true},
	}}
	rec, ok := h.listingInputs("example.com/root", pkgs)
	if !ok {
		t.Fatal("listingInputs rejected valid nested workspace")
	}
	for _, wantFile := range []string{
		filepath.Join(root, "go.work"),
		filepath.Join(root, "go.mod"),
		filepath.Join(sub, "go.mod"),
		filepath.Join(leaf, "go.mod"),
		filepath.Join(rep1, "go.mod"),
		filepath.Join(rep2, "go.mod"),
		filepath.Join(rep2, "go.sum"),
		filepath.Join(wrep1, "go.mod"),
		filepath.Join(wrep2, "go.mod"),
	} {
		if rec.Files[wantFile] == "" {
			t.Fatalf("missing %s from rec.Files: %v", wantFile, rec.Files)
		}
		if slices.Contains(rec.Absent, wantFile) {
			t.Fatalf("existing %s erroneously recorded in rec.Absent: %v", wantFile, rec.Absent)
		}
	}

	// Dangling symlink at an intermediate go.mod path must fail closed rather than
	// entering rec.Absent (os.ReadFile returns IsNotExist while os.Lstat succeeds).
	midDir := filepath.Join(leaf, "inner")
	if err := os.MkdirAll(midDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "does-not-exist-gomod"), filepath.Join(midDir, "go.mod")); err == nil {
		hDangling := &Hasher{
			ctx:         context.Background(),
			dir:         midDir,
			snapshot:    snap,
			fileDigests: map[string]string{},
			selection:   toolchain.SelectionForTest(true, "", "", "tc-content", "", nil, nil),
		}
		if _, ok := hDangling.listingInputs("example.com/root", pkgs); ok {
			t.Fatal("dangling go.mod symlink accepted into listingInputs")
		}
		if _, _, ok := hDangling.moduleGraphInputs(true, []string{"example.com/root"}, [][]listPkg{pkgs}); ok {
			t.Fatal("dangling go.mod symlink accepted into moduleGraphInputs")
		}
	}

	// Symlinked h.dir inside a standalone module must still resolve mainDir,
	// record intermediate absent go.mod / go.work sentinels, and invalidate
	// TreeDigestSnapshot.MatchesDisk when an intermediate go.mod appears.
	standaloneBase := t.TempDir()
	realMod := filepath.Join(standaloneBase, "real", "repo")
	realMid := filepath.Join(realMod, "mid")
	realLeaf := filepath.Join(realMid, "leaf")
	if err := os.MkdirAll(realLeaf, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, realMod, "go.mod", "module example.com/standalone\n\ngo 1.26\n")
	writeFile(t, realLeaf, "leaf.go", "package leaf\nfunc V() int { return 7 }\n")
	symParent := filepath.Join(standaloneBase, "symdir")
	if err := os.MkdirAll(symParent, 0o755); err != nil {
		t.Fatal(err)
	}
	symRepo := filepath.Join(symParent, "repo")
	if err := os.Symlink(realMod, symRepo); err == nil {
		symLeaf := filepath.Join(symRepo, "mid", "leaf")
		symEnv := withGoWork("")
		realSnap, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), realLeaf, symEnv)
		if err != nil {
			t.Fatal(err)
		}
		realPkgs := []listPkg{{
			ImportPath: "example.com/standalone/mid/leaf",
			Name:       "leaf",
			Dir:        realLeaf,
			GoFiles:    []string{"leaf.go"},
			Module:     &listMod{Path: "example.com/standalone", Dir: realMod, GoMod: filepath.Join(realMod, "go.mod"), Main: true},
		}}
		hSymPhysical := &Hasher{
			ctx:         context.Background(),
			dir:         symLeaf,
			snapshot:    realSnap,
			fileDigests: map[string]string{},
			selection:   toolchain.SelectionForTest(true, "", "", "tc-content", "", nil, nil),
		}
		_, absentBefore, ok := hSymPhysical.moduleGraphInputs(true, []string{"example.com/standalone/mid/leaf"}, [][]listPkg{realPkgs})
		if !ok || !slices.Contains(absentBefore, filepath.Join(realMid, "go.mod")) {
			t.Fatalf("moduleGraphInputs under symlinked h.dir failed to record realMid/go.mod in absent: ok=%v absent=%v", ok, absentBefore)
		}
		hSym, err := NewAt(context.Background(), gotool.PrimedEnvReader(gotool.Runner{}, symLeaf, symEnv, realSnap))
		if err != nil {
			t.Fatal(err)
		}
		treeSnap := hSym.SnapshotScanInputs("example.com/standalone/mid/leaf")
		if !treeSnap.MatchesDisk() {
			t.Fatalf("expected valid TreeDigestSnapshot on symlinked h.dir with physical GOMOD snapshot, got %+v", treeSnap)
		}
		writeFile(t, realMid, "go.mod", "module example.com/standalone/mid\n\ngo 1.26\n")
		if treeSnap.MatchesDisk() {
			t.Fatal("TreeDigestSnapshot.MatchesDisk missed mid-load intermediate mid/go.mod creation under symlinked h.dir")
		}
	}
}
