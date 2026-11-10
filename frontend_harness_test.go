package gofresh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/types"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/buildflags"
	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/dynstate"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/testvariant"
	"github.com/greatliontech/gofresh/internal/trace"
)

type engine = Session

type option func(*Session)

func withBuildFlags(flags ...string) option {
	return func(e *Session) { e.buildFlags = append([]string(nil), flags...) }
}

func withGoRunner(r gotool.Runner) option {
	return func(e *Session) { e.runner = r }
}

func withBuildInputs(inputs ...string) option {
	return func(e *Session) { e.buildInputs = append([]string(nil), inputs...) }
}

func withProgress(f func(Progress)) option {
	return func(e *Session) { e.progress = f }
}

func withAnalysisBudget(d time.Duration) option {
	return func(e *Session) { e.analysisBudget = d }
}

func withAssumePure(pred func(Subject) bool) option {
	return func(e *Session) {
		if pred != nil {
			e.assumePure = pred
		}
	}
}

func withDynamicStateVouches(identities ...string) option {
	return func(e *Session) {
		if len(identities) == 0 {
			return
		}
		if e.dynamicStateVouches == nil {
			e.dynamicStateVouches = make(map[string]bool, len(identities))
		}
		for _, identity := range identities {
			if identity != "" {
				e.dynamicStateVouches[identity] = true
			}
		}
	}
}

func withSingleSubjectExecution() option {
	return func(e *Session) { e.executionModel = SingleSubjectExecution }
}

func withPackageProcessExecution() option {
	return func(e *Session) {
		if e.executionModel != SingleSubjectExecution {
			e.executionModel = PackageExecution
		}
	}
}

func withDeferredCheckClose() option {
	return func(e *Session) { e.deferredCheckClose = true }
}

func withDir(dir string) option {
	return func(e *Session) { e.dir = dir }
}

func withEvidenceRoot(dir string) option {
	return func(e *Session) { e.evidenceRoot = dir }
}

func withEnv(env ...string) option {
	owned := make([]string, len(env))
	copy(owned, env)
	return func(e *Session) {
		e.env = make([]string, len(owned))
		copy(e.env, owned)
	}
}

func newEngine(opts ...option) (*Session, error) {
	return newEngineContext(context.Background(), opts...)
}

func newEngineContext(ctx context.Context, opts ...option) (eng *Session, err error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil construction context")
	}
	defer func() {
		if cause := ctx.Err(); cause != nil {
			eng, err = nil, cause
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e := &Session{assumePure: func(Subject) bool { return false }}
	for _, o := range opts {
		if o != nil {
			o(e)
		}
	}
	if e.env == nil {
		e.env = os.Environ()
	}
	normalized, err := gotool.NormalizeEnv(e.env)
	if err != nil {
		return nil, fmt.Errorf("gofresh: %w", err)
	}
	e.env = normalized
	if _, err := gotool.EnvForPackages(e.env); err != nil {
		return nil, fmt.Errorf("gofresh: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("gofresh: resolve working directory: %w", err)
		}
		e.dir = cwd
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	root, err := gotool.CanonicalDir(e.dir)
	if err != nil {
		return nil, fmt.Errorf("gofresh: resolve engine tree: %w", err)
	}
	e.dir = root
	if e.evidenceRoot != "" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		evidenceRoot, err := gotool.CanonicalDir(e.evidenceRoot)
		if err != nil {
			return nil, fmt.Errorf("gofresh: resolve evidence root: %w", err)
		}
		if rel, err := filepath.Rel(evidenceRoot, e.dir); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("gofresh: evidence root %s does not contain the module directory %s; relative identities recorded under it could not name the module's inputs", evidenceRoot, e.dir)
		}
		e.evidenceRoot = evidenceRoot
	}
	for _, input := range e.buildInputs {
		if strings.HasPrefix(strings.TrimSpace(input), "-") {
			return nil, fmt.Errorf("gofresh: build flag %q passed as opaque input; use WithBuildFlags", input)
		}
	}
	if err := buildflags.Validate(ctx, e.newPassReader(), e.buildFlags); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Session) newView(ctx context.Context, subjects []Subject, moduleDir string) (*Snapshot, error) {
	return e.observeSnapshot(ctx, subjects, moduleDir, CodeResult)
}

func (e *Session) newViewFor(ctx context.Context, subjects []Subject, moduleDir string, kind Kind) (*Snapshot, error) {
	return e.observeSnapshot(ctx, subjects, moduleDir, kind)
}

func (e *Session) capture(ctx context.Context, subject Subject, moduleDir string) (Fingerprint, error) {
	view, err := e.newView(ctx, []Subject{subject}, moduleDir)
	if err != nil {
		return Fingerprint{}, err
	}
	return view.Capture(ctx, subject)
}

func (e *Session) captureFor(ctx context.Context, subject Subject, moduleDir string, kind Kind) (Fingerprint, error) {
	view, err := e.newViewFor(ctx, []Subject{subject}, moduleDir, kind)
	if err != nil {
		return Fingerprint{}, err
	}
	return view.Capture(ctx, subject)
}

func (e *Session) check(ctx context.Context, recorded Fingerprint, subject Subject, moduleDir string) (Verdict, error) {
	if err := recorded.Validate(); err != nil {
		return Verdict{}, err
	}
	view, err := e.newViewFor(ctx, []Subject{subject}, moduleDir, recorded.ResultKind)
	if err != nil {
		return Verdict{}, err
	}
	return view.Check(ctx, recorded, subject)
}

func (e *Session) checkObserved(ctx context.Context, recorded Fingerprint, subject Subject, moduleDir string) (Verdict, error) {
	if err := recorded.Validate(); err != nil {
		return Verdict{}, err
	}
	view, err := e.newViewFor(ctx, []Subject{subject}, moduleDir, recorded.ResultKind)
	if err != nil {
		return Verdict{}, err
	}
	return view.CheckObserved(ctx, recorded, subject)
}

func hermeticEnvRunner() gotool.Runner {
	return gotool.Runner{
		Prepare: func(cmd *exec.Cmd) {
			if len(cmd.Args) >= 3 && cmd.Args[1] == "env" && cmd.Args[2] == "-json" {
				if sh, err := exec.LookPath("sh"); err == nil {
					cmd.Path = sh
					cmd.Args = []string{"sh", "-c", fmt.Sprintf(`printf '{"GOFLAGS":"","GOVERSION":%q,"GOGCCFLAGS":"-fPIC"}'`, runtime.Version())}
				}
			}
		},
	}
}

func testProgramCmd(ctx context.Context, dir string, env []string, binary string, args ...string) (*exec.Cmd, error) {
	if ctx == nil {
		return nil, errors.New("gofresh: nil program context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	normalized, err := gotool.EnvForCommand(env, dir)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	cmd.Env = normalized
	return cmd, nil
}

// The tests' ambient forms of the public entries: the process
// environment and a background context, spelled once here.
func closureNewAt(dir string, buildFlags ...string) (*closure.Hasher, error) {
	return closure.NewAt(context.Background(), gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()), buildFlags...)
}

func riFromTestLog(log []byte, moduleDir, packageDir string, opts ...runtimeinput.TestLogOption) (runtimeinput.Observation, error) {
	return runtimeinput.FromTestLog(log, moduleDir, packageDir, os.Environ(), opts...)
}

func riCaptureBracket(moduleDir string, roots []string, opts ...runtimeinput.BracketOption) (runtimeinput.Bracket, error) {
	return runtimeinput.CaptureBracket(context.Background(), moduleDir, roots, opts...)
}

func closureNewAtEnv(ctx context.Context, dir string, env []string, buildFlags ...string) (*closure.Hasher, error) {
	return closure.NewAt(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags...)
}

func scanPureDirectives(pkgPaths ...string) (func(Subject) bool, error) {
	return scanPureDirectivesAt("", os.Environ(), nil, pkgPaths...)
}

func scanPureDirectivesIn(dir string, pkgPaths ...string) (func(Subject) bool, error) {
	return scanPureDirectivesAt(dir, os.Environ(), nil, pkgPaths...)
}

func scanPureDirectivesAt(dir string, env, buildFlags []string, pkgPaths ...string) (func(Subject) bool, error) {
	scan, err := scanSubjectsInWithBuildFlagsEnv(context.Background(), dir, env, buildFlags, pkgPaths...)
	if err != nil {
		return nil, err
	}
	return scan.directivePure, nil
}

func scanSubjectsInWithBuildFlagsEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*subjectScan, error) {
	hasher, err := closure.NewAt(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags...)
	if err != nil {
		return nil, err
	}
	load, err := closure.LoadViewPackages(ctx, hasher.PassReader(), buildFlags, pkgPaths...)
	if err != nil {
		return nil, err
	}
	byPkg := map[string][]dynstate.Fact{}
	for _, pkg := range load.Packages() {
		if pkg.Name == "main" && strings.HasSuffix(pkg.PkgPath, ".test") {
			continue
		}
		for _, loadErr := range pkg.Errors {
			return nil, fmt.Errorf("gofresh: directive scan: load %s: %s", pkg.PkgPath, loadErr)
		}
		byPkg[pkg.PkgPath] = append(byPkg[pkg.PkgPath], dynstate.MethodDirectivesFactOf(pkg))
	}
	missingPromoted := map[string]bool{}
	for _, pkg := range load.Packages() {
		if pkg.Types == nil {
			continue
		}
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			typeName, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			for _, methods := range []*types.MethodSet{
				types.NewMethodSet(types.NewPointer(typeName.Type())),
				types.NewMethodSet(typeName.Type()),
			} {
				for i := 0; i < methods.Len(); i++ {
					method, ok := methods.At(i).Obj().(*types.Func)
					if !ok || method.Pkg() == nil {
						continue
					}
					depPath := method.Pkg().Path()
					first, _, _ := strings.Cut(depPath, "/")
					if len(byPkg[depPath]) == 0 && strings.Contains(first, ".") {
						missingPromoted[depPath] = true
					}
				}
			}
		}
	}
	if len(missingPromoted) > 0 {
		depPatterns := make([]string, 0, len(missingPromoted))
		for depPath := range missingPromoted {
			depPatterns = append(depPatterns, depPath)
		}
		sort.Strings(depPatterns)
		depLoad, err := closure.LoadViewPackages(ctx, hasher.PassReader(), buildFlags, depPatterns...)
		if err != nil {
			return nil, err
		}
		for _, pkg := range depLoad.Packages() {
			if pkg.ForTest != "" || pkg.Name == "main" {
				continue
			}
			byPkg[pkg.PkgPath] = append(byPkg[pkg.PkgPath], dynstate.MethodDirectivesFactOf(pkg))
		}
	}
	cones := make(map[string]map[string][]dynstate.Fact, len(pkgPaths))
	for _, pkgPath := range pkgPaths {
		cones[pkgPath] = byPkg
	}
	state := &viewDynamicState{cones: cones}
	return scanSubjectsFromLoadedWith(hasher.SelectionAudited(), false, load.Packages(), state, pkgPaths...)
}

func closureLoadViewPackagesEnv(ctx context.Context, dir string, env, buildFlags []string, pkgPaths ...string) (*closure.ViewLoad, error) {
	return closure.LoadViewPackages(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, env), buildFlags, pkgPaths...)
}

func riCurrentCtx(ctx context.Context, encoded, moduleDir string) (runtimeinput.State, error) {
	return runtimeinput.Current(ctx, encoded, moduleDir, os.Environ())
}

// cgoEnabled reports the go command's resolved CGO_ENABLED — the
// setting every listing obeys: without cgo the go command refuses a
// race listing.
func cgoEnabled(t *testing.T) bool {
	t.Helper()
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), t.TempDir(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	return snapshot.Value("CGO_ENABLED") == "1"
}

func isolateProofCache(t *testing.T) {
	t.Helper()
	cache, err := gotool.GoBuildCache(context.Background(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOCACHE", cache)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

// unauditedTagEnv constructs an isolated GOROOT copy of the host toolchain with
// a tag-gated file in package strings (`//go:build badstd`) that declares an
// unapproved single-argument push linkname, returning the normalized process
// environment rooted at that GOROOT with GOCACHE preserved.
func unauditedTagEnv(t *testing.T) []string {
	t.Helper()
	_, env := testenv.UnauditedTagGOROOTEnv(t, environmentWith(nil))
	return env
}

func parseAndTypecheckDAG(t testing.TB, virtualDir string, filesByPkg map[string]map[string]string) []*packages.Package {
	t.Helper()
	return testenv.ParseAndTypecheckDAG(t, virtualDir, filesByPkg)
}

func parseAndTypecheckModuleDir(dir string, viewPackages ...string) ([]*packages.Package, string, bool) {
	if dir == "" {
		return nil, "", false
	}
	goModBytes, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return nil, "", false
	}
	var modPath string
	for _, line := range strings.Split(string(goModBytes), "\n") {
		trimmed := strings.TrimSpace(line)
		if idx := strings.Index(trimmed, "//"); idx >= 0 {
			trimmed = strings.TrimSpace(trimmed[:idx])
		}
		if trimmed == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "module "):
			modPath = strings.TrimSpace(strings.TrimPrefix(trimmed, "module "))
		case strings.HasPrefix(trimmed, "require"),
			strings.HasPrefix(trimmed, "replace"),
			strings.HasPrefix(trimmed, "retract"),
			strings.HasPrefix(trimmed, "tool"):
			return nil, "", false
		}
	}
	if modPath == "" {
		return nil, "", false
	}
	filesByPkg := map[string]map[string]string{}
	pkgDirs := map[string]string{}
	valid := true
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			valid = false
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			valid = false
			return err
		}
		if rel == "go.mod" {
			return nil
		}
		if !strings.HasSuffix(rel, ".go") {
			valid = false
			return fs.SkipAll
		}
		srcBytes, err := os.ReadFile(path)
		if err != nil {
			valid = false
			return err
		}
		src := string(srcBytes)
		if strings.Contains(src, "//go:build") ||
			strings.Contains(src, "// +build") ||
			strings.Contains(src, `"C"`) {
			valid = false
			return fs.SkipAll
		}
		relDir := filepath.Dir(rel)
		pkgPath := modPath
		if relDir != "." {
			pkgPath = modPath + "/" + filepath.ToSlash(relDir)
		}
		baseName := filepath.Base(path)
		if strings.HasSuffix(baseName, "_test.go") && len(viewPackages) > 0 {
			if !slices.Contains(viewPackages, pkgPath) {
				return nil
			}
			if len(viewPackages) > 1 {
				valid = false
				return fs.SkipAll
			}
		}
		if filesByPkg[pkgPath] == nil {
			filesByPkg[pkgPath] = map[string]string{}
		}
		filesByPkg[pkgPath][baseName] = src
		pkgDirs[pkgPath] = filepath.Dir(path)
		return nil
	})
	if walkErr != nil || !valid || len(filesByPkg) == 0 {
		return nil, "", false
	}
	pkgs, err := testenv.ParseAndTypecheckInPlace(dir, pkgDirs, filesByPkg)
	if err != nil && len(viewPackages) > 0 && len(viewPackages) < len(filesByPkg) {
		subFiles := make(map[string]map[string]string, len(viewPackages))
		subDirs := make(map[string]string, len(viewPackages))
		for _, vp := range viewPackages {
			if m, ok := filesByPkg[vp]; ok {
				subFiles[vp] = m
				subDirs[vp] = pkgDirs[vp]
			}
		}
		if len(subFiles) == len(viewPackages) {
			pkgs, err = testenv.ParseAndTypecheckInPlace(dir, subDirs, subFiles)
		}
	}
	if err != nil || len(pkgs) == 0 {
		return nil, "", false
	}
	return pkgs, modPath, true
}

func buildInMemoryViewDynamicState(pkgs []*packages.Package, viewPackages []string, vouches map[string]bool, singleSubject, packageProcess bool) (*viewDynamicState, map[string]dynstate.Fact, bool) {
	var meta []closure.GraphPackage
	byListing := make(map[string]closure.GraphPackage, len(pkgs))
	factsByListing := make(map[string]dynstate.Fact, len(pkgs))
	factsByPkg := make(map[string]dynstate.Fact, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "main" && strings.HasSuffix(p.PkgPath, ".test") {
			continue
		}
		listing := p.ID
		if listing == "" {
			listing = p.PkgPath
			if p.ForTest != "" {
				listing = p.PkgPath + " [" + p.ForTest + ".test]"
			}
		}
		var imps []string
		for impPath, impPkg := range p.Imports {
			if impPkg != nil && impPkg.Module != nil && impPkg.ID != "" {
				imps = append(imps, impPkg.ID)
			} else {
				imps = append(imps, impPath)
			}
		}
		slices.Sort(imps)
		node := closure.GraphPackage{
			ImportPath: listing,
			PkgPath:    p.PkgPath,
			ForTest:    p.ForTest,
			Class:      closure.MutableLocalPackage,
			Imports:    imps,
		}
		meta = append(meta, node)
		byListing[listing] = node
		fact := dynstate.FactOf(true, p, singleSubject)
		factsByListing[listing] = fact
		if p.ForTest == "" || p.PkgPath == p.ForTest {
			factsByPkg[p.PkgPath] = fact
		}
	}
	state := &viewDynamicState{
		downgraded: map[string]string{},
		culprits:   map[string]Subject{},
		cones:      map[string]map[string][]dynstate.Fact{},
	}
	for _, viewPackage := range viewPackages {
		coneMeta, coneFacts := dynstate.Cone(meta, byListing, factsByListing, viewPackage)
		state.cones[viewPackage] = coneFacts
		composed := dynstate.Compose(coneMeta, coneFacts, viewPackage, vouches, singleSubject, packageProcess)
		if composed.Downgraded != "" {
			state.downgraded[viewPackage] = composed.Downgraded
			state.culprits[viewPackage] = Subject{Package: composed.CulpritPkg, Symbol: composed.CulpritSym}
		}
		if composed.VouchDischarges != "" {
			if state.vouchDischarges == nil {
				state.vouchDischarges = map[string]string{}
			}
			state.vouchDischarges[viewPackage] = composed.VouchDischarges
		}
		if composed.AttestationDischarges != "" {
			if state.attestationDischarges == nil {
				state.attestationDischarges = map[string]string{}
			}
			state.attestationDischarges[viewPackage] = composed.AttestationDischarges
		}
		if len(composed.RootCulprits) > 0 {
			if state.rootCulprits == nil {
				state.rootCulprits = map[string][]dynstate.Culprit{}
				state.culpritSites = map[string]map[string]dynstate.CulpritSiteSet{}
			}
			state.rootCulprits[viewPackage] = composed.RootCulprits
			state.culpritSites[viewPackage] = composed.CulpritSites
		}
	}
	return state, factsByPkg, true
}

func inMemorySnapshotForSubject(dir string, subject Subject, opts ...option) (*Snapshot, []*packages.Package, bool) {
	if hasAnyViewTestHook() {
		return nil, nil, false
	}
	e := &engine{assumePure: func(Subject) bool { return false }, dir: dir}
	for _, o := range opts {
		if o != nil {
			o(e)
		}
	}
	if e.env != nil || len(e.buildFlags) > 0 || len(e.buildInputs) > 0 || e.analysisBudget > 0 || e.progress != nil {
		return nil, nil, false
	}
	pkgs, _, ok := parseAndTypecheckModuleDir(dir, subject.Package)
	if !ok {
		return nil, nil, false
	}
	singleSubject, packageProcess := e.executionModel.singleSubject(), e.executionModel.packageProcess()
	state, _, ok := buildInMemoryViewDynamicState(pkgs, []string{subject.Package}, e.dynamicStateVouches, singleSubject, packageProcess)
	if !ok {
		return nil, nil, false
	}
	scan, err := scanSubjectsFromLoaded(true, pkgs, state, subject.Package)
	if err != nil || !scan.known[subject] {
		return nil, nil, false
	}
	if singleSubject {
		if culprits := state.rootCulprits[subject.Package]; scan.downgradeReason[subject] != "" && len(culprits) > 0 && !state.culpritSites[subject.Package][culprits[0].Key].Unattributed {
			req := closure.Subject{Package: subject.Package, Symbol: subject.Symbol}
			rooted, err := closure.InMemoryRootedFunctions(context.Background(), true, pkgs, subject.Package, []closure.Subject{req})
			if err != nil {
				return nil, nil, false
			}
			if proof := rooted[req]; proof.Complete {
				surviving, culprit, dischargedKeys := dischargeCulprits(proof, state, subject.Package)
				if surviving == "" {
					delete(scan.downgradeReason, subject)
					delete(scan.downgradeCulprit, subject)
				} else {
					scan.downgradeReason[subject] = sharedDynamicStatePrefix + surviving
					scan.downgradeCulprit[subject] = culprit
				}
				if len(dischargedKeys) > 0 {
					d := scan.discharges[subject]
					for _, key := range strings.Split(d.singleSubject, ",") {
						if key != "" {
							dischargedKeys[key] = true
						}
					}
					d.singleSubject = joinDischargedKeys(dischargedKeys)
					scan.discharges[subject] = d
				}
			}
		}
	} else if packageProcess {
		if culprits := state.rootCulprits[subject.Package]; scan.downgradeReason[subject] != "" && len(culprits) > 0 && !state.culpritSites[subject.Package][culprits[0].Key].Unattributed {
			proof, err := closure.InMemoryBinaryRootedFunctions(context.Background(), true, pkgs, subject.Package)
			if err != nil {
				return nil, nil, false
			}
			if proof.Complete {
				surviving, culprit, dischargedKeys := dischargeCulprits(proof, state, subject.Package)
				if surviving == "" {
					delete(scan.downgradeReason, subject)
					delete(scan.downgradeCulprit, subject)
				} else {
					scan.downgradeReason[subject] = sharedDynamicStatePrefix + surviving
					scan.downgradeCulprit[subject] = culprit
				}
				if len(dischargedKeys) > 0 {
					d := scan.discharges[subject]
					d.packageProcess = joinDischargedKeys(dischargedKeys)
					scan.discharges[subject] = d
				}
			}
		}
	}
	maxFacts, err := closure.InMemoryMaximalFacts(true, pkgs, closure.Subject{Package: subject.Package, Symbol: subject.Symbol})
	if err != nil {
		return nil, nil, false
	}
	maxFacts.Identity.TestVariants = testvariant.EmptyTestVariantClosure
	maximal := subjectFacts{source: maxFacts}
	if term := scan.openWorld[subject]; term != "" {
		maximal.openWorld = &subjectRefusal{reason: "subject accepts caller-supplied dynamic behavior through its " + term + " (dischargeable by bounding that type away from dynamic carriers, or by " + closure.PurityResponsibility + ")"}
	}
	if reason := scan.downgradeReason[subject]; reason != "" {
		maximal.sharedState = &subjectRefusal{
			reason:  reason,
			culprit: scan.downgradeCulprit[subject],
		}
	}
	if detail := scan.ambiguous[subject]; detail != "" {
		maximal.ambiguous = &subjectRefusal{reason: "ambiguous subject identity: " + detail + "; rename one declaration to address either"}
	}
	if scan.external[subject] {
		maximal.external = true
	}
	purity := map[Subject]string{}
	if !scan.external[subject] && scan.ambiguous[subject] == "" {
		switch caller, directive := e.assumePure(subject), scan.directivePure(subject); {
		case caller && directive:
			purity[subject] = "caller assertion and source directive"
		case caller:
			purity[subject] = "caller assertion"
		case directive:
			purity[subject] = "source directive"
		}
	}
	v := &Snapshot{
		session:   e,
		subjects:  []Subject{subject},
		packages:  []string{subject.Package},
		moduleDir: dir,
		kind:      CodeResult,
		facts: &observationFacts{
			maximal:            map[Subject]subjectFacts{subject: maximal},
			guards:             guard.Guards{Toolchain: "inmem-toolchain", BuildConfig: "inmem-buildconfig"},
			purity:             purity,
			vouchDischarges:    scan.vouchDischarges,
			discharges:         scan.discharges,
			testVariantLedgers: map[string]testvariant.TestVariantLedger{subject.Package: {}},
		},
		observable:           map[Subject]closure.Observability{},
		capturedObserved:     map[Subject]bool{},
		attachedObservations: map[Subject]runtimeinput.State{},
	}
	return v, pkgs, true
}

func inMemoryCaptureCheck(t *testing.T, dir string, subject Subject, opts ...option) (Fingerprint, Verdict, bool) {
	t.Helper()
	v, _, ok := inMemorySnapshotForSubject(dir, subject, opts...)
	if !ok {
		return Fingerprint{}, Verdict{}, false
	}
	fp, err := v.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := v.Check(context.Background(), fp, subject)
	if err != nil {
		t.Fatal(err)
	}
	return fp, verdict, true
}

func inMemoryExplainViewForSubject(t *testing.T, dir string, subject Subject, pkgPath, varName string) (Chain, bool) {
	t.Helper()
	v, pkgs, ok := inMemorySnapshotForSubject(dir, subject)
	if !ok {
		return Chain{}, false
	}
	fp, err := v.Capture(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := v.Check(context.Background(), fp, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Ground.Cause.Kind == SharedDynamicStateCause {
		parsed, ok := CulpritFromReason(verdict.Reason)
		if !ok || verdict.Ground.Cause.Culprit != parsed {
			t.Fatalf("Verdict.Ground.Cause.Culprit = %+v, CulpritFromReason(%q) = (%+v, %v)", verdict.Ground.Cause.Culprit, verdict.Reason, parsed, ok)
		}
	} else if verdict.Ground.Cause.Culprit != (Subject{}) {
		t.Fatalf("non-shared-state verdict carried culprit: %+v", verdict.Ground.Cause)
	}
	chain, err := explainCulprit(true, pkgs, pkgPath, pkgPath+"."+varName, varName, false)
	if err != nil {
		t.Fatal(err)
	}
	return chain, true
}

type pinnedDepTemplate struct {
	files            map[string]string
	meta             []closure.GraphPackage
	byListing        map[string]closure.GraphPackage
	localFacts       map[string]dynstate.Fact
	errgroupBucket   string
	errgroupBaseFact dynstate.Fact
}

var (
	pinnedDepTemplateMu  sync.Mutex
	pinnedDepTemplateVal *pinnedDepTemplate
	pinnedTemplateDirsMu sync.RWMutex
	pinnedTemplateDirs   = map[string]bool{}
)

func markPinnedTemplateDir(dir string) {
	pinnedTemplateDirsMu.Lock()
	pinnedTemplateDirs[dir] = true
	pinnedTemplateDirsMu.Unlock()
}

func isPinnedTemplateDir(dir string) bool {
	pinnedTemplateDirsMu.RLock()
	ok := pinnedTemplateDirs[dir]
	pinnedTemplateDirsMu.RUnlock()
	return ok
}

func getPinnedDepTemplate(t testing.TB) *pinnedDepTemplate {
	t.Helper()
	pinnedDepTemplateMu.Lock()
	defer pinnedDepTemplateMu.Unlock()
	if pinnedDepTemplateVal != nil {
		return pinnedDepTemplateVal
	}
	goModBytes, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read parent go.mod: %v", err)
	}
	var goVersion, version string
	for _, line := range strings.Split(string(goModBytes), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "go" {
			goVersion = fields[1]
		}
		if len(fields) >= 2 && fields[0] == "golang.org/x/sync" {
			version = fields[1]
		}
		if len(fields) >= 3 && fields[0] == "require" && fields[1] == "golang.org/x/sync" {
			version = fields[2]
		}
	}
	if goVersion == "" {
		goVersion = "1.26"
	}
	if version == "" {
		t.Fatal("could not find golang.org/x/sync version in go.mod")
	}
	goSumBytes, err := os.ReadFile("go.sum")
	if err != nil {
		t.Fatalf("read parent go.sum: %v", err)
	}
	var sumLines []string
	prefix := "golang.org/x/sync " + version
	for _, line := range strings.Split(string(goSumBytes), "\n") {
		if strings.HasPrefix(line, prefix+" ") || strings.HasPrefix(line, prefix+"/go.mod ") {
			sumLines = append(sumLines, line)
		}
	}

	files := map[string]string{
		"go.mod":      "module example.com/pinned\n\ngo " + goVersion + "\n\nrequire golang.org/x/sync " + version + "\n",
		"go.sum":      strings.Join(sumLines, "\n") + "\n",
		"lib.go":      "package pinned\n\nimport \"golang.org/x/sync/errgroup\"\n\nfunc Run() error {\n\tvar g errgroup.Group\n\tg.Go(func() error { return nil })\n\treturn g.Wait()\n}\n",
		"lib_test.go": "package pinned\n\nimport \"testing\"\n\nfunc TestRun(t *testing.T) {\n\tif Run() != nil {\n\t\tt.Fatal(\"run\")\n\t}\n}\n",
	}
	dagDir, err := os.MkdirTemp("", "gofresh-pinned-dag-*")
	if err != nil {
		t.Fatal(err)
	}
	sharedTestBinariesMu.Lock()
	sharedTestBinaryDirs = append(sharedTestBinaryDirs, dagDir)
	sharedTestBinariesMu.Unlock()

	dagPkgs := testenv.ParseAndTypecheckDAG(t, dagDir, map[string]map[string]string{
		"golang.org/x/sync/errgroup": {
			"errgroup.go": "package errgroup\n\ntype Group struct{}\n\nfunc (g *Group) Go(f func() error) { _ = f() }\nfunc (g *Group) Wait() error { return nil }\n",
		},
		"example.com/pinned": {
			"lib.go":      files["lib.go"],
			"lib_test.go": files["lib_test.go"],
		},
	})
	meta := []closure.GraphPackage{
		{
			ImportPath: "example.com/pinned",
			PkgPath:    "example.com/pinned",
			Class:      closure.MutableLocalPackage,
			Imports:    []string{"golang.org/x/sync/errgroup"},
		},
		{
			ImportPath: "golang.org/x/sync/errgroup",
			PkgPath:    "golang.org/x/sync/errgroup",
			Class:      closure.PinnedPackage,
			Pin:        "golang.org/x/sync@" + version,
		},
	}
	byListing := make(map[string]closure.GraphPackage, len(meta))
	for _, node := range meta {
		byListing[node.ImportPath] = node
	}
	localFacts := map[string]dynstate.Fact{}
	var egFact dynstate.Fact
	for _, pkg := range dagPkgs {
		if pkg.PkgPath == "golang.org/x/sync/errgroup" {
			pkg.Module = &packages.Module{Path: "golang.org/x/sync", Version: version}
			egFact = dynstate.FactOf(true, pkg, false)
			continue
		}
		if pkg.PkgPath == "example.com/pinned" {
			localFacts["example.com/pinned"] = dynstate.FactOf(true, pkg, false)
		}
	}
	buckets, _ := dynstate.PinnedBuckets(meta)
	egBucket := buckets["golang.org/x/sync@"+version]
	if egBucket == "" {
		t.Fatalf("missing errgroup bucket in %v", buckets)
	}
	pinnedDepTemplateVal = &pinnedDepTemplate{
		files:            files,
		meta:             meta,
		byListing:        byListing,
		localFacts:       localFacts,
		errgroupBucket:   egBucket,
		errgroupBaseFact: egFact,
	}
	return pinnedDepTemplateVal
}

func cloneDynamicStateFact(f dynstate.Fact) dynstate.Fact {
	var out dynstate.Fact
	if raw, err := json.Marshal(f); err == nil {
		_ = json.Unmarshal(raw, &out)
		return out
	}
	return f
}

func pinnedDirUnmodified(dir string, expected map[string]string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(expected) {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			return false
		}
		want, ok := expected[e.Name()]
		if !ok {
			return false
		}
		got, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || string(got) != want {
			return false
		}
	}
	return true
}

func inMemoryRunScanVouched(scope, dir string, vouches map[string]bool, pkgPaths ...string) (*subjectScan, map[string]dynstate.Fact, bool) {
	if hasScanOverrideViewTestHook() {
		return nil, nil, false
	}
	if isPinnedTemplateDir(dir) && len(pkgPaths) == 1 && pkgPaths[0] == "example.com/pinned" && pinnedDepTemplateVal != nil && pinnedDirUnmodified(dir, pinnedDepTemplateVal.files) {
		tmpl := pinnedDepTemplateVal
		factScope := scope
		cacheKey := factScope + "\x00" + tmpl.errgroupBucket + "\x00golang.org/x/sync/errgroup"
		egFact := cloneDynamicStateFact(tmpl.errgroupBaseFact)
		if factScope != "" {
			if cached, ok := processFactCache.Load(cacheKey); ok {
				egFact = cloneDynamicStateFact(cached)
			} else {
				if persisted := loadDynamicStateFacts(factScope, tmpl.errgroupBucket); persisted != nil {
					if raw, ok := persisted["golang.org/x/sync/errgroup"]; ok {
						_ = json.Unmarshal(raw, &egFact)
					}
				} else if raw, err := json.Marshal(egFact); err == nil {
					storeDynamicStateFacts(factScope, tmpl.errgroupBucket, map[string]json.RawMessage{"golang.org/x/sync/errgroup": raw})
				}
				processFactCache.Store(cacheKey, cloneDynamicStateFact(egFact))
			}
		}
		localFact := cloneDynamicStateFact(tmpl.localFacts["example.com/pinned"])
		factsByListing := map[string]dynstate.Fact{
			"example.com/pinned":         localFact,
			"golang.org/x/sync/errgroup": egFact,
		}

		coneMeta, coneFacts := dynstate.Cone(tmpl.meta, tmpl.byListing, factsByListing, "example.com/pinned")
		composed := dynstate.Compose(coneMeta, coneFacts, "example.com/pinned", vouches, false, false)
		state := &viewDynamicState{
			downgraded: map[string]string{},
			culprits:   map[string]Subject{},
			cones:      map[string]map[string][]dynstate.Fact{"example.com/pinned": coneFacts},
		}
		if composed.Downgraded != "" {
			state.downgraded["example.com/pinned"] = composed.Downgraded
			state.culprits["example.com/pinned"] = Subject{Package: composed.CulpritPkg, Symbol: composed.CulpritSym}
		}
		if composed.VouchDischarges != "" {
			state.vouchDischarges = map[string]string{"example.com/pinned": composed.VouchDischarges}
		}
		if composed.AttestationDischarges != "" {
			state.attestationDischarges = map[string]string{"example.com/pinned": composed.AttestationDischarges}
		}
		pkgs, err := testenv.ParseAndTypecheckInPlace(
			dir,
			map[string]string{
				"example.com/pinned":         dir,
				"golang.org/x/sync/errgroup": dir,
			},
			map[string]map[string]string{
				"golang.org/x/sync/errgroup": {
					"errgroup.go": "package errgroup\n\ntype Group struct{}\n\nfunc (g *Group) Go(f func() error) { _ = f() }\nfunc (g *Group) Wait() error { return nil }\n",
				},
				"example.com/pinned": {
					"lib.go":      tmpl.files["lib.go"],
					"lib_test.go": tmpl.files["lib_test.go"],
				},
			},
		)
		if err != nil || len(pkgs) == 0 {
			return nil, nil, false
		}
		scan, err := scanSubjectsFromLoaded(true, pkgs, state, "example.com/pinned")
		if err != nil {
			return nil, nil, false
		}
		return scan, map[string]dynstate.Fact{"example.com/pinned": localFact}, true
	}
	pkgs, _, ok := parseAndTypecheckModuleDir(dir, pkgPaths...)
	if !ok {
		return nil, nil, false
	}
	state, factsByPkg, ok := buildInMemoryViewDynamicState(pkgs, pkgPaths, vouches, false, false)
	if !ok {
		return nil, nil, false
	}
	scan, err := scanSubjectsFromLoaded(true, pkgs, state, pkgPaths...)
	if err != nil {
		return nil, nil, false
	}
	return scan, factsByPkg, true
}

var (
	sharedTestBinariesMu sync.Mutex
	sharedTestBinaries   = map[string]string{}
	sharedTestBinaryDirs []string
)

// compileSharedTestBinaryOnce compiles a `go test -c` binary for pkgDir and
// buildFlags at most once per test-binary execution, returning the compiled
// binary path. All shared binaries are removed at TestMain exit.
func compileSharedTestBinaryOnce(t testing.TB, pkgDir string, buildFlags ...string) string {
	t.Helper()
	absDir, err := filepath.Abs(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	key := absDir + "\x00" + strings.Join(buildFlags, "\x00")
	sharedTestBinariesMu.Lock()
	defer sharedTestBinariesMu.Unlock()
	if bin, ok := sharedTestBinaries[key]; ok {
		if _, err := os.Stat(bin); err == nil {
			return bin
		}
	}
	tmpDir, err := os.MkdirTemp("", "gofresh-shared-testbin-*")
	if err != nil {
		t.Fatal(err)
	}
	sharedTestBinaryDirs = append(sharedTestBinaryDirs, tmpDir)
	binPath := filepath.Join(tmpDir, "pkg.test")
	env, err := gotool.PreserveBuildCache(context.Background(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"test", "-c", "-o", binPath}
	args = append(args, buildFlags...)
	args = append(args, ".")
	if _, err := (gotool.Runner{}).Run(context.Background(), absDir, env, args...); err != nil {
		t.Fatalf("compileSharedTestBinaryOnce(%s): %v", absDir, err)
	}
	sharedTestBinaries[key] = binPath
	return binPath
}

func cleanupSharedTestBinaries() {
	sharedTestBinariesMu.Lock()
	dirs := sharedTestBinaryDirs
	sharedTestBinaryDirs = nil
	clear(sharedTestBinaries)
	sharedTestBinariesMu.Unlock()
	for _, dir := range dirs {
		_ = os.RemoveAll(dir)
	}
}

func writeViewModule(t *testing.T, source string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/view\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "view.go"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeObservedViewModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod": "module example.com/observed\n\ngo 1.26\n",
		// Sibling lives in production source so editing it moves the CORE
		// closure: a test-file sibling edit would move only the test-variant
		// compartment and stale as "test variants" instead
		// (REQ-closure-test-variant-identity).
		"observed.go":      "package observed\n\nfunc Sibling() int { return 1 }\n",
		"observed_test.go": "package observed\n\nimport (\"os\"; \"testing\")\n\nfunc TestRead(*testing.T) { _, _ = os.ReadFile(\"fixture\") }\n",
		"fixture":          "one",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func writeModuleTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func newTracedSession(t testing.TB, build BuildDescription, policy SessionPolicy, gateOpts ...testenv.TraceGateOption) (*Session, context.Context, *trace.Recorder) {
	t.Helper()
	ctx, rec := testenv.WithTraceGate(t, t.Context(), gateOpts...)
	sess, err := NewSession(ctx, build, policy)
	if err != nil {
		t.Fatal(err)
	}
	return sess, ctx, rec
}

func captureCheckFP(t *testing.T, dir string, subject Subject, opts ...option) (Fingerprint, Verdict) {
	t.Helper()
	if fp, verdict, ok := inMemoryCaptureCheck(t, dir, subject, opts...); ok {
		return fp, verdict
	}
	var probe Session
	for _, o := range opts {
		if o != nil {
			o(&probe)
		}
	}
	var gateOpts []testenv.TraceGateOption
	if probe.env != nil || len(probe.buildFlags) > 0 {
		gateOpts = append(gateOpts, testenv.AllowToolchainDegradation(), testenv.AllowToolchainVerdictError())
	}
	ctx, _ := testenv.WithTraceGate(t, t.Context(), gateOpts...)
	engine, err := newEngineContext(ctx, append([]option{withDir(dir)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.newView(ctx, []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := view.Check(ctx, fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint, verdict
}

func captureCheck(t *testing.T, dir string, subject Subject, opts ...option) Verdict {
	t.Helper()
	_, verdict := captureCheckFP(t, dir, subject, opts...)
	return verdict
}

type workspaceEnvironmentFixture struct {
	consumer       string
	workspaceFile  string
	standaloneFile string
	goWork         string
	subject        Subject
}

func writeWorkspaceEnvironmentFixture(t *testing.T) workspaceEnvironmentFixture {
	t.Helper()
	root := t.TempDir()
	consumer := filepath.Join(root, "consumer")
	standalone := filepath.Join(root, "standalone")
	workspace := filepath.Join(root, "workspace")
	for _, dir := range []string{consumer, standalone, workspace} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(consumer, "go.mod"), "module example.com/consumer\n\ngo 1.26.4\n\nrequire example.com/selected v0.0.0\nreplace example.com/selected => ../standalone\n")
	write(filepath.Join(consumer, "consumer.go"), "package consumer\n\nimport \"example.com/selected\"\n\nfunc Use() string { return selected.Source() }\n")
	write(filepath.Join(standalone, "go.mod"), "module example.com/selected\n\ngo 1.26.4\n")
	standaloneFile := filepath.Join(standalone, "selected.go")
	write(standaloneFile, "package selected\n\nfunc Source() string { return \"standalone\" }\n")
	write(filepath.Join(workspace, "go.mod"), "module example.com/selected\n\ngo 1.26.4\n")
	workspaceFile := filepath.Join(workspace, "selected.go")
	write(workspaceFile, "package selected\n\nfunc Source() string { return \"workspace\" }\n")
	goWork := filepath.Join(root, "go.work")
	write(goWork, "go 1.26.4\n\nuse (\n\t./consumer\n\t./workspace\n)\n")
	return workspaceEnvironmentFixture{
		consumer:       consumer,
		workspaceFile:  workspaceFile,
		standaloneFile: standaloneFile,
		goWork:         goWork,
		subject:        Subject{Package: "example.com/consumer", Symbol: "Use"},
	}
}

func environmentWith(values map[string]string) []string {
	env := append([]string(nil), os.Environ()...)
	for key, value := range values {
		filtered := env[:0]
		for _, entry := range env {
			name, _, _ := strings.Cut(entry, "=")
			same := name == key
			if runtime.GOOS == "windows" {
				same = strings.EqualFold(name, key)
			}
			if !same {
				filtered = append(filtered, entry)
			}
		}
		env = append(filtered, key+"="+value)
	}
	return env
}

func viewUsesSource(t *testing.T, engine *engine, fixture workspaceEnvironmentFixture, want, notWant string) {
	t.Helper()
	ctx, _ := testenv.WithTraceGate(t, t.Context())
	view, err := engine.newView(ctx, []Subject{fixture.subject}, fixture.consumer)
	if err != nil {
		t.Fatal(err)
	}
	files := view.SourceFiles()
	if !slices.Contains(files, want) || slices.Contains(files, notWant) {
		t.Fatalf("selected source files = %v, want %s and not %s", files, want, notWant)
	}
}

