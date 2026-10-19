package runtimeinput

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

func eligibilityFile(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// Positive cases name physical files even when the host's temp directory is an
// alias (for example /var on Darwin). Alias refusal has its own negative cases.
func eligibilityModule(t *testing.T) (string, string) {
	t.Helper()
	root, pkg := producerModule(t)
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err = filepath.EvalSymlinks(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return root, pkg
}

func eligibilityEnv(pkg string) []string {
	env := producerEnv(pkg)
	for k, v := range map[string]string{"GOENV": "off", "GOFLAGS": "", "GOWORK": "off", "GOTOOLCHAIN": "local"} {
		env = gotool.SetEnv(env, k, v)
	}
	return env
}

func eligibilityObserve(t *testing.T, frame ProducerFrame, log string, in ProducerIngest) Observation {
	t.Helper()
	var err error
	in.Completion, err = frame.Completion(in.Identity, in.Env, "")
	if err != nil {
		t.Fatal(err)
	}
	obs, why, err := frame.ObserveInputs(t.Context(), log, in)
	if err != nil || why != "" || !obs.OK || obs.Unverifiable {
		t.Fatalf("identity-only producer: %+v %q %v", obs, why, err)
	}
	m, err := decode(obs.Manifest)
	if err != nil || m.Outcome != "" || len(m.Subjects) != 0 {
		t.Fatalf("identity-only observation granted outcomes: %+v %v", m, err)
	}
	return obs
}

// The query and the public producer's identity-only guard construction agree.
// These synthetic logs exercise classification, not operation-outcome authority.
func TestFileInputEligibilityMatchesProducer(t *testing.T) {
	root, pkg := eligibilityModule(t)
	outside := t.TempDir()
	build, modules := filepath.Join(outside, "build"), filepath.Join(outside, "modules")
	for _, tc := range []struct {
		name, path, cache, modcache string
		want                        FileInputKind
	}{
		{"ordinary", filepath.Join(outside, "ordinary"), build, modules, RawFileInput},
		{"build-cache", filepath.Join(build, "manifest"), build, modules, ElidedFileInput},
		{"build-fuzz", filepath.Join(build, "fuzz", "manifest"), build, modules, RawFileInput},
		{"module-cache", filepath.Join(modules, "example.com", "m@v1.0.0", "manifest"), build, modules, ElidedFileInput},
		{"module-download", filepath.Join(modules, "cache", "manifest"), build, modules, RawFileInput},
		{"overlapping-cache", filepath.Join(modules, "cache", "nested-build", "manifest"), filepath.Join(modules, "cache", "nested-build"), modules, ElidedFileInput},
		{"overlapping-fuzz", filepath.Join(build, "fuzz", "nested-modules", "manifest"), build, filepath.Join(build, "fuzz", "nested-modules"), ElidedFileInput},
		{"inside-tree", filepath.Join(root, "cache", "manifest"), filepath.Join(root, "cache"), modules, RawFileInput},
		{"cache-equals-tree", filepath.Join(root, "manifest"), root, modules, RawFileInput},
		{"cache-contains-tree", filepath.Join(root, "sibling-manifest"), filepath.Dir(root), modules, RawFileInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := eligibilityFile(t, tc.path)
			env := gotool.SetEnv(gotool.SetEnv(eligibilityEnv(pkg), "GOCACHE", tc.cache), "GOMODCACHE", tc.modcache)
			memo := &Roots{}
			q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env, Roots: memo})
			if err != nil || q.Kind != tc.want || q.Kind != RawFileInput && q.Reason == "" {
				t.Fatalf("eligibility: %+v %v, want %v", q, err, tc.want)
			}
			frame := CaptureProducerFrame(t.Context(), root, pkg, FrameOptions{BracketPaths: []string{file}})
			obs := eligibilityObserve(t, frame, writeTestlog(t, "open "+file+"\n"), ProducerIngest{Identity: "eligibility-fixture", Env: env, Roots: memo})
			paths, err := Paths(obs.Manifest, root)
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(paths, file) != (tc.want == RawFileInput) {
				t.Fatalf("query and producer disagree: kind=%v paths=%v", q.Kind, paths)
			}
			if err := os.WriteFile(file, []byte("after"), 0o600); err != nil {
				t.Fatal(err)
			}
			current, err := Current(t.Context(), obs.Manifest, root, env)
			if err != nil || current.Unverifiable {
				t.Fatalf("current: %+v %v", current, err)
			}
			if (current.Digest != obs.Digest) != (tc.want == RawFileInput) {
				t.Fatalf("raw byte sensitivity differs from query: kind=%v", q.Kind)
			}
		})
	}
}

func TestFileInputEligibilityEffectiveRootsAndExceptions(t *testing.T) {
	root, pkg := eligibilityModule(t)
	out := t.TempDir()
	cache, modules := filepath.Join(out, "build"), filepath.Join(out, "modules")
	cacheFile := eligibilityFile(t, filepath.Join(cache, "manifest"))
	config := filepath.Join(out, "goenv")
	if err := os.WriteFile(config, []byte("GOCACHE="+cache+"\nGOMODCACHE="+modules+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := gotool.SetEnv(eligibilityEnv(pkg), "GOENV", config)
	env = gotool.UnsetEnv(gotool.UnsetEnv(env, "GOCACHE"), "GOMODCACHE")
	reader := gotool.NewEnvReader(gotool.Runner{}, pkg, env)
	snapshot, err := reader.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Value("GOCACHE") != cache || snapshot.Value("GOMODCACHE") != modules {
		t.Fatal("fixture did not activate effective GOENV roots")
	}
	q, err := FileInputEligibility(t.Context(), root, pkg, cacheFile, FileInputContext{Env: env})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("effective GOENV cache ignored: %+v %v", q, err)
	}
	// The same physical root reached through its root alias retains coverage.
	alias := filepath.Join(out, "cache-alias")
	if err := os.Symlink(cache, alias); err != nil {
		t.Fatal(err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, cacheFile, FileInputContext{Env: gotool.SetEnv(env, "GOCACHE", alias)})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("resolved cache root ignored: %+v %v", q, err)
	}
	// An explicit effective environment override wins over the persisted value.
	other := filepath.Join(out, "other-cache")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, cacheFile, FileInputContext{Env: gotool.SetEnv(env, "GOCACHE", other)})
	if err != nil || q.Kind != RawFileInput {
		t.Fatalf("environment override lost: %+v %v", q, err)
	}
	versionFile, err := filepath.EvalSymlinks(filepath.Join(snapshot.Value("GOROOT"), "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, versionFile, FileInputContext{Env: env})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("toolchain file: %+v %v", q, err)
	}
	toolchainAlias := filepath.Join(out, "toolchain-alias")
	if err := os.Symlink(snapshot.Value("GOROOT"), toolchainAlias); err != nil {
		t.Fatal(err)
	}
	goName := "go"
	if runtime.GOOS == "windows" {
		goName += ".exe"
	}
	realGo := filepath.Join(snapshot.Value("GOROOT"), "bin", goName)
	aliasRunner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
		// A launcher on PATH may clear GOROOT. Exercise the selected tool itself
		// with the declared alias, preserving the runner's environment and lifetime.
		cmd.Path, cmd.Args[0] = realGo, realGo
	}}
	aliasEnv := gotool.SetEnv(env, "GOROOT", toolchainAlias)
	aliasSnapshot, err := gotool.NewEnvReader(aliasRunner, pkg, aliasEnv).Snapshot(t.Context())
	if err != nil || aliasSnapshot.Value("GOROOT") != toolchainAlias {
		t.Fatalf("fixture did not activate aliased GOROOT: %q %v", aliasSnapshot.Value("GOROOT"), err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, versionFile, FileInputContext{Env: aliasEnv, Runner: aliasRunner})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("aliased toolchain root: %+v %v", q, err)
	}
	// A persistent regular file below temp roots is ordinary input, including
	// when the producer declares the minted root rather than inheriting TMPDIR.
	temp := filepath.Join(out, "temp")
	file := eligibilityFile(t, filepath.Join(temp, "persistent"))
	tempEnv := gotool.SetEnv(gotool.SetEnv(env, "TMPDIR", temp), "GOTMPDIR", temp)
	for _, scratch := range []string{"", temp} {
		q, err = FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: tempEnv, ScratchRoot: scratch})
		if err != nil || q.Kind != RawFileInput {
			t.Fatalf("persistent temp file was elided: %+v %v", q, err)
		}
	}
}

// A selected file can also be an input to root resolution. Reading that role
// establishes classification, not a test's consumption of the file as data.
func TestFileInputEligibilityResolutionInputs(t *testing.T) {
	root, pkg := eligibilityModule(t)
	config := eligibilityFile(t, filepath.Join(t.TempDir(), "goenv"))
	env := gotool.UnsetEnv(gotool.SetEnv(eligibilityEnv(pkg), "GOENV", config), "GOCACHE")
	for _, tc := range []struct {
		cache string
		want  FileInputKind
	}{
		{t.TempDir(), RawFileInput},
		{filepath.Dir(config), ElidedFileInput},
	} {
		if err := os.WriteFile(config, []byte("GOCACHE="+tc.cache+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Each query owns a new resolution span after the configuration changes.
		q, err := FileInputEligibility(t.Context(), root, pkg, config, FileInputContext{Env: env})
		if err != nil || q.Kind != tc.want {
			t.Fatalf("selected GOENV configuration: %+v %v, want %v", q, err, tc.want)
		}
		frame := CaptureProducerFrame(t.Context(), root, pkg, FrameOptions{BracketPaths: []string{config}})
		obs := eligibilityObserve(t, frame, writeTestlog(t, ""), ProducerIngest{Identity: "configuration-only", Env: env})
		m, err := decode(obs.Manifest)
		if err != nil || len(m.Paths) != 0 || len(m.Env) != 0 {
			t.Fatalf("root resolution manufactured a consumer observation: %+v %v", m, err)
		}
	}
}

func TestFileInputEligibilityRefusesProjectedAndUnsupported(t *testing.T) {
	root, pkg := eligibilityModule(t)
	env := eligibilityEnv(pkg)
	file := eligibilityFile(t, filepath.Join(t.TempDir(), "manifest"))
	for _, p := range []string{"", "relative", pkg, filepath.Dir(file), file + "-missing", file + "/../manifest", file + "\n", file + "\x00", file + "\xff"} {
		q, err := FileInputEligibility(t.Context(), root, pkg, p, FileInputContext{Env: env})
		if err == nil && (q.Kind != UnverifiableFileInput || q.Reason == "") {
			t.Fatalf("unsupported path %q admitted: %+v", p, q)
		}
	}
	for _, badEnv := range [][]string{nil, {"broken"}, {"PWD=" + pkg, "PWD=" + pkg}} {
		if q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: badEnv}); err == nil || q != (FileEligibility{}) {
			t.Fatalf("invalid environment: %+v %v", q, err)
		}
	}
	for _, badEnv := range [][]string{{}, gotool.UnsetEnv(env, "PWD"), gotool.SetEnv(env, "PWD", root)} {
		q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: badEnv})
		if err != nil || q.Kind != UnverifiableFileInput || q.Reason == "" {
			t.Fatalf("missing/foreign process directory admitted: %+v %v", q, err)
		}
	}
	for _, dirs := range [][2]string{{"relative", pkg}, {root, "relative"}, {root + "-missing", pkg}, {root, file + "-missing"}, {root, filepath.Dir(file)}} {
		q, err := FileInputEligibility(t.Context(), dirs[0], dirs[1], file, FileInputContext{Env: env})
		if err == nil && (q.Kind != UnverifiableFileInput || q.Reason == "") {
			t.Fatalf("invalid directories %v admitted: %+v", dirs, q)
		}
	}
	for _, target := range []string{file, filepath.Dir(file)} {
		link := target + "-link"
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if target != file {
			link = filepath.Join(link, filepath.Base(file))
		}
		q, err := FileInputEligibility(t.Context(), root, pkg, link, FileInputContext{Env: env})
		if err != nil || q.Kind != UnverifiableFileInput || q.Reason == "" {
			t.Fatalf("symlink: %+v %v", q, err)
		}
	}
	if filepath.IsAbs(os.DevNull) {
		q, err := FileInputEligibility(t.Context(), root, pkg, os.DevNull, FileInputContext{Env: env})
		if err != nil || q.Kind != ElidedFileInput || q.Reason == "" {
			t.Fatalf("null sink: %+v %v", q, err)
		}
	}
	if runtime.GOOS == "linux" {
		q, err := FileInputEligibility(t.Context(), root, pkg, "/proc/cpuinfo", FileInputContext{Env: env})
		if err != nil || q.Kind != ProjectedFileInput || q.Reason == "" {
			t.Fatalf("machine projection: %+v %v", q, err)
		}
		probe := classifyProbe
		classifyProbe = func(p string) (os.FileInfo, error) { t.Fatalf("volatile path probed: %s", p); return nil, nil }
		t.Cleanup(func() { classifyProbe = probe })
		q, err = FileInputEligibility(t.Context(), root, pkg, "/proc/self/status", FileInputContext{Env: env})
		if err != nil || q.Kind != UnverifiableFileInput || q.Reason == "" {
			t.Fatalf("volatile: %+v %v", q, err)
		}
	}
}

func TestFileInputEligibilityExclusionPrecedence(t *testing.T) {
	root, pkg := eligibilityModule(t)
	env := eligibilityEnv(pkg)
	file := eligibilityFile(t, filepath.Join(t.TempDir(), "manifest"))
	paths := []string{file, file + "-missing"}
	if runtime.GOOS == "linux" {
		paths = append(paths, "/proc/self/status", "/proc/nonexistent-gofresh-input", "/proc/cpuinfo")
	}
	for _, file := range paths {
		q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env, ExcludedPaths: []string{file}})
		if err != nil || q.Kind != ElidedFileInput || q.Reason == "" {
			t.Fatalf("excluded %s: %+v %v", file, q, err)
		}
		// Identity-only synthetic log: an excluded observation contributes
		// neither a path nor its classification refusal, even when absent.
		frame := CaptureProducerFrame(t.Context(), root, pkg, FrameOptions{})
		obs := eligibilityObserve(t, frame, writeTestlog(t, "open "+file+"\n"), ProducerIngest{Identity: "excluded", Env: env, ExcludedPaths: []string{file}})
		m, err := decode(obs.Manifest)
		if err != nil || len(m.Paths) != 0 {
			t.Fatalf("excluded path recorded: %+v %v", m, err)
		}
	}
	q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env, ExcludedPaths: []string{filepath.VolumeName(file) + string(filepath.Separator)}})
	if err != nil || q.Kind != RawFileInput {
		t.Fatalf("root-listing exclusion widened: %+v %v", q, err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, filepath.Join(root, ".git", "HEAD"), FileInputContext{Env: env})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("facade VCS exclusion lost: %+v %v", q, err)
	}
}

func TestFileInputEligibilityUnavailableRoots(t *testing.T) {
	root, pkg := eligibilityModule(t)
	file := eligibilityFile(t, filepath.Join(t.TempDir(), "manifest"))
	keys := []string{"GOROOT", "GOMODCACHE", "GOCACHE", "GOTMPDIR"}
	for _, missing := range keys {
		t.Run(missing, func(t *testing.T) {
			runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
				// A real go-env document with one required answer omitted.
				cmd.Args = append(cmd.Args[:1], "env", "-json")
				for _, key := range keys {
					if key != missing {
						cmd.Args = append(cmd.Args, key)
					}
				}
			}}
			q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: eligibilityEnv(pkg), Runner: runner})
			if err == nil || q != (FileEligibility{}) {
				t.Fatalf("missing %s granted eligibility: %+v %v", missing, q, err)
			}
		})
	}
}

func TestFileInputEligibilityCancellation(t *testing.T) {
	root, pkg := eligibilityModule(t)
	file := eligibilityFile(t, filepath.Join(t.TempDir(), "manifest"))
	env := eligibilityEnv(pkg)
	if q, err := FileInputEligibility(nil, root, pkg, file, FileInputContext{Env: env}); err == nil || q != (FileEligibility{}) {
		t.Fatalf("nil context: %+v %v", q, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if q, err := FileInputEligibility(ctx, root, pkg, file, FileInputContext{Env: env}); !errors.Is(err, context.Canceled) || q != (FileEligibility{}) {
		t.Fatalf("cancelled entry: %+v %v", q, err)
	}
	for _, elided := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var command *exec.Cmd
		runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
			// Model a runner completing its roots answer despite cancellation.
			// The query must check cancellation after accepting that answer,
			// even on a recordless early return.
			replacement := exec.Command(cmd.Path, cmd.Args[1:]...)
			replacement.Dir, replacement.Env = cmd.Dir, cmd.Env
			*cmd = *replacement
			command = cmd
			cancel()
		}}
		in := FileInputContext{Env: env, Runner: runner}
		if elided {
			in.ExcludedPaths = []string{file}
		}
		q, err := FileInputEligibility(ctx, root, pkg, file, in)
		if command == nil || command.ProcessState == nil || !command.ProcessState.Success() {
			t.Fatal("fixture did not finish the roots command")
		}
		if !errors.Is(err, context.Canceled) || q != (FileEligibility{}) {
			t.Fatalf("cancelled after roots, elided=%v: %+v %v", elided, q, err)
		}
	}
	// Cancellation also dominates pre-probe failures and malformed context.
	for _, tc := range []struct {
		path string
		env  []string
	}{{"relative", env}, {file, nil}} {
		ctx := &cancelAfterChecks{Context: t.Context(), after: 1}
		q, err := FileInputEligibility(ctx, root, pkg, tc.path, FileInputContext{Env: tc.env})
		if !errors.Is(err, context.Canceled) || q != (FileEligibility{}) {
			t.Fatalf("cancelled early refusal: %+v %v", q, err)
		}
	}
	paths := []string{file}
	if runtime.GOOS == "linux" {
		paths = append(paths, "/proc/cpuinfo")
	}
	for _, path := range paths {
		ctx, cancel := context.WithCancel(t.Context())
		probe := classifyProbe
		called := false
		classifyProbe = func(p string) (os.FileInfo, error) {
			called = true
			cancel()
			return probe(p)
		}
		q, err := FileInputEligibility(ctx, root, pkg, path, FileInputContext{Env: env})
		classifyProbe = probe
		cancel()
		if !called || !errors.Is(err, context.Canceled) || q != (FileEligibility{}) {
			t.Fatalf("cancelled after probe of %s: %+v %v", path, q, err)
		}
	}
}

func TestFileInputEligibilityOwnsCallerSlices(t *testing.T) {
	root, pkg := eligibilityModule(t)
	cache := t.TempDir()
	file := eligibilityFile(t, filepath.Join(cache, "manifest"))
	for _, excluded := range []bool{false, true} {
		env := gotool.SetEnv(eligibilityEnv(pkg), "GOCACHE", t.TempDir())
		exclusions := []string{file + "-other"}
		want := RawFileInput
		if excluded {
			exclusions[0], want = file, ElidedFileInput
		}
		called := false
		runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
			called = true
			for i, entry := range env {
				if strings.HasPrefix(entry, "GOCACHE=") {
					env[i] = "GOCACHE=" + cache
				}
				if strings.HasPrefix(entry, "PWD=") {
					env[i] = "PWD=" + root
				}
			}
			if excluded {
				exclusions[0] = file + "-other"
			} else {
				exclusions[0] = file
			}
			if pwd, _ := gotool.LookupEnv(cmd.Env, "PWD"); pwd != pkg {
				t.Fatalf("runner inherited mutated PWD: %q", pwd)
			}
		}}
		q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env, Runner: runner, ExcludedPaths: exclusions})
		if !called || err != nil || q.Kind != want {
			t.Fatalf("caller mutation changed query, excluded=%v: %+v %v", excluded, q, err)
		}
	}
}

func TestFileInputEligibilityExecution(t *testing.T) {
	const modeKey = "GOFRESH_ELIGIBILITY_CHILD"
	const fileKey = "GOFRESH_ELIGIBILITY_FILE"
	if mode := os.Getenv(modeKey); mode != "" {
		file := os.Getenv(fileKey)
		switch mode {
		case "read":
			data, err := os.ReadFile(file)
			if err != nil || string(data) != "before" {
				t.Fatalf("actual read: %q %v", data, err)
			}
		case "query":
			q, err := FileInputEligibility(t.Context(), os.Getenv("GOFRESH_ELIGIBILITY_ROOT"), os.Getenv("PWD"), file, FileInputContext{Env: os.Environ()})
			if err != nil || q.Kind != RawFileInput {
				t.Fatalf("child query: %+v %v", q, err)
			}
		default:
			t.Fatalf("unknown child mode: %s", mode)
		}
		return
	}
	root, pkg := eligibilityModule(t)
	file := eligibilityFile(t, filepath.Join(t.TempDir(), "manifest"))
	env := gotool.SetEnv(eligibilityEnv(pkg), fileKey, file)
	q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env})
	if err != nil || q.Kind != RawFileInput {
		t.Fatalf("preflight: %+v %v", q, err)
	}
	// Query and bracket declaration alone add no observed identity. This empty
	// synthetic capture makes only an identity-guard claim, with no outcomes.
	frame := CaptureProducerFrame(t.Context(), root, pkg, FrameOptions{BracketPaths: []string{file}})
	empty := eligibilityObserve(t, frame, writeTestlog(t, ""), ProducerIngest{Identity: "no-open", Env: env})
	m, err := decode(empty.Manifest)
	if err != nil || len(m.Paths) != 0 || len(m.Env) != 0 {
		t.Fatalf("preflight fabricated identities: %+v %v", m, err)
	}
	var observed Observation
	for _, mode := range []string{"query", "read"} {
		childEnv := gotool.SetEnv(gotool.SetEnv(env, modeKey, mode), "GOFRESH_ELIGIBILITY_ROOT", root)
		logPath := filepath.Join(t.TempDir(), "child.testlog")
		cmd, err := (gotool.Runner{}).Program(t.Context(), pkg, childEnv, os.Args[0], "-test.run=^TestFileInputEligibilityExecution$", "-test.testlogfile="+logPath)
		if err != nil {
			t.Fatal(err)
		}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s child: %v\n%s", mode, err, output)
		}
		log, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		hasOpen := slices.Contains(strings.Split(string(log), "\n"), "open "+file)
		if hasOpen != (mode == "read") {
			t.Fatalf("%s selected-file open=%v; log:\n%s", mode, hasOpen, log)
		}
		if mode == "read" {
			observed = eligibilityObserve(t, frame, logPath, ProducerIngest{Identity: "actual-read", Env: childEnv})
			paths, err := Paths(observed.Manifest, root)
			if err != nil || !slices.Contains(paths, file) {
				t.Fatalf("actual open not recorded: %v %v", paths, err)
			}
			m, err := decode(observed.Manifest)
			if err != nil || !slices.ContainsFunc(m.Env, func(e envInput) bool { return e.Name == fileKey }) {
				t.Fatalf("path environment read not recorded: %+v %v", m, err)
			}
			env = childEnv
		}
	}
	if err := os.WriteFile(file, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	current, err := Current(t.Context(), observed.Manifest, root, env)
	if err != nil || current.Unverifiable || current.Digest == observed.Digest {
		t.Fatalf("actual observed content change missed: %+v %v", current, err)
	}
}
