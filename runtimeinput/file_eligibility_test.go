package runtimeinput

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
)

func eligibilityFile(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func eligibilityEnv(pkg string) []string {
	env := producerEnv(pkg)
	for k, v := range map[string]string{"GOENV": "off", "GOFLAGS": "", "GOWORK": "off", "GOTOOLCHAIN": "local"} {
		env = gotool.SetEnv(env, k, v)
	}
	return env
}

// The query and the actual producer's identity-only guard construction agree.
// The synthetic log exercises classification, not operation-outcome authority.
func TestFileInputEligibilityMatchesProducer(t *testing.T) {
	root, pkg := producerModule(t)
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
			obs, why, err := captureGuards(frame, t.Context(), writeTestlog(t, "open "+file+"\n"), ProducerIngest{Identity: "eligibility-fixture", Env: env, Roots: memo})
			if err != nil || why != "" || obs.Unverifiable {
				t.Fatalf("producer: %+v %q %v", obs.State, why, err)
			}
			m, err := decode(obs.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			present := false
			for _, entry := range m.Paths {
				p, err := materializePath(root, entry.pathID)
				if err != nil {
					t.Fatal(err)
				}
				if p == file {
					present = true
				}
			}
			if present != (tc.want == RawFileInput) {
				t.Fatalf("query and producer disagree: kind=%v path present=%v", q.Kind, present)
			}
			if err := os.WriteFile(file, []byte("after"), 0600); err != nil {
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
	root, pkg := producerModule(t)
	out := t.TempDir()
	cache, modules := filepath.Join(out, "build"), filepath.Join(out, "modules")
	cacheFile := eligibilityFile(t, filepath.Join(cache, "manifest"))
	config := filepath.Join(out, "goenv")
	if err := os.WriteFile(config, []byte("GOCACHE="+cache+"\nGOMODCACHE="+modules+"\n"), 0600); err != nil {
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
	if err := os.Mkdir(other, 0700); err != nil {
		t.Fatal(err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, cacheFile, FileInputContext{Env: gotool.SetEnv(env, "GOCACHE", other)})
	if err != nil || q.Kind != RawFileInput {
		t.Fatalf("environment override lost: %+v %v", q, err)
	}
	versionFile := filepath.Join(snapshot.Value("GOROOT"), "VERSION")
	q, err = FileInputEligibility(t.Context(), root, pkg, versionFile, FileInputContext{Env: env})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("toolchain file: %+v %v", q, err)
	}
	// A persistent regular file below the temp roots is ordinary input.
	temp := filepath.Join(out, "temp")
	file := eligibilityFile(t, filepath.Join(temp, "persistent"))
	tempEnv := gotool.SetEnv(gotool.SetEnv(env, "TMPDIR", temp), "GOTMPDIR", temp)
	q, err = FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: tempEnv})
	if err != nil || q.Kind != RawFileInput {
		t.Fatalf("persistent temp file was elided: %+v %v", q, err)
	}
}

func TestFileInputEligibilityRefusesProjectedAndUnsupported(t *testing.T) {
	root, pkg := producerModule(t)
	env := eligibilityEnv(pkg)
	file := eligibilityFile(t, filepath.Join(t.TempDir(), "manifest"))
	for _, p := range []string{"", "relative", filepath.Dir(file), file + "-missing"} {
		q, err := FileInputEligibility(t.Context(), root, pkg, p, FileInputContext{Env: env})
		if err == nil && (q.Kind == RawFileInput || q.Reason == "") {
			t.Fatalf("unsupported path %q admitted: %+v", p, q)
		}
	}
	q, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env, ExcludedPaths: []string{file}})
	if err != nil || q.Kind != ElidedFileInput {
		t.Fatalf("excluded: %+v %v", q, err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: env, ExcludedPaths: []string{filepath.VolumeName(file) + string(filepath.Separator)}})
	if err != nil || q.Kind != RawFileInput {
		t.Fatalf("root-listing exclusion widened: %+v %v", q, err)
	}
	if _, err := FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{}); err == nil {
		t.Fatal("missing producing environment admitted")
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, file, FileInputContext{Env: gotool.SetEnv(env, "PWD", root)})
	if err != nil || q.Kind != UnverifiableFileInput || !strings.Contains(q.Reason, "PWD") {
		t.Fatalf("foreign process directory admitted: %+v %v", q, err)
	}
	link := file + "-link"
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	q, err = FileInputEligibility(t.Context(), root, pkg, link, FileInputContext{Env: env})
	if err != nil || q.Kind != UnverifiableFileInput || !strings.Contains(q.Reason, "symlink") {
		t.Fatalf("symlink: %+v %v", q, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := FileInputEligibility(ctx, root, pkg, file, FileInputContext{Env: env}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if runtime.GOOS == "linux" {
		q, err = FileInputEligibility(t.Context(), root, pkg, "/proc/cpuinfo", FileInputContext{Env: env})
		if err != nil || q.Kind != ProjectedFileInput {
			t.Fatalf("machine projection: %+v %v", q, err)
		}
		q, err = FileInputEligibility(t.Context(), root, pkg, "/proc/self/status", FileInputContext{Env: env})
		if err != nil || q.Kind != UnverifiableFileInput || !strings.Contains(q.Reason, "volatile") {
			t.Fatalf("volatile: %+v %v", q, err)
		}
	}
}
