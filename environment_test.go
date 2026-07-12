package gofresh

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/greatliontech/gofresh/runtimeinput"
)

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

func viewUsesSource(t *testing.T, engine *Engine, fixture workspaceEnvironmentFixture, want, notWant string) {
	t.Helper()
	view, err := engine.NewView([]Subject{fixture.subject}, fixture.consumer)
	if err != nil {
		t.Fatal(err)
	}
	files := view.SourceFiles()
	if !slices.Contains(files, want) || slices.Contains(files, notWant) {
		t.Fatalf("selected source files = %v, want %s and not %s", files, want, notWant)
	}
}

func TestWithEnvSelectsWorkspaceSource(t *testing.T) {
	fixture := writeWorkspaceEnvironmentFixture(t)
	t.Setenv("GOWORK", fixture.goWork)

	standalone, err := New(WithDir(fixture.consumer), WithEnv(environmentWith(map[string]string{"GOWORK": "off"})...))
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := New(WithDir(fixture.consumer), WithEnv(environmentWith(map[string]string{"GOWORK": fixture.goWork})...))
	if err != nil {
		t.Fatal(err)
	}
	viewUsesSource(t, standalone, fixture, fixture.standaloneFile, fixture.workspaceFile)
	viewUsesSource(t, workspace, fixture, fixture.workspaceFile, fixture.standaloneFile)
}

func TestEnginesWithDifferentEnvironmentsConstructViewsConcurrently(t *testing.T) {
	fixture := writeWorkspaceEnvironmentFixture(t)
	standalone, err := New(WithDir(fixture.consumer), WithEnv(environmentWith(map[string]string{"GOWORK": "off"})...))
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := New(WithDir(fixture.consumer), WithEnv(environmentWith(map[string]string{"GOWORK": fixture.goWork})...))
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		files []string
		err   error
	}
	results := make([]result, 2)
	engines := []*Engine{standalone, workspace}
	var wait sync.WaitGroup
	for i, engine := range engines {
		wait.Add(1)
		go func() {
			defer wait.Done()
			view, err := engine.NewView([]Subject{fixture.subject}, fixture.consumer)
			results[i].err = err
			if err == nil {
				results[i].files = view.SourceFiles()
			}
		}()
	}
	wait.Wait()
	for _, result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
	}
	if !slices.Contains(results[0].files, fixture.standaloneFile) || slices.Contains(results[0].files, fixture.workspaceFile) {
		t.Fatalf("standalone Engine files = %v", results[0].files)
	}
	if !slices.Contains(results[1].files, fixture.workspaceFile) || slices.Contains(results[1].files, fixture.standaloneFile) {
		t.Fatalf("workspace Engine files = %v", results[1].files)
	}
}

func TestWithEnvCopiesNormalizesAndRejectsAmbiguity(t *testing.T) {
	fixture := writeWorkspaceEnvironmentFixture(t)
	env := environmentWith(map[string]string{"GOWORK": "off"})
	option := WithEnv(env...)
	for i := range env {
		if strings.HasPrefix(env[i], "GOWORK=") {
			env[i] = "GOWORK=" + fixture.goWork
		}
	}
	engine, err := New(WithDir(fixture.consumer), option)
	if err != nil {
		t.Fatal(err)
	}
	viewUsesSource(t, engine, fixture, fixture.standaloneFile, fixture.workspaceFile)

	reversed := environmentWith(map[string]string{"GOWORK": "off"})
	slices.Reverse(reversed)
	other, err := New(WithDir(fixture.consumer), WithEnv(reversed...))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(engine.env, other.env) {
		t.Fatal("equivalent environments did not normalize deterministically")
	}

	for _, test := range []struct {
		name string
		env  []string
		want string
	}{
		{name: "missing equals", env: []string{"BROKEN"}, want: "malformed"},
		{name: "empty key", env: []string{"=value"}, want: "malformed"},
		{name: "NUL", env: []string{"KEY=value\x00tail"}, want: "NUL"},
		{name: "duplicate", env: []string{"KEY=first", "KEY=second"}, want: "duplicate key"},
		{name: "external package driver", env: environmentWith(map[string]string{"GOPACKAGESDRIVER": "custom-driver"}), want: "GOPACKAGESDRIVER"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(WithEnv(test.env...)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("New(WithEnv(%q)) = %v, want %q error", test.env, err, test.want)
			}
		})
	}

}

func TestDefaultEnvironmentIsCapturedAtNew(t *testing.T) {
	fixture := writeWorkspaceEnvironmentFixture(t)
	t.Setenv("GOWORK", "off")
	standalone, err := New(WithDir(fixture.consumer))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", fixture.goWork)
	workspace, err := New(WithDir(fixture.consumer))
	if err != nil {
		t.Fatal(err)
	}
	viewUsesSource(t, standalone, fixture, fixture.standaloneFile, fixture.workspaceFile)
	viewUsesSource(t, workspace, fixture, fixture.workspaceFile, fixture.standaloneFile)
}

func TestWithEnvDoesNotSelectGoLauncherFromSuppliedPath(t *testing.T) {
	fixture := writeWorkspaceEnvironmentFixture(t)
	env := environmentWith(map[string]string{"GOWORK": "off", "PATH": filepath.Join(t.TempDir(), "missing")})
	engine, err := New(WithDir(fixture.consumer), WithEnv(env...))
	if err != nil {
		t.Fatalf("host go launcher was not used: %v", err)
	}
	if _, err := engine.NewView([]Subject{fixture.subject}, fixture.consumer); err != nil {
		t.Fatalf("view did not retain host go launcher: %v", err)
	}
}

func TestPackageDriverSafetyPinDoesNotChangeRuntimeEnvironment(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/driverenv\n\ngo 1.26.4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package driverenv\n\nfunc F() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GOPACKAGESDRIVER=") {
			env = append(env, entry)
		}
	}
	engine, err := New(WithDir(dir), WithEnv(env...))
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Package: "example.com/driverenv", Symbol: "F"}
	view, err := engine.NewView([]Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := view.Capture(subject)
	if err != nil {
		t.Fatal(err)
	}
	state, err := runtimeinput.FromTestLogEnv([]byte("getenv GOPACKAGESDRIVER\n"), dir, dir, env)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint.RuntimeInputs = state.Manifest
	fingerprint.RuntimeDigest = state.Digest
	verdict, err := view.Check(fingerprint, subject)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("package-driver safety pin changed runtime environment: %+v", verdict)
	}
}
