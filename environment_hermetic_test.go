//go:build unix

package gofresh

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/gotool"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Complete build identity retains build-determining compilation environment
// keys and resolved Go settings while ignoring ambient shell variables and
// local checkout/cache directory paths.
func TestCompleteBuildDescriptionIdentity(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	work := filepath.Join(dir, "go-build123")
	base := map[string]string{"GOENV": "off", "GOAMD64": "v1", "GOGCCFLAGS": "-fPIC '-ffile-prefix-map=" + work + "=/tmp/go-build' -gno-record-gcc-switches"}
	identity := func(env []string, values map[string]string) string {
		t.Helper()
		normalized, err := gotool.NormalizeEnv(env)
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		got, err := completeBuildEnvironment(ctx, &gotool.EnvSnapshot{JSON: data}, dir, normalized)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	a := identity([]string{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH="}, base)
	for _, env := range [][]string{
		{"CGO_CFLAGS_ALLOW=b", "PKG_CONFIG_PATH="},
		{"CGO_CFLAGS_ALLOW=a"},
		{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH=", "SOURCE_DATE_EPOCH=1700000000"},
	} {
		if identity(env, base) == a {
			t.Fatalf("build environment change ignored: %q", env)
		}
	}
	if identity([]string{"PKG_CONFIG_PATH=", "CGO_CFLAGS_ALLOW=a"}, base) != a {
		t.Fatal("normalized ordering changed identity")
	}
	for _, ambient := range [][]string{
		{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH=", "ANTIGRAVITY_SOURCE_METADATA={\"stepIndex\":1}"},
		{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH=", "TERM=xterm-256color", "SHLVL=2", "PWD=/other"},
		{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH=", "GOMAXPROCS=2", "XDG_CACHE_HOME=/tmp/cache"},
	} {
		if identity(ambient, base) != a {
			t.Fatalf("ambient environment variable entered build identity: %q", ambient)
		}
	}
	for _, pair := range [][2][]string{
		{{"CGO_CFLAGS_ALLOW=\xff"}, {"CGO_CFLAGS_ALLOW=\xfe"}},
		{{"CGO_CFLAGS_ALLOW=x\nCGO_LDFLAGS_ALLOW=y"}, {"CGO_CFLAGS_ALLOW=x", "CGO_LDFLAGS_ALLOW=y"}},
		{{"CGO_CFLAGS_ALLOW="}, {}},
	} {
		if identity(pair[0], base) == identity(pair[1], base) {
			t.Fatalf("raw inputs collided: %q / %q", pair[0], pair[1])
		}
	}
	for _, key := range []string{"GOAMD64", "GOFIPS140", "CGO_LDFLAGS", "GODEBUG"} {
		changed := make(map[string]string)
		for k, v := range base {
			changed[k] = v
		}
		changed[key] = "changed"
		if identity([]string{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH="}, changed) == a {
			t.Fatalf("resolved setting %s dropped", key)
		}
	}
	for _, localKey := range []string{"GOMOD", "GOCACHE", "GOTMPDIR", "GOPATH", "GOMODCACHE", "GOBIN", "GOTOOLDIR", "GOROOT"} {
		changed := make(map[string]string)
		for k, v := range base {
			changed[k] = v
		}
		changed[localKey] = "/local/checkout/path"
		if identity([]string{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH="}, changed) != a {
			t.Fatalf("local path setting %s entered build identity", localKey)
		}
	}
	goworkA := make(map[string]string)
	goworkB := make(map[string]string)
	for k, v := range base {
		goworkA[k] = v
		goworkB[k] = v
	}
	goworkA["GOWORK"] = "/checkout-a/go.work"
	goworkB["GOWORK"] = "/checkout-b/go.work"
	if identity([]string{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH="}, goworkA) == a {
		t.Fatal("enabling GOWORK workspace mode did not move build identity")
	}
	if identity([]string{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH="}, goworkA) != identity([]string{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH="}, goworkB) {
		t.Fatal("local GOWORK path entered build identity")
	}
	changed := make(map[string]string)
	for k, v := range base {
		changed[k] = v
	}
	changed["GOGCCFLAGS"] = strings.Replace(base["GOGCCFLAGS"], work+"=", filepath.Join(dir, "go-build456")+"=", 1)
	if identity([]string{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH="}, changed) != a {
		t.Fatal("generated work path entered identity")
	}
	changed["GOGCCFLAGS"] += " -pthread"
	if identity([]string{"CGO_CFLAGS_ALLOW=a", "PKG_CONFIG_PATH="}, changed) == a {
		t.Fatal("compiler flag was normalized away")
	}
	file := filepath.Join(dir, "go-env")
	changed["GOENV"] = file
	if err := os.WriteFile(file, []byte("CUSTOM=\xff\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first := identity(nil, changed)
	if err := os.WriteFile(file, []byte("CUSTOM=\xfe\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if identity(nil, changed) == first {
		t.Fatal("raw GOENV content was not a dependency")
	}
}

func TestGeneratedCompilerFlagNormalization(t *testing.T) {
	for _, text := range []string{
		"'-fPIC",
		"-ffile-prefix-map=/source=/tmp/go-build",
		"-fdebug-prefix-map=/tmp/go-build123=/somewhere-else",
		"-ffile-prefix-map=/tmp/go-build123=/tmp/go-build -fdebug-prefix-map=/tmp/go-build456=/tmp/go-build",
	} {
		if _, err := normalizedGCCFlags(text); err == nil {
			t.Fatalf("ambiguous compiler mapping admitted: %q", text)
		}
	}
	for _, prefix := range []string{"-ffile-prefix-map=", "-fdebug-prefix-map="} {
		work := filepath.Join(t.TempDir(), "two spaces", "go-build123")
		flags, err := normalizedGCCFlags("'-DVALUE=two  spaces' '" + prefix + work + "=/tmp/go-build'")
		if err != nil || len(flags) != 2 || flags[0] != "-DVALUE=two  spaces" || flags[1] != prefix+"<generated-work-directory>=/tmp/go-build" {
			t.Fatalf("quoted compiler fields: %q %v", flags, err)
		}
	}
}

// Preparation cancellation reaches the actual query, including a cancellation
// after command preparation but before spawn and one while the child runs.
func TestConstructionContextOwnsTheEnvironmentQuery(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"before-spawn", "running", "completed-answer"} {
		t.Run(mode, func(t *testing.T) {
			during := mode != "before-spawn"
			dir := t.TempDir()
			started := filepath.Join(dir, "started")
			release := filepath.Join(dir, "release")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner := gotool.Runner{Prepare: func(cmd *exec.Cmd) {
				if strings.Join(cmd.Args[1:], " ") != "env -json" {
					t.Errorf("unexpected preparation query: %v", cmd.Args)
				}
				cmd.Path = shell
				cmd.Args = []string{shell, "-c", `printf started > "$1"; while ! test -f "$2"; do sleep 0.01; done; printf '{"GOFLAGS":""}'`, "constructor-query", started, release}
				if mode == "completed-answer" {
					// A policy may retain a successfully exiting child's answer.
					// That answer does not keep its cancelled owner alive.
					cmd.Cancel = func() error {
						if err := os.WriteFile(release, nil, 0600); err != nil {
							return err
						}
						return os.ErrProcessDone
					}
				}
				if !during {
					cancel()
				}
			}}
			if !during {
				if err := os.WriteFile(release, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			type result struct {
				engine *engine
				err    error
			}
			done := make(chan result, 1)
			go func() {
				e, err := newEngineContext(ctx, withDir(dir), withGoRunner(runner))
				done <- result{e, err}
			}()
			// Releasing the shim also cleans up a background-context mutant:
			// the deciding failure is the assertion, never an oracle timeout.
			defer func() { _ = os.WriteFile(release, nil, 0600) }()
			if during {
				deadline := time.NewTimer(5 * time.Second)
				defer deadline.Stop()
				tick := time.NewTicker(5 * time.Millisecond)
				defer tick.Stop()
			waitForStart:
				for {
					if _, err := os.Stat(started); err == nil {
						break
					}
					select {
					case <-tick.C:
					case r := <-done:
						t.Fatalf("constructor returned before query started: %v", r.err)
					case <-deadline.C:
						t.Error("query did not start")
						break waitForStart
					}
				}
				cancel()
			}
			var r result
			select {
			case r = <-done:
			case <-time.After(2 * time.Second):
				t.Error("cancelled construction kept its query running")
				if err := os.WriteFile(release, nil, 0600); err != nil {
					t.Fatal(err)
				}
				select {
				case r = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("released query did not end")
				}
			}
			if r.engine != nil || !errors.Is(r.err, context.Canceled) {
				t.Fatalf("cancelled construction: engine returned=%t error=%v", r.engine != nil, r.err)
			}
			if !during {
				if _, err := os.Stat(started); !os.IsNotExist(err) {
					t.Fatalf("query spawned after cancellation: %v", err)
				}
			}
		})
	}
}

func TestSessionChecksToolchainSkew(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(bin, "go")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\necho '{\"GOVERSION\":\"go99.1.0\",\"GOCACHE\":\"/tmp\",\"GOMODCACHE\":\"/tmp\",\"GOROOT\":\"/tmp\",\"GOTMPDIR\":\"/tmp\"}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, err := NewSession(context.Background(), BuildDescription{
		Directory:   dir,
		Environment: gotool.SetEnv(os.Environ(), "PWD", dir),
		Inputs:      []string{},
	}, SessionPolicy{})
	var skew *ToolchainProvenanceError
	if !errors.As(err, &skew) {
		t.Fatalf("NewSession under skewed GOVERSION returned %v, want *ToolchainProvenanceError", err)
	}
}

// Rebinding outer data cannot lend a proof or outcome a dependency it did not
// carry when produced. This is an integrity check, not provenance authentication.
func TestObservationProofBindsToolchainDependencies(t *testing.T) {
	subject := Subject{Package: "p", Symbol: "F"}
	record := Fingerprint{MaximalClosure: "core", ToolchainContent: "content", AdmissionPolicy: "policy", ObservationAssertion: "caller assertion", ObservationProof: ObservationProof{Strategy: ObservationRTA, Subject: subject, Observable: true}}
	record.ObservationProof.Evidence = observationProofEvidence(record)
	if !compatibleObservationProof(record, subject) {
		t.Fatal("positive proof control refused")
	}
	identity := outcomeSubject(record, subject)
	for _, change := range []func(*Fingerprint){
		func(f *Fingerprint) { f.ToolchainContent = "other" },
		func(f *Fingerprint) { f.ToolchainContent = "" },
		func(f *Fingerprint) { f.AdmissionPolicy = "other" },
		func(f *Fingerprint) { f.AdmissionPolicy = "" },
	} {
		moved := record
		change(&moved)
		if compatibleObservationProof(moved, subject) || outcomeSubject(moved, subject) == identity {
			t.Fatal("borrowed dependency admitted")
		}
	}
	old := record
	old.ObservationProof.Strategy = "gofresh/observation-rta@43"
	old.ObservationProof.Evidence = observationProofEvidence(old)
	if compatibleObservationProof(old, subject) {
		t.Fatal("historical strategy acquired new compatibility")
	}
}

// TestUnauditedToolchainDropsPurityAdmissions pins the purity tier's
// half of the content keying: on an unlisted surface the audited
// synchronization, pooling, and immutable-type admissions all keep
// their fail-closed classifications
// (REQ-closure-observability-toolchain-key).
func TestUnauditedToolchainDropsPurityAdmissions(t *testing.T) {
	syncPkg := types.NewPackage("sync", "sync")
	method := func(recvType string, name string) *types.Func {
		named := types.NewNamed(types.NewTypeName(token.NoPos, syncPkg, recvType, nil), types.NewStruct(nil, nil), nil)
		recv := types.NewVar(token.NoPos, syncPkg, "m", types.NewPointer(named))
		sig := types.NewSignatureType(recv, nil, nil, nil, nil, false)
		return types.NewFunc(token.NoPos, syncPkg, name, sig)
	}
	lock := method("Mutex", "Lock")
	get := method("Pool", "Get")
	reflectPkg := types.NewPackage("reflect", "reflect")
	reflType := types.NewNamed(types.NewTypeName(token.NoPos, reflectPkg, "Type", nil), types.NewInterfaceType(nil, nil), nil)
	// The vacuity guard: under an audited verdict the fakes admit, so
	// the refusals below witness the verdict parameter, not a
	// malformed fake. The verdict is the two-axis
	// Hasher-resolved audit verdict the scan entries read once — an
	// unlisted surface or unaudited selection reaches every
	// admission as false.
	if !refconfine.AuditedSynchronization(true, lock) || !refconfine.AuditedPooling(true, get) || !refconfine.AuditedImmutableType(true, reflType) {
		t.Fatal("fakes not admitted under an audited verdict; the refusal arms below would be vacuous")
	}
	if refconfine.AuditedSynchronization(false, lock) {
		t.Error("AuditedSynchronization admits sync.Mutex.Lock on an unaudited toolchain")
	}
	if refconfine.AuditedPooling(false, get) {
		t.Error("AuditedPooling admits sync.Pool.Get on an unaudited toolchain")
	}
	if refconfine.AuditedImmutableType(false, reflType) {
		t.Error("AuditedImmutableType admits reflect.Type on an unaudited toolchain")
	}
}
