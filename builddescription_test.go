package gofresh

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
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
