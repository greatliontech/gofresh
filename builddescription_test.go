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

// Complete build identity retains every raw environment byte and resolved
// setting; the generated work path alone is a licensed equivalence.
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
	a := identity([]string{"COMPILER_MODE=a", "EMPTY="}, base)
	for _, env := range [][]string{{"COMPILER_MODE=b", "EMPTY="}, {"COMPILER_MODE=a"}, {"COMPILER_MODE=a", "EMPTY=", "GOMAXPROCS=2"}} {
		if identity(env, base) == a {
			t.Fatalf("build environment change ignored: %q", env)
		}
	}
	if identity([]string{"EMPTY=", "COMPILER_MODE=a"}, base) != a {
		t.Fatal("normalized ordering changed identity")
	}
	for _, pair := range [][2][]string{
		{{"MODE=\xff"}, {"MODE=\xfe"}},
		{{"MODE=x\nOTHER=y"}, {"MODE=x", "OTHER=y"}},
		{{"MODE="}, {}},
	} {
		if identity(pair[0], base) == identity(pair[1], base) {
			t.Fatalf("raw inputs collided: %q / %q", pair[0], pair[1])
		}
	}
	for _, key := range []string{"GOAMD64", "COMPILER_FUTURE_SETTING"} {
		changed := make(map[string]string)
		for k, v := range base {
			changed[k] = v
		}
		changed[key] = "changed"
		if identity([]string{"COMPILER_MODE=a", "EMPTY="}, changed) == a {
			t.Fatalf("resolved setting %s dropped", key)
		}
	}
	changed := make(map[string]string)
	for k, v := range base {
		changed[k] = v
	}
	changed["GOGCCFLAGS"] = strings.Replace(base["GOGCCFLAGS"], work+"=", filepath.Join(dir, "go-build456")+"=", 1)
	if identity([]string{"COMPILER_MODE=a", "EMPTY="}, changed) != a {
		t.Fatal("generated work path entered identity")
	}
	changed["GOGCCFLAGS"] += " -pthread"
	if identity([]string{"COMPILER_MODE=a", "EMPTY="}, changed) == a {
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
