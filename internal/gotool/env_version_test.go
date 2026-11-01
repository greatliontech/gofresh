package gotool

import (
	"context"
	"errors"
	"go/version"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestForCommandDerivesPWDFromWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	got, err := EnvForCommand([]string{"PATH=/bin", "PWD=/wrong"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	pwd, ok := LookupEnv(got, "PWD")
	if !ok || pwd != filepath.Clean(dir) {
		t.Fatalf("PWD = %q/%v, want %s", pwd, ok, dir)
	}
}

func TestForCommandPreservesPWDWithoutWorkingDirectory(t *testing.T) {
	got, err := EnvForCommand([]string{"PATH=/bin", "PWD=/caller/path"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if pwd, ok := LookupEnv(got, "PWD"); !ok || pwd != "/caller/path" {
		t.Fatalf("PWD = %q/%v, want caller value", pwd, ok)
	}
}

func TestForGoPackagesDisablesExternalDrivers(t *testing.T) {
	for _, env := range [][]string{
		{"PATH=/bin"},
		{"PATH=/bin", "GOPACKAGESDRIVER="},
		{"PATH=/bin", "gopackagesdriver=off"},
	} {
		got, err := EnvForPackages(env)
		if err != nil {
			t.Fatal(err)
		}
		if driver, ok := LookupEnv(got, "GOPACKAGESDRIVER"); !ok || driver != "off" {
			t.Fatalf("EnvForPackages(%v) GOPACKAGESDRIVER = %q/%v, want off", env, driver, ok)
		}
		foundCanonical := false
		for _, entry := range got {
			foundCanonical = foundCanonical || entry == "GOPACKAGESDRIVER=off"
		}
		if !foundCanonical {
			t.Fatalf("EnvForPackages(%v) = %v, missing canonical safety pin", env, got)
		}
	}
	if _, err := EnvForPackages([]string{"PATH=/bin", "GOPACKAGESDRIVER=custom"}); err == nil {
		t.Fatal("external package driver accepted")
	}
}

// A duplicate key is refused, never resolved by first- or last-entry
// platform behaviour: the policy's environment is one binding per key.
func TestNormalizeEnvRefusesDuplicateKeys(t *testing.T) {
	if _, err := NormalizeEnv([]string{"A=1", "B=2", "A=3"}); err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("duplicate key accepted: %v", err)
	}
	if _, err := EnvForCommand([]string{"PWD=/x", "PWD=/y"}, ""); err == nil {
		t.Fatal("duplicate PWD accepted through EnvForCommand")
	}
}

// UnsetEnv removes every entry under the key as the policy judges keys
// and keeps the rest in order — SetEnv's exact inverse, so setting then
// unsetting a key returns the environment less that key, and unsetting
// an absent key changes nothing (REQ-fresh-go-command-policy).
func TestUnsetEnvRemovesEveryEntryUnderTheKey(t *testing.T) {
	env := []string{"A=1", "B=2", "a=3", "C=4"}
	got := UnsetEnv(env, "A")
	want := []string{"B=2", "a=3", "C=4"}
	if len(got) != len(want) {
		t.Fatalf("UnsetEnv = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("UnsetEnv = %v, want %v", got, want)
		}
	}
	if same := UnsetEnv(env, "ZZ"); len(same) != len(env) {
		t.Fatalf("an absent key changed the environment: %v", same)
	}
	set := SetEnv(env, "B", "9")
	back := UnsetEnv(set, "B")
	if len(back) != 3 || back[0] != "A=1" || back[1] != "a=3" || back[2] != "C=4" {
		t.Fatalf("set then unset = %v, want the environment less B", back)
	}
}

// SetEnv drops every entry of the key and inserts the new one where
// NormalizeEnv orders it: over a normalized environment the result is
// what NormalizeEnv would return over the appended form — the setter
// keeps the policy's order instead of appending out of it.
func TestSetEnvKeepsNormalizeEnvsOrder(t *testing.T) {
	cases := [][]string{
		{},
		{"A=2", "B=1"},
		{"GOFLAGS=old", "PWD=/a", "Z=1"},
		{"GOFLAGS=", "Z=1", "m=2"},
	}
	for _, env := range cases {
		got := SetEnv(env, "GOFLAGS", "-race")
		appended := append([]string(nil), env...)
		var kept []string
		for _, e := range appended {
			if !strings.HasPrefix(e, "GOFLAGS=") {
				kept = append(kept, e)
			}
		}
		want, err := NormalizeEnv(append(kept, "GOFLAGS=-race"))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("SetEnv(%v) = %v, want NormalizeEnv's order %v", env, got, want)
		}
		if n := strings.Count(strings.Join(got, "\n")+"\n", "GOFLAGS="); n != 1 {
			t.Fatalf("SetEnv(%v) carries GOFLAGS %d times", env, n)
		}
	}
}

// Coordinate never fails: the canonical coordinate where the
// filesystem answers, the absolute spelling for a directory that does
// not exist, the spelling itself only where even that fails.
func TestCoordinateDegrades(t *testing.T) {
	dir := t.TempDir()
	// A symlink spelling: the coordinate is the target's, never the
	// absolute spelling of the link.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := Coordinate(link); got != canonical || got == link {
		t.Fatalf("Coordinate(symlink) = %q, want the canonical %q", got, canonical)
	}
	missing := dir + "/no/such/dir"
	if got := Coordinate(missing); got != missing {
		t.Fatalf("Coordinate(missing absolute) = %q, want the absolute spelling", got)
	}
	if got := Coordinate("relative/missing"); got == "relative/missing" || got == "" {
		t.Fatalf("Coordinate(missing relative) = %q, want an absolute spelling", got)
	}
}

func TestPreserveBuildCachePinsEffectiveCache(t *testing.T) {
	for _, configured := range []string{t.TempDir(), "off"} {
		cache, err := goBuildCache([]string{"GOCACHE=" + configured}, func() (string, error) {
			t.Fatal("explicit cache caused a toolchain query")
			return "", nil
		})
		if err != nil || cache != configured {
			t.Fatalf("cache = %q, err = %v", cache, err)
		}
	}
	for _, cause := range []error{nil, errors.New("toolchain unavailable")} {
		cache, err := goBuildCache([]string{}, func() (string, error) { return "", cause })
		if err == nil || err.Error() == "" || (cause != nil && !errors.Is(err, cause)) || cache != "" {
			t.Fatalf("lookup %v: cache = %q, err = %v", cause, cache, err)
		}
	}
	base := SetEnv(os.Environ(), "GOCACHE", "")
	preserved, err := PreserveBuildCache(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	pinned, ok := LookupEnv(preserved, "GOCACHE")
	if !ok || pinned == "" {
		t.Fatalf("PreserveBuildCache did not pin GOCACHE: %v", preserved)
	}
	for _, env := range [][]string{{"GOCACHE=a", "GOCACHE=b"}, {"malformed"}} {
		if _, err := GoBuildCache(t.Context(), env); err == nil {
			t.Fatalf("GoBuildCache(%v) succeeded on invalid env", env)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := GoBuildCache(ctx, []string{"GOCACHE=", "GOENV=off"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("GoBuildCache(canceled) = %v, want context.Canceled", err)
	}
}

// Two snapshots of one environment render the same identity even though
// the raw go env output differs per invocation (GOGCCFLAGS embeds a
// temporary path), and the identity carries the settings that select
// source.
func TestEnvSnapshotIdentityIsStableAcrossTakes(t *testing.T) {
	base := os.Environ()[:0:0]
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GOENV" && key != "GOFLAGS" {
			base = append(base, entry)
		}
	}
	env := append(append([]string(nil), base...), "GOENV=off", "GOFLAGS=")
	dir := t.TempDir()
	first, err := (Runner{}).TakeEnvSnapshot(context.Background(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	second, err := (Runner{}).TakeEnvSnapshot(context.Background(), dir, env)
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity() != second.Identity() {
		t.Fatalf("identity moved between two takes:\n%s\n---\n%s", first.Identity(), second.Identity())
	}
	for _, key := range []string{"GOVERSION=", "GOROOT=", "GOOS=", "GOARCH=", "GOFLAGS=", "GOWORK="} {
		if !strings.Contains(first.Identity(), "\n"+key) && !strings.HasPrefix(first.Identity(), key) {
			t.Fatalf("identity lacks %s:\n%s", key, first.Identity())
		}
	}
	if strings.Contains(first.Identity(), "GOGCCFLAGS=") {
		t.Fatal("identity carries GOGCCFLAGS")
	}
	if (*EnvSnapshot)(nil).Identity() != "" {
		t.Fatal("nil snapshot has an identity")
	}
	tagged, err := (Runner{}).TakeEnvSnapshot(context.Background(), dir, append(append([]string(nil), base...), "GOENV=off", "GOFLAGS=-tags=x"))
	if err != nil {
		t.Fatal(err)
	}
	if tagged.Identity() == first.Identity() {
		t.Fatal("a changed GOFLAGS rendered the same identity")
	}
}

// One version grammar, gofresh's own, exported: a GOVERSION value — stock,
// flavored, experiment-suffixed, release-candidate, platform-suffixed,
// or the current development-build spelling — answers the canonical
// series, its pair, and its release tags; the legacy "devel …"
// spelling, a `go version` line, and what go/version's grammar
// refuses answer nothing, the tags nil, never empty
// (REQ-fresh-toolchain-skew).
func TestVersionGrammarIsOneAcrossTheForms(t *testing.T) {
	for _, c := range []struct {
		in     string
		series string
		major  int
		minor  int
		ok     bool
		tags   int
	}{
		{"go1.27.0", "go1.27", 1, 27, true, 27},
		{"go1.27", "go1.27", 1, 27, true, 27},
		{"go1.27.1\n", "go1.27", 1, 27, true, 27},
		{"go1.27.0-dst.10", "go1.27", 1, 27, true, 27},
		{"go1.26.5-X:nodwarf5", "go1.26", 1, 26, true, 26},
		{"go1.27rc1", "go1.27", 1, 27, true, 27},
		{"go1.27.0 linux/amd64", "go1.27", 1, 27, true, 27},
		{"go1.27.0 linux/amd64 x", "go1.27", 1, 27, true, 27}, // the FIRST space cuts
		{"go1.10.4", "go1.10", 1, 10, true, 10},               // never confused with go1.1
		{"go1.27garbage", "go1.27", 1, 27, true, 27},
		{"go1.28-devel_abc123 Wed Aug 20 10:00:00 2026 +0000", "go1.28", 1, 28, true, 28}, // a devel build spelled version-first
		{"go1.0", "go1", 1, 0, true, 0},                                                   // the canonical grammar's spelling of the go1.0 language
		{"go2.0.1", "go2.0", 2, 0, true, 0},
		{"go2.1.0", "go2.1", 2, 1, true, 0},                                        // no release tags outside major 1
		{"go0.5", "go0.5", 0, 5, true, 0},                                          // a major-0 series exists under Lang; no ladder outside major 1
		{"go0", "go0.0", 0, 0, true, 0},                                            // Lang spells go0 with its minor, unlike go1
		{"go1.99999999999999999999.0", "go1.99999999999999999999", 0, 0, false, 0}, // Lang bounds the digits' form, not their length: an overflow is no pair
		{"go99999999999999999999.1", "go99999999999999999999.1", 0, 0, false, 0},
		{"go1.4096", "go1.4096", 1, 4096, true, 4096}, // the ladder's bound, inclusive
		{"go1.4097", "go1.4097", 1, 4097, true, 0},    // past it, no ladder
		{"", "", 0, 0, false, 0},
		{"go", "", 0, 0, false, 0},
		{"gox.y", "", 0, 0, false, 0},
		{"1.27", "", 0, 0, false, 0},
		{"go1.27.0.0-x", "", 0, 0, false, 0},
		{"garbage-go1.27.0", "", 0, 0, false, 0},
		{"devel go1.28-abc1234 Thu Sep 30 00:00:00 2026 +0000", "", 0, 0, false, 0},
		{"go version go1.27.1 linux/amd64", "", 0, 0, false, 0},
	} {
		if got := LanguageSeries(c.in); got != c.series {
			t.Errorf("LanguageSeries(%q) = %q, want %q", c.in, got, c.series)
		}
		major, minor, ok := ParseGoVersion(c.in)
		if ok != c.ok || major != c.major || minor != c.minor {
			t.Errorf("ParseGoVersion(%q) = %d, %d, %v; want %d, %d, %v", c.in, major, minor, ok, c.major, c.minor, c.ok)
		}
		tags := ReleaseTags(c.in)
		if len(tags) != c.tags {
			t.Errorf("ReleaseTags(%q) = %d tags, want %d", c.in, len(tags), c.tags)
		}
		if c.tags == 0 && tags != nil {
			t.Errorf("ReleaseTags(%q) = %#v, want nil (a caller branches on nil)", c.in, tags)
		}
		if c.tags > 0 && (tags[0] != "go1.1" || tags[len(tags)-1] != c.series) {
			t.Errorf("ReleaseTags(%q) = %v … %v, want go1.1 … %s", c.in, tags[0], tags[len(tags)-1], c.series)
		}
	}
	// The running toolchain's own version parses to the series the
	// canonical parser gives it.
	if got, want := LanguageSeries(runtime.Version()), version.Lang(runtime.Version()); got != want {
		t.Fatalf("the running toolchain's series %q, go/version says %q", got, want)
	}
	if !reflect.DeepEqual(ReleaseTags("go1.3"), []string{"go1.1", "go1.2", "go1.3"}) {
		t.Fatalf("ReleaseTags(go1.3) = %v", ReleaseTags("go1.3"))
	}
}

func TestNormalizeEnvStripsTraceVarsAndValidatesDuplicates(t *testing.T) {
	base, err := NormalizeEnv([]string{"PATH=/bin", "HOME=/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	withTrace, err := NormalizeEnv([]string{"PATH=/bin", "GOFRESH_TRACE=all", "GOFRESH_TRACE_FILE=/tmp/trace.jsonl", "HOME=/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(base, withTrace) {
		t.Fatalf("NormalizeEnv with trace vars = %v, want %v", withTrace, base)
	}
	setTrace := SetEnv(base, "GOFRESH_TRACE", "toolchain")
	if !reflect.DeepEqual(setTrace, base) {
		t.Fatalf("SetEnv(GOFRESH_TRACE) = %v, want %v", setTrace, base)
	}
	if _, err := NormalizeEnv([]string{"GOFRESH_TRACE=all", "GOFRESH_TRACE=view"}); err == nil {
		t.Fatal("duplicate GOFRESH_TRACE should still be refused")
	}
	if _, err := NormalizeEnv([]string{"GOFRESH_TRACE=all\x00bad"}); err == nil {
		t.Fatal("NUL in GOFRESH_TRACE should still be refused")
	}
}
