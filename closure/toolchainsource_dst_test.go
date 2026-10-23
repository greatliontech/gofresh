package closure

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/gotool"
)

// TestDstSelectionIsJudgedByContentNeverByTag pins the structural content
// verification over the godst fork's `dst` selection
// (REQ-closure-observability-toolchain-key): on a stock toolchain the tag
// selects no different standard-library file and admits with the same content
// digest as the plain selection; on a repaired godst build (where
// dstHostStreamWrite returns write errors to StopTestLog) the selection admits
// through structural AST verification; on an older godst build whose in-bubble
// test-log writer discarded host write errors, structural verification of
// package testing refuses.
func TestDstSelectionIsJudgedByContentNeverByTag(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx := context.Background()
	base, err := newAtEnv(ctx, ".", environmentWith())
	if err != nil {
		t.Fatal(err)
	}
	if !base.SelectionAudited() {
		t.Fatalf("the running toolchain failed structural verification under its default selection: %s", base.SelectionNotice())
	}
	snapshot, err := base.PassReader().Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, godst := os.Stat(filepath.Join(snapshot.Value("GOROOT"), "src", "time", "dst_tz.go"))
	for _, sel := range []struct {
		suffix  string
		flags   []string
		without []string // the same selection without the dst tag
	}{
		{" dst", []string{"-tags", "dst"}, nil},
		{" dst race", []string{"-tags", "dst", "-race"}, []string{"-race"}},
	} {
		h, err := newAtEnv(ctx, ".", environmentWith(), sel.flags...)
		if err != nil {
			t.Fatal(err)
		}
		if godst == nil {
			failed := verifyToolchainSurface(h.source)
			dstHostIO, readErr := os.ReadFile(filepath.Join(snapshot.Value("GOROOT"), "src", "testing", "dst_hostio.go"))
			repaired := readErr == nil && strings.Contains(string(dstHostIO), "dstHostStreamWrite(fd int, header, payload []byte) (")
			if repaired {
				if !h.SelectionAudited() || len(failed) != 0 {
					t.Fatalf("repaired godst selection %q refused: %v; %s", sel.suffix, failed, h.SelectionNotice())
				}
				continue
			}
			if h.SelectionAudited() || !strings.Contains(h.SelectionAttribution(), "moved in") || !slices.Contains(failed, "testing") {
				t.Fatalf("the %q selection on an unrepaired godst build: audited=%v, failed %v, attribution %q, want a refusal with testing among the failed keys", sel.suffix, h.SelectionAudited(), failed, h.SelectionAttribution())
			}
			t.Logf("godst build: the %q selection refuses — %s", sel.suffix, h.SelectionAttribution())
			continue
		}
		// A stock toolchain: the tag selects no different file, so the same
		// selection without it has the same content and passes verification.
		if !h.SelectionAudited() {
			t.Fatalf("the %q selection on a stock toolchain refused: %s", sel.suffix, h.SelectionNotice())
		}
		plain, err := newAtEnv(ctx, ".", environmentWith(), sel.without...)
		if err != nil {
			t.Fatal(err)
		}
		if h.source.Content != plain.source.Content {
			t.Fatalf("the %q selection on a stock toolchain changed Content %q vs %q", sel.suffix, h.source.Content, plain.source.Content)
		}
	}
}

func TestHarnessPremisePackagesAreSurfaceSeedsAndVerified(t *testing.T) {
	for _, p := range []string{"testing", "testing/internal/testdeps"} {
		if !slices.Contains(auditedSurfaceTables(), p) || !slices.Contains(harnessPremisePackages, p) {
			t.Errorf("the harness premise package %s is not a surface seed", p)
		}
	}
	for _, version := range []string{"go1.27.1-dst.13", "go1.27.2-dst.15", "go1.28.0-dst.99"} {
		d := sourceDigests{Packages: map[string]string{"testing": "unlisted-content"}}
		if toolchainSourceDegradation(version, d, nil).audited() {
			t.Fatalf("version %q admitted unverified harness content", version)
		}
	}
}

// TestListingScopeFollowsTheSurfaceRule pins the listing memo's scope
// against the surface rule (REQ-closure-observability-toolchain-key's
// listing memo): the scope carries the surface seeds' digest, so two
// seed lists — the rule before and after a seed joins — make two scopes
// and a warm record of the old surface is never served to the new
// rule; the same list makes the same scope.
func TestListingScopeFollowsTheSurfaceRule(t *testing.T) {
	snapshot, err := (gotool.Runner{}).TakeEnvSnapshot(context.Background(), ".", os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	before := []string{"runtime", "sync/atomic", "testing"}
	after := []string{"runtime", "sync/atomic", "testing", "testing/internal/testdeps"}
	if a, b := toolchainSourceScope(snapshot, nil, before), toolchainSourceScope(snapshot, nil, after); a == b {
		t.Fatalf("a seed joining the surface kept the listing scope %q", a)
	}
	if a, b := toolchainSourceScope(snapshot, nil, after), toolchainSourceScope(snapshot, nil, slices.Clone(after)); a != b {
		t.Fatalf("the same seeds made two scopes: %q vs %q", a, b)
	}
	if a, b := toolchainSourceScope(snapshot, nil, surfaceSeeds()), toolchainSourceScope(snapshot, nil, before); a == b {
		t.Fatalf("the live seeds scope as a three-seed rule: %q", a)
	}
}

// TestListingMemoRecordLandsUnderTheLiveSeedsScope pins the memo's
// wiring (REQ-closure-observability-toolchain-key's listing memo): a
// listing is stored under the scope the live surface seeds make and
// under no other seed list's, so a record of another surface rule is
// never the one a construction finds.
func TestListingMemoRecordLandsUnderTheLiveSeedsScope(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the standard library")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	ctx := context.Background()
	dir := t.TempDir()
	runner := gotool.Runner{}
	snapshot, err := gotool.NewEnvReader(runner, dir, os.Environ()).Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env, err := gotool.NormalizeEnv(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := toolchainSourceDigests(ctx, runner, dir, env, snapshot, nil); err != nil {
		t.Fatal(err)
	}
	live, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, surfaceSeeds()), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("no listing record under the live seeds' scope: %v", err)
	}
	other, err := cachefile.Path(sourceDigestsDirName, toolchainSourceScope(snapshot, nil, []string{"runtime", "sync/atomic", "testing"}), "listing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(other); err == nil {
		t.Fatalf("a listing record under another seed list's scope: %s", other)
	}
}
