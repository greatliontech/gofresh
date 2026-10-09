package closure

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure/internal/cachefile"
	"github.com/greatliontech/gofresh/gotool"
)

// TestDstSelectionIsJudgedByContentNeverByTag pins the content key over
// the godst fork's `dst` selection (REQ-closure-observability-toolchain-key):
// on a stock toolchain the tag selects no different standard-library
// file, so the selection moves no key and is admitted by the same chain
// that admits the selection without the tag — the default row for the
// plain form, the race row under the detector — with nothing to list;
// on a repaired godst build the selection admits through its own measured
// content chain. Earlier builds remain refused: their in-bubble test-log
// writer discarded host errors, violating the harness premise. The minimum
// canary build never grants admission without matching source content.
// The host's own build decides which arm the pin exercises; the other
// is logged.
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
		// The canary's premise (TestAuditedToolchainCoversRunningToolchain):
		// a skip here would hide every admission fault behind it.
		t.Fatalf("the running toolchain is unlisted under its default selection: %s", base.SelectionNotice())
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
			moved, _ := movedKeys(h.source, auditedToolchainSources)
			if (listedSelection{Since: "go1.27.2-dst.15"}).demandedOf(snapshot.Value("GOVERSION")) {
				if !h.SelectionAudited() || len(moved) != 0 {
					t.Fatalf("repaired godst selection %q refused: %v; %s", sel.suffix, moved, h.SelectionNotice())
				}
				continue
			}
			// A godst build: the hook files move keys; no chain lists
			// them while the fork's harness premise fails. The refusal
			// names the moved keys under its bound, and testing — the
			// premise's own key — sorts past it under the race
			// detector, so its membership is read from the moved set.
			if h.SelectionAudited() || !strings.Contains(h.SelectionAttribution(), "moved in") || !slices.Contains(moved, "testing") {
				t.Fatalf("the %q selection on a godst build: audited=%v, moved %v, attribution %q, want a refusal with testing among the moved keys — the harness premise's key did not move: re-walk where the fork's test-log writer lives", sel.suffix, h.SelectionAudited(), moved, h.SelectionAttribution())
			}
			t.Logf("godst build: the %q selection refuses — %s", sel.suffix, h.SelectionAttribution())
			continue
		}
		// A stock toolchain: the tag moves nothing, so the same
		// selection without it is admitted by the same chain.
		if !h.SelectionAudited() {
			t.Fatalf("the %q selection on a stock toolchain refused: %s", sel.suffix, h.SelectionNotice())
		}
		moved, closest := movedKeys(h.source, auditedToolchainSources)
		plain, err := newAtEnv(ctx, ".", environmentWith(), sel.without...)
		if err != nil {
			t.Fatal(err)
		}
		_, want := movedKeys(plain.source, auditedToolchainSources)
		if len(moved) != 0 || closest != want {
			t.Fatalf("the %q selection on a stock toolchain moved %v, admitted by %q, want nothing moved and %q, the selection's own chain without the tag", sel.suffix, moved, closest, want)
		}
		t.Logf("stock toolchain: the %q selection moves no key and admits by %q", sel.suffix, want)
	}
}

func TestGodstCanaryRequirementDoesNotGrantAdmission(t *testing.T) {
	selection := listedSelection{Since: "go1.27.2-dst.15"}
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"go1.27.1-dst.13", false},
		{"go1.27.1-dst.14", false},
		{"go1.27.2-dst.15", true},
		{"go1.28.0-dst.16", true},
		{"go1.27.2", true},
		{"not-go-dst.1", true},
		{"go1.27.2-dst.bad", true},
		{"go1.27.2-dst.999999999999999999999", true},
	} {
		if got := selection.demandedOf(tc.version); got != tc.want {
			t.Errorf("demandedOf(%q)=%v, want %v", tc.version, got, tc.want)
		}
		if !(listedSelection{}).demandedOf(tc.version) {
			t.Errorf("ordinary selection not demanded of %q", tc.version)
		}
	}
	if !(listedSelection{Since: "invalid"}).demandedOf("go1.27.1-dst.13") {
		t.Fatal("malformed canary boundary silently skipped a selection")
	}
	for _, version := range []string{"go1.27.1-dst.13", "go1.27.2-dst.15", "go1.28.0-dst.99"} {
		d := sourceDigests{Packages: map[string]string{"testing": "unlisted-content"}}
		if toolchainSourceDegradation(version, d, nil).audited() {
			t.Fatalf("version %q admitted unlisted harness content", version)
		}
	}
}

func canarySelection(ctx context.Context, h *Hasher, sel listedSelection) (string, bool, error) {
	snapshot, err := h.PassReader().Snapshot(ctx)
	if err != nil {
		return "", false, err
	}
	version := snapshot.Value("GOVERSION")
	return version, sel.demandedOf(version), nil
}

// The inspected compiler need not be the one that built the test binary.
func TestCanaryUsesTheInspectedToolchainVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell snapshot fixture")
	}
	for _, tc := range []struct {
		version  string
		demanded bool
	}{{"go1.27.1-dst.13", false}, {"go1.27.2-dst.15", true}} {
		h := &Hasher{env: os.Environ(), runner: gotool.Runner{Prepare: func(cmd *exec.Cmd) {
			cmd.Path = "/bin/sh"
			cmd.Args = []string{"sh", "-c", `printf '%s' '{"GOVERSION":"` + tc.version + `"}'`}
		}}}
		version, demanded, err := canarySelection(t.Context(), h, listedSelection{Since: "go1.27.2-dst.15"})
		if err != nil || version != tc.version || demanded != tc.demanded {
			t.Fatalf("inspect %s: version=%q demanded=%v err=%v", tc.version, version, demanded, err)
		}
	}
}

// TestListingInstructionNamesTheHarnessPremise pins the listing
// procedure the canary prints (REQ-closure-observability-toolchain-key):
// the walk of the moved keys' delta against every admission, and the
// harness's write-propagation premise exactly when a harness premise
// package — testing, or testing/internal/testdeps, where the buffered
// writes and StopTestLog's flush error live — is among the moved keys;
// and both packages are seeds of the audited surface, so a build moving
// either moves a key.
func TestListingInstructionNamesTheHarnessPremise(t *testing.T) {
	for _, p := range []string{"testing", "testing/internal/testdeps"} {
		if !slices.Contains(auditedSurfaceTables(), p) || !slices.Contains(harnessPremisePackages, p) {
			t.Errorf("the harness premise package %s is not a surface seed naming the premise", p)
		}
	}
	const walk = "Walk the moved keys' delta against the audited admissions"
	const premise = "the harness's write-propagation premise the listing asserts (every test-log write the harness attempts lands or fails the binary)"
	const tail = ", then list this row in closure/toolchainaudit.go:"
	for _, tc := range []struct {
		moved   []string
		premise bool
	}{
		{nil, false},
		{[]string{"net", "time"}, false},
		{[]string{"testing"}, true},
		{[]string{"net", "os", "testing", "time"}, true},
		{[]string{"testing/internal/testdeps"}, true},
		{[]string{"testing/fstest"}, false},
	} {
		got := listingInstruction(tc.moved)
		if !strings.HasPrefix(got, walk) || !strings.HasSuffix(got, tail) || strings.Contains(got, premise) != tc.premise {
			t.Errorf("listingInstruction(%v) = %q, want the walk, the premise=%v, the listing tail", tc.moved, got, tc.premise)
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
