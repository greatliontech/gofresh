package gofresh

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The repository's reviewed vouch file is one of the two channels of
// the one vouch set: a file naming the culprit discharges it with no
// option given, the option extends the file's set and never removes
// from it, a consumer owning its own reviewed set declines the file,
// and the recorded discharge is the union's load-bearing part
// (REQ-vouch-input, REQ-vouch-recorded).
func TestRepositoryVouchFileJoinsTheVouchSet(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	viewTestHooks.scanMemoOff = true
	t.Cleanup(func() { viewTestHooks.scanMemoOff = false })
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := writePinnedDepModule(t)
	const ghost = "golang.org/x/sync/errgroup.Ghost"
	const shade = "golang.org/x/sync/errgroup.Shade"
	subject := Subject{Package: "example.com/pinned", Symbol: "Run"}
	processFactCache = sync.Map{}
	ctx := context.Background()

	warm, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := warm.NewView(ctx, []Subject{subject}, dir); err != nil {
		t.Fatal(err)
	}
	var hit bool
	processFactCache.Range(func(k, v any) bool {
		if strings.HasSuffix(k.(string), "\x00golang.org/x/sync/errgroup") {
			fact := v.(dynamicStateFact)
			fact.Declares = append(fact.Declares, ghost, shade)
			fact.Mutates = append(fact.Mutates, ghost, shade)
			processFactCache.Store(k, fact)
			hit = true
		}
		return true
	})
	if !hit {
		t.Fatal("no errgroup fact in the process cache")
	}
	// judge returns the subject's recorded discharges and its reason: the
	// fixture subject stays unverifiable for an unrelated reason, so the
	// vouch's effect is read from the culprit's absence and the record.
	judge := func(opts ...Option) (string, string) {
		t.Helper()
		e, err := New(append([]Option{WithDir(dir)}, opts...)...)
		if err != nil {
			t.Fatal(err)
		}
		view, err := e.NewView(ctx, []Subject{subject}, dir)
		if err != nil {
			t.Fatal(err)
		}
		fp, err := view.Capture(ctx, subject)
		if err != nil {
			t.Fatal(err)
		}
		v, err := view.Check(ctx, fp, subject)
		if err != nil {
			t.Fatal(err)
		}
		return fp.DynamicStateVouches, v.Reason
	}
	both := ghost + "," + shade
	vouchPath := filepath.Join(dir, RepositoryVouchFile)

	// No file: the two culprits downgrade and nothing is recorded.
	if rec, reason := judge(); rec != "" || !strings.Contains(reason, ghost) {
		t.Fatalf("no file: record %q, reason %q; want the culprit named and no discharge", rec, reason)
	}
	// The file names both, with comments and blank lines around them.
	if err := os.WriteFile(vouchPath, []byte("# reviewed 2026-09\n\ngolang.org/x/sync/errgroup:Ghost\n  golang.org/x/sync/errgroup:Shade  \n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec, reason := judge(); rec != both || strings.Contains(reason, "shares mutated dynamic state") {
		t.Fatalf("file naming the culprits: record %q, reason %q; want both discharged with no option given", rec, reason)
	}
	// The file names one; the option extends the set with the other.
	if err := os.WriteFile(vouchPath, []byte("golang.org/x/sync/errgroup:Ghost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec, reason := judge(); rec != ghost || !strings.Contains(reason, shade) {
		t.Fatalf("file naming one culprit: record %q, reason %q; want the other's downgrade", rec, reason)
	}
	if rec, reason := judge(WithDynamicStateVouches(shade)); rec != both || strings.Contains(reason, "shares mutated dynamic state") {
		t.Fatalf("file ∪ option: record %q, reason %q; want both discharged", rec, reason)
	}
	// An option never removes: the file's vouch stands beside an inert one.
	if rec, _ := judge(WithDynamicStateVouches("golang.org/x/sync/errgroup.Other", shade)); rec != both {
		t.Fatalf("file ∪ inert option: record %q, want the file's vouch still honored", rec)
	}
	// Declining the file leaves the downgrade to the option alone.
	if rec, reason := judge(WithoutRepositoryVouches(), WithDynamicStateVouches(shade)); rec != shade || !strings.Contains(reason, ghost) {
		t.Fatalf("declined file: record %q, reason %q; want %s's downgrade back", rec, reason, ghost)
	}
	// A malformed line refuses the engine naming the file and line.
	if err := os.WriteFile(vouchPath, []byte("# ok\ngolang.org/x/sync/errgroup:Ghost\ngolang.org/x/sync/errgroup.Shade\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(WithDir(dir)); err == nil || !strings.Contains(err.Error(), "vouches:3") || !strings.Contains(err.Error(), "not IMPORT-PATH:VARIABLE") {
		t.Fatalf("malformed file: %v, want a refusal naming the file and line", err)
	}
	if _, err := New(WithDir(dir), WithoutRepositoryVouches()); err != nil {
		t.Fatalf("declined malformed file: %v, want no read at all", err)
	}
	// A file that cannot be read whole refuses with nothing honored: a
	// directory at the path, and a line past the scanner's token size
	// after lines already read.
	if err := os.Remove(vouchPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(vouchPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(WithDir(dir)); err == nil || !strings.Contains(err.Error(), "vouch file") {
		t.Fatalf("directory at the vouch path: %v, want a refusal", err)
	}
	if err := os.Remove(vouchPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vouchPath, []byte("golang.org/x/sync/errgroup:Ghost\n#"+strings.Repeat("x", 70000)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(WithDir(dir)); err == nil || !strings.Contains(err.Error(), "vouch file") || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("oversized line after a good one: %v, want the whole file refused", err)
	}
	// The unreadable-file arm needs a caller the mode denies: root (and
	// the -1 a non-Unix host reports) reads a mode-000 file, so the arm
	// runs only for an ordinary Unix user.
	if uid := os.Getuid(); uid > 0 {
		if err := os.WriteFile(vouchPath, []byte("golang.org/x/sync/errgroup:Ghost\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(vouchPath, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(vouchPath, 0o644) })
		if _, err := New(WithDir(dir)); err == nil || !strings.Contains(err.Error(), "vouch file") {
			t.Fatalf("unreadable file: %v, want a refusal, never the empty set", err)
		}
	}
}

// One entry is IMPORT-PATH:VARIABLE mapped to the dotted identity; a
// missing colon, an empty half, a space in the path, or a variable that
// is not one Go identifier refuses (REQ-vouch-input).
func TestParseVouchEntryGrammar(t *testing.T) {
	if got, err := ParseVouchEntry("golang.org/x/sync/errgroup:Ghost"); err != nil || got != "golang.org/x/sync/errgroup.Ghost" {
		t.Fatalf("entry = %q, %v", got, err)
	}
	if got, err := ParseVouchEntry("a.example/dep/v2:_x9"); err != nil || got != "a.example/dep/v2._x9" {
		t.Fatalf("entry = %q, %v", got, err)
	}
	for _, bad := range []string{"", "nocolon", ":Var", "pkg:", "a b/dep:Var", "a\tb/dep:Var", "a\x7fb/dep:Var", "a\u0085b/dep:Var", "pkg:9x", "pkg:Var.Field", "pkg:Var:More"} {
		if _, err := ParseVouchEntry(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	// A file's entries are sorted and deduplicated, lines trimmed.
	path := filepath.Join(t.TempDir(), RepositoryVouchFile)
	if err := os.WriteFile(path, []byte("b.example/dep:Var\n# c\n\na.example/dep:Var\nb.example/dep:Var\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadVouchFile(path)
	if err != nil || strings.Join(got, ",") != "a.example/dep.Var,b.example/dep.Var" {
		t.Fatalf("file = %v, %v", got, err)
	}
	if got, err := ReadVouchFile(filepath.Join(t.TempDir(), RepositoryVouchFile)); err != nil || got != nil {
		t.Fatalf("absent file = %v, %v, want the empty set", got, err)
	}
}
