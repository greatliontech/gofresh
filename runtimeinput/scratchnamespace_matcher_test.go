package runtimeinput

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"testing/quick"
)

// Absolute identities use the host's volume and separators; slash-rooted
// spellings alone are not absolute identities on Windows.
func scratchMatcherHostRoot(t testing.TB) string {
	t.Helper()
	abs, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	return filepath.VolumeName(abs) + string(filepath.Separator)
}

func TestScratchNamespaceMatchesPath(t *testing.T) {
	root := scratchMatcherHostRoot(t)
	for _, tc := range []struct {
		dir, pattern, identity string
		want                   bool
	}{
		{".", "*", filepath.Join(root, "outside"), false},
		{".", "*", root, false},
		{".", "*", ".", true}, // Native conservative match; never absence evidence.
		{".", "*", "inside/deep", true},
		{".", "bench-*", "bench-9/deep", true},
		{".", "bench-*", "pkg/bench-9", false},
		{"pkg", "bench-*", "pkg", false},
		{"pkg", "bench-*", "pkg/bench-", true},
		{"pkg", "bench-*", "pkg/bench-9/deep/file", true},
		{"pkg", "bench-*", "pkg/other/bench-9", false},
		{"pkg", "bench-*", "pkg2/bench-9", false},
		{"pkg", "scratch", "pkg/scratch", true},
		{"pkg", "scratch", "pkg/scratch123", true},
		{"pkg", "scratch", "pkg/scratc", false},
		{"pkg", "pre*post", "pkg/prepost", true},
		{"pkg", "pre*post", "pkg/pre9post/deep", true},
		{"pkg", "pre*post", "pkg/pre9", false},
		{"pkg", "aba*aba", "pkg/aba", false},
		{"pkg", "aba*aba", "pkg/ababa", false},
		{"pkg", "aba*aba", "pkg/abaaba", true},
		{"pkg", "a*b*c", "pkg/a*b9c", true},
		{"pkg", "a*b*c", "pkg/a9b*c", false},
		{"./other/../pkg//", "pre*post", "pkg/pre9post", true},
	} {
		t.Run(tc.dir+":"+tc.pattern+":"+tc.identity, func(t *testing.T) {
			got, err := (ScratchNamespace{Dir: tc.dir, Pattern: tc.pattern}).MatchesPath(tc.identity)
			if err != nil || got != tc.want {
				t.Fatalf("MatchesPath(%q) = %t, %v; want %t", tc.identity, got, err, tc.want)
			}
		})
	}
}

// Constructed witnesses give the public/native agreement property independent
// positive and negative controls, so a shared always-false matcher cannot pass.
func TestScratchNamespaceMatchesPathAgreement(t *testing.T) {
	root := scratchMatcherHostRoot(t)
	property := func(dirChoice uint8, literalStar, noStar bool, prefixID, suffixID uint32, token uint64) bool {
		dirs := []string{".", "pkg", "pkg/sub", "./pkg//", "other/../pkg"}
		dir := dirs[int(dirChoice)%len(dirs)]
		prefix := fmt.Sprintf("p%x", prefixID)
		if literalStar {
			prefix += "*"
		}
		suffix := ""
		if suffixID%2 != 0 {
			suffix = fmt.Sprintf("s%x", suffixID)
		}
		pattern := prefix + "*" + suffix
		if noStar {
			prefix, suffix = "scratch", ""
			pattern = prefix
		}
		minted := prefix + fmt.Sprint(token) + suffix
		n := ScratchNamespace{Dir: dir, Pattern: pattern}
		var cfg testLogConfig
		WithScratchNamespace(dir, pattern)(&cfg)
		if cfg.err != nil {
			t.Error(cfg.err)
			return false
		}
		positive := path.Join(dir, minted)
		for _, tc := range []struct {
			id   pathID
			want bool
		}{
			{pathID{Kind: pathRel, Path: positive}, true},
			{pathID{Kind: pathRel, Path: positive + "/deep/file"}, true},
			{pathID{Kind: pathRel, Path: path.Join(dir, "!"+minted)}, false},
			{pathID{Kind: pathAbs, Path: filepath.Join(root, filepath.FromSlash(positive))}, false},
		} {
			got, err := n.MatchesPath(tc.id.Path)
			native := cfg.scratchNamespaces[0].matches(tc.id)
			if err != nil || got != native || got != tc.want {
				t.Errorf("%+v MatchesPath(%+v) = %t, %v; native %t, want %t", n, tc.id, got, err, native, tc.want)
				return false
			}
		}
		return true
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 1000}); err != nil {
		t.Fatal(err)
	}
}

func TestScratchNamespaceMatchesPathMkdirTemp(t *testing.T) {
	root := t.TempDir()
	patterns := []string{"scratch", "pre*post", "aba*aba", "*"}
	// Windows filenames cannot contain the earlier, literal star. Pure
	// matching of this pattern remains covered on every host above.
	if runtime.GOOS != "windows" {
		patterns = append(patterns, "a*b*c")
	}
	for _, pattern := range patterns {
		minted, err := os.MkdirTemp(root, pattern)
		if err != nil {
			t.Fatal(err)
		}
		n := ScratchNamespace{Dir: "pkg", Pattern: pattern}
		for _, identity := range []string{"pkg/" + filepath.Base(minted), "pkg/" + filepath.Base(minted) + "/deep/file"} {
			if got, err := n.MatchesPath(identity); err != nil || !got {
				t.Fatalf("MkdirTemp(%q) identity %q: match %t, %v", pattern, identity, got, err)
			}
		}
	}
}

func TestScratchNamespaceMatchesPathRejectsMalformed(t *testing.T) {
	root := scratchMatcherHostRoot(t)
	for _, n := range []ScratchNamespace{
		{}, {Dir: "", Pattern: "*"}, {Dir: filepath.Join(root, "abs"), Pattern: "*"},
		{Dir: "../up", Pattern: "*"}, {Dir: "pkg/../../up", Pattern: "*"},
		{Dir: "pkg\x00", Pattern: "*"}, {Dir: "pkg\r", Pattern: "*"},
		{Dir: "pkg\n", Pattern: "*"}, {Dir: "pkg\xff", Pattern: "*"},
		{Dir: ".", Pattern: ""}, {Dir: ".", Pattern: "a/b"}, {Dir: ".", Pattern: `a\b`},
		{Dir: ".", Pattern: "a\x00"}, {Dir: ".", Pattern: "a\r"},
		{Dir: ".", Pattern: "a\n"}, {Dir: ".", Pattern: "a\xff"},
	} {
		var cfg testLogConfig
		WithScratchNamespace(n.Dir, n.Pattern)(&cfg)
		validated := ValidateScratchNamespace(n.Dir, n.Pattern)
		got, err := n.MatchesPath("child")
		if got || err == nil || cfg.err == nil || validated == nil || err.Error() != cfg.err.Error() || err.Error() != validated.Error() {
			t.Fatalf("%+v: match %t, %v; option %v, validator %v", n, got, err, cfg.err, validated)
		}
	}
	sep := string(filepath.Separator)
	// Concatenation deliberately preserves the malformed absolute spelling;
	// filepath.Join would clean the very components this assertion rejects.
	abs := filepath.Join(root, "outside")
	for _, identity := range []string{"", "..", "../outside", "pkg/../../outside", "./pkg", "pkg/.", "pkg/../child", "pkg//child", "pkg/", abs + sep + ".." + sep + "child", abs + sep + sep + "child", abs + sep, "bad\x00", "bad\r", "bad\n", "bad\xff"} {
		got, err := (ScratchNamespace{Dir: ".", Pattern: "*"}).MatchesPath(identity)
		if got || err == nil {
			t.Fatalf("malformed identity %q: match %t, %v", identity, got, err)
		}
	}
}

// The classification-root hook must remain untouched, and matching must work
// identically with existing, absent and symlinked physical names. Only ingest
// may consult those objects to establish admission.
func TestScratchNamespaceMatchesPathDoesNotResolve(t *testing.T) {
	prior := producerTestHooks.beforeRoots
	producerTestHooks.beforeRoots = func() { t.Fatal("pure matching reached classification-root resolution") }
	t.Cleanup(func() { producerTestHooks.beforeRoots = prior })
	root := t.TempDir()
	t.Chdir(root)
	n := ScratchNamespace{Dir: ".", Pattern: "scratch-*"}
	check := func(t *testing.T) {
		t.Helper()
		if got, err := n.MatchesPath("scratch-child/deep"); err != nil || !got {
			t.Fatalf("syntactic match depends on physical state: %t, %v", got, err)
		}
		if got, err := n.MatchesPath(filepath.Join(root, "scratch-child", "deep")); err != nil || got {
			t.Fatalf("absolute path acquired a relative identity: %t, %v", got, err)
		}
	}
	check(t)
	if err := os.Mkdir("scratch-child", 0o700); err != nil {
		t.Fatal(err)
	}
	check(t)
	if err := os.Remove("scratch-child"); err != nil {
		t.Fatal(err)
	}
	t.Run("symlink", func(t *testing.T) {
		if err := os.Symlink(filepath.Join(root, "absent"), "scratch-child"); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		check(t)
	})
}

// Arbitrary declarations and identity bytes exercise the same rejection
// grammar as ingest and the manifest; valid inputs agree with native matching.
func FuzzScratchNamespaceMatchesPath(f *testing.F) {
	root := scratchMatcherHostRoot(f)
	for _, seed := range [][3]string{
		{".", "*", filepath.Join(root, "outside")}, {".", "*", "."}, {"pkg", "a*b*c", "pkg/a*b9c/deep"},
		{"pkg", "aba*aba", "pkg/ababa"}, {"./pkg//", "scratch", "pkg/scratch9"},
		{"..", "*", "child"}, {".", "*", "../outside"}, {".", "*", "bad\xff"},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, dir, pattern, identity string) {
		n := ScratchNamespace{Dir: dir, Pattern: pattern}
		got, err := n.MatchesPath(identity)
		var cfg testLogConfig
		WithScratchNamespace(dir, pattern)(&cfg)
		wantErr := cfg.err
		id := pathID{Kind: pathRel, Path: identity}
		if filepath.IsAbs(identity) {
			id.Kind = pathAbs
		}
		if wantErr == nil {
			wantErr = validateManifest(manifest{Version: manifestVersion, Paths: []pathInput{{pathID: id, Digest: "00000000000000000000000000000000"}}})
		}
		if wantErr != nil {
			if got || err == nil || err.Error() != wantErr.Error() {
				t.Fatalf("match %t, %v; want false, %v", got, err, wantErr)
			}
			return
		}
		want := cfg.scratchNamespaces[0].matches(id)
		if err != nil || got != want {
			t.Fatalf("match %t, %v; native %t", got, err, want)
		}
	})
}
