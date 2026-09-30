package runtimeinput

import (
	"os"
	"path/filepath"
	"testing"
)

// usableGuardRoot degrades every unusable setting to no root — cost-only
// — and refuses ".." outright: lexical cleaning across a symlink can
// rebind the referent, the one spurious-admission risk this class
// carries.
func TestUsableGuardRoot(t *testing.T) {
	cases := map[string]string{
		"":                  "",
		"off":               "",
		"relative/root":     "",
		"/x/link/../y":      "",
		"/usr/lib/go/":      "/usr/lib/go",
		"/usr/lib//go":      "/usr/lib/go",
		"/usr/lib/./go":     "/usr/lib/go",
		"/home/u/go/pkgmod": "/home/u/go/pkgmod",
	}
	for in, want := range cases {
		if got := usableGuardRoot(in); got != want {
			t.Errorf("usableGuardRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

// A guard root inside, equal to, or containing the tree — in its given
// or resolved form — declares nothing: it would admit the tree's own
// content as guard-covered (REQ-inputs-guard-covered).
func TestUsableGuardRootOutsideTheTree(t *testing.T) {
	for _, tc := range []struct{ root, tree, want string }{
		{"/repo/.modcache", "/repo", ""},
		{"/repo", "/repo", ""},
		{"/", "/repo", ""},
		{"/home/u", "/home/u/repo", ""},
		{"/home/u/go/pkg/mod", "/home/u/repo", "/home/u/go/pkg/mod"},
		{"/repository", "/repo", "/repository"},
	} {
		if got := usableGuardRootOutside(tc.root, tc.tree); got != tc.want {
			t.Errorf("usableGuardRootOutside(%q, %q) = %q, want %q", tc.root, tc.tree, got, tc.want)
		}
	}
	tree := t.TempDir()
	link := filepath.Join(t.TempDir(), "into-tree")
	if err := os.Symlink(tree, link); err != nil {
		t.Fatal(err)
	}
	if got := usableGuardRootOutside(filepath.Join(link, "cache"), tree); got != "" {
		t.Errorf("a root resolving into the tree was kept: %q", got)
	}
	treeLink := filepath.Join(t.TempDir(), "tree-link")
	if err := os.Symlink(tree, treeLink); err != nil {
		t.Fatal(err)
	}
	if got := usableGuardRootOutside(filepath.Join(tree, "cache"), treeLink); got != "" {
		t.Errorf("a root inside the tree's resolved form was kept: %q", got)
	}
}

// usableTempRoot degrades an in-tree temp root in its given and its
// resolved form (REQ-inputs-ephemeral-root).
func TestUsableTempRoot(t *testing.T) {
	if got := usableTempRoot("/a/link/../y", "/repo"); got != "" {
		t.Errorf("parent traversal kept: %q", got)
	}
	if got := usableTempRoot("/repo/.tmp", "/repo"); got != "" {
		t.Errorf("tree-interior root kept: %q", got)
	}
	if got := usableTempRoot("/scratch/run/", "/repo"); got != "/scratch/run" {
		t.Errorf("usable root: got %q", got)
	}
	tree := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "into-tree")
	if err := os.Symlink(tree, link); err != nil {
		t.Fatal(err)
	}
	if got := usableTempRoot(filepath.Join(link, "sub"), tree); got != "" {
		t.Errorf("resolved-interior root kept: %q", got)
	}
}

// The roots memo's key is the package directory's coordinate and the
// normalized environment less PWD: two package directories never share
// an entry, one directory spelled uncleaned or through a symlink and one
// environment in two orders share theirs, any other setting moves it,
// PWD alone does not, and a malformed environment is refused.
func TestRootsKeyCoversTheCoordinateAndEnvironment(t *testing.T) {
	key := func(dir string, env []string) string {
		t.Helper()
		k, err := rootsKey(dir, env)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	base := []string{"PATH=/bin", "HOME=/h", "PWD=" + dir}
	if key(dir, base) == key(filepath.Join(dir, "x"), base) {
		t.Fatal("two package directories share a key")
	}
	for _, spelling := range []string{dir + "/x/..", link} {
		if key(spelling, base) != key(dir, base) {
			t.Fatalf("%s spelled a second key for one directory", spelling)
		}
	}
	if key(dir, []string{"PWD=" + dir, "HOME=/h", "PATH=/bin"}) != key(dir, base) {
		t.Fatal("the environment's order moved the key")
	}
	if key(dir, base) != key(dir, []string{"PATH=/bin", "HOME=/h", "PWD=/other"}) {
		t.Fatal("PWD alone moved the key")
	}
	for _, extra := range []string{"GOWORK=/w/go.work", "XDG_CONFIG_HOME=/c", "GOTOOLCHAIN=local", "ZZZ=1"} {
		if key(dir, base) == key(dir, append(append([]string(nil), base...), extra)) {
			t.Fatalf("%s did not move the key", extra)
		}
	}
	if _, err := rootsKey(dir, []string{"A=1", "A=2"}); err == nil {
		t.Fatal("a duplicated key was admitted")
	}
}
