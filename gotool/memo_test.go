package gotool

import (
	"os"
	"path/filepath"
	"testing"
)

// The judged-run memo's key is the directory's coordinate and the
// normalized environment less PWD: two package directories never share
// an entry, one directory spelled uncleaned or through a symlink and one
// environment in two orders share theirs, any other setting moves it,
// PWD alone does not, and a malformed environment is refused.
func TestMemoKeyCoversTheCoordinateAndEnvironment(t *testing.T) {
	key := func(dir string, env []string) string {
		t.Helper()
		k, err := MemoKey(dir, env)
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
	// With no directory named the command runs in the process's own,
	// which the go command reads through PWD: two spellings keep their
	// own keys.
	if key("", base) == key("", []string{"PATH=/bin", "HOME=/h", "PWD=/other"}) {
		t.Fatal("PWD was dropped from the key of the process's own directory")
	}
	for _, extra := range []string{"GOWORK=/w/go.work", "XDG_CONFIG_HOME=/c", "GOTOOLCHAIN=local", "ZZZ=1"} {
		if key(dir, base) == key(dir, append(append([]string(nil), base...), extra)) {
			t.Fatalf("%s did not move the key", extra)
		}
	}
	if _, err := MemoKey(dir, []string{"A=1", "A=2"}); err == nil {
		t.Fatal("a duplicated key was admitted")
	}
}

// The memo files one holder per key for its lifetime, whatever the
// instance: two spellings of one directory and two orderings of one
// environment share a holder, another directory or setting gets its
// own, and a malformed environment is refused — the holder's
// discipline (an answer taken once, a failure sticky, a cancellation
// never stored, concurrent asks waiting) being each holder's own, which
// the Sampler and the pass reader pin (REQ-fresh-toolchain-skew).
func TestRunMemoHoldsOneHolderPerKey(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	made := 0
	make := func() *int { made++; v := made; return &v }
	m := &RunMemo[*int]{}
	base := []string{"PATH=/bin", "HOME=/h", "PWD=" + dir}
	first, err := m.Get(dir, base, make)
	if err != nil {
		t.Fatal(err)
	}
	for _, ask := range []struct {
		dir string
		env []string
	}{{dir + "/x/..", base}, {link, base}, {dir, []string{"PWD=/other", "HOME=/h", "PATH=/bin"}}} {
		got, err := m.Get(ask.dir, ask.env, make)
		if err != nil || got != first {
			t.Fatalf("Get(%s, %v) = %v, %v; want the first holder", ask.dir, ask.env, got, err)
		}
	}
	if made != 1 {
		t.Fatalf("%d holders made for one key, want 1", made)
	}
	other, err := m.Get(dir, append(append([]string(nil), base...), "GOTOOLCHAIN=local"), make)
	if err != nil || other == first {
		t.Fatalf("another setting shared the holder (%v, %v)", other, err)
	}
	if _, err := m.Get(dir, []string{"A=1", "A=2"}, make); err == nil {
		t.Fatal("a malformed environment was keyed")
	}
}
