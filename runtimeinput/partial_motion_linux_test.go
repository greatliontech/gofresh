package runtimeinput

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPartialRootKnownMovement(t *testing.T) {
	for _, scenario := range []string{"same-root FIFO", "external symlink", "unreadable file", "unreadable member"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "input")
			if err := os.WriteFile(p, []byte("before"), 0600); err != nil {
				t.Fatal(err)
			}
			roots := []string{"input"}
			if scenario == "same-root FIFO" {
				if err := syscall.Mkfifo(filepath.Join(dir, "unknown"), 0600); err != nil {
					t.Fatal(err)
				}
				roots = []string{"."}
			} else if scenario == "unreadable member" {
				roots = []string{"."}
			}
			b := testBracket(t, dir, roots...)
			before, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "external symlink" {
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("after!"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(target, before.ModTime(), before.ModTime()); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, p); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(p, []byte("after!"), 0600); err != nil {
					t.Fatal(err)
				}
				if scenario == "same-root FIFO" {
					if err := os.Chtimes(p, before.ModTime(), before.ModTime()); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "unreadable file" || scenario == "unreadable member" {
					if os.Geteuid() == 0 {
						t.Skip("requires non-root read denial")
					}
					if err := os.Chmod(p, 0000); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(p, 0600) })
					if _, err := os.ReadFile(p); !os.IsPermission(err) {
						t.Fatalf("read denial not established: %v", err)
					}
				}
			}
			observation, err := FromTestLog([]byte("open input\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
			if err != nil || !observation.BracketMoved {
				t.Fatalf("known facts lost: %+v %v", observation, err)
			}
		})
	}
}

func TestRootKnowledgeChangeAloneIsNotMovement(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root traversal denial")
	}
	for _, regain := range []bool{false, true} {
		dir := t.TempDir()
		parent := filepath.Join(dir, "parent")
		if err := os.Mkdir(parent, 0700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(parent, "input")
		if err := os.WriteFile(p, []byte("stable"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0700) })
		if regain {
			if err := os.Chmod(parent, 0000); err != nil {
				t.Fatal(err)
			}
		}
		// Only the file is bracketed. Traversal denial outside that root makes
		// its own stat and contents unknown without changing an observed value.
		bracket := testBracket(t, dir, "parent/input")
		mode := os.FileMode(0000)
		if regain {
			mode = 0700
		}
		if err := os.Chmod(parent, mode); err != nil {
			t.Fatal(err)
		}
		observation, err := FromTestLog([]byte("open parent/input\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(bracket))
		if err != nil || !observation.Unverifiable || observation.BracketMoved {
			t.Fatalf("regain=%t availability became drift: %+v %v", regain, observation, err)
		}
	}
}

func TestBracketSealBindsFactAvailabilityAndValues(t *testing.T) {
	dir := bindingModule(t)
	b := testBracket(t, dir, "data")
	for _, remove := range []bool{false, true} {
		for key := range b.roots[0].facts.values {
			copy := b
			copy.roots = append([]bracketRoot(nil), b.roots...)
			copy.roots[0].facts = clonePathFacts(b.roots[0].facts)
			if remove {
				delete(copy.roots[0].facts.values, key)
			} else {
				copy.roots[0].facts.values[key][0] += "changed"
			}
			if err := copy.checkSealed(); err == nil {
				t.Fatalf("tampered fact accepted: %+v remove=%t", key, remove)
			}
		}
	}
	if err := b.checkSealed(); err != nil {
		t.Fatal("test copies mutated original facts", err)
	}
}

func TestRootNamespaceFactsKeepAbsenceAndDanglingLinksDistinct(t *testing.T) {
	dir := t.TempDir()
	// An unobserved intermediate directory appearing does not change the
	// declared root's known absence.
	absent := testBracket(t, dir, "parent/input")
	if err := os.Mkdir(filepath.Join(dir, "parent"), 0700); err != nil {
		t.Fatal(err)
	}
	if unchanged, moved, reason, err := absent.revalidate(t.Context(), dir); err != nil || !unchanged || moved {
		t.Fatalf("unchanged absent root moved: %t %t %q %v", unchanged, moved, reason, err)
	}
	// Removing a dangling link is known namespace movement even though the
	// followed object was and remains absent, including through a parent link.
	if err := os.Symlink("parent", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"parent/input", "alias/input"} {
		p := filepath.Join(dir, "parent", "input")
		if err := os.Symlink("missing", p); err != nil {
			t.Fatal(err)
		}
		b := testBracket(t, dir, root)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if _, moved, reason, err := b.revalidate(t.Context(), dir); err != nil || !moved {
			t.Fatalf("lost dangling-link removal: %t %q %v", moved, reason, err)
		}
	}
}

func TestDirectoryEntryTypeSurvivesUnavailableInfo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root search denial")
	}
	for _, retype := range []bool{false, true} {
		dir := t.TempDir()
		data := filepath.Join(dir, "data")
		input := filepath.Join(data, "input")
		if err := os.Mkdir(data, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(data, 0700) })
		if err := os.WriteFile(input, []byte("before"), 0600); err != nil {
			t.Fatal(err)
		}
		checkEntry := func(wantDir bool) {
			t.Helper()
			entries, err := os.ReadDir(data)
			if err != nil || len(entries) != 1 {
				t.Fatalf("readable listing: %+v %v", entries, err)
			}
			if entries[0].IsDir() != wantDir || entries[0].Type().IsDir() != wantDir {
				t.Fatal("directory entry did not expose actual type")
			}
			if _, err := entries[0].Info(); !os.IsPermission(err) {
				t.Fatalf("Info must be unavailable: %v", err)
			}
		}
		if err := os.Chmod(data, 0400); err != nil {
			t.Fatal(err)
		}
		checkEntry(false)
		b := testBracket(t, dir, "data")
		if err := os.Chmod(data, 0700); err != nil {
			t.Fatal(err)
		}
		if consumed, err := os.ReadFile(input); err != nil || string(consumed) != "before" {
			t.Fatalf("producing read: %q %v", consumed, err)
		}
		if retype {
			if err := os.Remove(input); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(input, 0700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(data, 0400); err != nil {
			t.Fatal(err)
		}
		checkEntry(retype)
		observation, err := FromTestLog([]byte("open data/input\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(b))
		if err != nil || observation.BracketMoved != retype || !observation.Unverifiable {
			t.Fatalf("retype=%t lost dirent knowledge: %+v %v", retype, observation, err)
		}
	}
}
