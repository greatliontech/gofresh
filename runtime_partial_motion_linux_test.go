package gofresh

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPureUnitPartialRootMovement(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes a retained test binary")
	}
	f := newRuntimeMotionFixture(t)
	for _, scenario := range []string{"stable unknown", "known file with FIFO", "external link with FIFO", "read denied after stat", "independent stable unknown"} {
		t.Run(scenario, func(t *testing.T) {
			p := filepath.Join(f.dir, "input")
			if err := os.WriteFile(p, []byte("before"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0600); _ = os.Remove(p) })
			fifo := filepath.Join(f.dir, "unknown-fifo")
			if err := syscall.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(fifo) })
			u, err := f.binding.BeginPackage([]Subject{f.reader})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(u.Abort)
			before, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			// Exactly the facade's one directory root: no separate file root
			// can accidentally rescue a broken partial-directory comparison.
			c, err := u.Register(t.Context(), f.artifact, ProcessDescription{Identity: t.Name(), Capture: filepath.Join(t.TempDir(), "capture")})
			if err != nil {
				t.Fatal(err)
			}
			cmd, err := f.runner.Program(t.Context(), c.Directory(), c.Environment(), f.binary, "-test.v", "-test.run=^TestReader$", "-test.testlogfile="+c.Capture())
			if err != nil {
				t.Fatal(err)
			}
			output, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(output), `actually consumed "before"`) {
				t.Fatalf("producing execution: %s %v", output, err)
			}
			if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
				t.Fatal(err)
			}
			moved := scenario != "stable unknown" && scenario != "independent stable unknown"
			if scenario == "external link with FIFO" {
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("after"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, p); err != nil {
					t.Fatal(err)
				}
			} else if moved {
				if err := os.WriteFile(p, []byte("after!"), 0600); err != nil {
					t.Fatal(err)
				}
				if scenario == "known file with FIFO" {
					if err := os.Chtimes(p, before.ModTime(), before.ModTime()); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "read denied after stat" {
					if os.Geteuid() == 0 {
						t.Skip("requires non-root read denial")
					}
					if err := os.Chmod(p, 0000); err != nil {
						t.Fatal(err)
					}
					if _, err := os.ReadFile(p); !os.IsPermission(err) {
						t.Fatalf("read denial: %v", err)
					}
				}
			}
			result, closeErr := u.Close(t.Context())
			account, ok := u.Account()
			if !ok || account.Terminal.Kind != NormalCompletion || account.Inputs.Manifest == "" {
				t.Fatal("process facts lost")
			}
			if moved {
				var span *RuntimeInputSpanError
				if !errors.As(closeErr, &span) || !account.Inputs.BracketMoved || len(result.Subjects) != 0 {
					t.Fatalf("known movement waived: %+v %+v %v", result, account, closeErr)
				}
			} else if closeErr != nil || len(result.Subjects) != 1 || result.Subjects[0].Verdict.Status != Valid || account.Inputs.BracketMoved || !account.Inputs.Unverifiable {
				t.Fatalf("unchanged unknown was promoted to movement: %+v %+v %v", result, account, closeErr)
			}
		})
	}
}

func TestPureUnitRetainsDirentTypeAcrossSearchDenial(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and executes a retained test binary")
	}
	if os.Geteuid() == 0 {
		t.Skip("requires non-root search denial")
	}
	f := newRuntimeMotionFixture(t)
	for _, retype := range []bool{false, true} {
		data := filepath.Join(f.dir, "data")
		input := filepath.Join(data, "input")
		if err := os.Mkdir(data, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(data, 0700) })
		if err := os.WriteFile(input, []byte("before"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(data, 0400); err != nil {
			t.Fatal(err)
		}
		u, err := f.binding.BeginPackage([]Subject{f.direntReader})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(u.Abort)
		c, err := u.Register(t.Context(), f.artifact, ProcessDescription{Identity: t.Name(), Capture: filepath.Join(t.TempDir(), "capture")})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(data, 0700); err != nil {
			t.Fatal(err)
		}
		cmd, err := f.runner.Program(t.Context(), c.Directory(), c.Environment(), f.binary, "-test.v", "-test.run=^TestDirentReader$", "-test.testlogfile="+c.Capture())
		if err != nil {
			t.Fatal(err)
		}
		output, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(output), `actually consumed "before"`) {
			t.Fatalf("producing execution: %s %v", output, err)
		}
		if err := u.Submit(c, Terminal{Kind: NormalCompletion}); err != nil {
			t.Fatal(err)
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
		result, closeErr := u.Close(t.Context())
		account, ok := u.Account()
		if !ok || account.Terminal.Kind != NormalCompletion || account.Inputs.Manifest == "" {
			t.Fatal("process facts lost")
		}
		if retype {
			var span *RuntimeInputSpanError
			if !errors.As(closeErr, &span) || !account.Inputs.BracketMoved || len(result.Subjects) != 0 {
				t.Fatalf("known dirent movement waived: %+v %+v %v", result, account, closeErr)
			}
		} else if closeErr != nil || len(result.Subjects) != 1 || result.Subjects[0].Verdict.Status != Valid || account.Inputs.BracketMoved || !account.Inputs.Unverifiable {
			t.Fatalf("unchanged unknown control refused: %+v %+v %v", result, account, closeErr)
		}
		if err := os.Chmod(data, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(data); err != nil {
			t.Fatal(err)
		}
	}
}
