//go:build linux && !android

package assemblycapture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestActionValidationAttributesResolvedMutation(t *testing.T) {
	for _, tc := range []struct{ phase, tool string }{
		{"before-tool", "compile"},
		{"after-tool", "asm"},
		{"preprofile-output", "preprofile"},
	} {
		t.Run(tc.phase, func(t *testing.T) {
			dir := t.TempDir()
			targetDir := filepath.Join(dir, "resolved")
			target := filepath.Join(targetDir, "input")
			put(t, target, "original")
			alias := filepath.Join(dir, "alias")
			if err := os.Symlink(targetDir, alias); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(alias, "input")
			s := testInputs(t, t.Context(), Limits{})
			if _, err := s.read(path); err != nil {
				t.Fatal(err)
			}
			a := &capturedAction{inv: Invocation{
				Instance: "example.com/p [example.com/p.test]", Tool: "/tools/" + tc.tool,
				CWD: dir, Output: path,
				Args: []string{"private-argument"}, Env: []string{"PRIVATE=private-environment"},
			}}
			if err := a.validateInputs(s, tc.phase); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(target, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.WriteAt([]byte("modified"), 0); err != nil {
				t.Fatal(err)
			}
			err = a.validateInputs(s, tc.phase)
			if err == nil {
				t.Fatal("actual target mutation accepted")
			}
			text := err.Error()
			for _, token := range []string{
				strconv.Quote(a.inv.Instance), strconv.Quote(a.inv.Tool),
				strconv.Quote(a.inv.CWD), strconv.Quote(a.inv.Output), tc.phase,
				strconv.Quote(target), "initial validation drain", "mask 0x2",
			} {
				if !strings.Contains(text, token) {
					t.Errorf("missing attribution %q in %v", token, err)
				}
			}
			// Either the parent or inode event may arrive first. Its descriptor
			// and captured root must agree, including symlink target resolution.
			attributed := false
			for wd, interest := range s.watch.entries {
				if strings.Contains(text, fmt.Sprintf("wd %d,", wd)) {
					for root := range interest.paths {
						if (root == targetDir || root == target) && strings.Contains(text, strconv.Quote(root)) {
							attributed = true
						}
					}
				}
			}
			if !attributed {
				t.Fatalf("event descriptor lacks its registered resolved coordinate: %v", err)
			}
			for _, secret := range []string{"private-argument", "private-environment"} {
				if strings.Contains(text, secret) {
					t.Fatalf("diagnostic exposed invocation payload: %v", err)
				}
			}
		})
	}
}

func TestActionValidationPreservesUnderlyingErrors(t *testing.T) {
	for _, kind := range []string{"cancelled", "lost-descriptor"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			s := testInputs(t, ctx, Limits{})
			a := &capturedAction{inv: Invocation{Instance: "example.com/p", Tool: "/tools/compile"}}
			var want error = context.Canceled
			if kind == "cancelled" {
				cancel()
			} else {
				s.watch.close()
				want = unix.EBADF
			}
			err := a.validateInputs(s, "after-tool")
			if !errors.Is(err, want) || err == want {
				t.Fatalf("action validation lost wrapped cause %v: %v", want, err)
			}
			if !strings.Contains(err.Error(), "after-tool") || !strings.Contains(err.Error(), a.inv.Instance) {
				t.Fatalf("action validation lost context: %v", err)
			}
			if kind == "lost-descriptor" {
				var errno unix.Errno
				if !errors.As(err, &errno) || errno != unix.EBADF {
					t.Fatalf("descriptor error type lost: %v", err)
				}
			}
		})
	}
}

func TestMutationDiagnosticRetainsSharedWatchCoordinates(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "first"), filepath.Join(dir, "second")
	put(t, first, "original")
	if err := os.Link(first, second); err != nil {
		t.Fatal(err)
	}
	s := testInputs(t, t.Context(), Limits{})
	for _, path := range []string{first, second} {
		if _, err := s.read(path); err != nil {
			t.Fatal(err)
		}
	}
	var wd int
	for candidate, interest := range s.watch.entries {
		if interest.paths[first] && interest.paths[second] {
			wd = candidate
			break
		}
	}
	if wd == 0 {
		t.Fatal("hardlinked inputs did not retain both watch coordinates")
	}
	if _, err := unix.InotifyRmWatch(s.watch.fd, uint32(wd)); err != nil {
		t.Fatal(err)
	}
	err := s.validate()
	if err == nil {
		t.Fatal("lost shared inode watch accepted")
	}
	for _, token := range []string{strconv.Quote(first), strconv.Quote(second), fmt.Sprintf("wd %d,", wd), "mask 0x8000"} {
		if !strings.Contains(err.Error(), token) {
			t.Errorf("missing shared-watch attribution %q: %v", token, err)
		}
	}
}
