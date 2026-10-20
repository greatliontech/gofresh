//go:build linux && !android

package assemblycapture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// retainedWriter leaves only a duplicate of the original writable description
// open. Like an inherited descriptor, its final close can occur after the
// original writer has finished and the input watcher has been installed.
func retainedWriter(t *testing.T) (string, int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "importcfg")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("packagefile example=/build/example.a\n"); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	// The caller owns fd after return. Do not register a cleanup here: closing
	// it twice could close a descriptor subsequently allocated by the test.
	if err := f.Close(); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	return path, fd
}

func TestInputSetAcceptsRetainedWriterClose(t *testing.T) {
	path, fd := retainedWriter(t)
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	s := testInputs(t, t.Context(), Limits{})
	want, err := s.read(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.validate(); err != nil {
		t.Fatalf("before retained descriptor close: %v", err)
	}
	var before, after unix.Stat_t
	if err := unix.Stat(path, &before); err != nil {
		t.Fatal(err)
	}
	// No write, metadata operation or namespace operation occurs after the
	// agreeing observation: this is only the last reference's close.
	closeErr := unix.Close(fd)
	fd = -1
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if err := unix.Stat(path, &after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("close changed stat: before=%+v after=%+v", before, after)
	}
	got, err := readObservation(t.Context(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sameObservation(want, got) {
		t.Fatal("close changed path, bytes or observed file metadata")
	}
	t.Log("retained writable descriptor closed; full stat, path and bytes unchanged")
	if err := s.validate(); err != nil {
		t.Fatalf("unchanged input refused after retained writer close: %v", err)
	}
}

func TestInputSetDetectsMutationBeforeWriterClose(t *testing.T) {
	for _, mode := range []string{"write", "write-restore", "truncate", "truncate-restore", "chmod-restore"} {
		t.Run(mode, func(t *testing.T) {
			path, fd := retainedWriter(t)
			defer unix.Close(fd)
			s := testInputs(t, t.Context(), Limits{})
			want, err := s.read(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.validate(); err != nil {
				t.Fatal(err)
			}
			write := func(data []byte) {
				t.Helper()
				n, err := unix.Pwrite(fd, data, 0)
				if err != nil || n != len(data) {
					t.Fatalf("pwrite: n=%d want=%d err=%v", n, len(data), err)
				}
			}
			switch mode {
			case "write", "write-restore":
				write([]byte("X"))
			case "truncate", "truncate-restore":
				if err := unix.Ftruncate(fd, 0); err != nil {
					t.Fatal(err)
				}
			case "chmod-restore":
				if err := unix.Fchmod(fd, 0400); err != nil {
					t.Fatal(err)
				}
				if err := unix.Fchmod(fd, uint32(want.info.Mode().Perm())); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasSuffix(mode, "-restore") {
				if mode != "chmod-restore" {
					write(want.data)
				}
				if err := os.Chtimes(path, want.info.ModTime(), want.info.ModTime()); err != nil {
					t.Fatal(err)
				}
				got, err := readObservation(t.Context(), path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if !sameObservation(want, got) {
					t.Fatal("control did not restore the complete endpoint observation")
				}
			}
			// The writable description is still open: no CLOSE_WRITE can make
			// this pass, and restore cases cannot be caught by endpoint equality.
			err = s.validate()
			if err == nil || !strings.Contains(err.Error(), "protected input namespace mutated") {
				t.Fatalf("live-descriptor mutation not caught by notification: %v", err)
			}
			t.Logf("mutation caught with writer still open: %v", err)
		})
	}
}
