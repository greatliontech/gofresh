package runtimeinput

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadProducerLogClosesItsFile(t *testing.T) {
	good := writeTestlog(t, "")
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(good), alias); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "headerless")
	if err := os.WriteFile(bad, []byte("not a capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path          string
		ctx                 context.Context
		rejected, cancelled bool
	}{
		{"successful", good, context.Background(), false, false},
		{"symlinked spelling", filepath.Join(alias, filepath.Base(good)), context.Background(), false, false},
		{"header rejected", bad, context.Background(), true, false},
		{"read failure", t.TempDir(), context.Background(), true, false},
		{"cancelled after open", good, &cancelAfterChecks{Context: context.Background(), after: 1}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := os.Stat(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			_, reason, err := readProducerLog(tc.ctx, tc.path)
			if tc.cancelled {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancelled capture: %v", err)
				}
			} else if err != nil || (reason != "") != tc.rejected {
				t.Fatalf("capture: %q %v", reason, err)
			}
			entries, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if opened, err := os.Stat(filepath.Join("/proc/self/fd", entry.Name())); err == nil && os.SameFile(info, opened) {
					t.Fatalf("capture retained file descriptor %s", entry.Name())
				}
			}
		})
	}
}
