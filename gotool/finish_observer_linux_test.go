//go:build linux && !android

package gotool

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// collectedDescendantTerminated judges a descendant after collection has
// returned. Procfs reports ENOENT if lookup loses the task and ESRCH if a
// read loses it after open; both establish disappearance. This is not the
// leader-identity judgment, which requires the leader to remain waitable.
func collectedDescendantTerminated(data []byte, err error) (bool, error) {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	_, state, _ := strings.Cut(string(data), ") ")
	return strings.HasPrefix(state, "Z "), nil
}

func TestCollectedDescendantReadState(t *testing.T) {
	for _, row := range []struct {
		name, data string
		readErr    error
		terminated bool
		wantErr    bool
	}{
		{"lookup lost task", "", unix.ENOENT, true, false},
		{"read lost task", "", unix.ESRCH, true, false},
		{"permission", "", unix.EPERM, false, true},
		{"access denied", "", unix.EACCES, false, true},
		{"I/O fault", "", unix.EIO, false, true},
		{"zombie", "123 (sleep) Z 1 123 123 0", nil, true, false},
		{"sleeping", "123 (sleep) S 1 123 123 0", nil, false, false},
		{"running", "123 (sleep) R 1 123 123 0", nil, false, false},
		{"stopped", "123 (sleep) T 1 123 123 0", nil, false, false},
		{"uninterruptible", "123 (sleep) D 1 123 123 0", nil, false, false},
		{"empty", "", nil, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := row.readErr
			if err != nil {
				err = fmt.Errorf("observation: %w", &os.PathError{Op: "read", Path: "/proc/123/stat", Err: err})
			}
			got, readErr := collectedDescendantTerminated([]byte(row.data), err)
			if got != row.terminated || (readErr != nil) != row.wantErr {
				t.Fatalf("terminated=%t error=%v; want %t error=%t", got, readErr, row.terminated, row.wantErr)
			}
			if row.wantErr && !errors.Is(readErr, row.readErr) {
				t.Fatalf("lost observation error: %v", readErr)
			}
		})
	}
}
