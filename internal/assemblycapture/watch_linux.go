//go:build linux && !android

package assemblycapture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

type watchInterest struct {
	all   bool
	names map[string]bool
	// paths retains the coordinates reached by the component/symlink walk.
	// Several coordinates can share an inode watch. They are diagnostic facts
	// from registration, never re-resolved after a namespace mutation.
	paths map[string]bool
}
type watcher struct {
	fd      int
	m       *meter
	entries map[int]*watchInterest
	paths   map[string]bool
}

func newWatcher(m *meter) (*watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("assembly capture: mutation observation unavailable: %w", err)
	}
	return &watcher{fd: fd, m: m, entries: map[int]*watchInterest{}, paths: map[string]bool{}}, nil
}

func (w *watcher) close() {
	if w.fd >= 0 {
		_ = unix.Close(w.fd)
		w.fd = -1
	}
}

func (w *watcher) add(name, child string, nofollow bool) error {
	key := name + "\x00" + child
	if w.paths[key] {
		return nil
	}
	if err := w.m.charge("watches", 1); err != nil {
		return err
	}
	// Closing a writable description need not change the file, even when its
	// final reference outlives the original writer and watch installation.
	mask := uint32(unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM | unix.IN_MOVED_TO | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF | unix.IN_UNMOUNT | unix.IN_MASK_ADD)
	if nofollow {
		mask |= unix.IN_DONT_FOLLOW
	}
	wd, err := unix.InotifyAddWatch(w.fd, name, mask)
	if err != nil {
		return fmt.Errorf("assembly capture: watch %s: %w", name, err)
	}
	e := w.entries[wd]
	if e == nil {
		e = &watchInterest{names: map[string]bool{}, paths: map[string]bool{}}
		w.entries[wd] = e
	}
	e.paths[name] = true
	if child == "" {
		e.all = true
	} else {
		e.names[child] = true
	}
	w.paths[key] = true
	return nil
}

// Every path component is protected by its parent and, for a selected file,
// the inode itself. Symlink targets receive the same treatment. A missing tail
// remains protected at its first absent component; creating it refuses use.
func (w *watcher) addPath(path string) error { return w.addPathDepth(path, 0) }

func (w *watcher) addPathDepth(path string, depth int) error {
	if depth > w.m.limits.Depth {
		return fmt.Errorf("assembly capture: path resolution bound exhausted")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("assembly capture: nonabsolute watch path")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(current)
			continue
		}
		if err := w.add(current, part, false); err != nil {
			return err
		}
		next := filepath.Join(current, part)
		info, err := os.Lstat(next)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if err := w.add(next, "", true); err != nil {
				return err
			}
			target, err := os.Readlink(next)
			if err != nil {
				return err
			}
			target = absolute(current, target)
			if i+1 < len(parts) {
				target += string(filepath.Separator) + strings.Join(parts[i+1:], string(filepath.Separator))
			}
			return w.addPathDepth(target, depth+1)
		}
		if i < len(parts)-1 && !info.IsDir() {
			return fmt.Errorf("assembly capture: non-directory path component %s", next)
		}
		current = next
	}
	return w.add(current, "", false)
}

func (w *watcher) drain() error {
	if err := w.m.ctx.Err(); err != nil {
		return err
	}
	buf := make([]byte, 64<<10)
	for {
		if err := w.m.ctx.Err(); err != nil {
			return err
		}
		n, err := unix.Read(w.fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("assembly capture: mutation observation lost: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("assembly capture: mutation observation lost: end of event stream")
		}
		if err := w.acceptEvents(buf[:n]); err != nil {
			return err
		}
	}
}

func (w *watcher) acceptEvents(buf []byte) error {
	for at := 0; at < len(buf); {
		if err := w.m.charge("events", 1); err != nil {
			return err
		}
		if len(buf)-at < unix.SizeofInotifyEvent {
			return fmt.Errorf("assembly capture: incomplete mutation event")
		}
		wd := int(int32(binary.NativeEndian.Uint32(buf[at:])))
		mask := binary.NativeEndian.Uint32(buf[at+4:])
		length := uint64(binary.NativeEndian.Uint32(buf[at+12:]))
		if length > uint64(len(buf)-at-unix.SizeofInotifyEvent) {
			return fmt.Errorf("assembly capture: truncated mutation event")
		}
		name := strings.TrimRight(string(buf[at+unix.SizeofInotifyEvent:at+unix.SizeofInotifyEvent+int(length)]), "\x00")
		if mask&(unix.IN_Q_OVERFLOW|unix.IN_IGNORED|unix.IN_UNMOUNT) != 0 {
			return w.eventError("mutation observation incomplete", wd, name, mask)
		}
		e := w.entries[wd]
		if e == nil {
			return w.eventError("unknown mutation watch", wd, name, mask)
		}
		if e.all || e.names[name] || mask&(unix.IN_MOVE_SELF|unix.IN_DELETE_SELF) != 0 || name == "" && mask&unix.IN_ATTRIB != 0 {
			return w.eventError("protected input namespace mutated", wd, name, mask)
		}
		at += unix.SizeofInotifyEvent + int(length)
	}
	return nil
}

func (w *watcher) eventError(reason string, wd int, name string, mask uint32) error {
	var roots, paths []string
	if e := w.entries[wd]; e != nil {
		roots = slices.Sorted(maps.Keys(e.paths))
		for _, root := range roots {
			paths = append(paths, filepath.Join(root, name))
		}
	}
	return fmt.Errorf("assembly capture: %s (wd %d, watch paths %q, paths %q, name %q, mask %#x)", reason, wd, roots, paths, name, mask)
}
