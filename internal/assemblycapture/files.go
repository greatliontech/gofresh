package assemblycapture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type fileObservation struct {
	path, resolved string
	info           os.FileInfo
	data           []byte
	absent         bool
}

// readObservation only admits regular files and ENOENT lookup failures. An
// inaccessible earlier candidate is never reclassified as an empty namespace.
func readObservation(ctx context.Context, path string, m *meter) (fileObservation, error) {
	o := fileObservation{path: path}
	if err := ctx.Err(); err != nil {
		return o, err
	}
	if m != nil {
		if err := m.charge("files", 1); err != nil {
			return o, err
		}
	}
	f, err := openObservationFile(path)
	if os.IsNotExist(err) {
		o.absent = true
		return o, nil
	}
	if err != nil {
		return o, fmt.Errorf("assembly capture: read %s: %w", path, err)
	}
	defer f.Close()
	o.info, err = f.Stat()
	if err != nil {
		return o, err
	}
	if !o.info.Mode().IsRegular() {
		return o, fmt.Errorf("assembly capture: nonregular input %s", path)
	}
	o.resolved, err = filepath.EvalSymlinks(path)
	if err != nil {
		return o, err
	}
	var buf bytes.Buffer
	block := make([]byte, 32768)
	for {
		if err := ctx.Err(); err != nil {
			return o, err
		}
		n, err := f.Read(block)
		if m != nil {
			if err := m.readBytes(path, n); err != nil {
				return o, err
			}
		}
		buf.Write(block[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return o, err
		}
	}
	after, err := f.Stat()
	if err != nil {
		return o, err
	}
	if !sameStat(o.info, after) {
		return o, fmt.Errorf("assembly capture: input changed while reading %s", path)
	}
	o.data = buf.Bytes()
	return o, nil
}

func sameStat(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime() == b.ModTime()
}

func sameObservation(a, b fileObservation) bool {
	return a.path == b.path && a.absent == b.absent && (a.absent || a.resolved == b.resolved && sameStat(a.info, b.info) && bytes.Equal(a.data, b.data))
}

// inputSet installs watches before taking the observation that can authorize
// use. A second read agrees before the child proceeds, and a third closes its
// interval while the shim still blocks driver cleanup.
type inputSet struct {
	ctx   context.Context
	m     *meter
	watch *watcher
	files map[string]fileObservation
}

func newInputSet(ctx context.Context, m *meter) (*inputSet, error) {
	w, err := newWatcher(m)
	if err != nil {
		return nil, err
	}
	return &inputSet{ctx: ctx, m: m, watch: w, files: map[string]fileObservation{}}, nil
}

func (s *inputSet) close() { s.watch.close() }

func (s *inputSet) read(path string) (fileObservation, error) {
	if !filepath.IsAbs(path) {
		return fileObservation{}, fmt.Errorf("assembly capture: input is not absolute: %s", path)
	}
	if old, ok := s.files[path]; ok {
		return old, nil
	}
	if err := s.watch.addPath(path); err != nil {
		return fileObservation{}, err
	}
	o, err := readObservation(s.ctx, path, s.m)
	if err != nil {
		return o, err
	}
	s.files[path] = o
	return o, nil
}

func (s *inputSet) validate() error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if err := s.watch.drain(); err != nil {
		return fmt.Errorf("assembly capture: initial validation drain: %w", err)
	}
	for path, want := range s.files {
		got, err := readObservation(s.ctx, path, s.m)
		if err != nil {
			return fmt.Errorf("assembly capture: validation read %s: %w", path, err)
		}
		if !sameObservation(want, got) {
			return fmt.Errorf("assembly capture: input or lookup changed: %s", path)
		}
	}
	if err := s.watch.drain(); err != nil {
		return fmt.Errorf("assembly capture: final validation drain: %w", err)
	}
	return nil
}

func absolute(cwd, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	// Direct tool operands are opened by the kernel. Cleaning link/.. before
	// lookup would replace that lookup with a different file. Callers modelling
	// an interface which explicitly uses filepath.Join apply that operation at
	// their own boundary instead (the assembler's -I search, for example).
	return cwd + string(filepath.Separator) + path
}
