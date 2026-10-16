package gofresh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
)

// ArtifactDescription identifies the retained package-test file the executor
// built under the snapshot's description and will execute. Identity is the
// executor's nonempty label; its spelling supplies no content or semantic
// authority. Path is absolute or relative to the build directory, independently
// of the runtime directory.
type ArtifactDescription struct {
	Identity string
	Path     string
}

// inspectedArtifact is shared immutable input, never a transaction or a proof.
// No descriptor survives inspection: the executor owns the retained file's
// lifetime and protects its path resolution and bytes through publication.
type inspectedArtifact struct {
	path   string
	file   os.FileInfo
	bytes  []byte
	digest [sha256.Size]byte
}

// BindArtifact adds an agreeing complete file observation to the same successful
// package-test build declaration as BindBuilt. The caller protects the artifact,
// path resolution and build dependencies through execution, closing and
// publication. Inspection does not authenticate build or execution truth, prove
// native behavior, or add a persisted applicability guard to a fingerprint.
func (s *Snapshot) BindArtifact(ctx context.Context, pkg string, description ArtifactDescription) (binding BuildBinding, err error) {
	if ctx == nil {
		return BuildBinding{}, errors.New("gofresh: nil artifact context")
	}
	defer func() {
		if cause := ctx.Err(); cause != nil {
			binding, err = BuildBinding{}, cause
		}
	}()
	if err := ctx.Err(); err != nil {
		return BuildBinding{}, err
	}
	binding, err = s.BindBuilt(pkg, description.Identity)
	if err != nil {
		return BuildBinding{}, err
	}
	if description.Path == "" {
		return BuildBinding{}, errors.New("gofresh: empty artifact path")
	}
	path, err := rebaseProcessPath(s.session.build.Directory, description.Path)
	if err != nil {
		return BuildBinding{}, fmt.Errorf("gofresh: artifact path: %w", err)
	}
	artifact, err := readArtifact(ctx, path, nil)
	if err != nil {
		return BuildBinding{}, fmt.Errorf("gofresh: inspect artifact %q: %w", path, err)
	}
	if err := artifact.validate(ctx); err != nil {
		return BuildBinding{}, err
	}
	binding.inspected = artifact
	return binding, nil
}

// validate independently reopens the execution coordinate. Reading only a held
// descriptor would miss pathname replacement, including same-byte replacement.
// A comparison needs one full observation, not another agreement pair: equality
// during a change-and-restore interval remains the caller's exclusion obligation.
func (a *inspectedArtifact) validate(ctx context.Context) error {
	if a == nil {
		return nil // The declaration-only binding selects no artifact observation.
	}
	_, err := readArtifact(ctx, a.path, a)
	if cause := ctx.Err(); cause != nil {
		return cause
	}
	if err != nil {
		return fmt.Errorf("%w: artifact %q observation unavailable: %w", ErrViewChanged, a.path, err)
	}
	return ctx.Err()
}

// readArtifact captures an owned image when expected is nil. Otherwise it
// compares every byte against the immutable expected image and returns that
// unchanged input on success. Both paths share the same coordinate, identity,
// read-completeness and cancellation checks. Validation needs only a bounded
// buffer: reconstructing or hashing a second image adds no comparison evidence.
// Metadata enforces regular-file and file-identity constraints; complete bytes,
// never timestamps, establish content agreement. Context checks bound every
// read/hash chunk and both sides of filesystem calls; like other filesystem
// observations, an individual OS call is not interruptible.
func readArtifact(ctx context.Context, path string, expected *inspectedArtifact) (artifact *inspectedArtifact, err error) {
	defer func() {
		if cause := ctx.Err(); cause != nil {
			artifact, err = nil, cause
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("artifact is not a regular file")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("%w: artifact changed while opening", ErrViewChanged)
	}
	size := opened.Size()
	if size < 0 || int64(int(size)) != size {
		return nil, errors.New("artifact size exceeds addressable input")
	}
	a := expected
	if a == nil {
		// A successful capture owns all bytes, so reserve exactly the observed
		// size rather than repeatedly allocating and copying a growing image.
		a = &inspectedArtifact{path: path, file: opened, bytes: make([]byte, 0, int(size))}
	} else if !os.SameFile(a.file, opened) || int64(len(a.bytes)) != size {
		return nil, fmt.Errorf("%w: artifact identity or size changed", ErrViewChanged)
	}
	hash := sha256.New()
	var buffer [64 * 1024]byte
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, readErr := file.Read(buffer[:])
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if int64(n) > size-total {
			return nil, fmt.Errorf("%w: artifact grew during read", ErrViewChanged)
		}
		if expected == nil {
			a.bytes = append(a.bytes, buffer[:n]...)
			_, _ = hash.Write(buffer[:n])
		} else if !bytes.Equal(a.bytes[int(total):int(total)+n], buffer[:n]) {
			return nil, fmt.Errorf("%w: artifact content changed", ErrViewChanged)
		}
		total += int64(n)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	coordinate, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !coordinate.Mode().IsRegular() || !os.SameFile(opened, after) || !os.SameFile(after, coordinate) || total != size || after.Size() != size || coordinate.Size() != size {
		return nil, fmt.Errorf("%w: artifact changed during read", ErrViewChanged)
	}
	if expected == nil {
		copy(a.digest[:], hash.Sum(nil))
	}
	return a, nil
}
