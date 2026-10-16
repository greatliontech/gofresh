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
	artifact, err := observeArtifact(ctx, path)
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
	current, err := observeArtifact(ctx, a.path)
	if cause := ctx.Err(); cause != nil {
		return cause
	}
	if err != nil {
		return fmt.Errorf("%w: artifact %q observation unavailable: %w", ErrViewChanged, a.path, err)
	}
	if !os.SameFile(a.file, current.file) || a.digest != current.digest || !bytes.Equal(a.bytes, current.bytes) {
		return fmt.Errorf("%w: artifact %q identity or content changed", ErrViewChanged, a.path)
	}
	return ctx.Err()
}

// observeArtifact samples metadata only to enforce regular-file and file-identity
// constraints. Complete bytes, never timestamps, establish content agreement.
// Context checks bound every read/hash chunk and both sides of filesystem calls;
// like other filesystem observations, an individual OS call is not interruptible.
func observeArtifact(ctx context.Context, path string) (artifact *inspectedArtifact, err error) {
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
	a := &inspectedArtifact{path: path, file: opened}
	hash := sha256.New()
	var buffer [64 * 1024]byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, readErr := file.Read(buffer[:])
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		a.bytes = append(a.bytes, buffer[:n]...)
		_, _ = hash.Write(buffer[:n])
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
	if !after.Mode().IsRegular() || !coordinate.Mode().IsRegular() || !os.SameFile(opened, after) || !os.SameFile(after, coordinate) || opened.Size() != int64(len(a.bytes)) || after.Size() != opened.Size() || coordinate.Size() != opened.Size() {
		return nil, fmt.Errorf("%w: artifact changed during read", ErrViewChanged)
	}
	copy(a.digest[:], hash.Sum(nil))
	return a, nil
}
