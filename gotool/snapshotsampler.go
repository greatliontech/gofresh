package gotool

import (
	"context"
	"errors"
	"fmt"
)

// SnapshotSampler is a toolchain sampler over a pass reader's one
// snapshot: the sample is the GOVERSION the snapshot carries — the
// same string `go env GOVERSION` answers, which the memoized Sampler
// spawns for — so a consumer that already holds the pass's reader
// samples the toolchain without a second process. The reader is one
// (directory, environment) under the reader's own spelling — the
// process's directory named and unnamed are two passes, since the go
// command reads the unnamed one through PWD: an ask for another
// coordinate, spelling or environment is refused rather than answered
// from a snapshot that never described it, and a snapshot naming no
// GOVERSION is no sample.
type SnapshotSampler struct {
	Reader *EnvReader
}

// errSnapshotPass is the refusal of an ask outside the reader's pass.
var errSnapshotPass = errors.New("gotool: snapshot sampler: the ask names a directory or environment other than its reader's pass")

// Sample answers the reader's GOVERSION for the reader's own pass.
func (s SnapshotSampler) Sample(ctx context.Context, dir string, env []string) (string, error) {
	if s.Reader == nil {
		return "", errors.New("gotool: snapshot sampler: no reader")
	}
	asked, err := MemoKey(dir, env)
	if err != nil {
		return "", err
	}
	own, err := MemoKey(s.Reader.Dir, s.Reader.Env)
	if err != nil {
		return "", err
	}
	if asked != own {
		return "", errSnapshotPass
	}
	snapshot, err := s.Reader.Snapshot(ctx)
	if err != nil {
		return "", err
	}
	version := snapshot.Value("GOVERSION")
	if version == "" {
		return "", fmt.Errorf("gotool: snapshot sampler: go env -json answered no GOVERSION")
	}
	return version, nil
}
