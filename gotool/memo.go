package gotool

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// MemoKey is the one key a judged-run memo files a directory and an
// environment under: the directory's coordinate and the normalized
// environment — less PWD when a directory is named, since the policy
// derives PWD from it and the coordinate already collapses the
// directory's spellings; with no directory named the command runs in
// the process's own, which the go command reads through $PWD (a
// symlinked spelling walks a different parent chain to the module
// files), so PWD stays in the key — joined by NUL. Two spellings of
// one directory and two orderings of one environment key alike; any
// other setting moves the key; a malformed environment is refused
// rather than keyed raw.
func MemoKey(dir string, env []string) (string, error) {
	normalized, err := NormalizeEnv(env)
	if err != nil {
		return "", fmt.Errorf("gotool: memo key: %w", err)
	}
	var key strings.Builder
	key.WriteString(Coordinate(dir))
	for _, entry := range normalized {
		if name, _, _ := strings.Cut(entry, "="); dir != "" && EqualEnvKey(name, "PWD") {
			continue
		}
		key.WriteString("\x00" + entry)
	}
	return key.String(), nil
}

// RunMemo holds one value per MemoKey for one judged run — a
// consumer's verb invocation, a server's per-request operation, never
// a process: the span over which the caller holds the toolchain and
// its environment still. The value is a holder that takes its own
// answer on first use under its own lock (a pass reader, a version
// reader), so the memo's rules are the holder's: a failed answer is
// the holder's for the run, a cancellation is the caller's and never
// stored, and concurrent asks on one key wait on the first's spawn.
// The zero RunMemo is ready.
type RunMemo[V any] struct {
	mu   sync.Mutex
	held map[string]V
}

// Get answers the holder filed under (dir, env), making it on the
// first ask.
func (m *RunMemo[V]) Get(dir string, env []string, make func() V) (V, error) {
	key, err := MemoKey(dir, env)
	if err != nil {
		var zero V
		return zero, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.held[key]; ok {
		return v, nil
	}
	if m.held == nil {
		m.held = map[string]V{}
	}
	v := make()
	m.held[key] = v
	return v, nil
}

// once is the one-shot holder discipline both memo values share: the
// answer taken on the first ask, concurrent asks waiting on that take
// — each under its OWN context, a waiter whose context ends leaving
// with its cancellation while the take runs on — a failed answer the
// holder's for its lifetime, and a cancellation the caller's: a take
// that fails while its ask's context has ended answers the
// cancellation and stores nothing, so the next live ask takes again
// (a take that answered is stored whatever its context did after: a
// finished process's answer is the truth); a take that panics stores
// nothing and releases its waiters.
type once[V any] struct {
	mu       sync.Mutex
	taken    bool
	inflight chan struct{}
	value    V
	err      error
}

// prime fills the holder with an answer already taken.
func (o *once[V]) prime(v V) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.value, o.taken = v, true
}

// take answers the holder, taking it through fn on the first ask.
func (o *once[V]) take(ctx context.Context, fn func(context.Context) (V, error)) (V, error) {
	var zero V
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		o.mu.Lock()
		if o.taken {
			v, err := o.value, o.err
			o.mu.Unlock()
			return v, err
		}
		if o.inflight == nil {
			o.inflight = make(chan struct{})
			o.mu.Unlock()
			break
		}
		wait := o.inflight
		o.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return zero, ctx.Err()
		}
	}
	// The take completes under a defer: a take that panics (a
	// consumer's hook, recovered above) stores nothing and releases
	// the waiters, so the next ask takes again instead of waiting on a
	// take that never ends.
	var (
		v         V
		err       error
		returned  bool
		cancelled bool
	)
	defer func() {
		o.mu.Lock()
		if returned && !cancelled {
			o.value, o.err, o.taken = v, err, true
		}
		close(o.inflight)
		o.inflight = nil
		o.mu.Unlock()
	}()
	v, err = fn(ctx)
	// Judged once, here: what the caller hears and what the holder
	// stores agree even when the context ends between the two.
	returned, cancelled = true, err != nil && ctx.Err() != nil
	if cancelled {
		return zero, ctx.Err()
	}
	return v, err
}
