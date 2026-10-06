//go:build unix

package gotool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A failed sample is memoized like an answered one: two asks of one
// refused (coordinate, environment) spawn once and answer the same
// refusal — the toolchain does not change between two asks in one
// lifetime (REQ-fresh-toolchain-skew).
func TestSamplerMemoizesAFailedSample(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "count")
	env := shimGo(t, "echo x >> "+counter+"\necho 'go: cannot find main module' >&2\nexit 1\n")
	s := &Sampler{}
	ctx := context.Background()
	dir := t.TempDir()
	_, first := s.Sample(ctx, dir, env)
	_, second := s.Sample(ctx, dir, env)
	if first == nil || second == nil || first.Error() != second.Error() {
		t.Fatalf("a refused sample was not memoized: %v then %v", first, second)
	}
	if !strings.Contains(first.Error(), "cannot find main module") {
		t.Fatalf("the refusal lost go's own words: %v", first)
	}
	data, _ := os.ReadFile(counter)
	if n := strings.Count(string(data), "x"); n != 1 {
		t.Fatalf("%d spawns for one refused coordinate, want 1", n)
	}
}

// Concurrent asks on one key wait on the first's spawn: eight asks of
// one coordinate under one environment run the shim once, every ask
// answered with that one sample (REQ-fresh-toolchain-skew).
func TestSamplerSerializesConcurrentAsksOnOneKey(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "count")
	env := shimGo(t, "echo x >> "+counter+"\nsleep 0.3\necho go1.99.0\n")
	s := &Sampler{}
	dir := t.TempDir()
	const asks = 8
	answers := make(chan string, asks)
	var wg sync.WaitGroup
	for i := 0; i < asks; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := s.Sample(context.Background(), dir, env)
			if err != nil {
				t.Errorf("concurrent sample: %v", err)
			}
			answers <- v
		}()
	}
	wg.Wait()
	close(answers)
	for v := range answers {
		if v != "go1.99.0" {
			t.Fatalf("an ask answered %q", v)
		}
	}
	data, _ := os.ReadFile(counter)
	if n := strings.Count(string(data), "x"); n != 1 {
		t.Fatalf("%d spawns for %d concurrent asks on one key, want 1", n, asks)
	}
}

// A waiter on a key another ask is sampling leaves with its own
// cancellation when its context ends first — the first ask's spawn
// runs on and its answer is stored, so a later ask is served without
// a spawn (REQ-fresh-toolchain-skew).
func TestSamplerWaiterLeavesWithItsOwnCancellation(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "count")
	env := shimGo(t, "echo x >> "+counter+"\nsleep 2\necho go1.99.0\n")
	s := &Sampler{}
	dir := t.TempDir()
	first := make(chan error, 1)
	go func() {
		v, err := s.Sample(context.Background(), dir, env)
		if err == nil && v != "go1.99.0" {
			err = fmt.Errorf("first ask answered %q", v)
		}
		first <- err
	}()
	time.Sleep(200 * time.Millisecond)
	timed, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := s.Sample(timed, dir, env)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the waiter answered %v, want its own deadline", err)
	}
	if waited := time.Since(started); waited > time.Second {
		t.Fatalf("the waiter left after %s, want at its own deadline", waited)
	}
	if err := <-first; err != nil {
		t.Fatalf("the first ask: %v", err)
	}
	if v, err := s.Sample(context.Background(), dir, env); err != nil || v != "go1.99.0" {
		t.Fatalf("the later ask = %q, %v", v, err)
	}
	data, _ := os.ReadFile(counter)
	if n := strings.Count(string(data), "x"); n != 1 {
		t.Fatalf("%d spawns, want 1 (the first ask's; the waiter spawned nothing, the later ask was served)", n)
	}
}

// A take that panics — a consumer's hook, recovered by its caller —
// stores nothing and releases the holder: the next ask on the key
// takes again instead of waiting on a take that never ends
// (REQ-fresh-toolchain-skew).
func TestSamplerReleasesTheHolderAfterAPanickingTake(t *testing.T) {
	env := shimGo(t, "echo go1.99.0\n")
	first := true
	s := &Sampler{Runner: Runner{Prepare: func(*exec.Cmd) {
		if first {
			first = false
			panic("the hook's own fault")
		}
	}}}
	dir := t.TempDir()
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the hook's panic did not reach the caller")
			}
		}()
		_, _ = s.Sample(context.Background(), dir, env)
	}()
	timed, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if v, err := s.Sample(timed, dir, env); err != nil || v != "go1.99.0" {
		t.Fatalf("the ask after a panicking take = %q, %v; want the sample taken afresh", v, err)
	}
}
