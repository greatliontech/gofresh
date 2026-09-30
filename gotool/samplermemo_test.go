//go:build unix

package gotool

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
