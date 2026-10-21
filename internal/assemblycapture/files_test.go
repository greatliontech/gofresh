package assemblycapture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestObservationStreamingMatchesRetainedBytes(t *testing.T) {
	for _, size := range []int{0, 1, 32767, 32768, 32769, 2*32768 + 11} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "input")
			data := bytes.Repeat([]byte{0x5a}, size)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			want, err := readObservation(t.Context(), path, nil)
			if err != nil {
				t.Fatal(err)
			}
			check := func(expected bool) {
				t.Helper()
				limits, _ := (Limits{}).normalized()
				m := &meter{ctx: t.Context(), limits: limits}
				got, err := matchesObservation(t.Context(), path, want, m)
				if err != nil || got != expected {
					t.Fatalf("match=%v err=%v; want %v", got, err, expected)
				}
				if m.bytes != size || m.files != 1 {
					t.Fatalf("incomplete observation: bytes=%d files=%d", m.bytes, m.files)
				}
				if !bytes.Equal(want.data, bytes.Repeat([]byte{0x5a}, size)) {
					t.Fatal("comparison changed the retained input")
				}
				retained, err := readObservation(t.Context(), path, nil)
				if err != nil || sameObservation(want, retained) != got {
					t.Fatalf("streaming and retained comparisons disagree: %v", err)
				}
			}
			check(true)
			for _, offset := range []int{0, 32767, 32768, size - 1} {
				if offset < 0 || offset >= size {
					continue
				}
				data[offset] ^= 0xff
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, want.info.ModTime(), want.info.ModTime()); err != nil {
					t.Fatal(err)
				}
				check(false) // Metadata equality cannot hide changed content.
				data[offset] ^= 0xff
			}
		})
	}
}

func TestObservationStreamingNamespaceAndLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	absent, err := readObservation(t.Context(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	check := func(want fileObservation, expected bool) {
		t.Helper()
		got, err := matchesObservation(t.Context(), path, want, nil)
		if err != nil || got != expected {
			t.Fatalf("match=%v err=%v; want %v", got, err, expected)
		}
	}
	check(absent, true)
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	check(absent, false)
	want, err := readObservation(t.Context(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"ab", "abcd"} {
		other := want
		other.data = []byte(text)
		check(other, false) // Content length matters even beside matching metadata.
	}
	for _, text := range []string{"ab", "abcd"} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		check(want, false)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	check(want, false)
	check(absent, true)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := matchesObservation(t.Context(), path, absent, nil); got || err == nil {
		t.Fatal("a nonregular input became an absent lookup")
	}
}

func TestObservationStreamingIdentityAndResolution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	if err := os.WriteFile(path, []byte("same bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	want, err := readObservation(t.Context(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, want.data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, want.info.ModTime(), want.info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if same, err := matchesObservation(t.Context(), path, want, nil); err != nil || same {
		t.Fatalf("replacement identity: match=%v err=%v", same, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	want, err = readObservation(t.Context(), link, nil)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Link(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(alias, link); err != nil {
		t.Fatal(err)
	}
	if same, err := matchesObservation(t.Context(), link, want, nil); err != nil || same {
		t.Fatalf("changed resolution of the same object: match=%v err=%v", same, err)
	}
}

type observationCancelAfterRead struct {
	context.Context
	meter *meter
}

func (c *observationCancelAfterRead) Err() error {
	if c.meter.bytes != 0 {
		return context.Canceled
	}
	return c.Context.Err()
}

func TestObservationStreamingCancellationAndBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	data := bytes.Repeat([]byte{1}, 3*32768)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	want, err := readObservation(t.Context(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	data[0] = 2
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	limits, _ := (Limits{}).normalized()
	m := &meter{limits: limits}
	ctx := &observationCancelAfterRead{Context: t.Context(), meter: m}
	m.ctx = ctx
	if got, err := matchesObservation(ctx, path, want, m); got || !errors.Is(err, context.Canceled) {
		t.Fatalf("a mismatch bypassed cancellation: match=%v err=%v", got, err)
	}
	if m.bytes == 0 || m.bytes >= len(data) {
		t.Fatal("cancellation did not interrupt a partial observation")
	}
	limits.Bytes = len(data) - 1
	m = &meter{ctx: t.Context(), limits: limits}
	if got, err := matchesObservation(t.Context(), path, want, m); got || err == nil {
		t.Fatal("a mismatch bypassed the complete read budget")
	}
}
