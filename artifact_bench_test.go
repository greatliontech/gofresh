package gofresh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkArtifact measures file inspection independently of compiler and
// source-analysis work. Fixtures are already in the filesystem cache, so these
// are warm-filesystem observations, not cold-storage throughput measurements.
// Capture includes both agreeing observations and retains an owned byte image;
// validation reopens the same coordinate against an existing immutable image.
//
//gofresh:pure
func BenchmarkArtifact(b *testing.B) {
	for _, size := range []int{4 << 20, 32 << 20} {
		b.Run(fmt.Sprintf("bytes=%d", size), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "retained.test")
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i*31 + i/251)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				b.Fatal(err)
			}
			const pkg = "example.com/artifact"
			snapshot := &Snapshot{
				session:  &Session{build: BuildDescription{Directory: filepath.Dir(path)}},
				packages: []string{pkg},
			}
			description := ArtifactDescription{Identity: "retained", Path: path}
			ctx := context.Background()
			binding, err := snapshot.BindArtifact(ctx, pkg, description)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("capture", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(2 * size))
				for b.Loop() {
					captured, err := snapshot.BindArtifact(ctx, pkg, description)
					if err != nil {
						b.Fatal(err)
					}
					if len(captured.inspected.bytes) != size || captured.inspected.digest != binding.inspected.digest {
						b.Fatal("capture did not retain the complete expected artifact")
					}
				}
			})
			b.Run("validate", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				for b.Loop() {
					if err := binding.inspected.validate(ctx); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
