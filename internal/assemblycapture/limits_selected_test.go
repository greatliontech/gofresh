//go:build linux && !android

package assemblycapture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcquireCumulativeObservationLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-action end-to-end capture bounds")
	}
	f := newActionFixture(t, false)
	baseline, err := Acquire(t.Context(), f.selection, f.provider.ID, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.providers) != 2 || len(baseline.compilers) != 1 {
		t.Fatal("fixture does not exercise several independent actions")
	}
	// Each distinct input is observed once, agreed immediately before use,
	// and observed once more at close. Count from the actual input inventory,
	// rather than consulting the meter or the validation implementation.
	globalBytes := 0
	for _, o := range f.selection.files {
		globalBytes += len(o.data)
	}
	files := baseline.Files()
	localBytes, localFiles, maxActionBytes, maxActionFiles := 0, 0, 0, 0
	for _, inv := range baseline.compilers {
		p, err := parseTool(inv.ExpandedArgs, "compile")
		if err != nil {
			t.Fatal(err)
		}
		paths := append([]string(nil), inv.Sources...)
		for _, key := range []string{"importcfg", "embedcfg", "symabis", "pgoprofile", "coveragecfg"} {
			if name := p.last(key); name != "" {
				paths = append(paths, absolute(inv.CWD, name))
			}
		}
		n := 0
		for _, path := range paths {
			data, ok := files[path]
			if !ok {
				t.Fatal("actual compiler input missing", path)
			}
			n += len(data)
		}
		localBytes += n
		localFiles += len(paths)
		maxActionBytes = max(maxActionBytes, 3*n)
		maxActionFiles = max(maxActionFiles, 3*len(paths))
	}
	for _, p := range baseline.providers {
		// One source, one external include, and the failed CWD/object/tool
		// include candidates. Repeated CWD/top-source spelling is one path.
		paths := map[string]bool{p.Source: true}
		for _, lookup := range baseline.Lookups() {
			if lookup.Name != "capture_choice.h" {
				t.Fatal("unexpected fixture include")
			}
			paths[lookup.Selected] = true
			for _, path := range lookup.Failed {
				paths[path] = true
			}
		}
		n := 0
		for path := range paths {
			n += len(files[path])
		}
		localBytes += n
		localFiles += len(paths)
		maxActionBytes = max(maxActionBytes, 3*n)
		maxActionFiles = max(maxActionFiles, 3*len(paths))
	}
	usage := baseline.Usage()
	readBytes := 0
	for _, n := range usage.InputBytes {
		readBytes += n
	}
	if want := 3 * (globalBytes + localBytes); readBytes != want {
		t.Fatalf("agreement reads not charged exactly: got=%d want=%d usage=%+v", readBytes, want, usage)
	}
	if want := 3 * (len(f.selection.files) + localFiles); usage.Files != want {
		t.Fatalf("agreement file observations not charged: got=%d want=%d", usage.Files, want)
	}
	byteBound := usage.Bytes * 3 / 4
	fileBound := usage.Files * 3 / 4
	if byteBound <= maxActionBytes || fileBound <= maxActionFiles {
		t.Fatal("fixture bound would reject a single action instead of cumulative work")
	}
	for _, tc := range []struct {
		name  string
		limit Limits
	}{
		{"bytes", Limits{Bytes: byteBound}},
		{"files", Limits{Files: fileBound}},
		{"actions", Limits{Actions: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := Acquire(t.Context(), f.selection, f.provider.ID, tc.limit)
			if err == nil || packet != nil || !strings.Contains(err.Error(), tc.name+" bound exhausted") {
				t.Fatalf("cumulative %s acceptance: packet=%v err=%v", tc.name, packet, err)
			}
		})
	}
	// Explicit sufficient finite limits exercise the same complete acquisition.
	if packet, err := Acquire(t.Context(), f.selection, f.provider.ID, Limits{Bytes: usage.Bytes + 1<<20, Files: usage.Files + 16, Actions: usage.Actions + 8}); err != nil || packet == nil {
		t.Fatalf("sufficient cumulative bounds: %v", err)
	}
}

func TestAcquireTemporaryDirectoryWholeWordQuoting(t *testing.T) {
	if testing.Short() {
		t.Skip("actual tool boundary under whitespace TMPDIR")
	}
	dir, err := os.MkdirTemp("", "cap space 'quote-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	t.Setenv("TMPDIR", dir)
	f := newActionFixture(t, false)
	packet, err := Acquire(t.Context(), f.selection, f.provider.ID, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(packet.providers) != 2 {
		t.Fatal("quoted boundary lost final actions")
	}
	for _, p := range packet.providers {
		if p.Invocation.CWD != filepath.Dir(p.Source) {
			t.Fatal("quoted boundary changed real CWD")
		}
		if !strings.Contains(p.Invocation.Output, "cap space 'quote-") {
			t.Fatal("test did not use the selected whitespace namespace")
		}
	}
}
