package closure

import (
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSSAHandlesDoNotInventSourceUnsafePointers exercises the iterator and
// defer-stack handles introduced by the SSA builder, beside real source
// unsafe pointers (REQ-closure-observability-unsafe).
func TestSSAHandlesDoNotInventSourceUnsafePointers(t *testing.T) {
	if testing.Short() {
		t.Skip("builds SSA over module fixtures")
	}
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.com/ssahandles\n\ngo 1.27\n")
	cases := []struct {
		name, source string
		observable   bool
	}{
		{"maprange", `package p
func Subject() int { n := 0; for k, v := range map[int]int{1: 2} { n += k+v }; return n }
`, true},
		{"stringrange", `package p
func Subject() int { n := 0; for _, r := range "abc" { n += int(r) }; return n }
`, true},
		{"deferredrange", `package p
func values(yield func(int) bool) { yield(3) }
func Subject() (n int) { for v := range values { defer func() { n += v }() }; return }
`, true},
		{"sourceunsafe", `package p
import "unsafe"
type rangeIter unsafe.Pointer
func Subject() int { n := 3; p := rangeIter(unsafe.Pointer(&n)); return *(*int)(p) }
`, false},
	}
	var subjects []Subject
	for _, tc := range cases {
		dir := filepath.Join(root, tc.name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dir, "p.go", tc.source)
		subjects = append(subjects, Subject{Package: "example.com/ssahandles/" + tc.name, Symbol: "Subject"})
	}
	h, err := newAt(root)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := h.ComputeObservabilityBatch(subjects)
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range cases {
		p := proofs[subjects[i]]
		if p.Observable != tc.observable || !tc.observable && !strings.Contains(p.Reason, "unsafe pointer") {
			t.Errorf("%s: %+v, want observable=%v", tc.name, p, tc.observable)
		}
	}
}

func TestSSAHandleRecognitionKeepsSourceAndUnknownTypes(t *testing.T) {
	named := func(pkg, name string, underlying types.Type) types.Type {
		var p *types.Package
		if pkg != "" {
			p = types.NewPackage(pkg, "ssa")
		}
		return types.NewNamed(types.NewTypeName(token.NoPos, p, name, nil), underlying, nil)
	}
	for _, tc := range []struct {
		name string
		typ  types.Type
		want bool
	}{
		{"iterator", named("$ssa", "rangeIter", types.Typ[types.UnsafePointer]), true},
		{"defer stack", named("$ssa", "deferStack", types.Typ[types.UnsafePointer]), true},
		{"source name", named("example.com/ssa", "rangeIter", types.Typ[types.UnsafePointer]), false},
		{"unknown token", named("$ssa", "other", types.Typ[types.UnsafePointer]), false},
		{"changed representation", named("$ssa", "rangeIter", types.Typ[types.Int]), false},
		{"no package", named("", "rangeIter", types.Typ[types.UnsafePointer]), false},
		{"source pointer", types.Typ[types.UnsafePointer], false},
	} {
		if got := ssaOpaqueHandle(tc.typ); got != tc.want {
			t.Errorf("%s: handle=%v, want %v", tc.name, got, tc.want)
		}
	}
}
