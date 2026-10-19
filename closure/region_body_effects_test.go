package closure

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/greatliontech/go-x-tools/go/ssa"
)

func TestSourceContinuationInterpretsSelectedGoBodies(t *testing.T) {
	if testing.Short() {
		t.Skip("loads selected typed source and checks call-context effects")
	}
	for _, tc := range []struct {
		name, body   string
		reads, calls int
		refused      bool
	}{
		{"load", "return *p", 1, 1, false},
		{"both-loads", "a := *p; b := *p; if a != b { panic(\"inconsistent\") }; return b", 2, 1, false},
		{"nested-invocations", "a := Leaf(p); b := Leaf(p); if a != b { panic(\"inconsistent\") }; return b", 2, 3, false},
		{"changed-return", "return 8", 0, 0, true},
		{"hidden-opaque-call", "Opaque(p); return *p", 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			text := fmt.Sprintf(`package p
var Cell uint64
func Opaque(p *uint64)
func Stop(p *uint64) {}
func Leaf(p *uint64) uint64 { return *p }
func Read(p *uint64) uint64 { %s }
func Run() {
	Cell = 7
	a := Read(&Cell)
	if a != 7 { panic("first") }
	Cell = 9
	b := Read(&Cell)
	if b != 9 { panic("second") }
	Stop(&Cell)
}
`, tc.body)
			writeTree(t, dir, map[string]string{"go.mod": "module example.com/bodyeffects\n\ngo 1.27\n", "p.go": text})
			source := assemblyReferenceSelectedSource(t, dir)
			root := source.prog.Roots["Run"]
			var reads []*ssa.Call
			var stop *ssa.Call
			var returned *ssa.Return
			for _, block := range root.Blocks {
				for _, instruction := range block.Instrs {
					if ret, ok := instruction.(*ssa.Return); ok {
						returned = ret
					}
					call, ok := instruction.(*ssa.Call)
					if !ok {
						continue
					}
					switch call.Call.StaticCallee() {
					case source.prog.Roots["Read"]:
						reads = append(reads, call)
					case source.prog.Roots["Stop"]:
						stop = call
					}
				}
			}
			if len(reads) != 2 || stop == nil {
				t.Fatal("fixture call population differs")
			}
			prefix, err := checkSourceOperandPrefix(t.Context(), source, root, reads[0], defaultRegistrationLimits())
			if err != nil {
				t.Fatal(err)
			}
			middle, err := checkSourceOperandContinuation(t.Context(), prefix, reads[1], nil)
			if tc.refused {
				if err == nil {
					t.Fatal("changed or uncovered selected body admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			end, err := checkSourceOperandContinuation(t.Context(), middle, stop, nil)
			if err != nil {
				t.Fatal(err)
			}
			for phase, proof := range []*sourceOperandPrefix{middle, end} {
				trace := proof.region.packet.trace
				if len(trace.calls) != tc.calls {
					t.Fatalf("phase %d: %d calls, want %d", phase, len(trace.calls), tc.calls)
				}
				wantAccesses := tc.reads
				if phase == 0 {
					wantAccesses++
				}
				if len(trace.accesses) != wantAccesses {
					t.Fatalf("phase %d: %+v", phase, trace.accesses)
				}
				for i, access := range trace.accesses[:tc.reads] {
					if access.write || access.locked || access.value != uint64(7+2*phase) || access.invocation == (regionInvocation{}) || access.instruction.Parent() == root {
						t.Fatalf("phase %d read %d lost actual callee provenance/value: %+v", phase, i, access)
					}
				}
				if tc.name == "nested-invocations" {
					a, b := trace.accesses[0], trace.accesses[1]
					if a.instruction != b.instruction || a.invocation == b.invocation {
						t.Fatal("two invocations of one actual load were conflated")
					}
				}
			}
			if middle.region.packet.trace.accesses[0].invocation == end.region.packet.trace.accesses[0].invocation {
				t.Fatal("later root call reused an earlier activation identity")
			}
			complete, err := checkSourceReturnContinuation(t.Context(), middle, returned, nil)
			if err != nil {
				t.Fatal(err)
			}
			trace := complete.region.packet.trace
			if complete.returned != returned || len(trace.calls) != tc.calls+1 || len(trace.accesses) != tc.reads || len(trace.instructions) == 0 || trace.instructions[len(trace.instructions)-1].instruction != returned {
				t.Fatalf("source completion omitted actual callee or root return: %+v", trace)
			}
			for _, access := range trace.accesses {
				if access.write || access.value != 9 {
					t.Fatalf("source completion lost current state: %+v", access)
				}
			}
			other := source.prog.Roots["Stop"]
			foreign := other.Blocks[0].Instrs[len(other.Blocks[0].Instrs)-1].(*ssa.Return)
			if _, err := checkSourceReturnContinuation(t.Context(), middle, foreign, nil); err == nil {
				t.Fatal("foreign return endpoint admitted")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := checkSourceReturnContinuation(ctx, middle, returned, nil); !errors.Is(err, context.Canceled) {
				t.Fatalf("completion ignored cancellation: %v", err)
			}
		})
	}
}
