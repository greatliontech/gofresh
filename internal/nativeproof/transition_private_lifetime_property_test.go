package nativeproof

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// The expected lifetime comes from construction's temporal call order, not PC
// ordering or the checker's retained history: child addresses lie after its
// caller's continuation even though those child transfers execute first.
func checkPrivateLifetimePopulation(t testing.TB, prefixCount, childCount int, wide bool, choice int, value uint64) {
	t.Helper()
	move := func(code []byte, value uint64) []byte {
		if wide {
			code = append(code, 0x48, 0xb8)
			return binary.LittleEndian.AppendUint64(code, value)
		}
		code = append(code, 0xb8)
		return binary.LittleEndian.AppendUint32(code, uint32(value))
	}
	var prefix, body []byte
	var expired []uint64
	for i := range prefixCount {
		expired = append(expired, testEntry+uint64(len(prefix)))
		prefix = move(prefix, value+uint64(i))
	}
	expired = append(expired, testEntry+uint64(len(prefix))) // initiating CALL
	for i := range childCount {
		expired = append(expired, applicationChild+uint64(len(body)))
		body = move(body, value+uint64(i))
	}
	expired = append(expired, applicationChild+uint64(len(body))) // child RET
	body = append(body, 0xc3)
	deadlines := append(expired, testEntry+uint64(len(prefix))+5, testEntry+128)
	index := choice % len(deadlines)
	want := index >= len(expired)
	f := privateLifetimeFixture(t, fmt.Sprintf("%x", prefix), fmt.Sprintf("%x", body), deadlines[index])
	parent, child := privateLifetimeRoot(t, f, TransitionOptions{}), privateLifetimeChild(t, f)
	application, err := CheckTransitionCallReturn(t.Context(), parent, child)
	if !want {
		privateLifetimeRefused(t, application, err)
		return
	}
	if err != nil || !application.AppliesTo(child) {
		t.Fatalf("unexpired constructed invocation refused: %v", err)
	}
	bound, _ := application.BoundFor(f.im)
	result := value + uint64(childCount-1)
	if !wide {
		result = uint64(uint32(result))
	}
	if stateEval(t, bound.Successor.Registers[RAX].Value, nil) != result || bound.Successor.Boundary.PC != f.call+5 || len(bound.Successor.Frames) != 0 {
		t.Fatal("accepted lifetime lost actual child result or return")
	}
}

func TestTransitionPrivateLifetimePopulation(t *testing.T) {
	for prefix := range 4 {
		for child := 1; child <= 4; child++ {
			for _, wide := range []bool{false, true} {
				for deadline := range prefix + child + 4 {
					checkPrivateLifetimePopulation(t, prefix, child, wide, deadline, ^uint64(0)-uint64(child/2))
				}
			}
		}
	}
}

func FuzzTransitionPrivateLifetime(f *testing.F) {
	for _, seed := range [][4]uint8{{0, 0, 0, 0}, {0, 0, 1, 3}, {3, 3, 1, 5}, {3, 3, 0, 10}} {
		f.Add(seed[0], seed[1], seed[2], seed[3], ^uint64(0))
	}
	f.Fuzz(func(t *testing.T, prefix, child, wide, deadline uint8, value uint64) {
		checkPrivateLifetimePopulation(t, int(prefix%4), int(child%4)+1, wide&1 != 0, int(deadline), value)
	})
}
