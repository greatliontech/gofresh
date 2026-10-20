package nativeproof

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"testing"

	br "github.com/greatliontech/gofresh/internal/bitrelation"
)

func applicationFSCode(base uint64) []byte {
	code := []byte{0xb8, 0x9e, 0, 0, 0, 0xbf, 2, 0x10, 0, 0, 0x48, 0xbe}
	code = binary.LittleEndian.AppendUint64(code, base)
	return append(code, 0x0f, 0x05)
}

func TestTransitionApplicationAfterFSChange(t *testing.T) {
	const first, second = uint64(0x12340), uint64(0x23450)
	for _, tc := range []struct {
		name       string
		parentBase uint64
		childModel bool
		childSet   bool
		childBase  uint64
	}{
		{"model-free-child", first, false, false, 0},
		{"modeled-child", first, true, false, 0},
		{"failed-parent", ^uint64(0), true, false, 0},
		{"failed-child", first, true, true, ^uint64(0)},
		{"replaced-again", first, true, true, second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := applicationFSCode(tc.parentBase)
			body := []byte{}
			if tc.childSet {
				body = applicationFSCode(tc.childBase)
			}
			body = append(body, hexBytes(t, "b82a000000c3")...)
			f := newApplicationFixture(t, fmt.Sprintf("%x", prefix), fmt.Sprintf("%x", body))
			f.parent.Conditions.Syscall = LinuxAMD64SyscallModel
			f.parent.Conditions.UserAddressBits = 48
			f.parentExp = []TransitionExpansion{{PC: testEntry + uint64(len(prefix)-2)}}
			if tc.childModel {
				f.child.Conditions.Syscall = LinuxAMD64SyscallModel
				f.child.Conditions.UserAddressBits = 48
			}
			if tc.childSet {
				f.childExp = []TransitionExpansion{{PC: applicationChild + uint64(len(applicationFSCode(tc.childBase))-2)}}
			}
			parent, child := f.certificates(t)
			before, _ := parent.Bound()
			independent, _ := child.Bound()
			if !before.Thread.ContextChanged {
				t.Fatal("fixture did not execute the prior context-changing primitive")
			}
			applied, err := CheckTransitionCallReturn(t.Context(), parent, child)
			if err != nil {
				t.Fatal(err)
			}
			bound, ok := applied.BoundFor(f.im)
			if !ok || !applied.AppliesTo(child) || bound.Thread != before.Thread || bound.InputFS != independent.Prefix.InitialFS || bound.ChildEntry.Thread != before.Thread || bound.InputFS.Valid() != tc.childModel {
				t.Fatal("child-relative input state was not associated with actual current FS")
			}
			stateInheritedInputs(t, before, bound.Successor)
			count := 1
			if tc.childSet {
				count++
			}
			if len(bound.Successor.PrimitiveEffects) != count || len(bound.Successor.Abstractions) != count || !bound.Successor.Thread.ContextChanged || !reflect.DeepEqual(bound.Successor.PrimitiveEffects[:len(before.PrimitiveEffects)], before.PrimitiveEffects) || !reflect.DeepEqual(bound.Successor.Abstractions[:len(before.Abstractions)], before.Abstractions) {
				t.Fatal("child application erased prior context-change history")
			}
			for _, initial := range []uint64{0, 0xfedcba, ^uint64(0)} {
				values := map[br.Term]uint64{before.InitialFS: initial}
				want := tc.parentBase
				preserved := false
				if tc.parentBase == ^uint64(0) {
					want, preserved = initial, true
				}
				if tc.childSet && tc.childBase != ^uint64(0) {
					want, preserved = tc.childBase, false
				}
				if got := stateEval(t, bound.Successor.Thread.FS.Value, values); got != want || bound.Successor.Thread.SelectorPreserved != preserved {
					t.Fatalf("current FS or root-relative selector preservation changed: got=%#x want=%#x preserved=%v", got, want, bound.Successor.Thread.SelectorPreserved)
				}
			}
			if tc.childSet && tc.childBase == ^uint64(0) && (!independent.State.Thread.SelectorPreserved || bound.Successor.Thread.SelectorPreserved) {
				t.Fatal("child-relative selector preservation became parent-root preservation")
			}
			if tc.childModel {
				bad := f
				bad.child.Conditions.UserAddressBits = 57
				_, incompatible := bad.certificates(t)
				refused, err := CheckTransitionCallReturn(t.Context(), parent, incompatible)
				var cause *Refusal
				if refused.checked != nil || !errors.As(err, &cause) || cause.Premise != "transition-application-machine" {
					t.Fatalf("current state bypassed a distinct machine configuration: %v", err)
				}
			}
		})
	}
}
