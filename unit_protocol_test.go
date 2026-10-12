package gofresh

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// The protocol model tests arbitrary submission/abort/cancelled-close sequences.
// It supplies a prepared slot directly: real preparation, normal closing and
// native evidence are exercised by the separate process integration witness.
func FuzzUnitTerminalProtocol(f *testing.F) {
	for _, input := range [][]byte{{0, 1, 2, 3}, {4, 4, 0}, {5, 0}, {0, 0, 5}, {7, 8, 9, 10, 11, 12}} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		u := &Unit{snapshot: &Snapshot{}}
		x := &unitExecution{ready: true, cancel: func() {}}
		u.execution = x
		own := Contribution{unit: u, execution: x}
		other := Contribution{unit: &Unit{}, execution: x}
		cases := []struct {
			terminal Terminal
			valid    bool
		}{
			{Terminal{Kind: NormalCompletion}, true},
			{Terminal{Kind: AbnormalCompletion, Reason: "killed"}, true},
			{Terminal{Kind: NeverStarted, Reason: "no slot"}, true},
			{Terminal{}, false},
			{Terminal{Kind: NormalCompletion, Reason: "not normal"}, false},
			{Terminal{Kind: AbnormalCompletion}, false},
			{Terminal{Kind: 255, Reason: "unknown"}, false},
		}
		ended, settled := false, false
		for i, op := range input {
			switch op % 4 {
			case 0, 1:
				candidate := cases[int(op/4)%len(cases)]
				handle := own
				if op%4 == 1 {
					handle = other
				}
				err := u.Submit(handle, candidate.terminal)
				want := !ended && !settled && op%4 == 0 && candidate.valid
				if (err == nil) != want {
					t.Fatalf("step %d: submission accepted=%t want=%t ended=%t settled=%t", i, err == nil, want, ended, settled)
				}
				if want {
					settled = true
				}
			case 2:
				u.Abort()
				ended = true
			case 3:
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				result, err := u.Close(ctx)
				want := error(context.Canceled)
				if ended {
					want = ErrUnitClosed
				}
				if !errors.Is(err, want) || !reflect.DeepEqual(result, Finalized{}) {
					t.Fatalf("step %d: cancelled close returned evidence or wrong cause: %v (want %v)", i, err, want)
				}
				ended = true
			}
		}
	})
}
