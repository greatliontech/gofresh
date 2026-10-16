package runtimeinput

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestBracketRetypingRemainsKnownBesideUnhashableContent(t *testing.T) {
	for _, beforeFIFO := range []bool{false, true} {
		dir := t.TempDir()
		p := filepath.Join(dir, "input")
		makeObject := func(fifo bool) {
			t.Helper()
			var err error
			if fifo {
				err = syscall.Mkfifo(p, 0600)
			} else {
				err = os.WriteFile(p, []byte("value"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		makeObject(beforeFIFO)
		bracket := testBracket(t, dir, "input")
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		makeObject(!beforeFIFO)
		observation, err := FromTestLog([]byte("open input\n"), dir, dir, nil, WithCompletedProcess("reader"), WithBracket(bracket))
		if err != nil || !observation.BracketMoved {
			t.Fatalf("known type movement lost, beforeFIFO=%t: %+v %v", beforeFIFO, observation, err)
		}
	}
}
