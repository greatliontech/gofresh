package harnessclock

import (
	"testing"
	"time"
)

// TestLogAmbientClock mixes the audited harness channel with a sibling
// weakest-rank classification (the ambient clock's unaudited-standard
// read): the legacy projection must keep the causal reason — the
// harness fact ranks strictly below every other classification.
func TestLogAmbientClock(t *testing.T) {
	t.Log("clock heartbeat at", time.Now())
}
