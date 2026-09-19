package gofresh

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// TestProgressDiagnosticRendersDetailBearingEventsOnly pins the one
// diagnostic rendering: a detail-bearing event renders its phase, its
// package where it names one, and its detail; a keep-alive event
// renders nothing; and the diagnostics sink writes exactly the
// renderings, one prefixed line each.
func TestProgressDiagnosticRendersDetailBearingEventsOnly(t *testing.T) {
	cases := []struct {
		event Progress
		line  string
		ok    bool
	}{
		{Progress{Phase: "toolchain-unaudited", Detail: "selection \"race\" is unwalked"}, "toolchain-unaudited — selection \"race\" is unwalked", true},
		{Progress{Phase: "analysis-unavailable", Package: "example.com/m/a", Detail: "provenance"}, "analysis-unavailable example.com/m/a — provenance", true},
		{Progress{Phase: "listing-unmodelled", Package: "example.com/m/a", Detail: "go.mod:3: bad directive\ngo.mod:4: worse\n"}, "listing-unmodelled example.com/m/a — go.mod:3: bad directive; go.mod:4: worse", true},
		{Progress{Phase: "cancelled", Detail: "kept two\r\nlost one"}, "cancelled — kept two; lost one", true},
		{Progress{Phase: "load", Package: "example.com/m/a", Index: 1, Total: 2}, "", false},
		{Progress{Phase: "served", Served: "effect scan", Index: 3}, "", false},
	}
	var out bytes.Buffer
	sink := DiagnosticsTo(&out)
	var want bytes.Buffer
	for _, c := range cases {
		line, ok := c.event.Diagnostic()
		if line != c.line || ok != c.ok {
			t.Errorf("Diagnostic(%+v) = %q, %v; want %q, %v", c.event, line, ok, c.line, c.ok)
		}
		sink(c.event)
		if c.ok {
			want.WriteString("gofresh: " + c.line + "\n")
		}
	}
	if out.String() != want.String() {
		t.Fatalf("sink wrote:\n%s\nwant:\n%s", out.String(), want.String())
	}
	// The sink serializes its writes: concurrent events over one buffer
	// leave every line whole and every diagnostic present. Each burst
	// starts on one barrier so the writers genuinely overlap, and the
	// burst repeats so a lucky serialization cannot hide an unguarded
	// write.
	const burst, bursts = 256, 8
	for round := 0; round < bursts; round++ {
		var shared bytes.Buffer
		concurrent := DiagnosticsTo(&shared)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				concurrent(Progress{Phase: "toolchain-unaudited", Detail: strings.Repeat("x", 200) + " " + strconv.Itoa(i)})
			}(i)
		}
		close(start)
		wg.Wait()
		lines := strings.Split(strings.TrimSuffix(shared.String(), "\n"), "\n")
		if len(lines) != burst {
			t.Fatalf("burst %d: concurrent sink wrote %d lines, want %d", round, len(lines), burst)
		}
		for _, l := range lines {
			if !strings.HasPrefix(l, "gofresh: toolchain-unaudited — "+strings.Repeat("x", 200)+" ") {
				t.Fatalf("burst %d: a concurrent line is torn: %q", round, l)
			}
		}
	}
}
