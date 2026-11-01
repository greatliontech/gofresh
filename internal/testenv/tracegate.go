package testenv

import (
	"context"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/trace"
)

func formatEvent(ev trace.Event) string {
	return strings.TrimRight(string(trace.FormatText(ev)), "\n")
}

// TraceGateConfig configures which degradation or pass-divergence trace events
// are permitted by a test's zero-unintended-degradation gate.
type TraceGateConfig struct {
	allowToolchainDegradation  bool
	allowToolchainVerdictError bool
	allowToolchainIOError      bool
	allowTwoPassDiff           bool
}

// TraceGateOption customizes a TraceGateConfig.
type TraceGateOption func(*TraceGateConfig)

// AllowToolchainDegradation permits toolchain selection events with a non-empty
// degradation notice.
func AllowToolchainDegradation() TraceGateOption {
	return func(c *TraceGateConfig) { c.allowToolchainDegradation = true }
}

// AllowToolchainVerdictError permits toolchain package_verdict_error events.
func AllowToolchainVerdictError() TraceGateOption {
	return func(c *TraceGateConfig) { c.allowToolchainVerdictError = true }
}

// AllowToolchainIOError permits toolchain package_io_error events.
func AllowToolchainIOError() TraceGateOption {
	return func(c *TraceGateConfig) { c.allowToolchainIOError = true }
}

// AllowTwoPassDiff permits view two_pass_diff events.
func AllowTwoPassDiff() TraceGateOption {
	return func(c *TraceGateConfig) { c.allowTwoPassDiff = true }
}

// WithTraceGate attaches a *trace.Recorder to ctx (tied to t's lifetime so the
// active sink count is released when t finishes) and registers a t.Cleanup
// check asserting that no unintended toolchain degradation or view two-pass
// divergence occurred during the test.
func WithTraceGate(t testing.TB, ctx context.Context, opts ...TraceGateOption) (context.Context, *trace.Recorder) {
	t.Helper()
	if ctx == nil {
		ctx = t.Context()
	}
	ctx, cancel := context.WithCancel(ctx)
	rec := &trace.Recorder{}
	tracedCtx := trace.WithSink(ctx, rec)
	t.Cleanup(func() {
		cancel()
		// Trigger a disabled-check cleanup of the cancelled context sink node.
		trace.Enabled(tracedCtx, trace.DomainSession, "")
		AssertNoUnintendedDegradation(t, rec, opts...)
	})
	return tracedCtx, rec
}

// AssertNoUnintendedDegradation inspects all events recorded in rec and fails t
// if any unpermitted toolchain degradation (package_verdict_error,
// package_io_error, or non-empty selection degradation) or view two_pass_diff
// event was emitted.
func AssertNoUnintendedDegradation(t testing.TB, rec *trace.Recorder, opts ...TraceGateOption) {
	t.Helper()
	if rec == nil {
		return
	}
	var cfg TraceGateConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	for _, ev := range rec.Events() {
		switch ev.Domain {
		case trace.DomainToolchain:
			switch ev.Name {
			case "package_verdict_error":
				if !cfg.allowToolchainVerdictError {
					t.Errorf("unintended toolchain package_verdict_error on %q: %s", ev.Target, formatEvent(ev))
				}
			case "package_io_error":
				if !cfg.allowToolchainIOError {
					t.Errorf("unintended toolchain package_io_error on %q: %s", ev.Target, formatEvent(ev))
				}
			case "selection_resolved":
				if deg := ev.StringField("degradation"); deg != "" && !cfg.allowToolchainDegradation {
					t.Errorf("unintended toolchain selection degradation on %q: %s", ev.Target, deg)
				}
			case "listing_stamp_mismatch", "stamp_fallback":
				if !cfg.allowToolchainDegradation {
					t.Errorf("unintended toolchain %s on %q: %s", ev.Name, ev.Target, formatEvent(ev))
				}
			}
		case trace.DomainView:
			if ev.Name == "two_pass_diff" && !cfg.allowTwoPassDiff {
				t.Errorf("unintended view two_pass_diff on %q: %s", ev.Target, formatEvent(ev))
			}
		}
	}
}

// RequireTraceEvent returns the first recorded event in rec matching domain,
// name, and the optional match predicate, or fails t with the full recorded
// event dump if no matching event was emitted.
func RequireTraceEvent(t testing.TB, rec *trace.Recorder, domain trace.Domain, name string, match func(trace.Event) bool) trace.Event {
	t.Helper()
	if rec == nil {
		t.Fatalf("RequireTraceEvent(%s, %s): nil recorder", domain, name)
	}
	events := rec.Events()
	for _, ev := range events {
		if ev.Domain != domain || ev.Name != name {
			continue
		}
		if match == nil || match(ev) {
			return ev
		}
	}
	var formatted []string
	for _, ev := range events {
		formatted = append(formatted, formatEvent(ev))
	}
	t.Fatalf("missing required trace event domain=%q name=%q among %d recorded event(s):\n%v", domain, name, len(events), formatted)
	return trace.Event{}
}

// AssertNoTraceEvent fails t if any recorded event in rec matches domain,
// name, and the optional match predicate.
func AssertNoTraceEvent(t testing.TB, rec *trace.Recorder, domain trace.Domain, name string, match func(trace.Event) bool) {
	t.Helper()
	if rec == nil {
		return
	}
	for _, ev := range rec.Events() {
		if ev.Domain != domain || ev.Name != name {
			continue
		}
		if match == nil || match(ev) {
			t.Fatalf("unexpected trace event domain=%q name=%q: %s", domain, name, formatEvent(ev))
		}
	}
}
