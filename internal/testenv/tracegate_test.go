package testenv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/trace"
)

type spyTB struct {
	testing.TB
	errors []string
	fatals []string
}

func (s *spyTB) Helper() {}

func (s *spyTB) Errorf(format string, args ...any) {
	s.errors = append(s.errors, fmt.Sprintf(format, args...))
}

func (s *spyTB) Fatalf(format string, args ...any) {
	s.fatals = append(s.fatals, fmt.Sprintf(format, args...))
}

//gofresh:pure
func TestTraceGateEnforcesZeroUnintendedDegradationAndCausalWitnesses(t *testing.T) {
	// Verify WithTraceGate synchronously releases its active sink count when its subtest finishes.
	var subCtx context.Context
	t.Run("releases active sink on subtest cleanup", func(t *testing.T) {
		subCtx, _ = WithTraceGate(t, context.Background())
		if !trace.AnyEnabled() || !trace.Enabled(subCtx, trace.DomainSession, "") {
			t.Fatal("expected subCtx trace sink to be active during subtest")
		}
	})
	if trace.AnyEnabled() {
		t.Fatal("expected AnyEnabled() == false immediately after subtest cleanup")
	}
	if trace.Enabled(subCtx, trace.DomainSession, "") {
		t.Fatal("expected subCtx trace sink to be deactivated after subtest cleanup")
	}

	ctx, rec := WithTraceGate(t, context.Background(),
		AllowToolchainDegradation(),
		AllowToolchainVerdictError(),
		AllowToolchainIOError(),
		AllowTwoPassDiff(),
	)

	trace.Emit(ctx, trace.DomainToolchain, "selection_resolved", "/repo",
		trace.Bool("audited", false),
		trace.String("degradation", "unmodeled flag"),
	)
	trace.Emit(ctx, trace.DomainToolchain, "listing_stamp_mismatch", "/goroot",
		trace.String("cached_stamp", "a"),
		trace.String("current_stamp", "b"),
	)
	trace.Emit(ctx, trace.DomainToolchain, "stamp_fallback", "/goroot",
		trace.String("reason", "probe error"),
	)
	trace.Emit(ctx, trace.DomainToolchain, "package_verdict_error", "fmt",
		trace.Err(errors.New("verdict boom")),
	)
	trace.Emit(ctx, trace.DomainToolchain, "package_io_error", "os",
		trace.Err(errors.New("io boom")),
	)
	trace.Emit(ctx, trace.DomainView, "two_pass_diff", "/repo",
		trace.String("diff_field", "closure_hash"),
		trace.String("subject", "example.com/p.F"),
	)

	ev := RequireTraceEvent(t, rec, trace.DomainView, "two_pass_diff", func(e trace.Event) bool {
		return e.StringField("subject") == "example.com/p.F" && e.StringField("diff_field") == "closure_hash"
	})
	if ev.Target != "/repo" {
		t.Fatalf("ev.Target = %q, want /repo", ev.Target)
	}
	AssertNoTraceEvent(t, rec, trace.DomainSession, "check_verdict", nil)

	// Verify unpermitted degradation events fail the gate.
	spy := &spyTB{TB: t}
	AssertNoUnintendedDegradation(spy, rec)
	if len(spy.errors) != 6 {
		t.Fatalf("unpermitted degradation errors = %d (%v), want 6", len(spy.errors), spy.errors)
	}

	// Verify RequireTraceEvent and AssertNoTraceEvent fail when violated.
	spyMissing := &spyTB{TB: t}
	RequireTraceEvent(spyMissing, rec, trace.DomainSession, "nonexistent", nil)
	if len(spyMissing.fatals) != 1 || !strings.Contains(spyMissing.fatals[0], "missing required trace event") {
		t.Fatalf("expected RequireTraceEvent failure, got %v", spyMissing.fatals)
	}

	spyForbidden := &spyTB{TB: t}
	AssertNoTraceEvent(spyForbidden, rec, trace.DomainView, "two_pass_diff", nil)
	if len(spyForbidden.fatals) != 1 || !strings.Contains(spyForbidden.fatals[0], "unexpected trace event") {
		t.Fatalf("expected AssertNoTraceEvent failure, got %v", spyForbidden.fatals)
	}
}
