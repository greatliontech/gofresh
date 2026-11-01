package guard

import (
	"context"
	"errors"
	"testing"
)

func TestCaptureRuntimeAdmission(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		env  []string
		kind Kind
	}{
		{"nil context", nil, nil, CodeResult},
		{"cancelled context", cancelled, nil, CodeResult},
		{"missing kind", t.Context(), nil, invalidKind},
		{"unknown kind", t.Context(), nil, Kind(99)},
		{"duplicate environment", t.Context(), []string{"A=1", "A=2"}, CodeResult},
		{"malformed environment", t.Context(), []string{"A"}, Measurement},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CaptureRuntime(tc.ctx, tc.env, tc.kind)
			if err == nil || got != (RuntimeGuards{}) {
				t.Fatalf("invalid runtime capture admitted: %+v %v", got, err)
			}
			if tc.ctx == cancelled && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
	if got, err := CaptureRuntime(t.Context(), []string{}, CodeResult); err != nil || got != (RuntimeGuards{}) {
		t.Fatalf("code capture required measurement facts: %+v %v", got, err)
	}
}

func TestRuntimeCaptureCancellationOutranksMachineAnswer(t *testing.T) {
	for _, machineError := range []error{nil, errors.New("probe refused")} {
		ctx, cancel := context.WithCancel(t.Context())
		got, err := captureRuntimeFor(ctx, nil, Measurement, func() (MachineFacts, error) {
			cancel()
			return MachineFacts{CPUModel: "captured"}, machineError
		}, func([]string) string {
			t.Fatal("cancelled machine capture continued into runtime capture")
			return ""
		})
		cancel()
		if !errors.Is(err, context.Canceled) || got != (RuntimeGuards{}) {
			t.Fatalf("cancelled machine capture returned an answer: %+v %v", got, err)
		}
	}
}
