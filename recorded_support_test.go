package gofresh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/guard"
	"github.com/greatliontech/gofresh/internal/outcome"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// The real-binary producer anchor lives in outcome_test.go. This fixture keeps
// generated record corruption independent of whole-program analysis cost.
func recordedSupportFixture(t testing.TB) (Fingerprint, Subject) {
	t.Helper()
	subject := Subject{Package: "example.com/record", Symbol: "TestEnv"}
	fp := Fingerprint{
		MaximalClosure: strings.Repeat("a", 32), TestVariantClosure: strings.Repeat("b", 32),
		Guards:     guard.Guards{Toolchain: "toolchain", BuildConfig: "build"},
		ResultKind: CodeResult, ClosureStrategy: ClosureStrategy, DynamicStateStrategy: DynamicStateStrategy,
		ObservationAssertion: "caller assertion",
		ObservationProof:     ObservationProof{Strategy: ObservationRTA, Subject: subject, Observable: true},
	}
	fp.ObservationProof.Evidence = observationProofEvidence(fp.MaximalClosure, fp.ObservationAssertion, fp.ObservationProof)
	dir := t.TempDir()
	frame := runtimeinput.CaptureProducerFrame(context.Background(), dir, dir, runtimeinput.FrameOptions{})
	env, err := gotool.EnvForCommand(os.Environ(), dir)
	if err != nil {
		t.Fatal(err)
	}
	env = gotool.SetEnv(env, "RECORDED_INPUT", "original")
	binding, err := frame.OutcomeBinding("producer", env)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := frame.Completion("producer", env, "")
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "input.log")
	if err := os.WriteFile(log, []byte("# test log\ngetenv RECORDED_INPUT\n"), 0600); err != nil {
		t.Fatal(err)
	}
	obs, reason, err := frame.Observe(context.Background(), log, runtimeinput.ProducerIngest{
		Identity: "producer", Env: env, Completion: receipt,
		Outcome: outcome.Prepare(binding, []string{outcomeSubject(fp, subject)}, ""),
	})
	if err != nil || reason != "" {
		t.Fatalf("fixture: %s %v", reason, err)
	}
	fp.RuntimeInputs, fp.RuntimeDigest = obs.Manifest, obs.Digest
	return fp, subject
}

func TestRecordedSupportDoesNotObserveCurrentStateOrUseApplicability(t *testing.T) {
	fp, subject := recordedSupportFixture(t)
	t.Setenv("RECORDED_INPUT", "different current value")
	t.Setenv("PATH", "")
	t.Chdir(t.TempDir())
	fp.InertTestVariantApplicability = InertTestVariantApplicability{Strategy: InertTestVariantExtension, TestVariantClosure: "different"}
	fp.PurityAssertion = "caller assertion"
	if got := ValidateRecordedObservationSupport(fp, subject); got.Status != RecordedSupportNative || got.Reason != "" {
		t.Fatalf("record-only original support = %+v", got)
	}
	fp.ObservationProof = ObservationProof{}
	if got := ValidateRecordedObservationSupport(fp, subject); got.Status != RecordedSupportRefused || got.Reason == "" {
		t.Fatalf("purity supplied native support: %+v", got)
	}
}

func FuzzRecordedObservationSupportRejectsCorruption(f *testing.F) {
	fp, subject := recordedSupportFixture(f)
	for i := 0; i < 23; i++ {
		f.Add(uint8(i), "changed")
	}
	f.Fuzz(func(t *testing.T, operation uint8, salt string) {
		bad, expected := fp, subject
		changed := "changed:" + salt
		switch operation % 23 {
		case 0:
			bad.MaximalClosure += changed
		case 1:
			bad.TestVariantClosure += changed
		case 2:
			bad.Guards.Toolchain += changed
		case 3:
			bad.Guards.BuildConfig += changed
		case 4:
			bad.ObservationAssertion += changed
		case 5:
			bad.ObservationProof.Evidence += changed
		case 6:
			bad.ObservationProof.Strategy += changed
		case 7:
			bad.ObservationProof.Observable = false
		case 8:
			bad.ObservationProof.Reason = changed
		case 9:
			expected.Symbol += changed
		case 10:
			expected.Package += changed
		case 11:
			bad.RuntimeDigest += changed
		case 12:
			bad.RuntimeInputs += "="
		case 13:
			bad.RuntimeInputs = ""
		case 14:
			bad.RuntimeDigest = ""
		case 15:
			bad.ClosureStrategy += changed
		case 16:
			bad.DynamicStateStrategy += changed
		case 17:
			bad.Guards.BuildConfig = ""
		case 18:
			bad.ResultKind = 0
		default:
			data, err := base64.RawURLEncoding.DecodeString(fp.RuntimeInputs)
			if err != nil {
				t.Fatal(err)
			}
			// Preserve the canonical field order while corrupting one premise.
			text := string(data)
			switch operation % 23 {
			case 19:
				text = strings.Replace(text, outcome.Method, "unknown", 1)
			case 20:
				text = strings.Replace(text, outcomeSubject(fp, subject), strings.Repeat("0", 64), 1)
			case 21:
				text = strings.TrimSuffix(text, "}") + `,"unverifiable":["incomplete"]}`
			case 22:
				var doc struct {
					Env []struct {
						Digest string `json:"d"`
					} `json:"env"`
				}
				if err := json.Unmarshal(data, &doc); err != nil || len(doc.Env) != 1 {
					t.Fatalf("fixture env: %v", err)
				}
				text = strings.Replace(text, doc.Env[0].Digest, strings.Repeat("0", 32), 1)
			}
			bad.RuntimeInputs = base64.RawURLEncoding.EncodeToString([]byte(text))
		}
		if got := ValidateRecordedObservationSupport(bad, expected); got.Status != RecordedSupportRefused || got.Reason == "" {
			t.Fatalf("corruption %d admitted: %+v", operation%23, got)
		}
		if got := ValidateRecordedObservationSupport(fp, subject); got.Status != RecordedSupportNative {
			t.Fatalf("original record lost support: %+v", got)
		}
	})
}
