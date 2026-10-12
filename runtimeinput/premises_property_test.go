package runtimeinput

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/quick"

	"github.com/greatliontech/gofresh/internal/outcome"
)

// The native conjunction is independent of transcript multiplicity and portable
// encoded environment values. Every draw has a supported control and breaks each
// producing premise separately; identity-only finalization never repairs a
// missing outcome method.
func TestProducerPremisesAcrossGeneratedBindings(t *testing.T) {
	root, dir := producerModule(t)
	ctx := t.Context()
	frame := CaptureProducerFrame(ctx, root, dir, FrameOptions{})
	foreign := CaptureProducerFrame(ctx, root, dir, FrameOptions{})
	roots := &Roots{}
	path := filepath.Join(t.TempDir(), "capture")
	var failure string
	check := func(seed uint64, value []byte, repeated uint8) bool {
		env := producerEnv(dir, "PROPERTY="+base64.RawURLEncoding.EncodeToString(value))
		if repeated&1 == 1 {
			env = slices.DeleteFunc(env, func(s string) bool { return strings.HasPrefix(s, "PROPERTY=") })
		}
		r := rand.New(rand.NewSource(int64(seed)))
		identity := fmt.Sprintf("worker-%x", seed)
		changedEnv := append(slices.DeleteFunc(slices.Clone(env), func(s string) bool { return strings.HasPrefix(s, "PROPERTY=") }), "PROPERTY=changed~"+base64.RawURLEncoding.EncodeToString(value))
		for _, mode := range []string{"supported", "missing-receipt", "abnormal", "missing-support", "receipt-span", "receipt-env", "receipt-process", "support-span", "support-env", "support-process", "missing-env", "missing-pwd", "unsupported-open", "unsupported-stat", "unsupported-chdir", "unsupported-unknown", "identity-only"} {
			in := supportedIngest(t, frame, identity, env)
			in.Roots = roots
			log := strings.Repeat("getenv PROPERTY\n", int(repeated%16))
			wantReason := ""
			switch mode {
			case "missing-receipt":
				in.Completion = CompletionReceipt{}
				wantReason = "process completion receipt unavailable"
			case "abnormal":
				in.Completion, _ = frame.Completion(identity, env, "process did not complete")
				wantReason = "process did not complete"
			case "missing-support":
				in.Outcome = OutcomeSupport{}
				wantReason = "operation-outcome support unavailable"
			case "receipt-span":
				in.Completion, _ = foreign.Completion(identity, env, "")
				wantReason = "process completion receipt belongs to a different execution or environment"
			case "receipt-env":
				in.Completion, _ = frame.Completion(identity, changedEnv, "")
				wantReason = "process completion receipt belongs to a different execution or environment"
			case "receipt-process":
				in.Completion, _ = frame.Completion(identity+"-other", env, "")
				wantReason = "process completion receipt belongs to a different execution or environment"
			case "support-span", "support-env", "support-process":
				supportFrame, supportProcess, supportEnv := frame, identity, env
				switch mode {
				case "support-span":
					supportFrame = foreign
				case "support-env":
					supportEnv = changedEnv
				case "support-process":
					supportProcess += "-other"
				}
				binding, err := supportFrame.OutcomeBinding(supportProcess, supportEnv)
				if err != nil {
					t.Fatal(err)
				}
				in.Outcome = outcome.Prepare(binding, []string{supportedSubject}, "")
				wantReason = "operation-outcome support belongs to a different execution or environment"
			case "missing-env", "missing-pwd":
				withoutPWD := slices.DeleteFunc(slices.Clone(env), func(s string) bool { return strings.HasPrefix(s, "PWD=") })
				if mode == "missing-env" {
					withoutPWD = []string{}
				}
				in = supportedIngest(t, frame, identity, withoutPWD)
				in.Roots = roots
				wantReason = "process environment carries no PWD; cwd-anchored reads cannot classify under the frame"
			case "unsupported-open", "unsupported-stat", "unsupported-chdir", "unsupported-unknown":
				log += strings.TrimPrefix(mode, "unsupported-") + " unobserved-file\n"
				in.ExcludedPaths = []string{"pkg/unobserved-file"}
				wantReason = "operation-outcome support does not cover the captured operations"
			}
			// Capabilities keep their original ordering; the independently
			// permuted ingest describes the same environment.
			in.Env = slices.Clone(in.Env)
			r.Shuffle(len(in.Env), func(i, j int) { in.Env[i], in.Env[j] = in.Env[j], in.Env[i] })
			if err := os.WriteFile(path, []byte("# test log\n"+log), 0600); err != nil {
				t.Fatal(err)
			}
			var obs Observation
			var reason string
			var err error
			if mode == "identity-only" {
				obs, reason, err = frame.ObserveInputs(ctx, path, in)
			} else {
				obs, reason, err = frame.Observe(ctx, path, in)
			}
			fail := func(format string, args ...any) bool {
				failure = fmt.Sprintf("seed=%d mode=%s: ", seed, mode) + fmt.Sprintf(format, args...)
				return false
			}
			if err != nil {
				return fail("observation error: %v", err)
			}
			wantSupport := mode == "supported"
			wantIncomplete := !wantSupport && mode != "identity-only"
			if HasOutcomeSupport(obs.Manifest, supportedSubject) != wantSupport || obs.Unverifiable != wantIncomplete || reason != wantReason {
				return fail("premise disposition: %+v, %q", obs, reason)
			}
			conserved := func(stage string, got Observation) bool {
				if HasOutcomeSupport(got.Manifest, supportedSubject) != wantSupport || got.Unverifiable != wantIncomplete || (wantIncomplete && !strings.Contains(got.Reason, wantReason)) {
					return fail("%s changed support class or cause: %+v", stage, got)
				}
				if _, err := CompletedState(got); err != nil {
					return fail("%s unsealed result: %v", stage, err)
				}
				return true
			}
			if !conserved("original", obs) {
				return false
			}
			// Identity conversions and serialized re-admission preserve the
			// already-established class, not the current method's availability.
			absolute, err := Absolute(obs, root, in.Env)
			if err != nil {
				return fail("absolute: %v", err)
			}
			if !conserved("absolute", absolute) {
				return false
			}
			relative, err := Relative(absolute, root, in.Env)
			if err != nil {
				return fail("conversion changed authority: %+v, %v", relative, err)
			}
			if !conserved("relative", relative) {
				return false
			}
			adopted, err := Adopt(relative.Manifest, root, "reader", in.Env)
			if err != nil {
				return fail("readmission changed authority: %+v, %v", adopted, err)
			}
			if !conserved("adopted", adopted) {
				return false
			}
			if HasOutcomeSupport(adopted.Manifest, strings.Repeat("c", 64)) {
				return fail("another subject borrowed persisted support")
			}
		}
		return true
	}
	if !check(0, nil, 0) || !check(1, nil, 1) {
		t.Fatal(failure)
	}
	if err := quick.Check(check, &quick.Config{MaxCount: 20, Rand: rand.New(rand.NewSource(731))}); err != nil {
		t.Fatalf("%s\n%v", failure, err)
	}
}
