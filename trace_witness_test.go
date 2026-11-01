package gofresh

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/trace"
)

func TestTraceCausalWitnessesAcrossDomains(t *testing.T) {
	dir := t.TempDir()
	depDir := filepath.Join(dir, "dep")
	if err := os.MkdirAll(depDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/witness\n\ngo 1.26\n")
	write("dep/dep.go", "package dep\n\nvar State func(int) int\n\nfunc Touch(fn func(int) int) { State = fn }\n")
	write("pure/pure.go", "package pure\n\nfunc PureAdd(a, b int) int {\n\treturn a + b\n}\n")
	testSource := "package pure\n\nimport \"testing\"\n\nfunc helperVal() int { return 42 }\n\nfunc TestPureAdd(t *testing.T) {\n\tif PureAdd(1, helperVal()) != 43 {\n\t\tt.Fatal(\"bad\")\n\t}\n}\n"
	write("pure/pure_test.go", testSource)

	write("dyn/dyn.go", `package dyn

var globalHook func(int) int

func MutateGlobal(x int) int {
	globalHook = func(v int) int { return v + x }
	return globalHook(x)
}
`)
	write("usedep/usedep.go", `package usedep

import "example.com/witness/dep"

func UseDep(x int) int {
	dep.Touch(func(v int) int { return v + x })
	return x
}
`)
	write("envpkg/envpkg.go", `package envpkg

import "os"

func ReadEnv() string {
	return os.Getenv("WITNESS_KEY")
}

func ReadAllEnviron() []string {
	return os.Environ()
}
`)

	subjPure := Subject{Package: "example.com/witness/pure", Symbol: "PureAdd"}
	subjGlobal := Subject{Package: "example.com/witness/dyn", Symbol: "MutateGlobal"}
	subjDep := Subject{Package: "example.com/witness/usedep", Symbol: "UseDep"}
	subjEnv := Subject{Package: "example.com/witness/envpkg", Symbol: "ReadEnv"}
	subjEnviron := Subject{Package: "example.com/witness/envpkg", Symbol: "ReadAllEnviron"}
	allSubjects := []Subject{subjPure, subjGlobal, subjDep, subjEnv, subjEnviron}

	t.Run("toolchain selection and closure/session causal witnesses", func(t *testing.T) {
		env := gotool.SetEnv(os.Environ(), "PWD", dir)
		sess, ctx, rec := newTracedSession(t, BuildDescription{
			Directory:   dir,
			Environment: env,
			Inputs:      []string{},
		}, SessionPolicy{})

		// 1. Audited toolchain selection emits selection_resolved with audited=true.
		sel, err := ResolveToolchainSelection(ctx, BuildDescription{
			Directory:   dir,
			Environment: env,
		})
		if err != nil {
			t.Fatal(err)
		}
		if sel.ToolchainContent == "" || sel.AdmissionPolicy == "" || sel.SelectionNotice != "" {
			t.Fatalf("unexpected audited ToolchainSelection: %+v", sel)
		}
		testenv.RequireTraceEvent(t, rec, trace.DomainToolchain, "selection_resolved", func(ev trace.Event) bool {
			audited, ok := ev.BoolField("audited")
			return ok && audited && ev.StringField("content_digest") == sel.ToolchainContent && ev.StringField("policy_digest") == sel.AdmissionPolicy
		})

		// 2. Verify session_init + closure witnesses.
		testenv.RequireTraceEvent(t, rec, trace.DomainSession, "session_init", func(ev trace.Event) bool {
			cb, ok := ev.BoolField("complete_build")
			return ok && cb && ev.StringField("dir") == sess.dir
		})

		snap, err := sess.Snapshot(ctx, allSubjects, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		testenv.RequireTraceEvent(t, rec, trace.DomainView, "pass_summary", func(ev trace.Event) bool {
			n, ok := ev.IntField("subjects")
			return ok && n == int64(len(allSubjects))
		})

		// PureAdd must be verifiable with refusal=0 and empty culprit.
		testenv.RequireTraceEvent(t, rec, trace.DomainClosure, "subject_closure", func(ev trace.Event) bool {
			unv, ok := ev.BoolField("unverifiable")
			ref, okRef := ev.IntField("refusal")
			return ev.Target == "example.com/witness/pure.PureAdd" && ok && !unv && okRef && ref == 0 && ev.StringField("culprit") == ""
		})

		// MutateGlobal must name example.com/witness/dyn.globalHook as its exact SharedDynamicState culprit.
		testenv.RequireTraceEvent(t, rec, trace.DomainClosure, "subject_closure", func(ev trace.Event) bool {
			unv, ok := ev.BoolField("unverifiable")
			ref, okRef := ev.IntField("refusal")
			return ev.Target == "example.com/witness/dyn.MutateGlobal" && ok && unv && okRef &&
				ref == int64(closure.SharedDynamicStateRefusal) &&
				ev.StringField("culprit") == "example.com/witness/dyn.globalHook"
		})

		// UseDep must name example.com/witness/dep.State as its exact SharedDynamicState culprit.
		testenv.RequireTraceEvent(t, rec, trace.DomainClosure, "subject_closure", func(ev trace.Event) bool {
			unv, ok := ev.BoolField("unverifiable")
			ref, okRef := ev.IntField("refusal")
			return ev.Target == "example.com/witness/usedep.UseDep" && ok && unv && okRef &&
				ref == int64(closure.SharedDynamicStateRefusal) &&
				ev.StringField("culprit") == "example.com/witness/dep.State"
		})

		// Trigger observability analysis on ReadEnv and ReadAllEnviron via CaptureObservedBatch.
		rec.Reset()
		fps, err := snap.CaptureObservedBatch(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// ReadEnv is observable (os.Getenv with constant key).
		testenv.RequireTraceEvent(t, rec, trace.DomainClosure, "observability", func(ev trace.Event) bool {
			obs, ok := ev.BoolField("observable")
			return ev.Target == "example.com/witness/envpkg.ReadEnv" && ok && obs && ev.StringField("outcome_method") != ""
		})
		// ReadAllEnviron is unobservable (os.Environ is outside the admitted read set).
		testenv.RequireTraceEvent(t, rec, trace.DomainClosure, "observability", func(ev trace.Event) bool {
			obs, ok := ev.BoolField("observable")
			return ev.Target == "example.com/witness/envpkg.ReadAllEnviron" && ok && !obs && strings.Contains(ev.StringField("reason"), "Environ")
		})

		// Check verdicts across Valid and Unverifiable subjects and pin check_verdict witnesses.
		plainFPs, err := snap.CaptureBatch(ctx)
		if err != nil {
			t.Fatal(err)
		}
		rec.Reset()
		if v, err := snap.Check(ctx, plainFPs[subjPure], subjPure); err != nil || v.Status != Valid {
			t.Fatalf("Check(PureAdd) = %+v, %v", v, err)
		}
		testenv.RequireTraceEvent(t, rec, trace.DomainSession, "check_verdict", func(ev trace.Event) bool {
			cause, _ := ev.IntField("cause")
			return ev.Target == "example.com/witness/pure.PureAdd" && ev.StringField("status") == string(Valid) && cause == int64(NoCause)
		})

		rec.Reset()
		if v, err := snap.Check(ctx, plainFPs[subjGlobal], subjGlobal); err != nil || v.Status != Unverifiable {
			t.Fatalf("Check(MutateGlobal) = %+v, %v", v, err)
		}
		testenv.RequireTraceEvent(t, rec, trace.DomainSession, "check_verdict", func(ev trace.Event) bool {
			cause, _ := ev.IntField("cause")
			cond, _ := ev.IntField("condition")
			return ev.Target == "example.com/witness/dyn.MutateGlobal" &&
				ev.StringField("status") == string(Unverifiable) &&
				cause == int64(SharedDynamicStateCause) &&
				cond == int64(Refused) &&
				strings.Contains(ev.StringField("reason"), "example.com/witness/dyn.globalHook")
		})

		rec.Reset()
		if v, err := snap.CheckObserved(ctx, fps[subjEnviron], subjEnviron); err != nil || v.Status != Unverifiable {
			t.Fatalf("CheckObserved(ReadAllEnviron) = %+v, %v", v, err)
		}
		testenv.RequireTraceEvent(t, rec, trace.DomainSession, "check_verdict", func(ev trace.Event) bool {
			cause, _ := ev.IntField("cause")
			return ev.Target == "example.com/witness/envpkg.ReadAllEnviron" &&
				ev.StringField("status") == string(Unverifiable) &&
				cause == int64(ClosureDependenceCause)
		})

		// Stale verdicts on ClosureCause, TestVariantsCause, and RuntimeInputsCause.
		staleClosure := plainFPs[subjPure]
		staleClosure.MaximalClosure = "deadbeef"
		rec.Reset()
		if v, err := snap.Check(ctx, staleClosure, subjPure); err != nil || v.Status != Stale {
			t.Fatalf("Check(staleClosure) = %+v, %v", v, err)
		}
		testenv.RequireTraceEvent(t, rec, trace.DomainSession, "check_verdict", func(ev trace.Event) bool {
			cause, _ := ev.IntField("cause")
			cond, _ := ev.IntField("condition")
			return ev.Target == "example.com/witness/pure.PureAdd" &&
				ev.StringField("status") == string(Stale) &&
				cause == int64(ClosureCause) &&
				cond == int64(Changed)
		})

		staleTV := plainFPs[subjPure]
		staleTV.TestVariantClosure = "deadbeef"
		rec.Reset()
		if v, err := snap.Check(ctx, staleTV, subjPure); err != nil || v.Status != Stale {
			t.Fatalf("Check(staleTV) = %+v, %v", v, err)
		}
		testenv.RequireTraceEvent(t, rec, trace.DomainSession, "check_verdict", func(ev trace.Event) bool {
			cause, _ := ev.IntField("cause")
			cond, _ := ev.IntField("condition")
			return ev.Target == "example.com/witness/pure.PureAdd" &&
				ev.StringField("status") == string(Stale) &&
				cause == int64(TestVariantsCause) &&
				cond == int64(Changed)
		})

		staleRT := plainFPs[subjPure]
		staleRT.RuntimeDigest = "deadbeef"
		rec.Reset()
		if v, err := snap.Check(ctx, staleRT, subjPure); err != nil || v.Status != Stale {
			t.Fatalf("Check(staleRT) = %+v, %v", v, err)
		}
		testenv.RequireTraceEvent(t, rec, trace.DomainSession, "check_verdict", func(ev trace.Event) bool {
			cause, _ := ev.IntField("cause")
			cond, _ := ev.IntField("condition")
			return ev.Target == "example.com/witness/pure.PureAdd" &&
				ev.StringField("status") == string(Stale) &&
				cause == int64(RuntimeInputsCause) &&
				cond == int64(Missing)
		})
	})

	t.Run("degraded toolchain selection and two_pass_diff field witnesses", func(t *testing.T) {
		ctx, rec := testenv.WithTraceGate(t, t.Context(),
			testenv.AllowToolchainDegradation(),
			testenv.AllowTwoPassDiff(),
		)
		degradedEnv := gotool.SetEnv(gotool.SetEnv(os.Environ(), "PWD", dir), "GOFLAGS", "-tags")
		sel, err := ResolveToolchainSelection(ctx, BuildDescription{
			Directory:   dir,
			Environment: degradedEnv,
		})
		if err != nil {
			t.Fatal(err)
		}
		if sel.ToolchainContent != "" || !strings.Contains(sel.SelectionNotice, "-tags (from $GOFLAGS)") {
			t.Fatalf("expected degraded selection notice, got %+v", sel)
		}
		testenv.RequireTraceEvent(t, rec, trace.DomainToolchain, "selection_resolved", func(ev trace.Event) bool {
			audited, ok := ev.BoolField("audited")
			return ok && !audited && strings.Contains(ev.StringField("degradation"), "-tags (from $GOFLAGS)")
		})

		// Verify two_pass_diff on closure_test_variants change during Validate.
		env := gotool.SetEnv(os.Environ(), "PWD", dir)
		sess, err := NewSession(ctx, BuildDescription{
			Directory:   dir,
			Environment: env,
			Inputs:      []string{},
		}, SessionPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		snap, err := sess.Snapshot(ctx, []Subject{subjPure}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		rec.Reset()
		write("pure/pure_test.go", strings.Replace(testSource, "return 42", "return 43", 1))
		t.Cleanup(func() { write("pure/pure_test.go", testSource) })
		if err := snap.Validate(ctx); !errors.Is(err, ErrViewChanged) {
			t.Fatalf("Validate after test_variant edit = %v, want ErrViewChanged", err)
		}
		testenv.RequireTraceEvent(t, rec, trace.DomainView, "two_pass_diff", func(ev trace.Event) bool {
			return ev.Target == "example.com/witness/pure.PureAdd" && ev.StringField("diff_field") == "closure_test_variants"
		})
	})
}

func FuzzUniversalTraceNonInterference(f *testing.F) {
	f.Add(uint8(0), "alpha", true)
	f.Add(uint8(1), "beta", false)
	f.Add(uint8(2), "gamma", true)
	f.Add(uint8(3), "delta", false)

	baseDir := f.TempDir()
	if err := os.WriteFile(filepath.Join(baseDir, "go.mod"), []byte("module example.com/fuzznoninterf\n\ngo 1.26\n"), 0o644); err != nil {
		f.Fatal(err)
	}
	// Pre-warm the session and toolchain listing once before fuzz iterations.
	initSrc := "package fuzznoninterf\n\nimport \"os\"\n\nvar shared int\n\nfunc Pure(x int) int { return x + 1 }\nfunc Env() string { return os.Getenv(\"FUZZ_KEY\") }\nfunc Impure() int { shared++; return shared }\n"
	if err := os.WriteFile(filepath.Join(baseDir, "p.go"), []byte(initSrc), 0o644); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "p_test.go"), []byte("package fuzznoninterf\n\nimport \"testing\"\n\nfunc TestPure(t *testing.T) { _ = Pure(1) }\n"), 0o644); err != nil {
		f.Fatal(err)
	}

	subjPure := Subject{Package: "example.com/fuzznoninterf", Symbol: "Pure"}
	subjEnv := Subject{Package: "example.com/fuzznoninterf", Symbol: "Env"}
	subjImpure := Subject{Package: "example.com/fuzznoninterf", Symbol: "Impure"}
	subjects := []Subject{subjPure, subjEnv, subjImpure}

	f.Fuzz(func(t *testing.T, variant uint8, tag string, pureOverride bool) {
		// Register refreshTraceFromEnv before any t.Setenv so LIFO cleanup order
		// refreshes the ambient trace sink after t.Setenv restores the OS env,
		// even if t.Fatal aborts inside runPipeline(true).
		t.Cleanup(refreshTraceFromEnv)

		// Sanitize tag to a clean identifier/token.
		var clean strings.Builder
		for i := 0; i < len(tag) && clean.Len() < 16; i++ {
			ch := tag[i]
			if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
				clean.WriteByte(ch)
			}
		}
		tok := clean.String()
		if tok == "" {
			tok = "default"
		}

		c1 := int(variant%7) + 1
		src := fmt.Sprintf("package fuzznoninterf\n\nimport \"os\"\n\nvar shared func(int) int\n\nfunc Pure(x int) int { return x + %d }\nfunc Env() string { return os.Getenv(%q) }\nfunc Impure() int { shared = func(v int) int { return v + %d }; return shared(1) }\n",
			c1, "FUZZ_KEY_"+tok, c1)
		testSrc := fmt.Sprintf("package fuzznoninterf\n\nimport \"testing\"\n\nfunc helper_%s() int { return %d }\nfunc TestPure(t *testing.T) { _ = Pure(helper_%s()) }\n",
			tok, c1, tok)
		if err := os.WriteFile(filepath.Join(baseDir, "p.go"), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(baseDir, "p_test.go"), []byte(testSrc), 0o644); err != nil {
			t.Fatal(err)
		}

		type pipelineOutput struct {
			build       BuildDescription
			guards      Guards
			fpBytes     map[Subject][]byte
			obsFpBytes  map[Subject][]byte
			ledger      TestVariantLedger
			obsState    RuntimeState
			verdicts    map[Subject]Verdict
			obsVerdicts map[Subject]Verdict
			explain     Chain
		}

		runPipeline := func(traced bool) pipelineOutput {
			ctx := t.Context()
			var rec *trace.Recorder
			env := gotool.SetEnv(os.Environ(), "PWD", baseDir)
			env = gotool.SetEnv(env, "FUZZ_KEY_"+tok, tok)
			var tracePath string
			if traced {
				tracePath = filepath.Join(t.TempDir(), "trace.jsonl")
				t.Setenv(trace.EnvTrace, "all")
				t.Setenv(trace.EnvTraceFile, tracePath)
				env = gotool.SetEnv(env, trace.EnvTrace, "all")
				env = gotool.SetEnv(env, trace.EnvTraceFile, tracePath)
				ctx, rec = testenv.WithTraceGate(t, ctx)
			} else {
				t.Setenv(trace.EnvTrace, "")
				t.Setenv(trace.EnvTraceFile, "")
				env = gotool.SetEnv(env, trace.EnvTrace, "")
				env = gotool.SetEnv(env, trace.EnvTraceFile, "")
				refreshTraceFromEnv()
				if trace.AnyEnabled() {
					t.Fatal("expected tracing disabled (activeCount == 0) during untraced pipeline run")
				}
			}

			var policy SessionPolicy
			if pureOverride {
				policy.PureSubjects = []Subject{subjImpure}
			}
			sess, err := NewSession(ctx, BuildDescription{
				Directory:   baseDir,
				Environment: env,
				Inputs:      []string{"input:" + tok},
			}, policy)
			if err != nil {
				t.Fatal(err)
			}
			snap, err := sess.Snapshot(ctx, subjects, CodeResult)
			if err != nil {
				t.Fatal(err)
			}
			fps, err := snap.CaptureBatch(ctx)
			if err != nil {
				t.Fatal(err)
			}
			obsFPs, err := snap.CaptureObservedBatch(ctx)
			if err != nil {
				t.Fatal(err)
			}
			bd, err := snap.BuildDescription(subjPure.Package)
			if err != nil {
				t.Fatal(err)
			}
			bracket, err := CaptureBracket(ctx, baseDir, []string{"."})
			if err != nil {
				t.Fatal(err)
			}
			logText := fmt.Sprintf("# test log\ngetenv FUZZ_KEY_%s\n", tok)
			if traced {
				logText += "getenv GOFRESH_TRACE\ngetenv GOFRESH_TRACE_FILE\n"
			}
			obs, err := FromTestLog([]byte(logText), baseDir, baseDir, env, WithCompletedProcess("worker"), WithBracket(bracket))
			if err != nil {
				t.Fatal(err)
			}
			attachedEnvFP, err := snap.AttachObservation(subjEnv, obsFPs[subjEnv], obs)
			if err != nil {
				t.Fatal(err)
			}
			obsFPs[subjEnv] = attachedEnvFP

			fpBytes := make(map[Subject][]byte, len(subjects))
			obsFpBytes := make(map[Subject][]byte, len(subjects))
			for _, s := range subjects {
				b1, err := json.Marshal(fps[s])
				if err != nil {
					t.Fatal(err)
				}
				fpBytes[s] = b1
				b2, err := json.Marshal(obsFPs[s])
				if err != nil {
					t.Fatal(err)
				}
				obsFpBytes[s] = b2
			}
			ledger, err := snap.TestVariantLedger(subjPure)
			if err != nil {
				t.Fatal(err)
			}
			verdicts, err := snap.CheckBatch(ctx, fps)
			if err != nil {
				t.Fatal(err)
			}
			obsVerdicts, err := snap.CheckObservedBatch(ctx, obsFPs)
			if err != nil {
				t.Fatal(err)
			}
			explainChain, err := snap.ExplainDynamicState(ctx, subjImpure.Package, "shared")
			if err != nil {
				t.Fatal(err)
			}
			if traced {
				if len(rec.ByDomain(trace.DomainSession)) == 0 || len(rec.ByDomain(trace.DomainView)) == 0 || len(rec.ByDomain(trace.DomainClosure)) == 0 {
					t.Fatalf("expected session, view, and closure trace events in recorder")
				}
				rawTrace, err := os.ReadFile(tracePath)
				if err != nil || len(bytes.TrimSpace(rawTrace)) == 0 {
					t.Fatalf("expected non-empty JSONL trace file at %s, err=%v", tracePath, err)
				}
				for line := range strings.SplitSeq(strings.TrimSpace(string(rawTrace)), "\n") {
					var parsed map[string]any
					if err := json.Unmarshal([]byte(line), &parsed); err != nil {
						t.Fatalf("invalid JSONL trace line %q: %v", line, err)
					}
				}
			}
			return pipelineOutput{
				build:       bd,
				guards:      snap.guards(),
				fpBytes:     fpBytes,
				obsFpBytes:  obsFpBytes,
				ledger:      ledger,
				obsState:    obs.State,
				verdicts:    verdicts,
				obsVerdicts: obsVerdicts,
				explain:     explainChain,
			}
		}

		untracedOut := runPipeline(false)
		tracedOut := runPipeline(true)
		t.Setenv(trace.EnvTrace, "")
		t.Setenv(trace.EnvTraceFile, "")
		refreshTraceFromEnv()

		if !reflect.DeepEqual(untracedOut.build, tracedOut.build) {
			t.Fatalf("BuildDescription differed under tracing:\nuntraced: %+v\ntraced:   %+v", untracedOut.build, tracedOut.build)
		}
		if untracedOut.guards != tracedOut.guards {
			t.Fatalf("Guards differed under tracing:\nuntraced: %+v\ntraced:   %+v", untracedOut.guards, tracedOut.guards)
		}
		if !reflect.DeepEqual(untracedOut.ledger, tracedOut.ledger) {
			t.Fatalf("TestVariantLedger differed under tracing:\nuntraced: %+v\ntraced:   %+v", untracedOut.ledger, tracedOut.ledger)
		}
		if untracedOut.obsState != tracedOut.obsState {
			t.Fatalf("Observation.State differed under tracing:\nuntraced: %+v\ntraced:   %+v", untracedOut.obsState, tracedOut.obsState)
		}
		if !reflect.DeepEqual(untracedOut.explain, tracedOut.explain) {
			t.Fatalf("ExplainDynamicState Chain differed under tracing:\nuntraced: %+v\ntraced:   %+v", untracedOut.explain, tracedOut.explain)
		}
		for _, s := range subjects {
			if !bytes.Equal(untracedOut.fpBytes[s], tracedOut.fpBytes[s]) {
				t.Fatalf("Fingerprint JSON for %v differed under tracing:\nuntraced: %s\ntraced:   %s", s, untracedOut.fpBytes[s], tracedOut.fpBytes[s])
			}
			if !bytes.Equal(untracedOut.obsFpBytes[s], tracedOut.obsFpBytes[s]) {
				t.Fatalf("Observed Fingerprint JSON for %v differed under tracing:\nuntraced: %s\ntraced:   %s", s, untracedOut.obsFpBytes[s], tracedOut.obsFpBytes[s])
			}
			if !reflect.DeepEqual(untracedOut.verdicts[s], tracedOut.verdicts[s]) {
				t.Fatalf("Check verdict for %v differed under tracing:\nuntraced: %+v\ntraced:   %+v", s, untracedOut.verdicts[s], tracedOut.verdicts[s])
			}
			if !reflect.DeepEqual(untracedOut.obsVerdicts[s], tracedOut.obsVerdicts[s]) {
				t.Fatalf("CheckObserved verdict for %v differed under tracing:\nuntraced: %+v\ntraced:   %+v", s, untracedOut.obsVerdicts[s], tracedOut.obsVerdicts[s])
			}
		}
	})
}
