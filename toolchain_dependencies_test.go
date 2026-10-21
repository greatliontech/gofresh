package gofresh

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure"
	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/runtimeinput"
)

// A reported version is unchanged while real selected stdlib behavior moves.
// Both stored proof reuse and ordinary explicit-purity reuse need the content
// dependency; the latter reaches a package outside the admission surface.
func TestToolchainContentBindsRecordedApplicability(t *testing.T) {
	if testing.Short() {
		t.Skip("clones a toolchain and checks real source changes")
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux outcome support and reflink fixture")
	}
	originalRoot := runtime.GOROOT()
	for _, tc := range []struct {
		name, source, file, old, replacement, after string
		observed                                    bool
	}{
		{"observed", "package stdlibdep\nimport \"strings\"\nfunc Value() int { return strings.Compare(\"a\", \"a\") }\n", "strings/compare.go", "return bytealg.CompareString(a, b)", "return bytealg.CompareString(a, b) + 3", "3", true},
		{"asserted-pure", "package stdlibdep\nimport \"image/color\"\n//gofresh:pure\nfunc Value() int { y, _, _ := color.RGBToYCbCr(0, 0, 0); return int(y) }\n", "image/color/ycbcr.go", "r1 := int32(r)", "r1 := int32(r) + 255", "76", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			cache := t.TempDir()
			t.Setenv("XDG_CACHE_HOME", cache)
			root := filepath.Join(t.TempDir(), "go")
			copy := exec.CommandContext(ctx, "cp", "-a", "--reflink=auto", originalRoot, root)
			if out, err := copy.CombinedOutput(); err != nil {
				t.Fatalf("clone: %v %s", err, out)
			}
			t.Setenv("GOROOT", root)
			t.Setenv("GOTOOLCHAIN", "local")
			t.Setenv("GOENV", "off")
			t.Setenv("GOFLAGS", "")
			t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
			dir := t.TempDir()
			for name, text := range map[string]string{
				"go.mod":        "module example.com/stdlibdep\n\ngo 1.27\n",
				"value.go":      tc.source,
				"value_test.go": "package stdlibdep\nimport \"testing\"\nfunc TestValue(t *testing.T) { Value() }\n",
				"cmd/main.go":   "package main\nimport (\"fmt\"; p \"example.com/stdlibdep\")\nfunc main() { fmt.Print(p.Value()) }\n",
			} {
				path := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			subject := Subject{Package: "example.com/stdlibdep", Symbol: "Value"}
			newView := func() *View {
				t.Helper()
				e, err := New(WithDir(dir))
				if err != nil {
					t.Fatal(err)
				}
				v, err := e.NewView(ctx, []Subject{subject}, dir)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			runValue := func(want string) {
				t.Helper()
				cmd := exec.CommandContext(ctx, "go", "run", "./cmd")
				cmd.Dir = dir
				out, err := cmd.CombinedOutput()
				if err != nil || string(out) != want {
					t.Fatalf("actual value=%q want=%q error=%v", out, want, err)
				}
			}
			capture := func(v *View) (Fingerprint, error) {
				if tc.observed {
					return v.CaptureObserved(ctx, subject)
				}
				return v.Capture(ctx, subject)
			}
			check := func(v *View, f Fingerprint) (Verdict, error) {
				if tc.observed {
					return v.CheckObserved(ctx, f, subject)
				}
				return v.Check(ctx, f, subject)
			}
			producer := newView()
			record, err := capture(producer)
			if err != nil {
				t.Fatal(err)
			}
			if tc.observed {
				if !record.ObservationProof.Observable {
					t.Fatalf("initial proof: %+v", record.ObservationProof)
				}
				record, err = producer.AttachObservation(subject, record, supportedObservation(t, producer, dir, dir, "execution", ""))
				if err != nil {
					t.Fatal(err)
				}
			} else if record.PurityAssertion == "" {
				t.Fatal("missing explicit-purity control")
			}
			if err := producer.Validate(ctx); err != nil {
				t.Fatal(err)
			}
			if verdict, err := check(newView(), record); err != nil || verdict.Status != Valid {
				t.Fatalf("unchanged control: %+v %v", verdict, err)
			}
			runValue("0")
			pending := newView()
			pendingRecord, err := capture(pending)
			if err != nil {
				t.Fatal(err)
			}
			if tc.observed {
				_, err = pending.AttachObservation(subject, pendingRecord, supportedObservation(t, pending, dir, dir, "pending", ""))
				if err != nil {
					t.Fatal(err)
				}
			}
			file := filepath.Join(root, "src", tc.file)
			source, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			changed := strings.Replace(string(source), tc.old, tc.replacement, 1)
			if changed == string(source) {
				t.Fatal("source anchor absent")
			}
			if err := os.WriteFile(file, []byte(changed), 0o644); err != nil {
				t.Fatal(err)
			}
			runValue(tc.after)
			if err := pending.Validate(ctx); !errors.Is(err, ErrViewChanged) {
				t.Fatalf("closing accepted changed selected source: %v", err)
			}
			if !tc.observed {
				notice, err := closure.ToolchainSelectionNoticeResolved(ctx, gotool.NewEnvReader(gotool.Runner{}, dir, os.Environ()), nil)
				if err != nil || notice != "" {
					t.Fatalf("outside-audit control changed admission: %s %v", notice, err)
				}
			}
			var warm Fingerprint
			for _, state := range []string{"warm", "discarded-cache"} {
				if state == "discarded-cache" {
					if err := os.RemoveAll(filepath.Join(cache, "gofresh")); err != nil {
						t.Fatal(err)
					}
				}
				view := newView()
				current, err := capture(view)
				if err != nil {
					t.Fatal(err)
				}
				if current.Guards.Toolchain != record.Guards.Toolchain || current.MaximalClosure != record.MaximalClosure {
					t.Fatal("fixture changed the reported version or module-source hash")
				}
				if current.ToolchainContent == "" || current.ToolchainContent == record.ToolchainContent {
					t.Fatal("selected stdlib content did not move")
				}
				if current.AdmissionPolicy != record.AdmissionPolicy {
					t.Fatal("a source edit moved the policy identity")
				}
				if tc.observed && current.ObservationProof.Observable {
					t.Fatal("unlisted source retained an admitted proof")
				}
				if state == "warm" {
					warm = current
				} else if current.ObservationProof != warm.ObservationProof || current.ToolchainContent != warm.ToolchainContent {
					t.Fatal("warm and discarded-cache derivations disagree")
				}
				if verdict, err := check(view, record); err != nil || verdict.Status != Stale || verdict.Reason != "toolchain content" {
					t.Fatalf("%s old record: %+v %v", state, verdict, err)
				}
				legacy := record
				legacy.ToolchainContent = ""
				if verdict, err := check(view, legacy); err != nil || verdict.Status != Unverifiable {
					t.Fatalf("missing historical content: %+v %v", verdict, err)
				}
			}
		})
	}
}

// Rebinding outer data cannot lend a proof or outcome a dependency it did not
// carry when produced. This is an integrity check, not provenance authentication.
func TestObservationProofBindsToolchainDependencies(t *testing.T) {
	subject := Subject{Package: "p", Symbol: "F"}
	record := Fingerprint{MaximalClosure: "core", ToolchainContent: "content", AdmissionPolicy: "policy", ObservationAssertion: "caller assertion", ObservationProof: ObservationProof{Strategy: ObservationRTA, Subject: subject, Observable: true}}
	record.ObservationProof.Evidence = observationProofEvidence(record)
	if !compatibleObservationProof(record, subject) {
		t.Fatal("positive proof control refused")
	}
	identity := outcomeSubject(record, subject)
	for _, change := range []func(*Fingerprint){
		func(f *Fingerprint) { f.ToolchainContent = "other" },
		func(f *Fingerprint) { f.ToolchainContent = "" },
		func(f *Fingerprint) { f.AdmissionPolicy = "other" },
		func(f *Fingerprint) { f.AdmissionPolicy = "" },
	} {
		moved := record
		change(&moved)
		if compatibleObservationProof(moved, subject) || outcomeSubject(moved, subject) == identity {
			t.Fatal("borrowed dependency admitted")
		}
	}
	old := record
	old.ObservationProof.Strategy = "gofresh/observation-rta@43"
	old.ObservationProof.Evidence = observationProofEvidence(old)
	if compatibleObservationProof(old, subject) {
		t.Fatal("historical strategy acquired new compatibility")
	}
}

// A historical checker fixture can carry a different producing policy while
// its source, proof disposition and runtime inputs otherwise agree. The live
// checker must judge policy compatibility, not just that fixture's integrity.
func TestPolicyMismatchCannotLiftClosureRefusal(t *testing.T) {
	if testing.Short() {
		t.Skip("constructs an outcome-supported historical fixture")
	}
	dir := writeSupportedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := engine.NewView(t.Context(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	control, err := producer.CaptureObserved(t.Context(), subject)
	if err != nil || !control.ObservationProof.Observable {
		t.Fatalf("control: %+v %v", control, err)
	}
	// Model the stored policy of an older build after establishing the shared
	// disposition. This is not a claim of production under that live policy.
	cl := producer.facts.closure(subject)
	if cl.AdmissionPolicy == "" {
		t.Fatal("current policy missing")
	}
	cl.AdmissionPolicy = "historical-" + cl.AdmissionPolicy
	producer.facts.maximal[subject] = testSubjectFacts(cl)
	recorded, err := producer.CaptureObserved(t.Context(), subject)
	if err != nil {
		t.Fatal(err)
	}
	observation := supportedObservation(t, producer, dir, dir, "historical", "getenv OUTCOME_VALUE\n")
	recorded, err = producer.AttachObservation(subject, recorded, observation)
	if err != nil {
		t.Fatal(err)
	}
	if !compatibleObservationProof(recorded, subject) || !runtimeinput.HasOutcomeSupport(recorded.RuntimeInputs, outcomeSubject(recorded, subject)) {
		t.Fatal("historical checker fixture lacks internally bound support")
	}
	current, err := engine.NewView(t.Context(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if verdict, err := current.CheckObserved(t.Context(), recorded, subject); err != nil || verdict.Status != Unverifiable {
		t.Fatalf("policy mismatch lifted the closure refusal: %+v %v", verdict, err)
	}
}
