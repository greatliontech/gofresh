package gofresh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/greatliontech/gofresh/gotool"
	"github.com/greatliontech/gofresh/runtimeinput"
)

func TestProducerSnapshotRuntimePartitions(t *testing.T) {
	if testing.Short() {
		t.Skip("loads a multi-package source generation and validates producer transactions")
	}
	ctx := t.Context()
	dir := t.TempDir()
	for name, text := range map[string]string{
		"go.mod": "module example.com/partitions\n\ngo 1.27.0\n",
		"a/a.go": "package a\nimport \"os\"\nfunc F() string { return os.Getenv(\"PWD\") }\n",
		"b/b.go": "package b\nimport \"os\"\nfunc F() string { return os.Getenv(\"PWD\") }\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	subjects := []Subject{{Package: "example.com/partitions/a", Symbol: "F"}, {Package: "example.com/partitions/b", Symbol: "F"}}
	session, err := NewSession(ctx, BuildDescription{Directory: dir, Environment: os.Environ(), Inputs: []string{}}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	root, err := session.Snapshot(ctx, subjects, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := root.CaptureObservedBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Close the source transaction before deriving: its seal cannot close either
	// runtime partition. Its pre-execution proof provenance must survive selection.
	closing, cancel := context.WithCancel(ctx)
	cancel()
	if err := root.Validate(closing); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled source transaction close = %v", err)
	}
	bindings := make([]*RuntimeBinding, 2)
	views := make([]*Snapshot, 2)
	observations := make([]runtimeinput.Observation, 2)
	for i, name := range []string{"a", "b"} {
		bindings[i], err = root.BindRuntime(ctx, RuntimeDescription{Directory: name})
		if err != nil {
			t.Fatal(err)
		}
		views[i], err = bindings[i].ProducerSnapshot([]Subject{subjects[i], subjects[i]})
		if err != nil {
			t.Fatal(err)
		}
		if len(views[i].subjects) != 1 || !views[i].capturedObserved[subjects[i]] || views[i].sealed {
			t.Fatalf("partition lost scope/proof provenance or copied seal: %+v", views[i])
		}
		views[i].beforePreciseAnalysis = func() { t.Fatal("selection discarded the pre-execution source proof") }
		captured, err := views[i].CaptureObservedBatch(ctx)
		if err != nil || captured[subjects[i]] != proofs[subjects[i]] {
			t.Fatalf("partition capture changed source/build proof: %v, %v", captured, err)
		}
		if _, err := bindings[i].ProducerSnapshot([]Subject{{Package: subjects[i].Package, Symbol: "Outside"}}); err == nil {
			t.Fatal("accepted an out-of-snapshot subject")
		}
		if _, err := bindings[i].ProducerSnapshot(nil); err == nil {
			t.Fatal("accepted an empty producer scope")
		}
		// PWD is the actual package process directory, not the root build PWD.
		processDir := filepath.Join(dir, name)
		env, err := gotool.EnvForCommand(os.Environ(), processDir)
		if err != nil {
			t.Fatal(err)
		}
		observation, err := runtimeinput.FromTestLog([]byte("getenv PWD\n"), dir, processDir, env,
			runtimeinput.WithCompletedProcess(name), runtimeinput.WithBracket(testObservationBracket(t, dir)))
		if err != nil {
			t.Fatal(err)
		}
		attached, err := views[i].AttachObservation(subjects[i], proofs[subjects[i]], observation)
		if err != nil {
			t.Fatal(err)
		}
		observations[i] = observation
		// The selection must preserve compilation identity and the identity-only
		// manifest byte-for-byte rather than synthesizing completion support.
		if attached.Guards != proofs[subjects[i]].Guards || attached.RuntimeInputs != observation.Manifest || attached.RuntimeDigest != observation.Digest {
			t.Fatal("runtime selection changed compilation facts or observation authority")
		}
		verdict, err := views[i].CheckObserved(ctx, attached, subjects[i])
		if err != nil || verdict.Status != Unverifiable {
			t.Fatalf("identity-only observation acquired reuse authority: %+v, %v", verdict, err)
		}
	}
	for i, view := range views {
		if _, err := view.CaptureObservedBatch(ctx); err != nil {
			t.Fatalf("closing another partition sealed partition %d: %v", i, err)
		}
		if err := view.Validate(ctx); err != nil {
			t.Fatalf("partition %d falsely reported source/build/runtime drift: %v", i, err)
		}
	}
	rebound, err := views[0].BindRuntime(ctx, RuntimeDescription{Directory: "a"})
	if err != nil {
		t.Fatal(err)
	}
	reselected, err := rebound.ProducerSnapshot([]Subject{subjects[0]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reselected.AttachObservation(subjects[0], proofs[subjects[0]], observations[0]); err != nil {
		t.Fatalf("selection copied the parent's attachment or seal: %v", err)
	}
	if _, err := reselected.AttachObservation(subjects[0], proofs[subjects[0]], observations[0]); err == nil {
		t.Fatal("independent transaction lost its own duplicate-attachment guard")
	}
	// A fresh transaction gets neither its parent's nor its sibling's attachment.
	fresh, err := bindings[0].ProducerSnapshot([]Subject{subjects[0]})
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.attachedObservations) != 0 || fresh.sealed {
		t.Fatal("selection copied attachment or closing state")
	}
	// A real environment mismatch remains a closing refusal. The log comes from
	// another process environment; selection cannot bless it as this binding's.
	wrong, err := runtimeinput.FromTestLog([]byte("getenv PWD\n"), dir, dir, session.build.Environment,
		runtimeinput.WithCompletedProcess("wrong-pwd"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.AttachObservation(subjects[0], proofs[subjects[0]], wrong); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Validate(ctx); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("mismatched runtime environment validated: %v", err)
	}
	// A runtime file can move while source/build inputs remain unchanged.
	input := filepath.Join(dir, "a", "input.txt")
	if err := os.WriteFile(input, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := bindings[0].ProducerSnapshot([]Subject{subjects[0]})
	if err != nil {
		t.Fatal(err)
	}
	fileObservation, err := runtimeinput.FromTestLog([]byte("open input.txt\n"), dir, filepath.Dir(input), bindings[0].runtime.env,
		runtimeinput.WithCompletedProcess("file"), runtimeinput.WithBracket(testObservationBracket(t, dir)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := files.AttachObservation(subjects[0], proofs[subjects[0]], fileObservation); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := files.Validate(ctx); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("runtime file drift validated: %v", err)
	}
	// Rebinding retains the old generation, so persistent source motion cannot
	// be hidden by constructing another runtime-bound producer.
	if err := os.WriteFile(filepath.Join(dir, "a", "a.go"), []byte("package a\nfunc F() string { return \"changed\" }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale, err := bindings[0].ProducerSnapshot([]Subject{subjects[0]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stale.AttachObservation(subjects[0], proofs[subjects[0]], observations[0]); err != nil {
		t.Fatal(err)
	}
	if err := stale.Validate(ctx); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("selection refreshed source generation: %v", err)
	}
}

func TestProducerSnapshotRejectsUninitializedBinding(t *testing.T) {
	for _, binding := range []*RuntimeBinding{nil, {}} {
		if _, err := binding.ProducerSnapshot([]Subject{{Package: "p", Symbol: "F"}}); err == nil {
			t.Fatal("accepted an uninitialized binding")
		}
	}
}
