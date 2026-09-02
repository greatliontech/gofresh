package gofresh

import (
	"context"
	"strings"
	"testing"

	"github.com/greatliontech/gofresh/closure"
)

const preparationSource = "package view\n\nfunc F() int { return 1 }\n\nfunc G() int { return 2 }\n"

// A subject the scan does not know refuses before the maximal fold reads
// and hashes a single contributing file: the answer is the scan's, and the
// fold cannot change it (preparation before measurement).
func TestUnknownSubjectRefusesBeforeTheMaximalFold(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, preparationSource)
	folded := false
	viewTestHooks.maximalBatch = func() { folded = true }
	defer func() { viewTestHooks.maximalBatch = nil }()
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.NewView(context.Background(), []Subject{{Package: "example.com/view", Symbol: "NoSuch"}}, dir)
	if err == nil || !strings.Contains(err.Error(), "not found in selected source") {
		t.Fatalf("unknown subject = %v, want the not-found refusal", err)
	}
	if folded {
		t.Fatal("the maximal fold ran before the unknown subject refused")
	}
}

// A view package that resolves into the module cache refuses from the
// listing, before the typed load the scan would otherwise pay.
func TestModuleCacheViewPackageRefusesBeforeTheTypedLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("populates a module cache and runs the engine over a temporary module")
	}
	dir := writePinnedDepModule(t)
	loaded := false
	viewTestHooks.typedLoad = func() { loaded = true }
	defer func() { viewTestHooks.typedLoad = nil }()
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.NewView(context.Background(), []Subject{{Package: "golang.org/x/sync/errgroup", Symbol: "Group.Go"}}, dir)
	if err == nil || !strings.Contains(err.Error(), "resolves into the module cache") {
		t.Fatalf("module-cache view package = %v, want the module-cache refusal", err)
	}
	if loaded {
		t.Fatal("the typed load ran before the module-cache refusal")
	}
}

// A batch with one malformed record refuses whole before any verdict is
// decided or any runtime-input window is opened, on both check surfaces.
func TestMalformedRecordRefusesTheBatchBeforeAnyWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, preparationSource)
	f, g := Subject{Package: "example.com/view", Symbol: "F"}, Subject{Package: "example.com/view", Symbol: "G"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{f, g}, dir)
	if err != nil {
		t.Fatal(err)
	}
	good, err := view.Capture(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.ResultKind = Kind(99)
	opened := 0
	viewTestHooks.runtimeWindow = func() { opened++ }
	defer func() { viewTestHooks.runtimeWindow = nil }()
	for name, check := range map[string]func(map[Subject]Fingerprint) (map[Subject]Verdict, error){
		"CheckBatch": func(r map[Subject]Fingerprint) (map[Subject]Verdict, error) {
			return view.CheckBatch(context.Background(), r)
		},
		"CheckObservedBatch": func(r map[Subject]Fingerprint) (map[Subject]Verdict, error) {
			return view.CheckObservedBatch(context.Background(), r)
		},
	} {
		verdicts, err := check(map[Subject]Fingerprint{f: good, g: bad})
		if err == nil || !strings.Contains(err.Error(), "invalid recorded result kind") {
			t.Fatalf("%s with a malformed record = %v %v, want the kind refusal", name, verdicts, err)
		}
		if verdicts != nil {
			t.Fatalf("%s decided verdicts beside the refusal: %v", name, verdicts)
		}
	}
	if opened != 0 {
		t.Fatalf("%d runtime-input windows opened for refused batches", opened)
	}
}

// A sealed view whose captured proof has no completed observation
// attached refuses before the validation re-observes the tree.
func TestMissingAttachmentRefusesBeforeTheValidationObservation(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeObservedViewModule(t)
	subject := Subject{Package: "example.com/observed", Symbol: "TestRead"}
	engine, err := New(WithDir(dir))
	if err != nil {
		t.Fatal(err)
	}
	view, err := engine.NewView(context.Background(), []Subject{subject}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.CaptureObserved(context.Background(), subject); err != nil {
		t.Fatal(err)
	}
	observed := 0
	viewTestHooks.observe = func() { observed++ }
	defer func() { viewTestHooks.observe = nil }()
	err = view.Validate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no attached completed observation") {
		t.Fatalf("validation without an attachment = %v, want the attachment refusal", err)
	}
	if observed != 0 {
		t.Fatalf("validation observed the tree %d times before refusing on the missing attachment", observed)
	}
	_ = closure.Observability{}
}

// The toolchain-selection notice is announced at view construction —
// where the Hasher resolved it, one go env read the engine's own
// construction never pays — before any load, not first on the
// precise-analysis path.
func TestToolchainSelectionNoticeAnnouncedAtViewConstruction(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a module fixture and runs the engine over it")
	}
	dir := writeViewModule(t, preparationSource)
	var events []Progress
	engine, err := New(WithDir(dir), WithProgress(func(p Progress) { events = append(events, p) }), WithBuildFlags("-tags=dst"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.NewView(context.Background(), []Subject{{Package: "example.com/view", Symbol: "F"}}, dir); err != nil {
		t.Fatal(err)
	}
	notices := 0
	for _, e := range events {
		if e.Phase == "toolchain-unaudited" {
			notices++
			if e.Detail == "" {
				t.Fatal("notice carries no detail")
			}
		}
	}
	if notices != 1 {
		t.Fatalf("toolchain-unaudited notices at construction = %d, want exactly one (once per engine)", notices)
	}
}
