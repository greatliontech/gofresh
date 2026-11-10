package trace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func RefreshFromEnv() {
	Refresh(os.Getenv(EnvTrace), os.Getenv(EnvTraceFile))
}

type panicOnFormatError struct{}

func (panicOnFormatError) Error() string {
	panic("Error() must not be called on disabled fast path")
}

func TestDisabledFastPathZeroAllocs(t *testing.T) {
	t.Setenv(EnvTrace, "")
	t.Setenv(EnvTraceFile, "")
	RefreshFromEnv()

	ctx := t.Context()
	if Enabled(ctx, DomainToolchain, "encoding/json") {
		t.Fatal("expected Enabled to be false when tracing is off")
	}

	flags := []string{"-tags=purego", "-trimpath"}
	var lazyErr error = panicOnFormatError{}
	allocs := testing.AllocsPerRun(100, func() {
		_ = Enabled(ctx, DomainClosure, "pkg.BenchmarkFoo")
		Emit(ctx, DomainClosure, "subject_closure", "pkg.BenchmarkFoo",
			String("hash", "deadbeef"),
			Int("count", 3),
			Bool("unverifiable", false),
			Strings("flags", flags),
			Err(lazyErr),
		)
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocations on disabled fast path, got %v", allocs)
	}
}

func TestFilterGrammarAndContextSinks(t *testing.T) {
	t.Setenv(EnvTrace, "")
	t.Setenv(EnvTraceFile, "")
	RefreshFromEnv()

	for _, inactiveSpec := range []string{"", "  ", "0", "false", "off", "none", "unknown_domain"} {
		ctx := WithFilteredSink(context.Background(), inactiveSpec, NewRecorder())
		if Enabled(ctx, DomainToolchain, "fmt") {
			t.Fatalf("spec %q should not enable tracing", inactiveSpec)
		}
	}

	for _, allSpec := range []string{"1", "true", "ALL", "*", "all:"} {
		ctx, cancel := context.WithCancel(context.Background())
		rec := NewRecorder()
		tctx := WithFilteredSink(ctx, allSpec, rec)
		for _, dom := range []Domain{DomainToolchain, DomainClosure, DomainDynstate, DomainRuntimeInput, DomainCache, DomainView, DomainSession} {
			if !Enabled(tctx, dom, "any") {
				t.Fatalf("spec %q did not enable domain %s", allSpec, dom)
			}
			Emit(tctx, dom, "evt", "any")
		}
		if got := len(rec.Events()); got != 7 {
			t.Fatalf("spec %q recorded %d events, want 7", allSpec, got)
		}
		cancel()
		if Enabled(tctx, DomainToolchain, "any") {
			t.Fatalf("spec %q remained enabled after context cancellation", allSpec)
		}
	}

	// Targeted domain:substring filtering and nested sinks.
	parentCtx, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	parentRec := NewRecorder()
	pctx := WithFilteredSink(parentCtx, "closure:BenchmarkPWD,toolchain:encoding/json,dynstate:example.com/p,runtimeinput:testlog,cache:tier2,view", parentRec)

	childCtx, cancelChild := context.WithCancel(pctx)
	childRec := NewRecorder()
	cctx := WithFilteredSink(childCtx, "*:SpecialTarget", childRec)

	Emit(cctx, DomainClosure, "subject_closure", "example.com/p.BenchmarkPWD", String("hash", "h1"))
	Emit(cctx, DomainClosure, "subject_closure", "example.com/p.BenchmarkOther", String("hash", "h2"))
	Emit(cctx, DomainToolchain, "stamp_fallback", "encoding/json", Bool("content_equal", true))
	Emit(cctx, DomainToolchain, "stamp_fallback", "fmt", Bool("content_equal", true))
	Emit(cctx, DomainDynstate, "fact.package.done", "example.com/p", Int("culprits", 0))
	Emit(cctx, DomainDynstate, "fact.package.done", "example.com/other", Int("culprits", 1))
	Emit(cctx, DomainRuntimeInput, "testlog.extract.done", "testlog", Int("ops", 5))
	Emit(cctx, DomainRuntimeInput, "testlog.extract.done", "bracket", Int("ops", 0))
	Emit(cctx, DomainCache, "cache.load", "tier2", Bool("hit", true))
	Emit(cctx, DomainCache, "cache.load", "scanfacts", Bool("hit", false))
	Emit(cctx, DomainView, "pass_summary", "dir", Int("subjects", 2))
	Emit(cctx, DomainSession, "check_verdict", "example.com/p.SpecialTarget", String("status", "valid"))

	if got := len(parentRec.Events()); got != 6 {
		t.Fatalf("parent recorder got %d events, want 6: %+v", got, parentRec.Events())
	}
	if got := len(childRec.Events()); got != 1 || childRec.Events()[0].Target != "example.com/p.SpecialTarget" {
		t.Fatalf("child recorder got %+v, want 1 SpecialTarget event", childRec.Events())
	}

	cancelChild()
	// Even while parentCtx is still active (activeCount > 0), cctx's cancelled
	// child sink must not receive events or match Enabled for *:SpecialTarget.
	if Enabled(cctx, DomainSession, "example.com/p.SpecialTarget") {
		t.Fatal("cancelled child sink remained enabled while parent sink was active")
	}
	Emit(cctx, DomainSession, "check_verdict", "example.com/p.SpecialTarget", String("status", "stale"))
	if got := len(childRec.Events()); got != 1 {
		t.Fatalf("cancelled child sink received event after cancellation: %+v", childRec.Events())
	}

	cancelParent()
	if Enabled(pctx, DomainView, "dir") || AnyEnabled() {
		t.Fatal("expected AnyEnabled() == false immediately after cancelling all context sinks")
	}
	runtime.GC()
}

func TestRecorderAccessorsAndDeepCopy(t *testing.T) {
	t.Setenv(EnvTrace, "")
	RefreshFromEnv()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := NewRecorder()
	tctx := WithSink(ctx, rec)

	tags := []string{"a", "b"}
	Emit(tctx, DomainToolchain, "scope_resolved", "/goroot",
		String("goversion", "go1.26.0"),
		Int("count", 7),
		Int64("big", 42),
		Uint32("mode", 0o644),
		Bool("warm", true),
		Strings("flags", tags),
		Err(nil),
		Err(errors.New("bad package")),
	)
	tags[0] = "mutated"

	evts := rec.ByDomain(DomainToolchain)
	if len(evts) != 1 {
		t.Fatalf("expected 1 toolchain event, got %d", len(evts))
	}
	ev := evts[0]
	if got := ev.StringField("goversion"); got != "go1.26.0" {
		t.Fatalf("StringField(goversion) = %q, want go1.26.0", got)
	}
	if got, ok := ev.IntField("count"); !ok || got != 7 {
		t.Fatalf("IntField(count) = %d, %v", got, ok)
	}
	if got, ok := ev.IntField("big"); !ok || got != 42 {
		t.Fatalf("IntField(big) = %d, %v", got, ok)
	}
	if got, ok := ev.IntField("mode"); !ok || got != 0o644 {
		t.Fatalf("IntField(mode) = %d, %v", got, ok)
	}
	if got, ok := ev.BoolField("warm"); !ok || !got {
		t.Fatalf("BoolField(warm) = %v, %v", got, ok)
	}
	if got := ev.StringsField("flags"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("StringsField(flags) = %v, want [a b]", got)
	}
	if got := ev.StringField("error"); got != "bad package" {
		t.Fatalf("StringField(error) = %q, want 'bad package'", got)
	}
	if len(rec.ByName("scope_resolved")) != 1 {
		t.Fatalf("ByName(scope_resolved) count != 1")
	}
	rec.Reset()
	if len(rec.Events()) != 0 {
		t.Fatalf("expected empty recorder after Reset")
	}
}

func TestFormatTextAndJSONL(t *testing.T) {
	ev := Event{
		Time:   time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		PID:    1234,
		Domain: DomainView,
		Name:   "two_pass_diff",
		Target: "example.com/pkg.TestFoo",
		Fields: []Field{
			String("diff_field", "closure_hash"),
			String("reason", "contains space=and\"quote"),
			String("empty", ""),
			Int("pass", 2),
			Bool("changed", true),
			Strings("items", []string{"x", "y"}),
		},
	}

	textLine := string(FormatText(ev))
	wantPrefix := `gofresh/trace pid=1234 domain=view event=two_pass_diff target=example.com/pkg.TestFoo diff_field=closure_hash reason="contains space=and\"quote" empty="" pass=2 changed=true items=x,y` + "\n"
	if textLine != wantPrefix {
		t.Fatalf("FormatText mismatch:\ngot:  %q\nwant: %q", textLine, wantPrefix)
	}

	jsonlLine := FormatJSONL(ev)
	if !bytes.HasSuffix(jsonlLine, []byte("\n")) {
		t.Fatalf("FormatJSONL missing trailing newline: %q", string(jsonlLine))
	}
	var parsed jsonlEvent
	if err := json.Unmarshal(jsonlLine, &parsed); err != nil {
		t.Fatalf("FormatJSONL produced invalid JSON: %v (%s)", err, string(jsonlLine))
	}
	if parsed.PID != 1234 || parsed.Domain != "view" || parsed.Event != "two_pass_diff" || parsed.Target != "example.com/pkg.TestFoo" {
		t.Fatalf("unexpected parsed JSONL header: %+v", parsed)
	}
	if parsed.Fields["diff_field"] != "closure_hash" || parsed.Fields["changed"] != true {
		t.Fatalf("unexpected parsed JSONL fields: %+v", parsed.Fields)
	}
}

func TestEnvFileAndConcurrentEmission(t *testing.T) {
	tmp := t.TempDir()
	textPath := filepath.Join(tmp, "trace.log")
	jsonlPath := filepath.Join(tmp, "trace.jsonl")

	// Register RefreshFromEnv before t.Setenv so LIFO cleanup restores the
	// environment first and then refreshes the in-memory trace state without
	// calling os.Unsetenv directly.
	t.Cleanup(RefreshFromEnv)
	t.Setenv(EnvTrace, "toolchain,session")
	t.Setenv(EnvTraceFile, textPath)
	RefreshFromEnv()

	const workers = 8
	const perWorker = 25
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range perWorker {
				Emit(context.Background(), DomainSession, "check_verdict", "pkg.Sym",
					Int("worker", id),
					Int("iter", i),
					String("status", "valid"),
				)
				// Filtered out:
				Emit(context.Background(), DomainClosure, "subject_closure", "pkg.Sym")
			}
		}(w)
	}
	wg.Wait()

	data, err := os.ReadFile(textPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", textPath, err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) != workers*perWorker {
		t.Fatalf("expected %d lines in %s, got %d", workers*perWorker, textPath, len(lines))
	}
	for i, line := range lines {
		if !strings.HasPrefix(line, "gofresh/trace pid=") || !strings.Contains(line, "domain=session event=check_verdict") {
			t.Fatalf("line %d corrupted or unexpected: %q", i, line)
		}
	}

	// Switch to JSONL output file via RefreshFromEnv.
	t.Setenv(EnvTrace, "all")
	t.Setenv(EnvTraceFile, jsonlPath)
	RefreshFromEnv()

	Emit(context.Background(), DomainToolchain, "selection_resolved", "go1.26.0", Bool("audited", true))

	jdata, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", jsonlPath, err)
	}
	var parsed jsonlEvent
	if err := json.Unmarshal(jdata, &parsed); err != nil {
		t.Fatalf("Unmarshal JSONL file: %v (%s)", err, string(jdata))
	}
	if parsed.Domain != "toolchain" || parsed.Event != "selection_resolved" || parsed.Fields["audited"] != true {
		t.Fatalf("unexpected JSONL event: %+v", parsed)
	}

	// Verify failed OpenFile on a .jsonl path falls back to text format on stderr.
	Refresh("all", filepath.Join(tmp, "nonexistent_dir", "trace.jsonl"))
	cfg := envCfg.Load()
	fallbackJSONL := cfg != nil && cfg.jsonl
	if fallbackJSONL {
		t.Fatal("failed OpenFile on .jsonl path must fall back to text format (jsonl=false) on stderr")
	}
}
