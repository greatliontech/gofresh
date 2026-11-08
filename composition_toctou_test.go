package gofresh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/gofresh/internal/closure"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/guard"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/trace"
)

func TestMultiFeatureCompositionMatrix(t *testing.T) {
	dir := t.TempDir()
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

	write("go.mod", "module example.com/comp\n\ngo 1.26\n")
	write("p/p.go", `package p

import (
	"cmp"
	"slices"
	"sync"
)

type Evaler[T any] interface {
	Eval(T) T
}

type Box[T cmp.Ordered] struct {
	base T
}

func (b Box[T]) Eval(v T) T {
	return b.base + v
}

func (b Box[T]) Transform(items []T) []T {
	out := slices.Clone(items)
	slices.SortFunc(out, func(a, b T) int {
		return cmp.Compare(a, b)
	})
	fn := b.Eval
	for i := range out {
		out[i] = fn(out[i])
	}
	return out
}

//gofresh:single-subject
var VouchedGlobal = map[int]any{1: 10}

func TouchVouched(x int) {
	VouchedGlobal[x] = x
}

var UnvouchedCache map[int]any

func SetUnvouched(x int) {
	UnvouchedCache = map[int]any{x: x + 1}
}

func UseUnvouched(x int) int {
	SetUnvouched(x)
	v, _ := UnvouchedCache[x].(int)
	return v
}

func PureComposed(x int) int {
	base, _ := VouchedGlobal[1].(int)
	var ev Evaler[int] = Box[int]{base: base}
	b := Box[int]{base: ev.Eval(x)}
	sorted := b.Transform([]int{3, 1, 2})
	var once sync.Once
	once.Do(func() {
		sorted[0] += 1
	})
	return sorted[0] + sorted[1] + sorted[2]
}
`)

	write("linkpkg/linkpkg.go", `package linkpkg

import _ "unsafe"

//go:linkname runtimeNano runtime.nanotime
func runtimeNano() int64

func UseLinkname() int64 {
	return runtimeNano()
}
`)

	write("p/p_test.go", `package p

import "testing"

func TestInPkg(t *testing.T) {
	if got := PureComposed(5); got == 0 {
		t.Fatal("unexpected zero")
	}
}
`)

	extTestV1 := `package p_test

import (
	"testing"

	"example.com/comp/p"
)

func TestExternal(t *testing.T) {
	if got := p.PureComposed(7); got == 0 {
		t.Fatal("unexpected zero")
	}
}
`
	write("p/ext_test.go", extTestV1)

	subjPure := Subject{Package: "example.com/comp/p", Symbol: "PureComposed"}
	subjUnvouched := Subject{Package: "example.com/comp/p", Symbol: "UseUnvouched"}
	subjLinkname := Subject{Package: "example.com/comp/linkpkg", Symbol: "UseLinkname"}
	subjInPkg := Subject{Package: "example.com/comp/p", Symbol: "TestInPkg"}
	subjExt := Subject{Package: "example.com/comp/p", Symbol: "TestExternal"}
	allSubjects := []Subject{subjPure, subjUnvouched, subjLinkname, subjInPkg, subjExt}

	env := gotool.SetEnv(os.Environ(), "PWD", dir)
	sess, ctx, rec := newTracedSession(t, BuildDescription{
		Directory:   dir,
		Environment: env,
		Inputs:      []string{},
	}, SessionPolicy{
		Execution: SingleSubjectExecution,
	})

	snap, err := sess.Snapshot(ctx, allSubjects, CodeResult)
	if err != nil {
		t.Fatal(err)
	}

	// PureComposed reaches generic Box[int], RTA interface dispatch on Evaler[int],
	// bound method value b.Eval, stdlib higher-order slices.SortFunc, cmp.Compare,
	// sync.OnceFunc, and //gofresh:single-subject VouchedOnce, while discharging
	// UnvouchedCache under SingleSubjectExecution.
	testenv.RequireTraceEvent(t, rec, trace.DomainClosure, "subject_closure", func(ev trace.Event) bool {
		ref, okRef := ev.IntField("refusal")
		return ev.Target == "example.com/comp/p.PureComposed" && okRef && ref == 0 && ev.StringField("culprit") == ""
	})

	// UseUnvouched reaches SetUnvouched -> UnvouchedCache and must remain downgraded with exact culprit.
	testenv.RequireTraceEvent(t, rec, trace.DomainClosure, "subject_closure", func(ev trace.Event) bool {
		unv, ok := ev.BoolField("unverifiable")
		ref, okRef := ev.IntField("refusal")
		return ev.Target == "example.com/comp/p.UseUnvouched" && ok && unv && okRef &&
			ref == int64(closure.SharedDynamicStateRefusal) &&
			ev.StringField("culprit") == "example.com/comp/p.UnvouchedCache"
	})

	// Trigger observability batch to verify PureComposed and TestInPkg are EffectFree
	// while UseLinkname is refused for reaching runtime.nanotime via //go:linkname.
	rec.Reset()
	fps, err := snap.CaptureObservedBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	testenv.RequireTraceEvent(t, rec, trace.DomainClosure, "observability", func(ev trace.Event) bool {
		obs, ok := ev.BoolField("observable")
		ef, okEF := ev.BoolField("effect_free")
		return ev.Target == "example.com/comp/p.PureComposed" && ok && obs && okEF && ef
	})
	testenv.RequireTraceEvent(t, rec, trace.DomainClosure, "observability", func(ev trace.Event) bool {
		obs, ok := ev.BoolField("observable")
		return ev.Target == "example.com/comp/linkpkg.UseLinkname" && ok && !obs &&
			strings.Contains(ev.StringField("reason"), "runtime.nanotime")
	})

	// Verify 3-way compartment isolation via TestVariantLedger + CheckBatchWithLedgers:
	// mutating ext_test.go invalidates TestExternal while extending PureComposed and TestInPkg to Valid.
	priorLedger, err := snap.TestVariantLedger(subjPure)
	if err != nil {
		t.Fatal(err)
	}
	extTestV2 := strings.Replace(extTestV1, "p.PureComposed(7)", "p.PureComposed(99)", 1)
	write("p/ext_test.go", extTestV2)

	snap2, err := sess.Snapshot(ctx, []Subject{subjPure, subjInPkg, subjExt}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	rb2, err := snap2.BindRuntime(ctx, RuntimeDescription{Environment: env})
	if err != nil {
		t.Fatal(err)
	}
	checked, err := rb2.CheckBatchWithLedgers(ctx, []Candidate{
		{Subject: subjPure, Recorded: fps[subjPure]},
		{Subject: subjInPkg, Recorded: fps[subjInPkg]},
		{Subject: subjExt, Recorded: fps[subjExt]},
	}, map[int]TestVariantLedger{
		0: priorLedger,
		1: priorLedger,
		2: priorLedger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v := checked[0].Verdict; v.Status != Valid || checked[0].Extension == nil {
		t.Fatalf("PureComposed after ext_test.go edit = %+v (ext=%v), want Valid with Extension", v, checked[0].Extension)
	}
	if v := checked[1].Verdict; v.Status != Valid || checked[1].Extension == nil {
		t.Fatalf("TestInPkg after ext_test.go edit = %+v (ext=%v), want Valid with Extension", v, checked[1].Extension)
	}
	if v := checked[2].Verdict; v.Status != Stale || checked[2].Extension != nil {
		t.Fatalf("TestExternal after ext_test.go edit = %+v (ext=%v), want Stale without Extension", v, checked[2].Extension)
	}
}

func TestTwoPassCompareObservationsFieldPerturbationAndTOCTOU(t *testing.T) {
	subj := Subject{Package: "example.com/pkg", Symbol: "Target"}
	subjects := []Subject{subj}
	baseGuards := guard.Guards{
		Toolchain:     "go1.26 linux/amd64",
		BuildConfig:   "bc-1",
		Machine:       "mach-1",
		RuntimeConfig: "rc-1",
	}
	baseMaximal := closure.MaximalFacts{
		Identity: closure.MaximalIdentity{
			Hash:             "hash-1",
			TestVariants:     "tv-1",
			ToolchainContent: "tc-1",
			AdmissionPolicy:  "ap-1",
		},
	}
	makeBaseFacts := func() observationFacts {
		return observationFacts{
			guards: baseGuards,
			maximal: map[Subject]subjectFacts{
				subj: {
					source: baseMaximal.Clone(),
				},
			},
			purity:               map[Subject]string{subj: ""},
			vouchDischarges:      map[Subject]string{subj: "vouch-1"},
			discharges:           map[Subject]attestationDischarges{subj: {singleSubject: "ss-1", packageProcess: "pp-1"}},
			cut:                  map[Subject]bool{},
			sourceFiles:          []string{"/repo/pkg/a.go"},
			sourceFilesBySubject: map[Subject][]string{subj: {"/repo/pkg/a.go"}},
			fileDigests:          map[string]string{"/repo/pkg/a.go": "dig-1"},
		}
	}

	cases := []struct {
		name         string
		construction bool
		mutate       func(cur *observationFacts)
		wantField    string
	}{
		{
			name:         "guards",
			construction: true,
			mutate: func(cur *observationFacts) {
				cur.guards.BuildConfig = "bc-2"
			},
			wantField: "guards",
		},
		{
			name:         "closure_hash",
			construction: true,
			mutate: func(cur *observationFacts) {
				sf := cur.maximal[subj]
				sf.source.Identity.Hash = "hash-2"
				cur.maximal[subj] = sf
			},
			wantField: "closure_hash",
		},
		{
			name:         "closure_test_variants",
			construction: true,
			mutate: func(cur *observationFacts) {
				sf := cur.maximal[subj]
				sf.source.Identity.TestVariants = "tv-2"
				cur.maximal[subj] = sf
			},
			wantField: "closure_test_variants",
		},
		{
			name:         "closure_toolchain_content",
			construction: true,
			mutate: func(cur *observationFacts) {
				sf := cur.maximal[subj]
				sf.source.Identity.ToolchainContent = "tc-2"
				cur.maximal[subj] = sf
			},
			wantField: "closure_toolchain_content",
		},
		{
			name:         "closure_admission_policy",
			construction: true,
			mutate: func(cur *observationFacts) {
				sf := cur.maximal[subj]
				sf.source.Identity.AdmissionPolicy = "ap-2"
				cur.maximal[subj] = sf
			},
			wantField: "closure_admission_policy",
		},
		{
			name:         "closure_unverifiable",
			construction: true,
			mutate: func(cur *observationFacts) {
				sf := cur.maximal[subj]
				sf.source.Effects = []closure.Blocker{{Kind: closure.BlockerNetwork, Reason: "reaches net"}}
				sf.source.Diagnostic = "reaches net"
				cur.maximal[subj] = sf
			},
			wantField: "closure_unverifiable",
		},
		{
			name:         "closure_reason",
			construction: true,
			mutate: func(cur *observationFacts) {
				sf := cur.maximal[subj]
				sf.source.Diagnostic = "import candidate diagnostic"
				cur.maximal[subj] = sf
			},
			wantField: "closure_reason",
		},
		{
			name:         "closure_effects_with_same_closure_projection",
			construction: true,
			mutate: func(cur *observationFacts) {
				// Both base and cur have 1+ effects and identical Diagnostic, so Closure() is identical
				// while MaximalFacts.Equal is false due to a second blocker in Effects.
				sf := cur.maximal[subj]
				sf.source.Effects = []closure.Blocker{
					{Kind: closure.BlockerNetwork, Reason: "reaches net"},
					{Kind: closure.BlockerEnvironment, Reason: "reaches os.Getenv"},
				}
				sf.source.Diagnostic = "reaches net"
				cur.maximal[subj] = sf
			},
			wantField: "closure_effects",
		},
		{
			name:         "open_world",
			construction: true,
			mutate: func(cur *observationFacts) {
				sf := cur.maximal[subj]
				sf.openWorld = &subjectRefusal{reason: "parameter fn of func() int"}
				cur.maximal[subj] = sf
			},
			wantField: "open_world",
		},
		{
			name:         "shared_state",
			construction: true,
			mutate: func(cur *observationFacts) {
				sf := cur.maximal[subj]
				sf.sharedState = &subjectRefusal{reason: "mutates global", culprit: Subject{Package: "example.com/pkg", Symbol: "G"}}
				cur.maximal[subj] = sf
			},
			wantField: "shared_state",
		},
		{
			name:         "ambiguous",
			construction: true,
			mutate: func(cur *observationFacts) {
				sf := cur.maximal[subj]
				sf.ambiguous = &subjectRefusal{reason: "ambiguous method"}
				cur.maximal[subj] = sf
			},
			wantField: "ambiguous",
		},
		{
			name:         "external",
			construction: true,
			mutate: func(cur *observationFacts) {
				sf := cur.maximal[subj]
				sf.external = true
				cur.maximal[subj] = sf
			},
			wantField: "external",
		},
		{
			name:         "purity",
			construction: true,
			mutate: func(cur *observationFacts) {
				cur.purity[subj] = "source directive"
			},
			wantField: "purity",
		},
		{
			name:         "vouch_discharges",
			construction: true,
			mutate: func(cur *observationFacts) {
				cur.vouchDischarges[subj] = "vouch-2"
			},
			wantField: "vouch_discharges",
		},
		{
			name:         "single_subject_discharges",
			construction: true,
			mutate: func(cur *observationFacts) {
				d := cur.discharges[subj]
				d.singleSubject = "ss-2"
				cur.discharges[subj] = d
			},
			wantField: "single_subject_discharges",
		},
		{
			name:         "package_process_discharges",
			construction: true,
			mutate: func(cur *observationFacts) {
				d := cur.discharges[subj]
				d.packageProcess = "pp-2"
				cur.discharges[subj] = d
			},
			wantField: "package_process_discharges",
		},
		{
			name:         "subject_source_files_construction",
			construction: true,
			mutate: func(cur *observationFacts) {
				cur.sourceFilesBySubject[subj] = []string{"/repo/pkg/a.go", "/repo/pkg/b.go"}
			},
			wantField: "subject_source_files",
		},
		{
			name:         "subject_source_files_validation",
			construction: false,
			mutate: func(cur *observationFacts) {
				cur.sourceFilesBySubject[subj] = []string{"/repo/pkg/a.go", "/repo/pkg/b.go"}
			},
			wantField: "subject_source_files",
		},
		{
			name:         "source_files_construction",
			construction: true,
			mutate: func(cur *observationFacts) {
				cur.sourceFiles = []string{"/repo/pkg/a.go", "/repo/pkg/extra.go"}
			},
			wantField: "source_files",
		},
		{
			name:         "source_files_validation",
			construction: false,
			mutate: func(cur *observationFacts) {
				cur.sourceFiles = []string{"/repo/pkg/a.go", "/repo/pkg/extra.go"}
			},
			wantField: "source_files",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, rec := testenv.WithTraceGate(t, t.Context(), testenv.AllowTwoPassDiff())
			base := makeBaseFacts()
			if tc.wantField == "closure_effects" {
				sf := base.maximal[subj]
				sf.source.Effects = []closure.Blocker{{Kind: closure.BlockerNetwork, Reason: "reaches net"}}
				sf.source.Diagnostic = "reaches net"
				base.maximal[subj] = sf
			}
			cur := makeBaseFacts()
			tc.mutate(&cur)

			err := compareObservations(ctx, subjects, &base, base.guards, cur, tc.construction)
			if !errors.Is(err, ErrViewChanged) {
				t.Fatalf("compareObservations error = %v, want ErrViewChanged", err)
			}
			testenv.RequireTraceEvent(t, rec, trace.DomainView, "two_pass_diff", func(ev trace.Event) bool {
				return ev.StringField("diff_field") == tc.wantField
			})
		})
	}

	t.Run("toctou_mtime_only_succeeds_while_content_mutation_fails_closed", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/toctou\n\ngo 1.26\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		pFile := filepath.Join(dir, "p.go")
		v1 := "package toctou\n\nfunc Compute(x int) int { return x + 1 }\n"
		if err := os.WriteFile(pFile, []byte(v1), 0o644); err != nil {
			t.Fatal(err)
		}
		target := Subject{Package: "example.com/toctou", Symbol: "Compute"}
		env := gotool.SetEnv(os.Environ(), "PWD", dir)

		// 1. Metadata-only (mtime) bump between Pass 1 and Pass 2 must NOT trigger ErrViewChanged.
		observePass := 0
		sessMtime, ctxMtime, recMtime := newTracedSession(t, BuildDescription{
			Directory:   dir,
			Environment: env,
			Inputs:      []string{},
		}, SessionPolicy{
			Progress: func(p Progress) {
				if p.Phase == "observe" {
					observePass++
					if observePass == 2 {
						future := time.Now().Add(10 * time.Minute)
						_ = os.Chtimes(pFile, future, future)
					}
				}
			},
		})
		if _, err := sessMtime.Snapshot(ctxMtime, []Subject{target}, CodeResult); err != nil {
			t.Fatalf("metadata-only mtime bump between passes failed: %v", err)
		}
		testenv.AssertNoTraceEvent(t, recMtime, trace.DomainView, "two_pass_diff", nil)

		// 2. Single-byte content mutation between Pass 1 and Pass 2 must fail closed with ErrViewChanged.
		observePass = 0
		ctxMut, recMut := testenv.WithTraceGate(t, t.Context(), testenv.AllowTwoPassDiff())
		sessMut, err := NewSession(ctxMut, BuildDescription{
			Directory:   dir,
			Environment: env,
			Inputs:      []string{},
		}, SessionPolicy{
			Progress: func(p Progress) {
				if p.Phase == "observe" {
					observePass++
					if observePass == 2 {
						v2 := "package toctou\n\nfunc Compute(x int) int { return x + 2 }\n"
						_ = os.WriteFile(pFile, []byte(v2), 0o644)
					}
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = sessMut.Snapshot(ctxMut, []Subject{target}, CodeResult)
		if !errors.Is(err, ErrViewChanged) {
			t.Fatalf("Snapshot with mid-pass content mutation = %v, want ErrViewChanged", err)
		}
		testenv.RequireTraceEvent(t, recMut, trace.DomainView, "two_pass_diff", func(ev trace.Event) bool {
			return ev.Target == "example.com/toctou.Compute" && ev.StringField("diff_field") == "closure_hash"
		})
	})
}

func TestWorkspaceSymlinkedPWDAndCorruptedCacheResilience(t *testing.T) {
	t.Run("go_work_multi_module_closure_and_invalidation", func(t *testing.T) {
		wsDir := t.TempDir()
		write := func(rel, content string) {
			t.Helper()
			full := filepath.Join(wsDir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write("go.work", "go 1.26\n\nuse (\n\t./modA\n\t./modB\n)\n")
		write("modA/go.mod", "module example.com/modA\n\ngo 1.26\n\nrequire example.com/modB v0.0.0\n")
		write("modB/go.mod", "module example.com/modB\n\ngo 1.26\n")
		write("modB/b.go", "package modB\n\nfunc Value() int { return 10 }\n")
		write("modA/a.go", "package modA\n\nimport \"example.com/modB\"\n\nfunc CallB(x int) int { return x + modB.Value() }\n")

		modADir := filepath.Join(wsDir, "modA")
		env := gotool.SetEnv(os.Environ(), "PWD", modADir)
		env = gotool.SetEnv(env, "GOWORK", "")
		subj := Subject{Package: "example.com/modA", Symbol: "CallB"}

		sess, ctx, _ := newTracedSession(t, BuildDescription{
			Directory:   modADir,
			Environment: env,
			Inputs:      []string{},
		}, SessionPolicy{})
		snap1, err := sess.Snapshot(ctx, []Subject{subj}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		fps, err := snap1.CaptureObservedBatch(ctx)
		if err != nil {
			t.Fatal(err)
		}
		verdicts1, err := snap1.CheckBatch(ctx, fps)
		if err != nil {
			t.Fatal(err)
		}
		if verdicts1[subj].Status != Valid {
			t.Fatalf("initial workspace verdict = %+v, want Valid", verdicts1[subj])
		}

		// Mutate sibling workspace module modB and verify modA.CallB turns Stale.
		write("modB/b.go", "package modB\n\nfunc Value() int { return 20 }\n")
		snap2, err := sess.Snapshot(ctx, []Subject{subj}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		verdicts2, err := snap2.CheckBatch(ctx, fps)
		if err != nil {
			t.Fatal(err)
		}
		if verdicts2[subj].Status != Stale || verdicts2[subj].Ground.Cause.Kind != ClosureCause {
			t.Fatalf("workspace verdict after modB edit = %+v, want Stale/ClosureCause", verdicts2[subj])
		}
	})

	t.Run("symlinked_pwd_and_repo_under_tmpdir", func(t *testing.T) {
		outerTmp := t.TempDir()
		realRepo := filepath.Join(outerTmp, "real-repo")
		if err := os.MkdirAll(realRepo, 0o755); err != nil {
			t.Fatal(err)
		}
		symRepo := filepath.Join(outerTmp, "sym-repo")
		if err := os.Symlink(realRepo, symRepo); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(realRepo, "go.mod"), []byte("module example.com/symrepo\n\ngo 1.26\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(realRepo, "fixture.txt"), []byte("v1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		testSrc := `package symrepo

import (
	"os"
	"testing"
)

//gofresh:pure
func TestReadFixture(t *testing.T) {
	b, err := os.ReadFile("fixture.txt")
	if err != nil || len(b) == 0 {
		t.Fatal(err)
	}
}
`
		if err := os.WriteFile(filepath.Join(realRepo, "sym_test.go"), []byte(testSrc), 0o644); err != nil {
			t.Fatal(err)
		}

		env := gotool.SetEnv(os.Environ(), "PWD", symRepo)
		env = gotool.SetEnv(env, "TMPDIR", outerTmp)
		subj := Subject{Package: "example.com/symrepo", Symbol: "TestReadFixture"}

		sess, ctx, _ := newTracedSession(t, BuildDescription{
			Directory:   symRepo,
			Environment: env,
			Inputs:      []string{},
		}, SessionPolicy{})
		snap, err := sess.Snapshot(ctx, []Subject{subj}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		fp, err := snap.captureObserved(ctx, subj)
		if err != nil {
			t.Fatal(err)
		}
		bracket, err := CaptureBracket(ctx, symRepo, []string{"."})
		if err != nil {
			t.Fatal(err)
		}
		obs, err := FromTestLog([]byte("# test log\nopen fixture.txt\n"), symRepo, symRepo, env,
			WithCompletedProcess("worker"), WithBracket(bracket))
		if err != nil {
			t.Fatal(err)
		}
		if obs.State.Unverifiable {
			t.Fatalf("Observation under symlinked PWD & TMPDIR is unverifiable: %+v", obs.State)
		}
		attachedFP, err := snap.AttachObservation(subj, fp, obs)
		if err != nil {
			t.Fatal(err)
		}
		fps := map[Subject]Fingerprint{subj: attachedFP}
		verdicts1, err := snap.CheckObservedBatch(ctx, fps)
		if err != nil {
			t.Fatal(err)
		}
		if verdicts1[subj].Status != Valid {
			t.Fatalf("initial verdict under symlinked PWD = %+v, want Valid", verdicts1[subj])
		}

		// Mutating fixture.txt must invalidate the recorded fingerprint (never swallowed by TMPDIR scratch).
		if err := os.WriteFile(filepath.Join(realRepo, "fixture.txt"), []byte("v2-mutated\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		snap2, err := sess.Snapshot(ctx, []Subject{subj}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		verdicts2, err := snap2.CheckObservedBatch(ctx, fps)
		if err != nil {
			t.Fatal(err)
		}
		if verdicts2[subj].Status != Stale || verdicts2[subj].Ground.Cause.Kind != RuntimeInputsCause {
			t.Fatalf("verdict after fixture.txt edit = %+v, want Stale/RuntimeInputsCause", verdicts2[subj])
		}
	})

	t.Run("corrupted_truncated_and_bitflipped_xdg_cache_home_recovers_cleanly", func(t *testing.T) {
		// Preserve GOCACHE before isolating XDG_CACHE_HOME so child go commands do not cold-rebuild stdlib.
		goCache, err := gotool.GoBuildCache(context.Background(), os.Environ())
		if err != nil {
			t.Fatal(err)
		}
		xdgCache := t.TempDir()
		t.Setenv("GOCACHE", goCache)
		t.Setenv("XDG_CACHE_HOME", xdgCache)

		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/cachecorrupt\n\ngo 1.26\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package cachecorrupt\n\nfunc Add(a, b int) int { return a + b }\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		subj := Subject{Package: "example.com/cachecorrupt", Symbol: "Add"}
		env := gotool.SetEnv(os.Environ(), "PWD", dir)
		env = gotool.SetEnv(env, "GOCACHE", goCache)
		env = gotool.SetEnv(env, "XDG_CACHE_HOME", xdgCache)

		// 1. Populate XDG_CACHE_HOME with a clean run.
		sess1, ctx1, _ := newTracedSession(t, BuildDescription{
			Directory:   dir,
			Environment: env,
			Inputs:      []string{},
		}, SessionPolicy{})
		snap1, err := sess1.Snapshot(ctx1, []Subject{subj}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		fps1, err := snap1.CaptureObservedBatch(ctx1)
		if err != nil {
			t.Fatal(err)
		}

		// 2. Corrupt every cache file written under xdgCache (truncate some, invalid JSON others).
		var corruptedCount int
		err = filepath.WalkDir(xdgCache, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() {
				return walkErr
			}
			corruptedCount++
			switch corruptedCount % 3 {
			case 0:
				return os.WriteFile(path, []byte("{"), 0o600)
			case 1:
				return os.WriteFile(path, []byte(`{"digest":"00000000000000000000000000000000","payload":"corrupted"}`), 0o600)
			default:
				return os.WriteFile(path, []byte("\xff\xfe\xfdnot-json"), 0o600)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		if corruptedCount == 0 {
			t.Fatal("expected cache files under XDG_CACHE_HOME to corrupt, found 0")
		}

		// 3. Re-run against the corrupted cache and verify clean recovery and identical fingerprints.
		sess2, ctx2, _ := newTracedSession(t, BuildDescription{
			Directory:   dir,
			Environment: env,
			Inputs:      []string{},
		}, SessionPolicy{})
		snap2, err := sess2.Snapshot(ctx2, []Subject{subj}, CodeResult)
		if err != nil {
			t.Fatalf("Snapshot after cache corruption failed: %v", err)
		}
		fps2, err := snap2.CaptureObservedBatch(ctx2)
		if err != nil {
			t.Fatalf("CaptureObservedBatch after cache corruption failed: %v", err)
		}
		if fps1[subj] != fps2[subj] {
			t.Fatalf("fingerprint after cache corruption recovery differed:\ngot  %+v\nwant %+v", fps2[subj], fps1[subj])
		}
		verdicts, err := snap2.CheckBatch(ctx2, fps1)
		if err != nil {
			t.Fatal(err)
		}
		if verdicts[subj].Status != Valid {
			t.Fatalf("verdict after cache corruption recovery = %+v, want Valid", verdicts[subj])
		}
	})
}

func TestObservedReuseAcrossStartupZeroGlobalAndInterfaceCarriers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
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

	write("go.mod", "module example.com/obsreuse\n\ngo 1.26\n")
	write("object/object.go", `package object

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
)

var displayFeats *bool

func init() {
	if displayFeats != nil && *displayFeats {
		fmt.Println("features")
		os.Exit(1)
	}
}

var ErrCancelled = errors.New("cancelled")

type CancelledError struct {
	Op string
}

func (e *CancelledError) Error() string {
	return "cancelled: " + e.Op
}

func (e *CancelledError) Is(target error) bool {
	return target == ErrCancelled || target == strconv.ErrRange
}

func AsciiLowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func ReadWithCancel(ctx context.Context, data []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, &CancelledError{Op: "read"}
	default:
		out := make([]byte, len(data))
		for i, b := range data {
			out[i] = AsciiLowerByte(b)
		}
		return out, nil
	}
}
`)
	write("object/object_test.go", `package object

import (
	"context"
	"errors"
	"testing"
)

func TestObservedTargets(t *testing.T) {
	got, err := ReadWithCancel(t.Context(), []byte("AbC"))
	if err != nil || string(got) != "abc" {
		t.Fatalf("ReadWithCancel = %q, %v", got, err)
	}
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ReadWithCancel(cctx, []byte("X"))
	if !errors.Is(err, ErrCancelled) {
		t.Fatalf("errors.Is(%v, ErrCancelled) = false, want true", err)
	}
}
`)

	env := os.Environ()
	sess1, ctx1, _ := newTracedSession(t, BuildDescription{
		Directory:   dir,
		Environment: env,
		Inputs:      []string{},
	}, SessionPolicy{})

	const pkg = "example.com/obsreuse/object"
	subjects := []Subject{
		{Package: pkg, Symbol: "AsciiLowerByte"},
		{Package: pkg, Symbol: "CancelledError.Is"},
		{Package: pkg, Symbol: "ReadWithCancel"},
		{Package: pkg, Symbol: "TestObservedTargets"},
	}

	snap1, err := sess1.Snapshot(ctx1, subjects, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := snap1.CaptureObservedBatch(ctx1)
	if err != nil {
		t.Fatal(err)
	}
	bracket, err := CaptureBracket(ctx1, dir, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := FromTestLog([]byte("# test log\n"), dir, dir, env,
		WithCompletedProcess("worker"), WithBracket(bracket))
	if err != nil {
		t.Fatal(err)
	}
	attached := make(map[Subject]Fingerprint, len(subjects))
	for _, s := range subjects {
		fp := captured[s]
		if !fp.ObservationProof.Observable {
			t.Fatalf("%s.%s ObservationProof = %+v, want Observable", s.Package, s.Symbol, fp.ObservationProof)
		}
		sib, err := snap1.Sibling([]Subject{s})
		if err != nil {
			t.Fatal(err)
		}
		afp, err := sib.AttachObservation(s, fp, obs)
		if err != nil {
			t.Fatal(err)
		}
		if err := sib.Validate(ctx1); err != nil {
			t.Fatalf("%s.%s Validate failed: %v", s.Package, s.Symbol, err)
		}
		attached[s] = afp
	}

	sess2, ctx2, _ := newTracedSession(t, BuildDescription{
		Directory:   dir,
		Environment: env,
		Inputs:      []string{},
	}, SessionPolicy{})
	snap2, err := sess2.Snapshot(ctx2, subjects, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	verdicts, err := snap2.CheckObservedBatch(ctx2, attached)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range subjects {
		if v := verdicts[s]; v.Status != Valid {
			t.Errorf("%s.%s CheckObservedBatch verdict = %+v, want Valid", s.Package, s.Symbol, v)
		}
	}
}
