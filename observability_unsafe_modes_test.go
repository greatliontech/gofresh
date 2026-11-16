package gofresh

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate/refconfine"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"go/types"
)

func TestWholeSystemUnsafeExecutionModesMemoAndReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("builds multi-package views across execution models and persistent memo caches")
	}
	if runtime.GOOS != "linux" {
		t.Skip("supported outcome method requires Linux")
	}

	// Preserve GOCACHE before isolating XDG_CACHE_HOME so child go commands do not cold-rebuild stdlib.
	goCache, err := gotool.GoBuildCache(context.Background(), os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	xdgCache := t.TempDir()
	t.Setenv("GOCACHE", goCache)
	t.Setenv("XDG_CACHE_HOME", xdgCache)

	dir := t.TempDir()
	writeModFile := func(rel, content string) {
		t.Helper()
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeModFile("go.mod", "module example.com/unsafemodes\n\ngo 1.26\n")

	// 1. Compile-time layout intrinsics (Sizeof, Alignof, Offsetof) in subject & sibling.
	writeModFile("intrinsics/p.go", `package intrinsics

import "unsafe"

type Header struct {
	tag uint8
	len int64
}

func SiblingLayout[T any](h Header) uintptr {
	var zero T
	return unsafe.Sizeof(h) + unsafe.Alignof(h.len) + unsafe.Offsetof(h.len) + unsafe.Sizeof(zero)
}

func SubjectLayout() uintptr {
	var h Header
	return unsafe.Sizeof(h) + unsafe.Alignof(h.tag) + unsafe.Offsetof(h.len)
}
`)
	writeModFile("intrinsics/p_test.go", `package intrinsics

import "testing"

func TestIntrinsics(t *testing.T) {
	if SubjectLayout() == 0 {
		t.Fatal("unexpected zero size")
	}
}
`)

	// 2. Confined read-only / isomorphic / scalar-bitcast unsafe shapes in unreached siblings.
	writeModFile("confined/p.go", `package confined

import (
	"bytes"
	"unsafe"
)

type TypeParam struct{ name string }
type TypeParamList struct{ tparams []*TypeParam }

func (l *TypeParamList) Len() int {
	if l == nil {
		return 0
	}
	return len(l.tparams)
}

type Term term
type term struct {
	tilde bool
	typ   string
}

func (m *Term) Tilde() bool { return m.tilde }

func SiblingWrapList(n int) *TypeParamList {
	tpars := make([]*TypeParam, n)
	for i := range n {
		tpars[i] = &TypeParam{name: "T"}
	}
	return (*TypeParamList)(unsafe.Pointer(&tpars))
}

func SiblingConvertTerm(x *term) *Term {
	return (*Term)(unsafe.Pointer(x))
}

func SiblingFloatBits(f float64) uint64 {
	return *(*uint64)(unsafe.Pointer(&f))
}

func SiblingStringScan(a, b string) (bool, int) {
	same := unsafe.StringData(a) == unsafe.StringData(b)
	view := unsafe.Slice(unsafe.StringData(a), len(a))
	return same, bytes.IndexByte(view, 'a')
}
`)
	writeModFile("confined/p_test.go", `package confined

import (
	"os"
	"testing"
)

func TestConfinedClean(t *testing.T) {
	_ = os.Getenv("CONFINED_KEY")
}
`)

	// 3. Carrier-free global Banner corrupted via unreached sibling unsafe.Pointer.
	writeModFile("banner/p.go", `package banner

import "unsafe"

var Banner = "ok"

func UnreachedCorruptBanner() {
	p := *(*unsafe.Pointer)(unsafe.Pointer(&Banner))
	*(*byte)(p) = 'X'
}
`)
	writeModFile("banner/p_test.go", `package banner

import (
	"os"
	"testing"
)

func TestReadBanner(t *testing.T) {
	_ = os.Getenv("BANNER_KEY")
	if Banner == "" {
		t.Fatal("empty")
	}
}
`)

	// 4. Shadow capsule mutation (fakeGuidance -> *OnceGuidance) in unreached sibling.
	writeModFile("shadow/p.go", `package shadow

import (
	"sync"
	"unsafe"
)

type OnceGuidance struct {
	once sync.Once
	val  string
}

type fakeGuidance struct {
	once sync.Once
	val  string
}

func UnreachedShadowSmuggle() (*OnceGuidance, func()) {
	fg := &fakeGuidance{val: "a"}
	return (*OnceGuidance)(unsafe.Pointer(fg)), func() { fg.val = "b" }
}
`)
	writeModFile("shadow/p_test.go", `package shadow

import (
	"os"
	"testing"
)

func TestCleanShadow(t *testing.T) {
	_ = os.Getenv("SHADOW_KEY")
}
`)

	// 5. Subject itself reaches unsafe.Pointer.
	writeModFile("reached/p.go", `package reached

import "unsafe"

func FloatBits(f float64) uint64 {
	return *(*uint64)(unsafe.Pointer(&f))
}
`)
	writeModFile("reached/p_test.go", `package reached

import "testing"

func TestReachedUnsafe(t *testing.T) {
	if FloatBits(1.0) == 0 {
		t.Fatal("zero")
	}
}
`)

	// 6. Unreached runtime unsafe.Slice(&b[0], 1) (package-wide hazard across all modes).
	writeModFile("badslice/p.go", `package badslice

import "unsafe"

func UnreachedRawSlice() []byte {
	var b [2]byte
	return unsafe.Slice(&b[0], 2)
}
`)
	writeModFile("badslice/p_test.go", `package badslice

import (
	"os"
	"testing"
)

func TestCleanInBadSlicePkg(t *testing.T) {
	_ = os.Getenv("BADSLICE_KEY")
}
`)

	env := gotool.SetEnv(os.Environ(), "PWD", dir)
	env = gotool.SetEnv(env, "GOCACHE", goCache)
	env = gotool.SetEnv(env, "XDG_CACHE_HOME", xdgCache)
	env = gotool.SetEnv(env, "CONFINED_KEY", "1")
	env = gotool.SetEnv(env, "BANNER_KEY", "1")
	env = gotool.SetEnv(env, "SHADOW_KEY", "1")
	env = gotool.SetEnv(env, "BADSLICE_KEY", "1")
	env = gotool.SetEnv(env, "EXT_KEY", "1")

	subjIntrinsics := Subject{Package: "example.com/unsafemodes/intrinsics", Symbol: "TestIntrinsics"}
	subjConfined := Subject{Package: "example.com/unsafemodes/confined", Symbol: "TestConfinedClean"}
	subjBanner := Subject{Package: "example.com/unsafemodes/banner", Symbol: "TestReadBanner"}
	subjShadow := Subject{Package: "example.com/unsafemodes/shadow", Symbol: "TestCleanShadow"}
	subjReached := Subject{Package: "example.com/unsafemodes/reached", Symbol: "TestReachedUnsafe"}
	subjBadSlice := Subject{Package: "example.com/unsafemodes/badslice", Symbol: "TestCleanInBadSlicePkg"}

	allSubjects := []Subject{
		subjIntrinsics,
		subjConfined,
		subjBanner,
		subjShadow,
		subjReached,
		subjBadSlice,
	}

	logForSubject := map[Subject]string{
		subjIntrinsics: "",
		subjConfined:   "getenv CONFINED_KEY\n",
		subjBanner:     "getenv BANNER_KEY\n",
		subjShadow:     "getenv SHADOW_KEY\n",
		subjReached:    "",
		subjBadSlice:   "getenv BADSLICE_KEY\n",
	}

	newModeSession := func(t *testing.T, mode ExecutionModel, onServed func(Progress)) *Session {
		t.Helper()
		sess, err := NewSession(context.Background(), BuildDescription{
			Directory:   dir,
			Environment: env,
			Inputs:      []string{},
		}, SessionPolicy{
			EvidenceRoot:   dir,
			Execution:      mode,
			AnalysisBudget: 2 * time.Minute,
			Progress:       onServed,
		})
		if err != nil {
			t.Fatal(err)
		}
		return sess
	}

	type modeExpectation struct {
		wantPureCheck      Status
		wantObservable     bool
		wantCheckObserved  Status
		wantSingleSubjAuth bool
		wantReasonSubstr   string
	}

	// Run SingleSubjectExecution FIRST so its execution-agnostic Proofs() memos
	// (including RequiresSingleSubject=true on banner and shadow) populate xdgCache
	// BEFORE GeneralExecution and PackageExecution run!
	modesInOrder := []struct {
		name string
		mode ExecutionModel
	}{
		{"SingleSubjectExecution", SingleSubjectExecution},
		{"PackageExecution", PackageExecution},
		{"GeneralExecution", GeneralExecution},
	}

	var singleSubjectFPs map[Subject]Fingerprint
	for modeIdx, m := range modesInOrder {
		t.Run(m.name, func(t *testing.T) {
			ctx := context.Background()
			servedProofCount := 0
			sess := newModeSession(t, m.mode, func(p Progress) {
				if p.Phase == "served" && p.Served == "observability proof" {
					servedProofCount += p.Index
				}
			})
			producer, err := sess.Snapshot(ctx, allSubjects, CodeResult)
			if err != nil {
				t.Fatal(err)
			}
			fps, err := producer.CaptureObservedBatch(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Subsequent modes sharing xdgCache must hit the persisted Proofs() disk memo
			// written by SingleSubjectExecution across all 6 packages and STILL enforce
			// their own execution model!
			if modeIdx > 0 && servedProofCount != len(allSubjects) {
				t.Fatalf("%s served %d persisted proof packages, want %d", m.name, servedProofCount, len(allSubjects))
			}

			bracket, err := runtimeinput.CaptureBracket(ctx, dir, []string{"."})
			if err != nil {
				t.Fatal(err)
			}
			attached := make(map[Subject]Fingerprint, len(allSubjects))
			for _, s := range allSubjects {
				pkgDir := filepath.Join(dir, pathBase(s.Package))
				var obs runtimeinput.Observation
				if fps[s].ObservationProof.Observable {
					sib, err := producer.Sibling([]Subject{s})
					if err != nil {
						t.Fatal(err)
					}
					obs = supportedObservation(t, sib, dir, pkgDir, "worker-"+m.name, logForSubject[s])
				} else {
					obs, err = runtimeinput.FromTestLog([]byte("# test log\n"+logForSubject[s]), dir, pkgDir, env, runtimeinput.WithCompletedProcess("worker-"+m.name), runtimeinput.WithBracket(bracket))
					if err != nil {
						t.Fatal(err)
					}
				}
				afp, err := producer.AttachObservation(s, fps[s], obs)
				if err != nil {
					t.Fatalf("AttachObservation(%v): %v", s, err)
				}
				attached[s] = afp
			}
			if err := producer.Validate(ctx); err != nil {
				t.Fatalf("Validate(%s): %v", m.name, err)
			}
			if m.mode == SingleSubjectExecution {
				singleSubjectFPs = maps.Clone(attached)
			}

			checker, err := sess.Snapshot(ctx, allSubjects, CodeResult)
			if err != nil {
				t.Fatal(err)
			}

			singleOK := m.mode == SingleSubjectExecution
			wantBySubj := map[Subject]modeExpectation{
				subjIntrinsics: {
					wantPureCheck:      Valid,
					wantObservable:     true,
					wantCheckObserved:  Valid,
					wantSingleSubjAuth: false,
				},
				subjConfined: {
					wantPureCheck:      Unverifiable,
					wantObservable:     true,
					wantCheckObserved:  Valid,
					wantSingleSubjAuth: false,
				},
				subjBanner: {
					wantPureCheck:      Unverifiable,
					wantObservable:     singleOK,
					wantCheckObserved:   ternaryStatus(singleOK, Valid, Unverifiable),
					wantSingleSubjAuth: singleOK,
					wantReasonSubstr:   ternaryStr(singleOK, "", "un-confined unsafe.Pointer"),
				},
				subjShadow: {
					wantPureCheck:      Unverifiable,
					wantObservable:     singleOK,
					wantCheckObserved:  ternaryStatus(singleOK, Valid, Unverifiable),
					wantSingleSubjAuth: singleOK,
					wantReasonSubstr:   ternaryStr(singleOK, "", "un-confined unsafe.Pointer"),
				},
				subjReached: {
					wantPureCheck:     Unverifiable,
					wantObservable:    false,
					wantCheckObserved: Unverifiable,
					wantReasonSubstr:  "unsafe pointer reachable",
				},
				subjBadSlice: {
					wantPureCheck:     Unverifiable,
					wantObservable:    false,
					wantCheckObserved: Unverifiable,
					wantReasonSubstr:  "unsafe.Slice",
				},
			}

			for _, s := range allSubjects {
				exp := wantBySubj[s]
				fp := attached[s]
				if fp.ObservationProof.Observable != exp.wantObservable {
					t.Fatalf("%s %v ObservationProof = %+v, want Observable=%v", m.name, s, fp.ObservationProof, exp.wantObservable)
				}
				if exp.wantReasonSubstr != "" && !strings.Contains(fp.ObservationProof.Reason, exp.wantReasonSubstr) {
					t.Fatalf("%s %v ObservationProof.Reason = %q, want substring %q", m.name, s, fp.ObservationProof.Reason, exp.wantReasonSubstr)
				}
				vPure, err := checker.Check(ctx, fp, s)
				if err != nil || vPure.Status != exp.wantPureCheck {
					t.Fatalf("%s %v Check = (%+v, %v), want %v", m.name, s, vPure, err, exp.wantPureCheck)
				}
				vObs, err := checker.CheckObserved(ctx, fp, s)
				if err != nil || vObs.Status != exp.wantCheckObserved {
					t.Fatalf("%s %v CheckObserved = (%+v, %v), want %v", m.name, s, vObs, err, exp.wantCheckObserved)
				}
				if vObs.Ground.Accepted.Observation.SingleSubject != exp.wantSingleSubjAuth {
					t.Fatalf("%s %v Accepted.Observation = %+v, want SingleSubject=%v", m.name, s, vObs.Ground.Accepted.Observation, exp.wantSingleSubjAuth)
				}
			}
		})
	}

	// 8. Wire-key stability, cross-mode Fingerprint replay rejection, and corrupted Evidence rejection.
	t.Run("cross_mode_replay_and_wire_schema", func(t *testing.T) {
		ctx := context.Background()
		bannerFP := singleSubjectFPs[subjBanner]

		// Verify ObservationProof JSON wire keys remain strictly unchanged (REQ-fresh-fingerprint-record).
		rawProof, err := json.Marshal(bannerFP.ObservationProof)
		if err != nil {
			t.Fatal(err)
		}
		var wireMap map[string]any
		if err := json.Unmarshal(rawProof, &wireMap); err != nil {
			t.Fatal(err)
		}
		gotKeys := slices.Sorted(maps.Keys(wireMap))
		wantKeys := []string{"Evidence", "Observable", "Reason", "Strategy", "Subject"}
		if !slices.Equal(gotKeys, wantKeys) {
			t.Fatalf("ObservationProof JSON keys = %v, want %v", gotKeys, wantKeys)
		}

		// Replay SingleSubjectExecution's valid banner & shadow Fingerprints into
		// GeneralExecution and PackageExecution CheckObserved AND RuntimeBinding.Check.
		for _, sharedMode := range []ExecutionModel{GeneralExecution, PackageExecution} {
			sess := newModeSession(t, sharedMode, nil)
			snap, err := sess.Snapshot(ctx, []Subject{subjBanner, subjShadow, subjConfined}, CodeResult)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := snap.BindRuntime(ctx, RuntimeDescription{Directory: dir, Environment: env})
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range []Subject{subjBanner, subjShadow} {
				vObs, err := snap.CheckObserved(ctx, singleSubjectFPs[s], s)
				if err != nil || vObs.Status != Unverifiable || vObs.Ground.Accepted.Observation != (ObservationAuthority{}) {
					t.Fatalf("mode %v replaying SingleSubject %v via CheckObserved = (%+v, %v), want Unverifiable with zero ObservationAuthority", sharedMode, s, vObs, err)
				}
				vBind, err := binding.Check(ctx, s, singleSubjectFPs[s])
				if err != nil || vBind.Status != Unverifiable || vBind.Ground.Accepted.Observation != (ObservationAuthority{}) {
					t.Fatalf("mode %v replaying SingleSubject %v via RuntimeBinding.Check = (%+v, %v), want Unverifiable", sharedMode, s, vBind, err)
				}
			}
			// Meanwhile, confined's SingleSubjectExecution Fingerprint (which has :ss:false)
			// replays Valid across GeneralExecution and PackageExecution!
			vConf, err := snap.CheckObserved(ctx, singleSubjectFPs[subjConfined], subjConfined)
			if err != nil || vConf.Status != Valid || vConf.Ground.Accepted.Observation.SingleSubject {
				t.Fatalf("mode %v replaying confined FP = (%+v, %v), want Valid with SingleSubject=false", sharedMode, vConf, err)
			}
		}

		// Replay into a fresh SingleSubjectExecution session succeeds with SingleSubject=true,
		// while a tampered Evidence digest fails closed!
		soloSess := newModeSession(t, SingleSubjectExecution, nil)
		soloSnap, err := soloSess.Snapshot(ctx, []Subject{subjBanner}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		vValid, err := soloSnap.CheckObserved(ctx, bannerFP, subjBanner)
		if err != nil || vValid.Status != Valid || !vValid.Ground.Accepted.Observation.SingleSubject {
			t.Fatalf("fresh SingleSubjectExecution replay = (%+v, %v), want Valid with SingleSubject=true", vValid, err)
		}
		tampered := bannerFP
		if strings.HasSuffix(tampered.ObservationProof.Evidence, "0") {
			tampered.ObservationProof.Evidence = tampered.ObservationProof.Evidence[:len(tampered.ObservationProof.Evidence)-1] + "1"
		} else {
			tampered.ObservationProof.Evidence = tampered.ObservationProof.Evidence[:len(tampered.ObservationProof.Evidence)-1] + "0"
		}
		vTampered, err := soloSnap.CheckObserved(ctx, tampered, subjBanner)
		if err != nil || vTampered.Status != Unverifiable {
			t.Fatalf("tampered Evidence replay = (%+v, %v), want Unverifiable", vTampered, err)
		}

		// ExplicitPurity (PureSubjects) alongside RequiresSingleSubject: recording
		// under SingleSubjectExecution + PureSubjects and checking under
		// PackageExecution + PureSubjects admits on purity authority without
		// fabricating ObservationAuthority.
		soloPureSess, err := NewSession(ctx, BuildDescription{Directory: dir, Environment: env, Inputs: []string{}}, SessionPolicy{
			Execution:    SingleSubjectExecution,
			PureSubjects: []Subject{subjBanner},
		})
		if err != nil {
			t.Fatal(err)
		}
		soloPureProd, err := soloPureSess.Snapshot(ctx, []Subject{subjBanner}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		pureBaseFPs, err := soloPureProd.CaptureObservedBatch(ctx)
		if err != nil {
			t.Fatal(err)
		}
		pureObs := supportedObservation(t, soloPureProd, dir, filepath.Join(dir, "banner"), "worker-pure", logForSubject[subjBanner])
		pureBannerFP, err := soloPureProd.AttachObservation(subjBanner, pureBaseFPs[subjBanner], pureObs)
		if err != nil {
			t.Fatal(err)
		}
		if err := soloPureProd.Validate(ctx); err != nil {
			t.Fatal(err)
		}
		pureSess, err := NewSession(ctx, BuildDescription{Directory: dir, Environment: env, Inputs: []string{}}, SessionPolicy{
			Execution:    PackageExecution,
			PureSubjects: []Subject{subjBanner},
		})
		if err != nil {
			t.Fatal(err)
		}
		pureSnap, err := pureSess.Snapshot(ctx, []Subject{subjBanner}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		vPure, err := pureSnap.CheckObserved(ctx, pureBannerFP, subjBanner)
		if err != nil || vPure.Status != Valid {
			t.Fatalf("PackageExecution + PureSubjects CheckObserved = (%+v, %v), want Valid", vPure, err)
		}
		if vPure.Ground.Accepted.Purity.Recorded == 0 || vPure.Ground.Accepted.Purity.Current == 0 || vPure.Ground.Accepted.Observation != (ObservationAuthority{}) {
			t.Fatalf("PackageExecution + PureSubjects Accepted = %+v, want Recorded+Current Purity set and zero ObservationAuthority", vPure.Ground.Accepted)
		}

		// Unit.Execute / Close enforces RequiresSingleSubject across PackageExecution vs SingleSubjectExecution.
		pkgSess := newModeSession(t, PackageExecution, nil)
		pkgUnitSnap, err := pkgSess.Snapshot(ctx, []Subject{subjBanner}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		pkgBind, err := pkgUnitSnap.BindRuntime(ctx, RuntimeDescription{Directory: dir, Environment: env})
		if err != nil {
			t.Fatal(err)
		}
		pkgBuilt, err := pkgUnitSnap.BindBuilt(subjBanner.Package, "banner-pkg.test")
		if err != nil {
			t.Fatal(err)
		}
		pkgUnit, err := pkgBind.Begin(subjBanner)
		if err != nil {
			t.Fatal(err)
		}
		pkgLog := filepath.Join(t.TempDir(), "pkg-testlog.txt")
		pkgFin, err := pkgUnit.Execute(ctx, pkgBuilt, ProcessDescription{Identity: "pkg-proc", Capture: pkgLog}, func(_ context.Context, _ Contribution) (Terminal, error) {
			if err := os.WriteFile(pkgLog, []byte("# test log\n"), 0o600); err != nil {
				return Terminal{}, err
			}
			return Terminal{Kind: NormalCompletion}, nil
		})
		if err != nil {
			t.Fatalf("pkgUnit.Execute err = %v", err)
		}
		if pkgFin.Verdict.Status != Unverifiable || pkgFin.Verdict.Ground.Accepted.Observation != (ObservationAuthority{}) {
			t.Fatalf("PackageExecution Unit.Close verdict = %+v, want Unverifiable with zero ObservationAuthority", pkgFin.Verdict)
		}

		soloBind, err := soloSnap.BindRuntime(ctx, RuntimeDescription{Directory: dir, Environment: env})
		if err != nil {
			t.Fatal(err)
		}
		soloBuilt, err := soloSnap.BindBuilt(subjBanner.Package, "banner-solo.test")
		if err != nil {
			t.Fatal(err)
		}
		soloUnit, err := soloBind.Begin(subjBanner)
		if err != nil {
			t.Fatal(err)
		}
		soloLog := filepath.Join(t.TempDir(), "solo-testlog.txt")
		soloFin, err := soloUnit.Execute(ctx, soloBuilt, ProcessDescription{Identity: "solo-proc", Capture: soloLog}, func(_ context.Context, _ Contribution) (Terminal, error) {
			if err := os.WriteFile(soloLog, []byte("# test log\n"), 0o600); err != nil {
				return Terminal{}, err
			}
			return Terminal{Kind: NormalCompletion}, nil
		})
		if err != nil {
			t.Fatalf("soloUnit.Execute err = %v", err)
		}
		if soloFin.Verdict.Status != Valid || !soloFin.Verdict.Ground.Accepted.Observation.SingleSubject {
			t.Fatalf("SingleSubjectExecution Unit.Close verdict = %+v, want Valid with SingleSubject=true", soloFin.Verdict)
		}
	})

	// 9. Commit-1 -> Commit-2 ExtendInertBatch / CheckBatchWithLedgers applicability extension
	// when Commit 2 adds an unexecuted sibling test using un-confined unsafe.Pointer.
	t.Run("inert_test_variant_extension_introducing_sibling_unsafe", func(t *testing.T) {
		ctx := context.Background()
		writeModFile("ext/p.go", `package ext

var Banner = "clean"
`)
		commit1Test := `package ext

import (
	"os"
	"testing"
)

func TestReadExt(t *testing.T) {
	_ = os.Getenv("EXT_KEY")
	if Banner == "" {
		t.Fatal("empty")
	}
}
`
		writeModFile("ext/p_test.go", commit1Test)
		subjExt := Subject{Package: "example.com/unsafemodes/ext", Symbol: "TestReadExt"}

		// Capture Commit 1 under PackageExecution (RequiresSingleSubject == false at Commit 1).
		sess1 := newModeSession(t, PackageExecution, nil)
		prod1, err := sess1.Snapshot(ctx, []Subject{subjExt}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		fp1, err := prod1.captureObserved(ctx, subjExt)
		if err != nil {
			t.Fatal(err)
		}
		ledger1, err := prod1.TestVariantLedger(subjExt)
		if err != nil {
			t.Fatal(err)
		}
		extDir := filepath.Join(dir, "ext")
		fp1, err = prod1.AttachObservation(subjExt, fp1, supportedObservation(t, prod1, dir, extDir, "ext-c1", "getenv EXT_KEY\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := prod1.Validate(ctx); err != nil {
			t.Fatal(err)
		}

		// Commit 2: add unexecuted sibling test mutating Banner via unsafe.Pointer.
		commit2Test := commit1Test + `
func TestSiblingUnsafeCorrupt(t *testing.T) {
	// Never reached by TestReadExt, but shares the package test binary!
	corruptBanner()
}
`
		writeModFile("ext/unsafe_helper_test.go", `package ext

import "unsafe"

func corruptBanner() {
	p := *(*unsafe.Pointer)(unsafe.Pointer(&Banner))
	*(*byte)(p) = 'Z'
}
`)
		writeModFile("ext/p_test.go", commit2Test)

		// Under GeneralExecution and PackageExecution, CheckBatchWithLedgers MUST refuse extension!
		for _, sharedMode := range []ExecutionModel{GeneralExecution, PackageExecution} {
			sess2 := newModeSession(t, sharedMode, nil)
			snap2, err := sess2.Snapshot(ctx, []Subject{subjExt}, CodeResult)
			if err != nil {
				t.Fatal(err)
			}
			bind2, err := snap2.BindRuntime(ctx, RuntimeDescription{Directory: dir, Environment: env})
			if err != nil {
				t.Fatal(err)
			}
			checked, err := bind2.CheckBatchWithLedgers(ctx, []Candidate{{Subject: subjExt, Recorded: fp1}}, map[int]TestVariantLedger{0: ledger1.Clone()})
			if err != nil {
				t.Fatal(err)
			}
			if len(checked) != 1 || checked[0].Verdict.Status != Stale || checked[0].Verdict.Reason != ReasonTestVariants || checked[0].Extension != nil {
				t.Fatalf("mode %v CheckBatchWithLedgers at Commit 2 = %+v, want unextended Stale(test variants) with nil Extension", sharedMode, checked)
			}
			if _, _, extVerdict, err := snap2.checkInertTestVariantExtension(ctx, fp1, ledger1.Clone(), subjExt, true); err != nil || extVerdict.Status != Unverifiable {
				t.Fatalf("mode %v checkInertTestVariantExtension at Commit 2 = (%+v, %v), want Unverifiable", sharedMode, extVerdict, err)
			}
		}

		// Under SingleSubjectExecution, CheckBatchWithLedgers MUST extend Valid with SingleSubject=true!
		soloSess2 := newModeSession(t, SingleSubjectExecution, nil)
		soloSnap2, err := soloSess2.Snapshot(ctx, []Subject{subjExt}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		soloBind2, err := soloSnap2.BindRuntime(ctx, RuntimeDescription{Directory: dir, Environment: env})
		if err != nil {
			t.Fatal(err)
		}
		soloChecked, err := soloBind2.CheckBatchWithLedgers(ctx, []Candidate{{Subject: subjExt, Recorded: fp1}}, map[int]TestVariantLedger{0: ledger1.Clone()})
		if err != nil {
			t.Fatal(err)
		}
		if len(soloChecked) != 1 || soloChecked[0].Verdict.Status != Valid || soloChecked[0].Extension == nil {
			t.Fatalf("SingleSubjectExecution CheckBatchWithLedgers at Commit 2 = %+v, want Valid with Extension", soloChecked)
		}
		if !soloChecked[0].Verdict.Ground.Accepted.Observation.CurrentApplicability || !soloChecked[0].Verdict.Ground.Accepted.Observation.SingleSubject {
			t.Fatalf("SingleSubjectExecution extended authority = %+v, want CurrentApplicability=true and SingleSubject=true", soloChecked[0].Verdict.Ground.Accepted.Observation)
		}

		// Replaying that extended Fingerprint (whose Commit-1 producing proof had :ss:false!)
		// into PackageExecution MUST STILL refuse because Commit-2 applicability re-checks
		// currentApplicabilityObservableMode under PackageExecution!
		extendedFP := soloChecked[0].Extension.Fingerprint
		pkgSess2 := newModeSession(t, PackageExecution, nil)
		pkgSnap2, err := pkgSess2.Snapshot(ctx, []Subject{subjExt}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		vReplayPkg, err := pkgSnap2.CheckObserved(ctx, extendedFP, subjExt)
		if err != nil || vReplayPkg.Status != Unverifiable {
			t.Fatalf("PackageExecution replaying Commit-2 extended FP = (%+v, %v), want Unverifiable", vReplayPkg, err)
		}
		vReplaySolo, err := soloSnap2.CheckObserved(ctx, extendedFP, subjExt)
		if err != nil || vReplaySolo.Status != Valid || !vReplaySolo.Ground.Accepted.Observation.SingleSubject {
			t.Fatalf("SingleSubjectExecution replaying Commit-2 extended FP = (%+v, %v), want Valid with SingleSubject=true", vReplaySolo, err)
		}
	})

	// 10. Real go-x-tools & gofresh self-hosting verification: loading internal/closure
	// with LoadAllSyntax brings in the real go-x-tools/go/ssa, go-x-tools/go/ssa/ssautil,
	// go-x-tools/internal/typeparams, and gofresh/internal/closure packages on disk and
	// proves PackageHasUnconfinedUnsafeMemoryHazard is false on every one of them!
	t.Run("real_go_x_tools_self_hosting_does_not_require_single_subject", func(t *testing.T) {
		ctx := context.Background()
		repoRoot, err := filepath.Abs(".")
		if err != nil {
			t.Fatal(err)
		}
		repoEnv := gotool.SetEnv(os.Environ(), "PWD", repoRoot)
		repoEnv = gotool.SetEnv(repoEnv, "GOCACHE", goCache)
		repoEnv = gotool.SetEnv(repoEnv, "XDG_CACHE_HOME", xdgCache)
		roots, err := gotool.LoadPackages(ctx, packages.LoadAllSyntax, repoRoot, repoEnv, nil, "./internal/closure")
		if err != nil {
			t.Fatal(err)
		}
		byPath := map[string]*packages.Package{}
		byTypes := map[*types.Package]*packages.Package{}
		packages.Visit(roots, nil, func(p *packages.Package) {
			if p != nil && p.Types != nil {
				byPath[p.PkgPath] = p
				byTypes[p.Types] = p
			}
		})
		for _, target := range []string{
			"github.com/greatliontech/go-x-tools/go/ssa",
			"github.com/greatliontech/go-x-tools/go/ssa/ssautil",
			"github.com/greatliontech/go-x-tools/internal/typeparams",
			"github.com/greatliontech/gofresh/internal/closure",
		} {
			p := byPath[target]
			if p == nil {
				t.Fatalf("expected loaded package %s in ./internal/closure dependency graph", target)
			}
			if reason := refconfine.PackageUnsafeMemoryHazardReason(p, p.TypesSizes, byTypes); reason != "" {
				t.Fatalf("PackageHasUnconfinedUnsafeMemoryHazard(%s) = true (%s), want false on real self-hosted source", target, reason)
			}
		}
	})
}

func pathBase(pkgPath string) string {
	idx := strings.LastIndexByte(pkgPath, '/')
	if idx < 0 {
		return pkgPath
	}
	return pkgPath[idx+1:]
}

func ternaryStatus(cond bool, a, b Status) Status {
	if cond {
		return a
	}
	return b
}

func ternaryStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
