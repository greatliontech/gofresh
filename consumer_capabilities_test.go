package gofresh

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/trace"
	"pgregory.net/rapid"
)

func TestStaticDeclarationSubjectsAndSourceResultMatrix(t *testing.T) {
	isolateProofCache(t)
	dir := writeModuleTree(t, map[string]string{
		"go.mod": "module example.com/staticdecl\n\ngo 1.26\n",
		"sub/sub.go": "package sub\n\n" +
			"type Base struct {\n" +
			"\tPromoted int\n" +
			"\t//gofresh:external\n" +
			"\tExtField int\n" +
			"}\n\n" +
			"type BaseIface interface {\n" +
			"\tBaseOp() int\n" +
			"\t//gofresh:external\n" +
			"\tExtOp() int\n" +
			"}\n",
		"p.go": "package staticdecl\n\n" +
			"import (\n\t\"os\"\n\t\"example.com/staticdecl/sub\"\n)\n\n" +
			"const MaxItems = 64\n\n" +
			"var GlobalCount = 1\n\n" +
			"//gofresh:external\n" +
			"var ExternalReg = 2\n\n" +
			"type Node struct {\n" +
			"\t*Node\n" +
			"\tVal int\n" +
			"}\n\n" +
			"type Config struct {\n" +
			"\tsub.Base\n" +
			"\tTimeout int\n" +
			"\t//gofresh:external\n" +
			"\tFD uintptr\n" +
			"}\n\n" +
			"type AliasCfg = Config\n\n" +
			"type Spec interface {\n" +
			"\tsub.BaseIface\n" +
			"\tRun() error\n" +
			"}\n\n" +
			"func ImpureFunc() ([]byte, error) {\n" +
			"\treturn os.ReadFile(\"a.txt\")\n" +
			"}\n\n" +
			"func SiblingInImpurePkg() int { return MaxItems }\n\n" +
			"//gofresh:pure\n" +
			"func PureFunc() int { return MaxItems }\n",
		"p_test.go": "package staticdecl\n\nimport \"testing\"\n\nfunc TestPure(t *testing.T) {\n\tif PureFunc() != 64 {\n\t\tt.Fatal()\n\t}\n}\n",
		"ext_test.go": "package staticdecl_test\n\n" +
			"import \"example.com/staticdecl/sub\"\n\n" +
			"type AmbAlias = sub.Base\n",
		"amb.go": "package staticdecl\n\nimport \"example.com/staticdecl/sub\"\n\ntype AmbAlias = sub.Base\n",
	})

	pkg := "example.com/staticdecl"
	allSubjects := []Subject{
		{Package: pkg, Symbol: "MaxItems"},
		{Package: pkg, Symbol: "GlobalCount"},
		{Package: pkg, Symbol: "ExternalReg"},
		{Package: pkg, Symbol: "Node"},
		{Package: pkg, Symbol: "Node.Val"},
		{Package: pkg, Symbol: "Config"},
		{Package: pkg, Symbol: "Config.Timeout"},
		{Package: pkg, Symbol: "Config.Promoted"},
		{Package: pkg, Symbol: "Config.ExtField"},
		{Package: pkg, Symbol: "Config.FD"},
		{Package: pkg, Symbol: "AliasCfg"},
		{Package: pkg, Symbol: "AliasCfg.Timeout"},
		{Package: pkg, Symbol: "Spec"},
		{Package: pkg, Symbol: "Spec.Run"},
		{Package: pkg, Symbol: "Spec.BaseOp"},
		{Package: pkg, Symbol: "Spec.ExtOp"},
		{Package: pkg, Symbol: "ImpureFunc"},
		{Package: pkg, Symbol: "SiblingInImpurePkg"},
		{Package: pkg, Symbol: "PureFunc"},
		{Package: pkg, Symbol: "AmbAlias"},
		{Package: pkg, Symbol: "AmbAlias.Promoted"},
	}

	sess, ctx, rec := newTracedSession(t, BuildDescription{
		Directory:   dir,
		Environment: os.Environ(),
		Inputs:      []string{"classifier=v1"},
	}, SessionPolicy{Execution: PackageExecution})

	// 1. Measurement refuses non-callable declarations at Snapshot preparation with causal trace.
	if _, err := sess.Snapshot(ctx, []Subject{{Package: pkg, Symbol: "Config"}}, Measurement); err == nil || !strings.Contains(err.Error(), "non-callable declaration") {
		t.Fatalf("Snapshot(Measurement, Config) = %v, want non-callable declaration refusal", err)
	}
	testenv.RequireTraceEvent(t, rec, trace.DomainView, "snapshot.static_decl.refused", func(ev trace.Event) bool {
		return ev.StringField("reason") == "measurement_requires_callable"
	})

	// 2. SourceResult certifies both callables (even ImpureFunc!) and non-callables, while refusing ambiguous declarations.
	srcSnap, err := sess.Snapshot(ctx, allSubjects, SourceResult)
	if err != nil {
		t.Fatalf("Snapshot(SourceResult): %v", err)
	}
	srcFPs, err := srcSnap.CaptureBatch(ctx)
	if err != nil {
		t.Fatalf("SourceResult CaptureBatch: %v", err)
	}
	srcBind, err := srcSnap.BindRuntime(ctx, RuntimeDescription{Directory: dir})
	if err != nil {
		t.Fatalf("SourceResult BindRuntime: %v", err)
	}
	if _, err := srcBind.NeedsObservation([]Subject{{Package: pkg, Symbol: "PureFunc"}}); err == nil {
		t.Fatal("SourceResult NeedsObservation succeeded, want refusal")
	}
	if _, err := srcBind.Begin(Subject{Package: pkg, Symbol: "PureFunc"}); err == nil {
		t.Fatal("SourceResult Begin succeeded, want refusal")
	}
	var srcCands []Candidate
	for _, s := range allSubjects {
		fp := srcFPs[s]
		if fp.ResultKind != SourceResult || fp.DynamicStateStrategy != "" {
			t.Fatalf("SourceResult fingerprint for %v = %+v, want SourceResult with empty DynamicStateStrategy", s, fp)
		}
		raw, err := json.Marshal(fp)
		if err != nil {
			t.Fatalf("MarshalJSON SourceResult %v: %v", s, err)
		}
		var roundTrip Fingerprint
		if err := json.Unmarshal(raw, &roundTrip); err != nil || roundTrip != fp {
			t.Fatalf("UnmarshalJSON SourceResult %v: (%+v, %v)", s, roundTrip, err)
		}
		srcCands = append(srcCands, Candidate{Subject: s, Recorded: fp})
	}
	srcChecked, err := srcBind.CheckBatchWithLedgers(ctx, srcCands, nil)
	if err != nil {
		t.Fatalf("SourceResult CheckBatchWithLedgers: %v", err)
	}
	for _, c := range srcChecked {
		wantStatus := Valid
		wantCause := NoCause
		if c.Subject.Symbol == "AmbAlias" || c.Subject.Symbol == "AmbAlias.Promoted" {
			wantStatus = Unverifiable
			wantCause = AmbiguousSubjectCause
		}
		if c.Verdict.Status != wantStatus || c.Verdict.Ground.Cause.Kind != wantCause {
			t.Fatalf("SourceResult %s verdict = %+v, want %s/%v", c.Subject.Symbol, c.Verdict, wantStatus, wantCause)
		}
	}

	// 3. CodeResult certifies non-callable declarations (honoring //gofresh:external and AmbiguousSubjectCause),
	// keeps ImpureFunc unverifiable, and refuses Unit/NeedsObservation on non-callable declarations.
	codeSnap, err := sess.Snapshot(ctx, allSubjects, CodeResult)
	if err != nil {
		t.Fatalf("Snapshot(CodeResult): %v", err)
	}
	codeFPs, err := codeSnap.CaptureBatch(ctx)
	if err != nil {
		t.Fatalf("CodeResult CaptureBatch: %v", err)
	}
	codeBind, err := codeSnap.BindRuntime(ctx, RuntimeDescription{Directory: dir})
	if err != nil {
		t.Fatalf("CodeResult BindRuntime: %v", err)
	}
	for _, nonCall := range []string{"MaxItems", "GlobalCount", "Config", "Config.Timeout", "Spec", "Spec.Run"} {
		subj := Subject{Package: pkg, Symbol: nonCall}
		if _, err := codeBind.Begin(subj); err == nil || !strings.Contains(err.Error(), "non-callable declaration") {
			t.Fatalf("Begin(%s) = %v, want non-callable declaration refusal", nonCall, err)
		}
		if _, err := codeBind.NeedsObservation([]Subject{subj}); err == nil || !strings.Contains(err.Error(), "non-callable declaration") {
			t.Fatalf("NeedsObservation(%s) = %v, want non-callable declaration refusal", nonCall, err)
		}
	}

	var codeCands []Candidate
	for _, s := range allSubjects {
		codeCands = append(codeCands, Candidate{Subject: s, Recorded: codeFPs[s]})
	}
	codeChecked, err := codeBind.CheckBatchWithLedgers(ctx, codeCands, nil)
	if err != nil {
		t.Fatalf("CodeResult CheckBatchWithLedgers: %v", err)
	}
	for _, c := range codeChecked {
		switch c.Subject.Symbol {
		case "AmbAlias", "AmbAlias.Promoted":
			if c.Verdict.Status != Unverifiable || c.Verdict.Ground.Cause.Kind != AmbiguousSubjectCause {
				t.Fatalf("CodeResult %s = %+v, want Unverifiable/AmbiguousSubjectCause", c.Subject.Symbol, c.Verdict)
			}
		case "ExternalReg", "Config.ExtField", "Config.FD", "Spec.ExtOp":
			if c.Verdict.Status != Unverifiable || c.Verdict.Ground.Cause.Kind != ExternalDirectiveCause {
				t.Fatalf("CodeResult %s = %+v, want Unverifiable/ExternalDirectiveCause", c.Subject.Symbol, c.Verdict)
			}
		case "ImpureFunc", "SiblingInImpurePkg":
			if c.Verdict.Status != Unverifiable {
				t.Fatalf("CodeResult %s = %+v, want Unverifiable", c.Subject.Symbol, c.Verdict)
			}
		default:
			if c.Verdict.Status != Valid {
				t.Fatalf("CodeResult %s = %+v, want Valid", c.Subject.Symbol, c.Verdict)
			}
		}
	}

	// 4. Inert test-variant extension works on non-callable declarations (Config.Timeout, Spec.Run) and SourceResult!
	priorLedger, err := codeSnap.TestVariantLedger(Subject{Package: pkg, Symbol: "Config.Timeout"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p_test.go"), []byte("package staticdecl\n\nimport \"testing\"\n\nfunc TestPure(t *testing.T) {\n\tif PureFunc() != 64 {\n\t\tt.Fatal(\"edited\")\n\t}\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	codeSnap2, err := sess.Snapshot(ctx, []Subject{
		{Package: pkg, Symbol: "Config.Timeout"},
		{Package: pkg, Symbol: "Spec.Run"},
	}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	codeBind2, err := codeSnap2.BindRuntime(ctx, RuntimeDescription{Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	extChecked, err := codeBind2.CheckBatchWithLedgers(ctx, []Candidate{
		{Subject: Subject{Package: pkg, Symbol: "Config.Timeout"}, Recorded: codeFPs[Subject{Package: pkg, Symbol: "Config.Timeout"}]},
		{Subject: Subject{Package: pkg, Symbol: "Spec.Run"}, Recorded: codeFPs[Subject{Package: pkg, Symbol: "Spec.Run"}]},
	}, map[int]TestVariantLedger{0: priorLedger, 1: priorLedger})
	if err != nil {
		t.Fatalf("CheckBatchWithLedgers after sibling test edit: %v", err)
	}
	for _, c := range extChecked {
		if c.Verdict.Status != Valid || c.Extension == nil {
			t.Fatalf("inert extension for %s = %+v, want Valid with Extension", c.Subject.Symbol, c)
		}
	}

	// SourceResult also supports CheckBatchWithLedgers inert test-variant extension AND exercises
	// AdmissionPolicyCause, ClosureStrategyCause, and ToolchainContentCause branches!
	srcSnap2, err := sess.Snapshot(ctx, []Subject{
		{Package: pkg, Symbol: "Config.Timeout"},
		{Package: pkg, Symbol: "ImpureFunc"},
	}, SourceResult)
	if err != nil {
		t.Fatal(err)
	}
	srcBind2, err := srcSnap2.BindRuntime(ctx, RuntimeDescription{Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	srcExtChecked, err := srcBind2.CheckBatchWithLedgers(ctx, []Candidate{
		{Subject: Subject{Package: pkg, Symbol: "Config.Timeout"}, Recorded: srcFPs[Subject{Package: pkg, Symbol: "Config.Timeout"}]},
		{Subject: Subject{Package: pkg, Symbol: "ImpureFunc"}, Recorded: srcFPs[Subject{Package: pkg, Symbol: "ImpureFunc"}]},
	}, map[int]TestVariantLedger{0: priorLedger, 1: priorLedger})
	if err != nil {
		t.Fatalf("SourceResult CheckBatchWithLedgers: %v", err)
	}
	for _, c := range srcExtChecked {
		if c.Verdict.Status != Valid || c.Extension == nil {
			t.Fatalf("SourceResult inert extension for %s = %+v, want Valid with Extension", c.Subject.Symbol, c)
		}
	}
	freshSrcFP := srcExtChecked[0].Extension.Fingerprint
	for _, tc := range []struct {
		name   string
		mutate func(*Fingerprint)
		status Status
		cause  Cause
	}{
		{
			name:   "admission policy changed",
			mutate: func(fp *Fingerprint) { fp.AdmissionPolicy = "moved-policy" },
			status: Stale,
			cause:  Cause{Kind: AdmissionPolicyCause, Condition: Changed},
		},
		{
			name:   "admission policy missing",
			mutate: func(fp *Fingerprint) { fp.AdmissionPolicy = "" },
			status: Unverifiable,
			cause:  Cause{Kind: AdmissionPolicyCause, Condition: Missing},
		},
		{
			name:   "toolchain content changed",
			mutate: func(fp *Fingerprint) { fp.ToolchainContent = "moved-tc" },
			status: Stale,
			cause:  Cause{Kind: ToolchainContentCause, Condition: Changed},
		},
		{
			name:   "toolchain content missing",
			mutate: func(fp *Fingerprint) { fp.ToolchainContent = "" },
			status: Unverifiable,
			cause:  Cause{Kind: ToolchainContentCause, Condition: Missing},
		},
		{
			name:   "closure strategy missing",
			mutate: func(fp *Fingerprint) { fp.ClosureStrategy = "" },
			status: Stale,
			cause:  Cause{Kind: ClosureStrategyCause, Condition: Missing},
		},
		{
			name:   "closure strategy unsupported",
			mutate: func(fp *Fingerprint) { fp.ClosureStrategy = "gofresh/closure@999" },
			status: Stale,
			cause:  Cause{Kind: ClosureStrategyCause, Condition: Unsupported},
		},
	} {
		candFP := freshSrcFP
		tc.mutate(&candFP)
		got, err := srcBind2.Check(ctx, Subject{Package: pkg, Symbol: "Config.Timeout"}, candFP)
		if err != nil {
			t.Fatalf("%s: Check err = %v", tc.name, err)
		}
		if got.Status != tc.status || got.Ground.Cause != tc.cause {
			t.Fatalf("%s: got (%s, %+v), want (%s, %+v)", tc.name, got.Status, got.Ground.Cause, tc.status, tc.cause)
		}
	}

	// 5. Conflicting //gofresh:pure and //gofresh:external on a static declaration fails closed.
	conflictDir := writeModuleTree(t, map[string]string{
		"go.mod": "module example.com/conflict\n\ngo 1.26\n",
		"p.go":   "package conflict\n\n//gofresh:pure\n//gofresh:external\ntype Bad struct{}\n",
	})
	conflictSess, err := NewSession(ctx, BuildDescription{
		Directory:   conflictDir,
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conflictSess.Snapshot(ctx, []Subject{{Package: "example.com/conflict", Symbol: "Bad"}}, CodeResult); err == nil || !strings.Contains(err.Error(), "both //gofresh:pure and //gofresh:external") {
		t.Fatalf("Snapshot on conflicting static directives = %v, want directive conflict refusal", err)
	}
}

func TestWithExecutionProjectionEquivalenceAndZeroSpawns(t *testing.T) {
	isolateProofCache(t)
	dir := writeModuleTree(t, map[string]string{
		"go.mod":       "module example.com/execproj\n\ngo 1.26\n",
		"wire/wire.go": "package wire\n\nvar reg func() int\n\nfunc Touch() { reg = func() int { return 1 } }\nfunc Read() bool { return reg != nil }\n",
		"p/p.go":       "package p\n\nimport \"example.com/execproj/wire\"\n\nfunc Clean() bool { return wire.Read() }\nfunc Dirty() { wire.Touch() }\n",
		"p/p_test.go":  "package p\n\nimport \"testing\"\n\nfunc TestClean(t *testing.T) {\n\t_ = Clean()\n}\n\nfunc TestDirty(t *testing.T) {\n\tDirty()\n}\n",
		"q/q.go":       "package q\n\nimport \"example.com/execproj/wire\"\n\nfunc OnlyRead() bool { return wire.Read() }\n",
		"q/q_test.go":  "package q\n\nimport \"testing\"\n\nfunc TestOnlyRead(t *testing.T) {\n\t_ = OnlyRead()\n}\n",
	})

	sClean := Subject{Package: "example.com/execproj/p", Symbol: "TestClean"}
	sDirty := Subject{Package: "example.com/execproj/p", Symbol: "TestDirty"}
	sOnlyRead := Subject{Package: "example.com/execproj/q", Symbol: "TestOnlyRead"}
	subjects := []Subject{sClean, sDirty, sOnlyRead}

	var goSpawns int
	countingPrepare := func(*exec.Cmd) { goSpawns++ }

	pkgSess, ctx, _ := newTracedSession(t, BuildDescription{
		Directory:   dir,
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{
		Execution:      PackageExecution,
		PrepareCommand: countingPrepare,
	})
	baseSnap, err := pkgSess.Snapshot(ctx, subjects, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	if baseSnap.ExecutionModel() != PackageExecution {
		t.Fatalf("baseSnap.ExecutionModel() = %v, want PackageExecution", baseSnap.ExecutionModel())
	}

	spawnsBeforeProj := goSpawns
	genProj, err := baseSnap.WithExecution(GeneralExecution)
	if err != nil {
		t.Fatalf("WithExecution(GeneralExecution): %v", err)
	}
	soloProj, err := baseSnap.WithExecution(SingleSubjectExecution)
	if err != nil {
		t.Fatalf("WithExecution(SingleSubjectExecution): %v", err)
	}
	pkgRoundTrip, err := soloProj.WithExecution(PackageExecution)
	if err != nil {
		t.Fatalf("soloProj.WithExecution(PackageExecution): %v", err)
	}
	if goSpawns != spawnsBeforeProj {
		t.Fatalf("WithExecution spawned %d go commands, want 0", goSpawns-spawnsBeforeProj)
	}

	// Oracle check: compare projected snapshots against fresh independent Sessions for each ExecutionModel!
	for _, tc := range []struct {
		model     ExecutionModel
		projected *Snapshot
		wantValid map[Subject]bool
	}{
		{
			model:     GeneralExecution,
			projected: genProj,
			wantValid: map[Subject]bool{sClean: false, sDirty: false, sOnlyRead: false},
		},
		{
			model:     PackageExecution,
			projected: pkgRoundTrip,
			// Under PackageExecution: q's binary never touches wire.reg (TestOnlyRead Valid),
			// whereas p's binary contains TestDirty so both TestClean and TestDirty see wire.reg!
			wantValid: map[Subject]bool{sClean: false, sDirty: false, sOnlyRead: true},
		},
		{
			model:     SingleSubjectExecution,
			projected: soloProj,
			// Under SingleSubjectExecution: TestClean and TestOnlyRead never touch wire.reg (Valid),
			// while TestDirty mutates wire.reg (SharedDynamicStateCause)!
			wantValid: map[Subject]bool{sClean: true, sDirty: false, sOnlyRead: true},
		},
	} {
		oracleSess, err := NewSession(ctx, BuildDescription{
			Directory:   dir,
			Environment: os.Environ(),
			Inputs:      []string{},
		}, SessionPolicy{Execution: tc.model})
		if err != nil {
			t.Fatal(err)
		}
		oracleSnap, err := oracleSess.Snapshot(ctx, subjects, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		projFPs, err := tc.projected.CaptureBatch(ctx)
		if err != nil {
			t.Fatal(err)
		}
		oracleFPs, err := oracleSnap.CaptureBatch(ctx)
		if err != nil {
			t.Fatal(err)
		}
		projBind, err := tc.projected.BindRuntime(ctx, RuntimeDescription{Directory: dir})
		if err != nil {
			t.Fatal(err)
		}
		oracleBind, err := oracleSnap.BindRuntime(ctx, RuntimeDescription{Directory: dir})
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range subjects {
			if projFPs[s] != oracleFPs[s] {
				t.Fatalf("model %s subject %v projected FP = %+v != oracle FP = %+v", tc.model, s, projFPs[s], oracleFPs[s])
			}
			vProj, err := projBind.Check(ctx, s, projFPs[s])
			if err != nil {
				t.Fatalf("projBind.Check(%s, %v): %v", tc.model, s, err)
			}
			vOracle, err := oracleBind.Check(ctx, s, oracleFPs[s])
			if err != nil {
				t.Fatalf("oracleBind.Check(%s, %v): %v", tc.model, s, err)
			}
			if vProj != vOracle {
				t.Fatalf("model %s subject %v projected verdict = %+v != oracle verdict = %+v", tc.model, s, vProj, vOracle)
			}
			if (vProj.Status == Valid) != tc.wantValid[s] {
				t.Fatalf("model %s subject %v status = %s, wantValid=%v (verdict=%+v)", tc.model, s, vProj.Status, tc.wantValid[s], vProj)
			}
		}

		// Commutativity law: WithExecution(m).Sibling(sub) == Sibling(sub).WithExecution(m)
		subList := []Subject{sClean, sOnlyRead}
		lhs, err := tc.projected.Sibling(subList)
		if err != nil {
			t.Fatal(err)
		}
		sibFirst, err := baseSnap.Sibling(subList)
		if err != nil {
			t.Fatal(err)
		}
		rhs, err := sibFirst.WithExecution(tc.model)
		if err != nil {
			t.Fatal(err)
		}
		lhsFPs, err := lhs.CaptureBatch(ctx)
		if err != nil {
			t.Fatal(err)
		}
		rhsFPs, err := rhs.CaptureBatch(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range subList {
			if lhsFPs[s] != rhsFPs[s] {
				t.Fatalf("WithExecution/Sibling non-commutative for %s %v: %+v != %+v", tc.model, s, lhsFPs[s], rhsFPs[s])
			}
		}
	}

	// Shared BuildBinding from baseSnap registers cleanly on soloProj Unit, while BeginPackage(>1) refuses on soloProj!
	built, err := baseSnap.BindBuilt(sClean.Package, "p-test-bin-id")
	if err != nil {
		t.Fatal(err)
	}
	soloBind, err := soloProj.BindRuntime(ctx, RuntimeDescription{Directory: filepath.Join(dir, "p")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := soloBind.BeginPackage([]Subject{sClean, sDirty}); err == nil {
		t.Fatal("soloBind.BeginPackage with 2 subjects succeeded under SingleSubjectExecution")
	}
	soloUnit, err := soloBind.Begin(sClean)
	if err != nil {
		t.Fatal(err)
	}
	contrib, err := soloUnit.Register(ctx, built, ProcessDescription{Identity: "solo-clean"})
	if err != nil {
		t.Fatalf("soloUnit.Register with baseSnap BuildBinding: %v", err)
	}
	if err := soloUnit.Submit(contrib, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	fin, err := soloUnit.Close(ctx)
	if err != nil || fin.Verdict.Status != Valid {
		t.Fatalf("soloUnit.Close = (%+v, %v), want Valid", fin, err)
	}

	// Negative control: GeneralExecution snapshot refuses projection to PackageExecution/SingleSubjectExecution.
	genSess, err := NewSession(ctx, BuildDescription{
		Directory:   dir,
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{Execution: GeneralExecution})
	if err != nil {
		t.Fatal(err)
	}
	genOnlySnap, err := genSess.Snapshot(ctx, []Subject{sOnlyRead}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := genOnlySnap.WithExecution(GeneralExecution); err != nil {
		t.Fatalf("genOnlySnap.WithExecution(GeneralExecution): %v", err)
	}
	for _, disallowed := range []ExecutionModel{PackageExecution, SingleSubjectExecution} {
		if _, err := genOnlySnap.WithExecution(disallowed); err == nil || !strings.Contains(err.Error(), "cannot project "+disallowed.String()) {
			t.Fatalf("genOnlySnap.WithExecution(%s) = %v, want refusal naming %s", disallowed, err, disallowed)
		}
	}
}

func TestZeroOverheadPureUnitNeedsObservationExcludedEnvAndMovedInputs(t *testing.T) {
	isolateProofCache(t)
	dir := writeModuleTree(t, map[string]string{
		"go.mod":                   "module example.com/unitcaps\n\ngo 1.26\n",
		"purepkg/pure.go":          "package purepkg\n\nfunc PureAdd(a, b int) int { return a + b }\n",
		"purepkg/pure_test.go":     "package purepkg\n\nimport \"testing\"\n\nfunc TestPure(t *testing.T) {\n\tif PureAdd(2, 3) != 5 {\n\t\tt.Fatal()\n\t}\n}\n",
		"obspkg/obs.go":            "package obspkg\n\nimport \"os\"\n\nfunc ReadMode() string { return os.Getenv(\"APP_MODE\") }\n",
		"obspkg/obs_test.go":       "package obspkg\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestObs(t *testing.T) {\n\t_ = os.Getenv(\"GOCOVERDIR\")\n\t_ = ReadMode()\n}\n",
		"purepkg/fixture.txt":      "v1\n",
	})

	purePkg := "example.com/unitcaps/purepkg"
	obsPkg := "example.com/unitcaps/obspkg"
	pureDir := filepath.Join(dir, "purepkg")
	obsDir := filepath.Join(dir, "obspkg")
	sPure := Subject{Package: purePkg, Symbol: "TestPure"}
	sObs := Subject{Package: obsPkg, Symbol: "TestObs"}

	var goSpawns int
	sess, ctx, rec := newTracedSession(t, BuildDescription{
		Directory:   dir,
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{
		Execution:      PackageExecution,
		PrepareCommand: func(*exec.Cmd) { goSpawns++ },
	})
	snap, err := sess.Snapshot(ctx, []Subject{sPure, sObs}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	runtimeEnv := append(slices.Clone(os.Environ()), "GOCOVERDIR=/tmp/cov-run-1", "APP_MODE=prod")
	pureBind, err := snap.BindRuntime(ctx, RuntimeDescription{Directory: pureDir, Environment: runtimeEnv})
	if err != nil {
		t.Fatal(err)
	}
	obsBind, err := snap.BindRuntime(ctx, RuntimeDescription{Directory: obsDir, Environment: runtimeEnv})
	if err != nil {
		t.Fatal(err)
	}

	// 1. NeedsObservation accurately distinguishes pure vs observed sets (and rejects cross-package sets) before execution.
	needPure, err := pureBind.NeedsObservation([]Subject{sPure})
	if err != nil || needPure {
		t.Fatalf("NeedsObservation([TestPure]) = (%v, %v), want (false, nil)", needPure, err)
	}
	needObs, err := obsBind.NeedsObservation([]Subject{sObs})
	if err != nil || !needObs {
		t.Fatalf("NeedsObservation([TestObs]) = (%v, %v), want (true, nil)", needObs, err)
	}
	if _, err := pureBind.NeedsObservation([]Subject{sPure, sObs}); err == nil {
		t.Fatal("NeedsObservation across two packages succeeded, want refusal")
	}

	builtPure, err := snap.BindBuilt(purePkg, "pure-bin-1")
	if err != nil {
		t.Fatal(err)
	}
	builtObs, err := snap.BindBuilt(obsPkg, "obs-bin-1")
	if err != nil {
		t.Fatal(err)
	}

	// 2. Pure Unit with omitted Capture triggers unit.register.pure_fastpath, zero precise analysis,
	// and rejects malformed ExcludedEnv / PWD exclusion up front before reserving execution!
	pureUnit, err := pureBind.Begin(sPure)
	if err != nil {
		t.Fatal(err)
	}
	preciseTriggered := false
	pureUnit.view.beforePreciseAnalysis = func() { preciseTriggered = true }
	if _, err := pureUnit.Register(ctx, builtPure, ProcessDescription{Identity: "pure-bad-env", ExcludedEnv: []string{"PWD"}}); err == nil {
		t.Fatal("Register accepted ExcludedEnv containing PWD")
	}
	if _, err := pureUnit.Register(ctx, builtPure, ProcessDescription{Identity: "pure-bad-bracket", BracketPaths: []string{"../escape"}}); err == nil {
		t.Fatal("Register accepted escaping BracketPaths on pure unit")
	}
	// Because validation failed before reservation, pureUnit is still open and accepts a valid Register!
	spawnsBeforePureReg := goSpawns
	pureContrib, err := pureUnit.Register(ctx, builtPure, ProcessDescription{Identity: "pure-ok"})
	if err != nil {
		t.Fatalf("pureUnit.Register valid: %v", err)
	}
	if goSpawns != spawnsBeforePureReg {
		t.Fatalf("pureUnit.Register spawned %d go commands, want 0", goSpawns-spawnsBeforePureReg)
	}
	if preciseTriggered {
		t.Fatal("pure unit registration triggered Tier-2 precise analysis")
	}
	testenv.RequireTraceEvent(t, rec, trace.DomainSession, "unit.register.pure_fastpath", func(ev trace.Event) bool {
		return ev.Target == "pure-ok"
	})
	// Mutating an untracked file in pureDir during pure execution does NOT fail bracket span because pure unit needed no bracket!
	if err := os.WriteFile(filepath.Join(pureDir, "scratch.tmp"), []byte("ephemeral"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := pureUnit.Submit(pureContrib, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	pureFin, err := pureUnit.Close(ctx)
	if err != nil || pureFin.Verdict.Status != Valid {
		t.Fatalf("pureUnit.Close = (%+v, %v), want Valid", pureFin, err)
	}
	if pureFin.Observation != UnknownObservation || pureFin.Fingerprint.RuntimeInputs != "" {
		t.Fatalf("pureFin observation = (%v, %q), want (UnknownObservation, \"\")", pureFin.Observation, pureFin.Fingerprint.RuntimeInputs)
	}
	_ = os.Remove(filepath.Join(pureDir, "scratch.tmp"))

	// Abnormal completion on a pure unit with omitted Capture still synthesizes canonical incomplete evidence!
	crashUnit, err := pureBind.Begin(sPure)
	if err != nil {
		t.Fatal(err)
	}
	crashContrib, err := crashUnit.Register(ctx, builtPure, ProcessDescription{Identity: "pure-crash"})
	if err != nil {
		t.Fatal(err)
	}
	if err := crashUnit.Submit(crashContrib, Terminal{Kind: AbnormalCompletion, Reason: "exit status 2"}); err != nil {
		t.Fatal(err)
	}
	crashFin, err := crashUnit.Close(ctx)
	if err != nil || crashFin.Observation != IncompleteObservation || crashFin.ObservationReason != "exit status 2" {
		t.Fatalf("crashUnit.Close = (%+v, %v), want IncompleteObservation 'exit status 2'", crashFin, err)
	}

	// 3. Observed Unit with ExcludedEnv: GOCOVERDIR is elided while APP_MODE is guarded under supported observation!
	logPath := filepath.Join(t.TempDir(), "obs.log")
	obsUnit, err := obsBind.Begin(sObs)
	if err != nil {
		t.Fatal(err)
	}
	obsContrib, err := obsUnit.Register(ctx, builtObs, ProcessDescription{
		Identity:    "obs-run-1",
		Capture:     logPath,
		ExcludedEnv: []string{"GOCOVERDIR"},
	})
	if err != nil {
		t.Fatalf("obsUnit.Register: %v", err)
	}
	if err := os.WriteFile(obsContrib.Capture(), []byte("# test log\ngetenv GOCOVERDIR\ngetenv APP_MODE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := obsUnit.Submit(obsContrib, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	obsFin, err := obsUnit.Close(ctx)
	if err != nil || obsFin.Verdict.Status != Valid {
		t.Fatalf("obsUnit.Close = (%+v, %v), want Valid", obsFin, err)
	}

	// Changing GOCOVERDIR keeps TestObs Valid!
	runtimeEnv2 := append(slices.Clone(os.Environ()), "GOCOVERDIR=/tmp/cov-run-999", "APP_MODE=prod")
	bind2, err := snap.BindRuntime(ctx, RuntimeDescription{Directory: obsDir, Environment: runtimeEnv2})
	if err != nil {
		t.Fatal(err)
	}
	checked2, err := bind2.CheckBatchWithLedgers(ctx, []Candidate{{Subject: sObs, Recorded: obsFin.Fingerprint}}, nil)
	if err != nil || checked2[0].Verdict.Status != Valid || len(checked2[0].MovedInputs) != 0 {
		t.Fatalf("check after excluded GOCOVERDIR change = (%+v, %v), want Valid with empty MovedInputs", checked2, err)
	}

	// Optional capture on pure unit guards BOTH env APP_MODE and file fixture.txt,
	// exposing sorted uncapped MovedInputs and preserving movers across ABA revert!
	optLog := filepath.Join(t.TempDir(), "opt.log")
	optUnit, err := pureBind.Begin(sPure)
	if err != nil {
		t.Fatal(err)
	}
	optContrib, err := optUnit.Register(ctx, builtPure, ProcessDescription{
		Identity:    "pure-with-opt-capture",
		Capture:     optLog,
		ExcludedEnv: []string{"GOCOVERDIR"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(optContrib.Capture(), []byte("# test log\ngetenv GOCOVERDIR\ngetenv APP_MODE\nopen fixture.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := optUnit.Submit(optContrib, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	optFin, err := optUnit.Close(ctx)
	if err != nil || optFin.Verdict.Status != Valid {
		t.Fatalf("optUnit.Close = (%+v, %v), want Valid", optFin, err)
	}

	// Changing BOTH APP_MODE and fixture.txt yields Stale/RuntimeInputsCause AND coherent sorted MovedInputs!
	if err := os.WriteFile(filepath.Join(pureDir, "fixture.txt"), []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runtimeEnv3 := append(slices.Clone(os.Environ()), "GOCOVERDIR=/tmp/cov-run-999", "APP_MODE=staging")
	pureBind3, err := snap.BindRuntime(ctx, RuntimeDescription{Directory: pureDir, Environment: runtimeEnv3})
	if err != nil {
		t.Fatal(err)
	}
	checked3, err := pureBind3.CheckBatchWithLedgers(ctx, []Candidate{{Subject: sPure, Recorded: optFin.Fingerprint}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantMovers := []string{"env APP_MODE", "path purepkg/fixture.txt"}
	if checked3[0].Verdict.Status != Stale || checked3[0].Verdict.Ground.Cause.Kind != RuntimeInputsCause || !slices.Equal(checked3[0].MovedInputs, wantMovers) {
		t.Fatalf("stale check = %+v, want Stale/RuntimeInputsCause with MovedInputs=%v", checked3[0], wantMovers)
	}

	// ABA revert preservation: CheckBatch sees v2 (Stale with MovedInputs), then fixture.txt reverts to v1 before Close!
	// CheckingUnit.Close MUST preserve the exact MovedInputs witnessed at the deciding round endpoint!
	pureBindRevert, err := snap.BindRuntime(ctx, RuntimeDescription{Directory: pureDir, Environment: runtimeEnv2})
	if err != nil {
		t.Fatal(err)
	}
	cu, err := pureBindRevert.BeginCheck([]Subject{sPure})
	if err != nil {
		t.Fatal(err)
	}
	provisional, err := cu.CheckBatch(ctx, []Candidate{{Subject: sPure, Recorded: optFin.Fingerprint}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(provisional[0].MovedInputs, []string{"path purepkg/fixture.txt"}) {
		t.Fatalf("provisional MovedInputs = %v, want [path purepkg/fixture.txt]", provisional[0].MovedInputs)
	}
	// Revert fixture.txt back to v1 BEFORE Close!
	if err := os.WriteFile(filepath.Join(pureDir, "fixture.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	closedABA, err := cu.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if closedABA[0].Verdict.Status != Stale || !slices.Equal(closedABA[0].MovedInputs, []string{"path purepkg/fixture.txt"}) {
		t.Fatalf("closedABA after revert = %+v, want Stale preserving MovedInputs=[path purepkg/fixture.txt]", closedABA[0])
	}

	// RuntimeInputSpanError.MovedInputs when fixture.txt moves during an observed Unit execution!
	spanLog := filepath.Join(t.TempDir(), "span.log")
	spanUnit, err := pureBindRevert.Begin(sPure)
	if err != nil {
		t.Fatal(err)
	}
	spanContrib, err := spanUnit.Register(ctx, builtPure, ProcessDescription{
		Identity: "obs-span-move",
		Capture:  spanLog,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pureDir, "fixture.txt"), []byte("moved-mid-run\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spanContrib.Capture(), []byte("# test log\nopen fixture.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := spanUnit.Submit(spanContrib, Terminal{Kind: NormalCompletion}); err != nil {
		t.Fatal(err)
	}
	_, spanCloseErr := spanUnit.Close(ctx)
	var spanErr *RuntimeInputSpanError
	if !errors.As(spanCloseErr, &spanErr) || !slices.Contains(spanErr.MovedInputs, "path purepkg/fixture.txt") {
		t.Fatalf("spanUnit.Close err = %v (spanErr=%+v), want RuntimeInputSpanError naming path purepkg/fixture.txt", spanCloseErr, spanErr)
	}
}

func TestPropertySourceResultFingerprintValidationAndExcludedEnvMetamorphic(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		base := Fingerprint{
			MaximalClosure:     strings.Repeat("a", 32),
			TestVariantClosure: strings.Repeat("b", 32),
			ToolchainContent:   "tc-content",
			AdmissionPolicy:    "adm-policy",
			Guards:             Guards{Toolchain: "go1.27.4 linux/amd64", BuildConfig: strings.Repeat("c", 32)},
			ClosureStrategy:    ClosureStrategy,
			ResultKind:         SourceResult,
		}
		if err := base.Validate(); err != nil {
			rt.Fatalf("valid SourceResult failed Validate: %v", err)
		}
		mutation := rapid.IntRange(0, 10).Draw(rt, "mutation")
		mut := base
		switch mutation {
		case 0:
			mut.Guards.Machine = "mach"
		case 1:
			mut.Guards.RuntimeConfig = "rc"
		case 2:
			mut.RuntimeInputs = "manifest"
		case 3:
			mut.RuntimeDigest = "digest"
		case 4:
			mut.ObservationAssertion = "caller assertion"
		case 5:
			mut.ObservationProof = ObservationProof{Strategy: ObservationRTA, Subject: Subject{Package: "p", Symbol: "F"}, Observable: true, Evidence: "ev"}
		case 6:
			mut.PurityAssertion = "caller assertion"
		case 7:
			mut.DynamicStateVouches = "pkg.V"
		case 8:
			mut.SingleSubjectDischarges = "pkg.V"
		case 9:
			mut.DynamicStateStrategy = DynamicStateStrategy
		case 10:
			mut.PackageProcessDischarges = "pkg.V"
		}
		if err := mut.Validate(); err == nil {
			rt.Fatalf("SourceResult with forbidden field (mutation %d) passed Validate: %+v", mutation, mut)
		}
	})

	dir := t.TempDir()
	bracket, err := runtimeinput.CaptureBracket(t.Context(), dir, []string{"."})
	if err != nil {
		t.Fatal(err)
	}
	rapid.Check(t, func(rt *rapid.T) {
		keys := []string{"COV_DIR", "IPC_SOCK", "KEEP_A", "KEEP_B"}
		exclMask := rapid.Uint8Range(0, 15).Draw(rt, "exclMask")
		var excluded []string
		exclSet := map[string]bool{}
		for i, k := range keys {
			if (exclMask>>i)&1 != 0 {
				excluded = append(excluded, k)
				exclSet[k] = true
			}
		}
		env := []string{"PWD=" + dir, "COV_DIR=/tmp/1", "IPC_SOCK=/tmp/s", "KEEP_A=1", "KEEP_B=2"}
		var fullLines, filteredLines strings.Builder
		for _, k := range append(slices.Clone(keys), "PWD") {
			fullLines.WriteString("getenv " + k + "\n")
			if !exclSet[k] {
				filteredLines.WriteString("getenv " + k + "\n")
			}
		}
		got, err := runtimeinput.FromTestLog([]byte(fullLines.String()), dir, dir, env,
			runtimeinput.WithCompletedProcess("p"), runtimeinput.WithBracket(bracket), runtimeinput.WithExcludedEnv(excluded...))
		if err != nil {
			rt.Fatalf("FromTestLog with exclusions %v: %v", excluded, err)
		}
		oracle, err := runtimeinput.FromTestLog([]byte(filteredLines.String()), dir, dir, env,
			runtimeinput.WithCompletedProcess("p"), runtimeinput.WithBracket(bracket))
		if err != nil {
			rt.Fatalf("oracle FromTestLog: %v", err)
		}
		if got.State != oracle.State {
			rt.Fatalf("ExcludedEnv metamorphic mismatch for %v: got %+v, want %+v", excluded, got.State, oracle.State)
		}
	})
}

func TestMemberDirectivesAcrossEmbeddedDefinedAndForeignInterfaceTypes(t *testing.T) {
	isolateProofCache(t)
	dir := writeModuleTree(t, map[string]string{
		"go.mod": "module example.com/memberdirs\n\ngo 1.26\n",
		"sub/sub.go": "package sub\n\n" +
			"type Base struct {\n" +
			"\t//gofresh:external\n" +
			"\tExtField int\n" +
			"\tCleanField int\n" +
			"}\n\n" +
			"type Derived Base\n\n" +
			"type BaseIface interface {\n" +
			"\t//gofresh:external\n" +
			"\tExtOp() int\n" +
			"\t//gofresh:pure\n" +
			"\tPureOp() int\n" +
			"}\n",
		"p.go": "package memberdirs\n\n" +
			"import \"example.com/memberdirs/sub\"\n\n" +
			"type LocalSub struct{ X int }\n\n" +
			"type Config struct {\n" +
			"\t//gofresh:external\n" +
			"\tLocalSub\n" +
			"\tsub.Derived\n" +
			"}\n\n" +
			"type MyCfg sub.Base\n" +
			"type MyIface sub.BaseIface\n\n" +
			"type Wrapper struct {\n" +
			"\tsub.BaseIface\n" +
			"}\n",
	})
	const pkg = "example.com/memberdirs"
	ctx := t.Context()
	subjects := []Subject{
		{Package: pkg, Symbol: "Config.LocalSub"},
		{Package: pkg, Symbol: "Config.ExtField"},
		{Package: pkg, Symbol: "Config.CleanField"},
		{Package: pkg, Symbol: "MyCfg.ExtField"},
		{Package: pkg, Symbol: "MyCfg.CleanField"},
		{Package: pkg, Symbol: "MyIface.ExtOp"},
		{Package: pkg, Symbol: "MyIface.PureOp"},
		{Package: pkg, Symbol: "Wrapper.ExtOp"},
		{Package: pkg, Symbol: "Wrapper.PureOp"},
	}
	sess, err := NewSession(ctx, BuildDescription{
		Directory:   dir,
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{PureSubjects: subjects})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := sess.Snapshot(ctx, subjects, CodeResult)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	fps, err := snap.CaptureBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bind, err := snap.BindRuntime(ctx, RuntimeDescription{Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	var cands []Candidate
	for _, s := range subjects {
		cands = append(cands, Candidate{Subject: s, Recorded: fps[s]})
	}
	checked, err := bind.CheckBatchWithLedgers(ctx, cands, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantExt := map[string]bool{
		"Config.LocalSub": true,
		"Config.ExtField": true,
		"MyCfg.ExtField":  true,
		"MyIface.ExtOp":   true,
		"Wrapper.ExtOp":   true,
	}
	for _, c := range checked {
		if wantExt[c.Subject.Symbol] {
			if c.Verdict.Status != Unverifiable || c.Verdict.Ground.Cause.Kind != ExternalDirectiveCause {
				t.Fatalf("%s = %+v, want Unverifiable(ExternalDirectiveCause)", c.Subject.Symbol, c.Verdict)
			}
		} else if c.Verdict.Status != Valid {
			t.Fatalf("%s = %+v, want Valid", c.Subject.Symbol, c.Verdict)
		}
	}

	// Conflicting directives on an embedded struct field must refuse Snapshot preparation.
	conflictDir := writeModuleTree(t, map[string]string{
		"go.mod": "module example.com/embedconflict\n\ngo 1.26\n",
		"p.go": "package embedconflict\n\n" +
			"type Sub struct{ X int }\n" +
			"type Bad struct {\n" +
			"\t//gofresh:pure\n" +
			"\t//gofresh:external\n" +
			"\tSub\n" +
			"}\n",
	})
	conflictSess, err := NewSession(ctx, BuildDescription{
		Directory:   conflictDir,
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conflictSess.Snapshot(ctx, []Subject{{Package: "example.com/embedconflict", Symbol: "Bad.Sub"}}, CodeResult); err == nil || !strings.Contains(err.Error(), "carries both //gofresh:pure and //gofresh:external") {
		t.Fatalf("conflicting embedded field directives err = %v, want conflict refusal", err)
	}
}

func TestSourceResultScanDriftAndBrokenPackageRefusal(t *testing.T) {
	isolateProofCache(t)
	ctx := t.Context()

	// 1. Mid-load ABA extra file injection during SourceResult LoadViewPackages must NOT poison scanfacts.
	abaDir := writeModuleTree(t, map[string]string{
		"go.mod": "module example.com/srcaba\n\ngo 1.26\n",
		"p.go":   "package srcaba\n\ntype Real struct{}\n",
	})
	abaSess, err := NewSession(ctx, BuildDescription{
		Directory:   abaDir,
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	ghostPath := filepath.Join(abaDir, "ghost.go")
	injected := false
	withViewTestHooks(viewTestHookSet{
		typedLoad: func() {
			if !injected {
				injected = true
				_ = os.WriteFile(ghostPath, []byte("package srcaba\n\ntype Ghost struct{}\n"), 0o600)
			}
		},
		beforeDischarge: func() {
			_ = os.Remove(ghostPath)
		},
	}, func() {
		_, err := abaSess.Snapshot(ctx, []Subject{{Package: "example.com/srcaba", Symbol: "Ghost"}}, SourceResult)
		var unk *UnknownSubjectsError
		if !errors.As(err, &unk) {
			t.Fatalf("ABA Ghost Snapshot(SourceResult) err = %v, want *UnknownSubjectsError (not poisoned Valid)", err)
		}
	})
	// Subsequent clean Snapshot must also reject Ghost (scanfacts stayed unpoisoned) and accept Real.
	if _, err := abaSess.Snapshot(ctx, []Subject{{Package: "example.com/srcaba", Symbol: "Ghost"}}, SourceResult); err == nil {
		t.Fatal("clean Snapshot(SourceResult, Ghost) succeeded; scanfacts was poisoned")
	}
	realSnap, err := abaSess.Snapshot(ctx, []Subject{{Package: "example.com/srcaba", Symbol: "Real"}}, SourceResult)
	if err != nil {
		t.Fatalf("clean Snapshot(SourceResult, Real): %v", err)
	}
	realFP, err := realSnap.Capture(ctx, Subject{Package: "example.com/srcaba", Symbol: "Real"})
	if err != nil {
		t.Fatal(err)
	}
	realVerdict, err := realSnap.Check(ctx, realFP, Subject{Package: "example.com/srcaba", Symbol: "Real"})
	if err != nil || realVerdict.Status != Valid {
		t.Fatalf("clean Real SourceResult check = (%+v, %v), want Valid", realVerdict, err)
	}

	// 2. Broken package refuses SourceResult with load error and reports load error (not UnknownSubjectsError) for unresolved promoted members on CodeResult.
	brokenDir := writeModuleTree(t, map[string]string{
		"go.mod": "module example.com/broken\n\ngo 1.26\n",
		"p.go":   "package broken\n\ntype Broken struct { MissingEmbed }\n",
	})
	brokenSess, err := NewSession(ctx, BuildDescription{
		Directory:   brokenDir,
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := brokenSess.Snapshot(ctx, []Subject{{Package: "example.com/broken", Symbol: "Broken"}}, SourceResult); err == nil || !strings.Contains(err.Error(), "gofresh: load example.com/broken:") {
		t.Fatalf("broken SourceResult Snapshot err = %v, want load error", err)
	}
	var unk *UnknownSubjectsError
	err = func() error {
		_, e := brokenSess.Snapshot(ctx, []Subject{{Package: "example.com/broken", Symbol: "Broken.Val"}}, CodeResult)
		return e
	}()
	if err == nil || errors.As(err, &unk) || !strings.Contains(err.Error(), "gofresh: load example.com/broken:") {
		t.Fatalf("broken CodeResult unresolved member err = %v, want load error rather than UnknownSubjectsError", err)
	}

	// 3. Imported dependency with compile error refuses static declarations (Wrapper, Wrapper.F) on BOTH SourceResult and CodeResult!
	brokenDepDir := writeModuleTree(t, map[string]string{
		"go.mod":     "module example.com/brokendep\n\ngo 1.26\n",
		"sub/sub.go": "package sub\n\ntype Other struct { F string }\ntype Base struct {\n\tOther\n\tTypoEmbed\n}\n",
		"p/p.go":     "package p\n\nimport \"example.com/brokendep/sub\"\n\ntype Wrapper struct { sub.Base }\n",
	})
	brokenDepSess, err := NewSession(ctx, BuildDescription{
		Directory:   brokenDepDir,
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []Kind{SourceResult, CodeResult} {
		for _, sym := range []string{"Wrapper", "Wrapper.F"} {
			if _, err := brokenDepSess.Snapshot(ctx, []Subject{{Package: "example.com/brokendep/p", Symbol: sym}}, kind); err == nil || !strings.Contains(err.Error(), "gofresh: load example.com/brokendep/p:") {
				t.Fatalf("broken dependency Snapshot(kind=%d, %s) err = %v, want load error", kind, sym, err)
			}
		}
	}
}

func TestWithExecutionSecondaryModelCutAndStageADischargePreservation(t *testing.T) {
	isolateProofCache(t)
	ctx := t.Context()
	// AaaInitPool is an exported sync.Pool touched in init() (_ = AaaInitPool.Get()):
	// - Under PackageExecution (singleSubject=false), AaaInitPool is in PoolEscapes with zero attributed
	//   functions (Unattributed=true) and sorts before reg ('A' < 'r'), so culprits[0] is Unattributed ->
	//   pkgDowngraded is empty -> primary PackageExecution cut stays false on BOTH Pass 1 and Pass 2!
	// - Under SingleSubjectExecution (singleSubject=true), AaaInitPool IS Stage-A discharged via
	//   PoolDischarges into SingleSubjectDischarges, leaving reg (mutated in MutateReg) as attributed
	//   culprits[0] -> soloDowngraded contains TestPureCalc -> Pass 1 discharges reg and Pass 2 cuts it!
	dir := writeModuleTree(t, map[string]string{
		"go.mod": "module example.com/seccut\n\ngo 1.26\n",
		"sub/sub.go": "package sub\n\n" +
			"var Reg func() int\n\n" +
			"func MutateReg() { Reg = func() int { return 1 } }\n",
		"p.go": "package seccut\n\n" +
			"import (\n" +
			"\t\"sync\"\n\n" +
			"\t_ \"example.com/seccut/sub\"\n" +
			")\n\n" +
			"var AaaInitPool sync.Pool\n\n" +
			"func init() {\n" +
			"\t_ = AaaInitPool.Get()\n" +
			"}\n\n" +
			"func PureCalc() int { return 1 }\n",
		"p_test.go": "package seccut\n\n" +
			"import (\n" +
			"\t\"testing\"\n\n" +
			"\t\"example.com/seccut/sub\"\n" +
			")\n\n" +
			"func TestMutate(t *testing.T) { sub.MutateReg() }\n" +
			"func TestPureCalc(t *testing.T) {\n" +
			"\tif PureCalc() != 1 {\n" +
			"\t\tt.Fatal(\"bad\")\n" +
			"\t}\n" +
			"}\n",
	})
	const pkg = "example.com/seccut"
	sCalc := Subject{Package: pkg, Symbol: "TestPureCalc"}
	sess, err := NewSession(ctx, BuildDescription{
		Directory:   dir,
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{
		Execution:      PackageExecution,
		AnalysisBudget: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	boundPass := 0
	var pkgSnap *Snapshot
	var soloBind *RuntimeBinding
	var soloFP Fingerprint
	var verdict Verdict
	withViewTestHooks(viewTestHookSet{
		scanMemoOff: true,
		analysisBound: func(parent context.Context, requested time.Duration) (context.Context, context.CancelFunc) {
			boundPass++
			if boundPass == 1 {
				// Pass 1 completes Stage-B cleanly (TestPureCalc discharged in SingleSubjectExecution).
				return context.WithTimeout(parent, requested)
			}
			// Pass >= 2 hits deterministic budget expiry: PackageExecution has empty pkgDowngraded
			// (current.cut == false), whereas SingleSubjectExecution cuts TestPureCalc!
			return context.WithDeadline(parent, time.Now().Add(-time.Second))
		},
	}, func() {
		pkgSnap, err = sess.Snapshot(ctx, []Subject{sCalc}, CodeResult)
		if err != nil {
			t.Fatalf("PackageExecution Snapshot with Pass-2 secondary cut: %v", err)
		}
		if pkgSnap.facts.cut[sCalc] {
			t.Fatal("primary PackageExecution snapshot unexpectedly marked sCalc cut")
		}
		soloSnap, projErr := pkgSnap.WithExecution(SingleSubjectExecution)
		if projErr != nil {
			t.Fatalf("WithExecution(SingleSubjectExecution): %v", projErr)
		}
		soloBind, err = soloSnap.BindRuntime(ctx, RuntimeDescription{Directory: dir})
		if err != nil {
			t.Fatal(err)
		}
		needObs, needErr := soloBind.NeedsObservation([]Subject{sCalc})
		if needErr != nil || !needObs {
			t.Fatalf("NeedsObservation on secondary-cut SingleSubjectExecution = (%v, %v), want (true, nil)", needObs, needErr)
		}
		soloFP, err = soloSnap.Capture(ctx, sCalc)
		if err != nil {
			t.Fatal(err)
		}
		verdict, err = soloBind.Check(ctx, sCalc, soloFP)
		if err != nil {
			t.Fatal(err)
		}
	})
	// Stage-A PoolDischarges MUST be preserved on soloFP even though Stage-B was cut on Pass 2!
	if !strings.Contains(soloFP.SingleSubjectDischarges, "example.com/seccut.AaaInitPool") {
		t.Fatalf("Stage-A SingleSubjectDischarges lost on secondary-model cut: %q", soloFP.SingleSubjectDischarges)
	}
	if verdict.Status != Unverifiable || verdict.Ground.Cause.Kind != SharedDynamicStateCause || verdict.Ground.Cause.Condition != Unavailable {
		t.Fatalf("Projected SingleSubjectExecution verdict after Pass-2 cut = %+v, want Unverifiable(SharedDynamicStateCause, Unavailable)", verdict)
	}
}

func FuzzValidateExcludedEnvAndSourceFingerprint(f *testing.F) {
	for _, seed := range []string{
		"", "PWD", "pwd", "GOCOVERDIR", "A=B", "X\x00Y", "X\nY", "X\rY", string([]byte{0xff, 0xfe}),
		`{"maximalClosure":"a","testVariantClosure":"b","toolchain":"t","buildConfig":"c","resultKind":3}`,
		`{"maximalClosure":"a","testVariantClosure":"b","toolchain":"t","buildConfig":"c","machine":"m","resultKind":3}`,
		`{"maximalClosure":"a","testVariantClosure":"b","toolchain":"t","buildConfig":"c","packageProcessDischarges":"p.V","resultKind":3}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cand string) {
		err1 := runtimeinput.ValidateExcludedEnv([]string{cand})
		err2 := runtimeinput.ValidateExcludedEnv([]string{cand})
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic ValidateExcludedEnv(%q)", cand)
		}
		wantInvalidEnv := cand == "" || !utf8.ValidString(cand) || strings.ContainsAny(cand, "=\x00\r\n") || gotool.EqualEnvKey(cand, "PWD")
		if (err1 != nil) != wantInvalidEnv {
			t.Fatalf("ValidateExcludedEnv(%q) err = %v, wantInvalid = %v", cand, err1, wantInvalidEnv)
		}

		var fp Fingerprint
		decErr := json.Unmarshal([]byte(cand), &fp)
		if decErr == nil {
			if valErr := fp.Validate(); valErr != nil {
				t.Fatalf("decoded Fingerprint failed Validate: %v (%+v)", valErr, fp)
			}
			enc, encErr := json.Marshal(fp)
			if encErr != nil {
				t.Fatalf("decoded Fingerprint failed MarshalJSON: %v (%+v)", encErr, fp)
			}
			var roundTrip Fingerprint
			if err := json.Unmarshal(enc, &roundTrip); err != nil || roundTrip != fp {
				t.Fatalf("Fingerprint round-trip mismatch: %v, %+v vs %+v", err, roundTrip, fp)
			}
		}
	})
}
