package gofresh

import (
	"context"
	"errors"
	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/gofresh/internal/dynstate"
	"github.com/greatliontech/gofresh/internal/gotool"
	"github.com/greatliontech/gofresh/internal/runtimeinput"
	"github.com/greatliontech/gofresh/internal/testenv"
	"github.com/greatliontech/gofresh/internal/trace"
	"github.com/greatliontech/stipulator/stipulate/structural"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// Every exported analysis entry of the public packages names its
// environment in its signature (REQ-closure-analysis: the analyzed tree
// and build selection are explicit inputs, never implicit coupling): no
// production source of the internal packages or the root files outside
// session.go and view.go reads the ambient process environment (os.Environ,
// Getenv, LookupEnv, ExpandEnv, and syscall's).
//
//gofresh:pure
func TestPublicPackagesReadNoAmbientEnvironment(t *testing.T) {
	roots := []string{"internal"}
	files := []string{"checking.go", "explain.go", "fingerprint.go", "judgment.go", "provenance.go", "runtimeinputs.go", "unit.go", "vouchfile.go"}
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && (d.Name() == "fixtures" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
				files = append(files, path)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, hit := range ambientReads(t, files) {
		t.Errorf("%s: reads the ambient environment; the entry must take env", hit)
	}
}

// ambientReads names every call of an ambient-environment reader in the
// given Go sources, as file:line:col.
func ambientReads(t *testing.T, files []string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var hits []string
	for _, path := range files {
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			ambient := (pkg.Name == "os" && (sel.Sel.Name == "Environ" || sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv" || sel.Sel.Name == "ExpandEnv")) ||
				(pkg.Name == "syscall" && (sel.Sel.Name == "Environ" || sel.Sel.Name == "Getenv"))
			if ambient {
				hits = append(hits, fset.Position(call.Pos()).String())
			}
			return true
		})
	}
	return hits
}

// The walk's logic over synthetic sources: every ambient reader is named,
// a same-named method on another receiver is not, and a clean file yields
// nothing — the real-source walk above is this logic's hand-edit oracle
// (a source-reading pin cannot see an overlay, so the logic is pinned
// where a probe can reach it).
//
//gofresh:pure
func TestAmbientReadsNameEveryAmbientReader(t *testing.T) {
	dir := t.TempDir()
	dirty := filepath.Join(dir, "dirty.go")
	if err := os.WriteFile(dirty, []byte(`package p

import (
	"os"
	"syscall"
)

type env struct{}

func (env) Environ() []string { return nil }

func f() {
	_ = os.Environ()
	_ = os.Getenv("K")
	_, _ = os.LookupEnv("K")
	_ = os.ExpandEnv("$K")
	_ = syscall.Environ()
	_, _ = syscall.Getenv("K")
	_ = env{}.Environ()
}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(dir, "clean.go")
	if err := os.WriteFile(clean, []byte("package p\n\nfunc g(env []string) []string { return env }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hits := ambientReads(t, []string{dirty, clean})
	if len(hits) != 6 {
		t.Fatalf("hits = %v; want the six ambient readers and not the method", hits)
	}
	for _, h := range hits {
		if !strings.HasPrefix(h, dirty+":") {
			t.Fatalf("a clean file was named: %s", h)
		}
	}
}

// A cancelled or missing preparation context admits no configuration work.
func TestConstructionContextRefusesBeforeOptions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []context.Context{nil, ctx} {
		called := false
		e, err := newEngineContext(input, func(*engine) { called = true })
		if e != nil || err == nil || called {
			t.Fatalf("context %v: engine returned=%t error=%v option called=%v", input, e != nil, err, called)
		}
		if input != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation returned %v", err)
		}
	}
}

// A cancellation during configuration cannot be reported as an unrelated flag
// refusal, even where the invalid flag prevents an environment query entirely.
func TestConstructionContextKeepsCancellationAttribution(t *testing.T) {
	for _, option := range []option{withBuildFlags("-overlay=unused"), withBuildInputs("-overlay=unused"), withEnv("malformed")} {
		ctx, cancel := context.WithCancel(context.Background())
		e, err := newEngineContext(ctx, withDir(t.TempDir()), option, func(*engine) { cancel() })
		cancel()
		if e != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled preparation: engine returned=%t error=%v", e != nil, err)
		}
	}
}

// The fast tier's gates are inert under a plain `go test`: every gate in
// the repository's test files is a skipping statement of a Test or Fuzz
// body, never in a helper, an uninvoked closure, or a fixture string
// (internal/testenv.PinShortGates states the rules and pins its own arms).
func TestShortGatesLiveInTestBodiesAndSkip(t *testing.T) {
	testenv.PinShortGates(t, ".")
}

func TestVariantLedgerTypesAreExportedData(t *testing.T) {
	// TestVariantLedger and TestVariantDelta carry deliberate methods (Clone;
	// Inert, the one Go-semantics judgment), so their field shapes are pinned
	// by reflection rather than the method-free ExportedData contract.
	for typeOf, want := range map[reflect.Type][]string{
		reflect.TypeFor[TestVariantLedger](): {"BindingStrategy", "BaseFiles", "Declarations", "FileHeaders"},
		reflect.TypeFor[TestVariantDelta]():  {"BindingsPreserved", "Added", "Changed", "Removed", "HeaderChanges"},
	} {
		if typeOf.NumField() != len(want) {
			t.Fatalf("%s has %d fields, want %d", typeOf, typeOf.NumField(), len(want))
		}
		for i, name := range want {
			if typeOf.Field(i).Name != name {
				t.Fatalf("%s field %d = %s, want %s", typeOf, i, typeOf.Field(i).Name, name)
			}
		}
	}
	structural.ExportedData[TestVariantDeclaration](t,
		structural.FieldOf[string]("File"),
		structural.FieldOf[string]("Kind"),
		structural.FieldOf[string]("Name"),
		structural.FieldOf[string]("Receiver"),
		structural.FieldOf[string]("Hash"),
		structural.FieldOf[string]("Package"),
		structural.FieldOf[[]string]("References"),
	)
	structural.ExportedData[TestVariantFileHeader](t,
		structural.FieldOf[string]("File"),
		structural.FieldOf[string]("Hash"),
		structural.FieldOf[bool]("Embedded"),
		structural.FieldOf[*TestVariantFileBindings]("Bindings"),
	)
	structural.ExportedData[TestVariantFileBindings](t,
		structural.FieldOf[string]("Package"),
		structural.FieldOf[[]string]("References"),
		structural.FieldOf[[]TestVariantImport]("Imports"),
	)
	structural.ExportedData[TestVariantImport](t,
		structural.FieldOf[string]("Name"),
		structural.FieldOf[string]("Path"),
	)
	structural.ExportedData[TestVariantDeclarationChange](t,
		structural.FieldOf[TestVariantDeclaration]("Before"),
		structural.FieldOf[TestVariantDeclaration]("After"),
	)
	structural.ExportedData[TestVariantHeaderChange](t,
		structural.FieldOf[string]("File"),
		structural.FieldOf[string]("Before"),
		structural.FieldOf[string]("After"),
		structural.FieldOf[bool]("Embedded"),
	)
}

func TestPurityInputIsSubjectPredicate(t *testing.T) {
	structural.ExportedData[SessionPolicy](t,
		structural.FieldOf[string]("EvidenceRoot"),
		structural.FieldOf[[]string]("Vouches"),
		structural.FieldOf[[]Subject]("PureSubjects"),
		structural.FieldOf[func(Subject) bool]("AssumePure"),
		structural.FieldOf[ExecutionModel]("Execution"),
		structural.FieldOf[time.Duration]("AnalysisBudget"),
		structural.FieldOf[func(*exec.Cmd)]("PrepareCommand"),
		structural.FieldOf[func(Progress)]("Progress"),
	)
}

func TestViewCheckUsesConstructionKind(t *testing.T) {
	structural.FunctionSignature[func(*Snapshot, context.Context, Fingerprint, Subject) (Verdict, error)](t, (*Snapshot).Check)
}

func TestVouchInputShapes(t *testing.T) {
	structural.FunctionSignature[func(string) (string, error)](t, ParseVouchEntry)
	structural.FunctionSignature[func([]string) ([]string, error)](t, ParseVouchEntries)
}

func TestTraceDomainsAndTwoPassDiff(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/traced\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package traced\n\nfunc Add(a, b int) int { return a + b }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := trace.NewRecorder()
	ctx := trace.WithSink(t.Context(), rec)

	session, err := NewSession(ctx, BuildDescription{
		Directory:   dir,
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	subj := Subject{Package: "example.com/traced", Symbol: "Add"}
	snap, err := session.Snapshot(ctx, []Subject{subj}, CodeResult)
	if err != nil {
		t.Fatal(err)
	}
	fps, err := snap.CaptureBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := snap.Check(ctx, fps[subj], subj)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Status != Valid {
		t.Fatalf("Check status = %s, want valid", verdict.Status)
	}

	if len(rec.ByName("session_init")) == 0 {
		t.Fatal("missing session_init trace event")
	}
	if len(rec.ByName("subject_closure")) == 0 {
		t.Fatal("missing subject_closure trace event")
	}
	if len(rec.ByName("pass_summary")) == 0 {
		t.Fatal("missing pass_summary trace event")
	}
	if len(rec.ByName("check_verdict")) == 0 {
		t.Fatal("missing check_verdict trace event")
	}

	// Mutate p.go and verify compareObservations emits two_pass_diff naming closure_hash.
	rec.Reset()
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package traced\n\nfunc Add(a, b int) int { return a + b + 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := snap.Validate(ctx); !errors.Is(err, ErrViewChanged) {
		t.Fatalf("Validate after source edit = %v, want ErrViewChanged", err)
	}
	diffs := rec.ByName("two_pass_diff")
	if len(diffs) == 0 {
		t.Fatal("expected two_pass_diff trace event on ErrViewChanged")
	}
	if got := diffs[0].StringField("diff_field"); got != "closure_hash" {
		t.Fatalf("two_pass_diff diff_field = %q, want closure_hash", got)
	}
}

func TestTraceNonInterference(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/noninterf\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package noninterf\n\nfunc Mul(a, b int) int { return a * b }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	subj := Subject{Package: "example.com/noninterf", Symbol: "Mul"}

	runCapture := func(traced bool) (Fingerprint, BuildDescription, runtimeinput.Observation) {
		env := os.Environ()
		sess, err := NewSession(t.Context(), BuildDescription{
			Directory:   dir,
			Environment: env,
			Inputs:      []string{},
		}, SessionPolicy{})
		if err != nil {
			t.Fatal(err)
		}
		snap, err := sess.Snapshot(t.Context(), []Subject{subj}, CodeResult)
		if err != nil {
			t.Fatal(err)
		}
		bd, err := snap.BuildDescription(subj.Package)
		if err != nil {
			t.Fatal(err)
		}
		fps, err := snap.CaptureBatch(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		bracket, err := runtimeinput.CaptureBracket(t.Context(), dir, []string{"."})
		if err != nil {
			t.Fatal(err)
		}
		log := "# test log\ngetenv HOME\n"
		if traced {
			log += "getenv GOFRESH_TRACE\ngetenv GOFRESH_TRACE_FILE\n"
		}
		obs, err := runtimeinput.FromTestLog([]byte(log), dir, dir, env, runtimeinput.WithCompletedProcess("worker"), runtimeinput.WithBracket(bracket))
		if err != nil {
			t.Fatal(err)
		}
		return fps[subj], bd, obs
	}

	t.Setenv(trace.EnvTrace, "")
	t.Setenv(trace.EnvTraceFile, "")
	plainFP, plainBD, plainObs := runCapture(false)

	traceFile := filepath.Join(t.TempDir(), "trace.jsonl")
	t.Setenv(trace.EnvTrace, "all")
	t.Setenv(trace.EnvTraceFile, traceFile)
	t.Cleanup(func() {
		os.Unsetenv(trace.EnvTrace)
		os.Unsetenv(trace.EnvTraceFile)
		refreshTraceFromEnv()
	})
	tracedFP, tracedBD, tracedObs := runCapture(true)

	if plainFP != tracedFP {
		t.Fatalf("fingerprint changed under tracing:\nplain:  %+v\ntraced: %+v", plainFP, tracedFP)
	}
	if !reflect.DeepEqual(plainBD, tracedBD) {
		t.Fatalf("BuildDescription changed under tracing:\nplain:  %+v\ntraced: %+v", plainBD, tracedBD)
	}
	if plainObs.State != tracedObs.State {
		t.Fatalf("runtime input State changed under tracing:\nplain:  %+v\ntraced: %+v", plainObs.State, tracedObs.State)
	}
}

//gofresh:pure
func TestExportedSurfaceInventory(t *testing.T) {
	// 1. Verify github.com/greatliontech/gofresh is the sole public package:
	// no non-root directory outside internal/ may contain .go source files.
	if err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "internal" || name == "docs" || name == "testdata" || (len(name) > 1 && strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Dir(path) != "." && strings.HasSuffix(path, ".go") {
			t.Errorf("public subpackage Go file outside internal/: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// 2. Verify no exported struct field or exported function/method signature in
	// root gofresh spells an internal package selector directly in the AST.
	internalPkgs := map[string]bool{
		"auditset": true, "buildflags": true, "cachefile": true, "closure": true,
		"dynstate": true, "gotool": true, "guard": true, "jsonrecord": true,
		"outcome": true, "render": true, "runtimeinput": true, "testenv": true,
		"testvariant": true, "trace": true,
	}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	checkTypeExpr := func(contextName string, expr ast.Expr) {
		ast.Inspect(expr, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && internalPkgs[id.Name] {
				t.Errorf("%s references internal package selector %s.%s in exported signature", contextName, id.Name, sel.Sel.Name)
			}
			return true
		})
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() {
					continue
				}
				if d.Recv != nil && len(d.Recv.List) > 0 {
					var recvIdent *ast.Ident
					switch rt := d.Recv.List[0].Type.(type) {
					case *ast.Ident:
						recvIdent = rt
					case *ast.StarExpr:
						recvIdent, _ = rt.X.(*ast.Ident)
					}
					if recvIdent != nil && !recvIdent.IsExported() {
						continue
					}
				}
				if d.Type.Params != nil {
					for _, p := range d.Type.Params.List {
						checkTypeExpr(name+":"+d.Name.Name, p.Type)
					}
				}
				if d.Type.Results != nil {
					for _, r := range d.Type.Results.List {
						checkTypeExpr(name+":"+d.Name.Name, r.Type)
					}
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || !ts.Name.IsExported() || ts.Assign.IsValid() {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok || st.Fields == nil {
						continue
					}
					for _, field := range st.Fields.List {
						exportedField := len(field.Names) == 0
						for _, fn := range field.Names {
							if fn.IsExported() {
								exportedField = true
							}
						}
						if exportedField {
							checkTypeExpr(name+":"+ts.Name.Name, field.Type)
						}
					}
				}
			}
		}
	}

	// 3. Verify promoted type aliases do not expose any method whose signature
	// references an unexported or internal-only type outside the promoted root aliases.
	promotedPkgPaths := map[string]bool{
		"":                                     true,
		"github.com/greatliontech/gofresh":     true,
		"github.com/greatliontech/gofresh/internal/runtimeinput": true,
		"github.com/greatliontech/gofresh/internal/guard":        true,
		"github.com/greatliontech/gofresh/internal/testvariant":  true,
	}
	for _, typ := range []reflect.Type{
		reflect.TypeFor[*InputRoots](),
		reflect.TypeFor[Observation](),
		reflect.TypeFor[RuntimeState](),
		reflect.TypeFor[Bracket](),
		reflect.TypeFor[ScratchNamespace](),
		reflect.TypeFor[Guards](),
		reflect.TypeFor[TestVariantLedger](),
	} {
		for i := range typ.NumMethod() {
			m := typ.Method(i)
			mt := m.Type
			for j := 1; j < mt.NumIn(); j++ {
				inPkg := mt.In(j).PkgPath()
				if strings.Contains(inPkg, "/internal/") && !promotedPkgPaths[inPkg] {
					t.Errorf("%v.%s param %d leaks internal package %s (%v)", typ, m.Name, j, inPkg, mt.In(j))
				}
			}
			for j := range mt.NumOut() {
				outPkg := mt.Out(j).PkgPath()
				if strings.Contains(outPkg, "/internal/") && !promotedPkgPaths[outPkg] {
					t.Errorf("%v.%s result %d leaks internal package %s (%v)", typ, m.Name, j, outPkg, mt.Out(j))
				}
			}
		}
	}
}

func TestModulePackagesHaveNoSharedDynamicStateUnderPackageExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("scans module packages under PackageExecution")
	}
	const modulePath = "github.com/greatliontech/gofresh"
	ctx := t.Context()
	loaded, err := gotool.LoadPackages(
		ctx,
		packages.NeedName|packages.NeedFiles|packages.NeedCompiledGoFiles|packages.NeedSyntax|packages.NeedForTest|packages.NeedModule,
		".",
		os.Environ(),
		nil,
		"./...",
	)
	if err != nil {
		t.Fatalf("LoadPackages(./...): %v", err)
	}

	type pkgReps struct {
		prodSym         string
		prodFallbackSym string
		inPkgTestSym    string
		inPkgFallback   string
		extTestSym      string
		extFallback     string
	}
	repsByPkg := map[string]*pkgReps{}
	activePkgs := map[string]bool{}
	for _, p := range loaded {
		if p == nil || (p.Name == "main" && strings.HasSuffix(p.PkgPath, ".test")) {
			continue
		}
		if len(p.Errors) > 0 {
			t.Fatalf("load error in %s: %v", p.ID, p.Errors[0])
		}
		basePkg := p.PkgPath
		if p.ForTest != "" {
			basePkg = p.ForTest
		}
		if basePkg != modulePath && !strings.HasPrefix(basePkg, modulePath+"/") {
			continue
		}
		if len(p.CompiledGoFiles) > 0 {
			activePkgs[basePkg] = true
		}
		rep := repsByPkg[basePkg]
		if rep == nil {
			rep = &pkgReps{}
			repsByPkg[basePkg] = rep
		}
		isExtTestPkg := strings.HasSuffix(p.PkgPath, "_test")
		for _, file := range p.Syntax {
			if file == nil || p.Fset == nil {
				continue
			}
			tf := p.Fset.File(file.Pos())
			if tf == nil {
				continue
			}
			isTestFile := strings.HasSuffix(tf.Name(), "_test.go")
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name == nil || fn.Name.Name == "init" || fn.Name.Name == "TestMain" || fn.Name.Name == "_" {
					continue
				}
				if dynstate.HasDirective(fn.Doc, "//gofresh:external") {
					continue
				}
				sym := fn.Name.Name
				if fn.Recv != nil {
					recv := dynstate.RecvTypeName(fn)
					if recv == "" {
						continue
					}
					sym = recv + "." + fn.Name.Name
				}
				if isTestFile {
					isRunnerTarget := fn.Recv == nil && (isTestName(fn.Name.Name, "Test") ||
						isTestName(fn.Name.Name, "Benchmark") ||
						isTestName(fn.Name.Name, "Fuzz") ||
						isTestName(fn.Name.Name, "Example"))
					if isExtTestPkg {
						if isRunnerTarget && rep.extTestSym == "" {
							rep.extTestSym = sym
						} else if rep.extFallback == "" {
							rep.extFallback = sym
						}
					} else {
						if isRunnerTarget && rep.inPkgTestSym == "" {
							rep.inPkgTestSym = sym
						} else if rep.inPkgFallback == "" {
							rep.inPkgFallback = sym
						}
					}
				} else {
					if fn.Recv == nil && rep.prodSym == "" {
						rep.prodSym = sym
					} else if rep.prodFallbackSym == "" {
						rep.prodFallbackSym = sym
					}
				}
			}
		}
	}

	pkgPaths := make([]string, 0, len(activePkgs))
	for pkgPath := range activePkgs {
		pkgPaths = append(pkgPaths, pkgPath)
	}
	slices.Sort(pkgPaths)
	if len(pkgPaths) == 0 {
		t.Fatal("LoadPackages(./...) discovered zero active module packages")
	}
	var subjects []Subject
	for _, pkgPath := range pkgPaths {
		rep := repsByPkg[pkgPath]
		prod := rep.prodSym
		if prod == "" {
			prod = rep.prodFallbackSym
		}
		inPkg := rep.inPkgTestSym
		if inPkg == "" {
			inPkg = rep.inPkgFallback
		}
		ext := rep.extTestSym
		if ext == "" {
			ext = rep.extFallback
		}
		added := 0
		for _, sym := range []string{prod, inPkg, ext} {
			if sym != "" {
				subjects = append(subjects, Subject{Package: pkgPath, Symbol: sym})
				added++
			}
		}
		if added == 0 {
			t.Fatalf("active module package %s yielded zero Subject representatives", pkgPath)
		}
	}

	session, err := NewSession(ctx, BuildDescription{
		Directory:   ".",
		Environment: os.Environ(),
		Inputs:      []string{},
	}, SessionPolicy{
		Execution: PackageExecution,
		Vouches: []string{
			"github.com/greatliontech/go-x-tools/internal/gcimporter.exportMap",
			"github.com/greatliontech/go-x-tools/go/ast/edge.fieldInfos",
		},
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	snap, err := session.Snapshot(ctx, subjects, CodeResult)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	for _, s := range subjects {
		if st := snap.facts.maximal[s].sharedState; st != nil {
			t.Errorf("undischarged shared dynamic state on %s.%s: culprit=%s.%s reason=%s",
				s.Package, s.Symbol, st.culprit.Package, st.culprit.Symbol, st.reason)
		}
	}
	fps, err := snap.CaptureBatch(ctx)
	if err != nil {
		t.Fatalf("CaptureBatch: %v", err)
	}
	binding, err := snap.BindRuntime(ctx, RuntimeDescription{Directory: "."})
	if err != nil {
		t.Fatalf("BindRuntime: %v", err)
	}
	cands := make([]Candidate, 0, len(subjects))
	for _, s := range subjects {
		cands = append(cands, Candidate{Subject: s, Recorded: fps[s]})
	}
	verdicts, err := binding.CheckBatchWithLedgers(ctx, cands, nil)
	if err != nil {
		t.Fatalf("CheckBatchWithLedgers: %v", err)
	}
	seenCulprits := map[Subject]string{}
	for _, v := range verdicts {
		if v.Verdict.Ground.Cause.Kind == SharedDynamicStateCause {
			if _, ok := seenCulprits[v.Verdict.Ground.Cause.Culprit]; !ok {
				seenCulprits[v.Verdict.Ground.Cause.Culprit] = v.Subject.Package + "." + v.Subject.Symbol + ": " + v.Verdict.Reason
			}
		}
	}
	for culprit, sample := range seenCulprits {
		t.Errorf("SharedDynamicStateCause culprit %s.%s (e.g. %s)", culprit.Package, culprit.Symbol, sample)
	}
}
