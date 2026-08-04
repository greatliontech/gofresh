package closure

type externalEffectKind uint8

// The enum ORDER is the effect projection's primary sort key; the proof's
// refusal names the highest-ranked blocking effect under effectCauseRank
// with this order as the tie-break — so inserting or reordering members
// AND editing the rank table both move recorded diagnostic texts and owe
// an ObservationRTA bump (the recorded-evidence versioning clause).
const (
	externalEffectOpaque externalEffectKind = iota
	externalEffectStandardInput
	externalEffectFormattedOutput
	externalEffectEnvironment
	externalEffectFileIO
	externalEffectFilesystemMutation
	externalEffectPathMutation
	externalEffectTestRuntime
	externalEffectNetwork
	externalEffectPlugin
	externalEffectNative
	externalEffectLinkage
	externalEffectUnauditedStandard
)

// externalEffect retains the complete machine-readable fact independently of the
// single legacy diagnostic projected through Closure.Reason.
type externalEffect struct {
	kind        externalEffectKind
	packagePath string
	symbol      string
	detail      string
	reason      string
	unrefinable bool
	observable  bool
}

type maximalEffectScan struct {
	effects   []externalEffect
	preferred string
}

func (s *maximalEffectScan) add(effect externalEffect) {
	s.effects = appendExternalEffect(s.effects, effect)
}

func opaqueExternalEffect(kind externalEffectKind, reason string) externalEffect {
	return externalEffect{kind: kind, detail: reason, reason: reason}
}

func symbolExternalEffect(kind externalEffectKind, pkgPath, name, reason string) externalEffect {
	return externalEffect{kind: kind, packagePath: pkgPath, symbol: name, reason: reason}
}

func appendExternalEffect(effects []externalEffect, effect externalEffect) []externalEffect {
	if effect.reason == "" {
		return effects
	}
	for _, existing := range effects {
		if existing == effect {
			return effects
		}
	}
	return append(effects, effect)
}

func classBEffect(pkgPath, name string) (externalEffect, bool) {
	if pkgPath == "fmt" {
		switch name {
		case "Scan", "Scanf", "Scanln", "Fscan", "Fscanf", "Fscanln":
			return symbolExternalEffect(externalEffectStandardInput, pkgPath, name, "reaches fmt."+name+" (standard input)"), true
		case "Print", "Printf", "Println", "Fprint", "Fprintf", "Fprintln":
			return symbolExternalEffect(externalEffectFormattedOutput, pkgPath, name, "reaches fmt."+name+" (formatted output)"), true
		}
	}
	if pkgPath == "os" {
		switch name {
		case "Getenv", "LookupEnv", "Environ", "ExpandEnv":
			return symbolExternalEffect(externalEffectEnvironment, pkgPath, name, "reaches os."+name+" (environment input)"), true
		case "Open", "OpenFile", "ReadFile", "ReadDir", "Stat", "Lstat":
			return symbolExternalEffect(externalEffectFileIO, pkgPath, name, "reaches os."+name+" (file I/O)"), true
		case "Create", "CreateTemp", "WriteFile":
			return symbolExternalEffect(externalEffectFilesystemMutation, pkgPath, name, "reaches os."+name+" (filesystem mutation)"), true
		case "CopyFS", "Link", "Mkdir", "MkdirAll", "MkdirTemp", "Remove", "RemoveAll", "Rename", "Symlink":
			return symbolExternalEffect(externalEffectPathMutation, pkgPath, name, "reaches os."+name+" (path mutation)"), true
		}
	}
	if pkgPath == "syscall" || pkgPath == "golang.org/x/sys/unix" {
		switch name {
		case "Creat":
			return symbolExternalEffect(externalEffectFilesystemMutation, pkgPath, name, "reaches "+pkgPath+"."+name+" (filesystem mutation)"), true
		case "Link", "Linkat", "Mkdir", "Mkdirat", "Rename", "Renameat", "Renameat2", "Rmdir", "Symlink", "Symlinkat", "Unlink", "Unlinkat":
			return symbolExternalEffect(externalEffectPathMutation, pkgPath, name, "reaches "+pkgPath+"."+name+" (path mutation)"), true
		}
	}
	if pkgPath == "testing" {
		switch name {
		case "TempDir", "Chdir", "Setenv":
			return symbolExternalEffect(externalEffectPathMutation, pkgPath, name, "reaches testing."+name+" (process or path mutation)"), true
		case "Short", "Verbose", "Testing", "CoverMode", "Coverage", "Deadline", "N", "Loop", "Parallel", "ArtifactDir", "Context":
			return symbolExternalEffect(externalEffectTestRuntime, pkgPath, name, "reaches testing."+name+" (test runtime configuration)"), true
		case "Run", "Fuzz", "RunParallel", "Elapsed", "Result", "AllocsPerRun", "Benchmark", "RunBenchmarks", "RunExamples", "RunTests", "Main", "MainStart":
			return symbolExternalEffect(externalEffectTestRuntime, pkgPath, name, "reaches testing."+name+" (test runtime execution)"), true
		}
	}
	if pkgPath == "net" {
		switch name {
		case "Dial", "DialContext", "DialTCP", "DialUDP", "DialIP", "Listen", "ListenTCP", "ListenUDP", "ListenIP", "ListenPacket":
			return symbolExternalEffect(externalEffectNetwork, pkgPath, name, "reaches net."+name+" (network I/O)"), true
		}
	}
	if pkgPath == "net/http" {
		switch name {
		case "Get", "Head", "Post", "PostForm", "Do", "ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS":
			return symbolExternalEffect(externalEffectNetwork, pkgPath, name, "reaches net/http."+name+" (network I/O)"), true
		}
	}
	if pkgPath == "html/template" || pkgPath == "text/template" {
		switch name {
		case "ParseFiles", "ParseGlob":
			return symbolExternalEffect(externalEffectFileIO, pkgPath, name, "reaches "+pkgPath+"."+name+" (file I/O)"), true
		}
	}
	if pkgPath == "plugin" && (name == "Open" || name == "Lookup") {
		return symbolExternalEffect(externalEffectPlugin, pkgPath, name, "reaches plugin."+name), true
	}
	return externalEffect{}, false
}

// auditedHarnessLogging reports whether a testing-package symbol is the
// harness's failure/logging channel: output lands only in the harness's
// own in-memory buffer and the run's captured output, both already part
// of the recorded test outcome, so the channel is output-only and adds
// no testlog-invisible input (REQ-closure-observability-analysis).
// Argument method sets stay visible to reachability at the call site,
// exactly as fmt's Sprint family. Deliberately excluded: the harness's
// ambient-input and mutation surfaces (Setenv, Chdir, TempDir, the
// runtime-configuration reads) keep their own classifications.
func auditedHarnessLogging(pkgPath, name string) bool {
	if pkgPath != "testing" {
		return false
	}
	switch name {
	case "Fatal", "Fatalf", "Error", "Errorf", "Log", "Logf", "Skip", "Skipf", "SkipNow", "Fail", "FailNow":
		return true
	}
	return false
}

// harnessLoggingEffect is the admitted harness fact the walk records in
// place of descending into harness internals: observable, so the
// observation proof never blocks on it, while the record still flips the
// legacy unverifiable projection — an audited harness call is not purity
// evidence.
func harnessLoggingEffect(name string) externalEffect {
	effect := symbolExternalEffect(externalEffectTestRuntime, "testing", name, "reaches testing."+name+" (test harness logging)")
	effect.observable = true
	return effect
}

// classBPureStandard audits specific operations of effect-bearing
// standard packages as pure: value-to-value computation with no ambient
// acquisition and no testlog-invisible channel. fmt's Sprint family
// qualifies (arguments' methods stay visible to reachability); its
// Print family is classified output and its Scan family classified
// input, so only the pure remainder lands here
// (REQ-closure-observability-analysis).
func classBPureStandard(pkgPath, name string) bool {
	if pkgPath != "fmt" {
		return false
	}
	switch name {
	case "Sprint", "Sprintf", "Sprintln", "Errorf", "Append", "Appendf", "Appendln", "FormatString":
		return true
	}
	return false
}

// fmtFprintFamily names fmt's writer-first print operations — the one
// classified family whose effect is decided by an operand: the writer
// receives every formatted byte, so a writer proven to be an audited
// in-memory sink makes the call Sprint-equivalent value computation,
// while Print (implicit stdout) and the Scan families carry their
// channel in the symbol itself
// (REQ-closure-observability-analysis's writer-sink admission).
func fmtFprintFamily(pkgPath, name string) bool {
	if pkgPath != "fmt" {
		return false
	}
	switch name {
	case "Fprint", "Fprintf", "Fprintln":
		return true
	}
	return false
}

func classBReason(pkgPath, name string) string {
	effect, ok := classBEffect(pkgPath, name)
	if !ok {
		return ""
	}
	return effect.reason
}
