package closure

type externalEffectKind uint8

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

func classBReason(pkgPath, name string) string {
	effect, ok := classBEffect(pkgPath, name)
	if !ok {
		return ""
	}
	return effect.reason
}
