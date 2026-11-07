package closure

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
)

const nonStdAsmVerifierVersion = "gofresh/nonstd-asm-verifier@4"

// auditedReadOnlyVarLinknameTargets maps runtime startup-constant scalar
// variables to their exact underlying Go BasicKind so two-argument pull-form
// //go:linkname bindings cannot widen layout or reinterpret scalars as string
// or pointer headers, and are admitted at Tier-2 observability only when the
// local variable (and every peer bound to the same target in the program) has
// no initializer, no stores, no address escapes, and no non-SSA native hazards
// in its declaring package.
var auditedReadOnlyVarLinknameTargets = map[string]types.BasicKind{
	"internal/cpu.HWCap": types.Uint,
}

type asmTextSummary struct {
	cpuidArgs  int // 1 or 2 for canonical CPUID wrappers; 0 otherwise
	impureKind string
}

type verifiedAsmPackage struct {
	ok            bool
	funcs         map[string]asmTextSummary
	rodataGoNames []string
}

const verifiedNonStdAsmMemoSummaryKey = "gofresh/verified-nonstd-asm@4"

func sortedCleanBasenamesKey(files []string) string {
	if len(files) == 0 {
		return ""
	}
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = filepath.Base(filepath.Clean(f))
	}
	slices.Sort(names)
	return strings.Join(names, "\x00")
}

func checkVerifiedAsmTypeScopes(vp *verifiedAsmPackage, typeScopes []*types.Package) bool {
	if vp == nil || !vp.ok {
		return false
	}
	for _, goName := range vp.rodataGoNames {
		if goName == "" {
			continue
		}
		for _, tp := range typeScopes {
			if tp == nil || tp.Scope() == nil || tp.Scope().Lookup(goName) != nil {
				return false
			}
		}
	}
	return true
}

func verifyNonStdAssemblyMemo(p *program, goarch, pkgPath, dir string, sFiles, hFiles []string, typeScopes []*types.Package, read func(string) ([]byte, error)) (*verifiedAsmPackage, bool) {
	memoKey := goarch + "\x00" + pkgPath + "\x00" + filepath.Clean(dir) + "\x00" + sortedCleanBasenamesKey(sFiles) + "\x00|\x00" + sortedCleanBasenamesKey(hFiles)
	if p != nil && p.Summaries != nil {
		if memoMap, ok := p.Summaries[verifiedNonStdAsmMemoSummaryKey].(map[string]*verifiedAsmPackage); ok {
			if cached, found := memoMap[memoKey]; found && cached != nil {
				if !cached.ok || !checkVerifiedAsmTypeScopes(cached, typeScopes) {
					return &verifiedAsmPackage{ok: false}, false
				}
				return cached, true
			}
		}
	}
	vp, ok := verifyNonStdAssemblyFiles(goarch, pkgPath, dir, sFiles, hFiles, typeScopes, read)
	if !ok || vp == nil {
		vp = &verifiedAsmPackage{ok: false}
	}
	if p != nil {
		if p.Summaries == nil {
			p.Summaries = make(map[string]any, 4)
		}
		memoMap, _ := p.Summaries[verifiedNonStdAsmMemoSummaryKey].(map[string]*verifiedAsmPackage)
		if memoMap == nil {
			memoMap = make(map[string]*verifiedAsmPackage, 4)
			p.Summaries[verifiedNonStdAsmMemoSummaryKey] = memoMap
		}
		memoMap[memoKey] = vp
	}
	if !vp.ok || !checkVerifiedAsmTypeScopes(vp, typeScopes) {
		return &verifiedAsmPackage{ok: false}, false
	}
	return vp, true
}

func (b *tier2Base) verifiedPackageAssembly(pkg *listPkg) (*verifiedAsmPackage, bool) {
	if b == nil || b.h == nil || !b.h.SelectionAudited() || pkg == nil || len(pkg.SFiles) == 0 {
		return nil, false
	}
	if hasExternalCgoMeta(pkg) || len(pkg.SysoFiles) != 0 || hasNonHeaderNativeSource(pkg) {
		return nil, false
	}
	key := pkg.ImportPath + "\x00" + filepath.Clean(pkg.Dir)
	if b.verifiedAsm != nil {
		if cached, ok := b.verifiedAsm[key]; ok {
			return cached, cached.ok
		}
	}
	var typeScopes []*types.Package
	srcPath := pkg.SourcePath()
	for tp, idx := range b.idxByTypes {
		if tp != nil && idx != nil && (idx.path == srcPath || idx.path == pkg.ImportPath || (idx.meta != nil && idx.meta.Dir == pkg.Dir)) {
			typeScopes = append(typeScopes, tp)
		}
	}
	if len(pkg.GoFiles) > 0 && len(typeScopes) == 0 {
		if b.verifiedAsm == nil {
			b.verifiedAsm = make(map[string]*verifiedAsmPackage, 4)
		}
		res := &verifiedAsmPackage{ok: false}
		b.verifiedAsm[key] = res
		return res, false
	}
	readFn := func(fullPath string) ([]byte, error) {
		if b.h.underCache(pkg.Dir) {
			return os.ReadFile(fullPath)
		}
		fb, err := b.h.readFile(fullPath)
		if err != nil {
			return nil, err
		}
		return fb.content, nil
	}
	res, ok := verifyNonStdAssemblyMemo(b.prog, b.h.effectiveGOARCH(), srcPath, pkg.Dir, pkg.SFiles, pkg.HFiles, typeScopes, readFn)
	if !ok {
		res = &verifiedAsmPackage{ok: false}
	}
	if b.verifiedAsm == nil {
		b.verifiedAsm = make(map[string]*verifiedAsmPackage, 4)
	}
	b.verifiedAsm[key] = res
	return res, res.ok
}

func (b *tier2Base) verifiedPackageAssemblyMaximalPure(pkg *listPkg) bool {
	vp, ok := b.verifiedPackageAssembly(pkg)
	if !ok || vp == nil {
		return false
	}
	for _, sum := range vp.funcs {
		if sum.impureKind != "" || sum.cpuidArgs > 0 {
			return false
		}
	}
	matchedIdx := false
	srcPath := pkg.SourcePath()
	for _, idx := range b.idxByTypes {
		if idx == nil || (idx.path != srcPath && idx.path != pkg.ImportPath && (idx.meta == nil || idx.meta.Dir != pkg.Dir)) {
			continue
		}
		matchedIdx = true
		for obj, node := range idx.decls {
			fnObj, isFn := obj.(*types.Func)
			fd, isFD := node.(*ast.FuncDecl)
			if !isFn || !isFD || fd.Body != nil {
				continue
			}
			sig, isSig := fnObj.Type().(*types.Signature)
			if !isSig || sig.Recv() != nil || sig.TypeParams().Len() > 0 || !asmSignatureCarrierFree(sig) {
				return false
			}
			if _, found := vp.funcs[fnObj.Name()]; !found {
				return false
			}
		}
	}
	return matchedIdx
}

func (a *tier2Analyzer) verifiedPackageAssembly(pkg *listPkg) bool {
	if a == nil || a.base == nil {
		return false
	}
	_, ok := a.base.verifiedPackageAssembly(pkg)
	return ok
}

func (a *tier2Analyzer) verifiedPackageAssemblyFunc(pkg *listPkg, fn *ssa.Function) (asmTextSummary, bool) {
	if a == nil || a.base == nil || fn == nil || fn.Signature == nil || fn.Signature.Recv() != nil || fn.TypeParams().Len() > 0 {
		return asmTextSummary{}, false
	}
	if !asmSignatureCarrierFree(fn.Signature) {
		return asmTextSummary{}, false
	}
	vp, ok := a.base.verifiedPackageAssembly(pkg)
	if !ok || vp == nil {
		return asmTextSummary{}, false
	}
	sum, found := vp.funcs[fn.Name()]
	if !found {
		return asmTextSummary{}, false
	}
	if sum.cpuidArgs > 0 && !isCanonicalCPUIDSignature(fn.Signature, sum.cpuidArgs) {
		sum.cpuidArgs = 0
		if sum.impureKind == "" {
			sum.impureKind = "per-core CPUID register"
		}
	}
	return sum, true
}

func isCanonicalCPUIDSignature(sig *types.Signature, argCount int) bool {
	if sig == nil || sig.Recv() != nil || sig.Variadic() {
		return false
	}
	if sig.Params() == nil || sig.Params().Len() != argCount || sig.Results() == nil || sig.Results().Len() != 4 {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		b, ok := sig.Params().At(i).Type().Underlying().(*types.Basic)
		if !ok || b.Kind() != types.Uint32 {
			return false
		}
	}
	for i := 0; i < 4; i++ {
		b, ok := sig.Results().At(i).Type().Underlying().(*types.Basic)
		if !ok || b.Kind() != types.Uint32 {
			return false
		}
	}
	return true
}

func asmSignatureCarrierFree(sig *types.Signature) bool {
	if sig == nil || sig.Recv() != nil {
		return false
	}
	checkTuple := func(tup *types.Tuple) bool {
		if tup == nil {
			return true
		}
		for i := 0; i < tup.Len(); i++ {
			if !asmTypeSafe(tup.At(i).Type(), map[types.Type]bool{}) {
				return false
			}
		}
		return true
	}
	return checkTuple(sig.Params()) && checkTuple(sig.Results())
}

func asmTypeSafe(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if seen[t] {
		return true
	}
	seen[t] = true
	switch u := t.Underlying().(type) {
	case *types.Basic:
		return u.Kind() != types.UnsafePointer && u.Kind() != types.Uintptr && u.Kind() != types.Invalid
	case *types.Array:
		return asmTypeSafe(u.Elem(), seen)
	case *types.Slice:
		return asmTypeSafe(u.Elem(), seen)
	case *types.Pointer:
		return asmTypeSafe(u.Elem(), seen)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if !asmTypeSafe(u.Field(i).Type(), seen) {
				return false
			}
		}
		return true
	default:
		// Interfaces, funcs, channels, maps, and type parameters are rejected.
		return false
	}
}

func verifyNonStdAssemblyFiles(goarch, pkgPath, dir string, sFiles, hFiles []string, typeScopes []*types.Package, read func(string) ([]byte, error)) (*verifiedAsmPackage, bool) {
	if (goarch != "amd64" && goarch != "arm64") || pkgPath == "" || dir == "" || len(sFiles) == 0 || read == nil {
		return nil, false
	}
	cleanDir := filepath.Clean(dir)
	resolveMember := func(f string) (string, string, bool) {
		if f == "" {
			return "", "", false
		}
		if filepath.IsAbs(f) {
			cf := filepath.Clean(f)
			if filepath.Dir(cf) != cleanDir {
				return "", "", false
			}
			base := filepath.Base(cf)
			if base == "" || base == "." || base == ".." {
				return "", "", false
			}
			return base, cf, true
		}
		if strings.ContainsAny(f, `/\`) || strings.Contains(f, "..") {
			return "", "", false
		}
		return f, filepath.Join(cleanDir, f), true
	}

	type loadedHeader struct {
		name string
		txt  string
	}
	selectedHeaders := make(map[string]bool, len(hFiles))
	localHeaders := make(map[string]string, len(hFiles))
	headers := make([]loadedHeader, 0, len(hFiles))
	for _, hf := range hFiles {
		name, full, ok := resolveMember(hf)
		if !ok || !strings.EqualFold(filepath.Ext(name), ".h") {
			return nil, false
		}
		raw, err := read(full)
		if err != nil {
			return nil, false
		}
		selectedHeaders[name] = true
		headers = append(headers, loadedHeader{name: name, txt: string(raw)})
	}
	for _, hdr := range headers {
		if verifyNonStdAsmPreprocessor("", hdr.name, hdr.txt, selectedHeaders) != nil {
			return nil, false
		}
		localHeaders[hdr.name] = foldAsmDefineNewlines(stripAssemblyComments(hdr.txt, true, false))
	}

	foldedFiles := make([]string, 0, len(sFiles))
	for _, sf := range sFiles {
		name, full, ok := resolveMember(sf)
		if !ok || filepath.Ext(name) != ".s" {
			return nil, false
		}
		raw, err := read(full)
		if err != nil {
			return nil, false
		}
		txt := string(raw)
		if verifyNonStdAsmPreprocessor(pkgPath, name, txt, selectedHeaders) != nil {
			return nil, false
		}
		folded := foldAsmDefineNewlines(stripAssemblyComments(txt, true, false))
		foldedFiles = append(foldedFiles, folded)
	}

	pkgRodataSyms := map[string]bool{}
	var rodataGoNames []string
	seenRodataGo := map[string]bool{}
	parsedFiles := make([]*parsedNonStdAsmFile, 0, len(foldedFiles))
	for _, folded := range foldedFiles {
		parsed, ok := parseSingleNonStdAsmFile(pkgPath, folded, localHeaders, typeScopes, pkgRodataSyms)
		if !ok {
			return nil, false
		}
		for _, gn := range parsed.rodataGoNames {
			if gn != "" && !seenRodataGo[gn] {
				seenRodataGo[gn] = true
				rodataGoNames = append(rodataGoNames, gn)
			}
		}
		parsedFiles = append(parsedFiles, parsed)
	}

	funcs := map[string]asmTextSummary{}
	for _, parsed := range parsedFiles {
		if !verifyParsedNonStdAsmFile(goarch, pkgPath, parsed, pkgRodataSyms, funcs) {
			return nil, false
		}
	}
	slices.Sort(rodataGoNames)
	return &verifiedAsmPackage{ok: true, funcs: funcs, rodataGoNames: rodataGoNames}, true
}

// foldAsmDefineNewlines converts backslash-continued lines inside #define
// bodies into semicolon-separated assembly statements unless the line ends with
// a token that continues an operand list or expression (matching cmd/asm's
// macro newline tokenization on multi-instruction macros).
func foldAsmDefineNewlines(src string) string {
	if !strings.Contains(src, "\\") {
		return src
	}
	lines := strings.Split(src, "\n")
	var out strings.Builder
	out.Grow(len(src) + 32)
	inDefine := false
	for idx, line := range lines {
		trimmedRight := strings.TrimRight(line, " \t\r")
		trimmed := strings.TrimSpace(trimmedRight)
		if !inDefine && strings.HasPrefix(trimmed, "#") {
			rest := strings.TrimSpace(trimmed[1:])
			if strings.HasPrefix(rest, "define") && (len(rest) == 6 || rest[6] == ' ' || rest[6] == '\t') {
				inDefine = true
			}
		}
		bs := 0
		for bs < len(trimmedRight) && trimmedRight[len(trimmedRight)-1-bs] == '\\' {
			bs++
		}
		if bs%2 == 1 && idx+1 < len(lines) {
			prefix := strings.TrimRight(trimmedRight[:len(trimmedRight)-1], " \t")
			out.WriteString(prefix)
			if inDefine && !asmLineContinuesOperandOrHeader(prefix) {
				out.WriteString(" ; ")
			} else {
				out.WriteByte(' ')
			}
			continue
		}
		inDefine = false
		out.WriteString(line)
		if idx+1 < len(lines) {
			out.WriteByte('\n')
		}
	}
	return out.String()
}

func asmLineContinuesOperandOrHeader(prefix string) bool {
	trimmed := strings.TrimSpace(prefix)
	if trimmed == "" {
		return true
	}
	if strings.HasPrefix(trimmed, "#") {
		rest := strings.TrimSpace(trimmed[1:])
		if strings.HasPrefix(rest, "define") {
			after := strings.TrimSpace(rest[6:])
			mEnd := 0
			for mEnd < len(after) && isASCIIIdentByte(after[mEnd]) {
				mEnd++
			}
			tail := after[mEnd:]
			if strings.HasPrefix(tail, "(") {
				if closeIdx := strings.IndexByte(tail, ')'); closeIdx >= 0 {
					return strings.TrimSpace(tail[closeIdx+1:]) == ""
				}
				return true
			}
			return strings.TrimSpace(tail) == ""
		}
	}
	last := trimmed[len(trimmed)-1]
	switch last {
	case ',', '(', '+', '-', '*', '/', '|', '&', '^', '~', '<', '>', ';', ':':
		return true
	}
	return false
}

func verifyNonStdAsmPreprocessor(pkgPath, name, src string, selectedHeaders map[string]bool) error {
	if err := verifyNonStdAsmPreprocessorPass(pkgPath, name, src, selectedHeaders, true); err != nil {
		return err
	}
	return verifyNonStdAsmPreprocessorPass(pkgPath, name, src, selectedHeaders, false)
}

func appendMacroDefUnique(defs map[string][]cppMacroDef, name string, def cppMacroDef) {
	for _, prev := range defs[name] {
		if prev.hasParams == def.hasParams && prev.variadic == def.variadic && prev.namedVarParam == def.namedVarParam && prev.body == def.body && slices.Equal(prev.params, def.params) {
			return
		}
	}
	defs[name] = append(defs[name], def)
}

func ensureMacroIdentityChoice(defs map[string][]cppMacroDef, name string) {
	dList := defs[name]
	if len(dList) == 0 {
		return
	}
	for _, d := range dList {
		if !d.hasParams && d.body == name {
			return
		}
	}
	defs[name] = append(dList, cppMacroDef{body: name})
}

func isForbiddenX86ControlOrDebugReg(u string) bool {
	for _, pfx := range []string{"CR", "DR", "TR"} {
		if rest, ok := strings.CutPrefix(u, pfx); ok && len(rest) > 0 && len(rest) <= 2 {
			allDigits := true
			for i := 0; i < len(rest); i++ {
				if rest[i] < '0' || rest[i] > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				n, err := strconv.Atoi(rest)
				if err == nil && ((pfx != "TR" && n <= 15) || (pfx == "TR" && n <= 7)) {
					return true
				}
			}
		}
	}
	return false
}

func isARM64TLSSysReg(u string) bool {
	return strings.HasPrefix(u, "TPIDR") || strings.HasPrefix(u, "SCXTNUM")
}

func hasARM64ELRegSuffix(u string) bool {
	return strings.Contains(u, "_EL0") || strings.Contains(u, "_EL1") ||
		strings.Contains(u, "_EL2") || strings.Contains(u, "_EL3")
}

// isARM64SystemOrPStateReg reports whether u (uppercased) names an ARM64
// system register or PSTATE field recognized by cmd/asm (including all
// arm64.SystemReg entries in cmd/internal/obj/arm64/sysRegEnc.go and PSTATE
// special operands). On arm64, cmd/asm accepts MOVD <SysReg>, Rd and
// MOVD Rs/$imm, <SysReg> as aliases for MRS and MSR.
func isARM64SystemOrPStateReg(u string) bool {
	if hasARM64ELRegSuffix(u) {
		return true
	}
	switch u {
	case "CURRENTEL", "DAIF", "DAIFSET", "DAIFCLR", "DIT", "FPCR", "FPSR",
		"NZCV", "PAN", "RNDR", "RNDRRS", "SPSEL",
		"SPSR_ABT", "SPSR_FIQ", "SPSR_IRQ", "SPSR_UND",
		"SSBS", "TCO", "UAO",
		"ALLINT", "SVCR", "SVCRSM", "SVCRZA", "SVCRSMZA":
		return true
	}
	return false
}

func isReservedNonStdAsmMacroName(name string) bool {
	if name == "g" || name == "init" {
		return true
	}
	u := strings.ToUpper(name)
	if isForbiddenX86ControlOrDebugReg(u) || isARM64TLSSysReg(u) || isARM64SystemOrPStateReg(u) ||
		strings.HasPrefix(u, "RDRAND") || strings.HasPrefix(u, "RDSEED") ||
		strings.HasPrefix(u, "RDFSBASE") || strings.HasPrefix(u, "RDGSBASE") ||
		strings.HasPrefix(u, "WRFSBASE") || strings.HasPrefix(u, "WRGSBASE") ||
		strings.HasPrefix(u, "FXRSTOR") || strings.HasPrefix(u, "XRSTOR") ||
		strings.HasPrefix(u, "POPF") || strings.HasPrefix(u, "PUSHF") {
		return true
	}
	switch u {
	case "TEXT", "GLOBL", "DATA", "FUNCDATA", "PCDATA", "PCALIGN", "PCALIGNMAX",
		"DUFFCOPY", "DUFFZERO", "GETCALLERPC", "UNDEF", "END", "XXX",
		"BYTE", "WORD", "DWORD", "LONG", "QUAD",
		"CALL", "BL", "BLR", "BLRAA", "BLRAAZ", "BLRAB", "BLRABZ",
		"JAL", "JALR", "CALLF", "BSR", "BCTRL", "BLRL",
		"BR", "BRAA", "BRAAZ", "BRAB", "BRABZ", "JMP", "JMPF",
		"RET", "RETF", "RETFW", "RETFL", "RETFQ", "RETAA", "RETAB", "ADR", "ADRP",
		"SYSCALL", "SYSENTER", "SYSENTER64", "SYSEXIT", "SYSEXIT64", "SYSRET", "SYSRET64",
		"SVC", "ECALL", "SCALL", "SWI", "INT", "INT1", "INT3", "INTO", "ICEBP", "TA",
		"CPUID", "RDTSC", "RDTSCP", "RDPMC", "RDTIME", "RDCYCLE", "RDINSTRET",
		"MSR", "MRS", "SYS", "SYSL", "DC", "IC", "AT", "TLBI", "HINT", "SEV", "SEVL", "WRMSR", "RDMSR", "RDPID",
		"LDMXCSR", "VLDMXCSR", "FLDCW", "FLDENV", "FRSTOR", "FINIT", "FNINIT", "XSETBV", "STD",
		"LFS", "LFSW", "LFSL", "LFSQ", "LGS", "LGSW", "LGSL", "LGSQ",
		"LSS", "LSSW", "LSSL", "LSSQ", "LDS", "LDSW", "LDSL", "LDSQ", "LES", "LESW", "LESL", "LESQ",
		"WRPKRU", "RDPKRU", "SGDT", "SIDT", "LGDT", "LIDT", "LLDT", "LTR", "LMSW", "CLTS", "INVD", "WBINVD", "INVLPG", "INVPCID", "SWAPGS",
		"XBEGIN", "XEND", "XABORT", "XTEST",
		"TPAUSE", "UMWAIT", "MWAIT", "MONITOR", "MWAITX", "MONITORX",
		"UD0", "UD1", "UD2", "BRK", "HVC", "SMC", "HLT", "DCPS1", "DCPS2", "DCPS3", "DRPS", "ERET", "WFI", "WFE",
		"INB", "INW", "INL", "OUTB", "OUTW", "OUTL", "INSB", "INSW", "INSL", "OUTSB", "OUTSW", "OUTSL",
		"R28", "R18", "R18_PLATFORM", "FS", "GS", "CS", "SS", "DS", "ES",
		"GDTR", "IDTR", "LDTR", "MSW", "TASK", "SPR", "SREG", "IP", "MAXREG",
		"RODATA", "NOPTR", "DUPOK", "NOPROF", "TLSBSS", "NOSPLIT",
		"SB", "FP", "SP", "PC", "TLS":
		return true
	}
	return false
}

func verifyNonStdAsmPreprocessorPass(pkgPath, name, src string, selectedHeaders map[string]bool, joinSpace bool) error {
	isHeader := pkgPath == "" || strings.EqualFold(filepath.Ext(name), ".h")
	noComments := stripAssemblyComments(src, true, joinSpace)
	definedMacros := map[string]bool{}
	condDepth := 0
	for _, rawLine := range strings.Split(noComments, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if !strings.HasPrefix(trimmed, "#") {
			continue
		}
		directive := strings.TrimSpace(trimmed[1:])
		kwEnd := 0
		for kwEnd < len(directive) && ((directive[kwEnd] >= 'a' && directive[kwEnd] <= 'z') || (directive[kwEnd] >= 'A' && directive[kwEnd] <= 'Z') || directive[kwEnd] == '_') {
			kwEnd++
		}
		kw := directive[:kwEnd]
		if !allowedAsmDirectiveKeywords[kw] {
			return fmt.Errorf("%s/%s: unsupported preprocessor directive", pkgPath, name)
		}
		switch kw {
		case "if", "ifdef", "ifndef":
			condDepth++
			continue
		case "elif", "else":
			if condDepth <= 0 {
				return fmt.Errorf("%s/%s: unmatched #%s", pkgPath, name, kw)
			}
			continue
		case "endif":
			if condDepth <= 0 {
				return fmt.Errorf("%s/%s: unmatched #endif", pkgPath, name)
			}
			condDepth--
			continue
		case "undef":
			uRest := strings.TrimSpace(directive[kwEnd:])
			uEnd := 0
			for uEnd < len(uRest) && isASCIIIdentByte(uRest[uEnd]) && (uEnd > 0 || (uRest[uEnd] < '0' || uRest[uEnd] > '9')) {
				uEnd++
			}
			uName := uRest[:uEnd]
			if uName == "" || strings.TrimSpace(uRest[uEnd:]) != "" || isReservedNonStdAsmMacroName(uName) {
				return fmt.Errorf("%s/%s: forbidden or malformed #undef %q", pkgPath, name, uRest)
			}
			continue
		}
		if kw == "define" {
			defRest := strings.TrimSpace(directive[kwEnd:])
			mEnd := 0
			for mEnd < len(defRest) && isASCIIIdentByte(defRest[mEnd]) && (mEnd > 0 || (defRest[mEnd] < '0' || defRest[mEnd] > '9')) {
				mEnd++
			}
			macroName := defRest[:mEnd]
			afterMacroName := defRest[mEnd:]
			if macroName == "" || isReservedNonStdAsmMacroName(macroName) ||
				(afterMacroName != "" && afterMacroName[0] != '(' && afterMacroName[0] != ' ' && afterMacroName[0] != '\t') {
				return fmt.Errorf("%s/%s: malformed or reserved #define %q", pkgPath, name, macroName)
			}
			hasMacroParams := strings.HasPrefix(afterMacroName, "(")
			macroBody := afterMacroName
			if hasMacroParams {
				if closeIdx := strings.IndexByte(afterMacroName, ')'); closeIdx >= 0 {
					macroBody = afterMacroName[closeIdx+1:]
				}
			}
			if pkgPath != "" && (macroName == pkgPath || strings.Contains(pkgPath, "/"+macroName) || strings.HasPrefix(pkgPath, macroName+"/")) {
				return fmt.Errorf("%s/%s: #define %s shadows package path", pkgPath, name, macroName)
			}
			if isHeader && !hasMacroParams && strings.TrimSpace(macroBody) != "" && macroName[0] >= 'a' && macroName[0] <= 'z' {
				return fmt.Errorf("%s/%s: header #define %s shadows lowercase identifier", pkgPath, name, macroName)
			}
			definedMacros[macroName] = true
			continue
		}
		if kw != "include" {
			continue
		}
		incArg := strings.TrimSpace(directive[kwEnd:])
		if len(incArg) < 2 || incArg[0] != '"' {
			return fmt.Errorf("%s/%s: unapproved #include %s", pkgPath, name, incArg)
		}
		hdr, err := strconv.Unquote(incArg)
		if err != nil || hdr == "" || strings.ContainsAny(hdr, `/\`) || strings.Contains(hdr, "..") {
			return fmt.Errorf("%s/%s: forbidden #include %q", pkgPath, name, hdr)
		}
		if !allowedPureAsmStandardHeaders[hdr] && !selectedHeaders[hdr] {
			return fmt.Errorf("%s/%s: unapproved #include %q", pkgPath, name, hdr)
		}
	}
	if condDepth != 0 {
		return fmt.Errorf("%s/%s: unterminated conditional directive", pkgPath, name)
	}

	cleaned := stripAssemblyComments(src, false, joinSpace)
	for _, line := range strings.Split(cleaned, "\n") {
		trimmedClean := strings.TrimSpace(line)
		isDirectiveLine := strings.HasPrefix(trimmedClean, "#")
		if strings.Contains(trimmedClean, "#") && (!isDirectiveLine || strings.Contains(trimmedClean[1:], "#")) {
			return fmt.Errorf("%s/%s: unexpected '#' in assembly", pkgPath, name)
		}
		scanLine := line
		var macroParams map[string]bool
		isObjectDefine := false
		if isDirectiveLine {
			dRest := strings.TrimSpace(trimmedClean[1:])
			if strings.HasPrefix(dRest, "define") && (len(dRest) == 6 || dRest[6] == ' ' || dRest[6] == '\t') {
				afterDef := strings.TrimSpace(dRest[6:])
				mEnd := 0
				for mEnd < len(afterDef) && isASCIIIdentByte(afterDef[mEnd]) {
					mEnd++
				}
				afterName := afterDef[mEnd:]
				if strings.HasPrefix(afterName, "(") {
					closeIdx := strings.IndexByte(afterName, ')')
					if closeIdx < 0 {
						return fmt.Errorf("%s/%s: malformed function-like #define", pkgPath, name)
					}
					macroParams = map[string]bool{}
					for _, p := range strings.Split(afterName[1:closeIdx], ",") {
						if p = strings.TrimSpace(p); p != "" {
							macroParams[p] = true
						}
					}
					scanLine = afterName[closeIdx+1:]
				} else {
					isObjectDefine = true
					scanLine = afterName
				}
			}
		}
		runes := []rune(scanLine)
		stmtWordIdx := 0
		prevWord := ""
		for i := 0; i < len(runes); {
			if runes[i] == ';' {
				stmtWordIdx = 0
				prevWord = ""
				i++
				continue
			}
			if !isAsmWordRune(runes[i]) {
				i++
				continue
			}
			start := i
			for i < len(runes) && isAsmWordRune(runes[i]) {
				i++
			}
			rawTok := string(runes[start:i])
			prevNonSpace := rune(0)
			for back := start - 1; back >= 0; back-- {
				if runes[back] != ' ' && runes[back] != '\t' && runes[back] != '\r' {
					prevNonSpace = runes[back]
					break
				}
			}
			if strings.ContainsRune(rawTok, '·') {
				if strings.HasSuffix(rawTok, "·") || strings.HasPrefix(rawTok, "/") || strings.HasPrefix(rawTok, "∕") ||
					prevNonSpace == '/' || prevNonSpace == '∕' || prevNonSpace == ')' ||
					strings.HasSuffix(prevWord, "/") || strings.HasSuffix(prevWord, "∕") {
					return fmt.Errorf("%s/%s: split middle-dot symbol %s", pkgPath, name, rawTok)
				}
				if (isObjectDefine || macroParams != nil) && strings.HasPrefix(rawTok, "·") && prevNonSpace == 0 {
					return fmt.Errorf("%s/%s: macro body starts with middle-dot symbol %s", pkgPath, name, rawTok)
				}
				if strings.HasPrefix(rawTok, "·") && isAsmWordRune(prevNonSpace) {
					prevHasLowerOrSlash := strings.ContainsAny(prevWord, "abcdefghijklmnopqrstuvwxyz/∕·")
					if stmtWordIdx != 1 || prevHasLowerOrSlash || definedMacros[prevWord] || macroParams[prevWord] {
						return fmt.Errorf("%s/%s: split package-qualified symbol %s %s", pkgPath, name, prevWord, rawTok)
					}
				}
				pkgPrefix, symPart, _ := strings.Cut(rawTok, "·")
				pkgPrefix = strings.ReplaceAll(pkgPrefix, "∕", "/")
				if pkgPrefix != "" {
					baseSym, _, _ := strings.Cut(symPart, "<")
					if definedMacros[pkgPrefix] || macroParams[pkgPrefix] || definedMacros[baseSym] || macroParams[baseSym] {
						return fmt.Errorf("%s/%s: macro-qualified assembly symbol %s", pkgPath, name, rawTok)
					}
					if pkgPrefix != pkgPath {
						return fmt.Errorf("%s/%s: cross-package assembly symbol %s", pkgPath, name, rawTok)
					}
				}
			}
			if isObjectDefine || macroParams != nil {
				switch rawTok {
				case "runtime", "syscall", "os", "internal":
					if !macroParams[rawTok] {
						return fmt.Errorf("%s/%s: forbidden package token %s in #define", pkgPath, name, rawTok)
					}
				}
			}
			stmtWordIdx++
			prevWord = rawTok
		}
	}
	return nil
}

type asmCondKind uint8

const (
	asmCondNone asmCondKind = iota
	asmCondIf
	asmCondElif
	asmCondElse
	asmCondEndif
)

type asmLogicalLine struct {
	choices   []string
	condDepth int
	condEpoch int
	condOp    asmCondKind
}

type asmTextBlock struct {
	name          string
	openCondDepth int
	labels        map[string]bool
	lines         []asmLogicalLine
}

type parsedNonStdAsmFile struct {
	lines          []asmLogicalLine
	fileRodataSyms map[string]bool
	rodataGoNames  []string
	blocks         []asmTextBlock
}

func parseSingleNonStdAsmFile(pkgPath, folded string, localHeaders map[string]string, typeScopes []*types.Package, pkgRodataSyms map[string]bool) (*parsedNonStdAsmFile, bool) {
	activeDefs := map[string][]cppMacroDef{}
	includeStack := map[string]bool{}
	condDepth := 0
	condEpoch := 0
	var logicalLines []asmLogicalLine

	emitLogicalLine := func(line string) bool {
		if len(activeDefs) == 0 {
			logicalLines = append(logicalLines, asmLogicalLine{
				choices:   []string{line},
				condDepth: condDepth,
				condEpoch: condEpoch,
			})
			return true
		}
		budget := &cppExpandBudget{statesLeft: maxCPPExpandedStatesPerLine}
		_, terminals := expandAsmCPPStatesWithBudget(line, activeDefs, "", "", 0, budget)
		if budget.overflow || len(terminals) == 0 {
			return false
		}
		logicalLines = append(logicalLines, asmLogicalLine{
			choices:   terminals,
			condDepth: condDepth,
			condEpoch: condEpoch,
		})
		return true
	}

	var walkUnit func(unitFolded string) bool
	walkUnit = func(unitFolded string) bool {
		rawLines := strings.Split(unitFolded, "\n")
		var pending string
		flushPending := func() bool {
			if pending == "" {
				return true
			}
			line := pending
			pending = ""
			return emitLogicalLine(line)
		}
		for idx := 0; idx < len(rawLines); idx++ {
			line := strings.TrimSpace(rawLines[idx])
			if line == "" {
				continue
			}
			if len(line) > maxNonGoLogicalLineBytes {
				return false
			}
			if strings.HasPrefix(line, "#") {
				if !flushPending() {
					return false
				}
				directive := strings.TrimSpace(line[1:])
				kwEnd := 0
				for kwEnd < len(directive) && ((directive[kwEnd] >= 'a' && directive[kwEnd] <= 'z') || (directive[kwEnd] >= 'A' && directive[kwEnd] <= 'Z') || directive[kwEnd] == '_') {
					kwEnd++
				}
				kw := directive[:kwEnd]
				switch kw {
				case "if", "ifdef", "ifndef":
					condDepth++
					condEpoch++
					logicalLines = append(logicalLines, asmLogicalLine{condDepth: condDepth, condEpoch: condEpoch, condOp: asmCondIf})
				case "elif":
					if condDepth <= 0 {
						return false
					}
					condEpoch++
					logicalLines = append(logicalLines, asmLogicalLine{condDepth: condDepth, condEpoch: condEpoch, condOp: asmCondElif})
				case "else":
					if condDepth <= 0 {
						return false
					}
					condEpoch++
					logicalLines = append(logicalLines, asmLogicalLine{condDepth: condDepth, condEpoch: condEpoch, condOp: asmCondElse})
				case "endif":
					if condDepth <= 0 {
						return false
					}
					condDepth--
					condEpoch++
					logicalLines = append(logicalLines, asmLogicalLine{condDepth: condDepth, condEpoch: condEpoch, condOp: asmCondEndif})
				case "include":
					hdr, err := strconv.Unquote(strings.TrimSpace(directive[kwEnd:]))
					if err != nil || hdr == "" {
						return false
					}
					if allowedPureAsmStandardHeaders[hdr] {
						continue
					}
					hdrFolded, ok := localHeaders[hdr]
					if !ok || includeStack[hdr] || len(includeStack) >= 16 {
						return false
					}
					includeStack[hdr] = true
					savedDepth := condDepth
					okHdr := walkUnit(hdrFolded)
					delete(includeStack, hdr)
					if !okHdr || condDepth != savedDepth {
						return false
					}
				case "define":
					tmp := map[string][]cppMacroDef{}
					collectCPPMacrosFromText(line, tmp)
					if len(tmp) != 1 {
						return false
					}
					for mName, dList := range tmp {
						if len(dList) != 1 {
							return false
						}
						def := dList[0]
						if condDepth == 0 {
							activeDefs[mName] = []cppMacroDef{def}
						} else if len(activeDefs[mName]) == 0 {
							activeDefs[mName] = []cppMacroDef{def}
							ensureMacroIdentityChoice(activeDefs, mName)
						} else {
							appendMacroDefUnique(activeDefs, mName, def)
						}
					}
				case "undef":
					rest := strings.TrimSpace(directive[kwEnd:])
					mEnd := 0
					for mEnd < len(rest) && isASCIIIdentByte(rest[mEnd]) && (mEnd > 0 || (rest[mEnd] < '0' || rest[mEnd] > '9')) {
						mEnd++
					}
					if mEnd == 0 || strings.TrimSpace(rest[mEnd:]) != "" {
						return false
					}
					mName := rest[:mEnd]
					if condDepth == 0 {
						delete(activeDefs, mName)
					} else if len(activeDefs[mName]) > 0 {
						ensureMacroIdentityChoice(activeDefs, mName)
					}
				default:
					return false
				}
				continue
			}
			if pending == "" {
				pending = line
			} else if len(pending)+1+len(line) <= maxNonGoLogicalLineBytes {
				pending = pending + " " + line
			} else {
				return false
			}
			if unquotedParenBalance(pending) > 0 {
				continue
			}
			if trailingAsmFuncMacroIdent(pending, activeDefs) {
				peek := idx + 1
				for peek < len(rawLines) && strings.TrimSpace(rawLines[peek]) == "" {
					peek++
				}
				if peek < len(rawLines) && strings.HasPrefix(strings.TrimSpace(rawLines[peek]), "(") {
					continue
				}
			}
			if !flushPending() {
				return false
			}
		}
		return flushPending()
	}

	if !walkUnit(folded) || condDepth != 0 {
		return nil, false
	}

	// Pass 1: collect and validate RODATA GLOBL symbols and per-TEXT local labels.
	fileRodataSyms := map[string]bool{}
	var rodataGoNames []string
	var blocks []asmTextBlock
	curBlock := -1

	for _, line := range logicalLines {
		if line.condOp != asmCondNone {
			if curBlock >= 0 {
				openDepth := blocks[curBlock].openCondDepth
				if (line.condOp == asmCondEndif && line.condDepth < openDepth) ||
					((line.condOp == asmCondElif || line.condOp == asmCondElse) && line.condDepth == openDepth) {
					curBlock = -1
				} else {
					blocks[curBlock].lines = append(blocks[curBlock].lines, line)
				}
			}
			continue
		}
		nextBlock := curBlock
		for choiceIdx, expanded := range line.choices {
			choiceCur := curBlock
			stmts := splitAsmStatements(expanded)
			for _, stmt := range stmts {
				stmt = strings.TrimSpace(stmt)
				if stmt == "" {
					continue
				}
				for {
					lbl, rest, ok := cutAsmLabel(stmt)
					if !ok {
						break
					}
					if choiceCur < 0 {
						return nil, false
					}
					blocks[choiceCur].labels[lbl] = true
					stmt = strings.TrimSpace(rest)
				}
				if stmt == "" {
					continue
				}
				op, rest := splitAsmOp(stmt)
				switch strings.ToUpper(op) {
				case "GLOBL":
					if choiceCur >= 0 && line.condDepth > blocks[choiceCur].openCondDepth {
						return nil, false
					}
					choiceCur = -1
					sym, goName, ok := parseAsmGloblRODATA(pkgPath, rest, typeScopes)
					if !ok {
						return nil, false
					}
					if goName != "" {
						rodataGoNames = append(rodataGoNames, goName)
					}
					if strings.HasPrefix(sym, "<>") {
						fileRodataSyms[sym] = true
					} else {
						pkgRodataSyms[sym] = true
					}
				case "DATA":
					if choiceCur >= 0 && line.condDepth > blocks[choiceCur].openCondDepth {
						return nil, false
					}
					choiceCur = -1
				case "TEXT":
					if choiceCur >= 0 && line.condDepth > blocks[choiceCur].openCondDepth {
						return nil, false
					}
					fnName, ok := parseAsmTextHeader(pkgPath, rest)
					if !ok {
						return nil, false
					}
					if choiceIdx == 0 {
						blocks = append(blocks, asmTextBlock{
							name:          fnName,
							openCondDepth: line.condDepth,
							labels:        map[string]bool{},
						})
						choiceCur = len(blocks) - 1
					} else if nextBlock < 0 || blocks[nextBlock].name != fnName {
						return nil, false
					} else {
						choiceCur = nextBlock
					}
				default:
					if choiceCur < 0 {
						uop := strings.ToUpper(op)
						if (uop != "FUNCDATA" && uop != "PCDATA" && uop != "PCALIGN" && uop != "PCALIGNMAX") ||
							hasUnquotedColon(rest) || hasForbiddenAsmToken(rest) || hasAsmPCToken(rest) {
							return nil, false
						}
					}
				}
			}
			if choiceIdx == 0 {
				nextBlock = choiceCur
			} else if choiceCur != nextBlock {
				return nil, false
			}
		}
		curBlock = nextBlock
		if curBlock >= 0 {
			blocks[curBlock].lines = append(blocks[curBlock].lines, line)
		}
	}

	return &parsedNonStdAsmFile{
		lines:          logicalLines,
		fileRodataSyms: fileRodataSyms,
		rodataGoNames:  rodataGoNames,
		blocks:         blocks,
	}, true
}

func verifyParsedNonStdAsmFile(goarch, pkgPath string, parsed *parsedNonStdAsmFile, pkgRodataSyms map[string]bool, funcs map[string]asmTextSummary) bool {
	if parsed == nil || (goarch != "amd64" && goarch != "arm64") {
		return false
	}
	rodataSyms := make(map[string]bool, len(pkgRodataSyms)+len(parsed.fileRodataSyms))
	for k := range pkgRodataSyms {
		rodataSyms[k] = true
	}
	for k := range parsed.fileRodataSyms {
		rodataSyms[k] = true
	}

	// Validate all top-level DATA directives against rodataSyms.
	for _, line := range parsed.lines {
		if line.condOp != asmCondNone {
			continue
		}
		for _, expanded := range line.choices {
			for _, stmt := range splitAsmStatements(expanded) {
				stmt = strings.TrimSpace(stmt)
				for {
					_, rest, ok := cutAsmLabel(stmt)
					if !ok {
						break
					}
					stmt = strings.TrimSpace(rest)
				}
				op, rest := splitAsmOp(stmt)
				if strings.EqualFold(op, "DATA") {
					if !validateAsmDataDirective(pkgPath, rest, rodataSyms) {
						return false
					}
				}
			}
		}
	}

	// Pass 2: verify every TEXT block's control flow, (SB) references, and instructions.
	for _, blk := range parsed.blocks {
		if rodataSyms["·"+blk.name] || rodataSyms[blk.name] {
			return false
		}
		if goarch == "amd64" && !verifyAMD64EntryR14NotRead(blk) {
			return false
		}
		sum := funcs[blk.name]
		sawCPUID := false
		var pendingBytes []byte
		lastByteEpoch := -1
		flushBytes := func() {
			if len(pendingBytes) == 0 {
				return
			}
			if !(goarch == "amd64" && len(pendingBytes) == 3 && pendingBytes[0] == 0x0f && pendingBytes[1] == 0x01 && pendingBytes[2] == 0xd0) {
				if sum.impureKind == "" {
					sum.impureKind = "unverified raw opcode in assembly"
				}
			}
			pendingBytes = pendingBytes[:0]
			lastByteEpoch = -1
		}
		for _, line := range blk.lines {
			if line.condOp != asmCondNone {
				flushBytes()
				continue
			}
			if len(pendingBytes) > 0 && line.condEpoch != lastByteEpoch {
				flushBytes()
			}
			for _, expanded := range line.choices {
				for _, stmt := range splitAsmStatements(expanded) {
					stmt = strings.TrimSpace(stmt)
					if stmt == "" {
						continue
					}
					for {
						_, rest, ok := cutAsmLabel(stmt)
						if !ok {
							break
						}
						flushBytes()
						stmt = strings.TrimSpace(rest)
					}
					if stmt == "" {
						continue
					}
					op, rest := splitAsmOp(stmt)
					uop := strings.ToUpper(op)
					if uop == "TEXT" {
						flushBytes()
						continue
					}
					if uop == "BYTE" {
						if goarch != "amd64" || line.condDepth != blk.openCondDepth || len(line.choices) != 1 {
							flushBytes()
							if sum.impureKind == "" {
								sum.impureKind = "unverified raw opcode in assembly"
							}
							continue
						}
						b, ok := parseAsmImmByte(rest)
						if !ok {
							if sum.impureKind == "" {
								sum.impureKind = "unverified raw opcode in assembly"
							}
							pendingBytes = pendingBytes[:0]
							lastByteEpoch = -1
						} else {
							pendingBytes = append(pendingBytes, b)
							lastByteEpoch = line.condEpoch
						}
						continue
					}
					flushBytes()
					ok, cpuid, impure := verifyAsmTextInstruction(goarch, pkgPath, uop, rest, blk.labels, rodataSyms)
					if !ok {
						return false
					}
					if cpuid {
						sawCPUID = true
					}
					if impure != "" && sum.impureKind == "" {
						sum.impureKind = impure
					}
				}
			}
		}
		flushBytes()
		if sum.impureKind != "" {
			sum.cpuidArgs = 0
		} else if sawCPUID {
			argCount, okCanonical := verifyCanonicalCPUIDTextBlock(blk)
			if !okCanonical || (sum.cpuidArgs != 0 && sum.cpuidArgs != argCount) {
				sum.cpuidArgs = 0
				sum.impureKind = "per-core CPUID register"
			} else {
				sum.cpuidArgs = argCount
			}
		}
		funcs[blk.name] = sum
	}
	return true
}

func parseAsmFrameSlotOffset(opnd string) (int, bool) {
	opnd = strings.TrimSpace(opnd)
	if !strings.HasSuffix(opnd, "(FP)") {
		return 0, false
	}
	head := strings.TrimSuffix(opnd, "(FP)")
	plus := strings.LastIndexByte(head, '+')
	if plus <= 0 {
		return 0, false
	}
	ident := head[:plus]
	for i := 0; i < len(ident); i++ {
		if !isASCIIIdentByte(ident[i]) || (i == 0 && ident[i] >= '0' && ident[i] <= '9') {
			return 0, false
		}
	}
	off, err := strconv.Atoi(head[plus+1:])
	if err != nil || off < 0 {
		return 0, false
	}
	return off, true
}

func verifyCanonicalCPUIDTextBlock(blk asmTextBlock) (int, bool) {
	if len(blk.labels) != 0 || len(blk.lines) == 0 {
		return 0, false
	}
	phase := 0 // 0 = pre-CPUID, 1 = post-CPUID, 2 = post-RET
	loadedAX := false
	cxMode := 0 // 0 = unset, 1 = zeroed (1-arg), 2 = loaded +4(FP) (2-arg)
	var storeOff [4]int
	storedMask := 0
	seenText := false

	for _, line := range blk.lines {
		if line.condOp != asmCondNone || line.condDepth != blk.openCondDepth || len(line.choices) != 1 {
			return 0, false
		}
		for _, stmt := range splitAsmStatements(line.choices[0]) {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, _, hasLbl := cutAsmLabel(stmt); hasLbl {
				return 0, false
			}
			op, rest := splitAsmOp(stmt)
			uop := strings.ToUpper(op)
			if uop == "TEXT" {
				if seenText || phase != 0 {
					return 0, false
				}
				seenText = true
				continue
			}
			switch phase {
			case 0:
				if uop == "CPUID" && rest == "" {
					if !loadedAX || (cxMode != 1 && cxMode != 2) {
						return 0, false
					}
					phase = 1
					continue
				}
				operands := splitAsmOperands(rest)
				if len(operands) != 2 {
					return 0, false
				}
				src := strings.TrimSpace(operands[0])
				dst := strings.ToUpper(strings.TrimSpace(operands[1]))
				switch uop {
				case "MOVL":
					if dst == "AX" {
						off, ok := parseAsmFrameSlotOffset(src)
						if !ok || off != 0 || loadedAX {
							return 0, false
						}
						loadedAX = true
						continue
					}
					if dst == "CX" {
						if src == "$0" {
							if cxMode != 0 {
								return 0, false
							}
							cxMode = 1
							continue
						}
						off, ok := parseAsmFrameSlotOffset(src)
						if !ok || off != 4 || cxMode != 0 {
							return 0, false
						}
						cxMode = 2
						continue
					}
				case "MOVQ":
					if dst == "CX" && src == "$0" && cxMode == 0 {
						cxMode = 1
						continue
					}
				case "XORL", "XORQ":
					if strings.EqualFold(src, "CX") && dst == "CX" && cxMode == 0 {
						cxMode = 1
						continue
					}
				}
				return 0, false
			case 1:
				if uop == "RET" && rest == "" {
					phase = 2
					continue
				}
				if uop != "MOVL" {
					return 0, false
				}
				operands := splitAsmOperands(rest)
				if len(operands) != 2 {
					return 0, false
				}
				src := strings.ToUpper(strings.TrimSpace(operands[0]))
				off, ok := parseAsmFrameSlotOffset(operands[1])
				if !ok {
					return 0, false
				}
				regIdx := -1
				switch src {
				case "AX":
					regIdx = 0
				case "BX":
					regIdx = 1
				case "CX":
					regIdx = 2
				case "DX":
					regIdx = 3
				default:
					return 0, false
				}
				if storedMask&(1<<regIdx) != 0 {
					return 0, false
				}
				storedMask |= 1 << regIdx
				storeOff[regIdx] = off
			default:
				return 0, false
			}
		}
	}
	if phase != 2 || storedMask != 0x0f {
		return 0, false
	}
	retBase := storeOff[0]
	if retBase != 8 || storeOff[1] != retBase+4 || storeOff[2] != retBase+8 || storeOff[3] != retBase+12 {
		return 0, false
	}
	if cxMode == 1 {
		return 1, true
	}
	if cxMode == 2 {
		return 2, true
	}
	return 0, false
}

func splitAsmStatements(line string) []string {
	if !strings.ContainsRune(line, ';') {
		return []string{line}
	}
	if !strings.ContainsAny(line, `"'`) {
		return strings.Split(line, ";")
	}
	var out []string
	start := 0
	for i := 0; i < len(line); i++ {
		if line[i] == '"' || line[i] == '\'' {
			q := line[i]
			i++
			for i < len(line) && line[i] != q {
				if line[i] == '\\' && i+1 < len(line) {
					i += 2
					continue
				}
				i++
			}
			continue
		}
		if line[i] == ';' {
			out = append(out, line[start:i])
			start = i + 1
		}
	}
	out = append(out, line[start:])
	return out
}

func cutAsmLabel(stmt string) (string, string, bool) {
	if stmt == "" {
		return "", "", false
	}
	i := 0
	for i < len(stmt) && isASCIIIdentByte(stmt[i]) && (i > 0 || (stmt[i] < '0' || stmt[i] > '9')) {
		i++
	}
	if i == 0 || i >= len(stmt) || stmt[i] != ':' {
		return "", "", false
	}
	return stmt[:i], stmt[i+1:], true
}

func splitAsmOp(stmt string) (string, string) {
	i := 0
	for i < len(stmt) && stmt[i] != ' ' && stmt[i] != '\t' && stmt[i] != ',' {
		i++
	}
	return stmt[:i], strings.TrimSpace(stmt[i:])
}

const maxConstAsmUintOffset = uint64(0x3fffffff)

// evalConstAsmUintExpr evaluates a pure non-negative constant integer arithmetic
// expression using '+', '*', '|', '<<', '>>', and parentheses without overflow
// above maxConstAsmUintOffset. Identifiers, registers, '-', '/', '^', and
// symbol references are rejected.
func evalConstAsmUintExpr(expr string) (uint64, bool) {
	s := strings.TrimSpace(expr)
	if s == "" {
		return 0, false
	}
	pos := 0
	var parseExpr func() (uint64, bool)
	parseAtom := func() (uint64, bool) {
		for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
			pos++
		}
		if pos >= len(s) {
			return 0, false
		}
		if s[pos] == '(' {
			pos++
			v, ok := parseExpr()
			if !ok {
				return 0, false
			}
			for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
				pos++
			}
			if pos >= len(s) || s[pos] != ')' {
				return 0, false
			}
			pos++
			return v, true
		}
		if s[pos] < '0' || s[pos] > '9' {
			return 0, false
		}
		start := pos
		for pos < len(s) && isASCIIIdentByte(s[pos]) {
			pos++
		}
		v, err := strconv.ParseUint(s[start:pos], 0, 64)
		if err != nil || v > maxConstAsmUintOffset {
			return 0, false
		}
		return v, true
	}
	parseExpr = func() (uint64, bool) {
		acc, ok := parseAtom()
		if !ok {
			return 0, false
		}
		for {
			for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
				pos++
			}
			if pos >= len(s) || s[pos] == ')' {
				return acc, true
			}
			op := ""
			switch {
			case strings.HasPrefix(s[pos:], "<<"):
				op = "<<"
				pos += 2
			case strings.HasPrefix(s[pos:], ">>"):
				op = ">>"
				pos += 2
			case s[pos] == '+' || s[pos] == '*' || s[pos] == '|':
				op = s[pos : pos+1]
				pos++
			default:
				return 0, false
			}
			rhs, rok := parseAtom()
			if !rok {
				return 0, false
			}
			switch op {
			case "+":
				if acc+rhs < acc || acc+rhs > maxConstAsmUintOffset {
					return 0, false
				}
				acc += rhs
			case "*":
				if rhs != 0 && acc > maxConstAsmUintOffset/rhs {
					return 0, false
				}
				acc *= rhs
			case "|":
				acc |= rhs
				if acc > maxConstAsmUintOffset {
					return 0, false
				}
			case "<<":
				if rhs >= 30 || (acc<<rhs) > maxConstAsmUintOffset {
					return 0, false
				}
				acc <<= rhs
			case ">>":
				if rhs >= 64 {
					acc = 0
				} else {
					acc >>= rhs
				}
			}
		}
	}
	val, ok := parseExpr()
	if !ok || pos != len(s) || val > maxConstAsmUintOffset {
		return 0, false
	}
	return val, true
}

func isValidAsmGoSymbolIdent(s string) bool {
	if s == "" {
		return false
	}
	for idx, r := range s {
		if r == '_' || unicode.IsLetter(r) || (idx > 0 && unicode.IsDigit(r)) {
			continue
		}
		return false
	}
	return true
}

func parseAsmLocalSBRef(pkgPath, rawSym string) (normSym string, hasOffset bool, goName string, ok bool) {
	rawSym = strings.TrimSpace(rawSym)
	rawSym = strings.TrimSpace(strings.TrimPrefix(rawSym, "$"))
	if rawSym == "" {
		return "", false, "", false
	}
	if pkgPrefix, symAndOff, hasDot := strings.Cut(rawSym, "·"); hasDot {
		if strings.ContainsAny(pkgPrefix, " \t+<>()*") {
			return "", false, "", false
		}
		pkgPrefix = strings.ReplaceAll(pkgPrefix, "∕", "/")
		if pkgPrefix != "" && pkgPrefix != pkgPath {
			return "", false, "", false
		}
		if strings.ContainsRune(symAndOff, '-') {
			return "", false, "", false
		}
		symPart, offExpr, hasPlus := strings.Cut(symAndOff, "+")
		if hasPlus {
			if _, offOK := evalConstAsmUintExpr(offExpr); !offOK {
				return "", false, "", false
			}
		}
		symPart = strings.TrimSpace(symPart)
		baseSym, abiPart, hasABI := strings.Cut(symPart, "<")
		if hasABI && abiPart != "ABI0>" {
			return "", false, "", false
		}
		if !isValidAsmGoSymbolIdent(baseSym) {
			return "", false, "", false
		}
		return "·" + baseSym, hasPlus, baseSym, true
	}
	if strings.ContainsRune(rawSym, '-') {
		return "", false, "", false
	}
	symPart, offExpr, hasPlus := strings.Cut(rawSym, "+")
	if hasPlus {
		if _, offOK := evalConstAsmUintExpr(offExpr); !offOK {
			return "", false, "", false
		}
	}
	symPart = strings.TrimSpace(symPart)
	base, isStatic := strings.CutSuffix(symPart, "<>")
	if !isStatic || !isValidAsmGoSymbolIdent(base) {
		return "", false, "", false
	}
	return "<>" + base, hasPlus, "", true
}

func normalizeAsmLocalSBSym(pkgPath, rawSym string) (string, string, bool) {
	normSym, _, goName, ok := parseAsmLocalSBRef(pkgPath, rawSym)
	return normSym, goName, ok
}

func parseAsmGloblRODATA(pkgPath, rest string, typeScopes []*types.Package) (string, string, bool) {
	if hasUnquotedColon(rest) || hasForbiddenAsmToken(rest) || hasAsmPCToken(rest) {
		return "", "", false
	}
	operands := splitAsmOperands(rest)
	if len(operands) != 3 {
		return "", "", false
	}
	symOp := strings.TrimSpace(operands[0])
	if strings.HasPrefix(symOp, "$") || !strings.HasSuffix(symOp, "(SB)") {
		return "", "", false
	}
	normSym, hasOffset, goName, ok := parseAsmLocalSBRef(pkgPath, strings.TrimSuffix(symOp, "(SB)"))
	if !ok || hasOffset {
		return "", "", false
	}
	if goName == "init" || strings.HasPrefix(goName, "init·") || strings.HasPrefix(goName, "init.") ||
		strings.ContainsRune(goName, '·') || strings.ContainsAny(goName, "()*") {
		return "", "", false
	}
	if goName != "" {
		for _, tp := range typeScopes {
			if tp == nil || tp.Scope() == nil || tp.Scope().Lookup(goName) != nil {
				return "", "", false
			}
		}
	}
	flagsExpr := strings.TrimSpace(operands[1])
	if !asmFlagsIncludeRODATA(flagsExpr) {
		return "", "", false
	}
	sizeOp := strings.TrimSpace(operands[2])
	if !strings.HasPrefix(sizeOp, "$") || strings.Contains(sizeOp, "(SB)") || strings.Contains(sizeOp, "(TLS)") || strings.ContainsRune(sizeOp, '·') {
		return "", "", false
	}
	sizeVal, sizeOK := evalConstAsmUintExpr(strings.TrimSpace(sizeOp[1:]))
	if !sizeOK || sizeVal == 0 {
		return "", "", false
	}
	return normSym, goName, true
}

// asmFlagsIncludeRODATA evaluates a Plan 9 GLOBL flag expression fail-closed:
// only bitwise-OR ('|') or disjoint-bit '+' combinations of RODATA (8),
// NOPTR (16), DUPOK (2), and NOPROF (1) (or equivalent non-negative integer
// literals) are admitted, and the resulting mask must set RODATA (8) without
// any unknown or TLSBSS bits. Any other operator ('-', '^', '&', '~', '<<',
// '>>', '*', '/'), unknown identifier, or overlapping '+' carry is rejected.
func asmFlagsIncludeRODATA(expr string) bool {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(expr), "$"))
	if s == "" {
		return false
	}
	const allowedBits = uint64(1 | 2 | 8 | 16) // NOPROF | DUPOK | RODATA | NOPTR
	pos := 0
	var parseExpr func() (uint64, bool)
	parseAtom := func() (uint64, bool) {
		for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
			pos++
		}
		if pos >= len(s) {
			return 0, false
		}
		if s[pos] == '$' {
			pos++
			for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
				pos++
			}
		}
		if pos < len(s) && s[pos] == '(' {
			pos++
			v, ok := parseExpr()
			if !ok {
				return 0, false
			}
			for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
				pos++
			}
			if pos >= len(s) || s[pos] != ')' {
				return 0, false
			}
			pos++
			return v, true
		}
		start := pos
		for pos < len(s) && isASCIIIdentByte(s[pos]) {
			pos++
		}
		tok := s[start:pos]
		if tok == "" {
			return 0, false
		}
		switch tok {
		case "RODATA":
			return 8, true
		case "NOPTR":
			return 16, true
		case "DUPOK":
			return 2, true
		case "NOPROF":
			return 1, true
		}
		v, err := strconv.ParseUint(tok, 0, 64)
		if err != nil || v&^allowedBits != 0 {
			return 0, false
		}
		return v, true
	}
	parseExpr = func() (uint64, bool) {
		acc, ok := parseAtom()
		if !ok {
			return 0, false
		}
		for {
			for pos < len(s) && (s[pos] == ' ' || s[pos] == '\t') {
				pos++
			}
			if pos >= len(s) || s[pos] == ')' {
				return acc, true
			}
			op := s[pos]
			if op != '|' && op != '+' {
				return 0, false
			}
			pos++
			rhs, rok := parseAtom()
			if !rok {
				return 0, false
			}
			if op == '+' && (acc&rhs) != 0 {
				return 0, false
			}
			acc |= rhs
		}
	}
	mask, ok := parseExpr()
	if !ok || pos != len(s) {
		return false
	}
	return (mask&8) != 0 && (mask&^allowedBits) == 0
}

func validateAsmDataDirective(pkgPath, rest string, rodataSyms map[string]bool) bool {
	if hasUnquotedColon(rest) || hasForbiddenAsmToken(rest) || hasAsmPCToken(rest) {
		return false
	}
	operands := splitAsmOperands(rest)
	if len(operands) != 2 {
		return false
	}
	lhs := strings.TrimSpace(operands[0])
	rhs := strings.TrimSpace(operands[1])
	slashIdx := strings.LastIndexByte(lhs, '/')
	if slashIdx <= 0 {
		return false
	}
	target := strings.TrimSpace(lhs[:slashIdx])
	widthStr := strings.TrimSpace(lhs[slashIdx+1:])
	width, wErr := strconv.ParseUint(widthStr, 0, 64)
	if wErr != nil || (width != 1 && width != 2 && width != 4 && width != 8) {
		return false
	}
	if strings.HasPrefix(target, "$") || !strings.HasSuffix(target, "(SB)") {
		return false
	}
	normSym, _, _, ok := parseAsmLocalSBRef(pkgPath, strings.TrimSuffix(target, "(SB)"))
	if !ok || !rodataSyms[normSym] {
		return false
	}
	unquotedRHS := stripAsmQuotedLiterals(rhs)
	if !strings.HasPrefix(rhs, "$") || strings.TrimSpace(rhs[1:]) == "" ||
		strings.Contains(unquotedRHS, "(SB)") || strings.Contains(unquotedRHS, "(TLS)") || strings.ContainsRune(unquotedRHS, '·') {
		return false
	}
	return true
}

func stripAsmQuotedLiterals(s string) string {
	if !strings.ContainsAny(s, `"'`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			b.WriteByte(q)
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				i++
			}
			if i < len(s) {
				b.WriteByte(q)
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func parseAsmTextHeader(pkgPath, rest string) (string, bool) {
	if hasUnquotedColon(rest) || hasForbiddenAsmToken(rest) || hasAsmPCToken(rest) {
		return "", false
	}
	operands := splitAsmOperands(rest)
	if len(operands) < 2 || len(operands) > 3 {
		return "", false
	}
	symOp := strings.TrimSpace(operands[0])
	if strings.HasPrefix(symOp, "$") || !strings.HasSuffix(symOp, "(SB)") {
		return "", false
	}
	normSym, hasOffset, goName, ok := parseAsmLocalSBRef(pkgPath, strings.TrimSuffix(symOp, "(SB)"))
	if !ok || hasOffset {
		return "", false
	}
	if goName == "init" || strings.HasPrefix(goName, "init·") || strings.HasPrefix(goName, "init.") ||
		strings.ContainsRune(goName, '·') || strings.ContainsAny(goName, "()*") {
		return "", false
	}
	if goName != "" {
		return goName, true
	}
	return normSym, true
}

func splitAsmOperands(rest string) []string {
	if rest == "" {
		return nil
	}
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(rest); i++ {
		if rest[i] == '"' || rest[i] == '\'' {
			q := rest[i]
			i++
			for i < len(rest) && rest[i] != q {
				if rest[i] == '\\' && i+1 < len(rest) {
					i += 2
					continue
				}
				i++
			}
			continue
		}
		switch rest[i] {
		case '(', '[':
			depth++
		case ')', ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(rest[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(rest[start:]))
	return out
}

func isValidAsmMnemonic(uop string) bool {
	if uop == "" || uop[0] < 'A' || uop[0] > 'Z' {
		return false
	}
	for i := 1; i < len(uop); i++ {
		c := uop[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func isFrameSlotIdentBeforePlusFP(s string, start, end int) bool {
	if start > 0 && s[start-1] != ' ' && s[start-1] != '\t' && s[start-1] != ',' && s[start-1] != '$' {
		return false
	}
	if end >= len(s) || s[end] != '+' {
		return false
	}
	p := end + 1
	digits := 0
	for p < len(s) && s[p] >= '0' && s[p] <= '9' {
		p++
		digits++
	}
	return digits > 0 && strings.HasPrefix(s[p:], "(FP)")
}

// hasUnquotedColon reports whether s contains any ':' character outside single
// or double quotes. In Plan 9 cmd/asm (parse.go:operand), an unquoted 'X:Y'
// operand pair at nesting depth 0 splits into two reversed operands '[Y, X]'
// (e.g. 'MOVD R0:CNTVCT_EL0' assembles as 'MOVD CNTVCT_EL0, R0').
func hasUnquotedColon(s string) bool {
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				i++
			}
			if i >= len(s) {
				return true
			}
			i++
			continue
		}
		if s[i] == ':' {
			return true
		}
		i++
	}
	return false
}

// hasAsmPCToken reports whether s contains the PC pseudo-register token
// (excluding a lowercase stack-slot label `pc+<digits>(FP)` or middle-dot
// RODATA symbol `·pc(SB)`). Non-branch PC-relative addressing (`LEAQ 0(PC), AX`,
// `MOVQ 0x1000(PC), AX`, `ADR 0(PC), R0`) can read arbitrary link-address or
// adjacent-section bytes without naming `(SB)`.
func hasAsmPCToken(s string) bool {
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				i++
			}
			if i >= len(s) {
				return true
			}
			i++
			continue
		}
		end, okIdent := scanIdentToken(s, i, true)
		if okIdent && end > i {
			start := i
			i = end
			tok := s[start:end]
			if strings.EqualFold(tok, "PC") && !(tok == "pc" && isFrameSlotIdentBeforePlusFP(s, start, end)) {
				return true
			}
			continue
		}
		i++
	}
	return false
}

// stmtContainsARM64SysReg reports whether s references any ARM64 system
// register or PSTATE field token (excluding lowercase `<ident>+<digits>(FP)`
// frame-slot labels and middle-dot `(SB)` symbols).
func stmtContainsARM64SysReg(s string) bool {
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				i++
			}
			if i >= len(s) {
				return true
			}
			i++
			continue
		}
		end, okIdent := scanIdentToken(s, i, true)
		if okIdent && end > i {
			start := i
			i = end
			tok := s[start:end]
			if strings.ContainsRune(tok, '·') || (tok == strings.ToLower(tok) && isFrameSlotIdentBeforePlusFP(s, start, end)) {
				continue
			}
			if isARM64SystemOrPStateReg(strings.ToUpper(tok)) {
				return true
			}
			continue
		}
		i++
	}
	return false
}

func isCleanARM64SysRegDestGPR(opnd string) bool {
	s := strings.TrimSpace(opnd)
	if s == "LR" {
		return true
	}
	if len(s) < 2 || len(s) > 3 || s[0] != 'R' {
		return false
	}
	n, err := strconv.Atoi(s[1:])
	if err != nil || strconv.Itoa(n) != s[1:] {
		return false
	}
	return n >= 0 && n <= 30 && n != 18 && n != 28
}

// hasForbiddenAsmToken rejects TLS references (spaced, unspaced, bare, or
// ARM64 `TPIDR*`/`SCXTNUM*` TLS system registers), non-canonical SB
// pseudo-register spellings (such as spaced `( SB )` or `sym (SB)`),
// parameterized register forms (`R(28)`, `SPR(...)`, `SREG(...)`, `PN(...)`),
// x86 segment/control/debug/descriptor registers (`FS`, `GS`, `CS`, `SS`, `DS`,
// `ES`, `CR0`-`CR15`, `DR0`-`DR15`, `TR0`-`TR7`, `GDTR`, `IDTR`, `LDTR`, `MSW`,
// `TASK`, `MAXREG`), ARM64 platform/goroutine registers (`R18`, `R18_PLATFORM`,
// `R28`), `IP`, and Go goroutine-pointer register `g` unless it is a lowercase
// stack-slot label `<ident>+<digits>(FP)`. Scanning uses asmIdentMode so
// middle-dot RODATA symbols (`·g(SB)`) scan as a single symbol token.
func hasForbiddenAsmToken(s string) bool {
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				i++
			}
			if i >= len(s) {
				return true
			}
			i++
			continue
		}
		end, okIdent := scanIdentToken(s, i, true)
		if okIdent && end > i {
			start := i
			i = end
			tok := s[start:end]
			u := strings.ToUpper(tok)
			if u == "TLS" {
				return true
			}
			if u == "SB" {
				if tok != "SB" || start < 2 || s[start-1] != '(' || s[start-2] == ' ' || s[start-2] == '\t' || end >= len(s) || s[end] != ')' {
					return true
				}
				continue
			}
			switch u {
			case "R", "F", "V", "Z", "P", "M", "SPR", "SREG", "PN":
				p := end
				for p < len(s) && (s[p] == ' ' || s[p] == '\t') {
					p++
				}
				if p < len(s) && s[p] == '(' {
					return true
				}
			}
			isLowerFrameSlot := tok == strings.ToLower(tok) && isFrameSlotIdentBeforePlusFP(s, start, end)
			if tok == "g" && !isLowerFrameSlot {
				return true
			}
			if !isLowerFrameSlot {
				switch u {
				case "R28", "R18", "R18_PLATFORM", "IP", "MAXREG",
					"FS", "GS", "CS", "SS", "DS", "ES",
					"GDTR", "IDTR", "LDTR", "MSW", "TASK":
					return true
				}
				if isForbiddenX86ControlOrDebugReg(u) || isARM64TLSSysReg(u) {
					return true
				}
			}
			continue
		}
		i++
	}
	return false
}

func isImpureOrSystemAsmMnemonic(goarch, baseOp string) bool {
	if strings.HasPrefix(baseOp, "RDRAND") ||
		strings.HasPrefix(baseOp, "RDSEED") ||
		strings.HasPrefix(baseOp, "RDFSBASE") ||
		strings.HasPrefix(baseOp, "RDGSBASE") ||
		strings.HasPrefix(baseOp, "WRFSBASE") ||
		strings.HasPrefix(baseOp, "WRGSBASE") ||
		strings.HasPrefix(baseOp, "FXRSTOR") ||
		strings.HasPrefix(baseOp, "XRSTOR") ||
		strings.HasPrefix(baseOp, "POPF") ||
		strings.HasPrefix(baseOp, "PUSHF") {
		return true
	}
	switch baseOp {
	case "GETCALLERPC", "UNDEF",
		"SYSCALL", "SYSENTER", "SYSENTER64", "SYSEXIT", "SYSEXIT64", "SYSRET", "SYSRET64",
		"SVC", "ECALL", "SCALL", "SWI", "INT", "INT1", "INT3", "INTO", "ICEBP", "TA",
		"RDTSC", "RDTSCP", "RDPMC", "RDTIME", "RDCYCLE", "RDINSTRET",
		"MSR", "LDMXCSR", "VLDMXCSR", "FLDCW", "FLDENV", "FRSTOR", "FINIT", "FNINIT", "XSETBV", "STD",
		"WRPKRU", "RDPKRU", "WRMSR", "RDMSR", "RDPID",
		"SGDT", "SIDT", "LGDT", "LIDT", "LLDT", "LTR", "LMSW", "CLTS", "INVD", "WBINVD", "INVLPG", "INVPCID", "SWAPGS",
		"XBEGIN", "XEND", "XABORT", "XTEST",
		"TPAUSE", "UMWAIT", "MWAIT", "MONITOR", "MWAITX", "MONITORX",
		"UD0", "UD1", "UD2", "BRK", "HVC", "SMC", "HLT",
		"INB", "INW", "INL", "OUTB", "OUTW", "OUTL",
		"INSB", "INSW", "INSL", "OUTSB", "OUTSW", "OUTSL":
		return true
	}
	if goarch == "amd64" {
		if strings.HasPrefix(baseOp, "SMSW") ||
			strings.HasPrefix(baseOp, "SLDT") ||
			strings.HasPrefix(baseOp, "LAR") ||
			strings.HasPrefix(baseOp, "LSL") {
			return true
		}
		switch baseOp {
		case "STR", "STRW", "STRL", "STRQ", "VERR", "VERW",
			"LFS", "LFSW", "LFSL", "LFSQ",
			"LGS", "LGSW", "LGSL", "LGSQ",
			"LSS", "LSSW", "LSSL", "LSSQ",
			"LDS", "LDSW", "LDSL", "LDSQ",
			"LES", "LESW", "LESL", "LESQ":
			return true
		}
	}
	if goarch == "arm64" {
		switch baseOp {
		case "SYS", "SYSL", "DC", "IC", "AT", "TLBI", "HINT", "SEV", "SEVL",
			"DCPS1", "DCPS2", "DCPS3", "DRPS", "ERET", "WFI", "WFE":
			return true
		}
	}
	return false
}

func verifyAsmTextInstruction(goarch, pkgPath, uop, rest string, localLabels, rodataSyms map[string]bool) (ok bool, cpuid bool, impure string) {
	if (goarch != "amd64" && goarch != "arm64") || !isValidAsmMnemonic(uop) || hasUnquotedColon(rest) || hasForbiddenAsmToken(uop) || hasForbiddenAsmToken(rest) {
		return false, false, ""
	}
	unquotedRest := stripAsmQuotedLiterals(rest)
	if strings.Contains(unquotedRest, "(TLS)") || strings.Contains(uop, "(TLS)") {
		return false, false, ""
	}
	baseOp, _, hasDot := strings.Cut(uop, ".")
	if baseOp == "" || baseOp == "TEXT" || baseOp == "GLOBL" || baseOp == "DATA" ||
		baseOp == "DUFFCOPY" || baseOp == "DUFFZERO" || baseOp == "END" || baseOp == "XXX" {
		return false, false, ""
	}
	if hasDot {
		switch baseOp {
		case "BYTE", "WORD", "DWORD", "LONG", "QUAD",
			"RET", "CPUID", "MRS", "FUNCDATA", "PCDATA", "PCALIGN", "PCALIGNMAX":
			return false, false, ""
		}
	}
	// Leaf-only control-flow rule: forbid all subroutine calls, indirect/tail
	// returns (`RET reg` / `RET sym(SB)`), far/interrupt/authenticated returns,
	// runtime Duff helpers, and ARM64 ADR/ADRP PC-relative page/address calculation.
	if strings.HasPrefix(baseOp, "RET") {
		if uop != "RET" || rest != "" {
			return false, false, ""
		}
		return true, false, ""
	}
	if strings.HasPrefix(baseOp, "CALL") || strings.HasPrefix(baseOp, "IRET") {
		return false, false, ""
	}
	switch baseOp {
	case "BL", "BLR", "BLRAA", "BLRAAZ", "BLRAB", "BLRABZ",
		"JAL", "JALR", "BSR", "BCTRL", "BLRL",
		"BR", "BRAA", "BRAAZ", "BRAB", "BRABZ", "JMPF",
		"ADR", "ADRP":
		return false, false, ""
	}

	operands := splitAsmOperands(rest)

	// Any jump or branch must target a local label defined in the same TEXT
	// block (or a PC-relative numeric offset), never a register or (SB) symbol.
	// PC pseudo-register references are forbidden everywhere outside that branch
	// target operand.
	if isAsmBranchMnemonic(uop) || isAsmBranchMnemonic(baseOp) {
		if len(operands) == 0 {
			return false, false, ""
		}
		for _, nonTarget := range operands[:len(operands)-1] {
			if hasAsmPCToken(nonTarget) {
				return false, false, ""
			}
		}
		target := strings.TrimSpace(operands[len(operands)-1])
		if !isLocalAsmBranchTarget(goarch, target, localLabels) {
			return false, false, ""
		}
	} else if hasAsmPCToken(rest) {
		return false, false, ""
	}

	// Verify every (SB) reference names a package/file RODATA GLOBL and is never
	// modified by a destination or read-modify-write operand.
	for idx, opnd := range operands {
		unquotedOpnd := stripAsmQuotedLiterals(opnd)
		if strings.Contains(unquotedOpnd, "(SB)") {
			if strings.ContainsAny(opnd, `"'`) || isAsmReadModifyWriteMnemonic(baseOp) {
				return false, false, ""
			}
			if len(operands) == 1 && !strings.HasPrefix(baseOp, "PUSH") && !strings.HasPrefix(baseOp, "PREFETCH") {
				return false, false, ""
			}
			if len(operands) >= 2 && idx == len(operands)-1 && !isAsmReadOnlyCompareMnemonic(baseOp) {
				return false, false, ""
			}
			sbIdx := strings.Index(unquotedOpnd, "(SB)")
			if sbIdx <= 0 {
				return false, false, ""
			}
			tail := strings.TrimSpace(unquotedOpnd[sbIdx+4:])
			if tail != "" {
				if !strings.HasPrefix(tail, "(") || !strings.HasSuffix(tail, ")") || strings.Contains(tail, "(SB)") || strings.ContainsRune(tail, '·') {
					return false, false, ""
				}
			}
			normSym, _, _, symOK := parseAsmLocalSBRef(pkgPath, unquotedOpnd[:sbIdx])
			if !symOK || !rodataSyms[normSym] {
				return false, false, ""
			}
		} else if strings.ContainsRune(unquotedOpnd, '·') {
			return false, false, ""
		}
	}

	if uop == "CPUID" {
		if goarch != "amd64" || rest != "" {
			return false, false, ""
		}
		return true, true, ""
	}
	if uop == "MRS" {
		if goarch != "arm64" {
			return false, false, ""
		}
		if len(operands) == 2 && isAuditedARM64IDRegName(operands[0]) && isCleanARM64SysRegDestGPR(operands[1]) {
			return true, false, ""
		}
		return true, false, "hardware counter, entropy, or system assembly instruction"
	}
	if uop == "WORD" {
		if goarch != "arm64" {
			return true, false, "unverified raw opcode in assembly"
		}
		w, wordOK := parseAsmImmUint32(rest)
		if !wordOK || !isAuditedARM64WordOpcode(w) {
			return true, false, "unverified raw opcode in assembly"
		}
		return true, false, ""
	}
	if baseOp == "DWORD" || baseOp == "LONG" || baseOp == "QUAD" {
		return true, false, "unverified raw opcode in assembly"
	}
	if isImpureOrSystemAsmMnemonic(goarch, baseOp) {
		return true, false, "hardware counter, entropy, or system assembly instruction"
	}
	if stmtContainsARM64SysReg(rest) {
		// On arm64, cmd/asm encodes `MOVD <SysReg>, Rd` as `MRS` and
		// `MOVD Rs/$imm, <SysReg>` as `MSR`. Admit only exact unsuffixed `MOVD`
		// reading an audited static feature/ID register into a clean GPR.
		if goarch == "arm64" && uop == "MOVD" && len(operands) == 2 &&
			isAuditedARM64IDRegName(operands[0]) && isCleanARM64SysRegDestGPR(operands[1]) {
			return true, false, ""
		}
		return true, false, "hardware counter, entropy, or system assembly instruction"
	}
	return true, false, ""
}

func isAsmReadOnlyCompareMnemonic(uop string) bool {
	return strings.HasPrefix(uop, "CMP") && !strings.HasPrefix(uop, "CMPXCHG") ||
		strings.HasPrefix(uop, "TEST") || strings.HasPrefix(uop, "UCOMI") || strings.HasPrefix(uop, "VCOMI")
}

func isAsmReadModifyWriteMnemonic(uop string) bool {
	return uop == "LOCK" ||
		strings.HasPrefix(uop, "XCHG") ||
		strings.HasPrefix(uop, "XADD") ||
		strings.HasPrefix(uop, "CMPXCHG") ||
		strings.HasPrefix(uop, "BTS") ||
		strings.HasPrefix(uop, "BTR") ||
		strings.HasPrefix(uop, "BTC") ||
		strings.HasPrefix(uop, "VSCATTER") ||
		strings.HasPrefix(uop, "VPSCATTER") ||
		strings.HasPrefix(uop, "STXR") ||
		strings.HasPrefix(uop, "STLXR") ||
		strings.HasPrefix(uop, "STXP") ||
		strings.HasPrefix(uop, "STLXP") ||
		strings.HasPrefix(uop, "CAS") ||
		strings.HasPrefix(uop, "SWP") ||
		strings.HasPrefix(uop, "LDADD") ||
		strings.HasPrefix(uop, "LDCLR") ||
		strings.HasPrefix(uop, "LDEOR") ||
		strings.HasPrefix(uop, "LDOR") ||
		strings.HasPrefix(uop, "LDSET") ||
		strings.HasPrefix(uop, "LDSMAX") ||
		strings.HasPrefix(uop, "LDSMIN") ||
		strings.HasPrefix(uop, "LDUMAX") ||
		strings.HasPrefix(uop, "LDUMIN") ||
		strings.HasPrefix(uop, "STADD") ||
		strings.HasPrefix(uop, "STCLR") ||
		strings.HasPrefix(uop, "STEOR") ||
		strings.HasPrefix(uop, "STOR") ||
		strings.HasPrefix(uop, "STSET") ||
		strings.HasPrefix(uop, "STSMAX") ||
		strings.HasPrefix(uop, "STSMIN") ||
		strings.HasPrefix(uop, "STUMAX") ||
		strings.HasPrefix(uop, "STUMIN")
}

func isAsmBranchMnemonic(uop string) bool {
	if uop == "B" || strings.HasPrefix(uop, "B.") {
		return true
	}
	switch uop {
	case "JMP", "JA", "JAE", "JB", "JBE", "JC", "JCC", "JCS", "JE", "JEQ", "JG", "JGE", "JGT",
		"JHI", "JHS", "JL", "JLE", "JLO", "JLS", "JLT", "JMI",
		"JNA", "JNAE", "JNB", "JNBE", "JNC", "JNE", "JNG", "JNGE", "JNL", "JNLE",
		"JNO", "JNP", "JNS", "JNZ", "JO", "JOC", "JOS", "JP", "JPC", "JPE", "JPL", "JPO", "JPS", "JS", "JZ",
		"JCXZ", "JCXZW", "JCXZL", "JCXZQ", "JECXZ", "JRCXZ",
		"LOOP", "LOOPE", "LOOPEQ", "LOOPNE", "LOOPNZ", "LOOPZ",
		"BEQ", "BNE", "BCS", "BHS", "BCC", "BLO", "BMI", "BPL", "BVS", "BVC",
		"BHI", "BLS", "BGE", "BLT", "BGT", "BLE",
		"CBZ", "CBZW", "CBNZ", "CBNZW", "TBZ", "TBZW", "TBNZ", "TBNZW":
		return true
	}
	return false
}

func isArchRegisterIdent(goarch, s string) bool {
	switch s {
	case "FP", "SP", "SB", "PC", "TLS", "g", "IP", "MAXREG":
		return true
	}
	if goarch == "amd64" {
		switch s {
		case "AX", "BX", "CX", "DX", "SI", "DI", "BP",
			"AL", "AH", "BL", "BH", "CL", "CH", "DL", "DH",
			"SIL", "DIL", "BPL", "SPL", "SPB", "BPB", "SIB", "DIB":
			return true
		}
		if len(s) >= 2 && (s[0] == 'R' || s[0] == 'X' || s[0] == 'Y' || s[0] == 'Z' || s[0] == 'K' || s[0] == 'M' || s[0] == 'F') {
			tail := s[1:]
			if s[0] == 'R' {
				if last := tail[len(tail)-1]; last == 'B' || last == 'W' || last == 'D' || last == 'L' {
					tail = tail[:len(tail)-1]
				}
			}
			if len(tail) > 0 && len(tail) <= 2 {
				allDigits := true
				for i := 0; i < len(tail); i++ {
					if tail[i] < '0' || tail[i] > '9' {
						allDigits = false
						break
					}
				}
				if allDigits {
					return true
				}
			}
		}
	}
	if goarch == "arm64" {
		switch s {
		case "ZR", "LR", "RSP":
			return true
		}
		u := strings.ToUpper(s)
		if isARM64TLSSysReg(u) || isARM64SystemOrPStateReg(u) {
			return true
		}
		if strings.HasPrefix(s, "PN") && len(s) >= 3 && len(s) <= 4 {
			tail := s[2:]
			allDigits := true
			for i := 0; i < len(tail); i++ {
				if tail[i] < '0' || tail[i] > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				return true
			}
		}
		if len(s) >= 2 && (s[0] == 'R' || s[0] == 'F' || s[0] == 'V' || s[0] == 'Z' || s[0] == 'P') {
			tail := s[1:]
			if len(tail) > 0 && len(tail) <= 2 {
				allDigits := true
				for i := 0; i < len(tail); i++ {
					if tail[i] < '0' || tail[i] > '9' {
						allDigits = false
						break
					}
				}
				if allDigits {
					return true
				}
			}
		}
	}
	return false
}

func isLocalAsmBranchTarget(goarch, target string, localLabels map[string]bool) bool {
	if target == "" || strings.Contains(target, "(SB)") || strings.ContainsAny(target, "[]") {
		return false
	}
	if isArchRegisterIdent(goarch, target) {
		return false
	}
	if localLabels[target] {
		return true
	}
	if strings.HasSuffix(target, "(PC)") {
		off := strings.TrimSpace(strings.TrimSuffix(target, "(PC)"))
		_, err := strconv.ParseInt(off, 0, 64)
		return err == nil
	}
	return false
}

func parseAsmImmByte(rest string) (byte, bool) {
	s := strings.TrimSpace(rest)
	if !strings.HasPrefix(s, "$") {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(s[1:]), 0, 8)
	if err != nil {
		return 0, false
	}
	return byte(v), true
}

func parseAsmImmUint32(rest string) (uint32, bool) {
	s := strings.TrimSpace(rest)
	if !strings.HasPrefix(s, "$") {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(s[1:]), 0, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func isAuditedARM64IDRegName(opnd string) bool {
	u := strings.ToUpper(strings.TrimSpace(opnd))
	if u == "MIDR_EL1" || u == "REVIDR_EL1" {
		return true
	}
	return strings.HasPrefix(u, "ID_AA64") && strings.HasSuffix(u, "_EL1")
}

func isAuditedARM64WordOpcode(w uint32) bool {
	// Reject writes targeting R18 (platform register), R28 (g), or SP/XZR (31).
	rd := w & 0x1f
	if rd == 18 || rd == 28 || rd == 31 {
		return false
	}
	// MOVZ Wd/Xd, #imm16, LSL #(hw*16)
	if (w & 0x7f800000) == 0x52800000 {
		return true
	}
	// UBFM / LSL / LSR Wd/Xd, Wn/Xn, #immr, #imms
	if (w & 0x7f800000) == 0x53000000 {
		rn := (w >> 5) & 0x1f
		return rn != 18 && rn != 28 && rn != 31
	}
	// SVE ADDVL / ADDPL Xd, Xn, #imm6
	if (w & 0xffa0f800) == 0x04205000 {
		rn := (w >> 5) & 0x1f
		return rn != 18 && rn != 28 && rn != 31
	}
	// MRS Xt, <sysreg>: 1101_0101_0011_op1_CRn_CRm_op2_Rt
	if (w & 0xfff00000) == 0xd5300000 {
		op0 := ((w >> 19) & 1) + 2
		op1 := (w >> 16) & 7
		crn := (w >> 12) & 0xf
		crm := (w >> 8) & 0xf
		op2 := (w >> 5) & 7
		if op0 != 3 || op1 != 0 || crn != 0 {
			return false
		}
		if crm == 0 {
			// MIDR_EL1 (op2=0) and REVIDR_EL1 (op2=6) are static chip IDs;
			// MPIDR_EL1 (op2=5) is per-core affinity and MUST be rejected.
			return op2 == 0 || op2 == 6
		}
		// ID_AA64PFR*, ID_AA64DFR*, ID_AA64AFR*, ID_AA64ISAR*, ID_AA64MMFR*, ID_AA64ZFR*, ID_AA64SMFR*
		return crm >= 1 && crm <= 7
	}
	return false
}

func isAMD64R14AliasToken(tok string) bool {
	switch strings.ToUpper(tok) {
	case "R14", "R14L", "R14D", "R14W", "R14B":
		return true
	}
	return false
}

func isAMD64FullWidthR14Reg(opnd string) bool {
	switch strings.ToUpper(strings.TrimSpace(opnd)) {
	case "R14", "R14L", "R14D":
		return true
	}
	return false
}

func stmtMentionsAMD64R14(s string) bool {
	for i := 0; i < len(s); {
		if s[i] == '"' || s[i] == '\'' {
			q := s[i]
			i++
			for i < len(s) && s[i] != q {
				if s[i] == '\\' && i+1 < len(s) {
					i += 2
					continue
				}
				i++
			}
			if i >= len(s) {
				return true
			}
			i++
			continue
		}
		end, okIdent := scanIdentToken(s, i, true)
		if okIdent && end > i {
			tok := s[i:end]
			if isAMD64R14AliasToken(tok) && !(tok == strings.ToLower(tok) && isFrameSlotIdentBeforePlusFP(s, i, end)) {
				return true
			}
			i = end
			continue
		}
		i++
	}
	return false
}

func stmtUnconditionallyKillsAMD64R14(stmt string) bool {
	if hasUnquotedColon(stmt) {
		return false
	}
	op, rest := splitAsmOp(stmt)
	uop := strings.ToUpper(op)
	if strings.ContainsRune(uop, '.') {
		return false
	}
	operands := splitAsmOperands(rest)
	switch uop {
	case "XORL", "XORQ", "SUBL", "SUBQ":
		return len(operands) == 2 && isAMD64FullWidthR14Reg(operands[0]) &&
			strings.EqualFold(strings.TrimSpace(operands[0]), strings.TrimSpace(operands[1]))
	case "POPQ":
		return len(operands) == 1 && strings.EqualFold(strings.TrimSpace(operands[0]), "R14")
	case "MOVQ", "MOVL", "MOVABS",
		"MOVBLZX", "MOVWLZX", "MOVBQZX", "MOVWQZX", "MOVLQZX",
		"MOVBLSX", "MOVWLSX", "MOVBQSX", "MOVWQSX", "MOVLQSX",
		"LEAQ", "LEAL",
		"MOVD", "VMOVD", "VMOVQ",
		"MOVMSKPS", "MOVMSKPD", "VMOVMSKPS", "VMOVMSKPD", "PMOVMSKB", "VPMOVMSKB",
		"KMOVB", "KMOVW", "KMOVD", "KMOVQ",
		"LZCNTQ", "LZCNTL", "TZCNTQ", "TZCNTL", "POPCNTQ", "POPCNTL":
		return len(operands) == 2 && !stmtMentionsAMD64R14(operands[0]) && isAMD64FullWidthR14Reg(operands[1])
	case "PEXTRD", "PEXTRQ", "VPEXTRD", "VPEXTRQ",
		"BEXTRQ", "BEXTRL", "BZHIQ", "BZHIL", "PDEPQ", "PDEPL", "PEXTQ", "PEXTL",
		"SARXQ", "SARXL", "SHLXQ", "SHLXL", "SHRXQ", "SHRXL", "RORXQ", "RORXL",
		"ANDNQ", "ANDNL":
		return len(operands) == 3 && !stmtMentionsAMD64R14(operands[0]) && !stmtMentionsAMD64R14(operands[1]) && isAMD64FullWidthR14Reg(operands[2])
	case "MULXQ", "MULXL":
		if len(operands) != 3 || stmtMentionsAMD64R14(operands[0]) {
			return false
		}
		return isAMD64FullWidthR14Reg(operands[1]) || isAMD64FullWidthR14Reg(operands[2])
	}
	return false
}

func appendUniqueR14Nodes(dst []int, more ...int) []int {
	for _, v := range more {
		if !slices.Contains(dst, v) {
			dst = append(dst, v)
		}
	}
	return dst
}

// verifyAMD64EntryR14NotRead proves via forward CFG reachability that no path
// from an amd64 ABI0 TEXT entry can read or partially clobber R14 (which holds
// the caller's Go goroutine pointer g on entry under the register ABI) before
// an instruction unconditionally overwrites all 64 bits of R14.
func verifyAMD64EntryR14NotRead(blk asmTextBlock) bool {
	mentionsR14 := false
	for _, line := range blk.lines {
		for _, ch := range line.choices {
			if strings.Contains(ch, "R14") || strings.Contains(ch, "r14") {
				mentionsR14 = true
				break
			}
		}
		if mentionsR14 {
			break
		}
	}
	if !mentionsR14 {
		return true
	}

	type r14Node struct {
		stmt  string
		succs []int
	}
	type r14Branch struct {
		from   int
		target string
	}
	type r14CondFrame struct {
		entryFrontier []int
		exitFrontiers []int
		hasElse       bool
	}

	var nodes []r14Node
	addNode := func(stmt string) int {
		nodes = append(nodes, r14Node{stmt: stmt})
		return len(nodes) - 1
	}
	wireFrontier := func(frontier []int, to int) {
		for _, u := range frontier {
			if !slices.Contains(nodes[u].succs, to) {
				nodes[u].succs = append(nodes[u].succs, to)
			}
		}
	}

	entry := addNode("")
	frontier := []int{entry}
	labelNodes := map[string][]int{}
	var branches []r14Branch
	var condStack []r14CondFrame

	for _, line := range blk.lines {
		if line.condOp != asmCondNone {
			switch line.condOp {
			case asmCondIf:
				if line.condDepth > blk.openCondDepth {
					condStack = append(condStack, r14CondFrame{
						entryFrontier: slices.Clone(frontier),
					})
				}
			case asmCondElif:
				if len(condStack) == 0 || condStack[len(condStack)-1].hasElse {
					return false
				}
				top := &condStack[len(condStack)-1]
				top.exitFrontiers = appendUniqueR14Nodes(top.exitFrontiers, frontier...)
				frontier = slices.Clone(top.entryFrontier)
			case asmCondElse:
				if len(condStack) == 0 || condStack[len(condStack)-1].hasElse {
					return false
				}
				top := &condStack[len(condStack)-1]
				top.hasElse = true
				top.exitFrontiers = appendUniqueR14Nodes(top.exitFrontiers, frontier...)
				frontier = slices.Clone(top.entryFrontier)
			case asmCondEndif:
				if len(condStack) == 0 {
					return false
				}
				top := condStack[len(condStack)-1]
				condStack = condStack[:len(condStack)-1]
				merged := appendUniqueR14Nodes(top.exitFrontiers, frontier...)
				if !top.hasElse {
					merged = appendUniqueR14Nodes(merged, top.entryFrontier...)
				}
				frontier = merged
			}
			continue
		}

		var nextFrontier []int
		for _, ch := range line.choices {
			chFrontier := slices.Clone(frontier)
			for _, stmt := range splitAsmStatements(ch) {
				stmt = strings.TrimSpace(stmt)
				if stmt == "" {
					continue
				}
				for {
					lbl, rest, ok := cutAsmLabel(stmt)
					if !ok {
						break
					}
					lblNode := addNode("")
					wireFrontier(chFrontier, lblNode)
					labelNodes[lbl] = append(labelNodes[lbl], lblNode)
					chFrontier = []int{lblNode}
					stmt = strings.TrimSpace(rest)
				}
				if stmt == "" {
					continue
				}
				op, rest := splitAsmOp(stmt)
				uop := strings.ToUpper(op)
				baseOp, _, hasDot := strings.Cut(uop, ".")
				if !hasDot && (uop == "TEXT" || uop == "FUNCDATA" || uop == "PCDATA" || uop == "PCALIGN" || uop == "PCALIGNMAX") {
					continue
				}
				n := addNode(stmt)
				wireFrontier(chFrontier, n)
				if strings.HasPrefix(baseOp, "RET") {
					if uop != "RET" || rest != "" {
						return false
					}
					chFrontier = nil
					continue
				}
				if isAsmBranchMnemonic(uop) || isAsmBranchMnemonic(baseOp) {
					operands := splitAsmOperands(rest)
					if len(operands) == 0 {
						return false
					}
					target := strings.TrimSpace(operands[len(operands)-1])
					branches = append(branches, r14Branch{from: n, target: target})
					if !hasDot && (uop == "JMP" || uop == "B") {
						chFrontier = nil
					} else {
						chFrontier = []int{n}
					}
					continue
				}
				chFrontier = []int{n}
			}
			nextFrontier = appendUniqueR14Nodes(nextFrontier, chFrontier...)
		}
		frontier = nextFrontier
	}
	if len(condStack) != 0 {
		return false
	}

	for _, br := range branches {
		if strings.HasSuffix(br.target, "(PC)") {
			for idx := range nodes {
				if idx != br.from && !slices.Contains(nodes[br.from].succs, idx) {
					nodes[br.from].succs = append(nodes[br.from].succs, idx)
				}
			}
			continue
		}
		targets := labelNodes[br.target]
		if len(targets) == 0 {
			return false
		}
		for _, t := range targets {
			if !slices.Contains(nodes[br.from].succs, t) {
				nodes[br.from].succs = append(nodes[br.from].succs, t)
			}
		}
	}

	liveIn := make([]bool, len(nodes))
	liveIn[entry] = true
	worklist := []int{entry}
	for len(worklist) > 0 {
		u := worklist[len(worklist)-1]
		worklist = worklist[:len(worklist)-1]
		if nodes[u].stmt != "" && stmtMentionsAMD64R14(nodes[u].stmt) {
			if !stmtUnconditionallyKillsAMD64R14(nodes[u].stmt) {
				return false
			}
			continue
		}
		for _, v := range nodes[u].succs {
			if !liveIn[v] {
				liveIn[v] = true
				worklist = append(worklist, v)
			}
		}
	}
	return true
}

func (a *tier2Analyzer) scanVerifiedAsmBodylessFunction(fn *ssa.Function, idx *pkgIndex, isRoot bool) {
	if a == nil || fn == nil || idx == nil || idx.std || idx.meta == nil || len(idx.meta.SFiles) == 0 || len(fn.Blocks) != 0 {
		return
	}
	sum, ok := a.verifiedPackageAssemblyFunc(idx.meta, fn)
	if !ok {
		a.recordExternalEffect(opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly"))
		a.requestWiden("non-toolchain assembly in " + idx.id)
		return
	}
	fnName := functionSymbolName(fn)
	if sum.impureKind != "" {
		a.recordExternalEffect(symbolExternalEffect(externalEffectNative, idx.path, fnName, "reaches "+idx.path+"."+fnName+" ("+sum.impureKind+")"))
		return
	}
	if sum.cpuidArgs > 0 && isRoot {
		a.recordExternalEffect(symbolExternalEffect(externalEffectNative, idx.path, fnName, "reaches "+idx.path+"."+fnName+" (per-core CPUID register)"))
	}
}

func (a *tier2Analyzer) classifyVerifiedAsmCallee(callee *ssa.Function, calleeIdx *pkgIndex, c *ssa.CallCommon, site ssa.CallInstruction) (externalEffect, bool) {
	if callee == nil || calleeIdx == nil || calleeIdx.meta == nil || len(calleeIdx.meta.SFiles) == 0 {
		return externalEffect{}, false
	}
	sum, ok := a.verifiedPackageAssemblyFunc(calleeIdx.meta, callee)
	if !ok {
		a.requestWiden("non-toolchain assembly in " + calleeIdx.id)
		return opaqueExternalEffect(externalEffectNative, "reaches non-standard assembly"), true
	}
	fnName := functionSymbolName(callee)
	if sum.impureKind != "" {
		return symbolExternalEffect(externalEffectNative, calleeIdx.path, fnName, "reaches "+calleeIdx.path+"."+fnName+" ("+sum.impureKind+")"), true
	}
	if sum.cpuidArgs > 0 && cpuidCallReadsPerCoreState(c, site) {
		return symbolExternalEffect(externalEffectNative, calleeIdx.path, fnName, "reaches "+calleeIdx.path+"."+fnName+" (per-core CPUID register)"), true
	}
	return externalEffect{}, false
}

func cpuidCallReadsPerCoreState(c *ssa.CallCommon, site ssa.CallInstruction) bool {
	if c == nil || site == nil || len(c.Args) == 0 {
		return true
	}
	callVal, ok := site.(*ssa.Call)
	if !ok {
		return true
	}
	leaves, known := evalBoundedUint32Leaves(c.Args[0], site.Block(), 0)
	tup, isTuple := callVal.Type().Underlying().(*types.Tuple)
	if !isTuple || tup.Len() != 4 {
		if !known {
			return true
		}
		for _, leaf := range leaves {
			if isPerCoreCPUIDLeaf(leaf) {
				return true
			}
		}
		return false
	}
	if callVal.Referrers() == nil {
		return false
	}
	var extracts [4][]*ssa.Extract
	for _, ref := range *callVal.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
		case *ssa.Extract:
			if r.Tuple != callVal || r.Index < 0 || r.Index >= 4 {
				return true
			}
			extracts[r.Index] = append(extracts[r.Index], r)
		default:
			return true
		}
	}
	hasUsedExtract := func(idx int) bool {
		for _, ex := range extracts[idx] {
			if ex.Referrers() == nil {
				continue
			}
			for _, ref := range *ex.Referrers() {
				if _, isDbg := ref.(*ssa.DebugRef); !isDbg {
					return true
				}
			}
		}
		return false
	}
	extractMasksBits := func(idx int, forbiddenMask uint32) bool {
		for _, ex := range extracts[idx] {
			if !ssaUint32MasksOutBits(ex, forbiddenMask, 0) {
				return false
			}
		}
		return true
	}

	mayBeLeaf := func(target uint32) bool {
		if !known {
			return true
		}
		for _, l := range leaves {
			if l == target {
				return true
			}
		}
		return false
	}

	// Leaf 0x01: EBX[31:24] holds Initial APIC ID of the current logical processor.
	if mayBeLeaf(0x01) && !extractMasksBits(1, 0xff000000) {
		return true
	}
	// Leaves 0x0B, 0x1F, 0x80000026: EDX[31:0] holds x2APIC / Extended APIC ID.
	if (mayBeLeaf(0x0b) || mayBeLeaf(0x1f) || mayBeLeaf(0x80000026)) && hasUsedExtract(3) {
		return true
	}
	// AMD Leaf 0x8000001E: EAX holds ExtendedApicId; EBX[7:0] holds ComputeUnitId; ECX[7:0] holds NodeId.
	if mayBeLeaf(0x8000001e) {
		if hasUsedExtract(0) || !extractMasksBits(1, 0x000000ff) || !extractMasksBits(2, 0x000000ff) {
			return true
		}
	}
	return false
}

func isPerCoreCPUIDLeaf(leaf uint32) bool {
	switch leaf {
	case 0x01, 0x0b, 0x1f, 0x8000001e, 0x80000026:
		return true
	default:
		return false
	}
}

func ssaUint32MasksOutBits(v ssa.Value, forbiddenMask uint32, depth int) bool {
	if forbiddenMask == 0 {
		return true
	}
	if v == nil || depth > 4 {
		return false
	}
	if v.Referrers() == nil {
		return true
	}
	for _, ref := range *v.Referrers() {
		switch r := ref.(type) {
		case *ssa.DebugRef:
			continue
		case *ssa.BinOp:
			switch r.Op {
			case token.AND:
				var c *ssa.Const
				if r.X == v {
					c, _ = r.Y.(*ssa.Const)
				} else if r.Y == v {
					c, _ = r.X.(*ssa.Const)
				}
				if c == nil {
					return false
				}
				mask, ok := constUint32(c)
				if !ok {
					return false
				}
				if mask&forbiddenMask == 0 {
					continue
				}
				if !ssaUint32MasksOutBits(r, forbiddenMask&mask, depth+1) {
					return false
				}
			case token.SHR:
				if r.X != v {
					return false
				}
				c, ok := r.Y.(*ssa.Const)
				if !ok {
					return false
				}
				shift, ok := constUint32(c)
				if !ok || shift >= 32 {
					if ok && shift >= 32 {
						continue
					}
					return false
				}
				// Right-shifting drops low bits [shift-1:0] and moves high bits down by shift.
				shiftedForbidden := forbiddenMask >> shift
				if !ssaUint32MasksOutBits(r, shiftedForbidden, depth+1) {
					return false
				}
			case token.SHL:
				if r.X != v {
					return false
				}
				c, ok := r.Y.(*ssa.Const)
				if !ok {
					return false
				}
				shift, ok := constUint32(c)
				if !ok || shift >= 32 {
					if ok && shift >= 32 {
						continue
					}
					return false
				}
				shiftedForbidden := forbiddenMask << shift
				if !ssaUint32MasksOutBits(r, shiftedForbidden, depth+1) {
					return false
				}
			default:
				return false
			}
		case *ssa.Convert:
			b, ok := r.Type().Underlying().(*types.Basic)
			if !ok {
				return false
			}
			var narrowMask uint32 = 0xffffffff
			switch b.Kind() {
			case types.Uint8, types.Int8:
				narrowMask = 0x000000ff
			case types.Uint16, types.Int16:
				narrowMask = 0x0000ffff
			}
			if forbiddenMask&narrowMask == 0 {
				continue
			}
			if !ssaUint32MasksOutBits(r, forbiddenMask&narrowMask, depth+1) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func constUint32(c *ssa.Const) (uint32, bool) {
	if c == nil || c.Value == nil || c.Value.Kind() != constant.Int {
		return 0, false
	}
	v, ok := constant.Uint64Val(c.Value)
	if !ok || v > 0xffffffff {
		return 0, false
	}
	return uint32(v), true
}

func evalBoundedUint32Leaves(v ssa.Value, useBlock *ssa.BasicBlock, depth int) ([]uint32, bool) {
	if v == nil || depth > 4 {
		return nil, false
	}
	switch x := v.(type) {
	case *ssa.Const:
		u, ok := constUint32(x)
		if !ok {
			return nil, false
		}
		return []uint32{u}, true
	case *ssa.Convert:
		b, ok := x.Type().Underlying().(*types.Basic)
		if !ok || (b.Info()&types.IsInteger) == 0 {
			return nil, false
		}
		return evalBoundedUint32Leaves(x.X, useBlock, depth+1)
	case *ssa.BinOp:
		if x.Op == token.ADD {
			left, lok := evalBoundedUint32Leaves(x.X, useBlock, depth+1)
			right, rok := evalBoundedUint32Leaves(x.Y, useBlock, depth+1)
			if !lok || !rok || len(left)*len(right) > 16 {
				return nil, false
			}
			out := make([]uint32, 0, len(left)*len(right))
			for _, l := range left {
				for _, r := range right {
					out = append(out, l+r)
				}
			}
			return out, true
		}
	case *ssa.Phi:
		// Recognize canonical bounded loop induction variables (up to 16
		// iterations), covering both classic header-phi loops
		// (`for i := uint32(lo); i < hi; i++`) and Go 1.22+ integer-range
		// body-phi loops (`for i := range uint32(hi)`).
		if len(x.Edges) == 2 && x.Block() != nil && useBlock != nil {
			stepIdx := 1
			initConst, ok0 := x.Edges[0].(*ssa.Const)
			stepOp, ok1 := x.Edges[1].(*ssa.BinOp)
			if !ok0 || !ok1 {
				stepIdx = 0
				initConst, ok0 = x.Edges[1].(*ssa.Const)
				stepOp, ok1 = x.Edges[0].(*ssa.BinOp)
			}
			if ok0 && ok1 && stepOp.Op == token.ADD {
				lo, loOK := constUint32(initConst)
				var stepConst *ssa.Const
				if stepOp.X == x {
					stepConst, _ = stepOp.Y.(*ssa.Const)
				} else if stepOp.Y == x {
					stepConst, _ = stepOp.X.(*ssa.Const)
				}
				step, stepOK := constUint32(stepConst)
				if loOK && stepOK && step == 1 {
					if hi, hiOK := phiBoundedLoopUpperBound(x, stepOp, stepIdx, useBlock); hiOK && hi > lo && hi <= 0x7fffffff && hi-lo <= 16 {
						out := make([]uint32, 0, hi-lo)
						for cur := lo; cur < hi; cur++ {
							out = append(out, cur)
						}
						return out, true
					}
				}
			}
		}
	}
	return nil, false
}

func phiBoundedLoopUpperBound(phi *ssa.Phi, stepOp *ssa.BinOp, stepIdx int, useBlock *ssa.BasicBlock) (uint32, bool) {
	blk := phi.Block()
	if blk == nil || useBlock == nil {
		return 0, false
	}
	// Classic header-phi loop: blk ends with `if phi < hi` and the bounded
	// successor dominates useBlock.
	if len(blk.Instrs) > 0 && len(blk.Succs) == 2 && blk.Succs[0] != blk.Succs[1] {
		if ifInstr, ok := blk.Instrs[len(blk.Instrs)-1].(*ssa.If); ok {
			if blk.Succs[0] == useBlock || blk.Succs[0].Dominates(useBlock) {
				if hi, ok := cmpStrictUpperBound(ifInstr.Cond, phi, true); ok {
					return hi, true
				}
			} else if blk.Succs[1] == useBlock || blk.Succs[1].Dominates(useBlock) {
				if hi, ok := cmpStrictUpperBound(ifInstr.Cond, phi, false); ok {
					return hi, true
				}
			}
		}
	}
	// Go 1.22+ range-over-int loop: phi sits in rangeint.body (which dominates
	// useBlock), while predStep computes `incr = phi + 1` and ends with
	// `if incr < hi` branching back into blk.
	if (blk == useBlock || blk.Dominates(useBlock)) && stepIdx >= 0 && stepIdx < len(blk.Preds) {
		predStep := blk.Preds[stepIdx]
		if predStep != nil && stepOp.Block() == predStep && len(predStep.Instrs) > 0 && len(predStep.Succs) == 2 && predStep.Succs[0] != predStep.Succs[1] {
			if ifInstr, ok := predStep.Instrs[len(predStep.Instrs)-1].(*ssa.If); ok {
				if predStep.Succs[0] == blk {
					return cmpStrictUpperBound(ifInstr.Cond, stepOp, true)
				}
				if predStep.Succs[1] == blk {
					return cmpStrictUpperBound(ifInstr.Cond, stepOp, false)
				}
			}
		}
	}
	return 0, false
}

func cmpStrictUpperBound(cond, target ssa.Value, wantTrue bool) (uint32, bool) {
	cmp, ok := cond.(*ssa.BinOp)
	if !ok {
		return 0, false
	}
	op := cmp.Op
	if !wantTrue {
		switch op {
		case token.GEQ:
			op = token.LSS
		case token.GTR:
			op = token.LEQ
		case token.LEQ:
			op = token.GTR
		case token.LSS:
			op = token.GEQ
		default:
			return 0, false
		}
	}
	switch op {
	case token.LSS:
		if cmp.X == target {
			if c, ok := cmp.Y.(*ssa.Const); ok {
				return constUint32(c)
			}
		}
	case token.LEQ:
		if cmp.X == target {
			if c, ok := cmp.Y.(*ssa.Const); ok {
				if hi, ok := constUint32(c); ok && hi < 0xffffffff {
					return hi + 1, true
				}
			}
		}
	case token.GTR:
		if cmp.Y == target {
			if c, ok := cmp.X.(*ssa.Const); ok {
				return constUint32(c)
			}
		}
	case token.GEQ:
		if cmp.Y == target {
			if c, ok := cmp.X.(*ssa.Const); ok {
				if hi, ok := constUint32(c); ok && hi < 0xffffffff {
					return hi + 1, true
				}
			}
		}
	}
	return 0, false
}

func (b *tier2Base) isVerifiedReadOnlyLinknameVar(idx *pkgIndex, obj types.Object, target string) bool {
	if b == nil || b.h == nil || !b.h.SelectionAudited() || idx == nil || obj == nil {
		return false
	}
	wantKind, ok := auditedReadOnlyVarLinknameTargets[target]
	if !ok {
		return false
	}
	checkOne := func(pIdx *pkgIndex, pObj types.Object) bool {
		if pIdx == nil || pObj == nil || pIdx.ssa == nil {
			return false
		}
		v, ok := pObj.(*types.Var)
		if !ok || v.IsField() || v.Pkg() == nil || v.Parent() != v.Pkg().Scope() {
			return false
		}
		basic, ok := v.Type().Underlying().(*types.Basic)
		if !ok || basic.Kind() != wantKind {
			return false
		}
		if !b.pkgFreeOfUnverifiedNativeWriteHazard(pIdx) {
			return false
		}
		if g := pIdx.ssa.Var(v.Name()); g == nil || !ssaGlobalStrictlyReadOnly(b.prog, g) {
			return false
		}
		if pIdx.pkg != nil && !astPackageVarReadOnly(pIdx.pkg, v, false) {
			return false
		}
		if v.Exported() {
			for _, otherIdx := range b.idxByTypes {
				if otherIdx != nil && otherIdx != pIdx && otherIdx.pkg != nil && !astPackageVarReadOnly(otherIdx.pkg, v, false) {
					return false
				}
			}
		}
		return true
	}
	if !checkOne(idx, obj) {
		return false
	}
	for _, peer := range b.objsByLinkTarget[target] {
		if peer == obj {
			continue
		}
		if peer == nil || peer.Pkg() == nil {
			return false
		}
		peerIdx := b.idxByTypes[peer.Pkg()]
		if peerIdx != nil && peerIdx.std {
			continue
		}
		if !checkOne(peerIdx, peer) {
			return false
		}
	}
	return true
}

func (b *tier2Base) verifiedReadOnlyLinknameLocals(pkgPath string) map[string]bool {
	if b == nil || b.h == nil || !b.h.SelectionAudited() || pkgPath == "" {
		return nil
	}
	var out map[string]bool
	for _, idx := range b.idxByTypes {
		if idx == nil || idx.path != pkgPath {
			continue
		}
		for obj, target := range idx.linknames {
			if b.isVerifiedReadOnlyLinknameVar(idx, obj, target) {
				if out == nil {
					out = make(map[string]bool, 2)
				}
				out[obj.Name()] = true
			}
		}
		if idx.pkg != nil && idx.pkg.Types != nil && idx.pkg.Types.Scope() != nil {
			for name, target := range idx.linknameByName {
				obj := idx.pkg.Types.Scope().Lookup(name)
				if obj == nil {
					continue
				}
				if docTarget := idx.linknames[obj]; docTarget != "" && docTarget != target {
					delete(out, name)
					continue
				}
				if b.isVerifiedReadOnlyLinknameVar(idx, obj, target) {
					if out == nil {
						out = make(map[string]bool, 2)
					}
					out[name] = true
				}
			}
		}
	}
	return out
}

const nonReadOnlyGlobalsSummaryKey = "gofresh/non-readonly-globals@1"

func nonReadOnlySSAGlobals(p *program) map[*ssa.Global]bool {
	if p == nil || p.Prog == nil {
		return nil
	}
	if p.Summaries != nil {
		if cached, ok := p.Summaries[nonReadOnlyGlobalsSummaryKey].(map[*ssa.Global]bool); ok {
			return cached
		}
	}
	nonRO := map[*ssa.Global]bool{}
	var ops [16]*ssa.Value
	for _, fn := range progOrderedFunctions(p) {
		if fn == nil {
			continue
		}
		for _, blk := range fn.Blocks {
			for _, instr := range blk.Instrs {
				if _, ok := instr.(*ssa.DebugRef); ok {
					continue
				}
				for _, op := range instr.Operands(ops[:0]) {
					if op == nil || *op == nil {
						continue
					}
					g, ok := (*op).(*ssa.Global)
					if !ok {
						continue
					}
					un, isUn := instr.(*ssa.UnOp)
					if !isUn || un.Op != token.MUL || un.X != g {
						nonRO[g] = true
					}
				}
			}
		}
	}
	if p.Summaries == nil {
		p.Summaries = make(map[string]any, 2)
	}
	p.Summaries[nonReadOnlyGlobalsSummaryKey] = nonRO
	return nonRO
}

func ssaGlobalStrictlyReadOnly(p *program, g *ssa.Global) bool {
	if p == nil || g == nil || g.Pkg == nil {
		return false
	}
	return !nonReadOnlySSAGlobals(p)[g]
}

// astPackageVarReadOnly verifies across every syntax tree of pkg (including
// uninstantiated generic functions that SSA may not materialize) that v is
// never assigned, incremented/decremented, bound in a range clause, or
// address-taken, and (when allowDeclInit is false) carries no ValueSpec
// initializer.
func astPackageVarReadOnly(pkg *packages.Package, v *types.Var, allowDeclInit bool) bool {
	if pkg == nil || v == nil || pkg.TypesInfo == nil {
		return false
	}
	usesVar := func(e ast.Expr) bool {
		switch x := unwrapASTParen(e).(type) {
		case *ast.Ident:
			return pkg.TypesInfo.Uses[x] == v || pkg.TypesInfo.Defs[x] == v
		case *ast.SelectorExpr:
			return x.Sel != nil && pkg.TypesInfo.Uses[x.Sel] == v
		}
		return false
	}
	ok := true
	for _, file := range pkg.Syntax {
		if file == nil || !ok {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if !ok || n == nil {
				return false
			}
			switch x := n.(type) {
			case *ast.ValueSpec:
				for i, id := range x.Names {
					if pkg.TypesInfo.Defs[id] == v {
						if !allowDeclInit && (len(x.Values) > i || len(x.Values) > 0) {
							ok = false
							return false
						}
					}
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if usesVar(lhs) {
						ok = false
						return false
					}
				}
			case *ast.IncDecStmt:
				if usesVar(x.X) {
					ok = false
					return false
				}
			case *ast.RangeStmt:
				if x.Tok == token.ASSIGN && (usesVar(x.Key) || usesVar(x.Value)) {
					ok = false
					return false
				}
			case *ast.UnaryExpr:
				if x.Op == token.AND && usesVar(x.X) {
					ok = false
					return false
				}
			}
			return true
		})
	}
	return ok
}
