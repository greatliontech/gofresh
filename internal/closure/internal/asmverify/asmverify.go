// Package asmverify implements mechanical Plan 9 .s assembly parsing, RODATA
// and (SB) symbol discipline verification, and ISA instruction purity analysis
// for amd64 and arm64.
package asmverify

import (
	"go/types"
	"path/filepath"
	"slices"
	"strings"

	"github.com/greatliontech/gofresh/internal/closure/internal/cprep"
)

// NonStdAsmVerifierVersion identifies the non-standard assembly verifier version.
const NonStdAsmVerifierVersion = "gofresh/nonstd-asm-verifier@4"

// TextSummary summarizes the purity classification of one assembly TEXT symbol.
type TextSummary struct {
	CPUIDArgs  int // 1 or 2 for canonical CPUID wrappers; 0 otherwise
	ImpureKind string
}

// VerifiedPackage records the verified assembly summary for a package's .s and .h files.
type VerifiedPackage struct {
	OK            bool
	Funcs         map[string]TextSummary
	RodataGoNames []string
}

// CheckVerifiedTypeScopes verifies that none of vp's assembly RODATA GLOBL
// symbols collide with Go declarations in typeScopes.
func CheckVerifiedTypeScopes(vp *VerifiedPackage, typeScopes []*types.Package) bool {
	if vp == nil || !vp.OK {
		return false
	}
	for _, goName := range vp.RodataGoNames {
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

// IsCanonicalCPUIDSignature reports whether sig has argCount uint32 parameters
// and 4 uint32 results with no receiver and no variadic parameter.
func IsCanonicalCPUIDSignature(sig *types.Signature, argCount int) bool {
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

// SignatureCarrierFree reports whether sig is a top-level function signature
// whose parameter and result types are free of unsafe.Pointer, uintptr,
// interfaces, funcs, channels, maps, and type parameters.
func SignatureCarrierFree(sig *types.Signature) bool {
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

// VerifyNonStdFiles mechanically parses and verifies all .s and .h files of a
// non-standard package on amd64 or arm64.
func VerifyNonStdFiles(goarch, pkgPath, dir string, sFiles, hFiles []string, typeScopes []*types.Package, read func(string) ([]byte, error)) (*VerifiedPackage, bool) {
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
		localHeaders[hdr.name] = foldAsmDefineNewlines(cprep.StripAssemblyComments(hdr.txt, true, false))
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
		folded := foldAsmDefineNewlines(cprep.StripAssemblyComments(txt, true, false))
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

	funcs := map[string]TextSummary{}
	for _, parsed := range parsedFiles {
		if !verifyParsedNonStdAsmFile(goarch, pkgPath, parsed, pkgRodataSyms, funcs) {
			return nil, false
		}
	}
	slices.Sort(rodataGoNames)
	return &VerifiedPackage{OK: true, Funcs: funcs, RodataGoNames: rodataGoNames}, true
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
		if !inDefine {
			if kw, _, ok := cprep.CutDirectiveKeyword(trimmed); ok && kw == "define" {
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
	if kw, after, ok := cprep.CutDirectiveKeyword(trimmed); ok && kw == "define" {
		if _, def, _, okDef := cprep.ParseDefineRest(after); okDef {
			return def.Body == ""
		}
		after = strings.TrimSpace(after)
		mName := cprep.LeadingASCIIIdent(after)
		tail := after[len(mName):]
		if strings.HasPrefix(tail, "(") {
			if closeIdx := strings.IndexByte(tail, ')'); closeIdx >= 0 {
				return strings.TrimSpace(tail[closeIdx+1:]) == ""
			}
			return true
		}
		return strings.TrimSpace(tail) == ""
	}
	last := trimmed[len(trimmed)-1]
	switch last {
	case ',', '(', '+', '-', '*', '/', '|', '&', '^', '~', '<', '>', ';', ':':
		return true
	}
	return false
}

func verifyNonStdAsmPreprocessor(pkgPath, name, src string, selectedHeaders map[string]bool) error {
	opts := cprep.AsmPreprocessorOptions{
		NonStd:            true,
		ReservedMacroName: isReservedNonStdAsmMacroName,
	}
	if err := cprep.VerifyAssemblyPreprocessorPass(pkgPath, name, src, selectedHeaders, true, opts); err != nil {
		return err
	}
	if !strings.Contains(src, "\\") {
		return nil
	}
	return cprep.VerifyAssemblyPreprocessorPass(pkgPath, name, src, selectedHeaders, false, opts)
}
