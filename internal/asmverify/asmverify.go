// Package asmverify implements mechanical Plan 9 .s assembly parsing, RODATA
// and (SB) symbol discipline verification, and ISA instruction purity analysis
// for amd64 and arm64.
package asmverify

import (
	"go/types"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/greatliontech/gofresh/internal/cprep"
)

// NonStdAsmVerifierVersion identifies the non-standard assembly verifier version.
const NonStdAsmVerifierVersion = "gofresh/nonstd-asm-verifier@6"

// ExternalSBRef identifies a read-only non-RODATA or cross-package (SB) data
// symbol referenced by an assembly TEXT block.
type ExternalSBRef struct {
	PkgPath string
	Name    string
}

// TextSummary summarizes the verification and purity classification of one
// assembly TEXT symbol.
type TextSummary struct {
	Verified                bool
	CPUIDArgs               int // 1 or 2 for canonical CPUID wrappers; 0 otherwise
	ForwardsTrapArg0Syscall bool
	ImpureKind              string
	ExternalSBRefs          []ExternalSBRef
	GoCallees               []string // sorted transitive Go-visible intra-package TEXT callees
}

// VerifiedPackage records the verified assembly summary for a package's .s and .h files.
type VerifiedPackage struct {
	PackageSafe      bool
	AllTextsVerified bool
	Funcs            map[string]TextSummary
	RodataGoNames    []string
}

// CheckVerifiedTypeScopes verifies that none of vp's assembly RODATA GLOBL
// symbols collide with Go declarations in typeScopes, and no assembly TEXT
// symbol collides with a non-function Go declaration.
func CheckVerifiedTypeScopes(vp *VerifiedPackage, typeScopes []*types.Package) bool {
	if vp == nil || !vp.PackageSafe {
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
	for fnName := range vp.Funcs {
		if fnName == "" {
			continue
		}
		for _, tp := range typeScopes {
			if tp == nil || tp.Scope() == nil {
				return false
			}
			if obj := tp.Scope().Lookup(fnName); obj != nil {
				if _, isFn := obj.(*types.Func); !isFn {
					return false
				}
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

	vp, ok := verifyParsedNonStdAsmPackage(goarch, pkgPath, parsedFiles, pkgRodataSyms, rodataGoNames)
	if !ok || vp == nil {
		return nil, false
	}
	if !CheckVerifiedTypeScopes(vp, typeScopes) {
		return nil, false
	}
	return vp, true
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
		NonStd:             true,
		ReservedMacroName:  isReservedNonStdAsmMacroName,
		AllowedCrossPkgSym: func(string) bool { return true },
	}
	if err := cprep.VerifyAssemblyPreprocessorPass(pkgPath, name, src, selectedHeaders, true, opts); err != nil {
		return err
	}
	if !strings.Contains(src, "\\") {
		return nil
	}
	return cprep.VerifyAssemblyPreprocessorPass(pkgPath, name, src, selectedHeaders, false, opts)
}

func mergeExternalSBRefs(dst, more []ExternalSBRef) []ExternalSBRef {
	if len(more) == 0 {
		return dst
	}
	out := slices.Clone(dst)
	for _, r := range more {
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b ExternalSBRef) int {
		if c := strings.Compare(a.PkgPath, b.PkgPath); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

func mergeGoCallees(dst, more []string, direct string) []string {
	if len(more) == 0 && direct == "" {
		return dst
	}
	out := slices.Clone(dst)
	if direct != "" && !slices.Contains(out, direct) {
		out = append(out, direct)
	}
	for _, s := range more {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

type localTextVerifyEntry struct {
	key                     string
	goName                  string
	blockCount              int
	cfgs                    []*asmBlockCFG
	callees                 []string
	goCallees               []string
	localOK                 bool
	cpuidArgs               int
	forwardsTrapArg0Syscall bool
	impureKind              string
	extRefs                 []ExternalSBRef
}

func verifyParsedNonStdAsmPackage(goarch, pkgPath string, parsedFiles []*parsedNonStdAsmFile, pkgRodataSyms map[string]bool, rodataGoNames []string) (*VerifiedPackage, bool) {
	if goarch != "amd64" && goarch != "arm64" {
		return nil, false
	}

	rodataByFile := make([]map[string]bool, len(parsedFiles))
	definedTexts := map[string]bool{}
	for fileIdx, parsed := range parsedFiles {
		if parsed == nil {
			return nil, false
		}
		rodataSyms := make(map[string]bool, len(pkgRodataSyms)+len(parsed.fileRodataSyms))
		for k := range pkgRodataSyms {
			rodataSyms[k] = true
		}
		for k := range parsed.fileRodataSyms {
			rodataSyms[k] = true
		}
		for _, dataRest := range parsed.dataDirectives {
			if !validateAsmDataDirective(pkgPath, dataRest, rodataSyms) {
				return nil, false
			}
		}
		for _, blk := range parsed.blocks {
			if rodataSyms["·"+blk.name] || rodataSyms[blk.name] {
				return nil, false
			}
			definedTexts[scopedAsmTextKey(fileIdx, blk.name)] = true
		}
		rodataByFile[fileIdx] = rodataSyms
	}

	entries := map[string]*localTextVerifyEntry{}
	var orderedKeys []string
	for fileIdx, parsed := range parsedFiles {
		rodataSyms := rodataByFile[fileIdx]
		for _, blk := range parsed.blocks {
			key := scopedAsmTextKey(fileIdx, blk.name)
			ent := entries[key]
			firstBlock := ent == nil
			if firstBlock {
				goName := ""
				if !strings.HasPrefix(blk.name, "<>") {
					goName = blk.name
				}
				ent = &localTextVerifyEntry{
					key:     key,
					goName:  goName,
					localOK: true,
				}
				entries[key] = ent
				orderedKeys = append(orderedKeys, key)
			}
			ent.blockCount++
			if ent.blockCount == 1 && ent.goName != "" {
				ent.forwardsTrapArg0Syscall = verifyTrapArg0SyscallTrampoline(goarch, blk)
			} else {
				ent.forwardsTrapArg0Syscall = false
			}
			blkCFG, blkSum, okBlk := verifySingleAsmTextBlock(goarch, pkgPath, fileIdx, blk, rodataSyms, definedTexts)
			if blkSum.ImpureKind != "" && (ent.impureKind == "" || blkSum.ImpureKind < ent.impureKind) {
				ent.impureKind = blkSum.ImpureKind
			}
			if !okBlk || !ent.localOK {
				ent.localOK = false
				ent.cpuidArgs = 0
				continue
			}
			ent.cfgs = append(ent.cfgs, blkCFG)
			for _, c := range blkCFG.callees {
				if !slices.Contains(ent.callees, c) {
					ent.callees = append(ent.callees, c)
				}
			}
			ent.extRefs = mergeExternalSBRefs(ent.extRefs, blkSum.ExternalSBRefs)
			if blkSum.ImpureKind != "" {
				ent.cpuidArgs = 0
			} else if firstBlock {
				ent.cpuidArgs = blkSum.CPUIDArgs
			} else if ent.cpuidArgs != blkSum.CPUIDArgs {
				ent.cpuidArgs = 0
				if ent.impureKind == "" {
					ent.impureKind = "per-core CPUID register"
				}
			}
			if len(ent.callees) > 0 && ent.cpuidArgs > 0 {
				ent.cpuidArgs = 0
				if ent.impureKind == "" {
					ent.impureKind = "per-core CPUID register"
				}
			}
		}
	}

	slices.Sort(orderedKeys)
	verified := make(map[string]bool, len(entries))
	entryTaint := make(map[string]uint32, len(entries))
	retTaint := make(map[string]uint32, len(entries))
	for _, k := range orderedKeys {
		verified[k] = entries[k].localOK
	}
	for {
		changed := false
		for _, k := range orderedKeys {
			if !verified[k] {
				continue
			}
			ent := entries[k]
			for _, c := range ent.callees {
				if !verified[c] {
					verified[k] = false
					changed = true
					break
				}
			}
			if !verified[k] {
				continue
			}
			var combinedRet uint32
			for _, cfg := range ent.cfgs {
				rt, demand, okTaint := verifyAsmBlockSBAddrTaint(goarch, cfg, entryTaint[k], retTaint)
				if !okTaint {
					verified[k] = false
					changed = true
					break
				}
				combinedRet |= rt
				for target, dMask := range demand {
					if (entryTaint[target] | dMask) != entryTaint[target] {
						entryTaint[target] |= dMask
						changed = true
					}
				}
			}
			if verified[k] && (combinedRet|retTaint[k]) != retTaint[k] {
				retTaint[k] |= combinedRet
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	for {
		changed := false
		for _, k := range orderedKeys {
			if !verified[k] {
				continue
			}
			ent := entries[k]
			for _, c := range ent.callees {
				ce := entries[c]
				calleeImpure := ce.impureKind
				if calleeImpure == "" && ce.cpuidArgs > 0 {
					calleeImpure = "per-core CPUID register"
				}
				if calleeImpure != "" && (ent.impureKind == "" || calleeImpure < ent.impureKind) {
					ent.impureKind = calleeImpure
					ent.cpuidArgs = 0
					changed = true
				}
				mergedRefs := mergeExternalSBRefs(ent.extRefs, ce.extRefs)
				if !slices.Equal(mergedRefs, ent.extRefs) {
					ent.extRefs = mergedRefs
					changed = true
				}
				mergedGoCallees := mergeGoCallees(ent.goCallees, ce.goCallees, ce.goName)
				if !slices.Equal(mergedGoCallees, ent.goCallees) {
					ent.goCallees = mergedGoCallees
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	allTextsVerified := true
	funcs := make(map[string]TextSummary, len(entries))
	for _, k := range orderedKeys {
		ent := entries[k]
		if !verified[k] {
			allTextsVerified = false
		}
		if ent.goName == "" {
			continue
		}
		if !verified[k] {
			funcs[ent.goName] = TextSummary{
				Verified:                false,
				ForwardsTrapArg0Syscall: ent.blockCount == 1 && ent.forwardsTrapArg0Syscall,
				ImpureKind:              ent.impureKind,
			}
			continue
		}
		cpuidArgs := ent.cpuidArgs
		if ent.impureKind != "" {
			cpuidArgs = 0
		}
		funcs[ent.goName] = TextSummary{
			Verified:       true,
			CPUIDArgs:      cpuidArgs,
			ImpureKind:     ent.impureKind,
			ExternalSBRefs: ent.extRefs,
			GoCallees:      ent.goCallees,
		}
	}
	slices.Sort(rodataGoNames)
	return &VerifiedPackage{
		PackageSafe:      true,
		AllTextsVerified: allTextsVerified,
		Funcs:            funcs,
		RodataGoNames:    rodataGoNames,
	}, true
}

func verifySingleAsmTextBlock(goarch, pkgPath string, fileIdx int, blk asmTextBlock, rodataSyms, definedTexts map[string]bool) (*asmBlockCFG, TextSummary, bool) {
	cfg, okCFG := buildAsmBlockCFG(goarch, pkgPath, fileIdx, blk, definedTexts)
	if !okCFG {
		return nil, TextSummary{}, false
	}
	if goarch == "amd64" && !verifyAMD64EntryR14NotRead(cfg) {
		return nil, TextSummary{}, false
	}

	var sum TextSummary
	writeSafe := true
	sawCPUID := false
	var pendingBytes []byte
	lastByteEpoch := -1
	flushBytes := func() {
		if len(pendingBytes) == 0 {
			return
		}
		if !(goarch == "amd64" && len(pendingBytes) == 3 && pendingBytes[0] == 0x0f && pendingBytes[1] == 0x01 && pendingBytes[2] == 0xd0) {
			writeSafe = false
			if sum.ImpureKind == "" {
				sum.ImpureKind = "unverified raw opcode in assembly"
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
						writeSafe = false
						if sum.ImpureKind == "" {
							sum.ImpureKind = "unverified raw opcode in assembly"
						}
						continue
					}
					b, ok := parseAsmImmByte(rest)
					if !ok {
						writeSafe = false
						if sum.ImpureKind == "" {
							sum.ImpureKind = "unverified raw opcode in assembly"
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
				res := verifyAsmTextInstruction(goarch, pkgPath, fileIdx, uop, rest, blk.labels, rodataSyms, definedTexts)
				if res.impure != "" && sum.ImpureKind == "" {
					sum.ImpureKind = res.impure
				}
				if !res.ok {
					if res.impure == "" {
						return nil, TextSummary{}, false
					}
					writeSafe = false
					continue
				}
				if res.cpuid {
					sawCPUID = true
				}
				if len(res.extRefs) > 0 {
					sum.ExternalSBRefs = mergeExternalSBRefs(sum.ExternalSBRefs, res.extRefs)
				}
			}
		}
	}
	flushBytes()
	if !writeSafe {
		return nil, TextSummary{Verified: false, ImpureKind: sum.ImpureKind}, false
	}
	if sum.ImpureKind != "" {
		sum.CPUIDArgs = 0
	} else if sawCPUID {
		argCount, okCanonical := verifyCanonicalCPUIDTextBlock(blk)
		if !okCanonical {
			sum.CPUIDArgs = 0
			sum.ImpureKind = "per-core CPUID register"
		} else {
			sum.CPUIDArgs = argCount
		}
	}
	sum.Verified = true
	return cfg, sum, true
}

// verifyTrapArg0SyscallTrampoline reports whether blk is a single-entry linear
// syscall trampoline that either tail-jumps directly to a stdlib syscall
// trampoline or loads 0(FP) directly into the architecture's syscall-number
// register (AX on amd64, R8 on arm64) without overwriting it before SYSCALL/SVC.
func verifyTrapArg0SyscallTrampoline(goarch string, blk asmTextBlock) bool {
	if len(blk.labels) != 0 {
		return false
	}
	var stmts [][2]string
	for _, line := range blk.lines {
		if line.condOp != asmCondNone || line.condDepth != blk.openCondDepth || len(line.choices) != 1 {
			return false
		}
		for _, stmt := range splitAsmStatements(line.choices[0]) {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, _, hasLabel := cutAsmLabel(stmt); hasLabel {
				return false
			}
			op, rest := splitAsmOp(stmt)
			uop := strings.ToUpper(op)
			if uop == "TEXT" {
				continue
			}
			stmts = append(stmts, [2]string{uop, strings.TrimSpace(rest)})
		}
	}
	if len(stmts) == 0 {
		return false
	}
	if len(stmts) == 1 {
		jmpOp := "JMP"
		if goarch == "arm64" {
			jmpOp = "B"
		}
		if stmts[0][0] != jmpOp {
			return false
		}
		switch stmts[0][1] {
		case "syscall·Syscall(SB)", "syscall·Syscall6(SB)", "syscall·RawSyscall(SB)", "syscall·RawSyscall6(SB)":
			return true
		default:
			return false
		}
	}
	if stmts[len(stmts)-1][0] != "RET" || stmts[len(stmts)-1][1] != "" {
		return false
	}
	var movOp, callOp, trapOp, trapReg string
	var argRegs, retRegs map[string]bool
	switch goarch {
	case "amd64":
		movOp, callOp, trapOp, trapReg = "MOVQ", "CALL", "SYSCALL", "AX"
		argRegs = map[string]bool{"DI": true, "SI": true, "DX": true, "R10": true, "R8": true, "R9": true, "AX": true}
		retRegs = map[string]bool{"AX": true, "DX": true}
	case "arm64":
		movOp, callOp, trapOp, trapReg = "MOVD", "BL", "SVC", "R8"
		argRegs = map[string]bool{"R0": true, "R1": true, "R2": true, "R3": true, "R4": true, "R5": true, "R8": true}
		retRegs = map[string]bool{"R0": true, "R1": true}
	default:
		return false
	}
	phase := 0
	sawMove := false
	loadedTrapReg := false
	sawEnter := false
	sawExit := false
	for _, st := range stmts[:len(stmts)-1] {
		uop, rest := st[0], st[1]
		if phase == 0 {
			switch uop {
			case callOp:
				if sawEnter || sawMove || rest != "runtime·entersyscall(SB)" {
					return false
				}
				sawEnter = true
			case movOp:
				src, dst, ok := splitTwoAsmOperands(rest)
				if !ok || !argRegs[dst] {
					return false
				}
				if dst == trapReg {
					if !isAsmFPSlotOffset(src, 0) {
						return false
					}
					loadedTrapReg = true
				} else if src != "$0" && !isPositiveAsmFPSlot(src) {
					return false
				}
				sawMove = true
			case trapOp:
				if !loadedTrapReg {
					return false
				}
				if goarch == "amd64" && rest != "" {
					return false
				}
				if goarch == "arm64" && rest != "" && rest != "$0" {
					return false
				}
				phase = 1
			default:
				return false
			}
		} else {
			switch uop {
			case movOp:
				if sawExit {
					return false
				}
				src, dst, ok := splitTwoAsmOperands(rest)
				if !ok || !retRegs[src] || !isPositiveAsmFPSlot(dst) {
					return false
				}
			case callOp:
				if sawExit || rest != "runtime·exitsyscall(SB)" {
					return false
				}
				sawExit = true
			default:
				return false
			}
		}
	}
	return phase == 1
}

func splitTwoAsmOperands(rest string) (string, string, bool) {
	a, b, ok := strings.Cut(rest, ",")
	if !ok || strings.Contains(b, ",") {
		return "", "", false
	}
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return "", "", false
	}
	return a, b, true
}

func parseAsmFPSlotOffset(op string) (int, bool) {
	base, ok := strings.CutSuffix(strings.TrimSpace(op), "(FP)")
	if !ok || base == "" {
		return 0, false
	}
	offStr := base
	if name, off, hasPlus := strings.Cut(base, "+"); hasPlus {
		if name == "" || cprep.LeadingASCIIIdent(name) != name {
			return 0, false
		}
		offStr = off
	}
	n, err := strconv.Atoi(offStr)
	if err != nil || n < 0 || n%8 != 0 {
		return 0, false
	}
	return n, true
}

func isAsmFPSlotOffset(op string, want int) bool {
	n, ok := parseAsmFPSlotOffset(op)
	return ok && n == want
}

func isPositiveAsmFPSlot(op string) bool {
	n, ok := parseAsmFPSlotOffset(op)
	return ok && n >= 8
}
