package closure

import (
	"fmt"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"

	"github.com/greatliontech/go-x-tools/go/ssa"
	"github.com/greatliontech/gofresh/internal/auditset"
)

func maximalObservabilityBlocker(audited bool, effect externalEffect) bool {
	if effect.packagePath == "testing" && (effect.symbol == "Run" || effect.symbol == "Fuzz") {
		return false
	}
	if isPropertyHarnessFact(effect) {
		return false
	}
	if effect.reason == "testing runtime value escapes analyzable receiver" {
		return false
	}
	if effect.packagePath == "runtime" && effect.symbol == "GOROOT" {
		return false
	}
	if audited && auditset.WriterFirstStdFunc(effect.packagePath, effect.symbol) {
		return false
	}
	if fmtFscanFamily(audited, effect.packagePath, effect.symbol) {
		return false
	}
	if audited && effect.packagePath == "go/parser" && auditset.GoParserSourceFunc(effect.symbol) {
		return false
	}
	if audited && effect.packagePath == "runtime/debug" && effect.symbol == "ReadBuildInfo" {
		return false
	}
	if effect.packagePath == "testing" && effect.symbol == "TempDir" {
		return false
	}
	if effect.packagePath == "path/filepath" && effect.symbol == "Join" {
		return false
	}
	if audited && effect.packagePath == "math" {
		return false
	}
	if effect.packagePath == "os" && isOpenFlagSymbol(effect.symbol) {
		return false
	}
	if effect.packagePath == "os" {
		switch effect.symbol {
		case "Getenv", "LookupEnv", "Open", "OpenFile", "ReadFile", "ReadDir", "WriteFile", "Remove", "RemoveAll":
			return false
		}
	}
	if effect.packagePath == "unsafe" && (effect.symbol == "Pointer" || isCompileTimeUnsafeIntrinsic(effect.packagePath, effect.symbol)) {
		return false
	}
	return true
}

func isOpenFlagSymbol(symbol string) bool {
	switch symbol {
	case "O_RDONLY", "O_WRONLY", "O_RDWR", "O_APPEND", "O_CREATE", "O_EXCL", "O_SYNC", "O_TRUNC":
		return true
	default:
		return false
	}
}

func flagRegistrationSymbol(pkgPath, name string) bool {
	return pkgPath == "flag" && auditset.FlagSurface(name).IsRegistration()
}

func flagValueRegistration(pkgPath, name string) bool {
	return pkgPath == "flag" && auditset.FlagSurface(name) == auditset.FlagRoleValueRegistration
}

func flagPointerRegistration(pkgPath, name string) bool {
	return pkgPath == "flag" && auditset.FlagSurface(name) == auditset.FlagRolePointerRegistration
}

func (b *tier2Base) flagRegistrationFacts() (map[*ssa.Global]bool, map[string]string) {
	if b.flagBacked != nil {
		return b.flagBacked, b.flagUntraceable
	}
	backed := map[*ssa.Global]bool{}
	poisoned := map[string]string{}
	userPaths := userModulePaths(b.prog.Pkgs)
	var userFunctions []*ssa.Function
	for fn := range progAllFunctions(b.prog) {
		pkgPath := funcPkgPath(fn)
		if pkgPath == "" || (isStdImportPath(pkgPath) && !userPaths[pkgPath]) {
			continue
		}
		userFunctions = append(userFunctions, fn)
	}
	proven := b.flagSetProvenance(userPaths, userFunctions)
	poison := func(fn *ssa.Function, instr ssa.Instruction, what string) {
		pkgPath := funcPkgPath(fn)
		if pkgPath == "" {
			return
		}
		pos := ""
		if b.prog != nil && b.prog.Prog != nil && instr.Pos().IsValid() {
			position := b.prog.Prog.Fset.Position(instr.Pos())
			name := position.Filename
			relative := ""
			if b.h != nil && b.h.dir != "" {
				if rel, err := filepath.Rel(b.h.dir, name); err == nil && !strings.HasPrefix(rel, "..") {
					relative = rel
				}
			}
			if relative != "" {
				name = relative
			} else {
				name = filepath.Base(name)
			}
			pos = fmt.Sprintf(" at %s:%d:%d", name, position.Line, position.Column)
		}
		reason := "flag registration with untraceable sink in " + pkgPath + " (" + what + ")" + pos + "; blocks every subject sharing the test binary"
		if current, ok := poisoned[pkgPath]; !ok || reason < current {
			poisoned[pkgPath] = reason
		}
	}
	for _, fn := range userFunctions {
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				site, ok := instr.(ssa.CallInstruction)
				if !ok || site.Common() == nil {
					continue
				}
				callee := site.Common().StaticCallee()
				if callee == nil {
					continue
				}
				calleePkg, calleeName := funcPkgPath(callee), functionSymbolName(callee)
				args := site.Common().Args
				kind := flagSetUnproven
				if callee.Signature != nil && len(args) > 0 &&
					(callee.Signature.Recv() != nil || flagSetReceiverParam(callee.Signature)) {
					kind = proven[args[0]]
					args = args[1:]
				}
				switch {
				case flagPointerRegistration(calleePkg, calleeName):
					if len(args) == 0 {
						poison(fn, instr, calleeName+" has no pointer argument")
						continue
					}
					g, admitted := provenStorage(kind, args[0], fn)
					if !admitted {
						poison(fn, instr, calleeName+" target is not a package-level variable")
					} else if g != nil && kind != flagSetStartup {
						backed[g] = true
					}
				case flagValueRegistration(calleePkg, calleeName):
					call, ok := instr.(*ssa.Call)
					if !ok {
						continue
					}
					refs := call.Referrers()
					if refs == nil {
						continue
					}
					for _, ref := range *refs {
						if _, ok := ref.(*ssa.DebugRef); ok {
							continue
						}
						if kind == flagSetLocal {
							if load, ok := ref.(*ssa.UnOp); ok && load.Op == token.MUL && load.X == call {
								continue
							}
							if store, ok := ref.(*ssa.Store); ok && store.Addr == call {
								continue
							}
						}
						if store, ok := ref.(*ssa.Store); ok && store.Val == call {
							if g, admitted := provenStorage(kind, store.Addr, fn); admitted && g != nil {
								if kind != flagSetStartup {
									backed[g] = true
								}
								continue
							}
						}
						poison(fn, instr, calleeName+" result escapes its registration site")
					}
				}
			}
		}
	}
	b.flagBacked = backed
	b.flagUntraceable = poisoned
	return backed, poisoned
}

type flagSetKind uint8

const (
	flagSetUnproven flagSetKind = iota
	flagSetStartup
	flagSetLocal
)

func (b *tier2Base) flagSetProvenance(userPaths map[string]bool, userFunctions []*ssa.Function) map[ssa.Value]flagSetKind {
	if b.flagProven != nil {
		return b.flagProven
	}
	proven := map[ssa.Value]flagSetKind{}
	var ctors []*ssa.Call
	globalUses := map[*ssa.Global][]ssa.Instruction{}
	for _, fn := range userFunctions {
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				if call, ok := instr.(*ssa.Call); ok && call.Common() != nil {
					if callee := call.Common().StaticCallee(); callee != nil &&
						funcPkgPath(callee) == "flag" && functionSymbolName(callee) == "NewFlagSet" {
						ctors = append(ctors, call)
					}
				}
				for _, rand := range instr.Operands(nil) {
					if rand == nil || *rand == nil {
						continue
					}
					if g, ok := (*rand).(*ssa.Global); ok {
						globalUses[g] = append(globalUses[g], instr)
					}
				}
			}
		}
	}
	for _, ctor := range ctors {
		var holder *ssa.Global
		var carriers []ssa.Value
		var sites []ssa.CallInstruction
		ok := true
		judgeCarrier := func(v ssa.Value, allowStore bool) {
			carriers = append(carriers, v)
			refs := v.Referrers()
			if refs == nil {
				return
			}
			for _, ref := range *refs {
				switch r := ref.(type) {
				case *ssa.DebugRef:
				case *ssa.Store:
					g, isGlobal := r.Addr.(*ssa.Global)
					if !allowStore || r.Val != v || !isGlobal || holder != nil ||
						g.Pkg == nil || g.Pkg.Pkg == nil || (isStdImportPath(g.Pkg.Pkg.Path()) && !userPaths[g.Pkg.Pkg.Path()]) ||
						!ownInitializerFrame(r.Parent()) {
						ok = false
						return
					}
					holder = g
				case ssa.CallInstruction:
					common := r.Common()
					callee := common.StaticCallee()
					if _, launched := r.(*ssa.Go); launched || callee == nil || len(common.Args) == 0 || common.Args[0] != v ||
						funcPkgPath(callee) != "flag" || !flagProvenSetMethod(functionSymbolName(callee)) {
						ok = false
						return
					}
					sites = append(sites, r)
				default:
					ok = false
					return
				}
			}
		}
		judgeCarrier(ctor, true)
		if ok && holder != nil {
			for _, use := range globalUses[holder] {
				switch u := use.(type) {
				case *ssa.Store:
					if u.Addr != holder || u.Val != ctor {
						ok = false
					}
				case *ssa.UnOp:
					if u.Op != token.MUL || u.X != holder {
						ok = false
					} else {
						judgeCarrier(u, false)
					}
				case *ssa.DebugRef:
				default:
					ok = false
				}
				if !ok {
					break
				}
			}
		}
		if !ok {
			continue
		}
		kind := flagSetLocal
		if holder != nil {
			kind = flagSetStartup
		}
		for _, site := range sites {
			if kind == flagSetStartup && !ownInitializerFrame(site.Parent()) {
				ok = false
				break
			}
			callee := site.Common().StaticCallee()
			if functionSymbolName(callee) == "Parse" &&
				(len(site.Common().Args) != 2 || !closedParseArgument(site.Common().Args[1])) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		for _, carrier := range carriers {
			proven[carrier] = kind
		}
	}
	b.flagProven = proven
	return proven
}

func flagProvenSetMethod(name string) bool {
	return name == "Parse" || name == "ErrorHandling" || auditset.FlagSurface(name).IsRegistration()
}

func flagProvenSetUse(proven map[ssa.Value]flagSetKind, pkgPath, name string, c *ssa.CallCommon) bool {
	if pkgPath != "flag" || len(c.Args) == 0 || proven[c.Args[0]] == flagSetUnproven {
		return false
	}
	return name == "Parse" || auditset.FlagSurface(name).IsRegistration()
}

func closedParseArgument(v ssa.Value) bool {
	if c, ok := v.(*ssa.Const); ok {
		return c.Value == nil
	}
	slice, _, ok := forEachLocalSliceAllocStore(v, func(_ *ssa.IndexAddr, val ssa.Value) bool {
		c, isConst := val.(*ssa.Const)
		return isConst && c.Value != nil
	})
	return ok && slice.Low == nil && slice.High == nil && slice.Max == nil
}

func ownInitializerFrame(fn *ssa.Function) bool {
	return fn != nil && fn.Parent() == nil && initFlowFrame(fn)
}

func provenStorage(kind flagSetKind, addr ssa.Value, fn *ssa.Function) (*ssa.Global, bool) {
	switch root := addressRoot(addr).(type) {
	case *ssa.Global:
		return root, true
	case *ssa.Alloc:
		return nil, kind == flagSetLocal && root.Parent() == fn && confinedLocalStorage(root, map[ssa.Value]bool{})
	}
	return nil, false
}

func flagSetReceiverParam(sig *types.Signature) bool {
	if sig == nil || sig.Recv() != nil || sig.Params() == nil || sig.Params().Len() == 0 {
		return false
	}
	ptr, ok := types.Unalias(sig.Params().At(0).Type()).(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := types.Unalias(ptr.Elem()).(*types.Named)
	return ok && named.Obj() != nil && named.Obj().Pkg() != nil &&
		named.Obj().Pkg().Path() == "flag" && named.Obj().Name() == "FlagSet"
}

func flagRegistrationWriteShape(instr ssa.Instruction) bool {
	switch x := instr.(type) {
	case ssa.CallInstruction:
		if x.Common() == nil {
			return false
		}
		callee := x.Common().StaticCallee()
		return callee != nil && flagRegistrationSymbol(funcPkgPath(callee), functionSymbolName(callee))
	case *ssa.Store:
		call, ok := x.Val.(*ssa.Call)
		if !ok || call.Common() == nil {
			return false
		}
		callee := call.Common().StaticCallee()
		return callee != nil && flagValueRegistration(funcPkgPath(callee), functionSymbolName(callee))
	}
	return false
}

func recordFlagBackedReferences(backed map[*ssa.Global]bool, zeroGlobals map[*ssa.Global]bool, record func(externalEffect), instr ssa.Instruction) {
	if len(backed) == 0 || flagRegistrationWriteShape(instr) {
		return
	}
	switch x := instr.(type) {
	case *ssa.FieldAddr:
		if registrationAddressComputation(x, map[ssa.Value]bool{}) {
			return
		}
	case *ssa.IndexAddr:
		if registrationAddressComputation(x, map[ssa.Value]bool{}) {
			return
		}
	}
	for _, rand := range instr.Operands(nil) {
		if rand == nil || *rand == nil {
			continue
		}
		if g, ok := (*rand).(*ssa.Global); ok && backed[g] && !zeroGlobals[g] {
			record(flagBackedReadEffect(g))
		}
	}
}

func flagBackedReadEffect(g *ssa.Global) externalEffect {
	pkgPath := ""
	if g.Pkg != nil && g.Pkg.Pkg != nil {
		pkgPath = g.Pkg.Pkg.Path()
	}
	return symbolExternalEffect(externalEffectEnvironment, pkgPath, g.Name(), "references flag-registered state "+g.String()+" (storage flag.Parse writes from the command line, a channel the test log cannot audit)")
}

func packageWideMaximalHazard(effect externalEffect) bool {
	if effect.packagePath == "unsafe" && effect.symbol != "Pointer" && !isCompileTimeUnsafeIntrinsic(effect.packagePath, effect.symbol) {
		return true
	}
	if effect.packagePath == "os" && effect.symbol == "Exit" {
		return true
	}
	if effect.packagePath == "testing" && (effect.symbol == "Setenv" || effect.symbol == "Chdir") {
		return true
	}
	if effect.packagePath == "os" || effect.packagePath == "syscall" || strings.HasPrefix(effect.packagePath, "golang.org/x/sys/") {
		switch effect.symbol {
		case "Setenv", "Unsetenv", "Clearenv", "Chdir", "Fchdir":
			return true
		}
	}
	return false
}

func isConditionallyConfinedUnsafeSymbol(effect externalEffect) bool {
	return effect.packagePath == "unsafe" && (effect.symbol == "StringData" || effect.symbol == "Slice")
}

func packageWideMaximalHazardForPkg(effect externalEffect, pkgConfinedUnsafe bool) bool {
	if pkgConfinedUnsafe && isConditionallyConfinedUnsafeSymbol(effect) {
		return false
	}
	return packageWideMaximalHazard(effect)
}

func hasFilterableMaximalBlocker(audited bool, effects []externalEffect) bool {
	for _, effect := range effects {
		if maximalObservabilityBlocker(audited, effect) && (!packageWideMaximalHazard(effect) || isConditionallyConfinedUnsafeSymbol(effect)) {
			return true
		}
	}
	return false
}

func hasAnyMaximalBlocker(audited bool, effects []externalEffect) bool {
	for _, effect := range effects {
		if maximalObservabilityBlocker(audited, effect) {
			return true
		}
	}
	return false
}
