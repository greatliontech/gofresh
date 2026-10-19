package closure

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
	br "github.com/greatliontech/gofresh/internal/bitrelation"
	"github.com/greatliontech/gofresh/internal/nativeproof"
	"golang.org/x/arch/x86/x86asm"
)

const assemblyReferenceRules = "gofresh/selected-assembly-reference@2;go-amd64-abi0;" + br.RuleModel + ";" + nativeproof.TransferRules

// assemblyReference is source-owned evidence, not an observed native image. Only
// checking a selected acquisition and its complete provider scope constructs it.
// Its private ABI frame is a specification allocation: it grants no storage or
// permission to an actual native continuation. Actual-use, native correspondence,
// isolation, omitted-prefix and runtime applicability remain separate obligations.
type assemblyReference struct{ checked *assemblyReferenceProof }

type assemblyReferenceProof struct {
	owner       *selectedSourceOwner
	program     *program
	target      *ssa.Function
	declaration selectedSourceDeclaration
	provider    *packages.Package
	acquisition *selectedAssemblyPacket
	rules       string
	relation    *assemblyReferenceRelation
	limits      assemblyReferenceLimits
	work        int
}

type assemblyReferenceAccess struct {
	Write, Locked bool
	Value         uint64
}

type assemblyReferenceResult struct {
	Value    uint64
	Result   regionValue
	Accesses []assemblyReferenceAccess
	Atomics  []assemblyReferenceAtomic
}

// Indices address the projected access sequence; Statement identifies the actual
// checked assembly occurrence. Kind records ISA semantics, not a callee summary.
type assemblyReferenceAtomic struct {
	Statement               int
	Kind                    x86asm.Op
	ReadAccess, WriteAccess int
}

type assemblyReferenceLimits struct {
	source                                  selectedSourceLimits
	instructions, nodes, work, bytes, depth int
}

func defaultAssemblyReferenceLimits() assemblyReferenceLimits {
	return assemblyReferenceLimits{source: selectedSourceLimits{work: 20_000_000, depth: 256, bytes: 256 << 20}, instructions: 4096, nodes: 32768, work: 2_000_000, bytes: 16 << 20, depth: 256}
}

func assemblyReferenceBudget(l assemblyReferenceLimits) (assemblyReferenceLimits, error) {
	d := defaultAssemblyReferenceLimits()
	if l == (assemblyReferenceLimits{}) {
		return d, nil
	}
	if l.source == (selectedSourceLimits{}) {
		l.source = d.source
	}
	if l.instructions <= 0 || l.instructions > 65536 || l.nodes <= 0 || l.nodes > 1<<20 || l.work <= 0 || l.work > 20_000_000 || l.bytes <= 0 || l.bytes > 256<<20 || l.depth <= 0 || l.depth > 512 {
		return l, assemblyReferenceError("invalid resource limits")
	}
	return l, nil
}

func assemblyReferenceError(message string) error {
	return fmt.Errorf("selected assembly reference: %s", message)
}

// The context wrapper makes every subordinate scalar-proof and ISA-kernel
// checkpoint spend this derivation's account, as well as its caller's account.
type assemblyReferenceMeter struct {
	context.Context
	limits      assemblyReferenceLimits
	work, bytes int
}

func (m *assemblyReferenceMeter) Err() error {
	if m.Context == nil {
		return assemblyReferenceError("missing context")
	}
	if err := m.Context.Err(); err != nil {
		return err
	}
	if m.work >= m.limits.work {
		return assemblyReferenceError("work budget exhausted")
	}
	m.work++
	return nil
}

func (m *assemblyReferenceMeter) chargeBytes(n int) error {
	if err := m.Err(); err != nil {
		return err
	}
	if n < 0 || n > m.limits.bytes-m.bytes {
		return assemblyReferenceError("byte budget exhausted")
	}
	m.bytes += n
	return nil
}

func checkAssemblyReference(ctx context.Context, source computationSource, target *ssa.Function, packet *selectedAssemblyPacket, limits assemblyReferenceLimits) (*assemblyReference, error) {
	l, err := assemblyReferenceBudget(limits)
	if err != nil {
		return nil, err
	}
	m := &assemblyReferenceMeter{Context: ctx, limits: l}
	if err := m.Err(); err != nil {
		return nil, err
	}
	if source.owner == nil || packet == nil || target == nil {
		return nil, assemblyReferenceError("missing immutable source owner, declaration or acquisition")
	}
	p, err := source.owner.packageFor(target)
	if err != nil {
		return nil, err
	}
	if !packet.boundTo(source, p) {
		return nil, assemblyReferenceError("acquisition belongs to another selected package owner")
	}
	if packet.selectionEnv()["GOARCH"] != "amd64" {
		return nil, assemblyReferenceError("selected assembly machine is not amd64")
	}
	for _, flag := range packet.selectionFlags() {
		if err := m.chargeBytes(len(flag)); err != nil {
			return nil, err
		}
		name, _, _ := strings.Cut(strings.TrimLeft(flag, "-"), "=")
		switch name {
		case "race", "asan", "msan", "cover", "covermode", "coverpkg", "compiler", "buildmode", "linkshared":
			return nil, assemblyReferenceError("unsupported selected instrumentation or ABI transformation: " + name)
		}
	}
	b, err := newSelectedSourceBinder(ctx, source, target, l.source)
	if err != nil {
		return nil, err
	}
	decl, err := b.bindDeclaration(target)
	if err != nil {
		return nil, err
	}
	if decl.pkg != p || decl.decl.Body != nil || decl.decl.Recv != nil || len(target.Blocks) != 0 || target.Signature != target.Object().Type() || target.Synthetic != "" || len(target.FreeVars) != 0 {
		return nil, assemblyReferenceError("target is not the exact selected bodyless declaration")
	}
	inventory := b.packages[p]
	for _, input := range inventory.otherInputs {
		if err := m.Err(); err != nil {
			return nil, err
		}
		if input.kind != "assembly" && input.kind != "header" {
			return nil, assemblyReferenceError("competing opaque compilation input: " + input.kind)
		}
	}
	if err := assemblyReferenceDirectives(m, b, p, inventory); err != nil {
		return nil, err
	}
	frame, err := assemblyReferenceABI(target.Signature, p.TypesSizes)
	if err != nil {
		return nil, err
	}
	providers := packet.providerTexts()
	meta := b.metas[p.ID]
	members := map[string]bool{}
	for _, name := range meta.SFiles {
		if err := m.chargeBytes(len(name)); err != nil {
			return nil, err
		}
		if !filepath.IsAbs(name) {
			name = filepath.Join(meta.Dir, name)
		}
		members[filepath.Clean(name)] = true
	}
	if len(members) != len(providers) {
		return nil, assemblyReferenceError("acquisition omits selected assembly providers")
	}
	for _, provider := range providers {
		if !members[filepath.Clean(provider.Source)] {
			return nil, assemblyReferenceError("acquisition contains another selected provider")
		}
		delete(members, filepath.Clean(provider.Source))
	}
	definitions, err := assemblyReferenceDefinitions(m, providers, p.PkgPath)
	if err != nil {
		return nil, err
	}
	// The compilation unit's Go definitions participate in the same symbol
	// namespace. A bodyful declaration cannot be silently replaced by TEXT.
	for fn, goDecl := range inventory.declarations {
		if err := m.Err(); err != nil {
			return nil, err
		}
		if goDecl.Recv != nil {
			continue // method symbol spellings are refused by the TEXT grammar
		}
		name := assemblyReferencePackagePrefix(p.PkgPath) + "." + fn.Name()
		if goDecl.Body != nil {
			for _, definition := range definitions {
				if err := m.Err(); err != nil {
					return nil, err
				}
				if definition.symbol.name == name && definition.symbol.local == "" {
					return nil, assemblyReferenceError("TEXT competes with a selected Go definition")
				}
			}
		}
	}
	name := assemblyReferencePackagePrefix(p.PkgPath) + "." + decl.decl.Name.Name
	var definition *assemblyReferenceDefinition
	for i := range definitions {
		if err := m.Err(); err != nil {
			return nil, err
		}
		d := &definitions[i]
		if d.symbol.name != name || d.symbol.local != "" {
			continue
		}
		if definition != nil || d.symbol.abi != "ABI0" {
			return nil, assemblyReferenceError("ambiguous provider or incompatible definition ABI")
		}
		definition = d
	}
	if definition == nil {
		return nil, assemblyReferenceError("no unique external selected TEXT provider")
	}
	relation, err := assemblyReferenceInterpret(m, *definition, frame)
	if err != nil {
		return nil, err
	}
	if err := m.Err(); err != nil {
		return nil, err
	}
	return &assemblyReference{checked: &assemblyReferenceProof{owner: source.owner, program: source.prog, target: target, declaration: decl, provider: p, acquisition: packet, rules: assemblyReferenceRules, relation: relation, limits: l, work: m.work}}, nil
}

// boundTo only checks retained identity. It never constructs a relation, changes
// a builder, or borrows a declaration from an equal-text independent load.
func (r *assemblyReference) boundTo(source computationSource, target *ssa.Function) error {
	if r == nil || r.checked == nil {
		return assemblyReferenceError("missing checked reference")
	}
	p := r.checked
	if p.rules != assemblyReferenceRules || p.owner == nil || source.owner != p.owner || source.prog != p.program || target != p.target || target == nil || source.prog == nil || target.Prog != source.prog.Prog || p.relation == nil || !p.acquisition.boundTo(source, p.provider) {
		return assemblyReferenceError("reference has another exact source/declaration owner")
	}
	return nil
}

func assemblyReferenceDirectives(m *assemblyReferenceMeter, b *selectedSourceBinder, p *packages.Package, inventory selectedSourcePackage) error {
	links := map[types.Object]bool{}
	attached := map[token.Pos]*ast.FuncDecl{}
	for _, decl := range inventory.declarations {
		if decl.Doc != nil {
			for _, comment := range decl.Doc.List {
				if err := m.Err(); err != nil {
					return err
				}
				attached[comment.Slash] = decl
			}
		}
	}
	seen := map[*ast.FuncDecl]map[string]bool{}
	for _, directive := range inventory.directives {
		if err := m.chargeBytes(len(directive.text)); err != nil {
			return err
		}
		if directive.file == nil || p.Fset.PositionFor(directive.at, false).Column != 1 {
			return assemblyReferenceError("unsupported declaration directive placement")
		}
		fields := strings.Fields(directive.text)
		if len(fields) == 2 && (fields[0] == "//go:linkname" || fields[0] == "//go:linknamestd") && strings.HasPrefix(directive.text, fields[0]+" ") {
			unsafeImport := false
			for _, spec := range directive.file.Imports {
				if err := m.Err(); err != nil {
					return err
				}
				path, err := strconv.Unquote(spec.Path.Value)
				if err != nil || path != "unsafe" {
					continue
				}
				object := p.TypesInfo.Implicits[spec]
				if spec.Name != nil {
					object = p.TypesInfo.Defs[spec.Name]
				}
				name, ok := object.(*types.PkgName)
				unsafeImport = ok && name.Pkg() == p.Types && name.Imported() == types.Unsafe
			}
			object, ok := p.Types.Scope().Lookup(fields[1]).(*types.Func)
			if !ok || !unsafeImport || object.Pkg() != p.Types || object.Parent() != p.Types.Scope() || links[object] {
				return assemblyReferenceError("linkname lacks a unique local function and directive-file unsafe import")
			}
			fn := b.source.prog.Prog.FuncValue(object)
			decl := inventory.declarations[fn]
			if fn == nil || decl == nil || decl.Recv != nil || decl.Name.Name != fields[1] || p.TypesInfo.Defs[decl.Name] != object || fn.Object() != object || fn.Syntax() != decl || fn.Signature != object.Type() {
				return assemblyReferenceError("linkname local declaration ownership disagrees")
			}
			links[object] = true
			continue
		}
		// These compiler-facing annotations neither redirect definitions nor
		// prove their bodies. noescape is discharged by interpreted effects.
		if len(fields) != 1 || fields[0] != "//go:noescape" && fields[0] != "//go:nosplit" && fields[0] != "//go:noinline" {
			return assemblyReferenceError("unsupported, malformed or redirecting declaration directive")
		}
		decl := attached[directive.at]
		if decl == nil || fields[0] == "//go:noescape" && decl.Body != nil {
			return assemblyReferenceError("directive lacks its applicable actual declaration")
		}
		if seen[decl] == nil {
			seen[decl] = map[string]bool{}
		}
		if seen[decl][fields[0]] {
			return assemblyReferenceError("duplicate declaration directive")
		}
		seen[decl][fields[0]] = true
	}
	return nil
}
