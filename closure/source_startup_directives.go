package closure

import (
	"go/types"
	"strconv"
	"strings"

	"github.com/greatliontech/go-x-tools/go/packages"
)

// sourceStartupDirectives admits declaration inventory, never linkage semantics.
// A bodyless function has no storage or executable body in the ordinary source
// model. Its linkname's exact spelling remains in inventory.directives, unresolved;
// calls still require a source body. In particular, a remote name never selects a
// nominal body to interpret. Bodyful and variable aliases retain their refusal.
func (c *selectedSourceBinder) sourceStartupDirectives(p *packages.Package, inventory selectedSourcePackage) error {
	seen := map[*types.Func]bool{}
	for _, directive := range inventory.directives {
		fail := func(detail string) error {
			return computationRefusal(nil, directive.at, detail)
		}
		if err := c.chargeBytes(nil, directive.at, len(directive.text)); err != nil {
			return err
		}
		// The compiler recognizes the literal space after the verb, then splits
		// fields. This subset requires column one: it establishes a standalone
		// directive without guessing the source prefix from a normalized AST.
		if !strings.HasPrefix(directive.text, "//go:linkname ") || directive.file == nil || p.Fset.PositionFor(directive.at, false).Column != 1 {
			return fail("unsupported source startup directive or placement")
		}
		var fields [3]string
		n := 0
		for field := range strings.FieldsSeq(directive.text) {
			if err := c.tick(nil, directive.at); err != nil {
				return err
			}
			if n == len(fields) {
				return fail("malformed function linkname directive")
			}
			fields[n] = field
			n++
		}
		if n < 2 || n == 3 && strings.Contains(fields[2], "[") && strings.Contains(fields[2], "]") {
			return fail("malformed or instantiated function linkname directive")
		}
		unsafeImport := false
		for _, spec := range directive.file.Imports {
			if err := c.chargeBytes(nil, directive.at, len(spec.Path.Value)); err != nil {
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
		if !unsafeImport {
			return fail("function linkname requires a selected file-local unsafe import")
		}
		object, ok := p.Types.Scope().Lookup(fields[1]).(*types.Func)
		if !ok || object.Pkg() != p.Types || object.Parent() != p.Types.Scope() {
			return fail("linkname does not bind a selected package function")
		}
		if seen[object] {
			return fail("duplicate or conflicting function linkname directive")
		}
		seen[object] = true
		function := c.source.prog.Prog.FuncValue(object)
		decl := inventory.declarations[function]
		owner := c.source.prog.Prog.Package(p.Types)
		if function == nil || decl == nil || decl.Body != nil || decl.Recv != nil || decl.Name.Name != fields[1] || p.TypesInfo.Defs[decl.Name] != object || function.Syntax() != decl || function.Object() != object || function.Prog != c.source.prog.Prog || function.Pkg != owner || owner.Func(fields[1]) != function || function.Signature != object.Type() || len(function.Blocks) != 0 {
			return fail("linkname requires the exact selected bodyless function declaration")
		}
	}
	return nil
}
