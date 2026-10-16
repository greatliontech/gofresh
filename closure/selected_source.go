package closure

import (
	"context"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/printer"
	"go/token"
	"go/types"
	"hash"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/greatliontech/go-x-tools/go/packages"
	"github.com/greatliontech/go-x-tools/go/ssa"
)

type selectedSourceLimits struct{ work, depth, bytes int }

// selectedSourceBinder owns input identity, not a semantic grammar. Its loader
// objects belong to one immutable, pass-local source owner. Consumers may inspect
// the bound syntax, types and SSA within that pass, but only frozen identities
// belong in evidence. Native inputs and directives are inventory, not approval
// or proof of their behavior (nor hashes of unavailable native file contents).
// Every consumer shares this binder's work/byte counter with its interpretation;
// creating another counter would allow a derivation to spend its bound twice.
type selectedSourceBinder struct {
	ctx         context.Context
	source      computationSource
	limits      selectedSourceLimits
	work, bytes int
	pkgs        map[*types.Package]*packages.Package
	metas       map[string]listPkg
	packages    map[*packages.Package]selectedSourcePackage
	bound       map[*ssa.Function]selectedSourceDeclaration
}

type selectedSourceInput struct{ kind, name string }
type selectedSourceDirective struct {
	text string
	at   token.Pos
}

// The source digest preserves the existing canonical selected-Go encoding.
// Other input names describe open implementation boundaries, not covered bytes.
type selectedSourcePackage struct {
	digest       [32]byte
	declarations map[*ssa.Function]*ast.FuncDecl
	directives   []selectedSourceDirective
	otherInputs  []selectedSourceInput
}

type selectedSourceIdentity struct {
	packageID, function, position string
	source, body                  [32]byte
}

// A declaration may have no Go body. Binding it proves only its exact selected
// ownership. Generated package init has no declaration and cannot enter here:
// its synthetic label is never ownership evidence. A consumer modeling that
// construction must reconstruct its exact SSA/AST initialization association.
type selectedSourceDeclaration struct {
	identity selectedSourceIdentity
	pkg      *packages.Package
	decl     *ast.FuncDecl
}

func newSelectedSourceBinder(ctx context.Context, source computationSource, root *ssa.Function, limits selectedSourceLimits) (*selectedSourceBinder, error) {
	if ctx == nil || limits.work <= 0 || limits.depth <= 0 || limits.bytes <= 0 {
		return nil, computationRefusal(root, token.NoPos, "invalid selected source context or budget")
	}
	if source.prog == nil || source.prog.Prog == nil || root == nil || root.Prog != source.prog.Prog {
		return nil, computationRefusal(root, token.NoPos, "local relation root has no selected owner")
	}
	c := &selectedSourceBinder{ctx: ctx, source: source, limits: limits,
		pkgs: map[*types.Package]*packages.Package{}, metas: map[string]listPkg{},
		packages: map[*packages.Package]selectedSourcePackage{}, bound: map[*ssa.Function]selectedSourceDeclaration{}}
	for _, p := range source.prog.Pkgs {
		if err := c.tick(root, root.Pos()); err != nil {
			return nil, err
		}
		if p == nil || p.Types == nil || c.pkgs[p.Types] != nil {
			return nil, computationRefusal(root, root.Pos(), "duplicate or absent selected typed package")
		}
		if err := c.chargeBytes(root, root.Pos(), len(p.ID)); err != nil {
			return nil, err
		}
		if err := c.chargeBytes(root, root.Pos(), len(p.Types.Path())); err != nil {
			return nil, err
		}
		c.pkgs[p.Types] = p
	}
	for _, m := range source.metas {
		if err := c.tick(root, root.Pos()); err != nil {
			return nil, err
		}
		if err := c.chargeBytes(root, root.Pos(), len(m.ImportPath)); err != nil {
			return nil, err
		}
		if _, exists := c.metas[m.ImportPath]; exists {
			return nil, computationRefusal(root, root.Pos(), "duplicate selected package metadata")
		}
		c.metas[m.ImportPath] = m
	}
	return c, nil
}

func (c *selectedSourceBinder) tick(fn *ssa.Function, at token.Pos) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	c.work++
	if c.work > c.limits.work {
		return computationRefusal(fn, at, "local relation work budget exhausted")
	}
	return nil
}

// chargeBytes accounts for input payload before any scan/copy/format, and for
// encoded bytes before hashing them. The remaining-budget comparison cannot
// overflow even for an adversarial string length.
func (c *selectedSourceBinder) chargeBytes(fn *ssa.Function, at token.Pos, n int) error {
	if err := c.tick(fn, at); err != nil {
		return err
	}
	if n < 0 || n > c.limits.bytes-c.bytes {
		return computationRefusal(fn, at, "local relation byte budget exhausted")
	}
	c.bytes += n
	return nil
}

type selectedSourceHash struct {
	c   *selectedSourceBinder
	fn  *ssa.Function
	at  token.Pos
	h   hash.Hash
	err error
}

func (c *selectedSourceBinder) hasher(fn *ssa.Function, at token.Pos) *selectedSourceHash {
	return &selectedSourceHash{c: c, fn: fn, at: at, h: sha256.New()}
}

func (w *selectedSourceHash) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.err = w.c.chargeBytes(w.fn, w.at, len(p)); w.err != nil {
		return 0, w.err
	}
	n := 0
	for len(p) != 0 {
		if w.err = w.c.tick(w.fn, w.at); w.err != nil {
			return n, w.err
		}
		chunk := min(len(p), 4096)
		w.h.Write(p[:chunk])
		n += chunk
		p = p[chunk:]
	}
	return n, nil
}

func (w *selectedSourceHash) sum() [32]byte {
	var sum [32]byte
	copy(sum[:], w.h.Sum(nil))
	return sum
}

// Canonical selected syntax preserves import order and literal spelling. Use
// the printer directly: format.Node may first buffer an entire unsorted file.
// Syntax preflight bounds the printer's token buffer and build normalization;
// tabular padding then streams through the byte-limited, cancellable writer.
func selectedSourcePrint(dst *selectedSourceHash, fset *token.FileSet, node ast.Node) error {
	config := printer.Config{Mode: printer.TabIndent | printer.UseSpaces, Tabwidth: 8}
	return config.Fprint(dst, fset, node)
}

// ast.Walk cannot stop visiting siblings by returning nil. This private sentinel
// unwinds the whole walk at the first refusal without swallowing other panics.
type selectedSourceWalkStop struct{ err error }
type selectedSourceAST struct {
	c                                *selectedSourceBinder
	fn                               *ssa.Function
	at                               token.Pos
	depth                            int
	constraintUnits, constraintBytes int
	directives                       []selectedSourceDirective
	seenDirectives                   map[*ast.Comment]bool
}

func (v *selectedSourceAST) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		v.depth--
		return nil
	}
	v.depth++
	stop := func(err error) {
		if err != nil {
			panic(selectedSourceWalkStop{err})
		}
	}
	// Node.Pos recursively descends left operands/selectors. Keep diagnostics at
	// a stored position until the walk has checked the subtree's depth and work.
	stop(v.c.tick(v.fn, v.at))
	if v.depth > v.c.limits.depth {
		stop(computationRefusal(v.fn, v.at, "local relation syntax depth budget exhausted"))
	}
	// Bound internal punctuation/indentation buffers before invoking the printer.
	stop(v.c.chargeBytes(v.fn, v.at, 32))
	for range v.depth {
		stop(v.c.chargeBytes(v.fn, v.at, 8))
	}
	var text string
	switch n := n.(type) {
	case *ast.Ident:
		text = n.Name
	case *ast.BasicLit:
		text = n.Value
	case *ast.Comment:
		text = n.Text
	case *ast.File:
		text = n.GoVersion
	}
	stop(v.c.chargeBytes(v.fn, v.at, len(text)))
	if comment, ok := n.(*ast.Comment); ok {
		if strings.HasPrefix(comment.Text, "//go:") && !strings.HasPrefix(comment.Text, "//go:build ") && !v.seenDirectives[comment] {
			v.seenDirectives[comment] = true
			v.directives = append(v.directives, selectedSourceDirective{comment.Text, comment.Slash})
		}
		stop(v.buildConstraint(comment.Text))
	}
	return v
}

// buildConstraint bounds the hidden tree go/printer builds when joining legacy
// lines. Tag runs reserve a leaf and implicit join; punctuation reserves an
// operator and possible empty tag. Across the file, units bound recursion and
// bytes times units bounds repeated subtree copying, for both spellings.
func (v *selectedSourceAST) buildConstraint(text string) error {
	if !constraint.IsGoBuild(text) && !constraint.IsPlusBuild(text) {
		return nil
	}
	units := 0
	inTag := false
	for _, r := range text {
		if err := v.c.tick(v.fn, v.at); err != nil {
			return err
		}
		switch {
		case unicode.IsSpace(r):
			inTag = false
		case strings.ContainsRune("!(),&|", r):
			units += 2
			inTag = false
		default:
			if !inTag {
				units += 2
			}
			inTag = true
		}
		if units > v.c.limits.depth-v.constraintUnits {
			return computationRefusal(v.fn, v.at, "local relation build-constraint depth budget exhausted")
		}
	}
	// Eight bytes per unit cover generated separators, parentheses, negations
	// and replacement of malformed tags by "ignore". Check before multiplying.
	total := v.constraintUnits + units
	chargeCopies := func(size, copies int) error {
		if copies != 0 && size > (v.c.limits.bytes-v.c.bytes)/copies {
			return computationRefusal(v.fn, v.at, "local relation build-constraint byte budget exhausted")
		}
		return v.c.chargeBytes(v.fn, v.at, size*copies)
	}
	if err := chargeCopies(v.constraintBytes, units); err != nil {
		return err
	}
	if err := chargeCopies(len(text), total); err != nil {
		return err
	}
	for range 8 {
		if err := chargeCopies(units, total); err != nil {
			return err
		}
	}
	v.constraintUnits = total
	v.constraintBytes += len(text) + 8*units
	return nil
}

func (c *selectedSourceBinder) preflightSyntax(fn *ssa.Function, file *ast.File) (directives []selectedSourceDirective, err error) {
	defer func() {
		if p := recover(); p != nil {
			if stop, ok := p.(selectedSourceWalkStop); ok {
				err = stop.err
			} else {
				panic(p)
			}
		}
	}()
	v := &selectedSourceAST{c: c, fn: fn, seenDirectives: map[*ast.Comment]bool{}}
	if fn != nil {
		v.at = fn.Pos()
	}
	ast.Walk(v, file)
	// File.Comments includes unattached comments omitted by ast.Walk, as well
	// as attached comments already charged conservatively above.
	for _, group := range file.Comments {
		ast.Walk(v, group)
	}
	return v.directives, nil
}

// selectedPackage validates and hashes each package once per pass. Preflight
// precedes all printing; a bounded writer alone cannot bound printer buffering.
func (c *selectedSourceBinder) selectedPackage(fn *ssa.Function, p *packages.Package) (selectedSourcePackage, error) {
	var zero selectedSourcePackage
	if p == nil || p.Types == nil || c.pkgs[p.Types] != p || p.TypesInfo == nil || p.Fset == nil || p.Fset != c.source.prog.Prog.Fset || p.TypesSizes == nil || c.source.prog.Prog.Package(p.Types) == nil {
		return zero, computationRefusal(fn, token.NoPos, "incomplete local selected package or type-size binding")
	}
	if prior, ok := c.packages[p]; ok {
		return prior, nil
	}
	m, ok := c.metas[p.ID]
	if !ok {
		return zero, computationRefusal(fn, fn.Pos(), "selected package metadata is absent")
	}
	files := map[string]bool{}
	if err := c.chargeBytes(fn, fn.Pos(), len(m.Dir)); err != nil {
		return zero, err
	}
	for _, name := range m.GoFiles {
		if err := c.chargeBytes(fn, fn.Pos(), len(name)); err != nil {
			return zero, err
		}
		if err := c.chargeBytes(fn, fn.Pos(), len(m.Dir)); err != nil {
			return zero, err
		}
		// Generated test-main files may already be absolute cache paths.
		// Only relative listing entries are interpreted under the package directory.
		if !filepath.IsAbs(name) {
			name = filepath.Join(m.Dir, name)
		}
		files[filepath.Clean(name)] = true
	}
	if len(files) == 0 || len(files) != len(p.Syntax) || len(files) != len(p.CompiledGoFiles) {
		return zero, computationRefusal(fn, fn.Pos(), "incomplete local selected source")
	}
	names := make([]string, len(p.Syntax))
	selected := selectedSourcePackage{declarations: map[*ssa.Function]*ast.FuncDecl{}}
	for i, file := range p.Syntax {
		if err := c.tick(fn, fn.Pos()); err != nil {
			return zero, err
		}
		if file == nil {
			return zero, computationRefusal(fn, fn.Pos(), "nil selected syntax")
		}
		name := p.Fset.PositionFor(file.Pos(), false).Filename
		if err := c.chargeBytes(fn, file.Pos(), len(name)); err != nil {
			return zero, err
		}
		if err := c.chargeBytes(fn, file.Pos(), len(p.CompiledGoFiles[i])); err != nil {
			return zero, err
		}
		name = filepath.Clean(name)
		if !files[name] || name != filepath.Clean(p.CompiledGoFiles[i]) {
			return zero, computationRefusal(fn, file.Pos(), "local selected source disagrees with syntax")
		}
		delete(files, name)
		names[i] = name
		directives, err := c.preflightSyntax(fn, file)
		if err != nil {
			return zero, err
		}
		selected.directives = append(selected.directives, directives...)
	}
	for _, input := range []struct {
		kind  string
		names []string
	}{
		{"cgo", m.CgoFiles}, {"c", m.CFiles}, {"cxx", m.CXXFiles}, {"objc", m.MFiles},
		{"header", m.HFiles}, {"fortran", m.FFiles}, {"assembly", m.SFiles},
		{"swig", m.SwigFiles}, {"swig-cxx", m.SwigCXXFiles}, {"syso", m.SysoFiles}, {"embed", m.EmbedFiles},
	} {
		for _, name := range input.names {
			if err := c.chargeBytes(fn, fn.Pos(), len(name)); err != nil {
				return zero, err
			}
			selected.otherInputs = append(selected.otherInputs, selectedSourceInput{input.kind, name})
		}
	}
	content := c.hasher(fn, fn.Pos())
	for i, file := range p.Syntax {
		if err := c.tick(fn, file.Pos()); err != nil {
			return zero, err
		}
		if _, err := fmt.Fprintf(content, "%q\n", names[i]); err != nil {
			return zero, err
		}
		if err := selectedSourcePrint(content, p.Fset, file); err != nil {
			if content.err != nil {
				return zero, content.err
			}
			return zero, computationRefusal(fn, file.Pos(), "selected syntax cannot be encoded")
		}
		for _, d := range file.Decls {
			if err := c.tick(fn, d.Pos()); err != nil {
				return zero, err
			}
			decl, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			obj, _ := p.TypesInfo.Defs[decl.Name].(*types.Func)
			if obj == nil {
				return zero, computationRefusal(fn, decl.Pos(), "function declaration has no selected binding")
			}
			bound := c.source.prog.Prog.FuncValue(obj)
			if bound == nil {
				continue
			}
			if selected.declarations[bound] != nil {
				return zero, computationRefusal(fn, decl.Pos(), "duplicate selected function declaration")
			}
			selected.declarations[bound] = decl
		}
	}
	selected.digest = content.sum()
	c.packages[p] = selected
	return selected, nil
}

func (c *selectedSourceBinder) bindDeclaration(fn *ssa.Function) (selectedSourceDeclaration, error) {
	var zero selectedSourceDeclaration
	if fn == nil || fn.Pkg == nil || fn.Prog != c.source.prog.Prog {
		return zero, computationRefusal(fn, token.NoPos, "callee has no selected source package")
	}
	p := c.pkgs[fn.Pkg.Pkg]
	if p == nil || c.source.prog.Prog.Package(p.Types) != fn.Pkg {
		return zero, computationRefusal(fn, fn.Pos(), "incomplete local selected package or type-size binding")
	}
	if prior, ok := c.bound[fn]; ok {
		return prior, nil
	}
	selected, err := c.selectedPackage(fn, p)
	if err != nil {
		return zero, err
	}
	decl := selected.declarations[fn]
	if decl == nil || fn.Syntax() != decl || fn.Object() != p.TypesInfo.Defs[decl.Name] {
		return zero, computationRefusal(fn, fn.Pos(), "selected function body binding disagrees")
	}
	body := c.hasher(fn, fn.Pos())
	if err := selectedSourcePrint(body, p.Fset, decl); err != nil {
		if body.err != nil {
			return zero, body.err
		}
		return zero, computationRefusal(fn, fn.Pos(), "selected function syntax cannot be encoded")
	}
	identity := selectedSourceIdentity{packageID: p.ID, function: fn.String(), position: p.Fset.PositionFor(fn.Pos(), false).String(), source: selected.digest, body: body.sum()}
	bound := selectedSourceDeclaration{identity: identity, pkg: p, decl: decl}
	c.bound[fn] = bound
	return bound, nil
}
