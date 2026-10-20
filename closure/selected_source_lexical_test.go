package closure

import (
	"context"
	"errors"
	"go/ast"
	"testing"
)

func TestSelectedSourceLexicalIndexSharesCheckedParent(t *testing.T) {
	s := sourceRegionFixture(t, `func F()[]func(){a:=func(){};b:=func(){};return []func(){a,b}}`, false)
	root := s.prog.Roots["F"]
	b, err := newSelectedSourceBinder(t.Context(), s, root, defaultRegistrationLimits().source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.bindCallable(root); err != nil {
		t.Fatal(err)
	}
	first, second := root.AnonFuncs[0], root.AnonFuncs[1]
	if count, err := b.lexicalLiteral(first, root.Syntax(), first.Syntax().(*ast.FuncLit)); err != nil || count != 1 {
		t.Fatal("actual first literal not owned", count, err)
	}
	// One application remains affordable after the complete parent walk. A new
	// parent walk would exhaust this budget; cached identity must still be exact.
	b.limits.work = b.work + 1
	if count, err := b.lexicalLiteral(second, root.Syntax(), second.Syntax().(*ast.FuncLit)); err != nil || count != 1 {
		t.Fatal("checked parent was rescanned", count, err)
	}
	b.limits.work = b.work + 1
	copy := *second.Syntax().(*ast.FuncLit)
	if count, err := b.lexicalLiteral(second, root.Syntax(), &copy); err != nil || count != 0 {
		t.Fatal("copied literal acquired membership", count, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	b.ctx = ctx
	if _, err := b.lexicalLiteral(second, root.Syntax(), second.Syntax().(*ast.FuncLit)); !errors.Is(err, context.Canceled) {
		t.Fatal("cached membership bypassed cancellation", err)
	}
}

func TestSelectedSourceLexicalIndexRetainsMultiplicity(t *testing.T) {
	s := sourceRegionFixture(t, `func F()func(){return func(){}}`, false)
	root := s.prog.Roots["F"]
	fn := root.AnonFuncs[0]
	lit := fn.Syntax().(*ast.FuncLit)
	b, err := newSelectedSourceBinder(t.Context(), s, root, defaultRegistrationLimits().source)
	if err != nil {
		t.Fatal(err)
	}
	// This detached candidate syntax is never bound as source. The membership
	// helper must retain two occurrences so its consumer can reject the claim.
	parent := &ast.BlockStmt{List: []ast.Stmt{&ast.ExprStmt{X: lit}, &ast.ExprStmt{X: lit}}}
	for range 2 {
		if count, err := b.lexicalLiteral(fn, parent, lit); err != nil || count != 2 {
			t.Fatal("duplicate literal collapsed", count, err)
		}
	}
}
