// Package externaldirective is a fixture for the //gofresh:external scanner:
// declarations carrying the external-state directive in its exact form, plus
// near-miss forms that must not count.
package externaldirective

//gofresh:external
func Declared() int { return 1 }

func NotDeclared() int { return 2 }

// gofresh:external
func SpacedDirective() int { return 3 }

type T struct{}

//gofresh:external
func (T) Declared() int { return 4 }

func (T) NotDeclared() int { return 5 }
