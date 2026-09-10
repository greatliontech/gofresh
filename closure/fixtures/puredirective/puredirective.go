// Package puredirective is a fixture for the //gofresh:pure scanner: one function
// and one method carry the directive, their neighbours do not.
package puredirective

//gofresh:pure
func Asserted() int { return sink() }

// NotAsserted carries no directive.
func NotAsserted() int { return sink() }

// gofresh:pure
func SpacedDirective() int { return sink() }

// T has one asserted method and one not.
type T struct{}

//gofresh:pure
func (t T) Asserted() int { return sink() }

func (t T) NotAsserted() int { return sink() }

func sink() int { return 1 }
