// Package methodsubject exercises method subjects: value- and pointer-receiver
// methods that reach distinct helpers, so each method's closure is its own.
package methodsubject

type Adder struct{ base int }

// Value is a value-receiver method reaching only valueHelper.
func (a Adder) Value() int { return a.base + valueHelper() }

// Ptr is a pointer-receiver method reaching only ptrHelper.
func (a *Adder) Ptr() int { return a.base + ptrHelper() }

func valueHelper() int { return 1 }

func ptrHelper() int { return 2 }
