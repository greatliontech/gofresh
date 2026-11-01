// Package genericmethod exercises method subjects on a generic receiver type:
// each method reaches a distinct helper, so per-method closures stay distinct.
package genericmethod

type Box[T any] struct{ v T }

// Get is a value-receiver method on a generic type, reaching getHelper.
func (b Box[T]) Get() int { return getHelper() }

// Set is a pointer-receiver method on a generic type, reaching setHelper.
func (b *Box[T]) Set() int { return setHelper() }

func getHelper() int { return 1 }

func setHelper() int { return 2 }
