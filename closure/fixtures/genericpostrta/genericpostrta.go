package genericpostrta

type caller interface {
	M() int
}

type direct struct{}

func (direct) M() int { return 1 }

type viaASM struct{}

func (viaASM) M() int { return 2 }

func call[T caller](v T) int {
	return v.M()
}

func asmEntry()

func helper() int {
	return call(viaASM{})
}
