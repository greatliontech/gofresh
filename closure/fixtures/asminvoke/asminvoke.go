package asminvoke

type iface interface {
	M() int
}

type concrete struct{}

func (concrete) M() int { return 1 }

var sink iface

func init() {
	sink = concrete{}
}

func asmEntry()

func helper() int {
	return sink.M()
}
