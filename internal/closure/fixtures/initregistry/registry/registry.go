package registry

type Codec interface {
	Decode([]byte) []byte
}

var impls = map[string]Codec{}

func Register(name string, c Codec) {
	impls[name] = c
}

func Get(name string) Codec {
	return impls[name]
}
