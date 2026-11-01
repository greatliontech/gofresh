package batchisolation

type callback func() int

var (
	callbackSlot  callback
	interfaceSlot any
	startupValue  = startupHelper()
)

func startupHelper() int { return 1 }

func dynamicTarget() int { return 2 }

func AddressTaker() int {
	callbackSlot = dynamicTarget
	return startupValue
}

func DynamicCaller() int { return callbackSlot() }

func alternateDynamicTarget() int { return 5 }

func KnownDynamic() int {
	fn := callback(dynamicTarget)
	if startupValue < 0 {
		fn = alternateDynamicTarget
	}
	return fn()
}

func CallbackRoot(fn callback) int { return fn() }

type runner interface {
	Run() int
}

type nested struct{}

func (nested) Exported() int { return 4 }

type concrete struct {
	value nested
}

func (concrete) Run() int { return concreteMethodHelper() }

func concreteMethodHelper() int { return 3 }

func Materializer() int {
	interfaceSlot = concrete{value: nested{}}
	return startupValue
}

func Invoker(value runner) int { return value.Run() }

func Production() int { return startupValue }
