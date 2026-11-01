package toolchainruntime

import (
	"runtime"
	"testing"
)

func TestOtherRuntimeSurface(*testing.T) {
	_ = runtime.NumCPU()
}
